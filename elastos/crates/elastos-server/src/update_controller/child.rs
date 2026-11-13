//! The update controller owns one unreaped child and its process group.

use anyhow::{Context, Result};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(test)]
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::Duration;
use tokio::process::{Child, Command};

use elastos_common::process_lifetime::{parent_pipe, pipe_identity, set_cloexec, PARENT_PIPE_ENV};
// Process birth identity lives in elastos-common so other owners of a child
// process (the public IPFS store) prove ownership the same way.
use elastos_common::process_identity::valid_pid;
pub(crate) use elastos_common::process_identity::{
    generation_gone, group_descendants, observe_exit, process_identity,
};
#[cfg(test)]
use elastos_common::process_identity::{linux_stat_group, linux_stat_start};
const GRACE_PERIOD: Duration = Duration::from_secs(12);
const REAP_PERIOD: Duration = Duration::from_secs(2);
const POLL_PERIOD: Duration = Duration::from_millis(20);
const DROP_PERIOD: Duration = Duration::from_millis(200);
// Darwin: a leader in exit is neither signalable (EPERM) nor yet waitable.
#[cfg(target_os = "macos")]
const EXIT_SETTLE_PERIOD: Duration = Duration::from_millis(500);

pub(crate) struct OwnedChild {
    child: Option<Child>,
    pid: u32,
    parent_lifetime: Option<OwnedFd>,
    status: Option<ExitStatus>,
}

impl OwnedChild {
    /// `command` is a fresh, single-use command for an already verified binary.
    pub(crate) fn spawn(command: &mut Command) -> Result<Self> {
        let (reader, writer) = parent_pipe().context("create child ownership pipe")?;
        let reader_fd = reader.as_raw_fd();
        let writer_fd = writer.as_raw_fd();
        let identity = pipe_identity(reader_fd)?;
        command
            .env(
                PARENT_PIPE_ENV,
                format!("{reader_fd}:{}:{}", identity.0, identity.1),
            )
            .process_group(0)
            .kill_on_drop(false);
        #[cfg(target_os = "linux")]
        let parent_pid = std::process::id() as libc::pid_t;
        unsafe {
            command.pre_exec(move || {
                // Only the reader survives exec. Other children retain CLOEXEC.
                libc::close(writer_fd);
                set_cloexec(reader_fd, false)?;
                #[cfg(target_os = "linux")]
                {
                    // Covers parent loss in the loader, before Rust can watch EOF.
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::getppid() != parent_pid {
                        libc::kill(libc::getpid(), libc::SIGTERM);
                    }
                }
                Ok(())
            });
        }
        let child = crate::install_transaction::retry_text_file_busy(|| command.spawn())
            .context("spawn owned update child")?;
        let pid = child.id().expect("newly spawned child has a process ID");
        drop(reader);
        Ok(Self {
            child: Some(child),
            pid,
            parent_lifetime: Some(writer),
            status: None,
        })
    }

    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// Observes exit without releasing the PID which anchors our process group.
    pub(crate) fn observed_exit(&self) -> Result<Option<ExitStatus>> {
        if self.child.is_none() {
            return Ok(self.status);
        }
        observe_exit(self.pid).context("observe owned update child")
    }

    /// Sends the final group signal before reaping, including on early exit.
    pub(crate) async fn stop(&mut self) -> Result<()> {
        self.stop_with_limits(GRACE_PERIOD, REAP_PERIOD).await
    }

    async fn stop_with_limits(&mut self, grace: Duration, reap: Duration) -> Result<()> {
        if self.child.is_none() {
            return Ok(());
        }
        let deadline = tokio::time::Instant::now() + grace + reap;
        let graceful_deadline = deadline - reap;
        // Successful waitid also proves that this PID is still our direct child.
        self.observed_exit()?;
        self.parent_lifetime.take();
        signal_group(self.pid, libc::SIGTERM)?;
        while self.observed_exit()?.is_none() && tokio::time::Instant::now() < graceful_deadline {
            tokio::time::sleep_until(
                (tokio::time::Instant::now() + POLL_PERIOD).min(graceful_deadline),
            )
            .await;
        }
        // A crashed leader can leave helpers with inherited stdout or stderr.
        // Its unreaped PID reserves the group ID until this last group signal.
        self.observed_exit()?;
        signal_group(self.pid, libc::SIGKILL)?;
        // Keep the anchor until helpers, including adopted zombies, are gone.
        // An uninterruptible helper holds the transaction at this same deadline.
        loop {
            let members = group_descendants(self.pid)?;
            if members.is_empty() {
                break;
            }
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "owned update group still has {} descendants at shutdown deadline",
                members.len()
            );
            tokio::time::sleep_until((tokio::time::Instant::now() + POLL_PERIOD).min(deadline))
                .await;
        }
        let child = self.child.as_mut().expect("owned child remains until reap");
        let status = tokio::time::timeout_at(deadline, child.wait())
            .await
            .context("owned update child exceeded shutdown deadline")?
            .context("reap owned update child")?;
        self.status = Some(status);
        self.child.take();
        Ok(())
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.child.is_none() {
            return;
        }
        // The same ownership check protects cancellation and unwinding paths.
        if self.observed_exit().is_ok() {
            let _ = signal_group(self.pid, libc::SIGKILL);
        }
        self.parent_lifetime.take();
        let deadline = std::time::Instant::now() + DROP_PERIOD;
        while std::time::Instant::now() < deadline {
            match group_descendants(self.pid) {
                Ok(members) if !members.is_empty() => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                _ => break,
            }
        }
        let child = self.child.as_mut().expect("owned child remains until reap");
        loop {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(None) => break,
            }
        }
        // Tokio owns final reaping if the kernel cannot finish within this bound.
        // kill_on_drop is disabled: only our checked group receives signals.
    }
}

pub(crate) fn signal_group(pid: u32, signal: libc::c_int) -> io::Result<()> {
    if unsafe { libc::kill(-(pid as libc::pid_t), signal) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let settled = std::time::Instant::now() + EXIT_SETTLE_PERIOD;
        if completed_group_after_signal_denial(
            &error,
            || observe_exit(pid),
            || group_descendants(pid),
            || {
                let now = std::time::Instant::now();
                if now >= settled {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(5).min(settled - now));
                true
            },
        )? {
            return Ok(());
        }
    }
    Err(error)
}

#[cfg(any(target_os = "macos", test))]
fn completed_group_after_signal_denial(
    error: &io::Error,
    mut observe: impl FnMut() -> io::Result<Option<ExitStatus>>,
    descendants: impl FnOnce() -> io::Result<Vec<u32>>,
    mut settle: impl FnMut() -> bool,
) -> io::Result<bool> {
    if error.raw_os_error() != Some(libc::EPERM) {
        return Ok(false);
    }
    // A leader still in exit becomes waitable within `settle`'s bound.
    let exited = loop {
        match observe()? {
            Some(exited) => break exited,
            None if settle() => {}
            None => return Ok(false),
        }
    };
    if !descendants()?.is_empty() {
        return Ok(false);
    }
    // Darwin denies signals to a group containing only its exited leader. WNOWAIT
    // keeps our direct child's PID reserved through both observations and the scan.
    Ok(observe()?.is_some_and(|current| current == exited))
}

/// Read process birth from the kernel without starting a helper process.
pub(crate) fn process_start(pid: u32) -> Option<String> {
    process_identity(pid).ok().flatten()
}

pub(crate) fn process_group(pid: u32) -> io::Result<Option<u32>> {
    valid_pid(pid)?;
    let group = unsafe { libc::getpgid(pid as libc::pid_t) };
    if group >= 0 {
        return Ok(Some(group as u32));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(None)
    } else {
        Err(error)
    }
}

/// Call after installing SIGTERM handling and before launching subordinate groups.
/// The inherited descriptor belongs only to the controller's direct child.
/// Graceful exit drains owned groups before returning; its process exit also
/// ends this watcher's force timer. Recovery retains incomplete group cleanup.
pub(crate) fn watch_parent() -> Result<()> {
    let Ok(value) = std::env::var(PARENT_PIPE_ENV) else {
        return Ok(());
    };
    let mut fields = value.split(':');
    let fd: libc::c_int = fields
        .next()
        .context("missing update parent pipe descriptor")?
        .parse()?;
    let device: u64 = fields
        .next()
        .context("missing update parent pipe device")?
        .parse()?;
    let inode: u64 = fields
        .next()
        .context("missing update parent pipe inode")?
        .parse()?;
    anyhow::ensure!(
        fd >= 3 && fields.next().is_none(),
        "invalid update parent pipe"
    );
    // Descendant execs keep the marker in their environment, but CLOEXEC closes
    // the reader. Its exact identity also rejects a reused descriptor number.
    if pipe_identity(fd).ok() != Some((device, inode)) {
        return Ok(());
    }
    set_cloexec(fd, true)?;
    let reader = unsafe { OwnedFd::from_raw_fd(fd) };
    std::thread::Builder::new()
        .name("update-parent-watch".into())
        .spawn(move || {
            let mut byte = 0u8;
            loop {
                let result =
                    unsafe { libc::read(reader.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) };
                if result > 0 {
                    continue;
                }
                if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            // This thread has the same lifetime as this process, so self-signals
            // remain tied to the owned child even if its controller has exited.
            unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
            std::thread::sleep(GRACE_PERIOD);
            unsafe {
                let pid = libc::getpid();
                if libc::getpgrp() == pid {
                    libc::kill(-pid, libc::SIGKILL);
                } else {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        })
        .context("start update parent watcher")?;
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0) } != 0 {
        return Err(io::Error::last_os_error()).context("transfer parent watch to ownership pipe");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Stdio;

    async fn wait_for_file(path: &Path) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !path.exists() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "child did not become ready"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn wait_for_exit(child: &OwnedChild) -> ExitStatus {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = child.observed_exit().unwrap() {
                return status;
            }
            assert!(tokio::time::Instant::now() < deadline, "child did not exit");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn stop_reaps_helpers_with_inherited_output_and_preserves_another_group() {
        let temp = tempfile::tempdir().unwrap();
        let ready = temp.path().join("ready");
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 60 & helper=$!; trap 'kill $helper 2>/dev/null; wait $helper 2>/dev/null; exit 0' TERM; touch \"$1\"; wait $helper", "owned-child"])
            .arg(&ready).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = OwnedChild::spawn(&mut command).unwrap();
        let pid = child.pid();
        let birth = process_start(pid).unwrap();
        assert!(!generation_gone(pid, &birth).unwrap());
        let mut other_command = Command::new("sleep");
        other_command.arg("60");
        let mut other = OwnedChild::spawn(&mut other_command).unwrap();
        wait_for_file(&ready).await;
        child.stop().await.unwrap();
        assert!(generation_gone(pid, &birth).unwrap());
        assert_eq!(
            observe_exit(pid).unwrap_err().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert!(other.observed_exit().unwrap().is_none());
        other.stop().await.unwrap();
    }

    #[tokio::test]
    async fn hung_child_is_killed_within_the_shutdown_bound() {
        let temp = tempfile::tempdir().unwrap();
        let ready = temp.path().join("ready");
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "trap '' TERM; touch \"$1\"; while :; do :; done",
                "owned-child",
            ])
            .arg(&ready);
        let mut child = OwnedChild::spawn(&mut command).unwrap();
        let pid = child.pid();
        wait_for_file(&ready).await;
        tokio::time::timeout(
            Duration::from_millis(500),
            child.stop_with_limits(Duration::from_millis(30), Duration::from_millis(200)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            child.observed_exit().unwrap().unwrap().signal(),
            Some(libc::SIGKILL)
        );
        assert_eq!(
            observe_exit(pid).unwrap_err().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[tokio::test]
    async fn crash_stays_unreaped_until_group_cleanup_and_drop_reaps() {
        let mut command = Command::new("sh");
        command.args(["-c", "kill -KILL $$"]);
        let child = OwnedChild::spawn(&mut command).unwrap();
        let pid = child.pid();
        assert_eq!(wait_for_exit(&child).await.signal(), Some(libc::SIGKILL));
        assert!(observe_exit(pid).unwrap().is_some());
        drop(child);
        assert_eq!(
            observe_exit(pid).unwrap_err().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[tokio::test]
    async fn stop_reaps_exited_and_term_exiting_groups_and_preserves_another_group() {
        for already_exited in [true, false] {
            let mut command = if already_exited {
                let mut command = Command::new("/bin/sh");
                command.args(["-c", "exit 0"]);
                command
            } else {
                let mut command = Command::new("/bin/sleep");
                command.arg("60");
                command
            };
            let mut child = OwnedChild::spawn(&mut command).unwrap();
            let pid = child.pid();
            let mut other_command = Command::new("/bin/sleep");
            other_command.arg("60");
            let mut other = OwnedChild::spawn(&mut other_command).unwrap();
            if already_exited {
                assert!(wait_for_exit(&child).await.success());
                assert!(group_descendants(pid).unwrap().is_empty());
                #[cfg(target_os = "macos")]
                for signal in [libc::SIGTERM, libc::SIGKILL] {
                    assert_eq!(unsafe { libc::kill(-(pid as libc::pid_t), signal) }, -1);
                    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
                    assert!(observe_exit(pid).unwrap().is_some());
                }
            } else {
                assert!(child.observed_exit().unwrap().is_none());
            }
            tokio::time::timeout(Duration::from_secs(2), child.stop())
                .await
                .unwrap()
                .unwrap();
            let status = child.observed_exit().unwrap().unwrap();
            if already_exited {
                assert!(status.success());
            } else {
                assert_eq!(status.signal(), Some(libc::SIGTERM));
            }
            assert_eq!(
                observe_exit(pid).unwrap_err().raw_os_error(),
                Some(libc::ECHILD)
            );
            assert!(group_descendants(pid).unwrap().is_empty());
            assert!(other.observed_exit().unwrap().is_none());
            tokio::time::timeout(Duration::from_secs(2), other.stop())
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn signal_denial_requires_stable_exited_direct_child_and_empty_proved_group() {
        for case in [
            "complete",
            "exit settling",
            "other errno",
            "live child",
            "not direct child",
            "uncertain exit",
            "remaining descendant",
            "uncertain group",
            "anchor disappeared",
            "anchor reaped",
            "changed exit event",
        ] {
            let error = io::Error::from_raw_os_error(if case == "other errno" {
                libc::EACCES
            } else {
                libc::EPERM
            });
            let before = match case {
                "not direct child" => Err(io::Error::from_raw_os_error(libc::ECHILD)),
                "uncertain exit" => Err(io::Error::from_raw_os_error(libc::EPERM)),
                _ => Ok(Some(ExitStatus::from_raw(0))),
            };
            let after = match case {
                "anchor disappeared" => Ok(None),
                "anchor reaped" => Err(io::Error::from_raw_os_error(libc::ECHILD)),
                "changed exit event" => Ok(Some(ExitStatus::from_raw(7 << 8))),
                _ => Ok(Some(ExitStatus::from_raw(0))),
            };
            // Popped from the end; an exhausted list observes a leader still running.
            let mut observations = match case {
                "live child" => Vec::new(),
                "exit settling" => vec![after, before, Ok(None)],
                _ => vec![after, before],
            };
            let mut settles = 0;
            let result = completed_group_after_signal_denial(
                &error,
                || observations.pop().unwrap_or(Ok(None)),
                || match case {
                    "remaining descendant" => Ok(vec![42]),
                    "uncertain group" => Err(io::Error::from_raw_os_error(libc::EPERM)),
                    _ => Ok(Vec::new()),
                },
                || {
                    settles += 1;
                    settles <= 2
                },
            );
            if matches!(
                case,
                "not direct child" | "uncertain exit" | "uncertain group" | "anchor reaped"
            ) {
                assert!(result.is_err(), "{case}");
            } else {
                assert_eq!(
                    result.unwrap(),
                    matches!(case, "complete" | "exit settling"),
                    "{case}"
                );
            }
            // Only a leader not yet waitable waits, and only within the bound.
            let expected = match case {
                "live child" => 3,
                "exit settling" => 1,
                _ => 0,
            };
            assert_eq!(settles, expected, "{case}");
        }
    }

    #[tokio::test]
    async fn crashed_leader_keeps_its_anchor_until_term_resistant_helper_is_gone() {
        let temp = tempfile::tempdir().unwrap();
        let helper_ready = temp.path().join("helper");
        let mut command = Command::new("sh");
        command.args(["-c", "sh -c 'trap \"\" TERM; touch \"$1\"; while :; do :; done' owned-helper \"$1\" & while [ ! -f \"$1\" ]; do :; done; kill -KILL $$", "owned-child"])
            .arg(&helper_ready);
        let mut child = OwnedChild::spawn(&mut command).unwrap();
        let pid = child.pid();
        assert_eq!(wait_for_exit(&child).await.signal(), Some(libc::SIGKILL));
        assert!(!group_descendants(pid).unwrap().is_empty());
        child.stop().await.unwrap();
        assert!(group_descendants(pid).unwrap().is_empty());
        assert_eq!(
            observe_exit(pid).unwrap_err().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn proc_stat_parser_handles_spaces_and_parentheses_in_process_names() {
        assert_eq!(
            linux_stat_group("12 (strange ) process) Z 1 17 19 0").unwrap(),
            17
        );
        // Captured from a listed task that exited during a /proc scan.
        assert_eq!(
            linux_stat_group("304929 (true) X 0 -1 -1 0 -1").unwrap(),
            -1
        );
        assert!(linux_stat_group("12 (unfinished").is_err());
        assert_eq!(
            linux_stat_start(
                "12 (strange ) process) Z 1 17 19 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345"
            )
            .unwrap(),
            12345
        );
        assert!(linux_stat_start("12 (unfinished").is_err());
    }

    #[test]
    fn generation_observation_preserves_live_and_reused_process_ids() {
        let pid = std::process::id();
        let birth = process_start(pid).unwrap();
        assert!(!generation_gone(pid, &birth).unwrap());
        assert!(generation_gone(pid, "another-generation").is_err());
        assert!(process_start(0).is_none());
        assert!(generation_gone(0, "invalid").is_err());
    }

    #[tokio::test]
    async fn loader_failure_returns_without_an_owned_child() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("invalid-executable");
        std::fs::write(&binary, b"#!/elastos-test-missing-loader/interpreter\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(OwnedChild::spawn(&mut Command::new(binary)).is_err());
    }

    #[tokio::test]
    async fn parent_pipe_loss_starts_graceful_shutdown() {
        let temp = tempfile::tempdir().unwrap();
        let ready = temp.path().join("ready");
        let fixture = format!(
            "{}::parent_watch_fixture",
            module_path!().split_once("::").unwrap().1
        );
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", &fixture, "--ignored", "--nocapture"])
            .env("ELASTOS_UPDATE_PARENT_WATCH_TEST_READY", &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = OwnedChild::spawn(&mut command).unwrap();
        wait_for_file(&ready).await;
        child.parent_lifetime.take();
        assert!(wait_for_exit(&child).await.success());
        let pid = child.pid();
        child.stop().await.unwrap();
        assert_eq!(
            observe_exit(pid).unwrap_err().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[tokio::test]
    #[ignore = "subprocess fixture for parent_pipe_loss_starts_graceful_shutdown"]
    async fn parent_watch_fixture() {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        watch_parent().unwrap();
        let ready = std::path::PathBuf::from(
            std::env::var_os("ELASTOS_UPDATE_PARENT_WATCH_TEST_READY").unwrap(),
        );
        let helper_ready = ready.with_extension("helper");
        let mut helper_command = Command::new("sh");
        helper_command
            .args([
                "-c",
                "trap '' TERM; touch \"$1\"; while :; do :; done",
                "parent-loss-helper",
            ])
            .arg(&helper_ready);
        let mut helper = OwnedChild::spawn(&mut helper_command).unwrap();
        wait_for_file(&helper_ready).await;
        std::fs::write(&ready, b"ready").unwrap();
        terminate.recv().await;
        // Mirrors gateway shutdown: the leader drains its separate owned groups.
        helper
            .stop_with_limits(Duration::from_millis(30), Duration::from_millis(200))
            .await
            .unwrap();
    }
}

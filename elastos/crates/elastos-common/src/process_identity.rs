//! Process birth identity read from the kernel, and observation of one
//! process generation. A PID with its birth identity names exactly one process
//! generation, so a reused PID is never mistaken for an owned process.

use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

pub fn observe_exit(pid: u32) -> io::Result<Option<ExitStatus>> {
    use rustix::process::{waitid, Pid, WaitId, WaitIdOptions};

    let target =
        Pid::from_raw(pid as i32).ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
    loop {
        let status = match waitid(
            WaitId::Pid(target),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Ok(Some(status)) => status,
            Ok(None) => return Ok(None),
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(error) => return Err(error.into()),
        };
        let raw_status = if status.exited() {
            status.exit_status().unwrap_or_default() << 8
        } else if status.killed() {
            status.terminating_signal().unwrap_or_default()
        } else if status.dumped() {
            status.terminating_signal().unwrap_or_default() | 0x80
        } else {
            return Err(io::Error::other("unexpected owned child exit event"));
        };
        return Ok(Some(ExitStatus::from_raw(raw_status)));
    }
}

/// Recovery observes an old generation; it gives signal authority only to owners.
/// A reused PID or incomplete kernel view keeps restoration blocked.
pub fn generation_gone(pid: u32, start: &str) -> io::Result<bool> {
    for inspection in 0..2 {
        if let Some(current) = process_identity(pid)? {
            if current != start {
                return Err(io::Error::other(
                    "update child process ID belongs to another generation",
                ));
            }
            return Ok(false);
        }
        // macOS hides zombie birth records from libproc. A direct-child event
        // still proves that this process has a reserved PID and needs reaping.
        match observe_exit(pid) {
            Ok(_) => return Ok(false),
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {}
            Err(error) => return Err(error),
        }
        if inspection == 0 && !group_descendants(pid)?.is_empty() {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn valid_pid(pid: u32) -> io::Result<()> {
    if pid == 0 || pid > libc::pid_t::MAX as u32 {
        return Err(io::Error::other("invalid update child process ID"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn process_identity(pid: u32) -> io::Result<Option<String>> {
    valid_pid(pid)?;
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if process_vanished(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let start = linux_stat_start(&stat)?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|boot| boot.trim().to_owned())
        .filter(|boot| !boot.is_empty());
    Ok(Some(match boot {
        Some(boot) => format!("linux:{boot}:{start}"),
        None => format!("linux:{start}"),
    }))
}

#[cfg(target_os = "macos")]
pub fn process_identity(pid: u32) -> io::Result<Option<String>> {
    valid_pid(pid)?;
    let (bytes, info, error) = libproc::bsd_info(pid as libc::pid_t);
    if bytes == libproc::BSD_INFO_BYTES && info.pbi_pid == pid {
        return Ok(Some(format!(
            "macos:{}:{}",
            info.pbi_start_tvsec, info.pbi_start_tvusec
        )));
    }
    if bytes == 0 && error.raw_os_error() == Some(libc::ESRCH) {
        // An inaccessible or unreaped process is ambiguous even if libproc
        // cannot supply its birth record. Signal zero is an existence check.
        let gone = rustix::process::Pid::from_raw(pid as i32).is_some_and(|target| {
            rustix::process::test_kill_process(target) == Err(rustix::io::Errno::SRCH)
        });
        if gone {
            return Ok(None);
        }
    }
    Err(if error.raw_os_error() != Some(0) {
        error
    } else {
        io::Error::other("incomplete update child birth record")
    })
}

/// The macOS libproc reads: the only `unsafe` in this module.
/// User-approved exception 2026-11-12 (ADV-04). Each read clears errno
/// first and returns it as the call left it, so callers can tell an empty
/// answer from a failure.
#[cfg(target_os = "macos")]
mod libproc {
    use std::io;

    pub(super) const BSD_INFO_BYTES: libc::c_int =
        std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    const SHORT_INFO_BYTES: libc::c_int =
        std::mem::size_of::<libc::proc_bsdshortinfo>() as libc::c_int;

    /// `proc_pidinfo(PROC_PIDTBSDINFO)`: the byte count, the record (the
    /// process start time) and errno after the call.
    pub(super) fn bsd_info(pid: libc::pid_t) -> (libc::c_int, libc::proc_bsdinfo, io::Error) {
        // SAFETY: `proc_bsdinfo` is a C struct of integers and byte arrays,
        // for which all-zero bytes are a valid value.
        // User-approved exception 2026-11-12 (ADV-04).
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        errno::set_errno(errno::Errno(0));
        // SAFETY: the buffer is `info`, valid, writable and exactly
        // `BSD_INFO_BYTES` long; libproc writes at most that many bytes.
        // User-approved exception 2026-11-12 (ADV-04).
        let bytes = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                BSD_INFO_BYTES,
            )
        };
        (bytes, info, io::Error::last_os_error())
    }

    /// `proc_listpids(PROC_PGRP_ONLY, leader)` into `pids`: the byte count
    /// and errno after the call.
    pub(super) fn group_pids(leader: u32, pids: &mut [libc::pid_t]) -> (libc::c_int, io::Error) {
        // PROC_PGRP_ONLY from the SDK's sys/proc_info.h; libc exports the API.
        const PROC_PGRP_ONLY: u32 = 2;
        let buffer_size = std::mem::size_of_val(pids) as libc::c_int;
        errno::set_errno(errno::Errno(0));
        // SAFETY: the buffer is `pids`, valid, writable and exactly
        // `buffer_size` bytes long; libproc writes at most that many bytes.
        // User-approved exception 2026-11-12 (ADV-04).
        let bytes = unsafe {
            libc::proc_listpids(
                PROC_PGRP_ONLY,
                leader,
                pids.as_mut_ptr().cast(),
                buffer_size,
            )
        };
        (bytes, io::Error::last_os_error())
    }

    /// `proc_pidinfo(PROC_PIDT_SHORTBSDINFO)`: the byte count, the record
    /// (the process group) and errno after the call.
    pub(super) fn short_info(
        pid: libc::pid_t,
    ) -> (libc::c_int, libc::proc_bsdshortinfo, io::Error) {
        // SAFETY: `proc_bsdshortinfo` is a C struct of integers and byte
        // arrays, for which all-zero bytes are a valid value.
        // User-approved exception 2026-11-12 (ADV-04).
        let mut info: libc::proc_bsdshortinfo = unsafe { std::mem::zeroed() };
        errno::set_errno(errno::Errno(0));
        // SAFETY: the buffer is `info`, valid, writable and exactly
        // `SHORT_INFO_BYTES` long; libproc writes at most that many bytes.
        // User-approved exception 2026-11-12 (ADV-04).
        let bytes = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDT_SHORTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdshortinfo).cast(),
                SHORT_INFO_BYTES,
            )
        };
        (bytes, info, io::Error::last_os_error())
    }

    pub(super) const fn short_info_bytes() -> libc::c_int {
        SHORT_INFO_BYTES
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn process_identity(_pid: u32) -> io::Result<Option<String>> {
    Err(io::Error::other(
        "update process birth proof is unsupported on this platform",
    ))
}

#[cfg(target_os = "linux")]
pub fn group_descendants(leader: u32) -> io::Result<Vec<u32>> {
    let mut members = Vec::new();
    for (index, entry) in std::fs::read_dir("/proc")?.enumerate() {
        if index >= 16_384 {
            return Err(io::Error::other("process group scan exceeded its bound"));
        }
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == leader {
            continue;
        }
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if process_vanished(&error) => continue,
            Err(error) => return Err(error),
        };
        if linux_stat_group(&stat)? == leader as libc::pid_t {
            members.push(pid);
        }
    }
    Ok(members)
}

/// A process can exit between listing and reading its stat: open then reports
/// ENOENT or ESRCH, and read reports ESRCH.
#[cfg(target_os = "linux")]
fn process_vanished(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

/// The process group field of a Linux `/proc/<pid>/stat` line.
pub fn linux_stat_group(stat: &str) -> io::Result<libc::pid_t> {
    // A process name can contain spaces and closing parentheses. A dead task
    // that is still listed reports group -1.
    let group = stat
        .rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(2));
    group
        .and_then(|group| group.parse().ok())
        .ok_or_else(|| io::Error::other("invalid process group in proc stat"))
}

/// The start-time field of a Linux `/proc/<pid>/stat` line.
pub fn linux_stat_start(stat: &str) -> io::Result<u64> {
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|start| start.parse().ok())
        .ok_or_else(|| io::Error::other("invalid process birth in proc stat"))
}

#[cfg(target_os = "macos")]
pub fn group_descendants(leader: u32) -> io::Result<Vec<u32>> {
    let mut pids = [0 as libc::pid_t; 4096];
    let buffer_size = std::mem::size_of_val(&pids) as libc::c_int;
    let (bytes, error) = libproc::group_pids(leader, &mut pids);
    if bytes < 0 || (bytes == 0 && error.raw_os_error() != Some(0)) {
        return Err(error);
    }
    if bytes >= buffer_size || !(bytes as usize).is_multiple_of(std::mem::size_of::<libc::pid_t>())
    {
        return Err(io::Error::other(
            "owned process group listing exceeded its bound",
        ));
    }
    let mut members = Vec::new();
    for &pid in &pids[..bytes as usize / std::mem::size_of::<libc::pid_t>()] {
        if pid <= 0 || pid as u32 == leader {
            continue;
        }
        let (bytes, info, error) = libproc::short_info(pid);
        if bytes != libproc::short_info_bytes() {
            if error.raw_os_error() == Some(libc::ESRCH) {
                // A member can exit between list and info. Keep it pending until
                // the next group list also proves that its PID has disappeared.
                members.push(pid as u32);
                continue;
            }
            return Err(if bytes == 0 && error.raw_os_error() != Some(0) {
                error
            } else {
                io::Error::other("incomplete owned process group member info")
            });
        }
        if info.pbsi_pgid == leader {
            members.push(pid as u32);
        }
    }
    Ok(members)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn group_descendants(_leader: u32) -> io::Result<Vec<u32>> {
    Err(io::Error::other(
        "owned process group proof is unsupported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_live_process_keeps_its_birth_identity() {
        let pid = std::process::id();
        let birth = process_identity(pid).unwrap().unwrap();
        assert_eq!(
            process_identity(pid).unwrap().as_deref(),
            Some(birth.as_str())
        );
        assert!(!generation_gone(pid, &birth).unwrap());
        assert!(generation_gone(pid, "another-generation").is_err());
        assert!(process_identity(0).is_err());
    }
}

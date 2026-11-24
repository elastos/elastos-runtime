//! Public IPFS store tests: settings, readiness, the lifecycle against a
//! fake bridge on the real registry, and the Stop table against real
//! lock-holding child processes.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use elastos_runtime::provider::{ResourceRequest, ResourceResponse};
use serde_json::{json, Value};

use super::test_seams::{HooksGuard, StoreHooks};
use super::*;
use crate::protected_content_config::tests::{owner_only_dir, safe_ancestor_tempdir};
use crate::public_metadata_consent::tests::{
    close_public_metadata_gate, open_public_metadata_gate,
};
use crate::public_metadata_consent::{
    acquire_public_state_lock, consent_enabled, create_withdrawal_marker, phase_allowed,
    read_consent, read_withdrawal_marker, write_consent, PublicMetadataErrorCode,
};

const TEST_PEER: &str =
    "/ip4/198.51.100.7/tcp/4001/p2p/12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8";
const TEST_ROOT: &str = "bafkreiapyat3eabmkxkzoe6xn46wg5iupsz2xgumhbpbrzoroxyclri4ai";

// ── Fake bridge ─────────────────────────────────────────────────────

/// A gate a fake op waits on until it is opened.
pub(crate) struct Gate(watch::Sender<bool>);

impl Gate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self(watch::Sender::new(false)))
    }

    pub(crate) fn open(&self) {
        self.0.send_replace(true);
    }

    async fn wait(&self) {
        let mut open = self.0.subscribe();
        let _ = open.wait_for(|open| *open).await;
    }
}

/// A public ipfs-provider behind a fake bridge with the real bridge's
/// shape: one request at a time on its I/O, and a shutdown that delivers
/// the protocol Shutdown behind that I/O within 5 s or force-reaps the
/// provider after 5 s more, failing every queued and in-flight request.
pub(crate) struct FakeBridge {
    ops: StdMutex<Vec<String>>,
    io: tokio::sync::Mutex<()>,
    dead: watch::Sender<bool>,
    started: AtomicBool,
    pub(crate) peers: AtomicU32,
    holds: StdMutex<HashMap<String, Arc<Gate>>>,
    delays: StdMutex<HashMap<String, Duration>>,
    shutdown_script: StdMutex<VecDeque<Result<(), ProviderError>>>,
    shutdown_gate: StdMutex<Option<Arc<Gate>>>,
    pub(crate) shutdown_calls: AtomicUsize,
    shut_down: AtomicBool,
    reads: AtomicUsize,
    pub(crate) max_reads: AtomicUsize,
    failures: StdMutex<HashMap<String, String>>,
}

impl FakeBridge {
    pub(crate) fn new() -> Self {
        Self {
            ops: StdMutex::new(Vec::new()),
            io: tokio::sync::Mutex::new(()),
            dead: watch::Sender::new(false),
            started: AtomicBool::new(false),
            peers: AtomicU32::new(2),
            holds: StdMutex::new(HashMap::new()),
            delays: StdMutex::new(HashMap::new()),
            shutdown_script: StdMutex::new(VecDeque::new()),
            shutdown_gate: StdMutex::new(None),
            shutdown_calls: AtomicUsize::new(0),
            shut_down: AtomicBool::new(false),
            reads: AtomicUsize::new(0),
            max_reads: AtomicUsize::new(0),
            failures: StdMutex::new(HashMap::new()),
        }
    }

    pub(crate) fn hold(&self, op: &str) -> Arc<Gate> {
        let gate = Gate::new();
        self.holds.lock().unwrap().insert(op.into(), gate.clone());
        gate
    }

    pub(crate) fn delay(&self, op: &str, delay: Duration) {
        self.delays.lock().unwrap().insert(op.into(), delay);
    }

    pub(crate) fn script_shutdown(&self, results: Vec<Result<(), ProviderError>>) {
        self.shutdown_script.lock().unwrap().extend(results);
    }

    pub(crate) fn hold_shutdown(&self) -> Arc<Gate> {
        let gate = Gate::new();
        *self.shutdown_gate.lock().unwrap() = Some(gate.clone());
        gate
    }

    pub(crate) fn ops(&self) -> Vec<String> {
        self.ops.lock().unwrap().clone()
    }

    fn reap(&self) {
        self.started.store(false, Ordering::SeqCst);
        self.dead.send_replace(true);
    }

    /// The real bridge's answer once its provider process has exited.
    fn exited() -> ProviderError {
        ProviderError::Provider("provider process exited unexpectedly".into())
    }

    /// The provider process dies on its own (a crash): every later request
    /// fails as the real bridge's does.
    pub(crate) fn crash(&self) {
        self.reap();
    }

    /// `op` fails with a provider error carrying `message`.
    pub(crate) fn fail(&self, op: &str, message: &str) {
        self.failures
            .lock()
            .unwrap()
            .insert(op.into(), message.into());
    }

    async fn died(&self) {
        let mut dead = self.dead.subscribe();
        let _ = dead.wait_for(|dead| *dead).await;
    }

    fn answer(&self, op: &str) -> Value {
        match op {
            "ensure_started" => {
                self.started.store(true, Ordering::SeqCst);
                json!({"status":"ok","data":{"state":"ready"}})
            }
            "status" if self.started.load(Ordering::SeqCst) => json!({"status":"ok","data":{
                "state":"ready","api_endpoint":"http://127.0.0.1:5001","runtime_store_mode":"public"}}),
            "status" => json!({"status":"ok","data":{"state":"cold","api_endpoint":null}}),
            "runtime_public_peers" if self.started.load(Ordering::SeqCst) => {
                json!({"status":"ok","data":{"peers":self.peers.load(Ordering::SeqCst)}})
            }
            "runtime_public_peers"
            | "runtime_public_import_car"
            | "runtime_public_pin"
            | "runtime_public_provide"
                if !self.started.load(Ordering::SeqCst) =>
            {
                json!({"status":"error","code":"not_ready","message":"not started"})
            }
            _ => json!({"status":"ok","data":{}}),
        }
    }
}

#[async_trait::async_trait]
impl Provider for FakeBridge {
    async fn handle(&self, _: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider("fake bridge is raw only".into()))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![]
    }

    fn name(&self) -> &'static str {
        "public-ipfs-fake-bridge"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let op = request["op"].as_str().unwrap_or_default().to_string();
        self.ops.lock().unwrap().push(op.clone());
        if *self.dead.borrow() {
            return Err(Self::exited());
        }
        if let Some(message) = self.failures.lock().unwrap().get(&op).cloned() {
            return Err(ProviderError::Provider(message));
        }
        let read = matches!(op.as_str(), "status" | "runtime_public_peers");
        if read {
            let now = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_reads.fetch_max(now, Ordering::SeqCst);
        }
        let outcome = async {
            let _io = tokio::select! {
                io = self.io.lock() => io,
                () = self.died() => return Err(Self::exited()),
            };
            let hold = self.holds.lock().unwrap().get(&op).cloned();
            let delay = self.delays.lock().unwrap().get(&op).copied();
            tokio::select! {
                () = async {
                    if let Some(hold) = hold {
                        hold.wait().await;
                    }
                    if let Some(delay) = delay {
                        tokio::time::sleep(delay).await;
                    }
                } => Ok(self.answer(&op)),
                () = self.died() => Err(Self::exited()),
            }
        }
        .await;
        if read {
            self.reads.fetch_sub(1, Ordering::SeqCst);
        }
        outcome
    }

    async fn shutdown(&self) -> Result<(), ProviderError> {
        self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
        let gate = self.shutdown_gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate.wait().await;
        }
        let scripted = self.shutdown_script.lock().unwrap().pop_front();
        if let Some(result) = scripted {
            // A scripted answer comes after the child's reap.
            self.reap();
            self.shut_down.store(true, Ordering::SeqCst);
            return result;
        }
        if self.shut_down.load(Ordering::SeqCst) {
            return Ok(());
        }
        match tokio::time::timeout(Duration::from_secs(5), self.io.lock()).await {
            Ok(_io) => {
                self.reap();
                self.shut_down.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(_) => {
                // The child does not exit on its own either: force-reap.
                tokio::time::sleep(Duration::from_secs(5)).await;
                self.reap();
                self.shut_down.store(true, Ordering::SeqCst);
                Err(ProviderError::Provider("provider request timed out".into()))
            }
        }
    }
}

// ── Fixtures ────────────────────────────────────────────────────────

pub(crate) type Configure = Arc<dyn Fn(&FakeBridge) + Send + Sync>;

/// The launcher, signal and identity hooks of one data dir: every launched
/// provider is a fake bridge, every signal is recorded (and sent, unless
/// refused), and every launch's settings are kept.
pub(crate) struct FakeStore {
    pub(crate) launched: Arc<StdMutex<Vec<Arc<FakeBridge>>>>,
    pub(crate) settings: Arc<StdMutex<Vec<PublicIpfsSettings>>>,
    pub(crate) signals: Arc<StdMutex<Vec<(i32, i32)>>>,
    ignore_term: Arc<StdMutex<Vec<i32>>>,
    _hooks: HooksGuard,
}

impl FakeStore {
    pub(crate) fn install(data_dir: &Path, configure: Configure) -> Self {
        Self::install_with(data_dir, configure, false, None)
    }

    pub(crate) fn install_with(
        data_dir: &Path,
        configure: Configure,
        refuse_signals: bool,
        identity: Option<test_seams::Identity>,
    ) -> Self {
        let launched = Arc::new(StdMutex::new(Vec::<Arc<FakeBridge>>::new()));
        let settings = Arc::new(StdMutex::new(Vec::new()));
        let signals = Arc::new(StdMutex::new(Vec::new()));
        let ignore_term = Arc::new(StdMutex::new(Vec::<i32>::new()));
        let (launches, seen, sent, ignoring) = (
            launched.clone(),
            settings.clone(),
            signals.clone(),
            ignore_term.clone(),
        );
        let hooks = StoreHooks {
            launch: Some(Arc::new(move |chosen: &PublicIpfsSettings| {
                let fake = Arc::new(FakeBridge::new());
                configure(&fake);
                seen.lock().unwrap().push(chosen.clone());
                launches.lock().unwrap().push(fake.clone());
                Ok(fake as Arc<dyn Provider>)
            })),
            signal: Some(Arc::new(move |pid, number| {
                sent.lock().unwrap().push((pid, number));
                if refuse_signals {
                    return Err(io::Error::from_raw_os_error(libc::EPERM));
                }
                // A process that ignores SIGTERM: delivered, without effect.
                if number == libc::SIGTERM && ignoring.lock().unwrap().contains(&pid) {
                    return Ok(());
                }
                send_signal(pid, number)
            })),
            identity,
        };
        Self {
            launched,
            settings,
            signals,
            ignore_term,
            _hooks: test_seams::install(data_dir, hooks),
        }
    }

    pub(crate) fn launches(&self) -> usize {
        self.launched.lock().unwrap().len()
    }

    pub(crate) fn last(&self) -> Arc<FakeBridge> {
        self.launched.lock().unwrap().last().unwrap().clone()
    }

    pub(crate) fn signals(&self) -> Vec<(i32, i32)> {
        self.signals.lock().unwrap().clone()
    }

    /// `pid` ignores SIGTERM: the cleanup's SIGTERM is recorded and has no
    /// effect, so only its SIGKILL stops it.
    pub(crate) fn ignore_term(&self, pid: u32) {
        self.ignore_term.lock().unwrap().push(pid as i32);
    }
}

pub(crate) fn no_configure() -> Configure {
    Arc::new(|_: &FakeBridge| {})
}

struct Home {
    _dir: tempfile::TempDir,
    data_dir: PathBuf,
    registry: Arc<ProviderRegistry>,
}

/// A Home that offers public metadata sharing (A5 gate open), as a proof
/// Home is set up; the gate-closure tests close it themselves.
fn home() -> Home {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("data");
    owner_only_dir(&data_dir);
    open_public_metadata_gate(&data_dir);
    Home {
        _dir: dir,
        data_dir,
        registry: Arc::new(ProviderRegistry::new()),
    }
}

pub(crate) async fn record_consent(data_dir: &Path, state: ConsentState) {
    let guard = acquire_public_state_lock(data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap();
    write_consent(data_dir, state, "principal:test", &guard).unwrap();
}

async fn guard(data_dir: &Path) -> PublicStateGuard {
    acquire_public_state_lock(data_dir, STATE_LOCK_BUDGET)
        .await
        .unwrap()
}

async fn registered(registry: &ProviderRegistry) -> bool {
    registry
        .has_ready_runtime_provider_target(PUBLIC_IPFS_TARGET)
        .await
}

/// Register a fake bridge directly, as a Ready `public-ipfs` target.
async fn register_fake(registry: &ProviderRegistry, fake: Arc<FakeBridge>) {
    registry
        .register_runtime_provider_target(PUBLIC_IPFS_TARGET, fake)
        .await
        .unwrap();
}

async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !condition() {
        assert!(tokio::time::Instant::now() < deadline, "never: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn marker_exists(data_dir: &Path) -> bool {
    read_withdrawal_marker(data_dir).unwrap().is_some()
}

fn consent_state(data_dir: &Path) -> Option<ConsentState> {
    read_consent(data_dir).unwrap().map(|record| record.state)
}

// ── Kubo stand-in: a real child that holds the public repo lock ─────

const STAND_IN_LOCK_ENV: &str = "ELASTOS_TEST_KUBO_STAND_IN_LOCK";
const STAND_IN_STARTED_ENV: &str = "ELASTOS_TEST_KUBO_STAND_IN_STARTED";
const STAND_IN_HELD_ENV: &str = "ELASTOS_TEST_KUBO_STAND_IN_HELD";
const STAND_IN_GATE_ENV: &str = "ELASTOS_TEST_KUBO_STAND_IN_GATE";
const STAND_IN_TEST: &str = "public_ipfs_store::tests::kubo_stand_in_child_process";

/// The stand-in's own process: this test binary run again for only this
/// test, with the stand-in's paths in its environment. Run without them (an
/// ordinary test run), it does nothing.
#[test]
fn kubo_stand_in_child_process() {
    let Some(lock_path) = std::env::var_os(STAND_IN_LOCK_ENV) else {
        return;
    };
    let path = |name: &str| PathBuf::from(std::env::var_os(name).expect("stand-in path"));
    std::fs::write(path(STAND_IN_STARTED_ENV), b"").unwrap();
    if let Some(gate) = std::env::var_os(STAND_IN_GATE_ENV).map(PathBuf::from) {
        while !gate.exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    // `fcntl(F_SETLK)` on `repo.lock`, as Kubo does; the file stays open,
    // and the lock held, until the process ends.
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .ok();
    let held = lock.as_ref().is_some_and(|file| {
        nix::fcntl::fcntl(
            file,
            nix::fcntl::FcntlArg::F_SETLK(&super::whole_file_write_lock()),
        )
        .is_ok()
    });
    std::fs::write(path(STAND_IN_HELD_ENV), if held { b"1" } else { b"0" }).unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// A child process standing in for a public Kubo: it writes `started`, then
/// waits for the gate file (if any) BEFORE it takes `repo.lock` with
/// `fcntl(F_SETLK)`, as Kubo does, and then waits for a signal. A reaper
/// thread waits for it, so its exit is observed as soon as it happens.
pub(crate) struct KuboStandIn {
    pub(crate) pid: u32,
    held: PathBuf,
    exited: std::sync::mpsc::Receiver<libc::c_int>,
    status: Option<libc::c_int>,
}

impl KuboStandIn {
    pub(crate) fn spawn(data_dir: &Path, gate: Option<&Path>) -> Self {
        use std::os::unix::process::ExitStatusExt as _;

        let repo = data_dir.join(PUBLIC_REPO_DIR);
        std::fs::create_dir_all(&repo).unwrap();
        // The provider's markers (IP5): the repo's store mode and the
        // startup lock both say `public`.
        std::fs::write(repo.join(PUBLIC_REPO_MODE_MARKER), PUBLIC_MARKER).unwrap();
        std::fs::write(data_dir.join(PUBLIC_STARTUP_LOCK), PUBLIC_MARKER).unwrap();
        let tag = rand::random::<u64>();
        let started = data_dir.join(format!("stand-in-started-{tag}"));
        let held = data_dir.join(format!("stand-in-held-{tag}"));
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([STAND_IN_TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(STAND_IN_LOCK_ENV, repo.join(PUBLIC_REPO_LOCK))
            .env(STAND_IN_STARTED_ENV, &started)
            .env(STAND_IN_HELD_ENV, &held)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if let Some(gate) = gate {
            command.env(STAND_IN_GATE_ENV, gate);
        }
        let mut child = command.spawn().unwrap();
        let pid = child.id();
        let (sender, exited) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let status = child.wait().map(|status| status.into_raw()).unwrap_or(-1);
            let _ = sender.send(status);
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !started.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the stand-in never started"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        Self {
            pid,
            held,
            exited,
            status: None,
        }
    }

    /// True once the stand-in holds the lock; false if it could not take it
    /// or exited first.
    pub(crate) fn took_lock(&mut self) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            // `fs::write` creates the file before it writes the byte, so an
            // empty read is "not yet answered", not "lock not taken".
            match std::fs::read(&self.held) {
                Ok(held) if !held.is_empty() => return held == b"1",
                _ => {}
            }
            if self.status.is_none() {
                self.status = self.exited.try_recv().ok();
            }
            if self.status.is_some() || std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    pub(crate) fn identity(&self) -> String {
        elastos_common::process_identity::process_identity(self.pid)
            .unwrap()
            .unwrap()
    }

    /// Writes the public coord naming this stand-in, as the provider does
    /// before Kubo's health check.
    pub(crate) fn write_coord(&self, data_dir: &Path, identity: &str) {
        std::fs::write(
            data_dir.join(PUBLIC_COORD_FILE),
            json!({"mode":"public","pid":self.pid,"identity":identity}).to_string(),
        )
        .unwrap();
    }

    /// The wait status once the stand-in exited, if it did within 2 s.
    pub(crate) fn exit_status(&mut self) -> Option<libc::c_int> {
        if self.status.is_none() {
            self.status = self.exited.recv_timeout(Duration::from_secs(2)).ok();
        }
        self.status
    }
}

impl Drop for KuboStandIn {
    fn drop(&mut self) {
        if self.status.is_none() && self.exited.try_recv().is_err() {
            let _ = send_signal(self.pid as i32, libc::SIGKILL);
            let _ = self.exited.recv_timeout(Duration::from_secs(10));
        }
    }
}

fn coord_exists(data_dir: &Path) -> bool {
    data_dir.join(PUBLIC_COORD_FILE).exists()
}

// ── Settings ────────────────────────────────────────────────────────

fn settings_from(config: &str) -> anyhow::Result<PublicIpfsSettings> {
    let home = home();
    std::fs::write(home.data_dir.join("config.toml"), config).unwrap();
    public_ipfs_settings(&home.data_dir)
}

fn defaults() -> Vec<String> {
    DEFAULT_PUBLIC_IPFS_BOOTSTRAP
        .iter()
        .map(|entry| entry.to_string())
        .collect()
}

#[test]
fn public_settings_defaults_when_absent() {
    let home = home();
    let expected = PublicIpfsSettings {
        swarm_port: 4001,
        peers: vec![ELACITY_PREFERRED_PEER.to_string()],
        bootstrap: defaults(),
    };
    assert_eq!(public_ipfs_settings(&home.data_dir).unwrap(), expected);
    assert_eq!(
        settings_from("protected_content = true\n").unwrap(),
        expected
    );
    assert_eq!(DEFAULT_PUBLIC_IPFS_SWARM_PORT, 4001);
    assert_eq!(DEFAULT_PUBLIC_IPFS_PEERS, &[ELACITY_PREFERRED_PEER]);
}

/// Elacity's well-known node: its public QUIC address (it advertises no
/// public TCP address).
const ELACITY_PREFERRED_PEER: &str =
    "/ip4/34.77.31.164/udp/4001/quic-v1/p2p/12D3KooWNieM3HRBJdVqaQucZEJdqA3oWKrKf3Gx3hp2cmtR9GNK";

#[test]
fn public_default_peer_is_elacitys_node() {
    assert_eq!(DEFAULT_PUBLIC_IPFS_PEERS, &[ELACITY_PREFERRED_PEER]);
    let entry = DEFAULT_PUBLIC_IPFS_PEERS[0];
    validate_peer_multiaddr(entry).unwrap();
    let parts: Vec<&str> = entry[1..].split('/').collect();
    assert_eq!(
        parts,
        [
            "ip4",
            "34.77.31.164",
            "udp",
            "4001",
            "quic-v1",
            "p2p",
            "12D3KooWNieM3HRBJdVqaQucZEJdqA3oWKrKf3Gx3hp2cmtR9GNK"
        ]
    );
    assert!(parts[1].parse::<std::net::Ipv4Addr>().is_ok());
    // The peer ID is an identity multihash of an Ed25519 public key.
    let bytes = cid::multibase::Base::Base58Btc.decode(parts[6]).unwrap();
    let multihash = cid::multihash::Multihash::<64>::from_bytes(&bytes).unwrap();
    assert_eq!(multihash.code(), 0x00);
    assert_eq!(multihash.digest().len(), 36);
    assert_eq!(cid::multibase::Base::Base58Btc.encode(&bytes), parts[6]);
}

#[test]
fn public_settings_override_from_config_toml() {
    let settings = settings_from(&format!(
        "public_ipfs_swarm_port = 4101\npublic_ipfs_peers = [\"{TEST_PEER}\"]\n\
         public_ipfs_bootstrap = [\"{}\"]\n",
        DEFAULT_PUBLIC_IPFS_BOOTSTRAP[4]
    ))
    .unwrap();
    assert_eq!(
        settings,
        PublicIpfsSettings {
            swarm_port: 4101,
            peers: vec![TEST_PEER.to_string()],
            bootstrap: vec![DEFAULT_PUBLIC_IPFS_BOOTSTRAP[4].to_string()],
        }
    );
    for port in ["0", "65536", "\"4001\""] {
        assert!(
            settings_from(&format!("public_ipfs_swarm_port = {port}\n")).is_err(),
            "{port}"
        );
    }
}

#[test]
fn public_malformed_entry_is_refused_with_its_text() {
    for entry in [
        "/ip4/198.51.100.7/tcp/4001",
        "ip4/198.51.100.7/tcp/4001/p2p/12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8",
        "/ip4/198.51.100.7//p2p/12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8",
        "/ip4/198.51.100.7/tcp/4001/p2p/bafzbeigai3eoy2ccc7ybwjfz5r3rdxqrinwi4rwytly24tdbh6yk7zslrm",
        "/ip4/198.51.100.7/tcp/4001/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJ0",
        "/ip4/198.51.100.7/tcp/4001/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGA",
    ] {
        for key in ["public_ipfs_peers", "public_ipfs_bootstrap"] {
            let error = settings_from(&format!("{key} = [\"{entry}\"]\n")).unwrap_err();
            let text = format!("{error:#}");
            assert!(text.contains(entry) && text.contains(key), "{text}");
        }
    }
    for config in [
        "public_ipfs_peers = \"one\"\n",
        "public_ipfs_peers = [4001]\n",
    ] {
        assert!(settings_from(config).is_err(), "{config}");
    }
    let too_many = vec![format!("\"{TEST_PEER}\""); 65].join(",");
    assert!(settings_from(&format!("public_ipfs_peers = [{too_many}]\n")).is_err());
}

#[test]
fn public_empty_bootstrap_with_empty_peers_is_refused() {
    let error = settings_from("public_ipfs_bootstrap = []\npublic_ipfs_peers = []\n").unwrap_err();
    assert!(
        format!("{error:#}").contains("public_ipfs_bootstrap"),
        "{error:#}"
    );
    // An empty bootstrap alone keeps the default preferred peer.
    let settings = settings_from("public_ipfs_bootstrap = []\n").unwrap();
    assert_eq!(settings.peers, vec![ELACITY_PREFERRED_PEER.to_string()]);
    assert!(settings.bootstrap.is_empty());
}

#[test]
fn public_empty_bootstrap_with_peers_is_allowed() {
    let settings = settings_from(&format!(
        "public_ipfs_bootstrap = []\npublic_ipfs_peers = [\"{TEST_PEER}\"]\n"
    ))
    .unwrap();
    assert!(settings.bootstrap.is_empty());
    assert_eq!(settings.peers, vec![TEST_PEER.to_string()]);
}

#[test]
fn public_defaults_parse() {
    assert_eq!(DEFAULT_PUBLIC_IPFS_BOOTSTRAP.len(), 7);
    for entry in DEFAULT_PUBLIC_IPFS_BOOTSTRAP
        .iter()
        .chain(DEFAULT_PUBLIC_IPFS_PEERS)
        .chain(&[TEST_PEER])
    {
        validate_peer_multiaddr(entry).unwrap_or_else(|error| panic!("{entry}: {error}"));
    }
}

#[test]
fn public_provider_init_is_the_public_envelope() {
    let home = home();
    let settings = PublicIpfsSettings {
        swarm_port: 4101,
        peers: vec![TEST_PEER.to_string()],
        bootstrap: defaults(),
    };
    let config = public_provider_config(&home.data_dir, &settings).unwrap();
    assert_eq!(config.base_path, home.data_dir.to_str().unwrap());
    assert_eq!(
        config.extra,
        json!({
            "runtime_host_role": "gateway",
            "runtime_store_mode": "public",
            "public_swarm_port": 4101,
            "public_peers": [TEST_PEER],
            "public_bootstrap": defaults(),
        })
    );
    assert!(public_provider_config(Path::new("relative"), &settings).is_err());
}

#[test]
fn public_ipfs_target_not_on_carrier_allow_list() {
    assert!(!crate::carrier::carrier_provider_target_allowed(
        PUBLIC_IPFS_TARGET
    ));
}

// ── Readiness ───────────────────────────────────────────────────────

#[tokio::test]
async fn public_fresh_store_ready_through_bootstrap_without_preferred_peer() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let guard = guard(&home.data_dir).await;
    PublicIpfsStore::start(&home.registry, &home.data_dir, &guard)
        .await
        .unwrap();
    drop(guard);
    let chosen = store.settings.lock().unwrap()[0].clone();
    assert_eq!(chosen.peers, vec![ELACITY_PREFERRED_PEER.to_string()]);
    assert_eq!(chosen.bootstrap, defaults());

    // Two swarm peers, the preferred peer not needed among them: ready.
    let status = PublicIpfsStore::status(&home.registry).await;
    assert_eq!(
        status,
        PublicStoreStatus {
            liveness: StoreLiveness::Running,
            ready: true,
            peers: 2,
        }
    );
    store.last().peers.store(0, Ordering::SeqCst);
    let status = PublicIpfsStore::status(&home.registry).await;
    assert_eq!(status.liveness, StoreLiveness::Running);
    assert!(!status.ready);
    assert_eq!(status.peers, 0);
}

#[tokio::test]
async fn public_publication_ops_reach_the_store_and_keep_their_codes() {
    let home = home();
    let refused = PublicIpfsStore::pin(&home.registry, TEST_ROOT)
        .await
        .unwrap_err();
    assert_eq!(refused.code(), PublicMetadataErrorCode::NotReady);

    let store = Arc::new(FakeBridge::new());
    register_fake(&home.registry, store.clone()).await;
    // A provider not_ready stays not_ready, so the phase reads as a retry.
    let refused = PublicIpfsStore::provide(&home.registry, TEST_ROOT)
        .await
        .unwrap_err();
    assert_eq!(refused.code(), PublicMetadataErrorCode::NotReady);
    let _ = store
        .send_raw(&json!({"op":"ensure_started"}))
        .await
        .unwrap();
    PublicIpfsStore::import_car(&home.registry, TEST_ROOT, b"car")
        .await
        .unwrap();
    PublicIpfsStore::pin(&home.registry, TEST_ROOT)
        .await
        .unwrap();
    PublicIpfsStore::provide(&home.registry, TEST_ROOT)
        .await
        .unwrap();
    assert_eq!(
        store.ops(),
        [
            "runtime_public_provide",
            "ensure_started",
            "runtime_public_import_car",
            "runtime_public_pin",
            "runtime_public_provide"
        ]
    );

    // A stopped store fails each op with that op's own code.
    store.shutdown().await.unwrap();
    for (result, code) in [
        (
            PublicIpfsStore::import_car(&home.registry, TEST_ROOT, b"car").await,
            PublicMetadataErrorCode::ImportFailed,
        ),
        (
            PublicIpfsStore::pin(&home.registry, TEST_ROOT).await,
            PublicMetadataErrorCode::PinFailed,
        ),
        (
            PublicIpfsStore::provide(&home.registry, TEST_ROOT).await,
            PublicMetadataErrorCode::AnnounceFailed,
        ),
    ] {
        assert_eq!(result.unwrap_err().code(), code);
    }
}

// ── Lifecycle ───────────────────────────────────────────────────────

#[tokio::test]
async fn public_start_is_idempotent() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    let first = guard(&home.data_dir).await;
    PublicIpfsStore::start(&home.registry, &home.data_dir, &first)
        .await
        .unwrap();
    drop(first);
    // The provider's healthy Kubo: a real child holding the repo lock,
    // named by an identity-matched coord.
    let mut kubo = KuboStandIn::spawn(&home.data_dir, None);
    assert!(kubo.took_lock());
    let identity = kubo.identity();
    kubo.write_coord(&home.data_dir, &identity);
    let fake = store.last();
    let provide_gate = fake.hold("runtime_public_provide");
    let registry = home.registry.clone();
    let in_flight =
        tokio::spawn(async move { PublicIpfsStore::provide(&registry, TEST_ROOT).await });
    eventually("the provide is in flight", || {
        fake.ops().contains(&"runtime_public_provide".to_string())
    })
    .await;

    let (registry, data_dir) = (home.registry.clone(), home.data_dir.clone());
    let again = tokio::spawn(async move {
        let guard = guard(&data_dir).await;
        let first = PublicIpfsStore::start(&registry, &data_dir, &guard).await;
        let second = PublicIpfsStore::start(&registry, &data_dir, &guard).await;
        (first, second)
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    provide_gate.open();
    in_flight.await.unwrap().unwrap();
    let (first, second) = again.await.unwrap();
    first.unwrap();
    second.unwrap();

    assert_eq!(store.launches(), 1, "the same registration is kept");
    assert!(store.signals().is_empty(), "start never signals");
    assert_eq!(fake.shutdown_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fake.ops(),
        [
            "ensure_started",
            "runtime_public_provide",
            "ensure_started",
            "ensure_started"
        ]
    );
    assert_eq!(kubo.identity(), identity, "the healthy child keeps running");
    assert!(coord_exists(&home.data_dir));
    assert!(registered(&home.registry).await);
}

/// User decision 2026-11-12 10:40: a Ready provider whose process exited is
/// stopped (unregistered, its Kubo cleared by identity) and spawned fresh.
#[tokio::test]
async fn public_start_respawns_a_crashed_provider() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    let first = guard(&home.data_dir).await;
    PublicIpfsStore::start(&home.registry, &home.data_dir, &first)
        .await
        .unwrap();
    drop(first);
    // The crashed provider's Kubo is left behind, named by its coord.
    let mut kubo = KuboStandIn::spawn(&home.data_dir, None);
    assert!(kubo.took_lock());
    kubo.write_coord(&home.data_dir, &kubo.identity());
    let crashed = store.last();
    crashed.crash();

    let guard = guard(&home.data_dir).await;
    PublicIpfsStore::start(&home.registry, &home.data_dir, &guard)
        .await
        .unwrap();
    assert_eq!(
        crashed.shutdown_calls.load(Ordering::SeqCst),
        1,
        "unregistered"
    );
    assert_eq!(store.signals(), [(kubo.pid as i32, libc::SIGTERM)]);
    assert!(kubo.exit_status().is_some(), "its Kubo is cleared");
    assert!(!coord_exists(&home.data_dir));
    assert_eq!(store.launches(), 2, "a fresh provider");
    let fresh = store.last();
    assert!(!Arc::ptr_eq(&fresh, &crashed));
    assert_eq!(fresh.ops(), ["ensure_started"]);
    assert!(registered(&home.registry).await);
}

/// Only a transport failure respawns: a provider that answers, even with an
/// error, keeps its registration.
#[tokio::test]
async fn public_start_keeps_a_provider_that_answers_an_error() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    let guard = guard(&home.data_dir).await;
    PublicIpfsStore::start(&home.registry, &home.data_dir, &guard)
        .await
        .unwrap();
    let fake = store.last();
    fake.fail("ensure_started", "provider request timed out");
    let error = PublicIpfsStore::start(&home.registry, &home.data_dir, &guard)
        .await
        .unwrap_err();
    assert_eq!(error.code(), PublicMetadataErrorCode::NotReady);
    assert_eq!(store.launches(), 1);
    assert_eq!(fake.shutdown_calls.load(Ordering::SeqCst), 0);
    assert!(store.signals().is_empty());
    assert!(registered(&home.registry).await);
}

/// A dispatch fence refusal is no transport failure: the provider keeps its
/// registration and nothing is respawned or signalled.
#[tokio::test]
async fn public_start_keeps_a_provider_behind_a_fence_refusal() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    let guard = guard(&home.data_dir).await;
    PublicIpfsStore::start(&home.registry, &home.data_dir, &guard)
        .await
        .unwrap();
    let fake = store.last();
    let refusal = elastos_runtime::provider::bridge::BridgeError::DispatchRefused(
        "Browser internet access has stopped".into(),
    );
    fake.fail("ensure_started", &refusal.to_string());
    let error = PublicIpfsStore::start(&home.registry, &home.data_dir, &guard)
        .await
        .unwrap_err();
    assert_eq!(error.code(), PublicMetadataErrorCode::NotReady);
    assert_eq!(store.launches(), 1, "no respawn");
    assert_eq!(fake.shutdown_calls.load(Ordering::SeqCst), 0);
    assert!(store.signals().is_empty());
    assert!(registered(&home.registry).await);
}

#[tokio::test]
async fn public_start_on_settling_is_not_ready() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    std::fs::write(home.data_dir.join(PUBLIC_COORD_FILE), b"not json").unwrap();

    // Settling with its shutdown in progress.
    let settling = Arc::new(FakeBridge::new());
    let release = settling.hold_shutdown();
    register_fake(&home.registry, settling.clone()).await;
    let registry = home.registry.clone();
    let unregister = tokio::spawn(async move {
        registry
            .unregister_runtime_provider_target(PUBLIC_IPFS_TARGET)
            .await
    });
    eventually("the shutdown is in progress", || {
        settling.shutdown_calls.load(Ordering::SeqCst) == 1
    })
    .await;
    let guard = guard(&home.data_dir).await;
    let error = PublicIpfsStore::start(&home.registry, &home.data_dir, &guard)
        .await
        .unwrap_err();
    assert_eq!(error.code(), PublicMetadataErrorCode::NotReady);
    assert!(
        error.detail().contains("still stopping"),
        "{}",
        error.detail()
    );
    release.open();
    unregister.await.unwrap().unwrap();

    // Settling, not in progress, and every retry fails.
    let failing = Arc::new(FakeBridge::new());
    failing.script_shutdown(
        (0..4)
            .map(|_| Err(ProviderError::Provider("reap failed".into())))
            .collect(),
    );
    register_fake(&home.registry, failing.clone()).await;
    assert!(home
        .registry
        .unregister_runtime_provider_target(PUBLIC_IPFS_TARGET)
        .await
        .is_err());
    let error = PublicIpfsStore::start(&home.registry, &home.data_dir, &guard)
        .await
        .unwrap_err();
    assert_eq!(error.code(), PublicMetadataErrorCode::NotReady);
    assert_eq!(failing.shutdown_calls.load(Ordering::SeqCst), 4);

    // No spawn and no cleanup: the malformed coord is untouched.
    assert_eq!(store.launches(), 0);
    assert!(store.signals().is_empty());
    assert_eq!(
        std::fs::read(home.data_dir.join(PUBLIC_COORD_FILE)).unwrap(),
        b"not json"
    );
}

#[tokio::test]
async fn public_supervisor_starts_when_enabled() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let supervisor = PublicIpfsSupervisor::spawn(home.registry.clone(), home.data_dir.clone());
    eventually("the first tick starts the store", || store.launches() == 1).await;
    let fake = store.last();
    eventually("the store answers ready", || {
        fake.ops().contains(&"ensure_started".to_string())
    })
    .await;
    assert!(PublicIpfsStore::status(&home.registry).await.ready);
    supervisor.shutdown(&home.registry, &home.data_dir).await;
    assert!(!registered(&home.registry).await);
    assert_eq!(fake.shutdown_calls.load(Ordering::SeqCst), 1);
    assert!(
        consent_enabled(&home.data_dir).unwrap(),
        "shutdown keeps the consent"
    );
}

#[tokio::test(start_paused = true)]
async fn public_supervisor_stops_and_never_restarts_when_disabled() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let supervisor = PublicIpfsSupervisor::spawn(home.registry.clone(), home.data_dir.clone());
    eventually("the first tick starts the store", || store.launches() == 1).await;

    // Withdrawal: the next tick completes it, and nothing restarts after.
    create_withdrawal_marker(&home.data_dir, "principal:test").unwrap();
    tokio::time::sleep(SUPERVISOR_TICK).await;
    eventually("the withdrawal completes", || {
        !marker_exists(&home.data_dir)
    })
    .await;
    assert_eq!(consent_state(&home.data_dir), Some(ConsentState::Disabled));
    assert!(!registered(&home.registry).await);
    tokio::time::sleep(SUPERVISOR_TICK * 5).await;
    assert_eq!(store.launches(), 1, "no restart after the withdrawal");
    assert!(!registered(&home.registry).await);

    // Consent turned off without a marker while running: the tick stops it.
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    tokio::time::sleep(SUPERVISOR_TICK).await;
    eventually("enabled again, it restarts", || store.launches() == 2).await;
    eventually("and is registered", || {
        store.last().ops().contains(&"ensure_started".to_string())
    })
    .await;
    record_consent(&home.data_dir, ConsentState::Disabled).await;
    tokio::time::sleep(SUPERVISOR_TICK).await;
    let second = store.last();
    eventually("the running store stops", || {
        second.shutdown_calls.load(Ordering::SeqCst) == 1
    })
    .await;
    tokio::time::sleep(SUPERVISOR_TICK * 5).await;
    assert_eq!(store.launches(), 2);
    assert!(!registered(&home.registry).await);
    supervisor.shutdown(&home.registry, &home.data_dir).await;
}

#[tokio::test(start_paused = true)]
async fn public_supervisor_shutdown_cancels_before_stop() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let supervisor = PublicIpfsSupervisor::spawn(home.registry.clone(), home.data_dir.clone());
    eventually("the first tick starts the store", || store.launches() == 1).await;
    let fake = store.last();
    eventually("started", || {
        fake.ops().contains(&"ensure_started".to_string())
    })
    .await;

    supervisor.shutdown(&home.registry, &home.data_dir).await;
    assert!(!registered(&home.registry).await);
    assert!(
        consent_enabled(&home.data_dir).unwrap(),
        "the consent stays enabled"
    );
    tokio::time::sleep(SUPERVISOR_TICK * 10).await;
    assert_eq!(store.launches(), 1, "no start after shutdown");
    assert!(!registered(&home.registry).await);
}

#[tokio::test(start_paused = true)]
async fn public_status_timeout_is_unknown_and_never_restarts() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let slow = Arc::new(FakeBridge::new());
    let release = slow.hold("status");
    register_fake(&home.registry, slow.clone()).await;

    let started = tokio::time::Instant::now();
    let status = PublicIpfsStore::status(&home.registry).await;
    assert_eq!(status, PublicStoreStatus::UNKNOWN);
    assert!(started.elapsed() >= STATUS_TIMEOUT);
    // The slot is still owned by the first read: no second read is queued.
    let busy = PublicIpfsStore::status(&home.registry).await;
    assert_eq!(busy.liveness, StoreLiveness::Unknown);

    let supervisor = PublicIpfsSupervisor::spawn(home.registry.clone(), home.data_dir.clone());
    tokio::time::sleep(SUPERVISOR_TICK * 3).await;
    assert_eq!(store.launches(), 0, "Unknown never starts a store");
    assert!(!slow.ops().contains(&"ensure_started".to_string()));
    assert_eq!(slow.ops(), ["status"]);
    assert_eq!(slow.max_reads.load(Ordering::SeqCst), 1);

    release.open();
    eventually("the slot frees once the read drains", || {
        slow.ops().len() >= 2
    })
    .await;
    supervisor.shutdown(&home.registry, &home.data_dir).await;
    assert_eq!(slow.max_reads.load(Ordering::SeqCst), 1);
}

/// A-F3: a shutdown during a tick that is inside its unregister lets that
/// unregister finish: nothing is left settling and the store is stopped.
#[tokio::test(start_paused = true)]
async fn public_supervisor_shutdown_drains_a_tick_inside_unregister() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let supervisor = PublicIpfsSupervisor::spawn(home.registry.clone(), home.data_dir.clone());
    eventually("the first tick starts the store", || store.launches() == 1).await;
    let fake = store.last();
    eventually("started", || {
        fake.ops().contains(&"ensure_started".to_string())
    })
    .await;
    // Consent off: the next tick stops the store, and its unregister waits.
    let release = fake.hold_shutdown();
    record_consent(&home.data_dir, ConsentState::Disabled).await;
    tokio::time::sleep(SUPERVISOR_TICK).await;
    eventually("the tick is inside its unregister", || {
        fake.shutdown_calls.load(Ordering::SeqCst) == 1
    })
    .await;

    let (registry, data_dir) = (home.registry.clone(), home.data_dir.clone());
    let teardown = tokio::spawn(async move { supervisor.shutdown(&registry, &data_dir).await });
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(
        !teardown.is_finished(),
        "teardown drains the tick in flight"
    );
    release.open();
    teardown.await.unwrap();
    assert!(!registered(&home.registry).await);
    // Not left settling: a new registration succeeds.
    register_fake(&home.registry, Arc::new(FakeBridge::new())).await;
    assert_eq!(store.launches(), 1);
}

/// A-F3: a shutdown while an Enable holds the state lock for 45 s waits for
/// it and then stops the store the Enable started.
#[tokio::test(start_paused = true)]
async fn public_supervisor_shutdown_waits_for_an_enable_holding_the_guard() {
    let home = home();
    let store = FakeStore::install(
        &home.data_dir,
        Arc::new(|fake: &FakeBridge| fake.delay("ensure_started", Duration::from_secs(45))),
    );
    let supervisor = PublicIpfsSupervisor::spawn(home.registry.clone(), home.data_dir.clone());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    // The Enable: the guard across a 45 s start.
    let (registry, data_dir) = (home.registry.clone(), home.data_dir.clone());
    let enable = tokio::spawn(async move {
        let guard = guard(&data_dir).await;
        PublicIpfsStore::start(&registry, &data_dir, &guard).await
    });
    eventually("the Enable holds the guard", || store.launches() == 1).await;

    let began = tokio::time::Instant::now();
    supervisor.shutdown(&home.registry, &home.data_dir).await;
    assert!(began.elapsed() > STATE_LOCK_BUDGET, "{:?}", began.elapsed());
    enable.await.unwrap().unwrap();
    assert!(!registered(&home.registry).await, "the store is stopped");
    assert_eq!(store.last().shutdown_calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.launches(), 1);
}

#[tokio::test(start_paused = true)]
async fn public_withdrawal_waits_past_ordinary_budget() {
    let home = home();
    let store = FakeStore::install(
        &home.data_dir,
        Arc::new(|fake: &FakeBridge| fake.delay("ensure_started", Duration::from_secs(45))),
    );
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    // An Enable holds the state lock across a 45 s EnsureStarted.
    let (registry, data_dir) = (home.registry.clone(), home.data_dir.clone());
    let enable = tokio::spawn(async move {
        let guard = guard(&data_dir).await;
        PublicIpfsStore::start(&registry, &data_dir, &guard).await
    });
    eventually("the start holds the lock", || store.launches() == 1).await;

    create_withdrawal_marker(&home.data_dir, "principal:test").unwrap();
    let began = tokio::time::Instant::now();
    let outcome = complete_withdrawal(&home.registry, &home.data_dir).await;
    assert_eq!(outcome, StopOutcome::Stopped);
    assert!(began.elapsed() > STATE_LOCK_BUDGET, "{:?}", began.elapsed());
    enable.await.unwrap().unwrap();
    assert_eq!(consent_state(&home.data_dir), Some(ConsentState::Disabled));
    assert!(!registered(&home.registry).await);
    assert!(!marker_exists(&home.data_dir));
}

#[tokio::test]
async fn public_withdrawal_recovered_after_restart() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    create_withdrawal_marker(&home.data_dir, "principal:test").unwrap();
    // "Startup": an empty registry, the marker and an Enabled consent.
    let supervisor = PublicIpfsSupervisor::spawn(home.registry.clone(), home.data_dir.clone());
    eventually("the first tick completes the withdrawal", || {
        !marker_exists(&home.data_dir)
    })
    .await;
    assert_eq!(consent_state(&home.data_dir), Some(ConsentState::Disabled));
    assert_eq!(store.launches(), 0, "no start before the withdrawal");
    supervisor.shutdown(&home.registry, &home.data_dir).await;
    assert_eq!(store.launches(), 0);
}

// ── Stop transitions ────────────────────────────────────────────────

async fn withdraw(home: &Home) -> StopOutcome {
    if !marker_exists(&home.data_dir) {
        create_withdrawal_marker(&home.data_dir, "principal:test").unwrap();
    }
    complete_withdrawal(&home.registry, &home.data_dir).await
}

#[tokio::test]
async fn public_stop_marker_empty_registry_no_daemon() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    assert_eq!(withdraw(&home).await, StopOutcome::Stopped);
    assert_eq!(consent_state(&home.data_dir), Some(ConsentState::Disabled));
    assert!(!marker_exists(&home.data_dir));
    assert!(store.signals().is_empty());
    // Idempotent: a second Stop is Stopped too.
    let guard = guard(&home.data_dir).await;
    assert_eq!(
        PublicIpfsStore::stop(&home.registry, &home.data_dir, &guard).await,
        StopOutcome::Stopped
    );
}

/// A force-reaped provider (P1): its owned Kubo was started and its coord
/// written, but it has not yet taken the repo lock.
async fn force_reaped_provider(home: &Home) {
    let reaped = Arc::new(FakeBridge::new());
    reaped.script_shutdown(vec![Err(ProviderError::Provider(
        "provider request timed out".into(),
    ))]);
    register_fake(&home.registry, reaped).await;
}

#[tokio::test]
async fn public_stop_pre_lock_owned_child_is_not_left_running() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let gate = home.data_dir.join("stand-in-gate");
    let mut kubo = KuboStandIn::spawn(&home.data_dir, Some(&gate));
    kubo.write_coord(&home.data_dir, &kubo.identity());
    force_reaped_provider(&home).await;
    assert_eq!(public_repo_lock_holder(&home.data_dir).unwrap(), None);

    assert_eq!(withdraw(&home).await, StopOutcome::Stopped);
    // Stopped is reported only after its generation is gone.
    assert!(elastos_common::process_identity::process_identity(kubo.pid)
        .unwrap()
        .is_none());
    assert_eq!(store.signals(), [(kubo.pid as i32, libc::SIGTERM)]);
    let status = kubo.exit_status().expect("the owned child exited");
    assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGTERM);
    // Releasing the gate now shows it never took the lock.
    std::fs::write(&gate, b"").unwrap();
    assert!(!kubo.took_lock());
    assert_eq!(public_repo_lock_holder(&home.data_dir).unwrap(), None);
    assert!(!coord_exists(&home.data_dir));
    assert!(!marker_exists(&home.data_dir));
    assert!(!registered(&home.registry).await);
    assert_eq!(consent_state(&home.data_dir), Some(ConsentState::Disabled));
}

#[tokio::test]
async fn public_stop_owned_child_with_unreadable_identity_is_pending() {
    let home = home();
    let unreadable: test_seams::Identity =
        Arc::new(|_| Err(io::Error::from_raw_os_error(libc::EACCES)));
    let store = FakeStore::install_with(&home.data_dir, no_configure(), false, Some(unreadable));
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let gate = home.data_dir.join("stand-in-gate");
    let mut kubo = KuboStandIn::spawn(&home.data_dir, Some(&gate));
    kubo.write_coord(&home.data_dir, &kubo.identity());

    let StopOutcome::Pending(reason) = withdraw(&home).await else {
        panic!("an unreadable identity must keep Stop pending");
    };
    assert!(reason.contains("cannot be checked"), "{reason}");
    assert!(store.signals().is_empty());
    assert!(coord_exists(&home.data_dir));
    let marker = read_withdrawal_marker(&home.data_dir).unwrap().unwrap();
    assert_eq!(marker.stop_pending.as_deref(), Some(reason.as_str()));
    assert_eq!(consent_state(&home.data_dir), Some(ConsentState::Disabled));
    assert!(kubo.exit_status().is_none(), "never signalled");
}

#[tokio::test]
async fn public_restart_with_pre_lock_owned_child() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    create_withdrawal_marker(&home.data_dir, "principal:test").unwrap();
    let gate = home.data_dir.join("stand-in-gate");
    let mut kubo = KuboStandIn::spawn(&home.data_dir, Some(&gate));
    kubo.write_coord(&home.data_dir, &kubo.identity());

    // A restarted Home: empty registry; the first tick cleans it up.
    let supervisor = PublicIpfsSupervisor::spawn(home.registry.clone(), home.data_dir.clone());
    eventually("the first tick completes the withdrawal", || {
        !marker_exists(&home.data_dir)
    })
    .await;
    assert!(kubo.exit_status().is_some());
    assert_eq!(store.signals(), [(kubo.pid as i32, libc::SIGTERM)]);
    std::fs::write(&gate, b"").unwrap();
    assert!(!kubo.took_lock());
    assert!(!coord_exists(&home.data_dir));
    assert_eq!(store.launches(), 0);
    assert_eq!(consent_state(&home.data_dir), Some(ConsentState::Disabled));
    supervisor.shutdown(&home.registry, &home.data_dir).await;
}

#[tokio::test]
async fn public_stop_marker_empty_registry_orphan() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let mut orphan = KuboStandIn::spawn(&home.data_dir, None);
    assert!(orphan.took_lock());
    assert_eq!(
        public_repo_lock_holder(&home.data_dir).unwrap(),
        Some(orphan.pid as i32)
    );

    assert_eq!(withdraw(&home).await, StopOutcome::Stopped);
    assert_eq!(store.signals(), [(orphan.pid as i32, libc::SIGTERM)]);
    assert!(orphan.exit_status().is_some());
    assert_eq!(public_repo_lock_holder(&home.data_dir).unwrap(), None);
    assert!(!marker_exists(&home.data_dir));
}

/// A-F1 (IP5): a lock holder at the public paths whose repo or startup-lock
/// marker is missing or another store's is never signalled.
#[tokio::test]
async fn public_stop_refuses_a_holder_without_public_markers() {
    let repo_marker =
        |data_dir: &Path| data_dir.join(PUBLIC_REPO_DIR).join(PUBLIC_REPO_MODE_MARKER);
    let startup_lock = |data_dir: &Path| data_dir.join(PUBLIC_STARTUP_LOCK);
    type Unmark = fn(&Path, &Path);
    let cases: [(&str, Unmark); 4] = [
        ("no repo marker", |repo, _| {
            std::fs::remove_file(repo).unwrap()
        }),
        ("private repo marker", |repo, _| {
            std::fs::write(repo, b"private").unwrap()
        }),
        ("no startup lock", |_, lock| {
            std::fs::remove_file(lock).unwrap()
        }),
        ("unmarked startup lock", |_, lock| {
            std::fs::write(lock, b"").unwrap()
        }),
    ];
    for (case, unmark) in cases {
        let home = home();
        let store = FakeStore::install(&home.data_dir, no_configure());
        record_consent(&home.data_dir, ConsentState::Enabled).await;
        let mut holder = KuboStandIn::spawn(&home.data_dir, None);
        assert!(holder.took_lock(), "{case}");
        unmark(&repo_marker(&home.data_dir), &startup_lock(&home.data_dir));

        let StopOutcome::Pending(reason) = withdraw(&home).await else {
            panic!("{case}: an unmarked repo must keep Stop pending");
        };
        assert!(reason.contains("nothing signalled"), "{case}: {reason}");
        assert!(store.signals().is_empty(), "{case}: never signalled");
        assert!(holder.exit_status().is_none(), "{case}: still running");
        assert!(marker_exists(&home.data_dir), "{case}");
        assert_eq!(
            public_repo_lock_holder(&home.data_dir).unwrap(),
            Some(holder.pid as i32),
            "{case}"
        );
    }
}

/// A-F2: a candidate whose PID is reused during the TERM wait, while another
/// candidate keeps the wait open, is never sent SIGKILL.
#[tokio::test]
async fn public_stop_never_kills_a_pid_reused_during_the_term_wait() {
    let home = home();
    // The owned child exits on SIGTERM; afterwards its PID names another
    // process (a reuse), which only the identity reader can tell.
    let gate = home.data_dir.join("never-opened");
    let owned = KuboStandIn::spawn(&home.data_dir, Some(&gate));
    let owned_pid = owned.pid;
    let reused: test_seams::Identity = Arc::new(move |pid| {
        let current = elastos_common::process_identity::process_identity(pid)?;
        if pid == owned_pid && current.is_none() {
            return Ok(Some("reused-generation".into()));
        }
        Ok(current)
    });
    let store = FakeStore::install_with(&home.data_dir, no_configure(), false, Some(reused));
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    owned.write_coord(&home.data_dir, &owned.identity());
    // The repo lock's holder ignores SIGTERM and keeps the wait open.
    let mut stubborn = KuboStandIn::spawn(&home.data_dir, None);
    assert!(stubborn.took_lock());
    store.ignore_term(stubborn.pid);

    assert_eq!(withdraw(&home).await, StopOutcome::Stopped);
    let signals = store.signals();
    assert_eq!(
        signals,
        [
            (owned_pid as i32, libc::SIGTERM),
            (stubborn.pid as i32, libc::SIGTERM),
            (stubborn.pid as i32, libc::SIGKILL),
        ],
        "the reused PID is re-checked and never killed"
    );
    let status = stubborn.exit_status().expect("SIGKILL stopped the holder");
    assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL);
    assert!(!marker_exists(&home.data_dir));
    drop(owned);
}

#[tokio::test(start_paused = true)]
async fn public_stop_reaped_then_unregister_error_then_retry() {
    let home = home();
    let reaped = Arc::new(FakeBridge::new());
    reaped.script_shutdown(vec![
        Err(ProviderError::Provider("provider request timed out".into())),
        Ok(()),
    ]);
    register_fake(&home.registry, reaped.clone()).await;
    let guard = guard(&home.data_dir).await;
    assert_eq!(
        PublicIpfsStore::stop(&home.registry, &home.data_dir, &guard).await,
        StopOutcome::Stopped
    );
    assert_eq!(reaped.shutdown_calls.load(Ordering::SeqCst), 2);
    assert!(!registered(&home.registry).await);
    // The entry is gone, not Settling: a new registration succeeds.
    register_fake(&home.registry, Arc::new(FakeBridge::new())).await;
}

#[tokio::test(start_paused = true)]
async fn public_stop_provider_exited_between_calls() {
    let home = home();
    let exited = Arc::new(FakeBridge::new());
    exited.script_shutdown(vec![
        Err(ProviderError::Provider("provider process exited".into())),
        Ok(()),
    ]);
    register_fake(&home.registry, exited.clone()).await;
    let guard = guard(&home.data_dir).await;
    assert_eq!(
        PublicIpfsStore::stop(&home.registry, &home.data_dir, &guard).await,
        StopOutcome::Stopped
    );
    assert_eq!(exited.shutdown_calls.load(Ordering::SeqCst), 2);
    assert!(!registered(&home.registry).await);
}

#[tokio::test]
async fn public_stop_settling_in_progress_is_pending() {
    let home = home();
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let settling = Arc::new(FakeBridge::new());
    let release = settling.hold_shutdown();
    register_fake(&home.registry, settling.clone()).await;
    let registry = home.registry.clone();
    let unregister = tokio::spawn(async move {
        registry
            .unregister_runtime_provider_target(PUBLIC_IPFS_TARGET)
            .await
    });
    eventually("the shutdown is in progress", || {
        settling.shutdown_calls.load(Ordering::SeqCst) == 1
    })
    .await;

    assert_eq!(
        withdraw(&home).await,
        StopOutcome::Pending("shutdown already settling".into())
    );
    let marker = read_withdrawal_marker(&home.data_dir).unwrap().unwrap();
    assert_eq!(
        marker.stop_pending.as_deref(),
        Some("shutdown already settling")
    );
    release.open();
    unregister.await.unwrap().unwrap();
    // The next completion finds it settled.
    assert_eq!(withdraw(&home).await, StopOutcome::Stopped);
    assert!(!marker_exists(&home.data_dir));
}

#[tokio::test]
async fn public_stop_unkillable_holder_is_pending() {
    let home = home();
    let store = FakeStore::install_with(&home.data_dir, no_configure(), true, None);
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let mut holder = KuboStandIn::spawn(&home.data_dir, None);
    assert!(holder.took_lock());
    holder.write_coord(&home.data_dir, &holder.identity());

    let StopOutcome::Pending(reason) = withdraw(&home).await else {
        panic!("an unkillable holder must keep Stop pending");
    };
    assert!(reason.contains("could not be signalled"), "{reason}");
    assert_eq!(store.signals(), [(holder.pid as i32, libc::SIGTERM)]);
    assert!(marker_exists(&home.data_dir));
    assert!(coord_exists(&home.data_dir));
    assert_eq!(
        public_repo_lock_holder(&home.data_dir).unwrap(),
        Some(holder.pid as i32)
    );
}

#[tokio::test]
async fn public_stop_unrelated_coord_pid_preserved() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    // A live process named by the coord, with another identity (pid reuse),
    // that never holds the repo lock.
    let gate = home.data_dir.join("never-opened");
    let mut unrelated = KuboStandIn::spawn(&home.data_dir, Some(&gate));
    unrelated.write_coord(&home.data_dir, "macos:1:1");

    assert_eq!(withdraw(&home).await, StopOutcome::Stopped);
    assert!(store.signals().is_empty(), "pid reuse is never signalled");
    assert!(unrelated.exit_status().is_none());
    assert!(
        elastos_common::process_identity::process_identity(unrelated.pid)
            .unwrap()
            .is_some()
    );
    assert!(!coord_exists(&home.data_dir), "the stale coord is removed");
    assert!(!marker_exists(&home.data_dir));
}

// ── Bounded under load (IP4.2) ──────────────────────────────────────

/// When the caller of Stop goes away: never, while waiting for the lock, or
/// while the stop is in flight.
#[derive(Clone, Copy, Debug)]
enum CallerCancel {
    Never,
    WhileWaiting,
    WhileStopping,
}

async fn stop_not_delayed_by_queued_publication(cancel: CallerCancel) {
    let home = home();
    let store = FakeStore::install(
        &home.data_dir,
        Arc::new(|fake: &FakeBridge| {
            // Mint A's Provide never answers on its own.
            fake.hold("runtime_public_provide");
        }),
    );
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    {
        let guard = guard(&home.data_dir).await;
        PublicIpfsStore::start(&home.registry, &home.data_dir, &guard)
            .await
            .unwrap();
    }
    let fake = store.last();
    let mint = |registry: Arc<ProviderRegistry>| {
        tokio::spawn(async move { PublicIpfsStore::provide(&registry, TEST_ROOT).await })
    };
    let mint_a = mint(home.registry.clone());
    eventually("mint A's Provide is in flight", || {
        fake.ops()
            .iter()
            .filter(|op| *op == "runtime_public_provide")
            .count()
            == 1
    })
    .await;
    let mint_b = mint(home.registry.clone());
    eventually("mint B's Provide is queued", || {
        fake.ops()
            .iter()
            .filter(|op| *op == "runtime_public_provide")
            .count()
            == 2
    })
    .await;
    let polling = Arc::new(AtomicBool::new(true));
    let poller = {
        let (registry, polling) = (home.registry.clone(), polling.clone());
        tokio::spawn(async move {
            while polling.load(Ordering::SeqCst) {
                let _ = PublicIpfsStore::status(&registry).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        })
    };
    tokio::time::sleep(Duration::from_secs(7)).await;

    // Disable, as the route does: the marker, then a detached completion.
    let began = tokio::time::Instant::now();
    create_withdrawal_marker(&home.data_dir, "principal:test").unwrap();
    let completion = {
        let (registry, data_dir) = (home.registry.clone(), home.data_dir.clone());
        tokio::spawn(async move { complete_withdrawal(&registry, &data_dir).await })
    };
    let caller = tokio::spawn(async move { completion.await.unwrap() });
    let outcome = match cancel {
        CallerCancel::Never => caller.await.unwrap(),
        CallerCancel::WhileWaiting | CallerCancel::WhileStopping => {
            if matches!(cancel, CallerCancel::WhileStopping) {
                eventually("the stop is in flight", || {
                    fake.shutdown_calls.load(Ordering::SeqCst) >= 1
                })
                .await;
            }
            caller.abort();
            eventually("the detached completion ends", || {
                !marker_exists(&home.data_dir)
            })
            .await;
            StopOutcome::Stopped
        }
    };
    assert_eq!(outcome, StopOutcome::Stopped, "{cancel:?}");
    assert!(
        began.elapsed() <= Duration::from_secs(45),
        "{cancel:?}: {:?}",
        began.elapsed()
    );
    assert_eq!(consent_state(&home.data_dir), Some(ConsentState::Disabled));
    assert!(!registered(&home.registry).await);
    assert_eq!(public_repo_lock_holder(&home.data_dir).unwrap(), None);
    assert!(!marker_exists(&home.data_dir));
    // Both Provides failed, so no approval can follow either mint.
    assert!(mint_a.await.unwrap().is_err());
    assert!(mint_b.await.unwrap().is_err());
    polling.store(false, Ordering::SeqCst);
    poller.await.unwrap();
    assert_eq!(
        fake.max_reads.load(Ordering::SeqCst),
        1,
        "one status read at most"
    );
    assert_eq!(store.launches(), 1);
}

#[tokio::test(start_paused = true)]
async fn public_stop_not_delayed_by_queued_publication() {
    stop_not_delayed_by_queued_publication(CallerCancel::Never).await;
}

#[tokio::test(start_paused = true)]
async fn public_stop_not_delayed_by_queued_publication_caller_cancelled_while_waiting() {
    stop_not_delayed_by_queued_publication(CallerCancel::WhileWaiting).await;
}

#[tokio::test(start_paused = true)]
async fn public_stop_not_delayed_by_queued_publication_caller_cancelled_while_stopping() {
    stop_not_delayed_by_queued_publication(CallerCancel::WhileStopping).await;
}

// ── A5: the closed gate (amendment §2.1, A45-F1) ────────────────────

/// A started store on `home`, through the fake launcher.
async fn started(home: &Home, store: &FakeStore) -> Arc<FakeBridge> {
    let guard = guard(&home.data_dir).await;
    PublicIpfsStore::start(&home.registry, &home.data_dir, &guard)
        .await
        .unwrap();
    drop(guard);
    let fake = store.last();
    assert!(fake.ops().contains(&"ensure_started".to_string()));
    fake
}

#[tokio::test]
async fn public_gate_closed_start_and_enable_paths_refuse() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    close_public_metadata_gate(&home.data_dir);
    let guard = guard(&home.data_dir).await;
    let refused = PublicIpfsStore::start(&home.registry, &home.data_dir, &guard)
        .await
        .unwrap_err();
    assert_eq!(refused.code(), PublicMetadataErrorCode::Disabled);
    assert_eq!(
        refused.detail(),
        crate::public_metadata_consent::PUBLIC_METADATA_OFF
    );
    assert_eq!(store.launches(), 0);
}

/// A start that already holds the guard when the gate closes runs to its
/// own end; no phase is admitted after; the next tick stops the store.
#[tokio::test]
async fn public_gate_closes_during_running_start() {
    let home = home();
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let held = Arc::new(StdMutex::new(None::<Arc<Gate>>));
    let holds = held.clone();
    let store = FakeStore::install(
        &home.data_dir,
        Arc::new(move |fake: &FakeBridge| {
            *holds.lock().unwrap() = Some(fake.hold("ensure_started"));
        }),
    );
    let start = {
        let (registry, data_dir) = (home.registry.clone(), home.data_dir.clone());
        tokio::spawn(async move {
            let guard = acquire_public_state_lock(&data_dir, STATE_LOCK_BUDGET)
                .await
                .unwrap();
            PublicIpfsStore::start(&registry, &data_dir, &guard).await
        })
    };
    eventually("the start reaches EnsureStarted", || {
        store.launches() == 1 && store.last().ops().contains(&"ensure_started".to_string())
    })
    .await;
    close_public_metadata_gate(&home.data_dir);
    held.lock().unwrap().take().unwrap().open();
    start.await.unwrap().unwrap();

    assert_eq!(
        phase_allowed(&home.data_dir).unwrap_err().code(),
        PublicMetadataErrorCode::Disabled
    );
    supervise_once(&home.registry, &home.data_dir).await;
    assert_eq!(store.last().shutdown_calls.load(Ordering::SeqCst), 1);
    assert!(!registered(&home.registry).await);
    assert_eq!(consent_state(&home.data_dir), Some(ConsentState::Enabled));
}

/// The closed-gate cleanup waits for a guard holder, then runs.
#[tokio::test]
async fn public_gate_closes_while_guard_held() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let fake = started(&home, &store).await;
    close_public_metadata_gate(&home.data_dir);
    let held = guard(&home.data_dir).await;
    let tick = {
        let (registry, data_dir) = (home.registry.clone(), home.data_dir.clone());
        tokio::spawn(async move { supervise_once(&registry, &data_dir).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fake.shutdown_calls.load(Ordering::SeqCst), 0);
    assert!(registered(&home.registry).await);
    drop(held);
    tick.await.unwrap();
    assert_eq!(fake.shutdown_calls.load(Ordering::SeqCst), 1);
    assert!(!registered(&home.registry).await);
}

/// A `Pending` Stop is retried by a later tick; meanwhile the paused card's
/// last-known state stays running.
#[tokio::test(start_paused = true)]
async fn public_gate_closed_stop_pending_retried() {
    let home = home();
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let stubborn = Arc::new(FakeBridge::new());
    let release = stubborn.hold_shutdown();
    register_fake(&home.registry, stubborn.clone()).await;
    {
        let guard = guard(&home.data_dir).await;
        PublicIpfsStore::start(&home.registry, &home.data_dir, &guard)
            .await
            .unwrap();
    }
    let read = PublicIpfsStore::status(&home.registry).await;
    assert_eq!(read.liveness, StoreLiveness::Running);
    close_public_metadata_gate(&home.data_dir);

    // An unregister already in flight keeps this tick's Stop pending.
    let registry = home.registry.clone();
    let unregister = tokio::spawn(async move {
        registry
            .unregister_runtime_provider_target(PUBLIC_IPFS_TARGET)
            .await
    });
    eventually("the shutdown is in progress", || {
        stubborn.shutdown_calls.load(Ordering::SeqCst) == 1
    })
    .await;
    supervise_once(&home.registry, &home.data_dir).await;
    assert_eq!(
        PublicIpfsStore::last_known(&home.registry).map(|status| status.liveness),
        Some(StoreLiveness::Running),
        "the paused card keeps the last-known running state"
    );
    release.open();
    unregister.await.unwrap().unwrap();
    // A later tick reaches Stopped.
    supervise_once(&home.registry, &home.data_dir).await;
    assert!(!registered(&home.registry).await);
    assert!(
        !home
            .registry
            .has_runtime_provider_target_registration(PUBLIC_IPFS_TARGET)
            .await
    );
    assert_eq!(consent_state(&home.data_dir), Some(ConsentState::Enabled));
}

/// The cleanup does not match on liveness: a store whose status is still
/// unknown is stopped too.
#[tokio::test(start_paused = true)]
async fn public_gate_closed_supervisor_stops_unknown_liveness() {
    let home = home();
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let slow = Arc::new(FakeBridge::new());
    let _held = slow.hold("status");
    register_fake(&home.registry, slow.clone()).await;
    assert_eq!(
        PublicIpfsStore::status(&home.registry).await.liveness,
        StoreLiveness::Unknown
    );
    close_public_metadata_gate(&home.data_dir);
    supervise_once(&home.registry, &home.data_dir).await;
    assert!(slow.shutdown_calls.load(Ordering::SeqCst) >= 1);
    assert!(!registered(&home.registry).await);
}

/// A registration left Settling is unregistered again by the cleanup.
#[tokio::test(start_paused = true)]
async fn public_gate_closed_supervisor_stops_settling_registration() {
    let home = home();
    let reaped = Arc::new(FakeBridge::new());
    // The first shutdown fails after the reap: the entry stays Settling.
    reaped.script_shutdown(vec![
        Err(ProviderError::Provider("provider request timed out".into())),
        Ok(()),
    ]);
    register_fake(&home.registry, reaped.clone()).await;
    assert!(home
        .registry
        .unregister_runtime_provider_target(PUBLIC_IPFS_TARGET)
        .await
        .is_err());
    assert!(!registered(&home.registry).await);
    assert!(
        home.registry
            .has_runtime_provider_target_registration(PUBLIC_IPFS_TARGET)
            .await,
        "the entry is Settling"
    );
    close_public_metadata_gate(&home.data_dir);
    supervise_once(&home.registry, &home.data_dir).await;
    assert_eq!(reaped.shutdown_calls.load(Ordering::SeqCst), 2);
    assert!(
        !home
            .registry
            .has_runtime_provider_target_registration(PUBLIC_IPFS_TARGET)
            .await
    );
}

/// An owned public Kubo left with no registration (an orphan) is found by
/// its held repo lock and stopped by identity.
#[tokio::test]
async fn public_gate_closed_supervisor_stops_orphan_owned_kubo() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let mut orphan = KuboStandIn::spawn(&home.data_dir, None);
    assert!(orphan.took_lock());
    close_public_metadata_gate(&home.data_dir);

    supervise_once(&home.registry, &home.data_dir).await;
    assert_eq!(store.signals(), [(orphan.pid as i32, libc::SIGTERM)]);
    assert!(orphan.exit_status().is_some());
    assert_eq!(public_repo_lock_holder(&home.data_dir).unwrap(), None);
    // Paused, not withdrawn.
    assert_eq!(consent_state(&home.data_dir), Some(ConsentState::Enabled));
    assert!(!marker_exists(&home.data_dir));
}

/// While closed, consent Enabled never starts the store, and a Home with no
/// public state is not touched at all.
#[tokio::test(start_paused = true)]
async fn public_gate_closed_never_restarts() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let before = read_consent(&home.data_dir).unwrap();
    close_public_metadata_gate(&home.data_dir);
    let supervisor = PublicIpfsSupervisor::spawn(home.registry.clone(), home.data_dir.clone());
    tokio::time::sleep(SUPERVISOR_TICK * 5).await;
    assert_eq!(store.launches(), 0);
    assert!(!registered(&home.registry).await);
    assert_eq!(read_consent(&home.data_dir).unwrap(), before);
    supervisor.shutdown(&home.registry, &home.data_dir).await;
    assert_eq!(store.launches(), 0);

    // A default Home (nothing offered, nothing ever run) gets no state lock.
    let fresh = safe_ancestor_tempdir();
    let data_dir = fresh.path().join("data");
    owner_only_dir(&data_dir);
    let registry = Arc::new(ProviderRegistry::new());
    supervise_once(&registry, &data_dir).await;
    assert!(!data_dir.join("public-ipfs").exists());
}

/// The withdrawal completion, the marker-first branch and the shutdown stop
/// are not gated.
#[tokio::test]
async fn public_gate_closed_withdrawal_and_shutdown_still_run() {
    let home = home();
    let store = FakeStore::install(&home.data_dir, no_configure());
    record_consent(&home.data_dir, ConsentState::Enabled).await;
    let fake = started(&home, &store).await;
    close_public_metadata_gate(&home.data_dir);
    create_withdrawal_marker(&home.data_dir, "principal:test").unwrap();
    supervise_once(&home.registry, &home.data_dir).await;
    assert!(!marker_exists(&home.data_dir));
    assert_eq!(consent_state(&home.data_dir), Some(ConsentState::Disabled));
    assert_eq!(fake.shutdown_calls.load(Ordering::SeqCst), 1);

    // Shutdown with the gate closed stops a store that runs.
    let other = self::home();
    let store = FakeStore::install(&other.data_dir, no_configure());
    record_consent(&other.data_dir, ConsentState::Enabled).await;
    let fake = started(&other, &store).await;
    let supervisor = PublicIpfsSupervisor::spawn(other.registry.clone(), other.data_dir.clone());
    close_public_metadata_gate(&other.data_dir);
    supervisor.shutdown(&other.registry, &other.data_dir).await;
    assert!(fake.shutdown_calls.load(Ordering::SeqCst) >= 1);
    assert!(!registered(&other.registry).await);
}

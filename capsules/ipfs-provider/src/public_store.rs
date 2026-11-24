//! The public IPFS store: a second Kubo repo, separate from the private local
//! store, that keeps and announces only the public metadata Runtime gives it.
//!
//! Runtime selects this mode with `extra.runtime_store_mode = "public"` at
//! Init. The instance then owns `ipfs-public-repo/`, `ipfs-public-coords.json`
//! and `ipfs-public-startup.lock`, each marked `public`, and never reads the
//! private store's files. Kubo runs online as a DHT client with no gateway. The
//! provider spawns it as its own child, proves that ownership in the coord from
//! spawn on, and stops and reaps only that child.

use super::{
    kubo_rpc_url, repo_lock_is_free, rewrite_kubo_config, try_flock_exclusive, IpfsProvider,
    KuboState, Request, Response, BASE64, HEALTH_POLL_INTERVAL, PROVIDER_VERSION,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

pub(crate) const PUBLIC_REPO_DIR: &str = "ipfs-public-repo";
pub(crate) const PUBLIC_COORD_FILE: &str = "ipfs-public-coords.json";
pub(crate) const PUBLIC_LOCK_FILE: &str = "ipfs-public-startup.lock";
/// The repo's store-mode marker file, beside Kubo's own files.
pub(crate) const STORE_MODE_MARKER: &str = "elastos-store-mode";
/// The identity of every public repo, coord and lock.
pub(crate) const PUBLIC_MARKER: &str = "public";

/// One whole-operation deadline per op: every RPC and wait inside the op
/// uses the time that remains of it.
pub(crate) const PUBLIC_START_DEADLINE: Duration = Duration::from_secs(50);
pub(crate) const PUBLIC_IMPORT_DEADLINE: Duration = Duration::from_secs(20);
pub(crate) const PUBLIC_PIN_DEADLINE: Duration = Duration::from_secs(20);
pub(crate) const PUBLIC_PROVIDE_DEADLINE: Duration = Duration::from_secs(120);
pub(crate) const PUBLIC_READ_DEADLINE: Duration = Duration::from_secs(5);
/// Protocol shutdown: SIGTERM, this wait, then SIGKILL and reap, all inside
/// `PUBLIC_SHUTDOWN_BOUND`, below the bridge's 5 s shutdown timeout.
pub(crate) const PUBLIC_TERM_WAIT: Duration = Duration::from_secs(3);
pub(crate) const PUBLIC_SHUTDOWN_BOUND: Duration = Duration::from_millis(4400);
/// Time kept back from a failed start to kill and reap the child.
const START_STOP_RESERVE: Duration = Duration::from_millis(1000);
/// The least time a kill gets to reap, even past the deadline.
const MIN_REAP_WAIT: Duration = Duration::from_millis(200);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(20);
const HEALTH_CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// One public metadata CAR (cover plus folder) is at most this size.
pub(crate) const MAX_PUBLIC_CAR_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CAR_HEADER_BYTES: u64 = 4096;
const MAX_CAR_ROOTS: u64 = 16;
/// Kubo's answer streams (import events, provide query events) are read to
/// their end, up to this size.
const MAX_EVENT_STREAM_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STDERR_TAIL: usize = 2048;
const MAX_PUBLIC_ADDRESSES: usize = 64;
const MAX_PUBLIC_ADDRESS_LEN: usize = 512;
const MAX_PROVIDE_TIMEOUT_SECS: u64 = 120;

// ── Mode selection ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreMode {
    Private,
    Public,
}

impl StoreMode {
    /// The store mode belongs to Runtime's private Init envelope, as the host
    /// role does: never a top-level option, environment variable or argv.
    pub(crate) fn from_init(config: &Value) -> Result<Self, ()> {
        if config.get("runtime_store_mode").is_some() {
            return Err(());
        }
        match config
            .get("extra")
            .and_then(|extra| extra.get("runtime_store_mode"))
        {
            None => Ok(Self::Private),
            Some(Value::String(mode)) if mode == "private" => Ok(Self::Private),
            Some(Value::String(mode)) if mode == "public" => Ok(Self::Public),
            Some(_) => Err(()),
        }
    }
}

const PUBLIC_INIT_KEYS: [&str; 3] = ["public_swarm_port", "public_peers", "public_bootstrap"];

/// The public store's Init settings: its swarm port and the two peer lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicInit {
    pub(crate) swarm_port: u16,
    pub(crate) peers: Vec<String>,
    pub(crate) bootstrap: Vec<String>,
}

impl PublicInit {
    /// Whether Init names any public setting, at the top level or in `extra`.
    pub(crate) fn requested(config: &Value) -> bool {
        PUBLIC_INIT_KEYS.iter().any(|key| {
            config.get(key).is_some()
                || config
                    .get("extra")
                    .and_then(|extra| extra.get(key))
                    .is_some()
        })
    }

    pub(crate) fn from_init(config: &Value) -> Result<Self, String> {
        if PUBLIC_INIT_KEYS.iter().any(|key| config.get(key).is_some()) {
            return Err("Public IPFS settings belong to the Runtime Init envelope".into());
        }
        let extra = config.get("extra").unwrap_or(&Value::Null);
        let swarm_port = extra
            .get("public_swarm_port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .ok_or("Public IPFS needs a swarm port from 1 to 65535")?;
        let peers = public_addresses(extra, "public_peers")?;
        let bootstrap = public_addresses(extra, "public_bootstrap")?;
        if peers.is_empty() && bootstrap.is_empty() {
            return Err("Public IPFS needs a bootstrap or a preferred peer".into());
        }
        Ok(Self {
            swarm_port,
            peers,
            bootstrap,
        })
    }
}

fn public_addresses(extra: &Value, key: &str) -> Result<Vec<String>, String> {
    let Some(value) = extra.get(key) else {
        return Ok(Vec::new());
    };
    let invalid = || format!("{key} must list at most {MAX_PUBLIC_ADDRESSES} /p2p/ addresses");
    let items = value.as_array().ok_or_else(invalid)?;
    if items.len() > MAX_PUBLIC_ADDRESSES {
        return Err(invalid());
    }
    items
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|address| p2p_peer_id(address).is_some())
                .map(str::to_owned)
                .ok_or_else(invalid)
        })
        .collect()
}

/// The peer ID of a multiaddr that ends in `/p2p/<base58 peer id>`.
fn p2p_peer_id(address: &str) -> Option<&str> {
    const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if address.len() > MAX_PUBLIC_ADDRESS_LEN
        || !address.starts_with('/')
        || !address.bytes().all(|b| b.is_ascii_graphic())
    {
        return None;
    }
    let (_, id) = address.rsplit_once("/p2p/")?;
    ((40..=128).contains(&id.len()) && id.bytes().all(|b| BASE58.contains(&b))).then_some(id)
}

// ── Kubo daemon and config ──────────────────────────────────────────

/// Kubo runs online for the public store: no `--offline`, and no
/// `--enable-gc`, so pinned metadata stays.
pub(crate) fn public_daemon_args(api_port: u16) -> [String; 3] {
    [
        "daemon".into(),
        "--api".into(),
        format!("/ip4/127.0.0.1/tcp/{api_port}"),
    ]
}

/// Sets the repo config of the public store: no gateway and no fetch, a
/// loopback API, a swarm on the Init port, the Init bootstrap and preferred
/// peers, DHT client routing, and an awaited provide of pinned roots only.
/// AutoConf is off, so every `auto` placeholder is replaced or dropped.
pub(crate) fn apply_public_store_config(
    config: &mut Value,
    settings: &PublicInit,
    api_port: u16,
) -> Result<(), String> {
    let port = settings.swarm_port;
    let mut peering: Vec<(String, Vec<String>)> = Vec::new();
    for address in &settings.peers {
        let id = p2p_peer_id(address).ok_or("Invalid public IPFS peer address")?;
        let transport = &address[..address.len() - id.len() - "/p2p/".len()];
        let index = match peering.iter().position(|(peer, _)| peer == id) {
            Some(index) => index,
            None => {
                peering.push((id.to_owned(), Vec::new()));
                peering.len() - 1
            }
        };
        if !transport.is_empty() {
            peering[index].1.push(transport.to_owned());
        }
    }
    let peering: Vec<Value> = peering
        .into_iter()
        .map(|(id, addrs)| json!({"ID": id, "Addrs": addrs}))
        .collect();
    let settings: [(&[&str], Value); 20] = [
        (&["Addresses", "Gateway"], json!([])),
        (
            &["Addresses", "API"],
            json!(format!("/ip4/127.0.0.1/tcp/{api_port}")),
        ),
        (
            &["Addresses", "Swarm"],
            json!([
                format!("/ip4/0.0.0.0/tcp/{port}"),
                format!("/ip6/::/tcp/{port}"),
                format!("/ip4/0.0.0.0/udp/{port}/quic-v1"),
                format!("/ip6/::/udp/{port}/quic-v1"),
            ]),
        ),
        (&["Bootstrap"], json!(settings.bootstrap)),
        (&["Peering", "Peers"], json!(peering)),
        (&["Routing", "Type"], json!("dhtclient")),
        (&["Routing", "DelegatedRouters"], json!([])),
        (&["Ipns", "DelegatedPublishers"], json!([])),
        (&["Provide", "Enabled"], json!(true)),
        (&["Provide", "Strategy"], json!("roots")),
        (&["Provide", "DHT", "SweepEnabled"], json!(false)),
        (&["Gateway", "NoFetch"], json!(true)),
        (&["Gateway", "NoDNSLink"], json!(true)),
        (&["Gateway", "PublicGateways"], json!({})),
        (&["Discovery", "MDNS", "Enabled"], json!(false)),
        (&["AutoConf", "Enabled"], json!(false)),
        (
            &["Plugins", "Plugins", "telemetry", "Config", "Mode"],
            json!("off"),
        ),
        (&["Swarm", "ConnMgr", "Type"], json!("basic")),
        (&["Swarm", "ConnMgr", "LowWater"], json!(20)),
        (&["Swarm", "ConnMgr", "HighWater"], json!(40)),
    ];
    for (path, value) in settings {
        *super::kubo_config_entry(config, path)? = value;
    }
    *super::kubo_config_entry(config, &["Swarm", "ConnMgr", "GracePeriod"])? = json!("30s");
    let resolvers = super::kubo_config_entry(config, &["DNS", "Resolvers"])?;
    match resolvers.as_object_mut() {
        Some(resolvers) => resolvers.retain(|_, resolver| resolver.as_str() != Some("auto")),
        None => *resolvers = json!({}),
    }
    Ok(())
}

/// The only ops the public store answers. Every other op is refused, so the
/// public repo has one write path: a Runtime-validated CAR import.
pub(crate) fn public_op_allowed(req: &Request) -> bool {
    matches!(
        req,
        Request::Init { .. }
            | Request::EnsureStarted { .. }
            | Request::Health
            | Request::Status
            | Request::PinStatus { .. }
            | Request::Shutdown
            | Request::RuntimePublicImportCar { .. }
            | Request::RuntimePublicPin { .. }
            | Request::RuntimePublicProvide { .. }
            | Request::RuntimePublicPeers {}
    )
}

/// The ops that exist only in the public store.
pub(crate) fn public_only_op(req: &Request) -> bool {
    matches!(
        req,
        Request::RuntimePublicImportCar { .. }
            | Request::RuntimePublicPin { .. }
            | Request::RuntimePublicProvide { .. }
            | Request::RuntimePublicPeers {}
    )
}

pub(crate) fn public_op_refused() -> Response {
    Response::error(
        "public_store_op_refused",
        "The public IPFS store answers only its Runtime operations",
    )
}

/// A CID argument as Kubo writes it: CIDv0 base58 or CIDv1 base32.
pub(crate) fn valid_cid_arg(cid: &str) -> bool {
    (1..=128).contains(&cid.len()) && cid.bytes().all(|b| b.is_ascii_alphanumeric())
}

// ── CAR header ──────────────────────────────────────────────────────

/// The roots of a CARv1 header (a varint length, then dag-cbor
/// `{roots: [CID], version: 1}`), each as Kubo writes the CID: CIDv0 in
/// base58btc, CIDv1 in base32. Only the header is read.
pub(crate) fn car_header_roots(car: &[u8]) -> Result<Vec<String>, String> {
    let mut input = car;
    let length = read_uvarint(&mut input)?;
    if length == 0 || length > MAX_CAR_HEADER_BYTES || length > input.len() as u64 {
        return Err("CAR header length is invalid".into());
    }
    let mut header = Cbor(&input[..length as usize]);
    if header.head(5)? != 2 {
        return Err("CAR header is not a two-entry map".into());
    }
    let (mut roots, mut version) = (None, None);
    for _ in 0..2 {
        match header.text()? {
            "roots" if roots.is_none() => {
                let count = header.head(4)?;
                if count == 0 || count > MAX_CAR_ROOTS {
                    return Err("CAR header root count is invalid".into());
                }
                let mut cids = Vec::new();
                for _ in 0..count {
                    if header.head(6)? != 42 {
                        return Err("CAR header root is not a CID".into());
                    }
                    let length = header.head(2)?;
                    let bytes = header.take(length)?;
                    match bytes.split_first() {
                        Some((0, cid)) => cids.push(cid_string(cid)?),
                        _ => return Err("CAR header root is not a CID".into()),
                    }
                }
                roots = Some(cids);
            }
            "version" if version.is_none() => version = Some(header.head(0)?),
            _ => return Err("CAR header has an unexpected key".into()),
        }
    }
    if !header.0.is_empty() || version != Some(1) {
        return Err("CAR header is not a CARv1 header".into());
    }
    roots.ok_or_else(|| "CAR header has no roots".into())
}

fn read_uvarint(input: &mut &[u8]) -> Result<u64, String> {
    let mut value = 0u64;
    for index in 0..9 {
        let (&byte, rest) = input.split_first().ok_or("truncated varint")?;
        *input = rest;
        value |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("varint is too long".into())
}

/// A reader of the dag-cbor items a CAR header uses.
struct Cbor<'a>(&'a [u8]);

impl<'a> Cbor<'a> {
    /// The argument of the next item, which must have major type `major`.
    fn head(&mut self, major: u8) -> Result<u64, String> {
        let (&initial, rest) = self.0.split_first().ok_or("truncated CAR header")?;
        self.0 = rest;
        if initial >> 5 != major {
            return Err("CAR header has an unexpected item".into());
        }
        let size = match initial & 0x1f {
            info @ 0..=23 => return Ok(u64::from(info)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err("CAR header has an indefinite item".into()),
        };
        Ok(self
            .take(size)?
            .iter()
            .fold(0u64, |value, byte| value << 8 | u64::from(*byte)))
    }

    fn take(&mut self, length: u64) -> Result<&'a [u8], String> {
        if length > self.0.len() as u64 {
            return Err("truncated CAR header".into());
        }
        let (bytes, rest) = self.0.split_at(length as usize);
        self.0 = rest;
        Ok(bytes)
    }

    fn text(&mut self) -> Result<&'a str, String> {
        let length = self.head(3)?;
        std::str::from_utf8(self.take(length)?).map_err(|_| "CAR header key is not text".into())
    }
}

/// A binary CID in the string form Kubo writes.
fn cid_string(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() == 34 && bytes[..2] == [0x12, 0x20] {
        return Ok(base58btc(bytes));
    }
    let mut rest = bytes;
    let version = read_uvarint(&mut rest)?;
    let _codec = read_uvarint(&mut rest)?;
    let _hash = read_uvarint(&mut rest)?;
    let digest = read_uvarint(&mut rest)?;
    if version != 1 || digest == 0 || digest > 64 || digest != rest.len() as u64 {
        return Err("CAR header root is not a CIDv0 or CIDv1".into());
    }
    Ok(format!("b{}", base32_lower(bytes)))
}

fn base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in bytes {
        buffer = buffer << 8 | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[(buffer >> bits & 0x1f) as usize] as char);
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[(buffer << (5 - bits) & 0x1f) as usize] as char);
    }
    out
}

fn base58btc(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = Vec::new();
    for byte in bytes {
        let mut carry = u32::from(*byte);
        for digit in digits.iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    std::iter::repeat_n('1', zeros)
        .chain(
            digits
                .iter()
                .rev()
                .map(|digit| ALPHABET[*digit as usize] as char),
        )
        .collect()
}

// ── Owned Kubo process ──────────────────────────────────────────────

/// The public coord proves ownership of the spawned Kubo from spawn on: its
/// PID with the kernel's process-start identity names exactly that process.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PublicCoord {
    pub(crate) mode: String,
    pub(crate) pid: u32,
    pub(crate) identity: String,
}

pub(crate) struct PublicStore {
    pub(crate) settings: PublicInit,
    /// The flocked startup lock, held while this provider owns Kubo.
    lock: Option<fs::File>,
    stderr_tail: Arc<Mutex<Vec<u8>>>,
    stderr_done: Option<mpsc::Receiver<()>>,
    /// Test-only config changes after the public settings, which keep a real
    /// Kubo test on loopback.
    #[cfg(test)]
    pub(crate) config_hook: Option<fn(&mut Value)>,
}

impl PublicStore {
    pub(crate) fn new(settings: PublicInit) -> Self {
        Self {
            settings,
            lock: None,
            stderr_tail: Arc::new(Mutex::new(Vec::new())),
            stderr_done: None,
            #[cfg(test)]
            config_hook: None,
        }
    }
}

pub(crate) fn public_coord_path(data_dir: &Path) -> PathBuf {
    data_dir.join(PUBLIC_COORD_FILE)
}

#[cfg(unix)]
fn process_identity(pid: u32) -> io::Result<Option<String>> {
    elastos_common::process_identity::process_identity(pid)
}

#[cfg(not(unix))]
fn process_identity(_pid: u32) -> io::Result<Option<String>> {
    Err(io::Error::other(
        "public IPFS store needs process identity, which this platform lacks",
    ))
}

fn not_ready(message: &str) -> Response {
    Response::error("not_ready", message)
}

impl IpfsProvider {
    pub(crate) fn handle_public(&mut self, req: Request) -> Response {
        if !public_op_allowed(&req) {
            return public_op_refused();
        }
        match req {
            Request::Init { config } => self.init(config),
            Request::EnsureStarted { .. } => {
                self.public_ensure_started(Instant::now() + PUBLIC_START_DEADLINE)
            }
            Request::Health => {
                self.public_running();
                self.health()
            }
            Request::Status => self.public_status(),
            Request::PinStatus { cid, .. } => self.pin_status(&cid),
            Request::Shutdown => self.public_shutdown(),
            Request::RuntimePublicImportCar { root, car_base64 } => {
                self.public_import_car(&root, &car_base64, Instant::now() + PUBLIC_IMPORT_DEADLINE)
            }
            Request::RuntimePublicPin { cid } => {
                self.public_pin(&cid, Instant::now() + PUBLIC_PIN_DEADLINE)
            }
            Request::RuntimePublicProvide { cid, timeout_secs } => {
                if !(1..=MAX_PROVIDE_TIMEOUT_SECS).contains(&timeout_secs) {
                    return Response::error("announce_failed", "Invalid provide timeout");
                }
                let budget = PUBLIC_PROVIDE_DEADLINE.min(Duration::from_secs(timeout_secs));
                self.public_provide(&cid, Instant::now() + budget)
            }
            Request::RuntimePublicPeers {} => self.public_peers(),
            _ => public_op_refused(),
        }
    }

    fn public_store(&mut self) -> &mut PublicStore {
        self.public
            .as_mut()
            .expect("public operations run only in the public store mode")
    }

    /// Whether the owned Kubo still runs. A child that exited is reaped here,
    /// with its coord, so the next EnsureStarted starts a new one.
    pub(crate) fn public_running(&mut self) -> bool {
        let Some(child) = self.kubo_child.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(None) => true,
            Ok(Some(status)) => {
                let pid = child.id();
                tracing::warn!(pid, %status, "public Kubo exited");
                self.public_child_reaped(pid);
                self.state = KuboState::Cold;
                false
            }
            Err(error) => {
                // The child can no longer be waited for, so it is not ours.
                let pid = child.id();
                tracing::warn!(pid, %error, "public Kubo exit check failed");
                self.public_child_reaped(pid);
                self.state = KuboState::Cold;
                false
            }
        }
    }

    /// Answers `not_ready` unless the owned Kubo runs and answered health.
    fn public_ready(&mut self) -> Result<(), Response> {
        if self.public_running() && self.state == KuboState::Ready {
            Ok(())
        } else {
            Err(not_ready("The public IPFS store is not started"))
        }
    }

    /// Forgets a reaped child: its coord goes when it still names that child,
    /// and the startup lock is released.
    fn public_child_reaped(&mut self, pid: u32) {
        self.kubo_child = None;
        let path = public_coord_path(&self.data_dir);
        let ours = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<PublicCoord>(&bytes).ok())
            .is_some_and(|coord| coord.pid == pid);
        if ours {
            let _ = fs::remove_file(&path);
        }
        self.public_store().lock = None;
    }

    /// Kills a child that failed to start and reaps it by `deadline`, or
    /// shortly after when the deadline has passed.
    fn kill_failed_start(&mut self, deadline: Instant) {
        self.stop_owned_kubo(Duration::ZERO, deadline.max(Instant::now() + MIN_REAP_WAIT));
        self.state = KuboState::Error;
    }

    /// Stops the owned child: SIGTERM and up to `term_wait` (when not zero),
    /// then SIGKILL, and reaps it by `bound`. Only this child is signalled.
    /// Returns whether it was reaped.
    fn stop_owned_kubo(&mut self, term_wait: Duration, bound: Instant) -> bool {
        let Some(child) = self.kubo_child.as_mut() else {
            return true;
        };
        let pid = child.id();
        let exited = |child: &mut std::process::Child, until: Instant| loop {
            match child.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) if Instant::now() < until => std::thread::sleep(CHILD_POLL_INTERVAL),
                _ => return false,
            }
        };
        let mut reaped = false;
        if !term_wait.is_zero() {
            #[cfg(unix)]
            if let Some(target) = rustix::process::Pid::from_raw(pid as i32) {
                // A concurrent exit makes this fail; the poll still reaps it.
                let _ = rustix::process::kill_process(target, rustix::process::Signal::TERM);
            }
            reaped = exited(child, (Instant::now() + term_wait).min(bound));
        }
        if !reaped {
            // A concurrent exit can make kill fail; the poll still reaps it.
            let _ = child.kill();
            reaped = exited(child, bound);
        }
        if reaped {
            tracing::debug!(pid, "public Kubo stopped and reaped");
            self.public_child_reaped(pid);
        } else {
            tracing::warn!(pid, "public Kubo was not reaped in its bound; coord kept");
        }
        reaped
    }

    /// The protocol `shutdown` and stdin EOF: stop and reap the owned Kubo
    /// within `PUBLIC_SHUTDOWN_BOUND`. No RPC is posted.
    pub(crate) fn public_shutdown(&mut self) -> Response {
        let bound = Instant::now() + PUBLIC_SHUTDOWN_BOUND;
        let reaped = self.stop_owned_kubo(PUBLIC_TERM_WAIT, bound);
        self.state = KuboState::Cold;
        if reaped {
            Response::ok(json!({"message": "ipfs-provider shutting down"}))
        } else {
            Response::error("stop_pending", "The public Kubo was not reaped in time")
        }
    }

    pub(crate) fn public_ensure_started(&mut self, deadline: Instant) -> Response {
        if let Err(error) = self.public_start(deadline) {
            tracing::warn!(%error, "public IPFS store not ready");
            return not_ready(&error);
        }
        // The identity read shares the start's deadline.
        let identity = public_rpc(self.api_port, "id", &[], None, deadline)
            .and_then(|response| read_json(response, deadline));
        match identity {
            Ok(id) if id["ID"].as_str().is_some_and(|id| !id.is_empty()) => Response::ok(json!({
                "state": self.state,
                "runtime_store_mode": "public",
                "peer_id": id["ID"],
                "swarm_addrs": id["Addresses"].as_array().cloned().unwrap_or_default(),
            })),
            _ => not_ready("The public Kubo returned no peer identity"),
        }
    }

    /// Starts the public Kubo as this provider's child, inside `deadline`.
    /// Nothing at the public paths with another identity is adopted, started
    /// on or stopped, and a repo another process holds is never opened.
    pub(crate) fn public_start(&mut self, deadline: Instant) -> Result<(), String> {
        if self.public_running() {
            if self.state == KuboState::Ready {
                return Ok(());
            }
            // An owned child that never became ready is replaced only once reaped.
            if !self.stop_owned_kubo(Duration::ZERO, deadline.max(Instant::now() + MIN_REAP_WAIT)) {
                return Err("The previous public Kubo is not reaped yet".into());
            }
        }
        self.state = KuboState::Cold;
        let binary = self
            .kubo_binary
            .clone()
            .ok_or("kubo not found. Run: elastos setup --with kubo")?;
        let lock = open_public_lock(&self.data_dir)?;
        let repo = self.data_dir.join(PUBLIC_REPO_DIR);
        let repo_exists = public_repo_marked(&repo)?;
        clear_stale_public_coord(&self.data_dir)?;
        if !repo_lock_is_free(&repo) {
            return Err("The public IPFS repo is locked by another process".into());
        }
        let settings = self.public_store().settings.clone();
        swarm_port_free(settings.swarm_port)?;

        if !repo_exists {
            create_public_repo(&repo)?;
        }
        if !repo.join("config").is_file() {
            tracing::info!(repo = %repo.display(), "initializing the public IPFS repo");
            init_public_repo(&binary, &repo, deadline)?;
        }
        let api_port =
            super::bind_free_port().map_err(|e| format!("Failed to bind API port: {e}"))?;
        #[cfg(test)]
        let hook = self.public_store().config_hook;
        rewrite_kubo_config(&repo, |config| {
            apply_public_store_config(config, &settings, api_port)?;
            #[cfg(test)]
            if let Some(hook) = hook {
                hook(config);
            }
            Ok(())
        })?;

        let mut child = Command::new(&binary)
            .args(public_daemon_args(api_port))
            .env("IPFS_PATH", &repo)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn kubo: {e}"))?;
        let pid = child.id();
        let (tail, done) = drain_stderr(child.stderr.take());
        self.kubo_child = Some(child);
        self.api_port = api_port;
        self.gateway_port = 0;
        self.state = KuboState::Starting;
        let store = self.public_store();
        store.lock = Some(lock);
        store.stderr_tail = tail;
        store.stderr_done = Some(done);

        // The coord names the child before it takes the repo lock, so its
        // ownership is provable from spawn on.
        let identity = match process_identity(pid) {
            Ok(Some(identity)) => identity,
            other => {
                self.kill_failed_start(deadline);
                return Err(format!(
                    "public Kubo pid {pid} has no process identity: {other:?}"
                ));
            }
        };
        let coord = PublicCoord {
            mode: PUBLIC_MARKER.into(),
            pid,
            identity,
        };
        if let Err(error) = write_public_coord(&self.data_dir, &coord) {
            self.kill_failed_start(deadline);
            return Err(error);
        }
        tracing::info!(
            pid,
            api_port,
            swarm_port = settings.swarm_port,
            "spawned public Kubo"
        );
        self.public_await_health(pid, api_port, deadline)
    }

    fn public_await_health(
        &mut self,
        pid: u32,
        api_port: u16,
        deadline: Instant,
    ) -> Result<(), String> {
        let started = Instant::now();
        let health_deadline = deadline
            .checked_sub(START_STOP_RESERVE)
            .unwrap_or(deadline)
            .max(started);
        let health = kubo_rpc_url(api_port, "id", &[]);
        loop {
            if !self.public_running() {
                let tail = self.public_stderr_tail(deadline);
                self.state = KuboState::Error;
                return Err(format!("public Kubo exited during startup{tail}"));
            }
            let remaining = health_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.kill_failed_start(deadline);
                return Err(format!(
                    "public Kubo pid {pid} was not ready within the start deadline"
                ));
            }
            if matches!(
                ureq::post(&health).timeout(remaining.min(HEALTH_CALL_TIMEOUT)).call(),
                Ok(response) if response.status() == 200
            ) {
                self.state = KuboState::Ready;
                tracing::info!(
                    pid,
                    seconds = started.elapsed().as_secs_f64(),
                    "public Kubo ready"
                );
                return Ok(());
            }
            let remaining = health_deadline.saturating_duration_since(Instant::now());
            std::thread::sleep(remaining.min(HEALTH_POLL_INTERVAL));
        }
    }

    /// Kubo's last stderr bytes, after its pipe closes or `deadline` nears.
    fn public_stderr_tail(&mut self, deadline: Instant) -> String {
        let store = self.public_store();
        if let Some(done) = store.stderr_done.take() {
            let wait = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(500));
            let _ = done.recv_timeout(wait);
        }
        let tail = store
            .stderr_tail
            .lock()
            .map(|tail| tail.clone())
            .unwrap_or_default();
        let tail = String::from_utf8_lossy(&tail);
        if tail.trim().is_empty() {
            String::new()
        } else {
            format!(": {}", tail.trim())
        }
    }

    fn public_status(&mut self) -> Response {
        let running = self.public_running();
        let identity = if running { self.kubo_identity() } else { None };
        Response::ok(json!({
            "version": PROVIDER_VERSION,
            "state": self.state,
            "runtime_store_mode": "public",
            "api_endpoint": if running { Some(self.api_url()) } else { None },
            "kubo_pid": self.kubo_child.as_ref().map(std::process::Child::id),
            "peer_id": identity.as_ref().map(|(id, _)| id.clone()),
            "swarm_addrs": identity.as_ref().map(|(_, addrs)| addrs.clone()),
        }))
    }

    fn public_peers(&mut self) -> Response {
        if let Err(response) = self.public_ready() {
            return response;
        }
        let deadline = Instant::now() + PUBLIC_READ_DEADLINE;
        let body = public_rpc(self.api_port, "swarm/peers", &[], None, deadline)
            .and_then(|response| read_json(response, deadline));
        match body {
            Ok(body) => {
                let peers = body["Peers"].as_array().map_or(0, Vec::len);
                Response::ok(json!({"peers": peers}))
            }
            Err(error) => not_ready(&error),
        }
    }

    pub(crate) fn public_import_car(
        &mut self,
        root: &str,
        car_base64: &str,
        deadline: Instant,
    ) -> Response {
        let invalid = |message: &str| Response::error("invalid_car", message);
        if !valid_cid_arg(root) {
            return invalid("Invalid CAR root");
        }
        if car_base64.len() as u64 > MAX_PUBLIC_CAR_BYTES.div_ceil(3) * 4 {
            return invalid("CAR is larger than the public metadata bound");
        }
        let Ok(car) = BASE64.decode(car_base64) else {
            return invalid("CAR is not base64");
        };
        // Pre-ingest check: the header must name exactly the requested root,
        // before any Kubo call.
        match car_header_roots(&car) {
            Ok(roots) if roots == [root] => {}
            Ok(_) => return invalid("CAR header roots differ from the requested root"),
            Err(error) => return invalid(&error),
        }
        if let Err(response) = self.public_ready() {
            return response;
        }
        let boundary = format!("----elastos-car-{}", super::now_unix_secs());
        let mut body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"metadata.car\"\r\nContent-Type: application/vnd.ipld.car\r\n\r\n"
        )
        .into_bytes();
        body.extend_from_slice(&car);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let content_type = format!("multipart/form-data; boundary={boundary}");
        let imported = public_rpc(
            self.api_port,
            "dag/import",
            &[
                ("pin-roots", "false"),
                ("fast-provide-root", "false"),
                ("allow-big-block", "false"),
                ("stats", "false"),
            ],
            Some((&content_type, &body)),
            deadline,
        )
        .and_then(|response| check_event_stream(response, deadline));
        match imported {
            Ok(()) => Response::ok(json!({"imported": true})),
            Err(error) => Response::error("import_failed", &error),
        }
    }

    pub(crate) fn public_pin(&mut self, cid: &str, deadline: Instant) -> Response {
        let failed = |message: &str| Response::error("pin_failed", message);
        if !valid_cid_arg(cid) {
            return failed("Invalid CID");
        }
        if let Err(response) = self.public_ready() {
            return response;
        }
        let pinned = public_rpc(
            self.api_port,
            "pin/add",
            &[("arg", cid), ("recursive", "true"), ("offline", "true")],
            None,
            deadline,
        )
        .and_then(|response| read_json(response, deadline))
        .and_then(|_| {
            public_rpc(
                self.api_port,
                "pin/ls",
                &[("arg", cid), ("type", "recursive"), ("offline", "true")],
                None,
                deadline,
            )
        })
        .and_then(|response| read_json(response, deadline));
        let listed = match pinned {
            Ok(listed) => listed,
            Err(error) => return failed(&error),
        };
        // The recursive listing must name exactly this CID.
        let exact = listed["Keys"].as_object().is_some_and(|keys| {
            keys.len() == 1 && keys.get(cid).is_some_and(|pin| pin["Type"] == "recursive")
        });
        if exact {
            Response::ok(json!({"cid": cid, "pinned": true}))
        } else {
            failed("Kubo did not list the recursive pin")
        }
    }

    pub(crate) fn public_provide(&mut self, cid: &str, deadline: Instant) -> Response {
        let failed = |message: &str| Response::error("announce_failed", message);
        if !valid_cid_arg(cid) {
            return failed("Invalid CID");
        }
        if let Err(response) = self.public_ready() {
            return response;
        }
        // Awaited to the end of Kubo's event stream.
        let provided = public_rpc(
            self.api_port,
            "routing/provide",
            &[("arg", cid)],
            None,
            deadline,
        )
        .and_then(|response| check_event_stream(response, deadline));
        match provided {
            Ok(()) => Response::ok(json!({"cid": cid, "provided": true})),
            Err(error) => failed(&error),
        }
    }
}

// ── Public paths ────────────────────────────────────────────────────

/// Opens, checks and flocks the public startup lock. Its content is the
/// `public` marker; a lock marked otherwise is refused.
fn open_public_lock(data_dir: &Path) -> Result<fs::File, String> {
    fs::create_dir_all(data_dir).map_err(|e| format!("Failed to create data dir: {e}"))?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(data_dir.join(PUBLIC_LOCK_FILE))
        .map_err(|e| format!("Failed to open the public startup lock: {e}"))?;
    let mut marker = Vec::new();
    (&mut file)
        .take(64)
        .read_to_end(&mut marker)
        .map_err(|e| format!("Failed to read the public startup lock: {e}"))?;
    // A zero-length lock is an interrupted creation of this lock (created,
    // not yet stamped): it is stamped `public` below. Any other content
    // without exactly the `public` marker is refused.
    if !marker.is_empty() && marker != PUBLIC_MARKER.as_bytes() {
        return Err("The public startup lock belongs to another store; start refused".into());
    }
    if !try_flock_exclusive(&file) {
        return Err("Another process is starting the public IPFS store".into());
    }
    if marker.is_empty() {
        file.write_all(PUBLIC_MARKER.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("Failed to mark the public startup lock: {e}"))?;
    }
    Ok(file)
}

/// Whether the public repo exists; one that exists must carry the `public`
/// marker.
fn public_repo_marked(repo: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(repo) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err("The public IPFS repo is not a directory; start refused".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("Failed to read the public IPFS repo: {error}")),
    }
    match fs::read(repo.join(STORE_MODE_MARKER)) {
        Ok(marker) if marker == PUBLIC_MARKER.as_bytes() => Ok(true),
        Ok(_) => Err("The public IPFS repo is marked for another store; start refused".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Err("The public IPFS repo has no store-mode marker; start refused".into())
        }
        Err(error) => Err(format!("Failed to read the public repo marker: {error}")),
    }
}

/// Creates the public repo, owner-only, with its marker before Kubo's files.
fn create_public_repo(repo: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(repo)
        .map_err(|e| format!("Failed to create the public IPFS repo: {e}"))?;
    let tmp = repo.join(format!("{STORE_MODE_MARKER}.tmp"));
    fs::write(&tmp, PUBLIC_MARKER)
        .and_then(|()| fs::rename(&tmp, repo.join(STORE_MODE_MARKER)))
        .map_err(|e| format!("Failed to mark the public IPFS repo: {e}"))
}

/// `kubo init` of the public repo, bounded by the start deadline.
fn init_public_repo(binary: &Path, repo: &Path, deadline: Instant) -> Result<(), String> {
    let mut init = Command::new(binary)
        .args(["init", "--empty-repo"])
        .env("IPFS_PATH", repo)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to run kubo init: {e}"))?;
    loop {
        match init.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                let mut stderr = String::new();
                if let Some(pipe) = init.stderr.as_mut() {
                    let _ = pipe.take(4096).read_to_string(&mut stderr);
                }
                return Err(format!("kubo init failed ({status}): {}", stderr.trim()));
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(CHILD_POLL_INTERVAL),
            Ok(None) | Err(_) => {
                let _ = init.kill();
                let _ = init.wait();
                return Err("kubo init did not finish within the start deadline".into());
            }
        }
    }
}

/// A coord at the public path that names a live public Kubo blocks the start:
/// the provider never adopts or signals it, and Runtime's cleanup rule
/// removes it. A coord whose process is gone is stale and removed. A coord
/// without the `public` marker, or one that cannot be checked, refuses start.
fn clear_stale_public_coord(data_dir: &Path) -> Result<(), String> {
    let path = public_coord_path(data_dir);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("Failed to read the public coord: {error}")),
    };
    let coord: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "The public coord is unreadable; start refused".to_string())?;
    if coord["mode"] != PUBLIC_MARKER {
        return Err("The public coord is not a public store coord; start refused".into());
    }
    let coord: PublicCoord = serde_json::from_value(coord)
        .map_err(|_| "The public coord is incomplete; start refused".to_string())?;
    match process_identity(coord.pid) {
        Ok(Some(current)) if current == coord.identity => Err(format!(
            "An earlier public Kubo (pid {}) still runs; start refused until Runtime clears it",
            coord.pid
        )),
        Ok(_) => {
            tracing::debug!(pid = coord.pid, "removing a stale public coord");
            fs::remove_file(&path)
                .map_err(|e| format!("Failed to remove the stale public coord: {e}"))
        }
        Err(error) => Err(format!(
            "The public coord pid {} cannot be checked ({error}); start refused",
            coord.pid
        )),
    }
}

fn write_public_coord(data_dir: &Path, coord: &PublicCoord) -> Result<(), String> {
    let path = public_coord_path(data_dir);
    let tmp = path.with_extension("tmp");
    let body = serde_json::to_vec_pretty(coord).map_err(|e| format!("public coord: {e}"))?;
    fs::write(&tmp, body)
        .and_then(|()| fs::rename(&tmp, &path))
        .map_err(|e| format!("Failed to write the public coord: {e}"))
}

/// Refuses a swarm port another process holds, so a second Home on this
/// machine reads not-ready with the port named instead of a failing daemon.
fn swarm_port_free(port: u16) -> Result<(), String> {
    let tcp = std::net::TcpListener::bind(("0.0.0.0", port)).map(drop);
    let udp = std::net::UdpSocket::bind(("0.0.0.0", port)).map(drop);
    tcp.and(udp)
        .map_err(|error| format!("The public IPFS swarm port {port} is in use ({error})"))
}

/// Reads Kubo's stderr to its end on a thread, so an online daemon never
/// blocks on a full pipe. The last bytes are kept for a startup error.
fn drain_stderr(
    stderr: Option<std::process::ChildStderr>,
) -> (Arc<Mutex<Vec<u8>>>, mpsc::Receiver<()>) {
    let tail = Arc::new(Mutex::new(Vec::new()));
    let (done, finished) = mpsc::channel();
    let kept = Arc::clone(&tail);
    std::thread::spawn(move || {
        if let Some(stderr) = stderr {
            let mut reader = io::BufReader::new(stderr);
            let mut line = Vec::new();
            while matches!(reader.read_until(b'\n', &mut line), Ok(count) if count > 0) {
                tracing::debug!(line = %String::from_utf8_lossy(&line).trim_end(), "public Kubo");
                if let Ok(mut tail) = kept.lock() {
                    tail.extend_from_slice(&line);
                    let excess = tail.len().saturating_sub(MAX_STDERR_TAIL);
                    tail.drain(..excess);
                }
                line.clear();
            }
        }
        let _ = done.send(());
    });
    (tail, finished)
}

// ── Kubo RPC inside one deadline ────────────────────────────────────

/// One Kubo RPC whose whole exchange, body included, ends by `deadline`.
fn public_rpc(
    api_port: u16,
    command: &str,
    query: &[(&str, &str)],
    body: Option<(&str, &[u8])>,
    deadline: Instant,
) -> Result<ureq::Response, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(format!("kubo {command} -> operation deadline passed"));
    }
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .try_proxy_from_env(false)
        .build();
    let request = agent
        .post(&kubo_rpc_url(api_port, command, query))
        .timeout(remaining);
    let result = match body {
        Some((content_type, bytes)) => request.set("Content-Type", content_type).send_bytes(bytes),
        None => request.call(),
    };
    match result {
        Ok(response) if response.status() == 200 => Ok(response),
        Ok(response) => Err(format!("kubo {command} -> HTTP {}", response.status())),
        Err(ureq::Error::Status(status, response)) => {
            let mut message = String::new();
            let _ = response
                .into_reader()
                .take(4096)
                .read_to_string(&mut message);
            let message = serde_json::from_str::<Value>(&message)
                .ok()
                .and_then(|body| body["Message"].as_str().map(str::to_owned))
                .unwrap_or(message);
            Err(format!(
                "kubo {command} -> HTTP {status}: {}",
                message.trim()
            ))
        }
        Err(error) => Err(format!("kubo {command} -> {error}")),
    }
}

fn read_json(response: ureq::Response, deadline: Instant) -> Result<Value, String> {
    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_EVENT_STREAM_BYTES)
        .read_to_end(&mut body)
        .map_err(|e| format!("kubo answer -> {e}"))?;
    if Instant::now() > deadline {
        return Err("kubo answer -> operation deadline passed".into());
    }
    serde_json::from_slice(&body).map_err(|e| format!("kubo answer is not JSON: {e}"))
}

/// Reads Kubo's NDJSON event stream to its end. An error event (a command
/// error object, or a root with a pin error) fails it; an empty stream is a
/// success.
fn check_event_stream(response: ureq::Response, deadline: Instant) -> Result<(), String> {
    let mut reader = io::BufReader::new(response.into_reader().take(MAX_EVENT_STREAM_BYTES + 1));
    let mut read = 0u64;
    let mut line = Vec::new();
    loop {
        line.clear();
        let count = reader
            .read_until(b'\n', &mut line)
            .map_err(|e| format!("kubo event stream -> {e}"))?;
        if count == 0 {
            break;
        }
        read += count as u64;
        if read > MAX_EVENT_STREAM_BYTES {
            return Err("kubo event stream is too long".into());
        }
        let text = String::from_utf8_lossy(&line);
        if text.trim().is_empty() {
            continue;
        }
        let event: Value = serde_json::from_str(text.trim())
            .map_err(|_| "kubo event stream is not JSON".to_string())?;
        if event["Type"] == "error" {
            return Err(format!(
                "kubo error event: {}",
                event["Message"].as_str().unwrap_or("unknown error")
            ));
        }
        if let Some(error) = event["Root"]["PinErrorMsg"]
            .as_str()
            .filter(|e| !e.is_empty())
        {
            return Err(format!("kubo root error: {error}"));
        }
    }
    if Instant::now() > deadline {
        return Err("kubo event stream -> operation deadline passed".into());
    }
    Ok(())
}

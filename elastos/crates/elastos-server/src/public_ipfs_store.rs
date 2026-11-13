//! The public IPFS store: a second ipfs-provider, in public mode, that only
//! the Home gateway runs, as the Runtime-only target `public-ipfs`, while the
//! admin's consent is enabled.
//!
//! The store keeps no state of its own. The registry holds the provider, and
//! the files under the data dir hold the consent, the withdrawal and the
//! owned Kubo's coord and repo lock. Every state change runs under the
//! state lock (`public_metadata_consent`), and none of them has a Runtime
//! timeout: each is awaited to the provider's own bounded answer. Only the
//! read-only status has one, and a status that timed out reads `Unknown`,
//! which never starts anything.
//!
//! Stop never waits behind publication work: it unregisters the target, so
//! the bridge's bounded shutdown force-reaps a busy provider, and then the
//! cleanup rule removes any public Kubo the provider left behind.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, Weak};
use std::time::Duration;

use elastos_runtime::provider::{self, Provider, ProviderError, ProviderRegistry, PublicIpfsOp};
use tokio::sync::{oneshot, watch, Semaphore};

use crate::public_metadata_consent::{
    self as consent, ConsentState, PublicMetadataError, PublicMetadataErrorCode, PublicStateGuard,
    STATE_LOCK_BUDGET, WITHDRAWAL_LOCK_BUDGET,
};

pub(crate) const PUBLIC_IPFS_TARGET: &str = provider::PUBLIC_IPFS_TARGET;
pub(crate) const DEFAULT_PUBLIC_IPFS_SWARM_PORT: u16 = 4001;
/// The default preferred peer: Elacity's well-known node, at its public QUIC
/// address (it advertises no public TCP address).
pub(crate) const DEFAULT_PUBLIC_IPFS_PEERS: &[&str] = &[
    "/ip4/34.77.31.164/udp/4001/quic-v1/p2p/12D3KooWNieM3HRBJdVqaQucZEJdqA3oWKrKf3Gx3hp2cmtR9GNK",
];
/// Kubo v0.40.1's own default bootstrap list (its AutoConf fallback),
/// verified against that binary in the ipfs-provider's real-Kubo test.
pub(crate) const DEFAULT_PUBLIC_IPFS_BOOTSTRAP: &[&str] = &[
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
    "/dnsaddr/va1.bootstrap.libp2p.io/p2p/12D3KooWKnDdG3iXw9eTFijk3EWSunZcFi54Zka4wmtqtt6rPxc8",
    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
    "/ip4/104.131.131.82/udp/4001/quic-v1/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
];

const SWARM_PORT_KEY: &str = "public_ipfs_swarm_port";
const PEERS_KEY: &str = "public_ipfs_peers";
const BOOTSTRAP_KEY: &str = "public_ipfs_bootstrap";
/// The ipfs-provider's own bound on each list.
const MAX_PUBLIC_IPFS_ADDRESSES: usize = 64;
const MAX_PUBLIC_IPFS_ADDRESS_LEN: usize = 512;

/// The public paths the ipfs-provider owns in public mode (Task 1).
const PUBLIC_REPO_DIR: &str = "ipfs-public-repo";
const PUBLIC_REPO_LOCK: &str = "repo.lock";
const PUBLIC_COORD_FILE: &str = "ipfs-public-coords.json";
const PUBLIC_STARTUP_LOCK: &str = "ipfs-public-startup.lock";
const PUBLIC_REPO_MODE_MARKER: &str = "elastos-store-mode";
const PUBLIC_MARKER: &str = "public";
const MAX_COORD_BYTES: u64 = 4096;

/// The read-only Status/Peers bound. A read past it is `Unknown`.
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);
const SUPERVISOR_TICK: Duration = Duration::from_secs(60);
/// One unregister and at most two retries in the same call: a force-reaped
/// provider leaves its entry Settling, and the next call removes it.
const UNREGISTER_ATTEMPTS: usize = 3;
const CLEANUP_TERM_WAIT: Duration = Duration::from_secs(10);
const CLEANUP_KILL_WAIT: Duration = Duration::from_secs(5);
const CLEANUP_POLL: Duration = Duration::from_millis(50);

// ── Settings ────────────────────────────────────────────────────────

/// The public store's swarm port and its two peer lists, from `config.toml`
/// over the compiled-in defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicIpfsSettings {
    pub swarm_port: u16,
    pub peers: Vec<String>,
    pub bootstrap: Vec<String>,
}

pub(crate) fn public_ipfs_settings(data_dir: &Path) -> anyhow::Result<PublicIpfsSettings> {
    use anyhow::Context as _;

    let table = match std::fs::read_to_string(data_dir.join("config.toml")) {
        Ok(contents) => contents
            .parse::<toml::Table>()
            .context("Invalid Runtime config.toml")?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => toml::Table::new(),
        Err(error) => return Err(error).context("Cannot read Runtime config.toml"),
    };
    let swarm_port = match table.get(SWARM_PORT_KEY) {
        None => DEFAULT_PUBLIC_IPFS_SWARM_PORT,
        Some(value) => value
            .as_integer()
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .with_context(|| format!("{SWARM_PORT_KEY} must be a port from 1 to 65535"))?,
    };
    let peers = address_list(&table, PEERS_KEY, DEFAULT_PUBLIC_IPFS_PEERS)?;
    let bootstrap = address_list(&table, BOOTSTRAP_KEY, DEFAULT_PUBLIC_IPFS_BOOTSTRAP)?;
    if peers.is_empty() && bootstrap.is_empty() {
        anyhow::bail!("{BOOTSTRAP_KEY} may be empty only when {PEERS_KEY} names a preferred peer");
    }
    Ok(PublicIpfsSettings {
        swarm_port,
        peers,
        bootstrap,
    })
}

fn address_list(table: &toml::Table, key: &str, default: &[&str]) -> anyhow::Result<Vec<String>> {
    let Some(value) = table.get(key) else {
        return Ok(default.iter().map(|entry| entry.to_string()).collect());
    };
    let items = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("{key} must be an array of multiaddr strings"))?;
    if items.len() > MAX_PUBLIC_IPFS_ADDRESSES {
        anyhow::bail!("{key} lists more than {MAX_PUBLIC_IPFS_ADDRESSES} addresses");
    }
    items
        .iter()
        .map(|item| {
            let entry = item
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("{key} entry {item} is not a string"))?;
            validate_peer_multiaddr(entry)
                .map_err(|reason| anyhow::anyhow!("{key} entry {entry:?} is invalid: {reason}"))?;
            Ok(entry.to_string())
        })
        .collect()
}

/// A multiaddr that ends in `/p2p/<peer id>`, the peer ID base58 (`Qm…` or
/// `12D…`) decoding to a multihash.
pub(crate) fn validate_peer_multiaddr(entry: &str) -> Result<(), String> {
    if entry.is_empty() || entry.len() > MAX_PUBLIC_IPFS_ADDRESS_LEN {
        return Err(format!(
            "must be 1 to {MAX_PUBLIC_IPFS_ADDRESS_LEN} characters"
        ));
    }
    if !entry.starts_with('/') || !entry.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("must be a multiaddr of printable ASCII starting with '/'".into());
    }
    let parts: Vec<&str> = entry[1..].split('/').collect();
    if parts.iter().any(|part| part.is_empty()) {
        return Err("has an empty component".into());
    }
    let [.., protocol, peer_id] = parts.as_slice() else {
        return Err("must end in /p2p/<peer id>".into());
    };
    if *protocol != "p2p" || parts.len() < 2 {
        return Err("must end in /p2p/<peer id>".into());
    }
    if !(peer_id.starts_with("Qm") || peer_id.starts_with("12D")) {
        return Err("the peer id must be base58 (Qm… or 12D…)".into());
    }
    let bytes = cid::multibase::Base::Base58Btc
        .decode(peer_id)
        .map_err(|_| "the peer id is not base58".to_string())?;
    cid::multihash::Multihash::<64>::from_bytes(&bytes)
        .map_err(|_| "the peer id is not a multihash".to_string())?;
    Ok(())
}

/// The public Init envelope: the Runtime's data dir as the provider's root,
/// so the provider and the cleanup rule name the same public files.
fn public_provider_config(
    data_dir: &Path,
    settings: &PublicIpfsSettings,
) -> Result<provider::BridgeProviderConfig, String> {
    let base_path = data_dir
        .to_str()
        .filter(|path| data_dir.is_absolute() && !path.is_empty())
        .ok_or("the data dir must be an absolute UTF-8 path")?;
    let mut config = crate::ipfs::ipfs_provider_config(crate::ipfs::IpfsHostRole::Gateway);
    config.base_path = base_path.to_string();
    config.extra["runtime_store_mode"] = serde_json::json!("public");
    config.extra["public_swarm_port"] = serde_json::json!(settings.swarm_port);
    config.extra["public_peers"] = serde_json::json!(settings.peers);
    config.extra["public_bootstrap"] = serde_json::json!(settings.bootstrap);
    Ok(config)
}

// ── Status ──────────────────────────────────────────────────────────

/// `Unknown` means the status read timed out or another read is still in
/// flight. It is never proof the store is down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreLiveness {
    Running,
    Down,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicStoreStatus {
    pub liveness: StoreLiveness,
    pub ready: bool,
    pub peers: u32,
}

impl PublicStoreStatus {
    const UNKNOWN: Self = Self {
        liveness: StoreLiveness::Unknown,
        ready: false,
        peers: 0,
    };
    const DOWN: Self = Self {
        liveness: StoreLiveness::Down,
        ready: false,
        peers: 0,
    };
}

/// The single status slot of one registry: at most one status read is ever
/// in flight, and its spawned task owns the permit until the bridge read
/// itself drains, past any caller's timeout or cancellation.
struct StatusSlot {
    registry: Weak<ProviderRegistry>,
    permit: Arc<Semaphore>,
    last: StdMutex<Option<PublicStoreStatus>>,
}

impl StatusSlot {
    /// The last answer, marked unknown: the store may have changed since.
    fn busy(&self) -> PublicStoreStatus {
        self.last
            .lock()
            .ok()
            .and_then(|last| *last)
            .map(|last| PublicStoreStatus {
                liveness: StoreLiveness::Unknown,
                ..last
            })
            .unwrap_or(PublicStoreStatus::UNKNOWN)
    }

    fn remember(&self, status: PublicStoreStatus) {
        if let Ok(mut last) = self.last.lock() {
            *last = Some(status);
        }
    }
}

fn status_slot(registry: &Arc<ProviderRegistry>) -> Arc<StatusSlot> {
    static SLOTS: OnceLock<StdMutex<HashMap<usize, Arc<StatusSlot>>>> = OnceLock::new();
    let mut slots = SLOTS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // A registry that is gone frees its slot; a new one at its address gets
    // a fresh slot.
    slots.retain(|_, slot| slot.registry.strong_count() > 0);
    slots
        .entry(Arc::as_ptr(registry) as usize)
        .or_insert_with(|| {
            Arc::new(StatusSlot {
                registry: Arc::downgrade(registry),
                permit: Arc::new(Semaphore::new(1)),
                last: StdMutex::new(None),
            })
        })
        .clone()
}

/// Running: the provider answers Status with its owned Kubo ready. Down: no
/// Ready registration, or a provider whose Kubo is not running.
async fn read_liveness(registry: &ProviderRegistry) -> StoreLiveness {
    if !registry
        .has_ready_runtime_provider_target(PUBLIC_IPFS_TARGET)
        .await
    {
        return StoreLiveness::Down;
    }
    match registry.send_public_ipfs(PublicIpfsOp::Status).await {
        Ok(answer)
            if answer["status"] == "ok"
                && answer["data"]["state"] == "ready"
                && answer["data"]["api_endpoint"].is_string() =>
        {
            StoreLiveness::Running
        }
        Ok(_) => StoreLiveness::Down,
        Err(error) => {
            tracing::debug!(%error, "public IPFS status read failed");
            StoreLiveness::Down
        }
    }
}

/// Connected peers, bootstrap peers included, so a preferred-peer outage
/// never blocks readiness.
async fn read_peers(registry: &ProviderRegistry) -> Option<u32> {
    match registry.send_public_ipfs(PublicIpfsOp::Peers).await {
        Ok(answer) if answer["status"] == "ok" => answer["data"]["peers"]
            .as_u64()
            .map(|peers| u32::try_from(peers).unwrap_or(u32::MAX)),
        Ok(_) => None,
        Err(error) => {
            tracing::debug!(%error, "public IPFS peers read failed");
            None
        }
    }
}

// ── Store ───────────────────────────────────────────────────────────

/// Stop's result. `Stopped` iff the `public-ipfs` registration is absent AND
/// the cleanup rule confirmed no owned public Kubo alive and the repo lock
/// free. Anything less is `Pending`, with its evidence kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StopOutcome {
    Stopped,
    Pending(String),
}

/// Stateless: all state is in the registry and the files. Every method that
/// changes state takes the state guard; none acquires the lock.
pub(crate) struct PublicIpfsStore;

impl PublicIpfsStore {
    /// Ready registration: EnsureStarted only. Settling: the Stop table's
    /// unregister retry, and `not_ready` while it stays Settling. Absent: the
    /// cleanup rule, then a new provider registered and EnsureStarted.
    pub(crate) async fn start(
        registry: &ProviderRegistry,
        data_dir: &Path,
        _guard: &PublicStateGuard,
    ) -> Result<(), PublicMetadataError> {
        // A5: both callers hold the guard, so a gate closed before this read
        // never starts a store; one closed after it is stopped by the next
        // closed-gate tick.
        if !consent::public_metadata_offered(data_dir) {
            return Err(PublicMetadataError::disabled(consent::PUBLIC_METADATA_OFF));
        }
        if registry
            .has_ready_runtime_provider_target(PUBLIC_IPFS_TARGET)
            .await
        {
            match registry.send_public_ipfs(PublicIpfsOp::EnsureStarted).await {
                // A crashed provider (user decision 2026-11-12 10:40): its
                // bridge reports the process exited or its pipe failed. The
                // Stop transition below unregisters it and clears its Kubo
                // by identity, then a fresh provider is spawned.
                Err(error) if provider::is_bridge_transport_failure(&error) => {
                    tracing::warn!(%error, "public IPFS provider is gone; restarting it");
                }
                answer => return ensure_started_answer(answer),
            }
        }
        // Settling is never a new-start opportunity; an absent entry passes.
        if let Err(reason) = settle_registration(registry).await {
            return Err(PublicMetadataError::not_ready(format!(
                "the previous public IPFS store is still stopping: {reason}"
            )));
        }
        let signal = kubo_signal(data_dir);
        clear_public_kubo(data_dir, &*signal)
            .await
            .map_err(PublicMetadataError::not_ready)?;
        let settings = public_ipfs_settings(data_dir)
            .map_err(|error| PublicMetadataError::not_ready(format!("{error:#}")))?;
        let provider = launch_public_provider(data_dir, &settings)
            .await
            .map_err(PublicMetadataError::not_ready)?;
        if let Err(error) = registry
            .register_runtime_provider_target(PUBLIC_IPFS_TARGET, provider.clone())
            .await
        {
            if let Err(shutdown) = provider.shutdown().await {
                tracing::warn!(%shutdown, "unregistered public IPFS provider did not stop");
            }
            return Err(PublicMetadataError::not_ready(format!(
                "the public IPFS store could not be registered: {error}"
            )));
        }
        tracing::info!(
            swarm_port = settings.swarm_port,
            peers = settings.peers.len(),
            bootstrap = settings.bootstrap.len(),
            "public IPFS store provider registered"
        );
        ensure_started(registry).await
    }

    /// The Stop transition table: unregister (retried at most twice), then
    /// the cleanup rule as the Kubo-down evidence.
    pub(crate) async fn stop(
        registry: &ProviderRegistry,
        data_dir: &Path,
        _guard: &PublicStateGuard,
    ) -> StopOutcome {
        if let Err(reason) = settle_registration(registry).await {
            return StopOutcome::Pending(reason);
        }
        let signal = kubo_signal(data_dir);
        match clear_public_kubo(data_dir, &*signal).await {
            Ok(()) => StopOutcome::Stopped,
            Err(reason) => StopOutcome::Pending(reason),
        }
    }

    /// The status slot's last definite reading, without any provider read
    /// (A5 §1.6): the slot keeps only non-Unknown readings, so a busy slot
    /// never changes it. `None` before the first definite reading.
    pub(crate) fn last_known(registry: &Arc<ProviderRegistry>) -> Option<PublicStoreStatus> {
        status_slot(registry)
            .last
            .lock()
            .ok()
            .and_then(|last| *last)
    }

    /// Read-only and without the guard, through the registry's single status
    /// slot. A busy slot answers the last status with `Unknown` liveness.
    pub(crate) async fn status(registry: &Arc<ProviderRegistry>) -> PublicStoreStatus {
        let slot = status_slot(registry);
        let Ok(permit) = slot.permit.clone().try_acquire_owned() else {
            return slot.busy();
        };
        let (liveness_tx, liveness_rx) = oneshot::channel();
        let (peers_tx, peers_rx) = oneshot::channel();
        let reader = registry.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let liveness = read_liveness(&reader).await;
            let running = liveness == StoreLiveness::Running;
            let _ = liveness_tx.send(liveness);
            if running {
                let _ = peers_tx.send(read_peers(&reader).await);
            }
        });
        let deadline = tokio::time::Instant::now() + STATUS_TIMEOUT;
        let status = match tokio::time::timeout_at(deadline, liveness_rx).await {
            Ok(Ok(StoreLiveness::Running)) => {
                match tokio::time::timeout_at(deadline, peers_rx).await {
                    Ok(Ok(Some(peers))) => PublicStoreStatus {
                        liveness: StoreLiveness::Running,
                        ready: peers >= 1,
                        peers,
                    },
                    _ => PublicStoreStatus {
                        liveness: StoreLiveness::Running,
                        ready: false,
                        peers: 0,
                    },
                }
            }
            Ok(Ok(StoreLiveness::Down)) => PublicStoreStatus::DOWN,
            Ok(Ok(StoreLiveness::Unknown)) | Ok(Err(_)) => PublicStoreStatus::UNKNOWN,
            Err(_) => {
                tracing::debug!("public IPFS status read is still pending");
                return slot.busy();
            }
        };
        if status.liveness != StoreLiveness::Unknown {
            slot.remember(status);
        }
        status
    }

    /// Publication ops take no guard and no Runtime timeout: each is awaited
    /// to the provider's bounded answer, and a Stop fails it at once.
    pub(crate) async fn import_car(
        registry: &ProviderRegistry,
        root: &str,
        car: &[u8],
    ) -> Result<(), PublicMetadataError> {
        use base64::Engine as _;
        publication_op(
            registry,
            PublicIpfsOp::ImportCar {
                root: root.to_string(),
                car_base64: base64::engine::general_purpose::STANDARD.encode(car),
            },
            PublicMetadataErrorCode::ImportFailed,
        )
        .await
    }

    pub(crate) async fn pin(
        registry: &ProviderRegistry,
        cid: &str,
    ) -> Result<(), PublicMetadataError> {
        publication_op(
            registry,
            PublicIpfsOp::Pin {
                cid: cid.to_string(),
            },
            PublicMetadataErrorCode::PinFailed,
        )
        .await
    }

    pub(crate) async fn provide(
        registry: &ProviderRegistry,
        cid: &str,
    ) -> Result<(), PublicMetadataError> {
        publication_op(
            registry,
            PublicIpfsOp::Provide {
                cid: cid.to_string(),
            },
            PublicMetadataErrorCode::AnnounceFailed,
        )
        .await
    }
}

async fn ensure_started(registry: &ProviderRegistry) -> Result<(), PublicMetadataError> {
    ensure_started_answer(registry.send_public_ipfs(PublicIpfsOp::EnsureStarted).await)
}

fn ensure_started_answer(
    answer: Result<serde_json::Value, ProviderError>,
) -> Result<(), PublicMetadataError> {
    match answer {
        Ok(answer) if answer["status"] == "ok" => Ok(()),
        Ok(answer) => Err(PublicMetadataError::not_ready(provider_message(&answer))),
        Err(error) => Err(PublicMetadataError::not_ready(format!(
            "the public IPFS store did not answer: {error}"
        ))),
    }
}

/// A provider `not_ready` keeps its code, so a store that stopped between
/// phases reads as a retry; any other refusal takes the op's own code.
async fn publication_op(
    registry: &ProviderRegistry,
    op: PublicIpfsOp,
    failed: PublicMetadataErrorCode,
) -> Result<(), PublicMetadataError> {
    let invalid_car = matches!(op, PublicIpfsOp::ImportCar { .. });
    match registry.send_public_ipfs(op).await {
        Ok(answer) if answer["status"] == "ok" => Ok(()),
        Ok(answer) => {
            let code = match answer["code"].as_str() {
                Some("not_ready") => PublicMetadataErrorCode::NotReady,
                Some("invalid_car") if invalid_car => PublicMetadataErrorCode::InvalidCar,
                _ => failed,
            };
            Err(PublicMetadataError::new(code, provider_message(&answer)))
        }
        Err(ProviderError::NoProvider(_)) => Err(PublicMetadataError::not_ready(
            "the public IPFS store is not running",
        )),
        Err(error) => Err(PublicMetadataError::new(
            failed,
            format!("the public IPFS store did not answer: {error}"),
        )),
    }
}

fn provider_message(answer: &serde_json::Value) -> String {
    answer["message"]
        .as_str()
        .unwrap_or("the public IPFS store refused the request")
        .chars()
        .take(512)
        .collect()
}

/// The Stop table's registration step. Ready: unregister, so the bridge
/// shutdown stops Kubo or force-reaps the provider. Settling and not in
/// progress: unregister again, which an already-reaped bridge settles.
/// Settling in progress: pending. Absent: nothing.
async fn settle_registration(registry: &ProviderRegistry) -> Result<(), String> {
    let mut last_error = None;
    for _ in 0..UNREGISTER_ATTEMPTS {
        match registry
            .unregister_runtime_provider_target(PUBLIC_IPFS_TARGET)
            .await
        {
            Ok(()) => return Ok(()),
            // Only the registry's own in-progress check answers Unavailable.
            Err(ProviderError::Unavailable(_)) => {
                return Err("shutdown already settling".to_string());
            }
            Err(error) => {
                tracing::debug!(%error, "public IPFS provider shutdown did not settle");
                last_error = Some(error);
            }
        }
    }
    Err(format!(
        "the public IPFS provider did not stop: {}",
        last_error
            .map(|error| error.to_string())
            .unwrap_or_default()
    ))
}

async fn launch_public_provider(
    data_dir: &Path,
    settings: &PublicIpfsSettings,
) -> Result<Arc<dyn Provider>, String> {
    #[cfg(test)]
    if let Some(launch) = test_seams::hooks(data_dir).and_then(|hooks| hooks.launch) {
        return launch(settings);
    }
    let binary = crate::binaries::resolve_verified_native_provider_binary_with_data_dir(
        data_dir,
        "ipfs-provider",
    )
    .map_err(|error| format!("the ipfs-provider binary failed verification: {error:#}"))?
    .ok_or("the ipfs-provider binary is not installed; run: elastos setup --with ipfs-provider")?;
    let config = public_provider_config(data_dir, settings)?;
    let bridge = provider::ProviderBridge::spawn(&binary, config)
        .await
        .map_err(|error| format!("the public ipfs-provider did not start: {error}"))?;
    Ok(Arc::new(provider::CapsuleProvider::with_scheme(
        Arc::new(bridge),
        PUBLIC_IPFS_TARGET,
    )))
}

// ── Withdrawal ──────────────────────────────────────────────────────

/// Complete a requested withdrawal: the withdrawal lock budget, then
/// Disabled is persisted, then the store is stopped. The marker is removed
/// only on `Stopped`; any `Pending` keeps it with the reason, for the
/// supervisor's next tick to retry.
///
/// A lock timeout is reported but not written to the marker: only a guard
/// holder may rewrite it, so a stale reason can never race its removal.
/// The Creator keeps showing the withdrawal as stopping meanwhile.
pub(crate) async fn complete_withdrawal(
    registry: &ProviderRegistry,
    data_dir: &Path,
) -> StopOutcome {
    let guard = match consent::acquire_public_state_lock(data_dir, WITHDRAWAL_LOCK_BUDGET).await {
        Ok(guard) => guard,
        Err(error) => {
            tracing::warn!(
                detail = error.detail(),
                "public IPFS withdrawal is waiting for the state lock"
            );
            return StopOutcome::Pending(error.detail().to_string());
        }
    };
    let marker = match consent::read_withdrawal_marker(data_dir) {
        Ok(Some(marker)) => marker,
        // Another completion removed it: that withdrawal is complete, and a
        // later Enable may stand, so nothing here may touch the consent.
        Ok(None) => {
            tracing::debug!("public IPFS withdrawal already completed");
            return StopOutcome::Stopped;
        }
        Err(error) => return StopOutcome::Pending(format!("{error:#}")),
    };
    if let Err(error) =
        consent::write_consent(data_dir, ConsentState::Disabled, &marker.principal, &guard)
    {
        let reason = format!("the withdrawal could not be recorded: {error:#}");
        keep_pending_reason(data_dir, &reason, &guard);
        return StopOutcome::Pending(reason);
    }
    match PublicIpfsStore::stop(registry, data_dir, &guard).await {
        StopOutcome::Stopped => match consent::remove_withdrawal_marker(data_dir, &guard) {
            Ok(()) => StopOutcome::Stopped,
            Err(error) => StopOutcome::Pending(format!(
                "the store stopped but the withdrawal could not be closed: {error:#}"
            )),
        },
        StopOutcome::Pending(reason) => {
            keep_pending_reason(data_dir, &reason, &guard);
            StopOutcome::Pending(reason)
        }
    }
}

fn keep_pending_reason(data_dir: &Path, reason: &str, guard: &PublicStateGuard) {
    if let Err(error) = consent::record_withdrawal_pending(data_dir, reason, guard) {
        tracing::warn!(error = %format!("{error:#}"), "public IPFS stop reason was not kept");
    }
}

// ── Supervisor ──────────────────────────────────────────────────────

/// Keeps the store's run state equal to the consent: a 60 s tick, the first
/// at spawn. Only the Home gateway process runs one.
pub(crate) struct PublicIpfsSupervisor {
    task: tokio::task::JoinHandle<()>,
    cancel: watch::Sender<bool>,
}

impl PublicIpfsSupervisor {
    pub(crate) fn spawn(registry: Arc<ProviderRegistry>, data_dir: PathBuf) -> Self {
        let (cancel, mut cancelled) = watch::channel(false);
        let task = tokio::spawn(async move {
            loop {
                if *cancelled.borrow() {
                    break;
                }
                // A tick owns its transitions (an unregister, a start, a
                // Stop): it always runs to its end and is never dropped
                // midway, so no registration is left settling (A-F3).
                supervise_once(&registry, &data_dir).await;
                tokio::select! {
                    biased;
                    _ = cancelled.changed() => break,
                    () = tokio::time::sleep(SUPERVISOR_TICK) => {}
                }
            }
        });
        Self { task, cancel }
    }

    /// Cancel, then drain: the tick in flight finishes its transitions and no
    /// later tick starts. Then stop the store under the guard, waiting as
    /// long as a withdrawal would for an Enable that holds it (A-F3), so an
    /// enabled consent cannot restart the daemon during teardown.
    pub(crate) async fn shutdown(self, registry: &ProviderRegistry, data_dir: &Path) {
        let _ = self.cancel.send(true);
        if let Err(error) = self.task.await {
            tracing::warn!(%error, "public IPFS supervisor ended abnormally");
        }
        if !store_may_run(registry, data_dir).await {
            return;
        }
        let guard = match consent::acquire_public_state_lock(data_dir, WITHDRAWAL_LOCK_BUDGET).await
        {
            Ok(guard) => guard,
            Err(error) => {
                tracing::warn!(
                    detail = error.detail(),
                    "public IPFS store not stopped at shutdown"
                );
                return;
            }
        };
        match PublicIpfsStore::stop(registry, data_dir, &guard).await {
            StopOutcome::Stopped => tracing::info!("public IPFS store stopped at shutdown"),
            StopOutcome::Pending(reason) => {
                tracing::warn!(%reason, "public IPFS store stop is pending at shutdown");
            }
        }
    }
}

/// Whether any public state exists: without a consent record, a withdrawal
/// or a registration this Home never ran the store.
async fn store_may_run(registry: &ProviderRegistry, data_dir: &Path) -> bool {
    !matches!(consent::read_consent(data_dir), Ok(None))
        || !matches!(consent::read_withdrawal_marker(data_dir), Ok(None))
        || registry
            .has_ready_runtime_provider_target(PUBLIC_IPFS_TARGET)
            .await
}

/// Whether any public store state exists, whatever its liveness: a
/// `public-ipfs` registration in any state, the public coord, or a held
/// public repo lock. Read without the guard and without creating anything.
async fn public_state_exists(registry: &ProviderRegistry, data_dir: &Path) -> bool {
    registry
        .has_runtime_provider_target_registration(PUBLIC_IPFS_TARGET)
        .await
        || !matches!(read_public_coord(data_dir), Ok(None))
        || !matches!(public_repo_lock_holder(data_dir), Ok(None))
}

/// A5 closed-gate cleanup: the real Stop transition whenever any public
/// state exists. It never writes the consent (paused, not withdrawn) and
/// never starts; a `Pending` is retried by the next tick.
async fn stop_closed_gate(registry: &Arc<ProviderRegistry>, data_dir: &Path) {
    if !public_state_exists(registry, data_dir).await {
        return;
    }
    let guard = match consent::acquire_public_state_lock(data_dir, STATE_LOCK_BUDGET).await {
        Ok(guard) => guard,
        Err(error) => {
            tracing::debug!(
                detail = error.detail(),
                "public IPFS closed-gate cleanup waits for the next tick"
            );
            return;
        }
    };
    // A Stop that arrived while this waited wins; its completion runs next.
    if !matches!(consent::read_withdrawal_marker(data_dir), Ok(None)) {
        return;
    }
    match PublicIpfsStore::stop(registry, data_dir, &guard).await {
        StopOutcome::Stopped => {
            tracing::info!("public IPFS store stopped: sharing is not offered")
        }
        StopOutcome::Pending(reason) => {
            tracing::warn!(%reason, "public IPFS store stop is pending; sharing is not offered");
        }
    }
}

async fn supervise_once(registry: &Arc<ProviderRegistry>, data_dir: &Path) {
    // A requested withdrawal comes first, every tick, until it completes. It
    // is not gated (A5).
    if !matches!(consent::read_withdrawal_marker(data_dir), Ok(None)) {
        log_withdrawal(complete_withdrawal(registry, data_dir).await);
        return;
    }
    if !consent::public_metadata_offered(data_dir) {
        stop_closed_gate(registry, data_dir).await;
        return;
    }
    if !store_may_run(registry, data_dir).await {
        return;
    }
    let guard = match consent::acquire_public_state_lock(data_dir, STATE_LOCK_BUDGET).await {
        Ok(guard) => guard,
        Err(error) => {
            tracing::debug!(
                detail = error.detail(),
                "public IPFS supervisor tick skipped"
            );
            return;
        }
    };
    // A Stop that arrived while this waited wins; its completion runs next.
    if !matches!(consent::read_withdrawal_marker(data_dir), Ok(None)) {
        return;
    }
    let enabled = consent::consent_enabled(data_dir).unwrap_or_else(|error| {
        tracing::warn!(error = %format!("{error:#}"), "public IPFS consent is unreadable");
        false
    });
    let status = PublicIpfsStore::status(registry).await;
    match (enabled, status.liveness) {
        (false, StoreLiveness::Running) => {
            match PublicIpfsStore::stop(registry, data_dir, &guard).await {
                StopOutcome::Stopped => tracing::info!("public IPFS store stopped: consent is off"),
                StopOutcome::Pending(reason) => {
                    tracing::warn!(%reason, "public IPFS store stop is pending");
                }
            }
        }
        (true, StoreLiveness::Down) => {
            if let Err(error) = PublicIpfsStore::start(registry, data_dir, &guard).await {
                tracing::warn!(
                    code = error.code().as_str(),
                    detail = error.detail(),
                    "public IPFS store did not start"
                );
            }
        }
        _ => {}
    }
}

pub(crate) fn log_withdrawal(outcome: StopOutcome) {
    match outcome {
        StopOutcome::Stopped => {
            tracing::info!("public IPFS withdrawal complete; metadata sharing is off")
        }
        StopOutcome::Pending(reason) => {
            tracing::warn!(%reason, "public IPFS withdrawal is still pending");
        }
    }
}

// ── Public Kubo cleanup rule ────────────────────────────────────────

#[derive(serde::Deserialize)]
struct PublicCoord {
    mode: String,
    pid: u32,
    identity: String,
}

/// The `fcntl(F_GETLK)` holder of `ipfs-public-repo/repo.lock`, the lock
/// Kubo itself takes (go-fs-lock, F_SETLK). Only a public Kubo can hold it.
pub(crate) fn public_repo_lock_holder(data_dir: &Path) -> io::Result<Option<i32>> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let path = data_dir.join(PUBLIC_REPO_DIR).join(PUBLIC_REPO_LOCK);
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut lock = whole_file_write_lock();
    nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_GETLK(&mut lock)).map_err(io::Error::from)?;
    if lock.l_type == libc::F_UNLCK as libc::c_short {
        return Ok(None);
    }
    Ok(Some(lock.l_pid))
}

/// A whole-file write lock request (`F_WRLCK` from offset 0, length 0).
pub(crate) fn whole_file_write_lock() -> libc::flock {
    libc::flock {
        l_type: libc::F_WRLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    }
}

fn read_public_coord(data_dir: &Path) -> Result<Option<PublicCoord>, String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let path = data_dir.join(PUBLIC_COORD_FILE);
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("the public Kubo coord is unreadable: {error}")),
    };
    let mut bytes = Vec::new();
    file.take(MAX_COORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("the public Kubo coord is unreadable: {error}"))?;
    let coord: PublicCoord = serde_json::from_slice(&bytes)
        .ok()
        .filter(|_| bytes.len() as u64 <= MAX_COORD_BYTES)
        .ok_or("the public Kubo coord is malformed; evidence kept")?;
    if coord.mode != PUBLIC_MARKER {
        return Err("the public Kubo coord is not marked public; evidence kept".into());
    }
    Ok(Some(coord))
}

/// IP5: the repo's store-mode marker and the startup lock both say
/// `public`. A missing or different marker is another store's (or an
/// unmarked) repo, so nothing at the public paths is signalled.
fn require_public_mode_markers(data_dir: &Path) -> Result<(), String> {
    for (path, what) in [
        (
            data_dir.join(PUBLIC_REPO_DIR).join(PUBLIC_REPO_MODE_MARKER),
            "repo store-mode marker",
        ),
        (data_dir.join(PUBLIC_STARTUP_LOCK), "startup lock marker"),
    ] {
        match read_public_marker(&path) {
            Ok(true) => {}
            Ok(false) => {
                return Err(format!(
                    "the public {what} is missing or not `public`; nothing signalled, evidence kept"
                ));
            }
            Err(error) => {
                return Err(format!(
                    "the public {what} is unreadable ({error}); nothing signalled, evidence kept"
                ));
            }
        }
    }
    Ok(())
}

/// Whether the file at `path` holds exactly the `public` marker; a missing
/// file is `false`.
fn read_public_marker(path: &Path) -> io::Result<bool> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let mut marker = Vec::new();
    file.take(PUBLIC_MARKER.len() as u64 + 1)
        .read_to_end(&mut marker)?;
    Ok(marker == PUBLIC_MARKER.as_bytes())
}

fn remove_public_coord(data_dir: &Path) -> Result<(), String> {
    match std::fs::remove_file(data_dir.join(PUBLIC_COORD_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "the public Kubo coord could not be removed: {error}"
        )),
    }
}

fn process_identity_for(data_dir: &Path, pid: u32) -> io::Result<Option<String>> {
    #[cfg(test)]
    if let Some(identity) = test_seams::hooks(data_dir).and_then(|hooks| hooks.identity) {
        return identity(pid);
    }
    let _ = data_dir;
    elastos_common::process_identity::process_identity(pid)
}

type KuboSignal = dyn Fn(i32, i32) -> io::Result<()> + Send + Sync;

fn kubo_signal(data_dir: &Path) -> Arc<KuboSignal> {
    #[cfg(test)]
    if let Some(signal) = test_seams::hooks(data_dir).and_then(|hooks| hooks.signal) {
        return signal;
    }
    let _ = data_dir;
    Arc::new(send_signal)
}

/// `kill(pid, signal)`, with the OS error kept for the caller's ESRCH check.
pub(crate) fn send_signal(pid: i32, signal: i32) -> io::Result<()> {
    let signal = nix::sys::signal::Signal::try_from(signal).map_err(io::Error::from)?;
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), signal).map_err(io::Error::from)
}

/// The public Kubo cleanup rule, Runtime-side only, run under the state lock.
///
/// Nothing is signalled unless the repo and startup-lock markers both say
/// `public` (IP5). Candidates are the repo lock's holder and the coord's pid when its
/// process identity still equals the coord's: the owned child, even before
/// it takes the lock. Each is sent SIGTERM, then SIGKILL after 10 s, and the
/// rule succeeds only once every candidate's generation is gone and the lock
/// is free. A coord pid alive with another identity is pid reuse: never
/// signalled, and its stale coord is removed. Anything unproven fails closed
/// with the evidence kept. The private repo is never inspected.
///
/// Async, so its waits never block a Tokio worker.
pub(crate) async fn clear_public_kubo(data_dir: &Path, signal: &KuboSignal) -> Result<(), String> {
    let coord = read_public_coord(data_dir)?;
    let mut candidates: Vec<(u32, String)> = Vec::new();
    if let Some(coord) = &coord {
        match process_identity_for(data_dir, coord.pid) {
            Ok(Some(current)) if current == coord.identity => {
                candidates.push((coord.pid, current));
            }
            Ok(Some(_)) => {
                tracing::debug!(
                    pid = coord.pid,
                    "public Kubo coord names a reused pid; not signalled"
                );
            }
            Ok(None) => {}
            Err(error) => {
                return Err(format!(
                    "the public Kubo coord pid {} cannot be checked ({error}); evidence kept",
                    coord.pid
                ));
            }
        }
    }
    let holder = public_repo_lock_holder(data_dir)
        .map_err(|error| format!("the public Kubo repo lock cannot be checked: {error}"))?;
    if let Some(holder) = holder {
        let pid = u32::try_from(holder)
            .ok()
            .filter(|pid| *pid != 0)
            .ok_or_else(|| {
                format!("the public Kubo repo lock names pid {holder}; evidence kept")
            })?;
        if !candidates.iter().any(|(candidate, _)| *candidate == pid) {
            match process_identity_for(data_dir, pid) {
                Ok(Some(identity)) => candidates.push((pid, identity)),
                // Gone meanwhile; the lock check below decides.
                Ok(None) => {}
                Err(error) => {
                    return Err(format!(
                        "the public Kubo lock holder {pid} cannot be checked ({error}); evidence kept"
                    ));
                }
            }
        }
    }
    if !candidates.is_empty() {
        require_public_mode_markers(data_dir)?;
        tracing::info!(pids = ?candidates.iter().map(|(pid, _)| *pid).collect::<Vec<_>>(), "stopping a public Kubo left behind");
        signal_candidates(data_dir, &candidates, libc::SIGTERM, signal)?;
        if !wait_kubo_gone(data_dir, &candidates, CLEANUP_TERM_WAIT).await {
            signal_candidates(data_dir, &candidates, libc::SIGKILL, signal)?;
            if !wait_kubo_gone(data_dir, &candidates, CLEANUP_KILL_WAIT).await {
                return Err(format!(
                    "a public Kubo ({:?}) survived SIGKILL or holds the repo lock; evidence kept",
                    candidates.iter().map(|(pid, _)| *pid).collect::<Vec<_>>()
                ));
            }
        }
    }
    match public_repo_lock_holder(data_dir) {
        Ok(None) => {}
        Ok(Some(pid)) => {
            return Err(format!(
                "the public Kubo repo lock is still held by pid {pid}; evidence kept"
            ));
        }
        Err(error) => {
            return Err(format!(
                "the public Kubo repo lock cannot be checked: {error}"
            ));
        }
    }
    if coord.is_some() {
        remove_public_coord(data_dir)?;
    }
    Ok(())
}

/// Whether a captured candidate is still the generation it was captured as.
/// A PID that now names another process was reused: that generation is gone,
/// and the PID is never signalled again.
fn candidate_alive(data_dir: &Path, pid: u32, identity: &str) -> io::Result<bool> {
    match process_identity_for(data_dir, pid)? {
        Some(current) => Ok(current == identity),
        None => elastos_common::process_identity::generation_gone(pid, identity).map(|gone| !gone),
    }
}

/// Each candidate is re-validated right before its signal (A-F2): only a
/// PID that still names its captured generation is signalled.
fn signal_candidates(
    data_dir: &Path,
    candidates: &[(u32, String)],
    number: i32,
    signal: &KuboSignal,
) -> Result<(), String> {
    for (pid, identity) in candidates {
        match candidate_alive(data_dir, *pid, identity) {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(
                    pid,
                    number,
                    "public Kubo candidate already gone; not signalled"
                );
                continue;
            }
            Err(error) => {
                return Err(format!(
                    "the public Kubo pid {pid} cannot be re-checked before its signal ({error}); evidence kept"
                ));
            }
        }
        let target = i32::try_from(*pid).map_err(|_| format!("invalid public Kubo pid {pid}"))?;
        match signal(target, number) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
            Err(error) => {
                return Err(format!(
                    "the public Kubo pid {pid} could not be signalled ({error}); evidence kept"
                ));
            }
        }
    }
    Ok(())
}

/// Every candidate's generation gone and the repo lock free, within `wait`.
/// A transient unreadable view (an unreaped exit) is polled again.
async fn wait_kubo_gone(data_dir: &Path, candidates: &[(u32, String)], wait: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let gone = candidates
            .iter()
            .all(|(pid, identity)| matches!(candidate_alive(data_dir, *pid, identity), Ok(false)));
        if gone && matches!(public_repo_lock_holder(data_dir), Ok(None)) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(CLEANUP_POLL).await;
    }
}

#[cfg(test)]
pub(crate) mod test_seams {
    //! Per-data-dir test hooks: the provider launcher, the signal function
    //! and the identity reader. Production never consults them.

    use super::*;

    pub(crate) type Launch =
        Arc<dyn Fn(&PublicIpfsSettings) -> Result<Arc<dyn Provider>, String> + Send + Sync>;
    pub(crate) type Signal = Arc<KuboSignal>;
    pub(crate) type Identity = Arc<dyn Fn(u32) -> io::Result<Option<String>> + Send + Sync>;

    #[derive(Clone, Default)]
    pub(crate) struct StoreHooks {
        pub launch: Option<Launch>,
        pub signal: Option<Signal>,
        pub identity: Option<Identity>,
    }

    fn table() -> &'static StdMutex<HashMap<PathBuf, StoreHooks>> {
        static HOOKS: OnceLock<StdMutex<HashMap<PathBuf, StoreHooks>>> = OnceLock::new();
        HOOKS.get_or_init(Default::default)
    }

    pub(super) fn hooks(data_dir: &Path) -> Option<StoreHooks> {
        table()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(data_dir)
            .cloned()
    }

    pub(crate) fn install(data_dir: &Path, hooks: StoreHooks) -> HooksGuard {
        table()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(data_dir.to_path_buf(), hooks);
        HooksGuard(data_dir.to_path_buf())
    }

    pub(crate) struct HooksGuard(PathBuf);

    impl Drop for HooksGuard {
        fn drop(&mut self) {
            table()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&self.0);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;

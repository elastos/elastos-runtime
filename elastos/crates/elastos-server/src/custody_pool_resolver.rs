//! Plan B T4.3: where this Home finds an item's pool, and how it calls a
//! pool member.
//!
//! The resolver reads three sources, in this order:
//! - **own**: this Home's own pool descriptor (T3.3, owner);
//! - **served**: the descriptors this Home keeps as a pool member (T3.3);
//! - **known**: pools the admin added by address in Custody, kept in
//!   `protected-content/custody-known-pools.json`.
//!
//! A known pool is added only after a passkey step-up: its address names a
//! pool and a bootstrap member; the member's `describe` answer must verify
//! and be that pool's. The file is owner-only and bounded on read and write
//! (S4-Q11). Descriptors close to expiry are refreshed in the background.
//! Before a release, the item's already verified known pool is also checked
//! through public `describe`, under one existing node-round budget, so a
//! same-epoch sequence update reaches the reader before Wallet approval.
//!
//! [`RegistryPoolSessionTransport`] carries the pool session ops over the
//! Runtime's Carrier provider plane (S4-Q6), with a bounded answer wait on
//! both route kinds (S4-Q7).
//!
//! Item 10: descriptors and pool addresses carry no member tickets. A buyer
//! reaches every member by its peer DID through Carrier discovery. A pool
//! member that kept another member's node card (the owner that formed the
//! pool) dials that card's ticket.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Context as _;
use base64::Engine as _;
use elastos_protected_content_contracts::{
    CanonicalContract, KeyEnvelopeIdentityV1, PoolMemberRouteV2, SignedPoolDescriptorAnyV1,
    MAX_POOL_MEMBERS_V1, MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1,
};
use elastos_protected_content_runtime::{
    pool_wire_answer, PoolCallClass, PoolResolver, PoolResolverSource, PoolSessionClient,
    PoolSessionTransport, PoolTransportError, POOL_MISMATCH, POOL_OP_DESCRIBE,
};
use elastos_runtime::provider::{
    ProviderCarrierRoute, ProviderError, ProviderInvocation, ProviderInvocationTransport,
    ProviderRegistry, ProviderTransfer,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::custody_consent::CustodyWriteGuard;
use crate::custody_pool_setup::CustodyRefusal;
use crate::custody_surface::TARGET_CUSTODY_POOL;
use crate::protected_content_runtime::{
    protected_content_root, write_owner_only_bytes, RUNTIME_PROVIDER_ID,
};

pub(crate) const KNOWN_POOLS_FILE: &str = "custody-known-pools.json";
pub(crate) const KNOWN_POOLS_SCHEMA: &str = "elastos.protected-content.custody-known-pools/v1";
pub(crate) const MAX_KNOWN_POOLS: usize = 32;

const fn base64_len(bytes: usize) -> usize {
    bytes.div_ceil(3) * 4
}

/// 32 descriptors at their bound, plus room for each entry's address and
/// fields (S4-Q11).
pub(crate) const MAX_KNOWN_POOLS_FILE_BYTES: usize =
    MAX_KNOWN_POOLS * (base64_len(MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1) + 4 * 1024);

/// A known pool is refreshed once its descriptor has less than a day left.
const REFRESH_BEFORE_EXPIRY_SECS: u64 = 24 * 60 * 60;

/// Carrier budgets of a pool call: the connect, then the answer wait by
/// call class (S4-Q7). An open stages the item's content on the server, so
/// control calls get the longer wait.
const POOL_CONNECT_TIMEOUT_MS: u64 = 5_000;
const POOL_CONTROL_REPLY_WAIT_MS: u64 = 60_000;
const POOL_READ_REPLY_WAIT_MS: u64 = 30_000;
/// STAB-36 (J3-F3): the answer wait of one epoch-node call in a key release.
/// The release operation lives 50 s; a node that accepts the stream and
/// answers late must leave room for its replacement inside it: two calls
/// (connect and this wait each) take at most 40 s.
const POOL_RELEASE_REPLY_WAIT_MS: u64 = 15_000;

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Connect tickets from the node cards this Home kept, by peer DID.
pub(crate) type KeptCardTickets = BTreeMap<String, String>;

/// The pool session ops over the Carrier provider plane.
#[derive(Clone)]
pub(crate) struct RegistryPoolSessionTransport {
    registry: Arc<ProviderRegistry>,
    /// Empty on a Home that kept no member cards (every buyer).
    kept_card_tickets: Arc<KeptCardTickets>,
}

impl RegistryPoolSessionTransport {
    /// This Home's transport: the cards it kept for its own pool's members,
    /// read once, and Carrier discovery for every other route.
    pub(crate) fn new(data_dir: &Path, registry: Arc<ProviderRegistry>) -> Self {
        Self {
            registry,
            kept_card_tickets: Arc::new(crate::custody_pool_setup::kept_card_tickets(data_dir)),
        }
    }
}

/// A member route as a Carrier route (item 10): the ticket of a kept card
/// for that peer, else the peer DID through Carrier discovery. Both bound
/// the answer wait (S4-Q7).
pub(crate) fn carrier_route_for(
    route: &PoolMemberRouteV2,
    class: PoolCallClass,
    kept_card_tickets: &KeptCardTickets,
) -> ProviderCarrierRoute {
    let reply_wait_ms = match class {
        PoolCallClass::Control => POOL_CONTROL_REPLY_WAIT_MS,
        PoolCallClass::Read => POOL_READ_REPLY_WAIT_MS,
    };
    carrier_route_with_reply_wait(route, reply_wait_ms, kept_card_tickets)
}

/// STAB-36 (J3-F3): an epoch node's route for one release call, as
/// [`carrier_route_for`] builds it, with the release's shorter answer wait.
pub(crate) fn epoch_node_release_route(
    route: &PoolMemberRouteV2,
    kept_card_tickets: &KeptCardTickets,
) -> ProviderCarrierRoute {
    carrier_route_with_reply_wait(route, POOL_RELEASE_REPLY_WAIT_MS, kept_card_tickets)
}

fn carrier_route_with_reply_wait(
    route: &PoolMemberRouteV2,
    reply_wait_ms: u64,
    kept_card_tickets: &KeptCardTickets,
) -> ProviderCarrierRoute {
    let reply_wait_ms = Some(reply_wait_ms);
    match kept_card_tickets.get(route.peer_did()) {
        Some(ticket) => ProviderCarrierRoute::ConnectTicket {
            connect_ticket: ticket.clone(),
            peer_did: Some(route.peer_did().to_string()),
            timeout_ms: Some(POOL_CONNECT_TIMEOUT_MS),
            reply_wait_ms,
        },
        None => ProviderCarrierRoute::PeerDid {
            peer_did: route.peer_did().to_string(),
            timeout_ms: Some(POOL_CONNECT_TIMEOUT_MS),
            reply_wait_ms,
        },
    }
}

/// How a failed Carrier call reads to the pool client. No verified route
/// means nothing was sent (`Unreachable`). Any other failure may come after
/// the server acted (`NoExactResult`), except for `describe`, which never
/// acts.
pub(crate) fn pool_call_failure(op: &str, error: &ProviderError) -> PoolTransportError {
    if op == POOL_OP_DESCRIBE || matches!(error, ProviderError::Unavailable(_)) {
        PoolTransportError::Unreachable
    } else {
        PoolTransportError::NoExactResult
    }
}

#[async_trait::async_trait]
impl PoolSessionTransport for RegistryPoolSessionTransport {
    async fn call(
        &self,
        route: &PoolMemberRouteV2,
        op: &'static str,
        class: PoolCallClass,
        mut body: Value,
    ) -> Result<Value, PoolTransportError> {
        let Some(object) = body.as_object_mut() else {
            return Err(PoolTransportError::Refused("invalid_request".into()));
        };
        object.insert("op".into(), Value::String(op.to_string()));
        let answer = self
            .registry
            .invoke_provider(ProviderInvocation {
                source: RUNTIME_PROVIDER_ID.to_string(),
                target: TARGET_CUSTODY_POOL.to_string(),
                op: op.to_string(),
                request: body,
                transfer: ProviderTransfer::Json,
                range: None,
                progress: None,
                transport: ProviderInvocationTransport::Carrier(carrier_route_for(
                    route,
                    class,
                    &self.kept_card_tickets,
                )),
            })
            .await
            .map_err(|error| {
                tracing::debug!(%op, %error, "pool session call failed");
                pool_call_failure(op, &error)
            })?;
        pool_wire_answer(&answer)
    }
}

// ---------------------------------------------------------------------------
// Known pools file
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KnownPoolsFile {
    schema: String,
    pools: Vec<KnownPoolEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KnownPoolEntry {
    address: String,
    descriptor_b64: String,
    fetched_at: u64,
}

impl KnownPoolEntry {
    /// The kept descriptor, in its own version (item 10).
    fn descriptor(&self) -> Option<SignedPoolDescriptorAnyV1> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.descriptor_b64)
            .ok()?;
        if bytes.len() > MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1 {
            return None;
        }
        SignedPoolDescriptorAnyV1::from_canonical_bytes(&bytes).ok()
    }
}

/// What Custody shows for one known pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct KnownPoolView {
    pub pool: String,
    pub address: String,
    pub sequence: u64,
    pub members: usize,
    pub servers: usize,
    pub expires_at: u64,
    pub fetched_at: u64,
}

fn known_pools_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(KNOWN_POOLS_FILE)
}

fn load_known_pools(data_dir: &Path) -> anyhow::Result<KnownPoolsFile> {
    let path = known_pools_path(data_dir);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(KnownPoolsFile {
                schema: KNOWN_POOLS_SCHEMA.to_string(),
                pools: Vec::new(),
            });
        }
        Err(error) => return Err(error).context("the known pools file is unavailable"),
        Ok(_) => {}
    }
    let bytes = crate::collaboration_config::read_owner_only_file(
        &path,
        MAX_KNOWN_POOLS_FILE_BYTES,
        "custody known pools",
    )?;
    let file: KnownPoolsFile =
        serde_json::from_slice(&bytes).context("the known pools file is invalid")?;
    if file.schema != KNOWN_POOLS_SCHEMA || file.pools.len() > MAX_KNOWN_POOLS {
        anyhow::bail!("the known pools file is invalid");
    }
    Ok(file)
}

fn store_known_pools(
    _write: &CustodyWriteGuard,
    data_dir: &Path,
    file: &KnownPoolsFile,
) -> anyhow::Result<()> {
    if file.pools.len() > MAX_KNOWN_POOLS {
        return Err(CustodyRefusal::new("too_many_pools").into());
    }
    let bytes = serde_json::to_vec(file)?;
    if bytes.len() > MAX_KNOWN_POOLS_FILE_BYTES {
        return Err(CustodyRefusal::new("too_many_pools").into());
    }
    write_owner_only_bytes(&known_pools_path(data_dir), &bytes)
}

/// A pool past its window is still listed; the resolver skips it.
fn view_of(entry: &KnownPoolEntry) -> Option<KnownPoolView> {
    let signed = entry.descriptor()?;
    let pool = signed.pool().to_did_key().ok()?;
    // Member roles are the same in every version; only v1 routes differ.
    let roles = match &signed {
        SignedPoolDescriptorAnyV1::V1(descriptor) => descriptor
            .statement()
            .members()
            .iter()
            .map(|member| member.roles().serve)
            .collect::<Vec<_>>(),
        SignedPoolDescriptorAnyV1::V2(descriptor) => descriptor
            .statement()
            .members()
            .iter()
            .map(|member| member.roles().serve)
            .collect(),
        SignedPoolDescriptorAnyV1::V3(descriptor) => descriptor
            .statement()
            .members()
            .iter()
            .map(|member| member.roles().serve)
            .collect(),
    };
    Some(KnownPoolView {
        pool,
        address: entry.address.clone(),
        sequence: signed.sequence(),
        members: roles.len(),
        servers: roles.iter().filter(|serve| **serve).count(),
        expires_at: signed.expires_at(),
        fetched_at: entry.fetched_at,
    })
}

/// The kept descriptors of the known pools, read only: no Carrier call and
/// no refresh (Plan B T4.6, the cached resolve).
pub(crate) fn known_pool_descriptors(data_dir: &Path) -> Vec<SignedPoolDescriptorAnyV1> {
    load_known_pools(data_dir)
        .map(|file| {
            file.pools
                .iter()
                .filter_map(KnownPoolEntry::descriptor)
                .collect()
        })
        .unwrap_or_default()
}

/// The most members of the pools this Home uses that a content fetch asks,
/// beside its other holders (the Carrier candidate bound is 8 too).
pub(crate) const MAX_KNOWN_POOL_CONTENT_HOLDERS: usize = 8;

/// The peer DIDs of the members of the pools this Home uses, from the kept
/// descriptors that verify at `now` (signature and term); an expired,
/// unreadable or unverified one contributes nobody. In kept order, unique,
/// at most [`MAX_KNOWN_POOL_CONTENT_HOLDERS`]. A buyer Home asks them for a
/// pool item's content; the bytes are still checked against their CIDs.
pub(crate) fn known_pool_member_peer_dids(data_dir: &Path, now: u64) -> Vec<String> {
    known_pool_member_peer_dids_for(data_dir, None, now)
}

/// STAB-10 (J4-F7, D3): [`known_pool_member_peer_dids`], with the members of
/// the pools that name `item_pool` (the item's own) first, so they are within
/// the bound however many other pools this Home uses.
pub(crate) fn known_pool_member_peer_dids_for(
    data_dir: &Path,
    item_pool: Option<elastos_protected_content_contracts::CustodyPoolIdentityV1>,
    now: u64,
) -> Vec<String> {
    let mut descriptors = known_pool_descriptors(data_dir);
    if let Some(item_pool) = item_pool {
        descriptors.sort_by_key(|descriptor| {
            !crate::custody_pool_descriptor::descriptor_names_custody_pool(descriptor, item_pool)
        });
    }
    bounded_unique_peer_dids(
        descriptors
            .into_iter()
            .filter_map(|descriptor| descriptor.verify(now).ok())
            .flat_map(|verified| {
                verified
                    .members()
                    .iter()
                    .map(|member| member.route().peer_did().to_string())
                    .collect::<Vec<_>>()
            }),
    )
}

/// The first [`MAX_KNOWN_POOL_CONTENT_HOLDERS`] distinct DIDs, in order.
pub(crate) fn bounded_unique_peer_dids(dids: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    for did in dids {
        if kept.len() == MAX_KNOWN_POOL_CONTENT_HOLDERS {
            break;
        }
        if !kept.contains(&did) {
            kept.push(did);
        }
    }
    kept
}

/// Keeps `descriptor` as a known pool with no `describe` call, for tests
/// whose pool has no member to answer (Plan B T4.7).
#[cfg(test)]
pub(crate) fn keep_known_pool_for_test(
    write: &CustodyWriteGuard,
    data_dir: &Path,
    address: &str,
    descriptor: &SignedPoolDescriptorAnyV1,
    fetched_at: u64,
) -> anyhow::Result<()> {
    let bytes = descriptor
        .canonical_bytes()
        .map_err(|_| anyhow::anyhow!("the test descriptor does not encode"))?;
    let mut file = load_known_pools(data_dir)?;
    file.pools.push(KnownPoolEntry {
        address: address.to_string(),
        descriptor_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
        fetched_at,
    });
    store_known_pools(write, data_dir, &file)
}

/// The pools this Home uses, for Custody.
pub(crate) fn known_pools(data_dir: &Path) -> anyhow::Result<Vec<KnownPoolView>> {
    Ok(load_known_pools(data_dir)?
        .pools
        .iter()
        .filter_map(view_of)
        .collect())
}

/// Adds the pool at `address`, or replaces its kept descriptor (S4-Q13).
/// Refusals: `bad_address` (400), `pool_unreachable`, `pool_invalid` and
/// `too_many_pools` (409). The caller checked the admin and the step-up
/// before it took `write`.
pub(crate) async fn add_known_pool(
    write: &CustodyWriteGuard,
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    address: &str,
    now: u64,
) -> anyhow::Result<KnownPoolView> {
    let client = PoolSessionClient::new(RegistryPoolSessionTransport::new(data_dir, registry));
    add_known_pool_with(write, data_dir, &client, address, now).await
}

pub(crate) async fn add_known_pool_with<T: PoolSessionTransport>(
    write: &CustodyWriteGuard,
    data_dir: &Path,
    client: &PoolSessionClient<T>,
    address: &str,
    now: u64,
) -> anyhow::Result<KnownPoolView> {
    let address = address.trim();
    let parsed = crate::custody_pool_descriptor::parse_pool_address(address)
        .map_err(|error| CustodyRefusal::from_error("bad_address", &error))?;
    // Either address version; a v1 bootstrap ticket is never used (item 10).
    let bootstrap = PoolMemberRouteV2::new(parsed.peer_did().to_string())
        .map_err(|error| CustodyRefusal::with_detail("bad_address", format!("{error:?}")))?;
    let signed = match client.describe(&bootstrap, parsed.pool()).await {
        Ok(signed) => signed,
        Err(PoolTransportError::Refused(code)) if code == POOL_MISMATCH => {
            return Err(CustodyRefusal::with_detail(
                "pool_invalid",
                "the pool's member answered for another pool",
            )
            .into());
        }
        Err(error) => {
            return Err(CustodyRefusal::with_detail("pool_unreachable", error.to_string()).into());
        }
    };
    let verified = signed
        .verify(now)
        .map_err(|error| CustodyRefusal::with_detail("pool_invalid", format!("{error:?}")))?;
    if verified.pool() != parsed.pool() {
        return Err(CustodyRefusal::with_detail(
            "pool_invalid",
            "the pool's member answered for another pool",
        )
        .into());
    }
    let entry = KnownPoolEntry {
        address: address.to_string(),
        descriptor_b64: base64::engine::general_purpose::STANDARD.encode(signed.canonical_bytes()?),
        fetched_at: now,
    };
    let mut file = load_known_pools(data_dir)?;
    match position_of_pool(&file, parsed.pool()) {
        // T43-F1: a newer kept descriptor stays (monotonic per pool).
        Some(index) if kept_sequence(&file.pools[index]) > verified.sequence() => {
            tracing::debug!(
                sequence = verified.sequence(),
                "a newer descriptor of this pool is already kept"
            );
            return view_of(&file.pools[index]).context("the kept pool cannot be shown");
        }
        Some(index) => file.pools[index] = entry.clone(),
        None if file.pools.len() >= MAX_KNOWN_POOLS => {
            return Err(CustodyRefusal::new("too_many_pools").into());
        }
        None => file.pools.push(entry.clone()),
    }
    store_known_pools(write, data_dir, &file)?;
    tracing::debug!(sequence = verified.sequence(), "known custody pool added");
    view_of(&entry).context("the added pool cannot be shown")
}

/// The entry that keeps `pool`'s descriptor.
fn position_of_pool(
    file: &KnownPoolsFile,
    pool: &elastos_protected_content_contracts::PoolDidV1,
) -> Option<usize> {
    file.pools.iter().position(|kept| {
        kept.descriptor()
            .is_some_and(|descriptor| descriptor.pool() == pool)
    })
}

fn kept_sequence(entry: &KnownPoolEntry) -> u64 {
    entry
        .descriptor()
        .map_or(0, |descriptor| descriptor.sequence())
}

/// T43-F2: the kept members' peer DIDs, read from the kept descriptor even
/// past its window. They are discovery hints only, never release authority:
/// what a hint answers must itself verify at now and be this pool's.
/// Bounded by the descriptor's member limit, without the bootstrap.
fn member_hints(
    kept: &SignedPoolDescriptorAnyV1,
    bootstrap: &PoolMemberRouteV2,
) -> Vec<PoolMemberRouteV2> {
    let peer_dids: Vec<&str> = match kept {
        SignedPoolDescriptorAnyV1::V1(descriptor) => descriptor
            .statement()
            .members()
            .iter()
            .map(|member| member.route().peer_did())
            .collect(),
        SignedPoolDescriptorAnyV1::V2(descriptor) => descriptor
            .statement()
            .members()
            .iter()
            .map(|member| member.route().peer_did())
            .collect(),
        SignedPoolDescriptorAnyV1::V3(descriptor) => descriptor
            .statement()
            .members()
            .iter()
            .map(|member| member.route().peer_did())
            .collect(),
    };
    let mut hints: Vec<PoolMemberRouteV2> = Vec::new();
    for peer_did in peer_dids.into_iter().take(MAX_POOL_MEMBERS_V1) {
        let Ok(route) = PoolMemberRouteV2::new(peer_did.to_string()) else {
            continue;
        };
        if &route != bootstrap && !hints.contains(&route) {
            hints.push(route);
        }
    }
    hints
}

/// Best effort: asks each known pool whose descriptor has less than a day
/// left, or is past its window, for a newer one, first at its address's
/// bootstrap member, then at the kept members' peer DIDs (T43-F2). A newer
/// descriptor that verifies at now and is the same pool's replaces the
/// kept one, if it is still newer than the entry kept when the write lock
/// is held (T43-F1).
pub(crate) async fn refresh_known_pools<T: PoolSessionTransport>(
    data_dir: &Path,
    client: &PoolSessionClient<T>,
    now: u64,
) -> anyhow::Result<usize> {
    let due = load_known_pools(data_dir)?
        .pools
        .into_iter()
        .filter(|entry| {
            entry.descriptor().is_some_and(|descriptor| {
                descriptor.expires_at() <= now.saturating_add(REFRESH_BEFORE_EXPIRY_SECS)
            })
        })
        .collect::<Vec<_>>();
    refresh_known_pool_entries(data_dir, client, due, None, now).await
}

/// The shared describe/verify/monotonic-store path. A release refresh is
/// restricted to the exact item epoch it already knows; expiry maintenance
/// retains its existing descriptor-renewal behavior.
async fn refresh_known_pool_entries<T: PoolSessionTransport>(
    data_dir: &Path,
    client: &PoolSessionClient<T>,
    due: Vec<KnownPoolEntry>,
    key_envelope: Option<&KeyEnvelopeIdentityV1>,
    now: u64,
) -> anyhow::Result<usize> {
    let mut fresh = Vec::new();
    for entry in due {
        let (Ok(address), Some(kept)) = (
            crate::custody_pool_descriptor::parse_pool_address(&entry.address),
            entry.descriptor(),
        ) else {
            continue;
        };
        // The address bootstrap's peer DID, then the kept members' peer
        // DIDs (item 10: no tickets).
        let Ok(bootstrap) = PoolMemberRouteV2::new(address.peer_did().to_string()) else {
            continue;
        };
        let hints = member_hints(&kept, &bootstrap);
        for route in std::iter::once(bootstrap).chain(hints) {
            let Ok(newer) = client.describe(&route, address.pool()).await else {
                continue;
            };
            let pool_matches = newer.verify(now).is_ok_and(|verified| {
                verified.pool() == address.pool()
                    && key_envelope.is_none_or(|key_envelope| {
                        verified.admits_new_release().is_ok()
                            && verified.epoch_for(key_envelope).is_some()
                    })
            });
            if pool_matches && newer.sequence() > kept.sequence() {
                fresh.push(newer);
                break;
            }
        }
    }
    if fresh.is_empty() {
        return Ok(0);
    }
    let write = crate::custody_consent::lock_custody_writes().await;
    let mut file = load_known_pools(data_dir)?;
    let mut replaced = 0;
    for newer in fresh {
        // T43-F1: recheck against the entry kept now, not the snapshot the
        // describe started from; the newer descriptor wins.
        let Some(index) = position_of_pool(&file, newer.pool()) else {
            continue;
        };
        let entry = &mut file.pools[index];
        if kept_sequence(entry) >= newer.sequence() {
            continue;
        }
        entry.descriptor_b64 =
            base64::engine::general_purpose::STANDARD.encode(newer.canonical_bytes()?);
        entry.fetched_at = now;
        replaced += 1;
    }
    if replaced == 0 {
        return Ok(0);
    }
    store_known_pools(&write, data_dir, &file)?;
    Ok(replaced)
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

pub(crate) struct OwnPoolSource {
    data_dir: PathBuf,
}

#[async_trait::async_trait]
impl PoolResolverSource for OwnPoolSource {
    fn name(&self) -> &'static str {
        "own"
    }

    async fn candidates(
        &self,
        _key_envelope: &KeyEnvelopeIdentityV1,
    ) -> Vec<SignedPoolDescriptorAnyV1> {
        // `owner_descriptor` takes its own lock and may sign (T3.3).
        match crate::custody_pool_descriptor::owner_descriptor(
            &self.data_dir,
            crate::auth::now_ts(),
        ) {
            Ok(descriptor) => descriptor.into_iter().map(Into::into).collect(),
            Err(error) => {
                tracing::debug!(error = %format!("{error:#}"), "own pool descriptor unavailable");
                Vec::new()
            }
        }
    }
}

pub(crate) struct ServedPoolSource {
    data_dir: PathBuf,
}

#[async_trait::async_trait]
impl PoolResolverSource for ServedPoolSource {
    fn name(&self) -> &'static str {
        "served"
    }

    async fn candidates(
        &self,
        _key_envelope: &KeyEnvelopeIdentityV1,
    ) -> Vec<SignedPoolDescriptorAnyV1> {
        crate::custody_pool_descriptor::served_descriptors(&self.data_dir, crate::auth::now_ts())
            .unwrap_or_else(|error| {
                tracing::debug!(
                    error = %format!("{error:#}"),
                    "served pool descriptors unavailable"
                );
                Vec::new()
            })
    }
}

/// One background refresh at a time.
static KNOWN_POOL_REFRESH_RUNNING: AtomicBool = AtomicBool::new(false);

pub(crate) struct KnownPoolSource {
    data_dir: PathBuf,
    /// The background refresh asks members through it.
    transport: RegistryPoolSessionTransport,
}

impl KnownPoolSource {
    pub(crate) fn new(data_dir: PathBuf, registry: Arc<ProviderRegistry>) -> Self {
        Self {
            transport: RegistryPoolSessionTransport::new(&data_dir, registry),
            data_dir,
        }
    }

    /// Starts a refresh when a kept descriptor is near its end; the open
    /// that asked does not wait for it.
    fn refresh_in_background(&self, entries: &[KnownPoolEntry], now: u64) {
        let due = entries.iter().any(|entry| {
            entry.descriptor().is_some_and(|descriptor| {
                descriptor.expires_at() <= now.saturating_add(REFRESH_BEFORE_EXPIRY_SECS)
            })
        });
        if !due || KNOWN_POOL_REFRESH_RUNNING.swap(true, Ordering::SeqCst) {
            return;
        }
        let data_dir = self.data_dir.clone();
        let client = PoolSessionClient::new(self.transport.clone());
        tokio::spawn(async move {
            if let Err(error) = refresh_known_pools(&data_dir, &client, now).await {
                tracing::debug!(error = %format!("{error:#}"), "known pools were not refreshed");
            }
            KNOWN_POOL_REFRESH_RUNNING.store(false, Ordering::SeqCst);
        });
    }
}

#[async_trait::async_trait]
impl PoolResolverSource for KnownPoolSource {
    fn name(&self) -> &'static str {
        "known"
    }

    async fn candidates(
        &self,
        key_envelope: &KeyEnvelopeIdentityV1,
    ) -> Vec<SignedPoolDescriptorAnyV1> {
        let mut file = match load_known_pools(&self.data_dir) {
            Ok(file) => file,
            Err(error) => {
                tracing::debug!(error = %format!("{error:#}"), "known pools unavailable");
                return Vec::new();
            }
        };
        let now = crate::auth::now_ts();
        // A release checks only its already verified pool and epoch, not
        // every pool this Home knows. This finishes before the caller can
        // prepare recipients or ask the Wallet, so no second approval is
        // needed to replace a stale descriptor sequence.
        let target = file
            .pools
            .iter()
            .find(|entry| {
                entry.descriptor().is_some_and(|signed| {
                    signed.verify(now).is_ok_and(|verified| {
                        verified.admits_new_release().is_ok()
                            && verified.epoch_for(key_envelope).is_some()
                    })
                })
            })
            .cloned();
        if let Some(target) = target {
            let client = PoolSessionClient::new(self.transport.clone());
            // One existing epoch-node round (5 s connect + 15 s answer)
            // bounds the entire refresh, including all fallback peers.
            // An unresponsive first peer can consume this whole budget.
            let budget = std::time::Duration::from_millis(
                POOL_CONNECT_TIMEOUT_MS + POOL_RELEASE_REPLY_WAIT_MS,
            );
            match tokio::time::timeout(
                budget,
                refresh_known_pool_entries(
                    &self.data_dir,
                    &client,
                    vec![target],
                    Some(key_envelope),
                    now,
                ),
            )
            .await
            {
                Ok(Ok(_)) => {
                    if let Ok(current) = load_known_pools(&self.data_dir) {
                        file = current;
                    }
                }
                Ok(Err(error)) => {
                    tracing::debug!(error = %format!("{error:#}"), "the item's known pool was not refreshed")
                }
                Err(_) => tracing::debug!("the item's known pool refresh wait passed"),
            }
        }
        // An unreachable or invalid answer leaves the verified cached
        // descriptor available. Node high-water protection still decides
        // whether that descriptor can participate in a release.
        self.refresh_in_background(&file.pools, now);
        file.pools
            .iter()
            .filter_map(KnownPoolEntry::descriptor)
            .collect()
    }
}

/// The sources in resolve order: own, served, known.
pub(crate) fn home_pool_sources(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
) -> Vec<Box<dyn PoolResolverSource>> {
    vec![
        Box::new(OwnPoolSource {
            data_dir: data_dir.to_path_buf(),
        }),
        Box::new(ServedPoolSource {
            data_dir: data_dir.to_path_buf(),
        }),
        Box::new(KnownPoolSource::new(data_dir.to_path_buf(), registry)),
    ]
}

/// This Home's resolver over its own, served and known pools. T4.4 and T4.6
/// resolve through it.
pub(crate) fn home_pool_resolver(data_dir: &Path, registry: Arc<ProviderRegistry>) -> PoolResolver {
    PoolResolver::new(home_pool_sources(data_dir, registry))
}

#[cfg(all(test, unix))]
pub(crate) mod tests;

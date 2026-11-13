//! Plan B T4.2: the buyer side of a pool session, gateway-free.
//!
//! [`PoolResolver`] finds the item's pool from descriptor sources (this
//! Home's own pool, the pools it serves, the pools it knows) and keeps the
//! descriptor that names the item's epoch. [`select_session_servers`] picks
//! the session's servers by rendezvous hashing over the serve members of
//! that epoch. [`PoolSessionClient`] encodes the pool session wire ops
//! (`handoff-3b-rev3.md`, wire table) over an injected
//! [`PoolSessionTransport`]; the Carrier adapter lives in elastos-server
//! (T4.3).
//!
//! A server's answer is trusted only as far as it can be checked here: a
//! prepare answer must carry a node-signed attestation for the asked server
//! and request, and an open answer must name the operation's own expiry.
//! An answer that cannot be read after a call that may have acted is
//! [`PoolTransportError::NoExactResult`] (S4-Q10).
//!
//! Item 10: descriptors carry no member tickets. Sources answer either
//! descriptor version ([`SignedPoolDescriptorAnyV1`]); the verified form and
//! every member and route here are the ticketless v2 shapes, and the
//! transport reaches a member by its peer DID.

use base64::Engine as _;
use elastos_protected_content_contracts::{
    CanonicalContract, ContractError, KeyEnvelopeIdentityV1, NodePublicKey, PoolDidV1,
    PoolEpochBundleV1, PoolMemberRouteV2, PoolMemberV2, PoolSessionContentKindV1,
    RecipientPublicKeyBytesV1, SignedPoolDescriptorAnyV1, SignedPoolRecipientAttestationV2,
    VerifiedPoolDescriptorV1, ViewerPartIndexV1, PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::pool_session::{
    PoolContentIdentityV1, PoolSessionIdV1, PoolSessionOpenV1, PoolSessionOpenedV1,
    PoolSessionPrepareV1, PoolSessionPreparedV1, PoolSessionReadV1, PoolSessionRefusal,
};

/// The `custody-pool` wire ops (T3.4's surface rows).
pub const POOL_OP_DESCRIBE: &str = "describe";
pub const POOL_OP_SESSION_PREPARE: &str = "session.prepare";
pub const POOL_OP_SESSION_OPEN: &str = "session.open";
pub const POOL_OP_SESSION_READ: &str = "session.read";
pub const POOL_OP_SESSION_CLOSE: &str = "session.close";

/// The longest refusal code read off the wire.
const MAX_WIRE_CODE_BYTES: usize = 64;
/// `describe` answered another pool's descriptor (Plan B T4.3): the member
/// is reachable, but its answer is not this pool's.
pub const POOL_MISMATCH: &str = "pool_mismatch";
/// The code a malformed request earns on the server; used when this side
/// cannot even encode one, so nothing was sent.
const INVALID_REQUEST: &str = "invalid_request";

// ---------------------------------------------------------------------------
// Resolve
// ---------------------------------------------------------------------------

/// Where pool descriptors come from (own, served, known: T4.3).
#[async_trait::async_trait]
pub trait PoolResolverSource: Send + Sync {
    fn name(&self) -> &'static str;
    /// Either descriptor version; v1 bytes are historical reads (item 10).
    async fn candidates(
        &self,
        key_envelope: &KeyEnvelopeIdentityV1,
    ) -> Vec<SignedPoolDescriptorAnyV1>;
}

/// The S5 seam: which verified pools this Home trusts. M1 trusts every
/// verified descriptor ([`AcceptAnyPool`]).
pub trait PoolTrustCheck: Send + Sync {
    fn accept(&self, descriptor: &VerifiedPoolDescriptorV1) -> bool;
}

/// M1's trust check: every descriptor that verifies.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAnyPool;

impl PoolTrustCheck for AcceptAnyPool {
    fn accept(&self, _descriptor: &VerifiedPoolDescriptorV1) -> bool {
        true
    }
}

/// The item's pool: the descriptor kept, and the bundle it names for the
/// item's key envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPoolV1 {
    /// The descriptor as its source held it, in its own version (item 10).
    pub signed: SignedPoolDescriptorAnyV1,
    pub descriptor: VerifiedPoolDescriptorV1,
    pub epoch: PoolEpochBundleV1,
    pub source: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PoolResolveError {
    #[error("no pool descriptor names this item")]
    Unresolved,
    #[error("the item's pool has no server this Home may use")]
    NoEligibleServer,
    #[error("no pool descriptor for this item verifies")]
    Invalid,
}

pub struct PoolResolver {
    sources: Vec<Box<dyn PoolResolverSource>>,
    trust: Box<dyn PoolTrustCheck>,
}

impl PoolResolver {
    pub fn new(sources: Vec<Box<dyn PoolResolverSource>>) -> Self {
        Self {
            sources,
            trust: Box::new(AcceptAnyPool),
        }
    }

    /// Replaces M1's [`AcceptAnyPool`] (S5).
    #[must_use]
    pub fn with_trust_check(mut self, trust: Box<dyn PoolTrustCheck>) -> Self {
        self.trust = trust;
        self
    }

    /// verify → the item's epoch (others skipped, S4-Q9) → trust → highest
    /// sequence. Sequence orders only within one composition (L13); the
    /// epoch filter comes first, so only one composition's descriptors are
    /// compared. On a tie the earlier source wins. The pool must keep at
    /// least one serve member of the item's epoch outside `exclude`, unless
    /// it allows self-serve.
    pub async fn resolve(
        &self,
        key_envelope: &KeyEnvelopeIdentityV1,
        exclude: &[NodePublicKey],
        now: u64,
    ) -> Result<ResolvedPoolV1, PoolResolveError> {
        let mut candidates = Vec::new();
        for source in &self.sources {
            for signed in source.candidates(key_envelope).await {
                candidates.push((source.name(), signed));
            }
        }
        resolve_pool_from_candidates(candidates, self.trust.as_ref(), key_envelope, exclude, now)
    }
}

/// The resolve rules over candidates already gathered, in source order:
/// verify → admits a new release (#388 A2) → the item's epoch (others
/// skipped, S4-Q9) → trust → highest
/// sequence, the earlier source winning a tie; then at least one serve
/// member of that epoch outside `exclude`, unless the pool allows
/// self-serve. Plan B T4.6: a caller that must not reach Carrier gathers
/// its cached candidates and resolves here.
pub fn resolve_pool_from_candidates(
    candidates: Vec<(&'static str, SignedPoolDescriptorAnyV1)>,
    trust: &dyn PoolTrustCheck,
    key_envelope: &KeyEnvelopeIdentityV1,
    exclude: &[NodePublicKey],
    now: u64,
) -> Result<ResolvedPoolV1, PoolResolveError> {
    let mut seen = 0usize;
    let mut verified = 0usize;
    let mut best: Option<ResolvedPoolV1> = None;
    for (source, signed) in candidates {
        seen += 1;
        let Ok(descriptor) = signed.verify(now) else {
            tracing::debug!(source, "pool resolve: a descriptor did not verify");
            continue;
        };
        verified += 1;
        // #388 A2: a historical descriptor (trust absent) only reads; a new
        // open needs a trusted v3 pool.
        if descriptor.admits_new_release().is_err() {
            tracing::debug!(source, "pool resolve: the descriptor admits no new release");
            continue;
        }
        let Some(epoch) = descriptor.epoch_for(key_envelope).cloned() else {
            continue;
        };
        if !trust.accept(&descriptor) {
            tracing::debug!(source, "pool resolve: pool not trusted");
            continue;
        }
        if best
            .as_ref()
            .is_some_and(|kept| kept.descriptor.sequence() >= descriptor.sequence())
        {
            continue;
        }
        best = Some(ResolvedPoolV1 {
            signed,
            descriptor,
            epoch,
            source,
        });
    }
    let Some(resolved) = best else {
        return Err(if seen > 0 && verified == 0 {
            PoolResolveError::Invalid
        } else {
            PoolResolveError::Unresolved
        });
    };
    if eligible_servers(&resolved, exclude).is_empty() {
        return Err(PoolResolveError::NoEligibleServer);
    }
    Ok(resolved)
}

/// Serve members of the resolved epoch, outside `exclude` unless the pool
/// allows self-serve (D2).
fn eligible_servers<'a>(
    resolved: &'a ResolvedPoolV1,
    exclude: &[NodePublicKey],
) -> Vec<&'a PoolMemberV2> {
    let Ok(node_set) = resolved.epoch.signed_epoch().statement().node_set() else {
        return Vec::new();
    };
    let allow_self_serve = resolved.descriptor.serve_policy().allow_self_serve;
    resolved
        .descriptor
        .members()
        .iter()
        .filter(|member| {
            member.roles().serve
                && node_set.contains(member.node_public_key())
                && (allow_self_serve || !exclude.contains(&member.node_public_key()))
        })
        .collect()
}

fn rendezvous_weight(session_seed: &[u8; 16], node: NodePublicKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(session_seed);
    hasher.update(node.as_bytes());
    hasher.finalize().into()
}

/// The session's servers (S4-Q8): serve members of the resolved epoch, not
/// excluded (unless self-serve is allowed), ordered by
/// `sha256(seed ‖ node key)` descending, at most `wanted`. The buyer draws
/// `session_seed` at random, so load spreads over the pool.
pub fn select_session_servers(
    resolved: &ResolvedPoolV1,
    session_seed: [u8; 16],
    exclude: &[NodePublicKey],
    wanted: usize,
) -> Vec<PoolMemberV2> {
    let mut ranked = eligible_servers(resolved, exclude)
        .into_iter()
        .map(|member| {
            (
                rendezvous_weight(&session_seed, member.node_public_key()),
                member,
            )
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| right.0.cmp(&left.0));
    ranked
        .into_iter()
        .take(wanted)
        .map(|(_, member)| member.clone())
        .collect()
}

/// Which of `servers` reads `part` (used from T4.8; m = 1 at M1). Part n of
/// a rendition goes to `(rendition + n) mod servers`, so renditions start
/// on different servers. A rendition's init goes with its first segment.
pub fn stripe_index(part: &ViewerPartIndexV1, servers: usize) -> usize {
    if servers == 0 {
        return 0;
    }
    let (rendition, index) = match *part {
        ViewerPartIndexV1::MediaV1Init => (0, 0),
        ViewerPartIndexV1::MediaV1Segment(index) | ViewerPartIndexV1::ObjectChunk(index) => {
            (0, index)
        }
        ViewerPartIndexV1::DashInit { rendition } => (rendition, 0),
        ViewerPartIndexV1::DashSegment { rendition, index } => (rendition, index),
    };
    let position = u64::from(rendition) + u64::from(index);
    // `servers` fits u64 on every supported target.
    (position % servers as u64) as usize
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// How long a call may wait for its reply; the adapter maps it to
/// `reply_wait_ms` (T4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolCallClass {
    Control,
    Read,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PoolTransportError {
    /// The server was not reached; it did not act.
    #[error("pool server is unreachable")]
    Unreachable,
    /// The server refused with a wire code (the T3.2 set).
    #[error("pool server refused: {0}")]
    Refused(String),
    /// The call may have acted and no exact answer came back.
    #[error("pool server gave no exact answer")]
    NoExactResult,
}

#[async_trait::async_trait]
pub trait PoolSessionTransport: Send + Sync {
    /// Ok is the `data` of `{status:"ok", data}`; see [`pool_wire_answer`].
    async fn call(
        &self,
        route: &PoolMemberRouteV2,
        op: &'static str,
        class: PoolCallClass,
        body: Value,
    ) -> Result<Value, PoolTransportError>;
}

/// Reads one `custody-pool` answer (E12, R5): `{status:"ok", data}` gives
/// `data`; `{status:"error", code}` gives `Refused(code)`; anything else is
/// `NoExactResult`. Transports use it on what Carrier carried.
pub fn pool_wire_answer(answer: &Value) -> Result<Value, PoolTransportError> {
    match answer.get("status").and_then(Value::as_str) {
        Some("ok") => answer
            .get("data")
            .filter(|data| data.is_object())
            .cloned()
            .ok_or(PoolTransportError::NoExactResult),
        Some("error") => Err(answer
            .get("code")
            .and_then(Value::as_str)
            .filter(|code| !code.is_empty() && code.len() <= MAX_WIRE_CODE_BYTES)
            .map_or(PoolTransportError::NoExactResult, |code| {
                PoolTransportError::Refused(code.to_string())
            })),
        _ => Err(PoolTransportError::NoExactResult),
    }
}

/// The T3.2 refusal a wire code names; `None` for any other code. The bound
/// a server names is not on the wire, so it reads as `Bound("remote")`.
pub fn pool_refusal_from_code(code: &str) -> Option<PoolSessionRefusal> {
    Some(match code {
        "self_serve_refused" => PoolSessionRefusal::SelfServe,
        "not_eligible_server" => PoolSessionRefusal::NotEligible,
        "server_not_ready" => PoolSessionRefusal::NotReady,
        "pool_busy" => PoolSessionRefusal::PoolBusy,
        "session_bound_exceeded" => PoolSessionRefusal::Bound("remote"),
        "unknown_session" => PoolSessionRefusal::UnknownSession,
        "session_expired" => PoolSessionRefusal::Expired,
        "binding_mismatch" => PoolSessionRefusal::BindingMismatch,
        "content_unavailable" => PoolSessionRefusal::ContentUnavailable,
        "decrypt_unavailable" => PoolSessionRefusal::DecryptUnavailable,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct PoolSessionClient<T: PoolSessionTransport> {
    transport: T,
}

impl<T: PoolSessionTransport> PoolSessionClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// The pool's descriptor from one member. `describe` never acts, so an
    /// answer this side cannot read is `Unreachable`: the caller asks
    /// another member. A readable descriptor of another pool is
    /// `Refused(POOL_MISMATCH)`.
    pub async fn describe(
        &self,
        route: &PoolMemberRouteV2,
        pool: &PoolDidV1,
    ) -> Result<SignedPoolDescriptorAnyV1, PoolTransportError> {
        let pool_did = pool.to_did_key().map_err(|_| invalid_request())?;
        let data = self
            .transport
            .call(
                route,
                POOL_OP_DESCRIBE,
                PoolCallClass::Control,
                json!({ "pool": pool_did }),
            )
            .await?;
        let descriptor = b64_field(&data, "descriptor_b64")
            .and_then(|bytes| SignedPoolDescriptorAnyV1::from_canonical_bytes(&bytes).ok())
            .ok_or(PoolTransportError::Unreachable)?;
        if descriptor.pool() != pool {
            return Err(PoolTransportError::Refused(POOL_MISMATCH.to_string()));
        }
        Ok(descriptor)
    }

    /// `session.prepare`. The answer must be a recipient the asked server
    /// vouched for, for exactly this request.
    pub async fn prepare(
        &self,
        server: &PoolMemberV2,
        req: &PoolSessionPrepareV1,
    ) -> Result<PoolSessionPreparedV1, PoolTransportError> {
        let body = prepare_body(req).map_err(|_| invalid_request())?;
        let data = self
            .transport
            .call(
                server.route(),
                POOL_OP_SESSION_PREPARE,
                PoolCallClass::Control,
                body,
            )
            .await?;
        prepared_answer(&data, server, req).ok_or(PoolTransportError::NoExactResult)
    }

    /// `session.open`. The session lives to the signed rights expiry, capped
    /// by the attestations (user 2026-11-13 04:45), and the server must say
    /// so.
    pub async fn open(
        &self,
        server: &PoolMemberV2,
        req: &PoolSessionOpenV1,
    ) -> Result<PoolSessionOpenedV1, PoolTransportError> {
        let body = open_body(req).map_err(|_| invalid_request())?;
        let data = self
            .transport
            .call(
                server.route(),
                POOL_OP_SESSION_OPEN,
                PoolCallClass::Control,
                body,
            )
            .await?;
        let expires_at = data
            .get("expires_at")
            .and_then(Value::as_u64)
            .ok_or(PoolTransportError::NoExactResult)?;
        if expires_at != req.operation.statement().session_expires_at() {
            return Err(PoolTransportError::NoExactResult);
        }
        Ok(PoolSessionOpenedV1 { expires_at })
    }

    /// `session.read`: one part, sealed to the session's delivery key.
    pub async fn read_sealed(
        &self,
        server: &PoolMemberV2,
        req: &PoolSessionReadV1,
    ) -> Result<Vec<u8>, PoolTransportError> {
        let body = json!({
            "session_id_hex": hex::encode(req.session_id),
            "part": part_json(req.part),
        });
        let data = self
            .transport
            .call(
                server.route(),
                POOL_OP_SESSION_READ,
                PoolCallClass::Read,
                body,
            )
            .await?;
        b64_field(&data, "sealed_b64")
            .filter(|sealed| !sealed.is_empty())
            .ok_or(PoolTransportError::NoExactResult)
    }

    pub async fn close(
        &self,
        server: &PoolMemberV2,
        session_id: PoolSessionIdV1,
    ) -> Result<(), PoolTransportError> {
        self.transport
            .call(
                server.route(),
                POOL_OP_SESSION_CLOSE,
                PoolCallClass::Control,
                json!({ "session_id_hex": hex::encode(session_id) }),
            )
            .await
            .map(|_| ())
    }
}

fn invalid_request() -> PoolTransportError {
    PoolTransportError::Refused(INVALID_REQUEST.to_string())
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_field(value: &Value, field: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value.get(field)?.as_str()?)
        .ok()
}

/// The wire name of a content kind (T3.4 reads the same names).
pub fn content_kind_wire_name(kind: PoolSessionContentKindV1) -> &'static str {
    match kind {
        PoolSessionContentKindV1::MediaV1 => "media_v1",
        PoolSessionContentKindV1::DashV2 => "dash_v2",
        PoolSessionContentKindV1::Object => "object",
    }
}

fn identity_bytes(identity: &PoolContentIdentityV1) -> Result<Vec<u8>, ContractError> {
    match identity {
        PoolContentIdentityV1::MediaV1(identity) => identity.canonical_bytes(),
        PoolContentIdentityV1::DashV2(identity) => identity.canonical_bytes(),
        PoolContentIdentityV1::Object(identity) => identity.canonical_bytes(),
    }
}

/// rev 3 wire table, `session.prepare` (F4).
fn prepare_body(req: &PoolSessionPrepareV1) -> Result<Value, ContractError> {
    Ok(json!({
        "pool": req.pool.to_did_key()?,
        "binding_b64": b64(&req.binding.canonical_bytes()?),
        "action": req.action as u8,
        "runtime_operation_issuer_hex": hex::encode(req.runtime_operation_issuer.as_bytes()),
        "content": {
            "cid": req.content.cid,
            "kind": content_kind_wire_name(req.content.kind),
            "identity_b64": b64(&identity_bytes(&req.content.identity)?),
            "content_key_commitment_b64": b64(req.content.content_key_commitment.as_bytes()),
        },
        "expires_at": req.expires_at,
    }))
}

/// rev 3 wire table, `session.open` (F3).
fn open_body(req: &PoolSessionOpenV1) -> Result<Value, ContractError> {
    let contributions = req
        .contributions
        .iter()
        .map(|contribution| contribution.canonical_bytes().map(|bytes| b64(&bytes)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "session_id_hex": hex::encode(req.session_id),
        "operation_v2_b64": b64(&req.operation.canonical_bytes()?),
        "delivery_public_key_b64": b64(req.delivery_public_key.as_bytes()),
        "contributions_b64": contributions,
        "terminal_receipt_b64": b64(&req.terminal_receipt.canonical_bytes()?),
    }))
}

/// The `part` object of `session.read` (T3.4 reads the same shape).
pub fn part_json(part: ViewerPartIndexV1) -> Value {
    match part {
        ViewerPartIndexV1::MediaV1Init => json!({ "kind": "media_v1_init" }),
        ViewerPartIndexV1::MediaV1Segment(index) => {
            json!({ "kind": "media_v1_segment", "index": index })
        }
        ViewerPartIndexV1::DashInit { rendition } => {
            json!({ "kind": "dash_init", "rendition": rendition })
        }
        ViewerPartIndexV1::DashSegment { rendition, index } => {
            json!({ "kind": "dash_segment", "rendition": rendition, "index": index })
        }
        ViewerPartIndexV1::ObjectChunk(index) => json!({ "kind": "object_chunk", "index": index }),
    }
}

/// A prepare answer this request can use: the recipient the asked server
/// signed an attestation for, for this pool, item, action and Runtime.
fn prepared_answer(
    data: &Value,
    server: &PoolMemberV2,
    req: &PoolSessionPrepareV1,
) -> Option<PoolSessionPreparedV1> {
    let session_id: PoolSessionIdV1 = hex::decode(data.get("session_id_hex")?.as_str()?)
        .ok()?
        .try_into()
        .ok()?;
    let recipient_bytes: [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] =
        b64_field(data, "recipient_public_key_b64")?
            .try_into()
            .ok()?;
    let recipient_public_key = RecipientPublicKeyBytesV1::new(recipient_bytes).ok()?;
    let attestation = SignedPoolRecipientAttestationV2::from_canonical_bytes(&b64_field(
        data,
        "attestation_b64",
    )?)
    .ok()?;
    attestation.verify_node_signature().ok()?;
    let statement = attestation.statement();
    let matches = statement.server_node_public_key() == server.node_public_key()
        && statement.recipient_public_key() == recipient_public_key
        && statement.pool() == &req.pool
        && statement.binding() == &req.binding
        && statement.action() == req.action
        && statement.runtime_operation_issuer() == req.runtime_operation_issuer;
    matches.then_some(PoolSessionPreparedV1 {
        session_id,
        recipient_public_key,
        attestation,
    })
}

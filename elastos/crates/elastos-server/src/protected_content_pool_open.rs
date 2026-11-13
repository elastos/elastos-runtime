//! Plan B T4.4: a viewer opens through the item's pool.
//!
//! The buyer's Runtime reads the item's rights policy first (ADV-01 §4B),
//! asks one or more pool servers to prepare a session recipient, has the
//! Wallet sign one V2 rights request over every recipient, its own delivery
//! key and the policy's chain, runs the V2 release at the epoch nodes, and
//! opens each server's session with that delivery key. The content key stays
//! inside the pool: this Home's own decrypt provider is never called.
//!
//! One release per Wallet approval (user 2026-11-13 04:45). The session lives
//! to the signed rights expiry, capped by the earliest attestation expiry;
//! the release operation (≤ 60 s) bounds only the node release.
//!
//! The steps that decide something are small functions here, so each is
//! tested alone. [`open_pool_viewer`] runs them in order over two ports: the
//! pool session calls ([`PoolSessionCalls`]) and this Home's Wallet, rights
//! policy, device signing, release coordinator, chain and record store
//! ([`PoolOpenPorts`]).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use elastos_protected_content_contracts::{
    AuthenticatedRuntimeReleaseOperationV2, CanonicalContract, DeliveryKeyIdentityV1,
    DeliveryPublicKeyBytesV1, Digest32, KeyReleaseOutcomeV1, NodeContributionRefV1, NodePublicKey,
    PoolMemberV2, PoolSessionRecipientV1, ProtectedContentBindingV1, RecipientKeyIdentityV1,
    RecipientPublicKeyBytesV1, ReplayNonce16, RightsActionV1, RightsEvaluationEvidenceRequestV1,
    RightsPolicyBodyV1, RightsPolicyIdentityV1, RightsRequestAnyV1, RightsRequestV2,
    RuntimeIssuerPolicyV1, RuntimeOperationIssuerKeyV1, RuntimeReleaseAuditIdV1,
    RuntimeReleaseOperationStatementV2, SignedNodeContributionV1, SignedPoolRecipientAttestationV2,
    SignedRuntimeReleaseOperationV2, SignedTerminalReceiptV1, TerminalReceiptIssuerKey,
    TerminalReceiptStatementV1, ViewerPartAadV1, ViewerPartIndexV1, WalletSignedRightsRequestV2,
};
use elastos_protected_content_custody::{open_viewer_part_v1, DeliverySecretKeyV1};
use elastos_protected_content_provider_contracts::MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1;
use elastos_protected_content_runtime::{
    select_session_servers, stripe_index, PoolCallClass, PoolContentIdentityV1, PoolResolveError,
    PoolSessionClient, PoolSessionContentRefV1, PoolSessionIdV1, PoolSessionOpenV1,
    PoolSessionOpenedV1, PoolSessionPrepareV1, PoolSessionPreparedV1, PoolSessionReadV1,
    PoolSessionTransport, PoolTransportError, ResolvedPoolV1, RuntimeContentIdentityV1,
    RuntimeMintDraft, RuntimeReleaseCoordinatorOutcome, RuntimeReleaseTerminalResult,
};
use elastos_runtime::provider::ProviderInvocationTransport;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};

use crate::custody_pool_resolver::KeptCardTickets;
use crate::protected_content_runtime::{
    runtime_custody_open_denied, runtime_custody_open_unavailable, RuntimeCustodyAccessAt,
    RuntimeCustodyOpenProgress, RuntimeCustodyPoolContentUnavailable,
    RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE, RUNTIME_CUSTODY_NO_ELIGIBLE_SERVER_MESSAGE,
    RUNTIME_CUSTODY_OPEN_FINALIZING_MESSAGE, RUNTIME_CUSTODY_RELEASE_APPROVAL_UNAVAILABLE_MESSAGE,
    RUNTIME_CUSTODY_UNRESOLVED_MESSAGE,
};

// Unix only, like the composition journal fixture the tests use.
#[cfg(all(test, unix))]
mod tests;

/// A viewer's handle, as the viewer record keeps it.
pub(crate) type PoolViewerHandle = [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];

/// How long one release operation lives at most (below
/// `MAX_RUNTIME_RELEASE_OPERATION_LIFETIME_SECS`): it bounds only the node
/// release, never the session.
const POOL_OPERATION_LIFETIME_SECS: u64 = 50;
/// The operation is issued this far behind `now`, as in V1.
const POOL_OPERATION_ISSUED_BEHIND_SECS: u64 = 3;
/// The terminal receipt lives at most this long, as in V1.
const POOL_TERMINAL_RECEIPT_LIFETIME_SECS: u64 = 30;
/// The fingerprint length of the Wallet text's `Delivery key:` line.
const DELIVERY_KEY_FINGERPRINT_BYTES: usize = 8;

// ---------------------------------------------------------------------------
// Delivery keys
// ---------------------------------------------------------------------------

/// The delivery secret of one viewer and the sessions it reads from. The
/// secret never leaves this process: an entry lost with a restart makes the
/// next open start fresh. It holds no client, registry or signer.
pub(crate) struct PoolDeliveryEntry {
    secret: DeliverySecretKeyV1,
    servers: Vec<PoolMemberV2>,
    session_ids: Vec<PoolSessionIdV1>,
    /// `None` while the Wallet approval is pending.
    operation_hash: Option<Digest32>,
    /// T4.8: servers that stopped answering; their stripes move to the
    /// others, under the same release.
    lost: Vec<bool>,
    /// The session's end once open (the signed rights expiry, capped by the
    /// attestations); the approval window before.
    expires_at: u64,
}

impl PoolDeliveryEntry {
    pub(crate) fn pending(
        secret: DeliverySecretKeyV1,
        servers: Vec<PoolMemberV2>,
        session_ids: Vec<PoolSessionIdV1>,
        expires_at: u64,
    ) -> Self {
        let lost = vec![false; servers.len()];
        Self {
            secret,
            servers,
            session_ids,
            operation_hash: None,
            lost,
            expires_at,
        }
    }

    pub(crate) fn delivery_public_key(&self) -> anyhow::Result<DeliveryPublicKeyBytesV1> {
        self.secret
            .public_key()
            .map_err(|_| anyhow::anyhow!("the pool delivery key is invalid"))
    }

    // Unused since T4.5 reads through the viewer record; kept for review.
    #[allow(dead_code)]
    pub(crate) fn secret(&self) -> &DeliverySecretKeyV1 {
        &self.secret
    }

    // Unused since T4.5 reads through the viewer record; kept for review.
    #[allow(dead_code)]
    pub(crate) fn servers(&self) -> &[PoolMemberV2] {
        &self.servers
    }

    // Unused since T4.5 reads through the viewer record; kept for review.
    #[allow(dead_code)]
    pub(crate) fn session_ids(&self) -> &[PoolSessionIdV1] {
        &self.session_ids
    }

    #[cfg_attr(not(test), allow(dead_code))] // T4.5 reads with it
    pub(crate) const fn operation_hash(&self) -> Option<Digest32> {
        self.operation_hash
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

impl std::fmt::Debug for PoolDeliveryEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PoolDeliveryEntry")
            .field("secret", &"[redacted]")
            .field("servers", &self.servers.len())
            .field("operation_hash", &self.operation_hash.is_some())
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Viewer handle → delivery entry, for this process. An entry is dropped on
/// close, and at its end when it is next looked at. It holds secrets and
/// session facts only: no registry, transport, signer or authority.
#[derive(Default)]
pub(crate) struct PoolDeliveryKeys {
    entries: Mutex<HashMap<PoolViewerHandle, PoolDeliveryEntry>>,
}

impl PoolDeliveryKeys {
    pub(crate) fn global() -> &'static Self {
        static KEYS: OnceLock<PoolDeliveryKeys> = OnceLock::new();
        KEYS.get_or_init(Self::default)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<PoolViewerHandle, PoolDeliveryEntry>> {
        // A panic while holding the map leaves only whole entries behind.
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn insert(&self, handle: PoolViewerHandle, entry: PoolDeliveryEntry) {
        self.lock().insert(handle, entry);
    }

    /// Whether `handle` has a live entry at `now`; an ended one is dropped.
    pub(crate) fn contains(&self, handle: &PoolViewerHandle, now: u64) -> bool {
        let mut entries = self.lock();
        match entries.get(handle) {
            Some(entry) if now < entry.expires_at => true,
            Some(_) => {
                entries.remove(handle);
                false
            }
            None => false,
        }
    }

    pub(crate) fn take(&self, handle: &PoolViewerHandle) -> Option<PoolDeliveryEntry> {
        self.lock().remove(handle)
    }

    /// Runs `f` on the entry of `handle`.
    pub(crate) fn with_entry<R>(
        &self,
        handle: &PoolViewerHandle,
        f: impl FnOnce(&mut PoolDeliveryEntry) -> R,
    ) -> Option<R> {
        self.lock().get_mut(handle).map(f)
    }
}

// ---------------------------------------------------------------------------
// What the records keep
// ---------------------------------------------------------------------------

/// The pool part of a pending release (`RuntimeCustodyPendingRelease.pool`):
/// the prepared sessions, so a resumed open replays the exact rights request
/// to the same recipients. The delivery secret is not here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PoolPendingSessions {
    /// Each server's node key, hex, in prepare order.
    servers_hex: Vec<String>,
    session_ids_hex: Vec<String>,
    recipient_public_keys_hex: Vec<String>,
    /// Each server's `SignedPoolRecipientAttestationV2`, canonical, base64.
    attestations_b64: Vec<String>,
}

impl PoolPendingSessions {
    pub(crate) fn from_prepared(prepared: &[PoolPreparedServer]) -> anyhow::Result<Self> {
        let mut sessions = Self {
            servers_hex: Vec::with_capacity(prepared.len()),
            session_ids_hex: Vec::with_capacity(prepared.len()),
            recipient_public_keys_hex: Vec::with_capacity(prepared.len()),
            attestations_b64: Vec::with_capacity(prepared.len()),
        };
        for server in prepared {
            sessions
                .servers_hex
                .push(hex::encode(server.member.node_public_key().as_bytes()));
            sessions
                .session_ids_hex
                .push(hex::encode(server.prepared.session_id));
            sessions
                .recipient_public_keys_hex
                .push(hex::encode(server.prepared.recipient_public_key.as_bytes()));
            sessions.attestations_b64.push(
                base64::engine::general_purpose::STANDARD.encode(
                    server
                        .prepared
                        .attestation
                        .canonical_bytes()
                        .map_err(|_| anyhow::anyhow!("a pool attestation does not encode"))?,
                ),
            );
        }
        Ok(sessions)
    }

    /// The prepared servers again, with each member read from `resolved`.
    /// `None` when a server left the descriptor or a field does not decode:
    /// the open then starts fresh.
    pub(crate) fn restore(&self, resolved: &ResolvedPoolV1) -> Option<Vec<PoolPreparedServer>> {
        let count = self.servers_hex.len();
        if count == 0
            || self.session_ids_hex.len() != count
            || self.recipient_public_keys_hex.len() != count
            || self.attestations_b64.len() != count
        {
            return None;
        }
        (0..count)
            .map(|index| {
                let key: [u8; 32] = hex::decode(&self.servers_hex[index])
                    .ok()?
                    .try_into()
                    .ok()?;
                let member = resolved
                    .descriptor
                    .member(NodePublicKey::new(key).ok()?)?
                    .clone();
                let session_id: PoolSessionIdV1 = hex::decode(&self.session_ids_hex[index])
                    .ok()?
                    .try_into()
                    .ok()?;
                let recipient_public_key = RecipientPublicKeyBytesV1::new(
                    hex::decode(&self.recipient_public_keys_hex[index])
                        .ok()?
                        .try_into()
                        .ok()?,
                )
                .ok()?;
                let attestation = SignedPoolRecipientAttestationV2::from_canonical_bytes(
                    &base64::engine::general_purpose::STANDARD
                        .decode(&self.attestations_b64[index])
                        .ok()?,
                )
                .ok()?;
                Some(PoolPreparedServer {
                    member,
                    prepared: PoolSessionPreparedV1 {
                        session_id,
                        recipient_public_key,
                        attestation,
                    },
                })
            })
            .collect()
    }

    // Unused since T4.5 settles through the viewer record; kept for review.
    #[allow(dead_code)]
    pub(crate) fn session_ids(&self) -> Vec<PoolSessionIdV1> {
        self.session_ids_hex
            .iter()
            .filter_map(|id| hex::decode(id).ok()?.try_into().ok())
            .collect()
    }
}

/// The servers and sessions of an open pool viewer
/// (`RuntimeCustodyViewerRecord.pool`). T4.5 reads and closes through them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PoolViewerSessions {
    servers_hex: Vec<String>,
    session_ids_hex: Vec<String>,
}

impl PoolViewerSessions {
    pub(crate) fn new(servers: &[PoolMemberV2], session_ids: &[PoolSessionIdV1]) -> Self {
        Self {
            servers_hex: servers
                .iter()
                .map(|server| hex::encode(server.node_public_key().as_bytes()))
                .collect(),
            session_ids_hex: session_ids.iter().map(hex::encode).collect(),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))] // T4.5 reads and closes with it
    pub(crate) fn servers_hex(&self) -> &[String] {
        &self.servers_hex
    }

    #[cfg_attr(not(test), allow(dead_code))] // T4.5 reads and closes with it
    pub(crate) fn session_ids_hex(&self) -> &[String] {
        &self.session_ids_hex
    }
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// One prepared session: the server and its vouched recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PoolPreparedServer {
    pub(crate) member: PoolMemberV2,
    pub(crate) prepared: PoolSessionPreparedV1,
}

impl PoolPreparedServer {
    pub(crate) fn recipient_identity(&self) -> &RecipientKeyIdentityV1 {
        self.prepared.attestation.statement().recipient_identity()
    }

    pub(crate) fn attestation_expires_at(&self) -> u64 {
        self.prepared.attestation.statement().expires_at()
    }
}

/// The earliest attestation expiry of the prepared servers.
fn earliest_attestation_expiry(prepared: &[PoolPreparedServer]) -> Option<u64> {
    prepared
        .iter()
        .map(PoolPreparedServer::attestation_expires_at)
        .min()
}

/// What a session serves (F4), from the verified draft and the purchase's
/// CID: the values the V1 open uses.
pub(crate) fn pool_content_ref(cid: &str, draft: &RuntimeMintDraft) -> PoolSessionContentRefV1 {
    let identity = match draft.content_identity() {
        RuntimeContentIdentityV1::Media(media) => PoolContentIdentityV1::MediaV1(media.clone()),
        RuntimeContentIdentityV1::MediaDash(head) => PoolContentIdentityV1::DashV2(head.clone()),
        RuntimeContentIdentityV1::Object(object) => PoolContentIdentityV1::Object(object.clone()),
    };
    PoolSessionContentRefV1 {
        cid: cid.to_string(),
        kind: identity.kind(),
        identity,
        content_key_commitment: draft.content_key_commitment(),
    }
}

/// A `session.prepare` failure the next server may answer (L11, S4-Q10).
/// `NoExactResult` stops: the server may have acted. `not_eligible_server`
/// is refused before any action (OPEN-LOOP F4: a node of this Home's own).
pub(crate) fn prepare_fails_over(error: &PoolTransportError) -> bool {
    match error {
        PoolTransportError::Unreachable => true,
        PoolTransportError::Refused(code) => matches!(
            code.as_str(),
            "server_not_ready" | "pool_busy" | "decrypt_unavailable" | "not_eligible_server"
        ),
        PoolTransportError::NoExactResult => false,
    }
}

/// How many servers one session uses: the descriptor's bound, at least one
/// (F5: never more, the release refuses a larger recipient set).
pub(crate) fn wanted_servers(resolved: &ResolvedPoolV1) -> usize {
    usize::from(resolved.descriptor.serve_policy().max_servers_per_session).max(1)
}

/// Where the release coordinator reaches one epoch node: this Home's own
/// node in process; a member whose card this Home kept by that card's
/// ticket; else by its peer DID through Carrier discovery (item 10: the
/// descriptor carries no tickets). Both Carrier routes bound the wait.
pub(crate) fn epoch_node_transport(
    member: &PoolMemberV2,
    own_node_keys: &[NodePublicKey],
    kept_card_tickets: &KeptCardTickets,
) -> ProviderInvocationTransport {
    if own_node_keys.contains(&member.node_public_key()) {
        return ProviderInvocationTransport::Local;
    }
    ProviderInvocationTransport::Carrier(crate::custody_pool_resolver::carrier_route_for(
        member.route(),
        PoolCallClass::Control,
        kept_card_tickets,
    ))
}

/// The V2 rights request (pool form, ADV-01 §3): every prepared recipient,
/// the delivery key's identity (F3) and the policy's chain. Its expiry is no
/// later than the earliest attestation (the pre-Wallet cap) or the approval
/// window.
pub(crate) fn pool_rights_request(
    binding: &ProtectedContentBindingV1,
    action: RightsActionV1,
    prepared: &[PoolPreparedServer],
    delivery_public_key: &DeliveryPublicKeyBytesV1,
    now: u64,
    approval_expires_at: u64,
    chain_id: u64,
) -> anyhow::Result<RightsRequestV2> {
    let expires_at = earliest_attestation_expiry(prepared)
        .unwrap_or(approval_expires_at)
        .min(approval_expires_at);
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    RightsRequestV2::new(
        binding.clone(),
        action,
        prepared
            .iter()
            .map(|server| server.recipient_identity().clone())
            .collect(),
        delivery_public_key.identity(),
        now.saturating_sub(5),
        expires_at,
        ReplayNonce16::new(nonce),
        chain_id,
    )
    .map_err(|error| anyhow::anyhow!("the pool rights request is invalid: {error:?}"))
}

/// Whether a rights request is the one this open stands on (ADV-01 §4B):
/// a V2 request with its binding and action, exactly the prepared
/// recipients, the policy's chain, this viewer's delivery key, and an expiry
/// no later than the earliest attestation (the pre-Wallet cap, also for a
/// resumed request). A V1 or pre-alignment request never matches.
pub(crate) fn rights_request_matches(
    request: &RightsRequestAnyV1,
    binding: &ProtectedContentBindingV1,
    action: RightsActionV1,
    prepared: &[PoolPreparedServer],
    delivery_public_key: &DeliveryPublicKeyBytesV1,
    chain_id: u64,
) -> bool {
    let RightsRequestAnyV1::V2(request) = request else {
        return false;
    };
    request.binding() == binding
        && request.action() == action
        && request.chain_id() == chain_id
        && request.delivery_key() == Some(delivery_public_key.identity())
        && earliest_attestation_expiry(prepared)
            .is_some_and(|earliest| request.expires_at() <= earliest)
        && request.recipients().len() == prepared.len()
        && prepared
            .iter()
            .all(|server| request.recipients().contains(server.recipient_identity()))
}

/// The Wallet text's `Delivery key:` value for `identity` (ADV-01 §3,
/// item 4): `0x` and the lowercase hex of its first 8 bytes.
pub(crate) fn delivery_key_fingerprint(identity: DeliveryKeyIdentityV1) -> String {
    let digest = identity.digest();
    format!(
        "0x{}",
        hex::encode(&digest.as_bytes()[..DELIVERY_KEY_FINGERPRINT_BYTES])
    )
}

/// The operation is past its useful life before it is signed: the approval
/// came too close to the attestations' or the rights' expiry. The open
/// starts fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PoolOperationExpired;

impl std::fmt::Display for PoolOperationExpired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the pool release window has closed")
    }
}

impl std::error::Error for PoolOperationExpired {}

/// Everything a V2 operation is built from, besides the device key.
pub(crate) struct PoolOperationInput<'a> {
    pub(crate) signed_rights: &'a WalletSignedRightsRequestV2,
    pub(crate) prepared: &'a [PoolPreparedServer],
    pub(crate) policy_body: &'a RightsPolicyBodyV1,
    pub(crate) policy_identity: &'a RightsPolicyIdentityV1,
    pub(crate) resolved: &'a ResolvedPoolV1,
    pub(crate) audit_request_id: RuntimeReleaseAuditIdV1,
}

/// The V2 release statement for the device issuer (the issuer T3.1
/// expects). It is issued no earlier than any recipient attestation or the
/// rights (the contract refuses an operation issued before them), and
/// `expires_at = min(now + 50, earliest attestation, rights expiry)`;
/// nothing left is [`PoolOperationExpired`].
pub(crate) fn pool_release_statement(
    issuer: RuntimeOperationIssuerKeyV1,
    input: &PoolOperationInput<'_>,
    now: u64,
) -> anyhow::Result<RuntimeReleaseOperationStatementV2> {
    let earliest_attestation = earliest_attestation_expiry(input.prepared)
        .ok_or_else(|| anyhow::anyhow!("a pool release names no server"))?;
    let latest_attestation_issued = input
        .prepared
        .iter()
        .map(|server| server.prepared.attestation.statement().issued_at())
        .max()
        .unwrap_or(0);
    let issued_at = now
        .saturating_sub(POOL_OPERATION_ISSUED_BEHIND_SECS)
        .max(latest_attestation_issued)
        .max(input.signed_rights.request().issued_at());
    let expires_at = now
        .saturating_add(POOL_OPERATION_LIFETIME_SECS)
        .min(earliest_attestation)
        .min(input.signed_rights.request().expires_at());
    if expires_at <= now.max(issued_at) {
        return Err(PoolOperationExpired.into());
    }
    let recipients = input
        .prepared
        .iter()
        .map(|server| {
            PoolSessionRecipientV1::new(
                server.prepared.recipient_public_key,
                server.prepared.attestation.clone(),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| anyhow::anyhow!("a pool session recipient is invalid: {error:?}"))?;
    let evidence_request = RightsEvaluationEvidenceRequestV1::new(
        input.signed_rights.request().binding().clone(),
        input.policy_identity.clone(),
    )
    .map_err(|error| anyhow::anyhow!("rights evidence request is invalid: {error:?}"))?;
    RuntimeReleaseOperationStatementV2::new(
        issuer,
        input.signed_rights.clone(),
        recipients,
        input.policy_body.clone(),
        evidence_request,
        input.resolved.signed.clone(),
        input.audit_request_id,
        issued_at,
        expires_at,
    )
    .map_err(|error| anyhow::anyhow!("the pool release operation is invalid: {error:?}"))
}

/// Signs a V2 release statement with the device key. The port that calls it
/// loads the key for the call and drops it (S4-R4-F3).
pub(crate) fn sign_release_operation_v2_with(
    device_key: &ed25519_dalek::SigningKey,
    statement: RuntimeReleaseOperationStatementV2,
) -> anyhow::Result<SignedRuntimeReleaseOperationV2> {
    let signature = device_key
        .sign(
            &statement
                .canonical_bytes()
                .map_err(|_| anyhow::anyhow!("the pool release operation is not canonical"))?,
        )
        .to_bytes()
        .to_vec();
    SignedRuntimeReleaseOperationV2::new(statement, signature)
        .map_err(|error| anyhow::anyhow!("the pool release operation is invalid: {error:?}"))
}

/// One server's terminal receipt over its contributions, signed by the
/// device key, with `release_request_hash = operation_hash()` (L1). Every
/// contribution is verified first, against the item's epoch and the server's
/// recipient, at `now`: an open needs fresh proofs.
pub(crate) fn sign_terminal_receipt_v2_with(
    device_key: &ed25519_dalek::SigningKey,
    operation: &AuthenticatedRuntimeReleaseOperationV2,
    server_contributions: &[SignedNodeContributionV1],
    recipient: &RecipientKeyIdentityV1,
    now: u64,
) -> anyhow::Result<SignedTerminalReceiptV1> {
    let node_set = operation
        .epoch_bundle()
        .signed_epoch()
        .statement()
        .node_set()
        .map_err(|_| anyhow::anyhow!("the item's custody epoch is invalid"))?;
    let refs = server_contributions
        .iter()
        .map(|contribution| {
            operation
                .verify_node_contribution(contribution, &node_set, recipient, now)
                .map(|verified| NodeContributionRefV1::from(&verified))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| anyhow::anyhow!("a pool contribution does not verify: {error:?}"))?;
    let statement = operation.statement();
    let issued_at = server_contributions
        .iter()
        .map(|contribution| contribution.statement().issued_at())
        .max()
        .unwrap_or(now)
        .max(now)
        .max(statement.issued_at());
    let expires_at = server_contributions
        .iter()
        .map(|contribution| contribution.statement().expires_at())
        .min()
        .unwrap_or(statement.expires_at())
        .min(statement.expires_at())
        .min(issued_at.saturating_add(POOL_TERMINAL_RECEIPT_LIFETIME_SECS));
    if expires_at <= issued_at {
        return Err(PoolOperationExpired.into());
    }
    let receipt = TerminalReceiptStatementV1::new(
        operation.operation_hash(),
        operation.binding().clone(),
        TerminalReceiptIssuerKey::new(device_key.verifying_key().to_bytes())
            .map_err(|_| anyhow::anyhow!("local Runtime device signing key is invalid"))?,
        KeyReleaseOutcomeV1::Released,
        refs,
        issued_at,
        expires_at,
    )
    .map_err(|error| anyhow::anyhow!("the terminal receipt is invalid: {error:?}"))?;
    let signature = device_key
        .sign(
            &receipt
                .canonical_bytes()
                .map_err(|_| anyhow::anyhow!("the terminal receipt is not canonical"))?,
        )
        .to_bytes()
        .to_vec();
    SignedTerminalReceiptV1::new(receipt, signature)
        .map_err(|error| anyhow::anyhow!("the terminal receipt is invalid: {error:?}"))
}

/// The device issuer of `device_key`.
pub(crate) fn device_issuer_of(
    device_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<RuntimeOperationIssuerKeyV1> {
    RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())
        .map_err(|_| anyhow::anyhow!("local Runtime device signing key is invalid"))
}

/// What a node's `rights_denied` means, from the chain at both blocks (F9,
/// S4-Q17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RightsDeniedClass {
    /// Only `latest` grants: custody waits for finality.
    Finalizing,
    /// Neither block grants: the open is denied.
    Denied,
    /// The chain cannot say, or it grants at `finalized`: retry.
    Unavailable,
}

/// `denied` only when finalized access is absent and the head agrees.
pub(crate) fn rights_denied_class(
    finalized: RuntimeCustodyAccessAt,
    latest: RuntimeCustodyAccessAt,
) -> RightsDeniedClass {
    match (finalized, latest) {
        (RuntimeCustodyAccessAt::NotGranted, RuntimeCustodyAccessAt::Granted) => {
            RightsDeniedClass::Finalizing
        }
        (RuntimeCustodyAccessAt::NotGranted, RuntimeCustodyAccessAt::NotGranted) => {
            RightsDeniedClass::Denied
        }
        _ => RightsDeniedClass::Unavailable,
    }
}

/// [`RightsDeniedClass`] as the open answers it.
pub(crate) enum RightsDeniedVerdict {
    Finalizing(RuntimeCustodyOpenProgress),
    Denied,
    Unavailable,
}

fn rights_denied_error(verdict: RightsDeniedVerdict) -> anyhow::Error {
    match verdict {
        RightsDeniedVerdict::Finalizing(progress) => anyhow::Error::new(progress)
            .context(format!("{}:{}", file!(), line!()))
            .context(RUNTIME_CUSTODY_OPEN_FINALIZING_MESSAGE),
        RightsDeniedVerdict::Denied => runtime_custody_open_denied(),
        RightsDeniedVerdict::Unavailable => runtime_custody_open_unavailable(
            RUNTIME_CUSTODY_RELEASE_APPROVAL_UNAVAILABLE_MESSAGE,
            &anyhow::anyhow!("a custody node refused the rights while the chain grants them"),
        ),
    }
}

/// The open's answer to a pool that cannot be resolved or used (S4-Q16):
/// a non-resumable message with Retry, before any Wallet call.
pub(crate) fn pool_unresolved_error(error: PoolResolveError) -> anyhow::Error {
    match error {
        PoolResolveError::NoEligibleServer => runtime_custody_open_unavailable(
            RUNTIME_CUSTODY_NO_ELIGIBLE_SERVER_MESSAGE,
            &anyhow::anyhow!("no_eligible_server"),
        ),
        PoolResolveError::Unresolved | PoolResolveError::Invalid => {
            runtime_custody_open_unavailable(
                RUNTIME_CUSTODY_UNRESOLVED_MESSAGE,
                &anyhow::anyhow!("custody_unresolved"),
            )
        }
    }
}

fn no_eligible_server() -> anyhow::Error {
    pool_unresolved_error(PoolResolveError::NoEligibleServer)
}

fn pool_unavailable(detail: String) -> anyhow::Error {
    runtime_custody_open_unavailable(
        RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE,
        &anyhow::anyhow!(detail),
    )
}

/// OPEN-LOOP F2: what a failure after the Wallet signed answers. The signed
/// rights are spent on this open's one release (rev14), and a resumable
/// answer would re-run the open with a new Wallet request, so the open ends
/// with the typed `content_unavailable` refusal and Retry. Only a final
/// answer (a denial) stays as it is; a `finalizing` verdict here too (OP2:
/// finality is read before the Wallet is asked).
fn after_approval_failure(error: anyhow::Error) -> anyhow::Error {
    match error.downcast_ref::<RuntimeCustodyOpenProgress>() {
        Some(progress) if !progress.resumable() => error,
        _ => RuntimeCustodyPoolContentUnavailable::error(&error),
    }
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// The pool session calls the open makes. `PoolSessionClient` over the
/// registry transport implements it, built per call by the caller.
#[async_trait::async_trait]
pub(crate) trait PoolSessionCalls: Send + Sync {
    async fn prepare(
        &self,
        server: &PoolMemberV2,
        req: &PoolSessionPrepareV1,
    ) -> Result<PoolSessionPreparedV1, PoolTransportError>;

    async fn open(
        &self,
        server: &PoolMemberV2,
        req: &PoolSessionOpenV1,
    ) -> Result<PoolSessionOpenedV1, PoolTransportError>;

    /// T4.5: one part, sealed to the session's delivery key.
    async fn read_sealed(
        &self,
        server: &PoolMemberV2,
        req: &PoolSessionReadV1,
    ) -> Result<Vec<u8>, PoolTransportError>;

    /// T4.5: ends one server session.
    async fn close(
        &self,
        server: &PoolMemberV2,
        session_id: PoolSessionIdV1,
    ) -> Result<(), PoolTransportError>;
}

#[async_trait::async_trait]
impl<T: PoolSessionTransport> PoolSessionCalls for PoolSessionClient<T> {
    async fn prepare(
        &self,
        server: &PoolMemberV2,
        req: &PoolSessionPrepareV1,
    ) -> Result<PoolSessionPreparedV1, PoolTransportError> {
        PoolSessionClient::prepare(self, server, req).await
    }

    async fn open(
        &self,
        server: &PoolMemberV2,
        req: &PoolSessionOpenV1,
    ) -> Result<PoolSessionOpenedV1, PoolTransportError> {
        PoolSessionClient::open(self, server, req).await
    }

    async fn read_sealed(
        &self,
        server: &PoolMemberV2,
        req: &PoolSessionReadV1,
    ) -> Result<Vec<u8>, PoolTransportError> {
        PoolSessionClient::read_sealed(self, server, req).await
    }

    async fn close(
        &self,
        server: &PoolMemberV2,
        session_id: PoolSessionIdV1,
    ) -> Result<(), PoolTransportError> {
        PoolSessionClient::close(self, server, session_id).await
    }
}

/// What the Wallet answered to the V2 rights request.
pub(crate) enum PoolWalletAnswer {
    Signed {
        request_bytes: Vec<u8>,
        response_bytes: Vec<u8>,
        signed_rights: Box<WalletSignedRightsRequestV2>,
    },
    PendingApproval {
        request_bytes: Vec<u8>,
        approval_request_id: String,
        external_signer: bool,
        connector_id: Option<String>,
    },
}

/// What a pending open keeps, besides the record's own fields.
pub(crate) struct PoolPendingRelease {
    pub(crate) wallet_request: Vec<u8>,
    pub(crate) approval_request_id: String,
    pub(crate) sessions: PoolPendingSessions,
}

/// The rights request check the Wallet port applies before it sends a
/// replayed request, and to the request it built.
pub(crate) type RightsRequestCheck<'a> = &'a (dyn Fn(&RightsRequestAnyV1) -> bool + Send + Sync);

/// This Home's side of the open: Wallet, rights policy, device signing,
/// release coordinator, chain and record store. `RuntimePoolOpenPorts`
/// (pcr) implements it per call; it keeps no device key.
#[async_trait::async_trait]
pub(crate) trait PoolOpenPorts: Send + Sync {
    /// The item's rights policy. ADV-01 §4B: read once, before anything is
    /// built or sent to the Wallet; the open uses this one for everything.
    async fn rights_policy(&self) -> anyhow::Result<(RightsPolicyBodyV1, RightsPolicyIdentityV1)>;

    /// The device issuer (S4-R4-F3): the device key is loaded for the call.
    fn device_issuer(&self) -> anyhow::Result<RuntimeOperationIssuerKeyV1>;

    /// Signs a V2 release statement with the device key loaded for the call.
    fn sign_release_operation_v2(
        &self,
        statement: RuntimeReleaseOperationStatementV2,
    ) -> anyhow::Result<SignedRuntimeReleaseOperationV2>;

    /// Verifies one server's contributions and signs its V2 terminal
    /// receipt with the device key loaded for the call.
    fn sign_terminal_receipt_v2(
        &self,
        operation: &AuthenticatedRuntimeReleaseOperationV2,
        server_contributions: &[SignedNodeContributionV1],
        recipient: &RecipientKeyIdentityV1,
        now: u64,
    ) -> anyhow::Result<SignedTerminalReceiptV1>;

    /// Asks the Wallet to sign `fresh`, or replays the exact `replay`
    /// request (R1). Either must pass `expected` before it is sent (ADV-01
    /// §4B); the signed answer is checked again by the caller.
    async fn sign_rights(
        &self,
        fresh: Option<&RightsRequestV2>,
        replay: Option<&[u8]>,
        expected: RightsRequestCheck<'_>,
        now: u64,
    ) -> anyhow::Result<PoolWalletAnswer>;

    /// Runs the V2 release at the epoch nodes.
    async fn release(
        &self,
        wallet_request: &[u8],
        wallet_response: &[u8],
        operation: &SignedRuntimeReleaseOperationV2,
        now: u64,
    ) -> anyhow::Result<RuntimeReleaseCoordinatorOutcome>;

    /// Resumes the exact operation after a nonterminal answer.
    async fn resume_release(
        &self,
        operation_hash: Digest32,
        now: u64,
    ) -> anyhow::Result<RuntimeReleaseCoordinatorOutcome>;

    /// F9: what a node's `rights_denied` means now.
    async fn rights_denied_verdict(&self, now: u64) -> RightsDeniedVerdict;

    /// Keeps the first pending answer, so the next open replays it.
    fn persist_pending(&self, pending: &PoolPendingRelease) -> anyhow::Result<()>;
}

// ---------------------------------------------------------------------------
// The open
// ---------------------------------------------------------------------------

/// A resumed open: the request the Wallet holds and the sessions it names.
pub(crate) struct PoolResume {
    pub(crate) wallet_request: Vec<u8>,
    pub(crate) sessions: PoolPendingSessions,
}

/// What the open of one viewer is built from. No device key: the ports sign.
pub(crate) struct PoolOpenContext<'a> {
    pub(crate) resolved: &'a ResolvedPoolV1,
    /// This Home's node keys: never a session server, and a `Local` route.
    pub(crate) own_node_keys: &'a [NodePublicKey],
    /// The buy's binding for this runtime session.
    pub(crate) binding: ProtectedContentBindingV1,
    pub(crate) action: RightsActionV1,
    /// From the T4.6 verified draft (F4).
    pub(crate) content: PoolSessionContentRefV1,
    pub(crate) audit_request_id: RuntimeReleaseAuditIdV1,
    /// The viewer handle the record keeps; the delivery entry's key.
    pub(crate) handle: PoolViewerHandle,
    /// The resumable window: the pending record's expiry.
    pub(crate) approval_expires_at: u64,
    /// Set only when the delivery entry of `handle` is live.
    pub(crate) resume: Option<PoolResume>,
    pub(crate) now: u64,
}

/// An opened pool viewer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PoolOpened {
    pub(crate) handle: PoolViewerHandle,
    /// The session's end: the signed rights expiry, capped by the
    /// attestations (user 2026-11-13 04:45).
    pub(crate) expires_at: u64,
    pub(crate) sessions: PoolViewerSessions,
    /// The verified descriptor's read-ahead bound, a pacing hint for the
    /// viewer; the server enforces it (T4.5).
    pub(crate) read_ahead_segments: u16,
}

pub(crate) enum PoolOpenOutcome {
    Opened(PoolOpened),
    PendingApproval(RuntimeCustodyOpenProgress),
}

/// Prepares sessions down the server order until enough answer (S4-Q8,
/// S4-Q10). Every server refusing answers `no_eligible_server`, with no
/// fallback to the local branch.
async fn prepare_servers<S: PoolSessionCalls + ?Sized>(
    sessions: &S,
    ctx: &PoolOpenContext<'_>,
    runtime_issuer: RuntimeOperationIssuerKeyV1,
) -> anyhow::Result<Vec<PoolPreparedServer>> {
    let mut seed = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut seed);
    let ordered = select_session_servers(ctx.resolved, seed, ctx.own_node_keys, usize::MAX);
    if ordered.is_empty() {
        return Err(no_eligible_server());
    }
    let wanted = wanted_servers(ctx.resolved);
    let request = PoolSessionPrepareV1 {
        pool: *ctx.resolved.descriptor.pool(),
        binding: ctx.binding.clone(),
        action: ctx.action,
        runtime_operation_issuer: runtime_issuer,
        content: ctx.content.clone(),
        expires_at: ctx.approval_expires_at,
    };
    let mut prepared = Vec::with_capacity(wanted);
    for server in ordered {
        if prepared.len() == wanted {
            break;
        }
        match sessions.prepare(&server, &request).await {
            Ok(answer) => prepared.push(PoolPreparedServer {
                member: server,
                prepared: answer,
            }),
            Err(error) if prepare_fails_over(&error) => {
                tracing::debug!(
                    ?error,
                    "pool open: a server cannot prepare; trying the next"
                );
            }
            Err(error) => {
                return Err(pool_unavailable(format!("session.prepare: {error:?}")));
            }
        }
    }
    if prepared.is_empty() {
        return Err(no_eligible_server());
    }
    Ok(prepared)
}

/// The release's contributions, or the open's answer when there are none
/// (F9 on `rights_denied`).
async fn release_contributions<P: PoolOpenPorts + ?Sized>(
    ports: &P,
    outcome: RuntimeReleaseCoordinatorOutcome,
    now: u64,
) -> anyhow::Result<Vec<SignedNodeContributionV1>> {
    let outcome = match outcome {
        RuntimeReleaseCoordinatorOutcome::Nonterminal {
            operation_hash,
            reason,
        } => {
            tracing::debug!(
                ?reason,
                "pool open: release nonterminal; resuming the exact operation"
            );
            ports.resume_release(operation_hash, now).await?
        }
        terminal => terminal,
    };
    match outcome {
        RuntimeReleaseCoordinatorOutcome::Terminal(
            RuntimeReleaseTerminalResult::ContributionsReady {
                signed_node_contributions,
            },
        ) => Ok(signed_node_contributions),
        RuntimeReleaseCoordinatorOutcome::Terminal(
            RuntimeReleaseTerminalResult::RightsDenied { .. },
        ) => Err(rights_denied_error(ports.rights_denied_verdict(now).await)),
        RuntimeReleaseCoordinatorOutcome::Nonterminal { reason, .. } => Err(pool_unavailable(
            format!("release resume did not yield contributions: {reason:?}"),
        )),
    }
}

/// Opens the viewer through the pool (T4.4 flow steps 2-10). The caller
/// resolved the pool (step 1), checked the purchase, listing, session
/// binding and resume, and settles the record on any error.
pub(crate) async fn open_pool_viewer<S, P>(
    ctx: PoolOpenContext<'_>,
    sessions: &S,
    ports: &P,
    keys: &PoolDeliveryKeys,
) -> anyhow::Result<PoolOpenOutcome>
where
    S: PoolSessionCalls + ?Sized,
    P: PoolOpenPorts + ?Sized,
{
    // Policy first (ADV-01 §4B): if it cannot be read, nothing is built,
    // matched or sent to the Wallet. This one policy serves the whole open.
    let (policy_body, policy_identity) = ports.rights_policy().await?;
    let chain_id = policy_body.chain_id();
    let runtime_issuer = ports.device_issuer()?;

    // Steps 2-5: the servers, the delivery key and the rights request. A
    // resume reuses all three; its delivery entry is live (the caller checked).
    let (prepared, delivery_public_key, fresh_rights, replay) = match &ctx.resume {
        Some(resume) => {
            let prepared = resume
                .sessions
                .restore(ctx.resolved)
                .ok_or_else(|| pool_unavailable("the pending pool sessions are gone".into()))?;
            let delivery_public_key = keys
                .with_entry(&ctx.handle, |entry| entry.delivery_public_key())
                .ok_or_else(|| pool_unavailable("the delivery key is gone".into()))??;
            (
                prepared,
                delivery_public_key,
                None,
                Some(resume.wallet_request.as_slice()),
            )
        }
        None => {
            let prepared = prepare_servers(sessions, &ctx, runtime_issuer).await?;
            let secret = DeliverySecretKeyV1::generate()
                .map_err(|_| pool_unavailable("no delivery key could be made".into()))?;
            let delivery_public_key = secret
                .public_key()
                .map_err(|_| pool_unavailable("the delivery key is invalid".into()))?;
            let rights = pool_rights_request(
                &ctx.binding,
                ctx.action,
                &prepared,
                &delivery_public_key,
                ctx.now,
                ctx.approval_expires_at,
                chain_id,
            )?;
            keys.insert(
                ctx.handle,
                PoolDeliveryEntry::pending(
                    secret,
                    prepared
                        .iter()
                        .map(|server| server.member.clone())
                        .collect(),
                    prepared
                        .iter()
                        .map(|server| server.prepared.session_id)
                        .collect(),
                    ctx.approval_expires_at,
                ),
            );
            (prepared, delivery_public_key, Some(rights), None)
        }
    };

    // Step 6: the Wallet. The fresh, pending and replayed requests all pass
    // the same check before the Wallet sees them.
    let expected = |request: &RightsRequestAnyV1| {
        rights_request_matches(
            request,
            &ctx.binding,
            ctx.action,
            &prepared,
            &delivery_public_key,
            chain_id,
        )
    };
    if let Some(fresh) = fresh_rights.as_ref() {
        if !expected(&RightsRequestAnyV1::V2(fresh.clone())) {
            return Err(pool_unavailable(
                "the pool rights request does not match this open".into(),
            ));
        }
    }
    let (request_bytes, response_bytes, signed_rights) = match ports
        .sign_rights(fresh_rights.as_ref(), replay, &expected, ctx.now)
        .await?
    {
        PoolWalletAnswer::Signed {
            request_bytes,
            response_bytes,
            signed_rights,
        } => (request_bytes, response_bytes, *signed_rights),
        PoolWalletAnswer::PendingApproval {
            request_bytes,
            approval_request_id,
            external_signer,
            connector_id,
        } => {
            if ctx.resume.is_none() {
                ports.persist_pending(&PoolPendingRelease {
                    wallet_request: request_bytes,
                    approval_request_id: approval_request_id.clone(),
                    sessions: PoolPendingSessions::from_prepared(&prepared)?,
                })?;
                // User decision 2026-11-13 13:05: the delivery key the Wallet
                // text shows as its `Delivery key:` line is kept in the log
                // only, once, when the approval is created, matched by the
                // approval request and the audit id; the viewer is not shown
                // it, and a poll of the same approval logs nothing new.
                tracing::info!(
                    approval_request_id = %approval_request_id,
                    audit_request_id = %hex::encode(ctx.audit_request_id.digest().as_bytes()),
                    delivery_key = %delivery_key_fingerprint(delivery_public_key.identity()),
                    "pool open: the Wallet is asked to sign the rights request"
                );
            }
            let progress = RuntimeCustodyOpenProgress::awaiting_rights_approval(
                external_signer,
                connector_id.as_deref(),
                &approval_request_id,
                ctx.approval_expires_at,
            );
            tracing::debug!(
                stage = progress.stage_label(),
                "pool open: the rights request awaits the Wallet"
            );
            return Ok(PoolOpenOutcome::PendingApproval(progress));
        }
    };
    // Steps 7-10 run on the signed rights. OPEN-LOOP F2: they are spent on
    // this open's one release, so a failure from here ends the open.
    let opened = async {
        if !expected(&RightsRequestAnyV1::V2(signed_rights.request().clone())) {
            return Err(pool_unavailable(
                "the Wallet signed a rights request other than this open's".into(),
            ));
        }

        // Step 7: the operation, with the policy read first.
        let statement = pool_release_statement(
            runtime_issuer,
            &PoolOperationInput {
                signed_rights: &signed_rights,
                prepared: &prepared,
                policy_body: &policy_body,
                policy_identity: &policy_identity,
                resolved: ctx.resolved,
                audit_request_id: ctx.audit_request_id,
            },
            ctx.now,
        )?;
        let operation = ports.sign_release_operation_v2(statement)?;
        let authenticated = operation
            .verify(RuntimeIssuerPolicyV1::Expected(runtime_issuer), ctx.now)
            .map_err(|error| pool_unavailable(format!("the pool release operation: {error:?}")))?;
        let session_end = authenticated.session_expires_at();

        // Step 8: the release at the epoch nodes.
        let outcome = ports
            .release(&request_bytes, &response_bytes, &operation, ctx.now)
            .await?;
        let contributions = release_contributions(ports, outcome, ctx.now).await?;

        // Step 9: each server's receipt and session, with fresh proofs.
        for server in &prepared {
            let recipient = server.recipient_identity();
            let own = contributions
                .iter()
                .filter(|contribution| {
                    contribution
                        .statement()
                        .recipient_sealed_contribution()
                        .recipient()
                        == recipient
                })
                .cloned()
                .collect::<Vec<_>>();
            let terminal_receipt = ports.sign_terminal_receipt_v2(
                &authenticated,
                &own,
                recipient,
                crate::auth::now_ts().max(ctx.now),
            )?;
            let opened = sessions
                .open(
                    &server.member,
                    &PoolSessionOpenV1 {
                        session_id: server.prepared.session_id,
                        operation: operation.clone(),
                        delivery_public_key,
                        contributions: own,
                        terminal_receipt,
                    },
                )
                .await
                .map_err(|error| pool_unavailable(format!("session.open: {error:?}")))?;
            if opened.expires_at != session_end {
                return Err(pool_unavailable("a pool session names another end".into()));
            }
        }

        // Step 10: the delivery entry lives to the session's end.
        let servers = prepared
            .iter()
            .map(|server| server.member.clone())
            .collect::<Vec<_>>();
        let session_ids = prepared
            .iter()
            .map(|server| server.prepared.session_id)
            .collect::<Vec<_>>();
        keys.with_entry(&ctx.handle, |entry| {
            entry.operation_hash = Some(authenticated.operation_hash());
            entry.expires_at = session_end;
        })
        .ok_or_else(|| pool_unavailable("the delivery key is gone".into()))?;
        anyhow::Ok(PoolOpened {
            handle: ctx.handle,
            expires_at: session_end,
            sessions: PoolViewerSessions::new(&servers, &session_ids),
            read_ahead_segments: ctx
                .resolved
                .descriptor
                .serve_policy()
                .bounds
                .read_ahead_segments,
        })
    }
    .await
    .map_err(after_approval_failure)?;
    Ok(PoolOpenOutcome::Opened(opened))
}

// ---------------------------------------------------------------------------
// Read and close (T4.5)
// ---------------------------------------------------------------------------

/// The read answer at the session's end (C3, user 2026-11-13 04:45): the
/// Player or Reader keeps its place and runs the open once; its rights
/// approval is the one Wallet prompt.
pub(crate) const POOL_SESSION_RENEWAL_REQUIRED: &str = "pool_session_renewal_required";

/// Why a pool read returned no part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoolReadError {
    /// No delivery secret in this process (a restart, a close, or an open
    /// still pending): the read is unavailable and the next open reopens.
    NoSecret,
    /// Before the session's end, the server gave no part: a bound, a lost
    /// or restarted server, `unknown_session`, `session_expired`,
    /// `Unreachable` or `NoExactResult`. The read is unavailable and stalls;
    /// the entry stays, so nothing resets a budget, issues a release or asks
    /// the Wallet before the rights expire (C3).
    ServerLost,
    /// The sealed part does not open under this session's key and AAD.
    Invalid,
    /// At or after the session's end: the entry is dropped and its server
    /// sessions closed best effort; the viewer reopens once.
    RenewalRequired,
}

/// The server, session and AAD inputs of one read, copied out of the entry
/// so no lock is held across the call.
struct PoolReadTarget {
    index: usize,
    server: PoolMemberV2,
    session_id: PoolSessionIdV1,
    operation_hash: Digest32,
}

/// The server that reads `part`: its stripe's server ([`stripe_index`] over
/// all servers), or, once that one is lost, the stripe over the live ones
/// (T4.8). Every server holds an open session of the same release, so the
/// stripe moves without a new release. At or after the session's end no
/// server is picked (S4B-F2): the end answers the reopen whatever the live
/// count.
fn read_target(
    entry: &PoolDeliveryEntry,
    part: &ViewerPartIndexV1,
    now: u64,
) -> Result<PoolReadTarget, PoolReadError> {
    let operation_hash = entry.operation_hash.ok_or(PoolReadError::NoSecret)?;
    if now >= entry.expires_at {
        return Err(PoolReadError::RenewalRequired);
    }
    let count = entry.servers.len();
    if count == 0 || entry.session_ids.len() != count || entry.lost.len() != count {
        return Err(PoolReadError::NoSecret);
    }
    let live = (0..count)
        .filter(|index| !entry.lost[*index])
        .collect::<Vec<_>>();
    if live.is_empty() {
        return Err(PoolReadError::ServerLost);
    }
    let primary = stripe_index(part, count);
    let index = if entry.lost[primary] {
        live[stripe_index(part, live.len())]
    } else {
        primary
    };
    Ok(PoolReadTarget {
        index,
        server: entry.servers[index].clone(),
        session_id: entry.session_ids[index],
        operation_hash,
    })
}

/// Marks server `index` lost if another server is still live, checked and
/// set under the one entry lock (S4B-F2): of concurrent failures, the last
/// live server is never marked, so its failure stays an unavailable read.
fn mark_lost_if_others_live(entry: &mut PoolDeliveryEntry, index: usize) -> bool {
    let others_live = entry
        .lost
        .iter()
        .enumerate()
        .any(|(other, lost)| other != index && !*lost);
    match entry.lost.get_mut(index) {
        Some(lost) if others_live => {
            *lost = true;
            true
        }
        _ => false,
    }
}

/// Whether a failed read means its server is lost, so its stripe may move
/// (T4.8). A bound refusal (read-ahead or the byte budget) stays with its
/// server: moving it would spend another server's budget (C3).
fn server_is_lost(error: &PoolTransportError) -> bool {
    match error {
        PoolTransportError::Unreachable | PoolTransportError::NoExactResult => true,
        PoolTransportError::Refused(code) => {
            matches!(code.as_str(), "unknown_session" | "session_expired")
        }
    }
}

/// Closes every server session of a taken entry, best effort: a server that
/// does not answer keeps its session only until the session's end.
async fn close_entry_sessions<S: PoolSessionCalls + ?Sized>(
    entry: &PoolDeliveryEntry,
    sessions: &S,
) {
    for (server, session_id) in entry.servers.iter().zip(&entry.session_ids) {
        if let Err(error) = sessions.close(server, *session_id).await {
            tracing::debug!(
                ?error,
                "pool close: a server session ends at the session's end instead"
            );
        }
    }
}

/// Reads one part of an open pool viewer: the server [`stripe_index`]
/// picks returns it sealed, and it opens here with the in-memory delivery
/// secret and its `ViewerPartAadV1`. The buyer sends only the part index;
/// the server fetches the ciphertext (T3.4), so nothing is fetched here.
pub(crate) async fn read_pool_viewer<S: PoolSessionCalls + ?Sized>(
    handle: &PoolViewerHandle,
    part: ViewerPartIndexV1,
    sessions: &S,
    keys: &PoolDeliveryKeys,
    now: u64,
) -> Result<zeroize::Zeroizing<Vec<u8>>, PoolReadError> {
    // At most one try per server: each loss moves the stripe on (T4.8).
    let mut tries = 0usize;
    let (target, sealed) = loop {
        let target = match keys
            .with_entry(handle, |entry| read_target(entry, &part, now))
            .ok_or(PoolReadError::NoSecret)?
        {
            Err(PoolReadError::RenewalRequired) => {
                if let Some(entry) = keys.take(handle) {
                    close_entry_sessions(&entry, sessions).await;
                }
                return Err(PoolReadError::RenewalRequired);
            }
            target => target?,
        };
        let request = PoolSessionReadV1 {
            session_id: target.session_id,
            part,
        };
        match sessions.read_sealed(&target.server, &request).await {
            Ok(sealed) => break (target, sealed),
            Err(error) => {
                tries += 1;
                tracing::debug!(?error, "pool read: the server gave no part");
                // The last live server is never marked lost: its failure is
                // an unavailable read, and the viewer asks again. The live
                // count is read where the loss is set, not before the call.
                let moved = server_is_lost(&error)
                    && keys.with_entry(handle, |entry| {
                        tries < entry.servers.len() && mark_lost_if_others_live(entry, target.index)
                    }) == Some(true);
                if !moved {
                    return Err(PoolReadError::ServerLost);
                }
                tracing::debug!(
                    server = target.index,
                    "pool read: the stripe moves to another server"
                );
            }
        }
    };
    let aad = ViewerPartAadV1 {
        session_id: target.session_id,
        operation_hash: target.operation_hash,
        part,
    };
    keys.with_entry(handle, |entry| {
        open_viewer_part_v1(&entry.secret, &aad, &sealed)
    })
    .ok_or(PoolReadError::NoSecret)?
    .map_err(|_| PoolReadError::Invalid)
}

/// How a pool viewer closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoolCloseResult {
    Closed,
    /// No delivery entry here: the server sessions end at the session's end.
    AlreadyAbsent,
}

/// Ends every server session of the viewer and drops its delivery secret.
pub(crate) async fn close_pool_viewer<S: PoolSessionCalls + ?Sized>(
    handle: &PoolViewerHandle,
    sessions: &S,
    keys: &PoolDeliveryKeys,
) -> PoolCloseResult {
    let Some(entry) = keys.take(handle) else {
        return PoolCloseResult::AlreadyAbsent;
    };
    close_entry_sessions(&entry, sessions).await;
    PoolCloseResult::Closed
}

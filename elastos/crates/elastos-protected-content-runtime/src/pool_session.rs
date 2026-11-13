//! Plan B T3.2: the pool session server, behind ports and free of any gateway.
//!
//! A pool member serves a viewing session to another Home. It prepares a
//! recipient in its decrypt provider and has its custody node attest it, opens
//! the session with the contributions released to that recipient, and returns
//! each part sealed to the viewer's delivery key. The server never serves its
//! own Home (D2) unless the pool allows it, and it bounds every session and the
//! node as a whole.
//!
//! State lives behind one `std::sync::Mutex` that is never held across an
//! `.await`. A call checks its bounds and reserves its slot in one lock
//! section, before its first port call. A reservation is an RAII guard: a port
//! error rolls it back, and a dropped future marks the entry abandoned so the
//! next sweep cleans it. The call that started a port call owns its result: a
//! result that comes back after a close, an expiry or a sweep is cleaned up by
//! that call. Every call first sweeps expired and abandoned entries; their
//! cleanup runs outside the lock, and their slots are freed after it.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use elastos_protected_content_contracts::{
    ContentAccessIdV1, CustodyEpochIdentityV1, DeliveryPublicKeyBytesV1, Digest32,
    EncryptedContentIdentityV1, NodePublicKey, PoolDidV1, PoolRecipientAttestationStatementV2,
    PoolSessionContentKindV1, PoolTrustModeV1, ProtectedContentBindingV1, RecipientKeyIdentityV1,
    RecipientPublicKeyBytesV1, RightsActionV1, RuntimeIssuerPolicyV1, RuntimeOperationIssuerKeyV1,
    RuntimeReleaseAuditIdV1, SessionBoundsV1, SignedNodeContributionV1,
    SignedPoolRecipientAttestationV2, SignedRuntimeReleaseOperationV2, SignedTerminalReceiptV1,
    VerifiedPoolDescriptorV1, ViewerPartIndexV1, WalletAddress,
};
use elastos_protected_content_provider_contracts::{
    CencDashMediaIdentityV2, CencFmp4MediaIdentityV1, ChunkedPayloadObjectIdentityV1,
    DecryptProviderRequestV1, DecryptProviderResponseStatusV1, DecryptProviderResponseV1,
    DecryptViewerContentV1, ProviderFailureCodeV1, ViewerMediaPartSelectorV1,
    MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1, MAX_VIEWER_SESSIONS_V1,
};
use sha2::{Digest as _, Sha256};

use crate::RuntimeProviderCallError;

/// A pool session id: 16 bytes, named in every sealed part's AAD.
pub type PoolSessionIdV1 = [u8; 16];
type DecryptHandle = [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];

const PREPARE_AUDIT_DOMAIN_V1: &[u8] = b"elastos.protected-content.pool-session.prepare/v1";

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// Who called: the authenticated Carrier endpoint, or this Runtime itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSessionSource {
    pub endpoint_did: String,
    pub local: bool,
}

/// The full typed identity of the content a session serves (F4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolContentIdentityV1 {
    MediaV1(CencFmp4MediaIdentityV1),
    DashV2(CencDashMediaIdentityV2),
    Object(ChunkedPayloadObjectIdentityV1),
}

impl PoolContentIdentityV1 {
    pub fn kind(&self) -> PoolSessionContentKindV1 {
        match self {
            Self::MediaV1(_) => PoolSessionContentKindV1::MediaV1,
            Self::DashV2(_) => PoolSessionContentKindV1::DashV2,
            Self::Object(_) => PoolSessionContentKindV1::Object,
        }
    }

    pub fn encrypted_content(&self) -> &EncryptedContentIdentityV1 {
        match self {
            Self::MediaV1(identity) => identity.encrypted_content(),
            Self::DashV2(identity) => identity.encrypted_content(),
            Self::Object(identity) => identity.encrypted_content(),
        }
    }
}

/// What a session serves (F4). It comes from the buyer's verified draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSessionContentRefV1 {
    pub cid: String,
    /// The kind the wire names; it must be the identity's kind.
    pub kind: PoolSessionContentKindV1,
    pub identity: PoolContentIdentityV1,
    pub content_key_commitment: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSessionPrepareV1 {
    pub pool: PoolDidV1,
    pub binding: ProtectedContentBindingV1,
    pub action: RightsActionV1,
    pub runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
    pub content: PoolSessionContentRefV1,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSessionPreparedV1 {
    pub session_id: PoolSessionIdV1,
    pub recipient_public_key: RecipientPublicKeyBytesV1,
    pub attestation: SignedPoolRecipientAttestationV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSessionOpenV1 {
    pub session_id: PoolSessionIdV1,
    pub operation: SignedRuntimeReleaseOperationV2,
    /// F3: its identity must be the operation's wallet-signed delivery key.
    pub delivery_public_key: DeliveryPublicKeyBytesV1,
    pub contributions: Vec<SignedNodeContributionV1>,
    pub terminal_receipt: SignedTerminalReceiptV1,
}

/// The session's end (user 2026-11-13 04:45): the signed rights expiry,
/// capped by the earliest attestation expiry
/// (`AuthenticatedRuntimeReleaseOperationV2::session_expires_at`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSessionOpenedV1 {
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSessionReadV1 {
    pub session_id: PoolSessionIdV1,
    pub part: ViewerPartIndexV1,
}

/// Bytes a content port staged and verified against the full identity (F4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolStagedContentV1 {
    pub handle: [u8; 16],
    pub total_ciphertext_bytes: u64,
    pub duration_secs: Option<u64>,
    pub open: PoolStagedOpenV1,
}

/// The open material of staged content: only bytes verified against the
/// identity. DASH leaves stay inside the stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolStagedOpenV1 {
    MediaV1 {
        protected_init: Vec<u8>,
    },
    /// Head order.
    DashV2 {
        protected_inits: Vec<Vec<u8>>,
    },
    Object {
        framed_header: Vec<u8>,
    },
}

impl PoolStagedOpenV1 {
    fn kind(&self) -> PoolSessionContentKindV1 {
        match self {
            Self::MediaV1 { .. } => PoolSessionContentKindV1::MediaV1,
            Self::DashV2 { .. } => PoolSessionContentKindV1::DashV2,
            Self::Object { .. } => PoolSessionContentKindV1::Object,
        }
    }
}

/// One part's material. An init carries no bytes; a DASH segment carries its
/// audit path from the verified leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolStagedPartV1 {
    MediaV1Init,
    MediaV1Segment {
        index: u32,
        encrypted: Vec<u8>,
    },
    DashInit {
        rendition: u8,
    },
    DashSegment {
        rendition: u8,
        index: u32,
        encrypted: Vec<u8>,
        proof: Vec<Digest32>,
    },
    ObjectChunk {
        index: u32,
        framed_chunk: Vec<u8>,
    },
}

impl PoolStagedPartV1 {
    fn index(&self) -> ViewerPartIndexV1 {
        match self {
            Self::MediaV1Init => ViewerPartIndexV1::MediaV1Init,
            Self::MediaV1Segment { index, .. } => ViewerPartIndexV1::MediaV1Segment(*index),
            Self::DashInit { rendition } => ViewerPartIndexV1::DashInit {
                rendition: *rendition,
            },
            Self::DashSegment {
                rendition, index, ..
            } => ViewerPartIndexV1::DashSegment {
                rendition: *rendition,
                index: *index,
            },
            Self::ObjectChunk { index, .. } => ViewerPartIndexV1::ObjectChunk(*index),
        }
    }

    /// The ciphertext bytes the part serves; the budgets count these.
    fn ciphertext_bytes(&self) -> u64 {
        match self {
            Self::MediaV1Init | Self::DashInit { .. } => 0,
            Self::MediaV1Segment { encrypted, .. } | Self::DashSegment { encrypted, .. } => {
                encrypted.len() as u64
            }
            Self::ObjectChunk { framed_chunk, .. } => framed_chunk.len() as u64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolSessionRefusal {
    SelfServe,
    NotEligible,
    NotReady,
    PoolBusy,
    /// A session bound; the name says which.
    Bound(&'static str),
    UnknownSession,
    Expired,
    BindingMismatch,
    ContentUnavailable,
    DecryptUnavailable,
}

impl PoolSessionRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SelfServe => "self_serve_refused",
            Self::NotEligible => "not_eligible_server",
            Self::NotReady => "server_not_ready",
            Self::PoolBusy => "pool_busy",
            Self::Bound(_) => "session_bound_exceeded",
            Self::UnknownSession => "unknown_session",
            Self::Expired => "session_expired",
            Self::BindingMismatch => "binding_mismatch",
            Self::ContentUnavailable => "content_unavailable",
            Self::DecryptUnavailable => "decrypt_unavailable",
        }
    }
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// The local decrypt provider's V2 ops (T3.1), in the style of
/// `RuntimeDecryptProvider`.
#[async_trait::async_trait]
pub trait PoolSessionDecryptPort: Send + Sync {
    async fn prepare_recipient_v2(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError>;

    async fn open_viewer_session_v2(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError>;

    async fn read_viewer_media_part_sealed(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError>;

    async fn read_viewer_object_chunk_sealed(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError>;

    async fn cancel_prepared_recipient(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError>;

    async fn close_viewer_session(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError>;
}

/// Content staged by CID and verified against the full identity (F4). Test
/// fakes and the server's content-plane adapter implement the same contract.
#[async_trait::async_trait]
pub trait PoolSessionContentPort: Send + Sync {
    /// `ContentUnavailable` on any mismatch with the identity.
    async fn stage(
        &self,
        session_id: PoolSessionIdV1,
        content: &PoolSessionContentRefV1,
        binding: &ProtectedContentBindingV1,
    ) -> Result<PoolStagedContentV1, PoolSessionRefusal>;

    async fn part(
        &self,
        staged: &PoolStagedContentV1,
        part: &ViewerPartIndexV1,
    ) -> Result<PoolStagedPartV1, PoolSessionRefusal>;

    fn discard(&self, session_id: PoolSessionIdV1);
}

/// The custody node's recipient attestation (`sign_pool_statement`).
#[async_trait::async_trait]
pub trait PoolSessionAttestPort: Send + Sync {
    async fn attest_recipient(
        &self,
        statement: &PoolRecipientAttestationStatementV2,
    ) -> Result<SignedPoolRecipientAttestationV2, PoolSessionRefusal>;
}

pub trait PoolSessionPolicyPort: Send + Sync {
    fn descriptor(&self, pool: &PoolDidV1) -> Option<VerifiedPoolDescriptorV1>;
    fn own_node_key(&self, pool: &PoolDidV1) -> Option<NodePublicKey>;
    fn own_endpoint_did(&self) -> &str;
    /// The device-derived issuer (E12), not the chain-plane issuer.
    fn own_runtime_issuer(&self) -> RuntimeOperationIssuerKeyV1;
    fn decrypt_ready(&self) -> bool;
    /// #388 A1: whether this host is WCI-operated, as captured at its start.
    /// Otherwise every session op except `session.close` answers
    /// `not_eligible_server`.
    fn host_trusted(&self) -> bool;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct PreparedSession {
    pool: PoolDidV1,
    binding: ProtectedContentBindingV1,
    action: RightsActionV1,
    runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
    content: PoolSessionContentRefV1,
    prepared_handle: DecryptHandle,
    prepare_audit: RuntimeReleaseAuditIdV1,
    recipient_public_key: RecipientPublicKeyBytesV1,
    recipient_identity: RecipientKeyIdentityV1,
}

struct OpenSession {
    viewer_handle: DecryptHandle,
    audit: RuntimeReleaseAuditIdV1,
    staged: PoolStagedContentV1,
    served_bytes: u64,
    reserved_bytes: u64,
    /// The highest DASH segment index read per rendition.
    highest_read: [Option<u32>; 2],
    /// DASH segments whose read is in flight.
    in_flight: Vec<(u8, u32)>,
}

enum EntryState {
    /// The prepare port calls are in flight; the handle is known once the
    /// decrypt provider made it.
    Preparing {
        prepared: Option<(DecryptHandle, RuntimeReleaseAuditIdV1)>,
    },
    Prepared(Box<PreparedSession>),
    /// The open port calls are in flight.
    Opening(Box<PreparedSession>),
    Open(Box<OpenSession>),
    /// Swept; the slot is freed once its cleanup has run.
    Cleaning,
}

struct Entry {
    owner: String,
    wallet: WalletAddress,
    /// Set from the release at open (`Opening` and `Open`).
    kid: Option<ContentAccessIdV1>,
    bounds: SessionBoundsV1,
    expires_at: u64,
    /// A close came while a port call was in flight; that call cleans up.
    closing: bool,
    /// The call that owned the entry was dropped; the sweep cleans it.
    abandoned: bool,
    state: EntryState,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<PoolSessionIdV1, Entry>,
}

/// Work that runs outside the lock.
enum Cleanup {
    CancelPrepared {
        handle: DecryptHandle,
        audit: RuntimeReleaseAuditIdV1,
    },
    CloseViewer {
        handle: DecryptHandle,
        audit: RuntimeReleaseAuditIdV1,
    },
    Discard(PoolSessionIdV1),
}

fn cleanup_for(session_id: PoolSessionIdV1, state: &EntryState) -> Vec<Cleanup> {
    match state {
        EntryState::Preparing {
            prepared: Some((handle, audit)),
        } => vec![Cleanup::CancelPrepared {
            handle: *handle,
            audit: *audit,
        }],
        EntryState::Preparing { prepared: None } | EntryState::Cleaning => Vec::new(),
        EntryState::Prepared(prepared) => vec![Cleanup::CancelPrepared {
            handle: prepared.prepared_handle,
            audit: prepared.prepare_audit,
        }],
        // An abandoned open may have opened the decrypt session under the
        // prepared handle; both answers are idempotent.
        EntryState::Opening(prepared) => vec![
            Cleanup::CancelPrepared {
                handle: prepared.prepared_handle,
                audit: prepared.prepare_audit,
            },
            Cleanup::CloseViewer {
                handle: prepared.prepared_handle,
                audit: prepared.prepare_audit,
            },
            Cleanup::Discard(session_id),
        ],
        EntryState::Open(open) => vec![
            Cleanup::CloseViewer {
                handle: open.viewer_handle,
                audit: open.audit,
            },
            Cleanup::Discard(session_id),
        ],
    }
}

/// Marks an entry abandoned if the call holding it is dropped mid-await.
struct ReservationGuard<'a> {
    state: &'a Mutex<State>,
    session_id: PoolSessionIdV1,
    armed: bool,
}

impl ReservationGuard<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ReservationGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(entry) = state.entries.get_mut(&self.session_id) {
                entry.abandoned = true;
            }
        }
    }
}

/// Releases a read's in-flight index and reserved bytes unless committed.
struct ReadGuard<'a> {
    state: &'a Mutex<State>,
    session_id: PoolSessionIdV1,
    in_flight: Option<(u8, u32)>,
    reserved: u64,
    armed: bool,
}

impl Drop for ReadGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(Entry {
            state: EntryState::Open(open),
            ..
        }) = state.entries.get_mut(&self.session_id)
        {
            open.reserved_bytes = open.reserved_bytes.saturating_sub(self.reserved);
            if let Some(key) = self.in_flight {
                open.in_flight.retain(|item| *item != key);
            }
        }
    }
}

/// Frees swept slots once their cleanup has run, or if the sweeping call is
/// dropped (the decrypt provider's own purge is the backstop).
struct CleaningGuard<'a> {
    state: &'a Mutex<State>,
    session_ids: Vec<PoolSessionIdV1>,
}

impl Drop for CleaningGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        for session_id in &self.session_ids {
            state.entries.remove(session_id);
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

type SessionIdSource = Box<dyn FnMut() -> PoolSessionIdV1 + Send>;

pub struct PoolSessionServer<P, D, C, A> {
    policy: P,
    decrypt: D,
    content: C,
    attest: A,
    state: Mutex<State>,
    session_ids: Mutex<SessionIdSource>,
    node_budget: usize,
}

fn random_session_id() -> PoolSessionIdV1 {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        // An all-zero id is refused by `reserve_session_id`.
        return [0u8; 16];
    }
    bytes
}

/// The decrypt prepare's audit id: one per session.
fn prepare_audit_id(session_id: PoolSessionIdV1) -> Option<RuntimeReleaseAuditIdV1> {
    let mut hasher = Sha256::new();
    hasher.update(PREPARE_AUDIT_DOMAIN_V1);
    hasher.update(session_id);
    RuntimeReleaseAuditIdV1::new(Digest32::new(hasher.finalize().into())).ok()
}

/// A decrypt refusal: a binding mismatch stays one; any other refusal, the
/// capacity refusal included, means the decrypt plane cannot serve (L11).
fn decrypt_refusal(response: &DecryptProviderResponseV1) -> PoolSessionRefusal {
    match response.failure_code() {
        Ok(ProviderFailureCodeV1::BindingMismatch) => PoolSessionRefusal::BindingMismatch,
        _ => PoolSessionRefusal::DecryptUnavailable,
    }
}

/// The staged open material has the identity's kind; DASH has one init per
/// rendition.
fn staged_matches_identity(staged: &PoolStagedContentV1, identity: &PoolContentIdentityV1) -> bool {
    if staged.open.kind() != identity.kind() {
        return false;
    }
    match (&staged.open, identity) {
        (PoolStagedOpenV1::DashV2 { protected_inits }, PoolContentIdentityV1::DashV2(head)) => {
            protected_inits.len() == head.renditions().len()
        }
        _ => true,
    }
}

fn viewer_content<'a>(
    identity: &'a PoolContentIdentityV1,
    open: &'a PoolStagedOpenV1,
) -> Option<DecryptViewerContentV1<'a>> {
    match (identity, open) {
        (
            PoolContentIdentityV1::MediaV1(identity),
            PoolStagedOpenV1::MediaV1 { protected_init },
        ) => Some(DecryptViewerContentV1::MediaV1 {
            identity,
            protected_init_segment: protected_init,
        }),
        (PoolContentIdentityV1::DashV2(identity), PoolStagedOpenV1::DashV2 { protected_inits }) => {
            Some(DecryptViewerContentV1::DashV2 {
                identity,
                protected_init_segments: protected_inits,
            })
        }
        (PoolContentIdentityV1::Object(identity), PoolStagedOpenV1::Object { framed_header }) => {
            Some(DecryptViewerContentV1::Object {
                identity,
                framed_header,
            })
        }
        _ => None,
    }
}

impl<P, D, C, A> PoolSessionServer<P, D, C, A>
where
    P: PoolSessionPolicyPort,
    D: PoolSessionDecryptPort,
    C: PoolSessionContentPort,
    A: PoolSessionAttestPort,
{
    /// Session ids come from `getrandom` (E10). The node budget defaults to
    /// the decrypt provider's session bound.
    pub fn new(policy: P, decrypt: D, content: C, attest: A) -> Self {
        Self {
            policy,
            decrypt,
            content,
            attest,
            state: Mutex::new(State::default()),
            session_ids: Mutex::new(Box::new(random_session_id)),
            node_budget: MAX_VIEWER_SESSIONS_V1,
        }
    }

    /// Tests inject the session ids (E10).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn with_session_ids(self, ids: SessionIdSource) -> Self {
        Self {
            session_ids: Mutex::new(ids),
            ..self
        }
    }

    /// The node budget (`pool_sessions_per_node`), at most the decrypt
    /// provider's session bound (L11).
    pub fn with_node_budget(self, node_budget: usize) -> Self {
        Self {
            node_budget: node_budget.min(MAX_VIEWER_SESSIONS_V1),
            ..self
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // -- sweep and cleanup -------------------------------------------------

    /// Cleans expired and abandoned entries. Returns the expired ones with
    /// their owners, so a call can answer `Expired` for its own session.
    async fn sweep(&self, now: u64) -> Vec<(PoolSessionIdV1, String)> {
        let (swept, expired, jobs) = {
            let mut state = self.lock();
            let mut swept = Vec::new();
            let mut expired = Vec::new();
            let mut jobs = Vec::new();
            for (session_id, entry) in state.entries.iter_mut() {
                let in_flight = matches!(
                    entry.state,
                    EntryState::Preparing { .. } | EntryState::Opening(_)
                );
                let is_expired = now >= entry.expires_at;
                if matches!(entry.state, EntryState::Cleaning)
                    || !(entry.abandoned || (is_expired && !in_flight))
                {
                    continue;
                }
                if is_expired {
                    expired.push((*session_id, entry.owner.clone()));
                }
                jobs.extend(cleanup_for(*session_id, &entry.state));
                entry.state = EntryState::Cleaning;
                swept.push(*session_id);
            }
            (swept, expired, jobs)
        };
        if !swept.is_empty() {
            tracing::debug!(count = swept.len(), "pool sessions swept");
            let _slots = CleaningGuard {
                state: &self.state,
                session_ids: swept,
            };
            self.run_cleanup(jobs).await;
        }
        expired
    }

    /// The sweep, then `Expired` if `session_id` was one of the source's
    /// sessions that it just cleaned.
    async fn sweep_for(
        &self,
        session_id: PoolSessionIdV1,
        source: &PoolSessionSource,
        now: u64,
    ) -> Result<(), PoolSessionRefusal> {
        let expired = self.sweep(now).await;
        if expired
            .iter()
            .any(|(id, owner)| *id == session_id && *owner == source.endpoint_did)
        {
            return Err(PoolSessionRefusal::Expired);
        }
        Ok(())
    }

    async fn run_cleanup(&self, jobs: Vec<Cleanup>) {
        for job in jobs {
            match job {
                Cleanup::CancelPrepared { handle, audit } => {
                    if let Ok(request) =
                        DecryptProviderRequestV1::new_cancel_prepared_recipient(audit, handle)
                    {
                        let _ = self.decrypt.cancel_prepared_recipient(&request).await;
                    }
                }
                Cleanup::CloseViewer { handle, audit } => {
                    if let Ok(request) =
                        DecryptProviderRequestV1::new_close_viewer_session(audit, handle)
                    {
                        let _ = self.decrypt.close_viewer_session(&request).await;
                    }
                }
                Cleanup::Discard(session_id) => self.content.discard(session_id),
            }
        }
    }

    fn reserve_session_id(&self, state: &State) -> Option<PoolSessionIdV1> {
        let mut ids = self
            .session_ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let generate: &mut SessionIdSource = &mut ids;
        (0..8)
            .map(|_| generate())
            .find(|id| *id != [0u8; 16] && !state.entries.contains_key(id))
    }

    // -- prepare -----------------------------------------------------------

    pub async fn prepare(
        &self,
        prepare: PoolSessionPrepareV1,
        source: &PoolSessionSource,
        now: u64,
    ) -> Result<PoolSessionPreparedV1, PoolSessionRefusal> {
        if !self.policy.host_trusted() {
            return Err(PoolSessionRefusal::NotEligible);
        }
        self.sweep(now).await;
        let descriptor = self
            .policy
            .descriptor(&prepare.pool)
            .ok_or(PoolSessionRefusal::NotEligible)?;
        // #388 A2: only a v3 descriptor of a trusted pool admits a session.
        let trust_mode = descriptor
            .admits_new_release()
            .map_err(|_| PoolSessionRefusal::NotEligible)?;
        let own_node = self
            .policy
            .own_node_key(&prepare.pool)
            .ok_or(PoolSessionRefusal::NotEligible)?;
        if !descriptor
            .member(own_node)
            .is_some_and(|member| member.roles().serve)
        {
            return Err(PoolSessionRefusal::NotEligible);
        }
        // D2: never for this Home, unless a development pool allows it.
        let serve_policy = *descriptor.serve_policy();
        if !serve_policy.allow_self_serve
            && (source.local
                || source.endpoint_did == self.policy.own_endpoint_did()
                || prepare.runtime_operation_issuer == self.policy.own_runtime_issuer())
        {
            return Err(PoolSessionRefusal::SelfServe);
        }
        if !self.policy.decrypt_ready() {
            return Err(PoolSessionRefusal::NotReady);
        }
        // F4, before any port call: the identity is the content the wallet
        // binding names, of the kind the wire names.
        if prepare.content.identity.kind() != prepare.content.kind
            || prepare.content.identity.encrypted_content() != prepare.binding.encrypted_content()
        {
            return Err(PoolSessionRefusal::BindingMismatch);
        }
        let epoch = descriptor
            .epoch_for(prepare.binding.key_envelope())
            .and_then(|bundle| bundle.epoch_identity().ok())
            .ok_or(PoolSessionRefusal::BindingMismatch)?;
        if prepare.expires_at <= now {
            return Err(PoolSessionRefusal::Expired);
        }

        let bounds = serve_policy.bounds;
        let session_id = {
            let mut state = self.lock();
            if state.entries.len() >= self.node_budget {
                return Err(PoolSessionRefusal::PoolBusy);
            }
            if state
                .entries
                .values()
                .filter(|entry| entry.owner == source.endpoint_did)
                .count()
                >= usize::from(bounds.max_sessions_per_endpoint)
            {
                tracing::debug!(bound = "sessions_per_endpoint", "pool session bound");
                return Err(PoolSessionRefusal::Bound("sessions_per_endpoint"));
            }
            let wallet = prepare.binding.wallet();
            if state
                .entries
                .values()
                .filter(|entry| entry.wallet == wallet)
                .count()
                >= usize::from(bounds.max_sessions_per_wallet)
            {
                tracing::debug!(bound = "sessions_per_wallet", "pool session bound");
                return Err(PoolSessionRefusal::Bound("sessions_per_wallet"));
            }
            let session_id = self
                .reserve_session_id(&state)
                .ok_or(PoolSessionRefusal::NotReady)?;
            state.entries.insert(
                session_id,
                Entry {
                    owner: source.endpoint_did.clone(),
                    wallet,
                    kid: None,
                    bounds,
                    expires_at: prepare.expires_at,
                    closing: false,
                    abandoned: false,
                    state: EntryState::Preparing { prepared: None },
                },
            );
            session_id
        };
        let mut guard = ReservationGuard {
            state: &self.state,
            session_id,
            armed: true,
        };

        let result = self
            .prepare_in_flight(&prepare, session_id, own_node, epoch, trust_mode, now)
            .await;
        let (outcome, jobs) = {
            let mut state = self.lock();
            match result {
                Err((refusal, jobs)) => {
                    state.entries.remove(&session_id);
                    (Err(refusal), jobs)
                }
                Ok((prepared, attestation)) => {
                    let committable = state.entries.get(&session_id).is_some_and(|entry| {
                        matches!(entry.state, EntryState::Preparing { .. })
                            && !entry.closing
                            && !entry.abandoned
                    });
                    if committable {
                        let answer = PoolSessionPreparedV1 {
                            session_id,
                            recipient_public_key: prepared.recipient_public_key,
                            attestation,
                        };
                        if let Some(entry) = state.entries.get_mut(&session_id) {
                            entry.state = EntryState::Prepared(Box::new(prepared));
                        }
                        (Ok(answer), Vec::new())
                    } else {
                        // Closed or swept while in flight: this call cleans up.
                        state.entries.remove(&session_id);
                        (
                            Err(PoolSessionRefusal::UnknownSession),
                            vec![Cleanup::CancelPrepared {
                                handle: prepared.prepared_handle,
                                audit: prepared.prepare_audit,
                            }],
                        )
                    }
                }
            }
        };
        guard.disarm();
        self.run_cleanup(jobs).await;
        outcome
    }

    /// The prepare's port calls. An error carries the cleanup it needs.
    async fn prepare_in_flight(
        &self,
        prepare: &PoolSessionPrepareV1,
        session_id: PoolSessionIdV1,
        own_node: NodePublicKey,
        epoch: CustodyEpochIdentityV1,
        trust_mode: PoolTrustModeV1,
        now: u64,
    ) -> Result<
        (PreparedSession, SignedPoolRecipientAttestationV2),
        (PoolSessionRefusal, Vec<Cleanup>),
    > {
        let audit =
            prepare_audit_id(session_id).ok_or((PoolSessionRefusal::NotReady, Vec::new()))?;
        let request = DecryptProviderRequestV1::new_prepare_recipient_v2(
            &prepare.binding,
            audit,
            prepare.action,
            prepare.runtime_operation_issuer,
            prepare.expires_at,
        )
        .map_err(|_| (PoolSessionRefusal::BindingMismatch, Vec::new()))?;
        let response = self
            .decrypt
            .prepare_recipient_v2(&request)
            .await
            .map_err(|_| (PoolSessionRefusal::DecryptUnavailable, Vec::new()))?;
        if response.status() != DecryptProviderResponseStatusV1::PreparedRecipient
            || response.audit_request_id().ok() != Some(audit)
        {
            return Err((decrypt_refusal(&response), Vec::new()));
        }
        let (Ok(handle), Ok(recipient_public_key), Ok(recipient_identity)) = (
            response.prepared_recipient_handle().copied(),
            response.recipient_public_key(),
            response.recipient_identity(),
        ) else {
            return Err((PoolSessionRefusal::DecryptUnavailable, Vec::new()));
        };
        let cancel = || vec![Cleanup::CancelPrepared { handle, audit }];
        // From here a dropped call leaves a handle the sweep can cancel.
        if let Some(Entry {
            state: EntryState::Preparing { prepared },
            ..
        }) = self.lock().entries.get_mut(&session_id)
        {
            *prepared = Some((handle, audit));
        }
        let statement = PoolRecipientAttestationStatementV2::new(
            prepare.pool,
            epoch,
            own_node,
            prepare.binding.clone(),
            prepare.action,
            recipient_public_key,
            recipient_identity.clone(),
            prepare.runtime_operation_issuer,
            now,
            prepare.expires_at,
            // #388-2: the pool's own mode; WCI evidence is empty.
            trust_mode,
            Vec::new(),
        )
        .map_err(|_| (PoolSessionRefusal::BindingMismatch, cancel()))?;
        let attestation = self
            .attest
            .attest_recipient(&statement)
            .await
            .map_err(|refusal| (refusal, cancel()))?;
        Ok((
            PreparedSession {
                pool: prepare.pool,
                binding: prepare.binding.clone(),
                action: prepare.action,
                runtime_operation_issuer: prepare.runtime_operation_issuer,
                content: prepare.content.clone(),
                prepared_handle: handle,
                prepare_audit: audit,
                recipient_public_key,
                recipient_identity,
            },
            attestation,
        ))
    }

    // -- open --------------------------------------------------------------

    pub async fn open(
        &self,
        open: PoolSessionOpenV1,
        source: &PoolSessionSource,
        now: u64,
    ) -> Result<PoolSessionOpenedV1, PoolSessionRefusal> {
        if !self.policy.host_trusted() {
            return Err(PoolSessionRefusal::NotEligible);
        }
        let session_id = open.session_id;
        self.sweep_for(session_id, source, now).await?;
        // 1. No lock: the release under its declared issuer (the descriptor
        // by the release rule), and the delivery key the wallet signed (F3).
        let operation = open
            .operation
            .verify(RuntimeIssuerPolicyV1::Declared, now)
            .map_err(|_| PoolSessionRefusal::BindingMismatch)?;
        if open.delivery_public_key.identity() != operation.delivery_key() {
            return Err(PoolSessionRefusal::BindingMismatch);
        }
        let kid = operation.statement().policy_body().content_access_id();

        // 2. Lock: this source's prepared, unexpired entry, and the release it
        // was prepared for; reserve the wallet+KID count and move to Opening.
        let prepared = {
            let mut state = self.lock();
            let entry = state
                .entries
                .get(&session_id)
                .filter(|entry| entry.owner == source.endpoint_did)
                .ok_or(PoolSessionRefusal::UnknownSession)?;
            let EntryState::Prepared(prepared) = &entry.state else {
                return Err(PoolSessionRefusal::UnknownSession);
            };
            if now >= entry.expires_at {
                return Err(PoolSessionRefusal::Expired);
            }
            if operation.binding() != &prepared.binding
                || operation.action() != prepared.action
                || operation.runtime_operation_issuer() != prepared.runtime_operation_issuer
                || operation.pool() != &prepared.pool
                || !operation
                    .recipients()
                    .iter()
                    .any(|recipient| recipient.public_key() == prepared.recipient_public_key)
            {
                return Err(PoolSessionRefusal::BindingMismatch);
            }
            let wallet = entry.wallet;
            let bound = usize::from(entry.bounds.max_sessions_per_wallet_kid);
            let prepared = prepared.clone();
            let open_for_wallet_kid = state
                .entries
                .values()
                .filter(|other| {
                    other.wallet == wallet
                        && other.kid == Some(kid)
                        && matches!(other.state, EntryState::Opening(_) | EntryState::Open(_))
                })
                .count();
            if open_for_wallet_kid >= bound {
                tracing::debug!(bound = "sessions_per_wallet_kid", "pool session bound");
                return Err(PoolSessionRefusal::Bound("sessions_per_wallet_kid"));
            }
            let entry = state
                .entries
                .get_mut(&session_id)
                .ok_or(PoolSessionRefusal::UnknownSession)?;
            entry.kid = Some(kid);
            entry.state = EntryState::Opening(prepared.clone());
            prepared
        };
        let mut guard = ReservationGuard {
            state: &self.state,
            session_id,
            armed: true,
        };

        // 3. Stage, check the staged kind, then the decrypt open.
        let result = self.open_in_flight(&open, &prepared).await;
        let (outcome, jobs) = {
            let mut state = self.lock();
            let opening = state.entries.get(&session_id).map(|entry| {
                (
                    matches!(entry.state, EntryState::Opening(_)),
                    entry.closing,
                    entry.abandoned,
                )
            });
            match (result, opening) {
                // 4. Commit, if nobody closed or swept the entry meanwhile.
                (Ok((viewer_handle, staged)), Some((true, false, false))) => {
                    // The open needed a fresh release; the open session
                    // keeps its key to the rights expiry, capped by the
                    // attestations (user 2026-11-13 04:45).
                    let expires_at = operation.session_expires_at();
                    if let Some(entry) = state.entries.get_mut(&session_id) {
                        entry.expires_at = expires_at;
                        entry.state = EntryState::Open(Box::new(OpenSession {
                            viewer_handle,
                            audit: operation.statement().audit_request_id(),
                            staged,
                            served_bytes: 0,
                            reserved_bytes: 0,
                            highest_read: [None, None],
                            in_flight: Vec::new(),
                        }));
                    }
                    (Ok(PoolSessionOpenedV1 { expires_at }), Vec::new())
                }
                // A late result: this call closes what it opened.
                (Ok((viewer_handle, _)), _) => {
                    state.entries.remove(&session_id);
                    (
                        Err(PoolSessionRefusal::UnknownSession),
                        vec![
                            Cleanup::CloseViewer {
                                handle: viewer_handle,
                                audit: operation.statement().audit_request_id(),
                            },
                            Cleanup::Discard(session_id),
                        ],
                    )
                }
                // Roll back to Prepared; the decrypt refusal consumed nothing.
                (Err(refusal), Some((true, false, _))) => {
                    if let Some(entry) = state.entries.get_mut(&session_id) {
                        entry.kid = None;
                        entry.abandoned = false;
                        entry.state = EntryState::Prepared(prepared.clone());
                    }
                    (Err(refusal), vec![Cleanup::Discard(session_id)])
                }
                // Closed or swept meanwhile: this call releases the recipient.
                (Err(refusal), _) => {
                    state.entries.remove(&session_id);
                    (
                        Err(refusal),
                        vec![
                            Cleanup::CancelPrepared {
                                handle: prepared.prepared_handle,
                                audit: prepared.prepare_audit,
                            },
                            Cleanup::Discard(session_id),
                        ],
                    )
                }
            }
        };
        guard.disarm();
        self.run_cleanup(jobs).await;
        outcome
    }

    async fn open_in_flight(
        &self,
        open: &PoolSessionOpenV1,
        prepared: &PreparedSession,
    ) -> Result<(DecryptHandle, PoolStagedContentV1), PoolSessionRefusal> {
        let staged = self
            .content
            .stage(open.session_id, &prepared.content, &prepared.binding)
            .await?;
        if !staged_matches_identity(&staged, &prepared.content.identity) {
            return Err(PoolSessionRefusal::ContentUnavailable);
        }
        let content = viewer_content(&prepared.content.identity, &staged.open)
            .ok_or(PoolSessionRefusal::ContentUnavailable)?;
        // This server's contributions: the ones sealed to its recipient.
        let contributions = open
            .contributions
            .iter()
            .filter(|contribution| {
                contribution
                    .statement()
                    .recipient_sealed_contribution()
                    .recipient()
                    == &prepared.recipient_identity
            })
            .cloned()
            .collect::<Vec<_>>();
        let request = DecryptProviderRequestV1::new_open_pool_viewer_session(
            prepared.prepared_handle,
            &open.operation,
            &open.delivery_public_key,
            prepared.content.content_key_commitment,
            content,
            &contributions,
            &open.terminal_receipt,
        )
        .map_err(|_| PoolSessionRefusal::BindingMismatch)?;
        let response = self
            .decrypt
            .open_viewer_session_v2(&request)
            .await
            .map_err(|_| PoolSessionRefusal::DecryptUnavailable)?;
        if response.status() != DecryptProviderResponseStatusV1::ViewerSessionOpened {
            return Err(decrypt_refusal(&response));
        }
        let viewer_handle = *response
            .viewer_session_handle()
            .map_err(|_| PoolSessionRefusal::DecryptUnavailable)?;
        Ok((viewer_handle, staged))
    }

    // -- read --------------------------------------------------------------

    pub async fn read(
        &self,
        read: PoolSessionReadV1,
        source: &PoolSessionSource,
        now: u64,
    ) -> Result<Vec<u8>, PoolSessionRefusal> {
        if !self.policy.host_trusted() {
            return Err(PoolSessionRefusal::NotEligible);
        }
        let session_id = read.session_id;
        self.sweep_for(session_id, source, now).await?;
        // (1) Lock: this source's open, unexpired session, and the
        // read-ahead window, which counts reads in flight.
        let dash_segment = match read.part {
            ViewerPartIndexV1::DashSegment { rendition, index } => Some((rendition, index)),
            _ => None,
        };
        let (staged, viewer_handle, audit) = {
            let mut state = self.lock();
            let entry = state
                .entries
                .get_mut(&session_id)
                .filter(|entry| entry.owner == source.endpoint_did)
                .ok_or(PoolSessionRefusal::UnknownSession)?;
            if now >= entry.expires_at {
                return Err(PoolSessionRefusal::Expired);
            }
            let read_ahead = u32::from(entry.bounds.read_ahead_segments);
            let EntryState::Open(open) = &mut entry.state else {
                return Err(PoolSessionRefusal::UnknownSession);
            };
            if let Some((rendition, index)) = dash_segment {
                let Some(highest) = open.highest_read.get(usize::from(rendition)) else {
                    return Err(PoolSessionRefusal::ContentUnavailable);
                };
                if index > highest.unwrap_or(0).saturating_add(read_ahead)
                    || open.in_flight.contains(&(rendition, index))
                {
                    tracing::debug!(bound = "read_ahead", "pool session bound");
                    return Err(PoolSessionRefusal::Bound("read_ahead"));
                }
                open.in_flight.push((rendition, index));
            }
            (open.staged.clone(), open.viewer_handle, open.audit)
        };
        let mut guard = ReadGuard {
            state: &self.state,
            session_id,
            in_flight: dash_segment,
            reserved: 0,
            armed: true,
        };

        // (2) The part's material.
        let part = self.content.part(&staged, &read.part).await?;
        if part.index() != read.part {
            return Err(PoolSessionRefusal::ContentUnavailable);
        }
        // (3) Lock: reserve its ciphertext against the byte budgets.
        let bytes = part.ciphertext_bytes();
        {
            let mut state = self.lock();
            let Some(Entry {
                state: EntryState::Open(open),
                bounds,
                ..
            }) = state.entries.get_mut(&session_id)
            else {
                return Err(PoolSessionRefusal::UnknownSession);
            };
            check_byte_budgets(open, bounds, bytes)?;
            open.reserved_bytes += bytes;
            guard.reserved = bytes;
        }

        // (4) The decrypt sealed read.
        let request = sealed_read_request(audit, viewer_handle, &part, session_id)
            .map_err(|_| PoolSessionRefusal::ContentUnavailable)?;
        let response = match &part {
            PoolStagedPartV1::ObjectChunk { .. } => {
                self.decrypt.read_viewer_object_chunk_sealed(&request).await
            }
            _ => self.decrypt.read_viewer_media_part_sealed(&request).await,
        }
        .map_err(|_| PoolSessionRefusal::DecryptUnavailable)?;
        if response.status() != DecryptProviderResponseStatusV1::ViewerSealedPart {
            return Err(decrypt_refusal(&response));
        }
        let sealed = response
            .sealed_part()
            .map_err(|_| PoolSessionRefusal::DecryptUnavailable)?
            .to_vec();

        // (5) Lock: commit, or drop the late bytes.
        let mut state = self.lock();
        let Some(Entry {
            state: EntryState::Open(open),
            ..
        }) = state.entries.get_mut(&session_id)
        else {
            return Err(PoolSessionRefusal::UnknownSession);
        };
        open.reserved_bytes = open.reserved_bytes.saturating_sub(bytes);
        open.served_bytes += bytes;
        if let Some((rendition, index)) = dash_segment {
            open.in_flight.retain(|item| *item != (rendition, index));
            let highest = &mut open.highest_read[usize::from(rendition)];
            *highest = Some(highest.map_or(index, |current| current.max(index)));
        }
        guard.armed = false;
        Ok(sealed)
    }

    // -- close -------------------------------------------------------------

    pub async fn close(
        &self,
        session_id: PoolSessionIdV1,
        source: &PoolSessionSource,
    ) -> Result<(), PoolSessionRefusal> {
        let jobs = {
            let mut state = self.lock();
            let entry = state
                .entries
                .get_mut(&session_id)
                .filter(|entry| entry.owner == source.endpoint_did)
                .ok_or(PoolSessionRefusal::UnknownSession)?;
            match &entry.state {
                // The call in flight finishes the cleanup.
                EntryState::Preparing { .. } | EntryState::Opening(_) => {
                    entry.closing = true;
                    Vec::new()
                }
                EntryState::Cleaning => return Err(PoolSessionRefusal::UnknownSession),
                EntryState::Prepared(_) | EntryState::Open(_) => {
                    let jobs = cleanup_for(session_id, &entry.state);
                    state.entries.remove(&session_id);
                    jobs
                }
            }
        };
        self.run_cleanup(jobs).await;
        Ok(())
    }
}

/// Total served ciphertext stays within `total_bytes_multiplier ×` the staged
/// ciphertext. Committed and reserved bytes both count, over the whole
/// session. A session has no byte-rate bound (user decision 2026-11-12
/// 11:00): it ends at its end or at this budget, and there is no renewal
/// (user 2026-11-13 04:45).
fn check_byte_budgets(
    open: &OpenSession,
    bounds: &SessionBoundsV1,
    bytes: u64,
) -> Result<(), PoolSessionRefusal> {
    let total = u128::from(open.staged.total_ciphertext_bytes);
    let after = u128::from(open.served_bytes) + u128::from(open.reserved_bytes) + u128::from(bytes);
    if after > u128::from(bounds.total_bytes_multiplier) * total {
        tracing::debug!(bound = "total_bytes", "pool session bound");
        return Err(PoolSessionRefusal::Bound("total_bytes"));
    }
    Ok(())
}

fn sealed_read_request(
    audit: RuntimeReleaseAuditIdV1,
    viewer_handle: DecryptHandle,
    part: &PoolStagedPartV1,
    session_id: PoolSessionIdV1,
) -> Result<DecryptProviderRequestV1, elastos_protected_content_contracts::ContractError> {
    let selector = match part {
        PoolStagedPartV1::ObjectChunk {
            index,
            framed_chunk,
        } => {
            return DecryptProviderRequestV1::new_read_viewer_object_chunk_sealed(
                audit,
                viewer_handle,
                *index,
                framed_chunk,
                session_id,
            )
        }
        PoolStagedPartV1::MediaV1Init => ViewerMediaPartSelectorV1::init(),
        PoolStagedPartV1::MediaV1Segment { index, encrypted } => {
            ViewerMediaPartSelectorV1::segment(*index, encrypted.clone())?
        }
        PoolStagedPartV1::DashInit { rendition } => ViewerMediaPartSelectorV1::init_v2(*rendition)?,
        PoolStagedPartV1::DashSegment {
            rendition,
            index,
            encrypted,
            proof,
        } => ViewerMediaPartSelectorV1::segment_v2(
            *rendition,
            *index,
            encrypted.clone(),
            proof.clone(),
        )?,
    };
    DecryptProviderRequestV1::new_read_viewer_media_part_sealed(
        audit,
        viewer_handle,
        selector,
        session_id,
    )
}

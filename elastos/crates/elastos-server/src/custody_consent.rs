//! Custody consent, node side: whether this Home offers custody to its People
//! contacts, the requests pool owners send it, and its admin's decision on
//! each one.
//!
//! Gateway-free: the Custody app and Inbox routes adapt it, and the custody
//! message plane calls [`NodeConsentHandler`], which also hands decisions on
//! this Home's own requests to `custody_owner_requests`. A Home serves at
//! most eight pools (Plan B T2.2, D5), one custody root each. Who a root
//! serves comes only from that root's trusted issuer (`custody_root_trust_at`),
//! never from the offer, the request or the served-pools files. An owner's
//! issuer is derived from the verified signer of its request.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use elastos_common::collaboration_protocol::MAX_COLLABORATION_CLOCK_SKEW_SECS;
use elastos_runtime::provider::ProviderRegistry;
use serde::{Deserialize, Serialize};

use crate::collaboration_config::read_owner_only_file;
use crate::collaboration_custody_messages::{
    CollaborationCustodyMessageService, CustodyInbound, CustodyMessageHandler, CustodyOutboxState,
    CustodyRefusal as WireRefusal, WeakCustodyMessageService,
};
use crate::collaboration_profile_authority::VerifiedCollaborationProfileDocument;
use crate::custody_consent_protocol::{
    pool_active_is_newer, signed_composition_facts, CustodyDeclineCode, CustodyMessageRefusal,
    CustodyNodeDecisionOutcome, CustodyNodeDecisionPayload, CustodyNodeRequestPayload,
    CustodyOfferPayload, CustodyPayload, CustodyPoolActivePayload, CustodyPoolMember,
    CustodyPoolThreshold,
};
use crate::custody_node_card::{encode_node_card, node_provides, served_node_card, Fingerprint};
use crate::custody_owner_requests::RequestOutbox;
use crate::custody_pool_notices::NoticeOutbox;
use crate::custody_pool_setup::{
    custody_root_capacity_reached, holds_custody_state, provision_served_node,
    reserve_custody_root_for_new_pool, served_node_needs_restart, CustodyRefusal,
};
use crate::protected_content_config::{ensure_owner_only_dir, validated_custody_node_label};
use crate::protected_content_runtime::{protected_content_root, write_owner_only_bytes};

const OFFER_FILE: &str = "custody-offer.json";
const OFFER_SCHEMA_V1: &str = "elastos.protected-content.custody-offer/v1";
const MAX_OFFER_FILE_BYTES: usize = 4 * 1024;
const REQUESTS_FILE: &str = "custody-node-requests.json";
const REQUESTS_SCHEMA_V1: &str = "elastos.protected-content.custody-node-requests/v1";
const MAX_REQUESTS: usize = 16;
const MAX_LIVE_REQUESTS_PER_OWNER: usize = 2;
/// Room for every record with a signed decision carrying a card.
const MAX_REQUESTS_FILE_BYTES: usize = 512 * 1024;
/// Decided and expired requests stay this long, then go.
const TERMINAL_RETENTION_SECS: u64 = 7 * 86_400;
const DECISION_OUTBOX_PREFIX: &str = "custody-decision:";
/// The v1 consent file (one served owner). Plan B T2.2 reads it once into the
/// served-pools map and then leaves it on disk, unused (user decision
/// 2026-11-12 10:35: kept for rollback; removed only by a later approved
/// cleanup).
const SERVED_CONSENT_FILE: &str = "custody-served-consent.json";
const SERVED_CONSENT_SCHEMA_V1: &str = "elastos.protected-content.custody-served-consent/v1";
const MAX_SERVED_CONSENT_FILE_BYTES: usize = 1024;
/// Plan B T2.2 (S2-Q2): one entry per served pool, keyed by the pool
/// fingerprint `sha256:<hex>` of its signing key.
pub(crate) const SERVED_POOLS_FILE: &str = "custody-served-pools.json";
const SERVED_POOLS_SCHEMA_V2: &str = "elastos.protected-content.custody-served-pools/v2";
/// Eight entries, each with a member list and a signed pool descriptor (40
/// KiB, base64), and room around them.
const MAX_SERVED_POOLS_FILE_BYTES: usize = 1024 * 1024;
const MIN_DECISION_LIFETIME_SECS: u64 = 60 * 60;
/// The passkey step the Inbox asks for before Approve.
pub(crate) const APPROVE_STEP_UP_OPERATION: &str =
    crate::custody_surface::STEP_UP_NODE_REQUEST_APPROVE;
/// An owner, or all owners together, sent more live requests than a node keeps.
const TOO_MANY_REQUESTS: WireRefusal = WireRefusal::new("too_many_requests");

/// Request records change one writer at a time: the message plane receives
/// while an admin decides.
static REQUESTS_LOCK: Mutex<()> = Mutex::new(());

/// Custody writes run one at a time: the Custody app's, and the Inbox's
/// decisions. Install's stale-record cleanup, the create-only files and
/// approving one owner assume nobody else writes between check and write.
static CUSTODY_WRITE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Proof that the caller holds the custody write lock. Only
/// [`lock_custody_writes`] makes one, so a function that takes it runs
/// serialized with every other custody write.
pub(crate) struct CustodyWriteGuard {
    _held: tokio::sync::MutexGuard<'static, ()>,
}

pub(crate) async fn lock_custody_writes() -> CustodyWriteGuard {
    CustodyWriteGuard {
        _held: CUSTODY_WRITE_LOCK.lock().await,
    }
}

/// What this Home offers, as the admin set it in Hosting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyOfferFileV1 {
    schema: String,
    enabled: bool,
    run_by: String,
    location: String,
    provides: Vec<String>,
}

/// The Hosting switch: the offer, or what it would say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct OfferView {
    pub(crate) enabled: bool,
    pub(crate) run_by: String,
    pub(crate) location: String,
    pub(crate) provides: Vec<String>,
    /// This Home holds a custody state. Plan B T2.2: a fact only; the offer
    /// stays on below eight roots.
    pub(crate) holds_custody_state: bool,
    /// The admin's Profile can sign custody messages.
    pub(crate) messages_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RequestState {
    Pending,
    /// Approve began; a crash leaves it here, and approving again finishes it.
    Approving,
    Approved,
    Declined,
    Expired,
}

impl RequestState {
    fn is_live(self) -> bool {
        matches!(self, Self::Pending | Self::Approving)
    }
}

/// One owner's request, as this Home received and decided it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeRequestRecordV1 {
    request_id: String,
    /// `sha256:` of the exact request envelope.
    request_sha256: String,
    /// The verified signer: the owner's Home DID, which is its pool issuer.
    owner_home: String,
    owner_profile_did: String,
    /// The owner's signed Profile name, as this Home's contact holds it.
    owner_name: String,
    /// The Profile the request was addressed to; only its admin decides.
    local_profile_did: String,
    term_days: u16,
    signing_key_fingerprint_full: String,
    /// This Home's labels from its offer when the request came; approving
    /// provisions with exactly these.
    run_by: String,
    location: String,
    received_at: u64,
    expires_at: u64,
    state: RequestState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decided_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<CustodyDeclineCode>,
    /// The signed decision, standard base64, kept until it expires so a
    /// restart sends it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decision: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeRequestsFileV1 {
    schema: String,
    requests: Vec<NodeRequestRecordV1>,
}

/// An owner's request as the Inbox card shows it. It is also, field for
/// field, the request the admin's passkey approves, rebuilt from this Home's
/// own record and never taken from the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct NodeRequestView {
    pub(crate) request_id: String,
    pub(crate) request_sha256: String,
    pub(crate) owner_name: String,
    pub(crate) owner_home: String,
    pub(crate) term_days: u16,
    pub(crate) run_by: String,
    pub(crate) location: String,
    pub(crate) expires_at: u64,
}

impl NodeRequestView {
    fn of(record: &NodeRequestRecordV1) -> Self {
        Self {
            request_id: record.request_id.clone(),
            request_sha256: record.request_sha256.clone(),
            owner_name: record.owner_name.clone(),
            owner_home: record.owner_home.clone(),
            term_days: record.term_days,
            run_by: record.run_by.clone(),
            location: record.location.clone(),
            expires_at: record.expires_at,
        }
    }

    pub(crate) fn step_up_request(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("a custody request view serializes")
    }
}

/// A request waiting for the admin, for the Inbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InboxNodeRequest {
    pub(crate) request: NodeRequestView,
    pub(crate) received_at: u64,
    pub(crate) stage: crate::notifications::CustodyRequestStage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ApprovedRequest {
    pub(crate) owner_name: String,
    /// The node serves its owner only after this Home restarts: its custody
    /// provider did not start, or its Chain plane does not trust the owner yet.
    pub(crate) needs_restart: bool,
}

/// Signs and queues this Home's decisions. The message service is the real
/// one; it is a seam so the rules here are tested without Carrier.
pub(crate) trait DecisionOutbox: Send + Sync {
    fn sign(
        &self,
        local_profile_did: &str,
        owner_profile_did: &str,
        decision: CustodyNodeDecisionPayload,
        now: u64,
        expires_at: u64,
    ) -> anyhow::Result<Vec<u8>>;

    fn enqueue(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<()>;

    /// `None` when the outbox does not know the key, as after a restart.
    fn state(&self, key: &str, now: u64) -> Option<CustodyOutboxState>;
}

impl DecisionOutbox for CollaborationCustodyMessageService {
    fn sign(
        &self,
        local_profile_did: &str,
        owner_profile_did: &str,
        decision: CustodyNodeDecisionPayload,
        now: u64,
        expires_at: u64,
    ) -> anyhow::Result<Vec<u8>> {
        self.prepare(
            local_profile_did,
            owner_profile_did,
            &CustodyPayload::NodeDecision(decision),
            now,
            expires_at,
        )
    }

    fn enqueue(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<()> {
        CollaborationCustodyMessageService::enqueue(self, key, local_profile_did, envelope, now)
    }

    fn state(&self, key: &str, now: u64) -> Option<CustodyOutboxState> {
        self.outbox_state(key, now)
    }
}

impl DecisionOutbox for WeakCustodyMessageService {
    fn sign(
        &self,
        local_profile_did: &str,
        owner_profile_did: &str,
        decision: CustodyNodeDecisionPayload,
        now: u64,
        expires_at: u64,
    ) -> anyhow::Result<Vec<u8>> {
        DecisionOutbox::sign(
            &live_service(self)?,
            local_profile_did,
            owner_profile_did,
            decision,
            now,
            expires_at,
        )
    }

    fn enqueue(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<()> {
        DecisionOutbox::enqueue(&live_service(self)?, key, local_profile_did, envelope, now)
    }

    fn state(&self, key: &str, now: u64) -> Option<CustodyOutboxState> {
        self.upgrade()?.outbox_state(key, now)
    }
}

fn live_service(
    weak: &WeakCustodyMessageService,
) -> anyhow::Result<CollaborationCustodyMessageService> {
    weak.upgrade()
        .ok_or_else(|| anyhow::anyhow!("custody messages have stopped"))
}

/// What approving needs from the running Home.
pub(crate) struct NodeHost<'a> {
    pub(crate) data_dir: &'a Path,
    pub(crate) registry: Option<&'a Arc<ProviderRegistry>>,
    pub(crate) outbox: &'a dyn DecisionOutbox,
    /// This Home's Carrier connect ticket, which its node card carries.
    pub(crate) ticket: Option<String>,
}

/// This Home's Carrier connect ticket, read when a card is built.
pub(crate) type NodeTicket = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// This Home's custody consent on the message plane: the node side, and the
/// decisions that answer the requests it sent as a pool owner.
pub(crate) struct NodeConsentHandler {
    outbox: Arc<dyn DecisionOutbox>,
    ticket: NodeTicket,
    /// The owner side's sent requests, queued again on each delivery pass.
    owner_requests: Option<(PathBuf, Arc<dyn RequestOutbox>)>,
    /// The owner side's pool notices, built again on each delivery pass.
    pool_notices: Option<(PathBuf, Arc<dyn NoticeOutbox>)>,
    /// This Home's own decisions, queued again on each delivery pass.
    decisions_dir: Option<PathBuf>,
}

impl NodeConsentHandler {
    pub(crate) fn new(outbox: Arc<dyn DecisionOutbox>, ticket: NodeTicket) -> Self {
        Self {
            outbox,
            ticket,
            owner_requests: None,
            pool_notices: None,
            decisions_dir: None,
        }
    }

    /// Keeps this Home's decisions in its outbox across restarts.
    pub(crate) fn resuming_decisions(mut self, data_dir: PathBuf) -> Self {
        self.decisions_dir = Some(data_dir);
        self
    }

    /// Keeps this Home's sent requests in its outbox across restarts.
    pub(crate) fn with_owner_requests(
        mut self,
        data_dir: PathBuf,
        outbox: Arc<dyn RequestOutbox>,
    ) -> Self {
        self.owner_requests = Some((data_dir, outbox));
        self
    }

    /// Tells the installed pool's members until each has heard.
    pub(crate) fn with_pool_notices(
        mut self,
        data_dir: PathBuf,
        outbox: Arc<dyn NoticeOutbox>,
    ) -> Self {
        self.pool_notices = Some((data_dir, outbox));
        self
    }
}

impl CustodyMessageHandler for NodeConsentHandler {
    fn on_offer_query(
        &self,
        inbound: &CustodyInbound<'_>,
    ) -> Result<CustodyOfferPayload, WireRefusal> {
        offer_for_contact(inbound.data_dir, inbound.principal_id)
    }

    fn on_request(
        &self,
        inbound: &CustodyInbound<'_>,
        request: &CustodyNodeRequestPayload,
    ) -> Result<(), WireRefusal> {
        receive_request(inbound, request, self.outbox.as_ref(), (self.ticket)())
    }

    fn on_decision(
        &self,
        inbound: &CustodyInbound<'_>,
        decision: &CustodyNodeDecisionPayload,
    ) -> Result<(), WireRefusal> {
        crate::custody_owner_requests::on_decision(inbound, decision)
    }

    fn on_pool_active(
        &self,
        inbound: &CustodyInbound<'_>,
        notice: &CustodyPoolActivePayload,
    ) -> Result<(), WireRefusal> {
        receive_pool_active(inbound, notice)
    }

    fn on_pool_descriptor(
        &self,
        inbound: &CustodyInbound<'_>,
        descriptor: &crate::custody_consent_protocol::CustodyPoolDescriptorPayload,
    ) -> Result<(), WireRefusal> {
        receive_pool_descriptor(inbound, descriptor)
    }

    fn before_delivery_pass(&self, now: u64) {
        if let Some(data_dir) = &self.decisions_dir {
            if let Err(error) = resume_decisions(data_dir, self.outbox.as_ref(), now) {
                tracing::warn!(
                    error = %format!("{error:#}"),
                    "custody decisions were not queued again"
                );
            }
        }
        if let Some((data_dir, outbox)) = &self.owner_requests {
            if let Err(error) =
                crate::custody_owner_requests::resume_requests(data_dir, outbox.as_ref(), now)
            {
                tracing::warn!(
                    error = %format!("{error:#}"),
                    "custody node requests were not queued again"
                );
            }
        }
        if let Some((data_dir, outbox)) = &self.pool_notices {
            if let Err(error) =
                crate::custody_pool_notices::resume_notices(data_dir, outbox.as_ref(), now)
            {
                tracing::warn!(
                    error = %format!("{error:#}"),
                    "custody pool notices were not queued again"
                );
            }
        }
    }
}

fn offer_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(OFFER_FILE)
}

fn requests_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(REQUESTS_FILE)
}

/// The Hosting switch for the admin whose Profile is `profile`. Without a
/// stored offer it shows what one would say: Run by is the Profile name.
pub(crate) fn read_offer(
    data_dir: &Path,
    profile: Option<&VerifiedCollaborationProfileDocument>,
) -> anyhow::Result<OfferView> {
    let stored = load_offer(data_dir)?;
    let (enabled, run_by, location, provides) = match stored {
        Some(offer) => (offer.enabled, offer.run_by, offer.location, offer.provides),
        None => (
            false,
            profile
                .map(|profile| profile.document().display_name.clone())
                .unwrap_or_default(),
            String::new(),
            node_provides(data_dir),
        ),
    };
    Ok(OfferView {
        enabled,
        run_by,
        location,
        provides,
        holds_custody_state: holds_custody_state(data_dir)?,
        messages_enabled: profile.is_some_and(custody_messages_enabled),
    })
}

/// Turn the offer on or off. Plan B T2.2: a Home that serves pools may keep
/// offering; at eight roots it answers nobody's query.
pub(crate) fn set_offer(
    _write: &CustodyWriteGuard,
    data_dir: &Path,
    profile: Option<&VerifiedCollaborationProfileDocument>,
    enabled: bool,
    run_by: &str,
    location: &str,
) -> anyhow::Result<OfferView> {
    let run_by = validated_custody_node_label(run_by, "operator")
        .map_err(|_| CustodyRefusal::new("bad_labels"))?;
    let location = validated_custody_node_label(location, "failure domain")
        .map_err(|_| CustodyRefusal::new("bad_labels"))?;
    // A removal's tombstone holds no custody state; this only frees its space.
    if let Err(error) = crate::custody_pool_setup::finish_local_node_removal(_write, data_dir) {
        tracing::warn!(error = %format!("{error:#}"), "a removed custody root is still on disk");
    }
    // #388 A1: only a WCI-operated host offers custody; turning it off
    // stays possible. Plan B T2.2 (approved removal): a Home that holds
    // custody state may offer too.
    if enabled && !crate::host_trust::host_trusted(data_dir) {
        return Err(CustodyRefusal::new(crate::host_trust::HOST_TRUST_REQUIRED).into());
    }
    let offer = CustodyOfferFileV1 {
        schema: OFFER_SCHEMA_V1.to_string(),
        enabled,
        run_by,
        location,
        provides: node_provides(data_dir),
    };
    ensure_owner_only_dir(&protected_content_root(data_dir), "protected-content root")?;
    write_owner_only_bytes(&offer_path(data_dir), &serde_json::to_vec(&offer)?)?;
    tracing::debug!(enabled, "custody offer saved");
    read_offer(data_dir, profile)
}

fn load_offer(data_dir: &Path) -> anyhow::Result<Option<CustodyOfferFileV1>> {
    let path = offer_path(data_dir);
    if !present(&path)? {
        return Ok(None);
    }
    let bytes = read_owner_only_file(&path, MAX_OFFER_FILE_BYTES, "custody offer")?;
    let offer: CustodyOfferFileV1 = serde_json::from_slice(&bytes)?;
    if offer.schema != OFFER_SCHEMA_V1 {
        anyhow::bail!("custody offer has an unknown schema");
    }
    Ok(Some(offer))
}

/// The Profile's endpoint can sign every custody message of the current
/// scope. A Profile enabled before a type was added (the pool descriptor,
/// Plan B T3.3, L13c) reads as not enabled, so the Custody app asks its admin
/// once more.
pub(crate) fn custody_messages_enabled(profile: &VerifiedCollaborationProfileDocument) -> bool {
    let (service, object_types) = crate::custody_consent_protocol::CUSTODY_SIGNING_SCOPE;
    profile.sole_endpoint_did().is_ok_and(|endpoint| {
        object_types
            .iter()
            .all(|object_type| profile.authorizes_signer(endpoint, service, object_type))
    })
}

fn principal_is_admin(data_dir: &Path, principal_id: &str) -> anyhow::Result<bool> {
    Ok(crate::auth::active_passkey_principals(data_dir)?
        .iter()
        .any(|principal| {
            principal.principal_id == principal_id && crate::auth::is_admin(principal)
        }))
}

fn unavailable(error: anyhow::Error) -> WireRefusal {
    tracing::debug!(error = %format!("{error:#}"), "custody consent state is unavailable");
    WireRefusal::UNAVAILABLE
}

fn require_admin_recipient(data_dir: &Path, principal_id: &str) -> Result<(), WireRefusal> {
    if principal_is_admin(data_dir, principal_id).map_err(unavailable)? {
        Ok(())
    } else {
        Err(CustodyDeclineCode::NotAdmin.into())
    }
}

/// The offer a contact's query is answered with, while this Home offers and
/// holds fewer than eight custody roots.
fn offer_for_contact(
    data_dir: &Path,
    principal_id: &str,
) -> Result<CustodyOfferPayload, WireRefusal> {
    require_admin_recipient(data_dir, principal_id)?;
    // #388 A1: an everyday host offers nothing, whatever its stored offer.
    if !crate::protected_content_runtime::protected_content_enabled(data_dir)
        || !crate::host_trust::host_trusted(data_dir)
    {
        return Err(WireRefusal::NOT_OFFERING);
    }
    let offer = load_offer(data_dir).map_err(unavailable)?;
    match offer {
        Some(offer)
            if offer.enabled
                && !custody_root_capacity_reached(data_dir, &[]).map_err(unavailable)? =>
        {
            Ok(CustodyOfferPayload {
                location: offer.location,
                provides: offer.provides,
                run_by: offer.run_by,
            })
        }
        _ => Err(WireRefusal::NOT_OFFERING),
    }
}

fn receive_request(
    inbound: &CustodyInbound<'_>,
    request: &CustodyNodeRequestPayload,
    outbox: &dyn DecisionOutbox,
    ticket: Option<String>,
) -> Result<(), WireRefusal> {
    let data_dir = inbound.data_dir;
    require_admin_recipient(data_dir, inbound.principal_id)?;
    // A Home with protected content off takes no custody work, and neither
    // does an everyday host (#388 A1).
    if !crate::protected_content_runtime::protected_content_enabled(data_dir)
        || !crate::host_trust::host_trusted(data_dir)
    {
        return Err(WireRefusal::NOT_OFFERING);
    }
    let owner_home = inbound.message.signer_did();
    let now = inbound.now;
    let mut queued = Vec::new();
    let outcome = with_requests(data_dir, now, |records| {
        if let Some(existing) = records
            .iter()
            .find(|record| record.request_id == request.request_id)
        {
            // A request id is its owner's own, to one Profile; a repeat is
            // the same request to the same Profile.
            if existing.owner_home != owner_home
                || existing.local_profile_did != inbound.local_profile.document().profile_did
            {
                return Ok(Err(WireRefusal::REFUSED));
            }
            queued.extend(queued_decision(existing));
            return Ok(Ok(()));
        }
        let mut record = NodeRequestRecordV1 {
            request_id: request.request_id.clone(),
            request_sha256: inbound.message.envelope_sha256().to_string(),
            owner_home: owner_home.to_string(),
            owner_profile_did: inbound.message.sender_profile_did().to_string(),
            owner_name: inbound.sender_display_name.to_string(),
            local_profile_did: inbound.local_profile.document().profile_did.clone(),
            term_days: request.term_days,
            signing_key_fingerprint_full: request.signing_key_fingerprint_full.clone(),
            run_by: String::new(),
            location: String::new(),
            received_at: now,
            expires_at: inbound.message.expires_at(),
            state: RequestState::Pending,
            decided_at: None,
            code: None,
            decision: None,
        };
        // Checked under the lock, so a request that races an approval sees
        // the custody state it made. Plan B T2.2: the pool is the request's
        // pool fingerprint; another owner never declines it.
        let pools = served_pools(data_dir)?;
        let served_root = request_pool_root(data_dir, &pools, &record)?
            .filter(|root| matches!(custody_root_trust_at(data_dir, root), Ok(RootTrust::Trusts(owner)) if owner == owner_home));
        let serves_owner = served_root.is_some()
            || custody_root_trusts(data_dir)?
                .iter()
                .any(|(_, trust)| matches!(trust, RootTrust::Trusts(owner) if owner == owner_home));
        if let Some(root) = served_root {
            if let Some(card) = served_card(data_dir, &root, ticket.as_deref())? {
                let node = crate::custody_node_card::parse_node_card(&card)
                    .map_err(|refusal| anyhow::anyhow!("own card refused: {}", refusal.code()))?
                    .descriptor;
                record.run_by = node.operator;
                record.location = node.failure_domain;
                // The owner this Home already serves for this pool asks
                // again: its earlier consent stands for the term it
                // approved, so that gets the card again. Another term
                // waits for the admin.
                let consented = pools
                    .consent(owner_home, &request.signing_key_fingerprint_full)
                    .is_some_and(|consent| consent.term_days == request.term_days);
                if consented {
                    decide(
                        &mut record,
                        outbox,
                        Decision::Approved(card),
                        now,
                        &mut queued,
                    )?;
                    return Ok(insert_record(records, record));
                }
                let stored = insert_record(records, record);
                if stored.is_ok() {
                    tracing::debug!("the served owner asks for a new term; the admin decides");
                }
                return Ok(stored);
            }
        }
        // A new pool needs a new root: at eight roots, `too_many_pools`.
        if custody_root_capacity_reached(data_dir, &reserved_roots(&served_pools(data_dir)?))? {
            return Ok(Err(CustodyDeclineCode::TooManyPools.into()));
        }
        // An owner this Home serves already (another pool key) is heard
        // without the offer; anyone else needs it.
        match load_offer(data_dir)?.filter(|offer| offer.enabled) {
            Some(offer) => {
                record.run_by = offer.run_by;
                record.location = offer.location;
            }
            None if serves_owner => {
                let Some(node) = custody_root_trusts(data_dir)?
                    .into_iter()
                    .find(|(_, trust)| matches!(trust, RootTrust::Trusts(owner) if owner == owner_home))
                    .and_then(|(root, _)| served_node_card(data_dir, &root).ok().flatten())
                else {
                    return Ok(Err(WireRefusal::NOT_OFFERING));
                };
                let node = crate::protected_content_config::validated_custody_node_descriptor(
                    &node.node_bytes,
                    "this Home's custody node",
                )?;
                record.run_by = node.operator;
                record.location = node.failure_domain;
            }
            None => return Ok(Err(WireRefusal::NOT_OFFERING)),
        }
        let stored = insert_record(records, record);
        if stored.is_ok() {
            tracing::debug!("custody node request stored for the admin");
        }
        Ok(stored)
    })
    .map_err(unavailable)?;
    outcome?;
    send_queued(outbox, queued, now);
    Ok(())
}

/// Adds a request within the bounds: room is made from decided or expired
/// requests, never from live ones.
fn insert_record(
    records: &mut Vec<NodeRequestRecordV1>,
    record: NodeRequestRecordV1,
) -> Result<(), WireRefusal> {
    if record.state.is_live() {
        let live_for_owner = records
            .iter()
            .filter(|existing| existing.state.is_live() && existing.owner_home == record.owner_home)
            .count();
        if live_for_owner >= MAX_LIVE_REQUESTS_PER_OWNER {
            return Err(TOO_MANY_REQUESTS);
        }
    }
    if records.len() >= MAX_REQUESTS {
        let oldest_settled = records
            .iter()
            .enumerate()
            .filter(|(_, existing)| !existing.state.is_live())
            .min_by_key(|(_, existing)| settled_at(existing))
            .map(|(index, _)| index);
        match oldest_settled {
            Some(index) => {
                records.remove(index);
            }
            None => return Err(TOO_MANY_REQUESTS),
        }
    }
    records.push(record);
    Ok(())
}

fn settled_at(record: &NodeRequestRecordV1) -> u64 {
    record
        .decided_at
        .unwrap_or(record.expires_at)
        .max(record.received_at)
}

enum Decision {
    Approved(String),
    Declined(CustodyDeclineCode),
}

/// Signs a decision on a request and records it; the caller persists, then
/// queues it.
fn decide(
    record: &mut NodeRequestRecordV1,
    outbox: &dyn DecisionOutbox,
    decision: Decision,
    now: u64,
    queued: &mut Vec<QueuedDecision>,
) -> anyhow::Result<()> {
    let (outcome, card, code, state) = match decision {
        Decision::Approved(card) => (
            CustodyNodeDecisionOutcome::Approved,
            Some(card),
            None,
            RequestState::Approved,
        ),
        Decision::Declined(code) => (
            CustodyNodeDecisionOutcome::Declined,
            None,
            Some(code),
            RequestState::Declined,
        ),
    };
    let envelope = outbox.sign(
        &record.local_profile_did,
        &record.owner_profile_did,
        CustodyNodeDecisionPayload {
            card,
            code,
            outcome,
            request_id: record.request_id.clone(),
            request_sha256: record.request_sha256.clone(),
        },
        now,
        decision_expires_at(record, now),
    )?;
    record.state = state;
    record.code = code;
    record.decided_at = Some(now);
    record.decision = Some(base64::engine::general_purpose::STANDARD.encode(&envelope));
    queued.push(QueuedDecision {
        key: format!("{DECISION_OUTBOX_PREFIX}{}", record.request_id),
        local_profile_did: record.local_profile_did.clone(),
        envelope,
    });
    Ok(())
}

/// A decision lives as long as its request, and at least long enough to
/// reach the owner when it settles a request that was approving past its end.
fn decision_expires_at(record: &NodeRequestRecordV1, decided_at: u64) -> u64 {
    record
        .expires_at
        .max(decided_at.saturating_add(MIN_DECISION_LIFETIME_SECS))
}

struct QueuedDecision {
    key: String,
    local_profile_did: String,
    envelope: Vec<u8>,
}

fn queued_decision(record: &NodeRequestRecordV1) -> Option<QueuedDecision> {
    let envelope = base64::engine::general_purpose::STANDARD
        .decode(record.decision.as_deref()?)
        .inspect_err(|error| tracing::warn!(%error, "a stored custody decision is unreadable"))
        .ok()?;
    Some(QueuedDecision {
        key: format!("{DECISION_OUTBOX_PREFIX}{}", record.request_id),
        local_profile_did: record.local_profile_did.clone(),
        envelope,
    })
}

/// Queues persisted decisions. A failure here loses nothing: the decision is
/// on disk and the next start, or the owner asking again, queues it again.
fn send_queued(outbox: &dyn DecisionOutbox, queued: Vec<QueuedDecision>, now: u64) {
    for decision in queued {
        if let Err(error) = outbox.enqueue(
            &decision.key,
            &decision.local_profile_did,
            decision.envelope,
            now,
        ) {
            tracing::warn!(
                error = %format!("{error:#}"),
                "a custody decision was not queued; it is sent again on the next start"
            );
        }
    }
}

/// The card of the node at custody root `root_path`, with the ticket its
/// Carrier node answers at, once that root serves an owner.
fn served_card(
    data_dir: &Path,
    root_path: &str,
    ticket: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let Some(card) = served_node_card(data_dir, root_path)? else {
        return Ok(None);
    };
    let ticket = ticket.ok_or_else(|| CustodyRefusal::new("no_address"))?;
    encode_node_card(
        &card.node_bytes,
        ticket,
        &card.provides,
        card.ipfs_peer_id.as_deref(),
    )
    .map(Some)
    .map_err(|refusal| {
        CustodyRefusal::with_detail("card_refused", refusal.code().to_string()).into()
    })
}

/// The requests addressed to `local_profile_did` that wait for its admin.
pub(crate) fn inbox_requests(
    data_dir: &Path,
    local_profile_did: &str,
    now: u64,
) -> anyhow::Result<Vec<InboxNodeRequest>> {
    let mut records = load_requests(data_dir)?;
    expire(&mut records, now);
    let mut waiting: Vec<InboxNodeRequest> = records
        .iter()
        .filter(|record| record.state.is_live() && record.local_profile_did == local_profile_did)
        .map(|record| {
            Ok(InboxNodeRequest {
                request: NodeRequestView::of(record),
                received_at: record.received_at,
                stage: inbox_stage(data_dir, record),
            })
        })
        .collect::<anyhow::Result<_>>()?;
    waiting.sort_by(|left, right| {
        (left.received_at, &left.request.request_id)
            .cmp(&(right.received_at, &right.request.request_id))
    });
    Ok(waiting)
}

/// The request the admin's passkey approves, rebuilt from this Home's record.
pub(crate) fn approval_request(
    data_dir: &Path,
    local_profile_did: &str,
    request_id: &str,
    now: u64,
) -> anyhow::Result<NodeRequestView> {
    let mut records = load_requests(data_dir)?;
    expire(&mut records, now);
    let record = find(&records, local_profile_did, request_id)?;
    match record.state {
        state if state.is_live() => Ok(NodeRequestView::of(record)),
        RequestState::Expired => Err(CustodyRefusal::new("expired").into()),
        _ => Err(CustodyRefusal::new("not_pending").into()),
    }
}

fn find<'a>(
    records: &'a [NodeRequestRecordV1],
    local_profile_did: &str,
    request_id: &str,
) -> Result<&'a NodeRequestRecordV1, CustodyRefusal> {
    records
        .iter()
        .find(|record| {
            record.request_id == request_id && record.local_profile_did == local_profile_did
        })
        .ok_or_else(|| CustodyRefusal::new("unknown_request"))
}

fn find_mut<'a>(
    records: &'a mut [NodeRequestRecordV1],
    local_profile_did: &str,
    request_id: &str,
) -> Result<&'a mut NodeRequestRecordV1, CustodyRefusal> {
    records
        .iter_mut()
        .find(|record| {
            record.request_id == request_id && record.local_profile_did == local_profile_did
        })
        .ok_or_else(|| CustodyRefusal::new("unknown_request"))
}

enum ApproveStep {
    /// Provisioning runs next, outside the request lock.
    Provision(NodeRequestRecordV1, String),
    /// Answered with the node this Home already serves this pool with;
    /// `fresh` when this call approved it.
    Served {
        record: NodeRequestRecordV1,
        root: String,
        fresh: bool,
    },
    /// The pool's root serves another owner (the same pool key).
    TakenByAnother,
    /// This Home holds eight roots (Plan B T2.2, S2-U1).
    TooManyPools,
}

/// The v1 consent (one served owner): what its admin last approved, the term
/// and the pool signing key. Plan B T2.2 reads it once into the served-pools
/// map; the file stays on disk, unused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServedConsentFileV1 {
    schema: String,
    owner_home: String,
    term_days: u16,
    signing_key_fingerprint_full: String,
}

fn served_consent_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(SERVED_CONSENT_FILE)
}

fn load_v1_consent(data_dir: &Path) -> anyhow::Result<Option<ServedConsentFileV1>> {
    let path = served_consent_path(data_dir);
    if !present(&path)? {
        return Ok(None);
    }
    let bytes = read_owner_only_file(
        &path,
        MAX_SERVED_CONSENT_FILE_BYTES,
        "custody served consent",
    )?;
    let file: ServedConsentFileV1 = serde_json::from_slice(&bytes)?;
    if file.schema != SERVED_CONSENT_SCHEMA_V1 {
        anyhow::bail!("custody served consent has an unknown schema");
    }
    Ok(Some(file))
}

/// What this Home's admin approved for one served pool: the term. The pool
/// signing key is the entry's key. A repeat request for both is answered
/// without asking again; a pool that owner signs for this entry must be
/// signed by this key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServedConsentV2 {
    pub(crate) term_days: u16,
    pub(crate) signing_key_fingerprint_full: String,
}

/// The pool a served node is in, as its owner told it: the facts, never the
/// composition, which stays with the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServedPoolV2 {
    pub(crate) fingerprint_full: String,
    pub(crate) pool_start: u64,
    pub(crate) term_end: u64,
    pub(crate) share: u8,
    pub(crate) threshold: CustodyPoolThreshold,
    pub(crate) members: Vec<CustodyPoolMember>,
    pub(crate) received_at: u64,
}

/// One served pool (Plan B T2.2, §3b `ServedPoolEntryV2`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServedPoolEntryV2 {
    pub(crate) owner_home: String,
    pub(crate) consent: ServedConsentV2,
    /// `inactive` or `pools/<hex>`.
    pub(crate) root_path: String,
    /// The admin profile that approved serving (S7-U3); T7.5 publishes sealed
    /// packages under it. None for an entry read from the v1 files until an
    /// admin confirms it in Hosting (user decision 2026-11-12 10:35): no
    /// sealed publishing until then.
    #[serde(default)]
    pub(crate) admin_profile_did: Option<String>,
    /// The pool's DID text, once its owner's descriptor arrived.
    #[serde(default)]
    pub(crate) pool_did: Option<String>,
    #[serde(default)]
    pub(crate) served_pool: Option<ServedPoolV2>,
    /// The owner's signed pool descriptor, canonical bytes in standard base64.
    #[serde(default)]
    pub(crate) descriptor: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServedPoolsFileV2 {
    schema: String,
    entries: BTreeMap<String, ServedPoolEntryV2>,
    /// The v1 served pools with no matching consent, by pool fingerprint:
    /// left untouched on disk, and Hosting shows "needs attention".
    #[serde(default)]
    v1_needs_attention: Vec<String>,
    /// The admin profile that included this Home's own root (S7-U3, S2-A3);
    /// `None` until an admin confirms it.
    #[serde(default)]
    own_root_admin_profile_did: Option<String>,
    /// See `ServedPools::replica_grant_owners`. Left out while empty, so an
    /// older build still reads the file.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    replica_grant_owners: std::collections::BTreeSet<String>,
}

/// Every served pool, keyed by its pool fingerprint `sha256:<hex>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ServedPools {
    pub(crate) entries: BTreeMap<String, ServedPoolEntryV2>,
    /// See `ServedPoolsFileV2::v1_needs_attention`.
    pub(crate) v1_needs_attention: Vec<String>,
    /// See `ServedPoolsFileV2::own_root_admin_profile_did`.
    pub(crate) own_root_admin_profile_did: Option<String>,
    /// OPEN-LOOP F1: the served owners whose `content.replica` grant a pool
    /// approval added. The owner's last stopped root withdraws only these; a
    /// grant the owner held before any pool stays its own.
    pub(crate) replica_grant_owners: std::collections::BTreeSet<String>,
}

impl ServedPools {
    /// The consent kept for `owner_home`'s pool `fingerprint_full`.
    pub(crate) fn consent(
        &self,
        owner_home: &str,
        fingerprint_full: &str,
    ) -> Option<&ServedConsentV2> {
        self.entries
            .get(fingerprint_full)
            .filter(|entry| entry.owner_home == owner_home)
            .map(|entry| &entry.consent)
    }
}

fn served_pools_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(SERVED_POOLS_FILE)
}

/// The served pools (Plan B T2.2). Reads without a guard. Without the v2 file
/// the v1 files are read as one entry (pool #1, root `inactive`); after the
/// first v2 write they are no longer read, and they stay on disk.
pub(crate) fn served_pools(data_dir: &Path) -> anyhow::Result<ServedPools> {
    let path = served_pools_path(data_dir);
    if !present(&path)? {
        return served_pools_from_v1(data_dir);
    }
    let bytes = read_owner_only_file(&path, MAX_SERVED_POOLS_FILE_BYTES, "custody served pools")?;
    let file: ServedPoolsFileV2 = serde_json::from_slice(&bytes)?;
    if file.schema != SERVED_POOLS_SCHEMA_V2
        || file.entries.len() > crate::custody_release_limits::CUSTODY_NODE_SETTINGS.max_pools
        || file
            .entries
            .values()
            .any(|entry| !custody_provider::is_custody_root_path(&entry.root_path))
    {
        anyhow::bail!("custody served pools are not a known record");
    }
    Ok(ServedPools {
        entries: file.entries,
        v1_needs_attention: file.v1_needs_attention,
        own_root_admin_profile_did: file.own_root_admin_profile_did,
        replica_grant_owners: file.replica_grant_owners,
    })
}

/// The v1 consent and served pool as one entry keyed by the consent's pool
/// fingerprint, root `inactive`, no admin profile. A v1 served pool whose
/// owner has no consent is skipped and logged; the file stays untouched.
fn served_pools_from_v1(data_dir: &Path) -> anyhow::Result<ServedPools> {
    let mut pools = ServedPools::default();
    let consent = load_v1_consent(data_dir)?;
    let pool = load_v1_served_pool(data_dir)?;
    let Some(consent) = consent else {
        if let Some(pool) = pool {
            tracing::warn!(
                "a served pool from before this build has no consent; it needs attention"
            );
            pools.v1_needs_attention.push(pool.fingerprint_full);
        }
        return Ok(pools);
    };
    let served_pool = match pool {
        Some(pool) if pool.owner_home == consent.owner_home => Some(pool.into_v2()),
        Some(pool) => {
            tracing::warn!(
                "a served pool from before this build names another owner; it needs attention"
            );
            pools.v1_needs_attention.push(pool.fingerprint_full);
            None
        }
        None => None,
    };
    let descriptor = crate::custody_pool_descriptor::v1_served_descriptor_bytes(data_dir)?
        .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes));
    pools.entries.insert(
        consent.signing_key_fingerprint_full.clone(),
        ServedPoolEntryV2 {
            owner_home: consent.owner_home,
            consent: ServedConsentV2 {
                term_days: consent.term_days,
                signing_key_fingerprint_full: consent.signing_key_fingerprint_full,
            },
            root_path: custody_provider::CUSTODY_INACTIVE_ROOT_PATH.to_string(),
            admin_profile_did: None,
            pool_did: None,
            served_pool,
            descriptor,
        },
    );
    Ok(pools)
}

/// One read-change-write of the served pools, under the served-pool lock.
/// The file is written as v2 only when something changed.
pub(crate) fn update_served_pools<T>(
    data_dir: &Path,
    change: impl FnOnce(&mut ServedPools) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let _guard = SERVED_POOL_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("served pool lock is poisoned"))?;
    let loaded = served_pools(data_dir)?;
    let mut pools = loaded.clone();
    let result = change(&mut pools)?;
    if pools != loaded {
        store_served_pools(data_dir, &pools)?;
    }
    Ok(result)
}

fn store_served_pools(data_dir: &Path, pools: &ServedPools) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(&ServedPoolsFileV2 {
        schema: SERVED_POOLS_SCHEMA_V2.to_string(),
        entries: pools.entries.clone(),
        v1_needs_attention: pools.v1_needs_attention.clone(),
        own_root_admin_profile_did: pools.own_root_admin_profile_did.clone(),
        replica_grant_owners: pools.replica_grant_owners.clone(),
    })?;
    if bytes.len() > MAX_SERVED_POOLS_FILE_BYTES {
        anyhow::bail!("custody served pools exceed their byte limit");
    }
    ensure_owner_only_dir(&protected_content_root(data_dir), "protected-content root")?;
    // A crash before the rename re-reads v1; after it, v2 wins.
    crate::auth::atomic_write(&served_pools_path(data_dir), &bytes)
}

/// The consent kept for `owner_home`'s pool `fingerprint_full`.
#[cfg(test)]
fn served_consent(
    data_dir: &Path,
    owner_home: &str,
    fingerprint_full: &str,
) -> anyhow::Result<Option<ServedConsentV2>> {
    Ok(served_pools(data_dir)?
        .consent(owner_home, fingerprint_full)
        .cloned())
}

/// Keeps what an approval that already happened consented to, in the entry
/// of its pool, with the root it serves from and the admin profile that
/// approved. Without it a repeat request waits for the admin and the owner's
/// pool notices are refused, so a failure here is logged, not returned.
fn remember_served_consent(data_dir: &Path, approved: &NodeRequestRecordV1, root_path: &str) {
    let stored = update_served_pools(data_dir, |pools| {
        let consent = ServedConsentV2 {
            term_days: approved.term_days,
            signing_key_fingerprint_full: approved.signing_key_fingerprint_full.clone(),
        };
        match pools
            .entries
            .get_mut(&approved.signing_key_fingerprint_full)
        {
            Some(entry) if entry.owner_home == approved.owner_home => {
                entry.consent = consent;
                entry.root_path = root_path.to_string();
                entry.admin_profile_did = Some(approved.local_profile_did.clone());
            }
            _ => {
                pools.entries.insert(
                    approved.signing_key_fingerprint_full.clone(),
                    ServedPoolEntryV2 {
                        owner_home: approved.owner_home.clone(),
                        consent,
                        root_path: root_path.to_string(),
                        admin_profile_did: Some(approved.local_profile_did.clone()),
                        pool_did: None,
                        served_pool: None,
                        descriptor: None,
                    },
                );
            }
        }
        Ok(())
    });
    if let Err(error) = stored {
        tracing::warn!(
            error = %format!("{error:#}"),
            "the approved custody consent was not kept; a repeat request waits for the admin"
        );
    }
}

/// Plan B T2.2 (S2-A3): keeps the admin profile that included, or confirmed,
/// this Home's own root. No entry and no other root changes.
pub(crate) fn record_own_root_admin_profile(
    _write: &CustodyWriteGuard,
    data_dir: &Path,
    profile_did: &str,
) -> anyhow::Result<()> {
    update_served_pools(data_dir, |pools| {
        pools.own_root_admin_profile_did = Some(profile_did.to_string());
        Ok(())
    })
}

/// Plan B T2.2: forgets a served pool's entry (T2.3's Stop serving also sets
/// its root aside). Every other pool stays as it is.
pub(crate) fn forget_served_pool(
    _write: &CustodyWriteGuard,
    data_dir: &Path,
    fingerprint_full: &str,
) -> anyhow::Result<Option<ServedPoolEntryV2>> {
    update_served_pools(data_dir, |pools| Ok(pools.entries.remove(fingerprint_full)))
}

/// OPEN-LOOP F1 (user rule 2026-11-13 14:44): joining a pool is one consent
/// to two duties, a key share and a copy of the pool's files. Once the
/// custody root `root_path` trusts `owner_home`, that owner may send this
/// node its copies (`content.replica`). The owner is the verified signer the
/// root trusts, never a request field. A grant the owner held before any
/// pool stays its own; one added here is recorded first, so the owner's last
/// stopped root withdraws it. A failure is logged, not returned: the node is
/// set up, and approving again grants it.
fn grant_served_owner_replicas(data_dir: &Path, root_path: &str, owner_home: &str) {
    use crate::operator_control::OPERATOR_ACTION_CONTENT_REPLICA;
    let granted = (|| {
        if !matches!(
            custody_root_trust_at(data_dir, root_path)?,
            RootTrust::Trusts(owner) if owner == owner_home
        ) {
            return anyhow::Ok(());
        }
        let held = crate::operator_control::granted_peer_actions(data_dir, owner_home).is_some_and(
            |allow| {
                allow
                    .iter()
                    .any(|action| action == OPERATOR_ACTION_CONTENT_REPLICA)
            },
        );
        if held {
            return Ok(());
        }
        update_served_pools(data_dir, |pools| {
            pools.replica_grant_owners.insert(owner_home.to_string());
            Ok(())
        })?;
        crate::operator_control::grant_peer_action(
            data_dir,
            owner_home,
            OPERATOR_ACTION_CONTENT_REPLICA,
        )
    })();
    if let Err(error) = granted {
        tracing::warn!(
            error = %format!("{error:#}"),
            "the served pool owner cannot send its copies yet; approving again grants it"
        );
    }
}

/// OPEN-LOOP F1 / ADV-14: leaving a pool ends both duties. Once no custody
/// root on disk trusts `owner_home`, the replica grant a pool approval added
/// goes; a grant the owner held before any pool stays.
pub(crate) fn withdraw_served_owner_replicas(
    _write: &CustodyWriteGuard,
    data_dir: &Path,
    owner_home: &str,
) -> anyhow::Result<()> {
    if !served_pools(data_dir)?
        .replica_grant_owners
        .contains(owner_home)
    {
        return Ok(());
    }
    if custody_root_trusts(data_dir)?
        .iter()
        .any(|(_, trust)| matches!(trust, RootTrust::Trusts(owner) if owner == owner_home))
    {
        return Ok(());
    }
    crate::operator_control::revoke_peer_action(
        data_dir,
        owner_home,
        crate::operator_control::OPERATOR_ACTION_CONTENT_REPLICA,
    )?;
    update_served_pools(data_dir, |pools| {
        pools.replica_grant_owners.remove(owner_home);
        Ok(())
    })
}
/// Approve a request: set this Home up as the requesting owner's custody
/// node, answer with its card, and decline every other waiting request.
pub(crate) async fn approve(
    _write: &CustodyWriteGuard,
    host: &NodeHost<'_>,
    local_profile_did: &str,
    request_id: &str,
    now: u64,
) -> anyhow::Result<ApprovedRequest> {
    let data_dir = host.data_dir;
    // #388 A1: nothing is set up on an everyday host; the request is kept.
    if !crate::host_trust::host_trusted(data_dir) {
        return Err(CustodyRefusal::new(crate::host_trust::HOST_TRUST_REQUIRED).into());
    }
    let mut queued = Vec::new();
    let step = with_requests(data_dir, now, |records| {
        let approving = reserved_roots(&served_pools(data_dir)?);
        let record = find_mut(records, local_profile_did, request_id)?;
        match record.state {
            RequestState::Pending | RequestState::Approving => {}
            RequestState::Approved => {
                let pools = served_pools(data_dir)?;
                let root = request_pool_root(data_dir, &pools, record)?
                    .unwrap_or_else(|| custody_provider::CUSTODY_INACTIVE_ROOT_PATH.to_string());
                return Ok(ApproveStep::Served {
                    record: record.clone(),
                    root,
                    fresh: false,
                });
            }
            RequestState::Expired => return Err(CustodyRefusal::new("expired").into()),
            RequestState::Declined => return Err(CustodyRefusal::new("not_pending").into()),
        }
        let pools = served_pools(data_dir)?;
        let custody = custody_state_for(data_dir, &pools, &approving, record)?;
        match custody {
            CustodyStateFor::Incomplete => return Err(incomplete_custody_state()),
            CustodyStateFor::Another => {
                decide(
                    record,
                    host.outbox,
                    Decision::Declined(CustodyDeclineCode::AlreadyServing),
                    now,
                    &mut queued,
                )?;
                return Ok(ApproveStep::TakenByAnother);
            }
            CustodyStateFor::Full => {
                decide(
                    record,
                    host.outbox,
                    Decision::Declined(CustodyDeclineCode::TooManyPools),
                    now,
                    &mut queued,
                )?;
                return Ok(ApproveStep::TooManyPools);
            }
            CustodyStateFor::Free | CustodyStateFor::Ours => {}
        }
        // Provisioning cannot be undone, so everything the answer needs is
        // checked first; a refusal here leaves the request as it was.
        approval_preconditions(record, host, now)?;
        // The owner this Home already serves for this pool asked for a new
        // term: its node stands, so approving answers with its card and
        // provisions nothing.
        if custody == CustodyStateFor::Ours && record.state == RequestState::Pending {
            if let Some(root) = request_pool_root(data_dir, &pools, record)? {
                if let Some(card) = served_card(data_dir, &root, host.ticket.as_deref())? {
                    decide(
                        record,
                        host.outbox,
                        Decision::Approved(card),
                        now,
                        &mut queued,
                    )?;
                    return Ok(ApproveStep::Served {
                        record: record.clone(),
                        root,
                        fresh: true,
                    });
                }
            }
        }
        // R3-D5 = B: the reservation lives only in the served-pools entry,
        // found again by its fingerprint; a legacy approving record with no
        // entry takes its root by the same reserve rule.
        let root = match request_pool_root(data_dir, &pools, record)? {
            Some(root) => root,
            None => {
                reserve_custody_root_for_new_pool(data_dir, &record.signing_key_fingerprint_full)?
            }
        };
        record.state = RequestState::Approving;
        Ok(ApproveStep::Provision(record.clone(), root))
    });
    let (record, root) = match step {
        Ok(ApproveStep::Provision(record, root)) => (record, root),
        Ok(ApproveStep::Served {
            record,
            root,
            fresh,
        }) => {
            send_queued(host.outbox, queued, now);
            // Approvals from before consents were kept record theirs now,
            // but only for the owner the pool's root trusts: a former
            // owner's retained record never stands in for it.
            let backfill = matches!(
                custody_root_trust_at(data_dir, &root),
                Ok(RootTrust::Trusts(owner)) if owner == record.owner_home
            ) && served_pools(data_dir)
                .map(|pools| {
                    pools
                        .consent(&record.owner_home, &record.signing_key_fingerprint_full)
                        .is_none()
                })
                .unwrap_or(false);
            if fresh || backfill {
                remember_served_consent(data_dir, &record, &root);
            }
            grant_served_owner_replicas(data_dir, &root, &record.owner_home);
            return Ok(ApprovedRequest {
                owner_name: record.owner_name,
                needs_restart: served_node_needs_restart(data_dir, host.registry, &root).await,
            });
        }
        Ok(ApproveStep::TakenByAnother) => {
            send_queued(host.outbox, queued, now);
            return Err(CustodyRefusal::new("already_serving").into());
        }
        Ok(ApproveStep::TooManyPools) => {
            send_queued(host.outbox, queued, now);
            return Err(CustodyRefusal::new("too_many_pools").into());
        }
        Err(error) => return Err(error),
    };

    // R3-D5 = B: the entry holds the reservation before provisioning starts,
    // under `CustodyWriteGuard`; a failed provisioning releases it.
    let owner_issuer = runtime_issuer_for_did(&record.owner_home)?;
    let (_, own_did) = elastos_identity::load_existing_did(data_dir)?;
    let reserved = reserve_served_pool_entry(data_dir, &record, &root, local_profile_did)?;
    let provisioned = match provision_served_node(
        data_dir,
        host.registry,
        &root,
        &owner_issuer,
        &record.run_by,
        &record.location,
        &own_did,
    )
    .await
    {
        Ok(provisioned) => provisioned,
        Err(error) => {
            if reserved {
                release_served_pool_reservation(data_dir, &record.signing_key_fingerprint_full);
            }
            return Err(error);
        }
    };
    if !matches!(
        custody_root_trust_at(data_dir, &root)?,
        RootTrust::Trusts(owner) if owner == record.owner_home
    ) {
        anyhow::bail!("this Home's custody root does not trust the approved owner");
    }
    let card = served_card(data_dir, &root, host.ticket.as_deref())?
        .ok_or_else(|| anyhow::anyhow!("this Home's custody node details are missing"))?;
    let carried = crate::custody_node_card::parse_node_card(&card)
        .map_err(|refusal| anyhow::anyhow!("own card refused: {}", refusal.code()))?;
    if carried.node_bytes != provisioned.descriptor_bytes {
        anyhow::bail!("this Home's node card does not carry the node it set up");
    }

    with_requests(data_dir, now, |records| {
        let approved = find_mut(records, local_profile_did, request_id)?;
        decide(
            approved,
            host.outbox,
            Decision::Approved(card.clone()),
            now,
            &mut queued,
        )?;
        // This root now serves this owner's pool: the owner's other requests
        // for the same pool key and term get the same card. Every other
        // request stays waiting for the admin (Plan B T2.2: another owner is
        // no longer turned away). These are courtesies; one that cannot be
        // signed stays waiting, and approving it later answers it.
        for other in records.iter_mut().filter(|other| {
            other.state.is_live()
                && other.request_id != request_id
                && other.owner_home == record.owner_home
                && other.term_days == record.term_days
                && other.signing_key_fingerprint_full == record.signing_key_fingerprint_full
        }) {
            if let Err(error) = decide(
                other,
                host.outbox,
                Decision::Approved(card.clone()),
                now,
                &mut queued,
            ) {
                tracing::warn!(
                    error = %format!("{error:#}"),
                    "another custody request was not answered; it stays waiting"
                );
            }
        }
        Ok(())
    })?;
    remember_served_consent(data_dir, &record, &root);
    grant_served_owner_replicas(data_dir, &root, &record.owner_home);
    send_queued(host.outbox, queued, now);
    tracing::info!("this Home approved a custody request and serves its owner's pool");
    Ok(ApprovedRequest {
        owner_name: record.owner_name,
        needs_restart: provisioned.needs_restart,
    })
}

/// Approving `request_id` would get past everything but provisioning. The
/// Inbox asks before it spends the admin's passkey approval; [`approve`]
/// checks again under the write lock.
pub(crate) fn check_approval(
    host: &NodeHost<'_>,
    local_profile_did: &str,
    request_id: &str,
    now: u64,
) -> anyhow::Result<()> {
    // #388 A1: refused before the admin's passkey is spent.
    if !crate::host_trust::host_trusted(host.data_dir) {
        return Err(CustodyRefusal::new(crate::host_trust::HOST_TRUST_REQUIRED).into());
    }
    let mut records = load_requests(host.data_dir)?;
    expire(&mut records, now);
    let pools = served_pools(host.data_dir)?;
    let approving = reserved_roots(&pools);
    let record = find(&records, local_profile_did, request_id)?;
    if !record.state.is_live() {
        return Err(CustodyRefusal::new("not_pending").into());
    }
    match custody_state_for(host.data_dir, &pools, &approving, record)? {
        CustodyStateFor::Another => Err(CustodyRefusal::new("already_serving").into()),
        CustodyStateFor::Full => Err(CustodyRefusal::new("too_many_pools").into()),
        CustodyStateFor::Incomplete => Err(incomplete_custody_state()),
        CustodyStateFor::Free | CustodyStateFor::Ours => approval_preconditions(record, host, now),
    }
}

/// This Home's custody state, as it stands for one request's pool (Plan B
/// T2.2: per requesting owner and pool key; other owners stay waiting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyStateFor {
    /// The pool has no root yet, and this Home has room for one.
    Free,
    /// The pool's root trusts this request's owner.
    Ours,
    /// The pool's root serves someone else, or names nobody while this
    /// request is not the one that was approving it.
    Another,
    /// This request was approving and its provisioning stopped part way: its
    /// root names nobody readable. The provider does not repair such a root.
    Incomplete,
    /// The pool has no root and this Home holds eight (`too_many_pools`).
    Full,
}

/// Who a root serves comes from that root's trusted issuer alone. A root
/// that cannot be read right now is no answer: the caller refuses
/// `unavailable` and changes nothing.
fn custody_state_for(
    data_dir: &Path,
    pools: &ServedPools,
    approving: &[String],
    record: &NodeRequestRecordV1,
) -> anyhow::Result<CustodyStateFor> {
    let Some(root) = request_pool_root(data_dir, pools, record)? else {
        return Ok(if custody_root_capacity_reached(data_dir, approving)? {
            CustodyStateFor::Full
        } else {
            CustodyStateFor::Free
        });
    };
    Ok(match custody_root_trust_at(data_dir, &root)? {
        RootTrust::Trusts(owner) if owner == record.owner_home => CustodyStateFor::Ours,
        RootTrust::Trusts(_) => CustodyStateFor::Another,
        RootTrust::NamesNobody if record.state == RequestState::Approving => {
            CustodyStateFor::Incomplete
        }
        RootTrust::NamesNobody => CustodyStateFor::Another,
        RootTrust::NoRoot => CustodyStateFor::Free,
    })
}

/// The custody root of a request's pool, when it has one: the served-pools
/// entry for its owner and pool key (an approval's reservation, R3-D5 = B),
/// else (records from before the map, while no entry claims it) `inactive`
/// when that root trusts the owner. A legacy approving record with neither
/// takes a root by `reserve_custody_root_for_new_pool`.
fn request_pool_root(
    data_dir: &Path,
    pools: &ServedPools,
    record: &NodeRequestRecordV1,
) -> anyhow::Result<Option<String>> {
    if let Some(entry) = pools
        .entries
        .get(&record.signing_key_fingerprint_full)
        .filter(|entry| entry.owner_home == record.owner_home)
    {
        return Ok(Some(entry.root_path.clone()));
    }
    let inactive = custody_provider::CUSTODY_INACTIVE_ROOT_PATH;
    if pools
        .entries
        .values()
        .any(|entry| entry.root_path == inactive)
    {
        return Ok(None);
    }
    Ok(match custody_root_trust_at(data_dir, inactive)? {
        RootTrust::Trusts(owner) if owner == record.owner_home => Some(inactive.to_string()),
        _ => None,
    })
}

/// The roots the served-pools entries hold, reservations included; with the
/// roots on disk they count toward the cap (R3-D5 = B).
fn reserved_roots(pools: &ServedPools) -> Vec<String> {
    pools
        .entries
        .values()
        .map(|entry| entry.root_path.clone())
        .collect()
}

/// R3-D5 = B: Approve writes the pool's entry with its reserved root before
/// provisioning, under `CustodyWriteGuard`, so a crash and a second approval
/// find the same root by fingerprint. Only the request's facts are known
/// yet. Returns whether this call made the entry.
fn reserve_served_pool_entry(
    data_dir: &Path,
    record: &NodeRequestRecordV1,
    root_path: &str,
    local_profile_did: &str,
) -> anyhow::Result<bool> {
    update_served_pools(data_dir, |pools| {
        if pools
            .entries
            .contains_key(&record.signing_key_fingerprint_full)
        {
            return Ok(false);
        }
        pools.entries.insert(
            record.signing_key_fingerprint_full.clone(),
            ServedPoolEntryV2 {
                owner_home: record.owner_home.clone(),
                consent: ServedConsentV2 {
                    term_days: record.term_days,
                    signing_key_fingerprint_full: record.signing_key_fingerprint_full.clone(),
                },
                root_path: root_path.to_string(),
                admin_profile_did: Some(local_profile_did.to_string()),
                pool_did: None,
                served_pool: None,
                descriptor: None,
            },
        );
        Ok(true)
    })
}

/// A failed provisioning releases the reservation it made: the entry goes
/// while it still serves nothing.
fn release_served_pool_reservation(data_dir: &Path, fingerprint_full: &str) {
    let released = update_served_pools(data_dir, |pools| {
        if pools
            .entries
            .get(fingerprint_full)
            .is_some_and(|entry| entry.served_pool.is_none() && entry.descriptor.is_none())
        {
            pools.entries.remove(fingerprint_full);
        }
        Ok(())
    });
    if let Err(error) = released {
        tracing::warn!(
            error = %format!("{error:#}"),
            "a custody root reservation was not released"
        );
    }
}

/// The file the custody provider keeps its trusted Runtime issuer in, inside
/// the custody root (`capsules/custody-provider/src/lib.rs`).
const TRUSTED_RUNTIME_ISSUER_FILE: &str = "trusted-runtime-issuer";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RootTrust {
    NoRoot,
    /// The DID of the one Runtime the custody root trusts.
    Trusts(String),
    /// A custody root without a trusted issuer: its file is missing or empty,
    /// as a provisioning that stopped part way leaves it.
    NamesNobody,
}

/// Plan B T2.2 (user decision 2026-11-12 10:35): who the custody root at
/// `root_path` serves, from its own trusted issuer.
pub(crate) fn custody_root_trust_at(data_dir: &Path, root_path: &str) -> anyhow::Result<RootTrust> {
    let unavailable = |error: &dyn std::fmt::Debug| -> anyhow::Error {
        CustodyRefusal::with_detail("unavailable", format!("{error:?}")).into()
    };
    let root = crate::protected_content_runtime::custody_root_dir(data_dir, root_path);
    match std::fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(RootTrust::NoRoot),
        Err(error) => return Err(unavailable(&error)),
        Ok(_) => {}
    }
    match std::fs::symlink_metadata(root.join(TRUSTED_RUNTIME_ISSUER_FILE)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RootTrust::NamesNobody)
        }
        Err(error) => return Err(unavailable(&error)),
        Ok(metadata) if metadata.len() == 0 => return Ok(RootTrust::NamesNobody),
        Ok(_) => {}
    }
    let issuer = custody_provider::load_trusted_runtime_issuer(&root)
        .map_err(|error| unavailable(&error))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(issuer.as_bytes())
        .map_err(|error| unavailable(&error))?;
    Ok(RootTrust::Trusts(
        elastos_identity::encode_did_key(&key).map_err(|error| unavailable(&error))?,
    ))
}

/// Every root on disk with whom it serves.
pub(crate) fn custody_root_trusts(data_dir: &Path) -> anyhow::Result<Vec<(String, RootTrust)>> {
    crate::protected_content_runtime::custody_provider_root_paths(data_dir)?
        .into_iter()
        .map(|root| {
            let trust = custody_root_trust_at(data_dir, &root)?;
            Ok((root, trust))
        })
        .collect()
}

/// The `inactive` root's owner, as the single-owner code read it.
#[cfg(test)]
pub(crate) fn custody_owner_did(data_dir: &Path) -> Option<String> {
    match custody_root_trust_at(data_dir, custody_provider::CUSTODY_INACTIVE_ROOT_PATH) {
        Ok(RootTrust::Trusts(owner)) => Some(owner),
        _ => None,
    }
}

/// The incomplete-setup refusal; its detail is a stable key the Inbox reads.
const INCOMPLETE_CUSTODY_STATE: &str = "custody_state_incomplete";

fn incomplete_custody_state() -> anyhow::Error {
    CustodyRefusal::with_detail("provision_failed", INCOMPLETE_CUSTODY_STATE).into()
}

/// How the Inbox shows a live request: waiting for a decision, an approval
/// to finish (or decline, while it set nothing up), or an approval that
/// cannot finish and is only declined. A root that cannot be read now shows
/// as finishing, which declines nothing.
fn inbox_stage(
    data_dir: &Path,
    record: &NodeRequestRecordV1,
) -> crate::notifications::CustodyRequestStage {
    use crate::notifications::CustodyRequestStage;
    if record.state != RequestState::Approving {
        return CustodyRequestStage::Waiting;
    }
    let state = served_pools(data_dir).and_then(|pools| {
        let approving = reserved_roots(&pools);
        custody_state_for(data_dir, &pools, &approving, record)
    });
    match state {
        Ok(CustodyStateFor::Incomplete) => CustodyRequestStage::Incomplete,
        Ok(CustodyStateFor::Another) => CustodyRequestStage::ServesAnother,
        // An approving request holds its root, so it never meets the cap;
        // read as nothing set up yet.
        Ok(CustodyStateFor::Full) => CustodyRequestStage::Resumable,
        // Nothing was set up yet, so declining is still possible.
        Ok(CustodyStateFor::Free) => CustodyRequestStage::Resumable,
        Ok(CustodyStateFor::Ours) => CustodyRequestStage::Finishing,
        Err(error) => {
            tracing::debug!(error = %format!("{error:#}"), "custody root is unreadable now");
            CustodyRequestStage::Finishing
        }
    }
}

/// What approving needs besides provisioning: this Home's Carrier address for
/// its card, and a decision this Profile can sign to this owner, which needs
/// custody messages enabled and the owner still an accepted contact. The
/// decision is signed and dropped, never sent.
fn approval_preconditions(
    record: &NodeRequestRecordV1,
    host: &NodeHost<'_>,
    now: u64,
) -> anyhow::Result<()> {
    if host.ticket.is_none() {
        return Err(CustodyRefusal::new("no_address").into());
    }
    let dry_run = CustodyNodeDecisionPayload {
        card: None,
        code: Some(CustodyDeclineCode::Declined),
        outcome: CustodyNodeDecisionOutcome::Declined,
        request_id: record.request_id.clone(),
        request_sha256: record.request_sha256.clone(),
    };
    host.outbox
        .sign(
            &record.local_profile_did,
            &record.owner_profile_did,
            dry_run,
            now,
            decision_expires_at(record, now),
        )
        .map(drop)
        .map_err(signing_refusal)
}

/// Why the message service would not sign a custody message, as the code
/// the Custody app and Inbox show.
pub(crate) fn signing_refusal(error: anyhow::Error) -> anyhow::Error {
    let code = if matches!(
        error.downcast_ref::<crate::custody_consent_protocol::CustodyMessageRefusal>(),
        Some(crate::custody_consent_protocol::CustodyMessageRefusal::SignerNotAuthorized)
    ) {
        "messages_not_enabled"
    } else if error.downcast_ref::<WireRefusal>() == Some(&WireRefusal::NOT_CONTACT) {
        "not_contact"
    } else {
        "messages_unavailable"
    };
    CustodyRefusal::from_error(code, &error).into()
}

/// Decline a waiting request.
pub(crate) fn decline(
    _write: &CustodyWriteGuard,
    data_dir: &Path,
    outbox: &dyn DecisionOutbox,
    local_profile_did: &str,
    request_id: &str,
    now: u64,
) -> anyhow::Result<()> {
    let mut queued = Vec::new();
    // R3-D5 = B: a declined approval releases the root it reserved.
    let mut release = None;
    with_requests(data_dir, now, |records| {
        let pools = served_pools(data_dir)?;
        let approving = reserved_roots(&pools);
        let record = find_mut(records, local_profile_did, request_id)?;
        match record.state {
            RequestState::Pending => decide(
                record,
                outbox,
                Decision::Declined(CustodyDeclineCode::Declined),
                now,
                &mut queued,
            ),
            // An approving request is declined unless this Home's node already
            // trusts its owner: a custody root cannot be undone, so declining
            // then would leave the node serving the owner it said no to.
            RequestState::Approving => {
                let code = match custody_state_for(data_dir, &pools, &approving, record)? {
                    CustodyStateFor::Ours => {
                        return Err(CustodyRefusal::with_detail("not_pending", "approving").into())
                    }
                    CustodyStateFor::Another => CustodyDeclineCode::AlreadyServing,
                    CustodyStateFor::Free | CustodyStateFor::Incomplete | CustodyStateFor::Full => {
                        CustodyDeclineCode::Declined
                    }
                };
                release = Some(record.signing_key_fingerprint_full.clone());
                decide(record, outbox, Decision::Declined(code), now, &mut queued)
            }
            RequestState::Declined => Ok(()),
            RequestState::Expired => Err(CustodyRefusal::new("expired").into()),
            RequestState::Approved => Err(CustodyRefusal::new("not_pending").into()),
        }
    })?;
    if let Some(fingerprint) = release {
        release_served_pool_reservation(data_dir, &fingerprint);
    }
    send_queued(outbox, queued, now);
    Ok(())
}

/// Queues again every decision a restart may have left unsent.
pub(crate) fn resume(data_dir: &Path, outbox: &dyn DecisionOutbox, now: u64) -> anyhow::Result<()> {
    let queued = with_requests(data_dir, now, |records| {
        Ok(records.iter().filter_map(queued_decision).collect())
    })?;
    send_queued(outbox, queued, now);
    Ok(())
}

/// The delivery-pass step for this Home's decisions: one the outbox no
/// longer holds, as after a restart, is queued again while it lives, and one
/// the outbox can never take is let go once. The records are read once per
/// pass and written only when something changed.
fn resume_decisions(data_dir: &Path, outbox: &dyn DecisionOutbox, now: u64) -> anyhow::Result<()> {
    if !present(&requests_path(data_dir))? {
        return Ok(());
    }
    with_requests(data_dir, now, |records| {
        for record in records
            .iter_mut()
            .filter(|record| record.decision.is_some())
        {
            let key = format!("{DECISION_OUTBOX_PREFIX}{}", record.request_id);
            if outbox.state(&key, now).is_some() {
                continue;
            }
            let Some(queued) = queued_decision(record) else {
                record.decision = None;
                continue;
            };
            if let Err(error) =
                outbox.enqueue(&queued.key, &queued.local_profile_did, queued.envelope, now)
            {
                if crate::collaboration_custody_messages::terminal_state_for(&error).is_some() {
                    tracing::debug!(
                        error = %format!("{error:#}"),
                        "a custody decision can no longer be sent; it is let go"
                    );
                    record.decision = None;
                } else {
                    tracing::debug!(
                        error = %format!("{error:#}"),
                        "a custody decision stays unqueued until the next pass"
                    );
                }
            }
        }
        Ok(())
    })
}

/// The Runtime issuer of the Home whose DID is `did`: its DID key itself.
fn runtime_issuer_for_did(did: &str) -> anyhow::Result<String> {
    let key = elastos_identity::decode_did_key(did)?;
    Ok(format!("0x{}", hex::encode(key.as_bytes())))
}

/// One read-change-write of the request records, under their lock. Expired
/// requests and old settled ones are tidied first; the file is written only
/// when something changed.
fn with_requests<T>(
    data_dir: &Path,
    now: u64,
    change: impl FnOnce(&mut Vec<NodeRequestRecordV1>) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let _guard = REQUESTS_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("custody request lock is poisoned"))?;
    let loaded = load_requests(data_dir)?;
    let mut records = loaded.clone();
    expire(&mut records, now);
    let result = change(&mut records)?;
    if records != loaded {
        store_requests(data_dir, &records)?;
    }
    Ok(result)
}

fn expire(records: &mut Vec<NodeRequestRecordV1>, now: u64) {
    for record in records.iter_mut() {
        // Provisioning may have run for an approving request, so it stays
        // until approving it again finishes and answers its owner.
        if record.state == RequestState::Pending && record.expires_at <= now {
            record.state = RequestState::Expired;
        }
        if decision_expires_at(record, record.decided_at.unwrap_or(0)) <= now {
            record.decision = None;
        }
    }
    records.retain(|record| {
        record.state.is_live() || settled_at(record).saturating_add(TERMINAL_RETENTION_SECS) > now
    });
}

fn load_requests(data_dir: &Path) -> anyhow::Result<Vec<NodeRequestRecordV1>> {
    let path = requests_path(data_dir);
    if !present(&path)? {
        return Ok(Vec::new());
    }
    let bytes = read_owner_only_file(&path, MAX_REQUESTS_FILE_BYTES, "custody node requests")?;
    let file: NodeRequestsFileV1 = serde_json::from_slice(&bytes)?;
    if file.schema != REQUESTS_SCHEMA_V1 || file.requests.len() > MAX_REQUESTS {
        anyhow::bail!("custody node requests are not a known record");
    }
    Ok(file.requests)
}

fn store_requests(data_dir: &Path, records: &[NodeRequestRecordV1]) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(&NodeRequestsFileV1 {
        schema: REQUESTS_SCHEMA_V1.to_string(),
        requests: records.to_vec(),
    })?;
    if bytes.len() > MAX_REQUESTS_FILE_BYTES {
        anyhow::bail!("custody node requests exceed their byte limit");
    }
    ensure_owner_only_dir(&protected_content_root(data_dir), "protected-content root")?;
    write_owner_only_bytes(&requests_path(data_dir), &bytes)
}

fn present(path: &Path) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(anyhow::Error::new(error).context("custody consent file is unavailable")),
    }
}

/// The pool a served node is in, as its owner told it, for Hosting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ServedPoolView {
    pub(crate) share: u8,
    pub(crate) total: u8,
    pub(crate) required: u8,
    pub(crate) pool_start: u64,
    pub(crate) term_end: u64,
    pub(crate) members: Vec<CustodyPoolMember>,
}

/// The v1 served pool file. Plan B T2.2 reads it once into the map; it stays
/// on disk, unused.
const SERVED_POOL_FILE: &str = "custody-served-pool.json";
const NOT_SERVED_OWNER: WireRefusal = WireRefusal::new("not_served_owner");
const WRONG_ISSUER: WireRefusal = WireRefusal::new("wrong_issuer");
const NOT_MEMBER: WireRefusal = WireRefusal::new("not_member");
const WRONG_SHARE: WireRefusal = WireRefusal::new("wrong_share");
const STALE_NOTICE: WireRefusal = WireRefusal::new("stale_notice");
/// The pool runs longer than the term this node's admin approved.
const TERM_MISMATCH: WireRefusal = WireRefusal::new("term_mismatch");

fn served_pool_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(SERVED_POOL_FILE)
}

const SERVED_POOL_SCHEMA_V1: &str = "elastos.protected-content.custody-served-pool/v1";
/// Room for a member list at the threshold's largest size.
const MAX_SERVED_POOL_FILE_BYTES: usize = 16 * 1024;
const POOL_ACTIVE_TITLE: &str = "Custody pool active";
const UNNAMED_POOL_OWNER: &str = "The pool owner";

/// Served pool records change one writer at a time.
static SERVED_POOL_LOCK: Mutex<()> = Mutex::new(());

/// The v1 served pool record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServedPoolFileV1 {
    schema: String,
    owner_home: String,
    fingerprint_full: String,
    pool_start: u64,
    term_end: u64,
    share: u8,
    threshold: CustodyPoolThreshold,
    members: Vec<CustodyPoolMember>,
    received_at: u64,
}

impl ServedPoolFileV1 {
    fn into_v2(self) -> ServedPoolV2 {
        ServedPoolV2 {
            fingerprint_full: self.fingerprint_full,
            pool_start: self.pool_start,
            term_end: self.term_end,
            share: self.share,
            threshold: self.threshold,
            members: self.members,
            received_at: self.received_at,
        }
    }
}

/// A served owner's notice that this node is in its signed pool. Checked in
/// order, after the protocol verified the signature, scope, lifetime, size,
/// fingerprint and composition facts: some root trusts the signer, the pool
/// is signed by a key the admin consented to for that owner (the entry keyed
/// by that key) and runs no longer than the term consented to, this pool's
/// root node is in it at the share the notice names, and it is newer than
/// the pool that entry keeps. The same pool again is a no-op. Plan B T2.2:
/// a notice for one pool never touches another.
fn receive_pool_active(
    inbound: &CustodyInbound<'_>,
    notice: &CustodyPoolActivePayload,
) -> Result<(), WireRefusal> {
    let data_dir = inbound.data_dir;
    require_admin_recipient(data_dir, inbound.principal_id)?;
    let signer = inbound.message.signer_did();
    if !root_trusts(data_dir, signer).map_err(unavailable)? {
        return Err(NOT_SERVED_OWNER);
    }
    let facts = pool_active_facts(notice)?;
    let pool_key = Fingerprint::of(&facts.issuer).full;
    let pools = served_pools(data_dir).map_err(unavailable)?;
    let Some(entry) = pools
        .entries
        .get(&pool_key)
        .filter(|entry| entry.owner_home == signer)
        .cloned()
    else {
        return Err(WRONG_ISSUER);
    };
    // The pool's own root must trust the signer.
    if !matches!(
        custody_root_trust_at(data_dir, &entry.root_path).map_err(unavailable)?,
        RootTrust::Trusts(owner) if owner == signer
    ) {
        return Err(NOT_SERVED_OWNER);
    }
    // The admin consented to a term: the pool may not run longer. Install
    // starts a pool a minute early, and clocks may differ a little.
    let consented_secs = u64::from(entry.consent.term_days)
        .saturating_mul(86_400)
        .saturating_add(60 + MAX_COLLABORATION_CLOCK_SKEW_SECS);
    if notice.term_end.saturating_sub(notice.pool_start) > consented_secs {
        return Err(TERM_MISMATCH);
    }
    let own_key = root_node_public_key(data_dir, &entry.root_path).map_err(unavailable)?;
    match facts
        .members
        .iter()
        .find(|(node_key, _)| Some(node_key) == own_key.as_ref())
    {
        None => return Err(NOT_MEMBER),
        Some((_, share)) if *share != notice.share => return Err(WRONG_SHARE),
        Some(_) => {}
    }

    let outcome = update_served_pools(data_dir, |pools| {
        let Some(entry) = pools
            .entries
            .get_mut(&pool_key)
            .filter(|entry| entry.owner_home == signer)
        else {
            return Ok(Err(WRONG_ISSUER));
        };
        if let Some(stored) = &entry.served_pool {
            if stored.fingerprint_full == notice.fingerprint_full {
                // Kept already; an Inbox entry whose write was lost comes back.
                return Ok(Ok(()));
            }
            if !pool_active_is_newer(&stored.as_notice(), notice) {
                return Ok(Err(STALE_NOTICE));
            }
        }
        entry.served_pool = Some(ServedPoolV2 {
            fingerprint_full: notice.fingerprint_full.clone(),
            pool_start: notice.pool_start,
            term_end: notice.term_end,
            share: notice.share,
            threshold: notice.threshold,
            members: notice.members.clone(),
            received_at: inbound.now,
        });
        Ok(Ok(()))
    })
    .map_err(unavailable)?;
    outcome?;
    tracing::debug!(
        share = notice.share,
        "a served pool's owner confirmed its pool"
    );
    show_pool_active(inbound, notice);
    Ok(())
}

/// Some custody root trusts `owner`.
fn root_trusts(data_dir: &Path, owner: &str) -> anyhow::Result<bool> {
    Ok(custody_root_trusts(data_dir)?
        .iter()
        .any(|(_, trust)| matches!(trust, RootTrust::Trusts(trusted) if trusted == owner)))
}

/// What a member knows of the pool it serves, to match the owner's pool
/// descriptor against (Plan B T3.3, L13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServedPoolFacts {
    /// The fingerprint of the pool signing key the admin consented to: the
    /// pool's key in the served-pools map.
    pub(crate) issuer_fingerprint_full: String,
    /// The signed pool's start, which selects the composition.
    pub(crate) pool_start: u64,
    pub(crate) term_end: u64,
    pub(crate) required: u8,
    pub(crate) total: u8,
    /// This node's share and key, in this pool's root.
    pub(crate) share: u8,
    pub(crate) own_node_key: [u8; 32],
}

/// A served owner's signed pool descriptor (L13): the sender passes the
/// checks `receive_pool_active` makes of it, and the descriptor names a pool
/// this node keeps for that owner; the descriptor module checks the rest and
/// keeps it in that pool's entry.
fn receive_pool_descriptor(
    inbound: &CustodyInbound<'_>,
    payload: &crate::custody_consent_protocol::CustodyPoolDescriptorPayload,
) -> Result<(), WireRefusal> {
    let data_dir = inbound.data_dir;
    require_admin_recipient(data_dir, inbound.principal_id)?;
    let signer = inbound.message.signer_did();
    if !root_trusts(data_dir, signer).map_err(unavailable)? {
        return Err(NOT_SERVED_OWNER);
    }
    let descriptor = payload.signed_descriptor().map_err(WireRefusal::from)?;
    let pool_key = Fingerprint::of(descriptor.pool().issuer().as_bytes()).full;
    let facts = served_pool_facts(data_dir, signer, &pool_key)
        .map_err(unavailable)?
        .ok_or(NOT_MEMBER)?;
    crate::custody_pool_descriptor::store_member_descriptor(
        data_dir,
        &facts,
        &descriptor,
        inbound.now,
    )
}

/// The kept pool and consent of `owner`'s pool `pool_key`, with that root's
/// node key.
fn served_pool_facts(
    data_dir: &Path,
    owner: &str,
    pool_key: &str,
) -> anyhow::Result<Option<ServedPoolFacts>> {
    let pools = served_pools(data_dir)?;
    let Some(entry) = pools
        .entries
        .get(pool_key)
        .filter(|entry| entry.owner_home == owner)
    else {
        return Ok(None);
    };
    let (Some(pool), Some(own_node_key)) = (
        entry.served_pool.as_ref(),
        root_node_public_key(data_dir, &entry.root_path)?,
    ) else {
        return Ok(None);
    };
    Ok(Some(ServedPoolFacts {
        issuer_fingerprint_full: pool_key.to_string(),
        pool_start: pool.pool_start,
        term_end: pool.term_end,
        required: pool.threshold.required,
        total: pool.threshold.total,
        share: pool.share,
        own_node_key,
    }))
}

/// The admin's Inbox entry for the pool, once per pool. The pool is kept
/// whatever happens here. Plan B T2.2: the entries of the other served pools
/// stay.
fn show_pool_active(inbound: &CustodyInbound<'_>, notice: &CustodyPoolActivePayload) {
    let owner = Some(inbound.sender_display_name.trim())
        .filter(|name| !name.is_empty())
        .unwrap_or(UNNAMED_POOL_OWNER);
    let kept = served_pool_fingerprints(inbound.data_dir);
    if let Err(error) = crate::notifications::upsert_custody_pool_active_notification(
        inbound.data_dir,
        &inbound.local_profile.document().profile_did,
        &notice.fingerprint_full,
        &kept,
        POOL_ACTIVE_TITLE,
        &format!(
            "{owner}'s pool is active. This Home holds share {} of {}.",
            notice.share, notice.threshold.total
        ),
        inbound.now,
    ) {
        tracing::warn!(error = %format!("{error:#}"), "the pool notice is kept but not shown in Inbox");
    }
}

impl ServedPoolV2 {
    /// The kept pool, as the protocol orders notices.
    fn as_notice(&self) -> CustodyPoolActivePayload {
        CustodyPoolActivePayload {
            config: String::new(),
            fingerprint_full: self.fingerprint_full.clone(),
            members: self.members.clone(),
            pool_start: self.pool_start,
            share: self.share,
            term_end: self.term_end,
            threshold: self.threshold,
        }
    }
}

/// The verified notice's composition facts; the protocol read them already,
/// so a failure here is the same refusal it would give.
fn pool_active_facts(
    notice: &CustodyPoolActivePayload,
) -> Result<crate::custody_consent_protocol::SignedCompositionFacts, WireRefusal> {
    let config = base64::engine::general_purpose::STANDARD
        .decode(&notice.config)
        .map_err(|_| WireRefusal::from(CustodyMessageRefusal::InvalidConfig))?;
    signed_composition_facts(&config).map_err(WireRefusal::from)
}

/// The served node key of the custody root `root_path`, which its card and
/// descriptor carry.
fn root_node_public_key(data_dir: &Path, root_path: &str) -> anyhow::Result<Option<[u8; 32]>> {
    let Some(card) = served_node_card(data_dir, root_path)? else {
        return Ok(None);
    };
    let descriptor = crate::protected_content_config::validated_custody_node_descriptor(
        &card.node_bytes,
        "this Home's custody node",
    )?;
    Ok(Some(*descriptor.node_public_key.as_bytes()))
}

/// Plan B T3.4 / T2.2: this Home's served node key in `pool`, for the
/// `custody-pool` target: the node key of that pool's root.
pub(crate) fn served_node_public_key(
    data_dir: &Path,
    pool: &elastos_protected_content_contracts::PoolDidV1,
) -> Option<elastos_protected_content_contracts::NodePublicKey> {
    let pool_key = Fingerprint::of(pool.issuer().as_bytes()).full;
    let entry = served_pools(data_dir).ok()?.entries.remove(&pool_key)?;
    root_node_public_key(data_dir, &entry.root_path)
        .ok()
        .flatten()
        .and_then(|key| elastos_protected_content_contracts::NodePublicKey::new(key).ok())
}

/// The pool `pool_key` this node is in, while its root still trusts the
/// entry's owner.
fn current_served_pool(data_dir: &Path, pool_key: &str) -> Option<ServedPoolV2> {
    let pools = served_pools(data_dir)
        .inspect_err(|error| {
            tracing::warn!(error = %format!("{error:#}"), "the served pools are unreadable")
        })
        .ok()?;
    let entry = pools.entries.get(pool_key)?;
    match custody_root_trust_at(data_dir, &entry.root_path) {
        Ok(RootTrust::Trusts(owner)) if owner == entry.owner_home => entry.served_pool.clone(),
        _ => None,
    }
}

/// The pool `pool_key` this node is in, for Hosting.
pub(crate) fn served_pool_view(data_dir: &Path, pool_key: &str) -> Option<ServedPoolView> {
    current_served_pool(data_dir, pool_key).map(|record| ServedPoolView {
        share: record.share,
        total: record.threshold.total,
        required: record.threshold.required,
        pool_start: record.pool_start,
        term_end: record.term_end,
        members: record.members,
    })
}

/// The composition fingerprints of every pool this node is in now, which
/// their Inbox entries are keyed by.
pub(crate) fn served_pool_fingerprints(data_dir: &Path) -> Vec<String> {
    let Ok(pools) = served_pools(data_dir) else {
        return Vec::new();
    };
    pools
        .entries
        .keys()
        .filter_map(|pool_key| current_served_pool(data_dir, pool_key))
        .map(|pool| pool.fingerprint_full)
        .collect()
}

fn load_v1_served_pool(data_dir: &Path) -> anyhow::Result<Option<ServedPoolFileV1>> {
    let path = served_pool_path(data_dir);
    if !present(&path)? {
        return Ok(None);
    }
    let bytes = read_owner_only_file(&path, MAX_SERVED_POOL_FILE_BYTES, "custody served pool")?;
    let record: ServedPoolFileV1 = serde_json::from_slice(&bytes)?;
    if record.schema != SERVED_POOL_SCHEMA_V1 {
        anyhow::bail!("custody served pool has an unknown schema");
    }
    Ok(Some(record))
}

#[cfg(all(test, unix))]
pub(crate) mod tests;

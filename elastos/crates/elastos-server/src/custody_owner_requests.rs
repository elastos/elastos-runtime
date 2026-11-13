//! Custody consent, owner side: which contacts offer custody, the requests
//! this Home sends them to be its custody nodes, and their decisions.
//!
//! Gateway-free: the Custody app's routes adapt it, and the custody message
//! plane hands decisions to [`on_decision`] through the one consent handler.
//! A node's identity is the verified signer of its decision, which must be
//! the endpoint the request went to; nothing in a payload names it.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use anyhow::Context as _;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::collaboration_config::read_owner_only_file;
use crate::collaboration_contact_store::CollaborationContactStore;
use crate::collaboration_custody_messages::{
    terminal_state_for, CollaborationCustodyMessageService, CustodyInbound, CustodyOutboxState,
    CustodyQueryOutcome, CustodyRefusal as WireRefusal, WeakCustodyMessageService,
    CUSTODY_PROVIDER_TIMEOUT_MS,
};
use crate::collaboration_profile_authority::VerifiedCollaborationProfileDocument;
use crate::custody_consent::{custody_messages_enabled, CustodyWriteGuard};
use crate::custody_consent_protocol::{
    CustodyMessageRefusal, CustodyMessageType, CustodyNodeDecisionOutcome,
    CustodyNodeDecisionPayload, CustodyNodeRequestPayload, CustodyOfferPayload, CustodyPayload,
};
use crate::custody_pool_setup::{CardInput, CardView, CustodyRefusal, POOL_TERM_DAYS};
use crate::protected_content_config::ensure_owner_only_dir;
use crate::protected_content_runtime::{protected_content_root, write_owner_only_bytes};

const REQUESTS_FILE: &str = "custody-node-requests-out.json";
const REQUESTS_SCHEMA_V1: &str = "elastos.protected-content.custody-node-requests-out/v1";
const MAX_REQUESTS: usize = 16;
/// Room for every record with its signed request and a node card.
const MAX_REQUESTS_FILE_BYTES: usize = 512 * 1024;
const REQUEST_OUTBOX_PREFIX: &str = "custody-request:";
/// A node that decided as its request ran out still reaches the owner: its
/// decision is taken up to an hour after the request expired.
const DECISION_GRACE_SECS: u64 = 60 * 60;
/// Find nodes answers within this, whatever the contacts do: one not
/// answered by then reads as unreachable.
const FIND_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

const UNKNOWN_REQUEST: WireRefusal = WireRefusal::new("unknown_request");
const REQUEST_MISMATCH: WireRefusal = WireRefusal::new("request_mismatch");
const WRONG_SENDER: WireRefusal = WireRefusal::new("wrong_sender");
const DECISION_LATE: WireRefusal = WireRefusal::new("decision_late");
const BAD_CARD: WireRefusal = WireRefusal::new("bad_card");
const ALREADY_DECIDED: WireRefusal = WireRefusal::new("already_decided");

/// Request records change one writer at a time: the message plane receives
/// decisions while the admin sends.
static REQUESTS_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OwnerRequestState {
    Waiting,
    Approved,
    Declined,
    Expired,
}

/// One request this Home sent, and how its node answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerRequestRecordV1 {
    request_id: String,
    /// `sha256:` of the exact request envelope; the decision cites it.
    request_sha256: String,
    /// The admin's Profile that signed the request; the decision answers it.
    local_profile_did: String,
    recipient_profile_did: String,
    /// The contact's sole endpoint DID when the request went out: the only
    /// signer whose decision counts.
    recipient_home: String,
    recipient_name: String,
    term_days: u16,
    created_at: u64,
    expires_at: u64,
    state: OwnerRequestState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    card: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decided_at: Option<u64>,
    /// The signed request, standard base64, kept while it waits so a restart
    /// sends it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    envelope: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerRequestsFileV1 {
    schema: String,
    requests: Vec<OwnerRequestRecordV1>,
}

/// A sent request as the Custody app shows it. The card comes only with an
/// approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct NodeRequestOutView {
    pub(crate) request_id: String,
    pub(crate) request_sha256: String,
    pub(crate) recipient_profile_did: String,
    pub(crate) recipient_home: String,
    pub(crate) recipient_name: String,
    pub(crate) term_days: u16,
    pub(crate) created_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) state: OwnerRequestState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) card: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) decided_at: Option<u64>,
}

impl NodeRequestOutView {
    fn of(record: &OwnerRequestRecordV1) -> Self {
        Self {
            request_id: record.request_id.clone(),
            request_sha256: record.request_sha256.clone(),
            recipient_profile_did: record.recipient_profile_did.clone(),
            recipient_home: record.recipient_home.clone(),
            recipient_name: record.recipient_name.clone(),
            term_days: record.term_days,
            created_at: record.created_at,
            expires_at: record.expires_at,
            state: record.state,
            code: record.code.clone(),
            card: record
                .card
                .clone()
                .filter(|_| record.state == OwnerRequestState::Approved),
            decided_at: record.decided_at,
        }
    }
}

/// An accepted contact with its signed Profile.
pub(crate) struct AcceptedContact {
    pub(crate) profile_did: String,
    pub(crate) name: String,
    pub(crate) profile: VerifiedCollaborationProfileDocument,
}

/// The admin's accepted contacts. One whose Profile cannot be read is left
/// out rather than failing the list.
pub(crate) fn accepted_contacts(
    store: &CollaborationContactStore,
) -> anyhow::Result<Vec<AcceptedContact>> {
    let snapshot = store.snapshot()?;
    let mut contacts = Vec::new();
    for contact in snapshot.contacts() {
        match store.accepted_profile(contact.remote_profile_did()) {
            Ok(Some(profile)) => contacts.push(AcceptedContact {
                profile_did: contact.remote_profile_did().to_string(),
                name: contact.remote_display_name().to_string(),
                profile,
            }),
            Ok(None) => {}
            Err(error) => {
                tracing::debug!(error = %format!("{error:#}"), "a contact's Profile is unreadable");
            }
        }
    }
    Ok(contacts)
}

/// Signs and queues this Home's requests. The message service is the real
/// one; it is a seam so the rules here are tested without Carrier.
#[async_trait::async_trait]
pub(crate) trait RequestOutbox: Send + Sync {
    fn sign(
        &self,
        local_profile_did: &str,
        recipient_profile_did: &str,
        request: CustodyNodeRequestPayload,
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

    /// Queues the message and attempts it once now.
    async fn send(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<CustodyOutboxState>;
}

#[async_trait::async_trait]
impl RequestOutbox for CollaborationCustodyMessageService {
    fn sign(
        &self,
        local_profile_did: &str,
        recipient_profile_did: &str,
        request: CustodyNodeRequestPayload,
        now: u64,
        expires_at: u64,
    ) -> anyhow::Result<Vec<u8>> {
        self.prepare(
            local_profile_did,
            recipient_profile_did,
            &CustodyPayload::NodeRequest(request),
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

    async fn send(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<CustodyOutboxState> {
        CollaborationCustodyMessageService::send(self, key, local_profile_did, envelope, now).await
    }
}

#[async_trait::async_trait]
impl RequestOutbox for WeakCustodyMessageService {
    fn sign(
        &self,
        local_profile_did: &str,
        recipient_profile_did: &str,
        request: CustodyNodeRequestPayload,
        now: u64,
        expires_at: u64,
    ) -> anyhow::Result<Vec<u8>> {
        RequestOutbox::sign(
            &live_service(self)?,
            local_profile_did,
            recipient_profile_did,
            request,
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
        RequestOutbox::enqueue(&live_service(self)?, key, local_profile_did, envelope, now)
    }

    fn state(&self, key: &str, now: u64) -> Option<CustodyOutboxState> {
        self.upgrade()?.outbox_state(key, now)
    }

    async fn send(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<CustodyOutboxState> {
        RequestOutbox::send(&live_service(self)?, key, local_profile_did, envelope, now).await
    }
}

fn live_service(
    weak: &WeakCustodyMessageService,
) -> anyhow::Result<CollaborationCustodyMessageService> {
    weak.upgrade()
        .ok_or_else(|| anyhow::anyhow!("custody messages have stopped"))
}

/// Asks one contact's Home whether it offers custody.
#[async_trait::async_trait]
pub(crate) trait OfferQuery: Send + Sync {
    async fn query_offer(
        &self,
        contact_profile_did: &str,
        now: u64,
    ) -> anyhow::Result<CustodyQueryOutcome>;
}

/// The message service, asking as the admin's Profile.
pub(crate) struct ProfileOfferQuery<'a> {
    pub(crate) service: &'a CollaborationCustodyMessageService,
    pub(crate) local_profile_did: &'a str,
}

#[async_trait::async_trait]
impl OfferQuery for ProfileOfferQuery<'_> {
    async fn query_offer(
        &self,
        contact_profile_did: &str,
        now: u64,
    ) -> anyhow::Result<CustodyQueryOutcome> {
        self.service
            .query_offer(self.local_profile_did, contact_profile_did, now)
            .await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FoundStatus {
    Offering,
    NotOffering,
    Unreachable,
    /// The contact's Profile cannot sign custody messages yet.
    NeedsUpdate,
}

/// One contact in Find nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FoundContact {
    pub(crate) profile_did: String,
    pub(crate) name: String,
    pub(crate) status: FoundStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) run_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) provides: Option<Vec<String>>,
    /// This Home's latest request to the contact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) request: Option<OwnerRequestState>,
}

enum OfferAnswer {
    Offer(CustodyOfferPayload),
    Status(FoundStatus),
}

/// Every contact but the admin's own Profile, with whether it offers
/// custody. A contact whose Profile cannot sign custody messages is
/// `needs_update` without a call; the others are asked at most four at a
/// time, each within the transport's timeout.
pub(crate) async fn find_nodes(
    data_dir: &Path,
    owner: &VerifiedCollaborationProfileDocument,
    contacts: &[AcceptedContact],
    offers: &dyn OfferQuery,
    now: u64,
) -> anyhow::Result<Vec<FoundContact>> {
    if !custody_messages_enabled(owner) {
        return Err(CustodyRefusal::new("messages_not_enabled").into());
    }
    let mut records = load_records(data_dir)?;
    expire_waiting(&mut records, now);
    let own_profile_did = &owner.document().profile_did;
    let contacts: Vec<&AcceptedContact> = contacts
        .iter()
        .filter(|contact| &contact.profile_did != own_profile_did)
        .collect();
    let can_answer: Vec<bool> = contacts
        .iter()
        .map(|contact| custody_messages_enabled(&contact.profile))
        .collect();
    let to_ask = contacts
        .iter()
        .enumerate()
        .filter(|(index, _)| can_answer[*index])
        .map(|(index, contact)| (index, contact.profile_did.clone()))
        .collect();
    let answers = ask_offers(offers, to_ask, contacts.len(), now).await;
    Ok(contacts
        .into_iter()
        .zip(can_answer)
        .zip(answers)
        .map(|((contact, can_answer), answer)| {
            let mut found = FoundContact {
                profile_did: contact.profile_did.clone(),
                name: contact.name.clone(),
                // Asked but not answered within the deadline: unreachable.
                status: if can_answer {
                    FoundStatus::Unreachable
                } else {
                    FoundStatus::NeedsUpdate
                },
                run_by: None,
                location: None,
                provides: None,
                request: latest_request(&records, &contact.profile_did),
            };
            match answer {
                Some(OfferAnswer::Offer(offer)) => {
                    found.status = FoundStatus::Offering;
                    found.run_by = Some(offer.run_by);
                    found.location = Some(offer.location);
                    found.provides = Some(offer.provides);
                }
                Some(OfferAnswer::Status(status)) => found.status = status,
                None => {}
            }
            found
        })
        .collect())
}

/// The answers by contact index, `None` where none came. Four workers share
/// the list, so at most four queries are in flight, and all of them stop at
/// the deadline.
async fn ask_offers(
    offers: &dyn OfferQuery,
    contacts: Vec<(usize, String)>,
    slots: usize,
    now: u64,
) -> Vec<Option<OfferAnswer>> {
    let queue = Mutex::new(contacts.into_iter());
    let answers = Mutex::new((0..slots).map(|_| None).collect::<Vec<_>>());
    let (queue, answered) = (&queue, &answers);
    let worker = || async move {
        loop {
            let next = queue.lock().unwrap_or_else(PoisonError::into_inner).next();
            let Some((index, profile_did)) = next else {
                return;
            };
            let answer = ask_offer(offers, &profile_did, now).await;
            answered.lock().unwrap_or_else(PoisonError::into_inner)[index] = Some(answer);
        }
    };
    let all = async {
        tokio::join!(worker(), worker(), worker(), worker());
    };
    if tokio::time::timeout(FIND_DEADLINE, all).await.is_err() {
        tracing::debug!("find nodes stopped at its deadline");
    }
    answers.into_inner().unwrap_or_else(PoisonError::into_inner)
}

async fn ask_offer(offers: &dyn OfferQuery, profile_did: &str, now: u64) -> OfferAnswer {
    let limit = std::time::Duration::from_millis(CUSTODY_PROVIDER_TIMEOUT_MS);
    match tokio::time::timeout(limit, offers.query_offer(profile_did, now)).await {
        Ok(Ok(CustodyQueryOutcome::Offering(message))) => match message.payload() {
            CustodyPayload::Offer(offer) => OfferAnswer::Offer(offer.clone()),
            _ => OfferAnswer::Status(FoundStatus::Unreachable),
        },
        Ok(Ok(CustodyQueryOutcome::Refused(code))) if code == WireRefusal::NEEDS_UPDATE.code() => {
            OfferAnswer::Status(FoundStatus::NeedsUpdate)
        }
        Ok(Ok(CustodyQueryOutcome::Refused(code))) => {
            tracing::debug!(%code, "a contact does not offer custody");
            OfferAnswer::Status(FoundStatus::NotOffering)
        }
        Ok(Ok(CustodyQueryOutcome::Unreachable)) => OfferAnswer::Status(FoundStatus::Unreachable),
        Ok(Err(error)) => {
            tracing::debug!(error = %format!("{error:#}"), "custody offer query failed");
            OfferAnswer::Status(FoundStatus::Unreachable)
        }
        Err(_) => {
            tracing::debug!("custody offer query timed out");
            OfferAnswer::Status(FoundStatus::Unreachable)
        }
    }
}

fn latest_request(
    records: &[OwnerRequestRecordV1],
    profile_did: &str,
) -> Option<OwnerRequestState> {
    records
        .iter()
        .filter(|record| record.recipient_profile_did == profile_did)
        .max_by_key(|record| record.created_at)
        .map(|record| record.state)
}

/// What sending a request needs from the running Home.
pub(crate) struct OwnerHost<'a> {
    pub(crate) data_dir: &'a Path,
    pub(crate) outbox: &'a dyn RequestOutbox,
    /// The admin's Profile, which signs the request.
    pub(crate) profile: &'a VerifiedCollaborationProfileDocument,
    pub(crate) contacts: &'a [AcceptedContact],
}

/// Ask the contact whose Profile is `recipient_profile_did` to be a custody
/// node for `term_days`: sign the request, keep it, queue it, and send it
/// once now. It grants nothing; the node's admin decides with a passkey.
/// The custody write lock is released before the send, so no other custody
/// write waits on the network.
pub(crate) async fn send_request(
    write: CustodyWriteGuard,
    host: &OwnerHost<'_>,
    recipient_profile_did: &str,
    term_days: u64,
    now: u64,
) -> anyhow::Result<NodeRequestOutView> {
    let data_dir = host.data_dir;
    let term_days = u16::try_from(term_days)
        .ok()
        .filter(|days| POOL_TERM_DAYS.contains(days))
        .ok_or_else(|| CustodyRefusal::new("bad_term"))?;
    if crate::custody_pool_setup::pool_installed(data_dir)? {
        return Err(CustodyRefusal::new("pool_installed").into());
    }
    let signing_key = crate::custody_pool_setup::signing_key_fingerprint(data_dir)?
        .ok_or_else(|| CustodyRefusal::new("no_signing_key"))?;
    let contact = host
        .contacts
        .iter()
        .find(|contact| contact.profile_did == recipient_profile_did)
        .ok_or_else(|| CustodyRefusal::new("not_contact"))?;
    if !custody_messages_enabled(&contact.profile) {
        return Err(CustodyRefusal::new("needs_update").into());
    }
    if !custody_messages_enabled(host.profile) {
        return Err(CustodyRefusal::new("messages_not_enabled").into());
    }
    let local_profile_did = host.profile.document().profile_did.clone();
    let recipient_home = contact.profile.sole_endpoint_did()?.to_string();
    let request_id = random_request_id()?;
    let expires_at = now.saturating_add(CustodyMessageType::NodeRequest.max_lifetime_secs());

    let (record, envelope) = with_records(data_dir, now, |records| {
        // A waiting request may still be decided until its grace ends, so a
        // second one would let two terms be approved. A node that approved
        // one term may be asked for another; the same term again is moot.
        let waiting = records.iter().any(|record| {
            record.recipient_home == recipient_home && record.state == OwnerRequestState::Waiting
        });
        let approved_term =
            latest_approval(records, &recipient_home).map(|record| record.term_days);
        if waiting || approved_term == Some(term_days) {
            return Err(CustodyRefusal::new("already_requested").into());
        }
        make_room(records)?;
        let envelope = host
            .outbox
            .sign(
                &local_profile_did,
                &contact.profile_did,
                CustodyNodeRequestPayload {
                    request_id: request_id.clone(),
                    signing_key_fingerprint_full: signing_key.full.clone(),
                    term_days,
                },
                now,
                expires_at,
            )
            .map_err(crate::custody_consent::signing_refusal)?;
        let record = OwnerRequestRecordV1 {
            request_id: request_id.clone(),
            request_sha256: format!("sha256:{}", hex::encode(Sha256::digest(&envelope))),
            local_profile_did: local_profile_did.clone(),
            recipient_profile_did: contact.profile_did.clone(),
            recipient_home: recipient_home.clone(),
            recipient_name: contact.name.clone(),
            term_days,
            created_at: now,
            expires_at,
            state: OwnerRequestState::Waiting,
            code: None,
            card: None,
            decided_at: None,
            envelope: Some(base64::engine::general_purpose::STANDARD.encode(&envelope)),
        };
        records.push(record.clone());
        Ok((record, envelope))
    })?;
    tracing::debug!("custody node request stored");

    let key = outbox_key(&request_id);
    if let Err(error) = host
        .outbox
        .enqueue(&key, &local_profile_did, envelope.clone(), now)
    {
        if let Some(state) = terminal_state_for(&error) {
            return settle(data_dir, &request_id, state, now);
        }
        tracing::warn!(
            error = %format!("{error:#}"),
            "a custody node request was not queued; the next delivery pass queues it"
        );
        return Ok(NodeRequestOutView::of(&record));
    }
    drop(write);
    match host
        .outbox
        .send(&key, &local_profile_did, envelope, now)
        .await
    {
        Ok(state @ CustodyOutboxState::Refused(_)) => {
            return settle(data_dir, &request_id, state, now);
        }
        Ok(_) => {}
        Err(error) => tracing::debug!(
            error = %format!("{error:#}"),
            "a custody node request stays queued"
        ),
    }
    Ok(NodeRequestOutView::of(&record))
}

/// Room for one more record: the oldest declined or expired one goes first,
/// then the oldest approval that a newer approval of the same Home replaced.
/// A waiting request and each Home's latest approval stay: install binds a
/// slot's term to it. A pool is never installed here, since sending refuses
/// `pool_installed` first.
fn make_room(records: &mut Vec<OwnerRequestRecordV1>) -> anyhow::Result<()> {
    if records.len() < MAX_REQUESTS {
        return Ok(());
    }
    let oldest = |evictable: &dyn Fn(&OwnerRequestRecordV1) -> bool| {
        records
            .iter()
            .enumerate()
            .filter(|(_, record)| evictable(record))
            .min_by_key(|(_, record)| record.created_at)
            .map(|(index, _)| index)
    };
    let settled = oldest(&|record| {
        matches!(
            record.state,
            OwnerRequestState::Declined | OwnerRequestState::Expired
        )
    });
    let replaced = || {
        oldest(&|record| {
            record.state == OwnerRequestState::Approved
                && latest_approval(records, &record.recipient_home)
                    .is_some_and(|latest| latest.request_id != record.request_id)
        })
    };
    match settled.or_else(replaced) {
        Some(index) => {
            records.remove(index);
            Ok(())
        }
        None => Err(CustodyRefusal::new("too_many_requests").into()),
    }
}

/// A Home's latest approval: the term its node consents to now.
fn latest_approval<'a>(
    records: &'a [OwnerRequestRecordV1],
    recipient_home: &str,
) -> Option<&'a OwnerRequestRecordV1> {
    records
        .iter()
        .filter(|record| {
            record.state == OwnerRequestState::Approved && record.recipient_home == recipient_home
        })
        .max_by_key(|record| (record.decided_at, record.created_at))
}

/// Settles a request its outbox gave up on; see [`settle_unsendable`].
fn settle(
    data_dir: &Path,
    request_id: &str,
    state: CustodyOutboxState,
    now: u64,
) -> anyhow::Result<NodeRequestOutView> {
    with_records(data_dir, now, |records| {
        let record = records
            .iter_mut()
            .find(|record| record.request_id == request_id)
            .ok_or_else(|| anyhow::anyhow!("a sent custody node request disappeared"))?;
        settle_unsendable(record, state, now);
        Ok(NodeRequestOutView::of(record))
    })
}

/// A waiting request that can no longer be sent settles once: past its
/// envelope's life it expires; refused, by the node (such as `not_admin`)
/// or by this Home's own checks, it is declined with that code.
fn settle_unsendable(record: &mut OwnerRequestRecordV1, state: CustodyOutboxState, now: u64) {
    if record.state != OwnerRequestState::Waiting {
        return;
    }
    match state {
        CustodyOutboxState::Expired => {
            record.state = OwnerRequestState::Expired;
            record.envelope = None;
        }
        CustodyOutboxState::Refused(code) => decline(record, code, now),
        CustodyOutboxState::Pending | CustodyOutboxState::Delivered => {}
    }
}

fn decline(record: &mut OwnerRequestRecordV1, code: String, now: u64) {
    tracing::debug!(%code, "a custody node request was declined");
    record.state = OwnerRequestState::Declined;
    record.code = Some(code);
    record.decided_at = Some(now);
    record.envelope = None;
}

/// A node's decision on one of this Home's requests. Checked in order: the
/// request is ours, the decision cites its exact bytes, it comes from the
/// endpoint the request went to, in time, and an approval carries that
/// node's own card. The same decision again is a no-op.
pub(crate) fn on_decision(
    inbound: &CustodyInbound<'_>,
    decision: &CustodyNodeDecisionPayload,
) -> Result<(), WireRefusal> {
    let signer = inbound.message.signer_did();
    let sender_home = inbound.sender_profile.sole_endpoint_did().ok();
    let now = inbound.now;
    let outcome = with_records(inbound.data_dir, now, |records| {
        let Some(record) = records
            .iter_mut()
            .find(|record| record.request_id == decision.request_id)
        else {
            return Ok(Err(UNKNOWN_REQUEST));
        };
        if record.request_sha256 != decision.request_sha256 {
            return Ok(Err(REQUEST_MISMATCH));
        }
        if signer != record.recipient_home
            || sender_home != Some(signer)
            || inbound.message.sender_profile_did() != record.recipient_profile_did
            || inbound.local_profile.document().profile_did != record.local_profile_did
        {
            return Ok(Err(WRONG_SENDER));
        }
        if now > record.expires_at.saturating_add(DECISION_GRACE_SECS) {
            return Ok(Err(DECISION_LATE));
        }
        let decided = match (decision.outcome, &decision.card, decision.code) {
            (CustodyNodeDecisionOutcome::Approved, Some(card), None) => {
                let card = compact_card(card);
                if !card_is_signers_node(inbound.data_dir, &card, signer) {
                    return Ok(Err(BAD_CARD));
                }
                Decided::Approved(card)
            }
            (CustodyNodeDecisionOutcome::Approved, _, _) => return Ok(Err(BAD_CARD)),
            (CustodyNodeDecisionOutcome::Declined, None, Some(code)) => {
                Decided::Declined(WireRefusal::from(code).code().to_string())
            }
            (CustodyNodeDecisionOutcome::Declined, _, _) => {
                return Ok(Err(WireRefusal::INVALID_REQUEST))
            }
        };
        Ok(match (record.state, decided) {
            (OwnerRequestState::Waiting, Decided::Approved(card)) => {
                record.state = OwnerRequestState::Approved;
                record.card = Some(card);
                record.decided_at = Some(now);
                record.envelope = None;
                tracing::debug!("a custody node approved this Home's request");
                Ok(())
            }
            (OwnerRequestState::Waiting, Decided::Declined(code)) => {
                decline(record, code, now);
                Ok(())
            }
            (OwnerRequestState::Approved, Decided::Approved(card))
                if record.card.as_ref() == Some(&card) =>
            {
                Ok(())
            }
            (OwnerRequestState::Declined, Decided::Declined(code))
                if record.code.as_ref() == Some(&code) =>
            {
                Ok(())
            }
            _ => Err(ALREADY_DECIDED),
        })
    })
    .map_err(|error| {
        tracing::debug!(error = %format!("{error:#}"), "custody node requests are unavailable");
        WireRefusal::UNAVAILABLE
    })?;
    outcome
}

enum Decided {
    Approved(String),
    Declined(String),
}

/// The card reads, names the signer's Home as its node, and is not this
/// Home's own node.
fn card_is_signers_node(data_dir: &Path, card: &str, signer: &str) -> bool {
    match crate::custody_pool_setup::read_card(data_dir, card) {
        CardView::Read { home_id, .. } => home_id == signer,
        CardView::Refused { refused } => {
            tracing::debug!(code = refused, "a custody decision's card was refused");
            false
        }
    }
}

/// The delivery-pass step of the outbox: a waiting request the node refused
/// outright is declined with its code, and one the outbox no longer knows,
/// as after a restart, is queued again from its stored bytes while it lives.
/// One this Home can no longer send settles once instead of retrying.
pub(crate) fn resume_requests(
    data_dir: &Path,
    outbox: &dyn RequestOutbox,
    now: u64,
) -> anyhow::Result<()> {
    if !present(&requests_path(data_dir))? {
        return Ok(());
    }
    with_records(data_dir, now, |records| {
        for record in records
            .iter_mut()
            .filter(|record| record.state == OwnerRequestState::Waiting)
        {
            let key = outbox_key(&record.request_id);
            match outbox.state(&key, now) {
                Some(state @ CustodyOutboxState::Refused(_)) => {
                    settle_unsendable(record, state, now)
                }
                Some(_) => {}
                None if now < record.expires_at => {
                    let Some(envelope) = stored_envelope(record) else {
                        tracing::warn!("a stored custody node request is unreadable");
                        let code = CustodyMessageRefusal::InvalidEnvelope.code().to_string();
                        settle_unsendable(record, CustodyOutboxState::Refused(code), now);
                        continue;
                    };
                    if let Err(error) =
                        outbox.enqueue(&key, &record.local_profile_did, envelope, now)
                    {
                        match terminal_state_for(&error) {
                            Some(state) => settle_unsendable(record, state, now),
                            None => tracing::debug!(
                                error = %format!("{error:#}"),
                                "a custody node request stays unqueued until the next pass"
                            ),
                        }
                    }
                }
                None => {}
            }
        }
        Ok(())
    })
}

fn stored_envelope(record: &OwnerRequestRecordV1) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(record.envelope.as_deref()?)
        .ok()
}

/// The node behind an approved request consented to its term only: a slot
/// carrying that card installs with exactly that term. Pasted cards are not
/// matched to anything.
pub(crate) fn check_install_term(
    data_dir: &Path,
    cards: &[CardInput],
    term_days: u16,
) -> anyhow::Result<()> {
    let records = load_records(data_dir)?;
    for card in cards {
        let CardInput::Remote { text } = card else {
            continue;
        };
        let compact = compact_card(text);
        // The node's latest approval is the term it consents to now.
        let consented = records
            .iter()
            .filter(|record| {
                record.state == OwnerRequestState::Approved
                    && record.card.as_deref() == Some(compact.as_str())
            })
            .max_by_key(|record| (record.decided_at, record.created_at));
        if consented.is_some_and(|record| record.term_days != term_days) {
            return Err(CustodyRefusal::new("term_changed").into());
        }
    }
    Ok(())
}

/// The sent requests for the Custody app, newest first.
pub(crate) fn node_requests_view(
    data_dir: &Path,
    now: u64,
) -> anyhow::Result<Vec<NodeRequestOutView>> {
    let mut records = load_records(data_dir)?;
    expire_waiting(&mut records, now);
    records.sort_by(|left, right| {
        (right.created_at, &right.request_id).cmp(&(left.created_at, &left.request_id))
    });
    Ok(records.iter().map(NodeRequestOutView::of).collect())
}

/// A waiting request expires once even a late decision could no longer be
/// taken.
fn expire_waiting(records: &mut [OwnerRequestRecordV1], now: u64) {
    for record in records {
        if record.state == OwnerRequestState::Waiting
            && now > record.expires_at.saturating_add(DECISION_GRACE_SECS)
        {
            record.state = OwnerRequestState::Expired;
            record.envelope = None;
        }
    }
}

/// Card text as it is kept and compared: chat and email wrap long lines, and
/// a card never contains whitespace.
fn compact_card(text: &str) -> String {
    text.chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect()
}

fn outbox_key(request_id: &str) -> String {
    format!("{REQUEST_OUTBOX_PREFIX}{request_id}")
}

fn random_request_id() -> anyhow::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).context("OS randomness unavailable for a request id")?;
    Ok(hex::encode(bytes))
}

fn requests_path(data_dir: &Path) -> std::path::PathBuf {
    protected_content_root(data_dir).join(REQUESTS_FILE)
}

/// One read-change-write of the records, under their lock. Waiting requests
/// past their last chance expire first; the file is written only when
/// something changed.
fn with_records<T>(
    data_dir: &Path,
    now: u64,
    change: impl FnOnce(&mut Vec<OwnerRequestRecordV1>) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let _guard = REQUESTS_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("custody node request lock is poisoned"))?;
    let loaded = load_records(data_dir)?;
    let mut records = loaded.clone();
    expire_waiting(&mut records, now);
    let result = change(&mut records)?;
    if records != loaded {
        store_records(data_dir, &records)?;
    }
    Ok(result)
}

fn load_records(data_dir: &Path) -> anyhow::Result<Vec<OwnerRequestRecordV1>> {
    let path = requests_path(data_dir);
    if !present(&path)? {
        return Ok(Vec::new());
    }
    let bytes = read_owner_only_file(&path, MAX_REQUESTS_FILE_BYTES, "custody node requests sent")?;
    let file: OwnerRequestsFileV1 = serde_json::from_slice(&bytes)?;
    if file.schema != REQUESTS_SCHEMA_V1 || file.requests.len() > MAX_REQUESTS {
        anyhow::bail!("custody node requests sent are not a known record");
    }
    Ok(file.requests)
}

fn store_records(data_dir: &Path, records: &[OwnerRequestRecordV1]) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(&OwnerRequestsFileV1 {
        schema: REQUESTS_SCHEMA_V1.to_string(),
        requests: records.to_vec(),
    })?;
    if bytes.len() > MAX_REQUESTS_FILE_BYTES {
        anyhow::bail!("custody node requests sent exceed their byte limit");
    }
    ensure_owner_only_dir(&protected_content_root(data_dir), "protected-content root")?;
    write_owner_only_bytes(&requests_path(data_dir), &bytes)
}

fn present(path: &Path) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(anyhow::Error::new(error).context("custody node requests file is unavailable"))
        }
    }
}

#[cfg(all(test, unix))]
pub(crate) mod tests;

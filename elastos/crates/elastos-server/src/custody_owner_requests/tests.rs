use super::*;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::collaboration_custody_messages::CustodyMessageHandler;
use crate::collaboration_discovery_runtime::tests::signed_profile;
use crate::collaboration_network::VerifiedCollaborationNetworkProfile;
use crate::collaboration_profile_authority::{
    signed_profile_document_for_test, with_signing_scope_for_test,
};
use crate::custody_consent::{lock_custody_writes, DecisionOutbox, NodeConsentHandler};
use crate::custody_consent_protocol::{
    prepare_custody_message, verify_custody_message, CustodyDeclineCode, CustodyMessageRefusal,
    CUSTODY_SIGNING_SCOPE,
};
use crate::custody_node_card::tests::{card_for_device, labelled_card};
use crate::protected_content_config::tests::{owner_only_dir, safe_ancestor_tempdir};
use elastos_runtime::signature::{generate_keypair, SigningKey};

pub(crate) const NETWORK: &str = "elastos.custody-owner-requests.test";
const NOW: u64 = 1_800_000_000;
const STORAGE: &[&str] = &["chain", "custody", "ipfs"];

fn request_lifetime() -> u64 {
    CustodyMessageType::NodeRequest.max_lifetime_secs()
}

/// Stands in for the message service: a "signed" request is its payload's
/// JSON, and each attempt finds the state the test chose.
#[derive(Default)]
struct FakeOutbox {
    queued: Mutex<Vec<(String, String, Vec<u8>)>>,
    states: Mutex<BTreeMap<String, CustodyOutboxState>>,
    /// What the immediate attempt ends in; pending when unset.
    answer: Mutex<Option<CustodyOutboxState>>,
    /// Why queueing fails, when it does.
    enqueue_failure: Mutex<Option<EnqueueFailure>>,
    enqueue_calls: AtomicUsize,
}

#[derive(Clone, Copy)]
enum EnqueueFailure {
    /// The stored envelope no longer verifies: no retry fixes it.
    Refused(CustodyMessageRefusal),
    /// This Home's own trouble, such as a full outbox: the next pass retries.
    Busy,
}

impl FakeOutbox {
    fn queued(&self) -> Vec<(String, String, Vec<u8>)> {
        self.queued.lock().unwrap().clone()
    }

    fn answer_with(&self, state: CustodyOutboxState) {
        *self.answer.lock().unwrap() = Some(state);
    }

    fn settle(&self, key: &str, state: CustodyOutboxState) {
        self.states.lock().unwrap().insert(key.to_string(), state);
    }

    fn fail_enqueue(&self, failure: Option<EnqueueFailure>) {
        *self.enqueue_failure.lock().unwrap() = failure;
    }

    fn enqueue_calls(&self) -> usize {
        self.enqueue_calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl RequestOutbox for FakeOutbox {
    fn sign(
        &self,
        local_profile_did: &str,
        recipient_profile_did: &str,
        request: CustodyNodeRequestPayload,
        now: u64,
        expires_at: u64,
    ) -> anyhow::Result<Vec<u8>> {
        assert!(
            now < expires_at,
            "a request is signed only while it can live"
        );
        Ok(serde_json::to_vec(&serde_json::json!({
            "from": local_profile_did,
            "to": recipient_profile_did,
            "request": request,
        }))?)
    }

    fn enqueue(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        _now: u64,
    ) -> anyhow::Result<()> {
        self.enqueue_calls.fetch_add(1, Ordering::SeqCst);
        match *self.enqueue_failure.lock().unwrap() {
            Some(EnqueueFailure::Refused(refusal)) => return Err(refusal.into()),
            Some(EnqueueFailure::Busy) => anyhow::bail!("custody outbox is full"),
            None => {}
        }
        // Like the service: the same key and envelope again is a no-op.
        let mut queued = self.queued.lock().unwrap();
        if queued.iter().any(|(queued_key, _, queued_envelope)| {
            queued_key == key && *queued_envelope == envelope
        }) {
            return Ok(());
        }
        queued.push((key.to_string(), local_profile_did.to_string(), envelope));
        drop(queued);
        self.settle(key, CustodyOutboxState::Pending);
        Ok(())
    }

    fn state(&self, key: &str, _now: u64) -> Option<CustodyOutboxState> {
        self.states.lock().unwrap().get(key).cloned()
    }

    async fn send(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<CustodyOutboxState> {
        RequestOutbox::enqueue(self, key, local_profile_did, envelope, now)?;
        let state = self
            .answer
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(CustodyOutboxState::Pending);
        self.settle(key, state.clone());
        Ok(state)
    }
}

/// The owner side signs no decisions; the handler only needs one to exist.
impl DecisionOutbox for FakeOutbox {
    fn sign(
        &self,
        _local_profile_did: &str,
        _owner_profile_did: &str,
        _decision: CustodyNodeDecisionPayload,
        _now: u64,
        _expires_at: u64,
    ) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("an owner signs no decisions")
    }

    fn enqueue(
        &self,
        _key: &str,
        _local_profile_did: &str,
        _envelope: Vec<u8>,
        _now: u64,
    ) -> anyhow::Result<()> {
        anyhow::bail!("an owner queues no decisions")
    }

    fn state(&self, _key: &str, _now: u64) -> Option<CustodyOutboxState> {
        None
    }
}

/// A Profile whose sole endpoint is a Home's key.
pub(crate) struct Party {
    pub(crate) device: SigningKey,
    pub(crate) profile: VerifiedCollaborationProfileDocument,
    pub(crate) name: &'static str,
}

impl Party {
    pub(crate) fn new(name: &'static str, custody_enabled: bool) -> Self {
        Self::on(name, generate_keypair().0, custody_enabled)
    }

    pub(crate) fn on(name: &'static str, device: SigningKey, custody_enabled: bool) -> Self {
        let (profile_key, _) = generate_keypair();
        let profile = signed_profile_document_for_test(
            &profile_key,
            name,
            None,
            1,
            None,
            NOW - 100,
            vec![crate::crypto::encode_signing_key_did(&device)],
        )
        .unwrap();
        let profile = if custody_enabled {
            with_signing_scope_for_test(&profile_key, &profile, CUSTODY_SIGNING_SCOPE).unwrap()
        } else {
            profile
        };
        Self {
            device,
            profile,
            name,
        }
    }

    pub(crate) fn did(&self) -> String {
        crate::crypto::encode_signing_key_did(&self.device)
    }

    pub(crate) fn profile_did(&self) -> &str {
        &self.profile.document().profile_did
    }

    pub(crate) fn contact(&self) -> AcceptedContact {
        AcceptedContact {
            profile_did: self.profile_did().to_string(),
            name: self.name.to_string(),
            profile: self.profile.clone(),
        }
    }

    /// This party's own node card, in `location`.
    pub(crate) fn card(&self, location: &str) -> String {
        card_for_device(&self.device.verifying_key(), self.name, location, STORAGE)
    }
}

/// A pool owner's Home with its signing key, and its admin's Profile.
struct Owner {
    _dir: tempfile::TempDir,
    data_dir: PathBuf,
    home: SigningKey,
    network: VerifiedCollaborationNetworkProfile,
    admin: Party,
    outbox: Arc<FakeOutbox>,
    handler: NodeConsentHandler,
}

fn owner_with(custody_enabled: bool) -> Owner {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("owner");
    owner_only_dir(&data_dir);
    let (home, _) = elastos_identity::load_or_create_did(&data_dir).unwrap();
    crate::custody_pool_setup::create_signing_key(&data_dir).unwrap();
    let (trusted, _) = generate_keypair();
    let outbox = Arc::new(FakeOutbox::default());
    let handler = NodeConsentHandler::new(outbox.clone(), Arc::new(|| None))
        .with_owner_requests(data_dir.clone(), outbox.clone());
    Owner {
        _dir: dir,
        admin: Party::on("Olivia", home.clone(), custody_enabled),
        data_dir,
        home,
        network: signed_profile(NETWORK, &trusted, vec![]),
        outbox,
        handler,
    }
}

fn owner() -> Owner {
    owner_with(true)
}

fn approval(sent: &NodeRequestOutView, card: String) -> CustodyNodeDecisionPayload {
    CustodyNodeDecisionPayload {
        card: Some(card),
        code: None,
        outcome: CustodyNodeDecisionOutcome::Approved,
        request_id: sent.request_id.clone(),
        request_sha256: sent.request_sha256.clone(),
    }
}

fn declined(sent: &NodeRequestOutView, code: CustodyDeclineCode) -> CustodyNodeDecisionPayload {
    CustodyNodeDecisionPayload {
        card: None,
        code: Some(code),
        outcome: CustodyNodeDecisionOutcome::Declined,
        request_id: sent.request_id.clone(),
        request_sha256: sent.request_sha256.clone(),
    }
}

fn refusal(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<CustodyRefusal>()
        .unwrap_or_else(|| panic!("not a custody refusal: {error:#}"))
        .code()
}

impl Owner {
    fn host<'a>(&'a self, contacts: &'a [AcceptedContact]) -> OwnerHost<'a> {
        OwnerHost {
            data_dir: &self.data_dir,
            outbox: self.outbox.as_ref(),
            profile: &self.admin.profile,
            contacts,
        }
    }

    async fn send(
        &self,
        contacts: &[AcceptedContact],
        to: &str,
        term_days: u64,
        now: u64,
    ) -> anyhow::Result<NodeRequestOutView> {
        send_request(
            lock_custody_writes().await,
            &self.host(contacts),
            to,
            term_days,
            now,
        )
        .await
    }

    /// `node` decides, as the message plane hands it over once it verified
    /// the sender as an accepted contact.
    fn decide(
        &self,
        node: &Party,
        decision: CustodyNodeDecisionPayload,
        now: u64,
    ) -> Result<(), WireRefusal> {
        let envelope = prepare_custody_message(
            &node.device,
            &self.network,
            &node.profile,
            self.admin.profile_did(),
            &CustodyPayload::NodeDecision(decision.clone()),
            now,
            now + 3_600,
        )
        .unwrap();
        let message = verify_custody_message(
            &envelope,
            &self.network,
            &node.profile,
            Some(&self.admin.profile),
            CustodyMessageType::NodeDecision,
            now,
        )
        .unwrap();
        self.handler.on_decision(
            &CustodyInbound {
                data_dir: &self.data_dir,
                principal_id: "person:local:owner",
                localhost_root: "localhost://owner",
                local_profile: &self.admin.profile,
                sender_profile: &node.profile,
                sender_display_name: node.name,
                message: &message,
                envelope: &envelope,
                now,
            },
            &decision,
        )
    }

    fn requests(&self, now: u64) -> Vec<NodeRequestOutView> {
        node_requests_view(&self.data_dir, now).unwrap()
    }

    fn only_request(&self, now: u64) -> NodeRequestOutView {
        let requests = self.requests(now);
        assert_eq!(requests.len(), 1, "{requests:?}");
        requests.into_iter().next().unwrap()
    }
}

/// Plants an approved request for `card` at `term_days`, as a node's
/// approval leaves it.
pub(crate) fn plant_approved(data_dir: &Path, card: &str, term_days: u16) {
    let mut records = load_records(data_dir).unwrap();
    let seed = u8::try_from(records.len()).unwrap();
    let record = OwnerRequestRecordV1 {
        request_id: hex::encode([0x5a ^ seed; 16]),
        request_sha256: format!("sha256:{}", hex::encode([0x5b; 32])),
        local_profile_did: "did:key:z6MkOwnerProfile".to_string(),
        recipient_profile_did: "did:key:z6MkNodeProfile".to_string(),
        recipient_home: "did:key:z6MkNodeHome".to_string(),
        recipient_name: "Bob".to_string(),
        term_days,
        created_at: NOW,
        expires_at: NOW + request_lifetime(),
        state: OwnerRequestState::Approved,
        code: None,
        card: Some(card.to_string()),
        decided_at: Some(NOW + 60 + u64::from(seed)),
        envelope: None,
    };
    records.push(record);
    store_records(data_dir, &records).unwrap();
}

#[tokio::test]
async fn request_goes_out_signed_and_an_approval_fills_its_card() {
    let owner = owner();
    let bob = Party::new("Bob", true);
    let contacts = [bob.contact()];

    let sent = owner
        .send(&contacts, bob.profile_did(), 365, NOW)
        .await
        .unwrap();
    assert_eq!(sent.state, OwnerRequestState::Waiting);
    assert_eq!(sent.recipient_profile_did, bob.profile_did());
    assert_eq!(sent.recipient_home, bob.did());
    assert_eq!(sent.recipient_name, "Bob");
    assert_eq!(sent.term_days, 365);
    assert_eq!(sent.created_at, NOW);
    assert_eq!(sent.expires_at, NOW + request_lifetime());
    assert_eq!(sent.request_id.len(), 32);
    assert!(sent
        .request_id
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_eq!(sent.card, None);

    // Queued under its own key, signed by the admin's Profile, carrying the
    // pool signing key's full fingerprint.
    let queued = owner.outbox.queued();
    assert_eq!(queued.len(), 1);
    let (key, from, envelope) = &queued[0];
    assert_eq!(key, &format!("custody-request:{}", sent.request_id));
    assert_eq!(from, owner.admin.profile_did());
    assert_eq!(
        sent.request_sha256,
        format!("sha256:{}", hex::encode(Sha256::digest(envelope)))
    );
    let signed: serde_json::Value = serde_json::from_slice(envelope).unwrap();
    let fingerprint = crate::custody_pool_setup::signing_key_fingerprint(&owner.data_dir)
        .unwrap()
        .unwrap();
    assert_eq!(signed["to"], bob.profile_did());
    assert_eq!(
        signed["request"],
        serde_json::json!({
            "request_id": sent.request_id,
            "signing_key_fingerprint_full": fingerprint.full,
            "term_days": 365,
        })
    );
    assert_eq!(owner.only_request(NOW), sent);

    let card = bob.card("Oslo");
    owner
        .decide(&bob, approval(&sent, card.clone()), NOW + 60)
        .unwrap();
    let approved = owner.only_request(NOW + 60);
    assert_eq!(approved.state, OwnerRequestState::Approved);
    assert_eq!(approved.card.as_deref(), Some(card.as_str()));
    assert_eq!(approved.decided_at, Some(NOW + 60));
    assert_eq!(approved.code, None);

    // The node's retry of the same decision settles without a change.
    owner
        .decide(&bob, approval(&sent, card.clone()), NOW + 120)
        .unwrap();
    assert_eq!(owner.only_request(NOW + 120), approved);

    // A different decision on a decided request is refused.
    assert_eq!(
        owner.decide(
            &bob,
            declined(&sent, CustodyDeclineCode::Declined),
            NOW + 180
        ),
        Err(ALREADY_DECIDED)
    );
    assert_eq!(
        owner.decide(&bob, approval(&sent, bob.card("Kyiv")), NOW + 180),
        Err(ALREADY_DECIDED)
    );
    assert_eq!(owner.only_request(NOW + 180), approved);
}

#[tokio::test]
async fn decision_must_name_a_known_request_by_its_exact_bytes() {
    let owner = owner();
    let bob = Party::new("Bob", true);
    let contacts = [bob.contact()];
    let sent = owner
        .send(&contacts, bob.profile_did(), 365, NOW)
        .await
        .unwrap();

    let mut unknown = approval(&sent, bob.card("Oslo"));
    unknown.request_id = hex::encode([0x77; 16]);
    assert_eq!(owner.decide(&bob, unknown, NOW + 60), Err(UNKNOWN_REQUEST));

    let mut mismatched = approval(&sent, bob.card("Oslo"));
    mismatched.request_sha256 = format!("sha256:{}", hex::encode([0x11; 32]));
    assert_eq!(
        owner.decide(&bob, mismatched, NOW + 60),
        Err(REQUEST_MISMATCH)
    );
    assert_eq!(
        owner.only_request(NOW + 60).state,
        OwnerRequestState::Waiting
    );
}

#[tokio::test]
async fn only_the_requested_node_decides_and_only_with_its_own_card() {
    let owner = owner();
    let bob = Party::new("Bob", true);
    let carol = Party::new("Carol", true);
    // A contact whose endpoint is this owner's own Home.
    let echo = Party::on("Echo", owner.home.clone(), true);
    let contacts = [bob.contact(), carol.contact(), echo.contact()];
    let to_bob = owner
        .send(&contacts, bob.profile_did(), 365, NOW)
        .await
        .unwrap();
    let to_echo = owner
        .send(&contacts, echo.profile_did(), 365, NOW)
        .await
        .unwrap();

    // Another contact cannot answer for Bob, even with its own valid card.
    assert_eq!(
        owner.decide(&carol, approval(&to_bob, carol.card("Kyiv")), NOW + 60),
        Err(WRONG_SENDER)
    );
    assert_eq!(
        owner.decide(
            &carol,
            declined(&to_bob, CustodyDeclineCode::Declined),
            NOW + 60
        ),
        Err(WRONG_SENDER)
    );
    // Bob's approval must carry Bob's node, not another one.
    assert_eq!(
        owner.decide(&bob, approval(&to_bob, carol.card("Kyiv")), NOW + 60),
        Err(BAD_CARD)
    );
    assert_eq!(
        owner.decide(
            &bob,
            approval(&to_bob, labelled_card("Bob", "Oslo", STORAGE)),
            NOW + 60
        ),
        Err(BAD_CARD)
    );
    // A card for this Home's own node never fills a slot.
    assert_eq!(
        owner.decide(&echo, approval(&to_echo, echo.card("Paris")), NOW + 60),
        Err(BAD_CARD)
    );
    assert!(owner
        .requests(NOW + 60)
        .iter()
        .all(|request| request.state == OwnerRequestState::Waiting));
}

#[tokio::test]
async fn decision_is_taken_up_to_an_hour_after_its_request_expired() {
    let owner = owner();
    let bob = Party::new("Bob", true);
    let carol = Party::new("Carol", true);
    let contacts = [bob.contact(), carol.contact()];
    let to_bob = owner
        .send(&contacts, bob.profile_did(), 365, NOW)
        .await
        .unwrap();
    let to_carol = owner
        .send(&contacts, carol.profile_did(), 365, NOW)
        .await
        .unwrap();
    let last_chance = to_bob.expires_at + 3_600;

    owner
        .decide(&bob, approval(&to_bob, bob.card("Oslo")), last_chance)
        .unwrap();
    assert_eq!(
        owner.decide(
            &carol,
            approval(&to_carol, carol.card("Kyiv")),
            last_chance + 1
        ),
        Err(DECISION_LATE)
    );
    let states: BTreeMap<String, OwnerRequestState> = owner
        .requests(last_chance + 1)
        .into_iter()
        .map(|request| (request.recipient_name, request.state))
        .collect();
    assert_eq!(states["Bob"], OwnerRequestState::Approved);
    assert_eq!(states["Carol"], OwnerRequestState::Expired);
}

#[tokio::test]
async fn node_refusals_and_declines_are_kept_with_their_code() {
    let owner = owner();
    let bob = Party::new("Bob", true);
    let carol = Party::new("Carol", true);
    let dave = Party::new("Dave", true);
    let contacts = [bob.contact(), carol.contact(), dave.contact()];

    // Bob's Profile is not his Home's admin: his Home refuses the request.
    owner
        .outbox
        .answer_with(CustodyOutboxState::Refused("not_admin".to_string()));
    let to_bob = owner
        .send(&contacts, bob.profile_did(), 365, NOW)
        .await
        .unwrap();
    assert_eq!(to_bob.state, OwnerRequestState::Declined);
    assert_eq!(to_bob.code.as_deref(), Some("not_admin"));
    assert_eq!(to_bob.decided_at, Some(NOW));

    // A refusal the delivery pass finds later settles the same way.
    *owner.outbox.answer.lock().unwrap() = None;
    let to_carol = owner
        .send(&contacts, carol.profile_did(), 365, NOW)
        .await
        .unwrap();
    assert_eq!(to_carol.state, OwnerRequestState::Waiting);
    owner.outbox.settle(
        &format!("custody-request:{}", to_carol.request_id),
        CustodyOutboxState::Refused("already_serving".to_string()),
    );
    owner.handler.before_delivery_pass(NOW + 30);

    // A signed decline carries its code too.
    let to_dave = owner
        .send(&contacts, dave.profile_did(), 365, NOW)
        .await
        .unwrap();
    owner
        .decide(
            &dave,
            declined(&to_dave, CustodyDeclineCode::NotAdmin),
            NOW + 60,
        )
        .unwrap();
    owner
        .decide(
            &dave,
            declined(&to_dave, CustodyDeclineCode::NotAdmin),
            NOW + 90,
        )
        .unwrap();

    let codes: BTreeMap<String, (OwnerRequestState, Option<String>)> = owner
        .requests(NOW + 90)
        .into_iter()
        .map(|request| (request.recipient_name, (request.state, request.code)))
        .collect();
    let declined_with = |code: &str| (OwnerRequestState::Declined, Some(code.to_string()));
    assert_eq!(codes["Bob"], declined_with("not_admin"));
    assert_eq!(codes["Carol"], declined_with("already_serving"));
    assert_eq!(codes["Dave"], declined_with("not_admin"));
}

#[tokio::test]
async fn send_refuses_what_it_cannot_ask() {
    let owner = owner();
    let bob = Party::new("Bob", true);
    let stale = Party::new("Stale", false);
    let stranger = Party::new("Stranger", true);
    let contacts = [bob.contact(), stale.contact()];

    for term_days in [0, 30, 366, u64::from(u16::MAX) + 365] {
        let error = owner
            .send(&contacts, bob.profile_did(), term_days, NOW)
            .await
            .unwrap_err();
        assert_eq!(refusal(&error), "bad_term", "{term_days}");
    }
    let error = owner
        .send(&contacts, stranger.profile_did(), 365, NOW)
        .await
        .unwrap_err();
    assert_eq!(refusal(&error), "not_contact");
    let error = owner
        .send(&contacts, stale.profile_did(), 365, NOW)
        .await
        .unwrap_err();
    assert_eq!(refusal(&error), "needs_update");

    let unscoped = owner_with(false);
    let error = unscoped
        .send(&contacts, bob.profile_did(), 365, NOW)
        .await
        .unwrap_err();
    assert_eq!(refusal(&error), "messages_not_enabled");

    let keyless = owner_with(true);
    std::fs::remove_file(crate::custody_pool_setup::policy_authority_key_path(
        &keyless.data_dir,
    ))
    .unwrap();
    let error = keyless
        .send(&contacts, bob.profile_did(), 365, NOW)
        .await
        .unwrap_err();
    assert_eq!(refusal(&error), "no_signing_key");

    for refused in [&owner, &unscoped, &keyless] {
        assert!(refused.requests(NOW).is_empty());
        assert!(refused.outbox.queued().is_empty());
    }
}

#[tokio::test]
async fn an_installed_pool_takes_no_new_requests_but_keeps_late_answers() {
    let owner = owner();
    let bob = Party::new("Bob", true);
    let carol = Party::new("Carol", true);
    let contacts = [bob.contact(), carol.contact()];
    let to_bob = owner
        .send(&contacts, bob.profile_did(), 365, NOW)
        .await
        .unwrap();

    let pool =
        crate::protected_content_runtime::runtime_custody_composition_config_path(&owner.data_dir);
    std::fs::write(&pool, b"{}").unwrap();
    let error = owner
        .send(&contacts, carol.profile_did(), 365, NOW)
        .await
        .unwrap_err();
    assert_eq!(refusal(&error), "pool_installed");

    // The node's answer is still kept, so the app can show it.
    owner
        .decide(&bob, approval(&to_bob, bob.card("Oslo")), NOW + 60)
        .unwrap();
    assert_eq!(
        owner.only_request(NOW + 60).state,
        OwnerRequestState::Approved
    );
}

#[tokio::test]
async fn one_live_request_per_node_home() {
    let owner = owner();
    let bob = Party::new("Bob", true);
    let carol = Party::new("Carol", true);
    let contacts = [bob.contact(), carol.contact()];
    let to_bob = owner
        .send(&contacts, bob.profile_did(), 365, NOW)
        .await
        .unwrap();
    let error = owner
        .send(&contacts, bob.profile_did(), 730, NOW + 10)
        .await
        .unwrap_err();
    assert_eq!(refusal(&error), "already_requested");

    // Declined: Bob may be asked again.
    owner
        .decide(
            &bob,
            declined(&to_bob, CustodyDeclineCode::Declined),
            NOW + 20,
        )
        .unwrap();
    let again = owner
        .send(&contacts, bob.profile_did(), 730, NOW + 30)
        .await
        .unwrap();
    // Approved for 730 days: asking for the same term again is refused...
    owner
        .decide(&bob, approval(&again, bob.card("Oslo")), NOW + 40)
        .unwrap();
    let error = owner
        .send(&contacts, bob.profile_did(), 730, NOW + 50)
        .await
        .unwrap_err();
    assert_eq!(refusal(&error), "already_requested");
    // ...and asking for another term is a new request.
    owner
        .send(&contacts, bob.profile_did(), 365, NOW + 60)
        .await
        .unwrap();
    // While that one waits, Bob is asked nothing more.
    for term_days in [182, 365, 730] {
        let error = owner
            .send(&contacts, bob.profile_did(), term_days, NOW + 70)
            .await
            .unwrap_err();
        assert_eq!(refusal(&error), "already_requested", "{term_days}");
    }

    // A request whose envelope ran out may still be decided for an hour:
    // until then, a second request with another term is refused.
    let to_carol = owner
        .send(&contacts, carol.profile_did(), 365, NOW)
        .await
        .unwrap();
    let last_chance = to_carol.expires_at + 3_600;
    for now in [to_carol.expires_at, last_chance] {
        let error = owner
            .send(&contacts, carol.profile_did(), 730, now)
            .await
            .unwrap_err();
        assert_eq!(refusal(&error), "already_requested", "{now}");
    }
    owner
        .send(&contacts, carol.profile_did(), 730, last_chance + 1)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_full_request_list_makes_room_from_an_approval_a_newer_one_replaced() {
    let owner = owner();
    let bob = Party::new("Bob", true);
    let late = Party::new("Late", true);
    let others: Vec<Party> = (0..15).map(|_| Party::new("Node", true)).collect();
    let mut contacts: Vec<AcceptedContact> = others.iter().map(Party::contact).collect();
    contacts.push(bob.contact());
    contacts.push(late.contact());
    let first = owner
        .send(&contacts, bob.profile_did(), 182, NOW)
        .await
        .unwrap();
    owner
        .decide(&bob, approval(&first, bob.card("Oslo")), NOW + 1)
        .unwrap();
    let second = owner
        .send(&contacts, bob.profile_did(), 365, NOW + 2)
        .await
        .unwrap();
    owner
        .decide(&bob, approval(&second, bob.card("Oslo")), NOW + 3)
        .unwrap();
    for node in &others[..14] {
        owner
            .send(&contacts, node.profile_did(), 365, NOW + 4)
            .await
            .unwrap();
    }
    assert_eq!(owner.requests(NOW + 4).len(), 16);
    owner
        .send(&contacts, others[14].profile_did(), 365, NOW + 5)
        .await
        .unwrap();
    let kept: Vec<String> = owner
        .requests(NOW + 5)
        .into_iter()
        .map(|request| request.request_id)
        .collect();
    assert_eq!(kept.len(), 16);
    assert!(!kept.contains(&first.request_id));
    assert!(kept.contains(&second.request_id));
    // Bob's latest approval is never given up while no pool is installed.
    let error = owner
        .send(&contacts, late.profile_did(), 365, NOW + 6)
        .await
        .unwrap_err();
    assert_eq!(refusal(&error), "too_many_requests");
}

#[tokio::test]
async fn at_most_sixteen_requests_and_only_settled_ones_make_room() {
    let owner = owner();
    let nodes: Vec<Party> = (0..17).map(|_| Party::new("Node", true)).collect();
    let contacts: Vec<AcceptedContact> = nodes.iter().map(Party::contact).collect();
    let mut sent = Vec::new();
    for node in &nodes[..16] {
        sent.push(
            owner
                .send(&contacts, node.profile_did(), 365, NOW)
                .await
                .unwrap(),
        );
    }
    let error = owner
        .send(&contacts, nodes[16].profile_did(), 365, NOW)
        .await
        .unwrap_err();
    assert_eq!(refusal(&error), "too_many_requests");
    assert_eq!(owner.requests(NOW).len(), 16);

    // An approval makes no room; a decline does, and it goes first.
    owner
        .decide(
            &nodes[0],
            approval(&sent[0], nodes[0].card("Oslo")),
            NOW + 1,
        )
        .unwrap();
    let error = owner
        .send(&contacts, nodes[16].profile_did(), 365, NOW + 2)
        .await
        .unwrap_err();
    assert_eq!(refusal(&error), "too_many_requests");
    owner
        .decide(
            &nodes[1],
            declined(&sent[1], CustodyDeclineCode::Declined),
            NOW + 3,
        )
        .unwrap();
    owner
        .send(&contacts, nodes[16].profile_did(), 365, NOW + 4)
        .await
        .unwrap();
    let requests = owner.requests(NOW + 4);
    assert_eq!(requests.len(), 16);
    assert!(!requests
        .iter()
        .any(|request| request.request_id == sent[1].request_id));
    assert!(requests
        .iter()
        .any(|request| request.request_id == sent[0].request_id));
}

#[tokio::test]
async fn a_restart_queues_a_waiting_request_again_from_its_stored_bytes() {
    let owner = owner();
    let bob = Party::new("Bob", true);
    let carol = Party::new("Carol", true);
    let contacts = [bob.contact(), carol.contact()];
    let to_bob = owner
        .send(&contacts, bob.profile_did(), 365, NOW)
        .await
        .unwrap();
    let to_carol = owner
        .send(&contacts, carol.profile_did(), 365, NOW)
        .await
        .unwrap();
    owner
        .decide(
            &carol,
            declined(&to_carol, CustodyDeclineCode::Declined),
            NOW + 10,
        )
        .unwrap();
    let sent_bytes = owner.outbox.queued()[0].clone();

    // After a restart the outbox is empty: only Bob's waiting request goes
    // out again, byte for byte.
    let restarted = FakeOutbox::default();
    resume_requests(&owner.data_dir, &restarted, NOW + 20).unwrap();
    assert_eq!(restarted.queued(), vec![sent_bytes]);
    // Once queued, a pass leaves it alone.
    resume_requests(&owner.data_dir, &restarted, NOW + 40).unwrap();
    assert_eq!(restarted.queued().len(), 1);

    // An envelope that ran out is not sent again.
    let later = FakeOutbox::default();
    resume_requests(&owner.data_dir, &later, to_bob.expires_at).unwrap();
    assert!(later.queued().is_empty());

    // A Home that never sent a request has nothing to queue.
    let fresh = owner_with(true);
    resume_requests(&fresh.data_dir, &later, NOW).unwrap();
    assert!(later.queued().is_empty());
}

/// Answers offer queries after a short wait, counting how many run at once.
struct CountingOffers {
    network: VerifiedCollaborationNetworkProfile,
    owner_profile: VerifiedCollaborationProfileDocument,
    nodes: BTreeMap<String, (Party, &'static str)>,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
    asked: Mutex<Vec<String>>,
    delay: std::time::Duration,
}

impl CountingOffers {
    fn new(owner: &Owner, nodes: BTreeMap<String, (Party, &'static str)>) -> Self {
        Self {
            network: owner.network.clone(),
            owner_profile: owner.admin.profile.clone(),
            nodes,
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            asked: Mutex::new(Vec::new()),
            delay: std::time::Duration::from_millis(20),
        }
    }
}

#[async_trait::async_trait]
impl OfferQuery for CountingOffers {
    async fn query_offer(
        &self,
        contact_profile_did: &str,
        now: u64,
    ) -> anyhow::Result<CustodyQueryOutcome> {
        let running = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(running, Ordering::SeqCst);
        self.asked
            .lock()
            .unwrap()
            .push(contact_profile_did.to_string());
        tokio::time::sleep(self.delay).await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        let (node, answer) = &self.nodes[contact_profile_did];
        Ok(match *answer {
            "offering" => {
                let offer = CustodyPayload::Offer(CustodyOfferPayload {
                    location: "Oslo".to_string(),
                    provides: vec!["chain".to_string(), "custody".to_string()],
                    run_by: node.name.to_string(),
                });
                let envelope = prepare_custody_message(
                    &node.device,
                    &self.network,
                    &node.profile,
                    self.owner_profile.document().profile_did.as_str(),
                    &offer,
                    now,
                    now + 60,
                )?;
                CustodyQueryOutcome::Offering(Box::new(verify_custody_message(
                    &envelope,
                    &self.network,
                    &node.profile,
                    Some(&self.owner_profile),
                    CustodyMessageType::Offer,
                    now,
                )?))
            }
            "unreachable" => CustodyQueryOutcome::Unreachable,
            "failing" => anyhow::bail!("the custody plane failed"),
            code => CustodyQueryOutcome::Refused(code.to_string()),
        })
    }
}

#[tokio::test]
async fn find_asks_at_most_four_contacts_at_once_and_reads_needs_update_locally() {
    let owner = owner();
    let answers = [
        "offering",
        "offering",
        "not_offering",
        "not_admin",
        "unreachable",
        "failing",
        "needs_update",
        "offering",
        "offering",
        "offering",
    ];
    let mut nodes = BTreeMap::new();
    let mut contacts = vec![owner.admin.contact()];
    for answer in answers {
        let node = Party::new("Node", true);
        contacts.push(node.contact());
        nodes.insert(node.profile_did().to_string(), (node, answer));
    }
    let stale = Party::new("Stale", false);
    contacts.push(stale.contact());
    let offering = contacts[1].profile_did.clone();
    owner.send(&contacts, &offering, 365, NOW).await.unwrap();
    let offers = CountingOffers::new(&owner, nodes);

    let found = find_nodes(
        &owner.data_dir,
        &owner.admin.profile,
        &contacts,
        &offers,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(offers.peak.load(Ordering::SeqCst), 4);
    // The admin's own Profile and a contact that cannot sign are not asked.
    let mut asked = offers.asked.lock().unwrap().clone();
    asked.sort();
    let mut expected: Vec<String> = contacts[1..=answers.len()]
        .iter()
        .map(|contact| contact.profile_did.clone())
        .collect();
    expected.sort();
    assert_eq!(asked, expected);

    assert_eq!(found.len(), answers.len() + 1);
    let statuses: Vec<FoundStatus> = found.iter().map(|contact| contact.status).collect();
    use FoundStatus::*;
    assert_eq!(
        statuses,
        [
            Offering,
            Offering,
            NotOffering,
            NotOffering,
            Unreachable,
            Unreachable,
            NeedsUpdate,
            Offering,
            Offering,
            Offering,
            NeedsUpdate,
        ]
    );
    for (found, contact) in found.iter().zip(&contacts[1..]) {
        assert_eq!(found.profile_did, contact.profile_did);
        assert_eq!(found.name, contact.name);
    }
    let first = &found[0];
    assert_eq!(first.run_by.as_deref(), Some("Node"));
    assert_eq!(first.location.as_deref(), Some("Oslo"));
    assert_eq!(
        first.provides.as_deref(),
        Some(&["chain".to_string(), "custody".to_string()][..])
    );
    assert_eq!(first.request, Some(OwnerRequestState::Waiting));
    assert!(found[1..].iter().all(|contact| contact.request.is_none()));
    assert!(found[2..7]
        .iter()
        .all(|contact| contact.run_by.is_none() && contact.provides.is_none()));
    assert_eq!(
        serde_json::to_value(&found[10]).unwrap(),
        serde_json::json!({
            "profile_did": stale.profile_did(),
            "name": "Stale",
            "status": "needs_update",
        })
    );
}

#[tokio::test]
async fn find_needs_the_admins_own_profile_to_sign_custody_messages() {
    let owner = owner_with(false);
    let bob = Party::new("Bob", true);
    let offers = CountingOffers::new(&owner, BTreeMap::new());
    let error = find_nodes(
        &owner.data_dir,
        &owner.admin.profile,
        &[bob.contact()],
        &offers,
        NOW,
    )
    .await
    .unwrap_err();
    assert_eq!(refusal(&error), "messages_not_enabled");
    assert!(offers.asked.lock().unwrap().is_empty());
}

#[test]
fn install_keeps_the_term_an_approving_node_consented_to() {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("owner");
    owner_only_dir(&data_dir);
    let consented = labelled_card("Bob", "Oslo", STORAGE);
    let pasted = labelled_card("Carol", "Kyiv", STORAGE);
    let remote = |text: &str| CardInput::Remote {
        text: text.to_string(),
    };

    // No request was ever sent: nothing to match.
    check_install_term(&data_dir, &[remote(&consented)], 182).unwrap();

    plant_approved(&data_dir, &consented, 365);
    check_install_term(&data_dir, &[remote(&pasted), remote(&consented)], 365).unwrap();
    check_install_term(&data_dir, &[remote(&pasted), CardInput::ThisHome], 182).unwrap();
    let wrapped: String = consented
        .as_bytes()
        .chunks(40)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    for cards in [
        vec![remote(&consented)],
        vec![remote(&pasted), remote(&wrapped)],
    ] {
        let error = check_install_term(&data_dir, &cards, 182).unwrap_err();
        assert_eq!(refusal(&error), "term_changed");
    }
}

#[test]
fn records_file_is_owner_only_and_strict() {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("owner");
    owner_only_dir(&data_dir);
    assert!(node_requests_view(&data_dir, NOW).unwrap().is_empty());
    plant_approved(&data_dir, &labelled_card("Bob", "Oslo", STORAGE), 365);
    let path = requests_path(&data_dir);
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(file["schema"], REQUESTS_SCHEMA_V1);
    file["requests"][0]["extra"] = serde_json::json!(1);
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    assert!(node_requests_view(&data_dir, NOW).is_err());
}

#[tokio::test]
async fn a_request_over_carrier_comes_back_approved_with_the_node_card() {
    use crate::collaboration_custody_messages::ensure_custody_signing_scope;
    use crate::collaboration_discovery_runtime::tests::durable_profile_peer_pair;
    use crate::custody_consent::{approve, set_offer, NodeHost};
    use crate::protected_content_config::tests::install_successful_provision_script;

    let dir = safe_ancestor_tempdir();
    let pair = durable_profile_peer_pair(dir.path()).await;
    let now = crate::auth::now_ts();
    let (owner_root, node_root) = (dir.path().join("a"), dir.path().join("b"));
    std::fs::write(node_root.join("config.toml"), "protected_content = true\n").unwrap();
    for (identity, data_dir) in [
        (&pair.identity_a, &owner_root),
        (&pair.identity_b, &node_root),
    ] {
        ensure_custody_signing_scope(
            data_dir,
            &identity.principal_id,
            &identity.localhost_root,
            &identity.proof_binding_id,
            now,
        )
        .unwrap();
    }
    // Each learns the other's enabled Profile, as a Profile update brings it.
    for (store, identity, data_dir) in [
        (&pair.store_a, &pair.identity_b, &node_root),
        (&pair.store_b, &pair.identity_a, &owner_root),
    ] {
        let segment = crate::collaboration_profile_authority::profile_chain_segment(
            data_dir,
            &identity.principal_id,
            &identity.localhost_root,
        )
        .unwrap()
        .unwrap();
        let bytes = segment
            .iter()
            .map(|signed| serde_json::to_vec(signed).unwrap())
            .collect::<Vec<_>>();
        store
            .apply_accepted_profile_chain(
                &bytes,
                &crate::crypto::encode_signing_key_did(&identity.device_key),
                now,
            )
            .unwrap();
    }
    pair.service_a
        .register_runtime_owned_contexts(&owner_root)
        .unwrap();
    pair.service_b
        .register_runtime_owned_contexts(&node_root)
        .unwrap();
    let owner = pair.service_a.custody_message_service();
    let node = pair.service_b.custody_message_service();
    owner.set_handler(Arc::new(
        NodeConsentHandler::new(Arc::new(owner.downgrade()), Arc::new(|| None))
            .with_owner_requests(owner_root.clone(), Arc::new(owner.downgrade()))
            .with_pool_notices(owner_root.clone(), Arc::new(owner.downgrade())),
    ));
    let endpoint = pair._node_b.endpoint.clone();
    let ticket = crate::carrier::carrier_connect_ticket(&endpoint);
    node.set_handler(Arc::new(NodeConsentHandler::new(
        Arc::new(node.downgrade()),
        Arc::new(move || Some(crate::carrier::carrier_connect_ticket(&endpoint))),
    )));
    let owner_profile = crate::collaboration_profile_authority::load_profile_authority(
        &owner_root,
        &pair.identity_a.principal_id,
        &pair.identity_a.localhost_root,
    )
    .unwrap()
    .unwrap();
    let node_profile = pair.identity_b.profile.document().profile_did.clone();
    let node_home = crate::crypto::encode_signing_key_did(&pair.identity_b.device_key);
    crate::custody_pool_setup::create_signing_key(&owner_root).unwrap();
    // #388 A1: a node Home is a WCI-operated host.
    crate::host_trust::seed_for_test(&node_root, true);
    let write = lock_custody_writes().await;
    set_offer(&write, &node_root, None, true, "Bob", "Porto").unwrap();

    let contacts = accepted_contacts(&pair.store_a).unwrap();
    let offers = ProfileOfferQuery {
        service: &owner,
        local_profile_did: &owner_profile.document().profile_did,
    };
    let found = find_nodes(&owner_root, &owner_profile, &contacts, &offers, now)
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].profile_did, node_profile);
    assert_eq!(found[0].status, FoundStatus::Offering);
    assert_eq!(found[0].run_by.as_deref(), Some("Bob"));
    assert_eq!(found[0].location.as_deref(), Some("Porto"));

    let host = OwnerHost {
        data_dir: &owner_root,
        outbox: &owner,
        profile: &owner_profile,
        contacts: &contacts,
    };
    drop(write);
    let sent = send_request(lock_custody_writes().await, &host, &node_profile, 182, now)
        .await
        .unwrap();
    assert_eq!(sent.state, OwnerRequestState::Waiting);
    assert_eq!(sent.recipient_home, node_home);
    assert_eq!(
        owner.outbox_state(&format!("custody-request:{}", sent.request_id), now),
        Some(CustodyOutboxState::Delivered)
    );
    let waiting = crate::custody_consent::inbox_requests(&node_root, &node_profile, now).unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].request.request_id, sent.request_id);
    assert_eq!(waiting[0].request.request_sha256, sent.request_sha256);
    assert_eq!(waiting[0].request.term_days, 182);

    let owner_issuer = format!(
        "0x{}",
        hex::encode(pair.identity_a.device_key.verifying_key().to_bytes())
    );
    install_successful_provision_script(dir.path(), &node_root, &owner_issuer, 0x48);
    let node_host = NodeHost {
        data_dir: &node_root,
        registry: None,
        outbox: &node,
        ticket: Some(ticket),
    };
    let write = lock_custody_writes().await;
    approve(&write, &node_host, &node_profile, &sent.request_id, now)
        .await
        .unwrap();
    node.deliver_pending(now).await.unwrap();

    let approved = node_requests_view(&owner_root, now).unwrap();
    assert_eq!(approved.len(), 1);
    assert_eq!(approved[0].state, OwnerRequestState::Approved);
    let card = approved[0].card.as_deref().unwrap();
    let CardView::Read { home_id, .. } = crate::custody_pool_setup::read_card(&owner_root, card)
    else {
        panic!("the approved card reads");
    };
    assert_eq!(home_id, node_home);
    check_install_term(
        &owner_root,
        &[CardInput::Remote {
            text: card.to_string(),
        }],
        182,
    )
    .unwrap();
    drop(write);

    // The owner wants a year instead and asks again. The node's admin agreed
    // to 182 days only, so the request waits in its Inbox.
    let again = send_request(
        lock_custody_writes().await,
        &host,
        &node_profile,
        365,
        now + 1,
    )
    .await
    .unwrap();
    let waiting =
        crate::custody_consent::inbox_requests(&node_root, &node_profile, now + 1).unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].request.request_id, again.request_id);
    assert_eq!(waiting[0].request.term_days, 365);
    let write = lock_custody_writes().await;
    approve(
        &write,
        &node_host,
        &node_profile,
        &again.request_id,
        now + 1,
    )
    .await
    .unwrap();
    drop(write);
    node.deliver_pending(now + 1).await.unwrap();
    let approved_again = node_requests_view(&owner_root, now + 1)
        .unwrap()
        .into_iter()
        .find(|request| request.request_id == again.request_id)
        .unwrap();
    assert_eq!(approved_again.state, OwnerRequestState::Approved);
    let card = approved_again.card.unwrap();
    // Install now takes the year the node agreed to, and only that.
    let slot = [CardInput::Remote {
        text: card.to_string(),
    }];
    check_install_term(&owner_root, &slot, 365).unwrap();
    let error = check_install_term(&owner_root, &slot, 182).unwrap_err();
    assert_eq!(refusal(&error), "term_changed");

    // The owner installs a pool with this node and tells it.
    let remote = |text: String| CardInput::Remote { text };
    let cards = [
        remote(card.to_string()),
        remote(labelled_card("Alice", "Lisbon", STORAGE)),
        remote(labelled_card("Carol", "Kyiv", STORAGE)),
    ];
    crate::custody_pool_setup::install(&owner_root, &cards, 365)
        .await
        .unwrap();
    let notices =
        crate::custody_pool_notices::record_install(&owner_root, &owner_profile, &contacts)
            .unwrap();
    use crate::custody_pool_notices::NoticeState;
    let node_share = crate::custody_pool_setup::read_pool(&owner_root)
        .unwrap()
        .unwrap()
        .members
        .iter()
        .find(|member| member.home_id.as_deref() == Some(node_home.as_str()))
        .unwrap()
        .share;
    let state_of = |view: &crate::custody_pool_notices::PoolNoticesView, share: u8| {
        view.members
            .iter()
            .find(|member| member.share == share)
            .unwrap()
            .state
    };
    assert_eq!(state_of(&notices, node_share), NoticeState::Pending);
    for share in (1..=3).filter(|share| *share != node_share) {
        assert_eq!(state_of(&notices, share), NoticeState::Skipped);
    }
    owner.deliver_pending(now).await.unwrap();
    let served = crate::custody_consent::served_pools(&node_root)
        .unwrap()
        .entries
        .keys()
        .find_map(|key| crate::custody_consent::served_pool_view(&node_root, key))
        .unwrap();
    assert_eq!(
        (served.share, served.total, served.required),
        (node_share, 3, 2)
    );
    assert_eq!(served.members[usize::from(node_share) - 1].run_by, "Bob");
    // The next pass reads the node's receipt.
    owner.deliver_pending(now).await.unwrap();
    let told =
        crate::custody_pool_notices::pool_notices_view(&owner_root, &notices.fingerprint_full)
            .unwrap()
            .unwrap();
    assert_eq!(state_of(&told, node_share), NoticeState::Delivered);
}

#[tokio::test(start_paused = true)]
async fn find_answers_within_its_deadline_and_the_rest_read_unreachable() {
    let owner = owner();
    let mut nodes = BTreeMap::new();
    let mut contacts = Vec::new();
    for _ in 0..20 {
        let node = Party::new("Node", true);
        contacts.push(node.contact());
        nodes.insert(node.profile_did().to_string(), (node, "offering"));
    }
    // Each answer takes 4.5 s: four rounds of four fit in 20 s, the fifth
    // does not.
    let mut offers = CountingOffers::new(&owner, nodes);
    offers.delay = std::time::Duration::from_millis(4_500);
    let started = tokio::time::Instant::now();
    let found = find_nodes(
        &owner.data_dir,
        &owner.admin.profile,
        &contacts,
        &offers,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(started.elapsed(), FIND_DEADLINE);
    assert_eq!(found.len(), 20);
    let count = |status| found.iter().filter(|found| found.status == status).count();
    assert_eq!(count(FoundStatus::Offering), 16);
    assert_eq!(count(FoundStatus::Unreachable), 4);
}

#[tokio::test]
async fn a_wrapped_card_is_kept_compact() {
    let owner = owner();
    let bob = Party::new("Bob", true);
    let sent = owner
        .send(&[bob.contact()], bob.profile_did(), 365, NOW)
        .await
        .unwrap();
    let card = bob.card("Oslo");
    let wrapped = format!(
        "  {}\n{}\r\n ",
        &card[..card.len() / 2],
        &card[card.len() / 2..]
    );
    owner
        .decide(&bob, approval(&sent, wrapped.clone()), NOW + 60)
        .unwrap();
    assert_eq!(
        owner.only_request(NOW + 60).card.as_deref(),
        Some(card.as_str())
    );
    // The same card, wrapped or not, is the same decision.
    owner
        .decide(&bob, approval(&sent, card.clone()), NOW + 90)
        .unwrap();
    check_install_term(&owner.data_dir, &[CardInput::Remote { text: wrapped }], 365).unwrap();
}

#[tokio::test]
async fn a_request_that_can_no_longer_be_sent_settles_once() {
    let owner = owner();
    let nodes: Vec<Party> = (0..4).map(|_| Party::new("Node", true)).collect();
    let contacts: Vec<AcceptedContact> = nodes.iter().map(Party::contact).collect();

    // Refused by this Home's own checks as it is queued: settled at once.
    owner.outbox.fail_enqueue(Some(EnqueueFailure::Refused(
        CustodyMessageRefusal::WrongRecipient,
    )));
    let refused = owner
        .send(&contacts, nodes[0].profile_did(), 365, NOW)
        .await
        .unwrap();
    assert_eq!(refused.state, OwnerRequestState::Declined);
    assert_eq!(refused.code.as_deref(), Some("wrong_recipient"));
    owner.outbox.fail_enqueue(None);
    let mut sent = Vec::new();
    for node in &nodes[1..] {
        sent.push(
            owner
                .send(&contacts, node.profile_did(), 365, NOW)
                .await
                .unwrap(),
        );
    }
    // One stored envelope is damaged.
    let mut records = load_records(&owner.data_dir).unwrap();
    records
        .iter_mut()
        .find(|record| record.request_id == sent[2].request_id)
        .unwrap()
        .envelope = Some("not base64!".to_string());
    store_records(&owner.data_dir, &records).unwrap();

    // After a restart one request is already back in the outbox. A damaged
    // one settles without a try; this Home's own trouble retries...
    let restarted = FakeOutbox::default();
    restarted.settle(
        &format!("custody-request:{}", sent[1].request_id),
        CustodyOutboxState::Delivered,
    );
    restarted.fail_enqueue(Some(EnqueueFailure::Busy));
    resume_requests(&owner.data_dir, &restarted, NOW + 10).unwrap();
    resume_requests(&owner.data_dir, &restarted, NOW + 20).unwrap();
    assert_eq!(restarted.enqueue_calls(), 2);
    // ...while an envelope that no longer verifies settles, and only once.
    restarted.fail_enqueue(Some(EnqueueFailure::Refused(
        CustodyMessageRefusal::Expired,
    )));
    resume_requests(&owner.data_dir, &restarted, NOW + 30).unwrap();
    resume_requests(&owner.data_dir, &restarted, NOW + 40).unwrap();
    assert_eq!(restarted.enqueue_calls(), 3);

    let states: BTreeMap<String, (OwnerRequestState, Option<String>)> = owner
        .requests(NOW + 40)
        .into_iter()
        .map(|request| (request.request_id, (request.state, request.code)))
        .collect();
    assert_eq!(
        states[&sent[0].request_id],
        (OwnerRequestState::Expired, None)
    );
    assert_eq!(
        states[&sent[1].request_id],
        (OwnerRequestState::Waiting, None)
    );
    assert_eq!(
        states[&sent[2].request_id],
        (
            OwnerRequestState::Declined,
            Some("invalid_envelope".to_string())
        )
    );
    assert_eq!(
        states[&refused.request_id],
        (
            OwnerRequestState::Declined,
            Some("wrong_recipient".to_string())
        )
    );
}

#[test]
fn install_follows_the_nodes_latest_approval() {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("owner");
    owner_only_dir(&data_dir);
    let card = labelled_card("Bob", "Oslo", STORAGE);
    plant_approved(&data_dir, &card, 182);
    plant_approved(&data_dir, &card, 365);
    let slot = [CardInput::Remote { text: card }];
    check_install_term(&data_dir, &slot, 365).unwrap();
    let error = check_install_term(&data_dir, &slot, 182).unwrap_err();
    assert_eq!(refusal(&error), "term_changed");
}

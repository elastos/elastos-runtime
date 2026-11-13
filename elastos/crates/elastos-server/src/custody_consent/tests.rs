use super::*;
use crate::collaboration_discovery_runtime::tests::{
    durable_profile_identity, signed_profile, DurableProfileIdentity,
};
use crate::collaboration_network::VerifiedCollaborationNetworkProfile;
use crate::collaboration_profile_authority::{
    signed_profile_document_for_test, with_signing_scope_for_test,
};
use crate::custody_consent_protocol::{
    prepare_custody_message, verify_custody_message, CustodyMessageType, CustodyOfferQueryPayload,
    VerifiedCustodyMessage, CUSTODY_SIGNING_SCOPE,
};
use crate::custody_node_card::tests::ticket_for;
use crate::protected_content_config::tests::{
    install_successful_provision_script, owner_only_dir, safe_ancestor_tempdir,
};
use crate::protected_content_runtime::CUSTODY_PROVIDER_ID;
use elastos_runtime::signature::{generate_keypair, SigningKey};

const NETWORK: &str = "elastos.custody-consent.test";
const DAY: u64 = 86_400;

/// Stands in for the message service: a "signed" decision is its payload's
/// JSON, so tests read back exactly what the node decided.
#[derive(Default)]
struct RecordingOutbox {
    queued: Mutex<Vec<(String, String, Vec<u8>)>>,
    failure: Mutex<Option<SignFailure>>,
    /// Queueing refuses: the owner is no longer a contact.
    refuse_enqueue: Mutex<bool>,
    enqueue_calls: Mutex<usize>,
}

/// Why the message service would not sign a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SignFailure {
    /// This Profile never enabled custody messages.
    NotEnabled,
    /// The owner is no longer an accepted contact.
    NotContact,
    /// The custody plane is not running for this Profile.
    Unavailable,
    /// Only approvals fail: a failure after provisioning.
    Approvals,
    /// Only decisions on this request fail.
    ForRequest(String),
}

impl DecisionOutbox for RecordingOutbox {
    fn sign(
        &self,
        _local_profile_did: &str,
        _owner_profile_did: &str,
        decision: CustodyNodeDecisionPayload,
        now: u64,
        expires_at: u64,
    ) -> anyhow::Result<Vec<u8>> {
        assert!(
            now < expires_at,
            "a decision is signed only while it can live"
        );
        let failure = self.failure.lock().unwrap().clone();
        match failure {
            Some(SignFailure::NotEnabled) => Err(
                crate::custody_consent_protocol::CustodyMessageRefusal::SignerNotAuthorized.into(),
            ),
            Some(SignFailure::NotContact) => Err(WireRefusal::NOT_CONTACT.into()),
            Some(SignFailure::Unavailable) => {
                Err(anyhow::anyhow!("custody context is not registered"))
            }
            Some(SignFailure::Approvals)
                if decision.outcome == CustodyNodeDecisionOutcome::Approved =>
            {
                Err(anyhow::anyhow!("the decision was not signed"))
            }
            Some(SignFailure::ForRequest(request_id)) if decision.request_id == request_id => {
                Err(WireRefusal::NOT_CONTACT.into())
            }
            _ => Ok(serde_json::to_vec(&decision)?),
        }
    }

    fn enqueue(
        &self,
        key: &str,
        local_profile_did: &str,
        envelope: Vec<u8>,
        _now: u64,
    ) -> anyhow::Result<()> {
        *self.enqueue_calls.lock().unwrap() += 1;
        if *self.refuse_enqueue.lock().unwrap() {
            return Err(WireRefusal::NOT_CONTACT.into());
        }
        self.queued.lock().unwrap().push((
            key.to_string(),
            local_profile_did.to_string(),
            envelope,
        ));
        Ok(())
    }

    fn state(
        &self,
        key: &str,
        _now: u64,
    ) -> Option<crate::collaboration_custody_messages::CustodyOutboxState> {
        self.queued
            .lock()
            .unwrap()
            .iter()
            .any(|(queued, _, _)| queued == key)
            .then_some(crate::collaboration_custody_messages::CustodyOutboxState::Pending)
    }
}

impl RecordingOutbox {
    fn fail(&self, failure: Option<SignFailure>) {
        *self.failure.lock().unwrap() = failure;
    }

    fn decisions(&self) -> Vec<CustodyNodeDecisionPayload> {
        self.queued
            .lock()
            .unwrap()
            .iter()
            .map(|(_, _, envelope)| serde_json::from_slice(envelope).unwrap())
            .collect()
    }

    fn keys(&self) -> Vec<String> {
        self.queued
            .lock()
            .unwrap()
            .iter()
            .map(|(key, _, _)| key.clone())
            .collect()
    }

    fn clear(&self) {
        self.queued.lock().unwrap().clear();
    }
}

/// Stands in for a custody provider the Runtime already serves.
struct ReadyCustodyProvider;

#[async_trait::async_trait]
impl elastos_runtime::provider::Provider for ReadyCustodyProvider {
    async fn handle(
        &self,
        _request: elastos_runtime::provider::ResourceRequest,
    ) -> Result<elastos_runtime::provider::ResourceResponse, elastos_runtime::provider::ProviderError>
    {
        Err(elastos_runtime::provider::ProviderError::Provider(
            "test provider".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        Vec::new()
    }

    fn name(&self) -> &'static str {
        "ready-custody"
    }
}

/// Stands in for the running Chain plane: it keeps every Init it is sent.
#[derive(Default)]
struct RecordingChain {
    inits: Mutex<Vec<serde_json::Value>>,
    refuse: bool,
}

impl RecordingChain {
    fn trusted_issuers(&self) -> Vec<String> {
        self.inits
            .lock()
            .unwrap()
            .iter()
            .map(|init| {
                assert_eq!(init["op"], "init");
                init["config"]["extra"]["protected_content_runtime_issuer"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl elastos_runtime::provider::Provider for RecordingChain {
    async fn handle(
        &self,
        _request: elastos_runtime::provider::ResourceRequest,
    ) -> Result<elastos_runtime::provider::ResourceResponse, elastos_runtime::provider::ProviderError>
    {
        Err(elastos_runtime::provider::ProviderError::Provider(
            "test chain".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        Vec::new()
    }

    fn name(&self) -> &'static str {
        "recording-chain"
    }

    async fn send_raw(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, elastos_runtime::provider::ProviderError> {
        self.inits.lock().unwrap().push(request.clone());
        Ok(if self.refuse {
            serde_json::json!({ "status": "error", "code": "invalid_config" })
        } else {
            serde_json::json!({ "status": "ok", "data": {} })
        })
    }
}

/// A Runtime serving a ready custody provider and the given Chain plane.
async fn live_registry(chain: Option<Arc<RecordingChain>>) -> Arc<ProviderRegistry> {
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(CUSTODY_PROVIDER_ID, Arc::new(ReadyCustodyProvider))
        .await
        .unwrap();
    if let Some(chain) = chain {
        registry
            .register_sub_provider("chain", chain)
            .await
            .unwrap();
    }
    registry
}

/// A pool owner: a custody-enabled Profile whose endpoint is its Home DID.
struct Owner {
    device: SigningKey,
    profile: VerifiedCollaborationProfileDocument,
    name: &'static str,
    /// Its pool signing key, which its requests name and its pools are
    /// signed with.
    pool_key: SigningKey,
}

impl Owner {
    fn new(name: &'static str, now: u64) -> Self {
        let (device, _) = generate_keypair();
        let (profile_key, _) = generate_keypair();
        let profile = signed_profile_document_for_test(
            &profile_key,
            name,
            None,
            1,
            None,
            now - 100,
            vec![crate::crypto::encode_signing_key_did(&device)],
        )
        .unwrap();
        let profile =
            with_signing_scope_for_test(&profile_key, &profile, CUSTODY_SIGNING_SCOPE).unwrap();
        Self {
            device,
            profile,
            name,
            pool_key: generate_keypair().0,
        }
    }

    fn did(&self) -> String {
        crate::crypto::encode_signing_key_did(&self.device)
    }

    fn issuer(&self) -> String {
        format!("0x{}", hex::encode(self.device.verifying_key().to_bytes()))
    }

    fn pool_fingerprint(&self) -> String {
        crate::custody_node_card::Fingerprint::of(&self.pool_key.verifying_key().to_bytes()).full
    }
}

/// A Home that may become a custody node: its admin's Profile, its DID and
/// the Carrier ticket that reaches it.
struct Node {
    dir: tempfile::TempDir,
    data_dir: PathBuf,
    admin: DurableProfileIdentity,
    network: VerifiedCollaborationNetworkProfile,
    did: String,
    ticket: String,
    handler: NodeConsentHandler,
    outbox: Arc<RecordingOutbox>,
}

fn node(now: u64) -> Node {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("node");
    let admin = durable_profile_identity(&data_dir, "Nadia", None, now);
    std::fs::write(data_dir.join("config.toml"), "protected_content = true\n").unwrap();
    // #388 A1: a node Home is a WCI-operated host.
    crate::host_trust::seed_for_test(&data_dir, true);
    let (trusted, _) = generate_keypair();
    let network = signed_profile(NETWORK, &trusted, vec![]);
    let (key, did) = elastos_identity::load_existing_did(&data_dir).unwrap();
    let ticket = ticket_for(&key.verifying_key());
    let outbox = Arc::new(RecordingOutbox::default());
    let handler_ticket = ticket.clone();
    let handler = NodeConsentHandler::new(
        outbox.clone(),
        Arc::new(move || Some(handler_ticket.clone())),
    )
    .resuming_decisions(data_dir.clone());
    Node {
        dir,
        data_dir,
        admin,
        network,
        did,
        ticket,
        handler,
        outbox,
    }
}

fn request_id(seed: u8) -> String {
    hex::encode([seed; 16])
}

impl Node {
    fn profile_did(&self) -> &str {
        &self.admin.profile.document().profile_did
    }

    fn verified(
        &self,
        owner: &Owner,
        payload: &CustodyPayload,
        kind: CustodyMessageType,
        now: u64,
        expires_at: u64,
    ) -> (Vec<u8>, VerifiedCustodyMessage) {
        let envelope = prepare_custody_message(
            &owner.device,
            &self.network,
            &owner.profile,
            self.profile_did(),
            payload,
            now,
            expires_at,
        )
        .unwrap();
        let verified = verify_custody_message(
            &envelope,
            &self.network,
            &owner.profile,
            Some(&self.admin.profile),
            kind,
            now,
        )
        .unwrap();
        (envelope, verified)
    }

    fn inbound<'a>(
        &'a self,
        owner: &'a Owner,
        principal_id: &'a str,
        envelope: &'a [u8],
        message: &'a VerifiedCustodyMessage,
        now: u64,
    ) -> CustodyInbound<'a> {
        CustodyInbound {
            data_dir: &self.data_dir,
            principal_id,
            localhost_root: &self.admin.localhost_root,
            local_profile: &self.admin.profile,
            sender_profile: &owner.profile,
            sender_display_name: owner.name,
            message,
            envelope,
            now,
        }
    }

    /// `owner` asks this Home's admin Profile, as the message plane hands it
    /// over once it verified the sender.
    fn receive_as(
        &self,
        principal_id: &str,
        owner: &Owner,
        seed: u8,
        now: u64,
        expires_at: u64,
    ) -> Result<(), WireRefusal> {
        self.receive_for(principal_id, owner, seed, 365, now, expires_at)
    }

    /// `owner` asks for `term_days`.
    fn receive_for(
        &self,
        principal_id: &str,
        owner: &Owner,
        seed: u8,
        term_days: u16,
        now: u64,
        expires_at: u64,
    ) -> Result<(), WireRefusal> {
        self.receive_payload(
            principal_id,
            owner,
            CustodyNodeRequestPayload {
                request_id: request_id(seed),
                signing_key_fingerprint_full: owner.pool_fingerprint(),
                term_days,
            },
            now,
            expires_at,
        )
    }

    fn receive_payload(
        &self,
        principal_id: &str,
        owner: &Owner,
        request: CustodyNodeRequestPayload,
        now: u64,
        expires_at: u64,
    ) -> Result<(), WireRefusal> {
        let (envelope, message) = self.verified(
            owner,
            &CustodyPayload::NodeRequest(request.clone()),
            CustodyMessageType::NodeRequest,
            now,
            expires_at,
        );
        self.handler.on_request(
            &self.inbound(owner, principal_id, &envelope, &message, now),
            &request,
        )
    }

    fn receive(&self, owner: &Owner, seed: u8, now: u64) -> Result<(), WireRefusal> {
        self.receive_as(&self.admin.principal_id, owner, seed, now, now + DAY)
    }

    fn query_as(
        &self,
        principal_id: &str,
        owner: &Owner,
        now: u64,
    ) -> Result<CustodyOfferPayload, WireRefusal> {
        let (envelope, message) = self.verified(
            owner,
            &CustodyPayload::OfferQuery(CustodyOfferQueryPayload {}),
            CustodyMessageType::OfferQuery,
            now,
            now + 60,
        );
        self.handler
            .on_offer_query(&self.inbound(owner, principal_id, &envelope, &message, now))
    }

    async fn offer(&self, enabled: bool) -> anyhow::Result<OfferView> {
        let write = lock_custody_writes().await;
        set_offer(
            &write,
            &self.data_dir,
            Some(&self.admin.profile),
            enabled,
            "Nadia",
            "Porto",
        )
    }

    /// The custody provider binary provisions a root trusting `issuer`.
    fn installs_provider_for(&self, issuer: &str, seed: u8) {
        install_successful_provision_script(self.dir.path(), &self.data_dir, issuer, seed);
    }

    fn records(&self) -> Vec<NodeRequestRecordV1> {
        load_requests(&self.data_dir).unwrap()
    }

    fn record(&self, seed: u8) -> NodeRequestRecordV1 {
        self.records()
            .into_iter()
            .find(|record| record.request_id == request_id(seed))
            .unwrap()
    }

    async fn approve_with(
        &self,
        registry: Option<&Arc<ProviderRegistry>>,
        ticket: Option<String>,
        seed: u8,
        now: u64,
    ) -> anyhow::Result<ApprovedRequest> {
        let write = lock_custody_writes().await;
        let host = NodeHost {
            data_dir: &self.data_dir,
            registry,
            outbox: self.outbox.as_ref(),
            ticket,
        };
        approve(&write, &host, self.profile_did(), &request_id(seed), now).await
    }

    async fn approve(&self, seed: u8, now: u64) -> anyhow::Result<ApprovedRequest> {
        self.approve_with(None, Some(self.ticket.clone()), seed, now)
            .await
    }

    async fn decline(&self, seed: u8, now: u64) -> anyhow::Result<()> {
        let write = lock_custody_writes().await;
        decline(
            &write,
            &self.data_dir,
            self.outbox.as_ref(),
            self.profile_did(),
            &request_id(seed),
            now,
        )
    }

    fn descriptor_bytes(&self) -> Vec<u8> {
        std::fs::read(crate::protected_content_config::custody_node_descriptor_path(&self.data_dir))
            .unwrap()
    }
}

/// A request from `owner_home` waiting on this Home for `local_profile_did`,
/// as the message plane stores one: for routes tested without Carrier.
/// Marks a planted request as approving, as a provisioning that did not
/// finish leaves it.
pub(crate) fn mark_approving(data_dir: &Path, request_id: &str) {
    let mut records = load_requests(data_dir).unwrap();
    records
        .iter_mut()
        .find(|record| record.request_id == request_id)
        .unwrap()
        .state = RequestState::Approving;
    store_requests(data_dir, &records).unwrap();
}

/// R3-D5 = B: the reservation an approval makes in the served-pools map
/// before it provisions `root_path`.
pub(crate) fn reserve_for_approval(
    data_dir: &Path,
    request_id: &str,
    root_path: &str,
    local_profile_did: &str,
) {
    let record = load_requests(data_dir)
        .unwrap()
        .into_iter()
        .find(|record| record.request_id == request_id)
        .unwrap();
    assert!(reserve_served_pool_entry(data_dir, &record, root_path, local_profile_did).unwrap());
}

pub(crate) fn plant_request(
    data_dir: &Path,
    local_profile_did: &str,
    request_id: &str,
    owner_home: &str,
    received_at: u64,
    expires_at: u64,
) -> serde_json::Value {
    let record = NodeRequestRecordV1 {
        request_id: request_id.to_string(),
        request_sha256: format!("sha256:{}", hex::encode([0x5e; 32])),
        owner_home: owner_home.to_string(),
        owner_profile_did: "did:key:owner-profile".to_string(),
        owner_name: "Olivia".to_string(),
        local_profile_did: local_profile_did.to_string(),
        term_days: 365,
        signing_key_fingerprint_full: format!("sha256:{}", hex::encode([0xab; 32])),
        run_by: "Nadia".to_string(),
        location: "Porto".to_string(),
        received_at,
        expires_at,
        state: RequestState::Pending,
        decided_at: None,
        code: None,
        decision: None,
    };
    let view = NodeRequestView::of(&record).step_up_request();
    let mut records = load_requests(data_dir).unwrap();
    records.push(record);
    store_requests(data_dir, &records).unwrap();
    view
}

fn refusal_code(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<CustodyRefusal>()
        .unwrap_or_else(|| panic!("expected a custody refusal, got {error:#}"))
        .code()
}

fn guest_principal(data_dir: &Path, now: u64) -> String {
    let principal_id = "person:local:custody-guest".to_string();
    let binding = elastos_runtime::auth::ProofBinding::passkey_webauthn(
        elastos_runtime::auth::PasskeyWebAuthnBinding {
            credential_id: "credential:custody-guest".to_string(),
            public_key: "custody-guest-public-key".to_string(),
            sign_count: 1,
            user_verified: true,
            origin: "https://elastos.elacitylabs.com".to_string(),
            rp_id: "elastos.elacitylabs.com".to_string(),
            created_at: now,
            last_used_at: now,
            revoked_at: None,
        },
    );
    crate::auth::upsert_principal_for_binding_as_role_named(
        data_dir,
        binding,
        principal_id.clone(),
        crate::auth::RuntimePrincipalRole::Guest,
        Some("Guest"),
        now,
    )
    .unwrap();
    principal_id
}

fn approved_card(decision: &CustodyNodeDecisionPayload) -> crate::custody_node_card::NodeCard {
    assert_eq!(decision.outcome, CustodyNodeDecisionOutcome::Approved);
    assert_eq!(decision.code, None);
    crate::custody_node_card::parse_node_card(decision.card.as_deref().unwrap()).unwrap()
}

fn declined_with(decision: &CustodyNodeDecisionPayload) -> Option<CustodyDeclineCode> {
    assert_eq!(decision.outcome, CustodyNodeDecisionOutcome::Declined);
    assert_eq!(decision.card, None);
    decision.code
}

#[tokio::test]
async fn a_profile_that_is_not_an_admin_takes_no_request_and_offers_nothing() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let owner = Owner::new("Olivia", now);
    let guest = guest_principal(&node.data_dir, now);

    for principal in [guest.as_str(), "person:local:nobody"] {
        assert_eq!(
            node.receive_as(principal, &owner, 1, now, now + DAY),
            Err(WireRefusal::from(CustodyDeclineCode::NotAdmin))
        );
        assert_eq!(
            node.query_as(principal, &owner, now),
            Err(WireRefusal::from(CustodyDeclineCode::NotAdmin))
        );
    }
    assert!(node.records().is_empty());
    assert!(inbox_requests(&node.data_dir, node.profile_did(), now)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn a_home_takes_requests_only_while_it_offers() {
    let now = crate::auth::now_ts();
    let node = node(now);
    let owner = Owner::new("Olivia", now);

    // Never offered, then offered and turned off again.
    assert_eq!(node.receive(&owner, 1, now), Err(WireRefusal::NOT_OFFERING));
    assert_eq!(
        node.query_as(&node.admin.principal_id, &owner, now),
        Err(WireRefusal::NOT_OFFERING)
    );
    node.offer(true).await.unwrap();
    node.offer(false).await.unwrap();
    assert_eq!(node.receive(&owner, 1, now), Err(WireRefusal::NOT_OFFERING));
    assert!(node.records().is_empty());

    node.offer(true).await.unwrap();
    assert_eq!(
        node.query_as(&node.admin.principal_id, &owner, now),
        Ok(CustodyOfferPayload {
            location: "Porto".to_string(),
            provides: vec!["chain".to_string(), "custody".to_string()],
            run_by: "Nadia".to_string(),
        })
    );
    assert_eq!(node.receive(&owner, 1, now), Ok(()));
    let record = node.record(1);
    assert_eq!(record.state, RequestState::Pending);
    assert_eq!(record.owner_home, owner.did());
    assert_eq!(
        (record.run_by.as_str(), record.location.as_str()),
        ("Nadia", "Porto")
    );
    assert!(node.outbox.decisions().is_empty(), "nothing is decided yet");
}

#[tokio::test]
async fn the_offer_needs_labels_and_stays_on_for_a_home_with_custody_state() {
    let now = crate::auth::now_ts();
    let node = node(now);
    let write = lock_custody_writes().await;

    let shown = read_offer(&node.data_dir, Some(&node.admin.profile)).unwrap();
    assert_eq!(
        shown,
        OfferView {
            enabled: false,
            run_by: "Nadia".to_string(),
            location: String::new(),
            provides: vec!["chain".to_string(), "custody".to_string()],
            holds_custody_state: false,
            messages_enabled: false,
        }
    );
    for (run_by, location) in [
        (" Nadia", "Porto"),
        ("Nadia", ""),
        ("Nadia", &"x".repeat(65)),
    ] {
        let error = set_offer(&write, &node.data_dir, None, true, run_by, location).unwrap_err();
        assert_eq!(refusal_code(&error), "bad_labels");
    }
    assert!(!offer_path(&node.data_dir).exists());

    // Plan B T2.2 (removal approved 2026-11-12 10:35): a Home that holds
    // custody, here its own pool, may still offer below eight roots.
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(crate::protected_content_runtime::inactive_custody_state_root(&node.data_dir))
            .unwrap();
    }
    let on = set_offer(&write, &node.data_dir, None, true, "Nadia", "Porto").unwrap();
    assert!(on.enabled);
    assert!(on.holds_custody_state);
    let off = set_offer(&write, &node.data_dir, None, false, "Nadia", "Porto").unwrap();
    assert!(!off.enabled);
    assert!(off.holds_custody_state);
}

#[tokio::test]
async fn a_repeated_request_stays_one_record_and_requests_are_bounded() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);

    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    assert_eq!(node.receive(&olivia, 1, now + 5), Ok(()));
    assert_eq!(node.records().len(), 1);
    assert_eq!(node.record(1).received_at, now, "the first one stands");
    // A request id is its owner's own.
    assert_eq!(node.receive(&oscar, 1, now), Err(WireRefusal::REFUSED));

    // Two live requests per owner.
    assert_eq!(node.receive(&olivia, 2, now), Ok(()));
    assert_eq!(node.receive(&olivia, 3, now), Err(TOO_MANY_REQUESTS));

    // Sixteen in all; a settled request gives way, a live one never does.
    let owners: Vec<Owner> = (0..7).map(|_| Owner::new("Other", now)).collect();
    for (index, owner) in owners.iter().enumerate() {
        let seed = 10 + 2 * index as u8;
        assert_eq!(node.receive(owner, seed, now), Ok(()));
        assert_eq!(node.receive(owner, seed + 1, now), Ok(()));
    }
    assert_eq!(node.records().len(), MAX_REQUESTS);
    assert_eq!(node.receive(&oscar, 40, now), Err(TOO_MANY_REQUESTS));
    node.decline(1, now).await.unwrap();
    assert_eq!(node.receive(&oscar, 40, now), Ok(()));
    assert_eq!(node.records().len(), MAX_REQUESTS);
    assert!(node.records().iter().all(|record| record.state.is_live()));
}

#[tokio::test]
async fn requests_expire_at_their_envelope_and_settled_ones_go_after_a_week() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let owner = Owner::new("Olivia", now);
    assert_eq!(
        node.receive_as(&node.admin.principal_id, &owner, 1, now, now + 60),
        Ok(())
    );
    assert_eq!(node.record(1).expires_at, now + 60);

    assert_eq!(
        inbox_requests(&node.data_dir, node.profile_did(), now + 59)
            .unwrap()
            .len(),
        1
    );
    assert!(inbox_requests(&node.data_dir, node.profile_did(), now + 60)
        .unwrap()
        .is_empty());
    let error =
        approval_request(&node.data_dir, node.profile_did(), &request_id(1), now + 60).unwrap_err();
    assert_eq!(refusal_code(&error), "expired");

    // An expired request no longer counts against its owner.
    assert_eq!(
        node.receive_as(&node.admin.principal_id, &owner, 2, now + 61, now + DAY),
        Ok(())
    );
    assert_eq!(
        node.receive_as(&node.admin.principal_id, &owner, 3, now + 61, now + DAY),
        Ok(())
    );
    assert_eq!(node.record(1).state, RequestState::Expired);
    resume(
        &node.data_dir,
        node.outbox.as_ref(),
        now + 60 + TERMINAL_RETENTION_SECS,
    )
    .unwrap();
    assert!(
        node.records()
            .iter()
            .all(|record| record.request_id != request_id(1)),
        "a week after it ended, an expired request is gone"
    );
}

#[tokio::test]
async fn approve_refuses_an_expired_or_unknown_request() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let owner = Owner::new("Olivia", now);
    node.installs_provider_for(&owner.issuer(), 0x41);
    assert_eq!(
        node.receive_as(&node.admin.principal_id, &owner, 1, now, now + 60),
        Ok(())
    );

    let error = node.approve(9, now).await.unwrap_err();
    assert_eq!(refusal_code(&error), "unknown_request");
    let error = node.approve(1, now + 60).await.unwrap_err();
    assert_eq!(refusal_code(&error), "expired");
    let error = node.decline(1, now + 60).await.unwrap_err();
    assert_eq!(refusal_code(&error), "expired");
    assert!(!crate::custody_pool_setup::holds_custody_state(&node.data_dir).unwrap());
    assert!(node.outbox.decisions().is_empty());
}

#[tokio::test]
async fn approve_sets_up_the_node_answers_with_its_card_and_leaves_other_owners_waiting() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);
    node.installs_provider_for(&olivia.issuer(), 0x42);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    assert_eq!(node.receive(&olivia, 2, now), Ok(()));
    assert_eq!(node.receive(&oscar, 3, now), Ok(()));
    let waiting = inbox_requests(&node.data_dir, node.profile_did(), now).unwrap();
    assert_eq!(waiting.len(), 3);

    // Plan B T2.2 (S2-Q4): the running Chain plane is not re-pointed; boot
    // reads `inactive`. The test Runtime's custody target has no provider
    // process, so the new root waits for a restart.
    let chain = Arc::new(RecordingChain::default());
    let registry = live_registry(Some(chain.clone())).await;
    assert_eq!(
        crate::protected_content_runtime::chain_plane_runtime_issuer(&node.data_dir).unwrap(),
        crate::protected_content_runtime::derive_protected_content_runtime_issuer(
            &elastos_identity::load_or_create_device_key(&node.data_dir).unwrap()
        )
        .unwrap(),
        "before serving, this Home's Chain plane trusts its own Runtime"
    );
    let approved = node
        .approve_with(Some(&registry), Some(node.ticket.clone()), 1, now)
        .await
        .unwrap();
    assert_eq!(
        approved,
        ApprovedRequest {
            owner_name: "Olivia".to_string(),
            needs_restart: true,
        }
    );
    assert!(chain.trusted_issuers().is_empty());
    // Boot points it at the same owner.
    assert_eq!(
        format!(
            "0x{}",
            hex::encode(
                crate::protected_content_runtime::chain_plane_runtime_issuer(&node.data_dir)
                    .unwrap()
                    .as_bytes()
            )
        ),
        olivia.issuer()
    );

    // The node trusts Olivia's Home alone, and its card is the one it stored.
    assert_eq!(custody_owner_did(&node.data_dir), Some(olivia.did()));
    let decisions = node.outbox.decisions();
    assert_eq!(decisions.len(), 2);
    let card = approved_card(&decisions[0]);
    assert_eq!(decisions[0].request_id, request_id(1));
    assert_eq!(decisions[0].request_sha256, node.record(1).request_sha256);
    assert_eq!(card.node_bytes, node.descriptor_bytes());
    assert_eq!(card.ticket, node.ticket);
    assert!(matches!(
        &card.descriptor.transport,
        crate::protected_content_runtime::RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
            peer_did
        } if *peer_did == node.did
    ));
    assert_eq!(
        (
            card.descriptor.operator.as_str(),
            card.descriptor.failure_domain.as_str()
        ),
        ("Nadia", "Porto")
    );
    // Olivia's other request gets the same card; Oscar's stays waiting.
    assert_eq!(approved_card(&decisions[1]).node_bytes, card.node_bytes);
    assert_eq!(decisions[1].request_id, request_id(2));
    assert_eq!(
        node.records()
            .iter()
            .map(|record| record.state)
            .collect::<Vec<_>>(),
        [
            RequestState::Approved,
            RequestState::Approved,
            RequestState::Pending
        ]
    );
    let waiting = inbox_requests(&node.data_dir, node.profile_did(), now).unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].request.request_id, request_id(3));

    // Serving one pool, it still offers, and approving again changes nothing.
    assert!(node.query_as(&node.admin.principal_id, &oscar, now).is_ok());
    node.outbox.clear();
    assert_eq!(
        node.approve_with(Some(&registry), None, 1, now)
            .await
            .unwrap(),
        approved
    );
    assert!(node.outbox.decisions().is_empty());

    // A restart queues every unexpired decision again, under the same keys.
    resume(&node.data_dir, node.outbox.as_ref(), now + 1).unwrap();
    assert_eq!(
        node.outbox.keys(),
        [1, 2].map(|seed| format!("{DECISION_OUTBOX_PREFIX}{}", request_id(seed)))
    );
    node.outbox.clear();
    resume(&node.data_dir, node.outbox.as_ref(), now + DAY).unwrap();
    assert!(
        node.outbox.keys().is_empty(),
        "an expired decision is not sent"
    );
}

#[tokio::test]
async fn chain_issuer_is_not_repointed() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    node.installs_provider_for(&olivia.issuer(), 0x48);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    let chain = Arc::new(RecordingChain {
        refuse: true,
        ..RecordingChain::default()
    });
    let registry = live_registry(Some(chain.clone())).await;

    let approved = node
        .approve_with(Some(&registry), Some(node.ticket.clone()), 1, now)
        .await
        .unwrap();
    assert!(approved.needs_restart);
    // Plan B T2.2 (S2-Q4, removal approved 2026-11-12 10:35): no live
    // re-point; boot reads the `inactive` root's issuer.
    assert!(chain.trusted_issuers().is_empty());
    let serving = crate::custody_pool_setup::summary(&node.data_dir, Some(&registry), None, None)
        .await
        .serving
        .into_iter()
        .next()
        .unwrap();
    assert!(serving.provider_running);
    assert!(
        serving.needs_restart,
        "the root is not loaded in a running provider: the Serving card says to restart"
    );
    // Approving again finds it still waiting for the restart.
    assert!(
        node.approve_with(Some(&registry), None, 1, now)
            .await
            .unwrap()
            .needs_restart
    );

    // Without a Runtime at all, both start on the next restart.
    let other = super::tests::node(now);
    other.offer(true).await.unwrap();
    other.installs_provider_for(&olivia.issuer(), 0x49);
    assert_eq!(other.receive(&olivia, 1, now), Ok(()));
    assert!(other.approve(1, now).await.unwrap().needs_restart);
}

#[tokio::test]
async fn second_owner_request_provisions_second_root() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);
    node.installs_provider_for(&olivia.issuer(), 0x43);
    assert_eq!(node.receive(&oscar, 3, now), Ok(()));
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    // Oscar's request is still waiting when Olivia's is approved first, as
    // two admins deciding at once would leave it. The write lock orders them.
    {
        let write = lock_custody_writes().await;
        // While one approval holds the lock, no other custody write starts.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), lock_custody_writes())
                .await
                .is_err()
        );
        let host = NodeHost {
            data_dir: &node.data_dir,
            registry: None,
            outbox: node.outbox.as_ref(),
            ticket: Some(node.ticket.clone()),
        };
        approve(&write, &host, node.profile_did(), &request_id(1), now)
            .await
            .unwrap();
    }
    // Released, the next write proceeds (other tests may hold it briefly).
    drop(
        tokio::time::timeout(std::time::Duration::from_secs(30), lock_custody_writes())
            .await
            .expect("the custody write lock is released"),
    );
    node.outbox.clear();
    // Plan B T2.2: Oscar's request was left waiting, and approving it sets
    // up a second root for his pool; Olivia's stays as it was.
    assert_eq!(node.record(3).state, RequestState::Pending);
    assert!(node.outbox.decisions().is_empty());
    node.installs_provider_for(&oscar.issuer(), 0x60);
    node.approve(3, now).await.unwrap();
    assert_eq!(node.record(3).state, RequestState::Approved);
    let oscar_root = pool_root_of(&oscar);
    assert_eq!(
        custody_root_trust_at(&node.data_dir, &oscar_root).unwrap(),
        RootTrust::Trusts(oscar.did())
    );
    assert_eq!(custody_owner_did(&node.data_dir), Some(olivia.did()));
    let pools = served_pools(&node.data_dir).unwrap();
    assert_eq!(pools.entries.len(), 2);
    assert_eq!(
        pools.entries[&olivia.pool_fingerprint()].root_path,
        "inactive"
    );
    assert_eq!(
        pools.entries[&oscar.pool_fingerprint()].root_path,
        oscar_root
    );
    let card = approved_card(&node.outbox.decisions()[0]);
    assert_eq!(
        card.node_bytes,
        std::fs::read(
            crate::protected_content_config::custody_node_descriptor_path_for(
                &node.data_dir,
                &oscar_root
            )
        )
        .unwrap()
    );
    assert_ne!(card.node_bytes, node.descriptor_bytes());
    // Oscar asks again for the same pool and term: the card, no admin.
    assert_eq!(node.receive(&oscar, 4, now), Ok(()));
    assert_eq!(node.record(4).state, RequestState::Approved);
}

/// The `pools/<hex>` root of `owner`'s pool.
fn pool_root_of(owner: &Owner) -> String {
    format!(
        "pools/{}",
        owner.pool_fingerprint().strip_prefix("sha256:").unwrap()
    )
}

#[tokio::test]
async fn serve_on_an_including_home_uses_a_pools_root() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));

    let own_issuer = crate::protected_content_config::runtime_issuer_hex(&node.data_dir).unwrap();
    node.installs_provider_for(&own_issuer, 0x44);
    crate::custody_pool_setup::include_local_node(
        &lock_custody_writes().await,
        &node.data_dir,
        None,
        "Home",
        "Paris",
    )
    .await
    .unwrap();

    // Plan B T2.2 (S2-Q5): the own pool took `inactive`; serving Olivia
    // takes `pools/<hex>` and leaves this Home's own node as it is.
    let write = lock_custody_writes().await;
    set_offer(&write, &node.data_dir, None, true, "Nadia", "Porto").unwrap();
    drop(write);
    assert!(node
        .query_as(&node.admin.principal_id, &olivia, now)
        .is_ok());
    node.installs_provider_for(&olivia.issuer(), 0x61);
    node.approve(1, now).await.unwrap();
    let root = pool_root_of(&olivia);
    assert_eq!(
        custody_root_trust_at(&node.data_dir, &root).unwrap(),
        RootTrust::Trusts(olivia.did())
    );
    assert!(
        crate::protected_content_config::custody_node_descriptor_path_for(&node.data_dir, &root)
            .exists()
    );
    assert_eq!(custody_owner_did(&node.data_dir), Some(node.did.clone()));
    assert!(
        crate::protected_content_runtime::protected_content_root(&node.data_dir)
            .join("custody-local-node.descriptor.json")
            .exists()
    );
}

#[tokio::test]
async fn owner_may_serve_another_pool() {
    // A Home that owns a pool (its composition installed) still hears and
    // stores another owner's request below eight roots.
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    std::fs::write(
        crate::protected_content_runtime::runtime_custody_composition_config_path(&node.data_dir),
        b"{}",
    )
    .unwrap();
    assert!(holds_custody_state(&node.data_dir).unwrap());
    assert!(node.offer(true).await.unwrap().enabled);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    assert_eq!(node.record(1).state, RequestState::Pending);
}

#[tokio::test]
async fn a_crash_while_approving_gives_the_same_node_when_approved_again() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    node.installs_provider_for(&olivia.issuer(), 0x45);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));

    // Provisioning finishes, then the answer is not signed: the request stays
    // approving, still in the Inbox.
    node.outbox.fail(Some(SignFailure::Approvals));
    node.approve(1, now).await.unwrap_err();
    assert_eq!(node.record(1).state, RequestState::Approving);
    assert_eq!(custody_owner_did(&node.data_dir), Some(olivia.did()));
    // The node may already trust Olivia, so declining it now is refused.
    let error = node.decline(1, now).await.unwrap_err();
    assert_eq!(refusal_code(&error), "not_pending");
    assert_eq!(
        error.downcast_ref::<CustodyRefusal>().unwrap().detail(),
        Some("approving")
    );
    assert_eq!(node.record(1).state, RequestState::Approving);
    assert_eq!(
        approval_request(&node.data_dir, node.profile_did(), &request_id(1), now)
            .unwrap()
            .request_id,
        request_id(1)
    );
    let first = node.descriptor_bytes();
    assert!(node.outbox.decisions().is_empty());
    // R3-D5 = B: the reservation (with the request's consent facts) was kept
    // before provisioning, so the next approval finds the same root.
    assert!(
        served_consent(&node.data_dir, &olivia.did(), &olivia.pool_fingerprint())
            .unwrap()
            .is_some()
    );

    // A crash before the node details were stored.
    std::fs::remove_file(
        crate::protected_content_config::custody_node_descriptor_path(&node.data_dir),
    )
    .unwrap();
    node.outbox.fail(None);
    node.approve(1, now + 1).await.unwrap();
    assert_eq!(node.descriptor_bytes(), first);
    assert_eq!(node.record(1).state, RequestState::Approved);
    assert_eq!(approved_card(&node.outbox.decisions()[0]).node_bytes, first);
    // Finishing the approval keeps what it consented to, key included.
    let consent = served_consent(&node.data_dir, &olivia.did(), &olivia.pool_fingerprint())
        .unwrap()
        .unwrap();
    assert_eq!(consent.term_days, 365);
    assert_eq!(
        consent.signing_key_fingerprint_full,
        olivia.pool_fingerprint()
    );
}

#[tokio::test]
async fn approve_refuses_what_it_could_not_answer_before_provisioning() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    node.installs_provider_for(&olivia.issuer(), 0x4a);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));

    let host = |ticket: Option<String>| NodeHost {
        data_dir: &node.data_dir,
        registry: None,
        outbox: node.outbox.as_ref(),
        ticket,
    };
    for (ticket, failure, code) in [
        (None, None, "no_address"),
        (
            Some(node.ticket.clone()),
            Some(SignFailure::NotEnabled),
            "messages_not_enabled",
        ),
        (
            Some(node.ticket.clone()),
            Some(SignFailure::NotContact),
            "not_contact",
        ),
        (
            Some(node.ticket.clone()),
            Some(SignFailure::Unavailable),
            "messages_unavailable",
        ),
    ] {
        node.outbox.fail(failure);
        let error = check_approval(
            &host(ticket.clone()),
            node.profile_did(),
            &request_id(1),
            now,
        )
        .unwrap_err();
        assert_eq!(refusal_code(&error), code);
        let error = node.approve_with(None, ticket, 1, now).await.unwrap_err();
        assert_eq!(refusal_code(&error), code);
        assert_eq!(node.record(1).state, RequestState::Pending, "{code}");
        assert!(
            !crate::custody_pool_setup::holds_custody_state(&node.data_dir).unwrap(),
            "{code}: no custody root was made"
        );
        assert!(node.outbox.decisions().is_empty(), "{code}");
    }
    node.outbox.fail(None);
    check_approval(
        &host(Some(node.ticket.clone())),
        node.profile_did(),
        &request_id(1),
        now,
    )
    .unwrap();
    node.approve(1, now).await.unwrap();
    assert_eq!(node.record(1).state, RequestState::Approved);
}

/// A custody root that a provisioning stopped part way left: there, but it
/// names nobody readable.
fn partial_custody_root(data_dir: &Path) {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(crate::protected_content_runtime::inactive_custody_state_root(data_dir))
        .unwrap();
}

#[tokio::test]
async fn an_approval_stopped_part_way_is_refused_honestly_and_can_be_declined() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    mark_approving(&node.data_dir, &request_id(1));
    // R3-D5 = B: the approval reserved `inactive` before it provisioned.
    assert!(reserve_served_pool_entry(
        &node.data_dir,
        &node.record(1),
        "inactive",
        node.profile_did()
    )
    .unwrap());
    partial_custody_root(&node.data_dir);
    assert_eq!(custody_owner_did(&node.data_dir), None);

    // It is this approval's own residue, not another owner's.
    let waiting = inbox_requests(&node.data_dir, node.profile_did(), now + DAY).unwrap();
    assert_eq!(waiting.len(), 1, "it stays past its expiry");
    assert_eq!(
        waiting[0].stage,
        crate::notifications::CustodyRequestStage::Incomplete
    );
    let host = NodeHost {
        data_dir: &node.data_dir,
        registry: None,
        outbox: node.outbox.as_ref(),
        ticket: Some(node.ticket.clone()),
    };
    let incomplete = |error: anyhow::Error| {
        let refusal = error.downcast_ref::<CustodyRefusal>().unwrap();
        assert_eq!(refusal.code(), "provision_failed");
        assert_eq!(refusal.detail(), Some(INCOMPLETE_CUSTODY_STATE));
    };
    incomplete(check_approval(&host, node.profile_did(), &request_id(1), now).unwrap_err());
    incomplete(node.approve(1, now).await.unwrap_err());
    assert_eq!(node.record(1).state, RequestState::Approving);
    assert!(node.outbox.decisions().is_empty());

    // No usable node exists for Olivia, so the admin can tell her no.
    node.decline(1, now).await.unwrap();
    assert_eq!(node.record(1).state, RequestState::Declined);
    assert_eq!(
        declined_with(&node.outbox.decisions()[0]),
        Some(CustodyDeclineCode::Declined)
    );
    assert!(inbox_requests(&node.data_dir, node.profile_did(), now)
        .unwrap()
        .is_empty());
    // The declined approval released its reservation.
    assert!(!served_pools(&node.data_dir)
        .unwrap()
        .entries
        .contains_key(&olivia.pool_fingerprint()));
}

/// Plan B T2.2 (approved removal of the one-role guards): an approving
/// request on a Home that serves another owner gets its own root; it is no
/// longer `already_serving`.
#[tokio::test]
async fn an_approving_request_on_a_home_serving_another_owner_gets_its_own_root() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);
    node.installs_provider_for(&oscar.issuer(), 0x4f);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    assert_eq!(node.receive(&oscar, 2, now), Ok(()));
    node.outbox
        .fail(Some(SignFailure::ForRequest(request_id(1))));
    node.approve(2, now).await.unwrap();
    node.outbox.fail(None);
    mark_approving(&node.data_dir, &request_id(1));

    let host = NodeHost {
        data_dir: &node.data_dir,
        registry: None,
        outbox: node.outbox.as_ref(),
        ticket: Some(node.ticket.clone()),
    };
    check_approval(&host, node.profile_did(), &request_id(1), now).unwrap();
    assert_ne!(
        inbox_requests(&node.data_dir, node.profile_did(), now).unwrap()[0].stage,
        crate::notifications::CustodyRequestStage::ServesAnother
    );
    // Approving it sets up a second root for Olivia; Oscar's stays.
    node.installs_provider_for(&olivia.issuer(), 0x50);
    node.approve(1, now).await.unwrap();
    assert_eq!(
        custody_root_trust_at(&node.data_dir, &pool_root_of(&olivia)).unwrap(),
        RootTrust::Trusts(olivia.did())
    );
    assert_eq!(custody_owner_did(&node.data_dir), Some(oscar.did()));
}

#[tokio::test]
async fn a_root_that_cannot_be_read_now_declines_nothing() {
    use std::os::unix::fs::PermissionsExt as _;
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    node.installs_provider_for(&olivia.issuer(), 0x50);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    node.outbox.fail(Some(SignFailure::Approvals));
    node.approve(1, now).await.unwrap_err();
    node.outbox.fail(None);
    assert_eq!(node.record(1).state, RequestState::Approving);

    // A complete root whose issuer cannot be read right now.
    let issuer = crate::protected_content_runtime::inactive_custody_state_root(&node.data_dir)
        .join(TRUSTED_RUNTIME_ISSUER_FILE);
    std::fs::set_permissions(&issuer, std::fs::Permissions::from_mode(0o000)).unwrap();
    let error = node.decline(1, now).await.unwrap_err();
    assert_eq!(refusal_code(&error), "unavailable");
    let host = NodeHost {
        data_dir: &node.data_dir,
        registry: None,
        outbox: node.outbox.as_ref(),
        ticket: Some(node.ticket.clone()),
    };
    let error = check_approval(&host, node.profile_did(), &request_id(1), now).unwrap_err();
    assert_eq!(refusal_code(&error), "unavailable");
    assert_eq!(
        inbox_requests(&node.data_dir, node.profile_did(), now).unwrap()[0].stage,
        crate::notifications::CustodyRequestStage::Finishing,
        "an unreadable root offers no Decline"
    );
    assert_eq!(node.record(1).state, RequestState::Approving);
    assert!(node.outbox.decisions().is_empty());

    // Readable again, it trusts Olivia: still not declinable.
    std::fs::set_permissions(&issuer, std::fs::Permissions::from_mode(0o600)).unwrap();
    let error = node.decline(1, now).await.unwrap_err();
    assert_eq!(refusal_code(&error), "not_pending");
}

#[tokio::test]
async fn custody_state_without_a_root_is_free_and_an_unnamed_root_is_incomplete() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    mark_approving(&node.data_dir, &request_id(1));
    // A served node's details, with no custody root.
    crate::collaboration_config::create_owner_only_file(
        &crate::protected_content_config::custody_node_descriptor_path(&node.data_dir),
        b"{}",
        "test custody node",
    )
    .unwrap();
    assert!(
        !crate::protected_content_runtime::inactive_custody_state_root(&node.data_dir).exists()
    );

    // Plan B T2.2: a node file with no root is no root; the request's pool
    // has room, and nothing was set up for it yet.
    assert_eq!(
        inbox_requests(&node.data_dir, node.profile_did(), now).unwrap()[0].stage,
        crate::notifications::CustodyRequestStage::Resumable
    );
    let host = NodeHost {
        data_dir: &node.data_dir,
        registry: None,
        outbox: node.outbox.as_ref(),
        ticket: Some(node.ticket.clone()),
    };
    check_approval(&host, node.profile_did(), &request_id(1), now).unwrap();

    // An empty issuer file in a root names nobody, as a missing one does.
    let other = super::tests::node(now);
    other.offer(true).await.unwrap();
    assert_eq!(other.receive(&olivia, 1, now), Ok(()));
    mark_approving(&other.data_dir, &request_id(1));
    // R3-D5 = B: the approval reserved `inactive` before it provisioned.
    assert!(reserve_served_pool_entry(
        &other.data_dir,
        &other.record(1),
        "inactive",
        other.profile_did()
    )
    .unwrap());
    partial_custody_root(&other.data_dir);
    crate::collaboration_config::create_owner_only_file(
        &crate::protected_content_runtime::inactive_custody_state_root(&other.data_dir)
            .join(TRUSTED_RUNTIME_ISSUER_FILE),
        b"",
        "test issuer",
    )
    .unwrap();
    assert_eq!(
        inbox_requests(&other.data_dir, other.profile_did(), now).unwrap()[0].stage,
        crate::notifications::CustodyRequestStage::Incomplete
    );
}

#[tokio::test]
async fn approve_completes_when_another_request_cannot_be_answered() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);
    let otto = Owner::new("Otto", now);
    node.installs_provider_for(&olivia.issuer(), 0x4e);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    assert_eq!(node.receive(&oscar, 3, now), Ok(()));
    assert_eq!(node.receive(&otto, 4, now), Ok(()));
    // Oscar is no longer a contact, so no decline can be signed to him.
    node.outbox
        .fail(Some(SignFailure::ForRequest(request_id(3))));

    node.approve(1, now).await.unwrap();
    assert_eq!(node.record(1).state, RequestState::Approved);
    assert_eq!(
        node.record(3).state,
        RequestState::Pending,
        "it stays waiting"
    );
    // Plan B T2.2: other owners' requests stay waiting for the admin.
    assert_eq!(node.record(4).state, RequestState::Pending);
    let decisions = node.outbox.decisions();
    assert_eq!(
        decisions
            .iter()
            .map(|decision| decision.request_id.clone())
            .collect::<Vec<_>>(),
        [request_id(1)]
    );
    // Declining it later answers it once it can be signed.
    node.outbox.fail(None);
    node.decline(3, now).await.unwrap();
    assert_eq!(node.record(3).state, RequestState::Declined);
}

#[tokio::test]
async fn an_approving_request_outlives_its_expiry_until_approved() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    node.installs_provider_for(&olivia.issuer(), 0x4b);
    assert_eq!(
        node.receive_as(&node.admin.principal_id, &olivia, 1, now, now + 60),
        Ok(())
    );
    node.outbox.fail(Some(SignFailure::Approvals));
    node.approve(1, now).await.unwrap_err();
    assert_eq!(node.record(1).state, RequestState::Approving);

    // Past the request's end it stays approving and in the Inbox.
    let later = now + 120;
    assert_eq!(
        inbox_requests(&node.data_dir, node.profile_did(), later)
            .unwrap()
            .len(),
        1
    );
    assert!(approval_request(&node.data_dir, node.profile_did(), &request_id(1), later).is_ok());
    let error = node.decline(1, later).await.unwrap_err();
    assert_eq!(refusal_code(&error), "not_pending");
    node.outbox.fail(None);
    node.approve(1, later).await.unwrap();
    assert_eq!(node.record(1).state, RequestState::Approved);
    assert_eq!(node.outbox.decisions().len(), 1);
    // Its answer lives long enough to reach Olivia after the request ended.
    node.outbox.clear();
    resume(
        &node.data_dir,
        node.outbox.as_ref(),
        later + MIN_DECISION_LIFETIME_SECS - 1,
    )
    .unwrap();
    assert_eq!(node.outbox.decisions().len(), 1);
    node.outbox.clear();
    resume(
        &node.data_dir,
        node.outbox.as_ref(),
        later + MIN_DECISION_LIFETIME_SECS,
    )
    .unwrap();
    assert!(node.outbox.decisions().is_empty());
}

#[tokio::test]
async fn a_request_id_repeated_to_another_profile_is_refused() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    let request = CustodyNodeRequestPayload {
        request_id: request_id(1),
        signing_key_fingerprint_full: format!("sha256:{}", hex::encode([0xab; 32])),
        term_days: 365,
    };
    let (envelope, message) = node.verified(
        &olivia,
        &CustodyPayload::NodeRequest(request.clone()),
        CustodyMessageType::NodeRequest,
        now,
        now + DAY,
    );
    // The same id, as received for another Profile on this Home.
    let other = Owner::new("Second admin", now);
    let inbound = CustodyInbound {
        local_profile: &other.profile,
        ..node.inbound(&olivia, &node.admin.principal_id, &envelope, &message, now)
    };
    assert_eq!(
        node.handler.on_request(&inbound, &request),
        Err(WireRefusal::REFUSED)
    );
    assert_eq!(node.records().len(), 1);
    assert_eq!(node.record(1).local_profile_did, node.profile_did());
}

#[tokio::test]
async fn include_on_a_serving_home_uses_a_pools_root() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    node.installs_provider_for(&olivia.issuer(), 0x4c);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    node.approve(1, now).await.unwrap();

    // Were the provider run again, it would make a root trusting this Home.
    let own_issuer = crate::protected_content_config::runtime_issuer_hex(&node.data_dir).unwrap();
    node.installs_provider_for(&own_issuer, 0x4d);
    // Plan B T2.2 (S2-Q5): Include takes a `pools/<hex>` root named by this
    // Home's own pool key; the served root is never provisioned over.
    crate::custody_pool_setup::include_local_node(
        &lock_custody_writes().await,
        &node.data_dir,
        None,
        "Home",
        "Paris",
    )
    .await
    .unwrap();
    assert_eq!(custody_owner_did(&node.data_dir), Some(olivia.did()));
    assert!(
        crate::protected_content_runtime::protected_content_root(&node.data_dir)
            .join("custody-local-node.descriptor.json")
            .exists()
    );
    let own = crate::custody_pool_setup::own_root_path(&node.data_dir)
        .unwrap()
        .unwrap();
    assert!(own.starts_with("pools/"));
    assert_eq!(
        custody_root_trust_at(&node.data_dir, &own).unwrap(),
        RootTrust::Trusts(node.did.clone())
    );

    // A root that names nobody readable is not provisioned over either:
    // Include takes its own root beside it.
    let bare = super::tests::node(now);
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(crate::protected_content_runtime::inactive_custody_state_root(&bare.data_dir))
            .unwrap();
    }
    let bare_issuer = crate::protected_content_config::runtime_issuer_hex(&bare.data_dir).unwrap();
    bare.installs_provider_for(&bare_issuer, 0x62);
    crate::custody_pool_setup::include_local_node(
        &lock_custody_writes().await,
        &bare.data_dir,
        None,
        "Home",
        "Paris",
    )
    .await
    .unwrap();
    assert_eq!(
        custody_root_trust_at(&bare.data_dir, "inactive").unwrap(),
        RootTrust::NamesNobody
    );
}

#[tokio::test]
async fn the_served_owner_comes_from_the_custody_root_alone() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);
    node.installs_provider_for(&olivia.issuer(), 0x46);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    node.approve(1, now).await.unwrap();
    node.outbox.clear();

    // Stale files: an offer still switched on, and Olivia's approved request
    // rewritten to name Oscar's Home.
    write_owner_only_bytes(
        &offer_path(&node.data_dir),
        &serde_json::to_vec(&CustodyOfferFileV1 {
            schema: OFFER_SCHEMA_V1.to_string(),
            enabled: true,
            run_by: "Nadia".to_string(),
            location: "Porto".to_string(),
            provides: vec!["chain".to_string(), "custody".to_string()],
        })
        .unwrap(),
    )
    .unwrap();
    let mut records = node.records();
    records[0].owner_home = oscar.did();
    store_requests(&node.data_dir, &records).unwrap();

    // Plan B T2.2: Oscar is a new pool, heard below eight roots; the
    // rewritten record never makes him the served owner.
    assert!(node.query_as(&node.admin.principal_id, &oscar, now).is_ok());
    assert_eq!(node.receive(&oscar, 2, now), Ok(()));
    assert_eq!(node.record(2).state, RequestState::Pending);
    assert!(node.outbox.decisions().is_empty());
    // Olivia asks again and is answered with the card, with no new consent.
    assert_eq!(node.receive(&olivia, 3, now), Ok(()));
    assert_eq!(node.record(3).state, RequestState::Approved);
    let decisions = node.outbox.decisions();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].request_id, request_id(3));
    assert_eq!(
        approved_card(&decisions[0]).node_bytes,
        node.descriptor_bytes()
    );
    // Its repeat is the same request: the decision is queued again, no more.
    node.outbox.clear();
    assert_eq!(node.receive(&olivia, 3, now + 1), Ok(()));
    assert_eq!(
        node.outbox.keys(),
        [format!("{DECISION_OUTBOX_PREFIX}{}", request_id(3))]
    );
    assert_eq!(node.records().len(), 3);
}

#[tokio::test]
async fn the_served_owner_gets_the_card_again_only_for_the_term_approved() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    let admin = node.admin.principal_id.clone();
    node.installs_provider_for(&olivia.issuer(), 0x49);
    assert_eq!(
        node.receive_for(&admin, &olivia, 1, 365, now, now + DAY),
        Ok(())
    );
    // Another term from the same owner is not a courtesy of the approval.
    assert_eq!(
        node.receive_for(&admin, &olivia, 2, 730, now, now + DAY),
        Ok(())
    );
    node.approve(1, now).await.unwrap();
    assert_eq!(node.record(2).state, RequestState::Pending);
    let descriptor = node.descriptor_bytes();
    node.outbox.clear();

    // The same term again: answered with the card, no new consent.
    assert_eq!(
        node.receive_for(&admin, &olivia, 3, 365, now, now + DAY),
        Ok(())
    );
    assert_eq!(node.record(3).state, RequestState::Approved);
    let decisions = node.outbox.decisions();
    assert_eq!(decisions.len(), 1);
    assert_eq!(approved_card(&decisions[0]).node_bytes, descriptor);
    node.outbox.clear();

    // Another term waits for the admin, as any request does.
    node.decline(2, now).await.unwrap();
    node.outbox.clear();
    assert_eq!(
        node.receive_for(&admin, &olivia, 4, 182, now, now + DAY),
        Ok(())
    );
    assert_eq!(node.record(4).state, RequestState::Pending);
    assert!(node.outbox.decisions().is_empty());
    let waiting = inbox_requests(&node.data_dir, node.profile_did(), now).unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].request.term_days, 182);
    assert_eq!(
        waiting[0].stage,
        crate::notifications::CustodyRequestStage::Waiting
    );

    // Approving it answers with the node it already runs: a provider that
    // would refuse to provision for Olivia proves nothing is provisioned.
    node.installs_provider_for(&Owner::new("Oscar", now).issuer(), 0x4a);
    node.approve(4, now).await.unwrap();
    assert_eq!(node.record(4).state, RequestState::Approved);
    let decisions = node.outbox.decisions();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].request_id, request_id(4));
    assert_eq!(approved_card(&decisions[0]).node_bytes, descriptor);
    assert_eq!(node.descriptor_bytes(), descriptor);
    node.outbox.clear();

    // The newly approved term is the one a repeat now gets; the old one waits.
    assert_eq!(
        node.receive_for(&admin, &olivia, 5, 182, now, now + DAY),
        Ok(())
    );
    assert_eq!(node.record(5).state, RequestState::Approved);
    assert_eq!(
        node.receive_for(&admin, &olivia, 6, 365, now, now + DAY),
        Ok(())
    );
    assert_eq!(node.record(6).state, RequestState::Pending);
}

#[tokio::test]
async fn decline_answers_once() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));

    node.decline(1, now).await.unwrap();
    node.decline(1, now + 1).await.unwrap();
    let decisions = node.outbox.decisions();
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        declined_with(&decisions[0]),
        Some(CustodyDeclineCode::Declined)
    );
    assert_eq!(decisions[0].request_sha256, node.record(1).request_sha256);
    assert_eq!(node.record(1).state, RequestState::Declined);
    let error =
        approval_request(&node.data_dir, node.profile_did(), &request_id(1), now).unwrap_err();
    assert_eq!(refusal_code(&error), "not_pending");
    assert!(!crate::custody_pool_setup::holds_custody_state(&node.data_dir).unwrap());
}

#[tokio::test]
async fn the_inbox_and_the_step_up_show_exactly_the_recorded_request() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    let record = node.record(1);

    let waiting = inbox_requests(&node.data_dir, node.profile_did(), now).unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].received_at, now);
    let shown = approval_request(&node.data_dir, node.profile_did(), &request_id(1), now).unwrap();
    assert_eq!(waiting[0].request, shown);
    assert_eq!(
        shown.step_up_request(),
        serde_json::json!({
            "request_id": request_id(1),
            "request_sha256": record.request_sha256,
            "owner_name": "Olivia",
            "owner_home": olivia.did(),
            "term_days": 365,
            "run_by": "Nadia",
            "location": "Porto",
            "expires_at": now + DAY,
        })
    );
    // Another Profile on this Home sees nothing and approves nothing.
    assert!(inbox_requests(&node.data_dir, "did:example:other", now)
        .unwrap()
        .is_empty());
    let error =
        approval_request(&node.data_dir, "did:example:other", &request_id(1), now).unwrap_err();
    assert_eq!(refusal_code(&error), "unknown_request");
}

/// The owner side's stand-in: it keeps the decisions that reach it.
#[derive(Default)]
struct DecisionsSeen(Mutex<Vec<CustodyNodeDecisionPayload>>);

impl CustodyMessageHandler for DecisionsSeen {
    fn on_offer_query(
        &self,
        _inbound: &CustodyInbound<'_>,
    ) -> Result<CustodyOfferPayload, WireRefusal> {
        Err(WireRefusal::NOT_OFFERING)
    }

    fn on_request(
        &self,
        _inbound: &CustodyInbound<'_>,
        _request: &CustodyNodeRequestPayload,
    ) -> Result<(), WireRefusal> {
        Err(WireRefusal::REFUSED)
    }

    fn on_decision(
        &self,
        _inbound: &CustodyInbound<'_>,
        decision: &CustodyNodeDecisionPayload,
    ) -> Result<(), WireRefusal> {
        self.0.lock().unwrap().push(decision.clone());
        Ok(())
    }

    fn on_pool_active(
        &self,
        _inbound: &CustodyInbound<'_>,
        _notice: &CustodyPoolActivePayload,
    ) -> Result<(), WireRefusal> {
        Err(WireRefusal::REFUSED)
    }
}

#[tokio::test]
async fn an_approved_request_brings_the_node_card_to_its_owner_over_carrier() {
    use crate::collaboration_custody_messages::{
        ensure_custody_signing_scope, CustodyDeliveryOutcome, CustodyQueryOutcome,
    };
    use crate::collaboration_discovery_runtime::tests::durable_profile_peer_pair;

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
    let seen = Arc::new(DecisionsSeen::default());
    owner.set_handler(seen.clone());
    let endpoint = pair._node_b.endpoint.clone();
    let ticket = crate::carrier::carrier_connect_ticket(&endpoint);
    node.set_handler(Arc::new(NodeConsentHandler::new(
        Arc::new(node.downgrade()),
        Arc::new(move || Some(crate::carrier::carrier_connect_ticket(&endpoint))),
    )));
    let owner_profile = pair.identity_a.profile.document().profile_did.clone();
    let node_profile = pair.identity_b.profile.document().profile_did.clone();
    // #388 A1: a node Home is a WCI-operated host.
    crate::host_trust::seed_for_test(&node_root, true);
    let write = lock_custody_writes().await;
    set_offer(&write, &node_root, None, true, "Bob", "Porto").unwrap();

    let CustodyQueryOutcome::Offering(offer) = owner
        .query_offer(&owner_profile, &node_profile, now)
        .await
        .unwrap()
    else {
        panic!("an offering contact answers with its offer");
    };
    assert!(matches!(
        offer.payload(),
        CustodyPayload::Offer(offer) if offer.run_by == "Bob" && offer.location == "Porto"
    ));
    let request = owner
        .prepare(
            &owner_profile,
            &node_profile,
            &CustodyPayload::NodeRequest(CustodyNodeRequestPayload {
                request_id: request_id(7),
                signing_key_fingerprint_full: format!("sha256:{}", hex::encode([0xcd; 32])),
                term_days: 182,
            }),
            now,
            now + DAY,
        )
        .unwrap();
    assert_eq!(
        owner.deliver(&owner_profile, &request, now).await.unwrap(),
        CustodyDeliveryOutcome::Delivered
    );
    let waiting = inbox_requests(&node_root, &node_profile, now).unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].request.owner_name, "Alice");
    assert_eq!(
        waiting[0].request.owner_home,
        crate::crypto::encode_signing_key_did(&pair.identity_a.device_key)
    );
    assert_eq!(waiting[0].request.term_days, 182);

    let owner_issuer = format!(
        "0x{}",
        hex::encode(pair.identity_a.device_key.verifying_key().to_bytes())
    );
    install_successful_provision_script(dir.path(), &node_root, &owner_issuer, 0x47);
    let host = NodeHost {
        data_dir: &node_root,
        registry: None,
        outbox: &node,
        ticket: Some(ticket.clone()),
    };
    approve(&write, &host, &node_profile, &request_id(7), now)
        .await
        .unwrap();
    node.deliver_pending(now).await.unwrap();

    let decisions = seen.0.lock().unwrap().clone();
    assert_eq!(decisions.len(), 1);
    let card = approved_card(&decisions[0]);
    assert_eq!(decisions[0].request_id, request_id(7));
    assert_eq!(
        decisions[0].request_sha256,
        format!(
            "sha256:{}",
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&request))
        )
    );
    assert_eq!(card.ticket, ticket);
    assert!(matches!(
        &card.descriptor.transport,
        crate::protected_content_runtime::RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
            peer_did
        } if *peer_did == crate::crypto::encode_signing_key_did(&pair.identity_b.device_key)
    ));
    assert_eq!(
        custody_owner_did(&node_root),
        Some(crate::crypto::encode_signing_key_did(
            &pair.identity_a.device_key
        ))
    );
}

/* ---------- Pool active: the owner tells this node it is in the pool ---------- */

/// A Home serving `owner`: its request approved, its node set up.
async fn serving(owner: &Owner, now: u64, seed: u8) -> Node {
    let node = node(now);
    node.offer(true).await.unwrap();
    node.installs_provider_for(&owner.issuer(), seed);
    assert_eq!(node.receive(owner, 1, now), Ok(()));
    node.approve(1, now).await.unwrap();
    node.outbox.clear();
    node
}

impl Node {
    /// A three-node pool `signer` signs, active from a minute before `at`,
    /// with this node in it when `own`, told to this node's share (to share
    /// 1 when it is not in the pool).
    fn notice(&self, signer: &SigningKey, own: bool, at: u64) -> CustodyPoolActivePayload {
        self.notice_for_days(signer, own, at, 365)
    }

    /// The same, for a pool signed for `days`.
    fn notice_for_days(
        &self,
        signer: &SigningKey,
        own: bool,
        at: u64,
        days: u16,
    ) -> CustodyPoolActivePayload {
        self.notice_with(signer, own.then(|| self.descriptor_bytes()), at, days)
    }

    /// Plan B T2.2: a pool with the node of custody root `root` in it.
    fn notice_in_root(&self, signer: &SigningKey, root: &str, at: u64) -> CustodyPoolActivePayload {
        let bytes = std::fs::read(
            crate::protected_content_config::custody_node_descriptor_path_for(&self.data_dir, root),
        )
        .unwrap();
        self.notice_with(signer, Some(bytes), at, 365)
    }

    fn notice_with(
        &self,
        signer: &SigningKey,
        own_bytes: Option<Vec<u8>>,
        at: u64,
        days: u16,
    ) -> CustodyPoolActivePayload {
        let own = own_bytes.is_some();
        let descriptors: Vec<_> = (0..3usize)
            .map(|index| {
                let bytes = if let (Some(bytes), 0) = (&own_bytes, index) {
                    bytes.clone()
                } else {
                    crate::custody_node_card::tests::carrier_descriptor_bytes(
                        &generate_keypair().0.verifying_key(),
                        &format!("Other {index}"),
                        &format!("Place {index}"),
                    )
                };
                crate::protected_content_config::validated_custody_node_descriptor(
                    &bytes,
                    "pool node",
                )
                .unwrap()
            })
            .collect();
        let named: Vec<([u8; 32], String, String)> = descriptors
            .iter()
            .map(|descriptor| {
                (
                    *descriptor.node_public_key.as_bytes(),
                    descriptor.operator.clone(),
                    descriptor.failure_domain.clone(),
                )
            })
            .collect();
        let config = crate::protected_content_config::signed_custody_composition_config_at(
            signer,
            descriptors,
            days,
            elastos_protected_content_contracts::ThresholdV1::new(2, 3).unwrap(),
            at,
        )
        .unwrap();
        let config = serde_json::to_vec(&serde_json::to_value(&config).unwrap()).unwrap();
        // The epoch numbers shares in node key order.
        let facts = signed_composition_facts(&config).unwrap();
        let share_of = |key: &[u8; 32]| {
            facts
                .members
                .iter()
                .find(|(node_key, _)| node_key == key)
                .unwrap()
                .1
        };
        let labels: Vec<(u8, String, String)> = named
            .iter()
            .map(|(key, run_by, location)| (share_of(key), run_by.clone(), location.clone()))
            .collect();
        let share = if own { share_of(&named[0].0) } else { 1 };
        crate::custody_pool_notices::pool_active_notice(&config, &labels, share).unwrap()
    }

    /// `owner` tells this Home's admin Profile, as `name`.
    fn tell_as(
        &self,
        owner: &Owner,
        name: &str,
        notice: &CustodyPoolActivePayload,
        now: u64,
    ) -> Result<(), WireRefusal> {
        self.tell_to(&self.admin.principal_id, owner, name, notice, now)
    }

    /// `owner` tells the Profile of `principal_id` on this Home.
    fn tell_to(
        &self,
        principal_id: &str,
        owner: &Owner,
        name: &str,
        notice: &CustodyPoolActivePayload,
        now: u64,
    ) -> Result<(), WireRefusal> {
        let (envelope, message) = self.verified(
            owner,
            &CustodyPayload::PoolActive(notice.clone()),
            CustodyMessageType::PoolActive,
            now,
            now + 3_600,
        );
        let inbound = CustodyInbound {
            sender_display_name: name,
            ..self.inbound(owner, principal_id, &envelope, &message, now)
        };
        self.handler.on_pool_active(&inbound, notice)
    }

    fn tell(
        &self,
        owner: &Owner,
        notice: &CustodyPoolActivePayload,
        now: u64,
    ) -> Result<(), WireRefusal> {
        self.tell_as(owner, owner.name, notice, now)
    }

    /// The Inbox entries `viewer` sees for the pool this node is in now.
    fn pool_entries(&self, viewer: &str) -> Vec<crate::notifications::NotificationEntryView> {
        let mut summary = crate::notifications::NotificationSummary::default();
        crate::notifications::project_custody_pool_active_notifications(
            &mut summary,
            &self.data_dir,
            viewer,
            &served_pool_fingerprints(&self.data_dir),
        )
        .unwrap();
        summary.entries
    }

    fn served_pool_bytes(&self) -> Vec<u8> {
        std::fs::read(served_pools_path(&self.data_dir)).unwrap()
    }
}

#[tokio::test]
async fn a_pool_notice_from_the_served_owner_is_kept_and_shown_once() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x50).await;
    assert_eq!(only_served_pool_view(&node.data_dir), None);

    let notice = node.notice(&olivia.pool_key, true, now);
    assert_eq!(node.tell(&olivia, &notice, now), Ok(()));
    let view = only_served_pool_view(&node.data_dir).unwrap();
    assert_eq!(
        view,
        ServedPoolView {
            share: notice.share,
            total: 3,
            required: 2,
            pool_start: notice.pool_start,
            term_end: notice.term_end,
            members: notice.members.clone(),
        }
    );
    let own = &view.members[usize::from(notice.share) - 1];
    assert_eq!(
        (own.run_by.as_str(), own.location.as_str()),
        ("Nadia", "Porto")
    );
    assert_eq!(
        served_pool_fingerprints(&node.data_dir).into_iter().next(),
        Some(notice.fingerprint_full.clone())
    );
    // The record keeps the facts, not the composition.
    let stored = node.served_pool_bytes();
    // Plan B T2.2: the v2 map keeps one entry per pool.
    let file: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    let entries = file["entries"].as_object().unwrap();
    assert_eq!(entries.len(), 1);
    let entry = entries.values().next().unwrap();
    assert_eq!(entry["owner_home"], olivia.did());
    let record = &entry["served_pool"];
    assert_eq!(record["fingerprint_full"], notice.fingerprint_full);
    assert_eq!(record["received_at"], now);
    assert!(record.get("config").is_none());

    // The Inbox shows it to the admin Profile the owner told, once.
    let admin = node.profile_did().to_string();
    let entries = node.pool_entries(&admin);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, "custody_pool_active");
    assert_eq!(entries[0].source_app, "custody");
    assert_eq!(entries[0].title, "Custody pool active");
    assert_eq!(
        entries[0].body,
        format!(
            "Olivia's pool is active. This Home holds share {} of 3.",
            notice.share
        )
    );
    assert_eq!(entries[0].action_ref, None);
    assert!(!entries[0].passkey_approval);
    assert!(node.pool_entries("did:key:z6MkAnotherProfile").is_empty());

    // The same notice again changes nothing.
    assert_eq!(node.tell(&olivia, &notice, now + 5), Ok(()));
    assert_eq!(node.served_pool_bytes(), stored);
    assert_eq!(node.pool_entries(&admin).len(), 1);
    // Dismissed, it stays gone for this pool.
    assert!(crate::notifications::dismiss(&node.data_dir, Some(&admin), &entries[0].id).unwrap());
    assert_eq!(node.tell(&olivia, &notice, now + 10), Ok(()));
    assert!(node.pool_entries(&admin).is_empty());
}

#[tokio::test]
async fn only_the_served_owner_and_its_consented_key_can_place_this_node() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);
    let node = serving(&olivia, now, 0x51).await;

    // Oscar does not own this node, even with a pool that names it.
    let oscars = node.notice(&oscar.pool_key, true, now);
    assert_eq!(node.tell(&oscar, &oscars, now), Err(NOT_SERVED_OWNER));
    // Olivia's Home, but a pool another key signed.
    assert_eq!(node.tell(&olivia, &oscars, now), Err(WRONG_ISSUER));
    // A pool without this node, or with it at another share.
    let without = node.notice(&olivia.pool_key, false, now);
    assert_eq!(node.tell(&olivia, &without, now), Err(NOT_MEMBER));
    let mut elsewhere = node.notice(&olivia.pool_key, true, now);
    elsewhere.share = elsewhere.share % 3 + 1;
    assert_eq!(node.tell(&olivia, &elsewhere, now), Err(WRONG_SHARE));
    // A fingerprint that is not its composition's never reaches the node:
    // the protocol refuses to sign or verify it.
    let mut forged = node.notice(&olivia.pool_key, true, now);
    forged.fingerprint_full = format!("sha256:{}", hex::encode([0x11; 32]));
    let refused = prepare_custody_message(
        &olivia.device,
        &node.network,
        &olivia.profile,
        node.profile_did(),
        &CustodyPayload::PoolActive(forged),
        now,
        now + 60,
    )
    .unwrap_err();
    assert_eq!(
        refused.downcast_ref::<crate::custody_consent_protocol::CustodyMessageRefusal>(),
        Some(&crate::custody_consent_protocol::CustodyMessageRefusal::FingerprintMismatch)
    );
    // Without the consent kept at approval, no pool key is trusted.
    std::fs::remove_file(served_pools_path(&node.data_dir)).unwrap();
    let genuine = node.notice(&olivia.pool_key, true, now);
    assert_eq!(node.tell(&olivia, &genuine, now), Err(WRONG_ISSUER));
    assert_eq!(only_served_pool_view(&node.data_dir), None);
}

#[tokio::test]
async fn a_newer_pool_replaces_the_kept_one_and_an_older_or_equal_one_is_stale() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x52).await;
    let admin = node.profile_did().to_string();
    let older = node.notice(&olivia.pool_key, true, now - 600);
    let newer = node.notice(&olivia.pool_key, true, now);
    // Signed in the same second: the same start, another pool.
    let twin = node.notice(&olivia.pool_key, true, now);
    assert_eq!(older.pool_start + 600, newer.pool_start);
    assert_eq!(twin.pool_start, newer.pool_start);
    assert_ne!(twin.fingerprint_full, newer.fingerprint_full);

    assert_eq!(node.tell(&olivia, &older, now), Ok(()));
    // Without a People name the owner is named for what it is.
    assert_eq!(node.tell_as(&olivia, "", &newer, now), Ok(()));
    let view = only_served_pool_view(&node.data_dir).unwrap();
    assert_eq!(
        (view.share, view.pool_start),
        (newer.share, newer.pool_start)
    );
    let entries = node.pool_entries(&admin);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].body,
        format!(
            "The pool owner's pool is active. This Home holds share {} of 3.",
            newer.share
        )
    );

    let kept = node.served_pool_bytes();
    assert_eq!(node.tell(&olivia, &twin, now + 1), Err(STALE_NOTICE));
    assert_eq!(node.tell(&olivia, &older, now + 1), Err(STALE_NOTICE));
    assert_eq!(node.served_pool_bytes(), kept);
}

#[tokio::test]
async fn a_served_owner_change_hides_the_kept_pool() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x53).await;
    let notice = node.notice(&olivia.pool_key, true, now);
    assert_eq!(node.tell(&olivia, &notice, now), Ok(()));
    assert!(only_served_pool_view(&node.data_dir).is_some());

    let mut record: serde_json::Value = serde_json::from_slice(&node.served_pool_bytes()).unwrap();
    record["entries"][olivia.pool_fingerprint()]["owner_home"] =
        serde_json::json!(Owner::new("Oscar", now).did());
    write_owner_only_bytes(
        &served_pools_path(&node.data_dir),
        &serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    assert_eq!(only_served_pool_view(&node.data_dir), None);
    assert_eq!(
        served_pool_fingerprints(&node.data_dir).into_iter().next(),
        None
    );
    assert!(node.pool_entries(node.profile_did()).is_empty());
}

#[tokio::test]
async fn the_served_owner_with_another_pool_signing_key_waits_for_the_admin() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x54).await;
    let admin = node.admin.principal_id.clone();
    let request = |seed: u8, fingerprint: String| CustodyNodeRequestPayload {
        request_id: request_id(seed),
        signing_key_fingerprint_full: fingerprint,
        term_days: 365,
    };
    let other_key = format!("sha256:{}", hex::encode([0xcd; 32]));
    assert_eq!(
        node.receive_payload(&admin, &olivia, request(2, other_key), now, now + DAY),
        Ok(())
    );
    assert_eq!(node.record(2).state, RequestState::Pending);
    assert_eq!(
        node.receive_payload(
            &admin,
            &olivia,
            request(3, olivia.pool_fingerprint()),
            now,
            now + DAY
        ),
        Ok(())
    );
    assert_eq!(node.record(3).state, RequestState::Approved);
}

#[tokio::test]
async fn a_pool_notice_is_taken_only_for_an_admin_profile() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x55).await;
    let guest = guest_principal(&node.data_dir, now);
    let notice = node.notice(&olivia.pool_key, true, now);
    assert_eq!(
        node.tell_to(&guest, &olivia, "Olivia", &notice, now),
        Err(CustodyDeclineCode::NotAdmin.into())
    );
    assert_eq!(only_served_pool_view(&node.data_dir), None);
}

#[tokio::test]
async fn a_node_record_it_cannot_read_refuses_unavailable_and_changes_nothing() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x56).await;
    let older = node.notice(&olivia.pool_key, true, now - 600);
    assert_eq!(node.tell(&olivia, &older, now), Ok(()));
    // The kept record is no longer owner-only.
    use std::os::unix::fs::PermissionsExt as _;
    let path = served_pools_path(&node.data_dir);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let kept = node.served_pool_bytes();
    let newer = node.notice(&olivia.pool_key, true, now);
    assert_eq!(
        node.tell(&olivia, &newer, now),
        Err(WireRefusal::UNAVAILABLE)
    );
    assert_eq!(node.served_pool_bytes(), kept);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        only_served_pool_view(&node.data_dir).unwrap().pool_start,
        older.pool_start
    );
}

#[tokio::test]
async fn a_lost_inbox_entry_returns_when_the_owner_tells_again() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x57).await;
    let admin = node.profile_did().to_string();
    let notice = node.notice(&olivia.pool_key, true, now);
    assert_eq!(node.tell(&olivia, &notice, now), Ok(()));
    let notifications = elastos_common::localhost::rooted_localhost_fs_path(
        &node.data_dir,
        "localhost://Local/Shared/System/Notifications",
    )
    .unwrap()
    .join("notifications.json");
    std::fs::remove_file(&notifications).unwrap();
    assert!(node.pool_entries(&admin).is_empty());
    let kept = node.served_pool_bytes();
    assert_eq!(node.tell(&olivia, &notice, now + 5), Ok(()));
    assert_eq!(node.served_pool_bytes(), kept);
    assert_eq!(node.pool_entries(&admin).len(), 1);
}

#[tokio::test]
async fn a_former_owners_kept_approval_never_becomes_the_current_consent() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);
    let node = serving(&olivia, now, 0x58).await;
    // Approved records from before consents were kept: one from Olivia, and
    // a retained one that names a former owner.
    std::fs::remove_file(served_pools_path(&node.data_dir)).unwrap();
    let mut records = node.records();
    let mut former = records[0].clone();
    former.request_id = request_id(9);
    former.owner_home = oscar.did();
    former.signing_key_fingerprint_full = oscar.pool_fingerprint();
    records.push(former);
    store_requests(&node.data_dir, &records).unwrap();

    node.approve(9, now).await.unwrap();
    assert!(!served_pools_path(&node.data_dir).exists());
    node.approve(1, now).await.unwrap();
    let consent = served_consent(&node.data_dir, &olivia.did(), &olivia.pool_fingerprint())
        .unwrap()
        .unwrap();
    assert_eq!(
        consent.signing_key_fingerprint_full,
        olivia.pool_fingerprint()
    );
}

#[tokio::test]
async fn a_new_pool_signing_key_the_admin_approves_signs_the_next_pool() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x59).await;
    let admin = node.admin.principal_id.clone();
    let new_key = generate_keypair().0;
    let new_fingerprint =
        crate::custody_node_card::Fingerprint::of(&new_key.verifying_key().to_bytes()).full;
    let request = CustodyNodeRequestPayload {
        request_id: request_id(2),
        signing_key_fingerprint_full: new_fingerprint.clone(),
        term_days: 365,
    };
    assert_eq!(
        node.receive_payload(&admin, &olivia, request, now, now + DAY),
        Ok(())
    );
    assert_eq!(node.record(2).state, RequestState::Pending);
    node.approve(2, now).await.unwrap();
    assert_eq!(
        served_consent(&node.data_dir, &olivia.did(), &new_fingerprint)
            .unwrap()
            .unwrap()
            .signing_key_fingerprint_full,
        new_fingerprint
    );
    // Plan B T2.2: a new pool key is a new pool with its own root and
    // entry; the old pool stays served until it ends.
    let pools = served_pools(&node.data_dir).unwrap();
    assert_eq!(pools.entries.len(), 2);
    assert_eq!(
        pools.entries[&new_fingerprint].root_path,
        format!("pools/{}", new_fingerprint.strip_prefix("sha256:").unwrap())
    );
    let old_pool = node.notice(&olivia.pool_key, true, now);
    assert_eq!(node.tell(&olivia, &old_pool, now), Ok(()));
    let new_pool = node.notice(&new_key, true, now);
    assert_eq!(node.tell(&olivia, &new_pool, now), Ok(()));
    // A key no consent names is still refused.
    let stranger = node.notice(&generate_keypair().0, true, now);
    assert_eq!(node.tell(&olivia, &stranger, now), Err(WRONG_ISSUER));
}

#[tokio::test]
async fn a_pool_longer_than_the_consented_term_is_refused() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    // Approved for 365 days.
    let node = serving(&olivia, now, 0x5a).await;
    let longer = node.notice_for_days(&olivia.pool_key, true, now, 730);
    assert_eq!(node.tell(&olivia, &longer, now), Err(TERM_MISMATCH));
    assert_eq!(only_served_pool_view(&node.data_dir), None);
    let shorter = node.notice_for_days(&olivia.pool_key, true, now, 182);
    assert_eq!(node.tell(&olivia, &shorter, now), Ok(()));
    let consented = node.notice(&olivia.pool_key, true, now + 1);
    assert_eq!(node.tell(&olivia, &consented, now + 1), Ok(()));
}

#[tokio::test]
async fn with_protected_content_off_a_node_offers_and_takes_nothing_but_declines() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    std::fs::write(
        node.data_dir.join("config.toml"),
        "protected_content = false\n",
    )
    .unwrap();
    assert_eq!(
        node.query_as(&node.admin.principal_id, &olivia, now),
        Err(WireRefusal::NOT_OFFERING)
    );
    assert_eq!(
        node.receive(&olivia, 2, now),
        Err(WireRefusal::NOT_OFFERING)
    );
    node.decline(1, now).await.unwrap();
    assert_eq!(node.record(1).state, RequestState::Declined);
}

#[tokio::test]
async fn each_delivery_pass_queues_a_decision_the_outbox_lost_and_settles_a_refused_one_once() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    assert_eq!(node.receive(&olivia, 2, now), Ok(()));
    node.decline(1, now).await.unwrap();
    node.decline(2, now).await.unwrap();
    // A restart: the outbox is empty, the decisions are on disk.
    node.outbox.clear();
    node.handler.before_delivery_pass(now + 1);
    let mut keys = node.outbox.keys();
    keys.sort();
    assert_eq!(
        keys,
        [1, 2].map(|seed| format!("{DECISION_OUTBOX_PREFIX}{}", request_id(seed)))
    );
    // Known to the outbox, they are left alone.
    node.handler.before_delivery_pass(now + 2);
    assert_eq!(node.outbox.keys().len(), 2);

    // The owner is no longer a contact: queueing is refused, once.
    node.outbox.clear();
    *node.outbox.refuse_enqueue.lock().unwrap() = true;
    *node.outbox.enqueue_calls.lock().unwrap() = 0;
    node.handler.before_delivery_pass(now + 3);
    assert_eq!(*node.outbox.enqueue_calls.lock().unwrap(), 2);
    node.handler.before_delivery_pass(now + 4);
    assert_eq!(*node.outbox.enqueue_calls.lock().unwrap(), 2);
    assert!(node
        .records()
        .iter()
        .all(|record| record.decision.is_none()));
    // A decision past its life is not sent either.
    *node.outbox.refuse_enqueue.lock().unwrap() = false;
    node.handler.before_delivery_pass(now + DAY + 3_600);
    assert!(node.outbox.keys().is_empty());
}

#[tokio::test]
async fn an_approval_that_set_nothing_up_can_be_finished_or_declined() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    mark_approving(&node.data_dir, &request_id(1));
    let waiting = inbox_requests(&node.data_dir, node.profile_did(), now).unwrap();
    assert_eq!(
        waiting[0].stage,
        crate::notifications::CustodyRequestStage::Resumable
    );
    // Once its node trusts the owner, it can only be finished.
    node.installs_provider_for(&olivia.issuer(), 0x5b);
    node.outbox.fail(Some(SignFailure::Approvals));
    node.approve(1, now).await.unwrap_err();
    let waiting = inbox_requests(&node.data_dir, node.profile_did(), now).unwrap();
    assert_eq!(
        waiting[0].stage,
        crate::notifications::CustodyRequestStage::Finishing
    );
}

#[test]
fn each_admin_told_about_a_pool_gets_its_own_inbox_entry() {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("node");
    owner_only_dir(&data_dir);
    let fingerprint = format!("sha256:{}", hex::encode([0x42; 32]));
    for admin in ["did:key:z6MkAdminOne", "did:key:z6MkAdminTwo"] {
        crate::notifications::upsert_custody_pool_active_notification(
            &data_dir,
            admin,
            &fingerprint,
            &[],
            "Custody pool active",
            "Olivia's pool is active.",
            1,
        )
        .unwrap();
    }
    for admin in ["did:key:z6MkAdminOne", "did:key:z6MkAdminTwo"] {
        let mut summary = crate::notifications::NotificationSummary::default();
        crate::notifications::project_custody_pool_active_notifications(
            &mut summary,
            &data_dir,
            admin,
            std::slice::from_ref(&fingerprint),
        )
        .unwrap();
        assert_eq!(summary.entries.len(), 1, "{admin}");
        assert!(summary.entries[0].id.contains(admin), "{admin}");
        // Dismissing one admin's entry leaves the other's.
        assert!(
            crate::notifications::dismiss(&data_dir, Some(admin), &summary.entries[0].id).unwrap()
        );
    }
}

/// #388 A1 (#388-1): on an everyday host the Hosting roles are off. Offer
/// stays off, a contact's query and a new request answer `not_offering`, and
/// Approve refuses `host_trust_required` before anything is set up. The
/// stored request is kept.
#[tokio::test]
async fn everyday_home_cannot_offer_approve_or_include() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let owner = Owner::new("Olivia", now);
    node.installs_provider_for(&owner.issuer(), 0x41);
    assert_eq!(
        node.receive_as(&node.admin.principal_id, &owner, 1, now, now + 600),
        Ok(())
    );
    // The operator set everyday; the next clean start reads it.
    crate::host_trust::seed_for_test(&node.data_dir, false);

    let write = lock_custody_writes().await;
    let error = set_offer(&write, &node.data_dir, None, true, "Nadia", "Porto").unwrap_err();
    assert_eq!(refusal_code(&error), "host_trust_required");
    // Turning it off stays possible.
    set_offer(&write, &node.data_dir, None, false, "Nadia", "Porto").unwrap();
    set_offer_for_test_reenable(&node.data_dir);
    drop(write);
    assert_eq!(
        node.query_as(&node.admin.principal_id, &owner, now),
        Err(WireRefusal::NOT_OFFERING)
    );
    assert_eq!(node.receive(&owner, 2, now), Err(WireRefusal::NOT_OFFERING));

    let error = node.approve(1, now).await.unwrap_err();
    assert_eq!(refusal_code(&error), "host_trust_required");
    assert!(!crate::custody_pool_setup::holds_custody_state(&node.data_dir).unwrap());
    assert!(node.outbox.decisions().is_empty());
    assert_eq!(
        node.record(1).state,
        RequestState::Pending,
        "the request is kept"
    );

    // Positive control: the same Home after `wci-operated` and a restart.
    crate::host_trust::seed_for_test(&node.data_dir, true);
    node.offer(true).await.unwrap();
}

/// An offer written while the Home was trusted stays on disk; the gate, not
/// the file, keeps it off.
fn set_offer_for_test_reenable(data_dir: &Path) {
    let offer = CustodyOfferFileV1 {
        schema: OFFER_SCHEMA_V1.to_string(),
        enabled: true,
        run_by: "Nadia".to_string(),
        location: "Porto".to_string(),
        provides: node_provides(data_dir),
    };
    write_owner_only_bytes(&offer_path(data_dir), &serde_json::to_vec(&offer).unwrap()).unwrap();
}

// Plan B T2.2: one custody root per served pool.

/// The pool view of the one pool a test serves.
fn only_served_pool_view(data_dir: &Path) -> Option<ServedPoolView> {
    served_pools(data_dir)
        .ok()?
        .entries
        .keys()
        .find_map(|key| served_pool_view(data_dir, key))
}

#[tokio::test]
async fn v1_served_files_read_as_pool_one() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x70).await;
    let notice = node.notice(&olivia.pool_key, true, now);
    assert_eq!(node.tell(&olivia, &notice, now), Ok(()));
    let pool = served_pools(&node.data_dir).unwrap().entries[&olivia.pool_fingerprint()]
        .served_pool
        .clone()
        .unwrap();

    // The v1 files a Home from before the map keeps, and no v2 file.
    std::fs::remove_file(served_pools_path(&node.data_dir)).unwrap();
    let consent = serde_json::to_vec(&ServedConsentFileV1 {
        schema: SERVED_CONSENT_SCHEMA_V1.to_string(),
        owner_home: olivia.did(),
        term_days: 365,
        signing_key_fingerprint_full: olivia.pool_fingerprint(),
    })
    .unwrap();
    write_owner_only_bytes(&served_consent_path(&node.data_dir), &consent).unwrap();
    let v1_pool = serde_json::to_vec(&ServedPoolFileV1 {
        schema: SERVED_POOL_SCHEMA_V1.to_string(),
        owner_home: olivia.did(),
        fingerprint_full: pool.fingerprint_full.clone(),
        pool_start: pool.pool_start,
        term_end: pool.term_end,
        share: pool.share,
        threshold: pool.threshold,
        members: pool.members.clone(),
        received_at: pool.received_at,
    })
    .unwrap();
    write_owner_only_bytes(&served_pool_path(&node.data_dir), &v1_pool).unwrap();

    // Read as one entry: pool #1, root `inactive`, no admin profile yet.
    let read = served_pools(&node.data_dir).unwrap();
    assert!(read.v1_needs_attention.is_empty());
    assert_eq!(read.entries.len(), 1);
    let entry = &read.entries[&olivia.pool_fingerprint()];
    assert_eq!(entry.owner_home, olivia.did());
    assert_eq!(entry.root_path, "inactive");
    assert_eq!(entry.admin_profile_did, None);
    assert_eq!(entry.consent.term_days, 365);
    assert_eq!(entry.served_pool.as_ref(), Some(&pool));
    assert_eq!(
        only_served_pool_view(&node.data_dir).unwrap().share,
        pool.share
    );

    // The next write is v2; the v1 files stay on disk, unread from then on.
    update_served_pools(&node.data_dir, |pools| {
        pools
            .entries
            .get_mut(&olivia.pool_fingerprint())
            .unwrap()
            .pool_did = Some("did:key:z6MkTestPool".to_string());
        Ok(())
    })
    .unwrap();
    assert!(served_pools_path(&node.data_dir).exists());
    assert_eq!(
        std::fs::read(served_consent_path(&node.data_dir)).unwrap(),
        consent
    );
    assert_eq!(
        std::fs::read(served_pool_path(&node.data_dir)).unwrap(),
        v1_pool
    );
    write_owner_only_bytes(&served_consent_path(&node.data_dir), b"{}").unwrap();
    assert_eq!(served_pools(&node.data_dir).unwrap().entries.len(), 1);

    // A v1 pool without a matching consent is skipped, left as it is, and
    // needs attention.
    let other = super::tests::node(now);
    let orphan = serde_json::to_vec(&ServedPoolFileV1 {
        schema: SERVED_POOL_SCHEMA_V1.to_string(),
        owner_home: Owner::new("Oscar", now).did(),
        fingerprint_full: pool.fingerprint_full.clone(),
        pool_start: pool.pool_start,
        term_end: pool.term_end,
        share: pool.share,
        threshold: pool.threshold,
        members: pool.members,
        received_at: pool.received_at,
    })
    .unwrap();
    write_owner_only_bytes(&served_pool_path(&other.data_dir), &orphan).unwrap();
    let read = served_pools(&other.data_dir).unwrap();
    assert!(read.entries.is_empty());
    assert_eq!(read.v1_needs_attention.len(), 1);
    assert_eq!(
        std::fs::read(served_pool_path(&other.data_dir)).unwrap(),
        orphan
    );
}

#[tokio::test]
async fn ninth_pool_request_declines_with_too_many_pools() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let base = crate::protected_content_runtime::custody_provider_base(&node.data_dir);
    let roots: Vec<String> = (1u8..=8)
        .map(|fill| format!("pools/{}", hex::encode([fill; 32])))
        .collect();
    for root in &roots {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(base.join(root))
            .unwrap();
    }
    let olivia = Owner::new("Olivia", now);
    assert_eq!(
        WireRefusal::from(CustodyDeclineCode::TooManyPools),
        WireRefusal::new("too_many_pools")
    );
    assert_eq!(
        node.receive(&olivia, 1, now),
        Err(WireRefusal::from(CustodyDeclineCode::TooManyPools))
    );
    assert_eq!(
        node.query_as(&node.admin.principal_id, &olivia, now),
        Err(WireRefusal::NOT_OFFERING)
    );

    // Below eight it is heard; at eight again, approving declines with the
    // new code before anything is provisioned.
    std::fs::remove_dir(base.join(&roots[7])).unwrap();
    assert_eq!(node.receive(&olivia, 2, now), Ok(()));
    std::fs::create_dir(base.join(&roots[7])).unwrap();
    let error = node.approve(2, now).await.unwrap_err();
    assert_eq!(refusal_code(&error), "too_many_pools");
    assert_eq!(node.record(2).state, RequestState::Declined);
    assert_eq!(
        declined_with(&node.outbox.decisions()[0]),
        Some(CustodyDeclineCode::TooManyPools)
    );
    assert!(!base.join(pool_root_of(&olivia)).exists());
}

#[tokio::test]
async fn pool_active_for_pool_two_does_not_touch_pool_one() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);
    let node = serving(&olivia, now, 0x71).await;
    node.installs_provider_for(&oscar.issuer(), 0x72);
    assert_eq!(node.receive(&oscar, 2, now), Ok(()));
    node.approve(2, now).await.unwrap();

    let first = node.notice(&olivia.pool_key, true, now);
    assert_eq!(node.tell(&olivia, &first, now), Ok(()));
    let kept = served_pools(&node.data_dir).unwrap().entries[&olivia.pool_fingerprint()].clone();

    // Oscar's notice names his root's node, and keeps to his entry.
    let second = node.notice_in_root(&oscar.pool_key, &pool_root_of(&oscar), now);
    assert_eq!(node.tell(&oscar, &second, now), Ok(()));
    let pools = served_pools(&node.data_dir).unwrap();
    assert_eq!(pools.entries[&olivia.pool_fingerprint()], kept);
    assert_eq!(
        pools.entries[&oscar.pool_fingerprint()]
            .served_pool
            .as_ref()
            .unwrap()
            .fingerprint_full,
        second.fingerprint_full
    );
    // Oscar's pool cannot place this node through Olivia's root.
    let through_olivia = node.notice(&oscar.pool_key, true, now);
    assert_eq!(node.tell(&oscar, &through_olivia, now), Err(NOT_MEMBER));
    // Both Inbox entries stay.
    let admin = node.profile_did().to_string();
    assert_eq!(node.pool_entries(&admin).len(), 2);
}

#[tokio::test]
async fn removing_one_pool_leaves_the_other() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);
    let node = serving(&olivia, now, 0x73).await;
    node.installs_provider_for(&oscar.issuer(), 0x74);
    assert_eq!(node.receive(&oscar, 2, now), Ok(()));
    node.approve(2, now).await.unwrap();
    let kept = served_pools(&node.data_dir).unwrap().entries[&olivia.pool_fingerprint()].clone();

    let write = lock_custody_writes().await;
    let forgotten = forget_served_pool(&write, &node.data_dir, &oscar.pool_fingerprint())
        .unwrap()
        .unwrap();
    assert_eq!(forgotten.owner_home, oscar.did());
    drop(write);
    let pools = served_pools(&node.data_dir).unwrap();
    assert_eq!(pools.entries.len(), 1);
    assert_eq!(pools.entries[&olivia.pool_fingerprint()], kept);
    let notice = node.notice(&olivia.pool_key, true, now);
    assert_eq!(node.tell(&olivia, &notice, now), Ok(()));
}

#[tokio::test]
async fn entry_keeps_the_approving_admin_profile() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x75).await;
    let entry = served_pools(&node.data_dir).unwrap().entries[&olivia.pool_fingerprint()].clone();
    assert_eq!(entry.admin_profile_did.as_deref(), Some(node.profile_did()));
    assert_eq!(entry.root_path, "inactive");
    assert_eq!(
        entry.consent.signing_key_fingerprint_full,
        olivia.pool_fingerprint()
    );
}

// ---------------------------------------------------------------------------
// Plan B T2.2 rev 3: migration, roots, cap, owners and R3-D1/D4/D5
// ---------------------------------------------------------------------------

/// A Home serving `olivia` from before the map: its v1 consent and served
/// pool files, and no v2 file. Returns the v1 bytes as written.
async fn v1_home(olivia: &Owner, now: u64, seed: u8) -> (Node, Vec<u8>, Vec<u8>) {
    let node = serving(olivia, now, seed).await;
    let notice = node.notice(&olivia.pool_key, true, now);
    assert_eq!(node.tell(olivia, &notice, now), Ok(()));
    let pool = served_pools(&node.data_dir).unwrap().entries[&olivia.pool_fingerprint()]
        .served_pool
        .clone()
        .unwrap();
    std::fs::remove_file(served_pools_path(&node.data_dir)).unwrap();
    let consent = serde_json::to_vec(&ServedConsentFileV1 {
        schema: SERVED_CONSENT_SCHEMA_V1.to_string(),
        owner_home: olivia.did(),
        term_days: 365,
        signing_key_fingerprint_full: olivia.pool_fingerprint(),
    })
    .unwrap();
    write_owner_only_bytes(&served_consent_path(&node.data_dir), &consent).unwrap();
    let v1_pool = serde_json::to_vec(&ServedPoolFileV1 {
        schema: SERVED_POOL_SCHEMA_V1.to_string(),
        owner_home: olivia.did(),
        fingerprint_full: pool.fingerprint_full.clone(),
        pool_start: pool.pool_start,
        term_end: pool.term_end,
        share: pool.share,
        threshold: pool.threshold,
        members: pool.members.clone(),
        received_at: pool.received_at,
    })
    .unwrap();
    write_owner_only_bytes(&served_pool_path(&node.data_dir), &v1_pool).unwrap();
    (node, consent, v1_pool)
}

/// Marks a change so `update_served_pools` writes the v2 file.
fn touch_entry(data_dir: &Path, fingerprint: &str) {
    update_served_pools(data_dir, |pools| {
        pools.entries.get_mut(fingerprint).unwrap().pool_did =
            Some("did:key:z6MkTestPool".to_string());
        Ok(())
    })
    .unwrap();
}

/// Fills the map with reservations (no root on disk yet) until this Home
/// holds `in_use` roots.
fn reserve_until(data_dir: &Path, in_use: usize) {
    let mut seed = 0x10u8;
    while crate::custody_pool_setup::custody_roots_in_use(
        data_dir,
        &reserved_roots(&served_pools(data_dir).unwrap()),
    )
    .unwrap()
        < in_use
    {
        let fingerprint = format!("sha256:{}", hex::encode([seed; 32]));
        update_served_pools(data_dir, |pools| {
            pools.entries.insert(
                fingerprint.clone(),
                ServedPoolEntryV2 {
                    owner_home: format!("did:key:z6MkReserved{seed}"),
                    consent: ServedConsentV2 {
                        term_days: 365,
                        signing_key_fingerprint_full: fingerprint.clone(),
                    },
                    root_path: format!("pools/{}", hex::encode([seed; 32])),
                    admin_profile_did: None,
                    pool_did: None,
                    served_pool: None,
                    descriptor: None,
                },
            );
            Ok(())
        })
        .unwrap();
        seed += 1;
    }
}

/// `olivia`'s Home with a new pool signing key (R3-D4).
fn with_new_pool_key(olivia: &Owner) -> Owner {
    Owner {
        device: olivia.device.clone(),
        profile: olivia.profile.clone(),
        name: olivia.name,
        pool_key: generate_keypair().0,
    }
}

#[tokio::test]
async fn migrated_entry_has_no_admin_profile() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let (node, _, _) = v1_home(&olivia, now, 0x71).await;
    let read = served_pools(&node.data_dir).unwrap();
    assert_eq!(
        read.entries[&olivia.pool_fingerprint()].admin_profile_did,
        None
    );
    assert_eq!(read.own_root_admin_profile_did, None);
}

#[tokio::test]
async fn v1_files_are_kept_after_the_v2_write() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let (node, consent, v1_pool) = v1_home(&olivia, now, 0x72).await;
    touch_entry(&node.data_dir, &olivia.pool_fingerprint());
    assert!(served_pools_path(&node.data_dir).exists());
    assert_eq!(
        std::fs::read(served_consent_path(&node.data_dir)).unwrap(),
        consent
    );
    assert_eq!(
        std::fs::read(served_pool_path(&node.data_dir)).unwrap(),
        v1_pool
    );
}

#[tokio::test]
async fn v2_is_preferred_over_kept_v1_files() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let (node, _, _) = v1_home(&olivia, now, 0x73).await;
    touch_entry(&node.data_dir, &olivia.pool_fingerprint());
    // Another owner's v1 consent appears later: v2 is read, never v1.
    let oscar = Owner::new("Oscar", now);
    let other = serde_json::to_vec(&ServedConsentFileV1 {
        schema: SERVED_CONSENT_SCHEMA_V1.to_string(),
        owner_home: oscar.did(),
        term_days: 30,
        signing_key_fingerprint_full: oscar.pool_fingerprint(),
    })
    .unwrap();
    write_owner_only_bytes(&served_consent_path(&node.data_dir), &other).unwrap();
    let read = served_pools(&node.data_dir).unwrap();
    assert_eq!(read.entries.len(), 1);
    assert!(read.entries.contains_key(&olivia.pool_fingerprint()));
    assert_eq!(
        read.entries[&olivia.pool_fingerprint()].pool_did.as_deref(),
        Some("did:key:z6MkTestPool")
    );
}

#[tokio::test]
async fn interrupted_migration_rereads_v1_and_writes_v2_once() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let (node, _, _) = v1_home(&olivia, now, 0x74).await;
    // A crash before the rename leaves only a temporary file: v1 is read
    // again, the same each time, and nothing is written by a read.
    std::fs::write(
        served_pools_path(&node.data_dir).with_file_name(".custody-served-pools.json.0.tmp"),
        b"partial",
    )
    .unwrap();
    let first = served_pools(&node.data_dir).unwrap();
    assert_eq!(served_pools(&node.data_dir).unwrap(), first);
    assert!(!served_pools_path(&node.data_dir).exists());
    // A change with nothing to change writes nothing either.
    update_served_pools(&node.data_dir, |_| Ok(())).unwrap();
    assert!(!served_pools_path(&node.data_dir).exists());
    // The first real change writes v2, once; after it v2 wins.
    touch_entry(&node.data_dir, &olivia.pool_fingerprint());
    let written = std::fs::read(served_pools_path(&node.data_dir)).unwrap();
    assert_eq!(served_pools(&node.data_dir).unwrap().entries.len(), 1);
    update_served_pools(&node.data_dir, |_| Ok(())).unwrap();
    assert_eq!(
        std::fs::read(served_pools_path(&node.data_dir)).unwrap(),
        written
    );
}

#[tokio::test]
async fn malformed_v2_fails_closed_and_never_revives_v1_consent() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let (node, _, _) = v1_home(&olivia, now, 0x75).await;
    write_owner_only_bytes(&served_pools_path(&node.data_dir), b"{ not json").unwrap();
    assert!(served_pools(&node.data_dir).is_err());
    assert!(update_served_pools(&node.data_dir, |_| Ok(())).is_err());
    // The old consent is not revived: a repeat request is not auto-approved.
    let _ = node.receive(&olivia, 6, now);
    assert!(
        node.records()
            .iter()
            .all(|record| record.request_id != request_id(6)
                || record.state != RequestState::Approved)
    );
}

#[tokio::test]
async fn orphan_v1_pool_is_skipped_logged_and_needs_attention() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let (node, _, v1_pool) = v1_home(&olivia, now, 0x76).await;
    std::fs::remove_file(served_consent_path(&node.data_dir)).unwrap();
    let read = served_pools(&node.data_dir).unwrap();
    assert!(read.entries.is_empty());
    assert_eq!(read.v1_needs_attention.len(), 1);
    // Left untouched on disk.
    assert_eq!(
        std::fs::read(served_pool_path(&node.data_dir)).unwrap(),
        v1_pool
    );
}

#[test]
fn inactive_goes_only_to_the_first_pool_ever() {
    let now = crate::auth::now_ts();
    let node = node(now);
    let first = format!("sha256:{}", hex::encode([0x31; 32]));
    let second = format!("sha256:{}", hex::encode([0x32; 32]));
    assert_eq!(
        crate::custody_pool_setup::reserve_custody_root_for_new_pool(&node.data_dir, &first)
            .unwrap(),
        "inactive"
    );
    // The `pools` folder now records that `inactive` was given out.
    assert_eq!(
        crate::custody_pool_setup::reserve_custody_root_for_new_pool(&node.data_dir, &second)
            .unwrap(),
        format!("pools/{}", hex::encode([0x32; 32]))
    );
}

#[test]
fn inactive_is_not_reused_after_its_tombstone() {
    let now = crate::auth::now_ts();
    let node = node(now);
    let first = format!("sha256:{}", hex::encode([0x33; 32]));
    let root = crate::custody_pool_setup::reserve_custody_root_for_new_pool(&node.data_dir, &first)
        .unwrap();
    let inactive = crate::protected_content_runtime::custody_root_dir(&node.data_dir, &root);
    owner_only_dir(&inactive);
    std::fs::rename(&inactive, inactive.with_file_name("inactive.stopped-1")).unwrap();
    let later = format!("sha256:{}", hex::encode([0x34; 32]));
    assert_eq!(
        crate::custody_pool_setup::reserve_custody_root_for_new_pool(&node.data_dir, &later)
            .unwrap(),
        format!("pools/{}", hex::encode([0x34; 32]))
    );
}

/// Two served pools: Olivia on `inactive`, Oscar on his `pools/<hex>` root.
async fn two_pools(now: u64) -> (Node, Owner, Owner) {
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);
    let node = serving(&olivia, now, 0x77).await;
    node.installs_provider_for(&oscar.issuer(), 0x78);
    assert_eq!(node.receive(&oscar, 3, now), Ok(()));
    node.approve(3, now).await.unwrap();
    node.outbox.clear();
    (node, olivia, oscar)
}

#[tokio::test]
async fn restart_keeps_the_root_set() {
    let now = crate::auth::now_ts();
    let (node, _, oscar) = two_pools(now).await;
    // A restart reads the roots from disk again: the same set, in order.
    let roots =
        crate::protected_content_runtime::custody_provider_root_paths(&node.data_dir).unwrap();
    assert_eq!(roots, vec!["inactive".to_string(), pool_root_of(&oscar)]);
    assert_eq!(
        crate::protected_content_runtime::custody_provider_root_paths(&node.data_dir).unwrap(),
        roots
    );
}

#[tokio::test]
async fn one_node_descriptor_per_root() {
    let now = crate::auth::now_ts();
    let (node, _, oscar) = two_pools(now).await;
    let first = std::fs::read(
        crate::protected_content_config::custody_node_descriptor_path_for(
            &node.data_dir,
            "inactive",
        ),
    )
    .unwrap();
    let second = std::fs::read(
        crate::protected_content_config::custody_node_descriptor_path_for(
            &node.data_dir,
            &pool_root_of(&oscar),
        ),
    )
    .unwrap();
    assert_ne!(first, second);
}

#[tokio::test]
async fn legacy_approving_record_gets_a_root_by_the_same_rule() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);
    let node = serving(&olivia, now, 0x79).await;
    assert_eq!(node.receive(&oscar, 3, now), Ok(()));
    // An approval from before T2.2 stopped after marking the record, with
    // no reservation anywhere.
    with_requests(&node.data_dir, now, |records| {
        records
            .iter_mut()
            .find(|record| record.request_id == request_id(3))
            .unwrap()
            .state = RequestState::Approving;
        Ok(())
    })
    .unwrap();
    node.installs_provider_for(&oscar.issuer(), 0x7a);
    node.approve(3, now).await.unwrap();
    assert_eq!(
        served_pools(&node.data_dir).unwrap().entries[&oscar.pool_fingerprint()].root_path,
        pool_root_of(&oscar)
    );
}

#[tokio::test]
async fn card_read_answers_from_the_first_root_that_trusts_the_requester() {
    let now = crate::auth::now_ts();
    let (node, olivia, oscar) = two_pools(now).await;
    assert_eq!(
        crate::operator_control::custody_root_of_owner(&node.data_dir, &olivia.did()),
        Some("inactive".to_string())
    );
    assert_eq!(
        crate::operator_control::custody_root_of_owner(&node.data_dir, &oscar.did()),
        Some(pool_root_of(&oscar))
    );
    let stranger = Owner::new("Sam", now);
    assert_eq!(
        crate::operator_control::custody_root_of_owner(&node.data_dir, &stranger.did()),
        None
    );
}

#[tokio::test]
async fn cap_counts_include_and_approving_roots() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x7b).await;
    let in_use = |data_dir: &Path| {
        crate::custody_pool_setup::custody_roots_in_use(
            data_dir,
            &reserved_roots(&served_pools(data_dir).unwrap()),
        )
        .unwrap()
    };
    assert_eq!(in_use(&node.data_dir), 1);
    // A reservation an approval holds counts before its root exists.
    reserve_until(&node.data_dir, 2);
    assert_eq!(in_use(&node.data_dir), 2);
    // An Include root counts like any root on disk.
    owner_only_dir(&crate::protected_content_runtime::custody_root_dir(
        &node.data_dir,
        &format!("pools/{}", hex::encode([0x7c; 32])),
    ));
    assert_eq!(in_use(&node.data_dir), 3);
}

#[tokio::test]
async fn concurrent_ninth_admission_declines_one() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x7d).await;
    reserve_until(&node.data_dir, 7);
    let oscar = Owner::new("Oscar", now);
    let sam = Owner::new("Sam", now);
    assert_eq!(node.receive(&oscar, 3, now), Ok(()));
    assert_eq!(node.receive(&sam, 4, now), Ok(()));
    node.installs_provider_for(&oscar.issuer(), 0x7e);
    // The two approvals serialize on the write lock: the first takes the
    // eighth root, the second declines.
    node.approve(3, now).await.unwrap();
    let error = node.approve(4, now).await.unwrap_err();
    assert_eq!(refusal_code(&error), "too_many_pools");
    assert_eq!(node.record(4).code, Some(CustodyDeclineCode::TooManyPools));
}

#[tokio::test]
async fn failed_provisioning_releases_its_reservation() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);
    let node = serving(&olivia, now, 0x7f).await;
    assert_eq!(node.receive(&oscar, 3, now), Ok(()));
    // The provider installed for Olivia refuses Oscar's issuer, so his root
    // is never provisioned.
    assert!(node.approve(3, now).await.is_err());
    assert!(!served_pools(&node.data_dir)
        .unwrap()
        .entries
        .contains_key(&oscar.pool_fingerprint()));
}

#[tokio::test]
async fn inbox_stages_are_per_request() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);
    let node = serving(&olivia, now, 0x80).await;
    assert_eq!(node.receive(&olivia, 2, now + 1), Ok(()));
    assert_eq!(node.receive(&oscar, 3, now), Ok(()));
    let stage_of = |seed: u8| {
        let pools = served_pools(&node.data_dir).unwrap();
        custody_state_for(
            &node.data_dir,
            &pools,
            &reserved_roots(&pools),
            &node.record(seed),
        )
        .unwrap()
    };
    // Each request by its own owner and pool key: Olivia's pool is ours,
    // Oscar's is free below eight.
    assert_eq!(stage_of(2), CustodyStateFor::Ours);
    assert_eq!(stage_of(3), CustodyStateFor::Free);
    reserve_until(&node.data_dir, 8);
    assert_eq!(stage_of(3), CustodyStateFor::Full);
}

#[tokio::test]
async fn refresh_only_a_provider_this_server_started() {
    let now = crate::auth::now_ts();
    let (node, _, _) = two_pools(now).await;
    // No provider was started by this process for this Home.
    assert!(!crate::protected_content_runtime::custody_bridge_known(
        &node.data_dir
    ));
    assert!(
        crate::protected_content_runtime::refresh_custody_roots(&node.data_dir)
            .await
            .is_err()
    );
    assert!(
        !crate::protected_content_runtime::custody_root_loaded(&node.data_dir, "inactive").await
    );
}

#[tokio::test]
async fn remove_on_a_serving_home_keeps_the_served_pools() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x81).await;
    let own_issuer = crate::protected_content_config::runtime_issuer_hex(&node.data_dir).unwrap();
    node.installs_provider_for(&own_issuer, 0x88);
    let write = lock_custody_writes().await;
    crate::custody_pool_setup::include_local_node(&write, &node.data_dir, None, "Home", "Paris")
        .await
        .unwrap();
    let own = crate::custody_pool_setup::own_root_path(&node.data_dir)
        .unwrap()
        .unwrap();
    assert_ne!(own, "inactive");
    crate::custody_pool_setup::remove_local_node(&write, &node.data_dir, None)
        .await
        .unwrap();
    drop(write);
    // Only this Home's own root went; the served pool and its root stay.
    assert!(!crate::protected_content_runtime::custody_root_dir(&node.data_dir, &own).exists());
    assert!(
        crate::protected_content_runtime::custody_root_dir(&node.data_dir, "inactive").is_dir()
    );
    assert!(served_pools(&node.data_dir)
        .unwrap()
        .entries
        .contains_key(&olivia.pool_fingerprint()));
    assert_eq!(
        custody_root_trust_at(&node.data_dir, "inactive").unwrap(),
        RootTrust::Trusts(olivia.did())
    );
}

#[tokio::test]
async fn served_owner_with_a_new_key_gets_a_second_pool() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x82).await;
    let renewed = with_new_pool_key(&olivia);
    assert_eq!(node.receive(&renewed, 2, now), Ok(()));
    node.installs_provider_for(&olivia.issuer(), 0x83);
    node.approve(2, now).await.unwrap();
    let pools = served_pools(&node.data_dir).unwrap();
    assert_eq!(pools.entries.len(), 2);
    assert_eq!(
        pools.entries[&olivia.pool_fingerprint()].root_path,
        "inactive"
    );
    assert_eq!(
        pools.entries[&renewed.pool_fingerprint()].root_path,
        pool_root_of(&renewed)
    );
}

#[tokio::test]
async fn new_key_request_counts_toward_the_cap() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x84).await;
    reserve_until(&node.data_dir, 8);
    let renewed = with_new_pool_key(&olivia);
    assert_eq!(
        node.receive(&renewed, 2, now),
        Err(WireRefusal::from(CustodyDeclineCode::TooManyPools))
    );
}

#[tokio::test]
async fn new_key_request_is_heard_without_the_offer() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x85).await;
    node.offer(false).await.unwrap();
    let renewed = with_new_pool_key(&olivia);
    assert_eq!(node.receive(&renewed, 2, now), Ok(()));
    assert_eq!(node.record(2).state, RequestState::Pending);
    // Someone this Home does not serve still needs the offer.
    let stranger = Owner::new("Sam", now);
    assert_eq!(
        node.receive(&stranger, 3, now),
        Err(WireRefusal::NOT_OFFERING)
    );
}

#[tokio::test]
async fn approval_after_a_crash_provisions_the_same_root() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);
    let node = serving(&olivia, now, 0x86).await;
    assert_eq!(node.receive(&oscar, 3, now), Ok(()));
    // The first approval reserved Oscar's root in the map and stopped.
    let record = node.record(3);
    assert!(reserve_served_pool_entry(
        &node.data_dir,
        &record,
        &pool_root_of(&oscar),
        node.profile_did()
    )
    .unwrap());
    with_requests(&node.data_dir, now, |records| {
        records
            .iter_mut()
            .find(|record| record.request_id == request_id(3))
            .unwrap()
            .state = RequestState::Approving;
        Ok(())
    })
    .unwrap();
    node.installs_provider_for(&oscar.issuer(), 0x87);
    node.approve(3, now).await.unwrap();
    assert_eq!(
        served_pools(&node.data_dir).unwrap().entries[&oscar.pool_fingerprint()].root_path,
        pool_root_of(&oscar)
    );
    assert_eq!(
        custody_root_trust_at(&node.data_dir, &pool_root_of(&oscar)).unwrap(),
        RootTrust::Trusts(oscar.did())
    );
}

/// R3-D5 = B: the request record is unchanged, so an older build still
/// reads the requests file after an approval.
#[tokio::test]
async fn requests_file_stays_readable_by_the_older_schema() {
    let now = crate::auth::now_ts();
    let (node, _, _) = two_pools(now).await;
    let text = std::fs::read_to_string(requests_path(&node.data_dir)).unwrap();
    assert!(!text.contains("root_path"));
    assert!(!load_requests(&node.data_dir).unwrap().is_empty());
}

/// Plan B T2.3: an orphan v1 pool is named in the summary's
/// `serving_needs_attention`.
#[tokio::test]
async fn orphan_v1_pool_is_in_serving_needs_attention() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let (node, _, _) = v1_home(&olivia, now, 0x89).await;
    std::fs::remove_file(served_consent_path(&node.data_dir)).unwrap();
    let summary = crate::custody_pool_setup::summary(&node.data_dir, None, None, None).await;
    assert_eq!(summary.serving_needs_attention.len(), 1);
}

/* ---------- OPEN-LOOP F1: one consent, two duties ---------- */

/// `owner`'s allow list on this node, as replica admission reads it.
fn owner_allows(node: &Node, owner: &Owner) -> Option<Vec<String>> {
    crate::operator_control::granted_peer_actions(&node.data_dir, &owner.did())
}

/// Whether this node takes a replica `import_exact` from `owner`.
fn takes_replicas_from(node: &Node, owner: &Owner) -> bool {
    let mut request = serde_json::json!({ "op": "import_exact", "cid": "bafy-sealed" });
    crate::carrier::admit_carrier_peer_content_request(
        &node.data_dir,
        &owner.did(),
        "import_exact",
        &mut request,
    )
    .is_ok()
}

/// This node registers `owner` as a peer with `allow`, before any pool.
fn grant_before_any_pool(node: &Node, owner: &Owner, allow: &[&str]) {
    crate::operator_control::upsert_peer(
        &node.data_dir,
        crate::operator_control::OperatorPeer {
            did: owner.did(),
            label: "Olivia's Home".to_string(),
            connect_ticket: "ticket-olivia".to_string(),
            allow: allow.iter().map(|action| action.to_string()).collect(),
            ..crate::operator_control::OperatorPeer::default()
        },
    )
    .unwrap();
}

/// Stop serving `owner`'s pool, as Hosting does it.
async fn stop_serving(node: &Node, owner: &Owner, now: u64) {
    let write = lock_custody_writes().await;
    crate::custody_pool_setup::stop_serving_pool(
        &write,
        &node.data_dir,
        None,
        owner.pool_fingerprint().strip_prefix("sha256:").unwrap(),
        now,
    )
    .await
    .unwrap();
}

/// `owner`'s second pool: the same Home, another pool signing key.
fn second_pool_of(owner: &Owner) -> Owner {
    Owner {
        device: owner.device.clone(),
        profile: owner.profile.clone(),
        name: owner.name,
        pool_key: generate_keypair().0,
    }
}

#[tokio::test]
async fn approving_a_pool_lets_its_owner_send_copies_and_keeps_other_allows() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    let oscar = Owner::new("Oscar", now);
    grant_before_any_pool(&node, &olivia, &["status.read"]);
    node.installs_provider_for(&olivia.issuer(), 0x90);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    assert_eq!(node.receive(&oscar, 2, now), Ok(()));
    assert!(!takes_replicas_from(&node, &olivia));

    node.approve(1, now).await.unwrap();

    // The served owner may now send its copies; what it held stays.
    let allows = owner_allows(&node, &olivia).unwrap();
    assert!(
        allows.iter().any(|action| action == "content.replica"),
        "{allows:?}"
    );
    assert!(
        allows.iter().any(|action| action == "status.read"),
        "{allows:?}"
    );
    let peer = crate::operator_control::load_operator_control(&node.data_dir)
        .unwrap()
        .peers
        .into_iter()
        .find(|peer| peer.did == olivia.did())
        .unwrap();
    assert_eq!(peer.connect_ticket, "ticket-olivia");
    assert_eq!(peer.label, "Olivia's Home");
    assert!(takes_replicas_from(&node, &olivia));
    // An owner whose request waits gets nothing.
    assert_eq!(owner_allows(&node, &oscar), None);
    assert!(!takes_replicas_from(&node, &oscar));

    // Approving again keeps one grant.
    node.approve(1, now).await.unwrap();
    assert_eq!(
        owner_allows(&node, &olivia)
            .unwrap()
            .iter()
            .filter(|action| *action == "content.replica")
            .count(),
        1
    );
}

#[tokio::test]
async fn an_owner_unknown_to_this_node_is_registered_with_the_replica_grant_alone() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x91).await;
    assert_eq!(
        owner_allows(&node, &olivia),
        Some(vec!["content.replica".to_string()])
    );
    assert!(takes_replicas_from(&node, &olivia));
}

/// ADV-14: withdrawal revokes both duties. Stopping the owner's last pool
/// takes the share role and the replica grant a pool added.
#[tokio::test]
async fn guard_a_withdrawn_member_refuses_a_replica_import_from_its_former_owner() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0x92).await;
    assert!(takes_replicas_from(&node, &olivia));

    stop_serving(&node, &olivia, now).await;

    assert!(!takes_replicas_from(&node, &olivia));
}

/// ADV-14: until POOL-SERVE lands, a withdrawn member serves nothing of the
/// former pool because it holds no grant for it: only the grant a pool
/// added goes, and only with the owner's last root.
#[tokio::test]
async fn guard_a_withdrawn_member_holds_no_replica_grant_for_its_former_owner() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let second = second_pool_of(&olivia);
    let node = serving(&olivia, now, 0x93).await;
    node.installs_provider_for(&olivia.issuer(), 0x94);
    assert_eq!(node.receive(&second, 3, now), Ok(()));
    node.approve(3, now).await.unwrap();

    // One of two roots stops: the owner still has a pool here.
    stop_serving(&node, &olivia, now).await;
    assert!(owner_allows(&node, &olivia)
        .unwrap()
        .iter()
        .any(|action| action == "content.replica"));

    // Its last root stops: the grant the pools added goes.
    stop_serving(&node, &second, now).await;
    assert!(!owner_allows(&node, &olivia)
        .unwrap_or_default()
        .iter()
        .any(|action| action == "content.replica"));
}

#[tokio::test]
async fn stopping_keeps_a_replica_grant_the_owner_held_before_the_pool() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    grant_before_any_pool(&node, &olivia, &["content.replica", "status.read"]);
    node.installs_provider_for(&olivia.issuer(), 0x95);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    node.approve(1, now).await.unwrap();

    stop_serving(&node, &olivia, now).await;

    let mut allows = owner_allows(&node, &olivia).unwrap();
    allows.sort();
    assert_eq!(allows, ["content.replica", "status.read"]);
    assert!(takes_replicas_from(&node, &olivia));
}

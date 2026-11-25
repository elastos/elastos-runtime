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
        Self::with_device(name, now, generate_keypair().0)
    }

    /// An owner whose Home runs under `device`.
    fn with_device(name: &'static str, now: u64, device: SigningKey) -> Self {
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
            copies_pending: false,
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
    let ticket = crate::carrier::local_carrier_connect_ticket(&endpoint);
    node.set_handler(Arc::new(NodeConsentHandler::new(
        Arc::new(node.downgrade()),
        Arc::new(move || Some(crate::carrier::local_carrier_connect_ticket(&endpoint))),
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

/* ---------- MEMBER-COPIES: members keep copies of their pools' files, and serve them ---------- */

use std::collections::BTreeSet;
use std::sync::Mutex as StdMutex;

/// A content-plane folder as its owner's Home published it.
#[derive(Clone)]
struct Folder {
    cid: String,
    manifest: Vec<u8>,
    files: Vec<(String, Vec<u8>)>,
}

impl Folder {
    fn new(
        label: &str,
        kind: &str,
        files: Vec<(&str, Vec<u8>)>,
        links: serde_json::Value,
        object_did: Option<&str>,
        publisher_did: Option<&str>,
    ) -> Self {
        use sha2::Digest as _;
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schema": "elastos.content.object.manifest/v1",
            "kind": kind,
            "content_digest": format!("sha256:{:x}", sha2::Sha256::digest(label.as_bytes())),
            "files": files.iter().map(|(path, bytes)| serde_json::json!({
                "path": path,
                "sha256": format!("{:x}", sha2::Sha256::digest(bytes)),
                "size": bytes.len(),
            })).collect::<Vec<_>>(),
            "links": links,
            "object_did": object_did,
            "publisher_did": publisher_did,
        }))
        .unwrap();
        let cid = cid::Cid::new_v1(
            0x70,
            cid::multihash::Multihash::<64>::wrap(0x12, sha2::Sha256::digest(&manifest).as_slice())
                .unwrap(),
        )
        .to_string();
        Self {
            cid,
            manifest,
            files: files
                .into_iter()
                .map(|(path, bytes)| (path.to_string(), bytes))
                .collect(),
        }
    }

    fn bytes(&self) -> u64 {
        self.files
            .iter()
            .fold(self.manifest.len() as u64, |total, (_, bytes)| {
                total + bytes.len() as u64
            })
    }
}

/// A protected listing and the payload and metadata folders it names.
struct ListedItem {
    listing: Folder,
    content: Folder,
    metadata: Folder,
    /// A pool-minted item's real custody envelope, whose node shares a
    /// member's share store can accept.
    envelope: Option<elastos_protected_content_contracts::CustodyEnvelopeV1>,
}

/// When the copy fixtures' custody pool was signed.
static COPY_POOL_AT: std::sync::LazyLock<u64> = std::sync::LazyLock::new(crate::auth::now_ts);

fn copy_xwing(
    seed: u8,
) -> [u8; elastos_protected_content_contracts::PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
    use x_wing::kem::Decapsulator as _;
    use x_wing::KeyExport as _;
    let secret = x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE]);
    secret.encapsulation_key().to_bytes().into()
}

/// The custody pool the member serves for its owner.
fn served_custody_pool() -> elastos_protected_content_contracts::PoolEpochBundleV1 {
    elastos_protected_content_contracts::test_fixtures::pool_bundle(copy_xwing, *COPY_POOL_AT)
}

/// Another owner's custody pool.
fn other_custody_pool() -> elastos_protected_content_contracts::PoolEpochBundleV1 {
    elastos_protected_content_contracts::test_fixtures::pool_bundle_signed_by(
        copy_xwing,
        *COPY_POOL_AT,
        None,
        None,
        0x73,
    )
}

impl ListedItem {
    /// An item of the custody pool the member serves.
    fn new(label: &str) -> Self {
        Self::in_pool(label, &served_custody_pool())
    }

    /// An item whose key envelope names the custody pool of `bundle`.
    fn in_pool(
        label: &str,
        bundle: &elastos_protected_content_contracts::PoolEpochBundleV1,
    ) -> Self {
        use elastos_protected_content_contracts::CanonicalContract as _;
        let content = Folder::new(
            &format!("{label} payload"),
            "protected-content-object",
            vec![("object.epc1", vec![0x51; 300])],
            serde_json::json!([]),
            None,
            None,
        );
        let metadata = Folder::new(
            &format!("{label} metadata"),
            "protected-content-metadata",
            vec![(
                "metadata.json",
                format!("{{\"name\":\"{label}\"}}").into_bytes(),
            )],
            serde_json::json!([]),
            None,
            None,
        );
        let mut package =
            crate::protected_content_runtime::tests::runtime_custody_listing_record_for_test(
                elastos_protected_content_contracts::Digest32::new([0x74; 32]),
                "person:local:owner",
                label,
                2_000_000_000,
            )
            .package;
        let envelope =
            elastos_protected_content_contracts::KeyEnvelopeIdentityV1::from_canonical_bytes(
                &base64::engine::general_purpose::STANDARD
                    .decode(&package.key_envelope_identity_base64)
                    .unwrap(),
            )
            .unwrap();
        package.key_envelope_identity_base64 = base64::engine::general_purpose::STANDARD.encode(
            elastos_protected_content_contracts::test_fixtures::key_envelope_for(
                bundle,
                envelope.encrypted_content(),
            )
            .canonical_bytes()
            .unwrap(),
        );
        package.content_cid = content.cid.clone();
        package.metadata_cid = metadata.cid.clone();
        package.token_uri = format!("ipfs://{}", metadata.cid);
        let listing = Folder::new(
            label,
            "protected-content-listing",
            vec![("listing.json", serde_json::to_vec(&package).unwrap())],
            serde_json::json!([
                {"rel": "metadata", "cid": metadata.cid},
                {"rel": "encrypted-content", "cid": content.cid},
            ]),
            Some(&package.content_id),
            Some(&package.publisher_profile_did),
        );
        Self {
            listing,
            content,
            metadata,
            envelope: None,
        }
    }

    /// MC-F6: an item of the served custody pool that the Home seeded
    /// `minter_seed` minted into `pool`: its listing carries that Home's
    /// signed share statement, for its own key envelope and KID unless
    /// `kid` names another.
    fn minted(
        label: &str,
        minter_seed: u8,
        pool: elastos_protected_content_contracts::PoolDidV1,
        kid: Option<elastos_protected_content_contracts::ContentAccessIdV1>,
    ) -> Self {
        use elastos_protected_content_contracts::CanonicalContract as _;
        let mut item = Self::new(label);
        let mut package: crate::protected_content_runtime::RuntimePortableListingPackage =
            serde_json::from_slice(&item.listing.files[0].1).unwrap();
        let synthetic =
            elastos_protected_content_contracts::KeyEnvelopeIdentityV1::from_canonical_bytes(
                &base64::engine::general_purpose::STANDARD
                    .decode(&package.key_envelope_identity_base64)
                    .unwrap(),
            )
            .unwrap();
        // A real envelope of the served pool's committee for this item, so
        // its node share is one a member's store accepts.
        let bundle = served_custody_pool();
        let nodes: Vec<_> = bundle
            .signed_epoch()
            .statement()
            .nodes()
            .iter()
            .map(|node| {
                elastos_protected_content_custody::ExactCustodyEnvelopeNodeV1::new(
                    node.node_public_key(),
                    node.custody_public_key(),
                )
            })
            .collect();
        let custody_envelope =
            elastos_protected_content_custody::provision_custody_envelope_for_exact_nodes(
                synthetic.encrypted_content().clone(),
                &elastos_protected_content_custody::ContentEncryptionKeyV1::generate().unwrap(),
                bundle.signed_pool().pool_identity().unwrap(),
                bundle.signed_epoch().epoch_identity().unwrap(),
                bundle
                    .signed_committee_authorization()
                    .authorization_identity()
                    .unwrap(),
                &nodes,
            )
            .unwrap();
        let envelope = custody_envelope.key_envelope_identity().unwrap();
        package.key_envelope_identity_base64 =
            base64::engine::general_purpose::STANDARD.encode(envelope.canonical_bytes().unwrap());
        let own_kid = elastos_protected_content_contracts::ContentAccessIdV1::new(
            hex::decode(package.content_access_id.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let (minter_key, _) = elastos_identity::derive_did(&[minter_seed; 32]);
        let statement = elastos_protected_content_contracts::PoolMintShareStatementV1::new(
            pool,
            elastos_protected_content_contracts::RuntimeOperationIssuerKeyV1::new(
                minter_key.verifying_key().to_bytes(),
            )
            .unwrap(),
            envelope,
            kid.unwrap_or(own_kid),
        )
        .unwrap();
        use ed25519_dalek::Signer as _;
        let signature = minter_key
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec();
        package.pool_mint_share_b64 = Some(
            base64::engine::general_purpose::STANDARD.encode(
                elastos_protected_content_contracts::SignedPoolMintShareV1::new(
                    statement, signature,
                )
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            ),
        );
        item.listing = Folder::new(
            label,
            "protected-content-listing",
            vec![("listing.json", serde_json::to_vec(&package).unwrap())],
            serde_json::json!([
                {"rel": "metadata", "cid": item.metadata.cid},
                {"rel": "encrypted-content", "cid": item.content.cid},
            ]),
            Some(&package.content_id),
            Some(&package.publisher_profile_did),
        );
        item.envelope = Some(custody_envelope);
        item
    }

    /// The minting Home's signed share statement this item's listing carries.
    fn mint_share(&self) -> elastos_protected_content_contracts::SignedPoolMintShareV1 {
        use elastos_protected_content_contracts::CanonicalContract as _;
        let package: crate::protected_content_runtime::RuntimePortableListingPackage =
            serde_json::from_slice(&self.listing.files[0].1).unwrap();
        elastos_protected_content_contracts::SignedPoolMintShareV1::from_canonical_bytes(
            &base64::engine::general_purpose::STANDARD
                .decode(package.pool_mint_share_b64.unwrap())
                .unwrap(),
        )
        .unwrap()
    }

    /// The minting Home's Runtime key and the KID of this item.
    fn minted_slot(
        &self,
        minter_seed: u8,
    ) -> (
        elastos_protected_content_contracts::RuntimeOperationIssuerKeyV1,
        elastos_protected_content_contracts::ContentAccessIdV1,
    ) {
        let package: crate::protected_content_runtime::RuntimePortableListingPackage =
            serde_json::from_slice(&self.listing.files[0].1).unwrap();
        let (minter_key, _) = elastos_identity::derive_did(&[minter_seed; 32]);
        (
            elastos_protected_content_contracts::RuntimeOperationIssuerKeyV1::new(
                minter_key.verifying_key().to_bytes(),
            )
            .unwrap(),
            elastos_protected_content_contracts::ContentAccessIdV1::new(
                hex::decode(package.content_access_id.trim_start_matches("0x"))
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        )
    }

    fn folders(&self) -> [&Folder; 3] {
        [&self.listing, &self.content, &self.metadata]
    }

    fn cids(&self) -> BTreeSet<String> {
        self.folders()
            .iter()
            .map(|folder| folder.cid.clone())
            .collect()
    }
}

/// The fixture committee node 1's provisioning record of a minted `item`'s
/// share, the Runtime statement of the Home seeded `seed` for it, and that
/// Home's Runtime key.
fn minted_provisioning(
    seed: u8,
    item: &ListedItem,
) -> (
    elastos_protected_content_contracts::CustodyNodeProvisioningRecordV1,
    elastos_protected_content_contracts::SignedRuntimeCustodyProvisioningV1,
    elastos_protected_content_contracts::RuntimeOperationIssuerKeyV1,
) {
    use ed25519_dalek::Signer as _;
    use elastos_protected_content_contracts::test_fixtures::node_public_key;
    use elastos_protected_content_contracts::CanonicalContract as _;
    let envelope = item.envelope.as_ref().unwrap();
    let record = elastos_protected_content_contracts::CustodyNodeProvisioningRecordV1::new(
        envelope.key_envelope_identity().unwrap(),
        envelope.manifest().clone(),
        node_public_key(1),
        envelope
            .stored_share_for_node(node_public_key(1))
            .unwrap()
            .clone(),
    )
    .unwrap();
    let (minter_key, _) = elastos_identity::derive_did(&[seed; 32]);
    let issuer = elastos_protected_content_contracts::RuntimeOperationIssuerKeyV1::new(
        minter_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let now = crate::auth::now_ts();
    let statement =
        elastos_protected_content_contracts::RuntimeCustodyProvisioningStatementV1::new(
            issuer,
            record.record_identity().unwrap(),
            elastos_protected_content_contracts::RuntimeCustodyProvisioningIdV1::new(
                elastos_protected_content_contracts::Digest32::new([seed; 32]),
            )
            .unwrap(),
            now - 1,
            now + 59,
        )
        .unwrap();
    let provisioning =
        elastos_protected_content_contracts::SignedRuntimeCustodyProvisioningV1::new(
            statement.clone(),
            minter_key
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
    (record, provisioning, issuer)
}

/// Holds one fixture call until the test lets it go, and says when it is
/// held.
#[derive(Clone)]
struct Gate {
    at: (String, String),
    reached: Arc<tokio::sync::Notify>,
    open: Arc<tokio::sync::Semaphore>,
}

impl Gate {
    fn new(cid: &str, path: &str) -> Self {
        Self {
            at: (cid.to_string(), path.to_string()),
            reached: Arc::new(tokio::sync::Notify::new()),
            open: Arc::new(tokio::sync::Semaphore::new(0)),
        }
    }

    async fn pass(gate: &StdMutex<Option<Gate>>, cid: &str, path: &str) {
        let held = {
            let mut gate = gate.lock().unwrap();
            if gate
                .as_ref()
                .is_some_and(|gate| gate.at == (cid.to_string(), path.to_string()))
            {
                gate.take()
            } else {
                None
            }
        };
        if let Some(gate) = held {
            gate.reached.notify_one();
            let _ = gate.open.acquire().await.unwrap();
        }
    }

    fn release(&self) {
        self.open.add_permits(1);
    }
}

/// The owner Home's content plane: it serves the files of the folders it
/// published, and records each read.
#[derive(Default)]
struct OwnerFolders {
    files: StdMutex<BTreeMap<(String, String), Vec<u8>>>,
    reads: StdMutex<Vec<(String, String)>>,
    gate: StdMutex<Option<Gate>>,
}

impl OwnerFolders {
    /// Serves `folder`'s files under `cid`.
    fn serve_as(&self, cid: &str, folder: &Folder) {
        let mut files = self.files.lock().unwrap();
        files.insert(
            (
                cid.to_string(),
                crate::content::CONTENT_OBJECT_MANIFEST_PATH.to_string(),
            ),
            folder.manifest.clone(),
        );
        for (path, bytes) in &folder.files {
            files.insert((cid.to_string(), path.clone()), bytes.clone());
        }
    }

    fn reads(&self) -> usize {
        self.reads.lock().unwrap().len()
    }
}

#[async_trait::async_trait]
impl elastos_runtime::provider::Provider for OwnerFolders {
    async fn handle(
        &self,
        _: elastos_runtime::provider::ResourceRequest,
    ) -> Result<elastos_runtime::provider::ResourceResponse, elastos_runtime::provider::ProviderError>
    {
        Err(elastos_runtime::provider::ProviderError::Provider(
            "fixture raw only".into(),
        ))
    }
    fn schemes(&self) -> Vec<&'static str> {
        vec![]
    }
    fn name(&self) -> &'static str {
        "owner-folders"
    }
    async fn send_raw(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, elastos_runtime::provider::ProviderError> {
        let key = (
            request["cid"].as_str().unwrap_or_default().to_string(),
            request["path"].as_str().unwrap_or_default().to_string(),
        );
        Gate::pass(&self.gate, &key.0, &key.1).await;
        self.reads.lock().unwrap().push(key.clone());
        Ok(match self.files.lock().unwrap().get(&key) {
            Some(bytes) => serde_json::json!({"status": "ok", "data": {
                "data": base64::engine::general_purpose::STANDARD.encode(bytes),
            }}),
            None => serde_json::json!({"status": "error", "code": "not_found",
                "message": "no such file"}),
        })
    }
}

/// The member's offline Kubo: it pins only blocks it holds, and imports a
/// staged folder as the CID of the folder whose manifest it carries.
#[derive(Default)]
struct MemberIpfs {
    folder_cids: StdMutex<BTreeMap<Vec<u8>, String>>,
    local_files: StdMutex<BTreeMap<(String, String), Vec<u8>>>,
    imported: StdMutex<BTreeSet<String>>,
    pinned: StdMutex<BTreeSet<String>>,
    unpinned: StdMutex<Vec<String>>,
    /// Holds a `pin` of one CID (path "pin").
    gate: StdMutex<Option<Gate>>,
    /// CIDs whose `pin` lands but answers an error.
    pin_answers_badly: StdMutex<BTreeSet<String>>,
    /// CIDs whose `pin` lands but whose answer is lost.
    pin_reply_lost: StdMutex<BTreeSet<String>>,
    /// A CID whose `pin` fails and whose pin state then cannot be read.
    pin_state_unknown: StdMutex<Option<String>>,
    /// A CID whose pin state can never be read.
    pin_status_fails: StdMutex<Option<String>>,
    /// Every request this Kubo was sent, as (op, cid).
    ops: StdMutex<Vec<(String, String)>>,
}

impl MemberIpfs {
    fn knows(&self, folder: &Folder) {
        self.folder_cids
            .lock()
            .unwrap()
            .insert(folder.manifest.clone(), folder.cid.clone());
    }

    fn pinned(&self) -> BTreeSet<String> {
        self.pinned.lock().unwrap().clone()
    }

    fn imported(&self) -> BTreeSet<String> {
        self.imported.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl elastos_runtime::provider::Provider for MemberIpfs {
    async fn handle(
        &self,
        _: elastos_runtime::provider::ResourceRequest,
    ) -> Result<elastos_runtime::provider::ResourceResponse, elastos_runtime::provider::ProviderError>
    {
        Err(elastos_runtime::provider::ProviderError::Provider(
            "fixture raw only".into(),
        ))
    }
    fn schemes(&self) -> Vec<&'static str> {
        vec![]
    }
    fn name(&self) -> &'static str {
        "member-ipfs"
    }
    async fn send_raw(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, elastos_runtime::provider::ProviderError> {
        let cid = request["cid"].as_str().unwrap_or_default().to_string();
        self.ops.lock().unwrap().push((
            request["op"].as_str().unwrap_or_default().to_string(),
            cid.clone(),
        ));
        if request["op"] == "pin" {
            Gate::pass(&self.gate, &cid, "pin").await;
            if self.imported.lock().unwrap().contains(&cid) {
                if self.pin_answers_badly.lock().unwrap().contains(&cid) {
                    self.pinned.lock().unwrap().insert(cid);
                    return Ok(serde_json::json!({"status": "error", "message": "pin timed out"}));
                }
                if self.pin_reply_lost.lock().unwrap().contains(&cid) {
                    self.pinned.lock().unwrap().insert(cid);
                    return Err(elastos_runtime::provider::ProviderError::Io(
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "reply lost"),
                    ));
                }
            }
            if self.pin_state_unknown.lock().unwrap().as_deref() == Some(cid.as_str()) {
                return Ok(serde_json::json!({"status": "error", "message": "pin failed"}));
            }
        }
        if request["op"] == "pin_status"
            && self.pin_status_fails.lock().unwrap().as_deref() == Some(cid.as_str())
        {
            return Ok(serde_json::json!({"status": "error", "message": "unavailable"}));
        }
        if request["op"] == "pin_status"
            && self.pin_state_unknown.lock().unwrap().as_deref() == Some(cid.as_str())
            && self.imported.lock().unwrap().contains(&cid)
        {
            return Ok(serde_json::json!({"status": "error", "message": "unavailable"}));
        }
        Ok(match request["op"].as_str() {
            Some("cat") => {
                let key = (
                    cid.clone(),
                    request["path"].as_str().unwrap_or_default().to_string(),
                );
                match self.local_files.lock().unwrap().get(&key) {
                    Some(bytes) => serde_json::json!({"status": "ok", "data": {
                        "data": base64::engine::general_purpose::STANDARD.encode(bytes),
                    }}),
                    None => {
                        serde_json::json!({"status": "error", "code": "not_found", "message": "not found locally"})
                    }
                }
            }
            Some("pin_status") => serde_json::json!({"status": "ok", "data": {
                "pinned": self.pinned.lock().unwrap().contains(&cid),
            }}),
            Some("pin")
                if self.imported.lock().unwrap().contains(&cid)
                    || self.pinned.lock().unwrap().contains(&cid) =>
            {
                self.pinned.lock().unwrap().insert(cid);
                serde_json::json!({"status": "ok", "data": {}})
            }
            Some("pin") => serde_json::json!({"status": "error",
                "message": "block was not found locally (offline)"}),
            Some("unpin") => {
                Gate::pass(&self.gate, &cid, "unpin").await;
                self.pinned.lock().unwrap().remove(&cid);
                self.unpinned.lock().unwrap().push(cid);
                serde_json::json!({"status": "ok", "data": {}})
            }
            Some("runtime_add_local_object") => {
                let root = std::path::Path::new(request["object"]["root"].as_str().unwrap());
                let manifest =
                    std::fs::read(root.join(crate::content::CONTENT_OBJECT_MANIFEST_PATH)).unwrap();
                match self.folder_cids.lock().unwrap().get(&manifest) {
                    Some(cid) => {
                        let object: crate::content::ContentObjectManifest =
                            serde_json::from_slice(&manifest).unwrap();
                        let mut files = self.local_files.lock().unwrap();
                        for file in object.files {
                            files.insert(
                                (cid.clone(), file.path.clone()),
                                std::fs::read(root.join(file.path)).unwrap(),
                            );
                        }
                        self.imported.lock().unwrap().insert(cid.clone());
                        serde_json::json!({"status": "ok", "data": {"cid": cid}})
                    }
                    None => serde_json::json!({"status": "error", "code": "unknown"}),
                }
            }
            _ => serde_json::json!({"status": "error", "code": "unsupported"}),
        })
    }
}

/// A pool owner's Home on Carrier, and a member serving its pool with its
/// own content plane over an offline Kubo.
struct CopyFixture {
    owner: Owner,
    owner_home: crate::carrier::tests::HolderRuntime,
    folders: Arc<OwnerFolders>,
    member: Node,
    registry: Arc<ProviderRegistry>,
    ipfs: Arc<MemberIpfs>,
    carrier: crate::carrier::CarrierNode,
}

impl CopyFixture {
    /// The owner seeded `seed` published `items`; the member serves its pool
    /// on a host whose storage maximum is `max`.
    async fn new(seed: u8, items: &[&ListedItem], max: Option<u64>) -> Self {
        let now = crate::auth::now_ts();
        let (device, owner_did) = elastos_identity::derive_did(&[seed; 32]);
        let owner = Owner::with_device("Olivia", now, device);
        assert_eq!(owner.did(), owner_did);
        let folders = Arc::new(OwnerFolders::default());
        let owner_home =
            crate::carrier::tests::start_holder_runtime(seed, folders.clone(), None).await;
        assert_eq!(owner_home.did, owner_did);
        let ipfs = Arc::new(MemberIpfs::default());
        for item in items {
            for folder in item.folders() {
                folders.serve_as(&folder.cid, folder);
                owner_home.publish(&folder.cid);
                ipfs.knows(folder);
            }
        }
        let member = serving(&owner, now, seed.wrapping_add(1)).await;
        // The owner's descriptor reached the member: it names the custody pool.
        let descriptor = elastos_protected_content_contracts::test_fixtures::pool_descriptor(
            &served_custody_pool(),
            2,
            elastos_protected_content_contracts::RuntimeOperationIssuerKeyV1::new(
                owner.device.verifying_key().to_bytes(),
            )
            .unwrap(),
            *COPY_POOL_AT,
        );
        update_served_pools(&member.data_dir, |pools| {
            use elastos_protected_content_contracts::CanonicalContract as _;
            pools
                .entries
                .get_mut(&owner.pool_fingerprint())
                .unwrap()
                .descriptor = Some(
                base64::engine::general_purpose::STANDARD
                    .encode(descriptor.canonical_bytes().unwrap()),
            );
            Ok(())
        })
        .unwrap();
        if max.is_some() {
            crate::host_trust::write_host_trust(
                &member.data_dir,
                crate::host_trust::HostTrustModeV1::WciOperated,
                max,
            )
            .unwrap();
        }
        let registry = Arc::new(ProviderRegistry::new());
        registry
            .register_sub_provider(
                "content",
                Arc::new(crate::content::ContentProvider::new(
                    member.data_dir.clone(),
                    Arc::downgrade(&registry),
                )),
            )
            .await
            .unwrap();
        registry
            .register_sub_provider("ipfs", ipfs.clone())
            .await
            .unwrap();
        let (key, did) = elastos_identity::load_existing_did(&member.data_dir).unwrap();
        let carrier = crate::carrier::start_isolated_carrier_node_with_registry(
            &key,
            &did,
            member.data_dir.clone(),
            Some(Arc::downgrade(&registry)),
        )
        .await
        .unwrap();
        registry
            .set_carrier_invoker(Arc::new(
                crate::carrier::CarrierProviderInvoker::with_carrier_endpoint_and_registry(
                    carrier.endpoint.clone(),
                    Arc::downgrade(&registry),
                ),
            ))
            .await;
        carrier
            .memory_lookup
            .add_endpoint_info(owner_home.addr.clone());
        Self {
            owner,
            owner_home,
            folders,
            member,
            registry,
            ipfs,
            carrier,
        }
    }

    /// Stops serving the owner's pool, as Custody's Stop does.
    async fn stop(&self) -> anyhow::Result<()> {
        self.stop_with(Some(&self.registry)).await
    }

    async fn stop_with(&self, registry: Option<&Arc<ProviderRegistry>>) -> anyhow::Result<()> {
        let write = lock_custody_writes().await;
        crate::custody_pool_setup::stop_serving_pool(
            &write,
            &self.member.data_dir,
            registry,
            self.owner
                .pool_fingerprint()
                .strip_prefix("sha256:")
                .unwrap(),
            crate::auth::now_ts(),
        )
        .await
    }

    /// MC-F6: a Home seeded `seed` that minted into the owner's pool, on
    /// Carrier, serving `items`, with a replica grant the member's operator
    /// added by hand.
    async fn minter(
        &self,
        seed: u8,
        items: &[&ListedItem],
    ) -> crate::carrier::tests::HolderRuntime {
        let home = self.minter_home(seed, items).await;
        self.hand_grant(&home.did);
        home
    }

    /// The same Home, with no grant on the member.
    async fn minter_home(
        &self,
        seed: u8,
        items: &[&ListedItem],
    ) -> crate::carrier::tests::HolderRuntime {
        let home =
            crate::carrier::tests::start_holder_runtime(seed, self.folders.clone(), None).await;
        for item in items {
            for folder in item.folders() {
                home.publish(&folder.cid);
            }
        }
        self.carrier
            .memory_lookup
            .add_endpoint_info(home.addr.clone());
        home
    }

    /// The member's operator allows `did`'s replicas by hand.
    fn hand_grant(&self, did: &str) {
        crate::operator_control::upsert_peer(
            &self.member.data_dir,
            crate::operator_control::OperatorPeer {
                did: did.to_string(),
                allow: vec![crate::operator_control::OPERATOR_ACTION_CONTENT_REPLICA.to_string()],
                ..Default::default()
            },
        )
        .unwrap();
    }

    /// The member's served root for the owner's pool, its node made the
    /// fixture committee's node 1 so the committee's shares are for it.
    fn pool_node_root(&self) -> std::path::PathBuf {
        let root_path = served_pools(&self.member.data_dir)
            .unwrap()
            .entries
            .into_values()
            .find(|entry| entry.owner_home == self.owner.did())
            .unwrap()
            .root_path;
        let root =
            crate::protected_content_runtime::custody_root_dir(&self.member.data_dir, &root_path);
        std::fs::write(root.join("node-signing-key"), hex::encode([1u8; 32])).unwrap();
        root
    }

    /// The member's share store accepts, through its real write, the share
    /// the Home seeded `seed` provisioned for `item` (with `item`'s own
    /// statement unless `statement_of` names another item's), then settles
    /// the copy admission as the custody wrapper does.
    async fn accept_minted(&self, seed: u8, item: &ListedItem) {
        self.accept_minted_with(seed, item, item);
    }

    fn accept_minted_with(&self, seed: u8, item: &ListedItem, statement_of: &ListedItem) {
        let (root, issuer) = self.store_minted_share(seed, item, statement_of);
        settle_accepted_pool_share(&self.member.data_dir, &root, issuer).unwrap();
    }

    /// The real share-store write alone: the share is stored, its
    /// admission not yet settled.
    fn store_minted_share(
        &self,
        seed: u8,
        item: &ListedItem,
        statement_of: &ListedItem,
    ) -> (
        std::path::PathBuf,
        elastos_protected_content_contracts::RuntimeOperationIssuerKeyV1,
    ) {
        use elastos_protected_content_contracts::test_fixtures::{
            node_public_key, CUSTODY_KEY_SEED_BASE,
        };
        let root = self.pool_node_root();
        let (record, provisioning, issuer) = minted_provisioning(seed, item);
        let secret = elastos_protected_content_custody::NodeCustodySecretKeyV1::from_guarded_bytes(
            zeroize::Zeroizing::new([CUSTODY_KEY_SEED_BASE + 1; 32]),
        )
        .unwrap();
        elastos_protected_content_custody::NodeLocalShareStoreV1::new(
            node_public_key(1),
            custody_provider::node_share_store_dir(&root),
        )
        .provision_pool_node_share_classified(
            &record,
            &provisioning,
            &statement_of.mint_share(),
            &secret,
            crate::auth::now_ts(),
        )
        .unwrap();
        (root, issuer)
    }

    /// The pool share request the Home seeded `seed` sends this member for
    /// `item`, as the custody wrapper receives it.
    fn pool_share_request_for(
        &self,
        record: &elastos_protected_content_contracts::CustodyNodeProvisioningRecordV1,
        provisioning: &elastos_protected_content_contracts::SignedRuntimeCustodyProvisioningV1,
        item: &ListedItem,
    ) -> serde_json::Value {
        let request =
            elastos_protected_content_provider_contracts::PoolCustodyRequestV1::new_provision_pool_node_share(
                record,
                provisioning,
                &item.mint_share(),
                &self.served_descriptor(),
            )
            .unwrap();
        serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap()
    }

    /// The served pool's descriptor, as a minting Home sends it with each
    /// pool share write.
    fn served_descriptor(&self) -> elastos_protected_content_contracts::SignedPoolDescriptorAnyV1 {
        elastos_protected_content_contracts::test_fixtures::pool_descriptor(
            &served_custody_pool(),
            2,
            elastos_protected_content_contracts::RuntimeOperationIssuerKeyV1::new(
                self.owner.device.verifying_key().to_bytes(),
            )
            .unwrap(),
            *COPY_POOL_AT,
        )
        .into()
    }

    /// Keys the served pool by the pool's own fingerprint, as a real join
    /// does, so the custody wrapper finds its root for a pool share write.
    fn key_served_pool_as_a_join_does(&self) {
        let pool_key =
            crate::custody_node_card::Fingerprint::of(self.served_pool_did().issuer().as_bytes())
                .full;
        update_served_pools(&self.member.data_dir, |pools| {
            let entry = pools
                .entries
                .remove(&self.owner.pool_fingerprint())
                .unwrap();
            pools.entries.insert(pool_key, entry);
            Ok(())
        })
        .unwrap();
    }

    fn replica_granted(&self, did: &str) -> bool {
        crate::operator_control::granted_peer_actions(&self.member.data_dir, did)
            .unwrap_or_default()
            .iter()
            .any(|action| action == crate::operator_control::OPERATOR_ACTION_CONTENT_REPLICA)
    }

    /// The pool the member serves for the owner, as its kept descriptor names it.
    fn served_pool_did(&self) -> elastos_protected_content_contracts::PoolDidV1 {
        let pools = served_pools(&self.member.data_dir).unwrap();
        crate::custody_pool_descriptor::served_entry_pool_did(
            &pools.entries[&self.owner.pool_fingerprint()],
        )
        .unwrap()
    }

    /// The owner's replica `ensure` for `cid`, as this member's Carrier
    /// dispatch receives it from the owner's Home.
    async fn owner_asks_to_keep(&self, cid: &str) -> serde_json::Value {
        self.asks_to_keep(&self.owner_endpoint(), cid).await
    }

    /// The replica `ensure` for `cid` from the Home at `endpoint`, as this
    /// member's Carrier dispatch receives it.
    async fn asks_to_keep(&self, endpoint: &iroh::PublicKey, cid: &str) -> serde_json::Value {
        let invocation = serde_json::json!({
            "source": "carrier-availability", "target": "content", "operation": "ensure",
            "transfer": "json",
            "request": {
                "op": "ensure", "cid": cid, "availability_policy": "carrier_replica",
                "availability_requirements": {"min_replicas": 1, "max_replicas": 1,
                    "require_live_multi_peer_proof": false},
                "_runtime_invocation": {
                    "schema": "elastos.provider.invocation/v1", "source": "carrier-availability",
                    "target": "content", "op": "ensure",
                    "capability": "provider:carrier-availability->content:ensure",
                    "transport": "carrier-provider-plane", "carrier": null, "transfer": "json",
                    "range": null, "progress": null,
                },
            },
        });
        crate::carrier::carrier_provider_invoke_registry(
            &self.registry,
            &invocation,
            endpoint,
            crate::carrier::CarrierProviderCaller::Peer {
                data_dir: &self.member.data_dir,
                network: None,
            },
        )
        .await
        .unwrap()
    }

    fn owner_endpoint(&self) -> iroh::PublicKey {
        iroh::PublicKey::from_bytes(&self.owner.device.verifying_key().to_bytes()).unwrap()
    }

    async fn keep(
        &self,
        cid: &str,
    ) -> Result<crate::carrier::MemberCopyOutcome, serde_json::Value> {
        crate::carrier::keep_member_copies(
            &self.registry,
            &self.member.data_dir,
            &self.owner.did(),
            cid,
        )
        .await
    }

    fn recorded(&self) -> BTreeSet<String> {
        member_copies(&self.member.data_dir)
            .unwrap()
            .into_iter()
            .map(|copy| copy.cid)
            .collect()
    }

    /// Whether `peer` may read `cid` from this member, counting the read.
    async fn peer_reads(&self, peer: &iroh::PublicKey, cid: &str) -> Result<(), serde_json::Value> {
        crate::carrier::admit_carrier_peer_content_fetch(crate::carrier::CarrierPeerContentFetch {
            registry: &self.registry,
            data_dir: &self.member.data_dir,
            network: None,
            source: peer,
            request: &serde_json::json!({ "cid": cid }),
            count_read: true,
        })
        .await
    }
}

/// The Runtime metadata a Carrier `content` invocation of `op` carries.
fn runtime_invocation(op: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": "elastos.provider.invocation/v1", "source": "carrier-availability",
        "target": "content", "op": op,
        "capability": format!("provider:carrier-availability->content:{op}"),
        "transport": "carrier-provider-plane", "carrier": null, "transfer": "json",
        "range": null, "progress": null,
    })
}

/// A Home that is no contact of anyone on the member.
fn stranger() -> iroh::PublicKey {
    iroh::PublicKey::from_bytes(&generate_keypair().0.verifying_key().to_bytes()).unwrap()
}

/// The member's room for new copies: ample.
const AMPLE: Option<u64> = Some(1 << 30);

#[tokio::test]
async fn a_replica_ensure_from_the_pool_owner_makes_the_member_pull_and_pin_the_listing_set() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xa1, &[&item], AMPLE).await;

    // The owner's mint ensures the payload before the listing exists: the
    // member cannot tell it is a listing's, so it keeps nothing yet.
    let early = fixture.owner_asks_to_keep(&item.content.cid).await;
    assert_eq!(early["ok"], true, "{early}");
    assert_eq!(
        early["result"]["data"]["availability"]["status"], "repair_needed",
        "{early}"
    );
    assert!(fixture.recorded().is_empty());

    // The listing's ensure brings the whole artifact set over Carrier.
    let answer = fixture.owner_asks_to_keep(&item.listing.cid).await;
    assert_eq!(answer["ok"], true, "{answer}");
    assert_eq!(
        answer["result"]["data"]["availability"]["status"], "local_pinned",
        "{answer}"
    );
    assert_eq!(fixture.ipfs.pinned(), item.cids());
    assert_eq!(fixture.recorded(), item.cids());
    for copy in member_copies(&fixture.member.data_dir).unwrap() {
        assert_eq!(copy.owner_did, fixture.owner.did());
        assert_eq!(copy.pool_fingerprint, fixture.owner.pool_fingerprint());
    }
    // One host storage account: the copies count with the shares.
    let copies: u64 = item.folders().iter().map(|folder| folder.bytes()).sum();
    assert_eq!(
        member_copies_bytes(&fixture.member.data_dir).unwrap(),
        copies
    );
    assert!(
        crate::protected_content_runtime::host_custody_storage_bytes(&fixture.member.data_dir)
            .unwrap()
            >= copies
    );
    // The payload's next ensure is answered from the pin.
    let later = fixture.owner_asks_to_keep(&item.content.cid).await;
    assert_eq!(
        later["result"]["data"]["availability"]["status"], "local_pinned",
        "{later}"
    );
    // The staging folders are gone.
    let staging = protected_content_root(&fixture.member.data_dir).join("member-copies");
    assert_eq!(std::fs::read_dir(staging).unwrap().count(), 0);
}

#[tokio::test]
async fn guard_a_requester_without_the_replica_grant_gets_no_copy_pulled() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xa2, &[&item], AMPLE).await;
    crate::operator_control::revoke_peer_action(
        &fixture.member.data_dir,
        &fixture.owner.did(),
        crate::operator_control::OPERATOR_ACTION_CONTENT_REPLICA,
    )
    .unwrap();

    let outcome = fixture.keep(&item.listing.cid).await;

    assert!(
        matches!(outcome, Ok(crate::carrier::MemberCopyOutcome::NotKept(_))),
        "{outcome:?}"
    );
    assert_eq!(fixture.folders.reads(), 0, "nothing was asked of the owner");
    assert!(fixture.ipfs.pinned().is_empty());
    assert!(fixture.recorded().is_empty());
}

#[tokio::test]
async fn guard_a_cid_outside_a_protected_listing_artifact_set_is_not_pulled() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xa3, &[&item], AMPLE).await;
    // A plain file folder its owner published.
    let plain = Folder::new(
        "notes",
        "file",
        vec![("notes.txt", b"not a listing".to_vec())],
        serde_json::json!([]),
        None,
        None,
    );
    fixture.folders.serve_as(&plain.cid, &plain);
    fixture.owner_home.publish(&plain.cid);
    fixture.ipfs.knows(&plain);

    for cid in [&plain.cid, &item.content.cid, &item.metadata.cid] {
        let outcome = fixture.keep(cid).await;
        assert_eq!(
            outcome,
            Ok(crate::carrier::MemberCopyOutcome::NotKept(
                "not a protected listing's artifact set"
            )),
            "{cid}"
        );
    }
    assert!(fixture.ipfs.imported().is_empty());
    assert!(fixture.ipfs.pinned().is_empty());
    assert!(fixture.recorded().is_empty());
}

#[tokio::test]
async fn guard_a_listing_of_another_pool_than_the_requesters_is_not_pulled() {
    let foreign = ListedItem::in_pool("foreign film", &other_custody_pool());
    let fixture = CopyFixture::new(0xac, &[&foreign], AMPLE).await;

    let outcome = fixture.keep(&foreign.listing.cid).await;

    assert_eq!(
        outcome,
        Ok(crate::carrier::MemberCopyOutcome::NotKept(
            "the listing names a pool the requester does not own here"
        ))
    );
    assert!(fixture.ipfs.pinned().is_empty());
    assert!(fixture.recorded().is_empty());
}

#[tokio::test]
async fn a_pool_listing_is_copied_to_every_member_but_its_owner() {
    use elastos_protected_content_contracts::test_fixtures::pool_descriptor_routed;
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let owner = serving(&olivia, now, 0xad).await;
    let (_, own) = elastos_identity::load_existing_did(&owner.data_dir).unwrap();
    // A pool of three members, this Home one of them.
    let bundle = elastos_protected_content_contracts::test_fixtures::pool_bundle(copy_xwing, now);
    let member = |seed: u8| {
        crate::carrier::public_key_to_did(&iroh::SecretKey::from_bytes(&[0x90 + seed; 32]).public())
            .unwrap()
    };
    let first = elastos_protected_content_contracts::test_fixtures::POOL_NODE_SEEDS[0];
    let route = |seed: u8| {
        if seed == first {
            own.clone()
        } else {
            member(seed)
        }
    };
    let descriptor: elastos_protected_content_contracts::SignedPoolDescriptorAnyV1 =
        pool_descriptor_routed(
            &bundle,
            1,
            now,
            elastos_protected_content_contracts::test_fixtures::POOL_AUTHORITY_SEED,
            &route,
        )
        .into();
    let write = lock_custody_writes().await;
    crate::custody_pool_resolver::keep_known_pool_for_test(
        &write,
        &owner.data_dir,
        "elastos-pool:test",
        &descriptor,
        now,
    )
    .unwrap();
    drop(write);
    let pool = bundle.signed_pool().pool_identity().unwrap();

    let holders = crate::custody_pool_descriptor::pool_copy_holders(&owner.data_dir, pool, now);

    let others: Vec<String> = elastos_protected_content_contracts::test_fixtures::POOL_NODE_SEEDS
        [1..]
        .iter()
        .map(|seed| member(*seed))
        .collect();
    assert_eq!(holders, others, "N members, N-1 copies requested");
    // Another pool's listing names none of them.
    let other = other_custody_pool().signed_pool().pool_identity().unwrap();
    assert!(
        crate::custody_pool_descriptor::pool_copy_holders(&owner.data_dir, other, now).is_empty()
    );
}

#[tokio::test]
async fn guard_a_copy_that_imports_as_another_cid_is_refused() {
    let item = ListedItem::new("film");
    let other = ListedItem::new("another film");
    let fixture = CopyFixture::new(0xa4, &[&item, &other], AMPLE).await;
    // Asked for this listing, the owner sends another listing's folder.
    fixture.folders.serve_as(&item.listing.cid, &other.listing);

    let outcome = fixture.keep(&item.listing.cid).await;

    let refusal = outcome.unwrap_err();
    assert_eq!(refusal["code"], "cid_mismatch", "{refusal}");
    assert!(fixture.ipfs.pinned().is_empty());
    assert!(fixture.recorded().is_empty());
}

#[tokio::test]
async fn guard_a_new_copy_at_a_full_host_maximum_is_refused_with_storage_full() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xa5, &[&item], Some(16)).await;

    let answer = fixture.owner_asks_to_keep(&item.listing.cid).await;

    assert_eq!(answer["ok"], false, "{answer}");
    assert_eq!(answer["code"], crate::host_trust::HOST_STORAGE_FULL);
    // Refused once its size was known, before any file was fetched.
    assert_eq!(fixture.folders.reads(), 1);
    assert!(fixture.ipfs.pinned().is_empty());
    assert!(fixture.recorded().is_empty());
}

/* ---------- PR2-F1: staged copies are charged before their files ---------- */

impl Folder {
    /// The bytes a copy of this folder is charged: its manifest and files.
    fn charged_bytes(&self) -> u64 {
        self.files
            .iter()
            .fold(self.manifest.len() as u64, |total, (_, bytes)| {
                total + bytes.len() as u64
            })
    }
}

impl CopyFixture {
    fn reads_of(&self, cid: &str) -> usize {
        self.folders
            .reads
            .lock()
            .unwrap()
            .iter()
            .filter(|(read, _)| read == cid)
            .count()
    }

    fn set_storage_maximum(&self, max: u64) {
        crate::host_trust::write_host_trust(
            &self.member.data_dir,
            crate::host_trust::HostTrustModeV1::WciOperated,
            Some(max),
        )
        .unwrap();
    }

    fn staging_bytes(&self) -> u64 {
        member_copy_staging_bytes(&self.member.data_dir).unwrap()
    }
}

/// A staged copy of `item`'s payload is held mid-download: its gate.
async fn hold_payload_download(
    fixture: &Arc<CopyFixture>,
    item: &ListedItem,
) -> (
    Gate,
    tokio::task::JoinHandle<Result<crate::carrier::MemberCopyOutcome, serde_json::Value>>,
) {
    let gate = Gate::new(&item.content.cid, "object.epc1");
    *fixture.folders.gate.lock().unwrap() = Some(gate.clone());
    let keeping = tokio::spawn({
        let fixture = Arc::clone(fixture);
        let cid = item.listing.cid.clone();
        async move { fixture.keep(&cid).await }
    });
    gate.reached.notified().await;
    (gate, keeping)
}

/// PR2-F1: a copy being staged is charged to the host storage account. A
/// second copy that fits only without that charge is refused before any of
/// its files is fetched, and fits once the first copy's staging is gone.
/// (The first copy is held as its reservation: a second pull from the same
/// owner would queue behind a paused one in this fixture.)
#[tokio::test]
async fn guard_a_copy_being_staged_holds_its_charge_against_another_copy() {
    let song = ListedItem::new("song");
    let fixture = Arc::new(CopyFixture::new(0xc1, &[&song], AMPLE).await);
    let staging = MemberCopyStaging::reserve(&fixture.member.data_dir, 64, || false)
        .await
        .unwrap();
    let used =
        crate::protected_content_runtime::host_custody_storage_bytes(&fixture.member.data_dir)
            .unwrap();
    assert_eq!(used, 64);
    // The song's listing, staged first, fits beside everything but the
    // staged copy.
    let listing_bytes = song.listing.charged_bytes();
    fixture.set_storage_maximum(listing_bytes + 63);

    let refused = fixture.keep(&song.listing.cid).await;

    let answer = refused.expect_err("refused");
    assert_eq!(
        answer["code"],
        crate::host_trust::HOST_STORAGE_FULL,
        "{answer}"
    );
    assert_eq!(
        fixture.reads_of(&song.listing.cid),
        1,
        "only the manifest was read"
    );
    drop(staging);
    assert_eq!(fixture.staging_bytes(), 0);
    let listing = MemberCopyStaging::reserve(&fixture.member.data_dir, listing_bytes, || false)
        .await
        .unwrap();
    drop(listing);
    fixture.set_storage_maximum(AMPLE.unwrap());
    assert_eq!(
        fixture.keep(&song.listing.cid).await,
        Ok(crate::carrier::MemberCopyOutcome::Kept)
    );
    assert_eq!(fixture.staging_bytes(), 0);
}

/// PR2-F1: a copy cancelled mid-download removes its files, then its charge.
#[tokio::test]
async fn guard_a_copy_cancelled_while_staging_releases_its_charge() {
    let film = ListedItem::new("film");
    let fixture = Arc::new(CopyFixture::new(0xc2, &[&film], AMPLE).await);
    let (gate, keeping) = hold_payload_download(&fixture, &film).await;
    assert!(fixture.staging_bytes() > 0);

    keeping.abort();
    assert!(keeping.await.unwrap_err().is_cancelled());
    gate.release();

    assert_eq!(fixture.staging_bytes(), 0);
    let parent = protected_content_root(&fixture.member.data_dir).join("member-copies");
    let left: Vec<_> = std::fs::read_dir(parent)
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("staging-"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

/// PR2-F1: once a copy's commit is dispatched, cancelling its caller frees
/// nothing: the commit settles on its own and the kept copy stays charged
/// once, by its record.
#[tokio::test]
async fn guard_a_copy_cancelled_after_its_commit_is_dispatched_stays_charged() {
    let film = ListedItem::new("film");
    let fixture = Arc::new(CopyFixture::new(0xc3, &[&film], AMPLE).await);
    let gate = Gate::new(&film.listing.cid, "pin");
    *fixture.ipfs.gate.lock().unwrap() = Some(gate.clone());
    let keeping = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        let cid = film.listing.cid.clone();
        async move { fixture.keep(&cid).await }
    });
    gate.reached.notified().await;
    let charged =
        crate::protected_content_runtime::host_custody_storage_bytes(&fixture.member.data_dir)
            .unwrap();

    keeping.abort();
    let _ = keeping.await;
    assert!(fixture.recorded().contains(&film.listing.cid));
    gate.release();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !fixture.ipfs.pinned().contains(&film.listing.cid) {
        assert!(
            std::time::Instant::now() < deadline,
            "the commit did not settle"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    assert!(fixture.recorded().contains(&film.listing.cid));
    assert_eq!(fixture.staging_bytes(), 0);
    assert!(
        crate::protected_content_runtime::host_custody_storage_bytes(&fixture.member.data_dir)
            .unwrap()
            <= charged
    );
}

fn member_host(max: u64) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    crate::host_trust::write_host_trust(
        &data_dir,
        crate::host_trust::HostTrustModeV1::WciOperated,
        Some(max),
    )
    .unwrap();
    (dir, data_dir)
}

/// PR2-F1: staging and share writes are admitted against one account under
/// one lock. A reservation fills the maximum exactly; a share that needs
/// one byte more is refused, and a commit already charged by it fits.
#[tokio::test]
async fn guard_staging_and_share_writes_share_one_host_account() {
    let (_dir, data_dir) = member_host(100);
    let staging = MemberCopyStaging::reserve(&data_dir, 100, || false)
        .await
        .unwrap();
    assert_eq!(member_copy_staging_bytes(&data_dir).unwrap(), 100);

    let share = crate::protected_content_runtime::guarded_host_share_write(
        data_dir.clone(),
        1,
        || false,
        || async { Ok(serde_json::json!({ "status": "ok" })) },
    )
    .await
    .unwrap();
    assert_eq!(
        share["code"],
        crate::host_trust::HOST_STORAGE_FULL,
        "{share}"
    );
    let committed = crate::protected_content_runtime::guarded_host_share_write(
        data_dir.clone(),
        0,
        || false,
        || async { Ok(serde_json::json!({ "status": "ok" })) },
    )
    .await
    .unwrap();
    assert_eq!(committed["status"], "ok", "{committed}");
    assert_eq!(
        MemberCopyStaging::reserve(&data_dir, 1, || false)
            .await
            .err()
            .flatten()
            .unwrap()["code"],
        crate::host_trust::HOST_STORAGE_FULL
    );
    drop(staging);
    assert_eq!(member_copy_staging_bytes(&data_dir).unwrap(), 0);
}

/// PR2-F1: a reservation waits for a share write that holds the host lock,
/// and is then checked against the bytes that write stored.
#[tokio::test]
async fn guard_a_reservation_waits_for_an_admitted_share_write() {
    let (_dir, data_dir) = member_host(100);
    let (entered, entry) = tokio::sync::oneshot::channel::<()>();
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let writing = tokio::spawn(crate::protected_content_runtime::guarded_host_share_write(
        data_dir.clone(),
        60,
        || false,
        {
            let data_dir = data_dir.clone();
            move || async move {
                entered.send(()).unwrap();
                let _ = released.await;
                let store = custody_provider::node_share_store_dir(
                    &crate::protected_content_runtime::custody_root_dir(&data_dir, "inactive"),
                );
                std::fs::create_dir_all(&store).unwrap();
                std::fs::write(store.join("share"), [0u8; 60]).unwrap();
                Ok(serde_json::json!({ "status": "ok" }))
            }
        },
    ));
    entry.await.unwrap();
    let reserving = tokio::spawn({
        let data_dir = data_dir.clone();
        async move {
            MemberCopyStaging::reserve(&data_dir, 50, || false)
                .await
                .map(|_| ())
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!reserving.is_finished(), "the reservation did not wait");
    release.send(()).unwrap();
    writing.await.unwrap().unwrap();

    let refusal = reserving
        .await
        .unwrap()
        .expect_err("refused")
        .expect("a refusal");
    assert_eq!(
        refusal["code"],
        crate::host_trust::HOST_STORAGE_FULL,
        "{refusal}"
    );
}

/// PR2-F1: after a restart, a leftover staging folder stays charged until
/// it is removed; one without its charge keeps the host refusing storage.
#[test]
fn guard_leftover_staging_is_charged_until_it_is_removed() {
    let (_dir, data_dir) = member_host(1_000);
    let parent = protected_content_root(&data_dir).join("member-copies");
    let charged = parent.join("staging-charged");
    std::fs::create_dir_all(charged.join("payload")).unwrap();
    std::fs::write(charged.join("staging-bytes"), b"400").unwrap();
    std::fs::write(charged.join("payload/object.epc1"), [0u8; 400]).unwrap();
    assert_eq!(member_copy_staging_bytes(&data_dir).unwrap(), 400);
    assert!(crate::protected_content_runtime::host_storage_refusal(&data_dir, 601).is_some());

    let uncharged = parent.join("staging-uncharged");
    std::fs::create_dir_all(&uncharged).unwrap();
    std::fs::write(uncharged.join("object.epc1"), [0u8; 4]).unwrap();
    assert!(member_copy_staging_bytes(&data_dir).is_err());
    assert!(crate::protected_content_runtime::host_storage_refusal(&data_dir, 1).is_some());

    remove_stale_member_copy_staging(&data_dir);
    assert_eq!(member_copy_staging_bytes(&data_dir).unwrap(), 0);
    assert_eq!(
        crate::protected_content_runtime::host_storage_refusal(&data_dir, 1_000),
        None
    );
}

/// M0R3-F2: a protected listing's folder is its package alone. A "listing"
/// whose manifest declares any other file, or a package over the listing
/// bound, is refused once the manifest is read, before any file is fetched
/// or staged.
#[tokio::test]
async fn guard_a_listing_folder_with_more_than_its_package_is_refused_before_any_fetch() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xbb, &[&item], AMPLE).await;
    let package = item.listing.files[0].1.clone();
    let bloated = Folder::new(
        "film",
        "protected-content-listing",
        vec![("listing.json", package), ("extra.bin", vec![0u8; 4096])],
        serde_json::json!([
            {"rel": "metadata", "cid": item.metadata.cid},
            {"rel": "encrypted-content", "cid": item.content.cid},
        ]),
        None,
        None,
    );
    fixture.folders.serve_as(&item.listing.cid, &bloated);

    let outcome = fixture.keep(&item.listing.cid).await;

    assert_eq!(
        outcome,
        Ok(crate::carrier::MemberCopyOutcome::NotKept(
            "not a protected listing's artifact set"
        ))
    );
    assert_eq!(fixture.folders.reads(), 1, "only the manifest was read");
    assert!(fixture.ipfs.pinned().is_empty());
    assert!(fixture.recorded().is_empty());
}

/// M0R3-F2: a listing package declared over the listing bound is refused
/// before it is fetched.
#[tokio::test]
async fn guard_an_oversized_listing_package_is_refused_before_any_fetch() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xbc, &[&item], AMPLE).await;
    let oversized = Folder::new(
        "film",
        "protected-content-listing",
        vec![(
            "listing.json",
            vec![
                b' ';
                crate::protected_content_runtime::MAX_RUNTIME_REMOTE_PORTABLE_LISTING_BYTES
                    as usize
                    + 1
            ],
        )],
        serde_json::json!([
            {"rel": "metadata", "cid": item.metadata.cid},
            {"rel": "encrypted-content", "cid": item.content.cid},
        ]),
        None,
        None,
    );
    fixture.folders.serve_as(&item.listing.cid, &oversized);

    let outcome = fixture.keep(&item.listing.cid).await;

    assert_eq!(
        outcome,
        Ok(crate::carrier::MemberCopyOutcome::NotKept(
            "not a protected listing's artifact set"
        ))
    );
    assert_eq!(fixture.folders.reads(), 1, "only the manifest was read");
    assert!(fixture.recorded().is_empty());
}

#[tokio::test]
async fn guard_a_new_copy_without_a_host_maximum_is_refused_with_storage_max_unset() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xa6, &[&item], None).await;

    let answer = fixture.owner_asks_to_keep(&item.listing.cid).await;

    assert_eq!(answer["ok"], false, "{answer}");
    assert_eq!(answer["code"], crate::host_trust::HOST_STORAGE_MAX_UNSET);
    assert!(fixture.ipfs.pinned().is_empty());
    assert!(fixture.recorded().is_empty());
}

#[tokio::test]
async fn a_copy_already_held_is_free_at_a_full_host_maximum() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xa7, &[&item], AMPLE).await;
    assert_eq!(
        fixture.keep(&item.listing.cid).await,
        Ok(crate::carrier::MemberCopyOutcome::Kept)
    );
    // The host is now exactly full, and the listing's pin was lost.
    let used =
        crate::protected_content_runtime::host_custody_storage_bytes(&fixture.member.data_dir)
            .unwrap();
    crate::host_trust::write_host_trust(
        &fixture.member.data_dir,
        crate::host_trust::HostTrustModeV1::WciOperated,
        Some(used),
    )
    .unwrap();
    fixture
        .ipfs
        .pinned
        .lock()
        .unwrap()
        .remove(&item.listing.cid);

    assert_eq!(
        fixture.keep(&item.listing.cid).await,
        Ok(crate::carrier::MemberCopyOutcome::Kept)
    );
    assert_eq!(fixture.ipfs.pinned(), item.cids());
    assert_eq!(
        crate::protected_content_runtime::host_custody_storage_bytes(&fixture.member.data_dir)
            .unwrap(),
        used,
        "the copy is not charged twice"
    );
}

#[tokio::test]
async fn a_kept_copy_is_served_to_a_home_that_is_no_contact() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xa8, &[&item], AMPLE).await;
    let peer = stranger();
    assert!(fixture.peer_reads(&peer, &item.content.cid).await.is_err());

    fixture.keep(&item.listing.cid).await.unwrap();

    for cid in item.cids() {
        assert_eq!(fixture.peer_reads(&peer, &cid).await, Ok(()), "{cid}");
    }
}

#[tokio::test]
async fn guard_an_unrecorded_unpinned_or_unserved_pool_copy_is_not_served() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xa9, &[&item], AMPLE).await;
    fixture.keep(&item.listing.cid).await.unwrap();
    let peer = stranger();
    let refused = |answer: Result<(), serde_json::Value>| {
        answer.is_err_and(|answer| answer["code"] == crate::carrier::CARRIER_PEER_REFUSED)
    };

    // Pinned but never recorded as a copy.
    let pinned_only = Folder::new(
        "received",
        "file",
        vec![("a.txt", b"x".to_vec())],
        serde_json::json!([]),
        None,
        None,
    );
    fixture
        .ipfs
        .pinned
        .lock()
        .unwrap()
        .insert(pinned_only.cid.clone());
    assert!(refused(fixture.peer_reads(&peer, &pinned_only.cid).await));

    // Recorded, but its pin is gone.
    fixture
        .ipfs
        .pinned
        .lock()
        .unwrap()
        .remove(&item.content.cid);
    assert!(refused(fixture.peer_reads(&peer, &item.content.cid).await));
    fixture
        .ipfs
        .pinned
        .lock()
        .unwrap()
        .insert(item.content.cid.clone());
    assert_eq!(fixture.peer_reads(&peer, &item.content.cid).await, Ok(()));

    // Recorded and pinned, for a pool this Home no longer serves.
    let write = lock_custody_writes().await;
    forget_served_pool(
        &write,
        &fixture.member.data_dir,
        &fixture.owner.pool_fingerprint(),
    )
    .unwrap();
    drop(write);
    assert!(refused(fixture.peer_reads(&peer, &item.content.cid).await));
}

#[tokio::test]
async fn reads_of_kept_copies_are_rate_limited_per_peer() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xaa, &[&item], AMPLE).await;
    fixture.keep(&item.listing.cid).await.unwrap();
    let (busy, other) = (stranger(), stranger());

    for _ in 0..240 {
        assert_eq!(fixture.peer_reads(&busy, &item.content.cid).await, Ok(()));
    }
    let limited = fixture
        .peer_reads(&busy, &item.content.cid)
        .await
        .unwrap_err();
    assert_eq!(limited["code"], "rate_limited", "{limited}");
    // Another Home keeps its own window.
    assert_eq!(fixture.peer_reads(&other, &item.content.cid).await, Ok(()));
    // The second admission of a read already counted is not counted again.
    assert_eq!(
        crate::carrier::admit_carrier_peer_content_fetch(crate::carrier::CarrierPeerContentFetch {
            registry: &fixture.registry,
            data_dir: &fixture.member.data_dir,
            network: None,
            source: &busy,
            request: &serde_json::json!({ "cid": item.content.cid }),
            count_read: false,
        })
        .await,
        Ok(())
    );
}

#[tokio::test]
async fn stopping_a_pool_drops_its_copies_unpins_them_and_revokes_the_grant() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xab, &[&item], AMPLE).await;
    fixture.keep(&item.listing.cid).await.unwrap();
    assert_eq!(fixture.recorded(), item.cids());

    let write = lock_custody_writes().await;
    crate::custody_pool_setup::stop_serving_pool(
        &write,
        &fixture.member.data_dir,
        Some(&fixture.registry),
        fixture
            .owner
            .pool_fingerprint()
            .strip_prefix("sha256:")
            .unwrap(),
        crate::auth::now_ts(),
    )
    .await
    .unwrap();
    drop(write);

    assert!(fixture.recorded().is_empty());
    assert!(fixture.ipfs.pinned().is_empty());
    assert_eq!(
        fixture
            .ipfs
            .unpinned
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        item.cids()
    );
    assert!(!crate::operator_control::granted_peer_actions(
        &fixture.member.data_dir,
        &fixture.owner.did()
    )
    .unwrap_or_default()
    .iter()
    .any(|action| action == "content.replica"));
    assert!(fixture
        .peer_reads(&stranger(), &item.content.cid)
        .await
        .is_err());
}

/* ---------- M0-FIX: MC-F2..MC-F6 ---------- */

/// MC-F2: a Stop asked while an admitted copy is committing waits for it,
/// and then takes its record with the pool's other copies. (The Stop runs
/// without the provider registry here: with it, a last root's unregister
/// already waits for the held provider call, which would hide the order.)
#[tokio::test]
async fn a_stop_waits_for_an_admitted_copy_and_takes_it_with_the_pool() {
    let item = ListedItem::new("film");
    let fixture = Arc::new(CopyFixture::new(0xb1, &[&item], AMPLE).await);
    let gate = Gate::new(&item.listing.cid, "pin");
    *fixture.ipfs.gate.lock().unwrap() = Some(gate.clone());
    let keeping = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        let cid = item.listing.cid.clone();
        async move { fixture.keep(&cid).await }
    });
    gate.reached.notified().await;

    let stopping = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        async move { fixture.stop_with(None).await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let stopped_early = stopping.is_finished();
    gate.release();
    let _ = keeping.await.unwrap();
    stopping.await.unwrap().unwrap();

    assert!(
        !stopped_early,
        "the Stop completed while a copy was committing"
    );
    assert!(fixture.recorded().is_empty(), "{:?}", fixture.recorded());
}

/// MC-F2, with the provider registry: whichever order the Stop and the
/// committing copy settle in, no copy stays pinned or recorded.
#[tokio::test]
async fn a_stop_during_a_committing_copy_leaves_nothing_pinned() {
    let item = ListedItem::new("film");
    let fixture = Arc::new(CopyFixture::new(0xba, &[&item], AMPLE).await);
    let gate = Gate::new(&item.listing.cid, "pin");
    *fixture.ipfs.gate.lock().unwrap() = Some(gate.clone());
    let keeping = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        let cid = item.listing.cid.clone();
        async move { fixture.keep(&cid).await }
    });
    gate.reached.notified().await;
    let stopping = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        async move { fixture.stop().await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    gate.release();
    let _ = keeping.await.unwrap();
    stopping.await.unwrap().unwrap();

    assert!(fixture.recorded().is_empty(), "{:?}", fixture.recorded());
    assert!(
        fixture.ipfs.pinned().is_empty(),
        "{:?}",
        fixture.ipfs.pinned()
    );
}

/// MC-F2: a copy whose pool stopped after its pull was admitted is not
/// kept: the commit asks for the served pool again.
#[tokio::test]
async fn guard_a_copy_whose_pool_stopped_after_its_pull_was_admitted_is_not_kept() {
    let item = ListedItem::new("film");
    let fixture = Arc::new(CopyFixture::new(0xb2, &[&item], AMPLE).await);
    let gate = Gate::new(
        &item.metadata.cid,
        crate::content::CONTENT_OBJECT_MANIFEST_PATH,
    );
    *fixture.folders.gate.lock().unwrap() = Some(gate.clone());
    let keeping = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        let cid = item.listing.cid.clone();
        async move { fixture.keep(&cid).await }
    });
    gate.reached.notified().await;

    fixture.stop().await.unwrap();
    gate.release();
    let outcome = keeping.await.unwrap();

    assert!(
        !matches!(outcome, Ok(crate::carrier::MemberCopyOutcome::Kept)),
        "{outcome:?}"
    );
    assert!(fixture.recorded().is_empty(), "{:?}", fixture.recorded());
    assert!(
        fixture.ipfs.pinned().is_empty(),
        "{:?}",
        fixture.ipfs.pinned()
    );
}

/// MC-F3: the record is the copy's reservation. When it cannot be written
/// (here: the record is at its cap), nothing is pinned.
#[tokio::test]
async fn guard_a_copy_whose_record_cannot_be_written_pins_nothing() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xb3, &[&item], AMPLE).await;
    update_member_copies(&fixture.member.data_dir, |copies| {
        copies.extend((0..MAX_MEMBER_COPIES).map(|index| MemberCopyV1 {
            cid: format!("filler-{index}"),
            owner_did: "did:key:filler".to_string(),
            pool_fingerprint: "sha256:filler".to_string(),
            bytes: 0,
            borrowed: false,
        }));
        Ok(())
    })
    .unwrap();

    let outcome = fixture.keep(&item.listing.cid).await;

    assert!(outcome.is_err(), "{outcome:?}");
    assert!(
        fixture.ipfs.pinned().is_empty(),
        "{:?}",
        fixture.ipfs.pinned()
    );
    assert_eq!(
        member_copies(&fixture.member.data_dir).unwrap().len(),
        MAX_MEMBER_COPIES
    );
}

/// MC-F4: each pool's duty to keep a CID is its own record. The copy is
/// charged once, and unpinned only when no pool keeps it any more.
#[tokio::test]
async fn a_copy_two_pools_keep_is_charged_once_and_unpinned_only_when_neither_keeps_it() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xb4, &[&item], AMPLE).await;
    let cid = item.content.cid.clone();
    fixture.ipfs.pinned.lock().unwrap().insert(cid.clone());
    for pool in ["sha256:pool-a", "sha256:pool-b"] {
        assert!(record_member_copy(
            &fixture.member.data_dir,
            MemberCopyV1 {
                cid: cid.clone(),
                owner_did: fixture.owner.did(),
                pool_fingerprint: pool.to_string(),
                bytes: 100,
                borrowed: false,
            },
        )
        .unwrap());
    }
    assert_eq!(member_copies(&fixture.member.data_dir).unwrap().len(), 2);
    assert_eq!(member_copies_bytes(&fixture.member.data_dir).unwrap(), 100);

    let write = lock_custody_writes().await;
    withdraw_member_copies(
        &write,
        &fixture.member.data_dir,
        Some(&fixture.registry),
        "sha256:pool-a",
    )
    .await
    .unwrap();
    assert!(
        fixture.ipfs.pinned().contains(&cid),
        "pool B still keeps it"
    );
    assert_eq!(fixture.recorded(), BTreeSet::from([cid.clone()]));
    withdraw_member_copies(
        &write,
        &fixture.member.data_dir,
        Some(&fixture.registry),
        "sha256:pool-b",
    )
    .await
    .unwrap();
    drop(write);
    assert!(!fixture.ipfs.pinned().contains(&cid));
    assert!(fixture.recorded().is_empty());
}

/// MC-F4: a listing already kept does not stop the walk of its set: an
/// object whose pin was lost is pulled and pinned again on the next ensure.
#[tokio::test]
async fn a_listing_ensure_repairs_a_lost_copy_of_its_set() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xb5, &[&item], AMPLE).await;
    assert_eq!(
        fixture.keep(&item.listing.cid).await,
        Ok(crate::carrier::MemberCopyOutcome::Kept)
    );
    fixture
        .ipfs
        .pinned
        .lock()
        .unwrap()
        .remove(&item.content.cid);

    assert_eq!(
        fixture.keep(&item.listing.cid).await,
        Ok(crate::carrier::MemberCopyOutcome::Kept)
    );
    assert_eq!(fixture.ipfs.pinned(), item.cids());
    assert_eq!(fixture.recorded(), item.cids());
}

/* ---------- MC-F6: copies for accepted minters (option A, ADV-18, M0R1) ---------- */

fn home_endpoint(seed: u8) -> iroh::PublicKey {
    let (key, _) = elastos_identity::derive_did(&[seed; 32]);
    iroh::PublicKey::from_bytes(&key.verifying_key().to_bytes()).unwrap()
}

/// `item`'s folders, served by the owner's content plane and known to the
/// member's Kubo.
fn serve_items(fixture: &CopyFixture, items: &[&ListedItem]) {
    for item in items {
        for folder in item.folders() {
            fixture.folders.serve_as(&folder.cid, folder);
            fixture.ipfs.knows(folder);
        }
    }
}

/// A Home that minted into the served pool and is no owner of it: once the
/// member's share store accepted its share (the real store write) and the
/// write settled, its replica `ensure` passes admission, with no
/// `content.replica` grant, and the member keeps and serves the set.
#[tokio::test]
async fn a_non_owner_minter_whose_share_was_accepted_gets_its_copy_kept() {
    let fixture = CopyFixture::new(0xd1, &[], AMPLE).await;
    let item = ListedItem::minted("minted film", 0xe1, fixture.served_pool_did(), None);
    serve_items(&fixture, &[&item]);
    let minter = fixture.minter_home(0xe1, &[&item]).await;
    fixture.accept_minted(0xe1, &item).await;
    assert!(
        !fixture.replica_granted(&minter.did),
        "no content.replica grant"
    );
    assert!(minter_copy_admitted(&fixture.member.data_dir, &minter.did));

    let answer = fixture
        .asks_to_keep(&home_endpoint(0xe1), &item.listing.cid)
        .await;

    assert_eq!(answer["ok"], true, "{answer}");
    assert_eq!(
        answer["result"]["data"]["availability"]["status"], "local_pinned",
        "{answer}"
    );
    assert_eq!(fixture.ipfs.pinned(), item.cids());
    assert_eq!(fixture.recorded(), item.cids());
    for copy in member_copies(&fixture.member.data_dir).unwrap() {
        assert_eq!(copy.owner_did, minter.did);
        assert_eq!(copy.pool_fingerprint, fixture.owner.pool_fingerprint());
    }
    for cid in item.cids() {
        assert_eq!(fixture.peer_reads(&stranger(), &cid).await, Ok(()), "{cid}");
    }
}

/// M0R1-F1: the copy binds to the statement the store accepted. A listing
/// whose statement has the same minter, KID and pool but another envelope
/// is not the accepted item, though its (minter, KID) slot is held.
#[tokio::test]
async fn guard_a_listing_whose_statement_differs_from_the_accepted_one_gets_no_copy() {
    let fixture = CopyFixture::new(0xd5, &[], AMPLE).await;
    let accepted = ListedItem::minted("accepted film", 0xe5, fixture.served_pool_did(), None);
    let other = ListedItem::minted("other film", 0xe5, fixture.served_pool_did(), None);
    assert_eq!(
        accepted.minted_slot(0xe5),
        other.minted_slot(0xe5),
        "same minter and KID"
    );
    assert_ne!(
        accepted.mint_share().statement().key_envelope(),
        other.mint_share().statement().key_envelope()
    );
    serve_items(&fixture, &[&accepted, &other]);
    let minter = fixture.minter_home(0xe5, &[&accepted, &other]).await;
    fixture.accept_minted(0xe5, &accepted).await;

    let outcome = crate::carrier::keep_member_copies(
        &fixture.registry,
        &fixture.member.data_dir,
        &minter.did,
        &other.listing.cid,
    )
    .await;

    assert_eq!(
        outcome,
        Ok(crate::carrier::MemberCopyOutcome::NotKept(
            "the listing names a pool the requester does not own here"
        ))
    );
    assert!(fixture.ipfs.pinned().is_empty());
    assert!(fixture.recorded().is_empty());
}

/// MC-F6 guard: a minter whose share the member never accepted gets
/// nothing kept, though it holds a hand-added grant.
#[tokio::test]
async fn guard_a_minter_without_an_accepted_share_statement_gets_no_copy() {
    let fixture = CopyFixture::new(0xb7, &[], AMPLE).await;
    let item = ListedItem::minted("minted film", 0xc7, fixture.served_pool_did(), None);
    serve_items(&fixture, &[&item]);
    let minter = fixture.minter(0xc7, &[&item]).await;

    let outcome = crate::carrier::keep_member_copies(
        &fixture.registry,
        &fixture.member.data_dir,
        &minter.did,
        &item.listing.cid,
    )
    .await;

    assert_eq!(
        outcome,
        Ok(crate::carrier::MemberCopyOutcome::NotKept(
            "the listing names a pool the requester does not own here"
        ))
    );
    assert!(fixture.ipfs.pinned().is_empty());
    assert!(fixture.recorded().is_empty());
}

/// MC-F6 guard: a statement for another KID does not verify for the
/// listing; one for another pool names a pool this member does not serve.
#[tokio::test]
async fn guard_a_minter_statement_for_another_kid_or_pool_gets_no_copy() {
    let fixture = CopyFixture::new(0xb8, &[], AMPLE).await;
    let other_kid =
        elastos_protected_content_contracts::ContentAccessIdV1::new([0x5f; 16]).unwrap();
    let other_pool = *elastos_protected_content_contracts::SignedPoolDescriptorAnyV1::from(
        elastos_protected_content_contracts::test_fixtures::pool_descriptor_signed_by(
            &other_custody_pool(),
            1,
            *COPY_POOL_AT,
            0x73,
        ),
    )
    .pool();
    assert_ne!(other_pool, fixture.served_pool_did());
    let for_kid = ListedItem::minted("kid film", 0xc8, fixture.served_pool_did(), Some(other_kid));
    let for_pool = ListedItem::minted("pool film", 0xc8, other_pool, None);
    serve_items(&fixture, &[&for_kid, &for_pool]);
    let minter = fixture.minter(0xc8, &[&for_kid, &for_pool]).await;

    for item in [&for_kid, &for_pool] {
        let outcome = crate::carrier::keep_member_copies(
            &fixture.registry,
            &fixture.member.data_dir,
            &minter.did,
            &item.listing.cid,
        )
        .await;
        assert!(
            matches!(outcome, Ok(crate::carrier::MemberCopyOutcome::NotKept(_))),
            "{outcome:?}"
        );
    }
    assert!(fixture.ipfs.pinned().is_empty());
    assert!(fixture.recorded().is_empty());
}

/// MC-F6 guard: an accepted minter's ensure of a CID outside a listing's
/// artifact set (a plain folder, or the payload asked alone) keeps nothing.
#[tokio::test]
async fn guard_an_accepted_minters_cid_outside_the_artifact_set_is_not_kept() {
    let fixture = CopyFixture::new(0xb9, &[], AMPLE).await;
    let item = ListedItem::minted("minted film", 0xc9, fixture.served_pool_did(), None);
    let plain = Folder::new(
        "notes",
        "file",
        vec![("notes.txt", b"not a listing".to_vec())],
        serde_json::json!([]),
        None,
        None,
    );
    serve_items(&fixture, &[&item]);
    fixture.folders.serve_as(&plain.cid, &plain);
    fixture.ipfs.knows(&plain);
    let minter = fixture.minter_home(0xc9, &[&item]).await;
    minter.publish(&plain.cid);
    fixture.accept_minted(0xc9, &item).await;

    for cid in [&plain.cid, &item.content.cid, &item.metadata.cid] {
        let outcome = crate::carrier::keep_member_copies(
            &fixture.registry,
            &fixture.member.data_dir,
            &minter.did,
            cid,
        )
        .await;
        assert_eq!(
            outcome,
            Ok(crate::carrier::MemberCopyOutcome::NotKept(
                "not a protected listing's artifact set"
            )),
            "{cid}"
        );
    }
    assert!(fixture.ipfs.imported().is_empty());
    assert!(fixture.ipfs.pinned().is_empty());
    assert!(fixture.recorded().is_empty());
}

/// guard: a minter whose share this member never accepted is refused at
/// admission, before anything is read from it.
#[tokio::test]
async fn guard_a_minter_with_no_accepted_share_is_refused_at_admission() {
    let fixture = CopyFixture::new(0xd2, &[], AMPLE).await;
    let item = ListedItem::minted("minted film", 0xe2, fixture.served_pool_did(), None);
    serve_items(&fixture, &[&item]);
    let minter = fixture.minter_home(0xe2, &[&item]).await;

    let answer = fixture
        .asks_to_keep(&home_endpoint(0xe2), &item.listing.cid)
        .await;

    assert_eq!(answer["ok"], false, "{answer}");
    assert_eq!(
        answer["code"],
        crate::carrier::CARRIER_PEER_REFUSED,
        "{answer}"
    );
    assert!(!minter_copy_admitted(&fixture.member.data_dir, &minter.did));
    assert_eq!(
        fixture.folders.reads(),
        0,
        "nothing was asked of the minter"
    );
    assert!(fixture.ipfs.pinned().is_empty());
}

/// M0R1-F2 guard: the copy admission is not `content.replica`: an accepted
/// minter's `import_exact`, or an `ensure` of another policy, is refused.
#[tokio::test]
async fn guard_an_accepted_minters_import_exact_is_refused() {
    let fixture = CopyFixture::new(0xd6, &[], AMPLE).await;
    let item = ListedItem::minted("minted film", 0xe6, fixture.served_pool_did(), None);
    serve_items(&fixture, &[&item]);
    fixture.minter_home(0xe6, &[&item]).await;
    fixture.accept_minted(0xe6, &item).await;

    for (operation, mut request) in [
        (
            "import_exact",
            serde_json::json!({ "op": "import_exact", "cid": item.listing.cid, "data": "" }),
        ),
        (
            "ensure",
            serde_json::json!({ "op": "ensure", "cid": item.listing.cid,
                "availability_policy": "network_default" }),
        ),
    ] {
        request["_runtime_invocation"] = runtime_invocation(operation);
        let answer = crate::carrier::carrier_provider_invoke_registry(
            &fixture.registry,
            &serde_json::json!({
                "source": "carrier-availability", "target": "content",
                "operation": operation, "transfer": "json", "request": request,
            }),
            &home_endpoint(0xe6),
            crate::carrier::CarrierProviderCaller::Peer {
                data_dir: &fixture.member.data_dir,
                network: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(answer["ok"], false, "{operation}: {answer}");
        assert_eq!(
            answer["code"],
            crate::carrier::CARRIER_PEER_REFUSED,
            "{operation}: {answer}"
        );
    }
    assert!(fixture.ipfs.imported().is_empty());
    assert!(fixture.ipfs.pinned().is_empty());
}

/// guard: the copy admission an accepted share settled goes with the pool.
#[tokio::test]
async fn guard_after_stop_the_minters_admission_is_gone() {
    let fixture = CopyFixture::new(0xd3, &[], AMPLE).await;
    let item = ListedItem::minted("minted film", 0xe3, fixture.served_pool_did(), None);
    let minter = fixture.minter_home(0xe3, &[&item]).await;
    fixture.accept_minted(0xe3, &item).await;
    assert!(minter_copy_admitted(&fixture.member.data_dir, &minter.did));

    fixture.stop().await.unwrap();

    assert!(!minter_copy_admitted(&fixture.member.data_dir, &minter.did));
    assert!(minter_copy_admissions(&fixture.member.data_dir)
        .unwrap()
        .is_empty());
}

/// guard: a grant the member's operator added by hand is the operator's,
/// and survives the pool's Stop.
#[tokio::test]
async fn guard_a_hand_added_operator_grant_survives_stop() {
    let fixture = CopyFixture::new(0xd4, &[], AMPLE).await;
    let item = ListedItem::minted("minted film", 0xe4, fixture.served_pool_did(), None);
    let minter = fixture.minter(0xe4, &[&item]).await;
    fixture.accept_minted(0xe4, &item).await;

    fixture.stop().await.unwrap();

    assert!(fixture.replica_granted(&minter.did));
}

/// The answer a member's custody capsule gives a stored pool share, the one
/// the minting Home's coordinator accepts (`validate_provisioned_against`).
fn provisioned_answer(
    record: &elastos_protected_content_contracts::CustodyNodeProvisioningRecordV1,
    provisioning: &elastos_protected_content_contracts::SignedRuntimeCustodyProvisioningV1,
) -> serde_json::Value {
    use elastos_protected_content_contracts::CanonicalContract as _;
    let identity = record.record_identity().unwrap();
    serde_json::json!({
        "status": "provisioned",
        "schema": elastos_protected_content_provider_contracts::POOL_CUSTODY_RESPONSE_SCHEMA_V1,
        "provisioning_id": provisioning.statement().provisioning_id().digest().as_bytes(),
        "provisioning_operation_hash": provisioning.statement().canonical_hash().unwrap().as_bytes(),
        "custody_node_provisioning_record_sha256": identity.record_sha256().as_bytes(),
        "custody_node_provisioning_record_bytes": identity.record_bytes(),
        "selected_node_public_key": record.selected_node_public_key().as_bytes(),
    })
}

/// M0R1-F3: the custody wrapper settles the admission inside the share
/// write it owns: a caller that gave up waiting still leaves the minter
/// admitted. M0R2-F1: when the admission cannot be recorded, the minting
/// Home still gets the share write's own answer, the one its coordinator
/// accepts, so the mint goes on with the same request and nothing is
/// resealed; the admission settles from the stored share afterwards.
#[tokio::test]
async fn the_wrapper_settles_a_minters_admission_inside_its_share_write() {
    let fixture = CopyFixture::new(0xd7, &[], AMPLE).await;
    let item = ListedItem::minted("minted film", 0xe7, fixture.served_pool_did(), None);
    fixture.pool_node_root();
    fixture.key_served_pool_as_a_join_does();
    let (record, provisioning, _) = minted_provisioning(0xe7, &item);
    let request = fixture.pool_share_request_for(&record, &provisioning, &item);
    let answer = provisioned_answer(&record, &provisioning);
    let (_, minter_did) = elastos_identity::derive_did(&[0xe7; 32]);
    let wrapper = crate::protected_content_runtime::tests::PoolShareWrapperForTest::start(
        &fixture.member.data_dir,
        1,
        &answer,
    )
    .await;

    // The caller is gone before the capsule answers; the write settles.
    let cancelled = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        wrapper.provision(request.clone()),
    )
    .await;
    assert!(
        cancelled.is_err(),
        "the caller gave up before the answer: {cancelled:?}"
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while !minter_copy_admitted(&fixture.member.data_dir, &minter_did) {
        assert!(tokio::time::Instant::now() < deadline, "never settled");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // Admission persistence blocked: the minting Home still gets the share
    // write's answer, and its coordinator accepts it for the same request.
    let blocked = protected_content_root(&fixture.member.data_dir).join(MINTER_ADMISSIONS_FILE);
    std::fs::remove_file(&blocked).unwrap();
    std::fs::create_dir(&blocked).unwrap();
    let blocked_answer = wrapper.provision(request.clone()).await.unwrap();
    assert_eq!(blocked_answer["status"], "ok", "{blocked_answer}");
    // The coordinator's own call (`mint.rs` `provision_pool_node`): its
    // custody adapter returns the provisioned answer, which validates for the
    // request it sent, so the node's receipt is marked and nothing aborts.
    let typed: elastos_protected_content_provider_contracts::PoolCustodyRequestV1 =
        elastos_protected_content_provider_contracts::PoolCustodyRequestV1::from_json_slice(
            &serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
    wrapper
        .provision_as_the_coordinator(&typed)
        .await
        .expect("the coordinator's provider call is not NoExactResult")
        .validate_provisioned_against(&provisioning, &record)
        .expect("the coordinator accepts the answer and marks the node's receipt");

    // Restored, the admission settles from the stored share, and an exact
    // retry of the same request gets the same answer.
    std::fs::remove_dir_all(&blocked).unwrap();
    fixture.store_minted_share(0xe7, &item, &item);
    assert!(!minter_copy_admitted(&fixture.member.data_dir, &minter_did));
    fixture
        .member
        .handler
        .before_delivery_pass(crate::auth::now_ts());
    assert!(minter_copy_admitted(&fixture.member.data_dir, &minter_did));
    assert_eq!(wrapper.provision(request).await.unwrap(), blocked_answer);
}

/// A committee node a minting Home's coordinator selects, standing in for
/// another member: it answers a pool share write with its provisioned
/// answer.
struct AnsweringPoolNode;

#[async_trait::async_trait]
impl elastos_protected_content_runtime::RuntimeCustodyProvider for AnsweringPoolNode {
    async fn release_contribution(
        &self,
        _request: &elastos_protected_content_provider_contracts::CustodyProviderRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::CustodyProviderResponseV1,
        elastos_protected_content_runtime::RuntimeProviderCallError,
    > {
        Err(elastos_protected_content_runtime::RuntimeProviderCallError::NoExactResult)
    }

    async fn provision_node_share(
        &self,
        _request: &elastos_protected_content_provider_contracts::CustodyProviderRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::CustodyProviderResponseV1,
        elastos_protected_content_runtime::RuntimeProviderCallError,
    > {
        Err(elastos_protected_content_runtime::RuntimeProviderCallError::NoExactResult)
    }

    async fn release_pool_contribution(
        &self,
        _request: &elastos_protected_content_provider_contracts::PoolCustodyRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::PoolCustodyResponseV1,
        elastos_protected_content_runtime::RuntimeProviderCallError,
    > {
        Err(elastos_protected_content_runtime::RuntimeProviderCallError::NoExactResult)
    }

    async fn provision_pool_node_share(
        &self,
        request: &elastos_protected_content_provider_contracts::PoolCustodyRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::PoolCustodyResponseV1,
        elastos_protected_content_runtime::RuntimeProviderCallError,
    > {
        let (record, statement, _) = request.provision_contents().unwrap();
        Ok(
            elastos_protected_content_provider_contracts::PoolCustodyResponseV1::from_json_slice(
                &serde_json::to_vec(&provisioned_answer(&record, &statement)).unwrap(),
            )
            .unwrap(),
        )
    }
}

/// This member as a minting Home's coordinator reaches it for committee
/// node 1: the coordinator's registry adapter over the member's real
/// custody wrapper. The capsule stand-in answers each share write with the
/// provisioned answer for that write, as a custody capsule does; the writes
/// are kept so the test can store the share the capsule would have stored.
struct MemberPoolNode<'a> {
    wrapper: &'a crate::protected_content_runtime::tests::PoolShareWrapperForTest,
    writes: StdMutex<Vec<elastos_protected_content_provider_contracts::PoolCustodyRequestV1>>,
}

#[async_trait::async_trait]
impl elastos_protected_content_runtime::RuntimeCustodyProvider for MemberPoolNode<'_> {
    async fn release_contribution(
        &self,
        _request: &elastos_protected_content_provider_contracts::CustodyProviderRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::CustodyProviderResponseV1,
        elastos_protected_content_runtime::RuntimeProviderCallError,
    > {
        Err(elastos_protected_content_runtime::RuntimeProviderCallError::NoExactResult)
    }

    async fn provision_node_share(
        &self,
        _request: &elastos_protected_content_provider_contracts::CustodyProviderRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::CustodyProviderResponseV1,
        elastos_protected_content_runtime::RuntimeProviderCallError,
    > {
        Err(elastos_protected_content_runtime::RuntimeProviderCallError::NoExactResult)
    }

    async fn release_pool_contribution(
        &self,
        _request: &elastos_protected_content_provider_contracts::PoolCustodyRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::PoolCustodyResponseV1,
        elastos_protected_content_runtime::RuntimeProviderCallError,
    > {
        Err(elastos_protected_content_runtime::RuntimeProviderCallError::NoExactResult)
    }

    async fn provision_pool_node_share(
        &self,
        request: &elastos_protected_content_provider_contracts::PoolCustodyRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::PoolCustodyResponseV1,
        elastos_protected_content_runtime::RuntimeProviderCallError,
    > {
        let (record, statement, _) = request.provision_contents().unwrap();
        self.wrapper
            .answer_with(&provisioned_answer(&record, &statement));
        self.writes.lock().unwrap().push(request.clone());
        self.wrapper.provision_as_the_coordinator(request).await
    }
}

/// M0R2-F1 through the real mint caller: a whole pool mint by a
/// `RuntimeMintCoordinator`, with this member as committee node 1 behind
/// its real custody wrapper, completes while the member cannot record the
/// minter's copy admission: no abort and no reseal. Restored, the
/// admission settles from the stored share, and the same mint replays its
/// outcome without writing to any node again.
#[tokio::test]
async fn a_pool_mint_completes_while_a_member_cannot_record_the_minters_admission() {
    use ed25519_dalek::Signer as _;
    use elastos_protected_content_contracts::test_fixtures::{
        node_public_key, CUSTODY_KEY_SEED_BASE,
    };
    use elastos_protected_content_runtime::{
        RuntimeCustodyProvider, RuntimeMintCoordinator, RuntimeMintCoordinatorOutcome,
        RuntimeMintDraft, RuntimeMintJournal, RuntimeMintNodeBinding, RuntimeMintPoolProvisioning,
        RuntimeMintSelectedNode,
    };
    use std::os::unix::fs::DirBuilderExt as _;
    let fixture = CopyFixture::new(0xe6, &[], AMPLE).await;
    let root = fixture.pool_node_root();
    let descriptor = fixture.served_descriptor();
    fixture.key_served_pool_as_a_join_does();

    // The minting Home's draft: a real envelope of the served pool's
    // committee over the item's media.
    let bundle = served_custody_pool();
    let committee = bundle.signed_epoch().statement().nodes().to_vec();
    let (init_segment, encrypted_segments) =
        crate::protected_content_runtime::tests::media_components(0x5e);
    let envelope = elastos_protected_content_custody::provision_custody_envelope_for_exact_nodes(
        crate::protected_content_runtime::tests::media_identity(0x5e)
            .encrypted_content()
            .clone(),
        &elastos_protected_content_custody::ContentEncryptionKeyV1::generate().unwrap(),
        bundle.signed_pool().pool_identity().unwrap(),
        bundle.signed_epoch().epoch_identity().unwrap(),
        bundle
            .signed_committee_authorization()
            .authorization_identity()
            .unwrap(),
        &committee
            .iter()
            .map(|node| {
                elastos_protected_content_custody::ExactCustodyEnvelopeNodeV1::new(
                    node.node_public_key(),
                    node.custody_public_key(),
                )
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let kid = elastos_protected_content_contracts::ContentAccessIdV1::new([0x5e; 16]).unwrap();
    let bindings: Vec<RuntimeMintNodeBinding> = committee
        .iter()
        .zip(1u8..)
        .map(|(node, seed)| {
            RuntimeMintNodeBinding::new(
                node.node_public_key(),
                elastos_protected_content_contracts::CustodyPoolOperatorIdV1::new(
                    [0x80 + seed; 32],
                ),
                elastos_protected_content_contracts::CustodyPoolFailureDomainIdV1::new(
                    [0x90 + seed; 32],
                ),
                elastos_protected_content_contracts::Digest32::new([0x3f + seed; 32]),
            )
            .unwrap()
        })
        .collect();
    let draft = RuntimeMintDraft::new(
        &init_segment,
        &encrypted_segments,
        crate::protected_content_runtime::tests::MEDIA_MIME_TYPE_V1,
        crate::protected_content_runtime::tests::MEDIA_CODECS_V1,
        kid,
        envelope.key_envelope_identity().unwrap(),
        elastos_protected_content_contracts::RightsPolicyIdentityV1::new(
            elastos_protected_content_contracts::Digest32::new([0x44; 32]),
            384,
        )
        .unwrap(),
        envelope.manifest().content_key_commitment(),
        envelope.manifest().threshold(),
        bindings.clone(),
    )
    .unwrap();

    let wrapper = crate::protected_content_runtime::tests::PoolShareWrapperForTest::start(
        &fixture.member.data_dir,
        0,
        &serde_json::json!({}),
    )
    .await;
    let member = MemberPoolNode {
        wrapper: &wrapper,
        writes: StdMutex::new(Vec::new()),
    };
    let other = AnsweringPoolNode;
    let selected = bindings
        .into_iter()
        .map(|binding| {
            let custody: &dyn RuntimeCustodyProvider =
                if binding.node_public_key() == node_public_key(1) {
                    &member
                } else {
                    &other
                };
            RuntimeMintSelectedNode::new(binding, custody)
        })
        .collect();
    let (minter_key, minter_did) = elastos_identity::derive_did(&[0xe8; 32]);
    let minter = elastos_protected_content_contracts::RuntimeOperationIssuerKeyV1::new(
        minter_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let journal_parent = tempfile::tempdir().unwrap();
    let journal_owner = journal_parent.path().join("owner-only");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&journal_owner)
        .unwrap();
    let journal_root = journal_owner.join("runtime-mint");
    let coordinator = RuntimeMintCoordinator::new(
        RuntimeMintJournal::new(journal_root.clone()),
        minter,
        move |bytes: &[u8]| minter_key.sign(bytes).to_bytes(),
        selected,
    )
    .unwrap()
    .with_pool_provisioning(RuntimeMintPoolProvisioning::new(descriptor, kid));

    // The member cannot record the admission.
    let blocked =
        crate::protected_content_runtime::protected_content_root(&fixture.member.data_dir)
            .join(MINTER_ADMISSIONS_FILE);
    let _ = std::fs::remove_file(&blocked);
    std::fs::create_dir_all(&blocked).unwrap();

    let outcome = coordinator
        .provision(&draft, &envelope, crate::auth::now_ts())
        .await
        .unwrap();

    assert_eq!(
        outcome,
        RuntimeMintCoordinatorOutcome::CustodyProvisioned {
            mint_id: draft.mint_id()
        },
        "the mint is not aborted"
    );
    let journal = RuntimeMintJournal::new(journal_root.clone())
        .load(draft.mint_id())
        .unwrap();
    assert!(journal.all_receipts_present());
    assert_eq!(journal.uncertain_node_count(), 0);
    assert!(!minter_copy_admitted(&fixture.member.data_dir, &minter_did));

    // Restored. Not vacuous (M0R3-F1): the wrapper's root is a trusted
    // served pool's, so a settlement for it records the minter; the blocked
    // write above really failed to record it. Cleared again for the pass.
    std::fs::remove_dir_all(&blocked).unwrap();
    settle_accepted_pool_share(&fixture.member.data_dir, &root, minter).unwrap();
    assert!(minter_copy_admitted(&fixture.member.data_dir, &minter_did));
    std::fs::remove_file(&blocked).unwrap();
    assert!(!minter_copy_admitted(&fixture.member.data_dir, &minter_did));
    // The share the capsule stored settles the admission on the next
    // delivery pass.
    let writes = member.writes.lock().unwrap().clone();
    assert_eq!(writes.len(), 1);
    let (record, statement, mint_share) = writes[0].provision_contents().unwrap();
    elastos_protected_content_custody::NodeLocalShareStoreV1::new(
        node_public_key(1),
        custody_provider::node_share_store_dir(&root),
    )
    .provision_pool_node_share_classified(
        &record,
        &statement,
        &mint_share,
        &elastos_protected_content_custody::NodeCustodySecretKeyV1::from_guarded_bytes(
            zeroize::Zeroizing::new([CUSTODY_KEY_SEED_BASE + 1; 32]),
        )
        .unwrap(),
        crate::auth::now_ts(),
    )
    .unwrap();
    fixture
        .member
        .handler
        .before_delivery_pass(crate::auth::now_ts());
    assert!(minter_copy_admitted(&fixture.member.data_dir, &minter_did));

    // The same mint again: its outcome comes from the journal, and no node
    // is written again, so nothing is resealed.
    assert_eq!(
        coordinator
            .provision(&draft, &envelope, crate::auth::now_ts())
            .await
            .unwrap(),
        outcome
    );
    assert_eq!(member.writes.lock().unwrap().len(), 1);
}

/// M0R1-F4: a pin that landed although its answer was an error, or was
/// lost, is the copy: its record stays, and the copy is kept.
#[tokio::test]
async fn a_pin_that_lands_with_a_failed_or_lost_answer_keeps_its_record() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xd8, &[&item], AMPLE).await;
    fixture
        .ipfs
        .pin_answers_badly
        .lock()
        .unwrap()
        .insert(item.content.cid.clone());
    fixture
        .ipfs
        .pin_reply_lost
        .lock()
        .unwrap()
        .insert(item.metadata.cid.clone());

    let outcome = fixture.keep(&item.listing.cid).await;

    assert_eq!(outcome, Ok(crate::carrier::MemberCopyOutcome::Kept));
    assert_eq!(fixture.ipfs.pinned(), item.cids());
    assert_eq!(
        fixture.recorded(),
        item.cids(),
        "no pin is left unaccounted"
    );
}

/// M0R1-F4: when the pin state cannot be read after a failed pin, the
/// reservation stays until it is known.
#[tokio::test]
async fn guard_a_failed_pin_of_unknown_state_keeps_its_reservation() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xd9, &[&item], AMPLE).await;
    *fixture.ipfs.pin_state_unknown.lock().unwrap() = Some(item.content.cid.clone());

    let outcome = fixture.keep(&item.listing.cid).await;

    assert!(outcome.is_err(), "{outcome:?}");
    assert!(fixture.recorded().contains(&item.content.cid));
}

/// The member's record of `cid` for the owner's pool.
fn owner_pool_copy(fixture: &CopyFixture, cid: &str) -> MemberCopyV1 {
    member_copies(&fixture.member.data_dir)
        .unwrap()
        .into_iter()
        .find(|copy| copy.cid == cid && copy.pool_fingerprint == fixture.owner.pool_fingerprint())
        .unwrap()
}

/// M0R2-F2: a listing already pinned here when its copy commits is the
/// pool's duty, charged at its real size, but its pin is borrowed: Stop
/// unpins the copies' own pins and leaves it.
#[tokio::test]
async fn a_borrowed_pin_is_charged_and_kept_through_stop() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xda, &[&item], AMPLE).await;
    fixture
        .ipfs
        .pinned
        .lock()
        .unwrap()
        .insert(item.listing.cid.clone());

    assert_eq!(
        fixture.keep(&item.listing.cid).await,
        Ok(crate::carrier::MemberCopyOutcome::Kept)
    );
    assert_eq!(fixture.ipfs.pinned(), item.cids());
    assert_eq!(fixture.recorded(), item.cids());
    let listing = owner_pool_copy(&fixture, &item.listing.cid);
    assert!(listing.borrowed);
    assert_eq!(
        listing.bytes,
        item.listing.bytes(),
        "charged at its real size"
    );
    assert!(!owner_pool_copy(&fixture, &item.content.cid).borrowed);
    let charged: u64 = item.folders().iter().map(|folder| folder.bytes()).sum();
    assert_eq!(
        member_copies_bytes(&fixture.member.data_dir).unwrap(),
        charged
    );
    assert_eq!(
        fixture.peer_reads(&stranger(), &item.listing.cid).await,
        Ok(())
    );

    fixture.stop().await.unwrap();
    assert!(fixture.recorded().is_empty());
    assert_eq!(
        fixture.ipfs.pinned(),
        BTreeSet::from([item.listing.cid.clone()]),
        "the borrowed pin stays"
    );
}

/// M0R2-F2: a borrowed pin is never kept uncharged: at a full host it is
/// refused with storage_full. Once charged, its loss is repaired by a commit
/// that pins it again, free (it is charged already) and now owned, so Stop
/// unpins it.
#[tokio::test]
async fn a_borrowed_pin_at_a_full_host_is_refused_then_repaired_as_owned() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xdb, &[&item], AMPLE).await;
    fixture
        .ipfs
        .pinned
        .lock()
        .unwrap()
        .insert(item.listing.cid.clone());
    let set_max = |max: u64| {
        crate::host_trust::write_host_trust(
            &fixture.member.data_dir,
            crate::host_trust::HostTrustModeV1::WciOperated,
            Some(max),
        )
        .unwrap()
    };
    set_max(
        crate::protected_content_runtime::host_custody_storage_bytes(&fixture.member.data_dir)
            .unwrap(),
    );

    let refused = fixture.keep(&item.listing.cid).await.unwrap_err();
    assert_eq!(
        refused["code"],
        crate::host_trust::HOST_STORAGE_FULL,
        "{refused}"
    );
    assert!(fixture.recorded().is_empty(), "nothing kept uncharged");

    set_max(1 << 30);
    assert_eq!(
        fixture.keep(&item.listing.cid).await,
        Ok(crate::carrier::MemberCopyOutcome::Kept)
    );
    assert!(owner_pool_copy(&fixture, &item.listing.cid).borrowed);
    let used =
        crate::protected_content_runtime::host_custody_storage_bytes(&fixture.member.data_dir)
            .unwrap();

    // The borrowed pin is lost; the host is exactly full.
    fixture
        .ipfs
        .pinned
        .lock()
        .unwrap()
        .remove(&item.listing.cid);
    set_max(used);
    assert_eq!(
        fixture.keep(&item.listing.cid).await,
        Ok(crate::carrier::MemberCopyOutcome::Kept)
    );
    assert!(fixture.ipfs.pinned().contains(&item.listing.cid));
    assert!(
        !owner_pool_copy(&fixture, &item.listing.cid).borrowed,
        "now owned"
    );
    assert_eq!(
        crate::protected_content_runtime::host_custody_storage_bytes(&fixture.member.data_dir)
            .unwrap(),
        used
    );

    fixture.stop().await.unwrap();
    assert!(fixture.ipfs.pinned().is_empty());
    assert!(fixture.recorded().is_empty());
}

/// M0R2-F2: pool B sees the payload pinned (pool A's copy) and goes to
/// commit; A withdraws and unpins first. B's commit looks again under the
/// host lock, finds it gone, fetches the bytes and pins it again: owned and
/// charged, never recorded against a missing pin.
#[tokio::test]
async fn a_shared_pin_withdrawn_before_a_commit_is_repinned_owned_and_charged() {
    let item = ListedItem::new("film");
    let fixture = Arc::new(CopyFixture::new(0xdc, &[&item], AMPLE).await);
    fixture
        .ipfs
        .pinned
        .lock()
        .unwrap()
        .insert(item.content.cid.clone());
    assert!(record_member_copy(
        &fixture.member.data_dir,
        MemberCopyV1 {
            cid: item.content.cid.clone(),
            owner_did: fixture.owner.did(),
            pool_fingerprint: "sha256:pool-a".to_string(),
            bytes: item.content.bytes(),
            borrowed: false,
        },
    )
    .unwrap());
    // Pool A's withdrawal is held at its unpin, holding the host lock.
    let gate = Gate::new(&item.content.cid, "unpin");
    *fixture.ipfs.gate.lock().unwrap() = Some(gate.clone());
    let withdrawing = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        async move {
            let write = lock_custody_writes().await;
            withdraw_member_copies(
                &write,
                &fixture.member.data_dir,
                Some(&fixture.registry),
                "sha256:pool-a",
            )
            .await
        }
    });
    gate.reached.notified().await;
    // B sees the payload pinned and A's copy, and goes to commit.
    let keeping = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        let cid = item.listing.cid.clone();
        async move { fixture.keep(&cid).await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    gate.release();
    withdrawing.await.unwrap().unwrap();

    assert_eq!(
        keeping.await.unwrap(),
        Ok(crate::carrier::MemberCopyOutcome::Kept)
    );
    assert!(fixture.ipfs.pinned().contains(&item.content.cid));
    let content = owner_pool_copy(&fixture, &item.content.cid);
    assert!(!content.borrowed, "the commit that pinned it owns it");
    assert_eq!(content.bytes, item.content.bytes());
    let charged: u64 = item.folders().iter().map(|folder| folder.bytes()).sum();
    assert_eq!(
        member_copies_bytes(&fixture.member.data_dir).unwrap(),
        charged
    );
}

/* ---------- M0 R3 self-review ---------- */

/// R3 self-review: the delivery pass settles admissions from the stores
/// additively, so an admission a share write settled while the pass read
/// the stores is never dropped by it.
#[tokio::test]
async fn guard_a_delivery_pass_keeps_an_admission_settled_while_it_read() {
    let fixture = CopyFixture::new(0xdd, &[], AMPLE).await;
    let root = fixture.pool_node_root();
    let (_, minter_did) = elastos_identity::derive_did(&[0xed; 32]);
    let (minter_key, _) = elastos_identity::derive_did(&[0xed; 32]);
    // Settled by a share write whose share the pass did not see.
    settle_accepted_pool_share(
        &fixture.member.data_dir,
        &root,
        elastos_protected_content_contracts::RuntimeOperationIssuerKeyV1::new(
            minter_key.verifying_key().to_bytes(),
        )
        .unwrap(),
    )
    .unwrap();

    fixture
        .member
        .handler
        .before_delivery_pass(crate::auth::now_ts());

    assert!(minter_copy_admitted(&fixture.member.data_dir, &minter_did));
}

/// R3 self-review: a Stop whose caller goes away while it unpins the copies
/// still finishes: no record is left charging for a pin it no longer has.
#[tokio::test]
async fn a_stop_cancelled_while_it_unpins_still_drops_the_copies() {
    let item = ListedItem::new("film");
    let fixture = Arc::new(CopyFixture::new(0xde, &[&item], AMPLE).await);
    fixture.keep(&item.listing.cid).await.unwrap();
    let first = member_copies(&fixture.member.data_dir).unwrap()[0]
        .cid
        .clone();
    let gate = Gate::new(&first, "unpin");
    *fixture.ipfs.gate.lock().unwrap() = Some(gate.clone());
    let stopping = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        async move { fixture.stop().await }
    });
    gate.reached.notified().await;

    stopping.abort();
    let _ = stopping.await;
    gate.release();

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while !fixture.recorded().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{:?}",
            fixture.recorded()
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        fixture.ipfs.pinned().is_empty(),
        "{:?}",
        fixture.ipfs.pinned()
    );
}

/// R3 self-review: an unknown pin state at commit decides nothing: the copy
/// is not recorded, so it cannot claim, and later unpin, a pin it may only
/// borrow.
#[tokio::test]
async fn guard_an_unknown_pin_state_at_commit_records_no_copy() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xdf, &[&item], AMPLE).await;
    fixture
        .ipfs
        .pinned
        .lock()
        .unwrap()
        .insert(item.content.cid.clone());
    *fixture.ipfs.pin_status_fails.lock().unwrap() = Some(item.content.cid.clone());

    let outcome = fixture.keep(&item.listing.cid).await;

    assert!(outcome.is_err(), "{outcome:?}");
    assert!(!fixture.recorded().contains(&item.content.cid));
    assert!(fixture.ipfs.pinned().contains(&item.content.cid));
}

/// M0R2-F2: the charge is decided at the commit, under the host lock. A
/// borrowed listing that fit when it was staged but no longer fits once the
/// set's other copies are charged is refused with storage_full: never kept
/// uncharged.
#[tokio::test]
async fn guard_a_borrowed_pin_that_no_longer_fits_at_commit_is_refused() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xe0, &[&item], AMPLE).await;
    fixture
        .ipfs
        .pinned
        .lock()
        .unwrap()
        .insert(item.listing.cid.clone());
    let used =
        crate::protected_content_runtime::host_custody_storage_bytes(&fixture.member.data_dir)
            .unwrap();
    let set: u64 = item.folders().iter().map(|folder| folder.bytes()).sum();
    crate::host_trust::write_host_trust(
        &fixture.member.data_dir,
        crate::host_trust::HostTrustModeV1::WciOperated,
        Some(used + set - 1),
    )
    .unwrap();

    let refused = fixture.keep(&item.listing.cid).await.unwrap_err();

    assert_eq!(
        refused["code"],
        crate::host_trust::HOST_STORAGE_FULL,
        "{refused}"
    );
    assert!(!fixture.recorded().contains(&item.listing.cid));
    assert!(
        fixture.ipfs.pinned().contains(&item.listing.cid),
        "the borrowed pin stays"
    );
}

/// R3: Stop unpins a copy-owned pin only when no other local owner still
/// references the CID. This Home later published the payload itself: the
/// pool's duty and charge go, the pin stays for the publication.
#[tokio::test]
async fn a_copy_owned_pin_this_home_later_published_survives_stop() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xe2, &[&item], AMPLE).await;
    fixture.keep(&item.listing.cid).await.unwrap();
    assert!(!owner_pool_copy(&fixture, &item.content.cid).borrowed);
    crate::library::publish_cid_for_test(&fixture.member.data_dir, &item.content.cid);

    fixture.stop().await.unwrap();

    assert!(fixture.recorded().is_empty());
    assert_eq!(
        fixture.ipfs.pinned(),
        BTreeSet::from([item.content.cid.clone()]),
        "only the published CID stays pinned"
    );
}

/// R3: when this Home's published index cannot be read, the copy cannot
/// tell whether its own publications still need the CID, so its pin
/// survives Stop; only the pool's duty and charge go.
#[tokio::test]
async fn guard_a_copy_owned_pin_survives_stop_when_the_published_index_is_unreadable() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xe4, &[&item], AMPLE).await;
    fixture.keep(&item.listing.cid).await.unwrap();
    crate::library::break_published_index_for_test(&fixture.member.data_dir);

    fixture.stop().await.unwrap();

    assert!(fixture.recorded().is_empty());
    assert_eq!(
        fixture.ipfs.pinned(),
        item.cids(),
        "no pin given up on a guess"
    );
}

/// R3: a copy-owned pin that no other owner on this Home references is
/// still unpinned by Stop, with its duty and charge.
#[tokio::test]
async fn an_unreferenced_copy_owned_pin_is_unpinned_on_stop() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xe5, &[&item], AMPLE).await;
    fixture.keep(&item.listing.cid).await.unwrap();
    assert!(!owner_pool_copy(&fixture, &item.content.cid).borrowed);
    let charged =
        crate::protected_content_runtime::host_custody_storage_bytes(&fixture.member.data_dir)
            .unwrap();
    assert!(charged > 0);

    fixture.stop().await.unwrap();

    assert!(fixture.recorded().is_empty());
    assert!(
        fixture.ipfs.pinned().is_empty(),
        "{:?}",
        fixture.ipfs.pinned()
    );
    assert!(
        crate::protected_content_runtime::host_custody_storage_bytes(&fixture.member.data_dir)
            .unwrap()
            < charged,
        "the charge goes with the copies"
    );
}

/// R3: a CID a runtime listing on this Home names (an imported or bought
/// item) is another owner's too, and its pin survives Stop.
#[tokio::test]
async fn a_copy_owned_pin_a_runtime_listing_names_survives_stop() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xe3, &[&item], AMPLE).await;
    fixture.keep(&item.listing.cid).await.unwrap();
    let mut record =
        crate::protected_content_runtime::tests::runtime_custody_listing_record_for_test(
            elastos_protected_content_contracts::Digest32::new([0x75; 32]),
            "person:local:buyer",
            "film",
            2_000_000_000,
        );
    record.package.metadata_cid = item.metadata.cid.clone();
    let root = fixture
        .member
        .data_dir
        .join("protected-content/runtime-listings");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join(format!("{}.json", "7".repeat(64))),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();

    fixture.stop().await.unwrap();

    assert!(fixture.recorded().is_empty());
    assert_eq!(
        fixture.ipfs.pinned(),
        BTreeSet::from([item.metadata.cid.clone()])
    );
}

/// M0R3-F6: this Home's Content for a Library publish. It pins the CID on
/// the member's IPFS, then holds the publish until the test lets it go.
struct HeldPublishContent {
    ipfs: Arc<MemberIpfs>,
    cid: String,
    gate: StdMutex<Option<Gate>>,
}

#[async_trait::async_trait]
impl elastos_runtime::provider::Provider for HeldPublishContent {
    async fn handle(
        &self,
        _: elastos_runtime::provider::ResourceRequest,
    ) -> Result<elastos_runtime::provider::ResourceResponse, elastos_runtime::provider::ProviderError>
    {
        Err(elastos_runtime::provider::ProviderError::Provider(
            "fixture raw only".into(),
        ))
    }
    fn schemes(&self) -> Vec<&'static str> {
        vec![]
    }
    fn name(&self) -> &'static str {
        "held-publish-content"
    }
    async fn send_raw(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, elastos_runtime::provider::ProviderError> {
        if request["op"] != "publish" {
            return Ok(serde_json::json!({"status": "error", "code": "unsupported"}));
        }
        self.ipfs.pinned.lock().unwrap().insert(self.cid.clone());
        Gate::pass(&self.gate, &self.cid, "publish").await;
        Ok(serde_json::json!({"status": "ok", "data": {
            "cid": self.cid,
            "availability": {"status": "local_pinned"},
            "receipt": {"status": "local_pinned"},
        }}))
    }
}

/// M0R3-F6: a Stop asked while a Library publish of a copy-owned CID sits
/// between its pin and its record cannot unpin it: the CID stays pinned and
/// recorded.
#[tokio::test]
async fn a_stop_during_a_library_publish_keeps_the_copy_owned_pin_it_records() {
    let item = ListedItem::new("film");
    let fixture = CopyFixture::new(0xe6, &[&item], AMPLE).await;
    fixture.keep(&item.listing.cid).await.unwrap();
    assert!(!owner_pool_copy(&fixture, &item.content.cid).borrowed);
    let gate = Gate::new(&item.content.cid, "publish");
    let library = Arc::new(ProviderRegistry::new());
    library
        .register_sub_provider(
            "content",
            Arc::new(HeldPublishContent {
                ipfs: fixture.ipfs.clone(),
                cid: item.content.cid.clone(),
                gate: StdMutex::new(Some(gate.clone())),
            }),
        )
        .await
        .unwrap();
    let data_dir = fixture.member.data_dir.clone();
    let principal = "did:key:z6MkCopyOwnedLibraryPublish";
    let uri = format!(
        "{}/Documents/film.bin",
        crate::auth::principal_localhost_root(principal)
    );
    let write = Box::pin(crate::library::handle_object_provider_runtime_request(
        &data_dir,
        library.clone(),
        &serde_json::json!({
            "op": "write",
            "principal_id": principal,
            "uri": uri,
            "data": base64::engine::general_purpose::STANDARD.encode(b"film"),
        }),
    ))
    .await;
    assert_eq!(write["status"], "ok", "{write}");
    let publish = tokio::spawn({
        let (data_dir, library, uri) = (data_dir.clone(), library.clone(), uri.clone());
        async move {
            Box::pin(crate::library::handle_object_provider_runtime_request(
                &data_dir,
                library,
                &serde_json::json!({"op": "publish", "principal_id": principal, "uri": uri}),
            ))
            .await
        }
    });
    gate.reached.notified().await;

    // Stop is asked while the publish has pinned and not yet recorded.
    let mut stop = std::pin::pin!(fixture.stop());
    let stopped = tokio::time::timeout(std::time::Duration::from_millis(500), &mut stop).await;
    gate.release();
    let published = publish.await.unwrap();
    match stopped {
        Ok(stopped) => stopped.unwrap(),
        Err(_) => stop.await.unwrap(),
    }

    assert_eq!(published["status"], "ok", "{published}");
    assert!(crate::library::published_cids(&data_dir)
        .unwrap()
        .contains(&item.content.cid));
    assert!(
        fixture.ipfs.pinned().contains(&item.content.cid),
        "the recorded publication keeps its pin: {:?}",
        fixture.ipfs.pinned()
    );
}

/* ---------- OL-F1 / OL-F2 ---------- */

#[tokio::test]
async fn a_failed_replica_grant_leaves_the_join_incomplete_until_a_delivery_pass_settles_it() {
    let now = crate::auth::now_ts();
    let node = node(now);
    node.offer(true).await.unwrap();
    let olivia = Owner::new("Olivia", now);
    node.installs_provider_for(&olivia.issuer(), 0xb1);
    assert_eq!(node.receive(&olivia, 1, now), Ok(()));
    // The peer store cannot be written now.
    let peers = crate::operator_control::operator_control_path(&node.data_dir);
    std::fs::write(&peers, b"not a peer store").unwrap();

    let approved = node.approve(1, now).await.unwrap();

    assert!(approved.copies_pending, "{approved:?}");
    assert_eq!(node.record(1).state, RequestState::Approved);
    let root = served_pools(&node.data_dir).unwrap().entries[&olivia.pool_fingerprint()]
        .root_path
        .clone();
    assert!(!pool_join_complete(&node.data_dir, &root));
    // A pass while the store is still broken leaves it incomplete.
    node.handler.before_delivery_pass(now);
    assert!(!pool_join_complete(&node.data_dir, &root));

    // Once the store can be written, the next pass settles the grant.
    std::fs::remove_file(&peers).unwrap();
    node.handler.before_delivery_pass(now);

    assert!(pool_join_complete(&node.data_dir, &root));
    assert!(takes_replicas_from(&node, &olivia));
    assert!(replica_grant_owners(&node.data_dir)
        .unwrap()
        .contains(&olivia.did()));
}

/// The served-pools file as a build before OPEN-LOOP F1 reads it.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct ServedPoolsFileBeforeReplicaGrants {
    schema: String,
    entries: BTreeMap<String, ServedPoolEntryV2>,
    #[serde(default)]
    v1_needs_attention: Vec<String>,
    #[serde(default)]
    own_root_admin_profile_did: Option<String>,
}

#[tokio::test]
async fn an_older_build_reads_the_served_pools_file_this_build_writes() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0xb2).await;
    assert!(replica_grant_owners(&node.data_dir)
        .unwrap()
        .contains(&olivia.did()));
    // A later served-pools write, with the grant recorded.
    let write = lock_custody_writes().await;
    record_own_root_admin_profile(&write, &node.data_dir, node.profile_did()).unwrap();
    drop(write);

    let bytes = std::fs::read(served_pools_path(&node.data_dir)).unwrap();
    let older: ServedPoolsFileBeforeReplicaGrants = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&bytes)));
    assert!(older.entries.contains_key(&olivia.pool_fingerprint()));
}

#[tokio::test]
async fn replica_grants_kept_in_the_served_pools_file_move_to_their_own_file_on_read() {
    let now = crate::auth::now_ts();
    let olivia = Owner::new("Olivia", now);
    let node = serving(&olivia, now, 0xb3).await;
    // As a build before OL-F2 left the files.
    let path = served_pools_path(&node.data_dir);
    let mut file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file["replica_grant_owners"] = serde_json::json!([olivia.did()]);
    write_owner_only_bytes(&path, &serde_json::to_vec(&file).unwrap()).unwrap();
    std::fs::remove_file(replica_grants_path(&node.data_dir)).unwrap();

    let pools = served_pools(&node.data_dir).unwrap();

    assert!(pools.entries.contains_key(&olivia.pool_fingerprint()));
    assert!(read_replica_grant_owners(&node.data_dir)
        .unwrap()
        .contains(&olivia.did()));
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("replica_grant_owners"), "{text}");
    // The moved grant is still withdrawn with the owner's last root.
    stop_serving(&node, &olivia, now).await;
    assert!(!takes_replicas_from(&node, &olivia));
}

// AUDIT-REPRO J4 (red tests, no fix).
mod audit_j4_member_copies;

// AUDIT-REPRO J1/J5 (red tests, no fix).
mod audit_j1_j5_custody;

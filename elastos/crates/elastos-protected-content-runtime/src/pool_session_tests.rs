//! Plan B T3.2: the pool session server against fake ports and injected
//! session ids. The fakes record every port call; gates (semaphores with no
//! permits) hold a port call open so tests can race, close or cancel.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::Signer as _;
use elastos_protected_content_contracts::test_fixtures::{
    historical_v2_descriptor_with, key_envelope_for, node_public_key, pool_bundle,
    pool_descriptor_with, pool_did, pool_release_fixture, runtime_issuer,
    signed_node_rights_decision, signing_key, PoolReleaseFixtureV1, PoolReleaseSpecV1,
};
use elastos_protected_content_contracts::{
    CanonicalContract, ContentAccessIdV1, DeliveryPublicKeyBytesV1, Digest32,
    EncryptedContentIdentityV1, EvmContractAddressV1, EvmFunctionSelectorV1, EvmRightsMethodAbiV1,
    KeyReleaseOutcomeV1, NodeContributionRefV1, NodeContributionStatementV1, NodePublicKey,
    PoolDidV1, PoolRecipientAttestationStatementV2, PoolSessionContentKindV1, PoolTrustModeV1,
    ProtectedContentBindingV1, RecipientPublicKeyBytesV1, RecipientSealedContributionV1,
    RightsActionV1, RightsDecisionV1, RightsObservationFinalityV1, RightsPolicyBodyV1,
    RightsSubjectSourceV1, RuntimeIssuerPolicyV1, RuntimeOperationIssuerKeyV1,
    RuntimeReleaseAuditIdV1, ServePolicyV1, SignedNodeContributionV1,
    SignedPoolRecipientAttestationV2, SignedTerminalReceiptV1, TerminalReceiptIssuerKey,
    TerminalReceiptStatementV1, VerifiedPoolDescriptorV1, ViewerPartIndexV1,
    CUSTODY_X_WING_AES256GCM_SUITE_ID_V1, PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES,
};
use elastos_protected_content_provider_contracts::{
    CencDashRenditionKindV2, DecryptProviderRequestV1, DecryptProviderResponseV1,
    ProviderFailureCodeV1,
};
use serde_json::Value;
use tokio::sync::Semaphore;
use x_wing::kem::{Decapsulator as _, KeyExport as _};

use crate::pool_session::*;
use crate::RuntimeProviderCallError;

const NOW: u64 = 2_000_000_000;
const PREPARE_AT: u64 = NOW + 1;
/// The fixture operation runs from `now + 2` to `now + 40`.
const OPEN_AT: u64 = NOW + 5;
const READ_AT: u64 = NOW + 6;
const PREPARE_EXPIRES_AT: u64 = NOW + 250;
const DELIVERY_SEED: u8 = 0x5e;
const OWN_ENDPOINT: &str = "did:key:z6MkPoolServerHome";
const OWN_ISSUER_SEED: u8 = 0x50;
const BUYER_RUNTIME_SEED: u8 = 0x43;
/// The server is fixture pool node 1.
const SERVER_NODE: u8 = 1;
const STAGED_TOTAL_BYTES: u64 = 1200;
const PART_BYTES: u64 = 400;

pub(crate) fn xwing(seed: u8) -> [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
    let secret = x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE]);
    secret.encapsulation_key().to_bytes().into()
}

pub(crate) fn delivery_public_key(seed: u8) -> DeliveryPublicKeyBytesV1 {
    DeliveryPublicKeyBytesV1::new(xwing(seed)).unwrap()
}

fn source(n: u8) -> PoolSessionSource {
    PoolSessionSource {
        endpoint_did: format!("did:key:z6MkBuyerHome{n:02x}"),
        local: false,
    }
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Gates(Mutex<BTreeMap<&'static str, Arc<Semaphore>>>);

impl Gates {
    /// Holds every later call of `op` until `open` releases it.
    fn close(&self, op: &'static str) -> Arc<Semaphore> {
        let gate = Arc::new(Semaphore::new(0));
        self.0.lock().unwrap().insert(op, gate.clone());
        gate
    }

    async fn pass(&self, op: &'static str) {
        let gate = self.0.lock().unwrap().get(op).cloned();
        if let Some(gate) = gate {
            gate.acquire().await.unwrap().forget();
        }
    }
}

/// Lets the held tasks reach their gate.
async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

// ---------------------------------------------------------------------------
// Fake ports
// ---------------------------------------------------------------------------

fn request_json(request: &DecryptProviderRequestV1) -> Value {
    serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap()
}

fn audit_of(request: &Value) -> RuntimeReleaseAuditIdV1 {
    let bytes: [u8; 32] =
        serde_json::from_value(request["audit_request_id"].clone()).unwrap_or([0x91; 32]);
    RuntimeReleaseAuditIdV1::new(Digest32::new(bytes)).unwrap()
}

fn handle_of(request: &Value, field: &str) -> [u8; 32] {
    let text = request[field].as_str().unwrap();
    hex::decode(text).unwrap().try_into().unwrap()
}

#[derive(Default)]
struct DecryptState {
    calls: Mutex<Vec<(&'static str, Value)>>,
    next: AtomicU8,
    /// A typed refusal of the next opens.
    open_failure: Mutex<Option<ProviderFailureCodeV1>>,
    /// The next opens fail in transport.
    open_unreachable: AtomicBool,
    gates: Gates,
}

#[derive(Clone, Default)]
struct FakeDecrypt(Arc<DecryptState>);

impl FakeDecrypt {
    fn calls(&self, op: &str) -> Vec<Value> {
        self.0
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| *name == op)
            .map(|(_, request)| request.clone())
            .collect()
    }

    fn total_calls(&self) -> usize {
        self.0.calls.lock().unwrap().len()
    }

    async fn record(&self, op: &'static str, request: &DecryptProviderRequestV1) -> Value {
        let json = request_json(request);
        self.0.calls.lock().unwrap().push((op, json.clone()));
        self.0.gates.pass(op).await;
        json
    }
}

#[async_trait::async_trait]
impl PoolSessionDecryptPort for FakeDecrypt {
    async fn prepare_recipient_v2(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        let json = self.record("prepare_recipient_v2", request).await;
        let n = self.0.next.fetch_add(1, Ordering::SeqCst) + 1;
        let key = RecipientPublicKeyBytesV1::new(xwing(0x10 + n)).unwrap();
        Ok(DecryptProviderResponseV1::new_prepared_recipient(
            audit_of(&json),
            [n; 32],
            key,
            &key.key_identity(CUSTODY_X_WING_AES256GCM_SUITE_ID_V1)
                .unwrap(),
        )
        .unwrap())
    }

    async fn open_viewer_session_v2(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        let json = self.record("open_viewer_session_v2", request).await;
        let audit = RuntimeReleaseAuditIdV1::new(Digest32::new([0x91; 32])).unwrap();
        if self.0.open_unreachable.load(Ordering::SeqCst) {
            return Err(RuntimeProviderCallError::NotDispatched);
        }
        if let Some(code) = *self.0.open_failure.lock().unwrap() {
            return Ok(DecryptProviderResponseV1::new_failure(audit, code).unwrap());
        }
        Ok(DecryptProviderResponseV1::new_viewer_session_opened(
            audit,
            handle_of(&json, "prepared_recipient_handle"),
        )
        .unwrap())
    }

    async fn read_viewer_media_part_sealed(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        let json = self.record("read_viewer_media_part_sealed", request).await;
        Ok(sealed_answer(&json))
    }

    async fn read_viewer_object_chunk_sealed(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        let json = self
            .record("read_viewer_object_chunk_sealed", request)
            .await;
        Ok(sealed_answer(&json))
    }

    async fn cancel_prepared_recipient(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        let json = self.record("cancel_prepared_recipient", request).await;
        Ok(DecryptProviderResponseV1::new_cancelled_prepared_recipient(
            audit_of(&json),
            handle_of(&json, "prepared_recipient_handle"),
        )
        .unwrap())
    }

    async fn close_viewer_session(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        let json = self.record("close_viewer_session", request).await;
        Ok(DecryptProviderResponseV1::new_closed_viewer_session(
            audit_of(&json),
            handle_of(&json, "viewer_session_handle"),
        )
        .unwrap())
    }
}

/// What the fake decrypt provider "seals": a marker no ciphertext carries.
const SEALED_MARKER: &[u8] = b"sealed-to-the-delivery-key";

fn sealed_answer(request: &Value) -> DecryptProviderResponseV1 {
    DecryptProviderResponseV1::new_viewer_sealed_part(
        audit_of(request),
        handle_of(request, "viewer_session_handle"),
        SEALED_MARKER.to_vec(),
    )
    .unwrap()
}

struct ContentState {
    staged: Mutex<Vec<PoolSessionIdV1>>,
    discarded: Mutex<Vec<PoolSessionIdV1>>,
    parts: Mutex<Vec<ViewerPartIndexV1>>,
    /// Stage every item as an object, whatever its identity.
    wrong_kind: AtomicBool,
    part_bytes: AtomicU64,
    total_bytes: AtomicU64,
    gates: Gates,
}

#[derive(Clone)]
struct FakeContent(Arc<ContentState>);

impl Default for FakeContent {
    fn default() -> Self {
        Self(Arc::new(ContentState {
            staged: Mutex::default(),
            discarded: Mutex::default(),
            parts: Mutex::default(),
            wrong_kind: AtomicBool::new(false),
            part_bytes: AtomicU64::new(PART_BYTES),
            total_bytes: AtomicU64::new(STAGED_TOTAL_BYTES),
            gates: Gates::default(),
        }))
    }
}

/// The audit path the fake content port computes for a DASH segment.
fn fake_proof(rendition: u8, index: u32) -> Vec<Digest32> {
    vec![Digest32::new([0xd0 ^ rendition ^ index as u8; 32])]
}

#[async_trait::async_trait]
impl PoolSessionContentPort for FakeContent {
    async fn stage(
        &self,
        session_id: PoolSessionIdV1,
        content: &PoolSessionContentRefV1,
        _binding: &ProtectedContentBindingV1,
    ) -> Result<PoolStagedContentV1, PoolSessionRefusal> {
        self.0.gates.pass("stage").await;
        self.0.staged.lock().unwrap().push(session_id);
        let open = match (&content.identity, self.0.wrong_kind.load(Ordering::SeqCst)) {
            (_, true) | (PoolContentIdentityV1::Object(_), false) => PoolStagedOpenV1::Object {
                framed_header: vec![0x0f; 64],
            },
            (PoolContentIdentityV1::MediaV1(_), false) => PoolStagedOpenV1::MediaV1 {
                protected_init: vec![0x01; 32],
            },
            (PoolContentIdentityV1::DashV2(head), false) => PoolStagedOpenV1::DashV2 {
                protected_inits: head.renditions().iter().map(|_| vec![0x02; 32]).collect(),
            },
        };
        Ok(PoolStagedContentV1 {
            handle: session_id,
            total_ciphertext_bytes: self.0.total_bytes.load(Ordering::SeqCst),
            duration_secs: matches!(content.identity, PoolContentIdentityV1::DashV2(_))
                .then_some(20),
            open,
        })
    }

    async fn part(
        &self,
        _staged: &PoolStagedContentV1,
        part: &ViewerPartIndexV1,
    ) -> Result<PoolStagedPartV1, PoolSessionRefusal> {
        self.0.gates.pass("part").await;
        self.0.parts.lock().unwrap().push(*part);
        let bytes = vec![0xc1; self.0.part_bytes.load(Ordering::SeqCst) as usize];
        Ok(match *part {
            ViewerPartIndexV1::MediaV1Init => PoolStagedPartV1::MediaV1Init,
            ViewerPartIndexV1::MediaV1Segment(index) => PoolStagedPartV1::MediaV1Segment {
                index,
                encrypted: bytes,
            },
            ViewerPartIndexV1::DashInit { rendition } => PoolStagedPartV1::DashInit { rendition },
            ViewerPartIndexV1::DashSegment { rendition, index } => PoolStagedPartV1::DashSegment {
                rendition,
                index,
                encrypted: bytes,
                proof: fake_proof(rendition, index),
            },
            ViewerPartIndexV1::ObjectChunk(index) => PoolStagedPartV1::ObjectChunk {
                index,
                framed_chunk: bytes,
            },
        })
    }

    fn discard(&self, session_id: PoolSessionIdV1) {
        self.0.discarded.lock().unwrap().push(session_id);
    }
}

impl FakeContent {
    fn staged(&self) -> usize {
        self.0.staged.lock().unwrap().len()
    }

    fn discarded(&self) -> Vec<PoolSessionIdV1> {
        self.0.discarded.lock().unwrap().clone()
    }
}

#[derive(Clone, Default)]
struct FakeAttest(Arc<Mutex<Vec<PoolRecipientAttestationStatementV2>>>);

#[async_trait::async_trait]
impl PoolSessionAttestPort for FakeAttest {
    async fn attest_recipient(
        &self,
        statement: &PoolRecipientAttestationStatementV2,
    ) -> Result<SignedPoolRecipientAttestationV2, PoolSessionRefusal> {
        self.0.lock().unwrap().push(statement.clone());
        Ok(SignedPoolRecipientAttestationV2::new(
            statement.clone(),
            signing_key(SERVER_NODE)
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap())
    }
}

struct FakePolicy {
    descriptor: VerifiedPoolDescriptorV1,
    own_node: NodePublicKey,
    own_issuer: RuntimeOperationIssuerKeyV1,
    ready: Arc<AtomicBool>,
    /// #388 A1: the host's captured trust setting (true: `wci_operated`).
    host_trusted: Arc<AtomicBool>,
}

impl PoolSessionPolicyPort for FakePolicy {
    fn descriptor(&self, pool: &PoolDidV1) -> Option<VerifiedPoolDescriptorV1> {
        (self.descriptor.pool() == pool).then(|| self.descriptor.clone())
    }

    fn own_node_key(&self, _pool: &PoolDidV1) -> Option<NodePublicKey> {
        Some(self.own_node)
    }

    fn own_endpoint_did(&self) -> &str {
        OWN_ENDPOINT
    }

    fn own_runtime_issuer(&self) -> RuntimeOperationIssuerKeyV1 {
        self.own_issuer
    }

    fn decrypt_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    fn host_trusted(&self) -> bool {
        self.host_trusted.load(Ordering::SeqCst)
    }
}

fn descriptor(serve: ServePolicyV1, non_serving_node: Option<u8>) -> VerifiedPoolDescriptorV1 {
    pool_descriptor_with(
        &pool_bundle(xwing, NOW),
        1,
        serve,
        non_serving_node,
        runtime_issuer(BUYER_RUNTIME_SEED),
        NOW,
    )
    .verify(NOW)
    .unwrap()
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type Server = PoolSessionServer<FakePolicy, FakeDecrypt, FakeContent, FakeAttest>;

struct Harness {
    server: Arc<Server>,
    decrypt: FakeDecrypt,
    content: FakeContent,
    attest: FakeAttest,
    decrypt_ready: Arc<AtomicBool>,
    host_trusted: Arc<AtomicBool>,
}

fn harness_with(serve: ServePolicyV1, non_serving_node: Option<u8>, node_budget: usize) -> Harness {
    harness_for(descriptor(serve, non_serving_node), node_budget)
}

/// #388 A2: a server whose pool has the given verified descriptor.
fn harness_for(descriptor: VerifiedPoolDescriptorV1, node_budget: usize) -> Harness {
    let decrypt = FakeDecrypt::default();
    let content = FakeContent::default();
    let attest = FakeAttest::default();
    let decrypt_ready = Arc::new(AtomicBool::new(true));
    let host_trusted = Arc::new(AtomicBool::new(true));
    let policy = FakePolicy {
        descriptor,
        own_node: node_public_key(SERVER_NODE),
        own_issuer: runtime_issuer(OWN_ISSUER_SEED),
        ready: decrypt_ready.clone(),
        host_trusted: host_trusted.clone(),
    };
    let mut next = 0u8;
    let server = PoolSessionServer::new(policy, decrypt.clone(), content.clone(), attest.clone())
        .with_session_ids(Box::new(move || {
            next = next.wrapping_add(1);
            [next; 16]
        }))
        .with_node_budget(node_budget);
    Harness {
        server: Arc::new(server),
        decrypt,
        content,
        attest,
        decrypt_ready,
        host_trusted,
    }
}

fn harness() -> Harness {
    harness_with(ServePolicyV1::DEFAULT, None, 64)
}

/// One item of `kind`: its identity, and a wallet (by seed) that buys it.
#[derive(Clone)]
struct Item {
    identity: PoolContentIdentityV1,
    wallet_seed: u8,
}

fn item(kind: PoolSessionContentKindV1, seed: u8) -> Item {
    let identity = match kind {
        PoolSessionContentKindV1::MediaV1 => {
            PoolContentIdentityV1::MediaV1(crate::test_media::media_identity(seed))
        }
        PoolSessionContentKindV1::DashV2 => {
            PoolContentIdentityV1::DashV2(crate::test_media::media_dash_identity(
                seed,
                &[
                    CencDashRenditionKindV2::Video,
                    CencDashRenditionKindV2::Audio,
                ],
            ))
        }
        PoolSessionContentKindV1::Object => {
            PoolContentIdentityV1::Object(crate::test_object::object_identity(seed))
        }
    };
    Item {
        identity,
        wallet_seed: 7,
    }
}

fn policy_body(encrypted_content: &EncryptedContentIdentityV1) -> RightsPolicyBodyV1 {
    RightsPolicyBodyV1::new(
        encrypted_content.clone(),
        ContentAccessIdV1::new([0x44; 16]).unwrap(),
        RightsActionV1::View,
        RightsSubjectSourceV1::WalletAddress,
        11155111,
        EvmContractAddressV1::new([0x11; 20]).unwrap(),
        EvmFunctionSelectorV1::new([0x12, 0x34, 0x56, 0x78]).unwrap(),
        EvmRightsMethodAbiV1::HasAccessByContentIdAddressBytes16,
        RightsObservationFinalityV1::finalized(),
    )
    .unwrap()
}

impl Item {
    /// The release spec, built at `now`, naming `recipient` when given.
    fn spec(&self, recipient: Option<RecipientPublicKeyBytesV1>, now: u64) -> PoolReleaseSpecV1 {
        let mut spec =
            PoolReleaseSpecV1::new(xwing, policy_body(self.identity.encrypted_content()), now);
        spec.recipients = vec![(0x09, SERVER_NODE)];
        spec.recipient_public_keys = recipient.map(|key| vec![key]);
        spec.delivery_key = Some(delivery_public_key(DELIVERY_SEED).identity());
        spec.wallet_seed = self.wallet_seed;
        // One committee for every build time, so the binding is the same
        // whenever the release is made.
        spec.member_window = Some((NOW - 10, NOW + 86_400));
        spec.key_envelope = Some(key_envelope_for(
            &pool_bundle(xwing, NOW),
            self.identity.encrypted_content(),
        ));
        spec
    }

    fn binding(&self) -> ProtectedContentBindingV1 {
        pool_release_fixture(&self.spec(None, NOW)).binding
    }

    fn content_ref(&self) -> PoolSessionContentRefV1 {
        PoolSessionContentRefV1 {
            cid: "bafy-test-item".into(),
            kind: self.identity.kind(),
            identity: self.identity.clone(),
            content_key_commitment: Digest32::new([0xcc; 32]),
        }
    }

    fn prepare(&self, issuer_seed: u8) -> PoolSessionPrepareV1 {
        PoolSessionPrepareV1 {
            pool: pool_did(),
            binding: self.binding(),
            action: RightsActionV1::View,
            runtime_operation_issuer: runtime_issuer(issuer_seed),
            content: self.content_ref(),
            expires_at: PREPARE_EXPIRES_AT,
        }
    }
}

/// Structurally valid contributions and receipt for `recipient` (the fake
/// decrypt provider does not open them).
pub(crate) fn release_for(
    fixture: &PoolReleaseFixtureV1,
) -> (Vec<SignedNodeContributionV1>, SignedTerminalReceiptV1) {
    let operation = fixture
        .operation
        .verify(RuntimeIssuerPolicyV1::Declared, fixture.now + 3)
        .unwrap();
    let recipient = operation
        .statement()
        .rights_request()
        .request()
        .recipients()[0]
        .clone();
    let now = fixture.now;
    let contributions = [1u8, 2]
        .into_iter()
        .map(|node| {
            let statement = NodeContributionStatementV1::new(
                operation.operation_hash(),
                operation.binding().clone(),
                signed_node_rights_decision(&operation, node, RightsDecisionV1::Allowed, now),
                RecipientSealedContributionV1::new(recipient.clone(), vec![node; 96]).unwrap(),
                now + 5,
                now + 30,
            )
            .unwrap();
            SignedNodeContributionV1::new(
                statement.clone(),
                signing_key(node)
                    .sign(&statement.canonical_bytes().unwrap())
                    .to_bytes()
                    .to_vec(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let node_set = fixture.node_set();
    let refs = contributions
        .iter()
        .map(|contribution| {
            NodeContributionRefV1::from(
                &operation
                    .verify_node_contribution(contribution, &node_set, &recipient, now + 6)
                    .unwrap(),
            )
        })
        .collect();
    let key = signing_key(BUYER_RUNTIME_SEED);
    let statement = TerminalReceiptStatementV1::new(
        operation.operation_hash(),
        operation.binding().clone(),
        TerminalReceiptIssuerKey::new(key.verifying_key().to_bytes()).unwrap(),
        KeyReleaseOutcomeV1::Released,
        refs,
        now + 5,
        now + 30,
    )
    .unwrap();
    let receipt = SignedTerminalReceiptV1::new(
        statement.clone(),
        key.sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    (contributions, receipt)
}

/// The buyer's open for a prepared session, with a release built at `now`.
fn open_request_at(
    item: &Item,
    prepared: &PoolSessionPreparedV1,
    now: u64,
) -> (PoolSessionOpenV1, PoolReleaseFixtureV1) {
    let fixture = pool_release_fixture(&item.spec(Some(prepared.recipient_public_key), now));
    let (contributions, receipt) = release_for(&fixture);
    (
        PoolSessionOpenV1 {
            session_id: prepared.session_id,
            operation: fixture.operation.clone(),
            delivery_public_key: delivery_public_key(DELIVERY_SEED),
            contributions,
            terminal_receipt: receipt,
        },
        fixture,
    )
}

fn open_request(item: &Item, prepared: &PoolSessionPreparedV1) -> PoolSessionOpenV1 {
    open_request_at(item, prepared, NOW).0
}

impl Harness {
    async fn prepared(&self, item: &Item, from: &PoolSessionSource) -> PoolSessionPreparedV1 {
        self.server
            .prepare(item.prepare(BUYER_RUNTIME_SEED), from, PREPARE_AT)
            .await
            .unwrap()
    }

    async fn opened(&self, item: &Item, from: &PoolSessionSource) -> PoolSessionPreparedV1 {
        let prepared = self.prepared(item, from).await;
        self.server
            .open(open_request(item, &prepared), from, OPEN_AT)
            .await
            .unwrap();
        prepared
    }

    async fn read(
        &self,
        session_id: PoolSessionIdV1,
        part: ViewerPartIndexV1,
        from: &PoolSessionSource,
        now: u64,
    ) -> Result<Vec<u8>, PoolSessionRefusal> {
        self.server
            .read(PoolSessionReadV1 { session_id, part }, from, now)
            .await
    }
}

// ---------------------------------------------------------------------------
// Prepare
// ---------------------------------------------------------------------------

#[tokio::test]
async fn prepare_attests_recipient_made_in_the_decrypt_port() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.prepared(&item, &source(1)).await;
    // The recipient is the decrypt port's, and the attestation names it.
    assert_eq!(h.decrypt.calls("prepare_recipient_v2").len(), 1);
    assert_eq!(
        prepared.recipient_public_key,
        RecipientPublicKeyBytesV1::new(xwing(0x11)).unwrap()
    );
    let statement = prepared.attestation.statement();
    assert_eq!(
        statement.recipient_public_key(),
        prepared.recipient_public_key
    );
    assert_eq!(
        statement.server_node_public_key(),
        node_public_key(SERVER_NODE)
    );
    assert_eq!(
        statement.runtime_operation_issuer(),
        runtime_issuer(BUYER_RUNTIME_SEED)
    );
    assert_eq!(statement.binding(), &item.binding());
    // #388-2: the vouch binds the pool's trust mode, evidence empty.
    assert_eq!(statement.trust_mode(), PoolTrustModeV1::WciOperated);
    assert!(statement.evidence().is_empty());
    assert_eq!(h.attest.0.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn guard_prepare_from_own_endpoint_is_refused_self_serve() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let own = PoolSessionSource {
        endpoint_did: OWN_ENDPOINT.into(),
        local: false,
    };
    let local = PoolSessionSource {
        endpoint_did: "runtime-local".into(),
        local: true,
    };
    for from in [own, local] {
        assert_eq!(
            h.server
                .prepare(item.prepare(BUYER_RUNTIME_SEED), &from, PREPARE_AT)
                .await,
            Err(PoolSessionRefusal::SelfServe)
        );
    }
    assert_eq!(h.decrypt.total_calls(), 0);
}

#[tokio::test]
async fn guard_prepare_with_own_runtime_issuer_is_refused_self_serve() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    assert_eq!(
        h.server
            .prepare(item.prepare(OWN_ISSUER_SEED), &source(1), PREPARE_AT)
            .await,
        Err(PoolSessionRefusal::SelfServe)
    );
    assert_eq!(PoolSessionRefusal::SelfServe.code(), "self_serve_refused");
}

#[tokio::test]
async fn development_pool_allows_self_serve() {
    let h = harness_with(
        ServePolicyV1 {
            allow_self_serve: true,
            ..ServePolicyV1::DEFAULT
        },
        None,
        64,
    );
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let own = PoolSessionSource {
        endpoint_did: OWN_ENDPOINT.into(),
        local: false,
    };
    h.server
        .prepare(item.prepare(OWN_ISSUER_SEED), &own, PREPARE_AT)
        .await
        .unwrap();
}

#[tokio::test]
async fn guard_prepare_refuses_non_serve_member() {
    let h = harness_with(ServePolicyV1::DEFAULT, Some(SERVER_NODE), 64);
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    assert_eq!(
        h.server
            .prepare(item.prepare(BUYER_RUNTIME_SEED), &source(1), PREPARE_AT)
            .await,
        Err(PoolSessionRefusal::NotEligible)
    );
    assert_eq!(h.decrypt.total_calls(), 0);
}

#[tokio::test]
async fn guard_prepare_without_a_ready_decrypt_provider_is_not_ready() {
    let h = harness();
    h.decrypt_ready.store(false, Ordering::SeqCst);
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    assert_eq!(
        h.server
            .prepare(item.prepare(BUYER_RUNTIME_SEED), &source(1), PREPARE_AT)
            .await,
        Err(PoolSessionRefusal::NotReady)
    );
}

#[tokio::test]
async fn prepared_recipient_lives_through_approval_window() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.prepared(&item, &source(1)).await;
    // The buyer's wallet approval takes minutes; the release is made then.
    let late = NOW + 160;
    let (open, _) = open_request_at(&item, &prepared, late);
    h.server.open(open, &source(1), late + 5).await.unwrap();

    // A prepared recipient past its own expiry answers `Expired`.
    let other = h.prepared(&item, &source(2)).await;
    let (open, _) = open_request_at(&item, &other, PREPARE_EXPIRES_AT - 5);
    assert_eq!(
        h.server.open(open, &source(2), PREPARE_EXPIRES_AT).await,
        Err(PoolSessionRefusal::Expired)
    );
}

// ---------------------------------------------------------------------------
// Open and read
// ---------------------------------------------------------------------------

#[tokio::test]
async fn open_then_read_returns_sealed_bytes_only() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.opened(&item, &source(1)).await;
    let sealed = h
        .read(
            prepared.session_id,
            ViewerPartIndexV1::ObjectChunk(0),
            &source(1),
            READ_AT,
        )
        .await
        .unwrap();
    assert_eq!(sealed, SEALED_MARKER);
    // The decrypt read named this pool session; the ciphertext never left.
    let reads = h.decrypt.calls("read_viewer_object_chunk_sealed");
    assert_eq!(reads.len(), 1);
    assert_eq!(
        serde_json::from_value::<[u8; 16]>(reads[0]["session_id"].clone()).unwrap(),
        prepared.session_id
    );
}

#[tokio::test]
async fn guard_read_from_another_endpoint_is_unknown_session() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.opened(&item, &source(1)).await;
    assert_eq!(
        h.read(
            prepared.session_id,
            ViewerPartIndexV1::ObjectChunk(0),
            &source(2),
            READ_AT
        )
        .await,
        Err(PoolSessionRefusal::UnknownSession)
    );
    assert_eq!(
        h.server.close(prepared.session_id, &source(2)).await,
        Err(PoolSessionRefusal::UnknownSession)
    );
}

#[tokio::test]
async fn guard_read_ahead_past_window_is_refused() {
    let h = harness();
    h.content.0.part_bytes.store(1, Ordering::SeqCst);
    let item = item(PoolSessionContentKindV1::DashV2, 0x31);
    let prepared = h.opened(&item, &source(1)).await;
    let read_ahead = u32::from(ServePolicyV1::DEFAULT.bounds.read_ahead_segments);
    let segment = |index| ViewerPartIndexV1::DashSegment {
        rendition: 0,
        index,
    };
    h.read(prepared.session_id, segment(0), &source(1), READ_AT)
        .await
        .unwrap();
    assert_eq!(
        h.read(
            prepared.session_id,
            segment(read_ahead + 1),
            &source(1),
            READ_AT
        )
        .await,
        Err(PoolSessionRefusal::Bound("read_ahead"))
    );
    h.read(
        prepared.session_id,
        segment(read_ahead),
        &source(1),
        READ_AT,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn guard_total_bytes_bound_is_refused() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.opened(&item, &source(1)).await;
    let allowed = u64::from(ServePolicyV1::DEFAULT.bounds.total_bytes_multiplier)
        * STAGED_TOTAL_BYTES
        / PART_BYTES;
    for index in 0..allowed {
        h.read(
            prepared.session_id,
            ViewerPartIndexV1::ObjectChunk(index as u32),
            &source(1),
            READ_AT,
        )
        .await
        .unwrap();
    }
    let refused = h
        .read(
            prepared.session_id,
            ViewerPartIndexV1::ObjectChunk(allowed as u32),
            &source(1),
            READ_AT,
        )
        .await;
    assert_eq!(refused, Err(PoolSessionRefusal::Bound("total_bytes")));
    assert_eq!(refused.unwrap_err().code(), "session_bound_exceeded");
}

#[tokio::test]
async fn guard_third_session_same_wallet_kid_is_refused() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let bound = ServePolicyV1::DEFAULT.bounds.max_sessions_per_wallet_kid;
    for n in 0..bound {
        h.opened(&item, &source(n + 1)).await;
    }
    let third = h.prepared(&item, &source(bound + 1)).await;
    assert_eq!(
        h.server
            .open(open_request(&item, &third), &source(bound + 1), OPEN_AT)
            .await,
        Err(PoolSessionRefusal::Bound("sessions_per_wallet_kid"))
    );
}

#[tokio::test]
async fn full_node_budget_answers_pool_busy() {
    let h = harness_with(ServePolicyV1::DEFAULT, None, 2);
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    h.prepared(&item, &source(1)).await;
    h.prepared(&item, &source(2)).await;
    let refused = h
        .server
        .prepare(item.prepare(BUYER_RUNTIME_SEED), &source(3), PREPARE_AT)
        .await;
    assert_eq!(refused, Err(PoolSessionRefusal::PoolBusy));
    assert_eq!(refused.unwrap_err().code(), "pool_busy");
}

#[tokio::test]
async fn decrypt_refusal_answers_decrypt_unavailable() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.prepared(&item, &source(1)).await;
    // L11: the decrypt provider's capacity refusal, and an unreachable one.
    *h.decrypt.0.open_failure.lock().unwrap() = Some(ProviderFailureCodeV1::BackendUnavailable);
    assert_eq!(
        h.server
            .open(open_request(&item, &prepared), &source(1), OPEN_AT)
            .await,
        Err(PoolSessionRefusal::DecryptUnavailable)
    );
    *h.decrypt.0.open_failure.lock().unwrap() = None;
    h.decrypt.0.open_unreachable.store(true, Ordering::SeqCst);
    let refused = h
        .server
        .open(open_request(&item, &prepared), &source(1), OPEN_AT)
        .await;
    assert_eq!(refused, Err(PoolSessionRefusal::DecryptUnavailable));
    assert_eq!(refused.unwrap_err().code(), "decrypt_unavailable");
}

#[tokio::test]
async fn close_discards_staged_content_and_decrypt_session() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.opened(&item, &source(1)).await;
    h.server
        .close(prepared.session_id, &source(1))
        .await
        .unwrap();
    assert_eq!(h.decrypt.calls("close_viewer_session").len(), 1);
    assert_eq!(h.content.discarded(), vec![prepared.session_id]);
    assert_eq!(
        h.read(
            prepared.session_id,
            ViewerPartIndexV1::ObjectChunk(0),
            &source(1),
            READ_AT
        )
        .await,
        Err(PoolSessionRefusal::UnknownSession)
    );
    // A prepared, unopened session cancels its recipient.
    let other = h.prepared(&item, &source(1)).await;
    h.server.close(other.session_id, &source(1)).await.unwrap();
    assert_eq!(h.decrypt.calls("cancel_prepared_recipient").len(), 1);
}

// ---------------------------------------------------------------------------
// F3: the delivery key
// ---------------------------------------------------------------------------

#[tokio::test]
async fn guard_open_with_a_delivery_key_not_named_by_the_operation_is_refused_before_any_port_call()
{
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.prepared(&item, &source(1)).await;
    let calls = h.decrypt.total_calls();
    let mut open = open_request(&item, &prepared);
    open.delivery_public_key = delivery_public_key(DELIVERY_SEED + 1);
    assert_eq!(
        h.server.open(open, &source(1), OPEN_AT).await,
        Err(PoolSessionRefusal::BindingMismatch)
    );
    assert_eq!(h.decrypt.total_calls(), calls);
    assert_eq!(h.content.staged(), 0);
    // Nothing was stored: the right key still opens.
    h.server
        .open(open_request(&item, &prepared), &source(1), OPEN_AT)
        .await
        .unwrap();
}

#[tokio::test]
async fn open_passes_the_delivery_public_key_to_the_decrypt_open() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    h.opened(&item, &source(1)).await;
    let opens = h.decrypt.calls("open_viewer_session_v2");
    assert_eq!(opens.len(), 1);
    assert_eq!(
        serde_json::from_value::<Vec<u8>>(opens[0]["delivery_public_key"].clone()).unwrap(),
        delivery_public_key(DELIVERY_SEED).as_bytes().to_vec()
    );
}

// ---------------------------------------------------------------------------
// F4: the typed content contract
// ---------------------------------------------------------------------------

#[tokio::test]
async fn guard_prepare_with_an_identity_of_other_content_is_refused_before_any_port_call() {
    let h = harness();
    let bought = item(PoolSessionContentKindV1::Object, 0x21);
    let mut prepare = bought.prepare(BUYER_RUNTIME_SEED);
    prepare.content = item(PoolSessionContentKindV1::Object, 0x22).content_ref();
    assert_eq!(
        h.server.prepare(prepare, &source(1), PREPARE_AT).await,
        Err(PoolSessionRefusal::BindingMismatch)
    );
    assert_eq!(h.decrypt.total_calls(), 0);
    assert!(h.attest.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn guard_prepare_with_an_identity_of_another_kind_is_refused() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let mut prepare = item.prepare(BUYER_RUNTIME_SEED);
    prepare.content.kind = PoolSessionContentKindV1::DashV2;
    assert_eq!(
        h.server.prepare(prepare, &source(1), PREPARE_AT).await,
        Err(PoolSessionRefusal::BindingMismatch)
    );
    assert_eq!(h.decrypt.total_calls(), 0);
}

#[tokio::test]
async fn guard_open_with_a_binding_other_than_the_prepared_one_is_refused() {
    let h = harness();
    let item_a = item(PoolSessionContentKindV1::Object, 0x21);
    let mut item_b = item_a.clone();
    // Another wallet's release of the same item.
    item_b.wallet_seed = 8;
    let prepared = h.prepared(&item_a, &source(1)).await;
    assert_eq!(
        h.server
            .open(open_request(&item_b, &prepared), &source(1), OPEN_AT)
            .await,
        Err(PoolSessionRefusal::BindingMismatch)
    );
    assert_eq!(h.content.staged(), 0);
}

#[tokio::test]
async fn guard_staged_material_of_another_kind_is_refused_before_the_decrypt_open() {
    let h = harness();
    h.content.0.wrong_kind.store(true, Ordering::SeqCst);
    let item = item(PoolSessionContentKindV1::DashV2, 0x31);
    let prepared = h.prepared(&item, &source(1)).await;
    assert_eq!(
        h.server
            .open(open_request(&item, &prepared), &source(1), OPEN_AT)
            .await,
        Err(PoolSessionRefusal::ContentUnavailable)
    );
    assert!(h.decrypt.calls("open_viewer_session_v2").is_empty());
    assert_eq!(h.content.discarded(), vec![prepared.session_id]);
}

#[tokio::test]
async fn dash_read_passes_the_staged_proof_to_the_decrypt_read() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::DashV2, 0x31);
    let prepared = h.opened(&item, &source(1)).await;
    h.read(
        prepared.session_id,
        ViewerPartIndexV1::DashSegment {
            rendition: 1,
            index: 1,
        },
        &source(1),
        READ_AT,
    )
    .await
    .unwrap();
    let reads = h.decrypt.calls("read_viewer_media_part_sealed");
    let selector = &reads[0]["part_selector"];
    assert_eq!(selector["rendition_index"], 1);
    assert_eq!(selector["segment_index"], 1);
    assert_eq!(
        serde_json::from_value::<Vec<[u8; 32]>>(selector["segment_proof"].clone()).unwrap(),
        fake_proof(1, 1)
            .iter()
            .map(|node| *node.as_bytes())
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// F6: the session ends with the operation
// ---------------------------------------------------------------------------

/// Plan B S4 session lifetime (user 2026-11-13 04:45): the session lives to
/// the signed rights expiry, capped by the earliest attestation expiry. A
/// read after the operation's own expiry still answers; the session ends,
/// and is purged, exactly at its end.
#[tokio::test]
async fn session_lives_to_rights_expiry_capped_by_attestation() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.prepared(&item, &source(1)).await;
    let (open, fixture) = open_request_at(&item, &prepared, NOW);
    let operation_expires_at = fixture.operation.statement().expires_at();
    let session_end = fixture.authenticated().session_expires_at();
    assert_eq!(
        session_end,
        fixture
            .operation
            .statement()
            .rights_request()
            .request()
            .expires_at()
    );
    assert!(session_end > operation_expires_at);
    let opened = h.server.open(open, &source(1), OPEN_AT).await.unwrap();
    assert_eq!(opened.expires_at, session_end);
    // A read after the operation expired, while the rights are valid.
    h.read(
        prepared.session_id,
        ViewerPartIndexV1::ObjectChunk(0),
        &source(1),
        operation_expires_at + 1,
    )
    .await
    .unwrap();
    h.read(
        prepared.session_id,
        ViewerPartIndexV1::ObjectChunk(1),
        &source(1),
        session_end - 1,
    )
    .await
    .unwrap();
    assert!(h.decrypt.calls("close_viewer_session").is_empty());
    // Exactly at its end: expired, and purged with its decrypt session.
    let late = h
        .read(
            prepared.session_id,
            ViewerPartIndexV1::ObjectChunk(2),
            &source(1),
            session_end,
        )
        .await;
    assert_eq!(late, Err(PoolSessionRefusal::Expired));
    assert_eq!(late.unwrap_err().code(), "session_expired");
    assert_eq!(h.decrypt.calls("close_viewer_session").len(), 1);
    assert_eq!(h.content.discarded(), vec![prepared.session_id]);
}

/// Rights that outlive the attestations end with the earliest attestation.
#[tokio::test]
async fn session_end_is_capped_by_the_attestation_expiry() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.prepared(&item, &source(1)).await;
    let mut spec = item.spec(Some(prepared.recipient_public_key), NOW);
    spec.rights_expires_at = Some(NOW + 250);
    let fixture = pool_release_fixture(&spec);
    let (contributions, receipt) = release_for(&fixture);
    let session_end = fixture.authenticated().session_expires_at();
    assert_eq!(session_end, NOW + 200);
    let opened = h
        .server
        .open(
            PoolSessionOpenV1 {
                session_id: prepared.session_id,
                operation: fixture.operation.clone(),
                delivery_public_key: delivery_public_key(DELIVERY_SEED),
                contributions,
                terminal_receipt: receipt,
            },
            &source(1),
            OPEN_AT,
        )
        .await
        .unwrap();
    assert_eq!(opened.expires_at, session_end);
}

/// Admission needs a fresh release: an open after the operation expired is
/// refused, even while the signed rights are still valid.
#[tokio::test]
async fn open_with_expired_proofs_is_refused() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.prepared(&item, &source(1)).await;
    let (open, fixture) = open_request_at(&item, &prepared, NOW);
    let operation_expires_at = fixture.operation.statement().expires_at();
    assert!(fixture.authenticated().session_expires_at() > operation_expires_at);
    assert_eq!(
        h.server.open(open, &source(1), operation_expires_at).await,
        Err(PoolSessionRefusal::BindingMismatch)
    );
    assert!(h.decrypt.calls("open_viewer_session_v2").is_empty());
}

// ---------------------------------------------------------------------------
// F7: state and concurrency
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parallel_prepares_admit_exactly_the_node_budget() {
    let h = harness_with(ServePolicyV1::DEFAULT, None, 3);
    let gate = h.decrypt.0.gates.close("prepare_recipient_v2");
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let tasks = (1..=5u8)
        .map(|n| {
            let server = h.server.clone();
            let prepare = item.prepare(BUYER_RUNTIME_SEED);
            tokio::spawn(async move { server.prepare(prepare, &source(n), PREPARE_AT).await })
        })
        .collect::<Vec<_>>();
    settle().await;
    gate.add_permits(5);
    let mut admitted = 0;
    let mut busy = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => admitted += 1,
            Err(PoolSessionRefusal::PoolBusy) => busy += 1,
            Err(other) => panic!("{other:?}"),
        }
    }
    assert_eq!((admitted, busy), (3, 2));
    assert_eq!(h.decrypt.calls("prepare_recipient_v2").len(), 3);
}

#[tokio::test]
async fn parallel_opens_admit_exactly_the_wallet_kid_count() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let mut prepared = Vec::new();
    for n in 1..=3u8 {
        prepared.push((n, h.prepared(&item, &source(n)).await));
    }
    let gate = h.content.0.gates.close("stage");
    let tasks = prepared
        .iter()
        .map(|(n, prepared)| {
            let server = h.server.clone();
            let open = open_request(&item, prepared);
            let n = *n;
            tokio::spawn(async move { server.open(open, &source(n), OPEN_AT).await })
        })
        .collect::<Vec<_>>();
    settle().await;
    gate.add_permits(3);
    let results = futures_results(tasks).await;
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 2);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(PoolSessionRefusal::Bound("sessions_per_wallet_kid")))
            .count(),
        1
    );
}

async fn futures_results<T>(tasks: Vec<tokio::task::JoinHandle<T>>) -> Vec<T> {
    let mut out = Vec::new();
    for task in tasks {
        out.push(task.await.unwrap());
    }
    out
}

#[tokio::test]
async fn sessions_per_wallet_and_per_endpoint_are_bounded() {
    let bounds = ServePolicyV1::DEFAULT.bounds;
    // One wallet from many endpoints.
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    for n in 0..bounds.max_sessions_per_wallet {
        h.prepared(&item, &source(n + 1)).await;
    }
    assert_eq!(
        h.server
            .prepare(item.prepare(BUYER_RUNTIME_SEED), &source(0xf0), PREPARE_AT)
            .await,
        Err(PoolSessionRefusal::Bound("sessions_per_wallet"))
    );
    // Many wallets from one endpoint.
    let h = harness();
    for n in 0..bounds.max_sessions_per_endpoint {
        let mut wallet_item = item.clone();
        wallet_item.wallet_seed = 0x20 + n;
        h.prepared(&wallet_item, &source(1)).await;
    }
    let mut extra = item.clone();
    extra.wallet_seed = 0x70;
    assert_eq!(
        h.server
            .prepare(extra.prepare(BUYER_RUNTIME_SEED), &source(1), PREPARE_AT)
            .await,
        Err(PoolSessionRefusal::Bound("sessions_per_endpoint"))
    );
}

#[tokio::test]
async fn parallel_reads_never_exceed_the_total_bytes_budget() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.opened(&item, &source(1)).await;
    let gate = h.decrypt.0.gates.close("read_viewer_object_chunk_sealed");
    let allowed = u64::from(ServePolicyV1::DEFAULT.bounds.total_bytes_multiplier)
        * STAGED_TOTAL_BYTES
        / PART_BYTES;
    let tasks = (0..allowed + 3)
        .map(|index| {
            let server = h.server.clone();
            let session_id = prepared.session_id;
            tokio::spawn(async move {
                server
                    .read(
                        PoolSessionReadV1 {
                            session_id,
                            part: ViewerPartIndexV1::ObjectChunk(index as u32),
                        },
                        &source(1),
                        READ_AT,
                    )
                    .await
            })
        })
        .collect::<Vec<_>>();
    settle().await;
    gate.add_permits(tasks.len());
    let results = futures_results(tasks).await;
    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count() as u64,
        allowed
    );
    assert!(results
        .iter()
        .filter(|result| result.is_err())
        .all(|result| *result == Err(PoolSessionRefusal::Bound("total_bytes"))));
}

#[tokio::test]
async fn expired_session_is_swept_and_frees_its_slot() {
    let h = harness_with(ServePolicyV1::DEFAULT, None, 1);
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let first = h.prepared(&item, &source(1)).await;
    assert_eq!(
        h.server
            .prepare(item.prepare(BUYER_RUNTIME_SEED), &source(2), PREPARE_AT)
            .await,
        Err(PoolSessionRefusal::PoolBusy)
    );
    // Past the first prepare's expiry, the next call sweeps it.
    let mut later = item.prepare(BUYER_RUNTIME_SEED);
    later.expires_at = PREPARE_EXPIRES_AT + 100;
    h.server
        .prepare(later, &source(2), PREPARE_EXPIRES_AT)
        .await
        .unwrap();
    assert_eq!(h.decrypt.calls("cancel_prepared_recipient").len(), 1);
    assert_eq!(
        h.server.close(first.session_id, &source(1)).await,
        Err(PoolSessionRefusal::UnknownSession)
    );
}

#[tokio::test]
async fn close_during_open_cleans_up_the_late_result() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.prepared(&item, &source(1)).await;
    let gate = h.decrypt.0.gates.close("open_viewer_session_v2");
    let server = h.server.clone();
    let open = open_request(&item, &prepared);
    let task = tokio::spawn(async move { server.open(open, &source(1), OPEN_AT).await });
    settle().await;
    h.server
        .close(prepared.session_id, &source(1))
        .await
        .unwrap();
    gate.add_permits(1);
    assert_eq!(task.await.unwrap(), Err(PoolSessionRefusal::UnknownSession));
    // The open call closed the session it opened and discarded its stage.
    assert_eq!(h.decrypt.calls("close_viewer_session").len(), 1);
    assert_eq!(h.content.discarded(), vec![prepared.session_id]);
}

#[tokio::test]
async fn cancelled_prepare_releases_its_reservation() {
    let h = harness_with(ServePolicyV1::DEFAULT, None, 1);
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let gate = h.decrypt.0.gates.close("prepare_recipient_v2");
    let cancelled = tokio::time::timeout(
        Duration::from_millis(50),
        h.server
            .prepare(item.prepare(BUYER_RUNTIME_SEED), &source(1), PREPARE_AT),
    )
    .await;
    assert!(cancelled.is_err(), "the prepare was held at its gate");
    gate.add_permits(10);
    // The dropped call left its entry abandoned; the next call sweeps it.
    h.prepared(&item, &source(2)).await;
}

#[tokio::test]
async fn cancelled_read_releases_its_bytes() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.opened(&item, &source(1)).await;
    let gate = h.decrypt.0.gates.close("read_viewer_object_chunk_sealed");
    let cancelled = tokio::time::timeout(
        Duration::from_millis(50),
        h.read(
            prepared.session_id,
            ViewerPartIndexV1::ObjectChunk(0),
            &source(1),
            READ_AT,
        ),
    )
    .await;
    assert!(cancelled.is_err(), "the read was held at its gate");
    gate.add_permits(64);
    // The whole budget is still there.
    let allowed = u64::from(ServePolicyV1::DEFAULT.bounds.total_bytes_multiplier)
        * STAGED_TOTAL_BYTES
        / PART_BYTES;
    for index in 0..allowed {
        h.read(
            prepared.session_id,
            ViewerPartIndexV1::ObjectChunk(index as u32),
            &source(1),
            READ_AT,
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn failed_open_rolls_back_to_prepared() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.prepared(&item, &source(1)).await;
    *h.decrypt.0.open_failure.lock().unwrap() = Some(ProviderFailureCodeV1::BindingMismatch);
    assert_eq!(
        h.server
            .open(open_request(&item, &prepared), &source(1), OPEN_AT)
            .await,
        Err(PoolSessionRefusal::BindingMismatch)
    );
    assert_eq!(h.content.discarded(), vec![prepared.session_id]);
    *h.decrypt.0.open_failure.lock().unwrap() = None;
    h.server
        .open(open_request(&item, &prepared), &source(1), OPEN_AT)
        .await
        .unwrap();
}

#[tokio::test]
async fn guard_second_open_of_the_same_session_is_refused() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let prepared = h.prepared(&item, &source(1)).await;
    let gate = h.content.0.gates.close("stage");
    let server = h.server.clone();
    let open = open_request(&item, &prepared);
    let first = tokio::spawn(async move { server.open(open, &source(1), OPEN_AT).await });
    settle().await;
    assert_eq!(
        h.server
            .open(open_request(&item, &prepared), &source(1), OPEN_AT)
            .await,
        Err(PoolSessionRefusal::UnknownSession)
    );
    gate.add_permits(1);
    first.await.unwrap().unwrap();
    // An opened session cannot be opened again.
    assert_eq!(
        h.server
            .open(open_request(&item, &prepared), &source(1), OPEN_AT)
            .await,
        Err(PoolSessionRefusal::UnknownSession)
    );
}

#[test]
fn refusal_codes_are_the_wire_codes() {
    for (refusal, code) in [
        (PoolSessionRefusal::SelfServe, "self_serve_refused"),
        (PoolSessionRefusal::NotEligible, "not_eligible_server"),
        (PoolSessionRefusal::NotReady, "server_not_ready"),
        (PoolSessionRefusal::PoolBusy, "pool_busy"),
        (
            PoolSessionRefusal::Bound("read_ahead"),
            "session_bound_exceeded",
        ),
        (PoolSessionRefusal::UnknownSession, "unknown_session"),
        (PoolSessionRefusal::Expired, "session_expired"),
        (PoolSessionRefusal::BindingMismatch, "binding_mismatch"),
        (
            PoolSessionRefusal::ContentUnavailable,
            "content_unavailable",
        ),
        (
            PoolSessionRefusal::DecryptUnavailable,
            "decrypt_unavailable",
        ),
    ] {
        assert_eq!(refusal.code(), code);
    }
}

// ---------------------------------------------------------------------------
// #388 A1: the pool-server role on an everyday host
// ---------------------------------------------------------------------------

/// On a host whose captured setting is not `wci_operated`, every session op
/// except `session.close` answers `not_eligible_server`, before any port
/// call; a session already open can still be closed.
#[tokio::test]
async fn everyday_host_session_ops_answer_not_eligible_server_and_close_still_works() {
    let h = harness();
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let opened = h.opened(&item, &source(1)).await;
    let other = h.prepared(&item, &source(2)).await;
    h.host_trusted.store(false, Ordering::SeqCst);
    let prepares = h.decrypt.calls("prepare_recipient_v2").len();

    assert_eq!(
        h.server
            .prepare(item.prepare(BUYER_RUNTIME_SEED), &source(3), PREPARE_AT)
            .await
            .unwrap_err(),
        PoolSessionRefusal::NotEligible
    );
    assert_eq!(h.decrypt.calls("prepare_recipient_v2").len(), prepares);
    assert_eq!(
        h.server
            .open(open_request(&item, &other), &source(2), OPEN_AT)
            .await
            .unwrap_err(),
        PoolSessionRefusal::NotEligible
    );
    assert_eq!(
        h.read(
            opened.session_id,
            ViewerPartIndexV1::ObjectChunk(0),
            &source(1),
            READ_AT
        )
        .await
        .unwrap_err(),
        PoolSessionRefusal::NotEligible
    );
    assert!(h
        .decrypt
        .calls("read_viewer_object_chunk_sealed")
        .is_empty());
    h.server.close(opened.session_id, &source(1)).await.unwrap();
}

/// #388 A2: a pool whose descriptor is historical (v2, trust absent) admits
/// no session, before any port call, even on a `wci_operated` host.
#[tokio::test]
async fn historical_descriptor_session_prepare_answers_not_eligible() {
    let historical = historical_v2_descriptor_with(
        &pool_bundle(xwing, NOW),
        1,
        ServePolicyV1::DEFAULT,
        None,
        runtime_issuer(BUYER_RUNTIME_SEED),
        NOW,
    )
    .verify(NOW)
    .unwrap();
    assert_eq!(historical.trust(), None);
    let h = harness_for(historical, 64);
    assert!(h.host_trusted.load(Ordering::SeqCst));
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    assert_eq!(
        h.server
            .prepare(item.prepare(BUYER_RUNTIME_SEED), &source(1), PREPARE_AT)
            .await
            .unwrap_err(),
        PoolSessionRefusal::NotEligible
    );
    assert!(h.decrypt.calls("prepare_recipient_v2").is_empty());
    assert!(h.attest.0.lock().unwrap().is_empty());
}

/// Positive control: the same ops on a `wci_operated` host.
#[tokio::test]
async fn wci_operated_host_serves_sessions() {
    let h = harness();
    assert!(h.host_trusted.load(Ordering::SeqCst));
    let item = item(PoolSessionContentKindV1::Object, 0x21);
    let opened = h.opened(&item, &source(1)).await;
    h.read(
        opened.session_id,
        ViewerPartIndexV1::ObjectChunk(0),
        &source(1),
        READ_AT,
    )
    .await
    .unwrap();
}

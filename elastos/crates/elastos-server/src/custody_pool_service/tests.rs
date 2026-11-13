//! Plan B T3.4: the `custody-pool` target over a fake Carrier, and the
//! content-plane port against published bytes.
//!
//! The provider runs behind the real Carrier inbound dispatch
//! (`carrier_provider_invoke_registry`) with fake decrypt, attestation and
//! policy ports. The fake decrypt port seals each part for real to the
//! delivery key that `session.open` carried, so the buyer side opens every
//! part with its delivery secret (F3). The content port is the real
//! `ContentPlanePoolContentPort` over a fake `PoolContentSource` that serves
//! published files by CID.

use super::*;

use std::sync::atomic::{AtomicU64, AtomicU8};

use ed25519_dalek::Signer as _;
use elastos_protected_content_contracts::test_fixtures::{
    key_envelope_for, node_public_key, pool_bundle, pool_descriptor_with, pool_did,
    pool_release_fixture, runtime_issuer, signed_node_rights_decision, signing_key,
    PoolReleaseFixtureV1, PoolReleaseSpecV1,
};
use elastos_protected_content_contracts::{
    ContentAccessIdV1, EncryptedContentIdentityV1, EvmContractAddressV1, EvmFunctionSelectorV1,
    EvmRightsMethodAbiV1, KeyReleaseOutcomeV1, NodeContributionRefV1, NodeContributionStatementV1,
    RecipientPublicKeyBytesV1, RecipientSealedContributionV1, RightsDecisionV1,
    RightsObservationFinalityV1, RightsPolicyBodyV1, RightsSubjectSourceV1, RuntimeIssuerPolicyV1,
    RuntimeReleaseAuditIdV1, ServePolicyV1, TerminalReceiptIssuerKey, TerminalReceiptStatementV1,
    ViewerPartAadV1, CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
};
use elastos_protected_content_custody::{
    open_viewer_part_v1, seal_viewer_part_v1, DeliverySecretKeyV1, PayloadSealerV1,
};
use x_wing::kem::Decapsulator as _;
use x_wing::KeyExport as _;
use zeroize::Zeroizing;

use crate::carrier::{carrier_provider_invoke_registry, CarrierProviderCaller};
use crate::custody_surface::{carrier_op_allowed, carrier_target_allowed};
use crate::protected_content_config::tests::{owner_only_dir, safe_ancestor_tempdir};
use crate::protected_content_runtime::tests::media_dash_fixture::{
    MediaDashComponents, A as DASH_AUDIO, V as DASH_VIDEO,
};
use crate::protected_content_runtime::tests::{
    components_package_files, dash_manifest_from_files, media_components, media_dash_components,
};
use crate::protected_content_runtime::RUNTIME_PROVIDER_ID;

const NOW: u64 = 2_000_000_000;
const PREPARE_AT: u64 = NOW + 1;
/// The fixture operation runs from `now + 2` to `now + 40`.
const OPEN_AT: u64 = NOW + 5;
const READ_AT: u64 = NOW + 6;
const PREPARE_EXPIRES_AT: u64 = NOW + 250;
const DELIVERY_SEED: u8 = 0x5e;
const SUBSTITUTED_DELIVERY_SEED: u8 = 0x6e;
const OWN_ENDPOINT: &str = "did:key:z6MkPoolServerHome";
const OWN_ISSUER_SEED: u8 = 0x50;
const BUYER_RUNTIME_SEED: u8 = 0x43;
const BUYER_ENDPOINT_SEED: u8 = 0x61;
/// The server is fixture pool node 1.
const SERVER_NODE: u8 = 1;
const MEDIA_MIME_TYPE: &str = "video/mp4";
const MEDIA_CODECS: &str = "avc1.640028,mp4a.40.2";
const OBJECT_CONTENT_TYPE: &str = "application/pdf";

const KINDS: [PoolSessionContentKindV1; 3] = [
    PoolSessionContentKindV1::MediaV1,
    PoolSessionContentKindV1::DashV2,
    PoolSessionContentKindV1::Object,
];

fn xwing(seed: u8) -> [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
    let secret = x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE]);
    secret.encapsulation_key().to_bytes().into()
}

fn delivery_public_key(seed: u8) -> DeliveryPublicKeyBytesV1 {
    DeliveryPublicKeyBytesV1::new(xwing(seed)).unwrap()
}

/// The buyer Runtime's delivery secret for `DELIVERY_SEED`.
fn delivery_secret() -> DeliverySecretKeyV1 {
    let secret =
        DeliverySecretKeyV1::from_guarded_bytes(Zeroizing::new([DELIVERY_SEED; 32])).unwrap();
    assert_eq!(
        secret.public_key().unwrap(),
        delivery_public_key(DELIVERY_SEED)
    );
    secret
}

fn buyer_endpoint() -> iroh::PublicKey {
    iroh::SecretKey::from_bytes(&[BUYER_ENDPOINT_SEED; 32]).public()
}

fn b64_decode(value: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value.as_str().expect("a base64 string"))
        .unwrap()
}

fn refused<T>(result: Result<T, PoolSessionRefusal>) -> PoolSessionRefusal {
    match result {
        Ok(_) => panic!("the call must be refused"),
        Err(refusal) => refusal,
    }
}

// ---------------------------------------------------------------------------
// Published items
// ---------------------------------------------------------------------------

/// One item as the content plane serves it: its files by path.
#[derive(Clone)]
struct Published {
    cid: String,
    identity: PoolContentIdentityV1,
    files: BTreeMap<String, Vec<u8>>,
    /// Every part the round trip reads, in order.
    parts: Vec<ViewerPartIndexV1>,
}

fn media_v1_item(seed: u8) -> Published {
    let (init, segments) = media_components(seed);
    let identity =
        CencFmp4MediaIdentityV1::new_from_bytes(&init, &segments, MEDIA_MIME_TYPE, MEDIA_CODECS)
            .unwrap();
    let mut files = BTreeMap::new();
    files.insert(
        PROTECTED_CONTENT_IDENTITY_PATH.to_string(),
        identity.canonical_bytes().unwrap(),
    );
    files.insert(PROTECTED_CONTENT_INIT_PATH.to_string(), init);
    for (index, segment) in segments.iter().enumerate() {
        files.insert(protected_content_segment_path(index), segment.clone());
    }
    Published {
        cid: format!("bafy-media-v1-{seed:02x}"),
        identity: PoolContentIdentityV1::MediaV1(identity),
        files,
        parts: vec![
            ViewerPartIndexV1::MediaV1Init,
            ViewerPartIndexV1::MediaV1Segment(0),
        ],
    }
}

fn dash_components() -> MediaDashComponents {
    media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 1])
}

fn dash_item_from(components: &MediaDashComponents) -> Published {
    let package = components_package_files(components);
    let manifest = dash_manifest_from_files(&package);
    let mut files: BTreeMap<String, Vec<u8>> = package.into_iter().collect();
    files.insert(
        crate::content::CONTENT_OBJECT_MANIFEST_PATH.to_string(),
        serde_json::to_vec(&manifest).unwrap(),
    );
    Published {
        cid: "bafy-dash-v2".to_string(),
        identity: PoolContentIdentityV1::DashV2(components.head.clone()),
        files,
        parts: vec![
            ViewerPartIndexV1::DashInit { rendition: 0 },
            ViewerPartIndexV1::DashInit { rendition: 1 },
            ViewerPartIndexV1::DashSegment {
                rendition: 0,
                index: 0,
            },
            ViewerPartIndexV1::DashSegment {
                rendition: 1,
                index: 0,
            },
        ],
    }
}

/// A one-chunk sealed object and its framed header.
fn object_package(seed: u8) -> (ChunkedPayloadObjectIdentityV1, Vec<u8>, Vec<u8>) {
    let clear = vec![seed; 4096];
    let (mut sealer, framed_header) =
        PayloadSealerV1::open(OBJECT_CONTENT_TYPE, clear.len() as u64).unwrap();
    let chunk = sealer.seal_chunk(0, &clear).unwrap();
    let framed = [framed_header.clone(), chunk].concat();
    let identity = ChunkedPayloadObjectIdentityV1::new(
        EncryptedContentIdentityV1::new(
            Digest32::new(Sha256::digest(&framed).into()),
            framed.len() as u64,
        )
        .unwrap(),
        OBJECT_CONTENT_TYPE,
        clear.len() as u64,
        u32::try_from(framed_header.len()).unwrap(),
    )
    .unwrap();
    (identity, framed, framed_header)
}

/// An object item and its framed header. The sealer draws a fresh key, so
/// each call makes different bytes.
fn object_item_with_header(seed: u8) -> (Published, Vec<u8>) {
    let (identity, framed, framed_header) = object_package(seed);
    let mut files = BTreeMap::new();
    files.insert(PROTECTED_CONTENT_OBJECT_EPC1_PATH.to_string(), framed);
    let item = Published {
        cid: format!("bafy-object-{seed:02x}"),
        identity: PoolContentIdentityV1::Object(identity),
        files,
        parts: vec![ViewerPartIndexV1::ObjectChunk(0)],
    };
    (item, framed_header)
}

fn object_item(seed: u8) -> Published {
    object_item_with_header(seed).0
}

fn published(kind: PoolSessionContentKindV1) -> Published {
    match kind {
        PoolSessionContentKindV1::MediaV1 => media_v1_item(0x21),
        PoolSessionContentKindV1::DashV2 => dash_item_from(&dash_components()),
        PoolSessionContentKindV1::Object => object_item(0x23),
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

impl Published {
    /// The release spec, built at `now`, naming `recipient` when given.
    fn spec(&self, recipient: Option<RecipientPublicKeyBytesV1>, now: u64) -> PoolReleaseSpecV1 {
        let mut spec =
            PoolReleaseSpecV1::new(xwing, policy_body(self.identity.encrypted_content()), now);
        spec.recipients = vec![(0x09, SERVER_NODE)];
        spec.recipient_public_keys = recipient.map(|key| vec![key]);
        spec.delivery_key = Some(delivery_public_key(DELIVERY_SEED).identity());
        spec.wallet_seed = 7;
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
            cid: self.cid.clone(),
            kind: self.identity.kind(),
            identity: self.identity.clone(),
            content_key_commitment: Digest32::new([0xcc; 32]),
        }
    }

    /// The `session.prepare` fields, as a buyer Runtime sends them.
    fn prepare_fields(&self) -> Value {
        json!({
            "pool": pool_did().to_did_key().unwrap(),
            "binding_b64": b64(&self.binding().canonical_bytes().unwrap()),
            "action": RightsActionV1::View as u8,
            "runtime_operation_issuer_hex": hex::encode(runtime_issuer(BUYER_RUNTIME_SEED).as_bytes()),
            "content": {
                "cid": self.cid,
                "kind": content_kind_name(self.identity.kind()),
                "identity_b64": b64(&identity_bytes(&self.identity)),
                "content_key_commitment_b64": b64(&[0xcc; 32]),
            },
            "expires_at": PREPARE_EXPIRES_AT,
        })
    }
}

fn identity_bytes(identity: &PoolContentIdentityV1) -> Vec<u8> {
    match identity {
        PoolContentIdentityV1::MediaV1(identity) => identity.canonical_bytes().unwrap(),
        PoolContentIdentityV1::DashV2(identity) => identity.canonical_bytes().unwrap(),
        PoolContentIdentityV1::Object(identity) => identity.canonical_bytes().unwrap(),
    }
}

/// Structurally valid contributions and receipt for the release's
/// recipient (the fake decrypt port does not open them).
fn release_for(
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
                RecipientSealedContributionV1::new(recipient.clone(), sealed_contribution(node))
                    .unwrap(),
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

/// What node `node` seals to the recipient: the share material the buyer
/// must never see.
fn sealed_contribution(node: u8) -> Vec<u8> {
    vec![node; 96]
}

// ---------------------------------------------------------------------------
// Fake ports
// ---------------------------------------------------------------------------

/// The clear bytes the fake decrypt port "decrypts" for one part.
fn clear_part(part: ViewerPartIndexV1) -> Vec<u8> {
    let (tag, rendition, index) = match part {
        ViewerPartIndexV1::MediaV1Init => (1u8, 0u8, 0u32),
        ViewerPartIndexV1::MediaV1Segment(index) => (2, 0, index),
        ViewerPartIndexV1::DashInit { rendition } => (3, rendition, 0),
        ViewerPartIndexV1::DashSegment { rendition, index } => (4, rendition, index),
        ViewerPartIndexV1::ObjectChunk(index) => (5, 0, index),
    };
    let mut bytes = b"clear-viewer-part:".to_vec();
    bytes.extend_from_slice(&[tag, rendition]);
    bytes.extend_from_slice(&index.to_be_bytes());
    bytes
}

fn request_json(request: &DecryptProviderRequestV1) -> Value {
    serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap()
}

fn audit_of(request: &Value) -> RuntimeReleaseAuditIdV1 {
    let bytes: [u8; 32] =
        serde_json::from_value(request["audit_request_id"].clone()).unwrap_or([0x91; 32]);
    RuntimeReleaseAuditIdV1::new(Digest32::new(bytes)).unwrap()
}

fn handle_of(request: &Value, field: &str) -> [u8; 32] {
    hex::decode(request[field].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

/// The part a sealed read names, from its selector.
fn part_of(request: &Value) -> ViewerPartIndexV1 {
    if let Some(index) = request.get("chunk_index").and_then(Value::as_u64) {
        return ViewerPartIndexV1::ObjectChunk(u32::try_from(index).unwrap());
    }
    let selector = &request["part_selector"];
    let rendition = selector
        .get("rendition_index")
        .and_then(Value::as_u64)
        .map(|rendition| u8::try_from(rendition).unwrap());
    let index = || u32::try_from(selector["segment_index"].as_u64().unwrap()).unwrap();
    match (selector["part"].as_str().unwrap(), rendition) {
        ("init", None) => ViewerPartIndexV1::MediaV1Init,
        ("init", Some(rendition)) => ViewerPartIndexV1::DashInit { rendition },
        ("segment", None) => ViewerPartIndexV1::MediaV1Segment(index()),
        ("segment", Some(rendition)) => ViewerPartIndexV1::DashSegment {
            rendition,
            index: index(),
        },
        (other, _) => panic!("unexpected part selector {other}"),
    }
}

#[derive(Default)]
struct DecryptState {
    calls: Mutex<Vec<(&'static str, Value)>>,
    next: AtomicU8,
    /// The delivery key each open carried, by viewer session handle.
    delivery: Mutex<BTreeMap<[u8; 32], DeliveryPublicKeyBytesV1>>,
    /// The operation the buyer released, set by the test.
    operation_hash: Mutex<Option<Digest32>>,
}

/// A decrypt port that seals for real: each read is sealed to the delivery
/// key its session's open carried, under the read's session id and part.
#[derive(Clone, Default)]
struct FakeDecrypt(Arc<DecryptState>);

impl FakeDecrypt {
    fn calls(&self, op: &str) -> usize {
        self.0
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| *name == op)
            .count()
    }

    fn total_calls(&self) -> usize {
        self.0.calls.lock().unwrap().len()
    }

    fn released(&self, operation_hash: Digest32) {
        *self.0.operation_hash.lock().unwrap() = Some(operation_hash);
    }

    fn record(&self, op: &'static str, request: &DecryptProviderRequestV1) -> Value {
        let json = request_json(request);
        self.0.calls.lock().unwrap().push((op, json.clone()));
        json
    }

    fn sealed(&self, request: &Value) -> DecryptProviderResponseV1 {
        let handle = handle_of(request, "viewer_session_handle");
        let delivery = *self
            .0
            .delivery
            .lock()
            .unwrap()
            .get(&handle)
            .expect("a read follows its open");
        let part = part_of(request);
        let aad = ViewerPartAadV1 {
            session_id: serde_json::from_value(request["session_id"].clone()).unwrap(),
            operation_hash: self.0.operation_hash.lock().unwrap().expect("released"),
            part,
        };
        DecryptProviderResponseV1::new_viewer_sealed_part(
            audit_of(request),
            handle,
            seal_viewer_part_v1(&delivery, &aad, &clear_part(part)).unwrap(),
        )
        .unwrap()
    }
}

#[async_trait::async_trait]
impl PoolSessionDecryptPort for FakeDecrypt {
    async fn prepare_recipient_v2(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        let json = self.record("prepare_recipient_v2", request);
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
        let json = self.record("open_viewer_session_v2", request);
        let handle = handle_of(&json, "prepared_recipient_handle");
        let delivery: Vec<u8> =
            serde_json::from_value(json["delivery_public_key"].clone()).unwrap();
        let delivery = DeliveryPublicKeyBytesV1::new(delivery.try_into().unwrap()).unwrap();
        self.0.delivery.lock().unwrap().insert(handle, delivery);
        Ok(DecryptProviderResponseV1::new_viewer_session_opened(
            RuntimeReleaseAuditIdV1::new(Digest32::new([0x91; 32])).unwrap(),
            handle,
        )
        .unwrap())
    }

    async fn read_viewer_media_part_sealed(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        let json = self.record("read_viewer_media_part_sealed", request);
        Ok(self.sealed(&json))
    }

    async fn read_viewer_object_chunk_sealed(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        let json = self.record("read_viewer_object_chunk_sealed", request);
        Ok(self.sealed(&json))
    }

    async fn cancel_prepared_recipient(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        let json = self.record("cancel_prepared_recipient", request);
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
        let json = self.record("close_viewer_session", request);
        Ok(DecryptProviderResponseV1::new_closed_viewer_session(
            audit_of(&json),
            handle_of(&json, "viewer_session_handle"),
        )
        .unwrap())
    }
}

#[derive(Clone, Default)]
struct FakeAttest;

#[async_trait::async_trait]
impl PoolSessionAttestPort for FakeAttest {
    async fn attest_recipient(
        &self,
        statement: &PoolRecipientAttestationStatementV2,
    ) -> Result<SignedPoolRecipientAttestationV2, PoolSessionRefusal> {
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
    ready: Arc<AtomicBool>,
}

impl PoolSessionPolicyPort for FakePolicy {
    fn descriptor(&self, pool: &PoolDidV1) -> Option<VerifiedPoolDescriptorV1> {
        (self.descriptor.pool() == pool).then(|| self.descriptor.clone())
    }

    fn own_node_key(&self, _pool: &PoolDidV1) -> Option<NodePublicKey> {
        Some(node_public_key(SERVER_NODE))
    }

    fn own_endpoint_did(&self) -> &str {
        OWN_ENDPOINT
    }

    fn own_runtime_issuer(&self) -> RuntimeOperationIssuerKeyV1 {
        runtime_issuer(OWN_ISSUER_SEED)
    }

    fn decrypt_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    /// #388 A1: these servers run on a WCI-operated host.
    fn host_trusted(&self) -> bool {
        true
    }
}

/// Published bytes by (CID, path).
type PublishedFiles = BTreeMap<(String, String), Vec<u8>>;

/// The content plane: published files by `(cid, path)`, with every read
/// recorded.
#[derive(Clone, Default)]
struct FakeSource {
    files: Arc<Mutex<PublishedFiles>>,
    reads: Arc<Mutex<Vec<(String, String)>>>,
}

impl FakeSource {
    fn publish(&self, item: &Published) {
        let mut files = self.files.lock().unwrap();
        for (path, bytes) in &item.files {
            files.insert((item.cid.clone(), path.clone()), bytes.clone());
        }
    }

    fn replace(&self, cid: &str, path: &str, bytes: Vec<u8>) {
        self.files
            .lock()
            .unwrap()
            .insert((cid.to_string(), path.to_string()), bytes);
    }

    fn reads(&self) -> Vec<(String, String)> {
        self.reads.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl PoolContentSource for FakeSource {
    async fn bytes(&self, cid: &str, path: &str, cap: Option<usize>) -> anyhow::Result<Vec<u8>> {
        self.reads
            .lock()
            .unwrap()
            .push((cid.to_string(), path.to_string()));
        let bytes = self
            .files
            .lock()
            .unwrap()
            .get(&(cid.to_string(), path.to_string()))
            .cloned()
            .context("not on the content plane")?;
        if cap.is_some_and(|cap| bytes.len() > cap) {
            anyhow::bail!("larger than the requested bound");
        }
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type TestProvider = CustodyPoolServiceProvider<
    FakePolicy,
    FakeDecrypt,
    ContentPlanePoolContentPort<FakeSource>,
    FakeAttest,
>;

struct Harness {
    registry: Arc<ProviderRegistry>,
    decrypt: FakeDecrypt,
    source: FakeSource,
    clock: Arc<AtomicU64>,
    stage_root: PathBuf,
    /// Where Carrier keeps this Home's peer grants (none here).
    peer_dir: tempfile::TempDir,
    _dir: tempfile::TempDir,
}

/// The provider registered at `custody-pool`. With `readiness_from_registry`
/// the provider reads decrypt readiness from the registry, as it does in a
/// Home; otherwise the decrypt port is ready.
async fn harness(readiness_from_registry: bool) -> Harness {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("home");
    owner_only_dir(&data_dir);
    // #388 A1: a pool server Home is a WCI-operated host.
    crate::host_trust::seed_for_test(&data_dir, true);
    let stage_root = dir.path().join("pool-sessions");
    // The stage root is owner-only, as the Runtime's own storage is; the
    // temp dir above it need not be.
    owner_only_dir(&stage_root);
    let registry = Arc::new(ProviderRegistry::new());
    let decrypt = FakeDecrypt::default();
    let source = FakeSource::default();
    let ready = Arc::new(AtomicBool::new(true));
    let descriptor = pool_descriptor_with(
        &pool_bundle(xwing, NOW),
        1,
        ServePolicyV1::DEFAULT,
        None,
        runtime_issuer(BUYER_RUNTIME_SEED),
        NOW,
    )
    .verify(NOW)
    .unwrap();
    let server = PoolSessionServer::new(
        FakePolicy {
            descriptor,
            ready: ready.clone(),
        },
        decrypt.clone(),
        ContentPlanePoolContentPort::new(source.clone(), stage_root.clone()),
        FakeAttest,
    );
    let clock = Arc::new(AtomicU64::new(PREPARE_AT));
    let read_clock = clock.clone();
    let provider: TestProvider = CustodyPoolServiceProvider::new(
        server,
        data_dir,
        ready,
        readiness_from_registry.then(|| Arc::downgrade(&registry)),
    )
    .with_clock(Arc::new(move || read_clock.load(Ordering::SeqCst)));
    registry
        .register_runtime_provider_target(TARGET_CUSTODY_POOL, Arc::new(provider))
        .await
        .unwrap();
    Harness {
        registry,
        decrypt,
        source,
        clock,
        stage_root,
        peer_dir: safe_ancestor_tempdir(),
        _dir: dir,
    }
}

/// The Runtime envelope a buyer Runtime sends; Carrier fills `carrier`.
fn carrier_envelope(op: &str) -> Value {
    json!({
        "schema": "elastos.provider.invocation/v1",
        "source": RUNTIME_PROVIDER_ID,
        "target": TARGET_CUSTODY_POOL,
        "op": op,
        "capability": format!("provider:{RUNTIME_PROVIDER_ID}->{TARGET_CUSTODY_POOL}:{op}"),
        "transport": "carrier-provider-plane",
        "carrier": Value::Null,
        "transfer": "json",
        "range": Value::Null,
        "progress": Value::Null,
        "abi": {
            "schema": "elastos.provider.transfer-abi/v1",
            "transfer": "json",
            "transport": "carrier-provider-plane",
            "range_supported": false,
            "progress_supported": false,
            "progress_mode": "none",
            "transport_native_stream": false,
            "backpressure": "not_applicable",
            "cancel_supported": false,
        },
    })
}

impl Harness {
    fn at(&self, now: u64) {
        self.clock.store(now, Ordering::SeqCst);
    }

    /// One `provider_invoke` from the buyer's endpoint, through Carrier's
    /// inbound dispatch. Answers Carrier's whole reply.
    async fn carrier(&self, op: &str, mut fields: Value) -> Value {
        fields["op"] = json!(op);
        fields["_runtime_invocation"] = carrier_envelope(op);
        let invoke = json!({
            "source": RUNTIME_PROVIDER_ID,
            "target": TARGET_CUSTODY_POOL,
            "operation": op,
            "transfer": "json",
            "request": fields,
        });
        carrier_provider_invoke_registry(
            &self.registry,
            &invoke,
            &buyer_endpoint(),
            CarrierProviderCaller::Peer {
                data_dir: self.peer_dir.path(),
                network: None,
            },
        )
        .await
        .unwrap()
    }

    /// The provider's answer to one op, carried inside `{ok:true, result}`.
    async fn call(&self, op: &str, fields: Value) -> Value {
        let reply = self.carrier(op, fields).await;
        assert_eq!(reply["ok"], true, "Carrier carries every answer: {reply}");
        reply["result"].clone()
    }

    async fn ok(&self, op: &str, fields: Value) -> Value {
        let answer = self.call(op, fields).await;
        assert_eq!(answer["status"], "ok", "{op}: {answer}");
        answer["data"].clone()
    }

    async fn code(&self, op: &str, fields: Value) -> String {
        let answer = self.call(op, fields).await;
        assert_eq!(answer["status"], "error", "{op}: {answer}");
        assert_eq!(
            answer.as_object().unwrap().len(),
            2,
            "a refusal carries only its code: {answer}"
        );
        answer["code"].as_str().unwrap().to_string()
    }
}

/// A prepared session as the buyer sees it.
struct Prepared {
    session_id: [u8; 16],
    recipient: RecipientPublicKeyBytesV1,
}

impl Harness {
    async fn prepare(&self, item: &Published) -> (Prepared, Value) {
        self.at(PREPARE_AT);
        let data = self
            .ok(OP_CUSTODY_POOL_SESSION_PREPARE, item.prepare_fields())
            .await;
        let session_id: [u8; 16] = hex::decode(data["session_id_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let recipient = RecipientPublicKeyBytesV1::new(
            b64_decode(&data["recipient_public_key_b64"])
                .try_into()
                .unwrap(),
        )
        .unwrap();
        // The attestation names the recipient the decrypt port made, signed
        // by this node.
        let attestation = SignedPoolRecipientAttestationV2::from_canonical_bytes(&b64_decode(
            &data["attestation_b64"],
        ))
        .unwrap();
        attestation.verify_node_signature().unwrap();
        assert_eq!(attestation.statement().recipient_public_key(), recipient);
        assert_eq!(
            attestation.statement().server_node_public_key(),
            node_public_key(SERVER_NODE)
        );
        assert_eq!(attestation.statement().binding(), &item.binding());
        (
            Prepared {
                session_id,
                recipient,
            },
            data,
        )
    }

    /// The buyer's `session.open` fields for `prepared`, and the released
    /// operation's hash.
    fn open_fields(
        &self,
        item: &Published,
        prepared: &Prepared,
        delivery: DeliveryPublicKeyBytesV1,
    ) -> (Value, Digest32) {
        let fixture = pool_release_fixture(&item.spec(Some(prepared.recipient), NOW));
        let (contributions, receipt) = release_for(&fixture);
        let operation_hash = fixture.authenticated().operation_hash();
        let fields = json!({
            "session_id_hex": hex::encode(prepared.session_id),
            "operation_v2_b64": b64(&fixture.operation.canonical_bytes().unwrap()),
            "delivery_public_key_b64": b64(delivery.as_bytes()),
            "contributions_b64": contributions
                .iter()
                .map(|contribution| b64(&contribution.canonical_bytes().unwrap()))
                .collect::<Vec<_>>(),
            "terminal_receipt_b64": b64(&receipt.canonical_bytes().unwrap()),
        });
        (fields, operation_hash)
    }

    /// prepare, open, every part, close: every answer the buyer received.
    async fn round_trip(&self, item: &Published) -> Vec<Value> {
        self.source.publish(item);
        let (prepared, prepare_answer) = self.prepare(item).await;
        let (fields, operation_hash) =
            self.open_fields(item, &prepared, delivery_public_key(DELIVERY_SEED));
        self.decrypt.released(operation_hash);
        self.at(OPEN_AT);
        let open_answer = self.ok(OP_CUSTODY_POOL_SESSION_OPEN, fields).await;
        assert!(open_answer["expires_at"].as_u64().unwrap() > OPEN_AT);
        let mut answers = vec![prepare_answer, open_answer];

        self.at(READ_AT);
        let secret = delivery_secret();
        for part in &item.parts {
            let data = self
                .ok(
                    OP_CUSTODY_POOL_SESSION_READ,
                    json!({
                        "session_id_hex": hex::encode(prepared.session_id),
                        "part": part_json(*part),
                    }),
                )
                .await;
            let sealed = b64_decode(&data["sealed_b64"]);
            let aad = ViewerPartAadV1 {
                session_id: prepared.session_id,
                operation_hash,
                part: *part,
            };
            let opened = open_viewer_part_v1(&secret, &aad, &sealed).unwrap();
            assert_eq!(opened.as_slice(), clear_part(*part).as_slice());
            // The seal is bound to its session: another session id does not
            // open it.
            let other = ViewerPartAadV1 {
                session_id: [0xee; 16],
                ..aad
            };
            assert!(open_viewer_part_v1(&secret, &other, &sealed).is_err());
            answers.push(data);
        }

        let close_answer = self
            .ok(
                OP_CUSTODY_POOL_SESSION_CLOSE,
                json!({ "session_id_hex": hex::encode(prepared.session_id) }),
            )
            .await;
        answers.push(close_answer);
        assert_eq!(
            self.code(
                OP_CUSTODY_POOL_SESSION_READ,
                json!({
                    "session_id_hex": hex::encode(prepared.session_id),
                    "part": part_json(item.parts[0]),
                }),
            )
            .await,
            PoolSessionRefusal::UnknownSession.code()
        );
        answers
    }
}

fn part_json(part: ViewerPartIndexV1) -> Value {
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

// ---------------------------------------------------------------------------
// The target
// ---------------------------------------------------------------------------

#[tokio::test]
async fn custody_pool_target_is_declared_and_allowed() {
    // The surface declares the target as a Runtime provider target that
    // Carrier admits, with exactly its five ops.
    assert!(carrier_target_allowed(TARGET_CUSTODY_POOL));
    assert!(crate::carrier::carrier_provider_target_allowed(
        TARGET_CUSTODY_POOL
    ));
    assert!(crate::custody_surface::is_runtime_provider_target(
        TARGET_CUSTODY_POOL
    ));
    let ops = [
        OP_CUSTODY_POOL_DESCRIBE,
        OP_CUSTODY_POOL_SESSION_PREPARE,
        OP_CUSTODY_POOL_SESSION_OPEN,
        OP_CUSTODY_POOL_SESSION_READ,
        OP_CUSTODY_POOL_SESSION_CLOSE,
    ];
    for op in ops {
        assert!(carrier_op_allowed(TARGET_CUSTODY_POOL, op), "{op}");
    }
    assert_eq!(declared_ops(TARGET_CUSTODY_POOL).count(), ops.len());

    // The registry takes the target only because its name is reserved.
    let h = harness(false).await;
    assert!(ProviderRegistry::new()
        .register_runtime_provider_target("custody-pool-other", Arc::new(UnusedProvider))
        .await
        .is_err());

    // A refusal travels as a code inside Carrier's `{ok:true, result}`.
    assert_eq!(
        h.code(
            OP_CUSTODY_POOL_DESCRIBE,
            json!({ "pool": pool_did().to_did_key().unwrap() }),
        )
        .await,
        PoolSessionRefusal::NotEligible.code()
    );
}

/// A provider that is never called; it only proves a name is refused.
struct UnusedProvider;

#[async_trait::async_trait]
impl Provider for UnusedProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider("unused".into()))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["custody-pool-other"]
    }

    fn name(&self) -> &'static str {
        "unused"
    }
}

#[tokio::test]
async fn undeclared_custody_pool_op_is_refused() {
    let h = harness(false).await;
    // An op no surface row declares, and a custody op of another target.
    for op in ["session.renew", OP_CUSTODY_SIGN_POOL_STATEMENT] {
        let reply = h.carrier(op, json!({})).await;
        assert_eq!(reply["ok"], false, "{op}: {reply}");
        assert_eq!(reply["code"], "provider_error", "{op}: {reply}");
    }
    // Sent straight to the registry, the op is refused the same way.
    let mut request = json!({ "op": "session.renew" });
    request["_runtime_invocation"] = carrier_envelope("session.renew");
    assert!(h
        .registry
        .send_runtime_provider_target_raw(TARGET_CUSTODY_POOL, &request)
        .await
        .is_err());
    // A request without the Runtime envelope is refused too.
    assert!(h
        .registry
        .send_runtime_provider_target_raw(
            TARGET_CUSTODY_POOL,
            &json!({ "op": OP_CUSTODY_POOL_DESCRIBE, "pool": pool_did().to_did_key().unwrap() }),
        )
        .await
        .is_err());
    assert_eq!(h.decrypt.total_calls(), 0);
}

#[tokio::test]
async fn prepare_refuses_when_decrypt_not_ready() {
    // The registry has no decrypt target, so the provider reads "not ready".
    let h = harness(true).await;
    let item = published(PoolSessionContentKindV1::Object);
    h.source.publish(&item);
    assert_eq!(
        h.code(OP_CUSTODY_POOL_SESSION_PREPARE, item.prepare_fields())
            .await,
        "server_not_ready"
    );
    assert_eq!(h.decrypt.total_calls(), 0);
    assert!(h.source.reads().is_empty());
}

#[tokio::test]
async fn malformed_session_fields_are_invalid_requests() {
    let h = harness(false).await;
    let item = published(PoolSessionContentKindV1::Object);
    let mut unknown_kind = item.prepare_fields();
    unknown_kind["content"]["kind"] = json!("hls");
    let mut long_cid = item.prepare_fields();
    long_cid["content"]["cid"] = json!("b".repeat(MAX_CID_BYTES + 1));
    let mut bad_action = item.prepare_fields();
    bad_action["action"] = json!(99);
    for fields in [unknown_kind, long_cid, bad_action] {
        assert_eq!(
            h.code(OP_CUSTODY_POOL_SESSION_PREPARE, fields).await,
            INVALID_REQUEST
        );
    }
    assert_eq!(
        h.code(
            OP_CUSTODY_POOL_SESSION_READ,
            json!({ "session_id_hex": "00", "part": { "kind": "object_chunk", "index": 0 } }),
        )
        .await,
        INVALID_REQUEST
    );
    assert_eq!(h.decrypt.total_calls(), 0);
}

// ---------------------------------------------------------------------------
// Sessions over Carrier
// ---------------------------------------------------------------------------

#[tokio::test]
async fn session_round_trip_over_fake_carrier_for_each_kind() {
    for kind in KINDS {
        let h = harness(false).await;
        let item = published(kind);
        h.round_trip(&item).await;
        assert_eq!(h.decrypt.calls("prepare_recipient_v2"), 1, "{kind:?}");
        assert_eq!(h.decrypt.calls("open_viewer_session_v2"), 1, "{kind:?}");
        let reads = h.decrypt.calls("read_viewer_media_part_sealed")
            + h.decrypt.calls("read_viewer_object_chunk_sealed");
        assert_eq!(reads, item.parts.len(), "{kind:?}");
        assert_eq!(h.decrypt.calls("close_viewer_session"), 1, "{kind:?}");
        // The content plane was read by the item's CID only.
        assert!(h.source.reads().iter().all(|(cid, _)| cid == &item.cid));
    }
}

#[tokio::test]
async fn session_open_with_a_substituted_delivery_key_is_refused() {
    let h = harness(false).await;
    let item = published(PoolSessionContentKindV1::Object);
    h.source.publish(&item);
    let (prepared, _) = h.prepare(&item).await;
    // The wallet signed `DELIVERY_SEED`'s key; the open carries another.
    let (fields, operation_hash) = h.open_fields(
        &item,
        &prepared,
        delivery_public_key(SUBSTITUTED_DELIVERY_SEED),
    );
    h.decrypt.released(operation_hash);
    h.at(OPEN_AT);
    assert_eq!(
        h.code(OP_CUSTODY_POOL_SESSION_OPEN, fields).await,
        PoolSessionRefusal::BindingMismatch.code()
    );
    assert_eq!(h.decrypt.calls("open_viewer_session_v2"), 0);
    // Nothing was staged for the refused open.
    assert!(!h.stage_root.join(hex::encode(prepared.session_id)).exists());
}

#[tokio::test]
async fn buyer_sees_no_key_material() {
    for kind in KINDS {
        let h = harness(false).await;
        let item = published(kind);
        let answers = h.round_trip(&item).await;
        // Every answer has exactly its wire fields.
        let mut expected: Vec<Vec<&str>> = vec![
            vec![
                "attestation_b64",
                "recipient_public_key_b64",
                "session_id_hex",
            ],
            vec!["expires_at"],
        ];
        expected.extend(item.parts.iter().map(|_| vec!["sealed_b64"]));
        expected.push(vec![]);
        assert_eq!(answers.len(), expected.len());
        for (answer, fields) in answers.iter().zip(expected) {
            let mut keys: Vec<&str> = answer
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            assert_eq!(keys, fields, "{kind:?}: {answer}");
        }
        // No answer carries a node's sealed share or a clear part, in any
        // encoding the wire uses.
        let text = answers
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        let mut secrets = vec![sealed_contribution(1), sealed_contribution(2)];
        secrets.extend(item.parts.iter().map(|part| clear_part(*part)));
        for secret in secrets {
            assert!(!text.contains(&b64(&secret)), "{kind:?}");
            assert!(!text.contains(&hex::encode(&secret)), "{kind:?}");
        }
        // Each sealed part is ciphertext: it does not contain its clear bytes.
        for (answer, part) in answers[2..].iter().zip(&item.parts) {
            let sealed = b64_decode(&answer["sealed_b64"]);
            let clear = clear_part(*part);
            assert!(!sealed.windows(clear.len()).any(|window| window == clear));
        }
    }
}

// ---------------------------------------------------------------------------
// The content port
// ---------------------------------------------------------------------------

struct Port {
    port: ContentPlanePoolContentPort<FakeSource>,
    source: FakeSource,
    root: PathBuf,
    _dir: tempfile::TempDir,
}

fn port() -> Port {
    let dir = safe_ancestor_tempdir();
    let root = dir.path().join("pool-sessions");
    owner_only_dir(&root);
    let source = FakeSource::default();
    Port {
        port: ContentPlanePoolContentPort::new(source.clone(), root.clone()),
        source,
        root,
        _dir: dir,
    }
}

impl Port {
    async fn stage(
        &self,
        session_id: [u8; 16],
        item: &Published,
    ) -> Result<PoolStagedContentV1, PoolSessionRefusal> {
        self.port
            .stage(session_id, &item.content_ref(), &item.binding())
            .await
    }
}

#[tokio::test]
async fn ciphertext_is_fetched_by_cid_and_verified() {
    let p = port();
    let item = object_item(0x31);
    // Not published yet: the content plane has nothing for the CID.
    assert_eq!(
        refused(p.stage([1; 16], &item).await),
        PoolSessionRefusal::ContentUnavailable
    );
    p.source.publish(&item);
    p.stage([2; 16], &item).await.unwrap();
    assert!(p.source.reads().contains(&(
        item.cid.clone(),
        PROTECTED_CONTENT_OBJECT_EPC1_PATH.to_string()
    )));
    // One flipped byte under the same CID no longer matches the identity.
    let mut tampered = item.files[PROTECTED_CONTENT_OBJECT_EPC1_PATH].clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    p.source
        .replace(&item.cid, PROTECTED_CONTENT_OBJECT_EPC1_PATH, tampered);
    assert_eq!(
        refused(p.stage([3; 16], &item).await),
        PoolSessionRefusal::ContentUnavailable
    );
    assert!(!p.root.join(hex::encode([3u8; 16])).exists());
}

#[tokio::test]
async fn content_port_stages_each_kind_against_the_full_identity() {
    let p = port();

    // V1 media: the init, then a segment's ciphertext by index.
    let media = media_v1_item(0x32);
    p.source.publish(&media);
    let staged = p.stage([1; 16], &media).await.unwrap();
    assert_eq!(staged.handle, [1; 16]);
    assert_eq!(staged.duration_secs, None);
    assert_eq!(
        staged.total_ciphertext_bytes,
        media.identity.encrypted_content().ciphertext_bytes()
    );
    match &staged.open {
        PoolStagedOpenV1::MediaV1 { protected_init } => {
            assert_eq!(protected_init, &media.files[PROTECTED_CONTENT_INIT_PATH]);
        }
        _ => panic!("V1 media stages its init"),
    }
    assert!(matches!(
        p.port.part(&staged, &ViewerPartIndexV1::MediaV1Init).await,
        Ok(PoolStagedPartV1::MediaV1Init)
    ));
    match p
        .port
        .part(&staged, &ViewerPartIndexV1::MediaV1Segment(0))
        .await
        .unwrap()
    {
        PoolStagedPartV1::MediaV1Segment { index, encrypted } => {
            assert_eq!(index, 0);
            assert_eq!(encrypted, media.files[&protected_content_segment_path(0)]);
        }
        _ => panic!("a V1 segment"),
    }
    let PoolContentIdentityV1::MediaV1(identity) = &media.identity else {
        unreachable!()
    };
    let past_end = u32::try_from(identity.encrypted_segments().len()).unwrap();
    for part in [
        ViewerPartIndexV1::MediaV1Segment(past_end),
        ViewerPartIndexV1::ObjectChunk(0),
        ViewerPartIndexV1::DashInit { rendition: 0 },
    ] {
        assert_eq!(
            refused(p.port.part(&staged, &part).await),
            PoolSessionRefusal::ContentUnavailable,
            "{part:?}"
        );
    }

    // DASH: one init per rendition, and each segment with its audit path
    // from the verified leaves.
    let components = dash_components();
    let dash = dash_item_from(&components);
    p.source.publish(&dash);
    let staged = p.stage([2; 16], &dash).await.unwrap();
    match &staged.open {
        PoolStagedOpenV1::DashV2 { protected_inits } => {
            assert_eq!(protected_inits, &components.protected_inits);
        }
        _ => panic!("DASH stages its inits"),
    }
    let manifest = dash_manifest_from_files(&components_package_files(&components));
    let leaves = verify_protected_content_dash_manifest(&manifest, &components.head).unwrap();
    for (rendition, segments) in components.protected_segments.iter().enumerate() {
        for (index, segment) in segments.iter().enumerate() {
            let part = ViewerPartIndexV1::DashSegment {
                rendition: u8::try_from(rendition).unwrap(),
                index: u32::try_from(index).unwrap(),
            };
            match p.port.part(&staged, &part).await.unwrap() {
                PoolStagedPartV1::DashSegment {
                    encrypted, proof, ..
                } => {
                    assert_eq!(&encrypted, segment);
                    assert_eq!(
                        proof,
                        cenc_dash_merkle_audit_path(&leaves[rendition], index).unwrap()
                    );
                }
                _ => panic!("a DASH segment"),
            }
        }
    }
    for part in [
        ViewerPartIndexV1::DashInit { rendition: 2 },
        ViewerPartIndexV1::DashSegment {
            rendition: 0,
            index: 2,
        },
        ViewerPartIndexV1::MediaV1Init,
    ] {
        assert_eq!(
            refused(p.port.part(&staged, &part).await),
            PoolSessionRefusal::ContentUnavailable,
            "{part:?}"
        );
    }

    // Object: the framed header at open, then one framed chunk.
    let (object, framed_header) = object_item_with_header(0x33);
    let PoolContentIdentityV1::Object(identity) = &object.identity else {
        unreachable!()
    };
    let framed = &object.files[PROTECTED_CONTENT_OBJECT_EPC1_PATH];
    p.source.publish(&object);
    let staged = p.stage([3; 16], &object).await.unwrap();
    match &staged.open {
        PoolStagedOpenV1::Object {
            framed_header: header,
        } => assert_eq!(header, &framed_header),
        _ => panic!("an object stages its framed header"),
    }
    match p
        .port
        .part(&staged, &ViewerPartIndexV1::ObjectChunk(0))
        .await
        .unwrap()
    {
        PoolStagedPartV1::ObjectChunk {
            index,
            framed_chunk,
        } => {
            assert_eq!(index, 0);
            assert_eq!(
                framed_chunk,
                runtime_custody_object_framed_chunk(framed, identity, 0).unwrap()
            );
        }
        _ => panic!("an object chunk"),
    }
    assert_eq!(
        refused(
            p.port
                .part(&staged, &ViewerPartIndexV1::ObjectChunk(1))
                .await
        ),
        PoolSessionRefusal::ContentUnavailable
    );

    // A part of a session that was never staged.
    let unknown = PoolStagedContentV1 {
        handle: [9; 16],
        ..staged
    };
    assert_eq!(
        refused(
            p.port
                .part(&unknown, &ViewerPartIndexV1::ObjectChunk(0))
                .await
        ),
        PoolSessionRefusal::UnknownSession
    );
}

#[tokio::test]
async fn staged_bytes_that_do_not_match_the_identity_are_content_unavailable() {
    let p = port();

    // V1 media: another item's identity file, then a changed init.
    let media = media_v1_item(0x41);
    let other = media_v1_item(0x42);
    p.source.publish(&media);
    p.source.replace(
        &media.cid,
        PROTECTED_CONTENT_IDENTITY_PATH,
        other.files[PROTECTED_CONTENT_IDENTITY_PATH].clone(),
    );
    assert_eq!(
        refused(p.stage([1; 16], &media).await),
        PoolSessionRefusal::ContentUnavailable
    );
    p.source.publish(&media);
    let mut init = media.files[PROTECTED_CONTENT_INIT_PATH].clone();
    init[0] ^= 0x01;
    p.source
        .replace(&media.cid, PROTECTED_CONTENT_INIT_PATH, init);
    assert_eq!(
        refused(p.stage([2; 16], &media).await),
        PoolSessionRefusal::ContentUnavailable
    );

    // DASH: a manifest that lists other bytes, then a changed init.
    let components = dash_components();
    let dash = dash_item_from(&components);
    p.source.publish(&dash);
    let mut package = components_package_files(&components);
    package[0].1.push(0x00);
    p.source.replace(
        &dash.cid,
        crate::content::CONTENT_OBJECT_MANIFEST_PATH,
        serde_json::to_vec(&dash_manifest_from_files(&package)).unwrap(),
    );
    assert_eq!(
        refused(p.stage([3; 16], &dash).await),
        PoolSessionRefusal::ContentUnavailable
    );
    p.source.publish(&dash);
    let init_path = runtime_media_dash_init_path(components.head.renditions()[0].kind());
    let mut init = dash.files[&init_path].clone();
    init[0] ^= 0x01;
    p.source.replace(&dash.cid, &init_path, init);
    assert_eq!(
        refused(p.stage([4; 16], &dash).await),
        PoolSessionRefusal::ContentUnavailable
    );

    // Object: a truncated file.
    let object = object_item(0x43);
    p.source.publish(&object);
    let mut framed = object.files[PROTECTED_CONTENT_OBJECT_EPC1_PATH].clone();
    framed.pop();
    p.source
        .replace(&object.cid, PROTECTED_CONTENT_OBJECT_EPC1_PATH, framed);
    assert_eq!(
        refused(p.stage([5; 16], &object).await),
        PoolSessionRefusal::ContentUnavailable
    );

    // An identity that is not the binding's content is refused before any
    // fetch.
    let reads = p.source.reads().len();
    let elsewhere = object_item(0x44);
    let mut content = elsewhere.content_ref();
    content.cid = object.cid.clone();
    assert_eq!(
        refused(p.port.stage([6; 16], &content, &object.binding()).await),
        PoolSessionRefusal::ContentUnavailable
    );
    assert_eq!(p.source.reads().len(), reads);
}

#[tokio::test]
async fn staged_files_removed_at_close() {
    use std::os::unix::fs::PermissionsExt as _;

    // The port: the object is staged owner-only, and discard removes it.
    let p = port();
    let object = object_item(0x51);
    p.source.publish(&object);
    p.stage([7; 16], &object).await.unwrap();
    let dir = p.root.join(hex::encode([7u8; 16]));
    let staged = dir.join(STAGED_OBJECT_FILE);
    assert_eq!(
        std::fs::read(&staged).unwrap(),
        object.files[PROTECTED_CONTENT_OBJECT_EPC1_PATH]
    );
    assert_eq!(
        std::fs::metadata(&staged).unwrap().permissions().mode() & 0o777,
        0o600
    );
    p.port.discard([7; 16]);
    assert!(!dir.exists());
    // Discarding again, or a session never staged, is quiet.
    p.port.discard([7; 16]);
    p.port.discard([8; 16]);

    // Through the target: `session.close` removes the session's stage.
    let h = harness(false).await;
    let item = published(PoolSessionContentKindV1::Object);
    h.round_trip(&item).await;
    let left: Vec<_> = std::fs::read_dir(&h.stage_root)
        .map(|entries| entries.collect())
        .unwrap_or_default();
    assert!(left.is_empty(), "no session stage is left after close");
}

/// OPEN-LOOP F2: an operator sees a refused custody-pool request at WARN,
/// with its op and code and nothing else of the request.
#[tokio::test]
async fn a_refused_request_is_logged_at_warn_with_its_op_and_code() {
    #[derive(Clone)]
    struct LogWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for LogWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = LogWriter(std::sync::Arc::clone(&output));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let h = harness(true).await;
    let item = published(PoolSessionContentKindV1::Object);
    h.source.publish(&item);
    // A test on another thread may register this callsite while this one
    // sets its subscriber, caching it as disabled; a rebuild after that
    // registration settles it, so the request is asked again at most twice.
    let mut logged = String::new();
    for _ in 0..3 {
        tracing::callsite::rebuild_interest_cache();
        assert_eq!(
            h.code(OP_CUSTODY_POOL_SESSION_PREPARE, item.prepare_fields())
                .await,
            "server_not_ready"
        );
        logged = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        if !logged.is_empty() {
            break;
        }
    }
    let line = logged
        .lines()
        .find(|line| line.contains("custody-pool request refused"))
        .unwrap_or_else(|| panic!("no WARN refusal line in {logged:?}"));
    assert!(line.contains("WARN"), "{line}");
    assert!(
        line.contains(&format!("op={OP_CUSTODY_POOL_SESSION_PREPARE}")),
        "{line}"
    );
    assert!(line.contains("code=server_not_ready"), "{line}");
    // Only the op and the code: none of the request's fields.
    assert!(!line.contains(item.cid.as_str()), "{line}");
    assert!(!line.contains("binding"), "{line}");
}

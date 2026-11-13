//! Plan B T3.1: V2 pool viewer sessions. A V2 prepared recipient keeps the
//! Runtime issuer its prepare declared, a V2 open authenticates the release
//! under that issuer, and every part leaves the provider sealed to the delivery
//! key the wallet signed. V1 sessions and the trusted issuer are unchanged.

use super::*;

use ed25519_dalek::{Signer as _, SigningKey};
use elastos_protected_content_contracts::test_fixtures::{
    node_public_key as pool_node_public_key, pool_authority, pool_bundle_with,
    pool_release_fixture, signed_node_rights_decision, signing_key, PoolReleaseFixtureV1,
    PoolReleaseSpecV1, CUSTODY_KEY_SEED_BASE,
};
use elastos_protected_content_contracts::{
    validate_custody_epoch_for_release_at, CanonicalContract, CustodyEnvelopeV1,
    CustodyNodeProvisioningRecordV1, DeliveryPublicKeyBytesV1, Digest32,
    EncryptedContentIdentityV1, KeyReleaseOutcomeV1, NodeContributionRefV1, PoolEpochBundleV1,
    ProtectedContentBindingV1, RecipientPublicKeyBytesV1, RightsActionV1, RightsDecisionV1,
    SignedNodeContributionV1, SignedTerminalReceiptV1, TerminalReceiptIssuerKey,
    TerminalReceiptStatementV1, ValidatedCustodyCommitteeV1, ViewerPartAadV1, ViewerPartIndexV1,
    PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES,
};
use elastos_protected_content_custody::{
    open_viewer_part_v1, provision_custody_envelope, wrap_content_key_to_decrypt_session,
    ContentEncryptionKeyV1, DeliverySecretKeyV1, NodeCustodySecretKeyV1, NodeLocalShareStoreV1,
    PAYLOAD_PLAINTEXT_CHUNK_BYTES_V1,
};
use elastos_protected_content_provider_contracts::{
    CencFmp4MediaIdentityV1, ChunkedPayloadObjectIdentityV1, DecryptProviderRequestV1,
    DecryptProviderResponseStatusV1, DecryptViewerContentV1, ViewerMediaPartSelectorV1,
};
use rand::rngs::StdRng;
use zeroize::Zeroizing;

use crate::support::{
    self,
    dash::{
        dash_proof, media_dash_components_for, DashCommittee, DashComponents, DashOptions, A, V,
    },
};

const NOW: u64 = 2_000_000_000;
/// The issuer the provider is configured to trust for V1 ops.
const TRUSTED_RUNTIME_SEED: u8 = 0x42;
/// The buyer Runtime that declares the V2 operation (the fixture's default).
const POOL_RUNTIME_SEED: u8 = 0x43;
const PREPARE_AT: u64 = NOW + 1;
const OPEN_AT: u64 = NOW + 7;
const READ_AT: u64 = NOW + 8;
/// The fixture operation runs from `NOW + 2` to `NOW + 40`.
const OPERATION_EXPIRES_AT: u64 = NOW + 40;
const DELIVERY_SEED: u8 = 0x5e;
/// The KID every test item's tracks and Elastos header name.
const ITEM_KID: [u8; 16] = [0x44; 16];
const SESSION_ID: [u8; 16] = [0x5a; 16];

/// The X-Wing public key whose secret is `[seed; 32]`, as the fixture's
/// custody keys are.
fn xwing(seed: u8) -> [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
    *NodeCustodySecretKeyV1::from_guarded_bytes(Zeroizing::new([seed; 32]))
        .unwrap()
        .public_key()
        .unwrap()
        .as_bytes()
}

fn delivery_secret(seed: u8) -> DeliverySecretKeyV1 {
    DeliverySecretKeyV1::from_guarded_bytes(Zeroizing::new([seed; 32])).unwrap()
}

fn configured_provider() -> DecryptProvider {
    let mut provider = DecryptProvider::new();
    let init = provider.init(json!({
        "base_path": "",
        "allowed_paths": [],
        "read_only": false,
        "encryption_key": "",
        "extra": {
            "trusted_runtime_issuer": format!(
                "0x{}",
                hex::encode(support::runtime_signing_key(TRUSTED_RUNTIME_SEED).verifying_key().to_bytes())
            )
        }
    }));
    assert!(matches!(init, ProviderResponse::Ok { .. }));
    provider
}

/// Sends one request on the local provider plane; returns the raw answer.
fn send(provider: &mut DecryptProvider, request: &DecryptProviderRequestV1, now: u64) -> Value {
    let mut value = serde_json::to_value(request).unwrap();
    let op = value["op"].as_str().unwrap().to_string();
    value["_runtime_invocation"] = json!({
        "schema": "elastos.provider.invocation/v1",
        "source": "runtime",
        "target": PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET,
        "op": op,
        "capability": format!("provider:runtime->{PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET}:{op}"),
        "transport": "runtime-local-provider-plane",
        "carrier": null,
        "transfer": "json",
        "range": null,
        "progress": null,
        "abi": expected_local_json_runtime_invocation_abi()
    });
    serde_json::to_value(provider.handle_line_at(&value.to_string(), now)).unwrap()
}

fn typed(answer: Value) -> DecryptProviderResponseV1 {
    assert_eq!(answer["status"], "ok", "{answer}");
    DecryptProviderResponseV1::from_json_slice(&serde_json::to_vec(&answer["data"]).unwrap())
        .unwrap()
}

fn failure_code(answer: Value) -> ProviderFailureCodeV1 {
    typed(answer).failure_code().unwrap()
}

fn assert_invalid_request(answer: &Value) {
    assert_eq!(answer["status"], "error", "{answer}");
    assert_eq!(answer["code"], REQUEST_ERROR_CODE, "{answer}");
}

// ---------------------------------------------------------------------------
// Items kept by the fixture pool committee
// ---------------------------------------------------------------------------

enum ItemContent {
    MediaV1 {
        identity: CencFmp4MediaIdentityV1,
        init: Vec<u8>,
        segments: Vec<Vec<u8>>,
        cek: ContentEncryptionKeyV1,
    },
    Dash(DashComponents),
    Object {
        identity: ChunkedPayloadObjectIdentityV1,
        framed_header: Vec<u8>,
        framed_chunks: Vec<Vec<u8>>,
        chunks: Vec<Vec<u8>>,
    },
}

struct PoolItem {
    member_window: Option<(u64, u64)>,
    /// The release policy's content access id (the header's KID is `0x44`).
    kid: [u8; 16],
    envelope: CustodyEnvelopeV1,
    content: ItemContent,
}

#[derive(Clone, Copy)]
enum Kind {
    MediaV1,
    Dash,
    Object,
}

fn pool_committee(bundle: &PoolEpochBundleV1) -> ValidatedCustodyCommitteeV1 {
    validate_custody_epoch_for_release_at(
        pool_authority(),
        bundle
            .signed_committee_authorization()
            .authorization_identity()
            .unwrap(),
        bundle.signed_pool(),
        bundle.signed_epoch(),
        bundle.signed_committee_authorization(),
        NOW,
    )
    .unwrap()
}

fn pool_item(kind: Kind, member_window: Option<(u64, u64)>) -> PoolItem {
    let bundle = pool_bundle_with(xwing, NOW, member_window, None);
    let committee = pool_committee(&bundle);
    let (envelope, content) = match kind {
        Kind::MediaV1 => {
            let (init, segments, _, _) = support::media_components(0x21);
            let identity = support::media_identity(0x21);
            let cek = ContentEncryptionKeyV1::generate().unwrap();
            let envelope =
                provision_custody_envelope(identity.encrypted_content().clone(), &cek, &committee)
                    .unwrap();
            (
                envelope,
                ItemContent::MediaV1 {
                    identity,
                    init,
                    segments,
                    cek,
                },
            )
        }
        Kind::Dash => {
            let components = media_dash_components_for(
                0x31,
                &DashCommittee {
                    pool: bundle.signed_pool().pool_identity().unwrap(),
                    epoch: bundle.epoch_identity().unwrap(),
                    authorization: bundle
                        .signed_committee_authorization()
                        .authorization_identity()
                        .unwrap(),
                    committee,
                },
                DashOptions::default(),
            );
            (components.envelope.clone(), ItemContent::Dash(components))
        }
        Kind::Object => {
            // Every chunk but the last is a full chunk.
            let chunks = vec![
                vec![0x31; PAYLOAD_PLAINTEXT_CHUNK_BYTES_V1 as usize],
                vec![0x32; 37],
            ];
            let (framed_header, framed_chunks, identity, envelope) =
                support::object_components_for("application/octet-stream", &chunks, &committee);
            (
                envelope,
                ItemContent::Object {
                    identity,
                    framed_header,
                    framed_chunks,
                    chunks,
                },
            )
        }
    };
    PoolItem {
        member_window,
        kid: ITEM_KID,
        envelope,
        content,
    }
}

impl PoolItem {
    fn encrypted_content(&self) -> EncryptedContentIdentityV1 {
        self.envelope.manifest().encrypted_content().clone()
    }

    fn commitment(&self) -> Digest32 {
        self.envelope.manifest().content_key_commitment()
    }

    fn content(&self) -> DecryptViewerContentV1<'_> {
        match &self.content {
            ItemContent::MediaV1 { identity, init, .. } => DecryptViewerContentV1::MediaV1 {
                identity,
                protected_init_segment: init,
            },
            ItemContent::Dash(components) => DecryptViewerContentV1::DashV2 {
                identity: &components.head,
                protected_init_segments: &components.protected_inits,
            },
            ItemContent::Object {
                identity,
                framed_header,
                ..
            } => DecryptViewerContentV1::Object {
                identity,
                framed_header,
            },
        }
    }

    /// The release spec for this item, naming `recipient_key` (or a seeded
    /// key) and the delivery key the wallet signs.
    fn spec(
        &self,
        recipient_key: Option<RecipientPublicKeyBytesV1>,
        delivery: &DeliverySecretKeyV1,
    ) -> PoolReleaseSpecV1 {
        let mut spec = PoolReleaseSpecV1::new(
            xwing,
            support::policy_body_for_kid(self.encrypted_content(), self.kid),
            NOW,
        );
        spec.recipients = vec![(0x09, 1)];
        spec.recipient_public_keys = recipient_key.map(|key| vec![key]);
        spec.delivery_key = Some(delivery.public_key().unwrap().identity());
        spec.key_envelope = Some(self.envelope.key_envelope_identity().unwrap());
        spec.member_window = self.member_window;
        spec
    }

    /// The release binding: it does not depend on the recipients.
    fn binding(&self) -> ProtectedContentBindingV1 {
        pool_release_fixture(&self.spec(None, &delivery_secret(DELIVERY_SEED))).binding
    }
}

// ---------------------------------------------------------------------------
// Releases: real contributions from fixture nodes 1 and 2 (2-of-3)
// ---------------------------------------------------------------------------

struct PoolRelease {
    fixture: PoolReleaseFixtureV1,
    contributions: Vec<SignedNodeContributionV1>,
    receipt: SignedTerminalReceiptV1,
}

impl PoolRelease {
    fn audit(&self) -> RuntimeReleaseAuditIdV1 {
        self.fixture.operation.statement().audit_request_id()
    }

    fn operation_hash(&self) -> Digest32 {
        self.fixture.authenticated().operation_hash()
    }
}

/// Node `node`'s contribution for the release's one recipient, from a share
/// the node really holds.
fn node_contribution(
    fixture: &PoolReleaseFixtureV1,
    envelope: &CustodyEnvelopeV1,
    node: u8,
) -> SignedNodeContributionV1 {
    let operation = fixture.authenticated();
    let node_key = pool_node_public_key(node);
    let record = CustodyNodeProvisioningRecordV1::new(
        envelope.key_envelope_identity().unwrap(),
        envelope.manifest().clone(),
        node_key,
        envelope.stored_share_for_node(node_key).unwrap().clone(),
    )
    .unwrap();
    let provisioning =
        support::signed_runtime_provisioning_for_record(&record, TRUSTED_RUNTIME_SEED, NOW);
    let node_secret = support::node_custody_secret(CUSTODY_KEY_SEED_BASE + node);
    let temp = tempfile::TempDir::new().unwrap();
    support::tighten_tempdir_permissions(&temp);
    let provisioned = NodeLocalShareStoreV1::new(node_key, temp.path().join("share-store"))
        .provision_node_share(
            &record,
            &provisioning,
            support::runtime_issuer(TRUSTED_RUNTIME_SEED),
            &node_secret,
            NOW,
        )
        .unwrap();
    let decision = signed_node_rights_decision(&operation, node, RightsDecisionV1::Allowed, NOW);
    let mut replay = elastos_protected_content_custody::DurableReplayClaimStoreV1::new(
        node_key,
        temp.path().join("replay"),
    );
    replay
        .claim_or_replay_pool_contributions(
            operation,
            &decision,
            provisioned.node_share(),
            &support::node_signing_key(node),
            &node_secret,
            NOW + 5,
            NOW + 30,
            NOW + 6,
        )
        .unwrap()
        .remove(0)
}

/// A terminal receipt over `contributions`, signed by `issuer_seed`.
fn terminal_receipt(
    fixture: &PoolReleaseFixtureV1,
    contributions: &[SignedNodeContributionV1],
    issuer_seed: u8,
) -> SignedTerminalReceiptV1 {
    let operation = fixture.authenticated();
    let node_set = fixture.node_set();
    let refs = contributions
        .iter()
        .map(|contribution| {
            let recipient = contribution
                .statement()
                .recipient_sealed_contribution()
                .recipient()
                .clone();
            NodeContributionRefV1::from(
                &operation
                    .verify_node_contribution(contribution, &node_set, &recipient, NOW + 6)
                    .unwrap(),
            )
        })
        .collect();
    let key = signing_key(issuer_seed);
    let statement = TerminalReceiptStatementV1::new(
        operation.operation_hash(),
        operation.binding().clone(),
        TerminalReceiptIssuerKey::new(key.verifying_key().to_bytes()).unwrap(),
        KeyReleaseOutcomeV1::Released,
        refs,
        // Inside every contribution's window (`NOW + 5 .. NOW + 30`).
        NOW + 5,
        NOW + 30,
    )
    .unwrap();
    SignedTerminalReceiptV1::new(
        statement.clone(),
        key.sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn pool_release(item: &PoolItem, recipient_key: RecipientPublicKeyBytesV1) -> PoolRelease {
    let fixture =
        pool_release_fixture(&item.spec(Some(recipient_key), &delivery_secret(DELIVERY_SEED)));
    let contributions = [1u8, 2]
        .into_iter()
        .map(|node| node_contribution(&fixture, &item.envelope, node))
        .collect::<Vec<_>>();
    let receipt = terminal_receipt(&fixture, &contributions, POOL_RUNTIME_SEED);
    PoolRelease {
        fixture,
        contributions,
        receipt,
    }
}

// ---------------------------------------------------------------------------
// A V2 session
// ---------------------------------------------------------------------------

struct V2Session {
    provider: DecryptProvider,
    item: PoolItem,
    release: PoolRelease,
    delivery: DeliverySecretKeyV1,
    handle: HandleBytes,
}

fn prepare_v2_request(
    binding: &ProtectedContentBindingV1,
    issuer_seed: u8,
) -> DecryptProviderRequestV1 {
    DecryptProviderRequestV1::new_prepare_recipient_v2(
        binding,
        RuntimeReleaseAuditIdV1::new(Digest32::new([0xa1; 32])).unwrap(),
        RightsActionV1::View,
        support::runtime_issuer(issuer_seed),
        NOW + 250,
    )
    .unwrap()
}

fn open_v2_request(
    session: &V2Session,
    delivery_public_key: &DeliveryPublicKeyBytesV1,
    content_key_commitment: Digest32,
    content: DecryptViewerContentV1<'_>,
    contributions: &[SignedNodeContributionV1],
    receipt: &SignedTerminalReceiptV1,
) -> DecryptProviderRequestV1 {
    DecryptProviderRequestV1::new_open_pool_viewer_session(
        session.handle,
        &session.release.fixture.operation,
        delivery_public_key,
        content_key_commitment,
        content,
        contributions,
        receipt,
    )
    .unwrap()
}

impl V2Session {
    /// Prepares a V2 recipient for an item of `kind` and builds its release;
    /// the session is not open yet.
    fn prepared(kind: Kind, member_window: Option<(u64, u64)>) -> Self {
        let mut provider = configured_provider();
        let item = pool_item(kind, member_window);
        let prepared = typed(send(
            &mut provider,
            &prepare_v2_request(&item.binding(), POOL_RUNTIME_SEED),
            PREPARE_AT,
        ));
        assert_eq!(
            prepared.status(),
            DecryptProviderResponseStatusV1::PreparedRecipient
        );
        let release = pool_release(&item, prepared.recipient_public_key().unwrap());
        Self {
            provider,
            item,
            release,
            delivery: delivery_secret(DELIVERY_SEED),
            handle: *prepared.prepared_recipient_handle().unwrap(),
        }
    }

    fn open_answer(&mut self) -> Value {
        self.open_answer_at(OPEN_AT)
    }

    fn open_answer_at(&mut self, now: u64) -> Value {
        let request = open_v2_request(
            self,
            &self.delivery.public_key().unwrap(),
            self.item.commitment(),
            self.item.content(),
            &self.release.contributions,
            &self.release.receipt,
        );
        send(&mut self.provider, &request, now)
    }

    fn open(kind: Kind) -> Self {
        let mut session = Self::prepared(kind, None);
        let opened = typed(session.open_answer());
        assert_eq!(
            opened.status(),
            DecryptProviderResponseStatusV1::ViewerSessionOpened
        );
        // The viewer handle is the prepared handle.
        assert_eq!(opened.viewer_session_handle().unwrap(), &session.handle);
        session
    }

    fn read_media(&mut self, selector: ViewerMediaPartSelectorV1, now: u64) -> Value {
        let request = DecryptProviderRequestV1::new_read_viewer_media_part_sealed(
            self.release.audit(),
            self.handle,
            selector,
            SESSION_ID,
        )
        .unwrap();
        send(&mut self.provider, &request, now)
    }

    fn read_chunk(&mut self, index: u32, now: u64) -> Value {
        let ItemContent::Object { framed_chunks, .. } = &self.item.content else {
            panic!("an object item");
        };
        let request = DecryptProviderRequestV1::new_read_viewer_object_chunk_sealed(
            self.release.audit(),
            self.handle,
            index,
            &framed_chunks[index as usize],
            SESSION_ID,
        )
        .unwrap();
        send(&mut self.provider, &request, now)
    }

    /// Opens a sealed part with the delivery secret the open named.
    fn open_part(&self, answer: Value, part: ViewerPartIndexV1) -> Vec<u8> {
        let response = typed(answer);
        assert_eq!(
            response.status(),
            DecryptProviderResponseStatusV1::ViewerSealedPart
        );
        let aad = ViewerPartAadV1 {
            session_id: SESSION_ID,
            operation_hash: self.release.operation_hash(),
            part,
        };
        open_viewer_part_v1(&self.delivery, &aad, response.sealed_part().unwrap())
            .unwrap()
            .to_vec()
    }
}

/// The clear bytes a V1 segment decrypts to under `cek`, through the same
/// custody functions the provider uses.
fn expected_v1_segment(
    identity: &CencFmp4MediaIdentityV1,
    init: &[u8],
    encrypted: &[u8],
    index: u32,
    cek: &ContentEncryptionKeyV1,
) -> Vec<u8> {
    let layout = ValidatedCencFmp4MediaSessionLayoutV1::new(identity, init).unwrap();
    let secret = DecryptSessionSecretKeyV1::from_seed([0x77; 32]).unwrap();
    let public = secret.public_key().unwrap();
    let transcript = b"expected-v1-segment".to_vec();
    let wrapped = wrap_content_key_to_decrypt_session(
        cek,
        &public,
        &transcript,
        &mut StdRng::from_seed([0x01; 32]),
    )
    .unwrap();
    decrypt_validated_cenc_fmp4_segment_to_clear_v1(
        &layout,
        encrypted,
        index,
        &secret,
        &wrapped,
        &transcript,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Sealed round trips
// ---------------------------------------------------------------------------

#[test]
fn sealed_read_round_trips_media_v1() {
    let mut session = V2Session::open(Kind::MediaV1);
    let ItemContent::MediaV1 {
        identity,
        init,
        segments,
        cek,
    } = &session.item.content
    else {
        panic!("a V1 media item");
    };
    let layout = ValidatedCencFmp4MediaSessionLayoutV1::new(identity, init).unwrap();
    let expected_init = rewrite_validated_cenc_fmp4_init_to_clear_v1(&layout, init).unwrap();
    let expected_segments = segments
        .iter()
        .enumerate()
        .map(|(index, segment)| expected_v1_segment(identity, init, segment, index as u32, cek))
        .collect::<Vec<_>>();
    let segments = segments.clone();

    let answer = session.read_media(ViewerMediaPartSelectorV1::init(), READ_AT);
    assert_eq!(
        session.open_part(answer, ViewerPartIndexV1::MediaV1Init),
        expected_init
    );
    for (index, segment) in segments.iter().enumerate() {
        let answer = session.read_media(
            ViewerMediaPartSelectorV1::segment(index as u32, segment.clone()).unwrap(),
            READ_AT,
        );
        assert_eq!(
            session.open_part(answer, ViewerPartIndexV1::MediaV1Segment(index as u32)),
            expected_segments[index]
        );
    }
}

#[test]
fn sealed_read_round_trips_dash_v2() {
    let mut session = V2Session::open(Kind::Dash);
    let ItemContent::Dash(components) = &session.item.content else {
        panic!("a DASH item");
    };
    let clear_inits = components.clear_inits.clone();
    let clear_segments = components.clear_segments.clone();
    let protected_segments = components.protected_segments.clone();
    // Both renditions.
    for (rendition, kind) in [V, A].into_iter().enumerate() {
        let answer = session.read_media(
            ViewerMediaPartSelectorV1::init_v2(rendition as u8).unwrap(),
            READ_AT,
        );
        assert_eq!(
            session.open_part(
                answer,
                ViewerPartIndexV1::DashInit {
                    rendition: rendition as u8
                }
            ),
            clear_inits[rendition]
        );
        let segments = &protected_segments[rendition];
        for index in 0..segments.len() {
            let answer = session.read_media(
                ViewerMediaPartSelectorV1::segment_v2(
                    rendition as u8,
                    index as u32,
                    segments[index].clone(),
                    dash_proof(kind, segments, index),
                )
                .unwrap(),
                READ_AT,
            );
            assert_eq!(
                session.open_part(
                    answer,
                    ViewerPartIndexV1::DashSegment {
                        rendition: rendition as u8,
                        index: index as u32,
                    }
                ),
                clear_segments[rendition][index]
            );
        }
    }
}

#[test]
fn sealed_read_round_trips_object() {
    let mut session = V2Session::open(Kind::Object);
    let ItemContent::Object { chunks, .. } = &session.item.content else {
        panic!("an object item");
    };
    let chunks = chunks.clone();
    let last = chunks.len() as u32 - 1;
    // First and last chunk.
    for index in [0, last] {
        let answer = session.read_chunk(index, READ_AT);
        assert_eq!(
            session.open_part(answer, ViewerPartIndexV1::ObjectChunk(index)),
            chunks[index as usize]
        );
    }
}

#[test]
fn a_part_sealed_for_one_session_opens_only_under_its_own_aad() {
    let mut session = V2Session::open(Kind::Object);
    let answer = session.read_chunk(0, READ_AT);
    let response = typed(answer);
    let sealed = response.sealed_part().unwrap().to_vec();
    for aad in [
        ViewerPartAadV1 {
            session_id: [0x5b; 16],
            operation_hash: session.release.operation_hash(),
            part: ViewerPartIndexV1::ObjectChunk(0),
        },
        ViewerPartAadV1 {
            session_id: SESSION_ID,
            operation_hash: session.release.operation_hash(),
            part: ViewerPartIndexV1::ObjectChunk(1),
        },
    ] {
        assert!(open_viewer_part_v1(&session.delivery, &aad, &sealed).is_err());
    }
    // Another delivery key opens nothing.
    let aad = ViewerPartAadV1 {
        session_id: SESSION_ID,
        operation_hash: session.release.operation_hash(),
        part: ViewerPartIndexV1::ObjectChunk(0),
    };
    assert!(open_viewer_part_v1(&delivery_secret(DELIVERY_SEED + 1), &aad, &sealed).is_err());
}

// ---------------------------------------------------------------------------
// The V2 open's checks
// ---------------------------------------------------------------------------

#[test]
fn guard_v2_open_with_receipt_from_other_issuer_is_refused() {
    let mut session = V2Session::prepared(Kind::Object, None);
    let other_receipt = terminal_receipt(
        &session.release.fixture,
        &session.release.contributions,
        POOL_RUNTIME_SEED + 1,
    );
    let request = open_v2_request(
        &session,
        &session.delivery.public_key().unwrap(),
        session.item.commitment(),
        session.item.content(),
        &session.release.contributions,
        &other_receipt,
    );
    assert_invalid_request(&send(&mut session.provider, &request, OPEN_AT));
    // Nothing was consumed: the prepared recipient still opens.
    typed(session.open_answer());
}

#[test]
fn guard_v2_open_with_missing_contribution_is_refused() {
    let mut session = V2Session::prepared(Kind::Object, None);
    // One contribution of a 2-of-3 committee: the receipt over it does not
    // reach the threshold, so validation refuses the open before key work.
    let one = &session.release.contributions[..1];
    let request = open_v2_request(
        &session,
        &session.delivery.public_key().unwrap(),
        session.item.commitment(),
        session.item.content(),
        one,
        &session.release.receipt,
    );
    assert_invalid_request(&send(&mut session.provider, &request, OPEN_AT));
    typed(session.open_answer());
}

#[test]
fn guard_v2_open_with_contributions_for_another_recipient_is_refused() {
    let mut session = V2Session::prepared(Kind::Object, None);
    // The same item released to a recipient this provider did not prepare.
    let other = pool_release(&session.item, support_recipient_key(0x0b));
    let request = DecryptProviderRequestV1::new_open_pool_viewer_session(
        session.handle,
        &other.fixture.operation,
        &session.delivery.public_key().unwrap(),
        session.item.commitment(),
        session.item.content(),
        &other.contributions,
        &other.receipt,
    )
    .unwrap();
    assert_eq!(
        failure_code(send(&mut session.provider, &request, OPEN_AT)),
        ProviderFailureCodeV1::BindingMismatch
    );
    typed(session.open_answer());
}

/// A recipient public key this provider holds no secret of.
fn support_recipient_key(seed: u8) -> RecipientPublicKeyBytesV1 {
    RecipientPublicKeyBytesV1::new(xwing(seed)).unwrap()
}

#[test]
fn guard_v2_open_with_a_delivery_key_the_wallet_did_not_sign_is_refused_before_key_work() {
    let mut session = V2Session::prepared(Kind::MediaV1, None);
    let substituted = delivery_secret(DELIVERY_SEED + 1).public_key().unwrap();
    let request = open_v2_request(
        &session,
        &substituted,
        session.item.commitment(),
        session.item.content(),
        &session.release.contributions,
        &session.release.receipt,
    );
    assert_eq!(
        failure_code(send(&mut session.provider, &request, OPEN_AT)),
        ProviderFailureCodeV1::BindingMismatch
    );
    // The prepared recipient stays usable.
    typed(session.open_answer());
}

#[test]
fn guard_v2_open_with_an_identity_not_bound_to_the_release_is_refused_before_key_work() {
    let mut session = V2Session::prepared(Kind::MediaV1, None);
    // Another item's identity and init.
    let (other_init, _, _, _) = support::media_components(0x22);
    let other_identity = support::media_identity(0x22);
    let request = open_v2_request(
        &session,
        &session.delivery.public_key().unwrap(),
        session.item.commitment(),
        DecryptViewerContentV1::MediaV1 {
            identity: &other_identity,
            protected_init_segment: &other_init,
        },
        &session.release.contributions,
        &session.release.receipt,
    );
    assert_invalid_request(&send(&mut session.provider, &request, OPEN_AT));
    typed(session.open_answer());
}

#[test]
fn guard_v2_dash_sealed_read_with_an_altered_proof_is_refused_before_unwrap() {
    let mut session = V2Session::open(Kind::Dash);
    let ItemContent::Dash(components) = &session.item.content else {
        panic!("a DASH item");
    };
    let video = components.protected_segments[0].clone();
    // Segment 1's proof with segment 0's bytes.
    let altered = session.read_media(
        ViewerMediaPartSelectorV1::segment_v2(0, 0, video[0].clone(), dash_proof(V, &video, 1))
            .unwrap(),
        READ_AT,
    );
    assert_eq!(
        failure_code(altered),
        ProviderFailureCodeV1::BindingMismatch
    );
    // The session stays open for a good read.
    let answer = session.read_media(
        ViewerMediaPartSelectorV1::segment_v2(0, 0, video[0].clone(), dash_proof(V, &video, 0))
            .unwrap(),
        READ_AT,
    );
    session.open_part(
        answer,
        ViewerPartIndexV1::DashSegment {
            rendition: 0,
            index: 0,
        },
    );
}

#[test]
fn guard_v2_open_with_an_altered_commitment_opens_no_session() {
    let mut session = V2Session::prepared(Kind::Object, None);
    let request = open_v2_request(
        &session,
        &session.delivery.public_key().unwrap(),
        Digest32::new([0xee; 32]),
        session.item.content(),
        &session.release.contributions,
        &session.release.receipt,
    );
    assert_eq!(
        failure_code(send(&mut session.provider, &request, OPEN_AT)),
        ProviderFailureCodeV1::BindingMismatch
    );
    // No session: a sealed read finds no handle.
    assert_eq!(
        failure_code(session.read_chunk(0, READ_AT)),
        ProviderFailureCodeV1::HandleAbsent
    );
    // The prepared recipient stays usable.
    typed(session.open_answer());
}

#[test]
fn v2_open_after_the_member_term_opens() {
    // The members' signed term ended before the open; the release rule (F1)
    // does not read it, so the item keeps opening.
    let mut session = V2Session::prepared(Kind::Object, Some((NOW - 100, NOW + 4)));
    let opened = typed(session.open_answer());
    assert_eq!(
        opened.status(),
        DecryptProviderResponseStatusV1::ViewerSessionOpened
    );
    let ItemContent::Object { chunks, .. } = &session.item.content else {
        panic!("an object item");
    };
    let first = chunks[0].clone();
    let answer = session.read_chunk(0, READ_AT);
    assert_eq!(
        session.open_part(answer, ViewerPartIndexV1::ObjectChunk(0)),
        first
    );
}

/// Plan B S4 session lifetime (user 2026-11-13 04:45): the V2 viewer
/// session lives to the signed rights expiry (`NOW + 180`), capped by the
/// attestations (`NOW + 200`), past the operation's own expiry, and ends
/// exactly there.
#[test]
fn v2_viewer_session_lives_to_rights_expiry() {
    let mut session = V2Session::open(Kind::Object);
    let session_end = session.release.fixture.authenticated().session_expires_at();
    assert_eq!(session_end, NOW + 180);
    assert!(session_end > OPERATION_EXPIRES_AT);
    let answer = session.read_chunk(0, OPERATION_EXPIRES_AT + 1);
    session.open_part(answer, ViewerPartIndexV1::ObjectChunk(0));
    let answer = session.read_chunk(0, session_end - 1);
    session.open_part(answer, ViewerPartIndexV1::ObjectChunk(0));
    assert_eq!(
        failure_code(session.read_chunk(0, session_end)),
        ProviderFailureCodeV1::HandleAbsent
    );
}

/// Admission needs fresh proofs: an open after the operation expired is
/// refused, although the signed rights are still valid.
#[test]
fn guard_v2_open_after_the_operation_expiry_is_refused() {
    let mut session = V2Session::prepared(Kind::Object, None);
    assert!(session.release.fixture.authenticated().session_expires_at() > OPERATION_EXPIRES_AT);
    // Refused (invalid or typed); nothing opens.
    let answer = session.open_answer_at(OPERATION_EXPIRES_AT);
    let opened = answer["status"] == "ok"
        && typed(answer.clone()).status() == DecryptProviderResponseStatusV1::ViewerSessionOpened;
    assert!(!opened, "{answer}");
    assert_eq!(
        failure_code(session.read_chunk(0, OPERATION_EXPIRES_AT)),
        ProviderFailureCodeV1::HandleAbsent
    );
}

#[test]
fn guard_v2_open_with_another_runtime_issuer_than_the_prepare_is_refused() {
    let mut provider = configured_provider();
    let item = pool_item(Kind::Object, None);
    // Prepared for another Runtime than the one that declares the operation.
    let prepared = typed(send(
        &mut provider,
        &prepare_v2_request(&item.binding(), POOL_RUNTIME_SEED + 1),
        PREPARE_AT,
    ));
    let release = pool_release(&item, prepared.recipient_public_key().unwrap());
    let request = DecryptProviderRequestV1::new_open_pool_viewer_session(
        *prepared.prepared_recipient_handle().unwrap(),
        &release.fixture.operation,
        &delivery_secret(DELIVERY_SEED).public_key().unwrap(),
        item.commitment(),
        item.content(),
        &release.contributions,
        &release.receipt,
    )
    .unwrap();
    assert_eq!(
        failure_code(send(&mut provider, &request, OPEN_AT)),
        ProviderFailureCodeV1::BindingMismatch
    );
}

// ---------------------------------------------------------------------------
// V1 and V2 stay apart
// ---------------------------------------------------------------------------

/// A V1 media session under the trusted issuer, as the V1 tests open it.
fn open_v1_media_session(provider: &mut DecryptProvider) -> (HandleBytes, RuntimeReleaseAuditIdV1) {
    let envelope = support::custody_envelope_for_media(0x21, NOW);
    let binding = support::binding_for_envelope(&envelope);
    let (init, _, _, _) = support::media_components(0x21);
    let identity = support::media_identity(0x21);
    let prepare = DecryptProviderRequestV1::new_prepare_recipient(
        &binding,
        RuntimeReleaseAuditIdV1::new(support::digest(0xa1)).unwrap(),
        RightsActionV1::View,
        support::runtime_issuer(TRUSTED_RUNTIME_SEED),
        NOW,
        NOW + 30,
    )
    .unwrap();
    let prepared = typed(send(provider, &prepare, PREPARE_AT));
    let audit = RuntimeReleaseAuditIdV1::new(support::digest(0xa2)).unwrap();
    let operation = support::make_signed_runtime_release_operation(
        TRUSTED_RUNTIME_SEED,
        audit,
        &envelope,
        prepared.recipient_public_key().unwrap(),
        prepared.recipient_identity().unwrap(),
        NOW,
    );
    let contributions = vec![
        support::make_signed_node_contribution(&operation, &envelope, TRUSTED_RUNTIME_SEED, 1, NOW),
        support::make_signed_node_contribution(&operation, &envelope, TRUSTED_RUNTIME_SEED, 2, NOW),
    ];
    let receipt = support::make_signed_terminal_receipt(&operation, &contributions, 0x61, NOW);
    let open = DecryptProviderRequestV1::new_open_viewer_session(
        *prepared.prepared_recipient_handle().unwrap(),
        &operation,
        TerminalReceiptIssuerKey::new(
            SigningKey::from_bytes(&[0x61; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
        envelope.manifest().content_key_commitment(),
        &identity,
        &init,
        &contributions,
        &receipt,
    )
    .unwrap();
    let opened = typed(send(provider, &open, OPEN_AT));
    (*opened.viewer_session_handle().unwrap(), audit)
}

#[test]
fn guard_sealed_read_on_v1_session_is_refused() {
    let mut provider = configured_provider();
    let (handle, audit) = open_v1_media_session(&mut provider);
    let sealed = DecryptProviderRequestV1::new_read_viewer_media_part_sealed(
        audit,
        handle,
        ViewerMediaPartSelectorV1::init(),
        SESSION_ID,
    )
    .unwrap();
    assert_eq!(
        failure_code(send(&mut provider, &sealed, READ_AT)),
        ProviderFailureCodeV1::InvalidRequest
    );
    // The V1 read still answers in the clear for its own session.
    let clear = DecryptProviderRequestV1::new_read_viewer_media_part(
        audit,
        handle,
        ViewerMediaPartSelectorV1::init(),
    )
    .unwrap();
    assert_eq!(
        typed(send(&mut provider, &clear, READ_AT)).status(),
        DecryptProviderResponseStatusV1::ViewerMediaPart
    );
}

#[test]
fn guard_unsealed_read_on_v2_session_is_refused() {
    let mut media = V2Session::open(Kind::MediaV1);
    let clear = DecryptProviderRequestV1::new_read_viewer_media_part(
        media.release.audit(),
        media.handle,
        ViewerMediaPartSelectorV1::init(),
    )
    .unwrap();
    assert_eq!(
        failure_code(send(&mut media.provider, &clear, READ_AT)),
        ProviderFailureCodeV1::InvalidRequest
    );

    let mut object = V2Session::open(Kind::Object);
    let ItemContent::Object { framed_chunks, .. } = &object.item.content else {
        panic!("an object item");
    };
    let clear_chunk = DecryptProviderRequestV1::new_read_viewer_object_chunk(
        object.release.audit(),
        object.handle,
        0,
        &framed_chunks[0],
    )
    .unwrap();
    assert_eq!(
        failure_code(send(&mut object.provider, &clear_chunk, READ_AT)),
        ProviderFailureCodeV1::InvalidRequest
    );
}

#[test]
fn v1_ops_still_need_trusted_issuer() {
    let mut provider = configured_provider();
    let envelope = support::custody_envelope_for_media(0x21, NOW);
    let binding = support::binding_for_envelope(&envelope);
    // A V1 prepare for an untrusted issuer is refused, as before.
    let untrusted = DecryptProviderRequestV1::new_prepare_recipient(
        &binding,
        RuntimeReleaseAuditIdV1::new(support::digest(0xa3)).unwrap(),
        RightsActionV1::View,
        support::runtime_issuer(POOL_RUNTIME_SEED),
        NOW,
        NOW + 30,
    )
    .unwrap();
    assert_invalid_request(&send(&mut provider, &untrusted, PREPARE_AT));
    // The same issuer is accepted only by the V2 prepare, which declares it.
    let declared = prepare_v2_request(&binding, POOL_RUNTIME_SEED);
    assert_eq!(
        typed(send(&mut provider, &declared, PREPARE_AT)).status(),
        DecryptProviderResponseStatusV1::PreparedRecipient
    );
}

#[test]
fn guard_v1_open_of_a_v2_prepared_recipient_is_refused() {
    let mut provider = configured_provider();
    let envelope = support::custody_envelope_for_media(0x21, NOW);
    let binding = support::binding_for_envelope(&envelope);
    let (init, _, _, _) = support::media_components(0x21);
    let identity = support::media_identity(0x21);
    let prepared = typed(send(
        &mut provider,
        &prepare_v2_request(&binding, TRUSTED_RUNTIME_SEED),
        PREPARE_AT,
    ));
    let audit = RuntimeReleaseAuditIdV1::new(support::digest(0xa2)).unwrap();
    let operation = support::make_signed_runtime_release_operation(
        TRUSTED_RUNTIME_SEED,
        audit,
        &envelope,
        prepared.recipient_public_key().unwrap(),
        prepared.recipient_identity().unwrap(),
        NOW,
    );
    let contributions = vec![
        support::make_signed_node_contribution(&operation, &envelope, TRUSTED_RUNTIME_SEED, 1, NOW),
        support::make_signed_node_contribution(&operation, &envelope, TRUSTED_RUNTIME_SEED, 2, NOW),
    ];
    let receipt = support::make_signed_terminal_receipt(&operation, &contributions, 0x61, NOW);
    let open = DecryptProviderRequestV1::new_open_viewer_session(
        *prepared.prepared_recipient_handle().unwrap(),
        &operation,
        TerminalReceiptIssuerKey::new(
            SigningKey::from_bytes(&[0x61; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
        envelope.manifest().content_key_commitment(),
        &identity,
        &init,
        &contributions,
        &receipt,
    )
    .unwrap();
    assert_eq!(
        failure_code(send(&mut provider, &open, OPEN_AT)),
        ProviderFailureCodeV1::InvalidRequest
    );
}

#[test]
fn status_lists_the_v2_ops() {
    let provider = configured_provider();
    let status = serde_json::to_value(provider.status()).unwrap();
    let operations = status["data"]["supported_operations"].clone();
    for op in [
        "prepare_recipient_v2",
        "open_viewer_session_v2",
        "read_viewer_media_part_sealed",
        "read_viewer_object_chunk_sealed",
    ] {
        assert!(
            operations
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == op),
            "{op}"
        );
    }
}

// ---------------------------------------------------------------------------
// Plan B T3.5: the Elastos header is bound to the release
// ---------------------------------------------------------------------------

/// Which custody pool a test item's Elastos header names.
#[derive(Clone, Copy)]
enum HeaderNames {
    ItsPool,
    AnotherPool,
}

fn another_pool() -> elastos_protected_content_contracts::CustodyPoolIdentityV1 {
    elastos_protected_content_contracts::CustodyPoolIdentityV1::new(Digest32::new([0x99; 32]), 512)
        .unwrap()
}

/// A header naming the fixture committee's epoch and authorization, and its
/// pool or another one.
fn pool_header(
    bundle: &PoolEpochBundleV1,
    names: HeaderNames,
    suite: elastos_protected_content_provider_contracts::CencMediaSuite,
) -> elastos_protected_content_provider_contracts::CustodyProtectionHeader {
    let pool = match names {
        HeaderNames::ItsPool => bundle.signed_pool().pool_identity().unwrap(),
        HeaderNames::AnotherPool => another_pool(),
    };
    elastos_protected_content_provider_contracts::CustodyProtectionHeader::new(
        elastos_protected_content_contracts::ContentAccessIdV1::new(ITEM_KID).unwrap(),
        &pool,
        &bundle.epoch_identity().unwrap(),
        &bundle
            .signed_committee_authorization()
            .authorization_identity()
            .unwrap(),
        suite,
    )
}

/// A V1 media item whose init carries a header naming `names`, kept by the
/// fixture pool committee.
fn media_v1_item_with_header(names: HeaderNames) -> PoolItem {
    let bundle = pool_bundle_with(xwing, NOW, None, None);
    let committee = pool_committee(&bundle);
    let pssh = elastos_protected_content_provider_contracts::PROTECTION
        .encode_custody(&pool_header(
            &bundle,
            names,
            elastos_protected_content_provider_contracts::CencMediaSuite::Fmp4V1,
        ))
        .unwrap();
    let (init, segments, mime_type, codecs) =
        support::media_components_with_pssh(0x21, Some(&pssh));
    let identity =
        CencFmp4MediaIdentityV1::new_from_bytes(&init, &segments, mime_type, codecs).unwrap();
    let cek = ContentEncryptionKeyV1::generate().unwrap();
    let envelope =
        provision_custody_envelope(identity.encrypted_content().clone(), &cek, &committee).unwrap();
    PoolItem {
        member_window: None,
        kid: ITEM_KID,
        envelope,
        content: ItemContent::MediaV1 {
            identity,
            init,
            segments,
            cek,
        },
    }
}

/// A DASH item whose header names another pool than the one keeping it.
fn dash_item_naming_another_pool() -> PoolItem {
    let bundle = pool_bundle_with(xwing, NOW, None, None);
    let components = media_dash_components_for(
        0x31,
        &DashCommittee {
            pool: another_pool(),
            epoch: bundle.epoch_identity().unwrap(),
            authorization: bundle
                .signed_committee_authorization()
                .authorization_identity()
                .unwrap(),
            committee: pool_committee(&bundle),
        },
        DashOptions::default(),
    );
    PoolItem {
        member_window: None,
        kid: ITEM_KID,
        envelope: components.envelope.clone(),
        content: ItemContent::Dash(components),
    }
}

/// Prepares a V2 recipient for `item` and builds its release.
fn prepared_session_for(item: PoolItem) -> V2Session {
    let mut provider = configured_provider();
    let prepared = typed(send(
        &mut provider,
        &prepare_v2_request(&item.binding(), POOL_RUNTIME_SEED),
        PREPARE_AT,
    ));
    let release = pool_release(&item, prepared.recipient_public_key().unwrap());
    V2Session {
        provider,
        item,
        release,
        delivery: delivery_secret(DELIVERY_SEED),
        handle: *prepared.prepared_recipient_handle().unwrap(),
    }
}

/// The open is refused with `BindingMismatch` before any key work, twice:
/// the refusal consumed nothing, so the prepared recipient is still there.
fn assert_refused_and_still_prepared(session: &mut V2Session) {
    for _ in 0..2 {
        assert_eq!(
            failure_code(session.open_answer()),
            ProviderFailureCodeV1::BindingMismatch
        );
    }
}

#[test]
fn guard_header_of_another_pool_is_refused_before_key_work() {
    let mut session = prepared_session_for(dash_item_naming_another_pool());
    assert_refused_and_still_prepared(&mut session);
}

#[test]
fn guard_header_with_other_kid_is_refused() {
    // The header names the item's tracks' KID; the release's policy names
    // another one.
    let mut item = pool_item(Kind::Dash, None);
    item.kid = [0x45; 16];
    let mut session = prepared_session_for(item);
    assert_refused_and_still_prepared(&mut session);
}

#[test]
fn v1_media_without_header_still_opens() {
    // Develop behaviour: V1 media minted before the header existed plays.
    let mut session = prepared_session_for(pool_item(Kind::MediaV1, None));
    assert_eq!(
        typed(session.open_answer()).status(),
        DecryptProviderResponseStatusV1::ViewerSessionOpened
    );
}

#[test]
fn guard_v1_media_with_a_mismatching_header_is_refused() {
    // A V2 session.
    let mut session = prepared_session_for(media_v1_item_with_header(HeaderNames::AnotherPool));
    assert_refused_and_still_prepared(&mut session);

    // A V1 session: the header names another pool than the V1 envelope's.
    let mut provider = configured_provider();
    let committee = DashCommittee::v1(NOW);
    let header = elastos_protected_content_provider_contracts::CustodyProtectionHeader::new(
        elastos_protected_content_contracts::ContentAccessIdV1::new(ITEM_KID).unwrap(),
        &another_pool(),
        &committee.epoch,
        &committee.authorization,
        elastos_protected_content_provider_contracts::CencMediaSuite::Fmp4V1,
    );
    let answer = open_v1_session_with_header(&mut provider, &header);
    assert_eq!(failure_code(answer), ProviderFailureCodeV1::BindingMismatch);
}

/// T3.5: pins V1 media init compatibility with the custody header check.
#[test]
fn v1_init_box_compatibility_is_pinned() {
    // A V1 item whose header names another pool is refused.
    let item = media_v1_item_with_header(HeaderNames::AnotherPool);
    let ItemContent::MediaV1 {
        identity: minted, ..
    } = &item.content
    else {
        panic!("a V1 media item");
    };
    let minted_content = minted.encrypted_content().clone();
    let minted_init_sha256 = minted.init_segment_sha256();
    let mut session = prepared_session_for(item);
    assert_refused_and_still_prepared(&mut session);

    // A second V1 init form with the same encrypted content.
    let (stripped_init, segments, mime_type, codecs) =
        support::media_components_with_pssh(0x21, None);
    let stripped =
        CencFmp4MediaIdentityV1::new_from_bytes(&stripped_init, &segments, mime_type, codecs)
            .unwrap();
    assert_eq!(stripped.encrypted_content(), &minted_content);
    assert_ne!(stripped.init_segment_sha256(), minted_init_sha256);
    let request = open_v2_request(
        &session,
        &session.delivery.public_key().unwrap(),
        session.item.commitment(),
        DecryptViewerContentV1::MediaV1 {
            identity: &stripped,
            protected_init_segment: &stripped_init,
        },
        &session.release.contributions,
        &session.release.receipt,
    );
    assert_eq!(
        typed(send(&mut session.provider, &request, OPEN_AT)).status(),
        DecryptProviderResponseStatusV1::ViewerSessionOpened
    );
}

#[test]
fn matching_header_opens() {
    // V1 media with its header, in a V2 session.
    let mut v1 = prepared_session_for(media_v1_item_with_header(HeaderNames::ItsPool));
    assert_eq!(
        typed(v1.open_answer()).status(),
        DecryptProviderResponseStatusV1::ViewerSessionOpened
    );
    let answer = v1.read_media(ViewerMediaPartSelectorV1::init(), READ_AT);
    v1.open_part(answer, ViewerPartIndexV1::MediaV1Init);

    // DASH v2 in a V2 session: its header names the pool that keeps it.
    V2Session::open(Kind::Dash);

    // V1 media with its header, in a V1 session.
    let mut provider = configured_provider();
    let committee = DashCommittee::v1(NOW);
    let header = elastos_protected_content_provider_contracts::CustodyProtectionHeader::new(
        elastos_protected_content_contracts::ContentAccessIdV1::new(ITEM_KID).unwrap(),
        &committee.pool,
        &committee.epoch,
        &committee.authorization,
        elastos_protected_content_provider_contracts::CencMediaSuite::Fmp4V1,
    );
    assert_eq!(
        typed(open_v1_session_with_header(&mut provider, &header)).status(),
        DecryptProviderResponseStatusV1::ViewerSessionOpened
    );
}

/// Prepares and opens a V1 session (trusted issuer) over V1 media whose init
/// carries `header`; returns the raw open answer.
fn open_v1_session_with_header(
    provider: &mut DecryptProvider,
    header: &elastos_protected_content_provider_contracts::CustodyProtectionHeader,
) -> Value {
    let pssh = elastos_protected_content_provider_contracts::PROTECTION
        .encode_custody(header)
        .unwrap();
    let (init, segments, mime_type, codecs) =
        support::media_components_with_pssh(0x21, Some(&pssh));
    let identity =
        CencFmp4MediaIdentityV1::new_from_bytes(&init, &segments, mime_type, codecs).unwrap();
    // The segments, and so the encrypted content, are those of item 0x21.
    let envelope = support::custody_envelope_for_media(0x21, NOW);
    let binding = support::binding_for_envelope(&envelope);
    let prepare = DecryptProviderRequestV1::new_prepare_recipient(
        &binding,
        RuntimeReleaseAuditIdV1::new(support::digest(0xa1)).unwrap(),
        RightsActionV1::View,
        support::runtime_issuer(TRUSTED_RUNTIME_SEED),
        NOW,
        NOW + 30,
    )
    .unwrap();
    let prepared = typed(send(provider, &prepare, PREPARE_AT));
    let audit = RuntimeReleaseAuditIdV1::new(support::digest(0xa2)).unwrap();
    let operation = support::make_signed_runtime_release_operation(
        TRUSTED_RUNTIME_SEED,
        audit,
        &envelope,
        prepared.recipient_public_key().unwrap(),
        prepared.recipient_identity().unwrap(),
        NOW,
    );
    let contributions = vec![
        support::make_signed_node_contribution(&operation, &envelope, TRUSTED_RUNTIME_SEED, 1, NOW),
        support::make_signed_node_contribution(&operation, &envelope, TRUSTED_RUNTIME_SEED, 2, NOW),
    ];
    let receipt = support::make_signed_terminal_receipt(&operation, &contributions, 0x61, NOW);
    let open = DecryptProviderRequestV1::new_open_viewer_session(
        *prepared.prepared_recipient_handle().unwrap(),
        &operation,
        TerminalReceiptIssuerKey::new(
            SigningKey::from_bytes(&[0x61; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
        envelope.manifest().content_key_commitment(),
        &identity,
        &init,
        &contributions,
        &receipt,
    )
    .unwrap();
    send(provider, &open, OPEN_AT)
}

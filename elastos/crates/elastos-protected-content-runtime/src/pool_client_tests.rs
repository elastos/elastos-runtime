//! Plan B T4.2: the resolver, server selection, stripes and the pool session
//! client against fake sources and a fake transport.

use std::collections::VecDeque;
use std::sync::Mutex;

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use elastos_protected_content_contracts::test_fixtures::{
    historical_v2_descriptor_with, key_envelope_for, node_public_key, pool_authority, pool_bundle,
    pool_bundle_with, pool_descriptor_with, pool_did, pool_release_fixture,
    recipient_attestation_statement_for_key, runtime_issuer, signing_key, PoolReleaseFixtureV1,
    PoolReleaseSpecV1, CUSTODY_KEY_SEED_BASE, POOL_AUTHORITY_SEED,
};
use elastos_protected_content_contracts::{
    CanonicalContract, ContentAccessIdV1, CustodyApprovedSuitesV1,
    CustodyCommitteeAuthorizationStatementV1, CustodyEpochStatementV1, CustodyNodeIdentityV1,
    CustodyPoolFailureDomainIdV1, CustodyPoolMemberStateV1, CustodyPoolMemberV1,
    CustodyPoolOperatorIdV1, CustodyPoolStatementV1, Digest32, EncryptedContentIdentityV1,
    EvmContractAddressV1, EvmFunctionSelectorV1, EvmRightsMethodAbiV1, KeyEnvelopeIdentityV1,
    MintPolicyV1, NodeCustodyPublicKeyV1, NodePublicKey, PoolDescriptorStatementV3,
    PoolEpochBundleV1, PoolMemberRolesV1, PoolMemberRouteV2, PoolMemberV2, PoolMemberV3,
    PoolSessionContentKindV1, PoolTrustModeV1, RecipientPublicKeyBytesV1, RightsActionV1,
    RightsObservationFinalityV1, RightsPolicyBodyV1, RightsSubjectSourceV1, ServePolicyV1,
    ShareCoordinateV1, SignedCustodyCommitteeAuthorizationV1, SignedCustodyEpochV1,
    SignedCustodyPoolV1, SignedNodeContributionV1, SignedPoolDescriptorAnyV1,
    SignedPoolDescriptorV3, SignedPoolRecipientAttestationV2, SignedRuntimeReleaseOperationV2,
    SignedTerminalReceiptV1, ThresholdV1, ViewerPartIndexV1, CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use crate::pool_client::*;
use crate::pool_session::{
    PoolContentIdentityV1, PoolSessionContentRefV1, PoolSessionOpenV1, PoolSessionPrepareV1,
    PoolSessionReadV1, PoolSessionRefusal,
};
use crate::pool_session_tests::{delivery_public_key, release_for, xwing};

const NOW: u64 = 2_000_000_000;
const RUNTIME_SEED: u8 = 0x43;
const DELIVERY_SEED: u8 = 0x5e;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(value: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value.as_str().unwrap())
        .unwrap()
}

/// The v3 descriptor writers emit (#388 A2), as the resolver's sources read
/// it.
fn descriptor(
    sequence: u64,
    serve: ServePolicyV1,
    non_serving: Option<u8>,
) -> SignedPoolDescriptorAnyV1 {
    pool_descriptor_with(
        &pool_bundle(xwing, NOW),
        sequence,
        serve,
        non_serving,
        runtime_issuer(RUNTIME_SEED),
        NOW,
    )
    .into()
}

fn encrypted_content() -> EncryptedContentIdentityV1 {
    crate::test_object::object_identity(0x21)
        .encrypted_content()
        .clone()
}

/// The item's key envelope, naming the fixture pool's one committee.
fn item_key_envelope() -> KeyEnvelopeIdentityV1 {
    key_envelope_for(&pool_bundle(xwing, NOW), &encrypted_content())
}

/// A source that answers the same descriptors whatever the item.
struct Fixed {
    name: &'static str,
    descriptors: Vec<SignedPoolDescriptorAnyV1>,
}

#[async_trait::async_trait]
impl PoolResolverSource for Fixed {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn candidates(
        &self,
        _key_envelope: &KeyEnvelopeIdentityV1,
    ) -> Vec<SignedPoolDescriptorAnyV1> {
        self.descriptors.clone()
    }
}

fn source(
    name: &'static str,
    descriptors: Vec<SignedPoolDescriptorAnyV1>,
) -> Box<dyn PoolResolverSource> {
    Box::new(Fixed { name, descriptors })
}

struct RefuseAll;

impl PoolTrustCheck for RefuseAll {
    fn accept(
        &self,
        _descriptor: &elastos_protected_content_contracts::VerifiedPoolDescriptorV1,
    ) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// A second committee (nodes 1, 2 and 4) for the epoch-aware selection test.
// It follows the contracts fixture's `pool_bundle_with`.
// ---------------------------------------------------------------------------

fn suites() -> CustodyApprovedSuitesV1 {
    CustodyApprovedSuitesV1::new(
        CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
    )
    .unwrap()
}

fn sign(bytes: &[u8]) -> Vec<u8> {
    signing_key(POOL_AUTHORITY_SEED)
        .sign(bytes)
        .to_bytes()
        .to_vec()
}

fn bundle_for_nodes(seeds: [u8; 3]) -> PoolEpochBundleV1 {
    let custody_key =
        |seed: u8| NodeCustodyPublicKeyV1::new(xwing(CUSTODY_KEY_SEED_BASE + seed)).unwrap();
    let members = seeds
        .iter()
        .map(|seed| {
            CustodyPoolMemberV1::new(
                node_public_key(*seed),
                custody_key(*seed),
                CustodyPoolOperatorIdV1::new([0xa0 + seed; 32]),
                CustodyPoolFailureDomainIdV1::new([0xc0 + seed; 32]),
                suites(),
                (NOW - 10, NOW + 86_400),
                CustodyPoolMemberStateV1::Active,
            )
            .unwrap()
        })
        .collect();
    let pool_statement = CustodyPoolStatementV1::new(pool_authority(), members).unwrap();
    let pool = SignedCustodyPoolV1::new(
        pool_statement.clone(),
        sign(&pool_statement.canonical_bytes().unwrap()),
    )
    .unwrap();
    let nodes = seeds
        .iter()
        .enumerate()
        .map(|(index, seed)| {
            CustodyNodeIdentityV1::new(
                node_public_key(*seed),
                custody_key(*seed),
                ShareCoordinateV1::new(u8::try_from(index + 1).unwrap()).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let epoch_statement = CustodyEpochStatementV1::new(
        pool_authority(),
        suites(),
        ThresholdV1::new(2, 3).unwrap(),
        nodes,
    )
    .unwrap();
    let epoch = SignedCustodyEpochV1::new(
        epoch_statement.clone(),
        sign(&epoch_statement.canonical_bytes().unwrap()),
    )
    .unwrap();
    let authorization_statement = CustodyCommitteeAuthorizationStatementV1::new(
        pool_authority(),
        pool.pool_identity().unwrap(),
        epoch.epoch_identity().unwrap(),
    )
    .unwrap();
    let authorization = SignedCustodyCommitteeAuthorizationV1::new(
        authorization_statement.clone(),
        sign(&authorization_statement.canonical_bytes().unwrap()),
    )
    .unwrap();
    PoolEpochBundleV1::new(pool, epoch, authorization).unwrap()
}

/// One descriptor holding two committees, {1, 2, 3} and {1, 2, 4}; every
/// member serves.
fn two_committee_descriptor() -> (
    SignedPoolDescriptorAnyV1,
    PoolEpochBundleV1,
    PoolEpochBundleV1,
) {
    let first = bundle_for_nodes([1, 2, 3]);
    let second = bundle_for_nodes([1, 2, 4]);
    let members = [1u8, 2, 3, 4]
        .into_iter()
        .map(|seed| {
            PoolMemberV2::new(
                node_public_key(seed),
                PoolMemberRolesV1 {
                    hold: true,
                    serve: true,
                    seal: true,
                },
                PoolMemberRouteV2::new(format!("did:key:z6MkPoolNode{seed:02x}")).unwrap(),
            )
            .and_then(|member| PoolMemberV3::new(member, Vec::new()))
            .unwrap()
        })
        .collect();
    let statement = PoolDescriptorStatementV3::new(
        pool_did(),
        1,
        vec![first.clone(), second.clone()],
        members,
        ServePolicyV1::DEFAULT,
        MintPolicyV1::owner_default(runtime_issuer(RUNTIME_SEED)),
        NOW - 5,
        NOW + 86_400,
        PoolTrustModeV1::WciOperated,
    )
    .unwrap();
    let signed = SignedPoolDescriptorV3::new(
        statement.clone(),
        sign(&statement.canonical_bytes().unwrap()),
    )
    .unwrap();
    (signed.into(), first, second)
}

// ---------------------------------------------------------------------------
// Resolve
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolver_takes_highest_sequence_that_matches_the_item() {
    let default = ServePolicyV1::DEFAULT;
    let resolver = PoolResolver::new(vec![
        source(
            "own",
            vec![descriptor(1, default, None), descriptor(3, default, None)],
        ),
        source(
            "known",
            vec![descriptor(2, default, None), descriptor(3, default, None)],
        ),
    ]);
    let resolved = resolver
        .resolve(&item_key_envelope(), &[], NOW)
        .await
        .unwrap();
    assert_eq!(resolved.descriptor.sequence(), 3);
    // On a tie the earlier source wins.
    assert_eq!(resolved.source, "own");
    assert_eq!(resolved.epoch, pool_bundle(xwing, NOW));
    assert_eq!(resolved.signed, descriptor(3, default, None));
}

/// #388 A2: a historical descriptor (trust absent) only reads; the resolver
/// never opens through it, also at a higher sequence.
#[tokio::test]
async fn resolver_skips_a_historical_descriptor() {
    let historical: SignedPoolDescriptorAnyV1 = historical_v2_descriptor_with(
        &pool_bundle(xwing, NOW),
        5,
        ServePolicyV1::DEFAULT,
        None,
        runtime_issuer(RUNTIME_SEED),
        NOW,
    )
    .into();
    let resolver = PoolResolver::new(vec![source(
        "known",
        vec![
            historical.clone(),
            descriptor(1, ServePolicyV1::DEFAULT, None),
        ],
    )]);
    let resolved = resolver
        .resolve(&item_key_envelope(), &[], NOW)
        .await
        .unwrap();
    assert_eq!(resolved.descriptor.sequence(), 1);
    assert!(resolved.descriptor.trust().is_some());

    let only_historical = PoolResolver::new(vec![source("known", vec![historical])]);
    assert_eq!(
        only_historical
            .resolve(&item_key_envelope(), &[], NOW)
            .await
            .map(|_| ()),
        Err(PoolResolveError::Unresolved)
    );
}

#[tokio::test]
async fn resolver_skips_descriptor_of_another_epoch() {
    // The same pool after a recomposition: its committee is another epoch,
    // and its higher sequence does not count for this item (S4-Q9).
    let other_bundle = pool_bundle_with(xwing, NOW, Some((NOW - 20, NOW + 90_000)), None);
    let other_epoch: SignedPoolDescriptorAnyV1 = pool_descriptor_with(
        &other_bundle,
        9,
        ServePolicyV1::DEFAULT,
        None,
        runtime_issuer(RUNTIME_SEED),
        NOW,
    )
    .into();
    let resolver = PoolResolver::new(vec![source(
        "known",
        vec![
            other_epoch.clone(),
            descriptor(1, ServePolicyV1::DEFAULT, None),
        ],
    )]);
    let resolved = resolver
        .resolve(&item_key_envelope(), &[], NOW)
        .await
        .unwrap();
    assert_eq!(resolved.descriptor.sequence(), 1);

    let only_other = PoolResolver::new(vec![source("known", vec![other_epoch])]);
    assert_eq!(
        only_other.resolve(&item_key_envelope(), &[], NOW).await,
        Err(PoolResolveError::Unresolved)
    );
}

#[tokio::test]
async fn resolve_reports_no_eligible_server() {
    let all_nodes = [node_public_key(1), node_public_key(2), node_public_key(3)];
    let resolver = PoolResolver::new(vec![source(
        "own",
        vec![descriptor(1, ServePolicyV1::DEFAULT, None)],
    )]);
    assert_eq!(
        resolver
            .resolve(&item_key_envelope(), &all_nodes, NOW)
            .await,
        Err(PoolResolveError::NoEligibleServer)
    );
    // Node 1 does not serve: excluding the two others leaves nobody.
    let resolver = PoolResolver::new(vec![source(
        "own",
        vec![descriptor(1, ServePolicyV1::DEFAULT, Some(1))],
    )]);
    assert_eq!(
        resolver
            .resolve(&item_key_envelope(), &all_nodes[1..], NOW)
            .await,
        Err(PoolResolveError::NoEligibleServer)
    );
    // A development pool that allows self-serve keeps its excluded members.
    let self_serve = ServePolicyV1 {
        allow_self_serve: true,
        ..ServePolicyV1::DEFAULT
    };
    let resolver = PoolResolver::new(vec![source("own", vec![descriptor(1, self_serve, None)])]);
    assert!(resolver
        .resolve(&item_key_envelope(), &all_nodes, NOW)
        .await
        .is_ok());
}

#[tokio::test]
async fn resolver_unresolved_without_candidates() {
    assert_eq!(
        PoolResolver::new(Vec::new())
            .resolve(&item_key_envelope(), &[], NOW)
            .await,
        Err(PoolResolveError::Unresolved)
    );
    assert_eq!(
        PoolResolver::new(vec![source("known", Vec::new())])
            .resolve(&item_key_envelope(), &[], NOW)
            .await,
        Err(PoolResolveError::Unresolved)
    );
    // Candidates exist, but none verifies (past their window).
    let resolver = PoolResolver::new(vec![source(
        "known",
        vec![descriptor(1, ServePolicyV1::DEFAULT, None)],
    )]);
    assert_eq!(
        resolver
            .resolve(&item_key_envelope(), &[], NOW + 200_000)
            .await,
        Err(PoolResolveError::Invalid)
    );
    // A verified pool the trust check refuses is not resolved (S5 seam).
    let refused = PoolResolver::new(vec![source(
        "known",
        vec![descriptor(1, ServePolicyV1::DEFAULT, None)],
    )])
    .with_trust_check(Box::new(RefuseAll));
    assert_eq!(
        refused.resolve(&item_key_envelope(), &[], NOW).await,
        Err(PoolResolveError::Unresolved)
    );
}

// ---------------------------------------------------------------------------
// Selection and stripes
// ---------------------------------------------------------------------------

async fn resolved_for(
    descriptor: SignedPoolDescriptorAnyV1,
    key_envelope: &KeyEnvelopeIdentityV1,
) -> ResolvedPoolV1 {
    PoolResolver::new(vec![source("own", vec![descriptor])])
        .resolve(key_envelope, &[], NOW)
        .await
        .unwrap()
}

fn rendezvous_order(seed: [u8; 16], nodes: &[u8]) -> Vec<NodePublicKey> {
    let mut ranked = nodes
        .iter()
        .map(|node| {
            let key = node_public_key(*node);
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(key.as_bytes());
            let weight: [u8; 32] = hasher.finalize().into();
            (weight, key)
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| right.0.cmp(&left.0));
    ranked.into_iter().map(|(_, key)| key).collect()
}

fn keys(members: &[PoolMemberV2]) -> Vec<NodePublicKey> {
    members.iter().map(PoolMemberV2::node_public_key).collect()
}

#[tokio::test]
async fn selection_is_deterministic_and_excludes_self() {
    let resolved = resolved_for(
        descriptor(1, ServePolicyV1::DEFAULT, None),
        &item_key_envelope(),
    )
    .await;
    let seed = [0x3c; 16];
    let first = select_session_servers(&resolved, seed, &[], 3);
    assert_eq!(first, select_session_servers(&resolved, seed, &[], 3));
    assert_eq!(keys(&first), rendezvous_order(seed, &[1, 2, 3]));
    // This Home's own node is excluded (D2).
    let without_self = select_session_servers(&resolved, seed, &[node_public_key(1)], 3);
    assert_eq!(keys(&without_self), rendezvous_order(seed, &[2, 3]));
}

#[tokio::test]
async fn selection_keeps_only_serve_members_of_the_items_epoch() {
    let (signed, first, second) = two_committee_descriptor();
    let seed = [0x51; 16];
    // The item minted under {1, 2, 3}: node 4 serves the pool, but not this
    // item's epoch.
    let resolved = resolved_for(
        signed.clone(),
        &key_envelope_for(&first, &encrypted_content()),
    )
    .await;
    assert_eq!(resolved.epoch, first);
    assert_eq!(
        keys(&select_session_servers(&resolved, seed, &[], 4)),
        rendezvous_order(seed, &[1, 2, 3])
    );
    // An item of the other committee is served by {1, 2, 4}.
    let resolved = resolved_for(signed, &key_envelope_for(&second, &encrypted_content())).await;
    assert_eq!(
        keys(&select_session_servers(&resolved, seed, &[], 4)),
        rendezvous_order(seed, &[1, 2, 4])
    );
    // A member without the serve role is never selected.
    let resolved = resolved_for(
        descriptor(1, ServePolicyV1::DEFAULT, Some(2)),
        &item_key_envelope(),
    )
    .await;
    assert_eq!(
        keys(&select_session_servers(&resolved, seed, &[], 3)),
        rendezvous_order(seed, &[1, 3])
    );
}

#[tokio::test]
async fn selection_returns_wanted_or_fewer() {
    let resolved = resolved_for(
        descriptor(1, ServePolicyV1::DEFAULT, None),
        &item_key_envelope(),
    )
    .await;
    let seed = [0x07; 16];
    assert!(select_session_servers(&resolved, seed, &[], 0).is_empty());
    assert_eq!(select_session_servers(&resolved, seed, &[], 1).len(), 1);
    assert_eq!(
        keys(&select_session_servers(&resolved, seed, &[], 2)),
        rendezvous_order(seed, &[1, 2, 3])[..2].to_vec()
    );
    assert_eq!(select_session_servers(&resolved, seed, &[], 9).len(), 3);
}

#[test]
fn stripes_cover_every_server_and_keep_rendition_init_with_segments() {
    for servers in 1..=4usize {
        let mut used = std::collections::BTreeSet::new();
        for rendition in 0..2u8 {
            for index in 0..8u32 {
                let stripe = stripe_index(
                    &ViewerPartIndexV1::DashSegment { rendition, index },
                    servers,
                );
                assert!(stripe < servers);
                used.insert(stripe);
            }
            // A rendition's init goes with its first segment.
            assert_eq!(
                stripe_index(&ViewerPartIndexV1::DashInit { rendition }, servers),
                stripe_index(
                    &ViewerPartIndexV1::DashSegment {
                        rendition,
                        index: 0
                    },
                    servers
                )
            );
        }
        assert_eq!(
            used,
            (0..servers).collect::<std::collections::BTreeSet<_>>(),
            "{servers} servers"
        );
        assert_eq!(
            stripe_index(&ViewerPartIndexV1::MediaV1Init, servers),
            stripe_index(&ViewerPartIndexV1::MediaV1Segment(0), servers)
        );
        let chunks = (0..8u32)
            .map(|index| stripe_index(&ViewerPartIndexV1::ObjectChunk(index), servers))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            chunks,
            (0..servers).collect::<std::collections::BTreeSet<_>>()
        );
    }
    // With two servers, video and audio start on different servers.
    assert_ne!(
        stripe_index(&ViewerPartIndexV1::DashInit { rendition: 0 }, 2),
        stripe_index(&ViewerPartIndexV1::DashInit { rendition: 1 }, 2)
    );
    assert_eq!(stripe_index(&ViewerPartIndexV1::MediaV1Segment(5), 0), 0);
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

type Call = (PoolMemberRouteV2, &'static str, PoolCallClass, Value);

/// Records every call and answers from a script.
#[derive(Default)]
struct FakeTransport {
    calls: Mutex<Vec<Call>>,
    answers: Mutex<VecDeque<Result<Value, PoolTransportError>>>,
}

impl FakeTransport {
    fn answering(answers: Vec<Result<Value, PoolTransportError>>) -> Self {
        Self {
            calls: Mutex::default(),
            answers: Mutex::new(answers.into()),
        }
    }

    fn last_call(&self) -> Call {
        self.calls.lock().unwrap().last().cloned().unwrap()
    }
}

#[async_trait::async_trait]
impl PoolSessionTransport for &FakeTransport {
    async fn call(
        &self,
        route: &PoolMemberRouteV2,
        op: &'static str,
        class: PoolCallClass,
        body: Value,
    ) -> Result<Value, PoolTransportError> {
        self.calls
            .lock()
            .unwrap()
            .push((route.clone(), op, class, body));
        self.answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(PoolTransportError::Unreachable))
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

fn release() -> PoolReleaseFixtureV1 {
    pool_release_fixture(&PoolReleaseSpecV1::new(
        xwing,
        policy_body(&encrypted_content()),
        NOW,
    ))
}

fn server(seed: u8) -> PoolMemberV2 {
    descriptor(1, ServePolicyV1::DEFAULT, None)
        .verify(NOW)
        .unwrap()
        .member(node_public_key(seed))
        .unwrap()
        .clone()
}

fn prepare_request(fixture: &PoolReleaseFixtureV1) -> PoolSessionPrepareV1 {
    let identity = PoolContentIdentityV1::Object(crate::test_object::object_identity(0x21));
    PoolSessionPrepareV1 {
        pool: pool_did(),
        binding: fixture.binding.clone(),
        action: RightsActionV1::View,
        runtime_operation_issuer: runtime_issuer(RUNTIME_SEED),
        content: PoolSessionContentRefV1 {
            cid: "bafy-pool-item".to_string(),
            kind: identity.kind(),
            identity,
            content_key_commitment: Digest32::new([0xcc; 32]),
        },
        expires_at: NOW + 250,
    }
}

/// What server `server_seed` answers to a prepare: a recipient and its
/// attestation, signed by `signer_seed`.
fn prepare_answer(fixture: &PoolReleaseFixtureV1, server_seed: u8, signer_seed: u8) -> Value {
    let recipient = RecipientPublicKeyBytesV1::new(xwing(0x11)).unwrap();
    let statement = recipient_attestation_statement_for_key(
        &fixture.bundle,
        &fixture.binding,
        runtime_issuer(RUNTIME_SEED),
        recipient,
        server_seed,
        NOW,
    );
    let attestation = SignedPoolRecipientAttestationV2::new(
        statement.clone(),
        signing_key(signer_seed)
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    json!({
        "session_id_hex": hex::encode([0x07; 16]),
        "recipient_public_key_b64": b64(recipient.as_bytes()),
        "attestation_b64": b64(&attestation.canonical_bytes().unwrap()),
    })
}

fn open_request(fixture: &PoolReleaseFixtureV1) -> PoolSessionOpenV1 {
    let (contributions, terminal_receipt) = release_for(fixture);
    PoolSessionOpenV1 {
        session_id: [0x07; 16],
        operation: fixture.operation.clone(),
        delivery_public_key: delivery_public_key(DELIVERY_SEED),
        contributions,
        terminal_receipt,
    }
}

fn object_keys(value: &Value) -> Vec<&str> {
    let mut keys = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys
}

#[tokio::test]
async fn client_maps_wire_refusals_to_codes() {
    // The answer envelope (E12, R5).
    assert_eq!(
        pool_wire_answer(&json!({ "status": "ok", "data": { "expires_at": 1 } })),
        Ok(json!({ "expires_at": 1 }))
    );
    assert_eq!(
        pool_wire_answer(&json!({ "status": "error", "code": "pool_busy" })),
        Err(PoolTransportError::Refused("pool_busy".into()))
    );
    for unreadable in [
        json!({ "status": "ok" }),
        json!({ "status": "ok", "data": "text" }),
        json!({ "status": "error" }),
        json!({ "status": "error", "code": "" }),
        json!({ "status": "error", "code": "x".repeat(65) }),
        json!({ "ok": true }),
        json!("ok"),
    ] {
        assert_eq!(
            pool_wire_answer(&unreadable),
            Err(PoolTransportError::NoExactResult),
            "{unreadable}"
        );
    }
    // Every T3.2 refusal code reads back as its refusal.
    for refusal in [
        PoolSessionRefusal::SelfServe,
        PoolSessionRefusal::NotEligible,
        PoolSessionRefusal::NotReady,
        PoolSessionRefusal::PoolBusy,
        PoolSessionRefusal::Bound("total_bytes"),
        PoolSessionRefusal::UnknownSession,
        PoolSessionRefusal::Expired,
        PoolSessionRefusal::BindingMismatch,
        PoolSessionRefusal::ContentUnavailable,
        PoolSessionRefusal::DecryptUnavailable,
    ] {
        assert_eq!(
            pool_refusal_from_code(refusal.code()).map(|read| read.code()),
            Some(refusal.code())
        );
    }
    assert_eq!(pool_refusal_from_code("invalid_request"), None);
    assert_eq!(pool_refusal_from_code("teapot"), None);
    // Rev 14 (user 2026-11-13 04:45): no renewal, so the total-bytes bound
    // is a bound like the others and has no code of its own.
    assert_eq!(pool_refusal_from_code("session_budget_exhausted"), None);

    // A refusal reaches the caller as its code.
    let fixture = release();
    let transport = FakeTransport::answering(vec![Err(PoolTransportError::Refused(
        "decrypt_unavailable".into(),
    ))]);
    let client = PoolSessionClient::new(&transport);
    assert_eq!(
        client.prepare(&server(1), &prepare_request(&fixture)).await,
        Err(PoolTransportError::Refused("decrypt_unavailable".into()))
    );
}

#[tokio::test]
async fn unreadable_answer_after_open_is_no_exact_result() {
    let fixture = release();
    let request = open_request(&fixture);
    // Rev 14: the session lives to the signed rights expiry, capped by the
    // attestations; the operation's own expiry bounds only the release.
    let expiry = fixture.operation.statement().session_expires_at();
    assert!(expiry > fixture.operation.statement().expires_at());
    for answer in [
        json!({}),
        json!({ "expires_at": "soon" }),
        json!({ "expires_at": expiry + 1 }),
        json!({ "expires_at": fixture.operation.statement().expires_at() }),
    ] {
        let transport = FakeTransport::answering(vec![Ok(answer.clone())]);
        let client = PoolSessionClient::new(&transport);
        assert_eq!(
            client.open(&server(1), &request).await,
            Err(PoolTransportError::NoExactResult),
            "{answer}"
        );
    }

    // The same for every call that may have acted.
    let transport = FakeTransport::answering(vec![
        Ok(json!({ "session_id_hex": "07" })),
        Ok(prepare_answer(&fixture, 2, 2)),
        Ok(prepare_answer(&fixture, 1, 2)),
        Ok(json!({ "sealed_b64": "" })),
        Ok(json!({ "sealed_b64": "not base64!" })),
    ]);
    let client = PoolSessionClient::new(&transport);
    let prepare = prepare_request(&fixture);
    // Garbage.
    assert_eq!(
        client.prepare(&server(1), &prepare).await,
        Err(PoolTransportError::NoExactResult)
    );
    // An attestation for another server than the one asked.
    assert_eq!(
        client.prepare(&server(1), &prepare).await,
        Err(PoolTransportError::NoExactResult)
    );
    // An attestation the named server did not sign.
    assert_eq!(
        client.prepare(&server(1), &prepare).await,
        Err(PoolTransportError::NoExactResult)
    );
    let read = PoolSessionReadV1 {
        session_id: [0x07; 16],
        part: ViewerPartIndexV1::ObjectChunk(0),
    };
    for _ in 0..2 {
        assert_eq!(
            client.read_sealed(&server(1), &read).await,
            Err(PoolTransportError::NoExactResult)
        );
    }

    // `describe` never acts: an answer it cannot use sends the caller to
    // another member.
    let transport = FakeTransport::answering(vec![Ok(json!({ "descriptor_b64": "AAAA" }))]);
    let client = PoolSessionClient::new(&transport);
    assert_eq!(
        client.describe(server(1).route(), &pool_did()).await,
        Err(PoolTransportError::Unreachable)
    );
}

#[tokio::test]
async fn client_encodes_the_rev3_prepare_and_open_fields() {
    let fixture = release();
    let expiry = fixture.operation.statement().session_expires_at();
    let descriptor_bytes = descriptor(1, ServePolicyV1::DEFAULT, None)
        .canonical_bytes()
        .unwrap();
    let transport = FakeTransport::answering(vec![
        Ok(json!({ "descriptor_b64": b64(&descriptor_bytes) })),
        Ok(prepare_answer(&fixture, 1, 1)),
        Ok(json!({ "expires_at": expiry })),
        Ok(json!({ "sealed_b64": b64(&[0x5a; 48]) })),
        Ok(json!({})),
    ]);
    let client = PoolSessionClient::new(&transport);
    let node = server(1);

    // describe
    let described = client.describe(node.route(), &pool_did()).await.unwrap();
    assert_eq!(described.canonical_bytes().unwrap(), descriptor_bytes);
    let (route, op, class, body) = transport.last_call();
    assert_eq!(
        (&route, op, class),
        (node.route(), POOL_OP_DESCRIBE, PoolCallClass::Control)
    );
    assert_eq!(body, json!({ "pool": pool_did().to_did_key().unwrap() }));

    // session.prepare: the typed content reference (F4).
    let prepare = prepare_request(&fixture);
    let prepared = client.prepare(&node, &prepare).await.unwrap();
    assert_eq!(prepared.session_id, [0x07; 16]);
    assert_eq!(
        prepared.recipient_public_key,
        RecipientPublicKeyBytesV1::new(xwing(0x11)).unwrap()
    );
    let (route, op, class, body) = transport.last_call();
    assert_eq!(
        (&route, op, class),
        (
            node.route(),
            POOL_OP_SESSION_PREPARE,
            PoolCallClass::Control
        )
    );
    assert_eq!(
        object_keys(&body),
        [
            "action",
            "binding_b64",
            "content",
            "expires_at",
            "pool",
            "runtime_operation_issuer_hex"
        ]
    );
    assert_eq!(
        object_keys(&body["content"]),
        ["cid", "content_key_commitment_b64", "identity_b64", "kind"]
    );
    assert_eq!(body["pool"], pool_did().to_did_key().unwrap());
    assert_eq!(
        b64_decode(&body["binding_b64"]),
        fixture.binding.canonical_bytes().unwrap()
    );
    assert_eq!(body["action"], RightsActionV1::View as u8);
    assert_eq!(
        body["runtime_operation_issuer_hex"],
        hex::encode(runtime_issuer(RUNTIME_SEED).as_bytes())
    );
    assert_eq!(body["expires_at"], NOW + 250);
    assert_eq!(body["content"]["cid"], "bafy-pool-item");
    assert_eq!(
        body["content"]["kind"],
        content_kind_wire_name(PoolSessionContentKindV1::Object)
    );
    assert_eq!(body["content"]["kind"], "object");
    assert_eq!(
        b64_decode(&body["content"]["identity_b64"]),
        crate::test_object::object_identity(0x21)
            .canonical_bytes()
            .unwrap()
    );
    assert_eq!(
        b64_decode(&body["content"]["content_key_commitment_b64"]),
        [0xcc; 32]
    );

    // session.open: the delivery public key (F3); the answer is the
    // operation's expiry (F6).
    let open = open_request(&fixture);
    let opened = client.open(&node, &open).await.unwrap();
    assert_eq!(opened.expires_at, expiry);
    let (_, op, class, body) = transport.last_call();
    assert_eq!((op, class), (POOL_OP_SESSION_OPEN, PoolCallClass::Control));
    assert_eq!(
        object_keys(&body),
        [
            "contributions_b64",
            "delivery_public_key_b64",
            "operation_v2_b64",
            "session_id_hex",
            "terminal_receipt_b64"
        ]
    );
    assert_eq!(body["session_id_hex"], hex::encode([0x07; 16]));
    assert_eq!(
        b64_decode(&body["delivery_public_key_b64"]),
        delivery_public_key(DELIVERY_SEED).as_bytes()
    );
    assert_eq!(
        SignedRuntimeReleaseOperationV2::from_canonical_bytes(&b64_decode(
            &body["operation_v2_b64"]
        ))
        .unwrap(),
        fixture.operation
    );
    let contributions = body["contributions_b64"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| SignedNodeContributionV1::from_canonical_bytes(&b64_decode(item)).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(contributions, open.contributions);
    assert_eq!(
        SignedTerminalReceiptV1::from_canonical_bytes(&b64_decode(&body["terminal_receipt_b64"]))
            .unwrap(),
        open.terminal_receipt
    );

    // session.read is a Read call carrying only the part.
    let part = ViewerPartIndexV1::DashSegment {
        rendition: 1,
        index: 4,
    };
    let sealed = client
        .read_sealed(
            &node,
            &PoolSessionReadV1 {
                session_id: [0x07; 16],
                part,
            },
        )
        .await
        .unwrap();
    assert_eq!(sealed, vec![0x5a; 48]);
    let (_, op, class, body) = transport.last_call();
    assert_eq!((op, class), (POOL_OP_SESSION_READ, PoolCallClass::Read));
    assert_eq!(
        body,
        json!({
            "session_id_hex": hex::encode([0x07; 16]),
            "part": { "kind": "dash_segment", "rendition": 1, "index": 4 },
        })
    );
    assert_eq!(body["part"], part_json(part));

    // session.close
    client.close(&node, [0x07; 16]).await.unwrap();
    let (_, op, _, body) = transport.last_call();
    assert_eq!(op, POOL_OP_SESSION_CLOSE);
    assert_eq!(body, json!({ "session_id_hex": hex::encode([0x07; 16]) }));
}

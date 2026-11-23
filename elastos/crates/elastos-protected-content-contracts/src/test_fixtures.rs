//! Deterministic Plan B V2 pool-release fixtures.
//!
//! Built only for this crate's tests and with the `test-fixtures` feature,
//! which other crates enable from their dev-dependencies. The crates that carry
//! V2 releases (provider contracts, rights, custody) build the same signed
//! custody committee, pool descriptor, binding and operation here from fixed
//! seeds, instead of each keeping a copy.
//!
//! The caller supplies the X-Wing public key for a seed (`xwing_public_key`),
//! so this module needs no key-generation dependency, and a caller that must
//! also open sealed data uses keys whose secrets it holds.

use ed25519_dalek::{Signer as _, SigningKey};
use k256::ecdsa::SigningKey as WalletSigningKey;
use sha3::{Digest as _, Keccak256};

use crate::{
    AuthenticatedRuntimeReleaseOperationV2, CanonicalContract, CustodyApprovedSuitesV1,
    CustodyCommitteeAuthorizationStatementV1, CustodyEpochIssuerKeyV1, CustodyEpochStatementV1,
    CustodyNodeIdentityV1, CustodyPoolFailureDomainIdV1, CustodyPoolMemberStateV1,
    CustodyPoolMemberV1, CustodyPoolOperatorIdV1, CustodyPoolStatementV1, DeliveryKeyIdentityV1,
    Digest32, EncryptedContentIdentityV1, KeyEnvelopeIdentityV1, MintPolicyV1, NodePublicKey,
    NodeRightsDecisionStatementV1, NodeSetV1, PoolDescriptorStatementV1, PoolDescriptorStatementV2,
    PoolDescriptorStatementV3, PoolDidV1, PoolEpochBundleV1, PoolMemberRolesV1, PoolMemberRouteV1,
    PoolMemberRouteV2, PoolMemberV1, PoolMemberV2, PoolMemberV3,
    PoolRecipientAttestationStatementV1, PoolRecipientAttestationStatementV2,
    PoolSessionRecipientV1, PoolTrustModeV1, ProfileIdentityV1, ProtectedContentBindingV1,
    RecipientKeyIdentityV1, RecipientPublicKeyBytesV1, ReplayNonce16, RightsActionV1,
    RightsDecisionV1, RightsEvaluationEvidenceRequestV1, RightsPolicyBodyV1, RightsRequestV2,
    RuntimeIssuerPolicyV1, RuntimeOperationIssuerKeyV1, RuntimeReleaseAuditIdV1,
    RuntimeReleaseOperationStatementV2, RuntimeSessionBindingV1, ServePolicyV1, ShareCoordinateV1,
    SignedCustodyCommitteeAuthorizationV1, SignedCustodyEpochV1, SignedCustodyPoolV1,
    SignedNodeRightsDecisionV1, SignedPoolDescriptorAnyV1, SignedPoolDescriptorV1,
    SignedPoolDescriptorV2, SignedPoolDescriptorV3, SignedPoolRecipientAttestationAnyV1,
    SignedPoolRecipientAttestationV1, SignedPoolRecipientAttestationV2,
    SignedRuntimeReleaseOperationV2, ThresholdV1, WalletAddress, WalletSignedRightsRequestV2,
    CUSTODY_X_WING_AES256GCM_SUITE_ID_V1, PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES,
};

/// The X-Wing public key bytes for a seed, chosen by the caller.
pub type XWingPublicKeyFn = fn(u8) -> [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES];

/// Signs the pool's custody pool, epoch, committee authorization and
/// descriptor.
pub const POOL_AUTHORITY_SEED: u8 = 0x71;
/// Signs the item's recipient authorization in V1 fixtures; the item's
/// profile here.
pub const PROFILE_SEED: u8 = 0x26;
/// The pool nodes: seeds 1, 2 and 3, a 2-of-3 committee.
pub const POOL_NODE_SEEDS: [u8; 3] = [1, 2, 3];
/// A node's custody key is `xwing_public_key(CUSTODY_KEY_SEED_BASE + node)`.
pub const CUSTODY_KEY_SEED_BASE: u8 = 0x30;

pub fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn node_public_key(seed: u8) -> NodePublicKey {
    NodePublicKey::new(signing_key(seed).verifying_key().to_bytes())
        .expect("fixture node key is a valid Ed25519 key")
}

pub fn runtime_issuer(seed: u8) -> RuntimeOperationIssuerKeyV1 {
    RuntimeOperationIssuerKeyV1::new(signing_key(seed).verifying_key().to_bytes())
        .expect("fixture Runtime key is a valid Ed25519 key")
}

pub fn pool_authority() -> CustodyEpochIssuerKeyV1 {
    CustodyEpochIssuerKeyV1::new(signing_key(POOL_AUTHORITY_SEED).verifying_key().to_bytes())
        .expect("fixture pool authority is a valid Ed25519 key")
}

pub fn pool_did() -> PoolDidV1 {
    PoolDidV1::from_issuer(pool_authority())
}

pub fn wallet_signing_key(seed: u8) -> WalletSigningKey {
    WalletSigningKey::from_slice(&[seed; 32]).expect("fixture wallet key is a valid scalar")
}

pub fn wallet_address(seed: u8) -> WalletAddress {
    let encoded = wallet_signing_key(seed)
        .verifying_key()
        .to_encoded_point(false);
    let digest = Keccak256::digest(&encoded.as_bytes()[1..]);
    WalletAddress::new(
        digest[12..]
            .try_into()
            .expect("a Keccak-256 digest has 20 trailing bytes"),
    )
}

pub fn recipient_public_key(xwing: XWingPublicKeyFn, seed: u8) -> RecipientPublicKeyBytesV1 {
    RecipientPublicKeyBytesV1::new(xwing(seed)).expect("fixture recipient key is X-Wing")
}

pub fn recipient_identity(xwing: XWingPublicKeyFn, seed: u8) -> RecipientKeyIdentityV1 {
    recipient_public_key(xwing, seed)
        .key_identity(CUSTODY_X_WING_AES256GCM_SUITE_ID_V1)
        .expect("fixture recipient identity is valid")
}

fn sign(key: &SigningKey, bytes: &[u8]) -> Vec<u8> {
    key.sign(bytes).to_bytes().to_vec()
}

fn suites() -> CustodyApprovedSuitesV1 {
    CustodyApprovedSuitesV1::new(
        CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
    )
    .expect("fixture suites are valid")
}

/// The pool's one committee: nodes 1–3, 2-of-3, each with its own operator and
/// failure domain, members valid from `now - 10`.
pub fn pool_bundle(xwing: XWingPublicKeyFn, now: u64) -> PoolEpochBundleV1 {
    pool_bundle_with(xwing, now, None, None)
}

/// [`pool_bundle`] with the members' signed window (default
/// `now - 10 .. now + 1 day`) and, optionally, one revoked member.
pub fn pool_bundle_with(
    xwing: XWingPublicKeyFn,
    now: u64,
    member_window: Option<(u64, u64)>,
    revoked_node: Option<u8>,
) -> PoolEpochBundleV1 {
    pool_bundle_signed_by(xwing, now, member_window, revoked_node, POOL_AUTHORITY_SEED)
}

/// [`pool_bundle_with`] signed by `authority_seed`, whose key names the
/// custody pool (another pool's committee of the same nodes).
pub fn pool_bundle_signed_by(
    xwing: XWingPublicKeyFn,
    now: u64,
    member_window: Option<(u64, u64)>,
    revoked_node: Option<u8>,
    authority_seed: u8,
) -> PoolEpochBundleV1 {
    let member_window = member_window.unwrap_or((now - 10, now + 86_400));
    let authority = signing_key(authority_seed);
    let authority_key = CustodyEpochIssuerKeyV1::new(authority.verifying_key().to_bytes())
        .expect("fixture authority is a valid Ed25519 key");
    let members = POOL_NODE_SEEDS
        .iter()
        .map(|seed| {
            CustodyPoolMemberV1::new(
                node_public_key(*seed),
                crate::NodeCustodyPublicKeyV1::new(xwing(CUSTODY_KEY_SEED_BASE + seed))
                    .expect("fixture custody key is X-Wing"),
                CustodyPoolOperatorIdV1::new([0xa0 + seed; 32]),
                CustodyPoolFailureDomainIdV1::new([0xc0 + seed; 32]),
                suites(),
                member_window,
                if revoked_node == Some(*seed) {
                    CustodyPoolMemberStateV1::Revoked
                } else {
                    CustodyPoolMemberStateV1::Active
                },
            )
            .expect("fixture pool member is valid")
        })
        .collect();
    let pool_statement =
        CustodyPoolStatementV1::new(authority_key, members).expect("fixture pool is valid");
    let pool = SignedCustodyPoolV1::new(
        pool_statement.clone(),
        sign(
            &authority,
            &pool_statement.canonical_bytes().expect("pool bytes"),
        ),
    )
    .expect("fixture signed pool is valid");
    let nodes = POOL_NODE_SEEDS
        .iter()
        .enumerate()
        .map(|(index, seed)| {
            CustodyNodeIdentityV1::new(
                node_public_key(*seed),
                crate::NodeCustodyPublicKeyV1::new(xwing(CUSTODY_KEY_SEED_BASE + seed))
                    .expect("fixture custody key is X-Wing"),
                ShareCoordinateV1::new(u8::try_from(index + 1).expect("three nodes"))
                    .expect("fixture share coordinate is valid"),
            )
            .expect("fixture custody node is valid")
        })
        .collect();
    let epoch_statement = CustodyEpochStatementV1::new(
        authority_key,
        suites(),
        ThresholdV1::new(2, 3).expect("2-of-3 is valid"),
        nodes,
    )
    .expect("fixture epoch is valid");
    let epoch = SignedCustodyEpochV1::new(
        epoch_statement.clone(),
        sign(
            &authority,
            &epoch_statement.canonical_bytes().expect("epoch bytes"),
        ),
    )
    .expect("fixture signed epoch is valid");
    let authorization_statement = CustodyCommitteeAuthorizationStatementV1::new(
        authority_key,
        pool.pool_identity().expect("pool identity"),
        epoch.epoch_identity().expect("epoch identity"),
    )
    .expect("fixture authorization is valid");
    let authorization = SignedCustodyCommitteeAuthorizationV1::new(
        authorization_statement.clone(),
        sign(
            &authority,
            &authorization_statement
                .canonical_bytes()
                .expect("authorization bytes"),
        ),
    )
    .expect("fixture signed authorization is valid");
    PoolEpochBundleV1::new(pool, epoch, authorization).expect("fixture bundle is valid")
}

/// A synthetic key envelope identity that names the bundle (custody pool,
/// epoch, authorization, node set, threshold) for `encrypted_content`. Use a
/// real envelope's identity where the envelope itself is checked.
pub fn key_envelope_for(
    bundle: &PoolEpochBundleV1,
    encrypted_content: &EncryptedContentIdentityV1,
) -> KeyEnvelopeIdentityV1 {
    let epoch = bundle.signed_epoch();
    KeyEnvelopeIdentityV1::new(
        encrypted_content.clone(),
        Digest32::new([0x22; 32]),
        512,
        epoch
            .statement()
            .node_set()
            .and_then(|node_set| node_set.node_set_id())
            .expect("fixture node set"),
        epoch.statement().threshold(),
        bundle.signed_pool().pool_identity().expect("pool identity"),
        epoch.epoch_identity().expect("epoch identity"),
        bundle
            .signed_committee_authorization()
            .authorization_identity()
            .expect("authorization identity"),
    )
    .expect("fixture key envelope identity is valid")
}

/// What a V2 pool release is built from.
#[derive(Debug, Clone)]
pub struct PoolReleaseSpecV1 {
    pub xwing_public_key: XWingPublicKeyFn,
    /// The item's rights policy; its encrypted content is the item's.
    pub policy: RightsPolicyBodyV1,
    /// Every window is relative to this time.
    pub now: u64,
    /// The Runtime that signs the operation (any Runtime: V2 is `Declared`).
    pub runtime_seed: u8,
    pub wallet_seed: u8,
    /// The wallet key that signs the rights request; `None` is `wallet_seed`,
    /// the binding's wallet (ADV-02 must-refuse tests sign with another).
    pub wallet_signer_seed: Option<u8>,
    /// `(recipient key seed, serving node seed)`, one per session recipient.
    pub recipients: Vec<(u8, u8)>,
    pub max_servers_per_session: u8,
    /// The item's key envelope identity; `None` uses [`key_envelope_for`].
    pub key_envelope: Option<KeyEnvelopeIdentityV1>,
    pub replay_nonce: u8,
    /// The operation's audit id byte. A node refuses a second release under
    /// one audit id, so each release on one node needs its own.
    pub audit_request_id: u8,
    /// The descriptor's sequence (high-water tests).
    pub descriptor_sequence: u64,
    /// The members' signed window; `None` uses [`pool_bundle`]'s.
    pub member_window: Option<(u64, u64)>,
    pub revoked_node: Option<u8>,
    /// Plan B T3.1: the recipient public keys, in `recipients` order, when a
    /// test holds keys it did not derive from a seed (a decrypt provider's
    /// prepared recipient). `None` derives each from its seed.
    pub recipient_public_keys: Option<Vec<RecipientPublicKeyBytesV1>>,
    /// Plan B T3.1: the wallet-signed delivery key identity. `None` uses a
    /// fixed identity that no delivery key has.
    pub delivery_key: Option<DeliveryKeyIdentityV1>,
    /// Item 10: `true` nests the historical v1 descriptor (no tickets, as
    /// this fixture always built it) for the frozen V-OP vector. Writers emit
    /// the v3 descriptor, the default.
    pub v1_descriptor: bool,
    /// #388 A2: `true` nests the historical v2 descriptor (trust absent) for
    /// the frozen V-OP-2 vector; `v1_descriptor` wins over it.
    pub v2_descriptor: bool,
    /// #388-2: `true` signs historical v1 recipient attestations (trust
    /// absent) for the frozen V-OP vectors. Writers emit v2, the default.
    pub v1_attestations: bool,
    /// Plan B S4 session lifetime: the signed rights expiry; `None` is
    /// `now + 180`. The attestations stay at `now + 200`, so a later value
    /// lets the attestations cap the session.
    pub rights_expires_at: Option<u64>,
}

impl PoolReleaseSpecV1 {
    pub fn new(xwing_public_key: XWingPublicKeyFn, policy: RightsPolicyBodyV1, now: u64) -> Self {
        Self {
            xwing_public_key,
            policy,
            now,
            runtime_seed: 0x43,
            wallet_seed: 7,
            wallet_signer_seed: None,
            recipients: vec![(9, 1)],
            max_servers_per_session: 1,
            key_envelope: None,
            replay_nonce: 0x55,
            audit_request_id: 0x91,
            descriptor_sequence: 1,
            member_window: None,
            revoked_node: None,
            recipient_public_keys: None,
            delivery_key: None,
            v1_descriptor: false,
            v2_descriptor: false,
            v1_attestations: false,
            rights_expires_at: None,
        }
    }

    /// The public key of the `index`-th session recipient.
    fn recipient_public_key(&self, index: usize) -> RecipientPublicKeyBytesV1 {
        match &self.recipient_public_keys {
            Some(keys) => keys[index],
            None => recipient_public_key(self.xwing_public_key, self.recipients[index].0),
        }
    }
}

/// A signed V2 release and what it was built from.
///
/// Windows: descriptor `now - 5 .. now + 1 day`, rights `now .. now + 180`,
/// attestations `now .. now + 200`, operation `now + 2 .. now + 40`.
#[derive(Debug, Clone)]
pub struct PoolReleaseFixtureV1 {
    pub now: u64,
    pub bundle: PoolEpochBundleV1,
    /// The descriptor the operation nests, in its own version (item 10).
    pub descriptor: SignedPoolDescriptorAnyV1,
    pub binding: ProtectedContentBindingV1,
    pub operation: SignedRuntimeReleaseOperationV2,
}

impl PoolReleaseFixtureV1 {
    /// The operation verified by its declared issuer at `now + 3`.
    pub fn authenticated(&self) -> AuthenticatedRuntimeReleaseOperationV2 {
        self.operation
            .verify(RuntimeIssuerPolicyV1::Declared, self.now + 3)
            .expect("fixture operation verifies")
    }

    pub fn node_set(&self) -> NodeSetV1 {
        self.bundle
            .signed_epoch()
            .statement()
            .node_set()
            .expect("fixture node set")
    }
}

/// #388 A2: fixtures emit the v3 descriptor of a `WciOperated` pool, every
/// member slot empty.
pub fn pool_descriptor(
    bundle: &PoolEpochBundleV1,
    max_servers_per_session: u8,
    runtime_owner: RuntimeOperationIssuerKeyV1,
    now: u64,
) -> SignedPoolDescriptorV3 {
    pool_descriptor_with_sequence(bundle, 1, max_servers_per_session, runtime_owner, now)
}

pub fn pool_descriptor_with_sequence(
    bundle: &PoolEpochBundleV1,
    sequence: u64,
    max_servers_per_session: u8,
    runtime_owner: RuntimeOperationIssuerKeyV1,
    now: u64,
) -> SignedPoolDescriptorV3 {
    pool_descriptor_with(
        bundle,
        sequence,
        ServePolicyV1 {
            max_servers_per_session,
            ..ServePolicyV1::DEFAULT
        },
        None,
        runtime_owner,
        now,
    )
}

/// The fixture pool's members, ticketless, where `non_serving_node` (if
/// any) holds and seals but does not serve.
fn fixture_members(non_serving_node: Option<u8>) -> Vec<PoolMemberV2> {
    POOL_NODE_SEEDS
        .iter()
        .map(|seed| {
            PoolMemberV2::new(
                node_public_key(*seed),
                PoolMemberRolesV1 {
                    hold: true,
                    serve: non_serving_node != Some(*seed),
                    seal: true,
                },
                PoolMemberRouteV2::new(format!("did:key:z6MkPoolNode{seed:02x}"))
                    .expect("fixture route is valid"),
            )
            .expect("fixture member is valid")
        })
        .collect()
}

/// Plan B T3.2: a descriptor with `serve_policy`, where `non_serving_node`
/// (if any) holds and seals but does not serve. #388 A2: v3, `WciOperated`.
pub fn pool_descriptor_with(
    bundle: &PoolEpochBundleV1,
    sequence: u64,
    serve_policy: ServePolicyV1,
    non_serving_node: Option<u8>,
    runtime_owner: RuntimeOperationIssuerKeyV1,
    now: u64,
) -> SignedPoolDescriptorV3 {
    let members = fixture_members(non_serving_node)
        .into_iter()
        .map(|member| PoolMemberV3::new(member, Vec::new()).expect("fixture v3 member is valid"))
        .collect();
    let statement = PoolDescriptorStatementV3::new(
        pool_did(),
        sequence,
        vec![bundle.clone()],
        members,
        serve_policy,
        MintPolicyV1::owner_default(runtime_owner),
        now - 5,
        now + 86_400,
        PoolTrustModeV1::WciOperated,
    )
    .expect("fixture descriptor is valid");
    SignedPoolDescriptorV3::new(
        statement.clone(),
        sign(
            &signing_key(POOL_AUTHORITY_SEED),
            &statement.canonical_bytes().expect("descriptor bytes"),
        ),
    )
    .expect("fixture signed descriptor is valid")
}

/// Plan B POOL-MINT: a v3 descriptor of a pool at `sequence`, signed by
/// `authority_seed`, whose key names the pool (the fixture pool for
/// [`POOL_AUTHORITY_SEED`]); member routes are the fixture peer DIDs.
pub fn pool_descriptor_signed_by(
    bundle: &PoolEpochBundleV1,
    sequence: u64,
    now: u64,
    authority_seed: u8,
) -> SignedPoolDescriptorV3 {
    pool_descriptor_routed(bundle, sequence, now, authority_seed, &|seed| {
        format!("did:key:z6MkPoolNode{seed:02x}")
    })
}

/// [`pool_descriptor_signed_by`] with each member's peer DID from `route`,
/// for callers that check routes are canonical `did:key`s.
pub fn pool_descriptor_routed(
    bundle: &PoolEpochBundleV1,
    sequence: u64,
    now: u64,
    authority_seed: u8,
    route: &dyn Fn(u8) -> String,
) -> SignedPoolDescriptorV3 {
    let members = POOL_NODE_SEEDS
        .iter()
        .map(|seed| {
            let member = PoolMemberV2::new(
                node_public_key(*seed),
                PoolMemberRolesV1 {
                    hold: true,
                    serve: true,
                    seal: true,
                },
                PoolMemberRouteV2::new(route(*seed)).expect("fixture route is valid"),
            )
            .expect("fixture member is valid");
            PoolMemberV3::new(member, Vec::new()).expect("fixture v3 member is valid")
        })
        .collect();
    let authority =
        CustodyEpochIssuerKeyV1::new(signing_key(authority_seed).verifying_key().to_bytes())
            .expect("fixture authority is a valid Ed25519 key");
    let statement = PoolDescriptorStatementV3::new(
        PoolDidV1::from_issuer(authority),
        sequence,
        vec![bundle.clone()],
        members,
        ServePolicyV1::DEFAULT,
        MintPolicyV1::owner_default(runtime_issuer(authority_seed)),
        now - 5,
        now + 86_400,
        PoolTrustModeV1::WciOperated,
    )
    .expect("fixture descriptor is valid");
    SignedPoolDescriptorV3::new(
        statement.clone(),
        sign(
            &signing_key(authority_seed),
            &statement.canonical_bytes().expect("descriptor bytes"),
        ),
    )
    .expect("fixture signed descriptor is valid")
}

/// Plan B POOL-MINT: the minting Home `minter_seed`'s signed share statement
/// for one item of `pool`.
pub fn pool_mint_share(
    pool: PoolDidV1,
    key_envelope: &KeyEnvelopeIdentityV1,
    content_access_id: crate::ContentAccessIdV1,
    minter_seed: u8,
) -> crate::SignedPoolMintShareV1 {
    let statement = crate::PoolMintShareStatementV1::new(
        pool,
        runtime_issuer(minter_seed),
        key_envelope.clone(),
        content_access_id,
    )
    .expect("fixture share statement is valid");
    crate::SignedPoolMintShareV1::new(
        statement.clone(),
        sign(
            &signing_key(minter_seed),
            &statement.canonical_bytes().expect("statement bytes"),
        ),
    )
    .expect("fixture signed share statement is valid")
}

/// S7-lite T7.3: a structurally valid one-node provisioning record of the
/// fixture committee for `encrypted_content`. Its sealed share is filler:
/// for wire and routing tests only, never for a store that opens it.
pub fn pool_provisioning_record(
    bundle: &PoolEpochBundleV1,
    encrypted_content: &EncryptedContentIdentityV1,
    node_seed: u8,
) -> crate::CustodyNodeProvisioningRecordV1 {
    let key_envelope = key_envelope_for(bundle, encrypted_content);
    let manifest = crate::CustodyEnvelopeManifestV1::new(
        encrypted_content.clone(),
        key_envelope.custody_pool(),
        key_envelope.custody_epoch(),
        key_envelope.custody_committee_authorization(),
        key_envelope.threshold(),
        Digest32::new([0x5a; 32]),
        bundle.signed_epoch().statement().nodes().to_vec(),
    )
    .expect("fixture manifest is valid");
    crate::CustodyNodeProvisioningRecordV1::new(
        key_envelope,
        manifest,
        node_public_key(node_seed),
        crate::PqHybridSealedShareV1::new(vec![0x33; crate::PQ_HYBRID_SEALED_SHARE_ENVELOPE_BYTES])
            .expect("fixture sealed share has the envelope size"),
    )
    .expect("fixture provisioning record is valid")
}

/// S7-lite T7.3: the Runtime `runtime_seed`'s provisioning statement for
/// `record`, valid `issued_at .. issued_at + 60`.
pub fn runtime_custody_provisioning(
    record: &crate::CustodyNodeProvisioningRecordV1,
    runtime_seed: u8,
    provisioning_seed: u8,
    issued_at: u64,
) -> crate::SignedRuntimeCustodyProvisioningV1 {
    let statement = crate::RuntimeCustodyProvisioningStatementV1::new(
        runtime_issuer(runtime_seed),
        record.record_identity().expect("record identity"),
        crate::RuntimeCustodyProvisioningIdV1::new(Digest32::new([provisioning_seed; 32]))
            .expect("fixture provisioning id"),
        issued_at,
        issued_at + 60,
    )
    .expect("fixture provisioning statement is valid");
    crate::SignedRuntimeCustodyProvisioningV1::new(
        statement.clone(),
        sign(
            &signing_key(runtime_seed),
            &statement.canonical_bytes().expect("statement bytes"),
        ),
    )
    .expect("fixture signed provisioning is valid")
}

/// #388 A2: the historical v2 form of [`pool_descriptor_with`] (trust
/// absent), byte-for-byte what the fixture wrote before v3, for the frozen
/// V-OP-2 vector and the historical-read tests.
pub fn historical_v2_descriptor_with(
    bundle: &PoolEpochBundleV1,
    sequence: u64,
    serve_policy: ServePolicyV1,
    non_serving_node: Option<u8>,
    runtime_owner: RuntimeOperationIssuerKeyV1,
    now: u64,
) -> SignedPoolDescriptorV2 {
    let statement = PoolDescriptorStatementV2::new(
        pool_did(),
        sequence,
        vec![bundle.clone()],
        fixture_members(non_serving_node),
        serve_policy,
        MintPolicyV1::owner_default(runtime_owner),
        now - 5,
        now + 86_400,
    )
    .expect("fixture descriptor is valid");
    SignedPoolDescriptorV2::new(
        statement.clone(),
        sign(
            &signing_key(POOL_AUTHORITY_SEED),
            &statement.canonical_bytes().expect("descriptor bytes"),
        ),
    )
    .expect("fixture signed descriptor is valid")
}

/// [`historical_v2_descriptor_with`] for a server count.
pub fn historical_v2_descriptor(
    bundle: &PoolEpochBundleV1,
    sequence: u64,
    max_servers_per_session: u8,
    runtime_owner: RuntimeOperationIssuerKeyV1,
    now: u64,
) -> SignedPoolDescriptorV2 {
    historical_v2_descriptor_with(
        bundle,
        sequence,
        ServePolicyV1 {
            max_servers_per_session,
            ..ServePolicyV1::DEFAULT
        },
        None,
        runtime_owner,
        now,
    )
}

/// Item 10: the historical v1 form of [`pool_descriptor_with_sequence`], with
/// every route ticketless as this fixture always built it, for the frozen
/// V-OP vector. Writers emit v3 only.
fn historical_v1_descriptor(
    bundle: &PoolEpochBundleV1,
    sequence: u64,
    max_servers_per_session: u8,
    runtime_owner: RuntimeOperationIssuerKeyV1,
    now: u64,
) -> SignedPoolDescriptorV1 {
    let v2 = historical_v2_descriptor(
        bundle,
        sequence,
        max_servers_per_session,
        runtime_owner,
        now,
    );
    let statement = v2.statement();
    let members = statement
        .members()
        .iter()
        .map(|member| {
            PoolMemberV1::new(
                member.node_public_key(),
                member.roles(),
                PoolMemberRouteV1::new(member.route().peer_did().to_owned(), None)
                    .expect("fixture v1 route is valid"),
            )
            .expect("fixture v1 member is valid")
        })
        .collect();
    let v1 = PoolDescriptorStatementV1::new(
        *statement.pool(),
        statement.sequence(),
        statement.epochs().to_vec(),
        members,
        *statement.serve_policy(),
        statement.mint_policy().clone(),
        statement.issued_at(),
        statement.expires_at(),
    )
    .expect("fixture v1 descriptor is valid");
    SignedPoolDescriptorV1::new(
        v1.clone(),
        sign(
            &signing_key(POOL_AUTHORITY_SEED),
            &v1.canonical_bytes().expect("v1 descriptor bytes"),
        ),
    )
    .expect("fixture v1 signed descriptor is valid")
}

/// The statement a serving node signs for one session recipient. #388-2: v2,
/// `WciOperated`, evidence empty.
pub fn recipient_attestation_statement(
    xwing: XWingPublicKeyFn,
    bundle: &PoolEpochBundleV1,
    binding: &ProtectedContentBindingV1,
    runtime: RuntimeOperationIssuerKeyV1,
    recipient_seed: u8,
    server_seed: u8,
    now: u64,
) -> PoolRecipientAttestationStatementV2 {
    recipient_attestation_statement_for_key(
        bundle,
        binding,
        runtime,
        recipient_public_key(xwing, recipient_seed),
        server_seed,
        now,
    )
}

/// [`recipient_attestation_statement`] for a recipient key the test holds.
pub fn recipient_attestation_statement_for_key(
    bundle: &PoolEpochBundleV1,
    binding: &ProtectedContentBindingV1,
    runtime: RuntimeOperationIssuerKeyV1,
    recipient_key: RecipientPublicKeyBytesV1,
    server_seed: u8,
    now: u64,
) -> PoolRecipientAttestationStatementV2 {
    PoolRecipientAttestationStatementV2::new(
        pool_did(),
        bundle.epoch_identity().expect("epoch identity"),
        node_public_key(server_seed),
        binding.clone(),
        RightsActionV1::View,
        recipient_key,
        recipient_key
            .key_identity(CUSTODY_X_WING_AES256GCM_SUITE_ID_V1)
            .expect("fixture recipient identity is valid"),
        runtime,
        now,
        now + 200,
        PoolTrustModeV1::WciOperated,
        Vec::new(),
    )
    .expect("fixture attestation statement is valid")
}

/// #388-2: the historical v1 form of
/// [`recipient_attestation_statement_for_key`] (trust absent), for the frozen
/// V-OP vectors and the read-only tests.
pub fn historical_v1_attestation_statement_for_key(
    bundle: &PoolEpochBundleV1,
    binding: &ProtectedContentBindingV1,
    runtime: RuntimeOperationIssuerKeyV1,
    recipient_key: RecipientPublicKeyBytesV1,
    server_seed: u8,
    now: u64,
) -> PoolRecipientAttestationStatementV1 {
    PoolRecipientAttestationStatementV1::new(
        pool_did(),
        bundle.epoch_identity().expect("epoch identity"),
        node_public_key(server_seed),
        binding.clone(),
        RightsActionV1::View,
        recipient_key,
        recipient_key
            .key_identity(CUSTODY_X_WING_AES256GCM_SUITE_ID_V1)
            .expect("fixture recipient identity is valid"),
        runtime,
        now,
        now + 200,
    )
    .expect("fixture attestation statement is valid")
}

/// A serving node's signed vouch for one recipient, in the version the spec
/// asks for.
fn signed_attestation(
    spec: &PoolReleaseSpecV1,
    bundle: &PoolEpochBundleV1,
    binding: &ProtectedContentBindingV1,
    runtime: RuntimeOperationIssuerKeyV1,
    recipient_key: RecipientPublicKeyBytesV1,
    server_seed: u8,
) -> SignedPoolRecipientAttestationAnyV1 {
    let server_key = signing_key(server_seed);
    if spec.v1_attestations {
        let statement = historical_v1_attestation_statement_for_key(
            bundle,
            binding,
            runtime,
            recipient_key,
            server_seed,
            spec.now,
        );
        let signature = sign(
            &server_key,
            &statement.canonical_bytes().expect("attestation bytes"),
        );
        SignedPoolRecipientAttestationV1::new(statement, signature)
            .expect("fixture attestation is valid")
            .into()
    } else {
        let statement = recipient_attestation_statement_for_key(
            bundle,
            binding,
            runtime,
            recipient_key,
            server_seed,
            spec.now,
        );
        let signature = sign(
            &server_key,
            &statement.canonical_bytes().expect("attestation bytes"),
        );
        SignedPoolRecipientAttestationV2::new(statement, signature)
            .expect("fixture attestation is valid")
            .into()
    }
}

pub fn pool_release_fixture(spec: &PoolReleaseSpecV1) -> PoolReleaseFixtureV1 {
    let xwing = spec.xwing_public_key;
    let now = spec.now;
    let bundle = pool_bundle_with(xwing, now, spec.member_window, spec.revoked_node);
    let runtime = runtime_issuer(spec.runtime_seed);
    let key_envelope = spec
        .key_envelope
        .clone()
        .unwrap_or_else(|| key_envelope_for(&bundle, spec.policy.encrypted_content()));
    let binding = ProtectedContentBindingV1::new(
        spec.policy.encrypted_content().clone(),
        key_envelope,
        spec.policy.policy_identity().expect("policy identity"),
        ProfileIdentityV1::from_public_key_bytes(
            signing_key(PROFILE_SEED).verifying_key().to_bytes(),
        )
        .expect("fixture profile is valid"),
        wallet_address(spec.wallet_seed),
        RuntimeSessionBindingV1::new(Digest32::new([0x66; 32])).expect("session binding"),
    )
    .expect("fixture binding is valid");
    let descriptor: SignedPoolDescriptorAnyV1 = if spec.v1_descriptor {
        historical_v1_descriptor(
            &bundle,
            spec.descriptor_sequence,
            spec.max_servers_per_session,
            runtime,
            now,
        )
        .into()
    } else if spec.v2_descriptor {
        historical_v2_descriptor(
            &bundle,
            spec.descriptor_sequence,
            spec.max_servers_per_session,
            runtime,
            now,
        )
        .into()
    } else {
        pool_descriptor_with_sequence(
            &bundle,
            spec.descriptor_sequence,
            spec.max_servers_per_session,
            runtime,
            now,
        )
        .into()
    };

    let rights_request = RightsRequestV2::new(
        binding.clone(),
        RightsActionV1::View,
        (0..spec.recipients.len())
            .map(|index| {
                spec.recipient_public_key(index)
                    .key_identity(CUSTODY_X_WING_AES256GCM_SUITE_ID_V1)
                    .expect("fixture recipient identity is valid")
            })
            .collect(),
        spec.delivery_key
            .unwrap_or_else(|| DeliveryKeyIdentityV1::new(Digest32::new([0x5d; 32]))),
        now,
        spec.rights_expires_at.unwrap_or(now + 180),
        ReplayNonce16::new([spec.replay_nonce; 16]),
        // ADV-01: the request binds the policy's chain.
        spec.policy.chain_id(),
    )
    .expect("fixture rights request is valid");
    let (wallet_signature, recovery_id) =
        wallet_signing_key(spec.wallet_signer_seed.unwrap_or(spec.wallet_seed))
            .sign_prehash_recoverable(&rights_request.signing_hash().expect("signing hash"))
            .expect("fixture wallet signs");
    let mut wallet_signature_bytes = wallet_signature.to_bytes().to_vec();
    wallet_signature_bytes.push(recovery_id.to_byte());
    let signed_rights = WalletSignedRightsRequestV2::new(rights_request, wallet_signature_bytes)
        .expect("fixture signed rights request is valid");

    let recipients = spec
        .recipients
        .iter()
        .enumerate()
        .map(|(index, (_, server_seed))| {
            let recipient_key = spec.recipient_public_key(index);
            let attestation = signed_attestation(
                spec,
                &bundle,
                &binding,
                runtime,
                recipient_key,
                *server_seed,
            );
            PoolSessionRecipientV1::new(recipient_key, attestation)
                .expect("fixture session recipient is valid")
        })
        .collect();
    let evidence_request = RightsEvaluationEvidenceRequestV1::new(
        binding.clone(),
        spec.policy.policy_identity().expect("policy identity"),
    )
    .expect("fixture evidence request is valid");
    let statement = RuntimeReleaseOperationStatementV2::new(
        runtime,
        signed_rights,
        recipients,
        spec.policy.clone(),
        evidence_request,
        descriptor.clone(),
        RuntimeReleaseAuditIdV1::new(Digest32::new([spec.audit_request_id; 32])).expect("audit id"),
        now + 2,
        now + 40,
    )
    .expect("fixture operation statement is valid");
    let operation = SignedRuntimeReleaseOperationV2::new(
        statement.clone(),
        sign(
            &signing_key(spec.runtime_seed),
            &statement.canonical_bytes().expect("operation bytes"),
        ),
    )
    .expect("fixture signed operation is valid");
    PoolReleaseFixtureV1 {
        now,
        bundle,
        descriptor,
        binding,
        operation,
    }
}

/// A node's rights decision for the V2 operation: the operation hash in the
/// release slot (L1), window `now + 3 .. now + 30`.
pub fn signed_node_rights_decision(
    operation: &AuthenticatedRuntimeReleaseOperationV2,
    node_seed: u8,
    decision: RightsDecisionV1,
    now: u64,
) -> SignedNodeRightsDecisionV1 {
    let statement = NodeRightsDecisionStatementV1::new(
        operation.operation_hash(),
        operation.rights_request_hash(),
        operation.binding().clone(),
        operation.action(),
        node_public_key(node_seed),
        decision,
        Digest32::new([0x90; 32]),
        now + 3,
        now + 30,
    )
    .expect("fixture decision statement is valid");
    SignedNodeRightsDecisionV1::new(
        statement.clone(),
        sign(
            &signing_key(node_seed),
            &statement.canonical_bytes().expect("decision bytes"),
        ),
    )
    .expect("fixture signed decision is valid")
}

/// A decision for an operation that may not verify (refusal tests): the
/// hashes are taken from the signed statement, not from a verified operation.
pub fn signed_node_rights_decision_for_signed(
    operation: &SignedRuntimeReleaseOperationV2,
    node_seed: u8,
    decision: RightsDecisionV1,
    now: u64,
) -> SignedNodeRightsDecisionV1 {
    let request = operation.statement().rights_request().request();
    let statement = NodeRightsDecisionStatementV1::new(
        operation
            .statement()
            .canonical_hash()
            .expect("operation statement hash"),
        request.request_hash().expect("rights request hash"),
        request.binding().clone(),
        request.action(),
        node_public_key(node_seed),
        decision,
        Digest32::new([0x90; 32]),
        now + 3,
        now + 30,
    )
    .expect("fixture decision statement is valid");
    SignedNodeRightsDecisionV1::new(
        statement.clone(),
        sign(
            &signing_key(node_seed),
            &statement.canonical_bytes().expect("decision bytes"),
        ),
    )
    .expect("fixture signed decision is valid")
}

// ---------------------------------------------------------------------------
// ADV-01 §4A (Plan B T4.1): stored V2 operation bytes that a reader must map
// one by one. Both start from a valid signed V2 operation and change only
// its wallet-signed rights request, so every other field stays valid.
// ---------------------------------------------------------------------------

/// The pool-form tail of a current `rights-request/v2` after its
/// recipients: tag (1) · delivery key (32) · issued (8) · expires (8) ·
/// nonce (16) · chain id (8).
const CURRENT_V2_POOL_TAIL_BYTES: usize = 1 + 32 + 8 + 8 + 16 + 8;

fn after_domain(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|byte| *byte == 0)
        .expect("a canonical domain")
        + 1
}

/// Replaces the u16-length nested value that starts at `at`.
fn replace_nested(bytes: &[u8], at: usize, replacement: &[u8]) -> Vec<u8> {
    let length = usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
    let mut out = bytes[..at].to_vec();
    out.extend_from_slice(
        &u16::try_from(replacement.len())
            .expect("a nested value fits u16")
            .to_be_bytes(),
    );
    out.extend_from_slice(replacement);
    out.extend_from_slice(&bytes[at + 2 + length..]);
    out
}

/// The signed operation's bytes with its rights request replaced: the
/// wallet wrapper is the statement's first nested field after its 32-byte
/// head, and the request is the wrapper's first nested field.
fn operation_bytes_with_rights_request(
    operation: &SignedRuntimeReleaseOperationV2,
    request: &[u8],
) -> Vec<u8> {
    let wrapper = operation
        .statement()
        .rights_request()
        .canonical_bytes()
        .expect("wallet wrapper bytes");
    let wrapper = replace_nested(&wrapper, after_domain(&wrapper), request);
    let statement = operation
        .statement()
        .canonical_bytes()
        .expect("statement bytes");
    let statement = replace_nested(&statement, after_domain(&statement) + 32, &wrapper);
    let signed = operation.canonical_bytes().expect("operation bytes");
    replace_nested(&signed, after_domain(&signed), &statement)
}

/// The operation as a binary before ADV-01 stored it: its rights request in
/// the pre-alignment layout (no pool-form tag, no chain id), so decoding
/// answers `ContractError::UnsupportedVersion(PRE_ALIGNMENT_V2)`.
pub fn pre_alignment_v2_operation_bytes(operation: &SignedRuntimeReleaseOperationV2) -> Vec<u8> {
    let request = operation
        .statement()
        .rights_request()
        .request()
        .canonical_bytes()
        .expect("request bytes");
    let tail = request.len() - CURRENT_V2_POOL_TAIL_BYTES;
    let mut legacy = request[..tail].to_vec();
    legacy.extend_from_slice(&request[tail + 1..request.len() - 8]);
    operation_bytes_with_rights_request(operation, &legacy)
}

/// A current V2 operation whose rights request lost its last byte: the
/// remaining tail is not the 64-byte pre-alignment case, so decoding fails
/// with another `ContractError`.
pub fn malformed_current_v2_operation_bytes(
    operation: &SignedRuntimeReleaseOperationV2,
) -> Vec<u8> {
    let request = operation
        .statement()
        .rights_request()
        .request()
        .canonical_bytes()
        .expect("request bytes");
    operation_bytes_with_rights_request(operation, &request[..request.len() - 1])
}

//! Plan B T1.1: pool contracts, rights V2 and the V2 release operation.
//!
//! The fixtures build every signed object from fixed seeds: one pool
//! authority signs the custody pool, its epoch, the committee authorization
//! and the pool descriptor; node keys sign attestations, decisions and
//! contributions; one Runtime key signs the operation; one wallet signs the
//! rights request.

use ed25519_dalek::{Signer as _, SigningKey};
use hex::encode;
use k256::ecdsa::SigningKey as WalletSigningKey;
use sha2::{Digest as _, Sha256};

use crate::test_support::{
    archived_pre_alignment_v2_wrapper_bytes, digest, node_custody_public_key, node_key,
    node_public_key, recipient_public_key_bytes, wallet, xwing_public_key_bytes, NOW,
};
use crate::{
    validate_custody_epoch_against_pool_at, validate_custody_epoch_for_release_at,
    AuthenticatedRuntimeReleaseOperationAnyV1, AuthenticatedRuntimeReleaseOperationV2,
    CanonicalContract, ContractError, CustodyApprovedSuitesV1,
    CustodyCommitteeAuthorizationStatementV1, CustodyEpochIdentityV1, CustodyEpochIssuerKeyV1,
    CustodyEpochStatementV1, CustodyNodeIdentityV1, CustodyPoolError, CustodyPoolFailureDomainIdV1,
    CustodyPoolMemberStateV1, CustodyPoolMemberV1, CustodyPoolOperatorIdV1, CustodyPoolStatementV1,
    DeliveryKeyIdentityV1, DeliveryPublicKeyBytesV1, Digest32, EncryptedContentIdentityV1,
    EvmContractAddressV1, EvmFunctionSelectorV1, EvmRightsMethodAbiV1, KeyEnvelopeIdentityV1,
    KeyReleaseError, KeyReleaseOutcomeV1, MintPolicyV1, NodeContributionRefV1,
    NodeContributionStatementV1, NodeRightsDecisionStatementV1, PoolAddressAnyV1, PoolAddressV1,
    PoolAddressV2, PoolContractError, PoolDescriptorStatementV1, PoolDescriptorStatementV2,
    PoolDescriptorStatementV3, PoolDidV1, PoolEpochBundleV1, PoolMemberRolesV1, PoolMemberRouteV1,
    PoolMemberRouteV2, PoolMemberV1, PoolMemberV2, PoolMemberV3,
    PoolRecipientAttestationStatementV1, PoolRecipientAttestationStatementV2,
    PoolSessionRecipientV1, PoolTrustModeV1, ProfileIdentityV1, ProtectedContentBindingV1,
    RecipientKeyIdentityV1, RecipientSealedContributionV1, ReplayNonce16, RightsActionV1,
    RightsDecisionV1, RightsEvaluationEvidenceRequestV1, RightsObservationFinalityV1,
    RightsPolicyBodyV1, RightsRequestAnyV1, RightsRequestV1, RightsRequestV2,
    RightsSubjectSourceV1, RuntimeIssuerPolicyV1, RuntimeOperationIssuerKeyV1,
    RuntimeReleaseAuditIdV1, RuntimeReleaseOperationAnyV1, RuntimeReleaseOperationError,
    RuntimeReleaseOperationStatementV2, RuntimeSessionBindingV1, ServePolicyV1, ShareCoordinateV1,
    SignedCustodyCommitteeAuthorizationV1, SignedCustodyEpochV1, SignedCustodyPoolV1,
    SignedNodeContributionV1, SignedNodeRightsDecisionV1, SignedPoolDescriptorAnyV1,
    SignedPoolDescriptorV1, SignedPoolDescriptorV2, SignedPoolDescriptorV3,
    SignedPoolRecipientAttestationAnyV1, SignedPoolRecipientAttestationV1,
    SignedPoolRecipientAttestationV2, SignedRuntimeReleaseOperationV2, SignedTerminalReceiptV1,
    TerminalReceiptIssuerKey, TerminalReceiptStatementV1, ThresholdV1, VerifiedNodeContributionV1,
    WalletSignedRightsRequestV2, CUSTODY_X_WING_AES256GCM_SUITE_ID_V1, MAX_ADMITTED_MINTERS_V1,
    MAX_POOL_DESCRIPTOR_LIFETIME_SECS, MAX_POOL_MEMBERS_V1, MAX_POOL_MEMBER_PEER_DID_BYTES_V1,
    MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1, MAX_TRUST_ATTESTATION_BYTES_V1, PRE_ALIGNMENT_V2,
};

const POOL_AUTHORITY: u8 = 0x71;
const OTHER_AUTHORITY: u8 = 0x72;
const RUNTIME: u8 = 0x42;
const OTHER_RUNTIME: u8 = 0x43;
const WALLET: u8 = 7;
const PROFILE: u8 = 0x26;
const TERMINAL_ISSUER: u8 = 0x77;
const SUITE: &str = CUSTODY_X_WING_AES256GCM_SUITE_ID_V1;

const ALL_ROLES: PoolMemberRolesV1 = PoolMemberRolesV1 {
    hold: true,
    serve: true,
    seal: true,
};
const HOLD_ONLY: PoolMemberRolesV1 = PoolMemberRolesV1 {
    hold: true,
    serve: false,
    seal: false,
};

fn sign(key: &SigningKey, bytes: &[u8]) -> Vec<u8> {
    key.sign(bytes).to_bytes().to_vec()
}

fn authority_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn authority(seed: u8) -> CustodyEpochIssuerKeyV1 {
    CustodyEpochIssuerKeyV1::new(authority_key(seed).verifying_key().to_bytes()).unwrap()
}

fn pool_did() -> PoolDidV1 {
    PoolDidV1::from_issuer(authority(POOL_AUTHORITY))
}

fn runtime_issuer_for(seed: u8) -> RuntimeOperationIssuerKeyV1 {
    RuntimeOperationIssuerKeyV1::new(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap()
}

fn runtime_issuer() -> RuntimeOperationIssuerKeyV1 {
    runtime_issuer_for(RUNTIME)
}

fn suites() -> CustodyApprovedSuitesV1 {
    CustodyApprovedSuitesV1::new(SUITE, SUITE, SUITE).unwrap()
}

fn recipient(seed: u8) -> RecipientKeyIdentityV1 {
    recipient_public_key_bytes(seed)
        .key_identity(SUITE)
        .unwrap()
}

/// One custody committee of the pool: the custody pool, the epoch and the
/// authorization that binds them, all signed by the pool authority.
struct BundleSpec {
    nodes: Vec<u8>,
    required: u8,
    window: (u64, u64),
    revoked: Option<u8>,
}

impl Default for BundleSpec {
    fn default() -> Self {
        Self {
            nodes: vec![1, 2, 3],
            required: 2,
            window: (NOW - 10, NOW + 86_400),
            revoked: None,
        }
    }
}

fn custody_member(
    seed: u8,
    window: (u64, u64),
    state: CustodyPoolMemberStateV1,
) -> CustodyPoolMemberV1 {
    CustodyPoolMemberV1::new(
        node_public_key(seed),
        node_custody_public_key(seed),
        // Each node has its own operator and failure domain (L2 fixtures).
        CustodyPoolOperatorIdV1::new([0xa0 + seed; 32]),
        CustodyPoolFailureDomainIdV1::new([0xc0 + seed; 32]),
        suites(),
        window,
        state,
    )
    .unwrap()
}

fn bundle(spec: &BundleSpec) -> PoolEpochBundleV1 {
    let key = authority_key(POOL_AUTHORITY);
    let members = spec
        .nodes
        .iter()
        .map(|seed| {
            let state = if spec.revoked == Some(*seed) {
                CustodyPoolMemberStateV1::Revoked
            } else {
                CustodyPoolMemberStateV1::Active
            };
            custody_member(*seed, spec.window, state)
        })
        .collect();
    let pool_statement = CustodyPoolStatementV1::new(authority(POOL_AUTHORITY), members).unwrap();
    let pool = SignedCustodyPoolV1::new(
        pool_statement.clone(),
        sign(&key, &pool_statement.canonical_bytes().unwrap()),
    )
    .unwrap();
    let nodes = spec
        .nodes
        .iter()
        .enumerate()
        .map(|(index, seed)| {
            CustodyNodeIdentityV1::new(
                node_public_key(*seed),
                node_custody_public_key(*seed),
                ShareCoordinateV1::new(u8::try_from(index + 1).unwrap()).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let epoch_statement = CustodyEpochStatementV1::new(
        authority(POOL_AUTHORITY),
        suites(),
        ThresholdV1::new(spec.required, u8::try_from(spec.nodes.len()).unwrap()).unwrap(),
        nodes,
    )
    .unwrap();
    let epoch = SignedCustodyEpochV1::new(
        epoch_statement.clone(),
        sign(&key, &epoch_statement.canonical_bytes().unwrap()),
    )
    .unwrap();
    let authorization_statement = CustodyCommitteeAuthorizationStatementV1::new(
        authority(POOL_AUTHORITY),
        pool.pool_identity().unwrap(),
        epoch.epoch_identity().unwrap(),
    )
    .unwrap();
    let authorization = SignedCustodyCommitteeAuthorizationV1::new(
        authorization_statement.clone(),
        sign(&key, &authorization_statement.canonical_bytes().unwrap()),
    )
    .unwrap();
    PoolEpochBundleV1::new(pool, epoch, authorization).unwrap()
}

/// Item 10: a member route is its peer DID only.
fn route(seed: u8) -> PoolMemberRouteV2 {
    PoolMemberRouteV2::new(format!("did:key:z6MkPoolNode{seed:02x}")).unwrap()
}

fn member(seed: u8, roles: PoolMemberRolesV1) -> PoolMemberV2 {
    PoolMemberV2::new(node_public_key(seed), roles, route(seed)).unwrap()
}

/// The historical v1 route, with a connect ticket, for the frozen v1 vectors.
fn route_v1(seed: u8) -> PoolMemberRouteV1 {
    PoolMemberRouteV1::new(
        format!("did:key:z6MkPoolNode{seed:02x}"),
        Some(format!("ticket-{seed:02x}")),
    )
    .unwrap()
}

fn serve_policy(max_servers_per_session: u8) -> ServePolicyV1 {
    ServePolicyV1 {
        max_servers_per_session,
        ..ServePolicyV1::DEFAULT
    }
}

#[derive(Clone)]
struct DescriptorSpec {
    bundles: Vec<PoolEpochBundleV1>,
    members: Vec<PoolMemberV2>,
    serve_policy: ServePolicyV1,
    mint_policy: MintPolicyV1,
    window: (u64, u64),
    signer: u8,
}

impl DescriptorSpec {
    fn with_bundle(bundle_spec: &BundleSpec) -> Self {
        Self {
            bundles: vec![bundle(bundle_spec)],
            members: bundle_spec
                .nodes
                .iter()
                .map(|seed| member(*seed, ALL_ROLES))
                .collect(),
            serve_policy: ServePolicyV1::DEFAULT,
            mint_policy: MintPolicyV1::owner_default(runtime_issuer()),
            window: (NOW - 5, NOW + 86_400),
            signer: POOL_AUTHORITY,
        }
    }

    fn standard() -> Self {
        Self::with_bundle(&BundleSpec::default())
    }

    fn statement(&self) -> Result<PoolDescriptorStatementV2, ContractError> {
        PoolDescriptorStatementV2::new(
            pool_did(),
            1,
            self.bundles.clone(),
            self.members.clone(),
            self.serve_policy,
            self.mint_policy.clone(),
            self.window.0,
            self.window.1,
        )
    }

    fn signed(&self) -> SignedPoolDescriptorV2 {
        let statement = self.statement().unwrap();
        SignedPoolDescriptorV2::new(
            statement.clone(),
            sign(
                &authority_key(self.signer),
                &statement.canonical_bytes().unwrap(),
            ),
        )
        .unwrap()
    }

    /// #388 A2: the same descriptor in v3, every member with `slot`, under
    /// `trust_mode`.
    fn statement_v3(
        &self,
        trust_mode: PoolTrustModeV1,
        slot: &[u8],
    ) -> Result<PoolDescriptorStatementV3, ContractError> {
        PoolDescriptorStatementV3::new(
            pool_did(),
            1,
            self.bundles.clone(),
            self.members
                .iter()
                .map(|member| PoolMemberV3::new(member.clone(), slot.to_vec()))
                .collect::<Result<_, _>>()?,
            self.serve_policy,
            self.mint_policy.clone(),
            self.window.0,
            self.window.1,
            trust_mode,
        )
    }

    /// #388 A2: the v3 descriptor writers emit: `WciOperated`, slots empty.
    fn signed_v3(&self) -> SignedPoolDescriptorV3 {
        let statement = self
            .statement_v3(PoolTrustModeV1::WciOperated, &[])
            .unwrap();
        SignedPoolDescriptorV3::new(
            statement.clone(),
            sign(
                &authority_key(self.signer),
                &statement.canonical_bytes().unwrap(),
            ),
        )
        .unwrap()
    }

    /// Item 10: the same descriptor in the historical v1 format, each route
    /// with a connect ticket (`ticket-<seed>`), signed by the same authority.
    fn signed_v1(&self) -> SignedPoolDescriptorV1 {
        let members = self
            .members
            .iter()
            .map(|member| {
                let did = member.route().peer_did();
                PoolMemberV1::new(
                    member.node_public_key(),
                    member.roles(),
                    PoolMemberRouteV1::new(
                        did.to_owned(),
                        Some(format!("ticket-{}", &did[did.len() - 2..])),
                    )
                    .unwrap(),
                )
                .unwrap()
            })
            .collect();
        let statement = PoolDescriptorStatementV1::new(
            pool_did(),
            1,
            self.bundles.clone(),
            members,
            self.serve_policy,
            self.mint_policy.clone(),
            self.window.0,
            self.window.1,
        )
        .unwrap();
        SignedPoolDescriptorV1::new(
            statement.clone(),
            sign(
                &authority_key(self.signer),
                &statement.canonical_bytes().unwrap(),
            ),
        )
        .unwrap()
    }
}

/// The item's key envelope identity: it names the bundle's three identities,
/// its node set and its threshold.
fn key_envelope_for(bundle: &PoolEpochBundleV1) -> KeyEnvelopeIdentityV1 {
    let epoch = bundle.signed_epoch();
    KeyEnvelopeIdentityV1::new(
        EncryptedContentIdentityV1::new(digest(0x11), 4096).unwrap(),
        digest(0x22),
        512,
        epoch.statement().node_set().unwrap().node_set_id().unwrap(),
        epoch.statement().threshold(),
        bundle.signed_pool().pool_identity().unwrap(),
        epoch.epoch_identity().unwrap(),
        bundle
            .signed_committee_authorization()
            .authorization_identity()
            .unwrap(),
    )
    .unwrap()
}

fn policy_body() -> RightsPolicyBodyV1 {
    policy_body_on_chain(11155111)
}

/// ADV-01: the fixture policy on another chain, everything else equal.
fn policy_body_on_chain(chain_id: u64) -> RightsPolicyBodyV1 {
    RightsPolicyBodyV1::new(
        EncryptedContentIdentityV1::new(digest(0x11), 4096).unwrap(),
        crate::ContentAccessIdV1::new([0x41; 16]).unwrap(),
        RightsActionV1::View,
        RightsSubjectSourceV1::WalletAddress,
        chain_id,
        EvmContractAddressV1::new([0x11; 20]).unwrap(),
        EvmFunctionSelectorV1::new([0x12, 0x34, 0x56, 0x78]).unwrap(),
        EvmRightsMethodAbiV1::HasAccessByContentIdAddressBytes16,
        RightsObservationFinalityV1::finalized(),
    )
    .unwrap()
}

fn binding_for(bundle: &PoolEpochBundleV1) -> ProtectedContentBindingV1 {
    binding_for_policy(bundle, &policy_body())
}

fn binding_for_policy(
    bundle: &PoolEpochBundleV1,
    policy: &RightsPolicyBodyV1,
) -> ProtectedContentBindingV1 {
    ProtectedContentBindingV1::new(
        EncryptedContentIdentityV1::new(digest(0x11), 4096).unwrap(),
        key_envelope_for(bundle),
        policy.policy_identity().unwrap(),
        ProfileIdentityV1::from_public_key_bytes(
            SigningKey::from_bytes(&[PROFILE; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
        wallet(WALLET),
        RuntimeSessionBindingV1::new(digest(0x66)).unwrap(),
    )
    .unwrap()
}

fn delivery_key() -> DeliveryKeyIdentityV1 {
    DeliveryPublicKeyBytesV1::new(xwing_public_key_bytes(0x5d))
        .unwrap()
        .identity()
}

fn rights_request_v2(
    binding: ProtectedContentBindingV1,
    recipients: Vec<RecipientKeyIdentityV1>,
) -> Result<RightsRequestV2, ContractError> {
    rights_request_v2_on_chain(binding, recipients, policy_body().chain_id())
}

/// ADV-01: the pool form on `chain_id`; the fixture policy's chain is
/// `policy_body().chain_id()`.
fn rights_request_v2_on_chain(
    binding: ProtectedContentBindingV1,
    recipients: Vec<RecipientKeyIdentityV1>,
    chain_id: u64,
) -> Result<RightsRequestV2, ContractError> {
    RightsRequestV2::new(
        binding,
        RightsActionV1::View,
        recipients,
        delivery_key(),
        NOW,
        NOW + 180,
        ReplayNonce16::new([0x55; 16]),
        chain_id,
    )
}

fn wallet_signed(request: RightsRequestV2) -> WalletSignedRightsRequestV2 {
    let wallet_key = WalletSigningKey::from_slice(&[WALLET; 32]).unwrap();
    let (signature, recovery_id) = wallet_key
        .sign_prehash_recoverable(&request.signing_hash().unwrap())
        .unwrap();
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(recovery_id.to_byte());
    WalletSignedRightsRequestV2::new(request, bytes).unwrap()
}

fn attestation(
    binding: &ProtectedContentBindingV1,
    recipient_seed: u8,
    server_seed: u8,
    epoch: CustodyEpochIdentityV1,
    pool: PoolDidV1,
) -> SignedPoolRecipientAttestationV1 {
    let public_key = recipient_public_key_bytes(recipient_seed);
    let statement = PoolRecipientAttestationStatementV1::new(
        pool,
        epoch,
        node_public_key(server_seed),
        binding.clone(),
        RightsActionV1::View,
        public_key,
        public_key.key_identity(SUITE).unwrap(),
        runtime_issuer(),
        NOW,
        NOW + 200,
    )
    .unwrap();
    SignedPoolRecipientAttestationV1::new(
        statement.clone(),
        sign(
            &node_key(server_seed),
            &statement.canonical_bytes().unwrap(),
        ),
    )
    .unwrap()
}

/// #388-2: the v2 vouch writers emit (`WciOperated`, evidence empty).
fn attestation_v2(
    binding: &ProtectedContentBindingV1,
    recipient_seed: u8,
    server_seed: u8,
    epoch: CustodyEpochIdentityV1,
    pool: PoolDidV1,
) -> SignedPoolRecipientAttestationV2 {
    let statement = attestation_statement_v2(
        binding,
        recipient_seed,
        server_seed,
        epoch,
        pool,
        PoolTrustModeV1::WciOperated,
        Vec::new(),
    )
    .unwrap();
    SignedPoolRecipientAttestationV2::new(
        statement.clone(),
        sign(
            &node_key(server_seed),
            &statement.canonical_bytes().unwrap(),
        ),
    )
    .unwrap()
}

fn attestation_statement_v2(
    binding: &ProtectedContentBindingV1,
    recipient_seed: u8,
    server_seed: u8,
    epoch: CustodyEpochIdentityV1,
    pool: PoolDidV1,
    trust_mode: PoolTrustModeV1,
    evidence: Vec<u8>,
) -> Result<PoolRecipientAttestationStatementV2, ContractError> {
    let public_key = recipient_public_key_bytes(recipient_seed);
    PoolRecipientAttestationStatementV2::new(
        pool,
        epoch,
        node_public_key(server_seed),
        binding.clone(),
        RightsActionV1::View,
        public_key,
        public_key.key_identity(SUITE).unwrap(),
        runtime_issuer(),
        NOW,
        NOW + 200,
        trust_mode,
        evidence,
    )
}

/// A V2 release operation. `recipients` pairs each recipient key seed with
/// the seed of the pool node that vouches for it.
struct OperationSpec {
    descriptor: DescriptorSpec,
    item_bundle: PoolEpochBundleV1,
    recipients: Vec<(u8, u8)>,
    rights_recipients: Option<Vec<u8>>,
    /// ADV-01: the rights request's chain; `None` is the policy's chain.
    rights_chain_id: Option<u64>,
    /// ADV-01: the rights request in the direct form (no delivery key).
    direct_rights: bool,
    /// #388 A2: the nested descriptor's version; writers emit 3.
    descriptor_version: u8,
    /// #388-2: historical v1 vouches (trust absent); writers emit v2.
    v1_attestations: bool,
}

impl OperationSpec {
    fn with_descriptor(descriptor: DescriptorSpec) -> Self {
        Self {
            item_bundle: descriptor.bundles[0].clone(),
            descriptor,
            recipients: vec![(9, 1)],
            rights_recipients: None,
            rights_chain_id: None,
            direct_rights: false,
            descriptor_version: 3,
            v1_attestations: false,
        }
    }

    fn nested_descriptor(&self) -> SignedPoolDescriptorAnyV1 {
        match self.descriptor_version {
            1 => self.descriptor.signed_v1().into(),
            2 => self.descriptor.signed().into(),
            _ => self.descriptor.signed_v3().into(),
        }
    }

    fn standard() -> Self {
        Self::with_descriptor(DescriptorSpec::standard())
    }

    fn binding(&self) -> ProtectedContentBindingV1 {
        binding_for(&self.item_bundle)
    }

    fn statement(&self) -> Result<RuntimeReleaseOperationStatementV2, ContractError> {
        let binding = self.binding();
        let epoch = self.item_bundle.signed_epoch().epoch_identity().unwrap();
        let recipients = self
            .recipients
            .iter()
            .map(|(recipient_seed, server_seed)| {
                let vouch: SignedPoolRecipientAttestationAnyV1 = if self.v1_attestations {
                    attestation(&binding, *recipient_seed, *server_seed, epoch, pool_did()).into()
                } else {
                    attestation_v2(&binding, *recipient_seed, *server_seed, epoch, pool_did())
                        .into()
                };
                PoolSessionRecipientV1::new(recipient_public_key_bytes(*recipient_seed), vouch)
                    .unwrap()
            })
            .collect();
        let rights_recipients: Vec<RecipientKeyIdentityV1> = self
            .rights_recipients
            .clone()
            .unwrap_or_else(|| self.recipients.iter().map(|(seed, _)| *seed).collect())
            .into_iter()
            .map(recipient)
            .collect();
        let policy = policy_body();
        let chain_id = self.rights_chain_id.unwrap_or(policy.chain_id());
        let rights_request = if self.direct_rights {
            RightsRequestV2::new_direct(
                binding.clone(),
                RightsActionV1::View,
                rights_recipients[0].clone(),
                NOW,
                NOW + 180,
                ReplayNonce16::new([0x55; 16]),
                chain_id,
            )?
        } else {
            rights_request_v2_on_chain(binding.clone(), rights_recipients, chain_id)?
        };
        RuntimeReleaseOperationStatementV2::new(
            runtime_issuer(),
            wallet_signed(rights_request),
            recipients,
            policy.clone(),
            RightsEvaluationEvidenceRequestV1::new(binding, policy.policy_identity()?)?,
            self.nested_descriptor(),
            RuntimeReleaseAuditIdV1::new(digest(0x91))?,
            NOW + 2,
            NOW + 40,
        )
    }

    fn signed(&self) -> SignedRuntimeReleaseOperationV2 {
        let statement = self.statement().unwrap();
        SignedRuntimeReleaseOperationV2::new(
            statement.clone(),
            sign(
                &SigningKey::from_bytes(&[RUNTIME; 32]),
                &statement.canonical_bytes().unwrap(),
            ),
        )
        .unwrap()
    }

    fn authenticated(&self) -> AuthenticatedRuntimeReleaseOperationV2 {
        self.signed()
            .verify(RuntimeIssuerPolicyV1::Declared, NOW + 3)
            .unwrap()
    }
}

fn decision_for(
    operation: &AuthenticatedRuntimeReleaseOperationV2,
    node: u8,
    release_request_hash: Digest32,
) -> SignedNodeRightsDecisionV1 {
    let statement = NodeRightsDecisionStatementV1::new(
        release_request_hash,
        operation.rights_request_hash(),
        operation.binding().clone(),
        RightsActionV1::View,
        node_public_key(node),
        RightsDecisionV1::Allowed,
        digest(0x90),
        NOW + 3,
        NOW + 30,
    )
    .unwrap();
    SignedNodeRightsDecisionV1::new(
        statement.clone(),
        sign(&node_key(node), &statement.canonical_bytes().unwrap()),
    )
    .unwrap()
}

fn contribution_for(
    operation: &AuthenticatedRuntimeReleaseOperationV2,
    node: u8,
    sealed_to: RecipientKeyIdentityV1,
) -> SignedNodeContributionV1 {
    let statement = NodeContributionStatementV1::new(
        operation.operation_hash(),
        operation.binding().clone(),
        decision_for(operation, node, operation.operation_hash()),
        RecipientSealedContributionV1::new(sealed_to, vec![node; 64]).unwrap(),
        NOW + 4,
        NOW + 30,
    )
    .unwrap();
    SignedNodeContributionV1::new(
        statement.clone(),
        sign(&node_key(node), &statement.canonical_bytes().unwrap()),
    )
    .unwrap()
}

fn item_node_set(spec: &OperationSpec) -> crate::NodeSetV1 {
    spec.item_bundle
        .signed_epoch()
        .statement()
        .node_set()
        .unwrap()
}

// ---------------------------------------------------------------------------
// Descriptor
// ---------------------------------------------------------------------------

#[test]
fn descriptor_round_trips_and_verifies() {
    let signed = DescriptorSpec::standard().signed();
    let bytes = signed.canonical_bytes().unwrap();
    assert_eq!(
        SignedPoolDescriptorV2::from_canonical_bytes(&bytes).unwrap(),
        signed
    );
    assert_eq!(
        PoolDescriptorStatementV2::from_canonical_bytes(
            &signed.statement().canonical_bytes().unwrap()
        )
        .unwrap(),
        *signed.statement()
    );

    let verified = signed.verify(NOW).unwrap();
    assert_eq!(verified.pool(), &pool_did());
    assert_eq!(verified.sequence(), 1);
    assert_eq!(verified.expires_at(), NOW + 86_400);
    assert_eq!(verified.serve_policy(), &ServePolicyV1::DEFAULT);
    assert_eq!(
        verified.mint_policy(),
        &MintPolicyV1::owner_default(runtime_issuer())
    );
    assert_eq!(verified.members().len(), 3);
    assert_eq!(verified.eligible_servers().len(), 3);
    assert_eq!(verified.eligible_sealers().len(), 3);
    assert_eq!(
        verified.member(node_public_key(2)).unwrap().route(),
        &route(2)
    );
    assert!(verified.member(node_public_key(9)).is_none());
}

#[test]
fn descriptor_policy_defaults_are_the_decided_values() {
    let serve = ServePolicyV1::DEFAULT;
    assert_eq!(serve.max_servers_per_session, 1);
    assert!(!serve.allow_self_serve);
    let bounds = serve.bounds;
    assert_eq!(
        (
            bounds.byte_rate_multiplier,
            bounds.total_bytes_multiplier,
            bounds.read_ahead_segments,
            bounds.max_sessions_per_wallet_kid,
            bounds.max_sessions_per_wallet,
            bounds.max_sessions_per_endpoint,
        ),
        (2, 3, 6, 2, 8, 16)
    );
    let mint = MintPolicyV1::owner_default(runtime_issuer());
    assert_eq!(mint.admitted_minters, vec![runtime_issuer()]);
    assert!(!mint.allow_self_seal);
    assert_eq!(mint.max_seals_per_sealer, 8);
}

#[test]
fn guard_descriptor_signed_by_another_key_is_refused() {
    let mut spec = DescriptorSpec::standard();
    spec.signer = OTHER_AUTHORITY;
    assert_eq!(spec.signed().verify(NOW), Err(PoolContractError::Signature));
}

#[test]
fn guard_descriptor_member_outside_every_committee_is_refused() {
    let mut spec = DescriptorSpec::standard();
    spec.members.push(member(4, ALL_ROLES));
    assert_eq!(spec.signed().verify(NOW), Err(PoolContractError::NotMember));
}

#[test]
fn descriptor_members_are_unique() {
    let mut spec = DescriptorSpec::standard();
    spec.members.push(member(2, HOLD_ONLY));
    assert_eq!(
        spec.statement(),
        Err(ContractError::InvalidField("pool_descriptor.members"))
    );
}

#[test]
fn guard_descriptor_not_yet_valid_expired_or_too_long_is_refused() {
    let mut spec = DescriptorSpec::standard();
    spec.window = (NOW + 100, NOW + 200);
    assert_eq!(
        spec.signed().verify(NOW),
        Err(PoolContractError::NotYetValid)
    );

    spec.window = (NOW - 200, NOW - 1);
    assert_eq!(spec.signed().verify(NOW), Err(PoolContractError::Expired));
    // No skew on expiry: the last second of the window is already expired.
    spec.window = (NOW - 200, NOW);
    assert_eq!(spec.signed().verify(NOW), Err(PoolContractError::Expired));

    spec.window = (NOW - 5, NOW - 5 + MAX_POOL_DESCRIPTOR_LIFETIME_SECS + 1);
    assert_eq!(
        spec.statement(),
        Err(ContractError::InvalidField("pool_descriptor_lifetime"))
    );
    spec.window = (NOW - 5, NOW - 5 + MAX_POOL_DESCRIPTOR_LIFETIME_SECS);
    spec.signed().verify(NOW).unwrap();
}

#[test]
fn guard_descriptor_max_servers_above_threshold_total_is_refused() {
    let mut spec = DescriptorSpec::standard();
    // 2-of-3: three servers at most.
    spec.serve_policy = serve_policy(4);
    assert_eq!(spec.signed().verify(NOW), Err(PoolContractError::TooMany));
    spec.serve_policy = serve_policy(0);
    assert_eq!(
        spec.statement(),
        Err(ContractError::InvalidField(
            "serve_policy.max_servers_per_session"
        ))
    );
}

#[test]
fn guard_descriptor_two_of_five_epoch_is_refused_only_by_the_committee_rule() {
    let spec = DescriptorSpec::with_bundle(&BundleSpec {
        nodes: vec![1, 2, 3, 4, 5],
        ..BundleSpec::default()
    });
    // Every other check would pass: five members, each with its own
    // operator and failure domain, all in the committee. Only the single
    // 2-of-3 rule refuses (S8 changes that one place).
    assert_eq!(
        spec.signed().verify(NOW),
        Err(PoolContractError::CustodyPool(
            CustodyPoolError::PolicyViolation("committee_threshold")
        ))
    );
}

#[test]
fn descriptor_server_bound_reads_the_epoch_threshold() {
    let mut spec = DescriptorSpec::standard();
    // The bound is min(threshold total = 3, MAX_SESSION_RECIPIENTS_V2 = 4).
    spec.serve_policy = serve_policy(3);
    assert_eq!(
        spec.signed()
            .verify(NOW)
            .unwrap()
            .serve_policy()
            .max_servers_per_session,
        3
    );
    spec.serve_policy = serve_policy(4);
    assert_eq!(spec.signed().verify(NOW), Err(PoolContractError::TooMany));
}

#[test]
fn guard_descriptor_over_the_byte_cap_is_refused() {
    // Item 10: routes carry no ticket, so the cap is reached with the most
    // committees (four of four nodes, about 10.7 KiB each) and sixteen members
    // with the longest peer DID: within every count maximum, over the 40 KiB
    // byte cap.
    let mut spec = DescriptorSpec::with_bundle(&BundleSpec {
        nodes: vec![1, 2, 3, 4],
        ..BundleSpec::default()
    });
    for first in [5u8, 9, 13] {
        spec.bundles.push(bundle(&BundleSpec {
            nodes: (first..first + 4).collect(),
            ..BundleSpec::default()
        }));
    }
    spec.members = (1..=16)
        .map(|seed| {
            let prefix = format!("did:key:z6MkPoolNode{seed:02x}");
            let padding = "x".repeat(MAX_POOL_MEMBER_PEER_DID_BYTES_V1 - prefix.len());
            PoolMemberV2::new(
                node_public_key(seed),
                ALL_ROLES,
                PoolMemberRouteV2::new(format!("{prefix}{padding}")).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let statement = spec.statement().unwrap();
    let statement_bytes = statement.canonical_bytes().unwrap();
    assert!(
        statement_bytes.len() > MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1,
        "the test descriptor must exceed the cap: {} bytes",
        statement_bytes.len()
    );
    let signature = sign(&authority_key(POOL_AUTHORITY), &statement_bytes);
    assert_eq!(
        SignedPoolDescriptorV2::new(statement, signature),
        Err(ContractError::FieldTooLong("signed_pool_descriptor"))
    );
}

#[test]
fn guard_descriptor_with_too_many_admitted_minters_is_refused() {
    let minters = |count: u8| -> Vec<RuntimeOperationIssuerKeyV1> {
        (1..=count).map(runtime_issuer_for).collect()
    };
    let mut spec = DescriptorSpec::standard();
    spec.mint_policy = MintPolicyV1 {
        admitted_minters: minters(u8::try_from(MAX_ADMITTED_MINTERS_V1).unwrap()),
        allow_self_seal: false,
        max_seals_per_sealer: 8,
    };
    spec.statement().unwrap();

    spec.mint_policy.admitted_minters = minters(u8::try_from(MAX_ADMITTED_MINTERS_V1 + 1).unwrap());
    assert_eq!(
        spec.statement(),
        Err(ContractError::InvalidField("mint_policy.admitted_minters"))
    );

    spec.mint_policy.admitted_minters = vec![runtime_issuer(), runtime_issuer()];
    assert_eq!(
        spec.statement(),
        Err(ContractError::InvalidField("mint_policy.admitted_minters"))
    );
}

#[test]
fn epoch_for_matches_only_the_items_epoch() {
    let spec = DescriptorSpec::standard();
    let verified = spec.signed().verify(NOW).unwrap();
    let item = key_envelope_for(&spec.bundles[0]);
    assert_eq!(verified.epoch_for(&item), Some(&spec.bundles[0]));
    assert!(spec.bundles[0].matches_key_envelope(&item).unwrap());

    let other = bundle(&BundleSpec {
        nodes: vec![4, 5, 6],
        ..BundleSpec::default()
    });
    let other_item = key_envelope_for(&other);
    assert_eq!(verified.epoch_for(&other_item), None);
    assert!(!spec.bundles[0].matches_key_envelope(&other_item).unwrap());
}

#[test]
fn pool_address_canonical_round_trips() {
    // Item 10: the writer form (v2) carries the peer DID only.
    let address = PoolAddressV2::new(pool_did(), route(1)).unwrap();
    let bytes = address.canonical_bytes().unwrap();
    let decoded = PoolAddressV2::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(decoded, address);
    assert_eq!(decoded.pool(), &pool_did());
    assert_eq!(decoded.bootstrap(), &route(1));

    // The historical v1 form still reads, with and without a ticket.
    for bootstrap in [
        route_v1(1),
        PoolMemberRouteV1::new("did:key:z6MkPoolNode01".to_string(), None).unwrap(),
    ] {
        let address = PoolAddressV1::new(pool_did(), bootstrap.clone()).unwrap();
        let bytes = address.canonical_bytes().unwrap();
        let decoded = PoolAddressV1::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, address);
        assert_eq!(decoded.pool(), &pool_did());
        assert_eq!(decoded.bootstrap(), &bootstrap);
    }
    let did = pool_did().to_did_key().unwrap();
    assert!(did.starts_with("did:key:z6Mk"));
    assert_eq!(PoolDidV1::parse_did_key(&did).unwrap(), pool_did());
    assert_eq!(pool_did().issuer(), authority(POOL_AUTHORITY));

    let mut wrong_domain = PoolAddressV2::new(pool_did(), route(1))
        .unwrap()
        .canonical_bytes()
        .unwrap();
    wrong_domain[0] ^= 1;
    assert_eq!(
        PoolAddressV2::from_canonical_bytes(&wrong_domain),
        Err(ContractError::WrongDomain)
    );
    assert_eq!(
        PoolAddressAnyV1::from_canonical_bytes(&wrong_domain),
        Err(ContractError::WrongDomain)
    );
}

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

#[test]
fn guard_attestation_from_member_without_serve_role_is_refused() {
    let mut spec = DescriptorSpec::standard();
    spec.members[1] = member(2, HOLD_ONLY);
    let verified = spec.signed().verify(NOW).unwrap();
    let epoch = spec.bundles[0].signed_epoch().verify().unwrap();
    let binding = binding_for(&spec.bundles[0]);
    let vouched = attestation(&binding, 9, 2, epoch.epoch_identity(), pool_did());
    assert_eq!(
        vouched.verify(&verified, &epoch, NOW + 3).map(|_| ()),
        Err(PoolContractError::RoleMissing)
    );
    // The same vouch from a serving member verifies.
    attestation(&binding, 9, 1, epoch.epoch_identity(), pool_did())
        .verify(&verified, &epoch, NOW + 3)
        .unwrap();
}

#[test]
fn guard_attestation_for_another_pool_or_epoch_is_refused() {
    let spec = DescriptorSpec::standard();
    let verified = spec.signed().verify(NOW).unwrap();
    let epoch = spec.bundles[0].signed_epoch().verify().unwrap();
    let binding = binding_for(&spec.bundles[0]);

    let other_pool = attestation(
        &binding,
        9,
        1,
        epoch.epoch_identity(),
        PoolDidV1::from_issuer(authority(OTHER_AUTHORITY)),
    );
    assert_eq!(
        other_pool.verify(&verified, &epoch, NOW + 3).map(|_| ()),
        Err(PoolContractError::IssuerMismatch)
    );

    let other_epoch = attestation(
        &binding,
        9,
        1,
        CustodyEpochIdentityV1::new(digest(0xee), 512).unwrap(),
        pool_did(),
    );
    assert_eq!(
        other_epoch.verify(&verified, &epoch, NOW + 3).map(|_| ()),
        Err(PoolContractError::EpochMismatch)
    );
}

// ---------------------------------------------------------------------------
// Rights V2
// ---------------------------------------------------------------------------

#[test]
fn rights_v2_recipients_must_be_sorted_unique_and_at_most_four() {
    let binding = binding_for(&bundle(&BundleSpec::default()));
    let by_canonical_bytes = |seeds: &[u8]| {
        let mut identities: Vec<RecipientKeyIdentityV1> =
            seeds.iter().copied().map(recipient).collect();
        identities.sort_by_key(|identity| identity.canonical_bytes().unwrap());
        identities
    };

    // Given in any order, kept in canonical-byte order.
    let request = rights_request_v2(binding.clone(), vec![recipient(12), recipient(11)]).unwrap();
    assert_eq!(
        request.recipients(),
        by_canonical_bytes(&[11, 12]).as_slice()
    );
    let decoded =
        RightsRequestV2::from_canonical_bytes(&request.canonical_bytes().unwrap()).unwrap();
    assert_eq!(decoded, request);

    for refused in [
        vec![],
        vec![recipient(11), recipient(11)],
        (11..=15).map(recipient).collect::<Vec<_>>(),
    ] {
        assert_eq!(
            rights_request_v2(binding.clone(), refused),
            Err(ContractError::InvalidField("rights_request.recipients"))
        );
    }
    assert_eq!(
        rights_request_v2(binding, (11..=14).map(recipient).collect())
            .unwrap()
            .recipients()
            .len(),
        4
    );
}

#[test]
fn rights_any_decodes_v1_and_v2_by_domain() {
    let binding = binding_for(&bundle(&BundleSpec::default()));
    let v1 = RightsRequestV1::new(
        binding.clone(),
        RightsActionV1::View,
        recipient(9),
        NOW,
        NOW + 180,
        ReplayNonce16::new([0x55; 16]),
    )
    .unwrap();
    let v2 = rights_request_v2(binding, vec![recipient(9)]).unwrap();

    match RightsRequestAnyV1::from_canonical_bytes(&v1.canonical_bytes().unwrap()).unwrap() {
        RightsRequestAnyV1::V1(decoded) => assert_eq!(decoded, v1),
        RightsRequestAnyV1::V2(_) => panic!("V1 bytes decoded as V2"),
    }
    let any_v2 = RightsRequestAnyV1::from_canonical_bytes(&v2.canonical_bytes().unwrap()).unwrap();
    match &any_v2 {
        RightsRequestAnyV1::V2(decoded) => assert_eq!(decoded, &v2),
        RightsRequestAnyV1::V1(_) => panic!("V2 bytes decoded as V1"),
    }
    assert_eq!(any_v2.request_hash().unwrap(), v2.request_hash().unwrap());
    assert_eq!(any_v2.binding(), v2.binding());
    assert_eq!(any_v2.expires_at(), NOW + 180);

    // ADV-01 R2: V2 signs its own consent text, not the V1 layout.
    let message = v2.signing_message().unwrap();
    assert_ne!(message, v1.signing_message().unwrap());
    assert_eq!(
        message.lines().next(),
        Some(
            format!(
                "ElastOS rights-request/v2 chain {}",
                policy_body().chain_id()
            )
            .as_str()
        )
    );
    assert!(message.contains(&format!(
        "\nDelivery key: 0x{}\n",
        encode(&delivery_key().digest().as_bytes()[..8])
    )));
    assert!(message.contains(&format!(
        "\nServer:  0x{}\n",
        encode(&recipient(9).key_id().as_bytes()[..8])
    )));
    assert!(!message.contains("Device:"));
    assert!(message.ends_with(&format!(
        "Request: 0x{}\n",
        encode(v2.request_hash().unwrap().as_bytes())
    )));
    assert_eq!(any_v2.signing_message().unwrap(), message);

    let mut wrong_domain = v2.canonical_bytes().unwrap();
    wrong_domain[0] ^= 1;
    assert_eq!(
        RightsRequestAnyV1::from_canonical_bytes(&wrong_domain),
        Err(ContractError::WrongDomain)
    );
}

#[test]
fn rights_v2_replay_key_changes_with_every_scoped_field() {
    let binding = binding_for(&bundle(&BundleSpec::default()));
    let base = rights_request_v2(binding.clone(), vec![recipient(9)]).unwrap();
    let other_recipient = rights_request_v2(binding.clone(), vec![recipient(10)]).unwrap();
    let other_delivery = RightsRequestV2::new(
        binding,
        RightsActionV1::View,
        vec![recipient(9)],
        DeliveryPublicKeyBytesV1::new(xwing_public_key_bytes(0x5e))
            .unwrap()
            .identity(),
        NOW,
        NOW + 180,
        ReplayNonce16::new([0x55; 16]),
        policy_body().chain_id(),
    )
    .unwrap();
    let key = base.replay_claim_key().unwrap();
    assert_ne!(key, other_recipient.replay_claim_key().unwrap());
    assert_ne!(key, other_delivery.replay_claim_key().unwrap());
}

// ---------------------------------------------------------------------------
// Operation V2
// ---------------------------------------------------------------------------

#[test]
fn operation_v2_declared_issuer_verifies() {
    let spec = OperationSpec::standard();
    let signed = spec.signed();
    let decoded =
        SignedRuntimeReleaseOperationV2::from_canonical_bytes(&signed.canonical_bytes().unwrap())
            .unwrap();
    assert_eq!(decoded, signed);

    let declared = signed
        .verify(RuntimeIssuerPolicyV1::Declared, NOW + 3)
        .unwrap();
    let expected = signed
        .verify(RuntimeIssuerPolicyV1::Expected(runtime_issuer()), NOW + 3)
        .unwrap();
    assert_eq!(declared, expected);
    assert_eq!(
        declared.operation_hash(),
        signed.statement().canonical_hash().unwrap()
    );
    assert_eq!(
        declared.rights_request_hash(),
        signed
            .statement()
            .rights_request()
            .request()
            .request_hash()
            .unwrap()
    );
    assert_eq!(declared.runtime_operation_issuer(), runtime_issuer());
    assert_eq!(declared.pool(), &pool_did());
    assert_eq!(declared.descriptor_sequence(), 1);
    assert_eq!(declared.delivery_key(), delivery_key());
    assert_eq!(declared.recipients().len(), 1);
    assert_eq!(declared.epoch_bundle(), &spec.item_bundle);
    assert_eq!(
        declared.custody_epoch_identity(),
        spec.item_bundle.signed_epoch().epoch_identity().unwrap()
    );
    assert_eq!(signed.unverified_epoch_bundle(), Some(&spec.item_bundle));
}

#[test]
fn guard_operation_v2_recipient_not_in_rights_set_is_refused() {
    let mut spec = OperationSpec::standard();
    spec.rights_recipients = Some(vec![10]);
    assert_eq!(
        spec.statement(),
        Err(ContractError::InvalidField("recipients"))
    );
}

#[test]
fn guard_operation_v2_recipient_without_attestation_from_member_is_refused() {
    let mut spec = OperationSpec::standard();
    // Node 9 is in no committee and is no descriptor member.
    spec.recipients = vec![(9, 9)];
    assert_eq!(
        spec.signed()
            .verify(RuntimeIssuerPolicyV1::Declared, NOW + 3),
        Err(RuntimeReleaseOperationError::Pool(
            PoolContractError::NotMember
        ))
    );
}

#[test]
fn guard_operation_v2_expected_policy_rejects_other_issuer() {
    let signed = OperationSpec::standard().signed();
    assert_eq!(
        signed.verify(
            RuntimeIssuerPolicyV1::Expected(runtime_issuer_for(OTHER_RUNTIME)),
            NOW + 3
        ),
        Err(RuntimeReleaseOperationError::BindingMismatch(
            "runtime_operation_issuer"
        ))
    );
}

#[test]
fn guard_operation_v2_signed_by_another_key_is_refused() {
    let statement = OperationSpec::standard().statement().unwrap();
    let forged = SignedRuntimeReleaseOperationV2::new(
        statement.clone(),
        sign(
            &SigningKey::from_bytes(&[OTHER_RUNTIME; 32]),
            &statement.canonical_bytes().unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(
        forged.verify(RuntimeIssuerPolicyV1::Declared, NOW + 3),
        Err(RuntimeReleaseOperationError::InvalidRuntimeSignature)
    );
}

#[test]
fn guard_operation_v2_descriptor_without_the_items_bundle_is_refused() {
    let mut spec = OperationSpec::standard();
    // The item names another committee; the descriptor does not hold it (L3).
    spec.item_bundle = bundle(&BundleSpec {
        nodes: vec![4, 5, 6],
        ..BundleSpec::default()
    });
    assert_eq!(spec.signed().unverified_epoch_bundle(), None);
    assert_eq!(
        spec.signed()
            .verify(RuntimeIssuerPolicyV1::Declared, NOW + 3),
        Err(RuntimeReleaseOperationError::Pool(
            PoolContractError::EpochMismatch
        ))
    );
}

#[test]
fn operation_v2_decision_and_contribution_bind_the_operation_hash() {
    let spec = OperationSpec::standard();
    let operation = spec.authenticated();
    let node_set = item_node_set(&spec);
    assert_ne!(operation.operation_hash(), operation.rights_request_hash());

    let decision = decision_for(&operation, 1, operation.operation_hash());
    let verified = operation
        .verify_node_rights_decision(&decision, &node_set, NOW + 6)
        .unwrap();
    operation
        .validate_node_contribution_active_window(NOW + 4, NOW + 30, &verified, NOW + 6)
        .unwrap();
    // L1: the rights hash in the release slot is refused.
    let rights_slot = decision_for(&operation, 1, operation.rights_request_hash());
    assert_eq!(
        operation.verify_node_rights_decision(&rights_slot, &node_set, NOW + 6),
        Err(KeyReleaseError::BindingMismatch("key_release_request_hash"))
    );

    let contribution = contribution_for(&operation, 1, recipient(9));
    let verified = operation
        .verify_node_contribution(&contribution, &node_set, &recipient(9), NOW + 6)
        .unwrap();
    assert_eq!(verified.release_request_hash(), operation.operation_hash());
    assert_eq!(verified.recipient(), &recipient(9));
}

#[test]
fn guard_v2_contribution_for_a_recipient_outside_the_set_is_refused() {
    let spec = OperationSpec::standard();
    let operation = spec.authenticated();
    let node_set = item_node_set(&spec);
    let outside = contribution_for(&operation, 1, recipient(10));
    assert_eq!(
        operation.verify_node_contribution(&outside, &node_set, &recipient(10), NOW + 6),
        Err(KeyReleaseError::BindingMismatch("recipient_key_identity"))
    );
    // Sealed to a recipient other than the one asked for.
    assert_eq!(
        operation.verify_node_contribution(&outside, &node_set, &recipient(9), NOW + 6),
        Err(KeyReleaseError::BindingMismatch("recipient_key_identity"))
    );
}

#[test]
fn v2_terminal_receipt_binds_the_operation_hash() {
    let spec = OperationSpec::standard();
    let operation = spec.authenticated();
    let node_set = item_node_set(&spec);
    let contributions: Vec<VerifiedNodeContributionV1> = [1, 2]
        .into_iter()
        .map(|node| {
            operation
                .verify_node_contribution(
                    &contribution_for(&operation, node, recipient(9)),
                    &node_set,
                    &recipient(9),
                    NOW + 6,
                )
                .unwrap()
        })
        .collect();
    let issuer_key = SigningKey::from_bytes(&[TERMINAL_ISSUER; 32]);
    let issuer = TerminalReceiptIssuerKey::new(issuer_key.verifying_key().to_bytes()).unwrap();
    let receipt = |release_request_hash: Digest32| {
        let statement = TerminalReceiptStatementV1::new(
            release_request_hash,
            operation.binding().clone(),
            issuer,
            KeyReleaseOutcomeV1::Released,
            contributions
                .iter()
                .map(NodeContributionRefV1::from)
                .collect(),
            NOW + 5,
            NOW + 30,
        )
        .unwrap();
        SignedTerminalReceiptV1::new(
            statement.clone(),
            sign(&issuer_key, &statement.canonical_bytes().unwrap()),
        )
        .unwrap()
    };
    operation
        .verify_terminal_receipt(
            &receipt(operation.operation_hash()),
            &contributions,
            issuer,
            NOW + 6,
        )
        .unwrap();
    assert_eq!(
        operation.verify_terminal_receipt(
            &receipt(operation.rights_request_hash()),
            &contributions,
            issuer,
            NOW + 6,
        ),
        Err(KeyReleaseError::BindingMismatch("key_release_request_hash"))
    );
}

// ---------------------------------------------------------------------------
// One terminal receipt per signed recipient (user decision 2026-11-12 11:00):
// a receipt verifies only with the contributions of the recipient it was
// issued for; cross-recipient and mixed sets are refused.
// ---------------------------------------------------------------------------

/// A V2 operation for recipients 9 (server 1) and 10 (server 2).
fn two_recipient_operation() -> (AuthenticatedRuntimeReleaseOperationV2, crate::NodeSetV1) {
    let mut descriptor = DescriptorSpec::standard();
    descriptor.serve_policy = serve_policy(2);
    let mut spec = OperationSpec::with_descriptor(descriptor);
    spec.recipients = vec![(9, 1), (10, 2)];
    let node_set = item_node_set(&spec);
    (spec.authenticated(), node_set)
}

/// Verified contributions, each `(node, recipient seed)`.
fn verified_contributions_for(
    operation: &AuthenticatedRuntimeReleaseOperationV2,
    node_set: &crate::NodeSetV1,
    parts: &[(u8, u8)],
) -> Vec<VerifiedNodeContributionV1> {
    parts
        .iter()
        .map(|&(node, seed)| {
            operation
                .verify_node_contribution(
                    &contribution_for(operation, node, recipient(seed)),
                    node_set,
                    &recipient(seed),
                    NOW + 6,
                )
                .unwrap()
        })
        .collect()
}

fn terminal_issuer() -> (SigningKey, TerminalReceiptIssuerKey) {
    let key = SigningKey::from_bytes(&[TERMINAL_ISSUER; 32]);
    let issuer = TerminalReceiptIssuerKey::new(key.verifying_key().to_bytes()).unwrap();
    (key, issuer)
}

/// A Released receipt over `contributions`, valid from `issued_at`.
fn released_receipt(
    operation: &AuthenticatedRuntimeReleaseOperationV2,
    contributions: &[VerifiedNodeContributionV1],
    issued_at: u64,
) -> SignedTerminalReceiptV1 {
    let (key, issuer) = terminal_issuer();
    let statement = TerminalReceiptStatementV1::new(
        operation.operation_hash(),
        operation.binding().clone(),
        issuer,
        KeyReleaseOutcomeV1::Released,
        contributions
            .iter()
            .map(NodeContributionRefV1::from)
            .collect(),
        issued_at,
        NOW + 30,
    )
    .unwrap();
    SignedTerminalReceiptV1::new(
        statement.clone(),
        sign(&key, &statement.canonical_bytes().unwrap()),
    )
    .unwrap()
}

#[test]
fn v2_each_signed_recipient_verifies_its_own_terminal_receipt() {
    let (operation, node_set) = two_recipient_operation();
    let (_, issuer) = terminal_issuer();
    for seed in [9, 10] {
        let contributions =
            verified_contributions_for(&operation, &node_set, &[(1, seed), (2, seed)]);
        let receipt = released_receipt(&operation, &contributions, NOW + 5);
        assert_eq!(
            operation.verify_terminal_receipt(&receipt, &contributions, issuer, NOW + 6),
            Ok(()),
            "recipient {seed}"
        );
    }
}

#[test]
fn guard_v2_terminal_receipt_for_one_recipient_is_refused_for_another() {
    let (operation, node_set) = two_recipient_operation();
    let (_, issuer) = terminal_issuer();
    let for_9 = verified_contributions_for(&operation, &node_set, &[(1, 9), (2, 9)]);
    let for_10 = verified_contributions_for(&operation, &node_set, &[(1, 10), (2, 10)]);
    let receipt_9 = released_receipt(&operation, &for_9, NOW + 5);
    let receipt_10 = released_receipt(&operation, &for_10, NOW + 5);
    assert_eq!(
        operation.verify_terminal_receipt(&receipt_9, &for_10, issuer, NOW + 6),
        Err(KeyReleaseError::BindingMismatch("node_contribution_refs"))
    );
    assert_eq!(
        operation.verify_terminal_receipt(&receipt_10, &for_9, issuer, NOW + 6),
        Err(KeyReleaseError::BindingMismatch("node_contribution_refs"))
    );
}

#[test]
fn guard_v2_terminal_receipt_over_a_mixed_recipient_set_is_refused() {
    let (operation, node_set) = two_recipient_operation();
    let (_, issuer) = terminal_issuer();
    // One recipient's contribution with another's, in either order, under a
    // receipt that names exactly those contributions.
    for parts in [[(1, 9), (2, 10)], [(1, 10), (2, 9)]] {
        let mixed = verified_contributions_for(&operation, &node_set, &parts);
        let receipt = released_receipt(&operation, &mixed, NOW + 5);
        assert_eq!(
            operation.verify_terminal_receipt(&receipt, &mixed, issuer, NOW + 6),
            Err(KeyReleaseError::BindingMismatch("recipient_key_identity")),
            "{parts:?}"
        );
    }
    // One recipient's receipt with a set that also holds the other's
    // contribution.
    let for_9 = verified_contributions_for(&operation, &node_set, &[(1, 9), (2, 9)]);
    let receipt_9 = released_receipt(&operation, &for_9, NOW + 5);
    let mixed = verified_contributions_for(&operation, &node_set, &[(1, 9), (2, 10)]);
    assert_eq!(
        operation.verify_terminal_receipt(&receipt_9, &mixed, issuer, NOW + 6),
        Err(KeyReleaseError::BindingMismatch("recipient_key_identity"))
    );
}

/// Pins today's behaviour: receipt verification is stateless, so the same
/// receipt verifies again, and a second receipt for the same recipient and
/// contributions (another issue time) verifies as well. Deduplication is
/// not a property of `verify_terminal_receipt`.
#[test]
fn v2_duplicate_terminal_receipt_for_one_recipient_verifies_again() {
    let (operation, node_set) = two_recipient_operation();
    let (_, issuer) = terminal_issuer();
    let for_9 = verified_contributions_for(&operation, &node_set, &[(1, 9), (2, 9)]);
    let first = released_receipt(&operation, &for_9, NOW + 5);
    let second = released_receipt(&operation, &for_9, NOW + 6);
    assert_ne!(first, second);
    for receipt in [&first, &first, &second] {
        assert_eq!(
            operation.verify_terminal_receipt(receipt, &for_9, issuer, NOW + 6),
            Ok(())
        );
    }
}

// ---------------------------------------------------------------------------
// Known-answer vectors for V2 signed and durable preimages (append-only;
// audit M6, 2026-11-12). The V2 release operation and statement are pinned
// as V-OP in `runtime_release_operation.rs`; the pool descriptor waits for
// its format decision.
// ---------------------------------------------------------------------------

/// `canonical_bytes` as hex and their sha256, as pinned below.
fn kat(bytes: &[u8]) -> (String, String) {
    (encode(bytes), encode(Sha256::digest(bytes)))
}

/// The recipient attestation of the standard operation's recipient 9,
/// vouched by server 1.
fn kat_attestation() -> SignedPoolRecipientAttestationV1 {
    let spec = OperationSpec::standard();
    let epoch = spec.item_bundle.signed_epoch().epoch_identity().unwrap();
    attestation(&spec.binding(), 9, 1, epoch, pool_did())
}

fn kat_viewer_part_aads() -> Vec<crate::ViewerPartAadV1> {
    [
        crate::ViewerPartIndexV1::MediaV1Init,
        crate::ViewerPartIndexV1::MediaV1Segment(3),
        crate::ViewerPartIndexV1::DashInit { rendition: 1 },
        crate::ViewerPartIndexV1::DashSegment {
            rendition: 1,
            index: 7,
        },
        crate::ViewerPartIndexV1::ObjectChunk(5),
    ]
    .into_iter()
    .map(|part| crate::ViewerPartAadV1 {
        session_id: [0x5e; 16],
        operation_hash: Digest32::new([0x0b; 32]),
        part,
    })
    .collect()
}

#[test]
#[ignore = "prints the M6 vectors; run with --ignored --nocapture"]
fn m6_vector_dump() {
    let signed = kat_attestation();
    let (hex, sha) = kat(&signed.statement().canonical_bytes().unwrap());
    println!("ATTESTATION-STATEMENT {hex} {sha}");
    let (hex, sha) = kat(&signed.canonical_bytes().unwrap());
    println!("ATTESTATION-SIGNED {hex} {sha}");
    for aad in kat_viewer_part_aads() {
        let (hex, sha) = kat(&aad.canonical_bytes().unwrap());
        println!("AAD {:?} {hex} {sha}", aad.part);
    }
}

/// M6: the pool recipient attestation (statement 2,459 bytes, signed 2,583
/// bytes). Values reproduced on two runs and with an external `shasum`.
#[test]
fn v2_recipient_attestation_vector() {
    let signed = kat_attestation();
    let statement = signed.statement().canonical_bytes().unwrap();
    assert_eq!(statement.len(), 2459);
    assert_eq!(
        kat(&statement).1,
        "d5d15a20b8d7294a51c8dc2b565fc001ab2e0b37380a4979b2510359975a563e"
    );
    let bytes = signed.canonical_bytes().unwrap();
    assert_eq!(bytes.len(), 2583);
    assert_eq!(
        kat(&bytes).1,
        "c2ec1249f8b7064f31bdd75dbe7b37c2fa91475a85a610847684491f7cce1ee8"
    );
    assert_eq!(
        SignedPoolRecipientAttestationV1::from_canonical_bytes(&bytes).unwrap(),
        signed
    );
}

/// M6: the viewer-part AAD for every part kind (session `0x5e`×16,
/// operation hash `0x0b`×32). Values reproduced on two runs and with an
/// external `shasum`.
#[test]
fn v2_viewer_part_aad_vectors() {
    let expected = [
        (
            "656c6173746f732e70726f7465637465642d636f6e74656e742e7669657765722d706172742d6161642f7631005e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b01",
            "d409123517c1bcd0a86148f6d22c443d473c1329681edc9f43e3e0bf392c175e",
        ),
        (
            "656c6173746f732e70726f7465637465642d636f6e74656e742e7669657765722d706172742d6161642f7631005e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0200000003",
            "32241b8ea60a1f16016d13a6ba81c6876ad9ed4cd03b7e7834d2d310453cff0d",
        ),
        (
            "656c6173746f732e70726f7465637465642d636f6e74656e742e7669657765722d706172742d6161642f7631005e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0301",
            "6a4762b3a64d5631e556ec67225893bfb0196831115243617ddb66a7d90e8454",
        ),
        (
            "656c6173746f732e70726f7465637465642d636f6e74656e742e7669657765722d706172742d6161642f7631005e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b040100000007",
            "14d6ff3536c8824b7989c09c81cf7dbe630e5b5f75b3d0b34b9b0aedf24abb07",
        ),
        (
            "656c6173746f732e70726f7465637465642d636f6e74656e742e7669657765722d706172742d6161642f7631005e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0500000005",
            "7c293d839863ed579f7ce79f805835665871e47da246da27139f91c623f3c327",
        ),
    ];
    let aads = kat_viewer_part_aads();
    assert_eq!(aads.len(), expected.len());
    for (aad, (hex, sha)) in aads.iter().zip(expected) {
        let bytes = aad.canonical_bytes().unwrap();
        assert_eq!(
            kat(&bytes),
            (hex.to_string(), sha.to_string()),
            "{:?}",
            aad.part
        );
        assert_eq!(
            &crate::ViewerPartAadV1::from_canonical_bytes(&bytes).unwrap(),
            aad
        );
    }
}

#[test]
fn v2_evidence_binds_the_operation_hash_in_both_slots() {
    let operation = OperationSpec::standard().authenticated();
    let evidence = |release_request_hash: Digest32| {
        crate::RightsEvaluationEvidenceV1::new(
            operation.operation_hash(),
            release_request_hash,
            operation.binding().clone(),
            policy_body().policy_identity().unwrap(),
            operation.binding().wallet(),
            11155111,
            100,
            digest(0x88),
            true,
            NOW + 3,
            NOW + 30,
        )
        .unwrap()
    };
    evidence(operation.operation_hash())
        .validate_against_runtime_release_v2_at(&operation, NOW + 6)
        .unwrap();
    evidence(operation.operation_hash())
        .validate_against_runtime_release_any_at(
            &AuthenticatedRuntimeReleaseOperationAnyV1::V2(operation.clone()),
            NOW + 6,
        )
        .unwrap();
    assert_eq!(
        evidence(operation.rights_request_hash())
            .validate_against_runtime_release_v2_at(&operation, NOW + 6),
        Err(ContractError::InvalidField("evidence.release_request_hash"))
    );
}

// ---------------------------------------------------------------------------
// F1: release-time bundle rule (the term gates provisioning only)
// ---------------------------------------------------------------------------

fn ended_member_windows() -> BundleSpec {
    BundleSpec {
        window: (NOW - 1_000, NOW - 10),
        ..BundleSpec::default()
    }
}

#[test]
fn descriptor_verifies_after_every_member_window_ends() {
    let spec = DescriptorSpec::with_bundle(&ended_member_windows());
    spec.signed().verify(NOW).unwrap();

    // The provisioning rule still refuses the same bundle.
    let bundle = &spec.bundles[0];
    let authorization = bundle
        .signed_committee_authorization()
        .authorization_identity()
        .unwrap();
    assert_eq!(
        validate_custody_epoch_against_pool_at(
            authority(POOL_AUTHORITY),
            authorization,
            bundle.signed_pool(),
            bundle.signed_epoch(),
            bundle.signed_committee_authorization(),
            NOW,
        )
        .map(|_| ()),
        Err(CustodyPoolError::Expired)
    );
    validate_custody_epoch_for_release_at(
        authority(POOL_AUTHORITY),
        authorization,
        bundle.signed_pool(),
        bundle.signed_epoch(),
        bundle.signed_committee_authorization(),
        NOW,
    )
    .unwrap();
}

#[test]
fn operation_v2_verifies_after_the_signed_member_window_ends() {
    let spec = OperationSpec::with_descriptor(DescriptorSpec::with_bundle(&ended_member_windows()));
    spec.signed()
        .verify(RuntimeIssuerPolicyV1::Declared, NOW + 3)
        .unwrap();
}

#[test]
fn guard_descriptor_with_a_revoked_member_is_refused() {
    let spec = DescriptorSpec::with_bundle(&BundleSpec {
        revoked: Some(2),
        ..BundleSpec::default()
    });
    assert_eq!(
        spec.signed().verify(NOW),
        Err(PoolContractError::CustodyPool(CustodyPoolError::Revoked))
    );
}

#[test]
fn guard_descriptor_with_a_member_not_yet_valid_is_refused() {
    let spec = DescriptorSpec::with_bundle(&BundleSpec {
        window: (NOW + 10, NOW + 1_000),
        ..BundleSpec::default()
    });
    assert_eq!(
        spec.signed().verify(NOW),
        Err(PoolContractError::CustodyPool(
            CustodyPoolError::NotYetValid
        ))
    );
}

// ---------------------------------------------------------------------------
// F5: the pool's server count holds the session
// ---------------------------------------------------------------------------

#[test]
fn guard_operation_v2_two_vouched_recipients_with_max_one_server_is_refused() {
    let mut spec = OperationSpec::standard();
    spec.recipients = vec![(9, 1), (10, 2)];
    assert_eq!(
        spec.signed()
            .verify(RuntimeIssuerPolicyV1::Declared, NOW + 3),
        Err(RuntimeReleaseOperationError::Pool(
            PoolContractError::TooMany
        ))
    );
}

#[test]
fn operation_v2_two_vouched_recipients_with_max_two_servers_verifies() {
    let mut descriptor = DescriptorSpec::standard();
    descriptor.serve_policy = serve_policy(2);
    let mut spec = OperationSpec::with_descriptor(descriptor);
    spec.recipients = vec![(9, 1), (10, 2)];
    let operation = spec.authenticated();
    assert_eq!(operation.recipients().len(), 2);
}

#[test]
fn guard_operation_v2_one_server_cannot_vouch_for_two_recipients() {
    let mut descriptor = DescriptorSpec::standard();
    descriptor.serve_policy = serve_policy(2);
    let mut spec = OperationSpec::with_descriptor(descriptor);
    spec.recipients = vec![(9, 1), (10, 1)];
    assert_eq!(
        spec.signed()
            .verify(RuntimeIssuerPolicyV1::Declared, NOW + 3),
        Err(RuntimeReleaseOperationError::Pool(
            PoolContractError::TooMany
        ))
    );
}

// ---------------------------------------------------------------------------
// F2: authenticated Any (the V1 arm is covered next to the V1 fixture in
// runtime_release_operation.rs)
// ---------------------------------------------------------------------------

#[test]
fn authenticated_any_v2_release_request_hash_is_the_operation_hash() {
    let spec = OperationSpec::standard();
    let operation = spec.authenticated();
    let any = AuthenticatedRuntimeReleaseOperationAnyV1::V2(operation.clone());
    assert!(any.as_v1().is_none());
    assert_eq!(any.as_v2(), Some(&operation));
    assert_eq!(any.operation_hash(), operation.operation_hash());
    assert_eq!(any.release_request_hash(), operation.operation_hash());
    assert_eq!(any.rights_request_hash(), operation.rights_request_hash());
    assert_eq!(any.binding(), operation.binding());
    assert_eq!(any.action(), RightsActionV1::View);
    assert_eq!(
        any.audit_request_id(),
        RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap()
    );
    assert_eq!(any.expires_at(), NOW + 40);
    assert_eq!(any.rights_expires_at(), NOW + 180);
    assert_eq!(any.node_set().unwrap(), item_node_set(&spec));

    let node_set = item_node_set(&spec);
    let decision = decision_for(&operation, 1, operation.operation_hash());
    assert_eq!(
        any.verify_node_rights_decision(&decision, &node_set, NOW + 6),
        operation.verify_node_rights_decision(&decision, &node_set, NOW + 6)
    );
}

// ---------------------------------------------------------------------------
// F3: the delivery key identity
// ---------------------------------------------------------------------------

#[test]
fn delivery_key_identity_is_derived_from_the_public_key() {
    let key = DeliveryPublicKeyBytesV1::new(xwing_public_key_bytes(0x5d)).unwrap();
    let identity = key.identity();
    assert_eq!(identity, key.identity());
    assert_ne!(
        identity,
        DeliveryPublicKeyBytesV1::new(xwing_public_key_bytes(0x5e))
            .unwrap()
            .identity()
    );

    // sha256(domain || 0x00 || key bytes): the one derivation.
    let mut hasher = Sha256::new();
    hasher.update(b"elastos.protected-content.delivery-key-identity/v1");
    hasher.update([0u8]);
    hasher.update(key.as_bytes());
    let expected: [u8; 32] = hasher.finalize().into();
    assert_eq!(identity.digest(), Digest32::new(expected));
}

// ---------------------------------------------------------------------------
// ADV-01: the operation and the aligned rights request v2 (contract rev 6,
// §4 step 1)
// ---------------------------------------------------------------------------

/// The offset just after `domain\0`.
fn after_domain(bytes: &[u8]) -> usize {
    bytes.iter().position(|byte| *byte == 0).unwrap() + 1
}

/// `bytes` with the `u16`-length-prefixed segment at `at` replaced.
fn replace_nested(bytes: &[u8], at: usize, replacement: &[u8]) -> Vec<u8> {
    let length = usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
    let mut out = bytes[..at].to_vec();
    out.extend_from_slice(&u16::try_from(replacement.len()).unwrap().to_be_bytes());
    out.extend_from_slice(replacement);
    out.extend_from_slice(&bytes[at + 2 + length..]);
    out
}

/// V2 statement bytes whose rights request (the segment after the 32-byte
/// Runtime issuer) is `rights_request`. Built by hand so a request that the
/// constructor refuses still reaches the decoder.
fn statement_bytes_with_rights(statement: &[u8], rights_request: &[u8]) -> Vec<u8> {
    replace_nested(statement, after_domain(statement) + 32, rights_request)
}

#[test]
fn guard_operation_v2_with_direct_rights_is_refused() {
    let mut spec = OperationSpec::standard();
    spec.direct_rights = true;
    assert_eq!(
        spec.statement(),
        Err(ContractError::InvalidField("rights_request.delivery_key"))
    );

    let standard = OperationSpec::standard()
        .statement()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let direct = wallet_signed(
        RightsRequestV2::new_direct(
            spec.binding(),
            RightsActionV1::View,
            recipient(9),
            NOW,
            NOW + 180,
            ReplayNonce16::new([0x55; 16]),
            policy_body().chain_id(),
        )
        .unwrap(),
    );
    assert_eq!(
        RuntimeReleaseOperationStatementV2::from_canonical_bytes(&statement_bytes_with_rights(
            &standard,
            &direct.canonical_bytes().unwrap()
        )),
        Err(ContractError::InvalidField("rights_request.delivery_key"))
    );
}

/// AD01-F7 test 2: a request whose chain changed while its policy did not.
#[test]
fn operation_v2_rights_chain_must_match_policy_chain() {
    assert_ne!(policy_body().chain_id(), 8453);
    let mut spec = OperationSpec::standard();
    spec.rights_chain_id = Some(8453);
    assert_eq!(
        spec.statement(),
        Err(ContractError::InvalidField("rights_request.chain_id"))
    );

    let standard = OperationSpec::standard()
        .statement()
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let other_chain = wallet_signed(
        rights_request_v2_on_chain(spec.binding(), vec![recipient(9)], 8453).unwrap(),
    );
    assert_eq!(
        RuntimeReleaseOperationStatementV2::from_canonical_bytes(&statement_bytes_with_rights(
            &standard,
            &other_chain.canonical_bytes().unwrap()
        )),
        Err(ContractError::InvalidField("rights_request.chain_id"))
    );
}

#[test]
fn operation_v2_authenticated_delivery_key_is_the_signed_one() {
    let spec = OperationSpec::standard();
    let signed = spec.signed();
    let operation = signed
        .verify(RuntimeIssuerPolicyV1::Declared, NOW + 3)
        .unwrap();
    assert_eq!(
        Some(operation.delivery_key()),
        signed.statement().rights_request().request().delivery_key()
    );
    assert_eq!(operation.delivery_key(), delivery_key());
}

/// AD01-F7 test 1: two VALID requests whose policies differ only in their
/// chain, each request on its own policy's chain, everything else equal
/// (the nonce too). The chain reaches the scope through the binding's
/// policy identity. No test asserts that the raw request chain alone changes
/// the key.
#[test]
fn replay_key_differs_across_chains() {
    let bundle = bundle(&BundleSpec::default());
    let request_on = |chain_id: u64| {
        let binding = binding_for_policy(&bundle, &policy_body_on_chain(chain_id));
        rights_request_v2_on_chain(binding, vec![recipient(9)], chain_id).unwrap()
    };
    let base = request_on(8453);
    let other = request_on(20);
    assert_ne!(
        base.binding().rights_policy(),
        other.binding().rights_policy()
    );
    assert_eq!(base.replay_nonce(), other.replay_nonce());
    assert_eq!(base.recipients(), other.recipients());
    assert_eq!(base.delivery_key(), other.delivery_key());

    let base_key = base.replay_claim_key().unwrap();
    let other_key = other.replay_claim_key().unwrap();
    assert_ne!(
        base_key.authority_scope_hash(),
        other_key.authority_scope_hash()
    );
    assert_ne!(base_key, other_key);
}

/// R5: the pre-alignment rights bytes inside a V2 operation reach the
/// caller as the same typed error, through the statement, the signed
/// operation and the V1-or-V2 dispatch.
#[test]
fn guard_pre_alignment_v2_rights_in_an_operation_are_refused_as_unsupported() {
    let unsupported = ContractError::UnsupportedVersion(PRE_ALIGNMENT_V2);
    let signed = OperationSpec::standard().signed();
    let signed_bytes = signed.canonical_bytes().unwrap();
    let statement_bytes = signed.statement().canonical_bytes().unwrap();
    for n in 1..=4 {
        let statement = statement_bytes_with_rights(
            &statement_bytes,
            &archived_pre_alignment_v2_wrapper_bytes(n),
        );
        assert_eq!(
            RuntimeReleaseOperationStatementV2::from_canonical_bytes(&statement),
            Err(unsupported.clone())
        );
        let operation = replace_nested(&signed_bytes, after_domain(&signed_bytes), &statement);
        assert_eq!(
            SignedRuntimeReleaseOperationV2::from_canonical_bytes(&operation),
            Err(unsupported.clone())
        );
        assert_eq!(
            RuntimeReleaseOperationAnyV1::from_canonical_bytes(&operation),
            Err(unsupported.clone())
        );
    }
}

// ---------------------------------------------------------------------------
// Item 10 (user 2026-11-12 22:50; DEC-F1): ticketless v2 descriptor and
// address formats. The v1 formats stay as read-only historical decoders and
// the vectors are append-only.
// ---------------------------------------------------------------------------

const POOL_DESCRIPTOR_V2_DOMAIN: &[u8] = b"elastos.protected-content.pool-descriptor/v2";
const POOL_DESCRIPTOR_STATEMENT_V1_DOMAIN: &[u8] =
    b"elastos.protected-content.pool-descriptor-statement/v1";
const POOL_DESCRIPTOR_STATEMENT_V2_DOMAIN: &[u8] =
    b"elastos.protected-content.pool-descriptor-statement/v2";
const POOL_ADDRESS_V1_DOMAIN: &[u8] = b"elastos.protected-content.pool-address/v1";
const POOL_ADDRESS_V2_DOMAIN: &[u8] = b"elastos.protected-content.pool-address/v2";

/// Frozen v1: `DescriptorSpec::standard().signed_v1()`, a ticket on every
/// route (10,505 bytes). Pinned from `item10_vector_dump`, reproduced on two
/// runs and with an external `shasum`.
const V1_DESCRIPTOR_SHA256: &str =
    "1494828216ba9485f7f4368db03d6e6a33ee486664d20027134effd9657fb993";
/// Appended v2: `DescriptorSpec::standard().signed()` (10,469 bytes), pinned
/// the same way.
const V2_DESCRIPTOR_SHA256: &str =
    "37e594aad6dd0fc60d744d7553fca3d6208ba8416d7f38ee338e0a46f474d477";
/// Frozen v1: `PoolAddressV1 { pool_did(), route_v1(1) }` (110 bytes). From
/// an independent encoder (Python, PyNaCl for the pool key).
const V1_POOL_ADDRESS_HEX: &str = "656c6173746f732e70726f7465637465642d636f6e74656e742e706f6f6c2d616464726573732f763100e2fe2a39b7326642827d6d82d497622cd6c297fe78270eaa436b01f086b6f3cb00166469643a6b65793a7a364d6b506f6f6c4e6f646530310100097469636b65742d3031";
const V1_POOL_ADDRESS_SHA256: &str =
    "ef4c3917e3333393f33d8315c91ce39b44a2c1ea234990c7dfc298faab80b64f";
/// Appended v2: `PoolAddressV2 { pool_did(), route(1) }` (98 bytes), from the
/// same independent encoder.
const V2_POOL_ADDRESS_HEX: &str = "656c6173746f732e70726f7465637465642d636f6e74656e742e706f6f6c2d616464726573732f763200e2fe2a39b7326642827d6d82d497622cd6c297fe78270eaa436b01f086b6f3cb00166469643a6b65793a7a364d6b506f6f6c4e6f64653031";
const V2_POOL_ADDRESS_SHA256: &str =
    "d58352cdcc60d1601839761bf0d6b75d0d08a30414f9a044b9d90ec431467bdf";

fn release_spec() -> crate::test_fixtures::PoolReleaseSpecV1 {
    crate::test_fixtures::PoolReleaseSpecV1::new(xwing_public_key_bytes, policy_body(), NOW)
}

/// Plan B S4 session lifetime (user 2026-11-13 04:45): a session opened
/// under a release ends at the signed rights expiry, capped by the earliest
/// recipient attestation expiry. The operation's own expiry bounds only the
/// node release.
#[test]
fn session_expires_at_is_rights_expiry_capped_by_attestation() {
    let fixture = crate::test_fixtures::pool_release_fixture(&release_spec());
    let operation = fixture.authenticated();
    assert_eq!(operation.statement().expires_at(), NOW + 40);
    assert_eq!(operation.session_expires_at(), NOW + 180);
    // The signed statement says the same before it is verified (the buyer's
    // client checks a server's answer against it).
    assert_eq!(
        fixture.operation.statement().session_expires_at(),
        NOW + 180
    );

    // Rights that outlive the attestations (`now + 200`) end with them.
    let mut spec = release_spec();
    spec.rights_expires_at = Some(NOW + 250);
    let capped = crate::test_fixtures::pool_release_fixture(&spec).authenticated();
    assert_eq!(capped.session_expires_at(), NOW + 200);
    assert!(capped.session_expires_at() <= NOW + crate::MAX_RIGHTS_REQUEST_LIFETIME_SECS);
}

#[test]
fn v1_descriptor_vector_still_verifies_and_exposes_no_ticket() {
    let spec = DescriptorSpec::standard();
    let signed = spec.signed_v1();
    assert!(signed
        .statement()
        .members()
        .iter()
        .all(|member| member.route().connect_ticket().is_some()));
    let bytes = signed.canonical_bytes().unwrap();
    assert_eq!(kat(&bytes).1, V1_DESCRIPTOR_SHA256, "v1 descriptor sha256");

    let any = SignedPoolDescriptorAnyV1::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(any, SignedPoolDescriptorAnyV1::V1(signed));
    // The signature is checked over the exact original preimage.
    assert_eq!(any.canonical_bytes().unwrap(), bytes);
    assert_eq!(any.pool(), &pool_did());
    assert_eq!(any.sequence(), 1);

    // The verified form is the same ticketless value the v2 descriptor gives.
    let verified = any.verify(NOW).unwrap();
    assert_eq!(verified, spec.signed().verify(NOW).unwrap());
    assert_eq!(
        verified.member(node_public_key(2)).unwrap().route(),
        &route(2)
    );
}

#[test]
fn v1_pool_address_vector_still_parses() {
    let bytes = hex::decode(V1_POOL_ADDRESS_HEX).unwrap();
    assert_eq!(kat(&bytes).1, V1_POOL_ADDRESS_SHA256);
    let v1 = PoolAddressV1::new(pool_did(), route_v1(1)).unwrap();
    assert_eq!(v1.canonical_bytes().unwrap(), bytes);

    let any = PoolAddressAnyV1::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(any, PoolAddressAnyV1::V1(v1));
    assert_eq!(any.pool(), &pool_did());
    assert_eq!(any.peer_did(), "did:key:z6MkPoolNode01");
    assert_eq!(any.canonical_bytes().unwrap(), bytes);
}

#[test]
fn v2_descriptor_and_address_vectors_are_appended() {
    let address = PoolAddressV2::new(pool_did(), route(1)).unwrap();
    let bytes = address.canonical_bytes().unwrap();
    assert_eq!(
        kat(&bytes),
        (
            V2_POOL_ADDRESS_HEX.to_string(),
            V2_POOL_ADDRESS_SHA256.to_string()
        )
    );
    let any = PoolAddressAnyV1::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(any, PoolAddressAnyV1::V2(address));
    assert_eq!(any.peer_did(), "did:key:z6MkPoolNode01");

    let descriptor = DescriptorSpec::standard().signed();
    let bytes = descriptor.canonical_bytes().unwrap();
    assert_eq!(kat(&bytes).1, V2_DESCRIPTOR_SHA256, "v2 descriptor sha256");
    assert_eq!(
        SignedPoolDescriptorAnyV1::from_canonical_bytes(&bytes).unwrap(),
        SignedPoolDescriptorAnyV1::V2(descriptor)
    );
}

/// #388 A2: writers emit v3 (item 10's v2 is now historical).
#[test]
fn writers_emit_only_v3_descriptors() {
    let fixture = crate::test_fixtures::pool_release_fixture(&release_spec());
    assert!(matches!(
        fixture.descriptor,
        SignedPoolDescriptorAnyV1::V3(_)
    ));
    assert!(matches!(
        fixture.operation.statement().pool_descriptor(),
        SignedPoolDescriptorAnyV1::V3(_)
    ));
    let descriptor =
        crate::test_fixtures::pool_descriptor(&fixture.bundle, 1, runtime_issuer(), NOW);
    assert!(descriptor
        .canonical_bytes()
        .unwrap()
        .starts_with(POOL_DESCRIPTOR_V3_DOMAIN));
}

#[test]
fn v2_descriptor_encodes_no_ticket_and_no_presence_byte() {
    let spec = DescriptorSpec::standard();
    // The same fields in v1 without tickets: one presence byte per route.
    let v1_members = spec
        .members
        .iter()
        .map(|member| {
            PoolMemberV1::new(
                member.node_public_key(),
                member.roles(),
                PoolMemberRouteV1::new(member.route().peer_did().to_owned(), None).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let v1 = PoolDescriptorStatementV1::new(
        pool_did(),
        1,
        spec.bundles.clone(),
        v1_members,
        spec.serve_policy,
        spec.mint_policy.clone(),
        spec.window.0,
        spec.window.1,
    )
    .unwrap()
    .canonical_bytes()
    .unwrap();
    let v2 = spec.statement().unwrap().canonical_bytes().unwrap();
    assert!(v1.starts_with(POOL_DESCRIPTOR_STATEMENT_V1_DOMAIN));
    assert!(v2.starts_with(POOL_DESCRIPTOR_STATEMENT_V2_DOMAIN));
    assert_eq!(v2.len() + spec.members.len(), v1.len());
    assert!(spec
        .signed()
        .canonical_bytes()
        .unwrap()
        .starts_with(POOL_DESCRIPTOR_V2_DOMAIN));

    // The address: domain, separator, pool key, peer DID, and nothing after.
    let mut expected = POOL_ADDRESS_V2_DOMAIN.to_vec();
    expected.push(0);
    expected.extend_from_slice(pool_did().issuer().as_bytes());
    let did = route(1).peer_did().as_bytes().to_vec();
    expected.extend_from_slice(&u16::try_from(did.len()).unwrap().to_be_bytes());
    expected.extend_from_slice(&did);
    assert_eq!(
        PoolAddressV2::new(pool_did(), route(1))
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        expected
    );
}

#[test]
fn v2_refuses_a_ticket_field() {
    // A v1 address relabelled v2: its presence byte and ticket trail.
    for bootstrap in [
        route_v1(1),
        PoolMemberRouteV1::new("did:key:z6MkPoolNode01".to_string(), None).unwrap(),
    ] {
        let mut relabelled = PoolAddressV1::new(pool_did(), bootstrap)
            .unwrap()
            .canonical_bytes()
            .unwrap();
        assert!(relabelled.starts_with(POOL_ADDRESS_V1_DOMAIN));
        relabelled[POOL_ADDRESS_V1_DOMAIN.len() - 1] = b'2';
        assert_eq!(
            PoolAddressV2::from_canonical_bytes(&relabelled),
            Err(ContractError::TrailingBytes)
        );
        assert_eq!(
            PoolAddressAnyV1::from_canonical_bytes(&relabelled),
            Err(ContractError::TrailingBytes)
        );
    }

    // A v1 descriptor statement with tickets, relabelled v2, does not decode.
    let mut statement = DescriptorSpec::standard()
        .signed_v1()
        .statement()
        .canonical_bytes()
        .unwrap();
    statement[POOL_DESCRIPTOR_STATEMENT_V1_DOMAIN.len() - 1] = b'2';
    assert!(PoolDescriptorStatementV2::from_canonical_bytes(&statement).is_err());

    // The v2 route keeps the peer DID rules.
    assert_eq!(
        PoolMemberRouteV2::new(String::new()),
        Err(ContractError::InvalidField("pool_member.peer_did"))
    );
    assert_eq!(
        PoolMemberRouteV2::new("d".repeat(MAX_POOL_MEMBER_PEER_DID_BYTES_V1 + 1)),
        Err(ContractError::FieldTooLong("pool_member.peer_did"))
    );
}

/// Item 10 read path, #388 A2 admission: an operation nesting any descriptor
/// version decodes with the child's original bytes; only the v3 one (trust
/// present) verifies for a new release.
#[test]
fn operation_with_a_v1_or_v2_nested_descriptor_verifies() {
    for (v1_descriptor, v2_descriptor) in [(true, false), (false, true), (false, false)] {
        let mut spec = release_spec();
        spec.v1_descriptor = v1_descriptor;
        spec.v2_descriptor = v2_descriptor;
        let fixture = crate::test_fixtures::pool_release_fixture(&spec);
        let nested = fixture.operation.statement().pool_descriptor();
        assert_eq!(nested, &fixture.descriptor);
        assert_eq!(
            matches!(nested, SignedPoolDescriptorAnyV1::V1(_)),
            v1_descriptor
        );
        assert_eq!(
            matches!(nested, SignedPoolDescriptorAnyV1::V2(_)),
            v2_descriptor
        );

        let bytes = fixture.operation.canonical_bytes().unwrap();
        let decoded = SignedRuntimeReleaseOperationV2::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, fixture.operation);
        // The child keeps its own original bytes; it is never normalized.
        assert_eq!(
            decoded
                .statement()
                .pool_descriptor()
                .canonical_bytes()
                .unwrap(),
            fixture.descriptor.canonical_bytes().unwrap()
        );
        if v1_descriptor || v2_descriptor {
            assert_eq!(
                fixture
                    .operation
                    .verify(RuntimeIssuerPolicyV1::Declared, NOW + 3)
                    .map(|_| ()),
                Err(RuntimeReleaseOperationError::Pool(
                    PoolContractError::TrustRequired
                ))
            );
        } else {
            let authenticated = fixture.authenticated();
            assert_eq!(authenticated.pool(), &pool_did());
            assert_eq!(authenticated.descriptor_sequence(), 1);
        }
    }
}

#[test]
fn older_decoder_refuses_a_v2_nested_descriptor() {
    // Before item 10 the operation nested `SignedPoolDescriptorV1`, whose
    // decoder refuses the v2 domain: an older build fails closed.
    let v2 = DescriptorSpec::standard()
        .signed()
        .canonical_bytes()
        .unwrap();
    assert_eq!(
        SignedPoolDescriptorV1::from_canonical_bytes(&v2),
        Err(ContractError::WrongDomain)
    );
    let address = PoolAddressV2::new(pool_did(), route(1))
        .unwrap()
        .canonical_bytes()
        .unwrap();
    assert_eq!(
        PoolAddressV1::from_canonical_bytes(&address),
        Err(ContractError::WrongDomain)
    );
}

/// Prints the item-10 values pinned above (`--ignored --nocapture`).
#[test]
#[ignore = "prints the item-10 vectors"]
fn item10_vector_dump() {
    let spec = DescriptorSpec::standard();
    for (name, bytes) in [
        ("v1 descriptor", spec.signed_v1().canonical_bytes().unwrap()),
        ("v2 descriptor", spec.signed().canonical_bytes().unwrap()),
    ] {
        println!("{name} ({} bytes) sha256: {}", bytes.len(), kat(&bytes).1);
    }
}

// ---------------------------------------------------------------------------
// #388 A2 (Anders 2026-11-12; USER decisions 2026-11-13 02:55): descriptor v3
// with the pool's trust mode and a per-member attestation slot, and the v2
// recipient attestation that binds the trust mode and evidence. v1 and v2
// stay as read-only historical formats; the vectors are append-only.
// ---------------------------------------------------------------------------

const POOL_DESCRIPTOR_V3_DOMAIN: &[u8] = b"elastos.protected-content.pool-descriptor/v3";
const POOL_DESCRIPTOR_STATEMENT_V3_DOMAIN: &[u8] =
    b"elastos.protected-content.pool-descriptor-statement/v3";
const POOL_RECIPIENT_ATTESTATION_V2_DOMAIN: &[u8] =
    b"elastos.protected-content.pool-recipient-attestation/v2";

/// `DescriptorSpec::standard().signed_v3()` (10476 bytes), pinned from
/// `a388_vector_dump` on two runs and checked with an external `shasum`.
const V3_DESCRIPTOR_SHA256: &str =
    "07d4c82ee9407e223e34adae232133d4795376624df645fd97c26ab57930b6f4";
/// `kat_attestation_v2()`, the signed v2 vouch (2586 bytes), pinned the same
/// way.
const V2_ATTESTATION_SHA256: &str =
    "b957d7ea071f668e88d59e789ffc057039597dd660a5044e5c76acb8402af212";

/// The v2 vouch of the standard operation's recipient 9, by server 1.
fn kat_attestation_v2() -> SignedPoolRecipientAttestationV2 {
    let spec = OperationSpec::standard();
    let epoch = spec.item_bundle.signed_epoch().epoch_identity().unwrap();
    attestation_v2(&spec.binding(), 9, 1, epoch, pool_did())
}

#[test]
fn v1_and_v2_vectors_still_verify_with_trust_absent() {
    let spec = DescriptorSpec::standard();
    for (bytes, golden) in [
        (
            spec.signed_v1().canonical_bytes().unwrap(),
            V1_DESCRIPTOR_SHA256,
        ),
        (
            spec.signed().canonical_bytes().unwrap(),
            V2_DESCRIPTOR_SHA256,
        ),
    ] {
        assert_eq!(kat(&bytes).1, golden);
        let verified = SignedPoolDescriptorAnyV1::from_canonical_bytes(&bytes)
            .unwrap()
            .verify(NOW)
            .unwrap();
        // Trust ABSENT, never an implicit `WciOperated`.
        assert_eq!(verified.trust(), None);
    }
    // The frozen M6 vouch (v1) still decodes and verifies, trust absent.
    let vouch = kat_attestation();
    let bytes = vouch.canonical_bytes().unwrap();
    let any = SignedPoolRecipientAttestationAnyV1::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(any, SignedPoolRecipientAttestationAnyV1::V1(vouch));
    assert_eq!(any.canonical_bytes().unwrap(), bytes);
    assert_eq!(any.trust_mode(), None);
    let verified = spec.signed().verify(NOW).unwrap();
    let epoch = spec.bundles[0].signed_epoch().verify().unwrap();
    assert_eq!(
        any.verify(&verified, &epoch, NOW + 3).unwrap().trust_mode(),
        None
    );
}

#[test]
fn historical_descriptor_never_admits_a_new_release() {
    let spec = DescriptorSpec::standard();
    for verified in [
        spec.signed_v1().verify(NOW).unwrap(),
        spec.signed().verify(NOW).unwrap(),
    ] {
        assert_eq!(
            verified.admits_new_release(),
            Err(PoolContractError::TrustRequired)
        );
    }
    assert_eq!(
        spec.signed_v3().verify(NOW).unwrap().admits_new_release(),
        Ok(PoolTrustModeV1::WciOperated)
    );
    // An operation nesting a historical descriptor reads, and is refused.
    for version in [1, 2] {
        let mut operation = OperationSpec::standard();
        operation.descriptor_version = version;
        let signed = operation.signed();
        let bytes = signed.canonical_bytes().unwrap();
        assert_eq!(
            SignedRuntimeReleaseOperationV2::from_canonical_bytes(&bytes).unwrap(),
            signed
        );
        assert_eq!(
            signed
                .verify(RuntimeIssuerPolicyV1::Declared, NOW + 3)
                .map(|_| ()),
            Err(RuntimeReleaseOperationError::Pool(
                PoolContractError::TrustRequired
            ))
        );
    }
}

#[test]
fn v1_attestation_never_admits_a_new_release() {
    let mut spec = OperationSpec::standard();
    spec.v1_attestations = true;
    let signed = spec.signed();
    let bytes = signed.canonical_bytes().unwrap();
    assert_eq!(
        SignedRuntimeReleaseOperationV2::from_canonical_bytes(&bytes).unwrap(),
        signed
    );
    assert_eq!(
        signed
            .verify(RuntimeIssuerPolicyV1::Declared, NOW + 3)
            .map(|_| ()),
        Err(RuntimeReleaseOperationError::Pool(
            PoolContractError::TrustRequired
        ))
    );
    // The writers' form verifies, and the vouch carries the pool's mode.
    let authenticated = OperationSpec::standard().authenticated();
    assert_eq!(authenticated.pool(), &pool_did());
}

#[test]
fn v3_vectors_are_appended() {
    let spec = DescriptorSpec::standard();
    let descriptor = spec.signed_v3();
    let bytes = descriptor.canonical_bytes().unwrap();
    assert!(bytes.starts_with(POOL_DESCRIPTOR_V3_DOMAIN));
    assert!(descriptor
        .statement()
        .canonical_bytes()
        .unwrap()
        .starts_with(POOL_DESCRIPTOR_STATEMENT_V3_DOMAIN));
    let any = SignedPoolDescriptorAnyV1::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(any, SignedPoolDescriptorAnyV1::V3(descriptor));
    assert_eq!(any.canonical_bytes().unwrap(), bytes);
    let verified = any.verify(NOW).unwrap();
    let trust = verified.trust().unwrap();
    assert_eq!(trust.mode(), PoolTrustModeV1::WciOperated);
    assert_eq!(trust.member_attestations().len(), spec.members.len());
    assert!(trust.member_attestations().iter().all(Vec::is_empty));
    // Apart from trust, v3 verifies to the same descriptor as v2.
    let historical = spec.signed().verify(NOW).unwrap();
    assert_eq!(historical.trust(), None);
    assert_eq!(verified.pool(), historical.pool());
    assert_eq!(verified.sequence(), historical.sequence());
    assert_eq!(
        verified.member(node_public_key(2)),
        historical.member(node_public_key(2))
    );
    assert_eq!(kat(&bytes).1, V3_DESCRIPTOR_SHA256, "v3 descriptor sha256");

    let vouch = kat_attestation_v2();
    let bytes = vouch.canonical_bytes().unwrap();
    assert!(bytes.starts_with(POOL_RECIPIENT_ATTESTATION_V2_DOMAIN));
    let any = SignedPoolRecipientAttestationAnyV1::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(any, SignedPoolRecipientAttestationAnyV1::V2(vouch));
    assert_eq!(any.trust_mode(), Some(PoolTrustModeV1::WciOperated));
    assert!(any.evidence().is_empty());
    assert_eq!(
        SignedPoolRecipientAttestationV1::from_canonical_bytes(&bytes),
        Err(ContractError::WrongDomain)
    );
    let epoch = spec.bundles[0].signed_epoch().verify().unwrap();
    assert_eq!(
        any.verify(&verified, &epoch, NOW + 3).unwrap().trust_mode(),
        Some(PoolTrustModeV1::WciOperated)
    );
    assert_eq!(
        kat(&bytes).1,
        V2_ATTESTATION_SHA256,
        "v2 attestation sha256"
    );
}

#[test]
fn nonempty_wci_slot_refused() {
    let spec = DescriptorSpec::standard();
    assert_eq!(
        spec.statement_v3(PoolTrustModeV1::WciOperated, &[0])
            .map(|_| ()),
        Err(ContractError::InvalidField("attestation"))
    );
    let binding = binding_for(&spec.bundles[0]);
    let epoch = spec.bundles[0].signed_epoch().epoch_identity().unwrap();
    assert_eq!(
        attestation_statement_v2(
            &binding,
            9,
            1,
            epoch,
            pool_did(),
            PoolTrustModeV1::WciOperated,
            vec![0],
        )
        .map(|_| ()),
        Err(ContractError::InvalidField("evidence"))
    );
    // `AttestedTee` is unsupported in both formats, even with evidence.
    for slot in [&[][..], &[0][..]] {
        assert_eq!(
            spec.statement_v3(PoolTrustModeV1::AttestedTee, slot)
                .map(|_| ()),
            Err(ContractError::InvalidField("trust_mode"))
        );
        assert_eq!(
            attestation_statement_v2(
                &binding,
                9,
                1,
                epoch,
                pool_did(),
                PoolTrustModeV1::AttestedTee,
                slot.to_vec(),
            )
            .map(|_| ()),
            Err(ContractError::InvalidField("trust_mode"))
        );
    }
}

#[test]
fn slot_over_reserved_ceiling_refused() {
    let over = vec![0; MAX_TRUST_ATTESTATION_BYTES_V1 + 1];
    assert_eq!(
        PoolMemberV3::new(member(1, ALL_ROLES), over.clone()).map(|_| ()),
        Err(ContractError::FieldTooLong("attestation"))
    );
    let spec = DescriptorSpec::standard();
    assert_eq!(
        spec.statement_v3(PoolTrustModeV1::WciOperated, &over)
            .map(|_| ()),
        Err(ContractError::FieldTooLong("attestation"))
    );
    let binding = binding_for(&spec.bundles[0]);
    let epoch = spec.bundles[0].signed_epoch().epoch_identity().unwrap();
    assert_eq!(
        attestation_statement_v2(
            &binding,
            9,
            1,
            epoch,
            pool_did(),
            PoolTrustModeV1::WciOperated,
            over,
        )
        .map(|_| ()),
        Err(ContractError::FieldTooLong("evidence"))
    );
}

/// A388-F4: the 16 KiB slot ceiling is reserved; three full slots on top of
/// the standard v3 descriptor cross the unchanged 40 KiB signed cap.
#[test]
fn three_full_member_slots_overflow_the_descriptor_cap() {
    let descriptor = DescriptorSpec::standard().signed_v3();
    let statement = descriptor.statement().canonical_bytes().unwrap();
    let domain = std::str::from_utf8(POOL_DESCRIPTOR_V3_DOMAIN).unwrap();
    crate::pool::validate_signed_descriptor(domain, &statement, descriptor.authority_signature())
        .unwrap();
    let full_len = statement.len() + 3 * MAX_TRUST_ATTESTATION_BYTES_V1;
    let mut full = statement;
    full.resize(full_len, 0);
    assert_eq!(
        crate::pool::validate_signed_descriptor(domain, &full, descriptor.authority_signature()),
        Err(ContractError::FieldTooLong("signed_pool_descriptor"))
    );
}

#[test]
fn no_existing_cap_changed() {
    assert_eq!(MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1, 40 * 1024);
    assert_eq!(MAX_POOL_MEMBERS_V1, 16);
    assert_eq!(MAX_TRUST_ATTESTATION_BYTES_V1, 16 * 1024);
    // The slot fits its u16 length.
    const _: () = assert!(MAX_TRUST_ATTESTATION_BYTES_V1 <= u16::MAX as usize);
}

/// Prints the #388 A2 values pinned above (`--ignored --nocapture`).
#[test]
#[ignore = "prints the #388 A2 vectors"]
fn a388_vector_dump() {
    let descriptor = DescriptorSpec::standard()
        .signed_v3()
        .canonical_bytes()
        .unwrap();
    println!(
        "v3 descriptor ({} bytes) sha256: {}",
        descriptor.len(),
        kat(&descriptor).1
    );
    let vouch = kat_attestation_v2().canonical_bytes().unwrap();
    println!(
        "v2 attestation ({} bytes) sha256: {}",
        vouch.len(),
        kat(&vouch).1
    );
}

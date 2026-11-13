//! Canonical protected-content v1 contracts.
//!
//! This source-only crate defines identities and provider-private messages. It
//! does not select providers, transport requests, hold key shares, reconstruct
//! content keys, or expose capsule workflows.

mod canonical;
mod creator_mint_wire;
mod custody_envelope;
mod custody_epoch;
mod custody_pool;
mod custody_provisioning;
mod identity;
mod node_contribution;
mod node_decision;
mod node_set;
mod policy;
mod pool;
mod pool_mint;
mod recipient_authorization;
mod release_request;
mod replay;
mod rights;
mod rights_receipt;
mod runtime_release_operation;
mod terminal_receipt;

#[cfg(test)]
mod authority_tests;
#[cfg(test)]
mod policy_v2_tests;
#[cfg(test)]
mod pool_mint_tests;
#[cfg(test)]
mod pool_tests;
#[cfg(test)]
mod rights_v2_tests;
/// Plan B V2 fixtures for tests in other crates (feature `test-fixtures`).
#[cfg(any(test, feature = "test-fixtures"))]
pub mod test_fixtures;
#[cfg(test)]
mod test_support;

pub use canonical::{CanonicalContract, ContractError};
pub use creator_mint_wire::{
    ProtectedContentCreatorMintSourceV1, ProtectedContentCreatorMintV1,
    ProtectedContentMintReceiptV1, ProtectedContentPayTokenV1,
    PROTECTED_CONTENT_CREATOR_MINT_SCHEMA_V1, PROTECTED_CONTENT_CREATOR_MINT_SOURCE_SCHEMA_V1,
    PROTECTED_CONTENT_MINT_RECEIPT_SCHEMA_V1,
};
pub use custody_envelope::{
    CustodyEnvelopeManifestV1, CustodyEnvelopeV1, CustodyNodeIdentityV1, NodeCustodyPublicKeyV1,
    PqHybridSealedShareV1, ShareCoordinateV1, CONTENT_KEY_COMMITMENT_DOMAIN_V1,
    CUSTODY_X_WING_AES256GCM_SUITE_ID_V1, PQ_HYBRID_SEALED_SHARE_ENVELOPE_BYTES,
    PQ_HYBRID_SEALED_SHARE_MAX_BYTES, PQ_HYBRID_SEALED_SHARE_MIN_BYTES,
    PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES, RELEASED_SHARE_HPKE_INFO_V1, STORED_SHARE_HPKE_INFO_V1,
    X_WING_DRAFT06_CIPHERTEXT_BYTES,
};
pub use custody_epoch::{
    CustodyApprovedSuitesV1, CustodyEpochError, CustodyEpochIdentityV1, CustodyEpochIssuerKeyV1,
    CustodyEpochStatementV1, SignedCustodyEpochV1, VerifiedCustodyEpochV1,
};
pub use custody_pool::{
    validate_custody_epoch_against_pool_at, validate_custody_epoch_for_release_at,
    CustodyCommitteeAuthorizationIdentityV1, CustodyCommitteeAuthorizationStatementV1,
    CustodyPoolError, CustodyPoolFailureDomainIdV1, CustodyPoolIdentityV1,
    CustodyPoolMemberStateV1, CustodyPoolMemberV1, CustodyPoolOperatorIdV1, CustodyPoolStatementV1,
    SignedCustodyCommitteeAuthorizationV1, SignedCustodyPoolV1, ValidatedCustodyCommitteeV1,
    VerifiedCustodyCommitteeAuthorizationV1, VerifiedCustodyPoolV1,
};
pub use custody_provisioning::{
    AuthenticatedRuntimeCustodyProvisioningV1, CustodyNodeProvisioningRecordIdentityV1,
    CustodyNodeProvisioningRecordV1, RuntimeCustodyProvisioningError,
    RuntimeCustodyProvisioningIdV1, RuntimeCustodyProvisioningStatementV1,
    SignedRuntimeCustodyProvisioningV1, MAX_RUNTIME_CUSTODY_PROVISIONING_LIFETIME_SECS,
};
pub use identity::{
    Digest32, EncryptedContentIdentityV1, KeyEnvelopeIdentityV1, ProfileIdentityV1,
    ProtectedContentBindingV1, RecipientKeyIdentityV1, RightsPolicyIdentityV1,
    RuntimeSessionBindingV1, ThresholdV1, WalletAddress, MAX_ENCRYPTED_CONTENT_BYTES,
    MAX_KEY_ENVELOPE_BYTES, MAX_RECIPIENT_ENCRYPTION_SUITE_ID_BYTES, MAX_RIGHTS_POLICY_BYTES,
    MAX_THRESHOLD_NODES,
};
pub use node_contribution::{
    validate_node_contribution_active_window, NodeContributionStatementV1,
    RecipientSealedContributionV1, SignedNodeContributionV1, VerifiedNodeContributionV1,
    MAX_NODE_CONTRIBUTION_LIFETIME_SECS, MAX_RECIPIENT_SEALED_CONTRIBUTION_BYTES,
};
pub use node_decision::{
    NodeRightsDecisionStatementV1, SignedNodeRightsDecisionV1, VerifiedNodeRightsDecisionV1,
    MAX_NODE_DECISION_LIFETIME_SECS,
};
pub use node_set::{NodePublicKey, NodeSetV1};
pub use policy::{
    ContentAccessIdV1, EvmContractAddressV1, EvmFunctionSelectorV1, EvmRightsMethodAbiV1,
    RightsEvaluationEvidenceRequestV1, RightsEvaluationEvidenceV1, RightsExpectedItemV1,
    RightsObservationFinalityV1, RightsPolicyBodyV1, RightsSubjectSourceV1,
    MAX_RIGHTS_EVIDENCE_LIFETIME_SECS,
};
pub use pool::{
    DeliveryKeyIdentityV1, DeliveryPublicKeyBytesV1, MintPolicyV1, PoolAddressAnyV1, PoolAddressV1,
    PoolAddressV2, PoolContractError, PoolDescriptorStatementV1, PoolDescriptorStatementV2,
    PoolDescriptorStatementV3, PoolDidV1, PoolEpochBundleV1, PoolMemberRolesV1, PoolMemberRouteV1,
    PoolMemberRouteV2, PoolMemberV1, PoolMemberV2, PoolMemberV3,
    PoolRecipientAttestationStatementV1, PoolRecipientAttestationStatementV2,
    PoolSessionContentKindV1, PoolTrustModeV1, PoolTrustV1, ServePolicyV1, SessionBoundsV1,
    SignedPoolDescriptorAnyV1, SignedPoolDescriptorV1, SignedPoolDescriptorV2,
    SignedPoolDescriptorV3, SignedPoolRecipientAttestationAnyV1, SignedPoolRecipientAttestationV1,
    SignedPoolRecipientAttestationV2, VerifiedPoolDescriptorV1, VerifiedPoolRecipientAttestationV1,
    ViewerPartAadV1, ViewerPartIndexV1, DEFAULT_MAX_SEALS_PER_SEALER_V1, MAX_ADMITTED_MINTERS_V1,
    MAX_POOL_DESCRIPTOR_EPOCHS_V1, MAX_POOL_DESCRIPTOR_LIFETIME_SECS, MAX_POOL_MEMBERS_V1,
    MAX_POOL_MEMBER_CONNECT_TICKET_BYTES_V1, MAX_POOL_MEMBER_PEER_DID_BYTES_V1,
    MAX_SESSION_RECIPIENTS_V2, MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1, MAX_TRUST_ATTESTATION_BYTES_V1,
    MAX_VIEWER_DASH_RENDITION_V1,
};
pub use pool_mint::{PoolMintShareStatementV1, SignedPoolMintShareV1};
pub use recipient_authorization::{
    RecipientAuthorizationError, RecipientKeyAuthorizationContextV1,
    RecipientKeyAuthorizationStatementV1, RecipientPublicKeyBytesV1, RuntimeOperationIssuerKeyV1,
    SignedRecipientKeyAuthorizationV1, VerifiedRecipientKeyAuthorizationV1,
    MAX_RECIPIENT_KEY_AUTHORIZATION_LIFETIME_SECS,
};
pub use release_request::{
    KeyReleaseError, KeyReleaseRequestV1, VerifiedKeyReleaseRequestV1,
    MAX_RELEASE_REQUEST_LIFETIME_SECS,
};
pub use replay::{AtomicReplayClaimer, ReplayClaimEntryV1, ReplayClaimError, ReplayClaimKeyV1};
pub use rights::{
    ReplayNonce16, RightsActionV1, RightsDecisionV1, RightsError, RightsRequestAnyV1,
    RightsRequestV1, RightsRequestV2, RightsVerificationContextV1, VerifiedRightsRequestV1,
    WalletSignedRightsRequestAnyV1, WalletSignedRightsRequestV1, WalletSignedRightsRequestV2,
    MAX_RIGHTS_REQUEST_LIFETIME_SECS, PRE_ALIGNMENT_V2, RIGHTS_CLOCK_SKEW_SECS,
};
pub use rights_receipt::{
    RightsReceiptIssuerKey, RightsReceiptStatementV1, SignedRightsReceiptV1,
    MAX_RIGHTS_RECEIPT_LIFETIME_SECS,
};
pub use runtime_release_operation::{
    AuthenticatedRuntimeReleaseOperationAnyV1, AuthenticatedRuntimeReleaseOperationV1,
    AuthenticatedRuntimeReleaseOperationV2, PoolSessionRecipientV1, RuntimeIssuerPolicyV1,
    RuntimeReleaseAuditIdV1, RuntimeReleaseOperationAnyV1, RuntimeReleaseOperationError,
    RuntimeReleaseOperationStatementV1, RuntimeReleaseOperationStatementV2,
    SignedRuntimeReleaseOperationV1, SignedRuntimeReleaseOperationV2,
    MAX_RUNTIME_RELEASE_OPERATION_LIFETIME_SECS,
};
pub use terminal_receipt::{
    KeyReleaseOutcomeV1, NodeContributionRefV1, SignedTerminalReceiptV1, TerminalReceiptIssuerKey,
    TerminalReceiptStatementV1, MAX_TERMINAL_RECEIPT_LIFETIME_SECS,
};

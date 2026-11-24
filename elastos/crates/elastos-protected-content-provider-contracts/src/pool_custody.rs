//! Pool custody transport (Plan B T1.3): a pool node's custody provider is
//! asked for its contributions to a V2 release, or for its signature on a pool
//! statement. These types live beside the V1 custody types, which stay
//! byte-for-byte and API-stable (L6).
//!
//! `decode_and_validate_at` checks the shape and the operation's own
//! signatures (V2 under the issuer it declares). Pool membership, the node's
//! share and the release gate are the custody provider's (T1.5).

use elastos_protected_content_contracts::{
    AuthenticatedRuntimeCustodyProvisioningV1, AuthenticatedRuntimeReleaseOperationV2,
    CanonicalContract, ContractError, CustodyNodeProvisioningRecordIdentityV1,
    CustodyNodeProvisioningRecordV1, Digest32, KeyReleaseError, NodePublicKey, NodeSetV1,
    PoolRecipientAttestationStatementV2, RightsDecisionV1, RuntimeCustodyProvisioningIdV1,
    RuntimeIssuerPolicyV1, RuntimeReleaseAuditIdV1, SignedNodeContributionV1,
    SignedNodeRightsDecisionV1, SignedPoolDescriptorAnyV1, SignedPoolMintShareV1,
    SignedPoolRecipientAttestationV2, SignedRuntimeCustodyProvisioningV1,
    SignedRuntimeReleaseOperationV2, MAX_SESSION_RECIPIENTS_V2,
    MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1, RIGHTS_CLOCK_SKEW_SECS,
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use crate::wire::{
    contract_decode_error, decode_json, encode_json, validate_schema, CanonicalBlob,
    CanonicalBlobList, ProviderFailureCodeV1, MAX_CUSTODY_NODE_PROVISIONING_RECORD_BYTES_V1,
    MAX_POOL_STATEMENT_BYTES_V1, MAX_SIGNED_NODE_CONTRIBUTION_BYTES_V1,
    MAX_SIGNED_NODE_RIGHTS_DECISION_BYTES_V1, MAX_SIGNED_RUNTIME_CUSTODY_PROVISIONING_BYTES_V1,
    MAX_SIGNED_RUNTIME_RELEASE_OPERATION_BYTES_V2,
};
use crate::CustodyProviderRequestValidationErrorV1;

pub const POOL_CUSTODY_REQUEST_SCHEMA_V1: &str =
    "elastos.protected-content.pool-custody.request/v1";
pub const POOL_CUSTODY_RESPONSE_SCHEMA_V1: &str =
    "elastos.protected-content.pool-custody.response/v1";
const ED25519_SIGNATURE_BYTES: usize = 64;

type SignedRuntimeReleaseOperationV2BlobV1 =
    CanonicalBlob<MAX_SIGNED_RUNTIME_RELEASE_OPERATION_BYTES_V2>;
type SignedNodeRightsDecisionBlobV1 = CanonicalBlob<MAX_SIGNED_NODE_RIGHTS_DECISION_BYTES_V1>;
type PoolStatementBlobV1 = CanonicalBlob<MAX_POOL_STATEMENT_BYTES_V1>;
type CustodyNodeProvisioningRecordBlobV1 =
    CanonicalBlob<MAX_CUSTODY_NODE_PROVISIONING_RECORD_BYTES_V1>;
type SignedRuntimeCustodyProvisioningBlobV1 =
    CanonicalBlob<MAX_SIGNED_RUNTIME_CUSTODY_PROVISIONING_BYTES_V1>;
/// POOL-MINT: the signed share statement is far below the pool statement cap.
type SignedPoolMintShareBlobV1 = CanonicalBlob<MAX_POOL_STATEMENT_BYTES_V1>;
type SignedPoolDescriptorBlobV1 = CanonicalBlob<MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1>;
type SignedNodeContributionBlobListV1 =
    CanonicalBlobList<MAX_SESSION_RECIPIENTS_V2, MAX_SIGNED_NODE_CONTRIBUTION_BYTES_V1>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolCustodyRequestOpV1 {
    ReleasePoolContribution,
    SignPoolStatement,
    /// POOL-MINT: a Home that uses the pool provisions this node's share.
    ProvisionPoolNodeShare,
}

/// What a pool node signs. Only the recipient attestation now (L15); T7.1
/// adds its kinds with their domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatementKindV1 {
    RecipientAttestation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolCustodyRequestV1(PoolCustodyRequestKindV1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum PoolCustodyRequestKindV1 {
    ReleasePoolContribution {
        schema: String,
        signed_runtime_release_operation: SignedRuntimeReleaseOperationV2BlobV1,
        signed_node_rights_decision: SignedNodeRightsDecisionBlobV1,
    },
    SignPoolStatement {
        schema: String,
        kind: PoolStatementKindV1,
        statement: PoolStatementBlobV1,
    },
    ProvisionPoolNodeShare {
        schema: String,
        custody_node_provisioning_record: CustodyNodeProvisioningRecordBlobV1,
        signed_runtime_custody_provisioning: SignedRuntimeCustodyProvisioningBlobV1,
        signed_pool_mint_share: SignedPoolMintShareBlobV1,
        pool_descriptor: SignedPoolDescriptorBlobV1,
    },
}

/// The decoded parts of a provisioning request.
struct PoolProvisionPartsV1 {
    record: CustodyNodeProvisioningRecordV1,
    statement: SignedRuntimeCustodyProvisioningV1,
    mint_share: SignedPoolMintShareV1,
    descriptor: SignedPoolDescriptorAnyV1,
}

impl PoolCustodyRequestV1 {
    pub fn op(&self) -> PoolCustodyRequestOpV1 {
        match &self.0 {
            PoolCustodyRequestKindV1::ReleasePoolContribution { .. } => {
                PoolCustodyRequestOpV1::ReleasePoolContribution
            }
            PoolCustodyRequestKindV1::SignPoolStatement { .. } => {
                PoolCustodyRequestOpV1::SignPoolStatement
            }
            PoolCustodyRequestKindV1::ProvisionPoolNodeShare { .. } => {
                PoolCustodyRequestOpV1::ProvisionPoolNodeShare
            }
        }
    }

    /// POOL-MINT: one node's share of an item a Home that uses the pool sealed,
    /// with the minting Home's signed share statement and the pool descriptor it is
    /// admitted by.
    pub fn new_provision_pool_node_share(
        record: &CustodyNodeProvisioningRecordV1,
        statement: &SignedRuntimeCustodyProvisioningV1,
        mint_share: &SignedPoolMintShareV1,
        descriptor: &SignedPoolDescriptorAnyV1,
    ) -> Result<Self, ContractError> {
        let value = Self(PoolCustodyRequestKindV1::ProvisionPoolNodeShare {
            schema: POOL_CUSTODY_REQUEST_SCHEMA_V1.to_string(),
            custody_node_provisioning_record: CanonicalBlob::from_contract(record)?,
            signed_runtime_custody_provisioning: CanonicalBlob::from_contract(statement)?,
            signed_pool_mint_share: CanonicalBlob::from_contract(mint_share)?,
            pool_descriptor: CanonicalBlob::from_contract(descriptor)?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    /// The pool and descriptor sequence of a provisioning request, read from
    /// its structure only. It proves nothing: the Runtime wrapper uses it to
    /// find this Home's trusted binding for that pool (S7L-F2).
    pub fn provision_pool(
        &self,
    ) -> Result<(SignedPoolDescriptorAnyV1, NodePublicKey), ContractError> {
        let parts = self.provision_parts()?;
        Ok((parts.descriptor, parts.record.selected_node_public_key()))
    }

    /// The record, runtime statement and share statement of a provisioning
    /// request, decoded without any check.
    pub fn provision_contents(
        &self,
    ) -> Result<
        (
            CustodyNodeProvisioningRecordV1,
            SignedRuntimeCustodyProvisioningV1,
            SignedPoolMintShareV1,
        ),
        ContractError,
    > {
        let parts = self.provision_parts()?;
        Ok((parts.record, parts.statement, parts.mint_share))
    }

    fn provision_parts(&self) -> Result<PoolProvisionPartsV1, ContractError> {
        match &self.0 {
            PoolCustodyRequestKindV1::ProvisionPoolNodeShare {
                custody_node_provisioning_record,
                signed_runtime_custody_provisioning,
                signed_pool_mint_share,
                pool_descriptor,
                ..
            } => Ok(PoolProvisionPartsV1 {
                record: custody_node_provisioning_record.decode()?,
                statement: signed_runtime_custody_provisioning.decode()?,
                mint_share: signed_pool_mint_share.decode()?,
                descriptor: pool_descriptor.decode()?,
            }),
            _ => Err(ContractError::InvalidField("provision_pool_node_share")),
        }
    }

    /// One node's contributions to a V2 release (S4 R2).
    pub fn new_release_pool_contribution(
        signed_runtime_release_operation: &SignedRuntimeReleaseOperationV2,
        signed_node_rights_decision: &SignedNodeRightsDecisionV1,
    ) -> Result<Self, ContractError> {
        let value = Self(PoolCustodyRequestKindV1::ReleasePoolContribution {
            schema: POOL_CUSTODY_REQUEST_SCHEMA_V1.to_string(),
            signed_runtime_release_operation: CanonicalBlob::from_contract(
                signed_runtime_release_operation,
            )?,
            signed_node_rights_decision: CanonicalBlob::from_contract(signed_node_rights_decision)?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    /// The serving node's signature on one recipient attestation.
    pub fn new_sign_recipient_attestation(
        statement: &PoolRecipientAttestationStatementV2,
    ) -> Result<Self, ContractError> {
        let value = Self(PoolCustodyRequestKindV1::SignPoolStatement {
            schema: POOL_CUSTODY_REQUEST_SCHEMA_V1.to_string(),
            kind: PoolStatementKindV1::RecipientAttestation,
            statement: CanonicalBlob::from_contract(statement)?,
        });
        value.validate_structure()?;
        Ok(value)
    }

    pub fn to_json_vec(&self) -> Result<Vec<u8>, serde_json::Error> {
        encode_json(self)
    }

    /// The plain request, structure-checked; the caller's own copy for the
    /// response check.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let inner = decode_json::<PoolCustodyRequestKindV1>(bytes)?;
        let value = Self(inner);
        value.validate_structure().map_err(contract_decode_error)?;
        Ok(value)
    }

    fn signed_runtime_release_operation(
        &self,
    ) -> Result<SignedRuntimeReleaseOperationV2, ContractError> {
        match &self.0 {
            PoolCustodyRequestKindV1::ReleasePoolContribution {
                signed_runtime_release_operation,
                ..
            } => signed_runtime_release_operation.decode(),
            _ => Err(ContractError::InvalidField(
                "signed_runtime_release_operation",
            )),
        }
    }

    fn signed_node_rights_decision(&self) -> Result<SignedNodeRightsDecisionV1, ContractError> {
        match &self.0 {
            PoolCustodyRequestKindV1::ReleasePoolContribution {
                signed_node_rights_decision,
                ..
            } => signed_node_rights_decision.decode(),
            _ => Err(ContractError::InvalidField("signed_node_rights_decision")),
        }
    }

    fn recipient_attestation(&self) -> Result<PoolRecipientAttestationStatementV2, ContractError> {
        match &self.0 {
            PoolCustodyRequestKindV1::SignPoolStatement {
                kind: PoolStatementKindV1::RecipientAttestation,
                statement,
                ..
            } => statement.decode(),
            _ => Err(ContractError::InvalidField("pool_statement")),
        }
    }

    fn validate_structure(&self) -> Result<(), ContractError> {
        match &self.0 {
            PoolCustodyRequestKindV1::ReleasePoolContribution { schema, .. } => {
                validate_schema(
                    schema,
                    POOL_CUSTODY_REQUEST_SCHEMA_V1,
                    "pool_custody_request.schema",
                )?;
                let operation = self.signed_runtime_release_operation()?;
                let decision = self.signed_node_rights_decision()?;
                let node_set = operation
                    .unverified_epoch_bundle()
                    .ok_or(ContractError::InvalidField(
                        "signed_runtime_release_operation",
                    ))?
                    .signed_epoch()
                    .statement()
                    .node_set()
                    .map_err(|_| ContractError::InvalidField("signed_runtime_release_operation"))?;
                if !node_set.contains(decision.statement().node_public_key()) {
                    return Err(ContractError::InvalidField("signed_node_rights_decision"));
                }
                Ok(())
            }
            PoolCustodyRequestKindV1::SignPoolStatement { schema, .. } => {
                validate_schema(
                    schema,
                    POOL_CUSTODY_REQUEST_SCHEMA_V1,
                    "pool_custody_request.schema",
                )?;
                self.recipient_attestation().map(|_| ())
            }
            PoolCustodyRequestKindV1::ProvisionPoolNodeShare { schema, .. } => {
                validate_schema(
                    schema,
                    POOL_CUSTODY_REQUEST_SCHEMA_V1,
                    "pool_custody_request.schema",
                )?;
                let parts = self.provision_parts()?;
                let mint_share = parts.mint_share.statement();
                if mint_share.key_envelope() != parts.record.key_envelope_identity()
                    || mint_share.pool() != parts.descriptor.pool()
                {
                    return Err(ContractError::InvalidField("signed_pool_mint_share"));
                }
                Ok(())
            }
        }
    }

    fn into_validated_at(
        self,
        expected_local_node_public_key: NodePublicKey,
        now_unix_seconds: u64,
    ) -> Result<ValidatedPoolCustodyRequestV1, CustodyProviderRequestValidationErrorV1> {
        match &self.0 {
            PoolCustodyRequestKindV1::ReleasePoolContribution { .. } => {
                let signed_node_rights_decision = self.signed_node_rights_decision()?;
                let authenticated = self
                    .signed_runtime_release_operation()?
                    .verify(RuntimeIssuerPolicyV1::Declared, now_unix_seconds)
                    .map_err(|_| CustodyProviderRequestValidationErrorV1::Contract)?;
                let node_set = release_node_set(&authenticated)
                    .map_err(|_| CustodyProviderRequestValidationErrorV1::Contract)?;
                let selected_node_public_key =
                    signed_node_rights_decision.statement().node_public_key();
                if selected_node_public_key != expected_local_node_public_key
                    || !node_set.contains(selected_node_public_key)
                {
                    return Err(CustodyProviderRequestValidationErrorV1::Contract);
                }
                let decision = authenticated
                    .verify_node_rights_decision(
                        &signed_node_rights_decision,
                        &node_set,
                        now_unix_seconds,
                    )
                    .map_err(|error| match error {
                        KeyReleaseError::RightsDenied => {
                            CustodyProviderRequestValidationErrorV1::RightsDenied
                        }
                        _ => CustodyProviderRequestValidationErrorV1::Contract,
                    })?;
                if decision.decision() != RightsDecisionV1::Allowed {
                    return Err(CustodyProviderRequestValidationErrorV1::RightsDenied);
                }
                Ok(ValidatedPoolCustodyRequestV1 {
                    kind: ValidatedPoolCustodyRequestKindV1::Release(Box::new(
                        ValidatedPoolReleaseV1 {
                            selected_node_public_key,
                            authenticated_runtime_release_operation: authenticated,
                            signed_node_rights_decision,
                        },
                    )),
                })
            }
            PoolCustodyRequestKindV1::SignPoolStatement { kind, .. } => {
                let statement = self.recipient_attestation()?;
                if statement.server_node_public_key() != expected_local_node_public_key {
                    return Err(CustodyProviderRequestValidationErrorV1::Contract);
                }
                if now_unix_seconds.saturating_add(RIGHTS_CLOCK_SKEW_SECS) < statement.issued_at()
                    || now_unix_seconds >= statement.expires_at()
                {
                    return Err(CustodyProviderRequestValidationErrorV1::Contract);
                }
                Ok(ValidatedPoolCustodyRequestV1 {
                    kind: ValidatedPoolCustodyRequestKindV1::Statement(Box::new(
                        ValidatedPoolStatementV1 {
                            selected_node_public_key: expected_local_node_public_key,
                            kind: *kind,
                            recipient_attestation: statement,
                        },
                    )),
                })
            }
            PoolCustodyRequestKindV1::ProvisionPoolNodeShare { .. } => {
                let provision = self
                    .provision_parts()
                    .map_err(|_| CustodyProviderRequestValidationErrorV1::Contract)?;
                validate_pool_provision_at(
                    provision,
                    expected_local_node_public_key,
                    now_unix_seconds,
                )
                .map(|provision| ValidatedPoolCustodyRequestV1 {
                    kind: ValidatedPoolCustodyRequestKindV1::Provision(Box::new(provision)),
                })
                .map_err(|_| CustodyProviderRequestValidationErrorV1::Contract)
            }
        }
    }
}

/// Plan B POOL-MINT, at this node's clock `now`:
/// - the record selects this node, and this node is in the committee its key
///   envelope names (node set and threshold of that epoch);
/// - the attached descriptor verifies at `now`, is v3 `WciOperated` with
///   empty slots (#388 A2), and the item's epoch term is open;
/// - the minting Home signed the share statement, which names the
///   descriptor's pool and the record's key envelope (so its epoch);
/// - the runtime statement verifies for the record under the same issuer.
///
/// The Runtime wrapper has already checked that the pool is one this node
/// serves (the trusted binding); the provider checks the high-water mark,
/// the write-once slot and the per-minter cap.
fn validate_pool_provision_at(
    parts: PoolProvisionPartsV1,
    expected_local_node_public_key: NodePublicKey,
    now: u64,
) -> Result<ValidatedPoolProvisionV1, ContractError> {
    let invalid = |field: &'static str| ContractError::InvalidField(field);
    let record = &parts.record;
    if record.selected_node_public_key() != expected_local_node_public_key {
        return Err(invalid("custody_node_provisioning_record"));
    }
    let descriptor = parts
        .descriptor
        .verify(now)
        .map_err(|_| invalid("pool_descriptor"))?;
    descriptor
        .admits_new_release()
        .map_err(|_| invalid("pool_descriptor"))?;
    let key_envelope = record.key_envelope_identity();
    let epoch = descriptor
        .epoch_for_provisioning(key_envelope, now)
        .map_err(|_| invalid("pool_descriptor"))?
        .signed_epoch()
        .statement();
    let node_set = epoch.node_set()?;
    if node_set.node_set_id()? != key_envelope.node_set_id()
        || epoch.threshold() != key_envelope.threshold()
        || !node_set.contains(expected_local_node_public_key)
    {
        return Err(invalid("custody_node_provisioning_record"));
    }
    let statement = parts
        .mint_share
        .verify_signature()
        .map_err(|_| invalid("signed_pool_mint_share"))?;
    if statement.pool() != descriptor.pool() || statement.key_envelope() != key_envelope {
        return Err(invalid("signed_pool_mint_share"));
    }
    let authenticated = parts
        .statement
        .verify_for_record(record, statement.minter_runtime_issuer(), now)
        .map_err(|_| invalid("signed_runtime_custody_provisioning"))?;
    Ok(ValidatedPoolProvisionV1 {
        selected_node_public_key: expected_local_node_public_key,
        record: parts.record,
        signed_runtime_custody_provisioning: parts.statement,
        authenticated_runtime_custody_provisioning: authenticated,
        signed_pool_mint_share: parts.mint_share,
        pool_descriptor: parts.descriptor,
    })
}

impl PoolCustodyRequestV1 {
    /// The node a pool request names, read from its structure only (Plan B
    /// T2.1): the decision's node for a release, the serving node for a
    /// statement. It proves nothing; it picks the root that validates.
    pub fn peek_selected_node_public_key(
        bytes: &[u8],
    ) -> Result<NodePublicKey, CustodyProviderRequestValidationErrorV1> {
        let request = Self::from_json_slice(bytes)?;
        match &request.0 {
            PoolCustodyRequestKindV1::ReleasePoolContribution { .. } => Ok(request
                .signed_node_rights_decision()?
                .statement()
                .node_public_key()),
            PoolCustodyRequestKindV1::SignPoolStatement { .. } => {
                Ok(request.recipient_attestation()?.server_node_public_key())
            }
            PoolCustodyRequestKindV1::ProvisionPoolNodeShare { .. } => {
                Ok(request.provision_parts()?.record.selected_node_public_key())
            }
        }
    }
}

impl Serialize for PoolCustodyRequestV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

fn release_node_set(
    operation: &AuthenticatedRuntimeReleaseOperationV2,
) -> Result<NodeSetV1, ContractError> {
    operation
        .epoch_bundle()
        .signed_epoch()
        .statement()
        .node_set()
}

/// Provider-authoritative pool custody request. Construct only through
/// [`ValidatedPoolCustodyRequestV1::decode_and_validate_at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPoolCustodyRequestV1 {
    kind: ValidatedPoolCustodyRequestKindV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ValidatedPoolCustodyRequestKindV1 {
    Release(Box<ValidatedPoolReleaseV1>),
    Statement(Box<ValidatedPoolStatementV1>),
    Provision(Box<ValidatedPoolProvisionV1>),
}

/// S7-lite T7.3: a provisioning request that passed every check of
/// `validate_pool_provision_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPoolProvisionV1 {
    selected_node_public_key: NodePublicKey,
    record: CustodyNodeProvisioningRecordV1,
    signed_runtime_custody_provisioning: SignedRuntimeCustodyProvisioningV1,
    authenticated_runtime_custody_provisioning: AuthenticatedRuntimeCustodyProvisioningV1,
    signed_pool_mint_share: SignedPoolMintShareV1,
    pool_descriptor: SignedPoolDescriptorAnyV1,
}

impl ValidatedPoolProvisionV1 {
    pub const fn selected_node_public_key(&self) -> NodePublicKey {
        self.selected_node_public_key
    }

    pub fn custody_node_provisioning_record(&self) -> &CustodyNodeProvisioningRecordV1 {
        &self.record
    }

    pub fn signed_runtime_custody_provisioning(&self) -> &SignedRuntimeCustodyProvisioningV1 {
        &self.signed_runtime_custody_provisioning
    }

    pub fn signed_pool_mint_share(&self) -> &SignedPoolMintShareV1 {
        &self.signed_pool_mint_share
    }

    pub fn pool_descriptor(&self) -> &SignedPoolDescriptorAnyV1 {
        &self.pool_descriptor
    }

    pub fn provisioning_id(&self) -> RuntimeCustodyProvisioningIdV1 {
        self.authenticated_runtime_custody_provisioning
            .provisioning_id()
    }

    pub fn provisioning_operation_hash(&self) -> Digest32 {
        self.authenticated_runtime_custody_provisioning
            .operation_hash()
    }

    pub fn record_identity(&self) -> CustodyNodeProvisioningRecordIdentityV1 {
        self.authenticated_runtime_custody_provisioning
            .record_identity()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPoolReleaseV1 {
    selected_node_public_key: NodePublicKey,
    authenticated_runtime_release_operation: AuthenticatedRuntimeReleaseOperationV2,
    signed_node_rights_decision: SignedNodeRightsDecisionV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPoolStatementV1 {
    selected_node_public_key: NodePublicKey,
    kind: PoolStatementKindV1,
    recipient_attestation: PoolRecipientAttestationStatementV2,
}

impl ValidatedPoolCustodyRequestV1 {
    pub fn decode_and_validate_at(
        bytes: &[u8],
        expected_local_node_public_key: NodePublicKey,
        now_unix_seconds: u64,
    ) -> Result<Self, CustodyProviderRequestValidationErrorV1> {
        PoolCustodyRequestV1::from_json_slice(bytes)?
            .into_validated_at(expected_local_node_public_key, now_unix_seconds)
    }

    pub fn op(&self) -> PoolCustodyRequestOpV1 {
        match &self.kind {
            ValidatedPoolCustodyRequestKindV1::Release(_) => {
                PoolCustodyRequestOpV1::ReleasePoolContribution
            }
            ValidatedPoolCustodyRequestKindV1::Statement(_) => {
                PoolCustodyRequestOpV1::SignPoolStatement
            }
            ValidatedPoolCustodyRequestKindV1::Provision(_) => {
                PoolCustodyRequestOpV1::ProvisionPoolNodeShare
            }
        }
    }

    pub fn provision_pool_node_share(&self) -> Result<&ValidatedPoolProvisionV1, ContractError> {
        match &self.kind {
            ValidatedPoolCustodyRequestKindV1::Provision(request) => Ok(request),
            _ => Err(ContractError::InvalidField("provision_pool_node_share")),
        }
    }

    pub fn release_pool_contribution(&self) -> Result<&ValidatedPoolReleaseV1, ContractError> {
        match &self.kind {
            ValidatedPoolCustodyRequestKindV1::Release(request) => Ok(request),
            _ => Err(ContractError::InvalidField("release_pool_contribution")),
        }
    }

    pub fn sign_pool_statement(&self) -> Result<&ValidatedPoolStatementV1, ContractError> {
        match &self.kind {
            ValidatedPoolCustodyRequestKindV1::Statement(request) => Ok(request),
            _ => Err(ContractError::InvalidField("sign_pool_statement")),
        }
    }

    fn selected_node_public_key(&self) -> NodePublicKey {
        match &self.kind {
            ValidatedPoolCustodyRequestKindV1::Release(request) => request.selected_node_public_key,
            ValidatedPoolCustodyRequestKindV1::Statement(request) => {
                request.selected_node_public_key
            }
            ValidatedPoolCustodyRequestKindV1::Provision(request) => {
                request.selected_node_public_key
            }
        }
    }
}

impl ValidatedPoolReleaseV1 {
    pub const fn selected_node_public_key(&self) -> NodePublicKey {
        self.selected_node_public_key
    }

    pub fn authenticated_runtime_release_operation(
        &self,
    ) -> &AuthenticatedRuntimeReleaseOperationV2 {
        &self.authenticated_runtime_release_operation
    }

    pub fn signed_node_rights_decision(&self) -> &SignedNodeRightsDecisionV1 {
        &self.signed_node_rights_decision
    }
}

impl ValidatedPoolStatementV1 {
    pub const fn selected_node_public_key(&self) -> NodePublicKey {
        self.selected_node_public_key
    }

    pub const fn kind(&self) -> PoolStatementKindV1 {
        self.kind
    }

    pub fn recipient_attestation(&self) -> &PoolRecipientAttestationStatementV2 {
        &self.recipient_attestation
    }

    /// The exact bytes the node signs: the statement's canonical bytes.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.recipient_attestation.canonical_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolCustodyResponseStatusV1 {
    Contributions,
    StatementSignature,
    /// S7-lite T7.3: the node holds the share (stored now or already).
    Provisioned,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolCustodyResponseV1(PoolCustodyResponseKindV1);

/// A failure names what it answers: a release by its audit id and V2
/// operation hash (L1), a statement by its canonical hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum PoolCustodyResponseKindV1 {
    Contributions {
        schema: String,
        signed_node_contributions: SignedNodeContributionBlobListV1,
    },
    StatementSignature {
        schema: String,
        kind: PoolStatementKindV1,
        statement_sha256: [u8; 32],
        signature: Vec<u8>,
    },
    Provisioned {
        schema: String,
        provisioning_id: [u8; 32],
        provisioning_operation_hash: [u8; 32],
        custody_node_provisioning_record_sha256: [u8; 32],
        custody_node_provisioning_record_bytes: u32,
        selected_node_public_key: [u8; 32],
    },
    Failure {
        schema: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audit_request_id: Option<[u8; 32]>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_hash: Option<[u8; 32]>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        statement_sha256: Option<[u8; 32]>,
        selected_node_public_key: [u8; 32],
        code: ProviderFailureCodeV1,
    },
}

impl PoolCustodyResponseV1 {
    pub fn status(&self) -> PoolCustodyResponseStatusV1 {
        match &self.0 {
            PoolCustodyResponseKindV1::Contributions { .. } => {
                PoolCustodyResponseStatusV1::Contributions
            }
            PoolCustodyResponseKindV1::StatementSignature { .. } => {
                PoolCustodyResponseStatusV1::StatementSignature
            }
            PoolCustodyResponseKindV1::Provisioned { .. } => {
                PoolCustodyResponseStatusV1::Provisioned
            }
            PoolCustodyResponseKindV1::Failure { .. } => PoolCustodyResponseStatusV1::Failure,
        }
    }

    /// S7-lite T7.3: the node holds this request's share.
    pub fn new_pool_provisioned(
        request: &ValidatedPoolCustodyRequestV1,
    ) -> Result<Self, ContractError> {
        let provision = request.provision_pool_node_share()?;
        let record = provision.record_identity();
        let value = Self(PoolCustodyResponseKindV1::Provisioned {
            schema: POOL_CUSTODY_RESPONSE_SCHEMA_V1.to_string(),
            provisioning_id: *provision.provisioning_id().digest().as_bytes(),
            provisioning_operation_hash: *provision.provisioning_operation_hash().as_bytes(),
            custody_node_provisioning_record_sha256: *record.record_sha256().as_bytes(),
            custody_node_provisioning_record_bytes: record.record_bytes(),
            selected_node_public_key: *provision.selected_node_public_key().as_bytes(),
        });
        value.validate()?;
        Ok(value)
    }

    /// The provisioning a `Provisioned` answer names.
    pub fn provisioned_id(&self) -> Result<RuntimeCustodyProvisioningIdV1, ContractError> {
        match &self.0 {
            PoolCustodyResponseKindV1::Provisioned {
                provisioning_id, ..
            } => RuntimeCustodyProvisioningIdV1::new(Digest32::new(*provisioning_id)),
            _ => Err(ContractError::InvalidField("provisioning_id")),
        }
    }

    /// The minter's check of a `Provisioned` answer against the request it
    /// sent: the same provisioning, record and node.
    pub fn validate_provisioned_against(
        &self,
        statement: &SignedRuntimeCustodyProvisioningV1,
        record: &CustodyNodeProvisioningRecordV1,
    ) -> Result<(), ContractError> {
        match &self.0 {
            PoolCustodyResponseKindV1::Provisioned {
                provisioning_id,
                provisioning_operation_hash,
                custody_node_provisioning_record_sha256,
                custody_node_provisioning_record_bytes,
                selected_node_public_key,
                ..
            } => {
                let identity = record.record_identity()?;
                if Digest32::new(*provisioning_id)
                    != statement.statement().provisioning_id().digest()
                    || Digest32::new(*provisioning_operation_hash)
                        != statement.statement().canonical_hash()?
                    || Digest32::new(*custody_node_provisioning_record_sha256)
                        != identity.record_sha256()
                    || *custody_node_provisioning_record_bytes != identity.record_bytes()
                    || *selected_node_public_key != *record.selected_node_public_key().as_bytes()
                {
                    return Err(ContractError::InvalidField("pool_provisioned"));
                }
                Ok(())
            }
            _ => Err(ContractError::InvalidField("pool_provisioned")),
        }
    }

    /// One contribution per signed recipient, in the rights request's order.
    pub fn new_pool_contributions(
        request: &ValidatedPoolCustodyRequestV1,
        signed_node_contributions: &[SignedNodeContributionV1],
    ) -> Result<Self, ContractError> {
        request.release_pool_contribution()?;
        let contributions = signed_node_contributions
            .iter()
            .map(CanonicalBlob::from_contract)
            .collect::<Result<Vec<_>, _>>()?;
        let value = Self(PoolCustodyResponseKindV1::Contributions {
            schema: POOL_CUSTODY_RESPONSE_SCHEMA_V1.to_string(),
            signed_node_contributions: CanonicalBlobList::new(contributions)?,
        });
        value.validate()?;
        Ok(value)
    }

    pub fn new_pool_statement_signature(
        request: &ValidatedPoolCustodyRequestV1,
        signature: [u8; 64],
    ) -> Result<Self, ContractError> {
        let statement = request.sign_pool_statement()?;
        let value = Self(PoolCustodyResponseKindV1::StatementSignature {
            schema: POOL_CUSTODY_RESPONSE_SCHEMA_V1.to_string(),
            kind: statement.kind(),
            statement_sha256: *statement
                .recipient_attestation()
                .canonical_hash()?
                .as_bytes(),
            signature: signature.to_vec(),
        });
        value.validate()?;
        Ok(value)
    }

    /// Provider-bound failure. Construct only from a validated request.
    pub fn new_failure(
        request: &ValidatedPoolCustodyRequestV1,
        code: ProviderFailureCodeV1,
    ) -> Result<Self, ContractError> {
        let (audit_request_id, operation_hash, statement_sha256) = match &request.kind {
            ValidatedPoolCustodyRequestKindV1::Release(release) => {
                let operation = release.authenticated_runtime_release_operation();
                (
                    Some(*operation.statement().audit_request_id().digest().as_bytes()),
                    Some(*operation.operation_hash().as_bytes()),
                    None,
                )
            }
            ValidatedPoolCustodyRequestKindV1::Statement(statement) => (
                None,
                None,
                Some(
                    *statement
                        .recipient_attestation()
                        .canonical_hash()?
                        .as_bytes(),
                ),
            ),
            // A provisioning refusal is a plain provider error code.
            ValidatedPoolCustodyRequestKindV1::Provision(_) => {
                return Err(ContractError::InvalidField("pool_custody_failure"))
            }
        };
        let value = Self(PoolCustodyResponseKindV1::Failure {
            schema: POOL_CUSTODY_RESPONSE_SCHEMA_V1.to_string(),
            audit_request_id,
            operation_hash,
            statement_sha256,
            selected_node_public_key: *request.selected_node_public_key().as_bytes(),
            code,
        });
        value.validate()?;
        Ok(value)
    }

    pub fn signed_node_contributions(
        &self,
    ) -> Result<Vec<SignedNodeContributionV1>, ContractError> {
        match &self.0 {
            PoolCustodyResponseKindV1::Contributions {
                signed_node_contributions,
                ..
            } => signed_node_contributions
                .iter()
                .map(SignedNodeContributionV1::from_canonical_bytes)
                .collect(),
            _ => Err(ContractError::InvalidField("signed_node_contributions")),
        }
    }

    pub fn statement_signature(&self) -> Result<[u8; 64], ContractError> {
        match &self.0 {
            PoolCustodyResponseKindV1::StatementSignature { signature, .. } => signature
                .as_slice()
                .try_into()
                .map_err(|_| ContractError::InvalidField("pool_statement_signature")),
            _ => Err(ContractError::InvalidField("pool_statement_signature")),
        }
    }

    pub fn failure_code(&self) -> Result<ProviderFailureCodeV1, ContractError> {
        match &self.0 {
            PoolCustodyResponseKindV1::Failure { code, .. } => Ok(*code),
            _ => Err(ContractError::InvalidField("provider_failure_code")),
        }
    }

    /// The V2 operation a release failure answers (L1).
    pub fn failure_operation_hash(&self) -> Result<Digest32, ContractError> {
        match &self.0 {
            PoolCustodyResponseKindV1::Failure {
                operation_hash: Some(operation_hash),
                ..
            } => Ok(Digest32::new(*operation_hash)),
            _ => Err(ContractError::InvalidField("operation_hash")),
        }
    }

    pub fn failure_audit_request_id(&self) -> Result<RuntimeReleaseAuditIdV1, ContractError> {
        match &self.0 {
            PoolCustodyResponseKindV1::Failure {
                audit_request_id: Some(audit_request_id),
                ..
            } => RuntimeReleaseAuditIdV1::new(Digest32::new(*audit_request_id)),
            _ => Err(ContractError::InvalidField("audit_request_id")),
        }
    }

    /// The statement a signing failure answers.
    pub fn failure_statement_hash(&self) -> Result<Digest32, ContractError> {
        match &self.0 {
            PoolCustodyResponseKindV1::Failure {
                statement_sha256: Some(statement_sha256),
                ..
            } => Ok(Digest32::new(*statement_sha256)),
            _ => Err(ContractError::InvalidField("statement_sha256")),
        }
    }

    pub fn failure_selected_node_public_key(&self) -> Result<NodePublicKey, ContractError> {
        match &self.0 {
            PoolCustodyResponseKindV1::Failure {
                selected_node_public_key,
                ..
            } => NodePublicKey::new(*selected_node_public_key),
            _ => Err(ContractError::InvalidField("selected_node_public_key")),
        }
    }

    /// Checks this answer against the validated request it answers.
    pub fn validate_against_request_at(
        &self,
        request: &ValidatedPoolCustodyRequestV1,
        now_unix_seconds: u64,
    ) -> Result<(), ContractError> {
        match &self.0 {
            PoolCustodyResponseKindV1::Contributions { .. } => {
                let release = request.release_pool_contribution()?;
                let operation = release.authenticated_runtime_release_operation();
                let node_set = release_node_set(operation)
                    .map_err(|_| ContractError::InvalidField("signed_runtime_release_operation"))?;
                let recipients = operation
                    .statement()
                    .rights_request()
                    .request()
                    .recipients();
                let contributions = self.signed_node_contributions()?;
                if contributions.len() != recipients.len() {
                    return Err(ContractError::InvalidField("signed_node_contributions"));
                }
                for (contribution, recipient) in contributions.iter().zip(recipients) {
                    let verified = operation
                        .verify_node_contribution(
                            contribution,
                            &node_set,
                            recipient,
                            now_unix_seconds,
                        )
                        .map_err(|_| ContractError::InvalidField("signed_node_contribution"))?;
                    if verified.node_public_key() != release.selected_node_public_key() {
                        return Err(ContractError::InvalidField("signed_node_contribution"));
                    }
                }
                Ok(())
            }
            PoolCustodyResponseKindV1::StatementSignature {
                kind,
                statement_sha256,
                ..
            } => {
                let statement = request.sign_pool_statement()?;
                if *kind != statement.kind() {
                    return Err(ContractError::InvalidField("pool_statement_kind"));
                }
                if Digest32::new(*statement_sha256)
                    != statement.recipient_attestation().canonical_hash()?
                {
                    return Err(ContractError::InvalidField("pool_statement"));
                }
                SignedPoolRecipientAttestationV2::new(
                    statement.recipient_attestation().clone(),
                    self.statement_signature()?.to_vec(),
                )?
                .verify_node_signature()
                .map_err(|_| ContractError::InvalidField("pool_statement_signature"))
            }
            PoolCustodyResponseKindV1::Provisioned { .. } => {
                let provision = request.provision_pool_node_share()?;
                self.validate_provisioned_against(
                    provision.signed_runtime_custody_provisioning(),
                    provision.custody_node_provisioning_record(),
                )
            }
            PoolCustodyResponseKindV1::Failure { .. } => {
                if self.failure_selected_node_public_key()? != request.selected_node_public_key() {
                    return Err(ContractError::InvalidField("selected_node_public_key"));
                }
                match &request.kind {
                    ValidatedPoolCustodyRequestKindV1::Release(release) => {
                        let operation = release.authenticated_runtime_release_operation();
                        if self.failure_audit_request_id()?
                            != operation.statement().audit_request_id()
                        {
                            return Err(ContractError::InvalidField("audit_request_id"));
                        }
                        if self.failure_operation_hash()? != operation.operation_hash() {
                            return Err(ContractError::InvalidField("operation_hash"));
                        }
                    }
                    ValidatedPoolCustodyRequestKindV1::Statement(statement) => {
                        if self.failure_statement_hash()?
                            != statement.recipient_attestation().canonical_hash()?
                        {
                            return Err(ContractError::InvalidField("statement_sha256"));
                        }
                    }
                    ValidatedPoolCustodyRequestKindV1::Provision(_) => {
                        return Err(ContractError::InvalidField("pool_custody_failure"));
                    }
                }
                Ok(())
            }
        }
    }

    /// The buyer-side check against the caller's own request (S4 R2), as the
    /// V1 response check does.
    pub fn validate_against_plain_request_at(
        &self,
        request: &PoolCustodyRequestV1,
        node_public_key: NodePublicKey,
        now_unix_seconds: u64,
    ) -> Result<(), ContractError> {
        let validated = request
            .clone()
            .into_validated_at(node_public_key, now_unix_seconds)
            .map_err(|_| ContractError::InvalidField("pool_custody_request"))?;
        self.validate_against_request_at(&validated, now_unix_seconds)
    }

    pub fn to_json_vec(&self) -> Result<Vec<u8>, serde_json::Error> {
        encode_json(self)
    }

    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        decode_json(bytes)
    }

    fn validate(&self) -> Result<(), ContractError> {
        match &self.0 {
            PoolCustodyResponseKindV1::Contributions { schema, .. } => {
                validate_schema(
                    schema,
                    POOL_CUSTODY_RESPONSE_SCHEMA_V1,
                    "pool_custody_response.schema",
                )?;
                self.signed_node_contributions().map(|_| ())
            }
            PoolCustodyResponseKindV1::StatementSignature {
                schema, signature, ..
            } => {
                validate_schema(
                    schema,
                    POOL_CUSTODY_RESPONSE_SCHEMA_V1,
                    "pool_custody_response.schema",
                )?;
                if signature.len() != ED25519_SIGNATURE_BYTES {
                    return Err(ContractError::InvalidField("pool_statement_signature"));
                }
                Ok(())
            }
            PoolCustodyResponseKindV1::Provisioned {
                schema,
                provisioning_id,
                custody_node_provisioning_record_sha256,
                custody_node_provisioning_record_bytes,
                selected_node_public_key,
                ..
            } => {
                validate_schema(
                    schema,
                    POOL_CUSTODY_RESPONSE_SCHEMA_V1,
                    "pool_custody_response.schema",
                )?;
                RuntimeCustodyProvisioningIdV1::new(Digest32::new(*provisioning_id))?;
                CustodyNodeProvisioningRecordIdentityV1::new(
                    Digest32::new(*custody_node_provisioning_record_sha256),
                    *custody_node_provisioning_record_bytes,
                )?;
                NodePublicKey::new(*selected_node_public_key).map(|_| ())
            }
            PoolCustodyResponseKindV1::Failure {
                schema,
                audit_request_id,
                operation_hash,
                statement_sha256,
                ..
            } => {
                validate_schema(
                    schema,
                    POOL_CUSTODY_RESPONSE_SCHEMA_V1,
                    "pool_custody_response.schema",
                )?;
                // Exactly one subject: a release (audit id and operation
                // hash) or a statement.
                match (audit_request_id, operation_hash, statement_sha256) {
                    (Some(audit_request_id), Some(_), None) => {
                        RuntimeReleaseAuditIdV1::new(Digest32::new(*audit_request_id))?;
                    }
                    (None, None, Some(_)) => {}
                    _ => return Err(ContractError::InvalidField("pool_custody_failure")),
                }
                self.failure_selected_node_public_key().map(|_| ())
            }
        }
    }
}

impl Serialize for PoolCustodyResponseV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PoolCustodyResponseV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = PoolCustodyResponseKindV1::deserialize(deserializer)?;
        let value = Self(inner);
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

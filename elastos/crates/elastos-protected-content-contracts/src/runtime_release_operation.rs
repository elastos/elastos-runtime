use std::collections::HashSet;

use ed25519_dalek::Signature;
use serde::Serialize;
use thiserror::Error;

use crate::canonical::{CanonicalBody, ContractError, Decoder, Encoder};
use crate::rights::{sort_by_canonical_bytes, validate_active, validate_time_window, RightsError};
use crate::{
    CanonicalContract, CustodyEnvelopeV1, CustodyEpochError, CustodyEpochIdentityV1,
    DeliveryKeyIdentityV1, Digest32, KeyReleaseError, KeyReleaseRequestV1, NodePublicKey,
    NodeSetV1, PoolContractError, PoolDidV1, PoolEpochBundleV1, ProtectedContentBindingV1,
    RecipientAuthorizationError, RecipientKeyAuthorizationContextV1, RecipientKeyIdentityV1,
    RecipientPublicKeyBytesV1, ReplayClaimKeyV1, RightsActionV1, RightsEvaluationEvidenceRequestV1,
    RightsPolicyBodyV1, RuntimeOperationIssuerKeyV1, SignedCustodyEpochV1,
    SignedNodeContributionV1, SignedNodeRightsDecisionV1, SignedPoolDescriptorAnyV1,
    SignedPoolRecipientAttestationAnyV1, SignedRecipientKeyAuthorizationV1,
    SignedTerminalReceiptV1, TerminalReceiptIssuerKey, VerifiedCustodyEpochV1,
    VerifiedKeyReleaseRequestV1, VerifiedNodeContributionV1, VerifiedNodeRightsDecisionV1,
    VerifiedPoolDescriptorV1, WalletSignedRightsRequestV1, WalletSignedRightsRequestV2,
    MAX_SESSION_RECIPIENTS_V2,
};

pub const MAX_RUNTIME_RELEASE_OPERATION_LIFETIME_SECS: u64 = 60;
const ED25519_SIGNATURE_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct RuntimeReleaseAuditIdV1(Digest32);

impl RuntimeReleaseAuditIdV1 {
    pub fn new(value: Digest32) -> Result<Self, ContractError> {
        if value == Digest32::new([0; 32]) {
            return Err(ContractError::InvalidField("runtime_release_audit_id"));
        }
        Ok(Self(value))
    }

    pub const fn digest(&self) -> Digest32 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RuntimeReleaseOperationError {
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error(transparent)]
    Rights(#[from] RightsError),
    #[error(transparent)]
    KeyRelease(#[from] KeyReleaseError),
    #[error(transparent)]
    RecipientAuthorization(#[from] RecipientAuthorizationError),
    #[error(transparent)]
    CustodyEpoch(#[from] CustodyEpochError),
    #[error(transparent)]
    Pool(#[from] PoolContractError),
    #[error("runtime release operation mismatch: {0}")]
    BindingMismatch(&'static str),
    #[error("runtime release operation signature is invalid")]
    InvalidRuntimeSignature,
    #[error("runtime release operation is not yet valid")]
    NotYetValid,
    #[error("runtime release operation expired")]
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeReleaseOperationStatementV1 {
    runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
    rights_request: WalletSignedRightsRequestV1,
    release_request: KeyReleaseRequestV1,
    recipient_public_key: RecipientPublicKeyBytesV1,
    recipient_authorization: SignedRecipientKeyAuthorizationV1,
    policy_body: RightsPolicyBodyV1,
    evidence_request: RightsEvaluationEvidenceRequestV1,
    custody_epoch: SignedCustodyEpochV1,
    audit_request_id: RuntimeReleaseAuditIdV1,
    issued_at: u64,
    expires_at: u64,
}

impl RuntimeReleaseOperationStatementV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
        rights_request: WalletSignedRightsRequestV1,
        release_request: KeyReleaseRequestV1,
        recipient_public_key: RecipientPublicKeyBytesV1,
        recipient_authorization: SignedRecipientKeyAuthorizationV1,
        policy_body: RightsPolicyBodyV1,
        evidence_request: RightsEvaluationEvidenceRequestV1,
        custody_epoch: SignedCustodyEpochV1,
        audit_request_id: RuntimeReleaseAuditIdV1,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, ContractError> {
        let value = Self {
            runtime_operation_issuer,
            rights_request,
            release_request,
            recipient_public_key,
            recipient_authorization,
            policy_body,
            evidence_request,
            custody_epoch,
            audit_request_id,
            issued_at,
            expires_at,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn runtime_operation_issuer(&self) -> RuntimeOperationIssuerKeyV1 {
        self.runtime_operation_issuer
    }

    pub fn rights_request(&self) -> &WalletSignedRightsRequestV1 {
        &self.rights_request
    }

    pub fn release_request(&self) -> &KeyReleaseRequestV1 {
        &self.release_request
    }

    pub const fn recipient_public_key(&self) -> RecipientPublicKeyBytesV1 {
        self.recipient_public_key
    }

    pub fn recipient_authorization(&self) -> &SignedRecipientKeyAuthorizationV1 {
        &self.recipient_authorization
    }

    pub fn policy_body(&self) -> &RightsPolicyBodyV1 {
        &self.policy_body
    }

    pub fn evidence_request(&self) -> &RightsEvaluationEvidenceRequestV1 {
        &self.evidence_request
    }

    pub fn custody_epoch(&self) -> &SignedCustodyEpochV1 {
        &self.custody_epoch
    }

    pub const fn audit_request_id(&self) -> RuntimeReleaseAuditIdV1 {
        self.audit_request_id
    }

    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

impl CanonicalBody for RuntimeReleaseOperationStatementV1 {
    const DOMAIN: &'static str = "elastos.protected-content.runtime-release-operation-statement/v1";

    fn validate(&self) -> Result<(), ContractError> {
        RuntimeOperationIssuerKeyV1::new(*self.runtime_operation_issuer.as_bytes())?;
        self.rights_request.canonical_bytes()?;
        self.release_request.canonical_bytes()?;
        RecipientPublicKeyBytesV1::new(*self.recipient_public_key.as_bytes())?;
        self.recipient_authorization.canonical_bytes()?;
        self.policy_body.canonical_bytes()?;
        self.evidence_request.canonical_bytes()?;
        self.evidence_request
            .validate_against_policy(&self.policy_body)?;
        self.custody_epoch.canonical_bytes()?;
        RuntimeReleaseAuditIdV1::new(self.audit_request_id.digest())?;
        validate_time_window(
            self.issued_at,
            self.expires_at,
            MAX_RUNTIME_RELEASE_OPERATION_LIFETIME_SECS,
            "runtime_release_operation_lifetime",
        )?;

        if self.rights_request.request().binding() != self.release_request.binding() {
            return Err(ContractError::InvalidField("release_request.binding"));
        }
        if self.rights_request.request().request_hash()?
            != self.release_request.rights_request_hash()
        {
            return Err(ContractError::InvalidField(
                "release_request.rights_request_hash",
            ));
        }
        if self.rights_request.request().action() != self.release_request.action() {
            return Err(ContractError::InvalidField("release_request.action"));
        }
        if self.rights_request.request().recipient() != self.release_request.recipient() {
            return Err(ContractError::InvalidField("release_request.recipient"));
        }
        if self.rights_request.request().binding() != self.evidence_request.binding() {
            return Err(ContractError::InvalidField("evidence_request.binding"));
        }
        if self.rights_request.request().binding()
            != self.recipient_authorization.statement().binding()
        {
            return Err(ContractError::InvalidField(
                "recipient_authorization.binding",
            ));
        }
        if self.rights_request.request().action()
            != self.recipient_authorization.statement().action()
        {
            return Err(ContractError::InvalidField(
                "recipient_authorization.action",
            ));
        }
        if self.release_request.recipient()
            != self
                .recipient_authorization
                .statement()
                .recipient_identity()
        {
            return Err(ContractError::InvalidField(
                "recipient_authorization.recipient_key_identity",
            ));
        }
        if self.recipient_public_key
            != self
                .recipient_authorization
                .statement()
                .recipient_public_key()
        {
            return Err(ContractError::InvalidField(
                "recipient_authorization.recipient_public_key",
            ));
        }
        if self.runtime_operation_issuer
            != self
                .recipient_authorization
                .statement()
                .runtime_operation_issuer()
        {
            return Err(ContractError::InvalidField(
                "recipient_authorization.runtime_operation_issuer",
            ));
        }
        if !self
            .release_request
            .recipient()
            .matches_public_key(self.recipient_public_key.as_bytes())
        {
            return Err(ContractError::InvalidField("recipient_public_key"));
        }
        if self.policy_body.required_action() != self.release_request.action() {
            return Err(ContractError::InvalidField("policy_body.required_action"));
        }
        if self.policy_body.policy_identity()? != *self.release_request.binding().rights_policy() {
            return Err(ContractError::InvalidField("policy_body"));
        }
        if self.issued_at < self.release_request.issued_at()
            || self.expires_at > self.release_request.expires_at()
        {
            return Err(ContractError::InvalidField(
                "runtime_release_operation_lifetime",
            ));
        }
        if self.issued_at < self.recipient_authorization.statement().issued_at()
            || self.expires_at > self.recipient_authorization.statement().expires_at()
        {
            return Err(ContractError::InvalidField(
                "runtime_release_operation_lifetime",
            ));
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.fixed(self.runtime_operation_issuer.as_bytes());
        encoder.nested(&self.rights_request)?;
        encoder.nested(&self.release_request)?;
        encoder.fixed(self.recipient_public_key.as_bytes());
        encoder.nested(&self.recipient_authorization)?;
        encoder.nested(&self.policy_body)?;
        encoder.nested(&self.evidence_request)?;
        encoder.nested(&self.custody_epoch)?;
        encoder.fixed(self.audit_request_id.digest().as_bytes());
        encoder.u64(self.issued_at);
        encoder.u64(self.expires_at);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(
            RuntimeOperationIssuerKeyV1::new(decoder.fixed()?)?,
            decoder.nested("rights_request")?,
            decoder.nested("release_request")?,
            RecipientPublicKeyBytesV1::new(decoder.fixed()?)?,
            decoder.nested("recipient_authorization")?,
            decoder.nested("policy_body")?,
            decoder.nested("evidence_request")?,
            decoder.nested("custody_epoch")?,
            RuntimeReleaseAuditIdV1::new(Digest32::new(decoder.fixed()?))?,
            decoder.u64()?,
            decoder.u64()?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRuntimeReleaseOperationV1 {
    statement: RuntimeReleaseOperationStatementV1,
    runtime_signature: Vec<u8>,
}

impl SignedRuntimeReleaseOperationV1 {
    pub fn new(
        statement: RuntimeReleaseOperationStatementV1,
        runtime_signature: Vec<u8>,
    ) -> Result<Self, ContractError> {
        let value = Self {
            statement,
            runtime_signature,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn statement(&self) -> &RuntimeReleaseOperationStatementV1 {
        &self.statement
    }

    pub fn verify(
        &self,
        expected_runtime_issuer: RuntimeOperationIssuerKeyV1,
        now: u64,
    ) -> Result<AuthenticatedRuntimeReleaseOperationV1, RuntimeReleaseOperationError> {
        self.canonical_bytes()?;
        map_active(self.statement.issued_at, self.statement.expires_at, now)?;
        if self.statement.runtime_operation_issuer != expected_runtime_issuer {
            return Err(RuntimeReleaseOperationError::BindingMismatch(
                "runtime_operation_issuer",
            ));
        }
        let signature = Signature::from_bytes(
            &self
                .runtime_signature
                .clone()
                .try_into()
                .map_err(|_| RuntimeReleaseOperationError::InvalidRuntimeSignature)?,
        );
        let runtime_key = crate::identity::validate_ed25519_public_key(
            *self.statement.runtime_operation_issuer.as_bytes(),
            "runtime_operation_issuer",
        )
        .map_err(|_| RuntimeReleaseOperationError::InvalidRuntimeSignature)?;
        runtime_key
            .verify_strict(&self.statement.canonical_bytes()?, &signature)
            .map_err(|_| RuntimeReleaseOperationError::InvalidRuntimeSignature)?;
        let verified = verify_release_operation_statement(&self.statement, now)?;
        Ok(AuthenticatedRuntimeReleaseOperationV1 {
            statement: self.statement.clone(),
            operation_hash: self.statement.canonical_hash()?,
            rights_request_hash: self.statement.rights_request.request().request_hash()?,
            rights_request_replay_claim_key: self
                .statement
                .rights_request
                .request()
                .replay_claim_key()?,
            release_request_hash: verified.release.request_hash(),
            release_request_replay_claim_key: self.statement.release_request.replay_claim_key()?,
            recipient_authorization_hash: self
                .statement
                .recipient_authorization
                .statement()
                .canonical_hash()?,
            custody_epoch_identity: verified.epoch.epoch_identity(),
        })
    }
}

impl CanonicalBody for SignedRuntimeReleaseOperationV1 {
    const DOMAIN: &'static str = "elastos.protected-content.runtime-release-operation/v1";

    fn validate(&self) -> Result<(), ContractError> {
        self.statement.canonical_bytes()?;
        if self.runtime_signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(ContractError::InvalidField("runtime_signature"));
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.statement)?;
        encoder.bytes(&self.runtime_signature)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(
            decoder.nested("statement")?,
            decoder.bytes("runtime_signature", ED25519_SIGNATURE_BYTES)?,
        )
    }
}

/// Signature-checked Runtime release operation with exact replay claim keys.
///
/// This type is deliberately replay-pending. It proves the Runtime signature,
/// nested request signatures, recipient authorization, and custody epoch
/// bindings, but it does not claim replay and it does not expose actionable
/// `VerifiedRightsRequestV1` or `VerifiedKeyReleaseRequestV1` values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedRuntimeReleaseOperationV1 {
    statement: RuntimeReleaseOperationStatementV1,
    operation_hash: Digest32,
    rights_request_hash: Digest32,
    rights_request_replay_claim_key: ReplayClaimKeyV1,
    release_request_hash: Digest32,
    release_request_replay_claim_key: ReplayClaimKeyV1,
    recipient_authorization_hash: Digest32,
    custody_epoch_identity: CustodyEpochIdentityV1,
}

impl AuthenticatedRuntimeReleaseOperationV1 {
    pub fn statement(&self) -> &RuntimeReleaseOperationStatementV1 {
        &self.statement
    }

    pub const fn operation_hash(&self) -> Digest32 {
        self.operation_hash
    }

    pub const fn rights_request_hash(&self) -> Digest32 {
        self.rights_request_hash
    }

    pub const fn rights_request_replay_claim_key(&self) -> ReplayClaimKeyV1 {
        self.rights_request_replay_claim_key
    }

    pub const fn release_request_hash(&self) -> Digest32 {
        self.release_request_hash
    }

    pub const fn release_request_replay_claim_key(&self) -> ReplayClaimKeyV1 {
        self.release_request_replay_claim_key
    }

    pub const fn recipient_authorization_hash(&self) -> Digest32 {
        self.recipient_authorization_hash
    }

    pub const fn custody_epoch_identity(&self) -> CustodyEpochIdentityV1 {
        self.custody_epoch_identity
    }

    pub fn binding(&self) -> &crate::ProtectedContentBindingV1 {
        self.statement.release_request().binding()
    }

    pub fn action(&self) -> crate::RightsActionV1 {
        self.statement.release_request().action()
    }

    pub fn recipient(&self) -> &crate::RecipientKeyIdentityV1 {
        self.statement.release_request().recipient()
    }

    pub fn validate_node_release_claim_context(
        &self,
        envelope: &CustodyEnvelopeV1,
        node_public_key: NodePublicKey,
        now: u64,
    ) -> Result<(), RuntimeReleaseOperationError> {
        map_active(self.statement.issued_at, self.statement.expires_at, now)?;
        let verified = verify_release_operation_statement(&self.statement, now)?;
        if !envelope.matches_key_envelope_identity(verified.release.binding().key_envelope())? {
            return Err(RuntimeReleaseOperationError::BindingMismatch(
                "key_envelope",
            ));
        }
        if envelope.manifest().custody_epoch() != verified.epoch.epoch_identity() {
            return Err(RuntimeReleaseOperationError::BindingMismatch(
                "custody_epoch",
            ));
        }
        if envelope.manifest().node(node_public_key).is_none() {
            return Err(RuntimeReleaseOperationError::BindingMismatch(
                "custody_node",
            ));
        }
        Ok(())
    }

    pub fn verify_node_rights_decision(
        &self,
        decision: &SignedNodeRightsDecisionV1,
        node_set: &NodeSetV1,
        now: u64,
    ) -> Result<VerifiedNodeRightsDecisionV1, KeyReleaseError> {
        let verified = verify_release_operation_statement(&self.statement, now)
            .map_err(map_runtime_release_key_release_error)?;
        decision.verify(&verified.release, node_set, now)
    }

    pub fn validate_node_contribution_active_window(
        &self,
        issued_at: u64,
        expires_at: u64,
        decision: &VerifiedNodeRightsDecisionV1,
        now: u64,
    ) -> Result<(), KeyReleaseError> {
        let verified = verify_release_operation_statement(&self.statement, now)
            .map_err(map_runtime_release_key_release_error)?;
        crate::validate_node_contribution_active_window(
            issued_at,
            expires_at,
            &verified.release,
            decision,
            now,
        )
    }

    pub fn verify_node_contribution(
        &self,
        contribution: &SignedNodeContributionV1,
        node_set: &NodeSetV1,
        now: u64,
    ) -> Result<VerifiedNodeContributionV1, KeyReleaseError> {
        let verified = verify_release_operation_statement(&self.statement, now)
            .map_err(map_runtime_release_key_release_error)?;
        contribution.verify(&verified.release, node_set, now)
    }

    pub fn verify_terminal_receipt(
        &self,
        terminal_receipt: &SignedTerminalReceiptV1,
        contributions: &[VerifiedNodeContributionV1],
        expected_issuer: TerminalReceiptIssuerKey,
        now: u64,
    ) -> Result<(), KeyReleaseError> {
        let verified = verify_release_operation_statement(&self.statement, now)
            .map_err(map_runtime_release_key_release_error)?;
        terminal_receipt.verify(&verified.release, contributions, expected_issuer, now)
    }
}

fn map_active(
    issued_at: u64,
    expires_at: u64,
    now: u64,
) -> Result<(), RuntimeReleaseOperationError> {
    match validate_active(issued_at, expires_at, now) {
        Ok(()) => Ok(()),
        Err(RightsError::NotYetValid) => Err(RuntimeReleaseOperationError::NotYetValid),
        Err(RightsError::Expired) => Err(RuntimeReleaseOperationError::Expired),
        Err(RightsError::Contract(error)) => Err(RuntimeReleaseOperationError::Contract(error)),
        Err(other) => Err(RuntimeReleaseOperationError::Rights(other)),
    }
}

struct VerifiedReleaseOperationStatementV1 {
    release: VerifiedKeyReleaseRequestV1,
    epoch: crate::VerifiedCustodyEpochV1,
}

fn verify_release_operation_statement(
    statement: &RuntimeReleaseOperationStatementV1,
    now: u64,
) -> Result<VerifiedReleaseOperationStatementV1, RuntimeReleaseOperationError> {
    let rights_context = crate::RightsVerificationContextV1::new(
        statement.rights_request.request().binding().clone(),
        statement.rights_request.request().action(),
        statement.rights_request.request().recipient().clone(),
        now,
    );
    let verified_rights = statement.rights_request.verify_unclaimed(&rights_context)?;
    let verified_release = statement
        .release_request
        .verify_unclaimed(&verified_rights, now)?;
    let recipient_context = RecipientKeyAuthorizationContextV1::new(
        verified_release.binding().clone(),
        verified_release.action(),
        statement.recipient_public_key,
        statement.runtime_operation_issuer,
        now,
    );
    let verified_authorization = statement
        .recipient_authorization
        .verify(&recipient_context)?;
    let verified_epoch = statement
        .custody_epoch
        .verify_against_key_envelope(verified_release.binding().key_envelope())?;
    if verified_epoch
        .approved_suites()
        .recipient_encryption_suite_id()
        != verified_authorization
            .recipient_identity()
            .encryption_suite_id()
    {
        return Err(RuntimeReleaseOperationError::BindingMismatch(
            "recipient_encryption_suite_id",
        ));
    }
    if statement.recipient_public_key.key_identity(
        verified_epoch
            .approved_suites()
            .recipient_encryption_suite_id(),
    )? != *verified_authorization.recipient_identity()
    {
        return Err(RuntimeReleaseOperationError::BindingMismatch(
            "recipient_public_key",
        ));
    }
    Ok(VerifiedReleaseOperationStatementV1 {
        release: verified_release,
        epoch: verified_epoch,
    })
}

fn map_runtime_release_key_release_error(error: RuntimeReleaseOperationError) -> KeyReleaseError {
    match error {
        RuntimeReleaseOperationError::Contract(error) => KeyReleaseError::Contract(error),
        RuntimeReleaseOperationError::Rights(error) => KeyReleaseError::Rights(error),
        RuntimeReleaseOperationError::KeyRelease(error) => error,
        RuntimeReleaseOperationError::RecipientAuthorization(_) => {
            KeyReleaseError::BindingMismatch("recipient_authorization")
        }
        RuntimeReleaseOperationError::CustodyEpoch(_) => {
            KeyReleaseError::BindingMismatch("custody_epoch")
        }
        RuntimeReleaseOperationError::Pool(_) => KeyReleaseError::BindingMismatch("pool"),
        RuntimeReleaseOperationError::BindingMismatch(field) => {
            KeyReleaseError::BindingMismatch(field)
        }
        RuntimeReleaseOperationError::InvalidRuntimeSignature => {
            KeyReleaseError::BindingMismatch("runtime_signature")
        }
        RuntimeReleaseOperationError::NotYetValid => {
            KeyReleaseError::Rights(RightsError::NotYetValid)
        }
        RuntimeReleaseOperationError::Expired => KeyReleaseError::Rights(RightsError::Expired),
    }
}

// ---------------------------------------------------------------------------
// V2: a release for a pool session (Plan B T1.1)
// ---------------------------------------------------------------------------

/// Which Runtime may sign a V2 operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeIssuerPolicyV1 {
    /// Only this Runtime (the owner path).
    Expected(RuntimeOperationIssuerKeyV1),
    /// The issuer the operation declares (any Runtime the wallet chose).
    Declared,
}

/// One session recipient: its public key and the pool server's vouch for it.
/// The vouch is either attestation version (#388-2); writers emit v2, and a
/// v1 vouch (trust absent) only reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSessionRecipientV1 {
    public_key: RecipientPublicKeyBytesV1,
    attestation: SignedPoolRecipientAttestationAnyV1,
}

impl PoolSessionRecipientV1 {
    pub fn new(
        public_key: RecipientPublicKeyBytesV1,
        attestation: impl Into<SignedPoolRecipientAttestationAnyV1>,
    ) -> Result<Self, ContractError> {
        let value = Self {
            public_key,
            attestation: attestation.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn public_key(&self) -> RecipientPublicKeyBytesV1 {
        self.public_key
    }

    pub fn attestation(&self) -> &SignedPoolRecipientAttestationAnyV1 {
        &self.attestation
    }

    pub fn identity(&self) -> &RecipientKeyIdentityV1 {
        self.attestation.recipient_identity()
    }

    fn validate(&self) -> Result<(), ContractError> {
        RecipientPublicKeyBytesV1::new(*self.public_key.as_bytes())?;
        self.attestation.canonical_bytes()?;
        if self.attestation.recipient_public_key() != self.public_key {
            return Err(ContractError::InvalidField(
                "pool_session_recipient.public_key",
            ));
        }
        Ok(())
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.fixed(self.public_key.as_bytes());
        encoder.nested(&self.attestation)
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let public_key = RecipientPublicKeyBytesV1::new(decoder.fixed()?)?;
        Self::new(
            public_key,
            decoder.nested::<SignedPoolRecipientAttestationAnyV1>("pool_recipient_attestation")?,
        )
    }
}

/// L3: the operation has no separate custody epoch; the epoch is the
/// descriptor's bundle that the item's key envelope names.
///
/// Item 10: the statement keeps its `/v2` domain and field grammar. Its
/// `pool_descriptor` is the nested canonical bytes of either descriptor
/// version, with that descriptor's own domain; writers nest the ticketless
/// `/v2` descriptor, and a build that knows only `/v1` refuses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeReleaseOperationStatementV2 {
    runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
    rights_request: WalletSignedRightsRequestV2,
    recipients: Vec<PoolSessionRecipientV1>,
    policy_body: RightsPolicyBodyV1,
    evidence_request: RightsEvaluationEvidenceRequestV1,
    pool_descriptor: SignedPoolDescriptorAnyV1,
    audit_request_id: RuntimeReleaseAuditIdV1,
    issued_at: u64,
    expires_at: u64,
}

impl RuntimeReleaseOperationStatementV2 {
    /// Recipients are kept in the canonical-byte order of their identities,
    /// the order of the rights request's recipients (E2).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
        rights_request: WalletSignedRightsRequestV2,
        recipients: Vec<PoolSessionRecipientV1>,
        policy_body: RightsPolicyBodyV1,
        evidence_request: RightsEvaluationEvidenceRequestV1,
        pool_descriptor: SignedPoolDescriptorAnyV1,
        audit_request_id: RuntimeReleaseAuditIdV1,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, ContractError> {
        let value = Self {
            runtime_operation_issuer,
            rights_request,
            recipients: sort_by_canonical_bytes(recipients, |recipient| {
                recipient.identity().canonical_bytes()
            })?,
            policy_body,
            evidence_request,
            pool_descriptor,
            audit_request_id,
            issued_at,
            expires_at,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn runtime_operation_issuer(&self) -> RuntimeOperationIssuerKeyV1 {
        self.runtime_operation_issuer
    }

    pub fn rights_request(&self) -> &WalletSignedRightsRequestV2 {
        &self.rights_request
    }

    pub fn recipients(&self) -> &[PoolSessionRecipientV1] {
        &self.recipients
    }

    pub fn policy_body(&self) -> &RightsPolicyBodyV1 {
        &self.policy_body
    }

    pub fn evidence_request(&self) -> &RightsEvaluationEvidenceRequestV1 {
        &self.evidence_request
    }

    pub fn pool_descriptor(&self) -> &SignedPoolDescriptorAnyV1 {
        &self.pool_descriptor
    }

    pub const fn audit_request_id(&self) -> RuntimeReleaseAuditIdV1 {
        self.audit_request_id
    }

    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Plan B S4 session lifetime (user 2026-11-13 04:45): when a session
    /// opened under this release ends. It is the signed rights expiry,
    /// capped by the earliest recipient attestation expiry, so it is never
    /// later than `MAX_RIGHTS_REQUEST_LIFETIME_SECS` after the rights were
    /// issued. [`Self::expires_at`] bounds only the node release.
    pub fn session_expires_at(&self) -> u64 {
        self.recipients
            .iter()
            .map(|recipient| recipient.attestation().expires_at())
            .fold(self.rights_request.request().expires_at(), u64::min)
    }
}

impl CanonicalBody for RuntimeReleaseOperationStatementV2 {
    const DOMAIN: &'static str = "elastos.protected-content.runtime-release-operation-statement/v2";

    fn validate(&self) -> Result<(), ContractError> {
        RuntimeOperationIssuerKeyV1::new(*self.runtime_operation_issuer.as_bytes())?;
        self.rights_request.canonical_bytes()?;
        for recipient in &self.recipients {
            recipient.validate()?;
        }
        self.policy_body.canonical_bytes()?;
        self.evidence_request.canonical_bytes()?;
        self.evidence_request
            .validate_against_policy(&self.policy_body)?;
        self.pool_descriptor.canonical_bytes()?;
        RuntimeReleaseAuditIdV1::new(self.audit_request_id.digest())?;
        validate_time_window(
            self.issued_at,
            self.expires_at,
            MAX_RUNTIME_RELEASE_OPERATION_LIFETIME_SECS,
            "runtime_release_operation_lifetime",
        )?;

        let request = self.rights_request.request();
        // ADV-01 F4: a pool operation needs the pool form (tag 1), which
        // carries the delivery key.
        if request.delivery_key().is_none() {
            return Err(ContractError::InvalidField("rights_request.delivery_key"));
        }
        // E2: the recipients are the wallet-signed ones, in the same order.
        if self.recipients.len() != request.recipients().len()
            || self
                .recipients
                .iter()
                .zip(request.recipients())
                .any(|(recipient, signed)| recipient.identity() != signed)
        {
            return Err(ContractError::InvalidField("recipients"));
        }
        for recipient in &self.recipients {
            let attestation = &recipient.attestation;
            if attestation.binding() != request.binding() {
                return Err(ContractError::InvalidField(
                    "recipients.attestation.binding",
                ));
            }
            if attestation.action() != request.action() {
                return Err(ContractError::InvalidField("recipients.attestation.action"));
            }
            if attestation.runtime_operation_issuer() != self.runtime_operation_issuer {
                return Err(ContractError::InvalidField(
                    "recipients.attestation.runtime_operation_issuer",
                ));
            }
            if self.issued_at < attestation.issued_at()
                || self.expires_at > attestation.expires_at()
            {
                return Err(ContractError::InvalidField(
                    "runtime_release_operation_lifetime",
                ));
            }
        }
        if request.binding() != self.evidence_request.binding() {
            return Err(ContractError::InvalidField("evidence_request.binding"));
        }
        if self.policy_body.required_action() != request.action() {
            return Err(ContractError::InvalidField("policy_body.required_action"));
        }
        if self.policy_body.policy_identity()? != *request.binding().rights_policy() {
            return Err(ContractError::InvalidField("policy_body"));
        }
        // ADV-01: the wallet signed for the policy's chain.
        if request.chain_id() != self.policy_body.chain_id() {
            return Err(ContractError::InvalidField("rights_request.chain_id"));
        }
        if self.issued_at < request.issued_at() || self.expires_at > request.expires_at() {
            return Err(ContractError::InvalidField(
                "runtime_release_operation_lifetime",
            ));
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.fixed(self.runtime_operation_issuer.as_bytes());
        encoder.nested(&self.rights_request)?;
        encoder.u8(u8::try_from(self.recipients.len())
            .map_err(|_| ContractError::InvalidField("recipients"))?);
        for recipient in &self.recipients {
            recipient.encode(encoder)?;
        }
        encoder.nested(&self.policy_body)?;
        encoder.nested(&self.evidence_request)?;
        encoder.nested(&self.pool_descriptor)?;
        encoder.fixed(self.audit_request_id.digest().as_bytes());
        encoder.u64(self.issued_at);
        encoder.u64(self.expires_at);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let runtime_operation_issuer = RuntimeOperationIssuerKeyV1::new(decoder.fixed()?)?;
        let rights_request = decoder.nested("rights_request")?;
        let count = usize::from(decoder.u8()?);
        if count == 0 || count > MAX_SESSION_RECIPIENTS_V2 {
            return Err(ContractError::InvalidField("recipients"));
        }
        let mut recipients = Vec::with_capacity(count);
        for _ in 0..count {
            recipients.push(PoolSessionRecipientV1::decode(decoder)?);
        }
        Self::new(
            runtime_operation_issuer,
            rights_request,
            recipients,
            decoder.nested("policy_body")?,
            decoder.nested("evidence_request")?,
            decoder.nested("pool_descriptor")?,
            RuntimeReleaseAuditIdV1::new(Digest32::new(decoder.fixed()?))?,
            decoder.u64()?,
            decoder.u64()?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRuntimeReleaseOperationV2 {
    statement: RuntimeReleaseOperationStatementV2,
    runtime_signature: Vec<u8>,
}

impl SignedRuntimeReleaseOperationV2 {
    pub fn new(
        statement: RuntimeReleaseOperationStatementV2,
        runtime_signature: Vec<u8>,
    ) -> Result<Self, ContractError> {
        let value = Self {
            statement,
            runtime_signature,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn statement(&self) -> &RuntimeReleaseOperationStatementV2 {
        &self.statement
    }

    pub fn runtime_signature(&self) -> &[u8] {
        &self.runtime_signature
    }

    /// The descriptor bundle that the item's key envelope names, by decode
    /// only: no signature, window or committee check. For the draft-level
    /// check before verification (S4 R3).
    pub fn unverified_epoch_bundle(&self) -> Option<&PoolEpochBundleV1> {
        self.statement.pool_descriptor.unverified_epoch_for(
            self.statement
                .rights_request
                .request()
                .binding()
                .key_envelope(),
        )
    }

    /// Verifies the operation at the verifier's own clock `now`: its window,
    /// the issuer policy, the Runtime signature, the wallet signature, the
    /// embedded descriptor (release rule, F1), the server count (F5), the
    /// item's bundle (L3) and every recipient attestation.
    pub fn verify(
        &self,
        issuer_policy: RuntimeIssuerPolicyV1,
        now: u64,
    ) -> Result<AuthenticatedRuntimeReleaseOperationV2, RuntimeReleaseOperationError> {
        self.canonical_bytes()?;
        map_active(self.statement.issued_at, self.statement.expires_at, now)?;
        if let RuntimeIssuerPolicyV1::Expected(expected) = issuer_policy {
            if self.statement.runtime_operation_issuer != expected {
                return Err(RuntimeReleaseOperationError::BindingMismatch(
                    "runtime_operation_issuer",
                ));
            }
        }
        let signature = Signature::from_slice(&self.runtime_signature)
            .map_err(|_| RuntimeReleaseOperationError::InvalidRuntimeSignature)?;
        let runtime_key = crate::identity::validate_ed25519_public_key(
            *self.statement.runtime_operation_issuer.as_bytes(),
            "runtime_operation_issuer",
        )
        .map_err(|_| RuntimeReleaseOperationError::InvalidRuntimeSignature)?;
        runtime_key
            .verify_strict(&self.statement.canonical_bytes()?, &signature)
            .map_err(|_| RuntimeReleaseOperationError::InvalidRuntimeSignature)?;
        let verified = verify_release_operation_statement_v2(&self.statement, now)?;
        Ok(AuthenticatedRuntimeReleaseOperationV2 {
            statement: self.statement.clone(),
            operation_hash: self.statement.canonical_hash()?,
            rights_request_hash: verified.rights_request_hash,
            rights_request_replay_claim_key: self
                .statement
                .rights_request
                .request()
                .replay_claim_key()?,
            custody_epoch_identity: verified.epoch.epoch_identity(),
            pool: *verified.descriptor.pool(),
            descriptor_sequence: verified.descriptor.sequence(),
            epoch_bundle: verified.bundle,
            delivery_key: verified.delivery_key,
        })
    }
}

impl CanonicalBody for SignedRuntimeReleaseOperationV2 {
    const DOMAIN: &'static str = "elastos.protected-content.runtime-release-operation/v2";

    fn validate(&self) -> Result<(), ContractError> {
        self.statement.canonical_bytes()?;
        if self.runtime_signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(ContractError::InvalidField("runtime_signature"));
        }
        Ok(())
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.statement)?;
        encoder.bytes(&self.runtime_signature)
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(
            decoder.nested("statement")?,
            decoder.bytes("runtime_signature", ED25519_SIGNATURE_BYTES)?,
        )
    }
}

struct VerifiedReleaseOperationStatementV2 {
    rights_request_hash: Digest32,
    descriptor: VerifiedPoolDescriptorV1,
    bundle: PoolEpochBundleV1,
    epoch: VerifiedCustodyEpochV1,
    delivery_key: DeliveryKeyIdentityV1,
}

fn verify_release_operation_statement_v2(
    statement: &RuntimeReleaseOperationStatementV2,
    now: u64,
) -> Result<VerifiedReleaseOperationStatementV2, RuntimeReleaseOperationError> {
    let request = statement.rights_request.request();
    let delivery_key =
        request
            .delivery_key()
            .ok_or(RuntimeReleaseOperationError::BindingMismatch(
                "rights_request.delivery_key",
            ))?;
    let rights_request_hash = statement.rights_request.verify_unclaimed_at(now)?;
    let descriptor = statement.pool_descriptor.verify(now)?;
    // #388 A2: a new release needs a v3 descriptor of a trusted pool; a
    // historical v1 or v2 descriptor (trust absent) only reads.
    let trust_mode = descriptor.admits_new_release()?;
    // F5, D1: the pool's signed server count holds the session.
    if request.recipients().len() > usize::from(descriptor.serve_policy().max_servers_per_session) {
        return Err(PoolContractError::TooMany.into());
    }
    let key_envelope = request.binding().key_envelope();
    let bundle = descriptor
        .epoch_for(key_envelope)
        .cloned()
        .ok_or(PoolContractError::EpochMismatch)?;
    let epoch = bundle
        .signed_epoch()
        .verify_against_key_envelope(key_envelope)?;
    let suite = epoch.approved_suites().recipient_encryption_suite_id();
    let mut servers = HashSet::with_capacity(statement.recipients.len());
    for recipient in &statement.recipients {
        // #388-2: each vouch binds the pool's own trust mode; a v1 vouch
        // (trust absent) never admits a new release.
        if recipient.attestation.trust_mode() != Some(trust_mode) {
            return Err(PoolContractError::TrustRequired.into());
        }
        let vouched = recipient.attestation.verify(&descriptor, &epoch, now)?;
        // One server, one session key: a second vouch from the same server
        // would count it twice against the pool's server count.
        if !servers.insert(vouched.server_node_public_key()) {
            return Err(PoolContractError::TooMany.into());
        }
        if vouched.recipient_identity().encryption_suite_id() != suite {
            return Err(RuntimeReleaseOperationError::BindingMismatch(
                "recipient_encryption_suite_id",
            ));
        }
        if recipient.public_key.key_identity(suite)? != *vouched.recipient_identity() {
            return Err(RuntimeReleaseOperationError::BindingMismatch(
                "recipient_public_key",
            ));
        }
    }
    Ok(VerifiedReleaseOperationStatementV2 {
        rights_request_hash,
        descriptor,
        bundle,
        epoch,
        delivery_key,
    })
}

/// Signature-checked V2 operation. Like V1 it is replay-pending: it exposes
/// the claim key and claims nothing.
///
/// L1 (user ruling): for V2, every `release_request_hash` slot (decision,
/// contribution, `ReleasedShareAadV1`, evidence, terminal receipt) holds
/// [`Self::operation_hash`], and `rights_request_hash` holds the V2 rights
/// hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedRuntimeReleaseOperationV2 {
    statement: RuntimeReleaseOperationStatementV2,
    operation_hash: Digest32,
    rights_request_hash: Digest32,
    rights_request_replay_claim_key: ReplayClaimKeyV1,
    custody_epoch_identity: CustodyEpochIdentityV1,
    epoch_bundle: PoolEpochBundleV1,
    pool: PoolDidV1,
    descriptor_sequence: u64,
    /// The delivery key the wallet signed (the pool form always has one).
    delivery_key: DeliveryKeyIdentityV1,
}

impl AuthenticatedRuntimeReleaseOperationV2 {
    pub fn statement(&self) -> &RuntimeReleaseOperationStatementV2 {
        &self.statement
    }

    pub const fn operation_hash(&self) -> Digest32 {
        self.operation_hash
    }

    pub const fn rights_request_hash(&self) -> Digest32 {
        self.rights_request_hash
    }

    pub const fn rights_request_replay_claim_key(&self) -> ReplayClaimKeyV1 {
        self.rights_request_replay_claim_key
    }

    pub const fn custody_epoch_identity(&self) -> CustodyEpochIdentityV1 {
        self.custody_epoch_identity
    }

    /// The item's custody committee (S4 R3): its node set and threshold.
    pub fn epoch_bundle(&self) -> &PoolEpochBundleV1 {
        &self.epoch_bundle
    }

    pub fn recipients(&self) -> &[PoolSessionRecipientV1] {
        &self.statement.recipients
    }

    pub fn delivery_key(&self) -> DeliveryKeyIdentityV1 {
        self.delivery_key
    }

    /// See [`RuntimeReleaseOperationStatementV2::session_expires_at`].
    pub fn session_expires_at(&self) -> u64 {
        self.statement.session_expires_at()
    }

    pub const fn pool(&self) -> &PoolDidV1 {
        &self.pool
    }

    pub const fn descriptor_sequence(&self) -> u64 {
        self.descriptor_sequence
    }

    pub const fn runtime_operation_issuer(&self) -> RuntimeOperationIssuerKeyV1 {
        self.statement.runtime_operation_issuer
    }

    pub fn binding(&self) -> &ProtectedContentBindingV1 {
        self.statement.rights_request.request().binding()
    }

    pub fn action(&self) -> RightsActionV1 {
        self.statement.rights_request.request().action()
    }

    /// The release context the V1 node checks read (L1): the operation hash
    /// in the release slot and the operation's window.
    fn release_context(&self, recipient: RecipientKeyIdentityV1) -> VerifiedKeyReleaseRequestV1 {
        VerifiedKeyReleaseRequestV1::for_runtime_release_v2(
            self.operation_hash,
            self.binding().clone(),
            self.rights_request_hash,
            self.action(),
            recipient,
            (self.statement.issued_at, self.statement.expires_at),
        )
    }

    fn signed_recipient(
        &self,
        recipient: &RecipientKeyIdentityV1,
    ) -> Result<RecipientKeyIdentityV1, KeyReleaseError> {
        if !self
            .statement
            .rights_request
            .request()
            .recipients()
            .contains(recipient)
        {
            return Err(KeyReleaseError::BindingMismatch("recipient_key_identity"));
        }
        Ok(recipient.clone())
    }

    fn first_recipient(&self) -> RecipientKeyIdentityV1 {
        // A V2 rights request names at least one recipient.
        self.statement.rights_request.request().recipients()[0].clone()
    }

    pub fn validate_node_release_claim_context(
        &self,
        envelope: &CustodyEnvelopeV1,
        node_public_key: NodePublicKey,
        now: u64,
    ) -> Result<(), RuntimeReleaseOperationError> {
        map_active(self.statement.issued_at, self.statement.expires_at, now)?;
        let verified = verify_release_operation_statement_v2(&self.statement, now)?;
        if !envelope.matches_key_envelope_identity(self.binding().key_envelope())? {
            return Err(RuntimeReleaseOperationError::BindingMismatch(
                "key_envelope",
            ));
        }
        if envelope.manifest().custody_epoch() != verified.epoch.epoch_identity() {
            return Err(RuntimeReleaseOperationError::BindingMismatch(
                "custody_epoch",
            ));
        }
        if envelope.manifest().node(node_public_key).is_none() {
            return Err(RuntimeReleaseOperationError::BindingMismatch(
                "custody_node",
            ));
        }
        Ok(())
    }

    pub fn verify_node_rights_decision(
        &self,
        decision: &SignedNodeRightsDecisionV1,
        node_set: &NodeSetV1,
        now: u64,
    ) -> Result<VerifiedNodeRightsDecisionV1, KeyReleaseError> {
        verify_release_operation_statement_v2(&self.statement, now)
            .map_err(map_runtime_release_key_release_error)?;
        decision.verify(&self.release_context(self.first_recipient()), node_set, now)
    }

    pub fn validate_node_contribution_active_window(
        &self,
        issued_at: u64,
        expires_at: u64,
        decision: &VerifiedNodeRightsDecisionV1,
        now: u64,
    ) -> Result<(), KeyReleaseError> {
        verify_release_operation_statement_v2(&self.statement, now)
            .map_err(map_runtime_release_key_release_error)?;
        crate::validate_node_contribution_active_window(
            issued_at,
            expires_at,
            &self.release_context(self.first_recipient()),
            decision,
            now,
        )
    }

    /// A contribution sealed to `recipient`, which must be one of the
    /// wallet-signed recipients.
    pub fn verify_node_contribution(
        &self,
        contribution: &SignedNodeContributionV1,
        node_set: &NodeSetV1,
        recipient: &RecipientKeyIdentityV1,
        now: u64,
    ) -> Result<VerifiedNodeContributionV1, KeyReleaseError> {
        verify_release_operation_statement_v2(&self.statement, now)
            .map_err(map_runtime_release_key_release_error)?;
        let recipient = self.signed_recipient(recipient)?;
        contribution.verify(&self.release_context(recipient), node_set, now)
    }

    /// The terminal receipt of one recipient's release: the recipient is the
    /// one the contributions are sealed to (all the same, checked by the
    /// receipt), or the first signed recipient when there are none.
    pub fn verify_terminal_receipt(
        &self,
        terminal_receipt: &SignedTerminalReceiptV1,
        contributions: &[VerifiedNodeContributionV1],
        expected_issuer: TerminalReceiptIssuerKey,
        now: u64,
    ) -> Result<(), KeyReleaseError> {
        verify_release_operation_statement_v2(&self.statement, now)
            .map_err(map_runtime_release_key_release_error)?;
        let recipient = match contributions.first() {
            Some(contribution) => self.signed_recipient(contribution.recipient())?,
            None => self.first_recipient(),
        };
        terminal_receipt.verify(
            &self.release_context(recipient),
            contributions,
            expected_issuer,
            now,
        )
    }
}

/// A signed V1 or V2 operation, picked by its canonical domain (E7).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the V1 and V2 values are the planned by-value variants; callers match on them"
)]
pub enum RuntimeReleaseOperationAnyV1 {
    V1(SignedRuntimeReleaseOperationV1),
    V2(SignedRuntimeReleaseOperationV2),
}

impl RuntimeReleaseOperationAnyV1 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        match SignedRuntimeReleaseOperationV1::from_canonical_bytes(bytes) {
            Err(ContractError::WrongDomain) => {
                SignedRuntimeReleaseOperationV2::from_canonical_bytes(bytes).map(Self::V2)
            }
            other => other.map(Self::V1),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        match self {
            Self::V1(operation) => operation.canonical_bytes(),
            Self::V2(operation) => operation.canonical_bytes(),
        }
    }

    /// The hash of the signed operation, for both versions: the Runtime
    /// release journal's key and the `resume_exact` key (S4-Q4). It is not
    /// the statement hash (`operation_hash()` on the authenticated forms),
    /// which fills the release slots (L1).
    pub fn journal_key(&self) -> Result<Digest32, ContractError> {
        match self {
            Self::V1(operation) => operation.canonical_hash(),
            Self::V2(operation) => operation.canonical_hash(),
        }
    }

    /// The operation statement's window end.
    pub fn expires_at(&self) -> u64 {
        match self {
            Self::V1(operation) => operation.statement().expires_at(),
            Self::V2(operation) => operation.statement().expires_at(),
        }
    }

    pub fn audit_request_id(&self) -> RuntimeReleaseAuditIdV1 {
        match self {
            Self::V1(operation) => operation.statement().audit_request_id(),
            Self::V2(operation) => operation.statement().audit_request_id(),
        }
    }

    pub fn runtime_operation_issuer(&self) -> RuntimeOperationIssuerKeyV1 {
        match self {
            Self::V1(operation) => operation.statement().runtime_operation_issuer(),
            Self::V2(operation) => operation.statement().runtime_operation_issuer(),
        }
    }

    /// The custody node set by decode only, before verification: V1 from
    /// the operation's custody epoch, V2 from the descriptor bundle the
    /// item's key envelope names (S4 R3).
    pub fn unverified_node_set(&self) -> Option<NodeSetV1> {
        match self {
            Self::V1(operation) => operation
                .statement()
                .custody_epoch()
                .statement()
                .node_set()
                .ok(),
            Self::V2(operation) => operation
                .unverified_epoch_bundle()?
                .signed_epoch()
                .statement()
                .node_set()
                .ok(),
        }
    }

    /// Verifies either version. V1 takes the expected issuer, or its own
    /// declared one under `Declared`, as the providers already do.
    pub fn verify(
        &self,
        issuer_policy: RuntimeIssuerPolicyV1,
        now: u64,
    ) -> Result<AuthenticatedRuntimeReleaseOperationAnyV1, RuntimeReleaseOperationError> {
        match self {
            Self::V1(operation) => {
                let issuer = match issuer_policy {
                    RuntimeIssuerPolicyV1::Expected(expected) => expected,
                    RuntimeIssuerPolicyV1::Declared => {
                        operation.statement().runtime_operation_issuer()
                    }
                };
                operation
                    .verify(issuer, now)
                    .map(AuthenticatedRuntimeReleaseOperationAnyV1::V1)
            }
            Self::V2(operation) => operation
                .verify(issuer_policy, now)
                .map(AuthenticatedRuntimeReleaseOperationAnyV1::V2),
        }
    }
}

impl From<SignedRuntimeReleaseOperationV1> for RuntimeReleaseOperationAnyV1 {
    fn from(operation: SignedRuntimeReleaseOperationV1) -> Self {
        Self::V1(operation)
    }
}

impl From<SignedRuntimeReleaseOperationV2> for RuntimeReleaseOperationAnyV1 {
    fn from(operation: SignedRuntimeReleaseOperationV2) -> Self {
        Self::V2(operation)
    }
}

/// An authenticated V1 or V2 operation (F2). Each V1 arm calls today's V1
/// method, so V1 values and decisions are unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the V1 and V2 values are the planned by-value variants; callers match on them"
)]
pub enum AuthenticatedRuntimeReleaseOperationAnyV1 {
    V1(AuthenticatedRuntimeReleaseOperationV1),
    V2(AuthenticatedRuntimeReleaseOperationV2),
}

impl AuthenticatedRuntimeReleaseOperationAnyV1 {
    pub fn as_v1(&self) -> Option<&AuthenticatedRuntimeReleaseOperationV1> {
        match self {
            Self::V1(operation) => Some(operation),
            Self::V2(_) => None,
        }
    }

    pub fn as_v2(&self) -> Option<&AuthenticatedRuntimeReleaseOperationV2> {
        match self {
            Self::V1(_) => None,
            Self::V2(operation) => Some(operation),
        }
    }

    pub const fn operation_hash(&self) -> Digest32 {
        match self {
            Self::V1(operation) => operation.operation_hash(),
            Self::V2(operation) => operation.operation_hash(),
        }
    }

    /// V2: the operation hash (L1).
    pub const fn release_request_hash(&self) -> Digest32 {
        match self {
            Self::V1(operation) => operation.release_request_hash(),
            Self::V2(operation) => operation.operation_hash(),
        }
    }

    pub const fn rights_request_hash(&self) -> Digest32 {
        match self {
            Self::V1(operation) => operation.rights_request_hash(),
            Self::V2(operation) => operation.rights_request_hash(),
        }
    }

    pub fn binding(&self) -> &ProtectedContentBindingV1 {
        match self {
            Self::V1(operation) => operation.binding(),
            Self::V2(operation) => operation.binding(),
        }
    }

    pub fn action(&self) -> RightsActionV1 {
        match self {
            Self::V1(operation) => operation.action(),
            Self::V2(operation) => operation.action(),
        }
    }

    pub fn audit_request_id(&self) -> RuntimeReleaseAuditIdV1 {
        match self {
            Self::V1(operation) => operation.statement().audit_request_id(),
            Self::V2(operation) => operation.statement().audit_request_id(),
        }
    }

    /// The operation statement's window end.
    pub fn expires_at(&self) -> u64 {
        match self {
            Self::V1(operation) => operation.statement().expires_at(),
            Self::V2(operation) => operation.statement().expires_at(),
        }
    }

    /// V1: the release request's end; V2: the rights request's end.
    pub fn rights_expires_at(&self) -> u64 {
        match self {
            Self::V1(operation) => operation.statement().release_request().expires_at(),
            Self::V2(operation) => operation
                .statement()
                .rights_request()
                .request()
                .expires_at(),
        }
    }

    /// V1: the operation's custody epoch; V2: the item's bundle epoch.
    pub fn node_set(&self) -> Result<NodeSetV1, ContractError> {
        match self {
            Self::V1(operation) => operation.statement().custody_epoch().statement().node_set(),
            Self::V2(operation) => operation
                .epoch_bundle()
                .signed_epoch()
                .statement()
                .node_set(),
        }
    }

    pub fn verify_node_rights_decision(
        &self,
        decision: &SignedNodeRightsDecisionV1,
        node_set: &NodeSetV1,
        now: u64,
    ) -> Result<VerifiedNodeRightsDecisionV1, KeyReleaseError> {
        match self {
            Self::V1(operation) => operation.verify_node_rights_decision(decision, node_set, now),
            Self::V2(operation) => operation.verify_node_rights_decision(decision, node_set, now),
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use hex::encode;
    use k256::ecdsa::SigningKey as WalletSigningKey;
    use sha3::Digest as _;

    use super::*;
    use crate::test_support::{digest, NOW};
    use crate::{
        CustodyApprovedSuitesV1, CustodyEpochIssuerKeyV1, CustodyEpochStatementV1,
        CustodyNodeIdentityV1, EvmContractAddressV1, EvmFunctionSelectorV1, EvmRightsMethodAbiV1,
        NodeCustodyPublicKeyV1, NodePublicKey, ProfileIdentityV1, ProtectedContentBindingV1,
        ReplayNonce16, RightsActionV1, RightsObservationFinalityV1, RightsSubjectSourceV1,
        RuntimeSessionBindingV1, ShareCoordinateV1, ThresholdV1, WalletAddress,
    };

    fn wallet(seed: u8) -> WalletAddress {
        let key = WalletSigningKey::from_slice(&[seed; 32]).unwrap();
        let encoded = key.verifying_key().to_encoded_point(false);
        let digest = sha3::Keccak256::digest(&encoded.as_bytes()[1..]);
        WalletAddress::new(digest[12..].try_into().unwrap())
    }

    fn node_public_key(seed: u8) -> NodePublicKey {
        let key = SigningKey::from_bytes(&[seed; 32]);
        NodePublicKey::new(key.verifying_key().to_bytes()).unwrap()
    }

    fn custody_public_key(seed: u8) -> NodeCustodyPublicKeyV1 {
        crate::test_support::node_custody_public_key(seed)
    }

    fn signed_epoch() -> SignedCustodyEpochV1 {
        let issuer_key = SigningKey::from_bytes(&[0x71; 32]);
        let statement = CustodyEpochStatementV1::new(
            CustodyEpochIssuerKeyV1::new(issuer_key.verifying_key().to_bytes()).unwrap(),
            CustodyApprovedSuitesV1::new(
                crate::CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
                crate::CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
                crate::CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            )
            .unwrap(),
            ThresholdV1::new(2, 3).unwrap(),
            vec![
                CustodyNodeIdentityV1::new(
                    node_public_key(1),
                    custody_public_key(1),
                    ShareCoordinateV1::new(1).unwrap(),
                )
                .unwrap(),
                CustodyNodeIdentityV1::new(
                    node_public_key(2),
                    custody_public_key(2),
                    ShareCoordinateV1::new(2).unwrap(),
                )
                .unwrap(),
                CustodyNodeIdentityV1::new(
                    node_public_key(3),
                    custody_public_key(3),
                    ShareCoordinateV1::new(3).unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        SignedCustodyEpochV1::new(
            statement.clone(),
            issuer_key
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    fn envelope_for_epoch(custody_epoch: CustodyEpochIdentityV1) -> CustodyEnvelopeV1 {
        let manifest = crate::CustodyEnvelopeManifestV1::new(
            crate::EncryptedContentIdentityV1::new(digest(0x11), 4096).unwrap(),
            crate::CustodyPoolIdentityV1::new(digest(0x35), 512).unwrap(),
            custody_epoch,
            crate::CustodyCommitteeAuthorizationIdentityV1::new(digest(0x36), 512).unwrap(),
            ThresholdV1::new(2, 3).unwrap(),
            digest(0x19),
            vec![
                CustodyNodeIdentityV1::new(
                    node_public_key(1),
                    custody_public_key(1),
                    ShareCoordinateV1::new(1).unwrap(),
                )
                .unwrap(),
                CustodyNodeIdentityV1::new(
                    node_public_key(2),
                    custody_public_key(2),
                    ShareCoordinateV1::new(2).unwrap(),
                )
                .unwrap(),
                CustodyNodeIdentityV1::new(
                    node_public_key(3),
                    custody_public_key(3),
                    ShareCoordinateV1::new(3).unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let stored_share = crate::test_support::sealed_share(0x31);
        CustodyEnvelopeV1::new(
            manifest,
            vec![
                stored_share.clone(),
                stored_share.clone(),
                stored_share.clone(),
            ],
        )
        .unwrap()
    }

    fn policy_body() -> RightsPolicyBodyV1 {
        RightsPolicyBodyV1::new(
            crate::EncryptedContentIdentityV1::new(digest(0x11), 4096).unwrap(),
            crate::ContentAccessIdV1::new([0x41; 16]).unwrap(),
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

    fn binding() -> ProtectedContentBindingV1 {
        let encrypted_content = crate::EncryptedContentIdentityV1::new(digest(0x11), 4096).unwrap();
        let envelope = envelope_for_epoch(signed_epoch().epoch_identity().unwrap())
            .key_envelope_identity()
            .unwrap();
        let profile = SigningKey::from_bytes(&[0x26; 32]);
        let policy_body = policy_body();
        ProtectedContentBindingV1::new(
            encrypted_content,
            envelope,
            policy_body.policy_identity().unwrap(),
            ProfileIdentityV1::from_public_key_bytes(profile.verifying_key().to_bytes()).unwrap(),
            wallet(7),
            RuntimeSessionBindingV1::new(digest(0x66)).unwrap(),
        )
        .unwrap()
    }

    fn signed_operation() -> SignedRuntimeReleaseOperationV1 {
        let runtime_key = SigningKey::from_bytes(&[0x42; 32]);
        let recipient_public_key = crate::test_support::recipient_public_key_bytes(9);
        let binding = binding();
        let policy_body = policy_body();
        let rights_request = crate::RightsRequestV1::new(
            binding.clone(),
            RightsActionV1::View,
            recipient_public_key
                .key_identity(crate::CUSTODY_X_WING_AES256GCM_SUITE_ID_V1)
                .unwrap(),
            NOW,
            NOW + 180,
            ReplayNonce16::new([0x55; 16]),
        )
        .unwrap();
        let wallet_key = WalletSigningKey::from_slice(&[7; 32]).unwrap();
        let (wallet_signature, recovery_id) = wallet_key
            .sign_prehash_recoverable(&rights_request.signing_hash().unwrap())
            .unwrap();
        let mut wallet_signature_bytes = wallet_signature.to_bytes().to_vec();
        wallet_signature_bytes.push(recovery_id.to_byte());
        let rights_request =
            WalletSignedRightsRequestV1::new(rights_request, wallet_signature_bytes).unwrap();
        let release_request = KeyReleaseRequestV1::new(
            binding.clone(),
            rights_request.request().request_hash().unwrap(),
            RightsActionV1::View,
            rights_request.request().recipient().clone(),
            NOW + 1,
            NOW + 50,
            ReplayNonce16::new([0x66; 16]),
        )
        .unwrap();
        let profile = SigningKey::from_bytes(&[0x26; 32]);
        let authorization_statement = crate::RecipientKeyAuthorizationStatementV1::new(
            binding.clone(),
            RightsActionV1::View,
            recipient_public_key,
            rights_request.request().recipient().clone(),
            RuntimeOperationIssuerKeyV1::new(runtime_key.verifying_key().to_bytes()).unwrap(),
            NOW,
            NOW + 90,
        )
        .unwrap();
        let authorization = SignedRecipientKeyAuthorizationV1::new(
            authorization_statement.clone(),
            profile
                .sign(&authorization_statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        let statement = RuntimeReleaseOperationStatementV1::new(
            RuntimeOperationIssuerKeyV1::new(runtime_key.verifying_key().to_bytes()).unwrap(),
            rights_request,
            release_request,
            recipient_public_key,
            authorization,
            policy_body.clone(),
            RightsEvaluationEvidenceRequestV1::new(binding, policy_body.policy_identity().unwrap())
                .unwrap(),
            signed_epoch(),
            RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap(),
            NOW + 2,
            NOW + 40,
        )
        .unwrap();
        SignedRuntimeReleaseOperationV1::new(
            statement.clone(),
            runtime_key
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn runtime_release_operation_binds_exact_authority_hashes_and_replay_keys() {
        let operation = signed_operation();
        let authenticated = operation
            .verify(operation.statement().runtime_operation_issuer(), NOW + 3)
            .unwrap();
        // Moved 2026-09-22 with the readable signing format: this hash covers
        // the signed rights request, whose signature bytes changed when the
        // wallet began signing readable text instead of canonical bytes.
        assert_eq!(
            encode(authenticated.operation_hash().as_bytes()),
            "2ee287b35e150a48130aaa96886f09670d07c56fa314729c729294a94cc1337f"
        );
        assert_eq!(
            authenticated.rights_request_hash(),
            operation
                .statement()
                .rights_request()
                .request()
                .request_hash()
                .unwrap()
        );
        assert_eq!(
            authenticated.rights_request_replay_claim_key(),
            operation
                .statement()
                .rights_request()
                .request()
                .replay_claim_key()
                .unwrap()
        );
        assert_eq!(
            authenticated.release_request_replay_claim_key(),
            operation
                .statement()
                .release_request()
                .replay_claim_key()
                .unwrap()
        );
    }

    #[test]
    fn runtime_release_operation_exposes_exact_replay_keys_but_stays_non_actionable() {
        let operation = signed_operation();
        let authenticated = operation
            .verify(operation.statement().runtime_operation_issuer(), NOW + 3)
            .unwrap();
        assert_eq!(
            authenticated.release_request_hash(),
            operation
                .statement()
                .release_request()
                .request_hash()
                .unwrap()
        );
    }

    #[test]
    fn runtime_release_operation_claim_context_rejects_wrong_epoch_and_unknown_node() {
        let wrong_epoch = signed_operation()
            .verify(
                signed_operation().statement().runtime_operation_issuer(),
                NOW + 3,
            )
            .unwrap()
            .validate_node_release_claim_context(
                &envelope_for_epoch(CustodyEpochIdentityV1::new(digest(0xee), 512).unwrap()),
                node_public_key(1),
                NOW + 3,
            );
        assert!(matches!(
            wrong_epoch,
            Err(RuntimeReleaseOperationError::BindingMismatch(
                "key_envelope"
            ))
        ));

        let unknown_node = signed_operation()
            .verify(
                signed_operation().statement().runtime_operation_issuer(),
                NOW + 3,
            )
            .unwrap()
            .validate_node_release_claim_context(
                &envelope_for_epoch(signed_epoch().epoch_identity().unwrap()),
                NodePublicKey::new(
                    SigningKey::from_bytes(&[0x66; 32])
                        .verifying_key()
                        .to_bytes(),
                )
                .unwrap(),
                NOW + 3,
            );
        assert!(matches!(
            unknown_node,
            Err(RuntimeReleaseOperationError::BindingMismatch(
                "custody_node"
            ))
        ));
    }

    #[test]
    fn runtime_release_operation_rejects_invalid_wallet_signature_and_release_hash() {
        let operation = signed_operation();
        let mut wrong_rights = operation.statement().rights_request().clone();
        wrong_rights =
            WalletSignedRightsRequestV1::new(wrong_rights.request().clone(), vec![0; 65]).unwrap();
        let statement = RuntimeReleaseOperationStatementV1::new(
            operation.statement().runtime_operation_issuer(),
            wrong_rights,
            operation.statement().release_request().clone(),
            operation.statement().recipient_public_key(),
            operation.statement().recipient_authorization().clone(),
            operation.statement().policy_body().clone(),
            operation.statement().evidence_request().clone(),
            operation.statement().custody_epoch().clone(),
            operation.statement().audit_request_id(),
            operation.statement().issued_at(),
            operation.statement().expires_at(),
        )
        .unwrap();
        let runtime_key = SigningKey::from_bytes(&[0x42; 32]);
        let wrong = SignedRuntimeReleaseOperationV1::new(
            statement.clone(),
            runtime_key
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            wrong.verify(wrong.statement().runtime_operation_issuer(), NOW + 3),
            Err(RuntimeReleaseOperationError::Rights(
                RightsError::InvalidWalletSignature
            ))
        );

        let mut wrong_release = operation.statement().release_request().clone();
        wrong_release = KeyReleaseRequestV1::new(
            wrong_release.binding().clone(),
            digest(0xee),
            wrong_release.action(),
            wrong_release.recipient().clone(),
            wrong_release.issued_at(),
            wrong_release.expires_at(),
            wrong_release.replay_nonce(),
        )
        .unwrap();
        assert_eq!(
            RuntimeReleaseOperationStatementV1::new(
                operation.statement().runtime_operation_issuer(),
                operation.statement().rights_request().clone(),
                wrong_release,
                operation.statement().recipient_public_key(),
                operation.statement().recipient_authorization().clone(),
                operation.statement().policy_body().clone(),
                operation.statement().evidence_request().clone(),
                operation.statement().custody_epoch().clone(),
                operation.statement().audit_request_id(),
                operation.statement().issued_at(),
                operation.statement().expires_at(),
            ),
            Err(ContractError::InvalidField(
                "release_request.rights_request_hash"
            ))
        );
    }

    #[test]
    fn runtime_release_operation_rejects_wrong_policy_runtime_issuer_and_binding_mutations() {
        let operation = signed_operation();
        let wrong_policy = RightsPolicyBodyV1::new(
            crate::EncryptedContentIdentityV1::new(digest(0x22), 4096).unwrap(),
            crate::ContentAccessIdV1::new([0x42; 16]).unwrap(),
            RightsActionV1::View,
            RightsSubjectSourceV1::WalletAddress,
            11155111,
            EvmContractAddressV1::new([0x11; 20]).unwrap(),
            EvmFunctionSelectorV1::new([0x12, 0x34, 0x56, 0x78]).unwrap(),
            EvmRightsMethodAbiV1::HasAccessByContentIdAddressBytes16,
            RightsObservationFinalityV1::finalized(),
        )
        .unwrap();
        assert_eq!(
            RuntimeReleaseOperationStatementV1::new(
                operation.statement().runtime_operation_issuer(),
                operation.statement().rights_request().clone(),
                operation.statement().release_request().clone(),
                operation.statement().recipient_public_key(),
                operation.statement().recipient_authorization().clone(),
                wrong_policy,
                operation.statement().evidence_request().clone(),
                operation.statement().custody_epoch().clone(),
                operation.statement().audit_request_id(),
                operation.statement().issued_at(),
                operation.statement().expires_at(),
            ),
            Err(ContractError::InvalidField(
                "evidence_request.policy_identity"
            ))
        );

        let wrong_runtime_issuer = RuntimeOperationIssuerKeyV1::new(
            SigningKey::from_bytes(&[0x77; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        assert_eq!(
            RuntimeReleaseOperationStatementV1::new(
                wrong_runtime_issuer,
                operation.statement().rights_request().clone(),
                operation.statement().release_request().clone(),
                operation.statement().recipient_public_key(),
                operation.statement().recipient_authorization().clone(),
                operation.statement().policy_body().clone(),
                operation.statement().evidence_request().clone(),
                operation.statement().custody_epoch().clone(),
                operation.statement().audit_request_id(),
                operation.statement().issued_at(),
                operation.statement().expires_at(),
            ),
            Err(ContractError::InvalidField(
                "recipient_authorization.runtime_operation_issuer"
            ))
        );

        let mut wrong_binding = operation
            .statement()
            .rights_request()
            .request()
            .binding()
            .clone();
        wrong_binding = ProtectedContentBindingV1::new(
            wrong_binding.encrypted_content().clone(),
            wrong_binding.key_envelope().clone(),
            wrong_binding.rights_policy().clone(),
            wrong_binding.profile(),
            wrong_binding.wallet(),
            RuntimeSessionBindingV1::new(digest(0xaa)).unwrap(),
        )
        .unwrap();
        let wrong_release = KeyReleaseRequestV1::new(
            wrong_binding.clone(),
            operation
                .statement()
                .release_request()
                .rights_request_hash(),
            operation.statement().release_request().action(),
            operation.statement().release_request().recipient().clone(),
            operation.statement().release_request().issued_at(),
            operation.statement().release_request().expires_at(),
            operation.statement().release_request().replay_nonce(),
        )
        .unwrap();
        assert_eq!(
            RuntimeReleaseOperationStatementV1::new(
                operation.statement().runtime_operation_issuer(),
                operation.statement().rights_request().clone(),
                wrong_release,
                operation.statement().recipient_public_key(),
                operation.statement().recipient_authorization().clone(),
                operation.statement().policy_body().clone(),
                operation.statement().evidence_request().clone(),
                operation.statement().custody_epoch().clone(),
                operation.statement().audit_request_id(),
                operation.statement().issued_at(),
                operation.statement().expires_at(),
            ),
            Err(ContractError::InvalidField("release_request.binding"))
        );
    }

    #[test]
    fn runtime_release_operation_rejects_wrong_recipient_authorization_and_epoch_suite() {
        let operation = signed_operation();
        let wrong_recipient_public_key = crate::test_support::recipient_public_key_bytes(0x21);
        assert_eq!(
            RuntimeReleaseOperationStatementV1::new(
                operation.statement().runtime_operation_issuer(),
                operation.statement().rights_request().clone(),
                operation.statement().release_request().clone(),
                wrong_recipient_public_key,
                operation.statement().recipient_authorization().clone(),
                operation.statement().policy_body().clone(),
                operation.statement().evidence_request().clone(),
                operation.statement().custody_epoch().clone(),
                operation.statement().audit_request_id(),
                operation.statement().issued_at(),
                operation.statement().expires_at(),
            ),
            Err(ContractError::InvalidField(
                "recipient_authorization.recipient_public_key"
            ))
        );

        let mut wrong_epoch = operation.statement().custody_epoch().clone();
        let mut canonical = wrong_epoch.canonical_bytes().unwrap();
        *canonical.last_mut().unwrap() ^= 1;
        wrong_epoch = SignedCustodyEpochV1::from_canonical_bytes(&canonical).unwrap();
        let statement = RuntimeReleaseOperationStatementV1::new(
            operation.statement().runtime_operation_issuer(),
            operation.statement().rights_request().clone(),
            operation.statement().release_request().clone(),
            operation.statement().recipient_public_key(),
            operation.statement().recipient_authorization().clone(),
            operation.statement().policy_body().clone(),
            operation.statement().evidence_request().clone(),
            wrong_epoch,
            operation.statement().audit_request_id(),
            operation.statement().issued_at(),
            operation.statement().expires_at(),
        )
        .unwrap();
        let runtime_key = SigningKey::from_bytes(&[0x42; 32]);
        let wrong = SignedRuntimeReleaseOperationV1::new(
            statement.clone(),
            runtime_key
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            wrong.verify(wrong.statement().runtime_operation_issuer(), NOW + 3),
            Err(RuntimeReleaseOperationError::CustodyEpoch(
                CustodyEpochError::InvalidIssuerSignature
            ))
        );
    }

    #[test]
    fn runtime_release_operation_rejects_wrong_expected_runtime_issuer() {
        let operation = signed_operation();
        let wrong_runtime_issuer = RuntimeOperationIssuerKeyV1::new(
            SigningKey::from_bytes(&[0x77; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        assert_eq!(
            operation.verify(wrong_runtime_issuer, NOW + 3),
            Err(RuntimeReleaseOperationError::BindingMismatch(
                "runtime_operation_issuer"
            ))
        );
    }

    #[test]
    fn runtime_release_operation_decode_rejects_trailing_bytes() {
        let operation = signed_operation();
        let mut trailing = operation.canonical_bytes().unwrap();
        trailing.push(0);
        assert_eq!(
            SignedRuntimeReleaseOperationV1::from_canonical_bytes(&trailing),
            Err(ContractError::TrailingBytes)
        );
    }

    /// E5 guard: T1.1 adds V2 types beside V1 and changes no V1 byte. The
    /// statement hash is the existing golden above; the signed bytes are
    /// pinned here.
    #[test]
    fn operation_v1_bytes_unchanged() {
        // sha256 of `signed_operation().canonical_bytes()`, computed on the
        // unchanged V1 tree before T1.1.
        const SIGNED_OPERATION_V1_SHA256: &str =
            "e7b78574c30d80964540ccb728687c730741b6a297202f665fcf2491dc378f7a";
        let operation = signed_operation();
        let bytes = operation.canonical_bytes().unwrap();
        assert_eq!(
            encode(sha2::Sha256::digest(&bytes)),
            SIGNED_OPERATION_V1_SHA256
        );
        assert_eq!(
            encode(operation.statement().canonical_hash().unwrap().as_bytes()),
            "2ee287b35e150a48130aaa96886f09670d07c56fa314729c729294a94cc1337f"
        );
        assert_eq!(
            SignedRuntimeReleaseOperationV1::from_canonical_bytes(&bytes).unwrap(),
            operation
        );
    }

    /// ADV-01 V-OP, appended 2026-11-12: the `pool_release_fixture` default
    /// spec at `NOW` with this module's policy. The V1 goldens above stay as
    /// they are.
    ///
    /// Both values were pinned from the Rust build, which alone derives the
    /// X-Wing fixture keys, and checked with an external SHA-256 over the
    /// printed canonical bytes (statement 16,889 bytes, operation 17,012).
    ///
    /// Item 10: this vector nests the historical `/v1` descriptor, so the
    /// spec asks the fixture for it; the values stay byte-for-byte. #388-2:
    /// and the historical v1 recipient attestations.
    #[test]
    fn operation_v2_vector_v_op() {
        let mut spec = crate::test_fixtures::PoolReleaseSpecV1::new(
            crate::test_support::xwing_public_key_bytes,
            policy_body(),
            NOW,
        );
        spec.v1_descriptor = true;
        spec.v1_attestations = true;
        let fixture = crate::test_fixtures::pool_release_fixture(&spec);
        let operation = &fixture.operation;
        let bytes = operation.canonical_bytes().unwrap();
        assert_eq!(
            SignedRuntimeReleaseOperationV2::from_canonical_bytes(&bytes).unwrap(),
            *operation
        );
        assert_eq!(
            encode(operation.statement().canonical_hash().unwrap().as_bytes()),
            "0cf894278e757a9a140486f0d2df67951ea1b1245261e83146e24a0785561fd7",
            "V-OP statement canonical_hash"
        );
        assert_eq!(
            encode(sha2::Sha256::digest(&bytes)),
            "e8d452cc9581d091b26307f952df839a0b6cccfb6fadd7854d48bc68fb2ce2ac",
            "V-OP signed operation sha256"
        );
    }

    /// Item 10 V-OP-2, appended 2026-11-12: the same default spec, whose
    /// fixture now nests a ticketless `/v2` descriptor. The statement keeps
    /// its `/v2` domain and grammar; only the nested descriptor differs.
    ///
    /// Both values were pinned from the Mac build, reproduced on two runs and
    /// checked with an external SHA-256 over the printed canonical bytes
    /// (statement 16,886 bytes, operation 17,009).
    ///
    /// #388 A2: writers now emit v3 descriptors and v2 attestations, so the
    /// spec asks for the historical v2 descriptor and v1 attestations; the
    /// values stay byte-for-byte.
    #[test]
    fn operation_v2_vector_v_op_with_v2_descriptor() {
        let mut spec = crate::test_fixtures::PoolReleaseSpecV1::new(
            crate::test_support::xwing_public_key_bytes,
            policy_body(),
            NOW,
        );
        spec.v2_descriptor = true;
        spec.v1_attestations = true;
        let fixture = crate::test_fixtures::pool_release_fixture(&spec);
        assert!(matches!(
            fixture.operation.statement().pool_descriptor(),
            crate::SignedPoolDescriptorAnyV1::V2(_)
        ));
        let operation = &fixture.operation;
        let bytes = operation.canonical_bytes().unwrap();
        assert_eq!(
            SignedRuntimeReleaseOperationV2::from_canonical_bytes(&bytes).unwrap(),
            *operation
        );
        assert_eq!(
            encode(operation.statement().canonical_hash().unwrap().as_bytes()),
            "62f54c156b09677d9720b834e461c3aa6605a44c6bd628f80c8059eb674429a2",
            "V-OP-2 statement canonical_hash"
        );
        assert_eq!(
            encode(sha2::Sha256::digest(&bytes)),
            "95775f58a2d1cfb1cf18e38a4ea06e2af9d69a2102e19650088af3867245765a",
            "V-OP-2 signed operation sha256"
        );
    }

    /// #388 A2 V-OP-3, appended 2026-11-13: the default spec, whose fixture
    /// now nests a v3 descriptor (`WciOperated`, slots empty) and v2 recipient
    /// attestations. The statement keeps its `/v2` domain and framing; only
    /// the nested children differ.
    ///
    /// Both values pinned from the Mac build on two runs; the operation's
    /// SHA-256 checked with an external `shasum`.
    #[test]
    fn operation_v2_vector_v_op_with_v3_descriptor_and_v2_attestations() {
        let fixture = crate::test_fixtures::pool_release_fixture(
            &crate::test_fixtures::PoolReleaseSpecV1::new(
                crate::test_support::xwing_public_key_bytes,
                policy_body(),
                NOW,
            ),
        );
        assert!(matches!(
            fixture.operation.statement().pool_descriptor(),
            crate::SignedPoolDescriptorAnyV1::V3(_)
        ));
        assert!(fixture
            .operation
            .statement()
            .recipients()
            .iter()
            .all(|recipient| matches!(
                recipient.attestation(),
                crate::SignedPoolRecipientAttestationAnyV1::V2(_)
            )));
        let operation = &fixture.operation;
        let bytes = operation.canonical_bytes().unwrap();
        assert_eq!(
            SignedRuntimeReleaseOperationV2::from_canonical_bytes(&bytes).unwrap(),
            *operation
        );
        fixture.authenticated();
        assert_eq!(
            encode(operation.statement().canonical_hash().unwrap().as_bytes()),
            "3c1b29acf98ad468e3a24b4985950809a06b1f0ffeae8a1b4b91e9c38a4853f1",
            "V-OP-3 statement canonical_hash"
        );
        assert_eq!(
            encode(sha2::Sha256::digest(&bytes)),
            "5c5a430f4bd339a77196ca569f80872959ad5343f54f0fe6828f2259d3b923dc",
            "V-OP-3 signed operation sha256"
        );
    }

    #[test]
    fn operation_any_decodes_v1_bytes_as_the_same_v1_operation() {
        let operation = signed_operation();
        let bytes = operation.canonical_bytes().unwrap();
        match RuntimeReleaseOperationAnyV1::from_canonical_bytes(&bytes).unwrap() {
            RuntimeReleaseOperationAnyV1::V1(decoded) => {
                assert_eq!(decoded, operation);
                assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
            }
            RuntimeReleaseOperationAnyV1::V2(_) => panic!("V1 bytes decoded as V2"),
        }
    }

    #[test]
    fn authenticated_any_v1_arm_returns_the_v1_values() {
        let operation = signed_operation();
        let authenticated = operation
            .verify(operation.statement().runtime_operation_issuer(), NOW + 3)
            .unwrap();
        let any = AuthenticatedRuntimeReleaseOperationAnyV1::V1(authenticated.clone());
        assert_eq!(any.as_v1(), Some(&authenticated));
        assert!(any.as_v2().is_none());
        assert_eq!(any.operation_hash(), authenticated.operation_hash());
        assert_eq!(
            any.release_request_hash(),
            authenticated.release_request_hash()
        );
        assert_eq!(
            any.rights_request_hash(),
            authenticated.rights_request_hash()
        );
        assert_eq!(any.binding(), authenticated.binding());
        assert_eq!(any.action(), authenticated.action());
        assert_eq!(
            any.audit_request_id(),
            operation.statement().audit_request_id()
        );
        assert_eq!(any.expires_at(), operation.statement().expires_at());
        assert_eq!(
            any.rights_expires_at(),
            operation.statement().release_request().expires_at()
        );
        let node_set = signed_epoch().statement().node_set().unwrap();
        assert_eq!(any.node_set().unwrap(), node_set);

        let statement = crate::NodeRightsDecisionStatementV1::new(
            authenticated.release_request_hash(),
            authenticated.rights_request_hash(),
            authenticated.binding().clone(),
            RightsActionV1::View,
            node_public_key(1),
            crate::RightsDecisionV1::Allowed,
            digest(0x90),
            NOW + 3,
            NOW + 30,
        )
        .unwrap();
        let decision = SignedNodeRightsDecisionV1::new(
            statement.clone(),
            SigningKey::from_bytes(&[1; 32])
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        let direct = authenticated
            .verify_node_rights_decision(&decision, &node_set, NOW + 4)
            .unwrap();
        assert_eq!(
            any.verify_node_rights_decision(&decision, &node_set, NOW + 4),
            Ok(direct)
        );
    }
}

//! A proposed successor configuration. Accepting these bytes for review or
//! staging grants no authority to switch new provisioning to the successor.

use ed25519_dalek::Signature;

use crate::canonical::{validate_ascii_identifier, CanonicalBody, Decoder, Encoder};
use crate::identity::validate_ed25519_public_key;
use crate::rights::{validate_active, validate_time_window};
use crate::{
    CanonicalContract, ContractError, CustodyEpochIdentityV1, CustodyEpochIssuerKeyV1, Digest32,
    NodeCustodyPublicKeyV1, NodePublicKey, PoolContractError, PoolDidV1, RightsError,
    SignedPoolDescriptorV3, MAX_POOL_MEMBER_PEER_DID_BYTES_V1,
};

const MAX_PROPOSAL_LIFETIME_SECS: u64 = 86_400;
const MAX_READINESS_LIFETIME_SECS: u64 = 300;

/// Member consent and owner approval must cite the same complete proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolRolloverProposalV1 {
    pub pool: PoolDidV1,
    pub predecessor_sequence: u64,
    pub predecessor_digest: Digest32,
    pub candidate_descriptor_digest: Digest32,
    pub candidate_composition_digest: Digest32,
    pub provisioning_epoch: CustodyEpochIdentityV1,
    pub operation_id: [u8; 16],
    pub issued_at: u64,
    pub expires_at: u64,
}

impl CanonicalBody for PoolRolloverProposalV1 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-rollover-proposal-statement/v1";

    fn validate(&self) -> Result<(), ContractError> {
        if self.predecessor_sequence == 0 || self.operation_id == [0; 16] {
            return Err(ContractError::InvalidField(
                "pool_rollover.predecessor_or_operation",
            ));
        }
        self.provisioning_epoch.canonical_bytes()?;
        validate_time_window(
            self.issued_at,
            self.expires_at,
            MAX_PROPOSAL_LIFETIME_SECS,
            "pool_rollover.window",
        )
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.fixed(self.pool.issuer().as_bytes());
        encoder.u64(self.predecessor_sequence);
        encoder.fixed(self.predecessor_digest.as_bytes());
        encoder.fixed(self.candidate_descriptor_digest.as_bytes());
        encoder.fixed(self.candidate_composition_digest.as_bytes());
        encoder.nested(&self.provisioning_epoch)?;
        encoder.fixed(&self.operation_id);
        encoder.u64(self.issued_at);
        encoder.u64(self.expires_at);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            pool: PoolDidV1::from_issuer(CustodyEpochIssuerKeyV1::new(decoder.fixed()?)?),
            predecessor_sequence: decoder.u64()?,
            predecessor_digest: Digest32::new(decoder.fixed()?),
            candidate_descriptor_digest: Digest32::new(decoder.fixed()?),
            candidate_composition_digest: Digest32::new(decoder.fixed()?),
            provisioning_epoch: decoder.nested("pool_rollover.provisioning_epoch")?,
            operation_id: decoder.fixed()?,
            issued_at: decoder.u64()?,
            expires_at: decoder.u64()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPoolRolloverProposalV1 {
    statement: PoolRolloverProposalV1,
    signature: [u8; 64],
}

impl SignedPoolRolloverProposalV1 {
    pub fn new(
        statement: PoolRolloverProposalV1,
        signature: [u8; 64],
    ) -> Result<Self, ContractError> {
        CanonicalBody::validate(&statement)?;
        Ok(Self {
            statement,
            signature,
        })
    }

    /// Verify against the actual current head and the exact staged candidate.
    /// The composition digest is independently calculated from staged bytes.
    pub fn verify(
        &self,
        predecessor: &SignedPoolDescriptorV3,
        candidate: &SignedPoolDescriptorV3,
        composition_digest: Digest32,
        now: u64,
    ) -> Result<&PoolRolloverProposalV1, PoolContractError> {
        let statement = &self.statement;
        if predecessor.statement().pool() != &statement.pool
            || candidate.statement().pool() != &statement.pool
        {
            return Err(PoolContractError::IssuerMismatch);
        }
        let key = validate_ed25519_public_key(
            *statement.pool.issuer().as_bytes(),
            "pool_rollover_authority",
        )
        .map_err(|_| PoolContractError::Signature)?;
        key.verify_strict(
            &statement.canonical_bytes()?,
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| PoolContractError::Signature)?;
        validate_active(statement.issued_at, statement.expires_at, now).map_err(
            |error| match error {
                RightsError::NotYetValid => PoolContractError::NotYetValid,
                _ => PoolContractError::Expired,
            },
        )?;
        predecessor.verify(now)?.admits_new_release()?;
        candidate.verify(now)?.admits_new_release()?;
        if statement.predecessor_sequence != predecessor.statement().sequence()
            || statement.predecessor_digest != predecessor.canonical_hash()?
            || statement.predecessor_sequence.checked_add(1)
                != Some(candidate.statement().sequence())
            || statement.candidate_descriptor_digest != candidate.canonical_hash()?
            || statement.candidate_composition_digest != composition_digest
            || statement.expires_at
                > candidate
                    .statement()
                    .expires_at()
                    .min(predecessor.statement().expires_at())
        {
            return Err(ContractError::InvalidField("pool_rollover.candidate_binding").into());
        }
        if !candidate.preserves_serving_history(predecessor)
            || candidate.statement().epochs().len() != predecessor.statement().epochs().len() + 1
            || predecessor.statement().epochs().iter().any(|bundle| {
                bundle
                    .epoch_identity()
                    .is_ok_and(|epoch| epoch == statement.provisioning_epoch)
            })
        {
            return Err(ContractError::InvalidField("pool_rollover.serving_history").into());
        }
        let selected = candidate
            .statement()
            .epochs()
            .iter()
            .find(|bundle| {
                bundle
                    .epoch_identity()
                    .is_ok_and(|epoch| epoch == statement.provisioning_epoch)
            })
            .ok_or(PoolContractError::EpochMismatch)?;
        selected.validate_for_provisioning(statement.pool.issuer(), now)?;
        Ok(statement)
    }
}

impl CanonicalBody for SignedPoolRolloverProposalV1 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-rollover-proposal/v1";

    fn validate(&self) -> Result<(), ContractError> {
        CanonicalBody::validate(&self.statement)
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.statement)?;
        encoder.fixed(&self.signature);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(decoder.nested("pool_rollover_proposal")?, decoder.fixed()?)
    }
}

/// A running member signs this after checking that its staged state is
/// durable and that its previous serving state and both loaded keys agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolRolloverReadinessV1 {
    pub proposal_digest: Digest32,
    pub node: NodePublicKey,
    pub custody_key: NodeCustodyPublicKeyV1,
    pub peer_did: String,
    pub staged_state_digest: Digest32,
    pub provider_binary_digest: Digest32,
    pub generation: [u8; 16],
    pub challenge: [u8; 16],
    pub issued_at: u64,
    pub expires_at: u64,
}

impl CanonicalBody for PoolRolloverReadinessV1 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-rollover-readiness-statement/v1";

    fn validate(&self) -> Result<(), ContractError> {
        if self.generation == [0; 16] || self.challenge == [0; 16] {
            return Err(ContractError::InvalidField(
                "pool_rollover_readiness.generation_or_challenge",
            ));
        }
        validate_ascii_identifier(
            &self.peer_did,
            "pool_rollover_readiness.peer_did",
            MAX_POOL_MEMBER_PEER_DID_BYTES_V1,
        )?;
        validate_time_window(
            self.issued_at,
            self.expires_at,
            MAX_READINESS_LIFETIME_SECS,
            "pool_rollover_readiness.window",
        )
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.fixed(self.proposal_digest.as_bytes());
        encoder.fixed(self.node.as_bytes());
        encoder.fixed(self.custody_key.as_bytes());
        encoder.string(&self.peer_did)?;
        encoder.fixed(self.staged_state_digest.as_bytes());
        encoder.fixed(self.provider_binary_digest.as_bytes());
        encoder.fixed(&self.generation);
        encoder.fixed(&self.challenge);
        encoder.u64(self.issued_at);
        encoder.u64(self.expires_at);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Ok(Self {
            proposal_digest: Digest32::new(decoder.fixed()?),
            node: NodePublicKey::new(decoder.fixed()?)?,
            custody_key: NodeCustodyPublicKeyV1::new(decoder.fixed()?)?,
            peer_did: decoder.string(
                "pool_rollover_readiness.peer_did",
                MAX_POOL_MEMBER_PEER_DID_BYTES_V1,
            )?,
            staged_state_digest: Digest32::new(decoder.fixed()?),
            provider_binary_digest: Digest32::new(decoder.fixed()?),
            generation: decoder.fixed()?,
            challenge: decoder.fixed()?,
            issued_at: decoder.u64()?,
            expires_at: decoder.u64()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPoolRolloverReadinessV1 {
    statement: PoolRolloverReadinessV1,
    signature: [u8; 64],
}

impl SignedPoolRolloverReadinessV1 {
    pub fn new(
        statement: PoolRolloverReadinessV1,
        signature: [u8; 64],
    ) -> Result<Self, ContractError> {
        CanonicalBody::validate(&statement)?;
        Ok(Self {
            statement,
            signature,
        })
    }
}

impl CanonicalBody for SignedPoolRolloverReadinessV1 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-rollover-readiness/v1";

    fn validate(&self) -> Result<(), ContractError> {
        CanonicalBody::validate(&self.statement)
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.statement)?;
        encoder.fixed(&self.signature);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(decoder.nested("pool_rollover_readiness")?, decoder.fixed()?)
    }
}

/// A member's decision uses a domain distinct from setup consent and
/// provider readiness. The proposal digest commits to its assigned role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolRolloverConsentV1 {
    pub proposal_digest: Digest32,
    pub node: NodePublicKey,
    pub approved: bool,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl CanonicalBody for PoolRolloverConsentV1 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-rollover-consent-statement/v1";

    fn validate(&self) -> Result<(), ContractError> {
        validate_time_window(
            self.issued_at,
            self.expires_at,
            MAX_PROPOSAL_LIFETIME_SECS,
            "pool_rollover_consent.window",
        )
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.fixed(self.proposal_digest.as_bytes());
        encoder.fixed(self.node.as_bytes());
        encoder.u8(u8::from(self.approved));
        encoder.u64(self.issued_at);
        encoder.u64(self.expires_at);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        let proposal_digest = Digest32::new(decoder.fixed()?);
        let node = NodePublicKey::new(decoder.fixed()?)?;
        let approved = match decoder.u8()? {
            0 => false,
            1 => true,
            _ => {
                return Err(ContractError::InvalidField(
                    "pool_rollover_consent.decision",
                ))
            }
        };
        Ok(Self {
            proposal_digest,
            node,
            approved,
            issued_at: decoder.u64()?,
            expires_at: decoder.u64()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPoolRolloverConsentV1 {
    statement: PoolRolloverConsentV1,
    signature: [u8; 64],
}

impl SignedPoolRolloverConsentV1 {
    pub fn statement(&self) -> &PoolRolloverConsentV1 {
        &self.statement
    }

    pub fn new(
        statement: PoolRolloverConsentV1,
        signature: [u8; 64],
    ) -> Result<Self, ContractError> {
        CanonicalBody::validate(&statement)?;
        Ok(Self {
            statement,
            signature,
        })
    }

    fn verify_binding(
        &self,
        proposal: &PoolRolloverProposalV1,
        proposal_digest: Digest32,
        node: NodePublicKey,
        now: u64,
    ) -> Result<&PoolRolloverConsentV1, PoolContractError> {
        let consent = &self.statement;
        if consent.node != node
            || consent.proposal_digest != proposal_digest
            || consent.issued_at < proposal.issued_at
            || consent.expires_at > proposal.expires_at
        {
            return Err(ContractError::InvalidField("pool_rollover_consent.binding").into());
        }
        validate_active(consent.issued_at, consent.expires_at, now).map_err(
            |error| match error {
                RightsError::NotYetValid => PoolContractError::NotYetValid,
                _ => PoolContractError::Expired,
            },
        )?;
        let key = validate_ed25519_public_key(*node.as_bytes(), "pool_rollover_consent_node")
            .map_err(|_| PoolContractError::Signature)?;
        key.verify_strict(
            &consent.canonical_bytes()?,
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| PoolContractError::Signature)?;
        Ok(consent)
    }
}

impl SignedPoolRolloverProposalV1 {
    /// Verify a selected member's decision before retaining it, including a
    /// signed refusal. The caller verifies transport authorship separately.
    pub fn verify_member_consent<'a>(
        &self,
        predecessor: &SignedPoolDescriptorV3,
        candidate: &SignedPoolDescriptorV3,
        composition_digest: Digest32,
        consent: &'a SignedPoolRolloverConsentV1,
        now: u64,
    ) -> Result<&'a PoolRolloverConsentV1, PoolContractError> {
        let proposal = self.verify(predecessor, candidate, composition_digest, now)?;
        let node = consent.statement.node;
        if !candidate.statement().epochs().iter().any(|bundle| {
            bundle
                .epoch_identity()
                .is_ok_and(|identity| identity == proposal.provisioning_epoch)
                && bundle
                    .signed_epoch()
                    .statement()
                    .nodes()
                    .iter()
                    .any(|entry| entry.node_public_key() == node)
        }) {
            return Err(PoolContractError::NotMember);
        }
        consent.verify_binding(proposal, self.canonical_hash()?, node, now)
    }
}

impl CanonicalBody for SignedPoolRolloverConsentV1 {
    const DOMAIN: &'static str = "elastos.protected-content.pool-rollover-consent/v1";

    fn validate(&self) -> Result<(), ContractError> {
        CanonicalBody::validate(&self.statement)
    }

    fn encode_fields(&self, encoder: &mut Encoder) -> Result<(), ContractError> {
        encoder.nested(&self.statement)?;
        encoder.fixed(&self.signature);
        Ok(())
    }

    fn decode_fields(decoder: &mut Decoder<'_>) -> Result<Self, ContractError> {
        Self::new(decoder.nested("pool_rollover_consent")?, decoder.fixed()?)
    }
}

/// Facts held by the coordinator, independent of the reply. The coordinator
/// owns peer authentication, WCI admission, and single-use challenge state.
#[derive(Clone, Copy)]
pub struct ExpectedPoolRolloverReadinessV1<'a> {
    pub authenticated_peer_did: &'a str,
    pub staged_state_digest: Digest32,
    pub provider_binary_digest: Digest32,
    pub generation: [u8; 16],
    pub challenge: [u8; 16],
    pub challenge_issued_at: u64,
    pub challenge_expires_at: u64,
}

#[derive(Clone)]
pub struct PoolRolloverMemberEvidenceV1<'a> {
    pub expected: ExpectedPoolRolloverReadinessV1<'a>,
    pub consent: SignedPoolRolloverConsentV1,
    pub readiness: SignedPoolRolloverReadinessV1,
}

impl SignedPoolRolloverProposalV1 {
    /// Require evidence from every selected provisioning node. This verifies
    /// the signed evidence only. The coordinator checks for subsequent
    /// refusals, consumes the challenges and commits the result.
    pub fn verify_member_evidence(
        &self,
        predecessor: &SignedPoolDescriptorV3,
        candidate: &SignedPoolDescriptorV3,
        composition_digest: Digest32,
        evidence: &[PoolRolloverMemberEvidenceV1<'_>],
        now: u64,
    ) -> Result<(), PoolContractError> {
        let proposal = self.verify(predecessor, candidate, composition_digest, now)?;
        let proposal_digest = self.canonical_hash()?;
        let candidate = candidate.statement();
        let bundle = candidate
            .epochs()
            .iter()
            .find(|bundle| {
                bundle
                    .epoch_identity()
                    .is_ok_and(|epoch| epoch == proposal.provisioning_epoch)
            })
            .ok_or(PoolContractError::EpochMismatch)?;
        let nodes = bundle.signed_epoch().statement().nodes();
        if nodes.len() != evidence.len() {
            return Err(ContractError::InvalidField("pool_rollover_readiness.count").into());
        }
        for node in nodes {
            let evidence = evidence
                .iter()
                .find(|record| record.readiness.statement.node == node.node_public_key())
                .ok_or(PoolContractError::NotMember)?;
            let expected = &evidence.expected;
            let member = candidate
                .members()
                .iter()
                .find(|member| member.node_public_key() == node.node_public_key())
                .ok_or(PoolContractError::NotMember)?;
            let reply = &evidence.readiness.statement;
            let consent = evidence.consent.verify_binding(
                proposal,
                proposal_digest,
                node.node_public_key(),
                now,
            )?;
            if !consent.approved
                || reply.issued_at < consent.issued_at
                || reply.expires_at > consent.expires_at
            {
                return Err(ContractError::InvalidField("pool_rollover_consent.binding").into());
            }
            if reply.proposal_digest != proposal_digest
                || reply.custody_key != node.custody_public_key()
                || reply.peer_did != member.route().peer_did()
                || reply.peer_did != expected.authenticated_peer_did
                || reply.staged_state_digest != expected.staged_state_digest
                || reply.provider_binary_digest != expected.provider_binary_digest
                || reply.generation != expected.generation
                || reply.challenge != expected.challenge
                || reply.issued_at < expected.challenge_issued_at
                || reply.expires_at > expected.challenge_expires_at.min(proposal.expires_at)
                || now >= reply.expires_at
                || now < expected.challenge_issued_at
            {
                return Err(ContractError::InvalidField("pool_rollover_readiness.binding").into());
            }
            validate_active(reply.issued_at, reply.expires_at, now).map_err(
                |error| match error {
                    RightsError::NotYetValid => PoolContractError::NotYetValid,
                    _ => PoolContractError::Expired,
                },
            )?;
            let key = validate_ed25519_public_key(*reply.node.as_bytes(), "pool_rollover_node")
                .map_err(|_| PoolContractError::Signature)?;
            key.verify_strict(
                &reply.canonical_bytes()?,
                &Signature::from_bytes(&evidence.readiness.signature),
            )
            .map_err(|_| PoolContractError::Signature)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{
        node_public_key, pool_bundle, pool_descriptor_signed_by, signing_key, POOL_AUTHORITY_SEED,
    };
    use crate::test_support::{xwing_public_key_bytes, NOW};
    use crate::PoolDescriptorStatementV3;
    use ed25519_dalek::Signer as _;

    #[test]
    fn proposal_binds_complete_candidate_head_and_selected_epoch() {
        let prior_bundle = pool_bundle(xwing_public_key_bytes, NOW);
        let next_bundle = pool_bundle(|seed| xwing_public_key_bytes(seed + 8), NOW);
        let prior = pool_descriptor_signed_by(&prior_bundle, 3, NOW, POOL_AUTHORITY_SEED);
        let key = signing_key(POOL_AUTHORITY_SEED);
        let statement = prior.statement();
        let successor = |epochs, serve| {
            let candidate = PoolDescriptorStatementV3::new(
                *statement.pool(),
                4,
                epochs,
                statement.members().to_vec(),
                serve,
                statement.mint_policy().clone(),
                statement.issued_at(),
                statement.expires_at(),
                statement.trust_mode(),
            )
            .unwrap();
            let signature = key
                .sign(&candidate.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec();
            SignedPoolDescriptorV3::new(candidate, signature).unwrap()
        };
        let history = vec![prior_bundle.clone(), next_bundle.clone()];
        let candidate = successor(history.clone(), *statement.serve_policy());
        let composition_digest = Digest32::new([0x22; 32]);
        let proposal = PoolRolloverProposalV1 {
            pool: *statement.pool(),
            predecessor_sequence: 3,
            predecessor_digest: prior.canonical_hash().unwrap(),
            candidate_descriptor_digest: candidate.canonical_hash().unwrap(),
            candidate_composition_digest: composition_digest,
            provisioning_epoch: next_bundle.epoch_identity().unwrap(),
            operation_id: [0x34; 16],
            issued_at: NOW,
            expires_at: NOW + 300,
        };
        let sign = |proposal: PoolRolloverProposalV1| {
            let signature = key.sign(&proposal.canonical_bytes().unwrap()).to_bytes();
            SignedPoolRolloverProposalV1::new(proposal, signature).unwrap()
        };
        let signed = sign(proposal.clone());
        let encoded = signed.canonical_bytes().unwrap();
        let decoded = SignedPoolRolloverProposalV1::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(
            decoded.verify(&prior, &candidate, composition_digest, NOW),
            Ok(&proposal)
        );
        let wrong_composition = Digest32::new([0x23; 32]);
        assert!(decoded
            .verify(&prior, &candidate, wrong_composition, NOW)
            .is_err());
        assert!(decoded
            .verify(&candidate, &candidate, composition_digest, NOW)
            .is_err());
        assert_eq!(
            decoded.verify(&prior, &candidate, composition_digest, proposal.expires_at),
            Err(PoolContractError::Expired)
        );

        let mut changed_policy = *statement.serve_policy();
        changed_policy.max_servers_per_session = 2;
        let different_candidate = successor(history, changed_policy);
        assert_ne!(different_candidate, candidate);
        assert!(decoded
            .verify(&prior, &different_candidate, composition_digest, NOW)
            .is_err());

        let old_selection = sign(PoolRolloverProposalV1 {
            provisioning_epoch: prior_bundle.epoch_identity().unwrap(),
            ..proposal.clone()
        });
        assert!(old_selection
            .verify(&prior, &candidate, composition_digest, NOW)
            .is_err());

        let mut evidence = Vec::new();
        for node in next_bundle.signed_epoch().statement().nodes() {
            let node_key = node.node_public_key();
            let seed = (1..=3)
                .find(|seed| node_public_key(*seed) == node_key)
                .unwrap();
            let peer_did = candidate
                .statement()
                .members()
                .iter()
                .find(|member| member.node_public_key() == node_key)
                .unwrap()
                .route()
                .peer_did();
            let expected = ExpectedPoolRolloverReadinessV1 {
                authenticated_peer_did: peer_did,
                staged_state_digest: Digest32::new([seed; 32]),
                provider_binary_digest: Digest32::new([0x74; 32]),
                generation: [seed; 16],
                challenge: [seed + 5; 16],
                challenge_issued_at: NOW,
                challenge_expires_at: NOW + 60,
            };
            let reply = PoolRolloverReadinessV1 {
                proposal_digest: decoded.canonical_hash().unwrap(),
                node: node_key,
                custody_key: node.custody_public_key(),
                peer_did: peer_did.into(),
                staged_state_digest: expected.staged_state_digest,
                provider_binary_digest: expected.provider_binary_digest,
                generation: expected.generation,
                challenge: expected.challenge,
                issued_at: NOW,
                expires_at: NOW + 60,
            };
            let signature = signing_key(seed)
                .sign(&reply.canonical_bytes().unwrap())
                .to_bytes();
            let signed_reply = SignedPoolRolloverReadinessV1::new(reply, signature).unwrap();
            let bytes = signed_reply.canonical_bytes().unwrap();
            let consent = PoolRolloverConsentV1 {
                proposal_digest: decoded.canonical_hash().unwrap(),
                node: node_key,
                approved: true,
                issued_at: NOW,
                expires_at: NOW + 120,
            };
            let signature = signing_key(seed)
                .sign(&consent.canonical_bytes().unwrap())
                .to_bytes();
            let consent = SignedPoolRolloverConsentV1::new(consent, signature).unwrap();
            let encoded_consent = consent.canonical_bytes().unwrap();
            evidence.push(PoolRolloverMemberEvidenceV1 {
                expected,
                consent: SignedPoolRolloverConsentV1::from_canonical_bytes(&encoded_consent)
                    .unwrap(),
                readiness: SignedPoolRolloverReadinessV1::from_canonical_bytes(&bytes).unwrap(),
            });
        }
        assert_eq!(
            decoded.verify_member_evidence(&prior, &candidate, composition_digest, &evidence, NOW),
            Ok(())
        );
        assert!(decoded
            .verify_member_evidence(&prior, &candidate, composition_digest, &evidence[..2], NOW)
            .is_err());
        assert!(decoded
            .verify_member_evidence(&prior, &candidate, composition_digest, &evidence, NOW + 60)
            .is_err());
        for stale_context in [
            ExpectedPoolRolloverReadinessV1 {
                generation: [0x55; 16],
                ..evidence[0].expected
            },
            ExpectedPoolRolloverReadinessV1 {
                challenge: [0x55; 16],
                ..evidence[0].expected
            },
            ExpectedPoolRolloverReadinessV1 {
                provider_binary_digest: Digest32::new([0x51; 32]),
                ..evidence[0].expected
            },
        ] {
            let mut stale = evidence.clone();
            stale[0].expected = stale_context;
            assert!(decoded
                .verify_member_evidence(&prior, &candidate, composition_digest, &stale, NOW)
                .is_err());
        }
        let mut duplicate = evidence.clone();
        duplicate[0] = duplicate[1].clone();
        assert!(decoded
            .verify_member_evidence(&prior, &candidate, composition_digest, &duplicate, NOW)
            .is_err());

        let original = &evidence[0].consent.statement;
        let seed = (1..=3)
            .find(|seed| node_public_key(*seed) == original.node)
            .unwrap();
        for invalid in [
            PoolRolloverConsentV1 {
                approved: false,
                ..original.clone()
            },
            PoolRolloverConsentV1 {
                proposal_digest: Digest32::new([9; 32]),
                ..original.clone()
            },
            PoolRolloverConsentV1 {
                expires_at: NOW + 15,
                ..original.clone()
            },
        ] {
            let signature = signing_key(seed)
                .sign(&invalid.canonical_bytes().unwrap())
                .to_bytes();
            let mut refused = evidence.clone();
            refused[0].consent = SignedPoolRolloverConsentV1::new(invalid, signature).unwrap();
            assert!(decoded
                .verify_member_evidence(&prior, &candidate, composition_digest, &refused, NOW)
                .is_err());
        }

        let drops_history = successor(vec![next_bundle], *statement.serve_policy());
        let wrong_history = sign(PoolRolloverProposalV1 {
            candidate_descriptor_digest: drops_history.canonical_hash().unwrap(),
            ..proposal
        });
        assert!(wrong_history
            .verify(&prior, &drops_history, composition_digest, NOW)
            .is_err());
    }
}

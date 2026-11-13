//! Plan B T1.3: the pool custody request and response carry V2 releases and
//! the node's statement signatures, beside the unchanged V1 custody types.

use ed25519_dalek::Signer as _;
use elastos_protected_content_contracts::test_fixtures::{
    historical_v1_attestation_statement_for_key, node_public_key, pool_release_fixture,
    recipient_attestation_statement, recipient_identity, recipient_public_key, runtime_issuer,
    signed_node_rights_decision, signing_key, PoolReleaseFixtureV1, PoolReleaseSpecV1,
};
use elastos_protected_content_contracts::{
    CanonicalContract, NodeContributionStatementV1, PoolTrustModeV1, RecipientKeyIdentityV1,
    RecipientSealedContributionV1, RightsDecisionV1, SignedNodeContributionV1,
    MAX_TRUST_ATTESTATION_BYTES_V1,
};

use crate::test_support::{
    make_signed_runtime_release_operation, policy_body, xwing_public_key_bytes, NOW,
};
use crate::{
    CustodyProviderRequestValidationErrorV1, PoolCustodyRequestOpV1, PoolCustodyRequestV1,
    PoolCustodyResponseStatusV1, PoolCustodyResponseV1, PoolStatementKindV1, ProviderFailureCodeV1,
    ValidatedPoolCustodyRequestV1, MAX_POOL_STATEMENT_BYTES_V1,
};

/// Inside every fixture window.
const CHECK_AT: u64 = NOW + 6;

fn fixture_with(recipients: Vec<(u8, u8)>, max_servers: u8, nonce: u8) -> PoolReleaseFixtureV1 {
    let mut spec = PoolReleaseSpecV1::new(xwing_public_key_bytes, policy_body(), NOW);
    spec.recipients = recipients;
    spec.max_servers_per_session = max_servers;
    spec.replay_nonce = nonce;
    pool_release_fixture(&spec)
}

fn fixture() -> PoolReleaseFixtureV1 {
    fixture_with(vec![(9, 1)], 1, 0x55)
}

fn release_request(
    fixture: &PoolReleaseFixtureV1,
    decision: RightsDecisionV1,
) -> PoolCustodyRequestV1 {
    let signed_decision = signed_node_rights_decision(&fixture.authenticated(), 1, decision, NOW);
    PoolCustodyRequestV1::new_release_pool_contribution(&fixture.operation, &signed_decision)
        .unwrap()
}

fn validate(
    request: &PoolCustodyRequestV1,
    node_seed: u8,
) -> Result<ValidatedPoolCustodyRequestV1, CustodyProviderRequestValidationErrorV1> {
    ValidatedPoolCustodyRequestV1::decode_and_validate_at(
        &request.to_json_vec().unwrap(),
        node_public_key(node_seed),
        CHECK_AT,
    )
}

fn contribution_for(
    fixture: &PoolReleaseFixtureV1,
    node_seed: u8,
    sealed_to: RecipientKeyIdentityV1,
) -> SignedNodeContributionV1 {
    let operation = fixture.authenticated();
    let statement = NodeContributionStatementV1::new(
        operation.operation_hash(),
        operation.binding().clone(),
        signed_node_rights_decision(&operation, node_seed, RightsDecisionV1::Allowed, NOW),
        RecipientSealedContributionV1::new(sealed_to, vec![node_seed; 64]).unwrap(),
        NOW + 4,
        NOW + 30,
    )
    .unwrap();
    SignedNodeContributionV1::new(
        statement.clone(),
        signing_key(node_seed)
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

#[test]
fn pool_release_request_round_trips() {
    let fixture = fixture();
    let request = release_request(&fixture, RightsDecisionV1::Allowed);
    assert_eq!(
        request.op(),
        PoolCustodyRequestOpV1::ReleasePoolContribution
    );
    let bytes = request.to_json_vec().unwrap();
    assert_eq!(
        PoolCustodyRequestV1::from_json_slice(&bytes).unwrap(),
        request
    );

    let validated = validate(&request, 1).unwrap();
    assert_eq!(
        validated.op(),
        PoolCustodyRequestOpV1::ReleasePoolContribution
    );
    let release = validated.release_pool_contribution().unwrap();
    assert_eq!(release.selected_node_public_key(), node_public_key(1));
    assert_eq!(
        release.authenticated_runtime_release_operation(),
        &fixture.authenticated()
    );
    assert!(validated.sign_pool_statement().is_err());

    // The request names node 1's decision: node 2 cannot act on it.
    assert!(matches!(
        validate(&request, 2),
        Err(CustodyProviderRequestValidationErrorV1::Contract)
    ));
    // A denied decision releases nothing.
    assert!(matches!(
        validate(&release_request(&fixture, RightsDecisionV1::Denied), 1),
        Err(CustodyProviderRequestValidationErrorV1::RightsDenied)
    ));
}

#[test]
fn guard_pool_release_request_with_v1_operation_is_refused() {
    let request = release_request(&fixture(), RightsDecisionV1::Allowed);
    let mut value: serde_json::Value =
        serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap();
    value["signed_runtime_release_operation"] =
        serde_json::json!(make_signed_runtime_release_operation()
            .canonical_bytes()
            .unwrap());
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(PoolCustodyRequestV1::from_json_slice(&bytes).is_err());
    assert!(matches!(
        ValidatedPoolCustodyRequestV1::decode_and_validate_at(&bytes, node_public_key(1), CHECK_AT),
        Err(CustodyProviderRequestValidationErrorV1::Decode)
    ));
}

#[test]
fn sign_pool_statement_accepts_only_recipient_attestation() {
    let fixture = fixture();
    let statement = recipient_attestation_statement(
        xwing_public_key_bytes,
        &fixture.bundle,
        &fixture.binding,
        runtime_issuer(0x43),
        9,
        1,
        NOW,
    );
    let request = PoolCustodyRequestV1::new_sign_recipient_attestation(&statement).unwrap();
    assert_eq!(request.op(), PoolCustodyRequestOpV1::SignPoolStatement);
    let validated = validate(&request, 1).unwrap();
    let signing = validated.sign_pool_statement().unwrap();
    assert_eq!(signing.kind(), PoolStatementKindV1::RecipientAttestation);
    assert_eq!(signing.recipient_attestation(), &statement);
    assert_eq!(
        signing.signing_bytes().unwrap(),
        statement.canonical_bytes().unwrap()
    );
    // The statement names node 1 as the server: node 2 does not sign it.
    assert!(validate(&request, 2).is_err());

    let base: serde_json::Value = serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap();
    for kind in ["seal_receipt", "mint_admission", "provisioning", ""] {
        let mut value = base.clone();
        value["kind"] = serde_json::json!(kind);
        assert!(
            ValidatedPoolCustodyRequestV1::decode_and_validate_at(
                &serde_json::to_vec(&value).unwrap(),
                node_public_key(1),
                CHECK_AT,
            )
            .is_err(),
            "{kind}"
        );
    }
    // Other canonical bytes under the recipient-attestation kind.
    let mut value = base;
    value["statement"] = serde_json::json!(fixture.binding.canonical_bytes().unwrap());
    assert!(ValidatedPoolCustodyRequestV1::decode_and_validate_at(
        &serde_json::to_vec(&value).unwrap(),
        node_public_key(1),
        CHECK_AT,
    )
    .is_err());

    // The node's signature answers the exact statement.
    let signature = signing_key(1)
        .sign(&statement.canonical_bytes().unwrap())
        .to_bytes();
    let response =
        PoolCustodyResponseV1::new_pool_statement_signature(&validated, signature).unwrap();
    assert_eq!(
        response.status(),
        PoolCustodyResponseStatusV1::StatementSignature
    );
    let decoded = PoolCustodyResponseV1::from_json_slice(&response.to_json_vec().unwrap()).unwrap();
    assert_eq!(decoded.statement_signature().unwrap(), signature);
    decoded
        .validate_against_request_at(&validated, CHECK_AT)
        .unwrap();
    let forged = signing_key(2)
        .sign(&statement.canonical_bytes().unwrap())
        .to_bytes();
    assert!(
        PoolCustodyResponseV1::new_pool_statement_signature(&validated, forged)
            .unwrap()
            .validate_against_request_at(&validated, CHECK_AT)
            .is_err()
    );
}

#[test]
fn pool_contributions_answer_each_signed_recipient_in_order() {
    let fixture = fixture_with(vec![(9, 1), (10, 2)], 2, 0x55);
    let request = release_request(&fixture, RightsDecisionV1::Allowed);
    let validated = validate(&request, 1).unwrap();
    let recipients = fixture
        .operation
        .statement()
        .rights_request()
        .request()
        .recipients()
        .to_vec();
    let contributions: Vec<SignedNodeContributionV1> = recipients
        .iter()
        .map(|recipient| contribution_for(&fixture, 1, recipient.clone()))
        .collect();
    let response =
        PoolCustodyResponseV1::new_pool_contributions(&validated, &contributions).unwrap();
    assert_eq!(
        response.status(),
        PoolCustodyResponseStatusV1::Contributions
    );
    let decoded = PoolCustodyResponseV1::from_json_slice(&response.to_json_vec().unwrap()).unwrap();
    assert_eq!(decoded.signed_node_contributions().unwrap(), contributions);
    decoded
        .validate_against_request_at(&validated, CHECK_AT)
        .unwrap();
    decoded
        .validate_against_plain_request_at(&request, node_public_key(1), CHECK_AT)
        .unwrap();

    // Out of order, short, or sealed to someone else: refused.
    let reversed: Vec<_> = contributions.iter().rev().cloned().collect();
    assert!(
        PoolCustodyResponseV1::new_pool_contributions(&validated, &reversed)
            .unwrap()
            .validate_against_request_at(&validated, CHECK_AT)
            .is_err()
    );
    assert!(
        PoolCustodyResponseV1::new_pool_contributions(&validated, &contributions[..1])
            .unwrap()
            .validate_against_request_at(&validated, CHECK_AT)
            .is_err()
    );
    let outsider = vec![
        contribution_for(&fixture, 1, recipient_identity(xwing_public_key_bytes, 11)),
        contributions[1].clone(),
    ];
    assert!(
        PoolCustodyResponseV1::new_pool_contributions(&validated, &outsider)
            .unwrap()
            .validate_against_request_at(&validated, CHECK_AT)
            .is_err()
    );
}

#[test]
fn pool_failure_response_names_the_operation_hash() {
    let fixture = fixture();
    let request = release_request(&fixture, RightsDecisionV1::Allowed);
    let validated = validate(&request, 1).unwrap();
    let failure =
        PoolCustodyResponseV1::new_failure(&validated, ProviderFailureCodeV1::BackendUnavailable)
            .unwrap();
    assert_eq!(failure.status(), PoolCustodyResponseStatusV1::Failure);
    let operation = fixture.authenticated();
    // L1: the V2 operation hash, not a release-request hash.
    assert_eq!(
        failure.failure_operation_hash().unwrap(),
        operation.operation_hash()
    );
    assert_eq!(
        failure.failure_audit_request_id().unwrap(),
        operation.statement().audit_request_id()
    );
    assert_eq!(
        failure.failure_code().unwrap(),
        ProviderFailureCodeV1::BackendUnavailable
    );
    let decoded = PoolCustodyResponseV1::from_json_slice(&failure.to_json_vec().unwrap()).unwrap();
    decoded
        .validate_against_request_at(&validated, CHECK_AT)
        .unwrap();
    decoded
        .validate_against_plain_request_at(&request, node_public_key(1), CHECK_AT)
        .unwrap();

    // A failure for another operation does not answer this request.
    let other = fixture_with(vec![(9, 1)], 1, 0x56);
    let other_validated = validate(&release_request(&other, RightsDecisionV1::Allowed), 1).unwrap();
    let other_failure = PoolCustodyResponseV1::new_failure(
        &other_validated,
        ProviderFailureCodeV1::BackendUnavailable,
    )
    .unwrap();
    assert!(other_failure
        .validate_against_request_at(&validated, CHECK_AT)
        .is_err());
}

/// #388-2: the node signs only the v2 recipient attestation, which binds the
/// pool's trust mode (empty evidence under `WciOperated`).
#[test]
fn sign_pool_statement_signs_the_v2_attestation_and_refuses_v1() {
    let fixture = fixture();
    let statement = recipient_attestation_statement(
        xwing_public_key_bytes,
        &fixture.bundle,
        &fixture.binding,
        runtime_issuer(0x43),
        9,
        1,
        NOW,
    );
    assert_eq!(statement.trust_mode(), PoolTrustModeV1::WciOperated);
    assert!(statement.evidence().is_empty());
    let request = PoolCustodyRequestV1::new_sign_recipient_attestation(&statement).unwrap();
    validate(&request, 1).unwrap();

    let v1 = historical_v1_attestation_statement_for_key(
        &fixture.bundle,
        &fixture.binding,
        runtime_issuer(0x43),
        recipient_public_key(xwing_public_key_bytes, 9),
        1,
        NOW,
    );
    let mut value: serde_json::Value =
        serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap();
    value["statement"] = serde_json::json!(v1.canonical_bytes().unwrap());
    assert!(ValidatedPoolCustodyRequestV1::decode_and_validate_at(
        &serde_json::to_vec(&value).unwrap(),
        node_public_key(1),
        CHECK_AT,
    )
    .is_err());
}

/// A388-F4: the reserved 16 KiB slot does not raise the 8 KiB statement
/// request; a statement over it is refused at the wire.
#[test]
fn oversized_attestation_refused_at_sign_statement() {
    let fixture = fixture();
    let statement = recipient_attestation_statement(
        xwing_public_key_bytes,
        &fixture.bundle,
        &fixture.binding,
        runtime_issuer(0x43),
        9,
        1,
        NOW,
    );
    assert!(statement.canonical_bytes().unwrap().len() <= MAX_POOL_STATEMENT_BYTES_V1);
    let request = PoolCustodyRequestV1::new_sign_recipient_attestation(&statement).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap();
    value["statement"] = serde_json::json!(vec![0u8; MAX_POOL_STATEMENT_BYTES_V1 + 1]);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(PoolCustodyRequestV1::from_json_slice(&bytes).is_err());
    assert!(matches!(
        ValidatedPoolCustodyRequestV1::decode_and_validate_at(&bytes, node_public_key(1), CHECK_AT),
        Err(CustodyProviderRequestValidationErrorV1::Decode)
    ));
}

#[test]
fn no_existing_cap_changed() {
    assert_eq!(MAX_POOL_STATEMENT_BYTES_V1, 8 * 1024);
    // A full reserved slot would not fit the statement request.
    const _: () = assert!(MAX_TRUST_ATTESTATION_BYTES_V1 > MAX_POOL_STATEMENT_BYTES_V1);
}

// ---------------------------------------------------------------------------
// Plan B POOL-MINT: a Home that uses a pool provisions a member's share.
// ---------------------------------------------------------------------------

mod provision {
    use elastos_protected_content_contracts::test_fixtures::{
        pool_bundle, pool_descriptor_signed_by, pool_did, pool_mint_share,
        pool_provisioning_record, runtime_custody_provisioning, runtime_issuer,
        POOL_AUTHORITY_SEED,
    };
    use elastos_protected_content_contracts::{
        ContentAccessIdV1, CustodyNodeProvisioningRecordV1, Digest32, EncryptedContentIdentityV1,
        SignedPoolDescriptorAnyV1, SignedPoolMintShareV1, SignedRuntimeCustodyProvisioningV1,
    };

    use super::*;

    const MINTER: u8 = 0x44;
    const OTHER_HOME: u8 = 0x45;

    struct Parts {
        record: CustodyNodeProvisioningRecordV1,
        statement: SignedRuntimeCustodyProvisioningV1,
        mint_share: SignedPoolMintShareV1,
        descriptor: SignedPoolDescriptorAnyV1,
    }

    fn parts(minter_seed: u8, statement_seed: u8) -> Parts {
        let bundle = pool_bundle(xwing_public_key_bytes, NOW);
        let content = EncryptedContentIdentityV1::new(Digest32::new([0x11; 32]), 4096).unwrap();
        let record = pool_provisioning_record(&bundle, &content, 1);
        let statement = runtime_custody_provisioning(&record, statement_seed, 0xf1, NOW);
        let mint_share = pool_mint_share(
            pool_did(),
            record.key_envelope_identity(),
            ContentAccessIdV1::new([0x41; 16]).unwrap(),
            minter_seed,
        );
        Parts {
            record,
            statement,
            mint_share,
            descriptor: pool_descriptor_signed_by(&bundle, 1, NOW, POOL_AUTHORITY_SEED).into(),
        }
    }

    fn request(parts: &Parts) -> PoolCustodyRequestV1 {
        PoolCustodyRequestV1::new_provision_pool_node_share(
            &parts.record,
            &parts.statement,
            &parts.mint_share,
            &parts.descriptor,
        )
        .unwrap()
    }

    #[test]
    fn provision_pool_node_share_request_round_trips() {
        let parts = parts(MINTER, MINTER);
        let request = request(&parts);
        assert_eq!(request.op(), PoolCustodyRequestOpV1::ProvisionPoolNodeShare);
        let bytes = request.to_json_vec().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["op"], "provision_pool_node_share");
        assert_eq!(
            PoolCustodyRequestV1::from_json_slice(&bytes).unwrap(),
            request
        );
        assert_eq!(
            PoolCustodyRequestV1::peek_selected_node_public_key(&bytes).unwrap(),
            node_public_key(1)
        );
        // Any Home that uses the pool mints: no admission list is read.
        let validated = validate(&request, 1).unwrap();
        assert_eq!(
            validated.op(),
            PoolCustodyRequestOpV1::ProvisionPoolNodeShare
        );
        let provision = validated.provision_pool_node_share().unwrap();
        assert_eq!(
            provision
                .signed_pool_mint_share()
                .statement()
                .minter_runtime_issuer(),
            runtime_issuer(MINTER)
        );
        let response = PoolCustodyResponseV1::new_pool_provisioned(&validated).unwrap();
        assert_eq!(response.status(), PoolCustodyResponseStatusV1::Provisioned);
        let response =
            PoolCustodyResponseV1::from_json_slice(&response.to_json_vec().unwrap()).unwrap();
        response
            .validate_against_request_at(&validated, CHECK_AT)
            .unwrap();
        response
            .validate_provisioned_against(&parts.statement, &parts.record)
            .unwrap();
        assert!(PoolCustodyResponseV1::new_failure(
            &validated,
            ProviderFailureCodeV1::BackendUnavailable
        )
        .is_err());
    }

    #[test]
    fn guard_share_with_a_wrong_minter_signature_does_not_validate() {
        let mut parts = parts(MINTER, MINTER);
        let forged = pool_mint_share(
            pool_did(),
            parts.record.key_envelope_identity(),
            ContentAccessIdV1::new([0x41; 16]).unwrap(),
            OTHER_HOME,
        );
        parts.mint_share = SignedPoolMintShareV1::new(
            parts.mint_share.statement().clone(),
            forged.runtime_signature().to_vec(),
        )
        .unwrap();
        assert!(validate(&request(&parts), 1).is_err());
    }

    #[test]
    fn provisioning_statement_under_another_issuer_does_not_validate() {
        // The share statement is the minter's; the runtime statement must be
        // signed by the same issuer.
        let parts = parts(MINTER, OTHER_HOME);
        assert!(validate(&request(&parts), 1).is_err());
    }

    #[test]
    fn provisioning_for_another_node_does_not_validate() {
        let parts = parts(MINTER, MINTER);
        assert!(validate(&request(&parts), 2).is_err());
    }

    #[test]
    fn share_statement_for_another_envelope_is_refused_at_construction() {
        let mut parts = parts(MINTER, MINTER);
        let bundle = pool_bundle(xwing_public_key_bytes, NOW);
        let other = EncryptedContentIdentityV1::new(Digest32::new([0x12; 32]), 4096).unwrap();
        let other_record = pool_provisioning_record(&bundle, &other, 1);
        parts.mint_share = pool_mint_share(
            pool_did(),
            other_record.key_envelope_identity(),
            ContentAccessIdV1::new([0x41; 16]).unwrap(),
            MINTER,
        );
        assert!(PoolCustodyRequestV1::new_provision_pool_node_share(
            &parts.record,
            &parts.statement,
            &parts.mint_share,
            &parts.descriptor,
        )
        .is_err());
    }

    #[test]
    fn share_statement_for_another_pool_is_refused_at_construction() {
        let mut parts = parts(MINTER, MINTER);
        let bundle = pool_bundle(xwing_public_key_bytes, NOW);
        parts.descriptor = pool_descriptor_signed_by(&bundle, 1, NOW, 0x73).into();
        assert!(PoolCustodyRequestV1::new_provision_pool_node_share(
            &parts.record,
            &parts.statement,
            &parts.mint_share,
            &parts.descriptor,
        )
        .is_err());
    }
}

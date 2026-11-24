//! Test helpers shared by the pool client and pool session tests.

//! Plan B T3.2: the pool session server against fake ports and injected
//! session ids. The fakes record every port call; gates (semaphores with no
//! permits) hold a port call open so tests can race, close or cancel.

use ed25519_dalek::Signer as _;
use elastos_protected_content_contracts::test_fixtures::{
    signed_node_rights_decision, signing_key, PoolReleaseFixtureV1,
};
use elastos_protected_content_contracts::{
    CanonicalContract, DeliveryPublicKeyBytesV1, KeyReleaseOutcomeV1, NodeContributionRefV1,
    NodeContributionStatementV1, RecipientSealedContributionV1, RightsDecisionV1,
    RuntimeIssuerPolicyV1, SignedNodeContributionV1, SignedTerminalReceiptV1,
    TerminalReceiptIssuerKey, TerminalReceiptStatementV1, PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES,
};
use x_wing::kem::{Decapsulator as _, KeyExport as _};

pub(crate) fn xwing(seed: u8) -> [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
    let secret = x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE]);
    secret.encapsulation_key().to_bytes().into()
}

pub(crate) fn delivery_public_key(seed: u8) -> DeliveryPublicKeyBytesV1 {
    DeliveryPublicKeyBytesV1::new(xwing(seed)).unwrap()
}

/// Structurally valid contributions and receipt for `recipient` (the fake
/// decrypt provider does not open them).
pub(crate) fn release_for(
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
                RecipientSealedContributionV1::new(recipient.clone(), vec![node; 96]).unwrap(),
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

pub(crate) const BUYER_RUNTIME_SEED: u8 = 0x43;

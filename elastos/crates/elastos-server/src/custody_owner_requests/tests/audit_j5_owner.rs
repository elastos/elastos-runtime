//! AUDIT-REPRO J5 (coll-journey-audit-20261117.md J5-3): red test only, no
//! fix. The owner side of a member that stopped serving its pool.

use super::*;

/// J5-3: once the owner's pool is installed it sends no request at all, so
/// a member that approved and later stopped serving can never be asked
/// again (and no route re-forms or replaces a member of an installed pool).
#[tokio::test]
async fn audit_j5_3_owner_can_ask_a_member_again_after_it_left() {
    let owner = owner();
    let bob = Party::new("Bob", true);
    let contacts = [bob.contact()];
    let to_bob = owner
        .send(&contacts, bob.profile_did(), 365, NOW)
        .await
        .unwrap();
    owner
        .decide(&bob, approval(&to_bob, bob.card("Oslo")), NOW + 60)
        .unwrap();
    // The owner forms its pool with Bob in it.
    std::fs::write(
        crate::protected_content_runtime::runtime_custody_composition_config_path(&owner.data_dir),
        b"{}",
    )
    .unwrap();
    // Bob stops serving (Hosting's Stop): nothing reaches the owner (J5-2).
    // The owner asks Bob again, for another term.

    let again = owner
        .send(&contacts, bob.profile_did(), 730, NOW + 120)
        .await;

    assert!(
        again.is_ok(),
        "J5-3: the owner cannot ask a member that left its installed pool again: {}",
        again
            .as_ref()
            .err()
            .map(|error| refusal(error))
            .unwrap_or_default()
    );
}

//! Journey regression tests (#388): the owner side of a member that stopped
//! serving its pool.

use super::*;

/// J5-3: the owner of an installed pool can ask a member that stopped
/// serving it again. Tracked as a #388 follow-up.
#[ignore = "tracked: #388 follow-up"]
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
    // Bob stops serving (Hosting's Stop).
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

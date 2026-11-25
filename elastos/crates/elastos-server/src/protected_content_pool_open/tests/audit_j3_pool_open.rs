//! AUDIT-REPRO J3 (red, no fix): the pool open's time budgets.

use super::*;

/// J3-F3 (= independent audit F8). The release operation lives
/// `POOL_OPERATION_LIFETIME_SECS` (50 s) and bounds only the node release.
/// Each epoch-node call is routed as a Control call (`epoch_node_transport`),
/// which waits up to 5 s to connect and 60 s for the answer
/// (custody_pool_resolver.rs:72-74). The coordinator asks the next node only
/// after a launched call answers (elastos-protected-content-runtime
/// coordinator.rs:625-640), and the server refuses an operation past its
/// expiry at `session.open` (green: `open_with_expired_proofs_is_refused`).
/// So one node that accepts the stream and answers late expires the release
/// after the Wallet approved, with no room left to ask another node.
#[test]
fn audit_j3_f3_one_slow_epoch_node_leaves_room_for_a_replacement_inside_the_release() {
    let pool = pool(1);
    let member = pool
        .resolved
        .descriptor
        .members()
        .iter()
        .next()
        .expect("a member");
    let transport = epoch_node_transport(member, &[], &KeptCardTickets::new());
    let ProviderInvocationTransport::Carrier(route) = transport else {
        panic!("a buyer reaches an epoch node over Carrier");
    };
    let one_call_ms =
        route.timeout_ms().unwrap_or(0) + route.reply_wait_ms().unwrap_or(u64::MAX / 4);
    let lifetime_ms = super::super::POOL_OPERATION_LIFETIME_SECS * 1000;
    assert!(
        2 * one_call_ms <= lifetime_ms,
        "one epoch-node call may take {one_call_ms} ms; a slow node and its replacement \
         ({} ms) must fit in the release operation's {lifetime_ms} ms",
        2 * one_call_ms
    );
}

/// J3-F4 (STAB-37), ACCEPTED under D6: the rights request, and so the
/// session, are timed from the first open (`now + 290` at the first open,
/// and the session ends at the rights expiry capped by the attestations,
/// both fixed then). Every second the person takes to approve comes out of
/// this session; with STAB-05 in, that only brings the next renewal
/// earlier, since the renewed session reads on from the same part. This
/// pins the accepted bound so a change to it is a decision, not a drift.
#[tokio::test]
async fn audit_j3_f4_a_late_approval_shortens_the_session_and_only_the_renewal_comes_earlier() {
    let pool = pool(1);

    // Approved at once.
    let prompt_servers = FakeServers::new(&pool);
    let prompt_ports = FakePorts::new(&pool, &[WalletMode::Sign]);
    let prompt_keys = PoolDeliveryKeys::default();
    let prompt = opened(
        open_pool_viewer(
            context(&pool, &[], None),
            &prompt_servers,
            &prompt_ports,
            &prompt_keys,
        )
        .await
        .unwrap(),
    );
    let full_session = prompt.expires_at - NOW;

    // The person approves 150 s later. The rights request the Wallet holds
    // was built at the first open, so the session can end no later than its
    // expiry. The fixtures sign node contributions at `NOW`, so the late
    // resume itself cannot be run here; its bound is read instead.
    let servers = FakeServers::new(&pool);
    let ports = FakePorts::new(&pool, &[WalletMode::Pending]);
    let keys = PoolDeliveryKeys::default();
    let PoolOpenOutcome::PendingApproval(_) =
        open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys)
            .await
            .unwrap()
    else {
        panic!("expected a pending approval");
    };
    let rights_expiry = ports.fresh.lock().unwrap()[0].expires_at();
    let approved_at = NOW + 150;
    let latest_session = rights_expiry.saturating_sub(approved_at);
    assert_eq!(
        rights_expiry - NOW,
        full_session,
        "the rights window is the full session, fixed at the first open"
    );
    assert_eq!(
        latest_session,
        full_session - 150,
        "a session approved 150 s late lasts 150 s less after the approval (accepted, STAB-37)"
    );
}

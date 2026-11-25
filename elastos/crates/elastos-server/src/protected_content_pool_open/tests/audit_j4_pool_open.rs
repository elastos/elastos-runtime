//! AUDIT-REPRO J4 (coll-journey-audit-20261117.md J4-F1, journey-audit A2-F2):
//! red tests only, no fix. The reader's half: a server that answers
//! `content_unavailable` at `session.prepare` is not passed over.

use super::*;

/// J4-F1 / A2-F2: servers 1 and 2 hold no copy and say so at prepare; server
/// 3 serves. Every open must reach server 3, before any Wallet request.
#[tokio::test]
async fn audit_j4_f1_an_unreadable_server_is_passed_over_before_the_wallet() {
    let refusal = PoolTransportError::Refused("content_unavailable".into());
    let pool = pool(1);
    let mut failures = Vec::new();
    for attempt in 0..32 {
        let servers = FakeServers::new(&pool)
            .refusing(1, refusal.clone())
            .refusing(2, refusal.clone());
        let ports = FakePorts::new(&pool, &[WalletMode::Sign]);
        let keys = PoolDeliveryKeys::default();
        let outcome = open_pool_viewer(context(&pool, &[], None), &servers, &ports, &keys).await;
        if let Err(error) = outcome {
            failures.push(format!(
                "attempt {attempt}: prepared at {:?}, wallet calls {}: {error:#}",
                servers.prepared_seeds(),
                ports.wallet_calls()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "J4-F1: prepare_fails_over(content_unavailable) = {}; {} of 32 opens stopped at a \
         server without the content:\n{}",
        prepare_fails_over(&refusal),
        failures.len(),
        failures.join("\n")
    );
}

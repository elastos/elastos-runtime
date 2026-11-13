//! Plan B T1.7 (L10, L11, D5): release budgets of the custody target.

use elastos_protected_content_contracts::{ContentAccessIdV1, WalletAddress};
use elastos_protected_content_provider_contracts::MAX_VIEWER_SESSIONS_V1;

use super::*;

const NOW: u64 = 1_800_000_000;

fn wallet(seed: u8) -> WalletAddress {
    WalletAddress::new([seed; 20])
}

fn kid(seed: u8) -> ContentAccessIdV1 {
    ContentAccessIdV1::new([seed; 16]).unwrap()
}

fn limiter() -> CustodyReleaseLimiter {
    CustodyReleaseLimiter::new(CUSTODY_NODE_SETTINGS)
}

#[test]
fn custody_node_settings_are_the_d5_values() {
    assert_eq!(
        CUSTODY_NODE_SETTINGS,
        CustodyNodeSettingsV1 {
            max_pools: 8,
            releases_per_endpoint_per_minute: 30,
            releases_per_wallet_per_minute: 20,
            releases_per_kid_per_minute: 60,
            pool_sessions_per_node: 64,
        }
    );
    // The module also asserts this at compile time.
    const _: () = assert!(CUSTODY_NODE_SETTINGS.pool_sessions_per_node <= MAX_VIEWER_SESSIONS_V1);
}

#[test]
fn endpoint_budget_refuses_above_the_minute_and_recovers() {
    let limiter = limiter();
    for _ in 0..CUSTODY_NODE_SETTINGS.releases_per_endpoint_per_minute {
        limiter.admit_endpoint("did:key:a", NOW).unwrap();
    }
    assert_eq!(
        limiter.admit_endpoint("did:key:a", NOW + 59),
        Err(RateLimited)
    );
    // A refused call is not counted, and another endpoint has its own budget.
    limiter.admit_endpoint("did:key:b", NOW + 59).unwrap();
    limiter
        .admit_endpoint("did:key:a", NOW + CUSTODY_RELEASE_WINDOW_SECS)
        .unwrap();
}

#[test]
fn every_local_plane_call_shares_one_endpoint_key() {
    assert_eq!(
        RuntimeInvocationSource::Local.endpoint_key(),
        RUNTIME_LOCAL_ENDPOINT_KEY
    );
    assert_eq!(RUNTIME_LOCAL_ENDPOINT_KEY, "runtime-local");
    let carrier = RuntimeInvocationSource::Carrier {
        source_endpoint_did: "did:key:z6Mk".into(),
    };
    assert_eq!(carrier.endpoint_key(), "did:key:z6Mk");
}

#[test]
fn wallet_budget_spans_items() {
    let limiter = limiter();
    for index in 0..CUSTODY_NODE_SETTINGS.releases_per_wallet_per_minute {
        limiter
            .admit_rights(wallet(1), kid(index as u8 + 1), NOW)
            .unwrap();
    }
    assert_eq!(
        limiter.admit_rights(wallet(1), kid(0x7f), NOW),
        Err(RateLimited)
    );
    limiter.admit_rights(wallet(2), kid(0x7f), NOW).unwrap();
}

#[test]
fn kid_budget_spans_wallets() {
    let limiter = limiter();
    let per_wallet = CUSTODY_NODE_SETTINGS.releases_per_wallet_per_minute;
    let wallets = CUSTODY_NODE_SETTINGS.releases_per_kid_per_minute / per_wallet;
    for wallet_seed in 0..wallets {
        for _ in 0..per_wallet {
            limiter
                .admit_rights(wallet(wallet_seed as u8 + 1), kid(9), NOW)
                .unwrap();
        }
    }
    assert_eq!(
        limiter.admit_rights(wallet(0x70), kid(9), NOW),
        Err(RateLimited)
    );
    limiter.admit_rights(wallet(0x70), kid(10), NOW).unwrap();
}

#[test]
fn a_refused_rights_call_counts_neither_budget() {
    let limiter = limiter();
    let per_wallet = CUSTODY_NODE_SETTINGS.releases_per_wallet_per_minute;
    let wallets = CUSTODY_NODE_SETTINGS.releases_per_kid_per_minute / per_wallet;
    for wallet_seed in 0..wallets {
        for _ in 0..per_wallet {
            limiter
                .admit_rights(wallet(wallet_seed as u8 + 1), kid(9), NOW)
                .unwrap();
        }
    }
    // The item's budget is spent: wallet 0x70 is refused for it many times,
    // and none of those refusals spends wallet 0x70's own budget.
    for _ in 0..per_wallet * 2 {
        assert_eq!(
            limiter.admit_rights(wallet(0x70), kid(9), NOW),
            Err(RateLimited)
        );
    }
    for index in 0..per_wallet {
        limiter
            .admit_rights(wallet(0x70), kid(index as u8 + 0x20), NOW)
            .unwrap();
    }
}

/// Plan B T2.1 (user 10:26 (4)): the custody provider's own root cap is this
/// Home's pool cap. The provider is its own binary, so its constant is read
/// from its source.
#[test]
fn provider_root_cap_equals_max_pools() {
    const PROVIDER_LIB: &str = include_str!("../../../../../capsules/custody-provider/src/lib.rs");
    let line = PROVIDER_LIB
        .lines()
        .find(|line| line.starts_with("pub const MAX_CUSTODY_ROOTS_V1: usize = "))
        .expect("the provider declares MAX_CUSTODY_ROOTS_V1");
    let cap: usize = line
        .trim_start_matches("pub const MAX_CUSTODY_ROOTS_V1: usize = ")
        .trim_end_matches(';')
        .parse()
        .unwrap();
    assert_eq!(cap, CUSTODY_NODE_SETTINGS.max_pools);
}

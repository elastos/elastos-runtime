//! The custody node's settings (D5) and the release budgets of its custody
//! target (Plan B T1.7, L10).
//!
//! The custody wrapper spends two kinds of budget, each over one minute:
//! - the endpoint budget, at entry, for every release call. A Carrier peer is
//!   keyed by its authenticated endpoint DID; every call on the Runtime's own
//!   local provider plane shares the key `runtime-local`;
//! - the wallet and item (KID) budgets, after the capsule accepts
//!   `prepare_evidence` and before the chain read. The accepted prepare has
//!   proven the operation's signatures, so these budgets count only signed
//!   requests.
//!
//! A refused call spends nothing. Budgets live in memory and reset on restart.

use std::sync::{Mutex, PoisonError};

use elastos_protected_content_contracts::{ContentAccessIdV1, WalletAddress};
use elastos_protected_content_provider_contracts::MAX_VIEWER_SESSIONS_V1;

use crate::collaboration_rate_limit::ProfileRateLimiter;

/// The node's custody settings, declared once (D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// `max_pools` and `pool_sessions_per_node` are read by the pool tasks that
// follow (Plan B S2 and S3).
#[allow(dead_code)]
pub(crate) struct CustodyNodeSettingsV1 {
    /// Pools this node serves at most, each with its own keys.
    pub max_pools: usize,
    pub releases_per_endpoint_per_minute: u32,
    pub releases_per_wallet_per_minute: u32,
    pub releases_per_kid_per_minute: u32,
    /// Pool viewer sessions this node holds at most, within the decrypt
    /// capsule's own session bound (L11).
    pub pool_sessions_per_node: usize,
}

pub(crate) const CUSTODY_NODE_SETTINGS: CustodyNodeSettingsV1 = CustodyNodeSettingsV1 {
    max_pools: 8,
    releases_per_endpoint_per_minute: 30,
    releases_per_wallet_per_minute: 20,
    releases_per_kid_per_minute: 60,
    pool_sessions_per_node: 64,
};

const _: () = assert!(CUSTODY_NODE_SETTINGS.pool_sessions_per_node <= MAX_VIEWER_SESSIONS_V1);

/// The window of every release budget.
pub(crate) const CUSTODY_RELEASE_WINDOW_SECS: u64 = 60;
/// The one endpoint key of every call on the Runtime's local provider plane.
pub(crate) const RUNTIME_LOCAL_ENDPOINT_KEY: &str = "runtime-local";
/// The refusal code of a call above a budget. It is effect-free.
pub(crate) const RATE_LIMITED_CODE: &str = "rate_limited";

/// A call above one of its budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RateLimited;

/// Where a custody call came from, as its validated Runtime envelope says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeInvocationSource {
    Local,
    Carrier { source_endpoint_did: String },
}

impl RuntimeInvocationSource {
    /// The endpoint budget's key. A Carrier DID is canonical `did:key`, so it
    /// never equals the local key.
    pub(crate) fn endpoint_key(&self) -> &str {
        match self {
            Self::Local => RUNTIME_LOCAL_ENDPOINT_KEY,
            Self::Carrier {
                source_endpoint_did,
            } => source_endpoint_did,
        }
    }
}

/// The release budgets of one custody target.
pub(crate) struct CustodyReleaseLimiter {
    /// Serializes every check with its record, so a call is admitted only
    /// when all of its budgets fit and is then counted in all of them.
    admission: Mutex<()>,
    endpoints: ProfileRateLimiter,
    wallets: ProfileRateLimiter,
    kids: ProfileRateLimiter,
}

impl CustodyReleaseLimiter {
    pub(crate) fn new(settings: CustodyNodeSettingsV1) -> Self {
        let limiter = |per_minute: u32| {
            ProfileRateLimiter::new(per_minute as usize, CUSTODY_RELEASE_WINDOW_SECS)
        };
        Self {
            admission: Mutex::new(()),
            endpoints: limiter(settings.releases_per_endpoint_per_minute),
            wallets: limiter(settings.releases_per_wallet_per_minute),
            kids: limiter(settings.releases_per_kid_per_minute),
        }
    }

    /// Spends one call of `endpoint_key`'s budget, at entry.
    pub(crate) fn admit_endpoint(&self, endpoint_key: &str, now: u64) -> Result<(), RateLimited> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.endpoints
            .check(endpoint_key, now)
            .map_err(|_| RateLimited)?;
        self.endpoints.record(endpoint_key, now);
        Ok(())
    }

    /// Spends one call of the wallet's and the item's budgets, after the
    /// capsule accepts `prepare_evidence`. When either budget is spent,
    /// neither is counted.
    pub(crate) fn admit_rights(
        &self,
        wallet: WalletAddress,
        kid: ContentAccessIdV1,
        now: u64,
    ) -> Result<(), RateLimited> {
        let wallet_key = hex::encode(wallet.as_bytes());
        let kid_key = hex::encode(kid.as_bytes());
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.wallets
            .check(&wallet_key, now)
            .map_err(|_| RateLimited)?;
        self.kids.check(&kid_key, now).map_err(|_| RateLimited)?;
        self.wallets.record(&wallet_key, now);
        self.kids.record(&kid_key, now);
        Ok(())
    }
}

#[cfg(test)]
mod tests;

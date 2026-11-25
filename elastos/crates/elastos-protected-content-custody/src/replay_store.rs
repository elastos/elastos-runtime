use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use hpke::rand_core::{CryptoRng as HpkeCryptoRng, RngCore as HpkeRngCore};
use nix::fcntl::{Flock, FlockArg};
use nix::unistd::geteuid;
use rand09::SeedableRng as _;
use sha2::{Digest as _, Sha256};

use elastos_protected_content_contracts::{
    AuthenticatedRuntimeReleaseOperationV1, AuthenticatedRuntimeReleaseOperationV2,
    CanonicalContract, Digest32, NodePublicKey, NodeSetV1, ReplayClaimEntryV1, ReplayClaimError,
    ReplayClaimKeyV1, ReplayNonce16, RightsDecisionV1, RuntimeReleaseAuditIdV1,
    SignedNodeContributionV1, SignedNodeRightsDecisionV1, VerifiedNodeContributionV1,
    VerifiedNodeRightsDecisionV1, CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
    MAX_RECIPIENT_SEALED_CONTRIBUTION_BYTES, MAX_SESSION_RECIPIENTS_V2,
};

use crate::{
    node_share::NodeLocalStoredShareV1,
    release::{produce_node_contribution_with_rng, produce_pool_contributions_with_rng},
    secrets::NodeCustodySecretKeyV1,
    CustodyError, RecipientPublicKeyV1,
};

/// The record version written before Plan B: V1 records only, untagged. It is
/// still read, and rewritten as `epc-rcl2` on the next write (L4).
const STATE_MAGIC_V1: &[u8; 8] = b"epc-rcl1";
/// Every record carries a kind tag: a V1 release or a V2 pool release.
const STATE_MAGIC_V2: &[u8; 8] = b"epc-rcl2";
const RECORD_KIND_RELEASE_V1: u8 = 1;
const RECORD_KIND_POOL_RELEASE_V2: u8 = 2;
const STATE_DIGEST_DOMAIN: &[u8] = b"elastos/protected-content/node-replay-claims/state/v1";
const STATE_HEADER_BYTES: usize = 44;
const REPLAY_CLAIM_KEY_BYTES: usize = 48;
const STORED_RESULT_STATE_CLAIM_ONLY: u8 = 0;
const STORED_RESULT_STATE_PRESENT: u8 = 1;
const MAX_STORED_CONTRIBUTION_BYTES: usize = MAX_RECIPIENT_SEALED_CONTRIBUTION_BYTES + (4 * 1024);
const STATE_DIGEST_BYTES: usize = 32;
const MAX_REPLAY_CLAIMS: usize = 4096;
const MAX_NODE_RELEASE_RECORDS: usize = MAX_REPLAY_CLAIMS / 2;
const MAX_STATE_BYTES: usize = 8 * 1024 * 1024;
const MAX_STATE_PAYLOAD_BYTES: usize = MAX_STATE_BYTES - STATE_DIGEST_BYTES;

/// Atomically claimed node-release authority for one custody node.
///
/// This token is non-serializable and has no public constructor. Only the
/// concrete owner-only durable replay store can return it after the exact
/// dual-key claim succeeds.
#[derive(Debug)]
pub(crate) struct ClaimedNodeReleaseOperationV1 {
    authenticated_operation: AuthenticatedRuntimeReleaseOperationV1,
    selected_node_public_key: NodePublicKey,
}

impl ClaimedNodeReleaseOperationV1 {
    pub const fn release_request_hash(&self) -> Digest32 {
        self.authenticated_operation.release_request_hash()
    }

    pub const fn selected_node_public_key(&self) -> NodePublicKey {
        self.selected_node_public_key
    }

    pub(crate) fn validate_node_share(
        &self,
        node_share: &NodeLocalStoredShareV1,
        now: u64,
    ) -> Result<(), CustodyError> {
        node_share.validate_release_claim_context(
            &self.authenticated_operation,
            self.selected_node_public_key,
            now,
        )
    }

    pub fn binding(&self) -> &elastos_protected_content_contracts::ProtectedContentBindingV1 {
        self.authenticated_operation.binding()
    }

    pub fn recipient(&self) -> &elastos_protected_content_contracts::RecipientKeyIdentityV1 {
        self.authenticated_operation.recipient()
    }

    pub fn verify_node_rights_decision(
        &self,
        decision: &SignedNodeRightsDecisionV1,
        node_set: &NodeSetV1,
        now: u64,
    ) -> Result<VerifiedNodeRightsDecisionV1, CustodyError> {
        Ok(self
            .authenticated_operation
            .verify_node_rights_decision(decision, node_set, now)?)
    }

    pub fn validate_node_contribution_active_window(
        &self,
        issued_at: u64,
        expires_at: u64,
        decision: &VerifiedNodeRightsDecisionV1,
        now: u64,
    ) -> Result<(), CustodyError> {
        Ok(self
            .authenticated_operation
            .validate_node_contribution_active_window(issued_at, expires_at, decision, now)?)
    }

    pub fn verify_node_contribution(
        &self,
        contribution: &SignedNodeContributionV1,
        node_set: &NodeSetV1,
        now: u64,
    ) -> Result<VerifiedNodeContributionV1, CustodyError> {
        Ok(self
            .authenticated_operation
            .verify_node_contribution(contribution, node_set, now)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredNodeReleaseRecordV1 {
    rights_request_replay_claim_key: ReplayClaimKeyV1,
    rights_request_expires_at: u64,
    /// A V1 release also claims its key-release request. A V2 pool release
    /// has one claim key, its rights request's (L4).
    release_claim: Option<(ReplayClaimKeyV1, u64)>,
    audit_request_id: RuntimeReleaseAuditIdV1,
    operation_hash: Digest32,
    /// `None` until produced: one contribution for V1, one per signed
    /// recipient (1..=`MAX_SESSION_RECIPIENTS_V2`) for V2.
    contributions: Option<Vec<Vec<u8>>>,
}

impl StoredNodeReleaseRecordV1 {
    fn claim_only(
        rights_claim: ReplayClaimEntryV1,
        release_claim: ReplayClaimEntryV1,
        audit_request_id: RuntimeReleaseAuditIdV1,
        operation_hash: Digest32,
    ) -> Self {
        Self {
            rights_request_replay_claim_key: rights_claim.key(),
            rights_request_expires_at: rights_claim.expires_at(),
            release_claim: Some((release_claim.key(), release_claim.expires_at())),
            audit_request_id,
            operation_hash,
            contributions: None,
        }
    }

    fn pool_claim_only(
        rights_claim: ReplayClaimEntryV1,
        audit_request_id: RuntimeReleaseAuditIdV1,
        operation_hash: Digest32,
    ) -> Self {
        Self {
            rights_request_replay_claim_key: rights_claim.key(),
            rights_request_expires_at: rights_claim.expires_at(),
            release_claim: None,
            audit_request_id,
            operation_hash,
            contributions: None,
        }
    }

    const fn rights_request_replay_claim_key(&self) -> ReplayClaimKeyV1 {
        self.rights_request_replay_claim_key
    }

    fn release_request_replay_claim_key(&self) -> Option<ReplayClaimKeyV1> {
        self.release_claim.map(|(key, _)| key)
    }

    const fn is_pool_release(&self) -> bool {
        self.release_claim.is_none()
    }

    const fn audit_request_id(&self) -> RuntimeReleaseAuditIdV1 {
        self.audit_request_id
    }

    const fn operation_hash(&self) -> Digest32 {
        self.operation_hash
    }

    const fn rights_active(&self, now: u64) -> bool {
        self.rights_request_expires_at > now
    }

    fn release_active(&self, now: u64) -> bool {
        self.release_claim
            .is_some_and(|(_, expires_at)| expires_at > now)
    }

    fn any_active(&self, now: u64) -> bool {
        self.rights_active(now) || self.release_active(now)
    }

    /// The claim keys this record holds: one or two.
    fn claim_keys(&self) -> Vec<ReplayClaimKeyV1> {
        let mut keys = vec![self.rights_request_replay_claim_key];
        keys.extend(self.release_request_replay_claim_key());
        keys
    }

    /// A V1 record's one stored contribution.
    fn contribution_bytes(&self) -> Option<&[u8]> {
        if self.is_pool_release() {
            return None;
        }
        match self.contributions.as_deref() {
            Some([contribution]) => Some(contribution.as_slice()),
            _ => None,
        }
    }

    /// A V2 record's stored contributions, in the rights request's order.
    fn pool_contribution_bytes(&self) -> Option<&[Vec<u8>]> {
        if self.is_pool_release() {
            self.contributions.as_deref()
        } else {
            None
        }
    }

    fn set_contribution_bytes(&mut self, contribution_bytes: Vec<u8>) {
        self.contributions = Some(vec![contribution_bytes]);
    }

    fn set_pool_contribution_bytes(&mut self, contribution_bytes: Vec<Vec<u8>>) {
        self.contributions = Some(contribution_bytes);
    }

    /// V1: release key then rights key, as in `epc-rcl1`. V2: the one key
    /// twice, which no V1 record can equal (its two keys differ).
    fn sort_key(&self) -> [u8; REPLAY_CLAIM_KEY_BYTES * 2] {
        let mut bytes = [0u8; REPLAY_CLAIM_KEY_BYTES * 2];
        bytes[..REPLAY_CLAIM_KEY_BYTES].copy_from_slice(&replay_claim_sort_key(
            self.release_request_replay_claim_key()
                .unwrap_or(self.rights_request_replay_claim_key),
        ));
        bytes[REPLAY_CLAIM_KEY_BYTES..].copy_from_slice(&replay_claim_sort_key(
            self.rights_request_replay_claim_key(),
        ));
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct DurableReplayClaimStoreV1 {
    node_public_key: NodePublicKey,
    state_dir: PathBuf,
    lock_path: PathBuf,
    state_path: PathBuf,
    temp_path: PathBuf,
}

impl DurableReplayClaimStoreV1 {
    pub fn new(node_public_key: NodePublicKey, state_dir: impl Into<PathBuf>) -> Self {
        let state_dir = state_dir.into();
        Self {
            node_public_key,
            lock_path: state_dir.join("node-replay-claims.lock"),
            state_path: state_dir.join("node-replay-claims.v1"),
            temp_path: state_dir.join("node-replay-claims.tmp"),
            state_dir,
        }
    }

    pub const fn node_public_key(&self) -> NodePublicKey {
        self.node_public_key
    }

    #[cfg(test)]
    pub(crate) fn claim_node_release_operation(
        &mut self,
        operation: AuthenticatedRuntimeReleaseOperationV1,
        node_share: &NodeLocalStoredShareV1,
        selected_node_public_key: NodePublicKey,
        now: u64,
    ) -> Result<ClaimedNodeReleaseOperationV1, CustodyError> {
        if selected_node_public_key != self.node_public_key {
            return Err(CustodyError::BindingMismatch("store_node_public_key"));
        }
        node_share.validate_release_claim_context(&operation, selected_node_public_key, now)?;
        let rights_claim = ReplayClaimEntryV1::new(
            operation.rights_request_replay_claim_key(),
            operation
                .statement()
                .rights_request()
                .request()
                .expires_at(),
        );
        let release_claim = ReplayClaimEntryV1::new(
            operation.release_request_replay_claim_key(),
            operation.statement().release_request().expires_at(),
        );
        self.claim_claim_only_record(
            StoredNodeReleaseRecordV1::claim_only(
                rights_claim,
                release_claim,
                operation.statement().audit_request_id(),
                operation.operation_hash(),
            ),
            now,
        )?;
        Ok(ClaimedNodeReleaseOperationV1 {
            authenticated_operation: operation,
            selected_node_public_key,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn claim_or_replay_node_contribution(
        &mut self,
        operation: AuthenticatedRuntimeReleaseOperationV1,
        signed_rights_decision: &SignedNodeRightsDecisionV1,
        node_share: &NodeLocalStoredShareV1,
        node_signing_key: &SigningKey,
        node_custody_secret: &NodeCustodySecretKeyV1,
        recipient_public_key: &RecipientPublicKeyV1,
        issued_at: u64,
        expires_at: u64,
        now: u64,
    ) -> Result<SignedNodeContributionV1, CustodyError> {
        let mut hpke_rng = rand09::rngs::StdRng::try_from_os_rng()
            .map_err(|_| CustodyError::RandomnessUnavailable)?;
        self.claim_or_replay_node_contribution_with_rng(
            operation,
            signed_rights_decision,
            node_share,
            node_signing_key,
            node_custody_secret,
            recipient_public_key,
            issued_at,
            expires_at,
            now,
            &mut hpke_rng,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn claim_or_replay_node_contribution_with_rng<R: HpkeCryptoRng + HpkeRngCore>(
        &mut self,
        operation: AuthenticatedRuntimeReleaseOperationV1,
        signed_rights_decision: &SignedNodeRightsDecisionV1,
        node_share: &NodeLocalStoredShareV1,
        node_signing_key: &SigningKey,
        node_custody_secret: &NodeCustodySecretKeyV1,
        recipient_public_key: &RecipientPublicKeyV1,
        issued_at: u64,
        expires_at: u64,
        now: u64,
        hpke_rng: &mut R,
    ) -> Result<SignedNodeContributionV1, CustodyError> {
        let selected_node_public_key =
            NodePublicKey::new(node_signing_key.verifying_key().to_bytes())?;
        if selected_node_public_key != self.node_public_key {
            return Err(CustodyError::BindingMismatch("store_node_public_key"));
        }
        node_share.validate_release_claim_context(&operation, selected_node_public_key, now)?;
        if operation.recipient().encryption_suite_id() != CUSTODY_X_WING_AES256GCM_SUITE_ID_V1 {
            return Err(CustodyError::BindingMismatch(
                "recipient_encryption_suite_id",
            ));
        }
        if recipient_public_key.identity()? != *operation.recipient() {
            return Err(CustodyError::BindingMismatch("recipient_key_identity"));
        }
        let node_set = node_share.node_set()?;
        let decision =
            operation.verify_node_rights_decision(signed_rights_decision, &node_set, now)?;
        if decision.decision() != RightsDecisionV1::Allowed {
            return Err(CustodyError::Release(
                elastos_protected_content_contracts::KeyReleaseError::RightsDenied,
            ));
        }
        operation
            .validate_node_contribution_active_window(issued_at, expires_at, &decision, now)?;
        let node_entry = node_share.node()?;
        node_custody_secret.matches_node_entry(
            selected_node_public_key,
            node_entry.custody_public_key(),
            node_signing_key,
        )?;

        let rights_claim = ReplayClaimEntryV1::new(
            operation.rights_request_replay_claim_key(),
            operation
                .statement()
                .rights_request()
                .request()
                .expires_at(),
        );
        let release_claim = ReplayClaimEntryV1::new(
            operation.release_request_replay_claim_key(),
            operation.statement().release_request().expires_at(),
        );
        let audit_request_id = operation.statement().audit_request_id();
        let operation_hash = operation.operation_hash();
        let decision_bytes = signed_rights_decision.canonical_bytes()?;

        self.ensure_state_dir()?;
        let _lock = ExclusiveFileLock::acquire(&self.lock_path)?;
        self.cleanup_stale_temp()?;

        let mut records = self.read_state()?;
        records.retain(|record| record.any_active(now));

        match find_exact_record_index(
            &records,
            rights_claim.key(),
            Some(release_claim.key()),
            audit_request_id,
            operation_hash,
            now,
        )? {
            Some(index) => {
                return replay_exact_contribution(
                    &records[index],
                    &decision_bytes,
                    &operation,
                    &node_set,
                    now,
                );
            }
            None => {
                if has_conflicting_active_record(
                    &records,
                    &[rights_claim.key(), release_claim.key()],
                    audit_request_id,
                    now,
                ) {
                    return Err(CustodyError::Replay(ReplayClaimError::Unavailable));
                }
            }
        }

        let claim_only = StoredNodeReleaseRecordV1::claim_only(
            rights_claim,
            release_claim,
            audit_request_id,
            operation_hash,
        );
        records.push(claim_only);
        records.sort_unstable_by_key(StoredNodeReleaseRecordV1::sort_key);
        if records.len() > MAX_NODE_RELEASE_RECORDS {
            return Err(CustodyError::Replay(ReplayClaimError::Unavailable));
        }
        self.write_state(&records)?;

        let claimed = ClaimedNodeReleaseOperationV1 {
            authenticated_operation: operation,
            selected_node_public_key,
        };
        let contribution = produce_node_contribution_with_rng(
            &claimed,
            signed_rights_decision,
            node_share,
            node_signing_key,
            node_custody_secret,
            recipient_public_key,
            issued_at,
            expires_at,
            now,
            hpke_rng,
        )?;
        let contribution_bytes = contribution.canonical_bytes()?;

        let Some(record) = records.iter_mut().find(|record| {
            record.rights_request_replay_claim_key() == rights_claim.key()
                && record.release_request_replay_claim_key() == Some(release_claim.key())
                && record.audit_request_id() == audit_request_id
                && record.operation_hash() == operation_hash
        }) else {
            return Err(CustodyError::Replay(ReplayClaimError::Unavailable));
        };
        record.set_contribution_bytes(contribution_bytes);
        self.write_state(&records)?;
        Ok(contribution)
    }

    /// One durable claim for a V2 pool release, keyed by its rights request
    /// alone (L4), yields one contribution per wallet-signed recipient. An
    /// exact retry replays the stored contributions without new effects; the
    /// same claim with another operation or audit id is refused. The
    /// recipients come from the operation.
    #[allow(
        clippy::too_many_arguments,
        reason = "the pool release binds the authenticated operation, decision, share and both node keys explicitly, as the V1 claim does"
    )]
    pub fn claim_or_replay_pool_contributions(
        &mut self,
        operation: AuthenticatedRuntimeReleaseOperationV2,
        signed_rights_decision: &SignedNodeRightsDecisionV1,
        node_share: &NodeLocalStoredShareV1,
        node_signing_key: &SigningKey,
        node_custody_secret: &NodeCustodySecretKeyV1,
        issued_at: u64,
        expires_at: u64,
        now: u64,
    ) -> Result<Vec<SignedNodeContributionV1>, CustodyError> {
        let mut hpke_rng = rand09::rngs::StdRng::try_from_os_rng()
            .map_err(|_| CustodyError::RandomnessUnavailable)?;
        self.claim_or_replay_pool_contributions_with_rng(
            operation,
            signed_rights_decision,
            node_share,
            node_signing_key,
            node_custody_secret,
            issued_at,
            expires_at,
            now,
            &mut hpke_rng,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the pool release binds the authenticated operation, decision, share and both node keys explicitly, as the V1 claim does"
    )]
    pub(crate) fn claim_or_replay_pool_contributions_with_rng<R: HpkeCryptoRng + HpkeRngCore>(
        &mut self,
        operation: AuthenticatedRuntimeReleaseOperationV2,
        signed_rights_decision: &SignedNodeRightsDecisionV1,
        node_share: &NodeLocalStoredShareV1,
        node_signing_key: &SigningKey,
        node_custody_secret: &NodeCustodySecretKeyV1,
        issued_at: u64,
        expires_at: u64,
        now: u64,
        hpke_rng: &mut R,
    ) -> Result<Vec<SignedNodeContributionV1>, CustodyError> {
        let selected_node_public_key =
            NodePublicKey::new(node_signing_key.verifying_key().to_bytes())?;
        if selected_node_public_key != self.node_public_key {
            return Err(CustodyError::BindingMismatch("store_node_public_key"));
        }
        node_share.validate_pool_release_claim_context(
            &operation,
            selected_node_public_key,
            now,
        )?;
        let node_set = node_share.node_set()?;
        let decision =
            operation.verify_node_rights_decision(signed_rights_decision, &node_set, now)?;
        if decision.decision() != RightsDecisionV1::Allowed {
            return Err(CustodyError::Release(
                elastos_protected_content_contracts::KeyReleaseError::RightsDenied,
            ));
        }
        operation
            .validate_node_contribution_active_window(issued_at, expires_at, &decision, now)?;
        let node_entry = node_share.node()?;
        node_custody_secret.matches_node_entry(
            selected_node_public_key,
            node_entry.custody_public_key(),
            node_signing_key,
        )?;

        let rights_claim = ReplayClaimEntryV1::new(
            operation.rights_request_replay_claim_key(),
            operation
                .statement()
                .rights_request()
                .request()
                .expires_at(),
        );
        let audit_request_id = operation.statement().audit_request_id();
        let operation_hash = operation.operation_hash();
        let decision_bytes = signed_rights_decision.canonical_bytes()?;

        self.ensure_state_dir()?;
        let _lock = ExclusiveFileLock::acquire(&self.lock_path)?;
        self.cleanup_stale_temp()?;

        let mut records = self.read_state()?;
        records.retain(|record| record.any_active(now));
        match find_exact_record_index(
            &records,
            rights_claim.key(),
            None,
            audit_request_id,
            operation_hash,
            now,
        )? {
            Some(index) => {
                return replay_exact_pool_contributions(
                    &records[index],
                    &decision_bytes,
                    &operation,
                    &node_set,
                    now,
                );
            }
            None => {
                if has_conflicting_active_record(
                    &records,
                    &[rights_claim.key()],
                    audit_request_id,
                    now,
                ) {
                    return Err(CustodyError::Replay(ReplayClaimError::Unavailable));
                }
            }
        }

        records.push(StoredNodeReleaseRecordV1::pool_claim_only(
            rights_claim,
            audit_request_id,
            operation_hash,
        ));
        records.sort_unstable_by_key(StoredNodeReleaseRecordV1::sort_key);
        if records.len() > MAX_NODE_RELEASE_RECORDS {
            return Err(CustodyError::Replay(ReplayClaimError::Unavailable));
        }
        self.write_state(&records)?;

        let contributions = produce_pool_contributions_with_rng(
            &operation,
            selected_node_public_key,
            signed_rights_decision,
            node_share,
            node_signing_key,
            node_custody_secret,
            issued_at,
            expires_at,
            now,
            hpke_rng,
        )?;
        let contribution_bytes = contributions
            .iter()
            .map(CanonicalContract::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()?;

        let Some(record) = records.iter_mut().find(|record| {
            record.rights_request_replay_claim_key() == rights_claim.key()
                && record.is_pool_release()
                && record.audit_request_id() == audit_request_id
                && record.operation_hash() == operation_hash
        }) else {
            return Err(CustodyError::Replay(ReplayClaimError::Unavailable));
        };
        record.set_pool_contribution_bytes(contribution_bytes);
        self.write_state(&records)?;
        Ok(contributions)
    }

    #[cfg(test)]
    fn claim_pair_inner(
        &self,
        mut claims: [ReplayClaimEntryV1; 2],
        now: u64,
    ) -> Result<(), ReplayClaimError> {
        sort_claims(&mut claims);
        if claims[0].key() == claims[1].key() {
            return Err(ReplayClaimError::Unavailable);
        }
        self.claim_claim_only_record(
            StoredNodeReleaseRecordV1::claim_only(
                claims[0],
                claims[1],
                synthetic_runtime_release_audit_id(&claims),
                synthetic_operation_hash(&claims),
            ),
            now,
        )
    }

    #[cfg(test)]
    fn claim_claim_only_record(
        &self,
        record: StoredNodeReleaseRecordV1,
        now: u64,
    ) -> Result<(), ReplayClaimError> {
        self.ensure_state_dir()?;
        let _lock = ExclusiveFileLock::acquire(&self.lock_path)?;
        self.cleanup_stale_temp()?;

        let mut records = self.read_state()?;
        records.retain(|existing| existing.any_active(now));
        if has_conflicting_active_record(
            &records,
            &record.claim_keys(),
            record.audit_request_id(),
            now,
        ) {
            return Err(ReplayClaimError::AlreadyClaimed);
        }
        records.push(record);
        records.sort_unstable_by_key(StoredNodeReleaseRecordV1::sort_key);
        if records.len() > MAX_NODE_RELEASE_RECORDS {
            return Err(ReplayClaimError::Unavailable);
        }
        self.write_state(&records)
    }

    fn ensure_state_dir(&self) -> Result<(), ReplayClaimError> {
        let parent = self
            .state_dir
            .parent()
            .ok_or(ReplayClaimError::Unavailable)?;
        validate_owner_only_directory(parent)?;
        match fs::symlink_metadata(&self.state_dir) {
            Ok(metadata) => validate_owner_only_directory_metadata(&self.state_dir, &metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_owner_only_directory(&self.state_dir)?;
                sync_directory(parent)?;
                validate_owner_only_directory(&self.state_dir)
            }
            Err(_) => Err(ReplayClaimError::Unavailable),
        }
    }

    fn cleanup_stale_temp(&self) -> Result<(), ReplayClaimError> {
        match fs::symlink_metadata(&self.temp_path) {
            Ok(metadata) => {
                validate_owner_only_regular_file_metadata(&self.temp_path, &metadata)?;
                fs::remove_file(&self.temp_path).map_err(|_| ReplayClaimError::Unavailable)?;
                sync_directory(&self.state_dir)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(ReplayClaimError::Unavailable),
        }
    }

    fn read_state(&self) -> Result<Vec<StoredNodeReleaseRecordV1>, ReplayClaimError> {
        let metadata = match fs::symlink_metadata(&self.state_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(ReplayClaimError::Unavailable),
        };
        validate_owner_only_regular_file_metadata(&self.state_path, &metadata)?;
        let metadata_len =
            usize::try_from(metadata.len()).map_err(|_| ReplayClaimError::Unavailable)?;
        if metadata_len > MAX_STATE_BYTES {
            return Err(ReplayClaimError::Unavailable);
        }

        let file = open_owner_only_file(&self.state_path, false)?;
        let mut bytes = Vec::with_capacity(metadata_len);
        file.take((MAX_STATE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ReplayClaimError::Unavailable)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(ReplayClaimError::Unavailable);
        }
        decode_state(&bytes, self.node_public_key)
    }

    fn write_state(&self, records: &[StoredNodeReleaseRecordV1]) -> Result<(), ReplayClaimError> {
        match fs::symlink_metadata(&self.state_path) {
            Ok(metadata) => validate_owner_only_regular_file_metadata(&self.state_path, &metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ReplayClaimError::Unavailable),
        }
        let mut file = open_owner_only_temp_file_for_write(&self.temp_path)?;
        let bytes = encode_state(self.node_public_key, records)?;
        file.write_all(&bytes)
            .map_err(|_| ReplayClaimError::Unavailable)?;
        file.sync_all().map_err(|_| ReplayClaimError::Unavailable)?;
        validate_owner_only_regular_file_metadata(
            &self.temp_path,
            &file.metadata().map_err(|_| ReplayClaimError::Unavailable)?,
        )?;
        maybe_inject_test_fault(&self.state_dir)?;
        fs::rename(&self.temp_path, &self.state_path).map_err(|_| ReplayClaimError::Unavailable)?;
        sync_directory(&self.state_dir)
    }
}

#[derive(Debug)]
struct ExclusiveFileLock {
    file: Option<Flock<File>>,
}

impl ExclusiveFileLock {
    fn acquire(path: &Path) -> Result<Self, ReplayClaimError> {
        let file = open_or_create_owner_only_lock_file(path)?;
        let file = Flock::lock(file, FlockArg::LockExclusive)
            .map_err(|_| ReplayClaimError::Unavailable)?;
        validate_owner_only_regular_file_metadata(
            path,
            &file.metadata().map_err(|_| ReplayClaimError::Unavailable)?,
        )?;
        Ok(Self { file: Some(file) })
    }
}

impl Drop for ExclusiveFileLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = file.unlock();
        }
    }
}

fn create_owner_only_directory(path: &Path) -> Result<(), ReplayClaimError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err(ReplayClaimError::Unavailable),
    }
}

fn open_owner_only_file(path: &Path, write: bool) -> Result<File, ReplayClaimError> {
    let mut options = OpenOptions::new();
    options.read(true).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| ReplayClaimError::Unavailable)?;
    validate_owner_only_regular_file_metadata(
        path,
        &file.metadata().map_err(|_| ReplayClaimError::Unavailable)?,
    )?;
    Ok(file)
}

fn open_or_create_owner_only_lock_file(path: &Path) -> Result<File, ReplayClaimError> {
    let parent = path.parent().ok_or(ReplayClaimError::Unavailable)?;
    validate_owner_only_directory(parent)?;

    let mut create_new = OpenOptions::new();
    create_new.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create_new.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    match create_new.open(path) {
        Ok(file) => {
            validate_owner_only_regular_file_metadata(
                path,
                &file.metadata().map_err(|_| ReplayClaimError::Unavailable)?,
            )?;
            sync_directory(parent)?;
            Ok(file)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            open_owner_only_file(path, true)
        }
        Err(_) => Err(ReplayClaimError::Unavailable),
    }
}

fn open_owner_only_temp_file_for_write(path: &Path) -> Result<File, ReplayClaimError> {
    let parent = path.parent().ok_or(ReplayClaimError::Unavailable)?;
    validate_owner_only_directory(parent)?;

    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| ReplayClaimError::Unavailable)?;
    validate_owner_only_regular_file_metadata(
        path,
        &file.metadata().map_err(|_| ReplayClaimError::Unavailable)?,
    )?;
    sync_directory(parent)?;
    Ok(file)
}

fn sync_directory(path: &Path) -> Result<(), ReplayClaimError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| ReplayClaimError::Unavailable)
}

fn validate_owner_only_directory(path: &Path) -> Result<(), ReplayClaimError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ReplayClaimError::Unavailable)?;
    validate_owner_only_directory_metadata(path, &metadata)
}

fn validate_owner_only_directory_metadata(
    _path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ReplayClaimError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ReplayClaimError::Unavailable);
    }
    validate_owner_and_mode(metadata, 0o700)
}

fn validate_owner_only_regular_file_metadata(
    _path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ReplayClaimError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ReplayClaimError::Unavailable);
    }
    validate_owner_and_mode(metadata, 0o600)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.nlink() != 1 {
            return Err(ReplayClaimError::Unavailable);
        }
    }
    Ok(())
}

fn validate_owner_and_mode(
    metadata: &fs::Metadata,
    exact_mode: u32,
) -> Result<(), ReplayClaimError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.uid() != geteuid().as_raw() || metadata.mode() & 0o777 != exact_mode {
            return Err(ReplayClaimError::Unavailable);
        }
    }
    Ok(())
}

#[cfg(test)]
fn sort_claims(claims: &mut [ReplayClaimEntryV1; 2]) {
    if replay_claim_sort_key(claims[1].key()) < replay_claim_sort_key(claims[0].key()) {
        claims.swap(0, 1);
    }
}

fn replay_claim_sort_key(key: ReplayClaimKeyV1) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    bytes[..32].copy_from_slice(key.authority_scope_hash().as_bytes());
    bytes[32..].copy_from_slice(key.nonce().as_bytes());
    bytes
}

fn encode_state(
    node_public_key: NodePublicKey,
    records: &[StoredNodeReleaseRecordV1],
) -> Result<Vec<u8>, ReplayClaimError> {
    encode_state_with(STATE_MAGIC_V2, node_public_key, records)
}

/// The pre-Plan B format, kept to prove an `epc-rcl1` file still reads.
#[cfg(test)]
fn encode_state_rcl1(
    node_public_key: NodePublicKey,
    records: &[StoredNodeReleaseRecordV1],
) -> Result<Vec<u8>, ReplayClaimError> {
    if records
        .iter()
        .any(StoredNodeReleaseRecordV1::is_pool_release)
    {
        return Err(ReplayClaimError::Unavailable);
    }
    encode_state_with(STATE_MAGIC_V1, node_public_key, records)
}

fn encode_state_with(
    magic: &[u8; 8],
    node_public_key: NodePublicKey,
    records: &[StoredNodeReleaseRecordV1],
) -> Result<Vec<u8>, ReplayClaimError> {
    if records.len() > MAX_NODE_RELEASE_RECORDS {
        return Err(ReplayClaimError::Unavailable);
    }
    let kind_tagged = magic == STATE_MAGIC_V2;
    let mut payload = Vec::with_capacity(STATE_HEADER_BYTES);
    payload.extend_from_slice(magic);
    payload.extend_from_slice(node_public_key.as_bytes());
    payload.extend_from_slice(&(records.len() as u32).to_be_bytes());
    let mut previous = None;
    for record in records {
        let sort_key = record.sort_key();
        if previous.is_some_and(|prior| prior >= sort_key) {
            return Err(ReplayClaimError::Unavailable);
        }
        previous = Some(sort_key);
        if record.is_pool_release() {
            payload.push(RECORD_KIND_POOL_RELEASE_V2);
            encode_pool_release_record(&mut payload, record)?;
        } else {
            if kind_tagged {
                payload.push(RECORD_KIND_RELEASE_V1);
            }
            encode_release_record(&mut payload, record)?;
        }
        if payload.len() > MAX_STATE_PAYLOAD_BYTES {
            return Err(ReplayClaimError::Unavailable);
        }
    }
    let digest = state_integrity_digest(&payload);
    let mut bytes = payload;
    bytes.extend_from_slice(&digest);
    if bytes.len() > MAX_STATE_BYTES {
        return Err(ReplayClaimError::Unavailable);
    }
    Ok(bytes)
}

fn encode_claim(payload: &mut Vec<u8>, key: ReplayClaimKeyV1, expires_at: u64) {
    payload.extend_from_slice(key.authority_scope_hash().as_bytes());
    payload.extend_from_slice(key.nonce().as_bytes());
    payload.extend_from_slice(&expires_at.to_be_bytes());
}

fn encode_contribution(payload: &mut Vec<u8>, contribution: &[u8]) -> Result<(), ReplayClaimError> {
    if contribution.is_empty() || contribution.len() > MAX_STORED_CONTRIBUTION_BYTES {
        return Err(ReplayClaimError::Unavailable);
    }
    payload.extend_from_slice(
        &u16::try_from(contribution.len())
            .map_err(|_| ReplayClaimError::Unavailable)?
            .to_be_bytes(),
    );
    payload.extend_from_slice(contribution);
    Ok(())
}

/// The `epc-rcl1` record layout, also the V1 record body in `epc-rcl2`.
fn encode_release_record(
    payload: &mut Vec<u8>,
    record: &StoredNodeReleaseRecordV1,
) -> Result<(), ReplayClaimError> {
    let (release_key, release_expires_at) =
        record.release_claim.ok_or(ReplayClaimError::Unavailable)?;
    encode_claim(
        payload,
        record.rights_request_replay_claim_key,
        record.rights_request_expires_at,
    );
    encode_claim(payload, release_key, release_expires_at);
    payload.extend_from_slice(record.audit_request_id().digest().as_bytes());
    payload.extend_from_slice(record.operation_hash().as_bytes());
    match record.contributions.as_deref() {
        Some([contribution]) => {
            payload.push(STORED_RESULT_STATE_PRESENT);
            encode_contribution(payload, contribution)
        }
        Some(_) => Err(ReplayClaimError::Unavailable),
        None => {
            payload.push(STORED_RESULT_STATE_CLAIM_ONLY);
            payload.extend_from_slice(&0u16.to_be_bytes());
            Ok(())
        }
    }
}

/// A V2 record body: one claim, the audit id and operation hash, then a
/// state byte, a count and each contribution.
fn encode_pool_release_record(
    payload: &mut Vec<u8>,
    record: &StoredNodeReleaseRecordV1,
) -> Result<(), ReplayClaimError> {
    encode_claim(
        payload,
        record.rights_request_replay_claim_key,
        record.rights_request_expires_at,
    );
    payload.extend_from_slice(record.audit_request_id().digest().as_bytes());
    payload.extend_from_slice(record.operation_hash().as_bytes());
    match record.contributions.as_deref() {
        Some(contributions) => {
            if contributions.is_empty() || contributions.len() > MAX_SESSION_RECIPIENTS_V2 {
                return Err(ReplayClaimError::Unavailable);
            }
            payload.push(STORED_RESULT_STATE_PRESENT);
            payload.push(
                u8::try_from(contributions.len()).map_err(|_| ReplayClaimError::Unavailable)?,
            );
            for contribution in contributions {
                encode_contribution(payload, contribution)?;
            }
            Ok(())
        }
        None => {
            payload.push(STORED_RESULT_STATE_CLAIM_ONLY);
            payload.push(0);
            Ok(())
        }
    }
}

fn decode_state(
    bytes: &[u8],
    expected_node_public_key: NodePublicKey,
) -> Result<Vec<StoredNodeReleaseRecordV1>, ReplayClaimError> {
    if bytes.len() < STATE_HEADER_BYTES + STATE_DIGEST_BYTES {
        return Err(ReplayClaimError::Unavailable);
    }
    let (payload, digest) = bytes.split_at(bytes.len() - STATE_DIGEST_BYTES);
    let kind_tagged = if payload[..8] == *STATE_MAGIC_V2 {
        true
    } else if payload[..8] == *STATE_MAGIC_V1 {
        false
    } else {
        return Err(ReplayClaimError::Unavailable);
    };
    if state_integrity_digest(payload) != digest {
        return Err(ReplayClaimError::Unavailable);
    }
    if payload[8..40] != *expected_node_public_key.as_bytes() {
        return Err(ReplayClaimError::Unavailable);
    }
    let count = u32::from_be_bytes(
        payload[40..44]
            .try_into()
            .map_err(|_| ReplayClaimError::Unavailable)?,
    ) as usize;
    if count > MAX_NODE_RELEASE_RECORDS {
        return Err(ReplayClaimError::Unavailable);
    }

    let mut records = Vec::with_capacity(count);
    let mut previous = None;
    let mut offset = STATE_HEADER_BYTES;
    for _ in 0..count {
        let kind = if kind_tagged {
            take(payload, &mut offset, 1)?[0]
        } else {
            RECORD_KIND_RELEASE_V1
        };
        let record = match kind {
            RECORD_KIND_RELEASE_V1 => decode_release_record(payload, &mut offset)?,
            RECORD_KIND_POOL_RELEASE_V2 if kind_tagged => {
                decode_pool_release_record(payload, &mut offset)?
            }
            _ => return Err(ReplayClaimError::Unavailable),
        };
        let sort_key = record.sort_key();
        if previous.is_some_and(|prior| prior >= sort_key) {
            return Err(ReplayClaimError::Unavailable);
        }
        previous = Some(sort_key);
        records.push(record);
    }
    if offset != payload.len() {
        return Err(ReplayClaimError::Unavailable);
    }
    Ok(records)
}

fn take<'a>(
    payload: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], ReplayClaimError> {
    let end = offset
        .checked_add(length)
        .ok_or(ReplayClaimError::Unavailable)?;
    let bytes = payload
        .get(*offset..end)
        .ok_or(ReplayClaimError::Unavailable)?;
    *offset = end;
    Ok(bytes)
}

fn take_array<const N: usize>(
    payload: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], ReplayClaimError> {
    take(payload, offset, N)?
        .try_into()
        .map_err(|_| ReplayClaimError::Unavailable)
}

fn decode_claim(
    payload: &[u8],
    offset: &mut usize,
) -> Result<(ReplayClaimKeyV1, u64), ReplayClaimError> {
    let authority_scope_hash = take_array::<32>(payload, offset)?;
    let nonce = take_array::<16>(payload, offset)?;
    let expires_at = u64::from_be_bytes(take_array::<8>(payload, offset)?);
    Ok((
        ReplayClaimKeyV1::new(
            Digest32::new(authority_scope_hash),
            ReplayNonce16::new(nonce),
        ),
        expires_at,
    ))
}

fn decode_contribution(payload: &[u8], offset: &mut usize) -> Result<Vec<u8>, ReplayClaimError> {
    let length = usize::from(u16::from_be_bytes(take_array::<2>(payload, offset)?));
    if length == 0 || length > MAX_STORED_CONTRIBUTION_BYTES {
        return Err(ReplayClaimError::Unavailable);
    }
    Ok(take(payload, offset, length)?.to_vec())
}

fn decode_audit_and_operation(
    payload: &[u8],
    offset: &mut usize,
) -> Result<(RuntimeReleaseAuditIdV1, Digest32), ReplayClaimError> {
    let audit_request_id =
        RuntimeReleaseAuditIdV1::new(Digest32::new(take_array::<32>(payload, offset)?))
            .map_err(|_| ReplayClaimError::Unavailable)?;
    let operation_hash = Digest32::new(take_array::<32>(payload, offset)?);
    Ok((audit_request_id, operation_hash))
}

fn decode_release_record(
    payload: &[u8],
    offset: &mut usize,
) -> Result<StoredNodeReleaseRecordV1, ReplayClaimError> {
    let (rights_key, rights_expires_at) = decode_claim(payload, offset)?;
    let release_claim = decode_claim(payload, offset)?;
    let (audit_request_id, operation_hash) = decode_audit_and_operation(payload, offset)?;
    let state = take(payload, offset, 1)?[0];
    let contributions = match state {
        STORED_RESULT_STATE_CLAIM_ONLY => {
            if take_array::<2>(payload, offset)? != [0, 0] {
                return Err(ReplayClaimError::Unavailable);
            }
            None
        }
        STORED_RESULT_STATE_PRESENT => Some(vec![decode_contribution(payload, offset)?]),
        _ => return Err(ReplayClaimError::Unavailable),
    };
    Ok(StoredNodeReleaseRecordV1 {
        rights_request_replay_claim_key: rights_key,
        rights_request_expires_at: rights_expires_at,
        release_claim: Some(release_claim),
        audit_request_id,
        operation_hash,
        contributions,
    })
}

fn decode_pool_release_record(
    payload: &[u8],
    offset: &mut usize,
) -> Result<StoredNodeReleaseRecordV1, ReplayClaimError> {
    let (rights_key, rights_expires_at) = decode_claim(payload, offset)?;
    let (audit_request_id, operation_hash) = decode_audit_and_operation(payload, offset)?;
    let [state, count] = take_array::<2>(payload, offset)?;
    let count = usize::from(count);
    let contributions = match state {
        STORED_RESULT_STATE_CLAIM_ONLY if count == 0 => None,
        STORED_RESULT_STATE_PRESENT if (1..=MAX_SESSION_RECIPIENTS_V2).contains(&count) => {
            let mut contributions = Vec::with_capacity(count);
            for _ in 0..count {
                contributions.push(decode_contribution(payload, offset)?);
            }
            Some(contributions)
        }
        _ => return Err(ReplayClaimError::Unavailable),
    };
    Ok(StoredNodeReleaseRecordV1 {
        rights_request_replay_claim_key: rights_key,
        rights_request_expires_at: rights_expires_at,
        release_claim: None,
        audit_request_id,
        operation_hash,
        contributions,
    })
}

/// A record conflicts when it is active and shares any claim key with the new
/// claim, or its audit id.
fn has_conflicting_active_record(
    records: &[StoredNodeReleaseRecordV1],
    claim_keys: &[ReplayClaimKeyV1],
    audit_request_id: RuntimeReleaseAuditIdV1,
    now: u64,
) -> bool {
    records.iter().any(|record| {
        record.any_active(now)
            && (record
                .claim_keys()
                .iter()
                .any(|key| claim_keys.contains(key))
                || record.audit_request_id() == audit_request_id)
    })
}

fn find_exact_record_index(
    records: &[StoredNodeReleaseRecordV1],
    rights_request_replay_claim_key: ReplayClaimKeyV1,
    release_request_replay_claim_key: Option<ReplayClaimKeyV1>,
    audit_request_id: RuntimeReleaseAuditIdV1,
    operation_hash: Digest32,
    now: u64,
) -> Result<Option<usize>, ReplayClaimError> {
    let mut exact = None;
    for (index, record) in records.iter().enumerate() {
        if !record.any_active(now) {
            continue;
        }
        let same_claims = record.rights_request_replay_claim_key()
            == rights_request_replay_claim_key
            && record.release_request_replay_claim_key() == release_request_replay_claim_key;
        if same_claims && record.audit_request_id() == audit_request_id {
            if record.operation_hash() != operation_hash {
                return Err(ReplayClaimError::Unavailable);
            }
            exact = Some(index);
        }
    }
    Ok(exact)
}

/// The stored contributions of an exact V2 retry, re-verified against the
/// operation and its recipients in order.
fn replay_exact_pool_contributions(
    record: &StoredNodeReleaseRecordV1,
    decision_bytes: &[u8],
    operation: &AuthenticatedRuntimeReleaseOperationV2,
    node_set: &NodeSetV1,
    now: u64,
) -> Result<Vec<SignedNodeContributionV1>, CustodyError> {
    let stored = record
        .pool_contribution_bytes()
        .ok_or(CustodyError::Replay(ReplayClaimError::Unavailable))?;
    let recipients = operation
        .statement()
        .rights_request()
        .request()
        .recipients();
    if stored.len() != recipients.len() {
        return Err(CustodyError::Replay(ReplayClaimError::Unavailable));
    }
    stored
        .iter()
        .zip(recipients)
        .map(
            |(bytes, recipient)| -> Result<SignedNodeContributionV1, CustodyError> {
                let contribution = SignedNodeContributionV1::from_canonical_bytes(bytes)?;
                if contribution
                    .statement()
                    .signed_rights_decision()
                    .canonical_bytes()?
                    != decision_bytes
                {
                    return Err(CustodyError::BindingMismatch("node_rights_decision"));
                }
                operation.verify_node_contribution(&contribution, node_set, recipient, now)?;
                Ok(contribution)
            },
        )
        .collect()
}

fn replay_exact_contribution(
    record: &StoredNodeReleaseRecordV1,
    decision_bytes: &[u8],
    operation: &AuthenticatedRuntimeReleaseOperationV1,
    node_set: &NodeSetV1,
    now: u64,
) -> Result<SignedNodeContributionV1, CustodyError> {
    let contribution_bytes = record
        .contribution_bytes()
        .ok_or(CustodyError::Replay(ReplayClaimError::Unavailable))?;
    let contribution = SignedNodeContributionV1::from_canonical_bytes(contribution_bytes)?;
    if contribution
        .statement()
        .signed_rights_decision()
        .canonical_bytes()?
        != decision_bytes
    {
        return Err(CustodyError::BindingMismatch("node_rights_decision"));
    }
    operation.verify_node_contribution(&contribution, node_set, now)?;
    Ok(contribution)
}

#[cfg(test)]
fn synthetic_runtime_release_audit_id(claims: &[ReplayClaimEntryV1; 2]) -> RuntimeReleaseAuditIdV1 {
    let mut hasher = Sha256::new();
    hasher.update(b"elastos/protected-content/node-replay-claims/test-audit-id/v1");
    for claim in claims {
        hasher.update(claim.key().authority_scope_hash().as_bytes());
        hasher.update(claim.key().nonce().as_bytes());
        hasher.update(claim.expires_at().to_be_bytes());
    }
    RuntimeReleaseAuditIdV1::new(Digest32::new(hasher.finalize().into())).unwrap()
}

#[cfg(test)]
fn synthetic_operation_hash(claims: &[ReplayClaimEntryV1; 2]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(b"elastos/protected-content/node-replay-claims/test-operation-hash/v1");
    for claim in claims {
        hasher.update(claim.key().authority_scope_hash().as_bytes());
        hasher.update(claim.key().nonce().as_bytes());
        hasher.update(claim.expires_at().to_be_bytes());
    }
    Digest32::new(hasher.finalize().into())
}

fn state_integrity_digest(payload: &[u8]) -> [u8; STATE_DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(STATE_DIGEST_DOMAIN);
    hasher.update(payload);
    hasher.finalize().into()
}

#[cfg(not(test))]
fn maybe_inject_test_fault(_state_dir: &Path) -> Result<(), ReplayClaimError> {
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestFault {
    RenameStateDirBeforeRename,
}

#[cfg(test)]
static TEST_FAULT: std::sync::Mutex<Option<(TestFault, PathBuf)>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn maybe_inject_test_fault(state_dir: &Path) -> Result<(), ReplayClaimError> {
    let fault = {
        let mut guard = TEST_FAULT
            .lock()
            .map_err(|_| ReplayClaimError::Unavailable)?;
        match guard.as_ref() {
            Some((fault, path)) if path == state_dir => {
                let fault = *fault;
                guard.take();
                Some(fault)
            }
            _ => None,
        }
    };
    match fault {
        Some(TestFault::RenameStateDirBeforeRename) => {
            let moved = state_dir.with_extension("fault");
            if moved.exists() {
                if moved.is_dir() {
                    fs::remove_dir_all(&moved).map_err(|_| ReplayClaimError::Unavailable)?;
                } else {
                    fs::remove_file(&moved).map_err(|_| ReplayClaimError::Unavailable)?;
                }
            }
            fs::rename(state_dir, moved).map_err(|_| ReplayClaimError::Unavailable)
        }
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Barrier};

    use ed25519_dalek::SigningKey;
    use hpke::rand_core::{CryptoRng, RngCore};
    use rand09::{rngs::StdRng, SeedableRng as _};

    use super::*;
    use crate::test_support::{
        authenticated_runtime_release_operation_for_envelope_and_recipient_seed,
        node_custody_secret, node_public_key, node_signing_key, provisioned_envelope,
        recipient_public_key, signed_node_decision,
        verified_release_request_for_envelope_and_recipient_seed, NOW,
    };
    use elastos_protected_content_contracts::CustodyEnvelopeV1;

    #[derive(Debug)]
    struct PanicRng;

    impl CryptoRng for PanicRng {}

    impl RngCore for PanicRng {
        fn next_u32(&mut self) -> u32 {
            panic!("replay path must not consume randomness")
        }

        fn next_u64(&mut self) -> u64 {
            panic!("replay path must not consume randomness")
        }

        fn fill_bytes(&mut self, _dest: &mut [u8]) {
            panic!("replay path must not consume randomness")
        }
    }

    fn claim(seed: u8, expiry: u64) -> ReplayClaimEntryV1 {
        ReplayClaimEntryV1::new(
            ReplayClaimKeyV1::new(Digest32::new([seed; 32]), ReplayNonce16::new([seed; 16])),
            expiry,
        )
    }

    fn store_node(seed: u8) -> NodePublicKey {
        NodePublicKey::new(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap()
    }

    fn owner_only_tempdir() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        temp
    }

    fn store_dir(temp: &tempfile::TempDir) -> PathBuf {
        temp.path().join("replay")
    }

    fn durable_store(seed: u8, temp: &tempfile::TempDir) -> DurableReplayClaimStoreV1 {
        DurableReplayClaimStoreV1::new(store_node(seed), store_dir(temp))
    }

    fn node_share_for(envelope: &CustodyEnvelopeV1, node_seed: u8) -> NodeLocalStoredShareV1 {
        NodeLocalStoredShareV1::extract_from_envelope(envelope, node_public_key(node_seed)).unwrap()
    }

    fn derived_max_signed_node_contribution_bytes() -> usize {
        const DIGEST_BYTES: usize = 32;
        const U64_BYTES: usize = 8;
        const U32_BYTES: usize = 4;
        const U16_BYTES: usize = 2;
        const U8_BYTES: usize = 1;
        const WALLET_ADDRESS_BYTES: usize = 20;
        const ED25519_SIGNATURE_BYTES: usize = 64;

        let max_encrypted_content_identity_bytes =
            "elastos.protected-content.encrypted-content/v1".len() + 1 + DIGEST_BYTES + U64_BYTES;
        let max_rights_policy_identity_bytes = "elastos.protected-content.rights-policy-identity/v1"
            .len()
            + 1
            + DIGEST_BYTES + U32_BYTES;
        let max_profile_identity_bytes =
            "elastos.protected-content.profile-identity/v1".len() + 1 + DIGEST_BYTES;
        let max_custody_epoch_identity_bytes = "elastos.protected-content.custody-epoch-identity/v1"
            .len()
            + 1
            + DIGEST_BYTES
            + DIGEST_BYTES
            + U8_BYTES
            + U8_BYTES + U32_BYTES;
        let max_key_envelope_identity_bytes = "elastos.protected-content.key-envelope/v1".len()
            + 1
            + U16_BYTES
            + max_encrypted_content_identity_bytes
            + DIGEST_BYTES
            + U32_BYTES
            + DIGEST_BYTES
            + U8_BYTES
            + U8_BYTES
            + U16_BYTES
            + max_custody_epoch_identity_bytes;
        let max_protected_content_binding_bytes = "elastos.protected-content.binding/v1".len()
            + 1
            + U16_BYTES
            + max_encrypted_content_identity_bytes
            + U16_BYTES
            + max_key_envelope_identity_bytes
            + U16_BYTES
            + max_rights_policy_identity_bytes
            + U16_BYTES
            + max_profile_identity_bytes
            + WALLET_ADDRESS_BYTES
            + DIGEST_BYTES;
        let max_recipient_key_identity_bytes = "elastos.protected-content.recipient-key-identity/v1"
            .len()
            + 1
            + U16_BYTES
            + elastos_protected_content_contracts::MAX_RECIPIENT_ENCRYPTION_SUITE_ID_BYTES
            + DIGEST_BYTES;
        let max_recipient_sealed_contribution_bytes =
            "elastos.protected-content.recipient-sealed-contribution/v1".len()
                + 1
                + U16_BYTES
                + max_recipient_key_identity_bytes
                + U16_BYTES
                + elastos_protected_content_contracts::MAX_RECIPIENT_SEALED_CONTRIBUTION_BYTES;
        let max_signed_node_rights_decision_bytes =
            "elastos.protected-content.signed-node-rights-decision/v1".len()
                + 1
                + U16_BYTES
                + ("elastos.protected-content.node-rights-decision/v1".len()
                    + 1
                    + DIGEST_BYTES
                    + DIGEST_BYTES
                    + U16_BYTES
                    + max_protected_content_binding_bytes
                    + U8_BYTES
                    + DIGEST_BYTES
                    + U8_BYTES
                    + DIGEST_BYTES
                    + U64_BYTES
                    + U64_BYTES)
                + U16_BYTES
                + ED25519_SIGNATURE_BYTES;
        "elastos.protected-content.signed-node-contribution/v1".len()
            + 1
            + U16_BYTES
            + ("elastos.protected-content.node-contribution/v1".len()
                + 1
                + DIGEST_BYTES
                + U16_BYTES
                + max_protected_content_binding_bytes
                + U16_BYTES
                + max_signed_node_rights_decision_bytes
                + U16_BYTES
                + max_recipient_sealed_contribution_bytes
                + U64_BYTES
                + U64_BYTES)
            + U16_BYTES
            + ED25519_SIGNATURE_BYTES
    }

    fn allowed_decision_for(
        envelope: &CustodyEnvelopeV1,
        recipient_seed: u8,
    ) -> SignedNodeRightsDecisionV1 {
        let request =
            verified_release_request_for_envelope_and_recipient_seed(envelope, recipient_seed);
        signed_node_decision(&request, 1, RightsDecisionV1::Allowed)
    }

    #[test]
    fn durable_store_cap_admits_every_current_valid_signed_contribution_shape() {
        assert!(derived_max_signed_node_contribution_bytes() <= MAX_STORED_CONTRIBUTION_BYTES);
    }

    #[test]
    fn durable_store_claims_both_keys_atomically_and_persists_across_restart() {
        let temp = owner_only_tempdir();
        let store = durable_store(1, &temp);
        store
            .claim_pair_inner([claim(1, 30), claim(2, 40)], 10)
            .unwrap();

        let reopened = durable_store(1, &temp);
        assert_eq!(
            reopened.claim_pair_inner([claim(1, 30), claim(2, 40)], 10),
            Err(ReplayClaimError::AlreadyClaimed)
        );
    }

    #[test]
    fn durable_store_rejects_partial_overlap_without_claiming_new_key() {
        let temp = owner_only_tempdir();
        let store = durable_store(1, &temp);
        store
            .claim_pair_inner([claim(1, 30), claim(2, 40)], 10)
            .unwrap();
        assert_eq!(
            store.claim_pair_inner([claim(2, 40), claim(3, 50)], 11),
            Err(ReplayClaimError::AlreadyClaimed)
        );
        store
            .claim_pair_inner([claim(3, 50), claim(4, 60)], 11)
            .unwrap();
    }

    #[test]
    fn durable_store_prunes_expired_claims_inside_the_same_transaction() {
        let temp = owner_only_tempdir();
        let store = durable_store(1, &temp);
        store
            .claim_pair_inner([claim(1, 20), claim(2, 20)], 10)
            .unwrap();
        store
            .claim_pair_inner([claim(1, 40), claim(2, 40)], 21)
            .unwrap();
    }

    #[test]
    fn durable_store_replays_exact_contribution_after_restart_without_new_effects() {
        let temp = owner_only_tempdir();
        let envelope = provisioned_envelope();
        let decision = allowed_decision_for(&envelope, 0x30);
        let mut store = durable_store(1, &temp);
        let first_operation =
            authenticated_runtime_release_operation_for_envelope_and_recipient_seed(
                &envelope, 0x30,
            );
        let mut first_rng = StdRng::from_seed([0x51; 32]);
        let first = store
            .claim_or_replay_node_contribution_with_rng(
                first_operation,
                &decision,
                &node_share_for(&envelope, 1),
                &node_signing_key(1),
                &node_custody_secret(1),
                &recipient_public_key(0x30),
                NOW + 5,
                NOW + 45,
                NOW + 6,
                &mut first_rng,
            )
            .unwrap();
        let first_bytes = first.canonical_bytes().unwrap();

        let mut reopened = durable_store(1, &temp);
        let replayed = reopened
            .claim_or_replay_node_contribution_with_rng(
                authenticated_runtime_release_operation_for_envelope_and_recipient_seed(
                    &envelope, 0x30,
                ),
                &decision,
                &node_share_for(&envelope, 1),
                &node_signing_key(1),
                &node_custody_secret(1),
                &recipient_public_key(0x30),
                NOW + 5,
                NOW + 45,
                NOW + 6,
                &mut PanicRng,
            )
            .unwrap();
        assert_eq!(replayed.canonical_bytes().unwrap(), first_bytes);
    }

    #[test]
    fn durable_store_claim_without_result_fails_closed() {
        let temp = owner_only_tempdir();
        let envelope = provisioned_envelope();
        let mut store = durable_store(1, &temp);
        let operation = authenticated_runtime_release_operation_for_envelope_and_recipient_seed(
            &envelope, 0x30,
        );
        store
            .claim_node_release_operation(
                operation,
                &node_share_for(&envelope, 1),
                node_public_key(1),
                NOW + 3,
            )
            .unwrap();

        let decision = allowed_decision_for(&envelope, 0x30);
        let err = store
            .claim_or_replay_node_contribution_with_rng(
                authenticated_runtime_release_operation_for_envelope_and_recipient_seed(
                    &envelope, 0x30,
                ),
                &decision,
                &node_share_for(&envelope, 1),
                &node_signing_key(1),
                &node_custody_secret(1),
                &recipient_public_key(0x30),
                NOW + 5,
                NOW + 45,
                NOW + 6,
                &mut PanicRng,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            CustodyError::Replay(ReplayClaimError::Unavailable)
        ));
    }

    #[test]
    fn durable_store_rejects_mismatched_retry_without_mutating_stored_result() {
        let temp = owner_only_tempdir();
        let envelope = provisioned_envelope();
        let mut store = durable_store(1, &temp);
        let decision = allowed_decision_for(&envelope, 0x30);
        let mut first_rng = StdRng::from_seed([0x52; 32]);
        let first = store
            .claim_or_replay_node_contribution_with_rng(
                authenticated_runtime_release_operation_for_envelope_and_recipient_seed(
                    &envelope, 0x30,
                ),
                &decision,
                &node_share_for(&envelope, 1),
                &node_signing_key(1),
                &node_custody_secret(1),
                &recipient_public_key(0x30),
                NOW + 5,
                NOW + 45,
                NOW + 6,
                &mut first_rng,
            )
            .unwrap();
        let first_bytes = first.canonical_bytes().unwrap();

        let mismatched_decision = allowed_decision_for(&envelope, 0x31);
        let err = store
            .claim_or_replay_node_contribution_with_rng(
                authenticated_runtime_release_operation_for_envelope_and_recipient_seed(
                    &envelope, 0x31,
                ),
                &mismatched_decision,
                &node_share_for(&envelope, 1),
                &node_signing_key(1),
                &node_custody_secret(1),
                &recipient_public_key(0x31),
                NOW + 5,
                NOW + 45,
                NOW + 6,
                &mut PanicRng,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            CustodyError::Replay(ReplayClaimError::Unavailable)
        ));

        let replayed = store
            .claim_or_replay_node_contribution_with_rng(
                authenticated_runtime_release_operation_for_envelope_and_recipient_seed(
                    &envelope, 0x30,
                ),
                &decision,
                &node_share_for(&envelope, 1),
                &node_signing_key(1),
                &node_custody_secret(1),
                &recipient_public_key(0x30),
                NOW + 5,
                NOW + 45,
                NOW + 6,
                &mut PanicRng,
            )
            .unwrap();
        assert_eq!(replayed.canonical_bytes().unwrap(), first_bytes);
    }

    #[test]
    fn durable_store_rejects_corrupt_stored_result_without_mutation() {
        let temp = owner_only_tempdir();
        let envelope = provisioned_envelope();
        let decision = allowed_decision_for(&envelope, 0x30);
        let mut store = durable_store(1, &temp);
        let mut first_rng = StdRng::from_seed([0x53; 32]);
        store
            .claim_or_replay_node_contribution_with_rng(
                authenticated_runtime_release_operation_for_envelope_and_recipient_seed(
                    &envelope, 0x30,
                ),
                &decision,
                &node_share_for(&envelope, 1),
                &node_signing_key(1),
                &node_custody_secret(1),
                &recipient_public_key(0x30),
                NOW + 5,
                NOW + 45,
                NOW + 6,
                &mut first_rng,
            )
            .unwrap();

        let mut records = store.read_state().unwrap();
        let contribution = &mut records[0].contributions.as_mut().unwrap()[0];
        let last = contribution.len() - 1;
        contribution[last] ^= 0x5a;
        let expected = records.clone();
        store.write_state(&records).unwrap();

        let err = store
            .claim_or_replay_node_contribution_with_rng(
                authenticated_runtime_release_operation_for_envelope_and_recipient_seed(
                    &envelope, 0x30,
                ),
                &decision,
                &node_share_for(&envelope, 1),
                &node_signing_key(1),
                &node_custody_secret(1),
                &recipient_public_key(0x30),
                NOW + 5,
                NOW + 45,
                NOW + 6,
                &mut PanicRng,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            CustodyError::Contract(_) | CustodyError::Release(_) | CustodyError::BindingMismatch(_)
        ));
        assert_eq!(store.read_state().unwrap(), expected);
    }

    #[test]
    fn durable_store_serializes_concurrent_claims() {
        let temp = owner_only_tempdir();
        let store_dir = store_dir(&temp);
        let barrier = Arc::new(Barrier::new(3));
        let results = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for _ in 0..2 {
                let barrier = Arc::clone(&barrier);
                let store_dir = store_dir.clone();
                handles.push(scope.spawn(move || {
                    let store = DurableReplayClaimStoreV1::new(store_node(1), store_dir);
                    barrier.wait();
                    store.claim_pair_inner([claim(1, 30), claim(2, 40)], 10)
                }));
            }
            barrier.wait();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        let success = results.iter().filter(|result| result.is_ok()).count();
        let conflicts = results
            .iter()
            .filter(|result| matches!(result, Err(ReplayClaimError::AlreadyClaimed)))
            .count();
        assert_eq!(success, 1);
        assert_eq!(conflicts, 1);
    }

    #[test]
    fn durable_store_serializes_simultaneous_process_claims() {
        if std::env::var_os("ELASTOS_CUSTODY_REPLAY_RACE_CHILD").is_some() {
            let dir = PathBuf::from(std::env::var_os("ELASTOS_CUSTODY_REPLAY_DIR").unwrap());
            println!("ready");
            std::io::stdout().flush().unwrap();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            let store = DurableReplayClaimStoreV1::new(store_node(1), dir);
            let code = match store.claim_pair_inner([claim(1, 30), claim(2, 40)], 10) {
                Ok(()) => 10,
                Err(ReplayClaimError::AlreadyClaimed) => 11,
                Err(ReplayClaimError::Unavailable) => 12,
            };
            std::process::exit(code);
        }

        let temp = owner_only_tempdir();
        let exact_test =
            "replay_store::tests::durable_store_serializes_simultaneous_process_claims";
        let mut children = Vec::new();
        for _ in 0..2 {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .env("ELASTOS_CUSTODY_REPLAY_RACE_CHILD", "1")
                .env("ELASTOS_CUSTODY_REPLAY_DIR", store_dir(&temp))
                .arg("--exact")
                .arg(exact_test)
                .arg("--nocapture")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();

            let mut ready = String::new();
            let mut reader = BufReader::new(child.stdout.take().unwrap());
            loop {
                reader.read_line(&mut ready).unwrap();
                if ready.is_empty() {
                    panic!("child exited before ready barrier");
                }
                if ready.trim() == "ready" {
                    break;
                }
                ready.clear();
            }
            drop(reader);
            children.push(child);
        }

        for child in &mut children {
            child.stdin.as_mut().unwrap().write_all(b"go\n").unwrap();
        }

        let mut statuses = Vec::new();
        for mut child in children {
            statuses.push(child.wait().unwrap().code().unwrap());
        }

        let success = statuses.iter().filter(|code| **code == 10).count();
        let conflicts = statuses.iter().filter(|code| **code == 11).count();
        assert_eq!(success, 1);
        assert_eq!(conflicts, 1);
    }

    #[test]
    fn durable_store_rejects_corrupt_truncated_and_oversized_state() {
        let temp = owner_only_tempdir();
        let state_dir = store_dir(&temp);
        fs::create_dir(&state_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }

        fs::write(state_dir.join("node-replay-claims.v1"), b"broken").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                state_dir.join("node-replay-claims.v1"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let corrupt = durable_store(1, &temp);
        assert_eq!(
            corrupt.claim_pair_inner([claim(1, 30), claim(2, 40)], 10),
            Err(ReplayClaimError::Unavailable)
        );

        fs::write(
            state_dir.join("node-replay-claims.v1"),
            vec![0u8; MAX_STATE_BYTES + 1],
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                state_dir.join("node-replay-claims.v1"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let oversized = durable_store(1, &temp);
        assert_eq!(
            oversized.claim_pair_inner([claim(1, 30), claim(2, 40)], 10),
            Err(ReplayClaimError::Unavailable)
        );
    }

    #[test]
    fn durable_store_rejects_same_length_state_corruption_and_forged_digest() {
        let temp = owner_only_tempdir();
        let store = durable_store(1, &temp);
        store
            .claim_pair_inner([claim(1, 30), claim(2, 40)], 10)
            .unwrap();

        let state_path = store_dir(&temp).join("node-replay-claims.v1");
        let original = fs::read(&state_path).unwrap();
        let cases = [
            ("key-byte", STATE_HEADER_BYTES + 5),
            ("expiry-byte", STATE_HEADER_BYTES + 32 + 16 + 7),
            ("digest-byte", original.len() - 1),
        ];

        for (label, index) in cases {
            let mut corrupted = original.clone();
            corrupted[index] ^= 0x5a;
            fs::write(&state_path, &corrupted).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600)).unwrap();
            }

            let corrupted_store = durable_store(1, &temp);
            assert_eq!(
                corrupted_store.claim_pair_inner([claim(3, 50), claim(4, 60)], 11),
                Err(ReplayClaimError::Unavailable),
                "corruption case {label} should fail closed"
            );

            fs::write(&state_path, &original).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
    }

    #[test]
    fn durable_store_rejects_symlinked_loose_mode_and_hard_linked_paths() {
        let temp = owner_only_tempdir();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};

            let state_dir = store_dir(&temp);
            fs::create_dir(&state_dir).unwrap();
            fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();

            let target = temp.path().join("outside");
            fs::write(&target, b"state").unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
            symlink(&target, state_dir.join("node-replay-claims.v1")).unwrap();

            let symlink_store = durable_store(1, &temp);
            assert_eq!(
                symlink_store.claim_pair_inner([claim(1, 30), claim(2, 40)], 10),
                Err(ReplayClaimError::Unavailable)
            );

            fs::remove_file(state_dir.join("node-replay-claims.v1")).unwrap();
            fs::write(
                state_dir.join("node-replay-claims.v1"),
                encode_state(store_node(1), &[]).unwrap(),
            )
            .unwrap();
            fs::set_permissions(
                state_dir.join("node-replay-claims.v1"),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            let mode_store = durable_store(1, &temp);
            assert_eq!(
                mode_store.claim_pair_inner([claim(1, 30), claim(2, 40)], 10),
                Err(ReplayClaimError::Unavailable)
            );

            fs::remove_file(state_dir.join("node-replay-claims.v1")).unwrap();
            let hard_link_target = state_dir.join("lock-target");
            fs::write(&hard_link_target, b"keepme").unwrap();
            fs::set_permissions(&hard_link_target, fs::Permissions::from_mode(0o600)).unwrap();
            let _ = fs::remove_file(state_dir.join("node-replay-claims.lock"));
            fs::hard_link(&hard_link_target, state_dir.join("node-replay-claims.lock")).unwrap();
            let hard_link_store = durable_store(1, &temp);
            assert_eq!(
                hard_link_store.claim_pair_inner([claim(1, 30), claim(2, 40)], 10),
                Err(ReplayClaimError::Unavailable)
            );
            assert_eq!(fs::read(&hard_link_target).unwrap(), b"keepme");
        }
    }

    #[test]
    fn durable_store_rejects_non_not_found_state_metadata_errors_before_temp_write() {
        let temp = owner_only_tempdir();
        let blocker = temp.path().join("not-a-dir");
        fs::write(&blocker, b"blocker").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&blocker, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let store =
            DurableReplayClaimStoreV1::new(store_node(1), blocker.join("replay-store-state"));
        assert_eq!(store.write_state(&[]), Err(ReplayClaimError::Unavailable));
        assert_eq!(fs::read(&blocker).unwrap(), b"blocker");
        assert!(!blocker.join("replay-store-state").exists());
    }

    #[test]
    fn durable_store_recovers_valid_stale_temp_and_rejects_wrong_node_store() {
        let temp = owner_only_tempdir();
        let state_dir = store_dir(&temp);
        fs::create_dir(&state_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }

        fs::write(state_dir.join("node-replay-claims.tmp"), b"stale-temp").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                state_dir.join("node-replay-claims.tmp"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let recovered = durable_store(1, &temp);
        recovered
            .claim_pair_inner([claim(1, 30), claim(2, 40)], 10)
            .unwrap();
        assert!(!state_dir.join("node-replay-claims.tmp").exists());

        let wrong_node = durable_store(2, &temp);
        assert_eq!(
            wrong_node.claim_pair_inner([claim(3, 30), claim(4, 40)], 10),
            Err(ReplayClaimError::Unavailable)
        );
    }

    #[test]
    fn durable_store_rejects_wrong_selected_node_before_state_write_and_persists_node_identity() {
        let temp = owner_only_tempdir();
        let envelope = provisioned_envelope();
        let operation = authenticated_runtime_release_operation_for_envelope_and_recipient_seed(
            &envelope, 0x30,
        );
        let mut wrong_store = durable_store(2, &temp);
        assert!(matches!(
            wrong_store.claim_node_release_operation(
                operation,
                &node_share_for(&envelope, 1),
                node_public_key(1),
                NOW + 3
            ),
            Err(CustodyError::BindingMismatch("store_node_public_key"))
        ));
        assert!(!store_dir(&temp).exists());

        let mut correct_store = durable_store(1, &temp);
        let operation = authenticated_runtime_release_operation_for_envelope_and_recipient_seed(
            &envelope, 0x30,
        );
        correct_store
            .claim_node_release_operation(
                operation,
                &node_share_for(&envelope, 1),
                node_public_key(1),
                NOW + 3,
            )
            .unwrap();

        let mut reopened_wrong_store = durable_store(2, &temp);
        let operation = authenticated_runtime_release_operation_for_envelope_and_recipient_seed(
            &envelope, 0x30,
        );
        assert!(matches!(
            reopened_wrong_store.claim_node_release_operation(
                operation,
                &node_share_for(&envelope, 2),
                node_public_key(2),
                NOW + 3
            ),
            Err(CustodyError::Replay(ReplayClaimError::Unavailable))
        ));
    }

    #[test]
    fn durable_store_rename_failure_leaves_no_partial_claim_state() {
        let temp = owner_only_tempdir();
        let store = durable_store(1, &temp);
        store
            .claim_pair_inner([claim(1, 30), claim(2, 40)], 10)
            .unwrap();

        *TEST_FAULT.lock().unwrap() =
            Some((TestFault::RenameStateDirBeforeRename, store_dir(&temp)));
        let failure = store.claim_pair_inner([claim(3, 50), claim(4, 60)], 11);
        assert_eq!(failure, Err(ReplayClaimError::Unavailable));

        let moved = store_dir(&temp).with_extension("fault");
        fs::rename(&moved, store_dir(&temp)).unwrap();

        let reopened = durable_store(1, &temp);
        assert_eq!(
            reopened.claim_pair_inner([claim(1, 30), claim(2, 40)], 11),
            Err(ReplayClaimError::AlreadyClaimed)
        );
        reopened
            .claim_pair_inner([claim(3, 50), claim(4, 60)], 11)
            .unwrap();
    }

    #[test]
    fn durable_store_persists_across_process_boundary() {
        if std::env::var_os("ELASTOS_CUSTODY_REPLAY_CHILD").is_some() {
            let dir = PathBuf::from(std::env::var_os("ELASTOS_CUSTODY_REPLAY_DIR").unwrap());
            let store = DurableReplayClaimStoreV1::new(store_node(1), dir);
            store
                .claim_pair_inner([claim(1, 30), claim(2, 40)], 10)
                .unwrap();
            return;
        }

        let temp = owner_only_tempdir();
        let status = Command::new(std::env::current_exe().unwrap())
            .env("ELASTOS_CUSTODY_REPLAY_CHILD", "1")
            .env("ELASTOS_CUSTODY_REPLAY_DIR", store_dir(&temp))
            .arg("--exact")
            .arg("replay_store::tests::durable_store_persists_across_process_boundary")
            .arg("--nocapture")
            .status()
            .unwrap();
        assert!(status.success());

        let store = durable_store(1, &temp);
        assert_eq!(
            store.claim_pair_inner([claim(1, 30), claim(2, 40)], 10),
            Err(ReplayClaimError::AlreadyClaimed)
        );
    }

    // -----------------------------------------------------------------------
    // Plan B T1.4: V2 pool releases (record version epc-rcl2, L4)
    // -----------------------------------------------------------------------

    use crate::test_support::{pool_node_custody_secret, pool_release_test, recipient_secret};
    use elastos_protected_content_contracts::test_fixtures::signed_node_rights_decision;

    fn claim_pool(
        store: &mut DurableReplayClaimStoreV1,
        test: &crate::test_support::PoolReleaseTestV1,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<SignedNodeContributionV1>, CustodyError> {
        let operation = test.fixture.authenticated();
        let decision = signed_node_rights_decision(&operation, 1, RightsDecisionV1::Allowed, NOW);
        store.claim_or_replay_pool_contributions_with_rng(
            operation,
            &decision,
            &node_share_for(&test.envelope, 1),
            &node_signing_key(1),
            &pool_node_custody_secret(1),
            NOW + 5,
            NOW + 30,
            NOW + 6,
            rng,
        )
    }

    #[test]
    fn one_claim_yields_one_contribution_per_recipient() {
        let temp = owner_only_tempdir();
        let test = pool_release_test(vec![(9, 1), (10, 2)], 2, 0x43);
        let mut store = durable_store(1, &temp);
        let contributions =
            claim_pool(&mut store, &test, &mut StdRng::from_seed([0x61; 32])).unwrap();
        let operation = test.fixture.authenticated();
        let recipients = operation
            .statement()
            .rights_request()
            .request()
            .recipients()
            .to_vec();
        assert_eq!(contributions.len(), 2);
        for (contribution, recipient) in contributions.iter().zip(&recipients) {
            assert_eq!(
                contribution
                    .statement()
                    .recipient_sealed_contribution()
                    .recipient(),
                recipient
            );
            let verified = operation
                .verify_node_contribution(
                    contribution,
                    &test.fixture.node_set(),
                    recipient,
                    NOW + 6,
                )
                .unwrap();
            // L1: the release slot holds the V2 operation hash.
            assert_eq!(verified.release_request_hash(), operation.operation_hash());
        }
    }

    #[test]
    fn replay_returns_identical_contributions() {
        let temp = owner_only_tempdir();
        let test = pool_release_test(vec![(9, 1), (10, 2)], 2, 0x43);
        let mut store = durable_store(1, &temp);
        let first = claim_pool(&mut store, &test, &mut StdRng::from_seed([0x62; 32])).unwrap();
        let mut reopened = durable_store(1, &temp);
        let replayed = claim_pool(&mut reopened, &test, &mut PanicRng).unwrap();
        assert_eq!(
            replayed
                .iter()
                .map(|contribution| contribution.canonical_bytes().unwrap())
                .collect::<Vec<_>>(),
            first
                .iter()
                .map(|contribution| contribution.canonical_bytes().unwrap())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn guard_same_rights_claim_with_another_operation_is_refused() {
        let temp = owner_only_tempdir();
        let first = pool_release_test(vec![(9, 1)], 1, 0x43);
        // Another Runtime signs another operation for the same wallet-signed
        // rights request (same claim key, same audit id).
        let second = pool_release_test(vec![(9, 1)], 1, 0x44);
        assert_eq!(
            first
                .fixture
                .authenticated()
                .rights_request_replay_claim_key(),
            second
                .fixture
                .authenticated()
                .rights_request_replay_claim_key()
        );
        assert_ne!(
            first.fixture.authenticated().operation_hash(),
            second.fixture.authenticated().operation_hash()
        );
        let mut store = durable_store(1, &temp);
        claim_pool(&mut store, &first, &mut StdRng::from_seed([0x63; 32])).unwrap();
        assert!(matches!(
            claim_pool(&mut store, &second, &mut PanicRng),
            Err(CustodyError::Replay(ReplayClaimError::Unavailable))
        ));
    }

    #[test]
    fn rcl1_state_reads_and_is_rewritten_as_rcl2() {
        let temp = owner_only_tempdir();
        let state_dir = store_dir(&temp);
        fs::create_dir(&state_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut claims = [claim(1, 30), claim(2, 40)];
        sort_claims(&mut claims);
        let legacy = StoredNodeReleaseRecordV1::claim_only(
            claims[0],
            claims[1],
            synthetic_runtime_release_audit_id(&claims),
            synthetic_operation_hash(&claims),
        );
        let state_path = state_dir.join("node-replay-claims.v1");
        let legacy_bytes = encode_state_rcl1(store_node(1), &[legacy]).unwrap();
        assert_eq!(&legacy_bytes[..8], b"epc-rcl1");
        fs::write(&state_path, &legacy_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let store = durable_store(1, &temp);
        // The rcl1 record reads as a V1 claim.
        assert_eq!(
            store.claim_pair_inner([claim(1, 30), claim(2, 40)], 10),
            Err(ReplayClaimError::AlreadyClaimed)
        );
        // The next write rewrites the file as rcl2 and keeps the old record.
        store
            .claim_pair_inner([claim(3, 50), claim(4, 60)], 11)
            .unwrap();
        assert_eq!(&fs::read(&state_path).unwrap()[..8], b"epc-rcl2");
        assert_eq!(
            store.claim_pair_inner([claim(1, 30), claim(2, 40)], 12),
            Err(ReplayClaimError::AlreadyClaimed)
        );
    }

    #[test]
    fn v2_record_holds_at_most_the_session_recipient_cap() {
        let rights = claim(7, 90);
        let audit = RuntimeReleaseAuditIdV1::new(Digest32::new([0x91; 32])).unwrap();
        let record_with = |count: usize| {
            let mut record = StoredNodeReleaseRecordV1::pool_claim_only(
                rights,
                audit,
                Digest32::new([0x92; 32]),
            );
            record.set_pool_contribution_bytes(vec![vec![0x5a; 64]; count]);
            record
        };
        let cap = elastos_protected_content_contracts::MAX_SESSION_RECIPIENTS_V2;
        let at_cap = encode_state(store_node(1), &[record_with(cap)]).unwrap();
        assert_eq!(
            decode_state(&at_cap, store_node(1)).unwrap(),
            vec![record_with(cap)]
        );
        assert_eq!(
            encode_state(store_node(1), &[record_with(cap + 1)]),
            Err(ReplayClaimError::Unavailable)
        );
        assert_eq!(
            encode_state(store_node(1), &[record_with(0)]),
            Err(ReplayClaimError::Unavailable)
        );
    }

    // Known-answer vectors for the replay store file (append-only; audit
    // M6, 2026-11-12): one V1 release record (claims 1 and 2, with its one
    // contribution) and one V2 pool release record (claim 7, two
    // contributions), for node 1.

    fn kat_records() -> Vec<StoredNodeReleaseRecordV1> {
        let mut claims = [claim(1, 30), claim(2, 40)];
        sort_claims(&mut claims);
        let mut v1 = StoredNodeReleaseRecordV1::claim_only(
            claims[0],
            claims[1],
            synthetic_runtime_release_audit_id(&claims),
            synthetic_operation_hash(&claims),
        );
        v1.set_contribution_bytes(vec![0x5b; 48]);
        let mut v2 = StoredNodeReleaseRecordV1::pool_claim_only(
            claim(7, 90),
            RuntimeReleaseAuditIdV1::new(Digest32::new([0x91; 32])).unwrap(),
            Digest32::new([0x92; 32]),
        );
        v2.set_pool_contribution_bytes(vec![vec![0x5a; 64], vec![0x5c; 72]]);
        let mut records = vec![v1, v2];
        records.sort_unstable_by_key(StoredNodeReleaseRecordV1::sort_key);
        records
    }

    #[test]
    #[ignore = "prints the M6 replay store vectors; run with --ignored --nocapture"]
    fn m6_replay_state_vector_dump() {
        let records = kat_records();
        let v1_only: Vec<_> = records
            .iter()
            .filter(|record| !record.is_pool_release())
            .cloned()
            .collect();
        println!(
            "RCL1 {}",
            hex::encode(encode_state_rcl1(store_node(1), &v1_only).unwrap())
        );
        println!(
            "RCL2 {}",
            hex::encode(encode_state(store_node(1), &records).unwrap())
        );
    }

    /// M6: `epc-rcl1` (303 bytes) and `epc-rcl2` (567 bytes) state files.
    /// Values reproduced on two runs and with an external `shasum`.
    #[test]
    fn replay_state_rcl1_and_rcl2_vectors() {
        let records = kat_records();
        let v1_only: Vec<_> = records
            .iter()
            .filter(|record| !record.is_pool_release())
            .cloned()
            .collect();
        let rcl1 = encode_state_rcl1(store_node(1), &v1_only).unwrap();
        assert_eq!(
            hex::encode(&rcl1),
            "6570632d72636c318a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c00000001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101000000000000001e0202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020000000000000028a58941ec79b3c6e3c80fbf07caf19c4e6d30d3c31587160a1d314ba60f8d55c294adcae99c449e0628c170ad6ea3345263484bfaef00d37ca48d567efc5267390100305b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b7423fcec909e193bf22e7c53af2d0547224a01db3f8a023da7d8fc30eeb25af6"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&rcl1)),
            "d9979ab006ed214c084843c7de292e0575e813ddd641b177c8b886942ce1e084"
        );
        assert_eq!(decode_state(&rcl1, store_node(1)).unwrap(), v1_only);
        let rcl2 = encode_state(store_node(1), &records).unwrap();
        assert_eq!(
            hex::encode(&rcl2),
            "6570632d72636c328a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c0000000201010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101000000000000001e0202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020000000000000028a58941ec79b3c6e3c80fbf07caf19c4e6d30d3c31587160a1d314ba60f8d55c294adcae99c449e0628c170ad6ea3345263484bfaef00d37ca48d567efc5267390100305b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b02070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707000000000000005a91919191919191919191919191919191919191919191919191919191919191919292929292929292929292929292929292929292929292929292929292929292010200405a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a00485c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5cde1cca28655fd58eec3aff349dd7c9a18155c18cbe7decd71c78df9e224b185b"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&rcl2)),
            "9144d60c58b651d2bd69dd3a25c3bc9ecfbf6c7d5a48609b6a9328b76c1dc956"
        );
        assert_eq!(decode_state(&rcl2, store_node(1)).unwrap(), records);
    }

    /// The pool claim conflict check: an active release holds this audit
    /// id, so another rights claim under it is refused before anything is
    /// written. The state encoder alone would accept the second record (its
    /// claim key differs), so only the conflict check refuses it.
    #[test]
    fn guard_pool_claim_under_an_active_audit_id_is_refused() {
        let first = pool_release_test(vec![(9, 1)], 1, 0x43);
        let second = crate::test_support::pool_release_test_with(vec![(9, 1)], 1, 0x43, |spec| {
            spec.replay_nonce = 0x56;
        });
        let (first_op, second_op) = (
            first.fixture.authenticated(),
            second.fixture.authenticated(),
        );
        assert_ne!(
            first_op.rights_request_replay_claim_key(),
            second_op.rights_request_replay_claim_key()
        );
        assert_eq!(
            first_op.statement().audit_request_id(),
            second_op.statement().audit_request_id()
        );
        let temp = owner_only_tempdir();
        let mut store = durable_store(1, &temp);
        claim_pool(&mut store, &first, &mut StdRng::from_seed([0x63; 32])).unwrap();
        assert!(matches!(
            claim_pool(&mut store, &second, &mut StdRng::from_seed([0x64; 32])),
            Err(CustodyError::Replay(ReplayClaimError::Unavailable))
        ));
        // Positive control: the same second claim on a fresh node succeeds.
        let fresh = owner_only_tempdir();
        let mut store = durable_store(1, &fresh);
        claim_pool(&mut store, &second, &mut StdRng::from_seed([0x64; 32])).unwrap();
    }

    /// The state encoder's own refusal: two records under one rights claim
    /// key never encode (strictly increasing sort keys). This is the layer
    /// behind the conflict check for a repeated claim key.
    #[test]
    fn guard_replay_state_refuses_two_records_with_one_claim_key() {
        let rights = claim(7, 90);
        let record = |audit: u8, operation: u8| {
            let mut record = StoredNodeReleaseRecordV1::pool_claim_only(
                rights,
                RuntimeReleaseAuditIdV1::new(Digest32::new([audit; 32])).unwrap(),
                Digest32::new([operation; 32]),
            );
            record.set_pool_contribution_bytes(vec![vec![0x5a; 64]]);
            record
        };
        assert_eq!(
            encode_state(store_node(1), &[record(0x91, 0x92), record(0x93, 0x94)]),
            Err(ReplayClaimError::Unavailable)
        );
        assert!(encode_state(store_node(1), &[record(0x91, 0x92)]).is_ok());
    }

    /// The node refuses a pool release whose rights decision is Denied, before
    /// it claims anything; the same release with an Allowed decision then
    /// succeeds.
    #[test]
    fn guard_pool_release_with_a_denied_decision_is_refused() {
        let test = pool_release_test(vec![(9, 1)], 1, 0x43);
        let operation = test.fixture.authenticated();
        let denied = signed_node_rights_decision(&operation, 1, RightsDecisionV1::Denied, NOW);
        let temp = owner_only_tempdir();
        let mut store = durable_store(1, &temp);
        let refused = store.claim_or_replay_pool_contributions_with_rng(
            operation,
            &denied,
            &node_share_for(&test.envelope, 1),
            &node_signing_key(1),
            &pool_node_custody_secret(1),
            NOW + 5,
            NOW + 30,
            NOW + 6,
            &mut StdRng::from_seed([0x65; 32]),
        );
        assert!(
            matches!(
                refused,
                Err(CustodyError::Release(
                    elastos_protected_content_contracts::KeyReleaseError::RightsDenied
                ))
            ),
            "{refused:?}"
        );
        claim_pool(&mut store, &test, &mut StdRng::from_seed([0x66; 32])).unwrap();
    }

    #[test]
    fn guard_contribution_for_recipient_a_does_not_open_with_b() {
        let temp = owner_only_tempdir();
        let test = pool_release_test(vec![(9, 1), (10, 2)], 2, 0x43);
        let mut store = durable_store(1, &temp);
        let contributions =
            claim_pool(&mut store, &test, &mut StdRng::from_seed([0x64; 32])).unwrap();
        let operation = test.fixture.authenticated();
        let node_share = node_share_for(&test.envelope, 1);
        let decision = operation
            .verify_node_rights_decision(
                contributions[0].statement().signed_rights_decision(),
                &test.fixture.node_set(),
                NOW + 6,
            )
            .unwrap();
        for (contribution, (owner_seed, other_seed)) in
            contributions.iter().zip(sealed_owner_seeds(&operation))
        {
            let recipient = contribution
                .statement()
                .recipient_sealed_contribution()
                .recipient();
            let aad = node_share
                .node()
                .unwrap()
                .released_share_aad_bytes(
                    operation.operation_hash(),
                    operation.binding(),
                    decision.decision_hash(),
                    recipient,
                )
                .unwrap();
            let sealed = crate::share_wrap::decode_ciphertext_bytes(
                contribution
                    .statement()
                    .recipient_sealed_contribution()
                    .sealed_bytes(),
            )
            .unwrap();
            crate::share_wrap::open_share(
                &sealed,
                recipient_secret(owner_seed).secret_bytes(),
                elastos_protected_content_contracts::RELEASED_SHARE_HPKE_INFO_V1,
                &aad,
            )
            .unwrap();
            assert!(crate::share_wrap::open_share(
                &sealed,
                recipient_secret(other_seed).secret_bytes(),
                elastos_protected_content_contracts::RELEASED_SHARE_HPKE_INFO_V1,
                &aad,
            )
            .is_err());
        }
    }

    /// For each signed recipient in order: (its own key seed, the other one).
    fn sealed_owner_seeds(
        operation: &elastos_protected_content_contracts::AuthenticatedRuntimeReleaseOperationV2,
    ) -> Vec<(u8, u8)> {
        operation
            .statement()
            .rights_request()
            .request()
            .recipients()
            .iter()
            .map(|recipient| {
                if *recipient == recipient_secret(9).identity().unwrap() {
                    (9, 10)
                } else {
                    (10, 9)
                }
            })
            .collect()
    }
}

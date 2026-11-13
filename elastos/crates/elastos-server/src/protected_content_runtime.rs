//! Protected-content Runtime provider plane.
//!
//! This module registers the Runtime-owned `protect`, `media`, `custody`, and
//! `protected-content-decrypt` targets, scans the durable Runtime release
//! journal on startup, and evaluates policy through the `chain` registry
//! route. Library mint, buy, open, read, and close use these seams. It is the
//! only protected-content authority, and it exposes no provider topology to
//! capsules.

#[cfg(test)]
mod pool_mint_tests;
#[cfg(test)]
pub(crate) mod tests;
mod unfinished_mint;

pub(crate) use unfinished_mint::*;

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, Weak};

use crate::custody_release_limits::{
    CustodyReleaseLimiter, RuntimeInvocationSource, CUSTODY_NODE_SETTINGS, RATE_LIMITED_CODE,
};
use crate::custody_surface::{
    carrier_op_allowed, declared_ops, runtime_local_op_allowed, OP_CUSTODY_EVALUATE,
    OP_CUSTODY_PROVISION_NODE_SHARE, OP_CUSTODY_PROVISION_POOL_NODE_SHARE,
    OP_CUSTODY_RELEASE_CONTRIBUTION, OP_CUSTODY_RELEASE_POOL_CONTRIBUTION,
    OP_CUSTODY_SIGN_POOL_STATEMENT, OP_CUSTODY_STATUS, TARGET_CUSTODY,
};
use base64::Engine as _;
use ed25519_dalek::Signer as _;
use elastos_protected_content_contracts::{
    validate_custody_epoch_against_pool_at, CanonicalContract, ContentAccessIdV1,
    CustodyCommitteeAuthorizationIdentityV1, CustodyEnvelopeV1, CustodyEpochIssuerKeyV1, Digest32,
    EncryptedContentIdentityV1, KeyReleaseOutcomeV1, KeyReleaseRequestV1, NodeContributionRefV1,
    NodeCustodyPublicKeyV1, NodePublicKey, ProfileIdentityV1, RecipientKeyAuthorizationStatementV1,
    RecipientKeyIdentityV1, RecipientPublicKeyBytesV1, ReplayNonce16, RightsActionV1,
    RightsEvaluationEvidenceRequestV1, RightsPolicyBodyV1, RightsPolicyIdentityV1,
    RightsRequestAnyV1, RightsRequestV1, RightsRequestV2, RuntimeOperationIssuerKeyV1,
    RuntimeReleaseAuditIdV1, RuntimeReleaseOperationAnyV1, RuntimeReleaseOperationStatementV1,
    RuntimeSessionBindingV1, SignedCustodyCommitteeAuthorizationV1, SignedCustodyEpochV1,
    SignedCustodyPoolV1, SignedPoolDescriptorAnyV1, SignedRuntimeReleaseOperationV1,
    SignedTerminalReceiptV1, TerminalReceiptIssuerKey, TerminalReceiptStatementV1,
    ViewerPartIndexV1, WalletAddress, WalletSignedRightsRequestAnyV1, WalletSignedRightsRequestV1,
};
use elastos_protected_content_provider_contracts::{
    build_cenc_dash_mpd_v2, cenc_dash_merkle_audit_path, cenc_dash_merkle_audit_paths,
    cenc_dash_merkle_root, cenc_dash_segment_leaf_hash, pinned_declaration_v2,
    CencDashIdentityBuilderV2, CencDashMediaIdentityV2, CencDashMpdRenditionV2,
    CencDashMpdSegmentV2, CencDashRenditionDeclV2, CencDashRenditionKindV2,
    CencFmp4MediaIdentityV1, CencLayoutProfile, CencMediaSuite, ChunkedPayloadObjectIdentityV1,
    CustodyProtectionHeader, DecryptProviderRequestOpV1, DecryptProviderRequestV1,
    DecryptProviderResponseV1, Fmp4SegmentTimelineV2, ProtectFailureReasonV2,
    ProtectProviderRequestV1, ProtectProviderResponseStatusV1, ProtectProviderResponseV1,
    ProtectionRepresentationV2, ProtectionSessionNodeV1, RightsProviderRequestV1,
    RightsProviderResponseV1, ValidatedCencDashRenditionSessionV2,
    ValidatedClearFmp4MediaSessionLayoutV1, ViewerMediaPartSelectorV1,
    CUSTODY_PROVIDER_REQUEST_SCHEMA_V1, CUSTODY_PROVIDER_RESPONSE_SCHEMA_V1,
    DECRYPT_PROVIDER_REQUEST_SCHEMA_V1, DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1,
    MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1, MAX_PROTECT_MEDIA_PART_BYTES_V1,
    MAX_PROTECT_MEDIA_SEGMENTS_V1, MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1,
    MAX_VIEWER_MEDIA_PART_BYTES_V1, PROTECT_PROVIDER_REQUEST_SCHEMA_V1,
    PROTECT_PROVIDER_RESPONSE_SCHEMA_V1,
};
use elastos_protected_content_rights::{
    PrivateCustodyRightsRequestV1, CHAIN_PROVIDER_ID, CHAIN_RIGHTS_EVIDENCE_OP,
};
use elastos_protected_content_runtime::RuntimeProviderCallError;
use elastos_protected_content_runtime::{
    cancel_prepared_recipient, cancel_prepared_recipient_with_result_by_handle,
    close_viewer_session_with_result, open_viewer_session, prepare_recipient,
    read_viewer_media_part, read_viewer_object_chunk, resolve_runtime_mint_selected_nodes,
    ExclusiveFileLock, PersistedRuntimeMint, PersistedRuntimeReleaseOperation,
    RuntimeContentAvailabilityRequirement, RuntimeContentIdentityV1, RuntimeCustodyTerminalKind,
    RuntimeDecryptProvider, RuntimeMediaPreparationRecord, RuntimeMediaPreparationState,
    RuntimeMintConfiguredCustodyProvider, RuntimeMintCoordinator, RuntimeMintCoordinatorError,
    RuntimeMintCoordinatorOutcome, RuntimeMintCreatorStage, RuntimeMintCreatorState,
    RuntimeMintCreatorTerminalEvidence, RuntimeMintDraft, RuntimeMintIntent,
    RuntimeMintIntentRenditionV2, RuntimeMintJournal, RuntimeOpenViewerContentV1,
    RuntimeOpenViewerSessionInput, RuntimePreparedRecipient, RuntimePreparedRecipientCancelResult,
    RuntimeProtectedContentPurchaseIntent, RuntimePurchaseEffectAuthority,
    RuntimeReleaseAuditRecord, RuntimeReleaseCoordinator, RuntimeReleaseCoordinatorOutcome,
    RuntimeReleaseJournal, RuntimeReleaseJournalError, RuntimeReleaseTerminalResult,
    RuntimeSelectedProvider, RuntimeVerifiedContentAvailability,
    RuntimeVerifiedContentIdentityRootV1, RuntimeVerifiedPurchaseEffect, RuntimeViewerSession,
    RuntimeViewerSessionCloseResult,
};
use elastos_runtime::provider::bridge::{ProviderBridge, ProviderConfig};
use elastos_runtime::provider::{
    Provider, ProviderCarrierRoute, ProviderError, ProviderInvocation, ProviderInvocationTransport,
    ProviderRegistry, ProviderTransfer, ResourceRequest, ResourceResponse,
};
use elastos_wallet_contract::{
    ValidatedChainOutcomeBindingV1, VerifiedWalletInvocationContext, WalletProviderOperationV2,
    WalletProviderRequestV2, MAX_INVOCATION_TTL_SECS, WALLET_BUS_OPERATION,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest as _;

/// Protected content (Creator, Custody, Elacity Player, Elacity Reader, Protect
/// and List, Marketplace Media) ships after 0.8.0 (#91). It stays off, and Home
/// hides those surfaces and refuses protected publishing, unless the host sets
/// `elastos config set protected_content true`.
pub(crate) fn protected_content_enabled(data_dir: &Path) -> bool {
    protected_content_enabled_in(read_home_config(data_dir).as_ref())
}

/// One snapshot of this Home's `config.toml`, or `None` when it is missing
/// or unreadable. Flags that must agree are read from one snapshot.
pub(crate) fn read_home_config(data_dir: &Path) -> Option<toml::Table> {
    fs::read_to_string(data_dir.join("config.toml"))
        .ok()
        .and_then(|contents| contents.parse::<toml::Table>().ok())
}

/// `protected_content` in a config snapshot; off when absent.
pub(crate) fn protected_content_enabled_in(config: Option<&toml::Table>) -> bool {
    config
        .and_then(|config| config.get("protected_content"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
}
pub(crate) const ELACITY_PLAYER_CAPSULE_ID: &str = "elacity-player";
pub(crate) const ELACITY_READER_CAPSULE_ID: &str = "elacity-reader";
const CREATOR_CAPSULE_ID: &str = "creator";
const CUSTODY_CAPSULE_ID: &str = "custody";

/// Capsules that only work with protected content, so Home lists them only
/// while `protected_content_enabled` is on.
pub(crate) fn is_protected_content_capsule(name: &str) -> bool {
    [
        CREATOR_CAPSULE_ID,
        CUSTODY_CAPSULE_ID,
        ELACITY_PLAYER_CAPSULE_ID,
        ELACITY_READER_CAPSULE_ID,
    ]
    .contains(&name)
}

pub(crate) const CUSTODY_PROVIDER_ID: &str = crate::custody_surface::TARGET_CUSTODY;
pub(crate) const PROTECT_PROVIDER_ID: &str = "protect";
pub(crate) const MEDIA_PROVIDER_ID: &str = "media";
pub(crate) const RUNTIME_PROVIDER_ID: &str = "runtime";
pub(crate) const PROTECTED_CONTENT_DECRYPT_PROVIDER_ID: &str = "protected-content-decrypt";
const MEDIA_PROVIDER_CONFIG_FILE: &str = "protected-content/media-provider/config.json";
const MEDIA_PROVIDER_CONFIG_SCHEMA_V1: &str = "elastos.protected-content.media-provider-config/v1";
const MEDIA_PROVIDER_OUTPUT_PROFILE_V1: &str = "browser_fmp4_h264_v1";
const MAX_MEDIA_PROVIDER_CONFIG_BYTES: usize = 8 * 1024;
const MAX_MEDIA_PROVIDER_IMPORTED_TOOL_BYTES: u64 = 512 * 1024 * 1024;
const MEDIA_PROVIDER_TIMEOUT_MS_V1: u64 = 3_600_000;
const MEDIA_PROVIDER_MAX_STDIO_BYTES_V1: usize = 1 << 20;
const MEDIA_PROVIDER_MAX_INPUT_BYTES_V1: u64 = 1 << 30;
const MEDIA_PROVIDER_MAX_OUTPUT_PART_BYTES_V1: u64 = 64 << 20;
const MEDIA_PROVIDER_MAX_DURATION_SECS_V1: u64 = 1_800;
const MEDIA_PROVIDER_MAX_SOURCE_WIDTH_V1: u32 = 3_840;
const MEDIA_PROVIDER_MAX_SOURCE_HEIGHT_V1: u32 = 2_160;
const MEDIA_PROVIDER_MAX_SOURCE_FPS_V1: u32 = 60;
const MEDIA_PROVIDER_MAX_SEGMENT_COUNT_V1: usize = MAX_PROTECT_MEDIA_SEGMENTS_V1 as usize;
const MEDIA_PROVIDER_MAX_TOTAL_OUTPUT_BYTES_V1: u64 = 2 << 30;
const CONTENT_PROVIDER_ID: &str = "content";
const PROTECTED_CONTENT_REPLICATION_POLICY: &str = "protected-content-replication/v1";
/// The fewest verified copies a protected item may have and still be listed,
/// bought or opened. One: the creator's Home holds the ciphertext and serves
/// it to any peer. Listings verified with more copies stay valid, and a raised
/// new-mint target leaves this floor alone, so items already listed keep
/// their validity.
pub(crate) const PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR: u32 = 1;
/// The verified copies a new mint asks the content plane for. One: pool
/// members hold no copies until the pool redesign raises this. It is never
/// below the accepted floor.
pub(crate) const PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET: u32 = 1;
const _: () =
    assert!(PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR <= PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET);
/// Whether a check that asks for `minimum_replicas` copies also asks for a live
/// proof from another peer: only when it asks for another copy. Each check
/// applies this to its own requirement, so a mint (built at the new-mint
/// target) stays strict, and the re-check of a listing already made (built at
/// the accepted floor) still accepts that listing's one verified copy.
pub(crate) const fn protected_content_live_proof_required(minimum_replicas: u32) -> bool {
    minimum_replicas > 1
}
const PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS: u64 = 60;
const PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS: u64 = 5;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeMediaProviderConfigFile {
    schema: String,
    ffmpeg_path: String,
    ffprobe_path: String,
    staging_root: String,
    output_profile: String,
    timeout_ms: u64,
    max_stdio_bytes: usize,
    max_input_bytes: u64,
    max_output_part_bytes: u64,
    max_duration_secs: u64,
    max_source_width: u32,
    max_source_height: u32,
    max_source_fps: u32,
    max_segment_count: usize,
    max_total_output_bytes: u64,
}

struct RuntimeMediaToolSource {
    file: fs::File,
    size: u64,
}

struct RuntimeMediaToolImport {
    path: PathBuf,
    created: bool,
}
/// One critical step of a mint, traced at both ends.
///
/// Every trace on this path used to be an *end* marker -- "protected",
/// "provisioned", "verified". With only those, a step that is slow and a step
/// that is stuck look identical until it finishes, which is why a publish that
/// took nineteen minutes could not be attributed to any phase afterwards. A
/// step now announces itself before it begins and reports how long it took when
/// it stops.
///
/// It reports even when it stops by failing: the end is logged from `Drop`, so
/// an early `?` return still leaves a boundary in the log, marked `abandoned`
/// rather than `ok`. That is the case worth seeing, and it is the one an
/// explicit call at the end of the happy path would always miss.
///
/// DEBUG on purpose. An operator at INFO wants the outcome, not the itinerary;
/// this is for whoever is asking where the time went.
pub(crate) struct RuntimeMintStep {
    name: &'static str,
    request_id: String,
    started: std::time::Instant,
    outcome: &'static str,
    repeating: bool,
}

impl RuntimeMintStep {
    /// A step that happens once in a publish.
    pub(crate) fn begin(name: &'static str, request_id: &str) -> Self {
        tracing::debug!(step = name, %request_id, "runtime custody step: begin");
        Self {
            name,
            request_id: request_id.to_string(),
            started: std::time::Instant::now(),
            outcome: "abandoned",
            repeating: false,
        }
    }

    /// A step re-run by every poll of a wait.
    ///
    /// TRACE, not DEBUG. Waiting for a wallet approval or for a block to
    /// finalise means re-entering the same three steps every few seconds for
    /// minutes on end, and at DEBUG that repetition buries the things that
    /// happen once. What a reader needs from a wait is when it started and when
    /// it ended -- both of which are logged at DEBUG elsewhere -- not a
    /// transcript of every time nothing changed.
    pub(crate) fn begin_repeating(name: &'static str, request_id: &str) -> Self {
        tracing::trace!(step = name, %request_id, "runtime custody step: begin");
        Self {
            name,
            request_id: request_id.to_string(),
            started: std::time::Instant::now(),
            outcome: "abandoned",
            repeating: true,
        }
    }

    /// Mark the step as having run to completion. Anything that returns before
    /// this is reached is reported as abandoned.
    pub(crate) fn ok(mut self) {
        self.outcome = "ok";
    }

    /// Mark the step as having stopped because what it waits for has not
    /// happened yet.
    ///
    /// Without this, a chain answer of "not finalized yet" -- the expected
    /// shape of that wait, repeated every few seconds -- reads identically to a
    /// step that fell over. Distinguishing them is the whole point of recording
    /// an outcome, and `abandoned` is only useful if it stays rare.
    pub(crate) fn pending(mut self) {
        self.outcome = "pending";
    }
}

impl Drop for RuntimeMintStep {
    fn drop(&mut self) {
        let elapsed_ms = self.started.elapsed().as_millis();
        // A repeating step that ends badly is still worth DEBUG: the point of
        // quietening the loop is to hide the times nothing happened, not the
        // time something did.
        if self.repeating && self.outcome != "abandoned" {
            tracing::trace!(
                step = self.name,
                request_id = %self.request_id,
                outcome = self.outcome,
                elapsed_ms,
                "runtime custody step: end"
            );
            return;
        }
        tracing::debug!(
            step = self.name,
            request_id = %self.request_id,
            outcome = self.outcome,
            elapsed_ms,
            "runtime custody step: end"
        );
    }
}

/// Times one leg *inside* a step, for steps long enough that knowing they took
/// five minutes says nothing useful.
///
/// `availability_publish` is the case that forced this: it is a single step
/// that publishes the ciphertext, then reads a receipt, a manifest, and every
/// file back to prove the object replicated. When it takes five minutes, the
/// step timer can only report five minutes -- which of those legs spent them
/// is exactly the question, and was previously answerable only by guessing.
///
/// Reports on drop like `RuntimeMintStep`, so a leg that returns early is
/// still recorded rather than vanishing.
pub(crate) struct RuntimeCustodyPhase {
    name: &'static str,
    detail: String,
    started: std::time::Instant,
    outcome: &'static str,
}

impl RuntimeCustodyPhase {
    pub(crate) fn begin(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            detail: detail.into(),
            started: std::time::Instant::now(),
            outcome: "abandoned",
        }
    }

    pub(crate) fn ok(mut self) {
        self.outcome = "ok";
    }
}

impl Drop for RuntimeCustodyPhase {
    fn drop(&mut self) {
        tracing::debug!(
            phase = self.name,
            detail = %self.detail,
            outcome = self.outcome,
            elapsed_ms = self.started.elapsed().as_millis(),
            "runtime custody phase"
        );
    }
}

pub(crate) const RUNTIME_CUSTODY_COMPOSITION_MISSING_MESSAGE: &str =
    "Runtime custody composition is not configured";
pub(crate) const RUNTIME_CUSTODY_PURCHASE_DENIED_MESSAGE: &str =
    "Runtime custody purchase is denied before buy";
pub(crate) const RUNTIME_CUSTODY_PURCHASE_PENDING_MESSAGE: &str =
    "Runtime custody purchase is pending exact Wallet or Chain settlement";
pub(crate) const RUNTIME_CUSTODY_PURCHASE_UNBOUND_MESSAGE: &str =
    "Runtime custody purchase target is not bound on chain";
pub(crate) const RUNTIME_CUSTODY_PURCHASE_UNAVAILABLE_MESSAGE: &str =
    "Runtime custody purchase is unavailable";
pub(crate) const RUNTIME_CUSTODY_DOWNLOAD_DENIED_MESSAGE: &str =
    "Runtime custody download is denied without an owned copy";
pub(crate) const RUNTIME_CUSTODY_DOWNLOAD_UNAVAILABLE_MESSAGE: &str =
    "Runtime custody download is unavailable";
/// A download refusal a person can act on, carried as data -- `code` on the
/// error envelope -- so an app says what is missing without reading the
/// sentence, which stays `RUNTIME_CUSTODY_DOWNLOAD_DENIED_MESSAGE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyDownloadRefusal {
    /// The chain grants this account no access to the item.
    NoAccess,
    /// The head grants it and the finalized block does not yet: the grant is
    /// still being confirmed, and custody would refuse it until it is.
    Confirming,
}

impl RuntimeCustodyDownloadRefusal {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::NoAccess => "no_access",
            Self::Confirming => "access_confirming",
        }
    }

    pub(crate) fn error(self) -> anyhow::Error {
        anyhow::Error::new(self).context(RUNTIME_CUSTODY_DOWNLOAD_DENIED_MESSAGE)
    }
}

impl std::fmt::Display for RuntimeCustodyDownloadRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NoAccess => "the chain grants this account no access to the item",
            Self::Confirming => "the chain has not finalized this account's access yet",
        })
    }
}

impl std::error::Error for RuntimeCustodyDownloadRefusal {}

/// An item whose pool this Home cannot reach (Plan B T4.7): no copy of it can
/// be built, bought or opened here until the pool is added in Custody. It
/// travels as data -- `code` `custody_elsewhere` -- so an app says why
/// instead of failing generically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeCustodyElsewhere;

impl RuntimeCustodyElsewhere {
    pub(crate) const CODE: &'static str = "custody_elsewhere";

    pub(crate) fn error() -> anyhow::Error {
        anyhow::Error::new(Self).context(RUNTIME_CUSTODY_ELSEWHERE_MESSAGE)
    }

    /// Whether `error` is, at any depth, this refusal. Plan B T4.6: an item
    /// whose pool cannot be reached from here ([`RuntimeCustodyUnresolved`])
    /// answers the same refusal code to buy, adoption and download (T4.7).
    pub(crate) fn is(error: &anyhow::Error) -> bool {
        error.downcast_ref::<Self>().is_some()
            || error.downcast_ref::<RuntimeCustodyUnresolved>().is_some()
    }
}

impl std::fmt::Display for RuntimeCustodyElsewhere {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("this Home cannot reach the custody pool of this item")
    }
}

impl std::error::Error for RuntimeCustodyElsewhere {}

/// Plan B T4.7: the code stays `custody_elsewhere`; its words say what to do.
pub(crate) const RUNTIME_CUSTODY_ELSEWHERE_MESSAGE: &str =
    "This item's pool cannot be reached from this Home yet. Add the pool in Custody.";

/// Plan B T4.6: the item's pool cannot be found or used from this Home: no
/// descriptor names its epoch (own, served or known), or the listing is an
/// imported package on a Home that does not hold its ciphertext (S4-Q14).
/// It travels as data -- `code` `custody_unresolved` -- and is final until
/// the pool is added in Custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeCustodyUnresolved;

impl RuntimeCustodyUnresolved {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const CODE: &'static str = "custody_unresolved";

    pub(crate) fn error() -> anyhow::Error {
        anyhow::Error::new(Self).context(RUNTIME_CUSTODY_UNRESOLVED_MESSAGE)
    }

    /// Whether `error` is, at any depth, this refusal.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is(error: &anyhow::Error) -> bool {
        error.downcast_ref::<Self>().is_some()
    }
}

impl std::fmt::Display for RuntimeCustodyUnresolved {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("this item's pool cannot be reached from this Home")
    }
}

impl std::error::Error for RuntimeCustodyUnresolved {}

pub(crate) const RUNTIME_CUSTODY_UNRESOLVED_MESSAGE: &str =
    "This item's pool cannot be reached from this Home yet. Add the pool in Custody.";
/// Plan B T4.5 (C3): a pool viewer read at or after its session's end, the
/// signed rights expiry capped by the attestations. Its `code` tells the
/// Player or Reader to keep its place and run the open once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeCustodyPoolSessionRenewalRequired;

impl RuntimeCustodyPoolSessionRenewalRequired {
    pub(crate) const CODE: &'static str =
        crate::protected_content_pool_open::POOL_SESSION_RENEWAL_REQUIRED;

    pub(crate) fn error() -> anyhow::Error {
        anyhow::Error::new(Self).context(RUNTIME_CUSTODY_POOL_SESSION_RENEWAL_REQUIRED_MESSAGE)
    }

    /// Whether `error` is, at any depth, this answer.
    pub(crate) fn is(error: &anyhow::Error) -> bool {
        error.downcast_ref::<Self>().is_some()
    }
}

impl std::fmt::Display for RuntimeCustodyPoolSessionRenewalRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(Self::CODE)
    }
}

impl std::error::Error for RuntimeCustodyPoolSessionRenewalRequired {}

pub(crate) const RUNTIME_CUSTODY_POOL_SESSION_RENEWAL_REQUIRED_MESSAGE: &str =
    "The viewing session reached its end. Open the item again to continue.";

/// OPEN-LOOP F2: a pool open that failed after the Wallet signed. The signed
/// rights were spent on its one release (rev14), so asking again would mean a
/// new Wallet request: the open ends here, with no resumable stage, and the
/// Player or Reader offers Retry for the person to press. Its `code` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeCustodyPoolContentUnavailable;

impl RuntimeCustodyPoolContentUnavailable {
    pub(crate) const CODE: &'static str = "content_unavailable";

    /// The refusal, with `cause` in its detail chain.
    pub(crate) fn error(cause: &anyhow::Error) -> anyhow::Error {
        anyhow::Error::new(Self)
            .context(format!("{cause:?}"))
            .context(RUNTIME_CUSTODY_POOL_CONTENT_UNAVAILABLE_MESSAGE)
    }

    /// Whether `error` is, at any depth, this refusal.
    pub(crate) fn is(error: &anyhow::Error) -> bool {
        error.downcast_ref::<Self>().is_some()
    }
}

impl std::fmt::Display for RuntimeCustodyPoolContentUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(Self::CODE)
    }
}

impl std::error::Error for RuntimeCustodyPoolContentUnavailable {}

pub(crate) const RUNTIME_CUSTODY_POOL_CONTENT_UNAVAILABLE_MESSAGE: &str =
    "This file isn't available from the pool right now. Try again later.";

/// Plan B T4.4: the item's pool resolves, but none of its nodes can serve
/// this Home now. Not resumable; the viewer offers Retry (S4-Q16).
pub(crate) const RUNTIME_CUSTODY_NO_ELIGIBLE_SERVER_MESSAGE: &str =
    "No node of this item's pool can play it now. Try again later.";

/// The native pay token: the pay token a granted listing states.
pub(crate) const RUNTIME_CUSTODY_ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
/// `acquisition_stage.stage` of a granted copy. The stage names no
/// transaction: every transaction field of it is empty, because none exists.
pub(crate) const RUNTIME_CUSTODY_GRANT_STAGE: &str = "grant";
pub(crate) const RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE: &str =
    "Runtime custody open is denied before purchase";
pub(crate) const RUNTIME_CUSTODY_OPEN_FINALIZING_MESSAGE: &str =
    "Runtime custody open awaits chain finality of the acquisition";
pub(crate) const RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE: &str =
    "Runtime custody content availability is unavailable";
pub(crate) const RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE: &str =
    "Runtime custody decrypt provider is unavailable";
pub(crate) const RUNTIME_CUSTODY_RELEASE_APPROVAL_UNAVAILABLE_MESSAGE: &str =
    "Runtime custody viewer release approval is unavailable";
/// The Wallet holds the viewer release rights-signature request as a pending
/// managed approval; the caller approves it in the Wallet and re-issues the
/// identical open, which resumes the persisted release.
pub(crate) const RUNTIME_CUSTODY_OPEN_PENDING_MESSAGE: &str =
    "Runtime custody viewer release is pending exact Wallet approval";

/// How long one viewer open stays resumable while the person answers the
/// Wallet.
///
/// Every first rights-signature request answers `requires_approval`, so this
/// window is the whole of the time a person has to approve an open. It used to
/// be 60 s, which most human approvals lost: past it the record was torn down,
/// a fresh recipient and a new Wallet request were raised, and the approval the
/// person had just granted had nothing left to complete.
///
/// 290 s is the largest window that stays inside both contracts the open
/// depends on. `MAX_RECIPIENT_KEY_AUTHORIZATION_LIFETIME_SECS` and
/// `MAX_RIGHTS_REQUEST_LIFETIME_SECS` are each 300 s measured from `issued_at`,
/// and the open issues both 5 s behind `now`. The short-lived artifacts of the
/// release itself -- release request, release operation, node contribution,
/// terminal receipt -- are all minted after the signature comes back, so human
/// latency never reaches them and none of them is widened here.
///
/// The Wallet's own approval record expires at the rights request's own
/// `expires_at`, so both sides of the wait now lapse together: a window that
/// closes here is a window that closed there, and the Wallet's existing
/// lapsed-request path accepts the fresh ask rather than colliding with a
/// stale one.
pub(crate) const RUNTIME_CUSTODY_OPEN_APPROVAL_WINDOW_SECS: u64 = 290;

/// The least time a release operation needs left to be worth resuming: one
/// round of node calls, rights then contribution, with each node's bounded
/// chain read (about 20 s at most) inside it. An operation with less is
/// replaced by a fresh one when no custody node can have acted on it.
const RUNTIME_CUSTODY_RELEASE_RESUME_MIN_SECS: u64 = 20;

/// Fail-closed mapping for the viewer release path: logs the cause and source
/// line at warn and keeps the stable message outermost while carrying the
/// cause chain (surfaced as the library error `detail`).
macro_rules! release_unavailable {
    () => {
        |error| {
            tracing::warn!(
                line = line!(),
                error = ?error,
                "Runtime custody viewer release failed closed"
            );
            anyhow::anyhow!("{:?}", error)
                .context(format!("{}:{}", file!(), line!()))
                .context(RUNTIME_CUSTODY_RELEASE_APPROVAL_UNAVAILABLE_MESSAGE)
        }
    };
}

macro_rules! release_unavailable_missing {
    () => {
        || {
            tracing::warn!(
                line = line!(),
                "Runtime custody viewer release failed closed"
            );
            anyhow::anyhow!("{}:{}", file!(), line!())
                .context(RUNTIME_CUSTODY_RELEASE_APPROVAL_UNAVAILABLE_MESSAGE)
        }
    };
}
/// Wire identity of the typed answer a creator app gets when an attempt to
/// protect a file is refused because an earlier attempt for the same file is
/// already on record at different terms.
pub(crate) const RUNTIME_CUSTODY_CREATOR_MINT_BLOCKED_SCHEMA_V1: &str =
    "elastos.protected-content.creator-mint-blocked/v1";

/// What an earlier creator mint already on record means for a new attempt at
/// different terms, and what the creator may still do about it.
///
/// Mirrors [`RuntimeMintCreatorStage`] one-to-one and exists separately only so
/// the wire spelling an app branches on is fixed here rather than derived from
/// a type an app cannot see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyCreatorMintBlockedState {
    /// Terms are on record and nothing was raised on any ledger.
    RecordedOnly,
    /// A transaction is out for the creator's approval and may still settle.
    ApprovalOutstanding,
    /// The mint settled; a seller and a token id exist.
    AlreadyMinted,
}

impl RuntimeCustodyCreatorMintBlockedState {
    const fn wire_value(self) -> &'static str {
        match self {
            Self::RecordedOnly => "recorded_only",
            Self::ApprovalOutstanding => "approval_outstanding",
            Self::AlreadyMinted => "already_minted",
        }
    }
}

/// What a refused attempt collided with: how far the recorded attempt got and
/// which of its terms the new one would change.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyCreatorMintConflict {
    pub(crate) stage: Option<RuntimeCustodyUnfinishedMintStage>,
    pub(crate) differing_terms: Vec<&'static str>,
}

/// A refusal that carries its reason as data.
///
/// Re-terming a mint already in flight stays refused. What this adds is that
/// the creator is told what was recorded and which action is open to them,
/// without any app having to read the sentence. The recorded copies and price
/// travel here, to the person who entered them — never into the log.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyCreatorMintBlocked {
    state: RuntimeCustodyCreatorMintBlockedState,
    mint_id: String,
    copies: String,
    price: String,
    progress: Option<Value>,
    conflict: Option<RuntimeCustodyCreatorMintConflict>,
    /// Whether Resume can move this attempt forward. False only for an
    /// attempt whose mint reverted as a duplicate: nothing it does settles it.
    resumable: bool,
}

impl RuntimeCustodyCreatorMintBlocked {
    pub(crate) fn new(mint_id: Digest32, recorded: &RuntimeMintCreatorState) -> Self {
        let state = match recorded.stage() {
            RuntimeMintCreatorStage::Recorded => {
                RuntimeCustodyCreatorMintBlockedState::RecordedOnly
            }
            RuntimeMintCreatorStage::EffectRaised => {
                RuntimeCustodyCreatorMintBlockedState::ApprovalOutstanding
            }
            RuntimeMintCreatorStage::Settled => {
                RuntimeCustodyCreatorMintBlockedState::AlreadyMinted
            }
        };
        Self {
            state,
            mint_id: hex::encode(mint_id.as_bytes()),
            copies: recorded.desired_terms().copies().to_string(),
            price: recorded.desired_terms().price().to_string(),
            progress: None,
            conflict: None,
            resumable: true,
        }
    }

    /// An attempt whose mint transaction reverted because its content id was
    /// already bound (`IPAlreadyBound`, `InvalidTokenId`), and whose content id
    /// the chain's own binding confirms is bound. The file is minted; this
    /// attempt can never settle it, so it offers neither Start over nor
    /// Resume.
    pub(crate) fn reverted_as_duplicate(
        mint_id: Digest32,
        recorded: &RuntimeMintCreatorState,
    ) -> Self {
        Self {
            state: RuntimeCustodyCreatorMintBlockedState::AlreadyMinted,
            resumable: false,
            ..Self::new(mint_id, recorded)
        }
    }

    /// Attach what the new attempt collided with, so an app can say which
    /// terms differ and offer the recorded attempt back instead of a dead end.
    #[must_use]
    pub(crate) fn with_conflict(mut self, conflict: RuntimeCustodyCreatorMintConflict) -> Self {
        self.conflict = Some(conflict);
        self
    }

    /// Attach how far the blocked mint actually got.
    ///
    /// Opt-in for the same reason the waiting state's is: only a caller holding
    /// the mint record can say, and a caller that cannot must not fill it with
    /// a guess. It is what lets an app show which stage a blocked attempt
    /// reached instead of only that one exists.
    #[must_use]
    pub(crate) fn with_progress(mut self, progress: Value) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Stage name for the operator log. Carries no terms and no account.
    pub(crate) const fn state_label(&self) -> &'static str {
        self.state.wire_value()
    }

    pub(crate) fn as_json(&self) -> Value {
        let mut answer = json!({
            "schema": RUNTIME_CUSTODY_CREATOR_MINT_BLOCKED_SCHEMA_V1,
            "state": self.state.wire_value(),
            "mint_id": self.mint_id,
            "recorded_copies": self.copies,
            "recorded_price": self.price,
            // A refused attempt is one whose transaction was sent or mined, or
            // that is listed: it is never set aside, only resumed.
            "can_start_over": false,
            // Resuming re-runs the recorded attempt from its own terms, which
            // moves it forward in every state: a settled mint whose listing
            // never published is finished by it, and a listed one only replays.
            // A mint that reverted as a duplicate is the one it cannot move.
            "can_resume": self.resumable,
        });
        if let Some(progress) = self.progress.as_ref() {
            answer["progress"] = progress.clone();
        }
        if let Some(conflict) = self.conflict.as_ref() {
            answer["differing_terms"] = json!(conflict.differing_terms);
            if let Some(stage) = conflict.stage {
                answer["stage"] = json!(stage.wire_value());
            }
        }
        answer
    }
}

impl std::fmt::Display for RuntimeCustodyCreatorMintBlocked {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self.state {
            RuntimeCustodyCreatorMintBlockedState::RecordedOnly => {
                "An earlier attempt to protect this file is still on record at different terms"
            }
            RuntimeCustodyCreatorMintBlockedState::ApprovalOutstanding => {
                "An earlier attempt to protect this file already sent its transaction, so its terms can no longer change; resume it to finish"
            }
            RuntimeCustodyCreatorMintBlockedState::AlreadyMinted => {
                "This file is already protected and listed, so its terms can no longer change"
            }
        })
    }
}

impl std::error::Error for RuntimeCustodyCreatorMintBlocked {}

/// Wire identity of the state an app renders while a purchase settles.
pub(crate) const RUNTIME_CUSTODY_BUY_PROGRESS_SCHEMA_V1: &str =
    "elastos.protected-content.buy-progress/v1";

/// Where one purchase has got to.
///
/// A purchase is a sequence of waits, not a request: the wallet holds an
/// approval the person answers, the chain takes its own time to confirm what
/// they approved, and the right they bought becomes readable a block later
/// still. Each of those used to arrive as the same sentence, and Marketplace
/// dropped the sentence and showed "Media action could not be completed", so a
/// purchase that was proceeding normally read as one that had failed.
///
/// The stages are the buy twin of [`RuntimeCustodyOpenStage`] and carry the
/// same two facts an app decides from: whether asking again can answer
/// differently, and whether a person has to do something first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyBuyStage {
    /// The seller's payment token needs an allowance before the purchase can
    /// move it. Only an ERC-20 listing reaches this stage; a listing priced in
    /// the chain's own coin never does.
    AllowanceApproval,
    /// The Wallet holds the purchase itself. This is the approval that spends.
    PurchaseApproval,
    /// Approved, and the chain has not yet produced the evidence the purchase
    /// needs. Nobody can hurry it and nobody need act.
    ChainSettlement,
    /// The purchase is on the chain and the right it bought is not yet
    /// readable at the block Runtime trusts. The same purchase completes as
    /// soon as it is.
    AccessEvidence,
    /// The person answered the Wallet by declining. Asking again re-raises the
    /// same request rather than changing this answer, so an app offers a fresh
    /// purchase instead of a retry.
    Declined,
}

impl RuntimeCustodyBuyStage {
    const fn wire_value(self) -> &'static str {
        match self {
            Self::AllowanceApproval => "allowance_approval",
            Self::PurchaseApproval => "purchase_approval",
            Self::ChainSettlement => "chain_settlement",
            Self::AccessEvidence => "access_evidence",
            Self::Declined => "declined",
        }
    }

    /// Whether re-issuing the identical buy can produce a different answer.
    const fn resumable(self) -> bool {
        match self {
            Self::AllowanceApproval
            | Self::PurchaseApproval
            | Self::ChainSettlement
            | Self::AccessEvidence => true,
            Self::Declined => false,
        }
    }

    /// Whether the person has to act before this stage can move.
    const fn needs_an_answer(self) -> bool {
        matches!(self, Self::AllowanceApproval | Self::PurchaseApproval)
    }
}

/// How far a purchase has got, carried as data beside the stable message.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyBuyProgress {
    stage: RuntimeCustodyBuyStage,
    /// Who is being waited on, and only while that is a fact worth stating. A
    /// chain wait names nobody: the signer has already done everything asked
    /// of them.
    approval: Option<RuntimeCustodyBuyApproval>,
}

/// Who answers the Wallet for a purchase, and where they answer it.
#[derive(Debug, Clone)]
struct RuntimeCustodyBuyApproval {
    /// True when the account is an external wallet reached through a
    /// connector, so the outstanding approval needs the person to act there.
    external_signer: bool,
    /// Names the connector when there is one, so an app can say "MetaMask"
    /// rather than "your wallet".
    connector_id: Option<String>,
}

impl RuntimeCustodyBuyProgress {
    /// The Wallet holds an approval for this purchase.
    pub(crate) fn awaiting_approval(
        stage: RuntimeCustodyBuyStage,
        external_signer: bool,
        connector_id: Option<&str>,
    ) -> Self {
        Self {
            stage,
            approval: Some(RuntimeCustodyBuyApproval {
                external_signer,
                connector_id: connector_id.map(ToString::to_string),
            }),
        }
    }

    /// A wait that asks nothing of anyone: the chain, or the right becoming
    /// readable.
    pub(crate) const fn waiting(stage: RuntimeCustodyBuyStage) -> Self {
        Self {
            stage,
            approval: None,
        }
    }

    /// The person declined the Wallet request.
    pub(crate) const fn declined() -> Self {
        Self {
            stage: RuntimeCustodyBuyStage::Declined,
            approval: None,
        }
    }

    /// Stage name for the operator log. Carries no account and no address.
    pub(crate) const fn stage_label(&self) -> &'static str {
        self.stage.wire_value()
    }

    /// Whether the person has to do something, or the purchase is simply
    /// waiting. An app polls in both cases; only one of them asks anything of
    /// the buyer.
    pub(crate) const fn awaits_person(&self) -> bool {
        match self.approval {
            Some(ref approval) => self.stage.needs_an_answer() && approval.external_signer,
            None => false,
        }
    }

    pub(crate) fn as_json(&self) -> Value {
        let mut answer = json!({
            "schema": RUNTIME_CUSTODY_BUY_PROGRESS_SCHEMA_V1,
            "stage": self.stage.wire_value(),
            "resumable": self.stage.resumable(),
            "awaits_person": self.awaits_person(),
        });
        if let Some(approval) = self.approval.as_ref() {
            answer["external_signer"] = Value::Bool(approval.external_signer);
            answer["connector_id"] = approval
                .connector_id
                .as_ref()
                .map_or(Value::Null, |id| Value::String(id.clone()));
        }
        answer
    }
}

impl std::fmt::Display for RuntimeCustodyBuyProgress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.stage {
            RuntimeCustodyBuyStage::AllowanceApproval
            | RuntimeCustodyBuyStage::PurchaseApproval
                if self.awaits_person() =>
            {
                let what = if matches!(self.stage, RuntimeCustodyBuyStage::AllowanceApproval) {
                    "Allow the payment"
                } else {
                    "Approve this purchase"
                };
                match self
                    .approval
                    .as_ref()
                    .and_then(|approval| approval.connector_id.as_deref())
                {
                    Some(connector) => write!(
                        formatter,
                        "{what} in {connector}; the purchase continues on its own once you do"
                    ),
                    None => write!(
                        formatter,
                        "{what} in your wallet; the purchase continues on its own once you do"
                    ),
                }
            }
            RuntimeCustodyBuyStage::AllowanceApproval
            | RuntimeCustodyBuyStage::PurchaseApproval => {
                write!(
                    formatter,
                    "The wallet approval is still completing; nothing else is needed"
                )
            }
            RuntimeCustodyBuyStage::ChainSettlement => write!(
                formatter,
                "The purchase is approved and waiting for the network to confirm it; nothing \
                 else is needed"
            ),
            RuntimeCustodyBuyStage::AccessEvidence => write!(
                formatter,
                "The purchase is on the network and the copy is being confirmed as yours; \
                 nothing else is needed"
            ),
            RuntimeCustodyBuyStage::Declined => write!(
                formatter,
                "This purchase was declined in the wallet, so it did not go ahead"
            ),
        }
    }
}

impl std::error::Error for RuntimeCustodyBuyProgress {}

/// Wire identity of the typed answer an app gets when the wallet's transaction
/// default for a chain cannot carry a protected-content transaction.
pub(crate) const RUNTIME_CUSTODY_WALLET_DEFAULT_UNUSABLE_SCHEMA_V1: &str =
    "elastos.protected-content.wallet-default-unusable/v1";

/// Why the wallet's transaction default for one chain cannot be used.
///
/// Five distinct conditions used to share one opaque sentence, so a creator or
/// a buyer was told only that something was unavailable and no app could tell
/// which of the five it was, let alone what to offer. Each arm here names one
/// condition; the sentence in `Display` names the way out of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyWalletDefaultReason {
    /// No account is marked as the transaction default on this chain.
    NoTransactionDefaultForChainNamespace,
    /// Two accounts claim the default at the same instant, so neither wins.
    AmbiguousTransactionDefault,
    /// The default names an account the wallet no longer holds on this chain.
    DefaultAccountNotInWallet,
    /// The default cannot produce a signature: an external wallet whose
    /// connector is not linked. A linked one is signable through the handoff.
    DefaultAccountSigningUnavailable,
    /// The default's address is not usable on this chain.
    DefaultAccountAddressInvalid,
}

impl RuntimeCustodyWalletDefaultReason {
    /// Stable machine-readable spelling, shared by the wire answer and the
    /// operator log so the two can never drift apart.
    pub(crate) const fn wire_value(self) -> &'static str {
        match self {
            Self::NoTransactionDefaultForChainNamespace => {
                "no_transaction_default_for_chain_namespace"
            }
            Self::AmbiguousTransactionDefault => "ambiguous_transaction_default",
            Self::DefaultAccountNotInWallet => "default_account_not_in_wallet_for_chain_namespace",
            Self::DefaultAccountSigningUnavailable => "default_account_signing_unavailable",
            Self::DefaultAccountAddressInvalid => "default_account_address_invalid",
        }
    }
}

/// A refusal that carries its reason as data, sibling to
/// [`RuntimeCustodyCreatorMintBlocked`].
///
/// The refusal is unchanged and the opaque top-level sentence still stands
/// outermost, so nothing that matches on it breaks. What this adds is a typed
/// field an app branches on to offer the one action that fixes the state. It
/// carries the chain namespace so the sentence can name the network, and
/// nothing else: no account id, no address, no balance, no terms.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyWalletDefaultUnusable {
    reason: RuntimeCustodyWalletDefaultReason,
    chain_namespace: String,
}

impl RuntimeCustodyWalletDefaultUnusable {
    pub(crate) fn new(reason: RuntimeCustodyWalletDefaultReason, chain_namespace: &str) -> Self {
        Self {
            reason,
            chain_namespace: chain_namespace.to_string(),
        }
    }

    pub(crate) const fn reason(&self) -> RuntimeCustodyWalletDefaultReason {
        self.reason
    }

    /// Reason code for the operator log. Carries no account and no address.
    pub(crate) const fn reason_label(&self) -> &'static str {
        self.reason.wire_value()
    }

    pub(crate) fn as_json(&self) -> Value {
        json!({
            "schema": RUNTIME_CUSTODY_WALLET_DEFAULT_UNUSABLE_SCHEMA_V1,
            "reason": self.reason.wire_value(),
            "chain_namespace": self.chain_namespace,
        })
    }
}

impl std::fmt::Display for RuntimeCustodyWalletDefaultUnusable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let network = &self.chain_namespace;
        match self.reason {
            RuntimeCustodyWalletDefaultReason::NoTransactionDefaultForChainNamespace => write!(
                formatter,
                "No account is set as the transaction default for {network}; set one in Wallet, then try again"
            ),
            RuntimeCustodyWalletDefaultReason::AmbiguousTransactionDefault => write!(
                formatter,
                "More than one account claims the transaction default for {network}; set a single default in Wallet, then try again"
            ),
            RuntimeCustodyWalletDefaultReason::DefaultAccountNotInWallet => write!(
                formatter,
                "The transaction default for {network} names an account this wallet no longer holds; set a current account as the default in Wallet, then try again"
            ),
            RuntimeCustodyWalletDefaultReason::DefaultAccountSigningUnavailable => write!(
                formatter,
                "The transaction default for {network} is an external wallet with no connector linked, so it cannot sign; link it in Wallet, or set a built-in account as the default, then try again"
            ),
            RuntimeCustodyWalletDefaultReason::DefaultAccountAddressInvalid => write!(
                formatter,
                "The transaction default for {network} has an address this network cannot use; set an account on {network} as the default in Wallet, then try again"
            ),
        }
    }
}

impl std::error::Error for RuntimeCustodyWalletDefaultUnusable {}

/// Wire identity of the typed answer an app gets when a mint already under way
/// is bound to an account that is no longer the wallet's transaction default.
pub(crate) const RUNTIME_CUSTODY_CREATOR_WALLET_DRIFT_SCHEMA_V1: &str =
    "elastos.protected-content.creator-wallet-drift/v1";

/// A mint already under way names one account, and the wallet now names
/// another as its transaction default for that chain.
///
/// The recorded account wins — a retry must not switch payer mid-flight, which
/// is what makes an effect identity durable (PRINCIPLES.md 19). The defect this
/// answers is not the pinning; it is the *silence*. Before this, changing the
/// transaction default and re-publishing the same object completed the mint on
/// the old account with nothing said, so a creator who had deliberately
/// switched wallets was told only that the listing succeeded.
///
/// So the refusal is the honest move (PRINCIPLES.md 11): stop, name both
/// accounts, and give the two ways out — drop the recorded terms and start over
/// on the current default, or set the recorded account back as the default.
///
/// Unlike [`RuntimeCustodyWalletDefaultUnusable`], this one does carry
/// addresses. It has to: the whole refusal is "these two differ", and an app
/// that cannot say which two has nothing to show. They are the creator's own
/// accounts, returned to the creator's own authenticated session, and the
/// Wallet surface already displays both. They stay out of the operator log all
/// the same — `reason_label` is the only thing logged.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyCreatorWalletDrift {
    chain_namespace: String,
    bound_address: String,
    default_address: String,
}

impl RuntimeCustodyCreatorWalletDrift {
    pub(crate) fn new(chain_namespace: &str, bound_address: &str, default_address: &str) -> Self {
        Self {
            chain_namespace: chain_namespace.to_string(),
            bound_address: bound_address.to_ascii_lowercase(),
            default_address: default_address.to_ascii_lowercase(),
        }
    }

    /// Reason code for the operator log. Carries no account and no address.
    pub(crate) const fn reason_label(&self) -> &'static str {
        "creator_mint_bound_account_is_not_the_transaction_default"
    }

    pub(crate) fn as_json(&self) -> Value {
        json!({
            "schema": RUNTIME_CUSTODY_CREATOR_WALLET_DRIFT_SCHEMA_V1,
            "reason": self.reason_label(),
            "chain_namespace": self.chain_namespace,
            "bound_address": self.bound_address,
            "default_address": self.default_address,
        })
    }
}

impl std::fmt::Display for RuntimeCustodyCreatorWalletDrift {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "This mint is already bound to {bound} from an earlier attempt, but the transaction \
             default for {network} is now {default}. A mint keeps the account it started with, so \
             finish it by setting {bound} back as the default, or discard the recorded terms for \
             this object and protect it again on {default}",
            bound = self.bound_address,
            network = self.chain_namespace,
            default = self.default_address,
        )
    }
}

impl std::error::Error for RuntimeCustodyCreatorWalletDrift {}

/// Wire identity of the typed answer an app gets when a wallet approval can
/// never complete.
pub(crate) const RUNTIME_CUSTODY_APPROVAL_CLOSED_SCHEMA_V1: &str =
    "elastos.protected-content.approval-closed/v1";

/// Why an outstanding wallet approval will never complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyApprovalClosedReason {
    /// The person declined it in their wallet.
    Rejected,
    /// It lapsed before anyone answered it.
    Expired,
}

impl RuntimeCustodyApprovalClosedReason {
    const fn wire_value(self) -> &'static str {
        match self {
            Self::Rejected => "approval_rejected",
            Self::Expired => "approval_expired",
        }
    }
}

/// A wallet approval that is finished and did not succeed.
///
/// This used to be indistinguishable from "not yet": every approval status
/// other than `completed` produced one "not completed" answer, so a declined
/// transaction read exactly like one the person had not got to. A caller
/// polling for completion waited on it forever.
///
/// Neither of these ever produced a signature, so neither can produce a
/// transaction — which is what makes them terminal rather than slow.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyApprovalClosed {
    reason: RuntimeCustodyApprovalClosedReason,
}

impl RuntimeCustodyApprovalClosed {
    pub(crate) const fn new(reason: RuntimeCustodyApprovalClosedReason) -> Self {
        Self { reason }
    }

    /// Reason code for the operator log. Carries no account and no address.
    pub(crate) const fn reason_label(&self) -> &'static str {
        self.reason.wire_value()
    }

    pub(crate) fn as_json(&self) -> Value {
        json!({
            "schema": RUNTIME_CUSTODY_APPROVAL_CLOSED_SCHEMA_V1,
            "reason": self.reason.wire_value(),
        })
    }
}

impl std::fmt::Display for RuntimeCustodyApprovalClosed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.reason {
            RuntimeCustodyApprovalClosedReason::Rejected => write!(
                formatter,
                "This transaction was declined in the wallet, so the listing did not complete"
            ),
            RuntimeCustodyApprovalClosedReason::Expired => write!(
                formatter,
                "This transaction approval expired before it was answered, so the listing did not \
                 complete"
            ),
        }
    }
}

impl std::error::Error for RuntimeCustodyApprovalClosed {}

/// Wire identity of the progress an app renders while a creator publish runs.
pub(crate) const RUNTIME_CUSTODY_CREATOR_PROGRESS_SCHEMA_V1: &str =
    "elastos.protected-content.creator-progress/v1";

/// How far a creator publish has actually got, read from the mint journal.
///
/// The Creator used to show four dots it drove itself, one of them labelled
/// "(not tracked)" because the client had no way to know: the whole
/// server-side pipeline happened inside one request, so "encrypt" went active
/// when the request was sent and "assemble" went done when it returned, and
/// the publish step in between was a guess dressed as a stage.
///
/// Every state here is evidence the journal already holds, so this cannot
/// drift from what the server actually did (PRINCIPLES.md 12) -- there is no
/// second source of truth to keep in step, only a projection of the first:
///
/// * `escrow`  the custody envelope. The mint record exists at all only once
///   protection produced an encrypted content identity, so reaching this
///   function means encryption is done; `custody_terminal` says whether the
///   2-of-3 envelope settled or aborted.
/// * `publish` the ciphertext reaching content availability, which is exactly
///   `content_availability` -- a verified receipt, not a hopeful one. This is
///   the stage that was untracked.
/// * `public_metadata` the mint's metadata reaching the public IPFS store
///   before a new approval. Nothing about it is persisted, so the journal
///   alone says only `pending` (no terms recorded), `done` (settled) or
///   `active`; the creator tail, which knows, says `done` once an approval
///   exists and `failed` when the publication failed
///   ([`runtime_custody_creator_progress_with_public_metadata`]).
/// * `listing` the chain mint and listing projection, which is the creator
///   state's own three-stage lifecycle.
///
/// The vocabulary is `pending` (has not begun), `active` (running), `done`
/// (durably finished) and `failed` (finished badly). A stage never claims to be
/// running when its input has not arrived, and never claims to be done because
/// it merely stopped.
pub(crate) fn runtime_custody_creator_progress(
    mint: &elastos_protected_content_runtime::PersistedRuntimeMint,
) -> Value {
    creator_progress(mint, None)
}

/// What the creator tail knows about the `public_metadata` stage that the
/// journal does not record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyPublicMetadataStage {
    /// An approval exists: its metadata was published before it was raised,
    /// or it settles under the authority it already has.
    Done,
    /// The publication, or the approval phase's admission, failed.
    Failed,
}

/// [`runtime_custody_creator_progress`] with the `public_metadata` stage the
/// creator tail established.
pub(crate) fn runtime_custody_creator_progress_with_public_metadata(
    mint: &elastos_protected_content_runtime::PersistedRuntimeMint,
    stage: RuntimeCustodyPublicMetadataStage,
) -> Value {
    creator_progress(mint, Some(stage))
}

fn creator_progress(
    mint: &elastos_protected_content_runtime::PersistedRuntimeMint,
    public_metadata: Option<RuntimeCustodyPublicMetadataStage>,
) -> Value {
    use elastos_protected_content_runtime::RuntimeCustodyTerminalKind;

    // A terminal is not a success. `custody_terminal` is `Some` for an aborted
    // partial provision too, and reporting that as "done" told a creator their
    // escrow had settled at the exact moment the mint became unrecoverable.
    let escrow = match mint.custody_terminal() {
        Some(RuntimeCustodyTerminalKind::CustodyProvisioned) => "done",
        Some(RuntimeCustodyTerminalKind::AbortedPartialProvision) => "failed",
        None => "active",
    };
    // Availability work begins only once the envelope has settled, so before
    // that this stage has not started. Saying "active" for work that has not
    // begun — and for work that now never will — is the same untruth one stage
    // along.
    let publish = match (escrow, mint.content_availability().is_some()) {
        (_, true) => "done",
        ("done", false) => "active",
        _ => "pending",
    };
    let listing = match mint
        .creator_state()
        .map(elastos_protected_content_runtime::RuntimeMintCreatorState::stage)
    {
        None => "pending",
        Some(elastos_protected_content_runtime::RuntimeMintCreatorStage::Settled) => "done",
        Some(_) => "active",
    };
    let public_metadata = match public_metadata {
        Some(RuntimeCustodyPublicMetadataStage::Done) => "done",
        Some(RuntimeCustodyPublicMetadataStage::Failed) => "failed",
        // The journal's view: it starts once terms are recorded and is done
        // once the mint settled; in between it has no evidence either way.
        None => match listing {
            "pending" => "pending",
            "done" => "done",
            _ => "active",
        },
    };
    json!({
        "schema": RUNTIME_CUSTODY_CREATOR_PROGRESS_SCHEMA_V1,
        "stages": [
            { "id": "escrow", "state": escrow },
            { "id": "publish", "state": publish },
            { "id": "public_metadata", "state": public_metadata },
            { "id": "listing", "state": listing },
        ],
    })
}

/// Wire identity of the typed answer an app gets while a protected-content
/// effect is still outstanding.
pub(crate) const RUNTIME_CUSTODY_EFFECT_PENDING_SCHEMA_V1: &str =
    "elastos.protected-content.effect-pending/v1";

/// What an outstanding effect is actually waiting for.
///
/// The distinction is the whole point: one of these needs the person to do
/// something and the other needs them to do nothing at all. Collapsing both
/// into "pending" is why the Creator told a creator to approve a transaction
/// they had already approved, while the real wait was chain evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyEffectPendingReason {
    /// The wallet approval has not completed. A managed account completes this
    /// in place; an external one is waiting on its connector, which means it is
    /// waiting on the person.
    WalletApproval,
    /// The approval is done and the chain has not yet produced the evidence the
    /// operation needs. Nobody can hurry it and nobody need act.
    ChainSettlement,
}

impl RuntimeCustodyEffectPendingReason {
    const fn wire_value(self) -> &'static str {
        match self {
            Self::WalletApproval => "wallet_approval",
            Self::ChainSettlement => "chain_settlement",
        }
    }
}

/// A non-terminal waiting state, carried as data rather than prose.
///
/// Apps used to detect this by matching the English word "pending" in the
/// message. That is the same defect class as the opaque refusal it sits next
/// to: control flow decided by a sentence that exists to be read by a person,
/// and that no test pins. This carries the reason instead, plus enough about
/// the signer for an app to say whose turn it is -- and, when the answer is
/// "nobody's", to stop asking the creator to click anything.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyEffectPending {
    reason: RuntimeCustodyEffectPendingReason,
    /// Who is being waited on, and only where that is a fact worth stating.
    ///
    /// `None` for a chain wait: the signer has already done everything asked of
    /// them, so naming them would answer a question nobody is asking — and the
    /// site that raises a chain wait genuinely does not have the account in
    /// hand, so a default here would be an invention rather than a fact.
    signer: Option<RuntimeCustodyEffectPendingSigner>,
    /// How far the operation has got, when the raising site knows. This rides
    /// the pending answer rather than a channel of its own because the pending
    /// answer IS the poll response: an app waiting on a publish has exactly one
    /// thing arriving, and a second transport for progress would be a second
    /// thing to keep in step with it.
    progress: Option<Value>,
}

#[derive(Debug, Clone)]
struct RuntimeCustodyEffectPendingSigner {
    /// True when the signer is an external wallet reached through a connector,
    /// so the outstanding approval needs the person to act in that connector.
    external: bool,
    /// Names the connector when there is one, so an app can say "MetaMask"
    /// rather than "your wallet". A connector id is a local wallet-surface
    /// identifier, not a secret and not an account.
    connector_id: Option<String>,
}

impl RuntimeCustodyEffectPending {
    /// Waiting on the wallet approval, which is the only wait that can need a
    /// person.
    pub(crate) fn awaiting_wallet_approval(
        external_signer: bool,
        connector_id: Option<&str>,
    ) -> Self {
        Self {
            reason: RuntimeCustodyEffectPendingReason::WalletApproval,
            signer: Some(RuntimeCustodyEffectPendingSigner {
                external: external_signer,
                connector_id: connector_id.map(ToString::to_string),
            }),
            progress: None,
        }
    }

    /// Approved already; waiting on the chain. Never needs a person.
    pub(crate) const fn awaiting_chain_settlement() -> Self {
        Self {
            reason: RuntimeCustodyEffectPendingReason::ChainSettlement,
            signer: None,
            progress: None,
        }
    }

    /// Reason code for the operator log. Carries no account and no address.
    pub(crate) const fn reason_label(&self) -> &'static str {
        self.reason.wire_value()
    }

    /// Whether the person has to do something, or the operation is simply
    /// waiting. An app polls in both cases; only one of them asks anything of
    /// the creator.
    pub(crate) const fn awaits_person(&self) -> bool {
        match self.signer {
            Some(ref signer) => {
                matches!(
                    self.reason,
                    RuntimeCustodyEffectPendingReason::WalletApproval
                ) && signer.external
            }
            None => false,
        }
    }

    pub(crate) fn as_json(&self) -> Value {
        let mut answer = json!({
            "schema": RUNTIME_CUSTODY_EFFECT_PENDING_SCHEMA_V1,
            "reason": self.reason.wire_value(),
            "awaits_person": self.awaits_person(),
        });
        if let Some(signer) = self.signer.as_ref() {
            answer["external_signer"] = Value::Bool(signer.external);
            answer["connector_id"] = signer
                .connector_id
                .as_ref()
                .map_or(Value::Null, |id| Value::String(id.clone()));
        }
        if let Some(progress) = self.progress.as_ref() {
            answer["progress"] = progress.clone();
        }
        answer
    }

    /// Attach how far the publish has got. Only the sites that have the mint
    /// record in hand can say, and one of them (the chain-provider answer)
    /// cannot -- so this is opt-in rather than a constructor argument that
    /// would have to be filled with a guess.
    #[must_use]
    pub(crate) fn with_progress(mut self, progress: Value) -> Self {
        self.progress = Some(progress);
        self
    }
}

impl std::fmt::Display for RuntimeCustodyEffectPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.reason {
            RuntimeCustodyEffectPendingReason::ChainSettlement => write!(
                formatter,
                "The transaction is approved and waiting for the network to confirm it; nothing \
                 else is needed"
            ),
            RuntimeCustodyEffectPendingReason::WalletApproval if self.awaits_person() => match self
                .signer
                .as_ref()
                .and_then(|signer| signer.connector_id.as_deref())
            {
                Some(connector) => write!(
                    formatter,
                    "Approve this transaction in {connector}; the listing continues on its own \
                         once you do"
                ),
                None => write!(
                    formatter,
                    "Approve this transaction in your wallet; the listing continues on its own \
                         once you do"
                ),
            },
            RuntimeCustodyEffectPendingReason::WalletApproval => write!(
                formatter,
                "The wallet approval is still completing; nothing else is needed"
            ),
        }
    }
}

impl std::error::Error for RuntimeCustodyEffectPending {}

/// Wire identity of the state an app renders while a protected item opens.
pub(crate) const RUNTIME_CUSTODY_OPEN_PROGRESS_SCHEMA_V1: &str =
    "elastos.protected-content.open-progress/v1";

/// Where one open has got to.
///
/// The open ceremony has three outcomes a viewer has to present differently,
/// and until now all three arrived as one English sentence in an error. The
/// viewer showed the sentence and stopped, so the ordinary case -- the Wallet
/// holding a rights-signature request that the person is about to approve --
/// read exactly like a file that could never be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyOpenStage {
    /// The Wallet holds the rights-signature request for this exact open. The
    /// person approves it there, and the identical open then resumes the same
    /// attempt against the recipient the decrypt provider still holds.
    RightsApproval,
    /// Something this open depends on is absent for now: verified content
    /// availability, the decrypt provider, or the custody composition. The same
    /// open can succeed later.
    Unavailable,
    /// This principal may not open this item. Asking again answers the same.
    Denied,
    /// The acquisition is confirmed at the chain head but not yet at the
    /// finalized block, which is the only state custody releases a key on.
    /// Nobody has to act: the same open succeeds once finality passes it.
    Finalizing,
}

impl RuntimeCustodyOpenStage {
    const fn wire_value(self) -> &'static str {
        match self {
            Self::RightsApproval => "rights_approval",
            Self::Unavailable => "unavailable",
            Self::Denied => "denied",
            Self::Finalizing => "finalizing",
        }
    }

    /// Whether re-issuing the identical open can produce a different answer.
    ///
    /// This is the one fact a viewer needs to choose between waiting and
    /// offering the person a retry, and it is a property of the stage rather
    /// than of the words describing it.
    const fn resumable(self) -> bool {
        match self {
            Self::RightsApproval | Self::Unavailable | Self::Finalizing => true,
            Self::Denied => false,
        }
    }
}

/// Who is being waited on for a rights approval, and where they act.
#[derive(Debug, Clone)]
struct RuntimeCustodyOpenApproval {
    /// True when the account is an external wallet reached through a
    /// connector, so the outstanding approval needs the person to act there.
    external_signer: bool,
    /// Names the connector when there is one, so a viewer can say "MetaMask"
    /// rather than "your wallet". A connector id is a local wallet-surface
    /// identifier, not a secret and not an account.
    connector_id: Option<String>,
    /// The approval the person answers. It already reached callers inside the
    /// diagnostic cause chain; carrying it as data lets a viewer name the exact
    /// request instead of parsing it back out of a sentence.
    approval_request_id: String,
}

/// How far an open has got, carried as data beside the stable message.
///
/// A viewer reads `resumable` to decide whether to keep asking, and
/// `awaits_person` to decide whether to ask the person for anything at all.
/// Neither decision is taken by matching words in `message`.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyOpenProgress {
    stage: RuntimeCustodyOpenStage,
    /// Present only for a rights approval; the other stages wait on nobody.
    approval: Option<RuntimeCustodyOpenApproval>,
    /// When the resumable window closes, for the stages that have one.
    expires_at: Option<u64>,
    /// When a finalizing open is expected to succeed. An estimate for the
    /// viewer to show, never a bound on how long it may keep asking.
    ready_at: Option<u64>,
}

impl RuntimeCustodyOpenProgress {
    /// The Wallet holds this open's rights-signature request.
    pub(crate) fn awaiting_rights_approval(
        external_signer: bool,
        connector_id: Option<&str>,
        approval_request_id: &str,
        expires_at: u64,
    ) -> Self {
        Self {
            stage: RuntimeCustodyOpenStage::RightsApproval,
            approval: Some(RuntimeCustodyOpenApproval {
                external_signer,
                connector_id: connector_id.map(ToString::to_string),
                approval_request_id: approval_request_id.to_string(),
            }),
            expires_at: Some(expires_at),
            ready_at: None,
        }
    }

    /// Something the open depends on is absent for now.
    pub(crate) const fn unavailable() -> Self {
        Self {
            stage: RuntimeCustodyOpenStage::Unavailable,
            approval: None,
            expires_at: None,
            ready_at: None,
        }
    }

    /// This principal may not open this item.
    pub(crate) const fn denied() -> Self {
        Self {
            stage: RuntimeCustodyOpenStage::Denied,
            approval: None,
            expires_at: None,
            ready_at: None,
        }
    }

    /// The acquisition awaits finality; `ready_at` is the estimate to show.
    pub(crate) const fn finalizing(ready_at: u64) -> Self {
        Self {
            stage: RuntimeCustodyOpenStage::Finalizing,
            approval: None,
            expires_at: None,
            ready_at: Some(ready_at),
        }
    }

    /// Whether re-issuing the identical open can produce a different answer.
    pub(crate) const fn resumable(&self) -> bool {
        self.stage.resumable()
    }

    /// Stage code for the operator log. Carries no account and no address.
    pub(crate) const fn stage_label(&self) -> &'static str {
        self.stage.wire_value()
    }

    /// Whether the person has to do something, or the open is simply waiting.
    /// A managed approval is outstanding too, and nobody has to act on it.
    pub(crate) fn awaits_person(&self) -> bool {
        self.approval
            .as_ref()
            .is_some_and(|approval| approval.external_signer)
    }

    pub(crate) fn as_json(&self) -> Value {
        let mut answer = json!({
            "schema": RUNTIME_CUSTODY_OPEN_PROGRESS_SCHEMA_V1,
            "stage": self.stage.wire_value(),
            "resumable": self.stage.resumable(),
            "awaits_person": self.awaits_person(),
        });
        if let Some(approval) = self.approval.as_ref() {
            answer["external_signer"] = Value::Bool(approval.external_signer);
            answer["connector_id"] = approval
                .connector_id
                .as_ref()
                .map_or(Value::Null, |id| Value::String(id.clone()));
            answer["approval_request_id"] = Value::String(approval.approval_request_id.clone());
        }
        if let Some(expires_at) = self.expires_at {
            answer["expires_at"] = json!(expires_at);
        }
        if let Some(ready_at) = self.ready_at {
            answer["ready_at"] = json!(ready_at);
        }
        answer
    }
}

impl std::fmt::Display for RuntimeCustodyOpenProgress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.stage {
            RuntimeCustodyOpenStage::RightsApproval if self.awaits_person() => {
                match self
                    .approval
                    .as_ref()
                    .and_then(|approval| approval.connector_id.as_deref())
                {
                    Some(connector) => write!(
                        formatter,
                        "Approve opening this item in {connector}; it opens on its own once you do"
                    ),
                    None => write!(
                        formatter,
                        "Approve opening this item in your wallet; it opens on its own once you do"
                    ),
                }
            }
            RuntimeCustodyOpenStage::RightsApproval => write!(
                formatter,
                "Approve opening this item in your wallet; it opens on its own once you do"
            ),
            RuntimeCustodyOpenStage::Unavailable => write!(
                formatter,
                "This item is unavailable for now; opening it again later can succeed"
            ),
            RuntimeCustodyOpenStage::Denied => {
                write!(formatter, "This item belongs to a different account")
            }
            RuntimeCustodyOpenStage::Finalizing => write!(
                formatter,
                "This item's transaction is confirmed and awaits chain finality; it opens once finality passes"
            ),
        }
    }
}

impl std::error::Error for RuntimeCustodyOpenProgress {}

/// How far the publish of this object has actually got, read from the journal.
///
/// A creator watches one blocking request for the whole of a publish, so the
/// page can only guess which stage it is in, and it guesses the first one --
/// which is why a long content publish reads as a stalled "Encrypt & escrow"
/// when escrow finished in milliseconds. The journal has known better the
/// whole time: it records custody as provisioned before the publish begins,
/// and the same projection the creator tail returns can be read from it by
/// anyone, at any point, without touching the request that is in flight.
///
/// Answers `None` when this object has no mint intent, and in the brief window
/// where an intent exists but no record does -- there is genuinely nothing to
/// report yet, and inventing a stage would be the same guess in a new place.
///
/// The principal is the verified caller's, bound by the gateway before this is
/// reached, and the intent id derives from it -- so this cannot read another
/// principal's publish. Nothing here is an entitlement: it reports progress,
/// grants nothing, and takes no wallet authority.
pub(crate) fn runtime_custody_publish_progress(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
) -> anyhow::Result<Option<Value>> {
    Ok(
        runtime_custody_open_mint_for_source(data_dir, principal_id, object_uri, source_storage)?
            .as_ref()
            .map(runtime_custody_creator_progress),
    )
}

pub(crate) const RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE: &str =
    "Runtime custody mint requires cleanup reconciliation";

/// The protect request of the source's current attempt went out and its
/// outcome is unknown. Typed so Creator offers Start over on it.
fn runtime_custody_dispatch_uncertain() -> anyhow::Error {
    RuntimeCustodyAttemptConflict::error(RuntimeCustodyAttemptConflictReason::DispatchUncertain)
}
/// What the creator sees when the encoder wrote more slices per frame than the
/// protection can describe. It is the outermost error of the mint, so Creator
/// shows it as it is.
pub(crate) const RUNTIME_CUSTODY_MEDIA_TOO_MANY_SLICES_MESSAGE: &str =
    "This video has too many slices per frame; re-encode it with fewer slices.";
/// Said of a prepared or protected part over its limit (the provider's own
/// wording for a clear part).
const RUNTIME_CUSTODY_MEDIA_PART_TOO_LARGE_MESSAGE: &str =
    "a prepared media part exceeds the 2 MiB part limit";
pub(crate) const RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE: &str =
    "Runtime custody mint was settled before draft persistence";
const PROTECTED_CONTENT_ROOT: &str = "protected-content";
const CHAIN_PROVIDER_CONFIG_FILE: &str = "protected-content/chain-provider.json";
pub const PROTECTED_CONTENT_CHAIN_PROVIDER_CONFIG_SCHEMA_V1: &str =
    "elastos.protected-content.chain-provider-config/v1";
const MAX_CHAIN_PROVIDER_CONFIG_BYTES: usize = 64 * 1024;
const CUSTODY_COMPOSITION_CONFIG_FILE: &str = "protected-content/custody-composition.json";
const RUNTIME_MINT_JOURNAL_ROOT: &str = "protected-content/runtime-mint";
const RUNTIME_OPEN_MATERIAL_ROOT: &str = "protected-content/runtime-open";
const RUNTIME_LISTING_ROOT: &str = "protected-content/runtime-listings";
const RUNTIME_PURCHASE_ROOT: &str = "protected-content/runtime-purchases";
const RUNTIME_VIEWER_SCHEMA_V1: &str = "elastos.library.runtime-custody-viewer-state/v1";
const RUNTIME_LISTING_SCHEMA_V1: &str = "elastos.library.runtime-custody-listing/v1";
const RUNTIME_PORTABLE_LISTING_SCHEMA_V1: &str = "elastos.protected-content.portable-listing/v1";
const MAX_RUNTIME_PORTABLE_LISTING_BYTES: u64 = 128 * 1024;
pub(crate) const RUNTIME_PURCHASE_SCHEMA_V1: &str = "elastos.library.runtime-custody-purchase/v1";
/// Plan B T4.6: the availability a purchase records when the listing proved
/// it by a verified fetch, which makes no receipt.
pub(crate) const RUNTIME_PURCHASE_VERIFIED_FETCH_DIGEST: &str = "verified-fetch";
static RUNTIME_VIEWER_LIFECYCLE_GUARDS: OnceLock<
    StdMutex<HashMap<PathBuf, Weak<tokio::sync::Mutex<()>>>>,
> = OnceLock::new();
pub(crate) const CUSTODY_COMPOSITION_SCHEMA_V1: &str =
    "elastos.protected-content.custody-composition/v1";
const MAX_CUSTODY_COMPOSITION_BYTES: usize = 64 * 1024;
pub(crate) const MAX_CUSTODY_COMPOSITION_BLOB_BYTES: usize = 16 * 1024;
const MAX_CUSTODY_COMPOSITION_PEER_DID_BYTES: usize = 256;
const PROTECTED_CONTENT_OBJECT_KIND: &str = "protected-content";
pub(crate) const PROTECTED_CONTENT_IDENTITY_PATH: &str = "protected-content/v1/identity.bin";
pub(crate) const PROTECTED_CONTENT_INIT_PATH: &str = "protected-content/v1/init.mp4";
const PROTECTED_CONTENT_SEGMENTS_PREFIX: &str = "protected-content/v1/segments/";
const PROTECTED_CONTENT_SEGMENTS_SUFFIX: &str = ".m4s";
pub(crate) const PROTECTED_CONTENT_OBJECT_EPC1_PATH: &str = "protected-content/v1/object.epc1";
const PROTECTED_CONTENT_OBJECT_MANIFEST_PATH: &str = "protected-content/v1/manifest.json";
const PROTECTED_CONTENT_OBJECT_MANIFEST_SCHEMA_V1: &str =
    "elastos.protected-content.object-manifest/v1";
const PROTECTED_CONTENT_V2_IDENTITY_PATH: &str = "protected-content/v2/identity.bin";
const PROTECTED_CONTENT_V2_MPD_PATH: &str = "protected-content/v2/stream.mpd";
/// The viewer answer a DASH v2 session opens with. The player selects its
/// multi-rendition branch on this schema string.
const RUNTIME_CUSTODY_VIEWER_SCHEMA_V2: &str = "elastos.library.runtime-custody-viewer/v2";
/// The largest protected segment a v2 read fetches and a v2 mint accepts (the
/// manifest check enforces it on every listing): the
/// decrypt answer echoes the encrypted segment and the clear part as JSON
/// number arrays (4 characters per byte at worst), so `8 * cap` plus at most
/// 16 KiB of proof, keys and ids must stay under the 16 MiB provider frame.
/// `2 MiB - 32 KiB` leaves 256 KiB for that overhead.
pub(crate) const MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2: usize = 2 * 1024 * 1024 - 32 * 1024;
/// First bytes of the staged Merkle leaves of one v2 viewer session.
const RUNTIME_VIEWER_LEAVES_MAGIC: &[u8; 8] = b"epc-lv01";
const PROTECTED_CONTENT_AVAILABLE_STATUS: &str = "network_available";

/// Whether a receipt's status proves the copies `requirement` asks for. A
/// single required copy is proven by this Home's verified pin, announced over
/// Carrier or not.
fn protected_content_availability_status_accepted(
    status: &str,
    requirement: &RuntimeContentAvailabilityRequirement,
) -> bool {
    status == PROTECTED_CONTENT_AVAILABLE_STATUS
        || (!protected_content_live_proof_required(requirement.minimum_replicas())
            && matches!(status, "carrier_announced" | "local_pinned"))
}
const RUNTIME_CUSTODY_LISTINGS_RESPONSE_SCHEMA_V1: &str =
    "elastos.library.runtime-custody-listings/v1";
const RUNTIME_CUSTODY_LISTING_AVAILABILITY_SCHEMA_V1: &str =
    "elastos.library.runtime-custody-availability-summary/v1";
const RUNTIME_CUSTODY_LISTING_ACCESS_AVAILABLE: &str = "available";
const RUNTIME_CUSTODY_LISTING_ACCESS_CREATOR: &str = "creator";
const RUNTIME_CUSTODY_LISTING_ACCESS_PURCHASED: &str = "purchased";
const MAX_RUNTIME_CUSTODY_LISTINGS: usize = 128;
const MAX_RUNTIME_CUSTODY_PUBLIC_TEXT_BYTES: usize = 256;
const CONTENT_AVAILABILITY_RECEIPT_SCHEMA: &str = "elastos.content.availability.receipt/v1";
const CONTENT_AVAILABILITY_RECEIPT_DOMAIN: &str = "elastos.content.availability.receipt.v1";
const MAX_RUNTIME_VIEWER_RECONCILE_MINT_DIRS: usize = 256;
const MAX_RUNTIME_VIEWER_RECONCILE_RECORDS: usize = 1024;
const MAX_RUNTIME_VIEWER_RECORD_BYTES: u64 = 64 * 1024;
const PROTECT_PROVIDER_PROCESS_ID: &str = "protected-content-protect";
const MEDIA_PROVIDER_PROCESS_ID: &str = "media-provider";
const MEDIA_PROVIDER_PROTOCOL_VERSION: &str = "elastos.media-provider/v1";
const PROTECTED_CONTENT_PROVIDER_STATUS_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5);
const PROTECT_PROVIDER_OPERATIONS: &[&str] = &[
    "status",
    "open_protection_session",
    "protect_media_segment",
    "finalize_protection_session",
    "cancel_protection_session",
    "close_protection_session",
    "open_object_protection_session",
    "protect_object_chunk",
    "finalize_object_protection_session",
    "shutdown",
];
const MEDIA_PROVIDER_OPERATIONS: &[&str] = &["status", "prepare"];
const CUSTODY_PROVIDER_OPERATIONS: &[&str] = &[
    OP_CUSTODY_STATUS,
    OP_CUSTODY_PROVISION_NODE_SHARE,
    OP_CUSTODY_RELEASE_CONTRIBUTION,
    OP_CUSTODY_RELEASE_POOL_CONTRIBUTION,
    OP_CUSTODY_SIGN_POOL_STATEMENT,
    OP_CUSTODY_PROVISION_POOL_NODE_SHARE,
    "shutdown",
];
const PROTECTED_CONTENT_DECRYPT_PROVIDER_OPERATIONS: &[&str] = &[
    "status",
    "prepare_recipient",
    "open_viewer_session",
    "read_viewer_media_part",
    "cancel_prepared_recipient",
    "close_viewer_session",
    "read_viewer_object_chunk",
    "prepare_recipient_v2",
    "open_viewer_session_v2",
    "read_viewer_media_part_sealed",
    "read_viewer_object_chunk_sealed",
    "shutdown",
];
const WALLET_PROVIDER_ID: &str = "wallet";
/// Historical directory name. The path is frozen because provisioned custody
/// hosts already hold state there; `inactive` says nothing about whether the
/// custody plane is active.
const INACTIVE_CUSTODY_ROOT: &str = "protected-content/custody-provider/inactive";
/// The folder that holds every custody root (Plan B T2.1).
const CUSTODY_PROVIDER_STATE_DIR: &str = "protected-content/custody-provider";
const PROVIDER_INVOCATION_SCHEMA_V1: &str = "elastos.provider.invocation/v1";
const CHAIN_PROTECTED_CONTENT_POLICY_OP: &str = "resolve_protected_content_policy";
const CHAIN_PROTECTED_CONTENT_POLICY_SCHEMA_V1: &str = "elastos.chain.protected-content-policy/v1";
const MEDIA_PROVIDER_PREPARED_MEDIA_SCHEMA_V2: &str = "elastos.media-provider.prepared-media/v2";
const MEDIA_PROVIDER_INPUT_FILE_NAME: &str = "input.bin";
const MEDIA_PROVIDER_PREPARED_DIR_NAME: &str = "prepared";
const MEDIA_PROVIDER_SEGMENTS_DIR_NAME: &str = "segments";
/// The protocol's part rule for a prepared (clear) part: 2 MiB less 64 KiB, so
/// that protecting it, which adds at most a few KiB, stays under the 2 MiB
/// protected part and the decrypt answer stays under the provider frame. It
/// bounds one part, never a whole media: there is no cap on duration, size or
/// segment count.
const MEDIA_PROVIDER_MAX_PREPARED_PART_BYTES_V2: u64 = 2 * 1024 * 1024 - 64 * 1024;
const RUNTIME_MEDIA_PREPARATION_RECEIPT_DOMAIN: &[u8] =
    b"elastos.protected-content.runtime-media-preparation-receipt/v1";
const RUNTIME_MEDIA_PREPARATION_RECONCILIATION_MESSAGE: &str =
    "Runtime custody media preparation requires settlement reconciliation";

pub(crate) struct ResolvedRuntimeRightsPolicy {
    body: RightsPolicyBodyV1,
    identity: RightsPolicyIdentityV1,
}

impl ResolvedRuntimeRightsPolicy {
    pub(crate) fn body(&self) -> &RightsPolicyBodyV1 {
        &self.body
    }

    pub(crate) fn identity(&self) -> &RightsPolicyIdentityV1 {
        &self.identity
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainProtectedContentPolicyResponse {
    schema: String,
    policy_body: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeProtectedContentChainProviderConfigFile {
    schema: String,
    protected_content_network: Value,
}

#[derive(Clone)]
pub struct RuntimeProtectedContentChainProviderConfig {
    protected_content_network: Value,
}

impl RuntimeProtectedContentChainProviderConfig {
    pub fn protected_content_network(&self) -> &Value {
        &self.protected_content_network
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RuntimeCustodyRouteTransportConfig {
    Local,
    CarrierPeerDid { peer_did: String },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyRouteBindingConfig {
    pub(crate) node_public_key_base64: String,
    pub(crate) owner_state_root_base64: String,
    pub(crate) transport: RuntimeCustodyRouteTransportConfig,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyCompositionConfigFile {
    pub(crate) schema: String,
    pub(crate) expected_policy_authority_base64: String,
    pub(crate) expected_committee_authorization_identity_base64: String,
    pub(crate) signed_pool_base64: String,
    pub(crate) signed_epoch_base64: String,
    pub(crate) signed_committee_authorization_base64: String,
    pub(crate) routes: Vec<RuntimeCustodyRouteBindingConfig>,
}

struct RuntimeValidatedCustodyRouteBinding {
    owner_state_root: Digest32,
    transport: ProviderInvocationTransport,
}

struct RuntimeValidatedCustodyCompositionConfig {
    expected_policy_authority: CustodyEpochIssuerKeyV1,
    expected_authorization_identity: CustodyCommitteeAuthorizationIdentityV1,
    signed_pool: SignedCustodyPoolV1,
    signed_epoch: SignedCustodyEpochV1,
    signed_committee_authorization: SignedCustodyCommitteeAuthorizationV1,
    routes: [RuntimeValidatedCustodyRouteBinding; 3],
}

/// Where a custody node's own words go when a call to it fails.
///
/// The coordinator classifies a failure only by whether the node can have
/// acted -- a safety decision that deliberately carries no text, since a
/// reason must never widen what the Runtime is willing to assume. But a person
/// whose read just failed still needs to know why, and the node did say why.
/// That sentence is collected here so it can be reported with the refusal
/// instead of reaching the log alone.
///
/// Diagnostic only. Nothing reads this to decide anything; it is the shared
/// buffer for one composition's calls, and the text in it comes from a remote
/// peer, so it is bounded in both count and length and is never parsed.
#[derive(Clone, Default)]
pub(crate) struct RuntimeCustodyCallDiagnostics(Arc<std::sync::Mutex<Vec<String>>>);

/// Enough to hear from all three nodes on both the rights and the contribution
/// call, and no more: this is a hint, not a transcript.
const RUNTIME_CUSTODY_CALL_DIAGNOSTICS_MAX: usize = 6;
/// One line's worth of a peer's explanation.
const RUNTIME_CUSTODY_CALL_DETAIL_MAX_CHARS: usize = 300;

impl RuntimeCustodyCallDiagnostics {
    fn record(&self, op: &str, detail: &str) {
        let Ok(mut recorded) = self.0.lock() else {
            return;
        };
        if recorded.len() >= RUNTIME_CUSTODY_CALL_DIAGNOSTICS_MAX {
            return;
        }
        let detail = detail.trim();
        let detail: String = detail
            .chars()
            .take(RUNTIME_CUSTODY_CALL_DETAIL_MAX_CHARS)
            .collect();
        let line = format!("{op}: {detail}");
        // Three nodes refusing for one reason is one fact, not three.
        if recorded.iter().any(|existing| existing == &line) {
            return;
        }
        recorded.push(line);
    }

    /// What the nodes said, for reporting alongside a refusal.
    pub(crate) fn recorded(&self) -> Vec<String> {
        self.0
            .lock()
            .map(|recorded| recorded.clone())
            .unwrap_or_default()
    }
}

struct RuntimeCustodyCompositionNode {
    node_public_key: NodePublicKey,
    custody_public_key: NodeCustodyPublicKeyV1,
    owner_state_root: Digest32,
    adapter: RuntimeCustodyRegistryAdapter,
}

pub(crate) struct RuntimeCustodyComposition {
    expected_policy_authority: CustodyEpochIssuerKeyV1,
    expected_authorization_identity: CustodyCommitteeAuthorizationIdentityV1,
    signed_pool: SignedCustodyPoolV1,
    signed_epoch: SignedCustodyEpochV1,
    signed_committee_authorization: SignedCustodyCommitteeAuthorizationV1,
    nodes: [RuntimeCustodyCompositionNode; 3],
    /// Shared by all three node adapters, so one refusal is reportable no
    /// matter which node gave it.
    diagnostics: RuntimeCustodyCallDiagnostics,
}

impl std::fmt::Debug for RuntimeCustodyComposition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeCustodyComposition")
            .field("expected_policy_authority", &"[redacted]")
            .field("expected_authorization_identity", &"[redacted]")
            .field("signed_pool", &"[redacted]")
            .field("signed_epoch", &"[redacted]")
            .field("signed_committee_authorization", &"[redacted]")
            .field("node_count", &self.nodes.len())
            .finish()
    }
}

impl RuntimeCustodyComposition {
    /// The signed pool this loader validated: member terms for reading the
    /// installed pool.
    pub(crate) fn signed_pool(&self) -> &SignedCustodyPoolV1 {
        &self.signed_pool
    }

    /// The signed epoch this loader validated: threshold and share numbers.
    pub(crate) fn signed_epoch(&self) -> &SignedCustodyEpochV1 {
        &self.signed_epoch
    }

    pub(crate) fn configured_nodes(
        &self,
    ) -> Result<[RuntimeMintConfiguredCustodyProvider<'_>; 3], RuntimeMintCoordinatorError> {
        Ok([
            RuntimeMintConfiguredCustodyProvider::new(
                self.nodes[0].node_public_key,
                self.nodes[0].custody_public_key,
                self.nodes[0].owner_state_root,
                &self.nodes[0].adapter,
            )?,
            RuntimeMintConfiguredCustodyProvider::new(
                self.nodes[1].node_public_key,
                self.nodes[1].custody_public_key,
                self.nodes[1].owner_state_root,
                &self.nodes[1].adapter,
            )?,
            RuntimeMintConfiguredCustodyProvider::new(
                self.nodes[2].node_public_key,
                self.nodes[2].custody_public_key,
                self.nodes[2].owner_state_root,
                &self.nodes[2].adapter,
            )?,
        ])
    }
}

struct InactiveCustodyProvider {
    bridge: Arc<ProviderBridge>,
    registry: Weak<ProviderRegistry>,
    limiter: CustodyReleaseLimiter,
    /// #388 A1: the host trust setting captured at this process's start.
    host_trusted: bool,
    /// Plan B S7-lite (S7L-F2): this Home's records of which pool each root
    /// holds.
    data_dir: PathBuf,
}

impl InactiveCustodyProvider {
    fn new(
        bridge: Arc<ProviderBridge>,
        registry: Weak<ProviderRegistry>,
        host_trusted: bool,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            bridge,
            registry,
            limiter: CustodyReleaseLimiter::new(CUSTODY_NODE_SETTINGS),
            host_trusted,
            data_dir,
        }
    }

    /// Plan B POOL-MINT: a pool provisioning request reaches the node only
    /// when its pool is one this Home's records bind to the root holding the
    /// request's node, by a descriptor not older than the one kept
    /// (otherwise `provisioning_refused`). Admitted, it returns whether that
    /// root already holds the request's (minting Home, KID) slot (PM-F4),
    /// read when the host-wide share lock is held.
    fn admit_pool_share(
        &self,
        request: &Value,
    ) -> Result<impl FnOnce() -> bool + Send + 'static, Value> {
        let refused = |code: &str| {
            json!({
                "status": "error",
                "code": code,
                "message": "this node does not hold that pool",
            })
        };
        let parsed = serde_json::to_vec(request)
            .ok()
            .and_then(|bytes| {
                elastos_protected_content_provider_contracts::PoolCustodyRequestV1::from_json_slice(
                    &bytes,
                )
                .ok()
            })
            .and_then(|request| {
                let (descriptor, node) = request.provision_pool().ok()?;
                let (_, _, mint_share) = request.provision_contents().ok()?;
                Some((descriptor, node, mint_share))
            });
        let Some((descriptor, node, mint_share)) = parsed else {
            return Err(refused("invalid_request"));
        };
        let root_dir =
            crate::custody_pool_descriptor::admit_pool_provision(&self.data_dir, &descriptor, node)
                .map_err(|reason| {
                    tracing::debug!(
                        reason,
                        "pool provisioning refused: not this Home's pool root"
                    );
                    refused("provisioning_refused")
                })?;
        let statement = mint_share.statement().clone();
        Ok(move || {
            elastos_protected_content_custody::NodeLocalShareStoreV1::new(
                node,
                custody_provider::node_share_store_dir(&root_dir),
            )
            .pool_slot_held(
                statement.minter_runtime_issuer(),
                statement.content_access_id(),
            )
            // An unreadable slot is charged as a new one.
            .unwrap_or(false)
        })
    }

    /// Plan B POOL-MINT (PM-F2): whether the root holding a V1 share
    /// request's node already holds its key envelope's V1 slot, read when the
    /// host-wide share lock is held. A record that cannot be read, a node no
    /// root holds and an unreadable slot are charged as a new slot; the
    /// provider validates the request.
    fn v1_share_slot_held(&self, request: &Value) -> impl FnOnce() -> bool + Send + 'static {
        let record = serde_json::to_vec(request).ok().and_then(|bytes| {
            elastos_protected_content_provider_contracts::CustodyProviderRequestV1::peek_custody_node_provisioning_record(&bytes)
                .ok()
        });
        let data_dir = self.data_dir.clone();
        move || {
            let Some(record) = record else {
                return false;
            };
            let node = record.selected_node_public_key();
            custody_provider_root_paths(&data_dir)
                .unwrap_or_default()
                .iter()
                .map(|root| custody_root_dir(&data_dir, root))
                .find(|root| {
                    custody_provider::load_node_public_key(root).is_ok_and(|key| key == node)
                })
                .is_some_and(|root| {
                    elastos_protected_content_custody::NodeLocalShareStoreV1::new(
                        node,
                        custody_provider::node_share_store_dir(&root),
                    )
                    .v1_slot_held(record.key_envelope_identity())
                    .unwrap_or(false)
                })
        }
    }

    /// Plan B POOL-MINT (PM-F2): a share write, V1 or pool, through the one
    /// owned guarded write. The host's storage maximum decides, whichever
    /// Home mints; the request frame bounds what is stored.
    async fn write_host_share(
        &self,
        request: Value,
        slot_held: impl FnOnce() -> bool + Send + 'static,
    ) -> Result<Value, ProviderError> {
        let incoming = serde_json::to_vec(&request).map_or(u64::MAX, |bytes| {
            u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        });
        let bridge = Arc::clone(&self.bridge);
        guarded_host_share_write(
            self.data_dir.clone(),
            incoming,
            slot_held,
            move || async move {
                bridge
                    .send_raw(&request)
                    .await
                    .map_err(|error| ProviderError::Provider(error.to_string()))
            },
        )
        .await
    }

    /// Validates the Runtime envelope and admits the op from the custody
    /// surface: the Carrier plane admits the target's Carrier ops, and the
    /// local plane also admits its Runtime-local ops (L15). Returns the
    /// request without its envelope and the endpoint that sent it.
    fn strip_runtime_invocation(
        &self,
        request: &Value,
    ) -> Result<(Value, RuntimeInvocationSource), ProviderError> {
        let mut value = request.clone();
        let object = value
            .as_object_mut()
            .ok_or_else(|| ProviderError::Provider("custody request must be an object".into()))?;
        if object.contains_key("_runtime_transfer") {
            return Err(ProviderError::Provider(
                "custody request contains an unsupported transfer envelope".into(),
            ));
        }
        if object.contains_key("chain_data") || object.contains_key("evidence") {
            return Err(ProviderError::Provider(
                "custody request contains unsupported injected evidence".into(),
            ));
        }
        if object.contains_key("carrier") {
            return Err(ProviderError::Provider(
                "custody request contains unsupported injected carrier data".into(),
            ));
        }
        let op = object
            .get("op")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Provider("custody request is missing op".into()))?
            .to_owned();
        if matches!(
            op.as_str(),
            "evaluate_rights" | "prepare_evidence" | "settle_evidence"
        ) {
            return Err(ProviderError::Provider(
                "custody request op is private to the node-hosted wrapper".into(),
            ));
        }
        if !declared_ops(TARGET_CUSTODY).any(|declared| declared == op) {
            return Err(ProviderError::Provider(
                "custody request op is unsupported".into(),
            ));
        }
        let source = custody_runtime_invocation_source(object, TARGET_CUSTODY, &op)?;
        Ok((value, source))
    }

    async fn send_private_child_request(
        &self,
        request: &PrivateCustodyRightsRequestV1,
    ) -> Result<Value, ProviderError> {
        let request = serde_json::to_value(request)
            .map_err(|_| ProviderError::Provider("custody private request is invalid".into()))?;
        self.bridge
            .send_raw(&request)
            .await
            .map_err(|error| ProviderError::Provider(error.to_string()))
    }

    fn private_ok_data(&self, response: Value) -> Result<Value, ProviderError> {
        match response.get("status").and_then(Value::as_str) {
            Some("ok") => response.get("data").cloned().ok_or_else(|| {
                ProviderError::Provider("custody private response is missing data".into())
            }),
            Some("error") => Err(ProviderError::Provider(custody_private_rejection_message(
                response.get("code").and_then(Value::as_str),
            ))),
            _ => Err(ProviderError::Provider(
                "custody private response has unsupported status".into(),
            )),
        }
    }

    fn normalize_public_status(
        &self,
        response: Value,
        source: &RuntimeInvocationSource,
    ) -> Result<Value, ProviderError> {
        let data = self.private_ok_data(response)?;
        let object = data
            .as_object()
            .ok_or_else(|| ProviderError::Provider("custody status response is invalid".into()))?;
        let provider = object
            .get("provider")
            .cloned()
            .ok_or_else(|| ProviderError::Provider("custody status response is invalid".into()))?;
        let version = object
            .get("version")
            .cloned()
            .ok_or_else(|| ProviderError::Provider("custody status response is invalid".into()))?;
        let configured = object
            .get("configured")
            .cloned()
            .ok_or_else(|| ProviderError::Provider("custody status response is invalid".into()))?;
        let request_schema = object
            .get("request_schema")
            .cloned()
            .ok_or_else(|| ProviderError::Provider("custody status response is invalid".into()))?;
        let response_schema = object
            .get("response_schema")
            .cloned()
            .ok_or_else(|| ProviderError::Provider("custody status response is invalid".into()))?;
        // The public status lists what the wrapper's dispatch admits for this
        // caller, from the custody surface: a Carrier peer sees the Carrier
        // ops only, and a local caller also sees the Runtime-local ops.
        let supported_operations: Vec<&str> = declared_ops(TARGET_CUSTODY)
            .filter(|op| {
                *source == RuntimeInvocationSource::Local || carrier_op_allowed(TARGET_CUSTODY, op)
            })
            .collect();
        Ok(json!({
            "status": "ok",
            "data": {
                "provider": provider,
                "version": version,
                "configured": configured,
                "supported_operations": supported_operations,
                "request_schema": request_schema,
                "response_schema": response_schema,
            }
        }))
    }
}

/// Plan B T3.4 (E12): the Runtime envelope check shared by the custody
/// targets. It removes and validates `_runtime_invocation` for `target` and
/// `op`, and admits `op` from the custody surface: the Carrier plane admits the
/// target's Carrier ops, and the local plane also its Runtime-local ops (L15).
/// Returns the endpoint that sent the request.
pub(crate) fn custody_runtime_invocation_source(
    object: &mut serde_json::Map<String, Value>,
    target: &str,
    op: &str,
) -> Result<RuntimeInvocationSource, ProviderError> {
    let envelope = object.remove("_runtime_invocation").ok_or_else(|| {
        ProviderError::Provider("custody request is missing runtime envelope".into())
    })?;
    let envelope = envelope.as_object().ok_or_else(|| {
        ProviderError::Provider("custody request runtime envelope is invalid".into())
    })?;
    let transport = envelope
        .get("transport")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::Provider("custody request runtime envelope is invalid".into())
        })?;
    if !matches!(
        transport,
        "runtime-local-provider-plane" | "carrier-provider-plane"
    ) {
        return Err(ProviderError::Provider(
            "custody request runtime envelope is invalid".into(),
        ));
    }
    let carrier_is_valid = match transport {
        "runtime-local-provider-plane" => envelope.get("carrier") == Some(&Value::Null),
        "carrier-provider-plane" => envelope
            .get("carrier")
            .and_then(Value::as_object)
            .filter(|carrier| carrier.len() == 1)
            .and_then(|carrier| carrier.get("source_endpoint_did"))
            .and_then(Value::as_str)
            .and_then(|did| {
                crate::carrier::did_to_public_key(did).and_then(|public_key| {
                    crate::carrier::public_key_to_did(&public_key)
                        .ok()
                        .filter(|canonical| canonical == did)
                })
            })
            .is_some(),
        _ => false,
    };
    if envelope.len() != 11
        || envelope.get("schema").and_then(Value::as_str) != Some(PROVIDER_INVOCATION_SCHEMA_V1)
        || envelope.get("source").and_then(Value::as_str) != Some(RUNTIME_PROVIDER_ID)
        || envelope.get("target").and_then(Value::as_str) != Some(target)
        || envelope.get("op").and_then(Value::as_str) != Some(op)
        || envelope.get("capability").and_then(Value::as_str)
            != Some(&format!("provider:{RUNTIME_PROVIDER_ID}->{target}:{op}"))
        || !carrier_is_valid
        || envelope.get("transfer").and_then(Value::as_str) != Some("json")
        || envelope.get("range") != Some(&Value::Null)
        || envelope.get("progress") != Some(&Value::Null)
        || envelope.get("abi")
            != Some(&json!({
                "schema": "elastos.provider.transfer-abi/v1",
                "transfer": "json",
                "transport": transport,
                "range_supported": false,
                "progress_supported": false,
                "progress_mode": "none",
                "transport_native_stream": false,
                "backpressure": "not_applicable",
                "cancel_supported": false,
            }))
    {
        return Err(ProviderError::Provider(
            "custody request runtime envelope is invalid".into(),
        ));
    }
    let source = match envelope
        .get("carrier")
        .and_then(|carrier| carrier.get("source_endpoint_did"))
        .and_then(Value::as_str)
    {
        Some(did) if transport == "carrier-provider-plane" => RuntimeInvocationSource::Carrier {
            source_endpoint_did: did.to_owned(),
        },
        None if transport == "runtime-local-provider-plane" => RuntimeInvocationSource::Local,
        _ => {
            return Err(ProviderError::Provider(
                "custody request runtime envelope is invalid".into(),
            ))
        }
    };
    let admitted = carrier_op_allowed(target, op)
        || (source == RuntimeInvocationSource::Local && runtime_local_op_allowed(target, op));
    if !admitted {
        return Err(ProviderError::Provider(
            "custody request op is local to the Runtime".into(),
        ));
    }
    Ok(source)
}

impl std::fmt::Debug for InactiveCustodyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InactiveCustodyProvider")
            .field("bridge", &"<redacted>")
            .finish()
    }
}

struct RuntimeCustodyRegistryAdapter {
    registry: Arc<ProviderRegistry>,
    transport: ProviderInvocationTransport,
    diagnostics: RuntimeCustodyCallDiagnostics,
}

impl RuntimeCustodyRegistryAdapter {
    fn new(
        registry: Arc<ProviderRegistry>,
        transport: ProviderInvocationTransport,
        diagnostics: RuntimeCustodyCallDiagnostics,
    ) -> Self {
        Self {
            registry,
            transport,
            diagnostics,
        }
    }

    async fn invoke_rights(
        &self,
        request: &RightsProviderRequestV1,
    ) -> Result<RightsProviderResponseV1, RuntimeProviderCallError> {
        let request_value = serde_json::from_slice(
            &request
                .to_json_vec()
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?,
        )
        .map_err(|_| RuntimeProviderCallError::NoExactResult)?;
        let response_value = invoke_json_provider_with_transport(
            self.registry.as_ref(),
            CUSTODY_PROVIDER_ID,
            OP_CUSTODY_EVALUATE,
            request_value,
            self.transport.clone(),
        )
        .await
        .map_err(|error| {
            self.diagnostics
                .record("rights evaluate", &error.to_string());
            RuntimeProviderCallError::NoExactResult
        })?;
        RightsProviderResponseV1::from_json_slice(
            &serde_json::to_vec(&response_value)
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?,
        )
        .map_err(|_| RuntimeProviderCallError::NoExactResult)
    }

    async fn invoke_custody(
        &self,
        op: &'static str,
        request: &elastos_protected_content_provider_contracts::CustodyProviderRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::CustodyProviderResponseV1,
        RuntimeProviderCallError,
    > {
        // Encoding happens entirely here; a failure means nothing was sent.
        let request_value = serde_json::from_slice(
            &request
                .to_json_vec()
                .map_err(|_| RuntimeProviderCallError::NotDispatched)?,
        )
        .map_err(|_| RuntimeProviderCallError::NotDispatched)?;
        let response_value = invoke_json_provider_classified(
            self.registry.as_ref(),
            CUSTODY_PROVIDER_ID,
            op,
            request_value,
            self.transport.clone(),
        )
        .await
        .map_err(|failure| {
            self.diagnostics
                .record(op, &failure.clone().into_message(CUSTODY_PROVIDER_ID, op));
            classify_custody_failure(op, &failure)
        })?;
        // The node answered `ok`; only this Runtime can still fail to read it,
        // and by then the node has already acted.
        elastos_protected_content_provider_contracts::CustodyProviderResponseV1::from_json_slice(
            &serde_json::to_vec(&response_value)
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?,
        )
        .map_err(|_| RuntimeProviderCallError::NoExactResult)
    }

    /// Plan B T4.1: the pool custody op, with the same encoding and failure
    /// classification as [`Self::invoke_custody`].
    async fn invoke_pool_custody(
        &self,
        op: &'static str,
        request: &elastos_protected_content_provider_contracts::PoolCustodyRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::PoolCustodyResponseV1,
        RuntimeProviderCallError,
    > {
        // Encoding happens entirely here; a failure means nothing was sent.
        let request_value = serde_json::from_slice(
            &request
                .to_json_vec()
                .map_err(|_| RuntimeProviderCallError::NotDispatched)?,
        )
        .map_err(|_| RuntimeProviderCallError::NotDispatched)?;
        let response_value = invoke_json_provider_classified(
            self.registry.as_ref(),
            CUSTODY_PROVIDER_ID,
            op,
            request_value,
            self.transport.clone(),
        )
        .await
        .map_err(|failure| {
            self.diagnostics
                .record(op, &failure.clone().into_message(CUSTODY_PROVIDER_ID, op));
            classify_custody_failure(op, &failure)
        })?;
        // As for V1: an `ok` this Runtime cannot read came after the node acted.
        elastos_protected_content_provider_contracts::PoolCustodyResponseV1::from_json_slice(
            &serde_json::to_vec(&response_value)
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?,
        )
        .map_err(|_| RuntimeProviderCallError::NoExactResult)
    }
}

/// Codes the custody capsule emits only from paths that precede its durable
/// write, so a refusal carrying one proves the share was not stored.
///
/// `invalid_request` covers frame and request-validation refusals,
/// `rights_denied` the rights decision, and `provisioning_refused` everything
/// the share store rejects before it is touched — expiry above all. All three
/// are structurally before `NodeLocalShareStoreV1` writes. `backend_unavailable`
/// is deliberately absent: the capsule returns it from refusals before the
/// write, from failures after it, and from the `hard_link` that is the write,
/// so it proves nothing about the share.
///
/// A closed list, and the compatibility story runs the safe way in both
/// directions: an older capsule still answers `backend_unavailable` and this
/// Runtime keeps treating it as uncertain, and a code this Runtime does not
/// recognise is uncertain rather than effect-free.
///
/// `operation_expired` and `evidence_expired` are request-validation refusals
/// too: the operation or its chain evidence ended before the node acted, and
/// the capsule names them so the Runtime can start a fresh operation instead
/// of reporting a malformed request.
const CUSTODY_EFFECT_FREE_REFUSAL_CODES: [&str; 9] = [
    "invalid_request",
    "provisioning_refused",
    // Plan B POOL-MINT: refused by the Runtime wrapper before the provider.
    crate::host_trust::HOST_STORAGE_FULL,
    crate::host_trust::HOST_STORAGE_MAX_UNSET,
    "rights_denied",
    "operation_expired",
    "evidence_expired",
    "unknown_envelope",
    RATE_LIMITED_CODE,
];

/// Codes a custody capsule refusal may carry into a Runtime diagnostic. The
/// capsule answers with a fixed code and message; only a code from this
/// closed list is repeated, so a refusal can never carry free text, an
/// address or a path into the Runtime's report.
const CUSTODY_REPORTABLE_REFUSAL_CODES: [&str; 9] = [
    "invalid_request",
    "invalid_config",
    "backend_unavailable",
    "provisioning_refused",
    "rights_denied",
    "operation_expired",
    "evidence_expired",
    "unknown_envelope",
    RATE_LIMITED_CODE,
];

/// The capsule-style refusal of a custody call above one of its budgets.
/// #388 A1 (#388-1): on a host that is not WCI-operated, every custody op
/// that touches another party's content key is refused before the provider,
/// V1 and V2 alike and every statement kind, with that op's existing
/// effect-free code, so a remote coordinator fails over. The roots, shares,
/// replay state and journals stay as they are. `None` lets the op through.
pub(crate) fn custody_host_trust_refusal(op: &str, host_trusted: bool) -> Option<Value> {
    if host_trusted {
        return None;
    }
    let code = match op {
        OP_CUSTODY_RELEASE_CONTRIBUTION | OP_CUSTODY_SIGN_POOL_STATEMENT => "invalid_request",
        OP_CUSTODY_RELEASE_POOL_CONTRIBUTION => "unknown_envelope",
        OP_CUSTODY_PROVISION_NODE_SHARE | OP_CUSTODY_PROVISION_POOL_NODE_SHARE => {
            "provisioning_refused"
        }
        _ => return None,
    };
    Some(json!({
        "status": "error",
        "code": code,
        "message": "this host is not set up as a WCI-operated host",
    }))
}

fn custody_rate_limited_response() -> Value {
    json!({
        "status": "error",
        "code": RATE_LIMITED_CODE,
        "message": "custody release rate limit reached",
    })
}

/// The wallet and item of an evaluate request whose prepare the capsule
/// accepted. The wrapper decodes the operation only then: the capsule has
/// verified these exact bytes, so a decode is enough here.
fn custody_rights_budget_keys(
    request: &Value,
) -> Result<(WalletAddress, ContentAccessIdV1), ProviderError> {
    let invalid = || ProviderError::Provider("custody evaluate request is invalid".into());
    let bytes = request
        .get("signed_runtime_release_operation")
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<u8>>(value).ok())
        .ok_or_else(invalid)?;
    Ok(
        match RuntimeReleaseOperationAnyV1::from_canonical_bytes(&bytes).map_err(|_| invalid())? {
            RuntimeReleaseOperationAnyV1::V1(operation) => {
                let statement = operation.statement();
                (
                    statement.rights_request().request().binding().wallet(),
                    statement.policy_body().content_access_id(),
                )
            }
            RuntimeReleaseOperationAnyV1::V2(operation) => {
                let statement = operation.statement();
                (
                    statement.rights_request().request().binding().wallet(),
                    statement.policy_body().content_access_id(),
                )
            }
        },
    )
}

fn custody_private_rejection_message(code: Option<&str>) -> String {
    match code.filter(|code| CUSTODY_REPORTABLE_REFUSAL_CODES.contains(code)) {
        Some(code) => format!("custody private request was rejected: {code}"),
        None => "custody private request was rejected".into(),
    }
}

fn classify_custody_failure(
    op: &str,
    failure: &ProviderInvocationFailure,
) -> RuntimeProviderCallError {
    match failure {
        ProviderInvocationFailure::Refused { code, .. }
            if CUSTODY_EFFECT_FREE_REFUSAL_CODES.contains(&code.as_str()) =>
        {
            tracing::warn!(
                %op,
                %code,
                "custody provider refused before acting"
            );
            RuntimeProviderCallError::RefusedWithoutEffect
        }
        ProviderInvocationFailure::Refused { code, .. } => {
            tracing::warn!(
                %op,
                %code,
                "custody provider refused with an effect-uncertain code"
            );
            RuntimeProviderCallError::NoExactResult
        }
        // A lost reply is indistinguishable from a node that never heard us,
        // and the capsule can complete its write and then fail to answer.
        ProviderInvocationFailure::NotCompleted { .. }
        | ProviderInvocationFailure::MalformedResponse { .. } => {
            tracing::warn!(%op, "custody provider effect is uncertain");
            RuntimeProviderCallError::NoExactResult
        }
    }
}

impl std::fmt::Debug for RuntimeCustodyRegistryAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeCustodyRegistryAdapter")
            .field("registry", &"<redacted>")
            .field("transport", &"<redacted>")
            .finish()
    }
}

#[async_trait::async_trait]
impl elastos_protected_content_runtime::RuntimeRightsProvider for RuntimeCustodyRegistryAdapter {
    async fn evaluate_rights(
        &self,
        request: &RightsProviderRequestV1,
    ) -> Result<RightsProviderResponseV1, RuntimeProviderCallError> {
        self.invoke_rights(request).await
    }
}

#[async_trait::async_trait]
impl elastos_protected_content_runtime::RuntimeCustodyProvider for RuntimeCustodyRegistryAdapter {
    async fn release_contribution(
        &self,
        request: &elastos_protected_content_provider_contracts::CustodyProviderRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::CustodyProviderResponseV1,
        RuntimeProviderCallError,
    > {
        self.invoke_custody(OP_CUSTODY_RELEASE_CONTRIBUTION, request)
            .await
    }

    async fn provision_node_share(
        &self,
        request: &elastos_protected_content_provider_contracts::CustodyProviderRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::CustodyProviderResponseV1,
        RuntimeProviderCallError,
    > {
        self.invoke_custody(OP_CUSTODY_PROVISION_NODE_SHARE, request)
            .await
    }

    async fn release_pool_contribution(
        &self,
        request: &elastos_protected_content_provider_contracts::PoolCustodyRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::PoolCustodyResponseV1,
        RuntimeProviderCallError,
    > {
        self.invoke_pool_custody(OP_CUSTODY_RELEASE_POOL_CONTRIBUTION, request)
            .await
    }

    async fn provision_pool_node_share(
        &self,
        request: &elastos_protected_content_provider_contracts::PoolCustodyRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::PoolCustodyResponseV1,
        RuntimeProviderCallError,
    > {
        self.invoke_pool_custody(OP_CUSTODY_PROVISION_POOL_NODE_SHARE, request)
            .await
    }
}

#[async_trait::async_trait]
impl Provider for InactiveCustodyProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "inactive custody provider does not expose resources".into(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![CUSTODY_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        "inactive-custody-provider"
    }

    async fn send_raw(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, ProviderError> {
        let (request, source) = self.strip_runtime_invocation(request)?;
        let op = request
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if let Some(refusal) = custody_host_trust_refusal(op, self.host_trusted) {
            tracing::debug!(%op, "custody op refused: this host is not WCI-operated");
            return Ok(refusal);
        }
        if op == OP_CUSTODY_PROVISION_POOL_NODE_SHARE {
            let slot_held = match self.admit_pool_share(&request) {
                Ok(slot_held) => slot_held,
                Err(refusal) => return Ok(refusal),
            };
            return self.write_host_share(request, slot_held).await;
        }
        if op == OP_CUSTODY_PROVISION_NODE_SHARE {
            // V1 shares observe the same host maximum (PM-F2).
            let slot_held = self.v1_share_slot_held(&request);
            return self.write_host_share(request, slot_held).await;
        }
        // L10, first stage: every release call spends its endpoint's budget at
        // entry, whatever the capsule answers.
        if matches!(
            op,
            OP_CUSTODY_EVALUATE
                | OP_CUSTODY_RELEASE_CONTRIBUTION
                | OP_CUSTODY_RELEASE_POOL_CONTRIBUTION
        ) && self
            .limiter
            .admit_endpoint(source.endpoint_key(), crate::auth::now_ts())
            .is_err()
        {
            tracing::debug!(%op, "custody release refused at its endpoint budget");
            return Ok(custody_rate_limited_response());
        }
        if op == OP_CUSTODY_STATUS {
            let response = self
                .bridge
                .send_raw(&request)
                .await
                .map_err(|error| ProviderError::Provider(error.to_string()))?;
            return self.normalize_public_status(response, &source);
        }
        if op == OP_CUSTODY_EVALUATE {
            let prepare = PrivateCustodyRightsRequestV1::new_prepare(request.clone());
            let prepare_response = self.send_private_child_request(&prepare).await?;
            let chain_request = self.private_ok_data(prepare_response)?;
            // L10, second stage: the accepted prepare proved the operation's
            // signatures, so its wallet and item spend their budgets now,
            // before the chain read.
            let (wallet, kid) = custody_rights_budget_keys(&request)?;
            if self
                .limiter
                .admit_rights(wallet, kid, crate::auth::now_ts())
                .is_err()
            {
                tracing::debug!("custody evaluate refused at its wallet or item budget");
                return Ok(custody_rate_limited_response());
            }
            let registry = self.registry.upgrade().ok_or_else(|| {
                ProviderError::Provider("node-local custody registry is unavailable".into())
            })?;
            let chain_data = invoke_json_provider_with_transport(
                registry.as_ref(),
                CHAIN_PROVIDER_ID,
                CHAIN_RIGHTS_EVIDENCE_OP,
                chain_request,
                ProviderInvocationTransport::Local,
            )
            .await
            .map_err(ProviderError::Provider)?;
            let settle = PrivateCustodyRightsRequestV1::new_settle(request, chain_data);
            return self.send_private_child_request(&settle).await;
        }
        self.bridge
            .send_raw(&request)
            .await
            .map_err(|error| ProviderError::Provider(error.to_string()))
    }

    async fn shutdown(&self) -> Result<(), ProviderError> {
        self.bridge
            .shutdown()
            .await
            .map_err(|error| ProviderError::Provider(error.to_string()))
    }
}

/// Exact typed inputs for one Profile-authorized Runtime release operation.
///
/// This is an in-memory assembly value. It does not claim replay or persist
/// any provider result; the Runtime release journal owns both responsibilities.
#[derive(Clone)]
pub(crate) struct RuntimeReleaseOperationAssemblyInput {
    pub(crate) rights_request: WalletSignedRightsRequestV1,
    pub(crate) release_request: KeyReleaseRequestV1,
    pub(crate) recipient_public_key: RecipientPublicKeyBytesV1,
    pub(crate) recipient_identity: RecipientKeyIdentityV1,
    pub(crate) policy_body: RightsPolicyBodyV1,
    pub(crate) evidence_request: RightsEvaluationEvidenceRequestV1,
    pub(crate) custody_epoch: SignedCustodyEpochV1,
    pub(crate) audit_request_id: RuntimeReleaseAuditIdV1,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
}

/// Assemble and verify one Profile-authorized Runtime release operation.
///
/// The device key is loaded only from the existing local identity. This helper
/// never creates keys, dispatches providers, or claims replay.
pub(crate) fn assemble_protected_content_runtime_release_operation(
    data_dir: &Path,
    principal_id: &str,
    localhost_root: &str,
    proof_binding_id: &str,
    input: RuntimeReleaseOperationAssemblyInput,
    now_unix_seconds: u64,
) -> anyhow::Result<SignedRuntimeReleaseOperationV1> {
    let (device_key, _) =
        crate::collaboration_profile_authority::load_existing_device_signing_key(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    let runtime_issuer = RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())
        .map_err(|_| anyhow::anyhow!("local Runtime device signing key is invalid"))?;
    if input.release_request.recipient() != &input.recipient_identity {
        anyhow::bail!("release request recipient does not match recipient identity");
    }
    let authorization_statement = RecipientKeyAuthorizationStatementV1::new(
        input.rights_request.request().binding().clone(),
        input.rights_request.request().action(),
        input.recipient_public_key,
        input.recipient_identity,
        runtime_issuer,
        input.issued_at,
        input.expires_at,
    )
    .map_err(|_| anyhow::anyhow!("recipient authorization statement is invalid"))?;
    let recipient_authorization =
        crate::collaboration_profile_authority::sign_protected_content_recipient_key_authorization(
            data_dir,
            principal_id,
            localhost_root,
            proof_binding_id,
            authorization_statement,
            now_unix_seconds,
        )?;
    let statement = RuntimeReleaseOperationStatementV1::new(
        runtime_issuer,
        input.rights_request,
        input.release_request,
        input.recipient_public_key,
        recipient_authorization,
        input.policy_body,
        input.evidence_request,
        input.custody_epoch,
        input.audit_request_id,
        input.issued_at,
        input.expires_at,
    )
    .map_err(|_| anyhow::anyhow!("Runtime release operation statement is invalid"))?;
    let signed = SignedRuntimeReleaseOperationV1::new(
        statement.clone(),
        device_key
            .sign(
                &statement
                    .canonical_bytes()
                    .map_err(|_| anyhow::anyhow!("Runtime release operation is not canonical"))?,
            )
            .to_bytes()
            .to_vec(),
    )
    .map_err(|_| anyhow::anyhow!("Runtime release operation signature is invalid"))?;
    signed
        .verify(runtime_issuer, now_unix_seconds)
        .map_err(|_| anyhow::anyhow!("Runtime release operation verification failed"))?;
    Ok(signed)
}

struct RuntimeDecryptRegistryAdapter {
    registry: Arc<ProviderRegistry>,
}

impl RuntimeDecryptRegistryAdapter {
    fn new(registry: Arc<ProviderRegistry>) -> Self {
        Self { registry }
    }
}

fn decrypt_provider_op(request: &DecryptProviderRequestV1) -> &'static str {
    match request.op() {
        DecryptProviderRequestOpV1::PrepareRecipient => "prepare_recipient",
        DecryptProviderRequestOpV1::OpenViewerSession => "open_viewer_session",
        DecryptProviderRequestOpV1::ReadViewerMediaPart => "read_viewer_media_part",
        DecryptProviderRequestOpV1::CancelPreparedRecipient => "cancel_prepared_recipient",
        DecryptProviderRequestOpV1::CloseViewerSession => "close_viewer_session",
        DecryptProviderRequestOpV1::ReadViewerObjectChunk => "read_viewer_object_chunk",
        DecryptProviderRequestOpV1::PrepareRecipientV2 => "prepare_recipient_v2",
        DecryptProviderRequestOpV1::OpenViewerSessionV2 => "open_viewer_session_v2",
        DecryptProviderRequestOpV1::ReadViewerMediaPartSealed => "read_viewer_media_part_sealed",
        DecryptProviderRequestOpV1::ReadViewerObjectChunkSealed => {
            "read_viewer_object_chunk_sealed"
        }
    }
}

#[async_trait::async_trait]
impl RuntimeDecryptProvider for RuntimeDecryptRegistryAdapter {
    async fn prepare_recipient(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        invoke_decrypt_provider(self.registry.as_ref(), request).await
    }

    async fn open_viewer_session(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        invoke_decrypt_provider(self.registry.as_ref(), request).await
    }

    async fn read_viewer_media_part(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        invoke_decrypt_provider(self.registry.as_ref(), request).await
    }

    async fn read_viewer_object_chunk(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        invoke_decrypt_provider(self.registry.as_ref(), request).await
    }

    async fn cancel_prepared_recipient(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        invoke_decrypt_provider(self.registry.as_ref(), request).await
    }

    async fn close_viewer_session(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        invoke_decrypt_provider(self.registry.as_ref(), request).await
    }
}

pub(crate) async fn invoke_decrypt_provider(
    registry: &ProviderRegistry,
    request: &DecryptProviderRequestV1,
) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
    let request_bytes = request
        .to_json_vec()
        .map_err(|_| RuntimeProviderCallError::NoExactResult)?;
    let request_value: Value = serde_json::from_slice(&request_bytes)
        .map_err(|_| RuntimeProviderCallError::NoExactResult)?;
    let response_value = invoke_json_provider(
        registry,
        PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
        decrypt_provider_op(request),
        request_value,
    )
    .await
    .map_err(|_| RuntimeProviderCallError::NoExactResult)?;
    let response_bytes =
        serde_json::to_vec(&response_value).map_err(|_| RuntimeProviderCallError::NoExactResult)?;
    DecryptProviderResponseV1::from_json_slice(&response_bytes)
        .map_err(|_| RuntimeProviderCallError::NoExactResult)
}

pub fn runtime_release_journal(data_dir: &Path) -> RuntimeReleaseJournal {
    RuntimeReleaseJournal::new(data_dir.join("protected-content").join("runtime-release"))
}

pub(crate) fn runtime_mint_journal_root(data_dir: &Path) -> PathBuf {
    data_dir.join(RUNTIME_MINT_JOURNAL_ROOT)
}

pub(crate) fn runtime_mint_journal(data_dir: &Path) -> RuntimeMintJournal {
    RuntimeMintJournal::new(runtime_mint_journal_root(data_dir))
}

fn generate_runtime_content_access_id() -> anyhow::Result<ContentAccessIdV1> {
    loop {
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        if let Ok(value) = ContentAccessIdV1::new(bytes) {
            return Ok(value);
        }
    }
}

fn runtime_mint_intent_with_access_id(
    composition: &RuntimeCustodyComposition,
    input: &RuntimeCustodyLibraryPublishInput,
    selected_nodes: Vec<elastos_protected_content_runtime::RuntimeMintNodeBinding>,
    content_access_id: ContentAccessIdV1,
) -> anyhow::Result<RuntimeMintIntent> {
    RuntimeMintIntent::new_media_dash(
        input.principal_id.clone(),
        &input.object_uri,
        &input.source_storage,
        input.wallet_account_id.clone(),
        input.wallet_account_address.clone(),
        input.creator_mint_source_digest,
        input.media.preparation_receipt(),
        input
            .media
            .renditions
            .iter()
            .map(|rendition| RuntimeMintIntentRenditionV2 {
                kind: rendition.kind,
                segment_count: rendition.segment_count,
            })
            .collect(),
        content_access_id,
        composition
            .signed_pool
            .pool_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?,
        composition
            .signed_epoch
            .epoch_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?,
        composition
            .signed_committee_authorization
            .authorization_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?,
        selected_nodes,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))
}

fn load_or_persist_runtime_mint_intent(
    journal: &RuntimeMintJournal,
    composition: &RuntimeCustodyComposition,
    input: &RuntimeCustodyLibraryPublishInput,
    selected_nodes: Vec<elastos_protected_content_runtime::RuntimeMintNodeBinding>,
) -> anyhow::Result<RuntimeMintIntent> {
    // The source's current attempt: a new one once an earlier attempt was
    // archived, so a new mint never meets the identity of an archived one.
    let attempt = journal
        .current_attempt(
            &input.principal_id,
            &input.object_uri,
            &input.source_storage,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    match journal.load_intent(attempt.request_id()) {
        Ok(existing) => {
            let expected = runtime_mint_intent_with_access_id(
                composition,
                input,
                selected_nodes,
                existing.content_access_id(),
            )?
            .for_attempt(attempt.attempt())
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?;
            if !existing.same_authority_as(&expected) {
                return Err(RuntimeCustodyAttemptConflict::error(
                    RuntimeCustodyAttemptConflictReason::AuthorityChanged,
                ));
            }
            Ok(existing)
        }
        Err(elastos_protected_content_runtime::RuntimeMintJournalError::NotFound) => {
            let intent = runtime_mint_intent_with_access_id(
                composition,
                input,
                selected_nodes,
                generate_runtime_content_access_id()?,
            )?
            .for_attempt(attempt.attempt())
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?;
            journal
                .persist_intent(&intent)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))
        }
        Err(_) => Err(anyhow::anyhow!(
            "Runtime custody mint intent is unavailable"
        )),
    }
}

fn runtime_mint_intent_with_access_id_object(
    composition: &RuntimeCustodyComposition,
    input: &RuntimeCustodyLibraryPublishObjectInput,
    selected_nodes: Vec<elastos_protected_content_runtime::RuntimeMintNodeBinding>,
    content_access_id: ContentAccessIdV1,
) -> anyhow::Result<RuntimeMintIntent> {
    RuntimeMintIntent::new_object(
        input.principal_id.clone(),
        &input.object_uri,
        &input.source_storage,
        input.wallet_account_id.clone(),
        input.wallet_account_address.clone(),
        input.creator_mint_source_digest,
        input.content_type.clone(),
        &input.clear_plaintext,
        content_access_id,
        composition
            .signed_pool
            .pool_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?,
        composition
            .signed_epoch
            .epoch_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?,
        composition
            .signed_committee_authorization
            .authorization_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?,
        selected_nodes,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))
}

fn load_or_persist_runtime_mint_intent_object(
    journal: &RuntimeMintJournal,
    composition: &RuntimeCustodyComposition,
    input: &RuntimeCustodyLibraryPublishObjectInput,
    selected_nodes: Vec<elastos_protected_content_runtime::RuntimeMintNodeBinding>,
) -> anyhow::Result<RuntimeMintIntent> {
    // The source's current attempt: a new one once an earlier attempt was
    // archived, so a new mint never meets the identity of an archived one.
    let attempt = journal
        .current_attempt(
            &input.principal_id,
            &input.object_uri,
            &input.source_storage,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    match journal.load_intent(attempt.request_id()) {
        Ok(existing) => {
            let expected = runtime_mint_intent_with_access_id_object(
                composition,
                input,
                selected_nodes,
                existing.content_access_id(),
            )?
            .for_attempt(attempt.attempt())
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?;
            if !existing.same_authority_as(&expected) {
                return Err(RuntimeCustodyAttemptConflict::error(
                    RuntimeCustodyAttemptConflictReason::AuthorityChanged,
                ));
            }
            Ok(existing)
        }
        Err(elastos_protected_content_runtime::RuntimeMintJournalError::NotFound) => {
            let intent = runtime_mint_intent_with_access_id_object(
                composition,
                input,
                selected_nodes,
                generate_runtime_content_access_id()?,
            )?
            .for_attempt(attempt.attempt())
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?;
            journal
                .persist_intent(&intent)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))
        }
        Err(_) => Err(anyhow::anyhow!(
            "Runtime custody mint intent is unavailable"
        )),
    }
}

fn load_completed_runtime_mint_facts(
    journal: &RuntimeMintJournal,
    input: &RuntimeCustodyLibraryPublishInput,
    mint_id: Digest32,
) -> anyhow::Result<RuntimeCustodyLibraryPublishFacts> {
    let persisted = journal
        .load(mint_id)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let evidence = persisted
        .content_availability()
        .ok_or_else(|| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let content_id = runtime_protected_content_id(persisted.draft().encrypted_content())?;
    Ok(runtime_custody_library_publish_facts(
        &input.object_uri,
        &input.source_storage,
        persisted.draft(),
        &content_id,
        evidence,
    ))
}

fn load_completed_runtime_mint_object_facts(
    journal: &RuntimeMintJournal,
    input: &RuntimeCustodyLibraryPublishObjectInput,
    mint_id: Digest32,
) -> anyhow::Result<RuntimeCustodyLibraryPublishFacts> {
    let persisted = journal
        .load(mint_id)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let evidence = persisted
        .content_availability()
        .ok_or_else(|| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let content_id = runtime_protected_content_id(persisted.draft().encrypted_content())?;
    Ok(runtime_custody_library_publish_facts(
        &input.object_uri,
        &input.source_storage,
        persisted.draft(),
        &content_id,
        evidence,
    ))
}

/// A crash between the protect session's close settlement and
/// `mark_intent_completed` leaves the intent at `SettledBeforeDraft(Closed)`
/// while every durable mint step may already have finished; the deterministic
/// intent identity then bricks the source object permanently (ELACITY-2307).
/// Adopt the finished record when one exists: return its mint id after
/// completing the intent. A record that is not fully terminal cannot be rolled
/// forward (the content key material is gone), so it fails closed for cleanup
/// reconciliation with the orphaned custody evidence logged. No record means
/// nothing durable survived the crash and the terminal abort stands.
fn adopt_settled_runtime_mint_record(
    journal: &RuntimeMintJournal,
    mint_intent: &RuntimeMintIntent,
) -> anyhow::Result<Option<Digest32>> {
    let scan = journal
        .find_mint_record_for_intent(mint_intent.request_id())
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    // Closed attempts cannot be continued, but what they left on the nodes is
    // real and nothing else reports it. Say so every time this intent is looked
    // at, whatever happens next.
    for abandoned in scan.abandoned() {
        tracing::warn!(
            request_id = %hex::encode(mint_intent.request_id().as_bytes()),
            mint_id = %hex::encode(abandoned.mint_id.as_bytes()),
            node_receipts_accepted = abandoned.accepted_orphan_count,
            nodes_possibly_holding_a_share = abandoned.uncertain_node_count,
            "abandoned runtime custody mint attempt left custody state on nodes; cleanup reconciliation required"
        );
    }
    let Some(record) = scan.open() else {
        // Every attempt for this intent is closed, so a fresh one is the only
        // way forward and is safe: new shares seal against a new envelope and
        // cannot combine with what any earlier attempt left behind.
        return Ok(None);
    };
    let fully_terminal = record.custody_terminal()
        == Some(RuntimeCustodyTerminalKind::CustodyProvisioned)
        && record.content_availability().is_some();
    if fully_terminal {
        let mint_id = record.draft().mint_id();
        journal
            .mark_intent_completed(mint_intent.request_id(), mint_id)
            .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
        return Ok(Some(mint_id));
    }
    // This attempt can never finish -- its content key material did not outlive
    // the request that made it -- so keeping the record only wedges the object
    // it was minted from. Every later attempt on that path would find this
    // record, refuse to treat it as a candidate, and fail the same way forever.
    // Forget it instead, and say once what it left behind.
    //
    // Safe for what follows: a fresh attempt seals new shares against a new
    // envelope and cannot combine with anything this one left on the nodes.
    // Those shares open nothing without the envelope and no listing will ever
    // name them, so reclaiming the space is housekeeping, not a precondition.
    let mint_id = record.draft().mint_id();
    tracing::warn!(
        request_id = %hex::encode(mint_intent.request_id().as_bytes()),
        mint_id = %hex::encode(mint_id.as_bytes()),
        custody_terminal = ?record.custody_terminal(),
        content_availability_recorded = record.content_availability().is_some(),
        // What an operator needs is not "did anything start" but what was left
        // behind: shares this Runtime knows are held, and nodes that may be
        // holding one without ever having said so.
        node_receipts_accepted = record.accepted_orphans().len(),
        nodes_possibly_holding_a_share = record.uncertain_node_count(),
        "runtime custody mint attempt cannot finish and was discarded; its custody shares are inert residue"
    );
    journal
        .discard_unfinishable_mint(mint_id)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    Ok(None)
}

pub fn list_unresolved_runtime_releases(
    data_dir: &Path,
) -> Result<Vec<PersistedRuntimeReleaseOperation>, RuntimeReleaseJournalError> {
    runtime_release_journal(data_dir).list_unresolved()
}

pub fn unresolved_release_audit_records(
    data_dir: &Path,
) -> Result<Vec<RuntimeReleaseAuditRecord>, RuntimeReleaseJournalError> {
    list_unresolved_runtime_releases(data_dir)?
        .iter()
        .map(PersistedRuntimeReleaseOperation::audit_record)
        .collect()
}

/// Starts this Home's custody provider with every root on disk (Plan B
/// T2.1): `base_path` is the custody-provider folder and `extra.roots` lists
/// `inactive` and each `pools/<hex>` root, capped by the node settings.
pub async fn register_custody_provider(
    registry: &Arc<ProviderRegistry>,
    binary_path: &Path,
    data_dir: &Path,
) -> anyhow::Result<()> {
    let bridge_config = custody_provider_roots_config(data_dir)?;
    spawn_custody_provider(registry, binary_path, data_dir, bridge_config).await
}

/// Starts a custody host's provider with its one legacy root: `base_path` is
/// the `inactive` root itself and `extra` is null (Plan B T2.1).
pub async fn register_custody_host_provider(
    registry: &Arc<ProviderRegistry>,
    binary_path: &Path,
    data_dir: &Path,
) -> anyhow::Result<()> {
    let state_root = inactive_custody_state_root(data_dir);
    validate_custody_state_root(&state_root)?;
    let base_path = custody_utf8_path(&state_root)?;
    let bridge_config = ProviderConfig {
        base_path,
        ..Default::default()
    };
    spawn_custody_provider(registry, binary_path, data_dir, bridge_config).await
}

/// The running custody provider's bridge for each Home in this process.
static CUSTODY_BRIDGES: OnceLock<
    StdMutex<HashMap<PathBuf, Weak<elastos_runtime::provider::ProviderBridge>>>,
> = OnceLock::new();

fn custody_bridges(
) -> &'static StdMutex<HashMap<PathBuf, Weak<elastos_runtime::provider::ProviderBridge>>> {
    CUSTODY_BRIDGES.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn remember_custody_bridge(
    data_dir: &Path,
    bridge: &Arc<elastos_runtime::provider::ProviderBridge>,
) {
    if let Ok(mut bridges) = custody_bridges().lock() {
        bridges.insert(data_dir.to_path_buf(), Arc::downgrade(bridge));
    }
}

fn running_custody_bridge(
    data_dir: &Path,
) -> Option<Arc<elastos_runtime::provider::ProviderBridge>> {
    custody_bridges()
        .lock()
        .ok()?
        .get(data_dir)
        .and_then(Weak::upgrade)
}

/// Whether this server started the custody provider running for this Home,
/// and so can refresh its roots.
pub(crate) fn custody_bridge_known(data_dir: &Path) -> bool {
    running_custody_bridge(data_dir).is_some()
}

/// One root as the running custody provider lists it (local plane only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CustodyRootStatus {
    pub(crate) path: Option<String>,
    pub(crate) configured: bool,
    pub(crate) shares_held: Option<u64>,
}

/// Plan B T2.2 (S2-Q1): sends the running custody provider a fresh `init`
/// with every root on disk, so a new root serves and a stopped one ends
/// without a restart. The other roots load the same keys again. Fails when
/// no provider runs for this Home or it refuses the set.
pub(crate) async fn refresh_custody_roots(
    data_dir: &Path,
) -> anyhow::Result<Vec<CustodyRootStatus>> {
    let bridge = running_custody_bridge(data_dir)
        .ok_or_else(|| anyhow::anyhow!("this Home runs no custody provider"))?;
    let config = custody_provider_roots_config(data_dir)?;
    let response = bridge
        .send_raw(&json!({ "op": "init", "config": config }))
        .await
        .map_err(|error| anyhow::anyhow!("custody provider refresh failed: {error}"))?;
    require_custody_provider_status(&response)?;
    tracing::debug!("the custody provider holds the roots on disk now");
    Ok(custody_root_statuses(&response))
}

/// The roots the running custody provider holds, from its private status;
/// none when no provider runs for this Home.
pub(crate) async fn custody_provider_root_statuses(
    data_dir: &Path,
) -> Option<Vec<CustodyRootStatus>> {
    let bridge = running_custody_bridge(data_dir)?;
    let response = bridge.send_raw(&json!({ "op": "status" })).await.ok()?;
    require_custody_provider_status(&response).ok()?;
    Some(custody_root_statuses(&response))
}

fn custody_root_statuses(status: &Value) -> Vec<CustodyRootStatus> {
    status["data"]["roots"]
        .as_array()
        .map(|roots| {
            roots
                .iter()
                .map(|root| CustodyRootStatus {
                    path: root["path"].as_str().map(str::to_owned),
                    configured: root["configured"].as_bool() == Some(true),
                    shares_held: root["shares_held"].as_u64(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Whether the running custody provider serves the root at `path`.
pub(crate) async fn custody_root_loaded(data_dir: &Path, path: &str) -> bool {
    custody_provider_root_statuses(data_dir)
        .await
        .is_some_and(|roots| {
            roots
                .iter()
                .any(|root| root.path.as_deref() == Some(path) && root.configured)
        })
}

/// The folder of the custody root `path` (`inactive` or `pools/<hex>`).
pub(crate) fn custody_root_dir(data_dir: &Path, path: &str) -> PathBuf {
    custody_provider_base(data_dir).join(path)
}

/// The provider config for every root this Home holds on disk. With no root
/// there is nothing to start.
pub(crate) fn custody_provider_roots_config(data_dir: &Path) -> anyhow::Result<ProviderConfig> {
    let roots = custody_provider_root_paths(data_dir)?;
    if roots.is_empty() {
        return Err(invalid_custody_config("no provisioned custody root exists"));
    }
    let base = custody_provider_base(data_dir);
    // A root that fails the owner-only check follows the per-root rule (user
    // decision 2026-11-12 10:26): it is still named, the provider does not
    // load it, and its pool is not served; the other roots start.
    for root in &roots {
        if let Err(error) = validate_custody_state_root(&base.join(root)) {
            tracing::warn!(
                root = %root,
                error = %format!("{error:#}"),
                "a custody root is unsafe; its pool is not served"
            );
        }
    }
    Ok(ProviderConfig {
        base_path: custody_utf8_path(&base)?,
        extra: json!({
            "roots": roots
                .iter()
                .map(|path| json!({ "path": path }))
                .collect::<Vec<_>>(),
            "max_roots": crate::custody_release_limits::CUSTODY_NODE_SETTINGS.max_pools,
        }),
        ..Default::default()
    })
}

/// The folder holding every custody root of this Home.
pub(crate) fn custody_provider_base(data_dir: &Path) -> PathBuf {
    data_dir.join(CUSTODY_PROVIDER_STATE_DIR)
}

/// OPEN-LOOP F4: this Home's own custody node keys, the one answer to "is
/// this node mine": the key every root on disk holds, so the served pools'
/// nodes and the node Include set up alike. A root whose key cannot be read
/// runs no node and is left out.
pub(crate) fn own_custody_node_keys(data_dir: &Path) -> anyhow::Result<Vec<NodePublicKey>> {
    Ok(custody_provider_root_paths(data_dir)?
        .iter()
        .filter_map(|root| {
            custody_provider::load_node_public_key(&custody_root_dir(data_dir, root)).ok()
        })
        .collect())
}

/// Plan B POOL-MINT: the one host storage account (Anders #388): the bytes
/// of other parties' custody data this host keeps, across every pool it
/// serves. Shares now: every root's share store, and the shares a stopped
/// pool's set-aside root still retains (`pools/*.stopped-*`, PM-F3); member
/// copies are added here later. Nothing is deleted.
pub(crate) fn host_custody_storage_bytes(data_dir: &Path) -> anyhow::Result<u64> {
    let mut roots: Vec<PathBuf> = custody_provider_root_paths(data_dir)?
        .iter()
        .map(|root| custody_root_dir(data_dir, root))
        .collect();
    let pools = custody_provider_base(data_dir).join(custody_provider::CUSTODY_POOL_ROOTS_DIR);
    match fs::read_dir(&pools) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.contains(".stopped-"))
                {
                    roots.push(entry.path());
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut total = 0u64;
    for root in roots {
        let store = custody_provider::node_share_store_dir(&root);
        let entries = match fs::read_dir(&store) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let metadata = fs::symlink_metadata(entry?.path())?;
            if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    Ok(total)
}

/// Plan B POOL-MINT (PM-F2): the one host-wide lock every share write takes,
/// so the maximum check and the write it allows are one step.
static HOST_SHARE_WRITES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Plan B POOL-MINT (PM-F2, PM-F4): one share write under the host-wide lock.
/// Inside it, a write to a slot this host already holds (an exact retry
/// answers the stored receipt; anything else is refused) is not charged;
/// any other write is checked against the host storage maximum, then sent
/// and settled before the lock is released.
///
/// The write owns the lock, not its caller: it runs in its own task, in the
/// caller's dispatch fence, and the caller awaits it. A caller cancelled
/// after dispatch leaves the lock held until the write it allowed settles.
pub(crate) async fn guarded_host_share_write<Held, Write, Sent>(
    data_dir: PathBuf,
    incoming_bytes: u64,
    slot_held: Held,
    write: Write,
) -> Result<Value, ProviderError>
where
    Held: FnOnce() -> bool + Send + 'static,
    Write: FnOnce() -> Sent + Send + 'static,
    Sent: std::future::Future<Output = Result<Value, ProviderError>> + Send + 'static,
{
    let operation = async move {
        let _guard = HOST_SHARE_WRITES.lock().await;
        if !slot_held() {
            if let Some(refusal) = host_storage_refusal(&data_dir, incoming_bytes) {
                return Ok(refusal);
            }
        }
        write().await
    };
    let task = match elastos_runtime::provider::dispatch::DispatchFence::current() {
        Some(fence) => tokio::spawn(async move { fence.scope(operation).await }),
        None => tokio::spawn(operation),
    };
    task.await.map_err(|error| {
        ProviderError::Provider(format!("host share write did not finish: {error}"))
    })?
}

/// Plan B POOL-MINT: a WCI-operated host keeps at most the storage maximum
/// its operator set, whichever Home mints (no per-creator quota). With no
/// maximum set the share is refused (fail closed); a share of
/// `incoming_bytes` that would take the host past it is refused too.
pub(crate) fn host_storage_refusal(data_dir: &Path, incoming_bytes: u64) -> Option<Value> {
    let refusal = |code: &str, message: &str| {
        Some(json!({ "status": "error", "code": code, "message": message }))
    };
    let Some(max) = crate::host_trust::host_storage_max_bytes(data_dir) else {
        tracing::warn!("pool share refused: this host has no storage maximum");
        return refusal(
            crate::host_trust::HOST_STORAGE_MAX_UNSET,
            "this host has no storage maximum: its operator sets one with elastos setup --host-trust wci-operated --max-storage-bytes <bytes>",
        );
    };
    match host_custody_storage_bytes(data_dir) {
        Ok(used) if used.saturating_add(incoming_bytes) <= max => None,
        Ok(used) => {
            tracing::warn!(
                used,
                max,
                incoming_bytes,
                "pool share refused: host storage is full"
            );
            refusal(
                crate::host_trust::HOST_STORAGE_FULL,
                "this host's storage is full",
            )
        }
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "host storage cannot be counted");
            refusal(
                "provisioning_refused",
                "this host's storage cannot be counted",
            )
        }
    }
}

/// The roots on disk, as the provider's `extra.roots` names them: `inactive`
/// when it exists, then each `pools/<hex>` folder in name order. Tombstones,
/// staging folders and other names are not roots.
pub(crate) fn custody_provider_root_paths(data_dir: &Path) -> anyhow::Result<Vec<String>> {
    let base = custody_provider_base(data_dir);
    let mut roots = Vec::new();
    if base
        .join(custody_provider::CUSTODY_INACTIVE_ROOT_PATH)
        .is_dir()
    {
        roots.push(custody_provider::CUSTODY_INACTIVE_ROOT_PATH.to_string());
    }
    let pools = base.join(custody_provider::CUSTODY_POOL_ROOTS_DIR);
    let entries = match fs::read_dir(&pools) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(roots),
        Err(error) => {
            return Err(anyhow::anyhow!(
                "custody pool roots cannot be listed: {error}"
            ))
        }
    };
    let mut pool_roots = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|error| anyhow::anyhow!("custody pool roots cannot be listed: {error}"))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let path = format!("{}/{name}", custody_provider::CUSTODY_POOL_ROOTS_DIR);
        let is_dir = fs::symlink_metadata(entry.path())
            .map(|metadata| metadata.is_dir())
            .unwrap_or(false);
        if is_dir && custody_provider::is_custody_root_path(&path) {
            pool_roots.push(path);
        }
    }
    pool_roots.sort();
    roots.extend(pool_roots);
    Ok(roots)
}

fn custody_utf8_path(path: &Path) -> anyhow::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid_custody_config("custody provider folder must be valid UTF-8"))
}

async fn spawn_custody_provider(
    registry: &Arc<ProviderRegistry>,
    binary_path: &Path,
    data_dir: &Path,
    bridge_config: ProviderConfig,
) -> anyhow::Result<()> {
    let bridge = Arc::new(
        elastos_runtime::provider::ProviderBridge::spawn(binary_path, bridge_config)
            .await
            .map_err(|error| {
                anyhow::anyhow!("failed to spawn inactive custody provider: {error}")
            })?,
    );
    let startup = async {
        let status =
            request_protected_provider_startup_status(&bridge, "inactive custody provider").await?;
        require_custody_provider_status(&status)?;
        // The existing roots still load, so Hosting lists them; on an
        // everyday host they serve nothing (#388-1).
        let provider: Arc<dyn Provider> = Arc::new(InactiveCustodyProvider::new(
            bridge.clone(),
            Arc::downgrade(registry),
            crate::host_trust::host_trusted(data_dir),
            data_dir.to_path_buf(),
        ));
        register_custody_runtime_provider_target(registry, provider)
            .await
            .map_err(|error| anyhow::anyhow!("failed to register inactive custody route: {error}"))
    }
    .await;
    settle_protected_provider_startup(&bridge, startup, "inactive custody provider").await?;
    // Plan B T2.2 (user decision 2026-11-12 10:35): the server keeps the
    // bridge so a new or stopped root reaches the running provider by a fresh
    // `init`, with no registry change.
    remember_custody_bridge(data_dir, &bridge);
    // Plan B T3.4: whenever a custody root runs, this Home also answers the
    // `custody-pool` target. Its sessions fail closed until a pool descriptor
    // names this node as a server.
    if let Err(error) =
        crate::custody_pool_service::register_custody_pool_service(registry, data_dir).await
    {
        tracing::warn!(
            error = %format!("{error:#}"),
            "the custody-pool target is not registered"
        );
    }
    Ok(())
}

pub async fn register_protect_provider(
    registry: &Arc<ProviderRegistry>,
    binary_path: &Path,
) -> anyhow::Result<()> {
    let bridge = Arc::new(
        elastos_runtime::provider::ProviderBridge::spawn(
            binary_path,
            ProviderConfig {
                extra: json!({}),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| anyhow::anyhow!("failed to spawn protect provider: {error}"))?,
    );
    let startup = async {
        let status = request_protected_provider_startup_status(&bridge, "protect provider").await?;
        require_protect_provider_status(&status)?;
        let provider: Arc<dyn Provider> =
            Arc::new(elastos_runtime::provider::CapsuleProvider::with_scheme(
                bridge.clone(),
                PROTECT_PROVIDER_ID,
            ));
        registry
            .register_runtime_provider_target(PROTECT_PROVIDER_ID, provider)
            .await
            .map_err(|error| anyhow::anyhow!("failed to register protect provider: {error}"))
    }
    .await;
    settle_protected_provider_startup(&bridge, startup, "protect provider").await
}

pub async fn register_protected_content_decrypt_provider(
    registry: &Arc<ProviderRegistry>,
    binary_path: &Path,
    runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
) -> anyhow::Result<()> {
    let bridge = Arc::new(
        ProviderBridge::spawn(
            binary_path,
            ProviderConfig {
                extra: json!({
                    "trusted_runtime_issuer": format!(
                        "0x{}",
                        hex::encode(runtime_operation_issuer.as_bytes())
                    ),
                }),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| {
            anyhow::anyhow!("failed to spawn protected-content decrypt provider: {error}")
        })?,
    );
    let startup = async {
        let status = request_protected_provider_startup_status(
            &bridge,
            "protected-content decrypt provider",
        )
        .await?;
        require_protected_content_decrypt_provider_status(&status)?;
        let provider: Arc<dyn Provider> =
            Arc::new(elastos_runtime::provider::CapsuleProvider::with_scheme(
                bridge.clone(),
                PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            ));
        registry
            .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, provider)
            .await
            .map_err(|error| {
                anyhow::anyhow!("failed to register protected-content decrypt provider: {error}")
            })
    }
    .await;
    settle_protected_provider_startup(&bridge, startup, "protected-content decrypt provider").await
}

async fn request_protected_provider_startup_status(
    bridge: &ProviderBridge,
    label: &str,
) -> anyhow::Result<Value> {
    tokio::time::timeout(
        PROTECTED_CONTENT_PROVIDER_STATUS_TIMEOUT,
        bridge.send_raw(&json!({"op":"status"})),
    )
    .await
    .map_err(|_| anyhow::anyhow!("{label} status timed out"))?
    .map_err(|error| anyhow::anyhow!("{label} status failed: {error}"))
}

async fn settle_protected_provider_startup(
    bridge: &ProviderBridge,
    startup: anyhow::Result<()>,
    label: &str,
) -> anyhow::Result<()> {
    let Err(startup_error) = startup else {
        return Ok(());
    };
    if let Err(shutdown_error) = bridge.shutdown().await {
        return Err(anyhow::anyhow!(
            "{startup_error}; {label} shutdown/reap also failed: {shutdown_error}"
        ));
    }
    Err(startup_error)
}

fn require_protect_provider_status(status: &Value) -> anyhow::Result<()> {
    let data = require_exact_provider_status_data(
        status,
        "protect provider",
        &[
            "provider",
            "version",
            "configured",
            "supported_operations",
            "request_schema",
            "response_schema",
        ],
    )?;
    if data.get("provider").and_then(Value::as_str) != Some(PROTECT_PROVIDER_PROCESS_ID) {
        anyhow::bail!("protect provider status has an unsupported identity");
    }
    if data.get("configured").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("protect provider is not configured");
    }
    if data.get("request_schema").and_then(Value::as_str)
        != Some(PROTECT_PROVIDER_REQUEST_SCHEMA_V1)
        || data.get("response_schema").and_then(Value::as_str)
            != Some(PROTECT_PROVIDER_RESPONSE_SCHEMA_V1)
    {
        anyhow::bail!("protect provider status has unsupported protocol schemas");
    }
    require_exact_provider_operations(data, PROTECT_PROVIDER_OPERATIONS, "protect provider")
}

pub fn require_media_provider_status(status: &Value) -> anyhow::Result<()> {
    let data = require_exact_provider_status_data(
        status,
        "media-provider",
        &[
            "provider",
            "protocol_version",
            "version",
            "configured",
            "supported_operations",
        ],
    )?;
    if data.get("provider").and_then(Value::as_str) != Some(MEDIA_PROVIDER_PROCESS_ID) {
        anyhow::bail!("media-provider status has an unsupported provider identity");
    }
    if data.get("protocol_version").and_then(Value::as_str) != Some(MEDIA_PROVIDER_PROTOCOL_VERSION)
    {
        anyhow::bail!("media-provider status has an unsupported protocol version");
    }
    if data.get("configured").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("media-provider is not configured");
    }
    require_exact_provider_operations(data, MEDIA_PROVIDER_OPERATIONS, "media-provider")
}

fn require_custody_provider_status(status: &Value) -> anyhow::Result<()> {
    // Plan B T2.1: a provider that holds a root set also lists its roots on
    // this local-plane status; an older provider does not.
    const FIELDS: [&str; 6] = [
        "provider",
        "version",
        "configured",
        "supported_operations",
        "request_schema",
        "response_schema",
    ];
    let lists_roots = status
        .get("data")
        .and_then(Value::as_object)
        .is_some_and(|data| data.contains_key("roots"));
    let with_roots: Vec<&str> = FIELDS.iter().copied().chain(["roots"]).collect();
    let data = require_exact_provider_status_data(
        status,
        "inactive custody provider",
        if lists_roots {
            &with_roots[..]
        } else {
            &FIELDS[..]
        },
    )?;
    if lists_roots {
        require_custody_root_statuses(data.get("roots"))?;
    }
    if data.get("provider").and_then(Value::as_str) != Some(CUSTODY_PROVIDER_ID) {
        anyhow::bail!("inactive custody provider status has an unsupported identity");
    }
    if data.get("configured").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("inactive custody provider is not configured");
    }
    if data.get("request_schema").and_then(Value::as_str)
        != Some(CUSTODY_PROVIDER_REQUEST_SCHEMA_V1)
        || data.get("response_schema").and_then(Value::as_str)
            != Some(CUSTODY_PROVIDER_RESPONSE_SCHEMA_V1)
    {
        anyhow::bail!("inactive custody provider status has unsupported protocol schemas");
    }
    require_exact_provider_operations(
        data,
        CUSTODY_PROVIDER_OPERATIONS,
        "inactive custody provider",
    )
}

/// Each entry is exactly `{path, node_public_key, configured, shares_held}`.
fn require_custody_root_statuses(roots: Option<&Value>) -> anyhow::Result<()> {
    let roots = roots
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("inactive custody provider root list is invalid"))?;
    for root in roots {
        let valid = root.as_object().is_some_and(|root| {
            root.len() == 4
                && root
                    .get("path")
                    .is_some_and(|path| path.is_null() || path.is_string())
                && root
                    .get("node_public_key")
                    .is_some_and(|key| key.is_null() || key.is_string())
                && root.get("configured").is_some_and(Value::is_boolean)
                && root
                    .get("shares_held")
                    .is_some_and(|held| held.is_null() || held.is_u64())
        });
        if !valid {
            anyhow::bail!("inactive custody provider root list is invalid");
        }
    }
    Ok(())
}

fn require_protected_content_decrypt_provider_status(status: &Value) -> anyhow::Result<()> {
    let data = require_exact_provider_status_data(
        status,
        "protected-content decrypt provider",
        &[
            "provider",
            "version",
            "configured",
            "supported_operations",
            "request_schema",
            "response_schema",
        ],
    )?;
    if data.get("provider").and_then(Value::as_str) != Some(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID) {
        anyhow::bail!("protected-content decrypt provider status has an unsupported identity");
    }
    if data.get("configured").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("protected-content decrypt provider is not configured");
    }
    if data.get("request_schema").and_then(Value::as_str)
        != Some(DECRYPT_PROVIDER_REQUEST_SCHEMA_V1)
        || data.get("response_schema").and_then(Value::as_str)
            != Some(DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1)
    {
        anyhow::bail!("protected-content decrypt provider status has unsupported protocol schemas");
    }
    require_exact_provider_operations(
        data,
        PROTECTED_CONTENT_DECRYPT_PROVIDER_OPERATIONS,
        "protected-content decrypt provider",
    )
}

fn require_exact_provider_status_data<'a>(
    status: &'a Value,
    label: &str,
    expected_fields: &[&str],
) -> anyhow::Result<&'a serde_json::Map<String, Value>> {
    let status_object = status
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("{label} status is invalid"))?;
    if status_object.len() != 2
        || !status_object.contains_key("status")
        || !status_object.contains_key("data")
        || status.get("status").and_then(Value::as_str) != Some("ok")
    {
        anyhow::bail!("{label} status did not succeed");
    }
    let data = status
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("{label} status is missing data"))?;
    if data.len() != expected_fields.len()
        || expected_fields
            .iter()
            .any(|field| !data.contains_key(*field))
    {
        anyhow::bail!("{label} status has an unsupported shape");
    }
    // Release versions identify builds; protocol versions and schemas define compatibility.
    if data
        .get("version")
        .and_then(Value::as_str)
        .and_then(|version| semver::Version::parse(version).ok())
        .is_none()
    {
        anyhow::bail!("{label} status has an invalid release version");
    }
    Ok(data)
}

fn require_exact_provider_operations(
    data: &serde_json::Map<String, Value>,
    expected: &[&str],
    label: &str,
) -> anyhow::Result<()> {
    let supported_operations = data
        .get("supported_operations")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("{label} status is missing supported operations"))?;
    if supported_operations.len() != expected.len()
        || supported_operations
            .iter()
            .zip(expected)
            .any(|(actual, expected)| actual.as_str() != Some(*expected))
    {
        anyhow::bail!("{label} status has unsupported operations");
    }
    Ok(())
}

async fn register_custody_runtime_provider_target(
    registry: &ProviderRegistry,
    provider: Arc<dyn Provider>,
) -> Result<(), ProviderError> {
    registry
        .register_runtime_provider_target(CUSTODY_PROVIDER_ID, provider)
        .await
}

/// Derive the Runtime operation issuer custody and decrypt providers must
/// trust for the Runtime rooted at this device key.
pub fn derive_protected_content_runtime_issuer(
    device_key: &[u8; 32],
) -> anyhow::Result<RuntimeOperationIssuerKeyV1> {
    let (runtime_signing_key, _) = elastos_identity::derive_did(device_key);
    RuntimeOperationIssuerKeyV1::new(runtime_signing_key.verifying_key().to_bytes())
        .map_err(|_| anyhow::anyhow!("active Runtime operation issuer is invalid"))
}

/// The Runtime operation issuer this host's Chain plane checks release
/// operations against. A custody node settles releases for the one Runtime
/// its custody state was provisioned to trust, never for this host's own
/// device key; a host without custody state is its own Runtime.
pub fn chain_plane_runtime_issuer(data_dir: &Path) -> anyhow::Result<RuntimeOperationIssuerKeyV1> {
    let custody_state_root = inactive_custody_state_root(data_dir);
    if custody_state_root.is_dir() {
        return custody_provider::load_trusted_runtime_issuer(&custody_state_root).map_err(
            |error| {
                anyhow::anyhow!(
                    "provisioned custody state names no readable trusted Runtime issuer: {error:?}"
                )
            },
        );
    }
    let device_key = elastos_identity::load_or_create_device_key(data_dir)
        .map_err(|_| anyhow::anyhow!("chain-provider host identity is unavailable"))?;
    derive_protected_content_runtime_issuer(&device_key)
}

/// The provisioned state root an inactive custody provider is hosted from.
///
/// `elastos protected-content-config provision-custody-node` creates it; a
/// custody host reads it to fail closed before spawning anything.
pub fn inactive_custody_state_root(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(INACTIVE_CUSTODY_ROOT)
}

pub(crate) fn protected_content_root(data_dir: &Path) -> PathBuf {
    data_dir.join(PROTECTED_CONTENT_ROOT)
}

pub(crate) fn runtime_custody_composition_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CUSTODY_COMPOSITION_CONFIG_FILE)
}

fn validate_custody_state_root(root: &Path) -> anyhow::Result<()> {
    validate_owner_only_directory(root, "inactive custody provider root")
}

fn invalid_custody_config(reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("inactive custody provider configuration is missing or unsafe: {reason}")
}

pub(crate) fn validate_owner_only_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        let _ = error;
        invalid_custody_config(format!("{label} is unavailable"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "{}",
            invalid_custody_config(format!("{label} must be an owner-only directory"))
        );
    }
    validate_owner_only_metadata_with_error(label, &metadata, false, invalid_custody_config)
}

fn validate_owner_only_directory_with_error(
    path: &Path,
    label: &str,
    error_fn: fn(String) -> anyhow::Error,
) -> anyhow::Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| error_fn(format!("{label} is unavailable")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(error_fn(format!("{label} must be an owner-only directory")));
    }
    validate_owner_only_metadata_with_error(label, &metadata, false, error_fn)
}

#[cfg(unix)]
fn validate_owner_only_metadata_with_error(
    label: &str,
    metadata: &fs::Metadata,
    require_single_link: bool,
    error_fn: fn(String) -> anyhow::Error,
) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mode = metadata.permissions().mode() & 0o777;
    let expected_mask = if metadata.is_dir() { 0o700 } else { 0o600 };
    if metadata.uid() != unsafe { libc::geteuid() } || mode & 0o077 != 0 {
        anyhow::bail!("{}", error_fn(format!("{label} must be owner-only")));
    }
    if require_single_link && metadata.nlink() != 1 {
        anyhow::bail!("{}", error_fn(format!("{label} must not be hard-linked")));
    }
    if mode == 0 {
        anyhow::bail!("{}", error_fn(format!("{label} must not be inaccessible")));
    }
    if mode & expected_mask != mode {
        anyhow::bail!(
            "{}",
            error_fn(format!("{label} has an unsupported owner mode"))
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_only_metadata_with_error(
    _label: &str,
    _metadata: &fs::Metadata,
    _require_single_link: bool,
    _error_fn: fn(String) -> anyhow::Error,
) -> anyhow::Result<()> {
    anyhow::bail!("owner-only protected-content config validation is unsupported on this platform")
}

fn invalid_custody_composition_config(reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("protected-content custody composition config is missing or unsafe: {reason}")
}

fn invalid_chain_provider_config(reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("protected-content Chain provider config is missing or unsafe: {reason}")
}

fn validate_owner_only_protected_content_dir(data_dir: &Path) -> anyhow::Result<PathBuf> {
    validate_owner_only_protected_content_dir_with_error(
        data_dir,
        invalid_custody_composition_config,
    )
}

fn validate_owner_only_protected_content_dir_with_error(
    data_dir: &Path,
    error_fn: fn(String) -> anyhow::Error,
) -> anyhow::Result<PathBuf> {
    let root = protected_content_root(data_dir);
    let metadata = fs::symlink_metadata(&root)
        .map_err(|_| error_fn("protected-content parent is unavailable".to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "{}",
            error_fn("protected-content parent must be an owner-only directory".to_string())
        );
    }
    validate_owner_only_metadata_with_error(
        "protected-content parent",
        &metadata,
        false,
        error_fn,
    )?;
    Ok(root)
}

fn runtime_chain_provider_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CHAIN_PROVIDER_CONFIG_FILE)
}

pub fn load_runtime_protected_content_chain_provider_config(
    data_dir: &Path,
) -> anyhow::Result<Option<RuntimeProtectedContentChainProviderConfig>> {
    let config_path = runtime_chain_provider_config_path(data_dir);
    match fs::symlink_metadata(&config_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            anyhow::bail!(
                "{}",
                invalid_chain_provider_config("config file is unavailable")
            )
        }
    }
    validate_owner_only_protected_content_dir_with_error(data_dir, invalid_chain_provider_config)?;
    let bytes = read_owner_only_protected_content_config_bytes(
        &config_path,
        MAX_CHAIN_PROVIDER_CONFIG_BYTES,
        "Chain provider config file",
        invalid_chain_provider_config,
    )?;
    let config: RuntimeProtectedContentChainProviderConfigFile = serde_json::from_slice(&bytes)
        .map_err(|_| invalid_chain_provider_config("config JSON is invalid"))?;
    if config.schema != PROTECTED_CONTENT_CHAIN_PROVIDER_CONFIG_SCHEMA_V1
        || !config.protected_content_network.is_object()
    {
        anyhow::bail!(
            "{}",
            invalid_chain_provider_config("config fields are invalid")
        );
    }
    Ok(Some(RuntimeProtectedContentChainProviderConfig {
        protected_content_network: config.protected_content_network,
    }))
}

fn invalid_media_provider_config(reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("media-provider private config is missing or unsafe: {reason}")
}

fn runtime_media_provider_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(MEDIA_PROVIDER_CONFIG_FILE)
}

fn runtime_media_provider_root(data_dir: &Path) -> PathBuf {
    runtime_media_provider_config_path(data_dir)
        .parent()
        .expect("media-provider config has a parent")
        .to_path_buf()
}

fn runtime_media_provider_tools_root(data_dir: &Path) -> PathBuf {
    runtime_media_provider_root(data_dir).join("tools")
}

fn runtime_media_provider_staging_root(data_dir: &Path) -> PathBuf {
    runtime_media_provider_root(data_dir).join("staging")
}

pub fn load_runtime_media_provider_bridge_config(
    data_dir: &Path,
) -> anyhow::Result<Option<ProviderConfig>> {
    let config_path = runtime_media_provider_config_path(data_dir);
    match fs::symlink_metadata(&config_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid_media_provider_config("config file is unavailable")),
    }
    validate_owner_only_protected_content_dir_with_error(data_dir, invalid_media_provider_config)?;
    validate_owner_only_directory_with_error(
        &runtime_media_provider_root(data_dir),
        "media-provider root",
        invalid_media_provider_config,
    )?;
    validate_owner_only_directory_with_error(
        &runtime_media_provider_tools_root(data_dir),
        "media-provider tools root",
        invalid_media_provider_config,
    )?;
    validate_owner_only_directory_with_error(
        &runtime_media_provider_staging_root(data_dir),
        "media-provider staging root",
        invalid_media_provider_config,
    )?;
    let bytes = read_owner_only_protected_content_config_bytes(
        &config_path,
        MAX_MEDIA_PROVIDER_CONFIG_BYTES,
        "media-provider config file",
        invalid_media_provider_config,
    )?;
    let raw: RuntimeMediaProviderConfigFile = serde_json::from_slice(&bytes)
        .map_err(|_| invalid_media_provider_config("config JSON is invalid"))?;
    let canonical_root = fs::canonicalize(runtime_media_provider_root(data_dir))
        .map_err(|_| invalid_media_provider_config("provider root is unavailable"))?;
    let expected_tools = canonical_root.join("tools");
    let expected_staging = canonical_root.join("staging");
    let expected_ffmpeg = expected_tools.join("ffmpeg");
    let expected_ffprobe = expected_tools.join("ffprobe");
    if raw.schema != MEDIA_PROVIDER_CONFIG_SCHEMA_V1
        || raw.output_profile != MEDIA_PROVIDER_OUTPUT_PROFILE_V1
        || Path::new(&raw.staging_root) != expected_staging
        || Path::new(&raw.ffmpeg_path) != expected_ffmpeg
        || Path::new(&raw.ffprobe_path) != expected_ffprobe
        || raw.timeout_ms == 0
        || raw.timeout_ms > MEDIA_PROVIDER_TIMEOUT_MS_V1
        || raw.max_stdio_bytes == 0
        || raw.max_stdio_bytes > MEDIA_PROVIDER_MAX_STDIO_BYTES_V1
        || raw.max_input_bytes == 0
        || raw.max_input_bytes > MEDIA_PROVIDER_MAX_INPUT_BYTES_V1
        || raw.max_output_part_bytes == 0
        || raw.max_output_part_bytes > MEDIA_PROVIDER_MAX_OUTPUT_PART_BYTES_V1
        || raw.max_duration_secs == 0
        || raw.max_duration_secs > MEDIA_PROVIDER_MAX_DURATION_SECS_V1
        || raw.max_source_width == 0
        || raw.max_source_width > MEDIA_PROVIDER_MAX_SOURCE_WIDTH_V1
        || raw.max_source_height == 0
        || raw.max_source_height > MEDIA_PROVIDER_MAX_SOURCE_HEIGHT_V1
        || raw.max_source_fps == 0
        || raw.max_source_fps > MEDIA_PROVIDER_MAX_SOURCE_FPS_V1
        || raw.max_segment_count == 0
        || raw.max_segment_count > MEDIA_PROVIDER_MAX_SEGMENT_COUNT_V1
        || raw.max_total_output_bytes == 0
        || raw.max_total_output_bytes > MEDIA_PROVIDER_MAX_TOTAL_OUTPUT_BYTES_V1
        || raw.max_total_output_bytes < raw.max_output_part_bytes
    {
        return Err(invalid_media_provider_config("config fields are invalid"));
    }
    validate_runtime_media_import(&expected_ffmpeg, &expected_tools, "ffmpeg")?;
    validate_runtime_media_import(&expected_ffprobe, &expected_tools, "ffprobe")?;
    Ok(Some(ProviderConfig {
        extra: json!({
            "provider_id": MEDIA_PROVIDER_PROCESS_ID,
            "staging_root": raw.staging_root,
            "ffmpeg_path": raw.ffmpeg_path,
            "ffprobe_path": raw.ffprobe_path,
            "output_profile": raw.output_profile,
            "timeout_ms": raw.timeout_ms,
            "max_stdio_bytes": raw.max_stdio_bytes,
            "max_input_bytes": raw.max_input_bytes,
            "max_output_part_bytes": raw.max_output_part_bytes,
            "max_duration_secs": raw.max_duration_secs,
            "max_source_width": raw.max_source_width,
            "max_source_height": raw.max_source_height,
            "max_source_fps": raw.max_source_fps,
            "max_segment_count": raw.max_segment_count,
            "max_total_output_bytes": raw.max_total_output_bytes,
        }),
        ..Default::default()
    }))
}

/// SHA-256 digests of ffmpeg and ffprobe read from a media-tools archive whose
/// checksum was just verified against the installed signed release manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SignedMediaToolDigests {
    pub(crate) ffmpeg: [u8; 32],
    pub(crate) ffprobe: [u8; 32],
}

/// How a supplied pair may relate to an existing private import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MediaToolsTrust {
    /// The supplied pair must equal the private import byte for byte.
    MustMatch,
    /// A differing private import is replaced, but only with bytes that hash to
    /// the signed release's digests.
    SignedRelease(SignedMediaToolDigests),
}

/// Whether a private import exists and either tool differs from the supplied pair.
pub(crate) fn runtime_media_import_differs(
    data_dir: &Path,
    tools_dir: &Path,
) -> anyhow::Result<bool> {
    if load_runtime_media_provider_bridge_config(data_dir)?.is_none() {
        return Ok(false);
    }
    let mut ffmpeg = open_runtime_media_tool(tools_dir, "ffmpeg")?;
    let mut ffprobe = open_runtime_media_tool(tools_dir, "ffprobe")?;
    let tools = runtime_media_provider_tools_root(data_dir);
    Ok(
        !runtime_media_tool_matches(&mut ffmpeg, &tools.join("ffmpeg"), "ffmpeg")?
            || !runtime_media_tool_matches(&mut ffprobe, &tools.join("ffprobe"), "ffprobe")?,
    )
}

pub(crate) fn prepare_runtime_media_provider_prerequisite(
    data_dir: &Path,
    tools_dir: &Path,
    trust: MediaToolsTrust,
) -> anyhow::Result<()> {
    // Open the complete supplied pair before creating or changing private state.
    let mut ffmpeg = open_runtime_media_tool(tools_dir, "ffmpeg")?;
    let mut ffprobe = open_runtime_media_tool(tools_dir, "ffprobe")?;
    match fs::symlink_metadata(runtime_media_provider_config_path(data_dir)) {
        Ok(_) => {
            load_runtime_media_provider_bridge_config(data_dir)?.ok_or_else(|| {
                invalid_media_provider_config("config file disappeared during validation")
            })?;
            let tools = runtime_media_provider_tools_root(data_dir);
            if runtime_media_tool_matches(&mut ffmpeg, &tools.join("ffmpeg"), "ffmpeg")?
                && runtime_media_tool_matches(&mut ffprobe, &tools.join("ffprobe"), "ffprobe")?
            {
                return Ok(());
            }
            let MediaToolsTrust::SignedRelease(digests) = trust else {
                return Err(invalid_media_provider_config(
                    "supplied media tools differ from the private imported pair",
                ));
            };
            // The config stores only private paths and operator-tuned limits, so a
            // release upgrade replaces the imported bytes and leaves the config alone.
            #[cfg(unix)]
            {
                let canonical_tools = fs::canonicalize(&tools)
                    .map_err(|_| invalid_media_provider_config("tools root is unavailable"))?;
                replace_runtime_media_pair(
                    &canonical_tools,
                    [
                        ("ffmpeg", &mut ffmpeg, &digests.ffmpeg),
                        ("ffprobe", &mut ffprobe, &digests.ffprobe),
                    ],
                )?;
                load_runtime_media_provider_bridge_config(data_dir)?.ok_or_else(|| {
                    invalid_media_provider_config("config file disappeared after upgrade")
                })?;
            }
            #[cfg(not(unix))]
            let _ = digests;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(invalid_media_provider_config("config file is unavailable")),
    }
    #[cfg(unix)]
    {
        ensure_media_provider_directory(data_dir, "Runtime data root")?;
        ensure_media_provider_directory(
            &protected_content_root(data_dir),
            "protected-content parent",
        )?;
        ensure_media_provider_directory(
            &runtime_media_provider_root(data_dir),
            "media-provider root",
        )?;
        let tools_root = runtime_media_provider_tools_root(data_dir);
        ensure_media_provider_directory(&tools_root, "media-provider tools root")?;
        let staging_root = runtime_media_provider_staging_root(data_dir);
        ensure_media_provider_directory(&staging_root, "media-provider staging root")?;

        let canonical_root = fs::canonicalize(runtime_media_provider_root(data_dir))
            .map_err(|_| invalid_media_provider_config("provider root is unavailable"))?;
        let canonical_tools = fs::canonicalize(&tools_root)
            .map_err(|_| invalid_media_provider_config("tools root is unavailable"))?;
        let canonical_staging = fs::canonicalize(&staging_root)
            .map_err(|_| invalid_media_provider_config("staging root is unavailable"))?;
        if canonical_tools != canonical_root.join("tools")
            || canonical_staging != canonical_root.join("staging")
        {
            return Err(invalid_media_provider_config(
                "private paths escape the provider root",
            ));
        }

        let config_path = runtime_media_provider_config_path(data_dir);
        let mut created_tools = Vec::new();
        let mut config_created = false;
        let result = (|| -> anyhow::Result<()> {
            let ffmpeg_import = import_runtime_media_tool(&canonical_tools, "ffmpeg", &mut ffmpeg)?;
            if ffmpeg_import.created {
                created_tools.push(ffmpeg_import.path.clone());
            }
            let ffprobe_import =
                import_runtime_media_tool(&canonical_tools, "ffprobe", &mut ffprobe)?;
            if ffprobe_import.created {
                created_tools.push(ffprobe_import.path.clone());
            }
            let config = RuntimeMediaProviderConfigFile {
                schema: MEDIA_PROVIDER_CONFIG_SCHEMA_V1.to_string(),
                ffmpeg_path: media_path_string(&ffmpeg_import.path, "ffmpeg")?,
                ffprobe_path: media_path_string(&ffprobe_import.path, "ffprobe")?,
                staging_root: media_path_string(&canonical_staging, "staging")?,
                output_profile: MEDIA_PROVIDER_OUTPUT_PROFILE_V1.to_string(),
                timeout_ms: MEDIA_PROVIDER_TIMEOUT_MS_V1,
                max_stdio_bytes: MEDIA_PROVIDER_MAX_STDIO_BYTES_V1,
                max_input_bytes: MEDIA_PROVIDER_MAX_INPUT_BYTES_V1,
                max_output_part_bytes: MEDIA_PROVIDER_MAX_OUTPUT_PART_BYTES_V1,
                max_duration_secs: MEDIA_PROVIDER_MAX_DURATION_SECS_V1,
                max_source_width: MEDIA_PROVIDER_MAX_SOURCE_WIDTH_V1,
                max_source_height: MEDIA_PROVIDER_MAX_SOURCE_HEIGHT_V1,
                max_source_fps: MEDIA_PROVIDER_MAX_SOURCE_FPS_V1,
                max_segment_count: MEDIA_PROVIDER_MAX_SEGMENT_COUNT_V1,
                max_total_output_bytes: MEDIA_PROVIDER_MAX_TOTAL_OUTPUT_BYTES_V1,
            };
            let mut bytes = serde_json::to_vec_pretty(&config)?;
            bytes.push(b'\n');
            create_private_file_atomically(&config_path, &bytes, 0o600, "config")?;
            config_created = true;
            load_runtime_media_provider_bridge_config(data_dir)?.ok_or_else(|| {
                invalid_media_provider_config("config file disappeared after setup")
            })?;
            Ok(())
        })();
        if result.is_err() {
            if config_created {
                let _ = fs::remove_file(&config_path);
            }
            for path in created_tools {
                let _ = fs::remove_file(path);
            }
            let _ = sync_runtime_storage_parent(&canonical_tools);
            let _ = sync_runtime_storage_parent(&canonical_root);
        }
        result
    }
    #[cfg(not(unix))]
    {
        let _ = (data_dir, ffmpeg, ffprobe);
        anyhow::bail!(
            "owner-only media-provider prerequisite setup is unsupported on this platform"
        )
    }
}

fn media_path_string(path: &Path, label: &str) -> anyhow::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid_media_provider_config(format!("{label} path is not valid UTF-8")))
}

#[cfg(unix)]
pub(crate) fn ensure_media_provider_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_owner_only_directory_with_error(path, label, invalid_media_provider_config)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent).map_err(|_| {
                        invalid_media_provider_config(format!(
                            "{label} parent could not be created"
                        ))
                    })?;
                }
            }
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).create(path).map_err(|_| {
                invalid_media_provider_config(format!("{label} could not be created"))
            })?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            validate_owner_only_directory_with_error(path, label, invalid_media_provider_config)
        }
        Err(_) => Err(invalid_media_provider_config(format!(
            "{label} is unavailable"
        ))),
    }
}

#[cfg(unix)]
fn open_runtime_media_tool(tools_dir: &Path, name: &str) -> anyhow::Result<RuntimeMediaToolSource> {
    let candidate = tools_dir.join(name);
    let literal = if candidate.is_absolute() {
        candidate.clone()
    } else {
        std::env::current_dir()
            .map_err(|_| {
                invalid_media_provider_config(format!("{name} prerequisite is unavailable"))
            })?
            .join(&candidate)
    };
    let file = open_media_source_no_links(&literal, name)?;
    let metadata = file.metadata().map_err(|_| {
        invalid_media_provider_config(format!("{name} prerequisite metadata is unavailable"))
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || (metadata.uid() != 0 && metadata.uid() != uid)
        || mode & 0o022 != 0
        || mode & 0o111 == 0
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_MEDIA_PROVIDER_IMPORTED_TOOL_BYTES
    {
        return Err(invalid_media_provider_config(format!(
            "{name} prerequisite is unsafe or exceeds bounds"
        )));
    }
    Ok(RuntimeMediaToolSource {
        file,
        size: metadata.len(),
    })
}

#[cfg(not(unix))]
fn open_runtime_media_tool(
    _tools_dir: &Path,
    _name: &str,
) -> anyhow::Result<RuntimeMediaToolSource> {
    anyhow::bail!("owner-only media-provider prerequisite setup is unsupported on this platform")
}

/// Open an absolute source path one directory at a time with `openat` and
/// `O_NOFOLLOW`, so no link anywhere on the path is followed and every checked
/// directory is the one the next step opens from. Callers that need a system link
/// in their own root (macOS /var) canonicalize that root first.
#[cfg(unix)]
fn open_media_source_no_links(literal: &Path, name: &str) -> anyhow::Result<fs::File> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Component;

    let uid = unsafe { libc::geteuid() };
    let open_at = |dir: &fs::File, part: &std::ffi::OsStr, flags: libc::c_int| {
        let part = std::ffi::CString::new(part.as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                part.as_ptr(),
                flags | libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    };
    let check_dir = |dir: &fs::File, display: &Path| -> anyhow::Result<()> {
        let metadata = dir.metadata().map_err(|_| {
            invalid_media_provider_config(format!("{name} prerequisite parent is unavailable"))
        })?;
        if metadata.uid() != 0 && metadata.uid() != uid {
            return Err(invalid_media_provider_config(format!(
                "{name} prerequisite parent is unsafe: {} is not owned by you or root. Choose a user-owned location with safe parents",
                display.display()
            )));
        }
        if metadata.permissions().mode() & 0o002 != 0 {
            return Err(invalid_media_provider_config(format!(
                "{name} prerequisite parent is unsafe: {} is world-writable. Choose a user-owned location with safe parents",
                display.display()
            )));
        }
        Ok(())
    };

    let parts: Vec<Component> = literal.components().collect();
    let Some((Component::Normal(file_name), dirs)) = parts.split_last() else {
        return Err(invalid_media_provider_config(format!(
            "{name} prerequisite path is invalid"
        )));
    };
    let mut display = PathBuf::from("/");
    let mut dir = fs::File::open("/").map_err(|_| {
        invalid_media_provider_config(format!("{name} prerequisite parent is unavailable"))
    })?;
    check_dir(&dir, &display)?;
    for part in dirs {
        let step = match part {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => continue,
            Component::ParentDir => {
                display.pop();
                std::ffi::OsStr::new("..")
            }
            Component::Normal(part) => {
                display.push(part);
                part
            }
        };
        dir = open_at(&dir, step, libc::O_DIRECTORY).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                invalid_media_provider_config(format!("media-provider prerequisite '{name}' was not found in the supplied tools directory"))
            } else {
                invalid_media_provider_config(format!(
                    "{name} prerequisite parent is unsafe: {} is a symbolic link or not a real directory",
                    display.display()
                ))
            }
        })?;
        check_dir(&dir, &display)?;
    }
    open_at(&dir, file_name, 0).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            invalid_media_provider_config(format!(
                "media-provider prerequisite '{name}' was not found in the supplied tools directory"
            ))
        } else if error.raw_os_error() == Some(libc::ELOOP) {
            invalid_media_provider_config(format!("{name} prerequisite is a symbolic link"))
        } else {
            invalid_media_provider_config(format!("{name} prerequisite is unavailable"))
        }
    })
}

#[cfg(unix)]
fn validate_runtime_media_import(path: &Path, tools_root: &Path, name: &str) -> anyhow::Result<()> {
    let canonical = fs::canonicalize(path)
        .map_err(|_| invalid_media_provider_config(format!("{name} import is unavailable")))?;
    if canonical != path || canonical.parent() != Some(tools_root) {
        return Err(invalid_media_provider_config(format!(
            "{name} import escapes the tools root"
        )));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| invalid_media_provider_config(format!("{name} import is unavailable")))?;
    let mode = metadata.permissions().mode() & 0o777;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || mode != 0o500
        || metadata.len() == 0
        || metadata.len() > MAX_MEDIA_PROVIDER_IMPORTED_TOOL_BYTES
    {
        return Err(invalid_media_provider_config(format!(
            "{name} import is unsafe"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_runtime_media_import(
    _path: &Path,
    _tools_root: &Path,
    _name: &str,
) -> anyhow::Result<()> {
    anyhow::bail!("owner-only media-provider config validation is unsupported on this platform")
}

#[cfg(unix)]
fn import_runtime_media_tool(
    tools_root: &Path,
    name: &str,
    source: &mut RuntimeMediaToolSource,
) -> anyhow::Result<RuntimeMediaToolImport> {
    let destination = tools_root.join(name);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            validate_runtime_media_import(&destination, tools_root, name)?;
            if !runtime_media_tool_matches(source, &destination, name)? {
                return Err(invalid_media_provider_config(format!(
                    "{name} import conflicts with the discovered prerequisite"
                )));
            }
            return Ok(RuntimeMediaToolImport {
                path: destination,
                created: false,
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(invalid_media_provider_config(format!(
                "{name} import is unavailable"
            )))
        }
    }

    let temp_path = stage_runtime_media_tool(tools_root, name, source)?;
    let mut published = false;
    let result = (|| -> anyhow::Result<()> {
        fs::hard_link(&temp_path, &destination).map_err(|_| {
            invalid_media_provider_config(format!(
                "{name} import could not be installed atomically"
            ))
        })?;
        published = true;
        fs::remove_file(&temp_path)?;
        sync_runtime_storage_parent(tools_root)?;
        validate_runtime_media_import(&destination, tools_root, name)
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temp_path);
        if published {
            let _ = fs::remove_file(&destination);
        }
        return Err(error);
    }
    Ok(RuntimeMediaToolImport {
        path: destination,
        created: true,
    })
}

/// Copy the supplied tool into an fsynced owner-only temporary file beside its destination.
#[cfg(unix)]
fn stage_runtime_media_tool(
    tools_root: &Path,
    name: &str,
    source: &mut RuntimeMediaToolSource,
) -> anyhow::Result<PathBuf> {
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let temp_path = tools_root.join(format!(".{name}.tmp-{}", hex::encode(nonce)));
    let mut options = fs::OpenOptions::new();
    options
        .create_new(true)
        .write(true)
        .mode(0o500)
        .custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&temp_path).map_err(|_| {
        invalid_media_provider_config(format!("{name} temporary import could not be created"))
    })?;
    let result = (|| -> anyhow::Result<()> {
        source.file.seek(SeekFrom::Start(0))?;
        let copied = std::io::copy(
            &mut std::io::Read::by_ref(&mut source.file)
                .take(MAX_MEDIA_PROVIDER_IMPORTED_TOOL_BYTES + 1),
            &mut file,
        )?;
        if copied != source.size {
            return Err(invalid_media_provider_config(format!(
                "{name} prerequisite changed during import"
            )));
        }
        file.sync_all()?;
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o500))?;
        Ok(())
    })();
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }
    Ok(temp_path)
}

/// Replace the private pair with the signed release's tools. Every staged copy is
/// hashed against the signed digest before any rename, so altered bytes publish
/// nothing. A tool whose private copy already has the signed digest is kept, which
/// also repairs a pair left half-replaced by an interrupted run. Each previous
/// import stays in place until its rename publishes the new bytes.
#[cfg(unix)]
fn replace_runtime_media_pair(
    tools_root: &Path,
    pair: [(&str, &mut RuntimeMediaToolSource, &[u8; 32]); 2],
) -> anyhow::Result<()> {
    let mut staged = Vec::with_capacity(pair.len());
    let result = (|| -> anyhow::Result<()> {
        for (name, source, expected) in pair {
            let destination = tools_root.join(name);
            validate_runtime_media_import(&destination, tools_root, name)?;
            if runtime_media_file_sha256(&destination, name)? == *expected {
                continue;
            }
            let temp_path = stage_runtime_media_tool(tools_root, name, source)?;
            staged.push((name, temp_path.clone(), destination));
            if runtime_media_file_sha256(&temp_path, name)? != *expected {
                return Err(invalid_media_provider_config(format!(
                    "{name} does not match the signed release media tools"
                )));
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        for (_, temp_path, _) in staged {
            let _ = fs::remove_file(temp_path);
        }
        return Err(error);
    }
    for (name, temp_path, destination) in staged {
        if fs::rename(&temp_path, &destination).is_err() {
            let _ = fs::remove_file(&temp_path);
            return Err(invalid_media_provider_config(format!(
                "{name} import could not be replaced atomically"
            )));
        }
        sync_runtime_storage_parent(tools_root)?;
        validate_runtime_media_import(&destination, tools_root, name)?;
    }
    Ok(())
}

#[cfg(unix)]
fn runtime_media_file_sha256(path: &Path, name: &str) -> anyhow::Result<[u8; 32]> {
    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|_| invalid_media_provider_config(format!("{name} import is unavailable")))?;
    let mut hasher = sha2::Sha256::new();
    std::io::copy(
        &mut file.take(MAX_MEDIA_PROVIDER_IMPORTED_TOOL_BYTES + 1),
        &mut hasher,
    )?;
    Ok(hasher.finalize().into())
}

#[cfg(unix)]
fn runtime_media_tool_matches(
    source: &mut RuntimeMediaToolSource,
    destination: &Path,
    name: &str,
) -> anyhow::Result<bool> {
    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let mut imported = options
        .open(destination)
        .map_err(|_| invalid_media_provider_config(format!("{name} import is unavailable")))?;
    if imported.metadata()?.len() != source.size {
        return Ok(false);
    }
    source.file.seek(SeekFrom::Start(0))?;
    let mut source_reader = std::io::Read::by_ref(&mut source.file).take(source.size + 1);
    let mut imported_reader = std::io::Read::by_ref(&mut imported).take(source.size + 1);
    let mut source_buffer = [0u8; 64 * 1024];
    let mut imported_buffer = [0u8; 64 * 1024];
    loop {
        let source_read = source_reader.read(&mut source_buffer)?;
        let imported_read = imported_reader.read(&mut imported_buffer)?;
        if source_read != imported_read
            || source_buffer[..source_read] != imported_buffer[..imported_read]
        {
            return Ok(false);
        }
        if source_read == 0 {
            return Ok(true);
        }
    }
}

#[cfg(unix)]
fn create_private_file_atomically(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    label: &str,
) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_media_provider_config(format!("{label} parent is unavailable")))?;
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let temp_path = parent.join(format!(".{label}.tmp-{}", hex::encode(nonce)));
    let mut options = fs::OpenOptions::new();
    options
        .create_new(true)
        .write(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&temp_path).map_err(|_| {
        invalid_media_provider_config(format!("{label} temporary file could not be created"))
    })?;
    let mut published = false;
    let result = (|| -> anyhow::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&temp_path, path)
            .map_err(|_| invalid_media_provider_config(format!("{label} appeared during setup")))?;
        published = true;
        fs::remove_file(&temp_path)?;
        sync_runtime_storage_parent(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
        if published {
            let _ = fs::remove_file(path);
        }
    }
    result
}

#[cfg(unix)]
fn read_owner_only_config_bytes(path: &Path, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
    read_owner_only_protected_content_config_bytes(
        path,
        max_bytes,
        "custody-composition file",
        invalid_custody_composition_config,
    )
}

#[cfg(unix)]
fn read_owner_only_protected_content_config_bytes(
    path: &Path,
    max_bytes: usize,
    label: &str,
    error_fn: fn(String) -> anyhow::Error,
) -> anyhow::Result<Vec<u8>> {
    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|_| error_fn(format!("{label} is unavailable")))?;
    let metadata = file
        .metadata()
        .map_err(|_| error_fn(format!("{label} metadata is unavailable")))?;
    if !metadata.is_file() {
        anyhow::bail!("{}", error_fn(format!("{label} must be a regular file")));
    }
    validate_owner_only_metadata_with_error(label, &metadata, true, error_fn)?;
    let mut bytes = Vec::with_capacity(max_bytes.min(4096));
    std::io::Read::by_ref(&mut file)
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        anyhow::bail!("{}", error_fn(format!("{label} exceeds bounds")));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_owner_only_config_bytes(path: &Path, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
    let _ = (path, max_bytes);
    anyhow::bail!("owner-only protected-content config validation is unsupported on this platform")
}

#[cfg(not(unix))]
fn read_owner_only_protected_content_config_bytes(
    path: &Path,
    max_bytes: usize,
    label: &str,
    error_fn: fn(String) -> anyhow::Error,
) -> anyhow::Result<Vec<u8>> {
    let _ = (path, max_bytes, label, error_fn);
    anyhow::bail!("owner-only protected-content config validation is unsupported on this platform")
}

fn canonical_custody_composition_config_bytes(
    config: &RuntimeCustodyCompositionConfigFile,
) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::to_value(config)?)?)
}

fn decode_canonical_base64_bytes(
    encoded: &str,
    max_decoded_bytes: usize,
    field: &str,
) -> anyhow::Result<Vec<u8>> {
    let max_encoded_bytes = max_decoded_bytes.div_ceil(3) * 4;
    if encoded.is_empty() || encoded.len() > max_encoded_bytes {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config(format!("{field} base64 has invalid length"))
        );
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| invalid_custody_composition_config(format!("{field} base64 is invalid")))?;
    if decoded.is_empty()
        || decoded.len() > max_decoded_bytes
        || base64::engine::general_purpose::STANDARD.encode(&decoded) != encoded
    {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config(format!("{field} base64 is not canonical"))
        );
    }
    Ok(decoded)
}

pub(crate) fn decode_canonical_contract_base64<T: CanonicalContract>(
    encoded: &str,
    max_decoded_bytes: usize,
    field: &str,
) -> anyhow::Result<T> {
    let bytes = decode_canonical_base64_bytes(encoded, max_decoded_bytes, field)?;
    T::from_canonical_bytes(&bytes).map_err(|error| {
        invalid_custody_composition_config(format!("{field} canonical bytes are invalid: {error}"))
    })
}

fn decode_digest32_base64(encoded: &str, field: &str) -> anyhow::Result<Digest32> {
    let bytes = decode_canonical_base64_bytes(encoded, 32, field)?;
    let digest: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid_custody_composition_config(format!("{field} must be 32 bytes")))?;
    Ok(Digest32::new(digest))
}

pub(crate) fn decode_custody_epoch_issuer_base64(
    encoded: &str,
    field: &str,
) -> anyhow::Result<CustodyEpochIssuerKeyV1> {
    let bytes = decode_canonical_base64_bytes(encoded, 32, field)?;
    let issuer: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid_custody_composition_config(format!("{field} must be 32 bytes")))?;
    CustodyEpochIssuerKeyV1::new(issuer).map_err(|error| {
        invalid_custody_composition_config(format!("{field} bytes are invalid: {error}"))
    })
}

fn decode_node_public_key_base64(encoded: &str, field: &str) -> anyhow::Result<NodePublicKey> {
    let bytes = decode_canonical_base64_bytes(encoded, 32, field)?;
    let public_key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid_custody_composition_config(format!("{field} must be 32 bytes")))?;
    NodePublicKey::new(public_key).map_err(|error| {
        invalid_custody_composition_config(format!("{field} bytes are invalid: {error}"))
    })
}

pub(crate) fn decode_canonical_peer_did(peer_did: &str) -> anyhow::Result<String> {
    if peer_did.is_empty() || peer_did.len() > MAX_CUSTODY_COMPOSITION_PEER_DID_BYTES {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config("carrier peer DID is out of bounds")
        );
    }
    let verifying_key = crate::crypto::decode_did_key(peer_did).map_err(|_| {
        invalid_custody_composition_config("carrier peer DID is not a valid canonical did:key")
    })?;
    let canonical = crate::crypto::encode_did_key(&verifying_key).map_err(|_| {
        invalid_custody_composition_config("carrier peer DID cannot be canonicalized")
    })?;
    if canonical != peer_did {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config("carrier peer DID is not canonical")
        );
    }
    Ok(canonical)
}

fn load_runtime_custody_composition_config(
    data_dir: &Path,
) -> anyhow::Result<Option<RuntimeValidatedCustodyCompositionConfig>> {
    let config_path = runtime_custody_composition_config_path(data_dir);
    match fs::symlink_metadata(&config_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            anyhow::bail!(
                "{}",
                invalid_custody_composition_config("custody-composition file is unavailable")
            )
        }
    }
    let _protected_root = validate_owner_only_protected_content_dir(data_dir)?;
    let bytes = read_owner_only_config_bytes(&config_path, MAX_CUSTODY_COMPOSITION_BYTES)?;
    let config: RuntimeCustodyCompositionConfigFile =
        serde_json::from_slice(&bytes).map_err(|_| {
            invalid_custody_composition_config(
                "custody-composition file is not valid canonical JSON",
            )
        })?;
    if config.schema != CUSTODY_COMPOSITION_SCHEMA_V1
        || canonical_custody_composition_config_bytes(&config)? != bytes
    {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config("custody-composition file is not canonical")
        );
    }

    let expected_policy_authority = decode_custody_epoch_issuer_base64(
        &config.expected_policy_authority_base64,
        "expected_policy_authority",
    )?;
    let expected_authorization_identity = decode_canonical_contract_base64(
        &config.expected_committee_authorization_identity_base64,
        MAX_CUSTODY_COMPOSITION_BLOB_BYTES,
        "expected_committee_authorization_identity",
    )?;
    let signed_pool = decode_canonical_contract_base64(
        &config.signed_pool_base64,
        MAX_CUSTODY_COMPOSITION_BLOB_BYTES,
        "signed_pool",
    )?;
    let signed_epoch = decode_canonical_contract_base64(
        &config.signed_epoch_base64,
        MAX_CUSTODY_COMPOSITION_BLOB_BYTES,
        "signed_epoch",
    )?;
    let signed_committee_authorization = decode_canonical_contract_base64(
        &config.signed_committee_authorization_base64,
        MAX_CUSTODY_COMPOSITION_BLOB_BYTES,
        "signed_committee_authorization",
    )?;

    let now = crate::auth::now_ts();
    let validated = validate_custody_epoch_against_pool_at(
        expected_policy_authority,
        expected_authorization_identity,
        &signed_pool,
        &signed_epoch,
        &signed_committee_authorization,
        now,
    )
    .map_err(|_| {
        invalid_custody_composition_config(
            "signed pool/epoch/committee authorization does not validate against trust anchors",
        )
    })?;
    let committee_nodes = validated.committee().nodes();
    if committee_nodes.len() != 3 || config.routes.len() != 3 {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config(
                "custody-composition routes must cover exactly three selected nodes"
            )
        );
    }

    let mut configured_node_keys = std::collections::BTreeSet::new();
    let mut configured_roots = std::collections::BTreeSet::new();
    let mut configured_peer_dids = std::collections::BTreeSet::new();
    let mut local_count = 0usize;
    let mut route_bindings =
        std::collections::BTreeMap::<NodePublicKey, (Digest32, ProviderInvocationTransport)>::new();

    for route in &config.routes {
        let node_public_key =
            decode_node_public_key_base64(&route.node_public_key_base64, "route.node_public_key")?;
        let owner_state_root =
            decode_digest32_base64(&route.owner_state_root_base64, "route.owner_state_root")?;
        if owner_state_root == Digest32::new([0; 32])
            || !configured_node_keys.insert(node_public_key)
            || !configured_roots.insert(owner_state_root)
        {
            anyhow::bail!(
                "{}",
                invalid_custody_composition_config(
                    "custody-composition routes are duplicated or invalid"
                )
            );
        }
        let transport = match &route.transport {
            RuntimeCustodyRouteTransportConfig::Local => {
                local_count += 1;
                ProviderInvocationTransport::Local
            }
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid { peer_did } => {
                let canonical_peer_did = decode_canonical_peer_did(peer_did)?;
                if !configured_peer_dids.insert(canonical_peer_did.clone()) {
                    anyhow::bail!(
                        "{}",
                        invalid_custody_composition_config("carrier peer DIDs must be distinct")
                    );
                }
                ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                    peer_did: canonical_peer_did,
                    timeout_ms: None,
                    reply_wait_ms: None,
                })
            }
        };
        route_bindings.insert(node_public_key, (owner_state_root, transport));
    }

    if local_count > 1 {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config("at most one local custody route is allowed")
        );
    }

    let routes = committee_nodes
        .iter()
        .map(|node| {
            let (owner_state_root, transport) = route_bindings
                .remove(&node.node_public_key())
                .ok_or_else(|| {
                    invalid_custody_composition_config(
                        "custody-composition routes do not exactly cover the signed node set",
                    )
                })?;
            Ok(RuntimeValidatedCustodyRouteBinding {
                owner_state_root,
                transport,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if !route_bindings.is_empty() {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config(
                "custody-composition routes do not exactly cover the signed node set",
            )
        );
    }

    Ok(Some(RuntimeValidatedCustodyCompositionConfig {
        expected_policy_authority,
        expected_authorization_identity,
        signed_pool,
        signed_epoch,
        signed_committee_authorization,
        routes: routes.try_into().map_err(|_| {
            invalid_custody_composition_config(
                "custody-composition routes must cover exactly three selected nodes",
            )
        })?,
    }))
}

/// What the custody nodes said, rendered for a refusal that would otherwise
/// say only that the release produced nothing.
///
/// The coordinator's own outcome names the shape of the failure and never its
/// cause, because the cause comes from a remote peer and must not influence
/// what this Runtime concludes. It can still be repeated, which is the
/// difference between a person knowing their mint is not final yet and a
/// person seeing a dead end.
///
/// Empty when the nodes said nothing, so the message keeps its existing form
/// in the cases this adds nothing to.
fn runtime_custody_reported_by_nodes(diagnostics: &RuntimeCustodyCallDiagnostics) -> String {
    let recorded = diagnostics.recorded();
    if recorded.is_empty() {
        return String::new();
    }
    format!(" (reported by custody nodes: {})", recorded.join("; "))
}

pub(crate) fn load_runtime_custody_composition(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
) -> anyhow::Result<Option<RuntimeCustodyComposition>> {
    let Some(config) = load_runtime_custody_composition_config(data_dir)? else {
        return Ok(None);
    };
    let now = crate::auth::now_ts();
    let validated = validate_custody_epoch_against_pool_at(
        config.expected_policy_authority,
        config.expected_authorization_identity,
        &config.signed_pool,
        &config.signed_epoch,
        &config.signed_committee_authorization,
        now,
    )
    .map_err(|_| {
        invalid_custody_composition_config(
            "signed pool/epoch/committee authorization does not validate against trust anchors",
        )
    })?;
    let diagnostics = RuntimeCustodyCallDiagnostics::default();
    let nodes = validated
        .committee()
        .nodes()
        .iter()
        .zip(config.routes.iter())
        .map(|(node, route)| RuntimeCustodyCompositionNode {
            node_public_key: node.node_public_key(),
            custody_public_key: node.custody_public_key(),
            owner_state_root: route.owner_state_root,
            adapter: RuntimeCustodyRegistryAdapter::new(
                registry.clone(),
                route.transport.clone(),
                diagnostics.clone(),
            ),
        })
        .collect::<Vec<_>>();

    let composition = RuntimeCustodyComposition {
        expected_policy_authority: config.expected_policy_authority,
        expected_authorization_identity: config.expected_authorization_identity,
        signed_pool: config.signed_pool,
        signed_epoch: config.signed_epoch,
        signed_committee_authorization: config.signed_committee_authorization,
        diagnostics,
        nodes: nodes.try_into().map_err(|_| {
            invalid_custody_composition_config(
                "custody-composition routes must cover exactly three selected nodes",
            )
        })?,
    };
    let configured = composition
        .configured_nodes()
        .map_err(|_| invalid_custody_composition_config("configured custody linkage is invalid"))?;
    resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        now,
        &configured,
    )
    .map_err(|_| invalid_custody_composition_config("configured custody linkage is invalid"))?;
    Ok(Some(composition))
}

/// Plan B POOL-MINT: the mint refusal when this Home uses no pool. Checked
/// before any media work.
pub(crate) const RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE: &str =
    "This Home can't mint yet: create a custody pool or add one under Pools this Home uses.";
/// More than one pool is used and none was chosen.
pub(crate) const RUNTIME_CUSTODY_MINT_POOL_CHOICE_MESSAGE: &str =
    "This Home uses more than one pool: choose one in Creator.";

/// The pool a mint goes into (Plan B POOL-MINT): this Home's own
/// composition, or the committee of a pool it uses, with that pool's
/// descriptor.
pub(crate) struct RuntimeCustodyMintPool {
    pub(crate) composition: RuntimeCustodyComposition,
    pub(crate) used: Option<SignedPoolDescriptorAnyV1>,
    /// PM-F5: the pool and epoch a recorded mint already uses. Settling it
    /// skips the freshness checks only new provisioning needs.
    pub(crate) recorded: bool,
}

impl RuntimeCustodyMintPool {
    /// The committee's nodes for this mint: the provisioning rule for a new
    /// mint, the release rule (no pool term) for a recorded one (PM-F5).
    pub(crate) fn selected_nodes<'a>(
        &self,
        configured: &'a [elastos_protected_content_runtime::RuntimeMintConfiguredCustodyProvider<
            'a,
        >],
        now: u64,
    ) -> anyhow::Result<Vec<elastos_protected_content_runtime::RuntimeMintSelectedNode<'a>>> {
        let composition = &self.composition;
        let resolve = if self.recorded {
            elastos_protected_content_runtime::resolve_recorded_runtime_mint_selected_nodes
        } else {
            resolve_runtime_mint_selected_nodes
        };
        resolve(
            composition.expected_policy_authority,
            composition.expected_authorization_identity,
            &composition.signed_pool,
            &composition.signed_epoch,
            &composition.signed_committee_authorization,
            now,
            configured,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody mint selection is invalid"))
    }
}

/// The pools this Home uses (Plan B POOL-MINT): those added under "Pools
/// this Home uses" whose descriptor verifies at `now` and is v3
/// `WciOperated` (#388 A2). One per pool (highest sequence); this Home's own
/// pool is not listed. The same pools serve playback.
pub(crate) fn runtime_custody_used_pools(
    data_dir: &Path,
    own_pool: Option<&elastos_protected_content_contracts::PoolDidV1>,
    now: u64,
) -> Vec<SignedPoolDescriptorAnyV1> {
    let mut pools: std::collections::BTreeMap<[u8; 32], SignedPoolDescriptorAnyV1> =
        std::collections::BTreeMap::new();
    for descriptor in crate::custody_pool_resolver::known_pool_descriptors(data_dir) {
        if Some(descriptor.pool()) == own_pool {
            continue;
        }
        if !descriptor
            .verify(now)
            .is_ok_and(|verified| verified.admits_new_release().is_ok())
        {
            continue;
        }
        let key = *descriptor.pool().issuer().as_bytes();
        if pools
            .get(&key)
            .is_none_or(|kept| kept.sequence() < descriptor.sequence())
        {
            pools.insert(key, descriptor);
        }
    }
    pools.into_values().collect()
}

/// The committee of `descriptor`'s pool as a mint composition (Plan B
/// POOL-MINT, "No composition"): the `recorded` epoch for a resumed mint,
/// else its first epoch whose term is open now, with each node
/// bound by `pool_node_owner_state_root` (`ItemMintPath::Pool`) and routed
/// `Local` when this Home holds that node, else to the member's peer DID.
fn runtime_custody_composition_for_pool(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    descriptor: &SignedPoolDescriptorAnyV1,
    recorded: Option<elastos_protected_content_contracts::CustodyEpochIdentityV1>,
    now: u64,
) -> anyhow::Result<RuntimeCustodyComposition> {
    // PM-F5: new provisioning needs a descriptor that verifies now and an
    // open term; a recorded mint settles on the descriptor this Home kept for
    // it, under the release rule (no window, no term).
    if recorded.is_none() {
        descriptor
            .verify(now)
            .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE))?;
    }
    let authority = descriptor.pool().issuer();
    let (bundle, validated) = descriptor
        .epochs()
        .iter()
        .filter(|bundle| recorded.is_none() || bundle.epoch_identity().ok() == recorded)
        .find_map(|bundle| {
            let authorization = bundle
                .signed_committee_authorization()
                .authorization_identity()
                .ok()?;
            let rule = if recorded.is_some() {
                elastos_protected_content_contracts::validate_custody_epoch_for_release_at
            } else {
                validate_custody_epoch_against_pool_at
            };
            rule(
                authority,
                authorization,
                bundle.signed_pool(),
                bundle.signed_epoch(),
                bundle.signed_committee_authorization(),
                now,
            )
            .ok()
            .map(|validated| (bundle, validated))
        })
        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE))?;
    let epoch = bundle
        .epoch_identity()
        .map_err(|_| anyhow::anyhow!("the pool's custody epoch is invalid"))?;
    let own_nodes = own_custody_node_keys(data_dir)?;
    let diagnostics = RuntimeCustodyCallDiagnostics::default();
    let nodes = validated
        .committee()
        .nodes()
        .iter()
        .map(|node| {
            let key = node.node_public_key();
            let transport = if own_nodes.contains(&key) {
                ProviderInvocationTransport::Local
            } else {
                let peer_did = descriptor
                    .member_peer_did(key)
                    .ok_or_else(|| anyhow::anyhow!("the pool's committee has no route"))?;
                ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                    peer_did: decode_canonical_peer_did(peer_did)?,
                    timeout_ms: None,
                    reply_wait_ms: None,
                })
            };
            Ok(RuntimeCustodyCompositionNode {
                node_public_key: key,
                custody_public_key: node.custody_public_key(),
                owner_state_root: elastos_protected_content_runtime::pool_node_owner_state_root(
                    descriptor.pool(),
                    epoch,
                    key,
                ),
                adapter: RuntimeCustodyRegistryAdapter::new(
                    registry.clone(),
                    transport,
                    diagnostics.clone(),
                ),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(RuntimeCustodyComposition {
        expected_policy_authority: authority,
        expected_authorization_identity: bundle
            .signed_committee_authorization()
            .authorization_identity()
            .map_err(|_| anyhow::anyhow!("the pool's committee is invalid"))?,
        signed_pool: bundle.signed_pool().clone(),
        signed_epoch: bundle.signed_epoch().clone(),
        signed_committee_authorization: bundle.signed_committee_authorization().clone(),
        diagnostics,
        nodes: nodes
            .try_into()
            .map_err(|_| anyhow::anyhow!("the pool's committee is not three nodes"))?,
    })
}

/// Plan B POOL-MINT (S7I-F1): the pool a mint attempt was started on, kept
/// beside the mint journal before its intent is written: a used pool's
/// descriptor, or none for this Home's own composition. Once the intent
/// exists, a resume uses this pool and no other: no reselection and no
/// fallback.
const RUNTIME_POOL_MINTS_DIR: &str = "runtime-pool-mints";
const RUNTIME_POOL_MINT_ATTEMPT_SCHEMA_V1: &str =
    "elastos.protected-content.runtime-pool-mint-attempt/v1";
const RUNTIME_POOL_MINT_SHARE_SCHEMA_V1: &str = "elastos.protected-content.runtime-pool-mint/v2";
const MAX_RUNTIME_POOL_MINT_FILE_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimePoolMintAttemptV1 {
    schema: String,
    /// Standard base64 of the used pool's `SignedPoolDescriptorAnyV1`;
    /// `None` for this Home's own composition.
    descriptor_base64: Option<String>,
}

/// What a pool-minted listing carries (S7I-F2): this Runtime's signed share
/// statement for the item, kept per mint once its custody is provisioned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimePoolMintRecordV2 {
    schema: String,
    /// Standard base64 of the `SignedPoolMintShareV1` canonical bytes.
    pub(crate) mint_share_base64: String,
}

fn runtime_pool_mints_dir(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(RUNTIME_POOL_MINTS_DIR)
}

fn read_runtime_pool_mint_file<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> anyhow::Result<Option<T>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let bytes = crate::collaboration_config::read_owner_only_file(
        path,
        MAX_RUNTIME_POOL_MINT_FILE_BYTES,
        "runtime pool mint",
    )?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn write_runtime_pool_mint_file(
    data_dir: &Path,
    path: &Path,
    value: &impl Serialize,
) -> anyhow::Result<()> {
    crate::protected_content_config::ensure_owner_only_dir(
        &runtime_pool_mints_dir(data_dir),
        "runtime pool mints",
    )?;
    write_owner_only_bytes(path, &serde_json::to_vec(value)?)
}

fn runtime_pool_mint_attempt_path(data_dir: &Path, request_id: Digest32) -> PathBuf {
    runtime_pool_mints_dir(data_dir).join(format!(
        "attempt-{}.json",
        hex::encode(request_id.as_bytes())
    ))
}

/// The source's current attempt, and whether its intent is written. `None`
/// for a Home that never minted (reading would create the journal).
fn runtime_mint_attempt_state(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
) -> anyhow::Result<Option<(Digest32, Option<RuntimeMintIntent>)>> {
    if fs::symlink_metadata(runtime_mint_journal_root(data_dir)).is_err() {
        return Ok(None);
    }
    let journal = runtime_mint_journal(data_dir);
    let attempt = journal
        .current_attempt(principal_id, object_uri, source_storage)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let intent = match journal.load_intent(attempt.request_id()) {
        Ok(intent) => Some(intent),
        Err(elastos_protected_content_runtime::RuntimeMintJournalError::NotFound) => None,
        Err(_) => anyhow::bail!("Runtime custody mint intent is unavailable"),
    };
    Ok(Some((attempt.request_id(), intent)))
}

fn recorded_runtime_mint_pool(
    data_dir: &Path,
    request_id: Digest32,
) -> anyhow::Result<Option<SignedPoolDescriptorAnyV1>> {
    let Some(record) = read_runtime_pool_mint_file::<RuntimePoolMintAttemptV1>(
        &runtime_pool_mint_attempt_path(data_dir, request_id),
    )?
    else {
        return Ok(None);
    };
    if record.schema != RUNTIME_POOL_MINT_ATTEMPT_SCHEMA_V1 {
        anyhow::bail!("the runtime pool mint attempt has an unknown schema");
    }
    record
        .descriptor_base64
        .map(|encoded| {
            decode_canonical_contract_base64(
                &encoded,
                elastos_protected_content_contracts::MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1,
                "runtime pool mint attempt",
            )
        })
        .transpose()
}

/// Records the attempt's pool before its intent is written (S7I-F1).
fn record_runtime_mint_attempt_pool(
    data_dir: &Path,
    (principal_id, object_uri, source_storage): (&str, &str, &str),
    descriptor: Option<&SignedPoolDescriptorAnyV1>,
) -> anyhow::Result<()> {
    let attempt = runtime_mint_journal(data_dir)
        .current_attempt(principal_id, object_uri, source_storage)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let descriptor_base64 = descriptor
        .map(|descriptor| {
            descriptor
                .canonical_bytes()
                .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
        })
        .transpose()?;
    write_runtime_pool_mint_file(
        data_dir,
        &runtime_pool_mint_attempt_path(data_dir, attempt.request_id()),
        &RuntimePoolMintAttemptV1 {
            schema: RUNTIME_POOL_MINT_ATTEMPT_SCHEMA_V1.to_string(),
            descriptor_base64,
        },
    )
}

/// Plan B POOL-MINT: the pools Creator offers: this Home's own pool and the
/// pools it uses. One per pool; `pool_did` is what a publish sends.
pub(crate) fn runtime_custody_mint_pool_choices(data_dir: &Path) -> Vec<Value> {
    let now = crate::auth::now_ts();
    let mut choices = Vec::new();
    let mut own_pool = None;
    if let Ok(Some(own)) = crate::custody_pool_descriptor::owner_descriptor(data_dir, now) {
        let pool = *own.statement().pool();
        if let Ok(did) = pool.to_did_key() {
            choices.push(json!({ "pool_did": did, "label": "This Home's pool", "own": true }));
            own_pool = Some(pool);
        }
    }
    for descriptor in runtime_custody_used_pools(data_dir, own_pool.as_ref(), now) {
        let Ok(did) = descriptor.pool().to_did_key() else {
            continue;
        };
        let label = format!(
            "Pool {}",
            crate::custody_node_card::Fingerprint::of(descriptor.pool().issuer().as_bytes()).short
        );
        choices.push(json!({ "pool_did": did, "label": label, "own": false }));
    }
    choices
}

/// Plan B POOL-MINT: the pool this mint goes into.
/// - A source whose intent is written keeps the pool it recorded (S7I-F1):
///   the recorded pool file, else this Home's own composition. No
///   reselection and no fallback.
/// - `requested` names a pool: this Home's own, or one it uses.
/// - Otherwise this Home's own pool, else the only pool it uses.
///
/// Refused plainly when there is none, before any media work. A new pool
/// mint is recorded for its attempt before the intent is written.
pub(crate) fn load_runtime_custody_mint_pool(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    requested: Option<&str>,
    source: Option<(&str, &str, &str)>,
) -> anyhow::Result<RuntimeCustodyMintPool> {
    let now = crate::auth::now_ts();
    let attempt = match source {
        Some((principal, uri, storage)) => {
            runtime_mint_attempt_state(data_dir, principal, uri, storage)?
        }
        None => None,
    };
    let used_pool =
        |descriptor: SignedPoolDescriptorAnyV1,
         recorded: Option<elastos_protected_content_contracts::CustodyEpochIdentityV1>|
         -> anyhow::Result<RuntimeCustodyMintPool> {
            Ok(RuntimeCustodyMintPool {
                composition: runtime_custody_composition_for_pool(
                    data_dir,
                    registry.clone(),
                    &descriptor,
                    recorded,
                    now,
                )?,
                used: Some(descriptor),
                recorded: recorded.is_some(),
            })
        };
    if let Some((request_id, Some(intent))) = &attempt {
        return match recorded_runtime_mint_pool(data_dir, *request_id)? {
            Some(descriptor) => used_pool(descriptor, Some(intent.custody_epoch())),
            // A composition mint: its intent check reports a changed pool.
            None => Ok(RuntimeCustodyMintPool {
                composition: load_runtime_custody_composition(data_dir, registry.clone())?
                    .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE))?,
                used: None,
                recorded: false,
            }),
        };
    }
    let own = load_runtime_custody_composition(data_dir, registry.clone())?;
    let own_pool = own.as_ref().map(|own| {
        elastos_protected_content_contracts::PoolDidV1::from_issuer(own.expected_policy_authority)
    });
    let mut used = runtime_custody_used_pools(data_dir, own_pool.as_ref(), now);
    let chosen = match requested {
        Some(did) => {
            let pool = elastos_protected_content_contracts::PoolDidV1::parse_did_key(did)
                .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE))?;
            if own_pool == Some(pool) {
                None
            } else {
                Some(
                    used.into_iter()
                        .find(|descriptor| descriptor.pool() == &pool)
                        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE))?,
                )
            }
        }
        None if own.is_some() => None,
        None => match used.len() {
            0 => anyhow::bail!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE),
            1 => Some(used.remove(0)),
            _ => anyhow::bail!(RUNTIME_CUSTODY_MINT_POOL_CHOICE_MESSAGE),
        },
    };
    let pool = match chosen {
        None => RuntimeCustodyMintPool {
            composition: own
                .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE))?,
            used: None,
            recorded: false,
        },
        Some(descriptor) => used_pool(descriptor, None)?,
    };
    // A used pool is recorded for the attempt. A composition mint needs no
    // record; it only overwrites one an earlier choice for this attempt left.
    let recorded_before = match (&attempt, &pool.used) {
        (Some((request_id, _)), None) => {
            fs::symlink_metadata(runtime_pool_mint_attempt_path(data_dir, *request_id)).is_ok()
        }
        _ => false,
    };
    if let Some(source) = source {
        if pool.used.is_some() || recorded_before {
            record_runtime_mint_attempt_pool(data_dir, source, pool.used.as_ref())?;
        }
    }
    Ok(pool)
}

fn runtime_pool_mint_path(data_dir: &Path, mint_id: Digest32) -> PathBuf {
    runtime_pool_mints_dir(data_dir).join(format!("{}.json", hex::encode(mint_id.as_bytes())))
}

/// Writes the pool mint record once; a record already there is kept.
fn record_runtime_pool_mint(
    data_dir: &Path,
    draft: &RuntimeMintDraft,
    descriptor: &SignedPoolDescriptorAnyV1,
    device_key: &elastos_runtime::signature::SigningKey,
) -> anyhow::Result<()> {
    if runtime_pool_mint_record(data_dir, draft.mint_id())?.is_some() {
        return Ok(());
    }
    let issuer = RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())
        .map_err(|_| anyhow::anyhow!("local Runtime device signing key is invalid"))?;
    let sign_key = device_key.clone();
    let mint_share = elastos_protected_content_runtime::sign_pool_mint_share(
        descriptor,
        draft.key_envelope(),
        draft.content_access_id(),
        issuer,
        &move |bytes: &[u8]| sign_key.sign(bytes).to_bytes(),
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody pool mint share is invalid"))?;
    write_runtime_pool_mint_file(
        data_dir,
        &runtime_pool_mint_path(data_dir, draft.mint_id()),
        &RuntimePoolMintRecordV2 {
            schema: RUNTIME_POOL_MINT_SHARE_SCHEMA_V1.to_string(),
            mint_share_base64: base64::engine::general_purpose::STANDARD
                .encode(mint_share.canonical_bytes()?),
        },
    )?;
    tracing::debug!(
        mint_id = %hex::encode(draft.mint_id().as_bytes()),
        "runtime custody publish: pool mint recorded"
    );
    Ok(())
}

/// The pool mint record of `mint_id`, if this Home minted it into a pool it
/// uses.
pub(crate) fn runtime_pool_mint_record(
    data_dir: &Path,
    mint_id: Digest32,
) -> anyhow::Result<Option<RuntimePoolMintRecordV2>> {
    let Some(record) = read_runtime_pool_mint_file::<RuntimePoolMintRecordV2>(
        &runtime_pool_mint_path(data_dir, mint_id),
    )?
    else {
        return Ok(None);
    };
    if record.schema != RUNTIME_POOL_MINT_SHARE_SCHEMA_V1 {
        anyhow::bail!("the runtime pool mint record has an unknown schema");
    }
    Ok(Some(record))
}

pub fn log_unresolved_runtime_releases(data_dir: &Path) {
    match list_unresolved_runtime_releases(data_dir) {
        Ok(operations) => {
            let effect_started = operations
                .iter()
                .filter(|operation| operation.provider_effect_started())
                .count();
            if operations.is_empty() {
                return;
            }
            tracing::warn!(
                unresolved = operations.len(),
                effect_started,
                "protected-content runtime release journal has unresolved operations; Runtime will not infer completion from absence or elapsed time"
            );
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "protected-content runtime release journal scan failed closed"
            );
        }
    }
}

pub(crate) async fn invoke_json_provider(
    registry: &ProviderRegistry,
    target: &str,
    op: &str,
    request: Value,
) -> Result<Value, String> {
    invoke_json_provider_with_transport(
        registry,
        target,
        op,
        request,
        ProviderInvocationTransport::Local,
    )
    .await
}

/// Why a provider invocation did not yield data, keeping the distinction the
/// formatted-string form throws away.
///
/// The distinction that matters to a caller holding a durable journal is
/// whether the provider can have acted. `NotCompleted` is the only variant that
/// says nothing either way: the registry call failed, which covers a provider
/// that was never reached *and* a reply that was lost after the provider did
/// its work. `Refused` carries the provider's own code, which is the sole
/// evidence a caller has for classifying the refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProviderInvocationFailure {
    /// The registry call itself failed. The request may or may not have reached
    /// the provider, and a reply may have been lost on the way back.
    NotCompleted { detail: String },
    /// The provider answered `status: "error"` with its own code and message.
    Refused { code: String, message: String },
    /// The provider answered, but the frame was not a usable response.
    MalformedResponse { detail: String },
}

impl ProviderInvocationFailure {
    /// The formatted form the string-returning callers have always seen. Kept
    /// byte-identical so widening the typed layer changes no existing message.
    fn into_message(self, target: &str, op: &str) -> String {
        match self {
            Self::NotCompleted { detail } => {
                format!("{target} provider {op} invocation failed: {detail}")
            }
            Self::Refused { code, message } => {
                format!("{target} provider {op} rejected the request: {code}: {message}")
            }
            Self::MalformedResponse { detail } => detail,
        }
    }
}

pub(crate) async fn invoke_json_provider_with_transport(
    registry: &ProviderRegistry,
    target: &str,
    op: &str,
    request: Value,
    transport: ProviderInvocationTransport,
) -> Result<Value, String> {
    invoke_json_provider_classified(registry, target, op, request, transport)
        .await
        .map_err(|failure| failure.into_message(target, op))
}

/// The same invocation, with the failure kept as data.
pub(crate) async fn invoke_json_provider_classified(
    registry: &ProviderRegistry,
    target: &str,
    op: &str,
    request: Value,
    transport: ProviderInvocationTransport,
) -> Result<Value, ProviderInvocationFailure> {
    let response = registry
        .invoke_provider(ProviderInvocation {
            source: RUNTIME_PROVIDER_ID.to_string(),
            target: target.to_string(),
            op: op.to_string(),
            request,
            transfer: ProviderTransfer::Json,
            range: None,
            progress: None,
            transport,
        })
        .await
        .map_err(|error| {
            tracing::warn!(
                %target,
                %op,
                error = %error,
                "provider invocation failed"
            );
            ProviderInvocationFailure::NotCompleted {
                detail: error.to_string(),
            }
        })?;
    let Some(status) = response.get("status").and_then(Value::as_str) else {
        return Err(ProviderInvocationFailure::MalformedResponse {
            detail: format!("{target} provider {op} response is missing status"),
        });
    };
    match status {
        "ok" => response.get("data").cloned().ok_or_else(|| {
            ProviderInvocationFailure::MalformedResponse {
                detail: format!("{target} provider {op} response is missing data"),
            }
        }),
        "error" => {
            // Keep the provider's own code/message: this travels back to the
            // caller (over Carrier for a committee member) and is the only
            // trace of why a node refused.
            let code = response
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let message = response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("no message");
            tracing::warn!(%target, %op, %code, %message, "provider rejected the request");
            Err(ProviderInvocationFailure::Refused {
                code: code.to_string(),
                message: message.to_string(),
            })
        }
        _ => Err(ProviderInvocationFailure::MalformedResponse {
            detail: format!("{target} provider {op} response has unsupported status"),
        }),
    }
}

pub(crate) fn runtime_protected_content_id(
    encrypted_content: &EncryptedContentIdentityV1,
) -> anyhow::Result<String> {
    Ok(format!(
        "content:{}",
        hex::encode(encrypted_content.canonical_hash()?.as_bytes())
    ))
}

fn runtime_protected_content_identity_hex(
    encrypted_content: &EncryptedContentIdentityV1,
) -> anyhow::Result<String> {
    Ok(format!(
        "0x{}",
        hex::encode(
            encrypted_content
                .canonical_bytes()
                .map_err(|_| anyhow::anyhow!("protected content identity is invalid"))?
        )
    ))
}

fn runtime_content_access_id_hex(content_access_id: ContentAccessIdV1) -> String {
    format!("0x{}", hex::encode(content_access_id.as_bytes()))
}

pub(crate) async fn resolve_runtime_rights_policy(
    registry: &ProviderRegistry,
    encrypted_content: &EncryptedContentIdentityV1,
    content_access_id: ContentAccessIdV1,
    action: RightsActionV1,
) -> anyhow::Result<ResolvedRuntimeRightsPolicy> {
    let response_value = invoke_json_provider(
        registry,
        CHAIN_PROVIDER_ID,
        CHAIN_PROTECTED_CONTENT_POLICY_OP,
        json!({
            "op": CHAIN_PROTECTED_CONTENT_POLICY_OP,
            "encrypted_content": runtime_protected_content_identity_hex(encrypted_content)?,
            "content_access_id": runtime_content_access_id_hex(content_access_id),
            "action": runtime_rights_action_name(action),
        }),
    )
    .await
    .map_err(anyhow::Error::msg)?;
    let response = serde_json::from_value::<ChainProtectedContentPolicyResponse>(response_value)?;
    if response.schema != CHAIN_PROTECTED_CONTENT_POLICY_SCHEMA_V1 {
        anyhow::bail!("chain provider returned an unsupported protected-content policy schema");
    }
    let policy_bytes = decode_0x_hex(&response.policy_body).ok_or_else(|| {
        anyhow::anyhow!("chain provider returned an invalid protected-content policy body")
    })?;
    let body = RightsPolicyBodyV1::from_canonical_bytes(&policy_bytes)?;
    if body.encrypted_content() != encrypted_content
        || body.content_access_id() != content_access_id
        || body.required_action() != action
    {
        anyhow::bail!(
            "chain provider returned a protected-content policy that does not match the Runtime request"
        );
    }
    let identity = body.policy_identity()?;
    Ok(ResolvedRuntimeRightsPolicy { body, identity })
}

/// Publishes and verifies the one immutable CENC/DASH object Runtime may later
/// record as availability evidence. The directory is provider input only: no
/// file path, bytes, or receipt JSON crosses this boundary into Runtime state.
///
/// The staged package was fully checked when it was written, on the same private
/// directory, so this checks its path set and identity bytes again and then
/// verifies what was published: the manifest against the head, and every
/// published file against the manifest, one at a time.
pub(crate) async fn publish_and_verify_protected_content_dash_availability(
    registry: &ProviderRegistry,
    protected_content_dir: &Path,
    head: &CencDashMediaIdentityV2,
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: impl Fn() -> u64,
) -> anyhow::Result<RuntimeVerifiedContentAvailability> {
    validate_protected_content_availability_requirement(requirement)?;
    verify_protected_content_dash_directory_shape(protected_content_dir, head)?;
    // The receipt is verified against `requirement.policy()` below, and the
    // content plane records whatever `availability_policy` the publish
    // request names (its own `network_default` otherwise), so the policy has
    // to travel with the publish request.
    let publish_requirements = crate::content::ContentPublishRequirements::new(
        requirement.minimum_replicas(),
        protected_content_live_proof_required(requirement.minimum_replicas()),
    )?
    .with_availability_policy(requirement.policy())?;
    let content_cid = crate::content::publish_directory_via_provider_with_kind_and_requirements(
        registry,
        protected_content_dir,
        PROTECTED_CONTENT_OBJECT_KIND,
        Some(requirement.expected_object_identity()),
        Some(requirement.expected_publisher_did()),
        publish_requirements,
    )
    .await?;
    let receipt = fetch_content_availability_receipt(registry, &content_cid).await?;
    let manifest = crate::content::fetch_content_object_manifest(registry, &content_cid).await?;
    verify_protected_content_dash_manifest(&manifest, head)?;
    for file in &manifest.files {
        let bytes =
            crate::content::fetch_bytes_via_provider(registry, &content_cid, Some(&file.path))
                .await?;
        crate::content::verify_content_object_file(&content_cid, file, &bytes)?;
    }
    // The receipt's `checked_at` is stamped when the replication round
    // finishes, which can be well over the future-skew allowance after this
    // function was entered (three-node replication takes tens of seconds),
    // so the freshness reference is sampled now, not by the caller.
    let now_unix_seconds = now_unix_seconds();
    verify_protected_content_dash_receipt(
        &content_cid,
        &manifest,
        &receipt,
        head,
        requirement,
        now_unix_seconds,
        RuntimeManifestPublisherBinding::Exact,
    )
}

/// Which publisher a content object's manifest must name (D16, R40). Chosen
/// by the caller, which knows the listing's origin; never inferred from the
/// requirement's DID method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeManifestPublisherBinding {
    /// The manifest names exactly the publisher the requirement expects: the
    /// Runtime profile (`did:key`) the content was published under. Every
    /// package this Runtime or another one published (`LocalCreator`,
    /// `Imported`), and every publish.
    Exact,
    /// A listing adopted from a shared `metadata.json` (origin `Asset`) only.
    /// Its publisher is a `did:pkh` taken from the document, and it is
    /// ATTRIBUTION ONLY: it names the chain account the document states and
    /// authorizes nothing. The content object's manifest names the Runtime
    /// profile that published the bytes -- another namespace, with no mapping
    /// to the `did:pkh` -- so the manifest must name a well-formed `did:key`;
    /// the receipt, which the content plane binds to the publisher the
    /// `ensure` names, is what agrees with the requirement, and the bytes are
    /// bound by the content identity the document carries.
    AdoptedAttribution,
}

impl RuntimeManifestPublisherBinding {
    /// The binding a listing of this origin is verified under.
    pub(crate) fn for_origin(origin: &RuntimeCustodyListingOrigin) -> Self {
        match origin {
            RuntimeCustodyListingOrigin::Asset { .. }
            | RuntimeCustodyListingOrigin::Granted { .. } => Self::AdoptedAttribution,
            RuntimeCustodyListingOrigin::LocalCreator { .. }
            | RuntimeCustodyListingOrigin::Imported { .. } => Self::Exact,
        }
    }
}

/// Whether a content object's own manifest names the publisher an
/// availability requirement expects, under `binding` (R40).
fn content_manifest_binds_publisher(
    manifest: &crate::content::ContentObjectManifest,
    requirement: &RuntimeContentAvailabilityRequirement,
    binding: RuntimeManifestPublisherBinding,
) -> bool {
    let expected = requirement.expected_publisher_did();
    match binding {
        RuntimeManifestPublisherBinding::Exact => {
            manifest.publisher_did.as_deref() == Some(expected)
        }
        RuntimeManifestPublisherBinding::AdoptedAttribution => {
            parse_runtime_publisher_pkh(expected).is_some()
                && manifest
                    .publisher_did
                    .as_deref()
                    .is_some_and(|publisher| crate::crypto::decode_did_key(publisher).is_ok())
        }
    }
}

fn validate_protected_content_availability_requirement(
    requirement: &RuntimeContentAvailabilityRequirement,
) -> anyhow::Result<()> {
    if requirement.policy() != PROTECTED_CONTENT_REPLICATION_POLICY
        || requirement.minimum_replicas() < PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR
    {
        anyhow::bail!("protected content availability requirement is invalid");
    }
    Ok(())
}

/// Re-observes availability for `content_cid` through the content plane's
/// `ensure` (local pin + Carrier replica proofs, signed into a new receipt
/// bound to the requirement's policy, object identity and publisher), then
/// returns that receipt. Nothing is republished.
async fn refresh_content_availability_receipt(
    registry: &ProviderRegistry,
    content_cid: &str,
    requirement: &RuntimeContentAvailabilityRequirement,
) -> anyhow::Result<Vec<u8>> {
    let response = registry
        .send_raw(
            CONTENT_PROVIDER_ID,
            &json!({
                "op": "ensure",
                "cid": content_cid,
                "availability_requirements": {
                    "min_replicas": requirement.minimum_replicas(),
                    "require_live_multi_peer_proof":
                        protected_content_live_proof_required(requirement.minimum_replicas()),
                },
                "availability_policy": requirement.policy(),
                "object_did": requirement.expected_object_identity(),
                "publisher_did": requirement.expected_publisher_did(),
            }),
        )
        .await
        .map_err(|error| anyhow::anyhow!("protected content ensure is unavailable: {error}"))?;
    if response.get("status").and_then(Value::as_str) != Some("ok") {
        anyhow::bail!("protected content ensure is invalid");
    }
    fetch_content_availability_receipt(registry, content_cid).await
}

async fn fetch_content_availability_receipt(
    registry: &ProviderRegistry,
    content_cid: &str,
) -> anyhow::Result<Vec<u8>> {
    let response = registry
        .send_raw(
            CONTENT_PROVIDER_ID,
            &json!({ "op": "status", "cid": content_cid }),
        )
        .await
        .map_err(|error| anyhow::anyhow!("protected content status is unavailable: {error}"))?;
    if response.get("status").and_then(Value::as_str) != Some("ok") {
        anyhow::bail!("protected content status is invalid");
    }
    let receipt = response
        .get("data")
        .and_then(|data| data.get("receipt"))
        .ok_or_else(|| anyhow::anyhow!("protected content status receipt is absent"))?;
    serde_json::to_vec(receipt)
        .map_err(|_| anyhow::anyhow!("protected content status receipt is invalid"))
}

/// Every file path of a v2 package, in the order and the spelling the package
/// layout gives them: the identity, the MPD, then each rendition's init and
/// segments (spec section 3).
fn protected_content_dash_package_paths(head: &CencDashMediaIdentityV2) -> Vec<String> {
    let mut paths = vec![
        PROTECTED_CONTENT_V2_IDENTITY_PATH.to_string(),
        PROTECTED_CONTENT_V2_MPD_PATH.to_string(),
    ];
    for rendition in head.renditions() {
        paths.push(runtime_media_dash_init_path(rendition.kind()));
        paths.extend(
            (0..rendition.segment_count())
                .map(|index| runtime_media_dash_segment_path(rendition.kind(), index)),
        );
    }
    paths
}

/// Every regular file under `directory` as a `/`-separated relative path.
/// Links and anything else are refused. The result is a set: package files are
/// looked up by path, and a sorted list is never read as segment order
/// (`seg-10` sorts before `seg-2`).
fn protected_content_dash_directory_paths(
    directory: &Path,
) -> anyhow::Result<std::collections::BTreeSet<String>> {
    const INVALID: &str = "protected content directory is invalid";
    let mut paths = std::collections::BTreeSet::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(&current).map_err(|_| anyhow::anyhow!(INVALID))? {
            let entry = entry.map_err(|_| anyhow::anyhow!(INVALID))?;
            let file_type = entry.file_type().map_err(|_| anyhow::anyhow!(INVALID))?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                let relative = entry
                    .path()
                    .strip_prefix(directory)
                    .ok()
                    .and_then(Path::to_str)
                    .map(|relative| relative.replace('\\', "/"))
                    .ok_or_else(|| anyhow::anyhow!(INVALID))?;
                paths.insert(relative);
            } else {
                anyhow::bail!(INVALID);
            }
        }
    }
    Ok(paths)
}

/// The cheap half of the directory check: the path set is exactly the package's
/// and `identity.bin` is exactly the head.
fn verify_protected_content_dash_directory_shape(
    directory: &Path,
    head: &CencDashMediaIdentityV2,
) -> anyhow::Result<()> {
    let expected: std::collections::BTreeSet<String> = protected_content_dash_package_paths(head)
        .into_iter()
        .collect();
    if protected_content_dash_directory_paths(directory)? != expected {
        anyhow::bail!("protected content directory layout is invalid");
    }
    let canonical = head
        .canonical_bytes()
        .map_err(|_| anyhow::anyhow!("protected content media identity is invalid"))?;
    let descriptor = fs::read(directory.join(PROTECTED_CONTENT_V2_IDENTITY_PATH))
        .map_err(|_| anyhow::anyhow!("protected content descriptor is unavailable"))?;
    if descriptor != canonical {
        anyhow::bail!("protected content descriptor is invalid");
    }
    Ok(())
}

/// The full check of a staged v2 package against its head, one part at a time:
/// the layout, the descriptor, every init, and then every segment twice.
///
/// Pass A reads each segment and builds its Merkle leaf, and each rendition's
/// root must equal the head's. Pass B reads each segment again and requires it
/// to validate as a protected V2 segment under its proof against that root, so
/// a segment is proven in the place the head says it belongs. `timelines`, when
/// given, are the clear timelines the protection must have preserved.
fn verify_protected_content_dash_directory(
    directory: &Path,
    head: &CencDashMediaIdentityV2,
    timelines: Option<&[Vec<Fmp4SegmentTimelineV2>]>,
) -> anyhow::Result<()> {
    const INVALID: &str = "protected content media layout is invalid";
    verify_protected_content_dash_directory_shape(directory, head)?;
    let mpd = fs::metadata(directory.join(PROTECTED_CONTENT_V2_MPD_PATH))
        .map_err(|_| anyhow::anyhow!("protected content stream is unavailable"))?;
    if mpd.len() == 0 {
        anyhow::bail!("protected content stream is unavailable");
    }
    let mut sessions = Vec::with_capacity(head.renditions().len());
    for (index, rendition) in head.renditions().iter().enumerate() {
        let init = fs::read(directory.join(runtime_media_dash_init_path(rendition.kind())))
            .map_err(|_| anyhow::anyhow!("protected content init is unavailable"))?;
        sessions.push(
            ValidatedCencDashRenditionSessionV2::new(head, index, &init)
                .map_err(|_| anyhow::anyhow!(INVALID))?,
        );
    }
    let read_segment = |kind, index| {
        fs::read(directory.join(runtime_media_dash_segment_path(kind, index)))
            .map_err(|_| anyhow::anyhow!("protected content segment is unavailable"))
    };
    let mut all_leaves = Vec::with_capacity(head.renditions().len());
    for rendition in head.renditions() {
        let mut leaves = Vec::with_capacity(rendition.segment_count() as usize);
        for index in 0..rendition.segment_count() {
            let bytes = read_segment(rendition.kind(), index)?;
            leaves.push(cenc_dash_segment_leaf_hash(
                rendition.kind(),
                index,
                Digest32::new(sha2::Sha256::digest(&bytes).into()),
                bytes.len() as u64,
            ));
        }
        if cenc_dash_merkle_root(&leaves).map_err(|_| anyhow::anyhow!(INVALID))?
            != rendition.segments_root()
        {
            anyhow::bail!("protected content media identity is invalid");
        }
        all_leaves.push(leaves);
    }
    for (rendition_index, (session, leaves)) in sessions.iter().zip(&all_leaves).enumerate() {
        let proofs = cenc_dash_merkle_audit_paths(leaves).map_err(|_| anyhow::anyhow!(INVALID))?;
        for index in 0..session.segment_count() {
            let bytes = read_segment(session.kind(), index)?;
            if bytes.len() > MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2 {
                anyhow::bail!(INVALID);
            }
            let layout = session
                .validate_proven_segment(index, &bytes, &proofs[index as usize])
                .map_err(|_| anyhow::anyhow!(INVALID))?;
            if let Some(timelines) = timelines {
                let expected = timelines
                    .get(rendition_index)
                    .and_then(|rendition| rendition.get(index as usize));
                if expected.is_none() || layout.timeline().as_ref() != expected {
                    anyhow::bail!(INVALID);
                }
            }
        }
    }
    Ok(())
}

fn protected_content_directory_files(directory: &Path) -> anyhow::Result<Vec<String>> {
    let mut actual_paths = Vec::new();
    collect_protected_content_directory_files(directory, directory, &mut actual_paths)?;
    actual_paths.sort_unstable();
    Ok(actual_paths)
}

fn collect_protected_content_directory_files(
    root: &Path,
    directory: &Path,
    paths: &mut Vec<String>,
) -> anyhow::Result<()> {
    for entry in fs::read_dir(directory)
        .map_err(|_| anyhow::anyhow!("protected content directory is unavailable"))?
    {
        let entry = entry.map_err(|_| anyhow::anyhow!("protected content directory is invalid"))?;
        let file_type = entry
            .file_type()
            .map_err(|_| anyhow::anyhow!("protected content directory is invalid"))?;
        if file_type.is_symlink() {
            anyhow::bail!("protected content directory is invalid");
        }
        if file_type.is_dir() {
            collect_protected_content_directory_files(root, &entry.path(), paths)?;
            continue;
        }
        if !file_type.is_file() {
            anyhow::bail!("protected content directory is invalid");
        }
        let entry_path = entry.path();
        let relative = entry_path
            .strip_prefix(root)
            .map_err(|_| anyhow::anyhow!("protected content directory is invalid"))?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("protected content directory is invalid"))?;
        let normalized = relative.replace('\\', "/");
        match normalized.as_str() {
            PROTECTED_CONTENT_IDENTITY_PATH
            | PROTECTED_CONTENT_INIT_PATH
            | PROTECTED_CONTENT_OBJECT_EPC1_PATH
            | PROTECTED_CONTENT_OBJECT_MANIFEST_PATH => {}
            _ if normalized.starts_with(PROTECTED_CONTENT_SEGMENTS_PREFIX)
                && normalized.ends_with(PROTECTED_CONTENT_SEGMENTS_SUFFIX) =>
            {
                let index = normalized
                    .strip_prefix(PROTECTED_CONTENT_SEGMENTS_PREFIX)
                    .and_then(|value| value.strip_suffix(PROTECTED_CONTENT_SEGMENTS_SUFFIX))
                    .and_then(|value| value.parse::<usize>().ok())
                    .ok_or_else(|| {
                        anyhow::anyhow!("protected content directory layout is invalid")
                    })?;
                if normalized != protected_content_segment_path(index) {
                    anyhow::bail!("protected content directory layout is invalid");
                }
            }
            _ => anyhow::bail!("protected content directory layout is invalid"),
        }
        paths.push(normalized);
    }
    Ok(())
}

fn protected_content_files(
    media_identity: &CencFmp4MediaIdentityV1,
) -> anyhow::Result<Vec<crate::content::ContentObjectFile>> {
    let descriptor = media_identity
        .canonical_bytes()
        .map_err(|_| anyhow::anyhow!("protected content media identity is invalid"))?;
    let mut files = Vec::with_capacity(media_identity.encrypted_segments().len() + 2);
    files.push(content_object_file(
        PROTECTED_CONTENT_IDENTITY_PATH,
        &descriptor,
    ));
    files.push(crate::content::ContentObjectFile {
        path: PROTECTED_CONTENT_INIT_PATH.to_string(),
        sha256: hex::encode(media_identity.init_segment_sha256().as_bytes()),
        size: media_identity.init_segment_bytes(),
    });
    files.extend(
        media_identity
            .encrypted_segments()
            .iter()
            .enumerate()
            .map(|(index, segment)| crate::content::ContentObjectFile {
                path: protected_content_segment_path(index),
                sha256: hex::encode(segment.ciphertext_sha256().as_bytes()),
                size: segment.ciphertext_bytes(),
            }),
    );
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn content_object_file(path: &str, bytes: &[u8]) -> crate::content::ContentObjectFile {
    crate::content::ContentObjectFile {
        path: path.to_string(),
        sha256: hex::encode(sha2::Sha256::digest(bytes)),
        size: bytes.len() as u64,
    }
}

pub(crate) fn protected_content_segment_path(index: usize) -> String {
    format!("{PROTECTED_CONTENT_SEGMENTS_PREFIX}{index:08}{PROTECTED_CONTENT_SEGMENTS_SUFFIX}")
}

/// The manifest of a V1 media item names exactly its identity's files.
/// Plan B T4.6: also the open's manifest-only check on a non-holder.
fn protected_content_media_manifest_files(
    manifest: &crate::content::ContentObjectManifest,
    media_identity: &CencFmp4MediaIdentityV1,
) -> anyhow::Result<Vec<crate::content::ContentObjectFile>> {
    let expected_files = protected_content_files(media_identity)?;
    if manifest.schema != "elastos.content.object.manifest/v1"
        || manifest.kind != PROTECTED_CONTENT_OBJECT_KIND
        || !manifest.links.is_empty()
        || !content_object_files_match(&manifest.files, &expected_files)
        || manifest.content_digest != content_object_digest(&expected_files)
    {
        anyhow::bail!("protected content object manifest is invalid");
    }
    Ok(expected_files)
}

async fn verify_protected_content_manifest_and_files(
    registry: &ProviderRegistry,
    content_cid: &str,
    manifest: &crate::content::ContentObjectManifest,
    media_identity: &CencFmp4MediaIdentityV1,
) -> anyhow::Result<(Vec<u8>, Vec<Vec<u8>>)> {
    let expected_files = protected_content_media_manifest_files(manifest, media_identity)?;
    let mut protected_init = None;
    let mut encrypted_segments = Vec::with_capacity(media_identity.encrypted_segments().len());
    for file in &expected_files {
        let bytes =
            crate::content::fetch_bytes_via_provider(registry, content_cid, Some(&file.path))
                .await?;
        crate::content::verify_content_object_file(content_cid, file, &bytes)?;
        match file.path.as_str() {
            PROTECTED_CONTENT_IDENTITY_PATH => {
                let canonical_identity = media_identity
                    .canonical_bytes()
                    .map_err(|_| anyhow::anyhow!("protected content media identity is invalid"))?;
                if bytes != canonical_identity
                    || CencFmp4MediaIdentityV1::from_canonical_bytes(&bytes)
                        .map_err(|_| anyhow::anyhow!("protected content descriptor is invalid"))?
                        != *media_identity
                {
                    anyhow::bail!("protected content descriptor is invalid");
                }
            }
            PROTECTED_CONTENT_INIT_PATH => protected_init = Some(bytes),
            _ => encrypted_segments.push(bytes),
        }
    }
    let protected_init =
        protected_init.ok_or_else(|| anyhow::anyhow!("protected content init is absent"))?;
    let reconstructed = CencFmp4MediaIdentityV1::new_from_bytes(
        &protected_init,
        &encrypted_segments,
        media_identity.mime_type(),
        media_identity.codecs(),
    )
    .map_err(|_| anyhow::anyhow!("protected content media layout is invalid"))?;
    if reconstructed != *media_identity {
        anyhow::bail!("protected content media identity is invalid");
    }
    Ok((protected_init, encrypted_segments))
}

/// The object directory's descriptor file, mirroring the role
/// `PROTECTED_CONTENT_IDENTITY_PATH`'s raw canonical bytes play for media,
/// but as JSON per the brief's exact schema. Every field is independently
/// derivable from `ChunkedPayloadObjectIdentityV1`, so — exactly like the
/// media descriptor — its bytes are fully deterministic from the identity
/// alone; no separate hash/length parameters are needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedContentObjectManifestV1 {
    schema: String,
    content_type: String,
    plaintext_bytes: u64,
    framed_header_bytes: u32,
    encrypted_content: ProtectedContentObjectManifestEncryptedContentV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedContentObjectManifestEncryptedContentV1 {
    sha256: String,
    bytes: u64,
}

fn protected_content_object_manifest_bytes(
    object_identity: &ChunkedPayloadObjectIdentityV1,
) -> anyhow::Result<Vec<u8>> {
    let manifest = ProtectedContentObjectManifestV1 {
        schema: PROTECTED_CONTENT_OBJECT_MANIFEST_SCHEMA_V1.to_string(),
        content_type: object_identity.content_type().to_string(),
        plaintext_bytes: object_identity.plaintext_bytes(),
        framed_header_bytes: object_identity.framed_header_bytes(),
        encrypted_content: ProtectedContentObjectManifestEncryptedContentV1 {
            sha256: hex::encode(
                object_identity
                    .encrypted_content()
                    .ciphertext_sha256()
                    .as_bytes(),
            ),
            bytes: object_identity.encrypted_content().ciphertext_bytes(),
        },
    };
    serde_json::to_vec(&manifest)
        .map_err(|_| anyhow::anyhow!("protected content object manifest is invalid"))
}

/// Object twin of `verify_protected_content_directory`. The media function is
/// untouched — this is a fully parallel path so a change here can never move
/// media-side behaviour.
fn verify_protected_content_object_directory(
    directory: &Path,
    object_identity: &ChunkedPayloadObjectIdentityV1,
) -> anyhow::Result<()> {
    let expected_files = object_protected_content_files(object_identity)?;
    let expected_paths: Vec<String> = expected_files
        .iter()
        .map(|file| file.path.clone())
        .collect();
    let actual_paths = protected_content_directory_files(directory)?;
    if actual_paths != expected_paths {
        anyhow::bail!("protected content directory layout is invalid");
    }
    let manifest_bytes = fs::read(directory.join(PROTECTED_CONTENT_OBJECT_MANIFEST_PATH))
        .map_err(|_| anyhow::anyhow!("protected content descriptor is unavailable"))?;
    if manifest_bytes != protected_content_object_manifest_bytes(object_identity)? {
        anyhow::bail!("protected content descriptor is invalid");
    }
    let (framed_sha256, framed_bytes) =
        sha256_file(&directory.join(PROTECTED_CONTENT_OBJECT_EPC1_PATH))
            .map_err(|_| anyhow::anyhow!("protected content object is unavailable"))?;
    if framed_bytes != object_identity.encrypted_content().ciphertext_bytes()
        || framed_sha256 != object_identity.encrypted_content().ciphertext_sha256()
    {
        anyhow::bail!("protected content object is invalid");
    }
    Ok(())
}

/// Hashes a file without holding it: the streamed twin of `fs::read` plus
/// `Sha256::digest`, so verifying a large object never buffers it.
fn sha256_file(path: &Path) -> anyhow::Result<(Digest32, u64)> {
    let mut file = fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let bytes = std::io::copy(&mut file, &mut hasher)?;
    Ok((Digest32::new(hasher.finalize().into()), bytes))
}

fn object_protected_content_files(
    object_identity: &ChunkedPayloadObjectIdentityV1,
) -> anyhow::Result<Vec<crate::content::ContentObjectFile>> {
    let manifest_bytes = protected_content_object_manifest_bytes(object_identity)?;
    let mut files = vec![
        content_object_file(PROTECTED_CONTENT_OBJECT_MANIFEST_PATH, &manifest_bytes),
        crate::content::ContentObjectFile {
            path: PROTECTED_CONTENT_OBJECT_EPC1_PATH.to_string(),
            sha256: hex::encode(
                object_identity
                    .encrypted_content()
                    .ciphertext_sha256()
                    .as_bytes(),
            ),
            size: object_identity.encrypted_content().ciphertext_bytes(),
        },
    ];
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn content_object_files_match(
    actual: &[crate::content::ContentObjectFile],
    expected: &[crate::content::ContentObjectFile],
) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            actual.path == expected.path
                && actual.sha256 == expected.sha256
                && actual.size == expected.size
        })
}

fn content_object_digest(files: &[crate::content::ContentObjectFile]) -> String {
    let mut hasher = sha2::Sha256::new();
    for file in files {
        hasher.update(file.path.as_bytes());
        hasher.update(b"\0");
        hasher.update(file.sha256.as_bytes());
        hasher.update(b"\0");
        hasher.update(file.size.to_string().as_bytes());
        hasher.update(b"\0");
    }
    format!("sha256:{:x}", hasher.finalize())
}

/// Which half of a v2 package a rendition's files live under, and the names
/// the runtime and the player speak for it.
fn runtime_media_dash_representation(kind: CencDashRenditionKindV2) -> &'static str {
    match kind {
        CencDashRenditionKindV2::Video => "video/avc1",
        CencDashRenditionKindV2::Audio => "audio/und/mp4a",
    }
}

fn runtime_media_dash_rendition_name(kind: CencDashRenditionKindV2) -> &'static str {
    match kind {
        CencDashRenditionKindV2::Video => "video",
        CencDashRenditionKindV2::Audio => "audio",
    }
}

pub(crate) fn runtime_media_dash_init_path(kind: CencDashRenditionKindV2) -> String {
    format!(
        "protected-content/v2/{}/init.mp4",
        runtime_media_dash_representation(kind)
    )
}

/// `index` is the Runtime's zero-based segment index; the file is `seg-(index+1)`
/// (unpadded, one-based; spec section 3).
pub(crate) fn runtime_media_dash_segment_path(kind: CencDashRenditionKindV2, index: u32) -> String {
    format!(
        "protected-content/v2/{}/seg-{}.m4s",
        runtime_media_dash_representation(kind),
        u64::from(index) + 1
    )
}

/// The head's segment counts, one per rendition in head order.
fn runtime_media_dash_counts(head: &CencDashMediaIdentityV2) -> Vec<u32> {
    head.renditions()
        .iter()
        .map(|rendition| rendition.segment_count())
        .collect()
}

/// The fixed interleave `read_viewer` walks: every init in rendition order,
/// then for each segment index the segment of every rendition that has one.
/// Returns `(rendition, None)` for an init and `(rendition, Some(segment))`
/// for a segment, or `None` past the last part.
fn runtime_media_dash_part(counts: &[u32], part: u32) -> Option<(u8, Option<u32>)> {
    let renditions = u32::try_from(counts.len()).ok()?;
    if part < renditions {
        return Some((u8::try_from(part).ok()?, None));
    }
    let q = part - renditions;
    match *counts {
        [only] => (q < only).then_some((0, Some(q))),
        [first, second] => {
            let shared = first.min(second);
            let paired = shared.checked_mul(2)?;
            if q < paired {
                Some((u8::try_from(q % 2).ok()?, Some(q / 2)))
            } else if q == paired && first != second {
                Some((u8::from(second > first), Some(shared)))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// How many parts the interleave has: every init plus every segment.
fn runtime_media_dash_part_count(counts: &[u32]) -> Option<u32> {
    counts
        .iter()
        .try_fold(u32::try_from(counts.len()).ok()?, |total, count| {
            total.checked_add(*count)
        })
}

/// Checks a v2 manifest against its head and returns each rendition's Merkle
/// leaves, from the manifest alone (no segment is fetched).
///
/// Fails closed unless the manifest lists exactly the identity, the MPD, every
/// init and `seg-1..=count` of every rendition, and each entry agrees with the
/// head: the identity and inits by hash and size, every segment by a leaf that
/// folds into the rendition's committed root. Files are found by path, never
/// by position, because `seg-10` sorts before `seg-2`. Every segment's bytes
/// are still proven at read time, by the decrypt provider, against that root.
pub(crate) fn verify_protected_content_dash_manifest(
    manifest: &crate::content::ContentObjectManifest,
    head: &CencDashMediaIdentityV2,
) -> anyhow::Result<Vec<Vec<Digest32>>> {
    const INVALID: &str = "protected content object manifest is invalid";
    if manifest.schema != "elastos.content.object.manifest/v1"
        || manifest.kind != PROTECTED_CONTENT_OBJECT_KIND
        || !manifest.links.is_empty()
        || !manifest
            .files
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
        || manifest.content_digest != content_object_digest(&manifest.files)
    {
        anyhow::bail!(INVALID);
    }
    let mut expected_files: u64 = 2;
    for rendition in head.renditions() {
        expected_files += 1 + u64::from(rendition.segment_count());
    }
    if manifest.files.len() as u64 != expected_files {
        anyhow::bail!(INVALID);
    }
    let by_path: BTreeMap<&str, &crate::content::ContentObjectFile> = manifest
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let entry = |path: &str| {
        by_path
            .get(path)
            .copied()
            .ok_or_else(|| anyhow::anyhow!(INVALID))
    };
    let matches = |file: &crate::content::ContentObjectFile, sha256: Digest32, size: u64| {
        file.size == size && file.sha256 == hex::encode(sha256.as_bytes())
    };
    let identity_bytes = head
        .canonical_bytes()
        .map_err(|_| anyhow::anyhow!(INVALID))?;
    if !matches(
        entry(PROTECTED_CONTENT_V2_IDENTITY_PATH)?,
        Digest32::new(sha2::Sha256::digest(&identity_bytes).into()),
        identity_bytes.len() as u64,
    ) {
        anyhow::bail!(INVALID);
    }
    entry(PROTECTED_CONTENT_V2_MPD_PATH)?;
    let mut all_leaves = Vec::with_capacity(head.renditions().len());
    for rendition in head.renditions() {
        let kind = rendition.kind();
        if !matches(
            entry(&runtime_media_dash_init_path(kind))?,
            rendition.init_segment_sha256(),
            rendition.init_segment_bytes(),
        ) {
            anyhow::bail!(INVALID);
        }
        let mut leaves = Vec::with_capacity(rendition.segment_count() as usize);
        for index in 0..rendition.segment_count() {
            let file = entry(&runtime_media_dash_segment_path(kind, index))?;
            let valid_hex = file.sha256.len() == 64
                && file
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
            // The size bound is what keeps a read inside the provider frame: a
            // listing that declares a larger segment is refused here, before
            // any payment or open.
            if file.size == 0
                || file.size > MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2 as u64
                || !valid_hex
            {
                anyhow::bail!(INVALID);
            }
            let sha256: [u8; 32] = hex::decode(&file.sha256)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!(INVALID))?;
            leaves.push(cenc_dash_segment_leaf_hash(
                kind,
                index,
                Digest32::new(sha256),
                file.size,
            ));
        }
        if cenc_dash_merkle_root(&leaves).map_err(|_| anyhow::anyhow!(INVALID))?
            != rendition.segments_root()
        {
            anyhow::bail!(INVALID);
        }
        all_leaves.push(leaves);
    }
    Ok(all_leaves)
}

fn runtime_rights_action_name(action: RightsActionV1) -> &'static str {
    match action {
        RightsActionV1::View => "view",
        RightsActionV1::Stream => "stream",
        RightsActionV1::Download => "download",
        RightsActionV1::Execute => "execute",
    }
}

fn decode_0x_hex(value: &str) -> Option<Vec<u8>> {
    let hex = value.strip_prefix("0x")?;
    hex::decode(hex).ok()
}

fn verify_protected_content_receipt(
    content_cid: &str,
    manifest: &crate::content::ContentObjectManifest,
    receipt_json: &[u8],
    media_identity: &CencFmp4MediaIdentityV1,
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: u64,
    publisher_binding: RuntimeManifestPublisherBinding,
) -> anyhow::Result<RuntimeVerifiedContentAvailability> {
    validate_protected_content_availability_requirement(requirement)?;
    cid::Cid::try_from(content_cid)
        .map_err(|_| anyhow::anyhow!("protected content availability CID is invalid"))?;
    let receipt: crate::content::SignedAvailabilityReceipt =
        serde_json::from_slice(receipt_json)
            .map_err(|_| anyhow::anyhow!("protected content availability receipt is invalid"))?;
    let receipt_json = serde_json::to_vec(&receipt)
        .map_err(|_| anyhow::anyhow!("protected content availability receipt is invalid"))?;
    if receipt.payload.schema != CONTENT_AVAILABILITY_RECEIPT_SCHEMA
        || receipt.signer_did != requirement.expected_provider_did()
        || receipt.payload.cid != content_cid
        || receipt.payload.uri != format!("elastos://{content_cid}")
        || receipt.payload.object_did.as_deref() != Some(requirement.expected_object_identity())
        || receipt.payload.publisher_did != requirement.expected_publisher_did()
        || receipt.payload.policy != requirement.policy()
        || !protected_content_availability_status_accepted(&receipt.payload.status, requirement)
        || receipt.payload.replicas < requirement.minimum_replicas()
        || (protected_content_live_proof_required(requirement.minimum_replicas())
            && receipt
                .payload
                .peer_selection
                .get("live_multi_peer_proof")
                .and_then(Value::as_bool)
                != Some(true))
        || manifest.object_did.as_deref() != Some(requirement.expected_object_identity())
        || !content_manifest_binds_publisher(manifest, requirement, publisher_binding)
    {
        anyhow::bail!("protected content availability receipt binding is invalid");
    }
    let max_checked_at = now_unix_seconds
        .checked_add(requirement.max_future_skew_seconds())
        .ok_or_else(|| anyhow::anyhow!("protected content availability time is invalid"))?;
    if receipt.payload.checked_at > max_checked_at
        || now_unix_seconds.saturating_sub(receipt.payload.checked_at)
            > requirement.max_age_seconds()
    {
        anyhow::bail!("protected content availability receipt is outside its freshness window");
    }
    crate::crypto::verify_signed_json_envelope_against_dids(
        &receipt_json,
        CONTENT_AVAILABILITY_RECEIPT_DOMAIN,
        std::slice::from_ref(&requirement.expected_provider_did().to_string()),
    )
    .map_err(|_| anyhow::anyhow!("protected content availability receipt signature is invalid"))?;
    RuntimeVerifiedContentAvailability::new(
        content_cid,
        requirement.expected_object_identity(),
        requirement.expected_publisher_did(),
        requirement,
        receipt.payload.replicas,
        receipt.payload.checked_at,
        Digest32::new(sha2::Sha256::digest(&receipt_json).into()),
        media_identity.encrypted_content().clone(),
        RuntimeVerifiedContentIdentityRootV1::for_media(media_identity),
    )
    .map_err(|_| anyhow::anyhow!("protected content availability evidence is invalid"))
}

/// Object twin of `verify_protected_content_receipt`. Identical in every
/// respect except the last three lines, which build the evidence's
/// `encrypted_content`/identity-root from a `ChunkedPayloadObjectIdentityV1`
/// instead of a `CencFmp4MediaIdentityV1` — the media function is untouched.
fn verify_protected_content_object_receipt(
    content_cid: &str,
    manifest: &crate::content::ContentObjectManifest,
    receipt_json: &[u8],
    object_identity: &ChunkedPayloadObjectIdentityV1,
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: u64,
    publisher_binding: RuntimeManifestPublisherBinding,
) -> anyhow::Result<RuntimeVerifiedContentAvailability> {
    validate_protected_content_availability_requirement(requirement)?;
    cid::Cid::try_from(content_cid)
        .map_err(|_| anyhow::anyhow!("protected content availability CID is invalid"))?;
    let receipt: crate::content::SignedAvailabilityReceipt =
        serde_json::from_slice(receipt_json)
            .map_err(|_| anyhow::anyhow!("protected content availability receipt is invalid"))?;
    let receipt_json = serde_json::to_vec(&receipt)
        .map_err(|_| anyhow::anyhow!("protected content availability receipt is invalid"))?;
    if receipt.payload.schema != CONTENT_AVAILABILITY_RECEIPT_SCHEMA
        || receipt.signer_did != requirement.expected_provider_did()
        || receipt.payload.cid != content_cid
        || receipt.payload.uri != format!("elastos://{content_cid}")
        || receipt.payload.object_did.as_deref() != Some(requirement.expected_object_identity())
        || receipt.payload.publisher_did != requirement.expected_publisher_did()
        || receipt.payload.policy != requirement.policy()
        || !protected_content_availability_status_accepted(&receipt.payload.status, requirement)
        || receipt.payload.replicas < requirement.minimum_replicas()
        || (protected_content_live_proof_required(requirement.minimum_replicas())
            && receipt
                .payload
                .peer_selection
                .get("live_multi_peer_proof")
                .and_then(Value::as_bool)
                != Some(true))
        || manifest.object_did.as_deref() != Some(requirement.expected_object_identity())
        || !content_manifest_binds_publisher(manifest, requirement, publisher_binding)
    {
        anyhow::bail!("protected content availability receipt binding is invalid");
    }
    let max_checked_at = now_unix_seconds
        .checked_add(requirement.max_future_skew_seconds())
        .ok_or_else(|| anyhow::anyhow!("protected content availability time is invalid"))?;
    if receipt.payload.checked_at > max_checked_at
        || now_unix_seconds.saturating_sub(receipt.payload.checked_at)
            > requirement.max_age_seconds()
    {
        anyhow::bail!("protected content availability receipt is outside its freshness window");
    }
    crate::crypto::verify_signed_json_envelope_against_dids(
        &receipt_json,
        CONTENT_AVAILABILITY_RECEIPT_DOMAIN,
        std::slice::from_ref(&requirement.expected_provider_did().to_string()),
    )
    .map_err(|_| anyhow::anyhow!("protected content availability receipt signature is invalid"))?;
    RuntimeVerifiedContentAvailability::new(
        content_cid,
        requirement.expected_object_identity(),
        requirement.expected_publisher_did(),
        requirement,
        receipt.payload.replicas,
        receipt.payload.checked_at,
        Digest32::new(sha2::Sha256::digest(&receipt_json).into()),
        object_identity.encrypted_content().clone(),
        RuntimeVerifiedContentIdentityRootV1::for_object(object_identity)
            .map_err(|_| anyhow::anyhow!("protected content availability evidence is invalid"))?,
    )
    .map_err(|_| anyhow::anyhow!("protected content availability evidence is invalid"))
}

/// DASH v2 twin of `verify_protected_content_receipt`. Identical in every
/// respect except the last two arguments, which build the evidence's
/// `encrypted_content` and identity root from the head -- the media function is
/// untouched.
fn verify_protected_content_dash_receipt(
    content_cid: &str,
    manifest: &crate::content::ContentObjectManifest,
    receipt_json: &[u8],
    head: &CencDashMediaIdentityV2,
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: u64,
    publisher_binding: RuntimeManifestPublisherBinding,
) -> anyhow::Result<RuntimeVerifiedContentAvailability> {
    validate_protected_content_availability_requirement(requirement)?;
    cid::Cid::try_from(content_cid)
        .map_err(|_| anyhow::anyhow!("protected content availability CID is invalid"))?;
    let receipt: crate::content::SignedAvailabilityReceipt =
        serde_json::from_slice(receipt_json)
            .map_err(|_| anyhow::anyhow!("protected content availability receipt is invalid"))?;
    let receipt_json = serde_json::to_vec(&receipt)
        .map_err(|_| anyhow::anyhow!("protected content availability receipt is invalid"))?;
    if receipt.payload.schema != CONTENT_AVAILABILITY_RECEIPT_SCHEMA
        || receipt.signer_did != requirement.expected_provider_did()
        || receipt.payload.cid != content_cid
        || receipt.payload.uri != format!("elastos://{content_cid}")
        || receipt.payload.object_did.as_deref() != Some(requirement.expected_object_identity())
        || receipt.payload.publisher_did != requirement.expected_publisher_did()
        || receipt.payload.policy != requirement.policy()
        || !protected_content_availability_status_accepted(&receipt.payload.status, requirement)
        || receipt.payload.replicas < requirement.minimum_replicas()
        || (protected_content_live_proof_required(requirement.minimum_replicas())
            && receipt
                .payload
                .peer_selection
                .get("live_multi_peer_proof")
                .and_then(Value::as_bool)
                != Some(true))
        || manifest.object_did.as_deref() != Some(requirement.expected_object_identity())
        || !content_manifest_binds_publisher(manifest, requirement, publisher_binding)
    {
        anyhow::bail!("protected content availability receipt binding is invalid");
    }
    let max_checked_at = now_unix_seconds
        .checked_add(requirement.max_future_skew_seconds())
        .ok_or_else(|| anyhow::anyhow!("protected content availability time is invalid"))?;
    if receipt.payload.checked_at > max_checked_at
        || now_unix_seconds.saturating_sub(receipt.payload.checked_at)
            > requirement.max_age_seconds()
    {
        anyhow::bail!("protected content availability receipt is outside its freshness window");
    }
    crate::crypto::verify_signed_json_envelope_against_dids(
        &receipt_json,
        CONTENT_AVAILABILITY_RECEIPT_DOMAIN,
        std::slice::from_ref(&requirement.expected_provider_did().to_string()),
    )
    .map_err(|_| anyhow::anyhow!("protected content availability receipt signature is invalid"))?;
    RuntimeVerifiedContentAvailability::new(
        content_cid,
        requirement.expected_object_identity(),
        requirement.expected_publisher_did(),
        requirement,
        receipt.payload.replicas,
        receipt.payload.checked_at,
        Digest32::new(sha2::Sha256::digest(&receipt_json).into()),
        head.encrypted_content().clone(),
        RuntimeVerifiedContentIdentityRootV1::for_media_dash(head),
    )
    .map_err(|_| anyhow::anyhow!("protected content availability evidence is invalid"))
}

/// Object twin of `verify_protected_content_manifest_and_files`. Each fetched
/// file is verified and dropped before the next one is fetched.
/// The manifest of an object item names exactly its identity's files.
fn protected_content_object_manifest_files(
    manifest: &crate::content::ContentObjectManifest,
    object_identity: &ChunkedPayloadObjectIdentityV1,
) -> anyhow::Result<Vec<crate::content::ContentObjectFile>> {
    let expected_files = object_protected_content_files(object_identity)?;
    if manifest.schema != "elastos.content.object.manifest/v1"
        || manifest.kind != PROTECTED_CONTENT_OBJECT_KIND
        || !manifest.links.is_empty()
        || !content_object_files_match(&manifest.files, &expected_files)
        || manifest.content_digest != content_object_digest(&expected_files)
    {
        anyhow::bail!("protected content object manifest is invalid");
    }
    Ok(expected_files)
}

async fn verify_protected_content_object_manifest_and_files(
    registry: &ProviderRegistry,
    content_cid: &str,
    manifest: &crate::content::ContentObjectManifest,
    object_identity: &ChunkedPayloadObjectIdentityV1,
) -> anyhow::Result<()> {
    let expected_files = protected_content_object_manifest_files(manifest, object_identity)?;
    for file in &expected_files {
        let bytes =
            crate::content::fetch_bytes_via_provider(registry, content_cid, Some(&file.path))
                .await?;
        crate::content::verify_content_object_file(content_cid, file, &bytes)?;
        if file.path == PROTECTED_CONTENT_OBJECT_MANIFEST_PATH
            && bytes != protected_content_object_manifest_bytes(object_identity)?
        {
            anyhow::bail!("protected content descriptor is invalid");
        }
    }
    Ok(())
}

/// Object twin of `publish_and_verify_protected_content_availability`.
pub async fn publish_and_verify_protected_content_object_availability(
    registry: &ProviderRegistry,
    protected_content_dir: &Path,
    object_identity: &ChunkedPayloadObjectIdentityV1,
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: impl Fn() -> u64,
) -> anyhow::Result<RuntimeVerifiedContentAvailability> {
    validate_protected_content_availability_requirement(requirement)?;
    verify_protected_content_object_directory(protected_content_dir, object_identity)?;
    let publish_requirements = crate::content::ContentPublishRequirements::new(
        requirement.minimum_replicas(),
        protected_content_live_proof_required(requirement.minimum_replicas()),
    )?
    .with_availability_policy(requirement.policy())?;
    // Each leg is timed separately. This step is the one a creator watches as
    // a stalled "Encrypt & escrow", and it is four different pieces of work:
    // publishing and replicating the ciphertext, then reading back a receipt,
    // a manifest and every file to prove it landed. Without this split the
    // only honest thing anyone can say about a slow publish is its total.
    let phase = RuntimeCustodyPhase::begin(
        "content_publish",
        protected_content_dir.display().to_string(),
    );
    let content_cid = crate::content::publish_directory_via_provider_with_kind_and_requirements(
        registry,
        protected_content_dir,
        PROTECTED_CONTENT_OBJECT_KIND,
        Some(requirement.expected_object_identity()),
        Some(requirement.expected_publisher_did()),
        publish_requirements,
    )
    .await?;
    phase.ok();
    let phase = RuntimeCustodyPhase::begin("availability_receipt", &content_cid);
    let receipt = fetch_content_availability_receipt(registry, &content_cid).await?;
    phase.ok();
    let phase = RuntimeCustodyPhase::begin("object_manifest", &content_cid);
    let manifest = crate::content::fetch_content_object_manifest(registry, &content_cid).await?;
    phase.ok();
    let phase = RuntimeCustodyPhase::begin("object_files_verify", &content_cid);
    verify_protected_content_object_manifest_and_files(
        registry,
        &content_cid,
        &manifest,
        object_identity,
    )
    .await?;
    phase.ok();
    let now_unix_seconds = now_unix_seconds();
    verify_protected_content_object_receipt(
        &content_cid,
        &manifest,
        &receipt,
        object_identity,
        requirement,
        now_unix_seconds,
        RuntimeManifestPublisherBinding::Exact,
    )
}

#[derive(Debug)]
struct RuntimePreparedLibraryPublish {
    input: RuntimeCustodyLibraryPublishInput,
    request_id: Digest32,
    output_receipt_digest: Digest32,
    operation_root: PathBuf,
}

/// Both payloads are boxed. Each is large on its own — `Prepared` carries a
/// whole publish input including the listing terms, `Consumed` a preparation
/// record — so leaving either inline sizes every value of this enum, and the
/// common case, for the bigger of the two.
#[derive(Debug)]
enum RuntimeLibraryMediaPreparation {
    Prepared(Box<RuntimePreparedLibraryPublish>),
    Consumed {
        record: Box<RuntimeMediaPreparationRecord>,
        operation_root: PathBuf,
    },
}

enum RuntimeMediaProviderPrepareError {
    Settled,
    Unknown,
}

fn runtime_media_staging_root(data_dir: &Path) -> PathBuf {
    data_dir
        .join(PROTECTED_CONTENT_ROOT)
        .join("media-provider")
        .join("staging")
}

fn runtime_media_private_state_error(_reason: String) -> anyhow::Error {
    anyhow::anyhow!("Runtime custody media preparation private state is invalid")
}

fn validate_runtime_media_staging_root(staging_root: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(staging_root)
        .map_err(|_| runtime_media_private_state_error(String::new()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("Runtime custody media preparation private state is invalid");
    }
    validate_owner_only_metadata_with_error(
        "media-provider staging root",
        &metadata,
        false,
        runtime_media_private_state_error,
    )
}

/// Reads the creator's source object for media preparation through the
/// principal-root object path. A protected root (recovery activated) stores
/// every object as an encrypted `elastos.principal-root.object/v1` envelope,
/// which a raw file copy would hand to the media provider as ciphertext; an
/// unprotected root passes through unchanged. The whole object is held in
/// memory because a protected object is one AES-GCM envelope and cannot be
/// streamed. There is no size cap here: a protected root is read whole by the
/// principal-root object path, whose own limits are the protocol's.
fn read_runtime_media_source(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
    source_file_path: &Path,
) -> anyhow::Result<Vec<u8>> {
    const MESSAGE: &str = "Runtime custody media preparation input is invalid";
    let source = open_runtime_media_source_file(source_file_path)?;
    let stored_len = source
        .metadata()
        .map_err(|error| anyhow::Error::new(error).context(MESSAGE))?
        .len();
    drop(source);
    if stored_len == 0 {
        return Err(anyhow::anyhow!("stored source is empty").context(MESSAGE));
    }
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    let bytes = crate::auth::read_principal_root_object(
        data_dir,
        principal_id,
        &localhost_root,
        object_uri,
        source_file_path,
    )
    .map_err(|error| {
        tracing::warn!(
            %object_uri,
            error = ?error,
            "runtime custody media preparation: source object is unreadable"
        );
        error.context(MESSAGE)
    })?;
    if bytes.is_empty() {
        return Err(anyhow::anyhow!("source plaintext is empty").context(MESSAGE));
    }
    Ok(bytes)
}

/// Object twin of `read_runtime_media_source`'s read (not its media-specific
/// stored-length preflight, which does not apply to a plain uploaded file):
/// reads the principal-scoped object and refuses only an empty one. Minting
/// applies no size bound; the read itself is `auth.rs`'s (#444).
pub(crate) fn read_runtime_object_source(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
    source_file_path: &Path,
) -> anyhow::Result<Vec<u8>> {
    const MESSAGE: &str = "Runtime custody object publish input is invalid";
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    let bytes = crate::auth::read_principal_root_object(
        data_dir,
        principal_id,
        &localhost_root,
        object_uri,
        source_file_path,
    )
    .map_err(|error| {
        tracing::warn!(
            %object_uri,
            error = ?error,
            "runtime custody object publish: source object is unreadable"
        );
        error.context(MESSAGE)
    })?;
    if bytes.is_empty() {
        return Err(anyhow::anyhow!("source plaintext is empty").context(MESSAGE));
    }
    Ok(bytes)
}

fn runtime_media_source_digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(sha2::Sha256::digest(bytes).into())
}

fn reset_runtime_media_operation_root(operation_root: &Path) -> anyhow::Result<()> {
    if operation_root.exists() {
        let metadata = fs::symlink_metadata(operation_root)
            .map_err(|_| runtime_media_private_state_error(String::new()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            anyhow::bail!("Runtime custody media preparation private state is invalid");
        }
        fs::remove_dir_all(operation_root)
            .map_err(|_| runtime_media_private_state_error(String::new()))?;
    }
    fs::create_dir(operation_root).map_err(|_| runtime_media_private_state_error(String::new()))?;
    #[cfg(unix)]
    fs::set_permissions(operation_root, fs::Permissions::from_mode(0o700))
        .map_err(|_| runtime_media_private_state_error(String::new()))?;
    Ok(())
}

/// Stages the already-read source bytes as the media provider's input file.
/// The digest is re-checked here so the staged file is provably the bytes the
/// preparation record was keyed on.
fn stage_runtime_media_provider_input(
    source_bytes: &[u8],
    destination_path: &Path,
    expected_digest: Digest32,
) -> anyhow::Result<()> {
    if source_bytes.is_empty() || runtime_media_source_digest(source_bytes) != expected_digest {
        anyhow::bail!("Runtime custody media preparation input is invalid");
    }
    let mut destination = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination_path)
        .map_err(|_| runtime_media_private_state_error(String::new()))?;
    #[cfg(unix)]
    fs::set_permissions(destination_path, fs::Permissions::from_mode(0o600))
        .map_err(|_| runtime_media_private_state_error(String::new()))?;
    destination
        .write_all(source_bytes)
        .map_err(|_| runtime_media_private_state_error(String::new()))?;
    destination
        .sync_all()
        .map_err(|_| runtime_media_private_state_error(String::new()))?;
    Ok(())
}

#[cfg(unix)]
fn open_runtime_media_source_file(path: &Path) -> anyhow::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation input is invalid"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation input is invalid"))?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        anyhow::bail!("Runtime custody media preparation input is invalid");
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_runtime_media_source_file(path: &Path) -> anyhow::Result<fs::File> {
    let file = fs::File::open(path)
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation input is invalid"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation input is invalid"))?;
    if !metadata.is_file() {
        anyhow::bail!("Runtime custody media preparation input is invalid");
    }
    Ok(file)
}

fn invalid_prepared_media_output() -> anyhow::Error {
    anyhow::anyhow!("Runtime custody media preparation output is invalid")
}

/// Refuses a prepared output for `reason`, which only the operator log carries:
/// the caller sees the same fail-closed message whatever was wrong.
fn refuse_prepared_media_output(reason: &str) -> anyhow::Error {
    tracing::warn!(reason, "runtime custody media preparation output refused");
    invalid_prepared_media_output()
}

fn runtime_media_dash_rendition_kind(name: &str) -> Option<CencDashRenditionKindV2> {
    [
        CencDashRenditionKindV2::Video,
        CencDashRenditionKindV2::Audio,
    ]
    .into_iter()
    .find(|kind| runtime_media_dash_rendition_name(*kind) == name)
}

/// The prepared directory of one rendition: `prepared/<rendition>`.
fn runtime_prepared_rendition_dir(operation_root: &Path, kind: CencDashRenditionKindV2) -> PathBuf {
    operation_root
        .join(MEDIA_PROVIDER_PREPARED_DIR_NAME)
        .join(runtime_media_dash_rendition_name(kind))
}

/// One clear media part: `prepared/<rendition>/segments/NNNNNNNN.m4s`.
fn runtime_prepared_segment_path(
    operation_root: &Path,
    kind: CencDashRenditionKindV2,
    index: u32,
) -> PathBuf {
    runtime_prepared_rendition_dir(operation_root, kind)
        .join(MEDIA_PROVIDER_SEGMENTS_DIR_NAME)
        .join(format!("{index:08}.m4s"))
}

/// The name and metadata of every entry of `directory`, links not followed.
fn prepared_directory_entries(directory: &Path) -> anyhow::Result<Vec<(String, fs::Metadata)>> {
    fs::read_dir(directory)
        .map_err(|_| invalid_prepared_media_output())?
        .map(|entry| {
            let entry = entry.map_err(|_| invalid_prepared_media_output())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid_prepared_media_output())?;
            let metadata =
                fs::symlink_metadata(entry.path()).map_err(|_| invalid_prepared_media_output())?;
            if metadata.file_type().is_symlink() {
                return Err(refuse_prepared_media_output("a prepared entry is a link"));
            }
            Ok((name, metadata))
        })
        .collect()
}

fn require_private_prepared_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid_prepared_media_output())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(refuse_prepared_media_output(
            "a prepared directory is a link",
        ));
    }
    validate_owner_only_metadata_with_error(
        label,
        &metadata,
        false,
        runtime_media_private_state_error,
    )
    .map_err(|_| invalid_prepared_media_output())
}

/// The preparation receipt, fed one part at a time so it never needs the media
/// in memory: `SHA-256(domain || u8 n || per rendition: u8 kind || mime || 0 ||
/// codecs || 0 || u64 init_len || sha256(init) || u64 segment_count || per
/// segment: u64 index || u64 len || sha256(segment))`.
struct RuntimeMediaPreparationReceiptV2(sha2::Sha256);

impl RuntimeMediaPreparationReceiptV2 {
    fn new(rendition_count: usize) -> anyhow::Result<Self> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(RUNTIME_MEDIA_PREPARATION_RECEIPT_DOMAIN);
        hasher
            .update([u8::try_from(rendition_count).map_err(|_| invalid_prepared_media_output())?]);
        Ok(Self(hasher))
    }

    fn begin_rendition(
        &mut self,
        kind: CencDashRenditionKindV2,
        clear_init_segment: &[u8],
        segment_count: u32,
    ) {
        let (mime_type, codecs) = pinned_declaration_v2(kind);
        self.0.update([kind.code()]);
        self.0.update(mime_type.as_bytes());
        self.0.update([0]);
        self.0.update(codecs.as_bytes());
        self.0.update([0]);
        self.0
            .update((clear_init_segment.len() as u64).to_be_bytes());
        self.0.update(sha2::Sha256::digest(clear_init_segment));
        self.0.update(u64::from(segment_count).to_be_bytes());
    }

    fn push_segment(&mut self, index: u32, segment: &[u8]) {
        self.0.update(u64::from(index).to_be_bytes());
        self.0.update((segment.len() as u64).to_be_bytes());
        self.0.update(sha2::Sha256::digest(segment));
    }

    fn finish(self) -> Digest32 {
        Digest32::new(self.0.finalize().into())
    }
}

/// One prepared rendition as the publish keeps it: only its clear init segment,
/// which is small. Its segments stay on disk and are read one at a time.
#[derive(Clone)]
struct RuntimePreparedRenditionV2 {
    kind: CencDashRenditionKindV2,
    clear_init_segment: Vec<u8>,
    timescale: u32,
    segment_count: u32,
}

/// A validated v2 preparation: where the clear parts are and what binds them,
/// never the parts themselves. Memory is bounded by the inits whatever the
/// duration; the mint reads one part at a time.
#[derive(Clone)]
pub(crate) struct RuntimePreparedMediaV2 {
    operation_root: PathBuf,
    renditions: Vec<RuntimePreparedRenditionV2>,
    preparation_receipt: Digest32,
    clear_bytes: u64,
    /// How many segment files the protect loop has read, so a test can show that
    /// a part is read, protected and dropped before the next is read.
    #[cfg(test)]
    part_reads: Arc<std::sync::atomic::AtomicUsize>,
}

impl RuntimePreparedMediaV2 {
    /// The empty value of a preparation that was already consumed: nothing is
    /// on disk and nothing will be read.
    fn settled() -> Self {
        Self {
            operation_root: PathBuf::new(),
            renditions: Vec::new(),
            preparation_receipt: Digest32::new([0; 32]),
            clear_bytes: 0,
            #[cfg(test)]
            part_reads: Arc::default(),
        }
    }

    pub(crate) fn preparation_receipt(&self) -> Digest32 {
        self.preparation_receipt
    }

    /// Size of the clear media: every init plus every segment.
    pub(crate) fn clear_bytes(&self) -> u64 {
        self.clear_bytes
    }

    #[cfg(test)]
    pub(crate) fn part_reads(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        Arc::clone(&self.part_reads)
    }
}

impl std::fmt::Debug for RuntimePreparedMediaV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimePreparedMediaV2")
            .field(
                "renditions",
                &self
                    .renditions
                    .iter()
                    .map(|rendition| (rendition.kind, rendition.segment_count))
                    .collect::<Vec<_>>(),
            )
            .field("clear_bytes", &self.clear_bytes)
            .finish()
    }
}

/// What the media provider reports it prepared.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimePreparedMediaProviderOutputV2 {
    schema: String,
    renditions: Vec<RuntimePreparedMediaProviderRenditionV2>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimePreparedMediaProviderRenditionV2 {
    rendition: String,
    mime_type: String,
    codecs: String,
    segment_count: u32,
}

impl RuntimePreparedMediaProviderOutputV2 {
    /// The renditions it declares as `(kind, segment count)`: the v2 schema,
    /// one or two renditions with video first, and each one's pinned pair.
    fn declared_renditions(&self) -> anyhow::Result<Vec<(CencDashRenditionKindV2, u32)>> {
        if self.schema != MEDIA_PROVIDER_PREPARED_MEDIA_SCHEMA_V2 {
            return Err(refuse_prepared_media_output("the output schema is not v2"));
        }
        let mut declared = Vec::with_capacity(self.renditions.len());
        for rendition in &self.renditions {
            let kind = runtime_media_dash_rendition_kind(&rendition.rendition)
                .ok_or_else(|| refuse_prepared_media_output("an unknown rendition"))?;
            let (mime_type, codecs) = pinned_declaration_v2(kind);
            if rendition.mime_type != mime_type
                || rendition.codecs != codecs
                || rendition.segment_count == 0
                || declared.last().is_some_and(|(last, _)| *last >= kind)
            {
                return Err(refuse_prepared_media_output(
                    "a rendition is not the pinned pair, is empty, or is out of order",
                ));
            }
            declared.push((kind, rendition.segment_count));
        }
        if declared.is_empty() {
            return Err(refuse_prepared_media_output("no rendition"));
        }
        Ok(declared)
    }
}

/// Whether `operation_root` holds the output of the v1 media writer, whose one
/// rendition sat directly in `prepared/` (`prepared/init.mp4`).
fn runtime_prepared_output_is_v1_shaped(operation_root: &Path) -> bool {
    fs::symlink_metadata(
        operation_root
            .join(MEDIA_PROVIDER_PREPARED_DIR_NAME)
            .join("init.mp4"),
    )
    .is_ok()
}

/// Re-reads an already-settled preparation on resume. The durable record binds
/// the receipt, which covers every kind, pair, init and segment, so the files on
/// disk are loaded as they are and only an exact match is accepted.
fn load_settled_runtime_prepared_media_v2(
    operation_root: &Path,
    recorded_receipt: Digest32,
) -> anyhow::Result<RuntimePreparedMediaV2> {
    let media = load_runtime_prepared_media_v2(operation_root, None)?;
    if media.preparation_receipt != recorded_receipt {
        return Err(refuse_prepared_media_output(
            "the prepared files differ from the recorded receipt",
        ));
    }
    Ok(media)
}

/// Validates what the media provider just prepared against what it declared.
fn load_validated_runtime_prepared_media_v2(
    operation_root: &Path,
    prepared_output: &RuntimePreparedMediaProviderOutputV2,
) -> anyhow::Result<RuntimePreparedMediaV2> {
    let declared = prepared_output.declared_renditions()?;
    load_runtime_prepared_media_v2(operation_root, Some(&declared))
}

/// Loads `prepared/<rendition>/{init.mp4,segments/NNNNNNNN.m4s}` for every
/// rendition present, holding one part at a time. The kinds come from the
/// directories that exist, so a resume needs no declaration; a fresh output must
/// match its declaration exactly. Fails closed on anything else in the tree.
fn load_runtime_prepared_media_v2(
    operation_root: &Path,
    declared: Option<&[(CencDashRenditionKindV2, u32)]>,
) -> anyhow::Result<RuntimePreparedMediaV2> {
    let prepared_root = operation_root.join(MEDIA_PROVIDER_PREPARED_DIR_NAME);
    require_private_prepared_directory(&prepared_root, "media-provider prepared output root")?;
    let mut kinds = Vec::new();
    for (name, metadata) in prepared_directory_entries(&prepared_root)? {
        match runtime_media_dash_rendition_kind(&name) {
            Some(kind) if metadata.is_dir() => kinds.push(kind),
            _ => {
                return Err(refuse_prepared_media_output(
                    "an unexpected entry in prepared/",
                ))
            }
        }
    }
    kinds.sort_unstable();
    if kinds.is_empty()
        || declared.is_some_and(|declared| {
            declared.iter().map(|(kind, _)| *kind).collect::<Vec<_>>() != kinds
        })
    {
        return Err(refuse_prepared_media_output(
            "the rendition directories differ from the declaration",
        ));
    }
    let mut receipt = RuntimeMediaPreparationReceiptV2::new(kinds.len())?;
    let mut renditions = Vec::with_capacity(kinds.len());
    let mut clear_bytes = 0u64;
    for (position, kind) in kinds.iter().copied().enumerate() {
        let rendition_dir = runtime_prepared_rendition_dir(operation_root, kind);
        require_private_prepared_directory(&rendition_dir, "media-provider prepared rendition")?;
        let (mut saw_init, mut saw_segments) = (false, false);
        for (name, metadata) in prepared_directory_entries(&rendition_dir)? {
            match name.as_str() {
                "init.mp4" if metadata.is_file() => saw_init = true,
                MEDIA_PROVIDER_SEGMENTS_DIR_NAME if metadata.is_dir() => saw_segments = true,
                _ => {
                    return Err(refuse_prepared_media_output(
                        "an unexpected entry in a rendition",
                    ))
                }
            }
        }
        if !saw_init || !saw_segments {
            return Err(refuse_prepared_media_output(
                "a rendition lacks its init or segments",
            ));
        }
        let clear_init_segment = read_runtime_media_prepared_part(
            &rendition_dir.join("init.mp4"),
            true,
            MEDIA_PROVIDER_MAX_PREPARED_PART_BYTES_V2,
        )?;
        let session = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
            &clear_init_segment,
            CencLayoutProfile::V2,
        )
        .map_err(|_| refuse_prepared_media_output("an init does not validate under V2"))?;
        let track = session
            .rendition()
            .filter(|track| track.kind() == kind)
            .ok_or_else(|| {
                refuse_prepared_media_output("an init is not of its rendition's kind")
            })?;
        let timescale = track.timescale();
        let segments_root = rendition_dir.join(MEDIA_PROVIDER_SEGMENTS_DIR_NAME);
        require_private_prepared_directory(&segments_root, "media-provider prepared segments")?;
        let mut indexes = Vec::new();
        for (name, metadata) in prepared_directory_entries(&segments_root)? {
            if !metadata.is_file() {
                return Err(refuse_prepared_media_output("a segment is not a file"));
            }
            indexes.push(parse_runtime_media_segment_name(&name)?);
        }
        indexes.sort_unstable();
        if indexes
            .iter()
            .enumerate()
            .any(|(expected, actual)| *actual as usize != expected)
        {
            return Err(refuse_prepared_media_output(
                "segment names are not 0..count",
            ));
        }
        let segment_count =
            u32::try_from(indexes.len()).map_err(|_| invalid_prepared_media_output())?;
        if segment_count == 0
            || declared.is_some_and(|declared| declared[position].1 != segment_count)
        {
            return Err(refuse_prepared_media_output(
                "the segment files differ from the declared count",
            ));
        }
        receipt.begin_rendition(kind, &clear_init_segment, segment_count);
        clear_bytes = clear_bytes.saturating_add(clear_init_segment.len() as u64);
        // The package timeline starts at zero and has no gap, which is what
        // the MPD writer needs (it never shifts a start time).
        let mut expected_decode_time = 0u64;
        for index in 0..segment_count {
            let bytes = read_runtime_media_prepared_part(
                &runtime_prepared_segment_path(operation_root, kind, index),
                true,
                MEDIA_PROVIDER_MAX_PREPARED_PART_BYTES_V2,
            )?;
            let timeline = session
                .validate_segment(&bytes)
                .ok()
                .and_then(|layout| layout.timeline())
                .ok_or_else(|| {
                    refuse_prepared_media_output("a segment does not validate under V2")
                })?;
            if timeline.decode_time != expected_decode_time || timeline.duration == 0 {
                return Err(refuse_prepared_media_output(
                    "a rendition does not start at zero, has a gap, or has an empty segment",
                ));
            }
            expected_decode_time = timeline
                .decode_time
                .checked_add(timeline.duration)
                .ok_or_else(invalid_prepared_media_output)?;
            receipt.push_segment(index, &bytes);
            clear_bytes = clear_bytes.saturating_add(bytes.len() as u64);
        }
        renditions.push(RuntimePreparedRenditionV2 {
            kind,
            clear_init_segment,
            timescale,
            segment_count,
        });
    }
    // The head's own rules for the rendition set (order, skew, counts), asked of
    // the builder that will write it rather than restated here.
    CencDashIdentityBuilderV2::new(
        ContentAccessIdV1::new([1; 16]).map_err(|_| invalid_prepared_media_output())?,
        renditions
            .iter()
            .map(|rendition| {
                CencDashRenditionDeclV2::from_init(
                    rendition.kind,
                    rendition.timescale,
                    &rendition.clear_init_segment,
                    rendition.segment_count,
                )
            })
            .collect(),
    )
    .map_err(|_| refuse_prepared_media_output("the renditions do not form a valid set"))?;
    Ok(RuntimePreparedMediaV2 {
        operation_root: operation_root.to_path_buf(),
        renditions,
        preparation_receipt: receipt.finish(),
        clear_bytes,
        #[cfg(test)]
        part_reads: Arc::default(),
    })
}

fn read_runtime_media_prepared_part(
    path: &Path,
    require_non_empty: bool,
    max_output_part_bytes: u64,
) -> anyhow::Result<Vec<u8>> {
    #[cfg(unix)]
    let file = {
        let mut options = fs::OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        options
            .open(path)
            .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?
    };
    #[cfg(not(unix))]
    let file = fs::File::open(path)
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        anyhow::bail!("Runtime custody media preparation output is invalid");
    }
    if !metadata.is_file()
        || metadata.len() > max_output_part_bytes
        || (require_non_empty && metadata.len() == 0)
    {
        anyhow::bail!("Runtime custody media preparation output is invalid");
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    std::io::Read::take(file, max_output_part_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
    if bytes.len() as u64 > max_output_part_bytes || (require_non_empty && bytes.is_empty()) {
        anyhow::bail!("Runtime custody media preparation output is invalid");
    }
    Ok(bytes)
}

fn parse_runtime_media_segment_name(name: &str) -> anyhow::Result<u32> {
    let Some(index) = name.strip_suffix(".m4s") else {
        anyhow::bail!("Runtime custody media preparation output is invalid");
    };
    if index.len() != 8 || !index.as_bytes().iter().all(u8::is_ascii_digit) {
        anyhow::bail!("Runtime custody media preparation output is invalid");
    }
    index
        .parse::<u32>()
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))
}

async fn invoke_runtime_media_provider_prepare(
    registry: &ProviderRegistry,
    operation_id: Digest32,
) -> Result<RuntimePreparedMediaProviderOutputV2, RuntimeMediaProviderPrepareError> {
    let response = registry
        .invoke_provider(ProviderInvocation {
            source: RUNTIME_PROVIDER_ID.to_string(),
            target: MEDIA_PROVIDER_ID.to_string(),
            op: "prepare".to_string(),
            request: json!({
                "op": "prepare",
                "operation_id": hex::encode(operation_id.as_bytes()),
            }),
            transfer: ProviderTransfer::Json,
            range: None,
            progress: None,
            transport: ProviderInvocationTransport::Local,
        })
        .await
        .map_err(|_| RuntimeMediaProviderPrepareError::Unknown)?;
    match response.get("status").and_then(Value::as_str) {
        Some("ok") => response
            .get("data")
            .cloned()
            .ok_or(RuntimeMediaProviderPrepareError::Settled)
            .and_then(|data| {
                serde_json::from_value(data).map_err(|_| RuntimeMediaProviderPrepareError::Settled)
            }),
        Some("error")
            if response
                .get("data")
                .and_then(|data| data.get("operation_settled"))
                .and_then(Value::as_bool)
                == Some(true) =>
        {
            Err(RuntimeMediaProviderPrepareError::Settled)
        }
        _ => Err(RuntimeMediaProviderPrepareError::Unknown),
    }
}

/// Where a creator publish takes its mint terms from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyCreatorTermsSource {
    /// The terms the request carries: a new attempt, or a retry at the same
    /// terms.
    #[default]
    Requested,
    /// The terms already recorded for this mint, which is what Resume means.
    /// Nothing the request carries about terms is read.
    Recorded,
}

/// The publish-input fields the creator tail (chain mint, metadata, listing)
/// actually reads. Both publish inputs project into it, so the tail is one
/// kind-agnostic function instead of a media copy and an object copy:
/// everything kind-specific it needs, it reads from the persisted mint draft.
#[derive(Clone)]
pub(crate) struct RuntimeCustodyCreatorTailInput {
    pub object_uri: String,
    pub principal_id: String,
    pub wallet_account_id: String,
    pub wallet_account_address: String,
    pub creator_mint_source_digest: Digest32,
    pub copies: String,
    /// What a buyer pays for one copy, as a decimal amount of the pay token --
    /// scaled to its base units where the token's decimals are known, which is
    /// not here.
    pub price: String,
    /// The channel this mint publishes into. Never empty: a publish that named
    /// none was refused at the library boundary.
    pub channel: String,
    /// The token the sale is priced in. Empty means the mint source's first
    /// offered token.
    pub pay_token: String,

    /// The listing a marketplace displays. `None` keeps the pre-listing
    /// behaviour: a mint with no Elacity metadata folder.
    pub listing: Option<crate::library::RuntimeCustodyListingTerms>,
    /// Size of the CLEAR content, which both `metadata.json` and
    /// `content.json` state. It is computed here from the bytes the publish
    /// actually carried, because it is not recoverable later: the content
    /// identity reachable at the metadata site exposes the content type and
    /// the chunk count, never the plaintext length, and the mint intent that
    /// does record it is keyed by request id rather than mint id.
    pub plaintext_bytes: u64,
    pub terms_source: RuntimeCustodyCreatorTermsSource,
    /// Where the source lives, which with the object and the principal names
    /// the attempt a conflicting new mint sets aside.
    pub source_storage: String,
}

impl std::fmt::Debug for RuntimeCustodyCreatorTailInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeCustodyCreatorTailInput")
            .field("object_uri", &self.object_uri)
            .field("principal_id", &self.principal_id)
            .field("wallet_account_id", &"[redacted]")
            .field("wallet_account_address", &"[redacted]")
            .field(
                "creator_mint_source_digest",
                &self.creator_mint_source_digest,
            )
            .field("copies", &self.copies)
            .field("price", &self.price)
            .finish()
    }
}

impl From<&RuntimeCustodyLibraryPublishInput> for RuntimeCustodyCreatorTailInput {
    fn from(input: &RuntimeCustodyLibraryPublishInput) -> Self {
        Self {
            object_uri: input.object_uri.clone(),
            principal_id: input.principal_id.clone(),
            wallet_account_id: input.wallet_account_id.clone(),
            wallet_account_address: input.wallet_account_address.clone(),
            creator_mint_source_digest: input.creator_mint_source_digest,
            copies: input.copies.clone(),
            price: input.price.clone(),
            channel: input.channel.clone(),
            pay_token: input.pay_token.clone(),
            listing: input.listing.clone(),
            // The prepared renditions: every init segment plus every media
            // segment.
            plaintext_bytes: input.media.clear_bytes(),
            terms_source: RuntimeCustodyCreatorTermsSource::Requested,
            source_storage: input.source_storage.clone(),
        }
    }
}

impl From<&RuntimeCustodyLibraryPublishObjectInput> for RuntimeCustodyCreatorTailInput {
    fn from(input: &RuntimeCustodyLibraryPublishObjectInput) -> Self {
        Self {
            object_uri: input.object_uri.clone(),
            principal_id: input.principal_id.clone(),
            wallet_account_id: input.wallet_account_id.clone(),
            wallet_account_address: input.wallet_account_address.clone(),
            creator_mint_source_digest: input.creator_mint_source_digest,
            copies: input.copies.clone(),
            price: input.price.clone(),
            channel: input.channel.clone(),
            pay_token: input.pay_token.clone(),
            listing: input.listing.clone(),
            plaintext_bytes: input.clear_plaintext.len() as u64,
            terms_source: RuntimeCustodyCreatorTermsSource::Requested,
            source_storage: input.source_storage.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct RuntimeCustodyLibraryPublishInput {
    pub object_uri: String,
    pub principal_id: String,
    pub wallet_account_id: String,
    pub wallet_account_address: String,
    pub creator_mint_source_digest: Digest32,
    pub copies: String,
    /// What a buyer pays for one copy, as a decimal amount of the pay token --
    /// scaled to its base units where the token's decimals are known, which is
    /// not here.
    pub price: String,
    /// The channel this mint publishes into. Never empty: a publish that named
    /// none was refused at the library boundary.
    pub channel: String,
    /// The token the sale is priced in. Empty means the mint source's first
    /// offered token.
    pub pay_token: String,

    /// The validated clear media, which the mint streams from disk one part at
    /// a time.
    pub media: RuntimePreparedMediaV2,
    pub source_storage: String,
    pub listing: Option<crate::library::RuntimeCustodyListingTerms>,
    /// Plan B S7-lite T7.6: the pool this mint goes into; `None` is this
    /// Home's own pool, else the only pool that admits it.
    pub pool_did: Option<String>,
}

/// Object twin of `RuntimeCustodyLibraryPublishInput`. Deliberately a
/// separate type rather than an enum-widening of the media struct: every one
/// of that struct's ~15 production call sites (segment protection, mint
/// intent construction, staging directory writer, Debug impl) would need a
/// match arm added regardless of which shape is chosen, and a fully separate
/// type means the media struct and every function taking it verbatim by
/// reference stays completely untouched — the safest way to guarantee the
/// media path's behaviour cannot move.
#[derive(Clone)]
pub(crate) struct RuntimeCustodyLibraryPublishObjectInput {
    pub object_uri: String,
    pub principal_id: String,
    pub content_type: String,
    pub wallet_account_id: String,
    pub wallet_account_address: String,
    pub creator_mint_source_digest: Digest32,
    pub copies: String,
    /// What a buyer pays for one copy, as a decimal amount of the pay token --
    /// scaled to its base units where the token's decimals are known, which is
    /// not here.
    pub price: String,
    /// The channel this mint publishes into. Never empty: a publish that named
    /// none was refused at the library boundary.
    pub channel: String,
    /// The token the sale is priced in. Empty means the mint source's first
    /// offered token.
    pub pay_token: String,

    pub clear_plaintext: Vec<u8>,
    pub source_storage: String,
    pub listing: Option<crate::library::RuntimeCustodyListingTerms>,
    /// Plan B S7-lite T7.6: the pool this mint goes into; `None` is this
    /// Home's own pool, else the only pool that admits it.
    pub pool_did: Option<String>,
}

impl std::fmt::Debug for RuntimeCustodyLibraryPublishObjectInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeCustodyLibraryPublishObjectInput")
            .field("object_uri", &self.object_uri)
            .field("principal_id", &self.principal_id)
            .field("content_type", &self.content_type)
            .field("wallet_account_id", &"[redacted]")
            .field("wallet_account_address", &"[redacted]")
            .field(
                "creator_mint_source_digest",
                &self.creator_mint_source_digest,
            )
            .field("copies", &self.copies)
            .field("price", &self.price)
            .field("clear_plaintext_bytes", &self.clear_plaintext.len())
            .field("source_storage", &self.source_storage)
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct RuntimeCustodyLibrarySourceInput {
    pub object_uri: String,
    pub principal_id: String,
    pub source_file_path: PathBuf,
    pub wallet_account_id: String,
    pub wallet_account_address: String,
    pub creator_mint_source_digest: Digest32,
    pub copies: String,
    /// What a buyer pays for one copy, as a decimal amount of the pay token --
    /// scaled to its base units where the token's decimals are known, which is
    /// not here.
    pub price: String,
    /// The channel this mint publishes into. Never empty: a publish that named
    /// none was refused at the library boundary.
    pub channel: String,
    /// The token the sale is priced in. Empty means the mint source's first
    /// offered token.
    pub pay_token: String,

    pub source_storage: String,
    pub listing: Option<crate::library::RuntimeCustodyListingTerms>,
    /// Plan B S7-lite T7.6: the pool this mint goes into; `None` is this
    /// Home's own pool, else the only pool that admits it.
    pub pool_did: Option<String>,
}

impl std::fmt::Debug for RuntimeCustodyLibrarySourceInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeCustodyLibrarySourceInput")
            .field("object_uri", &self.object_uri)
            .field("principal_id", &self.principal_id)
            .field("source_file_path", &"[private]")
            .field("wallet_account_id", &"[redacted]")
            .field("wallet_account_address", &"[redacted]")
            .field(
                "creator_mint_source_digest",
                &self.creator_mint_source_digest,
            )
            .field("copies", &self.copies)
            .field("price", &self.price)
            .field("source_storage", &self.source_storage)
            .finish()
    }
}

impl std::fmt::Debug for RuntimeCustodyLibraryPublishInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeCustodyLibraryPublishInput")
            .field("object_uri", &self.object_uri)
            .field("principal_id", &self.principal_id)
            .field("wallet_account_id", &"[redacted]")
            .field("wallet_account_address", &"[redacted]")
            .field(
                "creator_mint_source_digest",
                &self.creator_mint_source_digest,
            )
            .field("copies", &self.copies)
            .field("price", &self.price)
            .field("media", &self.media)
            .field("source_storage", &self.source_storage)
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct RuntimeCustodyLibraryPublishFacts {
    pub content_cid: String,
    pub mint_id: Digest32,
    pub content_id: String,
    pub display_name: String,
    pub availability: Value,
    pub receipt: Value,
    pub content_security: Value,
    pub listing_uri: Option<String>,
    /// Where the `.ddrm` for this mint was filed. `None` until the tail has
    /// reached its terminal, since a capsule names a `tokenId` that does not
    /// exist before then.
    pub capsule_uri: Option<String>,
}

async fn prepare_runtime_custody_library_source(
    data_dir: &Path,
    registry: &ProviderRegistry,
    source: &RuntimeCustodyLibrarySourceInput,
) -> anyhow::Result<RuntimeLibraryMediaPreparation> {
    let staging_root = runtime_media_staging_root(data_dir);
    let source_bytes = read_runtime_media_source(
        data_dir,
        &source.principal_id,
        &source.object_uri,
        &source.source_file_path,
    )?;
    let source_object_digest = runtime_media_source_digest(&source_bytes);
    let expected = RuntimeMediaPreparationRecord::new(
        &source.principal_id,
        &source.object_uri,
        &source.source_storage,
        source_object_digest,
        MEDIA_PROVIDER_ID,
        source.wallet_account_id.clone(),
        source.wallet_account_address.clone(),
        source.creator_mint_source_digest,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody media preparation intent is invalid"))?;
    let journal = runtime_mint_journal(data_dir);
    if !runtime_media_provider_is_registered(registry).await
        && !data_dir.join(RUNTIME_MINT_JOURNAL_ROOT).exists()
    {
        anyhow::bail!("Runtime custody media preparation provider is unavailable");
    }
    // Re-pointed at the source's current attempt, so an attempt after an
    // archived one asks the media provider for an operation of its own.
    let attempt = journal
        .current_attempt(
            &source.principal_id,
            &source.object_uri,
            &source.source_storage,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation intent is invalid"))?;
    let expected = expected
        .for_attempt(&source.principal_id, attempt.attempt())
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation intent is invalid"))?;
    let record = match journal.load_media_preparation(expected.request_id()) {
        Ok(existing) => {
            if !existing.same_authority_as(&expected) {
                return Err(RuntimeCustodyAttemptConflict::error(
                    RuntimeCustodyAttemptConflictReason::SourceChanged,
                ));
            }
            existing
        }
        Err(elastos_protected_content_runtime::RuntimeMintJournalError::NotFound) => {
            if !runtime_media_provider_is_registered(registry).await {
                anyhow::bail!("Runtime custody media preparation provider is unavailable");
            }
            validate_runtime_media_staging_root(&staging_root)?;
            let operation_root = staging_root.join(hex::encode(expected.operation_id().as_bytes()));
            reset_runtime_media_operation_root(&operation_root)?;
            if let Err(error) = stage_runtime_media_provider_input(
                &source_bytes,
                &operation_root.join(MEDIA_PROVIDER_INPUT_FILE_NAME),
                source_object_digest,
            ) {
                let _ = fs::remove_dir_all(&operation_root);
                return Err(error);
            }
            journal.persist_media_preparation(&expected).map_err(|_| {
                let _ = fs::remove_dir_all(&operation_root);
                anyhow::anyhow!("Runtime custody media preparation intent is unavailable")
            })?
        }
        Err(_) => {
            anyhow::bail!("Runtime custody media preparation intent is unavailable");
        }
    };
    let operation_root = staging_root.join(hex::encode(record.operation_id().as_bytes()));
    match record.state() {
        RuntimeMediaPreparationState::Consumed => {
            if operation_root.exists() {
                validate_runtime_media_staging_root(&staging_root)?;
                reset_runtime_media_operation_root(&operation_root)?;
                fs::remove_dir(&operation_root)
                    .map_err(|_| runtime_media_private_state_error(String::new()))?;
            }
            return Ok(RuntimeLibraryMediaPreparation::Consumed {
                record: Box::new(record),
                operation_root,
            });
        }
        RuntimeMediaPreparationState::EffectPending => {
            anyhow::bail!(RUNTIME_MEDIA_PREPARATION_RECONCILIATION_MESSAGE);
        }
        RuntimeMediaPreparationState::Failed => {
            anyhow::bail!("Runtime custody media preparation failed");
        }
        RuntimeMediaPreparationState::Prepared => {
            validate_runtime_media_staging_root(&staging_root)?;
            let recorded_receipt = record.output_receipt_digest().ok_or_else(|| {
                anyhow::anyhow!("Runtime custody media preparation output is invalid")
            })?;
            // A mint that completed before this record was consumed (a crash
            // between the two, or a v1 mint from before the upgrade) is
            // finished, not prepared again: consume the record and adopt it.
            if let Some(mint_id) = journal
                .load_intent(record.request_id())
                .ok()
                .and_then(|intent| intent.completed_mint_id())
            {
                journal
                    .mark_media_preparation_consumed(record.request_id(), recorded_receipt, mint_id)
                    .map_err(|_| {
                        anyhow::anyhow!(RUNTIME_MEDIA_PREPARATION_RECONCILIATION_MESSAGE)
                    })?;
                let consumed = journal
                    .load_media_preparation(record.request_id())
                    .map_err(|_| {
                        anyhow::anyhow!("Runtime custody media preparation intent is unavailable")
                    })?;
                if operation_root.exists() {
                    reset_runtime_media_operation_root(&operation_root)?;
                    fs::remove_dir(&operation_root)
                        .map_err(|_| runtime_media_private_state_error(String::new()))?;
                }
                return Ok(RuntimeLibraryMediaPreparation::Consumed {
                    record: Box::new(consumed),
                    operation_root,
                });
            }
            let media = match load_settled_runtime_prepared_media_v2(
                &operation_root,
                recorded_receipt,
            ) {
                Ok(media) => media,
                Err(error) => {
                    // A settled output that cannot be used leaves the creator
                    // stuck unless it is answered as data: nothing was sent, so
                    // Start over can set the attempt aside. The output of the v1
                    // writer is a changed deployment; anything else a changed or
                    // damaged source.
                    tracing::warn!(%error, "runtime custody media preparation: settled output is unusable");
                    return Err(RuntimeCustodyAttemptConflict::error(
                        if runtime_prepared_output_is_v1_shaped(&operation_root) {
                            RuntimeCustodyAttemptConflictReason::AuthorityChanged
                        } else {
                            RuntimeCustodyAttemptConflictReason::SourceChanged
                        },
                    ));
                }
            };
            return Ok(RuntimeLibraryMediaPreparation::Prepared(Box::new(
                RuntimePreparedLibraryPublish {
                    input: RuntimeCustodyLibraryPublishInput {
                        object_uri: source.object_uri.clone(),
                        principal_id: source.principal_id.clone(),
                        listing: source.listing.clone(),
                        wallet_account_id: source.wallet_account_id.clone(),
                        wallet_account_address: source.wallet_account_address.clone(),
                        creator_mint_source_digest: source.creator_mint_source_digest,
                        copies: source.copies.clone(),
                        price: source.price.clone(),
                        channel: source.channel.clone(),
                        pay_token: source.pay_token.clone(),
                        media,
                        source_storage: source.source_storage.clone(),
                        pool_did: source.pool_did.clone(),
                    },
                    request_id: record.request_id(),
                    output_receipt_digest: recorded_receipt,
                    operation_root,
                },
            )));
        }
        RuntimeMediaPreparationState::Ready => {}
    }

    if !runtime_media_provider_is_registered(registry).await {
        anyhow::bail!("Runtime custody media preparation provider is unavailable");
    }
    validate_runtime_media_staging_root(&staging_root)?;
    reset_runtime_media_operation_root(&operation_root)?;
    if let Err(error) = stage_runtime_media_provider_input(
        &source_bytes,
        &operation_root.join(MEDIA_PROVIDER_INPUT_FILE_NAME),
        source_object_digest,
    ) {
        let _ = fs::remove_dir_all(&operation_root);
        return Err(error);
    }
    journal
        .mark_media_preparation_effect_started(record.request_id())
        .map_err(|_| anyhow::anyhow!(RUNTIME_MEDIA_PREPARATION_RECONCILIATION_MESSAGE))?;
    let output = match invoke_runtime_media_provider_prepare(registry, record.operation_id()).await
    {
        Ok(output) => output,
        Err(RuntimeMediaProviderPrepareError::Settled) => {
            journal
                .mark_media_preparation_failed(record.request_id())
                .map_err(|_| anyhow::anyhow!(RUNTIME_MEDIA_PREPARATION_RECONCILIATION_MESSAGE))?;
            let _ = fs::remove_dir_all(&operation_root);
            anyhow::bail!("Runtime custody media preparation failed");
        }
        Err(RuntimeMediaProviderPrepareError::Unknown) => {
            anyhow::bail!(RUNTIME_MEDIA_PREPARATION_RECONCILIATION_MESSAGE);
        }
    };
    let media = match load_validated_runtime_prepared_media_v2(&operation_root, &output) {
        Ok(prepared) => prepared,
        Err(error) => {
            journal
                .mark_media_preparation_failed(record.request_id())
                .map_err(|_| anyhow::anyhow!(RUNTIME_MEDIA_PREPARATION_RECONCILIATION_MESSAGE))?;
            let _ = fs::remove_dir_all(&operation_root);
            return Err(error);
        }
    };
    let output_receipt_digest = media.preparation_receipt();
    journal
        .mark_media_preparation_prepared(record.request_id(), output_receipt_digest)
        .map_err(|_| anyhow::anyhow!(RUNTIME_MEDIA_PREPARATION_RECONCILIATION_MESSAGE))?;
    Ok(RuntimeLibraryMediaPreparation::Prepared(Box::new(
        RuntimePreparedLibraryPublish {
            input: RuntimeCustodyLibraryPublishInput {
                object_uri: source.object_uri.clone(),
                principal_id: source.principal_id.clone(),
                listing: source.listing.clone(),
                wallet_account_id: source.wallet_account_id.clone(),
                wallet_account_address: source.wallet_account_address.clone(),
                creator_mint_source_digest: source.creator_mint_source_digest,
                copies: source.copies.clone(),
                price: source.price.clone(),
                channel: source.channel.clone(),
                pay_token: source.pay_token.clone(),
                media,
                source_storage: source.source_storage.clone(),
                pool_did: source.pool_did.clone(),
            },
            request_id: record.request_id(),
            output_receipt_digest,
            operation_root,
        },
    )))
}

async fn runtime_media_provider_is_registered(registry: &ProviderRegistry) -> bool {
    registry
        .has_ready_runtime_provider_target(MEDIA_PROVIDER_ID)
        .await
}

pub(crate) async fn publish_runtime_custody_library_source(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    source: RuntimeCustodyLibrarySourceInput,
) -> anyhow::Result<(
    RuntimeCustodyLibraryPublishFacts,
    RuntimeCustodyLibraryPublishInput,
)> {
    match prepare_runtime_custody_library_source(data_dir, registry.as_ref(), &source).await? {
        RuntimeLibraryMediaPreparation::Prepared(prepared) => {
            let input = prepared.input;
            let facts = publish_runtime_custody_library_object(
                data_dir,
                Arc::clone(&registry),
                input.clone(),
            )
            .await?;
            runtime_mint_journal(data_dir)
                .mark_media_preparation_consumed(
                    prepared.request_id,
                    prepared.output_receipt_digest,
                    facts.mint_id,
                )
                .map_err(|_| anyhow::anyhow!(RUNTIME_MEDIA_PREPARATION_RECONCILIATION_MESSAGE))?;
            fs::remove_dir_all(&prepared.operation_root)
                .map_err(|_| runtime_media_private_state_error(String::new()))?;
            Ok((facts, input))
        }
        RuntimeLibraryMediaPreparation::Consumed {
            record,
            operation_root,
        } => {
            let mint_id = record.consumed_mint_id().ok_or_else(|| {
                anyhow::anyhow!("Runtime custody media preparation intent is unavailable")
            })?;
            let journal = runtime_mint_journal(data_dir);
            let intent = journal
                .load_intent(record.request_id())
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
            if intent.completed_mint_id() != Some(mint_id) {
                anyhow::bail!("Runtime custody media preparation conflicts with mint settlement");
            }
            let persisted = journal
                .load(mint_id)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
            // Either media kind: a mint completed as v1 stays adoptable.
            if persisted.draft().media_identity().is_none()
                && persisted.draft().media_dash_identity().is_none()
            {
                anyhow::bail!("Runtime custody mint draft is not a media identity");
            }
            let input = RuntimeCustodyLibraryPublishInput {
                object_uri: source.object_uri,
                principal_id: source.principal_id,
                listing: source.listing,
                wallet_account_id: source.wallet_account_id,
                wallet_account_address: source.wallet_account_address,
                creator_mint_source_digest: source.creator_mint_source_digest,
                copies: source.copies,
                price: source.price,
                channel: source.channel,
                pay_token: source.pay_token,
                media: RuntimePreparedMediaV2::settled(),
                source_storage: source.source_storage,
                pool_did: source.pool_did,
            };
            let facts = load_completed_runtime_mint_facts(&journal, &input, mint_id)?;
            if operation_root.exists() {
                fs::remove_dir_all(&operation_root)
                    .map_err(|_| runtime_media_private_state_error(String::new()))?;
            }
            Ok((facts, input))
        }
    }
}

pub(crate) async fn publish_runtime_custody_library_object(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    input: RuntimeCustodyLibraryPublishInput,
) -> anyhow::Result<RuntimeCustodyLibraryPublishFacts> {
    let mint_pool = load_runtime_custody_mint_pool(
        data_dir,
        registry.clone(),
        input.pool_did.as_deref(),
        Some((
            &input.principal_id,
            &input.object_uri,
            &input.source_storage,
        )),
    )?;
    let composition = &mint_pool.composition;
    let used_pool = mint_pool.used.clone();
    let (device_key, device_did) =
        crate::collaboration_profile_authority::load_existing_device_signing_key(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    let runtime_issuer = RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())
        .map_err(|_| anyhow::anyhow!("local Runtime device signing key is invalid"))?;
    let now = crate::auth::now_ts();
    let configured = composition
        .configured_nodes()
        .map_err(|_| anyhow::anyhow!("Runtime custody mint selection is invalid"))?;
    let selected = mint_pool.selected_nodes(&configured, now)?;
    let mint_nodes = selected
        .iter()
        .map(|node| node.binding().clone())
        .collect::<Vec<_>>();
    let mint_journal = runtime_mint_journal(data_dir);
    let mint_intent = load_or_persist_runtime_mint_intent(
        &mint_journal,
        composition,
        &input,
        mint_nodes.clone(),
    )?;
    if let Some(mint_id) = mint_intent.completed_mint_id() {
        return load_completed_runtime_mint_facts(&mint_journal, &input, mint_id);
    }
    if mint_intent.protect_settled_closed_before_draft() {
        if let Some(mint_id) = adopt_settled_runtime_mint_record(&mint_journal, &mint_intent)? {
            return load_completed_runtime_mint_facts(&mint_journal, &input, mint_id);
        }
    }
    let protected = protect_runtime_custody_media(
        data_dir,
        &registry,
        &mint_journal,
        composition,
        &input,
        &mint_intent,
    )
    .await?;
    tracing::debug!(
        request_id = %hex::encode(mint_intent.request_id().as_bytes()),
        segments = protected
            .media_identity
            .renditions()
            .iter()
            .map(|rendition| u64::from(rendition.segment_count()))
            .sum::<u64>(),
        "runtime custody publish: media protected"
    );
    let policy = resolve_runtime_rights_policy(
        registry.as_ref(),
        protected.media_identity.encrypted_content(),
        mint_intent.content_access_id(),
        RightsActionV1::View,
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, "Runtime custody rights policy resolution failed");
        error.context("Runtime custody rights policy is unavailable")
    })?;
    tracing::debug!(
        request_id = %hex::encode(mint_intent.request_id().as_bytes()),
        "runtime custody publish: rights policy resolved"
    );
    let mint_draft = RuntimeMintDraft::new_from_identity(
        RuntimeContentIdentityV1::MediaDash(protected.media_identity.clone()),
        mint_intent.content_access_id(),
        protected
            .envelope
            .key_envelope_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?,
        policy.identity().clone(),
        protected.envelope.manifest().content_key_commitment(),
        protected.envelope.manifest().threshold(),
        mint_nodes,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody mint draft is invalid"))?;
    let sign_key = device_key.clone();
    let mut coordinator = RuntimeMintCoordinator::new(
        runtime_mint_journal(data_dir),
        runtime_issuer,
        move |bytes| sign_key.sign(bytes).to_bytes(),
        selected,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody mint coordinator is invalid"))?
    .with_dispatch_clock(crate::auth::now_ts);
    if let Some(descriptor) = &used_pool {
        coordinator = coordinator.with_pool_provisioning(
            elastos_protected_content_runtime::RuntimeMintPoolProvisioning::new(
                descriptor.clone(),
                mint_intent.content_access_id(),
            ),
        );
    }
    match coordinator
        .provision(&mint_draft, &protected.envelope, now)
        .await
        .map_err(|_| anyhow::anyhow!("Runtime custody mint failed"))?
    {
        RuntimeMintCoordinatorOutcome::CustodyProvisioned { mint_id }
            if mint_id == mint_draft.mint_id() => {}
        RuntimeMintCoordinatorOutcome::ContentAvailable { mint_id }
            if mint_id == mint_draft.mint_id() => {}
        _ => anyhow::bail!("Runtime custody mint failed"),
    }
    tracing::debug!(
        mint_id = %hex::encode(mint_draft.mint_id().as_bytes()),
        nodes = mint_draft.nodes().len(),
        "runtime custody publish: custody provisioned"
    );
    if let Some(descriptor) = &used_pool {
        record_runtime_pool_mint(data_dir, &mint_draft, descriptor, &device_key)?;
    }
    let content_id = runtime_protected_content_id(mint_draft.encrypted_content())?;
    let publisher_profile_did = load_runtime_custody_profile_did(data_dir, &input.principal_id)?;
    let requirement = RuntimeContentAvailabilityRequirement::new(
        device_did,
        content_id.clone(),
        publisher_profile_did,
        PROTECTED_CONTENT_REPLICATION_POLICY,
        PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET,
        PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody availability requirement is invalid"))?;
    let mint_draft_media_identity = mint_draft
        .media_dash_identity()
        .ok_or_else(|| anyhow::anyhow!("Runtime custody mint draft is not a media identity"))?;
    let evidence = publish_and_verify_protected_content_dash_availability(
        registry.as_ref(),
        protected.staging.path(),
        mint_draft_media_identity,
        &requirement,
        crate::auth::now_ts,
    )
    .await
    .map_err(|error| {
        // The caller sees the fail-closed message; the verifier's actual
        // reason travels as the cause chain (and the operator log).
        tracing::warn!(
            mint_id = %hex::encode(mint_draft.mint_id().as_bytes()),
            %error,
            "Runtime custody content availability verification failed"
        );
        error.context(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE)
    })?;
    tracing::debug!(
        mint_id = %hex::encode(mint_draft.mint_id().as_bytes()),
        content_id = %content_id,
        replicas = evidence.observed_replicas(),
        "runtime custody publish: content availability verified"
    );
    match coordinator
        .record_content_availability(&mint_draft, &requirement, evidence.clone())
        .map_err(|_| anyhow::anyhow!("Runtime custody availability record failed"))?
    {
        RuntimeMintCoordinatorOutcome::ContentAvailable { mint_id }
            if mint_id == mint_draft.mint_id() => {}
        _ => anyhow::bail!("Runtime custody availability record failed"),
    }
    let facts = runtime_custody_library_publish_facts(
        &input.object_uri,
        &input.source_storage,
        &mint_draft,
        &content_id,
        &evidence,
    );
    mint_journal
        .mark_intent_completed(mint_intent.request_id(), mint_draft.mint_id())
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    Ok(facts)
}

/// Object twin of `publish_runtime_custody_library_object`. Ends where the
/// media function's completed mint (custody-provisioned + content-available)
/// is ready. The creator/chain-mint/listing tail is NOT duplicated here: the
/// caller (`runtime_custody_publish_object_via_gateway`) runs the same shared
/// `runtime_custody_publish_creator_tail_from_facts` the media path runs, now
/// that the portable listing package carries either content kind.
pub(crate) async fn publish_runtime_custody_library_object_content(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    input: RuntimeCustodyLibraryPublishObjectInput,
) -> anyhow::Result<RuntimeCustodyLibraryPublishFacts> {
    let mint_pool = load_runtime_custody_mint_pool(
        data_dir,
        registry.clone(),
        input.pool_did.as_deref(),
        Some((
            &input.principal_id,
            &input.object_uri,
            &input.source_storage,
        )),
    )?;
    let composition = &mint_pool.composition;
    let used_pool = mint_pool.used.clone();
    let (device_key, device_did) =
        crate::collaboration_profile_authority::load_existing_device_signing_key(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    let runtime_issuer = RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())
        .map_err(|_| anyhow::anyhow!("local Runtime device signing key is invalid"))?;
    let now = crate::auth::now_ts();
    let configured = composition
        .configured_nodes()
        .map_err(|_| anyhow::anyhow!("Runtime custody mint selection is invalid"))?;
    let selected = mint_pool.selected_nodes(&configured, now)?;
    let mint_nodes = selected
        .iter()
        .map(|node| node.binding().clone())
        .collect::<Vec<_>>();
    let mint_journal = runtime_mint_journal(data_dir);
    let mint_intent = load_or_persist_runtime_mint_intent_object(
        &mint_journal,
        composition,
        &input,
        mint_nodes.clone(),
    )?;
    if let Some(mint_id) = mint_intent.completed_mint_id() {
        return load_completed_runtime_mint_object_facts(&mint_journal, &input, mint_id);
    }
    if mint_intent.protect_settled_closed_before_draft() {
        if let Some(mint_id) = adopt_settled_runtime_mint_record(&mint_journal, &mint_intent)? {
            return load_completed_runtime_mint_object_facts(&mint_journal, &input, mint_id);
        }
    }
    let request_id = hex::encode(mint_intent.request_id().as_bytes());
    let step = RuntimeMintStep::begin("protect", &request_id);
    let protected = protect_runtime_custody_object(
        data_dir,
        &registry,
        &mint_journal,
        composition,
        &input.content_type,
        &input.clear_plaintext,
        &mint_intent,
    )
    .await?;
    step.ok();
    // DEBUG, like its media twin: at INFO an operator wants the mint's outcome,
    // not each phase of it.
    tracing::debug!(
        request_id = %request_id,
        content_kind = "object",
        framed_bytes = protected.object_identity.encrypted_content().ciphertext_bytes(),
        "runtime custody publish: object protected"
    );
    let step = RuntimeMintStep::begin("rights_policy", &request_id);
    let policy = resolve_runtime_rights_policy(
        registry.as_ref(),
        protected.object_identity.encrypted_content(),
        mint_intent.content_access_id(),
        RightsActionV1::View,
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, "Runtime custody rights policy resolution failed");
        error.context("Runtime custody rights policy is unavailable")
    })?;
    step.ok();
    let mint_draft = RuntimeMintDraft::new_from_identity(
        RuntimeContentIdentityV1::Object(protected.object_identity.clone()),
        mint_intent.content_access_id(),
        protected
            .envelope
            .key_envelope_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?,
        policy.identity().clone(),
        protected.envelope.manifest().content_key_commitment(),
        protected.envelope.manifest().threshold(),
        mint_nodes,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody mint draft is invalid"))?;
    let sign_key = device_key.clone();
    let mut coordinator = RuntimeMintCoordinator::new(
        runtime_mint_journal(data_dir),
        runtime_issuer,
        move |bytes| sign_key.sign(bytes).to_bytes(),
        selected,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody mint coordinator is invalid"))?
    .with_dispatch_clock(crate::auth::now_ts);
    if let Some(descriptor) = &used_pool {
        coordinator = coordinator.with_pool_provisioning(
            elastos_protected_content_runtime::RuntimeMintPoolProvisioning::new(
                descriptor.clone(),
                mint_intent.content_access_id(),
            ),
        );
    }
    let step = RuntimeMintStep::begin("custody_provision", &request_id);
    match coordinator
        .provision(&mint_draft, &protected.envelope, crate::auth::now_ts())
        .await
        .map_err(|_| anyhow::anyhow!("Runtime custody mint failed"))?
    {
        RuntimeMintCoordinatorOutcome::CustodyProvisioned { mint_id }
            if mint_id == mint_draft.mint_id() => {}
        RuntimeMintCoordinatorOutcome::ContentAvailable { mint_id }
            if mint_id == mint_draft.mint_id() => {}
        _ => anyhow::bail!("Runtime custody mint failed"),
    }
    step.ok();
    tracing::debug!(
        mint_id = %hex::encode(mint_draft.mint_id().as_bytes()),
        "runtime custody publish: object custody provisioned"
    );
    if let Some(descriptor) = &used_pool {
        record_runtime_pool_mint(data_dir, &mint_draft, descriptor, &device_key)?;
    }
    let content_id = runtime_protected_content_id(mint_draft.encrypted_content())?;
    let publisher_profile_did = load_runtime_custody_profile_did(data_dir, &input.principal_id)?;
    let requirement = RuntimeContentAvailabilityRequirement::new(
        device_did,
        content_id.clone(),
        publisher_profile_did,
        PROTECTED_CONTENT_REPLICATION_POLICY,
        PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET,
        PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody availability requirement is invalid"))?;
    let step = RuntimeMintStep::begin("staging", &request_id);
    write_protected_content_object_manifest(protected.staging.path(), &protected.object_identity)?;
    step.ok();
    // The long one. Publishing the ciphertext and proving it replicated is what
    // a creator sees as a stalled "Encrypt & escrow", because the whole server
    // round trip is one request from the browser's side.
    let step = RuntimeMintStep::begin("availability_publish", &request_id);
    let evidence = publish_and_verify_protected_content_object_availability(
        registry.as_ref(),
        protected.staging.path(),
        &protected.object_identity,
        &requirement,
        crate::auth::now_ts,
    )
    .await
    .map_err(|error| {
        tracing::warn!(
            mint_id = %hex::encode(mint_draft.mint_id().as_bytes()),
            %error,
            "Runtime custody content availability verification failed"
        );
        error.context(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE)
    })?;
    step.ok();
    match coordinator
        .record_content_availability(&mint_draft, &requirement, evidence.clone())
        .map_err(|_| anyhow::anyhow!("Runtime custody availability record failed"))?
    {
        RuntimeMintCoordinatorOutcome::ContentAvailable { mint_id }
            if mint_id == mint_draft.mint_id() => {}
        _ => anyhow::bail!("Runtime custody availability record failed"),
    }
    let facts = runtime_custody_library_publish_facts(
        &input.object_uri,
        &input.source_storage,
        &mint_draft,
        &content_id,
        &evidence,
    );
    mint_journal
        .mark_intent_completed(mint_intent.request_id(), mint_draft.mint_id())
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    Ok(facts)
}

/// The result of a v2 protect: the protected package already laid out in a
/// private staging directory (the segments were written as they were produced,
/// never held together), the head that commits to it, and the key envelope.
/// Dropping it removes the staging directory.
struct ProtectedRuntimeCustodyMediaDash {
    staging: tempfile::TempDir,
    media_identity: CencDashMediaIdentityV2,
    envelope: CustodyEnvelopeV1,
}

enum RuntimeProtectRecoveryDisposition {
    Fresh,
    ReplayOpenAndSettleCancel,
    SettleCancel([u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]),
    SettleClose([u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]),
    TerminalAbort,
}

async fn protect_runtime_custody_media(
    data_dir: &Path,
    registry: &ProviderRegistry,
    journal: &RuntimeMintJournal,
    composition: &RuntimeCustodyComposition,
    input: &RuntimeCustodyLibraryPublishInput,
    mint_intent: &RuntimeMintIntent,
) -> anyhow::Result<ProtectedRuntimeCustodyMediaDash> {
    let open_request =
        runtime_custody_open_protection_session_request(composition, input, mint_intent)?;
    match runtime_protect_recovery_disposition(mint_intent) {
        RuntimeProtectRecoveryDisposition::TerminalAbort => {
            // This intent settled its protect session before any draft existed,
            // so it can produce nothing and there is no record to adopt. Its
            // identity comes from the object path, so keeping it makes that
            // file unmintable for good. Forget it: this attempt still fails,
            // but the next one starts from nothing instead of meeting the same
            // wall forever.
            tracing::warn!(
                request_id = %hex::encode(mint_intent.request_id().as_bytes()),
                "runtime custody mint intent settled before any draft and was discarded"
            );
            journal
                .discard_unmintable_intent(mint_intent.request_id())
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::SettleCancel(handle) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                handle,
                RuntimeProtectSessionSettlementOp::Cancel,
            )
            .await?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::SettleClose(handle) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                handle,
                RuntimeProtectSessionSettlementOp::Close,
            )
            .await?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::ReplayOpenAndSettleCancel => {
            if !registry
                .has_ready_runtime_provider_target(PROTECT_PROVIDER_ID)
                .await
            {
                return Err(runtime_custody_dispatch_uncertain());
            }
            let opened =
                invoke_typed_protect_provider(registry, "open_protection_session", &open_request)
                    .await
                    .map_err(|_| runtime_custody_dispatch_uncertain())?;
            if opened.status() != ProtectProviderResponseStatusV1::ProtectionSessionOpened {
                return Err(runtime_custody_dispatch_uncertain());
            }
            let handle = opened
                .protection_session_handle()
                .map_err(|_| runtime_custody_dispatch_uncertain())?
                .ok_or_else(runtime_custody_dispatch_uncertain)?;
            journal
                .mark_intent_protect_opened(mint_intent.request_id(), handle)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                handle,
                RuntimeProtectSessionSettlementOp::Cancel,
            )
            .await?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::Fresh => {}
    }

    if !registry
        .has_ready_runtime_provider_target(PROTECT_PROVIDER_ID)
        .await
    {
        anyhow::bail!("Runtime custody protect provider is unavailable");
    }
    journal
        .mark_intent_protect_effect_started(mint_intent.request_id())
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let opened =
        invoke_typed_protect_provider(registry, "open_protection_session", &open_request).await?;
    if opened.status() != ProtectProviderResponseStatusV1::ProtectionSessionOpened {
        anyhow::bail!("Runtime custody protect provider is unavailable");
    }
    let handle = opened
        .protection_session_handle()
        .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?
        .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
    journal
        .mark_intent_protect_opened(mint_intent.request_id(), handle)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let protect_result = protect_opened_runtime_custody_session(
        data_dir,
        registry,
        journal,
        mint_intent.request_id(),
        handle,
        &opened,
        input,
        composition,
        mint_intent.content_access_id(),
    )
    .await;
    match protect_result {
        Ok(protected) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                handle,
                RuntimeProtectSessionSettlementOp::Close,
            )
            .await?;
            Ok(protected)
        }
        Err(error) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                handle,
                RuntimeProtectSessionSettlementOp::Cancel,
            )
            .await
            .map_err(|_| runtime_custody_dispatch_uncertain())?;
            Err(error)
        }
    }
}

/// The result of an object protect: the framed object already written to its
/// private staging file (each chunk was written as the provider returned it,
/// never held together), the identity that commits to it, and the key
/// envelope. Dropping it removes the staging directory.
struct ProtectedRuntimeCustodyObject {
    staging: tempfile::TempDir,
    object_identity: ChunkedPayloadObjectIdentityV1,
    envelope: CustodyEnvelopeV1,
}

/// Object twin of `protect_runtime_custody_media`. Reuses
/// `runtime_protect_recovery_disposition` and
/// `settle_runtime_custody_protect_session` UNCHANGED: both are already
/// content-kind-agnostic (they only ever inspect the mint intent's protect
/// recovery fields and dispatch the shared, kind-agnostic
/// `cancel_protection_session`/`close_protection_session` ops by opaque
/// handle), so the object-specific session-open/chunk/finalize sequence is
/// the only new logic here — the recovery/settlement state machine that
/// makes this resumable across restarts is not duplicated.
async fn protect_runtime_custody_object(
    data_dir: &Path,
    registry: &ProviderRegistry,
    journal: &RuntimeMintJournal,
    composition: &RuntimeCustodyComposition,
    content_type: &str,
    clear_plaintext: &[u8],
    mint_intent: &RuntimeMintIntent,
) -> anyhow::Result<ProtectedRuntimeCustodyObject> {
    let open_request = runtime_custody_open_object_protection_session_request(
        composition,
        content_type,
        clear_plaintext.len() as u64,
        mint_intent,
    )?;
    let session_handle = *mint_intent.request_id().as_bytes();
    match runtime_protect_recovery_disposition(mint_intent) {
        RuntimeProtectRecoveryDisposition::TerminalAbort => {
            // This intent settled its protect session before any draft existed,
            // so it can produce nothing and there is no record to adopt. Its
            // identity comes from the object path, so keeping it makes that
            // file unmintable for good. Forget it: this attempt still fails,
            // but the next one starts from nothing instead of meeting the same
            // wall forever.
            tracing::warn!(
                request_id = %hex::encode(mint_intent.request_id().as_bytes()),
                "runtime custody mint intent settled before any draft and was discarded"
            );
            journal
                .discard_unmintable_intent(mint_intent.request_id())
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::SettleCancel(handle) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                handle,
                RuntimeProtectSessionSettlementOp::Cancel,
            )
            .await?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::SettleClose(handle) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                handle,
                RuntimeProtectSessionSettlementOp::Close,
            )
            .await?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::ReplayOpenAndSettleCancel => {
            if !registry
                .has_ready_runtime_provider_target(PROTECT_PROVIDER_ID)
                .await
            {
                return Err(runtime_custody_dispatch_uncertain());
            }
            let opened = invoke_typed_protect_provider(
                registry,
                "open_object_protection_session",
                &open_request,
            )
            .await
            .map_err(|_| runtime_custody_dispatch_uncertain())?;
            if opened.status() != ProtectProviderResponseStatusV1::ObjectProtectionSessionOpened {
                return Err(runtime_custody_dispatch_uncertain());
            }
            journal
                .mark_intent_protect_opened(mint_intent.request_id(), session_handle)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                session_handle,
                RuntimeProtectSessionSettlementOp::Cancel,
            )
            .await?;
            anyhow::bail!(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE);
        }
        RuntimeProtectRecoveryDisposition::Fresh => {}
    }

    if !registry
        .has_ready_runtime_provider_target(PROTECT_PROVIDER_ID)
        .await
    {
        anyhow::bail!("Runtime custody protect provider is unavailable");
    }
    journal
        .mark_intent_protect_effect_started(mint_intent.request_id())
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let opened =
        invoke_typed_protect_provider(registry, "open_object_protection_session", &open_request)
            .await?;
    if opened.status() != ProtectProviderResponseStatusV1::ObjectProtectionSessionOpened {
        anyhow::bail!("Runtime custody protect provider is unavailable");
    }
    journal
        .mark_intent_protect_opened(mint_intent.request_id(), session_handle)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let protect_result = protect_opened_runtime_custody_object_session(
        data_dir,
        registry,
        journal,
        mint_intent.request_id(),
        session_handle,
        &opened,
        content_type,
        clear_plaintext,
        composition,
    )
    .await;
    match protect_result {
        Ok(protected) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                session_handle,
                RuntimeProtectSessionSettlementOp::Close,
            )
            .await?;
            Ok(protected)
        }
        Err(error) => {
            settle_runtime_custody_protect_session(
                registry,
                journal,
                mint_intent.request_id(),
                session_handle,
                RuntimeProtectSessionSettlementOp::Cancel,
            )
            .await
            .map_err(|_| runtime_custody_dispatch_uncertain())?;
            Err(error)
        }
    }
}

fn runtime_custody_open_object_protection_session_request(
    composition: &RuntimeCustodyComposition,
    content_type: &str,
    plaintext_bytes: u64,
    mint_intent: &RuntimeMintIntent,
) -> anyhow::Result<ProtectProviderRequestV1> {
    let nodes = composition
        .nodes
        .iter()
        .map(|node| {
            ProtectionSessionNodeV1::new(node.node_public_key, node.custody_public_key)
                .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    ProtectProviderRequestV1::new_open_object_protection_session(
        mint_intent.request_id(),
        mint_intent.content_access_id(),
        composition
            .signed_pool
            .pool_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?,
        composition
            .signed_epoch
            .epoch_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?,
        composition
            .signed_committee_authorization
            .authorization_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?,
        // The object protect provider enforces exactly 2-of-3 regardless of
        // what is requested here (Task 10 review, Important 2); this mirrors
        // that fixed value rather than exposing it as a caller choice.
        2,
        3,
        content_type.to_string(),
        plaintext_bytes,
        nodes,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "This operation keeps protect-session authority and settlement inputs explicit at one boundary"
)]
async fn protect_opened_runtime_custody_object_session(
    data_dir: &Path,
    registry: &ProviderRegistry,
    journal: &RuntimeMintJournal,
    request_id: Digest32,
    handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    opened: &ProtectProviderResponseV1,
    content_type: &str,
    clear_plaintext: &[u8],
    composition: &RuntimeCustodyComposition,
) -> anyhow::Result<ProtectedRuntimeCustodyObject> {
    let framed_header = opened
        .framed_header()
        .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?
        .to_vec();
    let staging = create_protected_content_object_staging_directory(data_dir)?;
    let epc1 = fs::File::create(staging.path().join(PROTECTED_CONTENT_OBJECT_EPC1_PATH))
        .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))?;
    let mut sink = ObjectFramedStagingSink::new(std::io::BufWriter::new(epc1));
    sink.push(&framed_header)?;
    let session_id = Digest32::new(handle);
    for (chunk_index, chunk) in clear_plaintext
        .chunks(MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1)
        .enumerate()
    {
        let chunk_index = u32::try_from(chunk_index)
            .map_err(|_| anyhow::anyhow!("Runtime custody protect input is invalid"))?;
        let protected = invoke_typed_protect_provider(
            registry,
            "protect_object_chunk",
            &ProtectProviderRequestV1::new_protect_object_chunk(session_id, chunk_index, chunk)
                .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?,
        )
        .await?;
        if protected.status() != ProtectProviderResponseStatusV1::ObjectChunkProtected {
            anyhow::bail!("Runtime custody protect provider is unavailable");
        }
        sink.push(
            protected
                .framed_chunk()
                .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?,
        )?;
    }
    let (framed_encrypted_content, _) = sink.finish()?;
    let finalized = invoke_typed_protect_provider(
        registry,
        "finalize_object_protection_session",
        &ProtectProviderRequestV1::new_finalize_object_protection_session(
            session_id,
            &framed_encrypted_content,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?,
    )
    .await?;
    if finalized.status() != ProtectProviderResponseStatusV1::ObjectProtectionSessionFinalized {
        anyhow::bail!("Runtime custody protect provider is unavailable");
    }
    let object_identity = finalized
        .object_identity()
        .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?
        .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
    let envelope = finalized
        .custody_envelope()
        .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?
        .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
    let expected_object = ChunkedPayloadObjectIdentityV1::new(
        framed_encrypted_content,
        content_type,
        clear_plaintext.len() as u64,
        u32::try_from(framed_header.len())
            .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
    if object_identity != expected_object
        || envelope.manifest().encrypted_content() != object_identity.encrypted_content()
        || envelope.manifest().custody_pool()
            != composition
                .signed_pool
                .pool_identity()
                .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?
        || envelope.manifest().custody_epoch()
            != composition
                .signed_epoch
                .epoch_identity()
                .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?
        || envelope.manifest().custody_committee_authorization()
            != composition
                .signed_committee_authorization
                .authorization_identity()
                .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?
    {
        anyhow::bail!("Runtime custody protect output is invalid");
    }
    // No object-analogue of media's `content_access_id` cross-check: the
    // media response's `ValidatedCencFmp4MediaSessionLayoutV1` structurally
    // carries `content_access_id` (verified above via
    // `protected_session.content_access_id() != content_access_id` in
    // `protect_opened_runtime_custody_session`), but neither
    // `ObjectProtectionSessionOpened` nor `ObjectProtectionSessionFinalized`
    // carries any artefact binding the session to the requested
    // `content_access_id` — the object protect-provider contract (Task 8)
    // has no field to check here. `content_access_id` is still bound
    // one layer up, into the mint draft itself
    // (`RuntimeMintDraft::new_from_identity`'s `content_access_id` argument),
    // so a wrong id cannot silently propagate into the completed mint; it
    // just is not independently re-verified against the protect session the
    // way media's is.
    journal
        .mark_intent_protect_finalized(request_id, handle)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    Ok(ProtectedRuntimeCustodyObject {
        staging,
        object_identity,
        envelope,
    })
}

fn runtime_protect_recovery_disposition(
    mint_intent: &RuntimeMintIntent,
) -> RuntimeProtectRecoveryDisposition {
    if let Some(handle) = mint_intent.protect_pending_close_handle() {
        RuntimeProtectRecoveryDisposition::SettleClose(handle)
    } else if let Some(handle) = mint_intent.protect_pending_cancel_handle() {
        RuntimeProtectRecoveryDisposition::SettleCancel(handle)
    } else if mint_intent.protect_open_request_pending() {
        RuntimeProtectRecoveryDisposition::ReplayOpenAndSettleCancel
    } else if mint_intent.protect_terminal_before_draft() {
        RuntimeProtectRecoveryDisposition::TerminalAbort
    } else {
        RuntimeProtectRecoveryDisposition::Fresh
    }
}

fn runtime_custody_open_protection_session_request(
    composition: &RuntimeCustodyComposition,
    input: &RuntimeCustodyLibraryPublishInput,
    mint_intent: &RuntimeMintIntent,
) -> anyhow::Result<ProtectProviderRequestV1> {
    let nodes = composition
        .nodes
        .iter()
        .map(|node| {
            ProtectionSessionNodeV1::new(node.node_public_key, node.custody_public_key)
                .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let representations = input
        .media
        .renditions
        .iter()
        .map(|rendition| {
            let (mime_type, codecs) = pinned_declaration_v2(rendition.kind);
            ProtectionRepresentationV2::new(
                rendition.kind,
                mime_type,
                codecs,
                rendition.segment_count,
                &rendition.clear_init_segment,
            )
            .map_err(|_| anyhow::anyhow!("Runtime custody protect input is invalid"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    ProtectProviderRequestV1::new_open_protection_session_v2(
        mint_intent.request_id(),
        mint_intent.content_access_id(),
        composition
            .signed_pool
            .pool_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?,
        composition
            .signed_epoch
            .epoch_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?,
        composition
            .signed_committee_authorization
            .authorization_identity()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?,
        representations,
        // The Runtime adds no foreign protection-system boxes of its own.
        &[],
        nodes,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))
}

enum RuntimeProtectSessionSettlementOp {
    Cancel,
    Close,
}

async fn settle_runtime_custody_protect_session(
    registry: &ProviderRegistry,
    journal: &RuntimeMintJournal,
    request_id: Digest32,
    handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    op: RuntimeProtectSessionSettlementOp,
) -> anyhow::Result<()> {
    let (provider_op, request) = match op {
        RuntimeProtectSessionSettlementOp::Cancel => (
            "cancel_protection_session",
            ProtectProviderRequestV1::new_cancel_protection_session(handle)
                .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?,
        ),
        RuntimeProtectSessionSettlementOp::Close => (
            "close_protection_session",
            ProtectProviderRequestV1::new_close_protection_session(handle)
                .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?,
        ),
    };
    let response = invoke_typed_protect_provider(registry, provider_op, &request).await?;
    match (op, response.status()) {
        (
            RuntimeProtectSessionSettlementOp::Cancel,
            ProtectProviderResponseStatusV1::ProtectionSessionCancelled,
        ) => {
            journal
                .mark_intent_protect_cancelled_before_draft(request_id)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
        }
        (
            RuntimeProtectSessionSettlementOp::Close,
            ProtectProviderResponseStatusV1::ProtectionSessionClosed,
        ) => {
            journal
                .mark_intent_protect_closed_before_draft(request_id)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
        }
        (
            RuntimeProtectSessionSettlementOp::Cancel | RuntimeProtectSessionSettlementOp::Close,
            ProtectProviderResponseStatusV1::ProtectionSessionAlreadyAbsent,
        ) => {
            journal
                .mark_intent_protect_already_absent_before_draft(request_id)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
        }
        _ => return Err(runtime_custody_dispatch_uncertain()),
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "This operation keeps protect-session authority and settlement inputs explicit at one boundary"
)]
async fn protect_opened_runtime_custody_session(
    data_dir: &Path,
    registry: &ProviderRegistry,
    journal: &RuntimeMintJournal,
    request_id: Digest32,
    handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    opened: &ProtectProviderResponseV1,
    input: &RuntimeCustodyLibraryPublishInput,
    composition: &RuntimeCustodyComposition,
    content_access_id: ContentAccessIdV1,
) -> anyhow::Result<ProtectedRuntimeCustodyMediaDash> {
    const INVALID_OUTPUT: &str = "Runtime custody protect output is invalid";
    let renditions = &input.media.renditions;
    // One protected init per rendition, in request order.
    let protected_inits: Vec<Vec<u8>> = opened
        .protected_init_segments()
        .ok_or_else(|| anyhow::anyhow!(INVALID_OUTPUT))?
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect();
    if protected_inits.len() != renditions.len()
        || protected_inits
            .iter()
            .any(|init| init.is_empty() || init.len() > MAX_PROTECT_MEDIA_PART_BYTES_V1)
    {
        anyhow::bail!(INVALID_OUTPUT);
    }
    let staging = create_protected_content_staging_directory(data_dir)?;
    for (rendition, init) in renditions.iter().zip(&protected_inits) {
        write_protected_content_staging_file(
            staging.path(),
            &runtime_media_dash_init_path(rendition.kind),
            init,
        )?;
    }
    // The head is rebuilt here from the protected parts as they come, so the
    // provider's finalized head is checked against the Runtime's own.
    let mut builder = CencDashIdentityBuilderV2::new(
        content_access_id,
        renditions
            .iter()
            .zip(&protected_inits)
            .map(|(rendition, init)| {
                CencDashRenditionDeclV2::from_init(
                    rendition.kind,
                    rendition.timescale,
                    init,
                    rendition.segment_count,
                )
            })
            .collect(),
    )
    .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?;
    let mut receipt = RuntimeMediaPreparationReceiptV2::new(renditions.len())?;
    let mut mpd_segments: Vec<Vec<CencDashMpdSegmentV2>> = Vec::with_capacity(renditions.len());
    for (rendition_index, rendition) in renditions.iter().enumerate() {
        let rendition_index_wire = u8::try_from(rendition_index)
            .map_err(|_| anyhow::anyhow!("Runtime custody protect input is invalid"))?;
        let clear_session = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
            &rendition.clear_init_segment,
            CencLayoutProfile::V2,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
        receipt.begin_rendition(
            rendition.kind,
            &rendition.clear_init_segment,
            rendition.segment_count,
        );
        let mut rendition_segments = Vec::with_capacity(rendition.segment_count as usize);
        for segment_index in 0..rendition.segment_count {
            // One clear part and one protected part are alive at a time, so the
            // memory of a mint does not grow with the duration.
            let clear = read_runtime_media_prepared_part(
                &runtime_prepared_segment_path(
                    &input.media.operation_root,
                    rendition.kind,
                    segment_index,
                ),
                true,
                MEDIA_PROVIDER_MAX_PREPARED_PART_BYTES_V2,
            )?;
            #[cfg(test)]
            input
                .media
                .part_reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let timeline = clear_session
                .validate_segment(&clear)
                .ok()
                .and_then(|layout| layout.timeline())
                .ok_or_else(invalid_prepared_media_output)?;
            receipt.push_segment(segment_index, &clear);
            let request = ProtectProviderRequestV1::new_protect_media_segment_v2(
                handle,
                rendition_index_wire,
                segment_index,
                &clear,
            )
            .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?;
            drop(clear);
            let response =
                invoke_typed_protect_provider(registry, "protect_media_segment", &request).await?;
            drop(request);
            match response.status() {
                ProtectProviderResponseStatusV1::MediaSegmentProtected
                    if response.segment_index() == Some(segment_index) => {}
                ProtectProviderResponseStatusV1::Failure
                    if response.failure_reason()
                        == Some(ProtectFailureReasonV2::CencTooManySubsamples) =>
                {
                    anyhow::bail!(RUNTIME_CUSTODY_MEDIA_TOO_MANY_SLICES_MESSAGE);
                }
                _ => anyhow::bail!("Runtime custody protect provider is unavailable"),
            }
            let protected = response
                .protected_segment()
                .filter(|protected| !protected.is_empty())
                .ok_or_else(|| anyhow::anyhow!(INVALID_OUTPUT))?;
            // The viewer fetches and decrypts a protected segment only up to
            // this size, so a larger one could never be played: refuse it here,
            // before anything of it is staged or published.
            if protected.len() > MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2 {
                anyhow::bail!(RUNTIME_CUSTODY_MEDIA_PART_TOO_LARGE_MESSAGE);
            }
            write_protected_content_staging_file(
                staging.path(),
                &runtime_media_dash_segment_path(rendition.kind, segment_index),
                protected,
            )?;
            builder
                .push_segment(protected)
                .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?;
            rendition_segments.push(CencDashMpdSegmentV2 {
                timeline,
                bytes: protected.len() as u64,
            });
        }
        mpd_segments.push(rendition_segments);
    }
    if receipt.finish() != input.media.preparation_receipt() {
        anyhow::bail!("Runtime custody media preparation output changed");
    }
    let finalized = invoke_typed_protect_provider(
        registry,
        "finalize_protection_session",
        &ProtectProviderRequestV1::new_finalize_protection_session(handle)
            .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?,
    )
    .await?;
    if finalized.status() != ProtectProviderResponseStatusV1::ProtectionSessionFinalized {
        anyhow::bail!("Runtime custody protect provider is unavailable");
    }
    let media_identity = finalized
        .media_identity_v2()
        .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?
        .ok_or_else(|| anyhow::anyhow!(INVALID_OUTPUT))?;
    let envelope = finalized
        .custody_envelope()
        .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?
        .ok_or_else(|| anyhow::anyhow!(INVALID_OUTPUT))?;
    let expected_media = builder
        .finish()
        .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?;
    let sessions = protected_inits
        .iter()
        .enumerate()
        .map(|(index, init)| ValidatedCencDashRenditionSessionV2::new(&media_identity, index, init))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?;
    let custody_pool = composition
        .signed_pool
        .pool_identity()
        .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?;
    let custody_epoch = composition
        .signed_epoch
        .epoch_identity()
        .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?;
    let custody_committee_authorization = composition
        .signed_committee_authorization
        .authorization_identity()
        .map_err(|_| anyhow::anyhow!("Runtime custody protect committee is invalid"))?;
    // The CENC protection header the provider wrote into every init ships in a
    // public media file and is what a client reading the artifacts directly
    // will route on. Every rendition must carry one and the same header, under
    // one protection system, and it must name exactly this session's content
    // access id, pool, epoch and committee authorization. A provider that
    // omits it, or points it at some other quorum, fails here rather than
    // publishing. Every init must also have been written by the active
    // encoder: a new mint is produced only by the writer binding.
    let expected_protection_header = CustodyProtectionHeader::new(
        content_access_id,
        &custody_pool,
        &custody_epoch,
        &custody_committee_authorization,
        CencMediaSuite::DashV2,
    );
    let common_protection_header =
        elastos_protected_content_custody::require_common_cenc_dash_protection_header_v2(
            &media_identity,
            &sessions,
        )
        .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?;
    if media_identity != expected_media
        || media_identity.default_kid() != content_access_id
        || *common_protection_header != expected_protection_header
        || !sessions
            .iter()
            .all(ValidatedCencDashRenditionSessionV2::protected_by_active_encoder)
        || envelope.manifest().encrypted_content() != media_identity.encrypted_content()
        || envelope.manifest().custody_pool() != custody_pool
        || envelope.manifest().custody_epoch() != custody_epoch
        || envelope.manifest().custody_committee_authorization() != custody_committee_authorization
    {
        anyhow::bail!(INVALID_OUTPUT);
    }
    write_protected_content_staging_file(
        staging.path(),
        PROTECTED_CONTENT_V2_IDENTITY_PATH,
        &media_identity
            .canonical_bytes()
            .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?,
    )?;
    let mpd = build_cenc_dash_mpd_v2(
        &protected_inits
            .iter()
            .zip(&mpd_segments)
            .map(|(protected_init, segments)| CencDashMpdRenditionV2 {
                protected_init,
                segments,
            })
            .collect::<Vec<_>>(),
    )
    .map_err(|_| anyhow::anyhow!(INVALID_OUTPUT))?;
    write_protected_content_staging_file(
        staging.path(),
        PROTECTED_CONTENT_V2_MPD_PATH,
        mpd.as_bytes(),
    )?;
    // The full check, once, on the private staging tree and before any draft
    // or custody effect exists: invalid output never reaches custody.
    let timelines: Vec<Vec<Fmp4SegmentTimelineV2>> = mpd_segments
        .iter()
        .map(|segments| segments.iter().map(|segment| segment.timeline).collect())
        .collect();
    verify_protected_content_dash_directory(staging.path(), &media_identity, Some(&timelines))?;
    journal
        .mark_intent_protect_finalized(request_id, handle)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    Ok(ProtectedRuntimeCustodyMediaDash {
        staging,
        media_identity,
        envelope,
    })
}

async fn invoke_typed_protect_provider(
    registry: &ProviderRegistry,
    op: &str,
    request: &ProtectProviderRequestV1,
) -> anyhow::Result<ProtectProviderResponseV1> {
    let request_value = serde_json::from_slice(
        &request
            .to_json_vec()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?;
    let data = invoke_json_provider(registry, PROTECT_PROVIDER_ID, op, request_value)
        .await
        .map_err(|_| anyhow::anyhow!("Runtime custody protect provider is unavailable"))?;
    ProtectProviderResponseV1::from_json_slice(
        &serde_json::to_vec(&data)
            .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))
}

/// The private directory a package is staged in before it is published.
fn create_protected_content_staging_directory(
    data_dir: &Path,
) -> anyhow::Result<tempfile::TempDir> {
    let parent = protected_content_root(data_dir);
    fs::create_dir_all(&parent)?;
    tempfile::Builder::new()
        .prefix("publish-")
        .tempdir_in(&parent)
        .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))
}

/// Writes one staged file, creating its directories. A file is written once:
/// an existing one is an error, never overwritten.
fn write_protected_content_staging_file(
    staging: &Path,
    relative: &str,
    bytes: &[u8],
) -> anyhow::Result<()> {
    const UNAVAILABLE: &str = "Runtime custody publish staging is unavailable";
    let path = staging.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| anyhow::anyhow!(UNAVAILABLE))?;
    }
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .map_err(|_| anyhow::anyhow!(UNAVAILABLE))?;
    file.write_all(bytes)
        .map_err(|_| anyhow::anyhow!(UNAVAILABLE))
}

/// Creates the private `publish-*` directory and its `protected-content/v1`
/// tree. Protect writes `object.epc1` into it as the chunks arrive.
fn create_protected_content_object_staging_directory(
    data_dir: &Path,
) -> anyhow::Result<tempfile::TempDir> {
    let parent = protected_content_root(data_dir);
    fs::create_dir_all(&parent)?;
    let staging = tempfile::Builder::new()
        .prefix("publish-")
        .tempdir_in(&parent)
        .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))?;
    fs::create_dir_all(staging.path().join("protected-content/v1"))
        .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))?;
    Ok(staging)
}

fn write_protected_content_object_manifest(
    directory: &Path,
    object_identity: &ChunkedPayloadObjectIdentityV1,
) -> anyhow::Result<()> {
    fs::write(
        directory.join(PROTECTED_CONTENT_OBJECT_MANIFEST_PATH),
        protected_content_object_manifest_bytes(object_identity)?,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))
}

/// Writes the framed object straight to its staging file and hashes it as it
/// goes, so protecting an object never holds the framed bytes together.
struct ObjectFramedStagingSink<W: std::io::Write> {
    writer: W,
    hasher: sha2::Sha256,
    bytes: u64,
}

impl<W: std::io::Write> ObjectFramedStagingSink<W> {
    fn new(writer: W) -> Self {
        Self {
            writer,
            hasher: sha2::Sha256::new(),
            bytes: 0,
        }
    }

    fn push(&mut self, framed: &[u8]) -> anyhow::Result<()> {
        self.writer
            .write_all(framed)
            .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))?;
        self.hasher.update(framed);
        self.bytes = self
            .bytes
            .checked_add(framed.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
        Ok(())
    }

    fn finish(mut self) -> anyhow::Result<(EncryptedContentIdentityV1, W)> {
        self.writer
            .flush()
            .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))?;
        let identity = EncryptedContentIdentityV1::new(
            Digest32::new(self.hasher.finalize().into()),
            self.bytes,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
        Ok((identity, self.writer))
    }
}

fn runtime_custody_library_publish_facts(
    object_uri: &str,
    source_storage: &str,
    draft: &RuntimeMintDraft,
    content_id: &str,
    evidence: &RuntimeVerifiedContentAvailability,
) -> RuntimeCustodyLibraryPublishFacts {
    let mint_id_hex = hex::encode(draft.mint_id().as_bytes());
    let receipt_digest_hex = hex::encode(evidence.receipt_digest().as_bytes());
    let availability = json!({
        "schema": "elastos.library.runtime-custody-availability/v1",
        "cid": evidence.content_cid(),
        "content_id": content_id,
        "mint_id": mint_id_hex,
        "status": PROTECTED_CONTENT_AVAILABLE_STATUS,
        "replicas": evidence.observed_replicas(),
        "checked_at": evidence.checked_at(),
        "receipt_digest": receipt_digest_hex,
    });
    RuntimeCustodyLibraryPublishFacts {
        content_cid: evidence.content_cid().to_string(),
        mint_id: draft.mint_id(),
        content_id: content_id.to_string(),
        display_name: runtime_custody_display_name(object_uri),
        availability: availability.clone(),
        receipt: json!({
            "schema": "elastos.library.runtime-custody-receipt/v1",
            "receipt_digest": receipt_digest_hex,
        }),
        content_security: json!({
            "schema": "elastos.library.published-content-security/v1",
            "object_uri": object_uri,
            "source_storage": source_storage,
            "published_payload": "runtime_custody_encrypted",
            "key_release_required": false,
            "status": "runtime_custody_available",
            "content_id": content_id,
            "mint_id": mint_id_hex,
            // What the capsule protects. The Library item is a `.ddrm`, whose
            // name cannot say whether it holds a film or a PDF, so the viewer
            // routes on this rather than on the item's own extension.
            "asset_mime": draft.content_identity().content_type(),
            "required_providers": [],
        }),
        listing_uri: None,
        capsule_uri: None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimePortableListingPackage {
    pub(crate) schema: String,
    pub(crate) mint_id: String,
    pub(crate) content_id: String,
    pub(crate) content_cid: String,
    pub(crate) metadata_cid: String,
    pub(crate) token_uri: String,
    pub(crate) publisher_profile_did: String,
    pub(crate) display_name: String,
    /// Media listings only. Kept as the FIRST of the two identity fields and
    /// in its original position so a media package's JSON is byte-identical
    /// to what every listing already on disk carries — `package_sha256`
    /// (recomputed over `serde_json::to_vec(package)` on every load) and the
    /// listing CID both depend on that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) media_identity_base64: Option<String>,
    /// Object listings only: a `RuntimeContentIdentityV1` canonical encoding
    /// (kind byte ‖ nested identity), reusing Task 12's already-reviewed
    /// encoding rather than inventing a second one. Absent on every media
    /// listing, so media packages keep their exact pre-object bytes.
    ///
    /// Exactly one of the two fields is present; see
    /// [`RuntimePortableListingPackage::decode_and_validate`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) content_identity_base64: Option<String>,
    pub(crate) content_access_id: String,
    pub(crate) key_envelope_identity_base64: String,
    pub(crate) rights_policy_identity_base64: String,
    pub(crate) content_key_commitment_base64: String,
    pub(crate) seller_address: String,
    pub(crate) chain_namespace: String,
    pub(crate) network: String,
    pub(crate) ledger: String,
    pub(crate) token_id: String,
    pub(crate) operative: String,
    pub(crate) quantity: String,
    pub(crate) price: String,
    pub(crate) pay_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) payment_processor: Option<String>,
    /// The mint's own transaction. Absent only on a listing adopted from an
    /// asset's shared `metadata.json` (origin `Asset`): chain and document do
    /// not state it, and a made-up hash would be a fabricated fact (D11).
    /// Skipped when absent so every package that carries it keeps its bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mint_transaction_hash: Option<String>,
    /// When the creator published it. Absent exactly when
    /// `mint_transaction_hash` is, for the same reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) published_at: Option<u64>,
    /// Plan B POOL-MINT (S7I-F2): an item a Home minted through a pool it
    /// uses carries the minting Home's signed share statement for it, so
    /// every Home, the pool owner included, rebuilds it on the pool path with
    /// the same `mint_id`. Absent keeps every other package's bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) pool_mint_share_b64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RuntimeCustodyListingOrigin {
    LocalCreator {
        principal_id: String,
        listing_uri: String,
        package_sha256: String,
    },
    Imported {
        listing_uri: String,
        package_sha256: String,
    },
    /// Adopted after a market purchase from the asset's shared
    /// `metadata.json` (D10): no listing package was ever published for it,
    /// so it names the asset it was built from and its digest is computed.
    Asset { asset_uri: String },
    /// Adopted from the asset's shared `metadata.json` for a principal the
    /// chain grants access to without a purchase. It carries zero terms
    /// nobody agreed to sell on, so it is never bought, shared or listed.
    Granted { asset_uri: String },
}

fn availability_kind_receipt() -> String {
    elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::RECEIPT.to_string()
}

fn availability_kind_is_receipt(kind: &str) -> bool {
    kind == elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::RECEIPT
}

/// Plan B T4.6: `kind` says how availability was proven. A record written
/// before it has no `kind` and reads as a receipt; a receipt is written
/// without `kind`, so such a record keeps its exact bytes. A verified fetch
/// has no replicas and no receipt digest (both empty).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyListingAvailabilitySummary {
    #[serde(
        default = "availability_kind_receipt",
        skip_serializing_if = "availability_kind_is_receipt"
    )]
    kind: String,
    checked_at: u64,
    observed_replicas: u32,
    receipt_digest: String,
}

impl RuntimeCustodyListingAvailabilitySummary {
    pub(crate) fn from_evidence(
        evidence: &elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1,
    ) -> Self {
        Self {
            kind: evidence.kind().to_string(),
            checked_at: evidence.checked_at(),
            observed_replicas: evidence.observed_replicas(),
            receipt_digest: evidence
                .receipt_digest()
                .map(|digest| hex::encode(digest.as_bytes()))
                .unwrap_or_default(),
        }
    }

    pub(crate) fn is_verified_fetch(&self) -> bool {
        self.kind
            == elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::VERIFIED_FETCH
    }

    /// What a purchase records of this availability: the receipt digest, or
    /// `verified-fetch` when no receipt was made (Plan B T4.6).
    pub(crate) fn purchase_digest(&self) -> String {
        if self.is_verified_fetch() {
            RUNTIME_PURCHASE_VERIFIED_FETCH_DIGEST.to_string()
        } else {
            format!("sha256:{}", self.receipt_digest)
        }
    }

    /// The availability receipt this listing was recorded against, as the bare
    /// hex the record stores. Callers that need the `sha256:` spelling add it.
    // Unused since T4.6 records `purchase_digest`; kept for review.
    #[allow(dead_code)]
    pub(crate) fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyListingRecord {
    pub(crate) schema: String,
    pub(crate) origin: RuntimeCustodyListingOrigin,
    pub(crate) package: RuntimePortableListingPackage,
    pub(crate) availability: RuntimeCustodyListingAvailabilitySummary,
}

impl RuntimeCustodyListingOrigin {
    /// The `elastos://` address this listing's package was published at.
    ///
    /// Both origins carry it: a local creator's listing keeps the URI it
    /// published to, and an imported one keeps the URI it was fetched from.
    /// Either way it names the same package, so passing it on is how a listing
    /// travels between Homes.
    ///
    /// An adopted listing has no package of its own; the asset it was built
    /// from is what travels instead. A granted listing travels nowhere: its
    /// terms are nobody's, so `None`.
    pub(crate) fn listing_uri(&self) -> Option<&str> {
        match self {
            Self::LocalCreator { listing_uri, .. } | Self::Imported { listing_uri, .. } => {
                Some(listing_uri)
            }
            Self::Asset { asset_uri } => Some(asset_uri),
            Self::Granted { .. } => None,
        }
    }

    /// Whether this listing was built for a chain grant rather than from
    /// terms anyone offered. Such a listing is never bought, shared or listed.
    pub(crate) const fn is_granted(&self) -> bool {
        matches!(self, Self::Granted { .. })
    }
}

impl RuntimeCustodyListingRecord {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.schema != RUNTIME_LISTING_SCHEMA_V1 {
            anyhow::bail!("Runtime custody listing is invalid");
        }
        self.package.decode_and_validate()?;
        match &self.origin {
            RuntimeCustodyListingOrigin::LocalCreator {
                principal_id,
                listing_uri,
                package_sha256,
            } => {
                validate_runtime_custody_public_text(principal_id)?;
                validate_runtime_portable_listing_origin(
                    listing_uri,
                    package_sha256,
                    &self.package,
                )?;
                validate_runtime_published_package_facts(&self.package)?;
            }
            RuntimeCustodyListingOrigin::Imported {
                listing_uri,
                package_sha256,
            } => {
                validate_runtime_portable_listing_origin(
                    listing_uri,
                    package_sha256,
                    &self.package,
                )?;
                validate_runtime_published_package_facts(&self.package)?;
            }
            RuntimeCustodyListingOrigin::Asset { asset_uri } => {
                validate_runtime_adopted_package_facts(asset_uri, &self.package)?;
            }
            RuntimeCustodyListingOrigin::Granted { asset_uri } => {
                validate_runtime_adopted_package_facts(asset_uri, &self.package)?;
                validate_runtime_granted_package_terms(&self.package)?;
            }
        }
        let availability = &self.availability;
        let valid = match availability.kind.as_str() {
            elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::RECEIPT => {
                availability.observed_replicas >= PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR
                    && availability.receipt_digest.len() == 64
                    && hex::decode(&availability.receipt_digest)
                        .is_ok_and(|bytes| bytes.len() == 32)
            }
            // Only an adopted listing on a non-holder proves availability by
            // a verified fetch (S4-U2).
            elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::VERIFIED_FETCH => {
                matches!(
                    self.origin,
                    RuntimeCustodyListingOrigin::Asset { .. }
                        | RuntimeCustodyListingOrigin::Granted { .. }
                ) && availability.observed_replicas == 0
                    && availability.receipt_digest.is_empty()
            }
            _ => false,
        };
        if availability.checked_at == 0 || !valid {
            anyhow::bail!("Runtime custody listing is invalid");
        }
        Ok(())
    }

    pub(crate) fn portable_package_digest(&self) -> String {
        let package_sha256 = match &self.origin {
            RuntimeCustodyListingOrigin::LocalCreator { package_sha256, .. }
            | RuntimeCustodyListingOrigin::Imported { package_sha256, .. } => {
                package_sha256.clone()
            }
            // Never published, so never stated: computed over the package the
            // same way a published one's digest was, which is what a purchase
            // record binds to.
            RuntimeCustodyListingOrigin::Asset { .. }
            | RuntimeCustodyListingOrigin::Granted { .. } => {
                runtime_portable_package_sha256(&self.package)
            }
        };
        format!("sha256:{package_sha256}")
    }
}

/// `sha256` over a package's canonical bytes, bare hex.
fn runtime_portable_package_sha256(package: &RuntimePortableListingPackage) -> String {
    serde_json::to_vec(package)
        .map(|bytes| hex::encode(sha2::Sha256::digest(bytes)))
        .unwrap_or_default()
}

/// A package this Runtime or another one published (origins `LocalCreator`
/// and `Imported`): the mint's transaction and publication time are facts it
/// states, and its publisher is a Runtime profile, a `did:key`.
fn validate_runtime_published_package_facts(
    package: &RuntimePortableListingPackage,
) -> anyhow::Result<()> {
    if package.mint_transaction_hash.is_none() || package.published_at.is_none() {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    crate::crypto::decode_did_key(&package.publisher_profile_did)
        .map(|_| ())
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))
}

/// A package adopted from an asset's shared `metadata.json` (origin `Asset`,
/// D11 and D16): it states neither fact the shared document lacks, its
/// publisher is the document's `did:pkh` on the package's own chain, and the
/// asset it names is the package's own metadata folder.
fn validate_runtime_adopted_package_facts(
    asset_uri: &str,
    package: &RuntimePortableListingPackage,
) -> anyhow::Result<()> {
    if package.mint_transaction_hash.is_some()
        || package.published_at.is_some()
        || runtime_portable_listing_cid(asset_uri)? != package.metadata_cid
    {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    let chain_id = package
        .chain_namespace
        .strip_prefix("eip155:")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    match parse_runtime_publisher_pkh(&package.publisher_profile_did) {
        Some((pkh_chain_id, _)) if pkh_chain_id == chain_id => Ok(()),
        _ => anyhow::bail!("Runtime custody portable listing is invalid"),
    }
}

/// The acquisition stage of a granted copy: it names the chain and nothing
/// else, because no transaction stands behind the copy.
pub(crate) fn runtime_custody_grant_stage(
    chain_namespace: &str,
    network: &str,
) -> RuntimeCustodyPurchaseStageRecord {
    RuntimeCustodyPurchaseStageRecord {
        stage: RUNTIME_CUSTODY_GRANT_STAGE.to_string(),
        effect_id: String::new(),
        approval_request_id: String::new(),
        request_sha256: String::new(),
        chain_namespace: chain_namespace.to_string(),
        network: network.to_string(),
        to: String::new(),
        value: String::new(),
        data: String::new(),
    }
}

fn runtime_custody_grant_stage_is_empty(stage: &RuntimeCustodyPurchaseStageRecord) -> bool {
    *stage == runtime_custody_grant_stage(&stage.chain_namespace, &stage.network)
}

/// The terms a granted listing states (origin `Granted`): one copy, sold by
/// the item's own operative for nothing in the native token. No seller ever
/// offered them, which is what keeps them from passing for an offer.
fn runtime_granted_package_terms(operative: &str) -> (String, String, String, String) {
    (
        operative.to_ascii_lowercase(),
        "0x1".to_string(),
        "0x0".to_string(),
        RUNTIME_CUSTODY_ZERO_ADDRESS.to_string(),
    )
}

fn validate_runtime_granted_package_terms(
    package: &RuntimePortableListingPackage,
) -> anyhow::Result<()> {
    let (seller_address, quantity, price, pay_token) =
        runtime_granted_package_terms(&package.operative);
    if package.seller_address != seller_address
        || package.quantity != quantity
        || package.price != price
        || package.pay_token != pay_token
        || package.payment_processor.is_some()
    {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    Ok(())
}

/// `did:pkh:eip155:<chainId>:<address>` with a canonical decimal chain id and a
/// lowercase `0x` + 40 hex address, as `(chain_id, address)`.
pub(crate) fn parse_runtime_publisher_pkh(value: &str) -> Option<(u64, &str)> {
    let rest = value.strip_prefix("did:pkh:eip155:")?;
    let (chain_id, address) = rest.split_once(':')?;
    let parsed = chain_id.parse::<u64>().ok()?;
    if parsed.to_string() != chain_id {
        return None;
    }
    validate_runtime_custody_evm_address(address).ok()?;
    (address == address.to_ascii_lowercase()).then_some((parsed, address))
}

fn validate_runtime_portable_listing_origin(
    listing_uri: &str,
    package_sha256: &str,
    package: &RuntimePortableListingPackage,
) -> anyhow::Result<()> {
    if listing_uri != format!("elastos://{}", runtime_portable_listing_cid(listing_uri)?)
        || package_sha256.len() != 64
        || hex::decode(package_sha256).map_or(true, |bytes| bytes.len() != 32)
        || package_sha256 != hex::encode(sha2::Sha256::digest(serde_json::to_vec(package)?))
    {
        anyhow::bail!("Runtime custody listing is invalid");
    }
    Ok(())
}

struct DecodedRuntimePortableAsset {
    content_identity: RuntimeContentIdentityV1,
    content_access_id: ContentAccessIdV1,
    key_envelope: elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
    rights_policy: RightsPolicyIdentityV1,
    content_key_commitment: Digest32,
    /// POOL-MINT: minted through a pool its minter uses (signed share statement).
    pool_minted: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimePortableMetadata {
    schema: String,
    name: String,
    mime_type: String,
    codecs: String,
    encrypted_content_cid: String,
    content_access_id: String,
    protected_content_identity: String,
    mint_id: String,
    publisher_profile_did: String,
    /// Mirrors [`RuntimePortableListingPackage`]'s pair exactly (same order,
    /// same skip-when-absent rule), so a media metadata document keeps its
    /// pre-object bytes and `verify_runtime_portable_metadata` can compare
    /// both fields field-for-field against the package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    media_identity_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content_identity_base64: Option<String>,
    key_envelope_identity_base64: String,
    rights_policy_identity_base64: String,
    content_key_commitment_base64: String,
}

/// The two base64 identity fields a portable listing/metadata document
/// carries for `content_identity`: `(media_identity_base64,
/// content_identity_base64)`, exactly one of which is `Some`.
///
/// Media keeps writing `media_identity_base64` with the bare
/// `CencFmp4MediaIdentityV1` canonical bytes it always wrote — the object
/// widening must not move a single byte of a media listing, because
/// `package_sha256` and the listing CID are computed over them.
pub(crate) fn runtime_portable_identity_fields(
    content_identity: &RuntimeContentIdentityV1,
) -> anyhow::Result<(Option<String>, Option<String>)> {
    match content_identity {
        RuntimeContentIdentityV1::Media(media) => Ok((
            Some(base64::engine::general_purpose::STANDARD.encode(media.canonical_bytes()?)),
            None,
        )),
        // A head rides the object field, kind byte included (spec section 2).
        RuntimeContentIdentityV1::Object(_) | RuntimeContentIdentityV1::MediaDash(_) => {
            Ok((
                None,
                Some(base64::engine::general_purpose::STANDARD.encode(
                    content_identity.canonical_bytes().map_err(|_| {
                        anyhow::anyhow!("Runtime custody portable listing is invalid")
                    })?,
                )),
            ))
        }
    }
}

/// The `codecs` declaration a portable listing carries for a content kind:
/// the media identity's own `codecs` string, and the empty string for an
/// object, which has no codec declaration at all. Not a placeholder that is
/// then ignored — `verify_runtime_portable_metadata` compares the published
/// document's `codecs` against exactly this value, so an object metadata
/// document declaring any codec is rejected.
pub(crate) fn runtime_portable_content_codecs(
    content_identity: &RuntimeContentIdentityV1,
) -> std::borrow::Cow<'_, str> {
    match content_identity {
        RuntimeContentIdentityV1::Media(media) => std::borrow::Cow::Borrowed(media.codecs()),
        // The head pins its codecs per kind, so the joined string is the head's
        // own: video first, then audio, as the head lists them.
        RuntimeContentIdentityV1::MediaDash(head) => std::borrow::Cow::Owned(
            head.renditions()
                .iter()
                .map(|rendition| rendition.codecs())
                .collect::<Vec<_>>()
                .join(","),
        ),
        RuntimeContentIdentityV1::Object(_) => std::borrow::Cow::Borrowed(""),
    }
}

impl RuntimePortableListingPackage {
    fn decode_and_validate(&self) -> anyhow::Result<DecodedRuntimePortableAsset> {
        // The token URI names the metadata DIRECTORY. It used to name the
        // `metadata.json` inside it, which is what put a doubled path on chain
        // once the Operative appended its own suffix, so listings published
        // before that fix carry the older spelling and still verify.
        let directory_uri = format!("ipfs://{}", self.metadata_cid);
        let legacy_file_uri = format!("{directory_uri}/metadata.json");
        if self.schema != RUNTIME_PORTABLE_LISTING_SCHEMA_V1
            || (self.token_uri != directory_uri && self.token_uri != legacy_file_uri)
            || self.published_at == Some(0)
        {
            anyhow::bail!("Runtime custody portable listing is invalid");
        }
        let _ = parse_mint_id_hex(&self.mint_id)?;
        validate_runtime_custody_public_text(&self.content_id)?;
        validate_runtime_custody_cid(&self.content_cid)?;
        validate_runtime_custody_cid(&self.metadata_cid)?;
        validate_runtime_custody_profile_did(&self.publisher_profile_did)?;
        validate_runtime_custody_display_name(&self.display_name)?;
        validate_runtime_custody_evm_address(&self.seller_address)?;
        validate_runtime_custody_public_text(&self.chain_namespace)?;
        validate_runtime_custody_public_text(&self.network)?;
        validate_runtime_custody_evm_address(&self.ledger)?;
        validate_runtime_custody_canonical_quantity(&self.token_id)?;
        validate_runtime_custody_evm_address(&self.operative)?;
        validate_runtime_custody_canonical_quantity(&self.quantity)?;
        validate_runtime_custody_canonical_quantity(&self.price)?;
        validate_runtime_custody_evm_address(&self.pay_token)?;
        if let Some(payment_processor) = &self.payment_processor {
            validate_runtime_custody_evm_address(payment_processor)?;
        }
        // Both facts are optional at this level; which origin may omit them
        // is `RuntimeCustodyListingRecord::validate`'s to judge. What is
        // present must still be canonical.
        if let Some(mint_transaction_hash) = &self.mint_transaction_hash {
            let transaction_hash = decode_0x_hex(mint_transaction_hash)
                .filter(|bytes| bytes.len() == 32)
                .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
            if *mint_transaction_hash != format!("0x{}", hex::encode(transaction_hash)) {
                anyhow::bail!("Runtime custody portable listing is invalid");
            }
        }
        // Exactly one identity field, dispatched on which one is present —
        // never a default, never a silently-ignored second field. A media
        // listing MUST use `media_identity_base64` (the bare media canonical
        // bytes it always used); an object listing MUST use
        // `content_identity_base64`. A `RuntimeContentIdentityV1::Media`
        // hiding inside `content_identity_base64` is a cross-kind encoding
        // that would give one listing two possible byte encodings, so it is
        // rejected rather than accepted.
        let content_identity = match (&self.media_identity_base64, &self.content_identity_base64) {
            (Some(media_identity_base64), None) => {
                RuntimeContentIdentityV1::Media(decode_runtime_portable_contract(
                    media_identity_base64,
                    MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize,
                )?)
            }
            (None, Some(content_identity_base64)) => {
                let decoded = RuntimeContentIdentityV1::from_canonical_bytes(
                    &decode_runtime_portable_base64(
                        content_identity_base64,
                        MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize,
                    )?,
                )
                .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
                match decoded {
                    RuntimeContentIdentityV1::Object(_)
                    | RuntimeContentIdentityV1::MediaDash(_) => decoded,
                    RuntimeContentIdentityV1::Media(_) => {
                        anyhow::bail!("Runtime custody portable listing is invalid")
                    }
                }
            }
            (Some(_), Some(_)) | (None, None) => {
                anyhow::bail!("Runtime custody portable listing is invalid")
            }
        };
        let key_envelope: elastos_protected_content_contracts::KeyEnvelopeIdentityV1 =
            decode_runtime_portable_contract(
                &self.key_envelope_identity_base64,
                MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize,
            )?;
        let rights_policy = decode_runtime_portable_contract(
            &self.rights_policy_identity_base64,
            MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize,
        )?;
        let content_access_id = ContentAccessIdV1::new(
            decode_0x_hex(&self.content_access_id)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
        if self.content_access_id != format!("0x{}", hex::encode(content_access_id.as_bytes())) {
            anyhow::bail!("Runtime custody portable listing is invalid");
        }
        let content_key_commitment = Digest32::new(
            decode_runtime_portable_base64(&self.content_key_commitment_base64, 32)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?,
        );
        if content_identity.encrypted_content() != key_envelope.encrypted_content()
            || runtime_protected_content_id(content_identity.encrypted_content())?
                != self.content_id
            || content_identity.content_type().len() > MAX_RUNTIME_CUSTODY_PUBLIC_TEXT_BYTES
            || runtime_portable_content_codecs(&content_identity).len()
                > MAX_RUNTIME_CUSTODY_PUBLIC_TEXT_BYTES
        {
            anyhow::bail!("Runtime custody portable listing is invalid");
        }
        let pool_minted = verify_pool_mint_share(
            self.pool_mint_share_b64.as_deref(),
            &key_envelope,
            content_access_id,
        )?;
        Ok(DecodedRuntimePortableAsset {
            content_identity,
            content_access_id,
            key_envelope,
            rights_policy,
            content_key_commitment,
            pool_minted,
        })
    }
}

/// Plan B POOL-MINT (S7I-F2): whether a listing's item was minted through a
/// pool its minter uses. The carried share statement must be signed by the
/// minter it names and name exactly this item's key envelope and KID; a
/// tampered or swapped one is refused. `false` without one.
fn verify_pool_mint_share(
    encoded: Option<&str>,
    key_envelope: &elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
    content_access_id: ContentAccessIdV1,
) -> anyhow::Result<bool> {
    let Some(encoded) = encoded else {
        return Ok(false);
    };
    let mint_share: elastos_protected_content_contracts::SignedPoolMintShareV1 =
        decode_runtime_portable_contract(encoded, MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize)?;
    mint_share
        .verify_for_item(key_envelope, content_access_id)
        .map_err(|error| {
            tracing::debug!(
                ?error,
                "a pool-minted listing's share statement does not verify"
            );
            anyhow::anyhow!("Runtime custody portable listing is invalid")
        })?;
    Ok(true)
}

fn runtime_portable_listing_cid(uri: &str) -> anyhow::Result<&str> {
    let value = uri
        .strip_prefix("elastos://")
        .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    validate_runtime_custody_cid(value)?;
    Ok(value)
}

fn validate_runtime_custody_cid(value: &str) -> anyhow::Result<()> {
    let parsed = cid::Cid::try_from(value)
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    anyhow::ensure!(
        parsed.to_string() == value,
        "Runtime custody portable listing is invalid"
    );
    Ok(())
}

/// A publisher identity, typed by its DID method (D16): a Runtime profile's
/// `did:key`, or the `did:pkh` an adopted package names. Which of the two a
/// package may carry depends on its origin, which
/// `RuntimeCustodyListingRecord::validate` knows and this does not.
fn validate_runtime_custody_profile_did(value: &str) -> anyhow::Result<()> {
    validate_runtime_custody_public_text(value)?;
    if parse_runtime_publisher_pkh(value).is_some() {
        return Ok(());
    }
    crate::crypto::decode_did_key(value)
        .map(|_| ())
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))
}

fn decode_runtime_portable_base64(value: &str, max: usize) -> anyhow::Result<Vec<u8>> {
    decode_canonical_base64_bytes(value, max, "portable listing")
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))
}

fn decode_runtime_portable_contract<T: CanonicalContract>(
    value: &str,
    max: usize,
) -> anyhow::Result<T> {
    T::from_canonical_bytes(&decode_runtime_portable_base64(value, max)?)
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))
}

/// Fetch one named file from a published directory, verified against the
/// directory's own manifest.
///
/// Sibling files are expected: a listing directory now carries the Elacity
/// documents beside the runtime's `manifest.json`. What makes that safe is
/// unchanged — `verify_content_object_file` checks the named file's bytes
/// against the hash the manifest records for it, so a sibling can neither
/// stand in for it nor alter it.
async fn fetch_runtime_portable_file(
    registry: &ProviderRegistry,
    cid: &str,
    path: &str,
) -> anyhow::Result<(crate::content::ContentObjectManifest, Vec<u8>)> {
    let manifest = crate::content::fetch_content_object_manifest(registry, cid).await?;
    let file = manifest
        .files
        .iter()
        .find(|file| file.path == path)
        .filter(|file| file.size <= MAX_RUNTIME_PORTABLE_LISTING_BYTES)
        .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    let bytes = crate::content::fetch_bytes_via_provider(registry, cid, Some(path)).await?;
    if bytes.len() as u64 > MAX_RUNTIME_PORTABLE_LISTING_BYTES {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    crate::content::verify_content_object_file(cid, file, &bytes)?;
    Ok((manifest, bytes))
}

async fn verify_runtime_portable_metadata(
    registry: &ProviderRegistry,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
) -> anyhow::Result<()> {
    // `manifest.json` is where the runtime's document lives in a listing
    // published since the Elacity folder took the `metadata.json` name. Older
    // listings have it at `metadata.json` with no siblings, so that name is
    // tried second — and only accepted when the document there really is the
    // runtime's, so an Elacity `metadata.json` from a folder whose
    // `manifest.json` is missing is refused rather than mistaken for one.
    let (manifest, bytes, is_listing_folder) =
        match fetch_runtime_portable_file(registry, &package.metadata_cid, "manifest.json").await {
            Ok((manifest, bytes)) => (manifest, bytes, true),
            Err(_) => {
                let (manifest, bytes) =
                    fetch_runtime_portable_file(registry, &package.metadata_cid, "metadata.json")
                        .await?;
                (manifest, bytes, false)
            }
        };
    // The one interop fact a marketplace rejects outright: the listing
    // document's `kid` is the on-chain `contentId`, and the content market
    // refuses an asset whose metadata disagrees. Checking it here turns a
    // listing that would fail silently on chain into one that fails where the
    // cause is legible. Only a listing folder has the document to check.
    if is_listing_folder {
        let (_, listing_bytes) =
            fetch_runtime_portable_file(registry, &package.metadata_cid, "metadata.json").await?;
        let listing: serde_json::Value = serde_json::from_slice(&listing_bytes)
            .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
        let expected_kid = format!("0x{}", package.content_access_id.trim_start_matches("0x"));
        if listing.get("kid").and_then(serde_json::Value::as_str) != Some(expected_kid.as_str()) {
            anyhow::bail!("Runtime custody portable listing is invalid");
        }
    }
    let metadata: RuntimePortableMetadata = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    if serde_json::to_vec(&metadata)? != bytes
        || manifest.schema != "elastos.content.object.manifest/v1"
        || manifest.kind != "directory"
        || metadata.schema != "elastos.protected-content.metadata/v1"
        || metadata.name != package.display_name
        || metadata.mime_type != decoded.content_identity.content_type()
        || metadata.codecs != runtime_portable_content_codecs(&decoded.content_identity)
        || metadata.encrypted_content_cid != package.content_cid
        || metadata.content_access_id != package.content_access_id
        || metadata.protected_content_identity != package.content_id
        || metadata.mint_id != package.mint_id
        || metadata.publisher_profile_did != package.publisher_profile_did
        || metadata.media_identity_base64 != package.media_identity_base64
        || metadata.content_identity_base64 != package.content_identity_base64
        || metadata.key_envelope_identity_base64 != package.key_envelope_identity_base64
        || metadata.rights_policy_identity_base64 != package.rights_policy_identity_base64
        || metadata.content_key_commitment_base64 != package.content_key_commitment_base64
    {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    Ok(())
}

async fn verify_runtime_portable_chain(
    registry: &ProviderRegistry,
    package: &RuntimePortableListingPackage,
) -> anyhow::Result<()> {
    let chain_id = package
        .chain_namespace
        .strip_prefix("eip155:")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    let resolve = |request| async move {
        let response = registry
            .send_raw(CHAIN_PROVIDER_ID, &request)
            .await
            .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
        response
            .get("data")
            .cloned()
            .filter(|_| response.get("status").and_then(Value::as_str) == Some("ok"))
            .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))
    };
    // The one reader of the mint hash. Only an imported listing reaches here,
    // and a published package always states it.
    let mint_transaction_hash = package
        .mint_transaction_hash
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    let receipt: crate::api::gateway::ResolvedProtectedContentMintReceipt = serde_json::from_value(
        resolve(json!({
            "op": "resolve_protected_content_mint_receipt", "network": package.network,
            "hash": mint_transaction_hash, "creator": package.seller_address,
            "ledger": package.ledger, "token_uri": package.token_uri, "op_type_code": 1,
        }))
        .await?,
    )?;
    let listing: crate::api::gateway::ResolvedProtectedContentVerifiedListing = serde_json::from_value(resolve(json!({
        "op": "resolve_protected_content_verified_listing", "network": package.network,
        "seller": package.seller_address, "ledger": package.ledger, "token_id": package.token_id,
    })).await?)?;
    if receipt.schema != "elastos.chain.protected-content-mint-receipt/v1"
        || listing.schema != "elastos.chain.protected-content-verified-listing/v1"
        || receipt.network != package.network
        || listing.network != package.network
        || receipt.chain_id != chain_id
        || listing.chain_id != chain_id
        || receipt.token_id != package.token_id
        || receipt.operative != package.operative
        || !listing.seller.eq_ignore_ascii_case(&package.seller_address)
        || !listing.ledger.eq_ignore_ascii_case(&package.ledger)
        || listing.token_id != package.token_id
        || listing.operative != package.operative
        || listing.quantity != package.quantity
        || listing.price != package.price
        || !listing.pay_token.eq_ignore_ascii_case(&package.pay_token)
        || listing.payment_processor != package.payment_processor
    {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Plan B T4.6: a Home that does not hold an item's ciphertext.
// ---------------------------------------------------------------------------

/// How an item was minted. Every M1 item is composition-minted; T7.6 adds
/// `Pool`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ItemMintPath {
    Composition,
    /// Plan B POOL-MINT: minted by a Home through a pool it uses and does
    /// not own; pool-bound on every Home, so `mint_id` is the same everywhere.
    Pool,
}

/// Which node bindings a draft rebuilt here carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DraftNodeBindings {
    /// This Home's composition's selected nodes, as at mint.
    Composition,
    /// The item's epoch committee, bound by `pool_node_owner_state_root`
    /// (S4-Q15).
    PoolBound,
}

/// The one binding choice (re-anchor fix F2): every verifier and rebuild
/// site asks here. A composition-minted item keeps its composition bindings
/// on its holder and owner, and is pool-bound on a Home that does not hold
/// it. T7.6 adds the pool-minted branch, pool-bound everywhere.
pub(crate) fn draft_node_bindings_for(
    item: ItemMintPath,
    holds_ciphertext: bool,
) -> DraftNodeBindings {
    match item {
        ItemMintPath::Composition if holds_ciphertext => DraftNodeBindings::Composition,
        ItemMintPath::Composition | ItemMintPath::Pool => DraftNodeBindings::PoolBound,
    }
}

/// Why a portable listing is being verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortableVerifyMode {
    /// A package imported from a listing URI.
    Import,
    /// A listing adopted from an asset or a grant.
    Adopt,
    /// The fresh check before a buy or an open.
    Open,
}

/// What a Home that does not hold the ciphertext checks (S4-U2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NonHolderCheck {
    /// Adoption: the manifest and every file, fetched and verified now.
    FullFetch,
    /// An open: the manifest against the bound identity only. The staging
    /// pool server verifies the files it serves (T3.4).
    ManifestOnly,
}

/// An imported package names no pool this Home can verify it against, so
/// on a non-holder it is unresolved (S4-Q14).
pub(crate) fn non_holder_check(mode: PortableVerifyMode) -> anyhow::Result<NonHolderCheck> {
    match mode {
        PortableVerifyMode::Import => Err(RuntimeCustodyUnresolved::error()),
        PortableVerifyMode::Adopt => Ok(NonHolderCheck::FullFetch),
        PortableVerifyMode::Open => Ok(NonHolderCheck::ManifestOnly),
    }
}

/// The item's pool, from this Home's own, served and known pools.
pub(crate) async fn runtime_custody_pool_for_key_envelope(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    key_envelope: &elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
    now: u64,
) -> Result<
    elastos_protected_content_runtime::ResolvedPoolV1,
    elastos_protected_content_runtime::PoolResolveError,
> {
    crate::custody_pool_resolver::home_pool_resolver(data_dir, registry)
        .resolve(key_envelope, &[], now)
        .await
}

/// [`runtime_custody_pool_for_key_envelope`] from what this Home keeps, with
/// no Carrier call and no refresh: the listing (T4.7) uses it.
pub(crate) fn runtime_custody_pool_for_key_envelope_cached(
    data_dir: &Path,
    key_envelope: &elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
    now: u64,
) -> Result<
    elastos_protected_content_runtime::ResolvedPoolV1,
    elastos_protected_content_runtime::PoolResolveError,
> {
    let mut candidates = Vec::new();
    if let Ok(Some(own)) = crate::custody_pool_descriptor::owner_descriptor(data_dir, now) {
        candidates.push(("own", own.into()));
    }
    for served in
        crate::custody_pool_descriptor::served_descriptors(data_dir, now).unwrap_or_default()
    {
        candidates.push(("served", served));
    }
    for known in crate::custody_pool_resolver::known_pool_descriptors(data_dir) {
        candidates.push(("known", known));
    }
    elastos_protected_content_runtime::resolve_pool_from_candidates(
        candidates,
        &elastos_protected_content_runtime::AcceptAnyPool,
        key_envelope,
        &[],
        now,
    )
}

/// Pool-bound node bindings (S4-Q15): each node of the item's epoch, in the
/// epoch's order, with the operator and failure domain its committee names
/// and `pool_node_owner_state_root` as its owner-state root.
pub(crate) fn pool_bound_node_bindings(
    resolved: &elastos_protected_content_runtime::ResolvedPoolV1,
) -> anyhow::Result<Vec<elastos_protected_content_runtime::RuntimeMintNodeBinding>> {
    let epoch_identity = resolved
        .epoch
        .epoch_identity()
        .map_err(|_| anyhow::anyhow!("the item's custody epoch is invalid"))?;
    let members = resolved.epoch.signed_pool().statement().members();
    resolved
        .epoch
        .signed_epoch()
        .statement()
        .nodes()
        .iter()
        .map(|node| {
            let key = node.node_public_key();
            let member = members
                .iter()
                .find(|member| member.node_public_key() == key)
                .ok_or_else(|| anyhow::anyhow!("the item's custody committee is incomplete"))?;
            elastos_protected_content_runtime::RuntimeMintNodeBinding::new(
                key,
                member.operator_id(),
                member.failure_domain_id(),
                elastos_protected_content_runtime::pool_node_owner_state_root(
                    resolved.descriptor.pool(),
                    epoch_identity,
                    key,
                ),
            )
            .map_err(|_| anyhow::anyhow!("the item's custody committee is invalid"))
        })
        .collect()
}

/// A non-holder's availability check (S4-U2): the content plane is asked
/// for the files by CID (local store, then Carrier holders), and nothing is
/// pinned or ensured here.
pub(crate) async fn verify_non_holder_content(
    registry: &ProviderRegistry,
    content_cid: &str,
    content_id: &str,
    identity: &RuntimeContentIdentityV1,
    check: NonHolderCheck,
    now: u64,
) -> anyhow::Result<elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1> {
    use elastos_protected_content_runtime::RuntimeVerifiedContentIdentityRootV1 as Root;

    let manifest = crate::content::fetch_content_object_manifest(registry, content_cid).await?;
    let root = match identity {
        RuntimeContentIdentityV1::Media(media) => {
            match check {
                NonHolderCheck::FullFetch => {
                    verify_protected_content_manifest_and_files(
                        registry,
                        content_cid,
                        &manifest,
                        media,
                    )
                    .await?;
                }
                NonHolderCheck::ManifestOnly => {
                    protected_content_media_manifest_files(&manifest, media)?;
                }
            }
            Root::for_media(media)
        }
        RuntimeContentIdentityV1::Object(object) => {
            match check {
                NonHolderCheck::FullFetch => {
                    verify_protected_content_object_manifest_and_files(
                        registry,
                        content_cid,
                        &manifest,
                        object,
                    )
                    .await?;
                }
                NonHolderCheck::ManifestOnly => {
                    protected_content_object_manifest_files(&manifest, object)?;
                }
            }
            Root::for_object(object)
                .map_err(|_| anyhow::anyhow!("protected content object identity is invalid"))?
        }
        RuntimeContentIdentityV1::MediaDash(head) => {
            verify_protected_content_dash_manifest(&manifest, head)?;
            if check == NonHolderCheck::FullFetch {
                for file in &manifest.files {
                    let bytes = crate::content::fetch_bytes_via_provider(
                        registry,
                        content_cid,
                        Some(&file.path),
                    )
                    .await?;
                    crate::content::verify_content_object_file(content_cid, file, &bytes)?;
                }
            }
            Root::for_media_dash(head)
        }
    };
    let fetch = elastos_protected_content_runtime::RuntimeVerifiedContentFetchV1::new(
        content_cid,
        content_id,
        now,
        identity.encrypted_content().clone(),
        root,
    )
    .map_err(|_| anyhow::anyhow!("protected content availability is invalid"))?;
    Ok(elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::VerifiedFetch(fetch))
}

/// The non-holder rebuild: the item's pool is resolved, the content checked
/// as `mode` asks, and the draft bound to the pool's committee. Its
/// `mint_id` is this Home's own (adoption takes it from this draft).
async fn rebuild_non_holder_portable_content(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
    now_unix_seconds: u64,
    mode: PortableVerifyMode,
) -> anyhow::Result<(
    RuntimeMintDraft,
    elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1,
)> {
    let check = non_holder_check(mode)?;
    let now_unix_seconds = now_unix_seconds.max(crate::auth::now_ts());
    let resolved = runtime_custody_pool_for_key_envelope(
        data_dir,
        registry.clone(),
        &decoded.key_envelope,
        now_unix_seconds,
    )
    .await
    .map_err(|error| {
        tracing::debug!(%error, "runtime custody: the item's pool is unresolved");
        RuntimeCustodyUnresolved::error()
    })?;
    let evidence = verify_non_holder_content(
        registry,
        &package.content_cid,
        &package.content_id,
        &decoded.content_identity,
        check,
        now_unix_seconds,
    )
    .await?;
    let draft = RuntimeMintDraft::new_from_identity(
        decoded.content_identity.clone(),
        decoded.content_access_id,
        decoded.key_envelope.clone(),
        decoded.rights_policy.clone(),
        decoded.content_key_commitment,
        decoded.key_envelope.threshold(),
        pool_bound_node_bindings(&resolved)?,
    )?;
    Ok((draft, evidence))
}

/// Re-verifies a portable listing's published content and rebuilds the mint
/// draft it commits to. Dispatches on the listing's own content kind with an
/// explicit two-arm match: media keeps the untouched
/// [`verify_runtime_portable_media`] path and objects take
/// [`verify_runtime_portable_object`] — never silently treated as media, and
/// never defaulted.
async fn verify_runtime_portable_content(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
    now_unix_seconds: u64,
    publisher_binding: RuntimeManifestPublisherBinding,
    mode: PortableVerifyMode,
) -> anyhow::Result<(
    RuntimeMintDraft,
    elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1,
)> {
    let (draft, availability) = rebuild_runtime_portable_content(
        data_dir,
        registry,
        package,
        decoded,
        now_unix_seconds,
        publisher_binding,
        mode,
    )
    .await?;
    if draft.mint_id() != parse_mint_id_hex(&package.mint_id)? {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    Ok((draft, availability))
}

/// Whether this Home's custody pool holds the keys `key_envelope` names: the
/// envelope's node set -- its members under its own threshold -- is the one
/// this Home's composition selects. That is exactly what a draft rebuilt here
/// is bound to (`RuntimeMintDraft::new_from_identity`), and the only nodes a
/// release from here can reach. The pool, epoch and committee identities are
/// not compared: an epoch renewed over the same members still holds the key.
/// The threshold must be the epoch's own: an envelope asking for more (or
/// fewer) of the same members is not one this pool issued.
///
/// A Home with no custody composition holds no keys at all: `false`, so its
/// purchases answer that rather than waiting forever.
pub(crate) fn runtime_custody_composition_holds_key_envelope(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    key_envelope: &elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
) -> anyhow::Result<bool> {
    let Some(composition) = load_runtime_custody_composition(data_dir, registry.clone())? else {
        return Ok(false);
    };
    let threshold = composition.signed_epoch.statement().threshold();
    if key_envelope.threshold() != threshold {
        return Ok(false);
    }
    let configured = composition.configured_nodes()?;
    let selected = resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        crate::auth::now_ts(),
        &configured,
    )?;
    let node_set = elastos_protected_content_contracts::NodeSetV1::new(
        threshold,
        selected
            .iter()
            .map(|node| node.binding().node_public_key())
            .collect(),
    );
    Ok(node_set
        .ok()
        .and_then(|node_set| node_set.node_set_id().ok())
        .is_some_and(|node_set_id| node_set_id == key_envelope.node_set_id()))
}

/// Plan B T4.4 (S4-A1): whether this Home may open the item through its own
/// local V1 path. Both must hold: this Home's installed composition holds the
/// item's key envelope, and its local decrypt target is ready.
pub(crate) async fn runtime_custody_local_holder(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    key_envelope: &elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
) -> anyhow::Result<bool> {
    if !runtime_custody_composition_holds_key_envelope(data_dir, registry, key_envelope)? {
        return Ok(false);
    }
    Ok(registry
        .has_ready_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)
        .await)
}

/// Plan B T4.7: whether a buy from this Home has a route to the item's pool:
/// this Home's own pool holds the keys, or a cached descriptor (own, served
/// or known; no Carrier call) resolves the item's epoch with a server.
/// `Err` when the document or this Home's custody state cannot be read now.
pub(crate) fn runtime_custody_pool_route_for_shared_dataset(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    dataset: &crate::protected_content_market::SharedReadDataset,
    now: u64,
) -> anyhow::Result<bool> {
    let key_envelope: elastos_protected_content_contracts::KeyEnvelopeIdentityV1 =
        decode_runtime_portable_contract(
            &dataset.key_envelope_identity_base64,
            MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize,
        )?;
    runtime_custody_pool_route_for_key_envelope(data_dir, registry, &key_envelope, now)
}

/// [`runtime_custody_pool_route_for_shared_dataset`] for a decoded key
/// envelope. It is sync on purpose: no source here may call Carrier.
pub(crate) fn runtime_custody_pool_route_for_key_envelope(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    key_envelope: &elastos_protected_content_contracts::KeyEnvelopeIdentityV1,
    now: u64,
) -> anyhow::Result<bool> {
    if runtime_custody_composition_holds_key_envelope(data_dir, registry, key_envelope)? {
        return Ok(true);
    }
    Ok(runtime_custody_pool_for_key_envelope_cached(data_dir, key_envelope, now).is_ok())
}

/// Everything [`verify_runtime_portable_content`] does except compare the
/// rebuilt draft's `mint_id` with the package's: a fresh availability receipt,
/// the published content verified against the package's identity, and the
/// mint draft rebuilt from it. Adoption takes its `mint_id` from exactly this
/// draft, because a package built from a shared document has no `mint_id` of
/// its own to compare against.
async fn rebuild_runtime_portable_content(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
    now_unix_seconds: u64,
    publisher_binding: RuntimeManifestPublisherBinding,
    mode: PortableVerifyMode,
) -> anyhow::Result<(
    RuntimeMintDraft,
    elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1,
)> {
    // Before anything is pinned: the one binding choice (re-anchor fix F2).
    // A Home whose pool holds the item keeps the receipt path and its
    // composition bindings; any other Home goes through the item's pool.
    let holds =
        runtime_custody_composition_holds_key_envelope(data_dir, registry, &decoded.key_envelope)?;
    let item = if decoded.pool_minted {
        ItemMintPath::Pool
    } else {
        ItemMintPath::Composition
    };
    if draft_node_bindings_for(item, holds) == DraftNodeBindings::PoolBound {
        return rebuild_non_holder_portable_content(
            data_dir,
            registry,
            package,
            decoded,
            now_unix_seconds,
            mode,
        )
        .await;
    }
    let (draft, receipt) = match &decoded.content_identity {
        RuntimeContentIdentityV1::Media(media_identity) => {
            verify_runtime_portable_media(
                data_dir,
                registry,
                package,
                decoded,
                media_identity,
                now_unix_seconds,
                publisher_binding,
            )
            .await
        }
        RuntimeContentIdentityV1::MediaDash(head) => {
            verify_runtime_portable_media_dash(
                data_dir,
                registry,
                package,
                decoded,
                head,
                now_unix_seconds,
                publisher_binding,
            )
            .await
        }
        RuntimeContentIdentityV1::Object(object_identity) => {
            verify_runtime_portable_object(
                data_dir,
                registry,
                package,
                decoded,
                object_identity,
                now_unix_seconds,
                publisher_binding,
            )
            .await
        }
    }?;
    Ok((draft, receipt.into()))
}

/// Object twin of [`verify_runtime_portable_media`]. Step for step the same
/// sequence — re-observe availability, fetch and verify the published files
/// against the listing's own identity, verify the receipt, resolve the
/// custody composition's currently selected nodes, and rebuild the mint draft (its
/// `mint_id` is compared by the caller, `verify_runtime_portable_content`). The media function is
/// untouched; only the three content-shaped steps differ (object manifest and
/// `object.epc1` instead of `identity.bin` + `init.mp4` + segments, the object
/// receipt twin, and `RuntimeMintDraft::new_from_identity` with an
/// `Object` identity instead of `RuntimeMintDraft::new` from raw media bytes).
#[allow(clippy::too_many_arguments)]
async fn verify_runtime_portable_object(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
    object_identity: &ChunkedPayloadObjectIdentityV1,
    now_unix_seconds: u64,
    publisher_binding: RuntimeManifestPublisherBinding,
) -> anyhow::Result<(RuntimeMintDraft, RuntimeVerifiedContentAvailability)> {
    // Same clock discipline as the media path: a dead candidate's connect
    // timeouts can outlast the receipt's future-skew allowance.
    let now_unix_seconds = now_unix_seconds.max(crate::auth::now_ts());
    let trusted_receipt_signer_did =
        crate::collaboration_profile_authority::load_existing_device_did(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    let requirement = RuntimeContentAvailabilityRequirement::new(
        trusted_receipt_signer_did,
        &package.content_id,
        &package.publisher_profile_did,
        PROTECTED_CONTENT_REPLICATION_POLICY,
        PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR,
        PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )?;
    let receipt =
        refresh_content_availability_receipt(registry, &package.content_cid, &requirement).await?;
    let manifest =
        crate::content::fetch_content_object_manifest(registry, &package.content_cid).await?;
    verify_protected_content_object_manifest_and_files(
        registry,
        &package.content_cid,
        &manifest,
        object_identity,
    )
    .await?;
    let availability = verify_protected_content_object_receipt(
        &package.content_cid,
        &manifest,
        &receipt,
        object_identity,
        &requirement,
        now_unix_seconds.max(crate::auth::now_ts()),
        publisher_binding,
    )?;
    let composition = load_runtime_custody_composition(data_dir, registry.clone())?
        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_COMPOSITION_MISSING_MESSAGE))?;
    let configured_nodes = composition.configured_nodes()?;
    let selected = resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        now_unix_seconds.max(crate::auth::now_ts()),
        &configured_nodes,
    )?;
    let draft = RuntimeMintDraft::new_from_identity(
        RuntimeContentIdentityV1::Object(object_identity.clone()),
        decoded.content_access_id,
        decoded.key_envelope.clone(),
        decoded.rights_policy.clone(),
        decoded.content_key_commitment,
        decoded.key_envelope.threshold(),
        selected.iter().map(|node| node.binding().clone()).collect(),
    )?;
    Ok((draft, availability))
}

/// DASH v2 twin of `verify_runtime_portable_object`: the same refresh, receipt
/// and selection, with the content check reduced to the manifest. The head is
/// the identity, so no segment is fetched here; each is proven against the
/// head's root when it is read.
#[allow(clippy::too_many_arguments)]
async fn verify_runtime_portable_media_dash(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
    head: &CencDashMediaIdentityV2,
    now_unix_seconds: u64,
    publisher_binding: RuntimeManifestPublisherBinding,
) -> anyhow::Result<(RuntimeMintDraft, RuntimeVerifiedContentAvailability)> {
    let now_unix_seconds = now_unix_seconds.max(crate::auth::now_ts());
    let trusted_receipt_signer_did =
        crate::collaboration_profile_authority::load_existing_device_did(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    let requirement = RuntimeContentAvailabilityRequirement::new(
        trusted_receipt_signer_did,
        &package.content_id,
        &package.publisher_profile_did,
        PROTECTED_CONTENT_REPLICATION_POLICY,
        PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR,
        PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )?;
    let receipt =
        refresh_content_availability_receipt(registry, &package.content_cid, &requirement).await?;
    let manifest =
        crate::content::fetch_content_object_manifest(registry, &package.content_cid).await?;
    verify_protected_content_dash_manifest(&manifest, head)?;
    let availability = verify_protected_content_dash_receipt(
        &package.content_cid,
        &manifest,
        &receipt,
        head,
        &requirement,
        now_unix_seconds.max(crate::auth::now_ts()),
        publisher_binding,
    )?;
    let composition = load_runtime_custody_composition(data_dir, registry.clone())?
        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_COMPOSITION_MISSING_MESSAGE))?;
    let configured_nodes = composition.configured_nodes()?;
    let selected = resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        now_unix_seconds.max(crate::auth::now_ts()),
        &configured_nodes,
    )?;
    let draft = RuntimeMintDraft::new_from_identity(
        RuntimeContentIdentityV1::MediaDash(head.clone()),
        decoded.content_access_id,
        decoded.key_envelope.clone(),
        decoded.rights_policy.clone(),
        decoded.content_key_commitment,
        decoded.key_envelope.threshold(),
        selected.iter().map(|node| node.binding().clone()).collect(),
    )?;
    Ok((draft, availability))
}

#[allow(clippy::too_many_arguments)]
async fn verify_runtime_portable_media(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    package: &RuntimePortableListingPackage,
    decoded: &DecodedRuntimePortableAsset,
    media_identity: &CencFmp4MediaIdentityV1,
    now_unix_seconds: u64,
    publisher_binding: RuntimeManifestPublisherBinding,
) -> anyhow::Result<(RuntimeMintDraft, RuntimeVerifiedContentAvailability)> {
    // The caller samples its clock before the fresh ensure; walking a dead
    // candidate's connect timeouts can take longer than the receipt's
    // future-skew allowance, so a receipt stamped at completion would read
    // as "in the future". Verify against the later of the two clocks (a
    // fixed test clock ahead of wall time is preserved).
    let now_unix_seconds = now_unix_seconds.max(crate::auth::now_ts());
    let trusted_receipt_signer_did =
        crate::collaboration_profile_authority::load_existing_device_did(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    let requirement = RuntimeContentAvailabilityRequirement::new(
        trusted_receipt_signer_did,
        &package.content_id,
        &package.publisher_profile_did,
        PROTECTED_CONTENT_REPLICATION_POLICY,
        PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR,
        PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )?;
    // "Fresh" is a new observation, not the receipt stored at mint time:
    // that one is older than the freshness window for every purchase made
    // more than a minute after the mint. Ask the content plane to ensure the
    // CID again under the same bindings, then read the receipt it produced.
    let receipt =
        refresh_content_availability_receipt(registry, &package.content_cid, &requirement).await?;
    let manifest =
        crate::content::fetch_content_object_manifest(registry, &package.content_cid).await?;
    let (init, segments) = verify_protected_content_manifest_and_files(
        registry,
        &package.content_cid,
        &manifest,
        media_identity,
    )
    .await?;
    let availability = verify_protected_content_receipt(
        &package.content_cid,
        &manifest,
        &receipt,
        media_identity,
        &requirement,
        // Re-sampled: the refresh above may have walked dead-candidate timeouts.
        now_unix_seconds.max(crate::auth::now_ts()),
        publisher_binding,
    )?;
    let composition = load_runtime_custody_composition(data_dir, registry.clone())?
        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_COMPOSITION_MISSING_MESSAGE))?;
    let configured_nodes = composition.configured_nodes()?;
    let selected = resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        // Re-sampled: the refresh above may have walked dead-candidate timeouts.
        now_unix_seconds.max(crate::auth::now_ts()),
        &configured_nodes,
    )?;
    let draft = RuntimeMintDraft::new(
        &init,
        &segments,
        media_identity.mime_type(),
        media_identity.codecs(),
        decoded.content_access_id,
        decoded.key_envelope.clone(),
        decoded.rights_policy.clone(),
        decoded.content_key_commitment,
        decoded.key_envelope.threshold(),
        selected.iter().map(|node| node.binding().clone()).collect(),
    )?;
    Ok((draft, availability))
}

pub(crate) async fn import_runtime_custody_listing(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    principal_id: &str,
    listing_uri: &str,
) -> anyhow::Result<Value> {
    validate_runtime_custody_public_text(principal_id)?;
    let listing_cid = runtime_portable_listing_cid(listing_uri)?;
    let (manifest, bytes) =
        fetch_runtime_portable_file(&registry, listing_cid, "listing.json").await?;
    let package: RuntimePortableListingPackage = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))?;
    if serde_json::to_vec(&package)? != bytes {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    let decoded = package.decode_and_validate()?;
    // T8-M4: what an imported listing must state about itself is checked
    // before anything is asked of the network: a package lacking a published
    // package's facts is refused here, not after reading its folders.
    let package_sha256 = hex::encode(sha2::Sha256::digest(&bytes));
    validate_runtime_portable_listing_origin(listing_uri, &package_sha256, &package)?;
    validate_runtime_published_package_facts(&package)?;
    if manifest.schema != "elastos.content.object.manifest/v1"
        || manifest.kind != "protected-content-listing"
        || manifest.links.len() != 2
        || !manifest
            .links
            .iter()
            .any(|link| link.rel == "encrypted-content" && link.cid == package.content_cid)
        || !manifest
            .links
            .iter()
            .any(|link| link.rel == "metadata" && link.cid == package.metadata_cid)
        || manifest.object_did.as_deref() != Some(package.content_id.as_str())
        || manifest.publisher_did.as_deref() != Some(package.publisher_profile_did.as_str())
    {
        anyhow::bail!("Runtime custody portable listing is invalid");
    }
    verify_runtime_portable_metadata(&registry, &package, &decoded).await?;
    verify_runtime_portable_chain(&registry, &package).await?;
    let (draft, verified_availability) = verify_runtime_portable_content(
        data_dir,
        &registry,
        &package,
        &decoded,
        crate::auth::now_ts(),
        RuntimeManifestPublisherBinding::Exact,
        PortableVerifyMode::Import,
    )
    .await?;
    let availability =
        RuntimeCustodyListingAvailabilitySummary::from_evidence(&verified_availability);
    let expected = RuntimeCustodyListingRecord {
        schema: RUNTIME_LISTING_SCHEMA_V1.to_string(),
        origin: RuntimeCustodyListingOrigin::Imported {
            listing_uri: listing_uri.to_string(),
            package_sha256,
        },
        package,
        availability,
    };
    expected.validate()?;
    // A granted listing states terms nobody offered: the creator's own
    // package replaces it. Granted copies are bound to the item, not to the
    // listing's terms, and keep opening.
    let existing = load_runtime_custody_listing(data_dir, draft.mint_id())?
        .filter(|existing| !existing.origin.is_granted());
    if let Some(existing) = existing {
        if existing.schema != expected.schema
            || existing.origin != expected.origin
            || existing.package != expected.package
            || (existing.availability.checked_at == expected.availability.checked_at
                && existing.availability != expected.availability)
        {
            anyhow::bail!("Runtime custody listing is invalid");
        }
        if expected.availability.checked_at > existing.availability.checked_at {
            persist_runtime_custody_listing(data_dir, &expected)?;
        }
    } else {
        persist_runtime_custody_listing(data_dir, &expected)?;
    }
    Ok(json!({
        "schema": "elastos.library.runtime-custody-import/v1",
        "listing_uri": listing_uri,
        "mint_id": expected.package.mint_id,
        "status": "verified",
    }))
}

/// Decode the `content_identity_base64` a shared document's ElastOS
/// protection entry carries (`ProtectedContentIdentities`): the kind-prefixed
/// `RuntimeContentIdentityV1` encoding for an object, or the bare
/// `CencFmp4MediaIdentityV1` bytes for media.
///
/// Dispatched exactly as [`RuntimePortableListingPackage::decode_and_validate`]
/// dispatches its two fields: the kind-prefixed form is tried first and
/// accepted only when it is an `Object`; otherwise the bytes must be a bare
/// media identity. A kind-prefixed `Media` is refused, as it is for a package:
/// it would give one asset two encodings.
pub(crate) fn decode_runtime_shared_content_identity(
    encoded: &str,
) -> anyhow::Result<RuntimeContentIdentityV1> {
    let bytes =
        decode_runtime_portable_base64(encoded, MAX_RUNTIME_PORTABLE_LISTING_BYTES as usize)?;
    match RuntimeContentIdentityV1::from_canonical_bytes(&bytes) {
        Ok(RuntimeContentIdentityV1::Object(object)) => {
            return Ok(RuntimeContentIdentityV1::Object(object))
        }
        Ok(RuntimeContentIdentityV1::MediaDash(head)) => {
            return Ok(RuntimeContentIdentityV1::MediaDash(head))
        }
        Ok(RuntimeContentIdentityV1::Media(_)) => {
            anyhow::bail!("Runtime custody portable listing is invalid")
        }
        Err(_) => {}
    }
    CencFmp4MediaIdentityV1::from_canonical_bytes(&bytes)
        .map(RuntimeContentIdentityV1::Media)
        .map_err(|_| anyhow::anyhow!("Runtime custody portable listing is invalid"))
}

/// Why an adoption did not produce read-side records. Every one of these
/// leaves the market purchase exactly as complete as it was.
pub(crate) const RUNTIME_MARKET_ADOPTION_CONFLICT_MESSAGE: &str =
    "another listing already records this mint";

/// R39: whether `package` sells exactly what `purchase` paid for -- the same
/// item (chain, network, ledger, token, operative, KID) from the same seller at
/// the same price, pay token and processor. Addresses compare without regard
/// to case; quantity is availability, not a term.
fn runtime_listing_sells_on_market_terms(
    package: &RuntimePortableListingPackage,
    purchase: &crate::protected_content_market::RuntimeMarketPurchaseRecord,
) -> bool {
    let item = &purchase.item;
    let offer = &purchase.offer;
    let same_address = |left: Option<&str>, right: Option<&str>| match (left, right) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        (None, None) => true,
        _ => false,
    };
    package.chain_namespace == item.chain_namespace
        && package.network == item.network
        && package.ledger.eq_ignore_ascii_case(&item.ledger)
        && package.token_id.eq_ignore_ascii_case(&item.token_id)
        && package.operative.eq_ignore_ascii_case(&item.operative)
        && crate::protected_content_market::normalize_runtime_market_kid(&package.content_access_id)
            .is_some_and(|kid| item.kid.as_deref() == Some(kid.as_str()))
        && package.seller_address.eq_ignore_ascii_case(&offer.seller)
        && package.price == offer.price
        && package.pay_token.eq_ignore_ascii_case(&offer.pay_token)
        && same_address(
            package.payment_processor.as_deref(),
            offer.payment_processor.as_deref(),
        )
}

/// The terms an adopted listing states: the offer a market purchase paid, or
/// the zero terms of a granted copy.
pub(crate) struct RuntimeAdoptedListingTerms {
    pub(crate) seller_address: String,
    pub(crate) quantity: String,
    pub(crate) price: String,
    pub(crate) pay_token: String,
    pub(crate) payment_processor: Option<String>,
}

/// The listing a shared `metadata.json` describes for `item`, on `terms`:
/// the package built from the document, its content verified the way the
/// open path verifies it, and its `mint_id` taken from the rebuilt draft and
/// never from any document. Nothing is written.
///
/// `verify_runtime_portable_metadata` (which reads the ElastOS-only
/// `manifest.json`) and `verify_runtime_portable_chain` (whose facts the
/// caller proved from the chain) are deliberately not run.
async fn build_adopted_runtime_listing(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    item: &crate::protected_content_market::RuntimeMarketItem,
    origin: RuntimeCustodyListingOrigin,
    dataset: &crate::protected_content_market::SharedReadDataset,
    terms: RuntimeAdoptedListingTerms,
) -> anyhow::Result<RuntimeCustodyListingRecord> {
    // A document whose stated type contradicts the identity it carries says
    // two things about one asset; neither is adopted.
    if !dataset.mime_type.is_empty() && dataset.mime_type != dataset.content_identity.content_type()
    {
        anyhow::bail!("the shared document's mimeType disagrees with its content identity");
    }
    let (RuntimeCustodyListingOrigin::Asset { asset_uri }
    | RuntimeCustodyListingOrigin::Granted { asset_uri }) = &origin
    else {
        anyhow::bail!("Runtime custody listing is invalid");
    };
    let folder_cid = runtime_portable_listing_cid(asset_uri)?.to_string();
    let (media_identity_base64, content_identity_base64) =
        runtime_portable_identity_fields(&dataset.content_identity)?;
    let mut package = RuntimePortableListingPackage {
        schema: RUNTIME_PORTABLE_LISTING_SCHEMA_V1.to_string(),
        // Filled in from the rebuilt draft below; a valid placeholder only so
        // the package can be decoded first.
        mint_id: "00".repeat(32),
        content_id: runtime_protected_content_id(dataset.content_identity.encrypted_content())?,
        content_cid: dataset.content_cid.clone(),
        metadata_cid: folder_cid.clone(),
        token_uri: format!("ipfs://{folder_cid}"),
        publisher_profile_did: dataset.publisher_identity.clone(),
        display_name: dataset.name.clone(),
        media_identity_base64,
        content_identity_base64,
        content_access_id: dataset.kid.clone(),
        key_envelope_identity_base64: dataset.key_envelope_identity_base64.clone(),
        rights_policy_identity_base64: dataset.rights_policy_identity_base64.clone(),
        content_key_commitment_base64: dataset.content_key_commitment_base64.clone(),
        seller_address: terms.seller_address,
        chain_namespace: item.chain_namespace.clone(),
        network: item.network.clone(),
        ledger: item.ledger.to_ascii_lowercase(),
        token_id: item.token_id.to_ascii_lowercase(),
        operative: item.operative.to_ascii_lowercase(),
        quantity: terms.quantity,
        price: terms.price,
        pay_token: terms.pay_token,
        payment_processor: terms.payment_processor,
        mint_transaction_hash: None,
        published_at: None,
        // POOL-MINT (S7I-F2): the item's pool path, from its shared document.
        pool_mint_share_b64: dataset.pool_mint_share_b64.clone(),
    };
    let decoded = package.decode_and_validate()?;
    let (draft, verified_availability) = rebuild_runtime_portable_content(
        data_dir,
        registry,
        &package,
        &decoded,
        crate::auth::now_ts(),
        RuntimeManifestPublisherBinding::AdoptedAttribution,
        PortableVerifyMode::Adopt,
    )
    .await?;
    package.mint_id = hex::encode(draft.mint_id().as_bytes());
    let expected = RuntimeCustodyListingRecord {
        schema: RUNTIME_LISTING_SCHEMA_V1.to_string(),
        origin,
        package,
        availability: RuntimeCustodyListingAvailabilitySummary::from_evidence(
            &verified_availability,
        ),
    };
    expected.validate()?;
    Ok(expected)
}

/// Adoption for a chain grant: the listing and owned copy of an item the
/// chain grants `account` access to without any purchase or mint of this
/// principal's -- a channel admin's, say. Access is the chain's to decide,
/// not how it was come by.
///
/// The caller has verified `item` (all three legs of the binding check, so
/// its KID is proven) and read `access_evidence` for that KID at the
/// finalized block. The listing binds to one this Home already holds for the
/// mint, whatever its terms; otherwise it is recorded on zero terms (origin
/// `Granted`), which nothing ever buys, shares or lists. The owned copy is
/// recorded as `granted` unless this principal already holds a record for
/// the mint, which is left exactly as it is.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn adopt_runtime_granted_listing(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    principal_id: &str,
    profile_did: &str,
    item: &crate::protected_content_market::RuntimeMarketItem,
    asset_uri: &str,
    dataset: &crate::protected_content_market::SharedReadDataset,
    account_id: &str,
    address: &str,
    access_evidence: RuntimeCustodyPurchaseAccessEvidenceRecord,
) -> anyhow::Result<RuntimeCustodyListingRecord> {
    if item.kid.as_deref() != Some(dataset.kid.as_str())
        || !access_evidence.has_access
        || access_evidence.content_access_id.as_deref() != Some(dataset.kid.as_str())
        || !access_evidence.wallet.eq_ignore_ascii_case(address)
    {
        anyhow::bail!("Runtime custody grant does not bind to this document");
    }
    let (seller_address, quantity, price, pay_token) =
        runtime_granted_package_terms(&item.operative);
    let expected = build_adopted_runtime_listing(
        data_dir,
        registry,
        item,
        RuntimeCustodyListingOrigin::Granted {
            asset_uri: asset_uri.to_string(),
        },
        dataset,
        RuntimeAdoptedListingTerms {
            seller_address,
            quantity,
            price,
            pay_token,
            payment_processor: None,
        },
    )
    .await?;
    let mint_id = parse_mint_id_hex(&expected.package.mint_id)?;
    let listing = match load_runtime_custody_listing(data_dir, mint_id)? {
        // Whatever listing this Home already holds for the mint is the one the
        // copy opens through; a grant overwrites nothing.
        Some(existing) => {
            existing.validate()?;
            tracing::debug!(
                mint_id = %existing.package.mint_id,
                "runtime custody: granted copy bound to the listing already held for its mint"
            );
            existing
        }
        None => {
            persist_runtime_custody_listing(data_dir, &expected)?;
            expected
        }
    };
    // Decided under the purchase lock: a purchase of this mint that lands
    // first is never overwritten by the grant.
    let now = crate::auth::now_ts();
    let record = RuntimeCustodyPurchaseRecord {
        schema: RUNTIME_PURCHASE_SCHEMA_V1.to_string(),
        principal_id: principal_id.to_string(),
        profile_did: profile_did.to_string(),
        mint_id: listing.package.mint_id.clone(),
        content_id: listing.package.content_id.clone(),
        cid: listing.package.content_cid.clone(),
        listing_sha256: listing.portable_package_digest(),
        seller_address: listing.package.seller_address.clone(),
        chain_namespace: listing.package.chain_namespace.clone(),
        network: listing.package.network.clone(),
        ledger: listing.package.ledger.clone(),
        token_id: listing.package.token_id.clone(),
        operative: listing.package.operative.clone(),
        price: listing.package.price.clone(),
        pay_token: listing.package.pay_token.clone(),
        payment_processor: listing.package.payment_processor.clone(),
        availability_receipt_digest: listing.availability.purchase_digest(),
        account_id: account_id.to_string(),
        address: address.to_ascii_lowercase(),
        approval_stage: None,
        acquisition_stage: runtime_custody_grant_stage(
            &listing.package.chain_namespace,
            &listing.package.network,
        ),
        acquisition: RuntimeCustodyAcquisitionV1::Granted,
        capsule_uri: None,
        progress: RuntimeCustodyPurchaseProgress::Granted {
            access_evidence,
            acquired_at: now,
        },
        created_at: now,
        updated_at: now,
    };
    if create_runtime_custody_purchase_if_absent(data_dir, &record)? {
        tracing::debug!(
            mint_id = %listing.package.mint_id,
            "runtime custody: chain-granted copy recorded from the shared document"
        );
    }
    Ok(listing)
}

/// Adoption, steps 2-4 (D10): build the listing package a published listing
/// would have carried from the shared document and the market purchase, run
/// the content verification the open path runs, and record the listing
/// (origin `Asset`) and a purchase record (acquisition `market`) that the
/// unchanged open path then consumes.
///
/// `mint_id` is the rebuilt draft's, computed here and never read from any
/// document. `verify_runtime_portable_metadata` (which reads the ElastOS-only
/// `manifest.json`) and `verify_runtime_portable_chain` (whose facts the
/// purchase already proved) are deliberately not run.
///
/// Nothing is written unless every check passed. Returns the listing record
/// the purchase record is bound to: the adopted one, or (R39) the listing of
/// the same mint this Home already held on the same terms.
pub(crate) async fn adopt_runtime_market_listing(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    profile_did: &str,
    purchase: &crate::protected_content_market::RuntimeMarketPurchaseRecord,
    dataset: &crate::protected_content_market::SharedReadDataset,
) -> anyhow::Result<RuntimeCustodyListingRecord> {
    let RuntimeCustodyPurchaseProgress::Complete { terminal } = &purchase.progress else {
        anyhow::bail!("Runtime market purchase is not complete");
    };
    if purchase.item.kid.as_deref() != Some(dataset.kid.as_str()) {
        anyhow::bail!("Runtime market purchase does not bind to this document");
    }
    // The open path asks the purchase record for the chain's access answer
    // on this KID; a purchase whose KID was proven after it completed (R46)
    // must have read it before anything is adopted.
    if !terminal.access_evidence.as_ref().is_some_and(|evidence| {
        evidence.has_access && evidence.content_access_id.as_deref() == Some(dataset.kid.as_str())
    }) {
        anyhow::bail!("Runtime market purchase has no access evidence for this document");
    }
    let expected = build_adopted_runtime_listing(
        data_dir,
        registry,
        &purchase.item,
        RuntimeCustodyListingOrigin::Asset {
            asset_uri: purchase.asset_uri.clone(),
        },
        dataset,
        RuntimeAdoptedListingTerms {
            seller_address: purchase.offer.seller.to_ascii_lowercase(),
            quantity: "0x1".to_string(),
            price: purchase.offer.price.clone(),
            pay_token: purchase.offer.pay_token.to_ascii_lowercase(),
            payment_processor: purchase
                .offer
                .payment_processor
                .as_deref()
                .map(str::to_ascii_lowercase),
        },
    )
    .await?;
    let draft_mint_id = parse_mint_id_hex(&expected.package.mint_id)?;
    // The listing the purchase record binds to: the adopted one, or (R39) a
    // listing of this same mint this Home already holds on exactly the terms
    // the purchase paid.
    let expected = match load_runtime_custody_listing(data_dir, draft_mint_id)? {
        Some(existing)
            if existing.origin == expected.origin && existing.package == expected.package =>
        {
            if expected.availability.checked_at > existing.availability.checked_at {
                persist_runtime_custody_listing(data_dir, &expected)?;
            }
            expected
        }
        // R39: this Home already holds a listing of this mint -- imported from
        // its published package, say -- on the very terms this purchase paid.
        // The purchase opens through it, bound to its own package digest;
        // nothing is overwritten.
        Some(existing) if runtime_listing_sells_on_market_terms(&existing.package, purchase) => {
            existing.validate()?;
            tracing::debug!(
                mint_id = %existing.package.mint_id,
                "runtime custody: market purchase bound to the listing already held for its mint"
            );
            existing
        }
        // A granted listing states terms nobody offered, so the listing this
        // purchase paid on replaces it. The granted copies bound to it are
        // bound to the item, not to its terms, and keep opening.
        Some(existing) if existing.origin.is_granted() => {
            tracing::debug!(
                mint_id = %existing.package.mint_id,
                "runtime custody: market purchase replaced a granted listing"
            );
            persist_runtime_custody_listing(data_dir, &expected)?;
            expected
        }
        // One listing per mint on a Home. A listing this Home already holds
        // on other terms -- another seller or price -- is never overwritten by
        // a purchase that does not match it (per-purchase terms on the open
        // path are a recorded follow-up).
        Some(_) => anyhow::bail!(RUNTIME_MARKET_ADOPTION_CONFLICT_MESSAGE),
        None => {
            persist_runtime_custody_listing(data_dir, &expected)?;
            expected
        }
    };
    if load_runtime_custody_purchase(data_dir, &purchase.principal_id, draft_mint_id)?.is_none() {
        let now = crate::auth::now_ts();
        let record = RuntimeCustodyPurchaseRecord {
            schema: RUNTIME_PURCHASE_SCHEMA_V1.to_string(),
            principal_id: purchase.principal_id.clone(),
            profile_did: profile_did.to_string(),
            mint_id: expected.package.mint_id.clone(),
            content_id: expected.package.content_id.clone(),
            cid: expected.package.content_cid.clone(),
            listing_sha256: expected.portable_package_digest(),
            seller_address: expected.package.seller_address.clone(),
            chain_namespace: expected.package.chain_namespace.clone(),
            network: expected.package.network.clone(),
            ledger: expected.package.ledger.clone(),
            token_id: expected.package.token_id.clone(),
            operative: expected.package.operative.clone(),
            price: expected.package.price.clone(),
            pay_token: expected.package.pay_token.clone(),
            payment_processor: expected.package.payment_processor.clone(),
            availability_receipt_digest: expected.availability.purchase_digest(),
            account_id: purchase.account_id.clone(),
            address: purchase.address.clone(),
            approval_stage: purchase.approval_stage.clone(),
            acquisition_stage: purchase.acquisition_stage.clone(),
            acquisition: RuntimeCustodyAcquisitionV1::Market,
            capsule_uri: None,
            progress: purchase.progress.clone(),
            created_at: now,
            updated_at: now,
        };
        persist_runtime_custody_purchase(data_dir, &record)?;
    }
    tracing::debug!(
        mint_id = %expected.package.mint_id,
        "runtime custody: market purchase adopted from the shared document"
    );
    Ok(expected)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyPurchaseStageRecord {
    pub(crate) stage: String,
    pub(crate) effect_id: String,
    pub(crate) approval_request_id: String,
    pub(crate) request_sha256: String,
    pub(crate) chain_namespace: String,
    pub(crate) network: String,
    pub(crate) to: String,
    pub(crate) value: String,
    pub(crate) data: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyConfirmedPurchaseStage {
    pub(crate) chain_transaction: String,
    pub(crate) wallet_binding: ValidatedChainOutcomeBindingV1,
    pub(crate) chain_observation: Value,
    pub(crate) confirmed_at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyPurchaseAccessEvidenceRecord {
    pub(crate) schema: String,
    pub(crate) request_id: String,
    pub(crate) network: String,
    pub(crate) chain_id: u64,
    pub(crate) wallet: String,
    /// The KID the access was asked with (`hasAccessByContentId`). Absent on
    /// evidence asked by the item instead (R50), which names `ledger` and
    /// `token_id`. Every record written before R50 has it, and serializes
    /// exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) content_access_id: Option<String>,
    /// The item the access was asked about (`AuthorityGateway.hasAccess`,
    /// R50): set, with `token_id`, only on item-keyed evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ledger: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) token_id: Option<String>,
    pub(crate) has_access: bool,
    pub(crate) finalized_block_number: u64,
    pub(crate) finalized_block_hash: String,
    pub(crate) finalized_block_timestamp: u64,
    pub(crate) observed_at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyTerminalPurchaseRecord {
    pub(crate) chain_transaction: String,
    pub(crate) wallet_binding: ValidatedChainOutcomeBindingV1,
    pub(crate) chain_observation: Value,
    /// The chain's corroborated `hasAccess` answer. Every listing-path
    /// purchase carries it for the item's KID. A market purchase completed
    /// while its KID was unknown carries it asked by the item instead (R50);
    /// adoption, once it proves the KID, replaces it with the KID's answer.
    /// Only KID-keyed evidence opens. Absent only on a market purchase that
    /// completed on its mined receipt between R46 and R50.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) access_evidence: Option<RuntimeCustodyPurchaseAccessEvidenceRecord>,
    pub(crate) confirmed_at: u64,
    /// When this principal came to hold the copy. Written as `acquired_at`;
    /// `bought_at` is how every record predating minted copies spells it, and a
    /// minted copy was never bought.
    #[serde(alias = "bought_at")]
    pub(crate) acquired_at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RuntimeCustodyPurchaseProgress {
    Pending {
        /// Set once the ERC-20 approval stage's transaction has confirmed on
        /// chain, so a retried buy skips re-driving an already-confirmed
        /// approval instead of re-requesting it from the Wallet every call.
        /// Absent for two-legitimate-different reasons: native-token
        /// purchases that never had an approval stage, and records written
        /// before this field existed -- both must keep deserializing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        confirmed_approval: Option<RuntimeCustodyConfirmedPurchaseStage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        confirmed_buy: Option<RuntimeCustodyConfirmedPurchaseStage>,
    },
    Complete {
        terminal: RuntimeCustodyTerminalPurchaseRecord,
    },
    /// A copy the chain grants without any transaction of this principal's
    /// (acquisition `granted`). The finalized access answer is its only
    /// evidence, so it is the only state with no transaction to present; a
    /// purchase or a mint is always `Complete`.
    Granted {
        access_evidence: RuntimeCustodyPurchaseAccessEvidenceRecord,
        acquired_at: u64,
    },
}

/// How a principal came to own this copy.
///
/// Nothing downstream of the entitlement check reads this. The right to open
/// is the chain's answer to `hasAccess`, and buying and minting are two ways of
/// arriving at the same answer -- so an owned copy behaves identically either
/// way. This records only which one happened, so a reader can tell provenance
/// without that changing what the copy can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeCustodyAcquisitionV1 {
    /// Bought from a listing. Every record written before minted copies
    /// existed is one of these, which is why it is the default.
    #[default]
    Bought,
    /// Minted by this principal: the copy was theirs from the first block.
    Minted,
    /// Bought on the market from any live offer, and adopted from the asset's
    /// shared `metadata.json` rather than from a published listing package.
    Market,
    /// Granted by the chain without a purchase or a mint of this principal's
    /// -- a channel admin's access, say -- and adopted from the asset's shared
    /// `metadata.json`. No transaction stands behind it; the finalized grant
    /// does.
    Granted,
}

impl RuntimeCustodyAcquisitionV1 {
    /// How a copy says it was come by, in the spelling its record carries.
    pub(crate) const fn wire_value(self) -> &'static str {
        match self {
            Self::Bought => "bought",
            Self::Minted => "minted",
            Self::Market => "market",
            Self::Granted => "granted",
        }
    }
}

/// Wire identity of the answer to a request to rebuild an owned copy.
pub(crate) const RUNTIME_CUSTODY_DOWNLOAD_SCHEMA_V1: &str =
    "elastos.library.runtime-custody-download/v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyPurchaseRecord {
    pub(crate) schema: String,
    pub(crate) principal_id: String,
    pub(crate) profile_did: String,
    pub(crate) mint_id: String,
    pub(crate) content_id: String,
    pub(crate) cid: String,
    pub(crate) listing_sha256: String,
    pub(crate) seller_address: String,
    pub(crate) chain_namespace: String,
    pub(crate) network: String,
    pub(crate) ledger: String,
    pub(crate) token_id: String,
    pub(crate) operative: String,
    pub(crate) price: String,
    pub(crate) pay_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) payment_processor: Option<String>,
    pub(crate) availability_receipt_digest: String,
    pub(crate) account_id: String,
    pub(crate) address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) approval_stage: Option<RuntimeCustodyPurchaseStageRecord>,
    /// The transaction by which this principal acquired access: the buy for a
    /// bought copy, the mint for a minted one. The open path presents it as the
    /// chain evidence behind a release, so every owned copy has one -- which is
    /// why this is not optional and why a minted copy records its mint here
    /// rather than leaving a hole or fabricating a buy.
    ///
    /// Written as `acquisition_stage`; `buy_stage` is how every record predating
    /// minted copies spells the same field.
    #[serde(alias = "buy_stage")]
    pub(crate) acquisition_stage: RuntimeCustodyPurchaseStageRecord,
    #[serde(default)]
    pub(crate) acquisition: RuntimeCustodyAcquisitionV1,
    /// Where this copy's `.ddrm` was filed in the owner's Library.
    ///
    /// `None` means no capsule has been written yet -- either the copy predates
    /// capsules, or filing one has not succeeded. That is what a repair looks
    /// for, and what keeps a replayed buy from filing a second capsule beside
    /// the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) capsule_uri: Option<String>,
    pub(crate) progress: RuntimeCustodyPurchaseProgress,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
}

pub(crate) struct RuntimeCustodyBuyInput {
    pub principal_id: String,
    pub mint_id: String,
}

/// Which owned copy a download names.
pub(crate) enum RuntimeCustodyOwnedCopy {
    /// A copy this Home holds a listing for.
    Mint(String),
    /// A copy bought on the market, named the way the chain names it: until
    /// it is adopted there is no mint for it here to name.
    MarketItem(crate::protected_content_market::RuntimeMarketBuyItemClaim),
}

pub(crate) struct RuntimeCustodyDownloadInput {
    pub principal_id: String,
    pub copy: RuntimeCustodyOwnedCopy,
}

pub(crate) struct RuntimeCustodyViewerOpenInput {
    pub principal_id: String,
    pub mint_id: String,
    /// The verified capsule the caller was actually launched as (session
    /// binding v3's viewer-capsule field). Never taken from client-supplied
    /// request JSON: the gateway proxy overwrites whatever the client sent
    /// with `required.launch_context.executable_actor`, exactly as it already
    /// does for `launch_id`/`session_id`/`grant_id`, and it is the only route
    /// that may reach this function —
    /// `library::handle_runtime_custody_library_request` refuses the viewer
    /// operations on every route that does not perform that overwrite (see
    /// `library::LibraryRequestRoute`).
    pub executable_actor: String,
    pub launch_id: Option<String>,
    pub proof_binding_id: Option<String>,
    pub session_id: Option<String>,
    pub grant_id: Option<String>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeCustodyViewerRecord {
    schema: String,
    principal_id: String,
    profile_did: String,
    mint_id: String,
    content_id: String,
    runtime_session_binding_digest: String,
    audit_request_id: String,
    viewer_session_handle: String,
    expires_at: u64,
    #[serde(default)]
    next_media_part_index: u32,
    lifecycle_status: RuntimeCustodyViewerLifecycleStatus,
    pending_close_result: Option<RuntimeCustodyOpenPendingCloseResult>,
    pending_cancel_result: Option<RuntimeCustodyOpenPendingCancelResult>,
    /// Set while the viewer release waits on the Wallet's managed approval of
    /// the rights-signature request; absent for earlier records.
    #[serde(default)]
    pending_release: Option<RuntimeCustodyPendingRelease>,
    /// Plan B T4.4: the server sessions of a viewer opened through the item's
    /// pool. Absent for a viewer of this Home's decrypt provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pool: Option<crate::protected_content_pool_open::PoolViewerSessions>,
    created_at: u64,
    updated_at: u64,
}

/// Everything a resumed open needs to replay the exact rights-signature
/// request against the recipient the decrypt provider still holds under the
/// viewer session handle. The recipient private key never leaves the decrypt
/// provider; only its public identity is persisted.
///
/// Plan B T4.4: a pool open keeps its prepared server sessions in `pool`
/// instead, and leaves the local recipient fields empty. Its delivery
/// secret stays in this process only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RuntimeCustodyPendingRelease {
    wallet_request_hex: String,
    approval_request_id: String,
    #[serde(default)]
    recipient_public_key_hex: String,
    #[serde(default)]
    recipient_encryption_suite_id: String,
    #[serde(default)]
    recipient_key_id_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pool: Option<crate::protected_content_pool_open::PoolPendingSessions>,
}

impl RuntimeCustodyPendingRelease {
    fn new(
        wallet_request: &[u8],
        approval_request_id: &str,
        prepared: &RuntimePreparedRecipient,
    ) -> Self {
        Self {
            wallet_request_hex: hex::encode(wallet_request),
            approval_request_id: approval_request_id.to_string(),
            recipient_public_key_hex: hex::encode(prepared.recipient_public_key().as_bytes()),
            recipient_encryption_suite_id: prepared
                .recipient_identity()
                .encryption_suite_id()
                .to_string(),
            recipient_key_id_hex: hex::encode(prepared.recipient_identity().key_id().as_bytes()),
            pool: None,
        }
    }

    /// A pool open's pending release (Plan B T4.4).
    fn pool(pending: &crate::protected_content_pool_open::PoolPendingRelease) -> Self {
        Self {
            wallet_request_hex: hex::encode(&pending.wallet_request),
            approval_request_id: pending.approval_request_id.clone(),
            recipient_public_key_hex: String::new(),
            recipient_encryption_suite_id: String::new(),
            recipient_key_id_hex: String::new(),
            pool: Some(pending.sessions.clone()),
        }
    }

    fn wallet_request(&self) -> anyhow::Result<Vec<u8>> {
        decode_hex_bytes(&self.wallet_request_hex).map_err(release_unavailable!())
    }

    fn recipient_public_key(&self) -> anyhow::Result<RecipientPublicKeyBytesV1> {
        let bytes =
            decode_hex_bytes(&self.recipient_public_key_hex).map_err(release_unavailable!())?;
        RecipientPublicKeyBytesV1::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(release_unavailable!())?,
        )
        .map_err(release_unavailable!())
    }

    fn recipient_identity(&self) -> anyhow::Result<RecipientKeyIdentityV1> {
        let key_id: [u8; 32] = decode_hex_bytes(&self.recipient_key_id_hex)
            .map_err(release_unavailable!())?
            .as_slice()
            .try_into()
            .map_err(release_unavailable!())?;
        RecipientKeyIdentityV1::new(
            self.recipient_encryption_suite_id.clone(),
            Digest32::new(key_id),
        )
        .map_err(release_unavailable!())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeCustodyViewerLifecycleStatus {
    OpenPending,
    Active,
    CleanupPending,
    Closed,
    AlreadyAbsent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeCustodyOpenPendingCloseResult {
    Closed,
    AlreadyAbsent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeCustodyOpenPendingCancelResult {
    Cancelled,
    AlreadyAbsent,
}

struct RuntimeCustodyOpenPendingInput<'a> {
    principal_id: &'a str,
    profile_did: &'a str,
    mint_id: Digest32,
    content_id: &'a str,
    runtime_session_binding: RuntimeSessionBindingV1,
    audit_request_id: Digest32,
    viewer_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    expires_at: u64,
    now: u64,
}

impl RuntimeCustodyViewerRecord {
    fn from_open_pending(input: RuntimeCustodyOpenPendingInput<'_>) -> anyhow::Result<Self> {
        let record = Self {
            schema: RUNTIME_VIEWER_SCHEMA_V1.to_string(),
            principal_id: input.principal_id.to_string(),
            profile_did: input.profile_did.to_string(),
            mint_id: hex::encode(input.mint_id.as_bytes()),
            content_id: input.content_id.to_string(),
            runtime_session_binding_digest: hex::encode(
                input.runtime_session_binding.digest().as_bytes(),
            ),
            audit_request_id: hex::encode(input.audit_request_id.as_bytes()),
            viewer_session_handle: hex::encode(input.viewer_session_handle),
            expires_at: input.expires_at,
            next_media_part_index: 0,
            lifecycle_status: RuntimeCustodyViewerLifecycleStatus::OpenPending,
            pending_close_result: None,
            pending_cancel_result: None,
            pending_release: None,
            pool: None,
            created_at: input.now,
            updated_at: input.now,
        };
        let _ = record.audit_request_id()?;
        let _ = record.viewer_session_handle_bytes()?;
        if record.expires_at == 0 {
            anyhow::bail!("Runtime custody viewer session is unavailable");
        }
        Ok(record)
    }

    fn from_active_session(
        principal_id: &str,
        profile_did: &str,
        mint_id: Digest32,
        content_id: &str,
        runtime_session_binding: RuntimeSessionBindingV1,
        session: &RuntimeViewerSession,
        now: u64,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            schema: RUNTIME_VIEWER_SCHEMA_V1.to_string(),
            principal_id: principal_id.to_string(),
            profile_did: profile_did.to_string(),
            mint_id: hex::encode(mint_id.as_bytes()),
            content_id: content_id.to_string(),
            runtime_session_binding_digest: hex::encode(
                runtime_session_binding.digest().as_bytes(),
            ),
            audit_request_id: hex::encode(session.audit_request_id().as_bytes()),
            viewer_session_handle: hex::encode(session.viewer_session_handle()),
            expires_at: session.expires_at(),
            next_media_part_index: 0,
            lifecycle_status: RuntimeCustodyViewerLifecycleStatus::Active,
            pending_close_result: None,
            pending_cancel_result: None,
            pending_release: None,
            pool: None,
            created_at: now,
            updated_at: now,
        })
    }

    /// The record of a viewer opened through the item's pool (Plan B T4.4).
    /// Its handle keys the delivery entry; it expires at the session's end,
    /// the signed rights expiry capped by the attestations (user
    /// 2026-11-13 04:45).
    fn from_pool_opened(
        pending: &Self,
        opened: &crate::protected_content_pool_open::PoolOpened,
        now: u64,
    ) -> Self {
        let mut record = pending.clone();
        record.viewer_session_handle = hex::encode(opened.handle);
        record.expires_at = opened.expires_at;
        record.lifecycle_status = RuntimeCustodyViewerLifecycleStatus::Active;
        record.pending_release = None;
        record.pool = Some(opened.sessions.clone());
        record.updated_at = now;
        record
    }

    /// Whether this viewer reads through the pool (Plan B T4.4).
    fn is_pool(&self) -> bool {
        self.pool.is_some()
            || self
                .pending_release
                .as_ref()
                .is_some_and(|pending| pending.pool.is_some())
    }

    fn validates_authority_identity(
        &self,
        principal_id: &str,
        profile_did: &str,
        mint_id: Digest32,
        content_id: &str,
    ) -> bool {
        if self.schema != RUNTIME_VIEWER_SCHEMA_V1
            || self.principal_id != principal_id
            || self.profile_did != profile_did
            || self.mint_id != hex::encode(mint_id.as_bytes())
            || self.content_id != content_id
        {
            return false;
        }
        true
    }

    fn matches_runtime_session_binding(
        &self,
        runtime_session_binding: &RuntimeSessionBindingV1,
    ) -> bool {
        self.runtime_session_binding_digest
            == hex::encode(runtime_session_binding.digest().as_bytes())
    }

    fn audit_request_id(&self) -> anyhow::Result<Digest32> {
        Ok(Digest32::new(
            decode_hex_bytes(&self.audit_request_id)
                .map_err(|_| anyhow::anyhow!("Runtime custody viewer session is unavailable"))?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Runtime custody viewer session is unavailable"))?,
        ))
    }

    fn viewer_session_handle_bytes(
        &self,
    ) -> anyhow::Result<[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]> {
        decode_hex_bytes(&self.viewer_session_handle)
            .map_err(|_| anyhow::anyhow!("Runtime custody viewer session is unavailable"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Runtime custody viewer session is unavailable"))
    }

    fn to_runtime_viewer_session(
        &self,
        encrypted_content: &EncryptedContentIdentityV1,
    ) -> anyhow::Result<RuntimeViewerSession> {
        RuntimeViewerSession::from_persisted_parts(
            self.audit_request_id()?,
            self.viewer_session_handle_bytes()?,
            encrypted_content.clone(),
            RightsActionV1::View,
            self.expires_at,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody viewer session is unavailable"))
    }

    fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Media parts are released strictly in order: part 0 is the init
    /// segment (no `segment_index`), part n+1 is segment n. The stable
    /// message stays; the detail names the expected and requested parts.
    fn require_media_part_index(&self, segment_index: Option<u32>) -> anyhow::Result<()> {
        const MESSAGE: &str = "Runtime custody viewer media part is invalid";
        let requested = match segment_index {
            Some(index) => index.checked_add(1).ok_or_else(|| {
                anyhow::anyhow!("segment index {index} overflows the media part sequence")
                    .context(MESSAGE)
            })?,
            None => 0,
        };
        if requested != self.next_media_part_index {
            tracing::warn!(
                requested_part = requested,
                next_part = self.next_media_part_index,
                "runtime custody viewer: media part requested out of order"
            );
            return Err(anyhow::anyhow!(
                "requested media part {requested} (segment_index {segment_index:?}) but the next part is {} (part 0 is the init segment, part n+1 is segment n)",
                self.next_media_part_index
            )
            .context(MESSAGE));
        }
        Ok(())
    }

    /// Object chunks are released strictly in order too, but unlike media
    /// there is no init part: chunk n IS part n (media's part 0 is the init
    /// segment and part n+1 is segment n). The counter and
    /// `mark_media_part_read` are shared and kind-agnostic; only this
    /// mapping differs.
    ///
    /// `chunk_count` bounds the request the way media's caller bounds
    /// `segment_index` against `encrypted_segments().len()` — and, like
    /// media, before the published content is fetched, not after. Without it
    /// an exhausted session (`next_media_part_index == chunk_count`) would
    /// pass the ordering check for `chunk_index == chunk_count` and only fail
    /// once the whole framed object had been fetched and re-hashed.
    fn require_object_chunk_index(&self, chunk_index: u32, chunk_count: u32) -> anyhow::Result<()> {
        const MESSAGE: &str = "Runtime custody viewer object chunk is invalid";
        if chunk_index >= chunk_count {
            tracing::warn!(
                requested_chunk = chunk_index,
                chunk_count,
                "runtime custody viewer: object chunk requested past the last chunk"
            );
            return Err(anyhow::anyhow!(
                "requested object chunk {chunk_index} but the object has {chunk_count} chunks"
            )
            .context(MESSAGE));
        }
        if chunk_index != self.next_media_part_index {
            tracing::warn!(
                requested_chunk = chunk_index,
                next_chunk = self.next_media_part_index,
                "runtime custody viewer: object chunk requested out of order"
            );
            return Err(anyhow::anyhow!(
                "requested object chunk {chunk_index} but the next chunk is {}",
                self.next_media_part_index
            )
            .context(MESSAGE));
        }
        Ok(())
    }

    /// DASH v2 media parts are released strictly in order over the fixed
    /// interleave (inits, then each segment index across renditions). The
    /// counter is the same one v1 uses; this maps it to `(rendition, segment)`
    /// and requires the request's `segment_index` to be exactly that segment
    /// (`None` for an init). Same message and warning as
    /// [`Self::require_media_part_index`], and a part past the end fails
    /// before anything is fetched.
    fn require_media_dash_part(
        &self,
        head: &CencDashMediaIdentityV2,
        segment_index: Option<u32>,
    ) -> anyhow::Result<(u8, Option<u32>)> {
        const MESSAGE: &str = "Runtime custody viewer media part is invalid";
        let counts = runtime_media_dash_counts(head);
        let expected = runtime_media_dash_part(&counts, self.next_media_part_index);
        match expected {
            Some((rendition, segment)) if segment == segment_index => Ok((rendition, segment)),
            _ => {
                tracing::warn!(
                    requested_segment = ?segment_index,
                    next_part = self.next_media_part_index,
                    "runtime custody viewer: media part requested out of order"
                );
                Err(anyhow::anyhow!(
                    "requested media part (segment_index {segment_index:?}) but the next part is {} ({expected:?})",
                    self.next_media_part_index
                )
                .context(MESSAGE))
            }
        }
    }

    fn mark_media_part_read(&mut self, now: u64) -> anyhow::Result<()> {
        self.next_media_part_index = self
            .next_media_part_index
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Runtime custody viewer media part is invalid"))?;
        self.updated_at = now;
        Ok(())
    }

    fn open_pending_close_result(&self) -> Option<RuntimeCustodyOpenPendingCloseResult> {
        self.pending_close_result
    }

    fn open_pending_cancel_result(&self) -> Option<RuntimeCustodyOpenPendingCancelResult> {
        self.pending_cancel_result
    }

    fn mark_open_pending_close_result(
        &mut self,
        result: RuntimeViewerSessionCloseResult,
        now: u64,
    ) {
        self.pending_close_result = Some(match result {
            RuntimeViewerSessionCloseResult::Closed => RuntimeCustodyOpenPendingCloseResult::Closed,
            RuntimeViewerSessionCloseResult::AlreadyAbsent => {
                RuntimeCustodyOpenPendingCloseResult::AlreadyAbsent
            }
        });
        self.updated_at = now;
    }

    fn mark_open_pending_cancel_result(
        &mut self,
        result: RuntimePreparedRecipientCancelResult,
        now: u64,
    ) {
        self.pending_cancel_result = Some(match result {
            RuntimePreparedRecipientCancelResult::Cancelled => {
                RuntimeCustodyOpenPendingCancelResult::Cancelled
            }
            RuntimePreparedRecipientCancelResult::AlreadyAbsent => {
                RuntimeCustodyOpenPendingCancelResult::AlreadyAbsent
            }
        });
        self.updated_at = now;
    }

    fn mark_cleanup_pending(&mut self, now: u64) {
        self.lifecycle_status = RuntimeCustodyViewerLifecycleStatus::CleanupPending;
        self.pending_close_result = None;
        self.pending_cancel_result = None;
        self.updated_at = now;
    }

    /// Gives back the object this session staged.
    ///
    /// Called wherever a session becomes terminal, so the staged ciphertext
    /// never outlives the session that verified it. Absent is the normal case
    /// for a media session and for one whose staging failed, so a missing file
    /// is not an error.
    fn release_staged_object(data_dir: &Path, principal_id: &str, mint_id: Digest32) {
        let path = runtime_viewer_object_path(data_dir, principal_id, mint_id);
        match fs::remove_file(&path) {
            Ok(()) => tracing::debug!("runtime custody cleanup: staged object released"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(?error, "runtime custody cleanup: staged object remains"),
        }
        let leaves = runtime_viewer_leaves_path(data_dir, principal_id, mint_id);
        match fs::remove_file(&leaves) {
            Ok(()) => tracing::debug!("runtime custody cleanup: staged leaves released"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(?error, "runtime custody cleanup: staged leaves remain"),
        }
    }

    fn mark_terminal(&mut self, result: RuntimeViewerSessionCloseResult, now: u64) {
        self.lifecycle_status = match result {
            RuntimeViewerSessionCloseResult::Closed => RuntimeCustodyViewerLifecycleStatus::Closed,
            RuntimeViewerSessionCloseResult::AlreadyAbsent => {
                RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent
            }
        };
        self.pending_close_result = None;
        self.pending_cancel_result = None;
        self.updated_at = now;
    }
}

pub(crate) fn list_runtime_custody_listings(
    data_dir: &Path,
    principal_id: &str,
) -> anyhow::Result<Value> {
    if principal_id.trim().is_empty() {
        anyhow::bail!("Runtime custody listing principal is invalid");
    }
    let root = data_dir.join(RUNTIME_LISTING_ROOT);
    let (listing_paths, truncated) = select_runtime_custody_listing_paths(&root)?;
    let mut listings = Vec::with_capacity(listing_paths.len());
    for path in listing_paths {
        let bytes = fs::read(path)?;
        let record: RuntimeCustodyListingRecord = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("Runtime custody listing is invalid"))?;
        record.validate()?;
        // A listing adopted after a market purchase was never published as a
        // listing: it has no publication time and no package link to share,
        // which every row of this shelf states. The item reaches its owner as
        // the `.ddrm` adoption filed and through the market catalog, which
        // reads `runtime_custody_listing_chain_index` and so still sees it.
        // A granted listing is never shared: its terms were never offered.
        if matches!(
            record.origin,
            RuntimeCustodyListingOrigin::Asset { .. } | RuntimeCustodyListingOrigin::Granted { .. }
        ) {
            continue;
        }
        listings.push(runtime_custody_listing_summary(
            data_dir,
            principal_id,
            &record,
        )?);
    }
    Ok(json!({
        "schema": RUNTIME_CUSTODY_LISTINGS_RESPONSE_SCHEMA_V1,
        "truncated": truncated,
        "listings": listings,
    }))
}

/// Which chain assets this Home already holds a listing for, and what this
/// person may do with each.
///
/// The catalog names an asset by its channel and token, which is how the
/// chain names it; a listing here is named by its mint. This is the join
/// between the two, and it is made inside Runtime rather than by a surface,
/// because the channel an item lives on is deliberately not published to one.
///
/// The access state is this person's, so two people on one Home see their own
/// answer for the same asset.
pub(crate) fn runtime_custody_listing_chain_index(
    data_dir: &Path,
    principal_id: &str,
) -> anyhow::Result<Vec<RuntimeCustodyListingChainIdentity>> {
    if principal_id.trim().is_empty() {
        anyhow::bail!("Runtime custody listing principal is invalid");
    }
    let root = data_dir.join(RUNTIME_LISTING_ROOT);
    let (listing_paths, _) = select_runtime_custody_listing_paths(&root)?;
    let mut index = Vec::with_capacity(listing_paths.len());
    for path in listing_paths {
        let Ok(bytes) = fs::read(path) else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<RuntimeCustodyListingRecord>(&bytes) else {
            continue;
        };
        if record.validate().is_err() {
            continue;
        }
        let access_state = runtime_custody_listing_access_state(data_dir, principal_id, &record)?;
        // A granted listing exists for the person the chain granted it to.
        // Anyone else would be shown a mint on terms nobody offered.
        if record.origin.is_granted() && access_state == RUNTIME_CUSTODY_LISTING_ACCESS_AVAILABLE {
            continue;
        }
        index.push(RuntimeCustodyListingChainIdentity {
            chain_namespace: record.package.chain_namespace.clone(),
            ledger: record.package.ledger.to_ascii_lowercase(),
            token_id: record.package.token_id.to_ascii_lowercase(),
            mint_id: record.package.mint_id.clone(),
            access_state: access_state.to_string(),
        });
    }
    Ok(index)
}

/// One asset this Home holds, named the way the chain names it.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeCustodyListingChainIdentity {
    pub(crate) chain_namespace: String,
    pub(crate) ledger: String,
    pub(crate) token_id: String,
    pub(crate) mint_id: String,
    pub(crate) access_state: String,
}

fn select_runtime_custody_listing_paths(root: &Path) -> anyhow::Result<(Vec<PathBuf>, bool)> {
    if !root.is_dir() {
        return Ok((Vec::new(), false));
    }
    let mut selected = BTreeMap::<String, PathBuf>::new();
    let mut truncated = false;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let name = name.to_string();
        if selected.len() < MAX_RUNTIME_CUSTODY_LISTINGS {
            selected.insert(name, path);
            continue;
        }
        truncated = true;
        let Some(last_name) = selected.keys().next_back().cloned() else {
            continue;
        };
        if name < last_name {
            selected.remove(&last_name);
            selected.insert(name, path);
        }
    }
    Ok((selected.into_values().collect(), truncated))
}

fn runtime_custody_listing_summary(
    data_dir: &Path,
    principal_id: &str,
    record: &RuntimeCustodyListingRecord,
) -> anyhow::Result<Value> {
    let availability = runtime_custody_listing_availability(record);
    let access_state = runtime_custody_listing_access_state(data_dir, principal_id, record)?;
    let purchase_in_flight =
        runtime_custody_listing_purchase_in_flight(data_dir, principal_id, record)?;
    let content_identity = record.package.decode_and_validate()?.content_identity;
    // `mime_type`/`codecs` keep their exact media values (the listing summary
    // is a pre-existing public shape); an object listing reports its declared
    // `content_type` as `mime_type` and an empty `codecs`, which is what its
    // published metadata document carries too.
    Ok(json!({
        "schema": RUNTIME_LISTING_SCHEMA_V1,
        "mint_id": record.package.mint_id,
        "display_name": record.package.display_name,
        // Where this listing's package lives, which is the whole of what one
        // person needs to give another for the item to reach their shelf. It
        // is a public content address that the listing already published; the
        // answer to `publish` has carried it since listings existed, and no
        // surface has ever shown it.
        "listing_uri": record.origin.listing_uri(),
        // What this item is, in the two words the viewer session already
        // speaks. An app used to read the kind out of `mime_type`, which is a
        // second rule for a question Runtime answers here from the identity
        // itself, and a second rule can disagree with the one the open path
        // enforces.
        "content_kind": runtime_custody_content_kind(&content_identity),
        // Where this listing's published metadata document lives -- the same
        // directory the media token's URI names, which carries the title the
        // creator typed, the cover they chose and the category they picked.
        //
        // The CID travels rather than the document: a shelf of items would
        // otherwise make this Home fetch and parse one document per row before
        // it could answer at all, and the surface reads them from its own
        // `/ipfs/` route, which is already backed by the local node and its
        // disk cache. What comes out of that document is presentation only --
        // price, quantity and access are answered here and nowhere else.
        "metadata_cid": record.package.metadata_cid,
        "mime_type": content_identity.content_type(),
        "codecs": runtime_portable_content_codecs(&content_identity),
        "quantity": record.package.quantity,
        "price": record.package.price,
        "pay_token": record.package.pay_token,
        "seller_address": record.package.seller_address,
        "token_id": record.package.token_id,
        "published_at": record.package.published_at,
        "availability": availability,
        "access_state": access_state,
        // A purchase this person started and has not finished. It is its own
        // field rather than another `access_state`, because a state is a value
        // consumers switch on and a new one falls silently into whatever their
        // default does -- while an unknown FIELD is refused loudly by the
        // parser on the other side of this contract.
        "purchase_in_flight": purchase_in_flight,
    }))
}

fn runtime_custody_listing_availability(record: &RuntimeCustodyListingRecord) -> Value {
    json!({
        "schema": RUNTIME_CUSTODY_LISTING_AVAILABILITY_SCHEMA_V1,
        "status": "last_verified_receipt",
        "checked_at": record.availability.checked_at,
        "required_replicas": PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR,
        "observed_replicas": record.availability.observed_replicas,
        "receipt_digest": record.availability.receipt_digest,
        "recheck_before_buy": true,
        "recheck_before_open": true,
    })
}

/// Whether this person has a purchase of this item under way.
///
/// A purchase lives in Runtime, not in the page that started it, so closing
/// Marketplace or reloading it leaves the attempt running and the row looking
/// untouched. Pressing Buy again resumes the same attempt against the same
/// effect rather than starting a second one, which is safe but invisible --
/// and a person who cannot see that their purchase is still going has no way
/// to tell it from one that never started.
///
/// A record that has reached `Complete` is not in flight: the copy is theirs
/// and `access_state` already says so.
fn runtime_custody_listing_purchase_in_flight(
    data_dir: &Path,
    principal_id: &str,
    record: &RuntimeCustodyListingRecord,
) -> anyhow::Result<bool> {
    let mint_id = parse_mint_id_hex(&record.package.mint_id)?;
    Ok(
        load_runtime_custody_purchase(data_dir, principal_id, mint_id)?.is_some_and(|purchase| {
            matches!(
                purchase.progress,
                RuntimeCustodyPurchaseProgress::Pending { .. }
            )
        }),
    )
}

fn runtime_custody_listing_access_state(
    data_dir: &Path,
    principal_id: &str,
    record: &RuntimeCustodyListingRecord,
) -> anyhow::Result<&'static str> {
    if matches!(
        &record.origin,
        RuntimeCustodyListingOrigin::LocalCreator {
            principal_id: creator,
            ..
        } if creator == principal_id
    ) {
        return Ok(RUNTIME_CUSTODY_LISTING_ACCESS_CREATOR);
    }
    let mint_id = parse_mint_id_hex(&record.package.mint_id)?;
    let Some(purchase) = load_runtime_custody_purchase(data_dir, principal_id, mint_id)? else {
        return Ok(RUNTIME_CUSTODY_LISTING_ACCESS_AVAILABLE);
    };
    if purchase.mint_id != record.package.mint_id
        || purchase.content_id != record.package.content_id
    {
        anyhow::bail!("Runtime custody purchase is invalid");
    }
    // A granted copy is held exactly as a bought one is; `acquisition` says
    // which it was. It is bound to the mint and content checked above, not to
    // the terms of whichever listing now stands for the mint.
    let purchased = match purchase.progress {
        RuntimeCustodyPurchaseProgress::Complete { .. } => {
            purchase.listing_sha256 == record.portable_package_digest()
        }
        RuntimeCustodyPurchaseProgress::Granted { .. } => true,
        RuntimeCustodyPurchaseProgress::Pending { .. } => false,
    };
    Ok(if purchased {
        RUNTIME_CUSTODY_LISTING_ACCESS_PURCHASED
    } else {
        RUNTIME_CUSTODY_LISTING_ACCESS_AVAILABLE
    })
}

fn runtime_custody_display_name(object_uri: &str) -> String {
    let raw = object_uri
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or("protected-content");
    let cleaned = raw
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if cleaned.is_empty() {
        return "protected-content".to_string();
    }
    truncate_utf8_to_bytes(&cleaned, MAX_RUNTIME_CUSTODY_PUBLIC_TEXT_BYTES)
}

fn truncate_utf8_to_bytes(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn validate_runtime_custody_display_name(value: &str) -> anyhow::Result<()> {
    validate_runtime_custody_public_text(value)?;
    if value.chars().all(char::is_whitespace) {
        anyhow::bail!("Runtime custody listing is invalid");
    }
    Ok(())
}

fn validate_runtime_custody_public_text(value: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > MAX_RUNTIME_CUSTODY_PUBLIC_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        anyhow::bail!("Runtime custody listing is invalid");
    }
    Ok(())
}

pub(crate) fn validate_runtime_custody_canonical_quantity(value: &str) -> anyhow::Result<()> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("Runtime custody listing is invalid"))?;
    if raw.is_empty()
        || raw.len() > 64
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("Runtime custody listing is invalid");
    }
    if raw.len() > 1 && raw.starts_with('0') {
        anyhow::bail!("Runtime custody listing is invalid");
    }
    Ok(())
}

pub(crate) fn validate_runtime_custody_evm_address(value: &str) -> anyhow::Result<()> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("Runtime custody listing is invalid"))?;
    if raw.len() != 40
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("Runtime custody listing is invalid");
    }
    Ok(())
}

pub(crate) async fn verify_fresh_runtime_custody_availability(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    listing: &RuntimeCustodyListingRecord,
    mint_id: Digest32,
    now_unix_seconds: u64,
) -> anyhow::Result<(
    RuntimeMintDraft,
    elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1,
)> {
    let expected_mint_id = hex::encode(mint_id.as_bytes());
    if listing.package.mint_id != expected_mint_id {
        tracing::warn!(line = line!(), "Runtime custody purchase denied before buy");
        anyhow::bail!(RUNTIME_CUSTODY_PURCHASE_DENIED_MESSAGE);
    }
    let decoded = listing.package.decode_and_validate()?;
    verify_runtime_portable_content(
        data_dir,
        registry,
        &listing.package,
        &decoded,
        now_unix_seconds,
        RuntimeManifestPublisherBinding::for_origin(&listing.origin),
        PortableVerifyMode::Open,
    )
    .await
    .map_err(|error| {
        tracing::warn!(
            mint_id = %expected_mint_id,
            error = ?error,
            "runtime custody fresh availability failed closed"
        );
        error.context(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE)
    })
}

/// A refused open, carried as data so a viewer presents it as final.
///
/// The sentence stays outermost for the consumers that still read it; the
/// typed state underneath is what tells a viewer to offer no retry.
pub(crate) fn runtime_custody_open_denied() -> anyhow::Error {
    anyhow::Error::new(RuntimeCustodyOpenProgress::denied())
        .context(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE)
}

/// An open blocked by something absent for now, carried as data so a viewer
/// offers the person a retry. The original cause rides the detail chain.
pub(crate) fn runtime_custody_open_unavailable(
    message: &'static str,
    cause: &anyhow::Error,
) -> anyhow::Error {
    anyhow::Error::new(RuntimeCustodyOpenProgress::unavailable())
        .context(format!("{cause:?}"))
        .context(message)
}

/// How long after an acquisition confirms its finality is still watched for.
/// Finality on Base trails the head by about 15-20 minutes. The open reads
/// finality before any Wallet request however old the copy (OPEN-LOOP OP2).
pub(crate) const RUNTIME_CUSTODY_FINALITY_WATCH_SECS: u64 = 60 * 60;

/// How long finality usually trails a confirmed acquisition on Base: Ethereum
/// finalizes after two epochs (about 13-15 minutes) and the L2 batch must be
/// posted first. Only used to tell the person roughly when to expect it.
pub(crate) const RUNTIME_CUSTODY_EXPECTED_FINALITY_LAG_SECS: u64 = 20 * 60;

/// What one access read answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyAccessAt {
    Granted,
    NotGranted,
    Unanswered,
}

/// Asks the chain whether `wallet` holds the access at `block` (`finalized`
/// or `latest`). An unbound content id is an answer -- nothing is granted at
/// that block -- while anything the chain could not answer is `Unanswered`.
/// What a viewer release operation is built from, other than its time.
struct RuntimeViewerReleaseOperationInput<'a> {
    data_dir: &'a Path,
    principal_id: &'a str,
    proof_binding_id: &'a str,
    signed_rights: &'a WalletSignedRightsRequestV1,
    prepared: &'a RuntimePreparedRecipient,
    policy: &'a ResolvedRuntimeRightsPolicy,
    custody_epoch: &'a SignedCustodyEpochV1,
    audit_request_id: RuntimeReleaseAuditIdV1,
}

/// Builds the Runtime release operation for one viewer open, valid from `now`.
///
/// Everything here is signed by this Runtime over the Wallet's signed rights
/// request, which lives for the whole approval window, so a later `now` gives
/// a fresh operation without asking the Wallet again. The rights request, the
/// recipient and the audit ID stay those of the open.
fn runtime_viewer_release_operation_at(
    input: &RuntimeViewerReleaseOperationInput<'_>,
    now: u64,
) -> anyhow::Result<SignedRuntimeReleaseOperationV1> {
    let signed_rights = input.signed_rights;
    let release_request = KeyReleaseRequestV1::new(
        signed_rights.request().binding().clone(),
        signed_rights
            .request()
            .request_hash()
            .map_err(|error| anyhow::anyhow!("rights request hash is invalid: {error:?}"))?,
        RightsActionV1::View,
        input.prepared.recipient_identity().clone(),
        now.saturating_sub(5),
        now + 55,
        ReplayNonce16::new(audit_nonce_bytes(input.audit_request_id)),
    )
    .map_err(|error| anyhow::anyhow!("release request is invalid: {error:?}"))?;
    let evidence_request = RightsEvaluationEvidenceRequestV1::new(
        signed_rights.request().binding().clone(),
        input.policy.identity().clone(),
    )
    .map_err(|error| anyhow::anyhow!("rights evidence request is invalid: {error:?}"))?;
    let localhost_root = crate::auth::principal_localhost_root(input.principal_id);
    assemble_protected_content_runtime_release_operation(
        input.data_dir,
        input.principal_id,
        &localhost_root,
        input.proof_binding_id,
        RuntimeReleaseOperationAssemblyInput {
            rights_request: signed_rights.clone(),
            release_request,
            recipient_public_key: *input.prepared.recipient_public_key(),
            recipient_identity: input.prepared.recipient_identity().clone(),
            policy_body: input.policy.body().clone(),
            evidence_request,
            custody_epoch: input.custody_epoch.clone(),
            audit_request_id: input.audit_request_id,
            issued_at: now.saturating_sub(3),
            expires_at: now + 50,
        },
        now,
    )
}

async fn runtime_custody_access_at(
    registry: &ProviderRegistry,
    network: &str,
    wallet: &str,
    content_access_id: ContentAccessIdV1,
    request_id: &str,
    block: &'static str,
) -> RuntimeCustodyAccessAt {
    let content_access_id_hex = runtime_content_access_id_hex(content_access_id);
    let request_id = format!("{request_id}:{block}");
    let answer = invoke_json_provider_classified(
        registry,
        CHAIN_PROVIDER_ID,
        "resolve_protected_content_purchase_access",
        json!({
            "op": "resolve_protected_content_purchase_access",
            "request_id": request_id,
            "network": network,
            "wallet": wallet,
            "content_access_id": content_access_id_hex,
            "block": block,
        }),
        ProviderInvocationTransport::Local,
    )
    .await;
    match answer {
        Ok(data)
            if data["request_id"] == request_id.as_str()
                && data["content_access_id"]
                    .as_str()
                    .is_some_and(|id| id.eq_ignore_ascii_case(&content_access_id_hex)) =>
        {
            match data["has_access"].as_bool() {
                Some(true) => RuntimeCustodyAccessAt::Granted,
                Some(false) => RuntimeCustodyAccessAt::NotGranted,
                None => RuntimeCustodyAccessAt::Unanswered,
            }
        }
        Err(ProviderInvocationFailure::Refused { code, .. })
            if code == "unknown_protected_content_object" =>
        {
            RuntimeCustodyAccessAt::NotGranted
        }
        Ok(_) | Err(_) => RuntimeCustodyAccessAt::Unanswered,
    }
}

/// Whether an open should wait for finality instead of asking custody now.
///
/// Custody releases a key only on finalized rights evidence, while an
/// acquisition is readable at the head seconds after it confirms. Inside that
/// lag, every custody node would answer "unbound" and the open would fail
/// after spending a Wallet approval. This asks the same question custody will
/// ask first, and answers `finalizing` when only the head has the grant.
///
/// It only ever turns a certain failure into a wait: when the copy is already
/// finalized, not granted at the head either, or the chain cannot answer, it
/// returns `None` and the open proceeds exactly as before. OPEN-LOOP OP2: it
/// is asked however long ago the copy confirmed, so no Wallet request is
/// raised that cannot lead to a release.
pub(crate) async fn runtime_custody_open_finality_progress(
    registry: &ProviderRegistry,
    network: &str,
    wallet: &str,
    content_access_id: ContentAccessIdV1,
    request_id: &str,
    confirmed_at: u64,
    now: u64,
) -> Option<RuntimeCustodyOpenProgress> {
    let read = |block| {
        runtime_custody_access_at(
            registry,
            network,
            wallet,
            content_access_id,
            request_id,
            block,
        )
    };
    if !matches!(read("finalized").await, RuntimeCustodyAccessAt::NotGranted) {
        return None;
    }
    if !matches!(read("latest").await, RuntimeCustodyAccessAt::Granted) {
        return None;
    }
    let expected = confirmed_at.saturating_add(RUNTIME_CUSTODY_EXPECTED_FINALITY_LAG_SECS);
    // A lag longer than usual reads as "any moment now", never a time gone by.
    Some(RuntimeCustodyOpenProgress::finalizing(
        expected.max(now.saturating_add(60)),
    ))
}

pub(crate) async fn open_runtime_custody_viewer(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    input: RuntimeCustodyViewerOpenInput,
) -> anyhow::Result<Value> {
    let mint_id = parse_mint_id_hex(&input.mint_id)?;
    let _viewer_lifecycle_guard =
        acquire_runtime_custody_viewer_lifecycle_guard(data_dir, &input.principal_id, mint_id)
            .await;
    let purchase = load_runtime_custody_purchase(data_dir, &input.principal_id, mint_id)?
        .ok_or_else(runtime_custody_open_denied)?;
    if purchase.principal_id != input.principal_id {
        return Err(runtime_custody_open_denied());
    }
    let profile_did = load_runtime_custody_profile_did(data_dir, &input.principal_id)?;
    let listing =
        load_runtime_custody_listing(data_dir, mint_id)?.ok_or_else(runtime_custody_open_denied)?;
    let asset = validate_runtime_custody_viewer_asset(
        &listing,
        &input.principal_id,
        &profile_did,
        mint_id,
        &purchase,
    )?;
    let launch_id = input
        .launch_id
        .as_deref()
        .filter(|value| valid_runtime_viewer_launch_id(value));
    let proof_binding_id = input
        .proof_binding_id
        .as_deref()
        .filter(|value| !value.is_empty());
    let session_id = input
        .session_id
        .as_deref()
        .filter(|value| !value.is_empty());
    let grant_id = input.grant_id.as_deref().filter(|value| !value.is_empty());
    let (Some(launch_id), Some(proof_binding_id), Some(session_id), Some(grant_id)) =
        (launch_id, proof_binding_id, session_id, grant_id)
    else {
        return Err(release_unavailable_missing!()());
    };
    let runtime_session_binding = derive_runtime_custody_session_binding(
        &input.principal_id,
        &profile_did,
        &input.executable_actor,
        launch_id,
        proof_binding_id,
        session_id,
        grant_id,
        mint_id,
    )?;
    // Kind <-> viewer, checked ABOVE every replay / cached-response shortcut
    // below. `asset.content_identity` is the listing package's own identity,
    // already cross-bound to this principal's completed purchase by
    // `validate_runtime_custody_viewer_asset`, so the admitted viewer capsule
    // for this mint's content kind is known here without any provider round
    // trip or mint-journal read. The authoritative re-check against the
    // freshly verified mint draft stays further down (the draft is rebuilt
    // from re-fetched, re-verified content); this one only makes sure a
    // cross-kind actor can never reach a shortcut that returns a session.
    if input.executable_actor != expected_runtime_custody_viewer_capsule(&asset.content_identity) {
        return Err(runtime_custody_open_denied());
    }
    // An open-pending record that still waits on the Wallet approval of its
    // rights-signature request is resumed for the same runtime session
    // (same prepared recipient, same wallet request) instead of being torn
    // down and re-prepared, which would orphan the pending approval.
    let mut resumed_pending_release: Option<RuntimeCustodyViewerRecord> = None;
    if let Some(record) =
        load_runtime_custody_viewer_record(data_dir, &input.principal_id, mint_id)?
    {
        if !record.validates_authority_identity(
            &input.principal_id,
            &profile_did,
            mint_id,
            &purchase.content_id,
        ) {
            return Err(runtime_custody_open_denied());
        }
        let viewer_now = crate::auth::now_ts();
        match record.lifecycle_status {
            // A pool viewer is reused only while its delivery secret lives in
            // this process (Plan B T4.4); otherwise it settles below and the
            // open starts fresh.
            RuntimeCustodyViewerLifecycleStatus::Active
                if record.matches_runtime_session_binding(&runtime_session_binding)
                    && !record.is_expired(viewer_now)
                    && runtime_custody_pool_record_has_secret(&record, viewer_now) =>
            {
                let session =
                    record.to_runtime_viewer_session(asset.content_identity.encrypted_content())?;
                return runtime_custody_viewer_response_for(
                    &asset.content_identity,
                    mint_id,
                    session.viewer_session_handle(),
                    session.expires_at(),
                );
            }
            RuntimeCustodyViewerLifecycleStatus::OpenPending
                if record.pending_release.is_some()
                    && record.matches_runtime_session_binding(&runtime_session_binding)
                    && !record.is_expired(viewer_now)
                    && runtime_custody_pool_record_has_secret(&record, viewer_now) =>
            {
                tracing::debug!(
                    mint_id = %hex::encode(mint_id.as_bytes()),
                    "runtime custody open: resuming viewer release pending Wallet approval"
                );
                resumed_pending_release = Some(record);
            }
            RuntimeCustodyViewerLifecycleStatus::Active
                if !record.matches_runtime_session_binding(&runtime_session_binding)
                    && !record.is_expired(viewer_now) =>
            {
                return Err(runtime_custody_open_denied());
            }
            RuntimeCustodyViewerLifecycleStatus::OpenPending
            | RuntimeCustodyViewerLifecycleStatus::Active
            | RuntimeCustodyViewerLifecycleStatus::CleanupPending => {
                if record.lifecycle_status == RuntimeCustodyViewerLifecycleStatus::Active
                    && !record.is_expired(viewer_now)
                    && !record.matches_runtime_session_binding(&runtime_session_binding)
                {
                    return Err(runtime_custody_open_denied());
                }
                let _ = settle_runtime_custody_viewer_cleanup(
                    data_dir,
                    registry.clone(),
                    &listing,
                    &input.principal_id,
                    mint_id,
                    record,
                )
                .await?;
            }
            RuntimeCustodyViewerLifecycleStatus::Closed
            | RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent => {}
        }
    }
    let (draft, fresh_availability) = verify_fresh_runtime_custody_availability(
        data_dir,
        &registry,
        &listing,
        mint_id,
        crate::auth::now_ts(),
    )
    .await?;
    // Session binding v3, kind <-> viewer: the launch-verified
    // `executable_actor` (already checked at the gateway proxy to be one of
    // the two admitted viewer capsules) must be the ONE admitted capsule for
    // this draft's own content kind, not merely any admitted viewer.
    //
    // THIS IS THE SOLE ENFORCEMENT POINT for kind <-> viewer. The gateway
    // proxy deliberately does NOT also check it — see the comment at its
    // `is_protected_viewer_op` block: a pre-dispatch `RuntimeMintJournal::load`
    // there would create this Runtime's mint-journal directory as a side
    // effect of every `open_viewer` call, which broke cross-runtime isolation.
    // Removing the check below therefore removes it entirely; nothing else
    // rejects a reader opening a media mint (or a player opening an object).
    // The cached/replay shortcuts earlier in this function cannot be used to
    // slip past it: every one of them requires
    // `record.matches_runtime_session_binding(...)`, and the binding is
    // derived over `executable_actor`, so a cross-kind actor can never match a
    // session opened by the correct one.
    if input.executable_actor != expected_runtime_custody_viewer_capsule(draft.content_identity()) {
        return Err(runtime_custody_open_denied());
    }
    if fresh_availability.content_cid() != purchase.cid {
        return Err(runtime_custody_open_unavailable(
            RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE,
            &anyhow::anyhow!("fresh availability CID differs from the purchased CID"),
        ));
    }
    let buy = reconstructed_buy_receipt(&draft, &fresh_availability, &purchase, &profile_did)?;
    // Inside the finality lag custody would refuse this copy as unbound, and
    // only after the Wallet approved the release. Ask first and answer a wait.
    // A resumed approval is past this point already and is left to finish.
    if resumed_pending_release.is_none() {
        // A granted copy rests on nothing but the grant, so the grant is read
        // again, at finalized, before anything is asked of the Wallet: an
        // admin removed from the channel is refused here, not after approving.
        if let RuntimeCustodyPurchaseProgress::Granted { .. } = &purchase.progress {
            match runtime_custody_access_at(
                registry.as_ref(),
                &purchase.network,
                &purchase.address,
                draft.content_access_id(),
                &format!("open-grant:{}", hex::encode(mint_id.as_bytes())),
                "finalized",
            )
            .await
            {
                RuntimeCustodyAccessAt::NotGranted => {
                    tracing::debug!("runtime custody open: the chain no longer grants this copy");
                    return Err(runtime_custody_open_denied());
                }
                // A chain that cannot answer here leaves the answer to
                // custody, which reads the same grant before any release.
                RuntimeCustodyAccessAt::Granted | RuntimeCustodyAccessAt::Unanswered => {}
            }
        }
        if let RuntimeCustodyPurchaseProgress::Complete { terminal } = &purchase.progress {
            if let Some(progress) = runtime_custody_open_finality_progress(
                registry.as_ref(),
                &purchase.network,
                &purchase.address,
                draft.content_access_id(),
                &format!("open-finality:{}", hex::encode(mint_id.as_bytes())),
                terminal.confirmed_at,
                crate::auth::now_ts(),
            )
            .await
            {
                tracing::debug!(
                    stage = progress.stage_label(),
                    "runtime custody open: acquisition awaits finality, answering with typed open progress"
                );
                return Err(anyhow::Error::new(progress)
                    .context(format!("{}:{}", file!(), line!()))
                    .context(RUNTIME_CUSTODY_OPEN_FINALIZING_MESSAGE));
            }
        }
    }
    // Plan B T4.4, the route matrix (S4-A1), chosen once per open after the
    // checks above and before the composition load and any Wallet call:
    // 1. the item's pool resolves (this Home's node keys excluded; the owner
    //    included, through another member): the pool branch;
    // 2. otherwise a local holder (`runtime_custody_local_holder`): today's
    //    local V1 open below, unchanged;
    // 3. otherwise `custody_unresolved` or `no_eligible_server`.
    // A pending resume keeps the route it started on, and no failure after
    // the choice falls back to the local branch.
    let resumed_is_pool = resumed_pending_release
        .as_ref()
        .is_some_and(RuntimeCustodyViewerRecord::is_pool);
    if resumed_pending_release.is_none() || resumed_is_pool {
        // OPEN-LOOP F4: unreadable roots exclude nothing; a server that is
        // this Home's own then refuses `not_eligible_server`, and the open
        // fails over.
        let own_node_keys = own_custody_node_keys(data_dir).unwrap_or_else(|error| {
            tracing::warn!(error = %format!("{error:#}"), "this Home's custody roots cannot be listed");
            Vec::new()
        });
        let resolved = crate::custody_pool_resolver::home_pool_resolver(data_dir, registry.clone())
            .resolve(draft.key_envelope(), &own_node_keys, crate::auth::now_ts())
            .await;
        let local_holder = match &resolved {
            Ok(_) => false,
            Err(_) if resumed_is_pool => false,
            Err(_) => runtime_custody_local_holder(data_dir, &registry, draft.key_envelope())
                .await
                .unwrap_or(false),
        };
        match resolved {
            Ok(resolved) => {
                return open_runtime_custody_pool_viewer(RuntimeCustodyPoolOpenInput {
                    data_dir,
                    registry: registry.clone(),
                    listing: &listing,
                    principal_id: &input.principal_id,
                    profile_did: &profile_did,
                    mint_id,
                    purchase: &purchase,
                    proof_binding_id,
                    session_id,
                    grant_id,
                    runtime_session_binding,
                    buy: &buy,
                    draft: &draft,
                    resolved,
                    own_node_keys,
                    resumed: resumed_pending_release,
                })
                .await;
            }
            Err(error) if !local_holder => {
                tracing::debug!(%error, "runtime custody open: the item's pool cannot be used");
                if let Some(record) = resumed_pending_release {
                    let _ = settle_runtime_custody_viewer_cleanup(
                        data_dir,
                        registry.clone(),
                        &listing,
                        &input.principal_id,
                        mint_id,
                        record,
                    )
                    .await;
                }
                return Err(crate::protected_content_pool_open::pool_unresolved_error(
                    error,
                ));
            }
            Err(_) => {}
        }
    }
    let composition =
        load_runtime_custody_composition(data_dir, registry.clone())?.ok_or_else(|| {
            runtime_custody_open_unavailable(
                RUNTIME_CUSTODY_COMPOSITION_MISSING_MESSAGE,
                &anyhow::anyhow!("no signed custody composition is installed"),
            )
        })?;
    let (device_key, _) =
        crate::collaboration_profile_authority::load_existing_device_signing_key(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    let runtime_issuer = RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())
        .map_err(|_| anyhow::anyhow!("local Runtime device signing key is invalid"))?;
    let now = crate::auth::now_ts();
    let decrypt = RuntimeDecryptRegistryAdapter::new(registry.clone());
    let (prepared, mut open_pending, audit_request_id, replay_wallet_request) =
        if let Some(record) = resumed_pending_release {
            let pending = record
                .pending_release
                .clone()
                .ok_or_else(release_unavailable_missing!())?;
            let audit_request_id = RuntimeReleaseAuditIdV1::new(record.audit_request_id()?)
                .map_err(release_unavailable!())?;
            let prepared = RuntimePreparedRecipient::from_persisted_parts(
                audit_request_id.digest(),
                record.viewer_session_handle_bytes()?,
                buy.binding_for_session(runtime_session_binding)
                    .map_err(release_unavailable!())?,
                buy.action(),
                runtime_issuer,
                record.expires_at,
                pending.recipient_public_key()?,
                pending.recipient_identity()?,
            )
            .map_err(release_unavailable!())?;
            let replay = pending.wallet_request()?;
            (prepared, record, audit_request_id, Some(replay))
        } else {
            let audit_request_id = runtime_open_audit_id(&input.principal_id, mint_id, now);
            let prepared = match prepare_recipient(
                &decrypt,
                &buy,
                runtime_session_binding,
                audit_request_id,
                runtime_issuer,
                now.saturating_sub(5),
                now + RUNTIME_CUSTODY_OPEN_APPROVAL_WINDOW_SECS,
            )
            .await
            {
                Ok(prepared) => prepared,
                Err(error) => {
                    return Err(runtime_custody_open_unavailable(
                        RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE,
                        &anyhow::anyhow!("{error:?}"),
                    ))
                }
            };
            let open_pending =
                RuntimeCustodyViewerRecord::from_open_pending(RuntimeCustodyOpenPendingInput {
                    principal_id: &input.principal_id,
                    profile_did: &profile_did,
                    mint_id,
                    content_id: &purchase.content_id,
                    runtime_session_binding,
                    audit_request_id: prepared.audit_request_id(),
                    viewer_session_handle: *prepared.prepared_recipient_handle(),
                    expires_at: prepared.expires_at(),
                    now: crate::auth::now_ts(),
                })?;
            if let Err(error) = persist_runtime_custody_viewer_record(
                data_dir,
                &input.principal_id,
                mint_id,
                &open_pending,
            ) {
                let _ = cancel_prepared_recipient(&decrypt, &prepared).await;
                return Err(error);
            }
            (prepared, open_pending, audit_request_id, None)
        };
    let (release_wallet_request, release_wallet_response, signed_rights) =
        match invoke_runtime_release_wallet(
            registry.as_ref(),
            &buy,
            prepared.recipient_identity(),
            RuntimeReleaseWalletInvocation {
                principal_id: &input.principal_id,
                account_id: &purchase.account_id,
                proof_binding_id,
                session_id,
                grant_id,
                mint_id,
                runtime_session_binding,
            },
            replay_wallet_request.as_deref(),
            now,
        )
        .await
        {
            Ok(RuntimeReleaseWalletOutcome::Signed {
                request_bytes,
                response_bytes,
                signed_rights,
            }) => (request_bytes, response_bytes, *signed_rights),
            Ok(RuntimeReleaseWalletOutcome::PendingApproval {
                request_bytes,
                approval_request_id,
                external_signer,
                connector_id,
            }) => {
                // First pending answer: remember the exact request and the
                // recipient identity so the next open replays it; the prepared
                // recipient stays alive in the decrypt provider until the
                // record expires.
                if open_pending.pending_release.is_none() {
                    open_pending.pending_release = Some(RuntimeCustodyPendingRelease::new(
                        &request_bytes,
                        &approval_request_id,
                        &prepared,
                    ));
                    open_pending.updated_at = crate::auth::now_ts();
                    persist_runtime_custody_viewer_record(
                        data_dir,
                        &input.principal_id,
                        mint_id,
                        &open_pending,
                    )?;
                }
                // A waiting state, carried as data. The viewer reads it to show
                // the ceremony and to re-issue this identical open once the
                // person answers, instead of reading the sentence below and
                // stopping.
                let progress = RuntimeCustodyOpenProgress::awaiting_rights_approval(
                    external_signer,
                    connector_id.as_deref(),
                    &approval_request_id,
                    open_pending.expires_at,
                );
                tracing::debug!(
                    stage = progress.stage_label(),
                    awaits_person = progress.awaits_person(),
                    "runtime custody open: answering with typed open progress"
                );
                return Err(anyhow::Error::new(progress)
                    .context(format!("{}:{}", file!(), line!()))
                    .context(RUNTIME_CUSTODY_OPEN_PENDING_MESSAGE));
            }
            Err(error) => {
                let _ = settle_runtime_custody_viewer_cleanup(
                    data_dir,
                    registry.clone(),
                    &listing,
                    &input.principal_id,
                    mint_id,
                    open_pending.clone(),
                )
                .await;
                // Every release wallet error already carries the stable message
                // outermost with its cause chain; pass it through unchanged.
                return Err(error);
            }
        };
    let policy = match resolve_runtime_rights_policy(
        registry.as_ref(),
        draft.encrypted_content(),
        draft.content_access_id(),
        RightsActionV1::View,
    )
    .await
    {
        Ok(policy) => policy,
        Err(_) => {
            let _ = settle_runtime_custody_viewer_cleanup(
                data_dir,
                registry.clone(),
                &listing,
                &input.principal_id,
                mint_id,
                open_pending.clone(),
            )
            .await;
            anyhow::bail!("Runtime custody rights policy is unavailable");
        }
    };
    let release_input = RuntimeViewerReleaseOperationInput {
        data_dir,
        principal_id: &input.principal_id,
        proof_binding_id,
        signed_rights: &signed_rights,
        prepared: &prepared,
        policy: &policy,
        custody_epoch: &composition.signed_epoch,
        audit_request_id,
    };
    let mut operation = match runtime_viewer_release_operation_at(&release_input, now) {
        Ok(operation) => operation,
        Err(error) => {
            tracing::warn!(
                error = ?error,
                "Runtime custody viewer release operation could not be assembled"
            );
            let _ = settle_runtime_custody_viewer_cleanup(
                data_dir,
                registry.clone(),
                &listing,
                &input.principal_id,
                mint_id,
                open_pending.clone(),
            )
            .await;
            return Err(release_unavailable_missing!()());
        }
    };
    let selected = vec![
        RuntimeSelectedProvider::new(
            composition.nodes[0].node_public_key,
            &composition.nodes[0].adapter,
            &composition.nodes[0].adapter,
        ),
        RuntimeSelectedProvider::new(
            composition.nodes[1].node_public_key,
            &composition.nodes[1].adapter,
            &composition.nodes[1].adapter,
        ),
        RuntimeSelectedProvider::new(
            composition.nodes[2].node_public_key,
            &composition.nodes[2].adapter,
            &composition.nodes[2].adapter,
        ),
    ];
    let coordinator =
        RuntimeReleaseCoordinator::new(runtime_release_journal(data_dir), runtime_issuer, selected)
            .map_err(release_unavailable!())?
            .with_response_clock(crate::auth::now_ts);
    let contributions = match coordinator
        .release(
            &release_wallet_request,
            &release_wallet_response,
            operation.clone().into(),
            now,
        )
        .await
    {
        Ok(RuntimeReleaseCoordinatorOutcome::Terminal(
            RuntimeReleaseTerminalResult::ContributionsReady {
                signed_node_contributions,
            },
        )) => signed_node_contributions,
        Ok(RuntimeReleaseCoordinatorOutcome::Nonterminal {
            operation_hash,
            reason,
        }) => {
            let resume_now = crate::auth::now_ts();
            let seconds_left = operation
                .statement()
                .expires_at()
                .saturating_sub(resume_now);
            // An operation with less than one node round left expires part
            // way through the resume, at every node. When no custody node can
            // have been asked for a contribution yet, nothing durable stands
            // on this operation, so a fresh one is built from the same Wallet
            // signature instead. Otherwise the exact operation is resumed, as
            // a node that already contributed answers only to it.
            let supersede = seconds_left < RUNTIME_CUSTODY_RELEASE_RESUME_MIN_SECS
                && !coordinator.custody_contribution_possibly_requested(operation_hash);
            tracing::debug!(
                ?reason,
                seconds_left,
                supersede,
                "runtime custody open: release nonterminal"
            );
            let resumed = if supersede {
                match runtime_viewer_release_operation_at(&release_input, resume_now) {
                    Ok(fresh) => {
                        operation = fresh;
                        coordinator
                            .release(
                                &release_wallet_request,
                                &release_wallet_response,
                                operation.clone().into(),
                                resume_now,
                            )
                            .await
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = ?error,
                            "Runtime custody viewer release operation could not be rebuilt"
                        );
                        Err(elastos_protected_content_runtime::RuntimeReleaseCoordinatorError::OperationAuthority)
                    }
                }
            } else {
                coordinator.resume_exact(operation_hash, resume_now).await
            };
            match resumed {
                Ok(RuntimeReleaseCoordinatorOutcome::Terminal(
                    RuntimeReleaseTerminalResult::ContributionsReady {
                        signed_node_contributions,
                    },
                )) => signed_node_contributions,
                other => {
                    let _ = settle_runtime_custody_viewer_cleanup(
                        data_dir,
                        registry.clone(),
                        &listing,
                        &input.principal_id,
                        mint_id,
                        open_pending.clone(),
                    )
                    .await;
                    return Err(release_unavailable!()(format!(
                        "release resume did not yield contributions: {other:?}{}",
                        runtime_custody_reported_by_nodes(&composition.diagnostics)
                    )));
                }
            }
        }
        other => {
            let _ = settle_runtime_custody_viewer_cleanup(
                data_dir,
                registry.clone(),
                &listing,
                &input.principal_id,
                mint_id,
                open_pending.clone(),
            )
            .await;
            return Err(release_unavailable!()(format!(
                "release did not yield contributions: {other:?}{}",
                runtime_custody_reported_by_nodes(&composition.diagnostics)
            )));
        }
    };
    let receipt_now = crate::auth::now_ts();
    let terminal_receipt = match sign_runtime_terminal_receipt(
        &device_key,
        &operation,
        &contributions,
        &composition.signed_epoch,
        receipt_now,
    ) {
        Ok(receipt) => receipt,
        Err(_) => {
            let _ = settle_runtime_custody_viewer_cleanup(
                data_dir,
                registry.clone(),
                &listing,
                &input.principal_id,
                mint_id,
                open_pending.clone(),
            )
            .await;
            return Err(release_unavailable_missing!()());
        }
    };
    let expected_terminal_issuer =
        match TerminalReceiptIssuerKey::new(device_key.verifying_key().to_bytes()) {
            Ok(issuer) => issuer,
            Err(_) => {
                let _ = settle_runtime_custody_viewer_cleanup(
                    data_dir,
                    registry.clone(),
                    &listing,
                    &input.principal_id,
                    mint_id,
                    open_pending.clone(),
                )
                .await;
                anyhow::bail!("local Runtime device signing key is invalid");
            }
        };
    // Fetched here rather than before the Wallet was asked, which is where it
    // used to sit. `open_runtime_custody_viewer` runs top to bottom on every
    // call, and a viewer re-issues the identical open every couple of seconds
    // while a person reads their wallet prompt -- so the whole object was
    // fetched and re-hashed on the first open, thrown away with the pending
    // answer, and fetched again on every poll of the wait. A minute at the
    // prompt cost roughly thirty full fetches of the same file.
    //
    // Nothing between the availability check and here reads this content: the
    // prepared recipient and the rights request bind to `buy`, not to the
    // bytes. So a pending answer now returns without fetching at all, and only
    // the pass that actually holds a signature pays for it.
    //
    // The availability receipt is still verified before the prompt is raised,
    // so a person is not asked to approve content this Runtime cannot reach.
    // What moved is the expensive full fetch, not the availability decision.
    let open_content = match draft.content_identity() {
        RuntimeContentIdentityV1::MediaDash(expected_head) => {
            let (protected_init_segments, leaves) = fetch_runtime_custody_open_media_dash(
                registry.as_ref(),
                &purchase.cid,
                expected_head,
            )
            .await?;
            // Staged once so every segment read takes its proof from verified
            // leaves instead of fetching the manifest again. A staging failure
            // is not fatal: the read falls back to the manifest.
            if let Err(error) = stage_runtime_custody_media_dash_leaves(
                data_dir,
                &input.principal_id,
                mint_id,
                expected_head,
                &leaves,
            ) {
                tracing::warn!(
                    ?error,
                    "runtime custody open: staging the segment leaves failed; reads will fetch the manifest"
                );
            }
            RuntimeCustodyOpenContent::MediaDash {
                media_identity_v2: expected_head.clone(),
                protected_init_segments,
            }
        }
        RuntimeContentIdentityV1::Media(expected_media_identity) => {
            let (media_identity, protected_init) = fetch_runtime_custody_open_media(
                registry.as_ref(),
                &purchase.cid,
                expected_media_identity,
            )
            .await?;
            RuntimeCustodyOpenContent::Media {
                media_identity,
                protected_init,
            }
        }
        RuntimeContentIdentityV1::Object(expected_object_identity) => {
            let framed = fetch_runtime_custody_open_object(
                registry.as_ref(),
                &purchase.cid,
                expected_object_identity,
            )
            .await?;
            let framed_header =
                runtime_custody_object_framed_header(&framed, expected_object_identity)?;
            // Staged once, here, so every chunk read seeks into verified bytes
            // instead of fetching and re-hashing the whole object again. A
            // staging failure is not fatal: the read path falls back to
            // fetching, which is what it always did.
            if let Err(error) =
                stage_runtime_custody_object(data_dir, &input.principal_id, mint_id, &framed)
            {
                tracing::warn!(
                    ?error,
                    "runtime custody open: staging the object failed; reads will fetch"
                );
            }
            // The verified buffer is not held while the viewer session opens.
            drop(framed);
            RuntimeCustodyOpenContent::Object {
                object_identity: expected_object_identity.clone(),
                framed_header,
            }
        }
    };
    let session = match open_viewer_session(
        &decrypt,
        &RuntimeOpenViewerSessionInput {
            buy: &buy,
            prepared_recipient: &prepared,
            signed_runtime_release_operation: &operation,
            expected_terminal_issuer,
            content_key_commitment: draft.content_key_commitment(),
            content: open_content.as_open_viewer_content(),
            signed_node_contributions: &contributions,
            signed_terminal_receipt: &terminal_receipt,
            now_unix_seconds: crate::auth::now_ts(),
        },
    )
    .await
    {
        Ok(session) => session,
        Err(_) => {
            // No session will read the leaves staged for it.
            let _ = fs::remove_file(runtime_viewer_leaves_path(
                data_dir,
                &input.principal_id,
                mint_id,
            ));
            let _ = settle_runtime_custody_viewer_cleanup(
                data_dir,
                registry.clone(),
                &listing,
                &input.principal_id,
                mint_id,
                open_pending.clone(),
            )
            .await;
            return Err(runtime_custody_open_unavailable(
                RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE,
                &anyhow::anyhow!("opening the decrypt viewer session failed"),
            ));
        }
    };
    let handle = *session.viewer_session_handle();
    let expires_at = session.expires_at();
    let viewer_now = crate::auth::now_ts();
    let record = RuntimeCustodyViewerRecord::from_active_session(
        &input.principal_id,
        &profile_did,
        mint_id,
        &purchase.content_id,
        runtime_session_binding,
        &session,
        viewer_now,
    )?;
    if let Err(error) =
        persist_runtime_custody_viewer_record(data_dir, &input.principal_id, mint_id, &record)
    {
        let _ = fs::remove_file(runtime_viewer_leaves_path(
            data_dir,
            &input.principal_id,
            mint_id,
        ));
        let _ = settle_runtime_custody_viewer_cleanup(
            data_dir,
            registry.clone(),
            &listing,
            &input.principal_id,
            mint_id,
            open_pending,
        )
        .await;
        return Err(error);
    }
    // Built from `open_content` — the identity the fetch above re-verified
    // against the published bytes — so the response can never describe content
    // the Runtime did not just re-observe.
    match &open_content {
        RuntimeCustodyOpenContent::Media { media_identity, .. } => {
            runtime_custody_viewer_public_response(media_identity, mint_id, &handle, expires_at)
        }
        RuntimeCustodyOpenContent::Object {
            object_identity, ..
        } => runtime_custody_viewer_object_public_response(
            object_identity,
            mint_id,
            &handle,
            expires_at,
        ),
        RuntimeCustodyOpenContent::MediaDash {
            media_identity_v2, ..
        } => runtime_custody_viewer_media_dash_public_response(
            media_identity_v2,
            mint_id,
            &handle,
            expires_at,
        ),
    }
}

/// Whether a pool record still has its delivery secret in this process; a
/// local-decrypt record always passes. Without it a pool viewer can neither
/// read nor resume, so the open settles the record and starts fresh.
fn runtime_custody_pool_record_has_secret(record: &RuntimeCustodyViewerRecord, now: u64) -> bool {
    if !record.is_pool() {
        return true;
    }
    record.viewer_session_handle_bytes().is_ok_and(|handle| {
        crate::protected_content_pool_open::PoolDeliveryKeys::global().contains(&handle, now)
    })
}

/// The open's public answer, from the identity the draft verified.
fn runtime_custody_viewer_response_for(
    identity: &RuntimeContentIdentityV1,
    mint_id: Digest32,
    handle: &[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    expires_at: u64,
) -> anyhow::Result<Value> {
    match identity {
        RuntimeContentIdentityV1::Media(media_identity) => {
            runtime_custody_viewer_public_response(media_identity, mint_id, handle, expires_at)
        }
        RuntimeContentIdentityV1::Object(object_identity) => {
            runtime_custody_viewer_object_public_response(
                object_identity,
                mint_id,
                handle,
                expires_at,
            )
        }
        RuntimeContentIdentityV1::MediaDash(head) => {
            runtime_custody_viewer_media_dash_public_response(head, mint_id, handle, expires_at)
        }
    }
}

/// The pool open's public answer: the viewer answer plus the verified
/// descriptor's read-ahead bound, a pacing hint the server enforces (T4.5
/// "Strict read-ahead"). The viewer contract fixture
/// (`protected_content_runtime/viewer_contract.json`) pins its shape.
fn runtime_custody_pool_viewer_response(
    identity: &RuntimeContentIdentityV1,
    mint_id: Digest32,
    opened: &crate::protected_content_pool_open::PoolOpened,
) -> anyhow::Result<Value> {
    let mut response =
        runtime_custody_viewer_response_for(identity, mint_id, &opened.handle, opened.expires_at)?;
    response["read_ahead_segments"] = json!(opened.read_ahead_segments);
    Ok(response)
}

/// A read's public answer for one media part, v1 or DASH v2, local or pool.
fn runtime_custody_viewer_media_part_response(
    mint_id: Digest32,
    handle_hex: &str,
    clear: &[u8],
) -> Value {
    json!({
        "schema": "elastos.library.runtime-custody-viewer-part/v1",
        "mint_id": hex::encode(mint_id.as_bytes()),
        "viewer_session_handle": handle_hex,
        "encoding": "base64",
        "data": base64::engine::general_purpose::STANDARD.encode(clear),
    })
}

/// A read's public answer for one object chunk, local or pool.
fn runtime_custody_viewer_object_part_response(
    mint_id: Digest32,
    handle_hex: &str,
    chunk_index: u32,
    clear: &[u8],
) -> Value {
    json!({
        "schema": "elastos.library.runtime-custody-viewer-part/v1",
        "content_kind": RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_OBJECT,
        "mint_id": hex::encode(mint_id.as_bytes()),
        "viewer_session_handle": handle_hex,
        "chunk_index": chunk_index,
        "encoding": "base64",
        "data": base64::engine::general_purpose::STANDARD.encode(clear),
    })
}

/// What the pool open of one viewer is built from (Plan B T4.4).
struct RuntimeCustodyPoolOpenInput<'a> {
    data_dir: &'a Path,
    registry: Arc<ProviderRegistry>,
    listing: &'a RuntimeCustodyListingRecord,
    principal_id: &'a str,
    profile_did: &'a str,
    mint_id: Digest32,
    purchase: &'a RuntimeCustodyPurchaseRecord,
    proof_binding_id: &'a str,
    session_id: &'a str,
    grant_id: &'a str,
    runtime_session_binding: RuntimeSessionBindingV1,
    buy: &'a elastos_protected_content_runtime::RuntimeBuyReceipt,
    draft: &'a RuntimeMintDraft,
    resolved: elastos_protected_content_runtime::ResolvedPoolV1,
    own_node_keys: Vec<NodePublicKey>,
    /// A pending pool record whose delivery entry is live.
    resumed: Option<RuntimeCustodyViewerRecord>,
}

/// Plan B T4.4: opens the viewer through the item's pool. The checks above
/// it in [`open_runtime_custody_viewer`] stay as they are; this replaces the
/// composition load, the local recipient, the V1 release and the local
/// session. Any failure settles the record, which drops the delivery secret.
async fn open_runtime_custody_pool_viewer(
    input: RuntimeCustodyPoolOpenInput<'_>,
) -> anyhow::Result<Value> {
    // S4-R4-F3: the public issuer only; each signature loads the device key
    // for its call and drops it.
    let runtime_issuer = crate::protected_content_pool_open::device_issuer_of(
        &load_runtime_pool_device_signing_key(input.data_dir)?,
    )?;
    let now = crate::auth::now_ts();
    let binding = input
        .buy
        .binding_for_session(input.runtime_session_binding)
        .map_err(release_unavailable!())?;
    let (record, audit_request_id, resume) = match input.resumed {
        Some(record) => {
            let pending = record
                .pending_release
                .clone()
                .ok_or_else(release_unavailable_missing!())?;
            let sessions = pending
                .pool
                .clone()
                .ok_or_else(release_unavailable_missing!())?;
            let audit_request_id = RuntimeReleaseAuditIdV1::new(record.audit_request_id()?)
                .map_err(release_unavailable!())?;
            let resume = crate::protected_content_pool_open::PoolResume {
                wallet_request: pending.wallet_request()?,
                sessions,
            };
            (record, audit_request_id, Some(resume))
        }
        None => {
            let audit_request_id = runtime_open_audit_id(input.principal_id, input.mint_id, now);
            let mut handle = [0u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
            rand::rngs::OsRng.fill_bytes(&mut handle);
            let mut record =
                RuntimeCustodyViewerRecord::from_open_pending(RuntimeCustodyOpenPendingInput {
                    principal_id: input.principal_id,
                    profile_did: input.profile_did,
                    mint_id: input.mint_id,
                    content_id: &input.purchase.content_id,
                    runtime_session_binding: input.runtime_session_binding,
                    audit_request_id: audit_request_id.digest(),
                    viewer_session_handle: handle,
                    expires_at: now + RUNTIME_CUSTODY_OPEN_APPROVAL_WINDOW_SECS,
                    now,
                })?;
            // Marks the record as a pool viewer from its first write, so a
            // crash before the Wallet answers settles without local decrypt.
            record.pool = Some(crate::protected_content_pool_open::PoolViewerSessions::new(
                &[],
                &[],
            ));
            persist_runtime_custody_viewer_record(
                input.data_dir,
                input.principal_id,
                input.mint_id,
                &record,
            )?;
            (record, audit_request_id, None)
        }
    };
    let handle = record.viewer_session_handle_bytes()?;
    let approval_expires_at = record.expires_at;
    let ports = RuntimePoolOpenPorts {
        data_dir: input.data_dir,
        registry: input.registry.clone(),
        principal_id: input.principal_id,
        mint_id: input.mint_id,
        purchase: input.purchase,
        proof_binding_id: input.proof_binding_id,
        session_id: input.session_id,
        grant_id: input.grant_id,
        runtime_session_binding: input.runtime_session_binding,
        draft: input.draft,
        resolved: &input.resolved,
        own_node_keys: &input.own_node_keys,
        kept_card_tickets: crate::custody_pool_setup::kept_card_tickets(input.data_dir),
        runtime_issuer,
        record: std::sync::Mutex::new(record.clone()),
        diagnostics: RuntimeCustodyCallDiagnostics::default(),
    };
    // S4-F2: the request-scoped client over this call's registry.
    let sessions = elastos_protected_content_runtime::PoolSessionClient::new(
        crate::custody_pool_resolver::RegistryPoolSessionTransport::new(
            input.data_dir,
            input.registry.clone(),
        ),
    );
    let outcome = crate::protected_content_pool_open::open_pool_viewer(
        crate::protected_content_pool_open::PoolOpenContext {
            resolved: &input.resolved,
            own_node_keys: &input.own_node_keys,
            binding,
            action: input.buy.action(),
            content: crate::protected_content_pool_open::pool_content_ref(
                &input.purchase.cid,
                input.draft,
            ),
            audit_request_id,
            handle,
            approval_expires_at,
            resume,
            now,
        },
        &sessions,
        &ports,
        crate::protected_content_pool_open::PoolDeliveryKeys::global(),
    )
    .await;
    let settle = |record: RuntimeCustodyViewerRecord| {
        settle_runtime_custody_viewer_cleanup(
            input.data_dir,
            input.registry.clone(),
            input.listing,
            input.principal_id,
            input.mint_id,
            record,
        )
    };
    match outcome {
        Ok(crate::protected_content_pool_open::PoolOpenOutcome::Opened(opened)) => {
            let pending = ports
                .record
                .lock()
                .map_err(|_| anyhow::anyhow!("Runtime custody viewer session is unavailable"))?
                .clone();
            let active = RuntimeCustodyViewerRecord::from_pool_opened(
                &pending,
                &opened,
                crate::auth::now_ts(),
            );
            if let Err(error) = persist_runtime_custody_viewer_record(
                input.data_dir,
                input.principal_id,
                input.mint_id,
                &active,
            ) {
                let _ = settle(active).await;
                return Err(error);
            }
            runtime_custody_pool_viewer_response(
                input.draft.content_identity(),
                input.mint_id,
                &opened,
            )
        }
        Ok(crate::protected_content_pool_open::PoolOpenOutcome::PendingApproval(progress)) => {
            tracing::debug!(
                stage = progress.stage_label(),
                awaits_person = progress.awaits_person(),
                "runtime custody open: pool release awaits the Wallet"
            );
            Err(anyhow::Error::new(progress)
                .context(format!("{}:{}", file!(), line!()))
                .context(RUNTIME_CUSTODY_OPEN_PENDING_MESSAGE))
        }
        Err(error) => {
            let latest = ports
                .record
                .lock()
                .map(|record| record.clone())
                .unwrap_or(record);
            let _ = settle(latest).await;
            Err(error)
        }
    }
}

/// The device signing key for one signature of a pool open (S4-R4-F3),
/// through the identity load the V1 open uses; the caller drops it.
fn load_runtime_pool_device_signing_key(
    data_dir: &Path,
) -> anyhow::Result<ed25519_dalek::SigningKey> {
    let (device_key, _) =
        crate::collaboration_profile_authority::load_existing_device_signing_key(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    Ok(device_key)
}

/// This Home's side of a pool open (Plan B T4.4): the Wallet, the rights
/// policy, device signing, the V2 release over the descriptor's routes, the
/// chain for F9 and the viewer record. It keeps no device key.
struct RuntimePoolOpenPorts<'a> {
    data_dir: &'a Path,
    registry: Arc<ProviderRegistry>,
    principal_id: &'a str,
    mint_id: Digest32,
    purchase: &'a RuntimeCustodyPurchaseRecord,
    proof_binding_id: &'a str,
    session_id: &'a str,
    grant_id: &'a str,
    runtime_session_binding: RuntimeSessionBindingV1,
    draft: &'a RuntimeMintDraft,
    resolved: &'a elastos_protected_content_runtime::ResolvedPoolV1,
    own_node_keys: &'a [NodePublicKey],
    /// The tickets of the member cards this Home kept (a pool member).
    kept_card_tickets: crate::custody_pool_resolver::KeptCardTickets,
    /// Public only; no device key is kept (S4-R4-F3).
    runtime_issuer: RuntimeOperationIssuerKeyV1,
    record: std::sync::Mutex<RuntimeCustodyViewerRecord>,
    diagnostics: RuntimeCustodyCallDiagnostics,
}

impl RuntimePoolOpenPorts<'_> {
    /// One adapter per epoch node, routed by the descriptor: this Home's
    /// own node in process, others over Carrier (ticket, else peer DID).
    fn epoch_adapters(
        &self,
    ) -> anyhow::Result<Vec<(NodePublicKey, RuntimeCustodyRegistryAdapter)>> {
        self.resolved
            .epoch
            .signed_epoch()
            .statement()
            .nodes()
            .iter()
            .map(|node| {
                let key = node.node_public_key();
                let member = self
                    .resolved
                    .descriptor
                    .member(key)
                    .ok_or_else(release_unavailable_missing!())?;
                Ok((
                    key,
                    RuntimeCustodyRegistryAdapter::new(
                        self.registry.clone(),
                        crate::protected_content_pool_open::epoch_node_transport(
                            member,
                            self.own_node_keys,
                            &self.kept_card_tickets,
                        ),
                        self.diagnostics.clone(),
                    ),
                ))
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl crate::protected_content_pool_open::PoolOpenPorts for RuntimePoolOpenPorts<'_> {
    fn device_issuer(&self) -> anyhow::Result<RuntimeOperationIssuerKeyV1> {
        crate::protected_content_pool_open::device_issuer_of(&load_runtime_pool_device_signing_key(
            self.data_dir,
        )?)
    }

    fn sign_release_operation_v2(
        &self,
        statement: elastos_protected_content_contracts::RuntimeReleaseOperationStatementV2,
    ) -> anyhow::Result<elastos_protected_content_contracts::SignedRuntimeReleaseOperationV2> {
        crate::protected_content_pool_open::sign_release_operation_v2_with(
            &load_runtime_pool_device_signing_key(self.data_dir)?,
            statement,
        )
    }

    fn sign_terminal_receipt_v2(
        &self,
        operation: &elastos_protected_content_contracts::AuthenticatedRuntimeReleaseOperationV2,
        server_contributions: &[elastos_protected_content_contracts::SignedNodeContributionV1],
        recipient: &RecipientKeyIdentityV1,
        now: u64,
    ) -> anyhow::Result<SignedTerminalReceiptV1> {
        crate::protected_content_pool_open::sign_terminal_receipt_v2_with(
            &load_runtime_pool_device_signing_key(self.data_dir)?,
            operation,
            server_contributions,
            recipient,
            now,
        )
    }

    async fn sign_rights(
        &self,
        fresh: Option<&RightsRequestV2>,
        replay: Option<&[u8]>,
        expected: crate::protected_content_pool_open::RightsRequestCheck<'_>,
        now: u64,
    ) -> anyhow::Result<crate::protected_content_pool_open::PoolWalletAnswer> {
        let invocation = RuntimeReleaseWalletInvocation {
            principal_id: self.principal_id,
            account_id: &self.purchase.account_id,
            proof_binding_id: self.proof_binding_id,
            session_id: self.session_id,
            grant_id: self.grant_id,
            mint_id: self.mint_id,
            runtime_session_binding: self.runtime_session_binding,
        };
        let fresh = fresh.cloned().map(RightsRequestAnyV1::V2);
        let answer = invoke_runtime_release_wallet_any(
            self.registry.as_ref(),
            || fresh.ok_or_else(release_unavailable_missing!()),
            |request| expected(request),
            &invocation,
            replay,
            now,
        )
        .await?;
        match answer {
            RuntimeReleaseWalletAnyOutcome::Signed {
                request_bytes,
                response_bytes,
                signed_rights,
            } => match *signed_rights {
                WalletSignedRightsRequestAnyV1::V2(signed_rights) => Ok(
                    crate::protected_content_pool_open::PoolWalletAnswer::Signed {
                        request_bytes,
                        response_bytes,
                        signed_rights: Box::new(signed_rights),
                    },
                ),
                WalletSignedRightsRequestAnyV1::V1(_) => Err(release_unavailable!()(
                    "wallet signed a local rights request for a pool open",
                )),
            },
            RuntimeReleaseWalletAnyOutcome::PendingApproval {
                request_bytes,
                approval_request_id,
                external_signer,
                connector_id,
            } => Ok(
                crate::protected_content_pool_open::PoolWalletAnswer::PendingApproval {
                    request_bytes,
                    approval_request_id,
                    external_signer,
                    connector_id,
                },
            ),
        }
    }

    async fn rights_policy(&self) -> anyhow::Result<(RightsPolicyBodyV1, RightsPolicyIdentityV1)> {
        let policy = resolve_runtime_rights_policy(
            self.registry.as_ref(),
            self.draft.encrypted_content(),
            self.draft.content_access_id(),
            RightsActionV1::View,
        )
        .await
        .map_err(|_| anyhow::anyhow!("Runtime custody rights policy is unavailable"))?;
        Ok((policy.body().clone(), policy.identity().clone()))
    }

    async fn release(
        &self,
        wallet_request: &[u8],
        wallet_response: &[u8],
        operation: &elastos_protected_content_contracts::SignedRuntimeReleaseOperationV2,
        now: u64,
    ) -> anyhow::Result<RuntimeReleaseCoordinatorOutcome> {
        let adapters = self.epoch_adapters()?;
        let selected = adapters
            .iter()
            .map(|(key, adapter)| RuntimeSelectedProvider::new(*key, adapter, adapter))
            .collect();
        let coordinator = RuntimeReleaseCoordinator::new(
            runtime_release_journal(self.data_dir),
            self.runtime_issuer,
            selected,
        )
        .map_err(release_unavailable!())?
        .with_response_clock(crate::auth::now_ts);
        coordinator
            .release(
                wallet_request,
                wallet_response,
                RuntimeReleaseOperationAnyV1::from(operation.clone()),
                now,
            )
            .await
            .map_err(|error| {
                release_unavailable!()(format!(
                    "pool release failed: {error:?}{}",
                    runtime_custody_reported_by_nodes(&self.diagnostics)
                ))
            })
    }

    async fn resume_release(
        &self,
        operation_hash: Digest32,
        now: u64,
    ) -> anyhow::Result<RuntimeReleaseCoordinatorOutcome> {
        let adapters = self.epoch_adapters()?;
        let selected = adapters
            .iter()
            .map(|(key, adapter)| RuntimeSelectedProvider::new(*key, adapter, adapter))
            .collect();
        let coordinator = RuntimeReleaseCoordinator::new(
            runtime_release_journal(self.data_dir),
            self.runtime_issuer,
            selected,
        )
        .map_err(release_unavailable!())?
        .with_response_clock(crate::auth::now_ts);
        coordinator
            .resume_exact(operation_hash, now.max(crate::auth::now_ts()))
            .await
            .map_err(|error| {
                release_unavailable!()(format!("pool release resume failed: {error:?}"))
            })
    }

    async fn rights_denied_verdict(
        &self,
        now: u64,
    ) -> crate::protected_content_pool_open::RightsDeniedVerdict {
        use crate::protected_content_pool_open::{
            rights_denied_class, RightsDeniedClass, RightsDeniedVerdict,
        };
        let request_id = format!("open-pool-denied:{}", hex::encode(self.mint_id.as_bytes()));
        let read = |block| {
            runtime_custody_access_at(
                self.registry.as_ref(),
                &self.purchase.network,
                &self.purchase.address,
                self.draft.content_access_id(),
                &request_id,
                block,
            )
        };
        let finalized = read("finalized").await;
        let latest = read("latest").await;
        match rights_denied_class(finalized, latest) {
            RightsDeniedClass::Finalizing => {
                let confirmed_at = match &self.purchase.progress {
                    RuntimeCustodyPurchaseProgress::Complete { terminal } => terminal.confirmed_at,
                    _ => now,
                };
                let expected =
                    confirmed_at.saturating_add(RUNTIME_CUSTODY_EXPECTED_FINALITY_LAG_SECS);
                RightsDeniedVerdict::Finalizing(RuntimeCustodyOpenProgress::finalizing(
                    expected.max(now.saturating_add(60)),
                ))
            }
            RightsDeniedClass::Denied => RightsDeniedVerdict::Denied,
            RightsDeniedClass::Unavailable => RightsDeniedVerdict::Unavailable,
        }
    }

    fn persist_pending(
        &self,
        pending: &crate::protected_content_pool_open::PoolPendingRelease,
    ) -> anyhow::Result<()> {
        let mut record = self
            .record
            .lock()
            .map_err(|_| anyhow::anyhow!("Runtime custody viewer session is unavailable"))?;
        record.pending_release = Some(RuntimeCustodyPendingRelease::pool(pending));
        record.updated_at = crate::auth::now_ts();
        persist_runtime_custody_viewer_record(
            self.data_dir,
            self.principal_id,
            self.mint_id,
            &record,
        )
    }
}

/// The published content an open has fetched and verified, owned for the
/// lifetime of `open_runtime_custody_viewer`.
///
/// Only the framed HEADER of an object is retained: that is all
/// `RuntimeOpenViewerContentV1::Object` needs, and a framed object can be tens
/// of megabytes.
enum RuntimeCustodyOpenContent {
    Media {
        media_identity: CencFmp4MediaIdentityV1,
        protected_init: Vec<u8>,
    },
    Object {
        object_identity: ChunkedPayloadObjectIdentityV1,
        framed_header: Vec<u8>,
    },
    MediaDash {
        media_identity_v2: CencDashMediaIdentityV2,
        protected_init_segments: Vec<Vec<u8>>,
    },
}

impl RuntimeCustodyOpenContent {
    fn as_open_viewer_content(&self) -> RuntimeOpenViewerContentV1<'_> {
        match self {
            Self::Media {
                media_identity,
                protected_init,
            } => RuntimeOpenViewerContentV1::Media {
                media_identity,
                protected_init_segment: protected_init,
            },
            Self::Object {
                object_identity,
                framed_header,
            } => RuntimeOpenViewerContentV1::Object {
                object_identity,
                framed_header,
            },
            Self::MediaDash {
                media_identity_v2,
                protected_init_segments,
            } => RuntimeOpenViewerContentV1::MediaDash {
                media_identity_v2,
                protected_init_segments,
            },
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn read_runtime_custody_viewer(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    principal_id: &str,
    mint_id_hex: &str,
    handle_hex: &str,
    executable_actor: &str,
    launch_id: Option<&str>,
    proof_binding_id: Option<&str>,
    session_id: Option<&str>,
    grant_id: Option<&str>,
    segment_index: Option<u32>,
    chunk_index: Option<u32>,
) -> anyhow::Result<Value> {
    let mint_id = parse_mint_id_hex(mint_id_hex)?;
    let _viewer_lifecycle_guard =
        acquire_runtime_custody_viewer_lifecycle_guard(data_dir, principal_id, mint_id).await;
    let handle = parse_viewer_handle_hex(handle_hex)?;
    let purchase = load_runtime_custody_purchase(data_dir, principal_id, mint_id)?
        .ok_or_else(|| anyhow::anyhow!("Runtime custody viewer session is unavailable"))?;
    if purchase.principal_id != principal_id {
        anyhow::bail!("Runtime custody viewer session is unavailable");
    }
    let profile_did = load_runtime_custody_profile_did(data_dir, principal_id)?;
    let listing = load_runtime_custody_listing(data_dir, mint_id)?
        .ok_or_else(|| anyhow::anyhow!("Runtime custody viewer session is unavailable"))?;
    let asset = validate_runtime_custody_viewer_asset(
        &listing,
        principal_id,
        &profile_did,
        mint_id,
        &purchase,
    )?;
    let runtime_session_binding = require_runtime_custody_session_binding(
        principal_id,
        &profile_did,
        executable_actor,
        launch_id,
        proof_binding_id,
        session_id,
        grant_id,
        mint_id,
        "Runtime custody viewer session is unavailable",
    )?;
    // Kind dispatch above every lifecycle shortcut. Each kind names its parts
    // with its OWN selector, and the other kind's selector is refused rather
    // than accepted-and-ignored: a media read must not carry `chunk_index`, an
    // object read must not carry `segment_index`, and an object read must name
    // the chunk it wants (there is no object analogue of media's
    // "no segment_index means the init segment" default).
    let content_selector = match (&asset.content_identity, segment_index, chunk_index) {
        (RuntimeContentIdentityV1::Media(media_identity), _, None) => {
            RuntimeCustodyViewerReadSelector::Media {
                media_identity,
                segment_index,
            }
        }
        (RuntimeContentIdentityV1::Object(object_identity), None, Some(chunk_index)) => {
            RuntimeCustodyViewerReadSelector::Object {
                object_identity,
                chunk_index,
            }
        }
        (RuntimeContentIdentityV1::MediaDash(head), _, None) => {
            RuntimeCustodyViewerReadSelector::MediaDash {
                head,
                segment_index,
            }
        }
        (RuntimeContentIdentityV1::Media(_), _, Some(_))
        | (RuntimeContentIdentityV1::Object(_), Some(_), _)
        | (RuntimeContentIdentityV1::Object(_), None, None)
        | (RuntimeContentIdentityV1::MediaDash(_), _, Some(_)) => {
            anyhow::bail!("Runtime custody viewer session is unavailable")
        }
    };
    let mut record = load_runtime_custody_viewer_record(data_dir, principal_id, mint_id)?
        .ok_or_else(|| anyhow::anyhow!("Runtime custody viewer session is unavailable"))?;
    if !record.validates_authority_identity(
        principal_id,
        &profile_did,
        mint_id,
        &purchase.content_id,
    ) || !record.matches_runtime_session_binding(&runtime_session_binding)
        || record.viewer_session_handle != hex::encode(handle)
    {
        anyhow::bail!("Runtime custody viewer session is unavailable");
    }
    let now = crate::auth::now_ts();
    // Plan B T4.5: an Active pool viewer reads from its servers, and at the
    // session's end answers `pool_session_renewal_required` (C3). A pending
    // one settles below like any other.
    if record.is_pool() && record.lifecycle_status == RuntimeCustodyViewerLifecycleStatus::Active {
        return read_runtime_custody_pool_part(RuntimeCustodyPoolReadInput {
            data_dir,
            registry,
            listing: &listing,
            principal_id,
            mint_id,
            handle,
            handle_hex,
            record,
            selector: content_selector,
            now,
        })
        .await;
    }
    let session = match record.lifecycle_status {
        RuntimeCustodyViewerLifecycleStatus::Active if !record.is_expired(now) => {
            record.to_runtime_viewer_session(asset.content_identity.encrypted_content())?
        }
        RuntimeCustodyViewerLifecycleStatus::OpenPending
        | RuntimeCustodyViewerLifecycleStatus::Active
        | RuntimeCustodyViewerLifecycleStatus::CleanupPending => {
            let _ = settle_runtime_custody_viewer_cleanup(
                data_dir,
                registry.clone(),
                &listing,
                principal_id,
                mint_id,
                record,
            )
            .await?;
            anyhow::bail!("Runtime custody viewer session is unavailable");
        }
        RuntimeCustodyViewerLifecycleStatus::Closed
        | RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent => {
            anyhow::bail!("Runtime custody viewer session is unavailable");
        }
    };
    let decrypt = RuntimeDecryptRegistryAdapter::new(registry.clone());
    let response = match content_selector {
        RuntimeCustodyViewerReadSelector::Media {
            media_identity,
            segment_index,
        } => {
            record.require_media_part_index(segment_index)?;
            let selector = if let Some(segment_index) = segment_index {
                let path = protected_content_segment_path(usize::try_from(segment_index).map_err(
                    |_| anyhow::anyhow!("Runtime custody viewer media part is invalid"),
                )?);
                if usize::try_from(segment_index).ok()
                    >= Some(media_identity.encrypted_segments().len())
                {
                    anyhow::bail!("Runtime custody viewer media part is invalid");
                }
                let encrypted = crate::content::fetch_bytes_via_provider(
                    registry.as_ref(),
                    &purchase.cid,
                    Some(&path),
                )
                .await
                .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE))?;
                ViewerMediaPartSelectorV1::segment(segment_index, encrypted)
                    .map_err(|_| anyhow::anyhow!("Runtime custody viewer media part is invalid"))?
            } else {
                ViewerMediaPartSelectorV1::init()
            };
            let part = read_viewer_media_part(&decrypt, &session, selector, crate::auth::now_ts())
                .await
                .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE))?;
            runtime_custody_viewer_media_part_response(mint_id, handle_hex, part.clear_media_part())
        }
        RuntimeCustodyViewerReadSelector::MediaDash {
            head,
            segment_index,
        } => {
            // Mapped and checked before any fetch or provider call, like v1.
            let (rendition_index, segment) = record.require_media_dash_part(head, segment_index)?;
            let rendition = &head.renditions()[usize::from(rendition_index)];
            let selector = match segment {
                None => ViewerMediaPartSelectorV1::init_v2(rendition_index)
                    .map_err(|_| anyhow::anyhow!("Runtime custody viewer media part is invalid"))?,
                Some(segment) => {
                    let path = runtime_media_dash_segment_path(rendition.kind(), segment);
                    // The manifest check bounds the declared size at import, buy
                    // and open. This capped fetch is a second check only: the
                    // registry applies the range after loading the file, so it
                    // does not stop buffering. A longer file is refused before
                    // the decrypt provider is called.
                    let encrypted = crate::content::fetch_bytes_via_provider_capped(
                        registry.as_ref(),
                        &purchase.cid,
                        Some(&path),
                        MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2,
                    )
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE)
                    })?;
                    if encrypted.len() > MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2 {
                        tracing::warn!(
                            rendition_index,
                            segment,
                            "runtime custody read: published segment exceeds the protected segment cap"
                        );
                        anyhow::bail!("Runtime custody viewer media part is invalid");
                    }
                    let proof = runtime_custody_media_dash_proof(
                        data_dir,
                        principal_id,
                        mint_id,
                        head,
                        rendition_index,
                        segment,
                        registry.as_ref(),
                        &purchase.cid,
                    )
                    .await?;
                    ViewerMediaPartSelectorV1::segment_v2(
                        rendition_index,
                        segment,
                        encrypted,
                        proof,
                    )
                    .map_err(|_| anyhow::anyhow!("Runtime custody viewer media part is invalid"))?
                }
            };
            let part = read_viewer_media_part(&decrypt, &session, selector, crate::auth::now_ts())
                .await
                .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE))?;
            runtime_custody_viewer_media_part_response(mint_id, handle_hex, part.clear_media_part())
        }
        RuntimeCustodyViewerReadSelector::Object {
            object_identity,
            chunk_index,
        } => {
            record.require_object_chunk_index(chunk_index, object_identity.chunk_count())?;
            // Hand the decrypt provider exactly ONE framed chunk (~1 MiB +
            // tag), never the whole file: a provider frame carries the chunk
            // as a JSON integer array, so a 1 MiB chunk already costs roughly
            // 4 MiB of the 16 MiB frame ceiling.
            //
            // The chunk comes from the object this session staged at open,
            // read by seeking to its own range. Fetching and re-hashing the
            // whole object on every chunk is what made a thirteen-chunk read
            // take twenty-seven seconds while the decryption took one and a
            // half. Falling back to the fetch keeps a session that outlived
            // its staged file -- a Runtime restart -- working as before.
            let framed_chunk = runtime_custody_object_chunk_for_read(
                data_dir,
                registry.as_ref(),
                principal_id,
                mint_id,
                &purchase.cid,
                object_identity,
                chunk_index,
            )
            .await?;
            let chunk = read_viewer_object_chunk(
                &decrypt,
                &session,
                chunk_index,
                &framed_chunk,
                crate::auth::now_ts(),
            )
            .await
            .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE))?;
            runtime_custody_viewer_object_part_response(
                mint_id,
                handle_hex,
                chunk_index,
                chunk.plaintext(),
            )
        }
    };
    record.mark_media_part_read(crate::auth::now_ts())?;
    if persist_runtime_custody_viewer_record(data_dir, principal_id, mint_id, &record).is_err() {
        let _ = settle_runtime_custody_viewer_cleanup(
            data_dir,
            registry,
            &listing,
            principal_id,
            mint_id,
            record,
        )
        .await;
        anyhow::bail!("Runtime custody viewer session is unavailable");
    }
    Ok(response)
}

/// What one pool read is built from (Plan B T4.5).
struct RuntimeCustodyPoolReadInput<'a> {
    data_dir: &'a Path,
    registry: Arc<ProviderRegistry>,
    listing: &'a RuntimeCustodyListingRecord,
    principal_id: &'a str,
    mint_id: Digest32,
    handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    handle_hex: &'a str,
    record: RuntimeCustodyViewerRecord,
    selector: RuntimeCustodyViewerReadSelector<'a>,
    now: u64,
}

/// Plan B T4.5: one part of a pool viewer, in the public shape a local read
/// answers. The part index is checked against the record as the local read
/// does; the server fetches the ciphertext, so nothing is fetched here.
///
/// C3 (user 2026-11-13 04:45): at or after the session's end the record
/// settles and the read answers `pool_session_renewal_required`; the viewer
/// runs the open once. Before it, a server that gives no part is an
/// unavailable read that keeps the session, so nothing resets a budget,
/// issues a release or asks the Wallet early. A viewer with no delivery
/// secret here settles and answers the session as unavailable, and the next
/// open starts fresh.
async fn read_runtime_custody_pool_part(
    input: RuntimeCustodyPoolReadInput<'_>,
) -> anyhow::Result<Value> {
    let RuntimeCustodyPoolReadInput {
        data_dir,
        registry,
        listing,
        principal_id,
        mint_id,
        handle,
        handle_hex,
        mut record,
        selector,
        now,
    } = input;
    let (part, object) = match selector {
        RuntimeCustodyViewerReadSelector::Media {
            media_identity,
            segment_index,
        } => {
            record.require_media_part_index(segment_index)?;
            let part = match segment_index {
                None => ViewerPartIndexV1::MediaV1Init,
                Some(segment_index) => {
                    if usize::try_from(segment_index).ok()
                        >= Some(media_identity.encrypted_segments().len())
                    {
                        anyhow::bail!("Runtime custody viewer media part is invalid");
                    }
                    ViewerPartIndexV1::MediaV1Segment(segment_index)
                }
            };
            (part, None)
        }
        RuntimeCustodyViewerReadSelector::MediaDash {
            head,
            segment_index,
        } => {
            let (rendition, segment) = record.require_media_dash_part(head, segment_index)?;
            let part = match segment {
                None => ViewerPartIndexV1::DashInit { rendition },
                Some(index) => ViewerPartIndexV1::DashSegment { rendition, index },
            };
            (part, None)
        }
        RuntimeCustodyViewerReadSelector::Object {
            object_identity,
            chunk_index,
        } => {
            record.require_object_chunk_index(chunk_index, object_identity.chunk_count())?;
            (
                ViewerPartIndexV1::ObjectChunk(chunk_index),
                Some(chunk_index),
            )
        }
    };
    // S4-F2: the request-scoped client over this call's registry.
    let sessions = elastos_protected_content_runtime::PoolSessionClient::new(
        crate::custody_pool_resolver::RegistryPoolSessionTransport::new(data_dir, registry.clone()),
    );
    let clear = match crate::protected_content_pool_open::read_pool_viewer(
        &handle,
        part,
        &sessions,
        crate::protected_content_pool_open::PoolDeliveryKeys::global(),
        now,
    )
    .await
    {
        Ok(clear) => clear,
        Err(
            error @ (crate::protected_content_pool_open::PoolReadError::NoSecret
            | crate::protected_content_pool_open::PoolReadError::RenewalRequired),
        ) => {
            // The session's end, also for a record whose secret is gone.
            let ended = error == crate::protected_content_pool_open::PoolReadError::RenewalRequired
                || record.is_expired(now);
            let _ = settle_runtime_custody_viewer_cleanup(
                data_dir,
                registry,
                listing,
                principal_id,
                mint_id,
                record,
            )
            .await;
            if ended {
                tracing::debug!("runtime custody viewer: the pool session reached its end");
                return Err(RuntimeCustodyPoolSessionRenewalRequired::error());
            }
            anyhow::bail!("Runtime custody viewer session is unavailable");
        }
        Err(
            crate::protected_content_pool_open::PoolReadError::ServerLost
            | crate::protected_content_pool_open::PoolReadError::Invalid,
        ) => anyhow::bail!(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE),
    };
    let response = match object {
        Some(chunk_index) => runtime_custody_viewer_object_part_response(
            mint_id,
            handle_hex,
            chunk_index,
            clear.as_slice(),
        ),
        None => runtime_custody_viewer_media_part_response(mint_id, handle_hex, clear.as_slice()),
    };
    record.mark_media_part_read(crate::auth::now_ts())?;
    if persist_runtime_custody_viewer_record(data_dir, principal_id, mint_id, &record).is_err() {
        let _ = settle_runtime_custody_viewer_cleanup(
            data_dir,
            registry,
            listing,
            principal_id,
            mint_id,
            record,
        )
        .await;
        anyhow::bail!("Runtime custody viewer session is unavailable");
    }
    Ok(response)
}

/// Which part of which content kind one `read_viewer` call names, after the
/// caller's two selectors have been checked against the session's actual
/// content kind.
enum RuntimeCustodyViewerReadSelector<'a> {
    Media {
        media_identity: &'a CencFmp4MediaIdentityV1,
        /// `None` is media's init segment, exactly as before.
        segment_index: Option<u32>,
    },
    Object {
        object_identity: &'a ChunkedPayloadObjectIdentityV1,
        chunk_index: u32,
    },
    MediaDash {
        head: &'a CencDashMediaIdentityV2,
        /// `None` is an init, exactly as for media.
        segment_index: Option<u32>,
    },
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn close_runtime_custody_viewer(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    principal_id: &str,
    mint_id_hex: &str,
    handle_hex: &str,
    executable_actor: &str,
    launch_id: Option<&str>,
    proof_binding_id: Option<&str>,
    session_id: Option<&str>,
    grant_id: Option<&str>,
) -> anyhow::Result<Value> {
    let mint_id = parse_mint_id_hex(mint_id_hex)?;
    let _viewer_lifecycle_guard =
        acquire_runtime_custody_viewer_lifecycle_guard(data_dir, principal_id, mint_id).await;
    let handle = parse_viewer_handle_hex(handle_hex)?;
    let purchase = load_runtime_custody_purchase(data_dir, principal_id, mint_id)?
        .ok_or_else(|| anyhow::anyhow!("Runtime custody viewer session is unavailable"))?;
    if purchase.principal_id != principal_id {
        anyhow::bail!("Runtime custody viewer session is unavailable");
    }
    let profile_did = load_runtime_custody_profile_did(data_dir, principal_id)?;
    let listing = load_runtime_custody_listing(data_dir, mint_id)?
        .ok_or_else(|| anyhow::anyhow!("Runtime custody viewer session is unavailable"))?;
    let asset = validate_runtime_custody_viewer_asset(
        &listing,
        principal_id,
        &profile_did,
        mint_id,
        &purchase,
    )?;
    let runtime_session_binding = require_runtime_custody_session_binding(
        principal_id,
        &profile_did,
        executable_actor,
        launch_id,
        proof_binding_id,
        session_id,
        grant_id,
        mint_id,
        "Runtime custody viewer session is unavailable",
    )?;
    let mut record = load_runtime_custody_viewer_record(data_dir, principal_id, mint_id)?
        .ok_or_else(|| anyhow::anyhow!("Runtime custody viewer session is unavailable"))?;
    if !record.validates_authority_identity(
        principal_id,
        &profile_did,
        mint_id,
        &purchase.content_id,
    ) || !record.matches_runtime_session_binding(&runtime_session_binding)
        || record.viewer_session_handle != hex::encode(handle)
    {
        anyhow::bail!("Runtime custody viewer session is unavailable");
    }
    let result = match record.lifecycle_status {
        RuntimeCustodyViewerLifecycleStatus::Closed
        | RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent => None,
        RuntimeCustodyViewerLifecycleStatus::OpenPending
        | RuntimeCustodyViewerLifecycleStatus::CleanupPending => {
            let settled = settle_runtime_custody_viewer_cleanup(
                data_dir,
                registry.clone(),
                &listing,
                principal_id,
                mint_id,
                record.clone(),
            )
            .await?;
            Some(match settled.lifecycle_status {
                RuntimeCustodyViewerLifecycleStatus::Closed => {
                    RuntimeViewerSessionCloseResult::Closed
                }
                RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent => {
                    RuntimeViewerSessionCloseResult::AlreadyAbsent
                }
                _ => anyhow::bail!(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE),
            })
        }
        // Plan B T4.5: a pool viewer ends its server sessions and drops its
        // delivery secret; this Home's decrypt provider is not involved.
        RuntimeCustodyViewerLifecycleStatus::Active if record.is_pool() => {
            Some(runtime_custody_close_pool_viewer(data_dir, &registry, &handle).await)
        }
        RuntimeCustodyViewerLifecycleStatus::Active => {
            let session =
                record.to_runtime_viewer_session(asset.content_identity.encrypted_content())?;
            Some(
                match close_viewer_session_with_result(
                    &RuntimeDecryptRegistryAdapter::new(registry),
                    &session,
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        record.mark_cleanup_pending(crate::auth::now_ts());
                        persist_runtime_custody_viewer_record(
                            data_dir,
                            principal_id,
                            mint_id,
                            &record,
                        )?;
                        anyhow::bail!(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE);
                    }
                },
            )
        }
    };
    let close_result = if let Some(result) = result {
        record.mark_terminal(result, crate::auth::now_ts());
        RuntimeCustodyViewerRecord::release_staged_object(data_dir, principal_id, mint_id);
        persist_runtime_custody_viewer_record(data_dir, principal_id, mint_id, &record)?;
        result
    } else {
        RuntimeViewerSessionCloseResult::AlreadyAbsent
    };
    Ok(json!({
        "schema": "elastos.library.runtime-custody-viewer/v1",
        "mint_id": hex::encode(mint_id.as_bytes()),
        "closed": true,
        "close_result": match close_result {
            RuntimeViewerSessionCloseResult::Closed => "closed",
            RuntimeViewerSessionCloseResult::AlreadyAbsent => "already_absent",
        },
    }))
}

pub(crate) fn persist_runtime_custody_listing(
    data_dir: &Path,
    record: &RuntimeCustodyListingRecord,
) -> anyhow::Result<()> {
    write_owner_only_bytes(
        &runtime_listing_path(data_dir, parse_mint_id_hex(&record.package.mint_id)?),
        &serde_json::to_vec(record)?,
    )
}

pub(crate) fn load_runtime_custody_listing(
    data_dir: &Path,
    mint_id: Digest32,
) -> anyhow::Result<Option<RuntimeCustodyListingRecord>> {
    let path = runtime_listing_path(data_dir, mint_id);
    if !path.exists() {
        return Ok(None);
    }
    let record: RuntimeCustodyListingRecord = serde_json::from_slice(&fs::read(path)?)
        .map_err(|_| anyhow::anyhow!("Runtime custody listing is invalid"))?;
    record.validate()?;
    Ok(Some(record))
}

pub(crate) fn runtime_custody_creator_listing_package(
    data_dir: &Path,
    mint: &PersistedRuntimeMint,
    facts: &RuntimeCustodyLibraryPublishFacts,
    publisher_principal_id: &str,
    terminal: &RuntimeMintCreatorTerminalEvidence,
) -> anyhow::Result<RuntimePortableListingPackage> {
    let mint_id = mint.draft().mint_id();
    let availability = mint
        .content_availability()
        .ok_or_else(|| anyhow::anyhow!("Runtime custody listing is invalid"))?;
    let publisher_profile_did = load_runtime_custody_profile_did(data_dir, publisher_principal_id)?;
    if availability.publisher_identity() != publisher_profile_did {
        anyhow::bail!("Runtime custody listing is invalid");
    }
    let (media_identity_base64, content_identity_base64) =
        runtime_portable_identity_fields(mint.draft().content_identity())
            .map_err(|_| anyhow::anyhow!("Runtime custody listing is invalid"))?;
    // Plan B POOL-MINT (S7I-F2): a pool mint carries its share statement.
    let pool_mint_share_b64 =
        runtime_pool_mint_record(data_dir, mint_id)?.map(|record| record.mint_share_base64);
    Ok(RuntimePortableListingPackage {
        schema: RUNTIME_PORTABLE_LISTING_SCHEMA_V1.to_string(),
        mint_id: hex::encode(mint_id.as_bytes()),
        content_id: facts.content_id.clone(),
        content_access_id: format!(
            "0x{}",
            hex::encode(mint.draft().content_access_id().as_bytes())
        ),
        content_cid: facts.content_cid.clone(),
        metadata_cid: terminal.metadata_cid().to_string(),
        token_uri: terminal.token_uri().to_string(),
        publisher_profile_did,
        display_name: facts.display_name.clone(),
        media_identity_base64,
        content_identity_base64,
        key_envelope_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(mint.draft().key_envelope().canonical_bytes()?),
        rights_policy_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(mint.draft().policy().canonical_bytes()?),
        content_key_commitment_base64: base64::engine::general_purpose::STANDARD
            .encode(mint.draft().content_key_commitment().as_bytes()),
        quantity: terminal.quantity().to_string(),
        seller_address: terminal.seller().to_ascii_lowercase(),
        chain_namespace: terminal.chain_namespace().to_string(),
        network: terminal.network().to_string(),
        ledger: terminal.ledger().to_ascii_lowercase(),
        token_id: terminal.token_id().to_ascii_lowercase(),
        operative: terminal.operative().to_ascii_lowercase(),
        price: terminal.price().to_string(),
        pay_token: terminal.pay_token().to_ascii_lowercase(),
        payment_processor: terminal.payment_processor().map(str::to_ascii_lowercase),
        mint_transaction_hash: Some(terminal.transaction_hash().to_ascii_lowercase()),
        published_at: Some(terminal.published_at()),
        pool_mint_share_b64,
    })
}

/// The on-disk shape of an owned protected item: the `.ddrm` the Library shows
/// and the viewer opens.
pub(crate) const RUNTIME_CUSTODY_CAPSULE_SCHEMA_V1: &str =
    "elastos.library.protected-content-capsule/v1";

/// The document a `.ddrm` file contains.
///
/// It is the asset's own `metadata.json` -- the same document the token URI
/// resolves to -- with the handful of facts only the chain can supply raised to
/// the top level beside it: the authority governing the asset, its `kid`, the
/// `tokenId` minted on the ledger, the ledger itself, and the content type that
/// decides which viewer opens it.
///
/// Those five are lifted rather than left to readers to dig out, because they
/// are what every reader needs first and what `metadata.json` alone cannot
/// answer: a `tokenId` does not exist until the mint emits it, and an authority
/// may not have been configured when the metadata was written. The metadata is
/// carried whole rather than summarised, so a capsule is self-describing and
/// can be read without fetching anything.
///
/// `metadataUri` names where that document was published, so the embedded copy
/// can always be checked against the one the token URI resolves to.
pub(crate) fn runtime_custody_capsule_document(
    package: &RuntimePortableListingPackage,
    metadata: &Value,
    acquisition: RuntimeCustodyAcquisitionV1,
) -> Value {
    // Stated at mint time when the network had a market configured; otherwise
    // recovered afterwards from the gateway that emitted the mint's own
    // `ItemListed`, which IS the authority.
    let authority = metadata
        .get("properties")
        .and_then(|properties| properties.get("authority"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut capsule = serde_json::json!({
        "schema": RUNTIME_CUSTODY_CAPSULE_SCHEMA_V1,
        "authority": authority,
        "kid": package.content_access_id,
        "tokenId": package.token_id,
        "ledger": package.ledger,
        "contentType": runtime_custody_capsule_content_type(metadata),
        "operative": package.operative,
        "chainNamespace": package.chain_namespace,
        "network": package.network,
        "mintId": package.mint_id,
        "contentId": package.content_id,
        "contentCid": package.content_cid,
        "acquisition": acquisition,
        "metadataUri": format!("ipfs://{}", package.metadata_cid),
        "metadata": metadata,
    });
    // An adopted copy knows no mint transaction (D11); it says nothing rather
    // than stating one as `null`.
    if let Some(mint_transaction_hash) = &package.mint_transaction_hash {
        capsule["mintTransactionHash"] = Value::String(mint_transaction_hash.clone());
    }
    capsule
}

/// What the capsule protects, taken from the metadata document that describes
/// it.
///
/// `media.mimeType` is read first because that is where the MIME lives. In the
/// Elacity asset schema `media.contentType` is a category word -- Video, Audio,
/// Image, 3D Model, Document -- which a marketplace indexes on and which is
/// useless for deciding what this is. Older folders, and any that state only
/// one of the two, still answer through the fallback.
pub(crate) fn runtime_custody_capsule_content_type(metadata: &Value) -> String {
    let media = metadata.get("media");
    let mime = media
        .and_then(|media| media.get("mimeType"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !mime.is_empty() {
        return mime.to_string();
    }
    media
        .and_then(|media| media.get("contentType"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

pub(crate) fn persist_runtime_custody_creator_listing(
    data_dir: &Path,
    mint: &PersistedRuntimeMint,
    package: RuntimePortableListingPackage,
    publisher_principal_id: &str,
    listing_uri: String,
) -> anyhow::Result<()> {
    let mint_id = mint.draft().mint_id();
    let evidence = mint
        .content_availability()
        .ok_or_else(|| anyhow::anyhow!("Runtime custody listing is invalid"))?;
    let expected = RuntimeCustodyListingRecord {
        schema: RUNTIME_LISTING_SCHEMA_V1.to_string(),
        origin: RuntimeCustodyListingOrigin::LocalCreator {
            principal_id: publisher_principal_id.to_string(),
            package_sha256: hex::encode(sha2::Sha256::digest(serde_json::to_vec(&package)?)),
            listing_uri,
        },
        package,
        availability: RuntimeCustodyListingAvailabilitySummary::from_evidence(
            &evidence.clone().into(),
        ),
    };
    expected.validate()?;
    if let Some(existing) = load_runtime_custody_listing(data_dir, mint_id)? {
        if existing == expected {
            return Ok(());
        }
        anyhow::bail!("Runtime custody listing is invalid");
    }
    persist_runtime_custody_listing(data_dir, &expected)
}

/// Opens a purchase-ledger record file for read, refusing symlinks,
/// non-regular files, and hard-linked files — the same discipline
/// `open_runtime_media_source_file` applies to media source input.
///
/// A refused file is "invalid"; a file that could not be opened or examined
/// keeps its `io::Error` in the chain (R43), so a caller can tell a record
/// that is not one from a record it could not read.
#[cfg(unix)]
pub(crate) fn open_owner_only_runtime_record_file(path: &Path) -> anyhow::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = match options.open(path) {
        Ok(file) => file,
        // O_NOFOLLOW answers a symlink with ELOOP: a refusal, not a failure.
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(runtime_record_file_rejected(path))
        }
        Err(error) => return Err(runtime_record_file_unreadable(path, error)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| runtime_record_file_unreadable(path, error))?;
    if !(metadata.is_file() && metadata.nlink() == 1) {
        return Err(runtime_record_file_rejected(path));
    }
    Ok(file)
}

#[cfg(not(unix))]
pub(crate) fn open_owner_only_runtime_record_file(path: &Path) -> anyhow::Result<fs::File> {
    let file = fs::File::open(path).map_err(|error| runtime_record_file_unreadable(path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| runtime_record_file_unreadable(path, error))?;
    if !metadata.is_file() {
        return Err(runtime_record_file_rejected(path));
    }
    Ok(file)
}

fn runtime_record_file_rejected(path: &Path) -> anyhow::Error {
    tracing::warn!(path = %path.display(), "purchase ledger record rejected");
    anyhow::anyhow!("Runtime custody purchase is invalid")
}

fn runtime_record_file_unreadable(path: &Path, error: std::io::Error) -> anyhow::Error {
    tracing::warn!(
        path = %path.display(),
        %error,
        "purchase ledger record could not be read"
    );
    anyhow::Error::new(error).context("Runtime custody purchase is invalid")
}

pub(crate) fn load_runtime_custody_purchase(
    data_dir: &Path,
    principal_id: &str,
    mint_id: Digest32,
) -> anyhow::Result<Option<RuntimeCustodyPurchaseRecord>> {
    let path = runtime_purchase_path(data_dir, principal_id, mint_id);
    if !path.exists() {
        return Ok(None);
    }
    let mut file = open_owner_only_runtime_record_file(&path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let record: RuntimeCustodyPurchaseRecord = serde_json::from_slice(&bytes)?;
    if record.schema != RUNTIME_PURCHASE_SCHEMA_V1 || record.principal_id != principal_id {
        anyhow::bail!("Runtime custody purchase is invalid");
    }
    Ok(Some(record))
}

/// This principal's listing-package purchase (`buy`) of the item the chain
/// keys `(chain_namespace, ledger, token_id)` (D2), whatever its progress --
/// the record a market purchase of the same item must not race (R29).
///
/// Purchases are filed by mint, so this reads each of the principal's
/// records. One that does not parse or validate is skipped and logged: it is
/// not a purchase this Home can stand behind, and one broken file must not
/// stop every other purchase. One that cannot be READ is an error (R43): it
/// may be a purchase under way, and the caller refuses rather than start a
/// second one beside it.
pub(crate) fn load_runtime_custody_purchase_for_chain_item(
    data_dir: &Path,
    principal_id: &str,
    chain_namespace: &str,
    ledger: &str,
    token_id: &str,
) -> anyhow::Result<Option<RuntimeCustodyPurchaseRecord>> {
    let directory = runtime_purchase_lock_path(data_dir, principal_id)
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("Runtime custody purchase is invalid"))?;
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Some(mint_id) = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| parse_mint_id_hex(stem).ok())
        else {
            continue;
        };
        match load_runtime_custody_purchase(data_dir, principal_id, mint_id) {
            Ok(Some(record))
                if record.chain_namespace == chain_namespace
                    && record.ledger.eq_ignore_ascii_case(ledger)
                    && record.token_id.eq_ignore_ascii_case(token_id) =>
            {
                return Ok(Some(record));
            }
            Ok(_) => {}
            Err(error) => match error.downcast_ref::<std::io::Error>() {
                // Gone since the directory was listed: no purchase to find.
                Some(io) if io.kind() == std::io::ErrorKind::NotFound => {}
                Some(_) => return Err(error),
                None => tracing::warn!(
                    path = %path.display(),
                    error = %format!("{error:#}"),
                    "purchase ledger record invalid; skipped"
                ),
            },
        }
    }
    Ok(None)
}

fn validate_runtime_custody_viewer_asset(
    listing: &RuntimeCustodyListingRecord,
    principal_id: &str,
    profile_did: &str,
    mint_id: Digest32,
    purchase: &RuntimeCustodyPurchaseRecord,
) -> anyhow::Result<DecodedRuntimePortableAsset> {
    let package = &listing.package;
    let chain_id = package
        .chain_namespace
        .strip_prefix("eip155:")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE))?;
    let granted = purchase.acquisition == RuntimeCustodyAcquisitionV1::Granted;
    // A purchase is bound to the exact package it paid on. A granted copy
    // paid nothing and was offered on no terms, so it is bound to the item
    // and its content alone: a real listing that later replaces the granted
    // one (another person's purchase, or the creator's package) leaves it
    // opening. The KID is bound below, by the grant's own evidence.
    let terms_match = granted
        || (purchase.listing_sha256 == listing.portable_package_digest()
            && purchase
                .seller_address
                .eq_ignore_ascii_case(&package.seller_address)
            && purchase.price == package.price
            && purchase.pay_token.eq_ignore_ascii_case(&package.pay_token)
            && purchase
                .payment_processor
                .as_deref()
                .map(str::to_ascii_lowercase)
                == package
                    .payment_processor
                    .as_deref()
                    .map(str::to_ascii_lowercase));
    if purchase.schema != RUNTIME_PURCHASE_SCHEMA_V1
        || package.mint_id != hex::encode(mint_id.as_bytes())
        || purchase.principal_id != principal_id
        || purchase.profile_did != profile_did
        || purchase.mint_id != package.mint_id
        || purchase.content_id != package.content_id
        || purchase.cid != package.content_cid
        || !terms_match
        || purchase.chain_namespace != package.chain_namespace
        || purchase.network != package.network
        || !purchase.ledger.eq_ignore_ascii_case(&package.ledger)
        || !purchase.token_id.eq_ignore_ascii_case(&package.token_id)
        || !purchase.operative.eq_ignore_ascii_case(&package.operative)
        || purchase.acquisition_stage.chain_namespace != package.chain_namespace
        || purchase.acquisition_stage.network != package.network
    {
        anyhow::bail!(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE);
    }
    // A transaction-backed copy and a granted one each carry the chain's
    // access answer in their own state, and neither may pass for the other.
    let access_evidence = match &purchase.progress {
        RuntimeCustodyPurchaseProgress::Complete { terminal }
            if !granted && purchase.acquisition_stage.stage != RUNTIME_CUSTODY_GRANT_STAGE =>
        {
            terminal.access_evidence.as_ref()
        }
        RuntimeCustodyPurchaseProgress::Granted {
            access_evidence, ..
        } if granted && runtime_custody_grant_stage_is_empty(&purchase.acquisition_stage) => {
            Some(access_evidence)
        }
        _ => None,
    };
    // Nothing was ever bought on a granted listing's terms.
    if listing.origin.is_granted() && !granted {
        anyhow::bail!(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE);
    }
    let Some(access_evidence) = access_evidence else {
        anyhow::bail!(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE);
    };
    if !access_evidence.has_access
        || access_evidence.network != package.network
        || access_evidence.chain_id != chain_id
        || !access_evidence
            .wallet
            .eq_ignore_ascii_case(&purchase.address)
        || access_evidence.content_access_id.as_deref() != Some(package.content_access_id.as_str())
    {
        anyhow::bail!(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE);
    }
    package.decode_and_validate()
}

/// Test-only observability for the purchase-ledger lock: proves
/// `persist_runtime_custody_purchase` callers for the *same* lock path never
/// hold their critical section concurrently, without exposing anything from
/// production builds. Keyed by lock path so unrelated tests running in
/// parallel (distinct temp data dirs) cannot produce a false positive.
/// Compiled out entirely outside `cfg(test)`.
#[cfg(test)]
static RUNTIME_PURCHASE_LOCK_TEST_STATE: OnceLock<StdMutex<HashMap<PathBuf, (usize, bool)>>> =
    OnceLock::new();

#[cfg(test)]
fn runtime_purchase_lock_test_state() -> &'static StdMutex<HashMap<PathBuf, (usize, bool)>> {
    RUNTIME_PURCHASE_LOCK_TEST_STATE.get_or_init(|| StdMutex::new(HashMap::new()))
}

/// Held for the lifetime of one `persist_runtime_custody_purchase` critical
/// section. Records entry/exit against `path`'s holder count and latches
/// `true` if a second holder for the same path is ever observed while this
/// one is still live — the exact overlap `ExclusiveFileLock` must prevent.
/// The deliberate sleep widens the window: while this probe is alive the
/// real OS-level `flock` is held, so every other thread contending for the
/// same lock path is genuinely parked in the kernel, not merely lucky not to
/// race. That turns "no overlap ever observed" from a probabilistic outcome
/// into a deterministic one.
#[cfg(test)]
struct RuntimePurchaseLockTestProbe {
    path: PathBuf,
}

#[cfg(test)]
impl RuntimePurchaseLockTestProbe {
    fn enter(path: PathBuf) -> Self {
        {
            let mut state = runtime_purchase_lock_test_state()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let entry = state.entry(path.clone()).or_insert((0, false));
            entry.0 += 1;
            if entry.0 > 1 {
                entry.1 = true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        Self { path }
    }
}

#[cfg(test)]
impl Drop for RuntimePurchaseLockTestProbe {
    fn drop(&mut self) {
        let mut state = runtime_purchase_lock_test_state()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = state.get_mut(&self.path) {
            entry.0 -= 1;
        }
    }
}

#[cfg(test)]
pub(crate) fn runtime_purchase_lock_test_overlap_detected(path: &Path) -> bool {
    runtime_purchase_lock_test_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(path)
        .is_some_and(|(_, overlapped)| *overlapped)
}

pub(crate) fn persist_runtime_custody_purchase(
    data_dir: &Path,
    purchase: &RuntimeCustodyPurchaseRecord,
) -> anyhow::Result<()> {
    let lock_path = runtime_purchase_lock_path(data_dir, &purchase.principal_id);
    #[cfg(unix)]
    if let Some(parent) = lock_path.parent() {
        ensure_owner_only_runtime_storage_parent(parent)?;
    }
    #[cfg(not(unix))]
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _lock = ExclusiveFileLock::acquire(&lock_path)?;
    #[cfg(test)]
    let _lock_test_probe = RuntimePurchaseLockTestProbe::enter(lock_path.clone());
    write_owner_only_bytes(
        &runtime_purchase_path(
            data_dir,
            &purchase.principal_id,
            parse_mint_id_hex(&purchase.mint_id)?,
        ),
        &serde_json::to_vec(purchase)?,
    )
}

/// Record `purchase` only when this principal holds no record for its mint,
/// deciding under the purchase ledger lock. `Ok(false)` when a record --
/// a purchase under way, say -- was already there; it is left exactly as it
/// is.
pub(crate) fn create_runtime_custody_purchase_if_absent(
    data_dir: &Path,
    purchase: &RuntimeCustodyPurchaseRecord,
) -> anyhow::Result<bool> {
    let mint_id = parse_mint_id_hex(&purchase.mint_id)?;
    let lock_path = runtime_purchase_lock_path(data_dir, &purchase.principal_id);
    #[cfg(unix)]
    if let Some(parent) = lock_path.parent() {
        ensure_owner_only_runtime_storage_parent(parent)?;
    }
    #[cfg(not(unix))]
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _lock = ExclusiveFileLock::acquire(&lock_path)?;
    #[cfg(test)]
    let _lock_test_probe = RuntimePurchaseLockTestProbe::enter(lock_path.clone());
    if load_runtime_custody_purchase(data_dir, &purchase.principal_id, mint_id)?.is_some() {
        return Ok(false);
    }
    write_owner_only_bytes(
        &runtime_purchase_path(data_dir, &purchase.principal_id, mint_id),
        &serde_json::to_vec(purchase)?,
    )?;
    Ok(true)
}

/// Remove `attempt`'s listing-package purchase record, under the purchase
/// ledger lock, and only while the record on disk is still that attempt: a
/// `Pending` purchase of the same mint with the same buy effect, created at
/// the same moment. `Ok(false)` when the record is gone, complete, or another
/// attempt -- which is then left exactly as it is.
///
/// Only for an attempt that is provably over without payment (R41). The
/// caller holds the market-purchase lock around this, so the removal and
/// R29's cross-path check never interleave.
pub(crate) fn retire_runtime_custody_purchase_attempt(
    data_dir: &Path,
    attempt: &RuntimeCustodyPurchaseRecord,
) -> anyhow::Result<bool> {
    let mint_id = parse_mint_id_hex(&attempt.mint_id)?;
    let lock_path = runtime_purchase_lock_path(data_dir, &attempt.principal_id);
    #[cfg(unix)]
    if let Some(parent) = lock_path.parent() {
        ensure_owner_only_runtime_storage_parent(parent)?;
    }
    #[cfg(not(unix))]
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _lock = ExclusiveFileLock::acquire(&lock_path)?;
    #[cfg(test)]
    let _lock_test_probe = RuntimePurchaseLockTestProbe::enter(lock_path.clone());
    // The load refuses a symlink or a hard-linked file exactly as any read
    // does, so a retirement can never be pointed at anything but this record.
    match load_runtime_custody_purchase(data_dir, &attempt.principal_id, mint_id)? {
        Some(current)
            if matches!(
                current.progress,
                RuntimeCustodyPurchaseProgress::Pending { .. }
            ) && current.acquisition_stage.effect_id == attempt.acquisition_stage.effect_id
                && current.created_at == attempt.created_at => {}
        _ => return Ok(false),
    }
    let path = runtime_purchase_path(data_dir, &attempt.principal_id, mint_id);
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn load_runtime_custody_viewer_record(
    data_dir: &Path,
    principal_id: &str,
    mint_id: Digest32,
) -> anyhow::Result<Option<RuntimeCustodyViewerRecord>> {
    let path = runtime_viewer_path(data_dir, principal_id, mint_id);
    let Some(bytes) = load_runtime_custody_viewer_record_bytes(&path)? else {
        return Ok(None);
    };
    let record: RuntimeCustodyViewerRecord = serde_json::from_slice(&bytes)?;
    Ok(Some(record))
}

fn load_runtime_custody_viewer_record_from_path(
    path: &Path,
) -> anyhow::Result<Option<RuntimeCustodyViewerRecord>> {
    let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
        return Ok(None);
    };
    if extension != "json" {
        return Ok(None);
    }
    let Some(bytes) = load_runtime_custody_viewer_record_bytes(path)? else {
        return Ok(None);
    };
    let record: RuntimeCustodyViewerRecord = serde_json::from_slice(&bytes)?;
    Ok(Some(record))
}

fn load_runtime_custody_viewer_record_bytes(path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut reader = file.take(MAX_RUNTIME_VIEWER_RECORD_BYTES + 1);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RUNTIME_VIEWER_RECORD_BYTES {
        anyhow::bail!("Runtime custody viewer session is unavailable");
    }
    Ok(Some(bytes))
}

fn validate_runtime_custody_viewer_record_identity(
    data_dir: &Path,
    path: &Path,
    record: &RuntimeCustodyViewerRecord,
) -> anyhow::Result<(Digest32, RuntimeCustodyListingRecord)> {
    if record.schema != RUNTIME_VIEWER_SCHEMA_V1 {
        anyhow::bail!("viewer record schema is invalid");
    }
    let mint_id = parse_mint_id_hex(&record.mint_id)?;
    if runtime_viewer_path(data_dir, &record.principal_id, mint_id) != path {
        anyhow::bail!("viewer record path does not match its identities");
    }
    let purchase = load_runtime_custody_purchase(data_dir, &record.principal_id, mint_id)?
        .ok_or_else(|| anyhow::anyhow!("viewer record purchase is unavailable"))?;
    if purchase.principal_id != record.principal_id
        || purchase.profile_did != record.profile_did
        || purchase.content_id != record.content_id
    {
        anyhow::bail!("viewer record identities do not match the durable purchase");
    }
    let listing = load_runtime_custody_listing(data_dir, mint_id)?
        .ok_or_else(|| anyhow::anyhow!("viewer record listing is unavailable"))?;
    let asset = validate_runtime_custody_viewer_asset(
        &listing,
        &record.principal_id,
        &record.profile_did,
        mint_id,
        &purchase,
    )?;
    if runtime_protected_content_id(asset.content_identity.encrypted_content())?
        != record.content_id
    {
        anyhow::bail!("viewer record content does not match the durable mint");
    }
    let _ = record.audit_request_id()?;
    let _ = record.viewer_session_handle_bytes()?;
    if record.expires_at == 0 {
        anyhow::bail!("viewer record expiry is invalid");
    }
    // Media parts are the init segment plus one per encrypted segment;
    // object parts are chunks read strictly in order from 0, with no init
    // part, so the ceiling is the chunk count itself.
    let max_content_part_index = match &asset.content_identity {
        RuntimeContentIdentityV1::Media(media_identity) => {
            u32::try_from(media_identity.encrypted_segments().len())
                .map_err(|_| anyhow::anyhow!("viewer record media position is invalid"))?
                .saturating_add(1)
        }
        RuntimeContentIdentityV1::Object(object_identity) => object_identity.chunk_count(),
        RuntimeContentIdentityV1::MediaDash(head) => {
            runtime_media_dash_part_count(&runtime_media_dash_counts(head))
                .ok_or_else(|| anyhow::anyhow!("viewer record media position is invalid"))?
        }
    };
    if record.next_media_part_index > max_content_part_index {
        anyhow::bail!("viewer record media position is invalid");
    }
    if record.lifecycle_status != RuntimeCustodyViewerLifecycleStatus::OpenPending {
        let _ = record.to_runtime_viewer_session(asset.content_identity.encrypted_content())?;
    }
    Ok((mint_id, listing))
}

fn persist_runtime_custody_viewer_record(
    data_dir: &Path,
    principal_id: &str,
    mint_id: Digest32,
    record: &RuntimeCustodyViewerRecord,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(record)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RUNTIME_VIEWER_RECORD_BYTES {
        anyhow::bail!("Runtime custody viewer session is unavailable");
    }
    write_owner_only_bytes(
        &runtime_viewer_path(data_dir, principal_id, mint_id),
        &bytes,
    )
}

/// Plan B T4.5: closes a pool viewer's server sessions and drops its
/// delivery secret, as a local close result.
async fn runtime_custody_close_pool_viewer(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    handle: &[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
) -> RuntimeViewerSessionCloseResult {
    let sessions = elastos_protected_content_runtime::PoolSessionClient::new(
        crate::custody_pool_resolver::RegistryPoolSessionTransport::new(data_dir, registry.clone()),
    );
    match crate::protected_content_pool_open::close_pool_viewer(
        handle,
        &sessions,
        crate::protected_content_pool_open::PoolDeliveryKeys::global(),
    )
    .await
    {
        crate::protected_content_pool_open::PoolCloseResult::Closed => {
            RuntimeViewerSessionCloseResult::Closed
        }
        crate::protected_content_pool_open::PoolCloseResult::AlreadyAbsent => {
            RuntimeViewerSessionCloseResult::AlreadyAbsent
        }
    }
}

async fn settle_runtime_custody_viewer_cleanup(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    listing: &RuntimeCustodyListingRecord,
    principal_id: &str,
    mint_id: Digest32,
    mut record: RuntimeCustodyViewerRecord,
) -> anyhow::Result<RuntimeCustodyViewerRecord> {
    let purchase = load_runtime_custody_purchase(data_dir, principal_id, mint_id)?
        .ok_or_else(|| anyhow::anyhow!("Runtime custody viewer session is unavailable"))?;
    let asset = validate_runtime_custody_viewer_asset(
        listing,
        principal_id,
        &record.profile_did,
        mint_id,
        &purchase,
    )?;
    // Plan B T4.4/T4.5: a pool viewer holds nothing in this Home's decrypt
    // provider. It settles by `session.close` at its servers, which drops
    // its delivery secret; a server that does not answer keeps its session
    // only until the session's end.
    if record.is_pool() {
        let result = match record.viewer_session_handle_bytes() {
            Ok(handle) => runtime_custody_close_pool_viewer(data_dir, &registry, &handle).await,
            Err(_) => RuntimeViewerSessionCloseResult::AlreadyAbsent,
        };
        record.mark_terminal(result, crate::auth::now_ts());
        persist_runtime_custody_viewer_record(data_dir, principal_id, mint_id, &record)?;
        return Ok(record);
    }
    // Plan B T4.5: a Home with no ready decrypt target holds no local
    // session or recipient, so an old local record settles here as absent
    // and no longer blocks the next open, which goes through the pool.
    if !registry
        .has_ready_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)
        .await
    {
        tracing::debug!(
            "runtime custody viewer: no decrypt target; a local record settles as absent"
        );
        record.mark_terminal(
            RuntimeViewerSessionCloseResult::AlreadyAbsent,
            crate::auth::now_ts(),
        );
        RuntimeCustodyViewerRecord::release_staged_object(data_dir, principal_id, mint_id);
        persist_runtime_custody_viewer_record(data_dir, principal_id, mint_id, &record)?;
        return Ok(record);
    }
    let decrypt = RuntimeDecryptRegistryAdapter::new(registry);
    match record.lifecycle_status {
        RuntimeCustodyViewerLifecycleStatus::OpenPending => {
            let session =
                record.to_runtime_viewer_session(asset.content_identity.encrypted_content())?;
            let close_result = match record.open_pending_close_result() {
                Some(RuntimeCustodyOpenPendingCloseResult::Closed) => {
                    RuntimeViewerSessionCloseResult::Closed
                }
                Some(RuntimeCustodyOpenPendingCloseResult::AlreadyAbsent) => {
                    RuntimeViewerSessionCloseResult::AlreadyAbsent
                }
                None => {
                    let result = close_viewer_session_with_result(&decrypt, &session)
                        .await
                        .map_err(|_| {
                            anyhow::anyhow!(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE)
                        })?;
                    record.mark_open_pending_close_result(result, crate::auth::now_ts());
                    persist_runtime_custody_viewer_record(
                        data_dir,
                        principal_id,
                        mint_id,
                        &record,
                    )?;
                    result
                }
            };
            let cancel_result = match record.open_pending_cancel_result() {
                Some(RuntimeCustodyOpenPendingCancelResult::Cancelled) => {
                    RuntimePreparedRecipientCancelResult::Cancelled
                }
                Some(RuntimeCustodyOpenPendingCancelResult::AlreadyAbsent) => {
                    RuntimePreparedRecipientCancelResult::AlreadyAbsent
                }
                None => {
                    let result = cancel_prepared_recipient_with_result_by_handle(
                        &decrypt,
                        record.audit_request_id()?,
                        record.viewer_session_handle_bytes()?,
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE))?;
                    record.mark_open_pending_cancel_result(result, crate::auth::now_ts());
                    persist_runtime_custody_viewer_record(
                        data_dir,
                        principal_id,
                        mint_id,
                        &record,
                    )?;
                    result
                }
            };
            let _ = cancel_result;
            record.mark_terminal(close_result, crate::auth::now_ts());
            RuntimeCustodyViewerRecord::release_staged_object(data_dir, principal_id, mint_id);
            persist_runtime_custody_viewer_record(data_dir, principal_id, mint_id, &record)?;
            Ok(record)
        }
        RuntimeCustodyViewerLifecycleStatus::Active
        | RuntimeCustodyViewerLifecycleStatus::CleanupPending => {
            let session =
                record.to_runtime_viewer_session(asset.content_identity.encrypted_content())?;
            match close_viewer_session_with_result(&decrypt, &session).await {
                Ok(result) => {
                    record.mark_terminal(result, crate::auth::now_ts());
                    RuntimeCustodyViewerRecord::release_staged_object(
                        data_dir,
                        principal_id,
                        mint_id,
                    );
                    persist_runtime_custody_viewer_record(
                        data_dir,
                        principal_id,
                        mint_id,
                        &record,
                    )?;
                    Ok(record)
                }
                Err(_) => {
                    record.mark_cleanup_pending(crate::auth::now_ts());
                    persist_runtime_custody_viewer_record(
                        data_dir,
                        principal_id,
                        mint_id,
                        &record,
                    )?;
                    anyhow::bail!(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE);
                }
            }
        }
        RuntimeCustodyViewerLifecycleStatus::Closed
        | RuntimeCustodyViewerLifecycleStatus::AlreadyAbsent => Ok(record),
    }
}

/// Reconciles durable protected-content viewer records after canonical decrypt
/// provider registration so restart cleanup can settle exact viewer sessions.
pub async fn reconcile_runtime_custody_viewers_after_decrypt_registration(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
) -> anyhow::Result<()> {
    reconcile_runtime_custody_viewer_records(data_dir, registry, false).await
}

/// Plan B T4.5: at boot, whether or not a decrypt target registers, pool
/// viewer records settle. Their delivery secrets lived only in the process
/// that stopped, so each one is dropped and its next open starts fresh.
pub async fn reconcile_runtime_custody_pool_viewers_at_boot(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
) {
    if let Err(error) = reconcile_runtime_custody_viewer_records(data_dir, registry, true).await {
        tracing::warn!(
            error = %error,
            "Runtime custody pool viewer reconciliation at boot failed closed"
        );
    }
}

/// Settles every unresolved viewer record, or only the pool ones.
async fn reconcile_runtime_custody_viewer_records(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    only_pool: bool,
) -> anyhow::Result<()> {
    let root = data_dir.join(RUNTIME_OPEN_MATERIAL_ROOT);
    if !root.is_dir() {
        return Ok(());
    }
    let mut unresolved_mint_dirs = 0usize;
    let mut unresolved_viewer_records = 0usize;
    for mint_entry in fs::read_dir(&root)? {
        let mint_entry = mint_entry?;
        if !mint_entry.file_type()?.is_dir() {
            continue;
        }
        let viewers_dir = mint_entry.path().join("viewers");
        if !viewers_dir.is_dir() {
            continue;
        }
        let mut counted_mint_dir = false;
        for viewer_entry in fs::read_dir(&viewers_dir)? {
            let viewer_entry = viewer_entry?;
            if !viewer_entry.file_type()?.is_file() {
                continue;
            }
            let path = viewer_entry.path();
            let _viewer_lifecycle_guard =
                acquire_runtime_custody_viewer_lifecycle_guard_for_path(&path).await;
            let Some(record) = load_runtime_custody_viewer_record_from_path(&path)? else {
                continue;
            };
            let lifecycle_status = record.lifecycle_status;
            if only_pool && !record.is_pool() {
                continue;
            }
            if !matches!(
                record.lifecycle_status,
                RuntimeCustodyViewerLifecycleStatus::OpenPending
                    | RuntimeCustodyViewerLifecycleStatus::Active
                    | RuntimeCustodyViewerLifecycleStatus::CleanupPending
            ) {
                if validate_runtime_custody_viewer_record_identity(data_dir, &path, &record)
                    .is_err()
                {
                    continue;
                }
                continue;
            }
            if !counted_mint_dir {
                unresolved_mint_dirs += 1;
                counted_mint_dir = true;
                if unresolved_mint_dirs > MAX_RUNTIME_VIEWER_RECONCILE_MINT_DIRS {
                    anyhow::bail!(
                        "Runtime custody viewer reconciliation exceeds unresolved mint directory limit"
                    );
                }
            }
            unresolved_viewer_records += 1;
            if unresolved_viewer_records > MAX_RUNTIME_VIEWER_RECONCILE_RECORDS {
                anyhow::bail!(
                    "Runtime custody viewer reconciliation exceeds unresolved record limit"
                );
            }
            let (mint_id, listing) = validate_runtime_custody_viewer_record_identity(
                data_dir, &path, &record,
            )
            .map_err(|error| {
                anyhow::anyhow!(
                    "Runtime custody viewer reconciliation found invalid {:?} record at {}: {}",
                    lifecycle_status,
                    path.display(),
                    error
                )
            })?;
            let principal_id = record.principal_id.clone();
            if let Err(error) = settle_runtime_custody_viewer_cleanup(
                data_dir,
                registry.clone(),
                &listing,
                &principal_id,
                mint_id,
                record,
            )
            .await
            {
                tracing::warn!(
                    "Runtime custody viewer cleanup reconciliation remains pending at {}: {}",
                    path.display(),
                    error
                );
            }
        }
    }
    Ok(())
}

/// Boot-path hook after successful Runtime-only decrypt registration.
/// Viewer records created before decrypt came up are the state this reconcile
/// exists for. Boot keeps serving when reconciliation fails closed.
pub async fn reconcile_runtime_custody_viewers_after_decrypt_boot(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
) {
    if let Err(error) =
        reconcile_runtime_custody_viewers_after_decrypt_registration(data_dir, registry).await
    {
        tracing::warn!(
            error = %error,
            "Runtime custody viewer reconciliation after decrypt registration failed closed"
        );
    }
}

fn reconstructed_buy_receipt(
    draft: &RuntimeMintDraft,
    availability: &elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1,
    purchase: &RuntimeCustodyPurchaseRecord,
    current_profile_did: &str,
) -> anyhow::Result<elastos_protected_content_runtime::RuntimeBuyReceipt> {
    if purchase.profile_did != current_profile_did {
        return Err(runtime_open_error(
            elastos_protected_content_runtime::RuntimeOpenError::ChainEvidence,
        ));
    }
    let profile_identity = profile_identity_from_did(current_profile_did)?;
    let terminal = match &purchase.progress {
        RuntimeCustodyPurchaseProgress::Complete { terminal } => terminal,
        // A granted copy has no transaction to present; its receipt binds the
        // wallet the chain granted, and custody re-reads that grant.
        RuntimeCustodyPurchaseProgress::Granted { .. } => {
            return draft
                .bind_verified_grant(
                    availability,
                    profile_identity,
                    &purchase.address,
                    RightsActionV1::View,
                )
                .map_err(runtime_open_error);
        }
        RuntimeCustodyPurchaseProgress::Pending { .. } => {
            return Err(runtime_open_error(
                elastos_protected_content_runtime::RuntimeOpenError::ChainEvidence,
            ));
        }
    };
    let effect = RuntimeVerifiedPurchaseEffect::new(
        RuntimeProtectedContentPurchaseIntent::new(
            draft.mint_id(),
            draft.encrypted_content().clone(),
            draft.key_envelope().clone(),
            draft.policy().clone(),
            RightsActionV1::View,
            purchase.chain_namespace.clone(),
            purchase.network.clone(),
            purchase.acquisition_stage.to.clone(),
            purchase.acquisition_stage.value.clone(),
            purchase.acquisition_stage.data.clone(),
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody chain evidence is invalid"))?,
        RuntimePurchaseEffectAuthority::new(
            purchase.principal_id.clone(),
            purchase.account_id.clone(),
            purchase.address.clone(),
            purchase.acquisition_stage.approval_request_id.clone(),
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody wallet authority is invalid"))?,
        terminal.wallet_binding.clone(),
        terminal.chain_transaction.clone(),
        terminal.chain_observation.clone(),
        terminal.confirmed_at,
    )
    .map_err(runtime_open_error)?;
    draft
        .bind_verified_buy(
            availability,
            &purchase.principal_id,
            profile_identity,
            &effect,
        )
        .map_err(runtime_open_error)
}

struct RuntimeReleaseWalletInvocation<'a> {
    principal_id: &'a str,
    account_id: &'a str,
    proof_binding_id: &'a str,
    session_id: &'a str,
    grant_id: &'a str,
    mint_id: Digest32,
    runtime_session_binding: RuntimeSessionBindingV1,
}

/// What the Wallet answered to the viewer release rights-signature request.
#[derive(Debug)]
enum RuntimeReleaseWalletOutcome {
    /// The exact wallet request/response pair and the verified signed rights.
    Signed {
        request_bytes: Vec<u8>,
        response_bytes: Vec<u8>,
        /// Boxed: the signed rights request dwarfs the pending arm.
        signed_rights: Box<WalletSignedRightsRequestV1>,
    },
    /// The account needs the principal's explicit approval first; the exact
    /// request must be replayed once the approval is completed. Every first
    /// rights-signature request lands here, for managed and external accounts
    /// alike, so this is the ordinary path rather than an edge case.
    PendingApproval {
        request_bytes: Vec<u8>,
        approval_request_id: String,
        /// Read from the approval record the Wallet just created, which names
        /// the account the approval actually belongs to. An external account
        /// is waiting on its connector, which means it is waiting on a person.
        external_signer: bool,
        connector_id: Option<String>,
    },
}

/// The V1 rights request of a local-decrypt open: one recipient, the one
/// this Home's decrypt provider prepared.
fn runtime_release_v1_rights_request(
    buy: &elastos_protected_content_runtime::RuntimeBuyReceipt,
    recipient: &RecipientKeyIdentityV1,
    invocation: &RuntimeReleaseWalletInvocation<'_>,
    now: u64,
) -> anyhow::Result<RightsRequestAnyV1> {
    let mut replay_nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut replay_nonce);
    RightsRequestV1::new(
        buy.binding_for_session(invocation.runtime_session_binding)
            .map_err(release_unavailable!())?,
        buy.action(),
        recipient.clone(),
        now.saturating_sub(5),
        now + RUNTIME_CUSTODY_OPEN_APPROVAL_WINDOW_SECS,
        ReplayNonce16::new(replay_nonce),
    )
    .map(RightsRequestAnyV1::V1)
    .map_err(release_unavailable!())
}

/// Builds the exact wallet rights-signature request for this open, or
/// decodes the persisted one when a pending release is being resumed (the
/// rights request is bound to its recipients, so a resumed release must
/// replay byte-identical bytes for the Wallet to return its stored result).
///
/// Plan B T4.4 (R1): the request is V1 or V2, decoded by domain. A replay
/// must be the request this open stands on (`replay_matches`): V1 compares
/// the recipient, V2 the recipient set and the delivery key.
fn runtime_release_wallet_request(
    fresh: impl FnOnce() -> anyhow::Result<RightsRequestAnyV1>,
    replay_matches: impl Fn(&RightsRequestAnyV1) -> bool,
    invocation: &RuntimeReleaseWalletInvocation<'_>,
    replay_request: Option<&[u8]>,
    now: u64,
) -> anyhow::Result<(WalletProviderRequestV2, RightsRequestAnyV1)> {
    if let Some(bytes) = replay_request {
        let wallet_request =
            WalletProviderRequestV2::decode_at(bytes, now).map_err(release_unavailable!())?;
        let WalletProviderOperationV2::RequestProtectedContentRightsSignature {
            canonical_rights_request_hex,
            ..
        } = &wallet_request.operation
        else {
            return Err(release_unavailable_missing!()());
        };
        let rights_request = RightsRequestAnyV1::from_canonical_bytes(
            &decode_hex_bytes(canonical_rights_request_hex).map_err(release_unavailable!())?,
        )
        .map_err(release_unavailable!())?;
        if !replay_matches(&rights_request) {
            return Err(release_unavailable_missing!()());
        }
        return Ok((wallet_request, rights_request));
    }
    let rights_request = fresh()?;
    let mut request_entropy = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut request_entropy);
    let context = VerifiedWalletInvocationContext::new(
        invocation.principal_id.to_string(),
        invocation.session_id,
        Some(invocation.proof_binding_id.to_string()),
        invocation.grant_id,
        RUNTIME_PROVIDER_ID,
        format!(
            "runtime-open-{}",
            hex::encode(invocation.mint_id.as_bytes())
        ),
    )
    .map_err(release_unavailable!())?;
    let wallet_request = WalletProviderRequestV2::new(
        &context,
        format!("wallet-request:{}", hex::encode(request_entropy)),
        now,
        now.saturating_add(MAX_INVOCATION_TTL_SECS),
        WalletProviderOperationV2::RequestProtectedContentRightsSignature {
            account_id: invocation.account_id.to_string(),
            canonical_rights_request_hex: hex::encode(
                rights_request
                    .canonical_bytes()
                    .map_err(release_unavailable!())?,
            ),
            reason: "Open protected content".to_string(),
        },
    )
    .map_err(release_unavailable!())?;
    Ok((wallet_request, rights_request))
}

/// Whether the Wallet signed exactly `request`, V1 or V2.
fn wallet_signed_rights_request_is(
    signed: &WalletSignedRightsRequestAnyV1,
    request: &RightsRequestAnyV1,
) -> bool {
    match (signed, request) {
        (WalletSignedRightsRequestAnyV1::V1(signed), RightsRequestAnyV1::V1(request)) => {
            signed.request() == request
        }
        (WalletSignedRightsRequestAnyV1::V2(signed), RightsRequestAnyV1::V2(request)) => {
            signed.request() == request
        }
        _ => false,
    }
}

/// [`RuntimeReleaseWalletOutcome`] for a V1 or V2 rights request.
#[derive(Debug)]
enum RuntimeReleaseWalletAnyOutcome {
    Signed {
        request_bytes: Vec<u8>,
        response_bytes: Vec<u8>,
        signed_rights: Box<WalletSignedRightsRequestAnyV1>,
    },
    PendingApproval {
        request_bytes: Vec<u8>,
        approval_request_id: String,
        external_signer: bool,
        connector_id: Option<String>,
    },
}

/// The V1 open's Wallet call: a V1 request, and a V1 signature back.
async fn invoke_runtime_release_wallet(
    registry: &ProviderRegistry,
    buy: &elastos_protected_content_runtime::RuntimeBuyReceipt,
    recipient: &RecipientKeyIdentityV1,
    invocation: RuntimeReleaseWalletInvocation<'_>,
    replay_request: Option<&[u8]>,
    now: u64,
) -> anyhow::Result<RuntimeReleaseWalletOutcome> {
    let fresh = || runtime_release_v1_rights_request(buy, recipient, &invocation, now);
    let replay_matches = |request: &RightsRequestAnyV1| matches!(request, RightsRequestAnyV1::V1(request) if request.recipient() == recipient);
    match invoke_runtime_release_wallet_any(
        registry,
        fresh,
        replay_matches,
        &invocation,
        replay_request,
        now,
    )
    .await?
    {
        RuntimeReleaseWalletAnyOutcome::Signed {
            request_bytes,
            response_bytes,
            signed_rights,
        } => match *signed_rights {
            WalletSignedRightsRequestAnyV1::V1(signed_rights) => {
                Ok(RuntimeReleaseWalletOutcome::Signed {
                    request_bytes,
                    response_bytes,
                    signed_rights: Box::new(signed_rights),
                })
            }
            WalletSignedRightsRequestAnyV1::V2(_) => Err(release_unavailable!()(
                "wallet signed a pool rights request for a local open",
            )),
        },
        RuntimeReleaseWalletAnyOutcome::PendingApproval {
            request_bytes,
            approval_request_id,
            external_signer,
            connector_id,
        } => Ok(RuntimeReleaseWalletOutcome::PendingApproval {
            request_bytes,
            approval_request_id,
            external_signer,
            connector_id,
        }),
    }
}

async fn invoke_runtime_release_wallet_any(
    registry: &ProviderRegistry,
    fresh: impl FnOnce() -> anyhow::Result<RightsRequestAnyV1>,
    replay_matches: impl Fn(&RightsRequestAnyV1) -> bool,
    invocation: &RuntimeReleaseWalletInvocation<'_>,
    replay_request: Option<&[u8]>,
    now: u64,
) -> anyhow::Result<RuntimeReleaseWalletAnyOutcome> {
    let (wallet_request, rights_request) =
        runtime_release_wallet_request(fresh, replay_matches, invocation, replay_request, now)?;
    let response = registry
        .invoke_provider(ProviderInvocation {
            source: RUNTIME_PROVIDER_ID.to_string(),
            target: WALLET_PROVIDER_ID.to_string(),
            op: WALLET_BUS_OPERATION.to_string(),
            request: serde_json::json!({
                "op": WALLET_BUS_OPERATION,
                "request": wallet_request,
            }),
            transfer: ProviderTransfer::Json,
            range: None,
            progress: None,
            transport: ProviderInvocationTransport::Local,
        })
        .await
        .map_err(release_unavailable!())?;
    if response.get("status").and_then(Value::as_str) != Some("ok") {
        let code = response
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let message = response
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("wallet rights signature request rejected");
        return Err(release_unavailable!()(format!(
            "wallet rights signature request rejected: {code}: {message}"
        )));
    }
    let data = response
        .get("data")
        .ok_or_else(release_unavailable_missing!())?;
    let request_bytes = serde_json::to_vec(&wallet_request).map_err(release_unavailable!())?;
    let response_bytes = serde_json::to_vec(data).map_err(release_unavailable!())?;
    // The Wallet answers with its approval record until the signature exists;
    // the exact request is then replayed.
    let payload = data
        .get("result")
        .and_then(|result| result.get("data"))
        .unwrap_or(data);
    // An approval is outstanding while it is `pending` -- waiting on the
    // person -- AND while it is `approved`, which is the gap between the person
    // confirming in their wallet and the connector posting the signature back.
    //
    // `requires_approval` reports only the first of those, because it is
    // `status == Pending`. Reading it alone made `approved` look like a
    // finished approval carrying no signature, so the release failed closed on
    // a state that was about to succeed. An external wallet passes through that
    // gap on every single open, and a viewer polling every two seconds lands in
    // it reliably -- which is exactly what "approved it, then it errored" is.
    let approval_status = payload
        .get("approval_request")
        .and_then(|approval| approval.get("status"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let requires_approval = payload
        .get("requires_approval")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // A terminal answer is neither of those. It is reported by its own type so
    // a viewer stops waiting rather than polling something already decided.
    if matches!(approval_status, "rejected" | "expired") {
        let reason = if approval_status == "rejected" {
            RuntimeCustodyApprovalClosedReason::Rejected
        } else {
            RuntimeCustodyApprovalClosedReason::Expired
        };
        let closed = RuntimeCustodyApprovalClosed::new(reason);
        tracing::debug!(
            reason = closed.reason_label(),
            "runtime custody open: viewer release approval is closed"
        );
        return Err(anyhow::Error::new(closed)
            .context(format!("{}:{}", file!(), line!()))
            .context(RUNTIME_CUSTODY_RELEASE_APPROVAL_UNAVAILABLE_MESSAGE));
    }
    if requires_approval || approval_status == "approved" {
        let approval = payload
            .get("approval_request")
            .ok_or_else(release_unavailable_missing!())?;
        let approval_request_id = approval
            .get("request_id")
            .and_then(Value::as_str)
            .ok_or_else(release_unavailable_missing!())?
            .to_string();
        let external_signer =
            !crate::api::gateway::gateway_wallet::gateway_wallet_send::is_managed_wallet_proof_type(
                approval
                    .get("proof_type")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            );
        let connector_id = approval
            .get("connector_id")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        tracing::debug!(
            %approval_request_id,
            external_signer,
            approval_status,
            "runtime custody open: viewer release awaits exact Wallet approval"
        );
        return Ok(RuntimeReleaseWalletAnyOutcome::PendingApproval {
            request_bytes,
            approval_request_id,
            external_signer,
            connector_id,
        });
    }
    let signed_rights = wallet_signed_rights_from_bytes(&request_bytes, &response_bytes)
        .map_err(release_unavailable!())?;
    if !wallet_signed_rights_request_is(&signed_rights, &rights_request) {
        return Err(release_unavailable!()(
            "wallet signed a rights request other than the one issued",
        ));
    }
    Ok(RuntimeReleaseWalletAnyOutcome::Signed {
        request_bytes,
        response_bytes,
        signed_rights: Box::new(signed_rights),
    })
}

/// Decodes the Wallet's signed rights result from the exact request/response
/// pair, naming the step that failed so a live failure is diagnosable.
fn wallet_signed_rights_from_bytes(
    wallet_request_bytes: &[u8],
    wallet_response_bytes: &[u8],
) -> Result<WalletSignedRightsRequestAnyV1, String> {
    let now = crate::auth::now_ts();
    let request =
        elastos_wallet_contract::WalletProviderRequestV2::decode_at(wallet_request_bytes, now)
            .map_err(|err| format!("wallet request does not decode: {err:?}"))?;
    let response = elastos_wallet_contract::WalletProviderResponseV2::decode_for_request(
        wallet_response_bytes,
        &request,
    )
    .map_err(|err| format!("wallet response is not bound to the request: {err:?}"))?;
    let data = match response.result {
        elastos_wallet_contract::WalletResultV2::Ok { data } => data,
        elastos_wallet_contract::WalletResultV2::Error { code, message } => {
            return Err(format!("wallet answered an error: {code}: {message}"));
        }
    };
    let result = elastos_protected_content_runtime::wallet_rights_signature_result(&data)
        .ok_or_else(|| {
            let keys = data
                .as_object()
                .map(|object| object.keys().cloned().collect::<Vec<_>>().join(","))
                .unwrap_or_default();
            format!("wallet result carries no rights signature (keys: {keys})")
        })?;
    let bytes = decode_hex_bytes(&result.wallet_signed_rights_request_hex)
        .map_err(|err| format!("signed rights hex is invalid: {err}"))?;
    WalletSignedRightsRequestAnyV1::from_canonical_bytes(&bytes)
        .map_err(|err| format!("signed rights bytes are not canonical: {err:?}"))
}

fn sign_runtime_terminal_receipt(
    device_key: &ed25519_dalek::SigningKey,
    operation: &SignedRuntimeReleaseOperationV1,
    contributions: &[elastos_protected_content_contracts::SignedNodeContributionV1],
    epoch: &SignedCustodyEpochV1,
    now: u64,
) -> anyhow::Result<SignedTerminalReceiptV1> {
    let authenticated = operation
        .verify(operation.statement().runtime_operation_issuer(), now)
        .map_err(release_unavailable!())?;
    let node_set = epoch
        .statement()
        .node_set()
        .map_err(release_unavailable!())?;
    let refs = contributions
        .iter()
        .map(|contribution| {
            authenticated
                .verify_node_contribution(contribution, &node_set, now)
                .map(|verified| NodeContributionRefV1::from(&verified))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(release_unavailable!())?;
    let contribution_issued_at = contributions
        .iter()
        .map(|contribution| contribution.statement().issued_at())
        .max()
        .unwrap_or(now);
    let contribution_expires_at = contributions
        .iter()
        .map(|contribution| contribution.statement().expires_at())
        .min()
        .unwrap_or(now.saturating_add(30));
    let release = operation.statement().release_request();
    let issued_at = now.max(contribution_issued_at).max(release.issued_at());
    let expires_at = contribution_expires_at
        .min(release.expires_at())
        .min(issued_at.saturating_add(30));
    if expires_at <= issued_at {
        return Err(release_unavailable_missing!()());
    }
    let statement = TerminalReceiptStatementV1::new(
        authenticated.release_request_hash(),
        authenticated.binding().clone(),
        TerminalReceiptIssuerKey::new(device_key.verifying_key().to_bytes())
            .map_err(|_| anyhow::anyhow!("local Runtime device signing key is invalid"))?,
        KeyReleaseOutcomeV1::Released,
        refs,
        issued_at,
        expires_at,
    )
    .map_err(release_unavailable!())?;
    SignedTerminalReceiptV1::new(
        statement.clone(),
        device_key
            .sign(
                &statement
                    .canonical_bytes()
                    .map_err(release_unavailable!())?,
            )
            .to_bytes()
            .to_vec(),
    )
    .map_err(release_unavailable!())
}

async fn fetch_runtime_custody_open_media(
    registry: &ProviderRegistry,
    cid: &str,
    expected: &CencFmp4MediaIdentityV1,
) -> anyhow::Result<(CencFmp4MediaIdentityV1, Vec<u8>)> {
    let identity_bytes = crate::content::fetch_bytes_via_provider(
        registry,
        cid,
        Some(PROTECTED_CONTENT_IDENTITY_PATH),
    )
    .await
    .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE))?;
    let media = CencFmp4MediaIdentityV1::from_canonical_bytes(&identity_bytes)
        .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE))?;
    if &media != expected {
        anyhow::bail!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE);
    }
    let init =
        crate::content::fetch_bytes_via_provider(registry, cid, Some(PROTECTED_CONTENT_INIT_PATH))
            .await
            .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE))?;
    Ok((media, init))
}

/// DASH v2 twin of [`fetch_runtime_custody_open_media`]. Verifies the
/// published manifest against the head (which yields the Merkle leaves) and
/// fetches each rendition's protected init, checking it against the head. No
/// segment is fetched: each is proven against the head's root when read. The
/// identity file is not refetched either, because the manifest check binds its
/// hash to the expected head.
async fn fetch_runtime_custody_open_media_dash(
    registry: &ProviderRegistry,
    cid: &str,
    expected: &CencDashMediaIdentityV2,
) -> anyhow::Result<(Vec<Vec<u8>>, Vec<Vec<Digest32>>)> {
    let unavailable = || anyhow::anyhow!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE);
    let manifest = crate::content::fetch_content_object_manifest(registry, cid)
        .await
        .map_err(|_| unavailable())?;
    let leaves =
        verify_protected_content_dash_manifest(&manifest, expected).map_err(|_| unavailable())?;
    let mut inits = Vec::with_capacity(expected.renditions().len());
    for rendition in expected.renditions() {
        let init = crate::content::fetch_bytes_via_provider_capped(
            registry,
            cid,
            Some(&runtime_media_dash_init_path(rendition.kind())),
            MAX_VIEWER_MEDIA_PART_BYTES_V1,
        )
        .await
        .map_err(|_| unavailable())?;
        if init.len() as u64 != rendition.init_segment_bytes()
            || Digest32::new(sha2::Sha256::digest(&init).into()) != rendition.init_segment_sha256()
        {
            anyhow::bail!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE);
        }
        inits.push(init);
    }
    Ok((inits, leaves))
}

/// Object twin of [`fetch_runtime_custody_open_media`]. Fetches the published
/// `object.epc1` and verifies the whole framed file against the identity the
/// listing commits to (exact length and sha256) before a single byte of it is
/// used; the caller then slices the framed header or one framed chunk out of
/// it.
///
/// The whole file is fetched because an object is ONE published file, unlike
/// media's separately-addressable segment files. A ranged content fetch would
/// not avoid that: without a bounded read the content plane transfers and
/// holds the whole payload and slices it afterwards (#444's area). So the
/// open does one verified fetch and stages the file, and a read that finds no
/// staged file does one fetch and stages it again, instead of one fetch per
/// chunk.
async fn fetch_runtime_custody_open_object(
    registry: &ProviderRegistry,
    cid: &str,
    expected: &ChunkedPayloadObjectIdentityV1,
) -> anyhow::Result<Vec<u8>> {
    let framed = crate::content::fetch_bytes_via_provider(
        registry,
        cid,
        Some(PROTECTED_CONTENT_OBJECT_EPC1_PATH),
    )
    .await
    .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE))?;
    if framed.len() as u64 != expected.encrypted_content().ciphertext_bytes()
        || Digest32::new(sha2::Sha256::digest(&framed).into())
            != expected.encrypted_content().ciphertext_sha256()
    {
        anyhow::bail!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE);
    }
    Ok(framed)
}

/// One framed chunk for a read: from the staged object when there is one, and
/// otherwise from one verified fetch of the whole file, which is staged again
/// (best effort) so the chunks after it seek instead of fetching.
async fn runtime_custody_object_chunk_for_read(
    data_dir: &Path,
    registry: &ProviderRegistry,
    principal_id: &str,
    mint_id: Digest32,
    cid: &str,
    object_identity: &ChunkedPayloadObjectIdentityV1,
    chunk_index: u32,
) -> anyhow::Result<Vec<u8>> {
    if let Some(chunk) = runtime_custody_staged_object_chunk(
        data_dir,
        principal_id,
        mint_id,
        object_identity,
        chunk_index,
    ) {
        return Ok(chunk);
    }
    let framed = fetch_runtime_custody_open_object(registry, cid, object_identity).await?;
    if let Err(error) = stage_runtime_custody_object(data_dir, principal_id, mint_id, &framed) {
        tracing::warn!(
            ?error,
            "runtime custody read: restaging the object failed; reads will fetch"
        );
    }
    let chunk = runtime_custody_object_framed_chunk(&framed, object_identity, chunk_index)?;
    drop(framed);
    Ok(chunk)
}

/// The framed header block at offset 0 of a verified framed object.
pub(crate) fn runtime_custody_object_framed_header(
    framed: &[u8],
    object_identity: &ChunkedPayloadObjectIdentityV1,
) -> anyhow::Result<Vec<u8>> {
    let header_bytes = usize::try_from(object_identity.framed_header_bytes())
        .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE))?;
    framed
        .get(..header_bytes)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE))
}

/// One framed chunk of a verified framed object, addressed by chunk index.
/// The byte ranges come from the custody crate's own
/// `framed_chunk_ranges_v1`, the same arithmetic the sealer and the chunk
/// decrypter use, rather than being re-derived here.
pub(crate) fn runtime_custody_object_framed_chunk(
    framed: &[u8],
    object_identity: &ChunkedPayloadObjectIdentityV1,
    chunk_index: u32,
) -> anyhow::Result<Vec<u8>> {
    const MESSAGE: &str = "Runtime custody viewer object chunk is invalid";
    if chunk_index >= object_identity.chunk_count() {
        anyhow::bail!(MESSAGE);
    }
    let range = elastos_protected_content_custody::framed_chunk_ranges_v1(
        object_identity.framed_header_bytes(),
        object_identity.plaintext_bytes(),
    )
    .nth(usize::try_from(chunk_index).map_err(|_| anyhow::anyhow!(MESSAGE))?)
    .ok_or_else(|| anyhow::anyhow!(MESSAGE))?;
    let start = usize::try_from(range.start).map_err(|_| anyhow::anyhow!(MESSAGE))?;
    let end = usize::try_from(range.end).map_err(|_| anyhow::anyhow!(MESSAGE))?;
    framed
        .get(start..end)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| anyhow::anyhow!(MESSAGE))
}

fn runtime_open_error(error: elastos_protected_content_runtime::RuntimeOpenError) -> anyhow::Error {
    match error {
        elastos_protected_content_runtime::RuntimeOpenError::WalletAuthority => {
            anyhow::anyhow!("Runtime custody wallet authority is invalid")
        }
        elastos_protected_content_runtime::RuntimeOpenError::MintSelection => {
            anyhow::anyhow!("Runtime custody mint selection is invalid")
        }
        elastos_protected_content_runtime::RuntimeOpenError::DecryptResult => {
            anyhow::anyhow!(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE)
        }
        _ => anyhow::anyhow!("Runtime custody chain evidence is invalid"),
    }
}

pub(crate) fn parse_mint_id_hex(value: &str) -> anyhow::Result<Digest32> {
    let bytes = decode_hex_bytes(value)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint identity is invalid"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Runtime custody mint identity is invalid"))?;
    Ok(Digest32::new(bytes))
}

fn parse_viewer_handle_hex(
    value: &str,
) -> anyhow::Result<[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]> {
    let bytes = decode_hex_bytes(value)
        .map_err(|_| anyhow::anyhow!("Runtime custody viewer session is unavailable"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Runtime custody viewer session is unavailable"))
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
}

fn runtime_open_audit_id(
    principal_id: &str,
    mint_id: Digest32,
    now: u64,
) -> RuntimeReleaseAuditIdV1 {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"elastos.protected-content.runtime-open-audit.v1");
    hasher.update(principal_id.as_bytes());
    hasher.update(mint_id.as_bytes());
    hasher.update(now.to_be_bytes());
    // Each new open needs a distinct audit ID; pending retries reuse the persisted ID.
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    hasher.update(nonce);
    RuntimeReleaseAuditIdV1::new(Digest32::new(hasher.finalize().into())).unwrap_or_else(|_| {
        RuntimeReleaseAuditIdV1::new(Digest32::new([1; 32])).expect("nonzero audit id")
    })
}

pub(crate) fn load_runtime_custody_profile_did(
    data_dir: &Path,
    principal_id: &str,
) -> anyhow::Result<String> {
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    let profile = crate::collaboration_profile_authority::load_profile_authority(
        data_dir,
        principal_id,
        &localhost_root,
    )?
    .ok_or_else(release_unavailable_missing!())?;
    Ok(profile.document().profile_did.clone())
}

fn profile_identity_from_did(profile_did: &str) -> anyhow::Result<ProfileIdentityV1> {
    let key = crate::crypto::decode_did_key(profile_did).map_err(release_unavailable!())?;
    ProfileIdentityV1::from_public_key_bytes(key.to_bytes()).map_err(release_unavailable!())
}

fn update_length_prefixed_session_field(
    hasher: &mut sha2::Sha256,
    value: &[u8],
) -> anyhow::Result<()> {
    let encoded_len = u32::try_from(value.len()).map_err(release_unavailable!())?;
    hasher.update(encoded_len.to_be_bytes());
    hasher.update(value);
    Ok(())
}

/// Session binding v3: the preimage's viewer-capsule field is the verified
/// `executable_actor` the caller was actually launched as (checked by the
/// caller against the admitted viewer set — see `open_runtime_custody_viewer`
/// and `gateway_provider_proxy`'s `is_protected_viewer_op` admission), not a
/// hard-coded constant. v2 hard-coded `ELACITY_PLAYER_CAPSULE_ID` here, which
/// made a second viewer (the object reader) structurally inadmissible: any
/// binding derived for a non-player launch would simply never match one
/// derived (with the same hard-coded constant) on the other side.
#[allow(clippy::too_many_arguments)]
fn derive_runtime_custody_session_binding(
    principal_id: &str,
    profile_did: &str,
    executable_actor: &str,
    launch_id: &str,
    proof_binding_id: &str,
    session_id: &str,
    grant_id: &str,
    mint_id: Digest32,
) -> anyhow::Result<RuntimeSessionBindingV1> {
    if !valid_runtime_viewer_launch_id(launch_id) {
        return Err(release_unavailable_missing!()());
    }
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"elastos.protected-content.runtime-session-binding.v3");
    update_length_prefixed_session_field(&mut hasher, principal_id.as_bytes())?;
    update_length_prefixed_session_field(&mut hasher, profile_did.as_bytes())?;
    update_length_prefixed_session_field(&mut hasher, executable_actor.as_bytes())?;
    update_length_prefixed_session_field(&mut hasher, launch_id.as_bytes())?;
    update_length_prefixed_session_field(&mut hasher, proof_binding_id.as_bytes())?;
    update_length_prefixed_session_field(&mut hasher, session_id.as_bytes())?;
    update_length_prefixed_session_field(&mut hasher, grant_id.as_bytes())?;
    update_length_prefixed_session_field(&mut hasher, mint_id.as_bytes())?;
    RuntimeSessionBindingV1::new(Digest32::new(hasher.finalize().into()))
        .map_err(release_unavailable!())
}

#[allow(clippy::too_many_arguments)]
fn require_runtime_custody_session_binding(
    principal_id: &str,
    profile_did: &str,
    executable_actor: &str,
    launch_id: Option<&str>,
    proof_binding_id: Option<&str>,
    session_id: Option<&str>,
    grant_id: Option<&str>,
    mint_id: Digest32,
    missing_message: &'static str,
) -> anyhow::Result<RuntimeSessionBindingV1> {
    let launch_id = launch_id.filter(|value| valid_runtime_viewer_launch_id(value));
    let proof_binding_id = proof_binding_id.filter(|value| !value.is_empty());
    let session_id = session_id.filter(|value| !value.is_empty());
    let grant_id = grant_id.filter(|value| !value.is_empty());
    let (Some(launch_id), Some(proof_binding_id), Some(session_id), Some(grant_id)) =
        (launch_id, proof_binding_id, session_id, grant_id)
    else {
        anyhow::bail!(missing_message);
    };
    derive_runtime_custody_session_binding(
        principal_id,
        profile_did,
        executable_actor,
        launch_id,
        proof_binding_id,
        session_id,
        grant_id,
        mint_id,
    )
    .map_err(|_| anyhow::anyhow!(missing_message))
}

fn valid_runtime_viewer_launch_id(value: &str) -> bool {
    value
        .strip_prefix("launch:")
        .is_some_and(|suffix| suffix.len() == 32 && suffix.chars().all(|ch| ch.is_ascii_hexdigit()))
}

/// Content kind discriminant on the viewer open response.
///
/// A viewer must never have to infer the shape of the session it just opened
/// from which optional geometry fields happen to be present: the media
/// response carries `mime_type`/`codecs`/`has_init_segment`/`segment_count`,
/// and the object response (deferred with the object open path) carries its own
/// chunk geometry instead. This field names the kind outright so each viewer
/// can fail closed on the other one — `capsules/elacity-player` rejects
/// anything but `"media"`.
pub(crate) const RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_MEDIA: &str = "media";

/// The ONE viewer capsule admitted for a content kind. Media opens only in
/// `elacity-player`, objects only in `elacity-reader`; there is no arm that
/// admits both, and no default.
fn expected_runtime_custody_viewer_capsule(
    content_identity: &RuntimeContentIdentityV1,
) -> &'static str {
    match content_identity {
        RuntimeContentIdentityV1::Media(_) | RuntimeContentIdentityV1::MediaDash(_) => {
            ELACITY_PLAYER_CAPSULE_ID
        }
        RuntimeContentIdentityV1::Object(_) => ELACITY_READER_CAPSULE_ID,
    }
}

/// Object twin of [`RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_MEDIA`].
pub(crate) const RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_OBJECT: &str = "object";

/// The kind of one protected item, in the same two words the viewer session
/// already speaks.
///
/// This exists so that a listing can say what it is before anyone opens it.
/// Marketplace used to decide the viewer from the item's MIME, which is a
/// second rule for a question [`expected_runtime_custody_viewer_capsule`]
/// already answers, and a second rule can disagree. The arms here are that
/// function's arms: media is the player's, an object is the reader's, and a
/// test holds the two together.
/// [`runtime_custody_content_kind`] for the content a listing package names.
pub(crate) fn runtime_custody_package_content_kind(
    package: &RuntimePortableListingPackage,
) -> anyhow::Result<&'static str> {
    Ok(runtime_custody_content_kind(
        &package.decode_and_validate()?.content_identity,
    ))
}

pub(crate) const fn runtime_custody_content_kind(
    content_identity: &RuntimeContentIdentityV1,
) -> &'static str {
    match content_identity {
        RuntimeContentIdentityV1::Media(_) | RuntimeContentIdentityV1::MediaDash(_) => {
            RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_MEDIA
        }
        RuntimeContentIdentityV1::Object(_) => RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_OBJECT,
    }
}

/// Object twin of [`runtime_custody_viewer_public_response`]. Carries the same
/// five kind-independent fields in the same order (`schema`, `content_kind`,
/// `mint_id`, `viewer_session_handle`, `expires_at`) and then the geometry a
/// reader needs to walk the content: its declared content type, the plaintext
/// size it decrypts to, how many chunks that is, and the plaintext chunk size
/// every chunk but the last one has. Media's own four geometry fields
/// (`mime_type`/`codecs`/`has_init_segment`/`segment_count`) are untouched.
fn runtime_custody_viewer_object_public_response(
    object_identity: &ChunkedPayloadObjectIdentityV1,
    mint_id: Digest32,
    viewer_session_handle: &[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    expires_at: u64,
) -> anyhow::Result<Value> {
    Ok(json!({
        "schema": "elastos.library.runtime-custody-viewer/v1",
        "content_kind": RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_OBJECT,
        "mint_id": hex::encode(mint_id.as_bytes()),
        "viewer_session_handle": hex::encode(viewer_session_handle),
        "expires_at": expires_at,
        "content_type": object_identity.content_type(),
        "plaintext_bytes": object_identity.plaintext_bytes(),
        "chunk_count": object_identity.chunk_count(),
        "chunk_plaintext_bytes": MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1,
    }))
}

/// The v2 open answer: the same five kind-independent fields as v1, then one
/// entry per rendition, video first. The player parses these keys exactly.
fn runtime_custody_viewer_media_dash_public_response(
    head: &CencDashMediaIdentityV2,
    mint_id: Digest32,
    viewer_session_handle: &[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    expires_at: u64,
) -> anyhow::Result<Value> {
    let renditions = head
        .renditions()
        .iter()
        .map(|rendition| {
            json!({
                "rendition": runtime_media_dash_rendition_name(rendition.kind()),
                "mime_type": rendition.mime_type(),
                "codecs": rendition.codecs(),
                "segment_count": rendition.segment_count(),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schema": RUNTIME_CUSTODY_VIEWER_SCHEMA_V2,
        "content_kind": RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_MEDIA,
        "mint_id": hex::encode(mint_id.as_bytes()),
        "viewer_session_handle": hex::encode(viewer_session_handle),
        "expires_at": expires_at,
        "renditions": renditions,
    }))
}

fn runtime_custody_viewer_public_response(
    media_identity: &CencFmp4MediaIdentityV1,
    mint_id: Digest32,
    viewer_session_handle: &[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    expires_at: u64,
) -> anyhow::Result<Value> {
    let segment_count = u32::try_from(media_identity.encrypted_segments().len())
        .map_err(|_| anyhow::anyhow!("Runtime custody viewer session is unavailable"))?;
    Ok(json!({
        "schema": "elastos.library.runtime-custody-viewer/v1",
        "content_kind": RUNTIME_CUSTODY_VIEWER_CONTENT_KIND_MEDIA,
        "mint_id": hex::encode(mint_id.as_bytes()),
        "viewer_session_handle": hex::encode(viewer_session_handle),
        "expires_at": expires_at,
        "mime_type": media_identity.mime_type(),
        "codecs": media_identity.codecs(),
        "has_init_segment": true,
        "segment_count": segment_count,
    }))
}

fn audit_nonce_bytes(audit_request_id: RuntimeReleaseAuditIdV1) -> [u8; 16] {
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&audit_request_id.digest().as_bytes()[..16]);
    nonce
}

#[cfg(test)]
pub(crate) fn runtime_listing_path_for_test(data_dir: &Path, mint_id: Digest32) -> PathBuf {
    runtime_listing_path(data_dir, mint_id)
}

fn runtime_listing_path(data_dir: &Path, mint_id: Digest32) -> PathBuf {
    data_dir
        .join(RUNTIME_LISTING_ROOT)
        .join(format!("{}.json", hex::encode(mint_id.as_bytes())))
}

fn runtime_purchase_path(data_dir: &Path, principal_id: &str, mint_id: Digest32) -> PathBuf {
    let mut hasher = sha2::Sha256::new();
    hasher.update(principal_id.as_bytes());
    data_dir
        .join(RUNTIME_PURCHASE_ROOT)
        .join(hex::encode(hasher.finalize()))
        .join(format!("{}.json", hex::encode(mint_id.as_bytes())))
}

/// The lock file guarding a principal's purchase-ledger directory. Every
/// `persist_runtime_custody_purchase` call for this principal serializes
/// through this lock before writing, so two concurrent purchase writes never
/// race on the durable record's rename.
fn runtime_purchase_lock_path(data_dir: &Path, principal_id: &str) -> PathBuf {
    let mut hasher = sha2::Sha256::new();
    hasher.update(principal_id.as_bytes());
    data_dir
        .join(RUNTIME_PURCHASE_ROOT)
        .join(hex::encode(hasher.finalize()))
        .join(".lock")
}

fn runtime_viewer_path(data_dir: &Path, principal_id: &str, mint_id: Digest32) -> PathBuf {
    let mut hasher = sha2::Sha256::new();
    hasher.update(principal_id.as_bytes());
    data_dir
        .join(RUNTIME_OPEN_MATERIAL_ROOT)
        .join(hex::encode(mint_id.as_bytes()))
        .join("viewers")
        .join(format!("{}.json", hex::encode(hasher.finalize())))
}

/// Where one viewer session keeps the verified framed object it reads from.
///
/// Beside that session's own record, so it shares the record's lifetime and is
/// removed by the same cleanup.
fn runtime_viewer_object_path(data_dir: &Path, principal_id: &str, mint_id: Digest32) -> PathBuf {
    runtime_viewer_path(data_dir, principal_id, mint_id).with_extension("framed")
}

/// Stages the verified framed object for the life of one viewer session.
///
/// Every chunk read used to fetch the whole object through the content
/// provider and re-hash all of it to check the identity, then keep roughly one
/// megabyte and drop the rest. On a thirteen-chunk file that is thirteen
/// fetches and thirteen full re-hashes of the same bytes, and it is why a read
/// spent about two seconds per chunk while the decryption itself took about a
/// tenth of that.
///
/// What is staged is ciphertext that is already published and fetchable by
/// anyone, so this keeps no secret on disk that the network does not already
/// carry. The bytes are verified against the listing's identity once, here,
/// before anything is written.
///
/// Per-chunk integrity does not rest on repeating that check. An object's
/// chunks are AES-256-GCM, so a tampered staged byte fails the decrypt
/// provider's authentication tag and the read fails closed -- the repetition
/// bought re-verification of bytes the cipher already authenticates.
fn stage_runtime_custody_object(
    data_dir: &Path,
    principal_id: &str,
    mint_id: Digest32,
    framed: &[u8],
) -> anyhow::Result<()> {
    write_owner_only_bytes(
        &runtime_viewer_object_path(data_dir, principal_id, mint_id),
        framed,
    )
}

/// Reads exactly one framed chunk from the staged object.
///
/// Seeks to the chunk's own range rather than reading the file, so the cost is
/// the chunk rather than the object. Returns `None` when nothing is staged,
/// which is the case for a session that survived a Runtime restart; the caller
/// then falls back to fetching.
fn runtime_custody_staged_object_chunk(
    data_dir: &Path,
    principal_id: &str,
    mint_id: Digest32,
    object_identity: &ChunkedPayloadObjectIdentityV1,
    chunk_index: u32,
) -> Option<Vec<u8>> {
    const MESSAGE: &str = "Runtime custody viewer object chunk is invalid";
    let range = elastos_protected_content_custody::framed_chunk_ranges_v1(
        object_identity.framed_header_bytes(),
        object_identity.plaintext_bytes(),
    )
    .nth(usize::try_from(chunk_index).ok()?)?;
    let path = runtime_viewer_object_path(data_dir, principal_id, mint_id);
    let mut file = fs::File::open(path).ok()?;
    // The staged length is checked against the identity the range was derived
    // from, so a truncated or substituted file is refused before any read.
    if file.metadata().ok()?.len() != object_identity.encrypted_content().ciphertext_bytes() {
        tracing::warn!(
            ?MESSAGE,
            "runtime custody read: staged object length disagrees"
        );
        return None;
    }
    let length = usize::try_from(range.end.checked_sub(range.start)?).ok()?;
    file.seek(SeekFrom::Start(range.start)).ok()?;
    let mut chunk = vec![0u8; length];
    file.read_exact(&mut chunk).ok()?;
    Some(chunk)
}

/// Where one viewer session keeps its v2 Merkle leaves, beside its record so
/// the same cleanup removes it.
fn runtime_viewer_leaves_path(data_dir: &Path, principal_id: &str, mint_id: Digest32) -> PathBuf {
    runtime_viewer_path(data_dir, principal_id, mint_id).with_extension("leaves")
}

/// Stages the verified per-rendition leaves for the life of one v2 session:
/// `"epc-lv01" || head.media_manifest_root || (u32 count || count * 32 B)` per
/// rendition, owner-only.
///
/// The leaves are not trusted on read. The decrypt provider recomputes each
/// leaf from the real segment bytes and checks the proof against the head's
/// root, so a stale or tampered file can only fail a read closed.
fn stage_runtime_custody_media_dash_leaves(
    data_dir: &Path,
    principal_id: &str,
    mint_id: Digest32,
    head: &CencDashMediaIdentityV2,
    leaves: &[Vec<Digest32>],
) -> anyhow::Result<()> {
    let mut bytes = Vec::with_capacity(
        RUNTIME_VIEWER_LEAVES_MAGIC.len()
            + 32
            + leaves.iter().map(|set| 4 + 32 * set.len()).sum::<usize>(),
    );
    bytes.extend_from_slice(RUNTIME_VIEWER_LEAVES_MAGIC);
    bytes.extend_from_slice(head.media_manifest_root().as_bytes());
    for set in leaves {
        bytes.extend_from_slice(&u32::try_from(set.len())?.to_be_bytes());
        for leaf in set {
            bytes.extend_from_slice(leaf.as_bytes());
        }
    }
    write_owner_only_bytes(
        &runtime_viewer_leaves_path(data_dir, principal_id, mint_id),
        &bytes,
    )
}

/// The staged leaves, or `None` unless the file's magic, root, counts and
/// length all agree with the head (the case for a session that outlived its
/// file, or for a stale one).
fn runtime_custody_staged_media_dash_leaves(
    data_dir: &Path,
    principal_id: &str,
    mint_id: Digest32,
    head: &CencDashMediaIdentityV2,
) -> Option<Vec<Vec<Digest32>>> {
    let bytes = fs::read(runtime_viewer_leaves_path(data_dir, principal_id, mint_id)).ok()?;
    let rest = bytes.strip_prefix(RUNTIME_VIEWER_LEAVES_MAGIC)?;
    let (root, mut rest) = rest.split_at_checked(32)?;
    if root != head.media_manifest_root().as_bytes() {
        return None;
    }
    let mut all = Vec::with_capacity(head.renditions().len());
    for rendition in head.renditions() {
        let (count, tail) = rest.split_at_checked(4)?;
        let count = u32::from_be_bytes(count.try_into().ok()?);
        if count != rendition.segment_count() {
            return None;
        }
        let (body, tail) = tail.split_at_checked(usize::try_from(count).ok()?.checked_mul(32)?)?;
        all.push(
            body.chunks_exact(32)
                .map(|leaf| Digest32::new(leaf.try_into().expect("32-byte chunk")))
                .collect(),
        );
        rest = tail;
    }
    rest.is_empty().then_some(all)
}

/// The Merkle audit path of segment `segment` of rendition `rendition_index`,
/// from the staged leaves when they check out and otherwise from the manifest
/// fetched again and verified against the head. A one-segment rendition has an
/// empty path.
#[allow(clippy::too_many_arguments)]
async fn runtime_custody_media_dash_proof(
    data_dir: &Path,
    principal_id: &str,
    mint_id: Digest32,
    head: &CencDashMediaIdentityV2,
    rendition_index: u8,
    segment: u32,
    registry: &ProviderRegistry,
    cid: &str,
) -> anyhow::Result<Vec<Digest32>> {
    let leaves =
        match runtime_custody_staged_media_dash_leaves(data_dir, principal_id, mint_id, head) {
            Some(leaves) => leaves,
            None => {
                let manifest = crate::content::fetch_content_object_manifest(registry, cid)
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE)
                    })?;
                verify_protected_content_dash_manifest(&manifest, head).map_err(|_| {
                    anyhow::anyhow!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE)
                })?
            }
        };
    let rendition_leaves = leaves
        .get(usize::from(rendition_index))
        .ok_or_else(|| anyhow::anyhow!("Runtime custody viewer media part is invalid"))?;
    cenc_dash_merkle_audit_path(
        rendition_leaves,
        usize::try_from(segment)
            .map_err(|_| anyhow::anyhow!("Runtime custody viewer media part is invalid"))?,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody viewer media part is invalid"))
}

fn runtime_storage_write_error(reason: String) -> anyhow::Error {
    anyhow::anyhow!("Runtime custody protected-content storage is unavailable: {reason}")
}

#[cfg(unix)]
pub(crate) fn ensure_owner_only_runtime_storage_parent(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut missing = Vec::new();
    let mut cursor = path;
    loop {
        if cursor.exists() {
            let metadata = fs::symlink_metadata(cursor).map_err(|_| {
                runtime_storage_write_error("parent path is unavailable".to_string())
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                anyhow::bail!(
                    "{}",
                    runtime_storage_write_error(
                        "parent path must be an owner-only directory".to_string()
                    )
                );
            }
            validate_owner_only_metadata_with_error(
                "protected-content runtime storage parent",
                &metadata,
                false,
                runtime_storage_write_error,
            )?;
            break;
        }
        missing.push(cursor.to_path_buf());
        cursor = cursor
            .parent()
            .ok_or_else(|| runtime_storage_write_error("parent path is unavailable".to_string()))?;
    }
    for dir in missing.iter().rev() {
        // A sibling writer racing to bootstrap the same directory chain (for
        // example, another principal's first purchase creating the shared
        // `runtime-purchases/` root) may have created this exact level
        // between our existence check above and this call. Create with mode
        // 0700 atomically (the same idiom `create_owner_only_directory` uses
        // elsewhere in this codebase) rather than `mkdir` then `chmod`: a
        // losing racer's `AlreadyExists` is only ever returned after the
        // winner's `mkdir(..., 0700)` has already completed in the kernel,
        // so there is no window where the directory briefly has loose
        // default permissions for the validation pass below to observe.
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    for dir in missing {
        let metadata = fs::symlink_metadata(&dir)
            .map_err(|_| runtime_storage_write_error("parent path is unavailable".to_string()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            anyhow::bail!(
                "{}",
                runtime_storage_write_error(
                    "parent path must be an owner-only directory".to_string()
                )
            );
        }
        validate_owner_only_metadata_with_error(
            "protected-content runtime storage parent",
            &metadata,
            false,
            runtime_storage_write_error,
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_runtime_storage_parent(parent: &Path) -> anyhow::Result<()> {
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn runtime_storage_temp_path(path: &Path) -> anyhow::Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| runtime_storage_write_error("parent path is unavailable".to_string()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| runtime_storage_write_error("storage path is invalid".to_string()))?;
    for _ in 0..16 {
        let mut nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);
        let candidate = parent.join(format!(
            ".{}.tmp-{}",
            file_name.to_string_lossy(),
            hex::encode(nonce)
        ));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    anyhow::bail!(
        "{}",
        runtime_storage_write_error("temporary path allocation failed".to_string())
    );
}

pub(crate) fn write_owner_only_bytes(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        ensure_owner_only_runtime_storage_parent(parent)?;
        #[cfg(not(unix))]
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        let temp_path = runtime_storage_temp_path(path)?;
        let mut options = fs::OpenOptions::new();
        options
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = options.open(&temp_path)?;
        let result = (|| -> anyhow::Result<()> {
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp_path, path)?;
            if let Some(parent) = path.parent() {
                sync_runtime_storage_parent(parent)?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result?;
    }
    #[cfg(not(unix))]
    {
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, bytes)?;
        fs::rename(temp_path, path)?;
    }
    Ok(())
}

fn runtime_viewer_lifecycle_guards(
) -> &'static StdMutex<HashMap<PathBuf, Weak<tokio::sync::Mutex<()>>>> {
    RUNTIME_VIEWER_LIFECYCLE_GUARDS.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn runtime_viewer_lifecycle_guard_key(
    data_dir: &Path,
    principal_id: &str,
    mint_id: Digest32,
) -> PathBuf {
    runtime_viewer_lifecycle_guard_key_for_path(&runtime_viewer_path(
        data_dir,
        principal_id,
        mint_id,
    ))
}

fn runtime_viewer_lifecycle_guard_key_for_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

fn runtime_viewer_lifecycle_lock_by_key(key: &Path) -> Arc<tokio::sync::Mutex<()>> {
    let mut guards = match runtime_viewer_lifecycle_guards().lock() {
        Ok(guards) => guards,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(lock) = guards.get(key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    guards.insert(key.to_path_buf(), Arc::downgrade(&lock));
    lock
}

struct RuntimeViewerLifecycleExecutionGuard {
    key: PathBuf,
    lock: Arc<tokio::sync::Mutex<()>>,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl Drop for RuntimeViewerLifecycleExecutionGuard {
    fn drop(&mut self) {
        if Arc::strong_count(&self.lock) > 2 {
            return;
        }
        let mut guards = match runtime_viewer_lifecycle_guards().lock() {
            Ok(guards) => guards,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guards
            .get(&self.key)
            .and_then(Weak::upgrade)
            .is_some_and(|lock| Arc::ptr_eq(&lock, &self.lock))
        {
            guards.remove(&self.key);
        }
    }
}

async fn acquire_runtime_custody_viewer_lifecycle_guard(
    data_dir: &Path,
    principal_id: &str,
    mint_id: Digest32,
) -> RuntimeViewerLifecycleExecutionGuard {
    let key = runtime_viewer_lifecycle_guard_key(data_dir, principal_id, mint_id);
    acquire_runtime_custody_viewer_lifecycle_guard_by_key(key).await
}

async fn acquire_runtime_custody_viewer_lifecycle_guard_for_path(
    path: &Path,
) -> RuntimeViewerLifecycleExecutionGuard {
    acquire_runtime_custody_viewer_lifecycle_guard_by_key(
        runtime_viewer_lifecycle_guard_key_for_path(path),
    )
    .await
}

async fn acquire_runtime_custody_viewer_lifecycle_guard_by_key(
    key: PathBuf,
) -> RuntimeViewerLifecycleExecutionGuard {
    let lock = runtime_viewer_lifecycle_lock_by_key(&key);
    let guard = lock.clone().lock_owned().await;
    RuntimeViewerLifecycleExecutionGuard {
        key,
        lock,
        _guard: guard,
    }
}

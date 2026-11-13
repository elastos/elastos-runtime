//! Internal protected-content Runtime coordination foundation.
//!
//! This crate is deliberately source-only. It owns durable Runtime release and
//! mint journal state plus typed Runtime-to-provider seams. It does not expose
//! CEKs, shares, routes, endpoints, Carrier topology, or Library UI.
//! Registration of the Runtime-only provider targets lives in elastos-server.

#[cfg(test)]
mod availability_evidence_tests;
mod coordinator;
mod journal;
mod mint;
mod mint_journal;
mod open;
mod pool_client;
#[cfg(test)]
mod pool_client_tests;
mod pool_session;
#[cfg(test)]
mod pool_session_tests;
#[cfg(test)]
mod test_media;
#[cfg(test)]
mod test_object;

pub use coordinator::{
    wallet_rights_signature_result, RuntimeCustodyProvider, RuntimeProviderCallError,
    RuntimeReleaseCoordinator, RuntimeReleaseCoordinatorError, RuntimeReleaseCoordinatorOutcome,
    RuntimeReleaseNonterminalReason, RuntimeReleaseReconcileOffer, RuntimeRightsProvider,
    RuntimeSelectedProvider,
};
pub use journal::{
    PersistedRuntimeReleaseOperation, RuntimeReleaseAuditPhase, RuntimeReleaseAuditRecord,
    RuntimeReleaseJournal, RuntimeReleaseJournalError, RuntimeReleaseOperationDraft,
    RuntimeReleaseTerminalResult,
};
pub use mint::{
    resolve_recorded_runtime_mint_selected_nodes, resolve_runtime_mint_selected_nodes,
    sign_pool_mint_share, RuntimeMintConfiguredCustodyProvider, RuntimeMintCoordinator,
    RuntimeMintCoordinatorError, RuntimeMintCoordinatorOutcome, RuntimeMintNonterminalReason,
    RuntimeMintPoolProvisioning, RuntimeMintSelectedNode,
};
pub use mint_journal::{
    // Plan B T4.6.
    pool_node_owner_state_root,
    ExclusiveFileLock,
    PersistedRuntimeMint,
    RuntimeAvailabilityBinding,
    RuntimeAvailabilityEvidenceV1,
    RuntimeContentAvailabilityRequirement,
    RuntimeContentIdentityV1,
    RuntimeCustodyTerminalKind,
    RuntimeMediaPreparationRecord,
    RuntimeMediaPreparationState,
    RuntimeMintAbandonedRecordV1,
    RuntimeMintAccessMethod,
    RuntimeMintArchivedAttemptV1,
    RuntimeMintAttemptV1,
    RuntimeMintCreatorDesiredTerms,
    RuntimeMintCreatorEffectBinding,
    RuntimeMintCreatorStage,
    RuntimeMintCreatorState,
    RuntimeMintCreatorTerminalEvidence,
    RuntimeMintDraft,
    RuntimeMintIntent,
    RuntimeMintIntentContentV1,
    RuntimeMintIntentRecordScanV1,
    RuntimeMintIntentRenditionV2,
    RuntimeMintJournal,
    RuntimeMintJournalError,
    RuntimeMintNodeBinding,
    RuntimeMintNodeEffectV1,
    RuntimeMintNodeReceipt,
    RuntimeMintRoyaltyShare,
    RuntimeVerifiedContentAvailability,
    RuntimeVerifiedContentFetchV1,
    RuntimeVerifiedContentIdentityRootV1,
    RUNTIME_MINT_CREATOR_ROYALTY_UNITS,
    RUNTIME_MINT_RESELLER_CUT_MAX,
};
pub use open::{
    bind_buy, cancel_prepared_recipient, cancel_prepared_recipient_with_result_by_handle,
    close_viewer_session, close_viewer_session_with_result, open_viewer_session, prepare_recipient,
    read_viewer_media_part, read_viewer_object_chunk, reject_bearer_playback, RuntimeBuyReceipt,
    RuntimeDecryptProvider, RuntimeOpenError, RuntimeOpenViewerContentV1,
    RuntimeOpenViewerSessionInput, RuntimePreparedRecipient, RuntimePreparedRecipientCancelResult,
    RuntimeProtectedContentPurchaseIntent, RuntimePurchaseEffectAuthority,
    RuntimeVerifiedPurchaseEffect, RuntimeViewerMediaPart, RuntimeViewerObjectChunk,
    RuntimeViewerSession, RuntimeViewerSessionCloseResult,
};
pub use pool_client::{
    content_kind_wire_name, part_json, pool_refusal_from_code, pool_wire_answer,
    resolve_pool_from_candidates, select_session_servers, stripe_index, AcceptAnyPool,
    PoolCallClass, PoolResolveError, PoolResolver, PoolResolverSource, PoolSessionClient,
    PoolSessionTransport, PoolTransportError, PoolTrustCheck, ResolvedPoolV1, POOL_MISMATCH,
    POOL_OP_DESCRIBE, POOL_OP_SESSION_CLOSE, POOL_OP_SESSION_OPEN, POOL_OP_SESSION_PREPARE,
    POOL_OP_SESSION_READ,
};
pub use pool_session::{
    PoolContentIdentityV1, PoolSessionAttestPort, PoolSessionContentPort, PoolSessionContentRefV1,
    PoolSessionDecryptPort, PoolSessionIdV1, PoolSessionOpenV1, PoolSessionOpenedV1,
    PoolSessionPolicyPort, PoolSessionPrepareV1, PoolSessionPreparedV1, PoolSessionReadV1,
    PoolSessionRefusal, PoolSessionServer, PoolSessionSource, PoolStagedContentV1,
    PoolStagedOpenV1, PoolStagedPartV1,
};

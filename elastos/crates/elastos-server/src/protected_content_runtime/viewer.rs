use super::*;

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

pub(crate) const RUNTIME_CUSTODY_PURCHASE_DENIED_MESSAGE: &str =
    "Runtime custody purchase is denied before buy";

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

/// J3-F10 (D6): a pool read that got no part before the session's end (a
/// dropped or bounded server read). Transient: the session is kept, and the
/// Player asks the same read again a few times on a short backoff before it
/// stalls until the rights expiry (C3). Its `code` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeCustodyPoolReadUnavailable;

impl RuntimeCustodyPoolReadUnavailable {
    pub(crate) const CODE: &'static str = "pool_read_unavailable";

    pub(crate) fn error() -> anyhow::Error {
        anyhow::Error::new(Self).context(RUNTIME_CUSTODY_POOL_CONTENT_UNAVAILABLE_MESSAGE)
    }

    /// Whether `error` is, at any depth, this answer.
    pub(crate) fn is(error: &anyhow::Error) -> bool {
        error.downcast_ref::<Self>().is_some()
    }
}

impl std::fmt::Display for RuntimeCustodyPoolReadUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(Self::CODE)
    }
}

impl std::error::Error for RuntimeCustodyPoolReadUnavailable {}

/// `acquisition_stage.stage` of a granted copy. The stage names no
/// transaction: every transaction field of it is empty, because none exists.
pub(crate) const RUNTIME_CUSTODY_GRANT_STAGE: &str = "grant";

pub(crate) const RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE: &str =
    "Runtime custody open is denied before purchase";

pub(crate) const RUNTIME_CUSTODY_OPEN_FINALIZING_MESSAGE: &str =
    "Runtime custody open awaits chain finality of the acquisition";

pub(crate) const RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE: &str =
    "Runtime custody decrypt provider is unavailable";

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

/// Wire identity of the typed answer an app gets when a wallet approval can
/// never complete.
pub(crate) const RUNTIME_CUSTODY_APPROVAL_CLOSED_SCHEMA_V1: &str =
    "elastos.protected-content.approval-closed/v1";
pub(crate) const RUNTIME_CUSTODY_APPROVAL_HANDOFF_EXPIRED_MESSAGE: &str =
    "This request expired. Your wallet may still have sent the transaction. Check your wallet before starting a new request.";

/// Why an outstanding wallet approval will never complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeCustodyApprovalClosedReason {
    /// The person declined it in their wallet.
    Rejected,
    /// It lapsed before anyone answered it.
    Expired,
    /// Local authority expired after dispatch; the wallet may still send.
    HandoffExpired,
}

impl RuntimeCustodyApprovalClosedReason {
    const fn wire_value(self) -> &'static str {
        match self {
            Self::Rejected => "approval_rejected",
            Self::Expired => "approval_expired",
            Self::HandoffExpired => "handoff_expired",
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
/// An expired external handoff may still produce a transaction in the wallet.
/// Its local approval is closed; the person checks the wallet before a new ask.
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
            RuntimeCustodyApprovalClosedReason::HandoffExpired => {
                formatter.write_str(RUNTIME_CUSTODY_APPROVAL_HANDOFF_EXPIRED_MESSAGE)
            }
        }
    }
}

impl std::error::Error for RuntimeCustodyApprovalClosed {}

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

pub(super) const RUNTIME_VIEWER_SCHEMA_V1: &str = "elastos.library.runtime-custody-viewer-state/v1";

static RUNTIME_VIEWER_LIFECYCLE_GUARDS: OnceLock<
    StdMutex<HashMap<PathBuf, Weak<tokio::sync::Mutex<()>>>>,
> = OnceLock::new();

/// The viewer answer a DASH v2 session opens with. The player selects its
/// multi-rendition branch on this schema string.
const RUNTIME_CUSTODY_VIEWER_SCHEMA_V2: &str = "elastos.library.runtime-custody-viewer/v2";

/// First bytes of the staged Merkle leaves of one v2 viewer session.
const RUNTIME_VIEWER_LEAVES_MAGIC: &[u8; 8] = b"epc-lv01";

const MAX_RUNTIME_VIEWER_RECONCILE_MINT_DIRS: usize = 256;

const MAX_RUNTIME_VIEWER_RECONCILE_RECORDS: usize = 1024;

const MAX_RUNTIME_VIEWER_RECORD_BYTES: u64 = 64 * 1024;

const WALLET_PROVIDER_ID: &str = "wallet";

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

pub(super) struct RuntimeDecryptRegistryAdapter {
    registry: Arc<ProviderRegistry>,
}

impl RuntimeDecryptRegistryAdapter {
    pub(super) fn new(registry: Arc<ProviderRegistry>) -> Self {
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
pub(super) fn runtime_media_dash_part(counts: &[u32], part: u32) -> Option<(u8, Option<u32>)> {
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

/// The first part of the interleave that is `segment_index` (an init for
/// `None`): where a session that has read nothing yet starts (D6).
fn runtime_media_dash_first_part(counts: &[u32], segment_index: Option<u32>) -> Option<u32> {
    let total = runtime_media_dash_part_count(counts)?;
    (0..total).find(|part| {
        runtime_media_dash_part(counts, *part).is_some_and(|(_, segment)| segment == segment_index)
    })
}

/// How many parts the interleave has: every init plus every segment.
pub(super) fn runtime_media_dash_part_count(counts: &[u32]) -> Option<u32> {
    counts
        .iter()
        .try_fold(u32::try_from(counts.len()).ok()?, |total, count| {
            total.checked_add(*count)
        })
}

fn runtime_custody_grant_stage_is_empty(stage: &RuntimeCustodyPurchaseStageRecord) -> bool {
    *stage == runtime_custody_grant_stage(&stage.chain_namespace, &stage.network)
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

pub(crate) struct RuntimeCustodyBuyInput {
    pub principal_id: String,
    pub mint_id: String,
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
pub(super) struct RuntimeCustodyViewerRecord {
    pub(super) schema: String,
    pub(super) principal_id: String,
    profile_did: String,
    pub(super) mint_id: String,
    pub(super) content_id: String,
    runtime_session_binding_digest: String,
    audit_request_id: String,
    pub(super) viewer_session_handle: String,
    expires_at: u64,
    #[serde(default)]
    pub(super) next_media_part_index: u32,
    pub(super) lifecycle_status: RuntimeCustodyViewerLifecycleStatus,
    pending_close_result: Option<RuntimeCustodyOpenPendingCloseResult>,
    pending_cancel_result: Option<RuntimeCustodyOpenPendingCancelResult>,
    /// Set while the viewer release waits on the Wallet's managed approval of
    /// the rights-signature request; absent for earlier records.
    #[serde(default)]
    pub(super) pending_release: Option<RuntimeCustodyPendingRelease>,
    /// Plan B T4.4: the server sessions of a viewer opened through the item's
    /// pool. Absent for a viewer of this Home's decrypt provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) pool: Option<crate::protected_content_pool_open::PoolViewerSessions>,
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
pub(super) struct RuntimeCustodyPendingRelease {
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
pub(super) enum RuntimeCustodyViewerLifecycleStatus {
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

pub(super) struct RuntimeCustodyOpenPendingInput<'a> {
    pub(super) principal_id: &'a str,
    pub(super) profile_did: &'a str,
    pub(super) mint_id: Digest32,
    pub(super) content_id: &'a str,
    pub(super) runtime_session_binding: RuntimeSessionBindingV1,
    pub(super) audit_request_id: Digest32,
    pub(super) viewer_session_handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    pub(super) expires_at: u64,
    pub(super) now: u64,
}

impl RuntimeCustodyViewerRecord {
    pub(super) fn from_open_pending(
        input: RuntimeCustodyOpenPendingInput<'_>,
    ) -> anyhow::Result<Self> {
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

    pub(super) fn from_active_session(
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
    pub(super) fn from_pool_opened(
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

    pub(super) fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// D6 (STAB-05, STAB-39): a session that has read nothing yet starts at
    /// the part its first read asks for, and releases strictly in order from
    /// there. A renewed session reads on where the old one ended, and a seek
    /// back into an evicted range reopens at that part, through the same
    /// path. The window is the same one, moved: nothing before or after it
    /// is released out of order, and only the first read of a session (one
    /// per open, one per signed rights request) can place it.
    fn start_at_first_read(&mut self, part: u32) {
        if self.next_media_part_index == 0 {
            self.next_media_part_index = part;
        }
    }

    /// Media parts are released strictly in order: part 0 is the init
    /// segment (no `segment_index`), part n+1 is segment n. The stable
    /// message stays; the detail names the expected and requested parts.
    fn require_media_part_index(&mut self, segment_index: Option<u32>) -> anyhow::Result<()> {
        const MESSAGE: &str = "Runtime custody viewer media part is invalid";
        let requested = match segment_index {
            Some(index) => index.checked_add(1).ok_or_else(|| {
                anyhow::anyhow!("segment index {index} overflows the media part sequence")
                    .context(MESSAGE)
            })?,
            None => 0,
        };
        self.start_at_first_read(requested);
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
    pub(super) fn require_object_chunk_index(
        &self,
        chunk_index: u32,
        chunk_count: u32,
    ) -> anyhow::Result<()> {
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
    pub(super) fn require_media_dash_part(
        &mut self,
        head: &CencDashMediaIdentityV2,
        segment_index: Option<u32>,
    ) -> anyhow::Result<(u8, Option<u32>)> {
        const MESSAGE: &str = "Runtime custody viewer media part is invalid";
        let counts = runtime_media_dash_counts(head);
        // A first read of segment n starts at its first rendition; the Player
        // restarts a segment at rendition 0 after every reopen.
        if let Some(first) = runtime_media_dash_first_part(&counts, segment_index) {
            self.start_at_first_read(first);
        }
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

    pub(super) fn mark_media_part_read(&mut self, now: u64) -> anyhow::Result<()> {
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

    pub(super) fn mark_cleanup_pending(&mut self, now: u64) {
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

    pub(super) fn mark_terminal(&mut self, result: RuntimeViewerSessionCloseResult, now: u64) {
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
pub(super) struct RuntimeViewerReleaseOperationInput<'a> {
    pub(super) data_dir: &'a Path,
    pub(super) principal_id: &'a str,
    pub(super) proof_binding_id: &'a str,
    pub(super) signed_rights: &'a WalletSignedRightsRequestV1,
    pub(super) prepared: &'a RuntimePreparedRecipient,
    pub(super) policy: &'a ResolvedRuntimeRightsPolicy,
    pub(super) custody_epoch: &'a SignedCustodyEpochV1,
    pub(super) audit_request_id: RuntimeReleaseAuditIdV1,
}

/// Builds the Runtime release operation for one viewer open, valid from `now`.
///
/// Everything here is signed by this Runtime over the Wallet's signed rights
/// request, which lives for the whole approval window, so a later `now` gives
/// a fresh operation without asking the Wallet again. The rights request, the
/// recipient and the audit ID stay those of the open.
pub(super) fn runtime_viewer_release_operation_at(
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

/// Where a viewer's access to an item comes from. A completed purchase by
/// this principal is today's only source; another source is one more variant.
enum RuntimeCustodyViewerAccess {
    Purchase(RuntimeCustodyPurchaseRecord),
}

fn resolve_runtime_custody_viewer_access(
    data_dir: &Path,
    principal_id: &str,
    mint_id: Digest32,
) -> anyhow::Result<RuntimeCustodyViewerAccess> {
    let purchase = load_runtime_custody_purchase(data_dir, principal_id, mint_id)?
        .ok_or_else(runtime_custody_open_denied)?;
    if purchase.principal_id != principal_id {
        return Err(runtime_custody_open_denied());
    }
    Ok(RuntimeCustodyViewerAccess::Purchase(purchase))
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
    let RuntimeCustodyViewerAccess::Purchase(purchase) =
        resolve_runtime_custody_viewer_access(data_dir, &input.principal_id, mint_id)?;
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
            // D6 (STAB-40, J3-F9): a new launch by the same principal (the
            // record's principal, profile, mint and content were checked
            // above) takes over a live viewer. The old viewer is settled
            // (closed at its servers, its secret dropped) and this launch
            // opens fresh, instead of a final "different account" refusal
            // for the rest of the old session's life.
            RuntimeCustodyViewerLifecycleStatus::Active
                if !record.matches_runtime_session_binding(&runtime_session_binding)
                    && !record.is_expired(viewer_now) =>
            {
                tracing::debug!(
                    mint_id = %hex::encode(mint_id.as_bytes()),
                    "runtime custody open: a new launch takes over the live viewer"
                );
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
            RuntimeCustodyViewerLifecycleStatus::OpenPending
            | RuntimeCustodyViewerLifecycleStatus::Active
            | RuntimeCustodyViewerLifecycleStatus::CleanupPending => {
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
    // J3-F5: a failed fresh check is an unavailable (resumable) answer, so a
    // Player polling a pending approval keeps polling.
    let (draft, fresh_availability) = verify_fresh_runtime_custody_availability(
        data_dir,
        &registry,
        &listing,
        mint_id,
        crate::auth::now_ts(),
    )
    .await
    .map_err(|error| {
        if error
            .chain()
            .any(|cause| cause.is::<RuntimeCustodyOpenProgress>())
        {
            error
        } else {
            runtime_custody_open_unavailable(
                RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE,
                &error,
            )
        }
    })?;
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
    let sealed_policy = listing.package.sealed_policy()?;
    let buy = match &sealed_policy {
        Some(policy) => buy.with_sealed_policy(policy)?,
        None => buy,
    };
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
                    // IND F9: the copy goes back to Buy on the card and the
                    // catalog join; a later grant records it again.
                    if let Err(error) = retire_runtime_custody_granted_purchase(data_dir, &purchase)
                    {
                        tracing::warn!(
                            error = %format!("{error:#}"),
                            "runtime custody open: a lapsed grant record was not removed"
                        );
                    }
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
                    sealed_policy,
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
    let resolved_policy = match sealed_policy {
        Some(body) => body
            .policy_identity()
            .map(|identity| ResolvedRuntimeRightsPolicy { body, identity })
            .map_err(anyhow::Error::from),
        None => {
            resolve_runtime_rights_policy(
                registry.as_ref(),
                draft.encrypted_content(),
                draft.content_access_id(),
                RightsActionV1::View,
            )
            .await
        }
    };
    let policy = match resolved_policy {
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
pub(super) fn runtime_custody_viewer_response_for(
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
pub(super) fn runtime_custody_pool_viewer_response(
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
pub(super) fn runtime_custody_viewer_media_part_response(
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
pub(super) fn runtime_custody_viewer_object_part_response(
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
    sealed_policy: Option<RightsPolicyBodyV1>,
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
        sealed_policy: input.sealed_policy,
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
    sealed_policy: Option<RightsPolicyBodyV1>,
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
        if let Some(policy) = &self.sealed_policy {
            return Ok((policy.clone(), policy.policy_identity()?));
        }
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
/// secret here (a restart) settles and answers renewal too (J3-F2), so the
/// Player's reopen starts fresh.
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
        // The session's end, and (J3-F2) a record whose secret is gone, as
        // after a restart: both settle the record and answer the renewal
        // code the Player reopens on.
        Err(
            crate::protected_content_pool_open::PoolReadError::NoSecret
            | crate::protected_content_pool_open::PoolReadError::RenewalRequired,
        ) => {
            let _ = settle_runtime_custody_viewer_cleanup(
                data_dir,
                registry,
                listing,
                principal_id,
                mint_id,
                record,
            )
            .await;
            tracing::debug!("runtime custody viewer: the pool session reached its end");
            return Err(RuntimeCustodyPoolSessionRenewalRequired::error());
        }
        // J3-F10 (D6): the pool gave no part before the session's end. The
        // typed transient code lets the Player ask again within seconds; the
        // words name the pool, not the decrypt provider.
        Err(
            crate::protected_content_pool_open::PoolReadError::ServerLost
            | crate::protected_content_pool_open::PoolReadError::Invalid,
        ) => return Err(RuntimeCustodyPoolReadUnavailable::error()),
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

/// Remove `granted`'s record once the chain no longer grants the copy (IND
/// F9), under the purchase ledger lock, and only while the record on disk is
/// still that grant. A purchase that replaced it is left exactly as it is.
fn retire_runtime_custody_granted_purchase(
    data_dir: &Path,
    granted: &RuntimeCustodyPurchaseRecord,
) -> anyhow::Result<bool> {
    remove_runtime_custody_purchase_if(data_dir, granted, |current| {
        matches!(
            current.progress,
            RuntimeCustodyPurchaseProgress::Granted { .. }
        ) && current.created_at == granted.created_at
    })
}

pub(super) fn load_runtime_custody_viewer_record(
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

pub(super) fn validate_runtime_custody_viewer_record_identity(
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

pub(super) fn persist_runtime_custody_viewer_record(
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

pub(super) async fn settle_runtime_custody_viewer_cleanup(
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

pub(super) fn reconstructed_buy_receipt(
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

pub(super) struct RuntimeReleaseWalletInvocation<'a> {
    pub(super) principal_id: &'a str,
    pub(super) account_id: &'a str,
    pub(super) proof_binding_id: &'a str,
    pub(super) session_id: &'a str,
    pub(super) grant_id: &'a str,
    pub(super) mint_id: Digest32,
    pub(super) runtime_session_binding: RuntimeSessionBindingV1,
}

/// What the Wallet answered to the viewer release rights-signature request.
#[derive(Debug)]
pub(super) enum RuntimeReleaseWalletOutcome {
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
pub(super) async fn invoke_runtime_release_wallet(
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
pub(super) fn wallet_signed_rights_from_bytes(
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
pub(super) async fn fetch_runtime_custody_open_media_dash(
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
pub(super) async fn runtime_custody_object_chunk_for_read(
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

fn parse_viewer_handle_hex(
    value: &str,
) -> anyhow::Result<[u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]> {
    let bytes = decode_hex_bytes(value)
        .map_err(|_| anyhow::anyhow!("Runtime custody viewer session is unavailable"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Runtime custody viewer session is unavailable"))
}

pub(super) fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
}

pub(super) fn runtime_open_audit_id(
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
pub(super) fn derive_runtime_custody_session_binding(
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

/// The ONE viewer capsule admitted for a content kind. Media opens only in
/// `elacity-player`, objects only in `elacity-reader`; there is no arm that
/// admits both, and no default.
pub(super) fn expected_runtime_custody_viewer_capsule(
    content_identity: &RuntimeContentIdentityV1,
) -> &'static str {
    match content_identity {
        RuntimeContentIdentityV1::Media(_) | RuntimeContentIdentityV1::MediaDash(_) => {
            ELACITY_PLAYER_CAPSULE_ID
        }
        RuntimeContentIdentityV1::Object(_) => ELACITY_READER_CAPSULE_ID,
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
pub(super) fn runtime_custody_viewer_media_dash_public_response(
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

pub(super) fn runtime_viewer_path(
    data_dir: &Path,
    principal_id: &str,
    mint_id: Digest32,
) -> PathBuf {
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
pub(super) fn runtime_viewer_object_path(
    data_dir: &Path,
    principal_id: &str,
    mint_id: Digest32,
) -> PathBuf {
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
pub(super) fn runtime_viewer_leaves_path(
    data_dir: &Path,
    principal_id: &str,
    mint_id: Digest32,
) -> PathBuf {
    runtime_viewer_path(data_dir, principal_id, mint_id).with_extension("leaves")
}

/// Stages the verified per-rendition leaves for the life of one v2 session:
/// `"epc-lv01" || head.media_manifest_root || (u32 count || count * 32 B)` per
/// rendition, owner-only.
///
/// The leaves are not trusted on read. The decrypt provider recomputes each
/// leaf from the real segment bytes and checks the proof against the head's
/// root, so a stale or tampered file can only fail a read closed.
pub(super) fn stage_runtime_custody_media_dash_leaves(
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
pub(super) async fn runtime_custody_media_dash_proof(
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

pub(super) struct RuntimeViewerLifecycleExecutionGuard {
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

pub(super) async fn acquire_runtime_custody_viewer_lifecycle_guard(
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

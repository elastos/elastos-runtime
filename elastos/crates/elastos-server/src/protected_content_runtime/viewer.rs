use super::*;

pub(crate) const ELACITY_PLAYER_CAPSULE_ID: &str = "elacity-player";

pub(crate) const RUNTIME_CUSTODY_PURCHASE_DENIED_MESSAGE: &str =
    "Runtime custody purchase is denied before buy";

pub(crate) const RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE: &str =
    "Runtime custody open is denied before purchase";

pub(crate) const RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE: &str =
    "Runtime custody decrypt provider is unavailable";

/// The Wallet holds the viewer release rights-signature request as a pending
/// managed approval; the caller approves it in the Wallet and re-issues the
/// identical open, which resumes the persisted release.
pub(crate) const RUNTIME_CUSTODY_OPEN_PENDING_MESSAGE: &str =
    "Runtime custody viewer release is pending exact Wallet approval";

pub(super) const RUNTIME_VIEWER_SCHEMA_V1: &str = "elastos.library.runtime-custody-viewer-state/v1";

static RUNTIME_VIEWER_LIFECYCLE_GUARDS: OnceLock<
    StdMutex<HashMap<PathBuf, Weak<tokio::sync::Mutex<()>>>>,
> = OnceLock::new();

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

async fn invoke_decrypt_provider(
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
    pub(crate) access_evidence: RuntimeCustodyPurchaseAccessEvidenceRecord,
    pub(crate) confirmed_at: u64,
    pub(crate) bought_at: u64,
}

pub(crate) struct RuntimeCustodyBuyInput {
    pub principal_id: String,
    pub mint_id: String,
}

pub(crate) struct RuntimeCustodyViewerOpenInput {
    pub principal_id: String,
    pub mint_id: String,
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
    created_at: u64,
    updated_at: u64,
}

/// Everything a resumed open needs to replay the exact rights-signature
/// request against the recipient the decrypt provider still holds under the
/// viewer session handle. The recipient private key never leaves the decrypt
/// provider; only its public identity is persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct RuntimeCustodyPendingRelease {
    wallet_request_hex: String,
    approval_request_id: String,
    recipient_public_key_hex: String,
    recipient_encryption_suite_id: String,
    recipient_key_id_hex: String,
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
            created_at: now,
            updated_at: now,
        })
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

    pub(super) fn mark_cleanup_pending(&mut self, now: u64) {
        self.lifecycle_status = RuntimeCustodyViewerLifecycleStatus::CleanupPending;
        self.pending_close_result = None;
        self.pending_cancel_result = None;
        self.updated_at = now;
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
) -> anyhow::Result<(RuntimeMintDraft, RuntimeVerifiedContentAvailability)> {
    let expected_mint_id = hex::encode(mint_id.as_bytes());
    if listing.package.mint_id != expected_mint_id {
        tracing::warn!(line = line!(), "Runtime custody purchase denied before buy");
        anyhow::bail!(RUNTIME_CUSTODY_PURCHASE_DENIED_MESSAGE);
    }
    let decoded = listing.package.decode_and_validate()?;
    verify_runtime_portable_media(
        data_dir,
        registry,
        &listing.package,
        &decoded,
        now_unix_seconds,
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
        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE))?;
    if purchase.principal_id != principal_id {
        anyhow::bail!(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE);
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
    let listing = load_runtime_custody_listing(data_dir, mint_id)?
        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE))?;
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
        launch_id,
        proof_binding_id,
        session_id,
        grant_id,
        mint_id,
    )?;
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
            anyhow::bail!(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE);
        }
        let viewer_now = crate::auth::now_ts();
        match record.lifecycle_status {
            RuntimeCustodyViewerLifecycleStatus::Active
                if record.matches_runtime_session_binding(&runtime_session_binding)
                    && !record.is_expired(viewer_now) =>
            {
                let session =
                    record.to_runtime_viewer_session(asset.media_identity.encrypted_content())?;
                return runtime_custody_viewer_public_response(
                    &asset.media_identity,
                    mint_id,
                    session.viewer_session_handle(),
                    session.expires_at(),
                );
            }
            RuntimeCustodyViewerLifecycleStatus::OpenPending
                if record.pending_release.is_some()
                    && record.matches_runtime_session_binding(&runtime_session_binding)
                    && !record.is_expired(viewer_now) =>
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
                anyhow::bail!(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE);
            }
            RuntimeCustodyViewerLifecycleStatus::OpenPending
            | RuntimeCustodyViewerLifecycleStatus::Active
            | RuntimeCustodyViewerLifecycleStatus::CleanupPending => {
                if record.lifecycle_status == RuntimeCustodyViewerLifecycleStatus::Active
                    && !record.is_expired(viewer_now)
                    && !record.matches_runtime_session_binding(&runtime_session_binding)
                {
                    anyhow::bail!(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE);
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
    if fresh_availability.content_cid() != purchase.cid {
        anyhow::bail!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE);
    }
    let buy = reconstructed_buy_receipt(&draft, &fresh_availability, &purchase, &profile_did)?;
    let composition = load_runtime_custody_composition(data_dir, registry.clone())?
        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_COMPOSITION_MISSING_MESSAGE))?;
    let (device_key, _) =
        crate::collaboration_profile_authority::load_existing_device_signing_key(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    let runtime_issuer = RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())
        .map_err(|_| anyhow::anyhow!("local Runtime device signing key is invalid"))?;
    let (media_identity, protected_init) =
        fetch_runtime_custody_open_media(registry.as_ref(), &purchase.cid, draft.media_identity())
            .await?;
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
                now + 60,
            )
            .await
            {
                Ok(prepared) => prepared,
                Err(_) => anyhow::bail!(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE),
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
                return Err(anyhow::anyhow!(
                    "{}:{}: approval_request_id={approval_request_id}",
                    file!(),
                    line!()
                )
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
    let release_request = match KeyReleaseRequestV1::new(
        signed_rights.request().binding().clone(),
        signed_rights
            .request()
            .request_hash()
            .map_err(release_unavailable!())?,
        RightsActionV1::View,
        prepared.recipient_identity().clone(),
        now.saturating_sub(5),
        now + 55,
        ReplayNonce16::new(audit_nonce_bytes(audit_request_id)),
    ) {
        Ok(request) => request,
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
    let evidence_request = match RightsEvaluationEvidenceRequestV1::new(
        signed_rights.request().binding().clone(),
        policy.identity().clone(),
    ) {
        Ok(request) => request,
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
    let localhost_root = crate::auth::principal_localhost_root(&input.principal_id);
    let operation = match assemble_protected_content_runtime_release_operation(
        data_dir,
        &input.principal_id,
        &localhost_root,
        proof_binding_id,
        RuntimeReleaseOperationAssemblyInput {
            rights_request: signed_rights,
            release_request,
            recipient_public_key: *prepared.recipient_public_key(),
            recipient_identity: prepared.recipient_identity().clone(),
            policy_body: policy.body().clone(),
            evidence_request,
            custody_epoch: composition.signed_epoch.clone(),
            audit_request_id,
            issued_at: now.saturating_sub(3),
            expires_at: now + 50,
        },
        now,
    ) {
        Ok(operation) => operation,
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
            operation.clone(),
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
            tracing::debug!(
                ?reason,
                "runtime custody open: release nonterminal, resuming exact operation"
            );
            match coordinator
                .resume_exact(operation_hash, crate::auth::now_ts())
                .await
            {
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
                        "release resume did not yield contributions: {other:?}"
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
                "release did not yield contributions: {other:?}"
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
    let session = match open_viewer_session(
        &decrypt,
        &RuntimeOpenViewerSessionInput {
            buy: &buy,
            prepared_recipient: &prepared,
            signed_runtime_release_operation: &operation,
            expected_terminal_issuer,
            content_key_commitment: draft.content_key_commitment(),
            media_identity: &media_identity,
            protected_init_segment: &protected_init,
            signed_node_contributions: &contributions,
            signed_terminal_receipt: &terminal_receipt,
            now_unix_seconds: crate::auth::now_ts(),
        },
    )
    .await
    {
        Ok(session) => session,
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
            anyhow::bail!(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE);
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
    runtime_custody_viewer_public_response(draft.media_identity(), mint_id, &handle, expires_at)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn read_runtime_custody_viewer(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    principal_id: &str,
    mint_id_hex: &str,
    handle_hex: &str,
    launch_id: Option<&str>,
    proof_binding_id: Option<&str>,
    session_id: Option<&str>,
    grant_id: Option<&str>,
    segment_index: Option<u32>,
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
    let now = crate::auth::now_ts();
    let session = match record.lifecycle_status {
        RuntimeCustodyViewerLifecycleStatus::Active if !record.is_expired(now) => {
            record.to_runtime_viewer_session(asset.media_identity.encrypted_content())?
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
    record.require_media_part_index(segment_index)?;
    let selector = if let Some(segment_index) = segment_index {
        let path = protected_content_segment_path(
            usize::try_from(segment_index)
                .map_err(|_| anyhow::anyhow!("Runtime custody viewer media part is invalid"))?,
        );
        if usize::try_from(segment_index).ok()
            >= Some(asset.media_identity.encrypted_segments().len())
        {
            anyhow::bail!("Runtime custody viewer media part is invalid");
        }
        let encrypted =
            crate::content::fetch_bytes_via_provider(registry.as_ref(), &purchase.cid, Some(&path))
                .await
                .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_AVAILABILITY_UNAVAILABLE_MESSAGE))?;
        ViewerMediaPartSelectorV1::segment(segment_index, encrypted)
            .map_err(|_| anyhow::anyhow!("Runtime custody viewer media part is invalid"))?
    } else {
        ViewerMediaPartSelectorV1::init()
    };
    let part = read_viewer_media_part(
        &RuntimeDecryptRegistryAdapter::new(registry.clone()),
        &session,
        selector,
        crate::auth::now_ts(),
    )
    .await
    .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_DECRYPT_UNAVAILABLE_MESSAGE))?;
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
    Ok(json!({
        "schema": "elastos.library.runtime-custody-viewer-part/v1",
        "mint_id": hex::encode(mint_id.as_bytes()),
        "viewer_session_handle": handle_hex,
        "encoding": "base64",
        "data": base64::engine::general_purpose::STANDARD.encode(part.clear_media_part()),
    }))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn close_runtime_custody_viewer(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    principal_id: &str,
    mint_id_hex: &str,
    handle_hex: &str,
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
        RuntimeCustodyViewerLifecycleStatus::Active => {
            let session =
                record.to_runtime_viewer_session(asset.media_identity.encrypted_content())?;
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
    if purchase.schema != RUNTIME_PURCHASE_SCHEMA_V1
        || package.mint_id != hex::encode(mint_id.as_bytes())
        || purchase.principal_id != principal_id
        || purchase.profile_did != profile_did
        || purchase.mint_id != package.mint_id
        || purchase.content_id != package.content_id
        || purchase.cid != package.content_cid
        || purchase.listing_sha256 != listing.portable_package_digest()
        || !purchase
            .seller_address
            .eq_ignore_ascii_case(&package.seller_address)
        || purchase.chain_namespace != package.chain_namespace
        || purchase.network != package.network
        || !purchase.ledger.eq_ignore_ascii_case(&package.ledger)
        || !purchase.token_id.eq_ignore_ascii_case(&package.token_id)
        || !purchase.operative.eq_ignore_ascii_case(&package.operative)
        || purchase.price != package.price
        || !purchase.pay_token.eq_ignore_ascii_case(&package.pay_token)
        || purchase.buy_stage.chain_namespace != package.chain_namespace
        || purchase.buy_stage.network != package.network
        || purchase
            .payment_processor
            .as_deref()
            .map(str::to_ascii_lowercase)
            != package
                .payment_processor
                .as_deref()
                .map(str::to_ascii_lowercase)
    {
        anyhow::bail!(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE);
    }
    let RuntimeCustodyPurchaseProgress::Complete { terminal } = &purchase.progress else {
        anyhow::bail!(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE);
    };
    if !terminal.access_evidence.has_access
        || terminal.access_evidence.network != package.network
        || terminal.access_evidence.chain_id != chain_id
        || !terminal
            .access_evidence
            .wallet
            .eq_ignore_ascii_case(&purchase.address)
        || terminal.access_evidence.content_access_id != package.content_access_id
    {
        anyhow::bail!(RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE);
    }
    package.decode_and_validate()
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
    if runtime_protected_content_id(asset.media_identity.encrypted_content())? != record.content_id
    {
        anyhow::bail!("viewer record content does not match the durable mint");
    }
    let _ = record.audit_request_id()?;
    let _ = record.viewer_session_handle_bytes()?;
    if record.expires_at == 0 {
        anyhow::bail!("viewer record expiry is invalid");
    }
    let max_media_part_index = u32::try_from(asset.media_identity.encrypted_segments().len())
        .map_err(|_| anyhow::anyhow!("viewer record media position is invalid"))?
        .saturating_add(1);
    if record.next_media_part_index > max_media_part_index {
        anyhow::bail!("viewer record media position is invalid");
    }
    if record.lifecycle_status != RuntimeCustodyViewerLifecycleStatus::OpenPending {
        let _ = record.to_runtime_viewer_session(asset.media_identity.encrypted_content())?;
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
    let decrypt = RuntimeDecryptRegistryAdapter::new(registry);
    match record.lifecycle_status {
        RuntimeCustodyViewerLifecycleStatus::OpenPending => {
            let session =
                record.to_runtime_viewer_session(asset.media_identity.encrypted_content())?;
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
            persist_runtime_custody_viewer_record(data_dir, principal_id, mint_id, &record)?;
            Ok(record)
        }
        RuntimeCustodyViewerLifecycleStatus::Active
        | RuntimeCustodyViewerLifecycleStatus::CleanupPending => {
            let session =
                record.to_runtime_viewer_session(asset.media_identity.encrypted_content())?;
            match close_viewer_session_with_result(&decrypt, &session).await {
                Ok(result) => {
                    record.mark_terminal(result, crate::auth::now_ts());
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
    availability: &RuntimeVerifiedContentAvailability,
    purchase: &RuntimeCustodyPurchaseRecord,
    current_profile_did: &str,
) -> anyhow::Result<elastos_protected_content_runtime::RuntimeBuyReceipt> {
    if purchase.profile_did != current_profile_did {
        return Err(runtime_open_error(
            elastos_protected_content_runtime::RuntimeOpenError::ChainEvidence,
        ));
    }
    let profile_identity = profile_identity_from_did(current_profile_did)?;
    let RuntimeCustodyPurchaseProgress::Complete { terminal } = &purchase.progress else {
        return Err(runtime_open_error(
            elastos_protected_content_runtime::RuntimeOpenError::ChainEvidence,
        ));
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
            purchase.buy_stage.to.clone(),
            purchase.buy_stage.value.clone(),
            purchase.buy_stage.data.clone(),
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody chain evidence is invalid"))?,
        RuntimePurchaseEffectAuthority::new(
            purchase.principal_id.clone(),
            purchase.account_id.clone(),
            purchase.address.clone(),
            purchase.buy_stage.approval_request_id.clone(),
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
    /// A managed account needs the principal's explicit approval first; the
    /// exact request must be replayed once the approval is completed.
    PendingApproval {
        request_bytes: Vec<u8>,
        approval_request_id: String,
    },
}

/// Builds the exact wallet rights-signature request for this open, or
/// decodes the persisted one when a pending release is being resumed (the
/// rights request is bound to the recipient identity, so a resumed release
/// must replay byte-identical bytes for the Wallet to return its stored
/// result).
fn runtime_release_wallet_request(
    buy: &elastos_protected_content_runtime::RuntimeBuyReceipt,
    recipient: &RecipientKeyIdentityV1,
    invocation: &RuntimeReleaseWalletInvocation<'_>,
    replay_request: Option<&[u8]>,
    now: u64,
) -> anyhow::Result<(WalletProviderRequestV2, RightsRequestV1)> {
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
        let rights_request = RightsRequestV1::from_canonical_bytes(
            &decode_hex_bytes(canonical_rights_request_hex).map_err(release_unavailable!())?,
        )
        .map_err(release_unavailable!())?;
        if rights_request.recipient() != recipient {
            return Err(release_unavailable_missing!()());
        }
        return Ok((wallet_request, rights_request));
    }
    let mut replay_nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut replay_nonce);
    let rights_request = RightsRequestV1::new(
        buy.binding_for_session(invocation.runtime_session_binding)
            .map_err(release_unavailable!())?,
        buy.action(),
        recipient.clone(),
        now.saturating_sub(5),
        now + 180,
        ReplayNonce16::new(replay_nonce),
    )
    .map_err(release_unavailable!())?;
    let mut request_entropy = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut request_entropy);
    let context = VerifiedWalletInvocationContext::new(
        invocation.principal_id.to_string(),
        invocation.session_id,
        Some(invocation.proof_binding_id.to_string()),
        invocation.grant_id,
        "runtime",
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

pub(super) async fn invoke_runtime_release_wallet(
    registry: &ProviderRegistry,
    buy: &elastos_protected_content_runtime::RuntimeBuyReceipt,
    recipient: &RecipientKeyIdentityV1,
    invocation: RuntimeReleaseWalletInvocation<'_>,
    replay_request: Option<&[u8]>,
    now: u64,
) -> anyhow::Result<RuntimeReleaseWalletOutcome> {
    let (wallet_request, rights_request) =
        runtime_release_wallet_request(buy, recipient, &invocation, replay_request, now)?;
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
    // A managed account answers with its approval record until the principal
    // approves it in the Wallet; the exact request is then replayed.
    let payload = data
        .get("result")
        .and_then(|result| result.get("data"))
        .unwrap_or(data);
    if payload
        .get("requires_approval")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let approval_request_id = payload
            .get("approval_request")
            .and_then(|approval| approval.get("request_id"))
            .and_then(Value::as_str)
            .ok_or_else(release_unavailable_missing!())?
            .to_string();
        tracing::debug!(
            %approval_request_id,
            "runtime custody open: viewer release awaits exact Wallet approval"
        );
        return Ok(RuntimeReleaseWalletOutcome::PendingApproval {
            request_bytes,
            approval_request_id,
        });
    }
    let signed_rights = wallet_signed_rights_from_bytes(&request_bytes, &response_bytes)
        .map_err(release_unavailable!())?;
    if signed_rights.request() != &rights_request {
        return Err(release_unavailable!()(
            "wallet signed a rights request other than the one issued",
        ));
    }
    Ok(RuntimeReleaseWalletOutcome::Signed {
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
) -> Result<WalletSignedRightsRequestV1, String> {
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
    WalletSignedRightsRequestV1::from_canonical_bytes(&bytes)
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

pub(super) fn derive_runtime_custody_session_binding(
    principal_id: &str,
    profile_did: &str,
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
    hasher.update(b"elastos.protected-content.runtime-session-binding.v2");
    update_length_prefixed_session_field(&mut hasher, principal_id.as_bytes())?;
    update_length_prefixed_session_field(&mut hasher, profile_did.as_bytes())?;
    update_length_prefixed_session_field(&mut hasher, ELACITY_PLAYER_CAPSULE_ID.as_bytes())?;
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

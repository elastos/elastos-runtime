use super::*;

const MEDIA_PROVIDER_INPUT_FILE_NAME: &str = "input.bin";

const RUNTIME_MEDIA_PREPARATION_RECONCILIATION_MESSAGE: &str =
    "Runtime custody media preparation requires settlement reconciliation";

/// Publishes and verifies the one immutable CENC/fMP4 object Runtime may later
/// record as availability evidence. The directory is provider input only: no
/// file path, bytes, or receipt JSON crosses this boundary into Runtime state.
pub async fn publish_and_verify_protected_content_availability(
    registry: &ProviderRegistry,
    protected_content_dir: &Path,
    media_identity: &CencFmp4MediaIdentityV1,
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: impl Fn() -> u64,
) -> anyhow::Result<RuntimeVerifiedContentAvailability> {
    validate_protected_content_availability_requirement(requirement)?;
    verify_protected_content_directory(protected_content_dir, media_identity)?;
    // The receipt is verified against `requirement.policy()` below, and the
    // content plane records whatever `availability_policy` the publish
    // request names (its own `network_default` otherwise), so the policy has
    // to travel with the publish request.
    let publish_requirements = crate::content::ContentPublishRequirements::new(
        requirement.minimum_replicas(),
        PROTECTED_CONTENT_REQUIRE_LIVE_MULTI_PEER_PROOF,
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
    verify_protected_content_manifest_and_files(registry, &content_cid, &manifest, media_identity)
        .await?;
    // The receipt's `checked_at` is stamped when the replication round
    // finishes, which can be well over the future-skew allowance after this
    // function was entered (three-node replication takes tens of seconds),
    // so the freshness reference is sampled now, not by the caller.
    let now_unix_seconds = now_unix_seconds();
    verify_protected_content_receipt(
        &content_cid,
        &manifest,
        &receipt,
        media_identity,
        requirement,
        now_unix_seconds,
    )
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
    pub price: String,
    pub source_storage: String,
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

pub(super) async fn prepare_runtime_custody_library_source(
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
    let record = match journal.load_media_preparation(expected.request_id()) {
        Ok(existing) => {
            if !existing.same_authority_as(&expected) {
                anyhow::bail!(
                    "Runtime custody media preparation conflicts with existing authority"
                );
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
                record,
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
            let output = RuntimePreparedMediaProviderOutput {
                schema: MEDIA_PROVIDER_PREPARED_MEDIA_SCHEMA_V1.to_string(),
                mime_type: MEDIA_PROVIDER_OUTPUT_MIME_TYPE_V1.to_string(),
                codecs: MEDIA_PROVIDER_OUTPUT_CODECS_V1.to_string(),
            };
            let (media, output_receipt_digest) =
                load_validated_runtime_prepared_media(&operation_root, &output)?;
            if record.output_receipt_digest() != Some(output_receipt_digest) {
                anyhow::bail!("Runtime custody media preparation output is invalid");
            }
            return Ok(RuntimeLibraryMediaPreparation::Prepared(
                RuntimePreparedLibraryPublish {
                    input: RuntimeCustodyLibraryPublishInput {
                        object_uri: source.object_uri.clone(),
                        principal_id: source.principal_id.clone(),
                        mime_type: media.mime_type,
                        codecs: media.codecs,
                        wallet_account_id: source.wallet_account_id.clone(),
                        wallet_account_address: source.wallet_account_address.clone(),
                        creator_mint_source_digest: source.creator_mint_source_digest,
                        copies: source.copies.clone(),
                        price: source.price.clone(),
                        clear_init_segment: media.clear_init_segment,
                        clear_segments: media.clear_segments,
                        source_storage: source.source_storage.clone(),
                    },
                    request_id: record.request_id(),
                    output_receipt_digest,
                    operation_root,
                },
            ));
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
    let (media, output_receipt_digest) =
        match load_validated_runtime_prepared_media(&operation_root, &output) {
            Ok(prepared) => prepared,
            Err(error) => {
                journal
                    .mark_media_preparation_failed(record.request_id())
                    .map_err(|_| {
                        anyhow::anyhow!(RUNTIME_MEDIA_PREPARATION_RECONCILIATION_MESSAGE)
                    })?;
                let _ = fs::remove_dir_all(&operation_root);
                return Err(error);
            }
        };
    journal
        .mark_media_preparation_prepared(record.request_id(), output_receipt_digest)
        .map_err(|_| anyhow::anyhow!(RUNTIME_MEDIA_PREPARATION_RECONCILIATION_MESSAGE))?;
    Ok(RuntimeLibraryMediaPreparation::Prepared(
        RuntimePreparedLibraryPublish {
            input: RuntimeCustodyLibraryPublishInput {
                object_uri: source.object_uri.clone(),
                principal_id: source.principal_id.clone(),
                mime_type: media.mime_type,
                codecs: media.codecs,
                wallet_account_id: source.wallet_account_id.clone(),
                wallet_account_address: source.wallet_account_address.clone(),
                creator_mint_source_digest: source.creator_mint_source_digest,
                copies: source.copies.clone(),
                price: source.price.clone(),
                clear_init_segment: media.clear_init_segment,
                clear_segments: media.clear_segments,
                source_storage: source.source_storage.clone(),
            },
            request_id: record.request_id(),
            output_receipt_digest,
            operation_root,
        },
    ))
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
            let input = RuntimeCustodyLibraryPublishInput {
                object_uri: source.object_uri,
                principal_id: source.principal_id,
                mime_type: persisted.draft().media_identity().mime_type().to_string(),
                codecs: persisted.draft().media_identity().codecs().to_string(),
                wallet_account_id: source.wallet_account_id,
                wallet_account_address: source.wallet_account_address,
                creator_mint_source_digest: source.creator_mint_source_digest,
                copies: source.copies,
                price: source.price,
                clear_init_segment: Vec::new(),
                clear_segments: Vec::new(),
                source_storage: source.source_storage,
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
    let composition = load_runtime_custody_composition(data_dir, registry.clone())?
        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_COMPOSITION_MISSING_MESSAGE))?;
    let (device_key, device_did) =
        crate::collaboration_profile_authority::load_existing_device_signing_key(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    let runtime_issuer = RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())
        .map_err(|_| anyhow::anyhow!("local Runtime device signing key is invalid"))?;
    let now = crate::auth::now_ts();
    let configured = composition
        .configured_nodes()
        .map_err(|_| anyhow::anyhow!("Runtime custody mint selection is invalid"))?;
    let selected = resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        now,
        &configured,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody mint selection is invalid"))?;
    let mint_nodes = selected
        .iter()
        .map(|node| node.binding().clone())
        .collect::<Vec<_>>();
    let mint_journal = runtime_mint_journal(data_dir);
    let mint_intent = load_or_persist_runtime_mint_intent(
        &mint_journal,
        &composition,
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
    let protected =
        protect_runtime_custody_media(&registry, &mint_journal, &composition, &input, &mint_intent)
            .await?;
    tracing::debug!(
        request_id = %hex::encode(mint_intent.request_id().as_bytes()),
        segments = protected.encrypted_segments.len(),
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
    let mint_draft = RuntimeMintDraft::new(
        &protected.init_segment,
        &protected.encrypted_segments,
        input.mime_type.clone(),
        input.codecs.clone(),
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
    let coordinator = RuntimeMintCoordinator::new(
        runtime_mint_journal(data_dir),
        runtime_issuer,
        move |bytes| sign_key.sign(bytes).to_bytes(),
        selected,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody mint coordinator is invalid"))?;
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
    let content_id = runtime_protected_content_id(mint_draft.encrypted_content())?;
    let publisher_profile_did = load_runtime_custody_profile_did(data_dir, &input.principal_id)?;
    let requirement = RuntimeContentAvailabilityRequirement::new(
        device_did,
        content_id.clone(),
        publisher_profile_did,
        PROTECTED_CONTENT_REPLICATION_POLICY,
        PROTECTED_CONTENT_MIN_REPLICAS,
        PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody availability requirement is invalid"))?;
    let staging = write_protected_content_staging_directory(data_dir, &protected)?;
    let evidence = publish_and_verify_protected_content_availability(
        registry.as_ref(),
        staging.path(),
        mint_draft.media_identity(),
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
    let facts = runtime_custody_library_publish_facts(&input, &mint_draft, &content_id, &evidence);
    mint_journal
        .mark_intent_completed(mint_intent.request_id(), mint_draft.mint_id())
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    Ok(facts)
}

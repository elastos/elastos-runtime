use super::*;

/// One snapshot of this Home's `config.toml`, or `None` when it is missing
/// or unreadable. Flags that must agree are read from one snapshot.
pub(crate) fn read_home_config(data_dir: &Path) -> Option<toml::Table> {
    fs::read_to_string(data_dir.join("config.toml"))
        .ok()
        .and_then(|contents| contents.parse::<toml::Table>().ok())
}

const MEDIA_PROVIDER_INPUT_FILE_NAME: &str = "input.bin";

const RUNTIME_MEDIA_PREPARATION_RECONCILIATION_MESSAGE: &str =
    "Runtime custody media preparation requires settlement reconciliation";

/// More than one pool is used and none was chosen.
pub(crate) const RUNTIME_CUSTODY_MINT_POOL_CHOICE_MESSAGE: &str =
    "This Home uses more than one pool: choose one in Creator.";

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

/// Plan B POOL-MINT (S7I-F1): the pool a mint attempt was started on, kept
/// beside the mint journal before its intent is written: a used pool's
/// descriptor, or none for this Home's own composition. Once the intent
/// exists, a resume uses this pool and no other: no reselection and no
/// fallback.
pub(super) const RUNTIME_POOL_MINTS_DIR: &str = "runtime-pool-mints";

const RUNTIME_POOL_MINT_ATTEMPT_SCHEMA_V1: &str =
    "elastos.protected-content.runtime-pool-mint-attempt/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimePoolMintAttemptV1 {
    schema: String,
    /// Standard base64 of the used pool's `SignedPoolDescriptorAnyV1`;
    /// `None` for this Home's own composition.
    descriptor_base64: Option<String>,
}

pub(super) fn write_runtime_pool_mint_file(
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

pub(super) fn runtime_pool_mint_attempt_path(data_dir: &Path, request_id: Digest32) -> PathBuf {
    runtime_pool_mints_dir(data_dir).join(format!(
        "attempt-{}.json",
        hex::encode(request_id.as_bytes())
    ))
}

pub(super) fn recorded_runtime_mint_pool(
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
pub(super) fn record_runtime_mint_attempt_pool(
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

pub(super) fn runtime_media_dash_rendition_name(kind: CencDashRenditionKindV2) -> &'static str {
    match kind {
        CencDashRenditionKindV2::Video => "video",
        CencDashRenditionKindV2::Audio => "audio",
    }
}

/// Refuses a prepared output for `reason`, which only the operator log carries:
/// the caller sees the same fail-closed message whatever was wrong.
pub(super) fn refuse_prepared_media_output(reason: &str) -> anyhow::Error {
    tracing::warn!(reason, "runtime custody media preparation output refused");
    invalid_prepared_media_output()
}

pub(super) fn runtime_media_dash_rendition_kind(name: &str) -> Option<CencDashRenditionKindV2> {
    [
        CencDashRenditionKindV2::Video,
        CencDashRenditionKindV2::Audio,
    ]
    .into_iter()
    .find(|kind| runtime_media_dash_rendition_name(*kind) == name)
}

/// The prepared directory of one rendition: `prepared/<rendition>`.
pub(super) fn runtime_prepared_rendition_dir(
    operation_root: &Path,
    kind: CencDashRenditionKindV2,
) -> PathBuf {
    operation_root
        .join(MEDIA_PROVIDER_PREPARED_DIR_NAME)
        .join(runtime_media_dash_rendition_name(kind))
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

/// One prepared rendition as the publish keeps it: only its clear init segment,
/// which is small. Its segments stay on disk and are read one at a time.
#[derive(Clone)]
pub(super) struct RuntimePreparedRenditionV2 {
    pub(super) kind: CencDashRenditionKindV2,
    pub(super) clear_init_segment: Vec<u8>,
    pub(super) timescale: u32,
    pub(super) segment_count: u32,
    pub(super) segment_parts: Vec<(u32, Digest32)>,
}

/// A validated v2 preparation: where the clear parts are and what binds them,
/// never the segments themselves. Remote-sized renditions also retain a
/// bounded table of segment lengths and digests.
#[derive(Clone)]
pub struct RuntimePreparedMediaV2 {
    pub(super) operation_root: PathBuf,
    pub(super) renditions: Vec<RuntimePreparedRenditionV2>,
    pub(super) preparation_receipt: Digest32,
    pub(super) clear_bytes: u64,
    /// How many segment files the protect loop has read, so a test can show that
    /// a part is read, protected and dropped before the next is read.
    #[cfg(test)]
    pub(super) part_reads: Arc<std::sync::atomic::AtomicUsize>,
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
pub(super) fn load_settled_runtime_prepared_media_v2(
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
pub(super) fn load_validated_runtime_prepared_media_v2(
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
pub(super) fn load_runtime_prepared_media_v2(
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
        let keep_remote_parts = segment_count as usize
            <= elastos_protected_content_contracts::SEAL_DASH_MAX_SEGMENTS_PER_RENDITION;
        let mut segment_parts = Vec::new();
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
            let digest = receipt.push_segment(index, &bytes);
            if keep_remote_parts {
                segment_parts.push((u32::try_from(bytes.len())?, digest));
            }
            clear_bytes = clear_bytes.saturating_add(bytes.len() as u64);
        }
        renditions.push(RuntimePreparedRenditionV2 {
            kind,
            clear_init_segment,
            timescale,
            segment_count,
            segment_parts,
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
    let source = (
        input.principal_id.as_str(),
        input.object_uri.as_str(),
        input.source_storage.as_str(),
    );
    let existing = runtime_mint_attempt_state(data_dir, source.0, source.1, source.2)?
        .and_then(|(_, intent)| intent);
    let mint_journal = runtime_mint_journal(data_dir);
    if let Some(intent) = existing
        .as_ref()
        .filter(|intent| intent.remote_seal_request().is_some())
    {
        return resume_runtime_custody_remote_dash(
            data_dir,
            registry,
            &mint_journal,
            &input,
            intent,
        )
        .await;
    }
    let mut mint_pool = load_runtime_custody_mint_pool(
        data_dir,
        registry.clone(),
        input.pool_did.as_deref(),
        Some(source),
    )?;
    let (device_key, device_did) =
        crate::collaboration_profile_authority::load_existing_device_signing_key(data_dir)?
            .ok_or_else(|| anyhow::anyhow!("local Runtime device signing key is missing"))?;
    let runtime_issuer = RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())
        .map_err(|_| anyhow::anyhow!("local Runtime device signing key is invalid"))?;
    let now = crate::auth::now_ts();
    let remote_enabled = remote_sealing_enabled(
        data_dir,
        existing.as_ref(),
        "protected_content_remote_dash_sealing",
    );
    if remote_enabled {
        bind_remote_sealing_pool(data_dir, &registry, source, &mut mint_pool, now)?;
    }
    let composition = &mint_pool.composition;
    let used_pool = mint_pool.used.clone();
    let configured = composition
        .configured_nodes()
        .map_err(|_| anyhow::anyhow!("Runtime custody mint selection is invalid"))?;
    let selected = mint_pool.selected_nodes(&configured, now)?;
    let mint_nodes = selected
        .iter()
        .map(|node| node.binding().clone())
        .collect::<Vec<_>>();
    let mint_intent = load_or_persist_runtime_mint_intent(
        &mint_journal,
        composition,
        &input,
        mint_nodes.clone(),
        mint_pool.completed_local_mint,
    )?;
    if let Some(mint_id) = mint_intent.completed_mint_id() {
        return load_completed_runtime_mint_facts(&mint_journal, &input, mint_id);
    }
    if remote_enabled {
        let descriptor = used_pool
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE))?;
        let local_nodes = own_custody_node_keys(data_dir)?;
        let clear_layout = remote_dash_source::RemoteSealDashSource::layout(&input.media)?;
        let intent = crate::remote_seal_source::prepare_remote_mint(
            &mint_journal,
            mint_intent,
            clear_layout,
            descriptor,
            &device_key,
            elastos_protected_content_runtime::RemoteSealLocalIdentity {
                endpoint_did: &device_did,
                node_keys: &local_nodes,
            },
            now,
        )?;
        return resume_runtime_custody_remote_dash(
            data_dir,
            registry,
            &mint_journal,
            &input,
            &intent,
        )
        .await;
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
        _ => {
            return Err(runtime_custody_mint_failed(
                &composition.diagnostics,
                runtime_custody_composition_pool_did(composition),
            ))
        }
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

async fn resume_runtime_custody_remote_dash(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    journal: &RuntimeMintJournal,
    input: &RuntimeCustodyLibraryPublishInput,
    intent: &RuntimeMintIntent,
) -> anyhow::Result<RuntimeCustodyLibraryPublishFacts> {
    let attempt = journal.current_attempt(
        &input.principal_id,
        &input.object_uri,
        &input.source_storage,
    )?;
    let expected = RuntimeMintIntent::new_media_dash(
        input.principal_id.clone(),
        &input.object_uri,
        &input.source_storage,
        input.wallet_account_id.clone(),
        input.wallet_account_address.clone(),
        input.creator_mint_source_digest,
        input.media.preparation_receipt(),
        runtime_mint_media_renditions(&input.media),
        intent.content_access_id(),
        intent.custody_pool(),
        intent.custody_epoch(),
        intent.custody_committee_authorization(),
        intent.nodes().to_vec(),
    )?
    .for_attempt(attempt.attempt())?;
    if !intent.same_authority_as(&expected) {
        return Err(RuntimeCustodyAttemptConflict::error(
            RuntimeCustodyAttemptConflictReason::AuthorityChanged,
        ));
    }
    let record = finish_runtime_custody_remote_mint(data_dir, registry, journal, intent, || {
        remote_dash_source::RemoteSealDashSource::bind(&input.media, intent)
    })
    .await?;
    load_completed_runtime_mint_facts(journal, input, record.draft().mint_id())
}

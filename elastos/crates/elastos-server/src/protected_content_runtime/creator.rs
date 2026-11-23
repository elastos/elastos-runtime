use super::*;

const MEDIA_PROVIDER_CONFIG_FILE: &str = "protected-content/media-provider/config.json";

pub(super) const MEDIA_PROVIDER_CONFIG_SCHEMA_V1: &str =
    "elastos.protected-content.media-provider-config/v1";

const MEDIA_PROVIDER_OUTPUT_PROFILE_V1: &str = "browser_fmp4_h264_v1";

const MAX_MEDIA_PROVIDER_CONFIG_BYTES: usize = 8 * 1024;

const MAX_MEDIA_PROVIDER_IMPORTED_TOOL_BYTES: u64 = 512 * 1024 * 1024;

pub(super) const MEDIA_PROVIDER_TIMEOUT_MS_V1: u64 = 3_600_000;

const MEDIA_PROVIDER_MAX_STDIO_BYTES_V1: usize = 1 << 20;

pub(super) const MEDIA_PROVIDER_MAX_INPUT_BYTES_V1: u64 = 1 << 30;

const MEDIA_PROVIDER_MAX_OUTPUT_PART_BYTES_V1: u64 = 64 << 20;

const MEDIA_PROVIDER_MAX_DURATION_SECS_V1: u64 = 1_800;

const MEDIA_PROVIDER_MAX_SOURCE_WIDTH_V1: u32 = 3_840;

const MEDIA_PROVIDER_MAX_SOURCE_HEIGHT_V1: u32 = 2_160;

const MEDIA_PROVIDER_MAX_SOURCE_FPS_V1: u32 = 60;

const MEDIA_PROVIDER_MAX_SEGMENT_COUNT_V1: usize = MAX_PROTECT_MEDIA_SEGMENTS_V1 as usize;

const MEDIA_PROVIDER_MAX_TOTAL_OUTPUT_BYTES_V1: u64 = 2 << 30;

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

pub(super) struct RuntimeMediaToolSource {
    pub(super) file: fs::File,
    size: u64,
}

struct RuntimeMediaToolImport {
    path: PathBuf,
    created: bool,
}

pub(crate) const RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE: &str =
    "Runtime custody mint requires cleanup reconciliation";

pub(crate) const RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE: &str =
    "Runtime custody mint was settled before draft persistence";

const CHAIN_PROVIDER_CONFIG_FILE: &str = "protected-content/chain-provider.json";

pub const PROTECTED_CONTENT_CHAIN_PROVIDER_CONFIG_SCHEMA_V1: &str =
    "elastos.protected-content.chain-provider-config/v1";

pub(super) const MAX_CHAIN_PROVIDER_CONFIG_BYTES: usize = 64 * 1024;

const CHAIN_PROTECTED_CONTENT_POLICY_OP: &str = "resolve_protected_content_policy";

pub(super) const CHAIN_PROTECTED_CONTENT_POLICY_SCHEMA_V1: &str =
    "elastos.chain.protected-content-policy/v1";

const MEDIA_PROVIDER_PREPARED_DIR_NAME: &str = "prepared";

const MEDIA_PROVIDER_SEGMENTS_DIR_NAME: &str = "segments";

const MEDIA_PROVIDER_MAX_INPUT_BYTES: u64 = 1024 * 1024 * 1024;

const MEDIA_PROVIDER_MAX_OUTPUT_PART_BYTES: u64 = 64 * 1024 * 1024;

const MEDIA_PROVIDER_MAX_SEGMENT_COUNT: usize = 512;

const MEDIA_PROVIDER_MAX_TOTAL_OUTPUT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

const RUNTIME_MEDIA_PREPARATION_RECEIPT_DOMAIN: &[u8] =
    b"elastos.protected-content.runtime-media-preparation-receipt/v1";

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
    RuntimeMintIntent::new(
        input.principal_id.clone(),
        &input.object_uri,
        &input.source_storage,
        input.wallet_account_id.clone(),
        input.wallet_account_address.clone(),
        input.creator_mint_source_digest,
        input.mime_type.clone(),
        input.codecs.clone(),
        &input.clear_init_segment,
        &input.clear_segments,
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

pub(super) fn load_or_persist_runtime_mint_intent(
    journal: &RuntimeMintJournal,
    composition: &RuntimeCustodyComposition,
    input: &RuntimeCustodyLibraryPublishInput,
    selected_nodes: Vec<elastos_protected_content_runtime::RuntimeMintNodeBinding>,
) -> anyhow::Result<RuntimeMintIntent> {
    let request_id = RuntimeMintIntent::request_id_for_source(
        &input.principal_id,
        &input.object_uri,
        &input.source_storage,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is invalid"))?;
    match journal.load_intent(request_id) {
        Ok(existing) => {
            let expected = runtime_mint_intent_with_access_id(
                composition,
                input,
                selected_nodes,
                existing.content_access_id(),
            )?;
            if !existing.same_authority_as(&expected) {
                anyhow::bail!("Runtime custody mint intent conflicts with existing authority");
            }
            Ok(existing)
        }
        Err(elastos_protected_content_runtime::RuntimeMintJournalError::NotFound) => {
            let intent = runtime_mint_intent_with_access_id(
                composition,
                input,
                selected_nodes,
                generate_runtime_content_access_id()?,
            )?;
            journal
                .persist_intent(&intent)
                .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))
        }
        Err(_) => Err(anyhow::anyhow!(
            "Runtime custody mint intent is unavailable"
        )),
    }
}

pub(super) fn load_completed_runtime_mint_facts(
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
        input,
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
pub(super) fn adopt_settled_runtime_mint_record(
    journal: &RuntimeMintJournal,
    mint_intent: &RuntimeMintIntent,
) -> anyhow::Result<Option<Digest32>> {
    let record = journal
        .find_mint_record_for_intent(mint_intent.request_id())
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    let Some(record) = record else {
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
    tracing::warn!(
        request_id = %hex::encode(mint_intent.request_id().as_bytes()),
        mint_id = %hex::encode(record.draft().mint_id().as_bytes()),
        custody_terminal = ?record.custody_terminal(),
        content_availability_recorded = record.content_availability().is_some(),
        node_effects_started = record.any_effect_started(),
        node_receipts_accepted = record.accepted_orphans().len(),
        "settled runtime custody mint record is not fully terminal; orphaned custody state requires cleanup reconciliation"
    );
    anyhow::bail!(RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE);
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

fn invalid_chain_provider_config(reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("protected-content Chain provider config is missing or unsafe: {reason}")
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
pub(super) fn open_runtime_media_tool(
    tools_dir: &Path,
    name: &str,
) -> anyhow::Result<RuntimeMediaToolSource> {
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
pub(super) fn open_runtime_media_tool(
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
pub(super) fn create_private_file_atomically(
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

fn runtime_rights_action_name(action: RightsActionV1) -> &'static str {
    match action {
        RightsActionV1::View => "view",
        RightsActionV1::Stream => "stream",
        RightsActionV1::Download => "download",
        RightsActionV1::Execute => "execute",
    }
}

#[derive(Debug)]
pub(super) struct RuntimePreparedLibraryPublish {
    pub(super) input: RuntimeCustodyLibraryPublishInput,
    pub(super) request_id: Digest32,
    pub(super) output_receipt_digest: Digest32,
    pub(super) operation_root: PathBuf,
}

#[derive(Debug)]
pub(super) enum RuntimeLibraryMediaPreparation {
    Prepared(RuntimePreparedLibraryPublish),
    Consumed {
        record: RuntimeMediaPreparationRecord,
        operation_root: PathBuf,
    },
}

pub(super) enum RuntimeMediaProviderPrepareError {
    Settled,
    Unknown,
}

pub(super) fn runtime_media_staging_root(data_dir: &Path) -> PathBuf {
    data_dir
        .join(PROTECTED_CONTENT_ROOT)
        .join("media-provider")
        .join("staging")
}

pub(super) fn runtime_media_private_state_error(_reason: String) -> anyhow::Error {
    anyhow::anyhow!("Runtime custody media preparation private state is invalid")
}

pub(super) fn validate_runtime_media_staging_root(staging_root: &Path) -> anyhow::Result<()> {
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
/// streamed; MEDIA_PROVIDER_MAX_INPUT_BYTES bounds the plaintext.
pub(super) fn read_runtime_media_source(
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
    // A protected envelope carries base64 ciphertext plus metadata, so the
    // stored file may exceed the plaintext bound by a constant factor.
    if stored_len == 0 || stored_len > MEDIA_PROVIDER_MAX_INPUT_BYTES.saturating_mul(2) {
        return Err(
            anyhow::anyhow!("stored source length {stored_len} is out of bounds").context(MESSAGE),
        );
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
    if bytes.is_empty() || bytes.len() as u64 > MEDIA_PROVIDER_MAX_INPUT_BYTES {
        return Err(
            anyhow::anyhow!("source plaintext length {} is out of bounds", bytes.len())
                .context(MESSAGE),
        );
    }
    Ok(bytes)
}

pub(super) fn runtime_media_source_digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(sha2::Sha256::digest(bytes).into())
}

pub(super) fn reset_runtime_media_operation_root(operation_root: &Path) -> anyhow::Result<()> {
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
pub(super) fn stage_runtime_media_provider_input(
    source_bytes: &[u8],
    destination_path: &Path,
    expected_digest: Digest32,
) -> anyhow::Result<()> {
    if source_bytes.is_empty()
        || source_bytes.len() as u64 > MEDIA_PROVIDER_MAX_INPUT_BYTES
        || runtime_media_source_digest(source_bytes) != expected_digest
    {
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

pub(super) fn load_validated_runtime_prepared_media(
    operation_root: &Path,
    prepared_output: &RuntimePreparedMediaProviderOutput,
) -> anyhow::Result<(RuntimeCustodyLibraryPublishInputMedia, Digest32)> {
    if prepared_output.schema != MEDIA_PROVIDER_PREPARED_MEDIA_SCHEMA_V1
        || prepared_output.mime_type != MEDIA_PROVIDER_OUTPUT_MIME_TYPE_V1
        || prepared_output.codecs != MEDIA_PROVIDER_OUTPUT_CODECS_V1
    {
        anyhow::bail!("Runtime custody media preparation output is invalid");
    }
    let prepared_root = operation_root.join(MEDIA_PROVIDER_PREPARED_DIR_NAME);
    let prepared_metadata = fs::symlink_metadata(&prepared_root)
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
    if prepared_metadata.file_type().is_symlink() || !prepared_metadata.is_dir() {
        anyhow::bail!("Runtime custody media preparation output is invalid");
    }
    validate_owner_only_metadata_with_error(
        "media-provider prepared output root",
        &prepared_metadata,
        false,
        runtime_media_private_state_error,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
    let segments_root = prepared_root.join(MEDIA_PROVIDER_SEGMENTS_DIR_NAME);
    let mut saw_init = false;
    let mut saw_segments = false;
    for entry in fs::read_dir(&prepared_root)
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?
    {
        let entry = entry
            .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
        if metadata.file_type().is_symlink() {
            anyhow::bail!("Runtime custody media preparation output is invalid");
        }
        match name.as_str() {
            "init.mp4" if metadata.is_file() => saw_init = true,
            MEDIA_PROVIDER_SEGMENTS_DIR_NAME if metadata.is_dir() => saw_segments = true,
            _ => anyhow::bail!("Runtime custody media preparation output is invalid"),
        }
    }
    if !saw_init || !saw_segments {
        anyhow::bail!("Runtime custody media preparation output is invalid");
    }
    let clear_init_segment = read_runtime_media_prepared_part(
        &prepared_root.join("init.mp4"),
        false,
        MEDIA_PROVIDER_MAX_OUTPUT_PART_BYTES,
    )?;
    let mut total_output_bytes = clear_init_segment.len() as u64;
    let session = ValidatedClearFmp4MediaSessionLayoutV1::new(&clear_init_segment)
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
    let segments_metadata = fs::symlink_metadata(&segments_root)
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
    if segments_metadata.file_type().is_symlink() || !segments_metadata.is_dir() {
        anyhow::bail!("Runtime custody media preparation output is invalid");
    }
    validate_owner_only_metadata_with_error(
        "media-provider prepared segments root",
        &segments_metadata,
        false,
        runtime_media_private_state_error,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
    let mut segments = std::collections::BTreeMap::new();
    for entry in fs::read_dir(&segments_root)
        .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?
    {
        let entry = entry
            .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
        let index = parse_runtime_media_segment_name(&name)?;
        let bytes = read_runtime_media_prepared_part(
            &entry.path(),
            true,
            MEDIA_PROVIDER_MAX_OUTPUT_PART_BYTES,
        )?;
        total_output_bytes = total_output_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| {
                anyhow::anyhow!("Runtime custody media preparation output is invalid")
            })?;
        session
            .validate_segment(&bytes)
            .map_err(|_| anyhow::anyhow!("Runtime custody media preparation output is invalid"))?;
        if segments.insert(index, bytes).is_some() {
            anyhow::bail!("Runtime custody media preparation output is invalid");
        }
    }
    if segments.is_empty()
        || segments.len() > MEDIA_PROVIDER_MAX_SEGMENT_COUNT
        || segments.len() > MAX_PROTECT_MEDIA_SEGMENTS_V1 as usize
        || total_output_bytes > MEDIA_PROVIDER_MAX_TOTAL_OUTPUT_BYTES
    {
        anyhow::bail!("Runtime custody media preparation output is invalid");
    }
    let mut clear_segments = Vec::with_capacity(segments.len());
    for (expected_index, (actual_index, bytes)) in segments.into_iter().enumerate() {
        if actual_index != expected_index as u32 {
            anyhow::bail!("Runtime custody media preparation output is invalid");
        }
        clear_segments.push(bytes);
    }
    let media = RuntimeCustodyLibraryPublishInputMedia {
        mime_type: prepared_output.mime_type.clone(),
        codecs: prepared_output.codecs.clone(),
        clear_init_segment,
        clear_segments,
    };
    let receipt = runtime_media_preparation_receipt(&media);
    Ok((media, receipt))
}

pub(super) struct RuntimeCustodyLibraryPublishInputMedia {
    pub(super) mime_type: String,
    pub(super) codecs: String,
    pub(super) clear_init_segment: Vec<u8>,
    pub(super) clear_segments: Vec<Vec<u8>>,
}

fn runtime_media_preparation_receipt(media: &RuntimeCustodyLibraryPublishInputMedia) -> Digest32 {
    let mut hasher = sha2::Sha256::new();
    hasher.update(RUNTIME_MEDIA_PREPARATION_RECEIPT_DOMAIN);
    hasher.update(media.mime_type.as_bytes());
    hasher.update([0]);
    hasher.update(media.codecs.as_bytes());
    hasher.update([0]);
    hasher.update((media.clear_init_segment.len() as u64).to_be_bytes());
    hasher.update(sha2::Sha256::digest(&media.clear_init_segment));
    for (index, segment) in media.clear_segments.iter().enumerate() {
        hasher.update((index as u64).to_be_bytes());
        hasher.update((segment.len() as u64).to_be_bytes());
        hasher.update(sha2::Sha256::digest(segment));
    }
    Digest32::new(hasher.finalize().into())
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

pub(super) async fn invoke_runtime_media_provider_prepare(
    registry: &ProviderRegistry,
    operation_id: Digest32,
) -> Result<RuntimePreparedMediaProviderOutput, RuntimeMediaProviderPrepareError> {
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

pub(super) struct ProtectedRuntimeCustodyMedia {
    pub(super) init_segment: Vec<u8>,
    pub(super) encrypted_segments: Vec<Vec<u8>>,
    pub(super) media_identity: CencFmp4MediaIdentityV1,
    pub(super) envelope: CustodyEnvelopeV1,
}

enum RuntimeProtectRecoveryDisposition {
    Fresh,
    ReplayOpenAndSettleCancel,
    SettleCancel([u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]),
    SettleClose([u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1]),
    TerminalAbort,
}

pub(super) async fn protect_runtime_custody_media(
    registry: &ProviderRegistry,
    journal: &RuntimeMintJournal,
    composition: &RuntimeCustodyComposition,
    input: &RuntimeCustodyLibraryPublishInput,
    mint_intent: &RuntimeMintIntent,
) -> anyhow::Result<ProtectedRuntimeCustodyMedia> {
    let open_request =
        runtime_custody_open_protection_session_request(composition, input, mint_intent)?;
    match runtime_protect_recovery_disposition(mint_intent) {
        RuntimeProtectRecoveryDisposition::TerminalAbort => {
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
                anyhow::bail!(RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE);
            }
            let opened =
                invoke_typed_protect_provider(registry, "open_protection_session", &open_request)
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!(RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE)
                    })?;
            if opened.status() != ProtectProviderResponseStatusV1::ProtectionSessionOpened {
                anyhow::bail!(RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE);
            }
            let handle = opened
                .protection_session_handle()
                .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE))?
                .ok_or_else(|| {
                    anyhow::anyhow!(RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE)
                })?;
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
            .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE))?;
            Err(error)
        }
    }
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
    let segment_count = u32::try_from(input.clear_segments.len())
        .map_err(|_| anyhow::anyhow!("Runtime custody protect input is invalid"))?;
    ProtectProviderRequestV1::new_open_protection_session(
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
        input.mime_type.clone(),
        input.codecs.clone(),
        segment_count,
        &input.clear_init_segment,
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
        _ => anyhow::bail!(RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE),
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "This operation keeps protect-session authority and settlement inputs explicit at one boundary"
)]
async fn protect_opened_runtime_custody_session(
    registry: &ProviderRegistry,
    journal: &RuntimeMintJournal,
    request_id: Digest32,
    handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    opened: &ProtectProviderResponseV1,
    input: &RuntimeCustodyLibraryPublishInput,
    composition: &RuntimeCustodyComposition,
    content_access_id: ContentAccessIdV1,
) -> anyhow::Result<ProtectedRuntimeCustodyMedia> {
    let init_segment = opened
        .protected_init_segment()
        .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?
        .to_vec();
    let mut encrypted_segments = Vec::with_capacity(input.clear_segments.len());
    for (segment_index, clear_segment) in input.clear_segments.iter().enumerate() {
        let protected = invoke_typed_protect_provider(
            registry,
            "protect_media_segment",
            &ProtectProviderRequestV1::new_protect_media_segment(
                handle,
                u32::try_from(segment_index)
                    .map_err(|_| anyhow::anyhow!("Runtime custody protect input is invalid"))?,
                clear_segment,
            )
            .map_err(|_| anyhow::anyhow!("Runtime custody protect request is invalid"))?,
        )
        .await?;
        if protected.status() != ProtectProviderResponseStatusV1::MediaSegmentProtected
            || protected.segment_index()
                != Some(
                    u32::try_from(segment_index)
                        .map_err(|_| anyhow::anyhow!("Runtime custody protect input is invalid"))?,
                )
        {
            anyhow::bail!("Runtime custody protect provider is unavailable");
        }
        encrypted_segments.push(
            protected
                .protected_segment()
                .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?
                .to_vec(),
        );
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
        .media_identity()
        .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?
        .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
    let envelope = finalized
        .custody_envelope()
        .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?
        .ok_or_else(|| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
    let expected_media = CencFmp4MediaIdentityV1::new_from_bytes(
        &init_segment,
        &encrypted_segments,
        input.mime_type.clone(),
        input.codecs.clone(),
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
    let protected_session =
        ValidatedCencFmp4MediaSessionLayoutV1::new(&expected_media, &init_segment)
            .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?;
    if media_identity != expected_media
        || protected_session.content_access_id() != content_access_id
        || envelope.manifest().encrypted_content() != media_identity.encrypted_content()
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
    journal
        .mark_intent_protect_finalized(request_id, handle)
        .map_err(|_| anyhow::anyhow!("Runtime custody mint intent is unavailable"))?;
    Ok(ProtectedRuntimeCustodyMedia {
        init_segment,
        encrypted_segments,
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

pub(super) fn write_protected_content_staging_directory(
    data_dir: &Path,
    protected: &ProtectedRuntimeCustodyMedia,
) -> anyhow::Result<tempfile::TempDir> {
    let parent = protected_content_root(data_dir);
    fs::create_dir_all(&parent)?;
    let staging = tempfile::Builder::new()
        .prefix("publish-")
        .tempdir_in(&parent)
        .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))?;
    let tree = staging.path().join("protected-content/v1/segments");
    fs::create_dir_all(&tree)
        .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))?;
    fs::write(
        staging.path().join(PROTECTED_CONTENT_IDENTITY_PATH),
        protected
            .media_identity
            .canonical_bytes()
            .map_err(|_| anyhow::anyhow!("Runtime custody protect output is invalid"))?,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))?;
    fs::write(
        staging.path().join(PROTECTED_CONTENT_INIT_PATH),
        &protected.init_segment,
    )
    .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))?;
    for (index, segment) in protected.encrypted_segments.iter().enumerate() {
        fs::write(
            staging.path().join(protected_content_segment_path(index)),
            segment,
        )
        .map_err(|_| anyhow::anyhow!("Runtime custody publish staging is unavailable"))?;
    }
    Ok(staging)
}

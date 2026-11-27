use super::*;

pub(in crate::api::gateway) async fn wallet_connector_config(
    State(state): State<GatewayState>,
    Path(wallet_connector): Path<String>,
    headers: HeaderMap,
) -> Response {
    if gateway_walletconnect::attempt_headers_present(&headers) {
        return if wallet_connector == WALLET_WALLETCONNECT_CAPSULE_ID {
            gateway_walletconnect::attempt_config(&state, &headers).await
        } else {
            StatusCode::FORBIDDEN.into_response()
        };
    }
    let context = match require_wallet_connector_launch_context(
        &state.data_dir,
        &headers,
        wallet_connector.as_str(),
    )
    .await
    {
        Ok(context) => context,
        Err(err) => return system_error_response(err),
    };

    let mut payload = serde_json::json!({
        "schema": "elastos.wallet.connector.config/v1",
        "connector_id": wallet_connector.clone(),
        "label": wallet_connector_label(wallet_connector.as_str()),
        "evm_chains": wallet_connector_evm_chains(),
    });
    if wallet_connector == WALLET_WALLETCONNECT_CAPSULE_ID {
        match load_walletconnect_connector_config(&state.data_dir).and_then(|config| {
            validate_walletconnect_connector_config(&config)?;
            Ok(config)
        }) {
            Ok(config) => {
                let revision = match gateway_walletconnect::storage_revision(
                    &state.data_dir,
                    &context.principal_id,
                ) {
                    Ok(revision) => revision,
                    Err(err) => return system_error_response(err),
                };
                payload["walletconnect"] = serde_json::json!({
                    "project_id": config.project_id,
                    "storage_revision": revision,
                    "sdk_package": config.sdk_package,
                    "sdk_version": config.sdk_version,
                    "sdk_asset_path": "/apps/wallet-walletconnect/vendor/reown-appkit.js",
                    "sdk_sha256": config.sdk_sha256,
                });
            }
            Err(err) => return system_error_response(err),
        }
    }
    Json(payload).into_response()
}

pub(in crate::api::gateway) async fn wallet_connector_accounts(
    State(state): State<GatewayState>,
    Path(wallet_connector): Path<String>,
    headers: HeaderMap,
) -> Response {
    let authority = match require_wallet_connector_launch_authority(
        &state.data_dir,
        &headers,
        wallet_connector.as_str(),
    )
    .await
    {
        Ok(authority) => authority,
        Err(err) => return system_error_response(err),
    };
    let mut summary = system_wallet_accounts_summary(&state, &authority).await;
    summary.accounts.retain(|account| {
        !is_managed_wallet_proof_type(&account.proof_type)
            && account.connector_id.as_deref() == Some(wallet_connector.as_str())
    });
    summary.linked_count = summary.accounts.len();
    Json(summary).into_response()
}

pub(in crate::api::gateway) async fn wallet_connector_approvals(
    State(state): State<GatewayState>,
    Path(wallet_connector): Path<String>,
    headers: HeaderMap,
) -> Response {
    let authority = match require_wallet_connector_launch_authority(
        &state.data_dir,
        &headers,
        wallet_connector.as_str(),
    )
    .await
    {
        Ok(authority) => authority,
        Err(err) => return system_error_response(err),
    };
    let mut summary = system_wallet_approvals_summary(
        &state,
        &authority,
        wallet_connector == WALLET_WALLETCONNECT_CAPSULE_ID,
    )
    .await;
    summary.approval_requests.retain(|request| {
        !is_managed_wallet_proof_type(&request.proof_type)
            && request.connector_id.as_deref() == Some(wallet_connector.as_str())
            && (request.status == "pending"
                || (request.status == "approved" && request.intent == "transaction_intent"))
    });
    summary.pending_count = summary
        .approval_requests
        .iter()
        .filter(|r| r.status == "pending")
        .count();
    Json(summary).into_response()
}

pub(in crate::api::gateway) async fn wallet_connector_approval_approve(
    State(state): State<GatewayState>,
    Path((wallet_connector, request_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<WalletApprovalApproveRequest>,
) -> Response {
    if let Err(err) = require_capsule_owned_connector_effects(&wallet_connector) {
        return system_error_response(err);
    }
    let authority = match require_wallet_connector_launch_authority(
        &state.data_dir,
        &headers,
        wallet_connector.as_str(),
    )
    .await
    {
        Ok(authority) => authority,
        Err(err) => return system_error_response(err),
    };
    let context = authority.home_launch_context();
    let binding = if wallet_connector == WALLET_WALLETCONNECT_CAPSULE_ID {
        match walletconnect_request_binding(&state, &authority, &request_id, "pending").await {
            Ok(binding) => Some(binding),
            Err(err) => return system_error_response(err),
        }
    } else {
        None
    };
    let connector_label = wallet_connector_label(wallet_connector.as_str());
    let reason = input
        .reason
        .unwrap_or_else(|| format!("Approved in {connector_label} connector"));
    match approve_external_wallet_request(
        &state,
        &state.data_dir,
        &context,
        &authority,
        &request_id,
        &reason,
        wallet_connector.as_str(),
    )
    .await
    {
        Ok(outcome) => {
            let mut summary = system_wallet_approvals_summary(&state, &authority, false).await;
            summary.note = Some(format!("Approved. Continue in {connector_label}."));
            summary.handoff = outcome.handoff;
            let mut response = serde_json::to_value(summary).expect("wallet summary serialization");
            if let Some(binding) = binding {
                if let Err(err) = validate_walletconnect_handoff(
                    &request_id,
                    &binding,
                    &outcome.approval_request,
                    &response["handoff"],
                ) {
                    return system_error_response(err);
                }
                response["binding"] = binding;
            }
            Json(response).into_response()
        }
        Err(err) => system_error_response(err),
    }
}

pub(in crate::api::gateway) async fn wallet_connector_approval_complete(
    State(state): State<GatewayState>,
    Path((wallet_connector, request_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<WalletApprovalCompleteRequest>,
) -> Response {
    if let Err(err) = require_capsule_owned_connector_effects(&wallet_connector) {
        return system_error_response(err);
    }
    let authority = match require_wallet_connector_launch_authority(
        &state.data_dir,
        &headers,
        wallet_connector.as_str(),
    )
    .await
    {
        Ok(authority) => authority,
        Err(err) => return system_error_response(err),
    };
    let context = authority.home_launch_context();
    if wallet_connector == WALLET_WALLETCONNECT_CAPSULE_ID {
        let binding = match walletconnect_request_binding(
            &state,
            &authority,
            &request_id,
            "approved",
        )
        .await
        {
            Ok(binding) => binding,
            Err(err) => return system_error_response(err),
        };
        if binding["payload_hash"].as_str() != Some(input.payload_hash.as_str())
            || !binding["address"]
                .as_str()
                .is_some_and(|address| address.eq_ignore_ascii_case(&input.signer))
            || input
                .transaction_hash
                .as_deref()
                .is_some_and(|hash| !walletconnect_hash(hash))
            || (!input.declined
                && binding["intent"] == "transaction_intent"
                && (input.transaction_hash.is_none() || input.signature.is_some()))
            || (!input.declined
                && binding["intent"] != "transaction_intent"
                && (input.signature.is_none() || input.transaction_hash.is_some()))
        {
            return system_error_response(anyhow::anyhow!(
                "WalletConnect completion binding or transaction hash is invalid"
            ));
        }
    }
    let connector_label = wallet_connector_label(wallet_connector.as_str());
    match complete_external_wallet_approval(
        &state,
        &context,
        &authority,
        &request_id,
        input,
        wallet_connector.as_str(),
        &format!("External wallet signature completed through {connector_label} approval"),
    )
    .await
    {
        Ok(mut summary) => {
            summary.note = Some(if summary.receipt_status.as_deref() == Some("declined") {
                "Declined by wallet".to_string()
            } else if summary.receipt_status.as_deref() == Some("sent_after_dismissal") {
                "Request dismissed. Your wallet reported this transaction as sent.".to_string()
            } else {
                format!("Signed by {connector_label}.")
            });
            Json(summary).into_response()
        }
        Err(err) => system_error_response(err),
    }
}

fn require_capsule_owned_connector_effects(connector_id: &str) -> anyhow::Result<()> {
    if connector_id == WALLET_WALLETCONNECT_CAPSULE_ID {
        return Ok(());
    }
    if is_wallet_connector_capsule_id(connector_id) {
        anyhow::bail!(
            "wallet connector injected-wallet effects require the trusted Home host bridge"
        );
    }
    anyhow::bail!("unknown wallet connector capsule")
}

pub(in crate::api::gateway) async fn require_wallet_connector_launch_context(
    data_dir: &FsPath,
    headers: &HeaderMap,
    connector_id: &str,
) -> anyhow::Result<HomeLaunchTokenContext> {
    if !is_wallet_connector_capsule_id(connector_id) {
        anyhow::bail!("unknown wallet connector capsule");
    }
    ensure_wallet_connector_configured_async(data_dir, connector_id).await?;
    if connector_id == WALLET_WALLETCONNECT_CAPSULE_ID {
        Ok(
            gateway_walletconnect::connector_launch_authority(data_dir, headers)?
                .home_launch_context(),
        )
    } else {
        require_home_launch_token_context(data_dir, headers, connector_id)
    }
}

pub(in crate::api::gateway) async fn require_wallet_connector_launch_authority(
    data_dir: &FsPath,
    headers: &HeaderMap,
    connector_id: &str,
) -> anyhow::Result<RuntimeWalletAuthority> {
    if !is_wallet_connector_capsule_id(connector_id) {
        anyhow::bail!("unknown wallet connector capsule");
    }
    ensure_wallet_connector_configured_async(data_dir, connector_id).await?;
    if connector_id == WALLET_WALLETCONNECT_CAPSULE_ID {
        gateway_walletconnect::connector_launch_authority(data_dir, headers)
    } else {
        require_runtime_wallet_authority(data_dir, headers, &[connector_id])
    }
}

pub(in crate::api::gateway) fn require_wallet_app_launch_authority(
    data_dir: &FsPath,
    headers: &HeaderMap,
) -> anyhow::Result<RuntimeWalletAuthority> {
    require_runtime_wallet_authority(data_dir, headers, &[WALLET_CAPSULE_ID])
}

// Async callers use this entry point. Other targets retain their direct path.
pub(crate) async fn ensure_wallet_connector_configured_async(
    data_dir: &FsPath,
    connector_id: &str,
) -> anyhow::Result<()> {
    if connector_id != WALLET_WALLETCONNECT_CAPSULE_ID {
        return Ok(());
    }
    let data = data_dir.to_path_buf();
    blocking_capsule_inventory(move || {
        ensure_wallet_connector_configured(&data, WALLET_WALLETCONNECT_CAPSULE_ID)
    })
    .await
}

#[derive(Clone, PartialEq, Eq)]
struct WalletConnectSdkStamp {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
}

fn open_walletconnect_sdk(path: &FsPath) -> anyhow::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    // Refuse the final symlink on other platforms as well.
    anyhow::ensure!(
        !std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()),
        "WalletConnect connector requires a regular SDK file"
    );
    options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!("WalletConnect connector is not configured: pinned SDK asset missing")
        } else {
            error.into()
        }
    })
}

fn walletconnect_sdk_stamp(file: &std::fs::File) -> anyhow::Result<WalletConnectSdkStamp> {
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 8 * 1024 * 1024,
        "WalletConnect connector requires a bounded regular SDK file"
    );
    Ok(WalletConnectSdkStamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        identity: {
            use std::os::unix::fs::MetadataExt;
            (
                metadata.dev(),
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        },
    })
}

type SdkCache = std::collections::BTreeMap<PathBuf, (WalletConnectSdkStamp, String, bool)>;

// Synchronous inventory/setup callers share this cache with HTTP admissions.
// Callers on the blocking pool hash inline; synchronous setup uses its own thread.
pub(crate) fn ensure_wallet_connector_configured(
    data_dir: &FsPath,
    connector_id: &str,
) -> anyhow::Result<()> {
    if connector_id != WALLET_WALLETCONNECT_CAPSULE_ID {
        return Ok(());
    }
    static CACHE: std::sync::OnceLock<std::sync::Mutex<SdkCache>> = std::sync::OnceLock::new();
    ensure_wallet_connector_configured_with_cache(data_dir, CACHE.get_or_init(Default::default))
}

fn ensure_wallet_connector_configured_with_cache(
    data_dir: &FsPath,
    cache: &std::sync::Mutex<SdkCache>,
) -> anyhow::Result<()> {
    let config = load_walletconnect_connector_config(data_dir)?;
    validate_walletconnect_connector_config(&config)?;
    let sdk_path = data_dir.join(WALLETCONNECT_SDK_PATH);
    let file = open_walletconnect_sdk(&sdk_path)?;
    let stamp = walletconnect_sdk_stamp(&file)?;
    let mut cache = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mismatch =
        || anyhow::anyhow!("WalletConnect connector is not configured: pinned SDK hash mismatch");
    if let Some((cached_stamp, pin, matches)) = cache.get(&sdk_path) {
        if cached_stamp == &stamp && pin == &config.sdk_sha256 {
            return if *matches { Ok(()) } else { Err(mismatch()) };
        }
    }
    // Async admissions and inventories already own a blocking-pool worker.
    #[cfg(test)]
    sdk_verification_tests::record_read(&sdk_path);
    use std::io::Read as _;
    let mut bytes = Vec::new();
    (&file).take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 8 * 1024 * 1024,
        "WalletConnect SDK exceeds its limit"
    );
    let digest = format!("{:x}", Sha256::digest(&bytes));
    anyhow::ensure!(
        stamp == walletconnect_sdk_stamp(&file)?,
        "WalletConnect SDK changed during verification"
    );
    let matches = digest.eq_ignore_ascii_case(config.sdk_sha256.trim());
    // Runtime normally has one data root. Bound retained fixture/retired roots.
    if cache.len() >= 16 {
        cache.clear();
    }
    cache.insert(sdk_path, (stamp, config.sdk_sha256, matches));
    if matches {
        Ok(())
    } else {
        Err(mismatch())
    }
}

pub(in crate::api::gateway) fn load_walletconnect_connector_config(
    data_dir: &FsPath,
) -> anyhow::Result<WalletConnectConnectorConfig> {
    let operator = data_dir.join(WALLETCONNECT_CONFIG_PATH);
    let path = if operator.try_exists()? {
        operator
    } else {
        data_dir.join("capsules/wallet-walletconnect/vendor/connector.json")
    };
    let bytes = gateway_walletconnect::read_bytes(&path, 8192)?.ok_or_else(|| {
        anyhow::anyhow!("WalletConnect connector is not configured: pinned config missing")
    })?;
    serde_json::from_slice(&bytes).map_err(|err| {
        anyhow::anyhow!("WalletConnect connector is not configured: invalid pinned config ({err})")
    })
}

pub(in crate::api::gateway) fn validate_walletconnect_connector_config(
    config: &WalletConnectConnectorConfig,
) -> anyhow::Result<()> {
    if config.schema != WALLETCONNECT_CONFIG_SCHEMA {
        anyhow::bail!("WalletConnect connector is not configured: unsupported config schema");
    }
    let project_id = config.project_id.trim();
    if project_id.len() < 8
        || project_id.len() > 128
        || !project_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        anyhow::bail!("WalletConnect connector is not configured: invalid project id");
    }
    if config.sdk_package != WALLETCONNECT_SDK_PACKAGE {
        anyhow::bail!("WalletConnect connector is not configured: unsupported SDK package");
    }
    let version = config.sdk_version.trim();
    if version.is_empty()
        || version.starts_with('^')
        || version.starts_with('~')
        || version.starts_with('*')
        || version.contains(char::is_whitespace)
    {
        anyhow::bail!("WalletConnect connector is not configured: SDK version must be pinned");
    }
    let digest = config.sdk_sha256.trim();
    if digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        anyhow::bail!("WalletConnect connector is not configured: invalid SDK hash");
    }
    Ok(())
}

fn walletconnect_hash(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

async fn walletconnect_request_binding(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    request_id: &str,
    status: &str,
) -> anyhow::Result<serde_json::Value> {
    let data = runtime_wallet_data(
        state,
        authority,
        elastos_wallet_contract::WalletProviderOperationV2::ListApprovals {
            include_resolved: true,
        },
    )
    .await?;
    let request = data["approval_requests"]
        .as_array()
        .and_then(|requests| requests.iter().find(|r| r["request_id"] == request_id))
        .ok_or_else(|| anyhow::anyhow!("WalletConnect approval request not found"))?;
    let late_transaction_receipt = status == "approved"
        && request["status"] == "rejected"
        && request["approved_at"].as_u64().is_some()
        && request["intent"] == "transaction_intent"
        && request["signed_result"].is_null()
        && request["wallet_outcome"].is_null()
        && request["rejection_reason"] == elastos_wallet_contract::WALLETCONNECT_DISMISSAL_REASON;
    // Wallet retains the original approved send until its first outcome.
    // Completion uses that stored authority even after the prompt expires.
    let awaiting_transaction_outcome = status == "approved"
        && request["status"] == "approved"
        && request["approved_at"].as_u64().is_some()
        && request["intent"] == "transaction_intent"
        && request["signed_result"].is_null()
        && request["signature_receipt"].is_null()
        && request["wallet_outcome"].is_null();
    anyhow::ensure!(
        request["principal_id"].as_str() == Some(authority.verified_context().principal_id())
            && request["connector_id"] == WALLET_WALLETCONNECT_CAPSULE_ID
            && (request["status"] == status || late_transaction_receipt)
            && (request["expires_at"].as_u64().is_some_and(|expiry| expiry > now_ts())
                || awaiting_transaction_outcome
                // Owner dismissal retains its separate bounded receipt window.
                || late_transaction_receipt
                    && request["expires_at"].as_u64().is_some_and(|expiry| expiry.saturating_add(elastos_wallet_contract::WALLETCONNECT_TRANSACTION_COMPLETION_GRACE_SECS) > now_ts()))
            && request["payload_hash"]
                .as_str()
                .is_some_and(walletconnect_hash),
        "WalletConnect request binding changed or expired"
    );
    Ok(request.clone())
}

fn validate_walletconnect_handoff(
    request_id: &str,
    binding: &serde_json::Value,
    approved: &Option<serde_json::Value>,
    handoff: &serde_json::Value,
) -> anyhow::Result<()> {
    let approved = approved
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("WalletConnect approval binding is missing"))?;
    for field in [
        "principal_id",
        "requested_by_actor",
        "account_id",
        "chain_namespace",
        "payload_hash",
        "expires_at",
    ] {
        anyhow::ensure!(
            !binding[field].is_null() && approved[field] == binding[field],
            "WalletConnect approval binding mismatch"
        );
    }
    anyhow::ensure!(
        handoff["request_id"] == request_id
            && handoff["payload_hash"] == binding["payload_hash"]
            && handoff["intent"] == binding["intent"]
            && handoff["signer"] == binding["address"],
        "WalletConnect handoff binding mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod sdk_verification_tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::thread::ThreadId;

    type Reads = HashMap<PathBuf, Vec<ThreadId>>;
    static READS: OnceLock<Mutex<Reads>> = OnceLock::new();
    static REPLACE: OnceLock<Mutex<HashMap<PathBuf, Vec<u8>>>> = OnceLock::new();
    pub(super) fn record_read(path: &FsPath) {
        if let Some(bytes) = REPLACE
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .remove(path)
        {
            let parent = path.parent().unwrap();
            std::fs::rename(parent, parent.with_extension("original")).unwrap();
            std::fs::create_dir_all(parent).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        READS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .entry(path.to_path_buf())
            .or_default()
            .push(std::thread::current().id());
    }
    fn reads(path: &FsPath) -> Vec<ThreadId> {
        READS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .unwrap_or_default()
    }
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, serde_json::Value) {
        let dir = tempfile::tempdir().unwrap();
        let sdk = dir.path().join(WALLETCONNECT_SDK_PATH);
        let config = dir.path().join(WALLETCONNECT_CONFIG_PATH);
        std::fs::create_dir_all(sdk.parent().unwrap()).unwrap();
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&sdk, b"fixture-sdk").unwrap();
        let value = serde_json::json!({"schema":WALLETCONNECT_CONFIG_SCHEMA,
            "project_id":"fixture-project", "sdk_package":WALLETCONNECT_SDK_PACKAGE,
            "sdk_version":"1.0.0", "sdk_sha256":format!("{:x}",Sha256::digest(b"fixture-sdk"))});
        std::fs::write(&config, value.to_string()).unwrap();
        (dir, sdk, config, value)
    }

    #[tokio::test]
    async fn walletconnect_sdk_cache_reuses_verification_and_invalidates_files_and_pin() {
        let (dir, sdk, config, mut value) = fixture();
        let cache = Mutex::default();
        let check = || async { ensure_wallet_connector_configured_with_cache(dir.path(), &cache) };
        check().await.unwrap();
        // Other Homes can fill and evict the process-wide cache between checks.
        let other_homes: Vec<_> = (0..16).map(|_| fixture()).collect();
        for (other, _, _, _) in &other_homes {
            ensure_wallet_connector_configured(other.path(), WALLET_WALLETCONNECT_CAPSULE_ID)
                .unwrap();
        }
        check().await.unwrap();
        assert_eq!(
            reads(&sdk).len(),
            1,
            "unchanged requests reuse the verified SDK"
        );
        // Same length and restored mtime still invalidate through ctime on Unix.
        let modified = std::fs::metadata(&sdk).unwrap().modified().unwrap();
        // Allow coarse filesystem change clocks to advance before restoring mtime.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        std::fs::write(&sdk, b"tampered!!!").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&sdk)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        assert!(
            check().await.is_err(),
            "same-size tampering invalidates the cache"
        );
        assert_eq!(reads(&sdk).len(), 2);
        // Allow coarse filesystem change clocks to advance before a same-size rewrite.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        std::fs::write(&sdk, b"fixture-sdk").unwrap();
        check().await.unwrap();
        let replacement = sdk.with_extension("replacement");
        std::fs::write(&replacement, b"tampered!!!").unwrap();
        std::fs::rename(&replacement, &sdk).unwrap();
        assert!(
            check().await.is_err(),
            "file replacement invalidates the cache"
        );
        // Allow coarse filesystem change clocks to advance before a same-size rewrite.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        std::fs::write(&sdk, b"fixture-sdk").unwrap();
        check().await.unwrap();
        value["sdk_sha256"] = serde_json::json!("00".repeat(32));
        std::fs::write(&config, value.to_string()).unwrap();
        assert!(
            check().await.is_err(),
            "a different pinned digest invalidates the cache"
        );
        std::fs::remove_file(&sdk).unwrap();
        let missing = check().await.unwrap_err();
        assert!(
            missing
                .to_string()
                .contains("WalletConnect connector is not configured: pinned SDK asset missing"),
            "missing SDK keeps the configuration error response: {missing}"
        );
    }

    #[test]
    fn walletconnect_sdk_verification_recovers_a_poisoned_cache_and_hashes_inline() {
        let (dir, sdk, _, _) = fixture();
        let cache = Mutex::default();
        let _ = std::panic::catch_unwind(|| {
            let _guard = cache.lock().unwrap();
            panic!("fixture poisoned cache");
        });
        ensure_wallet_connector_configured_with_cache(dir.path(), &cache).unwrap();
        assert_eq!(reads(&sdk), [std::thread::current().id()]);
    }

    #[tokio::test]
    async fn walletconnect_inventories_hash_on_the_blocking_pool() {
        for source in ["catalog", "launcher", "local-exit"] {
            let (dir, sdk, _, _) = fixture();
            // A declared app makes both inventory entrypoints exercise availability.
            std::fs::write(dir.path().join("components.json"), serde_json::json!({
                "external": { "wallet-walletconnect": { "install_path": "capsules/wallet-walletconnect", "platforms": {} } },
                "capsules": {}, "profiles": {}
            }).to_string()).unwrap();
            let capsule = dir.path().join("capsules/wallet-walletconnect");
            std::fs::write(
                capsule.join("capsule.json"),
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../../capsules/wallet-walletconnect/capsule.json"
                )),
            )
            .unwrap();
            std::fs::create_dir_all(capsule.join("browser")).unwrap();
            std::fs::write(capsule.join("browser/index.html"), "fixture").unwrap();
            match source {
                "catalog" => {
                    capsule_catalog_summary_async(dir.path()).await;
                }
                "launcher" => {
                    crate::api::browser_capsules::list_launchable_browser_capsules_async(
                        dir.path(),
                    )
                    .await;
                }
                _ => {
                    assert!(crate::setup::walletconnect::local_exit_async(
                        dir.path(),
                        "darwin-arm64"
                    )
                    .await
                    .is_some());
                }
            }
            assert!(
                !reads(&sdk).is_empty(),
                "{source} must exercise SDK verification"
            );
            assert!(
                reads(&sdk)
                    .iter()
                    .all(|thread| *thread != std::thread::current().id()),
                "{source} blocked the async thread"
            );
        }
    }

    #[test]
    fn walletconnect_sdk_caches_hash_failure_until_file_or_pin_changes() {
        let (dir, sdk, config, mut value) = fixture();
        let cache = Mutex::default();
        value["sdk_sha256"] = serde_json::json!("00".repeat(32));
        std::fs::write(&config, value.to_string()).unwrap();
        for _ in 0..2 {
            assert!(
                ensure_wallet_connector_configured_with_cache(dir.path(), &cache)
                    .unwrap_err()
                    .to_string()
                    .contains("hash mismatch")
            );
        }
        assert_eq!(reads(&sdk).len(), 1, "unchanged hash failures are cached");
        value["sdk_sha256"] = serde_json::json!(format!("{:x}", Sha256::digest(b"fixture-sdk")));
        std::fs::write(&config, value.to_string()).unwrap();
        ensure_wallet_connector_configured_with_cache(dir.path(), &cache).unwrap();
        assert_eq!(reads(&sdk).len(), 2, "a new pin is checked immediately");
        // Allow coarse filesystem change clocks to advance before a same-size rewrite.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&sdk, b"tampered!!!").unwrap();
        assert!(ensure_wallet_connector_configured_with_cache(dir.path(), &cache).is_err());
        assert_eq!(
            reads(&sdk).len(),
            3,
            "changed bytes are checked immediately"
        );
    }

    #[test]
    fn walletconnect_sdk_stamp_and_hash_use_the_same_open_file() {
        let (dir, sdk, _, _) = fixture();
        let cache = Mutex::default();
        REPLACE
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .insert(sdk.clone(), b"tampered!!!".to_vec());
        ensure_wallet_connector_configured_with_cache(dir.path(), &cache).unwrap();
        assert!(
            ensure_wallet_connector_configured_with_cache(dir.path(), &cache).is_err(),
            "next admission sees the replacement immediately"
        );
        assert_eq!(reads(&sdk).len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn walletconnect_sdk_refuses_a_final_symlink_even_after_a_cached_pass() {
        let (dir, sdk, _, _) = fixture();
        let cache = Mutex::default();
        ensure_wallet_connector_configured_with_cache(dir.path(), &cache).unwrap();
        let target = sdk.with_extension("target");
        std::fs::rename(&sdk, &target).unwrap();
        std::os::unix::fs::symlink(&target, &sdk).unwrap();
        assert!(ensure_wallet_connector_configured_with_cache(dir.path(), &cache).is_err());
        assert_eq!(reads(&sdk).len(), 1);
    }

    #[test]
    fn other_targets_need_neither_a_runtime_nor_a_blocking_pool_hop() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};
        for target in ["wallet-metamask", "wallet-unisat", "browser", "chat-room"] {
            let mut future = std::pin::pin!(ensure_wallet_connector_configured_async(
                FsPath::new("absent-fixture"),
                target
            ));
            assert!(matches!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Ok(()))
            ));
        }
    }
}

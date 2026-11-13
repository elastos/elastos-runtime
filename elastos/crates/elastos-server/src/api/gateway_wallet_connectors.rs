use super::*;

pub(in crate::api::gateway) async fn wallet_connector_config(
    State(state): State<GatewayState>,
    Path(wallet_connector): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = require_wallet_connector_launch_context(
        &state.data_dir,
        &headers,
        wallet_connector.as_str(),
    ) {
        return system_error_response(err);
    }

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
                payload["walletconnect"] = serde_json::json!({
                    "project_id": config.project_id,
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
    ) {
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
    ) {
        Ok(authority) => authority,
        Err(err) => return system_error_response(err),
    };
    let mut summary = system_wallet_approvals_summary(&state, &authority, false).await;
    summary.approval_requests.retain(|request| {
        !is_managed_wallet_proof_type(&request.proof_type)
            && request.connector_id.as_deref() == Some(wallet_connector.as_str())
    });
    summary.pending_count = summary.approval_requests.len();
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
    ) {
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
    ) {
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
            || (binding["intent"] == "transaction_intent"
                && (input.transaction_hash.is_none() || input.signature.is_some()))
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
            summary.note = Some(format!("Signed by {connector_label}."));
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

pub(in crate::api::gateway) fn require_wallet_connector_launch_context(
    data_dir: &FsPath,
    headers: &HeaderMap,
    connector_id: &str,
) -> anyhow::Result<HomeLaunchTokenContext> {
    if !is_wallet_connector_capsule_id(connector_id) {
        anyhow::bail!("unknown wallet connector capsule");
    }
    ensure_wallet_connector_configured(data_dir, connector_id)?;
    require_home_launch_token_context(data_dir, headers, connector_id)
}

pub(in crate::api::gateway) fn require_wallet_connector_launch_authority(
    data_dir: &FsPath,
    headers: &HeaderMap,
    connector_id: &str,
) -> anyhow::Result<RuntimeWalletAuthority> {
    if !is_wallet_connector_capsule_id(connector_id) {
        anyhow::bail!("unknown wallet connector capsule");
    }
    ensure_wallet_connector_configured(data_dir, connector_id)?;
    require_runtime_wallet_authority(data_dir, headers, &[connector_id])
}

pub(in crate::api::gateway) fn require_wallet_app_launch_authority(
    data_dir: &FsPath,
    headers: &HeaderMap,
) -> anyhow::Result<RuntimeWalletAuthority> {
    require_runtime_wallet_authority(data_dir, headers, &[WALLET_CAPSULE_ID])
}

pub(crate) fn ensure_wallet_connector_configured(
    data_dir: &FsPath,
    connector_id: &str,
) -> anyhow::Result<()> {
    if connector_id != WALLET_WALLETCONNECT_CAPSULE_ID {
        return Ok(());
    }
    let config = load_walletconnect_connector_config(data_dir)?;
    validate_walletconnect_connector_config(&config)?;

    let sdk_path = data_dir.join(WALLETCONNECT_SDK_PATH);
    let bytes =
        gateway_walletconnect::read_bytes(&sdk_path, 8 * 1024 * 1024)?.ok_or_else(|| {
            anyhow::anyhow!("WalletConnect connector is not configured: pinned SDK asset missing")
        })?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if !digest.eq_ignore_ascii_case(config.sdk_sha256.trim()) {
        anyhow::bail!("WalletConnect connector is not configured: pinned SDK hash mismatch");
    }
    Ok(())
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
    anyhow::ensure!(
        request["principal_id"].as_str() == Some(authority.verified_context().principal_id())
            && request["connector_id"] == WALLET_WALLETCONNECT_CAPSULE_ID
            && request["status"] == status
            && request["expires_at"]
                .as_u64()
                .is_some_and(|expiry| expiry > now_ts())
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

use super::*;

pub(in crate::api::gateway) async fn system_wallet_approvals(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    let authority =
        match require_runtime_wallet_authority(&state.data_dir, &headers, &[SYSTEM_CAPSULE_ID]) {
            Ok(authority) => authority,
            Err(err) => return system_error_response(err),
        };
    Json(system_wallet_approvals_summary(&state, &authority, false).await).into_response()
}

pub(in crate::api::gateway) async fn system_wallet_approval_reject(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(input): Json<WalletApprovalRejectRequest>,
) -> Response {
    let authority =
        match require_runtime_wallet_authority(&state.data_dir, &headers, &[SYSTEM_CAPSULE_ID]) {
            Ok(authority) => authority,
            Err(err) => return system_error_response(err),
        };
    let context = authority.home_launch_context();
    reject_wallet_approval_request(
        &state,
        &context,
        &authority,
        &request_id,
        input,
        SYSTEM_CAPSULE_ID,
    )
    .await
}

pub(in crate::api::gateway) fn wallet_approval_is_dismissal(request: &serde_json::Value) -> bool {
    request["approved_at"].as_u64().is_some()
        && request["intent"] == "transaction_intent"
        && request["connector_id"] == WALLET_WALLETCONNECT_CAPSULE_ID
}

pub(in crate::api::gateway) async fn reject_wallet_approval_request(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    authority: &RuntimeWalletAuthority,
    request_id: &str,
    input: WalletApprovalRejectRequest,
    capsule_id: &'static str,
) -> Response {
    match runtime_wallet_data(
        state,
        authority,
        elastos_wallet_contract::WalletProviderOperationV2::RejectApproval {
            request_id: request_id.to_string(),
            reason: input.reason.unwrap_or_else(|| {
                if capsule_id == SYSTEM_CAPSULE_ID {
                    "Rejected in System".to_string()
                } else {
                    "Rejected in Wallet".to_string()
                }
            }),
        },
    )
    .await
    {
        Ok(rejected) => {
            let dismissed = wallet_approval_is_dismissal(&rejected["approval_request"]);
            let _ = append_wallet_approval_audit(
                &state.data_dir,
                WalletApprovalAuditInput {
                    capsule_id,
                    event_type: if dismissed {
                        "wallet.approval.dismissed"
                    } else {
                        "wallet.approval.rejected"
                    },
                    principal_id: &context.principal_id,
                    session_id: &context.session_id,
                    request_id,
                    result: if dismissed { "dismissed" } else { "rejected" },
                    reason: if dismissed {
                        elastos_wallet_contract::WALLETCONNECT_DISMISSAL_REASON
                    } else {
                        "Wallet approval rejected through Runtime authority"
                    },
                },
            );
            let mut summary = system_wallet_approvals_summary(state, authority, false).await;
            if dismissed {
                summary.receipt_status = Some("dismissed".to_string());
                summary.note = Some(
                    "Request dismissed. This does not cancel a transaction in your wallet. Check your wallet before sending again."
                        .to_string(),
                );
            }
            Json(summary).into_response()
        }
        Err(err) => system_error_response(err),
    }
}

pub(in crate::api::gateway) async fn system_wallet_approval_approve(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(input): Json<WalletApprovalApproveRequest>,
) -> Response {
    let launch =
        match require_home_launch_token_binding(&state.data_dir, &headers, &[SYSTEM_CAPSULE_ID]) {
            Ok(launch) => launch,
            Err(err) => return system_error_response(err),
        };
    let authority = match runtime_wallet_authority(&launch) {
        Ok(authority) => authority,
        Err(err) => return system_error_response(err),
    };
    let context = launch.context.clone();
    approve_wallet_managed_request(
        &state,
        &launch,
        &context,
        &authority,
        &request_id,
        input,
        SYSTEM_CAPSULE_ID,
    )
    .await
}

pub(in crate::api::gateway) async fn approve_wallet_managed_request(
    state: &GatewayState,
    launch: &RequiredHomeLaunchToken,
    context: &HomeLaunchTokenContext,
    authority: &RuntimeWalletAuthority,
    request_id: &str,
    input: WalletApprovalApproveRequest,
    capsule_id: &'static str,
) -> Response {
    let request = match pending_wallet_approval_request(state, authority, request_id).await {
        Ok(request) => request,
        Err(err) => return system_error_response(err),
    };
    if request.intent == "browser_account_access" && capsule_id != WALLET_CAPSULE_ID {
        return system_error_response(anyhow::anyhow!(
            "Review Browser account access in Wallet before allowing it"
        ));
    }
    let Some(step_up_token) = input.step_up_token.as_deref() else {
        return system_error_response(anyhow::anyhow!(
            "fresh passkey verification is required to sign with a built-in wallet"
        ));
    };
    let reason = input.reason.clone().unwrap_or_else(|| {
        if capsule_id == SYSTEM_CAPSULE_ID {
            "Approved in System".to_string()
        } else {
            "Approved in Wallet".to_string()
        }
    });
    if let Err(err) = consume_passkey_step_up_token(
        &state.data_dir,
        step_up_token,
        launch,
        180,
        "wallet.approve",
        &serde_json::json!({
            "request_id": request_id,
            "reason": reason,
        }),
    ) {
        return system_error_response(err);
    }
    match approve_pending_managed_wallet_request(
        state,
        &state.data_dir,
        context,
        authority,
        request,
        &reason,
        capsule_id,
    )
    .await
    {
        Ok(outcome) => {
            let mut summary = system_wallet_approvals_summary(state, authority, false).await;
            summary.note = Some(outcome.message);
            Json(summary).into_response()
        }
        Err(err) => system_error_response(err),
    }
}

pub(in crate::api::gateway) struct WalletApprovalReviewOutcome {
    pub(in crate::api::gateway) message: String,
    pub(in crate::api::gateway) handoff: Option<serde_json::Value>,
    pub(in crate::api::gateway) approval_request: Option<serde_json::Value>,
}

pub(in crate::api::gateway) async fn approve_managed_wallet_request(
    state: &GatewayState,
    data_dir: &FsPath,
    context: &HomeLaunchTokenContext,
    authority: &RuntimeWalletAuthority,
    request_id: &str,
    reason: &str,
    capsule_id: &'static str,
) -> anyhow::Result<WalletApprovalReviewOutcome> {
    let request = pending_wallet_approval_request(state, authority, request_id).await?;
    approve_pending_managed_wallet_request(
        state, data_dir, context, authority, request, reason, capsule_id,
    )
    .await
}

pub(in crate::api::gateway) async fn approve_pending_managed_wallet_request(
    state: &GatewayState,
    data_dir: &FsPath,
    context: &HomeLaunchTokenContext,
    authority: &RuntimeWalletAuthority,
    request: SystemWalletApprovalSummary,
    reason: &str,
    capsule_id: &'static str,
) -> anyhow::Result<WalletApprovalReviewOutcome> {
    if request.intent == "browser_account_access" && capsule_id != WALLET_CAPSULE_ID {
        anyhow::bail!("Review Browser account access in Wallet before allowing it");
    }
    if !is_managed_wallet_proof_type(&request.proof_type) || request.connector_id.is_some() {
        anyhow::bail!("Open the approval method to approve external wallet requests");
    }
    let request_id = request.request_id.as_str();
    let signed = runtime_wallet_data(
        state,
        authority,
        elastos_wallet_contract::WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: request_id.to_string(),
            reason: reason.to_string(),
        },
    )
    .await?;
    append_wallet_approval_audit(
        data_dir,
        WalletApprovalAuditInput {
            capsule_id,
            event_type: "wallet.approval.completed",
            principal_id: &context.principal_id,
            session_id: &context.session_id,
            request_id,
            result: "completed",
            reason: "Built-in managed wallet signed after Runtime approval",
        },
    )?;
    Ok(WalletApprovalReviewOutcome {
        message: "Approved and signed by built-in wallet.".to_string(),
        handoff: None,
        approval_request: signed
            .get("approval_request")
            .filter(|value| value.is_object())
            .cloned(),
    })
}

pub(in crate::api::gateway) async fn approve_external_wallet_request(
    state: &GatewayState,
    data_dir: &FsPath,
    context: &HomeLaunchTokenContext,
    authority: &RuntimeWalletAuthority,
    request_id: &str,
    reason: &str,
    capsule_id: &str,
) -> anyhow::Result<WalletApprovalReviewOutcome> {
    let request = pending_wallet_approval_request(state, authority, request_id).await?;
    if capsule_id == WALLET_WALLETCONNECT_CAPSULE_ID {
        anyhow::ensure!(
            request.status == "pending" && request.expires_at > now_ts(),
            "WalletConnect request changed or expired"
        );
    }
    if is_managed_wallet_proof_type(&request.proof_type) {
        anyhow::bail!("Use System to approve built-in wallet requests");
    }
    if request.connector_id.as_deref() != Some(capsule_id) {
        anyhow::bail!("wallet approval belongs to a different connector");
    }
    let data = runtime_wallet_data(
        state,
        authority,
        elastos_wallet_contract::WalletProviderOperationV2::ApproveConnectorHandoff {
            request_id: request_id.to_string(),
            reason: reason.to_string(),
        },
    )
    .await?;
    let handoff = data.get("handoff").cloned();
    append_wallet_approval_audit(
        data_dir,
        WalletApprovalAuditInput {
            capsule_id,
            event_type: "wallet.approval.approved",
            principal_id: &context.principal_id,
            session_id: &context.session_id,
            request_id,
            result: "approved",
            reason: "External wallet approval reviewed through approval method",
        },
    )?;
    Ok(WalletApprovalReviewOutcome {
        message: format!(
            "Approved. Continue in {}.",
            wallet_connector_label(capsule_id)
        ),
        handoff,
        approval_request: data.get("approval_request").cloned(),
    })
}

pub(in crate::api::gateway) async fn complete_external_wallet_approval(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    authority: &RuntimeWalletAuthority,
    request_id: &str,
    input: WalletApprovalCompleteRequest,
    capsule_id: &str,
    audit_reason: &str,
) -> anyhow::Result<SystemWalletApprovalsSummary> {
    let completed = runtime_wallet_data(
        state,
        authority,
        elastos_wallet_contract::WalletProviderOperationV2::CompleteConnectorHandoff {
            request_id: request_id.to_string(),
            payload_hash: input.payload_hash,
            signature: input.signature,
            signature_type: input.signature_type,
            public_key: input.public_key,
            signer: input.signer,
            transaction_hash: input.transaction_hash,
        },
    )
    .await?;
    let late_receipt = completed["approval_request"]["status"] == "rejected";
    let receipt_status = if late_receipt {
        "sent_after_dismissal"
    } else {
        "completed"
    };
    append_wallet_approval_audit(
        &state.data_dir,
        WalletApprovalAuditInput {
            capsule_id,
            event_type: if late_receipt {
                "wallet.approval.sent_after_dismissal"
            } else {
                "wallet.approval.completed"
            },
            principal_id: &context.principal_id,
            session_id: &context.session_id,
            request_id,
            result: receipt_status,
            reason: if late_receipt {
                "Request dismissed. Your wallet reported this transaction as sent."
            } else {
                audit_reason
            },
        },
    )?;
    let mut summary = system_wallet_approvals_summary(state, authority, false).await;
    summary.receipt_status = Some(receipt_status.to_string());
    Ok(summary)
}

pub(in crate::api::gateway) async fn pending_wallet_approval_request(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    request_id: &str,
) -> anyhow::Result<SystemWalletApprovalSummary> {
    let summary = system_wallet_approvals_summary(state, authority, false).await;
    if !summary.available {
        anyhow::bail!(
            "{}",
            summary
                .note
                .unwrap_or_else(|| "wallet approvals unavailable".to_string())
        );
    }
    summary
        .approval_requests
        .into_iter()
        .find(|request| request.request_id == request_id)
        .ok_or_else(|| anyhow::anyhow!("wallet approval request not found"))
}

pub(in crate::api::gateway) async fn system_wallet_approvals_summary(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    include_resolved: bool,
) -> SystemWalletApprovalsSummary {
    let response = runtime_wallet_data(
        state,
        authority,
        elastos_wallet_contract::WalletProviderOperationV2::ListApprovals { include_resolved },
    )
    .await;
    match response {
        Ok(data) => {
            let approval_requests = data
                .get("approval_requests")
                .and_then(|value| value.as_array())
                .into_iter()
                .flatten()
                .filter_map(|record| {
                    let mut summary = system_wallet_approval_summary(record)?;
                    let actor = authority.verified_context().actor();
                    let private_audience = matches!(actor, WALLET_CAPSULE_ID | INBOX_CAPSULE_ID)
                        || (!is_managed_wallet_proof_type(&summary.proof_type)
                            && summary.connector_id.as_deref() == Some(actor));
                    if private_audience
                        && record["principal_id"].as_str()
                            == Some(authority.verified_context().principal_id())
                        && (summary.intent != "transaction_intent"
                            || gateway_transaction_effects::wallet_display_transaction_bound(
                                state, authority, record,
                            ))
                    {
                        summary.requesting_origin = wallet_request_display_origin(record);
                    }
                    Some(summary)
                })
                .collect::<Vec<_>>();
            let pending_count = approval_requests
                .iter()
                .filter(|request| request.status == "pending")
                .count();
            SystemWalletApprovalsSummary {
                available: true,
                receipt_status: None,
                pending_count,
                approval_requests,
                handoff: None,
                note: None,
            }
        }
        Err(err) => SystemWalletApprovalsSummary {
            available: false,
            note: Some(err.to_string()),
            ..SystemWalletApprovalsSummary::default()
        },
    }
}

pub(in crate::api::gateway) struct WalletApprovalAuditInput<'a> {
    pub(in crate::api::gateway) capsule_id: &'a str,
    pub(in crate::api::gateway) event_type: &'a str,
    pub(in crate::api::gateway) principal_id: &'a str,
    pub(in crate::api::gateway) session_id: &'a str,
    pub(in crate::api::gateway) request_id: &'a str,
    pub(in crate::api::gateway) result: &'a str,
    pub(in crate::api::gateway) reason: &'a str,
}

pub(in crate::api::gateway) struct ProviderEffectAuditInput<'a> {
    pub(in crate::api::gateway) capsule_id: &'a str,
    pub(in crate::api::gateway) event_type: &'a str,
    pub(in crate::api::gateway) principal_id: &'a str,
    pub(in crate::api::gateway) session_id: &'a str,
    pub(in crate::api::gateway) request_id: &'a str,
    pub(in crate::api::gateway) result: &'a str,
    pub(in crate::api::gateway) reason: &'a str,
}

#[derive(Debug, Clone)]
pub(in crate::api::gateway) struct ChainLifecycleEffectAudit {
    pub(in crate::api::gateway) request_id: String,
    pub(in crate::api::gateway) network: String,
    pub(in crate::api::gateway) action: String,
}

pub(in crate::api::gateway) fn chain_lifecycle_effect_audit(
    scheme: &str,
    op: &str,
    request: &serde_json::Value,
) -> Option<ChainLifecycleEffectAudit> {
    if scheme != "chain" || op != "node_lifecycle" {
        return None;
    }
    let network = request.get("network")?.as_str()?.trim();
    let action = request.get("action")?.as_str()?.trim();
    if network.is_empty() || action.is_empty() || action == "status" {
        return None;
    }
    Some(ChainLifecycleEffectAudit {
        request_id: format!("chain-node-lifecycle:{network}:{action}:{}", now_ts()),
        network: network.to_string(),
        action: action.to_string(),
    })
}

pub(in crate::api::gateway) fn append_provider_effect_audit(
    data_dir: &FsPath,
    input: ProviderEffectAuditInput<'_>,
) -> anyhow::Result<()> {
    let now = now_ts();
    crate::auth::append_audit_event(
        data_dir,
        RuntimeAuditEventV1 {
            schema: RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: format!(
                "audit:provider-effect:{}:{}:{now}",
                input.event_type, input.request_id
            ),
            event_type: input.event_type.to_string(),
            principal_id: Some(input.principal_id.to_string()),
            proof_binding_id: None,
            session_id: Some(input.session_id.to_string()),
            challenge_id: Some(input.request_id.to_string()),
            capsule_id: Some(input.capsule_id.to_string()),
            result: input.result.to_string(),
            reason: input.reason.to_string(),
            occurred_at: now,
            signer_did: None,
            signature: None,
        },
    )
}

pub(in crate::api::gateway) fn append_wallet_approval_audit(
    data_dir: &FsPath,
    input: WalletApprovalAuditInput<'_>,
) -> anyhow::Result<()> {
    let now = now_ts();
    crate::auth::append_audit_event(
        data_dir,
        RuntimeAuditEventV1 {
            schema: RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: format!(
                "audit:wallet-approval:{}:{}:{now}",
                input.event_type, input.request_id
            ),
            event_type: input.event_type.to_string(),
            principal_id: Some(input.principal_id.to_string()),
            proof_binding_id: None,
            session_id: Some(input.session_id.to_string()),
            challenge_id: Some(input.request_id.to_string()),
            capsule_id: Some(input.capsule_id.to_string()),
            result: input.result.to_string(),
            reason: input.reason.to_string(),
            occurred_at: now,
            signer_did: None,
            signature: None,
        },
    )
}

pub(in crate::api::gateway) fn system_wallet_approval_summary(
    value: &serde_json::Value,
) -> Option<SystemWalletApprovalSummary> {
    let signed_result = value.get("signed_result").filter(|value| value.is_object());
    let signature_receipt = value
        .get("signature_receipt")
        .filter(|value| value.is_object());
    Some(SystemWalletApprovalSummary {
        requesting_app_name: Some(gateway_home_runtime::app_shell_title(
            value
                .get("requested_by_actor")
                .or_else(|| value.get("capsule_id"))?
                .as_str()?,
        )),
        requesting_origin: None,
        request_id: value.get("request_id")?.as_str()?.to_string(),
        status: value.get("status")?.as_str()?.to_string(),
        intent: value.get("intent")?.as_str()?.to_string(),
        capsule_id: value
            .get("requested_by_actor")
            .or_else(|| value.get("capsule_id"))?
            .as_str()?
            .to_string(),
        resource: value.get("resource")?.as_str()?.to_string(),
        reason: value.get("reason")?.as_str()?.to_string(),
        account_id: value.get("account_id")?.as_str()?.to_string(),
        address: value.get("address")?.as_str()?.to_string(),
        chain_namespace: value
            .get("chain_namespace")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        proof_type: value
            .get("proof_type")
            .and_then(|value| value.as_str())
            .unwrap_or("external")
            .to_string(),
        connector_id: value
            .get("connector_id")
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        review: wallet_account_access_review(value),
        created_at: value.get("created_at")?.as_u64()?,
        expires_at: value.get("expires_at")?.as_u64()?,
        completed_at: value
            .get("completed_at")
            .and_then(|value| value.as_u64())
            .or_else(|| {
                signature_receipt
                    .and_then(|value| value.get("completed_at"))
                    .and_then(|value| value.as_u64())
            }),
        approved_at: value.get("approved_at").and_then(|value| value.as_u64()),
        transaction_hash: signed_result
            .and_then(|value| value.get("transaction_hash"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
    })
}

/// Display context from the local Browser producer's immutable recorded fields.
/// The caller applies audience/session visibility and the transaction effect check.
pub(in crate::api::gateway) fn wallet_request_display_origin(
    record: &serde_json::Value,
) -> Option<String> {
    if record.get("schema")?.as_str()? != "elastos.wallet.approval_request/v1" {
        return None;
    }
    if record.get("requested_by_actor")?.as_str()? != BROWSER_CAPSULE_ID {
        return None;
    }
    let payload = record.get("payload")?;
    if serde_json::to_vec(payload).ok()?.len() > 32 * 1024 {
        return None;
    }
    let text = |key: &str| payload.get(key).and_then(|v| v.as_str());
    for key in [
        "principal_id",
        "session_id",
        "account_id",
        "chain_namespace",
    ] {
        if key == "chain_namespace" && record["intent"] == "browser_account_access" {
            continue;
        }
        if text(key)? != record.get(key)?.as_str()? || text(key)?.is_empty() {
            return None;
        }
    }
    let address_key = if record["intent"] == "transaction_intent" {
        "from"
    } else {
        "address"
    };
    if !text(address_key)?.eq_ignore_ascii_case(record.get("address")?.as_str()?) {
        return None;
    }
    match record.get("intent")?.as_str()? {
        "browser_personal_sign"
            if text("schema")? == "elastos.browser.wallet-signature-request/v1"
                && payload.get("requires_wallet_approval")?.as_bool()?
                && text("method")? == "personal_sign" => {}
        "browser_typed_data_sign"
            if text("schema")? == "elastos.browser.wallet-signature-request/v1"
                && payload.get("requires_wallet_approval")?.as_bool()?
                && matches!(
                    text("method")?,
                    "eth_signTypedData" | "eth_signTypedData_v3" | "eth_signTypedData_v4"
                ) => {}
        "transaction_intent"
            if text("schema")? == "elastos.chain.unsigned_transaction_intent/v1"
                && text("source")? == "browser_wallet" => {}
        "browser_account_access"
            if text("schema")? == "elastos.browser.account-access-request/v1"
                && wallet_account_access_review(record).is_some() => {}
        _ => return None,
    }
    let origin = text("origin")?;
    if origin.is_empty()
        || origin.len() > 512
        || !origin.is_ascii()
        || origin.bytes().any(|b| {
            b.is_ascii_whitespace()
                || b.is_ascii_control()
                || matches!(b, b'\\' | b'@' | b'?' | b'#')
        })
    {
        return None;
    }
    let (_, authority) = origin.split_once("://")?;
    if authority.is_empty() || authority.contains('/') {
        return None;
    }
    let parsed = url::Url::parse(origin).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return None;
    }
    let page = url::Url::parse(text("page_url")?).ok()?;
    if parsed.origin() != page.origin() {
        return None;
    }
    let display = parsed.origin().ascii_serialization();
    if display.is_empty() || display.len() > 512 || !display.is_ascii() {
        return None;
    }
    Some(display)
}

fn wallet_account_access_review(value: &serde_json::Value) -> Option<serde_json::Value> {
    if value.get("intent")?.as_str()? != "browser_account_access" {
        return None;
    }
    if value
        .get("requested_by_actor")
        .or_else(|| value.get("capsule_id"))?
        .as_str()?
        != BROWSER_CAPSULE_ID
    {
        return None;
    }
    let payload = value.get("payload")?.as_object()?;
    let text = |field: &str| payload.get(field).and_then(|value| value.as_str());
    if text("schema")? != "elastos.browser.account-access-request/v1"
        || text("permission")? != "eth_accounts"
        || text("principal_id")? != value.get("principal_id")?.as_str()?
        || text("session_id")? != value.get("session_id")?.as_str()?
        || text("launch_id")? != value.get("launch_id")?.as_str()?
        || text("account_id")? != value.get("account_id")?.as_str()?
        || text("requested_chain_namespace")? != value.get("chain_namespace")?.as_str()?
        || !text("address")?.eq_ignore_ascii_case(value.get("address")?.as_str()?)
        || text("proof_binding_id")?.trim().is_empty()
        || payload
            .get("requires_wallet_approval")
            .and_then(|value| value.as_bool())
            != Some(true)
    {
        return None;
    }
    let chain_namespaces = payload.get("chain_namespaces")?.as_array()?;
    if chain_namespaces.len() != 2
        || chain_namespaces[0].as_str() != Some("eip155:20")
        || chain_namespaces[1].as_str() != Some("eip155:8453")
        || !matches!(
            text("requested_chain_namespace")?,
            "eip155:20" | "eip155:8453"
        )
    {
        return None;
    }
    let origin = text("origin")?;
    let page_url = text("page_url")?;
    let page = url::Url::parse(page_url).ok()?;
    let parsed_origin = url::Url::parse(origin).ok()?;
    if !matches!(page.scheme(), "http" | "https")
        || page.host_str().is_none()
        || !matches!(parsed_origin.scheme(), "http" | "https")
        || parsed_origin.host_str().is_none()
        || parsed_origin.origin().ascii_serialization() != origin
        || page.origin() != parsed_origin.origin()
    {
        return None;
    }
    let grant_expires_at = payload.get("grant_expires_at")?.as_u64()?;
    if grant_expires_at <= now_ts() || grant_expires_at > now_ts().saturating_add(12 * 60 * 60) {
        return None;
    }
    Some(serde_json::json!({
        "kind": "account_access",
        "permission": "eth_accounts",
        "origin": origin,
        "page_url": page_url,
        "account_id": text("account_id")?,
        "requested_chain_namespace": text("requested_chain_namespace")?,
        "chain_namespaces": chain_namespaces,
        "address": text("address")?,
        "grant_expires_at": grant_expires_at,
    }))
}

#[cfg(test)]
mod wallet_display_tests {
    use super::*;
    use serde_json::json;

    fn browser_request(origin: &str, page_url: &str) -> serde_json::Value {
        json!({"schema":"elastos.wallet.approval_request/v1", "request_id":"request:display", "status":"pending", "intent":"browser_personal_sign",
            "requested_by_actor":"browser", "principal_id":"person:test", "session_id":"session:test",
            "account_id":"account:test", "address":"0xabc", "chain_namespace":"eip155:20", "resource":"wallet:test",
            "reason":"Sign message", "proof_type":"siwe", "connector_id":"wallet-metamask", "created_at":1, "expires_at":u64::MAX,
            "payload":{"schema":"elastos.browser.wallet-signature-request/v1", "requires_wallet_approval":true, "method":"personal_sign",
                "principal_id":"person:test", "session_id":"session:test", "account_id":"account:test",
                "chain_namespace":"eip155:20", "address":"0xabc", "origin":origin, "page_url":page_url}})
    }

    #[test]
    fn n7_origin_form_and_ascii_vectors() {
        for (source, page, expected) in [
            (
                "https://Shop.Example:443",
                "https://shop.example/pay?q=secret",
                Some("https://shop.example"),
            ),
            (
                "http://localhost:8099",
                "http://localhost:8099/pay",
                Some("http://localhost:8099"),
            ),
            (
                "https://[2001:db8::1]:443",
                "https://[2001:db8::1]/",
                Some("https://[2001:db8::1]"),
            ),
            (
                "https://xn--bcher-kva.example",
                "https://xn--bcher-kva.example/",
                Some("https://xn--bcher-kva.example"),
            ),
            (
                "https://shop_sub.example:8443",
                "https://shop_sub.example:8443/private",
                Some("https://shop_sub.example:8443"),
            ),
            ("https://bücher.example", "https://bücher.example/", None),
            (
                "https://user:pass@shop.example",
                "https://shop.example/",
                None,
            ),
            ("https://@shop.example", "https://shop.example/", None),
            ("https://shop.example/", "https://shop.example/", None),
            ("https://shop.example/pay", "https://shop.example/pay", None),
            ("https://shop.example?q", "https://shop.example/", None),
            (
                "https://shop.example#fragment",
                "https://shop.example/",
                None,
            ),
            ("https://shop.example", "https://other.example/", None),
            ("https:\\shop.example", "https://shop.example/", None),
            ("https://shop.\nexample", "https://shop.example/", None),
        ] {
            let record = browser_request(source, page);
            let before = record.clone();
            assert_eq!(
                wallet_request_display_origin(&record).as_deref(),
                expected,
                "{source:?}"
            );
            assert_eq!(record, before);
        }
        let mut large = browser_request("https://shop.example", "https://shop.example/");
        large["payload"]["private"] = json!("x".repeat(32768));
        assert_eq!(wallet_request_display_origin(&large), None);
    }

    #[test]
    fn n7_site_absent_or_forged_origin() {
        let valid = browser_request("https://shop.example", "https://shop.example/private");
        assert!(wallet_request_display_origin(&valid).is_some());
        for field in [
            "principal_id",
            "session_id",
            "account_id",
            "address",
            "chain_namespace",
        ] {
            let mut record = valid.clone();
            record["payload"][field] = json!("forged");
            assert_eq!(wallet_request_display_origin(&record), None, "{field}");
        }
        for origin in [
            serde_json::Value::Null,
            json!(123),
            json!(""),
            json!("a".repeat(513)),
        ] {
            let mut record = valid.clone();
            record["payload"]["origin"] = origin;
            assert_eq!(wallet_request_display_origin(&record), None);
        }
        let mut other = valid.clone();
        other["requested_by_actor"] = json!("notes");
        other["requesting_origin"] = json!("https://shop.example");
        assert_eq!(wallet_request_display_origin(&other), None);
        let mut remote = valid.clone();
        remote["payload"]["schema"] = json!("elastos.browser.engine.wallet-consumer-request/v1");
        assert_eq!(wallet_request_display_origin(&remote), None);
        // Generic summary mapping remains app-only for Home/System/Chat.
        assert!(
            serde_json::to_value(system_wallet_approval_summary(&valid).unwrap())
                .unwrap()
                .get("requesting_origin")
                .is_none()
        );
    }

    #[test]
    fn n3_external_inbox_review_action_classification() {
        for proof in ["siwe", "unknown", "", "managed_evm", "managed_btc_p2wpkh"] {
            for connector in [
                serde_json::Value::Null,
                json!("wallet-metamask"),
                json!("unknown"),
            ] {
                let mut record = browser_request("https://shop.example", "https://shop.example/");
                record["proof_type"] = json!(proof);
                record["connector_id"] = connector.clone();
                let mut notifications = HomeNotificationsSummary::default();
                append_wallet_approval_notifications(
                    &mut notifications,
                    vec![system_wallet_approval_summary(&record).unwrap()],
                );
                let external = !is_managed_wallet_proof_type(proof) || !connector.is_null();
                assert_eq!(
                    notifications.entries[0]
                        .action_ref
                        .as_ref()
                        .unwrap()
                        .action_id,
                    format!(
                        "wallet-{}-request:request:display",
                        if external { "review" } else { "approve" }
                    )
                );
            }
        }
    }

    #[test]
    fn n3_requester_provenance_without_site_invention() {
        let mut record = browser_request("https://shop.example", "https://shop.example/");
        record["capsule_id"] = json!("forged");
        record["reason"] = json!("Home says https://fake.example");
        let summary = system_wallet_approval_summary(&record).unwrap();
        assert_eq!(summary.capsule_id, "browser");
        assert!(summary.requesting_origin.is_none());
    }

    #[test]
    fn n7_account_access_uses_same_projection() {
        let mut record = browser_request("https://shop.example", "https://shop.example/private");
        record["intent"] = json!("browser_account_access");
        record["launch_id"] = json!("launch:browser");
        let payload = record["payload"].as_object_mut().unwrap();
        payload.insert(
            "schema".into(),
            json!("elastos.browser.account-access-request/v1"),
        );
        payload.insert("permission".into(), json!("eth_accounts"));
        payload.insert("launch_id".into(), json!("launch:browser"));
        payload.insert("proof_binding_id".into(), json!("proof:fixture"));
        payload.insert("requested_chain_namespace".into(), json!("eip155:20"));
        payload.insert(
            "chain_namespaces".into(),
            json!(["eip155:20", "eip155:8453"]),
        );
        payload.insert("grant_expires_at".into(), json!(now_ts() + 600));
        payload.insert("requires_wallet_approval".into(), json!(true));
        let before = record.clone();
        assert_eq!(
            wallet_request_display_origin(&record).as_deref(),
            Some("https://shop.example")
        );
        assert_eq!(
            record, before,
            "site projection keeps the account-access proof bindings"
        );
        record["payload"]["origin"] = serde_json::Value::Null;
        assert!(
            wallet_request_display_origin(&record).is_none(),
            "page_url supplies no display fallback"
        );
    }
}

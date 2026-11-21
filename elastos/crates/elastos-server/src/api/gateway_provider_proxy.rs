use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use elastos_protected_content_contracts::{CanonicalContract, Digest32};
use sha2::Digest as _;

use super::*;
use elastos_model_contract::{
    model_input_hash, RuntimeAccessBinding, RuntimeCreateBinding, RUNTIME_ACCESS_BINDING_SCHEMA,
    RUNTIME_CREATE_BINDING_SCHEMA,
};

const ASSISTANT_CAPSULE_ID: &str = "assistant";
/// The Home Agent capsule reaches the model provider through the same typed
/// contract as Assistant; every run is bound and audited to the capsule the
/// launch token was issued for.
const HOME_AGENT_CAPSULE_ID: &str = "home-agent";
const MODEL_TEXT_OUTPUT_SCHEMA: &str = "elastos.model.output.text/v1";
const MODEL_OBJECT_OUTPUT_SCHEMA: &str = "elastos.model.output.object/v1";
const MODEL_CONTENT_OUTPUT_SCHEMA: &str = "elastos.model.output.content/v1";
const MODEL_OUTPUT_URI_MAX_BYTES: usize = 4 * 1024;
use crate::protected_content_runtime::ELACITY_PLAYER_CAPSULE_ID;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelRunsCreateGatewayRequest {
    offer_id: String,
    operation: String,
    input: serde_json::Value,
    request_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelRunAccessGatewayRequest {
    run_id: String,
    request_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelRunEventsGatewayRequest {
    run_id: String,
    request_id: String,
    #[serde(default)]
    after_sequence: Option<u64>,
}

struct ModelProviderEffectAudit<'a> {
    request_id: &'a str,
    requested_event: &'static str,
    completed_event: &'static str,
    failed_event: &'static str,
    requested_reason: &'static str,
    completed_reason: &'static str,
    failed_reason: &'static str,
}

/// The creator tail fails closed with one opaque message; keep the actual
/// cause and its source line in the operator log so a live failure can be
/// located without re-instrumenting.
macro_rules! creator_mint_unavailable {
    () => {
        |error| {
            tracing::warn!(
                line = line!(),
                error = ?error,
                "Runtime custody creator mint failed closed"
            );
            anyhow::anyhow!("{:?}", error)
                .context(format!("{}:{}", file!(), line!()))
                .context(RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE)
        }
    };
}

/// Same operator-log discipline for the buyer side: "purchase is denied
/// before buy" is one opaque message over many fail-closed preconditions.
macro_rules! purchase_denied {
    () => {
        |error| {
            tracing::warn!(
                line = line!(),
                error = ?error,
                "Runtime custody purchase denied before buy"
            );
            anyhow::anyhow!("{:?}", error)
                .context(format!("{}:{}", file!(), line!()))
                .context(crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_DENIED_MESSAGE)
        }
    };
}

macro_rules! purchase_denied_missing {
    () => {
        || {
            tracing::warn!(line = line!(), "Runtime custody purchase denied before buy");
            anyhow::anyhow!("{}:{}", file!(), line!())
                .context(crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_DENIED_MESSAGE)
        }
    };
}

macro_rules! purchase_unavailable {
    () => {
        |error| {
            tracing::warn!(
                line = line!(),
                error = ?error,
                "Runtime custody purchase failed closed"
            );
            anyhow::anyhow!("{:?}", error)
                .context(format!("{}:{}", file!(), line!()))
                .context(crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_UNAVAILABLE_MESSAGE)
        }
    };
}

macro_rules! purchase_unavailable_missing {
    () => {
        || {
            tracing::warn!(line = line!(), "Runtime custody purchase failed closed");
            anyhow::anyhow!("{}:{}", file!(), line!()).context(
                crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_UNAVAILABLE_MESSAGE,
            )
        }
    };
}

macro_rules! creator_mint_unavailable_missing {
    () => {
        || {
            tracing::warn!(line = line!(), "Runtime custody creator mint failed closed");
            anyhow::anyhow!("{}:{}", file!(), line!())
                .context(RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE)
        }
    };
}

#[path = "gateway_provider_proxy/creator_publish.rs"]
mod creator_publish;
#[path = "gateway_provider_proxy/custody_buy.rs"]
mod custody_buy;
#[path = "gateway_provider_proxy/library_transfer.rs"]
mod library_transfer;

pub(crate) use self::creator_publish::*;
pub(crate) use self::custody_buy::*;
pub(super) use self::library_transfer::*;

#[derive(Clone)]
struct RuntimeCustodyCreatorAccount {
    account_id: String,
    address: String,
}

pub(super) async fn gateway_provider_proxy(
    State(state): State<GatewayState>,
    Path((scheme, op)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let allowed_apps: &[&str] = match scheme.as_str() {
        "documents" => match op.as_str() {
            "summary" | "get" => &[DOCUMENTS_CAPSULE_ID, LIBRARY_CAPSULE_ID],
            _ => &[DOCUMENTS_CAPSULE_ID],
        },
        "object" => match op.as_str() {
            "roots"
            | "list"
            | "stat"
            | "read"
            | "download"
            | "write"
            | "mkdir"
            | "rename"
            | "move"
            | "copy"
            | "trash"
            | "restore"
            | "delete_permanently"
            | "empty_trash"
            | "status"
            | "sync"
            | "extract_archive"
            | "archive_entries"
            | "archive_preview_entry"
            | "archive_extract_entries"
            | "compress_archive"
            | "publish"
            | "unpublish"
            | "repair"
            | "share"
            | "shared_access"
            | "events" => &[LIBRARY_CAPSULE_ID],
            "open_viewer" | "read_viewer" | "close_viewer" => &[ELACITY_PLAYER_CAPSULE_ID],
            "import_runtime_custody" => &[LIBRARY_CAPSULE_ID, MARKETPLACE_CAPSULE_ID],
            "list_runtime_custody" | "buy" => &[LIBRARY_CAPSULE_ID, MARKETPLACE_CAPSULE_ID],
            _ => {
                return (
                    StatusCode::NOT_FOUND,
                    "Gateway provider operation not found",
                )
                    .into_response()
            }
        },
        "chain" => match op.as_str() {
            "networks" | "status" | "block_number" | "sync_health" | "node_lifecycle" => {
                &[SYSTEM_CAPSULE_ID]
            }
            "balance" => &[SYSTEM_CAPSULE_ID, WALLET_CAPSULE_ID],
            _ => {
                return (
                    StatusCode::NOT_FOUND,
                    "Gateway provider operation not found",
                )
                    .into_response()
            }
        },
        "net" => match op.as_str() {
            "status" | "resolve" | "connect" | "stream" | "http" => &[BROWSER_CAPSULE_ID],
            _ => {
                return (
                    StatusCode::NOT_FOUND,
                    "Gateway provider operation not found",
                )
                    .into_response()
            }
        },
        "inspect" => match op.as_str() {
            "capsules" | "capsule" | "self" | "plan" | "request_act" => &[SYSTEM_CAPSULE_ID],
            _ => {
                return (
                    StatusCode::NOT_FOUND,
                    "Gateway provider operation not found",
                )
                    .into_response()
            }
        },
        "model" => match op.as_str() {
            "offers_list" => &[
                ASSISTANT_CAPSULE_ID,
                HOME_AGENT_CAPSULE_ID,
                MARKETPLACE_CAPSULE_ID,
            ],
            "runs_create" | "runs_get" | "runs_events" | "runs_cancel" => {
                &[ASSISTANT_CAPSULE_ID, HOME_AGENT_CAPSULE_ID]
            }
            _ => {
                return (
                    StatusCode::NOT_FOUND,
                    "Gateway provider operation not found",
                )
                    .into_response()
            }
        },
        _ => return (StatusCode::NOT_FOUND, "Gateway provider not found").into_response(),
    };
    let required = match require_home_launch_token_binding(&state.data_dir, &headers, allowed_apps)
    {
        Ok(required) => required,
        Err(err) => return gateway_provider_error_response(&scheme, err),
    };
    let is_protected_viewer_op =
        scheme == "object" && matches!(op.as_str(), "open_viewer" | "read_viewer" | "close_viewer");
    if is_protected_viewer_op
        && (required.launch_context.selected_resource != ELACITY_PLAYER_CAPSULE_ID
            || required.launch_context.executable_actor != ELACITY_PLAYER_CAPSULE_ID)
    {
        return (
            StatusCode::FORBIDDEN,
            "home launch token is not authorized for this viewer",
        )
            .into_response();
    }
    let context = required.context.clone();
    let principal_id = context.principal_id.clone();
    let session_id = context.session_id.clone();
    /* The verified capsule behind the launch token: model runs are bound and
    audited to it, never to a fixed name. */
    let launch_capsule_id = required.launch_context.executable_actor.clone();
    if scheme == "net" && matches!(op.as_str(), "http" | "connect" | "resolve" | "stream") {
        return (
            StatusCode::GONE,
            format!("legacy /api/provider/net/{op} is disabled; Browser streams must be opened through /api/apps/browser/open"),
        ).into_response();
    }
    let registry = match state.provider_registry.as_ref().cloned() {
        Some(registry) => registry,
        None => {
            return gateway_provider_error_response(
                &scheme,
                anyhow::anyhow!("{} provider unavailable", scheme),
            )
        }
    };
    let mut request = if body.is_empty() {
        serde_json::json!({})
    } else {
        match serde_json::from_slice::<serde_json::Value>(&body) {
            Ok(value) if value.is_object() => value,
            Ok(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "provider request body must be a JSON object",
                )
                    .into_response();
            }
            Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
        }
    };
    if let Some(field) = provider_proxy_runtime_metadata_field(&request) {
        return (
            StatusCode::BAD_REQUEST,
            format!("provider request must not predeclare Runtime metadata field {field}"),
        )
            .into_response();
    }
    let mut remote_model_grants = Vec::new();
    if scheme == "model" {
        request =
            match normalize_model_provider_request(&op, &request, &context, &launch_capsule_id) {
                Ok(value) => value,
                Err((status, message)) => return (status, message).into_response(),
            };
        if op == "runs_create" && !hosted_run_allowed(&state.data_dir, &context, &request) {
            return (StatusCode::FORBIDDEN, HOSTED_RUN_ADMIN_ONLY).into_response();
        }
        // Approved remote model grants route new runs to the granting Runtime.
        // A grant lookup failure keeps the local path; it cannot widen
        // authority. Runs already routed remotely settle through their stored
        // route even after the grant expired or was denied, so every run
        // operation consults the route; a local run returns to the local path.
        remote_model_grants = super::gateway_model_remote::consumer_grants(
            &state.data_dir,
            &context,
            state.collaboration_discovery_service.as_ref(),
        )
        .unwrap_or_default();
        if op != "offers_list" {
            match super::gateway_model_remote::route_run_operation(
                Arc::clone(&registry),
                &state.data_dir,
                &remote_model_grants,
                &context,
                &launch_capsule_id,
                (&op, &request),
                crate::auth::now_ts(),
            )
            .await
            {
                Ok(Some(mut remote_response)) => {
                    if let Err(err) = project_model_provider_response(&op, &mut remote_response) {
                        return gateway_provider_error_response(
                            &scheme,
                            anyhow::anyhow!(
                                "remote model service returned an invalid typed response: {err}"
                            ),
                        );
                    }
                    return (StatusCode::OK, Json(remote_response)).into_response();
                }
                Ok(None) => {}
                Err(super::gateway_model_remote::RemoteRouteError::InvocationRefused {
                    binding,
                    reason,
                }) => {
                    return (
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({
                            "status": "error", "code": "remote_model_invocation_refused",
                            "message": super::gateway_model_service::invocation_refusal_message(&reason),
                            "reason": reason, "refusal": binding,
                        })),
                    )
                        .into_response();
                }
                Err(super::gateway_model_remote::RemoteRouteError::Transport(message)) => {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(serde_json::json!({
                            "status": "error",
                            "code": super::gateway_model_remote::TRANSPORT_INTERRUPTED,
                            "message": format!("remote model service unreachable: {message}"),
                        })),
                    )
                        .into_response();
                }
                Err(err) => {
                    return gateway_provider_error_response(&scheme, anyhow::anyhow!("{err}"));
                }
            }
        }
    } else {
        request["op"] = serde_json::Value::String(op.clone());
    }
    if scheme == "documents" || scheme == "object" || scheme == "net" {
        request["principal_id"] = serde_json::Value::String(principal_id.clone());
    }
    if is_protected_viewer_op {
        if let Some(object) = request.as_object_mut() {
            object.remove("launch_id");
            object.remove("proof_binding_id");
            object.remove("session_id");
            object.remove("grant_id");
            object.remove("wallet_request_hex");
            object.remove("wallet_response_hex");
            if let Some(proof) = context
                .proof_binding_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                object.insert(
                    "proof_binding_id".to_string(),
                    serde_json::Value::String(proof.to_string()),
                );
            }
            if !context.session_id.trim().is_empty() {
                object.insert(
                    "session_id".to_string(),
                    serde_json::Value::String(context.session_id.clone()),
                );
            }
            if !context.grant_id.trim().is_empty() {
                object.insert(
                    "grant_id".to_string(),
                    serde_json::Value::String(context.grant_id.clone()),
                );
            }
            object.insert(
                "launch_id".to_string(),
                serde_json::Value::String(required.launch_id.clone()),
            );
        }
    }
    if scheme == "object" && op == "shared_access" {
        if let Some(object) = request.as_object_mut() {
            object.remove("recipient_proof");
            if object
                .get("recipient")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                == Some(principal_id.as_str())
                && context.proof_binding_id.is_some()
            {
                object.insert(
                    "recipient_proof".to_string(),
                    serde_json::json!({
                        "schema": "elastos.library.recipient-proof/v1",
                        "source": "runtime-launch-grant",
                        "recipient": principal_id,
                        "principal_id": principal_id,
                        "proof_binding_id": context.proof_binding_id.as_deref().unwrap_or_default(),
                        "session_id": session_id,
                    }),
                );
            }
        }
    }

    if scheme == "inspect" && op == "request_act" {
        return gateway_inspect_action_request(&state, &context, &request).await;
    }

    let chain_lifecycle_audit = chain_lifecycle_effect_audit(&scheme, &op, &request);
    let library_audit = (scheme == "object").then(|| format!("object:{op}:{}", now_ts()));
    let model_audit = model_provider_effect_audit(&scheme, &op, &request);
    if let Some(audit) = &chain_lifecycle_audit {
        if let Err(err) = append_provider_effect_audit(
            &state.data_dir,
            ProviderEffectAuditInput {
                capsule_id: SYSTEM_CAPSULE_ID,
                event_type: "chain.node_lifecycle.requested",
                principal_id: &principal_id,
                session_id: &session_id,
                request_id: &audit.request_id,
                result: "requested",
                reason: &format!(
                    "System requested chain node lifecycle action {} for {}",
                    audit.action, audit.network
                ),
            },
        ) {
            return gateway_provider_error_response(
                &scheme,
                anyhow::anyhow!("chain node lifecycle audit failed: {}", err),
            );
        }
    }
    if let Some(request_id) = &library_audit {
        if let Err(err) = append_provider_effect_audit(
            &state.data_dir,
            ProviderEffectAuditInput {
                capsule_id: LIBRARY_CAPSULE_ID,
                event_type: "object.provider.requested",
                principal_id: &principal_id,
                session_id: &session_id,
                request_id,
                result: "requested",
                reason: &format!("Library requested object provider operation {op}"),
            },
        ) {
            return gateway_provider_error_response(
                &scheme,
                anyhow::anyhow!("object provider audit failed: {}", err),
            );
        }
    }
    if let Some(audit) = &model_audit {
        if let Err(err) = append_provider_effect_audit(
            &state.data_dir,
            ProviderEffectAuditInput {
                capsule_id: &launch_capsule_id,
                event_type: audit.requested_event,
                principal_id: &principal_id,
                session_id: &session_id,
                request_id: audit.request_id,
                result: "requested",
                reason: audit.requested_reason,
            },
        ) {
            return gateway_provider_error_response(
                &scheme,
                anyhow::anyhow!("model provider audit failed: {}", err),
            );
        }
        if launch_capsule_id == "assistant" && op == "runs_create" {
            if let Some(offer_id) = request.get("offer_id").and_then(serde_json::Value::as_str) {
                if let Some(hint) = crate::api::hosted_model_offer_hint(&state.data_dir, offer_id) {
                    // No evaluator acts while Approval Lens is hidden: log the
                    // hosted request and let it through to its own Inbox approval.
                    let _ = crate::jev_approval_lens::record_assistant_hosted_http_shadow(
                        &state.data_dir,
                        &crate::jev_approval_lens::AssistantHostedHttpContext {
                            request_id: audit.request_id,
                            principal_id: &principal_id,
                            session_id: &session_id,
                            capsule_id: &launch_capsule_id,
                            grant_id: &context.grant_id,
                            offer_id,
                            hint,
                        },
                    );
                }
            }
        }
    }

    let mut response = if scheme == "object"
        && (library_operation_needs_runtime_coordinator(&op)
            || library_request_targets_webspace(&request))
    {
        let wallet_authority =
            if (op == "publish" && request.get("protection").is_some()) || op == "buy" {
                match runtime_wallet_authority(&required) {
                    Ok(authority) => Some(authority),
                    Err(err) => return gateway_provider_error_response(&scheme, err),
                }
            } else {
                None
            };
        crate::library::handle_object_provider_runtime_request_with_gateway(
            crate::library::ObjectProviderRuntimeRequest {
                data_dir: &state.data_dir,
                registry: Arc::clone(&registry),
                request: &request,
                gateway_authority: wallet_authority
                    .as_ref()
                    .map(|authority| (&state, authority)),
            },
        )
        .await
    } else {
        match registry.send_raw(&scheme, &request).await {
            Ok(value)
                if scheme == "net"
                    && value.get("status").and_then(|v| v.as_str()) == Some("error") =>
            {
                let message = value
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("net provider unavailable");
                return gateway_provider_error_response(
                    &scheme,
                    anyhow::anyhow!("net provider unavailable: {}", message),
                );
            }
            Ok(value) => value,
            Err(err) if scheme == "net" => {
                return gateway_provider_error_response(
                    &scheme,
                    anyhow::anyhow!("net provider unavailable: {}", err),
                )
            }
            Err(err) => serde_json::json!({
            "status": "error",
            "code": "provider_error",
                "message": err.to_string(),
            }),
        }
    };
    let mut response_status = StatusCode::OK;
    if scheme == "model" {
        if let Some(refusal) = local_model_request_expiry_refusal(&request, &response) {
            response = refusal;
            response_status = StatusCode::CONFLICT;
        }
        if op == "offers_list" && !remote_model_grants.is_empty() {
            // A consumer Home may run no local model provider at all; granted
            // remote offers still form its list.
            if response.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
                response = super::gateway_model_remote::offers_list_without_local_provider();
            }
            super::gateway_model_remote::append_remote_offers(
                &registry,
                &remote_model_grants,
                &context,
                &launch_capsule_id,
                &mut response,
            )
            .await;
        }
        if let Err(err) = project_model_provider_response(&op, &mut response) {
            return gateway_provider_error_response(
                &scheme,
                anyhow::anyhow!("model provider returned an invalid typed response: {err}"),
            );
        }
    }

    if let Some(audit) = &chain_lifecycle_audit {
        let completed = response.get("status").and_then(|value| value.as_str()) == Some("ok");
        if let Err(err) = append_provider_effect_audit(
            &state.data_dir,
            ProviderEffectAuditInput {
                capsule_id: SYSTEM_CAPSULE_ID,
                event_type: if completed {
                    "chain.node_lifecycle.completed"
                } else {
                    "chain.node_lifecycle.failed"
                },
                principal_id: &principal_id,
                session_id: &session_id,
                request_id: &audit.request_id,
                result: if completed { "completed" } else { "failed" },
                reason: &format!(
                    "System {} chain node lifecycle action {} for {}",
                    if completed { "completed" } else { "failed" },
                    audit.action,
                    audit.network
                ),
            },
        ) {
            return gateway_provider_error_response(
                &scheme,
                anyhow::anyhow!("chain node lifecycle audit failed: {}", err),
            );
        }
    }
    if let Some(request_id) = &library_audit {
        let completed = response.get("status").and_then(|value| value.as_str()) == Some("ok");
        if completed && library_operation_emits_events(&op) {
            crate::library::library_event_notifier().notify_waiters();
        }
        if let Err(err) = append_provider_effect_audit(
            &state.data_dir,
            ProviderEffectAuditInput {
                capsule_id: LIBRARY_CAPSULE_ID,
                event_type: if completed {
                    "object.provider.completed"
                } else {
                    "object.provider.failed"
                },
                principal_id: &principal_id,
                session_id: &session_id,
                request_id,
                result: if completed { "completed" } else { "failed" },
                reason: &format!(
                    "Library {} object provider operation {op}",
                    if completed { "completed" } else { "failed" }
                ),
            },
        ) {
            return gateway_provider_error_response(
                &scheme,
                anyhow::anyhow!("object provider audit failed: {}", err),
            );
        }
    }
    if let Some(audit) = &model_audit {
        let completed = response.get("status").and_then(|value| value.as_str()) == Some("ok");
        if let Err(err) = append_provider_effect_audit(
            &state.data_dir,
            ProviderEffectAuditInput {
                capsule_id: &launch_capsule_id,
                event_type: if completed {
                    audit.completed_event
                } else {
                    audit.failed_event
                },
                principal_id: &principal_id,
                session_id: &session_id,
                request_id: audit.request_id,
                result: if completed { "completed" } else { "failed" },
                reason: if completed {
                    audit.completed_reason
                } else {
                    audit.failed_reason
                },
            },
        ) {
            return gateway_provider_error_response(
                &scheme,
                anyhow::anyhow!("model provider audit failed: {}", err),
            );
        }
        if launch_capsule_id == "assistant" && op == "runs_create" {
            let outcome = if completed { "accepted" } else { "failed" };
            let request_id = request
                .get("offer_id")
                .and_then(serde_json::Value::as_str)
                .map(|offer_id| {
                    crate::jev_approval_lens::outcome_request_id(
                        &state.data_dir,
                        offer_id,
                        audit.request_id,
                    )
                })
                .unwrap_or_else(|| audit.request_id.to_string());
            let _ = crate::jev_approval_lens::record_actual_outcome(
                &state.data_dir,
                &request_id,
                outcome,
            );
        }
    }

    (response_status, Json(response)).into_response()
}

async fn resolve_runtime_custody_wallet_default_account(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    chain_namespace: &str,
    unavailable_message: &'static str,
) -> anyhow::Result<RuntimeCustodyCreatorAccount> {
    let accounts = system_wallet_accounts_summary(state, authority).await;
    let latest_default = accounts
        .default_accounts
        .iter()
        .filter(|default| {
            default.intent == "transaction_intent" && default.chain_namespace == chain_namespace
        })
        .max_by_key(|default| default.set_at)
        .ok_or_else(|| anyhow::anyhow!(unavailable_message))?;
    if accounts.default_accounts.iter().any(|default| {
        default.intent == "transaction_intent"
            && default.chain_namespace == chain_namespace
            && default.set_at == latest_default.set_at
            && default.account_id != latest_default.account_id
    }) {
        anyhow::bail!(unavailable_message);
    }
    let account = accounts
        .accounts
        .iter()
        .find(|account| {
            account.account_id == latest_default.account_id
                && account.chain_namespace == chain_namespace
        })
        .ok_or_else(|| anyhow::anyhow!(unavailable_message))?;
    if !account.signing_available || !is_managed_wallet_proof_type(&account.proof_type) {
        anyhow::bail!(unavailable_message);
    }
    validate_wallet_evm_address(&account.address, "wallet")
        .map_err(|_| anyhow::anyhow!(unavailable_message))?;
    Ok(RuntimeCustodyCreatorAccount {
        account_id: account.account_id.clone(),
        address: account.address.to_ascii_lowercase(),
    })
}

const ERC1155_IS_APPROVED_FOR_ALL_SELECTOR: &str = "e985e9c5";
const ERC1155_SET_APPROVAL_FOR_ALL_SELECTOR: &str = "a22cb465";

fn abi_word_from_address(address: &str) -> anyhow::Result<String> {
    let raw = address
        .strip_prefix("0x")
        .filter(|raw| raw.len() == 40 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow::anyhow!("invalid EVM address for ABI encoding"))?;
    Ok(format!("{:0>64}", raw.to_ascii_lowercase()))
}

async fn resolve_runtime_custody_market_gateway(
    state: &GatewayState,
    network: &str,
) -> anyhow::Result<String> {
    let response = wallet_chain_provider_data(
        state,
        serde_json::json!({
            "op": "describe_protected_content_market_source",
            "network": network,
        }),
    )
    .await
    .map_err(creator_mint_unavailable!())?;
    let source: ResolvedProtectedContentMarketSource =
        serde_json::from_value(response).map_err(creator_mint_unavailable!())?;
    if source.schema != "elastos.chain.protected-content-market-source/v1"
        || source.network != network
    {
        return Err(creator_mint_unavailable_missing!()());
    }
    validate_wallet_evm_address(&source.authority_gateway_contract, "market gateway")
        .map_err(creator_mint_unavailable!())?;
    Ok(source.authority_gateway_contract.to_ascii_lowercase())
}

pub(super) fn provider_proxy_runtime_metadata_field(request: &serde_json::Value) -> Option<&str> {
    request
        .as_object()?
        .keys()
        .find(|key| {
            key.starts_with("_runtime")
                || matches!(key.as_str(), "connect_ticket" | "carrier_route" | "carrier")
        })
        .map(String::as_str)
}

const HOSTED_RUN_ADMIN_ONLY: &str =
    "Hosted AI on this Home is for admins. Local models are still available.";

/// Hosted AI spends this Home's paid connection, so in 0.8.0 only an admin's
/// run may use a hosted offer. Other offers are not affected.
fn hosted_run_allowed(
    data_dir: &std::path::Path,
    context: &HomeLaunchTokenContext,
    request: &serde_json::Value,
) -> bool {
    let offer_id = request["offer_id"].as_str().unwrap_or_default();
    if !crate::api::model_provider_config::is_hosted_offer_id(offer_id) {
        return true;
    }
    context
        .proof_binding_id
        .as_deref()
        .and_then(|proof| crate::auth::load_principal_for_proof_binding(data_dir, proof).ok())
        .is_some_and(|principal| {
            crate::auth::ensure_proof_binding_not_revoked(&principal).is_ok()
                && principal.principal_id == context.principal_id
                && crate::auth::is_admin(&principal)
        })
}

pub(super) fn normalize_model_provider_request(
    op: &str,
    request: &serde_json::Value,
    context: &HomeLaunchTokenContext,
    capsule_id: &str,
) -> Result<serde_json::Value, (StatusCode, String)> {
    match op {
        "offers_list" => {
            if request.as_object().is_some_and(|value| value.is_empty()) {
                Ok(serde_json::json!({ "op": "offers_list" }))
            } else {
                Err((
                    StatusCode::BAD_REQUEST,
                    "model offers_list request must be an empty JSON object".to_string(),
                ))
            }
        }
        "runs_create" => {
            let parsed = serde_json::from_value::<ModelRunsCreateGatewayRequest>(request.clone())
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            let runtime_binding = RuntimeCreateBinding {
                schema: RUNTIME_CREATE_BINDING_SCHEMA.to_string(),
                principal_id: context.principal_id.clone(),
                session_id: context.session_id.clone(),
                capsule_id: capsule_id.to_string(),
                grant_id: context.grant_id.clone(),
                request_id: parsed.request_id,
                offer_id: parsed.offer_id.clone(),
                operation: parsed.operation.clone(),
                input_hash: model_input_hash(&parsed.input).map_err(|err| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("invalid model input: {err}"),
                    )
                })?,
            };
            runtime_binding
                .validate(&parsed.offer_id, &parsed.operation, &parsed.input)
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            Ok(serde_json::json!({
                "op": "runs_create",
                "offer_id": parsed.offer_id,
                "operation": parsed.operation,
                "input": parsed.input,
                "runtime_binding": runtime_binding,
            }))
        }
        "runs_get" | "runs_cancel" => {
            let parsed = serde_json::from_value::<ModelRunAccessGatewayRequest>(request.clone())
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            let runtime_binding = RuntimeAccessBinding {
                schema: RUNTIME_ACCESS_BINDING_SCHEMA.to_string(),
                principal_id: context.principal_id.clone(),
                session_id: context.session_id.clone(),
                capsule_id: capsule_id.to_string(),
                grant_id: context.grant_id.clone(),
                request_id: parsed.request_id,
                run_id: parsed.run_id.clone(),
            };
            runtime_binding
                .validate(&parsed.run_id)
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            Ok(serde_json::json!({
                "op": op,
                "run_id": parsed.run_id,
                "runtime_binding": runtime_binding,
            }))
        }
        "runs_events" => {
            let parsed = serde_json::from_value::<ModelRunEventsGatewayRequest>(request.clone())
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            let runtime_binding = RuntimeAccessBinding {
                schema: RUNTIME_ACCESS_BINDING_SCHEMA.to_string(),
                principal_id: context.principal_id.clone(),
                session_id: context.session_id.clone(),
                capsule_id: capsule_id.to_string(),
                grant_id: context.grant_id.clone(),
                request_id: parsed.request_id,
                run_id: parsed.run_id.clone(),
            };
            runtime_binding
                .validate(&parsed.run_id)
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            Ok(serde_json::json!({
                "op": "runs_events",
                "run_id": parsed.run_id,
                "after_sequence": parsed.after_sequence,
                "runtime_binding": runtime_binding,
            }))
        }
        _ => Err((
            StatusCode::NOT_FOUND,
            "Gateway provider operation not found".to_string(),
        )),
    }
}

fn local_model_request_expiry_refusal(
    request: &serde_json::Value,
    response: &serde_json::Value,
) -> Option<serde_json::Value> {
    if request["op"] != "runs_create"
        || !super::gateway_model_service::provider_refused_expired_request(response)
    {
        return None;
    }
    let binding: RuntimeCreateBinding =
        serde_json::from_value(request.get("runtime_binding")?.clone()).ok()?;
    binding
        .validate(
            request["offer_id"].as_str()?,
            request["operation"].as_str()?,
            request.get("input")?,
        )
        .ok()?;
    Some(serde_json::json!({
        "status": "error", "code": "model_invocation_refused",
        "reason": elastos_model_contract::MODEL_REQUEST_EXPIRED_CODE,
        "message": elastos_model_contract::MODEL_REQUEST_EXPIRED_MESSAGE,
        "refusal": {
            "schema": super::gateway_model_service::INVOCATION_REFUSAL_SCHEMA,
            "scope": "invocation", "dispatch": "provider_refused",
            "request_id": binding.request_id, "offer_id": binding.offer_id,
            "operation": binding.operation, "input_hash": binding.input_hash,
        },
    }))
}

fn model_provider_effect_audit<'a>(
    scheme: &str,
    op: &str,
    request: &'a serde_json::Value,
) -> Option<ModelProviderEffectAudit<'a>> {
    if scheme != "model" {
        return None;
    }
    let request_id = request.pointer("/runtime_binding/request_id")?.as_str()?;
    match op {
        "runs_create" => Some(ModelProviderEffectAudit {
            request_id,
            requested_event: "model.run_create.requested",
            completed_event: "model.run_create.completed",
            failed_event: "model.run_create.failed",
            requested_reason: "Assistant requested model run creation",
            completed_reason: "Assistant completed model run creation",
            failed_reason: "Assistant failed model run creation",
        }),
        "runs_cancel" => Some(ModelProviderEffectAudit {
            request_id,
            requested_event: "model.run_cancel.requested",
            completed_event: "model.run_cancel.completed",
            failed_event: "model.run_cancel.failed",
            requested_reason: "Assistant requested model run cancellation",
            completed_reason: "Assistant completed model run cancellation",
            failed_reason: "Assistant failed model run cancellation",
        }),
        _ => None,
    }
}

pub(super) fn project_model_provider_response(
    op: &str,
    response: &mut serde_json::Value,
) -> anyhow::Result<()> {
    if response.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
        return Ok(());
    }
    match op {
        "runs_get" => {
            if let Some(output) = response.pointer_mut("/data/terminal/output") {
                project_model_run_output(output)?;
            }
        }
        "runs_events" => {
            let events = response
                .pointer_mut("/data/events")
                .and_then(serde_json::Value::as_array_mut)
                .ok_or_else(|| anyhow::anyhow!("model run events response is missing events"))?;
            for event in events {
                if event.get("kind").and_then(serde_json::Value::as_str) == Some("output") {
                    project_model_run_output(event.get_mut("data").ok_or_else(|| {
                        anyhow::anyhow!("model output event is missing typed data")
                    })?)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn project_model_run_output(output: &mut serde_json::Value) -> anyhow::Result<()> {
    let object = output
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("model run output must be an object"))?;
    let schema = object
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("model run output is missing schema"))?
        .to_string();
    match schema.as_str() {
        MODEL_TEXT_OUTPUT_SCHEMA => {
            if object.len() != 2
                || object
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .is_none()
            {
                anyhow::bail!("model text output must contain only schema and text");
            }
        }
        MODEL_OBJECT_OUTPUT_SCHEMA => {
            project_model_output_resource(object, "elastos://object/")?;
        }
        MODEL_CONTENT_OUTPUT_SCHEMA => {
            project_model_output_resource(object, "elastos://content/")?;
        }
        _ => anyhow::bail!("model run output uses an unsupported schema"),
    }
    Ok(())
}

fn project_model_output_resource(
    output: &mut serde_json::Map<String, serde_json::Value>,
    prefix: &str,
) -> anyhow::Result<()> {
    if output.len() != 2 {
        anyhow::bail!("model resource output must contain only schema and uri");
    }
    let uri = output
        .get("uri")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("model resource output is missing uri"))?;
    if uri.trim() != uri
        || uri.len() <= prefix.len()
        || uri.len() > MODEL_OUTPUT_URI_MAX_BYTES
        || !uri.starts_with(prefix)
        || uri.bytes().any(|byte| byte.is_ascii_control())
    {
        anyhow::bail!("model resource output has an invalid Runtime resource uri");
    }
    let resource_id = uri[prefix.len()..].to_string();
    output.remove("uri");
    output.insert(
        "resource_id".to_string(),
        serde_json::Value::String(resource_id),
    );
    Ok(())
}

fn library_operation_emits_events(op: &str) -> bool {
    matches!(
        op,
        "write"
            | "mkdir"
            | "rename"
            | "move"
            | "copy"
            | "trash"
            | "restore"
            | "delete_permanently"
            | "empty_trash"
            | "extract_archive"
            | "archive_extract_entries"
            | "compress_archive"
            | "publish"
            | "unpublish"
            | "repair"
            | "share"
    )
}

fn library_operation_needs_runtime_coordinator(op: &str) -> bool {
    matches!(
        op,
        "publish"
            | "unpublish"
            | "repair"
            | "sync"
            | "list_runtime_custody"
            | "import_runtime_custody"
            | "buy"
            | "open_viewer"
            | "read_viewer"
            | "close_viewer"
    )
}

fn library_request_targets_webspace(request: &serde_json::Value) -> bool {
    ["uri", "parent_uri", "target_uri", "target_parent_uri"]
        .iter()
        .filter_map(|field| request.get(field).and_then(|value| value.as_str()))
        .map(str::trim)
        .map(|value| value.trim_end_matches('/'))
        .any(|value| {
            value == "localhost://WebSpaces"
                || value
                    .strip_prefix("localhost://WebSpaces/")
                    .is_some_and(|rest| !rest.is_empty())
        })
}

#[cfg(test)]
mod tests {
    #[test]
    fn fail_closed_macros_keep_the_stable_message_and_carry_the_cause() {
        let error = (creator_mint_unavailable!())("boom");
        assert_eq!(
            error.to_string(),
            RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE
        );
        let chain: Vec<String> = error.chain().map(|cause| cause.to_string()).collect();
        assert_eq!(chain.len(), 3);
        assert!(chain[1].contains("gateway_provider_proxy.rs:"));
        assert_eq!(chain[2], "\"boom\"");
        let missing = (purchase_denied_missing!())();
        assert_eq!(
            missing.to_string(),
            crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_DENIED_MESSAGE
        );
        assert!(missing.chain().nth(1).unwrap().to_string().contains(".rs:"));
    }

    #[test]
    fn erc1155_operator_approval_abi_helpers_encode_and_decode_exactly() {
        let owner = "0xF36C114c19F96b4174B6D71E392c00dB95093a1E";
        let gateway = "0x09dBe796f40ECEffEAccf243c3d758C4c1d8D87D";
        assert_eq!(
            super::erc1155_is_approved_for_all_call_data(owner, gateway).unwrap(),
            "0xe985e9c5000000000000000000000000f36c114c19f96b4174b6d71e392c00db95093a1e00000000000000000000000009dbe796f40eceffeaccf243c3d758c4c1d8d87d"
        );
        assert_eq!(
            super::erc1155_set_approval_for_all_call_data(gateway, true).unwrap(),
            "0xa22cb46500000000000000000000000009dbe796f40eceffeaccf243c3d758c4c1d8d87d0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert!(super::erc1155_is_approved_for_all_call_data("0x1234", gateway).is_err());
        assert_eq!(
            super::erc1155_bool_result(
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            ),
            Some(true)
        );
        assert_eq!(
            super::erc1155_bool_result(
                "0x0000000000000000000000000000000000000000000000000000000000000000"
            ),
            Some(false)
        );
        assert_eq!(super::erc1155_bool_result("0x01"), None);
        assert_eq!(
            super::erc1155_bool_result(
                "0x0000000000000000000000000000000000000000000000000000000000000042"
            ),
            None
        );
    }

    #[test]
    fn creator_mint_chain_error_maps_pending_codes_to_pending_and_others_to_unavailable() {
        let pending = super::creator_mint_chain_error(
            (
                StatusCode::BAD_REQUEST,
                "protected_content_mint_receipt_pending: protected-content mint receipt is not finalized on enough configured sources".to_string(),
            ),
            1,
        );
        assert_eq!(
            pending.to_string(),
            super::RUNTIME_CUSTODY_CREATOR_PENDING_MESSAGE
        );
        for (status, message) in [
            (
                StatusCode::BAD_REQUEST,
                "invalid_protected_content_mint_receipt: bad".to_string(),
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "protected_content_mint_receipt_pending: x".to_string(),
            ),
            (
                StatusCode::BAD_REQUEST,
                "upstream_unreachable: EVM RPC request failed".to_string(),
            ),
        ] {
            let error = super::creator_mint_chain_error((status, message), 1);
            assert_eq!(
                error.to_string(),
                super::RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE
            );
        }
    }

    use super::*;

    fn test_creator_state() -> elastos_protected_content_runtime::RuntimeMintCreatorState {
        let desired_terms = elastos_protected_content_runtime::RuntimeMintCreatorDesiredTerms::new(
            "wallet-account-1".to_string(),
            "0x2".to_string(),
            "0x5".to_string(),
        )
        .unwrap();
        elastos_protected_content_runtime::RuntimeMintCreatorState::new(
            desired_terms,
            "bafycreatorcid".to_string(),
            "ipfs://bafymetadata/metadata.json".to_string(),
        )
        .unwrap()
    }

    fn test_chain_plan() -> RuntimeCustodyCreatorChainPlan {
        RuntimeCustodyCreatorChainPlan {
            network: "base-mainnet".to_string(),
            chain_namespace: "eip155:8453".to_string(),
            ledger: "0x00000000000000000000000000000000000000aa".to_string(),
            pay_token: "0x00000000000000000000000000000000000000bb".to_string(),
            to: "0x00000000000000000000000000000000000000cc".to_string(),
            data: "0x1234".to_string(),
            value: "0x0".to_string(),
        }
    }

    fn test_receipt(chain_id: u64) -> ResolvedProtectedContentMintReceipt {
        ResolvedProtectedContentMintReceipt {
            schema: "elastos.chain.protected-content-mint-receipt/v1".to_string(),
            network: "base-mainnet".to_string(),
            chain_id,
            token_id: "0x77".to_string(),
            operative: "0x00000000000000000000000000000000000000dd".to_string(),
        }
    }

    fn test_listing(chain_id: u64) -> ResolvedProtectedContentVerifiedListing {
        ResolvedProtectedContentVerifiedListing {
            schema: "elastos.chain.protected-content-verified-listing/v1".to_string(),
            network: "base-mainnet".to_string(),
            chain_id,
            seller: "0x00000000000000000000000000000000000000ee".to_string(),
            ledger: "0x00000000000000000000000000000000000000aa".to_string(),
            token_id: "0x77".to_string(),
            operative: "0x00000000000000000000000000000000000000dd".to_string(),
            quantity: "0x2".to_string(),
            price: "0x5".to_string(),
            pay_token: "0x00000000000000000000000000000000000000bb".to_string(),
            payment_processor: Some("0x00000000000000000000000000000000000000ff".to_string()),
        }
    }

    #[test]
    fn runtime_custody_creator_terminal_bindings_accept_exact_chain_identity() {
        let creator_state = test_creator_state();
        let chain_plan = test_chain_plan();
        let receipt = test_receipt(8453);
        let listing = test_listing(8453);

        assert!(validate_runtime_custody_creator_terminal_bindings(
            &creator_state,
            "0x00000000000000000000000000000000000000ee",
            &chain_plan,
            &receipt,
            &listing,
        )
        .is_ok());
    }

    #[test]
    fn runtime_custody_creator_terminal_bindings_accept_normalized_price_terms() {
        let creator_state = elastos_protected_content_runtime::RuntimeMintCreatorState::new(
            elastos_protected_content_runtime::RuntimeMintCreatorDesiredTerms::new(
                "wallet-account-1",
                "0x02",
                "0x05",
            )
            .unwrap(),
            "bafycreatorcid",
            "ipfs://bafycreatorcid/metadata.json",
        )
        .unwrap();
        let chain_plan = test_chain_plan();
        let receipt = test_receipt(8453);
        let listing = test_listing(8453);

        assert!(validate_runtime_custody_creator_terminal_bindings(
            &creator_state,
            "0x00000000000000000000000000000000000000ee",
            &chain_plan,
            &receipt,
            &listing,
        )
        .is_ok());
        assert_eq!(creator_state.desired_terms().copies(), "0x2");
        assert_eq!(creator_state.desired_terms().price(), "0x5");
    }

    #[test]
    fn runtime_custody_creator_request_uses_canonical_exact_effect_identity() {
        let creator_state = test_creator_state();
        let chain_plan = test_chain_plan();
        let creator_account = RuntimeCustodyCreatorAccount {
            account_id: "wallet:eip155:8453:0x00000000000000000000000000000000000000ee".to_string(),
            address: "0x00000000000000000000000000000000000000ee".to_string(),
        };
        let request = runtime_custody_creator_transaction_request(
            "did:key:z6Mkcreatorprincipal1111111111111111111111111111111",
            &creator_account,
            &creator_state,
            &chain_plan,
            elastos_protected_content_contracts::Digest32::new([0x77; 32]),
            creator_state.token_uri(),
        )
        .unwrap();
        let request_binding = transaction_request_binding(&request);
        let expected = exact_runtime_transaction_effect_id(
            NATIVE_TRANSACTION_SOURCE,
            "did:key:z6Mkcreatorprincipal1111111111111111111111111111111",
            &request.request_sha256,
            &request_binding,
        )
        .unwrap();
        assert_eq!(request.effect_id, expected);
        assert!(request.metadata.get("method").is_none());
        assert_eq!(
            request
                .metadata
                .get("product_operation")
                .and_then(|value| value.as_str()),
            Some("protected_content_creator_mint")
        );
    }

    #[test]
    fn runtime_custody_creator_terminal_bindings_reject_mismatched_evidence_fields() {
        let cases: &[fn(
            &mut ResolvedProtectedContentMintReceipt,
            &mut ResolvedProtectedContentVerifiedListing,
            &mut RuntimeCustodyCreatorChainPlan,
        )] = &[
            |receipt, _, _| receipt.chain_id = 8454,
            |_, listing, _| listing.chain_id = 8454,
            |receipt, _, _| receipt.network = "wrong-mainnet".to_string(),
            |_, listing, _| listing.network = "wrong-mainnet".to_string(),
            |_, listing, _| {
                listing.seller = "0x00000000000000000000000000000000000000aa".to_string()
            },
            |_, listing, _| {
                listing.ledger = "0x00000000000000000000000000000000000000ab".to_string()
            },
            |receipt, _, _| receipt.token_id = "0x78".to_string(),
            |_, listing, _| listing.token_id = "0x78".to_string(),
            |receipt, _, _| {
                receipt.operative = "0x00000000000000000000000000000000000000ab".to_string()
            },
            |_, listing, _| {
                listing.operative = "0x00000000000000000000000000000000000000ab".to_string()
            },
            |_, listing, _| listing.quantity = "0x0".to_string(),
            |_, listing, _| listing.quantity = "0x3".to_string(),
            |_, listing, _| listing.price = "0x6".to_string(),
            |_, listing, _| {
                listing.pay_token = "0x00000000000000000000000000000000000000aa".to_string()
            },
            |_, _, chain_plan| {
                chain_plan.ledger = "0x00000000000000000000000000000000000000ab".to_string()
            },
            |_, _, chain_plan| {
                chain_plan.pay_token = "0x00000000000000000000000000000000000000aa".to_string()
            },
        ];

        for mutate in cases {
            let creator_state = test_creator_state();
            let mut chain_plan = test_chain_plan();
            let mut receipt = test_receipt(8453);
            let mut listing = test_listing(8453);
            mutate(&mut receipt, &mut listing, &mut chain_plan);
            let err = validate_runtime_custody_creator_terminal_bindings(
                &creator_state,
                "0x00000000000000000000000000000000000000ee",
                &chain_plan,
                &receipt,
                &listing,
            )
            .unwrap_err();
            assert_eq!(err.to_string(), RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE);
        }
    }
}

use super::*;

pub(super) const RUNTIME_CUSTODY_CREATOR_PENDING_MESSAGE: &str =
    "Runtime custody creator mint is pending exact Wallet or Chain settlement";

pub(super) const RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE: &str =
    "Runtime custody creator mint is unavailable";

/// The reason the creator mint's approval states. Hashed into its effect id,
/// so its value never changes; the Inbox card keys its public metadata line
/// on it.
pub(in crate::api::gateway) const RUNTIME_CUSTODY_CREATOR_APPROVAL_REASON: &str =
    "Create protected-content creator listing";

/// Raise the creator tail's non-terminal waiting state, typed.
///
/// The stable sentence stays outermost so nothing matching on it breaks; the
/// typed answer beneath it says what is actually being waited for and whether
/// anyone has to act. `WalletApproval` on an external signer is the only case
/// that asks anything of the creator.
fn runtime_custody_creator_effect_pending(
    pending: crate::protected_content_runtime::RuntimeCustodyEffectPending,
    line: u32,
) -> anyhow::Error {
    tracing::trace!(
        line,
        reason = pending.reason_label(),
        awaits_person = pending.awaits_person(),
        "runtime custody creator tail: pending exact Wallet or Chain settlement"
    );
    anyhow::Error::new(pending).context(RUNTIME_CUSTODY_CREATOR_PENDING_MESSAGE)
}

/// Chain-provider answers on the creator tail. A `*_pending` code (the
/// mint receipt or verified listing not yet finalized on enough evidence
/// sources) is the Chain half of "pending exact Wallet or Chain settlement":
/// the caller re-polls, exactly as it does while the Wallet approval is
/// outstanding. Anything else fails closed with the cause in the log.
/// Whether a chain-provider refusal means "not yet", rather than "no".
///
/// One definition, used both to shape the error a caller sees and to record
/// why a step stopped. Two copies of this rule would eventually disagree, and
/// the disagreement would show up as a step logged as broken while the caller
/// was told to keep waiting.
fn runtime_custody_chain_answer_is_pending(error: &(StatusCode, String)) -> bool {
    let (status, message) = error;
    *status == StatusCode::BAD_REQUEST
        && message
            .split(':')
            .next()
            .unwrap_or_default()
            .trim()
            .ends_with("_pending")
}

/// What the transaction-effect store answers when every Chain source replied
/// and none has the transaction yet. A connector broadcasts through its own
/// RPC, so the hash it returns can reach the Chain's sources seconds later:
/// this is "not yet", and asking again finds it. A failed lookup is a
/// different answer ("Chain reconciliation was unavailable") and stays an
/// error.
const CHAIN_HAS_NOT_SEEN_TRANSACTION: &str =
    "Chain could not independently determine the prior broadcast outcome";

/// Whether a transaction-effect completion error is
/// [`CHAIN_HAS_NOT_SEEN_TRANSACTION`], which the creator and buyer tails
/// treat as waiting on Chain settlement rather than a failure.
pub(in crate::api::gateway) fn chain_has_not_seen_transaction(
    error: &(StatusCode, String),
) -> bool {
    error.0 == StatusCode::SERVICE_UNAVAILABLE
        && error.1.starts_with(CHAIN_HAS_NOT_SEEN_TRANSACTION)
}

/// The chain provider's answer for a mint whose transaction reverted as a
/// second mint of a content id already bound (`IPAlreadyBound`,
/// `InvalidTokenId`).
const MINT_RECEIPT_REVERTED_ALREADY_BOUND: &str =
    "protected_content_mint_receipt_reverted_already_bound";

/// Whether a chain refusal is the reverted-duplicate answer.
fn runtime_custody_chain_answer_is_reverted_duplicate(error: &(StatusCode, String)) -> bool {
    let (status, message) = error;
    *status == StatusCode::BAD_REQUEST
        && message.split(':').next().unwrap_or_default().trim()
            == MINT_RECEIPT_REVERTED_ALREADY_BOUND
}

/// Whether the chain's own binding confirms a reverted mint's content id is
/// bound. The revert only asks the question: without this answer the attempt
/// stays the failure it was.
async fn runtime_custody_reverted_mint_kid_is_bound(
    state: &GatewayState,
    chain_plan: &RuntimeCustodyCreatorChainPlan,
    content_access_id: elastos_protected_content_contracts::ContentAccessIdV1,
) -> bool {
    let kid = format!("0x{}", hex::encode(content_access_id.as_bytes()));
    match market_kid_binding(
        state,
        &chain_plan.chain_namespace,
        &chain_plan.network,
        &kid,
    )
    .await
    {
        Ok(Some((ledger, token_id))) => {
            tracing::debug!(
                %ledger,
                %token_id,
                "runtime custody creator tail: a reverted mint's content id is bound on chain"
            );
            true
        }
        Ok(None) => {
            tracing::warn!(
                "runtime custody creator tail: the mint reverted as a duplicate, but the chain binds its content id to no item"
            );
            false
        }
        Err(refusal) => {
            tracing::warn!(
                ?refusal,
                "runtime custody creator tail: the chain binding of a reverted mint could not be read"
            );
            false
        }
    }
}

/// Whether a chain-provider answer, read after the mint transaction was
/// mined, is a transient one: the provider or its upstream did not answer,
/// rather than answered "no". The receipt is on chain, so the read will work
/// once the upstream does (STAB-34 / D5).
fn runtime_custody_chain_answer_is_transient(error: &(StatusCode, String)) -> bool {
    let (status, message) = error;
    if *status == StatusCode::SERVICE_UNAVAILABLE {
        // The chain provider itself did not answer.
        return true;
    }
    let code = message.split(':').next().unwrap_or_default().trim();
    matches!(
        code,
        "unavailable" | "upstream_unreachable" | "upstream_rpc_error" | "upstream_missing_result"
    ) || code.ends_with("_unavailable")
}

/// A chain-provider refusal on the creator tail after the transaction was
/// mined (the receipt and payment-processor reads). "Not yet finalized" and a
/// transient answer are both the Chain half of "pending exact Wallet or Chain
/// settlement": approved already, so nobody need act, and the caller
/// re-polls. Anything else fails closed with the cause in the log.
pub(super) fn creator_mint_chain_error(error: (StatusCode, String), line: u32) -> anyhow::Error {
    let pending = runtime_custody_chain_answer_is_pending(&error)
        || runtime_custody_chain_answer_is_transient(&error);
    let (status, message) = error;
    if pending {
        tracing::debug!(
            line,
            status = status.as_u16(),
            error = %message,
            "runtime custody creator tail: the chain has not answered yet after mining"
        );
        return runtime_custody_creator_effect_pending(
            crate::protected_content_runtime::RuntimeCustodyEffectPending::awaiting_chain_settlement(
            ),
            line,
        );
    }
    tracing::warn!(
        line,
        status = status.as_u16(),
        error = %message,
        "Runtime custody creator mint failed closed"
    );
    anyhow::anyhow!("({}, {message})", status.as_u16())
        .context(format!("{}:{line}", file!()))
        .context(RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE)
}

/// The zero address, which is how a listing says it is priced in the chain's
/// own coin rather than in an ERC-20.
pub(in crate::api::gateway) const RUNTIME_CUSTODY_NATIVE_PAY_TOKEN: &str =
    "0x0000000000000000000000000000000000000000";

/// The schema a chain-provider verified listing must carry, whether it was read
/// back from chain state or taken from the `ItemListed` the mint itself emitted.
pub(super) const RUNTIME_CUSTODY_VERIFIED_LISTING_SCHEMA: &str =
    "elastos.chain.protected-content-verified-listing/v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedProtectedContentVerifiedListing {
    pub(crate) schema: String,
    pub(crate) network: String,
    pub(crate) chain_id: u64,
    pub(crate) seller: String,
    pub(crate) ledger: String,
    pub(crate) token_id: String,
    pub(crate) operative: String,
    pub(crate) quantity: String,
    pub(crate) price: String,
    pub(crate) pay_token: String,
    #[serde(default)]
    pub(crate) payment_processor: Option<String>,
}

/// Writer twin of `protected_content_runtime`'s `RuntimePortableMetadata`
/// reader: same field order, same "exactly one identity field, absent one
/// skipped" rule, so a media metadata document keeps its exact pre-object
/// bytes and an object one carries `content_identity_base64` instead.
#[derive(Serialize)]
struct RuntimeCustodyCreatorMetadata<'a> {
    schema: &'static str,
    name: &'a str,
    mime_type: &'a str,
    codecs: &'a str,
    encrypted_content_cid: &'a str,
    content_access_id: String,
    protected_content_identity: &'a str,
    mint_id: String,
    publisher_profile_did: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    media_identity_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_identity_base64: Option<String>,
    key_envelope_identity_base64: String,
    rights_policy_identity_base64: String,
    content_key_commitment_base64: String,
    rights_policy_seal_required: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeCustodyCreatorPublishBinding {
    pub account_id: String,
    pub address: String,
    pub source_digest: Digest32,
}

#[derive(Clone)]
pub(super) struct RuntimeCustodyCreatorChainPlan {
    pub(super) network: String,
    pub(super) chain_namespace: String,
    pub(super) ledger: String,
    pub(super) pay_token: String,
    pub(super) to: String,
    pub(super) data: String,
    pub(super) value: String,
}

/// The deployment a mint is bound to.
///
/// The channel and the pay token used to be in here, back when a Home had
/// exactly one of each and a change to either meant the ground had moved. They
/// are the creator's choice now and legitimately differ from one mint to the
/// next, so pinning them here would refuse ordinary work. They are pinned
/// where they belong instead -- in the mint's own recorded terms, which a
/// retry re-encodes from and which cannot change once a mint is under way.
fn runtime_custody_creator_mint_source_digest(
    network: &str,
    chain_namespace: &str,
    abi: &str,
    function: &str,
) -> Digest32 {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"elastos.runtime-custody.creator-mint-source/v2");
    for field in [network, chain_namespace, abi, function] {
        hasher.update((field.len() as u32).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    Digest32::new(hasher.finalize().into())
}

fn runtime_custody_creator_mint_source_digest_for_source(
    source: &ResolvedProtectedContentCreatorMintSource,
) -> Digest32 {
    runtime_custody_creator_mint_source_digest(
        &source.network,
        &source.chain_namespace,
        &source.abi,
        &source.function,
    )
}

pub(super) async fn gateway_provider_proxy_inner(
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
            "list"
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
            | "unpublish"
            | "repair"
            | "share"
            | "shared_access"
            | "events" => &[LIBRARY_CAPSULE_ID],
            "roots" | "stat" | "publish" | "publish_progress" | "discard_protection" => {
                &[LIBRARY_CAPSULE_ID, CREATOR_CAPSULE_ID]
            }
            // Creator offers back the unfinished mints of the folder it mints
            // from when it opens; nothing else lists them.
            "unfinished_protections" => &[CREATOR_CAPSULE_ID],
            "open_viewer" | "read_viewer" | "close_viewer" => {
                &[ELACITY_PLAYER_CAPSULE_ID, ELACITY_READER_CAPSULE_ID]
            }
            "import_runtime_custody" => &[LIBRARY_CAPSULE_ID, MARKETPLACE_CAPSULE_ID],
            "list_runtime_custody" | "buy" | "download_owned_copy" => {
                &[LIBRARY_CAPSULE_ID, MARKETPLACE_CAPSULE_ID]
            }
            // A market purchase is the Marketplace's own surface: the page
            // that showed the buyer the offer is the only one that may ask to
            // buy it on those terms.
            "buy_offer" => &[MARKETPLACE_CAPSULE_ID],
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
    const NOT_AUTHORIZED_FOR_VIEWER: (StatusCode, &str) = (
        StatusCode::FORBIDDEN,
        "home launch token is not authorized for this viewer",
    );
    if is_protected_viewer_op
        && (required.launch_context.selected_resource != required.launch_context.executable_actor
            || !matches!(
                required.launch_context.executable_actor.as_str(),
                ELACITY_PLAYER_CAPSULE_ID | ELACITY_READER_CAPSULE_ID
            ))
    {
        return NOT_AUTHORIZED_FOR_VIEWER.into_response();
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
    // A creator opening an asset they minted before minted copies were recorded
    // as owned would be refused at their own door. Restore the record first,
    // from what was already written down -- silently, because there is nothing
    // here for them to decide.
    if is_protected_viewer_op && op == "open_viewer" {
        if let Some(mint_id) = request
            .get("mint_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| crate::protected_content_runtime::parse_mint_id_hex(value).ok())
        {
            repair_runtime_custody_minted_owned_copy(&state, &principal_id, mint_id).await;
        }
    }
    if is_protected_viewer_op {
        if let Some(object) = request.as_object_mut() {
            object.remove("launch_id");
            object.remove("proof_binding_id");
            object.remove("session_id");
            object.remove("grant_id");
            object.remove("wallet_request_hex");
            object.remove("wallet_response_hex");
            object.remove("executable_actor");
            object.insert(
                "executable_actor".to_string(),
                serde_json::Value::String(required.launch_context.executable_actor.clone()),
            );
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
    // Session binding v3, kind <-> viewer: `open_viewer` additionally
    // requires the admitted viewer to be the ONE that matches this mint's
    // own content kind (media -> player, object -> reader). This is NOT
    // decided here: `RuntimeMintJournal::load` unconditionally calls
    // `ensure_root_dir`, so a speculative pre-dispatch load (keyed off the
    // client-supplied, not-yet-authorized `mint_id`) would create this
    // Runtime's mint-journal directory as a side effect of every
    // `open_viewer` call — including ones from a principal who has never
    // minted anything (confirmed: it broke a gateway test's cross-runtime
    // isolation assertion). The check instead runs inside
    // `open_runtime_custody_viewer`, after the normal purchase/listing/draft
    // load that a legitimate open already performs, so it adds no new
    // filesystem footprint. Its rejection surfaces as
    // `RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE` there rather than the literal
    // "not authorized for this viewer" 403 this comment's neighbour uses —
    // see the Task 13 report for why that tradeoff was made deliberately.
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

    if scheme == "object" && op == "import_runtime_custody" {
        let cid = request
            .get("listing_uri")
            .and_then(serde_json::Value::as_str)
            .and_then(super::gateway_marketplace_listing::token_uri_folder_cid)
            .unwrap_or_default();
        tracing::Span::current().record("start_kind", "token_uri");
        tracing::Span::current().record("cid", cid.as_str());
    }
    let mut response = if scheme == "object"
        && (library_operation_needs_runtime_coordinator(&op)
            || library_request_targets_webspace(&request))
    {
        let wallet_authority = if (op == "publish" && request.get("protection").is_some())
            || op == "unfinished_protections"
            || op == "discard_protection"
            || op == "buy"
            || op == "buy_offer"
            || op == "download_owned_copy"
        {
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
                // This function verified the home launch token above and
                // overwrote `executable_actor` with the verified value, which is
                // what makes the protected viewer operations admissible at all.
                route: crate::library::LibraryRequestRoute::VerifiedGatewayLaunchToken,
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

    let import_outcome = if scheme == "object" && op == "import_runtime_custody" {
        // Provider envelopes may report failure with HTTP 200. Inspect the
        // existing JSON value without consuming or rewriting the response.
        let outcome = match response.get("status").and_then(serde_json::Value::as_str) {
            Some("ok") => "ok",
            Some("error") => "failed",
            _ => "unknown",
        };
        Some(crate::action_trace::Outcome(outcome))
    } else {
        None
    };
    let mut http_response = (response_status, Json(response)).into_response();
    if let Some(outcome) = import_outcome {
        http_response.extensions_mut().insert(outcome);
    }
    http_response
}

async fn resolve_runtime_custody_creator_account(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    wallet_account_id: &str,
) -> anyhow::Result<RuntimeCustodyCreatorAccount> {
    let accounts = system_wallet_accounts_summary(state, authority).await;
    let account = accounts
        .accounts
        .iter()
        .find(|account| account.account_id == wallet_account_id)
        .ok_or_else(creator_mint_unavailable_missing!())?;
    // `signing_available` is the whole precondition: it is already false for an
    // external account with no connector linked and true for a linked one,
    // which signs through the handoff. The tail past this point needs an
    // address and a completed approval — it never asks the Wallet to sign — so
    // requiring a managed proof type here only shut out linked external wallets.
    if !account.signing_available {
        return Err(creator_mint_unavailable_missing!()());
    }
    validate_wallet_evm_address(&account.address, "creator")
        .map_err(|(_, message)| anyhow::anyhow!(message))?;
    Ok(RuntimeCustodyCreatorAccount {
        account_id: account.account_id.clone(),
        address: account.address.to_ascii_lowercase(),
        external_signer: !is_managed_wallet_proof_type(&account.proof_type),
        connector_id: account.connector_id.clone(),
    })
}

pub(in crate::api::gateway) async fn resolve_runtime_custody_creator_mint_source(
    state: &GatewayState,
) -> anyhow::Result<ResolvedProtectedContentCreatorMintSource> {
    let response = wallet_chain_provider_data(
        state,
        serde_json::json!({
            "op": "describe_protected_content_creator_mint_source",
        }),
    )
    .await
    .map_err(creator_mint_unavailable!())?;
    let source: ResolvedProtectedContentCreatorMintSource =
        serde_json::from_value(response).map_err(creator_mint_unavailable!())?;
    if source.schema != "elastos.chain.protected-content-creator-mint-source/v1"
        || source.abi != "elacity_mint_v1"
        || source.function != "mint(string,uint16,bytes,bytes)"
        || wallet_chain_namespace_network(&source.chain_namespace) != Some(source.network.as_str())
    {
        return Err(creator_mint_unavailable_missing!()());
    }
    // No channel to validate: the source describes a deployment, and a mint
    // settles on the channel its creator chose. What it does offer is the set
    // of tokens a sale may be priced in, and every one of those has to be an
    // address this Runtime can encode.
    for pay_token in &source.pay_tokens {
        validate_wallet_evm_address(&pay_token.address, "creator pay token")
            .map_err(creator_mint_unavailable!())?;
    }
    Ok(source)
}

/// Resolve the account a mint already under way recorded.
///
/// `request_id` is derived from the principal, the object uri and its storage —
/// the content and where it lives, never the wallet. So re-publishing the same
/// object after switching wallets lands here with `account_id` naming the
/// account the first attempt recorded, and binding to it is deliberate: an
/// effect identity that changed payer on retry would not be durable.
///
/// Whether that pin is still the creator's intent is decided later, in the
/// creator tail, where the mint's stage is known — a mint with an effect
/// already in flight must finish on the account that raised it, and one that
/// has already settled is a replay, not a refusal. Only a mint that has
/// recorded terms and raised nothing can safely be stopped over a changed
/// default, which is why the question is not asked here.
async fn resolve_runtime_custody_bound_creator_account(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    account_id: &str,
    expected_address: &str,
) -> anyhow::Result<RuntimeCustodyCreatorAccount> {
    let account = resolve_runtime_custody_creator_account(state, authority, account_id).await?;
    if account.address != expected_address {
        return Err(creator_mint_unavailable_missing!()());
    }
    Ok(account)
}

/// What a price is denominated in: every token a sale may be priced in, with
/// the decimals that make its number readable and the name a person knows it
/// by.
///
/// Local configuration, read through the chain provider's description of the
/// mint source -- the same list a mint is priced against, so a shelf and a
/// creator's form cannot disagree about what a token is.
pub(in crate::api::gateway) async fn runtime_custody_pay_token_table(
    state: &GatewayState,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let source = resolve_runtime_custody_creator_mint_source(state).await?;
    Ok(source
        .pay_tokens
        .iter()
        .map(|token| {
            serde_json::json!({
                "symbol": token.symbol,
                "address": token.address,
                "decimals": token.decimals,
            })
        })
        .collect())
}

/// What this Home's account already holds on a set of channels.
///
/// The account is resolved here, from the launch context's wallet authority,
/// and is never returned to the caller -- a page that needs to know which
/// cards to offer a subscription for does not need to learn the address those
/// cards would be paid from.
///
/// Answers per channel, and answers `unknown` rather than `none` when the
/// chain could not be read: `none` is what puts a Subscribe button in front of
/// someone, and that must rest on an answer rather than on a silence.
pub(in crate::api::gateway) async fn runtime_custody_channel_access(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    channels: &[String],
) -> anyhow::Result<Vec<(String, String)>> {
    if channels.is_empty() {
        return Ok(Vec::new());
    }
    let source = resolve_runtime_custody_creator_mint_source(state).await?;
    let account = resolve_runtime_custody_wallet_default_account(
        state,
        authority,
        &source.chain_namespace,
        RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE,
    )
    .await?;
    let response = wallet_chain_provider_data(
        state,
        serde_json::json!({
            "op": "resolve_protected_content_channel_access",
            "network": source.network,
            "account": account.address.to_ascii_lowercase(),
            "channels": channels,
        }),
    )
    .await
    .map_err(|(_, message)| anyhow::anyhow!(message))?;
    let entries = response
        .get("channels")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("channel access answer carried no channels"))?;
    let mut states = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(channel) = entry.get("channel").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let value = entry
            .get("state")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        // Only the four words this Runtime knows reach a surface. A provider
        // that learns a fifth does not get to have it rendered untranslated.
        let value = match value {
            "administrator" | "subscribed" | "none" => value,
            _ => "unknown",
        };
        states.push((channel.to_ascii_lowercase(), value.to_string()));
    }
    Ok(states)
}

/// What a creator may choose from: the account a mint would be signed by, and
/// the tokens a sale may be priced in.
///
/// Both come from one description of the mint source, because they are one
/// question -- what can this Home mint, and as whom. Asking twice was two
/// identical round trips per page load.
///
/// The account is resolved here rather than taken from the page, because the
/// page choosing the account is the page choosing the answer: a directory
/// asked about a different account lists channels the mint could not use, and
/// the creator would pick one and be refused.
///
/// The address is the reason there is none when this Home has no usable
/// transaction default yet. That is not a failure of this call -- there is
/// simply nobody to ask a directory about, and the page can say which Wallet
/// step fixes it -- and the tokens are still worth returning.
pub(in crate::api::gateway) async fn runtime_custody_creator_choices(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
) -> anyhow::Result<(
    Result<String, crate::protected_content_runtime::RuntimeCustodyWalletDefaultReason>,
    Vec<serde_json::Value>,
)> {
    let source = resolve_runtime_custody_creator_mint_source(state).await?;
    let pay_tokens = source
        .pay_tokens
        .iter()
        .map(|token| {
            serde_json::json!({
                "symbol": token.symbol,
                "address": token.address,
                "decimals": token.decimals,
            })
        })
        .collect();
    let address = match resolve_runtime_custody_wallet_default_account(
        state,
        authority,
        &source.chain_namespace,
        RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE,
    )
    .await
    {
        Ok(account) => Ok(account.address.to_ascii_lowercase()),
        // The resolver already logged which precondition failed.
        Err(error) => Err(error
            .downcast_ref::<crate::protected_content_runtime::RuntimeCustodyWalletDefaultUnusable>()
            .map(|unusable| unusable.reason())
            .unwrap_or(
                crate::protected_content_runtime::RuntimeCustodyWalletDefaultReason::NoTransactionDefaultForChainNamespace,
            )),
    };
    Ok((address, pay_tokens))
}

pub(crate) async fn resolve_runtime_custody_creator_publish_binding(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
) -> anyhow::Result<RuntimeCustodyCreatorPublishBinding> {
    let mint_journal = crate::protected_content_runtime::runtime_mint_journal(&state.data_dir);
    let mint_journal_root =
        crate::protected_content_runtime::runtime_mint_journal_root(&state.data_dir);
    let source = resolve_runtime_custody_creator_mint_source(state).await?;
    let source_digest = runtime_custody_creator_mint_source_digest_for_source(&source);
    match std::fs::symlink_metadata(&mint_journal_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(creator_mint_unavailable_missing!()()),
        Ok(_) => {
            // The current attempt's account: an attempt set aside binds nothing,
            // so a new mint after it starts on today's transaction default.
            let request_id = mint_journal
                .current_attempt(principal_id, object_uri, source_storage)
                .map_err(creator_mint_unavailable!())?
                .request_id();
            match mint_journal.load_intent(request_id) {
                Ok(intent) => {
                    if intent.creator_mint_source_digest() != source_digest {
                        return Err(creator_mint_unavailable_missing!()());
                    }
                    let account = resolve_runtime_custody_bound_creator_account(
                        state,
                        authority,
                        intent.creator_wallet_account_id(),
                        intent.creator_wallet_address(),
                    )
                    .await?;
                    return Ok(RuntimeCustodyCreatorPublishBinding {
                        account_id: account.account_id,
                        address: account.address,
                        source_digest,
                    });
                }
                Err(elastos_protected_content_runtime::RuntimeMintJournalError::NotFound) => {}
                Err(_) => return Err(creator_mint_unavailable_missing!()()),
            }
            match mint_journal.load_media_preparation(request_id) {
                Ok(preparation) => {
                    if preparation.creator_mint_source_digest() != source_digest {
                        return Err(creator_mint_unavailable_missing!()());
                    }
                    let account = resolve_runtime_custody_bound_creator_account(
                        state,
                        authority,
                        preparation.creator_wallet_account_id(),
                        preparation.creator_wallet_address(),
                    )
                    .await?;
                    return Ok(RuntimeCustodyCreatorPublishBinding {
                        account_id: account.account_id,
                        address: account.address,
                        source_digest,
                    });
                }
                Err(elastos_protected_content_runtime::RuntimeMintJournalError::NotFound) => {}
                Err(_) => return Err(creator_mint_unavailable_missing!()()),
            }
        }
    }
    let account = resolve_runtime_custody_wallet_default_account(
        state,
        authority,
        &source.chain_namespace,
        RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE,
    )
    .await?;
    Ok(RuntimeCustodyCreatorPublishBinding {
        account_id: account.account_id,
        address: account.address,
        source_digest,
    })
}

/// `mime_type`/`codecs` are derived from the mint draft's own content
/// identity rather than taken as caller parameters. For media that is the
/// identical value the caller used to pass (`RuntimeMintDraft::new` is built
/// from the same two strings, and `verify_runtime_portable_metadata` already
/// asserts the published document matches the identity), so the emitted bytes
/// do not move; for an object there is no caller-side codecs string at all.
/// Publish the metadata DIRECTORY a mint's token URI resolves to.
///
/// Returns `(cid, "ipfs://{cid}")` — the FOLDER, never a file inside it. The
/// Operative appends to whatever base URI it is given
/// (`OperativePrimitive.uri(id)` is `base + "/{id}.json"`, `metadataURI()` is
/// `base + "/contract.json"`), so a base that already names `metadata.json`
/// makes every derived URI a doubled path that resolves to nothing. That is
/// exactly what shipped: `ipfs://Qm…/metadata.json/0000…0001.json`.
///
/// The directory holds the Elacity listing files a marketplace indexes, plus
/// the runtime's own document as `manifest.json`. The runtime document cannot
/// keep the name `metadata.json` because that is the one the token URI
/// resolves to, and it is the Elacity document that has to be there.
#[allow(
    clippy::too_many_arguments,
    reason = "these are the facts the folder states, each read from a different \
              authority -- the mint draft, the resolved chain source, the \
              creator's account and their listing terms; bundling them into a \
              struct would only move the same list one call further out"
)]
/// `ledger` is the channel this mint publishes into, which the document
/// states. It comes from the creator's choice rather than from the source,
/// which no longer names one.
async fn publish_runtime_custody_creator_metadata(
    registry: &ProviderRegistry,
    data_dir: &std::path::Path,
    object_uri: &str,
    facts: &crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts,
    mint: &elastos_protected_content_runtime::PersistedRuntimeMint,
    publisher_profile_did: &str,
    listing: Option<&crate::library::RuntimeCustodyListingTerms>,
    plaintext_bytes: u64,
    creator_address: &str,
    source: &ResolvedProtectedContentCreatorMintSource,
    copies_hex: &str,
    price_hex: &str,
    ledger: &str,
) -> anyhow::Result<(String, String)> {
    let draft = mint.draft();
    let (media_identity_base64, content_identity_base64) =
        crate::protected_content_runtime::runtime_portable_identity_fields(
            draft.content_identity(),
        )?;
    let metadata = RuntimeCustodyCreatorMetadata {
        schema: "elastos.protected-content.metadata/v1",
        name: runtime_custody_metadata_name(object_uri),
        mime_type: draft.content_identity().content_type(),
        codecs: &crate::protected_content_runtime::runtime_portable_content_codecs(
            draft.content_identity(),
        ),
        encrypted_content_cid: &facts.content_cid,
        content_access_id: format!("0x{}", hex::encode(draft.content_access_id().as_bytes())),
        protected_content_identity: &facts.content_id,
        mint_id: hex::encode(draft.mint_id().as_bytes()),
        publisher_profile_did,
        media_identity_base64,
        content_identity_base64,
        key_envelope_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.key_envelope().canonical_bytes()?),
        rights_policy_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.policy().canonical_bytes()?),
        content_key_commitment_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.content_key_commitment().as_bytes()),
        rights_policy_seal_required: true,
    };
    let bytes = serde_json::to_vec(&metadata)?;
    let parent = data_dir.join("protected-content");
    std::fs::create_dir_all(&parent)?;
    let staging = tempfile::Builder::new()
        .prefix("creator-metadata-")
        .tempdir_in(&parent)?;

    // The cover is pinned first and separately: it is the one part of the
    // listing that is bytes rather than a statement, and `metadata.json` has to
    // name its CID. Absent means the indexer falls back to its own type icon,
    // which is better than a broken image.
    let image = match listing.and_then(|listing| listing.thumbnail.as_ref()) {
        None => String::new(),
        Some(thumbnail) => {
            let filename = format!("cover{}", runtime_custody_cover_extension(&thumbnail.mime));
            let cover_cid = crate::content::publish_bytes_via_provider(
                registry,
                &filename,
                &thumbnail.bytes,
                None,
                None,
            )
            .await?;
            format!("ipfs://{cover_cid}")
        }
    };

    let threshold = draft.threshold();
    // Exactly one of the two is present, as in the listing package: a media
    // listing carries the media identity and an object the chunked one.
    let (media_identity, content_identity) =
        crate::protected_content_runtime::runtime_portable_identity_fields(
            draft.content_identity(),
        )?;
    // The helper answers with exactly one of the two, so whichever is present
    // is the identity this listing publishes.
    let published_content_identity = media_identity.or(content_identity).unwrap_or_default();
    let pool_mint_share =
        crate::protected_content_runtime::runtime_pool_mint_record(data_dir, draft.mint_id())?
            .map(|record| record.mint_share_base64);
    let inputs = crate::protected_content_elacity_metadata::ElacityMetadataInputs {
        encrypted_content_cid: &facts.content_cid,
        content_type: draft.content_identity().content_type(),
        plaintext_bytes,
        kid_0x: &format!("0x{}", hex::encode(draft.content_access_id().as_bytes())),
        publisher_address: creator_address,
        chain_id: runtime_custody_creator_chain_id(&source.chain_namespace)
            .map_err(creator_mint_unavailable!())?,
        ledger,
        authority: source
            .authority_gateway_contract
            .as_deref()
            .unwrap_or_default(),
        copies: runtime_custody_hex_quantity_to_u64(copies_hex)?,
        price: &runtime_custody_hex_quantity_to_decimal(price_hex)?,
        image: &image,
        protection: {
            let mut protection =
                crate::protected_content_elacity_metadata::runtime_custody_protection(
                    u32::from(threshold.required()),
                    u32::from(threshold.total()),
                    // The same four values the listing package carries, from the same
                    // draft, so a buyer who finds this asset in an index can open what
                    // they bought without needing the creator's link.
                    crate::protected_content_elacity_metadata::ProtectedContentIdentities {
                        rights_policy: &base64::engine::general_purpose::STANDARD
                            .encode(draft.policy().canonical_bytes()?),
                        key_envelope: &base64::engine::general_purpose::STANDARD
                            .encode(draft.key_envelope().canonical_bytes()?),
                        content_key_commitment: &base64::engine::general_purpose::STANDARD
                            .encode(draft.content_key_commitment().as_bytes()),
                        content_identity: &published_content_identity,
                        pool_mint_share: pool_mint_share.as_deref(),
                    },
                );
            // The immutable, pre-mint metadata names the policy's provisional
            // identity. The buyer can resolve its required seal after finality.
            protection["rights_policy_seal_required"] = serde_json::Value::Bool(true);
            protection
        },
        fallback_name: runtime_custody_metadata_name(object_uri),
        created_at: &crate::protected_content_elacity_metadata::rfc3339_utc(crate::auth::now_ts()),
        // From the mint's RECORDED terms, not the request: the document must
        // describe the mint that is actually being encoded, and a retry
        // re-encodes from these.
        access_method: mint.creator_state().map_or_else(Default::default, |state| {
            state.desired_terms().access_method()
        }),
        reseller_cut: mint
            .creator_state()
            .and_then(|state| state.desired_terms().reseller_cut()),
    };
    for (name, file_bytes) in
        crate::protected_content_elacity_metadata::elacity_metadata_files(listing, &inputs)?
    {
        std::fs::write(staging.path().join(name), file_bytes)?;
    }

    // The runtime's own document, unchanged in content, under the name the
    // Elacity one displaced.
    std::fs::write(staging.path().join("manifest.json"), bytes)?;

    let metadata_cid = crate::content::publish_directory_via_provider_with_kind(
        registry,
        staging.path(),
        "directory",
        None,
        None,
    )
    .await?;
    Ok((metadata_cid.clone(), format!("ipfs://{metadata_cid}")))
}

/// A file extension for the pinned cover, from its declared image type.
///
/// The extension is cosmetic — readers follow the CID, not the name — so an
/// unrecognised image type gets none rather than a guess.
fn runtime_custody_cover_extension(mime: &str) -> &'static str {
    match mime {
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/webp" => ".webp",
        "image/gif" => ".gif",
        "image/svg+xml" => ".svg",
        "image/avif" => ".avif",
        _ => "",
    }
}

/// Decimal count from a canonical `0x` quantity, for the listing documents.
fn runtime_custody_hex_quantity_to_u64(value: &str) -> anyhow::Result<u64> {
    u64::from_str_radix(value.trim().trim_start_matches("0x"), 16)
        .map_err(|_| creator_mint_unavailable_missing!()())
}

/// Decimal string from a canonical `0x` quantity. A price is `uint256` on
/// chain, so it is widened to `u128` and rendered as text rather than parsed
/// into anything narrower.
/// The creator's price in the base units of the token they chose.
///
/// The decimals come from the deployment's own list of offered tokens, which
/// is the only place they are stated, so the number that reaches the chain and
/// the number the creator typed cannot disagree about scale. A token this
/// deployment does not offer has unknown decimals and is refused rather than
/// guessed at.
///
/// `native_amount_to_hex_quantity` does the arithmetic: exact integer work
/// that rejects an amount more precise than its token, and the same conversion
/// the Wallet's own send path uses. One implementation, not two.
fn runtime_custody_creator_price_base_units(
    source: &ResolvedProtectedContentCreatorMintSource,
    chosen_pay_token: &str,
    price: &str,
) -> anyhow::Result<String> {
    let chosen = chosen_pay_token.trim();
    let token = if chosen.is_empty() {
        source.pay_tokens.first()
    } else {
        source
            .pay_tokens
            .iter()
            .find(|token| token.address.eq_ignore_ascii_case(chosen))
    };
    let decimals = match token {
        Some(token) => u32::from(token.decimals),
        // A deployment that offers no list priced in its chain's own coin,
        // which every EVM states at eighteen.
        None if chosen.is_empty() => RUNTIME_CUSTODY_NATIVE_PAY_TOKEN_DECIMALS,
        None => {
            tracing::warn!(
                line = line!(),
                pay_token = %chosen,
                "runtime custody creator mint: pay token is not offered by this deployment"
            );
            return Err(creator_mint_unavailable_missing!()());
        }
    };
    native_amount_to_hex_quantity(price, decimals).map_err(|(_, message)| {
        tracing::warn!(
            line = line!(),
            decimals,
            reason = %message,
            "runtime custody creator mint: price is not an amount of the chosen token"
        );
        // The creator's own words about their own number, kept beneath the
        // stable sentence: "supports at most 6 decimal places" is actionable
        // where "unavailable" is not.
        anyhow::anyhow!(message).context(RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE)
    })
}

/// Every EVM prices its own coin at eighteen decimals.
pub(in crate::api::gateway) const RUNTIME_CUSTODY_NATIVE_PAY_TOKEN_DECIMALS: u32 = 18;

fn runtime_custody_hex_quantity_to_decimal(value: &str) -> anyhow::Result<String> {
    u128::from_str_radix(value.trim().trim_start_matches("0x"), 16)
        .map(|parsed| parsed.to_string())
        .map_err(|_| creator_mint_unavailable_missing!()())
}

async fn publish_runtime_custody_creator_listing(
    registry: &ProviderRegistry,
    data_dir: &std::path::Path,
    mint: &elastos_protected_content_runtime::PersistedRuntimeMint,
    facts: &crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts,
    publisher_principal_id: &str,
    terminal: &elastos_protected_content_runtime::RuntimeMintCreatorTerminalEvidence,
) -> anyhow::Result<(
    String,
    crate::protected_content_runtime::RuntimePortableListingPackage,
)> {
    // A retry of a published v1 mint must keep the published CID. A new
    // listing (including a retry after chain settlement) requires its seal.
    let existing = crate::protected_content_runtime::load_runtime_custody_listing(
        data_dir,
        mint.draft().mint_id(),
    )?;
    let preserve_published_v1 = existing.as_ref().is_some_and(|record| {
        record.package.sealed_rights_policy_base64.is_none()
            && matches!(
                &record.origin,
                crate::protected_content_runtime::RuntimeCustodyListingOrigin::LocalCreator {
                    principal_id,
                    ..
                } if principal_id == publisher_principal_id
            )
    });
    let seal = if preserve_published_v1 {
        None
    } else {
        Some(
            crate::protected_content_runtime::ensure_finalized_mint_policy(
                registry, data_dir, mint, terminal,
            )
            .await
            .map_err(|error| {
                if error.is::<crate::protected_content_runtime::RuntimeMintSealAwaitingFinality>() {
                    return runtime_custody_creator_effect_pending(
                        crate::protected_content_runtime::creator_listing_awaiting_seal_finality(
                            mint,
                        ),
                        line!(),
                    );
                }
                error
            })?,
        )
    };
    let package = crate::protected_content_runtime::runtime_custody_creator_listing_package(
        data_dir,
        mint,
        facts,
        publisher_principal_id,
        terminal,
        seal.as_ref(),
    )?;
    let parent = data_dir.join("protected-content");
    std::fs::create_dir_all(&parent)?;
    let staging = tempfile::Builder::new()
        .prefix("creator-listing-")
        .tempdir_in(&parent)?;
    let listing_bytes = serde_json::to_vec(&package)?;
    package.check_encoded_listing_size(&listing_bytes)?;
    std::fs::write(staging.path().join("listing.json"), listing_bytes)?;
    let links = [
        ("metadata".to_string(), package.metadata_cid.clone()),
        ("encrypted-content".to_string(), package.content_cid.clone()),
    ];
    // MC-F1: no placement on the publish itself. A member asked to copy reads
    // the folder back from this Home, which serves a peer only a folder whose
    // listing and Library publication are recorded; the members are asked
    // after that ([`place_runtime_custody_listing_copies`]).
    let requirements = runtime_custody_listing_requirements()?;
    let cid = crate::content::publish_directory_via_provider_with_kind_links_and_requirements(
        registry,
        staging.path(),
        "protected-content-listing",
        Some(&package.content_id),
        Some(&package.publisher_profile_did),
        &links,
        requirements,
    )
    .await?;
    let listing_uri = format!("elastos://{cid}");
    crate::protected_content_runtime::persist_runtime_custody_creator_listing(
        data_dir,
        mint,
        package.clone(),
        publisher_principal_id,
        listing_uri.clone(),
    )?;
    Ok((listing_uri, package))
}

/// The availability a creator listing is published and placed with.
fn runtime_custody_listing_requirements(
) -> anyhow::Result<crate::content::ContentPublishRequirements> {
    crate::content::ContentPublishRequirements::new(
        crate::protected_content_runtime::PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET,
        crate::protected_content_runtime::protected_content_live_proof_required(
            crate::protected_content_runtime::PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET,
        ),
    )
}

/// MEMBER-COPIES (MC-F1): asks every member of a creator listing's pool to
/// keep a copy, with the content `ensure` a publish sends, on its own. Called
/// once the listing is persisted and its Library publication recorded, so the
/// members' read back of the folder is served. STAB-07 (J1-F3, A2-F1; D3):
/// the members that confirmed are recorded, and only the others are asked
/// on the next call, which the owner's re-place pass makes at start and at a
/// slow cadence until every member has confirmed. This never fails the
/// publish.
pub(crate) async fn place_runtime_custody_listing_copies(
    registry: &ProviderRegistry,
    data_dir: &std::path::Path,
    mint_id: elastos_protected_content_contracts::Digest32,
) {
    let placed = async {
        let Some(listing) =
            crate::protected_content_runtime::load_runtime_custody_listing(data_dir, mint_id)?
        else {
            return anyhow::Ok(());
        };
        let crate::protected_content_runtime::RuntimeCustodyListingOrigin::LocalCreator {
            listing_uri,
            ..
        } = &listing.origin
        else {
            return Ok(());
        };
        let Some(cid) = listing_uri.strip_prefix("elastos://") else {
            return Ok(());
        };
        let confirmed = listing_copy_placement(data_dir, mint_id)?;
        let targets: Vec<String> = listing_copy_holders(
            data_dir,
            crate::protected_content_runtime::listing_custody_pool(&listing.package)?,
        )
        .into_iter()
        .filter(|target| !confirmed.contains(target))
        .collect();
        if targets.is_empty() {
            return Ok(());
        }
        let response = crate::content::ensure_placement_via_provider(
            registry,
            cid,
            runtime_custody_listing_requirements()?.with_placement_targets(targets.clone()),
        )
        .await?;
        let confirmed_now: Vec<String> = response["data"]["availability"]["peer_selection"]
            ["replicas"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|replica| replica["role"] == "remote")
            .filter_map(|replica| replica["node_did"].as_str())
            .filter(|did| targets.iter().any(|target| target == did))
            .map(str::to_string)
            .collect();
        let unconfirmed = targets.len() - confirmed_now.len();
        if !confirmed_now.is_empty() {
            record_listing_copy_placement(data_dir, mint_id, &confirmed_now)?;
        }
        if unconfirmed > 0 {
            tracing::info!(
                mint_id = %hex::encode(mint_id.as_bytes()),
                unconfirmed,
                "runtime custody listing: pool members have not confirmed a copy yet; asked again later"
            );
        }
        Ok(())
    }
    .await;
    if let Err(error) = placed {
        tracing::warn!(
            error = %format!("{error:#}"),
            "runtime custody listing: the pool's members were not asked to keep a copy"
        );
    }
}

const LISTING_COPY_PLACEMENTS_SCHEMA: &str = "elastos.runtime.listing-copy-placements/v1";

const MAX_LISTING_COPY_PLACEMENTS_BYTES: usize = 4 * 1024 * 1024;

/// STAB-07 (D3): per created mint, the pool members that confirmed a copy of
/// its listing.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct ListingCopyPlacementsV1 {
    schema: String,
    #[serde(default)]
    placements: std::collections::BTreeMap<String, ListingCopyPlacementV1>,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct ListingCopyPlacementV1 {
    #[serde(default)]
    confirmed: std::collections::BTreeSet<String>,
}

fn listing_copy_placements_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    crate::protected_content_runtime::protected_content_root(data_dir)
        .join("listing-copy-placements.json")
}

fn load_listing_copy_placements(
    data_dir: &std::path::Path,
) -> anyhow::Result<ListingCopyPlacementsV1> {
    let path = listing_copy_placements_path(data_dir);
    if !path.exists() {
        return Ok(ListingCopyPlacementsV1 {
            schema: LISTING_COPY_PLACEMENTS_SCHEMA.to_string(),
            placements: Default::default(),
        });
    }
    let bytes = crate::collaboration_config::read_owner_only_file(
        &path,
        MAX_LISTING_COPY_PLACEMENTS_BYTES,
        "listing copy placements",
    )?;
    let file: ListingCopyPlacementsV1 = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        file.schema == LISTING_COPY_PLACEMENTS_SCHEMA,
        "the listing copy placements have an unknown schema"
    );
    Ok(file)
}

/// The members that confirmed a copy of `mint_id`'s listing so far.
fn listing_copy_placement(
    data_dir: &std::path::Path,
    mint_id: elastos_protected_content_contracts::Digest32,
) -> anyhow::Result<std::collections::BTreeSet<String>> {
    Ok(load_listing_copy_placements(data_dir)?
        .placements
        .remove(&hex::encode(mint_id.as_bytes()))
        .unwrap_or_default()
        .confirmed)
}

/// Adds `members` to those that confirmed a copy of `mint_id`'s listing.
fn record_listing_copy_placement(
    data_dir: &std::path::Path,
    mint_id: elastos_protected_content_contracts::Digest32,
    members: &[String],
) -> anyhow::Result<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut file = load_listing_copy_placements(data_dir)?;
    file.placements
        .entry(hex::encode(mint_id.as_bytes()))
        .or_default()
        .confirmed
        .extend(members.iter().cloned());
    let path = listing_copy_placements_path(data_dir);
    if let Some(parent) = path.parent() {
        crate::protected_content_config::ensure_owner_only_dir(parent, "protected-content root")?;
    }
    crate::protected_content_runtime::write_owner_only_bytes(
        &path,
        &serde_json::to_vec_pretty(&file)?,
    )
}

/// The members of `pool` asked to keep a copy of its listings.
fn listing_copy_holders(
    data_dir: &std::path::Path,
    pool: elastos_protected_content_contracts::CustodyPoolIdentityV1,
) -> Vec<String> {
    #[cfg(test)]
    if let Some(holders) = test_seams::listing_copy_holders(data_dir) {
        return holders;
    }
    crate::custody_pool_descriptor::pool_copy_holders(data_dir, pool, crate::auth::now_ts())
}

fn runtime_custody_metadata_name(object_uri: &str) -> &str {
    object_uri
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or("protected-content")
}

fn runtime_custody_creator_effect_binding(
    request: &RuntimeTransactionRequest,
) -> anyhow::Result<elastos_protected_content_runtime::RuntimeMintCreatorEffectBinding> {
    elastos_protected_content_runtime::RuntimeMintCreatorEffectBinding::new(
        request.effect_id.clone(),
        wallet_request_id(&request.effect_id, "approval"),
        request.request_sha256.clone(),
        request.account_id.clone(),
        request.address.clone(),
        request.chain_namespace.clone(),
        request.network.clone(),
    )
    .map_err(creator_mint_unavailable!())
}

/// The creator tail's refusal when a mint's metadata did not reach the public
/// IPFS store, or consent no longer stands at the approval phase: no approval
/// is raised, and the progress names the `public_metadata` stage as failed.
fn runtime_custody_creator_public_metadata_refused(
    mint: &elastos_protected_content_runtime::PersistedRuntimeMint,
    error: crate::public_metadata_consent::PublicMetadataError,
) -> anyhow::Error {
    if error.code() == crate::public_metadata_consent::PublicMetadataErrorCode::Disabled {
        tracing::debug!(
            detail = error.detail(),
            "runtime custody creator tail: public metadata sharing is off; no approval raised"
        );
    } else {
        tracing::warn!(
            code = error.code().as_str(),
            detail = error.detail(),
            "runtime custody creator tail: public metadata was not published; no approval raised"
        );
    }
    let progress =
        crate::protected_content_runtime::runtime_custody_creator_progress_with_public_metadata(
            mint,
            crate::protected_content_runtime::RuntimeCustodyPublicMetadataStage::Failed,
        );
    anyhow::Error::new(
        crate::public_metadata_publisher::PublicMetadataFailure::new(error, progress),
    )
    .context(RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE)
}

pub(super) fn runtime_custody_creator_chain_id(chain_namespace: &str) -> anyhow::Result<u64> {
    chain_namespace
        .strip_prefix("eip155:")
        .ok_or_else(creator_mint_unavailable_missing!())?
        .parse::<u64>()
        .map_err(creator_mint_unavailable!())
}

#[allow(
    clippy::too_many_arguments,
    reason = "creator mint assembly binds the exact on-chain mint terms without an intermediate authority struct"
)]
async fn resolve_runtime_custody_creator_chain_plan(
    state: &GatewayState,
    expected_source_digest: Digest32,
    source: &ResolvedProtectedContentCreatorMintSource,
    creator_state: &elastos_protected_content_runtime::RuntimeMintCreatorState,
    creator_address: &str,
    content_access_id: elastos_protected_content_contracts::ContentAccessIdV1,
    token_uri: &str,
) -> anyhow::Result<RuntimeCustodyCreatorChainPlan> {
    let response = wallet_chain_provider_data(
        state,
        serde_json::json!({
            "op": "resolve_protected_content_creator_mint",
            "creator": creator_address,
            "token_uri": token_uri,
            "content_access_id": format!("0x{}", hex::encode(content_access_id.as_bytes())),
            "copies": creator_state.desired_terms().copies(),
            "price": creator_state.desired_terms().price(),
            "op_type_code": creator_state.desired_terms().access_method().op_type_code(),
            "reseller_cut": creator_state.desired_terms().reseller_cut(),
            // The channel and the token, from the RECORDED terms for the same
            // reason as the payees below: a retry must publish into the same
            // channel, priced in the same token, as the attempt before it.
            "ledger": creator_state.desired_terms().ledger(),
            "pay_token": creator_state.desired_terms().pay_token(),
            // From the RECORDED terms, not the request: a retry re-encodes the
            // chain call here, and the payees have to be the ones the mint was
            // bound to rather than whatever the latest attempt happened to
            // carry. Empty is the chain default, the whole share to the creator.
            "royalties": creator_state
                .desired_terms()
                .royalties()
                .iter()
                .map(|royalty| serde_json::json!({
                    "address": royalty.address(),
                    "units": royalty.units(),
                }))
                .collect::<Vec<_>>(),
        }),
    )
    .await
    .map_err(creator_mint_unavailable!())?;
    let resolved: ResolvedProtectedContentCreatorMint =
        serde_json::from_value(response).map_err(creator_mint_unavailable!())?;
    let resolved_source_digest = runtime_custody_creator_mint_source_digest(
        &resolved.network,
        &resolved.chain_namespace,
        "elacity_mint_v1",
        &resolved.function,
    );
    // The capsule must hold the same decimals for this token as the source
    // that priced it. A disagreement here is a price wrong by a power of ten,
    // so it is refused rather than reconciled.
    let expected_decimals = source
        .pay_tokens
        .iter()
        .find(|token| token.address.eq_ignore_ascii_case(&resolved.pay_token))
        .map(|token| token.decimals);
    if expected_decimals.is_some_and(|decimals| decimals != resolved.pay_token_decimals) {
        tracing::warn!(
            line = line!(),
            pay_token = %resolved.pay_token,
            capsule_decimals = resolved.pay_token_decimals,
            source_decimals = ?expected_decimals,
            "runtime custody creator mint: pay token decimals disagree"
        );
        return Err(creator_mint_unavailable_missing!()());
    }
    if resolved.op_type_code != creator_state.desired_terms().access_method().op_type_code()
        || resolved.reseller_cut != creator_state.desired_terms().reseller_cut()
        || !resolved
            .ledger
            .eq_ignore_ascii_case(creator_state.desired_terms().ledger())
    {
        // The capsule encoded a different access method than the creator
        // recorded. Everything downstream -- the operative that is created,
        // whether a listing exists, what the receipt may be expected to prove
        // -- follows from this, so it is checked here rather than discovered
        // after the transaction settles.
        return Err(creator_mint_unavailable_missing!()());
    }
    if resolved.schema != "elastos.chain.protected-content-creator-mint/v1"
        || resolved.signed
        || resolved.function != "mint(string,uint16,bytes,bytes)"
        || resolved_source_digest != expected_source_digest
        || resolved.network != source.network
        || resolved.chain_namespace != source.chain_namespace
        || !resolved
            .content_access_id
            .eq_ignore_ascii_case(&format!("0x{}", hex::encode(content_access_id.as_bytes())))
        // The token the capsule priced in must be the one the terms recorded.
        // Empty terms are a record from before a token could be chosen, and
        // the capsule's own default answers for those.
        || (!creator_state.desired_terms().pay_token().is_empty()
            && !resolved
                .pay_token
                .eq_ignore_ascii_case(creator_state.desired_terms().pay_token()))
    {
        return Err(creator_mint_unavailable_missing!()());
    }
    validate_wallet_evm_address(&resolved.ledger, "creator ledger")
        .map_err(|(_, message)| anyhow::anyhow!(message))?;
    validate_wallet_evm_address(&resolved.to, "creator transaction target")
        .map_err(|(_, message)| anyhow::anyhow!(message))?;
    validate_wallet_evm_address(&resolved.pay_token, "creator pay token")
        .map_err(|(_, message)| anyhow::anyhow!(message))?;
    if !resolved.ledger.eq_ignore_ascii_case(&resolved.to) {
        return Err(creator_mint_unavailable_missing!()());
    }
    Ok(RuntimeCustodyCreatorChainPlan {
        network: resolved.network,
        chain_namespace: resolved.chain_namespace,
        ledger: resolved.ledger.to_ascii_lowercase(),
        pay_token: resolved.pay_token.to_ascii_lowercase(),
        to: resolved.to.to_ascii_lowercase(),
        data: resolved.data,
        value: resolved.value,
    })
}

pub(super) fn runtime_custody_creator_transaction_request(
    principal_id: &str,
    creator_account: &RuntimeCustodyCreatorAccount,
    creator_state: &elastos_protected_content_runtime::RuntimeMintCreatorState,
    chain_plan: &RuntimeCustodyCreatorChainPlan,
    mint_id: elastos_protected_content_contracts::Digest32,
    token_uri: &str,
) -> anyhow::Result<RuntimeTransactionRequest> {
    let stable_request = serde_json::json!({
        "domain": "elastos.protected-content.creator-request/v1",
        "effect_id": "",
        "wallet_account_id": creator_account.account_id,
        "address": creator_account.address,
        "chain_namespace": chain_plan.chain_namespace,
        "network": chain_plan.network,
        "to": chain_plan.to,
        "value": chain_plan.value,
        "data": chain_plan.data,
        "ledger": chain_plan.ledger,
        "pay_token": chain_plan.pay_token,
        "metadata_cid": creator_state.metadata_cid(),
        "token_uri": token_uri,
        "mint_id": hex::encode(mint_id.as_bytes()),
        "copies": creator_state.desired_terms().copies(),
        "price": creator_state.desired_terms().price(),
    });
    let request_sha256 = runtime_transaction_request_sha256(&stable_request)?;
    let mut request = RuntimeTransactionRequest {
        source: NATIVE_TRANSACTION_SOURCE,
        effect_id: String::new(),
        request_sha256,
        account_id: creator_account.account_id.clone(),
        address: creator_account.address.clone(),
        chain_namespace: chain_plan.chain_namespace.clone(),
        network: chain_plan.network.clone(),
        to: chain_plan.to.clone(),
        value: chain_plan.value.clone(),
        data: chain_plan.data.clone(),
        approval_reason: RUNTIME_CUSTODY_CREATOR_APPROVAL_REASON.to_string(),
        metadata: serde_json::json!({
            "product_operation": "protected_content_creator_mint",
            "ledger": chain_plan.ledger,
            "pay_token": chain_plan.pay_token,
            "metadata_cid": creator_state.metadata_cid(),
            "token_uri": token_uri,
        }),
    };
    let request_binding = transaction_request_binding(&request);
    request.effect_id = exact_runtime_transaction_effect_id(
        NATIVE_TRANSACTION_SOURCE,
        principal_id,
        &request.request_sha256,
        &request_binding,
    )?;
    Ok(request)
}

/// Resolves the finalized mint receipt (token id + operative) for the settled
/// mint transaction; a chain-provider `*_pending` answer surfaces as the
/// creator-pending state so callers re-poll.
///
/// A mint that reverted as a second mint of a content id already bound, and
/// whose content id the chain's own binding confirms is bound, ends as
/// `already_minted` ([`RuntimeCustodyCreatorMintBlocked::reverted_as_duplicate`]).
/// Every other failure stays what it was.
async fn resolve_runtime_custody_creator_mint_receipt(
    state: &GatewayState,
    mint_id: Digest32,
    creator_state: &elastos_protected_content_runtime::RuntimeMintCreatorState,
    creator_address: &str,
    chain_plan: &RuntimeCustodyCreatorChainPlan,
    content_access_id: elastos_protected_content_contracts::ContentAccessIdV1,
    transaction_hash: &str,
) -> anyhow::Result<ResolvedProtectedContentMintReceipt> {
    // Keyed by the transaction rather than the mint: this step is asking the
    // chain about one specific effect, and a reader chasing a stuck listing has
    // the hash in hand.
    let step = crate::protected_content_runtime::RuntimeMintStep::begin_repeating(
        "mint_receipt",
        transaction_hash,
    );
    let answer = wallet_chain_provider_data(
        state,
        serde_json::json!({
            "op": "resolve_protected_content_mint_receipt",
            "network": chain_plan.network,
            "hash": transaction_hash,
            "creator": creator_address,
            "ledger": chain_plan.ledger,
            "token_uri": creator_state.token_uri(),
            "op_type_code": creator_state.desired_terms().access_method().op_type_code(),
        }),
    )
    .await;
    let receipt_response = match answer {
        Ok(value) => value,
        Err(error) => {
            // "Not finalized yet" is this wait working, repeated every few
            // seconds until the chain catches up. Recording it as an
            // abandonment would bury the one case worth looking at.
            if runtime_custody_chain_answer_is_pending(&error) {
                step.pending();
            }
            if runtime_custody_chain_answer_is_reverted_duplicate(&error)
                && runtime_custody_reverted_mint_kid_is_bound(state, chain_plan, content_access_id)
                    .await
            {
                let blocked =
                    crate::protected_content_runtime::RuntimeCustodyCreatorMintBlocked::reverted_as_duplicate(
                        mint_id,
                        creator_state,
                    );
                tracing::warn!(
                    line = line!(),
                    state = blocked.state_label(),
                    "Runtime custody creator mint reverted as a duplicate of a minted item"
                );
                return Err(anyhow::Error::new(blocked));
            }
            return Err(creator_mint_chain_error(error, line!()));
        }
    };
    let receipt: ResolvedProtectedContentMintReceipt =
        serde_json::from_value(receipt_response).map_err(creator_mint_unavailable!())?;
    step.ok();
    tracing::debug!(
        token_id = %receipt.token_id,
        operative = %receipt.operative,
        "runtime custody creator tail: mint receipt resolved"
    );
    Ok(receipt)
}

/// The listing a native-priced mint proved by emitting `ItemListed` in its own
/// transaction.
///
/// The seller is the caller's address rather than a value read back from the
/// event because the chain provider already refused any receipt whose
/// `ItemListed` named a different seller or a different operative; restating it
/// here would only re-check what the capsule bound. Everything a reader still
/// has to be convinced of -- quantity, price, pay token -- comes from the
/// receipt, and `validate_runtime_custody_creator_terminal_bindings` is what
/// holds it to the creator's recorded terms.
pub(super) fn runtime_custody_listing_from_mint_receipt(
    creator_address: &str,
    chain_plan: &RuntimeCustodyCreatorChainPlan,
    receipt: &ResolvedProtectedContentMintReceipt,
) -> ResolvedProtectedContentVerifiedListing {
    ResolvedProtectedContentVerifiedListing {
        schema: RUNTIME_CUSTODY_VERIFIED_LISTING_SCHEMA.to_string(),
        network: chain_plan.network.clone(),
        chain_id: receipt.chain_id,
        seller: creator_address.to_string(),
        ledger: chain_plan.ledger.clone(),
        token_id: receipt.token_id.clone(),
        operative: receipt.operative.clone(),
        // A free mint lists nothing, so its receipt proves no sale terms. They
        // are recorded as a sale of nothing at no price in the chain's own
        // coin, which is what a free mint IS -- and is the shape every reader
        // of this record already understands.
        quantity: receipt
            .quantity
            .clone()
            .unwrap_or_else(|| RUNTIME_CUSTODY_UNSOLD_QUANTITY.to_string()),
        price: receipt
            .price
            .clone()
            .unwrap_or_else(|| RUNTIME_CUSTODY_UNSOLD_PRICE.to_string()),
        pay_token: receipt
            .pay_token
            .clone()
            .unwrap_or_else(|| RUNTIME_CUSTODY_NATIVE_PAY_TOKEN.to_string()),
        payment_processor: None,
    }
}

/// What a mint that sells nothing records in place of sale terms.
const RUNTIME_CUSTODY_UNSOLD_QUANTITY: &str = "0x0";

const RUNTIME_CUSTODY_UNSOLD_PRICE: &str = "0x0";

async fn finalize_runtime_custody_creator_listing(
    state: &GatewayState,
    creator_state: &elastos_protected_content_runtime::RuntimeMintCreatorState,
    creator_address: &str,
    chain_plan: &RuntimeCustodyCreatorChainPlan,
    receipt: &ResolvedProtectedContentMintReceipt,
    transaction_hash: &str,
) -> anyhow::Result<elastos_protected_content_runtime::RuntimeMintCreatorTerminalEvidence> {
    // The listing came with the receipt: the mint emits `ItemListed` in the same
    // transaction, so the quantity, price and pay token are already proven by
    // the evidence this tail has in hand. Only a non-native pay token needs
    // anything further, and only because its payment processor lives in chain
    // state rather than in the event.
    // A free mint has no listing to read back, and a native-priced one already
    // proved its terms in its own receipt. Only a non-native sale needs a
    // second read, and only because its payment processor lives in chain state
    // rather than in the event.
    let settles_in_native = receipt
        .pay_token
        .as_deref()
        .is_none_or(|pay_token| pay_token == RUNTIME_CUSTODY_NATIVE_PAY_TOKEN);
    let mut listing =
        runtime_custody_listing_from_mint_receipt(creator_address, chain_plan, receipt);
    if !settles_in_native {
        // The one fact the receipt cannot carry: where an ERC-20 sale pays
        // through. It lives on the operative rather than in the event.
        //
        // This used to re-read the WHOLE listing at a finalized block, which
        // re-proved terms the receipt had already proved and made every
        // non-native mint wait out L1 finality -- sixteen minutes on Base --
        // before its listing could be assembled. It did not wait: the two
        // evidence sources simply disagreed about a block that had not
        // finalized yet, and the mint failed with the listing unassembled
        // while the asset sat minted on chain.
        let response = wallet_chain_provider_data(
            state,
            serde_json::json!({
                "op": "resolve_protected_content_payment_processor",
                "network": chain_plan.network,
                "operative": receipt.operative,
            }),
        )
        .await
        .map_err(|error| creator_mint_chain_error(error, line!()))?;
        let payment_processor = response
            .get("payment_processor")
            .and_then(serde_json::Value::as_str)
            .map(str::to_ascii_lowercase)
            .ok_or_else(creator_mint_unavailable_missing!())?;
        validate_wallet_evm_address(&payment_processor, "payment processor")
            .map_err(|(_, message)| anyhow::anyhow!(message))?;
        listing.payment_processor = Some(payment_processor);
    }
    validate_runtime_custody_creator_terminal_bindings(
        creator_state,
        creator_address,
        chain_plan,
        receipt,
        &listing,
    )?;
    elastos_protected_content_runtime::RuntimeMintCreatorTerminalEvidence::new(
        creator_state.metadata_cid(),
        creator_state.token_uri(),
        creator_address,
        &chain_plan.chain_namespace,
        &chain_plan.network,
        &chain_plan.ledger,
        listing.token_id,
        listing.operative,
        listing.quantity,
        listing.price,
        listing.pay_token,
        listing
            .payment_processor
            .map(|value| value.to_ascii_lowercase()),
        transaction_hash,
        crate::auth::now_ts(),
    )
    .map_err(creator_mint_unavailable!())
}

pub(super) fn validate_runtime_custody_creator_terminal_bindings(
    creator_state: &elastos_protected_content_runtime::RuntimeMintCreatorState,
    creator_address: &str,
    chain_plan: &RuntimeCustodyCreatorChainPlan,
    receipt: &ResolvedProtectedContentMintReceipt,
    listing: &ResolvedProtectedContentVerifiedListing,
) -> anyhow::Result<()> {
    let expected_chain_id = runtime_custody_creator_chain_id(&chain_plan.chain_namespace)?;
    if receipt.schema != "elastos.chain.protected-content-mint-receipt/v1"
        || receipt.network != chain_plan.network
        || receipt.chain_id != expected_chain_id
    {
        return Err(creator_mint_unavailable_missing!()());
    }
    if listing.schema != RUNTIME_CUSTODY_VERIFIED_LISTING_SCHEMA
        || listing.network != chain_plan.network
        || listing.chain_id != expected_chain_id
        || listing.chain_id != receipt.chain_id
        || !listing.seller.eq_ignore_ascii_case(creator_address)
        || !listing.ledger.eq_ignore_ascii_case(&chain_plan.ledger)
        || !listing.token_id.eq_ignore_ascii_case(&receipt.token_id)
        || !listing.operative.eq_ignore_ascii_case(&receipt.operative)
        || listing.quantity != creator_state.desired_terms().copies()
        || listing.price != creator_state.desired_terms().price()
        || !listing
            .pay_token
            .eq_ignore_ascii_case(&chain_plan.pay_token)
    {
        return Err(creator_mint_unavailable_missing!()());
    }
    Ok(())
}

pub(crate) async fn runtime_custody_publish_via_gateway(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    registry: Arc<ProviderRegistry>,
    input: crate::protected_content_runtime::RuntimeCustodyLibrarySourceInput,
    terms_source: crate::protected_content_runtime::RuntimeCustodyCreatorTermsSource,
) -> anyhow::Result<crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts> {
    let (facts, prepared_input) =
        crate::protected_content_runtime::publish_runtime_custody_library_source(
            &state.data_dir,
            Arc::clone(&registry),
            input,
        )
        .await?;
    let mut tail_input =
        crate::protected_content_runtime::RuntimeCustodyCreatorTailInput::from(&prepared_input);
    tail_input.terms_source = terms_source;
    runtime_custody_publish_creator_tail_from_facts(state, authority, registry, tail_input, facts)
        .await
}

/// Object twin of [`runtime_custody_publish_via_gateway`]: seal, mint,
/// provision and publish the EPC1 object, then run the SAME creator tail
/// (chain mint, metadata document, portable listing) the media path runs. The
/// tail is shared, not duplicated — everything kind-specific it needs it reads
/// from the persisted mint draft.
pub(crate) async fn runtime_custody_publish_object_via_gateway(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    registry: Arc<ProviderRegistry>,
    input: crate::protected_content_runtime::RuntimeCustodyLibraryPublishObjectInput,
    terms_source: crate::protected_content_runtime::RuntimeCustodyCreatorTermsSource,
) -> anyhow::Result<crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts> {
    let mut tail_input =
        crate::protected_content_runtime::RuntimeCustodyCreatorTailInput::from(&input);
    tail_input.terms_source = terms_source;
    let facts = crate::protected_content_runtime::publish_runtime_custody_library_object_content(
        &state.data_dir,
        Arc::clone(&registry),
        input,
    )
    .await?;
    runtime_custody_publish_creator_tail_from_facts(state, authority, registry, tail_input, facts)
        .await
}

async fn runtime_custody_publish_creator_tail_from_facts(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    registry: Arc<ProviderRegistry>,
    input: crate::protected_content_runtime::RuntimeCustodyCreatorTailInput,
    mut facts: crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts,
) -> anyhow::Result<crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts> {
    let mint_journal = crate::protected_content_runtime::runtime_mint_journal(&state.data_dir);
    // Held from reading this attempt until its approval is raised, so an
    // unrecoverable-attempt drop can never land between the two.
    let attempt = crate::protected_content_runtime::runtime_custody_creator_attempt_lock(
        &state.data_dir,
        facts.mint_id,
    );
    let attempt_guard = attempt.lock().await;
    let mut mint = mint_journal
        .load(facts.mint_id)
        .map_err(creator_mint_unavailable!())?;
    let source = resolve_runtime_custody_creator_mint_source(state).await?;
    if runtime_custody_creator_mint_source_digest_for_source(&source)
        != input.creator_mint_source_digest
    {
        return Err(creator_mint_unavailable_missing!()());
    }
    let creator_account =
        resolve_runtime_custody_creator_account(state, authority, &input.wallet_account_id).await?;
    if creator_account.address != input.wallet_account_address {
        return Err(creator_mint_unavailable_missing!()());
    }
    let (desired_terms, price_hex, ledger) = match input.terms_source {
        // Resume runs from the record and nothing else: the person typed
        // nothing, and whatever the request carries about terms is not read.
        crate::protected_content_runtime::RuntimeCustodyCreatorTermsSource::Recorded => {
            let recorded = mint
                .creator_state()
                .map(|state| state.desired_terms().clone())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        crate::protected_content_runtime::RUNTIME_CUSTODY_CREATOR_NOTHING_TO_RESUME_MESSAGE
                    )
                })?;
            let price_hex = recorded.price().to_string();
            let ledger = recorded.ledger().to_string();
            (recorded, price_hex, ledger)
        }
        crate::protected_content_runtime::RuntimeCustodyCreatorTermsSource::Requested => {
            // The creator's royalty split is part of the recorded terms, not of
            // the request alone: a retry compares desired terms and re-encodes
            // the chain call from them, so a split held only in the request
            // could differ between attempts and silently change what the
            // transaction pays out. Absent means the chain default, a single
            // payee.
            let royalties = input
                .listing
                .as_ref()
                .map(|listing| {
                    listing
                        .royalties
                        .iter()
                        .map(|royalty| {
                            elastos_protected_content_runtime::RuntimeMintRoyaltyShare::new(
                                royalty.address.clone(),
                                royalty.units,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()
                .map_err(creator_mint_unavailable!())?
                .unwrap_or_default();
            // The access method travels with the royalty split for the same
            // reason: it is a term the chain call is re-encoded from on a retry,
            // not a description of the asset. A mint with no listing keeps the
            // pre-listing behaviour, which was buy once.
            let (access_method, reseller_cut) = input
                .listing
                .as_ref()
                .map(|listing| (listing.access_method, listing.reseller_cut))
                .unwrap_or_default();
            // The channel and token the creator chose. Mint terms, so they
            // arrive beside copies and price rather than inside the optional
            // listing: a mint with no marketplace listing still has to settle
            // somewhere.
            let (ledger, chosen_pay_token) = (input.channel.clone(), input.pay_token.clone());
            // The creator's price arrives as an amount of the token they chose,
            // and is scaled here because this is where that token's decimals
            // are known. The page used to scale it and then declare which
            // decimals it had used, which made the declaration something to
            // verify rather than something true -- and a page that got it
            // wrong priced a sale a million-fold under.
            let price_hex =
                runtime_custody_creator_price_base_units(&source, &chosen_pay_token, &input.price)?;
            let desired_terms =
                elastos_protected_content_runtime::RuntimeMintCreatorDesiredTerms::new(
                    creator_account.account_id.clone(),
                    input.copies.clone(),
                    price_hex.clone(),
                    royalties,
                    access_method,
                    reseller_cut,
                    ledger.clone(),
                    chosen_pay_token,
                )
                .map_err(creator_mint_unavailable!())?;
            (desired_terms, price_hex, ledger)
        }
    };
    // A new mint at other terms meets an earlier attempt. One that sent
    // nothing on chain never blocks it: that attempt is set aside -- archived,
    // not deleted -- and the publish runs again as a new attempt with an
    // identity of its own. One whose transaction was sent or mined, or that is
    // listed, keeps its terms: the refusal names the terms that differ and the
    // creator resumes it.
    if mint
        .creator_state()
        .is_some_and(|existing| existing.desired_terms() != &desired_terms)
    {
        let outcome = archive_runtime_custody_creator_attempt_locked(
            state,
            authority,
            &input.principal_id,
            &input.object_uri,
            &input.source_storage,
            Some(&mint),
            crate::protected_content_runtime::RuntimeCustodyAttemptArchiveReason::NewAttempt,
        )
        .await?;
        if let Some(refusal) = outcome.kept_refusal(Some(&desired_terms)) {
            return Err(refusal);
        }
        return Err(match outcome {
            RuntimeCustodyAttemptArchiveOutcome::Archived(_) => anyhow::Error::new(
                crate::protected_content_runtime::RuntimeCustodyCreatorAttemptArchived,
            ),
            // Nothing was on record to set aside after all; saying it was
            // would be untrue.
            _ => creator_mint_unavailable_missing!()(),
        });
    }
    if let Some(existing) = mint.creator_state() {
        // A mint keeps the account it started with, so a creator who changed
        // their transaction default after starting one would otherwise have it
        // settle, silently, on the account they stopped choosing.
        //
        // Only `Recorded` may be stopped over that. `EffectRaised` has an
        // approval out -- possibly signed, possibly already broadcast -- and
        // refusing there would strand a transaction that is in flight on the
        // bound account rather than protect anyone from it. `Settled` is a
        // replay: the chain effect is done, and refusing would leave the
        // listing permanently unpublishable. Both of those keep the account
        // they have; this one is still free.
        if existing.stage() == elastos_protected_content_runtime::RuntimeMintCreatorStage::Recorded
        {
            if let Ok(default_account) = resolve_runtime_custody_wallet_default_account(
                state,
                authority,
                &source.chain_namespace,
                RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE,
            )
            .await
            {
                if !default_account
                    .address
                    .eq_ignore_ascii_case(&creator_account.address)
                {
                    let drift =
                        crate::protected_content_runtime::RuntimeCustodyCreatorWalletDrift::new(
                            &source.chain_namespace,
                            &creator_account.address,
                            &default_account.address,
                        );
                    // Reason code only: the two addresses belong in the
                    // creator's answer, not in the operator log.
                    tracing::warn!(
                        reason = drift.reason_label(),
                        chain_namespace = %source.chain_namespace,
                        "runtime custody creator tail: recorded terms name an account that is no \
                         longer the transaction default; refusing before raising the effect"
                    );
                    return Err(anyhow::Error::new(drift)
                        .context(RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE));
                }
            }
        }
        if let Some(terminal) = existing.terminal() {
            if !terminal
                .seller()
                .eq_ignore_ascii_case(&creator_account.address)
            {
                return Err(creator_mint_unavailable_missing!()());
            }
            facts.listing_uri = Some(
                publish_runtime_custody_creator_listing(
                    registry.as_ref(),
                    &state.data_dir,
                    &mint,
                    &facts,
                    &input.principal_id,
                    terminal,
                )
                .await?
                .0,
            );
            drop(attempt_guard);
            repair_runtime_custody_minted_owned_copy(state, &input.principal_id, facts.mint_id)
                .await;
            facts.capsule_uri = crate::protected_content_runtime::load_runtime_custody_purchase(
                &state.data_dir,
                &input.principal_id,
                facts.mint_id,
            )
            .ok()
            .flatten()
            .and_then(|owned| owned.capsule_uri);
            // This request settled nothing: the mint was already terminal, so
            // no effect was raised and no transaction was sent. Without saying
            // so the answer is indistinguishable from a fresh mint, and the
            // Creator reported "Listed for sale" for work that happened over
            // an hour earlier -- including, in the case that surfaced this,
            // under a wallet the creator had since stopped using.
            //
            // Additive: `mint_id` and every other field a caller already reads
            // are unchanged, so an older client behaves exactly as before.
            facts.content_security["settled_before_this_request"] = serde_json::Value::Bool(true);
            facts.content_security["settled_at"] = serde_json::Value::from(terminal.published_at());
            facts.content_security["transaction_hash"] =
                serde_json::Value::from(terminal.transaction_hash());
            // Which account it actually minted on. A settled mint is never
            // refused over a changed transaction default -- the chain effect is
            // done and refusing would leave the listing unpublishable -- so
            // naming the seller is the only way a creator who has since
            // switched wallets can see that this listing is not on the account
            // they would choose today.
            facts.content_security["settled_seller_address"] =
                serde_json::Value::from(terminal.seller());
            return Ok(facts);
        }
    }
    let creator_state = match mint.creator_state().cloned() {
        Some(existing) => existing,
        None => {
            let publisher_profile_did =
                crate::protected_content_runtime::load_runtime_custody_profile_did(
                    &state.data_dir,
                    &input.principal_id,
                )?;
            let (metadata_cid, token_uri) = publish_runtime_custody_creator_metadata(
                registry.as_ref(),
                &state.data_dir,
                &input.object_uri,
                &facts,
                &mint,
                &publisher_profile_did,
                input.listing.as_ref(),
                input.plaintext_bytes,
                &creator_account.address,
                &source,
                &input.copies,
                // The scaled price, not the amount the creator typed: this
                // document states a price in the pay token's base units, which
                // is what the chain call carries and what a marketplace reads.
                &price_hex,
                &ledger,
            )
            .await?;
            let creator_state = elastos_protected_content_runtime::RuntimeMintCreatorState::new(
                desired_terms.clone(),
                metadata_cid,
                token_uri,
            )
            .map_err(creator_mint_unavailable!())?;
            mint = mint_journal
                .bind_creator_state(facts.mint_id, creator_state.clone())
                .map_err(creator_mint_unavailable!())?;
            creator_state
        }
    };
    let mint_ref = hex::encode(facts.mint_id.as_bytes());
    let step =
        crate::protected_content_runtime::RuntimeMintStep::begin_repeating("chain_plan", &mint_ref);
    let chain_plan = resolve_runtime_custody_creator_chain_plan(
        state,
        input.creator_mint_source_digest,
        &source,
        &creator_state,
        &creator_account.address,
        mint.draft().content_access_id(),
        creator_state.token_uri(),
    )
    .await?;
    step.ok();
    tracing::trace!(
        mint_id = %hex::encode(facts.mint_id.as_bytes()),
        network = %chain_plan.network,
        to = %chain_plan.to,
        value = %chain_plan.value,
        "runtime custody creator tail: mint chain plan resolved"
    );
    let request = runtime_custody_creator_transaction_request(
        &input.principal_id,
        &creator_account,
        &creator_state,
        &chain_plan,
        facts.mint_id,
        creator_state.token_uri(),
    )?;
    let effect_binding = runtime_custody_creator_effect_binding(&request)?;
    if let Some(existing) = mint.creator_state().and_then(|state| state.effect()) {
        if existing != &effect_binding {
            return Err(creator_mint_unavailable_missing!()());
        }
    } else {
        mint_journal
            .bind_creator_effect(facts.mint_id, &creator_state, effect_binding.clone())
            .map_err(creator_mint_unavailable!())?;
        // The wait starts here and is polled from the browser, so the server
        // sees it as many separate requests rather than a loop. These two
        // lines -- this one and "mint receipt resolved" -- are its start and
        // its end; everything in between repeats and lives at TRACE.
        tracing::debug!(
            mint_id = %mint_ref,
            effect_id = %effect_binding.effect_id(),
            "runtime custody creator tail: settlement wait began"
        );
    }
    // An approval or effect that already exists settles under the authority
    // it has: no public-store call and no new approval, whatever the consent
    // or the store. Only a new or reissued approval is new authority, and it
    // is raised only after this mint's metadata is public (META-PUBLIC §7.0).
    // An expired external handoff stays closed under its old effect id.
    let existing =
        runtime_transaction_effect_progress(state, authority, effect_binding.effect_id())
            .await
            .map_err(|(_, message)| anyhow::anyhow!(message))?;
    let reissue = match existing {
        RuntimeTransactionEffectProgress::Unknown
        | RuntimeTransactionEffectProgress::ClosedWithoutSignature => true,
        RuntimeTransactionEffectProgress::InConnector(_) => {
            runtime_transaction_effect_approval_lapsed(state, authority, effect_binding.effect_id())
                .await
                .map_err(|(_, message)| anyhow::anyhow!(message))?
        }
        RuntimeTransactionEffectProgress::AwaitingApproval
        | RuntimeTransactionEffectProgress::HandoffExpired
        | RuntimeTransactionEffectProgress::Signed
        | RuntimeTransactionEffectProgress::Mined => false,
    };
    if reissue {
        // A5 (binding O2): while sharing is not offered the tail is develop's:
        // no publication, no consent check, and the approval is raised.
        if crate::public_metadata_consent::public_metadata_offered(&state.data_dir) {
            let step = crate::protected_content_runtime::RuntimeMintStep::begin_repeating(
                "public_metadata",
                &mint_ref,
            );
            crate::public_metadata_publisher::publish_mint_public_metadata(
                &registry,
                &state.data_dir,
                creator_state.metadata_cid(),
            )
            .await
            .map_err(|error| runtime_custody_creator_public_metadata_refused(&mint, error))?;
            step.ok();
            // The approval phase: consent is read again, without the lock. An
            // approval created here is an existing one from then on, and a
            // withdrawal never waits for it.
            crate::public_metadata_publisher::approval_phase_allowed(&state.data_dir)
                .map_err(|error| runtime_custody_creator_public_metadata_refused(&mint, error))?;
        }
        let step = crate::protected_content_runtime::RuntimeMintStep::begin_repeating(
            "wallet_approval",
            &mint_ref,
        );
        let approval = ensure_exact_runtime_transaction_approval(state, authority, request.clone())
            .await
            .map_err(|(_, message)| anyhow::anyhow!(message))?;
        step.ok();
        tracing::trace!(
            effect_id = %approval.effect_id,
            "runtime custody creator tail: exact wallet effect ensured"
        );
    } else {
        tracing::trace!(
            effect_id = %effect_binding.effect_id(),
            existing = ?existing,
            "runtime custody creator tail: settling the existing wallet effect"
        );
    }
    // The approval is out (or was already): from here a drop is decided by
    // what the Wallet says about it, so the attempt no longer needs holding.
    drop(attempt_guard);
    let completion = match complete_runtime_transaction_effect(
        state,
        authority,
        RuntimeTransactionLookup::ApprovalId(effect_binding.approval_request_id()),
        Some(&request),
        None,
    )
    .await
    {
        Ok(completion) => completion,
        Err((status, message))
            if status == StatusCode::BAD_REQUEST
                && message == "transaction approval is not completed" =>
        {
            return Err(runtime_custody_creator_effect_pending(
                crate::protected_content_runtime::RuntimeCustodyEffectPending::awaiting_wallet_approval(
                    creator_account.external_signer,
                    creator_account.connector_id.as_deref(),
                )
                .with_progress(
                    crate::protected_content_runtime::runtime_custody_creator_progress_with_public_metadata(
                        &mint,
                        crate::protected_content_runtime::RuntimeCustodyPublicMetadataStage::Done,
                    ),
                ),
                line!(),
            ));
        }
        // Finished, and not successfully. Neither of these ever produced a
        // signature, so no transaction can result and there is nothing left to
        // wait for -- which is precisely what the shared "not completed"
        // answer could not say.
        Err((status, message))
            if status == StatusCode::BAD_REQUEST
                && (message
                    == super::gateway_transaction_effects::TRANSACTION_APPROVAL_REJECTED
                    || message
                        == super::gateway_transaction_effects::TRANSACTION_APPROVAL_EXPIRED) =>
        {
            let closed = crate::protected_content_runtime::RuntimeCustodyApprovalClosed::new(
                if message == super::gateway_transaction_effects::TRANSACTION_APPROVAL_REJECTED {
                    crate::protected_content_runtime::RuntimeCustodyApprovalClosedReason::Rejected
                } else {
                    crate::protected_content_runtime::RuntimeCustodyApprovalClosedReason::Expired
                },
            );
            tracing::warn!(
                line = line!(),
                reason = closed.reason_label(),
                "runtime custody creator tail: wallet approval closed without completing"
            );
            return Err(
                anyhow::Error::new(closed).context(RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE)
            );
        }
        // Signed and sent, and the Chain's sources have not seen it yet. Asking
        // again reconciles the same transaction; nothing is signed or sent.
        Err(error) if chain_has_not_seen_transaction(&error) => {
            tracing::warn!(
                line = line!(),
                error = %error.1,
                "runtime custody creator tail: the Chain has not seen the transaction yet"
            );
            return Err(runtime_custody_creator_effect_pending(
                crate::protected_content_runtime::RuntimeCustodyEffectPending::awaiting_chain_settlement()
                    .with_progress(
                        crate::protected_content_runtime::runtime_custody_creator_progress_with_public_metadata(
                            &mint,
                            crate::protected_content_runtime::RuntimeCustodyPublicMetadataStage::Done,
                        ),
                    ),
                line!(),
            ));
        }
        Err((status, message)) => {
            tracing::warn!(
                line = line!(),
                %status,
                %message,
                "runtime custody creator tail: transaction effect completion failed"
            );
            return Err(anyhow::anyhow!(message));
        }
    };
    // Approved, and the chain has not produced the evidence yet. Nobody need
    // act, which is exactly what the old shared "pending" could not say.
    if completion.receipt.is_none() || completion.completion_pending {
        return Err(runtime_custody_creator_effect_pending(
            crate::protected_content_runtime::RuntimeCustodyEffectPending::awaiting_chain_settlement()
                .with_progress(
                    crate::protected_content_runtime::runtime_custody_creator_progress_with_public_metadata(
                        &mint,
                        crate::protected_content_runtime::RuntimeCustodyPublicMetadataStage::Done,
                    ),
                ),
            line!(),
        ));
    }
    if completion.completion_error.is_some() {
        return Err(creator_mint_unavailable_missing!()());
    }
    // The finalized receipt names the operative that holds the minted copies.
    // The market gateway moves them without a separate ERC-1155 operator
    // approval -- the contract grants that itself -- so the mint is the ONE
    // wallet effect this tail raises. It previously raised a second
    // `setApprovalForAll` here, gated on an `isApprovedForAll` probe that
    // treated any undecodable answer as "not approved"; that asked the creator
    // to approve again on every mint, and the Creator disables its button at
    // this stage, so the prompt could not even be answered.
    //
    // Scope: this is about MINTING only. An operator approval is still the
    // mechanism for secondary trading -- an owner listing some of the Access
    // Tokens or Royalty Shares they hold has to authorize the operator that
    // moves them, and that flow will need one. What the contract change
    // removed is the need to ask for it while minting, where the creator is
    // not selling anything yet. The ERC-1155 call-data helpers went with the
    // probe rather than being kept unused; a resale path builds what it needs.
    let receipt = resolve_runtime_custody_creator_mint_receipt(
        state,
        facts.mint_id,
        &creator_state,
        &creator_account.address,
        &chain_plan,
        mint.draft().content_access_id(),
        &completion.transaction_hash,
    )
    .await?;
    let terminal = finalize_runtime_custody_creator_listing(
        state,
        &creator_state,
        &creator_account.address,
        &chain_plan,
        &receipt,
        &completion.transaction_hash,
    )
    .await?;
    mint = mint_journal
        .mark_creator_completed(facts.mint_id, terminal.clone())
        .map_err(creator_mint_unavailable!())?;
    let (listing_uri, package) = publish_runtime_custody_creator_listing(
        registry.as_ref(),
        &state.data_dir,
        &mint,
        &facts,
        &input.principal_id,
        &terminal,
    )
    .await?;
    facts.listing_uri = Some(listing_uri);
    // The `.ddrm` the creator opens. Written only now, because a capsule states
    // the `tokenId` the mint produced and that does not exist until it has.
    facts.capsule_uri = write_runtime_custody_owned_capsule(
        state,
        registry.as_ref(),
        &package,
        &input.principal_id,
        crate::protected_content_runtime::RuntimeCustodyAcquisitionV1::Minted,
    )
    .await;
    record_runtime_custody_minted_owned_copy(
        state,
        &package,
        &creator_account,
        &input.principal_id,
        mint.draft().content_access_id().as_bytes(),
        mint.content_availability()
            .map(runtime_custody_purchase_availability_receipt_digest),
        &request,
        completion,
        facts.mint_id,
        facts.capsule_uri.clone(),
    )
    .await;
    Ok(facts)
}

/// The digest a listing record states as its own, recomputed over the package.
///
/// It is the value `portable_package_digest` returns, spelled the one way, so a
/// copy recorded here binds to exactly the listing a viewer will validate it
/// against.
fn runtime_custody_portable_package_digest(
    package: &crate::protected_content_runtime::RuntimePortableListingPackage,
) -> anyhow::Result<String> {
    Ok(format!(
        "sha256:{}",
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(serde_json::to_vec(
            package
        )?))
    ))
}

/// Give a creator back the record of a copy they have always owned.
///
/// Minted copies were not recorded as owned until they were, so an asset minted
/// before that lands on disk with a listing, a terminal and no owned copy --
/// and its creator is refused at the door of their own asset. This restores the
/// record from what was already written down at the time.
///
/// Nothing is reconstructed or assumed. The listing names the content, the mint
/// journal names the wallet and the effect behind it, and the settled effect
/// still carries the exact transaction that was approved and sent. The one
/// question asked fresh is the one that must be: whether the chain says this
/// wallet has access now.
///
/// Authority-free on purpose. The proxy denies protected viewer operations a
/// Wallet authority, and this respects that: it reads the principal's own
/// durable state and asks one read-only chain question. It signs nothing, opens
/// no approval and moves no funds.
///
/// Silent and best effort. A creator opening their asset should not be shown
/// the repair, and a mint whose copy cannot be restored yet is simply not
/// restored -- the caller's own refusal still speaks for it.
async fn repair_runtime_custody_minted_owned_copy(
    state: &GatewayState,
    principal_id: &str,
    mint_id: elastos_protected_content_contracts::Digest32,
) {
    let Ok(owned) = crate::protected_content_runtime::load_runtime_custody_purchase(
        &state.data_dir,
        principal_id,
        mint_id,
    ) else {
        return;
    };
    if owned.as_ref().is_some_and(|record| {
        record.acquisition != crate::protected_content_runtime::RuntimeCustodyAcquisitionV1::Minted
            || record.capsule_uri.is_some()
    }) {
        return;
    }
    let Ok(Some(listing)) =
        crate::protected_content_runtime::load_runtime_custody_listing(&state.data_dir, mint_id)
    else {
        return;
    };
    // Only the creator of a locally minted listing owns it by minting. An
    // imported listing carries no principal at all, so it can never take this
    // path -- someone else's listing on this disk grants nothing.
    if !matches!(
        &listing.origin,
        crate::protected_content_runtime::RuntimeCustodyListingOrigin::LocalCreator {
            principal_id: creator,
            ..
        } if creator == principal_id
    ) {
        return;
    }
    let journal = crate::protected_content_runtime::runtime_mint_journal(&state.data_dir);
    let Ok(mint) = journal.load(mint_id) else {
        return;
    };
    let Some(creator_state) = mint.creator_state() else {
        return;
    };
    // No terminal means the mint never completed, so there is no copy to give
    // back.
    let (Some(terminal), Some(effect)) = (creator_state.terminal(), creator_state.effect()) else {
        return;
    };
    let Some(settled) = crate::api::gateway::settled_transaction_effect(
        state,
        principal_id,
        effect.approval_request_id(),
    ) else {
        return;
    };
    // The effect the journal points at must be the effect that was settled.
    if settled.request_sha256 != effect.request_sha256()
        || settled.effect_id != effect.effect_id()
        || !settled
            .outcome
            .transaction_hash
            .eq_ignore_ascii_case(terminal.transaction_hash())
        || settled.chain_namespace != listing.package.chain_namespace
        || settled.network != listing.package.network
    {
        return;
    }
    let creator_account = RuntimeCustodyCreatorAccount {
        account_id: effect.account_id().to_string(),
        address: effect.address().to_string(),
        external_signer: false,
        connector_id: None,
    };
    let acquisition_stage = crate::protected_content_runtime::RuntimeCustodyPurchaseStageRecord {
        stage: "mint".to_string(),
        effect_id: settled.effect_id.clone(),
        approval_request_id: settled.approval_request_id.clone(),
        request_sha256: settled.request_sha256.clone(),
        chain_namespace: settled.chain_namespace.clone(),
        network: settled.network.clone(),
        to: settled.to.clone(),
        value: settled.value.clone(),
        data: settled.data.clone(),
    };
    if owned.as_ref().is_some_and(|record| {
        record.listing_sha256 != listing.portable_package_digest()
            || record.account_id != creator_account.account_id
            || !record.address.eq_ignore_ascii_case(&creator_account.address)
            || record.acquisition_stage != acquisition_stage
            || !matches!(
                &record.progress,
                crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Complete { terminal }
                    if terminal.chain_transaction.eq_ignore_ascii_case(&settled.outcome.transaction_hash)
            )
    }) {
        return;
    }
    let content_access_id_hex = format!(
        "0x{}",
        hex::encode(mint.draft().content_access_id().as_bytes())
    );
    let Ok(Some(access)) = resolve_runtime_custody_purchase_access(
        state,
        &listing.package,
        &creator_account,
        &content_access_id_hex,
        &format!("minted-access:{}", settled.effect_id),
    )
    .await
    else {
        return;
    };
    let profile_did = match crate::protected_content_runtime::load_runtime_custody_profile_did(
        &state.data_dir,
        principal_id,
    ) {
        Ok(profile_did) => profile_did,
        Err(_) => return,
    };
    // Amend the asset in place while we are here: a copy minted before capsules
    // existed has no `.ddrm` anywhere, and restoring only the invisible record
    // would leave the Library still showing nothing.
    let capsule_uri = match state.provider_registry.as_ref() {
        Some(registry) => {
            write_runtime_custody_owned_capsule(
                state,
                registry.as_ref(),
                &listing.package,
                principal_id,
                crate::protected_content_runtime::RuntimeCustodyAcquisitionV1::Minted,
            )
            .await
        }
        None => None,
    };
    if let Some(owned) = owned {
        if let Some(capsule_uri) = capsule_uri {
            let _ = crate::protected_content_runtime::attach_runtime_custody_minted_capsule(
                &state.data_dir,
                &owned,
                capsule_uri,
            );
        }
        return;
    }
    let now = crate::auth::now_ts();
    let owned = crate::protected_content_runtime::RuntimeCustodyPurchaseRecord {
        attempt_id: None,
        schema: crate::protected_content_runtime::RUNTIME_PURCHASE_SCHEMA_V1.to_string(),
        principal_id: principal_id.to_string(),
        profile_did,
        mint_id: listing.package.mint_id.clone(),
        content_id: listing.package.content_id.clone(),
        cid: listing.package.content_cid.clone(),
        listing_sha256: listing.portable_package_digest(),
        seller_address: listing.package.seller_address.clone(),
        chain_namespace: listing.package.chain_namespace.clone(),
        network: listing.package.network.clone(),
        ledger: listing.package.ledger.clone(),
        token_id: listing.package.token_id.clone(),
        operative: listing.package.operative.clone(),
        price: listing.package.price.clone(),
        pay_token: listing.package.pay_token.clone(),
        payment_processor: listing.package.payment_processor.clone(),
        availability_receipt_digest: listing.availability.purchase_digest(),
        account_id: creator_account.account_id.clone(),
        address: creator_account.address.clone(),
        approval_stage: None,
        acquisition: crate::protected_content_runtime::RuntimeCustodyAcquisitionV1::Minted,
        capsule_uri,
        acquisition_stage,
        progress: crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Complete {
            terminal: crate::protected_content_runtime::RuntimeCustodyTerminalPurchaseRecord {
                chain_transaction: settled.outcome.transaction_hash.clone(),
                wallet_binding: settled.outcome.binding.clone(),
                chain_observation: settled.outcome.chain_observation.clone(),
                access_evidence: Some(access),
                confirmed_at: settled.outcome.confirmed_at,
                acquired_at: now,
            },
        },
        created_at: now,
        updated_at: now,
    };
    if let Ok(true) = crate::protected_content_runtime::create_runtime_custody_purchase_if_absent(
        &state.data_dir,
        &owned,
    ) {
        tracing::debug!("runtime custody: restored the owned copy of a minted asset");
    }
}

/// Record the copy the creator has owned since their mint landed.
///
/// A mint is not a purchase, but it ends somewhere identical: this principal
/// holds access to this content, and the chain is what says so. So the right is
/// established by the very question a buy asks -- `hasAccess` for the creator's
/// wallet, which is also how a subscription grants access, so asking it here
/// keeps one rule rather than inventing a second, weaker notion of ownership
/// that lives only on this disk.
///
/// The answer goes into the same store a purchase uses, which is what makes a
/// minted copy openable at all: below the entitlement check nothing
/// distinguishes the two, and `acquisition` records only which one happened.
///
/// Best effort by design. The mint has already settled on chain by the time
/// this runs, so a copy that cannot be recorded must not fail a mint that is
/// done -- the creator keeps their asset and their listing either way.
#[allow(
    clippy::too_many_arguments,
    reason = "an owned copy binds the listing, the wallet, the acquiring transaction and its confirmation"
)]
async fn record_runtime_custody_minted_owned_copy(
    state: &GatewayState,
    package: &crate::protected_content_runtime::RuntimePortableListingPackage,
    creator_account: &RuntimeCustodyCreatorAccount,
    principal_id: &str,
    content_access_id: &[u8],
    availability_receipt_digest: Option<String>,
    request: &RuntimeTransactionRequest,
    completion: RuntimeTransactionCompletion,
    mint_id: elastos_protected_content_contracts::Digest32,
    capsule_uri: Option<String>,
) {
    let step = crate::protected_content_runtime::RuntimeMintStep::begin(
        "owned_copy",
        &hex::encode(mint_id.as_bytes()),
    );
    let already_owned = crate::protected_content_runtime::load_runtime_custody_purchase(
        &state.data_dir,
        principal_id,
        mint_id,
    )
    .unwrap_or_default()
    .is_some();
    if already_owned {
        step.ok();
        return;
    }
    let (Some(confirmed), Some(availability_receipt_digest)) =
        (confirmed_stage(completion), availability_receipt_digest)
    else {
        step.pending();
        return;
    };
    let content_access_id_hex = format!("0x{}", hex::encode(content_access_id));
    let access = resolve_runtime_custody_purchase_access(
        state,
        package,
        creator_account,
        &content_access_id_hex,
        &format!("minted-access:{}", request.effect_id),
    )
    .await;
    let access = match access {
        Ok(Some(access)) => access,
        // The mint is on chain and the listing is recorded; the chain simply
        // has not answered yet, or answered no. Either way this is not a
        // failure of the mint.
        Ok(None) => {
            step.pending();
            return;
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "runtime custody creator tail: minted copy was not recorded"
            );
            return;
        }
    };
    let (Ok(profile_did), Ok(listing_sha256), Ok(acquisition_stage)) = (
        crate::protected_content_runtime::load_runtime_custody_profile_did(
            &state.data_dir,
            principal_id,
        ),
        runtime_custody_portable_package_digest(package),
        runtime_custody_purchase_stage_record("mint", request),
    ) else {
        tracing::warn!("runtime custody creator tail: minted copy was not recorded");
        return;
    };
    let now = crate::auth::now_ts();
    let owned = crate::protected_content_runtime::RuntimeCustodyPurchaseRecord {
        attempt_id: None,
        schema: crate::protected_content_runtime::RUNTIME_PURCHASE_SCHEMA_V1.to_string(),
        principal_id: principal_id.to_string(),
        profile_did,
        mint_id: package.mint_id.clone(),
        content_id: package.content_id.clone(),
        cid: package.content_cid.clone(),
        listing_sha256,
        seller_address: package.seller_address.clone(),
        chain_namespace: package.chain_namespace.clone(),
        network: package.network.clone(),
        ledger: package.ledger.clone(),
        token_id: package.token_id.clone(),
        operative: package.operative.clone(),
        price: package.price.clone(),
        pay_token: package.pay_token.clone(),
        payment_processor: package.payment_processor.clone(),
        availability_receipt_digest,
        account_id: creator_account.account_id.clone(),
        address: creator_account.address.clone(),
        approval_stage: None,
        acquisition: crate::protected_content_runtime::RuntimeCustodyAcquisitionV1::Minted,
        capsule_uri,
        acquisition_stage,
        progress: crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Complete {
            terminal: crate::protected_content_runtime::RuntimeCustodyTerminalPurchaseRecord {
                chain_transaction: confirmed.chain_transaction,
                wallet_binding: confirmed.wallet_binding,
                chain_observation: confirmed.chain_observation,
                access_evidence: Some(access),
                confirmed_at: confirmed.confirmed_at,
                acquired_at: now,
            },
        },
        created_at: now,
        updated_at: now,
    };
    match crate::protected_content_runtime::persist_runtime_custody_purchase(
        &state.data_dir,
        &owned,
    ) {
        Ok(()) => step.ok(),
        Err(error) => tracing::warn!(
            error = %error,
            "runtime custody creator tail: minted copy was not recorded"
        ),
    }
}

#[cfg(test)]
pub(crate) async fn runtime_custody_publish_creator_tail_for_test(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    registry: Arc<ProviderRegistry>,
    input: crate::protected_content_runtime::RuntimeCustodyLibraryPublishInput,
    facts: crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts,
) -> anyhow::Result<crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts> {
    runtime_custody_publish_creator_tail_from_facts(
        state,
        authority,
        registry,
        (&input).into(),
        facts,
    )
    .await
}

/// The creator mint's approval request for fixed inputs, as the Wallet sees
/// it: the full request binding (approval reason included), the request
/// SHA-256, the derived effect id and the approval request id.
#[cfg(test)]
pub(crate) fn runtime_custody_creator_approval_request_for_test(
    principal_id: &str,
    account_id: &str,
    address: &str,
    creator_state: &elastos_protected_content_runtime::RuntimeMintCreatorState,
    chain_plan: [&str; 7],
    mint_id: elastos_protected_content_contracts::Digest32,
) -> anyhow::Result<(serde_json::Value, String, String, String)> {
    let [network, chain_namespace, ledger, pay_token, to, data, value] = chain_plan;
    let request = runtime_custody_creator_transaction_request(
        principal_id,
        &RuntimeCustodyCreatorAccount {
            account_id: account_id.to_string(),
            address: address.to_string(),
            external_signer: false,
            connector_id: None,
        },
        creator_state,
        &RuntimeCustodyCreatorChainPlan {
            network: network.to_string(),
            chain_namespace: chain_namespace.to_string(),
            ledger: ledger.to_string(),
            pay_token: pay_token.to_string(),
            to: to.to_string(),
            data: data.to_string(),
            value: value.to_string(),
        },
        mint_id,
        creator_state.token_uri(),
    )?;
    let binding = runtime_custody_creator_effect_binding(&request)?;
    Ok((
        transaction_request_binding(&request),
        request.request_sha256.clone(),
        binding.effect_id().to_string(),
        binding.approval_request_id().to_string(),
    ))
}

/// Resume twin of [`runtime_custody_publish_creator_tail_for_test`]: the tail
/// runs from the mint's recorded terms, whatever `input` carries.
#[cfg(test)]
pub(crate) async fn runtime_custody_resume_creator_tail_for_test(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    registry: Arc<ProviderRegistry>,
    input: crate::protected_content_runtime::RuntimeCustodyLibraryPublishInput,
    facts: crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts,
) -> anyhow::Result<crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts> {
    let mut tail_input =
        crate::protected_content_runtime::RuntimeCustodyCreatorTailInput::from(&input);
    tail_input.terms_source =
        crate::protected_content_runtime::RuntimeCustodyCreatorTermsSource::Recorded;
    runtime_custody_publish_creator_tail_from_facts(state, authority, registry, tail_input, facts)
        .await
}

#[cfg(test)]
mod chain_has_not_seen_transaction_tests {
    use super::*;

    #[test]
    fn only_a_clean_not_yet_seen_answer_is_a_wait() {
        let connector = format!(
            "{CHAIN_HAS_NOT_SEEN_TRANSACTION}; Runtime never rebroadcasts connector transactions"
        );
        assert!(chain_has_not_seen_transaction(&(
            StatusCode::SERVICE_UNAVAILABLE,
            connector.clone()
        )));
        // A lookup that failed is not evidence of anything, and stays an error.
        assert!(!chain_has_not_seen_transaction(&(
            StatusCode::SERVICE_UNAVAILABLE,
            "Chain reconciliation was unavailable: transaction: timeout; Runtime never \
             rebroadcasts connector transactions"
                .to_string()
        )));
        assert!(!chain_has_not_seen_transaction(&(
            StatusCode::BAD_GATEWAY,
            connector
        )));
    }
}

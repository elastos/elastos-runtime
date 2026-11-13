//! The Custody app's routes: admin-only HTTP adapters over
//! `custody_pool_setup`, `custody_consent` and `custody_owner_requests`,
//! which own every rule and every file. The Inbox's custody request actions
//! are adapted here too, so every custody write shares one lock.
//!
//! A refusal answers `{code, detail}`: the app shows its own words for the
//! code and may show the Runtime's reason from `detail`. Any other failure is
//! logged and answered generically.

use axum::extract::rejection::JsonRejection;

use super::*;
use crate::custody_consent::{self, NodeConsentHandler, NodeHost, NodeTicket};
use crate::custody_owner_requests::{self, AcceptedContact, OwnerHost, ProfileOfferQuery};
use crate::custody_pool_notices::{self, NoticeHost};
use crate::custody_pool_setup::{self, CardInput, CustodyRefusal, FetchedCard, POOL_TERM_DAYS};

use crate::custody_surface::{
    STEP_UP_KNOWN_POOL_ADD as KNOWN_POOL_ADD_OPERATION,
    STEP_UP_LOCAL_NODE_INCLUDE as INCLUDE_LOCAL_NODE_OPERATION,
    STEP_UP_LOCAL_NODE_REMOVE as REMOVE_LOCAL_NODE_OPERATION,
    STEP_UP_MESSAGES_ENABLE as MESSAGES_ENABLE_OPERATION,
    STEP_UP_POOL_INSTALL as INSTALL_POOL_OPERATION,
    STEP_UP_SERVED_POOL_CONFIRM_PUBLISHER as SERVED_POOL_CONFIRM_PUBLISHER_OPERATION,
    STEP_UP_SERVED_POOL_REMOVE as SERVED_POOL_REMOVE_OPERATION,
};
const STEP_UP_MAX_AGE_SECS: u64 = 180;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CustodyCardReadRequest {
    card: String,
}

/// `address` is the node's Carrier connect ticket.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CustodyCardFetchRequest {
    address: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CustodyCheckRequest {
    slots: Vec<CustodySlot>,
}

/// The step-up request of Include this Home; the body adds `step_up_token`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyLocalNodeRequest {
    run_by: String,
    location: String,
}

/// The step-up request of Remove for this Home's node; the body adds
/// `step_up_token`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyLocalNodeRemoveRequest {}

/// The step-up request of Enable custody messages; the body adds
/// `step_up_token`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyMessagesEnableRequest {}

/// The Hosting switch.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CustodyOfferRequest {
    enabled: bool,
    run_by: String,
    location: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CustodyNodesFindRequest {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CustodyPoolNotifyRequest {}

/// Ask a contact to be a custody node for `term_days`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CustodyNodeRequestSendRequest {
    profile_did: String,
    term_days: u64,
}

/// The step-up request of Install; the body adds `step_up_token`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyInstallRequest {
    slots: Vec<CustodySlot>,
    term_days: u64,
}

/// `{"card": "<text>"}` or `{"this_home": true}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodySlot {
    card: Option<String>,
    this_home: Option<bool>,
}

fn custody_refusal_response(code: &str, detail: Option<&str>) -> Response {
    let status = match code {
        "bad_request" | "bad_slot" | "bad_term" | "bad_labels" | "bad_address" | "bad_pool" => {
            StatusCode::BAD_REQUEST
        }
        "protected_content_off"
        | "no_pool"
        | "no_local_node"
        | "unknown_share"
        | "unknown_pool"
        | "unknown_request" => StatusCode::NOT_FOUND,
        _ => StatusCode::CONFLICT,
    };
    (
        status,
        Json(serde_json::json!({ "code": code, "detail": detail })),
    )
        .into_response()
}

pub(super) fn custody_error_response(error: anyhow::Error) -> Response {
    match error.downcast_ref::<CustodyRefusal>() {
        Some(refusal) => custody_refusal_response(refusal.code(), refusal.detail()),
        None => {
            tracing::warn!(error = %format!("{error:#}"), "custody request failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "custody request failed").into_response()
        }
    }
}

fn custody_bad_request(rejection: impl std::fmt::Display) -> Response {
    tracing::debug!(%rejection, "custody request refused");
    custody_refusal_response("bad_request", None)
}

/// The Custody launch token of an admin passkey, on a Home with protected
/// content on.
fn require_custody_admin(
    state: &GatewayState,
    headers: &HeaderMap,
) -> Result<RequiredHomeLaunchToken, Box<Response>> {
    let refused = |error: anyhow::Error| Box::new(system_error_response(error));
    let launch = require_home_launch_token_binding(&state.data_dir, headers, &[CUSTODY_CAPSULE_ID])
        .map_err(refused)?;
    let Some(proof_binding_id) = launch.context.proof_binding_id.as_deref() else {
        return Err(refused(anyhow::anyhow!("admin passkey required")));
    };
    let principal =
        crate::auth::load_principal_for_proof_binding(&state.data_dir, proof_binding_id)
            .map_err(refused)?;
    crate::auth::ensure_proof_binding_not_revoked(&principal).map_err(refused)?;
    if !crate::auth::is_admin(&principal) {
        return Err(refused(anyhow::anyhow!("admin passkey required")));
    }
    if !crate::protected_content_runtime::protected_content_enabled(&state.data_dir) {
        return Err(Box::new(custody_refusal_response(
            "protected_content_off",
            None,
        )));
    }
    Ok(launch)
}

/// Split a step-up body into its token and the exact request the passkey
/// approved, so the app hands Home's prompt the same object minus the token.
fn split_step_up_body<T: serde::de::DeserializeOwned>(
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<(T, serde_json::Value, String), Box<Response>> {
    let refused = |rejection: &dyn std::fmt::Display| Box::new(custody_bad_request(rejection));
    let Json(mut request) = body.map_err(|rejection| refused(&rejection))?;
    let Some(object) = request.as_object_mut() else {
        return Err(refused(&"body is not a JSON object"));
    };
    let token = match object.remove("step_up_token") {
        None => String::new(),
        Some(serde_json::Value::String(token)) => token,
        Some(_) => return Err(refused(&"step_up_token is not a string")),
    };
    let input = serde_json::from_value(request.clone()).map_err(|error| refused(&error))?;
    Ok((input, request, token))
}

fn card_inputs(slots: Vec<CustodySlot>) -> Result<Vec<CardInput>, Box<Response>> {
    slots
        .into_iter()
        .map(|slot| match slot {
            CustodySlot {
                card: Some(text),
                this_home: None,
            } => Ok(CardInput::Remote { text }),
            CustodySlot {
                card: None,
                this_home: Some(true),
            } => Ok(CardInput::ThisHome),
            _ => Err(Box::new(custody_refusal_response("bad_slot", None))),
        })
        .collect()
}

pub(super) async fn custody_summary(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    let launch = match require_custody_admin(&state, &headers) {
        Ok(launch) => launch,
        Err(response) => return *response,
    };
    Json(
        custody_pool_setup::summary(
            &state.data_dir,
            state.provider_registry.as_ref(),
            state.carrier_endpoint.as_ref(),
            Some(&launch.context.principal_id),
        )
        .await,
    )
    .into_response()
}

/// Plan B T2.3: the pools this Home serves, one item per pool. The owner's
/// People name comes from the admin's accepted contacts, else its DID.
pub(super) async fn custody_served_pools_read(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    let launch = match require_custody_admin(&state, &headers) {
        Ok(launch) => launch,
        Err(response) => return *response,
    };
    let names: std::collections::BTreeMap<String, String> =
        super::gateway_home_system::load_profile_authority_for_context(
            &state.data_dir,
            &launch.context,
        )
        .ok()
        .flatten()
        .and_then(|profile| custody_contacts(&state, &launch.context, &profile).ok())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|contact| {
            let home = contact.profile.sole_endpoint_did().ok()?.to_string();
            Some((home, contact.name))
        })
        .collect();
    let name_of = |owner: &str| names.get(owner).cloned();
    match custody_pool_setup::served_pool_items(
        &state.data_dir,
        state.provider_registry.as_ref(),
        &name_of,
        now_ts(),
    )
    .await
    {
        Ok(items) => Json(items).into_response(),
        Err(error) => custody_error_response(error),
    }
}

/// `{"pool": "<64 hex>"}`, the path's pool again, so the passkey approves
/// exactly that pool.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CustodyServedPoolRemoveRequest {
    pool: String,
}

/// Plan B T2.3: Stop serving one pool. Admin and the passkey step-up are
/// checked before the write lock; a pool this Home does not serve is refused
/// before the approval is spent.
pub(super) async fn custody_served_pool_remove(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Path(pool): Path<String>,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let launch = match require_custody_admin(&state, &headers) {
        Ok(launch) => launch,
        Err(response) => return *response,
    };
    let (CustodyServedPoolRemoveRequest { pool: named }, request, step_up_token) =
        match split_step_up_body::<CustodyServedPoolRemoveRequest>(body) {
            Ok(parts) => parts,
            Err(response) => return *response,
        };
    if named != pool {
        return custody_refusal_response("bad_pool", Some("the body names another pool"));
    }
    if let Err(error) = custody_pool_setup::served_pool_stoppable(&state.data_dir, &pool) {
        return custody_error_response(error);
    }
    if let Err(error) = consume_passkey_step_up_token(
        &state.data_dir,
        &step_up_token,
        &launch,
        STEP_UP_MAX_AGE_SECS,
        SERVED_POOL_REMOVE_OPERATION,
        &request,
    ) {
        return system_error_response(error);
    }
    let write = custody_consent::lock_custody_writes().await;
    match custody_pool_setup::stop_serving_pool(
        &write,
        &state.data_dir,
        state.provider_registry.as_ref(),
        &pool,
        now_ts(),
    )
    .await
    {
        Ok(()) => Json(serde_json::json!({ "stopped": true })).into_response(),
        Err(error) => custody_error_response(error),
    }
}

/// Plan B T2.3 (S2-A3, S2-R3-F1): Confirm publisher. Admin, the body pool
/// equal to the path, a pool this Home serves or its own pool, and the
/// passkey step-up for exactly that `{pool}` are checked before the write
/// lock; then the calling admin profile is kept for that pool alone.
pub(super) async fn custody_served_pool_confirm_publisher(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Path(pool): Path<String>,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let launch = match require_custody_admin(&state, &headers) {
        Ok(launch) => launch,
        Err(response) => return *response,
    };
    let (CustodyServedPoolRemoveRequest { pool: named }, request, step_up_token) =
        match split_step_up_body::<CustodyServedPoolRemoveRequest>(body) {
            Ok(parts) => parts,
            Err(response) => return *response,
        };
    if named != pool {
        return custody_refusal_response("bad_pool", Some("the body names another pool"));
    }
    if let Err(error) = custody_pool_setup::publisher_target(&state.data_dir, &pool) {
        return custody_error_response(error);
    }
    let profile_did = match custody_admin_profile(&state.data_dir, &launch.context) {
        Ok(profile) => profile.document().profile_did.clone(),
        Err(error) => return custody_error_response(error),
    };
    if let Err(error) = consume_passkey_step_up_token(
        &state.data_dir,
        &step_up_token,
        &launch,
        STEP_UP_MAX_AGE_SECS,
        SERVED_POOL_CONFIRM_PUBLISHER_OPERATION,
        &request,
    ) {
        return system_error_response(error);
    }
    let write = custody_consent::lock_custody_writes().await;
    match custody_pool_setup::confirm_publisher(&write, &state.data_dir, &pool, &profile_did) {
        Ok(()) => Json(serde_json::json!({ "publisher_confirmed": true })).into_response(),
        Err(error) => custody_error_response(error),
    }
}

pub(super) async fn custody_signing_key_create(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_custody_admin(&state, &headers) {
        return *response;
    }
    let _write = custody_consent::lock_custody_writes().await;
    match custody_pool_setup::create_signing_key(&state.data_dir) {
        Ok(fingerprint) => Json(serde_json::json!({
            "fingerprint": fingerprint.short,
            "fingerprint_full": fingerprint.full,
        }))
        .into_response(),
        Err(error) => custody_error_response(error),
    }
}

pub(super) async fn custody_node_card_read(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Result<Json<CustodyCardReadRequest>, JsonRejection>,
) -> Response {
    if let Err(response) = require_custody_admin(&state, &headers) {
        return *response;
    }
    let Json(input) = match body {
        Ok(body) => body,
        Err(rejection) => return custody_bad_request(rejection),
    };
    Json(custody_pool_setup::read_card(&state.data_dir, &input.card)).into_response()
}

/// Fetch a node card from its node over Carrier. It writes nothing, so it
/// needs no step-up and does not wait for the custody write lock.
pub(super) async fn custody_node_card_fetch(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Result<Json<CustodyCardFetchRequest>, JsonRejection>,
) -> Response {
    if let Err(response) = require_custody_admin(&state, &headers) {
        return *response;
    }
    let Json(input) = match body {
        Ok(body) => body,
        Err(rejection) => return custody_bad_request(rejection),
    };
    match custody_pool_setup::fetch_card(&state.data_dir, &input.address).await {
        FetchedCard::Card { card, view } => {
            Json(serde_json::json!({ "card": card, "view": view })).into_response()
        }
        FetchedCard::Refused { refused, detail } => {
            custody_refusal_response(refused, detail.as_deref())
        }
    }
}

pub(super) async fn custody_local_node_include(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let launch = match require_custody_admin(&state, &headers) {
        Ok(launch) => launch,
        Err(response) => return *response,
    };
    let (input, request, step_up_token) = match split_step_up_body::<CustodyLocalNodeRequest>(body)
    {
        Ok(parts) => parts,
        Err(response) => return *response,
    };
    if let Err(error) = consume_passkey_step_up_token(
        &state.data_dir,
        &step_up_token,
        &launch,
        STEP_UP_MAX_AGE_SECS,
        INCLUDE_LOCAL_NODE_OPERATION,
        &request,
    ) {
        return system_error_response(error);
    }
    let write = custody_consent::lock_custody_writes().await;
    match custody_pool_setup::include_local_node(
        &write,
        &state.data_dir,
        state.provider_registry.as_ref(),
        &input.run_by,
        &input.location,
    )
    .await
    {
        Ok(node) => {
            // S2-A3 (Plan B T2.2): the admin profile that included this
            // Home's own root; until it is kept, the root publishes no sealed
            // package and Hosting asks to confirm it.
            let recorded =
                custody_admin_profile(&state.data_dir, &launch.context).and_then(|profile| {
                    custody_consent::record_own_root_admin_profile(
                        &write,
                        &state.data_dir,
                        &profile.document().profile_did,
                    )
                });
            if let Err(error) = recorded {
                tracing::warn!(
                    error = %format!("{error:#}"),
                    "the including admin profile was not kept; Hosting asks to confirm it"
                );
            }
            Json(node).into_response()
        }
        Err(error) => custody_error_response(error),
    }
}

/// Remove for this Home's node before install. A removal Runtime refuses is
/// refused before the passkey approval is spent.
pub(super) async fn custody_local_node_remove(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let launch = match require_custody_admin(&state, &headers) {
        Ok(launch) => launch,
        Err(response) => return *response,
    };
    let (CustodyLocalNodeRemoveRequest {}, request, step_up_token) =
        match split_step_up_body::<CustodyLocalNodeRemoveRequest>(body) {
            Ok(parts) => parts,
            Err(response) => return *response,
        };
    if let Err(error) = custody_pool_setup::local_node_removable(&state.data_dir) {
        // Nothing to remove may still mean a tombstone a stopped removal
        // left: delete it, with no passkey approval spent.
        if error
            .downcast_ref::<CustodyRefusal>()
            .is_some_and(|refusal| refusal.code() == "no_local_node")
        {
            let write = custody_consent::lock_custody_writes().await;
            if let Err(error) =
                custody_pool_setup::finish_local_node_removal(&write, &state.data_dir)
            {
                tracing::debug!(error = %format!("{error:#}"), "a removed custody root stays");
            }
        }
        return custody_error_response(error);
    }
    if let Err(error) = consume_passkey_step_up_token(
        &state.data_dir,
        &step_up_token,
        &launch,
        STEP_UP_MAX_AGE_SECS,
        REMOVE_LOCAL_NODE_OPERATION,
        &request,
    ) {
        return system_error_response(error);
    }
    let write = custody_consent::lock_custody_writes().await;
    match custody_pool_setup::remove_local_node(
        &write,
        &state.data_dir,
        state.provider_registry.as_ref(),
    )
    .await
    {
        Ok(node) => Json(node).into_response(),
        Err(error) => custody_error_response(error),
    }
}

pub(super) async fn custody_pool_check(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Result<Json<CustodyCheckRequest>, JsonRejection>,
) -> Response {
    if let Err(response) = require_custody_admin(&state, &headers) {
        return *response;
    }
    let Json(input) = match body {
        Ok(body) => body,
        Err(rejection) => return custody_bad_request(rejection),
    };
    let cards = match card_inputs(input.slots) {
        Ok(cards) => cards,
        Err(response) => return *response,
    };
    let checks = custody_pool_setup::check(&state.data_dir, &cards);
    Json(serde_json::json!({ "checks": checks })).into_response()
}

pub(super) async fn custody_pool_install(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let launch = match require_custody_admin(&state, &headers) {
        Ok(launch) => launch,
        Err(response) => return *response,
    };
    let (input, request, step_up_token) = match split_step_up_body::<CustodyInstallRequest>(body) {
        Ok(parts) => parts,
        Err(response) => return *response,
    };
    // Refused before the step-up, so a bad form never spends a passkey approval.
    let Some(term_days) = u16::try_from(input.term_days)
        .ok()
        .filter(|days| POOL_TERM_DAYS.contains(days))
    else {
        return custody_refusal_response("bad_term", None);
    };
    let cards = match card_inputs(input.slots) {
        Ok(cards) => cards,
        Err(response) => return *response,
    };
    // Likewise a second pool or a missing key; `install` checks both again.
    if let Err(error) = custody_pool_setup::ensure_installable(&state.data_dir) {
        return custody_error_response(error);
    }
    // A node that approved a request consented to that request's term.
    if let Err(error) =
        custody_owner_requests::check_install_term(&state.data_dir, &cards, term_days)
    {
        return custody_error_response(error);
    }
    if let Err(error) = consume_passkey_step_up_token(
        &state.data_dir,
        &step_up_token,
        &launch,
        STEP_UP_MAX_AGE_SECS,
        INSTALL_POOL_OPERATION,
        &request,
    ) {
        return system_error_response(error);
    }
    let write = custody_consent::lock_custody_writes().await;
    match custody_pool_setup::install(&state.data_dir, &cards, term_days).await {
        Ok(installed) => {
            record_pool_notices(&state, &launch.context);
            drop(write);
            if let Ok(messages) = custody_messages(&state) {
                deliver_decisions_soon(messages);
            }
            Json(installed).into_response()
        }
        Err(error) => custody_error_response(error),
    }
}

/// After an install: which members this Home tells they are in the pool,
/// queued for the next delivery pass. The pool is installed whatever happens
/// here; Notify members again records the set when this could not.
fn record_pool_notices(state: &GatewayState, context: &HomeLaunchTokenContext) {
    let recorded = custody_admin_profile(&state.data_dir, context).and_then(|profile| {
        let contacts = custody_contacts(state, context, &profile).unwrap_or_else(|error| {
            tracing::debug!(error = %format!("{error:#}"), "custody contacts are unavailable");
            Vec::new()
        });
        custody_pool_notices::record_install(&state.data_dir, &profile, &contacts)
    });
    if let Err(error) = recorded {
        tracing::warn!(error = %format!("{error:#}"), "custody pool notices were not recorded");
        return;
    }
    if let Ok(messages) = custody_messages(state) {
        if let Err(error) =
            custody_pool_notices::resume_notices(&state.data_dir, &messages, now_ts())
        {
            tracing::debug!(error = %format!("{error:#}"), "custody pool notices stay unqueued");
        }
    }
}

/// Notify members again: every member not yet told, or refused, is tried
/// again now.
pub(super) async fn custody_pool_notify(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Result<Json<CustodyPoolNotifyRequest>, JsonRejection>,
) -> Response {
    let launch = match require_custody_admin(&state, &headers) {
        Ok(launch) => launch,
        Err(response) => return *response,
    };
    if let Err(rejection) = body {
        return custody_bad_request(rejection);
    }
    match notify_pool_members(&state, &launch.context).await {
        Ok(notices) => Json(notices).into_response(),
        Err(error) => custody_error_response(error),
    }
}

async fn notify_pool_members(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
) -> anyhow::Result<custody_pool_notices::PoolNoticesView> {
    if !custody_pool_setup::pool_installed(&state.data_dir)? {
        return Err(CustodyRefusal::new("no_pool").into());
    }
    let profile = custody_admin_profile(&state.data_dir, context)?;
    let messages = custody_messages(state)?;
    let contacts = custody_contacts(state, context, &profile)?;
    let host = NoticeHost {
        data_dir: &state.data_dir,
        outbox: &messages,
        profile: &profile,
        contacts: &contacts,
    };
    let write = custody_consent::lock_custody_writes().await;
    custody_pool_notices::notify_members(write, &host, now_ts()).await
}

pub(super) async fn custody_pool_verify(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_custody_admin(&state, &headers) {
        return *response;
    }
    match custody_pool_setup::verify(&state.data_dir) {
        Ok(verified) => Json(verified).into_response(),
        Err(error) => custody_error_response(error),
    }
}

pub(super) async fn custody_pool_read(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_custody_admin(&state, &headers) {
        return *response;
    }
    match custody_pool_setup::read_pool(&state.data_dir) {
        Ok(Some(pool)) => Json(pool).into_response(),
        Ok(None) => custody_refusal_response("no_pool", None),
        Err(error) => custody_error_response(error),
    }
}

/// Probe every pool member over Carrier. It writes nothing, so it does not
/// wait for the custody write lock.
pub(super) async fn custody_pool_health(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_custody_admin(&state, &headers) {
        return *response;
    }
    match custody_pool_setup::pool_health(&state.data_dir, state.provider_registry.as_ref()).await {
        Ok(Some(health)) => Json(health).into_response(),
        Ok(None) => custody_refusal_response("no_pool", None),
        Err(error) => custody_error_response(error),
    }
}

pub(super) async fn custody_member_register(
    State(state): State<GatewayState>,
    Path(share): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_custody_admin(&state, &headers) {
        return *response;
    }
    // A share that is not a number names no member either.
    let Ok(share) = share.parse::<u8>() else {
        return custody_refusal_response("unknown_share", None);
    };
    let _write = custody_consent::lock_custody_writes().await;
    match custody_pool_setup::register_member(&state.data_dir, share) {
        Ok(()) => Json(serde_json::json!({ "share": share, "registered": true })).into_response(),
        Err(error) => custody_error_response(error),
    }
}

/// The admin's Profile, which custody requests are addressed to.
fn custody_admin_profile(
    data_dir: &std::path::Path,
    context: &HomeLaunchTokenContext,
) -> anyhow::Result<crate::collaboration_profile_authority::VerifiedCollaborationProfileDocument> {
    super::gateway_home_system::load_profile_authority_for_context(data_dir, context)?
        .ok_or_else(|| CustodyRefusal::new("no_profile").into())
}

/// Which contacts offer custody. It writes nothing, so it does not wait for
/// the custody write lock.
pub(super) async fn custody_nodes_find(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Result<Json<CustodyNodesFindRequest>, JsonRejection>,
) -> Response {
    let launch = match require_custody_admin(&state, &headers) {
        Ok(launch) => launch,
        Err(response) => return *response,
    };
    if let Err(rejection) = body {
        return custody_bad_request(rejection);
    }
    match find_custody_nodes(&state, &launch.context).await {
        Ok(contacts) => Json(serde_json::json!({ "contacts": contacts })).into_response(),
        Err(error) => custody_error_response(error),
    }
}

async fn find_custody_nodes(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
) -> anyhow::Result<Vec<custody_owner_requests::FoundContact>> {
    let profile = custody_admin_profile(&state.data_dir, context)?;
    let messages = custody_messages(state)?;
    let contacts = custody_contacts(state, context, &profile)?;
    let offers = ProfileOfferQuery {
        service: &messages,
        local_profile_did: &profile.document().profile_did,
    };
    custody_owner_requests::find_nodes(&state.data_dir, &profile, &contacts, &offers, now_ts())
        .await
}

/// Send a contact a request to be a custody node. It grants nothing, so it
/// needs no step-up: the node's admin approves with a passkey.
pub(super) async fn custody_node_request_send(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Result<Json<CustodyNodeRequestSendRequest>, JsonRejection>,
) -> Response {
    let launch = match require_custody_admin(&state, &headers) {
        Ok(launch) => launch,
        Err(response) => return *response,
    };
    let Json(input) = match body {
        Ok(body) => body,
        Err(rejection) => return custody_bad_request(rejection),
    };
    match send_custody_node_request(&state, &launch.context, &input).await {
        Ok(request) => Json(request).into_response(),
        Err(error) => custody_error_response(error),
    }
}

async fn send_custody_node_request(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    input: &CustodyNodeRequestSendRequest,
) -> anyhow::Result<custody_owner_requests::NodeRequestOutView> {
    let profile = custody_admin_profile(&state.data_dir, context)?;
    let messages = custody_messages(state)?;
    let contacts = custody_contacts(state, context, &profile)?;
    let host = OwnerHost {
        data_dir: &state.data_dir,
        outbox: &messages,
        profile: &profile,
        contacts: &contacts,
    };
    let write = custody_consent::lock_custody_writes().await;
    custody_owner_requests::send_request(
        write,
        &host,
        &input.profile_did,
        input.term_days,
        now_ts(),
    )
    .await
}

/// The admin's accepted contacts, each with its signed Profile.
fn custody_contacts(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    profile: &crate::collaboration_profile_authority::VerifiedCollaborationProfileDocument,
) -> anyhow::Result<Vec<AcceptedContact>> {
    let discovery = state
        .collaboration_discovery_service
        .as_ref()
        .ok_or_else(|| CustodyRefusal::new("messages_unavailable"))?;
    let authority = super::gateway_home_system::configured_contact_authority_from_profile(
        &state.data_dir,
        context,
        discovery,
        profile.clone(),
    )?;
    custody_owner_requests::accepted_contacts(&authority.store)
}

pub(super) async fn custody_offer_read(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    let launch = match require_custody_admin(&state, &headers) {
        Ok(launch) => launch,
        Err(response) => return *response,
    };
    let profile = super::gateway_home_system::load_profile_authority_for_context(
        &state.data_dir,
        &launch.context,
    )
    .inspect_err(
        |error| tracing::debug!(error = %format!("{error:#}"), "admin Profile is unreadable"),
    )
    .ok()
    .flatten();
    match custody_consent::read_offer(&state.data_dir, profile.as_ref()) {
        Ok(offer) => Json(offer).into_response(),
        Err(error) => custody_error_response(error),
    }
}

/// Turn the offer on or off. Offering signs nothing and serves nobody until
/// the admin approves a request in Inbox, so it needs no step-up.
pub(super) async fn custody_offer_set(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Result<Json<CustodyOfferRequest>, JsonRejection>,
) -> Response {
    let launch = match require_custody_admin(&state, &headers) {
        Ok(launch) => launch,
        Err(response) => return *response,
    };
    let Json(input) = match body {
        Ok(body) => body,
        Err(rejection) => return custody_bad_request(rejection),
    };
    let profile = super::gateway_home_system::load_profile_authority_for_context(
        &state.data_dir,
        &launch.context,
    )
    .inspect_err(
        |error| tracing::debug!(error = %format!("{error:#}"), "admin Profile is unreadable"),
    )
    .ok()
    .flatten();
    let write = custody_consent::lock_custody_writes().await;
    match custody_consent::set_offer(
        &write,
        &state.data_dir,
        profile.as_ref(),
        input.enabled,
        &input.run_by,
        &input.location,
    ) {
        Ok(offer) => Json(offer).into_response(),
        Err(error) => custody_error_response(error),
    }
}

/// The step-up request of Add a pool; the body adds `step_up_token`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyKnownPoolAddRequest {
    address: String,
}

/// Plan B T4.3: the pools this Home uses to buy and play.
pub(super) async fn custody_known_pools_read(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_custody_admin(&state, &headers) {
        return *response;
    }
    match crate::custody_pool_resolver::known_pools(&state.data_dir) {
        Ok(pools) => Json(serde_json::json!({ "pools": pools })).into_response(),
        Err(error) => custody_error_response(error),
    }
}

/// Plan B T4.3: Add a pool by its address. The admin and the passkey step-up
/// are checked before the write lock, as for Install; the address is read
/// first, so a bad one spends no approval.
pub(super) async fn custody_known_pool_add(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let launch = match require_custody_admin(&state, &headers) {
        Ok(launch) => launch,
        Err(response) => return *response,
    };
    let (input, request, step_up_token) =
        match split_step_up_body::<CustodyKnownPoolAddRequest>(body) {
            Ok(parts) => parts,
            Err(response) => return *response,
        };
    if let Err(error) = crate::custody_pool_descriptor::parse_pool_address(input.address.trim()) {
        return custody_error_response(CustodyRefusal::from_error("bad_address", &error).into());
    }
    if let Err(error) = consume_passkey_step_up_token(
        &state.data_dir,
        &step_up_token,
        &launch,
        STEP_UP_MAX_AGE_SECS,
        KNOWN_POOL_ADD_OPERATION,
        &request,
    ) {
        return system_error_response(error);
    }
    let Some(registry) = state.provider_registry.clone() else {
        return custody_refusal_response("pool_unreachable", None);
    };
    let write = custody_consent::lock_custody_writes().await;
    match crate::custody_pool_resolver::add_known_pool(
        &write,
        &state.data_dir,
        registry,
        &input.address,
        now_ts(),
    )
    .await
    {
        Ok(pool) => Json(serde_json::json!({ "pool": pool })).into_response(),
        Err(error) => custody_error_response(error),
    }
}

/// Enable custody messages: a new passkey-bound Profile revision lets this
/// Home's endpoint sign custody messages.
pub(super) async fn custody_messages_enable(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let launch = match require_custody_admin(&state, &headers) {
        Ok(launch) => launch,
        Err(response) => return *response,
    };
    let (CustodyMessagesEnableRequest {}, request, step_up_token) =
        match split_step_up_body::<CustodyMessagesEnableRequest>(body) {
            Ok(parts) => parts,
            Err(response) => return *response,
        };
    let context = &launch.context;
    // Refused before the step-up, so a Home without a Profile spends no
    // passkey approval.
    if let Err(error) = custody_admin_profile(&state.data_dir, context) {
        return custody_error_response(error);
    }
    if let Err(error) = consume_passkey_step_up_token(
        &state.data_dir,
        &step_up_token,
        &launch,
        STEP_UP_MAX_AGE_SECS,
        MESSAGES_ENABLE_OPERATION,
        &request,
    ) {
        return system_error_response(error);
    }
    let Some(proof_binding_id) = context.proof_binding_id.as_deref() else {
        return system_error_response(anyhow::anyhow!("admin passkey required"));
    };
    if let Err(error) = crate::collaboration_custody_messages::ensure_custody_signing_scope(
        &state.data_dir,
        &super::gateway_home_system::home_browser_principal_id(context),
        &super::gateway_home_system::home_browser_localhost_root(context),
        proof_binding_id,
        now_ts(),
    ) {
        return custody_error_response(error);
    }
    super::gateway_home_system::refresh_runtime_owned_contexts_after_profile_change(
        &state.data_dir,
        state.collaboration_discovery_service.as_ref(),
    );
    Json(serde_json::json!({ "messages_enabled": true })).into_response()
}

/// Inbox Approve: the admin's passkey approves exactly the request this Home
/// recorded, then this Home becomes that owner's custody node.
pub(super) async fn approve_custody_request(
    state: &GatewayState,
    launch: &RequiredHomeLaunchToken,
    request_id: &str,
    step_up_token: Option<&str>,
    step_up_request: Option<&serde_json::Value>,
) -> anyhow::Result<String> {
    let data_dir = &state.data_dir;
    let context = &launch.context;
    ensure_admin_context(data_dir, context)?;
    // Approving sets up a custody node, which needs protected content on.
    // Declining needs nothing and stays possible.
    if !crate::protected_content_runtime::protected_content_enabled(data_dir) {
        return Err(CustodyRefusal::new("protected_content_off").into());
    }
    let Some(step_up_token) = step_up_token else {
        anyhow::bail!("fresh passkey verification is required to approve a custody request");
    };
    let profile_did = custody_admin_profile(data_dir, context)?
        .document()
        .profile_did
        .clone();
    // Rebuilt from this Home's record. What the admin was shown must be what
    // it records, checked before the passkey approval is spent.
    let expected = custody_consent::approval_request(data_dir, &profile_did, request_id, now_ts())?
        .step_up_request();
    if step_up_request != Some(&expected) {
        return Err(CustodyRefusal::new("changed").into());
    }
    let messages = custody_messages(state)?;
    let host = NodeHost {
        data_dir,
        registry: state.provider_registry.as_ref(),
        outbox: &messages,
        ticket: state
            .carrier_endpoint
            .as_ref()
            .map(crate::carrier::carrier_connect_ticket),
    };
    // A Home that could not answer refuses before the approval is spent.
    custody_consent::check_approval(&host, &profile_did, request_id, now_ts())?;
    consume_passkey_step_up_token(
        data_dir,
        step_up_token,
        launch,
        STEP_UP_MAX_AGE_SECS,
        custody_consent::APPROVE_STEP_UP_OPERATION,
        &expected,
    )?;
    let write = custody_consent::lock_custody_writes().await;
    let approved =
        custody_consent::approve(&write, &host, &profile_did, request_id, now_ts()).await?;
    drop(write);
    deliver_decisions_soon(messages);
    Ok(if approved.needs_restart {
        format!(
            "Approved. Restart this Home to start serving {} as a custody node.",
            approved.owner_name
        )
    } else {
        format!(
            "Approved. This Home is now a custody node for {}.",
            approved.owner_name
        )
    })
}

/// Inbox Decline; it changes nothing on this Home, so it needs no step-up.
pub(super) async fn decline_custody_request(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    request_id: &str,
) -> anyhow::Result<String> {
    let data_dir = &state.data_dir;
    ensure_admin_context(data_dir, context)?;
    let profile_did = custody_admin_profile(data_dir, context)?
        .document()
        .profile_did
        .clone();
    let messages = custody_messages(state)?;
    let write = custody_consent::lock_custody_writes().await;
    custody_consent::decline(
        &write,
        data_dir,
        &messages,
        &profile_did,
        request_id,
        now_ts(),
    )?;
    drop(write);
    deliver_decisions_soon(messages);
    Ok("Declined the custody request.".to_string())
}

fn custody_messages(
    state: &GatewayState,
) -> anyhow::Result<crate::collaboration_custody_messages::CollaborationCustodyMessageService> {
    state
        .collaboration_discovery_service
        .as_ref()
        .map(|discovery| discovery.custody_message_service())
        .ok_or_else(|| CustodyRefusal::new("messages_unavailable").into())
}

/// Sends freshly queued custody messages now rather than on the next sync
/// pass, without holding the answer on a Carrier dial.
fn deliver_decisions_soon(
    messages: crate::collaboration_custody_messages::CollaborationCustodyMessageService,
) {
    tokio::spawn(async move {
        if let Err(error) = messages.deliver_pending(now_ts()).await {
            tracing::debug!(error = %format!("{error:#}"), "custody decision stays queued");
        }
    });
}

/// The custody requests waiting for this admin, for Home and Inbox. Nobody
/// else sees them, and an unreadable record shows nothing rather than
/// failing the read.
pub(super) fn append_custody_request_notifications(
    data_dir: &std::path::Path,
    context: &HomeLaunchTokenContext,
    notifications: &mut HomeNotificationsSummary,
) {
    if ensure_admin_context(data_dir, context).is_err() {
        return;
    }
    let Ok(profile) = custody_admin_profile(data_dir, context) else {
        return;
    };
    let pending = match custody_consent::inbox_requests(
        data_dir,
        &profile.document().profile_did,
        now_ts(),
    ) {
        Ok(pending) => pending,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "custody requests are unreadable");
            return;
        }
    };
    let pending = pending
        .into_iter()
        .map(
            |waiting| crate::notifications::PendingCustodyRequestNotification {
                step_up_request: waiting.request.step_up_request(),
                request_id: waiting.request.request_id,
                owner_name: waiting.request.owner_name,
                term_days: waiting.request.term_days,
                run_by: waiting.request.run_by,
                location: waiting.request.location,
                received_at: waiting.received_at,
                expires_at: waiting.request.expires_at,
                stage: waiting.stage,
            },
        )
        .collect::<Vec<_>>();
    let mut projected = crate::notifications::NotificationSummary::default();
    crate::notifications::project_custody_request_notifications(&mut projected, &pending);
    // The pools this node is in now: an older pool's entry, or one kept from
    // an owner this node no longer serves, is not shown.
    if let Err(error) = crate::notifications::project_custody_pool_active_notifications(
        &mut projected,
        data_dir,
        &profile.document().profile_did,
        &custody_consent::served_pool_fingerprints(data_dir),
    ) {
        tracing::warn!(error = %format!("{error:#}"), "custody pool notices are unreadable");
    }
    if projected.entries.is_empty() {
        return;
    }
    let projected = home_notifications_summary(projected);
    notifications.unread_count += projected.unread_count;
    notifications.attention_count += projected.attention_count;
    notifications.entries.extend(projected.entries);
}

/// Installs custody consent on this Home's custody message plane: the node
/// side, which decides requests and sends the decisions, and the owner side,
/// which takes decisions and sends requests and pool notices. Before each
/// delivery pass the handler queues again what the records still want sent.
/// At start, every decision a restart left unsent is queued again here.
pub(super) fn install_custody_consent(state: &GatewayState) {
    let Some(discovery) = state.collaboration_discovery_service.as_ref() else {
        return;
    };
    let messages = discovery.custody_message_service();
    let endpoint = state.carrier_endpoint.clone();
    let ticket: NodeTicket = Arc::new(move || {
        endpoint
            .as_ref()
            .map(crate::carrier::carrier_connect_ticket)
    });
    messages.set_handler(Arc::new(
        NodeConsentHandler::new(Arc::new(messages.downgrade()), ticket)
            .resuming_decisions(state.data_dir.clone())
            .with_owner_requests(state.data_dir.clone(), Arc::new(messages.downgrade()))
            .with_pool_notices(state.data_dir.clone(), Arc::new(messages.downgrade())),
    ));
    if let Err(error) = custody_consent::resume(&state.data_dir, &messages, now_ts()) {
        tracing::warn!(error = %format!("{error:#}"), "custody decisions were not queued again");
    }
}

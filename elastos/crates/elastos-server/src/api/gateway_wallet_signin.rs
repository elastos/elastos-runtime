//! Home/System adapter for account-bound wallet sign-in. Payment routes keep their authority.
use super::*;
use crate::auth::wallet_signin::{self as auth, Begin, Complete};
use elastos_runtime::auth::AuthSessionGrantV1;
use serde_json::json;

fn origin(headers: &HeaderMap) -> anyhow::Result<String> {
    Ok(crate::api::handlers::identity::derive_rp(headers)?.origin)
}
// Only the trusted Home/System caller can use its opaque capsule origin for
// management. Signed-out authentication keeps the same-origin front door.
fn management_origin(state: &GatewayState, headers: &HeaderMap) -> anyhow::Result<String> {
    if headers.get("origin").and_then(|v| v.to_str().ok()) == Some("null") {
        actor(state, headers)?;
        let mut admitted = headers.clone();
        admitted.remove("origin");
        return origin(&admitted);
    }
    origin(headers)
}
fn actor(
    state: &GatewayState,
    headers: &HeaderMap,
) -> anyhow::Result<(RequiredHomeLaunchToken, AuthSessionGrantV1)> {
    let launch = require_home_launch_token_binding(
        &state.data_dir,
        headers,
        &[HOME_CAPSULE_ID, SYSTEM_CAPSULE_ID],
    )?;
    let grant = crate::auth::load_active_session_grant(
        &home_launch_auth_data_dir(&state.data_dir),
        &launch.context.session_id,
        now_ts(),
    )?;
    Ok((launch, grant))
}
pub(super) fn approval_for_launch(
    state: &GatewayState,
    launch: &RequiredHomeLaunchToken,
    request: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let id = request["ceremony_id"].as_str().ok_or(auth::Refused)?;
    let grant = crate::auth::load_active_session_grant(
        &home_launch_auth_data_dir(&state.data_dir),
        &launch.context.session_id,
        now_ts(),
    )?;
    let stored = auth::approval_intent(&home_launch_auth_data_dir(&state.data_dir), id, &grant)?;
    anyhow::ensure!(*request == stored, "wallet method request changed");
    Ok(stored)
}
fn response<T: Serialize>(result: anyhow::Result<T>) -> Response {
    let mut response = match result {
        Ok(value) => Json(value).into_response(),
        Err(error) if error.is::<gateway_walletconnect::AttemptCapacity>() => {
            let seconds = error
                .downcast_ref::<gateway_walletconnect::AttemptCapacity>()
                .expect("capacity")
                .retry_after_secs;
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", seconds.to_string())],
                Json(json!({"error":"wallet_attempts_busy"})),
            )
                .into_response()
        }
        Err(error) if error.is::<auth::Capacity>() => (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "180")],
            Json(json!({"error":"wallet_attempts_busy"})),
        )
            .into_response(),
        Err(error) if error.is::<auth::Conflict>() => (
            StatusCode::CONFLICT,
            Json(json!({"error":"wallet_method_conflict"})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"wallet_signin_refused"})),
        )
            .into_response(),
    };
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
pub(super) async fn list(State(state): State<GatewayState>, headers: HeaderMap) -> Response {
    response(
        actor(&state, &headers)
            .and_then(|(_, a)| auth::list(&home_launch_auth_data_dir(&state.data_dir), &a)),
    )
}
pub(super) async fn method_begin(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<Begin>,
) -> Response {
    let result = async {
        let (_, a) = actor(&state, &headers)?;
        let result = auth::begin(
            &home_launch_auth_data_dir(&state.data_dir),
            &management_origin(&state, &headers)?,
            &load_existing_gateway_runtime_did(&state.data_dir).ok_or(auth::Refused)?,
            input,
            Some(a.clone()),
        )?;
        if result.attempt_token.is_some() {
            let _issue = gateway_walletconnect::issue_lock(&state).await;
            gateway_walletconnect::install_confirmation(&state, &result, &a.session_id).await?;
        }
        Ok::<_, anyhow::Error>(result)
    }
    .await;
    response(result)
}
pub(super) async fn method_complete(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<Complete>,
) -> Response {
    let result = async {
        let (launch, a) = actor(&state, &headers)?;
        // Authenticate browser ownership before consuming an approval.
        auth::intent(
            &home_launch_auth_data_dir(&state.data_dir),
            &input.ceremony_id,
            &input.browser_secret,
            &management_origin(&state, &headers)?,
            &a,
        )?;
        let result = auth::complete(
            &home_launch_auth_data_dir(&state.data_dir),
            &management_origin(&state, &headers)?,
            &input,
            Some(&a),
            |intent| {
                consume_passkey_step_up_token(
                    &state.data_dir,
                    &input.step_up_token,
                    &launch,
                    180,
                    auth::OPERATION,
                    intent,
                )
            },
        )?;
        gateway_walletconnect::retire_inactive_attempts(&state).await?;
        Ok::<_, anyhow::Error>(result)
    }
    .await;
    response(result)
}
pub(super) async fn signin_begin(
    State(state): State<GatewayState>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(input): Json<Begin>,
) -> Response {
    let result = async {
        let local =
            super::super::auth_gateway::local_first_owner_registration(&headers, peer.map(|p| p.0));
        let source = peer.map(|p| p.0.ip());
        let _issue = gateway_walletconnect::issue_lock(&state).await;
        if input.connector == "walletconnect" {
            gateway_walletconnect::preflight(&state, local, None, None, source).await?;
        }
        let result = auth::begin(
            &home_launch_auth_data_dir(&state.data_dir),
            &origin(&headers)?,
            &load_existing_gateway_runtime_did(&state.data_dir).ok_or(auth::Refused)?,
            input,
            None,
        )?;
        if result.attempt_token.is_some() {
            gateway_walletconnect::install_attempt(&state, &result, local, source).await?;
        }
        Ok::<_, anyhow::Error>(result)
    }
    .await;
    response(result)
}
pub(super) async fn signin_complete(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<Complete>,
) -> Response {
    let result = async {
        let value = auth::complete(
            &home_launch_auth_data_dir(&state.data_dir),
            &origin(&headers)?,
            &input,
            None,
            |_| Err(auth::Refused.into()),
        )?;
        let grant: AuthSessionGrantV1 = serde_json::from_value(value)?;
        gateway_walletconnect::retire_attempt(&state, &input.ceremony_id).await?;
        crate::auth::load_active_session_grant(
            &home_launch_auth_data_dir(&state.data_dir),
            &grant.session_id,
            now_ts(),
        )?;
        // Revocation may have won while the relay closed; token issuance checks
        // the live grant once more through the common Home launch path.
        let home_token =
            issue_home_launch_token_for_auth_grant(&state.data_dir, HOME_CAPSULE_ID, &grant)?;
        let system_token =
            issue_home_launch_token_for_auth_grant(&state.data_dir, SYSTEM_CAPSULE_ID, &grant)?;
        Ok::<_, anyhow::Error>((grant, home_token, system_token))
    }
    .await;
    match result {
        Ok((grant, home_token, system_token)) => {
            let cookie = home_session_cookie_header_for_token(
                &headers,
                &home_token,
                request_uses_tls(&headers),
            );
            let mut response = response(Ok(
                json!({"schema":"elastos.auth.wallet.signin/v1","principal_id":grant.principal_id,"proof_binding_id":grant.proof_binding_id,"session_id":grant.session_id,"expires_at":grant.expires_at,"app_token":home_token,"home_token":home_token,"system_token":system_token}),
            ));
            if let Ok(cookie) = cookie {
                response.headers_mut().append(SET_COOKIE, cookie);
            }
            response
        }
        Err(err) => response::<serde_json::Value>(Err(err)),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Select {
    ceremony_id: String,
    browser_secret: String,
    address: String,
    chain_id: u64,
}
pub(super) async fn select(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<Select>,
) -> Response {
    response(management_origin(&state, &headers).and_then(|o| {
        auth::select(
            &home_launch_auth_data_dir(&state.data_dir),
            &input.ceremony_id,
            &input.browser_secret,
            &o,
            input.address,
            input.chain_id,
        )
    }))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cancel {
    ceremony_id: String,
    browser_secret: String,
}
pub(super) async fn cancel(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<Cancel>,
) -> Response {
    let result = async {
        auth::cancel(
            &home_launch_auth_data_dir(&state.data_dir),
            &input.ceremony_id,
            &input.browser_secret,
            &management_origin(&state, &headers)?,
        )?;
        gateway_walletconnect::retire_attempt(&state, &input.ceremony_id).await?;
        Ok::<_, anyhow::Error>(json!({"status":"cancelled"}))
    }
    .await;
    response(result)
}
pub(super) async fn disabled() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error":"passkey_required"})),
    )
        .into_response()
}

use super::*;
use crate::auth::wallet_signin::{self as auth, tests as wallet_fixture};
const ORIGIN: &str = "http://localhost:61180";
const BROWSER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
async fn call(
    app: &Router,
    path: &str,
    token: Option<&str>,
    input: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .uri(path)
        .header(HOST, "localhost:61180")
        .header("origin", ORIGIN);
    if let Some(token) = token {
        request = request.header("x-elastos-home-token", token);
    }
    let body = if let Some(input) = input {
        request = request
            .method("POST")
            .header(CONTENT_TYPE, "application/json");
        Body::from(input.to_string())
    } else {
        Body::empty()
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&body)
            .unwrap_or_else(|_| json!({"text":String::from_utf8_lossy(&body)})),
    )
}
async fn begin(
    app: &Router,
    token: &str,
    f: &wallet_fixture::Fixture,
    action: &str,
    id: &str,
) -> auth::BeginResult {
    let (status,out)=call(app,"/api/auth/wallet-methods/begin",Some(token),Some(json!({"action":action,"method_id":id,"connector":"metamask","address":f.address,"chain_id":20,"browser_secret":BROWSER}))).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    serde_json::from_value(out).unwrap()
}
async fn change(
    app: &Router,
    token: &str,
    f: &wallet_fixture::Fixture,
    action: &str,
    id: &str,
) -> Value {
    let b = begin(app, token, f, action, id).await;
    let intent = b.approval.as_ref().unwrap();
    let approval = issue_passkey_step_up_token_for_test(
        f.data.path(),
        token,
        HOME_CAPSULE_ID,
        auth::OPERATION,
        &intent["request"],
    )
    .unwrap();
    let c = wallet_fixture::completion(f, &b);
    let (status,result)=call(app,"/api/auth/wallet-methods/complete",Some(token),Some(json!({"ceremony_id":c.ceremony_id,"browser_secret":c.browser_secret,"signature":c.signature,"signature_type":c.signature_type,"step_up_token":approval}))).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    result
}
#[tokio::test]
async fn wallet_signin_http_add_enable_signout_signin_disable_journey() {
    let f = wallet_fixture::fixture();
    let state = test_state(f.data.path());
    let token =
        issue_home_launch_token_for_auth_grant(f.data.path(), HOME_CAPSULE_ID, &f.actor).unwrap();
    let app = gateway_router(state);
    let method = change(&app, &token, &f, "add", "").await;
    assert_eq!(method["sign_in_enabled"], false);
    let id = method["method_id"].as_str().unwrap();
    change(&app, &token, &f, "enable", id).await;
    let (status,b)=call(&app,"/api/auth/wallet/signin/begin",None,Some(json!({"connector":"metamask","address":f.address,"chain_id":20,"browser_secret":BROWSER}))).await;
    assert_eq!(status, StatusCode::OK, "{b}");
    let b: auth::BeginResult = serde_json::from_value(b).unwrap();
    let c = wallet_fixture::completion(&f, &b);
    let request = json!({"ceremony_id":c.ceremony_id,"browser_secret":c.browser_secret,"signature":c.signature,"signature_type":c.signature_type});
    let (status, session) = call(
        &app,
        "/api/auth/wallet/signin/complete",
        None,
        Some(request.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["principal_id"], f.actor.principal_id);
    let wallet_token = session["home_token"].as_str().unwrap();
    let (status, list) = call(&app, "/api/auth/wallet-methods", Some(wallet_token), None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["methods"][0]["sign_in_enabled"], true);
    let b = begin(&app, wallet_token, &f, "disable", id).await;
    let c = wallet_fixture::completion(&f, &b);
    let (status, _) = call(
        &app,
        "/api/auth/wallet-methods/complete",
        Some(wallet_token),
        Some(json!({"ceremony_id":c.ceremony_id,"browser_secret":c.browser_secret})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "wallet session alone cannot disable a method"
    );
    // Same wallet session can obtain a token issued only after its account's
    // passkey ceremony. The test issuer models that completed WebAuthn proof.
    change(&app, wallet_token, &f, "disable", id).await;
    assert_eq!(
        call(&app, "/api/auth/wallet-methods", Some(wallet_token), None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app,
            "/api/auth/wallet/signin/complete",
            None,
            Some(request)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}
#[tokio::test]
async fn wallet_creation_recovery_approval_refused_at_both_routes() {
    let f = wallet_fixture::fixture();
    let app = gateway_router(test_state(f.data.path()));
    for operation in ["register", "recover", "approve"] {
        for phase in ["begin", "complete"] {
            let (status, out) = call(
                &app,
                &format!("/api/auth/wallet/{operation}/{phase}"),
                None,
                Some(json!({})),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(out["error"], "passkey_required");
        }
    }
}
#[tokio::test]
async fn wallet_session_role_change_requires_exact_fresh_passkey_approval() {
    let f = wallet_fixture::fixture();
    wallet_fixture::enabled(&f);
    let wallet = wallet_fixture::signin(&f);
    let guest = passkey_authority_with_name_role_credential(
        f.data.path(),
        Some("Guest"),
        crate::auth::RuntimePrincipalRole::Guest,
        "guest-wallet-role",
    );
    let state = test_state(f.data.path());
    let token =
        issue_home_launch_token_for_auth_grant(f.data.path(), SYSTEM_CAPSULE_ID, &wallet).unwrap();
    let path = format!(
        "/api/auth/passkeys/{}/promote-admin",
        guest.proof_binding_id
    );
    let before =
        crate::auth::load_principal_for_proof_binding(f.data.path(), &guest.proof_binding_id)
            .unwrap();
    let app = gateway_router(state);
    assert_eq!(
        call(&app, &path, Some(&token), Some(json!({}))).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        crate::auth::load_principal_for_proof_binding(f.data.path(), &guest.proof_binding_id)
            .unwrap()
            .role,
        before.role
    );
}

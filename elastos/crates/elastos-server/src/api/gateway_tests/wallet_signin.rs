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
        .header(
            "origin",
            if path.starts_with("/api/apps/inbox/") || path.starts_with("/api/apps/chat-room/") {
                "null"
            } else {
                ORIGIN
            },
        );
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

fn install_real_approver(data: &std::path::Path, account: &str, name: &[u8]) -> (String, String) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use elastos_identity::{IdentityStore, StoredCredential};
    let credential_id = URL_SAFE_NO_PAD.encode(name);
    let public_key = URL_SAFE_NO_PAD.encode(
        hex::decode(concat!(
            "a5010203262001215820",
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "225820",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        ))
        .unwrap(),
    );
    let mut store = IdentityStore::new(data).unwrap();
    store.load().unwrap();
    store.add_credential(StoredCredential {
        credential_id: credential_id.clone(),
        public_key: public_key.clone(),
        sign_count: 0,
        rp_id: "localhost".into(),
    });
    store.save().unwrap();
    let p = crate::auth::upsert_principal_for_binding_as_role(
        data,
        ProofBinding::passkey_webauthn(PasskeyWebAuthnBinding {
            credential_id: credential_id.clone(),
            public_key,
            sign_count: 0,
            user_verified: true,
            origin: ORIGIN.into(),
            rp_id: "localhost".into(),
            created_at: now_ts(),
            last_used_at: now_ts(),
            revoked_at: None,
        }),
        account.into(),
        crate::auth::RuntimePrincipalRole::Admin,
        now_ts(),
    )
    .unwrap();
    (p.proof_binding_id, credential_id)
}
async fn real_step_up(
    app: &Router,
    token: &str,
    operation: &str,
    request: &Value,
    approver: &str,
    credential: &str,
    count: u32,
) -> String {
    real_step_up_for_launch(
        app, token, token, operation, request, approver, credential, count,
    )
    .await
}
#[allow(clippy::too_many_arguments)]
async fn real_step_up_for_launch(
    app: &Router,
    token: &str,
    app_token: &str,
    operation: &str,
    request: &Value,
    approver: &str,
    credential: &str,
    count: u32,
) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    let (status,begin)=call(app,"/api/auth/passkey-step-up/begin",Some(token),Some(json!({"schema":"elastos.auth.passkey-step-up.begin.request/v1","app_token":app_token,"operation":operation,"request":request,"approving_passkey_id":approver}))).await;
    assert_eq!(status, StatusCode::OK, "{begin}");
    assert_eq!(
        begin["options"]["publicKey"]["allowCredentials"][0]["id"],
        credential
    );
    let client=json!({"type":"webauthn.get","challenge":begin["options"]["publicKey"]["challenge"],"origin":ORIGIN,"crossOrigin":false}).to_string();
    let mut auth = Sha256::digest(b"localhost").to_vec();
    auth.push(0x05);
    auth.extend_from_slice(&count.to_be_bytes());
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(client.as_bytes()));
    let mut key = [0u8; 32];
    key[31] = 1;
    let key = SigningKey::from_bytes((&key).into()).unwrap();
    let signature: Signature = key.sign(&signed);
    let (status,done)=call(app,"/api/auth/passkey-step-up/complete",Some(token),Some(json!({"schema":"elastos.auth.passkey-step-up.complete.request/v1","ceremony_id":begin["ceremony_id"],"response":{"id":credential,"rawId":credential,"type":"public-key","response":{"clientDataJson":URL_SAFE_NO_PAD.encode(client),"authenticatorData":URL_SAFE_NO_PAD.encode(auth),"signature":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())}}}))).await;
    assert_eq!(status, StatusCode::OK, "{done}");
    done["step_up_token"].as_str().unwrap().into()
}
#[tokio::test]
async fn wallet_step_up_defaults_to_the_accounts_matching_relying_party() {
    let f = wallet_fixture::fixture();
    let id = wallet_fixture::enabled(&f);
    let session = wallet_fixture::signin(&f);
    // The first active passkey belongs to the account but to another RP.
    crate::auth::mutate_auth_state_for_test(f.data.path(), |state| {
        let first = state
            .principals
            .iter_mut()
            .find(|p| p.proof_binding_id == f.actor.proof_binding_id)
            .unwrap();
        first.proof_binding.passkey.as_mut().unwrap().rp_id = "other.example".into();
    });
    let (_, credential) =
        install_real_approver(f.data.path(), &f.actor.principal_id, b"matching-rp");
    let token =
        issue_home_launch_token_for_auth_grant(f.data.path(), HOME_CAPSULE_ID, &session).unwrap();
    let app = gateway_router(test_state(f.data.path()));
    let b = begin(&app, &token, &f, "disable", &id).await;
    let request = &b.approval.as_ref().unwrap()["request"];
    let (status, result) = call(
        &app,
        "/api/auth/passkey-step-up/begin",
        Some(&token),
        Some(json!({
            "schema":"elastos.auth.passkey-step-up.begin.request/v1", "app_token":token,
            "operation":auth::OPERATION, "request":request
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["options"]["publicKey"]["rpId"], "localhost");
    assert_eq!(
        result["options"]["publicKey"]["allowCredentials"][0]["id"],
        credential
    );
    let (status, _) = call(&app, "/api/auth/passkey-step-up/begin", Some(&token), Some(json!({
        "schema":"elastos.auth.passkey-step-up.begin.request/v1", "app_token":token,
        "operation":auth::OPERATION, "request":request, "approving_passkey_id":f.actor.proof_binding_id
    }))).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "an explicit key still requires the request RP"
    );
}

#[tokio::test]
async fn wallet_session_real_webauthn_approves_only_same_account_and_exact_method_action() {
    let f = wallet_fixture::fixture();
    let id = wallet_fixture::enabled(&f);
    let (approver, credential) = install_real_approver(
        f.data.path(),
        &f.actor.principal_id,
        b"wallet-real-approver",
    );
    let (other, _) =
        install_real_approver(f.data.path(), "person:local:other", b"other-real-approver");
    let session = wallet_fixture::signin(&f);
    let token =
        issue_home_launch_token_for_auth_grant(f.data.path(), HOME_CAPSULE_ID, &session).unwrap();
    let app = gateway_router(test_state(f.data.path()));
    let b = begin(&app, &token, &f, "disable", &id).await;
    let request = &b.approval.as_ref().unwrap()["request"];
    let (status,_)=call(&app,"/api/auth/passkey-step-up/begin",Some(&token),Some(json!({"schema":"elastos.auth.passkey-step-up.begin.request/v1","app_token":token,"operation":auth::OPERATION,"request":request,"approving_passkey_id":other}))).await;
    assert!(matches!(
        status,
        StatusCode::FORBIDDEN | StatusCode::CONFLICT
    ));
    let approval = real_step_up(
        &app,
        &token,
        auth::OPERATION,
        request,
        &approver,
        &credential,
        1,
    )
    .await;
    let (status, out) = call(
        &app,
        "/api/auth/wallet-methods/complete",
        Some(&token),
        Some(
            json!({"ceremony_id":b.ceremony_id,"browser_secret":BROWSER,"step_up_token":approval}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["sign_in_enabled"], false);
    assert!(
        crate::auth::load_active_session_grant(f.data.path(), &session.session_id, now_ts())
            .is_err()
    );
}
#[tokio::test]
async fn wallet_session_guest_switch_requires_passkey_and_host_terminal_stays_with_passkey() {
    let f = wallet_fixture::fixture();
    wallet_fixture::enabled(&f);
    let session = wallet_fixture::signin(&f);
    let (approver, credential) = install_real_approver(
        f.data.path(),
        &f.actor.principal_id,
        b"guest-switch-approver",
    );
    let token =
        issue_home_launch_token_for_auth_grant(f.data.path(), HOME_CAPSULE_ID, &session).unwrap();
    let system = issue_home_projection_launch_token_with_context(
        f.data.path(),
        SYSTEM_CAPSULE_ID,
        SYSTEM_CAPSULE_ID,
        &HomeLaunchTokenContext {
            principal_id: session.principal_id.clone(),
            session_id: session.session_id.clone(),
            proof_binding_id: Some(session.proof_binding_id.clone()),
            grant_id: session.grant_id.clone(),
        },
    )
    .unwrap();
    assert!(!acts_for_host(
        f.data.path(),
        Some(&session.proof_binding_id)
    ));
    let app = gateway_router(test_state(f.data.path()));
    let path = "/api/apps/system/access/guest-registration";
    assert_eq!(
        call(&app, path, Some(&system), Some(json!({"enabled":true})))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert!(!crate::auth::guest_registration_enabled(f.data.path()).unwrap());
    // Use the Home-hosted System launch as the carried token, while Home owns
    // the WebAuthn request. This mirrors the host bridge's approval flow.
    let request = json!({"enabled":true});
    let (status,begin)=call(&app,"/api/auth/passkey-step-up/begin",Some(&token),Some(json!({"schema":"elastos.auth.passkey-step-up.begin.request/v1","app_token":system,"operation":"auth.account.guest-registration","request":request,"approving_passkey_id":approver}))).await;
    assert_eq!(status, StatusCode::OK, "{begin}");
    // The full signed assertion path is exercised above; cancellation keeps this
    // test focused on the host/System authority boundary and the safe refusal.
    assert_eq!(call(&app,"/api/auth/passkey-step-up/cancel",Some(&token),Some(json!({"schema":"elastos.auth.passkey-step-up.cancel.request/v1","ceremony_id":begin["ceremony_id"]}))).await.0,StatusCode::OK);
    assert!(!credential.is_empty());
}

fn new_passkey_response(challenge: &str, id: &[u8]) -> Value {
    let r = crate::auth::passkey_attestation_with_id_for_test(challenge, "localhost", ORIGIN, id);
    json!({"id":r._id,"rawId":r._raw_id,"type":r._type,"response":{"clientDataJson":r.response.client_data_json,"attestationObject":r.response.attestation_object}})
}
#[tokio::test]
async fn wallet_session_add_passkey_retains_the_exact_approving_key_until_completion() {
    let f = wallet_fixture::fixture();
    wallet_fixture::enabled(&f);
    let (approver, credential) = install_real_approver(
        f.data.path(),
        &f.actor.principal_id,
        b"add-passkey-approver",
    );
    let session = wallet_fixture::signin(&f);
    let home =
        issue_home_launch_token_for_auth_grant(f.data.path(), HOME_CAPSULE_ID, &session).unwrap();
    let system = issue_home_projection_launch_token_with_context(
        f.data.path(),
        SYSTEM_CAPSULE_ID,
        SYSTEM_CAPSULE_ID,
        &HomeLaunchTokenContext {
            principal_id: session.principal_id.clone(),
            session_id: session.session_id.clone(),
            proof_binding_id: Some(session.proof_binding_id.clone()),
            grant_id: session.grant_id.clone(),
        },
    )
    .unwrap();
    let app = gateway_router(test_state(f.data.path()));
    for counter in 1..=2 {
        let approval = real_step_up_for_launch(
            &app,
            &home,
            &system,
            "auth.passkey.add",
            &json!({"schema":"elastos.auth.passkey.add.intent/v1"}),
            &approver,
            &credential,
            counter,
        )
        .await;
        let (status,begin)=call(&app,"/api/auth/passkey/add/begin",Some(&home),Some(json!({"schema":"elastos.auth.passkey.add.begin.request/v1","app_token":system,"step_up_token":approval}))).await;
        assert_eq!(status, StatusCode::OK, "{begin}");
        if counter == 2 {
            crate::auth::revoke_passkey_binding(f.data.path(), &approver, now_ts()).unwrap();
        }
        let id = if counter == 1 {
            b"wallet-added-passkey".as_slice()
        } else {
            b"revoked-approver-passkey".as_slice()
        };
        let (status,result)=call(&app,"/api/auth/passkey/add/complete",Some(&home),Some(json!({"schema":"elastos.auth.passkey.add.complete.request/v1","app_token":system,"ceremony_id":begin["ceremony_id"],"response":new_passkey_response(begin["options"]["publicKey"]["challenge"].as_str().unwrap(),id)}))).await;
        if counter == 1 {
            assert_eq!(status, StatusCode::OK, "{result}");
            let p = crate::auth::load_principal_for_proof_binding(
                f.data.path(),
                result["proof_binding_id"].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(p.principal_id, f.actor.principal_id);
            assert_eq!(
                p.localhost_root,
                crate::auth::principal_localhost_root(&f.actor.principal_id)
            );
        } else {
            assert!(
                !status.is_success(),
                "revoked approving key granted authority: {result}"
            );
        }
    }
}

#[tokio::test]
async fn wallet_signin_public_availability_tracks_switch_without_account_details() {
    let f = wallet_fixture::fixture();
    let app = gateway_router(test_state(f.data.path()));
    assert_eq!(
        call(&app, "/api/auth/passkey/status", None, None).await.1["wallet_signin_available"],
        false
    );
    wallet_fixture::enabled(&f);
    let (status, state) = call(&app, "/api/auth/passkey/status", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state["wallet_signin_available"], true);
    assert_eq!(state["walletconnect_signin_available"], true);
    assert!(state.get("methods").is_none());
    assert!(state.get("account_id").is_none());
    assert!(state.get("address").is_none());
}
#[tokio::test]
async fn wallet_method_management_accepts_trusted_opaque_system_origin() {
    let f = wallet_fixture::fixture();
    let token =
        issue_home_launch_token_for_auth_grant(f.data.path(), SYSTEM_CAPSULE_ID, &f.actor).unwrap();
    let app = gateway_router(test_state(f.data.path()));
    let response=app.oneshot(Request::builder().uri("/api/auth/wallet-methods/begin").method("POST").header(HOST,"localhost:61180").header("origin","null").header("x-elastos-home-token",token).header(CONTENT_TYPE,"application/json").body(Body::from(json!({"action":"add","connector":"metamask","address":f.address,"chain_id":20,"browser_secret":BROWSER}).to_string())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn wallet_account_role_is_rechecked_inside_approved_mutation_after_demotion() {
    let f = wallet_fixture::fixture();
    wallet_fixture::enabled(&f);
    let session = wallet_fixture::signin(&f);
    let _other_admin = passkey_authority_with_name_role_credential(
        f.data.path(),
        Some("Other admin"),
        crate::auth::RuntimePrincipalRole::Admin,
        "role-race-admin",
    );
    let target = passkey_authority_with_name_role_credential(
        f.data.path(),
        Some("Guest"),
        crate::auth::RuntimePrincipalRole::Guest,
        "role-race-guest",
    );
    let token =
        issue_home_launch_token_for_auth_grant(f.data.path(), SYSTEM_CAPSULE_ID, &session).unwrap();
    let request = json!({"proof_binding_id":target.proof_binding_id});
    let approval = issue_passkey_step_up_token_for_test(
        f.data.path(),
        &token,
        SYSTEM_CAPSULE_ID,
        "auth.account.promote",
        &request,
    )
    .unwrap();
    let state = test_state(f.data.path());
    let mut headers = HeaderMap::new();
    headers.insert("x-elastos-home-token", token.parse().unwrap());
    headers.insert("x-elastos-step-up-token", approval.parse().unwrap());
    let context = runtime_wallet_authority_for_app_token(f.data.path(), SYSTEM_CAPSULE_ID, &token)
        .home_launch_context();
    // The initial HTTP Admin check won before this demotion. The callback must
    // verify current role again while the auth mutation lock is held.
    crate::auth::demote_passkey_to_guest(f.data.path(), &f.actor.proof_binding_id, now_ts())
        .unwrap();
    let result = crate::auth::promote_passkey_to_admin_approved(
        f.data.path(),
        &target.proof_binding_id,
        now_ts(),
        || {
            crate::api::auth_gateway::wallet_session_approval(
                &state,
                &headers,
                &context,
                "auth.account.promote",
                &request,
            )
        },
    );
    assert!(
        result.is_err(),
        "stale Admin approval changed an account role"
    );
    assert_eq!(
        crate::auth::load_principal_for_proof_binding(f.data.path(), &target.proof_binding_id)
            .unwrap()
            .role,
        crate::auth::RuntimePrincipalRole::Guest
    );
}

fn wallet_app_token(data: &std::path::Path, app: &str, session: &AuthSessionGrantV1) -> String {
    issue_home_projection_launch_token_with_context(
        data,
        app,
        app,
        &HomeLaunchTokenContext {
            principal_id: session.principal_id.clone(),
            session_id: session.session_id.clone(),
            proof_binding_id: Some(session.proof_binding_id.clone()),
            grant_id: session.grant_id.clone(),
        },
    )
    .unwrap()
}

async fn call_approved(
    app: &Router,
    path: &str,
    token: &str,
    approval: &str,
    input: Value,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(HOST, "localhost:61180")
                .header(
                    "origin",
                    if path.starts_with("/api/apps/chat-room/") {
                        "null"
                    } else {
                        ORIGIN
                    },
                )
                .header("x-elastos-home-token", token)
                .header("x-elastos-step-up-token", approval)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(input.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"text":String::from_utf8_lossy(&bytes)})),
    )
}

#[tokio::test]
async fn wallet_inbox_positive_permissions_require_exact_fresh_passkey() {
    let f = wallet_fixture::fixture();
    wallet_fixture::enabled(&f);
    let session = wallet_fixture::signin(&f);
    let (approver, credential) =
        install_real_approver(f.data.path(), "person:local:alice", b"inbox-approver");
    let app = gateway_router(test_state(f.data.path()));
    let home =
        issue_home_launch_token_for_auth_grant(f.data.path(), HOME_CAPSULE_ID, &session).unwrap();
    let inbox = wallet_app_token(f.data.path(), INBOX_CAPSULE_ID, &session);
    for action_id in [
        "community-presence-always:test",
        "community-presence-open:test",
        "contact-accept-request:test",
        "room-approve-request:test",
        "capability-approve-request:test",
        "service-approve-request:test",
        "model-egress-approve:test",
        WALLET_PRICE_HTTP_APPROVE_ACTION_ID,
    ] {
        let (status, result) = call(
            &app,
            "/api/apps/inbox/actions",
            Some(&inbox),
            Some(json!({"action_id":action_id})),
        )
        .await;
        assert!(
            !status.is_success(),
            "wallet alone approved {action_id}: {result}"
        );
        assert!(
            result.to_string().contains("passkey") || result.to_string().contains("step-up"),
            "{action_id}: {result}"
        );
    }
    let request = json!({"action_id":WALLET_PRICE_HTTP_APPROVE_ACTION_ID});
    let approval = real_step_up_for_launch(
        &app,
        &home,
        &inbox,
        "inbox.approve",
        &request,
        &approver,
        &credential,
        1,
    )
    .await;
    let (status, result) = call(
        &app,
        "/api/apps/inbox/actions",
        Some(&inbox),
        Some(json!({"action_id":WALLET_PRICE_HTTP_APPROVE_ACTION_ID,"step_up_token":approval})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    let (status, _) = call(
        &app,
        "/api/apps/inbox/actions",
        Some(&inbox),
        Some(json!({"action_id":WALLET_PRICE_HTTP_APPROVE_ACTION_ID,"step_up_token":approval})),
    )
    .await;
    assert!(!status.is_success(), "consumed approval was reused");
    assert_eq!(
        call(
            &app,
            "/api/apps/inbox/actions",
            Some(&inbox),
            Some(json!({"action_id":"notification-read:missing"}))
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn wallet_session_can_sign_out_but_other_session_revocation_needs_passkey() {
    let f = wallet_fixture::fixture();
    wallet_fixture::enabled(&f);
    let session = wallet_fixture::signin(&f);
    let (approver, credential) =
        install_real_approver(f.data.path(), "person:local:alice", b"session-approver");
    let state = test_state(f.data.path());
    let pending = auth::begin(
        f.data.path(), ORIGIN, "home-test",
        serde_json::from_value(json!({"action":"add","connector":"walletconnect","address":"","chain_id":0,"browser_secret":BROWSER})).unwrap(),
        Some(f.actor.clone()),
    ).unwrap();
    gateway_walletconnect::install_confirmation(&state, &pending, &f.actor.session_id)
        .await
        .unwrap();
    let relay_cancel =
        gateway_walletconnect::watch_attempt_socket_for_test(&state, &pending.ceremony_id).await;
    let app = gateway_router(state);

    let home =
        issue_home_launch_token_for_auth_grant(f.data.path(), HOME_CAPSULE_ID, &session).unwrap();
    let path = format!("/api/auth/sessions/{}/revoke", f.actor.session_id);
    assert!(!call(&app, &path, Some(&home), Some(json!({})))
        .await
        .0
        .is_success());
    assert!(
        crate::auth::load_active_session_grant(f.data.path(), &f.actor.session_id, now_ts())
            .is_ok()
    );
    let approval = real_step_up(
        &app,
        &home,
        "auth.session.revoke",
        &json!({"session_id":f.actor.session_id}),
        &approver,
        &credential,
        1,
    )
    .await;
    let (status, result) = call_approved(&app, &path, &home, &approval, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert!(
        *relay_cancel.borrow(),
        "revoking the approving passkey session must retire its relay"
    );

    assert!(
        crate::auth::load_active_session_grant(f.data.path(), &f.actor.session_id, now_ts())
            .is_err()
    );
    let path = format!("/api/auth/sessions/{}/revoke", session.session_id);
    assert_eq!(
        call(&app, &path, Some(&home), Some(json!({}))).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn wallet_explicit_account_removal_requires_exact_passkey_intent() {
    let f = wallet_fixture::fixture();
    wallet_fixture::enabled(&f);
    let session = wallet_fixture::signin(&f);
    install_real_approver(f.data.path(), "person:local:bob", b"other-admin");
    let (approver, credential) =
        install_real_approver(f.data.path(), "person:local:alice", b"removal-approver");
    let state = test_state(f.data.path());
    let attempt = auth::begin(
        f.data.path(),
        ORIGIN,
        "home-test",
        serde_json::from_value(
            json!({"connector":"walletconnect","address":"","chain_id":0,
            "browser_secret":BROWSER,"allow_temporary_internet":true}),
        )
        .unwrap(),
        None,
    )
    .unwrap();
    gateway_walletconnect::install_attempt(&state, &attempt, true, None)
        .await
        .unwrap();
    let relay_cancel =
        gateway_walletconnect::watch_attempt_socket_for_test(&state, &attempt.ceremony_id).await;
    let app = gateway_router(state);

    let home =
        issue_home_launch_token_for_auth_grant(f.data.path(), HOME_CAPSULE_ID, &session).unwrap();
    let path = format!("/api/auth/passkeys/{}/revoke", f.actor.proof_binding_id);
    let (malformed, _) = call(
        &app,
        &path,
        Some(&home),
        Some(json!({"remove_acount":true})),
    )
    .await;
    assert_eq!(malformed, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        crate::auth::load_active_session_grant(f.data.path(), &session.session_id, now_ts())
            .is_ok()
    );
    let body = json!({"remove_account":true,"account_id":session.principal_id});
    assert!(!call(&app, &path, Some(&home), Some(body.clone()))
        .await
        .0
        .is_success());
    let request = json!({"proof_binding_id":f.actor.proof_binding_id,"account_id":session.principal_id,"remove_account":true});
    let approval = real_step_up(
        &app,
        &home,
        "auth.account.remove",
        &request,
        &approver,
        &credential,
        1,
    )
    .await;
    let (status, result) = call_approved(&app, &path, &home, &approval, body).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert!(auth::inactive_attempts(f.data.path())
        .unwrap()
        .contains(&attempt.ceremony_id));
    assert!(
        *relay_cancel.borrow(),
        "committed account removal must close the open relay"
    );

    assert!(
        crate::auth::load_active_session_grant(f.data.path(), &session.session_id, now_ts())
            .is_err()
    );
    assert!(crate::auth::active_passkey_principals(f.data.path())
        .unwrap()
        .iter()
        .all(|p| p.principal_id != session.principal_id));
    assert_eq!(
        call(&app, "/api/auth/wallet-methods", Some(&home), None)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn wallet_guest_room_approval_stays_refused_with_a_valid_passkey() {
    let f = wallet_fixture::fixture();
    wallet_fixture::enabled(&f);
    let session = wallet_fixture::signin(&f);
    install_real_approver(f.data.path(), "person:local:bob", b"room-admin");
    let (approver, credential) =
        install_real_approver(f.data.path(), "person:local:alice", b"room-guest");
    crate::auth::demote_passkey_to_guest(f.data.path(), &approver, now_ts()).unwrap();
    let app = gateway_router(test_state(f.data.path()));
    let home =
        issue_home_launch_token_for_auth_grant(f.data.path(), HOME_CAPSULE_ID, &session).unwrap();
    let chat = wallet_app_token(f.data.path(), CHAT_ROOM_CAPSULE_ID, &session);
    let request = json!({"action_id":"room-approve-request:missing"});
    let approval = real_step_up_for_launch(
        &app,
        &home,
        &chat,
        "inbox.approve",
        &request,
        &approver,
        &credential,
        1,
    )
    .await;
    let (status, result) = call_approved(
        &app,
        "/api/apps/chat-room/requests/missing/approve",
        &chat,
        &approval,
        json!({}),
    )
    .await;
    assert!(!status.is_success());
    assert!(result.to_string().contains("admin"), "{result}");
}

#[cfg(unix)]
#[tokio::test]
async fn wallet_hosted_permission_can_be_approved_then_ended_or_denied() {
    use crate::api::model_provider_egress_decision as egress;
    let f = wallet_fixture::fixture();
    wallet_fixture::enabled(&f);
    let session = wallet_fixture::signin(&f);
    let (approver, credential) =
        install_real_approver(f.data.path(), "person:local:alice", b"egress-approver");
    crate::api::seed_model_provider_operator_offers_for_test(f.data.path(), vec![]).unwrap();
    let app = gateway_router(test_state(f.data.path()));
    let home =
        issue_home_launch_token_for_auth_grant(f.data.path(), HOME_CAPSULE_ID, &session).unwrap();
    let inbox = wallet_app_token(f.data.path(), INBOX_CAPSULE_ID, &session);
    let scope = egress::EgressScope {
        offer_id: "local:hosted:test".into(),
        effect: "model.http.request".into(),
        method: "POST".into(),
        url: "https://example.com/v1/chat".into(),
        origin: "https://example.com".into(),
        recipient: "example.com".into(),
        payer: "this Home".into(),
        provider: "test".into(),
        purpose: "test request".into(),
        configuration_id: "a".repeat(64),
    };
    let id = egress::request(f.data.path(), &scope, Some(&session.proof_binding_id)).unwrap();
    let action = format!("model-egress-approve:{id}");
    let approval = real_step_up_for_launch(
        &app,
        &home,
        &inbox,
        "inbox.approve",
        &json!({"action_id":action}),
        &approver,
        &credential,
        1,
    )
    .await;
    let (status, result) = call(
        &app,
        "/api/apps/inbox/actions",
        Some(&inbox),
        Some(json!({"action_id":action,"step_up_token":approval})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert!(egress::active(f.data.path(), &scope, Some(&session.proof_binding_id)).is_ok());
    let (status, result) = call(
        &app,
        "/api/apps/inbox/actions",
        Some(&inbox),
        Some(json!({"action_id":format!("model-egress-end:{id}")})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert!(egress::active(f.data.path(), &scope, Some(&session.proof_binding_id)).is_err());
    let mut next = scope.clone();
    next.url.push_str("/next");
    let id = egress::request(f.data.path(), &next, Some(&session.proof_binding_id)).unwrap();
    let (status, result) = call(
        &app,
        "/api/apps/inbox/actions",
        Some(&inbox),
        Some(json!({"action_id":format!("model-egress-deny:{id}")})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert!(egress::active(f.data.path(), &next, Some(&session.proof_binding_id)).is_err());
    let (other, _) = install_real_approver(f.data.path(), "person:local:bob", b"egress-other");
    let mut third = scope;
    third.url.push_str("/other");
    let id = egress::request(f.data.path(), &third, Some(&session.proof_binding_id)).unwrap();
    assert!(
        egress::approve(f.data.path(), &id, &other).is_err(),
        "other account approved wallet-bound request"
    );
}

#[tokio::test]
async fn walletconnect_review_note_storage_post_advances_etag_and_fences_stale_writes() {
    let f = wallet_fixture::fixture();
    wallet_fixture::enabled(&f);
    let state = test_state(f.data.path());
    let attempt = auth::begin(
        f.data.path(),
        ORIGIN,
        "home-test",
        serde_json::from_value(
            json!({"connector":"walletconnect","address":"","chain_id":0,
            "browser_secret":BROWSER,"allow_temporary_internet":true}),
        )
        .unwrap(),
        None,
    )
    .unwrap();
    gateway_walletconnect::install_attempt(&state, &attempt, true, None)
        .await
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-elastos-wallet-attempt",
        attempt.attempt_token.as_ref().unwrap().parse().unwrap(),
    );
    headers.insert(
        "x-elastos-wallet-instance",
        attempt.instance_id.parse().unwrap(),
    );
    headers.insert(
        "if-match",
        format!("\"{}\"", attempt.storage_revision).parse().unwrap(),
    );
    let write = || {
        Ok(AxumJson(
            serde_json::from_value(json!({"key":"pairing","value":"first"})).unwrap(),
        ))
    };
    let response = gateway_walletconnect::storage(
        AxumState(state.clone()),
        axum::http::Method::POST,
        headers.clone(),
        write(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let next = format!("\"{}\"", attempt.storage_revision + 1);
    assert_eq!(response.headers()["etag"], next);
    let response = gateway_walletconnect::storage(
        AxumState(state.clone()),
        axum::http::Method::POST,
        headers.clone(),
        write(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    headers.insert("if-match", next.parse().unwrap());
    let remove = Ok(AxumJson(
        serde_json::from_value(json!({"key":"pairing","value":null})).unwrap(),
    ));
    let response = gateway_walletconnect::storage(
        AxumState(state.clone()),
        axum::http::Method::POST,
        headers,
        remove,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["etag"],
        format!("\"{}\"", attempt.storage_revision + 2)
    );
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), json!({}));
    gateway_walletconnect::retire_attempt(&state, &attempt.ceremony_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn walletconnect_passkey_session_end_retires_confirmation_relay() {
    for sign_out in [false, true] {
        let f = wallet_fixture::fixture();
        let state = test_state(f.data.path());
        let pending = auth::begin(
            f.data.path(), ORIGIN, "home-test",
            serde_json::from_value(json!({"action":"add","connector":"walletconnect","address":"","chain_id":0,"browser_secret":BROWSER})).unwrap(),
            Some(f.actor.clone()),
        ).unwrap();
        gateway_walletconnect::install_confirmation(&state, &pending, &f.actor.session_id)
            .await
            .unwrap();
        let relay_cancel =
            gateway_walletconnect::watch_attempt_socket_for_test(&state, &pending.ceremony_id)
                .await;
        let home = issue_home_launch_token_for_auth_grant(f.data.path(), HOME_CAPSULE_ID, &f.actor)
            .unwrap();
        let path = if sign_out {
            "/api/auth/sessions/sign-out".into()
        } else {
            format!("/api/auth/sessions/{}/revoke", f.actor.session_id)
        };
        let (status, out) = call(&gateway_router(state), &path, Some(&home), Some(json!({}))).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert!(
            *relay_cancel.borrow(),
            "session end must retire its confirmation relay: {path}"
        );
    }
}

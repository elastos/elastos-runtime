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

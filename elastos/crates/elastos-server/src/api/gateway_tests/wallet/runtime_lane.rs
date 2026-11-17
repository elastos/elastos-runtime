use super::super::*;

async fn read_private(app: &Router, token: &str, route: &str) -> Value {
    let response = app.clone().oneshot(test_browser_request("localhost:61180", "null").uri(route)
        .header("x-elastos-home-token", token).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}

#[tokio::test]
async fn n7_browser_site_projection_all_surfaces_existing_routes() {
    let dir = tempfile::tempdir().unwrap();
    let authority = passkey_authority(dir.path());
    let wallet = app_token_for_authority(dir.path(), WALLET_CAPSULE_ID, &authority);
    let inbox = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &authority);
    let system = app_token_for_authority(dir.path(), SYSTEM_CAPSULE_ID, &authority);
    let metamask = projection_launch_token_for_authority_context(dir.path(), WALLET_METAMASK_CAPSULE_ID, &authority);
    let unisat = projection_launch_token_for_authority_context(dir.path(), WALLET_UNISAT_CAPSULE_ID, &authority);
    let record = json!({"request_id":"request:site", "status":"pending", "intent":"browser_personal_sign", "requested_by_actor":"browser",
        "principal_id":authority.principal_id, "session_id":authority.session_id, "account_id":"account:site", "chain_namespace":"eip155:20",
        "address":"0xabc", "resource":"elastos://wallet/sign", "reason":"Sign a message", "proof_type":"siwe", "connector_id":"wallet-metamask",
        "created_at":now_ts(), "expires_at":now_ts()+600, "payload":{
            "schema":"elastos.browser.wallet-signature-request/v1", "method":"personal_sign", "origin":"https://Shop.Example:443",
            "page_url":"https://shop.example/private?secret=1", "principal_id":authority.principal_id, "session_id":authority.session_id,
            "account_id":"account:site", "chain_namespace":"eip155:20", "address":"0xabc"
        }});
    let provider = MockWalletProvider { challenges:TokioMutex::default(), bitcoin_challenges:TokioMutex::default(), accounts:TokioMutex::default(),
        approvals:TokioMutex::new(vec![record]), defaults:TokioMutex::default() };
    let (state, _) = wallet_test_state_with_recording_provider(dir.path(), provider).await;
    let app = gateway_router(state);
    let body = read_private(&app, &wallet, "/api/apps/wallet/wallet/summary").await;
    assert_eq!(body["wallet_approvals"]["approval_requests"][0]["requesting_origin"], "https://shop.example");
    let body = read_private(&app, &inbox, "/api/apps/inbox/summary").await;
    let entry = body["notifications"]["entries"].as_array().unwrap().iter().find(|entry| entry["kind"] == "wallet_approval_request").unwrap();
    assert_eq!(entry["requesting_origin"], "https://shop.example");
    assert_eq!(entry["action_ref"]["action_id"], "wallet-review-request:request:site");
    let body = read_private(&app, &metamask, "/api/apps/wallet-metamask/wallet/approvals").await;
    assert_eq!(body["approval_requests"][0]["requesting_origin"], "https://shop.example");
    let body = read_private(&app, &unisat, "/api/apps/wallet-unisat/wallet/approvals").await;
    assert!(body["approval_requests"].as_array().unwrap().is_empty());
    let body = read_private(&app, &system, "/api/apps/system/wallet/approvals").await;
    assert!(body["approval_requests"][0].get("requesting_origin").is_none());
}

use super::super::*;

const PACKETS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../scripts/fixtures/wallet-connector-v2-messages.json"
));

async fn read_private(app: &Router, token: &str, route: &str) -> Value {
    let response = app
        .clone()
        .oneshot(
            test_browser_request("localhost:61180", "null")
                .uri(route)
                .header("x-elastos-home-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn n7_browser_site_projection_all_surfaces_existing_routes() {
    let packets: Value = serde_json::from_str(PACKETS).unwrap();
    let expected_site = packets["n7PrivateSummaries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "site-wallet")
        .unwrap()["summary"]["requesting_origin"]
        .clone();
    for connector in [
        Some(WALLET_METAMASK_CAPSULE_ID),
        Some(WALLET_WALLETCONNECT_CAPSULE_ID),
        None,
    ] {
        for (intent, method) in [
            ("browser_personal_sign", "personal_sign"),
            ("browser_typed_data_sign", "eth_signTypedData_v4"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            seed_walletconnect_connector_config(dir.path());
            let authority = passkey_authority(dir.path());
            let wallet = app_token_for_authority(dir.path(), WALLET_CAPSULE_ID, &authority);
            let inbox = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &authority);
            let system = app_token_for_authority(dir.path(), SYSTEM_CAPSULE_ID, &authority);
            let matching_actor = connector.unwrap_or(WALLET_METAMASK_CAPSULE_ID);
            let matching = projection_launch_token_for_authority_context(
                dir.path(),
                matching_actor,
                &authority,
            );
            let unisat = projection_launch_token_for_authority_context(
                dir.path(),
                WALLET_UNISAT_CAPSULE_ID,
                &authority,
            );
            let other = passkey_authority_with_name_role_credential(
                dir.path(),
                Some("other-site-reader"),
                crate::auth::RuntimePrincipalRole::Admin,
                "other-site-reader-credential",
            );
            let other_wallet = app_token_for_authority(dir.path(), WALLET_CAPSULE_ID, &other);
            let record = json!({"schema":"elastos.wallet.approval_request/v1", "request_id":"request:site", "status":"pending", "intent":intent, "requested_by_actor":"browser",
            "principal_id":authority.principal_id, "session_id":authority.session_id, "account_id":"account:site", "chain_namespace":"eip155:20",
            "address":"0xabc", "resource":"elastos://wallet/sign", "reason":"Sign a message", "proof_type":if connector.is_some() { "siwe" } else { "managed_evm" }, "connector_id":connector,
            "created_at":now_ts(), "expires_at":now_ts()+600, "payload":{
                "schema":"elastos.browser.wallet-signature-request/v1", "requires_wallet_approval":true, "method":method, "origin":"https://Shop.Example:443",
                "page_url":"https://shop.example/private?secret=1", "principal_id":authority.principal_id, "session_id":authority.session_id,
                "account_id":"account:site", "chain_namespace":"eip155:20", "address":"0xabc"
            }});
            let provider = MockWalletProvider {
                challenges: TokioMutex::default(),
                bitcoin_challenges: TokioMutex::default(),
                accounts: TokioMutex::default(),
                approvals: TokioMutex::new(vec![record]),
                defaults: TokioMutex::default(),
            };
            let (state, _) = wallet_test_state_with_recording_provider(dir.path(), provider).await;
            let app = gateway_router(state);
            let body = read_private(&app, &wallet, "/api/apps/wallet/wallet/summary").await;
            assert_eq!(
                body["wallet_approvals"]["approval_requests"][0]["requesting_origin"],
                expected_site
            );
            let body = read_private(&app, &inbox, "/api/apps/inbox/summary").await;
            let entry = body["notifications"]["entries"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["kind"] == "wallet_approval_request")
                .unwrap();
            assert_eq!(entry["requesting_origin"], expected_site);
            assert_eq!(
                entry["action_ref"]["action_id"],
                if connector.is_some() {
                    "wallet-review-request:request:site"
                } else {
                    "wallet-approve-request:request:site"
                }
            );
            let body = read_private(
                &app,
                &matching,
                &format!("/api/apps/{matching_actor}/wallet/approvals"),
            )
            .await;
            if connector.is_some() {
                assert_eq!(
                    body["approval_requests"][0]["requesting_origin"],
                    expected_site
                );
            } else {
                assert!(body["approval_requests"].as_array().unwrap().is_empty());
            }
            let body =
                read_private(&app, &unisat, "/api/apps/wallet-unisat/wallet/approvals").await;
            assert!(body["approval_requests"].as_array().unwrap().is_empty());
            let body = read_private(&app, &system, "/api/apps/system/wallet/approvals").await;
            assert!(body["approval_requests"][0]
                .get("requesting_origin")
                .is_none());
            let body = read_private(&app, &other_wallet, "/api/apps/wallet/wallet/summary").await;
            assert!(body["wallet_approvals"]["approval_requests"]
                .as_array()
                .unwrap()
                .is_empty());
        }
    }
}

#[tokio::test]
async fn n3_direct_external_approve_refused_existing_routes() {
    for (actor, route, reason) in [
        (
            WALLET_CAPSULE_ID,
            "/api/apps/wallet/wallet/managed-approvals/request:external/approve",
            "Approved in Wallet",
        ),
        (
            WALLET_CAPSULE_ID,
            "/api/apps/wallet/wallet/approvals/request:external/approve",
            "Approved in Wallet",
        ),
        (
            INBOX_CAPSULE_ID,
            "/api/apps/inbox/actions",
            "Approved in Inbox",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let authority = passkey_authority(dir.path());
        let token = app_token_for_authority(dir.path(), actor, &authority);
        let record = json!({"request_id":"request:external", "status":"pending", "intent":"credential", "requested_by_actor":"documents",
            "principal_id":authority.principal_id, "session_id":authority.session_id, "account_id":"account:external", "address":"0xabc",
            "chain_namespace":"eip155:20", "resource":"elastos://wallet/sign", "reason":"Sign a credential", "proof_type":"siwe",
            "connector_id":"wallet-metamask", "created_at":now_ts(), "expires_at":now_ts()+600});
        let provider = MockWalletProvider {
            challenges: TokioMutex::default(),
            bitcoin_challenges: TokioMutex::default(),
            accounts: TokioMutex::default(),
            approvals: TokioMutex::new(vec![record.clone()]),
            defaults: TokioMutex::default(),
        };
        let (state, recorder) =
            wallet_test_state_with_recording_provider(dir.path(), provider).await;
        let app = gateway_router(state);
        let proof = step_up_token_for_app_context(
            dir.path(),
            actor,
            &token,
            "wallet.approve",
            &json!({"request_id":"request:external", "reason":reason}),
        );
        let body = if actor == INBOX_CAPSULE_ID {
            json!({"action_id":"wallet-approve-request:request:external", "step_up_token":proof})
        } else {
            json!({"reason":reason, "step_up_token":proof})
        };
        let response = app
            .oneshot(
                test_browser_request("localhost:61180", "null")
                    .uri(route)
                    .method("POST")
                    .header("x-elastos-home-token", token)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let message = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(
            message.contains("approval method") || message.contains("different connector"),
            "{message}"
        );
        assert_eq!(recorder.provider.approvals.lock().await[0], record);
    }
}

#[tokio::test]
async fn n7_browser_site_projection_all_surfaces_transactions() {
    for connector in [
        Some(WALLET_METAMASK_CAPSULE_ID),
        Some(WALLET_WALLETCONNECT_CAPSULE_ID),
        None,
    ] {
        let dir = tempfile::tempdir().unwrap();
        seed_walletconnect_connector_config(dir.path());
        let authority = passkey_authority(dir.path());
        let browser = app_token_for_authority(dir.path(), BROWSER_CAPSULE_ID, &authority);
        let wallet = app_token_for_authority(dir.path(), WALLET_CAPSULE_ID, &authority);
        let inbox = app_token_for_authority(dir.path(), INBOX_CAPSULE_ID, &authority);
        let address = "0x1111111111111111111111111111111111111111";
        let account_id = format!("wallet:eip155:20:{address}");
        let provider = MockWalletProvider {
            challenges: TokioMutex::default(),
            bitcoin_challenges: TokioMutex::default(),
            accounts: TokioMutex::new(vec![
                json!({"account_id":account_id, "principal_id":authority.principal_id,
                "proof_binding_id":"proof:site-transaction", "chain_namespace":"eip155:20", "address":address,
                "proof_type":if connector.is_some() { "siwe" } else { "managed_evm" }, "connector_id":connector, "linked_at":now_ts() }),
            ]),
            approvals: TokioMutex::default(),
            defaults: TokioMutex::default(),
        };
        let app = gateway_router(
            wallet_chain_test_state_with_wallet_provider(dir.path(), provider).await,
        );
        let response = app.clone().oneshot(test_browser_request("localhost:61180", "null").uri("/api/apps/browser/wallet/request-transaction").method("POST")
            .header("x-elastos-home-token", browser).header(CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"method":"eth_sendTransaction", "params":[{"from":address,"to":"0x2222222222222222222222222222222222222222","value":"0x1","data":"0x"}],
                "account_id":account_id, "chain_namespace":"eip155:20", "address":address, "page_url":"https://shop.example/private?keep=private", "origin":"https://shop.example"}).to_string())).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_private(&app, &wallet, "/api/apps/wallet/wallet/summary").await;
        assert_eq!(
            body["wallet_approvals"]["approval_requests"][0]["requesting_origin"],
            "https://shop.example"
        );
        let body = read_private(&app, &inbox, "/api/apps/inbox/summary").await;
        let entry = body["notifications"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["kind"] == "wallet_approval_request")
            .unwrap();
        assert_eq!(entry["requesting_origin"], "https://shop.example");
        if let Some(actor) = connector {
            let token =
                projection_launch_token_for_authority_context(dir.path(), actor, &authority);
            let body =
                read_private(&app, &token, &format!("/api/apps/{actor}/wallet/approvals")).await;
            assert_eq!(
                body["approval_requests"][0]["requesting_origin"],
                "https://shop.example"
            );
        }
    }
}

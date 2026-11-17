use super::support::*;
use super::*;

fn external_request(provider: &mut WalletProvider, principal: &str) -> String {
    assert!(matches!(
        invoke_wallet(provider, principal, "wallet-metamask", WalletProviderOperationV2::LinkVerifiedAccount {
            proof_binding_id: "proof:eip155:20:0xabc".into(), chain_namespace: "eip155:20".into(),
            address: "0xabc".into(), proof_type: "siwe".into(), label: None,

            provider_id: None,
            wallet_peer_name: None,
}), Response::Ok { .. }
    ));
    match invoke_wallet(provider, principal, "documents", WalletProviderOperationV2::RequestApproval {
        account_id: "wallet:eip155:20:0xabc".into(), chain_namespace: "eip155:20".into(),
        intent: "publish_envelope".into(), resource: "elastos://content/publish".into(),
        reason: "Publish document revision".into(), payload: json!({"cid":"bafy-test"}),
        expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
    }) {
        Response::Ok { data: Some(data) } => data["approval_request"]["request_id"].as_str().unwrap().into(),
        other => panic!("expected request: {other:?}"),
    }
}

#[test]
fn n4_pending_requests_current_session_only_provider_list() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal = "person:local:alice";
    let id = external_request(&mut provider, principal);
    let original = serde_json::to_value(&provider.store).unwrap();
    let other = wallet_context_in_session(principal, "wallet", "session:other");
    for include_resolved in [false, true] {
        match invoke_wallet_with_context(&mut provider, &other, WalletProviderOperationV2::ListApprovals { include_resolved }) {
            Response::Ok { data: Some(data) } => assert_eq!(data["approval_requests"], json!([]), "foreign pending request is hidden"),
            other => panic!("expected list: {other:?}"),
        }
    }
    assert_eq!(serde_json::to_value(&provider.store).unwrap(), original);
    match invoke_wallet(&mut provider, principal, "wallet", WalletProviderOperationV2::ListApprovals { include_resolved: false }) {
        Response::Ok { data: Some(data) } => assert_eq!(data["approval_requests"][0]["request_id"], id),
        other => panic!("expected own list: {other:?}"),
    }
    provider.store.approval_requests[0].session_id.clear();
    for include_resolved in [false, true] {
        match invoke_wallet_with_context(&mut provider, &other, WalletProviderOperationV2::ListApprovals { include_resolved }) {
            Response::Ok { data: Some(data) } => assert_eq!(data["approval_requests"], json!([]), "legacy unbound pending request is hidden"),
            other => panic!("expected list: {other:?}"),
        }
    }
    provider.store.approval_requests[0].status = ApprovalStatus::Rejected;
    match invoke_wallet_with_context(&mut provider, &other, WalletProviderOperationV2::ListApprovals { include_resolved: true }) {
        Response::Ok { data: Some(data) } => assert_eq!(data["approval_requests"][0]["request_id"], id, "resolved history remains history"),
        other => panic!("expected history: {other:?}"),
    }
}

#[test]
fn n3_direct_external_approve_refused_provider() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal = "person:local:alice";
    let request_id = external_request(&mut provider, principal);
    let before = provider.store.approval_requests.clone();
    for actor in ["wallet", "inbox"] {
        match invoke_wallet(&mut provider, principal, actor, WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: request_id.clone(), reason: "Approved in Wallet".into(),
        }) {
            Response::Error { code, .. } => assert_eq!(code, "external_wallet_required"),
            other => panic!("expected external refusal: {other:?}"),
        }
        assert_eq!(provider.store.approval_requests, before);
    }
}

fn link_metadata(provider: &mut WalletProvider, principal: &str, actor: &str, metadata: Value) -> Response {
    let mut operation = json!({"kind":"link_verified_account", "params": {
        "proof_binding_id":"proof:eip155:20:0xabc", "chain_namespace":"eip155:20",
        "address":"0xabc", "proof_type":"siwe", "label":"My account"
    }});
    for (key, value) in metadata.as_object().unwrap() {
        operation["params"][key] = value.clone();
    }
    // Use the production Bus decoder, including its strict parameter shape.
    let operation: WalletProviderOperationV2 = serde_json::from_value(operation).unwrap();
    invoke_wallet(provider, principal, actor, operation)
}

#[test]
fn n4_metadata_bound_to_verified_link() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal = "person:local:alice";
    for actor in ["wallet-metamask", "wallet-unisat", "wallet-walletconnect"] {
        let metadata = match actor {
            "wallet-metamask" => json!({"provider_id":"io.metamask"}),
            "wallet-unisat" => json!({"provider_id":"unisat"}),
            _ => json!({"wallet_peer_name":"Meta\u{202e}Mask"}),
        };
        let expected = if actor == "wallet-unisat" { "UniSat" } else { "MetaMask" };
        match link_metadata(&mut provider, principal, actor, metadata) {
            Response::Ok { data: Some(data) } => {
                assert_eq!(data["account"]["wallet_display_name"], expected);
                assert_eq!(data["account"]["wallet_mark"], if actor == "wallet-walletconnect" { "wallet" } else if actor == "wallet-unisat" { "unisat" } else { "metamask" });
            }
            other => panic!("expected linked display: {other:?}"),
        }
    }
    let original = serde_json::to_value(&provider.store).unwrap();
    for (actor, metadata, expected) in [
        ("wallet-metamask", json!({"wallet_peer_name":"Trusted"}), "denied"),
        ("wallet-walletconnect", json!({"provider_id":"io.metamask"}), "denied"),
        ("wallet-unisat", json!({"provider_id":"io.metamask"}), "denied"),
        ("wallet-walletconnect", json!({"wallet_peer_name":"a".repeat(1025)}), "invalid_request"),
    ] {
        match link_metadata(&mut provider, principal, actor, metadata) {
            Response::Error { code, .. } => assert_eq!(code, expected),
            other => panic!("expected metadata refusal: {other:?}"),
        }
        assert_eq!(serde_json::to_value(&provider.store).unwrap(), original);
    }
}

#[test]
fn n4_old_record_and_reopened_window_provider() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal = "person:local:alice";
    assert!(matches!(link_metadata(&mut provider, principal, "wallet-walletconnect", json!({"wallet_peer_name":"Trust Wallet"})), Response::Ok { .. }));
    let mut provider = init_provider(dir.path());
    match invoke_wallet(&mut provider, principal, "wallet", WalletProviderOperationV2::ListAccounts { include_revoked: false }) {
        Response::Ok { data: Some(data) } => assert_eq!(data["accounts"][0]["wallet_display_name"], "Trust Wallet"),
        other => panic!("expected stored display: {other:?}"),
    }
    provider.store.accounts[0].provider_id = None;
    provider.store.accounts[0].connector_id = Some("wallet-metamask".into());
    provider.store.accounts[0].wallet_display_name = Some("MetaMask".into());
    provider.store.accounts[0].wallet_mark = Some("metamask".into());
    match invoke_wallet(&mut provider, principal, "wallet", WalletProviderOperationV2::ListAccounts { include_revoked: false }) {
        Response::Ok { data: Some(data) } => {
            assert!(data["accounts"][0].get("wallet_display_name").is_none());
            assert_eq!(data["accounts"][0]["wallet_mark"], "wallet");
        }
        other => panic!("expected fallback: {other:?}"),
    }
}

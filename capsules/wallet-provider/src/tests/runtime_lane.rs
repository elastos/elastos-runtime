use super::support::*;
use super::*;

fn external_request(provider: &mut WalletProvider, principal: &str) -> String {
    assert!(matches!(
        invoke_wallet(provider, principal, "wallet-metamask", WalletProviderOperationV2::LinkVerifiedAccount {
            proof_binding_id: "proof:eip155:20:0xabc".into(), chain_namespace: "eip155:20".into(),
            address: "0xabc".into(), proof_type: "siwe".into(), label: None,
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

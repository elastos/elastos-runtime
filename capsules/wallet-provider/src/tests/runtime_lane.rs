use super::support::*;
use super::*;

fn external_request(provider: &mut WalletProvider, principal: &str) -> String {
    assert!(matches!(
        invoke_wallet(
            provider,
            principal,
            "wallet-metamask",
            WalletProviderOperationV2::LinkVerifiedAccount {
                proof_binding_id: "proof:eip155:20:0xabc".into(),
                chain_namespace: "eip155:20".into(),
                address: "0xabc".into(),
                proof_type: "siwe".into(),
                label: None,

                provider_id: None,
                wallet_peer_name: None,
            }
        ),
        Response::Ok { .. }
    ));
    match invoke_wallet(
        provider,
        principal,
        "documents",
        WalletProviderOperationV2::RequestApproval {
            account_id: "wallet:eip155:20:0xabc".into(),
            chain_namespace: "eip155:20".into(),
            intent: "publish_envelope".into(),
            resource: "elastos://content/publish".into(),
            reason: "Publish document revision".into(),
            payload: json!({"cid":"bafy-test"}),
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    ) {
        Response::Ok { data: Some(data) } => data["approval_request"]["request_id"]
            .as_str()
            .unwrap()
            .into(),
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
        match invoke_wallet_with_context(
            &mut provider,
            &other,
            WalletProviderOperationV2::ListApprovals { include_resolved },
        ) {
            Response::Ok { data: Some(data) } => assert_eq!(
                data["approval_requests"],
                json!([]),
                "foreign pending request is hidden"
            ),
            other => panic!("expected list: {other:?}"),
        }
    }
    assert_eq!(serde_json::to_value(&provider.store).unwrap(), original);
    match invoke_wallet(
        &mut provider,
        principal,
        "wallet",
        WalletProviderOperationV2::ListApprovals {
            include_resolved: false,
        },
    ) {
        Response::Ok { data: Some(data) } => {
            assert_eq!(data["approval_requests"][0]["request_id"], id)
        }
        other => panic!("expected own list: {other:?}"),
    }
    provider.store.approval_requests[0].session_id.clear();
    for include_resolved in [false, true] {
        match invoke_wallet_with_context(
            &mut provider,
            &other,
            WalletProviderOperationV2::ListApprovals { include_resolved },
        ) {
            Response::Ok { data: Some(data) } => assert_eq!(
                data["approval_requests"],
                json!([]),
                "legacy unbound pending request is hidden"
            ),
            other => panic!("expected list: {other:?}"),
        }
    }
    provider.store.approval_requests[0].status = ApprovalStatus::Rejected;
    match invoke_wallet_with_context(
        &mut provider,
        &other,
        WalletProviderOperationV2::ListApprovals {
            include_resolved: true,
        },
    ) {
        Response::Ok { data: Some(data) } => assert_eq!(
            data["approval_requests"][0]["request_id"], id,
            "resolved history remains history"
        ),
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
        match invoke_wallet(
            &mut provider,
            principal,
            actor,
            WalletProviderOperationV2::ApproveAndSignManaged {
                request_id: request_id.clone(),
                reason: "Approved in Wallet".into(),
            },
        ) {
            Response::Error { code, .. } => assert_eq!(code, "external_wallet_required"),
            other => panic!("expected external refusal: {other:?}"),
        }
        assert_eq!(provider.store.approval_requests, before);
    }
}

fn link_metadata(
    provider: &mut WalletProvider,
    principal: &str,
    actor: &str,
    metadata: Value,
) -> Response {
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
        let expected = if actor == "wallet-unisat" {
            "UniSat"
        } else {
            "MetaMask"
        };
        match link_metadata(&mut provider, principal, actor, metadata) {
            Response::Ok { data: Some(data) } => {
                assert_eq!(data["account"]["wallet_display_name"], expected);
                assert_eq!(
                    data["account"]["wallet_mark"],
                    if actor == "wallet-walletconnect" {
                        "wallet"
                    } else if actor == "wallet-unisat" {
                        "unisat"
                    } else {
                        "metamask"
                    }
                );
            }
            other => panic!("expected linked display: {other:?}"),
        }
    }
    let original = serde_json::to_value(&provider.store).unwrap();
    for (actor, metadata, expected) in [
        (
            "wallet-metamask",
            json!({"wallet_peer_name":"Trusted"}),
            "denied",
        ),
        (
            "wallet-walletconnect",
            json!({"provider_id":"io.metamask"}),
            "denied",
        ),
        (
            "wallet-unisat",
            json!({"provider_id":"io.metamask"}),
            "denied",
        ),
        (
            "wallet-walletconnect",
            json!({"wallet_peer_name":"a".repeat(1025)}),
            "invalid_request",
        ),
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
    assert!(matches!(
        link_metadata(
            &mut provider,
            principal,
            "wallet-walletconnect",
            json!({"wallet_peer_name":"Trust Wallet"})
        ),
        Response::Ok { .. }
    ));
    let mut provider = init_provider(dir.path());
    match invoke_wallet(
        &mut provider,
        principal,
        "wallet",
        WalletProviderOperationV2::ListAccounts {
            include_revoked: false,
        },
    ) {
        Response::Ok { data: Some(data) } => {
            assert_eq!(data["accounts"][0]["wallet_display_name"], "Trust Wallet")
        }
        other => panic!("expected stored display: {other:?}"),
    }
    provider.store.accounts[0].provider_id = None;
    provider.store.accounts[0].connector_id = Some("wallet-metamask".into());
    provider.store.accounts[0].wallet_display_name = Some("MetaMask".into());
    provider.store.accounts[0].wallet_mark = Some("metamask".into());
    match invoke_wallet(
        &mut provider,
        principal,
        "wallet",
        WalletProviderOperationV2::ListAccounts {
            include_revoked: false,
        },
    ) {
        Response::Ok { data: Some(data) } => {
            assert!(data["accounts"][0].get("wallet_display_name").is_none());
            assert_eq!(data["accounts"][0]["wallet_mark"], "wallet");
        }
        other => panic!("expected fallback: {other:?}"),
    }
}

#[test]
fn n4_metadata_bounds_and_text_rendering_provider_shared_fields() {
    let packets: Value = serde_json::from_str(include_str!(
        "../../../../scripts/fixtures/wallet-connector-v2-messages.json"
    ))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    for fixture in packets["n4IdentityFields"].as_array().unwrap() {
        if fixture["operation"] != "link_verify" {
            continue;
        }
        if fixture["id"] == "peer-type" {
            let malformed = json!({"kind":"link_verified_account", "params": {
                "proof_binding_id":"proof:test", "chain_namespace":"eip155:20", "address":"0xabc", "proof_type":"siwe",
                "wallet_peer_name":3
            }});
            assert!(serde_json::from_value::<WalletProviderOperationV2>(malformed).is_err());
            continue;
        }
        let response = link_metadata(
            &mut provider,
            "person:local:alice",
            fixture["actor"].as_str().unwrap(),
            fixture["fields"].clone(),
        );
        match response {
            Response::Ok { .. } => assert_eq!(fixture["expect"], "accept", "{}", fixture["id"]),
            Response::Error { code, .. } => {
                assert_eq!(fixture["expect"], code, "{}", fixture["id"])
            }
        }
    }
}

fn old_provider_call(dir: &Path, request: &WalletProviderRequestV2) -> Value {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let executable = std::env::var_os("ELASTOS_WALLET_201_PROVIDER")
        .expect("exact 2.0.1 provider binary is required");
    let mut child = Command::new(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    writeln!(
        input,
        "{}",
        json!({"op":"init", "config":{"base_path":dir.display().to_string()}})
    )
    .unwrap();
    writeln!(input, "{}", json!({"op":"wallet_contract", "request":request, "_runtime_invocation":runtime_invocation_envelope()})).unwrap();
    drop(input);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("owned 2.0.1 provider process exceeded ten seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut output = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .take(1024 * 1024)
        .read_to_string(&mut output)
        .unwrap();
    let replies: Vec<Value> = output
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[0]["status"], "ok");
    replies[1].clone()
}

#[test]
#[ignore = "Linux command supplies the provider built from pinned v2.0.1 bde18c7bae"]
fn n4_update_201_undo_preserves_accounts() {
    let dir = tempfile::tempdir().unwrap();
    drop(init_provider(dir.path()));
    let principal = "person:local:alice";
    let old_link = wallet_request(
        &wallet_context(principal, "wallet-metamask"),
        WalletProviderOperationV2::LinkVerifiedAccount {
            proof_binding_id: "proof:eip155:20:0xabc".into(),
            chain_namespace: "eip155:20".into(),
            address: "0xabc".into(),
            proof_type: "siwe".into(),
            label: Some("My old account".into()),
            provider_id: None,
            wallet_peer_name: None,
        },
    );
    assert_eq!(old_provider_call(dir.path(), &old_link)["status"], "ok");
    let mut provider = init_provider(dir.path());
    assert!(provider.store.accounts[0].wallet_display_name.is_none());
    external_request(&mut provider, principal);
    assert!(matches!(
        link_metadata(
            &mut provider,
            principal,
            "wallet-walletconnect",
            json!({"wallet_peer_name":"Trust Wallet"})
        ),
        Response::Ok { .. }
    ));
    assert!(matches!(
        invoke_wallet(
            &mut provider,
            principal,
            "wallet-walletconnect",
            WalletProviderOperationV2::LinkVerifiedAccount {
                proof_binding_id: "proof:eip155:20:0xdef".into(),
                chain_namespace: "eip155:20".into(),
                address: "0xdef".into(),
                proof_type: "siwe".into(),
                label: Some("New account".into()),
                provider_id: None,
                wallet_peer_name: Some("Trust Wallet".into()),
            }
        ),
        Response::Ok { .. }
    ));
    assert!(matches!(
        invoke_wallet(
            &mut provider,
            principal,
            "wallet",
            WalletProviderOperationV2::SetDefaultAccount {
                account_id: "wallet:eip155:20:0xabc".into(),
                chain_namespace: "eip155:20".into(),
                intent: "publish_envelope".into(),
            }
        ),
        Response::Ok { .. }
    ));
    let before_requests = serde_json::to_value(&provider.store.approval_requests).unwrap();
    let before_defaults = serde_json::to_value(&provider.store.default_accounts).unwrap();
    let before_key = provider.storage_key;
    let before_proof = provider.store.accounts[0].proof_binding_id.clone();
    let request = wallet_request(
        &wallet_context(principal, "wallet"),
        WalletProviderOperationV2::RenameAccount {
            account_id: "wallet:eip155:20:0xabc".into(),
            label: "Renamed on 2.0.1".into(),
        },
    );
    assert_eq!(old_provider_call(dir.path(), &request)["status"], "ok");
    let mut updated = init_provider(dir.path());
    assert_eq!(
        updated.store.accounts.len(),
        2,
        "Undo reads the old account and the account linked after update"
    );
    assert_eq!(
        updated.store.accounts[1].account_id,
        "wallet:eip155:20:0xdef"
    );
    assert!(
        updated.storage_key == before_key,
        "Undo preserves the fixture key"
    );
    assert_eq!(
        serde_json::to_value(&updated.store.approval_requests).unwrap(),
        before_requests
    );
    assert_eq!(
        serde_json::to_value(&updated.store.default_accounts).unwrap(),
        before_defaults
    );
    assert_eq!(updated.store.accounts[0].proof_binding_id, before_proof);
    assert_eq!(
        updated.store.accounts[0].label.as_deref(),
        Some("Renamed on 2.0.1")
    );
    match invoke_wallet(
        &mut updated,
        principal,
        "wallet",
        WalletProviderOperationV2::ListAccounts {
            include_revoked: false,
        },
    ) {
        Response::Ok { data: Some(data) } => {
            assert!(data["accounts"][0].get("wallet_display_name").is_none());
            assert_eq!(data["accounts"][0]["wallet_mark"], "wallet");
        }
        other => panic!("expected re-update fallback: {other:?}"),
    }
}

#[test]
#[ignore = "Linux command supplies the provider built from pinned v2.0.1 bde18c7bae"]
fn n4_bus_mixed_version_optional_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal = "person:local:alice";
    external_request(&mut provider, principal);
    let context = wallet_context(principal, "wallet-walletconnect");
    let legacy = wallet_request(
        &context,
        WalletProviderOperationV2::ListAccounts {
            include_revoked: false,
        },
    );
    assert_eq!(old_provider_call(dir.path(), &legacy)["status"], "ok");
    let legacy_link = wallet_request(
        &context,
        WalletProviderOperationV2::LinkVerifiedAccount {
            proof_binding_id: "proof:eip155:20:0xabc".into(),
            chain_namespace: "eip155:20".into(),
            address: "0xabc".into(),
            proof_type: "siwe".into(),
            label: None,
            provider_id: None,
            wallet_peer_name: None,
        },
    );
    assert_eq!(
        old_provider_call(dir.path(), &legacy_link)["status"],
        "ok",
        "absent optional metadata keeps the old link shape"
    );
    let bytes = std::fs::read(provider.store_path.as_ref().unwrap()).unwrap();
    let metadata: WalletProviderOperationV2 = serde_json::from_value(json!({"kind":"link_verified_account", "params":{
        "proof_binding_id":"proof:eip155:20:0xabc", "chain_namespace":"eip155:20", "address":"0xabc", "proof_type":"siwe", "wallet_peer_name":"Trust Wallet"
    }})).unwrap();
    let request = wallet_request(&context, metadata.clone());
    let refused = old_provider_call(dir.path(), &request);
    assert_eq!(refused["status"], "error");
    assert_eq!(refused["code"], "invalid_wallet_contract");
    assert_eq!(
        std::fs::read(provider.store_path.as_ref().unwrap()).unwrap(),
        bytes,
        "strict legacy decoder refuses before store mutation"
    );
    assert!(matches!(
        invoke_wallet_with_context(&mut provider, &context, metadata),
        Response::Ok { .. }
    ));
    assert_eq!(
        provider.store.accounts[0].wallet_display_name.as_deref(),
        Some("Trust Wallet")
    );
}

#[test]
#[ignore = "Linux command supplies the provider built from pinned v2.0.1 bde18c7bae"]
fn n7_old_records_update_undo() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal = "person:local:alice";
    let address = format!("0x{}", "12".repeat(20));
    let account_id = format!("wallet:eip155:20:{address}");
    assert!(matches!(
        invoke_wallet(
            &mut provider,
            principal,
            "wallet-metamask",
            WalletProviderOperationV2::LinkVerifiedAccount {
                proof_binding_id: "proof:site-fixture".into(),
                chain_namespace: "eip155:20".into(),
                address: address.clone(),
                proof_type: "siwe".into(),
                label: None,
                provider_id: None,
                wallet_peer_name: None,
            }
        ),
        Response::Ok { .. }
    ));
    let context = wallet_context(principal, "browser");
    for has_origin in [true, false] {
        let mut payload =
            browser_personal_sign_payload(&account_id, &address, "Sign into the test app");
        payload["principal_id"] = json!(principal);
        payload["session_id"] = json!(context.session_id());
        payload["page_url"] = json!("https://dapp.example/private?query=kept#fragment");
        if !has_origin {
            payload.as_object_mut().unwrap().remove("origin");
        }
        assert!(matches!(
            invoke_wallet_with_context(
                &mut provider,
                &context,
                WalletProviderOperationV2::RequestApproval {
                    account_id: account_id.clone(),
                    chain_namespace: "eip155:20".into(),
                    intent: "browser_personal_sign".into(),
                    resource: "elastos://wallet/eip155:20/sign/browser_personal_sign".into(),
                    reason: "Sign a message".into(),
                    payload,
                    expires_at: now_ts() + 600,
                }
            ),
            Response::Ok { .. }
        ));
    }
    let before = serde_json::to_vec(&provider.store.approval_requests).unwrap();
    let request = wallet_request(
        &wallet_context(principal, "wallet"),
        WalletProviderOperationV2::RenameAccount {
            account_id,
            label: "Saved by 2.0.1".into(),
        },
    );
    assert_eq!(old_provider_call(dir.path(), &request)["status"], "ok");
    let updated = init_provider(dir.path());
    assert_eq!(
        serde_json::to_vec(&updated.store.approval_requests).unwrap(),
        before,
        "old writer preserves private payload bytes and request bindings"
    );
    for record in &updated.store.approval_requests {
        assert!(
            serde_json::to_value(record)
                .unwrap()
                .get("requesting_origin")
                .is_none(),
            "display origin is computed, never persisted"
        );
    }
}

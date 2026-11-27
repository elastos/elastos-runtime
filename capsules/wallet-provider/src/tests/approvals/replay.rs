use super::super::support::*;
use super::super::*;

const PRINCIPAL: &str = "person:local:alice";

fn approval_fixture(
    provider: &mut WalletProvider,
    connector: Option<&str>,
) -> WalletProviderRequestV2 {
    let address = if let Some(connector) = connector {
        let address = "0x3333333333333333333333333333333333333333";
        assert!(matches!(
            invoke_wallet(
                provider,
                PRINCIPAL,
                connector,
                WalletProviderOperationV2::LinkVerifiedAccount {
                    proof_binding_id: format!("proof:eip155:20:{address}"),
                    chain_namespace: "eip155:20".into(),
                    address: address.into(),
                    proof_type: "siwe".into(),
                    label: None,
                    provider_id: None,
                    wallet_peer_name: None,
                }
            ),
            Response::Ok { .. }
        ));
        address.to_string()
    } else {
        match invoke_wallet(
            provider,
            PRINCIPAL,
            "wallet",
            WalletProviderOperationV2::CreateManagedAccount {
                chain_namespace: "eip155:20".into(),
                label: None,
                create_new: false,
            },
        ) {
            Response::Ok { data: Some(data) } => {
                data["account"]["address"].as_str().unwrap().to_string()
            }
            other => panic!("account: {other:?}"),
        }
    };
    let account_id = provider
        .store
        .accounts
        .iter()
        .find(|a| a.address == address)
        .unwrap()
        .account_id
        .clone();
    let mut payload = transaction_intent_payload(&address);
    payload["network"] = json!({"id": "esc-mainnet"});
    let request = wallet_request(
        &wallet_context(PRINCIPAL, "system"),
        WalletProviderOperationV2::RequestApproval {
            account_id,
            chain_namespace: "eip155:20".into(),
            intent: "transaction_intent".into(),
            resource: "elastos://chain/esc-mainnet/broadcast_transaction".into(),
            reason: "Send EVM transaction".into(),
            payload,
            expires_at: now_ts() + 60,
        },
    );
    assert!(matches!(
        invoke_wallet_request(provider, &request),
        Response::Ok { .. }
    ));
    request
}

fn retry(
    original: &WalletProviderRequestV2,
    operation: WalletProviderOperationV2,
) -> WalletProviderRequestV2 {
    WalletProviderRequestV2::new(
        &wallet_context(PRINCIPAL, "system"),
        original.request_id.clone(),
        now_ts(),
        now_ts() + 120,
        operation,
    )
    .unwrap()
}

#[test]
fn renewal_refuses_every_operation_substitution_after_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let original = approval_fixture(&mut provider, None);
    let mut stored = provider.store.approval_requests[0].clone();
    stored.expires_at = now_ts() - 1;
    for status in [ApprovalStatus::Pending, ApprovalStatus::Expired] {
        for field in [
            "payload",
            "reason",
            "account_id",
            "chain_namespace",
            "intent",
            "resource",
        ] {
            provider.store.approval_requests = vec![stored.clone()];
            provider.store.approval_requests[0].status = status.clone();
            let mut operation = serde_json::to_value(&original.operation).unwrap();
            operation["params"]["expires_at"] = json!(now_ts() + 300);
            let replacement = match field {
                "payload" => {
                    let mut p = stored.payload.clone();
                    p["value"] = json!("0x1");
                    p
                }
                "intent" => json!("browser_personal_sign"),
                "chain_namespace" => json!("eip155:1"),
                "resource" => json!("elastos://chain/other/broadcast_transaction"),
                "account_id" => json!("wallet:other"),
                "reason" => json!("Substituted reason"),
                _ => unreachable!(),
            };
            operation["params"][field] = replacement;
            let request = retry(&original, serde_json::from_value(operation).unwrap());
            let before = provider.store.approval_requests.clone();
            let response = invoke_wallet_request(&mut provider, &request);
            assert!(
                matches!(response, Response::Error { ref code, .. } if code == "approval_identity_conflict"),
                "{status:?}/{field}: {response:?}"
            );
            assert_eq!(provider.store.approval_requests, before);
        }
    }
}

#[test]
fn renewal_refuses_duplicate_identities_without_discarding_an_existing_answer() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let original = approval_fixture(&mut provider, None);
    let mut expired = provider.store.approval_requests[0].clone();
    expired.status = ApprovalStatus::Expired;
    expired.expires_at = now_ts() - 1;
    let mut answered = expired.clone();
    answered.status = ApprovalStatus::Approved;
    answered.approved_at = Some(now_ts() - 2);
    provider.store.approval_requests = vec![expired, answered];
    let before = provider.store.approval_requests.clone();
    let response =
        invoke_wallet_request(&mut provider, &retry(&original, original.operation.clone()));
    assert!(
        matches!(response, Response::Error { ref code, .. } if code == "approval_identity_conflict")
    );
    assert_eq!(provider.store.approval_requests, before);
}

#[test]
fn renewal_state_table_keeps_answers_and_allows_only_unanswered_expiry_retry() {
    for connector in [None, Some("wallet-metamask"), Some("wallet-walletconnect")] {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = init_provider(dir.path());
        let original = approval_fixture(&mut provider, connector);
        let template = provider.store.approval_requests[0].clone();
        for (status, approved, allowed) in [
            (ApprovalStatus::Pending, false, true),
            (ApprovalStatus::Expired, false, true),
            (ApprovalStatus::Expired, true, false),
            (ApprovalStatus::Approved, true, false),
            (ApprovalStatus::Completed, true, false),
            (ApprovalStatus::Rejected, false, false),
        ] {
            let mut stored = template.clone();
            stored.status = status.clone();
            stored.expires_at = now_ts() - 1;
            stored.approved_at = approved.then_some(now_ts() - 2);
            provider.store.approval_requests = vec![stored];
            provider.store.consumed_lifecycles.clear();
            let mut operation = original.operation.clone();
            if let WalletProviderOperationV2::RequestApproval { expires_at, .. } = &mut operation {
                *expires_at = now_ts() + 300;
            }
            let response = invoke_wallet_request(&mut provider, &retry(&original, operation));
            assert_eq!(
                response.is_ok(),
                allowed,
                "{connector:?}/{status:?}/approved={approved}: {response:?}"
            );
            assert_eq!(provider.store.approval_requests.len(), 1);
            if allowed {
                assert_eq!(
                    provider.store.approval_requests[0].status,
                    ApprovalStatus::Pending
                );
            }
        }
    }
}

#[test]
fn handed_off_transaction_survives_expiry_restart_and_history_pressure_until_first_outcome() {
    for connector in ["wallet-metamask", "wallet-walletconnect"] {
        for legacy_expired in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut provider = init_provider(dir.path());
            let original = approval_fixture(&mut provider, Some(connector));
            assert!(matches!(
                invoke_wallet(
                    &mut provider,
                    PRINCIPAL,
                    connector,
                    WalletProviderOperationV2::ApproveConnectorHandoff {
                        request_id: original.request_id.clone(),
                        reason: "Send once".into(),
                    }
                ),
                Response::Ok { .. }
            ));
            let mut handed_off = provider.store.approval_requests[0].clone();
            handed_off.expires_at = now_ts()
                - elastos_wallet_contract::WALLETCONNECT_TRANSACTION_COMPLETION_GRACE_SECS
                - 60;
            if legacy_expired {
                handed_off.status = ApprovalStatus::Expired;
                handed_off.resolved_at = Some(now_ts() - 1);
            }
            provider.store.approval_requests = vec![handed_off.clone()];
            for i in 0..=MAX_RESOLVED_APPROVAL_HISTORY_PER_PRINCIPAL {
                let mut other = handed_off.clone();
                other.request_id = format!("resolved:{i}");
                other.status = ApprovalStatus::Rejected;
                other.approved_at = None;
                other.created_at += i as u64 + 1;
                provider.store.approval_requests.push(other);
            }
            provider.save().unwrap();
            let mut provider = init_provider(dir.path());
            let listed = invoke_wallet(
                &mut provider,
                PRINCIPAL,
                "system",
                WalletProviderOperationV2::ListApprovals {
                    include_resolved: true,
                },
            );
            assert!(
                matches!(listed, Response::Ok { data: Some(ref data) } if data["approval_requests"].as_array().unwrap().iter().any(|r| r["request_id"] == original.request_id && r["status"] == "approved")),
                "{connector}/{legacy_expired}: original handed-off approval must remain approved in history"
            );
            // The original id can never hand a second transaction to the connector.
            assert!(matches!(
                invoke_wallet(
                    &mut provider,
                    PRINCIPAL,
                    connector,
                    WalletProviderOperationV2::ApproveConnectorHandoff {
                        request_id: original.request_id.clone(),
                        reason: "Stale card".into(),
                    }
                ),
                Response::Error { .. }
            ));
            let complete = |hash: &str| WalletProviderOperationV2::CompleteConnectorHandoff {
                request_id: original.request_id.clone(),
                payload_hash: handed_off.payload_hash.clone(),
                signature: None,
                signature_type: None,
                public_key: None,
                signer: handed_off.address.clone(),
                transaction_hash: Some(hash.into()),
            };
            let transaction_hash = format!("0x{}", "a".repeat(64));
            let response = invoke_wallet(
                &mut provider,
                PRINCIPAL,
                connector,
                complete(&transaction_hash),
            );
            assert!(response.is_ok(), "late first outcome: {response:?}");
            let mut provider = init_provider(dir.path());
            let response = invoke_wallet_request(&mut provider, &original);
            assert!(
                matches!(response, Response::Ok { data: Some(ref data) } if data["approval_request"]["signed_result"]["transaction_hash"] == transaction_hash)
            );
            assert!(matches!(
                invoke_wallet(
                    &mut provider,
                    PRINCIPAL,
                    connector,
                    complete(&format!("0x{}", "b".repeat(64)))
                ),
                Response::Error { .. }
            ));
            // Runtime can finish the original effect with Chain's observation.
            let outcome = ValidatedChainOutcomeV1 {
                schema: elastos_wallet_contract::VALIDATED_CHAIN_OUTCOME_SCHEMA.into(),
                approval_request_id: original.request_id.clone(),
                account_id: handed_off.account_id.clone(),
                chain_namespace: handed_off.chain_namespace.clone(),
                network: elastos_wallet_contract::PublicNetwork::new("esc-mainnet").unwrap(),
                binding: ValidatedChainOutcomeBindingV1::ExternalConnector {
                    connector_id: connector.into(),
                    originating_address: handed_off.address.clone(),
                },
                transaction_hash: transaction_hash.clone(),
                chain_observation: json!({
                    "network": "esc-mainnet", "hash": transaction_hash,
                    "transaction": {
                        "hash": transaction_hash, "from": handed_off.address,
                        "blockNumber": "0x2a"
                    }
                }),
                confirmed_at: now_ts(),
            };
            assert!(invoke_wallet(
                &mut provider,
                PRINCIPAL,
                "system",
                WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
            )
            .is_ok());
        }
    }
}

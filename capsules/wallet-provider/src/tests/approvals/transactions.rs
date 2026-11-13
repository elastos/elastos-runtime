use super::super::support::*;
use super::super::*;

#[test]
fn managed_account_signs_eip155_transaction_intent_after_runtime_approval() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal_id = "person:local:alice";
    let (account_id, address) = match invoke_wallet(
        &mut provider,
        principal_id,
        "wallet",
        WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".into(),
            label: None,
            create_new: false,
        },
    ) {
        Response::Ok { data: Some(data) } => (
            data["account"]["account_id"].as_str().unwrap().to_string(),
            data["account"]["address"].as_str().unwrap().to_string(),
        ),
        other => panic!("expected managed account, got {other:?}"),
    };
    let mut payload = transaction_intent_payload(&address);
    payload["page_url"] = json!("https://ela.city/cinema/view/test");
    payload["origin"] = json!("https://ela.city");
    payload["network"] = json!({ "id": "esc-mainnet" });
    let request_id = match invoke_wallet(
        &mut provider,
        principal_id,
        "system",
        WalletProviderOperationV2::RequestApproval {
            account_id,
            chain_namespace: "eip155:20".into(),
            intent: "transaction_intent".into(),
            resource: "elastos://chain/esc-mainnet/broadcast_transaction".into(),
            reason: "Send EVM transaction".into(),
            payload,
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    ) {
        Response::Ok { data: Some(data) } => {
            let approval = &data["approval_request"];
            assert_eq!(approval["intent"], "transaction_intent");
            assert_eq!(approval["status"], "pending");
            approval["request_id"].as_str().unwrap().to_string()
        }
        other => panic!("expected transaction approval request, got {other:?}"),
    };
    let signed_transaction_hash = match invoke_wallet(
        &mut provider,
        principal_id,
        "system",
        WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: request_id.clone(),
            reason: "Approved transaction".to_string(),
        },
    ) {
        Response::Ok { data: Some(data) } => {
            assert_eq!(data["approval_request"]["status"], "completed");
            assert!(data["signed_transaction"]
                .as_str()
                .is_some_and(|value| value.starts_with("0x")));
            assert_eq!(
                data["approval_request"]["signed_result"]["page_url"],
                "https://ela.city/cinema/view/test"
            );
            assert_eq!(
                data["approval_request"]["signed_result"]["origin"],
                "https://ela.city"
            );
            assert!(data["approval_request"]["signed_result"]
                .get("broadcast_recorded_at")
                .is_none());
            data["approval_request"]["signed_result"]["transaction_hash"]
                .as_str()
                .expect("signed transaction hash")
                .to_string()
        }
        other => panic!("expected atomic managed transaction signature, got {other:?}"),
    };
    match invoke_wallet(
        &mut provider,
        principal_id,
        "wallet",
        WalletProviderOperationV2::ListApprovals {
            include_resolved: true,
        },
    ) {
        Response::Ok { data: Some(data) } => {
            let requests = data["approval_requests"].as_array().unwrap();
            assert!(requests.iter().any(|request| {
                request["request_id"] == request_id
                    && request["status"] == "completed"
                    && request["signed_result"]["transaction_hash"] == signed_transaction_hash
            }));
        }
        other => panic!("expected approval history with signed transaction hash, got {other:?}"),
    }
}

#[test]
fn validated_chain_outcome_projection_is_exact_and_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal_id = "person:local:alice";
    let (account_id, address) = match invoke_wallet(
        &mut provider,
        principal_id,
        "wallet",
        WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".into(),
            label: None,
            create_new: false,
        },
    ) {
        Response::Ok { data: Some(data) } => (
            data["account"]["account_id"].as_str().unwrap().to_string(),
            data["account"]["address"].as_str().unwrap().to_string(),
        ),
        other => panic!("expected managed account, got {other:?}"),
    };
    let mut payload = transaction_intent_payload(&address);
    payload["network"] = json!({ "id": "esc-mainnet" });
    let request_id = match invoke_wallet(
        &mut provider,
        principal_id,
        "system",
        WalletProviderOperationV2::RequestApproval {
            account_id: account_id.clone(),
            chain_namespace: "eip155:20".into(),
            intent: "transaction_intent".into(),
            resource: "elastos://chain/esc-mainnet/broadcast_transaction".into(),
            reason: "Send EVM transaction".into(),
            payload,
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    ) {
        Response::Ok { data: Some(data) } => data["approval_request"]["request_id"]
            .as_str()
            .unwrap()
            .to_string(),
        other => panic!("expected transaction approval request, got {other:?}"),
    };
    let (signed_transaction, transaction_hash) = match invoke_wallet(
        &mut provider,
        principal_id,
        "system",
        WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: request_id.clone(),
            reason: "Approved transaction".into(),
        },
    ) {
        Response::Ok { data: Some(data) } => (
            data["signed_transaction"].as_str().unwrap().to_string(),
            data["approval_request"]["signed_result"]["transaction_hash"]
                .as_str()
                .unwrap()
                .to_string(),
        ),
        other => panic!("expected managed transaction signature, got {other:?}"),
    };
    let signed_bytes = hex::decode(signed_transaction.trim_start_matches("0x")).unwrap();
    let outcome = ValidatedChainOutcomeV1 {
        schema: elastos_wallet_contract::VALIDATED_CHAIN_OUTCOME_SCHEMA.to_string(),
        approval_request_id: request_id.clone(),
        account_id: account_id.clone(),
        chain_namespace: "eip155:20".into(),
        network: elastos_wallet_contract::PublicNetwork::new("esc-mainnet").unwrap(),
        binding: ValidatedChainOutcomeBindingV1::ManagedSigned {
            signed_transaction_sha256: format!(
                "sha256:{}",
                hex::encode(sha2::Sha256::digest(signed_bytes))
            ),
        },
        transaction_hash: transaction_hash.clone(),
        chain_observation: json!({
            "schema": "elastos.chain.broadcast_receipt/v1",
            "network": "esc-mainnet",
            "transaction_hash": transaction_hash,
        }),
        confirmed_at: now_ts(),
    };

    for _ in 0..2 {
        match invoke_wallet(
            &mut provider,
            principal_id,
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome {
                outcome: outcome.clone(),
            },
        ) {
            Response::Ok { data: Some(data) } => {
                assert_eq!(
                    data["approval_request"]["validated_chain_outcome"],
                    serde_json::to_value(&outcome).unwrap()
                );
            }
            other => panic!("expected idempotent Chain outcome projection, got {other:?}"),
        }
    }

    let mut substituted = outcome.clone();
    substituted.chain_observation["status"] = json!("substituted");
    assert!(matches!(
        invoke_wallet(
            &mut provider,
            principal_id,
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome {
                outcome: substituted,
            },
        ),
        Response::Error { ref code, .. } if code == "chain_outcome_conflict"
    ));

    let mut substituted = outcome;
    substituted.account_id = "wallet-account:substituted".into();
    assert!(matches!(
        invoke_wallet(
            &mut provider,
            principal_id,
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome {
                outcome: substituted,
            },
        ),
        Response::Error { ref code, .. } if code == "chain_outcome_conflict"
    ));
}

#[test]
fn transaction_intent_validates_payload_and_allows_external_handoff() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal_id = "person:local:alice";
    let managed = match invoke_wallet(
        &mut provider,
        principal_id,
        "wallet",
        WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".into(),
            label: None,
            create_new: false,
        },
    ) {
        Response::Ok { data: Some(data) } => {
            data["account"]["account_id"].as_str().unwrap().to_string()
        }
        other => panic!("expected managed account, got {other:?}"),
    };

    match invoke_wallet(
        &mut provider,
        principal_id,
        "system",
        WalletProviderOperationV2::RequestApproval {
            account_id: managed,
            chain_namespace: "eip155:20".into(),
            intent: "transaction_intent".into(),
            resource: "elastos://chain/esc-mainnet/broadcast_transaction".into(),
            reason: "Send EVM transaction".into(),
            payload: json!({
                "schema": "elastos.chain.unsigned_transaction_intent/v1",
                "transaction_type": "eip155_legacy",
                "chain_id": 20
            }),
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    ) {
        Response::Error { code, message } => {
            assert_eq!(code, "invalid_transaction_intent");
            assert!(message.contains("wallet_intent") || message.contains("missing"));
        }
        other => panic!("expected invalid transaction payload, got {other:?}"),
    }

    let external_address = "0x3333333333333333333333333333333333333333";
    let external_account_id = format!("wallet:eip155:20:{external_address}");
    assert!(matches!(
        invoke_wallet(
            &mut provider,
            principal_id,
            "wallet-metamask",
            WalletProviderOperationV2::LinkVerifiedAccount {
                proof_binding_id: format!("proof:eip155:20:{external_address}"),
                chain_namespace: "eip155:20".into(),
                address: external_address.into(),
                proof_type: "siwe".into(),
                label: None,
            },
        ),
        Response::Ok { .. }
    ));
    let mut external_payload = transaction_intent_payload(external_address);
    external_payload["page_url"] = json!("https://ela.city/cinema/view/test");
    external_payload["origin"] = json!("https://ela.city");
    external_payload["network"] = json!({ "id": "esc-mainnet" });
    let (request_id, payload_hash) = match invoke_wallet(
        &mut provider,
        principal_id,
        "system",
        WalletProviderOperationV2::RequestApproval {
            account_id: external_account_id.clone(),
            chain_namespace: "eip155:20".into(),
            intent: "transaction_intent".into(),
            resource: "elastos://chain/esc-mainnet/broadcast_transaction".into(),
            reason: "Send EVM transaction".into(),
            payload: external_payload,
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    ) {
        Response::Ok { data: Some(data) } => {
            assert_eq!(data["approval_request"]["intent"], "transaction_intent");
            assert_eq!(data["approval_request"]["connector_id"], "wallet-metamask");
            assert_eq!(
                data["approval_request"]["payload"]["schema"],
                "elastos.chain.unsigned_transaction_intent/v1"
            );
            (
                data["approval_request"]["request_id"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                data["approval_request"]["payload_hash"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        }
        other => panic!("expected external transaction approval request, got {other:?}"),
    };
    let transaction = match invoke_wallet(
        &mut provider,
        principal_id,
        "wallet-metamask",
        WalletProviderOperationV2::ApproveConnectorHandoff {
            request_id: request_id.clone(),
            reason: "Approved transaction".into(),
        },
    ) {
        Response::Ok { data: Some(data) } => {
            assert_eq!(data["handoff"]["intent"], "transaction_intent");
            data["handoff"]["transaction"].clone()
        }
        other => panic!("expected external transaction handoff, got {other:?}"),
    };
    assert_eq!(transaction["from"], external_address);
    assert_eq!(transaction["chainId"], "0x14");
    let transaction_hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let context = wallet_context(principal_id, "wallet-metamask");
    let invalid_completion = wallet_request(
        &context,
        WalletProviderOperationV2::CompleteConnectorHandoff {
            request_id: request_id.clone(),
            payload_hash: payload_hash.clone(),
            signature: None,
            signature_type: None,
            public_key: None,
            signer: external_address.into(),
            transaction_hash: Some(transaction_hash.into()),
        },
    );
    let mut invalid_completion = serde_json::to_value(invalid_completion).unwrap();
    invalid_completion["operation"]["params"]["signature"] =
        json!("0xsigned-transaction-should-not-be-here");
    invalid_completion["operation"]["params"]["signature_type"] = json!("personal_sign");
    match decode_and_handle_outer(
        &mut provider,
        json!({
            "op": "wallet_contract",
            "request": invalid_completion,
            "_runtime_invocation": runtime_invocation_envelope(),
        }),
    ) {
        Response::Error { code, message } => {
            assert_eq!(code, "invalid_wallet_contract");
            assert!(message.contains("exactly one signature or transaction_hash"));
        }
        other => panic!("expected transaction signature rejection, got {other:?}"),
    }
    match invoke_wallet(
        &mut provider,
        principal_id,
        "wallet-metamask",
        WalletProviderOperationV2::CompleteConnectorHandoff {
            request_id: request_id.clone(),
            payload_hash: payload_hash.clone(),
            signature: None,
            signature_type: None,
            public_key: None,
            signer: external_address.into(),
            transaction_hash: Some(transaction_hash.into()),
        },
    ) {
        Response::Ok { data: Some(data) } => {
            assert_eq!(data["approval_request"]["status"], "completed");
            assert_eq!(
                data["approval_request"]["signed_result"]["schema"],
                "elastos.wallet.external-transaction-result/v1"
            );
            assert_eq!(
                data["approval_request"]["signed_result"]["transaction_hash"],
                transaction_hash
            );
            assert_eq!(
                data["approval_request"]["signed_result"]["page_url"],
                "https://ela.city/cinema/view/test"
            );
            assert_eq!(
                data["approval_request"]["signed_result"]["origin"],
                "https://ela.city"
            );
        }
        other => panic!("expected external transaction completion, got {other:?}"),
    };

    let outcome = ValidatedChainOutcomeV1 {
        schema: elastos_wallet_contract::VALIDATED_CHAIN_OUTCOME_SCHEMA.to_string(),
        approval_request_id: request_id.clone(),
        account_id: external_account_id,
        chain_namespace: "eip155:20".into(),
        network: elastos_wallet_contract::PublicNetwork::new("esc-mainnet").unwrap(),
        binding: ValidatedChainOutcomeBindingV1::ExternalConnector {
            connector_id: "wallet-metamask".into(),
            originating_address: external_address.into(),
        },
        transaction_hash: transaction_hash.into(),
        chain_observation: json!({
            "network": "esc-mainnet",
            "hash": transaction_hash,
            "transaction": {
                "hash": transaction_hash,
                "from": external_address,
                "blockNumber": "0x2a"
            }
        }),
        confirmed_at: now_ts(),
    };
    for _ in 0..2 {
        match invoke_wallet(
            &mut provider,
            principal_id,
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome {
                outcome: outcome.clone(),
            },
        ) {
            Response::Ok { .. } => {}
            other => panic!("expected external Chain outcome projection, got {other:?}"),
        }
    }

    let mut substituted = outcome;
    substituted.chain_observation["transaction"]["from"] =
        json!("0x4444444444444444444444444444444444444444");
    assert!(matches!(
        invoke_wallet(
            &mut provider,
            principal_id,
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome {
                outcome: substituted,
            },
        ),
        Response::Error { ref code, .. } if code == "chain_outcome_conflict"
    ));
}

/// A lapsed approval is replaced by its retry, not duplicated beside it.
///
/// The request id is derived from what is being approved, so a second attempt
/// at the same thing arrives under the same id. Two records sharing one
/// identity make the exact-effect lookup refuse as a conflict, which would
/// wedge the retry this allows -- a mint whose wallet prompt went unanswered
/// for ten minutes would strand its published content and provisioned custody
/// with no way back to a prompt.
#[test]
fn an_expired_approval_is_replaced_by_a_retry_under_the_same_request_id() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal_id = "person:local:alice";
    let (account_id, address) = match invoke_wallet(
        &mut provider,
        principal_id,
        "wallet",
        WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".into(),
            label: None,
            create_new: false,
        },
    ) {
        Response::Ok { data: Some(data) } => (
            data["account"]["account_id"].as_str().unwrap().to_string(),
            data["account"]["address"].as_str().unwrap().to_string(),
        ),
        other => panic!("expected managed account, got {other:?}"),
    };
    let mut payload = transaction_intent_payload(&address);
    payload["page_url"] = json!("https://ela.city/cinema/view/test");
    payload["origin"] = json!("https://ela.city");
    payload["network"] = json!({ "id": "esc-mainnet" });

    let context = wallet_context(principal_id, "system");
    let request_id = "wallet-request:00000000000000000000000000abcdef".to_string();
    let approval_for =
        |expires_at: u64, payload: Value| WalletProviderOperationV2::RequestApproval {
            account_id: account_id.clone(),
            chain_namespace: "eip155:20".into(),
            intent: "transaction_intent".into(),
            resource: "elastos://chain/esc-mainnet/broadcast_transaction".into(),
            reason: "Send EVM transaction".into(),
            payload,
            expires_at,
        };
    let send = |provider: &mut WalletProvider, operation| {
        let now = now_ts();
        let request = WalletProviderRequestV2::new(
            &context,
            request_id.clone(),
            now,
            now.saturating_add(120),
            operation,
        )
        .expect("test Wallet request must be valid");
        invoke_wallet_request(provider, &request)
    };

    // Raised with the shortest life the validator accepts, then left to lapse.
    match send(
        &mut provider,
        approval_for(now_ts().saturating_add(1), payload.clone()),
    ) {
        Response::Ok { .. } => {}
        other => panic!("expected the first approval to be raised, got {other:?}"),
    }
    std::thread::sleep(std::time::Duration::from_millis(1500));

    match send(
        &mut provider,
        approval_for(now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS), payload),
    ) {
        Response::Ok { .. } => {}
        other => panic!("expected the retry to be raised, got {other:?}"),
    }

    let listed = match invoke_wallet(
        &mut provider,
        principal_id,
        "system",
        WalletProviderOperationV2::ListApprovals {
            include_resolved: true,
        },
    ) {
        Response::Ok { data: Some(data) } => data,
        other => panic!("expected an approval listing, got {other:?}"),
    };
    let sharing_the_id: Vec<_> = listed["approval_requests"]
        .as_array()
        .expect("approval listing must be an array")
        .iter()
        .filter(|request| request["request_id"].as_str() == Some(request_id.as_str()))
        .collect();
    assert_eq!(
        sharing_the_id.len(),
        1,
        "one identity must name one approval, got {sharing_the_id:?}"
    );
    assert_eq!(
        sharing_the_id[0]["status"].as_str(),
        Some("pending"),
        "the surviving approval must be the retry, still awaiting an answer"
    );
}

/// The narrowing above reaches lapsed approvals and nothing else.
///
/// Declining is an answer. If a rejected approval could be re-asked under its
/// own identity, a caller could keep asking until it got a different one, and
/// the request id would stop meaning one exact request for the case that
/// matters most.
#[test]
fn a_rejected_approval_is_not_replaceable_under_the_same_request_id() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal_id = "person:local:alice";
    let (account_id, address) = match invoke_wallet(
        &mut provider,
        principal_id,
        "wallet",
        WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".into(),
            label: None,
            create_new: false,
        },
    ) {
        Response::Ok { data: Some(data) } => (
            data["account"]["account_id"].as_str().unwrap().to_string(),
            data["account"]["address"].as_str().unwrap().to_string(),
        ),
        other => panic!("expected managed account, got {other:?}"),
    };
    let mut payload = transaction_intent_payload(&address);
    payload["page_url"] = json!("https://ela.city/cinema/view/test");
    payload["origin"] = json!("https://ela.city");
    payload["network"] = json!({ "id": "esc-mainnet" });

    let context = wallet_context(principal_id, "system");
    let request_id = "wallet-request:00000000000000000000000000fedcba".to_string();
    let send = |provider: &mut WalletProvider, expires_at: u64, payload: Value| {
        let now = now_ts();
        let request = WalletProviderRequestV2::new(
            &context,
            request_id.clone(),
            now,
            now.saturating_add(120),
            WalletProviderOperationV2::RequestApproval {
                account_id: account_id.clone(),
                chain_namespace: "eip155:20".into(),
                intent: "transaction_intent".into(),
                resource: "elastos://chain/esc-mainnet/broadcast_transaction".into(),
                reason: "Send EVM transaction".into(),
                payload,
                expires_at,
            },
        )
        .expect("test Wallet request must be valid");
        invoke_wallet_request(provider, &request)
    };

    match send(
        &mut provider,
        now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        payload.clone(),
    ) {
        Response::Ok { .. } => {}
        other => panic!("expected the approval to be raised, got {other:?}"),
    }
    match invoke_wallet(
        &mut provider,
        principal_id,
        "system",
        WalletProviderOperationV2::RejectApproval {
            request_id: request_id.clone(),
            reason: "not now".into(),
        },
    ) {
        Response::Ok { .. } => {}
        other => panic!("expected the approval to be rejected, got {other:?}"),
    }

    // Same identity, different request: refused, because the answer stands.
    match send(
        &mut provider,
        now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS / 2),
        payload,
    ) {
        Response::Error { code, .. } => assert_eq!(code, "approval_identity_conflict"),
        other => panic!("a rejected approval must not be replaceable, got {other:?}"),
    }
}

fn managed_esc_account(provider: &mut WalletProvider, principal_id: &str) -> (String, String) {
    match invoke_wallet(
        provider,
        principal_id,
        "wallet",
        WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".into(),
            label: None,
            create_new: false,
        },
    ) {
        Response::Ok { data: Some(data) } => (
            data["account"]["account_id"].as_str().unwrap().to_string(),
            data["account"]["address"].as_str().unwrap().to_string(),
        ),
        other => panic!("expected managed account, got {other:?}"),
    }
}

fn request_base_transaction(
    provider: &mut WalletProvider,
    principal_id: &str,
    account_id: &str,
    payload: Value,
) -> String {
    match invoke_wallet(
        provider,
        principal_id,
        "system",
        WalletProviderOperationV2::RequestApproval {
            account_id: account_id.to_string(),
            chain_namespace: "eip155:8453".into(),
            intent: "transaction_intent".into(),
            resource: "elastos://chain/base-mainnet/broadcast_transaction".into(),
            reason: "Mint on Base".into(),
            payload,
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    ) {
        Response::Ok { data: Some(data) } => data["approval_request"]["request_id"]
            .as_str()
            .unwrap()
            .to_string(),
        other => panic!("expected a Base transaction approval, got {other:?}"),
    }
}

/// One EVM key is one address on every EVM chain. The built-in account Home
/// creates on Elastos Smart Chain must sign the Base mint it was asked for.
#[test]
fn managed_evm_account_signs_a_transaction_on_another_evm_chain() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal_id = "person:local:alice";
    let (account_id, address) = managed_esc_account(&mut provider, principal_id);
    let mut payload = transaction_intent_payload(&address);
    payload["chain_id"] = json!(8453);
    payload["network"] = json!({ "id": "base-mainnet" });
    let request_id = request_base_transaction(&mut provider, principal_id, &account_id, payload);

    match invoke_wallet(
        &mut provider,
        principal_id,
        "system",
        WalletProviderOperationV2::ApproveAndSignManaged {
            request_id,
            reason: "Approved mint".into(),
        },
    ) {
        Response::Ok { data: Some(data) } => {
            assert_eq!(data["approval_request"]["status"], "completed");
            assert_eq!(data["approval_request"]["chain_namespace"], "eip155:8453");
            assert_eq!(data["signed_payload"]["chain_namespace"], "eip155:8453");
            // EIP-155: v = chain_id * 2 + 35 + recovery id, so 16941 or 16942
            // proves the signature is valid on Base and nowhere else.
            let signed_transaction = data["signed_transaction"].as_str().unwrap();
            let v = legacy_transaction_v(signed_transaction);
            assert!(v == 16941 || v == 16942, "v = {v}");
        }
        other => panic!("expected the Base transaction to be signed, got {other:?}"),
    }
}

/// The signed transaction carries the payload chain_id. It must be the chain
/// the person approved, or the signature would be valid somewhere else. A
/// mismatch is refused before any passkey prompt, and again at signing.
#[test]
fn transaction_chain_id_must_match_the_approved_chain() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal_id = "person:local:alice";
    let (account_id, address) = managed_esc_account(&mut provider, principal_id);
    // Approved on Base, but the transaction is built for Elastos Smart Chain.
    let mut mismatched = transaction_intent_payload(&address);
    mismatched["network"] = json!({ "id": "base-mainnet" });
    match invoke_wallet(
        &mut provider,
        principal_id,
        "system",
        WalletProviderOperationV2::RequestApproval {
            account_id: account_id.clone(),
            chain_namespace: "eip155:8453".into(),
            intent: "transaction_intent".into(),
            resource: "elastos://chain/base-mainnet/broadcast_transaction".into(),
            reason: "Mint on Base".into(),
            payload: mismatched.clone(),
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    ) {
        Response::Error { code, message } => {
            assert_eq!(code, "invalid_transaction_intent");
            assert_eq!(
                message,
                "This transaction is for a different network than the one approved."
            );
        }
        other => panic!("expected the chain_id mismatch to be refused, got {other:?}"),
    }
    assert!(provider.store.approval_requests.is_empty());

    let mut matching = mismatched.clone();
    matching["chain_id"] = json!(8453);
    let request_id = request_base_transaction(&mut provider, principal_id, &account_id, matching);
    // A stored request whose payload changed after review is refused too.
    provider.store.approval_requests[0].payload_hash = value_hash(&mismatched);
    provider.store.approval_requests[0].payload = mismatched;

    match invoke_wallet(
        &mut provider,
        principal_id,
        "system",
        WalletProviderOperationV2::ApproveAndSignManaged {
            request_id,
            reason: "Approved mint".into(),
        },
    ) {
        Response::Error { code, message } => {
            assert_eq!(code, "invalid_transaction_intent");
            assert_eq!(
                message,
                "This transaction is for a different network than the one approved."
            );
        }
        other => panic!("expected the chain_id mismatch to be refused, got {other:?}"),
    }
    assert_ne!(
        provider.store.approval_requests[0].status,
        ApprovalStatus::Completed
    );
    assert!(provider.store.approval_requests[0].signed_result.is_none());
}

/// Only EVM chains share a key. A request recorded for a namespace the account
/// cannot serve is refused at signing with a plain reason.
#[test]
fn managed_signing_refuses_a_request_on_a_chain_the_account_cannot_serve() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal_id = "person:local:alice";
    let (account_id, address) = managed_esc_account(&mut provider, principal_id);
    let request_id = match invoke_wallet(
        &mut provider,
        principal_id,
        "browser",
        WalletProviderOperationV2::RequestApproval {
            account_id: account_id.clone(),
            chain_namespace: "eip155:20".into(),
            intent: "browser_personal_sign".into(),
            resource: "elastos://wallet/eip155:20/sign/browser_personal_sign".into(),
            reason: "Browser page requests personal_sign".into(),
            payload: browser_personal_sign_payload(&account_id, &address, "Hello"),
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    ) {
        Response::Ok { data: Some(data) } => data["approval_request"]["request_id"]
            .as_str()
            .unwrap()
            .to_string(),
        other => panic!("expected approval request, got {other:?}"),
    };
    provider.store.approval_requests[0].chain_namespace =
        BITCOIN_MAINNET_CHAIN_NAMESPACE.to_string();

    match invoke_wallet(
        &mut provider,
        principal_id,
        "browser",
        WalletProviderOperationV2::ApproveAndSignManaged {
            request_id,
            reason: "Approved".into(),
        },
    ) {
        Response::Error { code, message } => {
            assert_eq!(code, "signing_error");
            assert_eq!(
                message,
                "This account cannot sign on the requested network."
            );
        }
        other => panic!("expected the incompatible chain to be refused, got {other:?}"),
    }
    assert_ne!(
        provider.store.approval_requests[0].status,
        ApprovalStatus::Completed
    );
}

#[test]
fn managed_bitcoin_account_is_refused_for_an_evm_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal_id = "person:local:alice";
    let (account_id, address) = match invoke_wallet(
        &mut provider,
        principal_id,
        "wallet",
        WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: BITCOIN_MAINNET_CHAIN_NAMESPACE.into(),
            label: None,
            create_new: false,
        },
    ) {
        Response::Ok { data: Some(data) } => (
            data["account"]["account_id"].as_str().unwrap().to_string(),
            data["account"]["address"].as_str().unwrap().to_string(),
        ),
        other => panic!("expected managed Bitcoin account, got {other:?}"),
    };
    let mut payload = transaction_intent_payload(&address);
    payload["chain_id"] = json!(8453);
    match invoke_wallet(
        &mut provider,
        principal_id,
        "system",
        WalletProviderOperationV2::RequestApproval {
            account_id,
            chain_namespace: "eip155:8453".into(),
            intent: "transaction_intent".into(),
            resource: "elastos://chain/base-mainnet/broadcast_transaction".into(),
            reason: "Mint on Base".into(),
            payload,
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    ) {
        Response::Error { code, .. } => assert_eq!(code, "invalid_request"),
        other => panic!("a Bitcoin account must not serve an EVM request, got {other:?}"),
    }
    assert!(provider.store.approval_requests.is_empty());
}

/// The `v` field of a signed legacy transaction: the seventh RLP list item.
fn legacy_transaction_v(signed_transaction: &str) -> u64 {
    let bytes = hex::decode(signed_transaction.trim_start_matches("0x")).unwrap();
    // A single item: (payload offset, payload length) after its header.
    let header = |bytes: &[u8], at: usize| -> (usize, usize) {
        let prefix = bytes[at];
        let long = |base: u8| {
            let width = usize::from(prefix - base);
            let length = bytes[at + 1..at + 1 + width]
                .iter()
                .fold(0usize, |length, byte| (length << 8) | usize::from(*byte));
            (at + 1 + width, length)
        };
        match prefix {
            0x00..=0x7f => (at, 1),
            0x80..=0xb7 => (at + 1, usize::from(prefix - 0x80)),
            0xb8..=0xbf => long(0xb7),
            0xc0..=0xf7 => (at + 1, usize::from(prefix - 0xc0)),
            _ => long(0xf7),
        }
    };
    let (mut at, _) = header(&bytes, 0);
    for _ in 0..6 {
        let (offset, length) = header(&bytes, at);
        at = offset + length;
    }
    let (offset, length) = header(&bytes, at);
    bytes[offset..offset + length]
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
}

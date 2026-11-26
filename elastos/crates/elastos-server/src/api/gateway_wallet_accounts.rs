use super::*;

pub(in crate::api::gateway) async fn system_wallet_accounts_summary(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
) -> SystemWalletAccountsSummary {
    let response = runtime_wallet_data(
        state,
        authority,
        elastos_wallet_contract::WalletProviderOperationV2::ListAccounts {
            include_revoked: false,
        },
    )
    .await;
    wallet_accounts_summary_from_response(response)
}

/// A projection of the two authority stores. Reading it grants neither use.
#[derive(Serialize)]
pub(super) struct WalletInventoryEntry {
    inventory_id: String,
    address: String,
    chain_namespace: String,
    pub(super) accounts: Vec<SystemWalletAccountSummary>,
    wallet_display_name: Option<String>,
    sign_in: Option<serde_json::Value>,
}

fn wallet_inventory_identity(namespace: &str, address: &str) -> (String, String) {
    let address = if namespace.starts_with("eip155:") {
        address.to_ascii_lowercase()
    } else {
        address.to_string()
    };
    (namespace.to_string(), address)
}

pub(super) fn wallet_inventory_entries(
    principal: &str,
    accounts: &[serde_json::Value],
    methods: &[serde_json::Value],
) -> Vec<WalletInventoryEntry> {
    let mut entries: Vec<WalletInventoryEntry> = Vec::new();
    for account in accounts {
        // The provider scopes the read too. Retain the owner check at the join.
        if account["principal_id"].as_str() != Some(principal) || !account["revoked_at"].is_null() {
            continue;
        }
        let Some(account) = system_wallet_account_summary(account) else {
            continue;
        };
        let (namespace, address) =
            wallet_inventory_identity(&account.chain_namespace, &account.address);
        if let Some(entry) = entries
            .iter_mut()
            .find(|entry| entry.chain_namespace == namespace && entry.address == address)
        {
            entry.accounts.push(account);
        } else {
            entries.push(WalletInventoryEntry {
                inventory_id: format!("{namespace}:{address}"),
                address,
                chain_namespace: namespace,
                accounts: vec![account],
                wallet_display_name: None,
                sign_in: None,
            });
        }
    }
    for method in methods {
        // Auth owns and filters these methods before returning this snapshot.
        let Some(address) = method["address"].as_str() else {
            continue;
        };
        let namespace = match (method["chain_id"].as_u64(), method["network"].as_str()) {
            (Some(0), Some("bitcoin")) => "bip122:000000000019d6689c085ae165831e93".to_string(),
            (Some(chain), Some("")) if chain > 0 => format!("eip155:{chain}"),
            _ => continue,
        };
        let (namespace, address) = wallet_inventory_identity(&namespace, address);
        if let Some(entry) = entries
            .iter_mut()
            .find(|entry| entry.chain_namespace == namespace && entry.address == address)
        {
            entry.sign_in = Some(method.clone());
        } else {
            entries.push(WalletInventoryEntry {
                inventory_id: format!("{namespace}:{address}"),
                address,
                chain_namespace: namespace,
                accounts: vec![],
                wallet_display_name: None,
                sign_in: Some(method.clone()),
            });
        }
    }
    for entry in &mut entries {
        // Revoked app links retain display data, while auth still owns sign-in.
        // They contribute zero app-use records to this projection.
        entry.wallet_display_name = entry
            .accounts
            .first()
            .and_then(|account| account.wallet_display_name.clone())
            .or_else(|| {
                let method = entry.sign_in.as_ref()?;
                accounts
                    .iter()
                    .filter(|account| {
                        account["principal_id"].as_str() == Some(principal)
                            && account["connector_id"].as_str() == method["connector"].as_str()
                            && account["chain_namespace"].as_str() == Some(&entry.chain_namespace)
                            && account["address"].as_str().is_some_and(|address| {
                                wallet_inventory_identity(&entry.chain_namespace, address).1
                                    == entry.address
                            })
                    })
                    .max_by_key(|account| account["linked_at"].as_u64().unwrap_or(0))
                    .and_then(|account| system_wallet_account_summary(account)?.wallet_display_name)
            });
    }
    entries.sort_by_key(|entry| {
        let connector = entry
            .accounts
            .first()
            .and_then(|account| account.connector_id.as_deref())
            .or_else(|| {
                entry
                    .sign_in
                    .as_ref()
                    .and_then(|method| method["connector"].as_str())
            });
        match connector {
            None => 0,
            Some("wallet-metamask") => 1,
            Some("wallet-unisat") => 2,
            _ => 3,
        }
    });
    entries
}

pub(in crate::api::gateway) async fn wallet_inventory(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    let result = async {
        let launch = require_home_launch_token_binding(
            &state.data_dir,
            &headers,
            &[HOME_CAPSULE_ID, SYSTEM_CAPSULE_ID, WALLET_CAPSULE_ID],
        )?;
        let authority = runtime_wallet_authority(&launch)?;
        let auth_dir = home_launch_auth_data_dir(&state.data_dir);
        let actor = crate::auth::load_active_session_grant(
            &auth_dir,
            &launch.context.session_id,
            now_ts(),
        )?;
        let methods = crate::auth::wallet_signin::list(&auth_dir, &actor)?;
        let accounts = runtime_wallet_data(
            &state,
            &authority,
            elastos_wallet_contract::WalletProviderOperationV2::ListAccounts {
                include_revoked: true,
            },
        )
        .await;
        let apps_available = accounts.is_ok();
        let accounts = accounts.unwrap_or_else(|_| serde_json::json!({"accounts":[]}));
        let entries = wallet_inventory_entries(
            &actor.principal_id,
            accounts["accounts"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Wallet accounts unavailable"))?,
            methods["methods"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Wallet sign-in methods unavailable"))?,
        );
        Ok::<_, anyhow::Error>(serde_json::json!({
            "schema": "elastos.wallet.inventory/v1",
            "principal_id": actor.principal_id,
            "account_name": methods["account_name"],
            "apps_available": apps_available,
            "entries": entries,
        }))
    }
    .await;
    let mut response = match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => system_error_response(error),
    };
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn cleanup_removed_walletconnect_account(
    data_dir: &FsPath,
    data: &serde_json::Value,
) -> anyhow::Result<()> {
    let account = &data["account"];
    if account["connector_id"] == WALLET_WALLETCONNECT_CAPSULE_ID
        && !account["revoked_at"].is_null()
        && data["connector_accounts_remaining"] == 0
    {
        let owner = account["principal_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Removed account owner is missing"))?;
        gateway_walletconnect::clear_principal_storage(data_dir, owner)?;
    }
    Ok(())
}

pub(in crate::api::gateway) async fn runtime_wallet_data(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    operation: elastos_wallet_contract::WalletProviderOperationV2,
) -> anyhow::Result<serde_json::Value> {
    let registry = state
        .provider_registry
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("wallet provider unavailable"))?;
    match RuntimeWalletAdapter::new(registry, authority)
        .invoke(operation)
        .await?
        .result
    {
        elastos_wallet_contract::WalletResultV2::Ok { data } => {
            if cleanup_removed_walletconnect_account(&state.data_dir, &data).is_err() {
                tracing::warn!(
                    "WalletConnect session cleanup requires operator retry after account removal"
                );
            }
            Ok(data)
        }
        elastos_wallet_contract::WalletResultV2::Error { message, .. } => anyhow::bail!(message),
    }
}

pub(in crate::api::gateway) async fn runtime_wallet_data_with_request_id(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    request_id: String,
    operation: elastos_wallet_contract::WalletProviderOperationV2,
) -> anyhow::Result<serde_json::Value> {
    let registry = state
        .provider_registry
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("wallet provider unavailable"))?;
    match RuntimeWalletAdapter::new(registry, authority)
        .invoke_with_request_id(request_id, operation)
        .await?
        .result
    {
        elastos_wallet_contract::WalletResultV2::Ok { data } => {
            if cleanup_removed_walletconnect_account(&state.data_dir, &data).is_err() {
                tracing::warn!(
                    "WalletConnect session cleanup requires operator retry after account removal"
                );
            }
            Ok(data)
        }
        elastos_wallet_contract::WalletResultV2::Error { message, .. } => anyhow::bail!(message),
    }
}

fn wallet_accounts_summary_from_response(
    response: anyhow::Result<serde_json::Value>,
) -> SystemWalletAccountsSummary {
    match response {
        Ok(data) => {
            let accounts = data
                .get("accounts")
                .and_then(|value| value.as_array())
                .into_iter()
                .flatten()
                .filter_map(system_wallet_account_summary)
                .collect::<Vec<_>>();
            let default_accounts = data
                .get("default_accounts")
                .and_then(|value| value.as_array())
                .into_iter()
                .flatten()
                .filter_map(system_wallet_default_summary)
                .collect::<Vec<_>>();
            SystemWalletAccountsSummary {
                available: true,
                linked_count: accounts.len(),
                accounts,
                default_accounts,
                note: None,
            }
        }
        Err(err) => SystemWalletAccountsSummary {
            available: false,
            note: Some(err.to_string()),
            ..SystemWalletAccountsSummary::default()
        },
    }
}

pub(in crate::api::gateway) fn system_wallet_account_summary(
    value: &serde_json::Value,
) -> Option<SystemWalletAccountSummary> {
    Some(SystemWalletAccountSummary {
        provider_id: value
            .get("provider_id")
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        wallet_display_name: value
            .get("wallet_display_name")
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        wallet_mark: value
            .get("wallet_mark")
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        account_id: value.get("account_id")?.as_str()?.to_string(),
        chain_namespace: value.get("chain_namespace")?.as_str()?.to_string(),
        address: value.get("address")?.as_str()?.to_string(),
        proof_type: value.get("proof_type")?.as_str()?.to_string(),
        signing_available: value
            .get("signing_available")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        signing_status: value
            .get("signing_status")
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        label: value
            .get("label")
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        connector_id: value
            .get("connector_id")
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        linked_at: value.get("linked_at")?.as_u64()?,
    })
}

pub(in crate::api::gateway) fn system_wallet_default_summary(
    value: &serde_json::Value,
) -> Option<SystemWalletDefaultSummary> {
    Some(SystemWalletDefaultSummary {
        chain_namespace: value.get("chain_namespace")?.as_str()?.to_string(),
        intent: value.get("intent")?.as_str()?.to_string(),
        account_id: value.get("account_id")?.as_str()?.to_string(),
        set_at: value.get("set_at")?.as_u64()?,
    })
}

pub(in crate::api::gateway) async fn system_wallet_managed_create(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<SystemWalletManagedCreateRequest>,
) -> Response {
    let authority =
        match require_runtime_wallet_authority(&state.data_dir, &headers, &[SYSTEM_CAPSULE_ID]) {
            Ok(authority) => authority,
            Err(err) => return system_error_response(err),
        };
    let context = authority.home_launch_context();
    create_managed_wallet_accounts(&state, &context, &authority, input, SYSTEM_CAPSULE_ID).await
}

pub(in crate::api::gateway) async fn create_managed_wallet_accounts(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    authority: &RuntimeWalletAuthority,
    input: SystemWalletManagedCreateRequest,
    capsule_id: &'static str,
) -> Response {
    let chain_namespaces = input
        .chain_namespace
        .map(|namespace| vec![namespace])
        .unwrap_or_else(|| {
            MANAGED_WALLET_CHAIN_NAMESPACES
                .iter()
                .map(|namespace| (*namespace).to_string())
                .collect()
        });
    for chain_namespace in chain_namespaces {
        let label = input
            .label
            .clone()
            .unwrap_or_else(|| managed_wallet_label(&chain_namespace));
        if let Err(err) = runtime_wallet_data(
            state,
            authority,
            elastos_wallet_contract::WalletProviderOperationV2::CreateManagedAccount {
                chain_namespace,
                label: Some(label),
                create_new: input.create_new,
            },
        )
        .await
        {
            return system_error_response(err);
        }
    }
    let _ = append_wallet_approval_audit(
        &state.data_dir,
        WalletApprovalAuditInput {
            capsule_id,
            event_type: "wallet.managed.created",
            principal_id: &context.principal_id,
            session_id: &context.session_id,
            request_id: "wallet-managed",
            result: "ok",
            reason: if capsule_id == SYSTEM_CAPSULE_ID {
                "Built-in managed wallet accounts created through System"
            } else {
                "Built-in managed wallet accounts created through Wallet"
            },
        },
    );
    Json(system_wallet_accounts_summary(state, authority).await).into_response()
}

pub(in crate::api::gateway) async fn system_wallet_default_update(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<SystemWalletDefaultRequest>,
) -> Response {
    let authority =
        match require_runtime_wallet_authority(&state.data_dir, &headers, &[SYSTEM_CAPSULE_ID]) {
            Ok(authority) => authority,
            Err(err) => return system_error_response(err),
        };
    let context = authority.home_launch_context();
    update_default_wallet_account(&state, &context, &authority, input, SYSTEM_CAPSULE_ID).await
}

pub(in crate::api::gateway) async fn update_default_wallet_account(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    authority: &RuntimeWalletAuthority,
    input: SystemWalletDefaultRequest,
    capsule_id: &'static str,
) -> Response {
    let account_id = input.account_id.clone();
    let chain_namespace = input.chain_namespace.clone();
    let intent = input.intent.clone();
    let mirror_browser_default =
        chain_namespace.starts_with("eip155:") && intent == "transaction_intent";
    match runtime_wallet_data(
        state,
        authority,
        elastos_wallet_contract::WalletProviderOperationV2::SetDefaultAccount {
            chain_namespace: chain_namespace.clone(),
            intent: intent.clone(),
            account_id: account_id.clone(),
        },
    )
    .await
    {
        Ok(_) => {
            if mirror_browser_default {
                if let Err(err) = runtime_wallet_data(
                    state,
                    authority,
                    elastos_wallet_contract::WalletProviderOperationV2::SetDefaultAccount {
                        chain_namespace: chain_namespace.clone(),
                        intent: "browser_connect".to_string(),
                        account_id: account_id.clone(),
                    },
                )
                .await
                {
                    return system_error_response(err);
                }
            }
            let _ = append_wallet_approval_audit(
                &state.data_dir,
                WalletApprovalAuditInput {
                    capsule_id,
                    event_type: "wallet.default.updated",
                    principal_id: &context.principal_id,
                    session_id: &context.session_id,
                    request_id: "wallet-default",
                    result: "ok",
                    reason: if capsule_id == SYSTEM_CAPSULE_ID {
                        "Default wallet account updated through System"
                    } else {
                        "Default wallet account updated through Wallet"
                    },
                },
            );
            Json(system_wallet_accounts_summary(state, authority).await).into_response()
        }
        Err(err) => system_error_response(err),
    }
}

pub(in crate::api::gateway) async fn wallet_app_summary(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    let authority = match require_wallet_app_launch_authority(&state.data_dir, &headers) {
        Ok(authority) => authority,
        Err(err) => return system_error_response(err),
    };
    let (wallet_accounts, wallet_approvals) = tokio::join!(
        system_wallet_accounts_summary(&state, &authority),
        system_wallet_approvals_summary(&state, &authority, true)
    );
    Json(serde_json::json!({
        "app": {
            "id": WALLET_CAPSULE_ID,
            "title": "Wallet",
        },
        "approval_methods": wallet_approval_methods_summary(&state.data_dir).await,
        "wallet_accounts": wallet_accounts,
        "wallet_approvals": wallet_approvals,
    }))
    .into_response()
}

async fn wallet_approval_methods_summary(data_dir: &FsPath) -> serde_json::Value {
    let walletconnect_available =
        ensure_wallet_connector_configured_async(data_dir, WALLET_WALLETCONNECT_CAPSULE_ID)
            .await
            .is_ok();
    serde_json::json!({
        "schema": "elastos.wallet.approval-methods/v1",
        "metamask": {
            "available": true,
            "connector_id": WALLET_METAMASK_CAPSULE_ID,
        },
        "unisat": {
            "available": true,
            "connector_id": WALLET_UNISAT_CAPSULE_ID,
        },
        "walletconnect": {
            "available": walletconnect_available,
            "connector_id": WALLET_WALLETCONNECT_CAPSULE_ID,
            "requires_pinned_config": !walletconnect_available,
        },
    })
}

#[cfg(test)]
mod walletconnect_cleanup_tests {
    use super::*;
    #[test]
    fn walletconnect_account_cleanup_uses_owner_and_keeps_other_accounts_pairing() {
        let data = tempfile::tempdir().unwrap();
        for principal in ["owner", "caller"] {
            assert_eq!(
                gateway_walletconnect::storage_revision(data.path(), principal).unwrap(),
                "\"0\""
            );
        }
        let mut response = serde_json::json!({"account":{"connector_id":WALLET_WALLETCONNECT_CAPSULE_ID,
            "principal_id":"owner","revoked_at":1},"connector_accounts_remaining":1});
        cleanup_removed_walletconnect_account(data.path(), &response).unwrap();
        assert_eq!(
            gateway_walletconnect::storage_revision(data.path(), "owner").unwrap(),
            "\"0\""
        );
        response["connector_accounts_remaining"] = serde_json::json!(0);
        cleanup_removed_walletconnect_account(data.path(), &response).unwrap();
        assert_eq!(
            gateway_walletconnect::storage_revision(data.path(), "owner").unwrap(),
            "\"1\""
        );
        assert_eq!(
            gateway_walletconnect::storage_revision(data.path(), "caller").unwrap(),
            "\"0\""
        );
    }
}

#[cfg(test)]
mod wallet_inventory_tests {
    use super::*;
    use serde_json::{json, Value};

    fn account(owner: &str, namespace: &str, address: &str) -> Value {
        json!({"account_id":"app-link", "principal_id":owner,
            "chain_namespace":namespace, "address":address, "proof_type":"eip191",
            "connector_id":"wallet-metamask", "linked_at":1})
    }

    #[test]
    fn wallet_inventory_keeps_signin_when_home_address_collides() {
        for (namespace, proof, connector, chain, network, address) in [
            (
                "eip155:20",
                "managed_evm",
                "wallet-metamask",
                20,
                "",
                "0x1234",
            ),
            (
                "eip155:8453",
                "managed_evm",
                "wallet-metamask",
                8453,
                "",
                "0x1234",
            ),
            (
                "bip122:000000000019d6689c085ae165831e93",
                "managed_btc_p2wpkh",
                "wallet-unisat",
                0,
                "bitcoin",
                "bc1qverified",
            ),
        ] {
            let mut managed = account("owner", namespace, address);
            managed["proof_type"] = json!(proof);
            managed["connector_id"] = Value::Null;
            let method = json!({"proof_binding_id":"signin", "connector":connector, "address":address, "chain_id":chain, "network":network});
            let entries =
                wallet_inventory_entries("owner", &[managed], std::slice::from_ref(&method));
            assert_eq!(entries.len(), 1);
            assert_eq!(
                entries[0].sign_in.as_ref(),
                Some(&method),
                "{namespace}: a stored sign-in method stays visible"
            );
        }
    }

    #[test]
    fn wallet_inventory_projects_each_use_and_removal_without_changing_authority() {
        let f = crate::auth::wallet_signin::tests::fixture();
        crate::auth::wallet_signin::tests::enabled(&f);
        let methods = crate::auth::wallet_signin::list(f.data.path(), &f.actor).unwrap();
        let methods = methods["methods"].as_array().unwrap();
        let accounts = vec![account(
            &f.actor.principal_id,
            "eip155:20",
            &f.address.to_uppercase().replace("0X", "0x"),
        )];
        let project = |accounts: &[Value], methods: &[Value]| {
            wallet_inventory_entries(&f.actor.principal_id, accounts, methods)
        };
        let signin_only = project(&[], methods);
        assert_eq!(signin_only.len(), 1);
        assert!(signin_only[0].accounts.is_empty());
        assert!(signin_only[0].sign_in.is_some());
        let app_only = project(&accounts, &[]);
        assert_eq!(app_only.len(), 1);
        assert!(app_only[0].sign_in.is_none());
        let both = project(&accounts, methods);
        assert_eq!(both.len(), 1);
        assert_eq!(both[0].accounts.len(), 1);
        assert!(both[0].sign_in.is_some());
        assert_eq!(both[0].inventory_id, signin_only[0].inventory_id);
        // The same identity remains after either owner removes its own use.
        assert_eq!(project(&[], methods)[0].inventory_id, both[0].inventory_id);
        assert_eq!(
            project(&accounts, &[])[0].inventory_id,
            both[0].inventory_id
        );
        assert!(project(&[], &[]).is_empty());
        let other_network = vec![account(&f.actor.principal_id, "eip155:8453", &f.address)];
        assert_eq!(project(&other_network, methods).len(), 2);
        let mut revoked = accounts[0].clone();
        revoked["revoked_at"] = json!(2);
        assert!(project(&[revoked], &[]).is_empty());
        assert!(project(&[account("another-account", "eip155:20", &f.address)], &[]).is_empty());
    }

    #[test]
    fn wallet_inventory_removal_keeps_peer_display_without_app_authority() {
        let mut app = account("owner", "eip155:8453", "0x1234");
        app["connector_id"] = json!("wallet-walletconnect");
        app["wallet_display_name"] = json!("Rainbow");
        app["revoked_at"] = json!(2);
        let method = json!({"proof_binding_id":"signin", "connector":"wallet-walletconnect", "address":"0x1234", "chain_id":8453, "network":""});
        let entries = wallet_inventory_entries(
            "owner",
            std::slice::from_ref(&app),
            std::slice::from_ref(&method),
        );
        assert_eq!(entries.len(), 1);
        assert!(entries[0].accounts.is_empty());
        assert_eq!(entries[0].wallet_display_name.as_deref(), Some("Rainbow"));
        app["principal_id"] = json!("another-account");
        assert!(wallet_inventory_entries("owner", &[app], &[method])[0]
            .wallet_display_name
            .is_none());
    }

    #[test]
    fn wallet_inventory_keeps_bitcoin_network_and_connector_identity_separate() {
        let method = json!({"proof_binding_id":"signin", "connector":"wallet-unisat", "address":"bc1qverified", "chain_id":0, "network":"bitcoin"});
        let mut app = account(
            "owner",
            "bip122:000000000019d6689c085ae165831e93",
            "bc1qverified",
        );
        app["connector_id"] = json!("wallet-unisat");
        let entries = wallet_inventory_entries(
            "owner",
            std::slice::from_ref(&app),
            std::slice::from_ref(&method),
        );
        assert_eq!(entries.len(), 1);
        assert!(entries[0].sign_in.is_some());
        app["chain_namespace"] = json!("bip122:testnet");
        assert_eq!(
            wallet_inventory_entries("owner", &[app], &[method]).len(),
            2
        );
    }
}

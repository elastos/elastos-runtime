use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedProtectedContentPurchase {
    schema: String,
    network: String,
    purchase_quantity: String,
    verified_listing: ResolvedProtectedContentPurchaseListing,
    steps: Vec<ResolvedProtectedContentPurchaseStep>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedProtectedContentPurchaseListing {
    chain_id: u64,
    seller: String,
    ledger: String,
    token_id: String,
    operative: String,
    available_quantity: String,
    price: String,
    pay_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payment_processor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedProtectedContentPurchaseStep {
    stage: String,
    to: String,
    value: String,
    data: String,
}

type ResolvedProtectedContentPurchaseAccess =
    crate::protected_content_runtime::RuntimeCustodyPurchaseAccessEvidenceRecord;

async fn resolve_runtime_custody_buyer_account(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    chain_namespace: &str,
) -> anyhow::Result<RuntimeCustodyCreatorAccount> {
    resolve_runtime_custody_wallet_default_account(
        state,
        authority,
        chain_namespace,
        crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_DENIED_MESSAGE,
    )
    .await
}

fn runtime_custody_purchase_chain_id(chain_namespace: &str) -> anyhow::Result<u64> {
    runtime_custody_creator_chain_id(chain_namespace).map_err(purchase_unavailable!())
}

fn runtime_custody_purchase_availability_receipt_digest(
    availability: &elastos_protected_content_runtime::RuntimeVerifiedContentAvailability,
) -> String {
    format!(
        "sha256:{}",
        hex::encode(availability.receipt_digest().as_bytes())
    )
}

fn runtime_custody_buy_terminal_response(
    purchase: &crate::protected_content_runtime::RuntimeCustodyPurchaseRecord,
) -> serde_json::Value {
    serde_json::json!({
        "schema": crate::protected_content_runtime::RUNTIME_PURCHASE_SCHEMA_V1,
        "mint_id": purchase.mint_id,
        "content_id": purchase.content_id,
        "cid": purchase.cid,
        "availability": {
            "schema": "elastos.library.runtime-custody-availability/v1",
            "status": "buyer_owned",
            "cid": purchase.cid,
            "content_id": purchase.content_id,
            "mint_id": purchase.mint_id,
        },
    })
}

fn runtime_custody_purchase_stage_record(
    stage: &str,
    request: &RuntimeTransactionRequest,
) -> anyhow::Result<crate::protected_content_runtime::RuntimeCustodyPurchaseStageRecord> {
    Ok(
        crate::protected_content_runtime::RuntimeCustodyPurchaseStageRecord {
            stage: stage.to_string(),
            effect_id: request.effect_id.clone(),
            approval_request_id: wallet_request_id(&request.effect_id, "approval"),
            request_sha256: request.request_sha256.clone(),
            chain_namespace: request.chain_namespace.clone(),
            network: request.network.clone(),
            to: request.to.clone(),
            value: request.value.clone(),
            data: request.data.clone(),
        },
    )
}

fn runtime_custody_purchase_transaction_request(
    principal_id: &str,
    buyer_account: &RuntimeCustodyCreatorAccount,
    listing: &crate::protected_content_runtime::RuntimePortableListingPackage,
    listing_sha256: &str,
    mint_id: elastos_protected_content_contracts::Digest32,
    stage: &ResolvedProtectedContentPurchaseStep,
) -> anyhow::Result<RuntimeTransactionRequest> {
    let stable_request = serde_json::json!({
        "domain": "elastos.protected-content.purchase-request/v1",
        "effect_id": "",
        "wallet_account_id": buyer_account.account_id,
        "address": buyer_account.address,
        "chain_namespace": listing.chain_namespace,
        "network": listing.network,
        "to": stage.to,
        "value": stage.value,
        "data": stage.data,
        "listing_sha256": listing_sha256,
        "mint_id": hex::encode(mint_id.as_bytes()),
        "seller": listing.seller_address,
        "ledger": listing.ledger,
        "token_id": listing.token_id,
        "operative": listing.operative,
        "price": listing.price,
        "pay_token": listing.pay_token,
        "purchase_quantity": "0x1",
        "stage": stage.stage,
    });
    let request_sha256 = runtime_transaction_request_sha256(&stable_request)?;
    let mut request = RuntimeTransactionRequest {
        source: NATIVE_TRANSACTION_SOURCE,
        effect_id: String::new(),
        request_sha256,
        account_id: buyer_account.account_id.clone(),
        address: buyer_account.address.clone(),
        chain_namespace: listing.chain_namespace.clone(),
        network: listing.network.clone(),
        to: stage.to.clone(),
        value: stage.value.clone(),
        data: stage.data.clone(),
        approval_reason: "Buy protected content access".to_string(),
        metadata: serde_json::json!({
            "product_operation": format!("protected_content_purchase_{}", stage.stage),
            "mint_id": hex::encode(mint_id.as_bytes()),
            "listing_sha256": listing_sha256,
            "seller": listing.seller_address,
            "ledger": listing.ledger,
            "token_id": listing.token_id,
            "price": listing.price,
            "pay_token": listing.pay_token,
            "purchase_quantity": "0x1",
        }),
    };
    let request_binding = transaction_request_binding(&request);
    request.effect_id = exact_runtime_transaction_effect_id(
        NATIVE_TRANSACTION_SOURCE,
        principal_id,
        &request.request_sha256,
        &request_binding,
    )?;
    Ok(request)
}

fn validate_runtime_custody_purchase_stage_request(
    principal_id: &str,
    buyer_account: &RuntimeCustodyCreatorAccount,
    listing: &crate::protected_content_runtime::RuntimePortableListingPackage,
    listing_sha256: &str,
    mint_id: elastos_protected_content_contracts::Digest32,
    stage: &crate::protected_content_runtime::RuntimeCustodyPurchaseStageRecord,
    expected_stage: &str,
) -> anyhow::Result<RuntimeTransactionRequest> {
    let request = runtime_custody_purchase_transaction_request(
        principal_id,
        buyer_account,
        listing,
        listing_sha256,
        mint_id,
        &ResolvedProtectedContentPurchaseStep {
            stage: stage.stage.clone(),
            to: stage.to.clone(),
            value: stage.value.clone(),
            data: stage.data.clone(),
        },
    )?;
    if stage.stage != expected_stage
        || stage.effect_id != request.effect_id
        || stage.approval_request_id != wallet_request_id(&request.effect_id, "approval")
        || stage.request_sha256 != request.request_sha256
        || stage.chain_namespace != request.chain_namespace
        || stage.network != request.network
        || stage.to != request.to
        || stage.value != request.value
        || stage.data != request.data
    {
        return Err(purchase_denied_missing!()());
    }
    Ok(request)
}

struct RuntimeCustodyExpectedPurchaseIdentity<'a> {
    principal_id: &'a str,
    profile_did: &'a str,
    mint_id_hex: &'a str,
    content_id: &'a str,
    content_cid: &'a str,
    listing_sha256: &'a str,
    listing: &'a crate::protected_content_runtime::RuntimePortableListingPackage,
    buyer_account: &'a RuntimeCustodyCreatorAccount,
}

fn validate_runtime_custody_purchase_record_identity(
    purchase: &crate::protected_content_runtime::RuntimeCustodyPurchaseRecord,
    expected: &RuntimeCustodyExpectedPurchaseIdentity<'_>,
) -> anyhow::Result<()> {
    if purchase.schema != crate::protected_content_runtime::RUNTIME_PURCHASE_SCHEMA_V1
        || purchase.principal_id != expected.principal_id
        || purchase.profile_did != expected.profile_did
        || purchase.mint_id != expected.mint_id_hex
        || purchase.content_id != expected.content_id
        || purchase.cid != expected.content_cid
        || purchase.listing_sha256 != expected.listing_sha256
        || !purchase
            .seller_address
            .eq_ignore_ascii_case(&expected.listing.seller_address)
        || purchase.chain_namespace != expected.listing.chain_namespace
        || purchase.network != expected.listing.network
        || !purchase
            .ledger
            .eq_ignore_ascii_case(&expected.listing.ledger)
        || !purchase
            .token_id
            .eq_ignore_ascii_case(&expected.listing.token_id)
        || !purchase
            .operative
            .eq_ignore_ascii_case(&expected.listing.operative)
        || purchase.price != expected.listing.price
        || !purchase
            .pay_token
            .eq_ignore_ascii_case(&expected.listing.pay_token)
        || purchase
            .payment_processor
            .as_deref()
            .map(str::to_ascii_lowercase)
            != expected
                .listing
                .payment_processor
                .as_deref()
                .map(str::to_ascii_lowercase)
        || purchase.account_id != expected.buyer_account.account_id
        || !purchase
            .address
            .eq_ignore_ascii_case(&expected.buyer_account.address)
    {
        return Err(purchase_denied_missing!()());
    }
    Ok(())
}

async fn resolve_runtime_custody_purchase_plan(
    state: &GatewayState,
    listing: &crate::protected_content_runtime::RuntimePortableListingPackage,
) -> anyhow::Result<ResolvedProtectedContentPurchase> {
    let response = wallet_chain_provider_data(
        state,
        serde_json::json!({
            "op": "resolve_protected_content_purchase",
            "seller": listing.seller_address,
            "chain_namespace": listing.chain_namespace,
            "network": listing.network,
            "ledger": listing.ledger,
            "token_id": listing.token_id,
        }),
    )
    .await
    .map_err(purchase_unavailable!())?;
    let resolved: ResolvedProtectedContentPurchase =
        serde_json::from_value(response).map_err(purchase_unavailable!())?;
    let expected_chain_id = runtime_custody_purchase_chain_id(&listing.chain_namespace)?;
    if resolved.schema != "elastos.chain.protected-content-purchase/v1"
        || resolved.network != listing.network
        || resolved.purchase_quantity != "0x1"
        || resolved.verified_listing.chain_id != expected_chain_id
        || !resolved
            .verified_listing
            .seller
            .eq_ignore_ascii_case(&listing.seller_address)
        || !resolved
            .verified_listing
            .ledger
            .eq_ignore_ascii_case(&listing.ledger)
        || !resolved
            .verified_listing
            .token_id
            .eq_ignore_ascii_case(&listing.token_id)
        || !resolved
            .verified_listing
            .operative
            .eq_ignore_ascii_case(&listing.operative)
        || resolved.verified_listing.price != listing.price
        || !resolved
            .verified_listing
            .pay_token
            .eq_ignore_ascii_case(&listing.pay_token)
        || resolved
            .verified_listing
            .payment_processor
            .as_deref()
            .map(str::to_ascii_lowercase)
            != listing
                .payment_processor
                .as_deref()
                .map(str::to_ascii_lowercase)
        || resolved.verified_listing.available_quantity == "0x0"
    {
        return Err(purchase_denied_missing!()());
    }
    match resolved.steps.as_slice() {
        [buy] if buy.stage == "buy" => {}
        [approval, buy] if approval.stage == "approval" && buy.stage == "buy" => {}
        _ => return Err(purchase_unavailable_missing!()()),
    }
    for step in &resolved.steps {
        validate_wallet_evm_address(&step.to, "purchase transaction target").map_err(
            |(_, _)| {
                anyhow::anyhow!(
                    crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_UNAVAILABLE_MESSAGE
                )
            },
        )?;
    }
    Ok(resolved)
}

async fn resolve_runtime_custody_purchase_access(
    state: &GatewayState,
    listing: &crate::protected_content_runtime::RuntimePortableListingPackage,
    buyer_account: &RuntimeCustodyCreatorAccount,
    content_access_id_hex: &str,
    request_id: &str,
) -> anyhow::Result<Option<ResolvedProtectedContentPurchaseAccess>> {
    let response = wallet_chain_provider_data(
        state,
        serde_json::json!({
            "op": "resolve_protected_content_purchase_access",
            "request_id": request_id,
            "network": listing.network,
            "wallet": buyer_account.address,
            "content_access_id": content_access_id_hex,
        }),
    )
    .await;
    let Ok(response) = response else {
        return Ok(None);
    };
    let access: ResolvedProtectedContentPurchaseAccess =
        serde_json::from_value(response).map_err(purchase_unavailable!())?;
    if access.schema != "elastos.chain.protected-content-purchase-access/v1"
        || access.request_id != request_id
        || access.network != listing.network
        || access.chain_id != runtime_custody_purchase_chain_id(&listing.chain_namespace)?
        || !access.wallet.eq_ignore_ascii_case(&buyer_account.address)
        || !access
            .content_access_id
            .eq_ignore_ascii_case(content_access_id_hex)
    {
        return Err(purchase_unavailable_missing!()());
    }
    Ok(access.has_access.then_some(access))
}

async fn complete_runtime_custody_purchase_stage(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    request: &RuntimeTransactionRequest,
) -> anyhow::Result<Option<RuntimeTransactionCompletion>> {
    let _approval = ensure_exact_runtime_transaction_approval(state, authority, request.clone())
        .await
        .map_err(purchase_unavailable!())?;
    let completion = match complete_runtime_transaction_effect(
        state,
        authority,
        RuntimeTransactionLookup::ApprovalId(
            wallet_request_id(&request.effect_id, "approval").as_str(),
        ),
        Some(request),
        None,
    )
    .await
    {
        Ok(completion) => completion,
        Err((status, message))
            if status == StatusCode::BAD_REQUEST
                && message == "transaction approval is not completed" =>
        {
            tracing::debug!(
                effect_id = %request.effect_id,
                "runtime custody purchase: pending, wallet approval not completed"
            );
            return Ok(None);
        }
        Err((status, message)) => {
            tracing::warn!(
                effect_id = %request.effect_id,
                %status,
                %message,
                "runtime custody purchase: transaction effect completion failed"
            );
            return Err(purchase_unavailable!()(format!("{status}: {message}")));
        }
    };
    if completion.receipt.is_none() || completion.completion_pending {
        tracing::debug!(
            effect_id = %completion.effect_id,
            transaction_hash = %completion.transaction_hash,
            receipt = completion.receipt.is_some(),
            completion_pending = completion.completion_pending,
            completion_error = completion.completion_error.as_deref().unwrap_or(""),
            already_confirmed = completion.already_confirmed,
            "runtime custody purchase: pending exact Chain settlement"
        );
        return Ok(None);
    }
    if let Some(error) = completion.completion_error.as_deref() {
        return Err(purchase_unavailable!()(format!(
            "transaction effect completed with an error: {error}"
        )));
    }
    Ok(Some(completion))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResolvedProtectedContentMarketSource {
    pub(super) schema: String,
    pub(super) network: String,
    pub(super) authority_gateway_contract: String,
    #[allow(dead_code)]
    evidence_rpc_sources: u64,
}

pub(crate) async fn runtime_custody_buy_via_gateway(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    registry: Arc<ProviderRegistry>,
    input: crate::protected_content_runtime::RuntimeCustodyBuyInput,
) -> anyhow::Result<serde_json::Value> {
    let mint_id = hex::decode(&input.mint_id)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map(Digest32::new)
        .ok_or_else(purchase_denied_missing!())?;
    let listing_record =
        crate::protected_content_runtime::load_runtime_custody_listing(&state.data_dir, mint_id)?
            .ok_or_else(purchase_denied_missing!())?;
    let listing = &listing_record.package;
    let persisted_purchase = crate::protected_content_runtime::load_runtime_custody_purchase(
        &state.data_dir,
        &input.principal_id,
        mint_id,
    )?;
    let listing_sha256 = listing_record.portable_package_digest();
    if listing.mint_id != input.mint_id {
        return Err(purchase_denied_missing!()());
    }
    let localhost_root = crate::auth::principal_localhost_root(&input.principal_id);
    let profile = crate::collaboration_profile_authority::load_profile_authority(
        &state.data_dir,
        &input.principal_id,
        &localhost_root,
    )?
    .ok_or_else(purchase_denied_missing!())?;
    let profile_did = profile.document().profile_did.clone();
    let now = crate::auth::now_ts();
    let existing_buyer_account = if let Some(existing) = persisted_purchase.as_ref() {
        validate_wallet_evm_address(&existing.address, "buyer").map_err(purchase_denied!())?;
        let buyer_account = RuntimeCustodyCreatorAccount {
            account_id: existing.account_id.clone(),
            address: existing.address.clone(),
        };
        let expected_identity = RuntimeCustodyExpectedPurchaseIdentity {
            principal_id: &input.principal_id,
            profile_did: &profile_did,
            mint_id_hex: &input.mint_id,
            content_id: &listing.content_id,
            content_cid: &listing.content_cid,
            listing_sha256: &listing_sha256,
            listing,
            buyer_account: &buyer_account,
        };
        validate_runtime_custody_purchase_record_identity(existing, &expected_identity)?;
        if matches!(
            existing.progress,
            crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Complete { .. }
        ) {
            return Ok(runtime_custody_buy_terminal_response(existing));
        }
        Some(buyer_account)
    } else {
        None
    };
    let (draft, fresh_availability) =
        crate::protected_content_runtime::verify_fresh_runtime_custody_availability(
            &state.data_dir,
            &registry,
            &listing_record,
            mint_id,
            now,
        )
        .await
        .map_err(purchase_denied!())?;
    tracing::debug!(
        mint_id = %input.mint_id,
        principal = %input.principal_id,
        content_cid = %fresh_availability.content_cid(),
        replicas = fresh_availability.observed_replicas(),
        "runtime custody buy: fresh availability verified"
    );
    let expected_content_id =
        crate::protected_content_runtime::runtime_protected_content_id(draft.encrypted_content())
            .map_err(purchase_denied!())?;
    let expected_content_access_id =
        format!("0x{}", hex::encode(draft.content_access_id().as_bytes()));
    if listing.content_id != expected_content_id
        || listing.content_access_id != expected_content_access_id
        || listing.content_cid != fresh_availability.content_cid()
    {
        return Err(purchase_denied_missing!()());
    }
    let (mut purchase, buyer_account) = match (persisted_purchase, existing_buyer_account) {
        (Some(existing), Some(buyer_account)) => (existing, buyer_account),
        (None, None) => {
            let buyer_account =
                resolve_runtime_custody_buyer_account(state, authority, &listing.chain_namespace)
                    .await?;
            let purchase_plan = resolve_runtime_custody_purchase_plan(state, listing).await?;
            let mut steps = purchase_plan.steps.iter();
            let approval_request = match purchase_plan.steps.as_slice() {
                [approval, buy] if approval.stage == "approval" && buy.stage == "buy" => {
                    Some(runtime_custody_purchase_transaction_request(
                        &input.principal_id,
                        &buyer_account,
                        listing,
                        &listing_sha256,
                        mint_id,
                        approval,
                    )?)
                }
                [buy] if buy.stage == "buy" => None,
                _ => return Err(purchase_unavailable_missing!()()),
            };
            let buy_step = steps
                .next_back()
                .ok_or_else(purchase_unavailable_missing!())?;
            let buy_request = runtime_custody_purchase_transaction_request(
                &input.principal_id,
                &buyer_account,
                listing,
                &listing_sha256,
                mint_id,
                buy_step,
            )?;
            let purchase = crate::protected_content_runtime::RuntimeCustodyPurchaseRecord {
                schema: crate::protected_content_runtime::RUNTIME_PURCHASE_SCHEMA_V1.to_string(),
                principal_id: input.principal_id.clone(),
                profile_did: profile_did.clone(),
                mint_id: input.mint_id.clone(),
                content_id: expected_content_id.clone(),
                cid: fresh_availability.content_cid().to_string(),
                listing_sha256: listing_sha256.clone(),
                seller_address: listing.seller_address.clone(),
                chain_namespace: listing.chain_namespace.clone(),
                network: listing.network.clone(),
                ledger: listing.ledger.clone(),
                token_id: listing.token_id.clone(),
                operative: listing.operative.clone(),
                price: listing.price.clone(),
                pay_token: listing.pay_token.clone(),
                payment_processor: listing.payment_processor.clone(),
                availability_receipt_digest: runtime_custody_purchase_availability_receipt_digest(
                    &fresh_availability,
                ),
                account_id: buyer_account.account_id.clone(),
                address: buyer_account.address.clone(),
                approval_stage: approval_request
                    .as_ref()
                    .map(|request| runtime_custody_purchase_stage_record("approval", request))
                    .transpose()?,
                buy_stage: runtime_custody_purchase_stage_record("buy", &buy_request)?,
                progress:
                    crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Pending {
                        confirmed_buy: None,
                    },
                created_at: now,
                updated_at: now,
            };
            crate::protected_content_runtime::persist_runtime_custody_purchase(
                &state.data_dir,
                &purchase,
            )?;
            (purchase, buyer_account)
        }
        _ => return Err(purchase_denied_missing!()()),
    };

    let approval_request = purchase
        .approval_stage
        .as_ref()
        .map(|stage| {
            validate_runtime_custody_purchase_stage_request(
                &input.principal_id,
                &buyer_account,
                listing,
                &listing_sha256,
                mint_id,
                stage,
                "approval",
            )
        })
        .transpose()?;
    let buy_request = validate_runtime_custody_purchase_stage_request(
        &input.principal_id,
        &buyer_account,
        listing,
        &listing_sha256,
        mint_id,
        &purchase.buy_stage,
        "buy",
    )?;

    let fresh_receipt_digest =
        runtime_custody_purchase_availability_receipt_digest(&fresh_availability);
    if purchase.availability_receipt_digest != fresh_receipt_digest {
        purchase.availability_receipt_digest = fresh_receipt_digest;
        purchase.updated_at = crate::auth::now_ts();
        crate::protected_content_runtime::persist_runtime_custody_purchase(
            &state.data_dir,
            &purchase,
        )?;
    }

    if let Some(approval_request) = approval_request.as_ref() {
        let approval_completion =
            complete_runtime_custody_purchase_stage(state, authority, approval_request).await?;
        if approval_completion.is_none() {
            purchase.updated_at = crate::auth::now_ts();
            crate::protected_content_runtime::persist_runtime_custody_purchase(
                &state.data_dir,
                &purchase,
            )?;
            anyhow::bail!(
                crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_PENDING_MESSAGE
            );
        }
    }

    if let crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Pending {
        confirmed_buy: None,
    } = &purchase.progress
    {
        let buy_completion =
            complete_runtime_custody_purchase_stage(state, authority, &buy_request).await?;
        let Some(buy_completion) = buy_completion else {
            purchase.updated_at = crate::auth::now_ts();
            crate::protected_content_runtime::persist_runtime_custody_purchase(
                &state.data_dir,
                &purchase,
            )?;
            anyhow::bail!(
                crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_PENDING_MESSAGE
            );
        };
        let wallet_binding = buy_completion
            .validated_chain_outcome
            .as_ref()
            .map(|outcome| {
                (
                    outcome.binding.clone(),
                    outcome.chain_observation.clone(),
                    outcome.confirmed_at,
                )
            });
        let Some((wallet_binding, chain_observation, confirmed_at)) = wallet_binding else {
            return Err(purchase_unavailable_missing!()());
        };
        purchase.progress =
            crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Pending {
                confirmed_buy: Some(
                    crate::protected_content_runtime::RuntimeCustodyConfirmedPurchaseStage {
                        chain_transaction: buy_completion.transaction_hash,
                        wallet_binding,
                        chain_observation,
                        confirmed_at,
                    },
                ),
            };
        purchase.updated_at = crate::auth::now_ts();
        crate::protected_content_runtime::persist_runtime_custody_purchase(
            &state.data_dir,
            &purchase,
        )?;
    }

    let confirmed_buy = match &purchase.progress {
        crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Pending {
            confirmed_buy: Some(confirmed_buy),
        } => confirmed_buy.clone(),
        crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Complete { .. } => {
            return Ok(runtime_custody_buy_terminal_response(&purchase));
        }
        crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Pending {
            confirmed_buy: None,
        } => anyhow::bail!(
            crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_PENDING_MESSAGE
        ),
    };
    let access = resolve_runtime_custody_purchase_access(
        state,
        listing,
        &buyer_account,
        &expected_content_access_id,
        &format!("purchase-access:{}", purchase.buy_stage.effect_id),
    )
    .await?;
    let Some(access) = access else {
        purchase.updated_at = crate::auth::now_ts();
        crate::protected_content_runtime::persist_runtime_custody_purchase(
            &state.data_dir,
            &purchase,
        )?;
        anyhow::bail!(crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_PENDING_MESSAGE);
    };
    purchase.progress =
        crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Complete {
            terminal: crate::protected_content_runtime::RuntimeCustodyTerminalPurchaseRecord {
                chain_transaction: confirmed_buy.chain_transaction,
                wallet_binding: confirmed_buy.wallet_binding,
                chain_observation: confirmed_buy.chain_observation,
                access_evidence: access,
                confirmed_at: confirmed_buy.confirmed_at,
                bought_at: crate::auth::now_ts(),
            },
        };
    purchase.updated_at = crate::auth::now_ts();
    crate::protected_content_runtime::persist_runtime_custody_purchase(&state.data_dir, &purchase)?;
    Ok(runtime_custody_buy_terminal_response(&purchase))
}

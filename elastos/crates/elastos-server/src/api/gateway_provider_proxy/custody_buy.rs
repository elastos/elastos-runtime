use super::*;

/// Carry how far a purchase has got out to the caller, keeping the stable
/// sentence outermost for the consumers that still read it.
///
/// The twin of [`runtime_custody_creator_effect_pending`] on the buyer's side.
/// An app decides what to offer from `buy_progress`, which `provider_error_from`
/// projects onto the error envelope; the message stays what it was, because the
/// installed proof driver and the gateway tests match on it.
pub(in crate::api::gateway) fn runtime_custody_buy_progress(
    progress: crate::protected_content_runtime::RuntimeCustodyBuyProgress,
    line: u32,
) -> anyhow::Error {
    tracing::debug!(
        line,
        stage = progress.stage_label(),
        awaits_person = progress.awaits_person(),
        "runtime custody purchase: pending exact Wallet or Chain settlement"
    );
    anyhow::Error::new(progress)
        .context(crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_PENDING_MESSAGE)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::api::gateway) struct ResolvedProtectedContentPurchase {
    pub(in crate::api::gateway) schema: String,
    pub(in crate::api::gateway) network: String,
    pub(in crate::api::gateway) purchase_quantity: String,
    pub(in crate::api::gateway) verified_listing: ResolvedProtectedContentPurchaseListing,
    pub(in crate::api::gateway) steps: Vec<ResolvedProtectedContentPurchaseStep>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::api::gateway) struct ResolvedProtectedContentPurchaseListing {
    pub(in crate::api::gateway) chain_id: u64,
    pub(in crate::api::gateway) seller: String,
    pub(in crate::api::gateway) ledger: String,
    pub(in crate::api::gateway) token_id: String,
    pub(in crate::api::gateway) operative: String,
    pub(in crate::api::gateway) available_quantity: String,
    pub(in crate::api::gateway) price: String,
    pub(in crate::api::gateway) pay_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::api::gateway) payment_processor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::api::gateway) struct ResolvedProtectedContentPurchaseStep {
    pub(in crate::api::gateway) stage: String,
    pub(in crate::api::gateway) to: String,
    pub(in crate::api::gateway) value: String,
    pub(in crate::api::gateway) data: String,
}

pub(in crate::api::gateway) type ResolvedProtectedContentPurchaseAccess =
    crate::protected_content_runtime::RuntimeCustodyPurchaseAccessEvidenceRecord;

pub(in crate::api::gateway) async fn resolve_runtime_custody_buyer_account(
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

pub(super) fn runtime_custody_purchase_availability_receipt_digest(
    availability: &elastos_protected_content_runtime::RuntimeVerifiedContentAvailability,
) -> String {
    format!(
        "sha256:{}",
        hex::encode(availability.receipt_digest().as_bytes())
    )
}

/// Plan B T4.6: a fresh check on a non-holder is a verified fetch, which
/// makes no receipt; the purchase records `verified-fetch` instead.
fn runtime_custody_purchase_availability_digest(
    evidence: &elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1,
) -> String {
    match evidence.as_receipt() {
        Some(receipt) => runtime_custody_purchase_availability_receipt_digest(receipt),
        None => {
            crate::protected_content_runtime::RUNTIME_PURCHASE_VERIFIED_FETCH_DIGEST.to_string()
        }
    }
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

pub(in crate::api::gateway) fn runtime_custody_purchase_stage_record(
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

/// What the stable request hash binds besides the offer. A listing-package
/// buy binds its package digest and mint id exactly as today; a market buy
/// binds the asset URI instead.
pub(crate) enum RuntimePurchaseBinding<'a> {
    ListingPackage {
        listing_sha256: &'a str,
        mint_id: elastos_protected_content_contracts::Digest32,
    },
    /// `attempt_id` is the recorded attempt's own identity (R23): a retry
    /// after a reverted buy, even at identical terms, hashes to a new effect.
    Market {
        asset_uri: &'a str,
        attempt_id: &'a str,
    },
}

/// Merges `extra`'s entries into `target` in place. Both are always JSON
/// objects here; a mismatch is a programmer error the caller already ruled
/// out, so it is silently a no-op rather than a panic.
fn merge_json_object(target: &mut serde_json::Value, extra: serde_json::Value) {
    if let (Some(target_obj), serde_json::Value::Object(extra_obj)) =
        (target.as_object_mut(), extra)
    {
        target_obj.extend(extra_obj);
    }
}

pub(in crate::api::gateway) fn runtime_custody_purchase_transaction_request(
    principal_id: &str,
    buyer_account: &RuntimeCustodyCreatorAccount,
    item: &crate::protected_content_market::RuntimeMarketItem,
    offer: &crate::protected_content_market::RuntimeMarketOffer,
    binding: &RuntimePurchaseBinding<'_>,
    stage: &ResolvedProtectedContentPurchaseStep,
) -> anyhow::Result<RuntimeTransactionRequest> {
    let (domain, binding_stable_fields, binding_metadata_fields) = match binding {
        RuntimePurchaseBinding::ListingPackage {
            listing_sha256,
            mint_id,
        } => {
            let mint_id_hex = hex::encode(mint_id.as_bytes());
            (
                "elastos.protected-content.purchase-request/v1",
                serde_json::json!({
                    "listing_sha256": listing_sha256,
                    "mint_id": mint_id_hex,
                }),
                serde_json::json!({
                    "mint_id": mint_id_hex,
                    "listing_sha256": listing_sha256,
                }),
            )
        }
        RuntimePurchaseBinding::Market {
            asset_uri,
            attempt_id,
        } => (
            "elastos.protected-content.market-purchase-request/v1",
            serde_json::json!({ "asset_uri": asset_uri, "attempt_id": attempt_id }),
            serde_json::json!({ "asset_uri": asset_uri }),
        ),
    };
    let mut stable_request = serde_json::json!({
        "domain": domain,
        "effect_id": "",
        "wallet_account_id": buyer_account.account_id,
        "address": buyer_account.address,
        "chain_namespace": item.chain_namespace,
        "network": item.network,
        "to": stage.to,
        "value": stage.value,
        "data": stage.data,
        "seller": offer.seller,
        "ledger": item.ledger,
        "token_id": item.token_id,
        "operative": item.operative,
        "price": offer.price,
        "pay_token": offer.pay_token,
        "purchase_quantity": "0x1",
        "stage": stage.stage,
    });
    merge_json_object(&mut stable_request, binding_stable_fields);
    let request_sha256 = runtime_transaction_request_sha256(&stable_request)?;
    let mut metadata = serde_json::json!({
        "product_operation": format!("protected_content_purchase_{}", stage.stage),
        "seller": offer.seller,
        "ledger": item.ledger,
        "token_id": item.token_id,
        "price": offer.price,
        "pay_token": offer.pay_token,
        "purchase_quantity": "0x1",
    });
    merge_json_object(&mut metadata, binding_metadata_fields);
    let mut request = RuntimeTransactionRequest {
        source: NATIVE_TRANSACTION_SOURCE,
        effect_id: String::new(),
        request_sha256,
        account_id: buyer_account.account_id.clone(),
        address: buyer_account.address.clone(),
        chain_namespace: item.chain_namespace.clone(),
        network: item.network.clone(),
        to: stage.to.clone(),
        value: stage.value.clone(),
        data: stage.data.clone(),
        approval_reason: "Buy protected content access".to_string(),
        metadata,
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

pub(in crate::api::gateway) fn validate_runtime_custody_purchase_stage_request(
    principal_id: &str,
    buyer_account: &RuntimeCustodyCreatorAccount,
    item: &crate::protected_content_market::RuntimeMarketItem,
    offer: &crate::protected_content_market::RuntimeMarketOffer,
    binding: &RuntimePurchaseBinding<'_>,
    stage: &crate::protected_content_runtime::RuntimeCustodyPurchaseStageRecord,
    expected_stage: &str,
) -> anyhow::Result<RuntimeTransactionRequest> {
    let request = runtime_custody_purchase_transaction_request(
        principal_id,
        buyer_account,
        item,
        offer,
        binding,
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
    item: &crate::protected_content_market::RuntimeMarketItem,
    offer: &crate::protected_content_market::RuntimeMarketOffer,
) -> anyhow::Result<ResolvedProtectedContentPurchase> {
    let resolved = read_runtime_custody_purchase_plan(state, item, &offer.seller)
        .await?
        .ok_or_else(purchase_unavailable_missing!())?;
    if resolved.verified_listing.price != offer.price
        || !resolved
            .verified_listing
            .pay_token
            .eq_ignore_ascii_case(&offer.pay_token)
        || resolved
            .verified_listing
            .payment_processor
            .as_deref()
            .map(str::to_ascii_lowercase)
            != offer
                .payment_processor
                .as_deref()
                .map(str::to_ascii_lowercase)
        || resolved.verified_listing.available_quantity == "0x0"
    {
        return Err(purchase_denied_missing!()());
    }
    Ok(resolved)
}

/// The chain's current plan for buying one copy of `item` from `seller`,
/// checked to be about exactly that item and seller, but NOT compared with
/// any terms: each caller decides what a difference in terms means. The
/// listing-package path refuses it; the market path answers `terms_changed`.
///
/// `Ok(None)` is the chain saying the seller has no copy to sell -- the offer
/// is sold out or was never there (a `listings` read of zeros).
pub(in crate::api::gateway) async fn read_runtime_custody_purchase_plan(
    state: &GatewayState,
    item: &crate::protected_content_market::RuntimeMarketItem,
    seller: &str,
) -> anyhow::Result<Option<ResolvedProtectedContentPurchase>> {
    let response = match wallet_chain_provider_data(
        state,
        serde_json::json!({
            "op": "resolve_protected_content_purchase",
            "seller": seller,
            "chain_namespace": item.chain_namespace,
            "network": item.network,
            "ledger": item.ledger,
            "token_id": item.token_id,
        }),
    )
    .await
    {
        Ok(response) => response,
        Err((status, message))
            if status == StatusCode::BAD_REQUEST
                && message.split(':').next().unwrap_or_default().trim()
                    == "protected_content_verified_listing_unavailable" =>
        {
            tracing::debug!(%seller, "protected-content purchase: the offer has no copy to sell");
            return Ok(None);
        }
        Err(error) => return Err(purchase_unavailable!()(error)),
    };
    let resolved: ResolvedProtectedContentPurchase =
        serde_json::from_value(response).map_err(purchase_unavailable!())?;
    let expected_chain_id = runtime_custody_purchase_chain_id(&item.chain_namespace)?;
    if resolved.schema != "elastos.chain.protected-content-purchase/v1"
        || resolved.network != item.network
        || resolved.purchase_quantity != "0x1"
        || resolved.verified_listing.chain_id != expected_chain_id
        || !resolved
            .verified_listing
            .seller
            .eq_ignore_ascii_case(seller)
        || !resolved
            .verified_listing
            .ledger
            .eq_ignore_ascii_case(&item.ledger)
        || !resolved
            .verified_listing
            .token_id
            .eq_ignore_ascii_case(&item.token_id)
        || !resolved
            .verified_listing
            .operative
            .eq_ignore_ascii_case(&item.operative)
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
    Ok(Some(resolved))
}

pub(in crate::api::gateway) async fn resolve_runtime_custody_purchase_access(
    state: &GatewayState,
    listing: &crate::protected_content_runtime::RuntimePortableListingPackage,
    buyer_account: &RuntimeCustodyCreatorAccount,
    content_access_id_hex: &str,
    request_id: &str,
) -> anyhow::Result<Option<ResolvedProtectedContentPurchaseAccess>> {
    match runtime_custody_access_on_chain(
        state,
        &listing.network,
        &listing.chain_namespace,
        content_access_id_hex,
        buyer_account,
        request_id,
        None,
    )
    .await
    {
        // Every caller of this function treats a chain that could not answer
        // as "no access yet" and decides for itself what that means, so the
        // unanswered case keeps being folded here, at this boundary, rather
        // than inside the shared read.
        Err(error) => match error.downcast_ref::<RuntimeCustodyAccessUnanswered>() {
            Some(unanswered) => {
                tracing::debug!(
                    %request_id,
                    status = unanswered.status.as_u16(),
                    error = %unanswered.message,
                    "protected-content purchase access resolution failed closed"
                );
                Ok(None)
            }
            None => Err(error),
        },
        answered => answered,
    }
}

/// Whether `buyer_account` holds access to the item `kid` names, on
/// `network` of `chain_namespace` -- both as the item names them -- as the
/// chain answers it at the head, where a new purchase shows within seconds.
/// A copy is built on [`resolve_runtime_custody_finalized_grant`] instead.
///
/// `Ok(None)` only for a real "no access": the chain answered and said no.
/// A chain that could not answer is an error here -- a caller showing a state
/// must be able to say "unknown" rather than "available" -- and an unbound
/// KID is the purchase-unbound error, exactly as for a listing's purchase.
pub(in crate::api::gateway) async fn resolve_runtime_custody_item_access(
    state: &GatewayState,
    chain_namespace: &str,
    network: &str,
    kid: &str,
    buyer_account: &RuntimeCustodyCreatorAccount,
    request_id: &str,
) -> anyhow::Result<Option<ResolvedProtectedContentPurchaseAccess>> {
    runtime_custody_access_on_chain(
        state,
        network,
        chain_namespace,
        kid,
        buyer_account,
        request_id,
        None,
    )
    .await
}

/// The chain's grant of the item `kid` names to `buyer_account`, read the
/// way custody reads it before any release: at the finalized block.
pub(in crate::api::gateway) enum RuntimeCustodyFinalizedGrant {
    /// Granted at finalized, with the evidence the copy records. Boxed: the
    /// evidence dwarfs the other arms.
    Granted(Box<ResolvedProtectedContentPurchaseAccess>),
    /// Granted at the head only: a grant still being confirmed, which
    /// custody would refuse until finality reaches it.
    Confirming,
    /// Granted at neither.
    NotGranted,
}

/// Read the grant a copy is built on: at finalized, and -- only when
/// finalized says no -- at the head, to tell a grant still being confirmed
/// from none at all. A chain that cannot answer either read is an error.
pub(in crate::api::gateway) async fn resolve_runtime_custody_finalized_grant(
    state: &GatewayState,
    chain_namespace: &str,
    network: &str,
    kid: &str,
    buyer_account: &RuntimeCustodyCreatorAccount,
    request_id: &str,
) -> anyhow::Result<RuntimeCustodyFinalizedGrant> {
    if let Some(access) = runtime_custody_access_on_chain(
        state,
        network,
        chain_namespace,
        kid,
        buyer_account,
        &format!("{request_id}:finalized"),
        Some("finalized"),
    )
    .await?
    {
        return Ok(RuntimeCustodyFinalizedGrant::Granted(Box::new(access)));
    }
    let at_head = runtime_custody_access_on_chain(
        state,
        network,
        chain_namespace,
        kid,
        buyer_account,
        &format!("{request_id}:head"),
        None,
    )
    .await?;
    Ok(if at_head.is_some() {
        RuntimeCustodyFinalizedGrant::Confirming
    } else {
        RuntimeCustodyFinalizedGrant::NotGranted
    })
}

/// Whether `buyer_account` holds access to `item` itself -- asked by the item
/// (`AuthorityGateway.hasAccess(accessor, ledger, tokenId)`, R50), so it
/// needs no KID -- corroborated exactly like the KID-keyed read and at the
/// same block (`latest`, pinned and agreed across sources).
///
/// `Ok(None)` only for a real "no access". A chain that could not answer is
/// `RuntimeCustodyAccessUnanswered`, as for the KID-keyed read.
pub(in crate::api::gateway) async fn resolve_runtime_market_item_access(
    state: &GatewayState,
    item: &crate::protected_content_market::RuntimeMarketItem,
    buyer_account: &RuntimeCustodyCreatorAccount,
    request_id: &str,
) -> anyhow::Result<Option<ResolvedProtectedContentPurchaseAccess>> {
    let response = wallet_chain_provider_data(
        state,
        serde_json::json!({
            "op": "resolve_protected_content_item_access",
            "request_id": request_id,
            "network": item.network,
            "wallet": buyer_account.address,
            "ledger": item.ledger,
            "token_id": item.token_id,
            "block": "latest",
        }),
    )
    .await
    .map_err(|(status, message)| {
        anyhow::Error::new(RuntimeCustodyAccessUnanswered { status, message })
    })?;
    let access: ResolvedProtectedContentPurchaseAccess =
        serde_json::from_value(response).map_err(purchase_unavailable!())?;
    if access.schema != "elastos.chain.protected-content-item-access/v1"
        || access.request_id != request_id
        || access.network != item.network
        || access.chain_id != runtime_custody_purchase_chain_id(&item.chain_namespace)?
        || !access.wallet.eq_ignore_ascii_case(&buyer_account.address)
        || access.content_access_id.is_some()
        || !access
            .ledger
            .as_deref()
            .is_some_and(|ledger| ledger.eq_ignore_ascii_case(&item.ledger))
        || !access
            .token_id
            .as_deref()
            .is_some_and(|token_id| token_id.eq_ignore_ascii_case(&item.token_id))
    {
        return Err(purchase_unavailable_missing!()());
    }
    Ok(access.has_access.then_some(access))
}

/// The chain provider could not answer an access question at all. Distinct
/// from an answer of "no", which is `Ok(None)`.
#[derive(Debug)]
pub(in crate::api::gateway) struct RuntimeCustodyAccessUnanswered {
    pub(in crate::api::gateway) status: StatusCode,
    pub(in crate::api::gateway) message: String,
}

impl std::fmt::Display for RuntimeCustodyAccessUnanswered {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "protected-content access could not be read: {}",
            self.message
        )
    }
}

impl std::error::Error for RuntimeCustodyAccessUnanswered {}

/// The one read both access questions share. `chain_namespace` is the chain
/// the answer must be on, as the package or the item names it. `block` is
/// `None` for the chain provider's default, the head, or `Some("finalized")`
/// for the block custody reads before any release.
async fn runtime_custody_access_on_chain(
    state: &GatewayState,
    network: &str,
    chain_namespace: &str,
    content_access_id_hex: &str,
    buyer_account: &RuntimeCustodyCreatorAccount,
    request_id: &str,
    block: Option<&'static str>,
) -> anyhow::Result<Option<ResolvedProtectedContentPurchaseAccess>> {
    let mut request = serde_json::json!({
        "op": "resolve_protected_content_purchase_access",
        "request_id": request_id,
        "network": network,
        "wallet": buyer_account.address,
        "content_access_id": content_access_id_hex,
    });
    if let Some(block) = block {
        request["block"] = serde_json::Value::String(block.to_string());
    }
    let response = wallet_chain_provider_data(state, request).await;
    let response = match response {
        Ok(response) => response,
        Err((status, message)) => {
            let code = message.split(':').next().unwrap_or_default().trim();
            if status == StatusCode::BAD_REQUEST && code == "unknown_protected_content_object" {
                tracing::warn!(
                    %request_id,
                    "protected-content purchase target unbound on chain"
                );
                anyhow::bail!(
                    crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_UNBOUND_MESSAGE
                );
            }
            return Err(anyhow::Error::new(RuntimeCustodyAccessUnanswered {
                status,
                message,
            }));
        }
    };
    let access: ResolvedProtectedContentPurchaseAccess =
        serde_json::from_value(response).map_err(purchase_unavailable!())?;
    if access.schema != "elastos.chain.protected-content-purchase-access/v1"
        || access.request_id != request_id
        || access.network != network
        || access.chain_id != runtime_custody_purchase_chain_id(chain_namespace)?
        || !access.wallet.eq_ignore_ascii_case(&buyer_account.address)
        || !access
            .content_access_id
            .as_deref()
            .is_some_and(|answered| answered.eq_ignore_ascii_case(content_access_id_hex))
        || access.ledger.is_some()
        || access.token_id.is_some()
    {
        return Err(purchase_unavailable_missing!()());
    }
    Ok(access.has_access.then_some(access))
}

/// What one purchase stage did.
///
/// This used to be `Option<RuntimeTransactionCompletion>`, where `None` stood
/// for "the person has not answered the Wallet", "the chain has not confirmed
/// it" and, after the Wallet gained its lapsed-request path, nothing else --
/// three situations a buyer needs told apart, collapsed into one absence.
pub(in crate::api::gateway) enum RuntimeCustodyPurchaseStageOutcome {
    /// Confirmed on the chain, with the evidence the purchase record keeps.
    Confirmed(Box<RuntimeTransactionCompletion>),
    /// The Wallet holds the approval for this stage.
    AwaitingApproval,
    /// Approved, and the chain has not produced the evidence yet.
    AwaitingChainSettlement,
    /// The person declined. Nothing was signed, so nothing can arrive later.
    Declined,
}

pub(in crate::api::gateway) async fn complete_runtime_custody_purchase_stage(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    request: &RuntimeTransactionRequest,
) -> anyhow::Result<RuntimeCustodyPurchaseStageOutcome> {
    let _approval = ensure_exact_runtime_transaction_approval(state, authority, request.clone())
        .await
        .map_err(|error| {
            if error.1 == super::gateway_transaction_effects::TRANSACTION_APPROVAL_HANDOFF_EXPIRED {
                anyhow::anyhow!(error.1)
            } else {
                purchase_unavailable!()(error)
            }
        })?;
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
            return Ok(RuntimeCustodyPurchaseStageOutcome::AwaitingApproval);
        }
        // Declining is an answer. The Wallet re-raises a LAPSED approval under
        // its own id, so a window that closed becomes a fresh ask rather than
        // a dead end; a refusal is never re-raised, and saying so lets an app
        // offer a new purchase instead of a retry that cannot work.
        Err((status, message))
            if status == StatusCode::BAD_REQUEST
                && message == super::gateway_transaction_effects::TRANSACTION_APPROVAL_REJECTED =>
        {
            tracing::warn!(
                effect_id = %request.effect_id,
                "runtime custody purchase: wallet approval was declined"
            );
            return Ok(RuntimeCustodyPurchaseStageOutcome::Declined);
        }
        // Signed and sent, and the Chain's sources have not seen it yet. Asking
        // again reconciles the same transaction; nothing is signed or sent.
        Err(error) if chain_has_not_seen_transaction(&error) => {
            tracing::warn!(
                effect_id = %request.effect_id,
                error = %error.1,
                "runtime custody purchase: the Chain has not seen the transaction yet"
            );
            return Ok(RuntimeCustodyPurchaseStageOutcome::AwaitingChainSettlement);
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
        return Ok(RuntimeCustodyPurchaseStageOutcome::AwaitingChainSettlement);
    }
    if let Some(error) = completion.completion_error.as_deref() {
        return Err(purchase_unavailable!()(format!(
            "transaction effect completed with an error: {error}"
        )));
    }
    Ok(RuntimeCustodyPurchaseStageOutcome::Confirmed(Box::new(
        completion,
    )))
}

/// Turn what a stage did into the answer its caller returns.
///
/// Only `Confirmed` continues the purchase, and its caller has already taken
/// that arm; everything else is a wait or a refusal that names the stage it
/// belongs to, so a buyer is told which approval is outstanding rather than
/// that something is pending.
pub(in crate::api::gateway) fn runtime_custody_buy_stage_answer(
    outcome: RuntimeCustodyPurchaseStageOutcome,
    stage: crate::protected_content_runtime::RuntimeCustodyBuyStage,
    buyer_account: &RuntimeCustodyCreatorAccount,
    line: u32,
) -> anyhow::Error {
    match outcome {
        RuntimeCustodyPurchaseStageOutcome::Confirmed(_) => purchase_unavailable_missing!()(),
        RuntimeCustodyPurchaseStageOutcome::AwaitingApproval => runtime_custody_buy_progress(
            crate::protected_content_runtime::RuntimeCustodyBuyProgress::awaiting_approval(
                stage,
                buyer_account.external_signer,
                buyer_account.connector_id.as_deref(),
            ),
            line,
        ),
        RuntimeCustodyPurchaseStageOutcome::AwaitingChainSettlement => {
            runtime_custody_buy_progress(
                crate::protected_content_runtime::RuntimeCustodyBuyProgress::waiting(
                    crate::protected_content_runtime::RuntimeCustodyBuyStage::ChainSettlement,
                ),
                line,
            )
        }
        // A refusal is not a wait. It keeps the unavailable message rather than
        // the pending one, so a caller polling for settlement stops.
        RuntimeCustodyPurchaseStageOutcome::Declined => anyhow::Error::new(
            crate::protected_content_runtime::RuntimeCustodyBuyProgress::declined(),
        )
        .context(crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_UNAVAILABLE_MESSAGE),
    }
}

/// The confirmed approval and buy stages currently recorded on a `Pending`
/// purchase. `runtime_custody_buy_via_gateway` returns the terminal response
/// as soon as it observes `Complete` (before ever reaching a stage-progress
/// read), so every caller of this function has already ruled that out --
/// panicking on it rather than defaulting to "nothing confirmed yet" matters,
/// because `None` here is exactly the value that would re-enable re-driving
/// an already-confirmed (or already-complete) stage.
pub(in crate::api::gateway) fn pending_stages(
    progress: &crate::protected_content_runtime::RuntimeCustodyPurchaseProgress,
) -> (
    Option<crate::protected_content_runtime::RuntimeCustodyConfirmedPurchaseStage>,
    Option<crate::protected_content_runtime::RuntimeCustodyConfirmedPurchaseStage>,
) {
    match progress {
        crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Pending {
            confirmed_approval,
            confirmed_buy,
        } => (confirmed_approval.clone(), confirmed_buy.clone()),
        crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Complete { .. }
        | crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Granted { .. } => {
            unreachable!("terminal purchases return early before reaching stage-progress reads")
        }
    }
}

/// Rebuild the local copy of an item this principal owns.
///
/// The `.ddrm` capsule is made of public material — the metadata document the
/// token URI resolves to, and the content the listing names — so the only
/// question is whether the copy is theirs to hold. That answer lives on the
/// chain and nowhere else: the access token, read at the finalized block for
/// the wallet account this principal transacts with. A purchase record on this Home
/// is neither necessary nor sufficient, which is the point. It is not necessary
/// because someone who bought on one Home owns the same token on another, and
/// it is not sufficient because a record is local state and the grant is not.
///
/// Buying and minting both write the capsule already. This exists because
/// neither offers a way to ask again: a write that failed, a file since
/// deleted, or a Home that has never held the copy all end in the same place,
/// with a person who owns something they cannot see.
///
/// A copy bought on the market is named by its item, since until it is
/// adopted there is no mint for it on this Home. Adoption is retried here
/// (D10), and the adopted mint then takes exactly the path every other copy
/// takes.
pub(crate) async fn runtime_custody_download_owned_copy_via_gateway(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    registry: Arc<ProviderRegistry>,
    input: crate::protected_content_runtime::RuntimeCustodyDownloadInput,
) -> anyhow::Result<serde_json::Value> {
    let crate::protected_content_runtime::RuntimeCustodyDownloadInput { principal_id, copy } =
        input;
    let mint_id = match copy {
        crate::protected_content_runtime::RuntimeCustodyOwnedCopy::Mint(mint_id) => mint_id,
        crate::protected_content_runtime::RuntimeCustodyOwnedCopy::MarketItem(item) => {
            runtime_custody_market_copy_mint(state, authority, &registry, &principal_id, &item)
                .await?
        }
    };
    let input = crate::protected_content_runtime::RuntimeCustodyBuyInput {
        principal_id,
        mint_id,
    };
    let mint_id = hex::decode(&input.mint_id)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map(Digest32::new)
        .ok_or_else(download_denied_missing!())?;
    let listing_record =
        crate::protected_content_runtime::load_runtime_custody_listing(&state.data_dir, mint_id)?
            .ok_or_else(download_denied_missing!())?;
    let listing = &listing_record.package;
    let owner_account =
        resolve_runtime_custody_buyer_account(state, authority, &listing.chain_namespace)
            .await
            .map_err(download_denied!())?;
    runtime_custody_download_grant(
        state,
        &listing.chain_namespace,
        &listing.network,
        // The listing's own content access id, which is the value the chain
        // binds the grant to. `import_runtime_custody` verified it against the
        // package before this listing could exist here.
        &listing.content_access_id,
        &owner_account,
        &format!("download-access:{}", input.mint_id),
    )
    .await?;
    // What the copy says about how it was acquired comes from the record when
    // this Home has one, because that is the fact it already wrote down -- a
    // chain grant adopted above says `granted`. A Home that has never held the
    // copy has nothing to say about how the token was come by, and the chain
    // does not carry that either, so it records a purchase -- the only
    // acquisition it can witness from here.
    let acquisition = crate::protected_content_runtime::load_runtime_custody_purchase(
        &state.data_dir,
        &input.principal_id,
        mint_id,
    )?
    .map_or(
        crate::protected_content_runtime::RuntimeCustodyAcquisitionV1::Bought,
        |purchase| purchase.acquisition,
    );
    let capsule_uri = write_runtime_custody_owned_capsule(
        state,
        registry.as_ref(),
        listing,
        &input.principal_id,
        acquisition,
    )
    .await
    .ok_or_else(download_unavailable_missing!())?;
    // What the copy is, in the words the viewer session speaks, so a page
    // that just built it opens it in the viewer its kind needs.
    let content_kind =
        crate::protected_content_runtime::runtime_custody_package_content_kind(listing)
            .map_err(download_unavailable!())?;
    Ok(serde_json::json!({
        "schema": crate::protected_content_runtime::RUNTIME_CUSTODY_DOWNLOAD_SCHEMA_V1,
        "mint_id": input.mint_id,
        "capsule_uri": capsule_uri,
        "acquisition": acquisition.wire_value(),
        "content_kind": content_kind,
    }))
}

/// The grant a download builds a copy on, read at finalized as custody will
/// read it. A chain that cannot answer is unavailable, not a "no"; a grant
/// only the head has is `access_confirming`; none at all is `no_access`.
async fn runtime_custody_download_grant(
    state: &GatewayState,
    chain_namespace: &str,
    network: &str,
    kid: &str,
    account: &RuntimeCustodyCreatorAccount,
    request_id: &str,
) -> anyhow::Result<ResolvedProtectedContentPurchaseAccess> {
    let refusal = match resolve_runtime_custody_finalized_grant(
        state,
        chain_namespace,
        network,
        kid,
        account,
        request_id,
    )
    .await
    .map_err(download_unavailable!())?
    {
        RuntimeCustodyFinalizedGrant::Granted(access) => return Ok(*access),
        RuntimeCustodyFinalizedGrant::Confirming => {
            crate::protected_content_runtime::RuntimeCustodyDownloadRefusal::Confirming
        }
        RuntimeCustodyFinalizedGrant::NotGranted => {
            crate::protected_content_runtime::RuntimeCustodyDownloadRefusal::NoAccess
        }
    };
    tracing::warn!(
        line = line!(),
        %request_id,
        code = refusal.code(),
        "runtime custody download: the chain does not grant this account the copy at finalized"
    );
    Err(refusal.error())
}

/// The mint a market item's copy is held under here, adopting it first when
/// that has not happened yet.
///
/// A completed market purchase is adopted as it always was. With no purchase
/// at all, access is the chain's to decide, not how it was come by: an item
/// the chain grants this principal's account -- a channel admin's, say -- is
/// adopted for that grant (`granted`). A purchase still under way is neither.
async fn runtime_custody_market_copy_mint(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    registry: &Arc<ProviderRegistry>,
    principal_id: &str,
    item: &crate::protected_content_market::RuntimeMarketBuyItemClaim,
) -> anyhow::Result<String> {
    let purchase = crate::protected_content_market::load_runtime_market_purchase_by_key(
        &state.data_dir,
        principal_id,
        &item.chain_namespace,
        &item.ledger,
        &item.token_id,
    )
    .map_err(download_unavailable!())?;
    let purchase = match purchase {
        Some(purchase)
            if matches!(
                purchase.progress,
                crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Complete { .. }
            ) =>
        {
            purchase
        }
        Some(_) => return Err(download_denied_missing!()()),
        None => {
            return runtime_custody_granted_copy_mint(
                state,
                authority,
                registry,
                principal_id,
                item,
            )
            .await
        }
    };
    match adopt_runtime_market_purchase(state, registry, principal_id, &purchase)
        .await
        .map_err(download_unavailable!())?
    {
        crate::protected_content_market::AdoptionOutcome::Adopted { mint_id } => Ok(mint_id),
        crate::protected_content_market::AdoptionOutcome::Foreign
        | crate::protected_content_market::AdoptionOutcome::Mismatch => {
            tracing::debug!("runtime custody download: a foreign asset has no copy here");
            Err(download_unavailable_missing!()())
        }
        crate::protected_content_market::AdoptionOutcome::NotYet(reason) => {
            tracing::debug!(%reason, "runtime custody download: adoption is not possible yet");
            Err(download_unavailable_missing!()())
        }
        crate::protected_content_market::AdoptionOutcome::CustodyElsewhere => {
            Err(crate::protected_content_runtime::RuntimeCustodyElsewhere::error())
        }
    }
}

/// Adopt the copy of a market item the chain grants this principal's account
/// without a purchase, and answer its mint.
///
/// Nothing in the request is trusted: the item is re-derived from the chain
/// and its asset folder with the market listing object's own binding check
/// (`(ledger, token_id)` to a non-zero operative, `tokenURI` to the folder,
/// the folder's `metadata.json` to a KID the chain binds to that item), and
/// every identifier the request names must agree with it. Then the chain is
/// asked, for the proven KID, whether it grants the account access. A chain
/// that cannot answer is unavailable; only its "no" is `no_access`.
async fn runtime_custody_granted_copy_mint(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    registry: &Arc<ProviderRegistry>,
    principal_id: &str,
    claim: &crate::protected_content_market::RuntimeMarketBuyItemClaim,
) -> anyhow::Result<String> {
    let verified = match verify_market_item_binding(
        state,
        &MarketListingStart::Item {
            ledger: claim.ledger.clone(),
            token_id: claim.token_id.clone(),
        },
    )
    .await
    {
        Ok(verified) => verified,
        Err(MarketListingRefusal::Unavailable(reason)) => {
            return Err(download_unavailable!()(reason));
        }
        // No reachable Home serves the folder now: unreadable, as before.
        Err(refusal @ MarketListingRefusal::NoHolder) => {
            return Err(download_unavailable!()(refusal));
        }
        Err(refusal) => return Err(download_denied!()(refusal)),
    };
    let item = &verified.item;
    let claimed_kid = claim
        .kid
        .as_deref()
        .map(crate::protected_content_market::normalize_runtime_market_kid);
    // An unproven KID is no grant to ask about (R46), and any identifier the
    // request names must be the one the chain and the folder state.
    let (Some(kid), Some(metadata)) = (item.kid.as_deref(), verified.metadata.as_ref()) else {
        tracing::debug!(
            unreadable = verified.kid_unreadable,
            "runtime custody download: the item's kid is not proven"
        );
        // Not proven because something could not be read now is the chain or
        // the folder being unreachable, not the request being wrong.
        return Err(if verified.kid_unreadable {
            download_unavailable_missing!()()
        } else {
            download_denied_missing!()()
        });
    };
    if claim.chain_namespace != item.chain_namespace
        || claim.network != item.network
        || claimed_kid.is_some_and(|claimed| claimed.as_deref() != Some(kid))
    {
        tracing::debug!("runtime custody download: the request misnames the item");
        return Err(download_denied_missing!()());
    }
    let account = resolve_runtime_custody_buyer_account(state, authority, &item.chain_namespace)
        .await
        .map_err(download_denied!())?;
    let access = runtime_custody_download_grant(
        state,
        &item.chain_namespace,
        &item.network,
        kid,
        &account,
        &format!("download-grant:{}:{}", item.ledger, item.token_id),
    )
    .await?;
    let dataset = match crate::protected_content_market::shared_read_dataset(metadata) {
        Ok(Some(dataset)) => dataset,
        Ok(None) => {
            tracing::debug!("runtime custody download: a foreign asset has no copy here");
            return Err(download_unavailable_missing!()());
        }
        Err(error) => return Err(download_unavailable!()(error)),
    };
    let profile_did = crate::protected_content_runtime::load_runtime_custody_profile_did(
        &state.data_dir,
        principal_id,
    )
    .map_err(download_unavailable!())?;
    let listing = crate::protected_content_runtime::adopt_runtime_granted_listing(
        &state.data_dir,
        registry,
        principal_id,
        &profile_did,
        item,
        &format!("elastos://{}", verified.folder_cid),
        &dataset,
        &account.account_id,
        &account.address,
        access,
    )
    .await
    .map_err(|error| {
        // The one refusal that is an answer rather than a failure: it keeps
        // its type, so the page reads `custody_elsewhere`.
        if crate::protected_content_runtime::RuntimeCustodyElsewhere::is(&error) {
            error
        } else {
            download_unavailable!()(error)
        }
    })?;
    Ok(listing.package.mint_id)
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
    // A granted listing states terms nobody offered: it is never bought.
    if listing_record.origin.is_granted() {
        tracing::debug!(
            mint_id = %input.mint_id,
            "runtime custody purchase refused: a granted listing is not for sale"
        );
        return Err(purchase_denied_missing!()());
    }
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
    let (item, offer) = crate::protected_content_market::market_terms_from_package(
        listing,
        &listing.content_access_id,
    );
    let binding = RuntimePurchaseBinding::ListingPackage {
        listing_sha256: &listing_sha256,
        mint_id,
    };
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
        // A copy the chain granted is already held: nothing is bought.
        if matches!(
            existing.progress,
            crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Granted { .. }
        ) {
            return Err(runtime_market_buy_refused(
                RuntimeMarketBuyRefusal::AlreadyOwned,
                line!(),
            ));
        }
        validate_wallet_evm_address(&existing.address, "buyer").map_err(purchase_denied!())?;
        let buyer_account = RuntimeCustodyCreatorAccount {
            account_id: existing.account_id.clone(),
            address: existing.address.clone(),
            // Rebuilt from the recorded purchase, which stores the identity and
            // not the wallet surface it came from. Nothing downstream of here
            // raises a pending answer for this account, so the signer fields
            // stay at the value that claims the least.
            external_signer: false,
            connector_id: None,
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
        // R29, early: a market purchase already holds this item. Checked again,
        // under the lock, when the purchase is recorded below.
        if let Some(market_purchase) =
            crate::protected_content_market::load_runtime_market_purchase_by_key(
                &state.data_dir,
                &input.principal_id,
                &item.chain_namespace,
                &item.ledger,
                &item.token_id,
            )
            .map_err(purchase_unavailable!())?
        {
            return Err(runtime_listing_market_purchase_refusal(
                &market_purchase,
                line!(),
            ));
        }
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
        .map_err(|error| {
            // Refused before any Wallet request, as data the page decides on.
            if crate::protected_content_runtime::RuntimeCustodyElsewhere::is(&error) {
                runtime_market_buy_refused(RuntimeMarketBuyRefusal::CustodyElsewhere, line!())
            } else {
                purchase_denied!()(error)
            }
        })?;
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
            let purchase_plan = resolve_runtime_custody_purchase_plan(state, &item, &offer).await?;
            let mut steps = purchase_plan.steps.iter();
            let approval_request = match purchase_plan.steps.as_slice() {
                [approval, buy] if approval.stage == "approval" && buy.stage == "buy" => {
                    Some(runtime_custody_purchase_transaction_request(
                        &input.principal_id,
                        &buyer_account,
                        &item,
                        &offer,
                        &binding,
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
                &item,
                &offer,
                &binding,
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
                availability_receipt_digest: runtime_custody_purchase_availability_digest(
                    &fresh_availability,
                ),
                account_id: buyer_account.account_id.clone(),
                address: buyer_account.address.clone(),
                approval_stage: approval_request
                    .as_ref()
                    .map(|request| runtime_custody_purchase_stage_record("approval", request))
                    .transpose()?,
                acquisition_stage: runtime_custody_purchase_stage_record("buy", &buy_request)?,
                acquisition: crate::protected_content_runtime::RuntimeCustodyAcquisitionV1::Bought,
                capsule_uri: None,
                progress:
                    crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Pending {
                        confirmed_approval: None,
                        confirmed_buy: None,
                    },
                created_at: now,
                updated_at: now,
            };
            // R29: one purchase per item, whichever path started it. Recorded
            // under the market-purchase lock, so a market attempt for the same
            // item cannot be recorded between this check and this write.
            if let Some(market_purchase) =
                crate::protected_content_market::create_runtime_listing_purchase_unless_market(
                    &state.data_dir,
                    &purchase,
                )?
            {
                return Err(runtime_listing_market_purchase_refusal(
                    &market_purchase,
                    line!(),
                ));
            }
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
                &item,
                &offer,
                &binding,
                stage,
                "approval",
            )
        })
        .transpose()?;
    let buy_request = validate_runtime_custody_purchase_stage_request(
        &input.principal_id,
        &buyer_account,
        &item,
        &offer,
        &binding,
        &purchase.acquisition_stage,
        "buy",
    )?;

    let fresh_receipt_digest = runtime_custody_purchase_availability_digest(&fresh_availability);
    if purchase.availability_receipt_digest != fresh_receipt_digest {
        purchase.availability_receipt_digest = fresh_receipt_digest;
        purchase.updated_at = crate::auth::now_ts();
        crate::protected_content_runtime::persist_runtime_custody_purchase(
            &state.data_dir,
            &purchase,
        )?;
    }

    let (confirmed_approval_stage, _) = pending_stages(&purchase.progress);

    // Once the approval stage has confirmed on chain it is durable: skip
    // re-driving it (and re-touching the Wallet for it) on every retry.
    // `RuntimeCustodyPurchaseProgress::Pending` only remembered the buy
    // stage's confirmation before, so a still-pending buy stage forced this
    // block to run again on each call even after approval was long settled.
    if let (Some(approval_request), None) =
        (approval_request.as_ref(), confirmed_approval_stage.as_ref())
    {
        let approval_completion =
            complete_runtime_custody_purchase_stage(state, authority, approval_request).await?;
        let approval_completion = match approval_completion {
            RuntimeCustodyPurchaseStageOutcome::Confirmed(completion) => *completion,
            outcome => {
                // A declined effect is never re-raised or broadcast: the
                // attempt is over without payment and retired (R41), so it
                // blocks no later purchase of this item on either path.
                if matches!(outcome, RuntimeCustodyPurchaseStageOutcome::Declined) {
                    retire_runtime_listing_attempt(state, &purchase)?;
                } else {
                    purchase.updated_at = crate::auth::now_ts();
                    crate::protected_content_runtime::persist_runtime_custody_purchase(
                        &state.data_dir,
                        &purchase,
                    )?;
                }
                return Err(runtime_custody_buy_stage_answer(
                    outcome,
                    crate::protected_content_runtime::RuntimeCustodyBuyStage::AllowanceApproval,
                    &buyer_account,
                    line!(),
                ));
            }
        };
        let Some(confirmed_approval) = confirmed_stage(approval_completion) else {
            return Err(purchase_unavailable_missing!()());
        };
        let (_, confirmed_buy) = pending_stages(&purchase.progress);
        purchase.progress =
            crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Pending {
                confirmed_approval: Some(confirmed_approval),
                confirmed_buy,
            };
        purchase.updated_at = crate::auth::now_ts();
        crate::protected_content_runtime::persist_runtime_custody_purchase(
            &state.data_dir,
            &purchase,
        )?;
    }

    if let crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Pending {
        confirmed_buy: None,
        ..
    } = &purchase.progress
    {
        let buy_completion =
            complete_runtime_custody_purchase_stage(state, authority, &buy_request).await?;
        let buy_completion = match buy_completion {
            RuntimeCustodyPurchaseStageOutcome::Confirmed(completion) => *completion,
            outcome => {
                if matches!(outcome, RuntimeCustodyPurchaseStageOutcome::Declined) {
                    retire_runtime_listing_attempt(state, &purchase)?;
                } else {
                    purchase.updated_at = crate::auth::now_ts();
                    crate::protected_content_runtime::persist_runtime_custody_purchase(
                        &state.data_dir,
                        &purchase,
                    )?;
                }
                return Err(runtime_custody_buy_stage_answer(
                    outcome,
                    crate::protected_content_runtime::RuntimeCustodyBuyStage::PurchaseApproval,
                    &buyer_account,
                    line!(),
                ));
            }
        };
        if runtime_market_receipt_reverted(buy_completion.receipt.as_ref()) {
            return Err(runtime_listing_buy_reverted(state, &purchase));
        }
        let Some(confirmed_buy) = confirmed_stage(buy_completion) else {
            return Err(purchase_unavailable_missing!()());
        };
        let (confirmed_approval, _) = pending_stages(&purchase.progress);
        purchase.progress =
            crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Pending {
                confirmed_approval,
                confirmed_buy: Some(confirmed_buy),
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
            ..
        } => confirmed_buy.clone(),
        // Refused before any stage ran; said again rather than assumed.
        crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Granted { .. } => {
            return Err(runtime_market_buy_refused(
                RuntimeMarketBuyRefusal::AlreadyOwned,
                line!(),
            ));
        }
        crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Complete { .. } => {
            // Already owned. File the capsule if an earlier attempt settled the
            // purchase without one -- and only then, so asking again never
            // leaves a second copy of the same asset on the shelf.
            if purchase.capsule_uri.is_none() {
                purchase.capsule_uri = write_runtime_custody_owned_capsule(
                    state,
                    registry.as_ref(),
                    listing,
                    &input.principal_id,
                    crate::protected_content_runtime::RuntimeCustodyAcquisitionV1::Bought,
                )
                .await;
                if purchase.capsule_uri.is_some() {
                    purchase.updated_at = crate::auth::now_ts();
                    crate::protected_content_runtime::persist_runtime_custody_purchase(
                        &state.data_dir,
                        &purchase,
                    )?;
                }
            }
            return Ok(runtime_custody_buy_terminal_response(&purchase));
        }
        crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Pending {
            confirmed_buy: None,
            ..
        } => {
            return Err(runtime_custody_buy_progress(
                crate::protected_content_runtime::RuntimeCustodyBuyProgress::waiting(
                    crate::protected_content_runtime::RuntimeCustodyBuyStage::ChainSettlement,
                ),
                line!(),
            ))
        }
    };
    let access = resolve_runtime_custody_purchase_access(
        state,
        listing,
        &buyer_account,
        &expected_content_access_id,
        &format!("purchase-access:{}", purchase.acquisition_stage.effect_id),
    )
    .await?;
    let Some(access) = access else {
        // No grant yet. A buy the chain mined and reverted never grants one:
        // ask its receipt (the authoritative signal) before waiting on it.
        if runtime_market_buy_mined_reverted(
            state,
            &listing.network,
            &confirmed_buy.chain_transaction,
        )
        .await
        {
            return Err(runtime_listing_buy_reverted(state, &purchase));
        }
        purchase.updated_at = crate::auth::now_ts();
        crate::protected_content_runtime::persist_runtime_custody_purchase(
            &state.data_dir,
            &purchase,
        )?;
        // Paid for, on the chain, and the grant is not readable yet. Nobody
        // need act, and the same buy completes as soon as it is.
        return Err(runtime_custody_buy_progress(
            crate::protected_content_runtime::RuntimeCustodyBuyProgress::waiting(
                crate::protected_content_runtime::RuntimeCustodyBuyStage::AccessEvidence,
            ),
            line!(),
        ));
    };
    purchase.progress =
        crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Complete {
            terminal: crate::protected_content_runtime::RuntimeCustodyTerminalPurchaseRecord {
                chain_transaction: confirmed_buy.chain_transaction,
                wallet_binding: confirmed_buy.wallet_binding,
                chain_observation: confirmed_buy.chain_observation,
                access_evidence: Some(access),
                confirmed_at: confirmed_buy.confirmed_at,
                acquired_at: crate::auth::now_ts(),
            },
        };
    // A bought copy is filed exactly like a minted one: same capsule, same
    // shelf, chosen by what it protects. Nothing below this point can tell how
    // the copy was acquired, which is the point.
    purchase.capsule_uri = write_runtime_custody_owned_capsule(
        state,
        registry.as_ref(),
        listing,
        &input.principal_id,
        crate::protected_content_runtime::RuntimeCustodyAcquisitionV1::Bought,
    )
    .await;
    purchase.updated_at = crate::auth::now_ts();
    crate::protected_content_runtime::persist_runtime_custody_purchase(&state.data_dir, &purchase)?;
    Ok(runtime_custody_buy_terminal_response(&purchase))
}

/// Retire a listing-package attempt that is provably over without payment
/// (R41): its Wallet approval was declined, or its buy was mined and
/// reverted. R29 refuses a market purchase of an item while a listing
/// purchase of it is recorded, so a dead attempt left recorded would block
/// the item on both paths for good. Only this attempt is removed, under the
/// market-purchase lock; a newer one is left as it is. A revert known only
/// from the node's words proves nothing and never reaches here (R22).
fn retire_runtime_listing_attempt(
    state: &GatewayState,
    purchase: &crate::protected_content_runtime::RuntimeCustodyPurchaseRecord,
) -> anyhow::Result<()> {
    let retired =
        crate::protected_content_market::retire_runtime_listing_purchase(&state.data_dir, purchase)
            .map_err(purchase_unavailable!())?;
    tracing::debug!(
        effect_id = %purchase.acquisition_stage.effect_id,
        retired,
        "runtime custody purchase: attempt over without payment"
    );
    Ok(())
}

/// A listing-package buy the chain mined and reverted: its effect is spent
/// and paid nothing. The attempt is retired and the answer is the plain
/// failure; a record that could not be retired says so instead.
fn runtime_listing_buy_reverted(
    state: &GatewayState,
    purchase: &crate::protected_content_runtime::RuntimeCustodyPurchaseRecord,
) -> anyhow::Error {
    tracing::warn!(
        effect_id = %purchase.acquisition_stage.effect_id,
        "runtime custody purchase: the buy transaction was mined and reverted"
    );
    match retire_runtime_listing_attempt(state, purchase) {
        Ok(()) => purchase_unavailable_missing!()(),
        Err(error) => error,
    }
}

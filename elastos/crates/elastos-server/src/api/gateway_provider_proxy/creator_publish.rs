use super::*;

pub(super) const RUNTIME_CUSTODY_CREATOR_PENDING_MESSAGE: &str =
    "Runtime custody creator mint is pending exact Wallet or Chain settlement";

pub(super) const RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE: &str =
    "Runtime custody creator mint is unavailable";

/// Chain-provider answers on the creator tail. A `*_pending` code (the
/// mint receipt or verified listing not yet finalized on enough evidence
/// sources) is the Chain half of "pending exact Wallet or Chain settlement":
/// the caller re-polls, exactly as it does while the Wallet approval is
/// outstanding. Anything else fails closed with the cause in the log.
pub(super) fn creator_mint_chain_error(error: (StatusCode, String), line: u32) -> anyhow::Error {
    let (status, message) = error;
    let code = message.split(':').next().unwrap_or_default().trim();
    if status == StatusCode::BAD_REQUEST && code.ends_with("_pending") {
        return anyhow::anyhow!(RUNTIME_CUSTODY_CREATOR_PENDING_MESSAGE);
    }
    tracing::warn!(
        line,
        status = status.as_u16(),
        error = %message,
        "Runtime custody creator mint failed closed"
    );
    anyhow::anyhow!("({}, {message})", status.as_u16())
        .context(format!("{}:{line}", file!()))
        .context(RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE)
}

const RUNTIME_CUSTODY_CREATOR_OP_TYPE_CODE: u16 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedProtectedContentCreatorMint {
    schema: String,
    network: String,
    chain_namespace: String,
    function: String,
    ledger: String,
    pay_token: String,
    to: String,
    data: String,
    value: String,
    content_access_id: String,
    signed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedProtectedContentMintReceipt {
    pub(crate) schema: String,
    pub(crate) network: String,
    pub(crate) chain_id: u64,
    pub(crate) token_id: String,
    pub(crate) operative: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedProtectedContentVerifiedListing {
    pub(crate) schema: String,
    pub(crate) network: String,
    pub(crate) chain_id: u64,
    pub(crate) seller: String,
    pub(crate) ledger: String,
    pub(crate) token_id: String,
    pub(crate) operative: String,
    pub(crate) quantity: String,
    pub(crate) price: String,
    pub(crate) pay_token: String,
    #[serde(default)]
    pub(crate) payment_processor: Option<String>,
}

#[derive(Serialize)]
struct RuntimeCustodyCreatorMetadata<'a> {
    schema: &'static str,
    name: &'a str,
    mime_type: &'a str,
    codecs: &'a str,
    encrypted_content_cid: &'a str,
    content_access_id: String,
    protected_content_identity: &'a str,
    mint_id: String,
    publisher_profile_did: &'a str,
    media_identity_base64: String,
    key_envelope_identity_base64: String,
    rights_policy_identity_base64: String,
    content_key_commitment_base64: String,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeCustodyCreatorPublishBinding {
    pub account_id: String,
    pub address: String,
    pub source_digest: Digest32,
}

#[derive(Clone)]
pub(super) struct RuntimeCustodyCreatorChainPlan {
    pub(super) network: String,
    pub(super) chain_namespace: String,
    pub(super) ledger: String,
    pub(super) pay_token: String,
    pub(super) to: String,
    pub(super) data: String,
    pub(super) value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedProtectedContentCreatorMintSource {
    schema: String,
    network: String,
    chain_namespace: String,
    ledger: String,
    pay_token: String,
    abi: String,
    function: String,
}

fn runtime_custody_creator_mint_source_digest(
    network: &str,
    chain_namespace: &str,
    ledger: &str,
    pay_token: &str,
    abi: &str,
    function: &str,
) -> Digest32 {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"elastos.runtime-custody.creator-mint-source/v1");
    for field in [network, chain_namespace, ledger, pay_token, abi, function] {
        hasher.update((field.len() as u32).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    Digest32::new(hasher.finalize().into())
}

fn runtime_custody_creator_mint_source_digest_for_source(
    source: &ResolvedProtectedContentCreatorMintSource,
) -> Digest32 {
    runtime_custody_creator_mint_source_digest(
        &source.network,
        &source.chain_namespace,
        &source.ledger,
        &source.pay_token,
        &source.abi,
        &source.function,
    )
}

async fn resolve_runtime_custody_creator_account(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    wallet_account_id: &str,
) -> anyhow::Result<RuntimeCustodyCreatorAccount> {
    let accounts = system_wallet_accounts_summary(state, authority).await;
    let account = accounts
        .accounts
        .iter()
        .find(|account| account.account_id == wallet_account_id)
        .ok_or_else(creator_mint_unavailable_missing!())?;
    if !account.signing_available || !is_managed_wallet_proof_type(&account.proof_type) {
        return Err(creator_mint_unavailable_missing!()());
    }
    validate_wallet_evm_address(&account.address, "creator")
        .map_err(|(_, message)| anyhow::anyhow!(message))?;
    Ok(RuntimeCustodyCreatorAccount {
        account_id: account.account_id.clone(),
        address: account.address.to_ascii_lowercase(),
    })
}

async fn resolve_runtime_custody_creator_mint_source(
    state: &GatewayState,
) -> anyhow::Result<ResolvedProtectedContentCreatorMintSource> {
    let response = wallet_chain_provider_data(
        state,
        serde_json::json!({
            "op": "describe_protected_content_creator_mint_source",
        }),
    )
    .await
    .map_err(creator_mint_unavailable!())?;
    let source: ResolvedProtectedContentCreatorMintSource =
        serde_json::from_value(response).map_err(creator_mint_unavailable!())?;
    if source.schema != "elastos.chain.protected-content-creator-mint-source/v1"
        || source.abi != "elacity_mint_v1"
        || source.function != "mint(string,uint16,bytes,bytes)"
        || wallet_chain_namespace_network(&source.chain_namespace) != Some(source.network.as_str())
    {
        return Err(creator_mint_unavailable_missing!()());
    }
    validate_wallet_evm_address(&source.ledger, "creator ledger")
        .map_err(creator_mint_unavailable!())?;
    validate_wallet_evm_address(&source.pay_token, "creator pay token")
        .map_err(creator_mint_unavailable!())?;
    Ok(source)
}

async fn resolve_runtime_custody_bound_creator_account(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    account_id: &str,
    expected_address: &str,
) -> anyhow::Result<RuntimeCustodyCreatorAccount> {
    let account = resolve_runtime_custody_creator_account(state, authority, account_id).await?;
    if account.address != expected_address {
        return Err(creator_mint_unavailable_missing!()());
    }
    Ok(account)
}

pub(crate) async fn resolve_runtime_custody_creator_publish_binding(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
) -> anyhow::Result<RuntimeCustodyCreatorPublishBinding> {
    let request_id = elastos_protected_content_runtime::RuntimeMintIntent::request_id_for_source(
        principal_id,
        object_uri,
        source_storage,
    )
    .map_err(creator_mint_unavailable!())?;
    let mint_journal = crate::protected_content_runtime::runtime_mint_journal(&state.data_dir);
    let mint_journal_root =
        crate::protected_content_runtime::runtime_mint_journal_root(&state.data_dir);
    let source = resolve_runtime_custody_creator_mint_source(state).await?;
    let source_digest = runtime_custody_creator_mint_source_digest_for_source(&source);
    match std::fs::symlink_metadata(&mint_journal_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(creator_mint_unavailable_missing!()()),
        Ok(_) => {
            match mint_journal.load_intent(request_id) {
                Ok(intent) => {
                    if intent.creator_mint_source_digest() != source_digest {
                        return Err(creator_mint_unavailable_missing!()());
                    }
                    let account = resolve_runtime_custody_bound_creator_account(
                        state,
                        authority,
                        intent.creator_wallet_account_id(),
                        intent.creator_wallet_address(),
                    )
                    .await?;
                    return Ok(RuntimeCustodyCreatorPublishBinding {
                        account_id: account.account_id,
                        address: account.address,
                        source_digest,
                    });
                }
                Err(elastos_protected_content_runtime::RuntimeMintJournalError::NotFound) => {}
                Err(_) => return Err(creator_mint_unavailable_missing!()()),
            }
            match mint_journal.load_media_preparation(request_id) {
                Ok(preparation) => {
                    if preparation.creator_mint_source_digest() != source_digest {
                        return Err(creator_mint_unavailable_missing!()());
                    }
                    let account = resolve_runtime_custody_bound_creator_account(
                        state,
                        authority,
                        preparation.creator_wallet_account_id(),
                        preparation.creator_wallet_address(),
                    )
                    .await?;
                    return Ok(RuntimeCustodyCreatorPublishBinding {
                        account_id: account.account_id,
                        address: account.address,
                        source_digest,
                    });
                }
                Err(elastos_protected_content_runtime::RuntimeMintJournalError::NotFound) => {}
                Err(_) => return Err(creator_mint_unavailable_missing!()()),
            }
        }
    }
    let account = resolve_runtime_custody_wallet_default_account(
        state,
        authority,
        &source.chain_namespace,
        RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE,
    )
    .await?;
    Ok(RuntimeCustodyCreatorPublishBinding {
        account_id: account.account_id,
        address: account.address,
        source_digest,
    })
}

#[allow(clippy::too_many_arguments)]
async fn publish_runtime_custody_creator_metadata(
    registry: &ProviderRegistry,
    data_dir: &std::path::Path,
    object_uri: &str,
    mime_type: &str,
    codecs: &str,
    facts: &crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts,
    mint: &elastos_protected_content_runtime::PersistedRuntimeMint,
    publisher_profile_did: &str,
) -> anyhow::Result<(String, String)> {
    let draft = mint.draft();
    let metadata = RuntimeCustodyCreatorMetadata {
        schema: "elastos.protected-content.metadata/v1",
        name: runtime_custody_metadata_name(object_uri),
        mime_type,
        codecs,
        encrypted_content_cid: &facts.content_cid,
        content_access_id: format!("0x{}", hex::encode(draft.content_access_id().as_bytes())),
        protected_content_identity: &facts.content_id,
        mint_id: hex::encode(draft.mint_id().as_bytes()),
        publisher_profile_did,
        media_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.media_identity().canonical_bytes()?),
        key_envelope_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.key_envelope().canonical_bytes()?),
        rights_policy_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.policy().canonical_bytes()?),
        content_key_commitment_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.content_key_commitment().as_bytes()),
    };
    let bytes = serde_json::to_vec(&metadata)?;
    let parent = data_dir.join("protected-content");
    std::fs::create_dir_all(&parent)?;
    let staging = tempfile::Builder::new()
        .prefix("creator-metadata-")
        .tempdir_in(&parent)?;
    std::fs::write(staging.path().join("metadata.json"), bytes)?;
    let metadata_cid = crate::content::publish_directory_via_provider_with_kind(
        registry,
        staging.path(),
        "directory",
        None,
        None,
    )
    .await?;
    Ok((
        metadata_cid.clone(),
        format!("ipfs://{metadata_cid}/metadata.json"),
    ))
}

async fn publish_runtime_custody_creator_listing(
    registry: &ProviderRegistry,
    data_dir: &std::path::Path,
    mint: &elastos_protected_content_runtime::PersistedRuntimeMint,
    facts: &crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts,
    publisher_principal_id: &str,
    terminal: &elastos_protected_content_runtime::RuntimeMintCreatorTerminalEvidence,
) -> anyhow::Result<String> {
    let package = crate::protected_content_runtime::runtime_custody_creator_listing_package(
        data_dir,
        mint,
        facts,
        publisher_principal_id,
        terminal,
    )?;
    let parent = data_dir.join("protected-content");
    std::fs::create_dir_all(&parent)?;
    let staging = tempfile::Builder::new()
        .prefix("creator-listing-")
        .tempdir_in(&parent)?;
    let listing_bytes = serde_json::to_vec(&package)?;
    std::fs::write(staging.path().join("listing.json"), listing_bytes)?;
    let links = [
        ("metadata".to_string(), package.metadata_cid.clone()),
        ("encrypted-content".to_string(), package.content_cid.clone()),
    ];
    let requirements = runtime_custody_listing_requirements()?;
    let cid = crate::content::publish_directory_via_provider_with_kind_links_and_requirements(
        registry,
        staging.path(),
        "protected-content-listing",
        Some(&package.content_id),
        Some(&package.publisher_profile_did),
        &links,
        requirements,
    )
    .await?;
    let listing_uri = format!("elastos://{cid}");
    crate::protected_content_runtime::persist_runtime_custody_creator_listing(
        data_dir,
        mint,
        package,
        publisher_principal_id,
        listing_uri.clone(),
    )?;
    Ok(listing_uri)
}

/// The availability a creator listing is published with.
fn runtime_custody_listing_requirements(
) -> anyhow::Result<crate::content::ContentPublishRequirements> {
    crate::content::ContentPublishRequirements::new(3, true)
}

fn runtime_custody_metadata_name(object_uri: &str) -> &str {
    object_uri
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or("protected-content")
}

pub(super) fn erc1155_is_approved_for_all_call_data(
    owner: &str,
    operator: &str,
) -> anyhow::Result<String> {
    Ok(format!(
        "0x{ERC1155_IS_APPROVED_FOR_ALL_SELECTOR}{}{}",
        abi_word_from_address(owner)?,
        abi_word_from_address(operator)?
    ))
}

pub(super) fn erc1155_set_approval_for_all_call_data(
    operator: &str,
    approved: bool,
) -> anyhow::Result<String> {
    Ok(format!(
        "0x{ERC1155_SET_APPROVAL_FOR_ALL_SELECTOR}{}{:0>64}",
        abi_word_from_address(operator)?,
        if approved { "1" } else { "0" }
    ))
}

/// Decodes the single `bool` word an `isApprovedForAll` call returns.
/// Anything other than an exact 32-byte 0/1 word is treated as unknown,
/// which the caller resolves by raising the approval (a spurious second
/// `setApprovalForAll(true)` is harmless; a missed one breaks every buy).
pub(super) fn erc1155_bool_result(result: &str) -> Option<bool> {
    let raw = result.strip_prefix("0x")?;
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    match raw.trim_start_matches('0') {
        "" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

/// Builds the exact `setApprovalForAll(gateway, true)` transaction on the
/// mint's operative: the ERC-1155 contract the market gateway resolves from
/// `(ledger, token_id)` and transfers the sold copies from. The asset ledger
/// only records the mint; an approval granted there never reaches the
/// operative, and every purchase reverts with
/// `ERC1155MissingApprovalForAll(gateway, creator)`.
fn runtime_custody_creator_operator_approval_request(
    principal_id: &str,
    creator_account: &RuntimeCustodyCreatorAccount,
    chain_plan: &RuntimeCustodyCreatorChainPlan,
    operative: &str,
    gateway: &str,
    mint_id: elastos_protected_content_contracts::Digest32,
) -> anyhow::Result<RuntimeTransactionRequest> {
    let data = erc1155_set_approval_for_all_call_data(gateway, true)?;
    let stable_request = serde_json::json!({
        "domain": "elastos.protected-content.creator-operator-approval/v1",
        "effect_id": "",
        "wallet_account_id": creator_account.account_id,
        "address": creator_account.address,
        "chain_namespace": chain_plan.chain_namespace,
        "network": chain_plan.network,
        "to": operative,
        "value": "0x0",
        "data": data,
        "ledger": chain_plan.ledger,
        "operative": operative,
        "gateway": gateway,
        "mint_id": hex::encode(mint_id.as_bytes()),
    });
    let request_sha256 = runtime_transaction_request_sha256(&stable_request)?;
    let mut request = RuntimeTransactionRequest {
        source: NATIVE_TRANSACTION_SOURCE,
        effect_id: String::new(),
        request_sha256,
        account_id: creator_account.account_id.clone(),
        address: creator_account.address.clone(),
        chain_namespace: chain_plan.chain_namespace.clone(),
        network: chain_plan.network.clone(),
        to: operative.to_string(),
        value: "0x0".to_string(),
        data,
        approval_reason: "Allow the marketplace gateway to deliver sold copies".to_string(),
        metadata: serde_json::json!({
            "product_operation": "protected_content_creator_operator_approval",
            "ledger": chain_plan.ledger,
            "operative": operative,
            "gateway": gateway,
            "mint_id": hex::encode(mint_id.as_bytes()),
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

/// Ensures the mint's operative lets the market gateway move the creator's
/// copies (ERC-1155 operator approval on the contract `buyAccess` transfers
/// from). Returns Ok when the chain already reports the approval or the
/// approval effect has settled; bails with the creator-pending message while
/// the wallet approval or chain settlement is outstanding.
#[allow(clippy::too_many_arguments)]
async fn ensure_runtime_custody_creator_operator_approval(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    mint_journal: &elastos_protected_content_runtime::RuntimeMintJournal,
    mint: &elastos_protected_content_runtime::PersistedRuntimeMint,
    mint_id: elastos_protected_content_contracts::Digest32,
    principal_id: &str,
    creator_account: &RuntimeCustodyCreatorAccount,
    chain_plan: &RuntimeCustodyCreatorChainPlan,
    operative: &str,
) -> anyhow::Result<()> {
    validate_wallet_evm_address(operative, "mint operative")
        .map_err(creator_mint_unavailable!())?;
    let operative = operative.to_ascii_lowercase();
    let gateway = resolve_runtime_custody_market_gateway(state, &chain_plan.network).await?;
    let probe = wallet_chain_provider_data(
        state,
        serde_json::json!({
            "op": "contract_call",
            "network": chain_plan.network,
            "to": operative,
            "data": erc1155_is_approved_for_all_call_data(&creator_account.address, &gateway)?,
        }),
    )
    .await
    .map_err(creator_mint_unavailable!())?;
    let approved = probe
        .get("result")
        .and_then(serde_json::Value::as_str)
        .and_then(erc1155_bool_result)
        .unwrap_or(false);
    tracing::debug!(
        mint_id = %hex::encode(mint_id.as_bytes()),
        creator = %creator_account.address,
        %operative,
        %gateway,
        approved,
        "runtime custody creator tail: operative operator approval probed"
    );
    if approved {
        return Ok(());
    }
    let request = runtime_custody_creator_operator_approval_request(
        principal_id,
        creator_account,
        chain_plan,
        &operative,
        &gateway,
        mint_id,
    )?;
    let effect_binding = runtime_custody_creator_effect_binding(&request)?;
    if let Some(existing) = mint
        .creator_state()
        .and_then(|creator_state| creator_state.operator_approval())
    {
        if existing != &effect_binding {
            return Err(creator_mint_unavailable_missing!()());
        }
    } else {
        mint_journal
            .bind_creator_operator_approval(mint_id, effect_binding.clone())
            .map_err(creator_mint_unavailable!())?;
    }
    let approval = ensure_exact_runtime_transaction_approval(state, authority, request.clone())
        .await
        .map_err(|(_, message)| anyhow::anyhow!(message))?;
    tracing::debug!(
        effect_id = %approval.effect_id,
        "runtime custody creator tail: exact wallet effect ensured"
    );
    let completion = match complete_runtime_transaction_effect(
        state,
        authority,
        RuntimeTransactionLookup::ApprovalId(effect_binding.approval_request_id()),
        Some(&request),
        None,
    )
    .await
    {
        Ok(completion) => completion,
        Err((status, message))
            if status == StatusCode::BAD_REQUEST
                && message == "transaction approval is not completed" =>
        {
            let _ = approval;
            {
                tracing::debug!(
                    line = line!(),
                    "runtime custody creator tail: pending exact Wallet or Chain settlement"
                );
                anyhow::bail!(RUNTIME_CUSTODY_CREATOR_PENDING_MESSAGE);
            }
        }
        Err((_, message)) => return Err(anyhow::anyhow!(message)),
    };
    if completion.receipt.is_none() || completion.completion_pending {
        {
            tracing::debug!(
                line = line!(),
                "runtime custody creator tail: pending exact Wallet or Chain settlement"
            );
            anyhow::bail!(RUNTIME_CUSTODY_CREATOR_PENDING_MESSAGE);
        }
    }
    if completion.completion_error.is_some() {
        return Err(creator_mint_unavailable_missing!()());
    }
    Ok(())
}

fn runtime_custody_creator_effect_binding(
    request: &RuntimeTransactionRequest,
) -> anyhow::Result<elastos_protected_content_runtime::RuntimeMintCreatorEffectBinding> {
    elastos_protected_content_runtime::RuntimeMintCreatorEffectBinding::new(
        request.effect_id.clone(),
        wallet_request_id(&request.effect_id, "approval"),
        request.request_sha256.clone(),
        request.account_id.clone(),
        request.address.clone(),
        request.chain_namespace.clone(),
        request.network.clone(),
    )
    .map_err(creator_mint_unavailable!())
}

pub(super) fn runtime_custody_creator_chain_id(chain_namespace: &str) -> anyhow::Result<u64> {
    chain_namespace
        .strip_prefix("eip155:")
        .ok_or_else(creator_mint_unavailable_missing!())?
        .parse::<u64>()
        .map_err(creator_mint_unavailable!())
}

async fn resolve_runtime_custody_creator_chain_plan(
    state: &GatewayState,
    expected_source_digest: Digest32,
    source: &ResolvedProtectedContentCreatorMintSource,
    creator_state: &elastos_protected_content_runtime::RuntimeMintCreatorState,
    creator_address: &str,
    content_access_id: elastos_protected_content_contracts::ContentAccessIdV1,
    token_uri: &str,
) -> anyhow::Result<RuntimeCustodyCreatorChainPlan> {
    let response = wallet_chain_provider_data(
        state,
        serde_json::json!({
            "op": "resolve_protected_content_creator_mint",
            "creator": creator_address,
            "token_uri": token_uri,
            "content_access_id": format!("0x{}", hex::encode(content_access_id.as_bytes())),
            "copies": creator_state.desired_terms().copies(),
            "price": creator_state.desired_terms().price(),
        }),
    )
    .await
    .map_err(creator_mint_unavailable!())?;
    let resolved: ResolvedProtectedContentCreatorMint =
        serde_json::from_value(response).map_err(creator_mint_unavailable!())?;
    let resolved_source_digest = runtime_custody_creator_mint_source_digest(
        &resolved.network,
        &resolved.chain_namespace,
        &resolved.ledger,
        &resolved.pay_token,
        "elacity_mint_v1",
        &resolved.function,
    );
    if resolved.schema != "elastos.chain.protected-content-creator-mint/v1"
        || resolved.signed
        || resolved.function != "mint(string,uint16,bytes,bytes)"
        || resolved_source_digest != expected_source_digest
        || resolved.network != source.network
        || resolved.chain_namespace != source.chain_namespace
        || !resolved
            .content_access_id
            .eq_ignore_ascii_case(&format!("0x{}", hex::encode(content_access_id.as_bytes())))
        || !resolved.ledger.eq_ignore_ascii_case(&source.ledger)
        || !resolved.pay_token.eq_ignore_ascii_case(&source.pay_token)
    {
        return Err(creator_mint_unavailable_missing!()());
    }
    validate_wallet_evm_address(&resolved.ledger, "creator ledger")
        .map_err(|(_, message)| anyhow::anyhow!(message))?;
    validate_wallet_evm_address(&resolved.to, "creator transaction target")
        .map_err(|(_, message)| anyhow::anyhow!(message))?;
    validate_wallet_evm_address(&resolved.pay_token, "creator pay token")
        .map_err(|(_, message)| anyhow::anyhow!(message))?;
    if !resolved.ledger.eq_ignore_ascii_case(&resolved.to) {
        return Err(creator_mint_unavailable_missing!()());
    }
    Ok(RuntimeCustodyCreatorChainPlan {
        network: resolved.network,
        chain_namespace: resolved.chain_namespace,
        ledger: resolved.ledger.to_ascii_lowercase(),
        pay_token: resolved.pay_token.to_ascii_lowercase(),
        to: resolved.to.to_ascii_lowercase(),
        data: resolved.data,
        value: resolved.value,
    })
}

pub(super) fn runtime_custody_creator_transaction_request(
    principal_id: &str,
    creator_account: &RuntimeCustodyCreatorAccount,
    creator_state: &elastos_protected_content_runtime::RuntimeMintCreatorState,
    chain_plan: &RuntimeCustodyCreatorChainPlan,
    mint_id: elastos_protected_content_contracts::Digest32,
    token_uri: &str,
) -> anyhow::Result<RuntimeTransactionRequest> {
    let stable_request = serde_json::json!({
        "domain": "elastos.protected-content.creator-request/v1",
        "effect_id": "",
        "wallet_account_id": creator_account.account_id,
        "address": creator_account.address,
        "chain_namespace": chain_plan.chain_namespace,
        "network": chain_plan.network,
        "to": chain_plan.to,
        "value": chain_plan.value,
        "data": chain_plan.data,
        "ledger": chain_plan.ledger,
        "pay_token": chain_plan.pay_token,
        "metadata_cid": creator_state.metadata_cid(),
        "token_uri": token_uri,
        "mint_id": hex::encode(mint_id.as_bytes()),
        "copies": creator_state.desired_terms().copies(),
        "price": creator_state.desired_terms().price(),
    });
    let request_sha256 = runtime_transaction_request_sha256(&stable_request)?;
    let mut request = RuntimeTransactionRequest {
        source: NATIVE_TRANSACTION_SOURCE,
        effect_id: String::new(),
        request_sha256,
        account_id: creator_account.account_id.clone(),
        address: creator_account.address.clone(),
        chain_namespace: chain_plan.chain_namespace.clone(),
        network: chain_plan.network.clone(),
        to: chain_plan.to.clone(),
        value: chain_plan.value.clone(),
        data: chain_plan.data.clone(),
        approval_reason: "Create protected-content creator listing".to_string(),
        metadata: serde_json::json!({
            "product_operation": "protected_content_creator_mint",
            "ledger": chain_plan.ledger,
            "pay_token": chain_plan.pay_token,
            "metadata_cid": creator_state.metadata_cid(),
            "token_uri": token_uri,
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

/// Resolves the finalized mint receipt (token id + operative) for the settled
/// mint transaction; a chain-provider `*_pending` answer surfaces as the
/// creator-pending state so callers re-poll.
async fn resolve_runtime_custody_creator_mint_receipt(
    state: &GatewayState,
    creator_state: &elastos_protected_content_runtime::RuntimeMintCreatorState,
    creator_address: &str,
    chain_plan: &RuntimeCustodyCreatorChainPlan,
    transaction_hash: &str,
) -> anyhow::Result<ResolvedProtectedContentMintReceipt> {
    let receipt_response = wallet_chain_provider_data(
        state,
        serde_json::json!({
            "op": "resolve_protected_content_mint_receipt",
            "network": chain_plan.network,
            "hash": transaction_hash,
            "creator": creator_address,
            "ledger": chain_plan.ledger,
            "token_uri": creator_state.token_uri(),
            "op_type_code": RUNTIME_CUSTODY_CREATOR_OP_TYPE_CODE,
        }),
    )
    .await
    .map_err(|error| creator_mint_chain_error(error, line!()))?;
    let receipt: ResolvedProtectedContentMintReceipt =
        serde_json::from_value(receipt_response).map_err(creator_mint_unavailable!())?;
    tracing::debug!(
        token_id = %receipt.token_id,
        operative = %receipt.operative,
        "runtime custody creator tail: mint receipt resolved"
    );
    Ok(receipt)
}

async fn finalize_runtime_custody_creator_listing(
    state: &GatewayState,
    creator_state: &elastos_protected_content_runtime::RuntimeMintCreatorState,
    creator_address: &str,
    chain_plan: &RuntimeCustodyCreatorChainPlan,
    receipt: &ResolvedProtectedContentMintReceipt,
    transaction_hash: &str,
) -> anyhow::Result<elastos_protected_content_runtime::RuntimeMintCreatorTerminalEvidence> {
    let listing_response = wallet_chain_provider_data(
        state,
        serde_json::json!({
            "op": "resolve_protected_content_verified_listing",
            "network": chain_plan.network,
            "seller": creator_address,
            "ledger": chain_plan.ledger,
            "token_id": receipt.token_id,
        }),
    )
    .await
    .map_err(|error| creator_mint_chain_error(error, line!()))?;
    let listing: ResolvedProtectedContentVerifiedListing =
        serde_json::from_value(listing_response).map_err(creator_mint_unavailable!())?;
    validate_runtime_custody_creator_terminal_bindings(
        creator_state,
        creator_address,
        chain_plan,
        receipt,
        &listing,
    )?;
    elastos_protected_content_runtime::RuntimeMintCreatorTerminalEvidence::new(
        creator_state.metadata_cid(),
        creator_state.token_uri(),
        creator_address,
        &chain_plan.chain_namespace,
        &chain_plan.network,
        &chain_plan.ledger,
        listing.token_id,
        listing.operative,
        listing.quantity,
        listing.price,
        listing.pay_token,
        listing
            .payment_processor
            .map(|value| value.to_ascii_lowercase()),
        transaction_hash,
        crate::auth::now_ts(),
    )
    .map_err(creator_mint_unavailable!())
}

pub(super) fn validate_runtime_custody_creator_terminal_bindings(
    creator_state: &elastos_protected_content_runtime::RuntimeMintCreatorState,
    creator_address: &str,
    chain_plan: &RuntimeCustodyCreatorChainPlan,
    receipt: &ResolvedProtectedContentMintReceipt,
    listing: &ResolvedProtectedContentVerifiedListing,
) -> anyhow::Result<()> {
    let expected_chain_id = runtime_custody_creator_chain_id(&chain_plan.chain_namespace)?;
    if receipt.schema != "elastos.chain.protected-content-mint-receipt/v1"
        || receipt.network != chain_plan.network
        || receipt.chain_id != expected_chain_id
    {
        return Err(creator_mint_unavailable_missing!()());
    }
    if listing.schema != "elastos.chain.protected-content-verified-listing/v1"
        || listing.network != chain_plan.network
        || listing.chain_id != expected_chain_id
        || listing.chain_id != receipt.chain_id
        || !listing.seller.eq_ignore_ascii_case(creator_address)
        || !listing.ledger.eq_ignore_ascii_case(&chain_plan.ledger)
        || !listing.token_id.eq_ignore_ascii_case(&receipt.token_id)
        || !listing.operative.eq_ignore_ascii_case(&receipt.operative)
        || listing.quantity != creator_state.desired_terms().copies()
        || listing.price != creator_state.desired_terms().price()
        || !listing
            .pay_token
            .eq_ignore_ascii_case(&chain_plan.pay_token)
    {
        return Err(creator_mint_unavailable_missing!()());
    }
    Ok(())
}

pub(crate) async fn runtime_custody_publish_via_gateway(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    registry: Arc<ProviderRegistry>,
    input: crate::protected_content_runtime::RuntimeCustodyLibrarySourceInput,
) -> anyhow::Result<crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts> {
    let (facts, prepared_input) =
        crate::protected_content_runtime::publish_runtime_custody_library_source(
            &state.data_dir,
            Arc::clone(&registry),
            input,
        )
        .await?;
    runtime_custody_publish_creator_tail_from_facts(
        state,
        authority,
        registry,
        prepared_input,
        facts,
    )
    .await
}

async fn runtime_custody_publish_creator_tail_from_facts(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    registry: Arc<ProviderRegistry>,
    input: crate::protected_content_runtime::RuntimeCustodyLibraryPublishInput,
    mut facts: crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts,
) -> anyhow::Result<crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts> {
    let mint_journal = crate::protected_content_runtime::runtime_mint_journal(&state.data_dir);
    let mut mint = mint_journal
        .load(facts.mint_id)
        .map_err(creator_mint_unavailable!())?;
    let source = resolve_runtime_custody_creator_mint_source(state).await?;
    if runtime_custody_creator_mint_source_digest_for_source(&source)
        != input.creator_mint_source_digest
    {
        return Err(creator_mint_unavailable_missing!()());
    }
    let creator_account =
        resolve_runtime_custody_creator_account(state, authority, &input.wallet_account_id).await?;
    if creator_account.address != input.wallet_account_address {
        return Err(creator_mint_unavailable_missing!()());
    }
    let desired_terms = elastos_protected_content_runtime::RuntimeMintCreatorDesiredTerms::new(
        creator_account.account_id.clone(),
        input.copies.clone(),
        input.price.clone(),
    )
    .map_err(creator_mint_unavailable!())?;
    if let Some(existing) = mint.creator_state() {
        if existing.desired_terms() != &desired_terms {
            return Err(creator_mint_unavailable_missing!()());
        }
        if let Some(terminal) = existing.terminal() {
            if !terminal
                .seller()
                .eq_ignore_ascii_case(&creator_account.address)
            {
                return Err(creator_mint_unavailable_missing!()());
            }
            facts.listing_uri = Some(
                publish_runtime_custody_creator_listing(
                    registry.as_ref(),
                    &state.data_dir,
                    &mint,
                    &facts,
                    &input.principal_id,
                    terminal,
                )
                .await?,
            );
            return Ok(facts);
        }
    }
    let creator_state = match mint.creator_state().cloned() {
        Some(existing) => existing,
        None => {
            let publisher_profile_did =
                crate::protected_content_runtime::load_runtime_custody_profile_did(
                    &state.data_dir,
                    &input.principal_id,
                )?;
            let (metadata_cid, token_uri) = publish_runtime_custody_creator_metadata(
                registry.as_ref(),
                &state.data_dir,
                &input.object_uri,
                &input.mime_type,
                &input.codecs,
                &facts,
                &mint,
                &publisher_profile_did,
            )
            .await?;
            let creator_state = elastos_protected_content_runtime::RuntimeMintCreatorState::new(
                desired_terms.clone(),
                metadata_cid,
                token_uri,
            )
            .map_err(creator_mint_unavailable!())?;
            mint = mint_journal
                .bind_creator_state(facts.mint_id, creator_state.clone())
                .map_err(creator_mint_unavailable!())?;
            creator_state
        }
    };
    let chain_plan = resolve_runtime_custody_creator_chain_plan(
        state,
        input.creator_mint_source_digest,
        &source,
        &creator_state,
        &creator_account.address,
        mint.draft().content_access_id(),
        creator_state.token_uri(),
    )
    .await?;
    tracing::debug!(
        mint_id = %hex::encode(facts.mint_id.as_bytes()),
        network = %chain_plan.network,
        to = %chain_plan.to,
        value = %chain_plan.value,
        "runtime custody creator tail: mint chain plan resolved"
    );
    let request = runtime_custody_creator_transaction_request(
        &input.principal_id,
        &creator_account,
        &creator_state,
        &chain_plan,
        facts.mint_id,
        creator_state.token_uri(),
    )?;
    let effect_binding = runtime_custody_creator_effect_binding(&request)?;
    if let Some(existing) = mint.creator_state().and_then(|state| state.effect()) {
        if existing != &effect_binding {
            return Err(creator_mint_unavailable_missing!()());
        }
    } else {
        mint_journal
            .bind_creator_effect(facts.mint_id, effect_binding.clone())
            .map_err(creator_mint_unavailable!())?;
    }
    let approval = ensure_exact_runtime_transaction_approval(state, authority, request.clone())
        .await
        .map_err(|(_, message)| anyhow::anyhow!(message))?;
    tracing::debug!(
        effect_id = %approval.effect_id,
        "runtime custody creator tail: exact wallet effect ensured"
    );
    let completion = match complete_runtime_transaction_effect(
        state,
        authority,
        RuntimeTransactionLookup::ApprovalId(effect_binding.approval_request_id()),
        Some(&request),
        None,
    )
    .await
    {
        Ok(completion) => completion,
        Err((status, message))
            if status == StatusCode::BAD_REQUEST
                && message == "transaction approval is not completed" =>
        {
            let _ = approval;
            {
                tracing::debug!(
                    line = line!(),
                    "runtime custody creator tail: pending exact Wallet or Chain settlement"
                );
                anyhow::bail!(RUNTIME_CUSTODY_CREATOR_PENDING_MESSAGE);
            }
        }
        Err((_, message)) => return Err(anyhow::anyhow!(message)),
    };
    if completion.receipt.is_none() {
        {
            tracing::debug!(
                line = line!(),
                "runtime custody creator tail: pending exact Wallet or Chain settlement"
            );
            anyhow::bail!(RUNTIME_CUSTODY_CREATOR_PENDING_MESSAGE);
        }
    }
    if completion.completion_pending {
        {
            tracing::debug!(
                line = line!(),
                "runtime custody creator tail: pending exact Wallet or Chain settlement"
            );
            anyhow::bail!(RUNTIME_CUSTODY_CREATOR_PENDING_MESSAGE);
        }
    }
    if completion.completion_error.is_some() {
        return Err(creator_mint_unavailable_missing!()());
    }
    // The finalized receipt names the operative that holds the minted copies.
    // A listing only becomes deliverable once that operative lets the market
    // gateway move them (ERC-1155 operator approval); the mint itself never
    // grants that, so raise it here as a second exact wallet effect when the
    // chain does not already report it, then verify the listing.
    let receipt = resolve_runtime_custody_creator_mint_receipt(
        state,
        &creator_state,
        &creator_account.address,
        &chain_plan,
        &completion.transaction_hash,
    )
    .await?;
    ensure_runtime_custody_creator_operator_approval(
        state,
        authority,
        &mint_journal,
        &mint,
        facts.mint_id,
        &input.principal_id,
        &creator_account,
        &chain_plan,
        &receipt.operative,
    )
    .await?;
    let terminal = finalize_runtime_custody_creator_listing(
        state,
        &creator_state,
        &creator_account.address,
        &chain_plan,
        &receipt,
        &completion.transaction_hash,
    )
    .await?;
    mint = mint_journal
        .mark_creator_completed(facts.mint_id, terminal.clone())
        .map_err(creator_mint_unavailable!())?;
    facts.listing_uri = Some(
        publish_runtime_custody_creator_listing(
            registry.as_ref(),
            &state.data_dir,
            &mint,
            &facts,
            &input.principal_id,
            &terminal,
        )
        .await?,
    );
    Ok(facts)
}

#[cfg(test)]
pub(crate) async fn runtime_custody_publish_creator_tail_for_test(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    registry: Arc<ProviderRegistry>,
    input: crate::protected_content_runtime::RuntimeCustodyLibraryPublishInput,
    facts: crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts,
) -> anyhow::Result<crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts> {
    runtime_custody_publish_creator_tail_from_facts(state, authority, registry, input, facts).await
}

use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use elastos_protected_content_contracts::{CanonicalContract, Digest32};
use sha2::Digest as _;

use super::*;
use elastos_model_contract::{
    model_input_hash, RuntimeAccessBinding, RuntimeCreateBinding, RUNTIME_ACCESS_BINDING_SCHEMA,
    RUNTIME_CREATE_BINDING_SCHEMA,
};

const ASSISTANT_CAPSULE_ID: &str = "assistant";
/// The Home Agent capsule reaches the model provider through the same typed
/// contract as Assistant; every run is bound and audited to the capsule the
/// launch token was issued for.
const HOME_AGENT_CAPSULE_ID: &str = "home-agent";
const MODEL_TEXT_OUTPUT_SCHEMA: &str = "elastos.model.output.text/v1";
const MODEL_OBJECT_OUTPUT_SCHEMA: &str = "elastos.model.output.object/v1";
const MODEL_CONTENT_OUTPUT_SCHEMA: &str = "elastos.model.output.content/v1";
const MODEL_OUTPUT_URI_MAX_BYTES: usize = 4 * 1024;
use crate::protected_content_runtime::{ELACITY_PLAYER_CAPSULE_ID, ELACITY_READER_CAPSULE_ID};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelRunsCreateGatewayRequest {
    offer_id: String,
    operation: String,
    input: serde_json::Value,
    request_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelRunAccessGatewayRequest {
    run_id: String,
    request_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelRunEventsGatewayRequest {
    run_id: String,
    request_id: String,
    #[serde(default)]
    after_sequence: Option<u64>,
}

struct ModelProviderEffectAudit<'a> {
    request_id: &'a str,
    requested_event: &'static str,
    completed_event: &'static str,
    failed_event: &'static str,
    requested_reason: &'static str,
    completed_reason: &'static str,
    failed_reason: &'static str,
}

/// The creator tail fails closed with one opaque message; keep the actual
/// cause and its source line in the operator log so a live failure can be
/// located without re-instrumenting.
macro_rules! creator_mint_unavailable {
    () => {
        |error| {
            tracing::warn!(
                line = line!(),
                error = ?error,
                "Runtime custody creator mint failed closed"
            );
            anyhow::anyhow!("{:?}", error)
                .context(format!("{}:{}", file!(), line!()))
                .context(RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE)
        }
    };
}

/// Download refuses for one reason a person can act on -- the copy is not
/// theirs -- and fails closed for everything else, with the cause in the log.
macro_rules! download_denied {
    () => {
        |error| {
            tracing::warn!(
                line = line!(),
                error = ?error,
                "Runtime custody download denied without an owned copy"
            );
            anyhow::anyhow!("{:?}", error)
                .context(format!("{}:{}", file!(), line!()))
                .context(crate::protected_content_runtime::RUNTIME_CUSTODY_DOWNLOAD_DENIED_MESSAGE)
        }
    };
}

macro_rules! download_denied_missing {
    () => {
        || {
            tracing::warn!(
                line = line!(),
                "Runtime custody download denied without an owned copy"
            );
            anyhow::anyhow!("{}:{}", file!(), line!())
                .context(crate::protected_content_runtime::RUNTIME_CUSTODY_DOWNLOAD_DENIED_MESSAGE)
        }
    };
}

macro_rules! download_unavailable {
    () => {
        |error| {
            tracing::warn!(
                line = line!(),
                error = ?error,
                "Runtime custody download failed closed"
            );
            anyhow::anyhow!("{:?}", error)
                .context(format!("{}:{}", file!(), line!()))
                .context(
                    crate::protected_content_runtime::RUNTIME_CUSTODY_DOWNLOAD_UNAVAILABLE_MESSAGE,
                )
        }
    };
}

macro_rules! download_unavailable_missing {
    () => {
        || {
            tracing::warn!(line = line!(), "Runtime custody download failed closed");
            anyhow::anyhow!("{}:{}", file!(), line!()).context(
                crate::protected_content_runtime::RUNTIME_CUSTODY_DOWNLOAD_UNAVAILABLE_MESSAGE,
            )
        }
    };
}

/// Same operator-log discipline for the buyer side: "purchase is denied
/// before buy" is one opaque message over many fail-closed preconditions.
macro_rules! purchase_denied {
    () => {
        |error| {
            tracing::warn!(
                line = line!(),
                error = ?error,
                "Runtime custody purchase denied before buy"
            );
            anyhow::anyhow!("{:?}", error)
                .context(format!("{}:{}", file!(), line!()))
                .context(crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_DENIED_MESSAGE)
        }
    };
}

macro_rules! purchase_denied_missing {
    () => {
        || {
            tracing::warn!(line = line!(), "Runtime custody purchase denied before buy");
            anyhow::anyhow!("{}:{}", file!(), line!())
                .context(crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_DENIED_MESSAGE)
        }
    };
}

macro_rules! purchase_unavailable {
    () => {
        |error| {
            tracing::warn!(
                line = line!(),
                error = ?error,
                "Runtime custody purchase failed closed"
            );
            anyhow::anyhow!("{:?}", error)
                .context(format!("{}:{}", file!(), line!()))
                .context(crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_UNAVAILABLE_MESSAGE)
        }
    };
}

macro_rules! purchase_unavailable_missing {
    () => {
        || {
            tracing::warn!(line = line!(), "Runtime custody purchase failed closed");
            anyhow::anyhow!("{}:{}", file!(), line!()).context(
                crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_UNAVAILABLE_MESSAGE,
            )
        }
    };
}

// The buy-side refusal helpers, shared with `gateway_marketplace_buy`.
pub(super) use purchase_denied;
pub(super) use purchase_denied_missing;
pub(super) use purchase_unavailable;
pub(super) use purchase_unavailable_missing;

macro_rules! creator_mint_unavailable_missing {
    () => {
        || {
            tracing::warn!(line = line!(), "Runtime custody creator mint failed closed");
            anyhow::anyhow!("{}:{}", file!(), line!())
                .context(RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE)
        }
    };
}

#[path = "gateway_provider_proxy/creator_publish.rs"]
mod creator_publish;
#[path = "gateway_provider_proxy/custody_buy.rs"]
mod custody_buy;
#[path = "gateway_provider_proxy/library_transfer.rs"]
mod library_transfer;

pub(crate) use self::creator_publish::*;
pub(crate) use self::custody_buy::*;
pub(super) use self::library_transfer::*;

// The creator-mint wire, defined once in the contracts crate and used by both
// sides of it. These aliases keep the names this file already reads by.
//
// Declaring these shapes here as well is what let four field mismatches reach
// a person: `deny_unknown_fields` on one side and a JSON literal on the other,
// reconciled only by a hand-written mock that the tests answered with instead
// of the capsule.
pub(crate) use elastos_protected_content_contracts::{
    ProtectedContentCreatorMintSourceV1 as ResolvedProtectedContentCreatorMintSource,
    ProtectedContentCreatorMintV1 as ResolvedProtectedContentCreatorMint,
    ProtectedContentMintReceiptV1 as ResolvedProtectedContentMintReceipt,
};

/// One pay token the deployment offers, as the capsule describes it.

#[derive(Clone)]
pub(in crate::api::gateway) struct RuntimeCustodyCreatorAccount {
    pub(super) account_id: String,
    pub(super) address: String,
    /// Not an authority decision -- `signing_available` already made that. This
    /// only lets a pending answer say whose turn it is: an external signer's
    /// outstanding approval is waiting on the person, a managed one is not.
    pub(super) external_signer: bool,
    pub(super) connector_id: Option<String>,
}

pub(super) async fn gateway_provider_proxy(
    State(state): State<GatewayState>,
    Path((scheme, op)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Keep the large coordinator future out of this additional tracing frame.
    // Both traced and untraced operations retain their existing dispatch.
    if scheme != "object" || op != "import_runtime_custody" {
        return Box::pin(gateway_provider_proxy_inner(
            State(state),
            Path((scheme, op)),
            headers,
            body,
        ))
        .await;
    }
    let mut trace = crate::action_trace::ActionTrace::new(
        headers
            .get("x-elastos-action-id")
            .and_then(|value| value.to_str().ok()),
        "import_runtime_custody",
        "",
        "",
    );
    let mut response = tracing::Instrument::instrument(
        Box::pin(gateway_provider_proxy_inner(
            State(state),
            Path((scheme, op)),
            headers,
            body,
        )),
        trace.span(),
    )
    .await;
    trace.complete(&mut response);
    response
}

pub(in crate::api::gateway) async fn resolve_runtime_custody_wallet_default_account(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    chain_namespace: &str,
    unavailable_message: &'static str,
) -> anyhow::Result<RuntimeCustodyCreatorAccount> {
    // Every arm below fails closed with the caller's one opaque message, per
    // this file's discipline, and keeps it outermost so nothing that matches on
    // that sentence breaks. Each arm names WHICH precondition failed twice over,
    // because the two readers differ: in the operator log, without which the
    // five causes are indistinguishable and a live failure reads as an
    // unexplained "unavailable"; and as a typed reason beneath the sentence,
    // which is what an app branches on to offer the one action that fixes it.
    // Reason codes and the chain namespace only -- never an account id,
    // address, or balance.
    use crate::protected_content_runtime::{
        RuntimeCustodyWalletDefaultReason, RuntimeCustodyWalletDefaultUnusable,
    };
    use elastos_wallet_contract::{
        account_serves_chain_namespace, chain_namespaces_compatible, is_evm_eoa_proof_type,
    };
    let accounts = system_wallet_accounts_summary(state, authority).await;
    let namespace_accounts = accounts
        .accounts
        .iter()
        .filter(|account| chain_namespaces_compatible(&account.chain_namespace, chain_namespace))
        .count();
    // A default set on this chain itself wins. Without one, the Wallet's EVM
    // default serves it: the Wallet keeps a single EVM default for every EVM
    // chain, so the native EVM account a fresh Home creates is the creator's
    // Base account too. That reuse holds only for an externally owned
    // account; a contract account exists only on the chain it was deployed to.
    let transaction_defaults = || {
        accounts
            .default_accounts
            .iter()
            .filter(|default| default.intent == "transaction_intent")
    };
    let exact_default_exists =
        transaction_defaults().any(|default| default.chain_namespace == chain_namespace);
    let serves_chain = |default: &&SystemWalletDefaultSummary| {
        if exact_default_exists {
            default.chain_namespace == chain_namespace
        } else {
            chain_namespaces_compatible(&default.chain_namespace, chain_namespace)
                && accounts
                    .accounts
                    .iter()
                    .find(|account| account.account_id == default.account_id)
                    // A missing account is refused below with its own reason.
                    .is_none_or(|account| is_evm_eoa_proof_type(&account.proof_type))
        }
    };
    let latest_default = transaction_defaults()
        .filter(serves_chain)
        .max_by_key(|default| default.set_at)
        .ok_or_else(|| {
            let unusable = RuntimeCustodyWalletDefaultUnusable::new(
                RuntimeCustodyWalletDefaultReason::NoTransactionDefaultForChainNamespace,
                chain_namespace,
            );
            tracing::warn!(
                line = line!(),
                reason = unusable.reason_label(),
                chain_namespace,
                wallet_accounts_total = accounts.accounts.len(),
                wallet_accounts_on_chain_namespace = namespace_accounts,
                "Runtime custody wallet default account failed closed"
            );
            anyhow::Error::new(unusable).context(unavailable_message)
        })?;
    if transaction_defaults().filter(serves_chain).any(|default| {
        default.set_at == latest_default.set_at && default.account_id != latest_default.account_id
    }) {
        let unusable = RuntimeCustodyWalletDefaultUnusable::new(
            RuntimeCustodyWalletDefaultReason::AmbiguousTransactionDefault,
            chain_namespace,
        );
        tracing::warn!(
            line = line!(),
            reason = unusable.reason_label(),
            chain_namespace,
            "Runtime custody wallet default account failed closed"
        );
        return Err(anyhow::Error::new(unusable).context(unavailable_message));
    }
    let account = accounts
        .accounts
        .iter()
        // The default must name an account that serves both the chain it was
        // set for, as the Wallet only ever records, and this one. An
        // externally owned account serves every EVM chain; a record naming
        // any other account off its own chain is not trusted.
        .find(|account| {
            account.account_id == latest_default.account_id
                && account_serves_chain_namespace(
                    &account.chain_namespace,
                    &account.proof_type,
                    &latest_default.chain_namespace,
                )
                && account_serves_chain_namespace(
                    &account.chain_namespace,
                    &account.proof_type,
                    chain_namespace,
                )
        })
        .ok_or_else(|| {
            let unusable = RuntimeCustodyWalletDefaultUnusable::new(
                RuntimeCustodyWalletDefaultReason::DefaultAccountNotInWallet,
                chain_namespace,
            );
            tracing::warn!(
                line = line!(),
                reason = unusable.reason_label(),
                chain_namespace,
                wallet_accounts_on_chain_namespace = namespace_accounts,
                "Runtime custody wallet default account failed closed"
            );
            anyhow::Error::new(unusable).context(unavailable_message)
        })?;
    // `signing_available` is the whole precondition, and it already tells a
    // connector-linked external account (signable through the handoff) apart
    // from an unlinked one (not signable). The tail past this point needs an
    // address and a completed approval — it never asks the Wallet to sign — so
    // requiring a managed proof type here only shut out linked external wallets.
    if !account.signing_available {
        let unusable = RuntimeCustodyWalletDefaultUnusable::new(
            RuntimeCustodyWalletDefaultReason::DefaultAccountSigningUnavailable,
            chain_namespace,
        );
        tracing::warn!(
            line = line!(),
            reason = unusable.reason_label(),
            chain_namespace,
            "Runtime custody wallet default account failed closed"
        );
        return Err(anyhow::Error::new(unusable).context(unavailable_message));
    }
    validate_wallet_evm_address(&account.address, "wallet").map_err(|_| {
        let unusable = RuntimeCustodyWalletDefaultUnusable::new(
            RuntimeCustodyWalletDefaultReason::DefaultAccountAddressInvalid,
            chain_namespace,
        );
        tracing::warn!(
            line = line!(),
            reason = unusable.reason_label(),
            chain_namespace,
            "Runtime custody wallet default account failed closed"
        );
        anyhow::Error::new(unusable).context(unavailable_message)
    })?;
    Ok(RuntimeCustodyCreatorAccount {
        account_id: account.account_id.clone(),
        address: account.address.to_ascii_lowercase(),
        external_signer: !is_managed_wallet_proof_type(&account.proof_type),
        connector_id: account.connector_id.clone(),
    })
}

/// Build the confirmed-stage record for a purchase stage from its Runtime
/// transaction completion, or `None` if the completion has no validated
/// Chain outcome attached yet (the caller must treat that the same as
/// pending -- `RUNTIME_CUSTODY_PURCHASE_PENDING_MESSAGE`/`purchase_unavailable_missing!`).
pub(super) fn confirmed_stage(
    completion: RuntimeTransactionCompletion,
) -> Option<crate::protected_content_runtime::RuntimeCustodyConfirmedPurchaseStage> {
    let outcome = completion.validated_chain_outcome?;
    Some(
        crate::protected_content_runtime::RuntimeCustodyConfirmedPurchaseStage {
            chain_transaction: completion.transaction_hash,
            wallet_binding: outcome.binding,
            chain_observation: outcome.chain_observation,
            confirmed_at: outcome.confirmed_at,
        },
    )
}

#[cfg(test)]
pub(crate) mod test_seams {
    pub(crate) async fn materialize_owned_artifacts(
        registry: &elastos_runtime::provider::ProviderRegistry,
        package: &crate::protected_content_runtime::RuntimePortableListingPackage,
    ) {
        super::materialize_runtime_custody_artifacts(registry, package).await;
    }
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    static LISTING_COPY_HOLDERS: Mutex<Option<HashMap<PathBuf, Vec<String>>>> = Mutex::new(None);

    /// The pool members a test's Home places its listings on, in place of
    /// its pool descriptors.
    pub(crate) fn set_listing_copy_holders(data_dir: &Path, holders: Vec<String>) {
        LISTING_COPY_HOLDERS
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .insert(data_dir.to_path_buf(), holders);
    }

    pub(super) fn listing_copy_holders(data_dir: &Path) -> Option<Vec<String>> {
        LISTING_COPY_HOLDERS
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|holders| holders.get(data_dir).cloned())
    }
}

/// The typed refusal of a new attempt that would re-term a mint already on
/// record, built directly so its wire spelling can be pinned. In service the
/// same refusal comes from `RuntimeCustodyAttemptArchiveOutcome::kept_refusal`,
/// for an attempt whose transaction was sent or mined, or that is listed.
#[cfg(test)]
fn runtime_custody_creator_mint_blocked(
    mint_id: Digest32,
    existing: &elastos_protected_content_runtime::RuntimeMintCreatorState,
    progress: Option<serde_json::Value>,
    conflict: Option<crate::protected_content_runtime::RuntimeCustodyCreatorMintConflict>,
) -> anyhow::Error {
    let mut blocked =
        crate::protected_content_runtime::RuntimeCustodyCreatorMintBlocked::new(mint_id, existing);
    if let Some(progress) = progress {
        blocked = blocked.with_progress(progress);
    }
    if let Some(conflict) = conflict {
        blocked = blocked.with_conflict(conflict);
    }
    tracing::warn!(
        line = line!(),
        state = blocked.state_label(),
        "Runtime custody creator mint refused new terms for a mint already on record"
    );
    anyhow::Error::new(blocked)
}

/// File an owned protected item into its owner's Library as a `.ddrm`.
///
/// The capsule carries the asset's own `metadata.json` whole, so the Library
/// can show it and the viewer can open it without fetching anything; the
/// document is read back from the CID it was published under rather than kept
/// from whatever built it, so a copy acquired by buying is assembled exactly
/// like one acquired by minting.
///
/// When the metadata states no authority -- because none was configured at the
/// time it was written -- it is asked for now and filled in, which is the whole
/// reason the authority sits at the capsule's top level rather than only inside
/// the metadata it was published with.
///
/// Best effort: the asset is owned whether or not a file could be written for
/// it, and the owner keeps it either way. `None` when nothing was filed.
pub(super) async fn write_runtime_custody_owned_capsule(
    state: &GatewayState,
    registry: &ProviderRegistry,
    package: &crate::protected_content_runtime::RuntimePortableListingPackage,
    principal_id: &str,
    acquisition: crate::protected_content_runtime::RuntimeCustodyAcquisitionV1,
) -> Option<String> {
    let metadata = match crate::content::fetch_bytes_via_provider(
        registry,
        &package.metadata_cid,
        Some("metadata.json"),
    )
    .await
    .ok()
    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    {
        Some(metadata) => metadata,
        None => {
            tracing::debug!("runtime custody: no metadata document to build a capsule from");
            return None;
        }
    };
    let mut capsule = crate::protected_content_runtime::runtime_custody_capsule_document(
        package,
        &metadata,
        acquisition,
    );
    if capsule
        .get("authority")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .is_empty()
    {
        if let Some(authority) = runtime_custody_market_authority(state, &package.network).await {
            capsule["authority"] = serde_json::Value::String(authority);
        }
    }
    // The asset's material belongs on the machine that owns it, whether this
    // copy was minted here or bought from someone else.
    materialize_runtime_custody_artifacts(registry, package).await;
    let content_type =
        crate::protected_content_runtime::runtime_custody_capsule_content_type(&metadata);
    match crate::library::write_runtime_custody_capsule(
        &state.data_dir,
        principal_id,
        &package.display_name,
        &content_type,
        &capsule,
    ) {
        Ok(uri) => Some(uri),
        Err(error) => {
            tracing::warn!(error = %error, "runtime custody: the owned capsule was not filed");
            None
        }
    }
}

/// Keep an owned asset's material on the machine that owns it.
///
/// Content owns the local retention attempt. Recursive
/// pinning keeps a DASH directory's segments as well as its manifest. The
/// existing content read path owns delivery of material this Home lacks.
///
/// Silent and best effort, as the owner asked: nothing here is shown, and an
/// asset whose material could not be kept is still owned and still readable --
/// just over the network until the next attempt.
async fn materialize_runtime_custody_artifacts(
    registry: &ProviderRegistry,
    package: &crate::protected_content_runtime::RuntimePortableListingPackage,
) {
    for cid in [&package.content_cid, &package.metadata_cid] {
        if cid.trim().is_empty() {
            continue;
        }
        if let Err(error) = crate::content::retain_local_via_provider(registry, cid).await {
            tracing::debug!(
                error = %error,
                "runtime custody: owned material was not kept locally"
            );
        }
    }
}

/// The authority gateway this network's market is configured with, asked for
/// when an asset's metadata did not state one.
async fn runtime_custody_market_authority(state: &GatewayState, network: &str) -> Option<String> {
    let response = wallet_chain_provider_data(
        state,
        serde_json::json!({
            "op": "describe_protected_content_market_source",
            "network": network,
        }),
    )
    .await
    .ok()?;
    response
        .get("authority_gateway_contract")
        .and_then(serde_json::Value::as_str)
        .filter(|authority| !authority.is_empty())
        .map(str::to_string)
}

pub(super) fn provider_proxy_runtime_metadata_field(request: &serde_json::Value) -> Option<&str> {
    request
        .as_object()?
        .keys()
        .find(|key| {
            key.starts_with("_runtime")
                || matches!(key.as_str(), "connect_ticket" | "carrier_route" | "carrier")
        })
        .map(String::as_str)
}

const HOSTED_RUN_ADMIN_ONLY: &str =
    "Hosted AI on this Home is for admins. Local models are still available.";

/// Hosted AI spends this Home's paid connection, so in 0.8.0 only an admin's
/// run may use a hosted offer. Other offers are not affected.
fn hosted_run_allowed(
    data_dir: &std::path::Path,
    context: &HomeLaunchTokenContext,
    request: &serde_json::Value,
) -> bool {
    let offer_id = request["offer_id"].as_str().unwrap_or_default();
    if !crate::api::model_provider_config::is_hosted_offer_id(offer_id) {
        return true;
    }
    context
        .proof_binding_id
        .as_deref()
        .and_then(|proof| crate::auth::load_principal_for_proof_binding(data_dir, proof).ok())
        .is_some_and(|principal| {
            crate::auth::ensure_proof_binding_not_revoked(&principal).is_ok()
                && principal.principal_id == context.principal_id
                && crate::auth::is_admin(&principal)
        })
}

pub(super) fn normalize_model_provider_request(
    op: &str,
    request: &serde_json::Value,
    context: &HomeLaunchTokenContext,
    capsule_id: &str,
) -> Result<serde_json::Value, (StatusCode, String)> {
    match op {
        "offers_list" => {
            if request.as_object().is_some_and(|value| value.is_empty()) {
                Ok(serde_json::json!({ "op": "offers_list" }))
            } else {
                Err((
                    StatusCode::BAD_REQUEST,
                    "model offers_list request must be an empty JSON object".to_string(),
                ))
            }
        }
        "runs_create" => {
            let parsed = serde_json::from_value::<ModelRunsCreateGatewayRequest>(request.clone())
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            let runtime_binding = RuntimeCreateBinding {
                schema: RUNTIME_CREATE_BINDING_SCHEMA.to_string(),
                principal_id: context.principal_id.clone(),
                session_id: context.session_id.clone(),
                capsule_id: capsule_id.to_string(),
                grant_id: context.grant_id.clone(),
                request_id: parsed.request_id,
                offer_id: parsed.offer_id.clone(),
                operation: parsed.operation.clone(),
                input_hash: model_input_hash(&parsed.input).map_err(|err| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("invalid model input: {err}"),
                    )
                })?,
            };
            runtime_binding
                .validate(&parsed.offer_id, &parsed.operation, &parsed.input)
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            Ok(serde_json::json!({
                "op": "runs_create",
                "offer_id": parsed.offer_id,
                "operation": parsed.operation,
                "input": parsed.input,
                "runtime_binding": runtime_binding,
            }))
        }
        "runs_get" | "runs_cancel" => {
            let parsed = serde_json::from_value::<ModelRunAccessGatewayRequest>(request.clone())
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            let runtime_binding = RuntimeAccessBinding {
                schema: RUNTIME_ACCESS_BINDING_SCHEMA.to_string(),
                principal_id: context.principal_id.clone(),
                session_id: context.session_id.clone(),
                capsule_id: capsule_id.to_string(),
                grant_id: context.grant_id.clone(),
                request_id: parsed.request_id,
                run_id: parsed.run_id.clone(),
            };
            runtime_binding
                .validate(&parsed.run_id)
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            Ok(serde_json::json!({
                "op": op,
                "run_id": parsed.run_id,
                "runtime_binding": runtime_binding,
            }))
        }
        "runs_events" => {
            let parsed = serde_json::from_value::<ModelRunEventsGatewayRequest>(request.clone())
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            let runtime_binding = RuntimeAccessBinding {
                schema: RUNTIME_ACCESS_BINDING_SCHEMA.to_string(),
                principal_id: context.principal_id.clone(),
                session_id: context.session_id.clone(),
                capsule_id: capsule_id.to_string(),
                grant_id: context.grant_id.clone(),
                request_id: parsed.request_id,
                run_id: parsed.run_id.clone(),
            };
            runtime_binding
                .validate(&parsed.run_id)
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            Ok(serde_json::json!({
                "op": "runs_events",
                "run_id": parsed.run_id,
                "after_sequence": parsed.after_sequence,
                "runtime_binding": runtime_binding,
            }))
        }
        _ => Err((
            StatusCode::NOT_FOUND,
            "Gateway provider operation not found".to_string(),
        )),
    }
}

/// The Bus model path stamps the run binding as the gateway does: from the
/// bridge's own caller context. The session is the
/// bridge's launch handle and the grant is the capability token the Runtime
/// validated for this call. Errors are `(code, message)`.
pub(crate) fn bus_model_provider_request(
    op: &str,
    body: &serde_json::Value,
    data_dir: Option<&std::path::Path>,
    principal_id: Option<&str>,
    session_id: &str,
    grant_id: &str,
    capsule_id: &str,
) -> Result<serde_json::Value, (&'static str, String)> {
    let refused = |message: String| ("principal_context_required", message);
    let principal_id = principal_id.filter(|id| !id.trim().is_empty());
    let (Some(data_dir), Some(principal_id)) = (data_dir, principal_id) else {
        return Err(refused(
            "model runs require a principal-scoped launch context".to_string(),
        ));
    };
    if [session_id, grant_id, capsule_id]
        .iter()
        .any(|id| id.trim().is_empty())
    {
        return Err(refused(
            "model runs require a launch session and grant".to_string(),
        ));
    }
    let proof_binding_id = crate::auth::load_auth_state(data_dir)
        .ok()
        .and_then(|state| {
            state
                .principals
                .into_iter()
                .find(|principal| principal.principal_id == principal_id)
        })
        .map(|principal| principal.proof_binding_id);
    let context = HomeLaunchTokenContext {
        principal_id: principal_id.to_string(),
        session_id: session_id.to_string(),
        proof_binding_id,
        grant_id: grant_id.to_string(),
    };
    let mut body = body.clone();
    if let Some(object) = body.as_object_mut() {
        object.remove("op");
        object.remove("runtime_binding");
    }
    let request = normalize_model_provider_request(op, &body, &context, capsule_id)
        .map_err(|(_, message)| ("invalid_model_request", message))?;
    if op == "runs_create" && !hosted_run_allowed(data_dir, &context, &request) {
        return Err(("hosted_run_admin_only", HOSTED_RUN_ADMIN_ONLY.to_string()));
    }
    Ok(request)
}

fn local_model_request_expiry_refusal(
    request: &serde_json::Value,
    response: &serde_json::Value,
) -> Option<serde_json::Value> {
    if request["op"] != "runs_create"
        || !super::gateway_model_service::provider_refused_expired_request(response)
    {
        return None;
    }
    let binding: RuntimeCreateBinding =
        serde_json::from_value(request.get("runtime_binding")?.clone()).ok()?;
    binding
        .validate(
            request["offer_id"].as_str()?,
            request["operation"].as_str()?,
            request.get("input")?,
        )
        .ok()?;
    Some(serde_json::json!({
        "status": "error", "code": "model_invocation_refused",
        "reason": elastos_model_contract::MODEL_REQUEST_EXPIRED_CODE,
        "message": elastos_model_contract::MODEL_REQUEST_EXPIRED_MESSAGE,
        "refusal": {
            "schema": super::gateway_model_service::INVOCATION_REFUSAL_SCHEMA,
            "scope": "invocation", "dispatch": "provider_refused",
            "request_id": binding.request_id, "offer_id": binding.offer_id,
            "operation": binding.operation, "input_hash": binding.input_hash,
        },
    }))
}

fn model_provider_effect_audit<'a>(
    scheme: &str,
    op: &str,
    request: &'a serde_json::Value,
) -> Option<ModelProviderEffectAudit<'a>> {
    if scheme != "model" {
        return None;
    }
    let request_id = request.pointer("/runtime_binding/request_id")?.as_str()?;
    match op {
        "runs_create" => Some(ModelProviderEffectAudit {
            request_id,
            requested_event: "model.run_create.requested",
            completed_event: "model.run_create.completed",
            failed_event: "model.run_create.failed",
            requested_reason: "Assistant requested model run creation",
            completed_reason: "Assistant completed model run creation",
            failed_reason: "Assistant failed model run creation",
        }),
        "runs_cancel" => Some(ModelProviderEffectAudit {
            request_id,
            requested_event: "model.run_cancel.requested",
            completed_event: "model.run_cancel.completed",
            failed_event: "model.run_cancel.failed",
            requested_reason: "Assistant requested model run cancellation",
            completed_reason: "Assistant completed model run cancellation",
            failed_reason: "Assistant failed model run cancellation",
        }),
        _ => None,
    }
}

pub(super) fn project_model_provider_response(
    op: &str,
    response: &mut serde_json::Value,
) -> anyhow::Result<()> {
    if response.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
        return Ok(());
    }
    match op {
        "runs_get" => {
            if let Some(output) = response.pointer_mut("/data/terminal/output") {
                project_model_run_output(output)?;
            }
        }
        "runs_events" => {
            let events = response
                .pointer_mut("/data/events")
                .and_then(serde_json::Value::as_array_mut)
                .ok_or_else(|| anyhow::anyhow!("model run events response is missing events"))?;
            for event in events {
                if event.get("kind").and_then(serde_json::Value::as_str) == Some("output") {
                    project_model_run_output(event.get_mut("data").ok_or_else(|| {
                        anyhow::anyhow!("model output event is missing typed data")
                    })?)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn project_model_run_output(output: &mut serde_json::Value) -> anyhow::Result<()> {
    let object = output
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("model run output must be an object"))?;
    let schema = object
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("model run output is missing schema"))?
        .to_string();
    match schema.as_str() {
        MODEL_TEXT_OUTPUT_SCHEMA => {
            if object.len() != 2
                || object
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .is_none()
            {
                anyhow::bail!("model text output must contain only schema and text");
            }
        }
        MODEL_OBJECT_OUTPUT_SCHEMA => {
            project_model_output_resource(object, "elastos://object/")?;
        }
        MODEL_CONTENT_OUTPUT_SCHEMA => {
            project_model_output_resource(object, "elastos://content/")?;
        }
        _ => anyhow::bail!("model run output uses an unsupported schema"),
    }
    Ok(())
}

fn project_model_output_resource(
    output: &mut serde_json::Map<String, serde_json::Value>,
    prefix: &str,
) -> anyhow::Result<()> {
    if output.len() != 2 {
        anyhow::bail!("model resource output must contain only schema and uri");
    }
    let uri = output
        .get("uri")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("model resource output is missing uri"))?;
    if uri.trim() != uri
        || uri.len() <= prefix.len()
        || uri.len() > MODEL_OUTPUT_URI_MAX_BYTES
        || !uri.starts_with(prefix)
        || uri.bytes().any(|byte| byte.is_ascii_control())
    {
        anyhow::bail!("model resource output has an invalid Runtime resource uri");
    }
    let resource_id = uri[prefix.len()..].to_string();
    output.remove("uri");
    output.insert(
        "resource_id".to_string(),
        serde_json::Value::String(resource_id),
    );
    Ok(())
}

fn library_operation_emits_events(op: &str) -> bool {
    matches!(
        op,
        "write"
            | "mkdir"
            | "rename"
            | "move"
            | "copy"
            | "trash"
            | "restore"
            | "delete_permanently"
            | "empty_trash"
            | "extract_archive"
            | "archive_extract_entries"
            | "compress_archive"
            | "publish"
            | "unpublish"
            | "repair"
            | "share"
    )
}

fn library_operation_needs_runtime_coordinator(op: &str) -> bool {
    matches!(
        op,
        "publish"
            | "unpublish"
            | "repair"
            | "discard_protection"
            | "unfinished_protections"
            | "sync"
            | "list_runtime_custody"
            | "import_runtime_custody"
            | "buy"
            | "buy_offer"
            | "download_owned_copy"
            | "open_viewer"
            | "read_viewer"
            | "close_viewer"
    )
}

fn library_request_targets_webspace(request: &serde_json::Value) -> bool {
    ["uri", "parent_uri", "target_uri", "target_parent_uri"]
        .iter()
        .filter_map(|field| request.get(field).and_then(|value| value.as_str()))
        .map(str::trim)
        .map(|value| value.trim_end_matches('/'))
        .any(|value| {
            value == "localhost://WebSpaces"
                || value
                    .strip_prefix("localhost://WebSpaces/")
                    .is_some_and(|rest| !rest.is_empty())
        })
}

#[cfg(test)]
mod tests {
    #[test]
    fn fail_closed_macros_keep_the_stable_message_and_carry_the_cause() {
        let error = (creator_mint_unavailable!())("boom");
        assert_eq!(
            error.to_string(),
            RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE
        );
        let chain: Vec<String> = error.chain().map(|cause| cause.to_string()).collect();
        assert_eq!(chain.len(), 3);
        assert!(chain[1].contains("gateway_provider_proxy.rs:"));
        assert_eq!(chain[2], "\"boom\"");
        let missing = (purchase_denied_missing!())();
        assert_eq!(
            missing.to_string(),
            crate::protected_content_runtime::RUNTIME_CUSTODY_PURCHASE_DENIED_MESSAGE
        );
        assert!(missing.chain().nth(1).unwrap().to_string().contains(".rs:"));
    }

    /// STAB-34 / D5: after mining, "not finalized yet" and a transient chain
    /// answer (the upstream unreachable, the provider not answering) are both
    /// pending; only a definite refusal fails closed. (Before D5 the
    /// transient answers failed closed too, which stopped the open page.)
    #[test]
    fn creator_mint_chain_error_maps_pending_and_transient_to_pending_refusals_to_unavailable() {
        for (status, message) in [
            (
                StatusCode::BAD_REQUEST,
                "protected_content_mint_receipt_pending: protected-content mint receipt is not finalized on enough configured sources".to_string(),
            ),
            (
                StatusCode::BAD_REQUEST,
                "upstream_unreachable: EVM RPC request failed".to_string(),
            ),
            (
                StatusCode::BAD_REQUEST,
                "unavailable: mint receipt unavailable".to_string(),
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "chain provider unavailable: timed out".to_string(),
            ),
        ] {
            let pending = super::creator_mint_chain_error((status, message.clone()), 1);
            assert_eq!(
                pending.to_string(),
                super::RUNTIME_CUSTODY_CREATOR_PENDING_MESSAGE,
                "{message}"
            );
        }
        for (status, message) in [
            (
                StatusCode::BAD_REQUEST,
                "invalid_protected_content_mint_receipt: bad".to_string(),
            ),
            (
                StatusCode::BAD_REQUEST,
                "upstream_invalid_protected_content_verified_listing: bad".to_string(),
            ),
            (
                StatusCode::BAD_REQUEST,
                "protected_content_mint_receipt_reverted_already_bound: reverted".to_string(),
            ),
        ] {
            let error = super::creator_mint_chain_error((status, message.clone()), 1);
            assert_eq!(
                error.to_string(),
                super::RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE,
                "{message}"
            );
        }
    }

    use super::*;

    fn test_creator_state() -> elastos_protected_content_runtime::RuntimeMintCreatorState {
        let desired_terms = elastos_protected_content_runtime::RuntimeMintCreatorDesiredTerms::new(
            "wallet-account-1".to_string(),
            "0x2".to_string(),
            "0x5".to_string(),
            Vec::new(),
            elastos_protected_content_runtime::RuntimeMintAccessMethod::BuyOnce,
            None,
            String::new(),
            String::new(),
        )
        .unwrap();
        elastos_protected_content_runtime::RuntimeMintCreatorState::new(
            desired_terms,
            "bafycreatorcid".to_string(),
            "ipfs://bafymetadata/metadata.json".to_string(),
        )
        .unwrap()
    }

    fn test_chain_plan() -> RuntimeCustodyCreatorChainPlan {
        RuntimeCustodyCreatorChainPlan {
            network: "base-mainnet".to_string(),
            chain_namespace: "eip155:8453".to_string(),
            ledger: "0x00000000000000000000000000000000000000aa".to_string(),
            pay_token: "0x00000000000000000000000000000000000000bb".to_string(),
            to: "0x00000000000000000000000000000000000000cc".to_string(),
            data: "0x1234".to_string(),
            value: "0x0".to_string(),
        }
    }

    fn test_receipt(chain_id: u64) -> ResolvedProtectedContentMintReceipt {
        ResolvedProtectedContentMintReceipt {
            schema: "elastos.chain.protected-content-mint-receipt/v1".to_string(),
            network: "base-mainnet".to_string(),
            chain_id,
            token_id: "0x77".to_string(),
            operative: "0x00000000000000000000000000000000000000dd".to_string(),
            quantity: Some("0x7".to_string()),
            price: Some("0xf4240".to_string()),
            pay_token: Some(RUNTIME_CUSTODY_NATIVE_PAY_TOKEN.to_string()),
        }
    }

    fn test_listing(chain_id: u64) -> ResolvedProtectedContentVerifiedListing {
        ResolvedProtectedContentVerifiedListing {
            schema: RUNTIME_CUSTODY_VERIFIED_LISTING_SCHEMA.to_string(),
            network: "base-mainnet".to_string(),
            chain_id,
            seller: "0x00000000000000000000000000000000000000ee".to_string(),
            ledger: "0x00000000000000000000000000000000000000aa".to_string(),
            token_id: "0x77".to_string(),
            operative: "0x00000000000000000000000000000000000000dd".to_string(),
            quantity: "0x2".to_string(),
            price: "0x5".to_string(),
            pay_token: "0x00000000000000000000000000000000000000bb".to_string(),
            payment_processor: Some("0x00000000000000000000000000000000000000ff".to_string()),
        }
    }

    #[test]
    fn runtime_custody_creator_mint_blocked_reports_the_stage_and_the_recorded_terms() {
        let mint_id = elastos_protected_content_contracts::Digest32::new([0x11; 32]);
        let recorded = test_creator_state();

        // Recorded only: the wire spelling stays, though such an attempt is now
        // set aside rather than refused. Never offered Start over from here.
        let error = super::runtime_custody_creator_mint_blocked(mint_id, &recorded, None, None);
        let blocked = error
            .downcast_ref::<crate::protected_content_runtime::RuntimeCustodyCreatorMintBlocked>()
            .expect("refusal must carry its reason as data");
        let json = blocked.as_json();
        assert_eq!(
            json["schema"],
            crate::protected_content_runtime::RUNTIME_CUSTODY_CREATOR_MINT_BLOCKED_SCHEMA_V1
        );
        assert_eq!(json["state"], "recorded_only");
        assert_eq!(json["recorded_copies"], "0x2");
        assert_eq!(json["recorded_price"], "0x5");
        assert_eq!(json["can_start_over"], false);
        assert_eq!(json["can_resume"], true);
        assert_eq!(json["mint_id"], hex::encode(mint_id.as_bytes()));

        // A transaction is out for approval: it may still settle, so the
        // record must survive; only finishing it is on offer.
        let raised = recorded
            .clone()
            .with_effect(
                elastos_protected_content_runtime::RuntimeMintCreatorEffectBinding::new(
                    "effect-1",
                    "approval-1",
                    "a".repeat(64),
                    "wallet-account-1",
                    "0x00000000000000000000000000000000000000ee",
                    "eip155:8453",
                    "base-mainnet",
                )
                .unwrap(),
            )
            .unwrap();
        let json = super::runtime_custody_creator_mint_blocked(mint_id, &raised, None, None)
            .downcast_ref::<crate::protected_content_runtime::RuntimeCustodyCreatorMintBlocked>()
            .expect("refusal must carry its reason as data")
            .as_json();
        assert_eq!(json["state"], "approval_outstanding");
        assert_eq!(json["can_start_over"], false);
        assert_eq!(json["can_resume"], true);

        // Settled: a seller and a token id exist, so nothing may be dropped.
        // Resuming stays on offer: it finishes a listing that never published,
        // and only replays one that did.
        let settled = raised
            .with_terminal(creator_terminal_evidence_for_test())
            .unwrap();
        let json = super::runtime_custody_creator_mint_blocked(mint_id, &settled, None, None)
            .downcast_ref::<crate::protected_content_runtime::RuntimeCustodyCreatorMintBlocked>()
            .expect("refusal must carry its reason as data")
            .as_json();
        assert_eq!(json["state"], "already_minted");
        assert_eq!(json["can_start_over"], false);
        assert_eq!(json["can_resume"], true);
    }

    /// The refusal's own sentence stays plain, and no app is expected to read
    /// it: it is a fallback for surfaces that predate the typed answer.
    /// A blocked mint says how far it got, so an app can show which stage the
    /// existing attempt reached instead of only that one exists.
    #[test]
    fn runtime_custody_creator_mint_blocked_carries_progress_when_the_caller_has_it() {
        let mint_id = elastos_protected_content_contracts::Digest32::new([0x11; 32]);
        let progress = serde_json::json!({
            "schema": crate::protected_content_runtime::RUNTIME_CUSTODY_CREATOR_PROGRESS_SCHEMA_V1,
            "stages": [
                { "id": "escrow", "state": "done" },
                { "id": "publish", "state": "done" },
                { "id": "listing", "state": "active" },
            ],
        });
        let json = super::runtime_custody_creator_mint_blocked(
            mint_id,
            &test_creator_state(),
            Some(progress.clone()),
            None,
        )
        .downcast_ref::<crate::protected_content_runtime::RuntimeCustodyCreatorMintBlocked>()
        .expect("the refusal must stay typed")
        .as_json();
        assert_eq!(json["progress"], progress);

        // A caller without the record leaves it out rather than guessing.
        let without =
            super::runtime_custody_creator_mint_blocked(mint_id, &test_creator_state(), None, None)
                .downcast_ref::<crate::protected_content_runtime::RuntimeCustodyCreatorMintBlocked>(
                )
                .expect("the refusal must stay typed")
                .as_json();
        assert!(without.get("progress").is_none());
    }

    #[test]
    fn runtime_custody_creator_mint_blocked_never_reuses_the_unavailable_sentence() {
        let error = super::runtime_custody_creator_mint_blocked(
            elastos_protected_content_contracts::Digest32::new([0x11; 32]),
            &test_creator_state(),
            None,
            None,
        );
        assert_ne!(
            error.to_string(),
            super::RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE
        );
        assert!(error.to_string().contains("earlier attempt"));
    }

    fn creator_terminal_evidence_for_test(
    ) -> elastos_protected_content_runtime::RuntimeMintCreatorTerminalEvidence {
        elastos_protected_content_runtime::RuntimeMintCreatorTerminalEvidence::new(
            "bafycreatorcid",
            "ipfs://bafymetadata/metadata.json",
            "0x00000000000000000000000000000000000000ee",
            "eip155:8453",
            "base-mainnet",
            "0x00000000000000000000000000000000000000aa",
            "0x77",
            "0x00000000000000000000000000000000000000dd",
            "0x2",
            "0x5",
            "0x00000000000000000000000000000000000000bb",
            Some("0x00000000000000000000000000000000000000ff".to_string()),
            "c".repeat(64),
            1,
        )
        .unwrap()
    }

    #[test]
    fn runtime_custody_creator_terminal_bindings_accept_exact_chain_identity() {
        let creator_state = test_creator_state();
        let chain_plan = test_chain_plan();
        let receipt = test_receipt(8453);
        let listing = test_listing(8453);

        assert!(validate_runtime_custody_creator_terminal_bindings(
            &creator_state,
            "0x00000000000000000000000000000000000000ee",
            &chain_plan,
            &receipt,
            &listing,
        )
        .is_ok());
    }

    /// The native pay-token path builds its own listing instead of reading one
    /// back from chain state, so it has to satisfy the same bindings a fetched
    /// listing does. A field left unset here fails closed at the terminal --
    /// after the mint has already settled on chain -- which is the worst place
    /// to find out.
    #[test]
    fn runtime_custody_native_listing_from_receipt_satisfies_terminal_bindings() {
        let creator_state = test_creator_state();
        let chain_plan = RuntimeCustodyCreatorChainPlan {
            pay_token: RUNTIME_CUSTODY_NATIVE_PAY_TOKEN.to_string(),
            ..test_chain_plan()
        };
        let receipt = ResolvedProtectedContentMintReceipt {
            quantity: Some(creator_state.desired_terms().copies().to_string()),
            price: Some(creator_state.desired_terms().price().to_string()),
            pay_token: Some(RUNTIME_CUSTODY_NATIVE_PAY_TOKEN.to_string()),
            ..test_receipt(8453)
        };
        let creator_address = "0x00000000000000000000000000000000000000ee";

        let listing =
            runtime_custody_listing_from_mint_receipt(creator_address, &chain_plan, &receipt);

        assert_eq!(listing.schema, RUNTIME_CUSTODY_VERIFIED_LISTING_SCHEMA);
        assert!(validate_runtime_custody_creator_terminal_bindings(
            &creator_state,
            creator_address,
            &chain_plan,
            &receipt,
            &listing,
        )
        .is_ok());
    }

    /// The synthesized listing must not become a way to launder terms the
    /// creator never asked for: a receipt whose `ItemListed` priced the token
    /// differently is still refused.
    #[test]
    fn runtime_custody_native_listing_from_receipt_refuses_unrecorded_terms() {
        let creator_state = test_creator_state();
        let chain_plan = RuntimeCustodyCreatorChainPlan {
            pay_token: RUNTIME_CUSTODY_NATIVE_PAY_TOKEN.to_string(),
            ..test_chain_plan()
        };
        let creator_address = "0x00000000000000000000000000000000000000ee";
        for (quantity, price) in [
            ("0x3", creator_state.desired_terms().price().to_string()),
            (creator_state.desired_terms().copies(), "0x6".to_string()),
        ] {
            let receipt = ResolvedProtectedContentMintReceipt {
                quantity: Some(quantity.to_string()),
                price: Some(price),
                pay_token: Some(RUNTIME_CUSTODY_NATIVE_PAY_TOKEN.to_string()),
                ..test_receipt(8453)
            };
            let listing =
                runtime_custody_listing_from_mint_receipt(creator_address, &chain_plan, &receipt);

            assert!(validate_runtime_custody_creator_terminal_bindings(
                &creator_state,
                creator_address,
                &chain_plan,
                &receipt,
                &listing,
            )
            .is_err());
        }
    }

    #[test]
    fn runtime_custody_creator_terminal_bindings_accept_normalized_price_terms() {
        let creator_state = elastos_protected_content_runtime::RuntimeMintCreatorState::new(
            elastos_protected_content_runtime::RuntimeMintCreatorDesiredTerms::new(
                "wallet-account-1",
                "0x02",
                "0x05",
                Vec::new(),
                elastos_protected_content_runtime::RuntimeMintAccessMethod::BuyOnce,
                None,
                String::new(),
                String::new(),
            )
            .unwrap(),
            "bafycreatorcid",
            "ipfs://bafycreatorcid/metadata.json",
        )
        .unwrap();
        let chain_plan = test_chain_plan();
        let receipt = test_receipt(8453);
        let listing = test_listing(8453);

        assert!(validate_runtime_custody_creator_terminal_bindings(
            &creator_state,
            "0x00000000000000000000000000000000000000ee",
            &chain_plan,
            &receipt,
            &listing,
        )
        .is_ok());
        assert_eq!(creator_state.desired_terms().copies(), "0x2");
        assert_eq!(creator_state.desired_terms().price(), "0x5");
    }

    #[test]
    fn runtime_custody_creator_request_uses_canonical_exact_effect_identity() {
        let creator_state = test_creator_state();
        let chain_plan = test_chain_plan();
        let creator_account = RuntimeCustodyCreatorAccount {
            account_id: "wallet:eip155:8453:0x00000000000000000000000000000000000000ee".to_string(),
            address: "0x00000000000000000000000000000000000000ee".to_string(),
            external_signer: false,
            connector_id: None,
        };
        let request = runtime_custody_creator_transaction_request(
            "did:key:z6Mkcreatorprincipal1111111111111111111111111111111",
            &creator_account,
            &creator_state,
            &chain_plan,
            elastos_protected_content_contracts::Digest32::new([0x77; 32]),
            creator_state.token_uri(),
        )
        .unwrap();
        let request_binding = transaction_request_binding(&request);
        let expected = exact_runtime_transaction_effect_id(
            NATIVE_TRANSACTION_SOURCE,
            "did:key:z6Mkcreatorprincipal1111111111111111111111111111111",
            &request.request_sha256,
            &request_binding,
        )
        .unwrap();
        assert_eq!(request.effect_id, expected);
        assert!(request.metadata.get("method").is_none());
        assert_eq!(
            request
                .metadata
                .get("product_operation")
                .and_then(|value| value.as_str()),
            Some("protected_content_creator_mint")
        );
    }

    #[test]
    fn runtime_custody_creator_terminal_bindings_reject_mismatched_evidence_fields() {
        let cases: &[fn(
            &mut ResolvedProtectedContentMintReceipt,
            &mut ResolvedProtectedContentVerifiedListing,
            &mut RuntimeCustodyCreatorChainPlan,
        )] = &[
            |receipt, _, _| receipt.chain_id = 8454,
            |_, listing, _| listing.chain_id = 8454,
            |receipt, _, _| receipt.network = "wrong-mainnet".to_string(),
            |_, listing, _| listing.network = "wrong-mainnet".to_string(),
            |_, listing, _| {
                listing.seller = "0x00000000000000000000000000000000000000aa".to_string()
            },
            |_, listing, _| {
                listing.ledger = "0x00000000000000000000000000000000000000ab".to_string()
            },
            |receipt, _, _| receipt.token_id = "0x78".to_string(),
            |_, listing, _| listing.token_id = "0x78".to_string(),
            |receipt, _, _| {
                receipt.operative = "0x00000000000000000000000000000000000000ab".to_string()
            },
            |_, listing, _| {
                listing.operative = "0x00000000000000000000000000000000000000ab".to_string()
            },
            |_, listing, _| listing.quantity = "0x0".to_string(),
            |_, listing, _| listing.quantity = "0x3".to_string(),
            |_, listing, _| listing.price = "0x6".to_string(),
            |_, listing, _| {
                listing.pay_token = "0x00000000000000000000000000000000000000aa".to_string()
            },
            |_, _, chain_plan| {
                chain_plan.ledger = "0x00000000000000000000000000000000000000ab".to_string()
            },
            |_, _, chain_plan| {
                chain_plan.pay_token = "0x00000000000000000000000000000000000000aa".to_string()
            },
        ];

        for mutate in cases {
            let creator_state = test_creator_state();
            let mut chain_plan = test_chain_plan();
            let mut receipt = test_receipt(8453);
            let mut listing = test_listing(8453);
            mutate(&mut receipt, &mut listing, &mut chain_plan);
            let err = validate_runtime_custody_creator_terminal_bindings(
                &creator_state,
                "0x00000000000000000000000000000000000000ee",
                &chain_plan,
                &receipt,
                &listing,
            )
            .unwrap_err();
            assert_eq!(err.to_string(), RUNTIME_CUSTODY_CREATOR_UNAVAILABLE_MESSAGE);
        }
    }

    fn test_purchase_buyer_account() -> RuntimeCustodyCreatorAccount {
        RuntimeCustodyCreatorAccount {
            account_id: "wallet:eip155:8453:0x00000000000000000000000000000000000000bb".to_string(),
            address: "0x00000000000000000000000000000000000000bb".to_string(),
            external_signer: false,
            connector_id: None,
        }
    }

    fn test_purchase_listing_package(
    ) -> crate::protected_content_runtime::RuntimePortableListingPackage {
        crate::protected_content_runtime::RuntimePortableListingPackage {
            schema: "elastos.library.runtime-custody-portable-listing/v1".to_string(),
            mint_id: "0".repeat(64),
            content_id: "content:fixture".to_string(),
            content_cid: "bafyfixturecontent".to_string(),
            metadata_cid: "bafyfixturemetadata".to_string(),
            token_uri: "ipfs://bafyfixturemetadata".to_string(),
            publisher_profile_did: "did:key:z6MkFixture".to_string(),
            display_name: "Demo".to_string(),
            media_identity_base64: Some("ZGVtbw==".to_string()),
            content_identity_base64: None,
            content_access_id: format!("0x{}", "00".repeat(32)),
            key_envelope_identity_base64: "ZGVtbw==".to_string(),
            rights_policy_identity_base64: "ZGVtbw==".to_string(),
            content_key_commitment_base64: "ZGVtbw==".to_string(),
            seller_address: "0x0000000000000000000000000000000000000044".to_string(),
            chain_namespace: "eip155:8453".to_string(),
            network: "base".to_string(),
            ledger: "0x0000000000000000000000000000000000000022".to_string(),
            token_id: "0x3".to_string(),
            operative: "0x0000000000000000000000000000000000000033".to_string(),
            quantity: "0x1".to_string(),
            price: "0x5".to_string(),
            pay_token: "0x0000000000000000000000000000000000000055".to_string(),
            payment_processor: None,
            mint_transaction_hash: Some(format!("0x{}", "00".repeat(32))),
            published_at: Some(1),
            pool_mint_share_b64: None,
            sealed_rights_policy_base64: None,
            remote_seal: None,
        }
    }

    fn test_purchase_buy_stage() -> ResolvedProtectedContentPurchaseStep {
        ResolvedProtectedContentPurchaseStep {
            stage: "buy".to_string(),
            to: "0x0000000000000000000000000000000000000099".to_string(),
            value: "0x0".to_string(),
            data: "0xabcdef".to_string(),
        }
    }

    /// Guards `request_sha256` stability for the `ListingPackage` binding
    /// across the Task 4 refactor: the hash below was captured by running
    /// the pre-refactor `runtime_custody_purchase_transaction_request`
    /// (listing + listing_sha256 + mint_id signature) against this exact
    /// fixture. If this test ever needs a new literal, every in-flight
    /// purchase's `request_sha256` has silently changed underneath it.
    #[test]
    fn purchase_request_hash_is_unchanged_for_listing_packages() {
        let buyer_account = test_purchase_buyer_account();
        let listing = test_purchase_listing_package();
        let (item, offer) = crate::protected_content_market::market_terms_from_package(
            &listing,
            &listing.content_access_id,
        );
        let listing_sha256 = format!("sha256:{}", "cc".repeat(32));
        let mint_id = elastos_protected_content_contracts::Digest32::new([0x99; 32]);
        let stage = test_purchase_buy_stage();
        let request = runtime_custody_purchase_transaction_request(
            "did:key:z6Mkbuyerprincipal11111111111111111111111111111111",
            &buyer_account,
            &item,
            &offer,
            &RuntimePurchaseBinding::ListingPackage {
                listing_sha256: &listing_sha256,
                mint_id,
            },
            &stage,
        )
        .unwrap();
        assert_eq!(
            request.request_sha256,
            "d8d0abc7e0bbca17ecce84efe8140ae6c434060fe01cd5fc1f967e83c42450c3"
        );
        // Q-M10: the effect it names is pinned too -- a changed effect id is a
        // second effect for a purchase already in flight.
        assert_eq!(request.effect_id, "transaction-effect:sha256:b372d80079ffff8a7b8f2c25c4a05dd7de156d9c48cd81d5d15f71be95ee048c");
    }

    #[test]
    fn purchase_request_binds_asset_uri_for_a_market_buy() {
        let buyer_account = test_purchase_buyer_account();
        let listing = test_purchase_listing_package();
        let (item, offer) = crate::protected_content_market::market_terms_from_package(
            &listing,
            &listing.content_access_id,
        );
        let stage = test_purchase_buy_stage();
        let asset_uri = "elastos://bafyfixturemetadata";
        let request = runtime_custody_purchase_transaction_request(
            "did:key:z6Mkbuyerprincipal11111111111111111111111111111111",
            &buyer_account,
            &item,
            &offer,
            &RuntimePurchaseBinding::Market {
                asset_uri,
                attempt_id: "0123456789abcdef0123456789abcdef",
            },
            &stage,
        )
        .unwrap();
        // A market buy binds a different domain and `asset_uri` in place of
        // `listing_sha256` / `mint_id`, so it must hash to a different value
        // than the listing-package request built from the very same terms.
        assert_ne!(
            request.request_sha256,
            "d8d0abc7e0bbca17ecce84efe8140ae6c434060fe01cd5fc1f967e83c42450c3"
        );
        let other_uri_request = runtime_custody_purchase_transaction_request(
            "did:key:z6Mkbuyerprincipal11111111111111111111111111111111",
            &buyer_account,
            &item,
            &offer,
            &RuntimePurchaseBinding::Market {
                asset_uri: "elastos://someotherfolder",
                attempt_id: "0123456789abcdef0123456789abcdef",
            },
            &stage,
        )
        .unwrap();
        assert_ne!(request.request_sha256, other_uri_request.request_sha256);
        // R23: the attempt is part of what the hash binds. The same terms,
        // item and asset under another attempt are another effect; the same
        // attempt again is the same effect.
        let market_request = |attempt_id: &str| {
            runtime_custody_purchase_transaction_request(
                "did:key:z6Mkbuyerprincipal11111111111111111111111111111111",
                &buyer_account,
                &item,
                &offer,
                &RuntimePurchaseBinding::Market {
                    asset_uri,
                    attempt_id,
                },
                &stage,
            )
            .unwrap()
        };
        let same = market_request("0123456789abcdef0123456789abcdef");
        assert_eq!(same.request_sha256, request.request_sha256);
        assert_eq!(same.effect_id, request.effect_id);
        let retry = market_request("fedcba9876543210fedcba9876543210");
        assert_ne!(retry.request_sha256, request.request_sha256);
        assert_ne!(retry.effect_id, request.effect_id);
        // The Wallet is shown the asset, never the attempt's identity.
        assert!(retry.metadata.get("attempt_id").is_none());
    }
}

//! ElastOS protected-content custody node provider capsule.
//!
//! Runtime registers this provider on the Runtime-only `custody` target. It is
//! the only key-custody authority: each node evaluates rights locally and
//! releases one recipient-encrypted contribution per authenticated operation.

use std::env;
use std::io::{self, BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use std::collections::BTreeMap;

use custody_provider::{
    load_state_from_root, parse_runtime_issuer_hex, parse_state_root_from_provider_init,
    parse_state_roots_from_provider_init, provision_state_root, provisioning_receipt,
    PoolDescriptorHighWaterV1, PROVISIONING_SCHEMA_V1,
};
use ed25519_dalek::{Signer as _, SigningKey};
use elastos_protected_content_contracts::{
    AuthenticatedRuntimeReleaseOperationV2, KeyReleaseError, NodePublicKey,
    RuntimeOperationIssuerKeyV1, RuntimeReleaseOperationAnyV1,
};
use elastos_protected_content_custody::{
    CustodyError, DurableReplayClaimStoreV1, NodeCustodySecretKeyV1, NodeLocalShareStoreV1,
    RecipientPublicKeyV1,
};
use elastos_protected_content_provider_contracts::{
    CustodyProviderRequestOpV1, CustodyProviderRequestV1, CustodyProviderRequestValidationErrorV1,
    CustodyProviderResponseV1, PoolCustodyRequestOpV1, PoolCustodyRequestV1, PoolCustodyResponseV1,
    ProviderFailureCodeV1, RightsProviderResponseV1, ValidatedCustodyProviderRequestV1,
    ValidatedPoolCustodyRequestV1, ValidatedRightsProviderRequestV1,
    CUSTODY_PROVIDER_REQUEST_SCHEMA_V1, CUSTODY_PROVIDER_RESPONSE_SCHEMA_V1,
    MAX_PROVIDER_FRAME_BYTES_V1,
};
use elastos_protected_content_rights::{
    chain_rights_evidence_request_any, evaluate_validated_rights_with_evidence_at,
    parse_chain_rights_evidence_data, PrivateCustodyRightsRequestV1,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");
const INIT_ERROR_CODE: &str = "invalid_config";
const REQUEST_ERROR_CODE: &str = "invalid_request";
const BACKEND_ERROR_CODE: &str = "backend_unavailable";
const RIGHTS_DENIED_ERROR_CODE: &str = "rights_denied";
/// A refusal raised before the share store was touched. Distinct from
/// `backend_unavailable`, which this capsule also returns from paths that fail
/// *after* the durable write and so proves nothing about the share.
const PROVISIONING_REFUSED_ERROR_CODE: &str = "provisioning_refused";
/// The Runtime operation ended before this node acted on it. Raised only at
/// request validation, before any store is touched, so the Runtime may treat
/// it as effect-free and build a fresh operation.
const OPERATION_EXPIRED_ERROR_CODE: &str = "operation_expired";
/// The chain rights evidence expired before this node could settle it.
/// Settling only signs a decision, so nothing durable has happened either.
const EVIDENCE_EXPIRED_ERROR_CODE: &str = "evidence_expired";
/// This node holds no share of the item a V2 request names (L8). Raised
/// before any chain request, claim or signature, so it is effect-free.
const UNKNOWN_ENVELOPE_ERROR_CODE: &str = "unknown_envelope";

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum ControlRequest {
    Init { config: Value },
    Status,
    Shutdown,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ProviderResponse {
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<Value>,
    },
    Error {
        code: &'static str,
        message: &'static str,
    },
}

impl ProviderResponse {
    fn ok(data: Value) -> Self {
        Self::Ok { data: Some(data) }
    }

    fn empty_ok() -> Self {
        Self::Ok { data: None }
    }

    fn error(code: &'static str, message: &'static str) -> Self {
        Self::Error { code, message }
    }
}

struct CustodyProvider {
    roots: Option<CustodyRootSet>,
}

/// Every root this process holds (Plan B T2.1): one per pool, each with its
/// own trusted issuer, node keys, share store and descriptor high-water mark.
/// A request goes to the root whose node key it names.
struct CustodyRootSet {
    roots: BTreeMap<NodePublicKey, ConfiguredCustodyProvider>,
    /// The roots in the order `init` named them, for the private status. A
    /// root that did not load is listed `configured: false`, with its node
    /// key when that key could still be read, and its pool is not served
    /// (user decision 2026-11-12 10:26).
    listed: Vec<ListedRoot>,
}

/// One root `init` named, and whether it actually loaded (S2-F2): a root that
/// did not load stays unconfigured, never resolved through another root.
struct ListedRoot {
    path: Option<String>,
    node_public_key: Option<NodePublicKey>,
    loaded: bool,
}

struct ConfiguredCustodyProvider {
    expected_runtime_issuer: RuntimeOperationIssuerKeyV1,
    node_public_key: NodePublicKey,
    node_signing_key: SigningKey,
    node_custody_secret: NodeCustodySecretKeyV1,
    share_store: NodeLocalShareStoreV1,
    replay_store: DurableReplayClaimStoreV1,
    pool_high_water: PoolDescriptorHighWaterV1,
}

impl CustodyRootSet {
    /// The answer for a frame whose node no configured root holds: the
    /// unconfigured error for a listed root that did not load, otherwise
    /// `invalid_request`. Both come before any store.
    fn unconfigured_or_unknown(&self, node: NodePublicKey) -> ProviderResponse {
        if self
            .listed
            .iter()
            .any(|root| root.node_public_key == Some(node))
        {
            not_configured()
        } else {
            invalid_request()
        }
    }
}

impl CustodyProvider {
    fn new() -> Self {
        Self { roots: None }
    }

    fn handle_frame(&mut self, frame: &[u8]) -> (ProviderResponse, bool) {
        let value = match serde_json::from_slice::<Value>(frame) {
            Ok(value) => value,
            Err(_) => return (invalid_request(), false),
        };
        if reject_runtime_envelope_fields(&value).is_err() {
            return (invalid_request(), false);
        }
        let op = value.get("op").and_then(Value::as_str).map(str::to_owned);
        match op.as_deref() {
            Some("init" | "status" | "shutdown") => {
                if !control_request_has_exact_fields(&value, op.as_deref().unwrap_or_default()) {
                    return (invalid_request(), false);
                }
                match serde_json::from_value::<ControlRequest>(value) {
                    Ok(ControlRequest::Init { config }) => (self.init(config), false),
                    Ok(ControlRequest::Status) => (self.status(), false),
                    Ok(ControlRequest::Shutdown) => (ProviderResponse::empty_ok(), true),
                    Err(_) => (invalid_request(), false),
                }
            }
            Some("provision_node_share" | "release_contribution") => {
                let Ok(bytes) = serde_json::to_vec(&value) else {
                    return (invalid_request(), false);
                };
                (self.handle_custody_request(&bytes), false)
            }
            Some(
                "release_pool_contribution" | "sign_pool_statement" | "provision_pool_node_share",
            ) => {
                let Ok(bytes) = serde_json::to_vec(&value) else {
                    return (invalid_request(), false);
                };
                (self.handle_pool_custody_request(&bytes), false)
            }
            Some("prepare_evidence" | "settle_evidence") => {
                (self.handle_private_rights_request(&value), false)
            }
            _ => (invalid_request(), false),
        }
    }

    #[cfg(test)]
    fn handle_line(&mut self, line: &str) -> ProviderResponse {
        self.handle_frame(line.as_bytes()).0
    }

    /// Clears the set and loads every root `config` names, each on its own: a
    /// root that does not load is listed unconfigured and the others serve.
    /// Init fails when the config is invalid, when no root loads, or when two
    /// roots hold one node key. The Runtime re-sends `init` to add or remove a
    /// root; the roots it keeps load the same keys from disk.
    fn init(&mut self, config: Value) -> ProviderResponse {
        self.roots = None;
        match load_root_set(config) {
            Ok(roots) => {
                self.roots = Some(roots);
                self.status()
            }
            Err(_) => ProviderResponse::error(
                INIT_ERROR_CODE,
                "custody provider configuration is invalid",
            ),
        }
    }

    fn status(&self) -> ProviderResponse {
        ProviderResponse::ok(json!({
            "provider": "custody",
            "version": PROVIDER_VERSION,
            "configured": self.roots.is_some(),
            "supported_operations": [
                "status",
                "provision_node_share",
                "release_contribution",
                "release_pool_contribution",
                "sign_pool_statement",
                "provision_pool_node_share",
                "shutdown"
            ],
            "request_schema": CUSTODY_PROVIDER_REQUEST_SCHEMA_V1,
            "response_schema": CUSTODY_PROVIDER_RESPONSE_SCHEMA_V1,
            // Local plane only: the Runtime keeps the list off the public
            // status (S2-Q6).
            "roots": self.root_statuses(),
        }))
    }

    fn root_statuses(&self) -> Vec<Value> {
        let Some(set) = self.roots.as_ref() else {
            return Vec::new();
        };
        set.listed
            .iter()
            .map(|listed| {
                let key = listed.node_public_key;
                let loaded = key
                    .filter(|_| listed.loaded)
                    .and_then(|key| set.roots.get(&key));
                match loaded {
                    Some(root) => json!({
                        "path": listed.path,
                        "node_public_key": format!("0x{}", hex_bytes(root.node_public_key.as_bytes())),
                        "configured": true,
                        "shares_held": root.share_store.count().ok(),
                    }),
                    None => json!({
                        "path": listed.path,
                        "node_public_key": key.map(|key| format!("0x{}", hex_bytes(key.as_bytes()))),
                        "configured": false,
                        "shares_held": null,
                    }),
                }
            })
            .collect()
    }

    /// Routes a custody frame to the root whose node key it names. The key is
    /// read from the unvalidated frame; that root's issuer and key then
    /// validate it. An unknown key is refused before any store.
    fn handle_custody_request(&mut self, bytes: &[u8]) -> ProviderResponse {
        let Some(set) = self.roots.as_mut() else {
            return not_configured();
        };
        let node = match CustodyProviderRequestV1::peek_selected_node_public_key(bytes) {
            Ok(node) => node,
            Err(_) => {
                return request_refusal(release_operation_ended(
                    &value_of(bytes),
                    now_unix_seconds(),
                ))
            }
        };
        match set.roots.get_mut(&node) {
            Some(root) => root.handle_custody_request(bytes),
            None => set.unconfigured_or_unknown(node),
        }
    }

    fn handle_pool_custody_request(&mut self, bytes: &[u8]) -> ProviderResponse {
        let Some(set) = self.roots.as_mut() else {
            return not_configured();
        };
        let node = match PoolCustodyRequestV1::peek_selected_node_public_key(bytes) {
            Ok(node) => node,
            Err(_) => {
                return request_refusal(release_operation_ended(
                    &value_of(bytes),
                    now_unix_seconds(),
                ))
            }
        };
        match set.roots.get_mut(&node) {
            Some(root) => root.handle_pool_custody_request(bytes),
            None => set.unconfigured_or_unknown(node),
        }
    }

    fn handle_private_rights_request(&mut self, value: &Value) -> ProviderResponse {
        let Some(set) = self.roots.as_ref() else {
            return not_configured();
        };
        let now = now_unix_seconds();
        let frame = match serde_json::to_vec(value)
            .ok()
            .and_then(|bytes| PrivateCustodyRightsRequestV1::from_json_slice(&bytes).ok())
        {
            Some(frame) => frame,
            None => return invalid_request(),
        };
        let request_bytes = match serde_json::to_vec(frame.request_json()) {
            Ok(bytes) => bytes,
            Err(_) => return invalid_request(),
        };
        let request =
            match ValidatedRightsProviderRequestV1::decode_and_validate_at(&request_bytes, now) {
                Ok(request) => request,
                Err(_) => {
                    return request_refusal(release_operation_ended(frame.request_json(), now))
                }
            };
        // Rights frames validate without a root; the node they select picks it.
        let Some(state) = set.roots.get(&request.selected_node_public_key()) else {
            return set.unconfigured_or_unknown(request.selected_node_public_key());
        };
        match frame {
            PrivateCustodyRightsRequestV1::PrepareEvidence { .. } => {
                // V2, before any chain request: the request above proved the
                // frame, the operation's signatures, the descriptor and every
                // attestation, and that this node is in the item's epoch. The
                // descriptor must not be older than one this node accepted,
                // and the node must hold the item's share (L8).
                if let Some(operation) = request.authenticated_runtime_release_operation().as_v2() {
                    match admits_pool_descriptor(&state.pool_high_water, operation) {
                        Ok(true) => {}
                        Ok(false) => return invalid_request(),
                        Err(()) => return backend_unavailable(),
                    }
                    match state.share_store.load_node_share_if_present(
                        operation.binding().key_envelope(),
                        state.expected_runtime_issuer,
                        &state.node_custody_secret,
                    ) {
                        Ok(Some(_)) => {}
                        Ok(None) => return unknown_envelope(),
                        Err(_) => return backend_unavailable(),
                    }
                }
                match chain_rights_evidence_request_from_validated_request(frame.request_json()) {
                    Ok(chain_request) => ProviderResponse::ok(chain_request),
                    Err(()) => invalid_request(),
                }
            }
            PrivateCustodyRightsRequestV1::SettleEvidence { .. } => {
                let evidence = match frame
                    .chain_data()
                    .and_then(|data| parse_chain_rights_evidence_data(data).ok())
                {
                    Some(evidence) => evidence,
                    None => return invalid_request(),
                };
                // Read before the evaluation consumes it: an expiry is the
                // one evidence refusal the Runtime can recover from.
                let evidence_ended = evidence.expires_at() <= now;
                match evaluate_validated_rights_with_evidence_at(
                    &state.node_signing_key,
                    &request,
                    evidence,
                    now,
                ) {
                    Ok(response) => typed_rights_response(response),
                    Err(_) if evidence_ended => ProviderResponse::error(
                        EVIDENCE_EXPIRED_ERROR_CODE,
                        "custody provider rights evidence expired",
                    ),
                    Err(_) => request_refusal(release_operation_ended(frame.request_json(), now)),
                }
            }
        }
    }
}

impl ConfiguredCustodyProvider {
    fn handle_custody_request(&mut self, bytes: &[u8]) -> ProviderResponse {
        let now = now_unix_seconds();
        let request = match ValidatedCustodyProviderRequestV1::decode_and_validate_at(
            bytes,
            self.expected_runtime_issuer,
            self.node_public_key,
            now,
        ) {
            Ok(request) => request,
            Err(CustodyProviderRequestValidationErrorV1::RightsDenied) => return rights_denied(),
            Err(_) => return request_refusal(release_operation_ended(&value_of(bytes), now)),
        };
        match request.op() {
            CustodyProviderRequestOpV1::ProvisionNodeShare => {
                let provision = match request.provision_node_share() {
                    Ok(provision) => provision,
                    Err(_) => return invalid_request(),
                };
                match self.share_store.provision_node_share_classified(
                    provision.custody_node_provisioning_record(),
                    provision.signed_runtime_custody_provisioning(),
                    self.expected_runtime_issuer,
                    &self.node_custody_secret,
                    now,
                ) {
                    Ok(_) => typed_response(CustodyProviderResponseV1::new_provisioned(provision)),
                    // The store was never touched, so the caller can keep its
                    // mint open instead of stranding it. Expiry, a binding
                    // mismatch and a bad runtime signature all land here.
                    Err(error) if error.proves_not_stored() => ProviderResponse::error(
                        PROVISIONING_REFUSED_ERROR_CODE,
                        "custody provider refused the node share before storing it",
                    ),
                    Err(_) => ProviderResponse::error(
                        BACKEND_ERROR_CODE,
                        "custody provider could not provision the node share",
                    ),
                }
            }
            CustodyProviderRequestOpV1::ReleaseContribution => {
                let release = match request.release_contribution() {
                    Ok(release) => release,
                    Err(_) => return invalid_request(),
                };
                let operation = release.authenticated_runtime_release_operation().clone();
                let key_envelope = operation.binding().key_envelope();
                let node_share = match self.share_store.load_node_share(
                    key_envelope,
                    self.expected_runtime_issuer,
                    &self.node_custody_secret,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(CustodyProviderResponseV1::new_failure(
                            release,
                            ProviderFailureCodeV1::BackendUnavailable,
                        ));
                    }
                };
                let recipient_public_key = match RecipientPublicKeyV1::new(
                    *operation.statement().recipient_public_key().as_bytes(),
                ) {
                    Ok(value) => value,
                    Err(_) => return invalid_request(),
                };
                match self.replay_store.claim_or_replay_node_contribution(
                    operation,
                    release.signed_node_rights_decision(),
                    node_share.node_share(),
                    &self.node_signing_key,
                    &self.node_custody_secret,
                    &recipient_public_key,
                    now,
                    release
                        .signed_node_rights_decision()
                        .statement()
                        .expires_at(),
                    now,
                ) {
                    Ok(contribution) => {
                        typed_response(CustodyProviderResponseV1::new_contribution(&contribution))
                    }
                    Err(CustodyError::Release(KeyReleaseError::RightsDenied)) => rights_denied(),
                    Err(_) => typed_response(CustodyProviderResponseV1::new_failure(
                        release,
                        ProviderFailureCodeV1::BackendUnavailable,
                    )),
                }
            }
        }
    }

    /// V2 pool requests (Plan B T1.5). The validated request has proven the
    /// shape and the operation's signatures under its declared issuer, every
    /// recipient attestation against the embedded descriptor (`PoolVouched`),
    /// and the decision. This node then checks the descriptor high-water
    /// mark and that it holds the item's share before any claim or signature.
    fn handle_pool_custody_request(&mut self, bytes: &[u8]) -> ProviderResponse {
        let now = now_unix_seconds();
        let request = match ValidatedPoolCustodyRequestV1::decode_and_validate_at(
            bytes,
            self.node_public_key,
            now,
        ) {
            Ok(request) => request,
            Err(CustodyProviderRequestValidationErrorV1::RightsDenied) => return rights_denied(),
            Err(_) => return request_refusal(release_operation_ended(&value_of(bytes), now)),
        };
        match request.op() {
            PoolCustodyRequestOpV1::ReleasePoolContribution => {
                let Ok(release) = request.release_pool_contribution() else {
                    return invalid_request();
                };
                let operation = release.authenticated_runtime_release_operation().clone();
                match admits_pool_descriptor(&self.pool_high_water, &operation) {
                    Ok(true) => {}
                    Ok(false) => return invalid_request(),
                    Err(()) => {
                        return typed_pool_response(PoolCustodyResponseV1::new_failure(
                            &request,
                            ProviderFailureCodeV1::BackendUnavailable,
                        ))
                    }
                }
                let node_share = match self.share_store.load_node_share_if_present(
                    operation.binding().key_envelope(),
                    self.expected_runtime_issuer,
                    &self.node_custody_secret,
                ) {
                    Ok(Some(node_share)) => node_share,
                    Ok(None) => return unknown_envelope(),
                    Err(_) => {
                        return typed_pool_response(PoolCustodyResponseV1::new_failure(
                            &request,
                            ProviderFailureCodeV1::BackendUnavailable,
                        ))
                    }
                };
                let decision_expires_at = release
                    .signed_node_rights_decision()
                    .statement()
                    .expires_at();
                match self.replay_store.claim_or_replay_pool_contributions(
                    operation.clone(),
                    release.signed_node_rights_decision(),
                    node_share.node_share(),
                    &self.node_signing_key,
                    &self.node_custody_secret,
                    now,
                    decision_expires_at,
                    now,
                ) {
                    Ok(contributions) => {
                        if self
                            .pool_high_water
                            .record(
                                operation.pool().issuer().as_bytes(),
                                operation.descriptor_sequence(),
                            )
                            .is_err()
                        {
                            return typed_pool_response(PoolCustodyResponseV1::new_failure(
                                &request,
                                ProviderFailureCodeV1::BackendUnavailable,
                            ));
                        }
                        typed_pool_response(PoolCustodyResponseV1::new_pool_contributions(
                            &request,
                            &contributions,
                        ))
                    }
                    Err(CustodyError::Release(KeyReleaseError::RightsDenied)) => rights_denied(),
                    Err(_) => typed_pool_response(PoolCustodyResponseV1::new_failure(
                        &request,
                        ProviderFailureCodeV1::BackendUnavailable,
                    )),
                }
            }
            PoolCustodyRequestOpV1::ProvisionPoolNodeShare => {
                self.provision_pool_node_share(&request, now)
            }
            PoolCustodyRequestOpV1::SignPoolStatement => {
                let Ok(signing) = request.sign_pool_statement() else {
                    return invalid_request();
                };
                // The validated request names this node as the server. The
                // node signs only for an item it holds a share of in the
                // epoch the statement names (user decision 2026-11-11 21:52:
                // no condition on the statement's Runtime issuer; the share
                // stays loaded under this root's issuer).
                let statement = signing.recipient_attestation();
                let key_envelope = statement.binding().key_envelope();
                if key_envelope.custody_epoch() != statement.epoch() {
                    return invalid_request();
                }
                match self.share_store.load_node_share_if_present(
                    key_envelope,
                    self.expected_runtime_issuer,
                    &self.node_custody_secret,
                ) {
                    Ok(Some(_)) => {}
                    Ok(None) => return unknown_envelope(),
                    Err(_) => {
                        return typed_pool_response(PoolCustodyResponseV1::new_failure(
                            &request,
                            ProviderFailureCodeV1::BackendUnavailable,
                        ))
                    }
                }
                let Ok(signing_bytes) = signing.signing_bytes() else {
                    return invalid_request();
                };
                let signature = self.node_signing_key.sign(&signing_bytes).to_bytes();
                typed_pool_response(PoolCustodyResponseV1::new_pool_statement_signature(
                    &request, signature,
                ))
            }
        }
    }
}

impl ConfiguredCustodyProvider {
    /// Plan B POOL-MINT: a share a Home that uses this root's pool
    /// provisioned. The validated request proved the attached descriptor at
    /// `now` (v3 `WciOperated`, term open), the minting Home's signed share
    /// statement and the runtime statement under the same issuer; the
    /// Runtime wrapper proved that the pool is one this root serves (the
    /// trusted binding). Here the descriptor must be at or above this node's
    /// high-water mark for the pool; the store keeps the (minting Home, KID)
    /// slot write-once (ADV-16), and an accepted share advances the mark. The
    /// host storage maximum is the Runtime wrapper's.
    fn provision_pool_node_share(
        &mut self,
        request: &ValidatedPoolCustodyRequestV1,
        now: u64,
    ) -> ProviderResponse {
        let Ok(provision) = request.provision_pool_node_share() else {
            return invalid_request();
        };
        let descriptor = provision.pool_descriptor();
        let pool = *descriptor.pool().issuer().as_bytes();
        match self.pool_high_water.admits(&pool, descriptor.sequence()) {
            Ok(true) => {}
            Ok(false) => return provisioning_refused(),
            Err(_) => return backend_unavailable(),
        }
        match self.share_store.provision_pool_node_share_classified(
            provision.custody_node_provisioning_record(),
            provision.signed_runtime_custody_provisioning(),
            provision.signed_pool_mint_share(),
            &self.node_custody_secret,
            now,
        ) {
            Ok(_) => {
                if self
                    .pool_high_water
                    .record(&pool, descriptor.sequence())
                    .is_err()
                {
                    return backend_unavailable();
                }
                typed_pool_response(PoolCustodyResponseV1::new_pool_provisioned(request))
            }
            Err(error) if error.proves_not_stored() => provisioning_refused(),
            Err(_) => ProviderResponse::error(
                BACKEND_ERROR_CODE,
                "custody provider could not provision the node share",
            ),
        }
    }
}

fn provisioning_refused() -> ProviderResponse {
    ProviderResponse::error(
        PROVISIONING_REFUSED_ERROR_CODE,
        "custody provider refused the node share before storing it",
    )
}

enum CliCommand {
    Serve,
    Provision {
        base_path: String,
        trusted_runtime_issuer: String,
    },
}

fn parse_cli_command() -> Result<CliCommand, ()> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        return Ok(CliCommand::Serve);
    };
    if command != "provision" {
        return Err(());
    }
    let mut base_path = None;
    let mut trusted_runtime_issuer = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--base-path" => base_path = args.next(),
            "--trusted-runtime-issuer" => trusted_runtime_issuer = args.next(),
            _ => return Err(()),
        }
    }
    match (base_path, trusted_runtime_issuer) {
        (Some(base_path), Some(trusted_runtime_issuer)) => Ok(CliCommand::Provision {
            base_path,
            trusted_runtime_issuer,
        }),
        _ => Err(()),
    }
}

fn typed_response(
    result: Result<CustodyProviderResponseV1, impl std::fmt::Debug>,
) -> ProviderResponse {
    let Ok(response) = result else {
        return ProviderResponse::error(BACKEND_ERROR_CODE, "custody provider response failed");
    };
    let Ok(bytes) = response.to_json_vec() else {
        return ProviderResponse::error(BACKEND_ERROR_CODE, "custody provider response failed");
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => ProviderResponse::ok(value),
        Err(_) => ProviderResponse::error(BACKEND_ERROR_CODE, "custody provider response failed"),
    }
}

fn typed_pool_response(
    result: Result<PoolCustodyResponseV1, impl std::fmt::Debug>,
) -> ProviderResponse {
    let Ok(response) = result else {
        return ProviderResponse::error(BACKEND_ERROR_CODE, "custody provider response failed");
    };
    let Ok(bytes) = response.to_json_vec() else {
        return ProviderResponse::error(BACKEND_ERROR_CODE, "custody provider response failed");
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => ProviderResponse::ok(value),
        Err(_) => ProviderResponse::error(BACKEND_ERROR_CODE, "custody provider response failed"),
    }
}

/// Whether the operation's pool descriptor is at or above this node's
/// high-water mark for that pool. `Err` when the mark cannot be read.
fn admits_pool_descriptor(
    high_water: &PoolDescriptorHighWaterV1,
    operation: &AuthenticatedRuntimeReleaseOperationV2,
) -> Result<bool, ()> {
    high_water
        .admits(
            operation.pool().issuer().as_bytes(),
            operation.descriptor_sequence(),
        )
        .map_err(|_| ())
}

fn not_configured() -> ProviderResponse {
    ProviderResponse::error(BACKEND_ERROR_CODE, "custody provider is not configured")
}

fn unknown_envelope() -> ProviderResponse {
    ProviderResponse::error(
        UNKNOWN_ENVELOPE_ERROR_CODE,
        "custody provider holds no share of this item",
    )
}

fn backend_unavailable() -> ProviderResponse {
    ProviderResponse::error(BACKEND_ERROR_CODE, "custody provider store is unavailable")
}

fn typed_rights_response(response: RightsProviderResponseV1) -> ProviderResponse {
    let Ok(bytes) = response.to_json_vec() else {
        return ProviderResponse::error(BACKEND_ERROR_CODE, "custody provider response failed");
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => ProviderResponse::ok(value),
        Err(_) => ProviderResponse::error(BACKEND_ERROR_CODE, "custody provider response failed"),
    }
}

fn invalid_request() -> ProviderResponse {
    ProviderResponse::error(REQUEST_ERROR_CODE, "custody provider request is invalid")
}

fn operation_expired() -> ProviderResponse {
    ProviderResponse::error(
        OPERATION_EXPIRED_ERROR_CODE,
        "custody provider operation expired",
    )
}

/// A validation refusal, named `operation_expired` when the operation had
/// already ended and `invalid_request` otherwise.
fn request_refusal(operation_ended: bool) -> ProviderResponse {
    if operation_ended {
        operation_expired()
    } else {
        invalid_request()
    }
}

fn value_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or(Value::Null)
}

/// Whether the release operation a refused request carries had ended at
/// `now`: its own window or its release request's window closed.
///
/// The operation is decoded here without verification, so this only picks
/// which refusal the caller reads. Both refusals precede every store, and a
/// forged operation can at most choose between them.
fn release_operation_ended(request: &Value, now: u64) -> bool {
    let Some(operation) = request
        .get("signed_runtime_release_operation")
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<u8>>(value).ok())
        .and_then(|bytes| RuntimeReleaseOperationAnyV1::from_canonical_bytes(&bytes).ok())
    else {
        return false;
    };
    match operation {
        RuntimeReleaseOperationAnyV1::V1(operation) => {
            let statement = operation.statement();
            now >= statement.expires_at() || now >= statement.release_request().expires_at()
        }
        RuntimeReleaseOperationAnyV1::V2(operation) => {
            let statement = operation.statement();
            now >= statement.expires_at()
                || now >= statement.rights_request().request().expires_at()
        }
    }
}

fn rights_denied() -> ProviderResponse {
    ProviderResponse::error(
        RIGHTS_DENIED_ERROR_CODE,
        "custody provider release was denied",
    )
}

fn control_request_has_exact_fields(value: &Value, op: &str) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    match op {
        "init" => object.len() == 2 && object.contains_key("op") && object.contains_key("config"),
        "status" | "shutdown" => object.len() == 1 && object.contains_key("op"),
        _ => false,
    }
}

fn reject_runtime_envelope_fields(value: &Value) -> Result<(), ()> {
    let object = value.as_object().ok_or(())?;
    if object.contains_key("_runtime_invocation") || object.contains_key("_runtime_transfer") {
        return Err(());
    }
    Ok(())
}

fn chain_rights_evidence_request_from_validated_request(request: &Value) -> Result<Value, ()> {
    let object = request.as_object().ok_or(())?;
    if object.get("op").and_then(Value::as_str) != Some("evaluate") {
        return Err(());
    }
    let signed_runtime_release_operation_bytes = object
        .get("signed_runtime_release_operation")
        .cloned()
        .ok_or(())
        .and_then(|value| serde_json::from_value::<Vec<u8>>(value).map_err(|_| ()))?;
    let signed_runtime_release_operation =
        RuntimeReleaseOperationAnyV1::from_canonical_bytes(&signed_runtime_release_operation_bytes)
            .map_err(|_| ())?;
    chain_rights_evidence_request_any(&signed_runtime_release_operation).map_err(|_| ())
}

fn load_root_set(config: Value) -> Result<CustodyRootSet, ()> {
    let mut set = CustodyRootSet {
        roots: BTreeMap::new(),
        listed: Vec::new(),
    };
    for root in parse_state_roots_from_provider_init(&config).map_err(|_| ())? {
        let Ok(state) = load_provider_state(&root.root) else {
            // Its key, when readable, routes its frames to the unconfigured
            // answer instead of `invalid_request`.
            let key = custody_provider::load_node_public_key(&root.root).ok();
            set.listed.push(ListedRoot {
                path: root.path,
                node_public_key: key,
                loaded: false,
            });
            continue;
        };
        let key = state.node_public_key;
        set.roots.insert(key, state);
        set.listed.push(ListedRoot {
            path: root.path,
            node_public_key: Some(key),
            loaded: true,
        });
    }
    // Two roots with one node key, loaded or only readable, cannot be routed
    // apart: init fails closed (user decision 2026-11-12 10:26 (2), S2-F2).
    let mut keys = std::collections::BTreeSet::new();
    if set
        .listed
        .iter()
        .filter_map(|root| root.node_public_key)
        .any(|key| !keys.insert(key))
    {
        return Err(());
    }
    if set.roots.is_empty() {
        return Err(());
    }
    Ok(set)
}

/// Loads one root. Its durable state (share store, descriptor high-water) is
/// read and checked, never changed, before the root counts as loaded
/// (S2-F3); missing state is a valid empty store.
fn load_provider_state(root: &std::path::Path) -> Result<ConfiguredCustodyProvider, ()> {
    let loaded = load_state_from_root(root).map_err(|_| ())?;
    let state = ConfiguredCustodyProvider {
        expected_runtime_issuer: loaded.expected_runtime_issuer,
        node_public_key: loaded.node_public_key,
        share_store: NodeLocalShareStoreV1::new(
            loaded.node_public_key,
            loaded
                .data_root
                .join(custody_provider::NODE_SHARE_STORE_DIR),
        ),
        replay_store: DurableReplayClaimStoreV1::new(
            loaded.node_public_key,
            loaded.data_root.join("replay"),
        ),
        pool_high_water: PoolDescriptorHighWaterV1::new(&loaded.data_root),
        node_signing_key: loaded.node_signing_key,
        node_custody_secret: loaded.node_custody_secret,
    };
    state.share_store.validate().map_err(|_| ())?;
    state.pool_high_water.validate().map_err(|_| ())?;
    Ok(state)
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn read_provider_frame<R: BufRead>(reader: &mut R) -> io::Result<Option<Result<Vec<u8>, ()>>> {
    let mut frame = Vec::new();
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if frame.is_empty() && !oversized {
                return Ok(None);
            }
            return Ok(Some(if oversized { Err(()) } else { Ok(frame) }));
        }

        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            let chunk = &available[..newline];
            if !oversized {
                if frame.len().saturating_add(chunk.len()) > MAX_PROVIDER_FRAME_BYTES_V1 {
                    oversized = true;
                } else {
                    frame.extend_from_slice(chunk);
                }
            }
            reader.consume(newline + 1);
            return Ok(Some(if oversized { Err(()) } else { Ok(frame) }));
        }

        let consumed = available.len();
        if !oversized {
            if frame.len().saturating_add(consumed) > MAX_PROVIDER_FRAME_BYTES_V1 {
                oversized = true;
            } else {
                frame.extend_from_slice(available);
            }
        }
        reader.consume(consumed);
    }
}

fn run_provider_loop<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    provider: &mut CustodyProvider,
) {
    loop {
        let (response, should_shutdown) = match read_provider_frame(input) {
            Ok(Some(Ok(frame))) => provider.handle_frame(&frame),
            Ok(Some(Err(()))) => (invalid_request(), false),
            Ok(None) => break,
            // A transport read error is not recoverable: retrying re-reads the
            // same failing descriptor and spins. Report once, then exit.
            Err(_) => (
                ProviderResponse::error(REQUEST_ERROR_CODE, "custody provider request is invalid"),
                true,
            ),
        };
        if serde_json::to_writer(&mut *output, &response).is_err() {
            break;
        }
        if writeln!(output).and_then(|()| output.flush()).is_err() {
            break;
        }
        if should_shutdown {
            break;
        }
    }
}

fn main() {
    match parse_cli_command() {
        Ok(CliCommand::Serve) => {}
        Ok(CliCommand::Provision {
            base_path,
            trusted_runtime_issuer,
        }) => {
            if run_provision_command(&base_path, &trusted_runtime_issuer).is_err() {
                eprintln!("custody-provider: provisioning failed");
                std::process::exit(1);
            }
            return;
        }
        Err(()) => {
            eprintln!("custody-provider: usage: custody-provider provision --base-path <abs-root> --trusted-runtime-issuer <0x...>");
            std::process::exit(2);
        }
    }
    eprintln!("custody-provider: starting v{PROVIDER_VERSION}");
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut stdout = io::stdout();
    let mut provider = CustodyProvider::new();
    run_provider_loop(&mut input, &mut stdout, &mut provider);
}

fn run_provision_command(base_path: &str, trusted_runtime_issuer: &str) -> Result<(), ()> {
    let root = parse_state_root_from_provider_init(&json!({
        "base_path": base_path,
        "allowed_paths": [],
        "read_only": false,
        "encryption_key": "",
        "extra": null,
    }))
    .map_err(|_| ())?;
    let runtime_issuer = parse_runtime_issuer_hex(trusted_runtime_issuer).map_err(|_| ())?;
    let provisioned = provision_state_root(&root, runtime_issuer).map_err(|_| ())?;
    let receipt = provisioning_receipt(
        runtime_issuer,
        provisioned.node_public_key,
        provisioned.node_custody_public_key,
    );
    serde_json::to_writer(
        io::stdout(),
        &json!({
            "status": "ok",
            "data": {
                "schema": PROVISIONING_SCHEMA_V1,
                "provider": "custody",
                "node_public_key": format!("0x{}", hex_bytes(provisioned.node_public_key.as_bytes())),
                "node_custody_public_key": format!("0x{}", hex_bytes(provisioned.node_custody_public_key.as_bytes())),
                "receipt": format!("0x{}", hex_bytes(&receipt)),
            }
        }),
    )
    .map_err(|_| ())?;
    println!();
    Ok(())
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self};
    use std::io::Cursor;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CONFIG_ID: AtomicUsize = AtomicUsize::new(0);

    fn temp_root() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }

    fn runtime_issuer_hex(seed: u8) -> String {
        let key = SigningKey::from_bytes(&[seed; 32]);
        format!("0x{}", hex_bytes(&key.verifying_key().to_bytes()))
    }

    fn init_config(root: &Path) -> Value {
        let root = fs::canonicalize(root).unwrap();
        let id = CONFIG_ID.fetch_add(1, Ordering::Relaxed);
        let case = root.join(format!("case-{id}"));
        provision_state_root(
            &case,
            parse_runtime_issuer_hex(&runtime_issuer_hex(0x42)).unwrap(),
        )
        .unwrap();
        json!({
            "base_path": case,
            "allowed_paths": [],
            "read_only": false,
            "encryption_key": "",
            "extra": null
        })
    }

    fn hex_bytes(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn provider_loop_responses(input: Vec<u8>) -> Vec<Value> {
        let mut input = Cursor::new(input);
        let mut output = Vec::new();
        let mut provider = CustodyProvider::new();
        run_provider_loop(&mut input, &mut output, &mut provider);
        String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    struct FailingReader;

    impl io::Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("persistent transport failure"))
        }
    }

    impl BufRead for FailingReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::other("persistent transport failure"))
        }

        fn consume(&mut self, _amount: usize) {}
    }

    #[test]
    fn provider_loop_exits_after_one_error_frame_on_transport_read_failure() {
        let mut input = FailingReader;
        let mut output = Vec::new();
        let mut provider = CustodyProvider::new();
        run_provider_loop(&mut input, &mut output, &mut provider);
        let responses: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0]["status"], "error");
    }

    fn oversized_frame_for(op: &str) -> Vec<u8> {
        let mut frame = format!(r#"{{"op":"{op}","padding":""#).into_bytes();
        frame.resize(MAX_PROVIDER_FRAME_BYTES_V1 + 1, b'a');
        frame.push(b'\n');
        frame
    }

    #[test]
    fn init_status_and_shutdown_are_redacted_and_strict() {
        let temp = temp_root();
        let mut provider = CustodyProvider::new();
        let response = provider.init(init_config(temp.path()));
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(encoded.contains("\"configured\":true"));
        assert!(encoded.contains(CUSTODY_PROVIDER_REQUEST_SCHEMA_V1));
        assert!(!encoded.contains(temp.path().to_str().unwrap()));
        // The full 32-byte pattern: status now lists a random node key, whose
        // first bytes may be anything (Plan B T2.1).
        assert!(!encoded.contains(&format!("0x{}", "01".repeat(32))));
        assert!(!encoded.contains("carrier"));
        assert!(!encoded.contains("\"port\""));

        let response = provider.handle_line(r#"{"op":"shutdown"}"#);
        assert_eq!(serde_json::to_value(response).unwrap()["status"], "ok");
    }

    #[test]
    fn init_rejects_missing_unsafe_and_extra_config_inputs_and_clears_state() {
        let temp = temp_root();
        let mut provider = CustodyProvider::new();
        assert!(matches!(
            provider.init(init_config(temp.path())),
            ProviderResponse::Ok { .. }
        ));

        let bad = provider.init(json!({"base_path": "direct"}));
        assert!(matches!(
            bad,
            ProviderResponse::Error {
                code: INIT_ERROR_CODE,
                ..
            }
        ));
        assert!(provider.roots.is_none());

        let config = init_config(temp.path());
        let root = PathBuf::from(config["base_path"].as_str().unwrap());
        fs::set_permissions(
            root.join("node-signing-key"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            provider.init(config),
            ProviderResponse::Error { .. }
        ));

        let config = init_config(temp.path());
        let root = PathBuf::from(config["base_path"].as_str().unwrap());
        let custody = root.join("node-custody-secret");
        fs::remove_file(&custody).unwrap();
        symlink(temp.path().join("missing"), &custody).unwrap();
        assert!(matches!(
            provider.init(config),
            ProviderResponse::Error { .. }
        ));

        // Plan B T2.1: `extra` is the root set or null. Anything else, a path
        // outside the layout, a repeated path and an empty set are refused.
        let base = custody_base(temp.path());
        provision_root(&base, "inactive");
        for extra in [
            json!({"unexpected": true}),
            json!({"roots": [{"path": "inactive"}], "max_roots": 8, "unexpected": true}),
            json!({"roots": [{"path": "inactive", "unexpected": true}], "max_roots": 8}),
            json!({"roots": [], "max_roots": 8}),
            json!({"roots": [{"path": "inactive"}, {"path": "inactive"}], "max_roots": 8}),
            json!({"roots": [{"path": "../inactive"}], "max_roots": 8}),
            json!({"roots": [{"path": "/inactive"}], "max_roots": 8}),
            json!({"roots": [{"path": "pools/ABCD"}], "max_roots": 8}),
            json!({"roots": [{"path": format!("pools/{}", "A".repeat(64))}], "max_roots": 8}),
            json!({"roots": [{"path": format!("{}/x", pool_path('a'))}], "max_roots": 8}),
            json!({"roots": [{"path": "inactive"}], "max_roots": 0}),
        ] {
            let mut config = roots_config(&base, &["inactive"], 8);
            config["config"]["extra"] = extra;
            assert!(matches!(
                provider.init(config["config"].clone()),
                ProviderResponse::Error {
                    code: INIT_ERROR_CODE,
                    ..
                }
            ));
            assert!(provider.roots.is_none());
        }
    }

    #[test]
    fn init_rejects_relative_paths_symlinked_parent_and_data_root() {
        let temp = temp_root();
        let mut provider = CustodyProvider::new();

        let mut relative = init_config(temp.path());
        relative["base_path"] = json!("runtime");
        assert!(matches!(
            provider.init(relative),
            ProviderResponse::Error {
                code: INIT_ERROR_CODE,
                ..
            }
        ));

        let safe_root = fs::canonicalize(temp.path()).unwrap();
        let real_parent = safe_root.join("real-parent");
        fs::create_dir(&real_parent).unwrap();
        fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let linked_parent = safe_root.join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        let mut symlinked_parent = init_config(temp.path());
        symlinked_parent["base_path"] = json!(linked_parent);
        assert!(matches!(
            provider.init(symlinked_parent),
            ProviderResponse::Error { .. }
        ));

        let symlinked_data = init_config(temp.path());
        let root = PathBuf::from(symlinked_data["base_path"].as_str().unwrap());
        let data = root.join("data");
        fs::remove_dir(&data).unwrap();
        let target = safe_root.join("actual-data-root");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&target, &data).unwrap();
        assert!(matches!(
            provider.init(symlinked_data),
            ProviderResponse::Error { .. }
        ));
    }

    #[test]
    fn provider_loop_enforces_frame_limit_and_recovers_next_frame() {
        let mut input = vec![b' '; MAX_PROVIDER_FRAME_BYTES_V1];
        input.push(b'\n');
        input.extend_from_slice(&oversized_frame_for("status"));
        input.extend_from_slice(&oversized_frame_for("provision_node_share"));
        input.extend_from_slice(br#"{"op":"status"}"#);
        input.push(b'\n');
        input.extend_from_slice(br#"{"op":"shutdown"}"#);
        input.push(b'\n');

        let responses = provider_loop_responses(input);
        assert_eq!(responses.len(), 5);
        assert_eq!(responses[0]["status"], "error");
        assert_eq!(responses[1]["status"], "error");
        assert_eq!(responses[2]["status"], "error");
        assert_eq!(responses[3]["status"], "ok");
        assert_eq!(responses[3]["data"]["provider"], "custody");
        assert_eq!(responses[4]["status"], "ok");
    }

    #[test]
    fn malformed_requests_fail_with_fixed_redacted_error() {
        let temp = temp_root();
        let mut provider = CustodyProvider::new();
        assert!(matches!(
            provider.init(init_config(temp.path())),
            ProviderResponse::Ok { .. }
        ));
        for line in [
            r#"{"op":"provision_node_share","has_access":true}"#,
            r#"{"op":"release_contribution","custody_envelope":[]}"#,
            r#"{"op":"unknown","path":"/tmp/secret"}"#,
        ] {
            let encoded = serde_json::to_string(&provider.handle_line(line)).unwrap();
            assert!(encoded.contains(REQUEST_ERROR_CODE));
            assert!(!encoded.contains("/tmp/secret"));
            assert!(!encoded.contains("custody_envelope"));
            assert!(!encoded.contains("has_access"));
        }
    }

    fn runtime_invocation(op: &str, target: &str, carrier: Value) -> Value {
        json!({
            "schema": "elastos.provider.invocation/v1",
            "source": "runtime",
            "target": target,
            "op": op,
            "capability": format!("provider:runtime->{target}:{op}"),
            "transport": "runtime-local-provider-plane",
            "carrier": carrier,
            "transfer": "json",
            "range": null,
            "progress": null,
            "abi": {}
        })
    }

    #[test]
    fn status_rejects_runtime_invocation_and_transfer_envelopes() {
        let mut provider = CustodyProvider::new();
        for envelope in [
            runtime_invocation("status", "key", Value::Null),
            runtime_invocation("status", "custody", json!({"peer_did": "did:key:zX"})),
            json!({
                "schema": "elastos.provider.invocation/v1",
                "source": "runtime",
                "target": "custody",
                "op": "status",
                "transport": "carrier-provider-plane",
                "carrier": Value::Null
            }),
        ] {
            assert!(matches!(
                provider.handle_line(
                    &json!({
                        "op": "status",
                        "_runtime_invocation": envelope,
                    })
                    .to_string(),
                ),
                ProviderResponse::Error {
                    code: REQUEST_ERROR_CODE,
                    ..
                }
            ));
        }
        assert!(matches!(
            provider.handle_line(
                &json!({
                    "op": "status",
                    "_runtime_transfer": {
                        "schema": "elastos.provider.transfer/v1"
                    },
                })
                .to_string(),
            ),
            ProviderResponse::Error {
                code: REQUEST_ERROR_CODE,
                ..
            }
        ));
    }

    #[test]
    fn chain_request_rejects_string_signed_runtime_release_operation() {
        let mut request_value = json!({
            "op": "evaluate",
            "signed_runtime_release_operation": "0xdeadbeef",
        });
        request_value["signed_runtime_release_operation"] = Value::String("0xdeadbeef".to_string());
        assert!(chain_rights_evidence_request_from_validated_request(&request_value).is_err());
    }

    #[test]
    fn chain_request_rejects_malformed_canonical_bytes() {
        let mut request_value = json!({
            "op": "evaluate",
            "signed_runtime_release_operation": [1, 2, 3],
        });
        request_value["signed_runtime_release_operation"] = json!([1, 2, 3]);
        assert!(chain_rights_evidence_request_from_validated_request(&request_value).is_err());
    }

    #[test]
    fn chain_request_rejects_wrong_op() {
        let request_value = json!({
            "op": "status",
            "signed_runtime_release_operation": [1, 2, 3],
        });
        assert!(chain_rights_evidence_request_from_validated_request(&request_value).is_err());
    }

    // Plan B T2.1: one process, one root per pool.

    fn issuer_0x42() -> RuntimeOperationIssuerKeyV1 {
        parse_runtime_issuer_hex(&runtime_issuer_hex(0x42)).unwrap()
    }

    fn owner_only_dir(path: &Path) {
        if !path.exists() {
            fs::create_dir(path).unwrap();
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// `<temp>/data/protected-content/custody-provider`, laid out as the
    /// Runtime keeps it, with an owner-only `pools` folder.
    fn custody_base(temp: &Path) -> PathBuf {
        let data = fs::canonicalize(temp).unwrap().join("data");
        let base = data.join("protected-content/custody-provider");
        for dir in [
            data.clone(),
            data.join("protected-content"),
            base.clone(),
            base.join("pools"),
        ] {
            owner_only_dir(&dir);
        }
        base
    }

    fn pool_path(fill: char) -> String {
        format!("pools/{}", fill.to_string().repeat(64))
    }

    fn provision_root(base: &Path, path: &str) -> NodePublicKey {
        let root = base.join(path);
        if !root.exists() {
            provision_state_root(&root, issuer_0x42()).unwrap();
        }
        custody_provider::load_node_public_key(&root).unwrap()
    }

    fn roots_config(base: &Path, paths: &[&str], max_roots: usize) -> Value {
        json!({
            "op": "init",
            "config": {
                "base_path": base,
                "allowed_paths": [],
                "read_only": false,
                "encryption_key": "",
                "extra": {
                    "roots": paths.iter().map(|path| json!({"path": path})).collect::<Vec<_>>(),
                    "max_roots": max_roots,
                }
            }
        })
    }

    fn init_roots(provider: &mut CustodyProvider, base: &Path, paths: &[&str]) -> Value {
        serde_json::to_value(provider.init(roots_config(base, paths, 8)["config"].clone())).unwrap()
    }

    fn status_roots(provider: &CustodyProvider) -> Vec<Value> {
        serde_json::to_value(provider.status()).unwrap()["data"]["roots"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn key_hex(key: NodePublicKey) -> String {
        format!("0x{}", hex_bytes(key.as_bytes()))
    }

    #[test]
    fn legacy_inactive_root_loads_as_the_first_root() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        let key = provision_root(&base, "inactive");
        let mut provider = CustodyProvider::new();

        // An older Runtime and the custody host send the root itself, with
        // `extra: null`: one legacy root.
        let legacy = provider.init(json!({
            "base_path": base.join("inactive"),
            "allowed_paths": [],
            "read_only": false,
            "encryption_key": "",
            "extra": null,
        }));
        assert!(matches!(legacy, ProviderResponse::Ok { .. }));
        assert_eq!(
            status_roots(&provider),
            vec![json!({
                "path": null,
                "node_public_key": key_hex(key),
                "configured": true,
                "shares_held": 0,
            })]
        );

        // The Runtime's root set names the same folder `inactive`: the same
        // node, now the first root of the set.
        assert_eq!(
            init_roots(&mut provider, &base, &["inactive"])["status"],
            "ok"
        );
        let roots = status_roots(&provider);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0]["path"], "inactive");
        assert_eq!(roots[0]["node_public_key"], key_hex(key));
    }

    #[test]
    fn include_root_loads_as_own_pool() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        let pool = pool_path('c');
        let key = provision_root(&base, &pool);
        let mut provider = CustodyProvider::new();
        // A Home whose only root is a `pools/<hex>` root (its own pool or a
        // served one) starts with no `inactive` folder at all.
        assert_eq!(init_roots(&mut provider, &base, &[&pool])["status"], "ok");
        let roots = status_roots(&provider);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0]["path"], pool.as_str());
        assert_eq!(roots[0]["configured"], true);
        assert_eq!(roots[0]["node_public_key"], key_hex(key));
        assert!(!base.join("inactive").exists());
    }

    #[test]
    fn more_than_max_roots_is_refused_at_init() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        let paths = [pool_path('a'), pool_path('b'), pool_path('c')];
        for path in &paths {
            provision_root(&base, path);
        }
        let paths = paths.iter().map(String::as_str).collect::<Vec<_>>();
        let mut provider = CustodyProvider::new();
        assert!(matches!(
            provider.init(roots_config(&base, &paths, 2)["config"].clone()),
            ProviderResponse::Error {
                code: INIT_ERROR_CODE,
                ..
            }
        ));
        assert!(provider.roots.is_none());
        assert!(matches!(
            provider.init(roots_config(&base, &paths, 3)["config"].clone()),
            ProviderResponse::Ok { .. }
        ));
        assert_eq!(status_roots(&provider).len(), 3);
    }

    #[test]
    fn separate_keys_per_root() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        let pool = pool_path('a');
        let first = provision_root(&base, "inactive");
        let second = provision_root(&base, &pool);
        assert_ne!(first, second);
        let mut provider = CustodyProvider::new();
        assert_eq!(
            init_roots(&mut provider, &base, &["inactive", &pool])["status"],
            "ok"
        );
        let keys = status_roots(&provider)
            .iter()
            .map(|root| root["node_public_key"].clone())
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![json!(key_hex(first)), json!(key_hex(second))]);

        // Two roots holding one node key cannot be routed apart: refused.
        let copy = pool_path('b');
        provision_root(&base, &copy);
        let signing = fs::read(base.join("inactive/node-signing-key")).unwrap();
        fs::write(base.join(&copy).join("node-signing-key"), signing).unwrap();
        assert!(matches!(
            provider.init(roots_config(&base, &["inactive", &copy], 8)["config"].clone()),
            ProviderResponse::Error {
                code: INIT_ERROR_CODE,
                ..
            }
        ));
    }

    #[test]
    fn reinit_adds_a_root_and_keeps_the_others() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        let first = provision_root(&base, "inactive");
        let mut provider = CustodyProvider::new();
        assert_eq!(
            init_roots(&mut provider, &base, &["inactive"])["status"],
            "ok"
        );

        // T2.2 provisions a second root, then re-sends `init` with the set.
        let pool = pool_path('d');
        let second = provision_root(&base, &pool);
        assert_eq!(
            init_roots(&mut provider, &base, &["inactive", &pool])["status"],
            "ok"
        );
        let roots = status_roots(&provider);
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0]["node_public_key"], key_hex(first));
        assert_eq!(roots[1]["node_public_key"], key_hex(second));
        let set = provider.roots.as_ref().unwrap();
        assert!(set.roots.contains_key(&first));
        assert!(set.roots.contains_key(&second));

        // Stop serving (T2.3) re-sends the set without the root.
        assert_eq!(
            init_roots(&mut provider, &base, &["inactive"])["status"],
            "ok"
        );
        let set = provider.roots.as_ref().unwrap();
        assert!(set.roots.contains_key(&first));
        assert!(!set.roots.contains_key(&second));
    }

    #[test]
    fn a_root_that_fails_to_load_is_listed_unconfigured_and_the_others_serve() {
        // User decision 2026-11-12 10:26: per-root load.
        let temp = temp_root();
        let base = custody_base(temp.path());
        let first = provision_root(&base, "inactive");
        let pool = pool_path('e');
        provision_root(&base, &pool);
        fs::set_permissions(
            base.join(&pool).join("node-signing-key"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let missing = pool_path('f');
        let mut provider = CustodyProvider::new();
        assert_eq!(
            init_roots(&mut provider, &base, &["inactive", &pool, &missing])["status"],
            "ok"
        );
        let roots = status_roots(&provider);
        assert_eq!(roots[0]["configured"], true);
        assert_eq!(roots[0]["node_public_key"], key_hex(first));
        for (root, path) in roots[1..].iter().zip([&pool, &missing]) {
            assert_eq!(root["path"], path.as_str());
            assert_eq!(root["configured"], false);
            assert!(root["node_public_key"].is_null());
            assert!(root["shares_held"].is_null());
        }
        assert_eq!(provider.roots.as_ref().unwrap().roots.len(), 1);

        // With no root loaded the provider is not configured at all.
        assert!(matches!(
            provider.init(roots_config(&base, &[&pool, &missing], 8)["config"].clone()),
            ProviderResponse::Error {
                code: INIT_ERROR_CODE,
                ..
            }
        ));
        assert!(provider.roots.is_none());
    }

    #[test]
    fn more_than_the_provider_cap_of_eight_roots_is_refused() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        let fills = ['1', '2', '3', '4', '5', '6', '7', '8', '9'];
        let paths = fills
            .iter()
            .map(|fill| pool_path(*fill))
            .collect::<Vec<_>>();
        for path in &paths {
            provision_root(&base, path);
        }
        let paths = paths.iter().map(String::as_str).collect::<Vec<_>>();
        let mut provider = CustodyProvider::new();
        assert!(matches!(
            provider.init(roots_config(&base, &paths, 9)["config"].clone()),
            ProviderResponse::Error {
                code: INIT_ERROR_CODE,
                ..
            }
        ));
        assert!(matches!(
            provider.init(roots_config(&base, &paths[..8], 8)["config"].clone()),
            ProviderResponse::Ok { .. }
        ));
        assert_eq!(status_roots(&provider).len(), 8);
    }

    fn init_error(provider: &mut CustodyProvider, config: Value) -> bool {
        matches!(
            provider.init(config),
            ProviderResponse::Error {
                code: INIT_ERROR_CODE,
                ..
            }
        )
    }

    #[test]
    fn legacy_root_status_path_is_null() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        provision_root(&base, "inactive");
        let mut provider = CustodyProvider::new();
        let legacy = provider.init(json!({
            "base_path": base.join("inactive"),
            "allowed_paths": [],
            "read_only": false,
            "encryption_key": "",
            "extra": null,
        }));
        assert!(matches!(legacy, ProviderResponse::Ok { .. }));
        let roots = status_roots(&provider);
        assert_eq!(roots.len(), 1);
        assert!(roots[0]["path"].is_null());
        assert_eq!(roots[0]["configured"], true);
    }

    #[test]
    fn empty_roots_refused() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        provision_root(&base, "inactive");
        let mut provider = CustodyProvider::new();
        init_roots(&mut provider, &base, &["inactive"]);
        assert!(init_error(
            &mut provider,
            roots_config(&base, &[], 8)["config"].clone()
        ));
        // The set is cleared, as on every refused init.
        assert!(provider.roots.is_none());
    }

    #[test]
    fn unsafe_root_path_refuses_init() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        provision_root(&base, "inactive");
        let hex = "a".repeat(64);
        let absolute = base.join("inactive").display().to_string();
        let unsafe_paths = [
            absolute,
            "../inactive".to_string(),
            "pools/../inactive".to_string(),
            format!("pools/{hex}/nested"),
            format!("pools/{}", "A".repeat(64)),
            format!("pools/{}", "a".repeat(63)),
            "pools".to_string(),
            "Inactive".to_string(),
            String::new(),
        ];
        for path in &unsafe_paths {
            let mut provider = CustodyProvider::new();
            init_roots(&mut provider, &base, &["inactive"]);
            assert!(
                init_error(
                    &mut provider,
                    roots_config(&base, &["inactive", path], 8)["config"].clone()
                ),
                "{path:?}"
            );
            assert!(provider.roots.is_none(), "{path:?}");
        }
        // A repeated path refuses init too.
        let mut provider = CustodyProvider::new();
        assert!(init_error(
            &mut provider,
            roots_config(&base, &["inactive", "inactive"], 8)["config"].clone()
        ));
    }

    #[test]
    fn failed_root_status_has_null_key_and_count() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        provision_root(&base, "inactive");
        let missing = pool_path('9');
        let mut provider = CustodyProvider::new();
        assert_eq!(
            init_roots(&mut provider, &base, &["inactive", &missing])["status"],
            "ok"
        );
        let roots = status_roots(&provider);
        assert_eq!(
            roots[1],
            json!({
                "path": missing,
                "node_public_key": null,
                "configured": false,
                "shares_held": null,
            })
        );
    }

    #[test]
    fn init_fails_only_when_no_root_loads() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        provision_root(&base, "inactive");
        let missing = pool_path('8');
        let mut provider = CustodyProvider::new();
        // One loading root is enough.
        assert_eq!(
            init_roots(&mut provider, &base, &[&missing, "inactive"])["status"],
            "ok"
        );
        assert_eq!(provider.roots.as_ref().unwrap().roots.len(), 1);
        // None loading refuses init and clears the set.
        assert!(init_error(
            &mut provider,
            roots_config(&base, &[&missing], 8)["config"].clone()
        ));
        assert!(provider.roots.is_none());
    }

    #[test]
    fn status_redacts_root_folders() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        provision_root(&base, "inactive");
        let mut provider = CustodyProvider::new();
        init_roots(&mut provider, &base, &["inactive"]);
        let encoded = serde_json::to_string(&provider.status()).unwrap();
        assert!(!encoded.contains(base.to_str().unwrap()));
        assert!(encoded.contains("\"roots\""));
    }

    /// S2-F2: a failed root whose readable key is a healthy root's never
    /// borrows that root's status: two roots with one node key refuse init
    /// (user decision 2026-11-12 10:26 (2)), whichever loads, in both orders.
    #[test]
    fn a_failed_root_sharing_a_healthy_roots_key_refuses_init_in_both_orders() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        provision_root(&base, "inactive");
        let alias = pool_path('a');
        provision_root(&base, &alias);
        // The alias holds the healthy root's signing key, and its issuer no
        // longer reads, so it fails to load with the same readable key.
        fs::write(
            base.join(&alias).join("node-signing-key"),
            fs::read(base.join("inactive").join("node-signing-key")).unwrap(),
        )
        .unwrap();
        fs::write(
            base.join(&alias).join("trusted-runtime-issuer"),
            b"not hex\n",
        )
        .unwrap();
        assert_eq!(
            custody_provider::load_node_public_key(&base.join(&alias)).unwrap(),
            custody_provider::load_node_public_key(&base.join("inactive")).unwrap()
        );
        for paths in [["inactive", alias.as_str()], [alias.as_str(), "inactive"]] {
            let mut provider = CustodyProvider::new();
            assert!(init_error(
                &mut provider,
                roots_config(&base, &paths, 8)["config"].clone()
            ));
            assert!(provider.roots.is_none());
            assert!(status_roots(&provider).is_empty());
        }
    }

    /// The bytes and mode of every file under `dir`, to show init changed
    /// nothing.
    fn evidence(dir: &Path) -> Vec<(PathBuf, u32, Vec<u8>)> {
        let mut found = Vec::new();
        let mut pending = vec![dir.to_path_buf()];
        while let Some(dir) = pending.pop() {
            let mut entries = fs::read_dir(&dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            entries.sort();
            for path in entries {
                let metadata = fs::symlink_metadata(&path).unwrap();
                let mode = metadata.permissions().mode();
                if metadata.is_dir() {
                    found.push((path.clone(), mode, Vec::new()));
                    pending.push(path);
                } else {
                    found.push((path.clone(), mode, fs::read(&path).unwrap()));
                }
            }
        }
        found
    }

    /// S2-F3: a root whose durable state does not read is listed
    /// unconfigured beside a healthy root, and init changes nothing on disk.
    fn assert_bad_state_root_is_unconfigured(base: &Path, bad: &str) {
        let healthy = provision_root(base, "inactive");
        let bad_key = custody_provider::load_node_public_key(&base.join(bad)).unwrap();
        let before = evidence(&base.join(bad));
        let mut provider = CustodyProvider::new();
        assert_eq!(
            init_roots(&mut provider, base, &["inactive", bad])["status"],
            "ok"
        );
        let roots = status_roots(&provider);
        assert_eq!(roots[0]["configured"], true);
        assert_eq!(roots[0]["node_public_key"], key_hex(healthy));
        assert_eq!(
            roots[1],
            json!({
                "path": bad,
                "node_public_key": key_hex(bad_key),
                "configured": false,
                "shares_held": null,
            })
        );
        assert_eq!(provider.roots.as_ref().unwrap().roots.len(), 1);
        // Its frames get the unconfigured answer, before any store.
        assert!(matches!(
            provider
                .roots
                .as_ref()
                .unwrap()
                .unconfigured_or_unknown(bad_key),
            ProviderResponse::Error { .. }
        ));
        assert_eq!(evidence(&base.join(bad)), before);
    }

    #[test]
    fn a_root_with_a_corrupt_high_water_file_is_unconfigured_beside_a_healthy_root() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        let bad = pool_path('b');
        provision_root(&base, &bad);
        let high_water = base
            .join(&bad)
            .join("data")
            .join(custody_provider::POOL_DESCRIPTOR_SEQUENCE_FILE);
        fs::write(&high_water, b"not a high-water line\n").unwrap();
        fs::set_permissions(&high_water, fs::Permissions::from_mode(0o600)).unwrap();
        assert_bad_state_root_is_unconfigured(&base, &bad);
    }

    #[test]
    fn a_root_with_an_unsafe_share_store_is_unconfigured_beside_a_healthy_root() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        let bad = pool_path('c');
        provision_root(&base, &bad);
        let store = base.join(&bad).join("data").join("node-shares");
        fs::create_dir(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o755)).unwrap();
        assert_bad_state_root_is_unconfigured(&base, &bad);
    }

    #[test]
    fn a_root_with_an_unreadable_share_record_is_unconfigured_beside_a_healthy_root() {
        let temp = temp_root();
        let base = custody_base(temp.path());
        let bad = pool_path('d');
        provision_root(&base, &bad);
        let store = base.join(&bad).join("data").join("node-shares");
        owner_only_dir(&store);
        let record = store.join("ab".repeat(32));
        fs::write(&record, b"not a share record").unwrap();
        fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        assert_bad_state_root_is_unconfigured(&base, &bad);
    }
}

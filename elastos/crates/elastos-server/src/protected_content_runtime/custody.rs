use super::*;
use crate::custody_surface::{
    declared_ops, OP_CUSTODY_EVALUATE, OP_CUSTODY_PROVISION_NODE_SHARE,
    OP_CUSTODY_RELEASE_CONTRIBUTION, OP_CUSTODY_STATUS, TARGET_CUSTODY,
};

pub(crate) const CUSTODY_PROVIDER_ID: &str = "custody";

pub(crate) const CUSTODY_COMPOSITION_SCHEMA_V1: &str =
    "elastos.protected-content.custody-composition/v1";

const MAX_CUSTODY_COMPOSITION_BYTES: usize = 64 * 1024;

const MAX_CUSTODY_COMPOSITION_BLOB_BYTES: usize = 16 * 1024;

pub(super) const PROTECT_PROVIDER_PROCESS_ID: &str = "protected-content-protect";

const MEDIA_PROVIDER_PROTOCOL_VERSION: &str = "elastos.media-provider/v1";

pub(super) const PROTECTED_CONTENT_PROVIDER_STATUS_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5);

pub(super) const PROTECT_PROVIDER_OPERATIONS: &[&str] = &[
    "status",
    "open_protection_session",
    "protect_media_segment",
    "finalize_protection_session",
    "cancel_protection_session",
    "close_protection_session",
    "shutdown",
];

const MEDIA_PROVIDER_OPERATIONS: &[&str] = &["status", "prepare"];

/// The exact ops the custody child process reports in its own status. This
/// is not the public op list: that one is the custody surface.
pub(super) const CUSTODY_PROVIDER_OPERATIONS: &[&str] = &[
    OP_CUSTODY_STATUS,
    OP_CUSTODY_PROVISION_NODE_SHARE,
    OP_CUSTODY_RELEASE_CONTRIBUTION,
    "shutdown",
];

pub(super) const PROTECTED_CONTENT_DECRYPT_PROVIDER_OPERATIONS: &[&str] = &[
    "status",
    "prepare_recipient",
    "open_viewer_session",
    "read_viewer_media_part",
    "cancel_prepared_recipient",
    "close_viewer_session",
    "shutdown",
];

const PROVIDER_INVOCATION_SCHEMA_V1: &str = "elastos.provider.invocation/v1";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RuntimeCustodyRouteTransportConfig {
    Local,
    CarrierPeerDid { peer_did: String },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCustodyRouteBindingConfig {
    pub(crate) node_public_key_base64: String,
    pub(crate) owner_state_root_base64: String,
    pub(crate) transport: RuntimeCustodyRouteTransportConfig,
}

pub(super) struct RuntimeValidatedCustodyRouteBinding {
    owner_state_root: Digest32,
    pub(super) transport: ProviderInvocationTransport,
}

pub(super) struct RuntimeValidatedCustodyCompositionConfig {
    pub(super) expected_policy_authority: CustodyEpochIssuerKeyV1,
    expected_authorization_identity: CustodyCommitteeAuthorizationIdentityV1,
    pub(super) signed_pool: SignedCustodyPoolV1,
    signed_epoch: SignedCustodyEpochV1,
    signed_committee_authorization: SignedCustodyCommitteeAuthorizationV1,
    pub(super) routes: [RuntimeValidatedCustodyRouteBinding; 3],
}

pub(super) struct RuntimeCustodyCompositionNode {
    pub(super) node_public_key: NodePublicKey,
    pub(super) custody_public_key: NodeCustodyPublicKeyV1,
    owner_state_root: Digest32,
    pub(super) adapter: RuntimeCustodyRegistryAdapter,
}

pub(crate) struct RuntimeCustodyComposition {
    pub(super) expected_policy_authority: CustodyEpochIssuerKeyV1,
    pub(super) expected_authorization_identity: CustodyCommitteeAuthorizationIdentityV1,
    pub(super) signed_pool: SignedCustodyPoolV1,
    pub(super) signed_epoch: SignedCustodyEpochV1,
    pub(super) signed_committee_authorization: SignedCustodyCommitteeAuthorizationV1,
    pub(super) nodes: [RuntimeCustodyCompositionNode; 3],
}

impl std::fmt::Debug for RuntimeCustodyComposition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeCustodyComposition")
            .field("expected_policy_authority", &"[redacted]")
            .field("expected_authorization_identity", &"[redacted]")
            .field("signed_pool", &"[redacted]")
            .field("signed_epoch", &"[redacted]")
            .field("signed_committee_authorization", &"[redacted]")
            .field("node_count", &self.nodes.len())
            .finish()
    }
}

impl RuntimeCustodyComposition {
    pub(crate) fn configured_nodes(
        &self,
    ) -> Result<[RuntimeMintConfiguredCustodyProvider<'_>; 3], RuntimeMintCoordinatorError> {
        Ok([
            RuntimeMintConfiguredCustodyProvider::new(
                self.nodes[0].node_public_key,
                self.nodes[0].custody_public_key,
                self.nodes[0].owner_state_root,
                &self.nodes[0].adapter,
            )?,
            RuntimeMintConfiguredCustodyProvider::new(
                self.nodes[1].node_public_key,
                self.nodes[1].custody_public_key,
                self.nodes[1].owner_state_root,
                &self.nodes[1].adapter,
            )?,
            RuntimeMintConfiguredCustodyProvider::new(
                self.nodes[2].node_public_key,
                self.nodes[2].custody_public_key,
                self.nodes[2].owner_state_root,
                &self.nodes[2].adapter,
            )?,
        ])
    }
}

pub(super) struct InactiveCustodyProvider {
    bridge: Arc<ProviderBridge>,
    registry: Weak<ProviderRegistry>,
}

/// What the inactive custody wrapper is built from. A field added here leaves
/// every caller that builds it alone.
pub(super) struct InactiveCustodyProviderParts {
    pub(super) bridge: Arc<ProviderBridge>,
    pub(super) registry: Weak<ProviderRegistry>,
}

impl InactiveCustodyProvider {
    pub(super) fn new(parts: InactiveCustodyProviderParts) -> Self {
        let InactiveCustodyProviderParts { bridge, registry } = parts;
        Self { bridge, registry }
    }

    fn strip_runtime_invocation(&self, request: &Value) -> Result<Value, ProviderError> {
        let mut value = request.clone();
        let object = value
            .as_object_mut()
            .ok_or_else(|| ProviderError::Provider("custody request must be an object".into()))?;
        if object.contains_key("_runtime_transfer") {
            return Err(ProviderError::Provider(
                "custody request contains an unsupported transfer envelope".into(),
            ));
        }
        if object.contains_key("chain_data") || object.contains_key("evidence") {
            return Err(ProviderError::Provider(
                "custody request contains unsupported injected evidence".into(),
            ));
        }
        if object.contains_key("carrier") {
            return Err(ProviderError::Provider(
                "custody request contains unsupported injected carrier data".into(),
            ));
        }
        let op = object
            .get("op")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Provider("custody request is missing op".into()))?
            .to_owned();
        if matches!(
            op.as_str(),
            "evaluate_rights" | "prepare_evidence" | "settle_evidence"
        ) {
            return Err(ProviderError::Provider(
                "custody request op is private to the node-hosted wrapper".into(),
            ));
        }
        if !declared_ops(TARGET_CUSTODY).any(|declared| declared == op) {
            return Err(ProviderError::Provider(
                "custody request op is unsupported".into(),
            ));
        }
        let envelope = object.remove("_runtime_invocation").ok_or_else(|| {
            ProviderError::Provider("custody request is missing runtime envelope".into())
        })?;
        let envelope = envelope.as_object().ok_or_else(|| {
            ProviderError::Provider("custody request runtime envelope is invalid".into())
        })?;
        let transport = envelope
            .get("transport")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProviderError::Provider("custody request runtime envelope is invalid".into())
            })?;
        if !matches!(
            transport,
            "runtime-local-provider-plane" | "carrier-provider-plane"
        ) {
            return Err(ProviderError::Provider(
                "custody request runtime envelope is invalid".into(),
            ));
        }
        let carrier_is_valid = match transport {
            "runtime-local-provider-plane" => envelope.get("carrier") == Some(&Value::Null),
            "carrier-provider-plane" => envelope
                .get("carrier")
                .and_then(Value::as_object)
                .filter(|carrier| carrier.len() == 1)
                .and_then(|carrier| carrier.get("source_endpoint_did"))
                .and_then(Value::as_str)
                .and_then(|did| {
                    crate::carrier::did_to_public_key(did).and_then(|public_key| {
                        crate::carrier::public_key_to_did(&public_key)
                            .ok()
                            .filter(|canonical| canonical == did)
                    })
                })
                .is_some(),
            _ => false,
        };
        if envelope.len() != 11
            || envelope.get("schema").and_then(Value::as_str) != Some(PROVIDER_INVOCATION_SCHEMA_V1)
            || envelope.get("source").and_then(Value::as_str) != Some(RUNTIME_PROVIDER_ID)
            || envelope.get("target").and_then(Value::as_str) != Some(CUSTODY_PROVIDER_ID)
            || envelope.get("op").and_then(Value::as_str) != Some(op.as_str())
            || envelope.get("capability").and_then(Value::as_str)
                != Some(&format!(
                    "provider:{RUNTIME_PROVIDER_ID}->{CUSTODY_PROVIDER_ID}:{op}"
                ))
            || !carrier_is_valid
            || envelope.get("transfer").and_then(Value::as_str) != Some("json")
            || envelope.get("range") != Some(&Value::Null)
            || envelope.get("progress") != Some(&Value::Null)
            || envelope.get("abi")
                != Some(&json!({
                    "schema": "elastos.provider.transfer-abi/v1",
                    "transfer": "json",
                    "transport": transport,
                    "range_supported": false,
                    "progress_supported": false,
                    "progress_mode": "none",
                    "transport_native_stream": false,
                    "backpressure": "not_applicable",
                    "cancel_supported": false,
                }))
        {
            return Err(ProviderError::Provider(
                "custody request runtime envelope is invalid".into(),
            ));
        }
        Ok(value)
    }

    async fn send_private_child_request(
        &self,
        request: &PrivateCustodyRightsRequestV1,
    ) -> Result<Value, ProviderError> {
        let request = serde_json::to_value(request)
            .map_err(|_| ProviderError::Provider("custody private request is invalid".into()))?;
        self.bridge
            .send_raw(&request)
            .await
            .map_err(|error| ProviderError::Provider(error.to_string()))
    }

    fn private_ok_data(&self, response: Value) -> Result<Value, ProviderError> {
        match response.get("status").and_then(Value::as_str) {
            Some("ok") => response.get("data").cloned().ok_or_else(|| {
                ProviderError::Provider("custody private response is missing data".into())
            }),
            Some("error") => Err(ProviderError::Provider(
                "custody private request was rejected".into(),
            )),
            _ => Err(ProviderError::Provider(
                "custody private response has unsupported status".into(),
            )),
        }
    }

    fn normalize_public_status(&self, response: Value) -> Result<Value, ProviderError> {
        let data = self.private_ok_data(response)?;
        let object = data
            .as_object()
            .ok_or_else(|| ProviderError::Provider("custody status response is invalid".into()))?;
        let provider = object
            .get("provider")
            .cloned()
            .ok_or_else(|| ProviderError::Provider("custody status response is invalid".into()))?;
        let version = object
            .get("version")
            .cloned()
            .ok_or_else(|| ProviderError::Provider("custody status response is invalid".into()))?;
        let configured = object
            .get("configured")
            .cloned()
            .ok_or_else(|| ProviderError::Provider("custody status response is invalid".into()))?;
        let request_schema = object
            .get("request_schema")
            .cloned()
            .ok_or_else(|| ProviderError::Provider("custody status response is invalid".into()))?;
        let response_schema = object
            .get("response_schema")
            .cloned()
            .ok_or_else(|| ProviderError::Provider("custody status response is invalid".into()))?;
        Ok(json!({
            "status": "ok",
            "data": {
                "provider": provider,
                "version": version,
                "configured": configured,
                "supported_operations": declared_ops(TARGET_CUSTODY).collect::<Vec<_>>(),
                "request_schema": request_schema,
                "response_schema": response_schema,
            }
        }))
    }
}

impl std::fmt::Debug for InactiveCustodyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InactiveCustodyProvider")
            .field("bridge", &"<redacted>")
            .finish()
    }
}

pub(super) struct RuntimeCustodyRegistryAdapter {
    pub(super) registry: Arc<ProviderRegistry>,
    pub(super) transport: ProviderInvocationTransport,
}

impl RuntimeCustodyRegistryAdapter {
    pub(super) fn new(
        registry: Arc<ProviderRegistry>,
        transport: ProviderInvocationTransport,
    ) -> Self {
        Self {
            registry,
            transport,
        }
    }

    pub(super) async fn invoke_rights(
        &self,
        request: &RightsProviderRequestV1,
    ) -> Result<RightsProviderResponseV1, RuntimeProviderCallError> {
        let request_value = serde_json::from_slice(
            &request
                .to_json_vec()
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?,
        )
        .map_err(|_| RuntimeProviderCallError::NoExactResult)?;
        let response_value = invoke_json_provider_with_transport(
            self.registry.as_ref(),
            CUSTODY_PROVIDER_ID,
            "evaluate",
            request_value,
            self.transport.clone(),
        )
        .await
        .map_err(|_| RuntimeProviderCallError::NoExactResult)?;
        RightsProviderResponseV1::from_json_slice(
            &serde_json::to_vec(&response_value)
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?,
        )
        .map_err(|_| RuntimeProviderCallError::NoExactResult)
    }

    pub(super) async fn invoke_custody(
        &self,
        op: &'static str,
        request: &elastos_protected_content_provider_contracts::CustodyProviderRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::CustodyProviderResponseV1,
        RuntimeProviderCallError,
    > {
        let request_value = serde_json::from_slice(
            &request
                .to_json_vec()
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?,
        )
        .map_err(|_| RuntimeProviderCallError::NoExactResult)?;
        let response_value = invoke_json_provider_with_transport(
            self.registry.as_ref(),
            CUSTODY_PROVIDER_ID,
            op,
            request_value,
            self.transport.clone(),
        )
        .await
        .map_err(|_| RuntimeProviderCallError::NoExactResult)?;
        elastos_protected_content_provider_contracts::CustodyProviderResponseV1::from_json_slice(
            &serde_json::to_vec(&response_value)
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?,
        )
        .map_err(|_| RuntimeProviderCallError::NoExactResult)
    }
}

impl std::fmt::Debug for RuntimeCustodyRegistryAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeCustodyRegistryAdapter")
            .field("registry", &"<redacted>")
            .field("transport", &"<redacted>")
            .finish()
    }
}

#[async_trait::async_trait]
impl Provider for InactiveCustodyProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "inactive custody provider does not expose resources".into(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![CUSTODY_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        "inactive-custody-provider"
    }

    async fn send_raw(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, ProviderError> {
        let request = self.strip_runtime_invocation(request)?;
        if request.get("op").and_then(Value::as_str) == Some(OP_CUSTODY_STATUS) {
            let response = self
                .bridge
                .send_raw(&request)
                .await
                .map_err(|error| ProviderError::Provider(error.to_string()))?;
            return self.normalize_public_status(response);
        }
        if request.get("op").and_then(Value::as_str) == Some(OP_CUSTODY_EVALUATE) {
            let prepare = PrivateCustodyRightsRequestV1::new_prepare(request.clone());
            let prepare_response = self.send_private_child_request(&prepare).await?;
            let chain_request = self.private_ok_data(prepare_response)?;
            let registry = self.registry.upgrade().ok_or_else(|| {
                ProviderError::Provider("node-local custody registry is unavailable".into())
            })?;
            let chain_data = invoke_json_provider_with_transport(
                registry.as_ref(),
                CHAIN_PROVIDER_ID,
                CHAIN_RIGHTS_EVIDENCE_OP,
                chain_request,
                ProviderInvocationTransport::Local,
            )
            .await
            .map_err(ProviderError::Provider)?;
            let settle = PrivateCustodyRightsRequestV1::new_settle(request, chain_data);
            return self.send_private_child_request(&settle).await;
        }
        self.bridge
            .send_raw(&request)
            .await
            .map_err(|error| ProviderError::Provider(error.to_string()))
    }

    async fn shutdown(&self) -> Result<(), ProviderError> {
        self.bridge
            .shutdown()
            .await
            .map_err(|error| ProviderError::Provider(error.to_string()))
    }
}

pub async fn register_inactive_custody_provider(
    registry: &Arc<ProviderRegistry>,
    binary_path: &Path,
    data_dir: &Path,
) -> anyhow::Result<()> {
    let state_root = inactive_custody_state_root(data_dir);
    validate_inactive_custody_state_root(&state_root)?;
    let base_path = state_root
        .to_str()
        .ok_or_else(|| {
            invalid_inactive_custody_config("inactive custody provider root must be valid UTF-8")
        })?
        .to_owned();
    let bridge_config = ProviderConfig {
        base_path,
        ..Default::default()
    };
    let bridge = Arc::new(
        elastos_runtime::provider::ProviderBridge::spawn(binary_path, bridge_config)
            .await
            .map_err(|error| {
                anyhow::anyhow!("failed to spawn inactive custody provider: {error}")
            })?,
    );
    let startup = async {
        let status =
            request_protected_provider_startup_status(&bridge, "inactive custody provider").await?;
        require_inactive_custody_provider_status(&status)?;
        let provider: Arc<dyn Provider> =
            Arc::new(InactiveCustodyProvider::new(InactiveCustodyProviderParts {
                bridge: bridge.clone(),
                registry: Arc::downgrade(registry),
            }));
        register_inactive_custody_runtime_provider_target(registry, provider)
            .await
            .map_err(|error| anyhow::anyhow!("failed to register inactive custody route: {error}"))
    }
    .await;
    settle_protected_provider_startup(&bridge, startup, "inactive custody provider").await
}

pub async fn register_protect_provider(
    registry: &Arc<ProviderRegistry>,
    binary_path: &Path,
) -> anyhow::Result<()> {
    let bridge = Arc::new(
        elastos_runtime::provider::ProviderBridge::spawn(
            binary_path,
            ProviderConfig {
                extra: json!({}),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| anyhow::anyhow!("failed to spawn protect provider: {error}"))?,
    );
    let startup = async {
        let status = request_protected_provider_startup_status(&bridge, "protect provider").await?;
        require_protect_provider_status(&status)?;
        let provider: Arc<dyn Provider> =
            Arc::new(elastos_runtime::provider::CapsuleProvider::with_scheme(
                bridge.clone(),
                PROTECT_PROVIDER_ID,
            ));
        registry
            .register_runtime_provider_target(PROTECT_PROVIDER_ID, provider)
            .await
            .map_err(|error| anyhow::anyhow!("failed to register protect provider: {error}"))
    }
    .await;
    settle_protected_provider_startup(&bridge, startup, "protect provider").await
}

pub async fn register_protected_content_decrypt_provider(
    registry: &Arc<ProviderRegistry>,
    binary_path: &Path,
    runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
) -> anyhow::Result<()> {
    let bridge = Arc::new(
        ProviderBridge::spawn(
            binary_path,
            ProviderConfig {
                extra: json!({
                    "trusted_runtime_issuer": format!(
                        "0x{}",
                        hex::encode(runtime_operation_issuer.as_bytes())
                    ),
                }),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| {
            anyhow::anyhow!("failed to spawn protected-content decrypt provider: {error}")
        })?,
    );
    let startup = async {
        let status = request_protected_provider_startup_status(
            &bridge,
            "protected-content decrypt provider",
        )
        .await?;
        require_protected_content_decrypt_provider_status(&status)?;
        let provider: Arc<dyn Provider> =
            Arc::new(elastos_runtime::provider::CapsuleProvider::with_scheme(
                bridge.clone(),
                PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            ));
        registry
            .register_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID, provider)
            .await
            .map_err(|error| {
                anyhow::anyhow!("failed to register protected-content decrypt provider: {error}")
            })
    }
    .await;
    settle_protected_provider_startup(&bridge, startup, "protected-content decrypt provider").await
}

async fn request_protected_provider_startup_status(
    bridge: &ProviderBridge,
    label: &str,
) -> anyhow::Result<Value> {
    tokio::time::timeout(
        PROTECTED_CONTENT_PROVIDER_STATUS_TIMEOUT,
        bridge.send_raw(&json!({"op":"status"})),
    )
    .await
    .map_err(|_| anyhow::anyhow!("{label} status timed out"))?
    .map_err(|error| anyhow::anyhow!("{label} status failed: {error}"))
}

async fn settle_protected_provider_startup(
    bridge: &ProviderBridge,
    startup: anyhow::Result<()>,
    label: &str,
) -> anyhow::Result<()> {
    let Err(startup_error) = startup else {
        return Ok(());
    };
    if let Err(shutdown_error) = bridge.shutdown().await {
        return Err(anyhow::anyhow!(
            "{startup_error}; {label} shutdown/reap also failed: {shutdown_error}"
        ));
    }
    Err(startup_error)
}

pub(super) fn require_protect_provider_status(status: &Value) -> anyhow::Result<()> {
    let data = require_exact_provider_status_data(
        status,
        "protect provider",
        &[
            "provider",
            "version",
            "configured",
            "supported_operations",
            "request_schema",
            "response_schema",
        ],
    )?;
    if data.get("provider").and_then(Value::as_str) != Some(PROTECT_PROVIDER_PROCESS_ID) {
        anyhow::bail!("protect provider status has an unsupported identity");
    }
    if data.get("configured").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("protect provider is not configured");
    }
    if data.get("request_schema").and_then(Value::as_str)
        != Some(PROTECT_PROVIDER_REQUEST_SCHEMA_V1)
        || data.get("response_schema").and_then(Value::as_str)
            != Some(PROTECT_PROVIDER_RESPONSE_SCHEMA_V1)
    {
        anyhow::bail!("protect provider status has unsupported protocol schemas");
    }
    require_exact_provider_operations(data, PROTECT_PROVIDER_OPERATIONS, "protect provider")
}

pub fn require_media_provider_status(status: &Value) -> anyhow::Result<()> {
    let data = require_exact_provider_status_data(
        status,
        "media-provider",
        &[
            "provider",
            "protocol_version",
            "version",
            "configured",
            "supported_operations",
        ],
    )?;
    if data.get("provider").and_then(Value::as_str) != Some(MEDIA_PROVIDER_PROCESS_ID) {
        anyhow::bail!("media-provider status has an unsupported provider identity");
    }
    if data.get("protocol_version").and_then(Value::as_str) != Some(MEDIA_PROVIDER_PROTOCOL_VERSION)
    {
        anyhow::bail!("media-provider status has an unsupported protocol version");
    }
    if data.get("configured").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("media-provider is not configured");
    }
    require_exact_provider_operations(data, MEDIA_PROVIDER_OPERATIONS, "media-provider")
}

pub(super) fn require_inactive_custody_provider_status(status: &Value) -> anyhow::Result<()> {
    let data = require_exact_provider_status_data(
        status,
        "inactive custody provider",
        &[
            "provider",
            "version",
            "configured",
            "supported_operations",
            "request_schema",
            "response_schema",
        ],
    )?;
    if data.get("provider").and_then(Value::as_str) != Some(CUSTODY_PROVIDER_ID) {
        anyhow::bail!("inactive custody provider status has an unsupported identity");
    }
    if data.get("configured").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("inactive custody provider is not configured");
    }
    if data.get("request_schema").and_then(Value::as_str)
        != Some(CUSTODY_PROVIDER_REQUEST_SCHEMA_V1)
        || data.get("response_schema").and_then(Value::as_str)
            != Some(CUSTODY_PROVIDER_RESPONSE_SCHEMA_V1)
    {
        anyhow::bail!("inactive custody provider status has unsupported protocol schemas");
    }
    require_exact_provider_operations(
        data,
        CUSTODY_PROVIDER_OPERATIONS,
        "inactive custody provider",
    )
}

pub(super) fn require_protected_content_decrypt_provider_status(
    status: &Value,
) -> anyhow::Result<()> {
    let data = require_exact_provider_status_data(
        status,
        "protected-content decrypt provider",
        &[
            "provider",
            "version",
            "configured",
            "supported_operations",
            "request_schema",
            "response_schema",
        ],
    )?;
    if data.get("provider").and_then(Value::as_str) != Some(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID) {
        anyhow::bail!("protected-content decrypt provider status has an unsupported identity");
    }
    if data.get("configured").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("protected-content decrypt provider is not configured");
    }
    if data.get("request_schema").and_then(Value::as_str)
        != Some(DECRYPT_PROVIDER_REQUEST_SCHEMA_V1)
        || data.get("response_schema").and_then(Value::as_str)
            != Some(DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1)
    {
        anyhow::bail!("protected-content decrypt provider status has unsupported protocol schemas");
    }
    require_exact_provider_operations(
        data,
        PROTECTED_CONTENT_DECRYPT_PROVIDER_OPERATIONS,
        "protected-content decrypt provider",
    )
}

fn require_exact_provider_status_data<'a>(
    status: &'a Value,
    label: &str,
    expected_fields: &[&str],
) -> anyhow::Result<&'a serde_json::Map<String, Value>> {
    let status_object = status
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("{label} status is invalid"))?;
    if status_object.len() != 2
        || !status_object.contains_key("status")
        || !status_object.contains_key("data")
        || status.get("status").and_then(Value::as_str) != Some("ok")
    {
        anyhow::bail!("{label} status did not succeed");
    }
    let data = status
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("{label} status is missing data"))?;
    if data.len() != expected_fields.len()
        || expected_fields
            .iter()
            .any(|field| !data.contains_key(*field))
    {
        anyhow::bail!("{label} status has an unsupported shape");
    }
    // Release versions identify builds; protocol versions and schemas define compatibility.
    if data
        .get("version")
        .and_then(Value::as_str)
        .and_then(|version| semver::Version::parse(version).ok())
        .is_none()
    {
        anyhow::bail!("{label} status has an invalid release version");
    }
    Ok(data)
}

fn require_exact_provider_operations(
    data: &serde_json::Map<String, Value>,
    expected: &[&str],
    label: &str,
) -> anyhow::Result<()> {
    let supported_operations = data
        .get("supported_operations")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("{label} status is missing supported operations"))?;
    if supported_operations.len() != expected.len()
        || supported_operations
            .iter()
            .zip(expected)
            .any(|(actual, expected)| actual.as_str() != Some(*expected))
    {
        anyhow::bail!("{label} status has unsupported operations");
    }
    Ok(())
}

pub(super) async fn register_inactive_custody_runtime_provider_target(
    registry: &ProviderRegistry,
    provider: Arc<dyn Provider>,
) -> Result<(), ProviderError> {
    registry
        .register_runtime_provider_target(CUSTODY_PROVIDER_ID, provider)
        .await
}

/// The provisioned state root an inactive custody provider is hosted from.
///
/// `elastos protected-content-config provision-custody-node` creates it; a
/// custody host reads it to fail closed before spawning anything.
pub fn inactive_custody_state_root(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(INACTIVE_CUSTODY_ROOT)
}

pub(crate) fn runtime_custody_composition_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CUSTODY_COMPOSITION_CONFIG_FILE)
}

fn validate_inactive_custody_state_root(root: &Path) -> anyhow::Result<()> {
    validate_owner_only_directory(root, "inactive custody provider root")
}

fn validate_owner_only_protected_content_dir(data_dir: &Path) -> anyhow::Result<PathBuf> {
    validate_owner_only_protected_content_dir_with_error(
        data_dir,
        invalid_custody_composition_config,
    )
}

#[cfg(unix)]
fn read_owner_only_config_bytes(path: &Path, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
    read_owner_only_protected_content_config_bytes(
        path,
        max_bytes,
        "custody-composition file",
        invalid_custody_composition_config,
    )
}

#[cfg(not(unix))]
fn read_owner_only_config_bytes(path: &Path, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
    let _ = (path, max_bytes);
    anyhow::bail!("owner-only protected-content config validation is unsupported on this platform")
}

fn canonical_custody_composition_config_bytes(
    config: &RuntimeCustodyCompositionConfigFile,
) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::to_value(config)?)?)
}

fn decode_canonical_contract_base64<T: CanonicalContract>(
    encoded: &str,
    max_decoded_bytes: usize,
    field: &str,
) -> anyhow::Result<T> {
    let bytes = decode_canonical_base64_bytes(encoded, max_decoded_bytes, field)?;
    T::from_canonical_bytes(&bytes).map_err(|error| {
        invalid_custody_composition_config(format!("{field} canonical bytes are invalid: {error}"))
    })
}

fn decode_digest32_base64(encoded: &str, field: &str) -> anyhow::Result<Digest32> {
    let bytes = decode_canonical_base64_bytes(encoded, 32, field)?;
    let digest: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid_custody_composition_config(format!("{field} must be 32 bytes")))?;
    Ok(Digest32::new(digest))
}

fn decode_custody_epoch_issuer_base64(
    encoded: &str,
    field: &str,
) -> anyhow::Result<CustodyEpochIssuerKeyV1> {
    let bytes = decode_canonical_base64_bytes(encoded, 32, field)?;
    let issuer: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid_custody_composition_config(format!("{field} must be 32 bytes")))?;
    CustodyEpochIssuerKeyV1::new(issuer).map_err(|error| {
        invalid_custody_composition_config(format!("{field} bytes are invalid: {error}"))
    })
}

fn decode_node_public_key_base64(encoded: &str, field: &str) -> anyhow::Result<NodePublicKey> {
    let bytes = decode_canonical_base64_bytes(encoded, 32, field)?;
    let public_key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid_custody_composition_config(format!("{field} must be 32 bytes")))?;
    NodePublicKey::new(public_key).map_err(|error| {
        invalid_custody_composition_config(format!("{field} bytes are invalid: {error}"))
    })
}

pub(crate) fn decode_canonical_peer_did(peer_did: &str) -> anyhow::Result<String> {
    if peer_did.is_empty() || peer_did.len() > MAX_CUSTODY_COMPOSITION_PEER_DID_BYTES {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config("carrier peer DID is out of bounds")
        );
    }
    let verifying_key = crate::crypto::decode_did_key(peer_did).map_err(|_| {
        invalid_custody_composition_config("carrier peer DID is not a valid canonical did:key")
    })?;
    let canonical = crate::crypto::encode_did_key(&verifying_key).map_err(|_| {
        invalid_custody_composition_config("carrier peer DID cannot be canonicalized")
    })?;
    if canonical != peer_did {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config("carrier peer DID is not canonical")
        );
    }
    Ok(canonical)
}

pub(super) fn load_runtime_custody_composition_config(
    data_dir: &Path,
) -> anyhow::Result<Option<RuntimeValidatedCustodyCompositionConfig>> {
    let config_path = runtime_custody_composition_config_path(data_dir);
    match fs::symlink_metadata(&config_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            anyhow::bail!(
                "{}",
                invalid_custody_composition_config("custody-composition file is unavailable")
            )
        }
    }
    let _protected_root = validate_owner_only_protected_content_dir(data_dir)?;
    let bytes = read_owner_only_config_bytes(&config_path, MAX_CUSTODY_COMPOSITION_BYTES)?;
    let config: RuntimeCustodyCompositionConfigFile =
        serde_json::from_slice(&bytes).map_err(|_| {
            invalid_custody_composition_config(
                "custody-composition file is not valid canonical JSON",
            )
        })?;
    if config.schema != CUSTODY_COMPOSITION_SCHEMA_V1
        || canonical_custody_composition_config_bytes(&config)? != bytes
    {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config("custody-composition file is not canonical")
        );
    }

    let expected_policy_authority = decode_custody_epoch_issuer_base64(
        &config.expected_policy_authority_base64,
        "expected_policy_authority",
    )?;
    let expected_authorization_identity = decode_canonical_contract_base64(
        &config.expected_committee_authorization_identity_base64,
        MAX_CUSTODY_COMPOSITION_BLOB_BYTES,
        "expected_committee_authorization_identity",
    )?;
    let signed_pool = decode_canonical_contract_base64(
        &config.signed_pool_base64,
        MAX_CUSTODY_COMPOSITION_BLOB_BYTES,
        "signed_pool",
    )?;
    let signed_epoch = decode_canonical_contract_base64(
        &config.signed_epoch_base64,
        MAX_CUSTODY_COMPOSITION_BLOB_BYTES,
        "signed_epoch",
    )?;
    let signed_committee_authorization = decode_canonical_contract_base64(
        &config.signed_committee_authorization_base64,
        MAX_CUSTODY_COMPOSITION_BLOB_BYTES,
        "signed_committee_authorization",
    )?;

    let now = crate::auth::now_ts();
    let validated = validate_custody_epoch_against_pool_at(
        expected_policy_authority,
        expected_authorization_identity,
        &signed_pool,
        &signed_epoch,
        &signed_committee_authorization,
        now,
    )
    .map_err(|_| {
        invalid_custody_composition_config(
            "signed pool/epoch/committee authorization does not validate against trust anchors",
        )
    })?;
    let committee_nodes = validated.committee().nodes();
    if committee_nodes.len() != 3 || config.routes.len() != 3 {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config(
                "custody-composition routes must cover exactly three selected nodes"
            )
        );
    }

    let mut configured_node_keys = std::collections::BTreeSet::new();
    let mut configured_roots = std::collections::BTreeSet::new();
    let mut configured_peer_dids = std::collections::BTreeSet::new();
    let mut local_count = 0usize;
    let mut route_bindings =
        std::collections::BTreeMap::<NodePublicKey, (Digest32, ProviderInvocationTransport)>::new();

    for route in &config.routes {
        let node_public_key =
            decode_node_public_key_base64(&route.node_public_key_base64, "route.node_public_key")?;
        let owner_state_root =
            decode_digest32_base64(&route.owner_state_root_base64, "route.owner_state_root")?;
        if owner_state_root == Digest32::new([0; 32])
            || !configured_node_keys.insert(node_public_key)
            || !configured_roots.insert(owner_state_root)
        {
            anyhow::bail!(
                "{}",
                invalid_custody_composition_config(
                    "custody-composition routes are duplicated or invalid"
                )
            );
        }
        let transport = match &route.transport {
            RuntimeCustodyRouteTransportConfig::Local => {
                local_count += 1;
                ProviderInvocationTransport::Local
            }
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid { peer_did } => {
                let canonical_peer_did = decode_canonical_peer_did(peer_did)?;
                if !configured_peer_dids.insert(canonical_peer_did.clone()) {
                    anyhow::bail!(
                        "{}",
                        invalid_custody_composition_config("carrier peer DIDs must be distinct")
                    );
                }
                ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                    peer_did: canonical_peer_did,
                    timeout_ms: None,
                    reply_wait_ms: None,
                })
            }
        };
        route_bindings.insert(node_public_key, (owner_state_root, transport));
    }

    if local_count > 1 {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config("at most one local custody route is allowed")
        );
    }

    let routes = committee_nodes
        .iter()
        .map(|node| {
            let (owner_state_root, transport) = route_bindings
                .remove(&node.node_public_key())
                .ok_or_else(|| {
                    invalid_custody_composition_config(
                        "custody-composition routes do not exactly cover the signed node set",
                    )
                })?;
            Ok(RuntimeValidatedCustodyRouteBinding {
                owner_state_root,
                transport,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if !route_bindings.is_empty() {
        anyhow::bail!(
            "{}",
            invalid_custody_composition_config(
                "custody-composition routes do not exactly cover the signed node set",
            )
        );
    }

    Ok(Some(RuntimeValidatedCustodyCompositionConfig {
        expected_policy_authority,
        expected_authorization_identity,
        signed_pool,
        signed_epoch,
        signed_committee_authorization,
        routes: routes.try_into().map_err(|_| {
            invalid_custody_composition_config(
                "custody-composition routes must cover exactly three selected nodes",
            )
        })?,
    }))
}

pub(crate) fn load_runtime_custody_composition(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
) -> anyhow::Result<Option<RuntimeCustodyComposition>> {
    let Some(config) = load_runtime_custody_composition_config(data_dir)? else {
        return Ok(None);
    };
    let now = crate::auth::now_ts();
    let validated = validate_custody_epoch_against_pool_at(
        config.expected_policy_authority,
        config.expected_authorization_identity,
        &config.signed_pool,
        &config.signed_epoch,
        &config.signed_committee_authorization,
        now,
    )
    .map_err(|_| {
        invalid_custody_composition_config(
            "signed pool/epoch/committee authorization does not validate against trust anchors",
        )
    })?;
    let nodes = validated
        .committee()
        .nodes()
        .iter()
        .zip(config.routes.iter())
        .map(|(node, route)| RuntimeCustodyCompositionNode {
            node_public_key: node.node_public_key(),
            custody_public_key: node.custody_public_key(),
            owner_state_root: route.owner_state_root,
            adapter: RuntimeCustodyRegistryAdapter::new(registry.clone(), route.transport.clone()),
        })
        .collect::<Vec<_>>();

    let composition = RuntimeCustodyComposition {
        expected_policy_authority: config.expected_policy_authority,
        expected_authorization_identity: config.expected_authorization_identity,
        signed_pool: config.signed_pool,
        signed_epoch: config.signed_epoch,
        signed_committee_authorization: config.signed_committee_authorization,
        nodes: nodes.try_into().map_err(|_| {
            invalid_custody_composition_config(
                "custody-composition routes must cover exactly three selected nodes",
            )
        })?,
    };
    let configured = composition
        .configured_nodes()
        .map_err(|_| invalid_custody_composition_config("configured custody linkage is invalid"))?;
    resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        now,
        &configured,
    )
    .map_err(|_| invalid_custody_composition_config("configured custody linkage is invalid"))?;
    Ok(Some(composition))
}

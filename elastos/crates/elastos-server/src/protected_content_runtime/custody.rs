use super::*;

pub(crate) const CUSTODY_PROVIDER_ID: &str = crate::custody_surface::TARGET_CUSTODY;

pub(crate) const CUSTODY_COMPOSITION_SCHEMA_V1: &str =
    "elastos.protected-content.custody-composition/v1";

const MAX_CUSTODY_COMPOSITION_BYTES: usize = 64 * 1024;

pub(crate) const MAX_CUSTODY_COMPOSITION_BLOB_BYTES: usize = 16 * 1024;

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
    "open_object_protection_session",
    "protect_object_chunk",
    "finalize_object_protection_session",
    "shutdown",
];

const MEDIA_PROVIDER_OPERATIONS: &[&str] = &["status", "prepare"];

pub(super) const CUSTODY_PROVIDER_OPERATIONS: &[&str] = &[
    OP_CUSTODY_STATUS,
    OP_CUSTODY_PROVISION_NODE_SHARE,
    OP_CUSTODY_RELEASE_CONTRIBUTION,
    OP_CUSTODY_RELEASE_POOL_CONTRIBUTION,
    OP_CUSTODY_SIGN_POOL_STATEMENT,
    OP_CUSTODY_PROVISION_POOL_NODE_SHARE,
    "shutdown",
];

pub(super) const PROTECTED_CONTENT_DECRYPT_PROVIDER_OPERATIONS: &[&str] = &[
    "status",
    "prepare_recipient",
    "open_viewer_session",
    "read_viewer_media_part",
    "cancel_prepared_recipient",
    "close_viewer_session",
    "read_viewer_object_chunk",
    "prepare_recipient_v2",
    "open_viewer_session_v2",
    "read_viewer_media_part_sealed",
    "read_viewer_object_chunk_sealed",
    "shutdown",
];

/// The folder that holds every custody root (Plan B T2.1).
const CUSTODY_PROVIDER_STATE_DIR: &str = "protected-content/custody-provider";

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
    bytes: Vec<u8>,
    pub(super) expected_policy_authority: CustodyEpochIssuerKeyV1,
    expected_authorization_identity: CustodyCommitteeAuthorizationIdentityV1,
    pub(super) signed_pool: SignedCustodyPoolV1,
    signed_epoch: SignedCustodyEpochV1,
    signed_committee_authorization: SignedCustodyCommitteeAuthorizationV1,
    pub(super) routes: [RuntimeValidatedCustodyRouteBinding; 3],
}

/// Where a custody node's own words go when a call to it fails.
///
/// The coordinator classifies a failure only by whether the node can have
/// acted -- a safety decision that deliberately carries no text, since a
/// reason must never widen what the Runtime is willing to assume. But a person
/// whose read just failed still needs to know why, and the node did say why.
/// That sentence is collected here so it can be reported with the refusal
/// instead of reaching the log alone.
///
/// Diagnostic only. Nothing reads this to decide anything; it is the shared
/// buffer for one composition's calls, and the text in it comes from a remote
/// peer, so it is bounded in both count and length and is never parsed.
#[derive(Clone, Default)]
pub(crate) struct RuntimeCustodyCallDiagnostics(Arc<std::sync::Mutex<Vec<String>>>);

/// Enough to hear from all three nodes on both the rights and the contribution
/// call, and no more: this is a hint, not a transcript.
const RUNTIME_CUSTODY_CALL_DIAGNOSTICS_MAX: usize = 6;

/// One line's worth of a peer's explanation.
const RUNTIME_CUSTODY_CALL_DETAIL_MAX_CHARS: usize = 300;

impl RuntimeCustodyCallDiagnostics {
    pub(super) fn record(&self, op: &str, detail: &str) {
        let Ok(mut recorded) = self.0.lock() else {
            return;
        };
        if recorded.len() >= RUNTIME_CUSTODY_CALL_DIAGNOSTICS_MAX {
            return;
        }
        let detail = detail.trim();
        let detail: String = detail
            .chars()
            .take(RUNTIME_CUSTODY_CALL_DETAIL_MAX_CHARS)
            .collect();
        let line = format!("{op}: {detail}");
        // Three nodes refusing for one reason is one fact, not three.
        if recorded.iter().any(|existing| existing == &line) {
            return;
        }
        recorded.push(line);
    }

    /// What the nodes said, for reporting alongside a refusal.
    pub(crate) fn recorded(&self) -> Vec<String> {
        self.0
            .lock()
            .map(|recorded| recorded.clone())
            .unwrap_or_default()
    }
}

pub(super) struct RuntimeCustodyCompositionNode {
    pub(super) node_public_key: NodePublicKey,
    pub(super) custody_public_key: NodeCustodyPublicKeyV1,
    pub(super) owner_state_root: Digest32,
    pub(super) adapter: RuntimeCustodyRegistryAdapter,
}

pub(crate) struct RuntimeCustodyComposition {
    pub(super) expected_policy_authority: CustodyEpochIssuerKeyV1,
    pub(super) expected_authorization_identity: CustodyCommitteeAuthorizationIdentityV1,
    pub(super) signed_pool: SignedCustodyPoolV1,
    pub(super) signed_epoch: SignedCustodyEpochV1,
    pub(super) signed_committee_authorization: SignedCustodyCommitteeAuthorizationV1,
    pub(super) nodes: [RuntimeCustodyCompositionNode; 3],
    /// Shared by all three node adapters, so one refusal is reportable no
    /// matter which node gave it.
    pub(super) diagnostics: RuntimeCustodyCallDiagnostics,
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
    /// The signed pool this loader validated: member terms for reading the
    /// installed pool.
    pub(crate) fn signed_pool(&self) -> &SignedCustodyPoolV1 {
        &self.signed_pool
    }

    /// The signed epoch this loader validated: threshold and share numbers.
    pub(crate) fn signed_epoch(&self) -> &SignedCustodyEpochV1 {
        &self.signed_epoch
    }

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

/// MC-F6: the root a pool share is written to, and the Home that minted it.
struct AcceptedPoolShare {
    root_dir: PathBuf,
    minter: RuntimeOperationIssuerKeyV1,
}

/// MC-F6 (M0R1-F3, M0R2-F1): a stored pool share admits its minting Home for
/// the copy handoff, settled inside the share write. The answer is the
/// share write's own, always: the share is stored whatever this record does,
/// and the minting Home's coordinator treats any other answer as an effect
/// it cannot account for and abandons the item. A record that did not
/// settle is settled again from the stored shares by the delivery pass
/// ([`crate::custody_consent::reconcile_minter_copy_admissions`]).
fn settle_pool_share_admission(
    data_dir: &Path,
    accepted: &AcceptedPoolShare,
    response: Value,
) -> Value {
    if response.get("status").and_then(Value::as_str) == Some("ok") {
        if let Err(error) = crate::custody_consent::settle_accepted_pool_share(
            data_dir,
            &accepted.root_dir,
            accepted.minter,
        ) {
            crate::custody_consent::note_minter_settlement_failed();
            tracing::warn!(
                error = %format!("{error:#}"),
                "a stored pool share's copy admission was not recorded; the delivery pass settles it from the store"
            );
        }
    }
    response
}

pub(super) struct InactiveCustodyProvider {
    bridge: Arc<ProviderBridge>,
    registry: Weak<ProviderRegistry>,
    limiter: CustodyReleaseLimiter,
    /// #388 A1: the host trust setting captured at this process's start.
    host_trusted: bool,
    /// Plan B S7-lite (S7L-F2): this Home's records of which pool each root
    /// holds.
    data_dir: PathBuf,
}

/// What the inactive custody wrapper is built from. A field added here leaves
/// every caller that builds it alone.
pub(super) struct InactiveCustodyProviderParts {
    pub(super) bridge: Arc<ProviderBridge>,
    pub(super) registry: Weak<ProviderRegistry>,
    pub(super) host_trusted: bool,
    pub(super) data_dir: PathBuf,
}

impl InactiveCustodyProvider {
    pub(super) fn new(parts: InactiveCustodyProviderParts) -> Self {
        let InactiveCustodyProviderParts {
            bridge,
            registry,
            host_trusted,
            data_dir,
        } = parts;
        Self {
            bridge,
            registry,
            limiter: CustodyReleaseLimiter::new(CUSTODY_NODE_SETTINGS),
            host_trusted,
            data_dir,
        }
    }

    /// Plan B POOL-MINT: a pool provisioning request reaches the node only
    /// when its pool is one this Home's records bind to the root holding the
    /// request's node, by a descriptor not older than the one kept
    /// (otherwise `provisioning_refused`). Admitted, it returns whether that
    /// root already holds the request's (minting Home, KID) slot (PM-F4),
    /// read when the host-wide share lock is held.
    fn admit_pool_share(
        &self,
        request: &Value,
    ) -> Result<(impl FnOnce() -> bool + Send + 'static, AcceptedPoolShare), Value> {
        let refused = |code: &str| {
            json!({
                "status": "error",
                "code": code,
                "message": "this node does not hold that pool",
            })
        };
        let parsed = serde_json::to_vec(request)
            .ok()
            .and_then(|bytes| {
                elastos_protected_content_provider_contracts::PoolCustodyRequestV1::from_json_slice(
                    &bytes,
                )
                .ok()
            })
            .and_then(|request| {
                let (descriptor, node) = request.provision_pool().ok()?;
                let (_, _, mint_share) = request.provision_contents().ok()?;
                Some((descriptor, node, mint_share))
            });
        let Some((descriptor, node, mint_share)) = parsed else {
            return Err(refused("invalid_request"));
        };
        let root_dir =
            crate::custody_pool_descriptor::admit_pool_provision(&self.data_dir, &descriptor, node)
                .map_err(|reason| {
                    tracing::debug!(
                        reason,
                        "pool provisioning refused: not this Home's pool root"
                    );
                    refused("provisioning_refused")
                })?;
        let statement = mint_share.statement().clone();
        let accepted = AcceptedPoolShare {
            root_dir: root_dir.clone(),
            minter: statement.minter_runtime_issuer(),
        };
        Ok((
            move || {
                elastos_protected_content_custody::NodeLocalShareStoreV1::new(
                    node,
                    custody_provider::node_share_store_dir(&root_dir),
                )
                .pool_slot_held(
                    statement.minter_runtime_issuer(),
                    statement.content_access_id(),
                )
                // An unreadable slot is charged as a new one.
                .unwrap_or(false)
            },
            accepted,
        ))
    }

    async fn write_remote_pool_share(
        &self,
        request: Value,
        source: RuntimeInvocationSource,
    ) -> Result<Value, ProviderError> {
        let refuse = |code| {
            json!({
                "status": "error",
                "code": code,
                "message": "remote custody share was refused",
            })
        };
        let Ok(RemoteShareDeliveryV1::ProvisionPoolNodeShare {
            remote_seal_request,
        }) = serde_json::from_value(request)
        else {
            return Ok(refuse("invalid_request"));
        };
        let Ok(frame) = serde_json::to_vec(&remote_seal_request) else {
            return Ok(refuse("invalid_request"));
        };
        let Ok(parsed) = RemoteShareProvisionRequestV1::from_json_slice(&frame) else {
            return Ok(refuse("invalid_request"));
        };
        let data_dir = self.data_dir.clone();
        let bridge = Arc::clone(&self.bridge);
        let write = async move {
            // Stop and rollover take this same lock before the host storage
            // lock. Keep it through the detached write and its settlement.
            let _custody = crate::custody_consent::lock_custody_writes().await;
            let descriptor = &parsed.admission.descriptor;
            let now = crate::auth::now_ts();
            let Ok((authorization, minter)) =
                parsed.admission.authorization.verify_for_mint_request(
                    descriptor,
                    &parsed.admission.request,
                    parsed.record.key_envelope_identity(),
                    now,
                )
            else {
                return Ok(refuse("provisioning_refused"));
            };
            let endpoint = match source {
                RuntimeInvocationSource::Local => elastos_identity::load_existing_did(&data_dir)
                    .ok()
                    .map(|(_, did)| did),
                RuntimeInvocationSource::Carrier {
                    source_endpoint_did,
                } => Some(source_endpoint_did),
            };
            let source_matches = endpoint.as_deref().is_some_and(|endpoint| {
                descriptor.member_peer_did(authorization.sealer_node_public_key) == Some(endpoint)
                    && crate::crypto::decode_did_key(endpoint).is_ok_and(|key| {
                        key.as_bytes() == authorization.sealer_runtime_issuer.as_bytes()
                    })
            });
            if !source_matches {
                return Ok(refuse("provisioning_refused"));
            }
            let node = parsed.record.selected_node_public_key();
            let Ok(root_dir) =
                crate::custody_pool_descriptor::admit_pool_provision(&data_dir, descriptor, node)
            else {
                return Ok(refuse("provisioning_refused"));
            };
            let accepted = AcceptedPoolShare { root_dir, minter };
            let store = elastos_protected_content_custody::NodeLocalShareStoreV1::new(
                node,
                custody_provider::node_share_store_dir(&accepted.root_dir),
            );
            let access_id = authorization.content_access_id;
            let command =
                serde_json::to_value(ProvisionRemoteShareCommandV1::ProvisionRemoteShare {
                    pool_authority: *authorization.pool.issuer().as_bytes(),
                    request: remote_seal_request,
                })
                .map_err(|_| {
                    ProviderError::Provider("remote custody share request is invalid".into())
                })?;
            let incoming =
                serde_json::to_vec(&command).map_or(u64::MAX, |bytes| bytes.len() as u64);
            let settlement_dir = data_dir.clone();
            guarded_host_share_write(
                data_dir,
                incoming,
                move || store.pool_slot_held(minter, access_id).unwrap_or(false),
                move || async move {
                    bridge
                        .send_raw(&command)
                        .await
                        .map(|response| {
                            settle_pool_share_admission(&settlement_dir, &accepted, response)
                        })
                        .map_err(|error| ProviderError::Provider(error.to_string()))
                },
            )
            .await
        };
        let task = match elastos_runtime::provider::dispatch::DispatchFence::current() {
            Some(fence) => tokio::spawn(async move { fence.scope(write).await }),
            None => tokio::spawn(write),
        };
        task.await.map_err(|error| {
            ProviderError::Provider(format!("remote custody share did not finish: {error}"))
        })?
    }

    /// Plan B POOL-MINT (PM-F2): whether the root holding a V1 share
    /// request's node already holds its key envelope's V1 slot, read when the
    /// host-wide share lock is held. A record that cannot be read, a node no
    /// root holds and an unreadable slot are charged as a new slot; the
    /// provider validates the request.
    fn v1_share_slot_held(&self, request: &Value) -> impl FnOnce() -> bool + Send + 'static {
        let record = serde_json::to_vec(request).ok().and_then(|bytes| {
            elastos_protected_content_provider_contracts::CustodyProviderRequestV1::peek_custody_node_provisioning_record(&bytes)
                .ok()
        });
        let data_dir = self.data_dir.clone();
        move || {
            let Some(record) = record else {
                return false;
            };
            let node = record.selected_node_public_key();
            custody_provider_root_paths(&data_dir)
                .unwrap_or_default()
                .iter()
                .map(|root| custody_root_dir(&data_dir, root))
                .find(|root| {
                    custody_provider::load_node_public_key(root).is_ok_and(|key| key == node)
                })
                .is_some_and(|root| {
                    elastos_protected_content_custody::NodeLocalShareStoreV1::new(
                        node,
                        custody_provider::node_share_store_dir(&root),
                    )
                    .v1_slot_held(record.key_envelope_identity())
                    .unwrap_or(false)
                })
        }
    }

    /// Plan B POOL-MINT (PM-F2): a share write, V1 or pool, through the one
    /// owned guarded write. The host's storage maximum decides, whichever
    /// Home mints; the request frame bounds what is stored.
    async fn write_host_share(
        &self,
        request: Value,
        slot_held: impl FnOnce() -> bool + Send + 'static,
    ) -> Result<Value, ProviderError> {
        self.write_host_share_settled(request, slot_held, |response| response)
            .await
    }

    /// The same write, its answer passed through `settle` inside the write's
    /// own settlement: under the host lock, in the task that owns the write,
    /// so it runs even when the caller is gone.
    async fn write_host_share_settled(
        &self,
        request: Value,
        slot_held: impl FnOnce() -> bool + Send + 'static,
        settle: impl FnOnce(Value) -> Value + Send + 'static,
    ) -> Result<Value, ProviderError> {
        let incoming = serde_json::to_vec(&request).map_or(u64::MAX, |bytes| {
            u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        });
        let bridge = Arc::clone(&self.bridge);
        guarded_host_share_write(
            self.data_dir.clone(),
            incoming,
            slot_held,
            move || async move {
                bridge
                    .send_raw(&request)
                    .await
                    .map(settle)
                    .map_err(|error| ProviderError::Provider(error.to_string()))
            },
        )
        .await
    }

    /// Validates the Runtime envelope and admits the op from the custody
    /// surface: the Carrier plane admits the target's Carrier ops, and the
    /// local plane also admits its Runtime-local ops (L15). Returns the
    /// request without its envelope and the endpoint that sent it.
    fn strip_runtime_invocation(
        &self,
        request: &Value,
    ) -> Result<(Value, RuntimeInvocationSource), ProviderError> {
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
        let source = custody_runtime_invocation_source(object, TARGET_CUSTODY, &op)?;
        Ok((value, source))
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
            Some("error") => Err(ProviderError::Provider(custody_private_rejection_message(
                response.get("code").and_then(Value::as_str),
            ))),
            _ => Err(ProviderError::Provider(
                "custody private response has unsupported status".into(),
            )),
        }
    }

    fn normalize_public_status(
        &self,
        response: Value,
        source: &RuntimeInvocationSource,
    ) -> Result<Value, ProviderError> {
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
        // The public status lists what the wrapper's dispatch admits for this
        // caller, from the custody surface. Upload attestation is a private
        // call to the custody child, outside the advertised custody API.
        let supported_operations: Vec<&str> = declared_ops(TARGET_CUSTODY)
            .filter(|op| {
                !matches!(
                    *op,
                    ATTEST_REMOTE_SEAL_UPLOAD_OP
                        | AUTHORIZE_REMOTE_SEAL_SHARE_OP
                        | SIGN_REMOTE_SEAL_COMPLETION_OP
                )
            })
            .filter(|op| {
                *source == RuntimeInvocationSource::Local || carrier_op_allowed(TARGET_CUSTODY, op)
            })
            .collect();
        Ok(json!({
            "status": "ok",
            "data": {
                "provider": provider,
                "version": version,
                "configured": configured,
                "supported_operations": supported_operations,
                "request_schema": request_schema,
                "response_schema": response_schema,
            }
        }))
    }
}

/// Plan B T3.4 (E12): the Runtime envelope check shared by the custody
/// targets. It removes and validates `_runtime_invocation` for `target` and
/// `op`, and admits `op` from the custody surface: the Carrier plane admits the
/// target's Carrier ops, and the local plane also its Runtime-local ops (L15).
/// Returns the endpoint that sent the request.
pub(crate) fn custody_runtime_invocation_source(
    object: &mut serde_json::Map<String, Value>,
    target: &str,
    op: &str,
) -> Result<RuntimeInvocationSource, ProviderError> {
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
        || envelope.get("target").and_then(Value::as_str) != Some(target)
        || envelope.get("op").and_then(Value::as_str) != Some(op)
        || envelope.get("capability").and_then(Value::as_str)
            != Some(&format!("provider:{RUNTIME_PROVIDER_ID}->{target}:{op}"))
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
    let source = match envelope
        .get("carrier")
        .and_then(|carrier| carrier.get("source_endpoint_did"))
        .and_then(Value::as_str)
    {
        Some(did) if transport == "carrier-provider-plane" => RuntimeInvocationSource::Carrier {
            source_endpoint_did: did.to_owned(),
        },
        None if transport == "runtime-local-provider-plane" => RuntimeInvocationSource::Local,
        _ => {
            return Err(ProviderError::Provider(
                "custody request runtime envelope is invalid".into(),
            ))
        }
    };
    let admitted = carrier_op_allowed(target, op)
        || (source == RuntimeInvocationSource::Local && runtime_local_op_allowed(target, op));
    if !admitted {
        return Err(ProviderError::Provider(
            "custody request op is local to the Runtime".into(),
        ));
    }
    Ok(source)
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
    diagnostics: RuntimeCustodyCallDiagnostics,
}

impl RuntimeCustodyRegistryAdapter {
    pub(super) fn new(
        registry: Arc<ProviderRegistry>,
        transport: ProviderInvocationTransport,
        diagnostics: RuntimeCustodyCallDiagnostics,
    ) -> Self {
        Self {
            registry,
            transport,
            diagnostics,
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
            OP_CUSTODY_EVALUATE,
            request_value,
            self.transport.clone(),
        )
        .await
        .map_err(|error| {
            self.diagnostics
                .record("rights evaluate", &error.to_string());
            RuntimeProviderCallError::NoExactResult
        })?;
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
        // Encoding happens entirely here; a failure means nothing was sent.
        let request_value = serde_json::from_slice(
            &request
                .to_json_vec()
                .map_err(|_| RuntimeProviderCallError::NotDispatched)?,
        )
        .map_err(|_| RuntimeProviderCallError::NotDispatched)?;
        let response_value = invoke_json_provider_classified(
            self.registry.as_ref(),
            CUSTODY_PROVIDER_ID,
            op,
            request_value,
            self.transport.clone(),
        )
        .await
        .map_err(|failure| {
            self.diagnostics
                .record(op, &failure.clone().into_message(CUSTODY_PROVIDER_ID, op));
            classify_custody_failure(op, &failure)
        })?;
        // The node answered `ok`; only this Runtime can still fail to read it,
        // and by then the node has already acted.
        elastos_protected_content_provider_contracts::CustodyProviderResponseV1::from_json_slice(
            &serde_json::to_vec(&response_value)
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?,
        )
        .map_err(|_| RuntimeProviderCallError::NoExactResult)
    }

    /// Plan B T4.1: the pool custody op, with the same encoding and failure
    /// classification as [`Self::invoke_custody`].
    pub(super) async fn invoke_pool_custody(
        &self,
        op: &'static str,
        request: &elastos_protected_content_provider_contracts::PoolCustodyRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::PoolCustodyResponseV1,
        RuntimeProviderCallError,
    > {
        // Encoding happens entirely here; a failure means nothing was sent.
        let request_value = serde_json::from_slice(
            &request
                .to_json_vec()
                .map_err(|_| RuntimeProviderCallError::NotDispatched)?,
        )
        .map_err(|_| RuntimeProviderCallError::NotDispatched)?;
        let response_value = invoke_json_provider_classified(
            self.registry.as_ref(),
            CUSTODY_PROVIDER_ID,
            op,
            request_value,
            self.transport.clone(),
        )
        .await
        .map_err(|failure| {
            self.diagnostics
                .record(op, &failure.clone().into_message(CUSTODY_PROVIDER_ID, op));
            classify_custody_failure(op, &failure)
        })?;
        // As for V1: an `ok` this Runtime cannot read came after the node acted.
        elastos_protected_content_provider_contracts::PoolCustodyResponseV1::from_json_slice(
            &serde_json::to_vec(&response_value)
                .map_err(|_| RuntimeProviderCallError::NoExactResult)?,
        )
        .map_err(|_| RuntimeProviderCallError::NoExactResult)
    }
}

/// Codes the custody capsule emits only from paths that precede its durable
/// write, so a refusal carrying one proves the share was not stored.
///
/// `invalid_request` covers frame and request-validation refusals,
/// `rights_denied` the rights decision, and `provisioning_refused` everything
/// the share store rejects before it is touched — expiry above all. All three
/// are structurally before `NodeLocalShareStoreV1` writes. `backend_unavailable`
/// is deliberately absent: the capsule returns it from refusals before the
/// write, from failures after it, and from the `hard_link` that is the write,
/// so it proves nothing about the share.
///
/// A closed list, and the compatibility story runs the safe way in both
/// directions: an older capsule still answers `backend_unavailable` and this
/// Runtime keeps treating it as uncertain, and a code this Runtime does not
/// recognise is uncertain rather than effect-free.
///
/// `operation_expired` and `evidence_expired` are request-validation refusals
/// too: the operation or its chain evidence ended before the node acted, and
/// the capsule names them so the Runtime can start a fresh operation instead
/// of reporting a malformed request.
pub(super) const CUSTODY_EFFECT_FREE_REFUSAL_CODES: [&str; 9] = [
    "invalid_request",
    "provisioning_refused",
    // Plan B POOL-MINT: refused by the Runtime wrapper before the provider.
    crate::host_trust::HOST_STORAGE_FULL,
    crate::host_trust::HOST_STORAGE_MAX_UNSET,
    "rights_denied",
    "operation_expired",
    "evidence_expired",
    "unknown_envelope",
    RATE_LIMITED_CODE,
];

/// Codes a custody capsule refusal may carry into a Runtime diagnostic. The
/// capsule answers with a fixed code and message; only a code from this
/// closed list is repeated, so a refusal can never carry free text, an
/// address or a path into the Runtime's report.
pub(super) const CUSTODY_REPORTABLE_REFUSAL_CODES: [&str; 9] = [
    "invalid_request",
    "invalid_config",
    "backend_unavailable",
    "provisioning_refused",
    "rights_denied",
    "operation_expired",
    "evidence_expired",
    "unknown_envelope",
    RATE_LIMITED_CODE,
];

/// The capsule-style refusal of a custody call above one of its budgets.
/// #388 A1 (#388-1): on a host that is not WCI-operated, every custody op
/// that touches another party's content key is refused before the provider,
/// V1 and V2 alike and every statement kind, with that op's existing
/// effect-free code, so a remote coordinator fails over. The roots, shares,
/// replay state and journals stay as they are. `None` lets the op through.
pub(crate) fn custody_host_trust_refusal(op: &str, host_trusted: bool) -> Option<Value> {
    if host_trusted {
        return None;
    }
    let code = match op {
        OP_CUSTODY_RELEASE_CONTRIBUTION
        | OP_CUSTODY_SIGN_POOL_STATEMENT
        | ATTEST_REMOTE_SEAL_UPLOAD_OP
        | AUTHORIZE_REMOTE_SEAL_SHARE_OP
        | SIGN_REMOTE_SEAL_COMPLETION_OP => "invalid_request",
        OP_CUSTODY_RELEASE_POOL_CONTRIBUTION => "unknown_envelope",
        OP_CUSTODY_PROVISION_NODE_SHARE | OP_CUSTODY_PROVISION_POOL_NODE_SHARE => {
            "provisioning_refused"
        }
        _ => return None,
    };
    Some(json!({
        "status": "error",
        "code": code,
        "message": "this host is not set up as a WCI-operated host",
    }))
}

fn custody_rate_limited_response() -> Value {
    json!({
        "status": "error",
        "code": RATE_LIMITED_CODE,
        "message": "custody release rate limit reached",
    })
}

/// The wallet and item of an evaluate request whose prepare the capsule
/// accepted. The wrapper decodes the operation only then: the capsule has
/// verified these exact bytes, so a decode is enough here.
fn custody_rights_budget_keys(
    request: &Value,
) -> Result<(WalletAddress, ContentAccessIdV1), ProviderError> {
    let invalid = || ProviderError::Provider("custody evaluate request is invalid".into());
    let bytes = request
        .get("signed_runtime_release_operation")
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<u8>>(value).ok())
        .ok_or_else(invalid)?;
    Ok(
        match RuntimeReleaseOperationAnyV1::from_canonical_bytes(&bytes).map_err(|_| invalid())? {
            RuntimeReleaseOperationAnyV1::V1(operation) => {
                let statement = operation.statement();
                (
                    statement.rights_request().request().binding().wallet(),
                    statement.policy_body().content_access_id(),
                )
            }
            RuntimeReleaseOperationAnyV1::V2(operation) => {
                let statement = operation.statement();
                (
                    statement.rights_request().request().binding().wallet(),
                    statement.policy_body().content_access_id(),
                )
            }
        },
    )
}

pub(super) fn custody_private_rejection_message(code: Option<&str>) -> String {
    match code.filter(|code| CUSTODY_REPORTABLE_REFUSAL_CODES.contains(code)) {
        Some(code) => format!("custody private request was rejected: {code}"),
        None => "custody private request was rejected".into(),
    }
}

pub(super) fn classify_custody_failure(
    op: &str,
    failure: &ProviderInvocationFailure,
) -> RuntimeProviderCallError {
    match failure {
        ProviderInvocationFailure::Refused { code, .. }
            if CUSTODY_EFFECT_FREE_REFUSAL_CODES.contains(&code.as_str()) =>
        {
            tracing::warn!(
                %op,
                %code,
                "custody provider refused before acting"
            );
            RuntimeProviderCallError::RefusedWithoutEffect
        }
        ProviderInvocationFailure::Refused { code, .. } => {
            tracing::warn!(
                %op,
                %code,
                "custody provider refused with an effect-uncertain code"
            );
            RuntimeProviderCallError::NoExactResult
        }
        // A lost reply is indistinguishable from a node that never heard us,
        // and the capsule can complete its write and then fail to answer.
        ProviderInvocationFailure::NotCompleted { .. }
        | ProviderInvocationFailure::MalformedResponse { .. } => {
            tracing::warn!(%op, "custody provider effect is uncertain");
            RuntimeProviderCallError::NoExactResult
        }
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
        let (request, source) = self.strip_runtime_invocation(request)?;
        let op = request
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if let Some(refusal) = custody_host_trust_refusal(op, self.host_trusted) {
            tracing::debug!(%op, "custody op refused: this host is not WCI-operated");
            return Ok(refusal);
        }
        if op == OP_CUSTODY_PROVISION_POOL_NODE_SHARE {
            if request.get("remote_seal_request").is_some() {
                return self.write_remote_pool_share(request, source).await;
            }
            let (slot_held, accepted) = match self.admit_pool_share(&request) {
                Ok(admitted) => admitted,
                Err(refusal) => return Ok(refusal),
            };
            let data_dir = self.data_dir.clone();
            return self
                .write_host_share_settled(request, slot_held, move |response| {
                    settle_pool_share_admission(&data_dir, &accepted, response)
                })
                .await;
        }
        if op == OP_CUSTODY_PROVISION_NODE_SHARE {
            // V1 shares observe the same host maximum (PM-F2).
            let slot_held = self.v1_share_slot_held(&request);
            return self.write_host_share(request, slot_held).await;
        }
        // L10, first stage: every release call spends its endpoint's budget at
        // entry, whatever the capsule answers.
        if matches!(
            op,
            OP_CUSTODY_EVALUATE
                | OP_CUSTODY_RELEASE_CONTRIBUTION
                | OP_CUSTODY_RELEASE_POOL_CONTRIBUTION
        ) && self
            .limiter
            .admit_endpoint(source.endpoint_key(), crate::auth::now_ts())
            .is_err()
        {
            tracing::debug!(%op, "custody release refused at its endpoint budget");
            return Ok(custody_rate_limited_response());
        }
        if op == OP_CUSTODY_STATUS {
            let response = self
                .bridge
                .send_raw(&request)
                .await
                .map_err(|error| ProviderError::Provider(error.to_string()))?;
            return self.normalize_public_status(response, &source);
        }
        if op == OP_CUSTODY_EVALUATE {
            let prepare = PrivateCustodyRightsRequestV1::new_prepare(request.clone());
            let prepare_response = self.send_private_child_request(&prepare).await?;
            let chain_request = self.private_ok_data(prepare_response)?;
            // L10, second stage: the accepted prepare proved the operation's
            // signatures, so its wallet and item spend their budgets now,
            // before the chain read.
            let (wallet, kid) = custody_rights_budget_keys(&request)?;
            if self
                .limiter
                .admit_rights(wallet, kid, crate::auth::now_ts())
                .is_err()
            {
                tracing::debug!("custody evaluate refused at its wallet or item budget");
                return Ok(custody_rate_limited_response());
            }
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

/// Starts this Home's custody provider with every root on disk (Plan B
/// T2.1): `base_path` is the custody-provider folder and `extra.roots` lists
/// `inactive` and each `pools/<hex>` root, capped by the node settings.
pub async fn register_custody_provider(
    registry: &Arc<ProviderRegistry>,
    binary_path: &Path,
    data_dir: &Path,
) -> anyhow::Result<()> {
    let bridge_config = custody_provider_roots_config(data_dir)?;
    spawn_custody_provider(registry, binary_path, data_dir, bridge_config).await
}

/// What starting this Home's custody provider at boot came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyProviderStartup {
    /// The provider is running on this Home's roots.
    Registered,
    /// This Home has never provisioned custody, so there is nothing to start.
    /// It starts on demand when a pool creates its first root.
    NotProvisioned,
}

/// Starts this Home's custody provider at boot, unless the Home has never
/// provisioned custody. Only genuine absence is skipped: a present root that
/// is malformed or unreadable still goes to registration, which refuses it,
/// and an error reading the custody folder is returned, so both still warn.
pub async fn start_custody_provider_at_boot(
    registry: &Arc<ProviderRegistry>,
    binary_path: &Path,
    data_dir: &Path,
) -> anyhow::Result<CustodyProviderStartup> {
    if custody_never_provisioned(data_dir)? {
        return Ok(CustodyProviderStartup::NotProvisioned);
    }
    register_custody_provider(registry, binary_path, data_dir).await?;
    Ok(CustodyProviderStartup::Registered)
}

/// Whether neither the `inactive` root nor the pool roots folder exists at
/// all. Anything present, in any form, is not absence; neither is an error
/// other than "not found". The custody folder itself is read without
/// following links: a link there (dangling or to an empty folder) or a
/// non-folder is refused, not taken for absence.
fn custody_never_provisioned(data_dir: &Path) -> anyhow::Result<bool> {
    let base = custody_provider_base(data_dir);
    match fs::symlink_metadata(&base) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(invalid_custody_config(
                "custody provider folder must be a real folder",
            ))
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => {
            return Err(invalid_custody_config(format!(
                "custody provider folder cannot be read: {}",
                error.kind()
            )))
        }
    }
    for path in [
        base.join(custody_provider::CUSTODY_INACTIVE_ROOT_PATH),
        base.join(custody_provider::CUSTODY_POOL_ROOTS_DIR),
    ] {
        match fs::symlink_metadata(&path) {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(invalid_custody_config(format!(
                    "custody provider folder cannot be read: {}",
                    error.kind()
                )))
            }
        }
    }
    Ok(true)
}

/// Starts a custody host's provider with its one legacy root: `base_path` is
/// the `inactive` root itself and `extra` is null (Plan B T2.1).
pub async fn register_custody_host_provider(
    registry: &Arc<ProviderRegistry>,
    binary_path: &Path,
    data_dir: &Path,
) -> anyhow::Result<()> {
    let state_root = inactive_custody_state_root(data_dir);
    validate_custody_state_root(&state_root)?;
    let base_path = custody_utf8_path(&state_root)?;
    let bridge_config = ProviderConfig {
        base_path,
        ..Default::default()
    };
    spawn_custody_provider(registry, binary_path, data_dir, bridge_config).await
}

/// The running custody provider's bridge for each Home in this process.
static CUSTODY_BRIDGES: OnceLock<
    StdMutex<HashMap<PathBuf, Weak<elastos_runtime::provider::ProviderBridge>>>,
> = OnceLock::new();

fn custody_bridges(
) -> &'static StdMutex<HashMap<PathBuf, Weak<elastos_runtime::provider::ProviderBridge>>> {
    CUSTODY_BRIDGES.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn remember_custody_bridge(
    data_dir: &Path,
    bridge: &Arc<elastos_runtime::provider::ProviderBridge>,
) {
    if let Ok(mut bridges) = custody_bridges().lock() {
        bridges.insert(data_dir.to_path_buf(), Arc::downgrade(bridge));
    }
}

fn running_custody_bridge(
    data_dir: &Path,
) -> Option<Arc<elastos_runtime::provider::ProviderBridge>> {
    custody_bridges()
        .lock()
        .ok()?
        .get(data_dir)
        .and_then(Weak::upgrade)
}

/// Whether this server started the custody provider running for this Home,
/// and so can refresh its roots.
pub(crate) fn custody_bridge_known(data_dir: &Path) -> bool {
    running_custody_bridge(data_dir).is_some()
}

/// One root as the running custody provider lists it (local plane only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CustodyRootStatus {
    pub(crate) path: Option<String>,
    pub(crate) configured: bool,
    pub(crate) shares_held: Option<u64>,
}

/// Plan B T2.2 (S2-Q1): sends the running custody provider a fresh `init`
/// with every root on disk, so a new root serves and a stopped one ends
/// without a restart. The other roots load the same keys again. Fails when
/// no provider runs for this Home or it refuses the set.
pub(crate) async fn refresh_custody_roots(
    data_dir: &Path,
) -> anyhow::Result<Vec<CustodyRootStatus>> {
    let bridge = running_custody_bridge(data_dir)
        .ok_or_else(|| anyhow::anyhow!("this Home runs no custody provider"))?;
    let config = custody_provider_roots_config(data_dir)?;
    let response = bridge
        .send_raw(&json!({ "op": "init", "config": config }))
        .await
        .map_err(|error| anyhow::anyhow!("custody provider refresh failed: {error}"))?;
    require_custody_provider_status(&response)?;
    tracing::debug!("the custody provider holds the roots on disk now");
    Ok(custody_root_statuses(&response))
}

/// The roots the running custody provider holds, from its private status;
/// none when no provider runs for this Home.
pub(crate) async fn custody_provider_root_statuses(
    data_dir: &Path,
) -> Option<Vec<CustodyRootStatus>> {
    let bridge = running_custody_bridge(data_dir)?;
    let response = bridge.send_raw(&json!({ "op": "status" })).await.ok()?;
    require_custody_provider_status(&response).ok()?;
    Some(custody_root_statuses(&response))
}

fn custody_root_statuses(status: &Value) -> Vec<CustodyRootStatus> {
    status["data"]["roots"]
        .as_array()
        .map(|roots| {
            roots
                .iter()
                .map(|root| CustodyRootStatus {
                    path: root["path"].as_str().map(str::to_owned),
                    configured: root["configured"].as_bool() == Some(true),
                    shares_held: root["shares_held"].as_u64(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Whether the running custody provider serves the root at `path`.
pub(crate) async fn custody_root_loaded(data_dir: &Path, path: &str) -> bool {
    custody_provider_root_statuses(data_dir)
        .await
        .is_some_and(|roots| {
            roots
                .iter()
                .any(|root| root.path.as_deref() == Some(path) && root.configured)
        })
}

/// The folder of the custody root `path` (`inactive` or `pools/<hex>`).
pub(crate) fn custody_root_dir(data_dir: &Path, path: &str) -> PathBuf {
    custody_provider_base(data_dir).join(path)
}

/// The provider config for every root this Home holds on disk. With no root
/// there is nothing to start.
pub(crate) fn custody_provider_roots_config(data_dir: &Path) -> anyhow::Result<ProviderConfig> {
    let roots = custody_provider_root_paths(data_dir)?;
    if roots.is_empty() {
        return Err(invalid_custody_config("no provisioned custody root exists"));
    }
    let base = custody_provider_base(data_dir);
    // A root that fails the owner-only check follows the per-root rule (user
    // decision 2026-11-12 10:26): it is still named, the provider does not
    // load it, and its pool is not served; the other roots start.
    for root in &roots {
        if let Err(error) = validate_custody_state_root(&base.join(root)) {
            tracing::warn!(
                root = %root,
                error = %format!("{error:#}"),
                "a custody root is unsafe; its pool is not served"
            );
        }
    }
    Ok(ProviderConfig {
        base_path: custody_utf8_path(&base)?,
        extra: json!({
            "roots": roots
                .iter()
                .map(|path| json!({ "path": path }))
                .collect::<Vec<_>>(),
            "max_roots": crate::custody_release_limits::CUSTODY_NODE_SETTINGS.max_pools,
        }),
        ..Default::default()
    })
}

/// The folder holding every custody root of this Home.
pub(crate) fn custody_provider_base(data_dir: &Path) -> PathBuf {
    data_dir.join(CUSTODY_PROVIDER_STATE_DIR)
}

/// Plan B POOL-MINT: the one host storage account (Anders #388): the bytes
/// of other parties' custody data this host keeps, across every pool it
/// serves: every root's share store, the shares a stopped pool's set-aside
/// root still retains (`pools/*.stopped-*`, PM-F3), the copies of its
/// pools' files this member keeps (MEMBER-COPIES) and those being staged
/// (PR2-F1), and the objects staged for pool viewing sessions (PR4-F1).
/// Nothing is deleted.
pub(crate) fn host_custody_storage_bytes(data_dir: &Path) -> anyhow::Result<u64> {
    let mut roots: Vec<PathBuf> = custody_provider_root_paths(data_dir)?
        .iter()
        .map(|root| custody_root_dir(data_dir, root))
        .collect();
    let pools = custody_provider_base(data_dir).join(custody_provider::CUSTODY_POOL_ROOTS_DIR);
    match fs::read_dir(&pools) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.contains(".stopped-"))
                {
                    roots.push(entry.path());
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut total = crate::custody_consent::member_copies_bytes(data_dir)?
        .saturating_add(crate::custody_consent::member_copy_staging_bytes(data_dir)?)
        .saturating_add(
            crate::custody_pool_seal::storage::host_remote_seal_storage_bytes(data_dir)?,
        )
        .saturating_add(crate::custody_pool_service::pool_session_stage_bytes(
            data_dir,
        )?);
    for root in roots {
        let store = custody_provider::node_share_store_dir(&root);
        let entries = match fs::read_dir(&store) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let metadata = fs::symlink_metadata(entry?.path())?;
            if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    Ok(total)
}

/// Plan B POOL-MINT (PM-F2): the one host-wide lock every share write takes,
/// so the maximum check and the write it allows are one step.
static HOST_SHARE_WRITES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The host-wide share lock on its own: a pool's withdrawal of its copies
/// holds it, so no copy commits half way through it (MC-F2).
pub(crate) async fn lock_host_share_writes() -> tokio::sync::MutexGuard<'static, ()> {
    HOST_SHARE_WRITES.lock().await
}

/// Plan B POOL-MINT (PM-F2, PM-F4): one share write under the host-wide lock.
/// Inside it, a write to a slot this host already holds (an exact retry
/// answers the stored receipt; anything else is refused) is not charged;
/// any other write is checked against the host storage maximum, then sent
/// and settled before the lock is released.
///
/// The write owns the lock, not its caller: it runs in its own task, in the
/// caller's dispatch fence, and the caller awaits it. A caller cancelled
/// after dispatch leaves the lock held until the write it allowed settles.
pub(crate) async fn guarded_host_share_write<Held, Write, Sent>(
    data_dir: PathBuf,
    incoming_bytes: u64,
    slot_held: Held,
    write: Write,
) -> Result<Value, ProviderError>
where
    Held: FnOnce() -> bool + Send + 'static,
    Write: FnOnce() -> Sent + Send + 'static,
    Sent: std::future::Future<Output = Result<Value, ProviderError>> + Send + 'static,
{
    let operation = async move {
        let _guard = HOST_SHARE_WRITES.lock().await;
        if !slot_held() {
            if let Some(refusal) = host_storage_refusal(&data_dir, incoming_bytes) {
                return Ok(refusal);
            }
        }
        write().await
    };
    let task = match elastos_runtime::provider::dispatch::DispatchFence::current() {
        Some(fence) => tokio::spawn(async move { fence.scope(operation).await }),
        None => tokio::spawn(operation),
    };
    task.await.map_err(|error| {
        ProviderError::Provider(format!("host share write did not finish: {error}"))
    })?
}

/// Plan B POOL-MINT: a WCI-operated host keeps at most the storage maximum
/// its operator set, whichever Home mints (no per-creator quota). With no
/// maximum set the share is refused (fail closed); a share of
/// `incoming_bytes` that would take the host past it is refused too.
pub(crate) fn host_storage_refusal(data_dir: &Path, incoming_bytes: u64) -> Option<Value> {
    let refusal = |code: &str, message: &str| {
        Some(json!({ "status": "error", "code": code, "message": message }))
    };
    let Some(max) = crate::host_trust::host_storage_max_bytes(data_dir) else {
        tracing::warn!("custody data refused: this host has no storage maximum");
        return refusal(
            crate::host_trust::HOST_STORAGE_MAX_UNSET,
            "this host has no storage maximum: its operator sets one with elastos setup --host-trust wci-operated --max-storage-bytes <bytes>",
        );
    };
    match host_custody_storage_bytes(data_dir) {
        Ok(used) if used.saturating_add(incoming_bytes) <= max => None,
        Ok(used) => {
            tracing::warn!(
                used,
                max,
                incoming_bytes,
                "custody data refused: host storage is full"
            );
            refusal(
                crate::host_trust::HOST_STORAGE_FULL,
                "this host's storage is full",
            )
        }
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "host storage cannot be counted");
            refusal(
                "provisioning_refused",
                "this host's storage cannot be counted",
            )
        }
    }
}

/// The roots on disk, as the provider's `extra.roots` names them: `inactive`
/// when it exists, then each `pools/<hex>` folder in name order. Tombstones,
/// staging folders and other names are not roots.
pub(crate) fn custody_provider_root_paths(data_dir: &Path) -> anyhow::Result<Vec<String>> {
    let base = custody_provider_base(data_dir);
    let mut roots = Vec::new();
    if base
        .join(custody_provider::CUSTODY_INACTIVE_ROOT_PATH)
        .is_dir()
    {
        roots.push(custody_provider::CUSTODY_INACTIVE_ROOT_PATH.to_string());
    }
    let pools = base.join(custody_provider::CUSTODY_POOL_ROOTS_DIR);
    let entries = match fs::read_dir(&pools) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(roots),
        Err(error) => {
            return Err(anyhow::anyhow!(
                "custody pool roots cannot be listed: {error}"
            ))
        }
    };
    let mut pool_roots = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|error| anyhow::anyhow!("custody pool roots cannot be listed: {error}"))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let path = format!("{}/{name}", custody_provider::CUSTODY_POOL_ROOTS_DIR);
        let is_dir = fs::symlink_metadata(entry.path())
            .map(|metadata| metadata.is_dir())
            .unwrap_or(false);
        if is_dir && custody_provider::is_custody_root_path(&path) {
            pool_roots.push(path);
        }
    }
    pool_roots.sort();
    roots.extend(pool_roots);
    Ok(roots)
}

fn custody_utf8_path(path: &Path) -> anyhow::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid_custody_config("custody provider folder must be valid UTF-8"))
}

async fn spawn_custody_provider(
    registry: &Arc<ProviderRegistry>,
    binary_path: &Path,
    data_dir: &Path,
    bridge_config: ProviderConfig,
) -> anyhow::Result<()> {
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
        require_custody_provider_status(&status)?;
        // The existing roots still load, so Hosting lists them; on an
        // everyday host they serve nothing (#388-1).
        let provider: Arc<dyn Provider> =
            Arc::new(InactiveCustodyProvider::new(InactiveCustodyProviderParts {
                bridge: bridge.clone(),
                registry: Arc::downgrade(registry),
                host_trusted: crate::host_trust::host_trusted(data_dir),
                data_dir: data_dir.to_path_buf(),
            }));
        register_custody_runtime_provider_target(registry, provider)
            .await
            .map_err(|error| anyhow::anyhow!("failed to register inactive custody route: {error}"))
    }
    .await;
    settle_protected_provider_startup(&bridge, startup, "inactive custody provider").await?;
    // Plan B T2.2 (user decision 2026-11-12 10:35): the server keeps the
    // bridge so a new or stopped root reaches the running provider by a fresh
    // `init`, with no registry change.
    remember_custody_bridge(data_dir, &bridge);
    // Plan B T3.4: whenever a custody root runs, this Home also answers the
    // `custody-pool` target. Its sessions fail closed until a pool descriptor
    // names this node as a server.
    if let Err(error) =
        crate::custody_pool_service::register_custody_pool_service(registry, data_dir).await
    {
        tracing::warn!(
            error = %format!("{error:#}"),
            "the custody-pool target is not registered"
        );
    }
    Ok(())
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

pub(super) fn require_custody_provider_status(status: &Value) -> anyhow::Result<()> {
    // Plan B T2.1: a provider that holds a root set also lists its roots on
    // this local-plane status; an older provider does not.
    const FIELDS: [&str; 6] = [
        "provider",
        "version",
        "configured",
        "supported_operations",
        "request_schema",
        "response_schema",
    ];
    let lists_roots = status
        .get("data")
        .and_then(Value::as_object)
        .is_some_and(|data| data.contains_key("roots"));
    let with_roots: Vec<&str> = FIELDS.iter().copied().chain(["roots"]).collect();
    let data = require_exact_provider_status_data(
        status,
        "inactive custody provider",
        if lists_roots {
            &with_roots[..]
        } else {
            &FIELDS[..]
        },
    )?;
    if lists_roots {
        require_custody_root_statuses(data.get("roots"))?;
    }
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

/// Each entry is exactly `{path, node_public_key, configured, shares_held}`.
fn require_custody_root_statuses(roots: Option<&Value>) -> anyhow::Result<()> {
    let roots = roots
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("inactive custody provider root list is invalid"))?;
    for root in roots {
        let valid = root.as_object().is_some_and(|root| {
            root.len() == 4
                && root
                    .get("path")
                    .is_some_and(|path| path.is_null() || path.is_string())
                && root
                    .get("node_public_key")
                    .is_some_and(|key| key.is_null() || key.is_string())
                && root.get("configured").is_some_and(Value::is_boolean)
                && root
                    .get("shares_held")
                    .is_some_and(|held| held.is_null() || held.is_u64())
        });
        if !valid {
            anyhow::bail!("inactive custody provider root list is invalid");
        }
    }
    Ok(())
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

pub(super) async fn register_custody_runtime_provider_target(
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

fn validate_custody_state_root(root: &Path) -> anyhow::Result<()> {
    validate_owner_only_directory(root, "inactive custody provider root")
}

pub(super) fn invalid_custody_config(reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("inactive custody provider configuration is missing or unsafe: {reason}")
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

pub(super) fn canonical_custody_composition_config_bytes(
    config: &RuntimeCustodyCompositionConfigFile,
) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::to_value(config)?)?)
}

pub(crate) fn decode_canonical_contract_base64<T: CanonicalContract>(
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

pub(crate) fn decode_custody_epoch_issuer_base64(
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

#[cfg(test)]
pub(super) fn load_runtime_custody_composition_config(
    data_dir: &Path,
) -> anyhow::Result<Option<RuntimeValidatedCustodyCompositionConfig>> {
    load_runtime_custody_composition_config_from(
        data_dir,
        &runtime_custody_composition_config_path(data_dir),
        crate::auth::now_ts(),
        MintCompositionCheck::Provision,
    )
}

fn load_runtime_custody_composition_config_from(
    data_dir: &Path,
    config_path: &Path,
    now: u64,
    check: MintCompositionCheck,
) -> anyhow::Result<Option<RuntimeValidatedCustodyCompositionConfig>> {
    match fs::symlink_metadata(config_path) {
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
    let bytes = read_owner_only_config_bytes(config_path, MAX_CUSTODY_COMPOSITION_BYTES)?;
    parse_runtime_custody_composition_config(bytes, now, check).map(Some)
}

#[derive(Clone, Copy)]
pub(super) enum MintCompositionCheck {
    Provision,
    CompletedReplay,
}

pub(super) fn parse_runtime_custody_composition_config(
    bytes: Vec<u8>,
    now: u64,
    check: MintCompositionCheck,
) -> anyhow::Result<RuntimeValidatedCustodyCompositionConfig> {
    if bytes.is_empty() || bytes.len() > MAX_CUSTODY_COMPOSITION_BYTES {
        return Err(invalid_custody_composition_config(
            "custody-composition file exceeds bounds",
        ));
    }
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

    let validate = match check {
        MintCompositionCheck::Provision => validate_custody_epoch_against_pool_at,
        MintCompositionCheck::CompletedReplay => {
            elastos_protected_content_contracts::validate_custody_epoch_for_release_at
        }
    };
    let validated = validate(
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

    Ok(RuntimeValidatedCustodyCompositionConfig {
        bytes,
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
    })
}

pub(crate) fn load_runtime_custody_composition(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
) -> anyhow::Result<Option<RuntimeCustodyComposition>> {
    Ok(load_runtime_custody_composition_snapshot(
        data_dir,
        &runtime_custody_composition_config_path(data_dir),
        registry,
    )?
    .map(|(composition, _)| composition))
}

pub(super) fn load_runtime_custody_composition_snapshot(
    data_dir: &Path,
    config_path: &Path,
    registry: Arc<ProviderRegistry>,
) -> anyhow::Result<Option<(RuntimeCustodyComposition, Vec<u8>)>> {
    load_custody_composition_at(
        data_dir,
        config_path,
        registry,
        crate::auth::now_ts(),
        MintCompositionCheck::Provision,
    )
}

fn load_custody_composition_at(
    data_dir: &Path,
    config_path: &Path,
    registry: Arc<ProviderRegistry>,
    now: u64,
    check: MintCompositionCheck,
) -> anyhow::Result<Option<(RuntimeCustodyComposition, Vec<u8>)>> {
    let Some(config) =
        load_runtime_custody_composition_config_from(data_dir, config_path, now, check)?
    else {
        return Ok(None);
    };
    build_runtime_custody_composition(config, registry, now, check).map(Some)
}

/// Run the live composition loader's checks before publishing generated bytes.
pub(crate) fn validate_generated_custody_composition(bytes: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let now = crate::auth::now_ts();
    let check = MintCompositionCheck::Provision;
    let config = parse_runtime_custody_composition_config(bytes, now, check)?;
    let registry = Arc::new(ProviderRegistry::new());
    build_runtime_custody_composition(config, registry, now, check).map(|(_, bytes)| bytes)
}

pub(crate) fn verify_published_custody_composition(
    data_dir: &Path,
    expected: &[u8],
) -> anyhow::Result<()> {
    validate_owner_only_protected_content_dir(data_dir)?;
    let bytes = read_owner_only_config_bytes(
        &runtime_custody_composition_config_path(data_dir),
        MAX_CUSTODY_COMPOSITION_BYTES,
    )?;
    anyhow::ensure!(
        bytes == expected,
        "the published custody composition changed"
    );
    Ok(())
}

pub(super) fn build_runtime_custody_composition(
    config: RuntimeValidatedCustodyCompositionConfig,
    registry: Arc<ProviderRegistry>,
    now: u64,
    check: MintCompositionCheck,
) -> anyhow::Result<(RuntimeCustodyComposition, Vec<u8>)> {
    let validate = match check {
        MintCompositionCheck::Provision => validate_custody_epoch_against_pool_at,
        MintCompositionCheck::CompletedReplay => {
            elastos_protected_content_contracts::validate_custody_epoch_for_release_at
        }
    };
    let validated = validate(
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
    let diagnostics = RuntimeCustodyCallDiagnostics::default();
    let nodes = validated
        .committee()
        .nodes()
        .iter()
        .zip(config.routes.iter())
        .map(|(node, route)| RuntimeCustodyCompositionNode {
            node_public_key: node.node_public_key(),
            custody_public_key: node.custody_public_key(),
            owner_state_root: route.owner_state_root,
            adapter: RuntimeCustodyRegistryAdapter::new(
                registry.clone(),
                route.transport.clone(),
                diagnostics.clone(),
            ),
        })
        .collect::<Vec<_>>();

    let composition = RuntimeCustodyComposition {
        expected_policy_authority: config.expected_policy_authority,
        expected_authorization_identity: config.expected_authorization_identity,
        signed_pool: config.signed_pool,
        signed_epoch: config.signed_epoch,
        signed_committee_authorization: config.signed_committee_authorization,
        diagnostics,
        nodes: nodes.try_into().map_err(|_| {
            invalid_custody_composition_config(
                "custody-composition routes must cover exactly three selected nodes",
            )
        })?,
    };
    let configured = composition
        .configured_nodes()
        .map_err(|_| invalid_custody_composition_config("configured custody linkage is invalid"))?;
    let resolve = match check {
        MintCompositionCheck::Provision => resolve_runtime_mint_selected_nodes,
        MintCompositionCheck::CompletedReplay => {
            elastos_protected_content_runtime::resolve_recorded_runtime_mint_selected_nodes
        }
    };
    resolve(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        now,
        &configured,
    )
    .map_err(|_| invalid_custody_composition_config("configured custody linkage is invalid"))?;
    Ok((composition, config.bytes))
}

/// Plan B POOL-MINT: the mint refusal when this Home uses no pool. Checked
/// before any media work.
pub(crate) const RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE: &str =
    "This Home can't mint yet: create a custody pool or add one under Pools this Home uses.";

/// STAB-14: how long a mint waits for a pool member's answer. A lost reply
/// then ends well inside the 60 s provisioning statement, so the mint can
/// resend the identical request once before it aborts.
const RUNTIME_POOL_MINT_REPLY_WAIT_MS: u64 = 20_000;

/// The committee of `descriptor`'s pool as a mint composition (Plan B
/// POOL-MINT, "No composition"): the `recorded` epoch for a resumed mint,
/// else its first epoch whose term is open now, with each node
/// bound by `pool_node_owner_state_root` (`ItemMintPath::Pool`) and routed
/// `Local` when this Home holds that node, else to the member's peer DID.
pub(super) fn runtime_custody_composition_for_pool(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    descriptor: &SignedPoolDescriptorAnyV1,
    recorded: Option<elastos_protected_content_contracts::CustodyEpochIdentityV1>,
    now: u64,
) -> anyhow::Result<RuntimeCustodyComposition> {
    // PM-F5: new provisioning needs a descriptor that verifies now and an
    // open term; a recorded mint settles on the descriptor this Home kept for
    // it, under the release rule (no window, no term).
    if recorded.is_none() {
        descriptor
            .verify(now)
            .map_err(|_| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE))?;
    }
    let authority = descriptor.pool().issuer();
    let (bundle, validated) = descriptor
        .epochs()
        .iter()
        .filter(|bundle| recorded.is_none() || bundle.epoch_identity().ok() == recorded)
        .find_map(|bundle| {
            let authorization = bundle
                .signed_committee_authorization()
                .authorization_identity()
                .ok()?;
            let rule = if recorded.is_some() {
                elastos_protected_content_contracts::validate_custody_epoch_for_release_at
            } else {
                validate_custody_epoch_against_pool_at
            };
            rule(
                authority,
                authorization,
                bundle.signed_pool(),
                bundle.signed_epoch(),
                bundle.signed_committee_authorization(),
                now,
            )
            .ok()
            .map(|validated| (bundle, validated))
        })
        .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE))?;
    let epoch = bundle
        .epoch_identity()
        .map_err(|_| anyhow::anyhow!("the pool's custody epoch is invalid"))?;
    let own_nodes = own_custody_node_keys(data_dir)?;
    let diagnostics = RuntimeCustodyCallDiagnostics::default();
    let nodes = validated
        .committee()
        .nodes()
        .iter()
        .map(|node| {
            let key = node.node_public_key();
            let transport = if own_nodes.contains(&key) {
                ProviderInvocationTransport::Local
            } else {
                let peer_did = descriptor
                    .member_peer_did(key)
                    .ok_or_else(|| anyhow::anyhow!("the pool's committee has no route"))?;
                ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                    peer_did: decode_canonical_peer_did(peer_did)?,
                    timeout_ms: None,
                    reply_wait_ms: Some(RUNTIME_POOL_MINT_REPLY_WAIT_MS),
                })
            };
            Ok(RuntimeCustodyCompositionNode {
                node_public_key: key,
                custody_public_key: node.custody_public_key(),
                owner_state_root: elastos_protected_content_runtime::pool_node_owner_state_root(
                    descriptor.pool(),
                    epoch,
                    key,
                ),
                adapter: RuntimeCustodyRegistryAdapter::new(
                    registry.clone(),
                    transport,
                    diagnostics.clone(),
                ),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(RuntimeCustodyComposition {
        expected_policy_authority: authority,
        expected_authorization_identity: bundle
            .signed_committee_authorization()
            .authorization_identity()
            .map_err(|_| anyhow::anyhow!("the pool's committee is invalid"))?,
        signed_pool: bundle.signed_pool().clone(),
        signed_epoch: bundle.signed_epoch().clone(),
        signed_committee_authorization: bundle.signed_committee_authorization().clone(),
        diagnostics,
        nodes: nodes
            .try_into()
            .map_err(|_| anyhow::anyhow!("the pool's committee is not three nodes"))?,
    })
}

pub(super) fn retained_mint_composition_path(
    data_dir: &Path,
    authorization: CustodyCommitteeAuthorizationIdentityV1,
) -> PathBuf {
    runtime_pool_mints_dir(data_dir).join(format!(
        "composition-{}.json",
        hex::encode(authorization.authorization_sha256().as_bytes())
    ))
}

/// Keep the validated bytes used to select the committee before the mint can
/// write its intent. All attempts in that composition share one immutable copy.
pub(super) fn retain_mint_composition(
    data_dir: &Path,
    authorization: CustodyCommitteeAuthorizationIdentityV1,
    bytes: &[u8],
) -> anyhow::Result<()> {
    static RETAIN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = RETAIN_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("the custody composition archive is unavailable"))?;
    let path = retained_mint_composition_path(data_dir, authorization);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let kept = read_owner_only_config_bytes(&path, MAX_CUSTODY_COMPOSITION_BYTES)?;
            anyhow::ensure!(
                kept == bytes,
                "the retained custody composition has different bindings"
            );
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::protected_content_config::ensure_owner_only_dir(
                &runtime_pool_mints_dir(data_dir),
                "runtime pool mints",
            )?;
            write_owner_only_bytes(&path, bytes)
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) fn load_mint_composition_for_intent(
    data_dir: &Path,
    registry: Arc<ProviderRegistry>,
    intent: &RuntimeMintIntent,
    now: u64,
) -> anyhow::Result<RuntimeCustodyComposition> {
    let path = retained_mint_composition_path(data_dir, intent.custody_committee_authorization());
    let check = if intent.completed_mint_id().is_some() {
        MintCompositionCheck::CompletedReplay
    } else {
        MintCompositionCheck::Provision
    };
    let composition =
        match load_custody_composition_at(data_dir, &path, registry.clone(), now, check)? {
            Some((composition, _)) => composition,
            // Attempts created before composition retention use the active file.
            // The journal comparison keeps the existing typed conflict for a
            // changed binding and requires the same completion before replay.
            None => {
                return load_custody_composition_at(
                    data_dir,
                    &runtime_custody_composition_config_path(data_dir),
                    registry,
                    now,
                    check,
                )?
                .map(|(composition, _)| composition)
                .ok_or_else(|| anyhow::anyhow!(RUNTIME_CUSTODY_MINT_NO_POOL_MESSAGE));
            }
        };
    let configured = composition.configured_nodes()?;
    let resolve = match check {
        MintCompositionCheck::Provision => resolve_runtime_mint_selected_nodes,
        MintCompositionCheck::CompletedReplay => {
            elastos_protected_content_runtime::resolve_recorded_runtime_mint_selected_nodes
        }
    };
    let selected = resolve(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        now,
        &configured,
    )?;
    anyhow::ensure!(
        composition.expected_authorization_identity == intent.custody_committee_authorization()
            && composition.signed_pool.pool_identity()? == intent.custody_pool()
            && composition.signed_epoch.epoch_identity()? == intent.custody_epoch()
            && selected
                .iter()
                .map(|node| node.binding())
                .eq(intent.nodes()),
        "the retained custody composition does not match the mint intent"
    );
    Ok(composition)
}

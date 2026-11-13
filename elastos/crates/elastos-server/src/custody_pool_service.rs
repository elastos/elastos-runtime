//! Plan B T3.4: the `custody-pool` runtime provider target.
//!
//! A pool member answers `describe` and the `session.*` ops over Carrier with
//! the gateway-free session server (`elastos-protected-content-runtime`
//! `PoolSessionServer`) behind real adapters: the local decrypt target, the
//! content plane fetched by CID and verified against the full identity, and
//! this node's custody provider for the recipient attestation.
//!
//! The Runtime envelope is checked by the check the custody wrapper uses,
//! with this target and its ops from the custody surface (E12). A refusal
//! goes back as `Ok({status:"error", code})`, so Carrier carries the code
//! inside `{ok:true, result}`; nothing the buyer receives is key material.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

use anyhow::Context as _;
use base64::Engine as _;
use elastos_protected_content_contracts::{
    CanonicalContract, DeliveryPublicKeyBytesV1, Digest32, NodePublicKey, PoolDidV1,
    PoolRecipientAttestationStatementV2, PoolSessionContentKindV1, ProtectedContentBindingV1,
    RightsActionV1, RuntimeOperationIssuerKeyV1, SignedNodeContributionV1,
    SignedPoolRecipientAttestationV2, SignedRuntimeReleaseOperationV2, SignedTerminalReceiptV1,
    VerifiedPoolDescriptorV1, ViewerPartIndexV1, PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES,
};
use elastos_protected_content_provider_contracts::{
    cenc_dash_merkle_audit_path, CencDashMediaIdentityV2, CencFmp4MediaIdentityV1,
    ChunkedPayloadObjectIdentityV1, DecryptProviderRequestV1, DecryptProviderResponseV1,
    PoolCustodyRequestV1, PoolCustodyResponseV1, MAX_VIEWER_MEDIA_PART_BYTES_V1,
};
use elastos_protected_content_runtime::{
    PoolContentIdentityV1, PoolSessionAttestPort, PoolSessionContentPort, PoolSessionContentRefV1,
    PoolSessionDecryptPort, PoolSessionOpenV1, PoolSessionPolicyPort, PoolSessionPrepareV1,
    PoolSessionReadV1, PoolSessionRefusal, PoolSessionServer, PoolSessionSource,
    PoolStagedContentV1, PoolStagedOpenV1, PoolStagedPartV1, RuntimeProviderCallError,
};
use elastos_runtime::provider::{
    Provider, ProviderError, ProviderInvocationTransport, ProviderRegistry, ResourceRequest,
    ResourceResponse,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use crate::custody_release_limits::{
    RuntimeInvocationSource, CUSTODY_NODE_SETTINGS, RUNTIME_LOCAL_ENDPOINT_KEY,
};
use crate::custody_surface::{
    declared_ops, OP_CUSTODY_POOL_DESCRIBE, OP_CUSTODY_POOL_SESSION_CLOSE,
    OP_CUSTODY_POOL_SESSION_OPEN, OP_CUSTODY_POOL_SESSION_PREPARE, OP_CUSTODY_POOL_SESSION_READ,
    OP_CUSTODY_SIGN_POOL_STATEMENT, TARGET_CUSTODY_POOL,
};
use crate::protected_content_runtime::{
    custody_runtime_invocation_source, invoke_decrypt_provider,
    invoke_json_provider_with_transport, protected_content_root, protected_content_segment_path,
    runtime_custody_object_framed_chunk, runtime_custody_object_framed_header,
    runtime_media_dash_init_path, runtime_media_dash_segment_path,
    verify_protected_content_dash_manifest, write_owner_only_bytes, CUSTODY_PROVIDER_ID,
    MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2, PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
    PROTECTED_CONTENT_IDENTITY_PATH, PROTECTED_CONTENT_INIT_PATH,
    PROTECTED_CONTENT_OBJECT_EPC1_PATH,
};

/// Staged session content lives under the protected-content root.
const POOL_SESSIONS_DIR: &str = "pool-sessions";
const STAGED_OBJECT_FILE: &str = "object.epc1";
const INVALID_REQUEST: &str = "invalid_request";
/// The longest CID the wire accepts.
const MAX_CID_BYTES: usize = 256;
/// More contributions than any committee answers with.
const MAX_OPEN_CONTRIBUTIONS: usize = 64;

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// This Home's view of its pools, from its kept or owned descriptor.
pub(crate) struct ServerPoolPolicy {
    data_dir: PathBuf,
    endpoint_did: String,
    runtime_issuer: RuntimeOperationIssuerKeyV1,
    decrypt_ready: Arc<AtomicBool>,
}

impl PoolSessionPolicyPort for ServerPoolPolicy {
    fn descriptor(&self, pool: &PoolDidV1) -> Option<VerifiedPoolDescriptorV1> {
        let now = crate::auth::now_ts();
        crate::custody_pool_descriptor::served_descriptor(&self.data_dir, pool, now)
            .ok()
            .flatten()
            .or_else(|| {
                crate::custody_pool_descriptor::describe(&self.data_dir, pool, now)
                    .ok()
                    .flatten()
                    .and_then(|descriptor| descriptor.verify(now).ok())
            })
    }

    /// Plan B T2.2: that pool's root key (T3.2's `own_node_key(pool)`).
    fn own_node_key(&self, pool: &PoolDidV1) -> Option<NodePublicKey> {
        crate::custody_consent::served_node_public_key(&self.data_dir, pool)
    }

    fn own_endpoint_did(&self) -> &str {
        &self.endpoint_did
    }

    /// The device-derived issuer (E12), not the chain-plane issuer.
    fn own_runtime_issuer(&self) -> RuntimeOperationIssuerKeyV1 {
        self.runtime_issuer
    }

    /// #388 A1: captured once per process; restart-only activation.
    fn host_trusted(&self) -> bool {
        crate::host_trust::host_trusted(&self.data_dir)
    }

    fn decrypt_ready(&self) -> bool {
        self.decrypt_ready.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Decrypt and attestation
// ---------------------------------------------------------------------------

/// The local decrypt target, as the Runtime's decrypt adapter drives it.
pub(crate) struct RegistryPoolDecryptPort {
    registry: Weak<ProviderRegistry>,
}

impl RegistryPoolDecryptPort {
    async fn invoke(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        let registry = self
            .registry
            .upgrade()
            .ok_or(RuntimeProviderCallError::NotDispatched)?;
        invoke_decrypt_provider(registry.as_ref(), request).await
    }
}

#[async_trait::async_trait]
impl PoolSessionDecryptPort for RegistryPoolDecryptPort {
    async fn prepare_recipient_v2(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        self.invoke(request).await
    }

    async fn open_viewer_session_v2(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        self.invoke(request).await
    }

    async fn read_viewer_media_part_sealed(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        self.invoke(request).await
    }

    async fn read_viewer_object_chunk_sealed(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        self.invoke(request).await
    }

    async fn cancel_prepared_recipient(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        self.invoke(request).await
    }

    async fn close_viewer_session(
        &self,
        request: &DecryptProviderRequestV1,
    ) -> Result<DecryptProviderResponseV1, RuntimeProviderCallError> {
        self.invoke(request).await
    }
}

/// This node's custody provider signs the recipient attestation through the
/// Runtime-local `sign_pool_statement` op (L15).
pub(crate) struct CustodyProviderAttestPort {
    registry: Weak<ProviderRegistry>,
}

#[async_trait::async_trait]
impl PoolSessionAttestPort for CustodyProviderAttestPort {
    async fn attest_recipient(
        &self,
        statement: &PoolRecipientAttestationStatementV2,
    ) -> Result<SignedPoolRecipientAttestationV2, PoolSessionRefusal> {
        let registry = self
            .registry
            .upgrade()
            .ok_or(PoolSessionRefusal::NotReady)?;
        let request = PoolCustodyRequestV1::new_sign_recipient_attestation(statement)
            .map_err(|_| PoolSessionRefusal::BindingMismatch)?;
        let request: Value = request
            .to_json_vec()
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or(PoolSessionRefusal::BindingMismatch)?;
        // A node without the item's share refuses (`unknown_envelope`): it
        // cannot serve this item.
        let data = invoke_json_provider_with_transport(
            registry.as_ref(),
            CUSTODY_PROVIDER_ID,
            OP_CUSTODY_SIGN_POOL_STATEMENT,
            request,
            ProviderInvocationTransport::Local,
        )
        .await
        .map_err(|_| PoolSessionRefusal::NotEligible)?;
        let response = serde_json::to_vec(&data)
            .ok()
            .and_then(|bytes| PoolCustodyResponseV1::from_json_slice(&bytes).ok())
            .ok_or(PoolSessionRefusal::NotEligible)?;
        let signature = response
            .statement_signature()
            .map_err(|_| PoolSessionRefusal::NotEligible)?;
        let attestation =
            SignedPoolRecipientAttestationV2::new(statement.clone(), signature.to_vec())
                .map_err(|_| PoolSessionRefusal::NotEligible)?;
        attestation
            .verify_node_signature()
            .map_err(|_| PoolSessionRefusal::NotEligible)?;
        Ok(attestation)
    }
}

// ---------------------------------------------------------------------------
// Content
// ---------------------------------------------------------------------------

/// Where the content port reads published files: the content plane, local
/// store first, then Carrier holders. A seam, so the content contract is
/// tested without a content provider.
#[async_trait::async_trait]
pub(crate) trait PoolContentSource: Send + Sync {
    async fn bytes(&self, cid: &str, path: &str, cap: Option<usize>) -> anyhow::Result<Vec<u8>>;
}

pub(crate) struct RegistryContentSource {
    registry: Weak<ProviderRegistry>,
}

#[async_trait::async_trait]
impl PoolContentSource for RegistryContentSource {
    async fn bytes(&self, cid: &str, path: &str, cap: Option<usize>) -> anyhow::Result<Vec<u8>> {
        let registry = self
            .registry
            .upgrade()
            .context("the content plane has stopped")?;
        match cap {
            Some(cap) => {
                crate::content::fetch_bytes_via_provider_capped(
                    registry.as_ref(),
                    cid,
                    Some(path),
                    cap,
                )
                .await
            }
            None => {
                crate::content::fetch_bytes_via_provider(registry.as_ref(), cid, Some(path)).await
            }
        }
    }
}

fn content_unavailable<E>(_: E) -> PoolSessionRefusal {
    PoolSessionRefusal::ContentUnavailable
}

#[derive(Clone)]
struct Stage {
    cid: String,
    identity: PoolContentIdentityV1,
    /// DASH: the verified Merkle leaves per rendition; they stay here.
    leaves: Vec<Vec<Digest32>>,
}

/// T3.2's content contract (F4) over the content plane: `stage` fetches by
/// CID and verifies against the full identity, as the open's fetch helpers
/// do; `part` serves one part's material, with the DASH proof from the
/// verified leaves. An object is staged once, under
/// `protected-content/pool-sessions/<session>/`, and removed at discard.
pub(crate) struct ContentPlanePoolContentPort<S> {
    source: S,
    root: PathBuf,
    stages: Mutex<BTreeMap<[u8; 16], Stage>>,
}

impl<S: PoolContentSource> ContentPlanePoolContentPort<S> {
    pub(crate) fn new(source: S, root: PathBuf) -> Self {
        Self {
            source,
            root,
            stages: Mutex::new(BTreeMap::new()),
        }
    }

    fn session_dir(&self, session_id: [u8; 16]) -> PathBuf {
        self.root.join(hex::encode(session_id))
    }

    async fn verified_object(
        &self,
        cid: &str,
        identity: &ChunkedPayloadObjectIdentityV1,
    ) -> Result<Vec<u8>, PoolSessionRefusal> {
        let framed = self
            .source
            .bytes(cid, PROTECTED_CONTENT_OBJECT_EPC1_PATH, None)
            .await
            .map_err(|_| PoolSessionRefusal::ContentUnavailable)?;
        if framed.len() as u64 != identity.encrypted_content().ciphertext_bytes()
            || Digest32::new(Sha256::digest(&framed).into())
                != identity.encrypted_content().ciphertext_sha256()
        {
            return Err(PoolSessionRefusal::ContentUnavailable);
        }
        Ok(framed)
    }

    async fn stage_media(
        &self,
        cid: &str,
        identity: &CencFmp4MediaIdentityV1,
    ) -> Result<PoolStagedOpenV1, PoolSessionRefusal> {
        let published = self
            .source
            .bytes(cid, PROTECTED_CONTENT_IDENTITY_PATH, None)
            .await
            .map_err(content_unavailable)?;
        if CencFmp4MediaIdentityV1::from_canonical_bytes(&published)
            .ok()
            .as_ref()
            != Some(identity)
        {
            return Err(PoolSessionRefusal::ContentUnavailable);
        }
        let init = self
            .source
            .bytes(
                cid,
                PROTECTED_CONTENT_INIT_PATH,
                Some(MAX_VIEWER_MEDIA_PART_BYTES_V1),
            )
            .await
            .map_err(content_unavailable)?;
        if init.len() as u64 != identity.init_segment_bytes()
            || Digest32::new(Sha256::digest(&init).into()) != identity.init_segment_sha256()
        {
            return Err(PoolSessionRefusal::ContentUnavailable);
        }
        Ok(PoolStagedOpenV1::MediaV1 {
            protected_init: init,
        })
    }

    async fn stage_dash(
        &self,
        cid: &str,
        head: &CencDashMediaIdentityV2,
    ) -> Result<(PoolStagedOpenV1, Vec<Vec<Digest32>>), PoolSessionRefusal> {
        let manifest = self
            .source
            .bytes(cid, crate::content::CONTENT_OBJECT_MANIFEST_PATH, None)
            .await
            .map_err(content_unavailable)?;
        let manifest = crate::content::parse_content_object_manifest(cid, &manifest)
            .map_err(content_unavailable)?;
        let leaves =
            verify_protected_content_dash_manifest(&manifest, head).map_err(content_unavailable)?;
        let mut inits = Vec::with_capacity(head.renditions().len());
        for rendition in head.renditions() {
            let init = self
                .source
                .bytes(
                    cid,
                    &runtime_media_dash_init_path(rendition.kind()),
                    Some(MAX_VIEWER_MEDIA_PART_BYTES_V1),
                )
                .await
                .map_err(content_unavailable)?;
            if init.len() as u64 != rendition.init_segment_bytes()
                || Digest32::new(Sha256::digest(&init).into()) != rendition.init_segment_sha256()
            {
                return Err(PoolSessionRefusal::ContentUnavailable);
            }
            inits.push(init);
        }
        Ok((
            PoolStagedOpenV1::DashV2 {
                protected_inits: inits,
            },
            leaves,
        ))
    }
}

#[async_trait::async_trait]
impl<S: PoolContentSource> PoolSessionContentPort for ContentPlanePoolContentPort<S> {
    async fn stage(
        &self,
        session_id: [u8; 16],
        content: &PoolSessionContentRefV1,
        binding: &ProtectedContentBindingV1,
    ) -> Result<PoolStagedContentV1, PoolSessionRefusal> {
        if content.identity.encrypted_content() != binding.encrypted_content()
            || content.cid.is_empty()
            || content.cid.len() > MAX_CID_BYTES
        {
            return Err(PoolSessionRefusal::ContentUnavailable);
        }
        let cid = content.cid.as_str();
        let (open, leaves) = match &content.identity {
            PoolContentIdentityV1::MediaV1(identity) => {
                (self.stage_media(cid, identity).await?, Vec::new())
            }
            PoolContentIdentityV1::DashV2(head) => self.stage_dash(cid, head).await?,
            PoolContentIdentityV1::Object(identity) => {
                let framed = self.verified_object(cid, identity).await?;
                let header = runtime_custody_object_framed_header(&framed, identity)
                    .map_err(|_| PoolSessionRefusal::ContentUnavailable)?;
                // The write makes the owner-only session directory first.
                write_owner_only_bytes(
                    &self.session_dir(session_id).join(STAGED_OBJECT_FILE),
                    &framed,
                )
                .map_err(|error| {
                    tracing::warn!(
                        error = %format!("{error:#}"),
                        "a pool session object was not staged"
                    );
                    PoolSessionRefusal::ContentUnavailable
                })?;
                (
                    PoolStagedOpenV1::Object {
                        framed_header: header,
                    },
                    Vec::new(),
                )
            }
        };
        self.stages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                session_id,
                Stage {
                    cid: content.cid.clone(),
                    identity: content.identity.clone(),
                    leaves,
                },
            );
        Ok(PoolStagedContentV1 {
            handle: session_id,
            total_ciphertext_bytes: content.identity.encrypted_content().ciphertext_bytes(),
            duration_secs: None,
            open,
        })
    }

    async fn part(
        &self,
        staged: &PoolStagedContentV1,
        part: &ViewerPartIndexV1,
    ) -> Result<PoolStagedPartV1, PoolSessionRefusal> {
        let stage = self
            .stages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&staged.handle)
            .cloned()
            .ok_or(PoolSessionRefusal::UnknownSession)?;
        match (*part, &stage.identity) {
            (ViewerPartIndexV1::MediaV1Init, PoolContentIdentityV1::MediaV1(_)) => {
                Ok(PoolStagedPartV1::MediaV1Init)
            }
            (
                ViewerPartIndexV1::MediaV1Segment(index),
                PoolContentIdentityV1::MediaV1(identity),
            ) => {
                let position = usize::try_from(index).map_err(content_unavailable)?;
                if position >= identity.encrypted_segments().len() {
                    return Err(PoolSessionRefusal::ContentUnavailable);
                }
                let encrypted = self
                    .source
                    .bytes(
                        &stage.cid,
                        &protected_content_segment_path(position),
                        Some(MAX_VIEWER_MEDIA_PART_BYTES_V1),
                    )
                    .await
                    .map_err(content_unavailable)?;
                if encrypted.is_empty() || encrypted.len() > MAX_VIEWER_MEDIA_PART_BYTES_V1 {
                    return Err(PoolSessionRefusal::ContentUnavailable);
                }
                Ok(PoolStagedPartV1::MediaV1Segment { index, encrypted })
            }
            (ViewerPartIndexV1::DashInit { rendition }, PoolContentIdentityV1::DashV2(head))
                if usize::from(rendition) < head.renditions().len() =>
            {
                Ok(PoolStagedPartV1::DashInit { rendition })
            }
            (
                ViewerPartIndexV1::DashSegment { rendition, index },
                PoolContentIdentityV1::DashV2(head),
            ) => {
                let identity = head
                    .renditions()
                    .get(usize::from(rendition))
                    .ok_or(PoolSessionRefusal::ContentUnavailable)?;
                if index >= identity.segment_count() {
                    return Err(PoolSessionRefusal::ContentUnavailable);
                }
                let encrypted = self
                    .source
                    .bytes(
                        &stage.cid,
                        &runtime_media_dash_segment_path(identity.kind(), index),
                        Some(MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2),
                    )
                    .await
                    .map_err(content_unavailable)?;
                if encrypted.is_empty()
                    || encrypted.len() > MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2
                {
                    return Err(PoolSessionRefusal::ContentUnavailable);
                }
                let leaves = stage
                    .leaves
                    .get(usize::from(rendition))
                    .ok_or(PoolSessionRefusal::ContentUnavailable)?;
                let proof = cenc_dash_merkle_audit_path(
                    leaves,
                    usize::try_from(index).map_err(content_unavailable)?,
                )
                .map_err(content_unavailable)?;
                Ok(PoolStagedPartV1::DashSegment {
                    rendition,
                    index,
                    encrypted,
                    proof,
                })
            }
            (ViewerPartIndexV1::ObjectChunk(index), PoolContentIdentityV1::Object(identity)) => {
                let staged_path = self.session_dir(staged.handle).join(STAGED_OBJECT_FILE);
                let cap = usize::try_from(identity.encrypted_content().ciphertext_bytes())
                    .map_err(content_unavailable)?;
                let framed = match crate::collaboration_config::read_owner_only_file(
                    &staged_path,
                    cap,
                    "pool session object",
                ) {
                    Ok(framed) => framed,
                    // The stage is gone, as after a restart: fetch and verify again.
                    Err(_) => self.verified_object(&stage.cid, identity).await?,
                };
                let framed_chunk = runtime_custody_object_framed_chunk(&framed, identity, index)
                    .map_err(content_unavailable)?;
                Ok(PoolStagedPartV1::ObjectChunk {
                    index,
                    framed_chunk,
                })
            }
            _ => Err(PoolSessionRefusal::ContentUnavailable),
        }
    }

    fn discard(&self, session_id: [u8; 16]) {
        self.stages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&session_id);
        match std::fs::remove_dir_all(self.session_dir(session_id)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(%error, "a pool session stage was not removed"),
        }
    }
}

// ---------------------------------------------------------------------------
// The provider
// ---------------------------------------------------------------------------

pub(crate) struct CustodyPoolServiceProvider<P, D, C, A> {
    server: PoolSessionServer<P, D, C, A>,
    data_dir: PathBuf,
    decrypt_ready: Arc<AtomicBool>,
    /// Where readiness is read; `None` keeps the flag as set (tests).
    registry: Option<Weak<ProviderRegistry>>,
    /// Unix seconds; the wall clock outside tests.
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl<P, D, C, A> CustodyPoolServiceProvider<P, D, C, A>
where
    P: PoolSessionPolicyPort,
    D: PoolSessionDecryptPort,
    C: PoolSessionContentPort,
    A: PoolSessionAttestPort,
{
    pub(crate) fn new(
        server: PoolSessionServer<P, D, C, A>,
        data_dir: PathBuf,
        decrypt_ready: Arc<AtomicBool>,
        registry: Option<Weak<ProviderRegistry>>,
    ) -> Self {
        Self {
            server,
            data_dir,
            decrypt_ready,
            registry,
            clock: Arc::new(crate::auth::now_ts),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_clock(mut self, clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    async fn refresh_readiness(&self) {
        if let Some(registry) = self.registry.as_ref().and_then(Weak::upgrade) {
            let ready = registry
                .has_ready_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)
                .await;
            self.decrypt_ready.store(ready, Ordering::SeqCst);
        }
    }

    async fn answer(
        &self,
        op: &str,
        request: &Value,
        source: &PoolSessionSource,
    ) -> Result<Value, &'static str> {
        let now = (self.clock)();
        let refusal = |refusal: PoolSessionRefusal| refusal.code();
        match op {
            OP_CUSTODY_POOL_DESCRIBE => {
                let pool = pool_field(request)?;
                let descriptor =
                    crate::custody_pool_descriptor::describe(&self.data_dir, &pool, now)
                        .map_err(|_| PoolSessionRefusal::NotReady.code())?
                        .ok_or(PoolSessionRefusal::NotEligible.code())?;
                Ok(
                    json!({ "descriptor_b64": b64(&descriptor.canonical_bytes().map_err(|_| INVALID_REQUEST)?) }),
                )
            }
            OP_CUSTODY_POOL_SESSION_PREPARE => {
                let prepared = self
                    .server
                    .prepare(prepare_request(request)?, source, now)
                    .await
                    .map_err(refusal)?;
                Ok(json!({
                    "session_id_hex": hex::encode(prepared.session_id),
                    "recipient_public_key_b64": b64(prepared.recipient_public_key.as_bytes()),
                    "attestation_b64": b64(&prepared.attestation.canonical_bytes().map_err(|_| INVALID_REQUEST)?),
                }))
            }
            OP_CUSTODY_POOL_SESSION_OPEN => {
                let opened = self
                    .server
                    .open(open_request(request)?, source, now)
                    .await
                    .map_err(refusal)?;
                Ok(json!({ "expires_at": opened.expires_at }))
            }
            OP_CUSTODY_POOL_SESSION_READ => {
                let sealed = self
                    .server
                    .read(read_request(request)?, source, now)
                    .await
                    .map_err(refusal)?;
                Ok(json!({ "sealed_b64": b64(&sealed) }))
            }
            OP_CUSTODY_POOL_SESSION_CLOSE => {
                self.server
                    .close(session_id_field(request)?, source)
                    .await
                    .map_err(refusal)?;
                Ok(json!({}))
            }
            _ => Err(INVALID_REQUEST),
        }
    }
}

#[async_trait::async_trait]
impl<P, D, C, A> Provider for CustodyPoolServiceProvider<P, D, C, A>
where
    P: PoolSessionPolicyPort + 'static,
    D: PoolSessionDecryptPort + 'static,
    C: PoolSessionContentPort + 'static,
    A: PoolSessionAttestPort + 'static,
{
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "the custody-pool target does not expose resources".into(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![TARGET_CUSTODY_POOL]
    }

    fn name(&self) -> &'static str {
        "custody-pool-service"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let mut value = request.clone();
        let object = value.as_object_mut().ok_or_else(|| {
            ProviderError::Provider("custody-pool request must be an object".into())
        })?;
        if object.contains_key("_runtime_transfer") || object.contains_key("carrier") {
            return Err(ProviderError::Provider(
                "custody-pool request contains unsupported injected data".into(),
            ));
        }
        let op = object
            .get("op")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Provider("custody-pool request is missing op".into()))?
            .to_owned();
        if !declared_ops(TARGET_CUSTODY_POOL).any(|declared| declared == op) {
            return Err(ProviderError::Provider(
                "custody-pool request op is unsupported".into(),
            ));
        }
        let source = match custody_runtime_invocation_source(object, TARGET_CUSTODY_POOL, &op)? {
            RuntimeInvocationSource::Local => PoolSessionSource {
                endpoint_did: RUNTIME_LOCAL_ENDPOINT_KEY.to_string(),
                local: true,
            },
            RuntimeInvocationSource::Carrier {
                source_endpoint_did,
            } => PoolSessionSource {
                endpoint_did: source_endpoint_did,
                local: false,
            },
        };
        self.refresh_readiness().await;
        Ok(match self.answer(&op, &value, &source).await {
            Ok(data) => json!({ "status": "ok", "data": data }),
            Err(code) => {
                // OPEN-LOOP F2: an operator sees why a pool open failed; the
                // op and the code only, never a field of the request.
                tracing::warn!(%op, %code, "custody-pool request refused");
                json!({ "status": "error", "code": code })
            }
        })
    }
}

/// Registers this Home's `custody-pool` target, with the device-derived
/// issuer and this Home's DID as its own endpoint.
pub(crate) async fn register_custody_pool_service(
    registry: &Arc<ProviderRegistry>,
    data_dir: &Path,
) -> anyhow::Result<()> {
    let (device_key, _) =
        crate::collaboration_profile_authority::load_existing_device_signing_key(data_dir)?
            .context("this Home has no device key")?;
    let runtime_issuer = RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())
        .map_err(|error| anyhow::anyhow!("this Home's device key is invalid: {error:?}"))?;
    let (_, endpoint_did) = elastos_identity::load_existing_did(data_dir)?;
    let decrypt_ready = Arc::new(AtomicBool::new(false));
    let weak = Arc::downgrade(registry);
    let server = PoolSessionServer::new(
        ServerPoolPolicy {
            data_dir: data_dir.to_path_buf(),
            endpoint_did,
            runtime_issuer,
            decrypt_ready: decrypt_ready.clone(),
        },
        RegistryPoolDecryptPort {
            registry: weak.clone(),
        },
        ContentPlanePoolContentPort::new(
            RegistryContentSource {
                registry: weak.clone(),
            },
            protected_content_root(data_dir).join(POOL_SESSIONS_DIR),
        ),
        CustodyProviderAttestPort {
            registry: weak.clone(),
        },
    )
    .with_node_budget(CUSTODY_NODE_SETTINGS.pool_sessions_per_node);
    let provider: Arc<dyn Provider> = Arc::new(CustodyPoolServiceProvider::new(
        server,
        data_dir.to_path_buf(),
        decrypt_ready,
        Some(weak),
    ));
    registry
        .register_runtime_provider_target(TARGET_CUSTODY_POOL, provider)
        .await
        .map_err(|error| anyhow::anyhow!("failed to register the custody-pool target: {error}"))
}

// ---------------------------------------------------------------------------
// Wire
// ---------------------------------------------------------------------------

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn str_field<'a>(value: &'a Value, field: &str) -> Result<&'a str, &'static str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(INVALID_REQUEST)
}

fn b64_field(value: &Value, field: &str) -> Result<Vec<u8>, &'static str> {
    base64::engine::general_purpose::STANDARD
        .decode(str_field(value, field)?)
        .map_err(|_| INVALID_REQUEST)
}

fn contract_field<T: CanonicalContract>(value: &Value, field: &str) -> Result<T, &'static str> {
    T::from_canonical_bytes(&b64_field(value, field)?).map_err(|_| INVALID_REQUEST)
}

fn pool_field(value: &Value) -> Result<PoolDidV1, &'static str> {
    PoolDidV1::parse_did_key(str_field(value, "pool")?).map_err(|_| INVALID_REQUEST)
}

fn session_id_field(value: &Value) -> Result<[u8; 16], &'static str> {
    hex::decode(str_field(value, "session_id_hex")?)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(INVALID_REQUEST)
}

fn rights_action(code: u64) -> Result<RightsActionV1, &'static str> {
    [
        RightsActionV1::View,
        RightsActionV1::Stream,
        RightsActionV1::Download,
        RightsActionV1::Execute,
    ]
    .into_iter()
    .find(|action| u64::from(*action as u8) == code)
    .ok_or(INVALID_REQUEST)
}

/// The wire name of a content kind, as `session.prepare` carries it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn content_kind_name(kind: PoolSessionContentKindV1) -> &'static str {
    match kind {
        PoolSessionContentKindV1::MediaV1 => "media_v1",
        PoolSessionContentKindV1::DashV2 => "dash_v2",
        PoolSessionContentKindV1::Object => "object",
    }
}

fn prepare_request(value: &Value) -> Result<PoolSessionPrepareV1, &'static str> {
    let content = value.get("content").ok_or(INVALID_REQUEST)?;
    let kind = match str_field(content, "kind")? {
        "media_v1" => PoolSessionContentKindV1::MediaV1,
        "dash_v2" => PoolSessionContentKindV1::DashV2,
        "object" => PoolSessionContentKindV1::Object,
        _ => return Err(INVALID_REQUEST),
    };
    // The identity decodes as the kind the wire names; T3.2 then checks the
    // two agree and that the identity is the binding's content (F4).
    let identity = match kind {
        PoolSessionContentKindV1::MediaV1 => {
            PoolContentIdentityV1::MediaV1(contract_field(content, "identity_b64")?)
        }
        PoolSessionContentKindV1::DashV2 => {
            PoolContentIdentityV1::DashV2(contract_field(content, "identity_b64")?)
        }
        PoolSessionContentKindV1::Object => {
            PoolContentIdentityV1::Object(contract_field(content, "identity_b64")?)
        }
    };
    let commitment: [u8; 32] = b64_field(content, "content_key_commitment_b64")?
        .try_into()
        .map_err(|_| INVALID_REQUEST)?;
    let issuer: [u8; 32] = hex::decode(str_field(value, "runtime_operation_issuer_hex")?)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(INVALID_REQUEST)?;
    let cid = str_field(content, "cid")?;
    if cid.is_empty() || cid.len() > MAX_CID_BYTES {
        return Err(INVALID_REQUEST);
    }
    Ok(PoolSessionPrepareV1 {
        pool: pool_field(value)?,
        binding: contract_field(value, "binding_b64")?,
        action: rights_action(
            value
                .get("action")
                .and_then(Value::as_u64)
                .ok_or(INVALID_REQUEST)?,
        )?,
        runtime_operation_issuer: RuntimeOperationIssuerKeyV1::new(issuer)
            .map_err(|_| INVALID_REQUEST)?,
        content: PoolSessionContentRefV1 {
            cid: cid.to_string(),
            kind,
            identity,
            content_key_commitment: Digest32::new(commitment),
        },
        expires_at: value
            .get("expires_at")
            .and_then(Value::as_u64)
            .ok_or(INVALID_REQUEST)?,
    })
}

fn open_request(value: &Value) -> Result<PoolSessionOpenV1, &'static str> {
    let delivery: [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] =
        b64_field(value, "delivery_public_key_b64")?
            .try_into()
            .map_err(|_| INVALID_REQUEST)?;
    let contributions = value
        .get("contributions_b64")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty() && items.len() <= MAX_OPEN_CONTRIBUTIONS)
        .ok_or(INVALID_REQUEST)?
        .iter()
        .map(|item| {
            let text = item.as_str().ok_or(INVALID_REQUEST)?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(text)
                .map_err(|_| INVALID_REQUEST)?;
            SignedNodeContributionV1::from_canonical_bytes(&bytes).map_err(|_| INVALID_REQUEST)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PoolSessionOpenV1 {
        session_id: session_id_field(value)?,
        operation: contract_field::<SignedRuntimeReleaseOperationV2>(value, "operation_v2_b64")?,
        delivery_public_key: DeliveryPublicKeyBytesV1::new(delivery)
            .map_err(|_| INVALID_REQUEST)?,
        contributions,
        terminal_receipt: contract_field::<SignedTerminalReceiptV1>(value, "terminal_receipt_b64")?,
    })
}

fn read_request(value: &Value) -> Result<PoolSessionReadV1, &'static str> {
    let part = value.get("part").ok_or(INVALID_REQUEST)?;
    let index = || {
        part.get("index")
            .and_then(Value::as_u64)
            .and_then(|index| u32::try_from(index).ok())
            .ok_or(INVALID_REQUEST)
    };
    let rendition = || {
        part.get("rendition")
            .and_then(Value::as_u64)
            .and_then(|rendition| u8::try_from(rendition).ok())
            .ok_or(INVALID_REQUEST)
    };
    let part = match str_field(part, "kind")? {
        "media_v1_init" => ViewerPartIndexV1::MediaV1Init,
        "media_v1_segment" => ViewerPartIndexV1::MediaV1Segment(index()?),
        "dash_init" => ViewerPartIndexV1::DashInit {
            rendition: rendition()?,
        },
        "dash_segment" => ViewerPartIndexV1::DashSegment {
            rendition: rendition()?,
            index: index()?,
        },
        "object_chunk" => ViewerPartIndexV1::ObjectChunk(index()?),
        _ => return Err(INVALID_REQUEST),
    };
    Ok(PoolSessionReadV1 {
        session_id: session_id_field(value)?,
        part,
    })
}

#[cfg(all(test, unix))]
mod tests;

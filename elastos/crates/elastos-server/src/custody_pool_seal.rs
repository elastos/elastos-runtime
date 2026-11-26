//! Runtime authority for admitting an upload at the selected custody root.
//! The custody service obtains the source from the Carrier connection.

mod service;
pub(crate) mod storage;
pub(crate) use service::RemoteObjectSealService;
use storage::RemoteSealStorage;

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use elastos_protected_content_contracts::{
    CanonicalContract, ClearLayoutV1, ClearPartIndexV1, CustodyEnvelopeV1,
    CustodyNodeProvisioningRecordIdentityV1, EncryptedContentIdentityV1, KeyEnvelopeIdentityV1,
    NodePublicKey, PoolMemberRouteV2, RemoteShareAdmissionV1, RuntimeOperationIssuerKeyV1,
    SealCompletedV1, SealSessionAttestationV1, SignedMintRequestV1, SignedPoolDescriptorAnyV1,
    SignedPoolProvisioningAuthorizationV1, SignedSealCompletedV1, SignedSealSessionAttestationV1,
    MAX_KEY_ENVELOPE_BYTES,
};
use elastos_protected_content_provider_contracts::{
    AuthorizeRemoteSealShareReplyV1, AuthorizeRemoteSealShareRequestV1, CencDashRenditionKindV2,
    CencMediaSuite, ChunkedPayloadObjectIdentityV1, CustodyProtectionHeader,
    FinalizeRemoteDashSealRequestV1, FinalizeRemoteObjectSealReplyV1,
    FinalizeRemoteObjectSealRequestV1, OpenRemoteDashSealReplyV1, OpenRemoteDashSealRequestV1,
    OpenRemoteObjectSealReplyV1, OpenRemoteObjectSealRequestV1, RemoteObjectSealTransferV1,
    RemoteSealAttestationReplyV1, RemoteSealAttestationRequestV1, RemoteShareDeliveryV1,
    RemoteShareProvisionReplyV1, RemoteShareProvisionRequestV1, SignRemoteSealCompletionReplyV1,
    SignRemoteSealCompletionRequestV1, TransferRemoteDashSealRequestV1,
    TransferRemoteObjectSealReplyV1, TransferRemoteObjectSealRequestV1,
    ATTEST_REMOTE_SEAL_UPLOAD_OP, AUTHORIZE_REMOTE_SEAL_SHARE_OP, FINALIZE_REMOTE_DASH_SEAL_OP,
    FINALIZE_REMOTE_OBJECT_SEAL_OP, MAX_OBJECT_FRAMED_CHUNK_BYTES_V1,
    MAX_OBJECT_FRAMED_HEADER_BYTES_V1, MAX_PROTECT_MEDIA_PART_BYTES_V1,
    MAX_REMOTE_SEAL_COMPLETION_BYTES_V1, OPEN_REMOTE_DASH_SEAL_OP, OPEN_REMOTE_OBJECT_SEAL_OP,
    SIGN_REMOTE_SEAL_COMPLETION_OP, TRANSFER_REMOTE_DASH_SEAL_OP, TRANSFER_REMOTE_OBJECT_SEAL_OP,
};
use elastos_protected_content_runtime::{
    prepare_remote_share_provision_request, PoolCallClass, PoolSessionSource,
    RuntimeContentAvailabilityRequirement, RuntimeContentIdentityV1,
};
use elastos_runtime::provider::{ProviderInvocationTransport, ProviderRegistry};

use crate::custody_consent::{self, RootTrust};
use crate::custody_pool_descriptor;
use crate::custody_seal_completion::SealerCompletionStore;
use crate::custody_surface::{OP_CUSTODY_PROVISION_POOL_NODE_SHARE, TARGET_CUSTODY};
use crate::protected_content_runtime::{
    invoke_json_provider_classified, invoke_json_provider_with_transport,
    publish_remote_sealed_content, rebuild_staged_remote_dash, runtime_media_dash_init_path,
    runtime_media_dash_segment_path, runtime_protected_content_id, sha256_file,
    write_protected_content_object_manifest, ProviderInvocationFailure,
    MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2, PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
    PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS, PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET,
    PROTECTED_CONTENT_OBJECT_EPC1_PATH, PROTECTED_CONTENT_REPLICATION_POLICY, PROTECT_PROVIDER_ID,
};

/// Authorities captured at Open and carried unchanged to publication.
pub struct RemoteSealOpenAuthority {
    pub descriptor: SignedPoolDescriptorAnyV1,
    pub node: NodePublicKey,
    pub minter: RuntimeOperationIssuerKeyV1,
    pub publisher_did: String,
    pub root_path: String,
    source: PoolSessionSource,
}

pub struct OpenedRemoteObjectUpload {
    pub attestation: SignedSealSessionAttestationV1,
    pub framed_header: Vec<u8>,
}

/// Runtime's side of a single upload. An unanswered private provider call
/// keeps the exact command and sequence until Runtime can settle it.
pub struct RemoteObjectUploadStaging {
    pub attestation: SignedSealSessionAttestationV1,
    source: PoolSessionSource,
    publisher_did: String,
    root_path: String,
    descriptor: SignedPoolDescriptorAnyV1,
    request: SignedMintRequestV1,
    media: StagedUpload,
    storage: Arc<RemoteSealStorage>,
    staged_part_bytes: u64,
    last_staged: Option<ClearPartIndexV1>,
    sequence: u32,
    pending: Option<RemoteObjectSealTransferV1>,
    staging_failed: bool,
    delivered_shares: BTreeMap<NodePublicKey, VerifiedRemoteShareReceipt>,
    published_statement: Option<SealCompletedV1>,
}

enum StagedUpload {
    Object {
        file: File,
        framed_header_bytes: u32,
    },
    Dash,
}

#[derive(Clone, Copy)]
pub struct VerifiedRemoteShareReceipt {
    node: NodePublicKey,
    record: CustodyNodeProvisioningRecordIdentityV1,
}

impl VerifiedRemoteShareReceipt {
    pub(crate) fn matches(
        &self,
        node: NodePublicKey,
        record: CustodyNodeProvisioningRecordIdentityV1,
    ) -> bool {
        self.node == node && self.record == record
    }

    #[cfg(test)]
    pub(crate) fn from_local_store(
        receipt: &elastos_protected_content_custody::NodeLocalShareReceiptV1,
    ) -> Self {
        Self {
            node: receipt.selected_node_public_key(),
            record: receipt.record_identity(),
        }
    }
}

pub struct FinalizedRemoteObjectUpload {
    identity: RuntimeContentIdentityV1,
    envelope: CustodyEnvelopeV1,
    session_id: [u8; 16],
}

impl FinalizedRemoteObjectUpload {
    #[cfg(test)]
    pub fn object(&self) -> &ChunkedPayloadObjectIdentityV1 {
        let RuntimeContentIdentityV1::Object(object) = &self.identity else {
            panic!("expected object fixture")
        };
        object
    }
}

impl RemoteObjectUploadStaging {
    pub fn directory(&self) -> &Path {
        self.storage.directory()
    }

    /// Deliver the exact finalized envelope to every member of its
    /// committee. Keep verified receipts with the upload so a retry only
    /// resends unresolved recipients.
    pub async fn deliver_shares(
        &mut self,
        data_dir: &Path,
        registry: &Arc<ProviderRegistry>,
        finalized: &FinalizedRemoteObjectUpload,
    ) -> anyhow::Result<&BTreeMap<NodePublicKey, VerifiedRemoteShareReceipt>> {
        anyhow::ensure!(
            finalized.session_id == self.attestation.session_id(),
            "seal_finalize_binding_mismatch"
        );
        let (device_key, local_endpoint) = elastos_identity::load_existing_did(data_dir)?;
        let sealer = self.attestation.sealer_node_public_key();
        anyhow::ensure!(
            self.descriptor.member_peer_did(sealer) == Some(local_endpoint.as_str()),
            "seal_sealer_source_mismatch"
        );
        let mut outstanding = Vec::new();
        let tickets = crate::custody_pool_setup::kept_card_tickets(data_dir);
        for node in finalized.envelope.manifest().nodes() {
            let recipient = node.node_public_key();
            if self.delivered_shares.contains_key(&recipient) {
                continue;
            }
            let peer = self
                .descriptor
                .member_peer_did(recipient)
                .ok_or_else(|| anyhow::anyhow!("seal_recipient_route_missing"))?;
            let transport = if peer == local_endpoint {
                ProviderInvocationTransport::Local
            } else {
                let route = PoolMemberRouteV2::new(peer.to_owned())?;
                ProviderInvocationTransport::Carrier(
                    crate::custody_pool_resolver::carrier_route_for(
                        &route,
                        PoolCallClass::Control,
                        &tickets,
                    ),
                )
            };
            outstanding.push((recipient, transport));
        }
        if outstanding.is_empty() {
            return Ok(&self.delivered_shares);
        }
        let issuer = RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())?;
        let identity = finalized.envelope.key_envelope_identity()?;
        let authorization = self
            .authorize_share_delivery(registry, issuer, &identity)
            .await?;
        let admission = RemoteShareAdmissionV1 {
            descriptor: self.descriptor.clone(),
            request: self.request.clone(),
            authorization,
        };
        let now = crate::auth::now_ts();
        let sign = |bytes: &[u8]| device_key.sign(bytes).to_bytes();
        let jobs = outstanding
            .into_iter()
            .map(|(recipient, transport)| {
                let request = prepare_remote_share_provision_request(
                    admission.clone(),
                    &finalized.envelope,
                    recipient,
                    &sign,
                    now,
                )?;
                Ok((recipient, transport, request))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let mut sends = tokio::task::JoinSet::new();
        for (recipient, transport, request) in jobs {
            let registry = Arc::clone(registry);
            let send = async move {
                let receipt = deliver_remote_share(&registry, &request, transport).await?;
                Ok::<_, anyhow::Error>((recipient, receipt))
            };
            match elastos_runtime::provider::dispatch::DispatchFence::current() {
                Some(fence) => sends.spawn(async move { fence.scope(send).await }),
                None => sends.spawn(send),
            };
        }
        let mut failure = None;
        while let Some(result) = sends.join_next().await {
            match result {
                Ok(Ok((recipient, receipt))) => {
                    self.delivered_shares.insert(recipient, receipt);
                }
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Err(error) => {
                    failure.get_or_insert(error.into());
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(&self.delivered_shares)
    }

    /// Make the package available only once every share has its exact receipt.
    /// The statement is ready for custody to sign after publication is verified.
    pub async fn publish(
        &self,
        data_dir: &Path,
        registry: &ProviderRegistry,
        finalized: &FinalizedRemoteObjectUpload,
    ) -> anyhow::Result<SealCompletedV1> {
        anyhow::ensure!(
            finalized.session_id == self.attestation.session_id(),
            "seal_finalize_binding_mismatch"
        );
        anyhow::ensure!(
            self.delivered_shares.len() == finalized.envelope.manifest().nodes().len(),
            "remote sealed object has incomplete custody receipts"
        );
        let current = self.current_authority(data_dir).await?;
        let (_, receipt_signer) = elastos_identity::load_existing_did(data_dir)?;
        let requirement = RuntimeContentAvailabilityRequirement::new(
            receipt_signer,
            runtime_protected_content_id(finalized.identity.encrypted_content())?,
            self.publisher_did.clone(),
            PROTECTED_CONTENT_REPLICATION_POLICY,
            PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET,
            PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
            PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
        )?;
        let receipts: Vec<_> = self.delivered_shares.values().copied().collect();
        let result = publish_remote_sealed_content(
            registry,
            self.directory(),
            &finalized.identity,
            &finalized.envelope,
            &receipts,
            &requirement,
            crate::auth::now_ts,
        )
        .await?;
        result.prepare_completion(
            &self.descriptor,
            &self.request,
            current.node,
            crate::auth::now_ts(),
        )
    }

    /// Record the signed completion before releasing the reply to the minter.
    /// A retry uses the same publication statement and, after commit, the
    /// same signed bytes.
    pub async fn complete(
        &mut self,
        data_dir: &Path,
        registry: &ProviderRegistry,
        finalized: &FinalizedRemoteObjectUpload,
    ) -> anyhow::Result<SignedSealCompletedV1> {
        let session_id = self.attestation.session_id();
        anyhow::ensure!(
            finalized.session_id == session_id,
            "seal_finalize_binding_mismatch"
        );
        anyhow::ensure!(!self.source.local, "seal_completion_requires_carrier");
        let store = SealerCompletionStore::new(data_dir);
        if let Some(committed) = store.replay(&self.source, session_id, crate::auth::now_ts())? {
            return Ok(committed);
        }
        if self.published_statement.is_none() {
            self.published_statement = Some(self.publish(data_dir, registry, finalized).await?);
        }
        let statement = self
            .published_statement
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("seal_publication_unavailable"))?;
        let current = self.current_authority(data_dir).await?;
        let command = SignRemoteSealCompletionRequestV1::SignRemoteSealCompletion {
            pool_authority: *self.descriptor.pool().issuer().as_bytes(),
            descriptor: self.descriptor.canonical_bytes()?,
            mint_request: self.request.canonical_bytes()?,
            statement: statement.canonical_bytes()?,
        };
        let response = invoke_json_provider_with_transport(
            registry,
            TARGET_CUSTODY,
            SIGN_REMOTE_SEAL_COMPLETION_OP,
            serde_json::to_value(command)?,
            ProviderInvocationTransport::Local,
        )
        .await
        .map_err(|_| anyhow::anyhow!("seal_completion_signing_unavailable"))?;
        let reply: SignRemoteSealCompletionReplyV1 = serde_json::from_value(response)?;
        anyhow::ensure!(
            reply.completion.len() <= MAX_REMOTE_SEAL_COMPLETION_BYTES_V1,
            "seal_completion_invalid"
        );
        let signed = SignedSealCompletedV1::from_canonical_bytes(&reply.completion)?;
        let now = crate::auth::now_ts();
        let (verified, _) =
            signed.verify_for_request_at(&self.descriptor, &self.request, current.node, now)?;
        anyhow::ensure!(verified == statement, "seal_completion_invalid");
        store.commit(
            &self.source,
            &self.descriptor,
            &self.request,
            &self.attestation,
            &signed,
            now,
        )?;
        Ok(signed)
    }

    async fn current_authority(&self, data_dir: &Path) -> anyhow::Result<RemoteSealOpenAuthority> {
        let current = prepare_remote_seal_open(
            data_dir,
            &self.source,
            &self.descriptor,
            &self.request,
            crate::auth::now_ts(),
        )
        .await?;
        anyhow::ensure!(
            current.publisher_did == self.publisher_did && current.root_path == self.root_path,
            "seal_publisher_changed"
        );
        Ok(current)
    }

    async fn authorize_share_delivery(
        &self,
        registry: &ProviderRegistry,
        issuer: RuntimeOperationIssuerKeyV1,
        identity: &KeyEnvelopeIdentityV1,
    ) -> anyhow::Result<SignedPoolProvisioningAuthorizationV1> {
        let node = self.attestation.sealer_node_public_key();
        let command = AuthorizeRemoteSealShareRequestV1::AuthorizeRemoteSealShare {
            pool_authority: *self.descriptor.pool().issuer().as_bytes(),
            sealer_node: *node.as_bytes(),
            descriptor: self.descriptor.canonical_bytes()?,
            mint_request: self.request.canonical_bytes()?,
            key_envelope: identity.canonical_bytes()?,
            runtime_issuer: *issuer.as_bytes(),
        };
        let response = invoke_json_provider_with_transport(
            registry,
            TARGET_CUSTODY,
            AUTHORIZE_REMOTE_SEAL_SHARE_OP,
            serde_json::to_value(command)?,
            ProviderInvocationTransport::Local,
        )
        .await
        .map_err(|_| anyhow::anyhow!("seal_share_authorization_unavailable"))?;
        let reply: AuthorizeRemoteSealShareReplyV1 = serde_json::from_value(response)?;
        anyhow::ensure!(
            reply.authorization.len() <= 8 * 1024,
            "seal_share_authorization_invalid"
        );
        let signed =
            SignedPoolProvisioningAuthorizationV1::from_canonical_bytes(&reply.authorization)?;
        let (statement, _) = signed.verify_for_mint_request(
            &self.descriptor,
            &self.request,
            identity,
            crate::auth::now_ts(),
        )?;
        anyhow::ensure!(
            statement.sealer_node_public_key == node && statement.sealer_runtime_issuer == issuer,
            "seal_share_authorization_invalid"
        );
        Ok(signed)
    }

    pub async fn transfer(
        &mut self,
        registry: &ProviderRegistry,
        transfer: RemoteObjectSealTransferV1,
    ) -> anyhow::Result<Option<ClearPartIndexV1>> {
        anyhow::ensure!(!self.staging_failed, "seal_staging_unavailable");
        if let Some(pending) = &self.pending {
            if *pending == transfer {
                return self.settle_transfer(registry).await;
            }
            anyhow::ensure!(
                transfer == RemoteObjectSealTransferV1::Resume,
                "seal_resume_required"
            );
            self.settle_transfer(registry).await?;
        }
        self.pending = Some(transfer);
        self.settle_transfer(registry).await
    }

    /// Re-read the staged file and ask protect to compare it with the
    /// ciphertext it produced. An exact retry returns the same envelope.
    pub async fn finalize(
        &mut self,
        registry: &ProviderRegistry,
    ) -> anyhow::Result<FinalizedRemoteObjectUpload> {
        anyhow::ensure!(!self.staging_failed, "seal_staging_unavailable");
        if self.pending.is_some() {
            self.settle_transfer(registry).await?;
        }
        let mint = self.request.statement();
        let last_expected = mint.clear_layout.parts()?.last().map(|(part, _)| *part);
        anyhow::ensure!(
            self.last_staged.is_some() && self.last_staged == last_expected,
            "seal_upload_incomplete"
        );
        let session_id = self.attestation.session_id();
        let (content, op, command) = match (&self.media, &mint.clear_layout) {
            (
                StagedUpload::Object {
                    framed_header_bytes,
                    ..
                },
                ClearLayoutV1::Object {
                    content_type,
                    length,
                },
            ) => {
                let (digest, bytes) =
                    sha256_file(&self.directory().join(PROTECTED_CONTENT_OBJECT_EPC1_PATH))?;
                let identity = ChunkedPayloadObjectIdentityV1::new(
                    EncryptedContentIdentityV1::new(digest, bytes)?,
                    content_type,
                    *length,
                    *framed_header_bytes,
                )?;
                let command = FinalizeRemoteObjectSealRequestV1::FinalizeRemoteObjectSeal {
                    endpoint: self.source.endpoint_did.clone(),
                    session_id,
                    sequence: self.sequence,
                    ciphertext_sha256: *digest.as_bytes(),
                    ciphertext_bytes: bytes,
                };
                (
                    RuntimeContentIdentityV1::Object(identity),
                    FINALIZE_REMOTE_OBJECT_SEAL_OP,
                    serde_json::to_value(command)?,
                )
            }
            (StagedUpload::Dash, ClearLayoutV1::DashV2 { renditions }) => {
                let epoch = self
                    .descriptor
                    .epochs()
                    .iter()
                    .find(|epoch| epoch.epoch_identity().ok() == Some(mint.epoch))
                    .ok_or_else(|| anyhow::anyhow!("seal_finalize_binding_mismatch"))?;
                let header = CustodyProtectionHeader::new(
                    mint.content_access_id,
                    &epoch.signed_pool().pool_identity()?,
                    &mint.epoch,
                    &epoch
                        .signed_committee_authorization()
                        .authorization_identity()?,
                    CencMediaSuite::DashV2,
                );
                let storage = Arc::clone(&self.storage);
                let renditions = renditions.clone();
                let kid = mint.content_access_id;
                let head = tokio::task::spawn_blocking(move || {
                    rebuild_staged_remote_dash(storage.directory(), &renditions, kid, &header)
                })
                .await??;
                let command = FinalizeRemoteDashSealRequestV1::FinalizeRemoteDashSeal {
                    endpoint: self.source.endpoint_did.clone(),
                    session_id,
                    sequence: self.sequence,
                    staged_identity: head.canonical_bytes()?,
                };
                (
                    RuntimeContentIdentityV1::MediaDash(head),
                    FINALIZE_REMOTE_DASH_SEAL_OP,
                    serde_json::to_value(command)?,
                )
            }
            _ => anyhow::bail!("seal_layout_invalid"),
        };
        let reply = invoke_json_provider_with_transport(
            registry,
            PROTECT_PROVIDER_ID,
            op,
            command,
            ProviderInvocationTransport::Local,
        )
        .await
        .map_err(anyhow::Error::msg)?;
        let reply: FinalizeRemoteObjectSealReplyV1 = serde_json::from_value(reply)?;
        anyhow::ensure!(
            reply.session_id == session_id
                && reply.sequence == self.sequence
                && &reply.mint_request_hash
                    == self.attestation.statement().mint_request_hash.as_bytes()
                && &reply.content_access_id == mint.content_access_id.as_bytes()
                && reply.custody_envelope.len() <= MAX_KEY_ENVELOPE_BYTES as usize,
            "seal_finalize_binding_mismatch"
        );
        let envelope = CustodyEnvelopeV1::from_canonical_bytes(&reply.custody_envelope)?;
        let identity = envelope.key_envelope_identity()?;
        anyhow::ensure!(
            identity.encrypted_content() == content.encrypted_content()
                && identity.custody_epoch() == mint.epoch,
            "seal_finalize_binding_mismatch"
        );
        let now = crate::auth::now_ts();
        self.descriptor
            .verify(now)?
            .epoch_for_provisioning(&identity, now)?
            .signed_epoch()
            .verify_against_key_envelope(&identity)?;
        if let RuntimeContentIdentityV1::Object(object) = &content {
            write_protected_content_object_manifest(self.directory(), object)?;
        }
        Ok(FinalizedRemoteObjectUpload {
            identity: content,
            envelope,
            session_id,
        })
    }

    async fn settle_transfer(
        &mut self,
        registry: &ProviderRegistry,
    ) -> anyhow::Result<Option<ClearPartIndexV1>> {
        let transfer = self
            .pending
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("seal_transfer_missing"))?;
        let session_id = self.attestation.session_id();
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("seal_transfer_invalid"))?;
        let completed_part = match transfer {
            RemoteObjectSealTransferV1::Part {
                part,
                piece,
                piece_count,
                ..
            } if piece.checked_add(1) == Some(*piece_count) => Some(*part),
            _ => None,
        };
        let (op, command, max_output_bytes) = match self.media {
            StagedUpload::Object { .. } => (
                TRANSFER_REMOTE_OBJECT_SEAL_OP,
                serde_json::to_value(
                    TransferRemoteObjectSealRequestV1::TransferRemoteObjectSeal {
                        endpoint: self.source.endpoint_did.clone(),
                        session_id,
                        sequence,
                        transfer: transfer.clone(),
                    },
                )?,
                MAX_OBJECT_FRAMED_CHUNK_BYTES_V1,
            ),
            StagedUpload::Dash => (
                TRANSFER_REMOTE_DASH_SEAL_OP,
                serde_json::to_value(TransferRemoteDashSealRequestV1::TransferRemoteDashSeal {
                    endpoint: self.source.endpoint_did.clone(),
                    session_id,
                    sequence,
                    transfer: transfer.clone(),
                })?,
                MAX_PROTECT_MEDIA_PART_BYTES_V1,
            ),
        };
        let reply = invoke_json_provider_classified(
            registry,
            PROTECT_PROVIDER_ID,
            op,
            command,
            ProviderInvocationTransport::Local,
        )
        .await;
        let reply = match reply {
            Ok(reply) => reply,
            Err(ProviderInvocationFailure::Refused { code, .. }) => {
                self.pending = None;
                anyhow::bail!("seal_transfer_refused: {code}");
            }
            Err(_) => anyhow::bail!("seal_protect_unavailable"),
        };
        let reply: TransferRemoteObjectSealReplyV1 = serde_json::from_value(reply)?;
        anyhow::ensure!(
            reply.session_id == session_id
                && reply.sequence == sequence
                && reply.last_protected == completed_part.or(self.last_staged)
                && reply.framed_chunk.is_some() == completed_part.is_some(),
            "seal_transfer_invalid"
        );
        if let Some(chunk) = reply.framed_chunk {
            anyhow::ensure!(
                chunk.len() <= max_output_bytes.div_ceil(3) * 4,
                "seal_transfer_invalid"
            );
            let framed = base64::engine::general_purpose::STANDARD.decode(chunk)?;
            anyhow::ensure!(
                !framed.is_empty() && framed.len() <= max_output_bytes,
                "seal_transfer_invalid"
            );
            let next_bytes = self.staged_part_bytes.saturating_add(framed.len() as u64);
            anyhow::ensure!(
                next_bytes
                    <= self.storage.staging_bytes()
                        - crate::content::MAX_LOCAL_OBJECT_MANIFEST_BYTES,
                "remote seal staging exceeds its reservation"
            );
            // A failed write can leave a partial frame. This upload must never
            // acknowledge or append another frame to that staging file.
            self.staging_failed = true;
            match (&mut self.media, completed_part) {
                (StagedUpload::Object { file, .. }, Some(ClearPartIndexV1::ObjectChunk { .. })) => {
                    file.write_all(&framed)?;
                    file.sync_data()?;
                }
                (StagedUpload::Dash, Some(part)) => {
                    stage_dash_part(self.storage.directory(), part, &framed)?
                }
                _ => anyhow::bail!("seal_transfer_invalid"),
            }
            self.staged_part_bytes = next_bytes;
            self.staging_failed = false;
        }
        self.pending = None;
        self.sequence = sequence;
        self.last_staged = reply.last_protected;
        Ok(self.last_staged)
    }
}

fn stage_dash_part(directory: &Path, part: ClearPartIndexV1, bytes: &[u8]) -> anyhow::Result<()> {
    let kind = |code| {
        CencDashRenditionKindV2::from_code(code)
            .ok_or_else(|| anyhow::anyhow!("seal_transfer_invalid"))
    };
    let relative = match part {
        ClearPartIndexV1::DashInit { rendition } => runtime_media_dash_init_path(kind(rendition)?),
        ClearPartIndexV1::DashSegment { rendition, index } => {
            anyhow::ensure!(
                bytes.len() <= MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2,
                "seal_transfer_invalid"
            );
            runtime_media_dash_segment_path(kind(rendition)?, index)
        }
        ClearPartIndexV1::ObjectChunk { .. } => anyhow::bail!("seal_transfer_invalid"),
    };
    let path = directory.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_data()?;
    Ok(())
}

async fn deliver_remote_share(
    registry: &ProviderRegistry,
    request: &RemoteShareProvisionRequestV1,
    transport: ProviderInvocationTransport,
) -> anyhow::Result<VerifiedRemoteShareReceipt> {
    let delivery = RemoteShareDeliveryV1::ProvisionPoolNodeShare {
        remote_seal_request: serde_json::from_slice(&request.to_json_vec()?)?,
    };
    let response = invoke_json_provider_with_transport(
        registry,
        TARGET_CUSTODY,
        OP_CUSTODY_PROVISION_POOL_NODE_SHARE,
        serde_json::to_value(delivery)?,
        transport,
    )
    .await
    .map_err(anyhow::Error::msg)?;
    let receipt: RemoteShareProvisionReplyV1 = serde_json::from_value(response)?;
    let record = request.record.record_identity()?;
    anyhow::ensure!(
        &receipt.selected_node_public_key == request.record.selected_node_public_key().as_bytes()
            && &receipt.record_sha256 == record.record_sha256().as_bytes()
            && receipt.record_bytes == record.record_bytes()
            && &receipt.provisioning_id
                == request
                    .signed_provisioning
                    .statement()
                    .provisioning_id()
                    .digest()
                    .as_bytes(),
        "seal_share_receipt_mismatch"
    );
    Ok(VerifiedRemoteShareReceipt {
        node: request.record.selected_node_public_key(),
        record,
    })
}

impl RemoteSealOpenAuthority {
    async fn open_staged_upload(
        &self,
        storage: Arc<RemoteSealStorage>,
        registry: &ProviderRegistry,
        request: &SignedMintRequestV1,
    ) -> anyhow::Result<RemoteObjectUploadStaging> {
        if matches!(
            &request.statement().clear_layout,
            ClearLayoutV1::Object { .. }
        ) {
            return self
                .open_staged_object_upload(storage, registry, request)
                .await;
        }
        let command = OpenRemoteDashSealRequestV1::OpenRemoteDashSeal {
            endpoint: self.source.endpoint_did.clone(),
            minter_issuer: *self.minter.as_bytes(),
            sealer_node: *self.node.as_bytes(),
            descriptor: self.descriptor.canonical_bytes()?,
            mint_request: request.canonical_bytes()?,
        };
        let value = invoke_json_provider_with_transport(
            registry,
            PROTECT_PROVIDER_ID,
            OPEN_REMOTE_DASH_SEAL_OP,
            serde_json::to_value(command)?,
            ProviderInvocationTransport::Local,
        )
        .await
        .map_err(|_| anyhow::anyhow!("seal_protect_unavailable"))?;
        let reply: OpenRemoteDashSealReplyV1 = serde_json::from_value(value)?;
        anyhow::ensure!(reply.statement.len() <= 4 * 1024, "seal_protect_invalid");
        let statement = SealSessionAttestationV1::from_canonical_bytes(&reply.statement)?;
        let attestation = self.attest_upload(registry, request, &statement).await?;
        Ok(self.staged_upload(attestation, storage, StagedUpload::Dash, 0, request))
    }

    async fn open_staged_object_upload(
        &self,
        storage: Arc<RemoteSealStorage>,
        registry: &ProviderRegistry,
        request: &SignedMintRequestV1,
    ) -> anyhow::Result<RemoteObjectUploadStaging> {
        let opened = self.open_object_upload(registry, request).await?;
        let path = storage.directory().join(PROTECTED_CONTENT_OBJECT_EPC1_PATH);
        fs::create_dir_all(path.parent().expect("staged object has a parent"))?;
        let mut file = File::create(path)?;
        file.write_all(&opened.framed_header)?;
        file.sync_data()?;
        let media = StagedUpload::Object {
            file,
            framed_header_bytes: u32::try_from(opened.framed_header.len())?,
        };
        Ok(self.staged_upload(
            opened.attestation,
            storage,
            media,
            opened.framed_header.len() as u64,
            request,
        ))
    }

    fn staged_upload(
        &self,
        attestation: SignedSealSessionAttestationV1,
        storage: Arc<RemoteSealStorage>,
        media: StagedUpload,
        staged_part_bytes: u64,
        request: &SignedMintRequestV1,
    ) -> RemoteObjectUploadStaging {
        RemoteObjectUploadStaging {
            attestation,
            source: self.source.clone(),
            publisher_did: self.publisher_did.clone(),
            root_path: self.root_path.clone(),
            descriptor: self.descriptor.clone(),
            request: request.clone(),
            media,
            storage,
            staged_part_bytes,
            last_staged: None,
            sequence: 0,
            pending: None,
            staging_failed: false,
            delivered_shares: BTreeMap::new(),
            published_statement: None,
        }
    }

    /// Start the protect session on the local provider plane. Runtime gets
    /// only the framed header for staging and a public signed attestation.
    pub async fn open_object_upload(
        &self,
        registry: &ProviderRegistry,
        request: &SignedMintRequestV1,
    ) -> anyhow::Result<OpenedRemoteObjectUpload> {
        anyhow::ensure!(
            request.statement().minter_issuer == self.minter,
            "seal_minter_source_mismatch"
        );
        let command = OpenRemoteObjectSealRequestV1::OpenRemoteObjectSeal {
            endpoint: self.source.endpoint_did.clone(),
            minter_issuer: *self.minter.as_bytes(),
            sealer_node: *self.node.as_bytes(),
            descriptor: self.descriptor.canonical_bytes()?,
            mint_request: request.canonical_bytes()?,
        };
        let response = invoke_json_provider_with_transport(
            registry,
            PROTECT_PROVIDER_ID,
            OPEN_REMOTE_OBJECT_SEAL_OP,
            serde_json::to_value(command)?,
            ProviderInvocationTransport::Local,
        )
        .await
        .map_err(|_| anyhow::anyhow!("seal_protect_unavailable"))?;
        let reply: OpenRemoteObjectSealReplyV1 = serde_json::from_value(response)?;
        anyhow::ensure!(
            reply.statement.len() <= 4 * 1024
                && !reply.framed_header.is_empty()
                && reply.framed_header.len() <= MAX_OBJECT_FRAMED_HEADER_BYTES_V1,
            "seal_protect_invalid"
        );
        let statement = SealSessionAttestationV1::from_canonical_bytes(&reply.statement)?;
        let attestation = self.attest_upload(registry, request, &statement).await?;
        Ok(OpenedRemoteObjectUpload {
            attestation,
            framed_header: reply.framed_header,
        })
    }

    /// Pass the exact statement from the private protect provider to the
    /// selected local custody root. Verify the returned signature and body
    /// before passing the attestation across Carrier.
    pub async fn attest_upload(
        &self,
        registry: &ProviderRegistry,
        request: &SignedMintRequestV1,
        statement: &SealSessionAttestationV1,
    ) -> anyhow::Result<SignedSealSessionAttestationV1> {
        anyhow::ensure!(
            statement.sealer_node_public_key == self.node
                && request.statement().minter_issuer == self.minter,
            "seal_attestation_binding_mismatch"
        );
        let command = RemoteSealAttestationRequestV1::AttestRemoteSealUpload {
            pool_authority: *self.descriptor.pool().issuer().as_bytes(),
            descriptor: self.descriptor.canonical_bytes()?,
            mint_request: request.canonical_bytes()?,
            statement: statement.canonical_bytes()?,
        };
        let response = invoke_json_provider_with_transport(
            registry,
            TARGET_CUSTODY,
            ATTEST_REMOTE_SEAL_UPLOAD_OP,
            serde_json::to_value(command)?,
            ProviderInvocationTransport::Local,
        )
        .await
        .map_err(|_| anyhow::anyhow!("seal_attestation_unavailable"))?;
        let reply: RemoteSealAttestationReplyV1 = serde_json::from_value(response)?;
        anyhow::ensure!(
            reply.attestation.len() <= 4 * 1024,
            "seal_attestation_invalid"
        );
        let signed = SignedSealSessionAttestationV1::from_canonical_bytes(&reply.attestation)?;
        anyhow::ensure!(
            signed.statement() == statement,
            "seal_attestation_binding_mismatch"
        );
        signed.verify_for_upload(
            request,
            &self.descriptor,
            self.node,
            statement.seal_session_id,
            crate::auth::now_ts(),
        )?;
        Ok(signed)
    }
}

/// Resolve the exact root and its confirmed publisher before accepting any
/// file data. The offered descriptor must be the version this Home serves.
pub async fn prepare_remote_seal_open(
    data_dir: &Path,
    source: &PoolSessionSource,
    offered: &SignedPoolDescriptorAnyV1,
    signed: &SignedMintRequestV1,
    now: u64,
) -> anyhow::Result<RemoteSealOpenAuthority> {
    anyhow::ensure!(
        crate::host_trust::host_trusted(data_dir),
        "not_eligible_sealer"
    );
    let _guard = custody_consent::lock_custody_writes().await;
    let pool = offered.pool();
    let key = crate::custody_node_card::Fingerprint::of(pool.issuer().as_bytes()).full;
    let pools = custody_consent::served_pools(data_dir)?;
    let (device_key, endpoint) = elastos_identity::load_existing_did(data_dir)?;
    let local_issuer = RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())?;
    let trusted = custody_pool_descriptor::trusted_pool_root(data_dir, pool)?
        .ok_or_else(|| anyhow::anyhow!("not_eligible_sealer"))?;
    let descriptor = trusted
        .kept
        .ok_or_else(|| anyhow::anyhow!("not_eligible_sealer"))?;
    let root_path = trusted.root_path;
    let publisher = if let Some(entry) = pools.entries.get(&key) {
        anyhow::ensure!(
            entry.root_path == root_path
                && matches!(custody_consent::custody_root_trust_at(data_dir, &root_path)?, RootTrust::Trusts(owner) if owner == entry.owner_home),
            "not_eligible_sealer"
        );
        entry.admin_profile_did.clone()
    } else {
        anyhow::ensure!(
            matches!(custody_consent::custody_root_trust_at(data_dir, &root_path)?, RootTrust::Trusts(owner) if owner == endpoint),
            "not_eligible_sealer"
        );
        pools.own_root_admin_profile_did
    };
    anyhow::ensure!(&descriptor == offered, "seal_descriptor_changed");
    let root = crate::protected_content_runtime::custody_root_dir(data_dir, &root_path);
    let node = custody_provider::load_node_public_key(&root)
        .map_err(|_| anyhow::anyhow!("not_eligible_sealer"))?;
    let minter = signed
        .verify_for_sealer(&descriptor, node, now)?
        .minter_issuer;
    anyhow::ensure!(
        descriptor.member_peer_did(node) == Some(endpoint.as_str()),
        "not_eligible_sealer"
    );
    anyhow::ensure!(
        descriptor.mint_policy().allow_self_seal
            || (!source.local && source.endpoint_did != endpoint && minter != local_issuer),
        "self_seal_refused"
    );
    // The request verifies the minter's signature and pool admission. Bind
    // that issuer to the authenticated Home before any upload can open.
    let source_matches = if source.local {
        minter == local_issuer
    } else {
        crate::crypto::decode_did_key(&source.endpoint_did)
            .is_ok_and(|key| key.as_bytes() == minter.as_bytes())
    };
    anyhow::ensure!(source_matches, "seal_minter_source_mismatch");
    let publisher_did = publisher
        .filter(|did| crate::crypto::decode_did_key(did).is_ok())
        .ok_or_else(|| anyhow::anyhow!("seal_publisher_unconfirmed"))?;
    Ok(RemoteSealOpenAuthority {
        descriptor,
        node,
        minter,
        publisher_did,
        root_path,
        source: source.clone(),
    })
}

#[cfg(all(test, unix))]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    use elastos_protected_content_contracts::test_fixtures::{
        node_public_key, pool_bundle, pool_descriptor_routed, pool_did, runtime_issuer,
        signing_key, CUSTODY_KEY_SEED_BASE, POOL_AUTHORITY_SEED,
    };
    use elastos_protected_content_contracts::{
        CanonicalContract, ClearLayoutV1, ContentAccessIdV1, MintRequestV1,
    };

    use super::*;
    use crate::protected_content_config::tests::{owner_only_dir, safe_ancestor_tempdir};
    use crate::protected_content_runtime::write_owner_only_bytes;

    #[derive(Default)]
    struct ShareDeliveryFixture {
        requests: std::sync::Mutex<BTreeMap<NodePublicKey, usize>>,
    }

    struct SealIngressFixture<'a> {
        registry: &'a ProviderRegistry,
        endpoint: &'a str,
    }

    impl SealIngressFixture<'_> {
        async fn call_raw(
            &self,
            op: &str,
            mut request: serde_json::Value,
        ) -> Result<serde_json::Value, elastos_runtime::provider::ProviderError> {
            let target = crate::custody_surface::TARGET_CUSTODY_POOL;
            request["op"] = serde_json::json!(op);
            request["_runtime_invocation"] = serde_json::json!({
                "schema": "elastos.provider.invocation/v1",
                "source": "runtime",
                "target": target,
                "capability": format!("provider:runtime->{target}:{op}"),
                "op": op,
                "transport": "carrier-provider-plane",
                "carrier": { "source_endpoint_did": self.endpoint },
                "transfer": "json",
                "range": null,
                "progress": null,
                "abi": {
                    "schema": "elastos.provider.transfer-abi/v1",
                    "transfer": "json",
                    "transport": "carrier-provider-plane",
                    "range_supported": false,
                    "progress_supported": false,
                    "progress_mode": "none",
                    "transport_native_stream": false,
                    "backpressure": "not_applicable",
                    "cancel_supported": false,
                }
            });
            self.registry
                .send_runtime_provider_target_raw(target, &request)
                .await
        }
    }

    #[async_trait::async_trait]
    impl elastos_protected_content_runtime::PoolSessionTransport for SealIngressFixture<'_> {
        async fn call(
            &self,
            _: &PoolMemberRouteV2,
            op: &'static str,
            _: PoolCallClass,
            request: serde_json::Value,
        ) -> Result<serde_json::Value, elastos_protected_content_runtime::PoolTransportError>
        {
            let reply = self.call_raw(op, request).await.map_err(|_| {
                elastos_protected_content_runtime::PoolTransportError::NoExactResult
            })?;
            elastos_protected_content_runtime::pool_wire_answer(&reply)
        }
    }

    struct LibrarySealCarrierFixture {
        sealer: Arc<ProviderRegistry>,
        sealer_did: String,
        minter_did: String,
        calls: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl elastos_runtime::provider::ProviderCarrierInvoker for LibrarySealCarrierFixture {
        async fn invoke_carrier_provider(
            &self,
            route: &elastos_runtime::provider::ProviderCarrierRoute,
            invocation: &elastos_runtime::provider::ProviderInvocation,
            request: serde_json::Value,
        ) -> Result<serde_json::Value, elastos_runtime::provider::ProviderError> {
            use elastos_runtime::provider::ProviderCarrierRoute;
            assert!(
                matches!(route, ProviderCarrierRoute::PeerDid { peer_did, .. } if peer_did == &self.sealer_did)
            );
            assert_eq!(
                invocation.target,
                crate::custody_surface::TARGET_CUSTODY_POOL
            );
            self.calls.lock().unwrap().push(invocation.op.clone());
            SealIngressFixture {
                registry: &self.sealer,
                endpoint: &self.minter_did,
            }
            .call_raw(&invocation.op, request)
            .await
        }
    }

    #[async_trait::async_trait]
    impl elastos_runtime::provider::ProviderCarrierInvoker for ShareDeliveryFixture {
        async fn invoke_carrier_provider(
            &self,
            route: &elastos_runtime::provider::ProviderCarrierRoute,
            invocation: &elastos_runtime::provider::ProviderInvocation,
            value: serde_json::Value,
        ) -> Result<serde_json::Value, elastos_runtime::provider::ProviderError> {
            assert_eq!(invocation.target, TARGET_CUSTODY);
            assert_eq!(invocation.op, OP_CUSTODY_PROVISION_POOL_NODE_SHARE);
            let request = RemoteShareProvisionRequestV1::from_json_slice(
                &serde_json::to_vec(&value["remote_seal_request"]).unwrap(),
            )
            .unwrap();
            let node = request.record.selected_node_public_key();
            let elastos_runtime::provider::ProviderCarrierRoute::PeerDid { peer_did, .. } = route
            else {
                panic!("this fixture has no saved tickets");
            };
            assert_eq!(
                request.admission.descriptor.member_peer_did(node),
                Some(peer_did.as_str())
            );
            let record = request.record.record_identity().unwrap();
            let mut requests = self.requests.lock().unwrap();
            let count = requests.entry(node).or_default();
            *count += 1;
            let reply = RemoteShareProvisionReplyV1 {
                selected_node_public_key: *node.as_bytes(),
                record_sha256: *record.record_sha256().as_bytes(),
                record_bytes: if node == node_public_key(3) && *count == 1 {
                    record.record_bytes() + 1
                } else {
                    record.record_bytes()
                },
                provisioning_id: *request
                    .signed_provisioning
                    .statement()
                    .provisioning_id()
                    .digest()
                    .as_bytes(),
                already_stored: *count > 1,
            };
            Ok(serde_json::json!({"status": "ok", "data": reply}))
        }
    }

    #[tokio::test]
    async fn seal_open_needs_the_exact_root_and_its_confirmed_publisher() {
        check_seal_open(2_000_000_000, None).await;
    }

    #[tokio::test]
    #[ignore = "requires the built protect and custody provider binaries"]
    async fn remote_object_open_runs_through_both_provider_processes() {
        let protect = std::env::var_os("ELASTOS_TEST_PROTECT_PROVIDER_BIN")
            .expect("provide the compiled protect provider");
        let custody = std::env::var_os("ELASTOS_TEST_CUSTODY_PROVIDER_BIN")
            .expect("provide the compiled custody provider");
        check_seal_open(
            crate::auth::now_ts(),
            Some((
                std::path::Path::new(&protect),
                std::path::Path::new(&custody),
            )),
        )
        .await;
    }

    async fn check_seal_open(
        now: u64,
        provider_bins: Option<(&std::path::Path, &std::path::Path)>,
    ) {
        let temp = safe_ancestor_tempdir();
        let data_dir = temp.path().join("home");
        owner_only_dir(&data_dir);
        crate::host_trust::seed_for_test(&data_dir, true);
        let (device_key, own_endpoint) = elastos_identity::load_or_create_did(&data_dir).unwrap();
        let owner_home =
            elastos_identity::encode_did_key(&signing_key(POOL_AUTHORITY_SEED).verifying_key())
                .unwrap();
        let bundle = pool_bundle(
            |seed| {
                use x_wing::kem::{Decapsulator as _, KeyExport as _};
                x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE])
                    .encapsulation_key()
                    .to_bytes()
                    .into()
            },
            now,
        );
        let make_descriptor = |sequence| {
            pool_descriptor_routed(&bundle, sequence, now, POOL_AUTHORITY_SEED, &|id| {
                if id == 1 {
                    own_endpoint.clone()
                } else {
                    elastos_identity::encode_did_key(&signing_key(0x20 + id).verifying_key())
                        .unwrap()
                }
            })
            .into()
        };
        let descriptor: SignedPoolDescriptorAnyV1 = make_descriptor(1);
        let key = crate::custody_node_card::Fingerprint::of(pool_did().issuer().as_bytes()).full;
        let root_path = format!("pools/{}", key.trim_start_matches("sha256:"));
        let root = crate::protected_content_runtime::custody_root_dir(&data_dir, &root_path);
        write_owner_only_bytes(
            &root.join("node-signing-key"),
            hex::encode([1; 32]).as_bytes(),
        )
        .unwrap();
        write_owner_only_bytes(
            &root.join("trusted-runtime-issuer"),
            hex::encode(runtime_issuer(POOL_AUTHORITY_SEED).as_bytes()).as_bytes(),
        )
        .unwrap();
        custody_consent::update_served_pools(&data_dir, |pools| {
            pools.own_root_admin_profile_did = Some(owner_home.clone());
            pools.entries.insert(
                key.clone(),
                custody_consent::ServedPoolEntryV2 {
                    owner_home: owner_home.clone(),
                    consent: custody_consent::ServedConsentV2 {
                        term_days: 365,
                        signing_key_fingerprint_full: key.clone(),
                    },
                    root_path,
                    admin_profile_did: None,
                    pool_did: pool_did().to_did_key().ok(),
                    served_pool: None,
                    descriptor: Some(
                        base64::engine::general_purpose::STANDARD
                            .encode(descriptor.canonical_bytes().unwrap()),
                    ),
                },
            );
            Ok(())
        })
        .unwrap();
        let statement = MintRequestV1 {
            pool: pool_did(),
            epoch: bundle.epoch_identity().unwrap(),
            minter_issuer: runtime_issuer(POOL_AUTHORITY_SEED),
            content_access_id: ContentAccessIdV1::new([1; 16]).unwrap(),
            clear_layout: ClearLayoutV1::Object {
                content_type: "application/pdf".into(),
                length: 16,
            },
            request_nonce: [2; 16],
            issued_at: now,
            expires_at: now + 30,
        };
        let signature =
            signing_key(POOL_AUTHORITY_SEED).sign(&statement.canonical_bytes().unwrap());
        let request = SignedMintRequestV1::new(statement, signature.to_bytes()).unwrap();
        let source = PoolSessionSource {
            endpoint_did: owner_home.clone(),
            local: false,
        };
        assert!(matches!(
            prepare_remote_seal_open(&data_dir, &source, &descriptor, &request, now).await,
            Err(error) if error.to_string() == "seal_publisher_unconfirmed"
        ));
        let publisher =
            elastos_identity::encode_did_key(&signing_key(0x53).verifying_key()).unwrap();
        custody_consent::update_served_pools(&data_dir, |pools| {
            pools.entries.get_mut(&key).unwrap().admin_profile_did = Some(publisher.clone());
            Ok(())
        })
        .unwrap();
        let admitted = prepare_remote_seal_open(&data_dir, &source, &descriptor, &request, now)
            .await
            .unwrap();
        assert_eq!(admitted.publisher_did, publisher);
        assert_eq!(admitted.node, node_public_key(1));
        let different_home = PoolSessionSource {
            endpoint_did: elastos_identity::encode_did_key(&signing_key(0x54).verifying_key())
                .unwrap(),
            local: false,
        };
        assert!(matches!(
            prepare_remote_seal_open(&data_dir, &different_home, &descriptor, &request, now).await,
            Err(error) if error.to_string() == "seal_minter_source_mismatch"
        ));
        assert!(matches!(
            prepare_remote_seal_open(&data_dir, &source, &make_descriptor(2), &request, now).await,
            Err(error) if error.to_string() == "seal_descriptor_changed"
        ));
        let self_source = PoolSessionSource {
            endpoint_did: own_endpoint,
            local: false,
        };
        assert!(matches!(
            prepare_remote_seal_open(&data_dir, &self_source, &descriptor, &request, now).await,
            Err(error) if error.to_string() == "self_seal_refused"
        ));

        if let Some((protect, custody)) = provider_bins {
            use crate::protected_content_runtime::{
                register_custody_provider, register_protect_provider,
            };

            write_owner_only_bytes(
                &root.join("node-custody-secret"),
                hex::encode([CUSTODY_KEY_SEED_BASE + 1; 32]).as_bytes(),
            )
            .unwrap();
            owner_only_dir(&root.join("data"));
            let registry = Arc::new(ProviderRegistry::new());
            register_protect_provider(&registry, protect).await.unwrap();
            register_custody_provider(&registry, custody, &data_dir)
                .await
                .unwrap();
            let opened = admitted
                .open_object_upload(&registry, &request)
                .await
                .unwrap();
            assert_eq!(
                opened.attestation.statement().mint_request_hash,
                request.canonical_hash().unwrap()
            );
            assert!(opened.framed_header.len() > 4);
            let replay = admitted
                .open_object_upload(&registry, &request)
                .await
                .unwrap();
            assert_eq!(opened.attestation, replay.attestation);
            assert_eq!(opened.framed_header, replay.framed_header);

            crate::host_trust::seed_wci_host_for_test(&data_dir);
            let storage = RemoteSealStorage::reserve(
                &data_dir,
                storage::staging_reservation(&request.statement().clear_layout).unwrap(),
            )
            .await
            .unwrap();
            let mut staged = admitted
                .open_staged_object_upload(storage, &registry, &request)
                .await
                .unwrap();
            assert!(
                matches!(staged.finalize(&registry).await, Err(error) if error.to_string() == "seal_upload_incomplete")
            );
            let clear = [0x71; 16];
            let part = ClearPartIndexV1::ObjectChunk { index: 0 };
            let statement = staged.attestation.statement();
            let aad = elastos_protected_content_contracts::MintPieceAadV1 {
                mint_request_hash: statement.mint_request_hash,
                part,
                piece: 0,
                piece_count: 1,
            };
            let sealed = elastos_protected_content_custody::seal_mint_piece_v1(
                &statement.seal_session_public_key,
                &aad,
                &clear,
            )
            .unwrap();
            use sha2::{Digest as _, Sha256};
            let transfer = RemoteObjectSealTransferV1::Part {
                part,
                piece: 0,
                piece_count: 1,
                part_clear_sha256: Sha256::digest(clear).into(),
                sealed: base64::engine::general_purpose::STANDARD.encode(sealed),
            };
            // Simulate a lost reply after the real provider processed the part.
            let command = TransferRemoteObjectSealRequestV1::TransferRemoteObjectSeal {
                endpoint: source.endpoint_did.clone(),
                session_id: staged.attestation.session_id(),
                sequence: 1,
                transfer: transfer.clone(),
            };
            staged.pending = Some(transfer);
            let reply = invoke_json_provider_with_transport(
                &registry,
                PROTECT_PROVIDER_ID,
                TRANSFER_REMOTE_OBJECT_SEAL_OP,
                serde_json::to_value(command).unwrap(),
                ProviderInvocationTransport::Local,
            )
            .await
            .unwrap();
            let expected_chunk = base64::engine::general_purpose::STANDARD
                .decode(reply["framed_chunk"].as_str().unwrap())
                .unwrap();
            let path = staged.directory().join(PROTECTED_CONTENT_OBJECT_EPC1_PATH);
            assert_eq!(std::fs::read(&path).unwrap(), opened.framed_header);
            assert_eq!(
                staged
                    .transfer(&registry, RemoteObjectSealTransferV1::Resume)
                    .await
                    .unwrap(),
                Some(part),
            );
            let expected = [opened.framed_header, expected_chunk].concat();
            assert_eq!(std::fs::read(&path).unwrap(), expected);
            assert_eq!(staged.sequence, 2);
            let mut changed = expected.clone();
            *changed.last_mut().unwrap() ^= 1;
            std::fs::write(&path, changed).unwrap();
            let rejected = staged.finalize(&registry).await.err().unwrap();
            assert!(rejected.to_string().contains("seal_staging_mismatch"));
            std::fs::write(&path, &expected).unwrap();
            let finalized = staged.finalize(&registry).await.unwrap();
            assert_eq!(
                finalized.object().encrypted_content().ciphertext_sha256(),
                elastos_protected_content_contracts::Digest32::new(
                    Sha256::digest(&expected).into()
                ),
            );
            assert_eq!(
                finalized
                    .envelope
                    .key_envelope_identity()
                    .unwrap()
                    .encrypted_content(),
                finalized.object().encrypted_content(),
            );
            let recovered = staged.finalize(&registry).await.unwrap();
            assert_eq!(recovered.object(), finalized.object());
            assert_eq!(recovered.envelope, finalized.envelope);
            let local_issuer =
                RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes()).unwrap();
            let delivery = |issuer, runtime_key: &ed25519_dalek::SigningKey| {
                use elastos_protected_content_contracts::{
                    PoolProvisioningAuthorizationV1, RemoteShareAdmissionV1,
                    SignedPoolProvisioningAuthorizationV1,
                };
                use elastos_protected_content_provider_contracts::RemoteShareDeliveryV1;
                let statement = PoolProvisioningAuthorizationV1 {
                    pool: pool_did(),
                    epoch: request.statement().epoch,
                    sealer_node_public_key: admitted.node,
                    sealer_runtime_issuer: issuer,
                    key_envelope: recovered.envelope.key_envelope_identity().unwrap(),
                    content_access_id: request.statement().content_access_id,
                    mint_request_hash: request.canonical_hash().unwrap(),
                    issued_at: now,
                    expires_at: request.statement().expires_at,
                };
                let signature = signing_key(1)
                    .sign(&statement.canonical_bytes().unwrap())
                    .to_bytes();
                let authorization =
                    SignedPoolProvisioningAuthorizationV1::new(statement, signature).unwrap();
                let admission = RemoteShareAdmissionV1 {
                    descriptor: descriptor.clone(),
                    request: request.clone(),
                    authorization,
                };
                let share =
                    elastos_protected_content_runtime::prepare_remote_share_provision_request(
                        admission,
                        &recovered.envelope,
                        admitted.node,
                        &|bytes| runtime_key.sign(bytes).to_bytes(),
                        now,
                    )
                    .unwrap();
                serde_json::to_value(RemoteShareDeliveryV1::ProvisionPoolNodeShare {
                    remote_seal_request: serde_json::from_slice(&share.to_json_vec().unwrap())
                        .unwrap(),
                })
                .unwrap()
            };
            let deliver = |request| {
                invoke_json_provider_with_transport(
                    &registry,
                    TARGET_CUSTODY,
                    crate::custody_surface::OP_CUSTODY_PROVISION_POOL_NODE_SHARE,
                    request,
                    ProviderInvocationTransport::Local,
                )
            };
            let store = custody_provider::node_share_store_dir(&root);
            crate::host_trust::write_host_trust(
                &data_dir,
                crate::host_trust::HostTrustModeV1::WciOperated,
                None,
            )
            .unwrap();
            let foreign = signing_key(0x54);
            assert!(deliver(delivery(runtime_issuer(0x54), &foreign))
                .await
                .unwrap_err()
                .contains("provisioning_refused"));
            assert!(deliver(delivery(local_issuer, &device_key))
                .await
                .unwrap_err()
                .contains(crate::host_trust::HOST_STORAGE_MAX_UNSET));
            assert!(!store.exists());
            crate::host_trust::seed_wci_host_for_test(&data_dir);
            let carrier = Arc::new(ShareDeliveryFixture::default());
            registry.set_carrier_invoker(carrier.clone()).await;
            let content =
                crate::protected_content_runtime::tests::register_remote_seal_content_fixture(
                    &registry,
                    device_key.clone(),
                )
                .await;
            let refused = staged
                .deliver_shares(&data_dir, &registry, &finalized)
                .await
                .err()
                .unwrap();
            assert_eq!(refused.to_string(), "seal_share_receipt_mismatch");
            assert_eq!(staged.delivered_shares.len(), 2);
            assert!(store.is_dir());
            assert!(matches!(
                staged.publish(&data_dir, &registry, &finalized).await,
                Err(error) if error.to_string() == "remote sealed object has incomplete custody receipts"
            ));
            assert!(content.requests().await.is_empty());
            let receipts = staged
                .deliver_shares(&data_dir, &registry, &finalized)
                .await
                .unwrap();
            assert_eq!(receipts.len(), 3);
            {
                let counted = carrier.requests.lock().unwrap();
                assert_eq!(counted.get(&node_public_key(2)), Some(&1));
                assert_eq!(counted.get(&node_public_key(3)), Some(&2));
            }
            let completed = staged
                .complete(&data_dir, &registry, &finalized)
                .await
                .unwrap();
            let (statement, _) = completed
                .verify_for_request_at(&descriptor, &request, admitted.node, crate::auth::now_ts())
                .unwrap();
            assert_eq!(statement.content_publisher_did, publisher);
            assert_eq!(
                statement.mint_request_hash,
                request.canonical_hash().unwrap()
            );
            assert_eq!(
                statement.content_access_id,
                request.statement().content_access_id
            );
            assert_eq!(
                statement.key_envelope,
                finalized.envelope.key_envelope_identity().unwrap()
            );
            assert_eq!(statement.file_cids.len(), 2);
            let calls = content.requests().await.len();
            let replay = staged
                .complete(&data_dir, &registry, &finalized)
                .await
                .unwrap();
            assert_eq!(replay, completed);
            assert_eq!(content.requests().await.len(), calls);

            let session = staged.attestation.session_id();
            drop(staged);
            let completion_store = SealerCompletionStore::new(&data_dir);
            let stored = completion_store
                .replay(&source, session, crate::auth::now_ts())
                .unwrap();
            assert_eq!(stored, Some(completed));
            assert!(completion_store
                .replay(&different_home, session, crate::auth::now_ts())
                .unwrap()
                .is_none());
            assert!(completion_store
                .replay(&source, session, request.statement().expires_at)
                .unwrap()
                .is_none());

            use elastos_protected_content_runtime::{
                PoolRemoteSealTransport, PoolTransportError, RemoteSealTransport,
                RemoteSealUploadPieceV1,
            };
            let transport = PoolRemoteSealTransport(SealIngressFixture {
                registry: &registry,
                endpoint: &source.endpoint_did,
            });
            let foreign = PoolRemoteSealTransport(SealIngressFixture {
                registry: &registry,
                endpoint: &different_home.endpoint_did,
            });
            let mut statement = request.statement().clone();
            statement.request_nonce = [3; 16];
            statement.content_access_id = ContentAccessIdV1::new([3; 16]).unwrap();
            let signature = signing_key(POOL_AUTHORITY_SEED)
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes();
            let routed_request = SignedMintRequestV1::new(statement, signature).unwrap();
            let peer = descriptor.member_peer_did(admitted.node).unwrap();
            let stored_before =
                crate::protected_content_runtime::host_custody_storage_bytes(&data_dir).unwrap();
            let reserved =
                storage::staging_reservation(&routed_request.statement().clear_layout).unwrap();
            crate::host_trust::write_host_trust(
                &data_dir,
                crate::host_trust::HostTrustModeV1::WciOperated,
                Some(stored_before + reserved),
            )
            .unwrap();
            let opened = transport
                .open(peer, &routed_request, &descriptor)
                .await
                .unwrap();
            let repeat = transport
                .open(peer, &routed_request, &descriptor)
                .await
                .unwrap();
            assert_eq!(opened.attestation, repeat.attestation);
            assert_eq!(
                crate::protected_content_runtime::host_custody_storage_bytes(&data_dir).unwrap(),
                stored_before + reserved,
            );
            let denied = crate::protected_content_runtime::guarded_host_share_write(
                data_dir.clone(),
                1,
                || false,
                || async { panic!("remote upload reservation must block another host write") },
            )
            .await
            .unwrap();
            assert_eq!(denied["code"], crate::host_trust::HOST_STORAGE_FULL);
            assert!(matches!(
                foreign.resume(peer, opened.session_id).await,
                Err(PoolTransportError::Refused(code)) if code == "seal_session_lost"
            ));
            assert_eq!(
                transport
                    .resume(peer, opened.session_id)
                    .await
                    .unwrap()
                    .last_acked,
                None
            );
            let aad = elastos_protected_content_contracts::MintPieceAadV1 {
                mint_request_hash: routed_request.canonical_hash().unwrap(),
                part,
                piece: 0,
                piece_count: 1,
            };
            let sealed = elastos_protected_content_custody::seal_mint_piece_v1(
                &opened.attestation.statement().seal_session_public_key,
                &aad,
                &clear,
            )
            .unwrap();
            for _ in 0..2 {
                let ack = transport
                    .upload(
                        peer,
                        opened.session_id,
                        RemoteSealUploadPieceV1 {
                            aad,
                            part_clear_sha256: elastos_protected_content_contracts::Digest32::new(
                                Sha256::digest(clear).into(),
                            ),
                            sealed: sealed.clone(),
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(ack.last_acked, Some(part));
            }
            assert_eq!(
                crate::protected_content_runtime::host_custody_storage_bytes(&data_dir).unwrap(),
                stored_before + reserved,
            );
            crate::host_trust::write_host_trust(
                &data_dir,
                crate::host_trust::HostTrustModeV1::WciOperated,
                Some(1 << 40),
            )
            .unwrap();
            let completed = transport.finalize(peer, opened.session_id).await.unwrap();
            let (receipt, _) = completed
                .verify_for_request_at(
                    &descriptor,
                    &routed_request,
                    admitted.node,
                    crate::auth::now_ts(),
                )
                .unwrap();
            assert_eq!(
                receipt.content_access_id,
                routed_request.statement().content_access_id
            );
            assert_eq!(
                transport.finalize(peer, opened.session_id).await.unwrap(),
                completed
            );
            assert!(matches!(
                foreign.finalize(peer, opened.session_id).await,
                Err(PoolTransportError::Refused(code)) if code == "seal_session_lost"
            ));
            registry
                .unregister_runtime_provider_target(crate::custody_surface::TARGET_CUSTODY_POOL)
                .await
                .unwrap();
            crate::custody_pool_service::register_custody_pool_service(&registry, &data_dir)
                .await
                .unwrap();
            assert_eq!(
                transport.finalize(peer, opened.session_id).await.unwrap(),
                completed
            );

            let mut expiring = request.statement().clone();
            expiring.request_nonce = [0x28; 16];
            expiring.content_access_id = ContentAccessIdV1::new([0x28; 16]).unwrap();
            expiring.issued_at = crate::auth::now_ts();
            expiring.expires_at = expiring.issued_at + 60;
            let signature = signing_key(POOL_AUTHORITY_SEED)
                .sign(&expiring.canonical_bytes().unwrap())
                .to_bytes();
            let expiring = SignedMintRequestV1::new(expiring, signature).unwrap();
            service::check_expiry_during_part(
                &data_dir,
                &registry,
                &descriptor,
                &expiring,
                &source,
                &clear,
            )
            .await;

            check_remote_dash_publication(&registry, &source.endpoint_did, &descriptor, &request)
                .await;
            check_library_remote_mint(&data_dir, &registry, &descriptor, content).await;

            registry
                .unregister_runtime_provider_target(PROTECT_PROVIDER_ID)
                .await
                .unwrap();
            registry
                .unregister_runtime_provider_target(TARGET_CUSTODY)
                .await
                .unwrap();
        }
    }

    async fn check_remote_dash_publication(
        registry: &ProviderRegistry,
        minter: &str,
        descriptor: &SignedPoolDescriptorAnyV1,
        original: &SignedMintRequestV1,
    ) {
        use crate::protected_content_runtime::tests::media_dash_fixture;
        use elastos_protected_content_contracts::{ClearRenditionV1, Digest32, MintPieceAadV1};
        use elastos_protected_content_provider_contracts::CencDashMediaIdentityV2;
        use elastos_protected_content_runtime::{
            PoolRemoteSealTransport, RemoteSealTransport, RemoteSealUploadPieceV1,
        };
        use sha2::{Digest as _, Sha256};

        let now = crate::auth::now_ts();
        let kinds = [
            CencDashRenditionKindV2::Video,
            CencDashRenditionKindV2::Audio,
        ];
        let inits = kinds.map(|kind| media_dash_fixture::init(kind, 1));
        let segments = kinds.map(|kind| media_dash_fixture::clear_segments(kind, 1));
        let mut request = original.statement().clone();
        request.clear_layout = ClearLayoutV1::DashV2 {
            renditions: kinds
                .iter()
                .enumerate()
                .map(|(index, kind)| ClearRenditionV1 {
                    kind: kind.code(),
                    init_len: inits[index].len() as u32,
                    segment_lengths: segments[index]
                        .iter()
                        .map(|segment| segment.len() as u32)
                        .collect(),
                })
                .collect(),
        };
        request.content_access_id = ContentAccessIdV1::new([0x26; 16]).unwrap();
        request.request_nonce = [0x26; 16];
        request.issued_at = now;
        request.expires_at = now + 60;
        let signature = signing_key(POOL_AUTHORITY_SEED).sign(&request.canonical_bytes().unwrap());
        let request = SignedMintRequestV1::new(request, signature.to_bytes()).unwrap();
        let node = node_public_key(1);
        let peer = descriptor.member_peer_did(node).unwrap();
        let transport = PoolRemoteSealTransport(SealIngressFixture {
            registry,
            endpoint: minter,
        });
        let opened = transport.open(peer, &request, descriptor).await.unwrap();
        let request_hash = request.canonical_hash().unwrap();
        let key = &opened.attestation.statement().seal_session_public_key;
        let parts = request.statement().clear_layout.parts().unwrap();
        for ((part, _), clear) in parts
            .into_iter()
            .zip(inits.iter().chain(segments.iter().flatten()))
        {
            let aad = MintPieceAadV1 {
                mint_request_hash: request_hash,
                part,
                piece: 0,
                piece_count: 1,
            };
            let sealed =
                elastos_protected_content_custody::seal_mint_piece_v1(key, &aad, clear).unwrap();
            let reply = transport
                .upload(
                    peer,
                    opened.session_id,
                    RemoteSealUploadPieceV1 {
                        aad,
                        part_clear_sha256: Digest32::new(Sha256::digest(clear).into()),
                        sealed,
                    },
                )
                .await
                .unwrap();
            assert_eq!(reply.last_acked, Some(part));
        }
        let completed = transport.finalize(peer, opened.session_id).await.unwrap();
        let (statement, _) = completed
            .verify_for_request_at(descriptor, &request, node, crate::auth::now_ts())
            .unwrap();
        let head =
            CencDashMediaIdentityV2::from_canonical_bytes(&statement.content_identity).unwrap();
        assert_eq!(head.default_kid(), request.statement().content_access_id);
        assert_eq!(head.renditions().len(), 2);
        let manifest =
            crate::content::fetch_content_object_manifest(registry, &statement.package_cid)
                .await
                .unwrap();
        crate::protected_content_runtime::verify_protected_content_dash_manifest(&manifest, &head)
            .unwrap();
        assert_eq!(statement.file_cids.len(), 6);
        assert_eq!(
            transport.finalize(peer, opened.session_id).await.unwrap(),
            completed
        );
    }

    async fn check_library_remote_mint(
        sealer_dir: &Path,
        sealer: &Arc<ProviderRegistry>,
        initial: &SignedPoolDescriptorAnyV1,
        content: Arc<crate::protected_content_runtime::tests::ContentAvailabilityTestProvider>,
    ) {
        use crate::protected_content_runtime::{
            publish_runtime_custody_library_object, publish_runtime_custody_library_object_content,
            runtime_mint_journal, tests::library_publish_test_input_with_renditions,
            RuntimeCustodyLibraryPublishObjectInput,
        };
        use elastos_protected_content_contracts::{
            Digest32, MintPolicyV1, PoolDescriptorStatementV3, PoolMemberV2, PoolMemberV3,
            SignedPoolDescriptorV3,
        };

        let temp = safe_ancestor_tempdir();
        let home = temp.path().join("minter");
        owner_only_dir(&home);
        let (key, minter_did) = elastos_identity::load_or_create_did(&home).unwrap();
        let issuer = RuntimeOperationIssuerKeyV1::new(key.verifying_key().to_bytes()).unwrap();
        let SignedPoolDescriptorAnyV1::V3(previous) = initial else {
            panic!("test pool must have v3 trust")
        };
        let previous = previous.statement();
        let members = previous
            .members()
            .iter()
            .map(|member| {
                let mut roles = member.roles();
                roles.seal = member.member().node_public_key() == node_public_key(1);
                let route = PoolMemberV2::new(
                    member.member().node_public_key(),
                    roles,
                    member.route().clone(),
                )
                .unwrap();
                PoolMemberV3::new(route, member.attestation().to_vec()).unwrap()
            })
            .collect();
        let descriptor = PoolDescriptorStatementV3::new(
            *previous.pool(),
            previous.sequence() + 1,
            previous.epochs().to_vec(),
            members,
            *previous.serve_policy(),
            MintPolicyV1::owner_default(issuer),
            previous.issued_at(),
            previous.expires_at(),
            previous.trust_mode(),
        )
        .unwrap();
        let signature =
            signing_key(POOL_AUTHORITY_SEED).sign(&descriptor.canonical_bytes().unwrap());
        let descriptor: SignedPoolDescriptorAnyV1 =
            SignedPoolDescriptorV3::new(descriptor, signature.to_bytes().to_vec())
                .unwrap()
                .into();
        let encode = |bytes: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(bytes);
        custody_consent::update_served_pools(sealer_dir, |pools| {
            let entry = pools.entries.values_mut().next().unwrap();
            entry.descriptor = Some(encode(descriptor.canonical_bytes().unwrap()));
            Ok(())
        })
        .unwrap();
        let write = custody_consent::lock_custody_writes().await;
        crate::custody_pool_resolver::keep_known_pool_for_test(
            &write,
            &home,
            "elastos-pool:remote-object",
            &descriptor,
            crate::auth::now_ts(),
        )
        .unwrap();
        drop(write);
        std::fs::write(
            home.join("config.toml"),
            "protected_content_remote_object_sealing = true\n",
        )
        .unwrap();
        let registry = Arc::new(ProviderRegistry::new());
        registry
            .register_sub_provider("content", content)
            .await
            .unwrap();
        crate::protected_content_runtime::tests::register_remote_seal_provisional_policy_fixture(
            &registry,
        )
        .await;
        let transport = Arc::new(LibrarySealCarrierFixture {
            sealer: sealer.clone(),
            sealer_did: descriptor
                .member_peer_did(node_public_key(1))
                .unwrap()
                .into(),
            minter_did,
            calls: std::sync::Mutex::new(Vec::new()),
        });
        registry.set_carrier_invoker(transport.clone()).await;
        let principal = "person:local:remote-library-mint";
        let input = RuntimeCustodyLibraryPublishObjectInput {
            principal_id: principal.into(),
            object_uri: format!(
                "{}/Documents/remote.pdf",
                crate::auth::principal_localhost_root(principal)
            ),
            source_storage: "plain_localhost_root".into(),
            content_type: "application/pdf".into(),
            wallet_account_id: "wallet-fixture".into(),
            wallet_account_address: format!("0x{}", "11".repeat(20)),
            creator_mint_source_digest: Digest32::new([0x51; 32]),
            copies: "0x1".into(),
            price: "5".into(),
            channel: format!("0x{}", "22".repeat(20)),
            pay_token: String::new(),
            clear_plaintext: b"remote PDF fixture".to_vec(),
            listing: None,
            pool_did: None,
        };
        let mint = || {
            publish_runtime_custody_library_object_content(&home, registry.clone(), input.clone())
        };
        let facts = mint().await.unwrap();
        let journal = runtime_mint_journal(&home);
        let (recorded_descriptor, request, completion) = journal
            .load_remote_mint_proof(facts.mint_id)
            .unwrap()
            .unwrap();
        assert_eq!(recorded_descriptor, descriptor);
        let output = elastos_protected_content_runtime::verify_recorded_remote_seal_attestation(
            &completion,
            &descriptor,
            &request,
            node_public_key(1),
        )
        .unwrap();
        assert_eq!(output.statement().package_cid, facts.content_cid);
        let record = journal.load(facts.mint_id).unwrap();
        assert_eq!(
            record.draft().content_access_id(),
            request.statement().content_access_id
        );
        assert_eq!(record.draft().content_identity(), output.identity());
        assert!(!record.all_receipts_present());
        assert_eq!(
            *transport.calls.lock().unwrap(),
            ["seal.open", "seal.part", "seal.finalize"]
        );
        let replay = mint().await.unwrap();
        assert_eq!(replay.mint_id, facts.mint_id);
        assert_eq!(replay.content_cid, facts.content_cid);
        assert_eq!(transport.calls.lock().unwrap().len(), 3);

        std::fs::write(
            home.join("config.toml"),
            "protected_content_remote_dash_sealing = true\n",
        )
        .unwrap();
        transport.calls.lock().unwrap().clear();
        let media = library_publish_test_input_with_renditions(
            &home,
            principal,
            &[
                (CencDashRenditionKindV2::Video, 1),
                (CencDashRenditionKindV2::Audio, 1),
            ],
        );
        let facts = publish_runtime_custody_library_object(&home, registry.clone(), media.clone())
            .await
            .unwrap();
        let (recorded_descriptor, request, completion) = journal
            .load_remote_mint_proof(facts.mint_id)
            .unwrap()
            .unwrap();
        assert_eq!(recorded_descriptor, descriptor);
        let verified = elastos_protected_content_runtime::verify_recorded_remote_seal_attestation(
            &completion,
            &descriptor,
            &request,
            node_public_key(1),
        )
        .unwrap();
        assert_eq!(verified.statement().package_cid, facts.content_cid);
        let record = journal.load(facts.mint_id).unwrap();
        let dash = record.draft().media_dash_identity().unwrap();
        assert_eq!(dash.default_kid(), request.statement().content_access_id);
        assert_eq!(dash.renditions().len(), 2);
        assert_eq!(record.draft().content_identity(), verified.identity());
        assert_eq!(
            *transport.calls.lock().unwrap(),
            [
                "seal.open",
                "seal.part",
                "seal.part",
                "seal.part",
                "seal.part",
                "seal.finalize"
            ]
        );
        std::fs::write(home.join("config.toml"), "").unwrap();
        let replay = publish_runtime_custody_library_object(&home, registry.clone(), media.clone())
            .await
            .unwrap();
        assert_eq!(replay.mint_id, facts.mint_id);
        let mut changed = media;
        changed.wallet_account_id = "different-wallet".into();
        assert!(
            publish_runtime_custody_library_object(&home, registry, changed)
                .await
                .is_err()
        );
        assert_eq!(transport.calls.lock().unwrap().len(), 6);
    }
}

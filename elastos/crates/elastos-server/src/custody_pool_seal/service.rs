//! Carrier ingress for remotely sealed objects. The pool provider supplies
//! the authenticated endpoint after checking the Runtime invocation envelope.

use base64::Engine as _;
use elastos_protected_content_contracts::{
    CanonicalContract, ClearPartIndexV1, Digest32, SignedMintRequestV1, SignedPoolDescriptorAnyV1,
    DEFAULT_MAX_SEALS_PER_SEALER_V1, MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1,
    SEAL_PIECE_MAX_CLEAR_BYTES, SEAL_PIECE_OVERHEAD_BYTES,
};
use elastos_protected_content_provider_contracts::{
    RemoteObjectSealTransferV1, RemoteSealAckFieldsV1, RemoteSealOpenFieldsV1,
    RemoteSealPartFieldsV1, RemoteSealSessionFieldsV1,
};
use elastos_protected_content_runtime::PoolSessionSource;
use elastos_runtime::provider::ProviderRegistry;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, path::Path, sync::Arc};
use tokio::sync::Mutex;

use super::{prepare_remote_seal_open, FinalizedRemoteObjectUpload, RemoteObjectUploadStaging};
use crate::custody_seal_completion::SealerCompletionStore;
use crate::custody_surface::{
    OP_CUSTODY_POOL_SEAL_FINALIZE, OP_CUSTODY_POOL_SEAL_OPEN, OP_CUSTODY_POOL_SEAL_PART,
    OP_CUSTODY_POOL_SEAL_RESUME,
};

const INVALID: &str = "invalid_request";
const LOST: &str = "seal_session_lost";

#[derive(Default)]
pub(crate) struct RemoteObjectSealService {
    by_request: Mutex<BTreeMap<Digest32, Arc<LiveUpload>>>,
}

struct LiveUpload {
    source: PoolSessionSource,
    session: [u8; 16],
    descriptor_digest: Digest32,
    expires_at: u64,
    opened: Value,
    state: Mutex<UploadState>,
}

struct UploadState {
    staging: RemoteObjectUploadStaging,
    finalized: Option<FinalizedRemoteObjectUpload>,
    last_piece: Option<(Digest32, Option<ClearPartIndexV1>)>,
}

impl RemoteObjectSealService {
    pub(crate) async fn answer(
        &self,
        data_dir: &Path,
        registry: &Arc<ProviderRegistry>,
        op: &str,
        mut request: Value,
        source: &PoolSessionSource,
        now: u64,
    ) -> Result<Value, &'static str> {
        if source.local {
            return Err("not_eligible_sealer");
        }
        request.as_object_mut().ok_or(INVALID)?.remove("op");
        match op {
            OP_CUSTODY_POOL_SEAL_OPEN => self.open(data_dir, registry, request, source, now).await,
            OP_CUSTODY_POOL_SEAL_PART => self.part(registry, request, source, now).await,
            OP_CUSTODY_POOL_SEAL_RESUME => {
                let id = session_id(request)?;
                let live = self.session(id, source, now).await?;
                let mut state = live.state.lock().await;
                if state.finalized.is_some() {
                    return Err(LOST);
                }
                let last_acked = state
                    .staging
                    .transfer(registry, RemoteObjectSealTransferV1::Resume)
                    .await
                    .map_err(transfer_error)?;
                state.last_piece = None;
                ack(id, None, last_acked)
            }
            OP_CUSTODY_POOL_SEAL_FINALIZE => {
                self.finalize(data_dir, registry, session_id(request)?, source, now)
                    .await
            }
            _ => Err(INVALID),
        }
    }

    async fn open(
        &self,
        data_dir: &Path,
        registry: &ProviderRegistry,
        request: Value,
        source: &PoolSessionSource,
        now: u64,
    ) -> Result<Value, &'static str> {
        let fields: RemoteSealOpenFieldsV1 = fields(request)?;
        let descriptor = SignedPoolDescriptorAnyV1::from_canonical_bytes(&decode_b64(
            &fields.descriptor,
            MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1,
        )?)
        .map_err(|_| INVALID)?;
        let request =
            SignedMintRequestV1::from_canonical_bytes(&decode_b64(&fields.mint_request, 8 * 1024)?)
                .map_err(|_| INVALID)?;
        let layout = &request.statement().clear_layout;
        let authority = prepare_remote_seal_open(data_dir, source, &descriptor, &request, now)
            .await
            .map_err(|error| match error.to_string().as_str() {
                "seal_publisher_unconfirmed" => "seal_publisher_unconfirmed",
                "self_seal_refused" => "self_seal_refused",
                _ => "not_eligible_sealer",
            })?;
        let request_hash = request.canonical_hash().map_err(|_| INVALID)?;
        let descriptor_digest = descriptor.canonical_hash().map_err(|_| INVALID)?;
        let mut uploads = self.by_request.lock().await;
        uploads.retain(|_, upload| now < upload.expires_at);
        if let Some(live) = uploads.get(&request_hash) {
            return if live.source == *source && live.descriptor_digest == descriptor_digest {
                Ok(live.opened.clone())
            } else {
                Err(LOST)
            };
        }
        if uploads.len() >= usize::from(DEFAULT_MAX_SEALS_PER_SEALER_V1) {
            return Err("pool_busy");
        }
        let reserved_bytes = super::storage::staging_reservation(layout).map_err(|_| INVALID)?;
        let storage = super::RemoteSealStorage::reserve(data_dir, reserved_bytes).await?;
        let staging = authority
            .open_staged_upload(storage, registry, &request)
            .await
            .map_err(|_| "seal_protect_unavailable")?;
        let session = staging.attestation.session_id();
        let expires_at = staging.attestation.statement().expires_at;
        let opened = json!({
            "seal_session_id": hex::encode(session),
            "attestation": base64::engine::general_purpose::STANDARD.encode(
                staging.attestation.canonical_bytes().map_err(|_| INVALID)?,
            ),
        });
        if SealerCompletionStore::new(data_dir)
            .replay(source, session, now)
            .map_err(|_| "publication_unavailable")?
            .is_none()
        {
            uploads.insert(
                request_hash,
                Arc::new(LiveUpload {
                    source: source.clone(),
                    session,
                    descriptor_digest,
                    expires_at,
                    opened: opened.clone(),
                    state: Mutex::new(UploadState {
                        staging,
                        finalized: None,
                        last_piece: None,
                    }),
                }),
            );
        }
        Ok(opened)
    }

    async fn part(
        &self,
        registry: &ProviderRegistry,
        request: Value,
        source: &PoolSessionSource,
        now: u64,
    ) -> Result<Value, &'static str> {
        let request: RemoteSealPartFieldsV1 = fields(request)?;
        let id = parse_hex(&request.seal_session_id)?;
        let live = self.session(id, source, now).await?;
        let mut state = live.state.lock().await;
        if state.finalized.is_some() {
            return Err(LOST);
        }
        let piece = request.piece;
        let transfer = RemoteObjectSealTransferV1::Part {
            part: request.part,
            piece,
            piece_count: request.piece_count,
            part_clear_sha256: parse_hex(&request.part_clear_sha256)?,
            sealed: request.sealed,
        };
        if let RemoteObjectSealTransferV1::Part { sealed, .. } = &transfer {
            if sealed.len()
                > (SEAL_PIECE_MAX_CLEAR_BYTES + SEAL_PIECE_OVERHEAD_BYTES).div_ceil(3) * 4
            {
                return Err(INVALID);
            }
        }
        let bytes = serde_json::to_vec(&transfer).map_err(|_| INVALID)?;
        let hash = Digest32::new(Sha256::digest(&bytes).into());
        if let Some((previous, last_acked)) = state.last_piece {
            if previous == hash {
                return ack(id, Some(piece), last_acked);
            }
        }
        let last_acked = state
            .staging
            .transfer(registry, transfer)
            .await
            .map_err(transfer_error)?;
        state.last_piece = Some((hash, last_acked));
        ack(id, Some(piece), last_acked)
    }

    async fn finalize(
        &self,
        data_dir: &Path,
        registry: &Arc<ProviderRegistry>,
        id: [u8; 16],
        source: &PoolSessionSource,
        now: u64,
    ) -> Result<Value, &'static str> {
        let completion = SealerCompletionStore::new(data_dir);
        let frame = serde_json::to_vec(&RemoteSealSessionFieldsV1 {
            seal_session_id: hex::encode(id),
        })
        .map_err(|_| INVALID)?;
        if let Some(replayed) = completion
            .replay_finalize(source, &frame, now)
            .map_err(|_| "publication_unavailable")?
        {
            return Ok(replayed);
        }
        let live = self.session(id, source, now).await?;
        let operation_data = data_dir.to_path_buf();
        let operation_registry = Arc::clone(registry);
        let operation_upload = Arc::clone(&live);
        // The provider bridge can finish a dispatched import after the caller
        // leaves. This task owns the spool and its reservation until settlement.
        let operation = async move {
            let mut guard = operation_upload.state.lock().await;
            let UploadState {
                staging, finalized, ..
            } = &mut *guard;
            if finalized.is_none() {
                *finalized = Some(
                    staging
                        .finalize(&operation_registry)
                        .await
                        .map_err(|_| "seal_finalize_unavailable")?,
                );
            }
            let object = finalized.as_ref().ok_or("seal_finalize_unavailable")?;
            staging
                .deliver_shares(&operation_data, &operation_registry, object)
                .await
                .map_err(|_| "publication_unavailable")?;
            staging
                .complete(&operation_data, &operation_registry, object)
                .await
                .map_err(|_| "publication_unavailable")?;
            drop(guard);
            Ok::<_, &'static str>(())
        };
        let task = match elastos_runtime::provider::dispatch::DispatchFence::current() {
            Some(fence) => tokio::spawn(async move { fence.scope(operation).await }),
            None => tokio::spawn(operation),
        };
        task.await.map_err(|_| "publication_unavailable")??;
        let reply = completion
            .replay_finalize(source, &frame, crate::auth::now_ts())
            .map_err(|_| "publication_unavailable")?
            .ok_or(LOST)?;
        self.by_request
            .lock()
            .await
            .retain(|_, upload| !Arc::ptr_eq(upload, &live));
        Ok(reply)
    }

    async fn session(
        &self,
        id: [u8; 16],
        source: &PoolSessionSource,
        now: u64,
    ) -> Result<Arc<LiveUpload>, &'static str> {
        let mut uploads = self.by_request.lock().await;
        uploads.retain(|_, upload| now < upload.expires_at);
        uploads
            .values()
            .find(|upload| upload.session == id && upload.source == *source)
            .cloned()
            .ok_or(LOST)
    }
}

fn transfer_error(error: anyhow::Error) -> &'static str {
    match error.to_string().as_str() {
        "seal_transfer_refused: seal_session_lost" => LOST,
        "seal_transfer_refused: invalid_request" => INVALID,
        "seal_resume_required" => "seal_resume_required",
        _ => "seal_protect_unavailable",
    }
}

fn fields<T: DeserializeOwned>(value: Value) -> Result<T, &'static str> {
    serde_json::from_value(value).map_err(|_| INVALID)
}

fn session_id(value: Value) -> Result<[u8; 16], &'static str> {
    let request: RemoteSealSessionFieldsV1 = fields(value)?;
    parse_hex(&request.seal_session_id)
}

fn parse_hex<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| INVALID)?;
    if hex::encode(bytes) != value || bytes == [0; N] {
        return Err(INVALID);
    }
    Ok(bytes)
}

fn decode_b64(value: &str, limit: usize) -> Result<Vec<u8>, &'static str> {
    if value.len() > limit.div_ceil(3) * 4 {
        return Err(INVALID);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| INVALID)?;
    if bytes.len() > limit {
        return Err(INVALID);
    }
    Ok(bytes)
}

fn ack(
    id: [u8; 16],
    piece: Option<u16>,
    last_acked: Option<ClearPartIndexV1>,
) -> Result<Value, &'static str> {
    serde_json::to_value(RemoteSealAckFieldsV1 {
        seal_session_id: hex::encode(id),
        piece,
        last_acked,
    })
    .map_err(|_| INVALID)
}

#[cfg(all(test, unix))]
pub(super) async fn check_expiry_during_part(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    descriptor: &SignedPoolDescriptorAnyV1,
    request: &SignedMintRequestV1,
    source: &PoolSessionSource,
    clear: &[u8],
) {
    use crate::protected_content_runtime::host_custody_storage_bytes;
    use elastos_protected_content_contracts::{MintPieceAadV1, SignedSealSessionAttestationV1};
    use std::time::Duration;

    let now = crate::auth::now_ts();
    let service = Arc::new(RemoteObjectSealService::default());
    let baseline = host_custody_storage_bytes(data_dir).unwrap();
    let opened = service
        .open(
            data_dir,
            registry,
            json!({
                "descriptor": base64::engine::general_purpose::STANDARD.encode(
                    descriptor.canonical_bytes().unwrap()
                ),
                "mint_request": base64::engine::general_purpose::STANDARD.encode(
                    request.canonical_bytes().unwrap()
                )
            }),
            source,
            now,
        )
        .await
        .unwrap();
    let id = parse_hex(opened["seal_session_id"].as_str().unwrap()).unwrap();
    let attestation = SignedSealSessionAttestationV1::from_canonical_bytes(
        &base64::engine::general_purpose::STANDARD
            .decode(opened["attestation"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let part = ClearPartIndexV1::ObjectChunk { index: 0 };
    let aad = MintPieceAadV1 {
        mint_request_hash: request.canonical_hash().unwrap(),
        part,
        piece: 0,
        piece_count: 1,
    };
    let sealed = elastos_protected_content_custody::seal_mint_piece_v1(
        &attestation.statement().seal_session_public_key,
        &aad,
        clear,
    )
    .unwrap();
    let fields = serde_json::to_value(RemoteSealPartFieldsV1 {
        seal_session_id: hex::encode(id),
        part,
        piece: 0,
        piece_count: 1,
        part_clear_sha256: hex::encode(Sha256::digest(clear)),
        sealed: base64::engine::general_purpose::STANDARD.encode(sealed),
    })
    .unwrap();
    let live = service.session(id, source, now).await.unwrap();
    let guard = live.state.lock().await;
    let spool = guard.staging.directory().to_owned();
    let charged = host_custody_storage_bytes(data_dir).unwrap();

    let start = || {
        let service = Arc::clone(&service);
        let registry = Arc::clone(registry);
        let source = source.clone();
        let fields = fields.clone();
        tokio::spawn(async move { service.part(&registry, fields, &source, now).await })
    };
    let cancelled = start();
    let active = start();
    // Both part calls have looked up the live upload and are waiting for its
    // state. The test holds one reference and the service map holds another.
    tokio::time::timeout(Duration::from_secs(2), async {
        while Arc::strong_count(&live) < 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        service.session(id, source, live.expires_at).await,
        Err(LOST)
    ));
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    assert!(charged > baseline);
    assert_eq!(host_custody_storage_bytes(data_dir).unwrap(), charged);
    assert!(spool.is_dir());

    drop(guard);
    assert_eq!(active.await.unwrap().unwrap()["last_acked"], json!(part));
    drop(live);
    assert!(!spool.exists());
    assert_eq!(host_custody_storage_bytes(data_dir).unwrap(), baseline);
}

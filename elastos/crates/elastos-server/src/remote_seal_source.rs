//! Already authorized object data as input to the remote seal client.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer as _, SigningKey};
use elastos_protected_content_contracts::{
    CanonicalContract, ClearLayoutV1, ClearPartIndexV1, Digest32, MintPieceAadV1, MintRequestV1,
    RecipientPublicKeyBytesV1, RuntimeOperationIssuerKeyV1, SignedMintRequestV1,
    SignedPoolDescriptorAnyV1, SEAL_OBJECT_CHUNK_CLEAR_BYTES, SEAL_PIECE_MAX_CLEAR_BYTES,
    SEAL_SESSION_GRACE_SECS,
};
use elastos_protected_content_custody::seal_mint_piece_v1;
use elastos_protected_content_runtime::{
    prepare_remote_seal_upload, RemoteSealLocalIdentity, RemoteSealPartSource,
    RemoteSealUploadError, RemoteSealedPartV1, RuntimeMintIntent, RuntimeMintJournal,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// Bind one signed remote request to an authorized object mint before sending
/// any bytes. A retry uses the persisted request even if its time window has
/// passed. The upload coordinator checks that window before network effects
/// and can recover an already recorded completion without a new dispatch.
pub fn prepare_remote_object_mint(
    journal: &RuntimeMintJournal,
    request_id: Digest32,
    content_type: &str,
    descriptor: &SignedPoolDescriptorAnyV1,
    device_key: &SigningKey,
    local: RemoteSealLocalIdentity<'_>,
    now: u64,
) -> anyhow::Result<RuntimeMintIntent> {
    let intent = journal.load_intent(request_id)?;
    let (_, length) = intent
        .object_source_identity()
        .ok_or_else(|| anyhow::anyhow!("remote seal source is not an object"))?;
    let clear_layout = ClearLayoutV1::Object {
        content_type: content_type.into(),
        length,
    };
    prepare_remote_mint(
        journal,
        intent,
        clear_layout,
        descriptor,
        device_key,
        local,
        now,
    )
}

/// Persist the exact signed layout and sealer selection before dispatch.
pub(super) fn prepare_remote_mint(
    journal: &RuntimeMintJournal,
    intent: RuntimeMintIntent,
    clear_layout: ClearLayoutV1,
    descriptor: &SignedPoolDescriptorAnyV1,
    device_key: &SigningKey,
    local: RemoteSealLocalIdentity<'_>,
    now: u64,
) -> anyhow::Result<RuntimeMintIntent> {
    let minter = RuntimeOperationIssuerKeyV1::new(device_key.verifying_key().to_bytes())?;
    if let Some(recorded) = intent.remote_seal_request() {
        let request = recorded.request().statement();
        anyhow::ensure!(
            recorded.descriptor() == descriptor
                && request.minter_issuer == minter
                && request.clear_layout == clear_layout,
            "recorded remote seal request differs from this mint"
        );
        return Ok(intent);
    }
    let mut request_nonce = [0; 16];
    getrandom::getrandom(&mut request_nonce)?;
    let request = MintRequestV1 {
        pool: *descriptor.pool(),
        epoch: intent.custody_epoch(),
        minter_issuer: minter,
        content_access_id: intent.content_access_id(),
        clear_layout,
        request_nonce,
        issued_at: now,
        expires_at: now
            .saturating_add(SEAL_SESSION_GRACE_SECS)
            .min(descriptor.expires_at()),
    };
    let signature = device_key.sign(&request.canonical_bytes()?).to_bytes();
    let request = SignedMintRequestV1::new(request, signature)?;
    Ok(prepare_remote_seal_upload(
        journal,
        intent.request_id(),
        request,
        descriptor.clone(),
        minter,
        local,
        now,
    )?)
}

/// Reads the file descriptor supplied by the authorized source resolver.
/// The source stores digests only. Clear chunks are bounded and zeroized.
pub struct RemoteSealObjectFile {
    file: Arc<Mutex<File>>,
    request_hash: Digest32,
    parts: Vec<(usize, Digest32)>,
}

/// Borrows the authenticated bytes returned by a Library read. Each blocking
/// encryption task owns only one bounded clear chunk.
pub struct RemoteSealObjectBytes<'a> {
    clear: &'a [u8],
    request_hash: Digest32,
}

impl<'a> RemoteSealObjectBytes<'a> {
    pub fn from_authorized_bytes(
        clear: &'a [u8],
        intent: &RuntimeMintIntent,
    ) -> anyhow::Result<Self> {
        let remote = intent
            .remote_seal_request()
            .ok_or_else(|| anyhow::anyhow!("remote seal request is not recorded"))?;
        let (sha256, length) = intent
            .object_source_identity()
            .ok_or_else(|| anyhow::anyhow!("remote seal source is not an object"))?;
        anyhow::ensure!(
            clear.len() as u64 == length && Digest32::new(Sha256::digest(clear).into()) == sha256,
            "remote seal source differs from the mint intent"
        );
        Ok(Self {
            clear,
            request_hash: remote.request().canonical_hash()?,
        })
    }
}

#[async_trait::async_trait]
impl RemoteSealPartSource for RemoteSealObjectBytes<'_> {
    async fn seal_part(
        &self,
        upload_key: &RecipientPublicKeyBytesV1,
        request_hash: Digest32,
        part: ClearPartIndexV1,
        expected_clear_bytes: u64,
    ) -> Result<RemoteSealedPartV1, RemoteSealUploadError> {
        let ClearPartIndexV1::ObjectChunk { index } = part else {
            return Err(RemoteSealUploadError::InvalidPart);
        };
        let chunk_size = SEAL_OBJECT_CHUNK_CLEAR_BYTES as usize;
        let start = (index as usize)
            .checked_mul(chunk_size)
            .filter(|start| *start < self.clear.len())
            .ok_or(RemoteSealUploadError::InvalidPart)?;
        let size = (self.clear.len() - start).min(chunk_size);
        if request_hash != self.request_hash || expected_clear_bytes != size as u64 {
            return Err(RemoteSealUploadError::InvalidPart);
        }
        let upload_key = *upload_key;
        let clear = Zeroizing::new(self.clear[start..start + size].to_vec());
        tokio::task::spawn_blocking(move || {
            let clear_sha256 = Digest32::new(Sha256::digest(&*clear).into());
            seal_remote_part(&upload_key, request_hash, part, &clear, clear_sha256)
        })
        .await
        .map_err(|_| RemoteSealUploadError::InvalidPart)?
    }
}

impl RemoteSealObjectFile {
    pub async fn from_authorized_file(
        file: File,
        intent: &RuntimeMintIntent,
    ) -> anyhow::Result<Self> {
        let remote = intent
            .remote_seal_request()
            .ok_or_else(|| anyhow::anyhow!("remote seal request is not recorded"))?;
        let (sha256, length) = intent
            .object_source_identity()
            .ok_or_else(|| anyhow::anyhow!("remote seal source is not an object"))?;
        let request_hash = remote.request().canonical_hash()?;
        let parts = remote.request().statement().clear_layout.parts()?;
        tokio::task::spawn_blocking(move || {
            Self::verify_file(file, request_hash, sha256, length, &parts)
        })
        .await?
    }

    fn verify_file(
        mut file: File,
        request_hash: Digest32,
        sha256: Digest32,
        length: u64,
        layout: &[(ClearPartIndexV1, u64)],
    ) -> anyhow::Result<Self> {
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file() && metadata.len() == length,
            "remote seal source length differs from the mint intent"
        );
        file.rewind()?;
        let mut input = Zeroizing::new(vec![0; SEAL_OBJECT_CHUNK_CLEAR_BYTES as usize]);
        let mut hash = Sha256::new();
        let mut parts = Vec::with_capacity(layout.len());
        let mut bytes_read = 0_u64;
        for &(part, size) in layout {
            let size = usize::try_from(size)?;
            anyhow::ensure!(
                part == (ClearPartIndexV1::ObjectChunk {
                    index: parts.len() as u32
                }) && (1..=input.len()).contains(&size),
                "remote seal source has an invalid object layout"
            );
            let bytes = &mut input[..size];
            file.read_exact(bytes)?;
            hash.update(&*bytes);
            parts.push((size, Digest32::new(Sha256::digest(bytes).into())));
            bytes_read += size as u64;
        }
        anyhow::ensure!(
            bytes_read == length
                && file.metadata()?.len() == length
                && Digest32::new(hash.finalize().into()) == sha256,
            "remote seal source differs from the mint intent"
        );
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            request_hash,
            parts,
        })
    }
}

#[async_trait::async_trait]
impl RemoteSealPartSource for RemoteSealObjectFile {
    async fn seal_part(
        &self,
        upload_key: &RecipientPublicKeyBytesV1,
        request_hash: Digest32,
        part: ClearPartIndexV1,
        expected_clear_bytes: u64,
    ) -> Result<RemoteSealedPartV1, RemoteSealUploadError> {
        let ClearPartIndexV1::ObjectChunk { index } = part else {
            return Err(RemoteSealUploadError::InvalidPart);
        };
        let &(size, expected_hash) = self
            .parts
            .get(index as usize)
            .ok_or(RemoteSealUploadError::InvalidPart)?;
        if request_hash != self.request_hash || expected_clear_bytes != size as u64 {
            return Err(RemoteSealUploadError::InvalidPart);
        }
        let file = self.file.clone();
        let upload_key = *upload_key;
        tokio::task::spawn_blocking(move || {
            let mut clear = Zeroizing::new(vec![0; size]);
            {
                let mut file = file
                    .lock()
                    .map_err(|_| RemoteSealUploadError::InvalidPart)?;
                file.seek(SeekFrom::Start(
                    u64::from(index) * SEAL_OBJECT_CHUNK_CLEAR_BYTES,
                ))
                .and_then(|_| file.read_exact(&mut clear))
                .map_err(|_| RemoteSealUploadError::InvalidPart)?;
            }
            let clear_sha256 = Digest32::new(Sha256::digest(&*clear).into());
            if clear_sha256 != expected_hash {
                return Err(RemoteSealUploadError::InvalidPart);
            }
            seal_remote_part(&upload_key, request_hash, part, &clear, clear_sha256)
        })
        .await
        .map_err(|_| RemoteSealUploadError::InvalidPart)?
    }
}

pub(crate) fn seal_remote_part(
    upload_key: &RecipientPublicKeyBytesV1,
    request_hash: Digest32,
    part: ClearPartIndexV1,
    clear: &[u8],
    clear_sha256: Digest32,
) -> Result<RemoteSealedPartV1, RemoteSealUploadError> {
    let piece_count = clear.len().div_ceil(SEAL_PIECE_MAX_CLEAR_BYTES) as u16;
    let pieces = clear
        .chunks(SEAL_PIECE_MAX_CLEAR_BYTES)
        .enumerate()
        .map(|(index, piece)| {
            let aad = MintPieceAadV1 {
                mint_request_hash: request_hash,
                part,
                piece: index as u16,
                piece_count,
            };
            seal_mint_piece_v1(upload_key, &aad, piece)
                .map_err(|_| RemoteSealUploadError::InvalidPart)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RemoteSealedPartV1 {
        clear_sha256,
        clear_bytes: clear.len() as u64,
        pieces,
    })
}

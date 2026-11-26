//! Stream the files from an authorized DASH preparation into a remote seal.

use elastos_protected_content_contracts::{
    CanonicalContract, ClearLayoutV1, ClearPartIndexV1, ClearRenditionV1, Digest32,
    RecipientPublicKeyBytesV1,
};
use elastos_protected_content_runtime::{
    RemoteSealPartSource, RemoteSealUploadError, RemoteSealedPartV1, RuntimeMintIntent,
    RuntimeMintIntentContentV1,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{
    read_runtime_media_prepared_part, runtime_prepared_segment_path, RuntimePreparedMediaV2,
};
use crate::remote_seal_source::seal_remote_part;

pub struct RemoteSealDashSource<'a> {
    media: &'a RuntimePreparedMediaV2,
    request_hash: Digest32,
}

impl<'a> RemoteSealDashSource<'a> {
    /// The layout can be signed before opening a sealer. It contains sizes
    /// from validation, so neither signing nor opening needs a second read.
    pub fn layout(media: &RuntimePreparedMediaV2) -> anyhow::Result<ClearLayoutV1> {
        let renditions = media
            .renditions
            .iter()
            .map(|rendition| {
                anyhow::ensure!(
                    rendition.segment_parts.len() == rendition.segment_count as usize,
                    "prepared DASH rendition has incomplete segment evidence"
                );
                Ok(ClearRenditionV1 {
                    kind: rendition.kind.code(),
                    init_len: u32::try_from(rendition.clear_init_segment.len())?,
                    segment_lengths: rendition
                        .segment_parts
                        .iter()
                        .map(|(length, _)| *length)
                        .collect(),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let layout = ClearLayoutV1::DashV2 { renditions };
        layout.parts()?;
        Ok(layout)
    }

    /// Match the real preparation and signed layout to the saved mint.
    pub fn bind(
        media: &'a RuntimePreparedMediaV2,
        intent: &RuntimeMintIntent,
    ) -> anyhow::Result<Self> {
        let RuntimeMintIntentContentV1::MediaDash {
            preparation_receipt,
            ..
        } = intent.content()
        else {
            anyhow::bail!("remote seal source is not a DASH mint");
        };
        let remote = intent
            .remote_seal_request()
            .ok_or_else(|| anyhow::anyhow!("remote seal request is not recorded"))?;
        anyhow::ensure!(
            *preparation_receipt == media.preparation_receipt()
                && Self::layout(media)? == remote.request().statement().clear_layout,
            "the authorized DASH preparation differs from the remote seal request"
        );
        Ok(Self {
            media,
            request_hash: remote.request().canonical_hash()?,
        })
    }
}

#[async_trait::async_trait]
impl RemoteSealPartSource for RemoteSealDashSource<'_> {
    async fn seal_part(
        &self,
        upload_key: &RecipientPublicKeyBytesV1,
        request_hash: Digest32,
        part: ClearPartIndexV1,
        expected_clear_bytes: u64,
    ) -> Result<RemoteSealedPartV1, RemoteSealUploadError> {
        if self.request_hash != request_hash {
            return Err(RemoteSealUploadError::InvalidPart);
        }
        let rendition_code = match part {
            ClearPartIndexV1::DashInit { rendition }
            | ClearPartIndexV1::DashSegment { rendition, .. } => rendition,
            ClearPartIndexV1::ObjectChunk { .. } => return Err(RemoteSealUploadError::InvalidPart),
        };
        let rendition = self
            .media
            .renditions
            .iter()
            .find(|rendition| rendition.kind.code() == rendition_code)
            .ok_or(RemoteSealUploadError::InvalidPart)?;
        let upload_key = *upload_key;
        if let ClearPartIndexV1::DashSegment { index, .. } = part {
            let (length, expected_digest) = *rendition
                .segment_parts
                .get(index as usize)
                .filter(|(length, _)| u64::from(*length) == expected_clear_bytes)
                .ok_or(RemoteSealUploadError::InvalidPart)?;
            let path =
                runtime_prepared_segment_path(&self.media.operation_root, rendition.kind, index);
            return tokio::task::spawn_blocking(move || {
                let clear = Zeroizing::new(
                    read_runtime_media_prepared_part(&path, true, u64::from(length))
                        .map_err(|_| RemoteSealUploadError::InvalidPart)?,
                );
                if clear.len() != length as usize
                    || Digest32::new(Sha256::digest(&*clear).into()) != expected_digest
                {
                    return Err(RemoteSealUploadError::InvalidPart);
                }
                seal_remote_part(&upload_key, request_hash, part, &clear, expected_digest)
            })
            .await
            .map_err(|_| RemoteSealUploadError::InvalidPart)?;
        }
        if rendition.clear_init_segment.len() as u64 != expected_clear_bytes {
            return Err(RemoteSealUploadError::InvalidPart);
        }
        let clear = Zeroizing::new(rendition.clear_init_segment.clone());
        tokio::task::spawn_blocking(move || {
            let digest = Digest32::new(Sha256::digest(&*clear).into());
            seal_remote_part(&upload_key, request_hash, part, &clear, digest)
        })
        .await
        .map_err(|_| RemoteSealUploadError::InvalidPart)?
    }
}

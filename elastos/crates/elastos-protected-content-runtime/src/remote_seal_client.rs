//! Minter-side orchestration of one selected and journaled remote seal.

use elastos_protected_content_contracts::{
    CanonicalContract, ClearPartIndexV1, ContractError, Digest32, MintPieceAadV1, NodePublicKey,
    PoolContractError, RecipientPublicKeyBytesV1, RuntimeOperationIssuerKeyV1, SignedMintRequestV1,
    SignedPoolDescriptorAnyV1, SignedSealCompletedV1, SignedSealSessionAttestationV1,
    SEAL_PIECE_MAX_CLEAR_BYTES, SEAL_PIECE_OVERHEAD_BYTES,
};
use thiserror::Error;

use crate::{PoolTransportError, RuntimeMintJournal, RuntimeMintJournalError};

pub struct RemoteSealOpenedV1 {
    pub session_id: [u8; 16],
    pub attestation: SignedSealSessionAttestationV1,
}

pub struct RemoteSealAckV1 {
    pub session_id: [u8; 16],
    pub piece: Option<u16>,
    pub last_acked: Option<ClearPartIndexV1>,
}

pub struct RemoteSealUploadPieceV1 {
    pub aad: MintPieceAadV1,
    pub part_clear_sha256: Digest32,
    pub sealed: Vec<u8>,
}

#[async_trait::async_trait]
pub trait RemoteSealTransport: Send + Sync {
    /// Replies must come from the authenticated endpoint named by `peer`.
    async fn open(
        &self,
        peer: &str,
        request: &SignedMintRequestV1,
        descriptor: &SignedPoolDescriptorAnyV1,
    ) -> Result<RemoteSealOpenedV1, PoolTransportError>;

    async fn resume(
        &self,
        peer: &str,
        session: [u8; 16],
    ) -> Result<RemoteSealAckV1, PoolTransportError>;

    async fn upload(
        &self,
        peer: &str,
        session: [u8; 16],
        piece: RemoteSealUploadPieceV1,
    ) -> Result<RemoteSealAckV1, PoolTransportError>;

    async fn finalize(
        &self,
        peer: &str,
        session: [u8; 16],
    ) -> Result<SignedSealCompletedV1, PoolTransportError>;
}

pub struct RemoteSealedPartV1 {
    pub clear_sha256: Digest32,
    pub clear_bytes: u64,
    pub pieces: Vec<Vec<u8>>,
}

#[async_trait::async_trait]
pub trait RemoteSealPartSource: Send + Sync {
    /// Read the source bound to the intent, check its signed length, and
    /// seal the part in order. Clear bytes stay in the source's zeroizing
    /// buffer. Each piece uses the supplied request hash and part as AAD.
    async fn seal_part(
        &self,
        upload_key: &RecipientPublicKeyBytesV1,
        request_hash: Digest32,
        part: ClearPartIndexV1,
        expected_clear_bytes: u64,
    ) -> Result<RemoteSealedPartV1, RemoteSealUploadError>;
}

#[derive(Debug, Error)]
pub enum RemoteSealUploadError {
    #[error(transparent)]
    Journal(#[from] RuntimeMintJournalError),
    #[error(transparent)]
    Transport(#[from] PoolTransportError),
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error(transparent)]
    Completion(#[from] PoolContractError),
    #[error("remote seal returned an invalid upload acknowledgement")]
    InvalidAck,
    #[error("the remote seal source part does not match the signed layout")]
    InvalidPart,
}

/// Pick and persist a remote sealer before starting the upload. An existing
/// selection remains authoritative because its open may already have acted.
pub fn prepare_remote_seal_upload(
    journal: &RuntimeMintJournal,
    request_id: Digest32,
    request: SignedMintRequestV1,
    descriptor: SignedPoolDescriptorAnyV1,
    minter: RuntimeOperationIssuerKeyV1,
    local: RemoteSealLocalIdentity<'_>,
    now: u64,
) -> Result<crate::RuntimeMintIntent, RuntimeMintJournalError> {
    let intent = journal.load_intent(request_id)?;
    let mint = request.statement();
    if mint.minter_issuer != minter || local.endpoint_did.is_empty() {
        return Err(RuntimeMintJournalError::InvalidSelection);
    }
    let verified = descriptor
        .verify(now)
        .map_err(|_| RuntimeMintJournalError::InvalidSelection)?;
    let eligible = |member: &elastos_protected_content_contracts::PoolMemberV2| {
        verified.mint_policy().allow_self_seal
            || (member.route().peer_did() != local.endpoint_did
                && !local.node_keys.contains(&member.node_public_key()))
    };
    let selected = if let Some(recorded) = intent.remote_seal_request() {
        if recorded.request() != &request || recorded.descriptor() != &descriptor {
            return Err(RuntimeMintJournalError::Conflict);
        }
        verified
            .member(recorded.sealer())
            .filter(|member| eligible(member))
            .map(|member| member.node_public_key())
    } else {
        verified
            .members()
            .iter()
            .filter(|member| member.roles().seal && eligible(member))
            .filter(|member| {
                request
                    .verify_for_sealer(&descriptor, member.node_public_key(), now)
                    .is_ok()
            })
            .max_by_key(|member| {
                crate::pool_client::rendezvous_weight(&mint.request_nonce, member.node_public_key())
            })
            .map(|member| member.node_public_key())
    }
    .ok_or(RuntimeMintJournalError::InvalidSelection)?;
    journal
        .record_intent_remote_seal_request(request_id, request, descriptor, selected, minter, now)
}

pub struct RemoteSealLocalIdentity<'a> {
    pub endpoint_did: &'a str,
    pub node_keys: &'a [NodePublicKey],
}

/// Drive exactly the request already recorded in the mint journal. An
/// uncertain reply leaves progress recoverable by a later call to resume.
pub async fn upload_remote_seal(
    transport: &dyn RemoteSealTransport,
    source: &dyn RemoteSealPartSource,
    journal: &RuntimeMintJournal,
    request_id: Digest32,
    minter: RuntimeOperationIssuerKeyV1,
    now: &(dyn Fn() -> u64 + Sync),
) -> Result<SignedSealCompletedV1, RemoteSealUploadError> {
    if let Some(completion) = journal.load_remote_seal_completion(request_id, minter)? {
        return Ok(completion);
    }
    let intent = journal.load_intent(request_id)?;
    let remote = intent
        .remote_seal_request()
        .ok_or(RuntimeMintJournalError::Conflict)?;
    if remote.upload_is_acknowledged()? {
        return finish_remote_seal_upload(transport, journal, request_id, remote, minter, now)
            .await;
    }
    let peer = remote.verify_dispatch(minter, now())?;
    let layout = &remote.request().statement().clear_layout;
    let request_hash = remote.request().canonical_hash()?;
    let mut acknowledged = remote.session().and_then(|session| session.last_acked());

    let active = if let Some(session) = remote.session() {
        remote.verify_resume(minter, now())?;
        let ack = transport.resume(peer, session.session_id()).await?;
        if ack.session_id != session.session_id() || ack.piece.is_some() {
            return Err(RemoteSealUploadError::InvalidAck);
        }
        match ack.last_acked {
            Some(part) => {
                let next = layout
                    .part_position(part)
                    .ok_or(RemoteSealUploadError::InvalidAck)?;
                if acknowledged
                    .and_then(|previous| layout.part_position(previous))
                    .is_some_and(|previous| next < previous)
                {
                    return Err(RemoteSealUploadError::InvalidAck);
                }
                acknowledged = Some(part);
                journal.record_intent_remote_seal_ack(
                    request_id,
                    session.session_id(),
                    part,
                    minter,
                    now(),
                )?
            }
            None if acknowledged.is_some() => return Err(RemoteSealUploadError::InvalidAck),
            None => intent.clone(),
        }
    } else {
        let opened = transport
            .open(peer, remote.request(), remote.descriptor())
            .await?;
        journal.record_intent_remote_seal_session(
            request_id,
            opened.session_id,
            opened.attestation,
            minter,
            now(),
        )?
    };
    let remote = active
        .remote_seal_request()
        .ok_or(RuntimeMintJournalError::Conflict)?;
    let session_id = remote
        .session()
        .ok_or(RuntimeMintJournalError::Conflict)?
        .session_id();
    let (peer, upload_key) = remote.verify_resume(minter, now())?;
    let start = acknowledged
        .and_then(|part| layout.part_position(part))
        .map_or(0, |index| index + 1);
    for (part, bytes) in layout.parts()?.into_iter().skip(start as usize) {
        remote.verify_resume(minter, now())?;
        let sealed = source
            .seal_part(upload_key, request_hash, part, bytes)
            .await?;
        let count = bytes.div_ceil(SEAL_PIECE_MAX_CLEAR_BYTES as u64) as u16;
        if sealed.clear_bytes != bytes
            || sealed.clear_sha256 == Digest32::new([0; 32])
            || sealed.pieces.len() != usize::from(count)
        {
            return Err(RemoteSealUploadError::InvalidPart);
        }
        for (index, piece) in sealed.pieces.into_iter().enumerate() {
            remote.verify_resume(minter, now())?;
            let clear_bytes = (bytes as usize - index * SEAL_PIECE_MAX_CLEAR_BYTES)
                .min(SEAL_PIECE_MAX_CLEAR_BYTES);
            if piece.len() != clear_bytes + SEAL_PIECE_OVERHEAD_BYTES {
                return Err(RemoteSealUploadError::InvalidPart);
            }
            let piece_index = index as u16;
            let ack = transport
                .upload(
                    peer,
                    session_id,
                    RemoteSealUploadPieceV1 {
                        aad: MintPieceAadV1 {
                            mint_request_hash: request_hash,
                            part,
                            piece: piece_index,
                            piece_count: count,
                        },
                        part_clear_sha256: sealed.clear_sha256,
                        sealed: piece,
                    },
                )
                .await?;
            let expected = if piece_index + 1 == count {
                Some(part)
            } else {
                acknowledged
            };
            if ack.session_id != session_id
                || ack.piece != Some(piece_index)
                || ack.last_acked != expected
            {
                return Err(RemoteSealUploadError::InvalidAck);
            }
        }
        journal.record_intent_remote_seal_ack(request_id, session_id, part, minter, now())?;
        acknowledged = Some(part);
    }
    finish_remote_seal_upload(transport, journal, request_id, remote, minter, now).await
}

async fn finish_remote_seal_upload(
    transport: &dyn RemoteSealTransport,
    journal: &RuntimeMintJournal,
    request_id: Digest32,
    remote: &crate::RuntimeRemoteSealRequestV1,
    minter: RuntimeOperationIssuerKeyV1,
    now: &(dyn Fn() -> u64 + Sync),
) -> Result<SignedSealCompletedV1, RemoteSealUploadError> {
    let (peer, _) = remote.verify_resume(minter, now())?;
    let session_id = remote
        .session()
        .ok_or(RuntimeMintJournalError::Conflict)?
        .session_id();
    let completed = transport.finalize(peer, session_id).await?;
    completed.verify_for_request_at(
        remote.descriptor(),
        remote.request(),
        remote.sealer(),
        now(),
    )?;
    Ok(journal.record_remote_seal_completion(request_id, completed, minter, now())?)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    const FIRST: ClearPartIndexV1 = ClearPartIndexV1::ObjectChunk { index: 0 };
    const SECOND: ClearPartIndexV1 = ClearPartIndexV1::ObjectChunk { index: 1 };

    struct LostAck {
        accepted: AtomicBool,
        finalized: AtomicBool,
        session: [u8; 16],
        completion: Option<SignedSealCompletedV1>,
    }

    #[async_trait::async_trait]
    impl RemoteSealTransport for LostAck {
        async fn open(
            &self,
            _: &str,
            _: &SignedMintRequestV1,
            _: &SignedPoolDescriptorAnyV1,
        ) -> Result<RemoteSealOpenedV1, PoolTransportError> {
            panic!("a recorded session must resume without issuing a second Open");
        }

        async fn resume(
            &self,
            _: &str,
            session: [u8; 16],
        ) -> Result<RemoteSealAckV1, PoolTransportError> {
            assert_eq!(session, self.session);
            assert!(
                self.completion.is_none(),
                "a fully acknowledged upload should retry finalize directly"
            );
            Ok(RemoteSealAckV1 {
                session_id: session,
                piece: None,
                last_acked: Some(if self.accepted.load(Ordering::SeqCst) {
                    SECOND
                } else {
                    FIRST
                }),
            })
        }

        async fn upload(
            &self,
            _: &str,
            session: [u8; 16],
            piece: RemoteSealUploadPieceV1,
        ) -> Result<RemoteSealAckV1, PoolTransportError> {
            assert_eq!(session, self.session);
            assert_eq!(piece.aad.part, SECOND);
            assert_eq!((piece.aad.piece, piece.aad.piece_count), (0, 1));
            assert!(!self.accepted.swap(true, Ordering::SeqCst));
            Err(PoolTransportError::NoExactResult)
        }

        async fn finalize(
            &self,
            _: &str,
            session: [u8; 16],
        ) -> Result<SignedSealCompletedV1, PoolTransportError> {
            assert_eq!(session, self.session);
            assert!(self.accepted.load(Ordering::SeqCst));
            self.finalized.store(true, Ordering::SeqCst);
            self.completion
                .clone()
                .ok_or(PoolTransportError::NoExactResult)
        }
    }

    #[async_trait::async_trait]
    impl RemoteSealPartSource for LostAck {
        async fn seal_part(
            &self,
            _: &RecipientPublicKeyBytesV1,
            _: Digest32,
            part: ClearPartIndexV1,
            bytes: u64,
        ) -> Result<RemoteSealedPartV1, RemoteSealUploadError> {
            assert_eq!((part, bytes), (SECOND, 1));
            assert!(!self.accepted.load(Ordering::SeqCst));
            Ok(RemoteSealedPartV1 {
                clear_sha256: Digest32::new([0x55; 32]),
                clear_bytes: bytes,
                pieces: vec![vec![0; 1 + SEAL_PIECE_OVERHEAD_BYTES]],
            })
        }
    }

    pub(crate) async fn exercise_lost_ack(
        root: &std::path::Path,
        id: Digest32,
        session: [u8; 16],
        minter: RuntimeOperationIssuerKeyV1,
        now: u64,
    ) {
        let transport = LostAck {
            accepted: AtomicBool::new(false),
            finalized: AtomicBool::new(false),
            session,
            completion: None,
        };
        let journal = RuntimeMintJournal::new(root);
        journal
            .record_intent_remote_seal_ack(id, session, FIRST, minter, now)
            .unwrap();
        assert!(matches!(
            upload_remote_seal(&transport, &transport, &journal, id, minter, &|| now).await,
            Err(RemoteSealUploadError::Transport(
                PoolTransportError::NoExactResult
            ))
        ));
        assert!(transport.accepted.load(Ordering::SeqCst));
        assert!(!transport.finalized.load(Ordering::SeqCst));
        assert_eq!(
            journal
                .load_intent(id)
                .unwrap()
                .remote_seal_request()
                .unwrap()
                .session()
                .unwrap()
                .last_acked(),
            Some(FIRST),
        );
        let reopened = RuntimeMintJournal::new(root);
        assert!(matches!(
            upload_remote_seal(&transport, &transport, &reopened, id, minter, &|| now).await,
            Err(RemoteSealUploadError::Transport(
                PoolTransportError::NoExactResult
            ))
        ));
        assert!(transport.finalized.load(Ordering::SeqCst));
        assert_eq!(
            reopened
                .load_intent(id)
                .unwrap()
                .remote_seal_request()
                .unwrap()
                .session()
                .unwrap()
                .last_acked(),
            Some(SECOND),
        );
    }

    pub(crate) async fn exercise_finalize_replay(
        root: &std::path::Path,
        id: Digest32,
        session: [u8; 16],
        minter: RuntimeOperationIssuerKeyV1,
        now: u64,
        completion: SignedSealCompletedV1,
    ) {
        let transport = LostAck {
            accepted: AtomicBool::new(true),
            finalized: AtomicBool::new(false),
            session,
            completion: Some(completion.clone()),
        };
        let journal = RuntimeMintJournal::new(root);
        assert_eq!(
            upload_remote_seal(&transport, &transport, &journal, id, minter, &|| now)
                .await
                .unwrap(),
            completion
        );
        assert!(transport.finalized.load(Ordering::SeqCst));
        let restarted = RuntimeMintJournal::new(root);
        let offline = LostAck {
            accepted: AtomicBool::new(false),
            finalized: AtomicBool::new(false),
            ..transport
        };
        assert_eq!(
            upload_remote_seal(&offline, &offline, &restarted, id, minter, &|| now + 10_000)
                .await
                .unwrap(),
            completion
        );
        assert!(!offline.finalized.load(Ordering::SeqCst));
    }
}

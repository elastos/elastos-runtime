//! Isolated receiving side of a remote object upload.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};

use base64::Engine as _;
use elastos_protected_content_contracts::{
    CanonicalContract, ClearPartIndexV1, ContentAccessIdV1, Digest32, EncryptedContentIdentityV1,
    MintPieceAadV1, NodePublicKey, PoolDidV1, RuntimeOperationIssuerKeyV1,
    SealSessionAttestationV1, SignedMintRequestV1, SignedPoolDescriptorAnyV1,
    DEFAULT_MAX_SEALS_PER_SEALER_V1, MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1,
    SEAL_PIECE_MAX_CLEAR_BYTES, SEAL_PIECE_OVERHEAD_BYTES,
};
use elastos_protected_content_custody::{CustodyError, RemoteObjectSealerV1, RemoteSealedObjectV1};
use elastos_protected_content_provider_contracts::{
    CencDashMediaIdentityV2, FinalizeRemoteDashSealReplyV1, FinalizeRemoteDashSealRequestV1,
    FinalizeRemoteObjectSealReplyV1, FinalizeRemoteObjectSealRequestV1, OpenRemoteDashSealReplyV1,
    OpenRemoteDashSealRequestV1, OpenRemoteObjectSealReplyV1, OpenRemoteObjectSealRequestV1,
    RemoteObjectSealTransferV1, RemoteSealAckFieldsV1, RemoteSealOpenFieldsV1,
    RemoteSealPartFieldsV1, RemoteSealSessionFieldsV1, TransferRemoteDashSealReplyV1,
    TransferRemoteDashSealRequestV1, TransferRemoteObjectSealReplyV1,
    TransferRemoteObjectSealRequestV1,
};
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};

#[derive(Default)]
pub(super) struct PrivateRemoteUploads {
    sessions: BTreeMap<Digest32, PrivateRemoteUpload>,
}

struct PrivateRemoteUpload {
    endpoint: String,
    statement: SealSessionAttestationV1,
    content_access_id: ContentAccessIdV1,
    kind: SealKind,
    sealer: Option<PrivateSealer>,
    framed_header: Vec<u8>,
    last_transfer: Option<(Digest32, TransferRemoteObjectSealReplyV1)>,
    finalized: Option<(StagedIdentity, FinalizeRemoteObjectSealReplyV1)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SealKind {
    Object,
    Dash,
}

enum PrivateSealer {
    Object(Box<RemoteObjectSealerV1>),
    Dash(Box<super::RemoteDashSealerV1>),
}

#[derive(PartialEq, Eq)]
enum StagedIdentity {
    Object(EncryptedContentIdentityV1),
    Dash(CencDashMediaIdentityV2),
}

impl PrivateRemoteUploads {
    pub(super) fn len(&self) -> usize {
        self.sessions.len()
    }

    pub(super) fn expire(&mut self, now: u64) {
        self.sessions
            .retain(|_, upload| now < upload.statement.expires_at);
    }

    pub(super) fn open(
        &mut self,
        command: OpenRemoteObjectSealRequestV1,
        has_protect_slot: bool,
        now: u64,
    ) -> Result<OpenRemoteObjectSealReplyV1, CustodyError> {
        self.open_kind(command, SealKind::Object, has_protect_slot, now)
    }

    pub(super) fn open_dash(
        &mut self,
        command: OpenRemoteDashSealRequestV1,
        has_protect_slot: bool,
        now: u64,
    ) -> Result<OpenRemoteDashSealReplyV1, CustodyError> {
        let OpenRemoteDashSealRequestV1::OpenRemoteDashSeal {
            endpoint,
            minter_issuer,
            sealer_node,
            descriptor,
            mint_request,
        } = command;
        let reply = self.open_kind(
            OpenRemoteObjectSealRequestV1::OpenRemoteObjectSeal {
                endpoint,
                minter_issuer,
                sealer_node,
                descriptor,
                mint_request,
            },
            SealKind::Dash,
            has_protect_slot,
            now,
        )?;
        Ok(OpenRemoteDashSealReplyV1 {
            statement: reply.statement,
        })
    }

    fn open_kind(
        &mut self,
        command: OpenRemoteObjectSealRequestV1,
        kind: SealKind,
        has_protect_slot: bool,
        now: u64,
    ) -> Result<OpenRemoteObjectSealReplyV1, CustodyError> {
        let OpenRemoteObjectSealRequestV1::OpenRemoteObjectSeal {
            endpoint,
            minter_issuer,
            sealer_node,
            descriptor,
            mint_request,
        } = command;
        if endpoint.len() > 128
            || descriptor.len() > MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1
            || mint_request.len() > 8 * 1024
        {
            return Err(CustodyError::BindingMismatch("remote_object_open"));
        }
        let minter = RuntimeOperationIssuerKeyV1::new(minter_issuer)?;
        let node = NodePublicKey::new(sealer_node)?;
        let descriptor = SignedPoolDescriptorAnyV1::from_canonical_bytes(&descriptor)?;
        let request = SignedMintRequestV1::from_canonical_bytes(&mint_request)?;
        check_owner(&endpoint, minter, &request)?;
        let request_hash = request.canonical_hash()?;
        self.expire(now);
        if let Some(upload) = self.sessions.get(&request_hash) {
            let statement = &upload.statement;
            if kind != upload.kind
                || endpoint != upload.endpoint
                || node != statement.sealer_node_public_key
                || descriptor.canonical_hash()? != statement.descriptor_digest
            {
                return Err(CustodyError::BindingMismatch("remote_object_session"));
            }
            return Ok(OpenRemoteObjectSealReplyV1 {
                statement: statement.canonical_bytes()?,
                framed_header: upload.framed_header.clone(),
            });
        }
        let pool = *descriptor.pool();
        let pool_sessions = self
            .sessions
            .values()
            .filter(|upload| upload.statement.pool == pool)
            .count();
        if !has_protect_slot
            || self.sessions.len() >= usize::from(DEFAULT_MAX_SEALS_PER_SEALER_V1)
            || pool_sessions >= usize::from(descriptor.mint_policy().max_seals_per_sealer)
        {
            return Err(CustodyError::BindingMismatch("remote_object_pool_busy"));
        }

        let (sealer, statement, framed_header) = match kind {
            SealKind::Object => {
                let (sealer, header) =
                    RemoteObjectSealerV1::open(&request, &descriptor, node, now)?;
                let statement = sealer.attestation_statement()?;
                (PrivateSealer::Object(Box::new(sealer)), statement, header)
            }
            SealKind::Dash => {
                let sealer = super::RemoteDashSealerV1::open(&request, &descriptor, node, now)?;
                let statement = sealer.attestation_statement()?;
                (PrivateSealer::Dash(Box::new(sealer)), statement, Vec::new())
            }
        };
        let reply = OpenRemoteObjectSealReplyV1 {
            statement: statement.canonical_bytes()?,
            framed_header: framed_header.clone(),
        };
        self.sessions.insert(
            request_hash,
            PrivateRemoteUpload {
                endpoint,
                statement,
                content_access_id: request.statement().content_access_id,
                kind,
                sealer: Some(sealer),
                framed_header,
                last_transfer: None,
                finalized: None,
            },
        );
        Ok(reply)
    }

    pub(super) fn transfer(
        &mut self,
        command: TransferRemoteObjectSealRequestV1,
        now: u64,
    ) -> Result<TransferRemoteObjectSealReplyV1, CustodyError> {
        self.transfer_kind(command, SealKind::Object, now)
    }

    pub(super) fn transfer_dash(
        &mut self,
        command: TransferRemoteDashSealRequestV1,
        now: u64,
    ) -> Result<TransferRemoteDashSealReplyV1, CustodyError> {
        let TransferRemoteDashSealRequestV1::TransferRemoteDashSeal {
            endpoint,
            session_id,
            sequence,
            transfer,
        } = command;
        self.transfer_kind(
            TransferRemoteObjectSealRequestV1::TransferRemoteObjectSeal {
                endpoint,
                session_id,
                sequence,
                transfer,
            },
            SealKind::Dash,
            now,
        )
    }

    fn transfer_kind(
        &mut self,
        command: TransferRemoteObjectSealRequestV1,
        kind: SealKind,
        now: u64,
    ) -> Result<TransferRemoteObjectSealReplyV1, CustodyError> {
        let invalid = || CustodyError::BindingMismatch("remote_object_transfer");
        let TransferRemoteObjectSealRequestV1::TransferRemoteObjectSeal {
            endpoint,
            session_id,
            sequence,
            transfer,
        } = &command;
        let upload = self.session(endpoint, *session_id, kind, now)?;
        let sealer = upload
            .sealer
            .as_mut()
            .ok_or(CustodyError::BindingMismatch("remote_object_session"))?;
        if let RemoteObjectSealTransferV1::Part { sealed, .. } = transfer {
            let max_piece_bytes = SEAL_PIECE_MAX_CLEAR_BYTES + SEAL_PIECE_OVERHEAD_BYTES;
            if sealed.len() > max_piece_bytes.div_ceil(3) * 4 {
                return Err(invalid());
            }
        }
        let request_bytes = serde_json::to_vec(&command).map_err(|_| invalid())?;
        let digest = Digest32::new(Sha256::digest(&request_bytes).into());
        let mut previous_sequence = 0;
        if let Some((previous_digest, reply)) = &upload.last_transfer {
            if *sequence == reply.sequence && digest == *previous_digest {
                return Ok(reply.clone());
            }
            previous_sequence = reply.sequence;
        }
        if previous_sequence.checked_add(1) != Some(*sequence) {
            return Err(invalid());
        }

        let mut framed_chunk = None;
        let last_protected = match transfer {
            RemoteObjectSealTransferV1::Part {
                part,
                piece,
                piece_count,
                part_clear_sha256,
                sealed,
            } => {
                let sealed = decode_bytes(
                    sealed,
                    SEAL_PIECE_MAX_CLEAR_BYTES + SEAL_PIECE_OVERHEAD_BYTES,
                )?;
                let aad = MintPieceAadV1 {
                    mint_request_hash: upload.statement.mint_request_hash,
                    part: *part,
                    piece: *piece,
                    piece_count: *piece_count,
                };
                let mut stash_frame = |frame: &[u8]| {
                    framed_chunk = Some(base64::engine::general_purpose::STANDARD.encode(frame));
                    Ok(())
                };
                let hash = Digest32::new(*part_clear_sha256);
                match sealer {
                    PrivateSealer::Object(sealer) => {
                        sealer.stage_piece(&aad, hash, &sealed, now, stash_frame)?
                    }
                    PrivateSealer::Dash(sealer) => {
                        sealer
                            .stage_piece(&aad, hash, &sealed, now, |_, frame| stash_frame(frame))?
                    }
                }
            }
            RemoteObjectSealTransferV1::Resume => match sealer {
                PrivateSealer::Object(sealer) => sealer.resume_upload(now)?,
                PrivateSealer::Dash(sealer) => sealer.resume_upload(now)?,
            },
        };
        let reply = TransferRemoteObjectSealReplyV1 {
            session_id: *session_id,
            sequence: *sequence,
            last_protected,
            framed_chunk,
        };
        upload.last_transfer = Some((digest, reply.clone()));
        Ok(reply)
    }

    pub(super) fn finalize(
        &mut self,
        command: FinalizeRemoteObjectSealRequestV1,
        now: u64,
    ) -> Result<FinalizeRemoteObjectSealReplyV1, CustodyError> {
        let FinalizeRemoteObjectSealRequestV1::FinalizeRemoteObjectSeal {
            endpoint,
            session_id,
            sequence,
            ciphertext_sha256,
            ciphertext_bytes,
        } = command;
        let staged =
            EncryptedContentIdentityV1::new(Digest32::new(ciphertext_sha256), ciphertext_bytes)?;
        self.finalize_kind(
            &endpoint,
            session_id,
            sequence,
            StagedIdentity::Object(staged),
            now,
        )
    }

    pub(super) fn finalize_dash(
        &mut self,
        command: FinalizeRemoteDashSealRequestV1,
        now: u64,
    ) -> Result<FinalizeRemoteDashSealReplyV1, CustodyError> {
        let FinalizeRemoteDashSealRequestV1::FinalizeRemoteDashSeal {
            endpoint,
            session_id,
            sequence,
            staged_identity,
        } = command;
        let staged = CencDashMediaIdentityV2::from_canonical_bytes(&staged_identity)?;
        self.finalize_kind(
            &endpoint,
            session_id,
            sequence,
            StagedIdentity::Dash(staged),
            now,
        )
    }

    fn finalize_kind(
        &mut self,
        endpoint: &str,
        session_id: [u8; 16],
        sequence: u32,
        staged: StagedIdentity,
        now: u64,
    ) -> Result<FinalizeRemoteObjectSealReplyV1, CustodyError> {
        let kind = match &staged {
            StagedIdentity::Object(_) => SealKind::Object,
            StagedIdentity::Dash(_) => SealKind::Dash,
        };
        let upload = self.session(endpoint, session_id, kind, now)?;
        if upload
            .last_transfer
            .as_ref()
            .map(|(_, reply)| reply.sequence)
            != Some(sequence)
        {
            return Err(CustodyError::BindingMismatch("remote_object_transfer"));
        }
        if let Some((previous, reply)) = &upload.finalized {
            return if &staged == previous {
                Ok(reply.clone())
            } else {
                Err(CustodyError::BindingMismatch(
                    "remote_object_staged_ciphertext",
                ))
            };
        }
        let error = || CustodyError::BindingMismatch("remote_object_session");
        match (upload.sealer.as_ref().ok_or_else(error)?, &staged) {
            (PrivateSealer::Object(sealer), StagedIdentity::Object(staged)) => {
                sealer.check_staged_content(staged, now)?
            }
            (PrivateSealer::Dash(sealer), StagedIdentity::Dash(staged)) => {
                sealer.check_staged_content(staged, now)?
            }
            _ => return Err(error()),
        }
        let envelope = match (upload.sealer.take().ok_or_else(error)?, &staged) {
            (PrivateSealer::Object(sealer), StagedIdentity::Object(staged)) => {
                sealer.finish(staged, now)?.custody_envelope
            }
            (PrivateSealer::Dash(sealer), StagedIdentity::Dash(staged)) => {
                sealer.finish(staged, now)?
            }
            _ => return Err(error()),
        };
        let reply = FinalizeRemoteObjectSealReplyV1 {
            session_id,
            sequence,
            mint_request_hash: *upload.statement.mint_request_hash.as_bytes(),
            content_access_id: *upload.content_access_id.as_bytes(),
            custody_envelope: envelope.canonical_bytes()?,
        };
        upload.finalized = Some((staged, reply.clone()));
        Ok(reply)
    }

    fn session(
        &mut self,
        endpoint: &str,
        session_id: [u8; 16],
        kind: SealKind,
        now: u64,
    ) -> Result<&mut PrivateRemoteUpload, CustodyError> {
        self.sessions
            .values_mut()
            .find(|upload| {
                upload.statement.seal_session_id == session_id
                    && upload.endpoint == endpoint
                    && upload.kind == kind
                    && now >= upload.statement.issued_at
                    && now < upload.statement.expires_at
            })
            .ok_or(CustodyError::BindingMismatch("remote_object_session"))
    }
}

/// Uploads for one authorized pool and one local sealer. The caller resolves
/// the authenticated source's issuer and the current descriptor before open.
pub struct RemoteObjectUploadsV1<W> {
    pool: PoolDidV1,
    node: NodePublicKey,
    sessions: Vec<RemoteObjectReceiverV1<W>>,
}

impl<W: Read + Write + Seek> RemoteObjectUploadsV1<W> {
    pub fn new(pool: PoolDidV1, node: NodePublicKey) -> Self {
        Self {
            pool,
            node,
            sessions: Vec::new(),
        }
    }

    pub fn open_wire(
        &mut self,
        peer: &str,
        admitted_issuer: RuntimeOperationIssuerKeyV1,
        descriptor: &SignedPoolDescriptorAnyV1,
        frame: &[u8],
        now: u64,
        create_staging: impl FnOnce() -> Result<W, CustodyError>,
    ) -> Result<SealSessionAttestationV1, CustodyError> {
        if descriptor.pool() != &self.pool {
            return Err(CustodyError::BindingMismatch("remote_object_descriptor"));
        }
        let request = decode_open(frame, descriptor)?;
        check_owner(peer, admitted_issuer, &request)?;
        request
            .verify_for_sealer(descriptor, self.node, now)
            .map_err(|_| CustodyError::BindingMismatch("remote_object_descriptor"))?;
        self.expire(now);
        let request_hash = request.canonical_hash()?;
        if let Some(session) = self
            .sessions
            .iter()
            .find(|session| session.attestation.mint_request_hash == request_hash)
        {
            if session.owner != peer
                || session.attestation.descriptor_digest != descriptor.canonical_hash()?
            {
                return Err(CustodyError::BindingMismatch("remote_object_session"));
            }
            return Ok(session.attestation.clone());
        }
        let limit = descriptor.mint_policy().max_seals_per_sealer;
        if self.sessions.len() >= usize::from(limit) {
            return Err(CustodyError::BindingMismatch("remote_object_pool_busy"));
        }
        let session = RemoteObjectReceiverV1::open(
            peer.to_owned(),
            admitted_issuer,
            &request,
            descriptor,
            self.node,
            create_staging()?,
            now,
        )?;
        let attestation = session.attestation.clone();
        if self
            .sessions
            .iter()
            .any(|active| active.attestation.seal_session_id == attestation.seal_session_id)
        {
            return Err(CustodyError::BindingMismatch("remote_object_session"));
        }
        self.sessions.push(session);
        Ok(attestation)
    }

    /// A foreign peer and an unknown session have the same outcome.
    pub fn session(
        &mut self,
        peer: &str,
        id: [u8; 16],
        now: u64,
    ) -> Result<&mut RemoteObjectReceiverV1<W>, CustodyError> {
        self.expire(now);
        self.sessions
            .iter_mut()
            .find(|session| session.check_session(peer, id, now).is_ok())
            .ok_or(CustodyError::BindingMismatch("remote_object_session"))
    }

    pub fn expire(&mut self, now: u64) {
        self.sessions
            .retain(|session| now < session.attestation.expires_at);
    }
}

/// One provider-owned upload and its ciphertext staging sink. The caller
/// supplies the authenticated peer and its admitted issuer from trusted
/// configuration before routing the first request here.
pub struct RemoteObjectReceiverV1<W> {
    owner: String,
    attestation: SealSessionAttestationV1,
    sealer: Option<RemoteObjectSealerV1>,
    staged: W,
    staged_bytes: u64,
    last_acked: Option<ClearPartIndexV1>,
    finished: Option<RemoteSealedObjectV1>,
}

impl<W: Read + Write + Seek> RemoteObjectReceiverV1<W> {
    pub fn open_wire(
        owner: String,
        admitted_issuer: RuntimeOperationIssuerKeyV1,
        descriptor: &SignedPoolDescriptorAnyV1,
        sealer: NodePublicKey,
        frame: &[u8],
        staged: W,
        now: u64,
    ) -> Result<Self, CustodyError> {
        let request = decode_open(frame, descriptor)?;
        Self::open(
            owner,
            admitted_issuer,
            &request,
            descriptor,
            sealer,
            staged,
            now,
        )
    }

    pub fn upload_wire(
        &mut self,
        peer: &str,
        frame: &[u8],
        now: u64,
    ) -> Result<RemoteSealAckFieldsV1, CustodyError> {
        let fields: RemoteSealPartFieldsV1 = decode_frame(frame, 1024 * 1024)?;
        let session = decode_hex(&fields.seal_session_id)?;
        self.check_session(peer, session, now)?;
        let aad = MintPieceAadV1 {
            mint_request_hash: self.attestation.mint_request_hash,
            part: fields.part,
            piece: fields.piece,
            piece_count: fields.piece_count,
        };
        let clear_hash = Digest32::new(decode_hex(&fields.part_clear_sha256)?);
        let sealed = decode_bytes(
            &fields.sealed,
            SEAL_PIECE_MAX_CLEAR_BYTES + SEAL_PIECE_OVERHEAD_BYTES,
        )?;
        let last_acked = self.upload(peer, session, &aad, clear_hash, &sealed, now)?;
        Ok(RemoteSealAckFieldsV1 {
            seal_session_id: fields.seal_session_id,
            piece: Some(fields.piece),
            last_acked,
        })
    }

    pub fn resume_wire(
        &mut self,
        peer: &str,
        frame: &[u8],
        now: u64,
    ) -> Result<RemoteSealAckFieldsV1, CustodyError> {
        let fields: RemoteSealSessionFieldsV1 = decode_frame(frame, 128)?;
        let last_acked = self.resume(peer, decode_hex(&fields.seal_session_id)?, now)?;
        Ok(RemoteSealAckFieldsV1 {
            seal_session_id: fields.seal_session_id,
            piece: None,
            last_acked,
        })
    }

    pub fn finish_wire(
        &mut self,
        peer: &str,
        frame: &[u8],
        now: u64,
    ) -> Result<&RemoteSealedObjectV1, CustodyError> {
        let fields: RemoteSealSessionFieldsV1 = decode_frame(frame, 128)?;
        self.finish(peer, decode_hex(&fields.seal_session_id)?, now)
    }

    pub fn open(
        owner: String,
        admitted_issuer: RuntimeOperationIssuerKeyV1,
        request: &SignedMintRequestV1,
        descriptor: &SignedPoolDescriptorAnyV1,
        sealer: NodePublicKey,
        mut staged: W,
        now: u64,
    ) -> Result<Self, CustodyError> {
        check_owner(&owner, admitted_issuer, request)?;
        let (sealer, header) = RemoteObjectSealerV1::open(request, descriptor, sealer, now)?;
        let attestation = sealer.attestation_statement()?;
        if staged
            .seek(SeekFrom::End(0))
            .map_err(|_| CustodyError::PayloadIo)?
            != 0
        {
            return Err(CustodyError::PayloadIo);
        }
        stage_frame(&mut staged, &header)?;
        Ok(Self {
            owner,
            attestation,
            sealer: Some(sealer),
            staged,
            staged_bytes: header.len() as u64,
            last_acked: None,
            finished: None,
        })
    }

    pub fn attestation(&self) -> &SealSessionAttestationV1 {
        &self.attestation
    }

    pub fn upload(
        &mut self,
        peer: &str,
        session: [u8; 16],
        aad: &MintPieceAadV1,
        clear_sha256: Digest32,
        sealed: &[u8],
        now: u64,
    ) -> Result<Option<ClearPartIndexV1>, CustodyError> {
        self.check_session(peer, session, now)?;
        let sealer = self
            .sealer
            .as_mut()
            .ok_or(CustodyError::BindingMismatch("remote_object_session"))?;
        let staged = &mut self.staged;
        let staged_bytes = &mut self.staged_bytes;
        let ack = sealer.stage_piece(aad, clear_sha256, sealed, now, |frame| {
            stage_frame(staged, frame)?;
            *staged_bytes += frame.len() as u64;
            Ok(())
        })?;
        self.last_acked = ack;
        Ok(ack)
    }

    pub fn resume(
        &mut self,
        peer: &str,
        session: [u8; 16],
        now: u64,
    ) -> Result<Option<ClearPartIndexV1>, CustodyError> {
        self.check_session(peer, session, now)?;
        if self.finished.is_some() {
            return Ok(self.last_acked);
        }
        self.sealer
            .as_mut()
            .ok_or(CustodyError::BindingMismatch("remote_object_session"))?
            .resume_upload(now)
    }

    pub fn finish(
        &mut self,
        peer: &str,
        session: [u8; 16],
        now: u64,
    ) -> Result<&RemoteSealedObjectV1, CustodyError> {
        self.check_session(peer, session, now)?;
        if self.finished.is_none() {
            let sealer = self
                .sealer
                .as_ref()
                .ok_or(CustodyError::BindingMismatch("remote_object_session"))?;
            sealer.check_ready_to_finish(now)?;
            let identity = staged_identity(&mut self.staged, self.staged_bytes)?;
            let sealer = self
                .sealer
                .take()
                .ok_or(CustodyError::BindingMismatch("remote_object_session"))?;
            self.finished = Some(sealer.finish(&identity, now)?);
        }
        self.finished
            .as_ref()
            .ok_or(CustodyError::BindingMismatch("remote_object_session"))
    }

    fn check_session(&self, peer: &str, session: [u8; 16], now: u64) -> Result<(), CustodyError> {
        if peer != self.owner
            || session != self.attestation.seal_session_id
            || now < self.attestation.issued_at
            || now >= self.attestation.expires_at
        {
            return Err(CustodyError::BindingMismatch("remote_object_session"));
        }
        Ok(())
    }
}

fn check_owner(
    owner: &str,
    admitted_issuer: RuntimeOperationIssuerKeyV1,
    request: &SignedMintRequestV1,
) -> Result<(), CustodyError> {
    if owner.is_empty() || request.statement().minter_issuer != admitted_issuer {
        return Err(CustodyError::BindingMismatch("remote_object_owner"));
    }
    Ok(())
}

fn decode_open(
    frame: &[u8],
    descriptor: &SignedPoolDescriptorAnyV1,
) -> Result<SignedMintRequestV1, CustodyError> {
    let fields: RemoteSealOpenFieldsV1 = decode_frame(frame, 80 * 1024)?;
    let offered = decode_bytes(&fields.descriptor, MAX_SIGNED_POOL_DESCRIPTOR_BYTES_V1)?;
    if offered != descriptor.canonical_bytes()? {
        return Err(CustodyError::BindingMismatch("remote_object_descriptor"));
    }
    let request = decode_bytes(&fields.mint_request, 8 * 1024)?;
    Ok(SignedMintRequestV1::from_canonical_bytes(&request)?)
}

fn decode_frame<T: DeserializeOwned>(frame: &[u8], max: usize) -> Result<T, CustodyError> {
    if frame.len() > max {
        return Err(CustodyError::BindingMismatch("remote_object_frame"));
    }
    serde_json::from_slice(frame).map_err(|_| CustodyError::BindingMismatch("remote_object_frame"))
}

fn decode_bytes(text: &str, max: usize) -> Result<Vec<u8>, CustodyError> {
    let invalid = CustodyError::BindingMismatch("remote_object_frame");
    if text.len() > max.div_ceil(3) * 4 {
        return Err(invalid);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| CustodyError::BindingMismatch("remote_object_frame"))?;
    if bytes.len() > max {
        return Err(invalid);
    }
    Ok(bytes)
}

fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], CustodyError> {
    let mut bytes = [0; N];
    if text.bytes().any(|byte| byte.is_ascii_uppercase())
        || hex::decode_to_slice(text, &mut bytes).is_err()
    {
        return Err(CustodyError::BindingMismatch("remote_object_frame"));
    }
    Ok(bytes)
}

fn stage_frame(staged: &mut impl Write, frame: &[u8]) -> Result<(), CustodyError> {
    staged
        .write_all(frame)
        .and_then(|()| staged.flush())
        .map_err(|_| CustodyError::PayloadIo)
}

fn staged_identity(
    staged: &mut (impl Read + Seek),
    expected_bytes: u64,
) -> Result<EncryptedContentIdentityV1, CustodyError> {
    staged.rewind().map_err(|_| CustodyError::PayloadIo)?;
    let mut hash = Sha256::new();
    let read = std::io::copy(&mut staged.take(expected_bytes + 1), &mut hash)
        .map_err(|_| CustodyError::PayloadIo)?;
    if read != expected_bytes {
        return Err(CustodyError::BindingMismatch(
            "remote_object_staged_ciphertext",
        ));
    }
    Ok(EncryptedContentIdentityV1::new(
        Digest32::new(hash.finalize().into()),
        read,
    )?)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::tests::pool_custody_key;
    use ed25519_dalek::Signer as _;
    use elastos_protected_content_contracts::test_fixtures::{
        node_public_key, pool_bundle, pool_descriptor_signed_by, pool_did, runtime_issuer,
        signing_key, POOL_AUTHORITY_SEED,
    };
    use elastos_protected_content_contracts::{ClearLayoutV1, ContentAccessIdV1, MintRequestV1};
    use elastos_protected_content_custody::seal_mint_piece_v1;

    use super::*;

    #[test]
    fn remote_object_uploads_replay_open_for_the_same_peer_even_at_capacity() {
        let now = 2_000_000_000;
        let owner = "did:key:zMinter";
        let foreign = "did:key:zForeign";
        let issuer = runtime_issuer(POOL_AUTHORITY_SEED);
        let bundle = pool_bundle(pool_custody_key, now);
        let descriptor: SignedPoolDescriptorAnyV1 =
            pool_descriptor_signed_by(&bundle, 1, now, POOL_AUTHORITY_SEED).into();
        let successor: SignedPoolDescriptorAnyV1 =
            pool_descriptor_signed_by(&bundle, 2, now, POOL_AUTHORITY_SEED).into();
        let frame = |descriptor: &SignedPoolDescriptorAnyV1, nonce, issued_at| {
            let request = MintRequestV1 {
                pool: pool_did(),
                epoch: bundle.epoch_identity().unwrap(),
                minter_issuer: issuer,
                content_access_id: ContentAccessIdV1::new([nonce; 16]).unwrap(),
                clear_layout: ClearLayoutV1::Object {
                    content_type: "application/octet-stream".into(),
                    length: 1,
                },
                request_nonce: [nonce; 16],
                issued_at,
                expires_at: issued_at + 60,
            };
            let signature = signing_key(POOL_AUTHORITY_SEED)
                .sign(&request.canonical_bytes().unwrap())
                .to_bytes();
            let signed = SignedMintRequestV1::new(request, signature).unwrap();
            let base64 = base64::engine::general_purpose::STANDARD;
            serde_json::to_vec(&RemoteSealOpenFieldsV1 {
                mint_request: base64.encode(signed.canonical_bytes().unwrap()),
                descriptor: base64.encode(descriptor.canonical_bytes().unwrap()),
            })
            .unwrap()
        };
        let stage = || Ok(Cursor::new(Vec::new()));
        let must_not_stage = || panic!("retry or refusal must not allocate a sink");
        let mut uploads = RemoteObjectUploadsV1::new(pool_did(), node_public_key(1));
        let first = frame(&descriptor, 1, now);
        let opened = uploads
            .open_wire(owner, issuer, &descriptor, &first, now, stage)
            .unwrap();
        let cap = descriptor.mint_policy().max_seals_per_sealer;
        for nonce in 2..=cap {
            uploads
                .open_wire(
                    owner,
                    issuer,
                    &descriptor,
                    &frame(&descriptor, nonce, now),
                    now,
                    stage,
                )
                .unwrap();
        }
        assert_eq!(
            uploads
                .open_wire(owner, issuer, &descriptor, &first, now + 1, must_not_stage)
                .unwrap(),
            opened
        );
        for (peer, descriptor, retry) in [
            (foreign, &descriptor, first),
            (owner, &successor, frame(&successor, 1, now)),
        ] {
            assert!(matches!(
                uploads.open_wire(peer, issuer, descriptor, &retry, now + 1, must_not_stage),
                Err(CustodyError::BindingMismatch("remote_object_session"))
            ));
        }
        assert!(matches!(
            uploads.open_wire(
                owner,
                issuer,
                &descriptor,
                &frame(&descriptor, cap + 1, now),
                now + 1,
                must_not_stage
            ),
            Err(CustodyError::BindingMismatch("remote_object_pool_busy"))
        ));
        for (peer, id) in [(foreign, opened.seal_session_id), (owner, [0; 16])] {
            assert!(matches!(
                uploads.session(peer, id, now + 1),
                Err(CustodyError::BindingMismatch("remote_object_session"))
            ));
        }
        assert!(uploads
            .session(owner, opened.seal_session_id, now + 59)
            .is_ok());
        assert!(uploads
            .session(owner, opened.seal_session_id, now + 60)
            .is_err());
        assert!(uploads
            .open_wire(
                owner,
                issuer,
                &descriptor,
                &frame(&descriptor, cap + 1, now + 60),
                now + 60,
                stage
            )
            .is_ok());
    }

    #[test]
    fn remote_object_receiver_binds_owner_and_verifies_staged_bytes_before_finalizing() {
        let now = 2_000_000_000;
        let owner = "did:key:zMinter";
        let issuer = runtime_issuer(POOL_AUTHORITY_SEED);
        let bundle = pool_bundle(pool_custody_key, now);
        let descriptor = pool_descriptor_signed_by(&bundle, 1, now, POOL_AUTHORITY_SEED).into();
        let clear = b"object to protect";
        let request = MintRequestV1 {
            pool: pool_did(),
            epoch: bundle.epoch_identity().unwrap(),
            minter_issuer: issuer,
            content_access_id: ContentAccessIdV1::new([0x41; 16]).unwrap(),
            clear_layout: ClearLayoutV1::Object {
                content_type: "application/octet-stream".into(),
                length: clear.len() as u64,
            },
            request_nonce: [0x42; 16],
            issued_at: now,
            expires_at: now + 60,
        };
        let signature = signing_key(POOL_AUTHORITY_SEED)
            .sign(&request.canonical_bytes().unwrap())
            .to_bytes();
        let request = SignedMintRequestV1::new(request, signature).unwrap();
        let base64 = base64::engine::general_purpose::STANDARD;
        let descriptor: SignedPoolDescriptorAnyV1 = descriptor;
        let encode_open = |descriptor: &SignedPoolDescriptorAnyV1| {
            serde_json::to_vec(&RemoteSealOpenFieldsV1 {
                mint_request: base64.encode(request.canonical_bytes().unwrap()),
                descriptor: base64.encode(descriptor.canonical_bytes().unwrap()),
            })
            .unwrap()
        };
        let frame = encode_open(&descriptor);
        let open = |issuer, frame: &[u8], sink| {
            RemoteObjectReceiverV1::open_wire(
                owner.into(),
                issuer,
                &descriptor,
                node_public_key(1),
                frame,
                sink,
                now,
            )
        };
        assert!(open(runtime_issuer(0x43), &frame, Cursor::new(Vec::new())).is_err());
        assert!(open(issuer, &frame, Cursor::new(vec![0])).is_err());
        let different = pool_descriptor_signed_by(&bundle, 2, now, POOL_AUTHORITY_SEED).into();
        assert!(matches!(
            open(issuer, &encode_open(&different), Cursor::new(Vec::new())),
            Err(CustodyError::BindingMismatch("remote_object_descriptor"))
        ));
        let part = ClearPartIndexV1::ObjectChunk { index: 0 };
        let aad = MintPieceAadV1 {
            mint_request_hash: request.canonical_hash().unwrap(),
            part,
            piece: 0,
            piece_count: 1,
        };
        let sha256 = Digest32::new(Sha256::digest(clear).into());
        let stage = |receiver: &mut RemoteObjectReceiverV1<Cursor<Vec<u8>>>| {
            let attestation = receiver.attestation();
            let id = attestation.seal_session_id;
            let sealed =
                seal_mint_piece_v1(&attestation.seal_session_public_key, &aad, clear).unwrap();
            let session = serde_json::to_vec(&RemoteSealSessionFieldsV1 {
                seal_session_id: hex::encode(id),
            })
            .unwrap();
            let mut fields = RemoteSealPartFieldsV1 {
                seal_session_id: hex::encode(id),
                part,
                piece: 0,
                piece_count: 1,
                part_clear_sha256: hex::encode(sha256.as_bytes()),
                sealed: base64.encode(&sealed),
            };
            assert!(receiver.finish_wire(owner, &session, now + 1).is_err());
            let oversized = std::mem::replace(
                &mut fields.sealed,
                base64.encode(vec![
                    0;
                    SEAL_PIECE_MAX_CLEAR_BYTES
                        + SEAL_PIECE_OVERHEAD_BYTES
                        + 1
                ]),
            );
            assert!(receiver
                .upload_wire(owner, &serde_json::to_vec(&fields).unwrap(), now + 1)
                .is_err());
            fields.sealed = oversized;
            let upload = serde_json::to_vec(&fields).unwrap();
            assert!(receiver
                .upload_wire("did:key:zForeign", &upload, now + 1)
                .is_err());
            assert!(receiver
                .resume_wire(
                    owner,
                    br#"{"seal_session_id":"00","seal_session_id":"00"}"#,
                    now + 1
                )
                .is_err());
            assert_eq!(
                receiver
                    .resume_wire(owner, &session, now + 1)
                    .unwrap()
                    .last_acked,
                None
            );
            // Lose the upload response, then recover the cumulative acknowledgement.
            let _ = receiver.upload_wire(owner, &upload, now + 1).unwrap();
            let resumed = receiver.resume_wire(owner, &session, now + 2).unwrap();
            assert_eq!(resumed.seal_session_id, hex::encode(id));
            assert_eq!(resumed.piece, None);
            assert_eq!(resumed.last_acked, Some(part));
            session
        };

        let mut receiver = open(issuer, &frame, Cursor::new(Vec::new())).unwrap();
        let session = stage(&mut receiver);
        assert!(receiver
            .finish_wire("did:key:zForeign", &session, now + 2)
            .is_err());
        let expected = staged_identity(&mut receiver.staged, receiver.staged_bytes).unwrap();
        let envelope = receiver
            .finish_wire(owner, &session, now + 2)
            .unwrap()
            .custody_envelope
            .clone();
        assert_eq!(envelope.manifest().encrypted_content(), &expected);
        assert_eq!(
            receiver
                .resume_wire(owner, &session, now + 3)
                .unwrap()
                .last_acked,
            Some(part)
        );
        assert_eq!(
            &receiver
                .finish_wire(owner, &session, now + 3)
                .unwrap()
                .custody_envelope,
            &envelope
        );

        let mut tampered = open(issuer, &frame, Cursor::new(Vec::new())).unwrap();
        let session = stage(&mut tampered);
        tampered.staged.get_mut()[0] ^= 1;
        assert!(matches!(
            tampered.finish_wire(owner, &session, now + 2),
            Err(CustodyError::BindingMismatch(
                "remote_object_staged_ciphertext"
            ))
        ));
        assert!(tampered.resume_wire(owner, &session, now + 3).is_err());
    }
}

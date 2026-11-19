//! Remote-seal requests over the authenticated custody-pool transport.

use crate::remote_seal::MAX_REMOTE_SEAL_COMPLETION_BYTES;
use base64::Engine as _;
use elastos_protected_content_contracts::{
    CanonicalContract, PoolMemberRouteV2, SignedMintRequestV1, SignedPoolDescriptorAnyV1,
    SignedSealCompletedV1, SignedSealSessionAttestationV1, SEAL_PIECE_MAX_CLEAR_BYTES,
    SEAL_PIECE_OVERHEAD_BYTES,
};
use elastos_protected_content_provider_contracts::{
    RemoteSealAckFieldsV1, RemoteSealOpenFieldsV1, RemoteSealPartFieldsV1,
    RemoteSealSessionFieldsV1,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    PoolCallClass, PoolSessionTransport, PoolTransportError, RemoteSealAckV1, RemoteSealOpenedV1,
    RemoteSealTransport, RemoteSealUploadPieceV1,
};

const ATTESTATION_MAX_BYTES: usize = 4 * 1024;

pub struct PoolRemoteSealTransport<T>(pub T);

fn route_for(peer: &str) -> Result<PoolMemberRouteV2, PoolTransportError> {
    PoolMemberRouteV2::new(peer.to_owned()).map_err(|_| PoolTransportError::Unreachable)
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn encode_contract<T: CanonicalContract>(value: &T) -> Result<String, PoolTransportError> {
    value
        .canonical_bytes()
        .map(|bytes| encode(&bytes))
        .map_err(|_| PoolTransportError::Refused("invalid_request".into()))
}

fn decode_contract<T: CanonicalContract>(text: &str, cap: usize) -> Result<T, PoolTransportError> {
    if text.len() > cap.div_ceil(3) * 4 {
        return Err(PoolTransportError::NoExactResult);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| PoolTransportError::NoExactResult)?;
    if bytes.len() > cap {
        return Err(PoolTransportError::NoExactResult);
    }
    T::from_canonical_bytes(&bytes).map_err(|_| PoolTransportError::NoExactResult)
}

fn decode_id(id: &str) -> Result<[u8; 16], PoolTransportError> {
    let mut bytes = [0; 16];
    hex::decode_to_slice(id, &mut bytes).map_err(|_| PoolTransportError::NoExactResult)?;
    if bytes == [0; 16] || hex::encode(bytes) != id {
        return Err(PoolTransportError::NoExactResult);
    }
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenReply {
    seal_session_id: String,
    attestation: String,
}

fn decode_ack(
    reply: Value,
    expected_session: [u8; 16],
    expected_piece: Option<u16>,
) -> Result<RemoteSealAckV1, PoolTransportError> {
    let reply: RemoteSealAckFieldsV1 =
        serde_json::from_value(reply).map_err(|_| PoolTransportError::NoExactResult)?;
    let session_id = decode_id(&reply.seal_session_id)?;
    if session_id != expected_session || reply.piece != expected_piece {
        return Err(PoolTransportError::NoExactResult);
    }
    Ok(RemoteSealAckV1 {
        session_id,
        piece: reply.piece,
        last_acked: reply.last_acked,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizeReply {
    seal_completed: String,
}

#[async_trait::async_trait]
impl<T: PoolSessionTransport> RemoteSealTransport for PoolRemoteSealTransport<T> {
    async fn open(
        &self,
        peer: &str,
        request: &SignedMintRequestV1,
        descriptor: &SignedPoolDescriptorAnyV1,
    ) -> Result<RemoteSealOpenedV1, PoolTransportError> {
        let reply = self
            .0
            .call(
                &route_for(peer)?,
                "seal.open",
                PoolCallClass::Control,
                json!(RemoteSealOpenFieldsV1 {
                    mint_request: encode_contract(request)?,
                    descriptor: encode_contract(descriptor)?,
                }),
            )
            .await?;
        let reply: OpenReply =
            serde_json::from_value(reply).map_err(|_| PoolTransportError::NoExactResult)?;
        let session_id = decode_id(&reply.seal_session_id)?;
        let attestation: SignedSealSessionAttestationV1 =
            decode_contract(&reply.attestation, ATTESTATION_MAX_BYTES)?;
        if attestation.session_id() != session_id {
            return Err(PoolTransportError::NoExactResult);
        }
        Ok(RemoteSealOpenedV1 {
            session_id,
            attestation,
        })
    }

    async fn resume(
        &self,
        peer: &str,
        session: [u8; 16],
    ) -> Result<RemoteSealAckV1, PoolTransportError> {
        let reply = self
            .0
            .call(
                &route_for(peer)?,
                "seal.resume",
                PoolCallClass::Control,
                json!(RemoteSealSessionFieldsV1 {
                    seal_session_id: hex::encode(session)
                }),
            )
            .await?;
        decode_ack(reply, session, None)
    }

    async fn upload(
        &self,
        peer: &str,
        session: [u8; 16],
        piece: RemoteSealUploadPieceV1,
    ) -> Result<RemoteSealAckV1, PoolTransportError> {
        if piece.sealed.len() <= SEAL_PIECE_OVERHEAD_BYTES
            || piece.sealed.len() > SEAL_PIECE_MAX_CLEAR_BYTES + SEAL_PIECE_OVERHEAD_BYTES
            || piece.aad.canonical_bytes().is_err()
        {
            return Err(PoolTransportError::Refused("invalid_request".into()));
        }
        let reply = self
            .0
            .call(
                &route_for(peer)?,
                "seal.part",
                PoolCallClass::SealUpload,
                json!(RemoteSealPartFieldsV1 {
                    seal_session_id: hex::encode(session),
                    part: piece.aad.part,
                    piece: piece.aad.piece,
                    piece_count: piece.aad.piece_count,
                    part_clear_sha256: hex::encode(piece.part_clear_sha256.as_bytes()),
                    sealed: encode(&piece.sealed),
                }),
            )
            .await?;
        decode_ack(reply, session, Some(piece.aad.piece))
    }

    async fn finalize(
        &self,
        peer: &str,
        session: [u8; 16],
    ) -> Result<SignedSealCompletedV1, PoolTransportError> {
        let reply = self
            .0
            .call(
                &route_for(peer)?,
                "seal.finalize",
                PoolCallClass::SealFinalize,
                json!(RemoteSealSessionFieldsV1 {
                    seal_session_id: hex::encode(session)
                }),
            )
            .await?;
        let reply: FinalizeReply =
            serde_json::from_value(reply).map_err(|_| PoolTransportError::NoExactResult)?;
        decode_contract(&reply.seal_completed, MAX_REMOTE_SEAL_COMPLETION_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use elastos_protected_content_contracts::{ClearPartIndexV1, Digest32, MintPieceAadV1};

    use super::*;

    struct Calls {
        request: Mutex<Option<(&'static str, PoolCallClass, Value)>>,
        reply: Mutex<Value>,
    }

    #[async_trait::async_trait]
    impl PoolSessionTransport for Calls {
        async fn call(
            &self,
            route: &PoolMemberRouteV2,
            op: &'static str,
            class: PoolCallClass,
            body: Value,
        ) -> Result<Value, PoolTransportError> {
            assert_eq!(route.peer_did(), "did:key:z6MkPoolNode01");
            *self.request.lock().unwrap() = Some((op, class, body));
            Ok(self.reply.lock().unwrap().clone())
        }
    }

    #[tokio::test]
    async fn remote_seal_wire_bounds_uploads_and_correlates_acknowledgements() {
        let session = [0x42; 16];
        let part = ClearPartIndexV1::ObjectChunk { index: 2 };
        let good_ack = json!({
            "seal_session_id": hex::encode(session),
            "piece": 0,
            "last_acked": part,
        });
        let transport = PoolRemoteSealTransport(Calls {
            request: Mutex::new(None),
            reply: Mutex::new(good_ack.clone()),
        });
        let peer = "did:key:z6MkPoolNode01";
        let piece = |size| RemoteSealUploadPieceV1 {
            aad: MintPieceAadV1 {
                mint_request_hash: Digest32::new([0x51; 32]),
                part,
                piece: 0,
                piece_count: 1,
            },
            part_clear_sha256: Digest32::new([0x52; 32]),
            sealed: vec![0x53; size],
        };
        let size = SEAL_PIECE_OVERHEAD_BYTES + 1;
        assert!(matches!(
            transport
                .upload(peer, session, piece(SEAL_PIECE_OVERHEAD_BYTES))
                .await,
            Err(PoolTransportError::Refused(_))
        ));
        assert!(transport.0.request.lock().unwrap().is_none());
        let ack = transport.upload(peer, session, piece(size)).await.unwrap();
        assert_eq!(ack.last_acked, Some(part));
        let (op, class, body) = transport.0.request.lock().unwrap().take().unwrap();
        assert_eq!((op, class), ("seal.part", PoolCallClass::SealUpload));
        assert_eq!(body["part"], json!(part));
        assert_eq!(body["sealed"], encode(&vec![0x53; size]));
        assert_eq!(body.as_object().unwrap().len(), 6);

        for (key, invalid) in [
            ("seal_session_id", json!(hex::encode([0x43; 16]))),
            ("piece", json!(1)),
            (
                "last_acked",
                json!({"kind": "object_chunk", "index": 2, "extra": true}),
            ),
        ] {
            let mut reply = good_ack.clone();
            reply[key] = invalid;
            *transport.0.reply.lock().unwrap() = reply;
            assert!(matches!(
                transport.upload(peer, session, piece(size)).await,
                Err(PoolTransportError::NoExactResult)
            ));
        }
        *transport.0.reply.lock().unwrap() = good_ack.clone();
        assert!(matches!(
            transport.resume(peer, session).await,
            Err(PoolTransportError::NoExactResult)
        ));
        let mut resume = good_ack;
        resume["piece"] = Value::Null;
        *transport.0.reply.lock().unwrap() = resume;
        assert_eq!(
            transport.resume(peer, session).await.unwrap().last_acked,
            Some(part)
        );
    }
}

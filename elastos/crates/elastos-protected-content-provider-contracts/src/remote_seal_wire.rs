//! The JSON fields shared by the remote-seal sender and receiver.
//!
//! The endpoint checks the lengths and canonical form of encoded blobs
//! before passing any of these fields to the cryptographic contracts.

use elastos_protected_content_contracts::ClearPartIndexV1;
use serde::{Deserialize, Serialize};

/// Node-local custody command. The caller supplies the pool independently
/// of the signed request and attestation statement.
pub const ATTEST_REMOTE_SEAL_UPLOAD_OP: &str = "attest_remote_seal_upload";

#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteSealAttestationRequestV1 {
    AttestRemoteSealUpload {
        pool_authority: [u8; 32],
        descriptor: Vec<u8>,
        mint_request: Vec<u8>,
        statement: Vec<u8>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSealAttestationReplyV1 {
    pub attestation: Vec<u8>,
}

pub const SIGN_REMOTE_SEAL_COMPLETION_OP: &str = "sign_remote_seal_completion";
pub const MAX_REMOTE_SEAL_COMPLETION_BYTES_V1: usize = 512 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignRemoteSealCompletionRequestV1 {
    SignRemoteSealCompletion {
        pool_authority: [u8; 32],
        descriptor: Vec<u8>,
        mint_request: Vec<u8>,
        statement: Vec<u8>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignRemoteSealCompletionReplyV1 {
    pub completion: Vec<u8>,
}

pub const OPEN_REMOTE_OBJECT_SEAL_OP: &str = "open_remote_object_seal";

/// The authenticated endpoint and issuer come from Runtime's upload admission.
#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum OpenRemoteObjectSealRequestV1 {
    OpenRemoteObjectSeal {
        endpoint: String,
        minter_issuer: [u8; 32],
        sealer_node: [u8; 32],
        descriptor: Vec<u8>,
        mint_request: Vec<u8>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenRemoteObjectSealReplyV1 {
    pub statement: Vec<u8>,
    pub framed_header: Vec<u8>,
}

pub const TRANSFER_REMOTE_OBJECT_SEAL_OP: &str = "transfer_remote_object_seal";

/// Runtime owns the sequence. It reconciles an uncertain call using the same
/// request, and advances only after it saves any returned encrypted frame.
#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransferRemoteObjectSealRequestV1 {
    TransferRemoteObjectSeal {
        endpoint: String,
        session_id: [u8; 16],
        sequence: u32,
        transfer: RemoteObjectSealTransferV1,
    },
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteObjectSealTransferV1 {
    Part {
        part: ClearPartIndexV1,
        piece: u16,
        piece_count: u16,
        part_clear_sha256: [u8; 32],
        sealed: String,
    },
    Resume,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferRemoteObjectSealReplyV1 {
    pub session_id: [u8; 16],
    pub sequence: u32,
    pub last_protected: Option<ClearPartIndexV1>,
    pub framed_chunk: Option<String>,
}

pub const FINALIZE_REMOTE_OBJECT_SEAL_OP: &str = "finalize_remote_object_seal";

#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum FinalizeRemoteObjectSealRequestV1 {
    FinalizeRemoteObjectSeal {
        endpoint: String,
        session_id: [u8; 16],
        sequence: u32,
        ciphertext_sha256: [u8; 32],
        ciphertext_bytes: u64,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeRemoteObjectSealReplyV1 {
    pub session_id: [u8; 16],
    pub sequence: u32,
    pub mint_request_hash: [u8; 32],
    pub content_access_id: [u8; 16],
    pub custody_envelope: Vec<u8>,
}

pub const OPEN_REMOTE_DASH_SEAL_OP: &str = "open_remote_dash_seal";
pub const TRANSFER_REMOTE_DASH_SEAL_OP: &str = "transfer_remote_dash_seal";
pub const FINALIZE_REMOTE_DASH_SEAL_OP: &str = "finalize_remote_dash_seal";

#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum OpenRemoteDashSealRequestV1 {
    OpenRemoteDashSeal {
        endpoint: String,
        minter_issuer: [u8; 32],
        sealer_node: [u8; 32],
        descriptor: Vec<u8>,
        mint_request: Vec<u8>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenRemoteDashSealReplyV1 {
    pub statement: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransferRemoteDashSealRequestV1 {
    TransferRemoteDashSeal {
        endpoint: String,
        session_id: [u8; 16],
        sequence: u32,
        transfer: RemoteObjectSealTransferV1,
    },
}

/// `framed_chunk` contains exactly one protected init or segment when the
/// upload completes a part. Runtime uses the acknowledged part for its path.
pub type TransferRemoteDashSealReplyV1 = TransferRemoteObjectSealReplyV1;

#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum FinalizeRemoteDashSealRequestV1 {
    FinalizeRemoteDashSeal {
        endpoint: String,
        session_id: [u8; 16],
        sequence: u32,
        staged_identity: Vec<u8>,
    },
}

pub type FinalizeRemoteDashSealReplyV1 = FinalizeRemoteObjectSealReplyV1;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSealOpenFieldsV1 {
    pub mint_request: String,
    pub descriptor: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSealSessionFieldsV1 {
    pub seal_session_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSealPartFieldsV1 {
    pub seal_session_id: String,
    pub part: ClearPartIndexV1,
    pub piece: u16,
    pub piece_count: u16,
    pub part_clear_sha256: String,
    pub sealed: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSealAckFieldsV1 {
    pub seal_session_id: String,
    pub piece: Option<u16>,
    pub last_acked: Option<ClearPartIndexV1>,
}

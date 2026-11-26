//! Request framing for a remote share write.

use elastos_protected_content_contracts::{
    ContractError, CustodyNodeProvisioningRecordV1, RemoteShareAdmissionV1,
    SignedRuntimeCustodyProvisioningV1, MAX_REMOTE_SHARE_ADMISSION_BYTES_V1,
};
use serde::{Deserialize, Serialize};

use crate::wire::{
    contract_decode_error, decode_json, encode_json, validate_schema, CanonicalBlob,
    MAX_CUSTODY_NODE_PROVISIONING_RECORD_BYTES_V1,
    MAX_SIGNED_RUNTIME_CUSTODY_PROVISIONING_BYTES_V1,
};

const SCHEMA: &str = "elastos.protected-content.remote-share-provision.request/v1";
pub const PROVISION_REMOTE_SHARE_CHILD_OP: &str = "provision_remote_share";
pub const AUTHORIZE_REMOTE_SEAL_SHARE_OP: &str = "authorize_remote_seal_share";

/// Local custody signing request for the envelope verified by Runtime's
/// private protection path.
#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorizeRemoteSealShareRequestV1 {
    AuthorizeRemoteSealShare {
        pool_authority: [u8; 32],
        sealer_node: [u8; 32],
        descriptor: Vec<u8>,
        mint_request: Vec<u8>,
        key_envelope: Vec<u8>,
        runtime_issuer: [u8; 32],
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeRemoteSealShareReplyV1 {
    pub authorization: Vec<u8>,
}

/// Runtime custody ingress. Existing pool-share requests retain their wire
/// shape. Remote seals carry the complete signed admission separately.
#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteShareDeliveryV1 {
    ProvisionPoolNodeShare {
        remote_seal_request: serde_json::Value,
    },
}

/// Private custody command. Runtime resolves the pool authorized for the
/// selected root independently from the request before dispatch.
#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProvisionRemoteShareCommandV1 {
    ProvisionRemoteShare {
        pool_authority: [u8; 32],
        request: serde_json::Value,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteShareProvisionReplyV1 {
    pub selected_node_public_key: [u8; 32],
    pub record_sha256: [u8; 32],
    pub record_bytes: u32,
    pub provisioning_id: [u8; 32],
    pub already_stored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteShareProvisionWireV1 {
    schema: String,
    record: CanonicalBlob<MAX_CUSTODY_NODE_PROVISIONING_RECORD_BYTES_V1>,
    signed_provisioning: CanonicalBlob<MAX_SIGNED_RUNTIME_CUSTODY_PROVISIONING_BYTES_V1>,
    admission: CanonicalBlob<MAX_REMOTE_SHARE_ADMISSION_BYTES_V1>,
}

/// Shape-checked inputs. The provider separately checks admission against
/// the pool authorized for its loaded root.
pub struct RemoteShareProvisionRequestV1 {
    pub record: CustodyNodeProvisioningRecordV1,
    pub signed_provisioning: SignedRuntimeCustodyProvisioningV1,
    pub admission: RemoteShareAdmissionV1,
}

impl RemoteShareProvisionRequestV1 {
    pub fn to_json_vec(&self) -> Result<Vec<u8>, serde_json::Error> {
        let wire = RemoteShareProvisionWireV1 {
            schema: SCHEMA.to_owned(),
            record: CanonicalBlob::from_contract(&self.record).map_err(contract_decode_error)?,
            signed_provisioning: CanonicalBlob::from_contract(&self.signed_provisioning)
                .map_err(contract_decode_error)?,
            admission: CanonicalBlob::from_contract(&self.admission)
                .map_err(contract_decode_error)?,
        };
        encode_json(&wire)
    }

    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let wire: RemoteShareProvisionWireV1 = decode_json(bytes)?;
        Self::decode(wire).map_err(contract_decode_error)
    }

    fn decode(wire: RemoteShareProvisionWireV1) -> Result<Self, ContractError> {
        validate_schema(&wire.schema, SCHEMA, "remote_share_provision.schema")?;
        Ok(Self {
            record: wire.record.decode()?,
            signed_provisioning: wire.signed_provisioning.decode()?,
            admission: wire.admission.decode()?,
        })
    }
}

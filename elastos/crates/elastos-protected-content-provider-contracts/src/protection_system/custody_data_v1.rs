//! The JSON `Data` v1 codec shared by the Elastos custody systems: the wire
//! payload of a custody `pssh` box, never key material (the box ships inside a
//! public media file). It carries the content access id a consumer presents when
//! it asks for a key, and the custody pool, epoch and committee authorization
//! identities that say which quorum can answer.
//!
//! The codec maps between the wire DTO and [`CustodyProtectionHeader`]; the
//! protection scheme name it writes and the names it accepts are the adapter's
//! choice, passed in.

use elastos_protected_content_contracts::{
    ContentAccessIdV1, ContractError, CustodyCommitteeAuthorizationIdentityV1,
    CustodyEpochIdentityV1, CustodyPoolIdentityV1, Digest32, CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
};
use serde::{Deserialize, Serialize};

use super::header::{CencMediaSuite, CustodyProtectionHeader};
use super::ProtectionSystemId;
use crate::pssh::{build_pssh_v1, parse_pssh_v1};

/// The versioned shape of the JSON carried in the box's `Data` field.
pub const ELASTOS_PQ_PSSH_DATA_SCHEMA_V1: &str = "elastos.protected-content.cenc-pssh-data/v1";

/// A `Data` payload larger than this is refused rather than parsed: the payload is
/// a fixed set of identity fields, so anything near this size is malformed.
pub const MAX_ELASTOS_PQ_PSSH_DATA_BYTES_V1: usize = 4096;

/// Field order here is the serialized order, so the same inputs always produce the
/// same bytes and therefore the same init segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyDataV1 {
    schema: String,
    protection_scheme: String,
    content_encryption: String,
    key_encapsulation: String,
    content_access_id: String,
    custody_pool_sha256: String,
    custody_pool_bytes: u32,
    custody_epoch_sha256: String,
    custody_epoch_bytes: u32,
    custody_committee_authorization_sha256: String,
    custody_committee_authorization_bytes: u32,
}

impl CustodyDataV1 {
    fn from_header(scheme: &str, header: &CustodyProtectionHeader) -> Self {
        Self {
            schema: ELASTOS_PQ_PSSH_DATA_SCHEMA_V1.to_string(),
            protection_scheme: scheme.to_string(),
            content_encryption: header.media_suite().as_str().to_string(),
            key_encapsulation: CUSTODY_X_WING_AES256GCM_SUITE_ID_V1.to_string(),
            content_access_id: hex_lower(header.content_access_id().as_bytes()),
            custody_pool_sha256: hex_lower(header.custody_pool().pool_sha256().as_bytes()),
            custody_pool_bytes: header.custody_pool().pool_bytes(),
            custody_epoch_sha256: hex_lower(header.custody_epoch().epoch_sha256().as_bytes()),
            custody_epoch_bytes: header.custody_epoch().epoch_bytes(),
            custody_committee_authorization_sha256: hex_lower(
                header
                    .custody_committee_authorization()
                    .authorization_sha256()
                    .as_bytes(),
            ),
            custody_committee_authorization_bytes: header
                .custody_committee_authorization()
                .authorization_bytes(),
        }
    }

    fn parsed_content_access_id(&self) -> Result<ContentAccessIdV1, ContractError> {
        let bytes: [u8; 16] = parse_hex_lower::<16>(&self.content_access_id, "content_access_id")?;
        ContentAccessIdV1::new(bytes)
    }

    /// Rejects a payload whose constant fields are not this codec's, whose scheme
    /// name is not one of `accepted_schemes`, or whose variable fields are not
    /// well-formed, and returns what it declares.
    fn into_header(
        self,
        accepted_schemes: &[&str],
    ) -> Result<CustodyProtectionHeader, ContractError> {
        if self.schema != ELASTOS_PQ_PSSH_DATA_SCHEMA_V1 {
            return Err(ContractError::InvalidField("pssh_data_schema"));
        }
        if !accepted_schemes.contains(&self.protection_scheme.as_str()) {
            return Err(ContractError::InvalidField("pssh_protection_scheme"));
        }
        let media_suite = CencMediaSuite::parse(&self.content_encryption)?;
        if self.key_encapsulation != CUSTODY_X_WING_AES256GCM_SUITE_ID_V1 {
            return Err(ContractError::InvalidField("pssh_key_encapsulation"));
        }
        let content_access_id = self.parsed_content_access_id()?;
        let pool = Digest32::new(parse_hex_lower::<32>(
            &self.custody_pool_sha256,
            "pssh_custody_pool_sha256",
        )?);
        let epoch = Digest32::new(parse_hex_lower::<32>(
            &self.custody_epoch_sha256,
            "pssh_custody_epoch_sha256",
        )?);
        let authorization = Digest32::new(parse_hex_lower::<32>(
            &self.custody_committee_authorization_sha256,
            "pssh_custody_committee_authorization_sha256",
        )?);
        // Re-minting each identity applies the same field bounds the canonical
        // custody contracts apply, so a payload can never name an identity the
        // rest of the system would reject.
        Ok(CustodyProtectionHeader::new(
            content_access_id,
            &CustodyPoolIdentityV1::new(pool, self.custody_pool_bytes)?,
            &CustodyEpochIdentityV1::new(epoch, self.custody_epoch_bytes)?,
            &CustodyCommitteeAuthorizationIdentityV1::new(
                authorization,
                self.custody_committee_authorization_bytes,
            )?,
            media_suite,
        ))
    }
}

/// The complete v1 `pssh` box for `header` under `system_id`: the content access
/// id is the single KID and `Data` is the JSON naming `scheme`.
pub(crate) fn encode(
    system_id: ProtectionSystemId,
    scheme: &str,
    header: &CustodyProtectionHeader,
) -> Result<Vec<u8>, ContractError> {
    let data = CustodyDataV1::from_header(scheme, header);
    let bytes =
        serde_json::to_vec(&data).map_err(|_| ContractError::InvalidField("pssh_data_payload"))?;
    if bytes.len() > MAX_ELASTOS_PQ_PSSH_DATA_BYTES_V1 {
        return Err(ContractError::FieldTooLong("pssh_data_payload"));
    }
    data.into_header(&[scheme])?;
    let kid = *header.content_access_id().as_bytes();
    Ok(build_pssh_v1(system_id.as_bytes(), &[kid], &bytes))
}

/// Reads a whole v1 `pssh` box: version 1, one KID equal to the declared content
/// access id, `Data` a well-formed payload naming one of `accepted_schemes`. The
/// caller has already matched the system id.
pub(crate) fn decode(
    pssh_box: &[u8],
    accepted_schemes: &[&str],
) -> Result<CustodyProtectionHeader, ContractError> {
    let parsed = parse_pssh_v1(pssh_box).ok_or(ContractError::InvalidField("pssh_box"))?;
    if parsed.data.len() > MAX_ELASTOS_PQ_PSSH_DATA_BYTES_V1 {
        return Err(ContractError::FieldTooLong("pssh_data_payload"));
    }
    let data = serde_json::from_slice::<CustodyDataV1>(&parsed.data)
        .map_err(|_| ContractError::InvalidField("pssh_data_payload"))?;
    let header = data.into_header(accepted_schemes)?;
    if parsed.kids.as_slice() != [*header.content_access_id().as_bytes()] {
        return Err(ContractError::InvalidField("pssh_kids"));
    }
    Ok(header)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

fn parse_hex_lower<const N: usize>(
    text: &str,
    field: &'static str,
) -> Result<[u8; N], ContractError> {
    if text.len() != N * 2 {
        return Err(ContractError::InvalidField(field));
    }
    let mut out = [0u8; N];
    let raw = text.as_bytes();
    for (index, slot) in out.iter_mut().enumerate() {
        let high = hex_nibble(raw[index * 2], field)?;
        let low = hex_nibble(raw[index * 2 + 1], field)?;
        *slot = (high << 4) | low;
    }
    Ok(out)
}

fn hex_nibble(byte: u8, field: &'static str) -> Result<u8, ContractError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        // Lowercase only: one spelling on the wire means one byte sequence for the
        // same payload, so the init segment stays reproducible.
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ContractError::InvalidField(field)),
    }
}

//! Adapter: Elastos custody pool v1, the system that is written. Its identity is
//! the custody POOL: the KID plus the pool, epoch and committee identities. Its
//! data schema may get new versions while the id stays the same.

use super::custody_data_v1;
use super::{ProtectionRole, ProtectionSystem, ProtectionSystemId};
use crate::pssh::ELASTOS_PQ_PROTECTION_SCHEME_V1;

/// `b01c5dff-46fb-497e-8525-6fb946873253` · PSSH base64 `sBxd/0b7SX6FJW+5RocyUw==`.
pub(crate) const ELASTOS_CUSTODY_POOL: ProtectionSystem = ProtectionSystem {
    id: ProtectionSystemId::from_bytes([
        0xb0, 0x1c, 0x5d, 0xff, 0x46, 0xfb, 0x49, 0x7e, 0x85, 0x25, 0x6f, 0xb9, 0x46, 0x87, 0x32,
        0x53,
    ]),
    scheme: SCHEME,
    listed: true,
    role: ProtectionRole::Custody {
        encode: Some(encode),
        decode,
    },
};

/// The one place this system names its scheme: the MPD value, the data scheme it
/// writes and the only data scheme it reads.
const SCHEME: &str = ELASTOS_PQ_PROTECTION_SCHEME_V1;
const DATA_SCHEME_NAMES: &[&str] = &[SCHEME];

fn encode(
    id: ProtectionSystemId,
    header: &super::CustodyProtectionHeader,
) -> Result<Vec<u8>, elastos_protected_content_contracts::ContractError> {
    custody_data_v1::encode(id, SCHEME, header)
}

fn decode(
    pssh_box: &[u8],
) -> Result<super::CustodyProtectionHeader, elastos_protected_content_contracts::ContractError> {
    custody_data_v1::decode(pssh_box, DATA_SCHEME_NAMES)
}

#[cfg(test)]
mod tests {
    use elastos_protected_content_contracts::{
        ContentAccessIdV1, CustodyCommitteeAuthorizationIdentityV1, CustodyEpochIdentityV1,
        CustodyPoolIdentityV1, Digest32,
    };

    use super::*;
    use crate::protection_system::{CencMediaSuite, CustodyProtectionHeader};
    use crate::pssh::{build_pssh_v1, parse_pssh_v1, ELASTOS_PQ_PROTECTION_SCHEME_V0};

    fn header(media_suite: CencMediaSuite) -> CustodyProtectionHeader {
        CustodyProtectionHeader::new(
            ContentAccessIdV1::new([0x55; 16]).unwrap(),
            &CustodyPoolIdentityV1::new(Digest32::new([0x61; 32]), 512).unwrap(),
            &CustodyEpochIdentityV1::new(Digest32::new([0x62; 32]), 512).unwrap(),
            &CustodyCommitteeAuthorizationIdentityV1::new(Digest32::new([0x63; 32]), 512).unwrap(),
            media_suite,
        )
    }

    #[test]
    fn id_is_the_assigned_uuid() {
        assert_eq!(
            ELASTOS_CUSTODY_POOL.id.to_string(),
            "b01c5dff-46fb-497e-8525-6fb946873253"
        );
        assert_eq!(
            ELASTOS_CUSTODY_POOL.id.as_bytes(),
            &[
                0xb0, 0x1c, 0x5d, 0xff, 0x46, 0xfb, 0x49, 0x7e, 0x85, 0x25, 0x6f, 0xb9, 0x46, 0x87,
                0x32, 0x53
            ]
        );
        assert_eq!(
            ELASTOS_CUSTODY_POOL.scheme,
            "cenc:elastos-pq-hybrid-threshold-v1"
        );
        assert!(ELASTOS_CUSTODY_POOL.can_encode());
    }

    #[test]
    fn decode_of_encode_is_the_header_for_both_media_suites() {
        for suite in [CencMediaSuite::Fmp4V1, CencMediaSuite::DashV2] {
            let value = header(suite);
            let boxed = ELASTOS_CUSTODY_POOL.encode(&value).unwrap();
            assert_eq!(ELASTOS_CUSTODY_POOL.decode(&boxed).unwrap(), value);
        }
    }

    #[test]
    fn the_box_is_v1_with_the_content_access_id_as_its_only_kid() {
        let boxed = ELASTOS_CUSTODY_POOL
            .encode(&header(CencMediaSuite::DashV2))
            .unwrap();
        assert_eq!(boxed[8], 1, "version");
        assert_eq!(&boxed[12..28], ELASTOS_CUSTODY_POOL.id.as_bytes());
        let parsed = parse_pssh_v1(&boxed).unwrap();
        assert_eq!(parsed.kids, vec![[0x55u8; 16]]);
    }

    #[test]
    fn data_is_the_pinned_json_and_carries_no_secret() {
        // Every field is either a constant scheme name or a public identity digest,
        // so the JSON is exactly the declared field set and nothing else.
        let boxed = ELASTOS_CUSTODY_POOL
            .encode(&header(CencMediaSuite::Fmp4V1))
            .unwrap();
        let json = String::from_utf8(parse_pssh_v1(&boxed).unwrap().data).unwrap();
        assert_eq!(
            json,
            format!(
                concat!(
                    r#"{{"schema":"elastos.protected-content.cenc-pssh-data/v1","#,
                    r#""protection_scheme":"{scheme}","#,
                    r#""content_encryption":"cenc-fmp4-aes128ctr/v1","#,
                    r#""key_encapsulation":"elastos-xwing-draft06-hkdf-sha256-aes256gcm/v1","#,
                    r#""content_access_id":"55555555555555555555555555555555","#,
                    r#""custody_pool_sha256":"6161616161616161616161616161616161616161616161616161616161616161","#,
                    r#""custody_pool_bytes":512,"#,
                    r#""custody_epoch_sha256":"6262626262626262626262626262626262626262626262626262626262626262","#,
                    r#""custody_epoch_bytes":512,"#,
                    r#""custody_committee_authorization_sha256":"6363636363636363636363636363636363636363636363636363636363636363","#,
                    r#""custody_committee_authorization_bytes":512}}"#,
                ),
                scheme = ELASTOS_PQ_PROTECTION_SCHEME_V1,
            )
        );
        let again = ELASTOS_CUSTODY_POOL
            .encode(&header(CencMediaSuite::Fmp4V1))
            .unwrap();
        assert_eq!(boxed, again, "the same inputs give the same bytes");
    }

    #[test]
    fn it_reads_only_the_v1_data_scheme() {
        let boxed = ELASTOS_CUSTODY_POOL
            .encode(&header(CencMediaSuite::DashV2))
            .unwrap();
        let parsed = parse_pssh_v1(&boxed).unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&parsed.data).unwrap();
        json["protection_scheme"] = serde_json::json!(ELASTOS_PQ_PROTECTION_SCHEME_V0);
        let v0 = build_pssh_v1(
            ELASTOS_CUSTODY_POOL.id.as_bytes(),
            &parsed.kids,
            &serde_json::to_vec(&json).unwrap(),
        );
        assert!(ELASTOS_CUSTODY_POOL.decode(&v0).is_err());
    }

    #[test]
    fn it_does_not_read_another_systems_box() {
        let boxed = ELASTOS_CUSTODY_POOL
            .encode(&header(CencMediaSuite::DashV2))
            .unwrap();
        let mut other = boxed;
        other[12..28].copy_from_slice(
            crate::protection_system::elastos_legacy_v0::ELASTOS_CUSTODY_LEGACY
                .id
                .as_bytes(),
        );
        assert!(ELASTOS_CUSTODY_POOL.decode(&other).is_err());
    }
}

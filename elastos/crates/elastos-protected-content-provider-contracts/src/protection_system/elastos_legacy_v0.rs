//! Adapter: the earlier Elastos custody system, decode only. Items minted under it
//! stay readable; nothing new is written with it.

use super::custody_data_v1;
use super::{ProtectionRole, ProtectionSystem, ProtectionSystemId};
use crate::pssh::{ELASTOS_PQ_PROTECTION_SCHEME_V0, ELASTOS_PQ_PROTECTION_SCHEME_V1};

/// `b6e254ef-0dc5-47fe-94e7-0e72ed1dc7b0` · PSSH base64 `tuJU7w3FR/6U5w5y7R3HsA==`.
/// Both data scheme spellings exist in the wild under this id.
pub(crate) const ELASTOS_CUSTODY_LEGACY: ProtectionSystem = ProtectionSystem {
    id: ProtectionSystemId::from_bytes([
        0xb6, 0xe2, 0x54, 0xef, 0x0d, 0xc5, 0x47, 0xfe, 0x94, 0xe7, 0x0e, 0x72, 0xed, 0x1d, 0xc7,
        0xb0,
    ]),
    scheme: ELASTOS_PQ_PROTECTION_SCHEME_V0,
    listed: false,
    role: ProtectionRole::Custody {
        encode: None,
        decode,
    },
};

const DATA_SCHEME_NAMES: &[&str] = &[
    ELASTOS_PQ_PROTECTION_SCHEME_V0,
    ELASTOS_PQ_PROTECTION_SCHEME_V1,
];

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
    use crate::protection_system::custody_data_v1;
    use crate::protection_system::{CencMediaSuite, CustodyProtectionHeader};
    use crate::pssh::build_pssh_v1;

    fn header() -> CustodyProtectionHeader {
        CustodyProtectionHeader::new(
            ContentAccessIdV1::new([0x55; 16]).unwrap(),
            &CustodyPoolIdentityV1::new(Digest32::new([0x61; 32]), 512).unwrap(),
            &CustodyEpochIdentityV1::new(Digest32::new([0x62; 32]), 512).unwrap(),
            &CustodyCommitteeAuthorizationIdentityV1::new(Digest32::new([0x63; 32]), 512).unwrap(),
            CencMediaSuite::Fmp4V1,
        )
    }

    #[test]
    fn id_is_the_assigned_uuid_and_the_system_is_decode_only() {
        assert_eq!(
            ELASTOS_CUSTODY_LEGACY.id.to_string(),
            "b6e254ef-0dc5-47fe-94e7-0e72ed1dc7b0"
        );
        assert_eq!(
            ELASTOS_CUSTODY_LEGACY.scheme,
            ELASTOS_PQ_PROTECTION_SCHEME_V0
        );
        assert!(ELASTOS_CUSTODY_LEGACY.is_custody());
        assert!(!ELASTOS_CUSTODY_LEGACY.can_encode());
        assert!(ELASTOS_CUSTODY_LEGACY.encode(&header()).is_err());
    }

    #[test]
    fn it_decodes_both_data_scheme_spellings_found_in_the_wild() {
        // "-v1" is a real runtime mint shape; "-v0" is the rename window's.
        for scheme in [
            ELASTOS_PQ_PROTECTION_SCHEME_V1,
            ELASTOS_PQ_PROTECTION_SCHEME_V0,
        ] {
            let boxed =
                custody_data_v1::encode(ELASTOS_CUSTODY_LEGACY.id, scheme, &header()).unwrap();
            assert_eq!(
                ELASTOS_CUSTODY_LEGACY.decode(&boxed).unwrap(),
                header(),
                "{scheme}"
            );
        }
    }

    #[test]
    fn it_refuses_a_dkms_era_envelope() {
        let envelope = serde_json::json!({
            "protocolVersion": 1,
            "variant": "dkms",
            "data": "AAAA",
        });
        let boxed = build_pssh_v1(
            ELASTOS_CUSTODY_LEGACY.id.as_bytes(),
            &[[0x55; 16]],
            &serde_json::to_vec(&envelope).unwrap(),
        );
        assert!(ELASTOS_CUSTODY_LEGACY.decode(&boxed).is_err());
    }

    #[test]
    fn it_refuses_a_name_that_is_neither_spelling() {
        for scheme in ["cenc:elastos-pq-hybrid-threshold-v2", ""] {
            let boxed =
                custody_data_v1::encode(ELASTOS_CUSTODY_LEGACY.id, scheme, &header()).unwrap();
            assert!(ELASTOS_CUSTODY_LEGACY.decode(&boxed).is_err(), "{scheme}");
        }
    }
}

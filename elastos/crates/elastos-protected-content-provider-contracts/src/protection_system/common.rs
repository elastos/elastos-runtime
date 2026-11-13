//! Adapter: the W3C Common PSSH system. A KID list and no data.

use super::{ProtectionRole, ProtectionSystem, ProtectionSystemId};

/// W3C EME Common PSSH system `1077efec-c0b2-4d02-ace3-3c1e52e2fb4b`. A v2
/// protected init carries one such box listing the KID, so EME clients and
/// standard tools can find the key id without knowing the Elastos scheme.
pub(crate) const COMMON: ProtectionSystem = ProtectionSystem {
    id: ProtectionSystemId::from_bytes([
        0x10, 0x77, 0xef, 0xec, 0xc0, 0xb2, 0x4d, 0x02, 0xac, 0xe3, 0x3c, 0x1e, 0x52, 0xe2, 0xfb,
        0x4b,
    ]),
    scheme: "cenc",
    listed: false,
    role: ProtectionRole::CommonKidList,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pssh::{build_pssh_v1, parse_pssh_v0_or_v1};

    const KID: [u8; 16] = [0x55; 16];

    #[test]
    fn id_is_the_w3c_uuid() {
        assert_eq!(
            COMMON.id.to_string(),
            "1077efec-c0b2-4d02-ace3-3c1e52e2fb4b"
        );
    }

    #[test]
    fn kid_list_round_trips() {
        let boxed = COMMON.encode_kid_list(&KID).unwrap();
        let (version, parsed) = parse_pssh_v0_or_v1(&boxed).unwrap();
        assert_eq!(version, 1);
        assert_eq!(&parsed.system_id, COMMON.id.as_bytes());
        assert_eq!(parsed.kids, vec![KID]);
        assert!(parsed.data.is_empty());
        COMMON.check_kid_list(version, &parsed, &KID).unwrap();
    }

    #[test]
    fn a_v1_box_must_list_the_kid_and_v0_has_no_list() {
        let other = build_pssh_v1(COMMON.id.as_bytes(), &[[0x66; 16]], &[]);
        let (version, parsed) = parse_pssh_v0_or_v1(&other).unwrap();
        assert!(COMMON.check_kid_list(version, &parsed, &KID).is_err());
        let (_, parsed) = parse_pssh_v0_or_v1(&other).unwrap();
        assert!(COMMON.check_kid_list(0, &parsed, &KID).is_ok());
    }

    #[test]
    fn it_does_not_encode_or_decode_custody_data() {
        assert!(!COMMON.is_custody());
        assert!(!COMMON.can_encode());
        let boxed = COMMON.encode_kid_list(&KID).unwrap();
        assert!(COMMON.decode(&boxed).is_err());
        let header = super::super::conformance::sample_header(super::super::CencMediaSuite::DashV2);
        assert!(COMMON.encode(&header).is_err());
    }
}

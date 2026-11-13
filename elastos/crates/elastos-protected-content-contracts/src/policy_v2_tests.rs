//! Plan B S7-lite T7.1: the MINT-V2 policy format (item 5; patches 0006 and
//! 0018): `rights-policy-body/v2` names the minted item; v1 bytes are kept.

use hex::encode;

use crate::test_support::{digest, wallet};
use crate::{
    CanonicalContract, ContentAccessIdV1, ContractError, EncryptedContentIdentityV1,
    EvmContractAddressV1, EvmFunctionSelectorV1, EvmRightsMethodAbiV1, RightsActionV1,
    RightsExpectedItemV1, RightsObservationFinalityV1, RightsPolicyBodyV1, RightsSubjectSourceV1,
    WalletAddress,
};

fn policy() -> RightsPolicyBodyV1 {
    RightsPolicyBodyV1::new(
        EncryptedContentIdentityV1::new(digest(0x10), 2048).unwrap(),
        ContentAccessIdV1::new([0x20; 16]).unwrap(),
        RightsActionV1::Stream,
        RightsSubjectSourceV1::WalletAddress,
        11155111,
        EvmContractAddressV1::new([0x11; 20]).unwrap(),
        EvmFunctionSelectorV1::new([0x12, 0x34, 0x56, 0x78]).unwrap(),
        EvmRightsMethodAbiV1::HasAccessByContentIdAddressBytes16,
        RightsObservationFinalityV1::finalized(),
    )
    .unwrap()
}

fn creator_item(token_id: u8) -> RightsExpectedItemV1 {
    let mut token = [0u8; 32];
    token[31] = token_id;
    RightsExpectedItemV1::new(
        EvmContractAddressV1::new([0x22; 20]).unwrap(),
        token,
        wallet(0x51),
    )
    .unwrap()
}

#[test]
fn expected_item_seals_a_v2_policy_and_leaves_v1_bytes_unchanged() {
    let v1 = policy();
    let v2 = policy().with_expected_item(creator_item(7));
    assert!(v1
        .canonical_bytes()
        .unwrap()
        .starts_with(b"elastos.protected-content.rights-policy-body/v1\0"));
    assert!(v2
        .canonical_bytes()
        .unwrap()
        .starts_with(b"elastos.protected-content.rights-policy-body/v2\0"));
    assert_eq!(v1.expected_item(), None);
    assert_eq!(v2.expected_item(), Some(creator_item(7)));
    assert_ne!(v1.policy_identity().unwrap(), v2.policy_identity().unwrap());
    for body in [&v1, &v2] {
        assert_eq!(
            &RightsPolicyBodyV1::from_canonical_bytes(&body.canonical_bytes().unwrap()).unwrap(),
            body
        );
    }
    // v2 = v1 fields || channel (20) || token id (32) || creator (20).
    let v1_bytes = v1.canonical_bytes().unwrap();
    let v2_bytes = v2.canonical_bytes().unwrap();
    assert_eq!(v2_bytes.len(), v1_bytes.len() + 72);
    assert_eq!(&v2_bytes[v2_bytes.len() - 72..][..20], &[0x22; 20]);
}

#[test]
fn v2_policy_body_golden_is_appended_and_v1_goldens_are_unchanged() {
    // The v1 golden (`policy_identity_matches_exact_policy_bytes`) stays.
    let v1 = policy();
    assert_eq!(v1.canonical_bytes().unwrap().len(), 248);
    assert_eq!(
        encode(v1.policy_identity().unwrap().policy_sha256().as_bytes()),
        "2921fd94863d6f21c378ec930ac6f5f37a4407373411a1139800fcbf6ed300df"
    );
    // Appended (patch 0006 vector): the v2 identity of the same policy.
    let v2 = policy().with_expected_item(creator_item(7));
    assert_eq!(v2.canonical_bytes().unwrap().len(), 320);
    assert_eq!(
        encode(v2.policy_identity().unwrap().policy_sha256().as_bytes()),
        "d23fdb08868a1ab9d78eaa3b93a4c29854e46aa07cdfa4ffec283f9480e280f9"
    );
}

#[test]
fn non_canonical_v2_policy_bytes_are_refused() {
    let v1_bytes = policy().canonical_bytes().unwrap();
    let v2_bytes = policy()
        .with_expected_item(creator_item(7))
        .canonical_bytes()
        .unwrap();
    let item_bytes = &v2_bytes[v2_bytes.len() - 72..];
    let mut v2_without_item = v2_bytes[..v2_bytes.len() - 72].to_vec();
    assert_eq!(
        RightsPolicyBodyV1::from_canonical_bytes(&v2_without_item),
        Err(ContractError::UnexpectedEnd)
    );
    v2_without_item.extend_from_slice(item_bytes);
    assert!(RightsPolicyBodyV1::from_canonical_bytes(&v2_without_item).is_ok());
    let mut v1_with_item = v1_bytes;
    v1_with_item.extend_from_slice(item_bytes);
    assert_eq!(
        RightsPolicyBodyV1::from_canonical_bytes(&v1_with_item),
        Err(ContractError::TrailingBytes)
    );
    // A zero token id inside v2 bytes is refused at decode.
    let mut zero_token = v2_bytes.clone();
    let start = zero_token.len() - 52;
    zero_token[start..start + 32].fill(0);
    assert_eq!(
        RightsPolicyBodyV1::from_canonical_bytes(&zero_token),
        Err(ContractError::InvalidField("expected_item.token_id"))
    );
}

#[test]
fn expected_item_refuses_a_zero_token_id_or_creator() {
    let channel = EvmContractAddressV1::new([0x22; 20]).unwrap();
    assert_eq!(
        RightsExpectedItemV1::new(channel, [0; 32], wallet(0x51)),
        Err(ContractError::InvalidField("expected_item.token_id"))
    );
    assert_eq!(
        RightsExpectedItemV1::new(channel, [1; 32], WalletAddress::new([0; 20])),
        Err(ContractError::InvalidField("expected_item.creator"))
    );
    assert!(RightsExpectedItemV1::new(channel, [1; 32], wallet(0x51)).is_ok());
}

#[test]
fn sealing_names_the_item_once_and_unsealing_restores_the_v1_policy() {
    let v1 = policy();
    let sealed = v1.sealed_for_item(creator_item(7)).unwrap();
    assert_eq!(sealed, policy().with_expected_item(creator_item(7)));
    assert_eq!(sealed.unsealed(), v1);
    assert_eq!(
        sealed.unsealed().canonical_bytes().unwrap(),
        v1.canonical_bytes().unwrap()
    );
    assert_eq!(v1.unsealed(), v1);
    // A sealed policy is never re-pointed, not even to itself.
    for item in [creator_item(8), creator_item(7)] {
        assert_eq!(
            sealed.sealed_for_item(item),
            Err(ContractError::InvalidField("expected_item"))
        );
    }
}

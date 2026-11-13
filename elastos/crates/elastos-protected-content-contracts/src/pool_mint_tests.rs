//! Plan B POOL-MINT: the minting Home's signed share statement.

use hex::encode;
use sha2::{Digest as _, Sha256};

use crate::test_fixtures::{
    key_envelope_for, pool_bundle, pool_did, pool_mint_share, runtime_issuer,
};
use crate::test_support::{digest, xwing_public_key_bytes, NOW};
use crate::{
    CanonicalContract, ContentAccessIdV1, ContractError, EncryptedContentIdentityV1,
    KeyEnvelopeIdentityV1, PoolContractError, PoolMintShareStatementV1, SignedPoolMintShareV1,
};

const MINTER: u8 = 0x44;

fn kid(seed: u8) -> ContentAccessIdV1 {
    ContentAccessIdV1::new([seed; 16]).unwrap()
}

fn envelope(seed: u8) -> KeyEnvelopeIdentityV1 {
    key_envelope_for(
        &pool_bundle(xwing_public_key_bytes, NOW),
        &EncryptedContentIdentityV1::new(digest(seed), 4096).unwrap(),
    )
}

fn share() -> SignedPoolMintShareV1 {
    pool_mint_share(pool_did(), &envelope(0x11), kid(0x41), MINTER)
}

fn sha256_hex(bytes: &[u8]) -> String {
    encode(Sha256::digest(bytes))
}

#[test]
fn pool_mint_share_round_trips_under_its_own_domains() {
    let signed = share();
    let bytes = signed.canonical_bytes().unwrap();
    assert!(bytes.starts_with(b"elastos.protected-content.pool-mint-share/v1\0"));
    assert_eq!(
        SignedPoolMintShareV1::from_canonical_bytes(&bytes).unwrap(),
        signed
    );
    let statement = signed.statement().canonical_bytes().unwrap();
    assert!(statement.starts_with(b"elastos.protected-content.pool-mint-share-statement/v1\0"));
    assert_eq!(
        PoolMintShareStatementV1::from_canonical_bytes(&statement).unwrap(),
        *signed.statement()
    );
    assert_eq!(signed.statement().epoch(), envelope(0x11).custody_epoch());
    assert_eq!(
        signed.verify_signature().unwrap().minter_runtime_issuer(),
        runtime_issuer(MINTER)
    );
}

/// KATs (append-only): the fixture statement, its signed form and the
/// minter's Ed25519 signature.
#[test]
fn pool_mint_share_known_answers() {
    let signed = share();
    let statement = signed.statement().canonical_bytes().unwrap();
    let bytes = signed.canonical_bytes().unwrap();
    assert_eq!(
        (statement.len(), sha256_hex(&statement)),
        (KAT_STATEMENT_LEN, KAT_STATEMENT_SHA256.to_string())
    );
    assert_eq!(
        (bytes.len(), sha256_hex(&bytes)),
        (KAT_SIGNED_LEN, KAT_SIGNED_SHA256.to_string())
    );
    assert_eq!(encode(signed.runtime_signature()), KAT_SIGNATURE);
}

const KAT_STATEMENT_LEN: usize = 715;
const KAT_STATEMENT_SHA256: &str =
    "6570b86f986849e9ad1bcc6a9ccf1b7bf423d65f24ea7d966141cf98a35a1c2d";
const KAT_SIGNED_LEN: usize = 828;
const KAT_SIGNED_SHA256: &str = "2e33a1500f1de081fa5c7938be85184c7385f591af55b56de3ba47c7d667dfbf";
const KAT_SIGNATURE: &str =
    "7713c666207abe37b098af3b8d082f699841789da47803935e81bbe36ed55482fb9ba3884f367caebbbc0a0deb4db25f378404496bfd5c82d73e0fb0ddf6e400";

#[test]
fn guard_pool_mint_share_with_a_tampered_signature_is_refused() {
    let signed = share();
    let mut signature = signed.runtime_signature().to_vec();
    signature[0] ^= 1;
    let tampered = SignedPoolMintShareV1::new(signed.statement().clone(), signature).unwrap();
    assert_eq!(
        tampered.verify_signature(),
        Err(PoolContractError::Signature)
    );
    // Signed by another key than the statement's minter.
    let other = pool_mint_share(pool_did(), &envelope(0x11), kid(0x41), 0x45);
    let forged = SignedPoolMintShareV1::new(
        signed.statement().clone(),
        other.runtime_signature().to_vec(),
    )
    .unwrap();
    assert_eq!(forged.verify_signature(), Err(PoolContractError::Signature));
}

#[test]
fn guard_pool_mint_share_for_another_item_is_refused() {
    let signed = share();
    assert!(signed.verify_for_item(&envelope(0x11), kid(0x41)).is_ok());
    assert!(matches!(
        signed.verify_for_item(&envelope(0x12), kid(0x41)),
        Err(PoolContractError::Contract(ContractError::InvalidField(_)))
    ));
    assert!(matches!(
        signed.verify_for_item(&envelope(0x11), kid(0x42)),
        Err(PoolContractError::Contract(ContractError::InvalidField(_)))
    ));
}

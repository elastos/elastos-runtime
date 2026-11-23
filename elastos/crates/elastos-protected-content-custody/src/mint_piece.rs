//! Upload pieces encrypted to the remote protect provider's session key.

use hpke::rand_core::RngCore as _;
use rand09::SeedableRng as _;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use elastos_protected_content_contracts::{
    CanonicalContract, MintPieceAadV1, RecipientPublicKeyBytesV1, SEAL_PIECE_MAX_CLEAR_BYTES,
    SEAL_PIECE_OVERHEAD_BYTES,
};

use crate::pq_hybrid::{
    open_bytes_with_domain, seal_bytes_with_domain, session_public_bytes_from_secret_bytes,
    session_public_from_bytes, session_secret_from_bytes, PQ_HYBRID_SEALED_BYTES_OVERHEAD,
};
use crate::CustodyError;

const MINT_PIECE_HKDF_DOMAIN_V1: &[u8] = b"elastos.protected-content.mint-piece/v1";
const _: () = assert!(SEAL_PIECE_OVERHEAD_BYTES == PQ_HYBRID_SEALED_BYTES_OVERHEAD);
pub const MAX_SEALED_MINT_PIECE_BYTES: usize =
    SEAL_PIECE_MAX_CLEAR_BYTES + PQ_HYBRID_SEALED_BYTES_OVERHEAD;

/// The remote protect provider keeps this non-cloneable key in memory.
pub struct SealSessionSecretKeyV1(Zeroizing<[u8; 32]>);

impl SealSessionSecretKeyV1 {
    pub fn generate() -> Result<Self, CustodyError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        rand09::rngs::StdRng::try_from_os_rng()
            .map_err(|_| CustodyError::RandomnessUnavailable)?
            .fill_bytes(&mut *seed);
        if seed.ct_eq(&[0_u8; 32]).into() {
            return Err(CustodyError::RandomnessUnavailable);
        }
        Ok(Self(seed))
    }

    pub fn public_key(&self) -> Result<RecipientPublicKeyBytesV1, CustodyError> {
        Ok(RecipientPublicKeyBytesV1::new(
            session_public_bytes_from_secret_bytes(*self.0),
        )?)
    }
}

impl std::fmt::Debug for SealSessionSecretKeyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SealSessionSecretKeyV1([redacted])")
    }
}

pub fn seal_mint_piece_v1(
    public_key: &RecipientPublicKeyBytesV1,
    aad: &MintPieceAadV1,
    clear: &[u8],
) -> Result<Vec<u8>, CustodyError> {
    if !(1..=SEAL_PIECE_MAX_CLEAR_BYTES).contains(&clear.len()) {
        return Err(CustodyError::BindingMismatch("mint_piece_length"));
    }
    let aad = aad.canonical_bytes()?;
    let public = session_public_from_bytes(public_key.as_bytes())?;
    let mut rng =
        rand09::rngs::StdRng::try_from_os_rng().map_err(|_| CustodyError::RandomnessUnavailable)?;
    Ok(seal_bytes_with_domain(
        &public,
        MINT_PIECE_HKDF_DOMAIN_V1,
        clear,
        &aad,
        &mut rng,
    )?)
}

pub fn open_mint_piece_v1(
    secret: &SealSessionSecretKeyV1,
    aad: &MintPieceAadV1,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
    if !(PQ_HYBRID_SEALED_BYTES_OVERHEAD + 1..=MAX_SEALED_MINT_PIECE_BYTES).contains(&sealed.len())
    {
        return Err(CustodyError::BindingMismatch("mint_piece_length"));
    }
    let aad = aad.canonical_bytes()?;
    let secret = session_secret_from_bytes(*secret.0);
    Ok(open_bytes_with_domain(
        &secret,
        MINT_PIECE_HKDF_DOMAIN_V1,
        sealed,
        &aad,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use elastos_protected_content_contracts::{
        ClearPartIndexV1, Digest32, ViewerPartAadV1, ViewerPartIndexV1,
    };

    #[test]
    fn remote_piece_authenticates_request_position_count_and_domain() {
        let secret = SealSessionSecretKeyV1(Zeroizing::new([0x29; 32]));
        let public = secret.public_key().unwrap();
        let aad = MintPieceAadV1 {
            mint_request_hash: Digest32::new([1; 32]),
            part: ClearPartIndexV1::DashSegment {
                rendition: 1,
                index: 0,
            },
            piece: 0,
            piece_count: 2,
        };
        assert_eq!(
            MintPieceAadV1::from_canonical_bytes(&aad.canonical_bytes().unwrap()).unwrap(),
            aad
        );
        let clear = vec![0x91; SEAL_PIECE_MAX_CLEAR_BYTES];
        let sealed = seal_mint_piece_v1(&public, &aad, &clear).unwrap();
        assert_eq!(sealed.len(), MAX_SEALED_MINT_PIECE_BYTES);
        assert_eq!(
            open_mint_piece_v1(&secret, &aad, &sealed)
                .unwrap()
                .as_slice(),
            clear
        );
        for different in [
            MintPieceAadV1 {
                mint_request_hash: Digest32::new([2; 32]),
                ..aad
            },
            MintPieceAadV1 {
                part: ClearPartIndexV1::DashSegment {
                    rendition: 2,
                    index: 0,
                },
                ..aad
            },
            MintPieceAadV1 { piece: 1, ..aad },
            MintPieceAadV1 {
                piece_count: 1,
                ..aad
            },
        ] {
            assert!(open_mint_piece_v1(&secret, &different, &sealed).is_err());
        }
        let other_key = SealSessionSecretKeyV1(Zeroizing::new([0x30; 32]));
        assert!(open_mint_piece_v1(&other_key, &aad, &sealed).is_err());
        let viewing_key = crate::DeliverySecretKeyV1::from_test_bytes([0x29; 32]);
        let viewing_aad = ViewerPartAadV1 {
            session_id: [1; 16],
            operation_hash: aad.mint_request_hash,
            part: ViewerPartIndexV1::DashSegment {
                rendition: 0,
                index: 0,
            },
        };
        assert!(crate::open_viewer_part_v1(&viewing_key, &viewing_aad, &sealed).is_err());
        let mut overlong = sealed.clone();
        overlong.push(0);
        assert!(matches!(
            open_mint_piece_v1(&secret, &aad, &overlong),
            Err(CustodyError::BindingMismatch("mint_piece_length"))
        ));
        assert!(seal_mint_piece_v1(&public, &aad, &[]).is_err());
    }
}

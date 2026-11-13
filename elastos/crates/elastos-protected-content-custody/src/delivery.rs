//! Viewer parts sealed to the buyer's delivery key (Plan B T1.4, L5).
//!
//! A pool server seals every viewer part it serves to the delivery public key
//! the wallet signed (`RightsRequestV2::delivery_key`). The seal is the
//! existing `pq_hybrid` suite: X-Wing draft06, HKDF-SHA256 and AES-256-GCM,
//! not RFC 9180 HPKE. HKDF info is `elastos.protected-content.viewer-part/v1`
//! ‖ suite ‖ canonical `ViewerPartAadV1`, and the AEAD AAD is the same
//! canonical bytes. Each part has its own encapsulation, so there is no nonce
//! state, and a part opens only under its own session, operation and index.

use hpke::rand_core::{CryptoRng as HpkeCryptoRng, RngCore as HpkeRngCore};
use rand09::SeedableRng as _;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use elastos_protected_content_contracts::{
    CanonicalContract, DeliveryPublicKeyBytesV1, ViewerPartAadV1,
};
use elastos_protected_content_provider_contracts::MAX_VIEWER_MEDIA_PART_BYTES_V1;

use crate::pq_hybrid::{
    open_bytes_with_domain, seal_bytes_with_domain, session_public_bytes_from_secret_bytes,
    session_public_from_bytes, session_secret_from_bytes,
};
use crate::CustodyError;

const VIEWER_PART_HKDF_DOMAIN_V1: &[u8] = b"elastos.protected-content.viewer-part/v1";

/// The buyer Runtime's delivery secret. It stays in that Runtime's memory, is
/// zeroized on drop, cannot be cloned, and its `Debug` is redacted.
pub struct DeliverySecretKeyV1(Zeroizing<[u8; 32]>);

impl DeliverySecretKeyV1 {
    pub fn generate() -> Result<Self, CustodyError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand09::rngs::StdRng::try_from_os_rng()
            .map_err(|_| CustodyError::RandomnessUnavailable)?
            .fill_bytes(&mut *bytes);
        Self::from_guarded_bytes(bytes)
    }

    pub fn from_guarded_bytes(bytes: Zeroizing<[u8; 32]>) -> Result<Self, CustodyError> {
        if bytes.ct_eq(&[0u8; 32]).into() {
            return Err(CustodyError::BindingMismatch("delivery_secret"));
        }
        let value = Self(bytes);
        value.public_key()?;
        Ok(value)
    }

    pub fn public_key(&self) -> Result<DeliveryPublicKeyBytesV1, CustodyError> {
        Ok(DeliveryPublicKeyBytesV1::new(
            session_public_bytes_from_secret_bytes(*self.0),
        )?)
    }

    #[cfg(test)]
    pub(crate) fn from_test_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl std::fmt::Debug for DeliverySecretKeyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeliverySecretKeyV1([redacted])")
    }
}

/// Seals one clear viewer part (at most `MAX_VIEWER_MEDIA_PART_BYTES_V1`).
pub fn seal_viewer_part_v1(
    delivery_public_key: &DeliveryPublicKeyBytesV1,
    aad: &ViewerPartAadV1,
    clear_part: &[u8],
) -> Result<Vec<u8>, CustodyError> {
    let mut rng =
        rand09::rngs::StdRng::try_from_os_rng().map_err(|_| CustodyError::RandomnessUnavailable)?;
    seal_viewer_part_v1_with_rng(delivery_public_key, aad, clear_part, &mut rng)
}

pub(crate) fn seal_viewer_part_v1_with_rng<R: HpkeCryptoRng + HpkeRngCore>(
    delivery_public_key: &DeliveryPublicKeyBytesV1,
    aad: &ViewerPartAadV1,
    clear_part: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, CustodyError> {
    if clear_part.len() > MAX_VIEWER_MEDIA_PART_BYTES_V1 {
        return Err(CustodyError::BindingMismatch("viewer_part_bytes"));
    }
    let public = session_public_from_bytes(delivery_public_key.as_bytes())
        .map_err(|_| CustodyError::BindingMismatch("delivery_public_key"))?;
    let aad_bytes = aad.canonical_bytes()?;
    Ok(seal_bytes_with_domain(
        &public,
        VIEWER_PART_HKDF_DOMAIN_V1,
        clear_part,
        &aad_bytes,
        rng,
    )?)
}

/// Opens one sealed viewer part with the delivery secret and the exact AAD
/// (session, operation hash and part) it was sealed under.
pub fn open_viewer_part_v1(
    delivery_secret: &DeliverySecretKeyV1,
    aad: &ViewerPartAadV1,
    sealed_part: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
    let aad_bytes = aad.canonical_bytes()?;
    let secret = session_secret_from_bytes(*delivery_secret.0);
    let opened =
        open_bytes_with_domain(&secret, VIEWER_PART_HKDF_DOMAIN_V1, sealed_part, &aad_bytes)?;
    if opened.len() > MAX_VIEWER_MEDIA_PART_BYTES_V1 {
        return Err(CustodyError::BindingMismatch("viewer_part_bytes"));
    }
    Ok(opened)
}

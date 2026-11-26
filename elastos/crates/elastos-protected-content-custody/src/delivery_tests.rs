//! Plan B T1.4 (L5): viewer parts sealed to the buyer's delivery key with the
//! existing X-Wing suite under their own HKDF domain.

use rand09::{rngs::StdRng, SeedableRng as _};

use elastos_protected_content_contracts::{
    CanonicalContract, Digest32, ViewerPartAadV1, ViewerPartIndexV1,
};
use elastos_protected_content_provider_contracts::MAX_VIEWER_MEDIA_PART_BYTES_V1;

use crate::delivery::{open_viewer_part_v1, seal_viewer_part_v1_with_rng, DeliverySecretKeyV1};

fn aad(part: ViewerPartIndexV1) -> ViewerPartAadV1 {
    ViewerPartAadV1 {
        session_id: [0x5e; 16],
        operation_hash: Digest32::new([0x0b; 32]),
        part,
    }
}

fn delivery_secret(seed: u8) -> DeliverySecretKeyV1 {
    DeliverySecretKeyV1::from_test_bytes([seed; 32])
}

#[test]
fn viewer_part_round_trips() {
    let secret = delivery_secret(0x71);
    let public = secret.public_key().unwrap();
    for part in [
        ViewerPartIndexV1::MediaV1Init,
        ViewerPartIndexV1::MediaV1Segment(3),
        ViewerPartIndexV1::DashInit { rendition: 1 },
        ViewerPartIndexV1::DashSegment {
            rendition: 0,
            index: 7,
        },
        ViewerPartIndexV1::ObjectChunk(2),
    ] {
        let clear = vec![0x42; 1500];
        let sealed = seal_viewer_part_v1_with_rng(
            &public,
            &aad(part),
            &clear,
            &mut StdRng::from_seed([0x01; 32]),
        )
        .unwrap();
        assert_ne!(&sealed[sealed.len() - clear.len()..], clear.as_slice());
        let opened = open_viewer_part_v1(&secret, &aad(part), &sealed).unwrap();
        assert_eq!(opened.as_slice(), clear.as_slice());
    }
    // An empty part is a valid part.
    let sealed = seal_viewer_part_v1_with_rng(
        &public,
        &aad(ViewerPartIndexV1::MediaV1Init),
        &[],
        &mut StdRng::from_seed([0x02; 32]),
    )
    .unwrap();
    assert!(
        open_viewer_part_v1(&secret, &aad(ViewerPartIndexV1::MediaV1Init), &sealed)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn guard_viewer_part_with_other_aad_fails() {
    let secret = delivery_secret(0x71);
    let public = secret.public_key().unwrap();
    let sealed = seal_viewer_part_v1_with_rng(
        &public,
        &aad(ViewerPartIndexV1::MediaV1Segment(3)),
        b"segment three",
        &mut StdRng::from_seed([0x03; 32]),
    )
    .unwrap();
    for other in [
        aad(ViewerPartIndexV1::MediaV1Segment(4)),
        aad(ViewerPartIndexV1::DashSegment {
            rendition: 0,
            index: 3,
        }),
        ViewerPartAadV1 {
            session_id: [0x5f; 16],
            ..aad(ViewerPartIndexV1::MediaV1Segment(3))
        },
        ViewerPartAadV1 {
            operation_hash: Digest32::new([0x0c; 32]),
            ..aad(ViewerPartIndexV1::MediaV1Segment(3))
        },
    ] {
        assert!(open_viewer_part_v1(&secret, &other, &sealed).is_err());
    }
}

#[test]
fn guard_viewer_part_with_other_delivery_key_fails() {
    let public = delivery_secret(0x71).public_key().unwrap();
    let sealed = seal_viewer_part_v1_with_rng(
        &public,
        &aad(ViewerPartIndexV1::ObjectChunk(0)),
        b"chunk",
        &mut StdRng::from_seed([0x04; 32]),
    )
    .unwrap();
    assert!(open_viewer_part_v1(
        &delivery_secret(0x72),
        &aad(ViewerPartIndexV1::ObjectChunk(0)),
        &sealed
    )
    .is_err());
    // A truncated or extended seal is refused too.
    let secret = delivery_secret(0x71);
    assert!(open_viewer_part_v1(
        &secret,
        &aad(ViewerPartIndexV1::ObjectChunk(0)),
        &sealed[..sealed.len() - 1]
    )
    .is_err());
    let mut extended = sealed.clone();
    extended.push(0);
    assert!(
        open_viewer_part_v1(&secret, &aad(ViewerPartIndexV1::ObjectChunk(0)), &extended).is_err()
    );
}

#[test]
fn guard_sealed_share_aad_does_not_open_as_viewer_part() {
    // A share sealed with the share suite's HKDF domain over the very same
    // AAD bytes is not a viewer part.
    let secret = delivery_secret(0x71);
    let public = secret.public_key().unwrap();
    let part_aad = aad(ViewerPartIndexV1::MediaV1Init);
    let share = crate::share_wrap::seal_share(
        public.as_bytes(),
        b"",
        &part_aad.canonical_bytes().unwrap(),
        &[0x11; 32],
        &mut StdRng::from_seed([0x05; 32]),
    )
    .unwrap();
    assert!(open_viewer_part_v1(&secret, &part_aad, share.envelope()).is_err());
}

#[test]
fn guard_viewer_part_above_the_cap_is_refused() {
    let public = delivery_secret(0x71).public_key().unwrap();
    let too_large = vec![0u8; MAX_VIEWER_MEDIA_PART_BYTES_V1 + 1];
    assert!(seal_viewer_part_v1_with_rng(
        &public,
        &aad(ViewerPartIndexV1::MediaV1Segment(0)),
        &too_large,
        &mut StdRng::from_seed([0x06; 32]),
    )
    .is_err());
    let at_cap = vec![0u8; MAX_VIEWER_MEDIA_PART_BYTES_V1];
    seal_viewer_part_v1_with_rng(
        &public,
        &aad(ViewerPartIndexV1::MediaV1Segment(0)),
        &at_cap,
        &mut StdRng::from_seed([0x07; 32]),
    )
    .unwrap();
}

#[test]
fn delivery_secret_debug_is_redacted() {
    let secret = delivery_secret(0x71);
    let debug = format!("{secret:?}");
    assert_eq!(debug, "DeliverySecretKeyV1([redacted])");
    assert!(!debug.contains("71"));
    // A generated key derives a valid public key and a distinct identity.
    let generated = DeliverySecretKeyV1::generate().unwrap();
    assert_ne!(
        generated.public_key().unwrap().identity(),
        secret.public_key().unwrap().identity()
    );
}

// ---------------------------------------------------------------------------
// Known-answer vector for the viewer-part seal (append-only; audit M6,
// 2026-11-12): delivery secret `0x71`×32, AAD `MediaV1Init` with session
// `0x5e`×16 and operation hash `0x0b`×32, clear part `0x42`×32, and the
// seal randomness from `StdRng::from_seed([0x01; 32])`.
// ---------------------------------------------------------------------------

fn kat_sealed_part() -> (Vec<u8>, Vec<u8>) {
    let public = delivery_secret(0x71).public_key().unwrap();
    let sealed = seal_viewer_part_v1_with_rng(
        &public,
        &aad(ViewerPartIndexV1::MediaV1Init),
        &[0x42; 32],
        &mut StdRng::from_seed([0x01; 32]),
    )
    .unwrap();
    (public.as_bytes().to_vec(), sealed)
}

#[test]
#[ignore = "prints the M6 seal vector; run with --ignored --nocapture"]
fn m6_seal_vector_dump() {
    let (public, sealed) = kat_sealed_part();
    println!("DELIVERY-PUBLIC {}", hex::encode(&public));
    println!("SEALED {}", hex::encode(&sealed));
}

/// M6: the delivery public key (1,216 bytes) and the sealed part (1,180
/// bytes). Values reproduced on two runs and with an external `shasum`.
#[test]
fn viewer_part_seal_vector() {
    use sha2::{Digest as _, Sha256};
    let (public, sealed) = kat_sealed_part();
    assert_eq!(public.len(), 1216);
    assert_eq!(
        hex::encode(Sha256::digest(&public)),
        "210b99b973610f51016d17018555ec91574021063b1e002ae914d04786d88c80"
    );
    assert_eq!(sealed.len(), 1180);
    assert_eq!(
        hex::encode(Sha256::digest(&sealed)),
        "4cdbfb884ace6233049dc3eca58d9b41cabdeacacefb088c7d52b12ff7232401"
    );
    let opened = open_viewer_part_v1(
        &delivery_secret(0x71),
        &aad(ViewerPartIndexV1::MediaV1Init),
        &sealed,
    )
    .unwrap();
    assert_eq!(opened.as_slice(), &[0x42; 32]);
}

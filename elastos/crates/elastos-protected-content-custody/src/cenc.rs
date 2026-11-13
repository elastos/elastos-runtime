//! AES-128-CTR CENC (ISO/IEC 23001-7) primitive mined from PR #15 `cenc-core`.
//!
//! Container-agnostic. This is not a second key-wrap path. Callers must only
//! invoke it after a PQ-hybrid CEK exists inside the decrypt-session boundary.

use aes::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest as _, Sha256};

use crate::{CustodyError, CONTENT_KEY_BYTES};

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

const CENC_AES128_KEY_LABEL: &[u8] = b"elastos.protected-content.cenc-aes128-key/v1";

pub(crate) fn pad_iv(iv: &[u8]) -> Result<[u8; 16], CustodyError> {
    let mut out = [0u8; 16];
    match iv.len() {
        8 => out[..8].copy_from_slice(iv),
        16 => out.copy_from_slice(iv),
        _ => return Err(CustodyError::InvalidPayload("cenc_iv")),
    }
    Ok(out)
}

pub(crate) fn ctr_xor(buf: &mut [u8], cek: &[u8; 16], iv16: &[u8; 16]) {
    let mut cipher = Aes128Ctr::new(cek.into(), iv16.into());
    cipher.apply_keystream(buf);
}

pub(crate) fn ctr_xor_subsamples(
    buf: &mut [u8],
    cek: &[u8; 16],
    iv16: &[u8; 16],
    subs: &[(u32, u32)],
) -> Result<(), CustodyError> {
    let mut cipher = Aes128Ctr::new(cek.into(), iv16.into());
    let mut pos = 0usize;
    for &(clear, encrypted) in subs {
        pos = pos
            .checked_add(clear as usize)
            .ok_or(CustodyError::InvalidPayload("cenc_subsample"))?;
        let end = pos
            .checked_add(encrypted as usize)
            .ok_or(CustodyError::InvalidPayload("cenc_subsample"))?;
        if end > buf.len() {
            return Err(CustodyError::InvalidPayload("cenc_subsample"));
        }
        cipher.apply_keystream(&mut buf[pos..end]);
        pos = end;
    }
    Ok(())
}

/// Bento4 `AP4_CENC_NAL_UNIT_ENCRYPTION_MIN_SIZE`: shorter NAL units stay clear.
const AVC_NAL_ENCRYPTION_MIN_BYTES: usize = 112;
/// Clear lead of an encrypted NAL unit before 16-byte alignment (min size − one block).
const AVC_NAL_CLEAR_LEAD_BYTES: usize = AVC_NAL_ENCRYPTION_MIN_BYTES - 16;
/// A sample's `saiz` entry (IV + 2-byte count + 6 per subsample) must fit in
/// one byte: 40 subsamples with an 8-byte IV, 39 with a 16-byte IV.
const fn max_avc_subsamples_per_sample(iv_size: usize) -> usize {
    (u8::MAX as usize - iv_size - 2) / 6
}

/// AVC NAL subsample map, Bento4 `AP4_CencAdvancedSubSampleMapper` semantics
/// for `cenc`: VCL NAL units (types 1..=5) of at least 112 bytes keep their
/// length, header and 16-byte-alignment remainder clear and encrypt the rest;
/// every other NAL unit stays clear. A clear-only entry folds into the next one,
/// and clear runs over `u16::MAX` are split.
///
/// Stricter than Bento4, fail closed: the NAL units must tile the sample exactly
/// (Bento4 ignores trailing bytes), and zero-length NAL units and empty samples
/// are refused, all as `cenc_subsample_map`. A map that would not fit one
/// `saiz` entry for `iv_size` (8 or 16) is refused as
/// `cenc_too_many_subsamples`: the source has too many slices per frame.
pub(crate) fn avc_subsample_map(
    sample: &[u8],
    nal_length_size: u8,
    iv_size: u8,
) -> Result<Vec<(u16, u32)>, CustodyError> {
    const ERR: CustodyError = CustodyError::InvalidPayload("cenc_subsample_map");
    let length_size = match nal_length_size {
        1 | 2 | 4 => usize::from(nal_length_size),
        _ => return Err(ERR),
    };
    let max_subsamples = match iv_size {
        8 | 16 => max_avc_subsamples_per_sample(usize::from(iv_size)),
        _ => return Err(CustodyError::InvalidPayload("cenc_iv")),
    };
    if sample.is_empty() {
        return Err(ERR);
    }
    let mut map = Vec::new();
    let mut rest = sample;
    while !rest.is_empty() {
        let (length, body) = rest.split_at_checked(length_size).ok_or(ERR)?;
        let nal_len = length
            .iter()
            .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
        let (nal, tail) = body.split_at_checked(nal_len).ok_or(ERR)?;
        let nal_type = nal.first().ok_or(ERR)? & 0x1F;
        let size = length_size + nal_len;
        let (clear, encrypted) =
            if size < AVC_NAL_ENCRYPTION_MIN_BYTES || !(1..=5).contains(&nal_type) {
                (size, 0)
            } else {
                let encrypted = (size - AVC_NAL_CLEAR_LEAD_BYTES) & !0xF;
                (size - encrypted, encrypted)
            };
        append_subsample(&mut map, clear, encrypted, max_subsamples)?;
        rest = tail;
    }
    Ok(map)
}

fn append_subsample(
    map: &mut Vec<(u16, u32)>,
    mut clear: usize,
    encrypted: usize,
    max_subsamples: usize,
) -> Result<(), CustodyError> {
    const ERR: CustodyError = CustodyError::InvalidPayload("cenc_subsample_map");
    if let Some(&(last_clear, 0)) = map.last() {
        clear += usize::from(last_clear);
        map.pop();
    }
    while clear > usize::from(u16::MAX) {
        map.push((u16::MAX, 0));
        clear -= usize::from(u16::MAX);
    }
    map.push((
        u16::try_from(clear).map_err(|_| ERR)?,
        u32::try_from(encrypted).map_err(|_| ERR)?,
    ));
    if map.len() > max_subsamples {
        return Err(CustodyError::InvalidPayload("cenc_too_many_subsamples"));
    }
    Ok(())
}

pub(crate) fn derive_cenc_aes128_key(cek: &[u8; CONTENT_KEY_BYTES]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(CENC_AES128_KEY_LABEL);
    hasher.update(cek);
    let digest = hasher.finalize();
    digest[..16].try_into().expect("SHA-256 is 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_iv_accepts_8_or_16_and_rejects_other_sizes() {
        let iv16 = pad_iv(&[0xAA; 8]).unwrap();
        assert_eq!(&iv16[..8], &[0xAA; 8]);
        assert_eq!(&iv16[8..], &[0u8; 8]);
        assert_eq!(pad_iv(&[1u8; 16]).unwrap(), [1u8; 16]);
        assert!(pad_iv(&[0u8; 12]).is_err());
    }

    #[test]
    fn ctr_xor_round_trips() {
        let key = [0x01u8; 16];
        let iv = pad_iv(&[0x07u8; 8]).unwrap();
        let plaintext = b"Hello CENC decryption test data!".to_vec();
        let mut buf = plaintext.clone();
        ctr_xor(&mut buf, &key, &iv);
        assert_ne!(buf, plaintext);
        ctr_xor(&mut buf, &key, &iv);
        assert_eq!(buf, plaintext);
    }

    /// Builds an AVC sample from `(nal_size_with_length_prefix, nal_type)`.
    fn avc_sample(length_size: usize, nals: &[(usize, u8)]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(size, nal_type) in nals {
            let nal_len = (size - length_size) as u32;
            out.extend_from_slice(&nal_len.to_be_bytes()[4 - length_size..]);
            out.push(nal_type);
            out.resize(out.len() + size - length_size - 1, 0xAB);
        }
        out
    }

    fn map(length_size: usize, nals: &[(usize, u8)]) -> Vec<(u16, u32)> {
        avc_subsample_map(&avc_sample(length_size, nals), length_size as u8, 8).unwrap()
    }

    #[test]
    fn avc_subsample_map_matches_bento4_same_stream_vectors() {
        // NAL sizes/types of the clear `ref/out` segment 1 and the `senc` entries
        // Bento4 wrote for the same samples (`bento/same-stream` seg-1).
        assert_eq!(map(4, &[(689, 6), (21784, 5)]), [(793, 21680)]);
        assert_eq!(map(4, &[(11102, 1)]), [(110, 10992)]);
        assert_eq!(map(4, &[(14512, 1)]), [(96, 14416)]);
    }

    #[test]
    fn avc_subsample_map_keeps_short_nals_clear() {
        assert_eq!(map(4, &[(111, 1)]), [(111, 0)]);
        assert_eq!(map(4, &[(112, 1)]), [(96, 16)]);
        assert_eq!(map(4, &[(127, 1)]), [(111, 16)]);
        assert_eq!(map(4, &[(128, 1)]), [(96, 32)]);
    }

    #[test]
    fn avc_subsample_map_keeps_non_vcl_nals_clear() {
        for nal_type in [0u8, 6, 7, 8, 9, 12, 31] {
            assert_eq!(map(4, &[(500, nal_type)]), [(500, 0)], "type {nal_type}");
        }
        for nal_type in 1u8..=5 {
            assert_eq!(map(4, &[(500, nal_type)]), [(100, 400)], "type {nal_type}");
        }
        // Only the low five bits are the type: 0x65 is an IDR slice and 0x41 a
        // reference non-IDR slice; 17..=21 have bit 4 set and are not slices.
        assert_eq!(map(4, &[(500, 0x65)]), [(100, 400)]);
        assert_eq!(map(4, &[(500, 0x41)]), [(100, 400)]);
        for nal_type in 17u8..=21 {
            assert_eq!(map(4, &[(500, nal_type)]), [(500, 0)], "type {nal_type}");
        }
    }

    #[test]
    fn avc_subsample_map_folds_clear_runs_into_the_next_entry() {
        assert_eq!(map(4, &[(20, 7), (8, 8), (200, 5)]), [(132, 96)]);
        assert_eq!(map(4, &[(200, 1), (50, 6)]), [(104, 96), (50, 0)]);
        assert_eq!(
            map(4, &[(200, 1), (50, 6), (200, 1)]),
            [(104, 96), (154, 96)]
        );
    }

    #[test]
    fn avc_subsample_map_splits_clear_runs_over_u16() {
        assert_eq!(map(4, &[(70_000, 6)]), [(0xFFFF, 0), (4465, 0)]);
        assert_eq!(map(4, &[(70_000, 6), (200, 1)]), [(0xFFFF, 0), (4569, 96)]);
        assert_eq!(
            map(4, &[(0xFFFF, 6), (0xFFFF, 6)]),
            [(0xFFFF, 0), (0xFFFF, 0)]
        );
    }

    #[test]
    fn avc_subsample_map_accepts_length_sizes_1_2_4_only() {
        for length_size in [1usize, 2, 4] {
            assert_eq!(map(length_size, &[(200, 1)]), [(104, 96)]);
        }
        let sample = avc_sample(4, &[(200, 1)]);
        for length_size in [0u8, 3, 5, 8] {
            assert!(avc_subsample_map(&sample, length_size, 8).is_err());
        }
    }

    #[test]
    fn avc_subsample_map_refuses_samples_the_nals_do_not_tile() {
        let mut trailing = avc_sample(4, &[(200, 1)]);
        trailing.extend_from_slice(&[0, 0]);
        assert!(avc_subsample_map(&trailing, 4, 8).is_err());

        let mut overrun = avc_sample(4, &[(200, 1)]);
        overrun.truncate(199);
        assert!(avc_subsample_map(&overrun, 4, 8).is_err());

        let mut huge_length = avc_sample(4, &[(200, 1)]);
        huge_length[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(avc_subsample_map(&huge_length, 4, 8).is_err());

        let mut zero_length = avc_sample(4, &[(200, 1)]);
        zero_length.extend_from_slice(&[0, 0, 0, 0]);
        assert!(avc_subsample_map(&zero_length, 4, 8).is_err());

        assert!(avc_subsample_map(&[], 4, 8).is_err());
        assert!(avc_subsample_map(&[0, 0], 4, 8).is_err());
        for malformed in [trailing, overrun, huge_length, zero_length] {
            assert!(matches!(
                avc_subsample_map(&malformed, 4, 8),
                Err(CustodyError::InvalidPayload("cenc_subsample_map"))
            ));
        }
    }

    #[test]
    fn avc_subsample_map_keeps_each_saiz_entry_within_255_bytes() {
        // IV + 2-byte count + 6 bytes per entry ≤ 255: at most 40 entries with an
        // 8-byte IV and 39 with a 16-byte IV. Too many is its own error, so the
        // creator can be told to re-encode with fewer slices.
        for (iv_size, cap) in [(8u8, 40usize), (16, 39)] {
            let at_cap = avc_sample(4, &vec![(112usize, 1u8); cap]);
            assert_eq!(avc_subsample_map(&at_cap, 4, iv_size).unwrap().len(), cap);
            let over = avc_sample(4, &vec![(112usize, 1u8); cap + 1]);
            assert!(matches!(
                avc_subsample_map(&over, 4, iv_size),
                Err(CustodyError::InvalidPayload("cenc_too_many_subsamples"))
            ));
        }
        let sample = avc_sample(4, &[(200, 1)]);
        for iv_size in [0u8, 7, 12, 17] {
            assert!(
                avc_subsample_map(&sample, 4, iv_size).is_err(),
                "IV {iv_size}"
            );
        }
    }

    #[test]
    fn avc_subsample_map_drives_ctr_xor_subsamples_round_trip() {
        let key = [0x11u8; 16];
        let iv = pad_iv(&[0x22u8; 8]).unwrap();
        let clear = avc_sample(4, &[(30, 7), (10, 8), (700, 5), (90, 6), (11102, 1)]);
        let pairs: Vec<(u32, u32)> = avc_subsample_map(&clear, 4, 8)
            .unwrap()
            .into_iter()
            .map(|(c, e)| (u32::from(c), e))
            .collect();
        let covered: u64 = pairs
            .iter()
            .map(|&(c, e)| u64::from(c) + u64::from(e))
            .sum();
        assert_eq!(covered, clear.len() as u64);

        let mut buf = clear.clone();
        ctr_xor_subsamples(&mut buf, &key, &iv, &pairs).unwrap();
        let mut pos = 0usize;
        for &(c, e) in &pairs {
            let (c, e) = (c as usize, e as usize);
            assert_eq!(buf[pos..pos + c], clear[pos..pos + c]);
            if e > 0 {
                assert_ne!(buf[pos + c..pos + c + e], clear[pos + c..pos + c + e]);
            }
            pos += c + e;
        }
        ctr_xor_subsamples(&mut buf, &key, &iv, &pairs).unwrap();
        assert_eq!(buf, clear);
    }

    #[test]
    fn derive_cenc_aes128_key_is_stable_and_not_identity() {
        let cek = [0xAB; CONTENT_KEY_BYTES];
        let key = derive_cenc_aes128_key(&cek);
        assert_ne!(key, cek[..16]);
        assert_eq!(key, derive_cenc_aes128_key(&cek));
    }
}

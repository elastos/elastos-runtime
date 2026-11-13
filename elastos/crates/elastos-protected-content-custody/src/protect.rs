use std::collections::BTreeSet;

use elastos_protected_content_provider_contracts::{
    CencFmp4MediaIdentityV1, CustodyProtectionHeader, Fmp4SampleEntryV2,
    ValidatedClearFmp4MediaSessionLayoutV1, ValidatedClearFmp4SegmentLayoutV1,
};
use zeroize::Zeroizing;

use crate::{
    cenc::{avc_subsample_map, ctr_xor, ctr_xor_subsamples, derive_cenc_aes128_key, pad_iv},
    ContentEncryptionKeyV1, CustodyError,
};

pub fn protect_validated_clear_fmp4_init_to_cenc_v1(
    layout: &ValidatedClearFmp4MediaSessionLayoutV1,
    clear_init_segment: &[u8],
    pssh_data: &CustodyProtectionHeader,
) -> Result<Vec<u8>, CustodyError> {
    if clear_init_segment.is_empty() {
        return Err(CustodyError::InvalidPayload("clear_init_segment"));
    }
    layout
        .rewrite_protected_init(clear_init_segment, pssh_data)
        .map_err(Into::into)
}

pub fn protect_validated_clear_fmp4_segment_to_cenc_v1(
    layout: &ValidatedClearFmp4SegmentLayoutV1,
    clear_segment: &[u8],
    content_key: &ContentEncryptionKeyV1,
    sample_ivs: &[[u8; 8]],
) -> Result<Vec<u8>, CustodyError> {
    if clear_segment.is_empty() {
        return Err(CustodyError::InvalidPayload("clear_segment"));
    }
    if sample_ivs.len() != layout.samples().len() {
        return Err(CustodyError::InvalidPayload("sample_ivs"));
    }
    let cenc_key = Zeroizing::new(content_key.with_bytes(derive_cenc_aes128_key));
    let (encrypted_samples, _) = encrypt_validated_clear_segment_samples(
        layout,
        clear_segment,
        &cenc_key,
        sample_ivs,
        None,
    )?;
    layout
        .rewrite_protected_segment(clear_segment, &encrypted_samples, sample_ivs)
        .map_err(Into::into)
}

#[allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    reason = "the protect boundary binds the exact CENC inputs and returns the exact protected parts without an intermediate authority struct"
)]
pub fn protect_validated_clear_cenc_fmp4_media_v1(
    layout: &ValidatedClearFmp4MediaSessionLayoutV1,
    clear_init_segment: &[u8],
    clear_segments: &[Vec<u8>],
    mime_type: &str,
    codecs: &str,
    content_key: &ContentEncryptionKeyV1,
    pssh_data: &CustodyProtectionHeader,
    segment_sample_ivs: &[Vec<[u8; 8]>],
) -> Result<(Vec<u8>, Vec<Vec<u8>>, CencFmp4MediaIdentityV1), CustodyError> {
    if clear_segments.is_empty() || clear_segments.len() != segment_sample_ivs.len() {
        return Err(CustodyError::InvalidPayload("clear_segments"));
    }
    let protected_init =
        protect_validated_clear_fmp4_init_to_cenc_v1(layout, clear_init_segment, pssh_data)?;
    let mut protected_segments = Vec::with_capacity(clear_segments.len());
    for (clear_segment, sample_ivs) in clear_segments.iter().zip(segment_sample_ivs) {
        let segment_layout = layout
            .validate_segment(clear_segment)
            .map_err(|_| CustodyError::InvalidPayload("clear_segment"))?;
        protected_segments.push(protect_validated_clear_fmp4_segment_to_cenc_v1(
            &segment_layout,
            clear_segment,
            content_key,
            sample_ivs.as_slice(),
        )?);
    }
    let media_identity = CencFmp4MediaIdentityV1::new_from_bytes(
        &protected_init,
        &protected_segments,
        mime_type,
        codecs,
    )?;
    Ok((protected_init, protected_segments, media_identity))
}

/// Encrypted samples and, for V2 video, one `(clear, encrypted)` map per sample.
type EncryptedSamples = (Vec<Vec<u8>>, Vec<Vec<(u16, u32)>>);

/// The producer's IVs are 8 bytes (`tenc` default IV size).
const PRODUCER_IV_BYTES: u8 = 8;

/// Encrypts every sample. With `nal_length_size` (V2 video) each sample is
/// encrypted by its AVC NAL subsample map and the maps are returned; without it
/// (V1, V2 audio) each sample is encrypted whole and the maps are empty.
fn encrypt_validated_clear_segment_samples(
    layout: &ValidatedClearFmp4SegmentLayoutV1,
    clear_segment: &[u8],
    cenc_key: &[u8; 16],
    sample_ivs: &[[u8; 8]],
    nal_length_size: Option<u8>,
) -> Result<EncryptedSamples, CustodyError> {
    let clear_mdat = layout.exact_source_mdat_payload(clear_segment)?;
    let mut seen_ivs = BTreeSet::new();
    let mut encrypted_samples = Vec::with_capacity(layout.samples().len());
    let mut maps = Vec::new();
    for (sample, iv8) in layout.samples().iter().zip(sample_ivs) {
        if !seen_ivs.insert(*iv8) {
            return Err(CustodyError::InvalidPayload("sample_ivs"));
        }
        let start = usize::try_from(sample.mdat_offset())
            .map_err(|_| CustodyError::InvalidPayload("clear_segment"))?;
        let end = start
            .checked_add(sample.sample_size() as usize)
            .ok_or(CustodyError::InvalidPayload("clear_segment"))?;
        let mut sample_bytes = clear_mdat
            .get(start..end)
            .ok_or(CustodyError::InvalidPayload("clear_segment"))?
            .to_vec();
        let iv16 = pad_iv(iv8)?;
        match nal_length_size {
            None => ctr_xor(&mut sample_bytes, cenc_key, &iv16),
            Some(nal_length_size) => {
                let map = avc_subsample_map(&sample_bytes, nal_length_size, PRODUCER_IV_BYTES)?;
                let wide: Vec<(u32, u32)> = map
                    .iter()
                    .map(|&(clear, encrypted)| (u32::from(clear), encrypted))
                    .collect();
                ctr_xor_subsamples(&mut sample_bytes, cenc_key, &iv16, &wide)?;
                maps.push(map);
            }
        }
        encrypted_samples.push(sample_bytes);
    }
    Ok((encrypted_samples, maps))
}

pub fn protect_validated_clear_fmp4_init_to_cenc_v2(
    layout: &ValidatedClearFmp4MediaSessionLayoutV1,
    clear_init_segment: &[u8],
    pssh_data: &CustodyProtectionHeader,
    extra_pssh_boxes: &[Vec<u8>],
) -> Result<Vec<u8>, CustodyError> {
    if clear_init_segment.is_empty() {
        return Err(CustodyError::InvalidPayload("clear_init_segment"));
    }
    layout
        .rewrite_protected_init_v2(clear_init_segment, pssh_data, extra_pssh_boxes)
        .map_err(Into::into)
}

/// `session` is the clear V2 session of the init and `layout` comes from
/// `session.validate_segment(clear_segment)`. Video samples get AVC NAL
/// subsamples, audio samples are encrypted whole. The caller allocates one IV
/// per sample, unique across the whole media.
pub fn protect_validated_clear_fmp4_segment_to_cenc_v2(
    session: &ValidatedClearFmp4MediaSessionLayoutV1,
    layout: &ValidatedClearFmp4SegmentLayoutV1,
    clear_segment: &[u8],
    content_key: &ContentEncryptionKeyV1,
    sample_ivs: &[[u8; 8]],
) -> Result<Vec<u8>, CustodyError> {
    if clear_segment.is_empty() {
        return Err(CustodyError::InvalidPayload("clear_segment"));
    }
    let rendition = session
        .rendition()
        .ok_or(CustodyError::InvalidPayload("clear_init_segment"))?;
    if layout.track_id() != rendition.track_id() {
        return Err(CustodyError::InvalidPayload("clear_segment"));
    }
    if sample_ivs.len() != layout.samples().len() {
        return Err(CustodyError::InvalidPayload("sample_ivs"));
    }
    let nal_length_size = match rendition.sample_entry() {
        Fmp4SampleEntryV2::Video {
            nal_length_size, ..
        } => Some(nal_length_size),
        Fmp4SampleEntryV2::Audio { .. } => None,
    };
    let cenc_key = Zeroizing::new(content_key.with_bytes(derive_cenc_aes128_key));
    let (encrypted_samples, subsamples) = encrypt_validated_clear_segment_samples(
        layout,
        clear_segment,
        &cenc_key,
        sample_ivs,
        nal_length_size,
    )?;
    layout
        .rewrite_protected_segment_v2(clear_segment, &encrypted_samples, sample_ivs, &subsamples)
        .map_err(Into::into)
}

#[cfg(test)]
pub(crate) mod v2_test_media {
    use elastos_protected_content_contracts::{
        ContentAccessIdV1, CustodyCommitteeAuthorizationIdentityV1, CustodyEpochIdentityV1,
        CustodyPoolIdentityV1, Digest32,
    };
    use elastos_protected_content_provider_contracts::{
        cenc_dash_merkle_audit_path, cenc_dash_segment_leaf_hash, CencDashMediaIdentityV2,
        CencDashRenditionBytesV2, CencDashRenditionKindV2, CencLayoutProfile, CencMediaSuite,
        CustodyProtectionHeader, ValidatedCencDashRenditionSessionV2,
        ValidatedClearFmp4MediaSessionLayoutV1, PROTECTION,
    };
    use sha2::{Digest as _, Sha256};

    use super::*;

    pub(crate) const KID: [u8; 16] = [0x55; 16];
    pub(crate) const TIMESCALE: u32 = 15360;
    pub(crate) const V: CencDashRenditionKindV2 = CencDashRenditionKindV2::Video;
    pub(crate) const A: CencDashRenditionKindV2 = CencDashRenditionKindV2::Audio;
    const DEFAULT_DURATION: u32 = 512;
    const TFHD_FLAGS_BENTO4: u32 = 0x02002a;
    const TRUN_FLAGS_OFFSET_SIZE: u32 = 0x000201;

    pub(crate) fn bx(box_type: &[u8; 4], content: &[u8]) -> Vec<u8> {
        let mut out = ((8 + content.len()) as u32).to_be_bytes().to_vec();
        out.extend_from_slice(box_type);
        out.extend_from_slice(content);
        out
    }

    fn fbx(box_type: &[u8; 4], version: u8, flags: u32, payload: &[u8]) -> Vec<u8> {
        let mut content = vec![version];
        content.extend_from_slice(&flags.to_be_bytes()[1..]);
        content.extend_from_slice(payload);
        bx(box_type, &content)
    }

    pub(crate) fn pssh_data_v2(kid: [u8; 16]) -> CustodyProtectionHeader {
        pssh_data_v2_with_epoch(kid, 0x62)
    }

    pub(crate) fn pssh_data_v2_with_epoch(kid: [u8; 16], epoch: u8) -> CustodyProtectionHeader {
        CustodyProtectionHeader::new(
            ContentAccessIdV1::new(kid).unwrap(),
            &CustodyPoolIdentityV1::new(Digest32::new([0x61; 32]), 512).unwrap(),
            &CustodyEpochIdentityV1::new(Digest32::new([epoch; 32]), 512).unwrap(),
            &CustodyCommitteeAuthorizationIdentityV1::new(Digest32::new([0x63; 32]), 512).unwrap(),
            CencMediaSuite::DashV2,
        )
    }

    /// A one-track clear init: `avc1` (640x360, `avcC` NAL length 4) or `mp4a`.
    pub(crate) fn init(kind: CencDashRenditionKindV2, track_id: u32) -> Vec<u8> {
        let mut tkhd = vec![0u8; 12];
        tkhd[8..12].copy_from_slice(&track_id.to_be_bytes());
        let mut mdhd = vec![0u8; 20];
        mdhd[8..12].copy_from_slice(&TIMESCALE.to_be_bytes());
        let (handler, entry_type, entry) = match kind {
            V => {
                let mut entry = vec![0u8; 78];
                entry[24..26].copy_from_slice(&640u16.to_be_bytes());
                entry[26..28].copy_from_slice(&360u16.to_be_bytes());
                entry.extend_from_slice(&bx(b"avcC", &[1, 0x64, 0, 0x1f, 0xff, 0xe0, 0]));
                (b"vide", b"avc1", entry)
            }
            A => {
                let mut entry = vec![0u8; 28];
                entry[16..18].copy_from_slice(&2u16.to_be_bytes());
                entry[24..28].copy_from_slice(&(48_000u32 << 16).to_be_bytes());
                (b"soun", b"mp4a", entry)
            }
        };
        let mut hdlr = vec![0u8; 4];
        hdlr.extend_from_slice(handler);
        hdlr.extend_from_slice(&[0u8; 13]);
        let mut stsd = vec![0, 0, 0, 0, 0, 0, 0, 1];
        stsd.extend_from_slice(&bx(entry_type, &entry));
        let minf = bx(b"minf", &bx(b"stbl", &bx(b"stsd", &stsd)));
        let mdia = bx(
            b"mdia",
            &[fbx(b"mdhd", 0, 0, &mdhd), fbx(b"hdlr", 0, 0, &hdlr), minf].concat(),
        );
        let trak = bx(b"trak", &[fbx(b"tkhd", 0, 0, &tkhd), mdia].concat());
        let mut trex = track_id.to_be_bytes().to_vec();
        trex.extend_from_slice(&[0u8; 16]);
        let moov = bx(
            b"moov",
            &[
                bx(b"mvhd", &[0u8; 4]),
                trak,
                bx(b"mvex", &fbx(b"trex", 0, 0, &trex)),
            ]
            .concat(),
        );
        [bx(b"ftyp", b"iso6\0\0\0\0iso6dash"), moov].concat()
    }

    /// A length-prefixed (4 bytes) NAL unit of `len` bytes, header byte included.
    pub(crate) fn nal(nal_type: u8, len: usize) -> Vec<u8> {
        let mut out = (len as u32).to_be_bytes().to_vec();
        out.push(0x60 | nal_type);
        out.extend((1..len).map(|index| (index * 7 + 3) as u8));
        out
    }

    /// `moof(mfhd, traf(tfhd tfdt trun))` + `mdat(samples)` with Bento4's `tfhd`.
    pub(crate) fn clear_segment(track_id: u32, decode_time: u64, samples: &[Vec<u8>]) -> Vec<u8> {
        let mut tfhd = track_id.to_be_bytes().to_vec();
        tfhd.extend_from_slice(&1u32.to_be_bytes());
        tfhd.extend_from_slice(&DEFAULT_DURATION.to_be_bytes());
        tfhd.extend_from_slice(&0u32.to_be_bytes());
        let mut trun = (samples.len() as u32).to_be_bytes().to_vec();
        trun.extend_from_slice(&0i32.to_be_bytes());
        for sample in samples {
            trun.extend_from_slice(&(sample.len() as u32).to_be_bytes());
        }
        let tfhd = fbx(b"tfhd", 0, TFHD_FLAGS_BENTO4, &tfhd);
        let tfdt = fbx(b"tfdt", 1, 0, &decode_time.to_be_bytes());
        let trun = fbx(b"trun", 0, TRUN_FLAGS_OFFSET_SIZE, &trun);
        let trun_off = 8 + 16 + 8 + tfhd.len() + tfdt.len();
        let traf = bx(b"traf", &[tfhd, tfdt, trun].concat());
        let mut moof = bx(
            b"moof",
            &[fbx(b"mfhd", 0, 0, &1u32.to_be_bytes()), traf].concat(),
        );
        let data_offset = (moof.len() + 8) as i32;
        moof[trun_off + 16..trun_off + 20].copy_from_slice(&data_offset.to_be_bytes());
        [moof, bx(b"mdat", &samples.concat())].concat()
    }

    /// A video sample: SEI, one IDR/P slice of `slice_len` bytes, a short slice.
    pub(crate) fn video_sample(slice_len: usize) -> Vec<u8> {
        [nal(6, 30), nal(5, slice_len), nal(1, 100)].concat()
    }

    pub(crate) fn audio_sample(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| seed.wrapping_add(index as u8))
            .collect()
    }

    pub(crate) fn clear_session(
        kind: CencDashRenditionKindV2,
        track_id: u32,
    ) -> (ValidatedClearFmp4MediaSessionLayoutV1, Vec<u8>) {
        let clear_init = init(kind, track_id);
        let session = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
            &clear_init,
            CencLayoutProfile::V2,
        )
        .unwrap();
        (session, clear_init)
    }

    /// The IV of the `counter`-th sample of a session: `prefix4 ‖ counter32`.
    pub(crate) fn iv(prefix: [u8; 4], counter: u32) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&prefix);
        out[4..].copy_from_slice(&counter.to_be_bytes());
        out
    }

    pub(crate) struct ClearRenditionV2<'a> {
        pub(crate) session: &'a ValidatedClearFmp4MediaSessionLayoutV1,
        pub(crate) init: &'a [u8],
        pub(crate) segments: &'a [Vec<u8>],
    }

    pub(crate) struct ProtectedRenditionV2 {
        pub(crate) init: Vec<u8>,
        pub(crate) segments: Vec<Vec<u8>>,
    }

    /// Protects 1..=2 renditions the way the protect provider will: the same
    /// `pssh_data` and extra boxes on every init, one IV counter across all
    /// samples of all renditions, then the head over the protected bytes.
    pub(crate) fn protect_clear_cenc_dash_media_for_test_v2(
        renditions: &[ClearRenditionV2<'_>],
        content_key: &ContentEncryptionKeyV1,
        pssh_data: &CustodyProtectionHeader,
        extra_pssh_boxes: &[Vec<u8>],
        iv_prefix: [u8; 4],
    ) -> Result<(Vec<ProtectedRenditionV2>, CencDashMediaIdentityV2), CustodyError> {
        if renditions.is_empty() || renditions.len() > 2 {
            return Err(CustodyError::InvalidPayload("renditions"));
        }
        let mut counter = 0u32;
        let mut protected = Vec::new();
        for rendition in renditions {
            let protected_init = protect_validated_clear_fmp4_init_to_cenc_v2(
                rendition.session,
                rendition.init,
                pssh_data,
                extra_pssh_boxes,
            )?;
            let mut segments = Vec::new();
            for clear in rendition.segments {
                let layout = rendition
                    .session
                    .validate_segment(clear)
                    .map_err(|_| CustodyError::InvalidPayload("clear_segment"))?;
                let ivs: Vec<[u8; 8]> = layout
                    .samples()
                    .iter()
                    .map(|_| {
                        counter += 1;
                        iv(iv_prefix, counter)
                    })
                    .collect();
                segments.push(protect_validated_clear_fmp4_segment_to_cenc_v2(
                    rendition.session,
                    &layout,
                    clear,
                    content_key,
                    &ivs,
                )?);
            }
            protected.push(ProtectedRenditionV2 {
                init: protected_init,
                segments,
            });
        }
        let bytes: Vec<CencDashRenditionBytesV2<'_>> = renditions
            .iter()
            .zip(&protected)
            .map(|(clear, protected)| CencDashRenditionBytesV2 {
                kind: clear.session.rendition().unwrap().kind(),
                timescale: clear.session.rendition().unwrap().timescale(),
                init_segment: &protected.init,
                segments: &protected.segments,
            })
            .collect();
        let head = CencDashMediaIdentityV2::new_from_bytes(pssh_data.content_access_id(), &bytes)?;
        Ok((protected, head))
    }

    pub(crate) const TEST_CEK: [u8; 32] = [0x42; 32];
    pub(crate) const IV_PREFIX: [u8; 4] = [0x11; 4];

    /// One protected rendition with its head and session.
    pub(crate) struct Packed {
        pub(crate) clear_init: Vec<u8>,
        pub(crate) clear_segments: Vec<Vec<u8>>,
        pub(crate) protected: ProtectedRenditionV2,
        pub(crate) session: ValidatedCencDashRenditionSessionV2,
    }

    pub(crate) fn pack(kind: CencDashRenditionKindV2, clear_segments: Vec<Vec<u8>>) -> Packed {
        let (session, clear_init) = clear_session(kind, 1);
        let cek = ContentEncryptionKeyV1::from_test_bytes(TEST_CEK);
        let (mut protected, head) = protect_clear_cenc_dash_media_for_test_v2(
            &[ClearRenditionV2 {
                session: &session,
                init: &clear_init,
                segments: &clear_segments,
            }],
            &cek,
            &pssh_data_v2(KID),
            &[],
            IV_PREFIX,
        )
        .unwrap();
        let protected = protected.remove(0);
        let session = ValidatedCencDashRenditionSessionV2::new(&head, 0, &protected.init).unwrap();
        Packed {
            clear_init,
            clear_segments,
            protected,
            session,
        }
    }

    /// `n` video segments of two samples each.
    pub(crate) fn video_segments(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|index| {
                clear_segment(
                    1,
                    30_720 * index as u64,
                    &[video_sample(300 + index), video_sample(200)],
                )
            })
            .collect()
    }

    pub(crate) fn audio_segments(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|index| {
                clear_segment(
                    1,
                    30_720 * index as u64,
                    &[audio_sample(1, 120), audio_sample(9, 121)],
                )
            })
            .collect()
    }

    /// The Merkle audit path of segment `index` of `segments`.
    pub(crate) fn proof(
        kind: CencDashRenditionKindV2,
        segments: &[Vec<u8>],
        index: usize,
    ) -> Vec<Digest32> {
        let leaves: Vec<Digest32> = segments
            .iter()
            .enumerate()
            .map(|(position, segment)| {
                cenc_dash_segment_leaf_hash(
                    kind,
                    position as u32,
                    Digest32::new(Sha256::digest(segment).into()),
                    segment.len() as u64,
                )
            })
            .collect();
        cenc_dash_merkle_audit_path(&leaves, index).unwrap()
    }

    const BENTO4_INIT: &[u8] = include_bytes!(
        "../../elastos-protected-content-provider-contracts/tests/fixtures/bento4/same-stream/init.mp4"
    );
    const BENTO4_SEGMENT: &[u8] = include_bytes!(
        "../../elastos-protected-content-provider-contracts/tests/fixtures/bento4/same-stream/seg-1-first-2-samples.m4s"
    );
    /// The fixture's README: public test KID and raw AES-128 key.
    pub(crate) const BENTO4_KID: [u8; 16] = [
        0xfc, 0xa5, 0xa5, 0x80, 0x30, 0xfd, 0x8d, 0x6e, 0xb2, 0x30, 0xe4, 0xda, 0x8f, 0x36, 0x92,
        0xb5,
    ];
    pub(crate) const BENTO4_RAW_KEY: [u8; 16] =
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    pub(crate) const BENTO4_CLEAR_MDAT_SHA256: &str =
        "efaa7f2eb3bd3104c8e04e198b837823bcd361aba6d9d875c9f62b5a10481b1b";

    pub(crate) struct Bento4 {
        pub(crate) init: Vec<u8>,
        pub(crate) segment: Vec<u8>,
        pub(crate) session: ValidatedCencDashRenditionSessionV2,
    }

    /// The Bento4 init with an Elastos `pssh` added at the end of `moov` (the
    /// fixture has none), bound to a one-segment head.
    pub(crate) fn bento4() -> Bento4 {
        let mut init = BENTO4_INIT.to_vec();
        let mut at = 0usize;
        while &init[at + 4..at + 8] != b"moov" {
            at += u32::from_be_bytes(init[at..at + 4].try_into().unwrap()) as usize;
        }
        let moov_size = u32::from_be_bytes(init[at..at + 4].try_into().unwrap()) as usize;
        let pssh = PROTECTION
            .encode_custody(&pssh_data_v2(BENTO4_KID))
            .unwrap();
        init.splice(at + moov_size..at + moov_size, pssh.iter().copied());
        init[at..at + 4].copy_from_slice(&((moov_size + pssh.len()) as u32).to_be_bytes());
        let segments = vec![BENTO4_SEGMENT.to_vec()];
        let head = CencDashMediaIdentityV2::new_from_bytes(
            ContentAccessIdV1::new(BENTO4_KID).unwrap(),
            &[CencDashRenditionBytesV2 {
                kind: V,
                timescale: 15360,
                init_segment: &init,
                segments: &segments,
            }],
        )
        .unwrap();
        let session = ValidatedCencDashRenditionSessionV2::new(&head, 0, &init).unwrap();
        Bento4 {
            init,
            segment: BENTO4_SEGMENT.to_vec(),
            session,
        }
    }
}

#[cfg(test)]
mod tests {
    use elastos_protected_content_contracts::{
        ContentAccessIdV1, CustodyCommitteeAuthorizationIdentityV1, CustodyEpochIdentityV1,
        CustodyPoolIdentityV1, Digest32,
    };
    use elastos_protected_content_provider_contracts::{
        CencDashMediaIdentityV2, CencDashRenditionBytesV2, CencDashRenditionKindV2,
        CencLayoutProfile, CencMediaSuite, CustodyProtectionHeader,
        ValidatedCencDashRenditionSessionV2, ValidatedCencFmp4MediaSessionLayoutV1, PROTECTION,
    };
    use rand09::{rngs::StdRng as HpkeStdRng, SeedableRng as _};

    use super::v2_test_media::*;
    use super::*;
    use crate::{
        cenc::{ctr_xor, derive_cenc_aes128_key, pad_iv},
        decrypt_validated_cenc_fmp4_segment_to_clear_v1, mint_decrypt_session_from_seed,
        rewrite_validated_cenc_fmp4_init_to_clear_v1, wrap_content_key_to_decrypt_session,
    };

    const TRANSCRIPT: &[u8] = b"elastos.protected-content.test-protect-transcript/v1";
    const TFHD_FLAGS_PRODUCER_V1: u32 = 0x020038;
    const TRUN_FLAG_DATA_OFFSET: u32 = 0x000001;
    const TRUN_FLAG_SAMPLE_SIZE: u32 = 0x000200;
    const VISUAL_SAMPLE_ENTRY_FIXED_BYTES: usize = 78;
    const AUDIO_SAMPLE_ENTRY_FIXED_BYTES: usize = 28;

    fn pssh_data() -> CustodyProtectionHeader {
        CustodyProtectionHeader::new(
            ContentAccessIdV1::new([0x55; 16]).unwrap(),
            &CustodyPoolIdentityV1::new(Digest32::new([0x61; 32]), 512).unwrap(),
            &CustodyEpochIdentityV1::new(Digest32::new([0x62; 32]), 512).unwrap(),
            &CustodyCommitteeAuthorizationIdentityV1::new(Digest32::new([0x63; 32]), 512).unwrap(),
            CencMediaSuite::Fmp4V1,
        )
    }

    fn wrapped_cek(
        cek: &ContentEncryptionKeyV1,
    ) -> (
        crate::DecryptSessionSecretKeyV1,
        crate::DecryptSessionWrappedContentKeyV1,
    ) {
        let (session_secret, session_public) = mint_decrypt_session_from_seed([0x51; 32]).unwrap();
        let wrapped = wrap_content_key_to_decrypt_session(
            cek,
            &session_public,
            TRANSCRIPT,
            &mut HpkeStdRng::from_seed([0x71; 32]),
        )
        .unwrap();
        (session_secret, wrapped)
    }

    fn make_box(box_type: &[u8; 4], content: &[u8]) -> Vec<u8> {
        let size = (8 + content.len()) as u32;
        let mut out = Vec::with_capacity(size as usize);
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(box_type);
        out.extend_from_slice(content);
        out
    }

    fn make_fullbox(box_type: &[u8; 4], version: u8, flags: u32, payload: &[u8]) -> Vec<u8> {
        let mut content = Vec::with_capacity(4 + payload.len());
        content.push(version);
        content.extend_from_slice(&flags.to_be_bytes()[1..]);
        content.extend_from_slice(payload);
        make_box(box_type, &content)
    }

    fn make_clear_sample_entry(handler_type: &[u8; 4]) -> Vec<u8> {
        let (fourcc, fixed) = match handler_type {
            b"vide" => (b"avc1", VISUAL_SAMPLE_ENTRY_FIXED_BYTES),
            b"soun" => (b"mp4a", AUDIO_SAMPLE_ENTRY_FIXED_BYTES),
            _ => panic!("unsupported handler"),
        };
        let content = vec![0u8; fixed];
        make_box(fourcc, &content)
    }

    fn make_clear_trak(track_id: u32, handler_type: &[u8; 4]) -> Vec<u8> {
        let mut tkhd_payload = vec![0u8; 12];
        tkhd_payload[8..12].copy_from_slice(&track_id.to_be_bytes());
        let tkhd = make_fullbox(b"tkhd", 0, 0, &tkhd_payload);

        let mut hdlr_payload = vec![0u8; 4];
        hdlr_payload.extend_from_slice(handler_type);
        let hdlr = make_fullbox(b"hdlr", 0, 0, &hdlr_payload);

        let entry = make_clear_sample_entry(handler_type);
        let mut stsd_payload = vec![0u8; 4];
        stsd_payload.extend_from_slice(&1u32.to_be_bytes());
        stsd_payload.extend_from_slice(&entry);
        let stsd = make_box(b"stsd", &stsd_payload);
        let stbl = make_box(b"stbl", &stsd);
        let minf = make_box(b"minf", &stbl);

        let mut mdia_content = Vec::new();
        mdia_content.extend_from_slice(&hdlr);
        mdia_content.extend_from_slice(&minf);
        let mdia = make_box(b"mdia", &mdia_content);

        let mut trak_content = Vec::new();
        trak_content.extend_from_slice(&tkhd);
        trak_content.extend_from_slice(&mdia);
        make_box(b"trak", &trak_content)
    }

    fn make_trex(track_id: u32) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&track_id.to_be_bytes());
        payload.extend_from_slice(&[0u8; 16]);
        make_fullbox(b"trex", 0, 0, &payload)
    }

    fn valid_clear_init_segment() -> Vec<u8> {
        let ftyp = make_box(b"ftyp", b"isom\0\0\0\0isomiso6");
        let traks = [make_clear_trak(1, b"vide"), make_clear_trak(2, b"soun")];
        let mut mvex_content = Vec::new();
        mvex_content.extend_from_slice(&make_trex(1));
        mvex_content.extend_from_slice(&make_trex(2));
        let mvex = make_box(b"mvex", &mvex_content);
        let mvhd = make_box(b"mvhd", &[0u8; 4]);

        let mut moov_content = Vec::new();
        moov_content.extend_from_slice(&mvhd);
        for trak in traks {
            moov_content.extend_from_slice(&trak);
        }
        moov_content.extend_from_slice(&mvex);
        let moov = make_box(b"moov", &moov_content);

        let mut init = Vec::new();
        init.extend_from_slice(&ftyp);
        init.extend_from_slice(&moov);
        init
    }

    fn make_clear_segment(track_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut tfhd_payload = Vec::new();
        tfhd_payload.extend_from_slice(&track_id.to_be_bytes());
        tfhd_payload.extend_from_slice(&1u32.to_be_bytes());
        tfhd_payload.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        tfhd_payload.extend_from_slice(&0u32.to_be_bytes());
        let tfhd = make_fullbox(b"tfhd", 0, TFHD_FLAGS_PRODUCER_V1, &tfhd_payload);

        let mut trun_payload = Vec::new();
        trun_payload.extend_from_slice(&1u32.to_be_bytes());
        trun_payload.extend_from_slice(&0i32.to_be_bytes());
        trun_payload.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        let trun = make_fullbox(
            b"trun",
            0,
            TRUN_FLAG_DATA_OFFSET | TRUN_FLAG_SAMPLE_SIZE,
            &trun_payload,
        );

        let traf = {
            let mut traf_content = Vec::new();
            traf_content.extend_from_slice(&tfhd);
            traf_content.extend_from_slice(&make_fullbox(b"tfdt", 0, 0, &1u32.to_be_bytes()));
            traf_content.extend_from_slice(&trun);
            make_box(b"traf", &traf_content)
        };
        let mfhd = make_fullbox(b"mfhd", 0, 0, &1u32.to_be_bytes());
        let mut moof_content = Vec::new();
        moof_content.extend_from_slice(&mfhd);
        moof_content.extend_from_slice(&traf);
        let mut moof = make_box(b"moof", &moof_content);
        let sample_offset = (moof.len() + 8) as i32;
        let data_offset_at = moof.len() - trun.len() + 16;
        moof[data_offset_at..data_offset_at + 4].copy_from_slice(&sample_offset.to_be_bytes());

        let mdat = make_box(b"mdat", payload);
        let mut out = moof;
        out.extend_from_slice(&mdat);
        out
    }

    #[test]
    fn clear_fixture_protect_round_trips_through_validator_and_play_decrypt() {
        let clear_init = valid_clear_init_segment();
        let clear_segment = make_clear_segment(1, b"clear-video");
        let clear_layout = ValidatedClearFmp4MediaSessionLayoutV1::new(&clear_init).unwrap();
        let cek = ContentEncryptionKeyV1::from_test_bytes([0x42; 32]);
        let (protected_init, protected_segments, media_identity) =
            protect_validated_clear_cenc_fmp4_media_v1(
                &clear_layout,
                &clear_init,
                std::slice::from_ref(&clear_segment),
                "video/mp4",
                "avc1.64001f,mp4a.40.2",
                &cek,
                &pssh_data(),
                &[vec![[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]]],
            )
            .unwrap();

        let protected_layout =
            ValidatedCencFmp4MediaSessionLayoutV1::new(&media_identity, &protected_init).unwrap();
        let clear_rewritten =
            rewrite_validated_cenc_fmp4_init_to_clear_v1(&protected_layout, &protected_init)
                .unwrap();
        assert_eq!(clear_rewritten, clear_init);

        let (session_secret, wrapped) = wrapped_cek(&cek);
        let clear_segment_rewritten = decrypt_validated_cenc_fmp4_segment_to_clear_v1(
            &protected_layout,
            &protected_segments[0],
            0,
            &session_secret,
            &wrapped,
            TRANSCRIPT,
        )
        .unwrap();
        assert_eq!(clear_segment_rewritten, clear_segment);
    }

    #[test]
    fn protect_rejects_wrong_iv_count_duplicate_iv_and_mutated_protected_boundary() {
        let clear_init = valid_clear_init_segment();
        let clear_segment = make_clear_segment(1, b"clear-video");
        let clear_layout = ValidatedClearFmp4MediaSessionLayoutV1::new(&clear_init).unwrap();
        let segment_layout = clear_layout.validate_segment(&clear_segment).unwrap();
        let cek = ContentEncryptionKeyV1::from_test_bytes([0x24; 32]);

        assert!(protect_validated_clear_fmp4_segment_to_cenc_v1(
            &segment_layout,
            &clear_segment,
            &cek,
            &[]
        )
        .is_err());

        let two_sample_segment = {
            let mut tfhd_payload = Vec::new();
            tfhd_payload.extend_from_slice(&1u32.to_be_bytes());
            tfhd_payload.extend_from_slice(&1u32.to_be_bytes());
            tfhd_payload.extend_from_slice(&5u32.to_be_bytes());
            tfhd_payload.extend_from_slice(&0u32.to_be_bytes());
            let tfhd = make_fullbox(b"tfhd", 0, TFHD_FLAGS_PRODUCER_V1, &tfhd_payload);
            let mut trun_payload = Vec::new();
            trun_payload.extend_from_slice(&2u32.to_be_bytes());
            trun_payload.extend_from_slice(&0i32.to_be_bytes());
            trun_payload.extend_from_slice(&5u32.to_be_bytes());
            trun_payload.extend_from_slice(&6u32.to_be_bytes());
            let trun = make_fullbox(
                b"trun",
                0,
                TRUN_FLAG_DATA_OFFSET | TRUN_FLAG_SAMPLE_SIZE,
                &trun_payload,
            );
            let traf = {
                let mut traf_content = Vec::new();
                traf_content.extend_from_slice(&tfhd);
                traf_content.extend_from_slice(&make_fullbox(b"tfdt", 0, 0, &1u32.to_be_bytes()));
                traf_content.extend_from_slice(&trun);
                make_box(b"traf", &traf_content)
            };
            let mfhd = make_fullbox(b"mfhd", 0, 0, &1u32.to_be_bytes());
            let mut moof_content = Vec::new();
            moof_content.extend_from_slice(&mfhd);
            moof_content.extend_from_slice(&traf);
            let mut moof = make_box(b"moof", &moof_content);
            let sample_offset = (moof.len() + 8) as i32;
            let data_offset_at = moof.len() - trun.len() + 16;
            moof[data_offset_at..data_offset_at + 4].copy_from_slice(&sample_offset.to_be_bytes());
            let mut out = moof;
            out.extend_from_slice(&make_box(b"mdat", b"hello-world"));
            out
        };
        let two_sample_layout = clear_layout.validate_segment(&two_sample_segment).unwrap();
        assert!(protect_validated_clear_fmp4_segment_to_cenc_v1(
            &two_sample_layout,
            &two_sample_segment,
            &cek,
            &[
                [0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22],
                [0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22]
            ]
        )
        .is_err());

        let (protected_init, protected_segments, media_identity) =
            protect_validated_clear_cenc_fmp4_media_v1(
                &clear_layout,
                &clear_init,
                std::slice::from_ref(&clear_segment),
                "video/mp4",
                "avc1.64001f,mp4a.40.2",
                &cek,
                &pssh_data(),
                &[vec![[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]]],
            )
            .unwrap();
        let protected_layout =
            ValidatedCencFmp4MediaSessionLayoutV1::new(&media_identity, &protected_init).unwrap();
        let mut tampered_segment = protected_segments[0].clone();
        tampered_segment[0] ^= 1;
        assert!(decrypt_validated_cenc_fmp4_segment_to_clear_v1(
            &protected_layout,
            &tampered_segment,
            0,
            &wrapped_cek(&cek).0,
            &wrapped_cek(&cek).1,
            TRANSCRIPT,
        )
        .is_err());
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn v1_protect_and_decrypt_bytes_are_pinned() {
        let clear_init = valid_clear_init_segment();
        let clear_segment = make_clear_segment(1, b"clear-video");
        let clear_layout = ValidatedClearFmp4MediaSessionLayoutV1::new(&clear_init).unwrap();
        let cek = ContentEncryptionKeyV1::from_test_bytes([0x42; 32]);
        let (protected_init, protected_segments, media_identity) =
            protect_validated_clear_cenc_fmp4_media_v1(
                &clear_layout,
                &clear_init,
                std::slice::from_ref(&clear_segment),
                "video/mp4",
                "avc1.64001f,mp4a.40.2",
                &cek,
                &pssh_data(),
                &[vec![[0x11; 8]]],
            )
            .unwrap();
        assert_eq!(
            sha256_hex(&protected_init),
            "49bf4f571e0dfd3cf5c27b24215c94f5d97a7f7c812dcab8faa42d2958d97ba0"
        );
        assert_eq!(
            sha256_hex(&protected_segments[0]),
            "ed0f18b433a827fd690d164a429d4ddddfb8d7725546a77b5cdf46150f4f6946"
        );
        let protected_layout =
            ValidatedCencFmp4MediaSessionLayoutV1::new(&media_identity, &protected_init).unwrap();
        let (session_secret, wrapped) = wrapped_cek(&cek);
        let clear_again = decrypt_validated_cenc_fmp4_segment_to_clear_v1(
            &protected_layout,
            &protected_segments[0],
            0,
            &session_secret,
            &wrapped,
            TRANSCRIPT,
        )
        .unwrap();
        assert_eq!(clear_again, clear_segment);
    }

    fn cek() -> ContentEncryptionKeyV1 {
        ContentEncryptionKeyV1::from_test_bytes(TEST_CEK)
    }

    fn decrypt_v2(packed: &Packed, index: usize) -> Result<Vec<u8>, CustodyError> {
        let (session_secret, wrapped) = wrapped_cek(&cek());
        let kind = packed.session.kind();
        crate::decrypt_validated_cenc_dash_segment_to_clear_v2(
            &packed.session,
            &packed.protected.segments[index],
            index as u32,
            &v2_proof(kind, &packed.protected.segments, index),
            &session_secret,
            &wrapped,
            TRANSCRIPT,
        )
    }

    fn v2_proof(
        kind: CencDashRenditionKindV2,
        segments: &[Vec<u8>],
        index: usize,
    ) -> Vec<Digest32> {
        proof(kind, segments, index)
    }

    fn subsample_pairs(packed: &Packed, index: usize) -> Vec<Vec<(u16, u32)>> {
        let layout = packed
            .session
            .validate_proven_segment(
                index as u32,
                &packed.protected.segments[index],
                &v2_proof(packed.session.kind(), &packed.protected.segments, index),
            )
            .unwrap();
        layout
            .samples()
            .iter()
            .map(|sample| {
                sample
                    .subsamples()
                    .iter()
                    .map(|sub| (sub.clear_bytes(), sub.encrypted_bytes()))
                    .collect()
            })
            .collect()
    }

    fn clear_video_packed(segments: Vec<Vec<u8>>) -> Packed {
        pack(V, segments)
    }

    fn single_sample_video(sample: Vec<u8>) -> Vec<Vec<u8>> {
        vec![clear_segment(1, 0, &[sample])]
    }

    fn protect_error(sample: Vec<u8>) -> CustodyError {
        let (session, _) = clear_session(V, 1);
        let segment = clear_segment(1, 0, &[sample]);
        let layout = session.validate_segment(&segment).unwrap();
        protect_validated_clear_fmp4_segment_to_cenc_v2(
            &session,
            &layout,
            &segment,
            &cek(),
            &[iv(IV_PREFIX, 1)],
        )
        .unwrap_err()
    }

    #[test]
    fn v2_video_subsample_map_matches_bento4() {
        let bento = bento4();
        let (clear_init, clear_segment_bytes) = bento4_clear_pair(&bento);
        let session = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
            &clear_init,
            CencLayoutProfile::V2,
        )
        .unwrap();
        let packed = {
            let cek = cek();
            let (mut protected, head) = protect_clear_cenc_dash_media_for_test_v2(
                &[ClearRenditionV2 {
                    session: &session,
                    init: &clear_init,
                    segments: std::slice::from_ref(&clear_segment_bytes),
                }],
                &cek,
                &pssh_data_v2(KID),
                &[],
                IV_PREFIX,
            )
            .unwrap();
            let protected = protected.remove(0);
            let session =
                ValidatedCencDashRenditionSessionV2::new(&head, 0, &protected.init).unwrap();
            Packed {
                clear_init,
                clear_segments: vec![clear_segment_bytes],
                protected,
                session,
            }
        };
        assert_eq!(
            subsample_pairs(&packed, 0),
            vec![vec![(793, 21680)], vec![(110, 10992)]]
        );
        assert_eq!(decrypt_v2(&packed, 0).unwrap(), packed.clear_segments[0]);
        assert_eq!(
            rewrite_init_v2(&packed),
            packed.clear_init,
            "init round trip"
        );
    }

    fn rewrite_init_v2(packed: &Packed) -> Vec<u8> {
        crate::rewrite_validated_cenc_dash_init_to_clear_v2(&packed.session, &packed.protected.init)
            .unwrap()
    }

    /// The Bento4 stream decrypted with its raw key, as a clear init and segment.
    fn bento4_clear_pair(bento: &Bento4) -> (Vec<u8>, Vec<u8>) {
        let layout = bento
            .session
            .validate_proven_segment(0, &bento.segment, &[])
            .unwrap();
        let mdat = layout.exact_source_mdat_payload(&bento.segment).unwrap();
        let clear_mdat =
            crate::play::decrypt_validated_segment_mdat_v1(&layout, mdat, &BENTO4_RAW_KEY).unwrap();
        (
            bento.session.rewrite_clear_init(&bento.init).unwrap(),
            layout
                .rewrite_clear_segment(&bento.segment, &clear_mdat)
                .unwrap(),
        )
    }

    #[test]
    fn v2_video_round_trip_through_real_cek_path() {
        let packed = clear_video_packed(video_segments(3));
        for index in 0..3 {
            assert_eq!(
                decrypt_v2(&packed, index).unwrap(),
                packed.clear_segments[index]
            );
        }
        assert_eq!(rewrite_init_v2(&packed), packed.clear_init);
        assert!(subsample_pairs(&packed, 0)
            .iter()
            .all(|map| !map.is_empty()));
    }

    #[test]
    fn v2_video_clear_ranges_untouched_and_keystream_continuous() {
        let sample = [nal(7, 20), nal(1, 11102), nal(5, 400), nal(1, 100)].concat();
        let packed = clear_video_packed(single_sample_video(sample.clone()));
        let maps = subsample_pairs(&packed, 0);
        assert_eq!(maps.len(), 1);
        assert!(
            maps[0]
                .iter()
                .filter(|(_, encrypted)| *encrypted > 0)
                .count()
                >= 2
        );
        let layout = packed
            .session
            .validate_proven_segment(0, &packed.protected.segments[0], &[])
            .unwrap();
        let mdat = layout
            .exact_source_mdat_payload(&packed.protected.segments[0])
            .unwrap();
        let (mut pos, mut clear_encrypted, mut protected_encrypted) = (0usize, vec![], vec![]);
        for &(clear, encrypted) in &maps[0] {
            let clear = usize::from(clear);
            assert_eq!(mdat[pos..pos + clear], sample[pos..pos + clear]);
            pos += clear;
            let end = pos + encrypted as usize;
            clear_encrypted.extend_from_slice(&sample[pos..end]);
            protected_encrypted.extend_from_slice(&mdat[pos..end]);
            pos = end;
        }
        assert_eq!(pos, sample.len());
        assert!(!protected_encrypted.is_empty());
        let key = cek().with_bytes(derive_cenc_aes128_key);
        let mut expected = clear_encrypted;
        ctr_xor(&mut expected, &key, &pad_iv(&iv(IV_PREFIX, 1)).unwrap());
        assert_eq!(protected_encrypted, expected);
    }

    #[test]
    fn v2_audio_whole_sample_round_trip() {
        let packed = pack(A, audio_segments(2));
        assert!(subsample_pairs(&packed, 0).iter().all(Vec::is_empty));
        let layout = packed
            .session
            .validate_proven_segment(
                0,
                &packed.protected.segments[0],
                &proof(A, &packed.protected.segments, 0),
            )
            .unwrap();
        let mdat = layout
            .exact_source_mdat_payload(&packed.protected.segments[0])
            .unwrap();
        assert_ne!(
            mdat,
            &audio_sample(1, 120)
                .iter()
                .chain(&audio_sample(9, 121))
                .copied()
                .collect::<Vec<u8>>()[..]
        );
        for index in 0..2 {
            assert_eq!(
                decrypt_v2(&packed, index).unwrap(),
                packed.clear_segments[index]
            );
        }
    }

    #[test]
    fn v2_saiz_bound_40_ok_41_refused() {
        let sample_of = |count: usize| (0..count).flat_map(|_| nal(1, 112)).collect::<Vec<u8>>();
        let packed = clear_video_packed(single_sample_video(sample_of(40)));
        assert_eq!(subsample_pairs(&packed, 0)[0].len(), 40);
        assert_eq!(decrypt_v2(&packed, 0).unwrap(), packed.clear_segments[0]);
        assert!(matches!(
            protect_error(sample_of(41)),
            CustodyError::InvalidPayload("cenc_too_many_subsamples")
        ));
    }

    #[test]
    fn v2_many_small_nals_fold() {
        let sample = (0..100)
            .flat_map(|_| nal(6, 20))
            .chain(nal(1, 300))
            .collect::<Vec<u8>>();
        let packed = clear_video_packed(single_sample_video(sample));
        assert_eq!(subsample_pairs(&packed, 0), vec![vec![(2496, 208)]]);
        assert_eq!(decrypt_v2(&packed, 0).unwrap(), packed.clear_segments[0]);
    }

    #[test]
    fn v2_protect_refuses_bad_nal_tiling() {
        let trailing = [nal(1, 200), vec![1, 2]].concat();
        let overrun = [nal(1, 200), vec![0, 0, 1, 0, 0x61]].concat();
        let zero_length = [nal(1, 200), vec![0, 0, 0, 0]].concat();
        for sample in [trailing, overrun, zero_length] {
            assert!(matches!(
                protect_error(sample),
                CustodyError::InvalidPayload("cenc_subsample_map")
            ));
        }
    }

    #[test]
    fn v2_protect_refuses_mismatches() {
        let (video, video_init) = clear_session(V, 1);
        let (audio, _) = clear_session(A, 1);
        let (track2, _) = clear_session(V, 2);
        let video_segment = clear_segment(1, 0, &[video_sample(300), video_sample(200)]);
        let audio_segment = clear_segment(1, 0, &[audio_sample(1, 100)]);
        let track2_segment = clear_segment(2, 0, &[video_sample(300)]);
        let ivs = [iv(IV_PREFIX, 1), iv(IV_PREFIX, 2)];
        let key = cek();
        let try_segment = |session: &ValidatedClearFmp4MediaSessionLayoutV1,
                           layout: &ValidatedClearFmp4SegmentLayoutV1,
                           segment: &[u8],
                           ivs: &[[u8; 8]]| {
            protect_validated_clear_fmp4_segment_to_cenc_v2(session, layout, segment, &key, ivs)
        };
        let video_layout = video.validate_segment(&video_segment).unwrap();
        assert!(try_segment(&video, &video_layout, &video_segment, &ivs).is_ok());
        // IV count off by one either way, duplicate IVs, empty segment.
        assert!(try_segment(&video, &video_layout, &video_segment, &ivs[..1]).is_err());
        let three = [ivs[0], ivs[1], iv(IV_PREFIX, 3)];
        assert!(try_segment(&video, &video_layout, &video_segment, &three).is_err());
        assert!(try_segment(&video, &video_layout, &video_segment, &[ivs[0], ivs[0]]).is_err());
        assert!(try_segment(&video, &video_layout, &[], &ivs).is_err());
        // A segment layout of the other kind, or of another track, under this session.
        let audio_layout = audio.validate_segment(&audio_segment).unwrap();
        assert!(try_segment(&video, &audio_layout, &audio_segment, &ivs[..1]).is_err());
        assert!(try_segment(&audio, &video_layout, &video_segment, &ivs).is_err());
        let track2_layout = track2.validate_segment(&track2_segment).unwrap();
        assert!(try_segment(&video, &track2_layout, &track2_segment, &ivs[..1]).is_err());
        // A V1 session, and a V1 segment layout.
        let v1_init = valid_clear_init_segment();
        let v1 = ValidatedClearFmp4MediaSessionLayoutV1::new(&v1_init).unwrap();
        let v1_segment = make_clear_segment(1, b"clear-video");
        let v1_layout = v1.validate_segment(&v1_segment).unwrap();
        assert!(try_segment(&v1, &v1_layout, &v1_segment, &ivs[..1]).is_err());
        assert!(try_segment(&video, &v1_layout, &v1_segment, &ivs[..1]).is_err());
        // Init: empty, V1 suite, V1 session.
        let data = pssh_data_v2(KID);
        assert!(
            protect_validated_clear_fmp4_init_to_cenc_v2(&video, &video_init, &data, &[]).is_ok()
        );
        assert!(protect_validated_clear_fmp4_init_to_cenc_v2(&video, &[], &data, &[]).is_err());
        assert!(protect_validated_clear_fmp4_init_to_cenc_v2(
            &video,
            &video_init,
            &pssh_data(),
            &[]
        )
        .is_err());
        assert!(protect_validated_clear_fmp4_init_to_cenc_v2(&v1, &v1_init, &data, &[]).is_err());
    }

    #[test]
    fn v2_init_pssh_order_and_binding() {
        let (session, clear_init) = clear_session(V, 1);
        let data = pssh_data_v2(KID);
        let mut widevine = vec![0u8; 4];
        widevine.extend_from_slice(&[
            0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d,
            0x21, 0xed,
        ]);
        widevine.extend_from_slice(&2u32.to_be_bytes());
        widevine.extend_from_slice(b"wv");
        let widevine = bx(b"pssh", &widevine);
        let protected = protect_validated_clear_fmp4_init_to_cenc_v2(
            &session,
            &clear_init,
            &data,
            std::slice::from_ref(&widevine),
        )
        .unwrap();
        let find = |needle: &[u8]| {
            protected
                .windows(needle.len())
                .position(|window| window == needle)
                .unwrap()
        };
        let common = PROTECTION
            .registry()
            .common()
            .encode_kid_list(&KID)
            .unwrap();
        let elastos = PROTECTION.encode_custody(&data).unwrap();
        assert!(find(&common) < find(&widevine));
        assert!(find(&widevine) < find(&elastos));
        assert_eq!(protected.len() - (find(&elastos) + elastos.len()), 0);
        let (mut rendition, head) = protect_clear_cenc_dash_media_for_test_v2(
            &[ClearRenditionV2 {
                session: &session,
                init: &clear_init,
                segments: &[clear_segment(1, 0, &[video_sample(300)])],
            }],
            &cek(),
            &data,
            std::slice::from_ref(&widevine),
            IV_PREFIX,
        )
        .unwrap();
        let rendition = rendition.remove(0);
        assert!(ValidatedCencDashRenditionSessionV2::new(&head, 0, &rendition.init).is_ok());
        assert!(protect_validated_clear_fmp4_init_to_cenc_v2(
            &session,
            &clear_init,
            &data,
            &[elastos]
        )
        .is_err());
    }

    #[test]
    fn v1_functions_refuse_v2_layouts() {
        let (session, clear_init) = clear_session(V, 1);
        let segment = clear_segment(1, 0, &[video_sample(300)]);
        let layout = session.validate_segment(&segment).unwrap();
        assert!(
            protect_validated_clear_fmp4_init_to_cenc_v1(&session, &clear_init, &pssh_data())
                .is_err()
        );
        assert!(protect_validated_clear_fmp4_segment_to_cenc_v1(
            &layout,
            &segment,
            &cek(),
            &[iv(IV_PREFIX, 1)]
        )
        .is_err());
    }

    #[test]
    fn v2_whole_media_shares_one_iv_counter_and_one_pssh() {
        let (video, video_init) = clear_session(V, 1);
        let (audio, audio_init) = clear_session(A, 1);
        let video_segments = video_segments(2);
        let audio_segments = audio_segments(2);
        let data = pssh_data_v2(KID);
        let (protected, head) = protect_clear_cenc_dash_media_for_test_v2(
            &[
                ClearRenditionV2 {
                    session: &video,
                    init: &video_init,
                    segments: &video_segments,
                },
                ClearRenditionV2 {
                    session: &audio,
                    init: &audio_init,
                    segments: &audio_segments,
                },
            ],
            &cek(),
            &data,
            &[],
            IV_PREFIX,
        )
        .unwrap();
        let elastos = PROTECTION.encode_custody(&data).unwrap();
        let mut ivs = BTreeSet::new();
        let mut sessions = Vec::new();
        for (index, (rendition, clear)) in protected
            .iter()
            .zip([&video_segments, &audio_segments])
            .enumerate()
        {
            assert!(rendition.init.ends_with(&elastos));
            let session =
                ValidatedCencDashRenditionSessionV2::new(&head, index, &rendition.init).unwrap();
            sessions.push(session.clone());
            for (position, segment) in rendition.segments.iter().enumerate() {
                let layout = session
                    .validate_proven_segment(
                        position as u32,
                        segment,
                        &proof(session.kind(), &rendition.segments, position),
                    )
                    .unwrap();
                for sample in layout.samples() {
                    assert!(ivs.insert(sample.iv().to_vec()));
                }
                let (secret, wrapped) = wrapped_cek(&cek());
                let decrypted = crate::decrypt_validated_cenc_dash_segment_to_clear_v2(
                    &session,
                    segment,
                    position as u32,
                    &proof(session.kind(), &rendition.segments, position),
                    &secret,
                    &wrapped,
                    TRANSCRIPT,
                )
                .unwrap();
                assert_eq!(decrypted, clear[position]);
            }
        }
        assert_eq!(ivs.len(), 8);
        assert_eq!(
            crate::require_common_cenc_dash_protection_header_v2(&head, &sessions).unwrap(),
            &data
        );
        let direct = CencDashMediaIdentityV2::new_from_bytes(
            data.content_access_id(),
            &[
                CencDashRenditionBytesV2 {
                    kind: V,
                    timescale: TIMESCALE,
                    init_segment: &protected[0].init,
                    segments: &protected[0].segments,
                },
                CencDashRenditionBytesV2 {
                    kind: A,
                    timescale: TIMESCALE,
                    init_segment: &protected[1].init,
                    segments: &protected[1].segments,
                },
            ],
        )
        .unwrap();
        assert_eq!(head, direct);
    }

    #[test]
    fn content_key_debug_is_redacted() {
        let cek = ContentEncryptionKeyV1::from_test_bytes([0xAB; 32]);
        let debug = format!("{cek:?}");
        assert!(!debug.contains("abab"));
        assert!(debug.contains("redacted"));
    }
}

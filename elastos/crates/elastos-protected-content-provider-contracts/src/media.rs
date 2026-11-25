use elastos_protected_content_contracts::{
    CanonicalContract, ContentAccessIdV1, ContractError, Digest32, EncryptedContentIdentityV1,
    MAX_ENCRYPTED_CONTENT_BYTES,
};
use sha2::{Digest as _, Sha256};

use crate::media_dash::CiphertextStreamHasher;
use crate::protection_system::{
    CencMediaSuite, CustodyProtectionHeader, ProtectionClass, ProtectionContext,
    ProtectionSystemId, PROTECTION,
};
use crate::pssh::parse_pssh_v0_or_v1;

const CENC_FMP4_SEGMENT_IDENTITY_DOMAIN_V1: &str = "elastos.protected-content.cenc-fmp4-segment/v1";
const CENC_FMP4_MEDIA_IDENTITY_DOMAIN_V1: &str =
    "elastos.protected-content.cenc-fmp4-media-identity/v1";
pub const CENC_FMP4_MEDIA_SUITE_ID_V1: &str = "cenc-fmp4-aes128ctr/v1";
/// Sample-encryption suite of v2 (DASH) media: `cenc` AES-128-CTR, AVC NAL
/// subsamples, whole-sample AAC, `saiz`/`saio`/`senc` in every `traf`.
pub const CENC_DASH_MEDIA_SUITE_ID_V2: &str = "cenc-dash-aes128ctr/v2";
/// Largest single `pssh` box a v2 init may carry.
pub const MAX_PSSH_BOX_BYTES_V2: usize = 64 * 1024;
/// Largest total of all `pssh` boxes in one v2 init.
pub const MAX_INIT_PSSH_BYTES_V2: usize = 1024 * 1024;
pub const MAX_CENC_FMP4_MEDIA_IDENTITY_BYTES_V1: usize = 64 * 1024;
const MEDIA_MANIFEST_ROOT_DOMAIN_V1: &[u8] =
    b"elastos.protected-content.cenc-fmp4-manifest-root/v1";
pub(crate) const MAX_MEDIA_DECLARATION_BYTES_V1: usize = 255;
const MAX_MEDIA_SEGMENTS_V1: usize = 512;
const MAX_MEDIA_TRACKS_V1: usize = 8;
const MAX_TRACK_SAMPLES_V1: usize = 1 << 20;
const MAX_CHILD_BOXES_V1: usize = 64;
const SUPPORTED_COMMON_IV_SIZE_V1: u8 = 8;
/// V2 also accepts 16-byte per-sample IVs (Bento4 writes them).
const SUPPORTED_LARGE_IV_SIZE_V2: u8 = 16;
const VISUAL_SAMPLE_ENTRY_FIXED_BYTES: usize = 78;
const AUDIO_SAMPLE_ENTRY_FIXED_BYTES: usize = 28;
const TFHD_FLAG_BASE_DATA_OFFSET: u32 = 0x000001;
const TFHD_FLAG_SAMPLE_DESCRIPTION_INDEX: u32 = 0x000002;
const AUX_INFO_FLAG_TYPE_PRESENT: u32 = 0x000001;
const TFHD_FLAG_DEFAULT_SAMPLE_DURATION: u32 = 0x000008;
const TFHD_FLAG_DEFAULT_SAMPLE_SIZE: u32 = 0x000010;
const TFHD_FLAG_DEFAULT_SAMPLE_FLAGS: u32 = 0x000020;
const TFHD_FLAG_DEFAULT_BASE_IS_MOOF: u32 = 0x020000;
const TRUN_FLAG_DATA_OFFSET: u32 = 0x000001;
const TRUN_FLAG_FIRST_SAMPLE_FLAGS: u32 = 0x000004;
const TRUN_FLAG_SAMPLE_DURATION: u32 = 0x000100;
const TRUN_FLAG_SAMPLE_SIZE: u32 = 0x000200;
const TRUN_FLAG_SAMPLE_FLAGS: u32 = 0x000400;
const TRUN_FLAG_SAMPLE_COMPOSITION_TIME_OFFSET: u32 = 0x000800;
const SENC_FLAG_SUBSAMPLES: u32 = 0x000002;

/// Which media layout rules apply. `V1` is today's single-file fMP4 format and is
/// frozen; `V2` is the DASH/CENC format (spec §6, §7). Every validator and rewrite
/// keeps the V1 rules byte for byte and adds the V2 relaxations only under `V2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CencLayoutProfile {
    V1,
    V2,
}

/// The kind of a v2 rendition. A v2 init carries exactly one track.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CencDashRenditionKindV2 {
    Video,
    Audio,
}

impl CencDashRenditionKindV2 {
    /// The canonical byte: 1 video, 2 audio.
    pub const fn code(self) -> u8 {
        match self {
            Self::Video => 1,
            Self::Audio => 2,
        }
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Video),
            2 => Some(Self::Audio),
            _ => None,
        }
    }
}

/// What a v2 sample entry declares, read from its fixed fields (and `avcC`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fmp4SampleEntryV2 {
    /// `avc1` (or `encv` over `avc1`). `nal_length_size` is avcC
    /// `lengthSizeMinusOne + 1`: 1, 2 or 4.
    Video {
        width: u16,
        height: u16,
        nal_length_size: u8,
    },
    /// `mp4a` (or `enca` over `mp4a`). `sample_rate` is the integer part of the
    /// 16.16 field.
    Audio {
        sample_rate: u32,
        channel_count: u16,
    },
}

/// The single track of a validated v2 init segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedFmp4RenditionV2 {
    track_id: u32,
    timescale: u32,
    sample_entry: Fmp4SampleEntryV2,
}

impl ValidatedFmp4RenditionV2 {
    pub const fn kind(&self) -> CencDashRenditionKindV2 {
        match self.sample_entry {
            Fmp4SampleEntryV2::Video { .. } => CencDashRenditionKindV2::Video,
            Fmp4SampleEntryV2::Audio { .. } => CencDashRenditionKindV2::Audio,
        }
    }

    pub const fn track_id(&self) -> u32 {
        self.track_id
    }

    /// `mdhd` timescale of the track.
    pub const fn timescale(&self) -> u32 {
        self.timescale
    }

    pub const fn sample_entry(&self) -> Fmp4SampleEntryV2 {
        self.sample_entry
    }
}

/// One v2 media segment's place on the track timeline, in `mdhd` timescale
/// units: `decode_time` is the `tfdt` base media decode time and `duration` the
/// sum of the `trun` sample durations (else the `tfhd` default × sample count).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fmp4SegmentTimelineV2 {
    pub decode_time: u64,
    pub duration: u64,
}

/// Where a non-Elastos `pssh` box sits in a v2 protected init, so the clear
/// rewrite can take it out again.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PsshSpanV2 {
    moov_off: usize,
    pssh_off: usize,
    pssh_size: usize,
}

/// What the V2 segment validator needs from the protected init's one track.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CencTrackRulesV2 {
    track_id: u32,
    kind: CencDashRenditionKindV2,
    iv_size: u8,
}

#[derive(Debug, Clone, Copy)]
struct BoxHeader {
    box_type: [u8; 4],
    size: usize,
    header_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoxResizeTargetV1 {
    box_off: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedCencFmp4TrackRewriteV1 {
    track_id: u32,
    content_access_id: ContentAccessIdV1,
    /// `tenc` default per-sample IV size: always 8 under V1, 8 or 16 under V2.
    iv_size: u8,
    sample_entry_off: usize,
    original_fourcc: [u8; 4],
    sinf_off: usize,
    sinf_size: usize,
    resize_targets: Vec<BoxResizeTargetV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedCencFmp4SegmentRewriteV1 {
    moof_off: usize,
    traf_off: usize,
    trun_off: usize,
    senc_off: usize,
    senc_size: usize,
    trun_data_offset: i32,
    mdat_content_start: usize,
    mdat_content_end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedClearFmp4TrackLayoutV1 {
    track_id: u32,
    sample_entry_off: usize,
    original_fourcc: [u8; 4],
    resize_targets: Vec<BoxResizeTargetV1>,
}

/// The protected init segment's single `pssh` box: what it declares, and where it
/// sits so the read path can take it back out and reproduce the clear init segment
/// byte for byte.
///
/// The `header` is kept rather than discarded so the Runtime can compare what the
/// provider wrote into a public file against the identities the Runtime itself
/// holds — see `ValidatedCencFmp4MediaSessionLayoutV1::protection_header`.
///
/// The producer always appends the box as the LAST child of `moov`, and the
/// validator enforces that, so removing it never moves any `sinf` the track rewrite
/// pass is about to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedCencFmp4PsshV1 {
    system: ProtectionSystemId,
    header: CustodyProtectionHeader,
    moov_off: usize,
    pssh_off: usize,
    pssh_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedClearFmp4MediaSessionLayoutV1 {
    init_segment_sha256: Digest32,
    init_segment_bytes: u64,
    track_ids: Vec<u32>,
    tracks: Vec<ValidatedClearFmp4TrackLayoutV1>,
    moov_off: usize,
    /// `Some` exactly when the layout was validated under [`CencLayoutProfile::V2`].
    rendition: Option<ValidatedFmp4RenditionV2>,
}

impl ValidatedClearFmp4MediaSessionLayoutV1 {
    pub fn new(clear_init_segment: &[u8]) -> Result<Self, ContractError> {
        Self::new_with_profile(clear_init_segment, CencLayoutProfile::V1)
    }

    /// Validate a clear init under `profile`. V2 also requires exactly one track,
    /// an `mdhd` timescale, and for video an `avcC` with a 1, 2 or 4 byte NAL
    /// length; [`Self::rendition`] reports them.
    pub fn new_with_profile(
        clear_init_segment: &[u8],
        profile: CencLayoutProfile,
    ) -> Result<Self, ContractError> {
        let init = validate_clear_init_segment_v1(clear_init_segment)?;
        let rendition = match profile {
            CencLayoutProfile::V1 => None,
            CencLayoutProfile::V2 => {
                if init.tracks.len() != 1 {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
                Some(parse_rendition_v2(
                    clear_init_segment,
                    init.moov_off,
                    false,
                )?)
            }
        };
        Ok(Self {
            init_segment_sha256: Digest32::new(Sha256::digest(clear_init_segment).into()),
            init_segment_bytes: clear_init_segment.len() as u64,
            track_ids: init.track_ids,
            tracks: init.tracks,
            moov_off: init.moov_off,
            rendition,
        })
    }

    pub fn profile(&self) -> CencLayoutProfile {
        match self.rendition {
            None => CencLayoutProfile::V1,
            Some(_) => CencLayoutProfile::V2,
        }
    }

    /// The single track of a V2 layout; `None` under V1.
    pub fn rendition(&self) -> Option<&ValidatedFmp4RenditionV2> {
        self.rendition.as_ref()
    }

    pub fn track_ids(&self) -> &[u32] {
        &self.track_ids
    }

    pub fn validate_segment(
        &self,
        clear_segment: &[u8],
    ) -> Result<ValidatedClearFmp4SegmentLayoutV1, ContractError> {
        validate_clear_media_segment_v1(
            clear_segment,
            self.track_ids.as_slice(),
            self.rendition.map(|rendition| rendition.kind()),
        )
    }

    /// Protect the clear init segment and inject the CENC `pssh` box that declares
    /// the scheme.
    ///
    /// The `tenc` default KID is taken from `header`'s own content access id
    /// rather than passed alongside it, so the KID in the sample entry, the KID in
    /// the box's KID list, and the id named in the payload are one value and
    /// cannot disagree. The box is the writer binding's encoding of `header`.
    pub fn rewrite_protected_init(
        &self,
        clear_init_segment: &[u8],
        header: &CustodyProtectionHeader,
    ) -> Result<Vec<u8>, ContractError> {
        self.rewrite_protected_init_in(&PROTECTION, clear_init_segment, header)
    }

    pub(crate) fn rewrite_protected_init_in(
        &self,
        ctx: &ProtectionContext<'_>,
        clear_init_segment: &[u8],
        header: &CustodyProtectionHeader,
    ) -> Result<Vec<u8>, ContractError> {
        if self.rendition.is_some() || header.media_suite() != CencMediaSuite::Fmp4V1 {
            return Err(ContractError::InvalidField("init_segment_bytes"));
        }
        verify_exact_source_bytes(
            clear_init_segment,
            self.init_segment_sha256,
            self.init_segment_bytes,
            "init_segment_bytes",
        )?;
        rewrite_protected_init_v1(
            clear_init_segment,
            &self.tracks,
            self.moov_off,
            &[ctx.encode_custody(header)?],
            header,
        )
    }

    /// V2 protect of the clear init (spec §6 "PSSH set"): the same `sinf` as V1
    /// (`cenc`, 8-byte IVs, KID = content access id), then at the end of `moov`,
    /// in order: a Common `pssh` v1 listing the KID, `extra_pssh_boxes` verbatim,
    /// and the custody box last. `header` must declare
    /// [`CencMediaSuite::DashV2`]. Extra boxes must be well-formed v0/v1
    /// boxes of a non-custody system, each within [`MAX_PSSH_BOX_BYTES_V2`]. The
    /// output is re-validated under V2 before it is returned.
    pub fn rewrite_protected_init_v2(
        &self,
        clear_init_segment: &[u8],
        header: &CustodyProtectionHeader,
        extra_pssh_boxes: &[Vec<u8>],
    ) -> Result<Vec<u8>, ContractError> {
        self.rewrite_protected_init_v2_in(&PROTECTION, clear_init_segment, header, extra_pssh_boxes)
    }

    pub(crate) fn rewrite_protected_init_v2_in(
        &self,
        ctx: &ProtectionContext<'_>,
        clear_init_segment: &[u8],
        header: &CustodyProtectionHeader,
        extra_pssh_boxes: &[Vec<u8>],
    ) -> Result<Vec<u8>, ContractError> {
        if self.rendition.is_none() || header.media_suite() != CencMediaSuite::DashV2 {
            return Err(ContractError::InvalidField("init_segment_bytes"));
        }
        verify_exact_source_bytes(
            clear_init_segment,
            self.init_segment_sha256,
            self.init_segment_bytes,
            "init_segment_bytes",
        )?;
        let key_id = header.content_access_id();
        let mut pssh_boxes = Vec::with_capacity(extra_pssh_boxes.len() + 2);
        pssh_boxes.push(ctx.registry().common().encode_kid_list(key_id.as_bytes())?);
        for extra in extra_pssh_boxes {
            let (_, parsed) = parse_exact_pssh_v2(extra)?;
            if matches!(
                ctx.registry().classify(&parsed.system_id),
                ProtectionClass::Custody(_)
            ) {
                return Err(ContractError::InvalidField("extra_pssh_boxes"));
            }
            pssh_boxes.push(extra.clone());
        }
        pssh_boxes.push(ctx.encode_custody(header)?);
        let protected = rewrite_protected_init_v1(
            clear_init_segment,
            &self.tracks,
            self.moov_off,
            &pssh_boxes,
            header,
        )?;
        validate_init_segment_in(ctx, &protected, CencLayoutProfile::V2)?;
        Ok(protected)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedClearFmp4SegmentLayoutV1 {
    source_sha256: Digest32,
    source_bytes: u64,
    track_id: u32,
    samples: Vec<ValidatedClearFmp4SampleLayoutV1>,
    rewrite: ValidatedClearFmp4SegmentRewriteV1,
    /// `Some` exactly when validated under [`CencLayoutProfile::V2`].
    v2: Option<(CencDashRenditionKindV2, Fmp4SegmentTimelineV2)>,
}

impl ValidatedClearFmp4SegmentLayoutV1 {
    pub const fn source_sha256(&self) -> Digest32 {
        self.source_sha256
    }

    pub const fn source_bytes(&self) -> u64 {
        self.source_bytes
    }

    pub const fn track_id(&self) -> u32 {
        self.track_id
    }

    pub fn samples(&self) -> &[ValidatedClearFmp4SampleLayoutV1] {
        &self.samples
    }

    /// The segment's timeline under V2; `None` under V1.
    pub fn timeline(&self) -> Option<Fmp4SegmentTimelineV2> {
        self.v2.map(|(_, timeline)| timeline)
    }

    pub fn exact_source_mdat_payload<'a>(
        &self,
        clear_segment: &'a [u8],
    ) -> Result<&'a [u8], ContractError> {
        verify_exact_source_bytes(
            clear_segment,
            self.source_sha256,
            self.source_bytes,
            "clear_segment_bytes",
        )?;
        clear_segment
            .get(self.rewrite.mdat_content_start..self.rewrite.mdat_content_end)
            .ok_or(ContractError::InvalidField("clear_segment_bytes"))
    }

    pub fn rewrite_protected_segment(
        &self,
        clear_segment: &[u8],
        encrypted_samples: &[Vec<u8>],
        sample_ivs: &[[u8; 8]],
    ) -> Result<Vec<u8>, ContractError> {
        if self.v2.is_some() {
            return Err(ContractError::InvalidField("clear_segment_bytes"));
        }
        let protected_mdat = self.protected_mdat(clear_segment, encrypted_samples, sample_ivs)?;
        let senc = make_fullsample_senc_box_v1(sample_ivs)?;
        self.splice_protected_segment(clear_segment, &protected_mdat, senc)
    }

    /// V2 protect rewrite (spec §6): replaces the mdat payload with
    /// `encrypted_samples` and inserts `saiz`, `saio` and `senc` after `trun`.
    /// Video samples each carry a non-empty `(clear, encrypted)` subsample map
    /// that covers the sample exactly (`senc` flags 2); audio is whole-sample and
    /// `subsamples` must be empty (`senc` flags 0). Every `saiz` entry must fit in
    /// one byte.
    pub fn rewrite_protected_segment_v2(
        &self,
        clear_segment: &[u8],
        encrypted_samples: &[Vec<u8>],
        sample_ivs: &[[u8; 8]],
        subsamples: &[Vec<(u16, u32)>],
    ) -> Result<Vec<u8>, ContractError> {
        const ERR: ContractError = ContractError::InvalidField("clear_segment_bytes");
        let (kind, _) = self.v2.ok_or(ERR)?;
        let subsamples = match kind {
            CencDashRenditionKindV2::Video => {
                if subsamples.len() != self.samples.len() {
                    return Err(ERR);
                }
                for (sample, map) in self.samples.iter().zip(subsamples) {
                    let covered = map.iter().try_fold(0u64, |acc, &(clear, encrypted)| {
                        acc.checked_add(u64::from(clear) + u64::from(encrypted))
                    });
                    if map.is_empty() || covered != Some(u64::from(sample.sample_size)) {
                        return Err(ERR);
                    }
                }
                Some(subsamples)
            }
            CencDashRenditionKindV2::Audio => {
                if !subsamples.is_empty() {
                    return Err(ERR);
                }
                None
            }
        };
        let protected_mdat = self.protected_mdat(clear_segment, encrypted_samples, sample_ivs)?;
        let senc = make_senc_box_v2(sample_ivs, subsamples)?;
        let entry_sizes = senc_entry_sizes_v2(sample_ivs.len(), subsamples)?;
        let saiz = make_saiz_box_v2(&entry_sizes)?;
        // `saio` points at the first IV: the `senc` offset within `moof` (which
        // starts the segment) plus its 8-byte header, fullbox word and count.
        let senc_off = self
            .rewrite
            .senc_insert_off
            .checked_add(saiz.len())
            .and_then(|value| value.checked_add(SAIO_BOX_BYTES_V2))
            .and_then(|value| value.checked_sub(self.rewrite.moof_off))
            .and_then(|value| value.checked_add(16))
            .ok_or(ERR)?;
        let saio = make_fullbox_v1(
            b"saio",
            0,
            0,
            &[
                1u32.to_be_bytes(),
                u32::try_from(senc_off).map_err(|_| ERR)?.to_be_bytes(),
            ]
            .concat(),
        )?;
        let mut aux = saiz;
        aux.extend_from_slice(&saio);
        aux.extend_from_slice(&senc);
        self.splice_protected_segment(clear_segment, &protected_mdat, aux)
    }

    fn protected_mdat(
        &self,
        clear_segment: &[u8],
        encrypted_samples: &[Vec<u8>],
        sample_ivs: &[[u8; 8]],
    ) -> Result<Vec<u8>, ContractError> {
        verify_exact_source_bytes(
            clear_segment,
            self.source_sha256,
            self.source_bytes,
            "clear_segment_bytes",
        )?;
        if encrypted_samples.len() != self.samples.len() || sample_ivs.len() != self.samples.len() {
            return Err(ContractError::InvalidField("clear_segment_bytes"));
        }
        let mut seen_ivs = std::collections::BTreeSet::new();
        let mut protected_mdat = Vec::with_capacity(
            self.rewrite
                .mdat_content_end
                .checked_sub(self.rewrite.mdat_content_start)
                .ok_or(ContractError::InvalidField("clear_segment_bytes"))?,
        );
        for ((sample, encrypted_sample), iv) in
            self.samples.iter().zip(encrypted_samples).zip(sample_ivs)
        {
            if encrypted_sample.len() != sample.sample_size as usize || !seen_ivs.insert(*iv) {
                return Err(ContractError::InvalidField("clear_segment_bytes"));
            }
            protected_mdat.extend_from_slice(encrypted_sample);
        }
        Ok(protected_mdat)
    }

    /// Writes `protected_mdat`, then inserts `aux` (the CENC boxes) at the end of
    /// `traf`, growing `traf`/`moof` and moving `trun.data_offset` by its length.
    fn splice_protected_segment(
        &self,
        clear_segment: &[u8],
        protected_mdat: &[u8],
        aux: Vec<u8>,
    ) -> Result<Vec<u8>, ContractError> {
        let mut rewritten = clear_segment.to_vec();
        rewritten[self.rewrite.mdat_content_start..self.rewrite.mdat_content_end]
            .copy_from_slice(protected_mdat);
        grow_box_size_in_place(
            &mut rewritten,
            self.rewrite.traf_off,
            aux.len(),
            "clear_segment_bytes",
        )?;
        grow_box_size_in_place(
            &mut rewritten,
            self.rewrite.moof_off,
            aux.len(),
            "clear_segment_bytes",
        )?;
        let new_data_offset = self
            .rewrite
            .trun_data_offset
            .checked_add(
                i32::try_from(aux.len())
                    .map_err(|_| ContractError::InvalidField("clear_segment_bytes"))?,
            )
            .ok_or(ContractError::InvalidField("clear_segment_bytes"))?;
        let data_offset_at = self
            .rewrite
            .trun_off
            .checked_add(read_box_header(&rewritten, self.rewrite.trun_off)?.header_size)
            .and_then(|value| value.checked_add(8))
            .ok_or(ContractError::InvalidField("clear_segment_bytes"))?;
        rewritten[data_offset_at..data_offset_at + 4]
            .copy_from_slice(&new_data_offset.to_be_bytes());
        rewritten.splice(
            self.rewrite.senc_insert_off..self.rewrite.senc_insert_off,
            aux,
        );
        Ok(rewritten)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedClearFmp4SampleLayoutV1 {
    mdat_offset: u64,
    sample_size: u32,
}

impl ValidatedClearFmp4SampleLayoutV1 {
    pub const fn mdat_offset(&self) -> u64 {
        self.mdat_offset
    }

    pub const fn sample_size(&self) -> u32 {
        self.sample_size
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedClearFmp4SegmentRewriteV1 {
    moof_off: usize,
    traf_off: usize,
    trun_off: usize,
    trun_data_offset: i32,
    mdat_content_start: usize,
    mdat_content_end: usize,
    senc_insert_off: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCencFmp4MediaLayoutV1 {
    init_segment_sha256: Digest32,
    init_segment_bytes: u64,
    protected_track_ids: Vec<u32>,
    track_rewrites: Vec<ValidatedCencFmp4TrackRewriteV1>,
    pssh: Option<ValidatedCencFmp4PsshV1>,
    other_pssh: Vec<PsshSpanV2>,
    rendition: Option<ValidatedFmp4RenditionV2>,
    segments: Vec<ValidatedCencFmp4SegmentLayoutV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCencFmp4MediaSessionLayoutV1 {
    media_identity: CencFmp4MediaIdentityV1,
    protected_track_ids: Vec<u32>,
    track_rewrites: Vec<ValidatedCencFmp4TrackRewriteV1>,
    pssh: Option<ValidatedCencFmp4PsshV1>,
}

impl ValidatedCencFmp4MediaSessionLayoutV1 {
    pub fn new(
        media_identity: &CencFmp4MediaIdentityV1,
        protected_init_segment: &[u8],
    ) -> Result<Self, ContractError> {
        Self::new_in(&PROTECTION, media_identity, protected_init_segment)
    }

    pub(crate) fn new_in(
        ctx: &ProtectionContext<'_>,
        media_identity: &CencFmp4MediaIdentityV1,
        protected_init_segment: &[u8],
    ) -> Result<Self, ContractError> {
        media_identity.validate()?;
        let init = validate_staged_init_segment_in(
            ctx,
            protected_init_segment,
            media_identity.init_segment_sha256(),
            media_identity.init_segment_bytes(),
            CencLayoutProfile::V1,
        )?;
        Ok(Self {
            media_identity: media_identity.clone(),
            protected_track_ids: init.protected_track_ids,
            track_rewrites: init.track_rewrites,
            pssh: init.pssh,
        })
    }

    pub fn media_identity(&self) -> &CencFmp4MediaIdentityV1 {
        &self.media_identity
    }

    pub fn protected_track_ids(&self) -> &[u32] {
        &self.protected_track_ids
    }

    pub fn content_access_id(&self) -> ContentAccessIdV1 {
        self.track_rewrites
            .first()
            .expect("validated protected media session has at least one track")
            .content_access_id
    }

    /// What the init segment's CENC protection header declares, if it carries one.
    ///
    /// `None` means the init segment has no `pssh` box. That is legal on the read
    /// path — every media minted before the header existed is in that shape — and
    /// the Runtime is the layer that decides a NEW protect output must carry one.
    /// The validator has already proved that a header present here names this
    /// media's own content access id.
    pub fn protection_header(&self) -> Option<&CustodyProtectionHeader> {
        self.pssh.as_ref().map(|pssh| &pssh.header)
    }

    /// The protection system that carried [`Self::protection_header`].
    pub fn protection_system(&self) -> Option<ProtectionSystemId> {
        self.pssh.as_ref().map(|pssh| pssh.system)
    }

    /// Whether the init's custody box was written by the active encoder (the
    /// writer binding), as a new mint must be.
    pub fn protected_by_active_encoder(&self) -> bool {
        self.protected_by_active_encoder_in(&PROTECTION)
    }

    pub(crate) fn protected_by_active_encoder_in(&self, ctx: &ProtectionContext<'_>) -> bool {
        self.protection_system() == Some(ctx.writer().id)
    }

    pub fn rewrite_clear_init(
        &self,
        protected_init_segment: &[u8],
    ) -> Result<Vec<u8>, ContractError> {
        rewrite_clear_init_v1(
            protected_init_segment,
            self.media_identity.init_segment_sha256(),
            self.media_identity.init_segment_bytes(),
            &self.track_rewrites,
            self.pssh.as_ref(),
            &[],
        )
    }

    pub fn validate_indexed_segment(
        &self,
        segment_index: usize,
        encrypted_segment: &[u8],
    ) -> Result<ValidatedCencFmp4SegmentLayoutV1, ContractError> {
        let expected_segment = self
            .media_identity
            .encrypted_segments()
            .get(segment_index)
            .ok_or(ContractError::InvalidField("encrypted_segments"))?;
        validate_staged_segment_v1(
            expected_segment,
            encrypted_segment,
            self.protected_track_ids.as_slice(),
            None,
        )
    }
}

impl ValidatedCencFmp4MediaLayoutV1 {
    pub const fn init_segment_sha256(&self) -> Digest32 {
        self.init_segment_sha256
    }

    pub const fn init_segment_bytes(&self) -> u64 {
        self.init_segment_bytes
    }

    pub fn protected_track_ids(&self) -> &[u32] {
        &self.protected_track_ids
    }

    pub fn segments(&self) -> &[ValidatedCencFmp4SegmentLayoutV1] {
        &self.segments
    }

    /// The single track of a V2 layout; `None` under V1.
    pub fn rendition(&self) -> Option<&ValidatedFmp4RenditionV2> {
        self.rendition.as_ref()
    }

    /// What the init's Elastos `pssh` declares, if it carries one.
    pub fn protection_header(&self) -> Option<&CustodyProtectionHeader> {
        self.pssh.as_ref().map(|pssh| &pssh.header)
    }

    /// The protection system that carried [`Self::protection_header`].
    pub fn protection_system(&self) -> Option<ProtectionSystemId> {
        self.pssh.as_ref().map(|pssh| pssh.system)
    }

    pub fn rewrite_clear_init(
        &self,
        protected_init_segment: &[u8],
    ) -> Result<Vec<u8>, ContractError> {
        rewrite_clear_init_v1(
            protected_init_segment,
            self.init_segment_sha256,
            self.init_segment_bytes,
            &self.track_rewrites,
            self.pssh.as_ref(),
            &self.other_pssh,
        )
    }

    pub fn rewrite_clear_segment(
        &self,
        segment_index: usize,
        encrypted_segment: &[u8],
        clear_mdat: &[u8],
    ) -> Result<Vec<u8>, ContractError> {
        self.segments
            .get(segment_index)
            .ok_or(ContractError::InvalidField("encrypted_segments"))?
            .rewrite_clear_segment(encrypted_segment, clear_mdat)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCencFmp4SegmentLayoutV1 {
    source_sha256: Digest32,
    source_bytes: u64,
    track_id: u32,
    samples: Vec<ValidatedCencFmp4SampleLayoutV1>,
    rewrite: ValidatedCencFmp4SegmentRewriteV1,
    /// `Some` exactly when validated under [`CencLayoutProfile::V2`].
    timeline: Option<Fmp4SegmentTimelineV2>,
}

impl ValidatedCencFmp4SegmentLayoutV1 {
    pub const fn source_sha256(&self) -> Digest32 {
        self.source_sha256
    }

    pub const fn source_bytes(&self) -> u64 {
        self.source_bytes
    }

    pub const fn track_id(&self) -> u32 {
        self.track_id
    }

    pub fn samples(&self) -> &[ValidatedCencFmp4SampleLayoutV1] {
        &self.samples
    }

    /// The segment's timeline under V2; `None` under V1.
    pub fn timeline(&self) -> Option<Fmp4SegmentTimelineV2> {
        self.timeline
    }

    pub fn exact_source_mdat_payload<'a>(
        &self,
        encrypted_segment: &'a [u8],
    ) -> Result<&'a [u8], ContractError> {
        verify_exact_source_bytes(
            encrypted_segment,
            self.source_sha256,
            self.source_bytes,
            "encrypted_segments",
        )?;
        encrypted_segment
            .get(self.rewrite.mdat_content_start..self.rewrite.mdat_content_end)
            .ok_or(ContractError::InvalidField("encrypted_segments"))
    }

    pub fn rewrite_clear_segment(
        &self,
        encrypted_segment: &[u8],
        clear_mdat: &[u8],
    ) -> Result<Vec<u8>, ContractError> {
        verify_exact_source_bytes(
            encrypted_segment,
            self.source_sha256,
            self.source_bytes,
            "encrypted_segments",
        )?;
        rewrite_clear_segment_unchecked_v1(&self.rewrite, encrypted_segment, clear_mdat)
    }
}

fn rewrite_clear_segment_unchecked_v1(
    rewrite: &ValidatedCencFmp4SegmentRewriteV1,
    encrypted_segment: &[u8],
    clear_mdat: &[u8],
) -> Result<Vec<u8>, ContractError> {
    let expected_mdat_len = rewrite
        .mdat_content_end
        .checked_sub(rewrite.mdat_content_start)
        .ok_or(ContractError::InvalidField("encrypted_segments"))?;
    if clear_mdat.len() != expected_mdat_len {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let mut rewritten = encrypted_segment.to_vec();
    rewritten[rewrite.mdat_content_start..rewrite.mdat_content_end].copy_from_slice(clear_mdat);
    shrink_box_size_in_place(
        &mut rewritten,
        rewrite.traf_off,
        rewrite.senc_size,
        "encrypted_segments",
    )?;
    shrink_box_size_in_place(
        &mut rewritten,
        rewrite.moof_off,
        rewrite.senc_size,
        "encrypted_segments",
    )?;
    let new_data_offset = rewrite
        .trun_data_offset
        .checked_sub(
            i32::try_from(rewrite.senc_size)
                .map_err(|_| ContractError::InvalidField("encrypted_segments"))?,
        )
        .ok_or(ContractError::InvalidField("encrypted_segments"))?;
    if new_data_offset < 0 {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let data_offset_at = rewrite
        .trun_off
        .checked_add(read_box_header(&rewritten, rewrite.trun_off)?.header_size)
        .and_then(|value| value.checked_add(8))
        .ok_or(ContractError::InvalidField("encrypted_segments"))?;
    rewritten[data_offset_at..data_offset_at + 4].copy_from_slice(&new_data_offset.to_be_bytes());
    let senc_end = rewrite
        .senc_off
        .checked_add(rewrite.senc_size)
        .ok_or(ContractError::InvalidField("encrypted_segments"))?;
    if senc_end > rewritten.len() {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    rewritten.drain(rewrite.senc_off..senc_end);
    Ok(rewritten)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCencFmp4SampleLayoutV1 {
    ciphertext_offset: u64,
    sample_size: u32,
    /// The first `iv_size` bytes are the IV; the rest stay zero.
    iv: [u8; 16],
    iv_size: u8,
    subsamples: Vec<ValidatedCencFmp4SubsampleV1>,
}

impl ValidatedCencFmp4SampleLayoutV1 {
    pub const fn ciphertext_offset(&self) -> u64 {
        self.ciphertext_offset
    }

    pub const fn sample_size(&self) -> u32 {
        self.sample_size
    }

    /// The per-sample IV: 8 bytes, or 16 under V2.
    pub fn iv(&self) -> &[u8] {
        &self.iv[..usize::from(self.iv_size)]
    }

    pub fn subsamples(&self) -> &[ValidatedCencFmp4SubsampleV1] {
        &self.subsamples
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCencFmp4SubsampleV1 {
    clear_bytes: u16,
    encrypted_bytes: u32,
}

impl ValidatedCencFmp4SubsampleV1 {
    pub const fn clear_bytes(&self) -> u16 {
        self.clear_bytes
    }

    pub const fn encrypted_bytes(&self) -> u32 {
        self.encrypted_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CencFmp4SegmentIdentityV1 {
    ciphertext_sha256: Digest32,
    ciphertext_bytes: u64,
}

impl CencFmp4SegmentIdentityV1 {
    pub fn new_from_encrypted_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.is_empty() || (bytes.len() as u64) > MAX_ENCRYPTED_CONTENT_BYTES {
            return Err(ContractError::InvalidField("ciphertext_bytes"));
        }
        Ok(Self {
            ciphertext_sha256: Digest32::new(Sha256::digest(bytes).into()),
            ciphertext_bytes: bytes.len() as u64,
        })
    }

    fn new_recorded(
        ciphertext_sha256: Digest32,
        ciphertext_bytes: u64,
    ) -> Result<Self, ContractError> {
        let value = Self {
            ciphertext_sha256,
            ciphertext_bytes,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn ciphertext_sha256(&self) -> Digest32 {
        self.ciphertext_sha256
    }

    pub const fn ciphertext_bytes(&self) -> u64 {
        self.ciphertext_bytes
    }
}

impl CencFmp4SegmentIdentityV1 {
    fn validate(&self) -> Result<(), ContractError> {
        if self.ciphertext_bytes == 0 || self.ciphertext_bytes > MAX_ENCRYPTED_CONTENT_BYTES {
            return Err(ContractError::InvalidField("ciphertext_bytes"));
        }
        Ok(())
    }
}

impl CanonicalContract for CencFmp4SegmentIdentityV1 {
    fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let mut bytes = canonical_prefix(CENC_FMP4_SEGMENT_IDENTITY_DOMAIN_V1);
        bytes.extend_from_slice(self.ciphertext_sha256.as_bytes());
        bytes.extend_from_slice(&self.ciphertext_bytes.to_be_bytes());
        Ok(bytes)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        let mut cursor = canonical_cursor(bytes, CENC_FMP4_SEGMENT_IDENTITY_DOMAIN_V1)?;
        let value = Self::new_recorded(
            Digest32::new(read_fixed_32(bytes, &mut cursor)?),
            read_u64(bytes, &mut cursor)?,
        )?;
        finish_canonical(bytes, cursor)?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(ContractError::InvalidField("non-canonical encoding"));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CencFmp4MediaIdentityV1 {
    encrypted_content: EncryptedContentIdentityV1,
    media_manifest_root: Digest32,
    init_segment_sha256: Digest32,
    init_segment_bytes: u64,
    mime_type: String,
    codecs: String,
    encrypted_segments: Vec<CencFmp4SegmentIdentityV1>,
}

impl CencFmp4MediaIdentityV1 {
    pub fn validate_structure(
        init_segment: &[u8],
        encrypted_segments: &[Vec<u8>],
    ) -> Result<ValidatedCencFmp4MediaLayoutV1, ContractError> {
        validate_cenc_fmp4_media_structure_v1(
            init_segment,
            encrypted_segments,
            CencLayoutProfile::V1,
        )
    }

    pub fn new_from_bytes(
        init_segment: &[u8],
        encrypted_segments: &[Vec<u8>],
        mime_type: impl Into<String>,
        codecs: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let _ = Self::validate_structure(init_segment, encrypted_segments)?;
        if init_segment.is_empty() || (init_segment.len() as u64) > MAX_ENCRYPTED_CONTENT_BYTES {
            return Err(ContractError::InvalidField("init_segment_bytes"));
        }
        if encrypted_segments.is_empty() || encrypted_segments.len() > MAX_MEDIA_SEGMENTS_V1 {
            return Err(ContractError::InvalidField("encrypted_segments"));
        }
        let encrypted_segment_bytes = encrypted_segments;
        let encrypted_segments = encrypted_segment_bytes
            .iter()
            .map(|segment| CencFmp4SegmentIdentityV1::new_from_encrypted_bytes(segment))
            .collect::<Result<Vec<_>, _>>()?;
        let encrypted_content =
            Self::compute_encrypted_content_from_bytes(encrypted_segment_bytes)?;
        let mime_type = mime_type.into();
        let codecs = codecs.into();
        let init_segment_sha256 = Digest32::new(Sha256::digest(init_segment).into());
        let media_manifest_root = Self::compute_media_manifest_root(
            encrypted_content.clone(),
            init_segment_sha256,
            init_segment.len() as u64,
            &mime_type,
            &codecs,
            encrypted_segments.as_slice(),
        )?;
        let value = Self {
            encrypted_content,
            media_manifest_root,
            init_segment_sha256,
            init_segment_bytes: init_segment.len() as u64,
            mime_type,
            codecs,
            encrypted_segments,
        };
        value.validate()?;
        Ok(value)
    }

    fn new_recorded(
        encrypted_content: EncryptedContentIdentityV1,
        media_manifest_root: Digest32,
        init_segment_sha256: Digest32,
        init_segment_bytes: u64,
        mime_type: impl Into<String>,
        codecs: impl Into<String>,
        encrypted_segments: Vec<CencFmp4SegmentIdentityV1>,
    ) -> Result<Self, ContractError> {
        let value = Self {
            encrypted_content,
            media_manifest_root,
            init_segment_sha256,
            init_segment_bytes,
            mime_type: mime_type.into(),
            codecs: codecs.into(),
            encrypted_segments,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn encrypted_content(&self) -> &EncryptedContentIdentityV1 {
        &self.encrypted_content
    }

    pub const fn media_manifest_root(&self) -> Digest32 {
        self.media_manifest_root
    }

    pub const fn init_segment_sha256(&self) -> Digest32 {
        self.init_segment_sha256
    }

    pub const fn init_segment_bytes(&self) -> u64 {
        self.init_segment_bytes
    }

    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    pub fn codecs(&self) -> &str {
        &self.codecs
    }

    pub fn encrypted_segments(&self) -> &[CencFmp4SegmentIdentityV1] {
        &self.encrypted_segments
    }

    pub const fn suite_id(&self) -> &'static str {
        CENC_FMP4_MEDIA_SUITE_ID_V1
    }

    fn validate_mime_and_codecs(&self) -> Result<(), ContractError> {
        validate_visible_ascii(&self.mime_type, "mime_type", MAX_MEDIA_DECLARATION_BYTES_V1)?;
        validate_visible_ascii(&self.codecs, "codecs", MAX_MEDIA_DECLARATION_BYTES_V1)
    }

    fn compute_encrypted_content_from_bytes(
        encrypted_segments: &[Vec<u8>],
    ) -> Result<EncryptedContentIdentityV1, ContractError> {
        let mut hasher = CiphertextStreamHasher::new(
            u32::try_from(encrypted_segments.len())
                .map_err(|_| ContractError::FieldTooLong("encrypted_segments"))?,
        );
        for segment in encrypted_segments {
            hasher.push_segment(segment)?;
        }
        hasher.finish()
    }

    fn sum_encrypted_bytes(
        encrypted_segments: &[CencFmp4SegmentIdentityV1],
    ) -> Result<u64, ContractError> {
        encrypted_segments.iter().try_fold(0u64, |acc, segment| {
            acc.checked_add(segment.ciphertext_bytes())
                .ok_or(ContractError::InvalidField("total_encrypted_bytes"))
        })
    }

    fn compute_media_manifest_root(
        encrypted_content: EncryptedContentIdentityV1,
        init_segment_sha256: Digest32,
        init_segment_bytes: u64,
        mime_type: &str,
        codecs: &str,
        encrypted_segments: &[CencFmp4SegmentIdentityV1],
    ) -> Result<Digest32, ContractError> {
        let mut hasher = Sha256::new();
        hasher.update(MEDIA_MANIFEST_ROOT_DOMAIN_V1);
        hasher.update(CENC_FMP4_MEDIA_SUITE_ID_V1.as_bytes());
        hasher.update(
            &encrypted_content
                .canonical_bytes()
                .map_err(|_| ContractError::InvalidField("encrypted_content"))?,
        );
        hasher.update(init_segment_sha256.as_bytes());
        hasher.update(init_segment_bytes.to_be_bytes());
        hasher.update(mime_type.as_bytes());
        hasher.update([0]);
        hasher.update(codecs.as_bytes());
        hasher.update([0]);
        for segment in encrypted_segments {
            hasher.update(
                &segment
                    .canonical_bytes()
                    .map_err(|_| ContractError::InvalidField("encrypted_segments"))?,
            );
        }
        Ok(Digest32::new(hasher.finalize().into()))
    }
}

impl CencFmp4MediaIdentityV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.encrypted_content
            .canonical_bytes()
            .map_err(|_| ContractError::InvalidField("encrypted_content"))?;
        self.validate_mime_and_codecs()?;
        if self.init_segment_bytes == 0 || self.init_segment_bytes > MAX_ENCRYPTED_CONTENT_BYTES {
            return Err(ContractError::InvalidField("init_segment_bytes"));
        }
        if self.encrypted_segments.is_empty()
            || self.encrypted_segments.len() > MAX_MEDIA_SEGMENTS_V1
        {
            return Err(ContractError::InvalidField("encrypted_segments"));
        }
        for segment in &self.encrypted_segments {
            segment.validate()?;
        }
        if self.encrypted_content.ciphertext_bytes()
            != Self::sum_encrypted_bytes(self.encrypted_segments.as_slice())?
        {
            return Err(ContractError::InvalidField("total_encrypted_bytes"));
        }
        if self.media_manifest_root
            != Self::compute_media_manifest_root(
                self.encrypted_content.clone(),
                self.init_segment_sha256,
                self.init_segment_bytes,
                &self.mime_type,
                &self.codecs,
                self.encrypted_segments.as_slice(),
            )?
        {
            return Err(ContractError::InvalidField("media_manifest_root"));
        }
        Ok(())
    }
}

impl CanonicalContract for CencFmp4MediaIdentityV1 {
    fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        let mut bytes = canonical_prefix(CENC_FMP4_MEDIA_IDENTITY_DOMAIN_V1);
        push_string(&mut bytes, CENC_FMP4_MEDIA_SUITE_ID_V1)?;
        push_bytes(
            &mut bytes,
            "encrypted_content",
            &self.encrypted_content.canonical_bytes()?,
        )?;
        bytes.extend_from_slice(self.media_manifest_root.as_bytes());
        bytes.extend_from_slice(self.init_segment_sha256.as_bytes());
        bytes.extend_from_slice(&self.init_segment_bytes.to_be_bytes());
        push_string(&mut bytes, &self.mime_type)?;
        push_string(&mut bytes, &self.codecs)?;
        push_u16(
            &mut bytes,
            u16::try_from(self.encrypted_segments.len())
                .map_err(|_| ContractError::FieldTooLong("encrypted_segments"))?,
        );
        for segment in &self.encrypted_segments {
            push_bytes(&mut bytes, "encrypted_segment", &segment.canonical_bytes()?)?;
        }
        Ok(bytes)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ContractError> {
        let mut cursor = canonical_cursor(bytes, CENC_FMP4_MEDIA_IDENTITY_DOMAIN_V1)?;
        let suite = read_string(
            bytes,
            &mut cursor,
            "suite_id",
            MAX_MEDIA_DECLARATION_BYTES_V1,
        )?;
        if suite != CENC_FMP4_MEDIA_SUITE_ID_V1 {
            return Err(ContractError::InvalidField("suite_id"));
        }
        let encrypted_content = EncryptedContentIdentityV1::from_canonical_bytes(&read_bytes(
            bytes,
            &mut cursor,
            "encrypted_content",
            u16::MAX as usize,
        )?)?;
        let media_manifest_root = Digest32::new(read_fixed_32(bytes, &mut cursor)?);
        let init_segment_sha256 = Digest32::new(read_fixed_32(bytes, &mut cursor)?);
        let init_segment_bytes = read_u64(bytes, &mut cursor)?;
        let mime_type = read_string(
            bytes,
            &mut cursor,
            "mime_type",
            MAX_MEDIA_DECLARATION_BYTES_V1,
        )?;
        let codecs = read_string(bytes, &mut cursor, "codecs", MAX_MEDIA_DECLARATION_BYTES_V1)?;
        let segment_count = usize::from(read_u16(bytes, &mut cursor)?);
        if segment_count == 0 || segment_count > MAX_MEDIA_SEGMENTS_V1 {
            return Err(ContractError::InvalidField("encrypted_segments"));
        }
        let mut encrypted_segments = Vec::with_capacity(segment_count);
        for _ in 0..segment_count {
            encrypted_segments.push(CencFmp4SegmentIdentityV1::from_canonical_bytes(
                &read_bytes(bytes, &mut cursor, "encrypted_segment", u16::MAX as usize)?,
            )?);
        }
        let value = Self::new_recorded(
            encrypted_content,
            media_manifest_root,
            init_segment_sha256,
            init_segment_bytes,
            mime_type,
            codecs,
            encrypted_segments,
        )?;
        finish_canonical(bytes, cursor)?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(ContractError::InvalidField("non-canonical encoding"));
        }
        Ok(value)
    }
}

pub(crate) fn validate_visible_ascii(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), ContractError> {
    if value.is_empty() || value.len() > maximum {
        return Err(ContractError::InvalidField(field));
    }
    if !value
        .as_bytes()
        .iter()
        .all(|byte| matches!(*byte, 0x21..=0x7e))
    {
        return Err(ContractError::InvalidField(field));
    }
    Ok(())
}

pub(crate) fn canonical_prefix(domain: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(domain.len() + 1);
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes
}

pub(crate) fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn push_bytes(
    bytes: &mut Vec<u8>,
    field: &'static str,
    value: &[u8],
) -> Result<(), ContractError> {
    let length = u16::try_from(value.len()).map_err(|_| ContractError::FieldTooLong(field))?;
    push_u16(bytes, length);
    bytes.extend_from_slice(value);
    Ok(())
}

pub(crate) fn push_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), ContractError> {
    push_bytes(bytes, "canonical string", value.as_bytes())
}

pub(crate) fn canonical_cursor(bytes: &[u8], domain: &str) -> Result<usize, ContractError> {
    let prefix = domain.as_bytes();
    if bytes.len() <= prefix.len() || &bytes[..prefix.len()] != prefix || bytes[prefix.len()] != 0 {
        return Err(ContractError::WrongDomain);
    }
    Ok(prefix.len() + 1)
}

fn take_bytes<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], ContractError> {
    let end = cursor
        .checked_add(length)
        .ok_or(ContractError::UnexpectedEnd)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ContractError::UnexpectedEnd)?;
    *cursor = end;
    Ok(value)
}

pub(crate) fn read_fixed_32(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 32], ContractError> {
    take_bytes(bytes, cursor, 32)?
        .try_into()
        .map_err(|_| ContractError::UnexpectedEnd)
}

pub(crate) fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, ContractError> {
    Ok(u16::from_be_bytes(
        take_bytes(bytes, cursor, 2)?
            .try_into()
            .map_err(|_| ContractError::UnexpectedEnd)?,
    ))
}

pub(crate) fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, ContractError> {
    Ok(u64::from_be_bytes(
        take_bytes(bytes, cursor, 8)?
            .try_into()
            .map_err(|_| ContractError::UnexpectedEnd)?,
    ))
}

pub(crate) fn read_bytes(
    bytes: &[u8],
    cursor: &mut usize,
    field: &'static str,
    maximum: usize,
) -> Result<Vec<u8>, ContractError> {
    let length = usize::from(read_u16(bytes, cursor)?);
    if length > maximum {
        return Err(ContractError::FieldTooLong(field));
    }
    Ok(take_bytes(bytes, cursor, length)?.to_vec())
}

pub(crate) fn read_string(
    bytes: &[u8],
    cursor: &mut usize,
    field: &'static str,
    maximum: usize,
) -> Result<String, ContractError> {
    String::from_utf8(read_bytes(bytes, cursor, field, maximum)?)
        .map_err(|_| ContractError::InvalidUtf8(field))
}

pub(crate) fn finish_canonical(bytes: &[u8], cursor: usize) -> Result<(), ContractError> {
    if cursor == bytes.len() {
        Ok(())
    } else {
        Err(ContractError::TrailingBytes)
    }
}

/// Validates a protected init and its segments under `profile`. Under V2 the
/// segments are one rendition's, in order (their content is checked; their
/// authority is the caller's).
pub(crate) fn validate_cenc_fmp4_media_structure_v1(
    init_segment: &[u8],
    encrypted_segments: &[Vec<u8>],
    profile: CencLayoutProfile,
) -> Result<ValidatedCencFmp4MediaLayoutV1, ContractError> {
    validate_cenc_fmp4_media_structure_in(&PROTECTION, init_segment, encrypted_segments, profile)
}

pub(crate) fn validate_cenc_fmp4_media_structure_in(
    ctx: &ProtectionContext<'_>,
    init_segment: &[u8],
    encrypted_segments: &[Vec<u8>],
    profile: CencLayoutProfile,
) -> Result<ValidatedCencFmp4MediaLayoutV1, ContractError> {
    let init = validate_staged_init_segment_in(
        ctx,
        init_segment,
        Digest32::new(Sha256::digest(init_segment).into()),
        init_segment.len() as u64,
        profile,
    )?;
    let expected_segments = encrypted_segments
        .iter()
        .map(|segment| CencFmp4SegmentIdentityV1::new_from_encrypted_bytes(segment))
        .collect::<Result<Vec<_>, _>>()?;
    let mut segments = Vec::with_capacity(encrypted_segments.len());
    for (expected_segment, segment) in expected_segments.iter().zip(encrypted_segments) {
        segments.push(validate_staged_segment_v1(
            expected_segment,
            segment,
            init.protected_track_ids.as_slice(),
            init.segment_rules_v2(),
        )?);
    }
    Ok(ValidatedCencFmp4MediaLayoutV1 {
        init_segment_sha256: Digest32::new(Sha256::digest(init_segment).into()),
        init_segment_bytes: init_segment.len() as u64,
        protected_track_ids: init.protected_track_ids,
        track_rewrites: init.track_rewrites,
        pssh: init.pssh,
        other_pssh: init.other_pssh,
        rendition: init.rendition,
        segments,
    })
}

/// A validated v2 protected init: the one track's rules plus what the clear
/// rewrite needs. The authority for its segments lives in `media_dash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedCencDashInitV2 {
    init_segment_sha256: Digest32,
    init_segment_bytes: u64,
    protected_track_ids: Vec<u32>,
    track_rewrites: Vec<ValidatedCencFmp4TrackRewriteV1>,
    pssh: Option<ValidatedCencFmp4PsshV1>,
    other_pssh: Vec<PsshSpanV2>,
    rendition: ValidatedFmp4RenditionV2,
    rules: CencTrackRulesV2,
}

impl ValidatedCencDashInitV2 {
    pub(crate) fn new_in(
        ctx: &ProtectionContext<'_>,
        protected_init_segment: &[u8],
        expected_sha256: Digest32,
        expected_len: u64,
    ) -> Result<Self, ContractError> {
        let init = validate_staged_init_segment_in(
            ctx,
            protected_init_segment,
            expected_sha256,
            expected_len,
            CencLayoutProfile::V2,
        )?;
        let rules = init
            .segment_rules_v2()
            .ok_or(ContractError::InvalidField("init_segment_bytes"))?;
        let rendition = init
            .rendition
            .ok_or(ContractError::InvalidField("init_segment_bytes"))?;
        Ok(Self {
            init_segment_sha256: expected_sha256,
            init_segment_bytes: expected_len,
            protected_track_ids: init.protected_track_ids,
            track_rewrites: init.track_rewrites,
            pssh: init.pssh,
            other_pssh: init.other_pssh,
            rendition,
            rules,
        })
    }

    pub(crate) const fn rendition(&self) -> &ValidatedFmp4RenditionV2 {
        &self.rendition
    }

    pub(crate) fn content_access_id(&self) -> ContentAccessIdV1 {
        self.track_rewrites
            .first()
            .expect("validated v2 init has one track")
            .content_access_id
    }

    pub(crate) fn protection_header(&self) -> Option<&CustodyProtectionHeader> {
        self.pssh.as_ref().map(|pssh| &pssh.header)
    }

    pub(crate) fn protection_system(&self) -> Option<ProtectionSystemId> {
        self.pssh.as_ref().map(|pssh| pssh.system)
    }

    pub(crate) fn rewrite_clear_init(
        &self,
        protected_init_segment: &[u8],
    ) -> Result<Vec<u8>, ContractError> {
        rewrite_clear_init_v1(
            protected_init_segment,
            self.init_segment_sha256,
            self.init_segment_bytes,
            &self.track_rewrites,
            self.pssh.as_ref(),
            &self.other_pssh,
        )
    }

    /// Validates a segment's content. Its authority (the Merkle proof) is the
    /// caller's.
    pub(crate) fn validate_segment(
        &self,
        encrypted_segment: &[u8],
    ) -> Result<ValidatedCencFmp4SegmentLayoutV1, ContractError> {
        validate_media_segment_v1(
            encrypted_segment,
            self.protected_track_ids.as_slice(),
            Some(self.rules),
        )
    }
}

/// Every `pssh` box of a v2 init, whole and in box order (the MPD lists them).
pub(crate) fn cenc_dash_init_pssh_boxes(init: &[u8]) -> Result<Vec<&[u8]>, ContractError> {
    let top = scan_boxes(init, 0, init.len())?;
    let (moov_off, moov) = top
        .iter()
        .find(|(_, h)| h.box_type == *b"moov")
        .copied()
        .ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let mut boxes = Vec::new();
    for (off, h) in scan_boxes(init, moov_off + moov.header_size, moov_off + moov.size)? {
        if h.box_type == *b"pssh" {
            boxes.push(&init[off..off + h.size]);
        }
    }
    Ok(boxes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedCencFmp4InitRewriteV1 {
    protected_track_ids: Vec<u32>,
    track_rewrites: Vec<ValidatedCencFmp4TrackRewriteV1>,
    pssh: Option<ValidatedCencFmp4PsshV1>,
    /// V2 only: every non-Elastos `pssh` box, in box order.
    other_pssh: Vec<PsshSpanV2>,
    /// `Some` exactly under V2.
    rendition: Option<ValidatedFmp4RenditionV2>,
}

impl ValidatedCencFmp4InitRewriteV1 {
    fn segment_rules_v2(&self) -> Option<CencTrackRulesV2> {
        let rendition = self.rendition?;
        let track = self.track_rewrites.first()?;
        Some(CencTrackRulesV2 {
            track_id: rendition.track_id,
            kind: rendition.kind(),
            iv_size: track.iv_size,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedClearFmp4InitLayoutV1 {
    track_ids: Vec<u32>,
    tracks: Vec<ValidatedClearFmp4TrackLayoutV1>,
    moov_off: usize,
}

fn validate_staged_init_segment_in(
    ctx: &ProtectionContext<'_>,
    protected_init_segment: &[u8],
    expected_sha256: Digest32,
    expected_len: u64,
    profile: CencLayoutProfile,
) -> Result<ValidatedCencFmp4InitRewriteV1, ContractError> {
    verify_exact_source_bytes(
        protected_init_segment,
        expected_sha256,
        expected_len,
        "init_segment_bytes",
    )?;
    validate_init_segment_in(ctx, protected_init_segment, profile)
}

fn validate_staged_segment_v1(
    expected_segment: &CencFmp4SegmentIdentityV1,
    encrypted_segment: &[u8],
    protected_track_ids: &[u32],
    rules_v2: Option<CencTrackRulesV2>,
) -> Result<ValidatedCencFmp4SegmentLayoutV1, ContractError> {
    verify_exact_source_bytes(
        encrypted_segment,
        expected_segment.ciphertext_sha256(),
        expected_segment.ciphertext_bytes(),
        "encrypted_segments",
    )?;
    validate_media_segment_v1(encrypted_segment, protected_track_ids, rules_v2)
}

fn validate_clear_init_segment_v1(
    clear_init_segment: &[u8],
) -> Result<ValidatedClearFmp4InitLayoutV1, ContractError> {
    if clear_init_segment.is_empty()
        || (clear_init_segment.len() as u64) > MAX_ENCRYPTED_CONTENT_BYTES
    {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let top = scan_boxes(clear_init_segment, 0, clear_init_segment.len())?;
    if top.len() != 2 || top[0].1.box_type != *b"ftyp" || top[1].1.box_type != *b"moov" {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let (moov_off, moov_h) = top[1];
    let mut track_ids = Vec::new();
    let mut tracks = Vec::new();
    let mut mvex = None;
    for (off, h) in scan_boxes(
        clear_init_segment,
        moov_off + moov_h.header_size,
        moov_off + moov_h.size,
    )? {
        match &h.box_type {
            b"trak" => {
                let mut track = validate_clear_trak_v1(clear_init_segment, off, h)?;
                if track.track_id == 0 || track_ids.contains(&track.track_id) {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
                track_ids.push(track.track_id);
                track
                    .resize_targets
                    .push(BoxResizeTargetV1 { box_off: moov_off });
                tracks.push(track);
            }
            b"mvex" => {
                if mvex.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
            }
            b"mvhd" | b"udta" | b"iods" | b"meta" => {}
            _ => return Err(ContractError::InvalidField("init_segment_bytes")),
        }
    }
    let (mvex_off, mvex_h) = mvex.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    if track_ids.is_empty() || track_ids.len() > MAX_MEDIA_TRACKS_V1 {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    validate_mvex_v1(
        clear_init_segment,
        mvex_off + mvex_h.header_size,
        mvex_off + mvex_h.size,
        track_ids.as_slice(),
    )?;
    track_ids.sort_unstable();
    tracks.sort_by_key(|track| track.track_id);
    Ok(ValidatedClearFmp4InitLayoutV1 {
        track_ids,
        tracks,
        moov_off,
    })
}

fn rewrite_clear_init_v1(
    protected_init_segment: &[u8],
    expected_sha256: Digest32,
    expected_len: u64,
    track_rewrites: &[ValidatedCencFmp4TrackRewriteV1],
    pssh: Option<&ValidatedCencFmp4PsshV1>,
    other_pssh: &[PsshSpanV2],
) -> Result<Vec<u8>, ContractError> {
    verify_exact_source_bytes(
        protected_init_segment,
        expected_sha256,
        expected_len,
        "init_segment_bytes",
    )?;
    rewrite_clear_init_unchecked_v1(protected_init_segment, track_rewrites, pssh, other_pssh)
}

fn rewrite_protected_init_v1(
    clear_init_segment: &[u8],
    clear_tracks: &[ValidatedClearFmp4TrackLayoutV1],
    moov_off: usize,
    pssh_boxes: &[Vec<u8>],
    header: &CustodyProtectionHeader,
) -> Result<Vec<u8>, ContractError> {
    if clear_init_segment.is_empty() {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let key_id = *header.content_access_id().as_bytes();
    let mut rewritten = clear_init_segment.to_vec();
    let mut ordered_tracks = clear_tracks.to_vec();
    ordered_tracks.sort_by_key(|track| std::cmp::Reverse(track.sample_entry_off));
    for track in ordered_tracks {
        let protected_fourcc = protected_sample_entry_fourcc_v1(track.original_fourcc)?;
        let sinf = make_protected_sinf_v1(track.original_fourcc, key_id)?;
        let sample_entry_size = read_box_header(&rewritten, track.sample_entry_off)?.size;
        grow_box_size_in_place(
            &mut rewritten,
            track.sample_entry_off,
            sinf.len(),
            "init_segment_bytes",
        )?;
        for target in &track.resize_targets {
            grow_box_size_in_place(
                &mut rewritten,
                target.box_off,
                sinf.len(),
                "init_segment_bytes",
            )?;
        }
        let sample_entry_type = track
            .sample_entry_off
            .checked_add(4)
            .ok_or(ContractError::InvalidField("init_segment_bytes"))?;
        let sample_entry_type_end = sample_entry_type
            .checked_add(4)
            .ok_or(ContractError::InvalidField("init_segment_bytes"))?;
        rewritten
            .get_mut(sample_entry_type..sample_entry_type_end)
            .ok_or(ContractError::InvalidField("init_segment_bytes"))?
            .copy_from_slice(&protected_fourcc);
        let insert_at = track
            .sample_entry_off
            .checked_add(sample_entry_size)
            .ok_or(ContractError::InvalidField("init_segment_bytes"))?;
        rewritten.splice(insert_at..insert_at, sinf);
    }
    // `moov` is the last top-level box of an init segment, so appending the `pssh`
    // boxes to the buffer appends them as `moov`'s last children, in order. Growing
    // the header after the bytes are in place keeps the declared size and the
    // buffer length in step.
    for pssh in pssh_boxes {
        rewritten.extend_from_slice(pssh);
        grow_box_size_in_place(&mut rewritten, moov_off, pssh.len(), "init_segment_bytes")?;
    }
    Ok(rewritten)
}

fn rewrite_clear_init_unchecked_v1(
    protected_init_segment: &[u8],
    track_rewrites: &[ValidatedCencFmp4TrackRewriteV1],
    pssh: Option<&ValidatedCencFmp4PsshV1>,
    other_pssh: &[PsshSpanV2],
) -> Result<Vec<u8>, ContractError> {
    enum Removal<'a> {
        Pssh {
            moov_off: usize,
            off: usize,
            size: usize,
        },
        Sinf(&'a ValidatedCencFmp4TrackRewriteV1),
    }
    impl Removal<'_> {
        fn off(&self) -> usize {
            match self {
                Self::Pssh { off, .. } => *off,
                Self::Sinf(rewrite) => rewrite.sinf_off,
            }
        }
    }
    let mut removals: Vec<Removal<'_>> = pssh
        .map(|pssh| Removal::Pssh {
            moov_off: pssh.moov_off,
            off: pssh.pssh_off,
            size: pssh.pssh_size,
        })
        .into_iter()
        .chain(other_pssh.iter().map(|span| Removal::Pssh {
            moov_off: span.moov_off,
            off: span.pssh_off,
            size: span.pssh_size,
        }))
        .chain(track_rewrites.iter().map(Removal::Sinf))
        .collect();
    // Taken out from the highest offset down, so every box still to be removed
    // sits at a lower offset and does not move. Under V1 the one `pssh` is
    // `moov`'s last child, so it goes first, as it always has.
    removals.sort_by_key(|removal| std::cmp::Reverse(removal.off()));
    let mut rewritten = protected_init_segment.to_vec();
    for removal in removals {
        match removal {
            Removal::Pssh {
                moov_off,
                off,
                size,
            } => {
                let pssh_end = off
                    .checked_add(size)
                    .ok_or(ContractError::InvalidField("init_segment_bytes"))?;
                if pssh_end > rewritten.len() {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
                shrink_box_size_in_place(&mut rewritten, moov_off, size, "init_segment_bytes")?;
                rewritten.drain(off..pssh_end);
            }
            Removal::Sinf(rewrite) => {
                let sample_entry_type = rewrite
                    .sample_entry_off
                    .checked_add(4)
                    .ok_or(ContractError::InvalidField("init_segment_bytes"))?;
                let sample_entry_type_end = sample_entry_type
                    .checked_add(4)
                    .ok_or(ContractError::InvalidField("init_segment_bytes"))?;
                rewritten
                    .get_mut(sample_entry_type..sample_entry_type_end)
                    .ok_or(ContractError::InvalidField("init_segment_bytes"))?
                    .copy_from_slice(&rewrite.original_fourcc);
                shrink_box_size_in_place(
                    &mut rewritten,
                    rewrite.sample_entry_off,
                    rewrite.sinf_size,
                    "init_segment_bytes",
                )?;
                for target in &rewrite.resize_targets {
                    shrink_box_size_in_place(
                        &mut rewritten,
                        target.box_off,
                        rewrite.sinf_size,
                        "init_segment_bytes",
                    )?;
                }
                let sinf_end = rewrite
                    .sinf_off
                    .checked_add(rewrite.sinf_size)
                    .ok_or(ContractError::InvalidField("init_segment_bytes"))?;
                if sinf_end > rewritten.len() {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
                rewritten.drain(rewrite.sinf_off..sinf_end);
            }
        }
    }
    Ok(rewritten)
}

fn validate_init_segment_in(
    ctx: &ProtectionContext<'_>,
    bytes: &[u8],
    profile: CencLayoutProfile,
) -> Result<ValidatedCencFmp4InitRewriteV1, ContractError> {
    if bytes.is_empty() || (bytes.len() as u64) > MAX_ENCRYPTED_CONTENT_BYTES {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let top = scan_boxes(bytes, 0, bytes.len())?;
    if top.len() != 2 || top[0].1.box_type != *b"ftyp" || top[1].1.box_type != *b"moov" {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let (moov_off, moov_h) = top[1];
    let mut protected_track_ids = Vec::new();
    let mut track_rewrites = Vec::new();
    let mut mvex = None;
    let mut pssh = None;
    let mut pssh_boxes_v2 = Vec::new();
    for (off, h) in scan_boxes(bytes, moov_off + moov_h.header_size, moov_off + moov_h.size)? {
        match &h.box_type {
            b"trak" => {
                let mut rewrite = validate_trak_v1(bytes, off, h)?;
                if rewrite.track_id == 0 || protected_track_ids.contains(&rewrite.track_id) {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
                if profile == CencLayoutProfile::V1
                    && rewrite.iv_size != SUPPORTED_COMMON_IV_SIZE_V1
                {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
                protected_track_ids.push(rewrite.track_id);
                rewrite
                    .resize_targets
                    .push(BoxResizeTargetV1 { box_off: moov_off });
                track_rewrites.push(rewrite);
            }
            b"mvex" => {
                if mvex.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
            }
            // The ONE admitted exception to the strict `moov` child allowlist, and
            // it is admitted only after it parses as this scheme's own CENC
            // protection header. A second one, a foreign system id, a malformed box
            // or an unreadable payload all fall through to the error below.
            //
            // V2 instead admits any number of `pssh` boxes anywhere among the
            // `moov` children; `validate_pssh_set_v2` applies its rules below.
            b"pssh" => match profile {
                CencLayoutProfile::V1 => {
                    if pssh.replace((off, h)).is_some() {
                        return Err(ContractError::InvalidField("init_segment_bytes"));
                    }
                }
                CencLayoutProfile::V2 => pssh_boxes_v2.push((off, h)),
            },
            b"mvhd" | b"udta" | b"iods" | b"meta" => {}
            _ => return Err(ContractError::InvalidField("init_segment_bytes")),
        }
    }
    let (mvex_off, mvex_h) = mvex.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    if protected_track_ids.is_empty() || protected_track_ids.len() > MAX_MEDIA_TRACKS_V1 {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    if profile == CencLayoutProfile::V2 && protected_track_ids.len() != 1 {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let expected_access_id = track_rewrites
        .first()
        .ok_or(ContractError::InvalidField("init_segment_bytes"))?
        .content_access_id;
    if track_rewrites
        .iter()
        .any(|rewrite| rewrite.content_access_id != expected_access_id)
    {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    validate_mvex_v1(
        bytes,
        mvex_off + mvex_h.header_size,
        mvex_off + mvex_h.size,
        protected_track_ids.as_slice(),
    )?;
    let (pssh, other_pssh, rendition) = match profile {
        CencLayoutProfile::V1 => (
            pssh.map(|(off, h)| {
                validate_pssh_v1(ctx, bytes, moov_off, moov_h, off, h, expected_access_id)
            })
            .transpose()?,
            Vec::new(),
            None,
        ),
        CencLayoutProfile::V2 => {
            let (pssh, other_pssh) =
                validate_pssh_set_v2(ctx, bytes, moov_off, &pssh_boxes_v2, expected_access_id)?;
            (
                pssh,
                other_pssh,
                Some(parse_rendition_v2(bytes, moov_off, true)?),
            )
        }
    };
    protected_track_ids.sort_unstable();
    track_rewrites.sort_by_key(|rewrite| rewrite.track_id);
    Ok(ValidatedCencFmp4InitRewriteV1 {
        protected_track_ids,
        track_rewrites,
        pssh,
        other_pssh,
        rendition,
    })
}

/// V2 `pssh` rules (spec §7): every box is a well-formed v0/v1 box within
/// [`MAX_PSSH_BOX_BYTES_V2`] and all of them together within
/// [`MAX_INIT_PSSH_BYTES_V2`]; at most one is the Elastos box, which must declare
/// [`CENC_DASH_MEDIA_SUITE_ID_V2`] and be bound to the tracks' KID; a v1 Common
/// box must list the KID; any other system's box is kept opaque.
fn validate_pssh_set_v2(
    ctx: &ProtectionContext<'_>,
    data: &[u8],
    moov_off: usize,
    boxes: &[(usize, BoxHeader)],
    expected_access_id: ContentAccessIdV1,
) -> Result<(Option<ValidatedCencFmp4PsshV1>, Vec<PsshSpanV2>), ContractError> {
    const ERR: ContractError = ContractError::InvalidField("init_segment_bytes");
    let mut total = 0usize;
    let mut elastos = None;
    let mut others = Vec::new();
    for &(pssh_off, pssh_h) in boxes {
        total = total.checked_add(pssh_h.size).ok_or(ERR)?;
        if total > MAX_INIT_PSSH_BYTES_V2 {
            return Err(ERR);
        }
        let bytes = slice_at(data, pssh_off, pssh_h.size)?;
        match classify_pssh_v2(ctx, bytes, expected_access_id)? {
            Some((system, header)) => {
                let validated = ValidatedCencFmp4PsshV1 {
                    system,
                    header,
                    moov_off,
                    pssh_off,
                    pssh_size: pssh_h.size,
                };
                if elastos.replace(validated).is_some() {
                    return Err(ERR);
                }
            }
            None => others.push(PsshSpanV2 {
                moov_off,
                pssh_off,
                pssh_size: pssh_h.size,
            }),
        }
    }
    Ok((elastos, others))
}

/// Parses one complete `pssh` box (v0 or v1, nothing after it, 32-bit size,
/// within [`MAX_PSSH_BOX_BYTES_V2`]).
fn parse_exact_pssh_v2(bytes: &[u8]) -> Result<(u8, crate::pssh::PsshBoxV1), ContractError> {
    const ERR: ContractError = ContractError::InvalidField("pssh_box");
    if bytes.len() > MAX_PSSH_BOX_BYTES_V2 || read_u32_at(bytes, 0)? as usize != bytes.len() {
        return Err(ERR);
    }
    parse_pssh_v0_or_v1(bytes).ok_or(ERR)
}

/// `Some((system, header))` for the custody box, `None` for any other well-formed
/// box (the Common box is checked against the KID, a foreign box is opaque).
fn classify_pssh_v2(
    ctx: &ProtectionContext<'_>,
    bytes: &[u8],
    expected_access_id: ContentAccessIdV1,
) -> Result<Option<(ProtectionSystemId, CustodyProtectionHeader)>, ContractError> {
    const ERR: ContractError = ContractError::InvalidField("init_segment_bytes");
    let (version, parsed) = parse_exact_pssh_v2(bytes)?;
    match ctx.registry().classify(&parsed.system_id) {
        ProtectionClass::Custody(_) => {
            let (system, header) = ctx.registry().decode_custody(bytes)?;
            if header.media_suite() != CencMediaSuite::DashV2
                || header.content_access_id() != expected_access_id
            {
                return Err(ERR);
            }
            Ok(Some((system, header)))
        }
        ProtectionClass::Common(common) => {
            common.check_kid_list(version, &parsed, expected_access_id.as_bytes())?;
            Ok(None)
        }
        ProtectionClass::Foreign => Ok(None),
    }
}

/// Admit a `pssh` child of `moov` only when it is this scheme's own, well formed,
/// and bound to the same content access id the tracks declare.
///
/// Four separate checks, each of which alone rejects a box that is not ours: the
/// box must be the last `moov` child (the layout the read path removes), it must
/// be a registered custody system's, its payload must decode, and its single KID
/// must be the `tenc` default KID of every track.
fn validate_pssh_v1(
    ctx: &ProtectionContext<'_>,
    data: &[u8],
    moov_off: usize,
    moov_h: BoxHeader,
    pssh_off: usize,
    pssh_h: BoxHeader,
    expected_access_id: ContentAccessIdV1,
) -> Result<ValidatedCencFmp4PsshV1, ContractError> {
    let pssh_end = pssh_off
        .checked_add(pssh_h.size)
        .ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    if pssh_end != moov_off + moov_h.size {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let (system, header) = ctx
        .registry()
        .decode_custody(slice_at(data, pssh_off, pssh_h.size)?)?;
    // The header type admits both suites; V1 media pins its own.
    if header.media_suite() != CencMediaSuite::Fmp4V1 {
        return Err(ContractError::InvalidField("pssh_content_encryption"));
    }
    if header.content_access_id() != expected_access_id {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    Ok(ValidatedCencFmp4PsshV1 {
        system,
        header,
        moov_off,
        pssh_off,
        pssh_size: pssh_h.size,
    })
}

fn validate_mvex_v1(
    data: &[u8],
    start: usize,
    end: usize,
    protected_track_ids: &[u32],
) -> Result<(), ContractError> {
    let mut trex_track_ids = Vec::new();
    for (off, h) in scan_boxes(data, start, end)? {
        match &h.box_type {
            b"trex" => {
                let content = off + h.header_size;
                let (version, flags) = read_fullbox_header(data, content)?;
                if version != 0 || flags != 0 || h.size != h.header_size + 24 {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
                let track_id = read_u32_at(data, content + 4)?;
                if track_id == 0 || trex_track_ids.contains(&track_id) {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
                trex_track_ids.push(track_id);
            }
            b"mehd" => {}
            _ => return Err(ContractError::InvalidField("init_segment_bytes")),
        }
    }
    trex_track_ids.sort_unstable();
    if trex_track_ids != protected_track_ids {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    Ok(())
}

fn validate_trak_v1(
    data: &[u8],
    trak_off: usize,
    trak_h: BoxHeader,
) -> Result<ValidatedCencFmp4TrackRewriteV1, ContractError> {
    let mut tkhd = None;
    let mut mdia = None;
    for (off, h) in scan_boxes(data, trak_off + trak_h.header_size, trak_off + trak_h.size)? {
        match &h.box_type {
            b"tkhd" => {
                if tkhd.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
            }
            b"mdia" => {
                if mdia.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
            }
            _ => {}
        }
    }
    let (tkhd_off, tkhd_h) = tkhd.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let (mdia_off, mdia_h) = mdia.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let track_id = parse_tkhd_track_id(data, tkhd_off, tkhd_h)?;
    let mut rewrite = validate_mdia_v1(data, mdia_off, mdia_h)?;
    rewrite.track_id = track_id;
    rewrite
        .resize_targets
        .push(BoxResizeTargetV1 { box_off: trak_off });
    Ok(rewrite)
}

fn validate_clear_trak_v1(
    data: &[u8],
    trak_off: usize,
    trak_h: BoxHeader,
) -> Result<ValidatedClearFmp4TrackLayoutV1, ContractError> {
    let mut tkhd = None;
    let mut mdia = None;
    for (off, h) in scan_boxes(data, trak_off + trak_h.header_size, trak_off + trak_h.size)? {
        match &h.box_type {
            b"tkhd" => {
                if tkhd.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
            }
            b"mdia" => {
                if mdia.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
            }
            _ => {}
        }
    }
    let (tkhd_off, tkhd_h) = tkhd.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let (mdia_off, mdia_h) = mdia.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let track_id = parse_tkhd_track_id(data, tkhd_off, tkhd_h)?;
    let mut track = validate_clear_mdia_v1(data, mdia_off, mdia_h)?;
    track.track_id = track_id;
    track
        .resize_targets
        .push(BoxResizeTargetV1 { box_off: trak_off });
    Ok(track)
}

fn validate_mdia_v1(
    data: &[u8],
    mdia_off: usize,
    mdia_h: BoxHeader,
) -> Result<ValidatedCencFmp4TrackRewriteV1, ContractError> {
    let mut handler_type = None;
    let mut minf = None;
    for (off, h) in scan_boxes(data, mdia_off + mdia_h.header_size, mdia_off + mdia_h.size)? {
        match &h.box_type {
            b"hdlr" => {
                if handler_type.is_some() {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
                handler_type = Some(parse_hdlr_type(data, off, h)?);
            }
            b"minf" => {
                if minf.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
            }
            _ => {}
        }
    }
    let handler_type = handler_type.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let (minf_off, minf_h) = minf.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let mut rewrite = validate_minf_v1(data, minf_off, minf_h, handler_type)?;
    rewrite
        .resize_targets
        .push(BoxResizeTargetV1 { box_off: mdia_off });
    Ok(rewrite)
}

fn validate_clear_mdia_v1(
    data: &[u8],
    mdia_off: usize,
    mdia_h: BoxHeader,
) -> Result<ValidatedClearFmp4TrackLayoutV1, ContractError> {
    let mut handler_type = None;
    let mut minf = None;
    for (off, h) in scan_boxes(data, mdia_off + mdia_h.header_size, mdia_off + mdia_h.size)? {
        match &h.box_type {
            b"hdlr" => {
                if handler_type.is_some() {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
                handler_type = Some(parse_hdlr_type(data, off, h)?);
            }
            b"minf" => {
                if minf.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
            }
            _ => {}
        }
    }
    let handler_type = handler_type.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let (minf_off, minf_h) = minf.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let mut track = validate_clear_minf_v1(data, minf_off, minf_h, handler_type)?;
    track
        .resize_targets
        .push(BoxResizeTargetV1 { box_off: mdia_off });
    Ok(track)
}

fn validate_minf_v1(
    data: &[u8],
    minf_off: usize,
    minf_h: BoxHeader,
    handler_type: [u8; 4],
) -> Result<ValidatedCencFmp4TrackRewriteV1, ContractError> {
    let mut stbl = None;
    for (off, h) in scan_boxes(data, minf_off + minf_h.header_size, minf_off + minf_h.size)? {
        if &h.box_type == b"stbl" && stbl.replace((off, h)).is_some() {
            return Err(ContractError::InvalidField("init_segment_bytes"));
        }
    }
    let (stbl_off, stbl_h) = stbl.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let mut rewrite = validate_stbl_v1(data, stbl_off, stbl_h, handler_type)?;
    rewrite
        .resize_targets
        .push(BoxResizeTargetV1 { box_off: minf_off });
    Ok(rewrite)
}

fn validate_clear_minf_v1(
    data: &[u8],
    minf_off: usize,
    minf_h: BoxHeader,
    handler_type: [u8; 4],
) -> Result<ValidatedClearFmp4TrackLayoutV1, ContractError> {
    let mut stbl = None;
    for (off, h) in scan_boxes(data, minf_off + minf_h.header_size, minf_off + minf_h.size)? {
        if &h.box_type == b"stbl" && stbl.replace((off, h)).is_some() {
            return Err(ContractError::InvalidField("init_segment_bytes"));
        }
    }
    let (stbl_off, stbl_h) = stbl.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let mut track = validate_clear_stbl_v1(data, stbl_off, stbl_h, handler_type)?;
    track
        .resize_targets
        .push(BoxResizeTargetV1 { box_off: minf_off });
    Ok(track)
}

fn validate_stbl_v1(
    data: &[u8],
    stbl_off: usize,
    stbl_h: BoxHeader,
    handler_type: [u8; 4],
) -> Result<ValidatedCencFmp4TrackRewriteV1, ContractError> {
    let mut stsd = None;
    for (off, h) in scan_boxes(data, stbl_off + stbl_h.header_size, stbl_off + stbl_h.size)? {
        if &h.box_type == b"stsd" && stsd.replace((off, h)).is_some() {
            return Err(ContractError::InvalidField("init_segment_bytes"));
        }
    }
    let (stsd_off, stsd_h) = stsd.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let mut rewrite = validate_stsd_v1(data, stsd_off, stsd_h, handler_type)?;
    rewrite
        .resize_targets
        .push(BoxResizeTargetV1 { box_off: stbl_off });
    Ok(rewrite)
}

fn validate_clear_stbl_v1(
    data: &[u8],
    stbl_off: usize,
    stbl_h: BoxHeader,
    handler_type: [u8; 4],
) -> Result<ValidatedClearFmp4TrackLayoutV1, ContractError> {
    let mut stsd = None;
    for (off, h) in scan_boxes(data, stbl_off + stbl_h.header_size, stbl_off + stbl_h.size)? {
        if &h.box_type == b"stsd" && stsd.replace((off, h)).is_some() {
            return Err(ContractError::InvalidField("init_segment_bytes"));
        }
    }
    let (stsd_off, stsd_h) = stsd.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let mut track = validate_clear_stsd_v1(data, stsd_off, stsd_h, handler_type)?;
    track
        .resize_targets
        .push(BoxResizeTargetV1 { box_off: stbl_off });
    Ok(track)
}

fn validate_stsd_v1(
    data: &[u8],
    stsd_off: usize,
    stsd_h: BoxHeader,
    handler_type: [u8; 4],
) -> Result<ValidatedCencFmp4TrackRewriteV1, ContractError> {
    let content = stsd_off + stsd_h.header_size;
    if stsd_h.size < stsd_h.header_size + 16 || read_u32_at(data, content + 4)? != 1 {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let entry_off = content + 8;
    let entry_h = read_box_header(data, entry_off)?;
    if entry_off + entry_h.size != stsd_off + stsd_h.size {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let (fixed, expected_original_fourcc) = match (&handler_type, &entry_h.box_type) {
        (b"vide", b"encv") => (VISUAL_SAMPLE_ENTRY_FIXED_BYTES, *b"avc1"),
        (b"soun", b"enca") => (AUDIO_SAMPLE_ENTRY_FIXED_BYTES, *b"mp4a"),
        _ => return Err(ContractError::InvalidField("init_segment_bytes")),
    };
    let entry_content_start = entry_off + entry_h.header_size;
    let child_start = entry_content_start
        .checked_add(fixed)
        .ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    if child_start > entry_off + entry_h.size {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let mut sinf = None;
    for (off, h) in scan_boxes(data, child_start, entry_off + entry_h.size)? {
        if &h.box_type == b"sinf" && sinf.replace((off, h)).is_some() {
            return Err(ContractError::InvalidField("init_segment_bytes"));
        }
    }
    let (sinf_off, sinf_h) = sinf.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let (content_access_id, iv_size) =
        validate_sinf_v1(data, sinf_off, sinf_h, expected_original_fourcc)?;
    Ok(ValidatedCencFmp4TrackRewriteV1 {
        track_id: 0,
        content_access_id,
        iv_size,
        sample_entry_off: entry_off,
        original_fourcc: expected_original_fourcc,
        sinf_off,
        sinf_size: sinf_h.size,
        resize_targets: vec![BoxResizeTargetV1 { box_off: stsd_off }],
    })
}

fn validate_sinf_v1(
    data: &[u8],
    sinf_off: usize,
    sinf_h: BoxHeader,
    expected_original_fourcc: [u8; 4],
) -> Result<(ContentAccessIdV1, u8), ContractError> {
    let mut frma = None;
    let mut schm = None;
    let mut schi = None;
    for (off, h) in scan_boxes(data, sinf_off + sinf_h.header_size, sinf_off + sinf_h.size)? {
        match &h.box_type {
            b"frma" => {
                if frma.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
            }
            b"schm" => {
                if schm.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
            }
            b"schi" => {
                if schi.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("init_segment_bytes"));
                }
            }
            _ => return Err(ContractError::InvalidField("init_segment_bytes")),
        }
    }
    let (frma_off, frma_h) = frma.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let (schm_off, schm_h) = schm.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    let (schi_off, schi_h) = schi.ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    if frma_h.size != 12
        || slice_at(data, frma_off + frma_h.header_size, 4)? != expected_original_fourcc.as_slice()
    {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let schm_content = schm_off + schm_h.header_size;
    let (schm_version, schm_flags) = read_fullbox_header(data, schm_content)?;
    if schm_h.size != schm_h.header_size + 12
        || schm_version != 0
        || schm_flags != 0
        || &data[schm_content + 4..schm_content + 8] != b"cenc"
    {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let schi_boxes = scan_boxes(data, schi_off + schi_h.header_size, schi_off + schi_h.size)?;
    if schi_boxes.len() != 1 || schi_boxes[0].1.box_type != *b"tenc" {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let (tenc_off, tenc_h) = schi_boxes[0];
    let content = tenc_off + tenc_h.header_size;
    let (tenc_version, tenc_flags) = read_fullbox_header(data, content)?;
    if tenc_h.size != tenc_h.header_size + 24 || tenc_version != 0 || tenc_flags != 0 {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    // The IV size is returned rather than pinned here: V1 requires 8 and V2
    // accepts 8 or 16, and the caller applies its profile's rule.
    let iv_size = data[content + 7];
    if data[content + 6] != 1
        || (iv_size != SUPPORTED_COMMON_IV_SIZE_V1 && iv_size != SUPPORTED_LARGE_IV_SIZE_V2)
    {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    Ok((
        ContentAccessIdV1::new(
            slice_at(data, content + 8, 16)?
                .try_into()
                .map_err(|_| ContractError::InvalidField("init_segment_bytes"))?,
        )?,
        iv_size,
    ))
}

fn validate_clear_stsd_v1(
    data: &[u8],
    stsd_off: usize,
    stsd_h: BoxHeader,
    handler_type: [u8; 4],
) -> Result<ValidatedClearFmp4TrackLayoutV1, ContractError> {
    let content = stsd_off + stsd_h.header_size;
    if stsd_h.size < stsd_h.header_size + 16 || read_u32_at(data, content + 4)? != 1 {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let entry_off = content + 8;
    let entry_h = read_box_header(data, entry_off)?;
    if entry_off + entry_h.size != stsd_off + stsd_h.size {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let (fixed, original_fourcc) = match (&handler_type, &entry_h.box_type) {
        (b"vide", b"avc1") => (VISUAL_SAMPLE_ENTRY_FIXED_BYTES, *b"avc1"),
        (b"soun", b"mp4a") => (AUDIO_SAMPLE_ENTRY_FIXED_BYTES, *b"mp4a"),
        _ => return Err(ContractError::InvalidField("init_segment_bytes")),
    };
    let entry_content_start = entry_off + entry_h.header_size;
    let child_start = entry_content_start
        .checked_add(fixed)
        .ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    if child_start > entry_off + entry_h.size {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    // A real sample entry carries its codec configuration as child boxes
    // (`avcC` is mandatory for AVC; encoders also add `colr`, `pasp`, `btrt`,
    // `esds` for AAC). They must scan cleanly and are preserved verbatim by
    // the protect rewrite, which appends `sinf` after them; a clear entry
    // that already carries `sinf` is not clear and is rejected.
    if scan_boxes(data, child_start, entry_off + entry_h.size)?
        .iter()
        .any(|(_, h)| h.box_type == *b"sinf")
    {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    Ok(ValidatedClearFmp4TrackLayoutV1 {
        track_id: 0,
        sample_entry_off: entry_off,
        original_fourcc,
        resize_targets: vec![BoxResizeTargetV1 { box_off: stsd_off }],
    })
}

fn validate_media_segment_v1(
    segment: &[u8],
    protected_track_ids: &[u32],
    rules_v2: Option<CencTrackRulesV2>,
) -> Result<ValidatedCencFmp4SegmentLayoutV1, ContractError> {
    if segment.is_empty() || (segment.len() as u64) > MAX_ENCRYPTED_CONTENT_BYTES {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let top = scan_boxes(segment, 0, segment.len())?;
    if top.len() != 2 || top[0].1.box_type != *b"moof" || top[1].1.box_type != *b"mdat" {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let (moof_off, moof_h) = top[0];
    let (mdat_off, mdat_h) = top[1];
    if moof_off != 0 {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    if moof_off + moof_h.size != mdat_off || mdat_off + mdat_h.size != segment.len() {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let moof_children = scan_boxes(
        segment,
        moof_off + moof_h.header_size,
        moof_off + moof_h.size,
    )?;
    let mfhds: Vec<_> = moof_children
        .iter()
        .copied()
        .filter(|(_, h)| h.box_type == *b"mfhd")
        .collect();
    let trafs: Vec<_> = moof_children
        .iter()
        .copied()
        .filter(|(_, h)| h.box_type == *b"traf")
        .collect();
    if mfhds.len() != 1 || trafs.len() != 1 {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    if moof_children
        .iter()
        .any(|(_, h)| h.box_type != *b"mfhd" && h.box_type != *b"traf")
    {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    validate_mfhd_v1(segment, mfhds[0].0, mfhds[0].1)?;
    let mdat_content_start = mdat_off + mdat_h.header_size;
    let mdat_content_end = mdat_off + mdat_h.size;
    let mut layout = match rules_v2 {
        None => validate_traf_v1(
            segment,
            trafs[0].0,
            trafs[0].1,
            moof_off,
            mdat_content_start,
            mdat_content_end,
        )?,
        Some(rules) => validate_traf_v2(
            segment,
            trafs[0].0,
            trafs[0].1,
            moof_off,
            mdat_content_start,
            mdat_content_end,
            rules,
        )?,
    };
    if protected_track_ids.binary_search(&layout.track_id).is_err() {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let total = layout.samples.iter().try_fold(0usize, |acc, sample| {
        let start = usize::try_from(sample.ciphertext_offset)
            .map_err(|_| ContractError::InvalidField("encrypted_segments"))?;
        let end = start
            .checked_add(sample.sample_size as usize)
            .ok_or(ContractError::InvalidField("encrypted_segments"))?;
        if start != acc {
            return Err(ContractError::InvalidField("encrypted_segments"));
        }
        Ok(end)
    })?;
    if total != mdat_content_end - mdat_content_start {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    layout.source_sha256 = Digest32::new(Sha256::digest(segment).into());
    layout.source_bytes = segment.len() as u64;
    Ok(layout)
}

fn validate_clear_media_segment_v1(
    segment: &[u8],
    clear_track_ids: &[u32],
    kind_v2: Option<CencDashRenditionKindV2>,
) -> Result<ValidatedClearFmp4SegmentLayoutV1, ContractError> {
    if segment.is_empty() || (segment.len() as u64) > MAX_ENCRYPTED_CONTENT_BYTES {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let top = scan_boxes(segment, 0, segment.len())?;
    if top.len() != 2 || top[0].1.box_type != *b"moof" || top[1].1.box_type != *b"mdat" {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let (moof_off, moof_h) = top[0];
    let (mdat_off, mdat_h) = top[1];
    if moof_off != 0 {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    if moof_off + moof_h.size != mdat_off || mdat_off + mdat_h.size != segment.len() {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let moof_children = scan_boxes(
        segment,
        moof_off + moof_h.header_size,
        moof_off + moof_h.size,
    )?;
    let mfhds: Vec<_> = moof_children
        .iter()
        .copied()
        .filter(|(_, h)| h.box_type == *b"mfhd")
        .collect();
    let trafs: Vec<_> = moof_children
        .iter()
        .copied()
        .filter(|(_, h)| h.box_type == *b"traf")
        .collect();
    if mfhds.len() != 1 || trafs.len() != 1 {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    if moof_children
        .iter()
        .any(|(_, h)| h.box_type != *b"mfhd" && h.box_type != *b"traf")
    {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    validate_mfhd_v1(segment, mfhds[0].0, mfhds[0].1)?;
    let mut layout = match kind_v2 {
        None => validate_clear_traf_v1(
            segment,
            trafs[0].0,
            trafs[0].1,
            mdat_off + mdat_h.header_size,
            mdat_off + mdat_h.size,
        )?,
        Some(kind) => validate_clear_traf_v2(
            segment,
            trafs[0].0,
            trafs[0].1,
            mdat_off + mdat_h.header_size,
            mdat_off + mdat_h.size,
            kind,
        )?,
    };
    if clear_track_ids.binary_search(&layout.track_id).is_err() {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    layout.source_sha256 = Digest32::new(Sha256::digest(segment).into());
    layout.source_bytes = segment.len() as u64;
    Ok(layout)
}

fn validate_clear_traf_v1(
    data: &[u8],
    traf_off: usize,
    traf_h: BoxHeader,
    mdat_content_start: usize,
    mdat_content_end: usize,
) -> Result<ValidatedClearFmp4SegmentLayoutV1, ContractError> {
    let mut tfhd = None;
    let mut trun = None;
    let mut saw_tfdt = false;
    for (off, h) in scan_boxes(data, traf_off + traf_h.header_size, traf_off + traf_h.size)? {
        match &h.box_type {
            b"tfhd" => {
                if tfhd.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("encrypted_segments"));
                }
            }
            b"trun" => {
                if trun.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("encrypted_segments"));
                }
            }
            b"tfdt" => {
                if saw_tfdt {
                    return Err(ContractError::InvalidField("encrypted_segments"));
                }
                saw_tfdt = true;
                validate_tfdt_v1(data, off, h)?;
            }
            _ => return Err(ContractError::InvalidField("encrypted_segments")),
        }
    }
    let (tfhd_off, tfhd_h) = tfhd.ok_or(ContractError::InvalidField("encrypted_segments"))?;
    let (trun_off, trun_h) = trun.ok_or(ContractError::InvalidField("encrypted_segments"))?;
    let track_id = parse_tfhd_track_id(data, tfhd_off, tfhd_h)?;
    let trun = parse_trun_layout(data, trun_off, trun_h, CencLayoutProfile::V1)?;
    let sample_start = usize::try_from(trun.data_offset)
        .map_err(|_| ContractError::InvalidField("encrypted_segments"))?;
    if sample_start < mdat_content_start || sample_start > mdat_content_end {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let mut cursor = sample_start;
    let mut samples = Vec::with_capacity(trun.sample_sizes.len());
    for size in trun.sample_sizes {
        let end = cursor
            .checked_add(size as usize)
            .ok_or(ContractError::InvalidField("encrypted_segments"))?;
        if end > mdat_content_end {
            return Err(ContractError::InvalidField("encrypted_segments"));
        }
        samples.push(ValidatedClearFmp4SampleLayoutV1 {
            mdat_offset: (cursor - mdat_content_start) as u64,
            sample_size: size,
        });
        cursor = end;
    }
    if cursor != mdat_content_end {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    Ok(ValidatedClearFmp4SegmentLayoutV1 {
        source_sha256: Digest32::new([0u8; 32]),
        source_bytes: 0,
        track_id,
        samples,
        rewrite: ValidatedClearFmp4SegmentRewriteV1 {
            moof_off: 0,
            traf_off,
            trun_off,
            trun_data_offset: trun.data_offset,
            mdat_content_start,
            mdat_content_end,
            senc_insert_off: traf_off + traf_h.size,
        },
        v2: None,
    })
}

fn validate_traf_v1(
    data: &[u8],
    traf_off: usize,
    traf_h: BoxHeader,
    moof_off: usize,
    mdat_content_start: usize,
    mdat_content_end: usize,
) -> Result<ValidatedCencFmp4SegmentLayoutV1, ContractError> {
    let mut tfhd = None;
    let mut trun = None;
    let mut senc = None;
    let mut saw_tfdt = false;
    for (off, h) in scan_boxes(data, traf_off + traf_h.header_size, traf_off + traf_h.size)? {
        match &h.box_type {
            b"tfhd" => {
                if tfhd.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("encrypted_segments"));
                }
            }
            b"trun" => {
                if trun.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("encrypted_segments"));
                }
            }
            b"senc" => {
                if senc.replace((off, h)).is_some() {
                    return Err(ContractError::InvalidField("encrypted_segments"));
                }
            }
            b"tfdt" => {
                if saw_tfdt {
                    return Err(ContractError::InvalidField("encrypted_segments"));
                }
                saw_tfdt = true;
                validate_tfdt_v1(data, off, h)?;
            }
            _ => return Err(ContractError::InvalidField("encrypted_segments")),
        }
    }
    let (tfhd_off, tfhd_h) = tfhd.ok_or(ContractError::InvalidField("encrypted_segments"))?;
    let (trun_off, trun_h) = trun.ok_or(ContractError::InvalidField("encrypted_segments"))?;
    let (senc_off, senc_h) = senc.ok_or(ContractError::InvalidField("encrypted_segments"))?;
    let track_id = parse_tfhd_track_id(data, tfhd_off, tfhd_h)?;
    let trun = parse_trun_layout(data, trun_off, trun_h, CencLayoutProfile::V1)?;
    let senc_samples = parse_senc_layout(
        data,
        senc_off,
        senc_h,
        trun.sample_sizes.as_slice(),
        SUPPORTED_COMMON_IV_SIZE_V1,
        None,
    )?;
    let sample_start = usize::try_from(trun.data_offset)
        .map_err(|_| ContractError::InvalidField("encrypted_segments"))?;
    if sample_start < mdat_content_start || sample_start > mdat_content_end {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let mut cursor = sample_start;
    let mut samples = Vec::with_capacity(trun.sample_sizes.len());
    for (size, senc_sample) in trun.sample_sizes.into_iter().zip(senc_samples) {
        let end = cursor
            .checked_add(size as usize)
            .ok_or(ContractError::InvalidField("encrypted_segments"))?;
        if end > mdat_content_end {
            return Err(ContractError::InvalidField("encrypted_segments"));
        }
        samples.push(ValidatedCencFmp4SampleLayoutV1 {
            ciphertext_offset: (cursor - mdat_content_start) as u64,
            sample_size: size,
            iv: senc_sample.iv,
            iv_size: senc_sample.iv_size,
            subsamples: senc_sample.subsamples,
        });
        cursor = end;
    }
    Ok(ValidatedCencFmp4SegmentLayoutV1 {
        source_sha256: Digest32::new([0u8; 32]),
        source_bytes: 0,
        track_id,
        samples,
        rewrite: ValidatedCencFmp4SegmentRewriteV1 {
            moof_off,
            traf_off,
            trun_off,
            senc_off,
            senc_size: senc_h.size,
            trun_data_offset: trun.data_offset,
            mdat_content_start,
            mdat_content_end,
        },
        timeline: None,
    })
}

/// Children of a V2 clear `traf`, exactly and in order.
const CLEAR_TRAF_CHILDREN_V2: [[u8; 4]; 3] = [*b"tfhd", *b"tfdt", *b"trun"];
/// Children of a V2 protected `traf`, exactly and in order (spec §6).
const CENC_TRAF_CHILDREN_V2: [[u8; 4]; 6] =
    [*b"tfhd", *b"tfdt", *b"trun", *b"saiz", *b"saio", *b"senc"];
/// A `saio` v0 box with one 32-bit offset: header, fullbox word, count, offset.
const SAIO_BOX_BYTES_V2: usize = 20;

/// Scans a V2 `traf` and requires exactly `expected` children, in that order.
fn scan_traf_children_v2(
    data: &[u8],
    traf_off: usize,
    traf_h: BoxHeader,
    expected: &[[u8; 4]],
) -> Result<Vec<(usize, BoxHeader)>, ContractError> {
    let children = scan_boxes(data, traf_off + traf_h.header_size, traf_off + traf_h.size)?;
    if children.len() != expected.len()
        || children
            .iter()
            .zip(expected)
            .any(|((_, h), box_type)| h.box_type != *box_type)
    {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    Ok(children)
}

/// `tfdt`, `tfhd` and `trun` give the segment's timeline: `t` from `tfdt`, `d`
/// from the `trun` durations, else the `tfhd` default for every sample; a
/// segment that declares neither, or a zero duration, is refused.
fn segment_timeline_v2(
    data: &[u8],
    tfdt: (usize, BoxHeader),
    tfhd: &TfhdLayoutV1,
    trun: &TrunLayoutV1,
) -> Result<Fmp4SegmentTimelineV2, ContractError> {
    const ERR: ContractError = ContractError::InvalidField("encrypted_segments");
    let decode_time = parse_tfdt_decode_time(data, tfdt.0, tfdt.1)?;
    let duration = match (trun.duration_sum, tfhd.default_sample_duration) {
        (Some(sum), _) => sum,
        (None, Some(default)) => u64::from(default)
            .checked_mul(trun.sample_sizes.len() as u64)
            .ok_or(ERR)?,
        (None, None) => return Err(ERR),
    };
    if duration == 0 {
        return Err(ERR);
    }
    Ok(Fmp4SegmentTimelineV2 {
        decode_time,
        duration,
    })
}

/// Lays the `trun` samples out from `data_offset` and requires them to fill the
/// `mdat` payload exactly. Returns each sample's `(offset in mdat, size)`.
fn mdat_sample_ranges(
    sample_sizes: &[u32],
    data_offset: i32,
    mdat_content_start: usize,
    mdat_content_end: usize,
) -> Result<Vec<(u64, u32)>, ContractError> {
    const ERR: ContractError = ContractError::InvalidField("encrypted_segments");
    let sample_start = usize::try_from(data_offset).map_err(|_| ERR)?;
    if sample_start != mdat_content_start {
        return Err(ERR);
    }
    let mut cursor = sample_start;
    let mut ranges = Vec::with_capacity(sample_sizes.len());
    for &size in sample_sizes {
        let end = cursor.checked_add(size as usize).ok_or(ERR)?;
        if end > mdat_content_end {
            return Err(ERR);
        }
        ranges.push(((cursor - mdat_content_start) as u64, size));
        cursor = end;
    }
    if cursor != mdat_content_end {
        return Err(ERR);
    }
    Ok(ranges)
}

fn validate_clear_traf_v2(
    data: &[u8],
    traf_off: usize,
    traf_h: BoxHeader,
    mdat_content_start: usize,
    mdat_content_end: usize,
    kind: CencDashRenditionKindV2,
) -> Result<ValidatedClearFmp4SegmentLayoutV1, ContractError> {
    let children = scan_traf_children_v2(data, traf_off, traf_h, &CLEAR_TRAF_CHILDREN_V2)?;
    let (tfhd_off, tfhd_h) = children[0];
    let (trun_off, trun_h) = children[2];
    let tfhd = parse_tfhd_layout(data, tfhd_off, tfhd_h, CencLayoutProfile::V2)?;
    let trun = parse_trun_layout(data, trun_off, trun_h, CencLayoutProfile::V2)?;
    let timeline = segment_timeline_v2(data, children[1], &tfhd, &trun)?;
    let samples = mdat_sample_ranges(
        &trun.sample_sizes,
        trun.data_offset,
        mdat_content_start,
        mdat_content_end,
    )?
    .into_iter()
    .map(
        |(mdat_offset, sample_size)| ValidatedClearFmp4SampleLayoutV1 {
            mdat_offset,
            sample_size,
        },
    )
    .collect();
    Ok(ValidatedClearFmp4SegmentLayoutV1 {
        source_sha256: Digest32::new([0u8; 32]),
        source_bytes: 0,
        track_id: tfhd.track_id,
        samples,
        rewrite: ValidatedClearFmp4SegmentRewriteV1 {
            moof_off: 0,
            traf_off,
            trun_off,
            trun_data_offset: trun.data_offset,
            mdat_content_start,
            mdat_content_end,
            senc_insert_off: traf_off + traf_h.size,
        },
        v2: Some((kind, timeline)),
    })
}

/// V2 protected `traf` (spec §7): exactly `tfhd tfdt trun saiz saio senc`;
/// `senc` flags 2 for video and 0 for audio with the init's IV size and
/// subsample sums equal to each sample size; one `saiz` entry per sample equal
/// to its `senc` entry; one `saio` offset pointing exactly at the first IV.
fn validate_traf_v2(
    data: &[u8],
    traf_off: usize,
    traf_h: BoxHeader,
    moof_off: usize,
    mdat_content_start: usize,
    mdat_content_end: usize,
    rules: CencTrackRulesV2,
) -> Result<ValidatedCencFmp4SegmentLayoutV1, ContractError> {
    const ERR: ContractError = ContractError::InvalidField("encrypted_segments");
    let children = scan_traf_children_v2(data, traf_off, traf_h, &CENC_TRAF_CHILDREN_V2)?;
    let (tfhd_off, tfhd_h) = children[0];
    let (trun_off, trun_h) = children[2];
    let (saiz_off, saiz_h) = children[3];
    let (saio_off, saio_h) = children[4];
    let (senc_off, senc_h) = children[5];
    let tfhd = parse_tfhd_layout(data, tfhd_off, tfhd_h, CencLayoutProfile::V2)?;
    if tfhd.track_id != rules.track_id {
        return Err(ERR);
    }
    let trun = parse_trun_layout(data, trun_off, trun_h, CencLayoutProfile::V2)?;
    let timeline = segment_timeline_v2(data, children[1], &tfhd, &trun)?;
    let senc_flags = match rules.kind {
        CencDashRenditionKindV2::Video => SENC_FLAG_SUBSAMPLES,
        CencDashRenditionKindV2::Audio => 0,
    };
    let senc_samples = parse_senc_layout(
        data,
        senc_off,
        senc_h,
        trun.sample_sizes.as_slice(),
        rules.iv_size,
        Some(senc_flags),
    )?;
    let saiz_sizes = parse_saiz_v2(data, saiz_off, saiz_h, trun.sample_sizes.len())?;
    for (saiz_size, senc_sample) in saiz_sizes.iter().zip(&senc_samples) {
        if usize::from(*saiz_size) != senc_sample.entry_bytes {
            return Err(ERR);
        }
    }
    let first_iv = senc_off
        .checked_sub(moof_off)
        .and_then(|value| value.checked_add(senc_h.header_size + 8))
        .ok_or(ERR)?;
    if parse_saio_v2(data, saio_off, saio_h)? != first_iv as u64 {
        return Err(ERR);
    }
    let samples = mdat_sample_ranges(
        &trun.sample_sizes,
        trun.data_offset,
        mdat_content_start,
        mdat_content_end,
    )?
    .into_iter()
    .zip(senc_samples)
    .map(
        |((ciphertext_offset, sample_size), senc_sample)| ValidatedCencFmp4SampleLayoutV1 {
            ciphertext_offset,
            sample_size,
            iv: senc_sample.iv,
            iv_size: senc_sample.iv_size,
            subsamples: senc_sample.subsamples,
        },
    )
    .collect();
    // The clear rewrite removes `saiz`, `saio` and `senc` as one run: they are
    // the last three `traf` children, back to back.
    let aux_end = senc_off.checked_add(senc_h.size).ok_or(ERR)?;
    Ok(ValidatedCencFmp4SegmentLayoutV1 {
        source_sha256: Digest32::new([0u8; 32]),
        source_bytes: 0,
        track_id: tfhd.track_id,
        samples,
        rewrite: ValidatedCencFmp4SegmentRewriteV1 {
            moof_off,
            traf_off,
            trun_off,
            senc_off: saiz_off,
            senc_size: aux_end - saiz_off,
            trun_data_offset: trun.data_offset,
            mdat_content_start,
            mdat_content_end,
        },
        timeline: Some(timeline),
    })
}

#[derive(Debug)]
struct TrunLayoutV1 {
    data_offset: i32,
    sample_sizes: Vec<u32>,
    /// V2 only: the sum of the per-sample durations, when `trun` carries them.
    duration_sum: Option<u64>,
}

/// V1 requires `trun` version 0; V2 also accepts version 1 (signed composition
/// offsets, which this parser skips either way) and sums the sample durations.
fn parse_trun_layout(
    data: &[u8],
    off: usize,
    h: BoxHeader,
    profile: CencLayoutProfile,
) -> Result<TrunLayoutV1, ContractError> {
    let content = off + h.header_size;
    if h.size < h.header_size + 12 {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let (version, flags) = read_fullbox_header(data, content)?;
    let allowed_flags = TRUN_FLAG_DATA_OFFSET
        | TRUN_FLAG_FIRST_SAMPLE_FLAGS
        | TRUN_FLAG_SAMPLE_DURATION
        | TRUN_FLAG_SAMPLE_SIZE
        | TRUN_FLAG_SAMPLE_FLAGS
        | TRUN_FLAG_SAMPLE_COMPOSITION_TIME_OFFSET;
    let version_allowed = match profile {
        CencLayoutProfile::V1 => version == 0,
        CencLayoutProfile::V2 => version <= 1,
    };
    if !version_allowed || flags & !allowed_flags != 0 {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    if flags & TRUN_FLAG_DATA_OFFSET == 0 || flags & TRUN_FLAG_SAMPLE_SIZE == 0 {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let sample_count = read_u32_at(data, content + 4)? as usize;
    if sample_count == 0 || sample_count > MAX_TRACK_SAMPLES_V1 {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let data_offset = read_i32_at(data, content + 8)?;
    let mut cursor = content + 12;
    if flags & TRUN_FLAG_FIRST_SAMPLE_FLAGS != 0 {
        cursor = cursor
            .checked_add(4)
            .ok_or(ContractError::InvalidField("encrypted_segments"))?;
    }
    let mut sample_sizes = Vec::with_capacity(sample_count);
    let sum_durations = profile == CencLayoutProfile::V2 && flags & TRUN_FLAG_SAMPLE_DURATION != 0;
    let mut duration_sum = 0u64;
    for _ in 0..sample_count {
        if flags & TRUN_FLAG_SAMPLE_DURATION != 0 {
            if sum_durations {
                duration_sum = duration_sum
                    .checked_add(u64::from(read_u32_at(data, cursor)?))
                    .ok_or(ContractError::InvalidField("encrypted_segments"))?;
            }
            cursor = cursor
                .checked_add(4)
                .ok_or(ContractError::InvalidField("encrypted_segments"))?;
        }
        sample_sizes.push(read_u32_at(data, cursor)?);
        cursor = cursor
            .checked_add(4)
            .ok_or(ContractError::InvalidField("encrypted_segments"))?;
        if flags & TRUN_FLAG_SAMPLE_FLAGS != 0 {
            cursor = cursor
                .checked_add(4)
                .ok_or(ContractError::InvalidField("encrypted_segments"))?;
        }
        if flags & TRUN_FLAG_SAMPLE_COMPOSITION_TIME_OFFSET != 0 {
            cursor = cursor
                .checked_add(4)
                .ok_or(ContractError::InvalidField("encrypted_segments"))?;
        }
    }
    if cursor != off + h.size || sample_sizes.contains(&0) {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    Ok(TrunLayoutV1 {
        data_offset,
        sample_sizes,
        duration_sum: sum_durations.then_some(duration_sum),
    })
}

struct ParsedSencSampleV1 {
    iv: [u8; 16],
    iv_size: u8,
    subsamples: Vec<ValidatedCencFmp4SubsampleV1>,
    /// This sample's auxiliary-information size: IV, plus count and entries
    /// when subsamples are present. `saiz` must declare exactly this.
    entry_bytes: usize,
}

/// `required_flags` is `None` under V1 (flags 0 or 2 both accepted) and the one
/// value the rendition kind requires under V2.
fn parse_senc_layout(
    data: &[u8],
    off: usize,
    h: BoxHeader,
    sample_sizes: &[u32],
    iv_size: u8,
    required_flags: Option<u32>,
) -> Result<Vec<ParsedSencSampleV1>, ContractError> {
    let content = off + h.header_size;
    if h.size < h.header_size + 8 {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let (version, flags) = read_fullbox_header(data, content)?;
    let flags_allowed = match required_flags {
        None => flags == 0 || flags == SENC_FLAG_SUBSAMPLES,
        Some(required) => flags == required,
    };
    if version != 0 || !flags_allowed {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let sample_count = read_u32_at(data, content + 4)? as usize;
    if sample_count != sample_sizes.len() {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let mut cursor = content + 8;
    let mut samples = Vec::with_capacity(sample_sizes.len());
    for size in sample_sizes {
        let entry_start = cursor;
        let mut iv = [0u8; 16];
        iv.get_mut(..usize::from(iv_size))
            .ok_or(ContractError::InvalidField("encrypted_segments"))?
            .copy_from_slice(slice_at(data, cursor, usize::from(iv_size))?);
        cursor = cursor
            .checked_add(usize::from(iv_size))
            .ok_or(ContractError::InvalidField("encrypted_segments"))?;
        let mut subsamples = Vec::new();
        if flags & SENC_FLAG_SUBSAMPLES != 0 {
            let subsample_count = usize::from(read_u16_at(data, cursor)?);
            if subsample_count == 0 {
                return Err(ContractError::InvalidField("encrypted_segments"));
            }
            cursor = cursor
                .checked_add(2)
                .ok_or(ContractError::InvalidField("encrypted_segments"))?;
            let mut total = 0u64;
            for _ in 0..subsample_count {
                let clear = u64::from(read_u16_at(data, cursor)?);
                let encrypted = u64::from(read_u32_at(data, cursor + 2)?);
                cursor = cursor
                    .checked_add(6)
                    .ok_or(ContractError::InvalidField("encrypted_segments"))?;
                subsamples.push(ValidatedCencFmp4SubsampleV1 {
                    clear_bytes: clear as u16,
                    encrypted_bytes: encrypted as u32,
                });
                total = total
                    .checked_add(clear)
                    .and_then(|value| value.checked_add(encrypted))
                    .ok_or(ContractError::InvalidField("encrypted_segments"))?;
            }
            if total != u64::from(*size) {
                return Err(ContractError::InvalidField("encrypted_segments"));
            }
        }
        samples.push(ParsedSencSampleV1 {
            iv,
            iv_size,
            subsamples,
            entry_bytes: cursor - entry_start,
        });
    }
    if cursor != off + h.size {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    Ok(samples)
}

fn parse_tfhd_track_id(data: &[u8], off: usize, h: BoxHeader) -> Result<u32, ContractError> {
    Ok(parse_tfhd_layout(data, off, h, CencLayoutProfile::V1)?.track_id)
}

struct TfhdLayoutV1 {
    track_id: u32,
    default_sample_duration: Option<u32>,
}

/// V2 additionally admits a sample-description-index field whose value is 1
/// (Bento4 writes tfhd flags `0x02002a`).
fn parse_tfhd_layout(
    data: &[u8],
    off: usize,
    h: BoxHeader,
    profile: CencLayoutProfile,
) -> Result<TfhdLayoutV1, ContractError> {
    let content = off + h.header_size;
    if h.size < h.header_size + 8 {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let (version, flags) = read_fullbox_header(data, content)?;
    let mut allowed_flags = TFHD_FLAG_DEFAULT_BASE_IS_MOOF
        | TFHD_FLAG_DEFAULT_SAMPLE_DURATION
        | TFHD_FLAG_DEFAULT_SAMPLE_SIZE
        | TFHD_FLAG_DEFAULT_SAMPLE_FLAGS;
    if profile == CencLayoutProfile::V2 {
        allowed_flags |= TFHD_FLAG_SAMPLE_DESCRIPTION_INDEX;
    }
    if version != 0 {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    if flags & TFHD_FLAG_BASE_DATA_OFFSET != 0
        || flags & TFHD_FLAG_DEFAULT_BASE_IS_MOOF == 0
        || flags & !allowed_flags != 0
    {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let track_id = read_u32_at(data, content + 4)?;
    if track_id == 0 {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    let mut cursor = content + 8;
    if flags & TFHD_FLAG_SAMPLE_DESCRIPTION_INDEX != 0 {
        if read_u32_at(data, cursor)? != 1 {
            return Err(ContractError::InvalidField("encrypted_segments"));
        }
        cursor = cursor
            .checked_add(4)
            .ok_or(ContractError::InvalidField("encrypted_segments"))?;
    }
    let mut default_sample_duration = None;
    if flags & TFHD_FLAG_DEFAULT_SAMPLE_DURATION != 0 {
        if profile == CencLayoutProfile::V2 {
            default_sample_duration = Some(read_u32_at(data, cursor)?);
        }
        cursor = cursor
            .checked_add(4)
            .ok_or(ContractError::InvalidField("encrypted_segments"))?;
    }
    if flags & TFHD_FLAG_DEFAULT_SAMPLE_SIZE != 0 {
        cursor = cursor
            .checked_add(4)
            .ok_or(ContractError::InvalidField("encrypted_segments"))?;
    }
    if flags & TFHD_FLAG_DEFAULT_SAMPLE_FLAGS != 0 {
        cursor = cursor
            .checked_add(4)
            .ok_or(ContractError::InvalidField("encrypted_segments"))?;
    }
    if cursor != off + h.size {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    Ok(TfhdLayoutV1 {
        track_id,
        default_sample_duration,
    })
}

fn validate_mfhd_v1(data: &[u8], off: usize, h: BoxHeader) -> Result<(), ContractError> {
    let content = off + h.header_size;
    let (version, flags) = read_fullbox_header(data, content)?;
    if version != 0 || flags != 0 || h.size != h.header_size + 8 {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    Ok(())
}

fn validate_tfdt_v1(data: &[u8], off: usize, h: BoxHeader) -> Result<(), ContractError> {
    let content = off + h.header_size;
    let (version, flags) = read_fullbox_header(data, content)?;
    let exact_size = match version {
        0 => h.header_size + 8,
        1 => h.header_size + 12,
        _ => return Err(ContractError::InvalidField("encrypted_segments")),
    };
    if flags != 0 || h.size != exact_size {
        return Err(ContractError::InvalidField("encrypted_segments"));
    }
    Ok(())
}

fn parse_tfdt_decode_time(data: &[u8], off: usize, h: BoxHeader) -> Result<u64, ContractError> {
    validate_tfdt_v1(data, off, h)?;
    let content = off + h.header_size;
    match read_fullbox_header(data, content)?.0 {
        0 => Ok(u64::from(read_u32_at(data, content + 4)?)),
        _ => read_u64_at(data, content + 4),
    }
}

/// Reads the optional `aux_info_type` / `aux_info_type_parameter` of a `saiz` or
/// `saio` and returns where the box-specific fields start. When present they
/// must name `cenc` with parameter 0.
fn skip_aux_info_type_v2(data: &[u8], content: usize, flags: u32) -> Result<usize, ContractError> {
    const ERR: ContractError = ContractError::InvalidField("encrypted_segments");
    match flags {
        0 => Ok(content + 4),
        AUX_INFO_FLAG_TYPE_PRESENT => {
            if slice_at(data, content + 4, 4)? != b"cenc" || read_u32_at(data, content + 8)? != 0 {
                return Err(ERR);
            }
            Ok(content + 12)
        }
        _ => Err(ERR),
    }
}

/// `saiz` v0: the per-sample auxiliary-information sizes, one per sample.
fn parse_saiz_v2(
    data: &[u8],
    off: usize,
    h: BoxHeader,
    sample_count: usize,
) -> Result<Vec<u8>, ContractError> {
    const ERR: ContractError = ContractError::InvalidField("encrypted_segments");
    let content = off + h.header_size;
    let (version, flags) = read_fullbox_header(data, content)?;
    if version != 0 {
        return Err(ERR);
    }
    let fields = skip_aux_info_type_v2(data, content, flags)?;
    let default_size = *data.get(fields).ok_or(ContractError::UnexpectedEnd)?;
    if read_u32_at(data, fields + 1)? as usize != sample_count {
        return Err(ERR);
    }
    let table = fields + 5;
    let (sizes, end) = if default_size == 0 {
        let end = table.checked_add(sample_count).ok_or(ERR)?;
        (slice_at(data, table, sample_count)?.to_vec(), end)
    } else {
        (vec![default_size; sample_count], table)
    };
    if end != off + h.size {
        return Err(ERR);
    }
    Ok(sizes)
}

/// `saio` v0 or v1 with exactly one offset; returns it.
fn parse_saio_v2(data: &[u8], off: usize, h: BoxHeader) -> Result<u64, ContractError> {
    const ERR: ContractError = ContractError::InvalidField("encrypted_segments");
    let content = off + h.header_size;
    let (version, flags) = read_fullbox_header(data, content)?;
    let fields = skip_aux_info_type_v2(data, content, flags)?;
    if read_u32_at(data, fields)? != 1 {
        return Err(ERR);
    }
    let (offset, end) = match version {
        0 => (u64::from(read_u32_at(data, fields + 4)?), fields + 8),
        1 => (read_u64_at(data, fields + 4)?, fields + 12),
        _ => return Err(ERR),
    };
    if end != off + h.size {
        return Err(ERR);
    }
    Ok(offset)
}

/// Producer `senc` for V2: 8-byte IVs; flags 2 with one subsample map per sample
/// (video), else flags 0 (audio).
fn make_senc_box_v2(
    sample_ivs: &[[u8; 8]],
    subsamples: Option<&[Vec<(u16, u32)>]>,
) -> Result<Vec<u8>, ContractError> {
    const ERR: ContractError = ContractError::InvalidField("clear_segment_bytes");
    let mut payload = Vec::new();
    payload.extend_from_slice(
        &u32::try_from(sample_ivs.len())
            .map_err(|_| ERR)?
            .to_be_bytes(),
    );
    for (index, iv) in sample_ivs.iter().enumerate() {
        payload.extend_from_slice(iv);
        if let Some(subsamples) = subsamples {
            let map = subsamples.get(index).ok_or(ERR)?;
            payload.extend_from_slice(&u16::try_from(map.len()).map_err(|_| ERR)?.to_be_bytes());
            for (clear, encrypted) in map {
                payload.extend_from_slice(&clear.to_be_bytes());
                payload.extend_from_slice(&encrypted.to_be_bytes());
            }
        }
    }
    let flags = if subsamples.is_some() {
        SENC_FLAG_SUBSAMPLES
    } else {
        0
    };
    make_fullbox_v1(b"senc", 0, flags, &payload)
}

/// Each producer sample's `senc` entry size (8-byte IV, plus `2 + 6n` with
/// subsamples), refused when it does not fit a one-byte `saiz` entry.
fn senc_entry_sizes_v2(
    sample_count: usize,
    subsamples: Option<&[Vec<(u16, u32)>]>,
) -> Result<Vec<u8>, ContractError> {
    const ERR: ContractError = ContractError::InvalidField("clear_segment_bytes");
    (0..sample_count)
        .map(|index| {
            let size = match subsamples {
                None => usize::from(SUPPORTED_COMMON_IV_SIZE_V1),
                Some(subsamples) => subsamples
                    .get(index)
                    .ok_or(ERR)?
                    .len()
                    .checked_mul(6)
                    .and_then(|value| {
                        value.checked_add(2 + usize::from(SUPPORTED_COMMON_IV_SIZE_V1))
                    })
                    .ok_or(ERR)?,
            };
            u8::try_from(size).map_err(|_| ERR)
        })
        .collect()
}

/// `saiz` v0: the default size when every entry is equal, else 0 and a table.
fn make_saiz_box_v2(entry_sizes: &[u8]) -> Result<Vec<u8>, ContractError> {
    let uniform = entry_sizes
        .first()
        .filter(|first| entry_sizes.iter().all(|size| size == *first))
        .copied();
    let mut payload = vec![uniform.unwrap_or(0)];
    payload.extend_from_slice(
        &u32::try_from(entry_sizes.len())
            .map_err(|_| ContractError::InvalidField("clear_segment_bytes"))?
            .to_be_bytes(),
    );
    if uniform.is_none() {
        payload.extend_from_slice(entry_sizes);
    }
    make_fullbox_v1(b"saiz", 0, 0, &payload)
}

/// Exactly one child of `box_type` inside the given box.
fn single_child(
    data: &[u8],
    parent_off: usize,
    parent_h: BoxHeader,
    box_type: &[u8; 4],
) -> Result<(usize, BoxHeader), ContractError> {
    let mut found = None;
    for (off, h) in scan_boxes(
        data,
        parent_off + parent_h.header_size,
        parent_off + parent_h.size,
    )? {
        if h.box_type == *box_type && found.replace((off, h)).is_some() {
            return Err(ContractError::InvalidField("init_segment_bytes"));
        }
    }
    found.ok_or(ContractError::InvalidField("init_segment_bytes"))
}

/// Reads the one track of an already validated V2 init: `tkhd` id, `mdhd`
/// timescale, and the sample entry's fixed fields (plus `avcC` for video).
/// `protected` selects `encv`/`enca` over `avc1`/`mp4a`.
fn parse_rendition_v2(
    data: &[u8],
    moov_off: usize,
    protected: bool,
) -> Result<ValidatedFmp4RenditionV2, ContractError> {
    const ERR: ContractError = ContractError::InvalidField("init_segment_bytes");
    let moov_h = read_box_header(data, moov_off)?;
    let (trak_off, trak_h) = single_child(data, moov_off, moov_h, b"trak")?;
    let (tkhd_off, tkhd_h) = single_child(data, trak_off, trak_h, b"tkhd")?;
    let track_id = parse_tkhd_track_id(data, tkhd_off, tkhd_h)?;
    let (mdia_off, mdia_h) = single_child(data, trak_off, trak_h, b"mdia")?;
    let (mdhd_off, mdhd_h) = single_child(data, mdia_off, mdia_h, b"mdhd")?;
    let mdhd = mdhd_off + mdhd_h.header_size;
    let (mdhd_version, _) = read_fullbox_header(data, mdhd)?;
    let (timescale_at, mdhd_bytes) = match mdhd_version {
        0 => (mdhd + 12, 24),
        1 => (mdhd + 20, 36),
        _ => return Err(ERR),
    };
    if mdhd_h.size < mdhd_h.header_size + mdhd_bytes {
        return Err(ERR);
    }
    let timescale = read_u32_at(data, timescale_at)?;
    let (minf_off, minf_h) = single_child(data, mdia_off, mdia_h, b"minf")?;
    let (stbl_off, stbl_h) = single_child(data, minf_off, minf_h, b"stbl")?;
    let (stsd_off, stsd_h) = single_child(data, stbl_off, stbl_h, b"stsd")?;
    let entry_off = stsd_off + stsd_h.header_size + 8;
    let entry_h = read_box_header(data, entry_off)?;
    let entry = entry_off + entry_h.header_size;
    let sample_entry = match (&entry_h.box_type, protected) {
        (b"avc1", false) | (b"encv", true) => {
            let width = read_u16_at(data, entry + 24)?;
            let height = read_u16_at(data, entry + 26)?;
            let children_start = entry + VISUAL_SAMPLE_ENTRY_FIXED_BYTES;
            let mut avcc = None;
            for (off, h) in scan_boxes(data, children_start, entry_off + entry_h.size)? {
                if h.box_type == *b"avcC" && avcc.replace((off, h)).is_some() {
                    return Err(ERR);
                }
            }
            let (avcc_off, avcc_h) = avcc.ok_or(ERR)?;
            let avcc = slice_at(
                data,
                avcc_off + avcc_h.header_size,
                avcc_h.size - avcc_h.header_size,
            )?;
            // configurationVersion 1; byte 4 low two bits are lengthSizeMinusOne.
            let nal_length_size = match avcc {
                [1, _, _, _, length, ..] => (length & 0x03) + 1,
                _ => return Err(ERR),
            };
            if nal_length_size == 3 || width == 0 || height == 0 {
                return Err(ERR);
            }
            Fmp4SampleEntryV2::Video {
                width,
                height,
                nal_length_size,
            }
        }
        (b"mp4a", false) | (b"enca", true) => {
            let channel_count = read_u16_at(data, entry + 16)?;
            let sample_rate = read_u32_at(data, entry + 24)? >> 16;
            if channel_count == 0 || sample_rate == 0 {
                return Err(ERR);
            }
            Fmp4SampleEntryV2::Audio {
                sample_rate,
                channel_count,
            }
        }
        _ => return Err(ERR),
    };
    if timescale == 0 {
        return Err(ERR);
    }
    Ok(ValidatedFmp4RenditionV2 {
        track_id,
        timescale,
        sample_entry,
    })
}

fn verify_exact_source_bytes(
    bytes: &[u8],
    expected_sha256: Digest32,
    expected_len: u64,
    field: &'static str,
) -> Result<(), ContractError> {
    if bytes.len() as u64 != expected_len {
        return Err(ContractError::InvalidField(field));
    }
    if Digest32::new(Sha256::digest(bytes).into()) != expected_sha256 {
        return Err(ContractError::InvalidField(field));
    }
    Ok(())
}

fn shrink_box_size_in_place(
    bytes: &mut [u8],
    box_off: usize,
    delta: usize,
    field: &'static str,
) -> Result<(), ContractError> {
    let header = read_box_header(bytes, box_off)?;
    let new_size = header
        .size
        .checked_sub(delta)
        .ok_or(ContractError::InvalidField(field))?;
    if new_size < header.header_size {
        return Err(ContractError::InvalidField(field));
    }
    match header.header_size {
        8 => {
            let size32 = u32::try_from(new_size).map_err(|_| ContractError::InvalidField(field))?;
            bytes[box_off..box_off + 4].copy_from_slice(&size32.to_be_bytes());
        }
        16 => {
            bytes[box_off..box_off + 4].copy_from_slice(&1u32.to_be_bytes());
            bytes[box_off + 8..box_off + 16].copy_from_slice(&(new_size as u64).to_be_bytes());
        }
        _ => return Err(ContractError::InvalidField(field)),
    }
    Ok(())
}

fn grow_box_size_in_place(
    bytes: &mut [u8],
    box_off: usize,
    delta: usize,
    field: &'static str,
) -> Result<(), ContractError> {
    let header = read_box_header(bytes, box_off)?;
    let new_size = header
        .size
        .checked_add(delta)
        .ok_or(ContractError::InvalidField(field))?;
    match header.header_size {
        8 => {
            let size32 = u32::try_from(new_size).map_err(|_| ContractError::InvalidField(field))?;
            bytes[box_off..box_off + 4].copy_from_slice(&size32.to_be_bytes());
        }
        16 => {
            bytes[box_off..box_off + 4].copy_from_slice(&1u32.to_be_bytes());
            bytes[box_off + 8..box_off + 16].copy_from_slice(&(new_size as u64).to_be_bytes());
        }
        _ => return Err(ContractError::InvalidField(field)),
    }
    Ok(())
}

fn make_box_v1(box_type: &[u8; 4], payload: &[u8]) -> Result<Vec<u8>, ContractError> {
    let size = 8usize
        .checked_add(payload.len())
        .ok_or(ContractError::InvalidField("box_size"))?;
    let size32 = u32::try_from(size).map_err(|_| ContractError::InvalidField("box_size"))?;
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&size32.to_be_bytes());
    out.extend_from_slice(box_type);
    out.extend_from_slice(payload);
    Ok(out)
}

fn make_fullbox_v1(
    box_type: &[u8; 4],
    version: u8,
    flags: u32,
    payload: &[u8],
) -> Result<Vec<u8>, ContractError> {
    let mut content = Vec::with_capacity(4 + payload.len());
    content.push(version);
    content.extend_from_slice(&flags.to_be_bytes()[1..]);
    content.extend_from_slice(payload);
    make_box_v1(box_type, &content)
}

fn protected_sample_entry_fourcc_v1(original_fourcc: [u8; 4]) -> Result<[u8; 4], ContractError> {
    match &original_fourcc {
        b"avc1" => Ok(*b"encv"),
        b"mp4a" => Ok(*b"enca"),
        _ => Err(ContractError::InvalidField("init_segment_bytes")),
    }
}

fn make_protected_sinf_v1(
    original_fourcc: [u8; 4],
    key_id: [u8; 16],
) -> Result<Vec<u8>, ContractError> {
    let frma = make_box_v1(b"frma", &original_fourcc)?;
    let mut schm_payload = Vec::new();
    schm_payload.extend_from_slice(b"cenc");
    schm_payload.extend_from_slice(&0x0001_0000u32.to_be_bytes());
    let schm = make_fullbox_v1(b"schm", 0, 0, &schm_payload)?;
    let mut tenc_payload = vec![0, 0, 1, SUPPORTED_COMMON_IV_SIZE_V1];
    tenc_payload.extend_from_slice(&key_id);
    let tenc = make_fullbox_v1(b"tenc", 0, 0, &tenc_payload)?;
    let schi = make_box_v1(b"schi", &tenc)?;
    let mut sinf_payload = Vec::new();
    sinf_payload.extend_from_slice(&frma);
    sinf_payload.extend_from_slice(&schm);
    sinf_payload.extend_from_slice(&schi);
    make_box_v1(b"sinf", &sinf_payload)
}

fn make_fullsample_senc_box_v1(sample_ivs: &[[u8; 8]]) -> Result<Vec<u8>, ContractError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(
        &u32::try_from(sample_ivs.len())
            .map_err(|_| ContractError::InvalidField("clear_segment_bytes"))?
            .to_be_bytes(),
    );
    for iv in sample_ivs {
        payload.extend_from_slice(iv);
    }
    make_fullbox_v1(b"senc", 0, 0, &payload)
}

fn parse_tkhd_track_id(data: &[u8], off: usize, h: BoxHeader) -> Result<u32, ContractError> {
    let content = off + h.header_size;
    let version = *data
        .get(content)
        .ok_or(ContractError::InvalidField("init_segment_bytes"))?;
    if version != 0 && version != 1 {
        return Err(ContractError::InvalidField("init_segment_bytes"));
    }
    let track_id_offset = if version == 1 { 20 } else { 12 };
    read_u32_at(data, content + track_id_offset)
}

fn parse_hdlr_type(data: &[u8], off: usize, h: BoxHeader) -> Result<[u8; 4], ContractError> {
    let content = off + h.header_size;
    slice_at(data, content + 8, 4)?
        .try_into()
        .map_err(|_| ContractError::InvalidField("init_segment_bytes"))
}

fn read_box_header(data: &[u8], offset: usize) -> Result<BoxHeader, ContractError> {
    let size32 = read_u32_at(data, offset)?;
    let box_type: [u8; 4] = slice_at(data, offset + 4, 4)?
        .try_into()
        .map_err(|_| ContractError::UnexpectedEnd)?;
    if size32 == 0 {
        return Err(ContractError::InvalidField("box_size"));
    }
    if size32 == 1 {
        let size64 = read_u64_at(data, offset + 8)?;
        let size = usize::try_from(size64).map_err(|_| ContractError::InvalidField("box_size"))?;
        let end = offset
            .checked_add(size)
            .ok_or(ContractError::InvalidField("box_size"))?;
        if size < 16 || end > data.len() {
            return Err(ContractError::InvalidField("box_size"));
        }
        return Ok(BoxHeader {
            box_type,
            size,
            header_size: 16,
        });
    }
    let size = size32 as usize;
    let end = offset
        .checked_add(size)
        .ok_or(ContractError::InvalidField("box_size"))?;
    if size < 8 || end > data.len() {
        return Err(ContractError::InvalidField("box_size"));
    }
    Ok(BoxHeader {
        box_type,
        size,
        header_size: 8,
    })
}

fn scan_boxes(
    data: &[u8],
    start: usize,
    end: usize,
) -> Result<Vec<(usize, BoxHeader)>, ContractError> {
    if start > end || end > data.len() {
        return Err(ContractError::InvalidField("box_size"));
    }
    let mut out = Vec::new();
    let mut offset = start;
    while offset < end {
        let h = read_box_header(data, offset)?;
        let next = offset
            .checked_add(h.size)
            .ok_or(ContractError::InvalidField("box_size"))?;
        if next > end {
            return Err(ContractError::InvalidField("box_size"));
        }
        if out.len() == MAX_CHILD_BOXES_V1 {
            return Err(ContractError::InvalidField("box_count"));
        }
        out.push((offset, h));
        offset = next;
    }
    if offset != end {
        return Err(ContractError::TrailingBytes);
    }
    Ok(out)
}

fn slice_at(data: &[u8], start: usize, length: usize) -> Result<&[u8], ContractError> {
    let end = start
        .checked_add(length)
        .ok_or(ContractError::UnexpectedEnd)?;
    data.get(start..end).ok_or(ContractError::UnexpectedEnd)
}

fn read_fullbox_header(data: &[u8], content: usize) -> Result<(u8, u32), ContractError> {
    let version = *data.get(content).ok_or(ContractError::UnexpectedEnd)?;
    let flags = u32::from_be_bytes([
        0,
        *data.get(content + 1).ok_or(ContractError::UnexpectedEnd)?,
        *data.get(content + 2).ok_or(ContractError::UnexpectedEnd)?,
        *data.get(content + 3).ok_or(ContractError::UnexpectedEnd)?,
    ]);
    Ok((version, flags))
}

fn read_u16_at(data: &[u8], start: usize) -> Result<u16, ContractError> {
    Ok(u16::from_be_bytes(
        slice_at(data, start, 2)?
            .try_into()
            .map_err(|_| ContractError::UnexpectedEnd)?,
    ))
}

fn read_u32_at(data: &[u8], start: usize) -> Result<u32, ContractError> {
    Ok(u32::from_be_bytes(
        slice_at(data, start, 4)?
            .try_into()
            .map_err(|_| ContractError::UnexpectedEnd)?,
    ))
}

fn read_i32_at(data: &[u8], start: usize) -> Result<i32, ContractError> {
    Ok(i32::from_be_bytes(
        slice_at(data, start, 4)?
            .try_into()
            .map_err(|_| ContractError::UnexpectedEnd)?,
    ))
}

fn read_u64_at(data: &[u8], start: usize) -> Result<u64, ContractError> {
    Ok(u64::from_be_bytes(
        slice_at(data, start, 8)?
            .try_into()
            .map_err(|_| ContractError::UnexpectedEnd)?,
    ))
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use elastos_protected_content_contracts::{
        CustodyCommitteeAuthorizationIdentityV1, CustodyEpochIdentityV1, CustodyPoolIdentityV1,
    };
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::protection_system::{ELASTOS_CUSTODY_LEGACY, ELASTOS_CUSTODY_POOL};
    use crate::pssh::{build_pssh_v1, parse_pssh_v1};

    const TEST_KEY_ID: [u8; 16] = [0x55; 16];

    fn test_pssh_data_for(key_id: [u8; 16]) -> CustodyProtectionHeader {
        CustodyProtectionHeader::new(
            ContentAccessIdV1::new(key_id).unwrap(),
            &CustodyPoolIdentityV1::new(Digest32::new([0x61; 32]), 512).unwrap(),
            &CustodyEpochIdentityV1::new(Digest32::new([0x62; 32]), 512).unwrap(),
            &CustodyCommitteeAuthorizationIdentityV1::new(Digest32::new([0x63; 32]), 512).unwrap(),
            CencMediaSuite::Fmp4V1,
        )
    }

    /// `box_` with its `Data` JSON edited by `edit`, as one box under `system_id`.
    fn box_with_edited_data(
        box_: &[u8],
        system_id: &[u8; 16],
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> Vec<u8> {
        let parsed = parse_pssh_v1(box_).unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&parsed.data).unwrap();
        edit(&mut json);
        build_pssh_v1(system_id, &parsed.kids, &serde_json::to_vec(&json).unwrap())
    }

    fn test_pssh_data() -> CustodyProtectionHeader {
        test_pssh_data_for(TEST_KEY_ID)
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

    fn make_sinf(original_fourcc: &[u8; 4]) -> Vec<u8> {
        let frma = make_box(b"frma", original_fourcc);
        let mut schm_payload = Vec::new();
        schm_payload.extend_from_slice(b"cenc");
        schm_payload.extend_from_slice(&0x0001_0000u32.to_be_bytes());
        let schm = make_fullbox(b"schm", 0, 0, &schm_payload);
        let mut tenc_payload = vec![0, 0, 1, SUPPORTED_COMMON_IV_SIZE_V1];
        tenc_payload.extend_from_slice(&[0x44; 16]);
        let tenc = make_fullbox(b"tenc", 0, 0, &tenc_payload);
        let schi = make_box(b"schi", &tenc);
        let mut sinf_content = Vec::new();
        sinf_content.extend_from_slice(&frma);
        sinf_content.extend_from_slice(&schm);
        sinf_content.extend_from_slice(&schi);
        make_box(b"sinf", &sinf_content)
    }

    fn make_sample_entry(handler_type: &[u8; 4]) -> Vec<u8> {
        let (protected_fourcc, original_fourcc, fixed) = match handler_type {
            b"vide" => (b"encv", b"avc1", VISUAL_SAMPLE_ENTRY_FIXED_BYTES),
            b"soun" => (b"enca", b"mp4a", AUDIO_SAMPLE_ENTRY_FIXED_BYTES),
            _ => panic!("unsupported handler"),
        };
        let mut content = vec![0u8; fixed];
        content.extend_from_slice(&make_sinf(original_fourcc));
        make_box(protected_fourcc, &content)
    }

    fn make_clear_sample_entry(handler_type: &[u8; 4]) -> Vec<u8> {
        make_clear_sample_entry_with_children(handler_type, &[])
    }

    fn make_clear_sample_entry_with_children(
        handler_type: &[u8; 4],
        children: &[Vec<u8>],
    ) -> Vec<u8> {
        let (fourcc, fixed) = match handler_type {
            b"vide" => (b"avc1", VISUAL_SAMPLE_ENTRY_FIXED_BYTES),
            b"soun" => (b"mp4a", AUDIO_SAMPLE_ENTRY_FIXED_BYTES),
            _ => panic!("unsupported handler"),
        };
        let mut content = vec![0u8; fixed];
        for child in children {
            content.extend_from_slice(child);
        }
        make_box(fourcc, &content)
    }

    fn make_trak(track_id: u32, handler_type: &[u8; 4]) -> Vec<u8> {
        let mut tkhd_payload = vec![0u8; 12];
        tkhd_payload[8..12].copy_from_slice(&track_id.to_be_bytes());
        let tkhd = make_fullbox(b"tkhd", 0, 0, &tkhd_payload);

        let mut hdlr_payload = vec![0u8; 4];
        hdlr_payload.extend_from_slice(handler_type);
        let hdlr = make_fullbox(b"hdlr", 0, 0, &hdlr_payload);

        let entry = make_sample_entry(handler_type);
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

    fn make_clear_trak(track_id: u32, handler_type: &[u8; 4]) -> Vec<u8> {
        make_clear_trak_with_entry(
            track_id,
            handler_type,
            make_clear_sample_entry(handler_type),
        )
    }

    fn make_clear_trak_with_entry(
        track_id: u32,
        handler_type: &[u8; 4],
        entry: Vec<u8>,
    ) -> Vec<u8> {
        let mut tkhd_payload = vec![0u8; 12];
        tkhd_payload[8..12].copy_from_slice(&track_id.to_be_bytes());
        let tkhd = make_fullbox(b"tkhd", 0, 0, &tkhd_payload);

        let mut hdlr_payload = vec![0u8; 4];
        hdlr_payload.extend_from_slice(handler_type);
        let hdlr = make_fullbox(b"hdlr", 0, 0, &hdlr_payload);

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

    fn build_init_segment(
        tracks: &[(u32, &[u8; 4])],
        trex_ids: &[u32],
        extra_moov_children: &[Vec<u8>],
    ) -> Vec<u8> {
        let ftyp = make_box(b"ftyp", b"isom\0\0\0\0isomiso6");
        let traks: Vec<Vec<u8>> = tracks
            .iter()
            .map(|(track_id, handler)| make_trak(*track_id, handler))
            .collect();
        let mut mvex_content = Vec::new();
        for track_id in trex_ids {
            mvex_content.extend_from_slice(&make_trex(*track_id));
        }
        let mvex = make_box(b"mvex", &mvex_content);
        let mvhd = make_box(b"mvhd", &[0u8; 4]);

        let mut moov_content = Vec::new();
        moov_content.extend_from_slice(&mvhd);
        for trak in &traks {
            moov_content.extend_from_slice(trak);
        }
        moov_content.extend_from_slice(&mvex);
        for child in extra_moov_children {
            moov_content.extend_from_slice(child);
        }
        let moov = make_box(b"moov", &moov_content);

        let mut init = Vec::new();
        init.extend_from_slice(&ftyp);
        init.extend_from_slice(&moov);
        init
    }

    fn valid_init_segment() -> Vec<u8> {
        build_init_segment(&[(1, b"vide"), (2, b"soun")], &[1, 2], &[])
    }

    fn valid_clear_init_segment() -> Vec<u8> {
        clear_init_segment_with_traks([make_clear_trak(1, b"vide"), make_clear_trak(2, b"soun")])
    }

    fn clear_init_segment_with_traks(traks: [Vec<u8>; 2]) -> Vec<u8> {
        let ftyp = make_box(b"ftyp", b"isom\0\0\0\0isomiso6");
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

    fn make_segment_with(
        track_id: u32,
        payload: &[u8],
        tfhd_flags: u32,
        include_tfdt: bool,
        subsamples: Option<&[(u16, u32)]>,
    ) -> Vec<u8> {
        let mut tfhd_payload = Vec::new();
        tfhd_payload.extend_from_slice(&track_id.to_be_bytes());
        if tfhd_flags & TFHD_FLAG_DEFAULT_SAMPLE_DURATION != 0 {
            tfhd_payload.extend_from_slice(&1u32.to_be_bytes());
        }
        if tfhd_flags & TFHD_FLAG_DEFAULT_SAMPLE_SIZE != 0 {
            tfhd_payload.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        }
        if tfhd_flags & TFHD_FLAG_DEFAULT_SAMPLE_FLAGS != 0 {
            tfhd_payload.extend_from_slice(&0u32.to_be_bytes());
        }
        let tfhd = make_fullbox(b"tfhd", 0, tfhd_flags, &tfhd_payload);

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

        let iv = (u64::from(track_id) + 0x10).to_be_bytes();
        let mut senc_payload = Vec::new();
        senc_payload.extend_from_slice(&1u32.to_be_bytes());
        senc_payload.extend_from_slice(&iv);
        let senc_flags = if subsamples.is_some() {
            SENC_FLAG_SUBSAMPLES
        } else {
            0
        };
        if let Some(subsamples) = subsamples {
            senc_payload.extend_from_slice(&(subsamples.len() as u16).to_be_bytes());
            for (clear, encrypted) in subsamples {
                senc_payload.extend_from_slice(&clear.to_be_bytes());
                senc_payload.extend_from_slice(&encrypted.to_be_bytes());
            }
        }
        let senc = make_fullbox(b"senc", 0, senc_flags, &senc_payload);

        let traf = {
            let mut traf_content = Vec::new();
            traf_content.extend_from_slice(&tfhd);
            if include_tfdt {
                traf_content.extend_from_slice(&make_fullbox(b"tfdt", 0, 0, &1u32.to_be_bytes()));
            }
            traf_content.extend_from_slice(&trun);
            traf_content.extend_from_slice(&senc);
            make_box(b"traf", &traf_content)
        };
        let mfhd = make_fullbox(b"mfhd", 0, 0, &1u32.to_be_bytes());
        let mut moof_content = Vec::new();
        moof_content.extend_from_slice(&mfhd);
        moof_content.extend_from_slice(&traf);
        let mut moof = make_box(b"moof", &moof_content);

        let moof_children = scan_boxes(&moof, 8, moof.len()).unwrap();
        let traf_box = moof_children
            .iter()
            .copied()
            .find(|(_, h)| h.box_type == *b"traf")
            .unwrap();
        let traf_children = scan_boxes(
            &moof,
            traf_box.0 + traf_box.1.header_size,
            traf_box.0 + traf_box.1.size,
        )
        .unwrap();
        let trun_box = traf_children
            .iter()
            .copied()
            .find(|(_, h)| h.box_type == *b"trun")
            .unwrap();
        let data_offset_at = trun_box.0 + trun_box.1.header_size + 8;
        let sample_offset = (moof.len() + 8) as i32;
        moof[data_offset_at..data_offset_at + 4].copy_from_slice(&sample_offset.to_be_bytes());

        let mdat = make_box(b"mdat", payload);
        let mut out = moof;
        out.extend_from_slice(&mdat);
        out
    }

    fn top_boxes(bytes: &[u8]) -> Vec<(usize, BoxHeader)> {
        scan_boxes(bytes, 0, bytes.len()).unwrap()
    }

    fn child_box(bytes: &[u8], start: usize, end: usize, box_type: &[u8; 4]) -> (usize, BoxHeader) {
        scan_boxes(bytes, start, end)
            .unwrap()
            .into_iter()
            .find(|(_, h)| h.box_type == *box_type)
            .unwrap()
    }

    fn set_fullbox_version_and_flags(bytes: &mut [u8], box_off: usize, version: u8, flags: u32) {
        let header = read_box_header(bytes, box_off).unwrap();
        let content = box_off + header.header_size;
        bytes[content] = version;
        bytes[content + 1..content + 4].copy_from_slice(&flags.to_be_bytes()[1..]);
    }

    fn append_moof_child(segment: &mut Vec<u8>, child: Vec<u8>) {
        let top = top_boxes(segment);
        let (_, moof_h) = top[0];
        let mdat_off = top[1].0;
        let child_len = child.len();
        segment.splice(mdat_off..mdat_off, child);
        segment[..4].copy_from_slice(&((moof_h.size + child_len) as u32).to_be_bytes());
        let (traf_off, traf_h) = child_box(segment, 8, moof_h.size + child_len, b"traf");
        let (trun_off, trun_h) = child_box(segment, traf_off + 8, traf_off + traf_h.size, b"trun");
        let data_offset_at = trun_off + trun_h.header_size + 8;
        let old = i32::from_be_bytes(
            segment[data_offset_at..data_offset_at + 4]
                .try_into()
                .unwrap(),
        );
        segment[data_offset_at..data_offset_at + 4]
            .copy_from_slice(&(old + child_len as i32).to_be_bytes());
    }

    fn append_traf_child(segment: &mut Vec<u8>, child: Vec<u8>) {
        let top = top_boxes(segment);
        let (moof_off, moof_h) = top[0];
        let (traf_off, traf_h) = child_box(segment, moof_off + 8, moof_off + moof_h.size, b"traf");
        let insert_at = traf_off + traf_h.size;
        let child_len = child.len();
        segment.splice(insert_at..insert_at, child);
        segment[traf_off..traf_off + 4]
            .copy_from_slice(&((traf_h.size + child_len) as u32).to_be_bytes());
        segment[moof_off..moof_off + 4]
            .copy_from_slice(&((moof_h.size + child_len) as u32).to_be_bytes());
        let (trun_off, trun_h) = child_box(
            segment,
            traf_off + 8,
            traf_off + traf_h.size + child_len,
            b"trun",
        );
        let data_offset_at = trun_off + trun_h.header_size + 8;
        let old = i32::from_be_bytes(
            segment[data_offset_at..data_offset_at + 4]
                .try_into()
                .unwrap(),
        );
        segment[data_offset_at..data_offset_at + 4]
            .copy_from_slice(&(old + child_len as i32).to_be_bytes());
    }

    fn remove_moof_child(segment: &mut Vec<u8>, box_type: &[u8; 4]) {
        let top = top_boxes(segment);
        let (_, moof_h) = top[0];
        let (child_off, child_h) = child_box(segment, 8, moof_h.size, box_type);
        segment.drain(child_off..child_off + child_h.size);
        segment[..4].copy_from_slice(&((moof_h.size - child_h.size) as u32).to_be_bytes());
        let (traf_off, traf_h) = child_box(segment, 8, moof_h.size - child_h.size, b"traf");
        let (trun_off, trun_h) = child_box(segment, traf_off + 8, traf_off + traf_h.size, b"trun");
        let data_offset_at = trun_off + trun_h.header_size + 8;
        let old = i32::from_be_bytes(
            segment[data_offset_at..data_offset_at + 4]
                .try_into()
                .unwrap(),
        );
        segment[data_offset_at..data_offset_at + 4]
            .copy_from_slice(&(old - child_h.size as i32).to_be_bytes());
    }

    fn valid_segment(track_id: u32, payload: &[u8]) -> Vec<u8> {
        make_segment_with(track_id, payload, 0x020038, true, None)
    }

    fn make_clear_segment_with(
        track_id: u32,
        payload: &[u8],
        tfhd_flags: u32,
        include_tfdt: bool,
    ) -> Vec<u8> {
        let mut tfhd_payload = Vec::new();
        tfhd_payload.extend_from_slice(&track_id.to_be_bytes());
        if tfhd_flags & TFHD_FLAG_DEFAULT_SAMPLE_DURATION != 0 {
            tfhd_payload.extend_from_slice(&1u32.to_be_bytes());
        }
        if tfhd_flags & TFHD_FLAG_DEFAULT_SAMPLE_SIZE != 0 {
            tfhd_payload.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        }
        if tfhd_flags & TFHD_FLAG_DEFAULT_SAMPLE_FLAGS != 0 {
            tfhd_payload.extend_from_slice(&0u32.to_be_bytes());
        }
        let tfhd = make_fullbox(b"tfhd", 0, tfhd_flags, &tfhd_payload);

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
            if include_tfdt {
                traf_content.extend_from_slice(&make_fullbox(b"tfdt", 0, 0, &1u32.to_be_bytes()));
            }
            traf_content.extend_from_slice(&trun);
            make_box(b"traf", &traf_content)
        };
        let mfhd = make_fullbox(b"mfhd", 0, 0, &1u32.to_be_bytes());
        let mut moof_content = Vec::new();
        moof_content.extend_from_slice(&mfhd);
        moof_content.extend_from_slice(&traf);
        let mut moof = make_box(b"moof", &moof_content);

        let moof_children = scan_boxes(&moof, 8, moof.len()).unwrap();
        let traf_box = moof_children
            .iter()
            .copied()
            .find(|(_, h)| h.box_type == *b"traf")
            .unwrap();
        let traf_children = scan_boxes(
            &moof,
            traf_box.0 + traf_box.1.header_size,
            traf_box.0 + traf_box.1.size,
        )
        .unwrap();
        let trun_box = traf_children
            .iter()
            .copied()
            .find(|(_, h)| h.box_type == *b"trun")
            .unwrap();
        let data_offset_at = trun_box.0 + trun_box.1.header_size + 8;
        let sample_offset = (moof.len() + 8) as i32;
        moof[data_offset_at..data_offset_at + 4].copy_from_slice(&sample_offset.to_be_bytes());

        let mdat = make_box(b"mdat", payload);
        let mut out = moof;
        out.extend_from_slice(&mdat);
        out
    }

    fn valid_clear_segment(track_id: u32, payload: &[u8]) -> Vec<u8> {
        make_clear_segment_with(track_id, payload, 0x020038, true)
    }

    fn media_components() -> (Vec<u8>, Vec<Vec<u8>>, &'static str, &'static str) {
        (
            valid_init_segment(),
            vec![
                valid_segment(1, b"video-segment-ciphertext"),
                valid_segment(2, b"audio-segment-ciphertext"),
            ],
            "video/mp4",
            "avc1.64001f,mp4a.40.2",
        )
    }

    fn media() -> CencFmp4MediaIdentityV1 {
        let (init_segment, encrypted_segments, mime_type, codecs) = media_components();
        CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &encrypted_segments,
            mime_type,
            codecs,
        )
        .unwrap()
    }

    #[test]
    fn media_identity_is_ordered_and_deterministic() {
        let identity = media();
        let same = media();
        assert_eq!(identity, same);
        let (init_segment, encrypted_segments, mime_type, codecs) = media_components();
        let reversed = CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &[encrypted_segments[1].clone(), encrypted_segments[0].clone()],
            mime_type,
            codecs,
        )
        .unwrap();
        assert_ne!(identity.encrypted_content(), reversed.encrypted_content());
        assert_ne!(
            identity.media_manifest_root(),
            reversed.media_manifest_root()
        );
    }

    #[test]
    fn media_identity_rejects_empty_segments_and_distinguishes_init_media_and_ciphertext() {
        let base = media();
        let (init_segment, encrypted_segments, mime_type, codecs) = media_components();
        assert!(CencFmp4MediaIdentityV1::new_from_bytes(
            b"",
            &[encrypted_segments[0].clone()],
            mime_type,
            "avc1"
        )
        .is_err());
        assert!(
            CencFmp4MediaIdentityV1::new_from_bytes(&init_segment, &[], mime_type, "avc1").is_err()
        );
        assert!(CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &[encrypted_segments[0].clone(), Vec::new()],
            mime_type,
            codecs
        )
        .is_err());

        let mut changed_init_bytes = init_segment.clone();
        let changed_init_last = changed_init_bytes.len() - 1;
        changed_init_bytes[changed_init_last] ^= 1;
        let changed_init = CencFmp4MediaIdentityV1::new_from_bytes(
            &changed_init_bytes,
            &encrypted_segments,
            mime_type,
            codecs,
        )
        .unwrap();
        assert_eq!(base.encrypted_content(), changed_init.encrypted_content());
        assert_ne!(
            base.media_manifest_root(),
            changed_init.media_manifest_root()
        );

        let mut changed_second_segment = encrypted_segments[1].clone();
        let last = changed_second_segment.len() - 1;
        changed_second_segment[last] ^= 1;
        let changed_segment = CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &[encrypted_segments[0].clone(), changed_second_segment],
            mime_type,
            codecs,
        )
        .unwrap();
        assert_ne!(
            base.encrypted_content(),
            changed_segment.encrypted_content()
        );
        assert_ne!(
            base.media_manifest_root(),
            changed_segment.media_manifest_root()
        );

        let changed_mime = CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &encrypted_segments,
            "audio/mp4",
            codecs,
        )
        .unwrap();
        assert_eq!(base.encrypted_content(), changed_mime.encrypted_content());
        assert_ne!(
            base.media_manifest_root(),
            changed_mime.media_manifest_root()
        );

        let changed_codecs = CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &encrypted_segments,
            mime_type,
            "hev1.1.6.L93.B0,mp4a.40.2",
        )
        .unwrap();
        assert_eq!(base.encrypted_content(), changed_codecs.encrypted_content());
        assert_ne!(
            base.media_manifest_root(),
            changed_codecs.media_manifest_root()
        );
    }

    #[test]
    fn media_identity_rejects_invalid_declarations_and_segment_count_overflow() {
        let (init_segment, encrypted_segments, mime_type, _) = media_components();
        assert!(CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &[encrypted_segments[0].clone()],
            "",
            "avc1"
        )
        .is_err());
        assert!(CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &[encrypted_segments[0].clone()],
            mime_type,
            ""
        )
        .is_err());
        assert!(CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &[encrypted_segments[0].clone()],
            "v".repeat(256),
            "avc1"
        )
        .is_err());
        assert!(CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &[encrypted_segments[0].clone()],
            mime_type,
            "a".repeat(256)
        )
        .is_err());
        assert!(CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &vec![encrypted_segments[0].clone(); 513],
            mime_type,
            "avc1"
        )
        .is_err());
        assert!(CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &[Vec::new()],
            mime_type,
            "avc1"
        )
        .is_err());
    }

    #[test]
    fn media_structure_reports_exact_sample_layout() {
        let init = valid_init_segment();
        let segment_bytes = make_segment_with(1, b"abcdef", 0x020038, true, Some(&[(2, 4)]));
        let layout = CencFmp4MediaIdentityV1::validate_structure(
            &init,
            std::slice::from_ref(&segment_bytes),
        )
        .unwrap();
        assert_eq!(
            layout.init_segment_sha256(),
            Digest32::new(Sha256::digest(&init).into())
        );
        assert_eq!(layout.init_segment_bytes(), init.len() as u64);
        assert_eq!(layout.protected_track_ids(), &[1, 2]);
        assert_eq!(layout.segments().len(), 1);
        let segment = &layout.segments()[0];
        assert_eq!(
            segment.source_sha256(),
            Digest32::new(Sha256::digest(&segment_bytes).into())
        );
        assert_eq!(segment.source_bytes(), segment_bytes.len() as u64);
        assert_eq!(segment.track_id(), 1);
        assert_eq!(segment.samples().len(), 1);
        let sample = &segment.samples()[0];
        assert_eq!(sample.ciphertext_offset(), 0);
        assert_eq!(sample.sample_size(), 6);
        assert_eq!(sample.iv(), (0x10u64 + 1).to_be_bytes());
        assert_eq!(sample.subsamples().len(), 1);
        assert_eq!(sample.subsamples()[0].clear_bytes(), 2);
        assert_eq!(sample.subsamples()[0].encrypted_bytes(), 4);
    }

    #[test]
    fn clear_media_session_layout_accepts_direct_clear_fixture_and_reports_sample_ranges() {
        let init = valid_clear_init_segment();
        let segment = valid_clear_segment(1, b"clear-video");
        let session = ValidatedClearFmp4MediaSessionLayoutV1::new(&init).unwrap();
        let segment_layout = session.validate_segment(&segment).unwrap();

        assert_eq!(session.track_ids(), &[1, 2]);
        assert_eq!(session.tracks.len(), 2);
        assert_eq!(session.tracks[0].original_fourcc, *b"avc1");
        assert_eq!(session.tracks[1].original_fourcc, *b"mp4a");
        assert!(session.tracks[0].sample_entry_off > 0);
        assert_eq!(segment_layout.track_id(), 1);
        assert_eq!(segment_layout.samples().len(), 1);
        assert_eq!(segment_layout.samples()[0].mdat_offset(), 0);
        assert_eq!(segment_layout.samples()[0].sample_size(), 11);
    }

    #[test]
    fn clear_media_session_layout_keeps_codec_config_children_through_protect_round_trip() {
        // Real encoders emit codec configuration inside the sample entry
        // (`avcC` is mandatory for AVC; ffmpeg also adds `colr`). The clear
        // validator must accept them, the protect rewrite must keep them and
        // append `sinf` after them, and the clear rewrite must restore the
        // original bytes exactly.
        let avcc = make_box(b"avcC", &[0x01, 0x64, 0x00, 0x28, 0xff, 0xe1, 0x00, 0x00]);
        let colr = make_box(b"colr", b"nclx\0\x01\0\x01\0\x01\0");
        let esds = make_fullbox(b"esds", 0, 0, &[0x03, 0x00]);
        let clear_init = clear_init_segment_with_traks([
            make_clear_trak_with_entry(
                1,
                b"vide",
                make_clear_sample_entry_with_children(b"vide", &[avcc.clone(), colr.clone()]),
            ),
            make_clear_trak_with_entry(
                2,
                b"soun",
                make_clear_sample_entry_with_children(b"soun", &[esds]),
            ),
        ]);
        let session = ValidatedClearFmp4MediaSessionLayoutV1::new(&clear_init).unwrap();
        assert_eq!(session.track_ids(), &[1, 2]);

        let protected_init = session
            .rewrite_protected_init(&clear_init, &test_pssh_data())
            .unwrap();
        let clear_segment = valid_clear_segment(1, b"clear-video");
        let protected_segment = session
            .validate_segment(&clear_segment)
            .unwrap()
            .rewrite_protected_segment(&clear_segment, &[b"encrypted!!".to_vec()], &[[0x11; 8]])
            .unwrap();
        let protected_layout = CencFmp4MediaIdentityV1::validate_structure(
            &protected_init,
            std::slice::from_ref(&protected_segment),
        )
        .unwrap();
        assert_eq!(protected_layout.protected_track_ids(), &[1, 2]);

        // The video entry now reads encv, still carries avcC + colr, and has
        // sinf appended after them.
        let (fourcc, entry_off, entry_size, fixed) = sample_entry_info(&protected_init, 0);
        assert_eq!(fourcc, *b"encv");
        let children: Vec<[u8; 4]> = scan_boxes(
            &protected_init,
            entry_off + 8 + fixed,
            entry_off + entry_size,
        )
        .unwrap()
        .into_iter()
        .map(|(_, h)| h.box_type)
        .collect();
        assert_eq!(children, vec![*b"avcC", *b"colr", *b"sinf"]);

        let restored = protected_layout
            .rewrite_clear_init(&protected_init)
            .unwrap();
        assert_eq!(restored, clear_init);
    }

    #[test]
    fn clear_media_session_layout_rejects_sample_entry_that_already_carries_sinf() {
        let sinf = make_sinf(b"avc1");
        let init = clear_init_segment_with_traks([
            make_clear_trak_with_entry(
                1,
                b"vide",
                make_clear_sample_entry_with_children(b"vide", &[sinf]),
            ),
            make_clear_trak(2, b"soun"),
        ]);
        assert!(ValidatedClearFmp4MediaSessionLayoutV1::new(&init).is_err());
    }

    #[test]
    fn clear_media_session_layout_rejects_unsupported_sample_entry_and_unknown_track() {
        let mut bad_init = valid_clear_init_segment();
        let (moov_off, moov_h) = child_box(&bad_init, 0, bad_init.len(), b"moov");
        let (trak_off, trak_h) =
            child_box(&bad_init, moov_off + 8, moov_off + moov_h.size, b"trak");
        let (mdia_off, mdia_h) =
            child_box(&bad_init, trak_off + 8, trak_off + trak_h.size, b"mdia");
        let (minf_off, minf_h) =
            child_box(&bad_init, mdia_off + 8, mdia_off + mdia_h.size, b"minf");
        let (stbl_off, stbl_h) =
            child_box(&bad_init, minf_off + 8, minf_off + minf_h.size, b"stbl");
        let (stsd_off, _) = child_box(&bad_init, stbl_off + 8, stbl_off + stbl_h.size, b"stsd");
        let entry_off = stsd_off + 16;
        bad_init[entry_off + 4..entry_off + 8].copy_from_slice(b"encv");
        assert!(ValidatedClearFmp4MediaSessionLayoutV1::new(&bad_init).is_err());

        let session =
            ValidatedClearFmp4MediaSessionLayoutV1::new(&valid_clear_init_segment()).unwrap();
        let wrong_track = valid_clear_segment(9, b"clear-video");
        assert!(session.validate_segment(&wrong_track).is_err());
    }

    #[test]
    fn clear_media_session_layout_rejects_bad_offsets_truncation_and_sample_count_or_size_overflow()
    {
        let session =
            ValidatedClearFmp4MediaSessionLayoutV1::new(&valid_clear_init_segment()).unwrap();

        let mut bad_data_offset = valid_clear_segment(1, b"clear-video");
        let top = top_boxes(&bad_data_offset);
        let (traf_off, traf_h) = child_box(&bad_data_offset, 8, top[0].1.size, b"traf");
        let (trun_off, trun_h) = child_box(
            &bad_data_offset,
            traf_off + 8,
            traf_off + traf_h.size,
            b"trun",
        );
        let data_offset_at = trun_off + trun_h.header_size + 8;
        bad_data_offset[data_offset_at..data_offset_at + 4].copy_from_slice(&0i32.to_be_bytes());
        assert!(session.validate_segment(&bad_data_offset).is_err());

        let mut huge_sample = valid_clear_segment(1, b"clear-video");
        huge_sample[data_offset_at + 4..data_offset_at + 8]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(session.validate_segment(&huge_sample).is_err());

        let mut huge_count = valid_clear_segment(1, b"clear-video");
        let sample_count_at = trun_off + trun_h.header_size + 4;
        huge_count[sample_count_at..sample_count_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(session.validate_segment(&huge_count).is_err());

        let truncated = valid_clear_segment(1, b"clear-video")[..30].to_vec();
        assert!(session.validate_segment(&truncated).is_err());

        let mut malformed_bounds = valid_clear_segment(1, b"clear-video");
        malformed_bounds[..4].copy_from_slice(&0xFFFF_FFF0u32.to_be_bytes());
        assert!(session.validate_segment(&malformed_bounds).is_err());
    }

    #[test]
    fn clear_media_rewrite_produces_valid_protected_bytes() {
        let clear_init = valid_clear_init_segment();
        let clear_segment = valid_clear_segment(1, b"clear-video");
        let session = ValidatedClearFmp4MediaSessionLayoutV1::new(&clear_init).unwrap();
        let segment_layout = session.validate_segment(&clear_segment).unwrap();

        let protected_init = session
            .rewrite_protected_init(&clear_init, &test_pssh_data())
            .unwrap();
        let protected_segment = segment_layout
            .rewrite_protected_segment(
                &clear_segment,
                &[b"encrypted!!".to_vec()],
                &[[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]],
            )
            .unwrap();

        let protected_layout = CencFmp4MediaIdentityV1::validate_structure(
            &protected_init,
            std::slice::from_ref(&protected_segment),
        )
        .unwrap();
        assert_eq!(protected_layout.protected_track_ids(), &[1, 2]);
        assert_eq!(protected_layout.segments()[0].track_id(), 1);
        assert_eq!(
            protected_layout.segments()[0].samples()[0].iv(),
            [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]
        );
        assert_eq!(
            protected_layout.segments()[0]
                .exact_source_mdat_payload(&protected_segment)
                .unwrap(),
            b"encrypted!!"
        );
    }

    #[test]
    fn clear_media_rewrite_rejects_mutated_source_bad_counts_duplicate_iv_and_bad_sample_length() {
        let clear_init = valid_clear_init_segment();
        let clear_segment = valid_clear_segment(1, b"clear-video");
        let session = ValidatedClearFmp4MediaSessionLayoutV1::new(&clear_init).unwrap();
        let segment_layout = session.validate_segment(&clear_segment).unwrap();

        let mut tampered_init = clear_init.clone();
        tampered_init[0] ^= 1;
        assert!(session
            .rewrite_protected_init(&tampered_init, &test_pssh_data())
            .is_err());

        let mut tampered_segment = clear_segment.clone();
        tampered_segment[0] ^= 1;
        assert!(segment_layout
            .rewrite_protected_segment(
                &tampered_segment,
                &[b"encrypted!!".to_vec()],
                &[[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]],
            )
            .is_err());

        assert!(segment_layout
            .rewrite_protected_segment(&clear_segment, &[], &[])
            .is_err());
        assert!(segment_layout
            .rewrite_protected_segment(
                &clear_segment,
                &[b"encrypted!!".to_vec()],
                &[
                    [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11],
                    [0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22],
                ],
            )
            .is_err());
        assert!(segment_layout
            .rewrite_protected_segment(
                &clear_segment,
                &[b"short".to_vec()],
                &[[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]],
            )
            .is_err());
        assert!(segment_layout
            .rewrite_protected_segment(
                &clear_segment,
                &[b"encrypted!!".to_vec()],
                &[[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]],
            )
            .is_ok());
        assert!(segment_layout
            .rewrite_protected_segment(
                &clear_segment,
                &[b"encrypted!!".to_vec()],
                &[[0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]],
            )
            .is_ok());
    }

    fn sample_entry_info(bytes: &[u8], track_index: usize) -> ([u8; 4], usize, usize, usize) {
        let (_, moov_h) = child_box(bytes, 0, bytes.len(), b"moov");
        let moov_off = child_box(bytes, 0, bytes.len(), b"moov").0;
        let tracks: Vec<_> =
            scan_boxes(bytes, moov_off + moov_h.header_size, moov_off + moov_h.size)
                .unwrap()
                .into_iter()
                .filter(|(_, h)| h.box_type == *b"trak")
                .collect();
        let (trak_off, trak_h) = tracks[track_index];
        let (mdia_off, mdia_h) = child_box(bytes, trak_off + 8, trak_off + trak_h.size, b"mdia");
        let (hdlr_off, hdlr_h) = child_box(bytes, mdia_off + 8, mdia_off + mdia_h.size, b"hdlr");
        let handler_type = parse_hdlr_type(bytes, hdlr_off, hdlr_h).unwrap();
        let (minf_off, minf_h) = child_box(bytes, mdia_off + 8, mdia_off + mdia_h.size, b"minf");
        let (stbl_off, stbl_h) = child_box(bytes, minf_off + 8, minf_off + minf_h.size, b"stbl");
        let (stsd_off, _) = child_box(bytes, stbl_off + 8, stbl_off + stbl_h.size, b"stsd");
        let entry_off = stsd_off + 16;
        let entry_h = read_box_header(bytes, entry_off).unwrap();
        let fixed = if handler_type == *b"vide" {
            VISUAL_SAMPLE_ENTRY_FIXED_BYTES
        } else if handler_type == *b"soun" {
            AUDIO_SAMPLE_ENTRY_FIXED_BYTES
        } else {
            unreachable!()
        };
        (entry_h.box_type, entry_off, entry_h.size, fixed)
    }

    #[test]
    fn media_layout_rewrites_every_validated_track_in_init() {
        let init = valid_init_segment();
        let segment = valid_segment(1, b"video-segment-ciphertext");
        let layout = CencFmp4MediaIdentityV1::validate_structure(&init, &[segment]).unwrap();

        let rewritten = layout.rewrite_clear_init(&init).unwrap();
        let (video_type, video_entry_off, video_entry_size, video_fixed) =
            sample_entry_info(&rewritten, 0);
        let (audio_type, audio_entry_off, audio_entry_size, audio_fixed) =
            sample_entry_info(&rewritten, 1);

        assert_eq!(video_type, *b"avc1");
        assert_eq!(audio_type, *b"mp4a");
        assert!(scan_boxes(
            &rewritten,
            video_entry_off + 8 + video_fixed,
            video_entry_off + video_entry_size,
        )
        .unwrap()
        .is_empty());
        assert!(scan_boxes(
            &rewritten,
            audio_entry_off + 8 + audio_fixed,
            audio_entry_off + audio_entry_size,
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn media_layout_rewrites_segment_with_exact_source_and_offsets() {
        let init = valid_init_segment();
        let segment = make_segment_with(1, b"abcdef", 0x020038, true, Some(&[(2, 4)]));
        let layout =
            CencFmp4MediaIdentityV1::validate_structure(&init, std::slice::from_ref(&segment))
                .unwrap();

        let rewritten = layout
            .rewrite_clear_segment(0, &segment, b"ABCDEF")
            .unwrap();
        let top = top_boxes(&rewritten);
        let (moof_off, moof_h) = top[0];
        let (mdat_off, mdat_h) = top[1];
        let (traf_off, traf_h) =
            child_box(&rewritten, moof_off + 8, moof_off + moof_h.size, b"traf");
        let traf_children = scan_boxes(&rewritten, traf_off + 8, traf_off + traf_h.size).unwrap();
        assert!(traf_children.iter().all(|(_, h)| h.box_type != *b"senc"));
        let (trun_off, trun_h) =
            child_box(&rewritten, traf_off + 8, traf_off + traf_h.size, b"trun");
        let data_offset = read_i32_at(&rewritten, trun_off + trun_h.header_size + 8).unwrap();
        assert_eq!(
            usize::try_from(data_offset).unwrap(),
            mdat_off + mdat_h.header_size
        );
        assert_eq!(
            &rewritten[mdat_off + mdat_h.header_size..mdat_off + mdat_h.size],
            b"ABCDEF"
        );
    }

    #[test]
    fn media_layout_rewrite_fails_closed_for_changed_bytes_and_wrong_segment_index() {
        let init = valid_init_segment();
        let segment = valid_segment(1, b"video-segment-ciphertext");
        let layout =
            CencFmp4MediaIdentityV1::validate_structure(&init, std::slice::from_ref(&segment))
                .unwrap();

        let mut tampered_init = init.clone();
        tampered_init[0] ^= 1;
        assert!(layout.rewrite_clear_init(&tampered_init).is_err());

        let mut tampered_segment = segment.clone();
        tampered_segment[0] ^= 1;
        assert!(layout
            .rewrite_clear_segment(0, &tampered_segment, b"video-segment-ciphertext")
            .is_err());
        assert!(layout
            .rewrite_clear_segment(1, &segment, b"video-segment-ciphertext")
            .is_err());
    }

    #[test]
    fn media_layout_rewrite_helpers_reject_extended_size_malformed_and_underflow() {
        let mut extended = Vec::new();
        extended.extend_from_slice(&1u32.to_be_bytes());
        extended.extend_from_slice(b"test");
        extended.extend_from_slice(&24u64.to_be_bytes());
        extended.extend_from_slice(&[0u8; 8]);
        shrink_box_size_in_place(&mut extended, 0, 8, "test").unwrap();
        assert_eq!(read_u64_at(&extended, 8).unwrap(), 16);

        let mut malformed = Vec::new();
        malformed.extend_from_slice(&1u32.to_be_bytes());
        malformed.extend_from_slice(b"test");
        malformed.extend_from_slice(&8u64.to_be_bytes());
        assert!(shrink_box_size_in_place(&mut malformed, 0, 1, "test").is_err());

        let mut standard = make_box(b"test", &[]);
        assert!(shrink_box_size_in_place(&mut standard, 0, 1, "test").is_err());
    }

    /// `pssh` is the ONE box admitted into `moov` beyond the fixed allowlist, and
    /// only after it parses as this scheme's own protection header. Every other
    /// shape of `pssh` — and every other unknown box — still fails closed.
    #[test]
    fn media_structure_admits_only_a_well_formed_elacity_pssh_in_moov() {
        let valid_segment = valid_segment(1, b"video-segment-ciphertext");
        // `make_sinf` keys the fixture's `tenc` to this id, so the box's KID list
        // and its JSON payload must both name it.
        let fixture_key_id = [0x44u8; 16];
        let data = test_pssh_data_for(fixture_key_id);
        let good = PROTECTION.encode_custody(&data).unwrap();

        // An init segment with NO `pssh` is still valid: every media minted before
        // this box existed must keep validating.
        assert!(CencFmp4MediaIdentityV1::validate_structure(
            &build_init_segment(&[(1, b"vide"), (2, b"soun")], &[1, 2], &[]),
            std::slice::from_ref(&valid_segment),
        )
        .is_ok());

        let accepted = build_init_segment(
            &[(1, b"vide"), (2, b"soun")],
            &[1, 2],
            std::slice::from_ref(&good),
        );
        let layout = CencFmp4MediaIdentityV1::validate_structure(
            &accepted,
            std::slice::from_ref(&valid_segment),
        )
        .expect("a well-formed Elacity pssh is accepted");
        // And the read path takes it straight back out.
        assert_eq!(
            layout.rewrite_clear_init(&accepted).unwrap(),
            rewrite_clear_init_of(&build_init_segment(
                &[(1, b"vide"), (2, b"soun")],
                &[1, 2],
                &[]
            )),
        );

        let good_data = parse_pssh_v1(&good).unwrap().data;
        let foreign_system_id = {
            let mut id = *ELASTOS_CUSTODY_POOL.id.as_bytes();
            id[0] ^= 0xff;
            build_pssh_v1(&id, &[fixture_key_id], &good_data)
        };
        let unparseable_data = build_pssh_v1(
            ELASTOS_CUSTODY_POOL.id.as_bytes(),
            &[fixture_key_id],
            b"not-json-at-all",
        );
        let wrong_scheme =
            box_with_edited_data(&good, ELASTOS_CUSTODY_POOL.id.as_bytes(), |json| {
                json["protection_scheme"] = serde_json::json!("cenc:some-other-scheme");
            });
        let kid_not_in_payload = build_pssh_v1(
            ELASTOS_CUSTODY_POOL.id.as_bytes(),
            &[[0x99u8; 16]],
            &good_data,
        );
        let kid_is_a_different_track_key = PROTECTION
            .encode_custody(&test_pssh_data_for([0x99; 16]))
            .expect("a pssh for some other key id still builds");
        let empty_kid_list = build_pssh_v1(ELASTOS_CUSTODY_POOL.id.as_bytes(), &[], &good_data);
        let malformed = make_box(b"pssh", b"x");

        for rejected in [
            foreign_system_id,
            unparseable_data,
            wrong_scheme,
            kid_not_in_payload,
            kid_is_a_different_track_key,
            empty_kid_list,
            malformed,
        ] {
            assert!(
                CencFmp4MediaIdentityV1::validate_structure(
                    &build_init_segment(
                        &[(1, b"vide"), (2, b"soun")],
                        &[1, 2],
                        std::slice::from_ref(&rejected)
                    ),
                    std::slice::from_ref(&valid_segment),
                )
                .is_err(),
                "a pssh that is not this scheme's must be refused"
            );
        }

        // Two boxes, and a box that is not `moov`'s last child, are both refused:
        // the read path removes exactly one box from exactly one place.
        assert!(CencFmp4MediaIdentityV1::validate_structure(
            &build_init_segment(
                &[(1, b"vide"), (2, b"soun")],
                &[1, 2],
                &[good.clone(), good.clone()]
            ),
            std::slice::from_ref(&valid_segment),
        )
        .is_err());
        assert!(CencFmp4MediaIdentityV1::validate_structure(
            &build_init_segment(
                &[(1, b"vide"), (2, b"soun")],
                &[1, 2],
                &[good, make_box(b"udta", b"trailing")]
            ),
            std::slice::from_ref(&valid_segment),
        )
        .is_err());
    }

    fn rewrite_clear_init_of(protected_init_without_pssh: &[u8]) -> Vec<u8> {
        let valid_segment = valid_segment(1, b"video-segment-ciphertext");
        CencFmp4MediaIdentityV1::validate_structure(
            protected_init_without_pssh,
            std::slice::from_ref(&valid_segment),
        )
        .unwrap()
        .rewrite_clear_init(protected_init_without_pssh)
        .unwrap()
    }

    #[test]
    fn media_structure_rejects_invalid_init_and_segment_grammar() {
        let valid_init = valid_init_segment();
        let valid_segment = valid_segment(1, b"video-segment-ciphertext");

        assert!(CencFmp4MediaIdentityV1::validate_structure(
            &build_init_segment(&[(1, b"vide"), (1, b"soun")], &[1, 1], &[]),
            std::slice::from_ref(&valid_segment),
        )
        .is_err());
        assert!(CencFmp4MediaIdentityV1::validate_structure(
            &build_init_segment(&[(0, b"vide"), (2, b"soun")], &[0, 2], &[]),
            std::slice::from_ref(&valid_segment),
        )
        .is_err());
        assert!(CencFmp4MediaIdentityV1::validate_structure(
            &build_init_segment(&[(1, b"vide"), (2, b"soun")], &[1], &[]),
            std::slice::from_ref(&valid_segment),
        )
        .is_err());
        assert!(CencFmp4MediaIdentityV1::validate_structure(
            &build_init_segment(&[(1, b"vide"), (2, b"soun")], &[1, 2, 3], &[]),
            std::slice::from_ref(&valid_segment),
        )
        .is_err());
        assert!(CencFmp4MediaIdentityV1::validate_structure(
            &build_init_segment(&[(1, b"vide"), (2, b"soun")], &[1, 1], &[]),
            std::slice::from_ref(&valid_segment),
        )
        .is_err());
        let many_children = (0..65).fold(Vec::new(), |mut bytes, _| {
            bytes.extend_from_slice(&make_box(b"free", b"x"));
            bytes
        });
        assert!(scan_boxes(&many_children, 0, many_children.len()).is_err());

        let mut unknown_top_level = valid_segment.clone();
        unknown_top_level.extend_from_slice(&make_box(b"free", b"x"));
        assert!(
            CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[unknown_top_level],)
                .is_err()
        );
        let mut unknown_moof_child = valid_segment.clone();
        append_moof_child(&mut unknown_moof_child, make_box(b"free", b"x"));
        assert!(
            CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[unknown_moof_child],)
                .is_err()
        );
        let mut unknown_traf_child = valid_segment.clone();
        append_traf_child(&mut unknown_traf_child, make_box(b"free", b"x"));
        assert!(
            CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[unknown_traf_child],)
                .is_err()
        );
        assert!(CencFmp4MediaIdentityV1::validate_structure(
            &valid_init,
            &[make_segment_with(
                9,
                b"video-segment-ciphertext",
                0x020038,
                true,
                None
            )],
        )
        .is_err());

        let zero_subsample_segment =
            make_segment_with(1, b"video-segment-ciphertext", 0x020038, true, Some(&[]));
        assert!(CencFmp4MediaIdentityV1::validate_structure(
            &valid_init,
            &[zero_subsample_segment],
        )
        .is_err());
    }

    #[test]
    fn media_structure_rejects_strict_box_mutations() {
        let valid_init = valid_init_segment();
        let valid_segment = valid_segment(1, b"video-segment-ciphertext");

        let mut frma_wrong = valid_init.clone();
        let (moov_off, moov_h) = child_box(&frma_wrong, 0, frma_wrong.len(), b"moov");
        let (trak_off, trak_h) =
            child_box(&frma_wrong, moov_off + 8, moov_off + moov_h.size, b"trak");
        let (mdia_off, mdia_h) =
            child_box(&frma_wrong, trak_off + 8, trak_off + trak_h.size, b"mdia");
        let (minf_off, minf_h) =
            child_box(&frma_wrong, mdia_off + 8, mdia_off + mdia_h.size, b"minf");
        let (stbl_off, stbl_h) =
            child_box(&frma_wrong, minf_off + 8, minf_off + minf_h.size, b"stbl");
        let (stsd_off, _) = child_box(&frma_wrong, stbl_off + 8, stbl_off + stbl_h.size, b"stsd");
        let entry_off = stsd_off + 16;
        let entry_h = read_box_header(&frma_wrong, entry_off).unwrap();
        let sinf_off = child_box(
            &frma_wrong,
            entry_off + entry_h.header_size + VISUAL_SAMPLE_ENTRY_FIXED_BYTES,
            entry_off + entry_h.size,
            b"sinf",
        )
        .0;
        let frma_off = child_box(
            &frma_wrong,
            sinf_off + 8,
            sinf_off + read_box_header(&frma_wrong, sinf_off).unwrap().size,
            b"frma",
        )
        .0;
        frma_wrong[frma_off + 8..frma_off + 12].copy_from_slice(b"mp4a");
        assert!(CencFmp4MediaIdentityV1::validate_structure(
            &frma_wrong,
            std::slice::from_ref(&valid_segment)
        )
        .is_err());

        let mut missing_mfhd = valid_segment.clone();
        remove_moof_child(&mut missing_mfhd, b"mfhd");
        assert!(CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[missing_mfhd]).is_err());

        let mut duplicate_mfhd = valid_segment.clone();
        append_moof_child(
            &mut duplicate_mfhd,
            make_fullbox(b"mfhd", 0, 0, &1u32.to_be_bytes()),
        );
        assert!(
            CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[duplicate_mfhd]).is_err()
        );

        let mut duplicate_tfhd = valid_segment.clone();
        append_traf_child(
            &mut duplicate_tfhd,
            make_fullbox(
                b"tfhd",
                0,
                0x020038,
                &[0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 24, 0, 0, 0, 0],
            ),
        );
        assert!(
            CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[duplicate_tfhd]).is_err()
        );

        let mut duplicate_trun = valid_segment.clone();
        append_traf_child(
            &mut duplicate_trun,
            make_fullbox(
                b"trun",
                0,
                0x000205,
                &[0, 0, 0, 1, 0, 0, 0, 40, 0, 0, 0, 24],
            ),
        );
        assert!(
            CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[duplicate_trun]).is_err()
        );

        let mut duplicate_senc = valid_segment.clone();
        let mut senc_payload = Vec::new();
        senc_payload.extend_from_slice(&1u32.to_be_bytes());
        senc_payload.extend_from_slice(&(0x11u64).to_be_bytes());
        append_traf_child(
            &mut duplicate_senc,
            make_fullbox(b"senc", 0, 0, &senc_payload),
        );
        assert!(
            CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[duplicate_senc]).is_err()
        );

        let mut duplicate_tfdt = valid_segment.clone();
        append_traf_child(
            &mut duplicate_tfdt,
            make_fullbox(b"tfdt", 0, 0, &1u32.to_be_bytes()),
        );
        assert!(
            CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[duplicate_tfdt]).is_err()
        );

        let mut wrong_mfhd_version = valid_segment.clone();
        let mfhd_off = child_box(
            &wrong_mfhd_version,
            8,
            top_boxes(&wrong_mfhd_version)[0].1.size,
            b"mfhd",
        )
        .0;
        set_fullbox_version_and_flags(&mut wrong_mfhd_version, mfhd_off, 1, 0);
        assert!(
            CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[wrong_mfhd_version])
                .is_err()
        );

        let mut wrong_tfdt_version = valid_segment.clone();
        let top = top_boxes(&wrong_tfdt_version);
        let (traf_off, traf_h) = child_box(&wrong_tfdt_version, 8, top[0].1.size, b"traf");
        let tfdt_off = child_box(
            &wrong_tfdt_version,
            traf_off + 8,
            traf_off + traf_h.size,
            b"tfdt",
        )
        .0;
        set_fullbox_version_and_flags(&mut wrong_tfdt_version, tfdt_off, 2, 0);
        assert!(
            CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[wrong_tfdt_version])
                .is_err()
        );

        let mut wrong_tfhd_flags = valid_segment.clone();
        let top = top_boxes(&wrong_tfhd_flags);
        let (traf_off, traf_h) = child_box(&wrong_tfhd_flags, 8, top[0].1.size, b"traf");
        let tfhd_off = child_box(
            &wrong_tfhd_flags,
            traf_off + 8,
            traf_off + traf_h.size,
            b"tfhd",
        )
        .0;
        set_fullbox_version_and_flags(&mut wrong_tfhd_flags, tfhd_off, 0, 0x020039);
        assert!(
            CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[wrong_tfhd_flags]).is_err()
        );

        let mut wrong_trun_flags = valid_segment.clone();
        let top = top_boxes(&wrong_trun_flags);
        let (traf_off, traf_h) = child_box(&wrong_trun_flags, 8, top[0].1.size, b"traf");
        let trun_off = child_box(
            &wrong_trun_flags,
            traf_off + 8,
            traf_off + traf_h.size,
            b"trun",
        )
        .0;
        set_fullbox_version_and_flags(&mut wrong_trun_flags, trun_off, 0, 0);
        assert!(
            CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[wrong_trun_flags]).is_err()
        );

        let mut wrong_senc_flags = valid_segment.clone();
        let top = top_boxes(&wrong_senc_flags);
        let (traf_off, traf_h) = child_box(&wrong_senc_flags, 8, top[0].1.size, b"traf");
        let senc_off = child_box(
            &wrong_senc_flags,
            traf_off + 8,
            traf_off + traf_h.size,
            b"senc",
        )
        .0;
        set_fullbox_version_and_flags(&mut wrong_senc_flags, senc_off, 0, 0x000003);
        assert!(
            CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[wrong_senc_flags]).is_err()
        );

        let mut malformed_bounds = valid_segment.clone();
        malformed_bounds[..4].copy_from_slice(&0xFFFF_FFF0u32.to_be_bytes());
        assert!(
            CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[malformed_bounds]).is_err()
        );

        let truncated_segment = valid_segment[..valid_segment.len() - 1].to_vec();
        assert!(
            CencFmp4MediaIdentityV1::validate_structure(&valid_init, &[truncated_segment]).is_err()
        );
    }

    #[test]
    fn media_identity_round_trips_and_rejects_canonical_mutation_and_trailing_bytes() {
        let media = media();
        let bytes = media.canonical_bytes().unwrap();
        let decoded = CencFmp4MediaIdentityV1::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, media);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            CencFmp4MediaIdentityV1::from_canonical_bytes(&trailing),
            Err(ContractError::TrailingBytes)
        );

        let mut mutated = bytes.clone();
        let last = mutated.len() - 1;
        mutated[last] ^= 1;
        assert!(CencFmp4MediaIdentityV1::from_canonical_bytes(&mutated).is_err());

        let mut segment_length_mutated = bytes.clone();
        let last_segment = media
            .encrypted_segments()
            .last()
            .unwrap()
            .canonical_bytes()
            .unwrap();
        let last_segment_offset = bytes
            .windows(last_segment.len())
            .rposition(|window| window == last_segment.as_slice())
            .unwrap();
        let segment_length_offset = last_segment_offset - 2;
        segment_length_mutated[segment_length_offset + 1] ^= 1;
        assert!(CencFmp4MediaIdentityV1::from_canonical_bytes(&segment_length_mutated).is_err());

        let mut segment_digest_mutated = bytes.clone();
        segment_digest_mutated
            [last_segment_offset + CENC_FMP4_SEGMENT_IDENTITY_DOMAIN_V1.len() + 1] ^= 1;
        assert!(CencFmp4MediaIdentityV1::from_canonical_bytes(&segment_digest_mutated).is_err());
    }

    #[test]
    fn media_identity_has_stable_golden_vector() {
        let bytes = media().canonical_bytes().unwrap();
        assert_eq!(bytes.len(), 453);
        let digest = Sha256::digest(&bytes);
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            write!(&mut hex, "{byte:02x}").unwrap();
        }
        assert_eq!(
            hex,
            "3f544bcc0257f5ed6d5f4c67726a03abeacd0511bcd1efd9911bfa3defb6b6da"
        );
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hex = String::with_capacity(64);
        for byte in Sha256::digest(bytes) {
            write!(&mut hex, "{byte:02x}").unwrap();
        }
        hex
    }

    /// V1 bytes are frozen: these digests were taken on the pre-v2 code
    /// (756b55da), so any change to a V1 protect or clear rewrite shows here.
    #[test]
    fn v1_protect_and_clear_rewrites_have_stable_golden_bytes() {
        let clear_init = valid_clear_init_segment();
        let clear_segment = valid_clear_segment(1, b"clear-video");
        let session = ValidatedClearFmp4MediaSessionLayoutV1::new(&clear_init).unwrap();
        let protected_init = session
            .rewrite_protected_init(&clear_init, &test_pssh_data())
            .unwrap();
        let protected_segment = session
            .validate_segment(&clear_segment)
            .unwrap()
            .rewrite_protected_segment(&clear_segment, &[b"encrypted!!".to_vec()], &[[0x11; 8]])
            .unwrap();
        let layout = CencFmp4MediaIdentityV1::validate_structure(
            &protected_init,
            std::slice::from_ref(&protected_segment),
        )
        .unwrap();
        assert_eq!(
            layout.rewrite_clear_init(&protected_init).unwrap(),
            clear_init
        );
        assert_eq!(
            layout
                .rewrite_clear_segment(0, &protected_segment, b"clear-video")
                .unwrap(),
            clear_segment
        );
        assert_eq!(
            (protected_init.len(), sha256_hex(&protected_init)),
            (
                1300,
                "49bf4f571e0dfd3cf5c27b24215c94f5d97a7f7c812dcab8faa42d2958d97ba0".to_string()
            )
        );
        assert_eq!(
            (protected_segment.len(), sha256_hex(&protected_segment)),
            (
                143,
                "774112fa1935c94b8c124c07b29fb5d25cf297d9fd8c7876100ff1e1807362e8".to_string()
            )
        );
    }

    /// The V1 fMP4 writer now encodes through the writer binding, so its output
    /// differs from the pre-refactor bytes only in the 16 system-id bytes.
    #[test]
    fn v1_output_changed_only_in_its_system_id() {
        let clear_init = valid_clear_init_segment();
        let session = ValidatedClearFmp4MediaSessionLayoutV1::new(&clear_init).unwrap();
        let protected = session
            .rewrite_protected_init(&clear_init, &test_pssh_data())
            .unwrap();
        let writer_id = PROTECTION.writer().id;
        let at = protected
            .windows(16)
            .position(|w| w == writer_id.as_bytes())
            .unwrap();
        assert_eq!(
            protected
                .windows(16)
                .filter(|w| *w == writer_id.as_bytes())
                .count(),
            1
        );
        let mut legacy = protected;
        legacy[at..at + 16].copy_from_slice(ELASTOS_CUSTODY_LEGACY.id.as_bytes());
        assert_eq!(
            (legacy.len(), sha256_hex(&legacy)),
            (
                1300,
                "fae1a0886f80b28b245de74ffc8e9058364a5d4e4b28061c54c378cd52ab8d33".to_string()
            )
        );
    }

    #[test]
    fn v1_session_reports_whether_the_active_encoder_wrote_it() {
        let clear_init = valid_clear_init_segment();
        let session = ValidatedClearFmp4MediaSessionLayoutV1::new(&clear_init).unwrap();
        let protected = session
            .rewrite_protected_init(&clear_init, &test_pssh_data())
            .unwrap();
        let segment = vec![valid_segment(1, b"video-segment-ciphertext")];
        let media_of = |init: &[u8]| {
            let media = CencFmp4MediaIdentityV1::new_from_bytes(
                init,
                &segment,
                "video/mp4",
                "avc1.64001f,mp4a.40.2",
            )
            .unwrap();
            ValidatedCencFmp4MediaSessionLayoutV1::new(&media, init).unwrap()
        };
        assert!(media_of(&protected).protected_by_active_encoder());
        let mut legacy = protected;
        let at = legacy
            .windows(16)
            .position(|w| w == PROTECTION.writer().id.as_bytes())
            .unwrap();
        legacy[at..at + 16].copy_from_slice(ELASTOS_CUSTODY_LEGACY.id.as_bytes());
        assert!(!media_of(&legacy).protected_by_active_encoder());
    }

    #[test]
    fn media_session_layout_accepts_fixture_and_matches_full_layout() {
        let (init_segment, encrypted_segments, mime_type, codecs) = media_components();
        let media = CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &encrypted_segments,
            mime_type,
            codecs,
        )
        .unwrap();
        let session = ValidatedCencFmp4MediaSessionLayoutV1::new(&media, &init_segment).unwrap();
        let full_layout =
            CencFmp4MediaIdentityV1::validate_structure(&init_segment, &encrypted_segments)
                .unwrap();

        assert_eq!(session.media_identity(), &media);
        assert_eq!(
            session.protected_track_ids(),
            full_layout.protected_track_ids()
        );
        assert_eq!(
            session.rewrite_clear_init(&init_segment).unwrap(),
            full_layout.rewrite_clear_init(&init_segment).unwrap()
        );
        for (index, expected_segment) in full_layout.segments().iter().enumerate() {
            assert_eq!(
                session
                    .validate_indexed_segment(index, &encrypted_segments[index])
                    .unwrap(),
                *expected_segment
            );
        }
        let debug = format!("{session:?}");
        assert!(!debug.contains("path"));
        assert!(!debug.contains("route"));
        assert!(!debug.contains("share"));
        assert!(!debug.contains("credential"));
        assert!(!debug.contains("handle"));
    }

    #[test]
    fn media_session_layout_rejects_wrong_init_and_changed_identity() {
        let (init_segment, encrypted_segments, mime_type, codecs) = media_components();
        let media = CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &encrypted_segments,
            mime_type,
            codecs,
        )
        .unwrap();
        let mut tampered_init = init_segment.clone();
        tampered_init[0] ^= 1;
        assert!(ValidatedCencFmp4MediaSessionLayoutV1::new(&media, &tampered_init).is_err());

        let other_init = build_init_segment(&[(1, b"vide")], &[1], &[]);
        let other_segments = vec![valid_segment(1, b"video-segment-ciphertext")];
        let other_media = CencFmp4MediaIdentityV1::new_from_bytes(
            &other_init,
            &other_segments,
            mime_type,
            codecs,
        )
        .unwrap();
        assert!(ValidatedCencFmp4MediaSessionLayoutV1::new(&other_media, &init_segment).is_err());
    }

    #[test]
    fn media_session_layout_rejects_wrong_index_segment_substitution_changed_bytes_and_unknown_track(
    ) {
        let (init_segment, encrypted_segments, mime_type, codecs) = media_components();
        let media = CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &encrypted_segments,
            mime_type,
            codecs,
        )
        .unwrap();
        let session = ValidatedCencFmp4MediaSessionLayoutV1::new(&media, &init_segment).unwrap();

        assert!(session
            .validate_indexed_segment(encrypted_segments.len(), &encrypted_segments[0])
            .is_err());
        assert!(session
            .validate_indexed_segment(0, &encrypted_segments[1])
            .is_err());
        assert!(session
            .validate_indexed_segment(1, &encrypted_segments[0])
            .is_err());

        let mut tampered_segment = encrypted_segments[0].clone();
        tampered_segment[0] ^= 1;
        assert!(session
            .validate_indexed_segment(0, &tampered_segment)
            .is_err());

        let unknown_track_segment =
            make_segment_with(9, b"video-segment-ciphertext", 0x020038, true, None);
        assert!(session
            .validate_indexed_segment(0, &unknown_track_segment)
            .is_err());
    }
}

#[cfg(test)]
pub(crate) mod v2_tests {
    use elastos_protected_content_contracts::{
        CustodyCommitteeAuthorizationIdentityV1, CustodyEpochIdentityV1, CustodyPoolIdentityV1,
    };

    use super::*;
    use crate::protection_system::conformance::sample_box;
    use crate::protection_system::{COMMON, ELASTOS_CUSTODY_LEGACY, ELASTOS_CUSTODY_POOL};
    use crate::pssh::build_pssh_v1;

    pub(crate) const KID: [u8; 16] = [0x55; 16];
    const TRACK_ID: u32 = 1;
    pub(crate) const TIMESCALE: u32 = 15360;
    const DEFAULT_DURATION: u32 = 512;
    pub(crate) const WIDEVINE_SYSTEM_ID: [u8; 16] = [
        0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21,
        0xed,
    ];
    const PLAYREADY_SYSTEM_ID: [u8; 16] = [
        0x9a, 0x04, 0xf0, 0x79, 0x98, 0x40, 0x42, 0x86, 0xab, 0x92, 0xe6, 0x5b, 0xe0, 0x88, 0x5f,
        0x95,
    ];
    pub(crate) const V: CencDashRenditionKindV2 = CencDashRenditionKindV2::Video;
    pub(crate) const A: CencDashRenditionKindV2 = CencDashRenditionKindV2::Audio;

    fn bx(box_type: &[u8; 4], content: &[u8]) -> Vec<u8> {
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

    fn identities() -> (
        CustodyPoolIdentityV1,
        CustodyEpochIdentityV1,
        CustodyCommitteeAuthorizationIdentityV1,
    ) {
        (
            CustodyPoolIdentityV1::new(Digest32::new([0x61; 32]), 512).unwrap(),
            CustodyEpochIdentityV1::new(Digest32::new([0x62; 32]), 512).unwrap(),
            CustodyCommitteeAuthorizationIdentityV1::new(Digest32::new([0x63; 32]), 512).unwrap(),
        )
    }

    pub(crate) fn pssh_data_v2() -> CustodyProtectionHeader {
        let (pool, epoch, authorization) = identities();
        CustodyProtectionHeader::new(
            ContentAccessIdV1::new(KID).unwrap(),
            &pool,
            &epoch,
            &authorization,
            CencMediaSuite::DashV2,
        )
    }

    pub(crate) fn pssh_data_v1() -> CustodyProtectionHeader {
        let (pool, epoch, authorization) = identities();
        CustodyProtectionHeader::new(
            ContentAccessIdV1::new(KID).unwrap(),
            &pool,
            &epoch,
            &authorization,
            CencMediaSuite::Fmp4V1,
        )
    }

    pub(crate) fn pssh_v0(system_id: &[u8; 16], data: &[u8]) -> Vec<u8> {
        let mut payload = system_id.to_vec();
        payload.extend_from_slice(&(data.len() as u32).to_be_bytes());
        payload.extend_from_slice(data);
        fbx(b"pssh", 0, 0, &payload)
    }

    fn avcc(length_size_minus_one: u8) -> Vec<u8> {
        bx(
            b"avcC",
            &[
                1,
                0x64,
                0x00,
                0x1f,
                0xfc | length_size_minus_one,
                0xe0,
                0x00,
            ],
        )
    }

    fn sinf(original: &[u8; 4], iv_size: u8) -> Vec<u8> {
        let mut schm = b"cenc".to_vec();
        schm.extend_from_slice(&0x0001_0000u32.to_be_bytes());
        let mut tenc = vec![0, 0, 1, iv_size];
        tenc.extend_from_slice(&KID);
        bx(
            b"sinf",
            &[
                bx(b"frma", original),
                fbx(b"schm", 0, 0, &schm),
                bx(b"schi", &fbx(b"tenc", 0, 0, &tenc)),
            ]
            .concat(),
        )
    }

    /// One-track init. `protected_iv` adds `sinf` (and `encv`/`enca`);
    /// `pssh_after_mvhd` / `pssh_at_end` place `pssh` boxes like Bento4 / us.
    pub(crate) struct InitSpec {
        kind: CencDashRenditionKindV2,
        protected_iv: Option<u8>,
        avcc: Option<Vec<u8>>,
        pssh_after_mvhd: Vec<Vec<u8>>,
        pub(crate) pssh_at_end: Vec<Vec<u8>>,
        second_track: bool,
    }

    impl InitSpec {
        pub(crate) fn clear(kind: CencDashRenditionKindV2) -> Self {
            Self {
                kind,
                protected_iv: None,
                avcc: Some(avcc(3)),
                pssh_after_mvhd: Vec::new(),
                pssh_at_end: Vec::new(),
                second_track: false,
            }
        }

        pub(crate) fn protected(kind: CencDashRenditionKindV2, iv_size: u8) -> Self {
            Self {
                protected_iv: Some(iv_size),
                ..Self::clear(kind)
            }
        }
    }

    fn trak(track_id: u32, spec: &InitSpec) -> Vec<u8> {
        let mut tkhd = vec![0u8; 12];
        tkhd[8..12].copy_from_slice(&track_id.to_be_bytes());
        let mut mdhd = vec![0u8; 20];
        mdhd[8..12].copy_from_slice(&TIMESCALE.to_be_bytes());
        let (handler, clear_fourcc, protected_fourcc) = match spec.kind {
            CencDashRenditionKindV2::Video => (b"vide", b"avc1", b"encv"),
            CencDashRenditionKindV2::Audio => (b"soun", b"mp4a", b"enca"),
        };
        let mut hdlr = vec![0u8; 4];
        hdlr.extend_from_slice(handler);
        hdlr.extend_from_slice(&[0u8; 13]);
        let mut entry = match spec.kind {
            CencDashRenditionKindV2::Video => {
                let mut fixed = vec![0u8; VISUAL_SAMPLE_ENTRY_FIXED_BYTES];
                fixed[24..26].copy_from_slice(&640u16.to_be_bytes());
                fixed[26..28].copy_from_slice(&360u16.to_be_bytes());
                if let Some(avcc) = &spec.avcc {
                    fixed.extend_from_slice(avcc);
                }
                fixed
            }
            CencDashRenditionKindV2::Audio => {
                let mut fixed = vec![0u8; AUDIO_SAMPLE_ENTRY_FIXED_BYTES];
                fixed[16..18].copy_from_slice(&2u16.to_be_bytes());
                fixed[24..28].copy_from_slice(&(48_000u32 << 16).to_be_bytes());
                fixed
            }
        };
        let fourcc = match spec.protected_iv {
            Some(iv_size) => {
                entry.extend_from_slice(&sinf(clear_fourcc, iv_size));
                protected_fourcc
            }
            None => clear_fourcc,
        };
        let mut stsd = vec![0, 0, 0, 0, 0, 0, 0, 1];
        stsd.extend_from_slice(&bx(fourcc, &entry));
        let minf = bx(b"minf", &bx(b"stbl", &bx(b"stsd", &stsd)));
        let mdia = bx(
            b"mdia",
            &[fbx(b"mdhd", 0, 0, &mdhd), fbx(b"hdlr", 0, 0, &hdlr), minf].concat(),
        );
        bx(b"trak", &[fbx(b"tkhd", 0, 0, &tkhd), mdia].concat())
    }

    pub(crate) fn init(spec: &InitSpec) -> Vec<u8> {
        let mut moov = bx(b"mvhd", &[0u8; 4]);
        for pssh in &spec.pssh_after_mvhd {
            moov.extend_from_slice(pssh);
        }
        moov.extend_from_slice(&trak(TRACK_ID, spec));
        let mut trex = TRACK_ID.to_be_bytes().to_vec();
        trex.extend_from_slice(&[0u8; 16]);
        let mut mvex = fbx(b"trex", 0, 0, &trex);
        if spec.second_track {
            moov.extend_from_slice(&trak(TRACK_ID + 1, spec));
            let mut trex = (TRACK_ID + 1).to_be_bytes().to_vec();
            trex.extend_from_slice(&[0u8; 16]);
            mvex.extend_from_slice(&fbx(b"trex", 0, 0, &trex));
        }
        moov.extend_from_slice(&bx(b"mvex", &mvex));
        for pssh in &spec.pssh_at_end {
            moov.extend_from_slice(pssh);
        }
        [bx(b"ftyp", b"iso6\0\0\0\0iso6dash"), bx(b"moov", &moov)].concat()
    }

    #[derive(Clone)]
    struct SegSpec {
        tfhd_flags: u32,
        sdi: u32,
        trun_version: u8,
        durations: Option<Vec<u32>>,
        tfdt: bool,
        decode_time: u64,
    }

    impl Default for SegSpec {
        fn default() -> Self {
            // Bento4's tfhd flags: default-base-is-moof, sdi, default duration
            // and default flags.
            Self {
                tfhd_flags: 0x02002a,
                sdi: 1,
                trun_version: 0,
                durations: None,
                tfdt: true,
                decode_time: 30_720,
            }
        }
    }

    fn traf_head(samples: &[Vec<u8>], spec: &SegSpec) -> Vec<Vec<u8>> {
        let mut tfhd = TRACK_ID.to_be_bytes().to_vec();
        if spec.tfhd_flags & TFHD_FLAG_SAMPLE_DESCRIPTION_INDEX != 0 {
            tfhd.extend_from_slice(&spec.sdi.to_be_bytes());
        }
        if spec.tfhd_flags & TFHD_FLAG_DEFAULT_SAMPLE_DURATION != 0 {
            tfhd.extend_from_slice(&DEFAULT_DURATION.to_be_bytes());
        }
        if spec.tfhd_flags & TFHD_FLAG_DEFAULT_SAMPLE_FLAGS != 0 {
            tfhd.extend_from_slice(&0u32.to_be_bytes());
        }
        let mut trun_flags = TRUN_FLAG_DATA_OFFSET | TRUN_FLAG_SAMPLE_SIZE;
        if spec.durations.is_some() {
            trun_flags |= TRUN_FLAG_SAMPLE_DURATION;
        }
        let mut trun = (samples.len() as u32).to_be_bytes().to_vec();
        trun.extend_from_slice(&0i32.to_be_bytes());
        for (index, sample) in samples.iter().enumerate() {
            if let Some(durations) = &spec.durations {
                trun.extend_from_slice(&durations[index].to_be_bytes());
            }
            trun.extend_from_slice(&(sample.len() as u32).to_be_bytes());
        }
        let mut head = vec![fbx(b"tfhd", 0, spec.tfhd_flags, &tfhd)];
        if spec.tfdt {
            head.push(fbx(b"tfdt", 1, 0, &spec.decode_time.to_be_bytes()));
        }
        head.push(fbx(b"trun", spec.trun_version, trun_flags, &trun));
        head
    }

    /// `moof(mfhd, traf(children))` + `mdat(samples)`, with `trun.data_offset`
    /// pointing at the first sample.
    fn assemble(children: &[Vec<u8>], samples: &[Vec<u8>]) -> Vec<u8> {
        let traf = bx(b"traf", &children.concat());
        let mut moof = bx(
            b"moof",
            &[fbx(b"mfhd", 0, 0, &1u32.to_be_bytes()), traf].concat(),
        );
        let traf_off = 8 + 16;
        let trun_off = traf_off
            + 8
            + children
                .iter()
                .take_while(|child| &child[4..8] != b"trun")
                .map(Vec::len)
                .sum::<usize>();
        let at = trun_off + 16;
        let data_offset = (moof.len() + 8) as i32;
        moof[at..at + 4].copy_from_slice(&data_offset.to_be_bytes());
        [moof, bx(b"mdat", &samples.concat())].concat()
    }

    fn clear_segment(samples: &[Vec<u8>], spec: &SegSpec) -> Vec<u8> {
        assemble(&traf_head(samples, spec), samples)
    }

    fn senc_box(ivs: &[Vec<u8>], subsamples: Option<&[Vec<(u16, u32)>]>) -> (Vec<u8>, Vec<u8>) {
        let mut payload = (ivs.len() as u32).to_be_bytes().to_vec();
        let mut sizes = Vec::new();
        for (index, iv) in ivs.iter().enumerate() {
            let start = payload.len();
            payload.extend_from_slice(iv);
            if let Some(subsamples) = subsamples {
                payload.extend_from_slice(&(subsamples[index].len() as u16).to_be_bytes());
                for (clear, encrypted) in &subsamples[index] {
                    payload.extend_from_slice(&clear.to_be_bytes());
                    payload.extend_from_slice(&encrypted.to_be_bytes());
                }
            }
            sizes.push((payload.len() - start) as u8);
        }
        let flags = if subsamples.is_some() { 2 } else { 0 };
        (fbx(b"senc", 0, flags, &payload), sizes)
    }

    fn saiz_box(sizes: &[u8]) -> Vec<u8> {
        let uniform = sizes.iter().all(|size| *size == sizes[0]);
        let mut payload = vec![if uniform { sizes[0] } else { 0 }];
        payload.extend_from_slice(&(sizes.len() as u32).to_be_bytes());
        if !uniform {
            payload.extend_from_slice(sizes);
        }
        fbx(b"saiz", 0, 0, &payload)
    }

    /// An independent builder of a V2 protected segment (Bento4 layout).
    fn protected_segment(
        samples: &[Vec<u8>],
        ivs: &[Vec<u8>],
        subsamples: Option<&[Vec<(u16, u32)>]>,
        spec: &SegSpec,
    ) -> Vec<u8> {
        let mut children = traf_head(samples, spec);
        let (senc, sizes) = senc_box(ivs, subsamples);
        let saiz = saiz_box(&sizes);
        let senc_in_moof =
            8 + 16 + 8 + children.iter().map(Vec::len).sum::<usize>() + saiz.len() + 20;
        let mut saio = 1u32.to_be_bytes().to_vec();
        saio.extend_from_slice(&((senc_in_moof + 16) as u32).to_be_bytes());
        children.extend([saiz, fbx(b"saio", 0, 0, &saio), senc]);
        assemble(&children, samples)
    }

    fn video_samples() -> Vec<Vec<u8>> {
        vec![vec![0x11; 300], vec![0x22; 200], vec![0x33; 150]]
    }

    fn video_subsamples() -> Vec<Vec<(u16, u32)>> {
        // The first sample has two entries, so `saiz` needs a table.
        vec![vec![(20, 80), (40, 160)], vec![(56, 144)], vec![(150, 0)]]
    }

    fn audio_samples() -> Vec<Vec<u8>> {
        vec![vec![0x44; 120], vec![0x55; 121], vec![0x66; 122]]
    }

    fn producer_ivs(count: usize) -> Vec<[u8; 8]> {
        (0..count)
            .map(|index| (0xabcd_0000_0000_0000u64 + index as u64).to_be_bytes())
            .collect()
    }

    fn xor(samples: &[Vec<u8>]) -> Vec<Vec<u8>> {
        samples
            .iter()
            .map(|sample| sample.iter().map(|byte| byte ^ 0xa5).collect())
            .collect()
    }

    pub(crate) struct Protected {
        pub(crate) clear_init: Vec<u8>,
        pub(crate) clear_segment: Vec<u8>,
        pub(crate) init: Vec<u8>,
        pub(crate) segment: Vec<u8>,
        pub(crate) samples: Vec<Vec<u8>>,
        pub(crate) subsamples: Option<Vec<Vec<(u16, u32)>>>,
    }

    pub(crate) fn protect(kind: CencDashRenditionKindV2, extra_pssh: &[Vec<u8>]) -> Protected {
        protect_in(&PROTECTION, kind, extra_pssh)
    }

    pub(crate) fn protect_in(
        ctx: &ProtectionContext<'_>,
        kind: CencDashRenditionKindV2,
        extra_pssh: &[Vec<u8>],
    ) -> Protected {
        let clear_init = init(&InitSpec::clear(kind));
        let layout = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
            &clear_init,
            CencLayoutProfile::V2,
        )
        .unwrap();
        let protected_init = layout
            .rewrite_protected_init_v2_in(ctx, &clear_init, &pssh_data_v2(), extra_pssh)
            .unwrap();
        let (samples, subsamples) = match kind {
            CencDashRenditionKindV2::Video => (video_samples(), Some(video_subsamples())),
            CencDashRenditionKindV2::Audio => (audio_samples(), None),
        };
        let clear_segment = clear_segment(&samples, &SegSpec::default());
        let segment_layout = layout.validate_segment(&clear_segment).unwrap();
        let protected_segment = segment_layout
            .rewrite_protected_segment_v2(
                &clear_segment,
                &xor(&samples),
                &producer_ivs(samples.len()),
                subsamples.as_deref().unwrap_or(&[]),
            )
            .unwrap();
        Protected {
            clear_init,
            clear_segment,
            init: protected_init,
            segment: protected_segment,
            samples,
            subsamples,
        }
    }

    /// A valid V1 protected segment for the fixture track.
    pub(crate) fn v1_segment() -> Vec<u8> {
        let mut tfhd = TRACK_ID.to_be_bytes().to_vec();
        tfhd.extend_from_slice(&DEFAULT_DURATION.to_be_bytes());
        let mut trun = 1u32.to_be_bytes().to_vec();
        trun.extend_from_slice(&0i32.to_be_bytes());
        trun.extend_from_slice(&4u32.to_be_bytes());
        let mut senc = 1u32.to_be_bytes().to_vec();
        senc.extend_from_slice(&[7u8; 8]);
        assemble(
            &[
                fbx(b"tfhd", 0, 0x020008, &tfhd),
                fbx(
                    b"trun",
                    0,
                    TRUN_FLAG_DATA_OFFSET | TRUN_FLAG_SAMPLE_SIZE,
                    &trun,
                ),
                fbx(b"senc", 0, 0, &senc),
            ],
            &[vec![1, 2, 3, 4]],
        )
    }

    fn validate(
        init: &[u8],
        segment: &[u8],
    ) -> Result<ValidatedCencFmp4MediaLayoutV1, ContractError> {
        validate_in(&PROTECTION, init, segment)
    }

    pub(crate) fn validate_in(
        ctx: &ProtectionContext<'_>,
        init: &[u8],
        segment: &[u8],
    ) -> Result<ValidatedCencFmp4MediaLayoutV1, ContractError> {
        validate_cenc_fmp4_media_structure_in(
            ctx,
            init,
            std::slice::from_ref(&segment.to_vec()),
            CencLayoutProfile::V2,
        )
    }

    fn box_at(bytes: &[u8], path: &[&[u8; 4]]) -> (usize, BoxHeader) {
        let mut found = (0, read_box_header(bytes, 0).unwrap());
        let (mut start, mut end) = (0, bytes.len());
        for box_type in path {
            found = scan_boxes(bytes, start, end)
                .unwrap()
                .into_iter()
                .find(|(_, h)| h.box_type == **box_type)
                .unwrap();
            start = found.0 + found.1.header_size;
            end = found.0 + found.1.size;
        }
        found
    }

    #[test]
    fn our_v2_output_validates_and_rewrites_back_to_the_exact_clear_bytes() {
        for kind in [V, A] {
            let protected = protect(kind, &[]);
            let layout = validate(&protected.init, &protected.segment).unwrap();
            assert_eq!(
                layout.rewrite_clear_init(&protected.init).unwrap(),
                protected.clear_init
            );
            let segment = &layout.segments()[0];
            let clear_mdat: Vec<u8> = protected.samples.concat();
            assert_eq!(
                segment
                    .rewrite_clear_segment(&protected.segment, &clear_mdat)
                    .unwrap(),
                protected.clear_segment
            );
            assert_eq!(
                segment.timeline(),
                Some(Fmp4SegmentTimelineV2 {
                    decode_time: 30_720,
                    duration: 3 * u64::from(DEFAULT_DURATION),
                })
            );
            let rendition = layout.rendition().unwrap();
            assert_eq!(rendition.kind(), kind);
            assert_eq!(rendition.timescale(), TIMESCALE);
            assert_eq!(layout.protection_header(), Some(&pssh_data_v2()));
            for (index, sample) in segment.samples().iter().enumerate() {
                assert_eq!(sample.iv(), producer_ivs(3)[index]);
                let expected: Vec<(u16, u32)> = protected
                    .subsamples
                    .as_ref()
                    .map(|maps| maps[index].clone())
                    .unwrap_or_default();
                let actual: Vec<(u16, u32)> = sample
                    .subsamples()
                    .iter()
                    .map(|entry| (entry.clear_bytes(), entry.encrypted_bytes()))
                    .collect();
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn our_v2_segment_matches_the_independent_bento4_layout_builder() {
        let video = protect(V, &[]);
        let ivs: Vec<Vec<u8>> = producer_ivs(3).iter().map(|iv| iv.to_vec()).collect();
        assert_eq!(
            video.segment,
            protected_segment(
                &xor(&video.samples),
                &ivs,
                Some(&video_subsamples()),
                &SegSpec::default()
            )
        );
        let audio = protect(A, &[]);
        assert_eq!(
            audio.segment,
            protected_segment(&xor(&audio.samples), &ivs, None, &SegSpec::default())
        );
    }

    #[test]
    fn v2_init_carries_common_extras_then_elastos_and_reports_the_rendition() {
        let widevine = pssh_v0(&WIDEVINE_SYSTEM_ID, b"widevine-dummy");
        let playready = build_pssh_v1(&PLAYREADY_SYSTEM_ID, &[KID], b"playready-dummy");
        let protected = protect(V, &[widevine.clone(), playready.clone()]);
        let moov_children: Vec<[u8; 4]> = {
            let (moov_off, moov_h) = box_at(&protected.init, &[b"moov"]);
            scan_boxes(&protected.init, moov_off + 8, moov_off + moov_h.size)
                .unwrap()
                .into_iter()
                .map(|(_, h)| h.box_type)
                .collect()
        };
        assert_eq!(
            moov_children,
            [*b"mvhd", *b"trak", *b"mvex", *b"pssh", *b"pssh", *b"pssh", *b"pssh"]
        );
        let common = build_pssh_v1(COMMON.id.as_bytes(), &[KID], &[]);
        let elastos = PROTECTION.encode_custody(&pssh_data_v2()).unwrap();
        let tail = [common, widevine, playready, elastos].concat();
        assert!(protected.init.ends_with(&tail));
        let layout = validate(&protected.init, &protected.segment).unwrap();
        assert_eq!(
            layout.rewrite_clear_init(&protected.init).unwrap(),
            protected.clear_init
        );
        assert_eq!(
            layout.rendition().unwrap().sample_entry(),
            Fmp4SampleEntryV2::Video {
                width: 640,
                height: 360,
                nal_length_size: 4
            }
        );
        let audio = protect(A, &[]);
        assert_eq!(
            validate(&audio.init, &audio.segment)
                .unwrap()
                .rendition()
                .unwrap()
                .sample_entry(),
            Fmp4SampleEntryV2::Audio {
                sample_rate: 48_000,
                channel_count: 2
            }
        );
    }

    #[test]
    fn bento4_style_init_and_16_byte_ivs_are_accepted_and_every_pssh_is_removed() {
        // Bento4 puts its pssh boxes before the track and writes 16-byte IVs, a
        // trun v1 with per-sample durations, and no Elastos box.
        let mut spec = InitSpec::protected(V, 16);
        spec.pssh_after_mvhd = vec![
            build_pssh_v1(COMMON.id.as_bytes(), &[KID], &[]),
            pssh_v0(&WIDEVINE_SYSTEM_ID, &[0x08; 40]),
        ];
        spec.pssh_at_end = vec![build_pssh_v1(&PLAYREADY_SYSTEM_ID, &[], &[0x50; 64])];
        let protected_init = init(&spec);
        let samples = video_samples();
        let ivs: Vec<Vec<u8>> = (0..3u8).map(|index| vec![index + 1; 16]).collect();
        let seg_spec = SegSpec {
            trun_version: 1,
            durations: Some(vec![500, 512, 524]),
            ..SegSpec::default()
        };
        let segment = protected_segment(&xor(&samples), &ivs, Some(&video_subsamples()), &seg_spec);
        let layout = validate(&protected_init, &segment).unwrap();
        assert_eq!(layout.protection_header(), None);
        assert_eq!(
            layout.rewrite_clear_init(&protected_init).unwrap(),
            init(&InitSpec::clear(V))
        );
        let validated = &layout.segments()[0];
        assert_eq!(validated.samples()[2].iv(), [3u8; 16]);
        assert_eq!(validated.timeline().unwrap().duration, 1536);
        assert_eq!(
            validated
                .rewrite_clear_segment(&segment, &samples.concat())
                .unwrap(),
            clear_segment(&samples, &seg_spec)
        );
    }

    /// Real Bento4 output; see `tests/fixtures/bento4/README.md`.
    const BENTO4_INIT: &[u8] = include_bytes!("../tests/fixtures/bento4/same-stream/init.mp4");
    const BENTO4_SEGMENT: &[u8] =
        include_bytes!("../tests/fixtures/bento4/same-stream/seg-1-first-2-samples.m4s");

    #[test]
    fn real_bento4_init_and_segment_are_accepted_and_rewrite_to_valid_clear_v2() {
        let layout = validate(BENTO4_INIT, BENTO4_SEGMENT).unwrap();
        assert!(validate_cenc_fmp4_media_structure_v1(
            BENTO4_INIT,
            &[BENTO4_SEGMENT.to_vec()],
            CencLayoutProfile::V1
        )
        .is_err());
        let rendition = layout.rendition().unwrap();
        assert_eq!(rendition.timescale(), 15360);
        assert_eq!(
            rendition.sample_entry(),
            Fmp4SampleEntryV2::Video {
                width: 1920,
                height: 1080,
                nal_length_size: 4
            }
        );
        assert_eq!(layout.protection_header(), None);
        let segment = &layout.segments()[0];
        let maps: Vec<Vec<(u16, u32)>> = segment
            .samples()
            .iter()
            .map(|sample| {
                assert_eq!(sample.iv().len(), 16);
                sample
                    .subsamples()
                    .iter()
                    .map(|entry| (entry.clear_bytes(), entry.encrypted_bytes()))
                    .collect()
            })
            .collect();
        assert_eq!(maps, [vec![(793, 21680)], vec![(110, 10992)]]);
        assert_eq!(segment.timeline().unwrap().decode_time, 0);
        assert!(segment.timeline().unwrap().duration > 0);

        // The clear rewrites drop every pssh, sinf and CENC box and stay valid V2.
        let clear_init = layout.rewrite_clear_init(BENTO4_INIT).unwrap();
        assert_eq!(
            BENTO4_INIT.len() - clear_init.len(),
            52 + 80,
            "the Common pssh and the sinf"
        );
        let clear_layout = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
            &clear_init,
            CencLayoutProfile::V2,
        )
        .unwrap();
        let mdat = segment.exact_source_mdat_payload(BENTO4_SEGMENT).unwrap();
        let clear_segment = segment.rewrite_clear_segment(BENTO4_SEGMENT, mdat).unwrap();
        let clear_segment_layout = clear_layout.validate_segment(&clear_segment).unwrap();
        assert_eq!(clear_segment_layout.timeline(), segment.timeline());
        assert_eq!(clear_segment_layout.samples().len(), 2);
    }

    /// A V2 protected init with Common-less, Elastos-less protection: valid, but
    /// without the custody binding.
    pub(crate) fn protected_init_without_elastos(kind: CencDashRenditionKindV2) -> Vec<u8> {
        init(&InitSpec::protected(kind, 8))
    }

    #[test]
    fn v2_validators_never_panic_on_truncated_or_flipped_input() {
        let video = protect(V, &[]);
        let audio = protect(A, &[]);
        let inputs = [
            (BENTO4_INIT.to_vec(), BENTO4_SEGMENT.to_vec()),
            (video.init, video.segment),
            (audio.init, audio.segment),
        ];
        let check = |init: &[u8], segment: &[u8]| {
            let _ = validate(init, segment);
            let _ = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
                init,
                CencLayoutProfile::V2,
            )
            .map(|layout| layout.validate_segment(segment));
        };
        for (init, segment) in &inputs {
            assert!(validate(init, segment).is_ok());
            for len in 0..init.len() {
                check(&init[..len], segment);
            }
            for len in 0..segment.len() {
                check(init, &segment[..len]);
            }
            for at in 0..init.len() {
                for value in [0x00, 0xff] {
                    let mut bytes = init.clone();
                    bytes[at] = value;
                    check(&bytes, segment);
                }
            }
            for at in 0..segment.len() {
                for value in [0x00, 0xff] {
                    let mut bytes = segment.clone();
                    bytes[at] = value;
                    check(init, &bytes);
                }
            }
        }
    }

    #[test]
    fn v2_segment_refuses_wrong_order_offsets_sizes_flags_and_header_fields() {
        let video = protect(V, &[]);
        assert!(validate(&video.init, &video.segment).is_ok());
        let (saiz_off, saiz_h) = box_at(&video.segment, &[b"moof", b"traf", b"saiz"]);
        let (saio_off, saio_h) = box_at(&video.segment, &[b"moof", b"traf", b"saio"]);
        let (senc_off, _) = box_at(&video.segment, &[b"moof", b"traf", b"senc"]);

        let mut swapped = video.segment.clone();
        let saiz = swapped[saiz_off..saiz_off + saiz_h.size].to_vec();
        let saio = swapped[saio_off..saio_off + saio_h.size].to_vec();
        swapped.splice(saiz_off..saio_off + saio_h.size, [saio, saiz].concat());
        assert!(validate(&video.init, &swapped).is_err(), "saio before saiz");
        for (box_off, renamed) in [(senc_off, b"senx"), (saiz_off, b"saix")] {
            let mut wrong_type = video.segment.clone();
            wrong_type[box_off + 4..box_off + 8].copy_from_slice(renamed);
            assert!(
                validate(&video.init, &wrong_type).is_err(),
                "unexpected child type"
            );
        }

        for delta in [1i64, -1] {
            let mut moved = video.segment.clone();
            let at = saio_off + 16;
            let offset = u32::from_be_bytes(moved[at..at + 4].try_into().unwrap());
            moved[at..at + 4].copy_from_slice(&((offset as i64 + delta) as u32).to_be_bytes());
            assert!(
                validate(&video.init, &moved).is_err(),
                "saio off by {delta}"
            );
        }

        let mut wrong_size = video.segment.clone();
        let table = saiz_off + 12 + 5;
        wrong_size[table] += 6;
        assert!(
            validate(&video.init, &wrong_size).is_err(),
            "saiz != senc entry"
        );

        let mut whole_sample_video = video.segment.clone();
        whole_sample_video[senc_off + 11] = 0;
        assert!(validate(&video.init, &whole_sample_video).is_err());
        let audio = protect(A, &[]);
        let (audio_senc, _) = box_at(&audio.segment, &[b"moof", b"traf", b"senc"]);
        let mut subsample_audio = audio.segment.clone();
        subsample_audio[audio_senc + 11] = 2;
        assert!(validate(&audio.init, &subsample_audio).is_err());

        let samples = video_samples();
        let ivs: Vec<Vec<u8>> = producer_ivs(3).iter().map(|iv| iv.to_vec()).collect();
        let subsamples = video_subsamples();
        let build =
            |spec: SegSpec| protected_segment(&xor(&samples), &ivs, Some(&subsamples), &spec);
        assert!(validate(&video.init, &build(SegSpec::default())).is_ok());
        for (label, spec) in [
            (
                "sdi 2",
                SegSpec {
                    sdi: 2,
                    ..SegSpec::default()
                },
            ),
            (
                "trun v2",
                SegSpec {
                    trun_version: 2,
                    ..SegSpec::default()
                },
            ),
            (
                "no tfdt",
                SegSpec {
                    tfdt: false,
                    ..SegSpec::default()
                },
            ),
            (
                "no duration",
                SegSpec {
                    tfhd_flags: 0x020022,
                    ..SegSpec::default()
                },
            ),
            (
                "zero duration",
                SegSpec {
                    durations: Some(vec![0, 0, 0]),
                    ..SegSpec::default()
                },
            ),
            (
                "base data offset",
                SegSpec {
                    tfhd_flags: 0x02002b,
                    ..SegSpec::default()
                },
            ),
        ] {
            assert!(validate(&video.init, &build(spec)).is_err(), "{label}");
        }

        let mut bad_sum = subsamples.clone();
        bad_sum[1] = vec![(56, 145)];
        let bad = protected_segment(&xor(&samples), &ivs, Some(&bad_sum), &SegSpec::default());
        assert!(
            validate(&video.init, &bad).is_err(),
            "subsamples != sample size"
        );

        let short_ivs: Vec<Vec<u8>> = ivs.iter().map(|iv| iv[..8].to_vec()).collect();
        let long_ivs: Vec<Vec<u8>> = (0..3u8).map(|index| vec![index; 16]).collect();
        let sixteen_init = init(&InitSpec::protected(V, 16));
        let eight_init = init(&InitSpec::protected(V, 8));
        let with = |ivs: &[Vec<u8>]| {
            protected_segment(&xor(&samples), ivs, Some(&subsamples), &SegSpec::default())
        };
        assert!(validate(&eight_init, &with(&short_ivs)).is_ok());
        assert!(validate(&sixteen_init, &with(&long_ivs)).is_ok());
        assert!(
            validate(&eight_init, &with(&long_ivs)).is_err(),
            "IV size != tenc"
        );
        assert!(
            validate(&sixteen_init, &with(&short_ivs)).is_err(),
            "IV size != tenc"
        );
    }

    #[test]
    fn v2_init_refuses_bad_iv_size_pssh_sets_and_shapes() {
        let segment = protect(V, &[]).segment;
        assert!(
            validate(&init(&InitSpec::protected(V, 12)), &segment).is_err(),
            "IV 12"
        );
        let accepts = |spec: InitSpec| validate(&init(&spec), &segment).is_ok();
        let elastos_v2 = PROTECTION.encode_custody(&pssh_data_v2()).unwrap();
        let elastos_v1 = PROTECTION.encode_custody(&pssh_data_v1()).unwrap();
        let with_end = |pssh: Vec<Vec<u8>>| InitSpec {
            pssh_at_end: pssh,
            ..InitSpec::protected(V, 8)
        };
        assert!(accepts(with_end(vec![elastos_v2.clone()])));
        assert!(
            !accepts(with_end(vec![elastos_v2.clone(), elastos_v2.clone()])),
            "two Elastos"
        );
        assert!(
            !accepts(with_end(vec![elastos_v1])),
            "V1 suite in a V2 init"
        );
        let (pool, epoch, authorization) = identities();
        let other_kid = PROTECTION
            .encode_custody(&CustodyProtectionHeader::new(
                ContentAccessIdV1::new([0x66; 16]).unwrap(),
                &pool,
                &epoch,
                &authorization,
                CencMediaSuite::DashV2,
            ))
            .unwrap();
        assert!(
            !accepts(with_end(vec![other_kid])),
            "Elastos box for another KID"
        );
        assert!(
            accepts(with_end(vec![pssh_v0(COMMON.id.as_bytes(), &[])])),
            "Common v0"
        );
        assert!(!accepts(with_end(vec![build_pssh_v1(
            COMMON.id.as_bytes(),
            &[[0x66; 16]],
            &[]
        )])));
        assert!(accepts(with_end(vec![build_pssh_v1(
            COMMON.id.as_bytes(),
            &[[0x66; 16], KID],
            &[]
        )])));
        let largest = pssh_v0(&WIDEVINE_SYSTEM_ID, &vec![0; MAX_PSSH_BOX_BYTES_V2 - 32]);
        assert_eq!(largest.len(), MAX_PSSH_BOX_BYTES_V2);
        assert!(accepts(with_end(vec![largest.clone()])));
        let oversized = pssh_v0(&WIDEVINE_SYSTEM_ID, &vec![0; MAX_PSSH_BOX_BYTES_V2 - 31]);
        assert!(!accepts(with_end(vec![oversized])), "box over 64 KiB");
        assert!(!accepts(with_end(vec![largest; 17])), "total over 1 MiB");
        let mut malformed = pssh_v0(&WIDEVINE_SYSTEM_ID, b"data");
        let len = malformed.len();
        malformed[len - 5] = 9; // data size larger than the box
        assert!(!accepts(with_end(vec![malformed])), "malformed pssh");
        let mut version_two = pssh_v0(&WIDEVINE_SYSTEM_ID, b"data");
        version_two[8] = 2;
        assert!(!accepts(with_end(vec![version_two])), "pssh version 2");

        assert!(!accepts(InitSpec {
            second_track: true,
            ..InitSpec::protected(V, 8)
        }));
        assert!(!accepts(InitSpec {
            avcc: None,
            ..InitSpec::protected(V, 8)
        }));
    }

    #[test]
    fn v2_clear_layout_requires_one_track_and_a_usable_avcc() {
        let new = |spec: InitSpec| {
            ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
                &init(&spec),
                CencLayoutProfile::V2,
            )
        };
        for length_size_minus_one in [0u8, 1, 3] {
            assert!(new(InitSpec {
                avcc: Some(avcc(length_size_minus_one)),
                ..InitSpec::clear(V)
            })
            .is_ok());
        }
        assert!(new(InitSpec {
            avcc: Some(avcc(2)),
            ..InitSpec::clear(V)
        })
        .is_err());
        assert!(new(InitSpec {
            avcc: None,
            ..InitSpec::clear(V)
        })
        .is_err());
        assert!(new(InitSpec {
            avcc: Some(bx(b"avcC", &[0, 0x64, 0, 0x1f, 0xff])),
            ..InitSpec::clear(V)
        })
        .is_err());
        assert!(new(InitSpec {
            second_track: true,
            ..InitSpec::clear(V)
        })
        .is_err());
        // The same two-track init is still a valid V1 clear init.
        assert!(
            ValidatedClearFmp4MediaSessionLayoutV1::new(&init(&InitSpec {
                second_track: true,
                ..InitSpec::clear(V)
            }))
            .is_ok()
        );
    }

    #[test]
    fn v2_clear_segment_rules_and_profile_methods_do_not_cross() {
        let clear_init = init(&InitSpec::clear(V));
        let v2 = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
            &clear_init,
            CencLayoutProfile::V2,
        )
        .unwrap();
        let v1 = ValidatedClearFmp4MediaSessionLayoutV1::new(&clear_init).unwrap();
        assert_eq!(v2.profile(), CencLayoutProfile::V2);
        assert_eq!(v1.profile(), CencLayoutProfile::V1);
        assert!(v1.rendition().is_none());
        let samples = video_samples();
        let bento_style = clear_segment(&samples, &SegSpec::default());
        // V1 refuses the sample-description-index field; V2 admits it as 1.
        assert!(v1.validate_segment(&bento_style).is_err());
        let v2_segment = v2.validate_segment(&bento_style).unwrap();
        let (tfdt_off, _) = box_at(&bento_style, &[b"moof", b"traf", b"tfdt"]);
        let mut renamed = bento_style.clone();
        renamed[tfdt_off + 4..tfdt_off + 8].copy_from_slice(b"tfdx");
        assert!(
            v2.validate_segment(&renamed).is_err(),
            "unexpected child type"
        );
        for (label, spec) in [
            (
                "sdi 2",
                SegSpec {
                    sdi: 2,
                    ..SegSpec::default()
                },
            ),
            (
                "no tfdt",
                SegSpec {
                    tfdt: false,
                    ..SegSpec::default()
                },
            ),
            (
                "no duration",
                SegSpec {
                    tfhd_flags: 0x020022,
                    ..SegSpec::default()
                },
            ),
        ] {
            assert!(
                v2.validate_segment(&clear_segment(&samples, &spec))
                    .is_err(),
                "{label}"
            );
        }
        let plain = SegSpec {
            tfhd_flags: 0x020008,
            durations: Some(vec![1, 2, 3]),
            trun_version: 1,
            ..SegSpec::default()
        };
        assert_eq!(
            v2.validate_segment(&clear_segment(&samples, &plain))
                .unwrap()
                .timeline()
                .unwrap()
                .duration,
            6
        );

        let pssh_v2 = pssh_data_v2();
        let ivs = producer_ivs(3);
        assert!(v2
            .rewrite_protected_init(&clear_init, &pssh_data_v1())
            .is_err());
        assert!(v1
            .rewrite_protected_init_v2(&clear_init, &pssh_v2, &[])
            .is_err());
        assert!(v2
            .rewrite_protected_init_v2(&clear_init, &pssh_data_v1(), &[])
            .is_err());
        assert!(v2_segment
            .rewrite_protected_segment(&bento_style, &xor(&samples), &ivs)
            .is_err());
        let v1_segment = v1
            .validate_segment(&clear_segment(
                &samples,
                &SegSpec {
                    tfhd_flags: 0x020008,
                    ..SegSpec::default()
                },
            ))
            .unwrap();
        assert!(v1_segment.timeline().is_none());
        assert!(v1_segment
            .rewrite_protected_segment_v2(&bento_style, &xor(&samples), &ivs, &video_subsamples())
            .is_err());
    }

    #[test]
    fn v2_protect_refuses_bad_subsamples_ivs_and_extra_pssh() {
        let clear_init = init(&InitSpec::clear(V));
        let layout = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
            &clear_init,
            CencLayoutProfile::V2,
        )
        .unwrap();
        let samples = video_samples();
        let clear = clear_segment(&samples, &SegSpec::default());
        let segment = layout.validate_segment(&clear).unwrap();
        let encrypted = xor(&samples);
        let ivs = producer_ivs(3);
        let protect = |ivs: &[[u8; 8]], subsamples: &[Vec<(u16, u32)>]| {
            segment.rewrite_protected_segment_v2(&clear, &encrypted, ivs, subsamples)
        };
        assert!(protect(&ivs, &video_subsamples()).is_ok());
        let mut short = video_subsamples();
        short[0] = vec![(20, 80)];
        assert!(
            protect(&ivs, &short).is_err(),
            "map does not cover the sample"
        );
        let mut empty = video_subsamples();
        empty[2] = Vec::new();
        assert!(protect(&ivs, &empty).is_err(), "empty map");
        assert!(protect(&ivs, &[]).is_err(), "video without maps");
        let duplicate = [ivs[0], ivs[0], ivs[2]];
        assert!(
            protect(&duplicate, &video_subsamples()).is_err(),
            "IV repeat"
        );
        // 8 + 2 + 6·41 = 256 does not fit a `saiz` entry; 40 entries do.
        let mut forty = video_subsamples();
        forty[0] = vec![(1, 6); 40];
        forty[0][39] = (1, 300 - 39 * 7 - 1);
        assert!(protect(&ivs, &forty).is_ok(), "40 entries fit");
        let mut forty_one = video_subsamples();
        forty_one[0] = vec![(1, 6); 41];
        forty_one[0][40] = (1, 300 - 40 * 7 - 1);
        assert!(protect(&ivs, &forty_one).is_err(), "saiz entry over 255");

        let audio_init = init(&InitSpec::clear(A));
        let audio = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
            &audio_init,
            CencLayoutProfile::V2,
        )
        .unwrap();
        let audio_samples = audio_samples();
        let audio_clear = clear_segment(&audio_samples, &SegSpec::default());
        let audio_segment = audio.validate_segment(&audio_clear).unwrap();
        assert!(
            audio_segment
                .rewrite_protected_segment_v2(
                    &audio_clear,
                    &xor(&audio_samples),
                    &ivs,
                    &[vec![(120, 0)], vec![(121, 0)], vec![(122, 0)]]
                )
                .is_err(),
            "audio is whole-sample"
        );

        let pssh = pssh_data_v2();
        let elastos = PROTECTION.encode_custody(&pssh).unwrap();
        for (label, extra) in [
            ("Elastos as extra", elastos),
            ("malformed", b"not a pssh box".to_vec()),
            (
                "trailing bytes",
                [pssh_v0(&WIDEVINE_SYSTEM_ID, b"x"), vec![0]].concat(),
            ),
            (
                "Common without KID",
                build_pssh_v1(COMMON.id.as_bytes(), &[[0x66; 16]], &[]),
            ),
            (
                "over 64 KiB",
                pssh_v0(&WIDEVINE_SYSTEM_ID, &vec![0; MAX_PSSH_BOX_BYTES_V2 - 31]),
            ),
        ] {
            assert!(
                layout
                    .rewrite_protected_init_v2(&clear_init, &pssh, &[extra])
                    .is_err(),
                "{label}"
            );
        }
    }

    #[test]
    fn v1_profile_refuses_v2_shapes_it_never_admitted() {
        // A V1 protected init still admits only one Elastos box, last, with the
        // V1 suite; a V2-suite box, a Common box or 16-byte IVs are refused.
        let v1_segment = v1_segment();
        let v1 = |spec: InitSpec| {
            CencFmp4MediaIdentityV1::validate_structure(
                &init(&spec),
                std::slice::from_ref(&v1_segment),
            )
        };
        let with_end = |pssh: Vec<Vec<u8>>| InitSpec {
            pssh_at_end: pssh,
            ..InitSpec::protected(V, 8)
        };
        assert!(v1(with_end(vec![])).is_ok());
        assert!(v1(with_end(vec![PROTECTION
            .encode_custody(&pssh_data_v1())
            .unwrap()]))
        .is_ok());
        assert!(v1(with_end(vec![PROTECTION
            .encode_custody(&pssh_data_v2())
            .unwrap()]))
        .is_err());
        // Any registered custody system is the custody box of a V1 init.
        for system in PROTECTION.registry().systems() {
            if system.is_custody() {
                assert!(v1(with_end(vec![sample_box(system, &pssh_data_v1())])).is_ok());
            }
        }
        assert!(v1(with_end(vec![build_pssh_v1(
            COMMON.id.as_bytes(),
            &[KID],
            &[]
        )]))
        .is_err());
        assert!(v1(InitSpec::protected(V, 16)).is_err());
    }
    const V1_BOX_LEN: usize = 718;
    const V1_BOX_SHA: &str = "9b17a53c60f48e17e8cc08f7544c16a48c5a7c4a6a02508a71c9bae9e8c37ea0";
    const V2_BOX_LEN: usize = 718;
    const V2_BOX_SHA: &str = "e305acf5a45ac3e2948db3316099f290fc5885fddb5975a44485f004e24189a9";
    const V2_INIT_LEN: usize = 1172;
    const V2_INIT_SHA: &str = "5fdecb70f61bce5bc180910ef6ab7ede0d1d11bfb83a6f68f298ca1774f4f986";

    fn pin_sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// The PSSH writer's bytes: the v1 custody box (identical to its pre-refactor
    /// bytes once the system id is put back to the legacy one), the v2 custody box
    /// and the v2 video init (both unchanged by the refactor).
    #[test]
    fn pssh_writer_bytes_are_pinned() {
        let v1_box = PROTECTION.encode_custody(&pssh_data_v1()).unwrap();
        let v2_box = PROTECTION.encode_custody(&pssh_data_v2()).unwrap();
        assert_eq!(&v1_box[12..28], PROTECTION.writer().id.as_bytes());
        let mut legacy_v1_box = v1_box;
        legacy_v1_box[12..28].copy_from_slice(ELASTOS_CUSTODY_LEGACY.id.as_bytes());
        assert_eq!(
            (legacy_v1_box.len(), pin_sha256_hex(&legacy_v1_box)),
            (V1_BOX_LEN, V1_BOX_SHA.to_string())
        );
        assert_eq!(
            (v2_box.len(), pin_sha256_hex(&v2_box)),
            (V2_BOX_LEN, V2_BOX_SHA.to_string())
        );
        let init = protect(V, &[]).init;
        assert_eq!(
            (init.len(), pin_sha256_hex(&init)),
            (V2_INIT_LEN, V2_INIT_SHA.to_string())
        );
    }

    #[test]
    fn every_writer_uses_the_pool_id_and_any_registered_custody_id_is_accepted() {
        let pool_id = PROTECTION.writer().id;
        let video = protect(V, &[]);
        let contains = |init: &[u8], id: &[u8; 16]| init.windows(16).any(|w| w == id);
        assert!(contains(&video.init, pool_id.as_bytes()));
        assert!(!contains(&video.init, ELASTOS_CUSTODY_LEGACY.id.as_bytes()));
        assert!(validate(&video.init, &video.segment).is_ok());

        // The same init with the legacy id is accepted too.
        let mut legacy = video.init.clone();
        let at = legacy
            .windows(16)
            .position(|w| w == pool_id.as_bytes())
            .unwrap();
        legacy[at..at + 16].copy_from_slice(ELASTOS_CUSTODY_LEGACY.id.as_bytes());
        assert!(validate(&legacy, &video.segment).is_ok());

        // At most one custody box, counting every custody id together.
        let pool = sample_box(&ELASTOS_CUSTODY_POOL, &pssh_data_v2());
        let old = sample_box(&ELASTOS_CUSTODY_LEGACY, &pssh_data_v2());
        let accepts = |pssh: Vec<Vec<u8>>| {
            let spec = InitSpec {
                pssh_at_end: pssh,
                ..InitSpec::protected(V, 8)
            };
            validate(&init(&spec), &video.segment).is_ok()
        };
        assert!(accepts(vec![pool.clone()]));
        assert!(accepts(vec![old.clone()]));
        assert!(!accepts(vec![pool.clone(), old.clone()]));
        assert!(!accepts(vec![old.clone(), pool.clone()]));
        assert!(!accepts(vec![pool.clone(), pool]));

        // A foreign extra may carry no custody id.
        let (clear_init, layout) = {
            let clear_init = init(&InitSpec::clear(V));
            let layout = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
                &clear_init,
                CencLayoutProfile::V2,
            )
            .unwrap();
            (clear_init, layout)
        };
        for system in PROTECTION.registry().systems() {
            if system.is_custody() {
                assert!(layout
                    .rewrite_protected_init_v2(
                        &clear_init,
                        &pssh_data_v2(),
                        &[pssh_v0(system.id.as_bytes(), b"x")]
                    )
                    .is_err());
            }
        }
    }
}

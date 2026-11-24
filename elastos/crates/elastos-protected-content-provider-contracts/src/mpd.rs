//! The deterministic DASH MPD of a v2 package (`protected-content/v2/stream.mpd`).
//!
//! The MPD is only for external players; the product player never reads it and
//! its integrity is the content object manifest's. The builder is pure: the same
//! inputs always give the same bytes (UTF-8, LF, 2-space indent, fixed element
//! and attribute order, no comments).

use std::fmt::Write as _;

use elastos_protected_content_contracts::{ContractError, Digest32};
use sha2::{Digest as _, Sha256};

use crate::media::{
    cenc_dash_init_pssh_boxes, CencDashRenditionKindV2, Fmp4SampleEntryV2, Fmp4SegmentTimelineV2,
    ValidatedCencDashInitV2,
};
use crate::protection_system::{
    ProtectionContext, ProtectionRegistry, ProtectionSystemId, PROTECTION,
};

const VIDEO_REPRESENTATION_ID_V2: &str = "video/avc1";
const AUDIO_REPRESENTATION_ID_V2: &str = "audio/und/mp4a";
const VIDEO_CODECS_V2: &str = "avc1.640028";
const AUDIO_CODECS_V2: &str = "mp4a.40.2";
const MIN_BUFFER_TIME_V2: &str = "PT2.000S";

/// One media segment as the MPD sees it: its place on the timeline and its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CencDashMpdSegmentV2 {
    pub timeline: Fmp4SegmentTimelineV2,
    pub bytes: u64,
}

/// One rendition: its protected init and its segments in order.
#[derive(Debug, Clone, Copy)]
pub struct CencDashMpdRenditionV2<'a> {
    pub protected_init: &'a [u8],
    pub segments: &'a [CencDashMpdSegmentV2],
}

/// Builds the MPD for 1 or 2 renditions (video first, then audio). Every init is
/// validated under V2, so `ContentProtection` is read from what the init holds.
pub fn build_cenc_dash_mpd_v2(
    renditions: &[CencDashMpdRenditionV2<'_>],
) -> Result<String, ContractError> {
    build_cenc_dash_mpd_v2_in(&PROTECTION, renditions)
}

pub(crate) fn build_cenc_dash_mpd_v2_in(
    ctx: &ProtectionContext<'_>,
    renditions: &[CencDashMpdRenditionV2<'_>],
) -> Result<String, ContractError> {
    if renditions.is_empty() || renditions.len() > 2 {
        return Err(ContractError::InvalidField("representation_count"));
    }
    let mut sets = Vec::with_capacity(renditions.len());
    let mut duration_ms = 0u64;
    for rendition in renditions {
        let set = AdaptationSetV2::new(ctx, rendition)?;
        duration_ms = duration_ms.max(set.end_ms()?);
        sets.push(set);
    }
    let mut kinds = sets.iter().map(|set| set.kind);
    if let (Some(first), Some(second)) = (kinds.next(), kinds.next()) {
        if first != CencDashRenditionKindV2::Video || second != CencDashRenditionKindV2::Audio {
            return Err(ContractError::InvalidField("representation_kind"));
        }
    }
    let mut mpd = String::new();
    mpd.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        mpd,
        "<MPD xmlns=\"urn:mpeg:dash:schema:mpd:2011\" xmlns:cenc=\"urn:mpeg:cenc:2013\" \
         profiles=\"urn:mpeg:dash:profile:isoff-live:2011\" type=\"static\" \
         minBufferTime=\"{MIN_BUFFER_TIME_V2}\" mediaPresentationDuration=\"{}\">",
        format_duration(duration_ms)
    );
    mpd.push_str("  <Period id=\"0\" start=\"PT0.000S\">\n");
    for set in &sets {
        set.write(&mut mpd);
    }
    mpd.push_str("  </Period>\n</MPD>\n");
    Ok(mpd)
}

struct AdaptationSetV2 {
    kind: CencDashRenditionKindV2,
    entry: Fmp4SampleEntryV2,
    timescale: u32,
    kid: [u8; 16],
    protection: Vec<(String, Option<&'static str>, String)>,
    runs: Vec<(u64, u64, u64)>,
    end_units: u64,
    bandwidth: u64,
}

impl AdaptationSetV2 {
    fn new(
        ctx: &ProtectionContext<'_>,
        rendition: &CencDashMpdRenditionV2<'_>,
    ) -> Result<Self, ContractError> {
        let init = ValidatedCencDashInitV2::new_in(
            ctx,
            rendition.protected_init,
            Digest32::new(Sha256::digest(rendition.protected_init).into()),
            rendition.protected_init.len() as u64,
        )?;
        let track = *init.rendition();
        let timescale = track.timescale();
        if rendition.segments.is_empty() || timescale == 0 {
            return Err(ContractError::InvalidField("mpd_timeline"));
        }
        let mut runs: Vec<(u64, u64, u64)> = Vec::new();
        let mut next = None;
        let mut bandwidth = 0u64;
        for segment in rendition.segments {
            let Fmp4SegmentTimelineV2 {
                decode_time,
                duration,
            } = segment.timeline;
            if duration == 0 || segment.bytes == 0 || next.is_some_and(|next| next != decode_time) {
                return Err(ContractError::InvalidField("mpd_timeline"));
            }
            next = Some(
                decode_time
                    .checked_add(duration)
                    .ok_or(ContractError::InvalidField("mpd_timeline"))?,
            );
            match runs.last_mut() {
                Some((_, run_duration, repeats)) if *run_duration == duration => *repeats += 1,
                _ => runs.push((decode_time, duration, 0)),
            }
            // ceil(8 · bytes · timescale / duration)
            let bits_per_second = (u128::from(segment.bytes) * 8 * u128::from(timescale))
                .div_ceil(u128::from(duration));
            bandwidth = bandwidth.max(
                u64::try_from(bits_per_second)
                    .map_err(|_| ContractError::InvalidField("mpd_bandwidth"))?,
            );
        }
        let mut protection = Vec::new();
        for pssh in cenc_dash_init_pssh_boxes(rendition.protected_init)? {
            let system_id: [u8; 16] = pssh
                .get(12..28)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(ContractError::InvalidField("init_segment_bytes"))?;
            let value = content_protection_value(&ctx.registry(), &system_id);
            protection.push((format_uuid(&system_id), value, base64(pssh)));
        }
        Ok(Self {
            kind: track.kind(),
            entry: track.sample_entry(),
            timescale,
            kid: *init.content_access_id().as_bytes(),
            protection,
            runs,
            end_units: next.unwrap_or(0),
            bandwidth,
        })
    }

    /// The end of the rendition in whole milliseconds, rounded up.
    fn end_ms(&self) -> Result<u64, ContractError> {
        let ms = (u128::from(self.end_units) * 1000).div_ceil(u128::from(self.timescale));
        u64::try_from(ms).map_err(|_| ContractError::InvalidField("mpd_timeline"))
    }

    fn write(&self, mpd: &mut String) {
        let (id, content_type, mime, extra) = match (self.kind, self.entry) {
            (CencDashRenditionKindV2::Video, Fmp4SampleEntryV2::Video { width, height, .. }) => (
                0,
                "video",
                "video/mp4",
                format!(" maxWidth=\"{width}\" maxHeight=\"{height}\""),
            ),
            _ => (1, "audio", "audio/mp4", String::new()),
        };
        let lang = if self.kind == CencDashRenditionKindV2::Audio {
            " lang=\"und\""
        } else {
            ""
        };
        let _ = writeln!(
            mpd,
            "    <AdaptationSet id=\"{id}\" contentType=\"{content_type}\" mimeType=\"{mime}\"{lang} \
             segmentAlignment=\"true\" startWithSAP=\"1\"{extra}>"
        );
        let _ = writeln!(
            mpd,
            "      <ContentProtection schemeIdUri=\"urn:mpeg:dash:mp4protection:2011\" value=\"cenc\" \
             cenc:default_KID=\"{}\"/>",
            format_uuid(&self.kid)
        );
        for (system_id, value, pssh) in &self.protection {
            let value = value.map_or_else(String::new, |value| format!(" value=\"{value}\""));
            let _ = writeln!(
                mpd,
                "      <ContentProtection schemeIdUri=\"urn:uuid:{system_id}\"{value}>\
                 <cenc:pssh>{pssh}</cenc:pssh></ContentProtection>"
            );
        }
        let _ = writeln!(
            mpd,
            "      <SegmentTemplate timescale=\"{}\" initialization=\"$RepresentationID$/init.mp4\" \
             media=\"$RepresentationID$/seg-$Number$.m4s\" startNumber=\"1\">",
            self.timescale
        );
        mpd.push_str("        <SegmentTimeline>\n");
        for (index, (start, duration, repeats)) in self.runs.iter().enumerate() {
            let start = if index == 0 {
                format!(" t=\"{start}\"")
            } else {
                String::new()
            };
            let repeats = if *repeats > 0 {
                format!(" r=\"{repeats}\"")
            } else {
                String::new()
            };
            let _ = writeln!(mpd, "          <S{start} d=\"{duration}\"{repeats}/>");
        }
        mpd.push_str("        </SegmentTimeline>\n      </SegmentTemplate>\n");
        match self.entry {
            Fmp4SampleEntryV2::Video { width, height, .. } => {
                let _ = writeln!(
                    mpd,
                    "      <Representation id=\"{VIDEO_REPRESENTATION_ID_V2}\" codecs=\"{VIDEO_CODECS_V2}\" \
                     width=\"{width}\" height=\"{height}\" frameRate=\"30\" bandwidth=\"{}\"/>",
                    self.bandwidth
                );
            }
            Fmp4SampleEntryV2::Audio {
                sample_rate,
                channel_count,
            } => {
                let _ = writeln!(
                    mpd,
                    "      <Representation id=\"{AUDIO_REPRESENTATION_ID_V2}\" codecs=\"{AUDIO_CODECS_V2}\" \
                     audioSamplingRate=\"{sample_rate}\" bandwidth=\"{}\">",
                    self.bandwidth
                );
                let _ = writeln!(
                    mpd,
                    "        <AudioChannelConfiguration \
                     schemeIdUri=\"urn:mpeg:mpegB:cicp:ChannelConfiguration\" value=\"{channel_count}\"/>"
                );
                mpd.push_str("      </Representation>\n");
            }
        }
        mpd.push_str("    </AdaptationSet>\n");
    }
}

/// `PT{s}.{mmm}S`.
fn format_duration(ms: u64) -> String {
    format!("PT{}.{:03}S", ms / 1000, ms % 1000)
}

/// Lowercase `8-4-4-4-12` hex.
fn format_uuid(bytes: &[u8; 16]) -> String {
    ProtectionSystemId::from_bytes(*bytes).to_string()
}

/// The `ContentProtection@value` of a registered system; a foreign box carries none.
fn content_protection_value(
    registry: &ProtectionRegistry<'_>,
    system_id: &[u8; 16],
) -> Option<&'static str> {
    registry.lookup(system_id).map(|system| system.scheme)
}

/// Standard base64 with padding.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (index, byte)| {
            acc | u32::from(*byte) << (16 - 8 * index)
        });
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * index) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::v2_tests::{protect, pssh_v0, A, KID, TIMESCALE, V, WIDEVINE_SYSTEM_ID};
    use crate::protection_system::{ELASTOS_CUSTODY_LEGACY, ELASTOS_CUSTODY_POOL};

    fn segment(decode_time: u64, duration: u64, bytes: u64) -> CencDashMpdSegmentV2 {
        CencDashMpdSegmentV2 {
            timeline: Fmp4SegmentTimelineV2 {
                decode_time,
                duration,
            },
            bytes,
        }
    }

    fn mpd(
        video: &[u8],
        video_segments: &[CencDashMpdSegmentV2],
        audio: Option<(&[u8], &[CencDashMpdSegmentV2])>,
    ) -> Result<String, ContractError> {
        let mut renditions = vec![CencDashMpdRenditionV2 {
            protected_init: video,
            segments: video_segments,
        }];
        if let Some((init, segments)) = audio {
            renditions.push(CencDashMpdRenditionV2 {
                protected_init: init,
                segments,
            });
        }
        build_cenc_dash_mpd_v2(&renditions)
    }

    #[test]
    fn base64_uuid_and_duration_formats() {
        // RFC 4648 §10.
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(plain.as_bytes()), encoded);
        }
        assert_eq!(base64(&[0xfb, 0xff, 0xfe]), "+//+");
        assert_eq!(
            format_uuid(&[
                0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d,
                0x21, 0xed
            ]),
            "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"
        );
        assert_eq!(format_duration(0), "PT0.000S");
        assert_eq!(format_duration(1_001), "PT1.001S");
        assert_eq!(format_duration(3_723_450), "PT3723.450S");
    }

    #[test]
    fn video_and_audio_mpd_is_exactly_this() {
        let video = protect(V, &[]);
        let audio = protect(A, &[]);
        let video_segments = [
            segment(0, 30_720, 100_000),
            segment(30_720, 30_720, 90_000),
            segment(61_440, 15_360, 20_000),
        ];
        let audio_segments = [segment(0, 30_720, 8_000), segment(30_720, 30_720, 8_100)];
        let text = mpd(
            &video.init,
            &video_segments,
            Some((&audio.init, &audio_segments)),
        )
        .unwrap();

        let pssh_lines = |init: &[u8]| -> String {
            cenc_dash_init_pssh_boxes(init)
                .unwrap()
                .into_iter()
                .map(|pssh| {
                    let system_id: [u8; 16] = pssh[12..28].try_into().unwrap();
                    let system = format_uuid(&system_id);
                    let value = content_protection_value(&PROTECTION.registry(), &system_id)
                        .map(|scheme| format!(" value=\"{scheme}\""))
                        .unwrap_or_default();
                    format!(
                        "      <ContentProtection schemeIdUri=\"urn:uuid:{system}\"{value}>\
                         <cenc:pssh>{}</cenc:pssh></ContentProtection>\n",
                        base64(pssh)
                    )
                })
                .collect()
        };
        let kid = format_uuid(&KID);
        // 100000 B over 2 s at timescale 15360 is the busiest segment:
        // 8 · 100000 · 15360 / 30720 = 400000 bit/s.
        let sets = |kind: &str, protection: String, timeline: &str, representation: &str| {
            [
                kind.to_string(),
                format!("      <ContentProtection schemeIdUri=\"urn:mpeg:dash:mp4protection:2011\" value=\"cenc\" cenc:default_KID=\"{kid}\"/>"),
                protection.trim_end().to_string(),
                "      <SegmentTemplate timescale=\"15360\" initialization=\"$RepresentationID$/init.mp4\" media=\"$RepresentationID$/seg-$Number$.m4s\" startNumber=\"1\">".to_string(),
                "        <SegmentTimeline>".to_string(),
                timeline.to_string(),
                "        </SegmentTimeline>".to_string(),
                "      </SegmentTemplate>".to_string(),
                representation.to_string(),
                "    </AdaptationSet>".to_string(),
            ]
            .join("\n")
        };
        let video_set = sets(
            "    <AdaptationSet id=\"0\" contentType=\"video\" mimeType=\"video/mp4\" segmentAlignment=\"true\" startWithSAP=\"1\" maxWidth=\"640\" maxHeight=\"360\">",
            pssh_lines(&video.init),
            "          <S t=\"0\" d=\"30720\" r=\"1\"/>\n          <S d=\"15360\"/>",
            "      <Representation id=\"video/avc1\" codecs=\"avc1.640028\" width=\"640\" height=\"360\" frameRate=\"30\" bandwidth=\"400000\"/>",
        );
        let audio_set = sets(
            "    <AdaptationSet id=\"1\" contentType=\"audio\" mimeType=\"audio/mp4\" lang=\"und\" segmentAlignment=\"true\" startWithSAP=\"1\">",
            pssh_lines(&audio.init),
            "          <S t=\"0\" d=\"30720\" r=\"1\"/>",
            "      <Representation id=\"audio/und/mp4a\" codecs=\"mp4a.40.2\" audioSamplingRate=\"48000\" bandwidth=\"32400\">\n        <AudioChannelConfiguration schemeIdUri=\"urn:mpeg:mpegB:cicp:ChannelConfiguration\" value=\"2\"/>\n      </Representation>",
        );
        let expected = [
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>".to_string(),
            "<MPD xmlns=\"urn:mpeg:dash:schema:mpd:2011\" xmlns:cenc=\"urn:mpeg:cenc:2013\" profiles=\"urn:mpeg:dash:profile:isoff-live:2011\" type=\"static\" minBufferTime=\"PT2.000S\" mediaPresentationDuration=\"PT5.000S\">".to_string(),
            "  <Period id=\"0\" start=\"PT0.000S\">".to_string(),
            video_set,
            audio_set,
            "  </Period>".to_string(),
            "</MPD>".to_string(),
        ]
        .join("\n")
            + "\n";
        assert_eq!(text, expected);
        assert!(!text.contains('\r') && !text.contains('\t'));
        assert_eq!(
            text,
            mpd(
                &video.init,
                &video_segments,
                Some((&audio.init, &audio_segments))
            )
            .unwrap(),
            "deterministic"
        );
    }

    #[test]
    fn foreign_pssh_boxes_are_listed_in_init_order() {
        let widevine = pssh_v0(&WIDEVINE_SYSTEM_ID, b"dummy");
        let video = protect(V, std::slice::from_ref(&widevine));
        let text = mpd(&video.init, &[segment(0, 30_720, 1_000)], None).unwrap();
        let common = text
            .find("urn:uuid:1077efec-c0b2-4d02-ace3-3c1e52e2fb4b")
            .unwrap();
        let foreign = text
            .find("urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")
            .unwrap();
        let elastos = text
            .find(&format!("value=\"{}\"", PROTECTION.writer().scheme))
            .unwrap();
        assert!(common < foreign && foreign < elastos);
        assert!(text.contains(&format!(
            "<ContentProtection schemeIdUri=\"urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed\">\
             <cenc:pssh>{}</cenc:pssh></ContentProtection>",
            base64(&widevine)
        )));
        // The video-only MPD has no audio set.
        assert!(!text.contains("contentType=\"audio\""));
    }

    #[test]
    fn timeline_is_run_length_encoded_and_must_be_contiguous() {
        let video = protect(V, &[]).init;
        let render = |segments: &[CencDashMpdSegmentV2]| mpd(&video, segments, None);
        let text = render(&[
            segment(1_000, 100, 10),
            segment(1_100, 100, 10),
            segment(1_200, 100, 10),
            segment(1_300, 50, 10),
            segment(1_350, 100, 10),
        ])
        .unwrap();
        assert!(text.contains(
            "          <S t=\"1000\" d=\"100\" r=\"2\"/>\n\
             \x20         <S d=\"50\"/>\n\
             \x20         <S d=\"100\"/>\n"
        ));
        assert!(
            render(&[segment(0, 100, 10), segment(101, 100, 10)]).is_err(),
            "gap"
        );
        assert!(
            render(&[segment(0, 100, 10), segment(99, 100, 10)]).is_err(),
            "overlap"
        );
        assert!(
            render(&[segment(0, 100, 10), segment(0, 100, 10)]).is_err(),
            "repeat"
        );
        assert!(render(&[segment(0, 0, 10)]).is_err(), "zero duration");
        assert!(render(&[segment(0, 100, 0)]).is_err(), "zero bytes");
        assert!(render(&[segment(u64::MAX, 1, 10)]).is_err(), "overflow");
        assert!(render(&[]).is_err(), "no segments");
    }

    #[test]
    fn duration_is_the_longest_rendition_rounded_up_to_the_millisecond() {
        let video = protect(V, &[]).init;
        let audio = protect(A, &[]).init;
        let render = |video_end: u64, audio_end: u64| {
            mpd(
                &video,
                &[segment(0, video_end, 1_000)],
                Some((&audio, &[segment(0, audio_end, 1_000)])),
            )
            .unwrap()
        };
        let duration = |text: &str| {
            text.split("mediaPresentationDuration=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
                .to_string()
        };
        assert_eq!(
            duration(&render(15_360, 30_720)),
            "PT2.000S",
            "audio is longer"
        );
        assert_eq!(
            duration(&render(30_720, 15_360)),
            "PT2.000S",
            "video is longer"
        );
        // 15361 / 15360 s = 1.0000651 s, rounded up.
        assert_eq!(duration(&render(15_361, 15_360)), "PT1.001S");
        assert_eq!(TIMESCALE, 15_360);
    }

    #[test]
    fn bandwidth_is_the_peak_segment_rounded_up() {
        let video = protect(V, &[]).init;
        let render = |segments: &[CencDashMpdSegmentV2]| {
            let text = mpd(&video, segments, None).unwrap();
            text.split("bandwidth=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
                .parse::<u64>()
                .unwrap()
        };
        // 8 · 3 · 15360 / 30720 = 12 exactly.
        assert_eq!(render(&[segment(0, 30_720, 3)]), 12);
        // 8 · 1 · 15360 / 30721 = 3.99997, rounded up.
        assert_eq!(render(&[segment(0, 30_721, 1)]), 4);
        // The busiest segment wins, wherever it is.
        assert_eq!(
            render(&[
                segment(0, 30_720, 3),
                segment(30_720, 15_360, 100),
                segment(46_080, 30_720, 3),
            ]),
            800
        );
    }

    #[test]
    fn mpd_refuses_bad_rendition_sets_and_inits() {
        let video = protect(V, &[]).init;
        let audio = protect(A, &[]).init;
        let one = [segment(0, 30_720, 1_000)];
        assert!(build_cenc_dash_mpd_v2(&[]).is_err());
        let rendition = |init| CencDashMpdRenditionV2 {
            protected_init: init,
            segments: &one,
        };
        assert!(build_cenc_dash_mpd_v2(&[rendition(&audio), rendition(&video)]).is_err());
        assert!(build_cenc_dash_mpd_v2(&[rendition(&video), rendition(&video)]).is_err());
        assert!(
            build_cenc_dash_mpd_v2(&[rendition(&video), rendition(&audio), rendition(&audio)])
                .is_err()
        );
        assert!(
            build_cenc_dash_mpd_v2(&[rendition(&[0u8; 16])]).is_err(),
            "garbage"
        );
        assert!(build_cenc_dash_mpd_v2(&[rendition(&[])]).is_err(), "empty");
        // A clear init has no protection and is not a protected rendition.
        let clear = protect(V, &[]).clear_init;
        assert!(build_cenc_dash_mpd_v2(&[rendition(&clear)]).is_err());
        assert!(build_cenc_dash_mpd_v2(&[rendition(&video)]).is_ok());
    }
    #[test]
    fn mpd_value_follows_the_elastos_system_id() {
        let mut init = protect(V, &[]).init;
        let text = mpd(&init, &[segment(0, 30_720, 1_000)], None).unwrap();
        assert!(text.contains("schemeIdUri=\"urn:uuid:b01c5dff-46fb-497e-8525-6fb946873253\""));
        assert!(text.contains("value=\"cenc:elastos-pq-hybrid-threshold-v1\""));
        assert!(!text.contains("threshold-v0"));

        let at = init
            .windows(16)
            .position(|w| w == ELASTOS_CUSTODY_POOL.id.as_bytes())
            .unwrap();
        init[at..at + 16].copy_from_slice(ELASTOS_CUSTODY_LEGACY.id.as_bytes());
        let text = mpd(&init, &[segment(0, 30_720, 1_000)], None).unwrap();
        assert!(text.contains("schemeIdUri=\"urn:uuid:b6e254ef-0dc5-47fe-94e7-0e72ed1dc7b0\""));
        assert!(text.contains("value=\"cenc:elastos-pq-hybrid-threshold-v0\""));
        assert!(!text.contains("threshold-v1"));
    }
}

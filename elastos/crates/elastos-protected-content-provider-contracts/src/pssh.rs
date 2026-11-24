//! MPEG Common Encryption (CENC, ISO/IEC 23001-7 §8.1) Protection System Specific
//! Header (`pssh`) box grammar: build and parse the box, nothing about any one
//! protection system's data. What goes inside a box, and how it is read, belongs to
//! the adapters in [`crate::protection_system`].

/// The protection scheme the pooling system is registered for, and the scheme
/// named inside its `Data` payload.
pub const ELASTOS_PQ_PROTECTION_SCHEME_V1: &str = "cenc:elastos-pq-hybrid-threshold-v1";

/// The protection scheme the legacy system is registered for (the MPD `value` of a
/// legacy box).
pub const ELASTOS_PQ_PROTECTION_SCHEME_V0: &str = "cenc:elastos-pq-hybrid-threshold-v0";

/// A parsed **version-1** `pssh` box: system id, embedded KID list, and the opaque
/// key-acquisition payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsshBoxV1 {
    pub system_id: [u8; 16],
    pub kids: Vec<[u8; 16]>,
    pub data: Vec<u8>,
}

/// Build the **version-1** `pssh` box (ISO/IEC 23001-7 §8.1) that carries `data`
/// for `system_id`, listing `kids` as the embedded default-KID set.
///
/// Layout: `size:u32be ‖ "pssh" ‖ version=1:u8 ‖ flags:[0;3] ‖ system_id:16 ‖
/// kid_count:u32be ‖ kids:(16·n) ‖ data_size:u32be ‖ data`.
pub fn build_pssh_v1(system_id: &[u8; 16], kids: &[[u8; 16]], data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(1u8); // version
    body.extend_from_slice(&[0u8, 0, 0]); // flags
    body.extend_from_slice(system_id);
    body.extend_from_slice(&(kids.len() as u32).to_be_bytes());
    for kid in kids {
        body.extend_from_slice(kid);
    }
    body.extend_from_slice(&(data.len() as u32).to_be_bytes());
    body.extend_from_slice(data);

    let total = 8 + body.len(); // 4 (size) + 4 ("pssh")
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u32).to_be_bytes());
    out.extend_from_slice(b"pssh");
    out.extend_from_slice(&body);
    out
}

/// Parse a single **version-1** `pssh` box. Returns `None` on anything malformed.
///
/// Tolerant of trailing bytes AFTER the box (e.g. when handed a slice of a larger
/// `moov`): the declared `size` bounds the read. Intolerant of everything else —
/// a box whose declared size runs past the buffer, whose version is not 1 (the
/// only version this scheme emits), or that leaves slack bytes between the end of
/// `Data` and the end of the box is malformed, not ours.
pub fn parse_pssh_v1(bytes: &[u8]) -> Option<PsshBoxV1> {
    match parse_pssh_v0_or_v1(bytes)? {
        (1, parsed) => Some(parsed),
        _ => None,
    }
}

/// Parse a single `pssh` box of version 0 or 1 (ISO/IEC 23001-7 §8.1), with the
/// same strictness as [`parse_pssh_v1`]. Returns the box version with the box; a
/// version-0 box has no KID list, so its `kids` is empty.
pub fn parse_pssh_v0_or_v1(bytes: &[u8]) -> Option<(u8, PsshBoxV1)> {
    if bytes.len() < 12 || &bytes[4..8] != b"pssh" {
        return None;
    }
    let size = u32::from_be_bytes(bytes[0..4].try_into().ok()?) as usize;
    if size < 12 || size > bytes.len() {
        return None;
    }
    let buf = &bytes[..size];
    let version = *buf.get(8)?;
    if version > 1 {
        return None;
    }
    // buf[9..12] = flags (ignored)
    let mut off = 12usize;
    let system_id: [u8; 16] = buf.get(off..off + 16)?.try_into().ok()?;
    off += 16;
    let mut kids = Vec::new();
    if version == 1 {
        let kid_count = u32::from_be_bytes(buf.get(off..off + 4)?.try_into().ok()?) as usize;
        off += 4;
        kids.reserve(kid_count.min(16));
        for _ in 0..kid_count {
            let kid: [u8; 16] = buf.get(off..off + 16)?.try_into().ok()?;
            off += 16;
            kids.push(kid);
        }
    }
    let data_len = u32::from_be_bytes(buf.get(off..off + 4)?.try_into().ok()?) as usize;
    off += 4;
    let data = buf.get(off..off.checked_add(data_len)?)?.to_vec();
    if off.checked_add(data_len)? != size {
        return None;
    }
    Some((
        version,
        PsshBoxV1 {
            system_id,
            kids,
            data,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEM: [u8; 16] = [0xaa; 16];
    const KID: [u8; 16] = [0x55; 16];

    fn boxed() -> Vec<u8> {
        build_pssh_v1(&SYSTEM, &[KID], b"payload")
    }

    #[test]
    fn box_grammar_matches_iso_23001_7_version_1() {
        let boxed = boxed();
        assert_eq!(
            u32::from_be_bytes(boxed[0..4].try_into().unwrap()) as usize,
            boxed.len()
        );
        assert_eq!(&boxed[4..8], b"pssh");
        assert_eq!(boxed[8], 1, "version");
        assert_eq!(&boxed[9..12], &[0, 0, 0], "flags");
        assert_eq!(&boxed[12..28], &SYSTEM);
        assert_eq!(
            u32::from_be_bytes(boxed[28..32].try_into().unwrap()),
            1,
            "kid_count"
        );
        assert_eq!(&boxed[32..48], &KID, "the default KID");
        let data_len = u32::from_be_bytes(boxed[48..52].try_into().unwrap()) as usize;
        assert_eq!(48 + 4 + data_len, boxed.len());
    }

    #[test]
    fn build_then_parse_round_trips() {
        let parsed = parse_pssh_v1(&boxed()).expect("parse");
        assert_eq!(parsed.system_id, SYSTEM);
        assert_eq!(parsed.kids, vec![KID]);
        assert_eq!(parsed.data, b"payload");
    }

    #[test]
    fn parse_tolerates_trailing_bytes_but_rejects_short_and_wrong_type() {
        let mut with_trailing = boxed();
        with_trailing.extend_from_slice(b"TRAILING-MOOV-BYTES");
        assert_eq!(parse_pssh_v1(&with_trailing).unwrap().data, b"payload");

        assert!(parse_pssh_v1(b"short").is_none());
        let mut wrong_type = boxed();
        wrong_type[4] = b'm';
        assert!(parse_pssh_v1(&wrong_type).is_none());
    }

    #[test]
    fn parse_rejects_other_versions_oversized_declarations_and_slack_after_data() {
        // Version 0 is a legal CENC box but not one the v1 parser reads, and it
        // carries no KID list to bind. Anything else is simply malformed.
        for version in [0u8, 2, 255] {
            let mut other = boxed();
            other[8] = version;
            assert!(parse_pssh_v1(&other).is_none(), "version {version}");
        }

        // A declared size past the end of the buffer is refused instead of being
        // silently truncated to what happens to be there.
        let mut oversized = boxed();
        let grown = (oversized.len() as u32 + 8).to_be_bytes();
        oversized[0..4].copy_from_slice(&grown);
        assert!(parse_pssh_v1(&oversized).is_none());

        // Slack between the end of `Data` and the end of the box: the box claims
        // eight more bytes than its fields account for.
        let mut slack = boxed();
        let grown = (slack.len() as u32 + 8).to_be_bytes();
        slack[0..4].copy_from_slice(&grown);
        slack.extend_from_slice(&[0u8; 8]);
        assert!(parse_pssh_v1(&slack).is_none());

        // A zero size ("to end of file") is not a shape this scheme emits either.
        let mut zero_size = boxed();
        zero_size[0..4].copy_from_slice(&0u32.to_be_bytes());
        assert!(parse_pssh_v1(&zero_size).is_none());
    }

    #[test]
    fn v0_or_v1_parser_reads_both_versions_with_the_same_strictness() {
        let v1 = build_pssh_v1(&SYSTEM, &[KID], b"x");
        let (version, parsed) = parse_pssh_v0_or_v1(&v1).unwrap();
        assert_eq!(version, 1);
        assert_eq!(parsed, parse_pssh_v1(&v1).unwrap());

        let mut v0 = vec![0, 0, 0, 0];
        v0.extend_from_slice(b"pssh");
        v0.extend_from_slice(&[0, 0, 0, 0]);
        v0.extend_from_slice(&SYSTEM);
        v0.extend_from_slice(&3u32.to_be_bytes());
        v0.extend_from_slice(b"abc");
        let len = v0.len() as u32;
        v0[0..4].copy_from_slice(&len.to_be_bytes());
        let (version, parsed) = parse_pssh_v0_or_v1(&v0).unwrap();
        assert_eq!(version, 0);
        assert!(parsed.kids.is_empty());
        assert_eq!(parsed.data, b"abc");
        assert!(
            parse_pssh_v1(&v0).is_none(),
            "the v1 parser still refuses v0"
        );

        let mut slack = v0.clone();
        slack[0..4].copy_from_slice(&(len + 1).to_be_bytes());
        slack.push(0);
        assert!(parse_pssh_v0_or_v1(&slack).is_none());
        let mut overrun = v0.clone();
        let data_len_at = overrun.len() - 7;
        overrun[data_len_at..data_len_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_pssh_v0_or_v1(&overrun).is_none());
        let mut version_two = v0;
        version_two[8] = 2;
        assert!(parse_pssh_v0_or_v1(&version_two).is_none());
        let mut huge_kid_count = v1.clone();
        huge_kid_count[28..32].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_pssh_v0_or_v1(&huge_kid_count).is_none());
    }
}

# Bento4 fixtures

`same-stream/` is real Bento4 output, used to prove the V2 validators accept a
third-party CENC packager (spec §7, §10).

- **Origin:** the DASH v2 investigation (scratch `initcheck/bento/same-stream`). The Runtime's own H.264 stream was remuxed with `-c copy`, then run through `mp4fragment` and `mp4dash --use-segment-timeline --encryption-key=KID:KEY:random --encryption-cenc-scheme=cenc` (Bento4 2.0.0-640).
- **Contents:** video only. `cenc` with 16-byte IVs, NAL subsamples, `traf` = `tfhd tfdt trun(v1) saiz saio senc`, tfhd flags `0x02002a`, and one Common `pssh` v1 at the end of `moov` after `udta`.
- **`init.mp4`:** byte for byte as Bento4 wrote it.
- **`seg-1-first-2-samples.m4s`:** Bento4's `seg-1.m4s` cut to its first two samples (IDR 22,473 B and P 11,102 B), to keep the repo small.
  - The cut rewrote only counts, box sizes, the `saio` offset and `trun.data_offset`.
  - Every sample's bytes, IV and `senc` entry are Bento4's.
  - The `senc` entries are `(793, 21680)` and `(110, 10992)`.
- **Test key (public, test only):** KID `fca5a58030fd8d6eb230e4da8f3692b5`, key `000102030405060708090a0b0c0d0e0f`. This is a raw AES-128 key, not a CEK. Decrypting the two samples gives the clear samples, whose concatenation has SHA-256 `efaa7f2eb3bd3104c8e04e198b837823bcd361aba6d9d875c9f62b5a10481b1b`. This was checked independently with Python `cryptography`.

The multi-PSSH Bento4 vectors (audio, plus Widevine/PlayReady `--pssh`) come in T11a.

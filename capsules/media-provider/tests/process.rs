#![cfg(unix)]

use std::fs;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};

use elastos_protected_content_contracts::{
    ContentAccessIdV1, CustodyCommitteeAuthorizationIdentityV1, CustodyEpochIdentityV1,
    CustodyPoolIdentityV1, Digest32,
};
use elastos_protected_content_provider_contracts::{
    CencFmp4MediaIdentityV1, CencLayoutProfile, CencMediaSuite, CustodyProtectionHeader,
    ValidatedCencFmp4MediaSessionLayoutV1, ValidatedClearFmp4MediaSessionLayoutV1,
    ELASTOS_PQ_PROTECTION_SCHEME_V1, PROTECTION,
};
use serde_json::json;

const OPERATION_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
// Success-path budget. The mock tools are shell scripts, and under the full
// parallel suite on a loaded host a bare `sh` invocation has been observed to
// take several seconds to exit; keep this well above that. Tests that must
// observe a stall use SHORT_TIMEOUT_MS. The timeout is a stall timeout: it
// bounds how long the output may stop growing, not the whole run.
const NORMAL_TIMEOUT_MS: u64 = 30_000;
const SHORT_TIMEOUT_MS: u64 = 1_500;
// Stall timeout for the test whose mock keeps writing output for longer than
// this: a step every 250 ms leaves ample margin on a loaded host.
const PROGRESS_TIMEOUT_MS: u64 = 4_000;
// The protocol part rule: a clear part is at most 2 MiB - 64 KiB.
const PART_RULE_BYTES: usize = 2 * 1024 * 1024 - 64 * 1024;

#[derive(Clone, Copy)]
struct InitRequestConfig {
    timeout_ms: u64,
    max_stdio_bytes: usize,
    max_input_bytes: u64,
    max_output_part_bytes: u64,
    max_segment_count: usize,
    max_total_output_bytes: u64,
    max_duration_secs: u64,
    max_source_width: u32,
    max_source_height: u32,
    max_source_fps: u32,
}

impl Default for InitRequestConfig {
    fn default() -> Self {
        Self {
            timeout_ms: NORMAL_TIMEOUT_MS,
            max_stdio_bytes: 4096,
            max_input_bytes: 1 << 20,
            max_output_part_bytes: 1 << 20,
            max_segment_count: 8,
            max_total_output_bytes: 1 << 22,
            max_duration_secs: 60,
            max_source_width: 1920,
            max_source_height: 1080,
            max_source_fps: 60,
        }
    }
}

struct ProviderProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl ProviderProcess {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_media-provider"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Self {
            stdin: Some(child.stdin.take().unwrap()),
            stdout: BufReader::new(child.stdout.take().unwrap()),
            stderr: child.stderr.take(),
            child,
        }
    }

    fn request_json(&mut self, value: serde_json::Value) -> serde_json::Value {
        let stdin = self.stdin.as_mut().unwrap();
        serde_json::to_writer(&mut *stdin, &value).unwrap();
        writeln!(stdin).unwrap();
        stdin.flush().unwrap();
        self.read_response()
    }

    fn request_raw_line(&mut self, bytes: &[u8]) -> serde_json::Value {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(bytes).unwrap();
        writeln!(stdin).unwrap();
        stdin.flush().unwrap();
        self.read_response()
    }

    fn read_response(&mut self) -> serde_json::Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn shutdown_and_assert_clean(mut self) {
        let response = self.request_json(json!({"op":"shutdown"}));
        assert_eq!(response["status"], "ok");
        let status = self.child.wait().unwrap();
        assert!(status.success());
        self.assert_empty_stderr();
    }

    fn assert_empty_stderr(&mut self) {
        let mut stderr = String::new();
        self.stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
    }
}

struct ToolFixture {
    _root: tempfile::TempDir,
    staging_root: PathBuf,
    ffprobe_path: PathBuf,
    ffmpeg_path: PathBuf,
    ffprobe_args_log: PathBuf,
    ffmpeg_args_log: PathBuf,
    ffprobe_pid: PathBuf,
    ffmpeg_pid: PathBuf,
    ffprobe_stdout: PathBuf,
    ffprobe_stderr: PathBuf,
    ffprobe_mode: PathBuf,
    ffmpeg_mode: PathBuf,
    ffmpeg_stderr: PathBuf,
}

impl ToolFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let staging_root = root.path().join("staging");
        fs::create_dir(&staging_root).unwrap();
        fs::set_permissions(&staging_root, fs::Permissions::from_mode(0o700)).unwrap();
        let tools = root.path().join("tools");
        fs::create_dir(&tools).unwrap();
        fs::set_permissions(&tools, fs::Permissions::from_mode(0o700)).unwrap();

        let ffprobe_args_log = root.path().join("ffprobe.args");
        let ffmpeg_args_log = root.path().join("ffmpeg.args");
        let ffprobe_pid = root.path().join("ffprobe.pid");
        let ffmpeg_pid = root.path().join("ffmpeg.pid");
        let ffprobe_stdout = root.path().join("ffprobe.stdout.json");
        let ffprobe_stderr = root.path().join("ffprobe.stderr.txt");
        let ffprobe_mode = root.path().join("ffprobe.mode");
        let ffmpeg_mode = root.path().join("ffmpeg.mode");
        let ffmpeg_stderr = root.path().join("ffmpeg.stderr.txt");
        let init_fixture = root.path().join("init.mp4");
        let audio_init_fixture = root.path().join("audio-init.mp4");
        let segment_zero_fixture = root.path().join("00000000.m4s");
        let segment_one_fixture = root.path().join("00000001.m4s");
        let over_part_rule_fixture = root.path().join("over-part-rule.m4s");
        let at_part_rule_fixture = root.path().join("at-part-rule.m4s");
        // What real ffmpeg emits per DASH segment: styp + sidx ahead of the
        // moof/mdat pair. The provider must strip the prefix.
        let dash_prefixed_segment_fixture = root.path().join("dash-prefixed.m4s");
        let two_fragment_segment_fixture = root.path().join("two-fragments.m4s");

        fs::write(&ffprobe_stdout, valid_ffprobe_json()).unwrap();
        fs::write(&ffprobe_stderr, "").unwrap();
        fs::write(&ffprobe_mode, "normal\n").unwrap();
        fs::write(&ffmpeg_mode, "success\n").unwrap();
        fs::write(&ffmpeg_stderr, "").unwrap();

        fs::write(&init_fixture, clear_init_segment()).unwrap();
        fs::write(&audio_init_fixture, clear_audio_init_segment()).unwrap();
        fs::write(&segment_zero_fixture, clear_segment(1, b"segment-0")).unwrap();
        fs::write(&segment_one_fixture, clear_segment(1, b"segment-1")).unwrap();
        fs::write(&over_part_rule_fixture, segment_of_len(PART_RULE_BYTES + 1)).unwrap();
        fs::write(&at_part_rule_fixture, segment_of_len(PART_RULE_BYTES)).unwrap();
        fs::write(
            &dash_prefixed_segment_fixture,
            [
                make_box(b"styp", b"msdh\0\0\0\0msdhmsix"),
                make_box(b"sidx", &[0u8; 44]),
                clear_segment(1, b"segment-0"),
            ]
            .concat(),
        )
        .unwrap();
        fs::write(
            &two_fragment_segment_fixture,
            [
                clear_segment(1, b"segment-0"),
                clear_segment(1, b"segment-1"),
            ]
            .concat(),
        )
        .unwrap();

        let ffprobe_path = tools.join("ffprobe.sh");
        let ffmpeg_path = tools.join("ffmpeg.sh");
        fs::write(
            &ffprobe_path,
            format!(
                "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" > '{pid}'\n: > '{args}'\nfor arg in \"$@\"; do\n  printf '%s\\n' \"$arg\" >> '{args}'\ndone\nmode=\"$(tr -d '\\n' < '{mode}')\"\ncat '{stdout}'\nif [ -s '{stderr}' ]; then\n  cat '{stderr}' >&2\nfi\nif [ \"$mode\" = 'hang_after_output' ]; then\n  while :; do sleep 1; done\nfi\n",
                pid = ffprobe_pid.display(),
                args = ffprobe_args_log.display(),
                stdout = ffprobe_stdout.display(),
                stderr = ffprobe_stderr.display(),
                mode = ffprobe_mode.display(),
            ),
        )
        .unwrap();
        // Like real ffmpeg, the mock never creates the `$RepresentationID$`
        // directories: `cp` into a missing `./0/segments` fails the run. Stream 0
        // is the video rendition when there is one, otherwise the audio one.
        fs::write(
            &ffmpeg_path,
            format!(
                "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" > '{pid}'\n: > '{args}'\nmanifest=''\nfor arg in \"$@\"; do\n  manifest=\"$arg\"\n  printf '%s\\n' \"$arg\" >> '{args}'\ndone\nmode=\"$(tr -d '\\n' < '{mode}')\"\nif [ -s '{stderr}' ]; then\n  cat '{stderr}' >&2\nfi\n\
video0() {{\n  cp '{init_src}' ./0/init.mp4\n  cp '{seg0}' ./0/segments/00000000.m4s\n  cp '{seg1}' ./0/segments/00000001.m4s\n}}\n\
video1() {{\n  cp '{init_src}' ./0/init.mp4\n  cp '{seg0}' ./0/segments/00000001.m4s\n  cp '{seg1}' ./0/segments/00000002.m4s\n}}\n\
audio1() {{\n  cp '{audio_init_src}' \"./$1/init.mp4\"\n  cp '{seg0}' \"./$1/segments/00000001.m4s\"\n  cp '{seg1}' \"./$1/segments/00000002.m4s\"\n}}\n\
manifest() {{\n  printf '%s\\n' '<MPD />' > \"$manifest\"\n}}\n\
case \"$mode\" in\n  success)\n    video0\n    cp '{audio_init_src}' ./1/init.mp4\n    cp '{seg0}' ./1/segments/00000000.m4s\n    cp '{seg1}' ./1/segments/00000001.m4s\n    manifest\n    ;;\n  success_video)\n    video0\n    manifest\n    ;;\n  success_audio)\n    audio1 0\n    manifest\n    ;;\n  success_one_based)\n    video1\n    audio1 1\n    manifest\n    ;;\n  success_dash_prefixed)\n    cp '{init_src}' ./0/init.mp4\n    cp '{seg_prefixed}' ./0/segments/00000001.m4s\n    cp '{seg1}' ./0/segments/00000002.m4s\n    audio1 1\n    manifest\n    ;;\n  slow_progress)\n    i=0\n    while [ \"$i\" -lt 24 ]; do\n      printf 'x' >> ./0/progress.tmp\n      sleep 0.25\n      i=$((i + 1))\n    done\n    rm ./0/progress.tmp\n    video1\n    audio1 1\n    manifest\n    ;;\n  progress_then_stall)\n    printf 'x' >> ./0/progress.tmp\n    sleep 0.25\n    printf 'x' >> ./0/progress.tmp\n    while :; do sleep 1; done\n    ;;\n  over_part_rule)\n    cp '{init_src}' ./0/init.mp4\n    cp '{over}' ./0/segments/00000001.m4s\n    audio1 1\n    ;;\n  over_part_rule_init)\n    cp '{over}' ./0/init.mp4\n    cp '{seg0}' ./0/segments/00000001.m4s\n    audio1 1\n    ;;\n  at_part_rule)\n    cp '{init_src}' ./0/init.mp4\n    cp '{at}' ./0/segments/00000001.m4s\n    audio1 1\n    ;;\n  two_fragment_segment)\n    cp '{init_src}' ./0/init.mp4\n    cp '{seg_double}' ./0/segments/00000000.m4s\n    cp '{seg1}' ./0/segments/00000001.m4s\n    audio1 1\n    ;;\n  gapped_numbering)\n    cp '{init_src}' ./0/init.mp4\n    cp '{seg0}' ./0/segments/00000000.m4s\n    cp '{seg1}' ./0/segments/00000002.m4s\n    audio1 1\n    ;;\n  two_based_numbering)\n    cp '{init_src}' ./0/init.mp4\n    cp '{seg0}' ./0/segments/00000002.m4s\n    cp '{seg1}' ./0/segments/00000003.m4s\n    audio1 1\n    ;;\n  exit_nonzero)\n    exit 17\n    ;;\n  stall)\n    while :; do sleep 1; done\n    ;;\n  *)\n    exit 23\n    ;;\nesac\n",
                pid = ffmpeg_pid.display(),
                args = ffmpeg_args_log.display(),
                mode = ffmpeg_mode.display(),
                stderr = ffmpeg_stderr.display(),
                init_src = init_fixture.display(),
                audio_init_src = audio_init_fixture.display(),
                seg0 = segment_zero_fixture.display(),
                seg1 = segment_one_fixture.display(),
                over = over_part_rule_fixture.display(),
                at = at_part_rule_fixture.display(),
                seg_prefixed = dash_prefixed_segment_fixture.display(),
                seg_double = two_fragment_segment_fixture.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&ffprobe_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&ffmpeg_path, fs::Permissions::from_mode(0o700)).unwrap();

        Self {
            _root: root,
            staging_root,
            ffprobe_path,
            ffmpeg_path,
            ffprobe_args_log,
            ffmpeg_args_log,
            ffprobe_pid,
            ffmpeg_pid,
            ffprobe_stdout,
            ffprobe_stderr,
            ffprobe_mode,
            ffmpeg_mode,
            ffmpeg_stderr,
        }
    }

    fn init_request(&self, config: InitRequestConfig) -> serde_json::Value {
        json!({
            "op": "init",
            "config": {
                "base_path": "",
                "allowed_paths": [],
                "read_only": false,
                "encryption_key": "",
                "extra": {
                    "provider_id": "media-provider",
                    "staging_root": self.staging_root,
                    "ffmpeg_path": self.ffmpeg_path,
                    "ffprobe_path": self.ffprobe_path,
                    "output_profile": "browser_fmp4_h264_v1",
                    "timeout_ms": config.timeout_ms,
                    "max_stdio_bytes": config.max_stdio_bytes,
                    "max_input_bytes": config.max_input_bytes,
                    "max_output_part_bytes": config.max_output_part_bytes,
                    "max_duration_secs": config.max_duration_secs,
                    "max_source_width": config.max_source_width,
                    "max_source_height": config.max_source_height,
                    "max_source_fps": config.max_source_fps,
                    "max_segment_count": config.max_segment_count,
                    "max_total_output_bytes": config.max_total_output_bytes
                }
            }
        })
    }

    fn set_ffprobe_output(&self, output: &str) {
        fs::write(&self.ffprobe_stdout, output).unwrap();
    }

    fn set_ffprobe_stderr(&self, output: &str) {
        fs::write(&self.ffprobe_stderr, output).unwrap();
    }

    fn set_ffprobe_mode(&self, mode: &str) {
        fs::write(&self.ffprobe_mode, format!("{mode}\n")).unwrap();
    }

    fn set_ffmpeg_mode(&self, mode: &str) {
        fs::write(&self.ffmpeg_mode, format!("{mode}\n")).unwrap();
    }

    fn set_ffmpeg_stderr(&self, output: &str) {
        fs::write(&self.ffmpeg_stderr, output).unwrap();
    }

    fn prepare_operation(&self) -> PathBuf {
        let root = self.staging_root.join(OPERATION_ID);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let input = root.join("input.bin");
        fs::write(&input, b"source-video").unwrap();
        fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
        root
    }
}

/// A source carrying a video track and an AAC-LC stereo 48 kHz audio track,
/// which the audio plan copies.
fn valid_ffprobe_json() -> &'static str {
    concat!(
        r#"{"streams":["#,
        r#"{"codec_type":"video","codec_name":"h264","profile":"High","width":1280,"height":720,"avg_frame_rate":"30000/1001","r_frame_rate":"30000/1001"},"#,
        r#"{"codec_type":"audio","codec_name":"aac","profile":"LC","channels":2,"channel_layout":"stereo","sample_rate":"48000","r_frame_rate":"0/0","avg_frame_rate":"0/0"}"#,
        r#"],"format":{"duration":"4.25"}}"#,
    )
}

fn video_only_ffprobe_json() -> &'static str {
    r#"{"streams":[{"codec_type":"video","width":1280,"height":720,"avg_frame_rate":"30000/1001","r_frame_rate":"30000/1001"}],"format":{"duration":"4.25"}}"#
}

/// What real ffprobe reports for an audio-only source: no `width`/`height`,
/// and frame rates of `0/0`. An mp3 is never copied, so the plan encodes it,
/// keeping the 44.1 kHz rate and the stereo layout.
fn audio_only_ffprobe_json() -> &'static str {
    r#"{"streams":[{"codec_type":"audio","codec_name":"mp3","channels":2,"channel_layout":"stereo","sample_rate":"44100","r_frame_rate":"0/0","avg_frame_rate":"0/0"}],"format":{"duration":"4.25"}}"#
}

/// What ffprobe really reports for an mp3 or m4a carrying embedded cover art:
/// an audio stream plus a "video" stream that is a single attached still. Copied
/// from a real probe of an ID3-tagged file, including the `0/0` frame rate that
/// would fail the video gate outright.
fn audio_with_cover_art_ffprobe_json() -> &'static str {
    concat!(
        r#"{"streams":["#,
        r#"{"codec_type":"audio","r_frame_rate":"0/0","avg_frame_rate":"0/0","#,
        r#""disposition":{"attached_pic":0}},"#,
        r#"{"codec_type":"video","width":320,"height":240,"#,
        r#""r_frame_rate":"90000/1","avg_frame_rate":"0/0","#,
        r#""disposition":{"attached_pic":1}}"#,
        r#"],"format":{"duration":"4.25"}}"#,
    )
}

fn audio_probe(stream_fields: &str) -> String {
    format!(
        r#"{{"streams":[{{"codec_type":"audio",{stream_fields}}}],"format":{{"duration":"4.25"}}}}"#
    )
}

fn runtime_prepare_request() -> serde_json::Value {
    json!({
        "op": "prepare",
        "operation_id": OPERATION_ID,
        "_runtime_invocation": {
            "schema": "elastos.provider.invocation/v1",
            "source": "runtime",
            "target": "media",
            "op": "prepare",
            "capability": "provider:runtime->media:prepare",
            "transport": "runtime-local-provider-plane",
            "carrier": null,
            "transfer": "json",
            "range": null,
            "progress": null,
            "abi": {
                "schema": "elastos.provider.transfer-abi/v1",
                "transfer": "json",
                "transport": "runtime-local-provider-plane",
                "range_supported": false,
                "progress_supported": false,
                "progress_mode": "none",
                "transport_native_stream": false,
                "backpressure": "not_applicable",
                "cancel_supported": false
            }
        }
    })
}

fn video_rendition(segment_count: u32) -> serde_json::Value {
    json!({
        "rendition": "video",
        "mime_type": "video/mp4",
        "codecs": "avc1.640028",
        "segment_count": segment_count
    })
}

fn audio_rendition(segment_count: u32) -> serde_json::Value {
    json!({
        "rendition": "audio",
        "mime_type": "audio/mp4",
        "codecs": "mp4a.40.2",
        "segment_count": segment_count
    })
}

fn prepared_v2(renditions: &[serde_json::Value]) -> serde_json::Value {
    json!({
        "schema": "elastos.media-provider.prepared-media/v2",
        "renditions": renditions
    })
}

/// The exact argv the provider must hand ffmpeg: the given maps, the video
/// encode when `video`, then `audio` (the audio plan), then the shared DASH
/// container flags.
fn expected_ffmpeg_args(
    operation_root: &Path,
    maps: &[&str],
    video: bool,
    audio: &[&str],
    adaptation_sets: &str,
) -> Vec<String> {
    let mut args = vec![
        "-nostdin".to_string(),
        "-v".to_string(),
        "error".to_string(),
        "-y".to_string(),
        "-i".to_string(),
        operation_root
            .join("input.bin")
            .to_string_lossy()
            .to_string(),
    ];
    for map in maps {
        args.push("-map".to_string());
        args.push(map.to_string());
    }
    if video {
        args.extend(
            [
                "-c:v",
                "libx264",
                "-profile:v",
                "high",
                "-level:v",
                "4.0",
                "-pix_fmt",
                "yuv420p",
                "-r",
                "30",
                "-vf",
                "scale=w=min(iw\\,1920):h=min(ih\\,1080):force_original_aspect_ratio=decrease:force_divisible_by=2,fps=30",
                "-g",
                "60",
                "-keyint_min",
                "60",
                "-sc_threshold",
                "0",
                "-preset",
                "veryfast",
                "-crf",
                "28",
                "-maxrate",
                "5000k",
                "-bufsize",
                "5000k",
            ]
            .map(str::to_string),
        );
    }
    args.extend(audio.iter().map(|arg| arg.to_string()));
    args.extend(
        [
            "-movflags",
            "+frag_keyframe+empty_moov+default_base_moof+separate_moof",
            "-f",
            "dash",
            "-seg_duration",
            "2",
            "-streaming",
            "0",
            "-use_timeline",
            "1",
            "-use_template",
            "1",
            "-adaptation_sets",
            adaptation_sets,
            "-init_seg_name",
            "$RepresentationID$/init.mp4",
            "-media_seg_name",
            "$RepresentationID$/segments/$Number%08d$.m4s",
        ]
        .map(str::to_string),
    );
    args.push(
        operation_root
            .join("prepared")
            .join("manifest.mpd")
            .to_string_lossy()
            .to_string(),
    );
    args
}

fn sorted_entries(dir: &Path) -> Vec<String> {
    let mut entries = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

/// Every prepared rendition is `<rendition>/init.mp4` plus 0-based
/// `<rendition>/segments/NNNNNNNN.m4s`, and each segment validates against
/// its own init.
fn assert_rendition_validates(operation_root: &Path, rendition: &str, segment_count: usize) {
    let dir = operation_root.join("prepared").join(rendition);
    assert_layout(&dir, segment_count);
    let session =
        ValidatedClearFmp4MediaSessionLayoutV1::new(&fs::read(dir.join("init.mp4")).unwrap())
            .unwrap();
    for index in 0..segment_count {
        let name = format!("{index:08}.m4s");
        session
            .validate_segment(&fs::read(dir.join("segments").join(&name)).unwrap())
            .unwrap_or_else(|error| panic!("{rendition}/{name} rejected: {error:?}"));
    }
}

fn assert_layout(dir: &Path, segment_count: usize) {
    assert_eq!(
        sorted_entries(dir),
        vec!["init.mp4".to_string(), "segments".to_string()]
    );
    let expected_segments = (0..segment_count)
        .map(|index| format!("{index:08}.m4s"))
        .collect::<Vec<_>>();
    assert_eq!(sorted_entries(&dir.join("segments")), expected_segments);
}

/// Real-muxer twin of `assert_rendition_validates`: the same layout, checked
/// under the V2 rules the DASH package builds on. Every part must validate and
/// have a timeline, and the timeline must be contiguous (the MPD builder
/// refuses gaps).
fn assert_real_rendition_validates_v2(
    operation_root: &Path,
    rendition: &str,
    segment_count: usize,
) {
    let dir = operation_root.join("prepared").join(rendition);
    assert_layout(&dir, segment_count);
    let session = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
        &fs::read(dir.join("init.mp4")).unwrap(),
        CencLayoutProfile::V2,
    )
    .unwrap_or_else(|error| panic!("{rendition}/init.mp4 rejected under V2: {error:?}"));
    let mut expected_next = None;
    for index in 0..segment_count {
        let name = format!("{index:08}.m4s");
        let layout = session
            .validate_segment(&fs::read(dir.join("segments").join(&name)).unwrap())
            .unwrap_or_else(|error| panic!("{rendition}/{name} rejected under V2: {error:?}"));
        let timeline = layout
            .timeline()
            .unwrap_or_else(|| panic!("{rendition}/{name} has no timeline"));
        if index == 0 {
            // Recorded for the MPD ruling (E3): the package timeline starts here.
            println!("first tfdt {rendition}: {}", timeline.decode_time);
        }
        if let Some(expected) = expected_next {
            assert_eq!(
                timeline.decode_time, expected,
                "{rendition}/{name} is not contiguous"
            );
        }
        expected_next = Some(timeline.decode_time + timeline.duration);
    }
}

fn read_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(ToString::to_string)
        .collect()
}

fn read_pid(path: &Path) -> u32 {
    fs::read_to_string(path).unwrap().trim().parse().unwrap()
}

fn read_pid_within(path: &Path) -> u32 {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        if path.exists() {
            return read_pid(path);
        }
        assert!(
            std::time::Instant::now() < deadline,
            "pid file missing: {}",
            path.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn process_exists(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

fn make_box(kind: &[u8; 4], content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + content.len());
    out.extend_from_slice(&(u32::try_from(8 + content.len()).unwrap()).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(content);
    out
}

fn make_fullbox(kind: &[u8; 4], version: u8, flags: u32, payload: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(4 + payload.len());
    content.push(version);
    content.extend_from_slice(&flags.to_be_bytes()[1..]);
    content.extend_from_slice(payload);
    make_box(kind, &content)
}

fn make_clear_track(track_id: u32, handler_type: &[u8; 4]) -> Vec<u8> {
    let mut tkhd_payload = vec![0u8; 12];
    tkhd_payload[8..12].copy_from_slice(&track_id.to_be_bytes());
    let tkhd = make_fullbox(b"tkhd", 0, 0, &tkhd_payload);
    let mut hdlr_payload = vec![0u8; 4];
    hdlr_payload.extend_from_slice(handler_type);
    let hdlr = make_fullbox(b"hdlr", 0, 0, &hdlr_payload);
    let (entry_type, fixed) = match handler_type {
        b"vide" => (b"avc1", 78usize),
        b"soun" => (b"mp4a", 28usize),
        _ => panic!("unsupported handler"),
    };
    let entry = make_box(entry_type, &vec![0u8; fixed]);
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

fn clear_init_segment() -> Vec<u8> {
    let ftyp = make_box(b"ftyp", b"isom\0\0\0\0isomiso6");
    let trak_video = make_clear_track(1, b"vide");
    let trex_video = make_fullbox(
        b"trex",
        0,
        0,
        &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    let mvex = make_box(b"mvex", &trex_video);
    let mvhd = make_box(b"mvhd", &[0u8; 4]);
    let moov = {
        let mut content = Vec::new();
        content.extend_from_slice(&mvhd);
        content.extend_from_slice(&trak_video);
        content.extend_from_slice(&mvex);
        make_box(b"moov", &content)
    };
    [ftyp, moov].concat()
}

/// An audio-only initialisation segment: one `soun` track carrying an `mp4a`
/// sample entry, the shape an AAC fMP4 rendition produces.
fn clear_audio_init_segment() -> Vec<u8> {
    let ftyp = make_box(b"ftyp", b"isom\0\0\0\0isomiso6");
    let trak_audio = make_clear_track(1, b"soun");
    let trex_audio = make_fullbox(
        b"trex",
        0,
        0,
        &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    let mvex = make_box(b"mvex", &trex_audio);
    let mvhd = make_box(b"mvhd", &[0u8; 4]);
    let moov = {
        let mut content = Vec::new();
        content.extend_from_slice(&mvhd);
        content.extend_from_slice(&trak_audio);
        content.extend_from_slice(&mvex);
        make_box(b"moov", &content)
    };
    [ftyp, moov].concat()
}

fn clear_segment(track_id: u32, payload: &[u8]) -> Vec<u8> {
    const TFHD_FLAGS_PRODUCER_V1: u32 = 0x020038;
    const TRUN_FLAG_DATA_OFFSET: u32 = 0x000001;
    const TRUN_FLAG_SAMPLE_SIZE: u32 = 0x000200;

    let mfhd = make_fullbox(b"mfhd", 0, 0, &1u32.to_be_bytes());
    let tfhd = {
        let mut payload_bytes = Vec::new();
        payload_bytes.extend_from_slice(&track_id.to_be_bytes());
        payload_bytes.extend_from_slice(&1u32.to_be_bytes());
        payload_bytes.extend_from_slice(&(u32::try_from(payload.len()).unwrap()).to_be_bytes());
        payload_bytes.extend_from_slice(&0u32.to_be_bytes());
        make_fullbox(b"tfhd", 0, TFHD_FLAGS_PRODUCER_V1, &payload_bytes)
    };
    let tfdt = make_fullbox(b"tfdt", 0, 0, &1u32.to_be_bytes());
    let trun = {
        let mut payload_bytes = Vec::new();
        payload_bytes.extend_from_slice(&1u32.to_be_bytes());
        payload_bytes.extend_from_slice(&0u32.to_be_bytes());
        payload_bytes.extend_from_slice(&(u32::try_from(payload.len()).unwrap()).to_be_bytes());
        make_fullbox(
            b"trun",
            0,
            TRUN_FLAG_DATA_OFFSET | TRUN_FLAG_SAMPLE_SIZE,
            &payload_bytes,
        )
    };
    let traf = {
        let mut content = Vec::new();
        content.extend_from_slice(&tfhd);
        content.extend_from_slice(&tfdt);
        content.extend_from_slice(&trun);
        make_box(b"traf", &content)
    };
    let mut moof = {
        let mut content = Vec::new();
        content.extend_from_slice(&mfhd);
        content.extend_from_slice(&traf);
        make_box(b"moof", &content)
    };
    let data_offset = (moof.len() + 8) as i32;
    let trun_offset = moof
        .windows(4)
        .position(|window| window == b"trun")
        .expect("trun box present")
        - 4;
    let trun_data_offset_at = trun_offset + 16;
    moof[trun_data_offset_at..trun_data_offset_at + 4].copy_from_slice(&data_offset.to_be_bytes());
    let mdat = make_box(b"mdat", payload);
    [moof, mdat].concat()
}

/// A clear segment of exactly `len` bytes: one moof + mdat pair whose mdat
/// payload is padded to reach the length.
fn segment_of_len(len: usize) -> Vec<u8> {
    let overhead = clear_segment(1, b"").len();
    let segment = clear_segment(1, &vec![0x55; len - overhead]);
    assert_eq!(segment.len(), len);
    segment
}

#[test]
fn process_init_status_prepare_shutdown_emits_video_and_audio_renditions() {
    let fixture = ToolFixture::new();
    let operation_root = fixture.prepare_operation();
    let fixture_session =
        ValidatedClearFmp4MediaSessionLayoutV1::new(&clear_init_segment()).unwrap();
    fixture_session
        .validate_segment(&clear_segment(1, b"segment-0"))
        .unwrap();
    let mut provider = ProviderProcess::start();

    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");
    assert_eq!(init["data"]["configured"], true);

    let status = provider.request_json(json!({"op":"status"}));
    assert_eq!(status["status"], "ok");
    assert_eq!(status["data"]["provider"], "media-provider");

    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "ok", "{prepare}");
    assert_eq!(
        prepare["data"],
        prepared_v2(&[video_rendition(2), audio_rendition(2)])
    );

    let ffprobe_args = read_lines(&fixture.ffprobe_args_log);
    assert_eq!(
        ffprobe_args,
        vec![
            "-v".to_string(),
            "error".to_string(),
            "-print_format".to_string(),
            "json".to_string(),
            "-show_entries".to_string(),
            concat!(
                "format=duration",
                ":stream=codec_type,width,height,avg_frame_rate,r_frame_rate",
                ",codec_name,profile,channels,channel_layout,sample_rate",
                ":stream_disposition=attached_pic",
            )
            .to_string(),
            operation_root
                .join("input.bin")
                .to_string_lossy()
                .to_string(),
        ]
    );
    // One invocation, so both renditions share one timeline. The source audio
    // is AAC-LC stereo at 48 kHz, so it is copied, not re-encoded.
    assert_eq!(
        read_lines(&fixture.ffmpeg_args_log),
        expected_ffmpeg_args(
            &operation_root,
            &["0:v:0", "0:a:0"],
            true,
            &["-c:a", "copy", "-tag:a", "mp4a"],
            "id=0,streams=v id=1,streams=a",
        )
    );
    assert!(!operation_root.join("prepared/manifest.mpd").exists());
    assert_eq!(
        sorted_entries(&operation_root.join("prepared")),
        vec!["audio".to_string(), "video".to_string()]
    );
    assert_rendition_validates(&operation_root, "video", 2);
    assert_rendition_validates(&operation_root, "audio", 2);

    provider.shutdown_and_assert_clean();
}

#[test]
fn process_prepare_video_only_source_emits_video_only_v2() {
    let fixture = ToolFixture::new();
    fixture.set_ffprobe_output(video_only_ffprobe_json());
    fixture.set_ffmpeg_mode("success_video");
    let operation_root = fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");

    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "ok", "{prepare}");
    assert_eq!(prepare["data"], prepared_v2(&[video_rendition(2)]));
    assert_eq!(
        read_lines(&fixture.ffmpeg_args_log),
        expected_ffmpeg_args(&operation_root, &["0:v:0"], true, &[], "id=0,streams=v")
    );
    assert_eq!(
        sorted_entries(&operation_root.join("prepared")),
        vec!["video".to_string()]
    );
    assert_rendition_validates(&operation_root, "video", 2);

    provider.shutdown_and_assert_clean();
}

/// A container that states no duration (a raw stream, some live captures) is
/// still a source: the duration was only ever a sanity check on the probe.
#[test]
fn process_prepare_accepts_a_source_with_no_container_duration() {
    let fixture = ToolFixture::new();
    fixture.set_ffprobe_output(
        r#"{"streams":[{"codec_type":"video","width":1280,"height":720,"avg_frame_rate":"30000/1001","r_frame_rate":"30000/1001"}],"format":{}}"#,
    );
    fixture.set_ffmpeg_mode("success_video");
    fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");

    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "ok", "{prepare}");
    assert_eq!(prepare["data"], prepared_v2(&[video_rendition(2)]));

    provider.shutdown_and_assert_clean();
}

#[test]
fn process_stall_timeout_returns_settled_error_and_provider_remains_available() {
    let fixture = ToolFixture::new();
    fixture.set_ffmpeg_mode("stall");
    fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig {
        timeout_ms: SHORT_TIMEOUT_MS,
        ..InitRequestConfig::default()
    }));
    assert_eq!(init["status"], "ok");

    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "error");
    assert_eq!(prepare["code"], "internal_error");
    assert_eq!(prepare["data"]["operation_settled"], true);
    assert!(!process_exists(read_pid_within(&fixture.ffmpeg_pid)));

    let status = provider.request_json(json!({"op":"status"}));
    assert_eq!(status["status"], "ok");

    provider.shutdown_and_assert_clean();
}

/// `timeout_ms` bounds a stall, not the whole encode: ffmpeg runs for longer
/// than the timeout while its output keeps growing, and the prepare succeeds.
/// A fixed deadline would cap the media's length.
#[test]
fn process_prepare_stall_timeout_does_not_cap_a_run_whose_output_keeps_growing() {
    let fixture = ToolFixture::new();
    fixture.set_ffmpeg_mode("slow_progress");
    let operation_root = fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig {
        timeout_ms: PROGRESS_TIMEOUT_MS,
        ..InitRequestConfig::default()
    }));
    assert_eq!(init["status"], "ok");

    let started = std::time::Instant::now();
    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "ok", "{prepare}");
    assert!(
        started.elapsed() > std::time::Duration::from_millis(PROGRESS_TIMEOUT_MS),
        "the mock must outlive the timeout for this test to prove anything"
    );
    assert_eq!(
        prepare["data"],
        prepared_v2(&[video_rendition(2), audio_rendition(2)])
    );
    assert_rendition_validates(&operation_root, "video", 2);

    provider.shutdown_and_assert_clean();
}

#[test]
fn process_prepare_kills_ffmpeg_once_its_output_stops_growing() {
    let fixture = ToolFixture::new();
    fixture.set_ffmpeg_mode("progress_then_stall");
    fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig {
        timeout_ms: SHORT_TIMEOUT_MS,
        ..InitRequestConfig::default()
    }));
    assert_eq!(init["status"], "ok");

    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "error");
    assert_eq!(prepare["code"], "internal_error");
    assert_eq!(prepare["data"]["operation_settled"], true);
    assert!(!process_exists(read_pid_within(&fixture.ffmpeg_pid)));

    provider.shutdown_and_assert_clean();
}

#[test]
fn process_prepare_normalizes_ffmpeg_one_based_dash_segments_to_zero_based() {
    // Real ffmpeg's DASH muxer numbers media segments from 1; the Runtime
    // contract is 0-based, so the provider must shift each run down by one.
    let fixture = ToolFixture::new();
    fixture.set_ffmpeg_mode("success_one_based");
    let operation_root = fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");

    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "ok", "{prepare}");
    for rendition in ["video", "audio"] {
        let segments = operation_root
            .join("prepared")
            .join(rendition)
            .join("segments");
        assert_eq!(
            sorted_entries(&segments),
            vec!["00000000.m4s".to_string(), "00000001.m4s".to_string()]
        );
        assert_eq!(
            fs::read(segments.join("00000000.m4s")).unwrap(),
            clear_segment(1, b"segment-0")
        );
        assert_eq!(
            fs::read(segments.join("00000001.m4s")).unwrap(),
            clear_segment(1, b"segment-1")
        );
    }

    provider.shutdown_and_assert_clean();
}

#[test]
fn process_prepare_strips_ffmpeg_dash_styp_and_sidx_prefix_from_segments() {
    // Real ffmpeg DASH segments start with styp + sidx and are numbered from
    // 1; the provider must hand the Runtime bare, 0-based moof/mdat pairs.
    let fixture = ToolFixture::new();
    fixture.set_ffmpeg_mode("success_dash_prefixed");
    let operation_root = fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");

    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "ok", "prepare response: {prepare}");
    assert_eq!(
        fs::read(operation_root.join("prepared/video/segments/00000000.m4s")).unwrap(),
        clear_segment(1, b"segment-0")
    );
    assert_eq!(
        fs::read(operation_root.join("prepared/video/segments/00000001.m4s")).unwrap(),
        clear_segment(1, b"segment-1")
    );
    assert_rendition_validates(&operation_root, "video", 2);

    provider.shutdown_and_assert_clean();
}

#[test]
fn process_prepare_rejects_gapped_or_offset_segment_numbering() {
    for mode in [
        "gapped_numbering",
        "two_based_numbering",
        "two_fragment_segment",
    ] {
        let fixture = ToolFixture::new();
        fixture.set_ffmpeg_mode(mode);
        fixture.prepare_operation();
        let mut provider = ProviderProcess::start();
        let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
        assert_eq!(init["status"], "ok");

        let prepare = provider.request_json(runtime_prepare_request());
        assert_eq!(prepare["status"], "error", "mode {mode}");
        assert_eq!(prepare["code"], "internal_error", "mode {mode}");
        assert_eq!(prepare["data"]["operation_settled"], true, "mode {mode}");

        provider.shutdown_and_assert_clean();
    }
}

#[test]
fn process_prepare_rejects_nonzero_ffmpeg_exit() {
    let fixture = ToolFixture::new();
    fixture.set_ffmpeg_mode("exit_nonzero");
    fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");

    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "error");
    assert_eq!(prepare["code"], "internal_error");

    provider.shutdown_and_assert_clean();
}

#[test]
fn process_prepare_rejects_malformed_probe_output() {
    let fixture = ToolFixture::new();
    fixture.set_ffprobe_output("{not-json}\n");
    fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");

    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "error");
    assert_eq!(prepare["code"], "internal_error");

    provider.shutdown_and_assert_clean();
}

#[test]
fn probe_with_neither_video_nor_audio_is_rejected() {
    // A source with no playable track has no rendition to produce, so the
    // provider must refuse it rather than hand the Runtime an empty ladder.
    let fixture = ToolFixture::new();
    fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");

    for probe in [
        r#"{"streams":[{"codec_type":"subtitle"}],"format":{"duration":"4.25"}}"#,
        r#"{"streams":[],"format":{"duration":"4.25"}}"#,
    ] {
        fixture.set_ffprobe_output(probe);
        let prepare = provider.request_json(runtime_prepare_request());
        assert_eq!(prepare["status"], "error", "{probe}");
        assert_eq!(prepare["code"], "internal_error", "{probe}");
    }

    provider.shutdown_and_assert_clean();
}

/// A tagged mp3 or m4a is an AUDIO source, not a video one. ffprobe reports its
/// embedded cover art as a video stream, so without the `attached_pic` check the
/// provider would pick the still and run the H.264 branch on it. Library offers
/// protection for every `audio/*` file, so this is the common case, not an edge
/// one.
#[test]
fn prepare_audio_with_embedded_cover_art_chooses_the_aac_rendition() {
    let fixture = ToolFixture::new();
    fixture.set_ffprobe_output(audio_with_cover_art_ffprobe_json());
    fixture.set_ffmpeg_mode("success_audio");
    let operation_root = fixture.prepare_operation();
    let mut provider = ProviderProcess::start();

    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");

    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "ok", "{prepare}");
    assert_eq!(prepare["data"], prepared_v2(&[audio_rendition(2)]));

    // The audio branch only: the still is never mapped or encoded. The probe
    // names no codec, so the plan encodes rather than trusting a copy.
    assert_eq!(
        read_lines(&fixture.ffmpeg_args_log),
        expected_ffmpeg_args(
            &operation_root,
            &["0:a:0"],
            false,
            &[
                "-c:a",
                "aac",
                "-profile:a",
                "aac_low",
                "-b:a",
                "256k",
                "-ar",
                "48000",
                "-ac",
                "2"
            ],
            "id=0,streams=a",
        )
    );
    assert_eq!(
        sorted_entries(&operation_root.join("prepared")),
        vec!["audio".to_string()]
    );
    assert_rendition_validates(&operation_root, "audio", 2);

    provider.shutdown_and_assert_clean();
}

/// Cover art ahead of the real picture in the stream list: the provider maps
/// the real video track by its position among video streams, never the still.
#[test]
fn prepare_maps_the_first_moving_video_stream_past_leading_cover_art() {
    let fixture = ToolFixture::new();
    fixture.set_ffprobe_output(concat!(
        r#"{"streams":["#,
        r#"{"codec_type":"video","width":320,"height":240,"r_frame_rate":"90000/1","avg_frame_rate":"0/0","disposition":{"attached_pic":1}},"#,
        r#"{"codec_type":"video","width":1280,"height":720,"avg_frame_rate":"30/1","r_frame_rate":"30/1","disposition":{"attached_pic":0}},"#,
        r#"{"codec_type":"audio","codec_name":"aac","profile":"LC","channels":2,"channel_layout":"stereo","sample_rate":"44100"}"#,
        r#"],"format":{"duration":"4.25"}}"#,
    ));
    let operation_root = fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");

    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "ok", "{prepare}");
    assert_eq!(
        read_lines(&fixture.ffmpeg_args_log),
        expected_ffmpeg_args(
            &operation_root,
            &["0:v:1", "0:a:0"],
            true,
            &["-c:a", "copy", "-tag:a", "mp4a"],
            "id=0,streams=v id=1,streams=a",
        )
    );

    provider.shutdown_and_assert_clean();
}

#[test]
fn prepare_audio_only_source_emits_aac_dash_rendition() {
    let fixture = ToolFixture::new();
    fixture.set_ffprobe_output(audio_only_ffprobe_json());
    fixture.set_ffmpeg_mode("success_audio");
    let operation_root = fixture.prepare_operation();
    let mut provider = ProviderProcess::start();

    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");

    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "ok", "{prepare}");
    assert_eq!(prepare["data"], prepared_v2(&[audio_rendition(2)]));

    assert_eq!(
        read_lines(&fixture.ffmpeg_args_log),
        expected_ffmpeg_args(
            &operation_root,
            &["0:a:0"],
            false,
            &[
                "-c:a",
                "aac",
                "-profile:a",
                "aac_low",
                "-b:a",
                "256k",
                "-ar",
                "44100"
            ],
            "id=0,streams=a",
        )
    );
    assert_rendition_validates(&operation_root, "audio", 2);

    let init_bytes = fs::read(operation_root.join("prepared/audio/init.mp4")).unwrap();
    let segment_zero =
        fs::read(operation_root.join("prepared/audio/segments/00000000.m4s")).unwrap();
    assert_protection_header_survives_muxing(&init_bytes, &segment_zero, "audio/mp4", "mp4a.40.2");

    provider.shutdown_and_assert_clean();
}

/// Quality first: AAC-LC that MSE plays is copied bit for bit; anything else
/// is encoded to AAC-LC at 192k (mono), 256k (stereo) or 384k (more), never
/// downmixed below 5.1 and never resampled away from 44.1 or 48 kHz.
#[test]
fn prepare_audio_plan_copies_playable_aac_lc_and_encodes_everything_else() {
    const ENCODE: [&str; 4] = ["-c:a", "aac", "-profile:a", "aac_low"];
    let fixture = ToolFixture::new();
    fixture.set_ffmpeg_mode("success_audio");
    fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");

    let encode = |rest: &[&str]| -> Vec<String> {
        ENCODE
            .iter()
            .chain(rest)
            .map(|arg| arg.to_string())
            .collect()
    };
    // A copy re-tags the stream: MPEG-TS carries AAC under a tag the mp4
    // muxer refuses.
    let copy = ["-c:a", "copy", "-tag:a", "mp4a"]
        .map(str::to_string)
        .to_vec();
    let cases: Vec<(&str, Vec<String>)> = vec![
        (
            r#""codec_name":"aac","profile":"LC","channels":2,"channel_layout":"stereo","sample_rate":"48000""#,
            copy.clone(),
        ),
        (
            r#""codec_name":"aac","profile":"LC","channels":1,"channel_layout":"mono","sample_rate":"44100""#,
            copy.clone(),
        ),
        (
            r#""codec_name":"aac","profile":"LC","channels":6,"channel_layout":"5.1","sample_rate":"48000""#,
            copy.clone(),
        ),
        (
            r#""codec_name":"aac","profile":"LC","channels":6,"channel_layout":"5.1(side)","sample_rate":"44100""#,
            copy.clone(),
        ),
        // Six channels that are not 5.1: encoded, layout kept.
        (
            r#""codec_name":"aac","profile":"LC","channels":6,"channel_layout":"6.0","sample_rate":"48000""#,
            encode(&["-b:a", "384k", "-ar", "48000"]),
        ),
        (
            r#""codec_name":"aac","profile":"LC","channels":3,"channel_layout":"2.1","sample_rate":"48000""#,
            encode(&["-b:a", "384k", "-ar", "48000"]),
        ),
        (
            r#""codec_name":"aac","profile":"HE-AAC","channels":2,"channel_layout":"stereo","sample_rate":"48000""#,
            encode(&["-b:a", "256k", "-ar", "48000"]),
        ),
        (
            r#""codec_name":"aac","profile":"LC","channels":2,"channel_layout":"stereo","sample_rate":"32000""#,
            encode(&["-b:a", "256k", "-ar", "48000"]),
        ),
        (
            r#""codec_name":"aac","profile":"LC","channels":2,"channel_layout":"stereo","sample_rate":"96000""#,
            encode(&["-b:a", "256k", "-ar", "48000"]),
        ),
        (
            r#""codec_name":"mp3","channels":2,"channel_layout":"stereo","sample_rate":"44100""#,
            encode(&["-b:a", "256k", "-ar", "44100"]),
        ),
        (
            r#""codec_name":"opus","channels":1,"channel_layout":"mono","sample_rate":"48000""#,
            encode(&["-b:a", "192k", "-ar", "48000"]),
        ),
        (
            r#""codec_name":"flac","channels":4,"channel_layout":"quad","sample_rate":"96000""#,
            encode(&["-b:a", "384k", "-ar", "48000"]),
        ),
        // More than six channels: the one downmix, to 5.1.
        (
            r#""codec_name":"pcm_s24le","channels":8,"channel_layout":"7.1","sample_rate":"48000""#,
            encode(&["-b:a", "384k", "-ar", "48000", "-ac", "6"]),
        ),
        // Any doubt about the source means encode, to stereo.
        (
            r#""codec_name":"aac""#,
            encode(&["-b:a", "256k", "-ar", "48000", "-ac", "2"]),
        ),
    ];
    for (fields, expected) in cases {
        fixture.set_ffprobe_output(&audio_probe(fields));
        let prepare = provider.request_json(runtime_prepare_request());
        assert_eq!(prepare["status"], "ok", "{fields}: {prepare}");
        let args = read_lines(&fixture.ffmpeg_args_log);
        let start = args.iter().position(|arg| arg == "0:a:0").unwrap() + 1;
        let end = args.iter().position(|arg| arg == "-movflags").unwrap();
        assert_eq!(args[start..end].to_vec(), expected, "{fields}");
    }

    provider.shutdown_and_assert_clean();
}

/// Runs the audio argv through the real muxer. Ignored by default because it
/// needs `ffmpeg`/`ffprobe` on PATH and produces a real encode; run it with
/// `cargo test -- --ignored real_ffmpeg`.
///
/// It PANICS rather than returning when the tools are missing: this test is the
/// only proof that the protection header survives a real muxer's box layout, and a
/// green run that silently skipped the muxer would be worth nothing as evidence.
#[test]
#[ignore]
fn real_ffmpeg_audio_only_dash_layout_validates() {
    let (_root, operation_root, prepare, provider) = real_ffmpeg_prepare(&[
        "-f",
        "lavfi",
        "-i",
        "sine=frequency=440:duration=5",
        "-c:a",
        "pcm_s16le",
        "-f",
        "wav",
    ]);
    assert_eq!(prepare["status"], "ok", "{prepare}");
    assert_eq!(prepare["data"], prepared_v2(&[audio_rendition(3)]));
    assert_eq!(
        sorted_entries(&operation_root.join("prepared")),
        vec!["audio".to_string()]
    );
    assert_real_rendition_validates_v2(&operation_root, "audio", 3);
    assert_real_rendition_protects(&operation_root, "audio", "audio/mp4", "mp4a.40.2");

    provider.shutdown_and_assert_clean();
}

/// A real video + AAC-LC stereo source through the real muxer: one invocation
/// yields both renditions on 2 s segments, the audio is copied (AAC-LC 48 kHz
/// stereo), and every part validates and protects.
#[test]
#[ignore]
fn real_ffmpeg_video_and_audio_dash_layout_validates() {
    let (_root, operation_root, prepare, provider) = real_ffmpeg_prepare(&[
        "-f",
        "lavfi",
        "-i",
        "testsrc2=size=320x240:rate=30:duration=5",
        "-f",
        "lavfi",
        "-i",
        "sine=frequency=440:duration=5",
        "-map",
        "0:v",
        "-map",
        "1:a",
        "-c:v",
        "libx264",
        "-preset",
        "ultrafast",
        "-c:a",
        "aac",
        "-profile:a",
        "aac_low",
        "-ac",
        "2",
        "-ar",
        "48000",
        "-f",
        "mp4",
    ]);
    assert_eq!(prepare["status"], "ok", "{prepare}");
    assert_eq!(
        prepare["data"],
        prepared_v2(&[video_rendition(3), audio_rendition(3)])
    );
    assert_eq!(
        sorted_entries(&operation_root.join("prepared")),
        vec!["audio".to_string(), "video".to_string()]
    );
    assert_real_rendition_validates_v2(&operation_root, "video", 3);
    assert_real_rendition_validates_v2(&operation_root, "audio", 3);
    assert_real_rendition_protects(&operation_root, "video", "video/mp4", "avc1.640028");
    assert_real_rendition_protects(&operation_root, "audio", "audio/mp4", "mp4a.40.2");
    assert_real_video_codec_and_gop(&operation_root);
    assert_real_audio_was_copied(&operation_root);

    provider.shutdown_and_assert_clean();
}

/// MPEG-TS carries AAC under a stream tag the mp4 muxer refuses, so a plain
/// `-c:a copy` fails on every `.ts` source. The copy must re-tag it.
#[test]
#[ignore]
fn real_ffmpeg_mpegts_audio_only_copies_aac_lc() {
    let (_root, operation_root, prepare, provider) = real_ffmpeg_prepare(&[
        "-f",
        "lavfi",
        "-i",
        "sine=frequency=440:duration=5",
        "-c:a",
        "aac",
        "-profile:a",
        "aac_low",
        "-ac",
        "2",
        "-ar",
        "48000",
        "-f",
        "mpegts",
    ]);
    assert_eq!(prepare["status"], "ok", "{prepare}");
    assert_eq!(prepare["data"], prepared_v2(&[audio_rendition(3)]));
    assert_real_rendition_validates_v2(&operation_root, "audio", 3);
    assert_real_rendition_protects(&operation_root, "audio", "audio/mp4", "mp4a.40.2");
    assert_real_audio_was_copied(&operation_root);

    provider.shutdown_and_assert_clean();
}

/// A `.ts` with H.264 and AAC-LC, at 25 fps and 640x360: neither the source
/// rate nor its size matches the output's, and the 2 s GOP still holds.
#[test]
#[ignore]
fn real_ffmpeg_mpegts_video_and_audio_copies_aac_lc() {
    let (_root, operation_root, prepare, provider) = real_ffmpeg_prepare(&[
        "-f",
        "lavfi",
        "-i",
        "testsrc2=size=640x360:rate=25:duration=5",
        "-f",
        "lavfi",
        "-i",
        "sine=frequency=440:duration=5",
        "-map",
        "0:v",
        "-map",
        "1:a",
        "-c:v",
        "libx264",
        "-preset",
        "ultrafast",
        "-c:a",
        "aac",
        "-profile:a",
        "aac_low",
        "-ac",
        "2",
        "-ar",
        "48000",
        "-f",
        "mpegts",
    ]);
    assert_eq!(prepare["status"], "ok", "{prepare}");
    assert_eq!(
        prepare["data"],
        prepared_v2(&[video_rendition(3), audio_rendition(3)])
    );
    assert_real_rendition_validates_v2(&operation_root, "video", 3);
    assert_real_rendition_validates_v2(&operation_root, "audio", 3);
    assert_real_rendition_protects(&operation_root, "video", "video/mp4", "avc1.640028");
    assert_real_rendition_protects(&operation_root, "audio", "audio/mp4", "mp4a.40.2");
    assert_real_video_codec_and_gop(&operation_root);
    assert_real_audio_was_copied(&operation_root);

    provider.shutdown_and_assert_clean();
}

/// The pinned codec string must be what the encoder really wrote: avcC's
/// profile, compatibility and level bytes. And every video segment must open
/// on a keyframe and hold exactly one, so the GOP is the 2 s segment.
fn assert_real_video_codec_and_gop(operation_root: &Path) {
    let ffprobe = tool_on_path("ffprobe").expect("ffprobe on PATH");
    let dir = operation_root.join("prepared/video");
    let init = fs::read(dir.join("init.mp4")).unwrap();
    let avcc = init
        .windows(4)
        .position(|window| window == b"avcC")
        .expect("avcC box in the video init");
    assert_eq!(
        format!(
            "avc1.{:02x}{:02x}{:02x}",
            init[avcc + 5],
            init[avcc + 6],
            init[avcc + 7]
        ),
        "avc1.640028"
    );

    let scratch = tempfile::tempdir().unwrap();
    for name in sorted_entries(&dir.join("segments")) {
        let joined = scratch.path().join(format!("{name}.mp4"));
        fs::write(
            &joined,
            [
                init.clone(),
                fs::read(dir.join("segments").join(&name)).unwrap(),
            ]
            .concat(),
        )
        .unwrap();
        let output = Command::new(&ffprobe)
            .args([
                "-v",
                "error",
                "-select_streams",
                "v:0",
                "-show_entries",
                "packet=flags",
                "-of",
                "csv=p=0",
            ])
            .arg(&joined)
            .output()
            .unwrap();
        assert!(output.status.success(), "ffprobe failed on {name}");
        let flags = String::from_utf8(output.stdout).unwrap();
        let flags = flags.lines().collect::<Vec<_>>();
        assert!(
            flags.first().is_some_and(|first| first.starts_with('K')),
            "{name} does not open on a keyframe: {flags:?}"
        );
        assert_eq!(
            flags.iter().filter(|flag| flag.starts_with('K')).count(),
            1,
            "{name} holds more than one GOP: {flags:?}"
        );
    }
}

/// Proves copy-through: the audio samples in the prepared segments are the
/// source's AAC access units byte for byte. Any re-encode changes them.
fn assert_real_audio_was_copied(operation_root: &Path) {
    let ffmpeg = tool_on_path("ffmpeg").expect("ffmpeg on PATH");
    let scratch = tempfile::tempdir().unwrap();
    let adts_path = scratch.path().join("source.aac");
    let extracted = Command::new(&ffmpeg)
        .args(["-nostdin", "-v", "error", "-y", "-i"])
        .arg(operation_root.join("input.bin"))
        .args(["-map", "0:a:0", "-c:a", "copy", "-f", "adts"])
        .arg(&adts_path)
        .status()
        .unwrap();
    assert!(extracted.success(), "source AAC extraction failed");
    let adts = fs::read(&adts_path).unwrap();
    let mut source_units = Vec::new();
    let mut offset = 0;
    while offset < adts.len() {
        let header = &adts[offset..];
        assert_eq!(header[0], 0xff, "ADTS sync lost at {offset}");
        let header_len = if header[1] & 0x01 == 1 { 7 } else { 9 };
        let frame_len = (usize::from(header[3] & 0x03) << 11)
            | (usize::from(header[4]) << 3)
            | (usize::from(header[5]) >> 5);
        source_units.extend_from_slice(&header[header_len..frame_len]);
        offset += frame_len;
    }

    let segments = operation_root.join("prepared/audio/segments");
    let mut prepared_units = Vec::new();
    for name in sorted_entries(&segments) {
        prepared_units.extend_from_slice(&mdat_payload(&fs::read(segments.join(&name)).unwrap()));
    }
    assert!(!source_units.is_empty());
    assert!(
        prepared_units == source_units,
        "the prepared audio is not the source's AAC: {} vs {} bytes",
        prepared_units.len(),
        source_units.len()
    );
}

fn mdat_payload(segment: &[u8]) -> Vec<u8> {
    let mut offset = 0;
    while offset < segment.len() {
        let size = u32::from_be_bytes(segment[offset..offset + 4].try_into().unwrap()) as usize;
        if &segment[offset + 4..offset + 8] == b"mdat" {
            return segment[offset + 8..offset + size].to_vec();
        }
        offset += size;
    }
    panic!("segment without mdat");
}

/// Generates a 5 s source with the real ffmpeg (`source_args` are the encode
/// arguments, ending with the output format) and runs one prepare on it.
fn real_ffmpeg_prepare(
    source_args: &[&str],
) -> (
    tempfile::TempDir,
    PathBuf,
    serde_json::Value,
    ProviderProcess,
) {
    let (Some(ffmpeg), Some(ffprobe)) = (tool_on_path("ffmpeg"), tool_on_path("ffprobe")) else {
        panic!(
            "this test proves the real muxer's output, so it cannot pass without one: \
             ffmpeg and ffprobe must both be on PATH"
        );
    };
    let root = tempfile::tempdir().unwrap();
    let staging_root = root.path().join("staging");
    fs::create_dir(&staging_root).unwrap();
    fs::set_permissions(&staging_root, fs::Permissions::from_mode(0o700)).unwrap();
    let operation_root = staging_root.join(OPERATION_ID);
    fs::create_dir(&operation_root).unwrap();
    fs::set_permissions(&operation_root, fs::Permissions::from_mode(0o700)).unwrap();
    let input_path = operation_root.join("input.bin");
    let generated = Command::new(&ffmpeg)
        .args(["-nostdin", "-v", "error", "-y"])
        .args(source_args)
        .arg(&input_path)
        .status()
        .unwrap();
    assert!(generated.success(), "source generation failed");
    fs::set_permissions(&input_path, fs::Permissions::from_mode(0o600)).unwrap();

    let mut provider = ProviderProcess::start();
    let init = provider.request_json(json!({
        "op": "init",
        "config": {
            "base_path": "",
            "allowed_paths": [],
            "read_only": false,
            "encryption_key": "",
            "extra": {
                "provider_id": "media-provider",
                "staging_root": staging_root,
                "ffmpeg_path": ffmpeg,
                "ffprobe_path": ffprobe,
                "output_profile": "browser_fmp4_h264_v1",
                "timeout_ms": NORMAL_TIMEOUT_MS,
                "max_stdio_bytes": 4096,
                "max_input_bytes": 1u64 << 20,
                "max_output_part_bytes": 1u64 << 20,
                "max_duration_secs": 60,
                "max_source_width": 1920,
                "max_source_height": 1080,
                "max_source_fps": 60,
                "max_segment_count": 8,
                "max_total_output_bytes": 1u64 << 22
            }
        }
    }));
    assert_eq!(init["status"], "ok", "{init}");
    let prepare = provider.request_json(runtime_prepare_request());
    (root, operation_root, prepare, provider)
}

fn assert_real_rendition_protects(
    operation_root: &Path,
    rendition: &str,
    mime: &str,
    codecs: &str,
) {
    let dir = operation_root.join("prepared").join(rendition);
    let init_bytes = fs::read(dir.join("init.mp4")).unwrap();
    for name in sorted_entries(&dir.join("segments")) {
        let segment = fs::read(dir.join("segments").join(&name)).unwrap();
        assert!(
            segment.len() as u64 <= PART_RULE_BYTES as u64,
            "{rendition}/{name} breaks the part rule"
        );
        assert_protection_header_survives_muxing(&init_bytes, &segment, mime, codecs);
    }
}

/// A real muxed init segment must survive the protect rewrite with the CENC
/// protection header in place: the protected pair must validate as protected fMP4
/// media, the header must read back as this scheme's own, and rewriting the init
/// segment back to clear must reproduce the muxer's bytes exactly.
///
/// The samples are "encrypted" here by copying them at their original lengths.
/// Real content encryption is length-preserving and lives outside this capsule;
/// what this proves is that the box survives a REAL muxer's box layout, not that
/// the cipher works.
fn assert_protection_header_survives_muxing(
    clear_init: &[u8],
    clear_segment: &[u8],
    mime: &str,
    codecs: &str,
) {
    let content_access_id = ContentAccessIdV1::new([0x55; 16]).unwrap();
    let pssh_data = CustodyProtectionHeader::new(
        content_access_id,
        &CustodyPoolIdentityV1::new(Digest32::new([0x61; 32]), 512).unwrap(),
        &CustodyEpochIdentityV1::new(Digest32::new([0x62; 32]), 512).unwrap(),
        &CustodyCommitteeAuthorizationIdentityV1::new(Digest32::new([0x63; 32]), 512).unwrap(),
        CencMediaSuite::Fmp4V1,
    );
    let session = ValidatedClearFmp4MediaSessionLayoutV1::new(clear_init).unwrap();
    let protected_init = session
        .rewrite_protected_init(clear_init, &pssh_data)
        .expect("a real muxed init segment protects with the protection header");
    assert!(
        protected_init.len() > clear_init.len(),
        "the protection header must actually be in the bytes"
    );

    let segment_layout = session.validate_segment(clear_segment).unwrap();
    let clear_mdat = segment_layout
        .exact_source_mdat_payload(clear_segment)
        .unwrap();
    let mut samples = Vec::new();
    let mut ivs = Vec::new();
    for (index, sample) in segment_layout.samples().iter().enumerate() {
        let start = usize::try_from(sample.mdat_offset()).unwrap();
        let end = start + sample.sample_size() as usize;
        samples.push(clear_mdat[start..end].to_vec());
        ivs.push((index as u64 + 1).to_be_bytes());
    }
    let protected_segment = segment_layout
        .rewrite_protected_segment(clear_segment, &samples, &ivs)
        .unwrap();

    let media = CencFmp4MediaIdentityV1::new_from_bytes(
        &protected_init,
        std::slice::from_ref(&protected_segment),
        mime,
        codecs,
    )
    .expect("the protected pair validates with the protection header in moov");
    let protected_layout =
        ValidatedCencFmp4MediaSessionLayoutV1::new(&media, &protected_init).unwrap();
    assert_eq!(protected_layout.content_access_id(), content_access_id);

    let (system, parsed) = PROTECTION
        .registry()
        .decode_custody(&protected_init[find_pssh_offset(&protected_init)..])
        .expect("the box in the muxed init segment parses as ours");
    assert_eq!(
        PROTECTION
            .registry()
            .lookup(system.as_bytes())
            .unwrap()
            .scheme,
        ELASTOS_PQ_PROTECTION_SCHEME_V1
    );
    assert_eq!(parsed, pssh_data);

    assert_eq!(
        protected_layout
            .rewrite_clear_init(&protected_init)
            .unwrap(),
        clear_init,
        "the read path must restore the muxer's exact clear bytes"
    );
}

/// Locates the `pssh` box by walking `moov`'s children, so the assertion above
/// does not depend on a hardcoded offset into a real muxer's output.
fn find_pssh_offset(init: &[u8]) -> usize {
    let read_size =
        |off: usize| u32::from_be_bytes(init[off..off + 4].try_into().unwrap()) as usize;
    let mut off = 0usize;
    while &init[off + 4..off + 8] != b"moov" {
        off += read_size(off);
    }
    let moov_end = off + read_size(off);
    let mut child = off + 8;
    while child < moov_end {
        if &init[child + 4..child + 8] == b"pssh" {
            return child;
        }
        child += read_size(child);
    }
    panic!("no pssh box in the protected init segment");
}

/// Resolves a tool on PATH to a real (non-symlink) path, which the provider
/// config requires.
fn tool_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| fs::canonicalize(candidate).ok())
}

/// Mint has no size caps any more: a long, large, 8K, 120 fps source with
/// more segments, bytes and duration than every removed config field allows
/// still prepares. The removed fields are accepted but no longer enforced.
#[test]
fn process_prepare_refuses_nonfinite_duration_but_no_long_large_or_fast_source() {
    let fixture = ToolFixture::new();
    fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig {
        max_input_bytes: 1,
        max_output_part_bytes: 1,
        max_segment_count: 1,
        max_total_output_bytes: 1,
        max_duration_secs: 1,
        max_source_width: 1,
        max_source_height: 1,
        max_source_fps: 1,
        ..InitRequestConfig::default()
    }));
    assert_eq!(init["status"], "ok");

    fixture.set_ffprobe_output(
        r#"{"streams":[{"codec_type":"video","width":1280,"height":720,"avg_frame_rate":"30000/1001","r_frame_rate":"30000/1001"}],"format":{"duration":"NaN"}}"#,
    );
    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "error");

    fixture.set_ffprobe_output(concat!(
        r#"{"streams":["#,
        r#"{"codec_type":"video","width":7680,"height":4320,"avg_frame_rate":"120/1","r_frame_rate":"120/1"},"#,
        r#"{"codec_type":"audio","codec_name":"aac","profile":"LC","channels":2,"channel_layout":"stereo","sample_rate":"48000"}"#,
        r#"],"format":{"duration":"36000.0"}}"#,
    ));
    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "ok", "{prepare}");
    assert_eq!(
        prepare["data"],
        prepared_v2(&[video_rendition(2), audio_rendition(2)])
    );

    provider.shutdown_and_assert_clean();
}

/// The protocol part rule: a clear part is at most 2 MiB - 64 KiB. A part
/// exactly at the rule prepares; one byte over is refused with a message the
/// creator can act on, not the generic failure.
#[test]
fn process_prepare_refuses_a_part_over_the_part_rule_with_a_clear_message() {
    let fixture = ToolFixture::new();
    fixture.set_ffmpeg_mode("at_part_rule");
    let operation_root = fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");

    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "ok", "{prepare}");
    assert_eq!(
        fs::metadata(operation_root.join("prepared/video/segments/00000000.m4s"))
            .unwrap()
            .len(),
        PART_RULE_BYTES as u64
    );

    fixture.set_ffmpeg_mode("over_part_rule");
    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "error");
    assert_eq!(prepare["code"], "internal_error");
    assert_eq!(
        prepare["message"],
        "a prepared media part exceeds the 2 MiB part limit"
    );
    assert_eq!(prepare["data"]["operation_settled"], true);

    // The init is held to the same rule, with the same message.
    fixture.set_ffmpeg_mode("over_part_rule_init");
    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "error");
    assert_eq!(
        prepare["message"],
        "a prepared media part exceeds the 2 MiB part limit"
    );

    fixture.set_ffmpeg_mode("exit_nonzero");
    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["message"], "media preparation failed");

    provider.shutdown_and_assert_clean();
}

#[test]
fn process_prepare_kills_tool_on_oversized_stdout_or_stderr() {
    let fixture = ToolFixture::new();
    fixture.prepare_operation();
    let mut provider = ProviderProcess::start();

    let oversized = "x".repeat(8192);
    fixture.set_ffprobe_output(&oversized);
    fixture.set_ffprobe_mode("hang_after_output");
    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");
    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "error");
    assert!(!process_exists(read_pid_within(&fixture.ffprobe_pid)));

    fixture.set_ffprobe_output(valid_ffprobe_json());
    fixture.set_ffprobe_stderr("");
    fixture.set_ffprobe_mode("normal");
    fixture.set_ffmpeg_stderr(&oversized);
    fixture.set_ffmpeg_mode("stall");
    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "error");
    assert!(!process_exists(read_pid_within(&fixture.ffmpeg_pid)));

    provider.shutdown_and_assert_clean();
}

#[test]
fn process_rejects_oversized_request_frame_and_stays_synchronized() {
    let fixture = ToolFixture::new();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");

    let response = provider.request_raw_line(&vec![b'a'; 20 * 1024]);
    assert_eq!(response["status"], "error");
    assert_eq!(response["code"], "invalid_request");

    let status = provider.request_json(json!({"op":"status"}));
    assert_eq!(status["status"], "ok");
    assert_eq!(status["data"]["provider"], "media-provider");

    provider.shutdown_and_assert_clean();
}

#[test]
fn process_init_rejects_values_above_provider_hard_limits() {
    let fixture = ToolFixture::new();
    for request in [
        fixture.init_request(InitRequestConfig {
            timeout_ms: 3_600_001,
            ..InitRequestConfig::default()
        }),
        fixture.init_request(InitRequestConfig {
            timeout_ms: 0,
            ..InitRequestConfig::default()
        }),
        fixture.init_request(InitRequestConfig {
            max_stdio_bytes: (1 << 20) + 1,
            ..InitRequestConfig::default()
        }),
        fixture.init_request(InitRequestConfig {
            max_stdio_bytes: 0,
            ..InitRequestConfig::default()
        }),
    ] {
        let mut provider = ProviderProcess::start();
        let response = provider.request_json(request);
        assert_eq!(response["status"], "error");
        assert_eq!(response["code"], "invalid_config");
        provider.shutdown_and_assert_clean();
    }
}

/// Installed Homes keep their config file: the removed limit fields still load
/// with any value of their type, and a config that omits them loads too, so a
/// Runtime that stops writing them keeps working.
#[test]
fn process_init_accepts_any_value_in_the_removed_limit_fields_or_none_at_all() {
    let fixture = ToolFixture::new();
    for config in [
        InitRequestConfig {
            max_input_bytes: 0,
            max_output_part_bytes: 0,
            max_segment_count: 0,
            max_total_output_bytes: 0,
            max_duration_secs: 0,
            max_source_width: 0,
            max_source_height: 0,
            max_source_fps: 0,
            ..InitRequestConfig::default()
        },
        InitRequestConfig {
            max_input_bytes: u64::MAX,
            max_output_part_bytes: u64::MAX,
            max_segment_count: usize::MAX,
            max_total_output_bytes: u64::MAX,
            max_duration_secs: u64::MAX,
            max_source_width: u32::MAX,
            max_source_height: u32::MAX,
            max_source_fps: u32::MAX,
            ..InitRequestConfig::default()
        },
    ] {
        let mut provider = ProviderProcess::start();
        let response = provider.request_json(fixture.init_request(config));
        assert_eq!(response["status"], "ok", "{response}");
        provider.shutdown_and_assert_clean();
    }

    let mut without_removed_fields = fixture.init_request(InitRequestConfig::default());
    let extra = without_removed_fields["config"]["extra"]
        .as_object_mut()
        .unwrap();
    for field in [
        "max_input_bytes",
        "max_output_part_bytes",
        "max_duration_secs",
        "max_source_width",
        "max_source_height",
        "max_source_fps",
        "max_segment_count",
        "max_total_output_bytes",
    ] {
        extra.remove(field).unwrap();
    }
    let mut provider = ProviderProcess::start();
    let response = provider.request_json(without_removed_fields);
    assert_eq!(response["status"], "ok", "{response}");
    provider.shutdown_and_assert_clean();

    let mut missing_field = fixture.init_request(InitRequestConfig::default());
    missing_field["config"]["extra"]
        .as_object_mut()
        .unwrap()
        .remove("timeout_ms");
    let mut wrong_type = fixture.init_request(InitRequestConfig::default());
    wrong_type["config"]["extra"]["max_input_bytes"] = json!("unlimited");
    let mut wrong_profile = fixture.init_request(InitRequestConfig::default());
    wrong_profile["config"]["extra"]["output_profile"] = json!("browser_dash_v2");
    for request in [missing_field, wrong_type, wrong_profile] {
        let mut provider = ProviderProcess::start();
        let response = provider.request_json(request);
        assert_eq!(response["code"], "invalid_config");
        provider.shutdown_and_assert_clean();
    }
}

#[test]
fn process_prepare_rejects_path_indirection_and_redacts_private_details() {
    let fixture = ToolFixture::new();
    let operation_root = fixture.prepare_operation();
    let input_path = operation_root.join("input.bin");
    let outside_path = fixture
        .staging_root
        .parent()
        .unwrap()
        .join("private-source-video");
    fs::write(&outside_path, b"private-video").unwrap();
    fs::remove_file(&input_path).unwrap();
    std::os::unix::fs::symlink(&outside_path, &input_path).unwrap();
    let mut provider = ProviderProcess::start();
    assert_eq!(
        provider.request_json(fixture.init_request(InitRequestConfig::default()))["status"],
        "ok"
    );

    let response = provider.request_json(runtime_prepare_request());

    assert_eq!(response["status"], "error");
    assert_eq!(response["code"], "internal_error");
    let encoded = serde_json::to_string(&response).unwrap();
    assert!(!encoded.contains(outside_path.to_string_lossy().as_ref()));
    assert!(!fixture.ffprobe_args_log.exists());
    provider.shutdown_and_assert_clean();
}

#[test]
fn process_prepare_rejects_nonruntime_authority_and_topology_fields() {
    let fixture = ToolFixture::new();
    fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    assert_eq!(
        provider.request_json(fixture.init_request(InitRequestConfig::default()))["status"],
        "ok"
    );
    let mut wrong_transport = runtime_prepare_request();
    wrong_transport["_runtime_invocation"]["transport"] = json!("carrier-provider-plane");
    wrong_transport["_runtime_invocation"]["carrier"] = json!({"peer_did":"did:example:peer"});
    let mut wrong_capability = runtime_prepare_request();
    wrong_capability["_runtime_invocation"]["capability"] = json!("provider:caller->media:prepare");
    let mut caller_path = runtime_prepare_request();
    caller_path["local_path"] = json!("/private/source.mp4");
    let mut wrong_abi = runtime_prepare_request();
    wrong_abi["_runtime_invocation"]["abi"]["range_supported"] = json!(true);
    let mut missing_abi = runtime_prepare_request();
    missing_abi["_runtime_invocation"]
        .as_object_mut()
        .unwrap()
        .remove("abi");

    for request in [
        wrong_transport,
        wrong_capability,
        caller_path,
        wrong_abi,
        missing_abi,
    ] {
        let response = provider.request_json(request);
        assert_eq!(response["status"], "error");
        assert_eq!(response["code"], "invalid_request");
    }
    assert!(!fixture.ffprobe_args_log.exists());
    provider.shutdown_and_assert_clean();
}

#[test]
fn process_timeout_after_caller_cancellation_reports_settlement_and_exits_cleanly() {
    let fixture = ToolFixture::new();
    fixture.set_ffmpeg_mode("stall");
    fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    assert_eq!(
        provider.request_json(fixture.init_request(InitRequestConfig {
            timeout_ms: SHORT_TIMEOUT_MS,
            ..InitRequestConfig::default()
        }))["status"],
        "ok"
    );
    let mut stdin = provider.stdin.take().unwrap();
    serde_json::to_writer(&mut stdin, &runtime_prepare_request()).unwrap();
    writeln!(stdin).unwrap();
    stdin.flush().unwrap();
    drop(stdin);

    let response = provider.read_response();
    assert_eq!(response["status"], "error");
    assert_eq!(response["code"], "internal_error");
    assert_eq!(response["data"]["operation_settled"], true);
    assert!(provider.child.wait().unwrap().success());
    provider.assert_empty_stderr();
}

#[test]
fn process_prepare_accepts_extra_ffprobe_fields_and_falls_back_to_r_frame_rate() {
    let fixture = ToolFixture::new();
    fixture.set_ffprobe_output(
        r#"{"streams":[{"codec_type":"video","width":1280,"height":720,"avg_frame_rate":"oops","r_frame_rate":"30000/1001","codec_name":"h264","disposition":{"default":1}}],"format":{"duration":"4.25","format_name":"mov,mp4"},"packets_and_frames":{"ignored":true}}"#,
    );
    fixture.set_ffmpeg_mode("success_video");
    fixture.prepare_operation();
    let mut provider = ProviderProcess::start();
    let init = provider.request_json(fixture.init_request(InitRequestConfig::default()));
    assert_eq!(init["status"], "ok");

    let prepare = provider.request_json(runtime_prepare_request());
    assert_eq!(prepare["status"], "ok");

    provider.shutdown_and_assert_clean();
}

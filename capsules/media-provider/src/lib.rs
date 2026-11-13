use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const PROVIDER_ID: &str = "media-provider";
const PROTOCOL_VERSION: &str = "elastos.media-provider/v1";
const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");
const INIT_ERROR_CODE: &str = "invalid_config";
const REQUEST_ERROR_CODE: &str = "invalid_request";
const INTERNAL_ERROR_CODE: &str = "internal_error";
const OPERATION_ID_HEX_LEN: usize = 64;
const MAX_PROVIDER_FRAME_BYTES: usize = 16 * 1024;
const MAX_TIMEOUT_MS: u64 = 3_600_000;
const MAX_STDIO_BYTES: usize = 1024 * 1024;
/// The protocol part rule: every clear part handed to the Runtime is at most
/// 2 MiB - 64 KiB, so the protected part stays within the 2 MiB wire part.
/// 2 s segments under the 5 Mb/s VBV ceiling stay well below it.
const MAX_PREPARED_PART_BYTES: u64 = 2 * 1024 * 1024 - 64 * 1024;
const PART_TOO_LARGE_MESSAGE: &str = "a prepared media part exceeds the 2 MiB part limit";
/// How often the stall monitor rescans the prepared output. Long media yields
/// thousands of parts, so the scan must not run on every 10 ms wait tick.
const OUTPUT_MONITOR_SCAN_INTERVAL: Duration = Duration::from_millis(250);
const OUTPUT_SCHEMA_V2: &str = "elastos.media-provider.prepared-media/v2";
/// A historical name: every mint now produces the v2 output, but installed
/// Homes store this value in their config file.
const OUTPUT_PROFILE_BROWSER_FMP4_H264_V1: &str = "browser_fmp4_h264_v1";
const OUTPUT_MIME_TYPE_VIDEO_V1: &str = "video/mp4";
const OUTPUT_CODECS_VIDEO_V1: &str = "avc1.640028";
const OUTPUT_MIME_TYPE_AUDIO_V1: &str = "audio/mp4";
const OUTPUT_CODECS_AUDIO_V1: &str = "mp4a.40.2";
const OUTPUT_SEGMENT_DURATION_SECS: &str = "2";
/// 2 s fixed GOPs at the 30 fps output rate, aligned with the segments.
const OUTPUT_VIDEO_GOP_FRAMES: &str = "60";
const OUTPUT_VIDEO_VBV_RATE: &str = "5000k";

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum ControlRequest {
    Init { config: Value },
    Status,
    Shutdown,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum MediaProviderRequest {
    Prepare { operation_id: String },
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ProviderResponse {
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<Value>,
    },
    Error {
        code: &'static str,
        message: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<Value>,
    },
}

impl ProviderResponse {
    fn ok(data: Value) -> Self {
        Self::Ok { data: Some(data) }
    }

    fn empty_ok() -> Self {
        Self::Ok { data: None }
    }

    fn error(code: &'static str, message: &'static str) -> Self {
        Self::Error {
            code,
            message,
            data: None,
        }
    }

    fn settled_error(code: &'static str, message: &'static str, settled: bool) -> Self {
        Self::Error {
            code,
            message,
            data: Some(json!({"operation_settled": settled})),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitConfig {
    #[serde(default)]
    base_path: String,
    #[serde(default)]
    allowed_paths: Vec<String>,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    encryption_key: String,
    extra: MediaInitExtraConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MediaInitExtraConfig {
    provider_id: String,
    staging_root: String,
    ffmpeg_path: String,
    ffprobe_path: String,
    output_profile: String,
    timeout_ms: u64,
    max_stdio_bytes: usize,
    // The limit fields below are no longer enforced: mint has no size caps.
    // Installed config files still carry them, so they load with any value of
    // their type; a config that omits them loads too.
    #[allow(dead_code)]
    #[serde(default)]
    max_input_bytes: u64,
    #[allow(dead_code)]
    #[serde(default)]
    max_output_part_bytes: u64,
    #[allow(dead_code)]
    #[serde(default)]
    max_duration_secs: u64,
    #[allow(dead_code)]
    #[serde(default)]
    max_source_width: u32,
    #[allow(dead_code)]
    #[serde(default)]
    max_source_height: u32,
    #[allow(dead_code)]
    #[serde(default)]
    max_source_fps: u32,
    #[allow(dead_code)]
    #[serde(default)]
    max_segment_count: usize,
    #[allow(dead_code)]
    #[serde(default)]
    max_total_output_bytes: u64,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct PreparedMediaOutput {
    schema: &'static str,
    renditions: Vec<PreparedRendition>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct PreparedRendition {
    rendition: &'static str,
    mime_type: &'static str,
    codecs: &'static str,
    segment_count: u32,
}

#[derive(Debug, Clone)]
struct ConfiguredMediaProvider {
    staging_root: PathBuf,
    ffmpeg_path: PathBuf,
    ffprobe_path: PathBuf,
    /// For ffprobe a whole-run timeout; for ffmpeg a stall timeout, measured
    /// on the growth of the prepared output.
    timeout: Duration,
    max_stdio_bytes: usize,
}

#[derive(Debug, Deserialize)]
struct ProbeOutput {
    streams: Vec<ProbeStream>,
    format: ProbeFormat,
    #[serde(flatten)]
    _extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct ProbeStream {
    codec_type: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
    avg_frame_rate: Option<String>,
    r_frame_rate: Option<String>,
    codec_name: Option<String>,
    profile: Option<String>,
    channels: Option<u32>,
    channel_layout: Option<String>,
    sample_rate: Option<String>,
    disposition: Option<ProbeDisposition>,
    #[serde(flatten)]
    _extra: BTreeMap<String, Value>,
}

impl ProbeStream {
    /// Cover art embedded in an audio file (ID3 APIC, MP4 `covr`) is reported as
    /// a video stream carrying a single still frame. It is not a moving picture
    /// and must never be chosen as the source's video track.
    fn is_attached_picture(&self) -> bool {
        self.disposition
            .as_ref()
            .and_then(|disposition| disposition.attached_pic)
            == Some(1)
    }
}

#[derive(Debug, Deserialize)]
struct ProbeDisposition {
    attached_pic: Option<u8>,
    #[serde(flatten)]
    _extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct ProbeFormat {
    duration: Option<String>,
    #[serde(flatten)]
    _extra: BTreeMap<String, Value>,
}

#[derive(Debug)]
struct BoundedCommandOutput {
    stdout: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
enum CommandLifecycleEvent {
    Spawned {
        child_id: u32,
    },
    Reaped {
        child_id: u32,
        code: Option<i32>,
        signal: Option<i32>,
    },
}

#[derive(Debug)]
struct PreparedOutputMonitor<'a> {
    root: &'a Path,
}

/// The renditions a source yields: its first moving video stream and its
/// first audio stream, whichever exist. At least one does.
#[derive(Debug)]
struct ValidatedProbeOutput {
    /// Position of the video stream among the source's video streams (cover
    /// art counts), the `n` in `-map 0:v:n`.
    video_ordinal: Option<usize>,
    audio: Option<AudioPlan>,
}

impl ValidatedProbeOutput {
    /// Renditions in output stream order, video first: index `i` is ffmpeg's
    /// `$RepresentationID$`.
    fn renditions(&self) -> Vec<MediaTrackKind> {
        let mut renditions = Vec::with_capacity(2);
        if self.video_ordinal.is_some() {
            renditions.push(MediaTrackKind::Video);
        }
        if self.audio.is_some() {
            renditions.push(MediaTrackKind::Audio);
        }
        renditions
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MediaTrackKind {
    Video,
    Audio,
}

impl MediaTrackKind {
    fn rendition(self) -> &'static str {
        match self {
            Self::Video => "video",
            Self::Audio => "audio",
        }
    }

    fn stream_specifier(self) -> &'static str {
        match self {
            Self::Video => "v",
            Self::Audio => "a",
        }
    }

    fn mime_type_and_codecs(self) -> (&'static str, &'static str) {
        match self {
            Self::Video => (OUTPUT_MIME_TYPE_VIDEO_V1, OUTPUT_CODECS_VIDEO_V1),
            Self::Audio => (OUTPUT_MIME_TYPE_AUDIO_V1, OUTPUT_CODECS_AUDIO_V1),
        }
    }
}

/// How the source's audio becomes the AAC-LC rendition. Quality first: never
/// re-encode, downmix or resample without need.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AudioPlan {
    /// The source is already AAC-LC that MSE plays; its bits are kept.
    Copy,
    Encode {
        bitrate: &'static str,
        sample_rate: u32,
        /// Set only when the source's layout cannot be kept.
        channels: Option<u32>,
    },
}

/// Why a prepare failed. Every failure reads the same to the caller except an
/// oversized part, which the creator can act on.
#[derive(Debug, PartialEq, Eq)]
enum PrepareError {
    Failed,
    PartTooLarge,
}

impl From<()> for PrepareError {
    fn from((): ()) -> Self {
        Self::Failed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MonitoredOutputUsage {
    total_bytes: u64,
    entry_count: usize,
}

pub struct MediaProvider {
    state: Option<ConfiguredMediaProvider>,
}

impl Default for MediaProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MediaProvider {
    pub fn new() -> Self {
        Self { state: None }
    }

    fn handle_frame(&mut self, frame: &[u8]) -> (ProviderResponse, bool) {
        let mut value = match serde_json::from_slice::<Value>(frame) {
            Ok(value) => value,
            Err(_) => return (invalid_request(), false),
        };
        let op = value.get("op").and_then(Value::as_str).map(str::to_owned);
        let envelope_present = strip_runtime_invocation_envelope(
            &mut value,
            "media",
            op.as_deref().unwrap_or_default(),
        )
        .is_ok();
        match op.as_deref() {
            Some("init" | "status" | "shutdown") => {
                if !control_request_has_exact_fields(&value, op.as_deref().unwrap_or_default()) {
                    return (invalid_request(), false);
                }
                match serde_json::from_value::<ControlRequest>(value) {
                    Ok(ControlRequest::Init { config }) => (self.init(config), false),
                    Ok(ControlRequest::Status) => (self.status(), false),
                    Ok(ControlRequest::Shutdown) => (ProviderResponse::empty_ok(), true),
                    Err(_) => (invalid_request(), false),
                }
            }
            Some("prepare") => {
                if !envelope_present {
                    return (invalid_request(), false);
                }
                match serde_json::from_value::<MediaProviderRequest>(value) {
                    Ok(MediaProviderRequest::Prepare { operation_id }) => {
                        (self.prepare(&operation_id), false)
                    }
                    Err(_) => (invalid_request(), false),
                }
            }
            _ => (invalid_request(), false),
        }
    }

    fn init(&mut self, config: Value) -> ProviderResponse {
        self.state = None;
        match load_provider_state(config) {
            Ok(state) => {
                self.state = Some(state);
                self.status()
            }
            Err(()) => {
                ProviderResponse::error(INIT_ERROR_CODE, "media provider configuration is invalid")
            }
        }
    }

    fn status(&self) -> ProviderResponse {
        ProviderResponse::ok(json!({
            "provider": PROVIDER_ID,
            "protocol_version": PROTOCOL_VERSION,
            "version": PROVIDER_VERSION,
            "configured": self.state.is_some(),
            "supported_operations": ["status", "prepare"],
        }))
    }

    fn prepare(&self, operation_id: &str) -> ProviderResponse {
        let Some(state) = &self.state else {
            return ProviderResponse::error(
                INTERNAL_ERROR_CODE,
                "media provider is not configured",
            );
        };
        let mut lifecycle = Vec::new();
        let result = validate_operation_id(operation_id)
            .map_err(PrepareError::from)
            .and_then(|()| {
                run_prepare_observed(state, operation_id, &mut |event| lifecycle.push(event))
            });
        let operation_settled = command_lifecycle_is_settled(&lifecycle);
        match result {
            Ok(output) if operation_settled => {
                ProviderResponse::ok(serde_json::to_value(output).unwrap_or(Value::Null))
            }
            Err(PrepareError::PartTooLarge) if operation_settled => {
                ProviderResponse::settled_error(INTERNAL_ERROR_CODE, PART_TOO_LARGE_MESSAGE, true)
            }
            Ok(_) | Err(_) => ProviderResponse::settled_error(
                INTERNAL_ERROR_CODE,
                if operation_settled {
                    "media preparation failed"
                } else {
                    "media preparation settlement is unknown"
                },
                operation_settled,
            ),
        }
    }
}

fn load_provider_state(config: Value) -> Result<ConfiguredMediaProvider, ()> {
    let config = serde_json::from_value::<InitConfig>(config).map_err(|_| ())?;
    if !config.base_path.is_empty()
        || !config.allowed_paths.is_empty()
        || config.read_only
        || !config.encryption_key.is_empty()
    {
        return Err(());
    }
    let extra = config.extra;
    if extra.provider_id != PROVIDER_ID
        || extra.timeout_ms == 0
        || extra.max_stdio_bytes == 0
        || extra.timeout_ms > MAX_TIMEOUT_MS
        || extra.max_stdio_bytes > MAX_STDIO_BYTES
        || extra.output_profile != OUTPUT_PROFILE_BROWSER_FMP4_H264_V1
    {
        return Err(());
    }
    let staging_root = PathBuf::from(extra.staging_root);
    let ffmpeg_path = PathBuf::from(extra.ffmpeg_path);
    let ffprobe_path = PathBuf::from(extra.ffprobe_path);
    if !staging_root.is_absolute() || !ffmpeg_path.is_absolute() || !ffprobe_path.is_absolute() {
        return Err(());
    }
    validate_owner_only_dir(&staging_root).map_err(|_| ())?;
    validate_regular_executable_path(&ffmpeg_path).map_err(|_| ())?;
    validate_regular_executable_path(&ffprobe_path).map_err(|_| ())?;
    Ok(ConfiguredMediaProvider {
        staging_root,
        ffmpeg_path,
        ffprobe_path,
        timeout: Duration::from_millis(extra.timeout_ms),
        max_stdio_bytes: extra.max_stdio_bytes,
    })
}

fn run_prepare_observed(
    state: &ConfiguredMediaProvider,
    operation_id: &str,
    observe_lifecycle: &mut dyn FnMut(CommandLifecycleEvent),
) -> Result<PreparedMediaOutput, PrepareError> {
    let operation_root = state.staging_root.join(operation_id);
    validate_operation_root(&state.staging_root, &operation_root)?;
    let input_path = operation_root.join("input.bin");
    validate_regular_file(&input_path, true, u64::MAX)?;
    let prepared_dir = operation_root.join("prepared");
    if prepared_dir.exists() {
        fs::remove_dir_all(&prepared_dir).map_err(|_| ())?;
    }
    fs::create_dir(&prepared_dir).map_err(|_| ())?;
    set_owner_only_dir_permissions(&prepared_dir).map_err(|_| ())?;
    let probe = run_ffprobe_observed(state, &input_path, observe_lifecycle)?;
    let renditions = probe.renditions();
    // ffmpeg writes `$RepresentationID$/...` but never creates the directories.
    for representation_id in 0..renditions.len() {
        let representation_dir = prepared_dir.join(representation_id.to_string());
        for dir in [&representation_dir, &representation_dir.join("segments")] {
            fs::create_dir(dir).map_err(|_| ())?;
            set_owner_only_dir_permissions(dir).map_err(|_| ())?;
        }
    }
    run_ffmpeg_observed(state, &input_path, &prepared_dir, &probe, observe_lifecycle)?;
    let mut prepared = Vec::with_capacity(renditions.len());
    for (representation_id, kind) in renditions.into_iter().enumerate() {
        let rendition_dir = prepared_dir.join(kind.rendition());
        fs::rename(
            prepared_dir.join(representation_id.to_string()),
            &rendition_dir,
        )
        .map_err(|_| ())?;
        let segments_dir = rendition_dir.join("segments");
        normalize_segment_indexes(&segments_dir)?;
        normalize_segment_containers(&segments_dir)?;
        if validate_regular_file_len(&rendition_dir.join("init.mp4"), false, u64::MAX)?
            > MAX_PREPARED_PART_BYTES
        {
            return Err(PrepareError::PartTooLarge);
        }
        let segment_count = validate_segments_output(&segments_dir)?;
        let (mime_type, codecs) = kind.mime_type_and_codecs();
        prepared.push(PreparedRendition {
            rendition: kind.rendition(),
            mime_type,
            codecs,
            segment_count,
        });
    }
    Ok(PreparedMediaOutput {
        schema: OUTPUT_SCHEMA_V2,
        renditions: prepared,
    })
}

fn run_ffprobe_observed(
    state: &ConfiguredMediaProvider,
    input_path: &Path,
    observe_lifecycle: &mut dyn FnMut(CommandLifecycleEvent),
) -> Result<ValidatedProbeOutput, ()> {
    let mut cmd = Command::new(&state.ffprobe_path);
    cmd.arg("-v")
        .arg("error")
        .arg("-print_format")
        .arg("json")
        .arg("-show_entries")
        .arg(concat!(
            "format=duration",
            ":stream=codec_type,width,height,avg_frame_rate,r_frame_rate",
            // What the audio plan decides on.
            ",codec_name,profile,channels,channel_layout,sample_rate",
            // Distinguishes embedded cover art from a real video track.
            ":stream_disposition=attached_pic",
        ))
        .arg(input_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = run_bounded_command_observed(
        cmd,
        state.timeout,
        state.max_stdio_bytes,
        None,
        observe_lifecycle,
    )?;
    let probe = serde_json::from_slice::<ProbeOutput>(&output.stdout).map_err(|_| ())?;
    validate_probe_output(&probe)
}

fn run_ffmpeg_observed(
    state: &ConfiguredMediaProvider,
    input_path: &Path,
    prepared_dir: &Path,
    probe: &ValidatedProbeOutput,
    observe_lifecycle: &mut dyn FnMut(CommandLifecycleEvent),
) -> Result<(), ()> {
    let manifest_path = prepared_dir.join("manifest.mpd");
    let mut cmd = Command::new(&state.ffmpeg_path);
    cmd.arg("-nostdin")
        .arg("-v")
        .arg("error")
        .arg("-y")
        .arg("-i")
        .arg(input_path);
    // One invocation, so the renditions share one timeline.
    if let Some(ordinal) = probe.video_ordinal {
        cmd.arg("-map").arg(format!("0:v:{ordinal}"));
    }
    if probe.audio.is_some() {
        cmd.arg("-map").arg("0:a:0");
    }
    if probe.video_ordinal.is_some() {
        cmd.arg("-c:v")
            .arg("libx264")
            .arg("-profile:v")
            .arg("high")
            .arg("-level:v")
            .arg("4.0")
            .arg("-pix_fmt")
            .arg("yuv420p")
            .arg("-r")
            .arg("30")
            .arg("-vf")
            .arg("scale=w=min(iw\\,1920):h=min(ih\\,1080):force_original_aspect_ratio=decrease:force_divisible_by=2,fps=30")
            .arg("-g")
            .arg(OUTPUT_VIDEO_GOP_FRAMES)
            .arg("-keyint_min")
            .arg(OUTPUT_VIDEO_GOP_FRAMES)
            .arg("-sc_threshold")
            .arg("0")
            .arg("-preset")
            .arg("veryfast")
            .arg("-crf")
            .arg("28")
            .arg("-maxrate")
            .arg(OUTPUT_VIDEO_VBV_RATE)
            .arg("-bufsize")
            .arg(OUTPUT_VIDEO_VBV_RATE);
    }
    match &probe.audio {
        Some(AudioPlan::Copy) => {
            // MPEG-TS carries AAC under a stream tag the mp4 muxer refuses;
            // re-tag it so a `.ts` source copies like an mp4 or mkv one.
            cmd.arg("-c:a").arg("copy").arg("-tag:a").arg("mp4a");
        }
        Some(AudioPlan::Encode {
            bitrate,
            sample_rate,
            channels,
        }) => {
            cmd.arg("-c:a")
                .arg("aac")
                .arg("-profile:a")
                .arg("aac_low")
                .arg("-b:a")
                .arg(bitrate)
                .arg("-ar")
                .arg(sample_rate.to_string());
            if let Some(channels) = channels {
                cmd.arg("-ac").arg(channels.to_string());
            }
        }
        None => {}
    }
    let adaptation_sets = probe
        .renditions()
        .iter()
        .enumerate()
        .map(|(id, kind)| format!("id={id},streams={}", kind.stream_specifier()))
        .collect::<Vec<_>>()
        .join(" ");
    // The container and segmentation flags are the same for every rendition.
    cmd.arg("-movflags")
        .arg("+frag_keyframe+empty_moov+default_base_moof+separate_moof")
        .arg("-f")
        .arg("dash")
        .arg("-seg_duration")
        .arg(OUTPUT_SEGMENT_DURATION_SECS)
        .arg("-streaming")
        .arg("0")
        .arg("-use_timeline")
        .arg("1")
        .arg("-use_template")
        .arg("1")
        .arg("-adaptation_sets")
        .arg(adaptation_sets)
        .arg("-init_seg_name")
        .arg("$RepresentationID$/init.mp4")
        .arg("-media_seg_name")
        .arg("$RepresentationID$/segments/$Number%08d$.m4s")
        .arg(&manifest_path)
        .current_dir(prepared_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_bounded_command_observed(
        cmd,
        state.timeout,
        state.max_stdio_bytes,
        Some(PreparedOutputMonitor { root: prepared_dir }),
        observe_lifecycle,
    )
    .map(|_| ())?;
    if manifest_path.exists() {
        fs::remove_file(&manifest_path).map_err(|_| ())?;
    }
    Ok(())
}

fn run_bounded_command_observed(
    mut cmd: Command,
    timeout: Duration,
    max_stdio_bytes: usize,
    monitor: Option<PreparedOutputMonitor<'_>>,
    observe_lifecycle: &mut dyn FnMut(CommandLifecycleEvent),
) -> Result<BoundedCommandOutput, ()> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|_| ())?;
    observe_lifecycle(CommandLifecycleEvent::Spawned {
        child_id: child.id(),
    });
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate_child(&mut child, observe_lifecycle)?;
            return Err(());
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            terminate_child(&mut child, observe_lifecycle)?;
            return Err(());
        }
    };
    let stdout_thread = spawn_stdio_reader(stdout, max_stdio_bytes);
    let stderr_thread = spawn_stdio_reader(stderr, max_stdio_bytes);
    wait_for_child(
        &mut child,
        timeout,
        stdout_thread,
        stderr_thread,
        monitor,
        observe_lifecycle,
    )
}

fn wait_for_child(
    child: &mut Child,
    timeout: Duration,
    stdout_thread: thread::JoinHandle<Result<Vec<u8>, ()>>,
    stderr_thread: thread::JoinHandle<Result<Vec<u8>, ()>>,
    monitor: Option<PreparedOutputMonitor<'_>>,
    observe_lifecycle: &mut dyn FnMut(CommandLifecycleEvent),
) -> Result<BoundedCommandOutput, ()> {
    // Without a monitor the timeout bounds the whole run. With one it is a
    // stall timeout: any change in the monitored output counts as progress
    // and restarts the clock, so the media's length is never capped.
    let mut last_progress = Instant::now();
    let mut last_scan: Option<Instant> = None;
    let mut last_usage: Option<MonitoredOutputUsage> = None;
    let mut stdout_thread = Some(stdout_thread);
    let mut stderr_thread = Some(stderr_thread);
    let mut stdout_output = None;
    let mut stderr_output = None;
    loop {
        if let Some(reader) = stdout_thread.as_ref() {
            if reader.is_finished() {
                match stdout_thread.take().unwrap().join().map_err(|_| ())? {
                    Ok(stdout) => stdout_output = Some(stdout),
                    Err(()) => {
                        terminate_and_join(child, None, stderr_thread.take(), observe_lifecycle)?;
                        return Err(());
                    }
                }
            }
        }
        if let Some(reader) = stderr_thread.as_ref() {
            if reader.is_finished() {
                match stderr_thread.take().unwrap().join().map_err(|_| ())? {
                    Ok(stderr) => stderr_output = Some(stderr),
                    Err(()) => {
                        terminate_and_join(child, stdout_thread.take(), None, observe_lifecycle)?;
                        return Err(());
                    }
                }
            }
        }
        if let Some(monitor) = &monitor {
            let now = Instant::now();
            let scan_due = last_scan
                .is_none_or(|scanned| now.duration_since(scanned) >= OUTPUT_MONITOR_SCAN_INTERVAL);
            if scan_due {
                last_scan = Some(now);
                match monitored_output_usage(monitor.root) {
                    Ok(usage) => {
                        if last_usage != Some(usage) {
                            last_usage = Some(usage);
                            last_progress = now;
                        }
                    }
                    Err(()) => {
                        terminate_and_join(
                            child,
                            stdout_thread.take(),
                            stderr_thread.take(),
                            observe_lifecycle,
                        )?;
                        return Err(());
                    }
                }
            }
        }
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(_) => {
                terminate_and_join(
                    child,
                    stdout_thread.take(),
                    stderr_thread.take(),
                    observe_lifecycle,
                )?;
                return Err(());
            }
        };
        match status {
            Some(status) => {
                observe_reaped_child(child.id(), &status, observe_lifecycle);
                let stdout = match stdout_output {
                    Some(stdout) => stdout,
                    None => stdout_thread.take().unwrap().join().map_err(|_| ())??,
                };
                let _stderr = match stderr_output {
                    Some(stderr) => stderr,
                    None => stderr_thread.take().unwrap().join().map_err(|_| ())??,
                };
                return if status.success() {
                    Ok(BoundedCommandOutput { stdout })
                } else {
                    Err(())
                };
            }
            None if last_progress.elapsed() >= timeout => {
                terminate_and_join(
                    child,
                    stdout_thread.take(),
                    stderr_thread.take(),
                    observe_lifecycle,
                )?;
                return Err(());
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn spawn_stdio_reader<T>(
    mut stream: T,
    max_stdio_bytes: usize,
) -> thread::JoinHandle<Result<Vec<u8>, ()>>
where
    T: io::Read + Send + 'static,
{
    thread::spawn(move || {
        let mut output = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream.read(&mut buffer).map_err(|_| ())?;
            if read == 0 {
                return Ok(output);
            }
            if output.len().saturating_add(read) > max_stdio_bytes {
                return Err(());
            }
            output.extend_from_slice(&buffer[..read]);
        }
    })
}

fn terminate_child(
    child: &mut Child,
    observe_lifecycle: &mut dyn FnMut(CommandLifecycleEvent),
) -> Result<(), ()> {
    let child_id = child.id();
    let _ = child.kill();
    let status = child.wait().map_err(|_| ())?;
    observe_reaped_child(child_id, &status, observe_lifecycle);
    Ok(())
}

fn observe_reaped_child(
    child_id: u32,
    status: &ExitStatus,
    observe_lifecycle: &mut dyn FnMut(CommandLifecycleEvent),
) {
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt as _;
        status.signal()
    };
    #[cfg(not(unix))]
    let signal = None;
    observe_lifecycle(CommandLifecycleEvent::Reaped {
        child_id,
        code: status.code(),
        signal,
    });
}

fn command_lifecycle_is_settled(events: &[CommandLifecycleEvent]) -> bool {
    let mut active = BTreeMap::new();
    for event in events {
        match event {
            CommandLifecycleEvent::Spawned { child_id } => {
                if active.insert(*child_id, ()).is_some() {
                    return false;
                }
            }
            CommandLifecycleEvent::Reaped { child_id, .. } => {
                if active.remove(child_id).is_none() {
                    return false;
                }
            }
        }
    }
    active.is_empty()
}

fn terminate_and_join(
    child: &mut Child,
    stdout_thread: Option<thread::JoinHandle<Result<Vec<u8>, ()>>>,
    stderr_thread: Option<thread::JoinHandle<Result<Vec<u8>, ()>>>,
    observe_lifecycle: &mut dyn FnMut(CommandLifecycleEvent),
) -> Result<(), ()> {
    terminate_child(child, observe_lifecycle)?;
    if let Some(stdout_thread) = stdout_thread {
        let _ = stdout_thread.join();
    }
    if let Some(stderr_thread) = stderr_thread {
        let _ = stderr_thread.join();
    }
    Ok(())
}

/// The ffmpeg DASH muxer has no `start_number` option and always numbers media
/// segments from 1 (`startNumber="1"`), while the Runtime's prepared-media
/// contract is 0-based and contiguous. Shift a contiguous 1-based run down by
/// one so the output matches the contract; a 0-based run is left untouched and
/// any other numbering is rejected. Renaming ascending never collides because
/// index `n - 1` is always free once `n - 1` itself has been moved.
fn normalize_segment_indexes(segments_dir: &Path) -> Result<(), ()> {
    let mut indexes = Vec::new();
    for entry in fs::read_dir(segments_dir).map_err(|_| ())? {
        let entry = entry.map_err(|_| ())?;
        let name = entry.file_name();
        indexes.push(parse_segment_index(&name.to_string_lossy())?);
    }
    indexes.sort_unstable();
    let Some(&first) = indexes.first() else {
        return Err(());
    };
    if indexes
        .iter()
        .enumerate()
        .any(|(offset, actual)| *actual != first.saturating_add(offset))
    {
        return Err(());
    }
    match first {
        0 => Ok(()),
        1 => {
            for index in indexes {
                fs::rename(
                    segments_dir.join(format!("{index:08}.m4s")),
                    segments_dir.join(format!("{:08}.m4s", index - 1)),
                )
                .map_err(|_| ())?;
            }
            Ok(())
        }
        _ => Err(()),
    }
}

/// The Runtime's prepared-media contract wants each media segment to be exactly
/// one `moof` + `mdat` pair. ffmpeg's DASH muxer prefixes every segment with a
/// `styp` brand box and a `sidx` index box; both are optional in ISOBMFF/MSE
/// and the `sidx` byte ranges become stale once the segment is re-packaged
/// for protection anyway, so they are stripped here. Anything else (a
/// multi-fragment segment, a trailing box) is rejected rather than repaired.
///
/// The part rule is checked on the muxer's bytes, before anything is read:
/// the stripped prefix is a few dozen bytes, well inside the rule's margin.
fn normalize_segment_containers(segments_dir: &Path) -> Result<(), PrepareError> {
    for entry in fs::read_dir(segments_dir).map_err(|_| ())? {
        let path = entry.map_err(|_| ())?.path();
        if validate_regular_file_len(&path, true, u64::MAX)? > MAX_PREPARED_PART_BYTES {
            return Err(PrepareError::PartTooLarge);
        }
        let bytes = fs::read(&path).map_err(|_| ())?;
        let stripped = strip_dash_segment_prefix(&bytes)?;
        if stripped.len() != bytes.len() {
            fs::write(&path, stripped).map_err(|_| ())?;
        }
    }
    Ok(())
}

/// Drop leading `styp` / `sidx` boxes and require the remainder to be exactly
/// `moof` followed by `mdat`, spanning the whole segment.
fn strip_dash_segment_prefix(bytes: &[u8]) -> Result<&[u8], ()> {
    let mut offset = 0usize;
    let mut kinds = Vec::new();
    while offset < bytes.len() {
        let (kind, size) = read_box_header(bytes, offset)?;
        kinds.push((offset, kind));
        offset = offset.checked_add(size).ok_or(())?;
    }
    if offset != bytes.len() {
        return Err(());
    }
    let body_start = kinds
        .iter()
        .take_while(|(_, kind)| kind == b"styp" || kind == b"sidx")
        .count();
    let body: Vec<&[u8; 4]> = kinds[body_start..].iter().map(|(_, kind)| kind).collect();
    if body != [b"moof", b"mdat"] {
        return Err(());
    }
    Ok(&bytes[kinds[body_start].0..])
}

/// Minimal ISOBMFF box header reader: returns (type, total size) for the box
/// at `offset`, accepting 32-bit and 64-bit (`size == 1`) sizes and rejecting
/// zero-size ("to end of file") and out-of-range boxes.
fn read_box_header(bytes: &[u8], offset: usize) -> Result<([u8; 4], usize), ()> {
    let header = bytes
        .get(offset..offset.checked_add(8).ok_or(())?)
        .ok_or(())?;
    let size32 = u32::from_be_bytes(header[..4].try_into().map_err(|_| ())?);
    let kind: [u8; 4] = header[4..8].try_into().map_err(|_| ())?;
    let (size, header_len) = match size32 {
        0 => return Err(()),
        1 => {
            let large = bytes
                .get(offset + 8..offset.checked_add(16).ok_or(())?)
                .ok_or(())?;
            (
                usize::try_from(u64::from_be_bytes(large.try_into().map_err(|_| ())?))
                    .map_err(|_| ())?,
                16usize,
            )
        }
        size => (size as usize, 8usize),
    };
    if size < header_len || offset.checked_add(size).ok_or(())? > bytes.len() {
        return Err(());
    }
    Ok((kind, size))
}

/// Returns the segment count of a contiguous, 0-based run of parts that each
/// meet the part rule.
fn validate_segments_output(segments_dir: &Path) -> Result<u32, ()> {
    let mut indexes = Vec::new();
    for entry in fs::read_dir(segments_dir).map_err(|_| ())? {
        let entry = entry.map_err(|_| ())?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        indexes.push(parse_segment_index(&name)?);
        validate_regular_file_len(&path, true, MAX_PREPARED_PART_BYTES)?;
    }
    indexes.sort_unstable();
    if indexes.is_empty() {
        return Err(());
    }
    for (expected, actual) in indexes.iter().enumerate() {
        if *actual != expected {
            return Err(());
        }
    }
    u32::try_from(indexes.len()).map_err(|_| ())
}

fn validate_operation_root(staging_root: &Path, operation_root: &Path) -> Result<(), ()> {
    let canonical = staging_root.canonicalize().map_err(|_| ())?;
    let metadata = fs::symlink_metadata(operation_root).map_err(|_| ())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(());
    }
    #[cfg(unix)]
    validate_owner_only_dir(operation_root).map_err(|_| ())?;
    let canonical_operation_root = operation_root.canonicalize().map_err(|_| ())?;
    if !canonical_operation_root.starts_with(&canonical) {
        return Err(());
    }
    Ok(())
}

fn validate_regular_executable_path(path: &Path) -> Result<(), ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(());
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 || mode & 0o111 == 0 {
            return Err(());
        }
    }
    Ok(())
}

fn validate_regular_file_len(
    path: &Path,
    require_non_empty: bool,
    max_bytes: u64,
) -> Result<u64, ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(());
    }
    #[cfg(unix)]
    {
        if metadata.nlink() != 1 {
            return Err(());
        }
    }
    if metadata.len() > max_bytes || (require_non_empty && metadata.len() == 0) {
        return Err(());
    }
    Ok(metadata.len())
}

fn validate_regular_file(path: &Path, require_non_empty: bool, max_bytes: u64) -> Result<(), ()> {
    validate_regular_file_len(path, require_non_empty, max_bytes).map(|_| ())
}

fn validate_owner_only_dir(path: &Path) -> Result<(), ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(());
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if metadata.uid() != unsafe { libc::geteuid() } || mode != 0o700 {
            return Err(());
        }
    }
    Ok(())
}

fn set_owner_only_dir_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn validate_probe_output(probe: &ProbeOutput) -> Result<ValidatedProbeOutput, ()> {
    // A sanity check on the probe, not a cap: mint has no duration limit. A
    // container may state no duration at all; one that does must state a sane one.
    if let Some(duration) = probe.format.duration.as_deref() {
        if parse_finite_decimal(duration)? <= 0.0 {
            return Err(());
        }
    }
    // Cover art is skipped, not treated as the video track: a tagged mp3 or m4a is
    // an AUDIO source with a still picture attached, and routing it down the video
    // branch would re-encode the still. The ordinal counts cover art, as ffmpeg's
    // `v` stream specifier does.
    let video = probe
        .streams
        .iter()
        .filter(|stream| stream.codec_type.as_deref() == Some("video"))
        .enumerate()
        .find(|(_, stream)| !stream.is_attached_picture());
    let video_ordinal = match video {
        Some((ordinal, stream)) => {
            // Any geometry and rate are accepted: the output is always scaled
            // to at most 1080p30. These only refuse a malformed probe.
            let width = stream.width.ok_or(())?;
            let height = stream.height.ok_or(())?;
            if width == 0 || height == 0 {
                return Err(());
            }
            let fps = parse_frame_rate(
                stream.avg_frame_rate.as_deref(),
                stream.r_frame_rate.as_deref(),
            )?;
            if fps <= 0.0 {
                return Err(());
            }
            Some(ordinal)
        }
        None => None,
    };
    let audio = probe
        .streams
        .iter()
        .find(|stream| stream.codec_type.as_deref() == Some("audio"))
        .map(audio_plan);
    if video_ordinal.is_none() && audio.is_none() {
        return Err(());
    }
    Ok(ValidatedProbeOutput {
        video_ordinal,
        audio,
    })
}

/// Copy when the source is AAC-LC that MSE plays: one or two channels, or 5.1,
/// at 44.1 or 48 kHz. Otherwise encode AAC-LC, keeping the layout up to 5.1
/// (more channels are downmixed to 5.1) and a 44.1 or 48 kHz rate (any other
/// rate becomes 48 kHz). Any doubt about the source means encode.
fn audio_plan(stream: &ProbeStream) -> AudioPlan {
    let source_rate = stream
        .sample_rate
        .as_deref()
        .and_then(|rate| rate.parse::<u32>().ok())
        .filter(|rate| matches!(rate, 44_100 | 48_000));
    let mse_layout = match stream.channels {
        Some(1 | 2) => true,
        Some(6) => matches!(stream.channel_layout.as_deref(), Some("5.1" | "5.1(side)")),
        _ => false,
    };
    if stream.codec_name.as_deref() == Some("aac")
        && stream.profile.as_deref() == Some("LC")
        && mse_layout
        && source_rate.is_some()
    {
        return AudioPlan::Copy;
    }
    let (bitrate, channels) = match stream.channels {
        // Mono stays mono: 192k is above the 128k per channel of 256k stereo
        // and clear of the AAC-LC per-channel ceiling (~264k at 44.1 kHz).
        Some(1) => ("192k", None),
        Some(2) => ("256k", None),
        Some(3..=6) => ("384k", None),
        Some(7..) => ("384k", Some(6)),
        Some(0) | None => ("256k", Some(2)),
    };
    AudioPlan::Encode {
        bitrate,
        sample_rate: source_rate.unwrap_or(48_000),
        channels,
    }
}

fn parse_finite_decimal(value: &str) -> Result<f64, ()> {
    let parsed = value.parse::<f64>().map_err(|_| ())?;
    if parsed.is_finite() {
        Ok(parsed)
    } else {
        Err(())
    }
}

fn parse_frame_rate(avg_frame_rate: Option<&str>, r_frame_rate: Option<&str>) -> Result<f64, ()> {
    for candidate in [avg_frame_rate, r_frame_rate] {
        let Some(candidate) = candidate else {
            continue;
        };
        if let Ok(parsed) = parse_rate(candidate) {
            if parsed > 0.0 {
                return Ok(parsed);
            }
        }
    }
    Err(())
}

fn parse_rate(value: &str) -> Result<f64, ()> {
    let (numerator, denominator) = value.split_once('/').ok_or(())?;
    let numerator = numerator.parse::<f64>().map_err(|_| ())?;
    let denominator = denominator.parse::<f64>().map_err(|_| ())?;
    if !numerator.is_finite() || !denominator.is_finite() || denominator <= 0.0 {
        return Err(());
    }
    Ok(numerator / denominator)
}

fn parse_segment_index(name: &str) -> Result<usize, ()> {
    let stem = name.strip_suffix(".m4s").ok_or(())?;
    if stem.len() != 8 || !stem.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    stem.parse::<usize>().map_err(|_| ())
}

/// Sums the prepared output for the stall monitor. ffmpeg renames and
/// replaces files while it runs (its DASH manifest goes through a temporary
/// file after every segment), so an entry listed by one call can be gone by
/// the next: a vanished entry or directory is skipped. Every other error, a
/// symlink and any non-file non-directory still fail the run.
fn monitored_output_usage(root: &Path) -> Result<MonitoredOutputUsage, ()> {
    let mut usage = MonitoredOutputUsage {
        total_bytes: 0,
        entry_count: 0,
    };
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(usage),
        Err(_) => return Err(()),
    };
    for entry in entries {
        let entry = entry.map_err(|_| ())?;
        add_monitored_entry_usage(&entry.path(), &mut usage)?;
    }
    Ok(usage)
}

fn add_monitored_entry_usage(path: &Path, usage: &mut MonitoredOutputUsage) -> Result<(), ()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(()),
    };
    usage.entry_count = usage.entry_count.checked_add(1).ok_or(())?;
    if metadata.file_type().is_symlink() {
        return Err(());
    }
    if metadata.is_dir() {
        let child = monitored_output_usage(path)?;
        usage.total_bytes = usage.total_bytes.checked_add(child.total_bytes).ok_or(())?;
        usage.entry_count = usage.entry_count.checked_add(child.entry_count).ok_or(())?;
        return Ok(());
    }
    if !metadata.is_file() {
        return Err(());
    }
    usage.total_bytes = usage.total_bytes.checked_add(metadata.len()).ok_or(())?;
    Ok(())
}

fn validate_operation_id(value: &str) -> Result<(), ()> {
    if value.len() != OPERATION_ID_HEX_LEN
        || !value
            .as_bytes()
            .iter()
            .all(|byte| matches!(*byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(());
    }
    Ok(())
}

fn control_request_has_exact_fields(value: &Value, op: &str) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    match op {
        "init" => object.len() == 2 && object.contains_key("op") && object.contains_key("config"),
        "status" | "shutdown" => object.len() == 1 && object.contains_key("op"),
        _ => false,
    }
}

/// The transfer ABI the Runtime attaches to every local JSON provider
/// invocation; the provider only accepts an envelope carrying exactly this.
fn expected_local_json_runtime_invocation_abi() -> Value {
    json!({
        "schema": "elastos.provider.transfer-abi/v1",
        "transfer": "json",
        "transport": "runtime-local-provider-plane",
        "range_supported": false,
        "progress_supported": false,
        "progress_mode": "none",
        "transport_native_stream": false,
        "backpressure": "not_applicable",
        "cancel_supported": false
    })
}

fn strip_runtime_invocation_envelope(
    value: &mut Value,
    expected_target: &str,
    expected_op: &str,
) -> Result<(), ()> {
    let object = value.as_object_mut().ok_or(())?;
    if object.contains_key("_runtime_transfer") {
        return Err(());
    }
    let envelope = object.remove("_runtime_invocation").ok_or(())?;
    let envelope = envelope.as_object().ok_or(())?;
    if envelope.len() != 11 {
        return Err(());
    }
    if envelope.get("abi") != Some(&expected_local_json_runtime_invocation_abi()) {
        return Err(());
    }
    if envelope.get("schema").and_then(Value::as_str) != Some("elastos.provider.invocation/v1") {
        return Err(());
    }
    if envelope.get("source").and_then(Value::as_str) != Some("runtime")
        || envelope.get("target").and_then(Value::as_str) != Some(expected_target)
        || envelope.get("op").and_then(Value::as_str) != Some(expected_op)
        || envelope.get("capability").and_then(Value::as_str)
            != Some("provider:runtime->media:prepare")
        || envelope.get("transport").and_then(Value::as_str) != Some("runtime-local-provider-plane")
        || envelope.get("transfer").and_then(Value::as_str) != Some("json")
    {
        return Err(());
    }
    if !envelope.get("carrier").unwrap_or(&Value::Null).is_null()
        || !envelope.get("range").unwrap_or(&Value::Null).is_null()
        || !envelope.get("progress").unwrap_or(&Value::Null).is_null()
    {
        return Err(());
    }
    Ok(())
}

fn read_provider_frame<R: BufRead>(reader: &mut R) -> io::Result<Option<Result<Vec<u8>, ()>>> {
    let mut frame = Vec::new();
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if frame.is_empty() && !oversized {
                return Ok(None);
            }
            return Ok(Some(if oversized { Err(()) } else { Ok(frame) }));
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            let chunk = &available[..newline];
            if !oversized {
                if frame.len().saturating_add(chunk.len()) > MAX_PROVIDER_FRAME_BYTES {
                    oversized = true;
                } else {
                    frame.extend_from_slice(chunk);
                }
            }
            reader.consume(newline + 1);
            return Ok(Some(if oversized { Err(()) } else { Ok(frame) }));
        }
        let consumed = available.len();
        if !oversized {
            if frame.len().saturating_add(consumed) > MAX_PROVIDER_FRAME_BYTES {
                oversized = true;
            } else {
                frame.extend_from_slice(available);
            }
        }
        reader.consume(consumed);
    }
}

fn invalid_request() -> ProviderResponse {
    ProviderResponse::error(REQUEST_ERROR_CODE, "media provider request is invalid")
}

fn run_provider_loop<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    provider: &mut MediaProvider,
) {
    loop {
        let (response, should_exit) = match read_provider_frame(input) {
            Ok(Some(Ok(frame))) => provider.handle_frame(&frame),
            Ok(Some(Err(()))) => (invalid_request(), false),
            Ok(None) => break,
            Err(_) => break,
        };
        let bytes = match serde_json::to_vec(&response) {
            Ok(bytes) => bytes,
            Err(_) => break,
        };
        if output.write_all(&bytes).is_err()
            || output.write_all(b"\n").is_err()
            || output.flush().is_err()
        {
            break;
        }
        if should_exit {
            break;
        }
    }
}

pub fn run_provider_process() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut provider = MediaProvider::new();
    let mut input = stdin.lock();
    let mut writer = stdout.lock();
    run_provider_loop(&mut input, &mut writer, &mut provider);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_box(kind: &[u8; 4], content: &[u8]) -> Vec<u8> {
        let mut out = (8 + content.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(content);
        out
    }

    #[test]
    fn strip_dash_segment_prefix_drops_styp_and_sidx_and_keeps_single_fragment() {
        let moof = make_box(b"moof", b"fragment-header");
        let mdat = make_box(b"mdat", b"payload");
        let bare = [moof.clone(), mdat.clone()].concat();
        let prefixed = [
            make_box(b"styp", b"msdh"),
            make_box(b"sidx", &[0u8; 44]),
            moof.clone(),
            mdat.clone(),
        ]
        .concat();

        assert_eq!(strip_dash_segment_prefix(&bare).unwrap(), bare.as_slice());
        assert_eq!(
            strip_dash_segment_prefix(&prefixed).unwrap(),
            bare.as_slice()
        );
        assert_eq!(
            strip_dash_segment_prefix(&[make_box(b"styp", b"msdh"), bare.clone()].concat())
                .unwrap(),
            bare.as_slice()
        );
    }

    #[test]
    fn strip_dash_segment_prefix_rejects_multi_fragment_trailing_and_malformed_segments() {
        let moof = make_box(b"moof", b"fragment-header");
        let mdat = make_box(b"mdat", b"payload");
        let bare = [moof.clone(), mdat.clone()].concat();

        let two_fragments = [bare.clone(), bare.clone()].concat();
        assert!(strip_dash_segment_prefix(&two_fragments).is_err());
        let trailing = [bare.clone(), make_box(b"free", b"")].concat();
        assert!(strip_dash_segment_prefix(&trailing).is_err());
        let sidx_in_the_middle =
            [moof.clone(), make_box(b"sidx", &[0u8; 4]), mdat.clone()].concat();
        assert!(strip_dash_segment_prefix(&sidx_in_the_middle).is_err());
        assert!(strip_dash_segment_prefix(&[mdat.clone(), moof.clone()].concat()).is_err());
        assert!(strip_dash_segment_prefix(b"").is_err());
        assert!(strip_dash_segment_prefix(&bare[..bare.len() - 1]).is_err());
        let mut zero_size = bare.clone();
        zero_size[..4].copy_from_slice(&0u32.to_be_bytes());
        assert!(strip_dash_segment_prefix(&zero_size).is_err());
        let only_prefix = make_box(b"styp", b"msdh");
        assert!(strip_dash_segment_prefix(&only_prefix).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn ffmpeg_timeout_reports_exact_spawn_and_reap_events() {
        let root = tempfile::tempdir().unwrap();
        let ffmpeg_path = root.path().join("ffmpeg");
        fs::write(&ffmpeg_path, "#!/bin/sh\nwhile :; do :; done\n").unwrap();
        fs::set_permissions(&ffmpeg_path, fs::Permissions::from_mode(0o700)).unwrap();
        let staging_root = root.path().join("staging");
        fs::create_dir(&staging_root).unwrap();
        fs::set_permissions(&staging_root, fs::Permissions::from_mode(0o700)).unwrap();
        let input_path = root.path().join("input.bin");
        fs::write(&input_path, b"video").unwrap();
        let prepared_dir = root.path().join("prepared");
        fs::create_dir(&prepared_dir).unwrap();
        fs::create_dir_all(prepared_dir.join("0/segments")).unwrap();
        let state = ConfiguredMediaProvider {
            staging_root,
            ffmpeg_path,
            ffprobe_path: root.path().join("unused-ffprobe"),
            timeout: Duration::ZERO,
            max_stdio_bytes: 1024,
        };
        let probe = ValidatedProbeOutput {
            video_ordinal: Some(0),
            audio: None,
        };
        let mut events = Vec::new();

        assert!(
            run_ffmpeg_observed(&state, &input_path, &prepared_dir, &probe, &mut |event| {
                events.push(event)
            },)
            .is_err()
        );

        let [CommandLifecycleEvent::Spawned { child_id: spawned }, CommandLifecycleEvent::Reaped {
            child_id: reaped,
            code,
            signal,
        }] = events.as_slice()
        else {
            panic!("unexpected FFmpeg child lifecycle: {events:?}");
        };
        assert_eq!(spawned, reaped);
        assert_eq!(*code, None);
        assert_eq!(*signal, Some(libc::SIGKILL));
    }

    /// ffmpeg's DASH muxer replaces its manifest through a temporary file
    /// after every segment, so an entry the scan just listed can be gone by
    /// the time it is stat'ed. That race is not a failure: the entry is skipped.
    #[test]
    fn output_monitor_skips_an_entry_that_vanished_after_listing() {
        let root = tempfile::tempdir().unwrap();
        let mut usage = MonitoredOutputUsage {
            total_bytes: 7,
            entry_count: 3,
        };

        add_monitored_entry_usage(&root.path().join("manifest.mpd.tmp"), &mut usage).unwrap();

        assert_eq!(
            usage,
            MonitoredOutputUsage {
                total_bytes: 7,
                entry_count: 3,
            }
        );
    }

    #[test]
    fn output_monitor_treats_a_vanished_directory_as_empty() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            monitored_output_usage(&root.path().join("0")).unwrap(),
            MonitoredOutputUsage {
                total_bytes: 0,
                entry_count: 0,
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn output_monitor_still_fails_on_every_other_error() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("init.mp4"), b"init").unwrap();
        assert_eq!(
            monitored_output_usage(root.path()).unwrap(),
            MonitoredOutputUsage {
                total_bytes: 4,
                entry_count: 1,
            }
        );

        let unreadable = root.path().join("unreadable");
        fs::create_dir(&unreadable).unwrap();
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
        let result = monitored_output_usage(root.path());
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err());

        fs::remove_dir(&unreadable).unwrap();
        std::os::unix::fs::symlink(root.path().join("init.mp4"), root.path().join("link")).unwrap();
        assert!(monitored_output_usage(root.path()).is_err());
    }

    #[test]
    fn rejects_noncanonical_operation_id() {
        assert!(validate_operation_id(&"a".repeat(64)).is_ok());
        assert!(validate_operation_id("").is_err());
        assert!(validate_operation_id("a").is_err());
        assert!(validate_operation_id(&"A".repeat(64)).is_err());
        assert!(validate_operation_id(&"g".repeat(64)).is_err());
        assert!(validate_operation_id(&"a".repeat(63)).is_err());
    }

    #[test]
    fn parse_frame_rate_falls_back_to_r_frame_rate_when_avg_is_invalid_or_zero() {
        assert_eq!(
            parse_frame_rate(Some("oops"), Some("30000/1001")).unwrap(),
            30000.0 / 1001.0
        );
        assert_eq!(
            parse_frame_rate(Some("0/1"), Some("30000/1001")).unwrap(),
            30000.0 / 1001.0
        );
    }

    #[test]
    fn parse_frame_rate_uses_r_frame_rate_when_avg_is_missing() {
        assert_eq!(parse_frame_rate(None, Some("24/1")).unwrap(), 24.0);
    }
}

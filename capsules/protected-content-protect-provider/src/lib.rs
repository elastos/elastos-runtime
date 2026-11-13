use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, Write};

use elastos_protected_content_contracts::{
    CustodyCommitteeAuthorizationIdentityV1, CustodyEpochIdentityV1, CustodyPoolIdentityV1,
};
use elastos_protected_content_custody::{
    protect_validated_clear_fmp4_init_to_cenc_v1, protect_validated_clear_fmp4_init_to_cenc_v2,
    protect_validated_clear_fmp4_segment_to_cenc_v1,
    protect_validated_clear_fmp4_segment_to_cenc_v2, provision_custody_envelope_for_exact_nodes,
    ContentEncryptionKeyV1, CustodyError, ExactCustodyEnvelopeNodeV1, PayloadSealerV1,
};
use elastos_protected_content_provider_contracts::{
    CencDashIdentityBuilderV2, CencDashRenditionDeclV2, CencFmp4MediaIdentityV1, CencLayoutProfile,
    CencMediaSuite, ChunkedPayloadObjectIdentityV1, CustodyProtectionHeader,
    ProtectFailureReasonV2, ProtectProviderRequestOpV1, ProtectProviderRequestV1,
    ProtectProviderResponseV1, ProtectionSessionNodeV1, ProviderFailureCodeV1,
    ValidatedClearFmp4MediaSessionLayoutV1, MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1,
    MAX_PROVIDER_FRAME_BYTES_V1, MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1,
    PROTECT_PROVIDER_REQUEST_SCHEMA_V1, PROTECT_PROVIDER_RESPONSE_SCHEMA_V1,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tracing::info;

const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");
const INIT_ERROR_CODE: &str = "invalid_config";
const REQUEST_ERROR_CODE: &str = "invalid_request";
const MAX_ACTIVE_SESSIONS_V1: usize = 64;
const MAX_TERMINAL_REPLAYS_V1: usize = 64;
const MAX_AGGREGATE_PROTECTED_MEDIA_BYTES_V1: usize = 16 * 1024 * 1024;

type HandleBytes = [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
type RequestDigest = [u8; 32];

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlRequest {
    Init { config: Value },
    Status,
    Shutdown,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProviderResponse {
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<Value>,
    },
    Error {
        code: &'static str,
        message: &'static str,
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
        Self::Error { code, message }
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
    extra: ProtectInitExtraConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectInitExtraConfig {}

#[derive(Clone)]
struct OpenReplayEntry {
    request_digest: RequestDigest,
    response: ProtectProviderResponseV1,
}

/// Media's `protection_session_request_id` and an object session's
/// `session_id` are both caller-supplied 32-byte digests and share the
/// `open_replays` map's key space; without a domain tag, a media request id
/// and an object session id that happen to collide would spuriously read
/// each other's cached open response (or a digest mismatch between them
/// would surface as `BindingMismatch`), and `trim_btree_map`'s eviction
/// would evict across both namespaces instead of each one aging out on its
/// own terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum OpenReplayDomain {
    Media,
    Object,
}

type OpenReplayKey = (OpenReplayDomain, HandleBytes);

#[derive(Clone)]
struct SegmentReplayEntry {
    request_digest: RequestDigest,
}

struct MediaSessionState {
    mime_type: String,
    codecs: String,
    clear_session_layout: ValidatedClearFmp4MediaSessionLayoutV1,
    protected_init_segment: Vec<u8>,
    protected_segments: Vec<Vec<u8>>,
    segment_replays: BTreeMap<u32, SegmentReplayEntry>,
    content_key: Option<ContentEncryptionKeyV1>,
    iv_prefix: [u8; 4],
    next_iv_counter: u32,
    segment_count: u32,
    next_segment_index: u32,
    aggregate_protected_bytes: usize,
}

/// A v2 rendition's clear init layout and its declared segment count.
struct DashRenditionState {
    clear_session_layout: ValidatedClearFmp4MediaSessionLayoutV1,
    segment_count: u32,
}

/// The one segment a v2 session can replay: the last acknowledged one.
struct DashLastSegment {
    rendition_index: usize,
    segment_index: u32,
    request_digest: RequestDigest,
    response: ProtectProviderResponseV1,
}

/// A v2 media session. Its memory does not grow with the segment count: the
/// builder keeps a logarithmic Merkle stack and a streaming hasher, and only
/// the last response is kept for replay. One IV counter serves the whole
/// session, across both renditions, so no (key, IV) pair is ever reused.
struct MediaDashSessionStateV2 {
    request_id: HandleBytes,
    renditions: Vec<DashRenditionState>,
    builder: CencDashIdentityBuilderV2,
    content_key: Option<ContentEncryptionKeyV1>,
    iv_prefix: [u8; 4],
    next_iv_counter: u32,
    /// The rendition and per-rendition segment index expected next. The
    /// rendition equals `renditions.len()` once every segment is protected.
    cursor: (usize, u32),
    last: Option<DashLastSegment>,
}

/// `sealer` is `None` once the object session has been finalized: the sealer
/// is consumed by value (`PayloadSealerV1::finish_unprovisioned`), so there
/// is nothing to keep after a successful finalize, and `ProtectionSessionEntry::finalized`
/// (set at the same time) is what a finalize replay reads instead. Mirrors
/// `MediaSessionState::content_key`, which is set to `None` for the same
/// reason once the media session has been finalized.
struct ObjectSessionState {
    sealer: Option<PayloadSealerV1>,
    /// Byte length of the framed header prefix `PayloadSealerV1::open`
    /// returned when this session was opened. `AuthenticatedChunkPayloadHeaderV1`
    /// (reachable from the sealer only via a consuming `finish`/`finish_unprovisioned`
    /// call) exposes no public accessor for this length, so it is captured
    /// once, up front, from the prefix bytes this provider already emits in
    /// the open response.
    framed_header_bytes: u32,
}

enum ProtectionSessionKind {
    Media(MediaSessionState),
    MediaDash(Box<MediaDashSessionStateV2>),
    Object(ObjectSessionState),
}

struct ProtectionSessionEntry {
    custody_pool: CustodyPoolIdentityV1,
    custody_epoch: CustodyEpochIdentityV1,
    custody_committee_authorization: CustodyCommitteeAuthorizationIdentityV1,
    nodes: Vec<ExactCustodyEnvelopeNodeV1>,
    kind: ProtectionSessionKind,
    finalized: Option<ProtectProviderResponseV1>,
}

struct ConfiguredProtectProvider {
    open_replays: BTreeMap<OpenReplayKey, OpenReplayEntry>,
    sessions: BTreeMap<HandleBytes, ProtectionSessionEntry>,
    closed_handles: BTreeSet<HandleBytes>,
}

pub struct ProtectProvider {
    state: Option<ConfiguredProtectProvider>,
}

impl Default for ProtectProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ProtectProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.state {
            Some(state) => formatter
                .debug_struct("ProtectProvider")
                .field("configured", &true)
                .field("open_replays", &state.open_replays.len())
                .field("active_sessions", &state.sessions.len())
                .field("closed_handles", &state.closed_handles.len())
                .finish(),
            None => formatter
                .debug_struct("ProtectProvider")
                .field("configured", &false)
                .finish(),
        }
    }
}

impl ProtectProvider {
    pub fn new() -> Self {
        Self { state: None }
    }

    pub fn handle_frame(&mut self, frame: &[u8]) -> (ProviderResponse, bool) {
        let mut value = match serde_json::from_slice::<Value>(frame) {
            Ok(value) => value,
            Err(_) => return (invalid_request(), false),
        };
        let envelope = match strip_runtime_invocation_envelope(&mut value, "protect") {
            Ok(state) => state,
            Err(()) => return (invalid_request(), false),
        };
        let op = value.get("op").and_then(Value::as_str).map(str::to_owned);
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
            Some(
                "open_protection_session"
                | "protect_media_segment"
                | "finalize_protection_session"
                | "cancel_protection_session"
                | "close_protection_session"
                | "open_object_protection_session"
                | "protect_object_chunk"
                | "finalize_object_protection_session",
            ) => {
                if !matches!(envelope, EnvelopeState::Present) {
                    return (invalid_request(), false);
                }
                let Ok(bytes) = serde_json::to_vec(&value) else {
                    return (invalid_request(), false);
                };
                (self.handle_protect_request(&bytes), false)
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
            Err(()) => ProviderResponse::error(
                INIT_ERROR_CODE,
                "protect provider configuration is invalid",
            ),
        }
    }

    fn status(&self) -> ProviderResponse {
        ProviderResponse::ok(json!({
            "provider": "protected-content-protect",
            "version": PROVIDER_VERSION,
            "configured": self.state.is_some(),
            "request_schema": PROTECT_PROVIDER_REQUEST_SCHEMA_V1,
            "response_schema": PROTECT_PROVIDER_RESPONSE_SCHEMA_V1,
            "supported_operations": [
                "status",
                "open_protection_session",
                "protect_media_segment",
                "finalize_protection_session",
                "cancel_protection_session",
                "close_protection_session",
                "open_object_protection_session",
                "protect_object_chunk",
                "finalize_object_protection_session",
                "shutdown"
            ],
        }))
    }

    fn handle_protect_request(&mut self, request_bytes: &[u8]) -> ProviderResponse {
        let Some(state) = self.state.as_mut() else {
            return typed_response(ProtectProviderResponseV1::new_failure(
                ProviderFailureCodeV1::NotConfigured,
            ));
        };
        let request = match ProtectProviderRequestV1::from_json_slice(request_bytes) {
            Ok(value) => value,
            Err(_) => {
                return typed_response(ProtectProviderResponseV1::new_failure(
                    ProviderFailureCodeV1::InvalidRequest,
                ));
            }
        };
        let request_digest = sha256(request_bytes);
        match request.op() {
            ProtectProviderRequestOpV1::OpenProtectionSession => {
                if request.representations().is_some() {
                    return open_media_dash(state, &request, request_digest);
                }
                let (
                    Some(session_request_id),
                    Ok(Some(custody_pool)),
                    Ok(Some(custody_epoch)),
                    Ok(Some(custody_committee_authorization)),
                    Some(mime_type),
                    Some(codecs),
                    Some(segment_count),
                ) = (
                    request.protection_session_request_id(),
                    request.custody_pool(),
                    request.custody_epoch(),
                    request.custody_committee_authorization(),
                    request.mime_type(),
                    request.codecs(),
                    request.segment_count(),
                )
                else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                let mime_type = mime_type.to_string();
                let codecs = codecs.to_string();
                let request_id = *session_request_id.as_bytes();
                let open_replay_key: OpenReplayKey = (OpenReplayDomain::Media, request_id);
                if let Some(replay) = state.open_replays.get(&open_replay_key) {
                    return if replay.request_digest == request_digest {
                        typed_ok(replay.response.clone())
                    } else {
                        typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::BindingMismatch,
                        ))
                    };
                }
                if state.sessions.len() >= MAX_ACTIVE_SESSIONS_V1 {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::BackendUnavailable,
                    ));
                }
                let Some(clear_init_segment) = request.clear_init_segment() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                let clear_session_layout =
                    match ValidatedClearFmp4MediaSessionLayoutV1::new(clear_init_segment) {
                        Ok(value) => value,
                        Err(_) => {
                            return typed_response(ProtectProviderResponseV1::new_failure(
                                ProviderFailureCodeV1::InvalidRequest,
                            ));
                        }
                    };
                let content_key = match ContentEncryptionKeyV1::generate() {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                let Ok(Some(content_access_id)) = request.content_access_id() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                // The CENC protection header the protected init segment will carry.
                // It is built HERE because this is the only place that holds every
                // identity it names at once: the content access id the sample
                // entries are keyed to, and the custody pool, epoch and committee
                // authorization this session was opened against. It carries no key
                // material — it ships inside a public media file.
                let pssh_data = CustodyProtectionHeader::new(
                    content_access_id,
                    &custody_pool,
                    &custody_epoch,
                    &custody_committee_authorization,
                    CencMediaSuite::Fmp4V1,
                );
                let iv_prefix = match random_bytes::<4>() {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                let protected_init_segment = match protect_validated_clear_fmp4_init_to_cenc_v1(
                    &clear_session_layout,
                    clear_init_segment,
                    &pssh_data,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InvalidRequest,
                        ));
                    }
                };
                if protected_init_segment.len() > MAX_AGGREGATE_PROTECTED_MEDIA_BYTES_V1 {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                }
                let Some(request_nodes) = request.nodes() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                let nodes = match request_nodes
                    .iter()
                    .map(exact_custody_node)
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InvalidRequest,
                        ));
                    }
                };
                let handle =
                    match next_unique_handle(state.sessions.keys(), state.closed_handles.iter()) {
                        Ok(value) => value,
                        Err(_) => {
                            return typed_response(ProtectProviderResponseV1::new_failure(
                                ProviderFailureCodeV1::BackendUnavailable,
                            ));
                        }
                    };
                let response =
                    match ProtectProviderResponseV1::new_opened(handle, &protected_init_segment) {
                        Ok(value) => value,
                        Err(_) => {
                            return typed_response(ProtectProviderResponseV1::new_failure(
                                ProviderFailureCodeV1::InternalFailure,
                            ));
                        }
                    };
                let aggregate_protected_bytes = match response.protected_init_segment() {
                    Some(protected_init) => protected_init.len(),
                    None => {
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                trim_btree_map(&mut state.open_replays, MAX_TERMINAL_REPLAYS_V1);
                state.open_replays.insert(
                    open_replay_key,
                    OpenReplayEntry {
                        request_digest,
                        response: response.clone(),
                    },
                );
                state.sessions.insert(
                    handle,
                    ProtectionSessionEntry {
                        custody_pool,
                        custody_epoch,
                        custody_committee_authorization,
                        nodes,
                        kind: ProtectionSessionKind::Media(MediaSessionState {
                            mime_type,
                            codecs,
                            clear_session_layout,
                            protected_init_segment,
                            protected_segments: Vec::with_capacity(segment_count as usize),
                            segment_replays: BTreeMap::new(),
                            content_key: Some(content_key),
                            iv_prefix,
                            next_iv_counter: 0,
                            segment_count,
                            next_segment_index: 0,
                            aggregate_protected_bytes,
                        }),
                        finalized: None,
                    },
                );
                typed_ok(response)
            }
            ProtectProviderRequestOpV1::ProtectMediaSegment => {
                let Ok(Some(handle)) = request.protection_session_handle() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                let Some(session) = state.sessions.get_mut(&handle) else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::HandleAbsent,
                    ));
                };
                if matches!(session.kind, ProtectionSessionKind::MediaDash(_)) {
                    return protect_dash_segment(state, handle, &request, request_digest);
                }
                let ProtectionSessionKind::Media(media) = &mut session.kind else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                if request.rendition_index().is_some() {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                }
                let Some(segment_index) = request.segment_index() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                if let Some(replay) = media.segment_replays.get(&segment_index) {
                    return if replay.request_digest == request_digest {
                        match media.protected_segments.get(segment_index as usize) {
                            Some(protected_segment) => {
                                match ProtectProviderResponseV1::new_segment_protected(
                                    handle,
                                    segment_index,
                                    protected_segment,
                                ) {
                                    Ok(response) => typed_ok(response),
                                    Err(_) => {
                                        typed_response(ProtectProviderResponseV1::new_failure(
                                            ProviderFailureCodeV1::InternalFailure,
                                        ))
                                    }
                                }
                            }
                            None => typed_response(ProtectProviderResponseV1::new_failure(
                                ProviderFailureCodeV1::InternalFailure,
                            )),
                        }
                    } else {
                        typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::BindingMismatch,
                        ))
                    };
                }
                if session.finalized.is_some()
                    || segment_index != media.next_segment_index
                    || segment_index >= media.segment_count
                {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                }
                let Some(content_key) = media.content_key.as_ref() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::BindingMismatch,
                    ));
                };
                let Some(clear_segment) = request.clear_segment() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                let clear_segment_layout =
                    match media.clear_session_layout.validate_segment(clear_segment) {
                        Ok(value) => value,
                        Err(_) => {
                            return typed_response(ProtectProviderResponseV1::new_failure(
                                ProviderFailureCodeV1::InvalidRequest,
                            ));
                        }
                    };
                let sample_count = clear_segment_layout.samples().len();
                let sample_ivs = match allocate_sample_ivs(
                    media.iv_prefix,
                    &mut media.next_iv_counter,
                    sample_count,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::BackendUnavailable,
                        ));
                    }
                };
                let protected_segment = match protect_validated_clear_fmp4_segment_to_cenc_v1(
                    &clear_segment_layout,
                    clear_segment,
                    content_key,
                    &sample_ivs,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InvalidRequest,
                        ));
                    }
                };
                let new_aggregate = match media
                    .aggregate_protected_bytes
                    .checked_add(protected_segment.len())
                {
                    Some(value) if value <= MAX_AGGREGATE_PROTECTED_MEDIA_BYTES_V1 => value,
                    _ => {
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InvalidRequest,
                        ));
                    }
                };
                let response = match ProtectProviderResponseV1::new_segment_protected(
                    handle,
                    segment_index,
                    &protected_segment,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                media.aggregate_protected_bytes = new_aggregate;
                media.next_segment_index = media.next_segment_index.saturating_add(1);
                media.protected_segments.push(protected_segment);
                media
                    .segment_replays
                    .insert(segment_index, SegmentReplayEntry { request_digest });
                typed_ok(response)
            }
            ProtectProviderRequestOpV1::FinalizeProtectionSession => {
                let Ok(Some(handle)) = request.protection_session_handle() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                let Some(session) = state.sessions.get_mut(&handle) else {
                    return typed_response(if state.closed_handles.contains(&handle) {
                        ProtectProviderResponseV1::new_already_absent(handle)
                    } else {
                        ProtectProviderResponseV1::new_failure(ProviderFailureCodeV1::HandleAbsent)
                    });
                };
                if matches!(session.kind, ProtectionSessionKind::MediaDash(_)) {
                    return finalize_media_dash(session, handle);
                }
                let ProtectionSessionKind::Media(media) = &mut session.kind else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                if let Some(response) = &session.finalized {
                    return typed_ok(response.clone());
                }
                if media.next_segment_index != media.segment_count {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                }
                let Some(content_key) = media.content_key.as_ref() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::BindingMismatch,
                    ));
                };
                let media_identity = match CencFmp4MediaIdentityV1::new_from_bytes(
                    &media.protected_init_segment,
                    &media.protected_segments,
                    &media.mime_type,
                    &media.codecs,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                let custody_envelope = match provision_custody_envelope_for_exact_nodes(
                    media_identity.encrypted_content().clone(),
                    content_key,
                    session.custody_pool,
                    session.custody_epoch,
                    session.custody_committee_authorization,
                    &session.nodes,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                let response = match ProtectProviderResponseV1::new_finalized(
                    handle,
                    &media_identity,
                    &custody_envelope,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                media.content_key = None;
                session.finalized = Some(response.clone());
                typed_ok(response)
            }
            ProtectProviderRequestOpV1::CancelProtectionSession => {
                let Ok(Some(handle)) = request.protection_session_handle() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                if state.sessions.remove(&handle).is_some() {
                    trim_btree_set(&mut state.closed_handles, MAX_TERMINAL_REPLAYS_V1);
                    state.closed_handles.insert(handle);
                    typed_response(ProtectProviderResponseV1::new_cancelled(handle))
                } else {
                    typed_response(ProtectProviderResponseV1::new_already_absent(handle))
                }
            }
            ProtectProviderRequestOpV1::CloseProtectionSession => {
                let Ok(Some(handle)) = request.protection_session_handle() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                if state.sessions.remove(&handle).is_some() {
                    trim_btree_set(&mut state.closed_handles, MAX_TERMINAL_REPLAYS_V1);
                    state.closed_handles.insert(handle);
                    typed_response(ProtectProviderResponseV1::new_closed(handle))
                } else {
                    typed_response(ProtectProviderResponseV1::new_already_absent(handle))
                }
            }
            ProtectProviderRequestOpV1::OpenObjectProtectionSession => {
                let (
                    Some(session_id),
                    Ok(Some(custody_pool)),
                    Ok(Some(custody_epoch)),
                    Ok(Some(custody_committee_authorization)),
                    Some(content_type),
                    Some(plaintext_bytes),
                    Some(threshold_required),
                    Some(threshold_total),
                ) = (
                    request.session_id(),
                    request.custody_pool(),
                    request.custody_epoch(),
                    request.custody_committee_authorization(),
                    request.content_type(),
                    request.plaintext_bytes(),
                    request.threshold_required(),
                    request.threshold_total(),
                )
                else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                // The object contract accepts any valid (threshold_required,
                // threshold_total) with nodes.len() == threshold_total, but
                // provision_custody_envelope_for_exact_nodes (below) hard-
                // requires exactly 3 nodes and hard-codes a 2-of-3 threshold
                // internally regardless of what was asked for. Without this
                // check, a (3, 3) request with 3 nodes would provision
                // successfully and silently return a lower-than-requested
                // 2-of-3 envelope, and a (3, 5) request would burn a session
                // slot and a streamed object before failing at
                // finalize with a provider-fault code that misattributes a
                // caller error. Reject both up front instead.
                if (threshold_required, threshold_total) != (2, 3) {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                }
                let content_type = content_type.to_string();
                let session_key: HandleBytes = *session_id.as_bytes();
                let open_replay_key: OpenReplayKey = (OpenReplayDomain::Object, session_key);

                if let Some(replay) = state.open_replays.get(&open_replay_key) {
                    return if replay.request_digest == request_digest {
                        typed_ok(replay.response.clone())
                    } else {
                        typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::BindingMismatch,
                        ))
                    };
                }
                if state.sessions.contains_key(&session_key) {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::BindingMismatch,
                    ));
                }
                if state.sessions.len() >= MAX_ACTIVE_SESSIONS_V1 {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::BackendUnavailable,
                    ));
                }
                // No size cap here: the sealer bounds the framed object. The
                // chunk index on the wire is a u32, so a count past it fails closed.
                let chunk_count =
                    plaintext_bytes.div_ceil(MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1 as u64);
                if plaintext_bytes == 0 || chunk_count > u64::from(u32::MAX) {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                }
                let Some(request_nodes) = request.nodes() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                let nodes = match request_nodes
                    .iter()
                    .map(exact_custody_node)
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InvalidRequest,
                        ));
                    }
                };
                // Belt-and-suspenders alongside the threshold check above:
                // provision_custody_envelope_for_exact_nodes requires exactly
                // 3 nodes regardless of what the contract-level threshold
                // validation independently enforces.
                if nodes.len() != 3 {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                }
                let (sealer, framed_header) =
                    match PayloadSealerV1::open(&content_type, plaintext_bytes) {
                        Ok(value) => value,
                        Err(_) => {
                            return typed_response(ProtectProviderResponseV1::new_failure(
                                ProviderFailureCodeV1::InvalidRequest,
                            ));
                        }
                    };
                let framed_header_bytes = match u32::try_from(framed_header.len()) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                let response = match ProtectProviderResponseV1::new_object_opened(&framed_header) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };

                trim_btree_map(&mut state.open_replays, MAX_TERMINAL_REPLAYS_V1);
                state.open_replays.insert(
                    open_replay_key,
                    OpenReplayEntry {
                        request_digest,
                        response: response.clone(),
                    },
                );
                state.sessions.insert(
                    session_key,
                    ProtectionSessionEntry {
                        custody_pool,
                        custody_epoch,
                        custody_committee_authorization,
                        nodes,
                        kind: ProtectionSessionKind::Object(ObjectSessionState {
                            sealer: Some(sealer),
                            framed_header_bytes,
                        }),
                        finalized: None,
                    },
                );
                typed_ok(response)
            }
            ProtectProviderRequestOpV1::ProtectObjectChunk => {
                let Some(session_id) = request.session_id() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                let session_key: HandleBytes = *session_id.as_bytes();
                let Some(session) = state.sessions.get_mut(&session_key) else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::HandleAbsent,
                    ));
                };
                let ProtectionSessionKind::Object(object) = &mut session.kind else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                let (Some(chunk_index), Some(plaintext), Some(sealer)) = (
                    request.chunk_index(),
                    request.plaintext(),
                    object.sealer.as_mut(),
                ) else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                let framed_chunk = match sealer.seal_chunk(chunk_index, plaintext) {
                    Ok(value) => value,
                    Err(_) => {
                        // The sealer enforces strict, gap-free, non-replayable
                        // chunk ordering; any rejection here (wrong index,
                        // wrong length) means the caller's stream is
                        // desynchronized from what has already been sealed
                        // and folded into the running hash. There is no safe
                        // partial-retry: cancel the whole session rather than
                        // leave a half-sealed object reachable.
                        cancel_session(state, session_key);
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InvalidRequest,
                        ));
                    }
                };
                match ProtectProviderResponseV1::new_object_chunk_protected(&framed_chunk) {
                    Ok(response) => typed_ok(response),
                    Err(_) => typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InternalFailure,
                    )),
                }
            }
            ProtectProviderRequestOpV1::FinalizeObjectProtectionSession => {
                let Some(session_id) = request.session_id() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                let Ok(Some(declared_encrypted_content)) = request.encrypted_content() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                let session_key: HandleBytes = *session_id.as_bytes();
                let Some(session) = state.sessions.get_mut(&session_key) else {
                    return typed_response(if state.closed_handles.contains(&session_key) {
                        ProtectProviderResponseV1::new_already_absent(session_key)
                    } else {
                        ProtectProviderResponseV1::new_failure(ProviderFailureCodeV1::HandleAbsent)
                    });
                };
                let ProtectionSessionKind::Object(object) = &mut session.kind else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                if let Some(response) = &session.finalized {
                    return typed_ok(response.clone());
                }
                // Copied out now, before `sealer.take()`, so provisioning
                // below never needs to re-borrow `session` mutably (which
                // would otherwise require an infallible-but-panicking
                // re-lookup purely to satisfy the borrow checker, in a
                // sandboxed provider where a panic kills the process).
                let custody_pool = session.custody_pool;
                let custody_epoch = session.custody_epoch;
                let custody_committee_authorization = session.custody_committee_authorization;
                let nodes = session.nodes.clone();
                let framed_header_bytes = object.framed_header_bytes;
                let Some(sealer) = object.sealer.take() else {
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };

                let unprovisioned = match sealer.finish_unprovisioned() {
                    Ok(value) => value,
                    Err(_) => {
                        cancel_session(state, session_key);
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InvalidRequest,
                        ));
                    }
                };
                // Compare the caller's declared identity against the
                // identity actually sealed *before* provisioning anything:
                // a mismatch must not release any share of the content key.
                if unprovisioned.encrypted_content_identity() != &declared_encrypted_content {
                    cancel_session(state, session_key);
                    return typed_response(ProtectProviderResponseV1::new_failure(
                        ProviderFailureCodeV1::BindingMismatch,
                    ));
                }
                let custody_envelope = match provision_custody_envelope_for_exact_nodes(
                    unprovisioned.encrypted_content_identity().clone(),
                    unprovisioned.content_key(),
                    custody_pool,
                    custody_epoch,
                    custody_committee_authorization,
                    &nodes,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        cancel_session(state, session_key);
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                let object_identity = match ChunkedPayloadObjectIdentityV1::new(
                    unprovisioned.encrypted_content_identity().clone(),
                    unprovisioned.header().content_type(),
                    unprovisioned.header().plaintext_bytes(),
                    framed_header_bytes,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        cancel_session(state, session_key);
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                let response = match ProtectProviderResponseV1::new_object_finalized(
                    &object_identity,
                    custody_envelope.manifest().content_key_commitment(),
                    &custody_envelope,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        cancel_session(state, session_key);
                        return typed_response(ProtectProviderResponseV1::new_failure(
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };

                let plaintext_bytes = unprovisioned.header().plaintext_bytes();
                let chunks = plaintext_bytes.div_ceil(MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1 as u64);
                let session_id_hex = hex_encode(&session_key);
                info!(
                    session_id = %session_id_hex,
                    chunks,
                    plaintext_bytes,
                    "object protection session finalized"
                );

                session.finalized = Some(response.clone());
                typed_ok(response)
            }
        }
    }
}

fn failure(code: ProviderFailureCodeV1) -> ProviderResponse {
    typed_response(ProtectProviderResponseV1::new_failure(code))
}

/// Opens a v2 session: every rendition's init is rewritten under one protection
/// header and one list of foreign `pssh` boxes. Nothing is stored unless every
/// step succeeds.
fn open_media_dash(
    state: &mut ConfiguredProtectProvider,
    request: &ProtectProviderRequestV1,
    request_digest: RequestDigest,
) -> ProviderResponse {
    open_media_dash_within(state, request, request_digest, MAX_PROVIDER_FRAME_BYTES_V1)
}

/// `max_response_bytes` is the frame limit; a seam so a test can reach it.
fn open_media_dash_within(
    state: &mut ConfiguredProtectProvider,
    request: &ProtectProviderRequestV1,
    request_digest: RequestDigest,
    max_response_bytes: usize,
) -> ProviderResponse {
    let (
        Some(session_request_id),
        Ok(Some(custody_pool)),
        Ok(Some(custody_epoch)),
        Ok(Some(custody_committee_authorization)),
        Ok(Some(content_access_id)),
        Some(representations),
        Some(request_nodes),
    ) = (
        request.protection_session_request_id(),
        request.custody_pool(),
        request.custody_epoch(),
        request.custody_committee_authorization(),
        request.content_access_id(),
        request.representations(),
        request.nodes(),
    )
    else {
        return failure(ProviderFailureCodeV1::InvalidRequest);
    };
    let request_id = *session_request_id.as_bytes();
    let open_replay_key: OpenReplayKey = (OpenReplayDomain::Media, request_id);
    if let Some(replay) = state.open_replays.get(&open_replay_key) {
        return if replay.request_digest == request_digest {
            typed_ok(replay.response.clone())
        } else {
            failure(ProviderFailureCodeV1::BindingMismatch)
        };
    }
    if state.sessions.len() >= MAX_ACTIVE_SESSIONS_V1 {
        return failure(ProviderFailureCodeV1::BackendUnavailable);
    }
    let mut layouts = Vec::with_capacity(representations.len());
    for representation in representations {
        let Ok(layout) = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
            representation.clear_init_segment(),
            CencLayoutProfile::V2,
        ) else {
            return failure(ProviderFailureCodeV1::InvalidRequest);
        };
        if layout.rendition().map(|rendition| rendition.kind()) != Some(representation.kind()) {
            return failure(ProviderFailureCodeV1::InvalidRequest);
        }
        layouts.push(layout);
    }
    let Ok(content_key) = ContentEncryptionKeyV1::generate() else {
        return failure(ProviderFailureCodeV1::InternalFailure);
    };
    // One header and one list of foreign boxes for every rendition's init: the
    // renditions must agree on the key, the pool and the epoch.
    let pssh_data = CustodyProtectionHeader::new(
        content_access_id,
        &custody_pool,
        &custody_epoch,
        &custody_committee_authorization,
        CencMediaSuite::DashV2,
    );
    let Ok(iv_prefix) = random_bytes::<4>() else {
        return failure(ProviderFailureCodeV1::InternalFailure);
    };
    let extra_pssh_boxes = request.extra_pssh_boxes();
    let mut protected_inits = Vec::with_capacity(representations.len());
    let mut decls = Vec::with_capacity(representations.len());
    for (representation, layout) in representations.iter().zip(&layouts) {
        let (Ok(protected_init), Some(rendition)) = (
            protect_validated_clear_fmp4_init_to_cenc_v2(
                layout,
                representation.clear_init_segment(),
                &pssh_data,
                &extra_pssh_boxes,
            ),
            layout.rendition(),
        ) else {
            return failure(ProviderFailureCodeV1::InvalidRequest);
        };
        let decl = CencDashRenditionDeclV2::from_init(
            representation.kind(),
            rendition.timescale(),
            &protected_init,
            representation.segment_count(),
        );
        // The mime type and codecs of a v2 rendition are pinned by its kind.
        if decl.mime_type != representation.mime_type() || decl.codecs != representation.codecs() {
            return failure(ProviderFailureCodeV1::InvalidRequest);
        }
        protected_inits.push(protected_init);
        decls.push(decl);
    }
    let Ok(builder) = CencDashIdentityBuilderV2::new(content_access_id, decls) else {
        return failure(ProviderFailureCodeV1::InvalidRequest);
    };
    let Ok(nodes) = request_nodes
        .iter()
        .map(exact_custody_node)
        .collect::<Result<Vec<_>, _>>()
    else {
        return failure(ProviderFailureCodeV1::InvalidRequest);
    };
    let Ok(handle) = next_unique_handle(state.sessions.keys(), state.closed_handles.iter()) else {
        return failure(ProviderFailureCodeV1::BackendUnavailable);
    };
    let Ok(response) = ProtectProviderResponseV1::new_opened_v2(handle, &protected_inits) else {
        return failure(ProviderFailureCodeV1::InternalFailure);
    };
    // A response the frame limit refuses must not leave a session behind.
    if !serde_json::to_vec(&response).is_ok_and(|bytes| bytes.len() <= max_response_bytes) {
        return failure(ProviderFailureCodeV1::InvalidRequest);
    }
    let renditions = representations
        .iter()
        .zip(layouts)
        .map(
            |(representation, clear_session_layout)| DashRenditionState {
                clear_session_layout,
                segment_count: representation.segment_count(),
            },
        )
        .collect();
    trim_btree_map(&mut state.open_replays, MAX_TERMINAL_REPLAYS_V1);
    state.open_replays.insert(
        open_replay_key,
        OpenReplayEntry {
            request_digest,
            response: response.clone(),
        },
    );
    state.sessions.insert(
        handle,
        ProtectionSessionEntry {
            custody_pool,
            custody_epoch,
            custody_committee_authorization,
            nodes,
            kind: ProtectionSessionKind::MediaDash(Box::new(MediaDashSessionStateV2 {
                request_id,
                renditions,
                builder,
                content_key: Some(content_key),
                iv_prefix,
                next_iv_counter: 0,
                cursor: (0, 0),
                last: None,
            })),
            finalized: None,
        },
    );
    typed_ok(response)
}

/// Protects the next v2 segment. `segment_index` counts within the rendition at
/// `rendition_index`; renditions are protected in order, each to its last
/// segment. Only the last acknowledged segment can be replayed.
fn protect_dash_segment(
    state: &mut ConfiguredProtectProvider,
    handle: HandleBytes,
    request: &ProtectProviderRequestV1,
    request_digest: RequestDigest,
) -> ProviderResponse {
    let Some(session) = state.sessions.get_mut(&handle) else {
        return failure(ProviderFailureCodeV1::HandleAbsent);
    };
    let ProtectionSessionKind::MediaDash(dash) = &mut session.kind else {
        return failure(ProviderFailureCodeV1::InvalidRequest);
    };
    let (Some(rendition_index), Some(segment_index), Some(clear_segment)) = (
        request.rendition_index(),
        request.segment_index(),
        request.clear_segment(),
    ) else {
        return failure(ProviderFailureCodeV1::InvalidRequest);
    };
    let rendition_index = usize::from(rendition_index);
    if let Some(last) = &dash.last {
        if (last.rendition_index, last.segment_index) == (rendition_index, segment_index) {
            return if last.request_digest == request_digest {
                typed_ok(last.response.clone())
            } else {
                failure(ProviderFailureCodeV1::BindingMismatch)
            };
        }
    }
    let in_range = dash
        .renditions
        .get(rendition_index)
        .is_some_and(|rendition| segment_index < rendition.segment_count);
    if session.finalized.is_some() || !in_range || (rendition_index, segment_index) != dash.cursor {
        return failure(ProviderFailureCodeV1::InvalidRequest);
    }
    let Some(content_key) = dash.content_key.as_ref() else {
        return failure(ProviderFailureCodeV1::BindingMismatch);
    };
    let rendition = &dash.renditions[rendition_index];
    let Ok(segment_layout) = rendition
        .clear_session_layout
        .validate_segment(clear_segment)
    else {
        return failure(ProviderFailureCodeV1::InvalidRequest);
    };
    // The IVs are taken before the encryption and are not given back when it
    // fails, so a refused segment burns its range and no IV is ever reused.
    let Ok(sample_ivs) = allocate_sample_ivs(
        dash.iv_prefix,
        &mut dash.next_iv_counter,
        segment_layout.samples().len(),
    ) else {
        return failure(ProviderFailureCodeV1::BackendUnavailable);
    };
    let protected_segment = match protect_validated_clear_fmp4_segment_to_cenc_v2(
        &rendition.clear_session_layout,
        &segment_layout,
        clear_segment,
        content_key,
        &sample_ivs,
    ) {
        Ok(value) => value,
        Err(CustodyError::InvalidPayload("cenc_too_many_subsamples")) => {
            return typed_response(ProtectProviderResponseV1::new_failure_with_reason(
                ProviderFailureCodeV1::InvalidRequest,
                ProtectFailureReasonV2::CencTooManySubsamples,
            ));
        }
        Err(_) => return failure(ProviderFailureCodeV1::InvalidRequest),
    };
    // The response is built before the builder is fed: the builder cannot roll
    // back a segment.
    let Ok(response) =
        ProtectProviderResponseV1::new_segment_protected(handle, segment_index, &protected_segment)
    else {
        return failure(ProviderFailureCodeV1::InternalFailure);
    };
    if dash.builder.push_segment(&protected_segment).is_err() {
        let request_id = dash.request_id;
        cancel_media_dash_session(state, handle, request_id);
        return failure(ProviderFailureCodeV1::InternalFailure);
    }
    dash.cursor = if segment_index + 1 == rendition.segment_count {
        (rendition_index + 1, 0)
    } else {
        (rendition_index, segment_index + 1)
    };
    dash.last = Some(DashLastSegment {
        rendition_index,
        segment_index,
        request_digest,
        response: response.clone(),
    });
    typed_ok(response)
}

fn finalize_media_dash(
    session: &mut ProtectionSessionEntry,
    handle: HandleBytes,
) -> ProviderResponse {
    if let Some(response) = &session.finalized {
        return typed_ok(response.clone());
    }
    let ProtectionSessionKind::MediaDash(dash) = &mut session.kind else {
        return failure(ProviderFailureCodeV1::InvalidRequest);
    };
    if dash.cursor != (dash.renditions.len(), 0) {
        return failure(ProviderFailureCodeV1::InvalidRequest);
    }
    let Some(content_key) = dash.content_key.as_ref() else {
        return failure(ProviderFailureCodeV1::BindingMismatch);
    };
    // The builder is cloned (it is logarithmic) so a failed provisioning can
    // be retried.
    let Ok(head) = dash.builder.clone().finish() else {
        return failure(ProviderFailureCodeV1::InternalFailure);
    };
    let Ok(custody_envelope) = provision_custody_envelope_for_exact_nodes(
        head.encrypted_content().clone(),
        content_key,
        session.custody_pool,
        session.custody_epoch,
        session.custody_committee_authorization,
        &session.nodes,
    ) else {
        return failure(ProviderFailureCodeV1::InternalFailure);
    };
    let Ok(response) =
        ProtectProviderResponseV1::new_finalized_v2(handle, &head, &custody_envelope)
    else {
        return failure(ProviderFailureCodeV1::InternalFailure);
    };
    let segment_counts: Vec<u32> = dash
        .renditions
        .iter()
        .map(|rendition| rendition.segment_count)
        .collect();
    info!(
        handle = %hex_encode(&handle),
        renditions = segment_counts.len(),
        ?segment_counts,
        "media protection session finalized"
    );
    dash.content_key = None;
    dash.last = None;
    session.finalized = Some(response.clone());
    typed_ok(response)
}

#[cfg(test)]
impl MediaDashSessionStateV2 {
    /// The heap this session holds that could grow with the segment count: the
    /// rendition table and the one replayable response. The builder is
    /// logarithmic by construction.
    fn held_bytes(&self) -> usize {
        self.renditions.capacity() * std::mem::size_of::<DashRenditionState>()
            + self
                .last
                .as_ref()
                .and_then(|last| last.response.protected_segment())
                .map_or(0, <[u8]>::len)
    }
}

/// Tears down a v2 session a builder error has invalidated, including its
/// open-replay entry, so a re-open starts fresh.
fn cancel_media_dash_session(
    state: &mut ConfiguredProtectProvider,
    handle: HandleBytes,
    request_id: HandleBytes,
) {
    state.sessions.remove(&handle);
    state
        .open_replays
        .remove(&(OpenReplayDomain::Media, request_id));
    trim_btree_set(&mut state.closed_handles, MAX_TERMINAL_REPLAYS_V1);
    state.closed_handles.insert(handle);
}

fn exact_custody_node(node: &ProtectionSessionNodeV1) -> Result<ExactCustodyEnvelopeNodeV1, ()> {
    Ok(ExactCustodyEnvelopeNodeV1::new(
        node.node_public_key().map_err(|_| ())?,
        node.node_custody_public_key().map_err(|_| ())?,
    ))
}

fn load_provider_state(config: Value) -> Result<ConfiguredProtectProvider, ()> {
    let config = serde_json::from_value::<InitConfig>(config).map_err(|_| ())?;
    if !config.base_path.is_empty()
        || !config.allowed_paths.is_empty()
        || config.read_only
        || !config.encryption_key.is_empty()
    {
        return Err(());
    }
    let _ = config.extra;
    Ok(ConfiguredProtectProvider {
        open_replays: BTreeMap::new(),
        sessions: BTreeMap::new(),
        closed_handles: BTreeSet::new(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvelopeState {
    Absent,
    Present,
}

fn control_request_has_exact_fields(value: &Value, op: &str) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    match op {
        "status" | "shutdown" => object.len() == 1 && object.contains_key("op"),
        "init" => object.len() == 2 && object.contains_key("op") && object.contains_key("config"),
        _ => false,
    }
}

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
) -> Result<EnvelopeState, ()> {
    let object = value.as_object_mut().ok_or(())?;
    if object.contains_key("_runtime_transfer") {
        return Err(());
    }
    let Some(envelope) = object.remove("_runtime_invocation") else {
        return Ok(EnvelopeState::Absent);
    };
    let envelope = envelope.as_object().ok_or(())?;
    if envelope.len() != 11 {
        return Err(());
    }
    if ![
        "schema",
        "source",
        "target",
        "op",
        "capability",
        "transport",
        "carrier",
        "transfer",
        "range",
        "progress",
        "abi",
    ]
    .into_iter()
    .all(|key| envelope.contains_key(key))
    {
        return Err(());
    }
    let op = object.get("op").and_then(Value::as_str).ok_or(())?;
    let expected_capability = format!("provider:runtime->{expected_target}:{op}");
    let expected_abi = expected_local_json_runtime_invocation_abi();
    if envelope.get("schema").and_then(Value::as_str) != Some("elastos.provider.invocation/v1")
        || envelope.get("source").and_then(Value::as_str) != Some("runtime")
        || envelope.get("target").and_then(Value::as_str) != Some(expected_target)
        || envelope.get("op").and_then(Value::as_str) != Some(op)
        || envelope.get("capability").and_then(Value::as_str) != Some(expected_capability.as_str())
        || envelope.get("transport").and_then(Value::as_str) != Some("runtime-local-provider-plane")
        || envelope.get("carrier") != Some(&Value::Null)
        || envelope.get("transfer").and_then(Value::as_str) != Some("json")
        || envelope.get("range") != Some(&Value::Null)
        || envelope.get("progress") != Some(&Value::Null)
        || envelope.get("abi") != Some(&expected_abi)
    {
        return Err(());
    }
    Ok(EnvelopeState::Present)
}

fn invalid_request() -> ProviderResponse {
    ProviderResponse::error(REQUEST_ERROR_CODE, "protect provider request is invalid")
}

fn typed_ok(response: ProtectProviderResponseV1) -> ProviderResponse {
    match serde_json::to_value(response) {
        Ok(value) => ProviderResponse::ok(value),
        Err(_) => typed_response(ProtectProviderResponseV1::new_failure(
            ProviderFailureCodeV1::InternalFailure,
        )),
    }
}

fn typed_response(
    response: Result<ProtectProviderResponseV1, elastos_protected_content_contracts::ContractError>,
) -> ProviderResponse {
    match response {
        Ok(response) => match serde_json::to_value(response) {
            Ok(value) => ProviderResponse::ok(value),
            Err(_) => {
                ProviderResponse::error(REQUEST_ERROR_CODE, "protect provider request is invalid")
            }
        },
        Err(_) => {
            ProviderResponse::error(REQUEST_ERROR_CODE, "protect provider request is invalid")
        }
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn random_bytes<const N: usize>() -> Result<[u8; N], ()> {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).map_err(|_| ())?;
    Ok(bytes)
}

fn random_nonzero_bytes<const N: usize>() -> Result<[u8; N], ()> {
    let bytes = random_bytes::<N>()?;
    if bytes == [0u8; N] {
        return Err(());
    }
    Ok(bytes)
}

fn next_unique_handle<'a>(
    active: impl Iterator<Item = &'a HandleBytes>,
    closed: impl Iterator<Item = &'a HandleBytes>,
) -> Result<HandleBytes, ()> {
    let active: BTreeSet<HandleBytes> = active.copied().collect();
    let closed: BTreeSet<HandleBytes> = closed.copied().collect();
    for _ in 0..128 {
        let candidate = random_nonzero_bytes::<MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1>()?;
        if !active.contains(&candidate) && !closed.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(())
}

fn allocate_sample_ivs(
    prefix: [u8; 4],
    next_counter: &mut u32,
    count: usize,
) -> Result<Vec<[u8; 8]>, ()> {
    let count_u32 = u32::try_from(count).map_err(|_| ())?;
    let end_counter = next_counter.checked_add(count_u32).ok_or(())?;
    let mut counter = *next_counter;
    let mut ivs = Vec::with_capacity(count);
    for _ in 0..count {
        let mut iv = [0u8; 8];
        iv[..4].copy_from_slice(&prefix);
        iv[4..].copy_from_slice(&counter.to_be_bytes());
        ivs.push(iv);
        counter = counter.checked_add(1).ok_or(())?;
    }
    *next_counter = end_counter;
    Ok(ivs)
}

fn trim_btree_map<K: Ord, V>(map: &mut BTreeMap<K, V>, max: usize) {
    while map.len() >= max {
        let _ = map.pop_first();
    }
}

fn trim_btree_set<T: Ord + Clone>(set: &mut BTreeSet<T>, max: usize) {
    while set.len() >= max {
        let Some(first) = set.first().cloned() else {
            break;
        };
        set.remove(&first);
    }
}

/// Tear down a session that an error has invalidated: remove it from the
/// active map, drop its now-stale open-replay cache entry, and record the
/// handle as closed. Object protection sessions have no dedicated
/// cancel/close wire op (the existing media-shaped ones already work for
/// them, since both kinds share one handle/session-id keyspace and one
/// session map), so this helper is what an object-session error path uses
/// to reach the equivalent end state — this is currently only ever called
/// for object sessions (`ObjectProtectionSession`), so it clears the
/// `Object`-domain open-replay entry specifically. Without this, a
/// byte-identical re-open after an auto-cancelled session would hit the
/// stale replay cache and return a success response (`ObjectProtectionSessionOpened`)
/// for a session that no longer exists, permanently dead-ending that
/// session_id (every subsequent chunk would see `HandleAbsent`, and a
/// differing digest would see `BindingMismatch` instead of a fresh open).
fn cancel_session(state: &mut ConfiguredProtectProvider, handle: HandleBytes) {
    state.sessions.remove(&handle);
    state
        .open_replays
        .remove(&(OpenReplayDomain::Object, handle));
    trim_btree_set(&mut state.closed_handles, MAX_TERMINAL_REPLAYS_V1);
    state.closed_handles.insert(handle);
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn read_provider_frame<R: BufRead>(reader: &mut R) -> io::Result<Option<Result<Vec<u8>, ()>>> {
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
                if frame.len().saturating_add(chunk.len()) > MAX_PROVIDER_FRAME_BYTES_V1 {
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
            if frame.len().saturating_add(consumed) > MAX_PROVIDER_FRAME_BYTES_V1 {
                oversized = true;
            } else {
                frame.extend_from_slice(available);
            }
        }
        reader.consume(consumed);
    }
}

pub fn run_provider_loop<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    provider: &mut ProtectProvider,
) {
    loop {
        let (response, should_shutdown) = match read_provider_frame(input) {
            Ok(Some(Ok(frame))) => provider.handle_frame(&frame),
            Ok(Some(Err(()))) => (invalid_request(), false),
            Ok(None) => break,
            Err(_) => break,
        };
        if serde_json::to_writer(&mut *output, &response).is_err() {
            break;
        }
        if writeln!(output).and_then(|()| output.flush()).is_err() {
            break;
        }
        if should_shutdown {
            break;
        }
    }
}

pub fn run_provider_process() {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut stdout = io::stdout();
    let mut provider = ProtectProvider::new();
    run_provider_loop(&mut input, &mut stdout, &mut provider);
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use elastos_protected_content_contracts::{Digest32, NodeCustodyPublicKeyV1, NodePublicKey};
    use elastos_protected_content_provider_contracts::ProtectProviderResponseStatusV1;

    fn init_config() -> Value {
        json!({
            "base_path": "",
            "allowed_paths": [],
            "read_only": false,
            "encryption_key": "",
            "extra": {}
        })
    }

    fn digest(seed: u8) -> Digest32 {
        Digest32::new([seed; 32])
    }

    fn node_public_key(seed: u8) -> NodePublicKey {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        NodePublicKey::new(signing.verifying_key().to_bytes()).unwrap()
    }

    fn node_custody_public_key(seed: u8) -> NodeCustodyPublicKeyV1 {
        let secret = elastos_protected_content_custody::NodeCustodySecretKeyV1::generate().unwrap();
        let mut bytes = *secret.public_key().unwrap().as_bytes();
        bytes[0] ^= seed;
        NodeCustodyPublicKeyV1::new(bytes).unwrap_or_else(|_| secret.public_key().unwrap())
    }

    fn nodes() -> Vec<ProtectionSessionNodeV1> {
        vec![
            ProtectionSessionNodeV1::new(node_public_key(1), node_custody_public_key(1)).unwrap(),
            ProtectionSessionNodeV1::new(node_public_key(2), node_custody_public_key(2)).unwrap(),
            ProtectionSessionNodeV1::new(node_public_key(3), node_custody_public_key(3)).unwrap(),
        ]
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

    fn make_avc1_entry() -> Vec<u8> {
        let mut payload = vec![0u8; 78];
        payload[24..26].copy_from_slice(&1920u16.to_be_bytes());
        payload[26..28].copy_from_slice(&1080u16.to_be_bytes());
        payload[40..42].copy_from_slice(&1u16.to_be_bytes());
        make_box(b"avc1", &payload)
    }

    fn clear_init_segment() -> Vec<u8> {
        let ftyp = make_box(b"ftyp", b"isom\0\0\0\0isomiso6");
        let stsd = {
            let mut payload = Vec::new();
            payload.extend_from_slice(&1u32.to_be_bytes());
            payload.extend_from_slice(&make_avc1_entry());
            make_fullbox(b"stsd", 0, 0, &payload)
        };
        let stbl = make_box(b"stbl", &stsd);
        let minf = make_box(b"minf", &stbl);
        let hdlr = {
            let mut payload = Vec::new();
            payload.extend_from_slice(&0u32.to_be_bytes());
            payload.extend_from_slice(b"vide");
            payload.extend_from_slice(&[0u8; 12]);
            make_fullbox(b"hdlr", 0, 0, &payload)
        };
        let mdia = {
            let mut content = Vec::new();
            content.extend_from_slice(&hdlr);
            content.extend_from_slice(&minf);
            make_box(b"mdia", &content)
        };
        let trak = {
            let tkhd = {
                let mut payload = vec![0u8; 76];
                payload[8..12].copy_from_slice(&1u32.to_be_bytes());
                make_fullbox(b"tkhd", 0, 0x000007, &payload)
            };
            let mut content = Vec::new();
            content.extend_from_slice(&tkhd);
            content.extend_from_slice(&mdia);
            make_box(b"trak", &content)
        };
        let mvex = {
            let mut payload = Vec::new();
            payload.extend_from_slice(&1u32.to_be_bytes());
            payload.extend_from_slice(&1u32.to_be_bytes());
            payload.extend_from_slice(&0u32.to_be_bytes());
            payload.extend_from_slice(&0u32.to_be_bytes());
            payload.extend_from_slice(&0u32.to_be_bytes());
            let trex = make_fullbox(b"trex", 0, 0, &payload);
            make_box(b"mvex", &trex)
        };
        let moov = {
            let mut content = Vec::new();
            content.extend_from_slice(&trak);
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
            payload_bytes.extend_from_slice(&0i32.to_be_bytes());
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
        let data_offset_at = moof.len() - trun.len() + 16;
        let sample_offset = (moof.len() + 8) as i32;
        moof[data_offset_at..data_offset_at + 4].copy_from_slice(&sample_offset.to_be_bytes());
        [moof, make_box(b"mdat", payload)].concat()
    }

    fn wrap_request(request: &ProtectProviderRequestV1) -> Vec<u8> {
        let mut value = serde_json::to_value(request).unwrap();
        let op = value["op"].as_str().unwrap().to_string();
        value.as_object_mut().unwrap().insert(
            "_runtime_invocation".to_string(),
            json!({
                "schema": "elastos.provider.invocation/v1",
                "source": "runtime",
                "target": "protect",
                "op": op,
                "capability": format!("provider:runtime->protect:{op}"),
                "transport": "runtime-local-provider-plane",
                "carrier": null,
                "transfer": "json",
                "range": null,
                "progress": null,
                "abi": expected_local_json_runtime_invocation_abi()
            }),
        );
        serde_json::to_vec(&value).unwrap()
    }

    fn typed_ok_response(response: ProviderResponse) -> ProtectProviderResponseV1 {
        let typed = typed_provider_response(response);
        assert_ne!(typed.status(), ProtectProviderResponseStatusV1::Failure);
        typed
    }

    fn typed_provider_response(response: ProviderResponse) -> ProtectProviderResponseV1 {
        match response {
            ProviderResponse::Ok { data: Some(data) } => {
                ProtectProviderResponseV1::from_json_slice(&serde_json::to_vec(&data).unwrap())
                    .unwrap()
            }
            other => panic!(
                "unexpected response: {}",
                serde_json::to_string(&other).unwrap()
            ),
        }
    }

    fn assert_failure_code(response: ProviderResponse, expected: ProviderFailureCodeV1) {
        let typed = typed_provider_response(response);
        assert_eq!(typed.status(), ProtectProviderResponseStatusV1::Failure);
        assert_eq!(typed.failure_code(), Some(expected));
    }

    fn init_provider() -> ProtectProvider {
        let mut provider = ProtectProvider::new();
        let (init_response, _) = provider.handle_frame(
            &serde_json::to_vec(&json!({"op": "init", "config": init_config()})).unwrap(),
        );
        match init_response {
            ProviderResponse::Ok { .. } => provider,
            other => panic!(
                "unexpected init: {}",
                serde_json::to_string(&other).unwrap()
            ),
        }
    }

    #[test]
    fn status_exposes_exact_runtime_readiness_contract() {
        let mut provider = init_provider();
        let (response, should_shutdown) = provider.handle_frame(br#"{"op":"status"}"#);
        assert!(!should_shutdown);
        let ProviderResponse::Ok { data: Some(data) } = response else {
            panic!("status must return readiness data");
        };
        assert_eq!(
            data,
            json!({
                "provider": "protected-content-protect",
                "version": PROVIDER_VERSION,
                "configured": true,
                "request_schema": PROTECT_PROVIDER_REQUEST_SCHEMA_V1,
                "response_schema": PROTECT_PROVIDER_RESPONSE_SCHEMA_V1,
                "supported_operations": [
                    "status",
                    "open_protection_session",
                    "protect_media_segment",
                    "finalize_protection_session",
                    "cancel_protection_session",
                    "close_protection_session",
                    "open_object_protection_session",
                    "protect_object_chunk",
                    "finalize_object_protection_session",
                    "shutdown"
                ],
            })
        );
    }

    fn open_request(
        request_id_seed: u8,
        segment_count: u32,
        clear_init: &[u8],
        nodes: Vec<ProtectionSessionNodeV1>,
    ) -> ProtectProviderRequestV1 {
        ProtectProviderRequestV1::new_open_protection_session(
            digest(request_id_seed),
            elastos_protected_content_contracts::ContentAccessIdV1::new([0x41; 16]).unwrap(),
            CustodyPoolIdentityV1::new(digest(0x41), 32).unwrap(),
            CustodyEpochIdentityV1::new(digest(0x42), 32).unwrap(),
            CustodyCommitteeAuthorizationIdentityV1::new(digest(0x43), 32).unwrap(),
            "video/mp4",
            "avc1.640028",
            segment_count,
            clear_init,
            nodes,
        )
        .unwrap()
    }

    #[test]
    fn open_segment_finalize_success_produces_valid_identity_and_bound_envelope() {
        let clear_init = clear_init_segment();
        let clear_segments = [clear_segment(1, b"hello"), clear_segment(1, b"world!")];
        let request = open_request(
            0x31,
            u32::try_from(clear_segments.len()).unwrap(),
            &clear_init,
            nodes(),
        );

        let mut provider = init_provider();

        let opened = typed_ok_response(provider.handle_frame(&wrap_request(&request)).0);
        assert_eq!(
            opened.status(),
            ProtectProviderResponseStatusV1::ProtectionSessionOpened
        );
        let handle = opened.protection_session_handle().unwrap().unwrap();
        let protected_init = opened.protected_init_segment().unwrap().to_vec();

        let mut protected_segments = Vec::new();
        for (index, segment) in clear_segments.iter().enumerate() {
            let response = typed_ok_response(
                provider
                    .handle_frame(&wrap_request(
                        &ProtectProviderRequestV1::new_protect_media_segment(
                            handle,
                            u32::try_from(index).unwrap(),
                            segment,
                        )
                        .unwrap(),
                    ))
                    .0,
            );
            assert_eq!(
                response.status(),
                ProtectProviderResponseStatusV1::MediaSegmentProtected
            );
            protected_segments.push(response.protected_segment().unwrap().to_vec());
        }

        let finalized = typed_ok_response(
            provider
                .handle_frame(&wrap_request(
                    &ProtectProviderRequestV1::new_finalize_protection_session(handle).unwrap(),
                ))
                .0,
        );
        assert_eq!(
            finalized.status(),
            ProtectProviderResponseStatusV1::ProtectionSessionFinalized
        );
        let media_identity = finalized.media_identity().unwrap().unwrap();
        let expected_identity = CencFmp4MediaIdentityV1::new_from_bytes(
            &protected_init,
            &protected_segments,
            "video/mp4",
            "avc1.640028",
        )
        .unwrap();
        assert_eq!(media_identity, expected_identity);
        let validated =
            CencFmp4MediaIdentityV1::validate_structure(&protected_init, &protected_segments)
                .unwrap();
        assert_eq!(validated.protected_track_ids(), &[1]);

        let envelope = finalized.custody_envelope().unwrap().unwrap();
        assert_eq!(
            envelope.manifest().encrypted_content(),
            media_identity.encrypted_content()
        );
        assert_eq!(
            envelope.manifest().custody_pool(),
            request.custody_pool().unwrap().unwrap()
        );
        assert_eq!(
            envelope.manifest().custody_epoch(),
            request.custody_epoch().unwrap().unwrap()
        );
        assert_eq!(
            envelope.manifest().custody_committee_authorization(),
            request.custody_committee_authorization().unwrap().unwrap()
        );
        assert_eq!(envelope.manifest().threshold().required(), 2);
        assert_eq!(envelope.manifest().threshold().total(), 3);
        assert_eq!(envelope.manifest().nodes().len(), 3);
        let mut expected_nodes = request
            .nodes()
            .unwrap()
            .iter()
            .map(|node| node.node_public_key().unwrap())
            .collect::<Vec<_>>();
        expected_nodes.sort_unstable();
        assert_eq!(
            envelope
                .manifest()
                .nodes()
                .iter()
                .map(|node| node.node_public_key())
                .collect::<Vec<_>>(),
            expected_nodes
        );

        let debug = format!("{provider:?}");
        assert!(!debug.contains("key"));
        assert!(!debug.contains("share"));
        assert!(!debug.contains("route"));
        assert!(!debug.contains("path"));
        assert_ne!(protected_init, clear_init);
        assert_ne!(protected_segments[0], clear_segments[0]);
    }

    #[test]
    fn allocate_sample_ivs_is_atomic_on_exhaustion() {
        let mut next_counter = u32::MAX;
        assert!(allocate_sample_ivs([0x11, 0x22, 0x33, 0x44], &mut next_counter, 2).is_err());
        assert_eq!(next_counter, u32::MAX);

        let mut next_counter = u32::MAX - 2;
        let ivs = allocate_sample_ivs([0x11, 0x22, 0x33, 0x44], &mut next_counter, 2).unwrap();
        assert_eq!(next_counter, u32::MAX);
        assert_eq!(ivs.len(), 2);
        assert_eq!(ivs[0], [0x11, 0x22, 0x33, 0x44, 0xff, 0xff, 0xff, 0xfd]);
        assert_eq!(ivs[1], [0x11, 0x22, 0x33, 0x44, 0xff, 0xff, 0xff, 0xfe]);

        let mut next_counter = u32::MAX - 1;
        assert!(allocate_sample_ivs([0x11, 0x22, 0x33, 0x44], &mut next_counter, 2).is_err());
        assert_eq!(next_counter, u32::MAX - 1);
    }

    #[test]
    fn open_replay_is_exact_and_conflicting_reuse_fails() {
        let clear_init = clear_init_segment();
        let nodes = nodes();
        let request = open_request(0x51, 1, &clear_init, nodes.clone());
        let changed = open_request(0x51, 2, &clear_init, nodes);
        let mut provider = init_provider();

        let first = typed_ok_response(provider.handle_frame(&wrap_request(&request)).0);
        let replay = typed_ok_response(provider.handle_frame(&wrap_request(&request)).0);
        assert_eq!(first, replay);

        assert_failure_code(
            provider.handle_frame(&wrap_request(&changed)).0,
            ProviderFailureCodeV1::BindingMismatch,
        );
    }

    #[test]
    fn segment_replay_order_and_finalize_bounds_are_strict() {
        let clear_init = clear_init_segment();
        let segment0 = clear_segment(1, b"hello");
        let segment1 = clear_segment(1, b"world!");
        let mut provider = init_provider();
        let request = open_request(0x61, 2, &clear_init, nodes());
        let opened = typed_ok_response(provider.handle_frame(&wrap_request(&request)).0);
        let handle = opened.protection_session_handle().unwrap().unwrap();

        assert_failure_code(
            provider
                .handle_frame(&wrap_request(
                    &ProtectProviderRequestV1::new_protect_media_segment(handle, 1, &segment1)
                        .unwrap(),
                ))
                .0,
            ProviderFailureCodeV1::InvalidRequest,
        );

        let protected0 = typed_ok_response(
            provider
                .handle_frame(&wrap_request(
                    &ProtectProviderRequestV1::new_protect_media_segment(handle, 0, &segment0)
                        .unwrap(),
                ))
                .0,
        );
        let protected0_replay = typed_ok_response(
            provider
                .handle_frame(&wrap_request(
                    &ProtectProviderRequestV1::new_protect_media_segment(handle, 0, &segment0)
                        .unwrap(),
                ))
                .0,
        );
        assert_eq!(protected0, protected0_replay);

        assert_failure_code(
            provider
                .handle_frame(&wrap_request(
                    &ProtectProviderRequestV1::new_protect_media_segment(handle, 0, b"HELLO")
                        .unwrap(),
                ))
                .0,
            ProviderFailureCodeV1::BindingMismatch,
        );

        assert_failure_code(
            provider
                .handle_frame(&wrap_request(
                    &ProtectProviderRequestV1::new_finalize_protection_session(handle).unwrap(),
                ))
                .0,
            ProviderFailureCodeV1::InvalidRequest,
        );

        let protected1 = typed_ok_response(
            provider
                .handle_frame(&wrap_request(
                    &ProtectProviderRequestV1::new_protect_media_segment(handle, 1, &segment1)
                        .unwrap(),
                ))
                .0,
        );
        let finalized = typed_ok_response(
            provider
                .handle_frame(&wrap_request(
                    &ProtectProviderRequestV1::new_finalize_protection_session(handle).unwrap(),
                ))
                .0,
        );
        let finalized_replay = typed_ok_response(
            provider
                .handle_frame(&wrap_request(
                    &ProtectProviderRequestV1::new_finalize_protection_session(handle).unwrap(),
                ))
                .0,
        );
        assert_eq!(finalized, finalized_replay);

        assert_failure_code(
            provider
                .handle_frame(&wrap_request(
                    &ProtectProviderRequestV1::new_protect_media_segment(handle, 2, b"extra")
                        .unwrap(),
                ))
                .0,
            ProviderFailureCodeV1::InvalidRequest,
        );

        let protected_layout = CencFmp4MediaIdentityV1::validate_structure(
            opened.protected_init_segment().unwrap(),
            &[
                protected0.protected_segment().unwrap().to_vec(),
                protected1.protected_segment().unwrap().to_vec(),
            ],
        )
        .unwrap();
        assert_ne!(
            protected_layout.segments()[0].samples()[0].iv(),
            protected_layout.segments()[1].samples()[0].iv()
        );
    }

    #[test]
    fn cancel_close_and_repeated_close_are_typed() {
        let clear_init = clear_init_segment();
        let mut provider = init_provider();
        let request = open_request(0x71, 1, &clear_init, nodes());
        let opened = typed_ok_response(provider.handle_frame(&wrap_request(&request)).0);
        let handle = opened.protection_session_handle().unwrap().unwrap();

        let cancelled = typed_ok_response(
            provider
                .handle_frame(&wrap_request(
                    &ProtectProviderRequestV1::new_cancel_protection_session(handle).unwrap(),
                ))
                .0,
        );
        assert_eq!(
            cancelled.status(),
            ProtectProviderResponseStatusV1::ProtectionSessionCancelled
        );
        let absent = typed_ok_response(
            provider
                .handle_frame(&wrap_request(
                    &ProtectProviderRequestV1::new_close_protection_session(handle).unwrap(),
                ))
                .0,
        );
        assert_eq!(
            absent.status(),
            ProtectProviderResponseStatusV1::ProtectionSessionAlreadyAbsent
        );

        let request = open_request(0x72, 1, &clear_init, nodes());
        let opened = typed_ok_response(provider.handle_frame(&wrap_request(&request)).0);
        let handle = opened.protection_session_handle().unwrap().unwrap();
        let closed = typed_ok_response(
            provider
                .handle_frame(&wrap_request(
                    &ProtectProviderRequestV1::new_close_protection_session(handle).unwrap(),
                ))
                .0,
        );
        assert_eq!(
            closed.status(),
            ProtectProviderResponseStatusV1::ProtectionSessionClosed
        );
        let closed_replay = typed_ok_response(
            provider
                .handle_frame(&wrap_request(
                    &ProtectProviderRequestV1::new_close_protection_session(handle).unwrap(),
                ))
                .0,
        );
        assert_eq!(
            closed_replay.status(),
            ProtectProviderResponseStatusV1::ProtectionSessionAlreadyAbsent
        );
    }

    #[test]
    fn aggregate_cap_and_session_cap_are_enforced_without_permanent_open_exhaustion() {
        let clear_init = clear_init_segment();
        let mut provider = init_provider();

        let mut handles = Vec::new();
        for seed in 1..=MAX_ACTIVE_SESSIONS_V1 {
            let opened = typed_ok_response(
                provider
                    .handle_frame(&wrap_request(&open_request(
                        u8::try_from(seed).unwrap(),
                        1,
                        &clear_init,
                        nodes(),
                    )))
                    .0,
            );
            handles.push(opened.protection_session_handle().unwrap().unwrap());
        }
        assert_failure_code(
            provider
                .handle_frame(&wrap_request(&open_request(0xf1, 1, &clear_init, nodes())))
                .0,
            ProviderFailureCodeV1::BackendUnavailable,
        );
        let _ = typed_ok_response(
            provider
                .handle_frame(&wrap_request(
                    &ProtectProviderRequestV1::new_close_protection_session(handles[0]).unwrap(),
                ))
                .0,
        );
        let reopened = typed_ok_response(
            provider
                .handle_frame(&wrap_request(&open_request(0xf2, 1, &clear_init, nodes())))
                .0,
        );
        assert_eq!(
            reopened.status(),
            ProtectProviderResponseStatusV1::ProtectionSessionOpened
        );

        let mut provider = init_provider();
        let large_payload = vec![0x55; 2 * 1024 * 1024 - 256];
        let large_segment = clear_segment(1, &large_payload);
        let request = open_request(0x81, 16, &clear_init, nodes());
        let opened = typed_ok_response(provider.handle_frame(&wrap_request(&request)).0);
        let handle = opened.protection_session_handle().unwrap().unwrap();
        let mut failed = false;
        for index in 0..16u32 {
            let response = provider.handle_frame(&wrap_request(
                &ProtectProviderRequestV1::new_protect_media_segment(handle, index, &large_segment)
                    .unwrap(),
            ));
            let typed = typed_provider_response(response.0);
            if typed.status() == ProtectProviderResponseStatusV1::Failure {
                assert_eq!(
                    typed.failure_code(),
                    Some(ProviderFailureCodeV1::InvalidRequest)
                );
                failed = true;
                break;
            }
        }
        assert!(
            failed,
            "aggregate cap should reject oversized session retention"
        );
    }
    mod dash_v2 {
        use elastos_protected_content_contracts::ContentAccessIdV1;
        use elastos_protected_content_custody::require_common_cenc_dash_protection_header_v2;
        use elastos_protected_content_provider_contracts::{
            build_pssh_v1, cenc_dash_merkle_audit_path, cenc_dash_segment_leaf_hash,
            CencDashMediaIdentityV2, CencDashRenditionKindV2, ValidatedCencDashRenditionSessionV2,
            PROTECTION,
        };

        use super::*;

        const KID: [u8; 16] = [0x41; 16];
        const TIMESCALE: u32 = 15360;
        const WIDEVINE: [u8; 16] = [
            0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d,
            0x21, 0xed,
        ];
        const PLAYREADY: [u8; 16] = [
            0x9a, 0x04, 0xf0, 0x79, 0x98, 0x40, 0x42, 0x86, 0xab, 0x92, 0xe6, 0x5b, 0xe0, 0x88,
            0x5f, 0x95,
        ];
        const V: CencDashRenditionKindV2 = CencDashRenditionKindV2::Video;
        const A: CencDashRenditionKindV2 = CencDashRenditionKindV2::Audio;

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

        fn init(kind: CencDashRenditionKindV2) -> Vec<u8> {
            let mut tkhd = vec![0u8; 12];
            tkhd[8..12].copy_from_slice(&1u32.to_be_bytes());
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
            let mut trex = 1u32.to_be_bytes().to_vec();
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

        fn nal(nal_type: u8, len: usize) -> Vec<u8> {
            let mut out = (len as u32).to_be_bytes().to_vec();
            out.push(0x60 | nal_type);
            out.extend((1..len).map(|index| (index * 7 + 3) as u8));
            out
        }

        fn fragment(decode_time: u64, samples: &[Vec<u8>]) -> Vec<u8> {
            let mut tfhd = 1u32.to_be_bytes().to_vec();
            tfhd.extend_from_slice(&1u32.to_be_bytes());
            tfhd.extend_from_slice(&512u32.to_be_bytes());
            tfhd.extend_from_slice(&0u32.to_be_bytes());
            let mut trun = (samples.len() as u32).to_be_bytes().to_vec();
            trun.extend_from_slice(&0i32.to_be_bytes());
            for sample in samples {
                trun.extend_from_slice(&(sample.len() as u32).to_be_bytes());
            }
            let tfhd = fbx(b"tfhd", 0, 0x02002a, &tfhd);
            let tfdt = fbx(b"tfdt", 1, 0, &decode_time.to_be_bytes());
            let trun = fbx(b"trun", 0, 0x000201, &trun);
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

        /// A video segment of two multi-slice samples (SEI, two slices, a short one).
        fn video_segment(index: usize) -> Vec<u8> {
            let sample =
                |slice: usize| [nal(6, 30), nal(5, slice), nal(1, slice / 2), nal(1, 100)].concat();
            fragment(30_720 * index as u64, &[sample(300 + index), sample(200)])
        }

        fn audio_segment(index: usize) -> Vec<u8> {
            let audio = |seed: u8, len: usize| -> Vec<u8> {
                (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
            };
            fragment(30_720 * index as u64, &[audio(1, 120), audio(9, 121)])
        }

        fn too_many_slices_segment() -> Vec<u8> {
            let sample = (0..41).flat_map(|_| nal(1, 120)).collect::<Vec<u8>>();
            fragment(0, &[sample])
        }

        fn pssh_v0(system_id: &[u8; 16], data: &[u8]) -> Vec<u8> {
            let mut payload = system_id.to_vec();
            payload.extend_from_slice(&(data.len() as u32).to_be_bytes());
            payload.extend_from_slice(data);
            fbx(b"pssh", 0, 0, &payload)
        }

        fn pool() -> CustodyPoolIdentityV1 {
            CustodyPoolIdentityV1::new(digest(0x41), 32).unwrap()
        }

        fn epoch() -> CustodyEpochIdentityV1 {
            CustodyEpochIdentityV1::new(digest(0x42), 32).unwrap()
        }

        fn committee() -> CustodyCommitteeAuthorizationIdentityV1 {
            CustodyCommitteeAuthorizationIdentityV1::new(digest(0x43), 32).unwrap()
        }

        fn representation(
            kind: CencDashRenditionKindV2,
            segment_count: u32,
        ) -> elastos_protected_content_provider_contracts::ProtectionRepresentationV2 {
            let (mime, codecs) = match kind {
                V => ("video/mp4", "avc1.640028"),
                A => ("audio/mp4", "mp4a.40.2"),
            };
            elastos_protected_content_provider_contracts::ProtectionRepresentationV2::new(
                kind,
                mime,
                codecs,
                segment_count,
                &init(kind),
            )
            .unwrap()
        }

        fn open_v2(
            seed: u8,
            representations: Vec<
                elastos_protected_content_provider_contracts::ProtectionRepresentationV2,
            >,
            extras: &[Vec<u8>],
        ) -> ProtectProviderRequestV1 {
            ProtectProviderRequestV1::new_open_protection_session_v2(
                digest(seed),
                ContentAccessIdV1::new(KID).unwrap(),
                pool(),
                epoch(),
                committee(),
                representations,
                extras,
                nodes(),
            )
            .unwrap()
        }

        fn send(
            provider: &mut ProtectProvider,
            request: &ProtectProviderRequestV1,
        ) -> ProtectProviderResponseV1 {
            typed_provider_response(provider.handle_frame(&wrap_request(request)).0)
        }

        struct Opened {
            handle: HandleBytes,
            inits: Vec<Vec<u8>>,
        }

        fn open(
            provider: &mut ProtectProvider,
            seed: u8,
            counts: &[(CencDashRenditionKindV2, u32)],
            extras: &[Vec<u8>],
        ) -> Opened {
            let request = open_v2(
                seed,
                counts
                    .iter()
                    .map(|(kind, count)| representation(*kind, *count))
                    .collect(),
                extras,
            );
            let opened = send(provider, &request);
            assert_eq!(
                opened.status(),
                ProtectProviderResponseStatusV1::ProtectionSessionOpened,
                "{:?}",
                opened.failure_code()
            );
            Opened {
                handle: opened.protection_session_handle().unwrap().unwrap(),
                inits: opened
                    .protected_init_segments()
                    .unwrap()
                    .into_iter()
                    .map(<[u8]>::to_vec)
                    .collect(),
            }
        }

        fn segment_request(
            handle: HandleBytes,
            rendition: u8,
            index: u32,
            clear: &[u8],
        ) -> ProtectProviderRequestV1 {
            ProtectProviderRequestV1::new_protect_media_segment_v2(handle, rendition, index, clear)
                .unwrap()
        }

        fn protect_segment(
            provider: &mut ProtectProvider,
            handle: HandleBytes,
            rendition: u8,
            index: u32,
            clear: &[u8],
        ) -> Vec<u8> {
            let response = send(provider, &segment_request(handle, rendition, index, clear));
            assert_eq!(
                response.status(),
                ProtectProviderResponseStatusV1::MediaSegmentProtected,
                "{:?}",
                response.failure_code()
            );
            assert_eq!(response.segment_index(), Some(index));
            response.protected_segment().unwrap().to_vec()
        }

        fn finalize(
            provider: &mut ProtectProvider,
            handle: HandleBytes,
        ) -> ProtectProviderResponseV1 {
            send(
                provider,
                &ProtectProviderRequestV1::new_finalize_protection_session(handle).unwrap(),
            )
        }

        fn failure_of(response: &ProtectProviderResponseV1) -> Option<ProviderFailureCodeV1> {
            response.failure_code()
        }

        struct Run {
            opened: Opened,
            protected: Vec<Vec<Vec<u8>>>,
            finalized: ProtectProviderResponseV1,
        }

        /// Opens, protects every segment of every rendition in order, finalizes.
        fn run(
            provider: &mut ProtectProvider,
            seed: u8,
            video: u32,
            audio: u32,
            extras: &[Vec<u8>],
        ) -> Run {
            let opened = open(provider, seed, &[(V, video), (A, audio)], extras);
            let mut protected = vec![Vec::new(), Vec::new()];
            for index in 0..video {
                protected[0].push(protect_segment(
                    provider,
                    opened.handle,
                    0,
                    index,
                    &video_segment(index as usize),
                ));
            }
            for index in 0..audio {
                protected[1].push(protect_segment(
                    provider,
                    opened.handle,
                    1,
                    index,
                    &audio_segment(index as usize),
                ));
            }
            let finalized = finalize(provider, opened.handle);
            Run {
                opened,
                protected,
                finalized,
            }
        }

        fn proof(
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

        fn head_and_sessions(
            run: &Run,
        ) -> (
            CencDashMediaIdentityV2,
            Vec<ValidatedCencDashRenditionSessionV2>,
        ) {
            let head = run.finalized.media_identity_v2().unwrap().unwrap();
            let sessions = run
                .opened
                .inits
                .iter()
                .enumerate()
                .map(|(index, init)| {
                    ValidatedCencDashRenditionSessionV2::new(&head, index, init).unwrap()
                })
                .collect();
            (head, sessions)
        }

        /// Every sample IV of every segment, in stream order.
        fn stream_ivs(run: &Run) -> Vec<Vec<u8>> {
            let (_, sessions) = head_and_sessions(run);
            let mut ivs = Vec::new();
            for (rendition, session) in sessions.iter().enumerate() {
                let segments = &run.protected[rendition];
                for (index, segment) in segments.iter().enumerate() {
                    let layout = session
                        .validate_proven_segment(
                            index as u32,
                            segment,
                            &proof(session.kind(), segments, index),
                        )
                        .unwrap();
                    ivs.extend(layout.samples().iter().map(|sample| sample.iv().to_vec()));
                }
            }
            ivs
        }

        fn dash_state(provider: &ProtectProvider, handle: HandleBytes) -> &MediaDashSessionStateV2 {
            let session = &provider.state.as_ref().unwrap().sessions[&handle];
            match &session.kind {
                ProtectionSessionKind::MediaDash(dash) => dash,
                _ => panic!("not a v2 media session"),
            }
        }

        #[test]
        fn p1_v2_session_produces_a_valid_bound_head() {
            let mut provider = init_provider();
            let run = run(&mut provider, 0x31, 3, 3, &[]);
            assert_eq!(
                run.finalized.status(),
                ProtectProviderResponseStatusV1::ProtectionSessionFinalized
            );
            let (head, sessions) = head_and_sessions(&run);
            assert_eq!(head.renditions().len(), 2);
            assert_eq!(head.renditions()[0].kind(), V);
            assert_eq!(head.renditions()[1].kind(), A);
            assert!(head.renditions().iter().all(|r| r.segment_count() == 3));
            let envelope = run.finalized.custody_envelope().unwrap().unwrap();
            assert_eq!(
                envelope.manifest().encrypted_content(),
                head.encrypted_content()
            );
            assert_eq!(run.finalized.media_identity().unwrap(), None);
            require_common_cenc_dash_protection_header_v2(&head, &sessions).unwrap();
            for (rendition, session) in sessions.iter().enumerate() {
                let segments = &run.protected[rendition];
                for (index, segment) in segments.iter().enumerate() {
                    session
                        .validate_proven_segment(
                            index as u32,
                            segment,
                            &proof(session.kind(), segments, index),
                        )
                        .unwrap();
                }
            }
            // The head the provider returned is the head of the protected bytes.
            let expected = CencDashMediaIdentityV2::new_from_bytes(
                ContentAccessIdV1::new(KID).unwrap(),
                &[
                    elastos_protected_content_provider_contracts::CencDashRenditionBytesV2 {
                        kind: V,
                        timescale: TIMESCALE,
                        init_segment: &run.opened.inits[0],
                        segments: &run.protected[0],
                    },
                    elastos_protected_content_provider_contracts::CencDashRenditionBytesV2 {
                        kind: A,
                        timescale: TIMESCALE,
                        init_segment: &run.opened.inits[1],
                        segments: &run.protected[1],
                    },
                ],
            )
            .unwrap();
            assert_eq!(head, expected);
            // A finalize replay returns the same response; the key is gone.
            assert_eq!(finalize(&mut provider, run.opened.handle), run.finalized);
            let state = dash_state(&provider, run.opened.handle);
            assert!(state.content_key.is_none() && state.last.is_none());
        }

        #[test]
        fn p2_one_iv_counter_serves_both_renditions_and_burned_ivs_are_not_reused() {
            let mut provider = init_provider();
            let run = run(&mut provider, 0x32, 3, 3, &[]);
            let ivs = stream_ivs(&run);
            assert_eq!(ivs.len(), 12);
            let prefix = ivs[0][..4].to_vec();
            let mut unique = BTreeSet::new();
            for (position, iv) in ivs.iter().enumerate() {
                assert_eq!(iv.len(), 8);
                assert_eq!(iv[..4], prefix[..]);
                assert_eq!(iv[4..], (position as u32).to_be_bytes());
                assert!(unique.insert(iv.clone()), "IV reused");
            }

            // A refused segment burns its IVs; the next valid one starts after them.
            let opened = open(&mut provider, 0x33, &[(V, 3)], &[]);
            let first = protect_segment(&mut provider, opened.handle, 0, 0, &video_segment(0));
            let refused = send(
                &mut provider,
                &segment_request(opened.handle, 0, 1, &too_many_slices_segment()),
            );
            assert_eq!(
                failure_of(&refused),
                Some(ProviderFailureCodeV1::InvalidRequest)
            );
            let second = protect_segment(&mut provider, opened.handle, 0, 1, &video_segment(1));
            let third = protect_segment(&mut provider, opened.handle, 0, 2, &video_segment(2));
            let finalized = finalize(&mut provider, opened.handle);
            let head = finalized.media_identity_v2().unwrap().unwrap();
            let session =
                ValidatedCencDashRenditionSessionV2::new(&head, 0, &opened.inits[0]).unwrap();
            let segments = vec![first, second, third];
            let counters: Vec<u32> = (0..3)
                .flat_map(|index| {
                    session
                        .validate_proven_segment(
                            index as u32,
                            &segments[index],
                            &proof(V, &segments, index),
                        )
                        .unwrap()
                        .samples()
                        .iter()
                        .map(|sample| u32::from_be_bytes(sample.iv()[4..].try_into().unwrap()))
                        .collect::<Vec<_>>()
                })
                .collect();
            // Segment 0 used 0 and 1; the refused one burned 2; the rest follow.
            assert_eq!(counters, vec![0, 1, 3, 4, 5, 6]);
        }

        #[test]
        fn p3_too_many_slices_carries_a_reason_and_other_refusals_do_not() {
            let mut provider = init_provider();
            let opened = open(&mut provider, 0x34, &[(V, 2)], &[]);
            let refused = send(
                &mut provider,
                &segment_request(opened.handle, 0, 0, &too_many_slices_segment()),
            );
            assert_eq!(
                failure_of(&refused),
                Some(ProviderFailureCodeV1::InvalidRequest)
            );
            assert_eq!(
                refused.failure_reason(),
                Some(ProtectFailureReasonV2::CencTooManySubsamples)
            );
            let json = String::from_utf8(refused.to_json_vec().unwrap()).unwrap();
            assert!(json.contains("\"failure_reason\":\"cenc_too_many_subsamples\""));

            // NALs that do not tile the sample: refused with no reason.
            let mut sample = nal(1, 100);
            sample.extend_from_slice(&[0, 0, 0]);
            let untiled = send(
                &mut provider,
                &segment_request(opened.handle, 0, 0, &fragment(0, &[sample])),
            );
            assert_eq!(
                failure_of(&untiled),
                Some(ProviderFailureCodeV1::InvalidRequest)
            );
            assert_eq!(untiled.failure_reason(), None);
            let json = String::from_utf8(untiled.to_json_vec().unwrap()).unwrap();
            assert!(!json.contains("failure_reason"));

            // A v1 session never reports a reason.
            let clear_init = clear_init_segment();
            let v1 = typed_ok_response(
                provider
                    .handle_frame(&wrap_request(&open_request(0x35, 1, &clear_init, nodes())))
                    .0,
            );
            let v1_handle = v1.protection_session_handle().unwrap().unwrap();
            let v1_refused = send(
                &mut provider,
                &ProtectProviderRequestV1::new_protect_media_segment(v1_handle, 0, b"junk")
                    .unwrap(),
            );
            assert_eq!(
                failure_of(&v1_refused),
                Some(ProviderFailureCodeV1::InvalidRequest)
            );
            assert_eq!(v1_refused.failure_reason(), None);
        }

        fn moov_pssh_boxes(init: &[u8]) -> Vec<Vec<u8>> {
            let mut offset = 0;
            while offset + 8 <= init.len() {
                let size =
                    u32::from_be_bytes(init[offset..offset + 4].try_into().unwrap()) as usize;
                if &init[offset + 4..offset + 8] == b"moov" {
                    let mut boxes = Vec::new();
                    let mut child = offset + 8;
                    while child + 8 <= offset + size {
                        let child_size =
                            u32::from_be_bytes(init[child..child + 4].try_into().unwrap()) as usize;
                        if &init[child + 4..child + 8] == b"pssh" {
                            boxes.push(init[child..child + child_size].to_vec());
                        }
                        child += child_size;
                    }
                    return boxes;
                }
                offset += size;
            }
            panic!("no moov");
        }

        #[test]
        fn p4_foreign_pssh_boxes_are_preserved_in_every_init_in_order() {
            let extra0 = pssh_v0(&WIDEVINE, b"widevine-data");
            let extra1 = build_pssh_v1(&PLAYREADY, &[], b"playready-data");
            let extras = vec![extra0, extra1];
            let mut provider = init_provider();
            let opened = open(&mut provider, 0x36, &[(V, 1), (A, 1)], &extras);
            let kid = ContentAccessIdV1::new(KID).unwrap();
            let elastos = PROTECTION
                .encode_custody(&CustodyProtectionHeader::new(
                    kid,
                    &pool(),
                    &epoch(),
                    &committee(),
                    CencMediaSuite::DashV2,
                ))
                .unwrap();
            let expected = vec![
                PROTECTION
                    .registry()
                    .common()
                    .encode_kid_list(kid.as_bytes())
                    .unwrap(),
                extras[0].clone(),
                extras[1].clone(),
                elastos,
            ];
            assert_eq!(opened.inits.len(), 2);
            for init in &opened.inits {
                assert_eq!(moov_pssh_boxes(init), expected);
            }

            // An extra with the Elastos system id is refused.
            let elastos_extra = PROTECTION
                .encode_custody(&CustodyProtectionHeader::new(
                    kid,
                    &pool(),
                    &epoch(),
                    &committee(),
                    CencMediaSuite::DashV2,
                ))
                .unwrap();
            let refused = send(
                &mut provider,
                &open_v2(0x37, vec![representation(V, 1)], &[elastos_extra]),
            );
            assert_eq!(
                failure_of(&refused),
                Some(ProviderFailureCodeV1::InvalidRequest)
            );
            // A malformed extra is refused too, and nothing is stored.
            let before = provider.state.as_ref().unwrap().sessions.len();
            let refused = send(
                &mut provider,
                &open_v2(
                    0x38,
                    vec![representation(V, 1)],
                    &[b"not a pssh box".to_vec()],
                ),
            );
            assert_eq!(
                failure_of(&refused),
                Some(ProviderFailureCodeV1::InvalidRequest)
            );
            assert_eq!(provider.state.as_ref().unwrap().sessions.len(), before);
        }

        #[test]
        fn p5_segment_counts_follow_the_head_rule() {
            for (video, audio) in [(3, 4), (4, 3), (3, 3)] {
                let mut provider = init_provider();
                let run = run(&mut provider, 0x39, video, audio, &[]);
                let head = run.finalized.media_identity_v2().unwrap().unwrap();
                assert_eq!(head.renditions()[0].segment_count(), video);
                assert_eq!(head.renditions()[1].segment_count(), audio);
            }

            // (3, 5) is refused at open: the contract refuses it, and a frame
            // forged past the constructor is refused by the provider.
            assert!(ProtectProviderRequestV1::new_open_protection_session_v2(
                digest(0x3a),
                ContentAccessIdV1::new(KID).unwrap(),
                pool(),
                epoch(),
                committee(),
                vec![representation(V, 3), representation(A, 5)],
                &[],
                nodes(),
            )
            .is_err());
            let mut forged = serde_json::to_value(open_v2(
                0x3a,
                vec![representation(V, 3), representation(A, 4)],
                &[],
            ))
            .unwrap();
            forged["representations"][1]["segment_count"] = json!(5);
            let mut provider = init_provider();
            let wrapped = {
                let op = "open_protection_session";
                let mut value = forged;
                value.as_object_mut().unwrap().insert(
                    "_runtime_invocation".to_string(),
                    json!({
                        "schema": "elastos.provider.invocation/v1",
                        "source": "runtime",
                        "target": "protect",
                        "op": op,
                        "capability": format!("provider:runtime->protect:{op}"),
                        "transport": "runtime-local-provider-plane",
                        "carrier": null,
                        "transfer": "json",
                        "range": null,
                        "progress": null,
                        "abi": expected_local_json_runtime_invocation_abi()
                    }),
                );
                serde_json::to_vec(&value).unwrap()
            };
            let refused = typed_provider_response(provider.handle_frame(&wrapped).0);
            assert_eq!(
                failure_of(&refused),
                Some(ProviderFailureCodeV1::InvalidRequest)
            );
            assert!(provider.state.as_ref().unwrap().sessions.is_empty());

            // Finalize before the last segment, and an index past the count.
            let opened = open(&mut provider, 0x3b, &[(V, 2), (A, 2)], &[]);
            protect_segment(&mut provider, opened.handle, 0, 0, &video_segment(0));
            assert_eq!(
                failure_of(&finalize(&mut provider, opened.handle)),
                Some(ProviderFailureCodeV1::InvalidRequest)
            );
            protect_segment(&mut provider, opened.handle, 0, 1, &video_segment(1));
            let past = send(
                &mut provider,
                &segment_request(opened.handle, 0, 2, &video_segment(2)),
            );
            assert_eq!(
                failure_of(&past),
                Some(ProviderFailureCodeV1::InvalidRequest)
            );
            // Still before the audio: finalize is refused.
            assert_eq!(
                failure_of(&finalize(&mut provider, opened.handle)),
                Some(ProviderFailureCodeV1::InvalidRequest)
            );
        }

        #[test]
        fn p6_order_and_replay() {
            let mut provider = init_provider();
            let opened = open(&mut provider, 0x3c, &[(V, 2), (A, 2)], &[]);
            // Rendition 1 before rendition 0 is done.
            let early = send(
                &mut provider,
                &segment_request(opened.handle, 1, 0, &audio_segment(0)),
            );
            assert_eq!(
                failure_of(&early),
                Some(ProviderFailureCodeV1::InvalidRequest)
            );
            // Without a rendition index.
            let plain = send(
                &mut provider,
                &ProtectProviderRequestV1::new_protect_media_segment(
                    opened.handle,
                    0,
                    &video_segment(0),
                )
                .unwrap(),
            );
            assert_eq!(
                failure_of(&plain),
                Some(ProviderFailureCodeV1::InvalidRequest)
            );

            let request0 = segment_request(opened.handle, 0, 0, &video_segment(0));
            let first = send(&mut provider, &request0);
            let counter_after_first = dash_state(&provider, opened.handle).next_iv_counter;
            // An exact retry is answered from the replay and spends no IVs.
            assert_eq!(send(&mut provider, &request0), first);
            assert_eq!(
                dash_state(&provider, opened.handle).next_iv_counter,
                counter_after_first
            );
            // The same index with other bytes.
            let other = send(
                &mut provider,
                &segment_request(opened.handle, 0, 0, &video_segment(5)),
            );
            assert_eq!(
                failure_of(&other),
                Some(ProviderFailureCodeV1::BindingMismatch)
            );
            assert_eq!(
                dash_state(&provider, opened.handle).next_iv_counter,
                counter_after_first
            );

            protect_segment(&mut provider, opened.handle, 0, 1, &video_segment(1));
            // An older index with exact bytes is no longer replayable.
            let older = send(&mut provider, &request0);
            assert_eq!(
                failure_of(&older),
                Some(ProviderFailureCodeV1::InvalidRequest)
            );

            // A v1 session refuses a rendition index.
            let clear_init = clear_init_segment();
            let v1 = typed_ok_response(
                provider
                    .handle_frame(&wrap_request(&open_request(0x3d, 1, &clear_init, nodes())))
                    .0,
            );
            let v1_handle = v1.protection_session_handle().unwrap().unwrap();
            let v1_with_rendition = send(
                &mut provider,
                &segment_request(v1_handle, 0, 0, &clear_segment(1, b"hello")),
            );
            assert_eq!(
                failure_of(&v1_with_rendition),
                Some(ProviderFailureCodeV1::InvalidRequest)
            );
            // A v2 session refuses nothing the v1 path would: cancel is shared.
            let cancelled = send(
                &mut provider,
                &ProtectProviderRequestV1::new_cancel_protection_session(opened.handle).unwrap(),
            );
            assert_eq!(
                cancelled.status(),
                ProtectProviderResponseStatusV1::ProtectionSessionCancelled
            );
        }

        #[test]
        fn p7_session_memory_does_not_grow_with_the_segment_count() {
            const SEGMENTS: u32 = 5_000;
            let mut provider = init_provider();
            let opened = open(&mut provider, 0x3e, &[(A, SEGMENTS)], &[]);
            let clear = audio_segment(0);
            let mut at_ten = 0;
            for index in 0..SEGMENTS {
                protect_segment(&mut provider, opened.handle, 0, index, &clear);
                if index == 9 {
                    at_ten = dash_state(&provider, opened.handle).held_bytes();
                }
            }
            let at_end = dash_state(&provider, opened.handle).held_bytes();
            assert!(
                at_end.abs_diff(at_ten) < MAX_PART_BYTES,
                "{at_ten} vs {at_end}"
            );
            let finalized = finalize(&mut provider, opened.handle);
            let head = finalized.media_identity_v2().unwrap().unwrap();
            assert_eq!(head.renditions()[0].segment_count(), SEGMENTS);
        }

        #[test]
        fn oversized_open_response_leaves_no_session() {
            let request = open_v2(0x60, vec![representation(V, 1), representation(A, 1)], &[]);
            let mut provider = init_provider();
            let state = provider.state.as_mut().unwrap();
            let digest = sha256(&request.to_json_vec().unwrap());
            let response =
                typed_provider_response(open_media_dash_within(state, &request, digest, 1024));
            assert_eq!(
                failure_of(&response),
                Some(ProviderFailureCodeV1::InvalidRequest)
            );
            assert!(state.sessions.is_empty());
            assert!(state.open_replays.is_empty());
            // The same open within the real limit succeeds.
            let response = typed_provider_response(open_media_dash(state, &request, digest));
            assert_eq!(
                response.status(),
                ProtectProviderResponseStatusV1::ProtectionSessionOpened
            );
            assert_eq!(state.sessions.len(), 1);
        }

        const MAX_PART_BYTES: usize =
            elastos_protected_content_provider_contracts::MAX_PROTECT_MEDIA_PART_BYTES_V1;
    }
}

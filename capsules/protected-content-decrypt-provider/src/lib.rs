use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use elastos_protected_content_contracts::{
    AuthenticatedRuntimeReleaseOperationV1, AuthenticatedRuntimeReleaseOperationV2,
    ContentAccessIdV1, DeliveryPublicKeyBytesV1, Digest32, ProtectedContentBindingV1,
    RuntimeOperationIssuerKeyV1, RuntimeReleaseAuditIdV1, ViewerPartAadV1, ViewerPartIndexV1,
};
use elastos_protected_content_custody::{
    decrypt_validated_cenc_dash_segment_to_clear_v2,
    decrypt_validated_cenc_fmp4_segment_to_clear_v1, possession_transcript_v1,
    reconstruct_content_key_for_object_session, reconstruct_content_key_for_object_session_v2,
    reconstruct_content_key_into_decrypt_session, reconstruct_content_key_into_decrypt_session_v2,
    require_common_cenc_dash_protection_header_v2, rewrite_validated_cenc_dash_init_to_clear_v2,
    rewrite_validated_cenc_fmp4_init_to_clear_v1, seal_viewer_part_v1, ContentEncryptionKeyV1,
    DecryptSessionReconstructionInputsV1, DecryptSessionReconstructionInputsV2,
    DecryptSessionSecretKeyV1, DecryptSessionWrappedContentKeyV1, PayloadChunkDecrypterV1,
    RecipientSecretKeyV1,
};
use elastos_protected_content_provider_contracts::{
    require_protection_header_matches_release, DecryptProviderRequestOpV1,
    DecryptProviderResponseV1, ProviderFailureCodeV1, ValidatedCencDashRenditionSessionV2,
    ValidatedCencFmp4MediaSessionLayoutV1, ValidatedDecryptProviderRequestV1,
    ViewerMediaPartSelectorV1, DECRYPT_PROVIDER_REQUEST_SCHEMA_V1,
    DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1, MAX_PREPARED_RECIPIENTS_V1, MAX_PROVIDER_FRAME_BYTES_V1,
    MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1, MAX_VIEWER_SESSIONS_V1, VIEWER_SESSION_ID_BYTES_V1,
};
use rand::{rngs::StdRng, SeedableRng as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

#[cfg(test)]
#[path = "../tests/support.rs"]
mod support;

#[cfg(test)]
mod pool_session_tests;

pub const PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET: &str = "protected-content-decrypt";
const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");
const INIT_ERROR_CODE: &str = "invalid_config";
const REQUEST_ERROR_CODE: &str = "invalid_request";
const BACKEND_ERROR_CODE: &str = "backend_unavailable";

type HandleBytes = [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
type AuditDigest = [u8; 32];

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
    pub fn ok(data: Value) -> Self {
        Self::Ok { data: Some(data) }
    }

    pub fn empty_ok() -> Self {
        Self::Ok { data: None }
    }

    pub fn error(code: &'static str, message: &'static str) -> Self {
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
    extra: DecryptInitExtraConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecryptInitExtraConfig {
    trusted_runtime_issuer: String,
}

#[derive(Clone)]
struct PrepareReplayEntry {
    request_digest: AuditDigest,
    response: DecryptProviderResponseV1,
    expires_at: u64,
}

#[derive(Clone)]
struct OpenReplayEntry {
    request_digest: AuditDigest,
    response: DecryptProviderResponseV1,
    expires_at: u64,
}

struct PreparedRecipientEntry {
    protected_content_binding: elastos_protected_content_contracts::ProtectedContentBindingV1,
    action: elastos_protected_content_contracts::RightsActionV1,
    recipient_secret: RecipientSecretKeyV1,
    recipient_identity: elastos_protected_content_contracts::RecipientKeyIdentityV1,
    recipient_public_key: elastos_protected_content_contracts::RecipientPublicKeyBytesV1,
    expires_at: u64,
    /// Plan B T3.1: `Some` for a V2 prepared recipient, which opens only a
    /// V2 release of this declared Runtime issuer; `None` for V1, which opens
    /// only under the trusted issuer.
    declared_runtime_issuer: Option<RuntimeOperationIssuerKeyV1>,
}

/// A viewer session decrypts either fMP4/CENC media (part-at-a-time, via the
/// wrap/unwrap possession dance already used by the media path) or a chunked
/// EPC1 object (chunk-at-a-time, via a `PayloadChunkDecrypterV1` that already
/// holds the reconstructed content key's derived AEAD state). The two are
/// mutually exclusive for the life of a session, mirroring
/// `OpenViewerSession`'s own "exactly one of media/object" contract shape.
// `media_session_layout` and the whole of `PayloadChunkDecrypterV1` are each
// boxed: without indirection on both sides, whichever one is larger makes
// clippy::large_enum_variant flag every `ViewerSessionEntry` as paying that
// footprint even for a session of the other kind.
enum ViewerSessionContent {
    Media {
        renditions: MediaRenditions,
        decrypt_session_secret: DecryptSessionSecretKeyV1,
        wrapped_content_key: DecryptSessionWrappedContentKeyV1,
        wrap_transcript: Vec<u8>,
    },
    Object(Box<PayloadChunkDecrypterV1>),
}

/// The media layout of a session: the v1 single-init layout, or the 1..=2
/// rendition sessions of a DASH v2 item, each with its protected init. Both
/// share the wrap/unwrap key flow of `ViewerSessionContent::Media`.
enum MediaRenditions {
    V1 {
        layout: Box<ValidatedCencFmp4MediaSessionLayoutV1>,
        init: Vec<u8>,
    },
    Dash(Vec<(ValidatedCencDashRenditionSessionV2, Vec<u8>)>),
}

struct ViewerSessionEntry {
    audit_request_id: RuntimeReleaseAuditIdV1,
    content: ViewerSessionContent,
    expires_at: u64,
    /// Plan B T3.1: `Some` for a V2 session, which answers only sealed reads;
    /// `None` for V1, which answers only clear reads.
    sealed: Option<SealedViewerSessionV2>,
}

/// What a V2 session seals each part to: the delivery key the wallet signed
/// (checked at open) and the release it opened.
struct SealedViewerSessionV2 {
    delivery_public_key: DeliveryPublicKeyBytesV1,
    operation_hash: Digest32,
}

/// A request the provider refuses: with a typed failure, or as an invalid
/// request.
enum Refusal {
    Typed(ProviderFailureCodeV1),
    Invalid,
}

#[derive(Clone)]
struct HandleTombstone {
    audit_request_id: RuntimeReleaseAuditIdV1,
    request_digest: AuditDigest,
    response: DecryptProviderResponseV1,
    expires_at: u64,
}

struct ConfiguredDecryptProvider {
    expected_runtime_issuer: RuntimeOperationIssuerKeyV1,
    prepared_replays: BTreeMap<AuditDigest, PrepareReplayEntry>,
    prepared_by_handle: BTreeMap<HandleBytes, PreparedRecipientEntry>,
    cancelled_prepared: BTreeMap<HandleBytes, HandleTombstone>,
    open_replays: BTreeMap<AuditDigest, OpenReplayEntry>,
    viewer_by_handle: BTreeMap<HandleBytes, ViewerSessionEntry>,
    closed_viewers: BTreeMap<HandleBytes, HandleTombstone>,
}

pub struct DecryptProvider {
    state: Option<ConfiguredDecryptProvider>,
}

impl std::fmt::Debug for DecryptProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.state {
            Some(state) => formatter
                .debug_struct("DecryptProvider")
                .field("configured", &true)
                .field("prepared_replays", &state.prepared_replays.len())
                .field("prepared_handles", &state.prepared_by_handle.len())
                .field("cancelled_prepared", &state.cancelled_prepared.len())
                .field("open_replays", &state.open_replays.len())
                .field("viewer_handles", &state.viewer_by_handle.len())
                .field("closed_viewers", &state.closed_viewers.len())
                .finish(),
            None => formatter
                .debug_struct("DecryptProvider")
                .field("configured", &false)
                .finish(),
        }
    }
}

impl DecryptProvider {
    pub fn new() -> Self {
        Self { state: None }
    }

    pub fn handle_frame_at(
        &mut self,
        frame: &[u8],
        now_unix_seconds: u64,
    ) -> (ProviderResponse, bool) {
        let mut value = match serde_json::from_slice::<Value>(frame) {
            Ok(value) => value,
            Err(_) => return (invalid_request(), false),
        };
        let envelope = match strip_runtime_invocation_envelope(
            &mut value,
            PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET,
        ) {
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
                "prepare_recipient"
                | "open_viewer_session"
                | "read_viewer_media_part"
                | "cancel_prepared_recipient"
                | "close_viewer_session"
                | "read_viewer_object_chunk"
                | "prepare_recipient_v2"
                | "open_viewer_session_v2"
                | "read_viewer_media_part_sealed"
                | "read_viewer_object_chunk_sealed",
            ) => {
                if !matches!(envelope, EnvelopeState::Present) {
                    return (invalid_request(), false);
                }
                let Ok(bytes) = serde_json::to_vec(&value) else {
                    return (invalid_request(), false);
                };
                let declared_issuer_op = matches!(
                    op.as_deref(),
                    Some(
                        "prepare_recipient_v2"
                            | "open_viewer_session_v2"
                            | "read_viewer_media_part_sealed"
                            | "read_viewer_object_chunk_sealed"
                    )
                );
                (
                    self.handle_decrypt_request(&bytes, declared_issuer_op, now_unix_seconds),
                    false,
                )
            }
            _ => (invalid_request(), false),
        }
    }

    pub fn handle_frame(&mut self, frame: &[u8]) -> (ProviderResponse, bool) {
        self.handle_frame_at(frame, now_unix_seconds())
    }

    #[cfg(test)]
    pub fn handle_line_at(&mut self, line: &str, now_unix_seconds: u64) -> ProviderResponse {
        self.handle_frame_at(line.as_bytes(), now_unix_seconds).0
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
                "decrypt provider configuration is invalid",
            ),
        }
    }

    fn status(&self) -> ProviderResponse {
        ProviderResponse::ok(json!({
            "provider": PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET,
            "version": PROVIDER_VERSION,
            "configured": self.state.is_some(),
            "supported_operations": [
                "status",
                "prepare_recipient",
                "open_viewer_session",
                "read_viewer_media_part",
                "cancel_prepared_recipient",
                "close_viewer_session",
                "read_viewer_object_chunk",
                "prepare_recipient_v2",
                "open_viewer_session_v2",
                "read_viewer_media_part_sealed",
                "read_viewer_object_chunk_sealed",
                "shutdown"
            ],
            "request_schema": DECRYPT_PROVIDER_REQUEST_SCHEMA_V1,
            "response_schema": DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1,
        }))
    }

    fn handle_decrypt_request(
        &mut self,
        bytes: &[u8],
        declared_issuer_op: bool,
        now_unix_seconds: u64,
    ) -> ProviderResponse {
        let Some(state) = self.state.as_mut() else {
            return ProviderResponse::error(
                BACKEND_ERROR_CODE,
                "decrypt provider is not configured",
            );
        };
        state.purge_expired(now_unix_seconds);
        // V1 ops validate under the trusted issuer; the V2 ops (Plan B T3.1)
        // through their own entry, under the issuer each declares.
        let validated = if declared_issuer_op {
            ValidatedDecryptProviderRequestV1::decode_and_validate_declared_at(
                bytes,
                now_unix_seconds,
            )
        } else {
            ValidatedDecryptProviderRequestV1::decode_and_validate_at(
                bytes,
                state.expected_runtime_issuer,
                now_unix_seconds,
            )
        };
        let request = match validated {
            Ok(request) => request,
            Err(_) => return invalid_request(),
        };
        if request.op().is_declared_issuer_op() != declared_issuer_op {
            return invalid_request();
        }
        let request_digest = digest32(bytes);
        match request.op() {
            DecryptProviderRequestOpV1::PrepareRecipient
            | DecryptProviderRequestOpV1::PrepareRecipientV2 => {
                let audit_key = audit_digest(request.audit_request_id());
                if let Some(replay) = state.prepared_replays.get(&audit_key) {
                    return if replay.request_digest == request_digest {
                        typed_ok(replay.response.clone())
                    } else {
                        typed_response(DecryptProviderResponseV1::new_failure(
                            request.audit_request_id(),
                            ProviderFailureCodeV1::BindingMismatch,
                        ))
                    };
                }
                if state.prepared_by_handle.len() >= MAX_PREPARED_RECIPIENTS_V1
                    || state.prepared_replays.len() >= MAX_PREPARED_RECIPIENTS_V1
                {
                    return typed_response(DecryptProviderResponseV1::new_failure(
                        request.audit_request_id(),
                        ProviderFailureCodeV1::BackendUnavailable,
                    ));
                }
                let recipient_secret = match RecipientSecretKeyV1::generate() {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(DecryptProviderResponseV1::new_failure(
                            request.audit_request_id(),
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                let recipient_public_key = match recipient_secret.public_key() {
                    Ok(value) => {
                        match elastos_protected_content_contracts::RecipientPublicKeyBytesV1::new(
                            *value.as_bytes(),
                        ) {
                            Ok(value) => value,
                            Err(_) => {
                                return typed_response(DecryptProviderResponseV1::new_failure(
                                    request.audit_request_id(),
                                    ProviderFailureCodeV1::InternalFailure,
                                ));
                            }
                        }
                    }
                    Err(_) => {
                        return typed_response(DecryptProviderResponseV1::new_failure(
                            request.audit_request_id(),
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                let recipient_identity = match recipient_secret.identity() {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(DecryptProviderResponseV1::new_failure(
                            request.audit_request_id(),
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                let handle = match next_unique_handle(
                    state.prepared_by_handle.keys(),
                    state.viewer_by_handle.keys(),
                    state.cancelled_prepared.keys(),
                    state.closed_viewers.keys(),
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(DecryptProviderResponseV1::new_failure(
                            request.audit_request_id(),
                            ProviderFailureCodeV1::BackendUnavailable,
                        ));
                    }
                };
                let response = match DecryptProviderResponseV1::new_prepared_recipient(
                    request.audit_request_id(),
                    handle,
                    recipient_public_key,
                    &recipient_identity,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(DecryptProviderResponseV1::new_failure(
                            request.audit_request_id(),
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                let entry = PreparedRecipientEntry {
                    protected_content_binding: match request.protected_content_binding() {
                        Ok(value) => value.clone(),
                        Err(_) => return invalid_request(),
                    },
                    action: match request.action() {
                        Ok(value) => value,
                        Err(_) => return invalid_request(),
                    },
                    recipient_secret,
                    recipient_identity,
                    recipient_public_key,
                    expires_at: match request.expires_at() {
                        Ok(value) => value,
                        Err(_) => return invalid_request(),
                    },
                    declared_runtime_issuer: if request.op()
                        == DecryptProviderRequestOpV1::PrepareRecipientV2
                    {
                        match request.runtime_operation_issuer() {
                            Ok(value) => Some(value),
                            Err(_) => return invalid_request(),
                        }
                    } else {
                        None
                    },
                };
                state.prepared_replays.insert(
                    audit_key,
                    PrepareReplayEntry {
                        request_digest,
                        response: response.clone(),
                        expires_at: entry.expires_at,
                    },
                );
                state.prepared_by_handle.insert(handle, entry);
                typed_ok(response)
            }
            DecryptProviderRequestOpV1::OpenViewerSession
            | DecryptProviderRequestOpV1::OpenViewerSessionV2 => {
                let audit_key = audit_digest(request.audit_request_id());
                if let Some(replay) = state.open_replays.get(&audit_key) {
                    return if replay.request_digest == request_digest {
                        typed_ok(replay.response.clone())
                    } else {
                        typed_response(DecryptProviderResponseV1::new_failure(
                            request.audit_request_id(),
                            ProviderFailureCodeV1::BindingMismatch,
                        ))
                    };
                }
                if state.viewer_by_handle.len() >= MAX_VIEWER_SESSIONS_V1
                    || state.open_replays.len() >= MAX_VIEWER_SESSIONS_V1
                {
                    return typed_response(DecryptProviderResponseV1::new_failure(
                        request.audit_request_id(),
                        ProviderFailureCodeV1::BackendUnavailable,
                    ));
                }
                let Some(prepared) = state.prepared_by_handle.get(
                    request
                        .prepared_recipient_handle()
                        .expect("validated handle"),
                ) else {
                    return typed_response(DecryptProviderResponseV1::new_failure(
                        request.audit_request_id(),
                        ProviderFailureCodeV1::HandleAbsent,
                    ));
                };
                let opened = if request.op() == DecryptProviderRequestOpV1::OpenViewerSessionV2 {
                    open_pool_session(&request, prepared, now_unix_seconds)
                } else {
                    open_v1_session(&request, prepared, now_unix_seconds)
                };
                // A refusal consumes nothing: the prepared recipient stays.
                let (content, expires_at, sealed) = match opened {
                    Ok(value) => value,
                    Err(Refusal::Typed(code)) => {
                        return typed_response(DecryptProviderResponseV1::new_failure(
                            request.audit_request_id(),
                            code,
                        ));
                    }
                    Err(Refusal::Invalid) => return invalid_request(),
                };
                // The viewer handle is the prepared handle.
                let viewer_handle = *request
                    .prepared_recipient_handle()
                    .expect("validated handle");
                let response = match DecryptProviderResponseV1::new_viewer_session_opened(
                    request.audit_request_id(),
                    viewer_handle,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(DecryptProviderResponseV1::new_failure(
                            request.audit_request_id(),
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                let entry = ViewerSessionEntry {
                    audit_request_id: request.audit_request_id(),
                    content,
                    expires_at,
                    sealed,
                };
                state.open_replays.insert(
                    audit_key,
                    OpenReplayEntry {
                        request_digest,
                        response: response.clone(),
                        expires_at: entry.expires_at,
                    },
                );
                state.viewer_by_handle.insert(viewer_handle, entry);
                state.prepared_by_handle.remove(&viewer_handle);
                typed_ok(response)
            }
            DecryptProviderRequestOpV1::ReadViewerMediaPart
            | DecryptProviderRequestOpV1::ReadViewerMediaPartSealed => {
                let handle = *request.viewer_session_handle().expect("validated handle");
                let Some(session) = state.viewer_by_handle.get(&handle) else {
                    return typed_response(DecryptProviderResponseV1::new_failure(
                        request.audit_request_id(),
                        ProviderFailureCodeV1::HandleAbsent,
                    ));
                };
                // Kind discriminant first, above every other check: an
                // object session must never fall through to media handling
                // (and vice versa in `ReadViewerObjectChunk` below) no
                // matter what the rest of this arm would otherwise do.
                let ViewerSessionContent::Media {
                    renditions,
                    decrypt_session_secret,
                    wrapped_content_key,
                    wrap_transcript,
                } = &session.content
                else {
                    return typed_response(DecryptProviderResponseV1::new_failure(
                        request.audit_request_id(),
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                // A V2 session answers only sealed reads, a V1 session only
                // clear ones.
                let sealed_read =
                    request.op() == DecryptProviderRequestOpV1::ReadViewerMediaPartSealed;
                if session.sealed.is_some() != sealed_read {
                    return typed_response(DecryptProviderResponseV1::new_failure(
                        request.audit_request_id(),
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                }
                if session.audit_request_id != request.audit_request_id() {
                    return typed_response(DecryptProviderResponseV1::new_failure(
                        request.audit_request_id(),
                        ProviderFailureCodeV1::BindingMismatch,
                    ));
                }
                let selector = request
                    .viewer_media_part_selector()
                    .expect("validated selector");
                let clear_media_part = match clear_media_part(
                    renditions,
                    decrypt_session_secret,
                    wrapped_content_key,
                    wrap_transcript,
                    selector,
                ) {
                    Ok(value) => value,
                    Err(Refusal::Typed(code)) => {
                        return typed_response(DecryptProviderResponseV1::new_failure(
                            request.audit_request_id(),
                            code,
                        ));
                    }
                    Err(Refusal::Invalid) => return invalid_request(),
                };
                match &session.sealed {
                    None => typed_response(DecryptProviderResponseV1::new_viewer_media_part(
                        request.audit_request_id(),
                        handle,
                        selector.clone(),
                        clear_media_part,
                    )),
                    Some(sealed) => {
                        let Some(part) = viewer_part_index(renditions, selector) else {
                            return typed_response(DecryptProviderResponseV1::new_failure(
                                request.audit_request_id(),
                                ProviderFailureCodeV1::InvalidRequest,
                            ));
                        };
                        sealed_part_response(
                            request.audit_request_id(),
                            handle,
                            sealed,
                            request.session_id().expect("validated session id"),
                            part,
                            &clear_media_part,
                        )
                    }
                }
            }
            DecryptProviderRequestOpV1::CancelPreparedRecipient => {
                let handle = *request
                    .prepared_recipient_handle()
                    .expect("validated handle");
                if let Some(tombstone) = state.cancelled_prepared.get(&handle) {
                    return if tombstone.audit_request_id == request.audit_request_id()
                        && tombstone.request_digest == request_digest
                    {
                        typed_ok(tombstone.response.clone())
                    } else {
                        typed_response(
                            DecryptProviderResponseV1::new_prepared_recipient_already_absent(
                                request.audit_request_id(),
                                handle,
                            ),
                        )
                    };
                }
                let Some(prepared) = state.prepared_by_handle.remove(&handle) else {
                    return typed_response(
                        DecryptProviderResponseV1::new_prepared_recipient_already_absent(
                            request.audit_request_id(),
                            handle,
                        ),
                    );
                };
                let response = match DecryptProviderResponseV1::new_cancelled_prepared_recipient(
                    request.audit_request_id(),
                    handle,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(DecryptProviderResponseV1::new_failure(
                            request.audit_request_id(),
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                state.cancelled_prepared.insert(
                    handle,
                    HandleTombstone {
                        audit_request_id: request.audit_request_id(),
                        request_digest,
                        response: response.clone(),
                        expires_at: prepared.expires_at,
                    },
                );
                typed_ok(response)
            }
            DecryptProviderRequestOpV1::CloseViewerSession => {
                let handle = *request.viewer_session_handle().expect("validated handle");
                if let Some(tombstone) = state.closed_viewers.get(&handle) {
                    return if tombstone.audit_request_id == request.audit_request_id()
                        && tombstone.request_digest == request_digest
                    {
                        typed_ok(tombstone.response.clone())
                    } else {
                        typed_response(
                            DecryptProviderResponseV1::new_viewer_session_already_absent(
                                request.audit_request_id(),
                                handle,
                            ),
                        )
                    };
                }
                let Some(session) = state.viewer_by_handle.remove(&handle) else {
                    return typed_response(
                        DecryptProviderResponseV1::new_viewer_session_already_absent(
                            request.audit_request_id(),
                            handle,
                        ),
                    );
                };
                let response = match DecryptProviderResponseV1::new_closed_viewer_session(
                    request.audit_request_id(),
                    handle,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(DecryptProviderResponseV1::new_failure(
                            request.audit_request_id(),
                            ProviderFailureCodeV1::InternalFailure,
                        ));
                    }
                };
                state.closed_viewers.insert(
                    handle,
                    HandleTombstone {
                        audit_request_id: request.audit_request_id(),
                        request_digest,
                        response: response.clone(),
                        expires_at: session.expires_at,
                    },
                );
                typed_ok(response)
            }
            DecryptProviderRequestOpV1::ReadViewerObjectChunk
            | DecryptProviderRequestOpV1::ReadViewerObjectChunkSealed => {
                let sealed_read =
                    request.op() == DecryptProviderRequestOpV1::ReadViewerObjectChunkSealed;
                let handle = if sealed_read {
                    *request.viewer_session_handle().expect("validated handle")
                } else {
                    *request.session_handle().expect("validated handle")
                };
                let Some(session) = state.viewer_by_handle.get(&handle) else {
                    return typed_response(DecryptProviderResponseV1::new_failure(
                        request.audit_request_id(),
                        ProviderFailureCodeV1::HandleAbsent,
                    ));
                };
                // Kind discriminant first, above every other check — the
                // mirror image of the guard in `ReadViewerMediaPart` above.
                let ViewerSessionContent::Object(decrypter) = &session.content else {
                    return typed_response(DecryptProviderResponseV1::new_failure(
                        request.audit_request_id(),
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                };
                if session.sealed.is_some() != sealed_read {
                    return typed_response(DecryptProviderResponseV1::new_failure(
                        request.audit_request_id(),
                        ProviderFailureCodeV1::InvalidRequest,
                    ));
                }
                if session.audit_request_id != request.audit_request_id() {
                    return typed_response(DecryptProviderResponseV1::new_failure(
                        request.audit_request_id(),
                        ProviderFailureCodeV1::BindingMismatch,
                    ));
                }
                let chunk_index = request.chunk_index().expect("validated chunk index");
                let framed_chunk = request.framed_chunk().expect("validated framed chunk");
                // `decrypt_chunk` returns `Zeroizing<Vec<u8>>` (R21); the
                // only copy taken out of that protected buffer is the single
                // `.to_vec()` below, made directly at the point the response
                // is constructed (`new_viewer_object_chunk` requires an
                // owned `Vec<u8>` and `Zeroizing` has no `into_inner`).
                let plaintext_chunk = match decrypter.decrypt_chunk(chunk_index, framed_chunk) {
                    Ok(value) => value,
                    Err(_) => {
                        return typed_response(DecryptProviderResponseV1::new_failure(
                            request.audit_request_id(),
                            ProviderFailureCodeV1::BindingMismatch,
                        ));
                    }
                };
                match &session.sealed {
                    None => typed_response(DecryptProviderResponseV1::new_viewer_object_chunk(
                        request.audit_request_id(),
                        plaintext_chunk.to_vec(),
                    )),
                    Some(sealed) => sealed_part_response(
                        request.audit_request_id(),
                        handle,
                        sealed,
                        request.session_id().expect("validated session id"),
                        ViewerPartIndexV1::ObjectChunk(chunk_index),
                        &plaintext_chunk,
                    ),
                }
            }
        }
    }
}

impl Default for DecryptProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfiguredDecryptProvider {
    fn purge_expired(&mut self, now_unix_seconds: u64) {
        self.prepared_replays
            .retain(|_, entry| entry.expires_at > now_unix_seconds);
        self.prepared_by_handle
            .retain(|_, entry| entry.expires_at > now_unix_seconds);
        self.cancelled_prepared
            .retain(|_, entry| entry.expires_at > now_unix_seconds);
        self.open_replays
            .retain(|_, entry| entry.expires_at > now_unix_seconds);
        self.viewer_by_handle
            .retain(|_, entry| entry.expires_at > now_unix_seconds);
        self.closed_viewers
            .retain(|_, entry| entry.expires_at > now_unix_seconds);
    }
}

fn load_provider_state(config: Value) -> Result<ConfiguredDecryptProvider, ()> {
    let init: InitConfig = serde_json::from_value(config).map_err(|_| ())?;
    if !init.base_path.is_empty()
        || !init.allowed_paths.is_empty()
        || init.read_only
        || !init.encryption_key.is_empty()
    {
        return Err(());
    }
    let expected_runtime_issuer = parse_runtime_issuer_hex(&init.extra.trusted_runtime_issuer)?;
    Ok(ConfiguredDecryptProvider {
        expected_runtime_issuer,
        prepared_replays: BTreeMap::new(),
        prepared_by_handle: BTreeMap::new(),
        cancelled_prepared: BTreeMap::new(),
        open_replays: BTreeMap::new(),
        viewer_by_handle: BTreeMap::new(),
        closed_viewers: BTreeMap::new(),
    })
}

fn parse_runtime_issuer_hex(value: &str) -> Result<RuntimeOperationIssuerKeyV1, ()> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    if stripped.len() != 64 {
        return Err(());
    }
    let mut bytes = [0u8; 32];
    for (index, chunk) in stripped.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| ())?;
        bytes[index] = u8::from_str_radix(text, 16).map_err(|_| ())?;
    }
    RuntimeOperationIssuerKeyV1::new(bytes).map_err(|_| ())
}

/// What an accepted open stores: the session content, its expiry and, for a
/// V2 session, what its parts are sealed to.
type OpenedSession = (ViewerSessionContent, u64, Option<SealedViewerSessionV2>);

/// A V1 open: the release under the trusted issuer, for this V1 prepared
/// recipient. The session lives to the operation's expiry.
fn open_v1_session(
    request: &ValidatedDecryptProviderRequestV1,
    prepared: &PreparedRecipientEntry,
    now_unix_seconds: u64,
) -> Result<OpenedSession, Refusal> {
    let operation = request
        .authenticated_runtime_release_operation()
        .map_err(|_| Refusal::Invalid)?;
    // A V2 prepared recipient opens only a V2 release.
    if prepared.declared_runtime_issuer.is_some() {
        return Err(Refusal::Typed(ProviderFailureCodeV1::InvalidRequest));
    }
    if &prepared.protected_content_binding != operation.binding()
        || prepared.action != operation.action()
        || &prepared.recipient_identity != operation.recipient()
        || prepared.recipient_public_key != operation.statement().recipient_public_key()
    {
        return Err(Refusal::Typed(ProviderFailureCodeV1::BindingMismatch));
    }
    let content = open_session_content(
        request,
        operation.binding(),
        operation.statement().policy_body().content_access_id(),
        || {
            // Same authenticated-operation handling as the media path
            // (node-contribution + terminal-receipt verification,
            // possession check, commitment check), just without the
            // decrypt-session wrap.
            reconstruct_content_key_for_object_session(
                operation,
                request
                    .content_key_commitment()
                    .expect("validated content key commitment"),
                request
                    .signed_node_contributions()
                    .expect("validated contributions"),
                request
                    .signed_terminal_receipt()
                    .expect("validated terminal receipt"),
                request
                    .expected_terminal_issuer()
                    .expect("validated terminal issuer"),
                &prepared.recipient_secret,
                now_unix_seconds,
            )
            .map_err(|_| ProviderFailureCodeV1::BindingMismatch)
        },
        || reconstruct_media_decrypt_session(request, operation, prepared, now_unix_seconds),
    )?;
    Ok((content, operation.statement().expires_at(), None))
}

/// Plan B T3.1: a V2 open. The validated request has verified the operation
/// under its declared issuer (the descriptor by the release rule, F1), bound
/// the content identity to the release (F4), and verified every contribution
/// and the receipt under that issuer. Before any key work, this prepared
/// recipient must be the one the release names, under the issuer, binding and
/// action it was prepared for, and the delivery key must be the one the
/// wallet signed (F3). The session lives to the signed rights expiry, capped
/// by the attestations (user 2026-11-13 04:45), and seals every part to
/// that delivery key.
fn open_pool_session(
    request: &ValidatedDecryptProviderRequestV1,
    prepared: &PreparedRecipientEntry,
    now_unix_seconds: u64,
) -> Result<OpenedSession, Refusal> {
    let operation = request
        .authenticated_runtime_release_operation_v2()
        .map_err(|_| Refusal::Invalid)?;
    // A V1 prepared recipient opens only a V1 release.
    let Some(declared_runtime_issuer) = prepared.declared_runtime_issuer else {
        return Err(Refusal::Typed(ProviderFailureCodeV1::InvalidRequest));
    };
    let names_this_recipient = operation
        .recipients()
        .iter()
        .any(|recipient| recipient.public_key() == prepared.recipient_public_key)
        && operation
            .statement()
            .rights_request()
            .request()
            .recipients()
            .contains(&prepared.recipient_identity);
    let contribution_recipient = request
        .contribution_recipient()
        .map_err(|_| Refusal::Invalid)?;
    if declared_runtime_issuer != operation.runtime_operation_issuer()
        || &prepared.protected_content_binding != operation.binding()
        || prepared.action != operation.action()
        || !names_this_recipient
        || contribution_recipient != &prepared.recipient_identity
    {
        return Err(Refusal::Typed(ProviderFailureCodeV1::BindingMismatch));
    }
    let delivery_public_key = *request
        .delivery_public_key()
        .map_err(|_| Refusal::Invalid)?;
    if delivery_public_key.identity() != operation.delivery_key() {
        return Err(Refusal::Typed(ProviderFailureCodeV1::BindingMismatch));
    }
    let content = open_session_content(
        request,
        operation.binding(),
        operation.statement().policy_body().content_access_id(),
        || {
            reconstruct_content_key_for_object_session_v2(
                operation,
                request
                    .content_key_commitment()
                    .expect("validated content key commitment"),
                request
                    .signed_node_contributions()
                    .expect("validated contributions"),
                request
                    .signed_terminal_receipt()
                    .expect("validated terminal receipt"),
                request
                    .expected_terminal_issuer()
                    .expect("validated terminal issuer"),
                &prepared.recipient_secret,
                now_unix_seconds,
            )
            .map_err(|_| ProviderFailureCodeV1::BindingMismatch)
        },
        || reconstruct_media_decrypt_session_v2(request, operation, prepared, now_unix_seconds),
    )?;
    Ok((
        content,
        // The open needed fresh proofs; the session keeps its key to the
        // rights expiry, capped by the attestations (user 2026-11-13 04:45).
        operation.session_expires_at(),
        Some(SealedViewerSessionV2 {
            delivery_public_key,
            operation_hash: operation.operation_hash(),
        }),
    ))
}

/// The session content of an open after its release checks. `object_key` and
/// `media_session` reconstruct the content key; the reconstruction verifies
/// the content-key commitment before any wrap or read.
///
/// Plan B T3.5: before any key work, an item's Elastos header must name the
/// release (`binding`'s key envelope committee and the policy's
/// `content_access_id`). DASH v2 always carries one, and V1 media is checked
/// against the one its init carries. Objects carry none.
fn open_session_content(
    request: &ValidatedDecryptProviderRequestV1,
    binding: &ProtectedContentBindingV1,
    content_access_id: ContentAccessIdV1,
    object_key: impl FnOnce() -> Result<ContentEncryptionKeyV1, ProviderFailureCodeV1>,
    media_session: impl FnOnce() -> Result<
        (
            DecryptSessionSecretKeyV1,
            DecryptSessionWrappedContentKeyV1,
            Vec<u8>,
        ),
        ProviderFailureCodeV1,
    >,
) -> Result<ViewerSessionContent, Refusal> {
    // Content-kind branch. The open's "exactly one of media/object"
    // validation already guarantees `object_identity()` is Ok(..) iff this is
    // an object session.
    if request.object_identity().is_ok() {
        let framed_header = request.framed_header().expect("validated framed header");
        let content_key = object_key().map_err(Refusal::Typed)?;
        // `PayloadChunkDecrypterV1::new` performs its own header commitment
        // check against `content_key`; not duplicated or weakened here. It
        // derives its own AEAD state once and keeps only that.
        let decrypter = PayloadChunkDecrypterV1::new(framed_header, &content_key)
            .map_err(|_| Refusal::Typed(ProviderFailureCodeV1::BindingMismatch))?;
        return Ok(ViewerSessionContent::Object(Box::new(decrypter)));
    }
    // A v2 open is routed here, before the v1 layout below, which would
    // panic on a request without a v1 layout.
    let dash_sessions = request.media_dash_sessions().ok();
    if let Some(sessions) = dash_sessions {
        // Before any key work: every rendition init must carry the one
        // Elastos header of the whole item. A mismatch consumes nothing, so
        // the prepared recipient stays.
        let head = request
            .media_identity_v2()
            .expect("validated dash media identity");
        let Ok(header) = require_common_cenc_dash_protection_header_v2(head, sessions) else {
            return Err(Refusal::Typed(ProviderFailureCodeV1::BindingMismatch));
        };
        require_protection_header_matches_release(header, binding, content_access_id)
            .map_err(Refusal::Typed)?;
    } else if let Some(header) = request
        .media_session_layout()
        .expect("validated media layout")
        .protection_header()
    {
        require_protection_header_matches_release(header, binding, content_access_id)
            .map_err(Refusal::Typed)?;
    }
    let (decrypt_session_secret, wrapped_content_key, wrap_transcript) =
        media_session().map_err(Refusal::Typed)?;
    let renditions = match dash_sessions {
        Some(sessions) => MediaRenditions::Dash(
            sessions
                .iter()
                .cloned()
                .zip(
                    request
                        .protected_init_segments()
                        .expect("validated dash inits")
                        .into_iter()
                        .map(<[u8]>::to_vec),
                )
                .collect(),
        ),
        None => MediaRenditions::V1 {
            layout: Box::new(
                request
                    .media_session_layout()
                    .expect("validated media layout")
                    .clone(),
            ),
            init: request
                .protected_init_segment()
                .expect("validated init")
                .to_vec(),
        },
    };
    Ok(ViewerSessionContent::Media {
        renditions,
        decrypt_session_secret,
        wrapped_content_key,
        wrap_transcript,
    })
}

/// The clear bytes of one media part, from either media layout. For DASH the
/// proof is verified against the rendition's root before the key is
/// unwrapped or any byte is decrypted.
fn clear_media_part(
    renditions: &MediaRenditions,
    decrypt_session_secret: &DecryptSessionSecretKeyV1,
    wrapped_content_key: &DecryptSessionWrappedContentKeyV1,
    wrap_transcript: &[u8],
    selector: &ViewerMediaPartSelectorV1,
) -> Result<Vec<u8>, Refusal> {
    match renditions {
        MediaRenditions::V1 { layout, init } => {
            if selector.rendition_index().is_some() || selector.segment_proof().is_some() {
                return Err(Refusal::Typed(ProviderFailureCodeV1::InvalidRequest));
            }
            let result = if selector.is_init() {
                rewrite_validated_cenc_fmp4_init_to_clear_v1(layout, init)
            } else {
                let Some(segment_index) = selector.segment_index() else {
                    return Err(Refusal::Invalid);
                };
                let Some(encrypted_segment) = selector.encrypted_segment() else {
                    return Err(Refusal::Invalid);
                };
                decrypt_validated_cenc_fmp4_segment_to_clear_v1(
                    layout,
                    encrypted_segment,
                    segment_index,
                    decrypt_session_secret,
                    wrapped_content_key,
                    wrap_transcript,
                )
            };
            result.map_err(|_| Refusal::Typed(ProviderFailureCodeV1::BindingMismatch))
        }
        MediaRenditions::Dash(renditions) => {
            let Some(rendition_index) = selector.rendition_index() else {
                return Err(Refusal::Typed(ProviderFailureCodeV1::InvalidRequest));
            };
            let Some((session, init)) = renditions.get(usize::from(rendition_index)) else {
                return Err(Refusal::Typed(ProviderFailureCodeV1::BindingMismatch));
            };
            let result = if selector.is_init() {
                rewrite_validated_cenc_dash_init_to_clear_v2(session, init)
            } else {
                let (Some(segment_index), Some(encrypted_segment), Some(proof)) = (
                    selector.segment_index(),
                    selector.encrypted_segment(),
                    selector.segment_proof(),
                ) else {
                    return Err(Refusal::Typed(ProviderFailureCodeV1::InvalidRequest));
                };
                // The proof is verified against the rendition's root before
                // the key is unwrapped or any byte is decrypted.
                decrypt_validated_cenc_dash_segment_to_clear_v2(
                    session,
                    encrypted_segment,
                    segment_index,
                    &proof,
                    decrypt_session_secret,
                    wrapped_content_key,
                    wrap_transcript,
                )
            };
            result.map_err(|_| Refusal::Typed(ProviderFailureCodeV1::BindingMismatch))
        }
    }
}

/// The part a media selector names, in the sealed AAD.
fn viewer_part_index(
    renditions: &MediaRenditions,
    selector: &ViewerMediaPartSelectorV1,
) -> Option<ViewerPartIndexV1> {
    match renditions {
        MediaRenditions::V1 { .. } => Some(if selector.is_init() {
            ViewerPartIndexV1::MediaV1Init
        } else {
            ViewerPartIndexV1::MediaV1Segment(selector.segment_index()?)
        }),
        MediaRenditions::Dash(_) => {
            let rendition = selector.rendition_index()?;
            Some(if selector.is_init() {
                ViewerPartIndexV1::DashInit { rendition }
            } else {
                ViewerPartIndexV1::DashSegment {
                    rendition,
                    index: selector.segment_index()?,
                }
            })
        }
    }
}

/// One clear part sealed to the session's delivery key, under the AAD of the
/// pool session, the release and the part.
fn sealed_part_response(
    audit_request_id: RuntimeReleaseAuditIdV1,
    handle: HandleBytes,
    sealed: &SealedViewerSessionV2,
    session_id: [u8; VIEWER_SESSION_ID_BYTES_V1],
    part: ViewerPartIndexV1,
    clear_part: &[u8],
) -> ProviderResponse {
    let aad = ViewerPartAadV1 {
        session_id,
        operation_hash: sealed.operation_hash,
        part,
    };
    match seal_viewer_part_v1(&sealed.delivery_public_key, &aad, clear_part) {
        Ok(sealed_part) => typed_response(DecryptProviderResponseV1::new_viewer_sealed_part(
            audit_request_id,
            handle,
            sealed_part,
        )),
        Err(_) => typed_response(DecryptProviderResponseV1::new_failure(
            audit_request_id,
            ProviderFailureCodeV1::InternalFailure,
        )),
    }
}

/// A fresh decrypt session key and the RNG the reconstruction wraps with.
fn fresh_decrypt_session() -> Result<
    (
        DecryptSessionSecretKeyV1,
        elastos_protected_content_custody::DecryptSessionPublicKeyV1,
        StdRng,
    ),
    ProviderFailureCodeV1,
> {
    let session_seed =
        random_nonzero_bytes().map_err(|_| ProviderFailureCodeV1::InternalFailure)?;
    let reconstruction_rng_seed =
        random_nonzero_bytes().map_err(|_| ProviderFailureCodeV1::InternalFailure)?;
    let decrypt_session_secret = DecryptSessionSecretKeyV1::from_seed(session_seed)
        .map_err(|_| ProviderFailureCodeV1::InternalFailure)?;
    let decrypt_session_public = decrypt_session_secret
        .public_key()
        .map_err(|_| ProviderFailureCodeV1::InternalFailure)?;
    Ok((
        decrypt_session_secret,
        decrypt_session_public,
        StdRng::from_seed(reconstruction_rng_seed),
    ))
}

/// The decrypt-session reconstruction both media layouts share: a fresh session
/// key, the content key reconstructed and wrapped to it, and the possession
/// transcript the wrap is bound to. The error is the typed failure to answer.
fn reconstruct_media_decrypt_session(
    request: &ValidatedDecryptProviderRequestV1,
    operation: &AuthenticatedRuntimeReleaseOperationV1,
    prepared: &PreparedRecipientEntry,
    now_unix_seconds: u64,
) -> Result<
    (
        DecryptSessionSecretKeyV1,
        DecryptSessionWrappedContentKeyV1,
        Vec<u8>,
    ),
    ProviderFailureCodeV1,
> {
    let (decrypt_session_secret, decrypt_session_public, mut reconstruction_rng) =
        fresh_decrypt_session()?;
    let wrapped_content_key = reconstruct_content_key_into_decrypt_session(
        &DecryptSessionReconstructionInputsV1 {
            operation,
            content_key_commitment: request
                .content_key_commitment()
                .expect("validated content key commitment"),
            contributions: request
                .signed_node_contributions()
                .expect("validated contributions"),
            terminal_receipt: request
                .signed_terminal_receipt()
                .expect("validated terminal receipt"),
            expected_terminal_issuer: request
                .expected_terminal_issuer()
                .expect("validated terminal issuer"),
            recipient_secret: &prepared.recipient_secret,
            decrypt_session_public: &decrypt_session_public,
            now: now_unix_seconds,
        },
        &mut reconstruction_rng,
    )
    .map_err(|_| ProviderFailureCodeV1::BindingMismatch)?;
    let mut wrap_transcript = possession_transcript_v1(
        operation.binding().profile(),
        operation.binding().runtime_session_binding(),
        operation.recipient(),
        operation.release_request_hash(),
    )
    .map_err(|_| ProviderFailureCodeV1::InternalFailure)?;
    wrap_transcript.extend_from_slice(decrypt_session_public.as_bytes());
    Ok((decrypt_session_secret, wrapped_content_key, wrap_transcript))
}

/// Plan B T3.1: [`reconstruct_media_decrypt_session`] for a V2 release. The
/// transcript names this prepared recipient and the operation hash (L1), as
/// the custody crate's V2 wrap does.
fn reconstruct_media_decrypt_session_v2(
    request: &ValidatedDecryptProviderRequestV1,
    operation: &AuthenticatedRuntimeReleaseOperationV2,
    prepared: &PreparedRecipientEntry,
    now_unix_seconds: u64,
) -> Result<
    (
        DecryptSessionSecretKeyV1,
        DecryptSessionWrappedContentKeyV1,
        Vec<u8>,
    ),
    ProviderFailureCodeV1,
> {
    let (decrypt_session_secret, decrypt_session_public, mut reconstruction_rng) =
        fresh_decrypt_session()?;
    let wrapped_content_key = reconstruct_content_key_into_decrypt_session_v2(
        &DecryptSessionReconstructionInputsV2 {
            operation,
            content_key_commitment: request
                .content_key_commitment()
                .expect("validated content key commitment"),
            contributions: request
                .signed_node_contributions()
                .expect("validated contributions"),
            terminal_receipt: request
                .signed_terminal_receipt()
                .expect("validated terminal receipt"),
            expected_terminal_issuer: request
                .expected_terminal_issuer()
                .expect("validated terminal issuer"),
            recipient_secret: &prepared.recipient_secret,
            decrypt_session_public: &decrypt_session_public,
            now: now_unix_seconds,
        },
        &mut reconstruction_rng,
    )
    .map_err(|_| ProviderFailureCodeV1::BindingMismatch)?;
    let mut wrap_transcript = possession_transcript_v1(
        operation.binding().profile(),
        operation.binding().runtime_session_binding(),
        &prepared.recipient_identity,
        operation.operation_hash(),
    )
    .map_err(|_| ProviderFailureCodeV1::InternalFailure)?;
    wrap_transcript.extend_from_slice(decrypt_session_public.as_bytes());
    Ok((decrypt_session_secret, wrapped_content_key, wrap_transcript))
}

fn digest32(bytes: &[u8]) -> AuditDigest {
    Sha256::digest(bytes).into()
}

fn audit_digest(audit_request_id: RuntimeReleaseAuditIdV1) -> AuditDigest {
    *audit_request_id.digest().as_bytes()
}

fn random_nonzero_bytes() -> Result<[u8; 32], ()> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| ())?;
    if bytes == [0u8; 32] {
        return Err(());
    }
    Ok(bytes)
}

fn next_unique_handle<'a>(
    prepared_handles: impl Iterator<Item = &'a HandleBytes>,
    viewer_handles: impl Iterator<Item = &'a HandleBytes>,
    cancelled_handles: impl Iterator<Item = &'a HandleBytes>,
    closed_handles: impl Iterator<Item = &'a HandleBytes>,
) -> Result<HandleBytes, ()> {
    let mut occupied = BTreeMap::new();
    for handle in prepared_handles {
        occupied.insert(*handle, ());
    }
    for handle in viewer_handles {
        occupied.insert(*handle, ());
    }
    for handle in cancelled_handles {
        occupied.insert(*handle, ());
    }
    for handle in closed_handles {
        occupied.insert(*handle, ());
    }
    for _ in 0..32 {
        let candidate = random_nonzero_bytes()?;
        if !occupied.contains_key(&candidate) {
            return Ok(candidate);
        }
    }
    Err(())
}

fn typed_response(
    result: Result<DecryptProviderResponseV1, impl std::fmt::Debug>,
) -> ProviderResponse {
    let Ok(response) = result else {
        return ProviderResponse::error(BACKEND_ERROR_CODE, "decrypt provider response failed");
    };
    let Ok(bytes) = response.to_json_vec() else {
        return ProviderResponse::error(BACKEND_ERROR_CODE, "decrypt provider response failed");
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => ProviderResponse::ok(value),
        Err(_) => ProviderResponse::error(BACKEND_ERROR_CODE, "decrypt provider response failed"),
    }
}

fn typed_ok(response: DecryptProviderResponseV1) -> ProviderResponse {
    let Ok(bytes) = response.to_json_vec() else {
        return ProviderResponse::error(BACKEND_ERROR_CODE, "decrypt provider response failed");
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => ProviderResponse::ok(value),
        Err(_) => ProviderResponse::error(BACKEND_ERROR_CODE, "decrypt provider response failed"),
    }
}

fn invalid_request() -> ProviderResponse {
    ProviderResponse::error(REQUEST_ERROR_CODE, "decrypt provider request is invalid")
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum EnvelopeState {
    Absent,
    Present,
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
    provider: &mut DecryptProvider,
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
    let mut provider = DecryptProvider::new();
    run_provider_loop(&mut input, &mut stdout, &mut provider);
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use elastos_protected_content_contracts::{
        Digest32, ProtectedContentBindingV1, RightsActionV1, RuntimeReleaseAuditIdV1,
        SignedNodeContributionV1, SignedRuntimeReleaseOperationV1, SignedTerminalReceiptV1,
        TerminalReceiptIssuerKey,
    };
    use elastos_protected_content_provider_contracts::{
        CencFmp4MediaIdentityV1, DecryptProviderRequestV1, DecryptProviderResponseStatusV1,
        ProviderFailureCodeV1, ViewerMediaPartSelectorV1,
    };

    use super::support::{
        binding_for_envelope, custody_envelope_for_media, digest, make_signed_node_contribution,
        make_signed_runtime_release_operation, make_signed_terminal_receipt, media_components,
        runtime_issuer, runtime_signing_key, wallet, MEDIA_CODECS_V1, MEDIA_MIME_TYPE_V1,
    };

    const NOW: u64 = 2_000_000_000;

    fn init_config(runtime_seed: u8) -> Value {
        json!({
            "base_path": "",
            "allowed_paths": [],
            "read_only": false,
            "encryption_key": "",
            "extra": {
                "trusted_runtime_issuer": format!(
                    "0x{}",
                    hex::encode(runtime_signing_key(runtime_seed).verifying_key().to_bytes())
                )
            }
        })
    }

    fn wrap_request(value: Value) -> String {
        let mut value = value;
        let op = value.get("op").and_then(Value::as_str).unwrap().to_string();
        value.as_object_mut().unwrap().insert(
            "_runtime_invocation".to_string(),
            json!({
                "schema": "elastos.provider.invocation/v1",
                "source": "runtime",
                "target": PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET,
                "op": op,
                "capability": format!(
                    "provider:runtime->{PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET}:{op}"
                ),
                "transport": "runtime-local-provider-plane",
                "carrier": null,
                "transfer": "json",
                "range": null,
                "progress": null,
                "abi": expected_local_json_runtime_invocation_abi()
            }),
        );
        serde_json::to_string(&value).unwrap()
    }

    fn request_json(request: &DecryptProviderRequestV1) -> Value {
        serde_json::to_value(request).unwrap()
    }

    fn typed_response(response: ProviderResponse) -> DecryptProviderResponseV1 {
        match response {
            ProviderResponse::Ok { data: Some(data) } => {
                DecryptProviderResponseV1::from_json_slice(&serde_json::to_vec(&data).unwrap())
                    .unwrap()
            }
            other => panic!(
                "expected typed ok response, got {:?}",
                serde_json::to_value(&other).unwrap()
            ),
        }
    }

    fn response_error_code(response: &ProviderResponse) -> Option<&'static str> {
        match response {
            ProviderResponse::Error { code, .. } => Some(*code),
            _ => None,
        }
    }

    fn prepare_request(
        binding: &ProtectedContentBindingV1,
        audit_request_id: RuntimeReleaseAuditIdV1,
        runtime_seed: u8,
    ) -> DecryptProviderRequestV1 {
        DecryptProviderRequestV1::new_prepare_recipient(
            binding,
            audit_request_id,
            RightsActionV1::View,
            runtime_issuer(runtime_seed),
            NOW,
            NOW + 30,
        )
        .unwrap()
    }

    struct OpenRequestInputs<'a> {
        prepared_handle: HandleBytes,
        operation: &'a SignedRuntimeReleaseOperationV1,
        content_key_commitment: Digest32,
        media_identity: &'a CencFmp4MediaIdentityV1,
        init_segment: &'a [u8],
        contributions: &'a [SignedNodeContributionV1],
        terminal_receipt: &'a SignedTerminalReceiptV1,
        issuer_seed: u8,
    }

    fn open_request(inputs: OpenRequestInputs<'_>) -> DecryptProviderRequestV1 {
        DecryptProviderRequestV1::new_open_viewer_session(
            inputs.prepared_handle,
            inputs.operation,
            TerminalReceiptIssuerKey::new(
                SigningKey::from_bytes(&[inputs.issuer_seed; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap(),
            inputs.content_key_commitment,
            inputs.media_identity,
            inputs.init_segment,
            inputs.contributions,
            inputs.terminal_receipt,
        )
        .unwrap()
    }

    fn read_request(
        audit_request_id: RuntimeReleaseAuditIdV1,
        viewer_handle: HandleBytes,
        selector: ViewerMediaPartSelectorV1,
    ) -> DecryptProviderRequestV1 {
        DecryptProviderRequestV1::new_read_viewer_media_part(
            audit_request_id,
            viewer_handle,
            selector,
        )
        .unwrap()
    }

    fn cancel_request(
        audit_request_id: RuntimeReleaseAuditIdV1,
        prepared_handle: HandleBytes,
    ) -> DecryptProviderRequestV1 {
        DecryptProviderRequestV1::new_cancel_prepared_recipient(audit_request_id, prepared_handle)
            .unwrap()
    }

    fn close_request(
        audit_request_id: RuntimeReleaseAuditIdV1,
        viewer_handle: HandleBytes,
    ) -> DecryptProviderRequestV1 {
        DecryptProviderRequestV1::new_close_viewer_session(audit_request_id, viewer_handle).unwrap()
    }

    #[test]
    fn prepare_open_read_and_close_flow_is_exact_and_redacted() {
        let runtime_seed = 0x42;
        let media_seed = 0x21;
        let envelope = custody_envelope_for_media(media_seed, NOW);
        let binding = binding_for_envelope(&envelope);
        let (init_segment, encrypted_segments, _, _) = media_components(media_seed);
        let media_identity = CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &encrypted_segments,
            MEDIA_MIME_TYPE_V1,
            MEDIA_CODECS_V1,
        )
        .unwrap();
        let prepare_audit = RuntimeReleaseAuditIdV1::new(digest(0xa1)).unwrap();
        let mut provider = DecryptProvider::new();
        assert!(matches!(
            provider.init(init_config(runtime_seed)),
            ProviderResponse::Ok { .. }
        ));

        let prepare = prepare_request(&binding, prepare_audit, runtime_seed);
        let prepared =
            typed_response(provider.handle_line_at(&wrap_request(request_json(&prepare)), NOW + 1));
        assert_eq!(
            prepared.status(),
            DecryptProviderResponseStatusV1::PreparedRecipient
        );

        let open_audit = RuntimeReleaseAuditIdV1::new(digest(0xa2)).unwrap();
        let operation = make_signed_runtime_release_operation(
            runtime_seed,
            open_audit,
            &envelope,
            prepared.recipient_public_key().unwrap(),
            prepared.recipient_identity().unwrap(),
            NOW,
        );
        let contributions = vec![
            make_signed_node_contribution(&operation, &envelope, runtime_seed, 1, NOW),
            make_signed_node_contribution(&operation, &envelope, runtime_seed, 2, NOW),
        ];
        let terminal = make_signed_terminal_receipt(&operation, &contributions, 0x61, NOW);
        let wrong_commitment_open = open_request(OpenRequestInputs {
            prepared_handle: *prepared.prepared_recipient_handle().unwrap(),
            operation: &operation,
            content_key_commitment: Digest32::new([0xee; 32]),
            media_identity: &media_identity,
            init_segment: &init_segment,
            contributions: &contributions,
            terminal_receipt: &terminal,
            issuer_seed: 0x61,
        });
        let wrong_commitment = typed_response(
            provider.handle_line_at(&wrap_request(request_json(&wrong_commitment_open)), NOW + 7),
        );
        assert_eq!(
            wrong_commitment.failure_code().unwrap(),
            ProviderFailureCodeV1::BindingMismatch
        );
        let open = open_request(OpenRequestInputs {
            prepared_handle: *prepared.prepared_recipient_handle().unwrap(),
            operation: &operation,
            content_key_commitment: envelope.manifest().content_key_commitment(),
            media_identity: &media_identity,
            init_segment: &init_segment,
            contributions: &contributions,
            terminal_receipt: &terminal,
            issuer_seed: 0x61,
        });
        let opened =
            typed_response(provider.handle_line_at(&wrap_request(request_json(&open)), NOW + 7));
        assert_eq!(
            opened.status(),
            DecryptProviderResponseStatusV1::ViewerSessionOpened
        );
        assert_eq!(
            opened.viewer_session_handle().unwrap(),
            prepared.prepared_recipient_handle().unwrap()
        );

        let read_init = read_request(
            open_audit,
            *opened.viewer_session_handle().unwrap(),
            ViewerMediaPartSelectorV1::init(),
        );
        let clear_init = typed_response(
            provider.handle_line_at(&wrap_request(request_json(&read_init)), NOW + 8),
        );
        assert_eq!(
            clear_init.status(),
            DecryptProviderResponseStatusV1::ViewerMediaPart
        );
        assert!(clear_init
            .clear_media_part()
            .unwrap()
            .windows(4)
            .any(|w| w == b"avc1"));
        assert!(!clear_init
            .clear_media_part()
            .unwrap()
            .windows(4)
            .any(|w| w == b"sinf"));

        let selector =
            ViewerMediaPartSelectorV1::segment(1, encrypted_segments[1].clone()).unwrap();
        let read_segment = read_request(
            open_audit,
            *opened.viewer_session_handle().unwrap(),
            selector.clone(),
        );
        let clear_segment = typed_response(
            provider.handle_line_at(&wrap_request(request_json(&read_segment)), NOW + 8),
        );
        assert_eq!(
            clear_segment.status(),
            DecryptProviderResponseStatusV1::ViewerMediaPart
        );
        assert_eq!(
            clear_segment.viewer_media_part_selector().unwrap(),
            &selector
        );
        assert_ne!(
            clear_segment.clear_media_part().unwrap(),
            encrypted_segments[1].as_slice()
        );
        assert_eq!(encrypted_segments[1], media_components(media_seed).1[1]);

        let closed = typed_response(provider.handle_line_at(
            &wrap_request(request_json(&close_request(
                open_audit,
                *opened.viewer_session_handle().unwrap(),
            ))),
            NOW + 9,
        ));
        assert_eq!(
            closed.status(),
            DecryptProviderResponseStatusV1::ClosedViewerSession
        );

        let debug = format!("{provider:?}");
        assert!(debug.contains("configured"));
        assert!(!debug.contains("carrier"));
        assert!(!debug.contains("segx"));
    }

    #[test]
    fn init_rejects_old_raw_shape_and_unknown_generic_fields() {
        let runtime_seed = 0x42;
        let mut provider = DecryptProvider::new();

        assert_eq!(
            response_error_code(&provider.init(json!({
                "trusted_runtime_issuer": format!(
                    "0x{}",
                    hex::encode(runtime_signing_key(runtime_seed).verifying_key().to_bytes())
                )
            }))),
            Some(INIT_ERROR_CODE)
        );

        assert_eq!(
            response_error_code(&provider.init(json!({
                "base_path": "",
                "allowed_paths": [],
                "read_only": false,
                "encryption_key": "",
                "extra": {
                    "trusted_runtime_issuer": format!(
                        "0x{}",
                        hex::encode(runtime_signing_key(runtime_seed).verifying_key().to_bytes())
                    )
                },
                "ambient": true
            }))),
            Some(INIT_ERROR_CODE)
        );
    }

    #[test]
    fn exact_prepare_and_open_replay_return_same_response_and_conflicts_fail() {
        let runtime_seed = 0x42;
        let media_seed = 0x22;
        let envelope = custody_envelope_for_media(media_seed, NOW);
        let binding = binding_for_envelope(&envelope);
        let (init_segment, encrypted_segments, _, _) = media_components(media_seed);
        let media_identity = CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &encrypted_segments,
            MEDIA_MIME_TYPE_V1,
            MEDIA_CODECS_V1,
        )
        .unwrap();
        let prepare_audit = RuntimeReleaseAuditIdV1::new(digest(0xb1)).unwrap();
        let mut provider = DecryptProvider::new();
        let _ = provider.init(init_config(runtime_seed));

        let prepare = prepare_request(&binding, prepare_audit, runtime_seed);
        let prepare_line = wrap_request(request_json(&prepare));
        let prepared_a = typed_response(provider.handle_line_at(&prepare_line, NOW + 1));
        let prepared_b = typed_response(provider.handle_line_at(&prepare_line, NOW + 2));
        assert_eq!(prepared_a, prepared_b);

        let conflict_binding = ProtectedContentBindingV1::new(
            binding.encrypted_content().clone(),
            binding.key_envelope().clone(),
            binding.rights_policy().clone(),
            binding.profile(),
            wallet(8),
            binding.runtime_session_binding(),
        )
        .unwrap();
        let conflict_prepare = prepare_request(&conflict_binding, prepare_audit, runtime_seed);
        let prepare_conflict = typed_response(
            provider.handle_line_at(&wrap_request(request_json(&conflict_prepare)), NOW + 2),
        );
        assert_eq!(
            prepare_conflict.failure_code().unwrap(),
            ProviderFailureCodeV1::BindingMismatch
        );

        let open_audit = RuntimeReleaseAuditIdV1::new(digest(0xb2)).unwrap();
        let operation = make_signed_runtime_release_operation(
            runtime_seed,
            open_audit,
            &envelope,
            prepared_a.recipient_public_key().unwrap(),
            prepared_a.recipient_identity().unwrap(),
            NOW,
        );
        let contributions = vec![
            make_signed_node_contribution(&operation, &envelope, runtime_seed, 1, NOW),
            make_signed_node_contribution(&operation, &envelope, runtime_seed, 2, NOW),
        ];
        let terminal = make_signed_terminal_receipt(&operation, &contributions, 0x61, NOW);
        let open = open_request(OpenRequestInputs {
            prepared_handle: *prepared_a.prepared_recipient_handle().unwrap(),
            operation: &operation,
            content_key_commitment: envelope.manifest().content_key_commitment(),
            media_identity: &media_identity,
            init_segment: &init_segment,
            contributions: &contributions,
            terminal_receipt: &terminal,
            issuer_seed: 0x61,
        });
        let open_line = wrap_request(request_json(&open));
        let opened_a = typed_response(provider.handle_line_at(&open_line, NOW + 7));
        let opened_b = typed_response(provider.handle_line_at(&open_line, NOW + 8));
        assert_eq!(opened_a, opened_b);
        assert_eq!(
            opened_a.viewer_session_handle().unwrap(),
            prepared_a.prepared_recipient_handle().unwrap()
        );

        let conflicting_open = open_request(OpenRequestInputs {
            prepared_handle: [0x11; 32],
            operation: &operation,
            content_key_commitment: envelope.manifest().content_key_commitment(),
            media_identity: &media_identity,
            init_segment: &init_segment,
            contributions: &contributions,
            terminal_receipt: &terminal,
            issuer_seed: 0x61,
        });
        let open_conflict = typed_response(
            provider.handle_line_at(&wrap_request(request_json(&conflicting_open)), NOW + 8),
        );
        assert_eq!(
            open_conflict.failure_code().unwrap(),
            ProviderFailureCodeV1::BindingMismatch
        );
    }

    #[test]
    fn wrong_issuer_handle_expiry_capacity_and_tamper_fail_closed() {
        let runtime_seed = 0x42;
        let media_seed = 0x23;
        let envelope = custody_envelope_for_media(media_seed, NOW);
        let binding = binding_for_envelope(&envelope);
        let (init_segment, encrypted_segments, _, _) = media_components(media_seed);
        let media_identity = CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &encrypted_segments,
            MEDIA_MIME_TYPE_V1,
            MEDIA_CODECS_V1,
        )
        .unwrap();
        let mut provider = DecryptProvider::new();
        let _ = provider.init(init_config(runtime_seed));

        let wrong_issuer_prepare = DecryptProviderRequestV1::new_prepare_recipient(
            &binding,
            RuntimeReleaseAuditIdV1::new(digest(0xc1)).unwrap(),
            RightsActionV1::View,
            runtime_issuer(0x55),
            NOW,
            NOW + 10,
        )
        .unwrap();
        let wrong_issuer =
            provider.handle_line_at(&wrap_request(request_json(&wrong_issuer_prepare)), NOW + 1);
        assert_eq!(response_error_code(&wrong_issuer), Some(REQUEST_ERROR_CODE));

        let prepare_audit = RuntimeReleaseAuditIdV1::new(digest(0xc2)).unwrap();
        let prepared = typed_response(provider.handle_line_at(
            &wrap_request(request_json(&prepare_request(
                &binding,
                prepare_audit,
                runtime_seed,
            ))),
            NOW + 1,
        ));
        let absent_cancel = typed_response(provider.handle_line_at(
            &wrap_request(request_json(&cancel_request(
                RuntimeReleaseAuditIdV1::new(digest(0xc3)).unwrap(),
                [0x11; 32],
            ))),
            NOW + 1,
        ));
        assert_eq!(
            absent_cancel.status(),
            DecryptProviderResponseStatusV1::PreparedRecipientAlreadyAbsent
        );

        let operation = make_signed_runtime_release_operation(
            runtime_seed,
            RuntimeReleaseAuditIdV1::new(digest(0xc4)).unwrap(),
            &envelope,
            prepared.recipient_public_key().unwrap(),
            prepared.recipient_identity().unwrap(),
            NOW,
        );
        let contributions = vec![
            make_signed_node_contribution(&operation, &envelope, runtime_seed, 1, NOW),
            make_signed_node_contribution(&operation, &envelope, runtime_seed, 2, NOW),
        ];
        let terminal = make_signed_terminal_receipt(&operation, &contributions, 0x61, NOW);
        let opened = typed_response(provider.handle_line_at(
            &wrap_request(request_json(&open_request(OpenRequestInputs {
                prepared_handle: *prepared.prepared_recipient_handle().unwrap(),
                operation: &operation,
                content_key_commitment: envelope.manifest().content_key_commitment(),
                media_identity: &media_identity,
                init_segment: &init_segment,
                contributions: &contributions,
                terminal_receipt: &terminal,
                issuer_seed: 0x61,
            }))),
            NOW + 7,
        ));
        let wrong_segment = typed_response(provider.handle_line_at(
            &wrap_request(request_json(&read_request(
                RuntimeReleaseAuditIdV1::new(digest(0xc4)).unwrap(),
                *opened.viewer_session_handle().unwrap(),
                ViewerMediaPartSelectorV1::segment(3, encrypted_segments[0].clone()).unwrap(),
            ))),
            NOW + 8,
        ));
        assert_eq!(
            wrong_segment.failure_code().unwrap(),
            ProviderFailureCodeV1::BindingMismatch
        );

        let wrong_audit_read = typed_response(provider.handle_line_at(
            &wrap_request(request_json(&read_request(
                RuntimeReleaseAuditIdV1::new(digest(0xc5)).unwrap(),
                *opened.viewer_session_handle().unwrap(),
                ViewerMediaPartSelectorV1::init(),
            ))),
            NOW + 8,
        ));
        assert_eq!(
            wrong_audit_read.failure_code().unwrap(),
            ProviderFailureCodeV1::BindingMismatch
        );

        let expired_read = typed_response(provider.handle_line_at(
            &wrap_request(request_json(&read_request(
                RuntimeReleaseAuditIdV1::new(digest(0xc4)).unwrap(),
                *opened.viewer_session_handle().unwrap(),
                ViewerMediaPartSelectorV1::init(),
            ))),
            NOW + 100,
        ));
        assert_eq!(
            expired_read.failure_code().unwrap(),
            ProviderFailureCodeV1::HandleAbsent
        );

        let mut provider = DecryptProvider::new();
        let _ = provider.init(init_config(runtime_seed));
        for index in 0..MAX_PREPARED_RECIPIENTS_V1 {
            let audit = RuntimeReleaseAuditIdV1::new(digest((index as u8) + 1)).unwrap();
            let response = typed_response(provider.handle_line_at(
                &wrap_request(request_json(&prepare_request(
                    &binding,
                    audit,
                    runtime_seed,
                ))),
                NOW + 1,
            ));
            assert_eq!(
                response.status(),
                DecryptProviderResponseStatusV1::PreparedRecipient
            );
        }
        let over_capacity = typed_response(provider.handle_line_at(
            &wrap_request(request_json(&prepare_request(
                &binding,
                RuntimeReleaseAuditIdV1::new(digest(0xfe)).unwrap(),
                runtime_seed,
            ))),
            NOW + 1,
        ));
        assert_eq!(
            over_capacity.failure_code().unwrap(),
            ProviderFailureCodeV1::BackendUnavailable
        );

        let mut tampered_json = request_json(&open_request(OpenRequestInputs {
            prepared_handle: *prepared.prepared_recipient_handle().unwrap(),
            operation: &operation,
            content_key_commitment: envelope.manifest().content_key_commitment(),
            media_identity: &media_identity,
            init_segment: &init_segment,
            contributions: &contributions,
            terminal_receipt: &terminal,
            issuer_seed: 0x61,
        }));
        let contribution = tampered_json["signed_node_contributions"][0]
            .as_array_mut()
            .unwrap();
        contribution[10] = json!(contribution[10].as_u64().unwrap() ^ 1);
        let tampered = provider.handle_line_at(&wrap_request(tampered_json), NOW + 7);
        assert_eq!(response_error_code(&tampered), Some(REQUEST_ERROR_CODE));
    }

    #[test]
    fn invocation_envelope_requires_exact_eleven_field_local_json_shape() {
        let runtime_seed = 0x42;
        let envelope = custody_envelope_for_media(0x31, NOW);
        let binding = binding_for_envelope(&envelope);
        let request = prepare_request(
            &binding,
            RuntimeReleaseAuditIdV1::new(digest(0xd1)).unwrap(),
            runtime_seed,
        );
        let mut provider = DecryptProvider::new();
        let _ = provider.init(init_config(runtime_seed));

        let mut value = request_json(&request);
        value.as_object_mut().unwrap().insert(
            "_runtime_invocation".to_string(),
            json!({
                "schema": "elastos.provider.invocation/v1",
                "source": "runtime",
                "target": PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET,
                "op": "prepare_recipient",
                "transport": "runtime-local-provider-plane",
                "carrier": null
            }),
        );
        let response = provider.handle_line_at(&serde_json::to_string(&value).unwrap(), NOW + 1);
        assert_eq!(response_error_code(&response), Some(REQUEST_ERROR_CODE));

        let mut value = request_json(&request);
        value.as_object_mut().unwrap().insert(
            "_runtime_invocation".to_string(),
            json!({
                "schema": "elastos.provider.invocation/v1",
                "source": "runtime",
                "target": PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET,
                "op": "prepare_recipient",
                "capability": format!(
                    "provider:runtime->{PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET}:prepare_recipient"
                ),
                "transport": "runtime-local-provider-plane",
                "carrier": null,
                "transfer": "json",
                "range": null,
                "progress": null,
                "abi": expected_local_json_runtime_invocation_abi(),
                "host": "127.0.0.1"
            }),
        );
        let response = provider.handle_line_at(&serde_json::to_string(&value).unwrap(), NOW + 1);
        assert_eq!(response_error_code(&response), Some(REQUEST_ERROR_CODE));

        let mut value = request_json(&request);
        value.as_object_mut().unwrap().insert(
            "_runtime_invocation".to_string(),
            json!({
                "schema": "elastos.provider.invocation/v1",
                "source": "runtime",
                "target": PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET,
                "op": "prepare_recipient",
                "capability": format!(
                    "provider:runtime->{PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET}:open_viewer_session"
                ),
                "transport": "runtime-local-provider-plane",
                "carrier": null,
                "transfer": "json",
                "range": null,
                "progress": null,
                "abi": expected_local_json_runtime_invocation_abi(),
            }),
        );
        let response = provider.handle_line_at(&serde_json::to_string(&value).unwrap(), NOW + 1);
        assert_eq!(response_error_code(&response), Some(REQUEST_ERROR_CODE));

        let mut value = request_json(&request);
        value.as_object_mut().unwrap().insert(
            "_runtime_invocation".to_string(),
            json!({
                "schema": "elastos.provider.invocation/v1",
                "source": "runtime",
                "target": PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET,
                "op": "prepare_recipient",
                "capability": format!(
                    "provider:runtime->{PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET}:prepare_recipient"
                ),
                "transport": "runtime-local-provider-plane",
                "carrier": null,
                "transfer": "bytes",
                "range": null,
                "progress": null,
                "abi": expected_local_json_runtime_invocation_abi(),
            }),
        );
        let response = provider.handle_line_at(&serde_json::to_string(&value).unwrap(), NOW + 1);
        assert_eq!(response_error_code(&response), Some(REQUEST_ERROR_CODE));

        let mut value = request_json(&request);
        value.as_object_mut().unwrap().insert(
            "_runtime_invocation".to_string(),
            json!({
                "schema": "elastos.provider.invocation/v1",
                "source": "runtime",
                "target": PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET,
                "op": "prepare_recipient",
                "capability": format!(
                    "provider:runtime->{PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET}:prepare_recipient"
                ),
                "transport": "runtime-local-provider-plane",
                "carrier": {},
                "transfer": "json",
                "range": null,
                "progress": null,
                "abi": expected_local_json_runtime_invocation_abi(),
            }),
        );
        let response = provider.handle_line_at(&serde_json::to_string(&value).unwrap(), NOW + 1);
        assert_eq!(response_error_code(&response), Some(REQUEST_ERROR_CODE));

        let mut value = request_json(&request);
        value.as_object_mut().unwrap().insert(
            "_runtime_invocation".to_string(),
            json!({
                "schema": "elastos.provider.invocation/v1",
                "source": "runtime",
                "target": PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET,
                "op": "prepare_recipient",
                "capability": format!(
                    "provider:runtime->{PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET}:prepare_recipient"
                ),
                "transport": "runtime-local-provider-plane",
                "carrier": null,
                "transfer": "json",
                "range": {"start": 0, "end": 1},
                "progress": null,
                "abi": expected_local_json_runtime_invocation_abi(),
            }),
        );
        let response = provider.handle_line_at(&serde_json::to_string(&value).unwrap(), NOW + 1);
        assert_eq!(response_error_code(&response), Some(REQUEST_ERROR_CODE));

        let mut value = request_json(&request);
        value.as_object_mut().unwrap().insert(
            "_runtime_invocation".to_string(),
            json!({
                "schema": "elastos.provider.invocation/v1",
                "source": "runtime",
                "target": PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET,
                "op": "prepare_recipient",
                "capability": format!(
                    "provider:runtime->{PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET}:prepare_recipient"
                ),
                "transport": "runtime-local-provider-plane",
                "carrier": null,
                "transfer": "json",
                "range": null,
                "progress": {"request_id": "x", "expected_bytes": 1},
                "abi": expected_local_json_runtime_invocation_abi(),
            }),
        );
        let response = provider.handle_line_at(&serde_json::to_string(&value).unwrap(), NOW + 1);
        assert_eq!(response_error_code(&response), Some(REQUEST_ERROR_CODE));

        let mut value = request_json(&request);
        value.as_object_mut().unwrap().insert(
            "_runtime_invocation".to_string(),
            json!({
                "schema": "elastos.provider.invocation/v1",
                "source": "runtime",
                "target": PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET,
                "op": "prepare_recipient",
                "capability": format!(
                    "provider:runtime->{PROTECTED_CONTENT_DECRYPT_PROVIDER_TARGET}:prepare_recipient"
                ),
                "transport": "runtime-local-provider-plane",
                "carrier": null,
                "transfer": "json",
                "range": null,
                "progress": null,
                "abi": {
                    "schema": "elastos.provider.transfer-abi/v1",
                    "transfer": "bytes",
                    "transport": "runtime-local-provider-plane",
                    "range_supported": false,
                    "progress_supported": false,
                    "progress_mode": "none",
                    "transport_native_stream": false,
                    "backpressure": "not_applicable",
                    "cancel_supported": false
                },
            }),
        );
        let response = provider.handle_line_at(&serde_json::to_string(&value).unwrap(), NOW + 1);
        assert_eq!(response_error_code(&response), Some(REQUEST_ERROR_CODE));
    }

    // DASH v2 sessions: real protected media from `support::dash`.
    use super::support::dash::{
        dash_proof, media_dash_components, DashComponents, DashOptions, A, V,
    };

    struct Dash {
        provider: DecryptProvider,
        comps: DashComponents,
        prepared: DecryptProviderResponseV1,
        open: DecryptProviderRequestV1,
        audit: RuntimeReleaseAuditIdV1,
    }

    fn send(
        provider: &mut DecryptProvider,
        request: &DecryptProviderRequestV1,
        now: u64,
    ) -> ProviderResponse {
        provider.handle_line_at(&wrap_request(request_json(request)), now)
    }

    /// A configured provider with a prepared recipient and a v2 open request
    /// for `options`, not yet sent.
    fn dash(options: DashOptions) -> Dash {
        let runtime_seed = 0x42;
        let comps = media_dash_components(0x31, NOW, options);
        let binding = binding_for_envelope(&comps.envelope);
        let mut provider = DecryptProvider::new();
        assert!(matches!(
            provider.init(init_config(runtime_seed)),
            ProviderResponse::Ok { .. }
        ));
        let prepare_audit = RuntimeReleaseAuditIdV1::new(digest(0xc1)).unwrap();
        let prepared = typed_response(send(
            &mut provider,
            &prepare_request(&binding, prepare_audit, runtime_seed),
            NOW + 1,
        ));
        let audit = RuntimeReleaseAuditIdV1::new(digest(0xc2)).unwrap();
        let operation = make_signed_runtime_release_operation(
            runtime_seed,
            audit,
            &comps.envelope,
            prepared.recipient_public_key().unwrap(),
            prepared.recipient_identity().unwrap(),
            NOW,
        );
        let contributions = vec![
            make_signed_node_contribution(&operation, &comps.envelope, runtime_seed, 1, NOW),
            make_signed_node_contribution(&operation, &comps.envelope, runtime_seed, 2, NOW),
        ];
        let terminal = make_signed_terminal_receipt(&operation, &contributions, 0x61, NOW);
        let open = DecryptProviderRequestV1::new_open_viewer_session_v2(
            *prepared.prepared_recipient_handle().unwrap(),
            &operation,
            TerminalReceiptIssuerKey::new(
                SigningKey::from_bytes(&[0x61; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap(),
            comps.envelope.manifest().content_key_commitment(),
            &comps.head,
            &comps.protected_inits,
            &contributions,
            &terminal,
        )
        .unwrap();
        Dash {
            provider,
            comps,
            prepared,
            open,
            audit,
        }
    }

    impl Dash {
        fn open(&mut self) -> DecryptProviderResponseV1 {
            let open = self.open.clone();
            typed_response(send(&mut self.provider, &open, NOW + 7))
        }

        fn handle(&self) -> HandleBytes {
            *self.prepared.prepared_recipient_handle().unwrap()
        }

        fn read(&mut self, selector: ViewerMediaPartSelectorV1) -> DecryptProviderResponseV1 {
            let request = read_request(self.audit, self.handle(), selector);
            typed_response(send(&mut self.provider, &request, NOW + 8))
        }

        fn read_segment(&mut self, rendition: usize, index: usize) -> DecryptProviderResponseV1 {
            let kind = [V, A][rendition];
            let segments = &self.comps.protected_segments[rendition];
            let selector = ViewerMediaPartSelectorV1::segment_v2(
                rendition as u8,
                index as u32,
                segments[index].clone(),
                dash_proof(kind, segments, index),
            )
            .unwrap();
            self.read(selector)
        }
    }

    fn assert_failure(response: &DecryptProviderResponseV1, code: ProviderFailureCodeV1) {
        assert_eq!(response.failure_code().unwrap(), code, "{response:?}");
    }

    #[test]
    fn dash_open_and_reads_return_exact_clear_bytes_with_proofs() {
        let mut d = dash(DashOptions::default());
        let opened = d.open();
        assert_eq!(
            opened.status(),
            DecryptProviderResponseStatusV1::ViewerSessionOpened
        );
        for rendition in 0..2 {
            let init = d.read(ViewerMediaPartSelectorV1::init_v2(rendition as u8).unwrap());
            assert_eq!(
                init.clear_media_part().unwrap(),
                d.comps.clear_inits[rendition]
            );
            assert_eq!(
                init.viewer_media_part_selector().unwrap().rendition_index(),
                Some(rendition as u8)
            );
            for index in 0..d.comps.protected_segments[rendition].len() {
                let part = d.read_segment(rendition, index);
                assert_eq!(
                    part.clear_media_part().unwrap(),
                    d.comps.clear_segments[rendition][index],
                    "rendition {rendition} segment {index}"
                );
            }
        }
    }

    #[test]
    fn dash_one_segment_rendition_reads_with_an_empty_proof() {
        let mut d = dash(DashOptions::default());
        d.open();
        assert_eq!(d.comps.protected_segments[1].len(), 1);
        let segments = d.comps.protected_segments[1].clone();
        let proof = dash_proof(A, &segments, 0);
        assert!(proof.is_empty());
        let selector =
            ViewerMediaPartSelectorV1::segment_v2(1, 0, segments[0].clone(), proof).unwrap();
        let part = d.read(selector);
        assert_eq!(
            part.clear_media_part().unwrap(),
            d.comps.clear_segments[1][0]
        );
    }

    #[test]
    fn dash_reads_verify_the_proof_and_rendition_before_decrypting() {
        let mut d = dash(DashOptions::default());
        d.open();
        let video = d.comps.protected_segments[0].clone();
        let audio = d.comps.protected_segments[1].clone();
        let video_proof = dash_proof(V, &video, 0);
        let mut flipped = video_proof.clone();
        flipped[0] = Digest32::new({
            let mut bytes = *flipped[0].as_bytes();
            bytes[0] ^= 1;
            bytes
        });
        let cases = [
            // a proof with one byte flipped
            ViewerMediaPartSelectorV1::segment_v2(0, 0, video[0].clone(), flipped).unwrap(),
            // segment 1's proof with segment 0's bytes and index
            ViewerMediaPartSelectorV1::segment_v2(0, 0, video[0].clone(), dash_proof(V, &video, 1))
                .unwrap(),
            // audio bytes and proof sent as rendition 0
            ViewerMediaPartSelectorV1::segment_v2(0, 0, audio[0].clone(), dash_proof(A, &audio, 0))
                .unwrap(),
            // a rendition the session does not have is checked in the next test
        ];
        for selector in cases {
            assert_failure(&d.read(selector), ProviderFailureCodeV1::BindingMismatch);
        }
        // the session is still usable after the refusals
        let good = d.read_segment(0, 0);
        assert_eq!(
            good.clear_media_part().unwrap(),
            d.comps.clear_segments[0][0]
        );
        assert_eq!(video_proof.len(), dash_proof(V, &video, 0).len());
    }

    #[test]
    fn dash_rendition_out_of_range_is_a_binding_mismatch() {
        let mut d = dash(DashOptions {
            renditions: 1,
            ..DashOptions::default()
        });
        d.open();
        assert_failure(
            &d.read(ViewerMediaPartSelectorV1::init_v2(1).unwrap()),
            ProviderFailureCodeV1::BindingMismatch,
        );
        let video = d.comps.protected_segments[0].clone();
        let selector =
            ViewerMediaPartSelectorV1::segment_v2(1, 0, video[0].clone(), dash_proof(V, &video, 0))
                .unwrap();
        assert_failure(&d.read(selector), ProviderFailureCodeV1::BindingMismatch);
        let init = d.read(ViewerMediaPartSelectorV1::init_v2(0).unwrap());
        assert_eq!(init.clear_media_part().unwrap(), d.comps.clear_inits[0]);
    }

    #[test]
    fn dash_open_refuses_inits_whose_elastos_headers_differ() {
        let mut d = dash(DashOptions {
            audio_epoch: 0x77,
            ..DashOptions::default()
        });
        let refused = d.open();
        assert_failure(&refused, ProviderFailureCodeV1::BindingMismatch);
        // nothing was created: no session, and the prepared recipient is intact
        let read = d.read(ViewerMediaPartSelectorV1::init_v2(0).unwrap());
        assert_failure(&read, ProviderFailureCodeV1::HandleAbsent);
        let cancel_request = cancel_request(d.audit, d.handle());
        let cancel = typed_response(send(&mut d.provider, &cancel_request, NOW + 9));
        assert_eq!(
            cancel.status(),
            DecryptProviderResponseStatusV1::CancelledPreparedRecipient
        );
    }

    #[test]
    fn dash_open_refuses_an_init_without_the_elastos_header() {
        let mut d = dash(DashOptions {
            strip_video_elastos: true,
            ..DashOptions::default()
        });
        let open = d.open.clone();
        let response = send(&mut d.provider, &open, NOW + 7);
        assert_eq!(response_error_code(&response), Some("invalid_request"));
        let read = d.read(ViewerMediaPartSelectorV1::init_v2(0).unwrap());
        assert_failure(&read, ProviderFailureCodeV1::HandleAbsent);
    }

    #[test]
    fn dash_and_v1_selectors_do_not_cross_versions() {
        // a v2 session refuses v1 selectors
        let mut d = dash(DashOptions::default());
        d.open();
        assert_failure(
            &d.read(ViewerMediaPartSelectorV1::init()),
            ProviderFailureCodeV1::InvalidRequest,
        );
        let segment = d.comps.protected_segments[0][0].clone();
        assert_failure(
            &d.read(ViewerMediaPartSelectorV1::segment(0, segment).unwrap()),
            ProviderFailureCodeV1::InvalidRequest,
        );

        // a v1 session refuses v2 selectors
        let runtime_seed = 0x42;
        let media_seed = 0x23;
        let envelope = custody_envelope_for_media(media_seed, NOW);
        let binding = binding_for_envelope(&envelope);
        let (init_segment, encrypted_segments, _, _) = media_components(media_seed);
        let media_identity = CencFmp4MediaIdentityV1::new_from_bytes(
            &init_segment,
            &encrypted_segments,
            MEDIA_MIME_TYPE_V1,
            MEDIA_CODECS_V1,
        )
        .unwrap();
        let mut provider = DecryptProvider::new();
        let _ = provider.init(init_config(runtime_seed));
        let prepared = typed_response(send(
            &mut provider,
            &prepare_request(
                &binding,
                RuntimeReleaseAuditIdV1::new(digest(0xc3)).unwrap(),
                runtime_seed,
            ),
            NOW + 1,
        ));
        let audit = RuntimeReleaseAuditIdV1::new(digest(0xc4)).unwrap();
        let operation = make_signed_runtime_release_operation(
            runtime_seed,
            audit,
            &envelope,
            prepared.recipient_public_key().unwrap(),
            prepared.recipient_identity().unwrap(),
            NOW,
        );
        let contributions = vec![
            make_signed_node_contribution(&operation, &envelope, runtime_seed, 1, NOW),
            make_signed_node_contribution(&operation, &envelope, runtime_seed, 2, NOW),
        ];
        let terminal = make_signed_terminal_receipt(&operation, &contributions, 0x61, NOW);
        let open = open_request(OpenRequestInputs {
            prepared_handle: *prepared.prepared_recipient_handle().unwrap(),
            operation: &operation,
            content_key_commitment: envelope.manifest().content_key_commitment(),
            media_identity: &media_identity,
            init_segment: &init_segment,
            contributions: &contributions,
            terminal_receipt: &terminal,
            issuer_seed: 0x61,
        });
        assert_eq!(
            typed_response(send(&mut provider, &open, NOW + 7)).status(),
            DecryptProviderResponseStatusV1::ViewerSessionOpened
        );
        let handle = *prepared.prepared_recipient_handle().unwrap();
        for selector in [
            ViewerMediaPartSelectorV1::init_v2(0).unwrap(),
            ViewerMediaPartSelectorV1::segment_v2(0, 1, encrypted_segments[1].clone(), vec![])
                .unwrap(),
        ] {
            let response = typed_response(send(
                &mut provider,
                &read_request(audit, handle, selector),
                NOW + 8,
            ));
            assert_failure(&response, ProviderFailureCodeV1::InvalidRequest);
        }
    }

    #[test]
    fn dash_open_replay_is_exact_and_a_changed_open_conflicts() {
        let mut d = dash(DashOptions::default());
        let first = d.open();
        let again = d.open();
        assert_eq!(first, again);
        assert_eq!(first.viewer_session_handle().unwrap(), &d.handle());

        // same audit id, other bytes (another prepared handle)
        let contributions_source = d.open.clone();
        let mut value = request_json(&contributions_source);
        value["prepared_recipient_handle"] = json!(hex::encode([0x11u8; 32]));
        let conflicting = wrap_request(value);
        let response = typed_response(d.provider.handle_line_at(&conflicting, NOW + 8));
        assert_failure(&response, ProviderFailureCodeV1::BindingMismatch);
    }
}

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};

use ed25519_dalek::SigningKey;
use elastos_protected_content_contracts::{
    ContentAccessIdV1, CustodyCommitteeAuthorizationIdentityV1, CustodyEpochIdentityV1,
    CustodyPoolIdentityV1, Digest32, EncryptedContentIdentityV1, NodeCustodyPublicKeyV1,
    NodePublicKey,
};
use elastos_protected_content_provider_contracts::{
    CencDashRenditionKindV2, CencFmp4MediaIdentityV1, ProtectFailureReasonV2,
    ProtectProviderRequestV1, ProtectProviderResponseStatusV1, ProtectionRepresentationV2,
    ProtectionSessionNodeV1, ProviderFailureCodeV1,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};

struct ProviderProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl ProviderProcess {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_protected-content-protect-provider"))
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

    fn request_raw_line(&mut self, line: &[u8]) -> serde_json::Value {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(line).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
        self.read_response()
    }

    fn read_response(&mut self) -> serde_json::Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn shutdown_and_assert_clean(mut self) {
        let response = self.request_json(json!({"op": "shutdown"}));
        assert_eq!(response["status"], "ok");
        let status = self.child.wait().unwrap();
        assert!(status.success());
        self.assert_empty_stderr();
    }

    fn close_stdin_and_assert_clean(mut self) {
        drop(self.stdin.take());
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

fn init_config() -> serde_json::Value {
    json!({
        "base_path": "",
        "allowed_paths": [],
        "read_only": false,
        "encryption_key": "",
        "extra": {}
    })
}

fn local_json_runtime_invocation_abi() -> serde_json::Value {
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

fn wrap_runtime_request(request: &ProtectProviderRequestV1) -> serde_json::Value {
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
            "abi": local_json_runtime_invocation_abi()
        }),
    );
    value
}

fn typed_ok_response(
    response: serde_json::Value,
) -> elastos_protected_content_provider_contracts::ProtectProviderResponseV1 {
    assert_eq!(response["status"], "ok");
    elastos_protected_content_provider_contracts::ProtectProviderResponseV1::from_json_slice(
        &serde_json::to_vec(response.get("data").unwrap()).unwrap(),
    )
    .unwrap()
}

fn digest(seed: u8) -> Digest32 {
    Digest32::new([seed; 32])
}

fn assert_failure_code(response: serde_json::Value, expected: ProviderFailureCodeV1) {
    let typed = typed_ok_response(response);
    assert_eq!(
        typed.status(),
        ProtectProviderResponseStatusV1::Failure,
        "expected a failure response"
    );
    assert_eq!(typed.failure_code(), Some(expected));
}

fn open_object_request(
    session_id_seed: u8,
    content_type: &str,
    plaintext_bytes: u64,
    nodes: Vec<ProtectionSessionNodeV1>,
) -> ProtectProviderRequestV1 {
    ProtectProviderRequestV1::new_open_object_protection_session(
        digest(session_id_seed),
        ContentAccessIdV1::new([0x41; 16]).unwrap(),
        CustodyPoolIdentityV1::new(digest(0x41), 32).unwrap(),
        CustodyEpochIdentityV1::new(digest(0x42), 32).unwrap(),
        CustodyCommitteeAuthorizationIdentityV1::new(digest(0x43), 32).unwrap(),
        2,
        3,
        content_type,
        plaintext_bytes,
        nodes,
    )
    .unwrap()
}

fn node_public_key(seed: u8) -> NodePublicKey {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    NodePublicKey::new(signing.verifying_key().to_bytes()).unwrap()
}

fn node_custody_public_key() -> NodeCustodyPublicKeyV1 {
    elastos_protected_content_custody::NodeCustodySecretKeyV1::generate()
        .unwrap()
        .public_key()
        .unwrap()
}

fn nodes() -> Vec<ProtectionSessionNodeV1> {
    vec![
        ProtectionSessionNodeV1::new(node_public_key(1), node_custody_public_key()).unwrap(),
        ProtectionSessionNodeV1::new(node_public_key(2), node_custody_public_key()).unwrap(),
        ProtectionSessionNodeV1::new(node_public_key(3), node_custody_public_key()).unwrap(),
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

fn open_request(clear_init: &[u8], segment_count: u32) -> ProtectProviderRequestV1 {
    ProtectProviderRequestV1::new_open_protection_session(
        digest(0x31),
        elastos_protected_content_contracts::ContentAccessIdV1::new([0x41; 16]).unwrap(),
        CustodyPoolIdentityV1::new(digest(0x41), 32).unwrap(),
        CustodyEpochIdentityV1::new(digest(0x42), 32).unwrap(),
        CustodyCommitteeAuthorizationIdentityV1::new(digest(0x43), 32).unwrap(),
        "video/mp4",
        "avc1.640028",
        segment_count,
        clear_init,
        nodes(),
    )
    .unwrap()
}

#[test]
fn process_accepts_init_status_shutdown_and_clean_eof() {
    let mut process = ProviderProcess::start();

    let status_before = process.request_json(json!({"op": "status"}));
    assert_eq!(status_before["status"], "ok");
    assert_eq!(status_before["data"]["configured"], false);

    let init = process.request_json(json!({"op": "init", "config": init_config()}));
    assert_eq!(init["status"], "ok");
    assert_eq!(init["data"]["configured"], true);

    let status_after = process.request_json(json!({"op": "status"}));
    assert_eq!(status_after["status"], "ok");
    assert_eq!(status_after["data"]["configured"], true);

    process.shutdown_and_assert_clean();

    let process = ProviderProcess::start();
    process.close_stdin_and_assert_clean();
}

#[test]
fn process_rejects_malformed_and_oversized_frames_and_stays_alive() {
    let mut process = ProviderProcess::start();

    let malformed = process.request_raw_line(br#"{"op":"status""#);
    assert_eq!(malformed["status"], "error");
    assert_eq!(malformed["code"], "invalid_request");

    let trailing = process.request_raw_line(br#"{"op":"status"}[]"#);
    assert_eq!(trailing["status"], "error");
    assert_eq!(trailing["code"], "invalid_request");

    let oversized = process.request_raw_line(&vec![
        b'a';
        elastos_protected_content_provider_contracts::MAX_PROVIDER_FRAME_BYTES_V1
            + 1
    ]);
    assert_eq!(oversized["status"], "error");
    assert_eq!(oversized["code"], "invalid_request");

    let init = process.request_json(json!({"op": "init", "config": init_config()}));
    assert_eq!(init["status"], "ok");

    process.shutdown_and_assert_clean();
}

#[test]
fn process_open_segment_finalize_success_path_is_framed_and_bound() {
    let clear_init = clear_init_segment();
    let clear_segments = [clear_segment(1, b"hello"), clear_segment(1, b"world!")];
    let request = open_request(&clear_init, u32::try_from(clear_segments.len()).unwrap());

    let mut process = ProviderProcess::start();
    let init = process.request_json(json!({"op": "init", "config": init_config()}));
    assert_eq!(init["status"], "ok");

    let opened = typed_ok_response(process.request_json(wrap_runtime_request(&request)));
    assert_eq!(
        opened.status(),
        ProtectProviderResponseStatusV1::ProtectionSessionOpened,
        "open failure_code={:?}",
        opened.failure_code()
    );
    let handle = opened.protection_session_handle().unwrap().unwrap();
    let protected_init = opened.protected_init_segment().unwrap().to_vec();

    let mut protected_segments = Vec::new();
    for (index, clear_segment) in clear_segments.iter().enumerate() {
        let response = typed_ok_response(
            process.request_json(wrap_runtime_request(
                &ProtectProviderRequestV1::new_protect_media_segment(
                    handle,
                    u32::try_from(index).unwrap(),
                    clear_segment,
                )
                .unwrap(),
            )),
        );
        assert_eq!(
            response.status(),
            ProtectProviderResponseStatusV1::MediaSegmentProtected
        );
        protected_segments.push(response.protected_segment().unwrap().to_vec());
    }

    let finalized = typed_ok_response(process.request_json(wrap_runtime_request(
        &ProtectProviderRequestV1::new_finalize_protection_session(handle).unwrap(),
    )));
    assert_eq!(
        finalized.status(),
        ProtectProviderResponseStatusV1::ProtectionSessionFinalized
    );
    let media_identity = finalized.media_identity().unwrap().unwrap();
    let expected = CencFmp4MediaIdentityV1::new_from_bytes(
        &protected_init,
        &protected_segments,
        "video/mp4",
        "avc1.640028",
    )
    .unwrap();
    assert_eq!(media_identity, expected);
    let envelope = finalized.custody_envelope().unwrap().unwrap();
    assert_eq!(
        envelope.manifest().encrypted_content(),
        media_identity.encrypted_content()
    );
    assert_eq!(envelope.manifest().threshold().required(), 2);
    assert_eq!(envelope.manifest().threshold().total(), 3);

    // The object op on this (finalized, media-kind) session must be
    // rejected as an invalid session before it ever reaches the finalized-
    // response replay cache or the mandated encrypted_content comparison:
    // otherwise it would return the media session's cached finalized
    // response (a "success"-shaped reply) regardless of what identity is
    // declared here.
    assert_failure_code(
        process.request_json(wrap_runtime_request(
            &ProtectProviderRequestV1::new_finalize_object_protection_session(
                Digest32::new(handle),
                media_identity.encrypted_content(),
            )
            .unwrap(),
        )),
        ProviderFailureCodeV1::InvalidRequest,
    );

    process.shutdown_and_assert_clean();
}

#[test]
fn object_session_opens_above_the_old_cap() {
    let mut process = ProviderProcess::start();
    let init = process.request_json(json!({"op": "init", "config": init_config()}));
    assert_eq!(init["status"], "ok");

    let open_request = open_object_request(0x92, "application/pdf", 80 * 1024 * 1024, nodes());
    let opened = typed_ok_response(process.request_json(wrap_runtime_request(&open_request)));
    assert_eq!(
        opened.status(),
        ProtectProviderResponseStatusV1::ObjectProtectionSessionOpened,
        "open failure_code={:?}",
        opened.failure_code()
    );
}

#[test]
#[ignore = "heavy: 65 MiB through the provider process"]
fn object_session_seals_more_than_sixty_four_chunks() {
    const CHUNK_BYTES: usize = 1_048_576;
    let plaintext_bytes = u64::try_from(64 * CHUNK_BYTES + 1).unwrap();

    let mut process = ProviderProcess::start();
    let init = process.request_json(json!({"op": "init", "config": init_config()}));
    assert_eq!(init["status"], "ok");

    let open_request = open_object_request(0x93, "application/pdf", plaintext_bytes, nodes());
    let opened = typed_ok_response(process.request_json(wrap_runtime_request(&open_request)));
    assert_eq!(
        opened.status(),
        ProtectProviderResponseStatusV1::ObjectProtectionSessionOpened,
        "open failure_code={:?}",
        opened.failure_code()
    );
    let framed_header = opened.framed_header().unwrap().to_vec();
    let mut runtime_hasher = Sha256::new();
    runtime_hasher.update(&framed_header);
    let mut total_bytes = u64::try_from(framed_header.len()).unwrap();

    let session_id = digest(0x93);
    let full_chunk = vec![0x44u8; CHUNK_BYTES];
    for index in 0..65u32 {
        let chunk: &[u8] = if index == 64 { &[0x55] } else { &full_chunk };
        let response = typed_ok_response(process.request_json(wrap_runtime_request(
            &ProtectProviderRequestV1::new_protect_object_chunk(session_id, index, chunk).unwrap(),
        )));
        assert_eq!(
            response.status(),
            ProtectProviderResponseStatusV1::ObjectChunkProtected,
            "chunk {index} failure_code={:?}",
            response.failure_code()
        );
        let framed_chunk = response.framed_chunk().unwrap();
        runtime_hasher.update(framed_chunk);
        total_bytes += u64::try_from(framed_chunk.len()).unwrap();
    }

    let runtime_side_identity = EncryptedContentIdentityV1::new(
        Digest32::new(runtime_hasher.finalize().into()),
        total_bytes,
    )
    .unwrap();
    let finalized = typed_ok_response(
        process.request_json(wrap_runtime_request(
            &ProtectProviderRequestV1::new_finalize_object_protection_session(
                session_id,
                &runtime_side_identity,
            )
            .unwrap(),
        )),
    );
    assert_eq!(
        finalized.status(),
        ProtectProviderResponseStatusV1::ObjectProtectionSessionFinalized,
        "finalize failure_code={:?}",
        finalized.failure_code()
    );
    let object_identity = finalized.object_identity().unwrap().unwrap();
    assert_eq!(object_identity.chunk_count(), 65);
    assert_eq!(object_identity.encrypted_content(), &runtime_side_identity);
}

#[test]
fn object_session_open_three_chunks_finalize_round_trips() {
    const CHUNK_BYTES: usize = 1_048_576;
    let plaintext_bytes = u64::try_from(CHUNK_BYTES * 2 + CHUNK_BYTES / 2).unwrap();
    let chunks = [
        vec![0x11u8; CHUNK_BYTES],
        vec![0x22u8; CHUNK_BYTES],
        vec![0x33u8; CHUNK_BYTES / 2],
    ];

    let mut process = ProviderProcess::start();
    let init = process.request_json(json!({"op": "init", "config": init_config()}));
    assert_eq!(init["status"], "ok");

    let open_request = open_object_request(0x91, "application/pdf", plaintext_bytes, nodes());
    let opened = typed_ok_response(process.request_json(wrap_runtime_request(&open_request)));
    assert_eq!(
        opened.status(),
        ProtectProviderResponseStatusV1::ObjectProtectionSessionOpened,
        "open failure_code={:?}",
        opened.failure_code()
    );
    let framed_header = opened.framed_header().unwrap().to_vec();

    // The Runtime side of the wire never gets the sealer's internal running
    // hash; it independently re-derives the same identity from the public
    // framed bytes the provider hands back (header prefix, then each framed
    // chunk in order) using the same algorithm this provider's sealer uses.
    let mut runtime_hasher = Sha256::new();
    runtime_hasher.update(&framed_header);
    let mut total_bytes = u64::try_from(framed_header.len()).unwrap();

    let session_id = digest(0x91);
    for (index, chunk) in chunks.iter().enumerate() {
        let response = typed_ok_response(
            process.request_json(wrap_runtime_request(
                &ProtectProviderRequestV1::new_protect_object_chunk(
                    session_id,
                    u32::try_from(index).unwrap(),
                    chunk,
                )
                .unwrap(),
            )),
        );
        assert_eq!(
            response.status(),
            ProtectProviderResponseStatusV1::ObjectChunkProtected,
            "chunk {index} failure_code={:?}",
            response.failure_code()
        );
        let framed_chunk = response.framed_chunk().unwrap().to_vec();
        runtime_hasher.update(&framed_chunk);
        total_bytes += u64::try_from(framed_chunk.len()).unwrap();
    }

    let runtime_side_identity = EncryptedContentIdentityV1::new(
        Digest32::new(runtime_hasher.finalize().into()),
        total_bytes,
    )
    .unwrap();

    let finalized = typed_ok_response(
        process.request_json(wrap_runtime_request(
            &ProtectProviderRequestV1::new_finalize_object_protection_session(
                session_id,
                &runtime_side_identity,
            )
            .unwrap(),
        )),
    );
    assert_eq!(
        finalized.status(),
        ProtectProviderResponseStatusV1::ObjectProtectionSessionFinalized,
        "finalize failure_code={:?}",
        finalized.failure_code()
    );
    let object_identity = finalized.object_identity().unwrap().unwrap();
    assert_eq!(object_identity.encrypted_content(), &runtime_side_identity);
    assert_eq!(object_identity.content_type(), "application/pdf");
    assert_eq!(object_identity.plaintext_bytes(), plaintext_bytes);

    let envelope = finalized.custody_envelope().unwrap().unwrap();
    assert_eq!(
        envelope.manifest().encrypted_content(),
        object_identity.encrypted_content()
    );
    assert_eq!(
        envelope.manifest().content_key_commitment(),
        finalized.content_key_commitment().unwrap()
    );
    assert_eq!(envelope.manifest().threshold().required(), 2);
    assert_eq!(envelope.manifest().threshold().total(), 3);

    // A media op on an object session (identified by the same 32-byte
    // session_id/handle keyspace) returns the invalid-session error rather
    // than silently misinterpreting the session's stored state.
    assert_failure_code(
        process.request_json(wrap_runtime_request(
            &ProtectProviderRequestV1::new_protect_media_segment(*session_id.as_bytes(), 0, b"x")
                .unwrap(),
        )),
        ProviderFailureCodeV1::InvalidRequest,
    );

    process.shutdown_and_assert_clean();
}

#[test]
fn object_session_wrong_chunk_order_cancels_session() {
    const CHUNK_BYTES: usize = 1_048_576;
    let plaintext_bytes = u64::try_from(CHUNK_BYTES * 2).unwrap();

    let mut process = ProviderProcess::start();
    let init = process.request_json(json!({"op": "init", "config": init_config()}));
    assert_eq!(init["status"], "ok");

    let open_request =
        open_object_request(0x92, "application/octet-stream", plaintext_bytes, nodes());
    let opened = typed_ok_response(process.request_json(wrap_runtime_request(&open_request)));
    assert_eq!(
        opened.status(),
        ProtectProviderResponseStatusV1::ObjectProtectionSessionOpened,
        "open failure_code={:?}",
        opened.failure_code()
    );

    let session_id = digest(0x92);
    let wrong_order_chunk = vec![0xaau8; CHUNK_BYTES];
    assert_failure_code(
        process.request_json(wrap_runtime_request(
            &ProtectProviderRequestV1::new_protect_object_chunk(session_id, 1, &wrong_order_chunk)
                .unwrap(),
        )),
        ProviderFailureCodeV1::InvalidRequest,
    );

    // The ordering error must have cancelled the whole session, not merely
    // rejected the one bad request: chunk 0 (which would be perfectly valid
    // on a live, freshly opened session) now finds no session at all.
    let first_chunk = vec![0xbbu8; CHUNK_BYTES];
    assert_failure_code(
        process.request_json(wrap_runtime_request(
            &ProtectProviderRequestV1::new_protect_object_chunk(session_id, 0, &first_chunk)
                .unwrap(),
        )),
        ProviderFailureCodeV1::HandleAbsent,
    );

    // The auto-cancel must also have cleared the stale open-replay cache
    // entry: a byte-identical re-open of the same session_id must open a
    // genuinely fresh session, not resurrect the cached response for the
    // session that was just cancelled.
    let reopened = typed_ok_response(process.request_json(wrap_runtime_request(&open_request)));
    assert_eq!(
        reopened.status(),
        ProtectProviderResponseStatusV1::ObjectProtectionSessionOpened,
        "reopen failure_code={:?}",
        reopened.failure_code()
    );
    let second_chunk = vec![0xddu8; CHUNK_BYTES];
    let second_chunk_response = typed_ok_response(process.request_json(wrap_runtime_request(
        &ProtectProviderRequestV1::new_protect_object_chunk(session_id, 0, &second_chunk).unwrap(),
    )));
    assert_eq!(
        second_chunk_response.status(),
        ProtectProviderResponseStatusV1::ObjectChunkProtected,
        "chunk 0 on reopened session failure_code={:?}",
        second_chunk_response.failure_code()
    );

    process.shutdown_and_assert_clean();
}

#[test]
fn object_session_open_rejects_a_non_2_of_3_threshold() {
    let mut process = ProviderProcess::start();
    let init = process.request_json(json!({"op": "init", "config": init_config()}));
    assert_eq!(init["status"], "ok");

    // 3-of-3 with exactly 3 nodes passes the contract's own validation
    // (nodes.len() == threshold_total), but provision_custody_envelope_for_exact_nodes
    // hard-codes a 2-of-3 threshold internally regardless of what is asked
    // for. Without an open-time check this would provision successfully and
    // silently hand back a lower-than-requested threshold; it must instead
    // be rejected here, at open, before any session or sealer is created.
    let request = ProtectProviderRequestV1::new_open_object_protection_session(
        digest(0x93),
        ContentAccessIdV1::new([0x41; 16]).unwrap(),
        CustodyPoolIdentityV1::new(digest(0x41), 32).unwrap(),
        CustodyEpochIdentityV1::new(digest(0x42), 32).unwrap(),
        CustodyCommitteeAuthorizationIdentityV1::new(digest(0x43), 32).unwrap(),
        3,
        3,
        "application/octet-stream",
        1_048_576,
        nodes(),
    )
    .unwrap();

    assert_failure_code(
        process.request_json(wrap_runtime_request(&request)),
        ProviderFailureCodeV1::InvalidRequest,
    );

    process.shutdown_and_assert_clean();
}

#[test]
fn object_session_finalize_rejects_mismatched_identity_without_provisioning() {
    const CHUNK_BYTES: usize = 1_048_576;
    let plaintext_bytes = u64::try_from(CHUNK_BYTES).unwrap();

    let mut process = ProviderProcess::start();
    let init = process.request_json(json!({"op": "init", "config": init_config()}));
    assert_eq!(init["status"], "ok");

    let open_request =
        open_object_request(0x94, "application/octet-stream", plaintext_bytes, nodes());
    let opened = typed_ok_response(process.request_json(wrap_runtime_request(&open_request)));
    assert_eq!(
        opened.status(),
        ProtectProviderResponseStatusV1::ObjectProtectionSessionOpened,
        "open failure_code={:?}",
        opened.failure_code()
    );

    let session_id = digest(0x94);
    let chunk = vec![0xccu8; CHUNK_BYTES];
    let chunk_response = typed_ok_response(process.request_json(wrap_runtime_request(
        &ProtectProviderRequestV1::new_protect_object_chunk(session_id, 0, &chunk).unwrap(),
    )));
    assert_eq!(
        chunk_response.status(),
        ProtectProviderResponseStatusV1::ObjectChunkProtected,
        "chunk failure_code={:?}",
        chunk_response.failure_code()
    );

    // An identity that does not match what was actually sealed must be
    // rejected before anything is provisioned.
    let wrong_identity =
        EncryptedContentIdentityV1::new(Digest32::new([0xffu8; 32]), plaintext_bytes).unwrap();
    assert_failure_code(
        process.request_json(wrap_runtime_request(
            &ProtectProviderRequestV1::new_finalize_object_protection_session(
                session_id,
                &wrong_identity,
            )
            .unwrap(),
        )),
        ProviderFailureCodeV1::BindingMismatch,
    );

    // Nothing was provisioned: the mismatch must have cancelled the whole
    // session, so even a second finalize attempt (with the same, still-
    // wrong identity — there is no sealer left to retry into regardless of
    // what is declared) finds the handle already closed rather than a
    // lingering, retryable session — the same idempotent "already absent"
    // vocabulary media's finalize arm uses for a closed handle, not a
    // fresh failure.
    let second_attempt = typed_ok_response(
        process.request_json(wrap_runtime_request(
            &ProtectProviderRequestV1::new_finalize_object_protection_session(
                session_id,
                &wrong_identity,
            )
            .unwrap(),
        )),
    );
    assert_eq!(
        second_attempt.status(),
        ProtectProviderResponseStatusV1::ProtectionSessionAlreadyAbsent
    );

    process.shutdown_and_assert_clean();
}

const DASH_TIMESCALE: u32 = 15360;

fn dash_bx(box_type: &[u8; 4], content: &[u8]) -> Vec<u8> {
    let mut out = ((8 + content.len()) as u32).to_be_bytes().to_vec();
    out.extend_from_slice(box_type);
    out.extend_from_slice(content);
    out
}

fn dash_fbx(box_type: &[u8; 4], version: u8, flags: u32, payload: &[u8]) -> Vec<u8> {
    let mut content = vec![version];
    content.extend_from_slice(&flags.to_be_bytes()[1..]);
    content.extend_from_slice(payload);
    dash_bx(box_type, &content)
}

fn dash_init(kind: CencDashRenditionKindV2) -> Vec<u8> {
    let mut tkhd = vec![0u8; 12];
    tkhd[8..12].copy_from_slice(&1u32.to_be_bytes());
    let mut mdhd = vec![0u8; 20];
    mdhd[8..12].copy_from_slice(&DASH_TIMESCALE.to_be_bytes());
    let (handler, entry_type, entry) = match kind {
        CencDashRenditionKindV2::Video => {
            let mut entry = vec![0u8; 78];
            entry[24..26].copy_from_slice(&640u16.to_be_bytes());
            entry[26..28].copy_from_slice(&360u16.to_be_bytes());
            entry.extend_from_slice(&dash_bx(b"avcC", &[1, 0x64, 0, 0x1f, 0xff, 0xe0, 0]));
            (b"vide", b"avc1", entry)
        }
        CencDashRenditionKindV2::Audio => {
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
    stsd.extend_from_slice(&dash_bx(entry_type, &entry));
    let minf = dash_bx(b"minf", &dash_bx(b"stbl", &dash_bx(b"stsd", &stsd)));
    let mdia = dash_bx(
        b"mdia",
        &[
            dash_fbx(b"mdhd", 0, 0, &mdhd),
            dash_fbx(b"hdlr", 0, 0, &hdlr),
            minf,
        ]
        .concat(),
    );
    let trak = dash_bx(b"trak", &[dash_fbx(b"tkhd", 0, 0, &tkhd), mdia].concat());
    let mut trex = 1u32.to_be_bytes().to_vec();
    trex.extend_from_slice(&[0u8; 16]);
    let moov = dash_bx(
        b"moov",
        &[
            dash_bx(b"mvhd", &[0u8; 4]),
            trak,
            dash_bx(b"mvex", &dash_fbx(b"trex", 0, 0, &trex)),
        ]
        .concat(),
    );
    [dash_bx(b"ftyp", b"iso6\0\0\0\0iso6dash"), moov].concat()
}

fn dash_nal(nal_type: u8, len: usize) -> Vec<u8> {
    let mut out = (len as u32).to_be_bytes().to_vec();
    out.push(0x60 | nal_type);
    out.extend((1..len).map(|index| (index * 7 + 3) as u8));
    out
}

fn dash_fragment(decode_time: u64, samples: &[Vec<u8>]) -> Vec<u8> {
    let mut tfhd = 1u32.to_be_bytes().to_vec();
    tfhd.extend_from_slice(&1u32.to_be_bytes());
    tfhd.extend_from_slice(&512u32.to_be_bytes());
    tfhd.extend_from_slice(&0u32.to_be_bytes());
    let mut trun = (samples.len() as u32).to_be_bytes().to_vec();
    trun.extend_from_slice(&0i32.to_be_bytes());
    for sample in samples {
        trun.extend_from_slice(&(sample.len() as u32).to_be_bytes());
    }
    let tfhd = dash_fbx(b"tfhd", 0, 0x02002a, &tfhd);
    let tfdt = dash_fbx(b"tfdt", 1, 0, &decode_time.to_be_bytes());
    let trun = dash_fbx(b"trun", 0, 0x000201, &trun);
    let trun_off = 8 + 16 + 8 + tfhd.len() + tfdt.len();
    let traf = dash_bx(b"traf", &[tfhd, tfdt, trun].concat());
    let mut moof = dash_bx(
        b"moof",
        &[dash_fbx(b"mfhd", 0, 0, &1u32.to_be_bytes()), traf].concat(),
    );
    let data_offset = (moof.len() + 8) as i32;
    moof[trun_off + 16..trun_off + 20].copy_from_slice(&data_offset.to_be_bytes());
    [moof, dash_bx(b"mdat", &samples.concat())].concat()
}

fn dash_video_segment(index: usize) -> Vec<u8> {
    let sample = |slice: usize| {
        [
            dash_nal(6, 30),
            dash_nal(5, slice),
            dash_nal(1, slice / 2),
            dash_nal(1, 100),
        ]
        .concat()
    };
    dash_fragment(30_720 * index as u64, &[sample(300 + index), sample(200)])
}

fn dash_audio_segment(index: usize) -> Vec<u8> {
    let audio = |seed: u8, len: usize| -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
    };
    dash_fragment(30_720 * index as u64, &[audio(1, 120), audio(9, 121)])
}

fn dash_open_request() -> ProtectProviderRequestV1 {
    let representation = |kind, mime, codecs| {
        ProtectionRepresentationV2::new(kind, mime, codecs, 2, &dash_init(kind)).unwrap()
    };
    ProtectProviderRequestV1::new_open_protection_session_v2(
        digest(0x51),
        ContentAccessIdV1::new([0x41; 16]).unwrap(),
        CustodyPoolIdentityV1::new(digest(0x41), 32).unwrap(),
        CustodyEpochIdentityV1::new(digest(0x42), 32).unwrap(),
        CustodyCommitteeAuthorizationIdentityV1::new(digest(0x43), 32).unwrap(),
        vec![
            representation(CencDashRenditionKindV2::Video, "video/mp4", "avc1.640028"),
            representation(CencDashRenditionKindV2::Audio, "audio/mp4", "mp4a.40.2"),
        ],
        &[],
        nodes(),
    )
    .unwrap()
}

#[test]
fn process_v2_open_segments_finalize_is_framed_and_bound() {
    let mut process = ProviderProcess::start();
    let init = process.request_json(json!({"op": "init", "config": init_config()}));
    assert_eq!(init["status"], "ok");

    let opened =
        typed_ok_response(process.request_json(wrap_runtime_request(&dash_open_request())));
    assert_eq!(
        opened.status(),
        ProtectProviderResponseStatusV1::ProtectionSessionOpened,
        "open failure_code={:?}",
        opened.failure_code()
    );
    let handle = opened.protection_session_handle().unwrap().unwrap();
    assert_eq!(opened.protected_init_segments().unwrap().len(), 2);

    for (rendition, clear) in [
        (0u8, [dash_video_segment(0), dash_video_segment(1)]),
        (1u8, [dash_audio_segment(0), dash_audio_segment(1)]),
    ] {
        for (index, clear_segment) in clear.iter().enumerate() {
            let response = typed_ok_response(
                process.request_json(wrap_runtime_request(
                    &ProtectProviderRequestV1::new_protect_media_segment_v2(
                        handle,
                        rendition,
                        u32::try_from(index).unwrap(),
                        clear_segment,
                    )
                    .unwrap(),
                )),
            );
            assert_eq!(
                response.status(),
                ProtectProviderResponseStatusV1::MediaSegmentProtected,
                "{:?}",
                response.failure_code()
            );
        }
    }

    let finalized = typed_ok_response(process.request_json(wrap_runtime_request(
        &ProtectProviderRequestV1::new_finalize_protection_session(handle).unwrap(),
    )));
    assert_eq!(
        finalized.status(),
        ProtectProviderResponseStatusV1::ProtectionSessionFinalized
    );
    let head = finalized.media_identity_v2().unwrap().unwrap();
    assert_eq!(head.renditions().len(), 2);
    assert_eq!(finalized.media_identity().unwrap(), None);
    let envelope = finalized.custody_envelope().unwrap().unwrap();
    assert_eq!(
        envelope.manifest().encrypted_content(),
        head.encrypted_content()
    );

    process.shutdown_and_assert_clean();
}

#[test]
fn process_v2_too_many_slices_carries_its_reason_across_the_process_boundary() {
    let mut process = ProviderProcess::start();
    let init = process.request_json(json!({"op": "init", "config": init_config()}));
    assert_eq!(init["status"], "ok");
    let opened =
        typed_ok_response(process.request_json(wrap_runtime_request(&dash_open_request())));
    let handle = opened.protection_session_handle().unwrap().unwrap();

    let too_many = (0..41).flat_map(|_| dash_nal(1, 120)).collect::<Vec<u8>>();
    let response = process.request_json(wrap_runtime_request(
        &ProtectProviderRequestV1::new_protect_media_segment_v2(
            handle,
            0,
            0,
            &dash_fragment(0, &[too_many]),
        )
        .unwrap(),
    ));
    assert_eq!(response["status"], "ok");
    assert_eq!(
        response["data"]["failure_reason"],
        "cenc_too_many_subsamples"
    );
    let typed = typed_ok_response(response);
    assert_eq!(
        typed.failure_code(),
        Some(ProviderFailureCodeV1::InvalidRequest)
    );
    assert_eq!(
        typed.failure_reason(),
        Some(ProtectFailureReasonV2::CencTooManySubsamples)
    );

    process.shutdown_and_assert_clean();
}

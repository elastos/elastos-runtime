use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use ed25519_dalek::{Signer as _, SigningKey};
use elastos_protected_content_contracts::{
    CanonicalContract, ContentAccessIdV1, CustodyApprovedSuitesV1,
    CustodyCommitteeAuthorizationStatementV1, CustodyEnvelopeV1, CustodyEpochIdentityV1,
    CustodyEpochIssuerKeyV1, CustodyEpochStatementV1, CustodyNodeIdentityV1,
    CustodyNodeProvisioningRecordV1, CustodyPoolFailureDomainIdV1, CustodyPoolIdentityV1,
    CustodyPoolMemberStateV1, CustodyPoolMemberV1, CustodyPoolOperatorIdV1, CustodyPoolStatementV1,
    Digest32, EvmContractAddressV1, EvmFunctionSelectorV1, EvmRightsMethodAbiV1,
    KeyReleaseOutcomeV1, KeyReleaseRequestV1, NodeContributionRefV1, NodePublicKey,
    ProtectedContentBindingV1, RecipientKeyAuthorizationStatementV1, RecipientKeyIdentityV1,
    RecipientPublicKeyBytesV1, ReplayNonce16, RightsActionV1, RightsDecisionV1,
    RightsEvaluationEvidenceRequestV1, RightsObservationFinalityV1, RightsPolicyBodyV1,
    RightsRequestV1, RightsSubjectSourceV1, RuntimeCustodyProvisioningIdV1,
    RuntimeCustodyProvisioningStatementV1, RuntimeOperationIssuerKeyV1, RuntimeReleaseAuditIdV1,
    RuntimeReleaseOperationStatementV1, RuntimeSessionBindingV1, ShareCoordinateV1,
    SignedCustodyCommitteeAuthorizationV1, SignedCustodyEpochV1, SignedCustodyPoolV1,
    SignedNodeContributionV1, SignedRecipientKeyAuthorizationV1,
    SignedRuntimeCustodyProvisioningV1, SignedRuntimeReleaseOperationV1, SignedTerminalReceiptV1,
    TerminalReceiptIssuerKey, TerminalReceiptStatementV1, ThresholdV1, ValidatedCustodyCommitteeV1,
    WalletAddress, WalletSignedRightsRequestV1, CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
};
use elastos_protected_content_custody::{
    provision_custody_envelope, ContentEncryptionKeyV1, DurableReplayClaimStoreV1,
    NodeCustodySecretKeyV1, NodeLocalShareStoreV1, RecipientPublicKeyV1,
};
use elastos_protected_content_provider_contracts::CencFmp4MediaIdentityV1;
use k256::ecdsa::SigningKey as WalletSigningKey;
use sha3::{Digest as _, Keccak256};
use tempfile::TempDir;
use zeroize::Zeroizing;

pub const MEDIA_MIME_TYPE_V1: &str = "video/mp4";
pub const MEDIA_CODECS_V1: &str = "avc1.640028,mp4a.40.2";

pub fn issued_at(base_time: u64) -> u64 {
    base_time.saturating_sub(5)
}

pub fn digest(byte: u8) -> Digest32 {
    Digest32::new([byte; 32])
}

pub fn runtime_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn runtime_issuer(seed: u8) -> RuntimeOperationIssuerKeyV1 {
    RuntimeOperationIssuerKeyV1::new(runtime_signing_key(seed).verifying_key().to_bytes()).unwrap()
}

pub fn wallet(seed: u8) -> WalletAddress {
    let key = WalletSigningKey::from_slice(&[seed; 32]).unwrap();
    let encoded = key.verifying_key().to_encoded_point(false);
    let digest = Keccak256::digest(&encoded.as_bytes()[1..]);
    WalletAddress::new(digest[12..].try_into().unwrap())
}

pub fn node_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn node_public_key(seed: u8) -> NodePublicKey {
    NodePublicKey::new(node_signing_key(seed).verifying_key().to_bytes()).unwrap()
}

pub fn node_custody_secret(seed: u8) -> NodeCustodySecretKeyV1 {
    NodeCustodySecretKeyV1::from_guarded_bytes(Zeroizing::new([seed; 32])).unwrap()
}

fn make_box(box_type: &[u8; 4], content: &[u8]) -> Vec<u8> {
    let size = (8 + content.len()) as u32;
    let mut out = Vec::with_capacity(size as usize);
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(box_type);
    out.extend_from_slice(content);
    out
}

fn make_fullbox(box_type: &[u8; 4], flags: u32, payload: &[u8]) -> Vec<u8> {
    let mut content = vec![0u8];
    content.extend_from_slice(&flags.to_be_bytes()[1..]);
    content.extend_from_slice(payload);
    make_box(box_type, &content)
}

fn make_sinf(original_fourcc: &[u8; 4]) -> Vec<u8> {
    let frma = make_box(b"frma", original_fourcc);
    let mut schm_payload = Vec::new();
    schm_payload.extend_from_slice(b"cenc");
    schm_payload.extend_from_slice(&0x0001_0000u32.to_be_bytes());
    let schm = make_fullbox(b"schm", 0, &schm_payload);
    let mut tenc_payload = vec![0, 0, 1, 8];
    tenc_payload.extend_from_slice(&[0x44; 16]);
    let tenc = make_fullbox(b"tenc", 0, &tenc_payload);
    let schi = make_box(b"schi", &tenc);
    let mut sinf_content = Vec::new();
    sinf_content.extend_from_slice(&frma);
    sinf_content.extend_from_slice(&schm);
    sinf_content.extend_from_slice(&schi);
    make_box(b"sinf", &sinf_content)
}

fn make_track(track_id: u32, handler_type: &[u8; 4]) -> Vec<u8> {
    let mut tkhd_payload = vec![0u8; 12];
    tkhd_payload[8..12].copy_from_slice(&track_id.to_be_bytes());
    let tkhd = make_fullbox(b"tkhd", 0, &tkhd_payload);
    let mut hdlr_payload = vec![0u8; 4];
    hdlr_payload.extend_from_slice(handler_type);
    let hdlr = make_fullbox(b"hdlr", 0, &hdlr_payload);
    let (entry_type, orig_type, fixed) = match handler_type {
        b"vide" => (b"encv", b"avc1", 78usize),
        b"soun" => (b"enca", b"mp4a", 28usize),
        _ => panic!("unsupported handler"),
    };
    let mut entry_content = vec![0u8; fixed];
    entry_content.extend_from_slice(&make_sinf(orig_type));
    let entry = make_box(entry_type, &entry_content);
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

fn make_segment(track_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut tfhd_payload = Vec::new();
    tfhd_payload.extend_from_slice(&track_id.to_be_bytes());
    tfhd_payload.extend_from_slice(&1u32.to_be_bytes());
    tfhd_payload.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    tfhd_payload.extend_from_slice(&0u32.to_be_bytes());
    let tfhd = make_fullbox(b"tfhd", 0x020038, &tfhd_payload);
    let tfdt = make_fullbox(b"tfdt", 0, &1u32.to_be_bytes());
    let mut trun_payload = Vec::new();
    trun_payload.extend_from_slice(&1u32.to_be_bytes());
    trun_payload.extend_from_slice(&0i32.to_be_bytes());
    trun_payload.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    let trun = make_fullbox(b"trun", 0x000201, &trun_payload);
    let mut senc_payload = Vec::new();
    senc_payload.extend_from_slice(&1u32.to_be_bytes());
    senc_payload.extend_from_slice(&(0x10u64 + u64::from(track_id)).to_be_bytes());
    let senc = make_fullbox(b"senc", 0, &senc_payload);
    let mut traf_content = Vec::new();
    traf_content.extend_from_slice(&tfhd);
    traf_content.extend_from_slice(&tfdt);
    traf_content.extend_from_slice(&trun);
    traf_content.extend_from_slice(&senc);
    let traf = make_box(b"traf", &traf_content);
    let mfhd = make_fullbox(b"mfhd", 0, &1u32.to_be_bytes());
    let mut moof_content = Vec::new();
    moof_content.extend_from_slice(&mfhd);
    moof_content.extend_from_slice(&traf);
    let mut moof = make_box(b"moof", &moof_content);
    let data_offset = (moof.len() + 8) as i32;
    let trun_offset = moof
        .windows(4)
        .position(|window| window == b"trun")
        .unwrap()
        - 4;
    let trun_data_offset_at = trun_offset + 16;
    moof[trun_data_offset_at..trun_data_offset_at + 4].copy_from_slice(&data_offset.to_be_bytes());
    let mdat = make_box(b"mdat", payload);
    let mut out = moof;
    out.extend_from_slice(&mdat);
    out
}

pub fn media_components(seed: u8) -> (Vec<u8>, Vec<Vec<u8>>, &'static str, &'static str) {
    media_components_with_pssh(seed, None)
}

/// [`media_components`] whose init carries `pssh` (a whole custody `pssh` box)
/// as the last child of `moov` (Plan B T3.5). The encrypted segments are the
/// same with or without it.
pub fn media_components_with_pssh(
    seed: u8,
    pssh: Option<&[u8]>,
) -> (Vec<u8>, Vec<Vec<u8>>, &'static str, &'static str) {
    let ftyp = make_box(b"ftyp", b"isom\0\0\0\0isomiso6");
    let trak_video = make_track(1, b"vide");
    let trak_audio = make_track(2, b"soun");
    let trex_video = make_fullbox(
        b"trex",
        0,
        &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    let trex_audio = make_fullbox(
        b"trex",
        0,
        &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    let mut mvex_content = Vec::new();
    mvex_content.extend_from_slice(&trex_video);
    mvex_content.extend_from_slice(&trex_audio);
    let mvex = make_box(b"mvex", &mvex_content);
    let mvhd = make_box(b"mvhd", &[0u8; 4]);
    let mut moov_content = Vec::new();
    moov_content.extend_from_slice(&mvhd);
    moov_content.extend_from_slice(&trak_video);
    moov_content.extend_from_slice(&trak_audio);
    moov_content.extend_from_slice(&mvex);
    if let Some(pssh) = pssh {
        moov_content.extend_from_slice(pssh);
    }
    let moov = make_box(b"moov", &moov_content);
    let encrypted_segments = [0usize, 1]
        .into_iter()
        .map(|index| {
            let track_id = if index % 2 == 0 { 1 } else { 2 };
            let payload = vec![
                seed,
                track_id as u8,
                (index & 0xff) as u8,
                ((index >> 8) & 0xff) as u8,
                b's',
                b'e',
                b'g',
                b'x',
            ];
            make_segment(track_id, &payload)
        })
        .collect();
    (
        [ftyp, moov].concat(),
        encrypted_segments,
        MEDIA_MIME_TYPE_V1,
        MEDIA_CODECS_V1,
    )
}

pub fn media_identity(seed: u8) -> CencFmp4MediaIdentityV1 {
    let (init_segment, encrypted_segments, mime_type, codecs) = media_components(seed);
    CencFmp4MediaIdentityV1::new_from_bytes(&init_segment, &encrypted_segments, mime_type, codecs)
        .unwrap()
}

pub fn policy_body() -> RightsPolicyBodyV1 {
    policy_body_for(media_identity(0x10).encrypted_content().clone())
}

/// [`policy_body`] for another item (Plan B T3.1: V2 items of each kind).
#[allow(dead_code)]
pub fn policy_body_for(
    encrypted_content: elastos_protected_content_contracts::EncryptedContentIdentityV1,
) -> RightsPolicyBodyV1 {
    policy_body_for_kid(encrypted_content, [0x44; 16])
}

/// [`policy_body_for`] with another content access id (Plan B T3.5).
#[allow(dead_code)]
pub fn policy_body_for_kid(
    encrypted_content: elastos_protected_content_contracts::EncryptedContentIdentityV1,
    kid: [u8; 16],
) -> RightsPolicyBodyV1 {
    RightsPolicyBodyV1::new(
        encrypted_content,
        ContentAccessIdV1::new(kid).unwrap(),
        RightsActionV1::View,
        RightsSubjectSourceV1::WalletAddress,
        11155111,
        EvmContractAddressV1::new([0x11; 20]).unwrap(),
        EvmFunctionSelectorV1::new([0x12, 0x34, 0x56, 0x78]).unwrap(),
        EvmRightsMethodAbiV1::HasAccessByContentIdAddressBytes16,
        RightsObservationFinalityV1::finalized(),
    )
    .unwrap()
}

fn custody_pool_member(node_seed: u8, custody_seed: u8, base_time: u64) -> CustodyPoolMemberV1 {
    CustodyPoolMemberV1::new(
        node_public_key(node_seed),
        node_custody_secret(custody_seed).public_key().unwrap(),
        CustodyPoolOperatorIdV1::new([0x80 + node_seed; 32]),
        CustodyPoolFailureDomainIdV1::new([0x90 + node_seed; 32]),
        CustodyApprovedSuitesV1::new(
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        )
        .unwrap(),
        (issued_at(base_time), base_time + 600),
        CustodyPoolMemberStateV1::Active,
    )
    .unwrap()
}

pub fn signed_custody_pool(base_time: u64) -> SignedCustodyPoolV1 {
    let issuer_key = SigningKey::from_bytes(&[0x71; 32]);
    let statement = CustodyPoolStatementV1::new(
        CustodyEpochIssuerKeyV1::new(issuer_key.verifying_key().to_bytes()).unwrap(),
        vec![
            custody_pool_member(1, 1, base_time),
            custody_pool_member(2, 2, base_time),
            custody_pool_member(3, 3, base_time),
        ],
    )
    .unwrap();
    SignedCustodyPoolV1::new(
        statement.clone(),
        issuer_key
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

pub fn signed_custody_epoch() -> SignedCustodyEpochV1 {
    let issuer_key = SigningKey::from_bytes(&[0x71; 32]);
    let statement = CustodyEpochStatementV1::new(
        CustodyEpochIssuerKeyV1::new(issuer_key.verifying_key().to_bytes()).unwrap(),
        CustodyApprovedSuitesV1::new(
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        )
        .unwrap(),
        ThresholdV1::new(2, 3).unwrap(),
        vec![
            CustodyNodeIdentityV1::new(
                node_public_key(1),
                node_custody_secret(1).public_key().unwrap(),
                ShareCoordinateV1::new(1).unwrap(),
            )
            .unwrap(),
            CustodyNodeIdentityV1::new(
                node_public_key(2),
                node_custody_secret(2).public_key().unwrap(),
                ShareCoordinateV1::new(2).unwrap(),
            )
            .unwrap(),
            CustodyNodeIdentityV1::new(
                node_public_key(3),
                node_custody_secret(3).public_key().unwrap(),
                ShareCoordinateV1::new(3).unwrap(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    SignedCustodyEpochV1::new(
        statement.clone(),
        issuer_key
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

pub fn signed_committee_authorization(
    pool_identity: CustodyPoolIdentityV1,
    epoch_identity: CustodyEpochIdentityV1,
) -> SignedCustodyCommitteeAuthorizationV1 {
    let issuer_key = SigningKey::from_bytes(&[0x71; 32]);
    let statement = CustodyCommitteeAuthorizationStatementV1::new(
        CustodyEpochIssuerKeyV1::new(issuer_key.verifying_key().to_bytes()).unwrap(),
        pool_identity,
        epoch_identity,
    )
    .unwrap();
    SignedCustodyCommitteeAuthorizationV1::new(
        statement.clone(),
        issuer_key
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

pub fn validated_custody_committee(base_time: u64) -> ValidatedCustodyCommitteeV1 {
    let issuer_key = SigningKey::from_bytes(&[0x71; 32]);
    let issuer = CustodyEpochIssuerKeyV1::new(issuer_key.verifying_key().to_bytes()).unwrap();
    let pool = signed_custody_pool(base_time);
    let epoch = signed_custody_epoch();
    let authorization = signed_committee_authorization(
        pool.pool_identity().unwrap(),
        epoch.epoch_identity().unwrap(),
    );
    elastos_protected_content_contracts::validate_custody_epoch_against_pool_at(
        issuer,
        authorization.authorization_identity().unwrap(),
        &pool,
        &epoch,
        &authorization,
        base_time,
    )
    .unwrap()
}

pub fn custody_envelope_for_media(seed: u8, base_time: u64) -> CustodyEnvelopeV1 {
    let encrypted_content = media_identity(seed).encrypted_content().clone();
    let content_key = ContentEncryptionKeyV1::generate().unwrap();
    provision_custody_envelope(
        encrypted_content,
        &content_key,
        &validated_custody_committee(base_time),
    )
    .unwrap()
}

/// Seal `chunks` as a real EPC1 object via the same
/// `elastos-protected-content-custody` streaming sealer the protect-provider
/// capsule drives, and provision a custody envelope for the exact content
/// key the sealer generated — so, unlike [`custody_envelope_for_media`]
/// above (whose fixture bytes are never actually encrypted under the
/// envelope's key, since the media decrypt path's tests only assert box
/// structure, not exact plaintext), the returned framed header/chunks and
/// envelope are genuinely consistent: reconstructing the content key from
/// this envelope's custody flow and feeding it to `PayloadChunkDecrypterV1`
/// will decrypt these exact framed chunks back to `chunks` byte-for-byte.
/// Returns `(framed_header, framed_chunks, object_identity, envelope)`.
///
/// This module is compiled twice — once as `tests/process.rs`'s `mod
/// support`, once as `src/lib.rs`'s `#[path] mod support` for its own
/// inline `#[cfg(test)]` module — and only the former calls this helper, so
/// the latter compilation sees it as dead code.
#[allow(dead_code)]
pub fn object_components(
    content_type: &str,
    chunks: &[Vec<u8>],
    base_time: u64,
) -> (
    Vec<u8>,
    Vec<Vec<u8>>,
    elastos_protected_content_provider_contracts::ChunkedPayloadObjectIdentityV1,
    CustodyEnvelopeV1,
) {
    object_components_for(
        content_type,
        chunks,
        &validated_custody_committee(base_time),
    )
}

/// [`object_components`] kept by another committee (Plan B T3.1: the V2
/// pool fixture's committee).
#[allow(dead_code)]
pub fn object_components_for(
    content_type: &str,
    chunks: &[Vec<u8>],
    committee: &ValidatedCustodyCommitteeV1,
) -> (
    Vec<u8>,
    Vec<Vec<u8>>,
    elastos_protected_content_provider_contracts::ChunkedPayloadObjectIdentityV1,
    CustodyEnvelopeV1,
) {
    let plaintext_bytes: u64 = chunks.iter().map(|chunk| chunk.len() as u64).sum();
    let (mut sealer, framed_header) =
        elastos_protected_content_custody::PayloadSealerV1::open(content_type, plaintext_bytes)
            .unwrap();
    let framed_chunks: Vec<Vec<u8>> = chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            sealer
                .seal_chunk(u32::try_from(index).unwrap(), chunk)
                .unwrap()
        })
        .collect();
    let metadata = sealer.finish(committee).unwrap();
    let object_identity =
        elastos_protected_content_provider_contracts::ChunkedPayloadObjectIdentityV1::new(
            metadata.encrypted_content_identity().clone(),
            content_type,
            plaintext_bytes,
            u32::try_from(framed_header.len()).unwrap(),
        )
        .unwrap();
    (
        framed_header,
        framed_chunks,
        object_identity,
        metadata.custody_envelope().clone(),
    )
}

pub fn binding_for_envelope(envelope: &CustodyEnvelopeV1) -> ProtectedContentBindingV1 {
    let policy = policy_body();
    ProtectedContentBindingV1::new(
        envelope.manifest().encrypted_content().clone(),
        envelope.key_envelope_identity().unwrap(),
        policy.policy_identity().unwrap(),
        elastos_protected_content_contracts::ProfileIdentityV1::from_public_key_bytes(
            SigningKey::from_bytes(&[0x26; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
        wallet(7),
        RuntimeSessionBindingV1::new(digest(0x66)).unwrap(),
    )
    .unwrap()
}

pub fn make_signed_runtime_release_operation(
    runtime_seed: u8,
    audit_request_id: RuntimeReleaseAuditIdV1,
    envelope: &CustodyEnvelopeV1,
    recipient_public_key: RecipientPublicKeyBytesV1,
    recipient_identity: RecipientKeyIdentityV1,
    base_time: u64,
) -> SignedRuntimeReleaseOperationV1 {
    let runtime_key = runtime_signing_key(runtime_seed);
    let binding = binding_for_envelope(envelope);
    let rights_request = {
        let request = RightsRequestV1::new(
            binding.clone(),
            RightsActionV1::View,
            recipient_identity.clone(),
            issued_at(base_time),
            base_time + 180,
            ReplayNonce16::new([0x55; 16]),
        )
        .unwrap();
        let key = WalletSigningKey::from_slice(&[7; 32]).unwrap();
        let (signature, recovery_id) = key
            .sign_prehash_recoverable(&request.signing_hash().unwrap())
            .unwrap();
        let mut signature_bytes = signature.to_bytes().to_vec();
        signature_bytes.push(recovery_id.to_byte());
        WalletSignedRightsRequestV1::new(request, signature_bytes).unwrap()
    };
    let release_request = KeyReleaseRequestV1::new(
        binding.clone(),
        rights_request.request().request_hash().unwrap(),
        RightsActionV1::View,
        recipient_identity.clone(),
        issued_at(base_time),
        base_time + 50,
        ReplayNonce16::new([0x66; 16]),
    )
    .unwrap();
    let profile = SigningKey::from_bytes(&[0x26; 32]);
    let authorization_statement = RecipientKeyAuthorizationStatementV1::new(
        binding.clone(),
        RightsActionV1::View,
        recipient_public_key,
        recipient_identity,
        runtime_issuer(runtime_seed),
        issued_at(base_time),
        base_time + 180,
    )
    .unwrap();
    let authorization = SignedRecipientKeyAuthorizationV1::new(
        authorization_statement.clone(),
        profile
            .sign(&authorization_statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let policy = policy_body();
    let evidence_request =
        RightsEvaluationEvidenceRequestV1::new(binding.clone(), policy.policy_identity().unwrap())
            .unwrap();
    let statement = RuntimeReleaseOperationStatementV1::new(
        runtime_issuer(runtime_seed),
        rights_request,
        release_request,
        recipient_public_key,
        authorization,
        policy,
        evidence_request,
        signed_custody_epoch(),
        audit_request_id,
        issued_at(base_time),
        base_time + 40,
    )
    .unwrap();
    SignedRuntimeReleaseOperationV1::new(
        statement.clone(),
        runtime_key
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn make_signed_node_rights_decision(
    operation: &SignedRuntimeReleaseOperationV1,
    node_seed: u8,
    base_time: u64,
) -> elastos_protected_content_contracts::SignedNodeRightsDecisionV1 {
    let authenticated = operation
        .verify(operation.statement().runtime_operation_issuer(), base_time)
        .unwrap();
    let statement = elastos_protected_content_contracts::NodeRightsDecisionStatementV1::new(
        authenticated.release_request_hash(),
        authenticated.rights_request_hash(),
        authenticated.binding().clone(),
        authenticated.action(),
        node_public_key(node_seed),
        RightsDecisionV1::Allowed,
        digest(0x80 ^ node_seed),
        issued_at(base_time),
        base_time + 50,
    )
    .unwrap();
    elastos_protected_content_contracts::SignedNodeRightsDecisionV1::new(
        statement.clone(),
        node_signing_key(node_seed)
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

pub fn signed_runtime_provisioning_for_record(
    record: &CustodyNodeProvisioningRecordV1,
    runtime_seed: u8,
    base_time: u64,
) -> SignedRuntimeCustodyProvisioningV1 {
    let statement = RuntimeCustodyProvisioningStatementV1::new(
        runtime_issuer(runtime_seed),
        record.record_identity().unwrap(),
        RuntimeCustodyProvisioningIdV1::new(digest(
            0xc0 ^ record.selected_node_public_key().as_bytes()[0],
        ))
        .unwrap(),
        issued_at(base_time),
        base_time + 30,
    )
    .unwrap();
    SignedRuntimeCustodyProvisioningV1::new(
        statement.clone(),
        runtime_signing_key(runtime_seed)
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

pub fn tighten_tempdir_permissions(tempdir: &TempDir) {
    #[cfg(unix)]
    {
        fs::set_permissions(tempdir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
}

pub fn make_signed_node_contribution(
    operation: &SignedRuntimeReleaseOperationV1,
    envelope: &CustodyEnvelopeV1,
    runtime_seed: u8,
    node_seed: u8,
    base_time: u64,
) -> SignedNodeContributionV1 {
    let authenticated = operation
        .verify(operation.statement().runtime_operation_issuer(), base_time)
        .unwrap();
    let decision = make_signed_node_rights_decision(operation, node_seed, base_time);
    let record = CustodyNodeProvisioningRecordV1::new(
        envelope.key_envelope_identity().unwrap(),
        envelope.manifest().clone(),
        node_public_key(node_seed),
        envelope
            .stored_share_for_node(node_public_key(node_seed))
            .unwrap()
            .clone(),
    )
    .unwrap();
    let signed_provisioning =
        signed_runtime_provisioning_for_record(&record, runtime_seed, base_time);
    let node_secret = node_custody_secret(node_seed);
    let tempdir = TempDir::new().unwrap();
    tighten_tempdir_permissions(&tempdir);
    let node_share_store = NodeLocalShareStoreV1::new(
        node_public_key(node_seed),
        tempdir.path().join("share-store"),
    );
    let provisioned = node_share_store
        .provision_node_share(
            &record,
            &signed_provisioning,
            runtime_issuer(runtime_seed),
            &node_secret,
            base_time,
        )
        .unwrap();
    let recipient_public_key =
        RecipientPublicKeyV1::new(*operation.statement().recipient_public_key().as_bytes())
            .unwrap();
    let mut replay_store = DurableReplayClaimStoreV1::new(
        node_public_key(node_seed),
        tempdir.path().join("replay-store"),
    );
    replay_store
        .claim_or_replay_node_contribution(
            authenticated,
            &decision,
            provisioned.node_share(),
            &node_signing_key(node_seed),
            &node_secret,
            &recipient_public_key,
            issued_at(base_time),
            base_time + 40,
            base_time,
        )
        .unwrap()
}

pub fn make_signed_terminal_receipt(
    operation: &SignedRuntimeReleaseOperationV1,
    contributions: &[SignedNodeContributionV1],
    issuer_seed: u8,
    base_time: u64,
) -> SignedTerminalReceiptV1 {
    let authenticated = operation
        .verify(operation.statement().runtime_operation_issuer(), base_time)
        .unwrap();
    let node_set = signed_custody_epoch().statement().node_set().unwrap();
    let verified_contributions = contributions
        .iter()
        .map(|contribution| {
            authenticated
                .verify_node_contribution(contribution, &node_set, base_time)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let refs = verified_contributions
        .iter()
        .map(NodeContributionRefV1::from)
        .collect::<Vec<_>>();
    let issuer_key = SigningKey::from_bytes(&[issuer_seed; 32]);
    let statement = TerminalReceiptStatementV1::new(
        authenticated.release_request_hash(),
        authenticated.binding().clone(),
        TerminalReceiptIssuerKey::new(issuer_key.verifying_key().to_bytes()).unwrap(),
        KeyReleaseOutcomeV1::Released,
        refs,
        issued_at(base_time),
        base_time + 40,
    )
    .unwrap();
    SignedTerminalReceiptV1::new(
        statement.clone(),
        issuer_key
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

/// Real DASH v2 media for the decrypt provider: the clear fMP4 builders are
/// copied from the custody crate's `v2_test_media` (a `cfg(test)` module that
/// is not reachable from here), then really protected with the CEK that the
/// custody envelope is provisioned for, so reads can assert exact clear bytes.
///
/// This file is compiled twice (lib tests and process tests); helpers used by
/// only one side would otherwise warn as dead code.
#[allow(dead_code)]
pub mod dash {
    use super::*;
    use elastos_protected_content_contracts::CustodyEpochIdentityV1;
    use elastos_protected_content_custody::{
        protect_validated_clear_fmp4_init_to_cenc_v2,
        protect_validated_clear_fmp4_segment_to_cenc_v2,
    };
    use elastos_protected_content_provider_contracts::{
        cenc_dash_merkle_audit_path, cenc_dash_segment_leaf_hash, CencDashMediaIdentityV2,
        CencDashRenditionBytesV2, CencDashRenditionKindV2, CencLayoutProfile, CencMediaSuite,
        CustodyProtectionHeader, ProtectionClass, ValidatedClearFmp4MediaSessionLayoutV1,
        PROTECTION,
    };
    use sha2::Sha256;

    pub const KID: [u8; 16] = [0x44; 16];
    pub const TIMESCALE: u32 = 15360;
    pub const V: CencDashRenditionKindV2 = CencDashRenditionKindV2::Video;
    pub const A: CencDashRenditionKindV2 = CencDashRenditionKindV2::Audio;
    const DEFAULT_DURATION: u32 = 512;
    const TFHD_FLAGS_BENTO4: u32 = 0x02002a;
    const TRUN_FLAGS_OFFSET_SIZE: u32 = 0x000201;

    pub fn bx(box_type: &[u8; 4], content: &[u8]) -> Vec<u8> {
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

    /// A one-track clear init: `avc1` (640x360, `avcC` NAL length 4) or `mp4a`.
    pub fn init(kind: CencDashRenditionKindV2, track_id: u32) -> Vec<u8> {
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
    pub fn nal(nal_type: u8, len: usize) -> Vec<u8> {
        let mut out = (len as u32).to_be_bytes().to_vec();
        out.push(0x60 | nal_type);
        out.extend((1..len).map(|index| (index * 7 + 3) as u8));
        out
    }

    /// `moof(mfhd, traf(tfhd tfdt trun))` + `mdat(samples)` with Bento4's `tfhd`.
    pub fn clear_segment(track_id: u32, decode_time: u64, samples: &[Vec<u8>]) -> Vec<u8> {
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
    pub fn video_sample(slice_len: usize) -> Vec<u8> {
        [nal(6, 30), nal(5, slice_len), nal(1, 100)].concat()
    }

    pub fn audio_sample(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| seed.wrapping_add(index as u8))
            .collect()
    }

    /// The IV of the `counter`-th sample of a session: `prefix4 ‖ counter32`.
    pub fn iv(prefix: [u8; 4], counter: u32) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&prefix);
        out[4..].copy_from_slice(&counter.to_be_bytes());
        out
    }

    pub fn clear_session(
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

    /// `n` video segments of two samples each.
    pub fn video_segments(n: usize) -> Vec<Vec<u8>> {
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

    pub fn audio_segments(n: usize) -> Vec<Vec<u8>> {
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
    pub fn dash_proof(
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

    /// Removes the custody `pssh` child of `moov` (the box the registry
    /// classifies as custody) and fixes the `moov` size.
    pub fn strip_elastos_pssh(init: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < init.len() {
            let size = u32::from_be_bytes(init[at..at + 4].try_into().unwrap()) as usize;
            if &init[at + 4..at + 8] != b"moov" {
                out.extend_from_slice(&init[at..at + size]);
                at += size;
                continue;
            }
            let mut children: Vec<&[u8]> = Vec::new();
            let mut child = at + 8;
            while child < at + size {
                let child_size =
                    u32::from_be_bytes(init[child..child + 4].try_into().unwrap()) as usize;
                children.push(&init[child..child + child_size]);
                child += child_size;
            }
            let custody_pssh = children
                .iter()
                .position(|child| {
                    &child[4..8] == b"pssh"
                        && matches!(
                            PROTECTION
                                .registry()
                                .classify(child[12..28].try_into().unwrap()),
                            ProtectionClass::Custody(_)
                        )
                })
                .expect("a protected v2 init has a custody pssh box");
            children.remove(custody_pssh);
            out.extend_from_slice(&bx(b"moov", &children.concat()));
            at += size;
        }
        out
    }

    /// How a fixture deviates from the well-formed item.
    #[derive(Clone, Copy)]
    pub struct DashOptions {
        /// 1 (video only) or 2 (video and audio).
        pub renditions: usize,
        pub video_segments: usize,
        pub audio_segments: usize,
        /// The custody epoch byte of the audio init's Elastos header.
        pub audio_epoch: u8,
        pub strip_video_elastos: bool,
        /// Per rendition: write the init under the retired (decode-only) custody
        /// system instead of the writer's.
        pub retired_system: [bool; 2],
    }

    /// `init` with the writer's system id replaced by a registered custody system
    /// that is decode-only: an item minted before the writer binding changed.
    pub fn under_retired_system(init: &[u8]) -> Vec<u8> {
        let retired = PROTECTION
            .registry()
            .systems()
            .iter()
            .find(|system| system.is_custody() && !system.can_encode())
            .expect("a decode-only custody system is registered");
        let writer = PROTECTION.writer().id;
        let at = init
            .windows(16)
            .position(|window| window == writer.as_bytes())
            .expect("a protected v2 init carries the writer's custody box");
        let mut out = init.to_vec();
        out[at..at + 16].copy_from_slice(retired.id.as_bytes());
        out
    }

    impl Default for DashOptions {
        fn default() -> Self {
            Self {
                renditions: 2,
                video_segments: 2,
                audio_segments: 1,
                audio_epoch: 0,
                strip_video_elastos: false,
                retired_system: [false; 2],
            }
        }
    }

    pub struct DashComponents {
        pub head: CencDashMediaIdentityV2,
        pub clear_inits: Vec<Vec<u8>>,
        pub clear_segments: Vec<Vec<Vec<u8>>>,
        pub protected_inits: Vec<Vec<u8>>,
        pub protected_segments: Vec<Vec<Vec<u8>>>,
        pub envelope: CustodyEnvelopeV1,
    }

    /// The committee an item's Elastos header names and its envelope is
    /// provisioned for (Plan B T3.1: the V1 test committee or the V2 pool
    /// fixture's committee).
    pub struct DashCommittee {
        pub pool: elastos_protected_content_contracts::CustodyPoolIdentityV1,
        pub epoch: CustodyEpochIdentityV1,
        pub authorization:
            elastos_protected_content_contracts::CustodyCommitteeAuthorizationIdentityV1,
        pub committee: ValidatedCustodyCommitteeV1,
    }

    impl DashCommittee {
        /// The V1 test committee.
        pub fn v1(base_time: u64) -> Self {
            let pool = signed_custody_pool(base_time).pool_identity().unwrap();
            let epoch = signed_custody_epoch().epoch_identity().unwrap();
            let authorization = signed_committee_authorization(pool, epoch)
                .authorization_identity()
                .unwrap();
            Self {
                pool,
                epoch,
                authorization,
                committee: validated_custody_committee(base_time),
            }
        }
    }

    fn elastos_header(
        committee: &DashCommittee,
        epoch_override: Option<u8>,
    ) -> CustodyProtectionHeader {
        let pool = committee.pool;
        let epoch = committee.epoch;
        let authorization = committee.authorization;
        let epoch = match epoch_override {
            Some(byte) => CustodyEpochIdentityV1::new(Digest32::new([byte; 32]), 512).unwrap(),
            None => epoch,
        };
        CustodyProtectionHeader::new(
            ContentAccessIdV1::new(KID).unwrap(),
            &pool,
            &epoch,
            &authorization,
            CencMediaSuite::DashV2,
        )
    }

    /// A video+audio item really protected under the CEK its envelope holds.
    pub fn media_dash_components(seed: u8, base_time: u64, options: DashOptions) -> DashComponents {
        media_dash_components_for(seed, &DashCommittee::v1(base_time), options)
    }

    /// [`media_dash_components`] whose header names and whose envelope is
    /// kept by `committee`.
    pub fn media_dash_components_for(
        seed: u8,
        committee: &DashCommittee,
        options: DashOptions,
    ) -> DashComponents {
        let cek = ContentEncryptionKeyV1::generate().unwrap();
        let mut clear_segments = vec![
            video_segments(options.video_segments),
            audio_segments(options.audio_segments),
        ];
        clear_segments.truncate(options.renditions);
        let kinds = [V, A];
        let headers = [
            elastos_header(committee, None),
            elastos_header(
                committee,
                (options.audio_epoch != 0).then_some(options.audio_epoch),
            ),
        ];
        let iv_prefix = [seed; 4];
        let mut counter = 0u32;
        let mut clear_inits = Vec::new();
        let mut protected_inits = Vec::new();
        let mut protected_segments = Vec::new();
        for (index, kind) in kinds.into_iter().enumerate().take(options.renditions) {
            let (session, clear_init) = clear_session(kind, 1);
            let mut protected_init = protect_validated_clear_fmp4_init_to_cenc_v2(
                &session,
                &clear_init,
                &headers[index],
                &[],
            )
            .unwrap();
            if index == 0 && options.strip_video_elastos {
                protected_init = strip_elastos_pssh(&protected_init);
            } else if options.retired_system[index] {
                protected_init = under_retired_system(&protected_init);
            }
            let mut segments = Vec::new();
            for clear in &clear_segments[index] {
                let layout = session.validate_segment(clear).unwrap();
                let ivs: Vec<[u8; 8]> = layout
                    .samples()
                    .iter()
                    .map(|_| {
                        counter += 1;
                        iv(iv_prefix, counter)
                    })
                    .collect();
                segments.push(
                    protect_validated_clear_fmp4_segment_to_cenc_v2(
                        &session, &layout, clear, &cek, &ivs,
                    )
                    .unwrap(),
                );
            }
            clear_inits.push(clear_init);
            protected_inits.push(protected_init);
            protected_segments.push(segments);
        }
        let bytes: Vec<CencDashRenditionBytesV2<'_>> = (0..options.renditions)
            .map(|index| CencDashRenditionBytesV2 {
                kind: kinds[index],
                timescale: TIMESCALE,
                init_segment: &protected_inits[index],
                segments: &protected_segments[index],
            })
            .collect();
        let head =
            CencDashMediaIdentityV2::new_from_bytes(ContentAccessIdV1::new(KID).unwrap(), &bytes)
                .unwrap();
        let envelope = provision_custody_envelope(
            head.encrypted_content().clone(),
            &cek,
            &committee.committee,
        )
        .unwrap();
        DashComponents {
            head,
            clear_inits,
            clear_segments,
            protected_inits,
            protected_segments,
            envelope,
        }
    }
}

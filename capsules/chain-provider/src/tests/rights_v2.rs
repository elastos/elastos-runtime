//! Plan B T1.6: finalized rights evidence for a V2 release operation. A V2
//! operation verifies by the issuer it declares; the configured Runtime issuer
//! (the owner-only rule, L7) stays on the V1 branch, with V1's 16 KiB cap. For
//! V2 the release slot of the evidence holds the operation hash (L1).

use super::*;
use elastos_protected_content_contracts::{
    CustodyCommitteeAuthorizationStatementV1, CustodyPoolFailureDomainIdV1,
    CustodyPoolMemberStateV1, CustodyPoolMemberV1, CustodyPoolOperatorIdV1, CustodyPoolStatementV1,
    DeliveryKeyIdentityV1, MintPolicyV1, PoolDescriptorStatementV3, PoolDidV1, PoolEpochBundleV1,
    PoolMemberRolesV1, PoolMemberRouteV2, PoolMemberV2, PoolMemberV3,
    PoolRecipientAttestationStatementV2, PoolSessionRecipientV1, PoolTrustModeV1, RightsError,
    RightsRequestV2, RuntimeReleaseOperationError, RuntimeReleaseOperationStatementV2,
    ServePolicyV1, SignedCustodyCommitteeAuthorizationV1, SignedCustodyPoolV1,
    SignedPoolDescriptorV3, SignedPoolRecipientAttestationV2, SignedRuntimeReleaseOperationV2,
    WalletSignedRightsRequestV2,
};

const T0: u64 = 2_000_000_000;
const POOL_AUTHORITY: u8 = 0x71;
const BLOCK_HASH: &str = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn sign(key: &SigningKey, bytes: &[u8]) -> Vec<u8> {
    key.sign(bytes).to_bytes().to_vec()
}

fn pool_authority() -> (SigningKey, CustodyEpochIssuerKeyV1) {
    let key = SigningKey::from_bytes(&[POOL_AUTHORITY; 32]);
    let issuer = CustodyEpochIssuerKeyV1::new(key.verifying_key().to_bytes()).unwrap();
    (key, issuer)
}

/// The item's committee: the custody pool of nodes 1–3, the existing 2-of-3
/// epoch fixture (same authority, same custody keys), and the authorization
/// that binds them.
fn item_bundle() -> PoolEpochBundleV1 {
    let (authority, issuer) = pool_authority();
    let suites = CustodyApprovedSuitesV1::new(
        CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
    )
    .unwrap();
    let members = (1..=3u8)
        .map(|seed| {
            CustodyPoolMemberV1::new(
                node_public_key(seed),
                node_custody_public_key(0x30 + seed),
                CustodyPoolOperatorIdV1::new([0xa0 + seed; 32]),
                CustodyPoolFailureDomainIdV1::new([0xc0 + seed; 32]),
                suites.clone(),
                (T0 - 10, T0 + 86_400),
                CustodyPoolMemberStateV1::Active,
            )
            .unwrap()
        })
        .collect();
    let pool_statement = CustodyPoolStatementV1::new(issuer, members).unwrap();
    let pool = SignedCustodyPoolV1::new(
        pool_statement.clone(),
        sign(&authority, &pool_statement.canonical_bytes().unwrap()),
    )
    .unwrap();
    let epoch = signed_custody_epoch();
    let authorization_statement = CustodyCommitteeAuthorizationStatementV1::new(
        issuer,
        pool.pool_identity().unwrap(),
        epoch.epoch_identity().unwrap(),
    )
    .unwrap();
    let authorization = SignedCustodyCommitteeAuthorizationV1::new(
        authorization_statement.clone(),
        sign(
            &authority,
            &authorization_statement.canonical_bytes().unwrap(),
        ),
    )
    .unwrap();
    PoolEpochBundleV1::new(pool, epoch, authorization).unwrap()
}

/// #388 A2: writers emit the v3 descriptor of a `WciOperated` pool, every
/// member slot empty.
fn pool_descriptor(bundle: &PoolEpochBundleV1) -> SignedPoolDescriptorV3 {
    let (authority, issuer) = pool_authority();
    let members = (1..=3u8)
        .map(|seed| {
            PoolMemberV2::new(
                node_public_key(seed),
                PoolMemberRolesV1 {
                    hold: true,
                    serve: true,
                    seal: false,
                },
                PoolMemberRouteV2::new(format!("did:key:z6MkPoolNode{seed:02x}")).unwrap(),
            )
            .and_then(|member| PoolMemberV3::new(member, Vec::new()))
            .unwrap()
        })
        .collect();
    let statement = PoolDescriptorStatementV3::new(
        PoolDidV1::from_issuer(issuer),
        1,
        vec![bundle.clone()],
        members,
        ServePolicyV1::DEFAULT,
        MintPolicyV1::owner_default(runtime_issuer(0x42)),
        T0 - 5,
        T0 + 86_400,
        PoolTrustModeV1::WciOperated,
    )
    .unwrap();
    SignedPoolDescriptorV3::new(
        statement.clone(),
        sign(&authority, &statement.canonical_bytes().unwrap()),
    )
    .unwrap()
}

/// The binding of an item kept by the pool committee.
fn binding_v2(
    policy: &RightsPolicyBodyV1,
    bundle: &PoolEpochBundleV1,
) -> ProtectedContentBindingV1 {
    let epoch = bundle.signed_epoch();
    let key_envelope = KeyEnvelopeIdentityV1::new(
        policy.encrypted_content().clone(),
        digest(0x33),
        512,
        epoch.statement().node_set().unwrap().node_set_id().unwrap(),
        epoch.statement().threshold(),
        bundle.signed_pool().pool_identity().unwrap(),
        epoch.epoch_identity().unwrap(),
        bundle
            .signed_committee_authorization()
            .authorization_identity()
            .unwrap(),
    )
    .unwrap();
    ProtectedContentBindingV1::new(
        policy.encrypted_content().clone(),
        key_envelope,
        policy.policy_identity().unwrap(),
        ProfileIdentityV1::from_public_key_bytes(
            SigningKey::from_bytes(&[0x43; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
        wallet_address(7),
        RuntimeSessionBindingV1::new(digest(0x77)).unwrap(),
    )
    .unwrap()
}

/// A V2 operation signed by Runtime `runtime_seed`, with one recipient that
/// pool node 1 vouches for.
fn signed_runtime_operation_v2_statement(
    policy: RightsPolicyBodyV1,
    runtime_seed: u8,
    wallet_signer_seed: u8,
) -> RuntimeReleaseOperationStatementV2 {
    signed_runtime_operation_v2_statement_over(
        policy,
        runtime_seed,
        wallet_signer_seed,
        |request| request.signing_message().unwrap(),
    )
}

/// The same operation, with the wallet's EIP-191 signature over `text` of
/// the rights request (ADV-01 G2 signs the old v1 layout through here).
fn signed_runtime_operation_v2_statement_over(
    policy: RightsPolicyBodyV1,
    runtime_seed: u8,
    wallet_signer_seed: u8,
    text: fn(&RightsRequestV2) -> String,
) -> RuntimeReleaseOperationStatementV2 {
    let bundle = item_bundle();
    let binding = binding_v2(&policy, &bundle);
    let (_, pool_issuer) = pool_authority();
    let runtime = runtime_issuer(runtime_seed);
    let rights_request = RightsRequestV2::new(
        binding.clone(),
        RightsActionV1::View,
        vec![recipient_identity(0x30)],
        DeliveryKeyIdentityV1::new(digest(0x5d)),
        T0,
        T0 + 180,
        ReplayNonce16::new([0x55; 16]),
        policy.chain_id(),
    )
    .unwrap();
    let (wallet_signature, recovery_id) = WalletSigningKey::from_slice(&[wallet_signer_seed; 32])
        .unwrap()
        .sign_prehash_recoverable(&elastos_auth::ethereum_signed_message_hash(
            text(&rights_request).as_bytes(),
        ))
        .unwrap();
    let mut wallet_signature_bytes = wallet_signature.to_bytes().to_vec();
    wallet_signature_bytes.push(recovery_id.to_byte());
    let signed_rights =
        WalletSignedRightsRequestV2::new(rights_request, wallet_signature_bytes).unwrap();
    let attestation_statement = PoolRecipientAttestationStatementV2::new(
        PoolDidV1::from_issuer(pool_issuer),
        bundle.signed_epoch().epoch_identity().unwrap(),
        node_public_key(1),
        binding.clone(),
        RightsActionV1::View,
        recipient_public_key(0x30),
        recipient_identity(0x30),
        runtime,
        T0,
        T0 + 200,
        PoolTrustModeV1::WciOperated,
        Vec::new(),
    )
    .unwrap();
    let attestation = SignedPoolRecipientAttestationV2::new(
        attestation_statement.clone(),
        sign(
            &SigningKey::from_bytes(&[1; 32]),
            &attestation_statement.canonical_bytes().unwrap(),
        ),
    )
    .unwrap();
    let evidence_request =
        RightsEvaluationEvidenceRequestV1::new(binding, policy.policy_identity().unwrap()).unwrap();
    RuntimeReleaseOperationStatementV2::new(
        runtime,
        signed_rights,
        vec![PoolSessionRecipientV1::new(recipient_public_key(0x30), attestation).unwrap()],
        policy,
        evidence_request,
        pool_descriptor(&bundle).into(),
        RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap(),
        T0 + 2,
        T0 + 40,
    )
    .unwrap()
}

fn signed_runtime_operation_v2(runtime_seed: u8) -> SignedRuntimeReleaseOperationV2 {
    signed_runtime_operation_v2_with_wallet_signer(runtime_seed, 7)
}

/// A V2 operation whose rights request wallet `wallet_signer_seed` signs;
/// the binding always names wallet 7.
fn signed_runtime_operation_v2_with_wallet_signer(
    runtime_seed: u8,
    wallet_signer_seed: u8,
) -> SignedRuntimeReleaseOperationV2 {
    let statement = signed_runtime_operation_v2_statement(
        protected_content_policy_and_request().0,
        runtime_seed,
        wallet_signer_seed,
    );
    SignedRuntimeReleaseOperationV2::new(
        statement.clone(),
        sign(
            &SigningKey::from_bytes(&[runtime_seed; 32]),
            &statement.canonical_bytes().unwrap(),
        ),
    )
    .unwrap()
}

/// One source's answer to the rights read, at the finalized block only: a
/// request for any other block does not match the script.
fn finalized_rights_script(operation: &SignedRuntimeReleaseOperationV2) -> Vec<ScriptedReply> {
    let policy = operation.statement().policy_body();
    let subject = format!(
        "0x{}",
        encode_hex(
            operation
                .statement()
                .evidence_request()
                .binding()
                .wallet()
                .as_bytes()
        )
    );
    let expected_data = encode_has_access_by_content_id_call(
        "0x12345678",
        policy.content_access_id().as_bytes(),
        &subject,
    )
    .unwrap();
    vec![
        ScriptedReply::rpc("eth_chainId", json!([]), json!("0x14")),
        ScriptedReply::rpc(
            "eth_getBlockByNumber",
            json!(["finalized", false]),
            finalized_block_json("0x2a", BLOCK_HASH),
        ),
        ScriptedReply::rpc(
            "eth_call",
            json!([
                { "to": "0x0000000000000000000000000000000000000001", "data": expected_data },
                { "blockHash": BLOCK_HASH, "requireCanonical": true }
            ]),
            evm_bool_word(true),
        ),
    ]
}

/// A provider that trusts Runtime 0x42 for V1 and reads two scripted sources.
fn v2_rights_provider(operation: &SignedRuntimeReleaseOperationV2) -> ChainProvider {
    let (first, _) = spawn_scripted_rpc_server(finalized_rights_script(operation));
    let (second, _) = spawn_scripted_rpc_server(finalized_rights_script(operation));
    let mut provider = provider_with_rights_rpc_and_policies(
        "http://127.0.0.1:9".to_string(),
        "0x12345678",
        protected_content_policy_sources("view", vec![first, second]),
    );
    provider.sleep = record_sleep;
    provider.now_unix_seconds = rights_evidence_now;
    provider
}

fn read_evidence(
    provider: &mut ChainProvider,
    signed_runtime_release_operation: String,
) -> Response {
    provider.handle(Request::ProtectedContentRightsEvidence {
        signed_runtime_release_operation,
    })
}

fn evidence_of(data: &Value) -> RightsEvaluationEvidenceV1 {
    let bytes = decode_hex(
        data["rights_evaluation_evidence"].as_str().unwrap(),
        None,
        "rights_evaluation_evidence",
    )
    .unwrap();
    RightsEvaluationEvidenceV1::from_canonical_bytes(&bytes).unwrap()
}

#[test]
fn v2_operation_from_any_issuer_gets_finalized_evidence() {
    // Runtime 0x43 is not the configured V1 issuer (0x42).
    let operation = signed_runtime_operation_v2(0x43);
    let mut provider = v2_rights_provider(&operation);
    assert_eq!(
        provider.protected_content_runtime_issuer,
        Some(runtime_issuer(0x42))
    );
    let data = ok_data(read_evidence(&mut provider, contract_hex(&operation)));
    let evidence = evidence_of(&data);
    let operation_hash = operation.statement().canonical_hash().unwrap();
    assert_eq!(evidence.runtime_operation_hash(), operation_hash);
    // L1: the release slot holds the operation hash.
    assert_eq!(evidence.release_request_hash(), operation_hash);
    assert!(evidence.has_access());
    assert_eq!(
        evidence.binding(),
        operation.statement().evidence_request().binding()
    );
    assert!(evidence.expires_at() <= operation.statement().expires_at());
}

#[test]
fn guard_v2_operation_with_bad_runtime_signature_is_refused() {
    let operation = signed_runtime_operation_v2(0x43);
    let forged =
        SignedRuntimeReleaseOperationV2::new(operation.statement().clone(), vec![0; 64]).unwrap();
    // No source is reachable: the refusal comes before any read.
    let mut provider = provider_with_rights_rpc_at(
        "http://127.0.0.1:9".to_string(),
        "0x12345678",
        rights_evidence_now,
    );
    assert_eq!(
        error_code(read_evidence(&mut provider, contract_hex(&forged))),
        "invalid_runtime_operation"
    );
}

#[test]
fn v2_operation_needs_no_configured_issuer() {
    let operation = signed_runtime_operation_v2(0x43);
    let mut provider = v2_rights_provider(&operation);
    provider.protected_content_runtime_issuer = None;
    let evidence = evidence_of(&ok_data(read_evidence(
        &mut provider,
        contract_hex(&operation),
    )));
    assert_eq!(
        evidence.runtime_operation_hash(),
        operation.statement().canonical_hash().unwrap()
    );
}

/// Also #388 A2 `operation_over_chain_cap_refused` (A388-F4): the fixture
/// nests a v3 descriptor and v2 vouches, and the 96 KiB cap is unchanged.
#[test]
fn guard_v2_operation_above_the_v2_cap_is_refused() {
    assert_eq!(MAX_PROTECTED_CONTENT_RUNTIME_OPERATION_V2_BYTES, 96 * 1024);
    // A V2 operation carries the pool descriptor, so it is sized by the V2
    // cap, not by V1's 16 KiB one.
    let operation = signed_runtime_operation_v2(0x43);
    assert!(
        operation.canonical_bytes().unwrap().len()
            <= MAX_PROTECTED_CONTENT_RUNTIME_OPERATION_V2_BYTES
    );
    let mut provider = provider_with_rights_rpc_at(
        "http://127.0.0.1:9".to_string(),
        "0x12345678",
        rights_evidence_now,
    );
    let oversized = format!(
        "0x{}",
        "00".repeat(MAX_PROTECTED_CONTENT_RUNTIME_OPERATION_V2_BYTES + 1)
    );
    let response = read_evidence(&mut provider, oversized);
    match response {
        Response::Error { code, message } => {
            assert_eq!(code, "invalid_runtime_operation");
            assert_eq!(message, "signed_runtime_release_operation size is invalid");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn v1_operation_still_needs_configured_issuer() {
    let v1 = protected_content_signed_operation();
    let mut provider = provider_with_rights_rpc_at(
        "http://127.0.0.1:9".to_string(),
        "0x12345678",
        rights_evidence_now,
    );
    provider.protected_content_runtime_issuer = None;
    assert_eq!(
        error_code(read_evidence(&mut provider, contract_hex(&v1))),
        "runtime_issuer_not_configured"
    );

    // Owner-only (L7): a V1 operation from another Runtime is refused.
    let other_runtime = signed_runtime_operation_for_policy_and_runtime_seed(
        protected_content_policy_and_request().0,
        0x43,
    );
    let mut provider = provider_with_rights_rpc_at(
        "http://127.0.0.1:9".to_string(),
        "0x12345678",
        rights_evidence_now,
    );
    assert_eq!(
        error_code(read_evidence(&mut provider, contract_hex(&other_runtime))),
        "invalid_runtime_operation"
    );
}

#[test]
fn v2_evidence_reads_finalized_block_only() {
    let operation = signed_runtime_operation_v2(0x43);
    let mut provider = v2_rights_provider(&operation);
    // The scripted sources answer only `finalized` and a call pinned to that
    // block's hash; any other block would not match the script.
    let data = ok_data(read_evidence(&mut provider, contract_hex(&operation)));
    assert_eq!(data["finalized_block_number"], 0x2a);
    assert_eq!(data["finalized_block_hash"], BLOCK_HASH);
    let evidence = evidence_of(&data);
    assert_eq!(evidence.finalized_block_number(), 0x2a);
    assert_eq!(
        format!(
            "0x{}",
            encode_hex(evidence.finalized_block_hash().as_bytes())
        ),
        BLOCK_HASH
    );
}

// ADV-02: gates of the V2 declared-issuer evidence path, each with a
// must-refuse test and a positive control.

/// Gate (a): the rights request must carry the bound wallet's signature.
/// Positive control: `v2_operation_from_any_issuer_gets_finalized_evidence`.
#[test]
fn guard_adv02_v2_rights_signed_by_another_wallet_are_refused_before_any_read() {
    let forged = signed_runtime_operation_v2_with_wallet_signer(0x43, 8);
    let mut provider = v2_rights_provider(&forged);
    assert_eq!(
        error_code(read_evidence(&mut provider, contract_hex(&forged))),
        "invalid_runtime_operation"
    );
    let genuine = signed_runtime_operation_v2(0x43);
    let mut provider = v2_rights_provider(&genuine);
    ok_data(read_evidence(&mut provider, contract_hex(&genuine)));
}

/// Gate (b): the read is the finalized block's even when the head already
/// grants access. Each source's chain state answers both blocks: the head
/// says yes, the finalized block says no, so the evidence must say no and
/// name the finalized block. A read at the head would grant access.
#[test]
fn guard_v2_evidence_ignores_access_granted_only_at_the_head() {
    const HEAD_HASH: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let operation = signed_runtime_operation_v2(0x43);
    let policy = operation.statement().policy_body();
    let subject = format!(
        "0x{}",
        encode_hex(
            operation
                .statement()
                .evidence_request()
                .binding()
                .wallet()
                .as_bytes()
        )
    );
    let data = encode_has_access_by_content_id_call(
        "0x12345678",
        policy.content_access_id().as_bytes(),
        &subject,
    )
    .unwrap();
    let call_at = |hash: &str| {
        json!([
            { "to": "0x0000000000000000000000000000000000000001", "data": data },
            { "blockHash": hash, "requireCanonical": true }
        ])
    };
    let state = || {
        vec![
            ("eth_chainId", json!([]), json!("0x14")),
            (
                "eth_getBlockByNumber",
                json!(["finalized", false]),
                finalized_block_json("0x2a", BLOCK_HASH),
            ),
            (
                "eth_getBlockByNumber",
                json!(["latest", false]),
                finalized_block_json("0x2b", HEAD_HASH),
            ),
            (
                "eth_getBlockByNumber",
                json!(["0x2a", false]),
                finalized_block_json("0x2a", BLOCK_HASH),
            ),
            (
                "eth_getBlockByNumber",
                json!(["0x2b", false]),
                finalized_block_json("0x2b", HEAD_HASH),
            ),
            ("eth_call", call_at(BLOCK_HASH), evm_bool_word(false)),
            ("eth_call", call_at(HEAD_HASH), evm_bool_word(true)),
        ]
    };
    let mut provider = provider_with_rights_rpc_and_policies(
        "http://127.0.0.1:9".to_string(),
        "0x12345678",
        protected_content_policy_sources(
            "view",
            vec![
                spawn_rpc_state_server(state()),
                spawn_rpc_state_server(state()),
            ],
        ),
    );
    provider.sleep = record_sleep;
    provider.now_unix_seconds = rights_evidence_now;
    let data = ok_data(read_evidence(&mut provider, contract_hex(&operation)));
    assert_eq!(data["finalized_block_hash"], BLOCK_HASH);
    assert!(!evidence_of(&data).has_access());
}

/// Gate (b): evidence is read at the finalized block only. Sources that have
/// no finalized block yield no evidence. Positive control:
/// `v2_evidence_reads_finalized_block_only`.
#[test]
fn guard_adv02_v2_evidence_is_refused_without_a_finalized_block() {
    let operation = signed_runtime_operation_v2(0x43);
    let no_finalized_block = || {
        vec![
            ScriptedReply::rpc("eth_chainId", json!([]), json!("0x14")),
            ScriptedReply::rpc(
                "eth_getBlockByNumber",
                json!(["finalized", false]),
                Value::Null,
            ),
        ]
    };
    let (first, _) = spawn_scripted_rpc_server(no_finalized_block());
    let (second, _) = spawn_scripted_rpc_server(no_finalized_block());
    let mut provider = provider_with_rights_rpc_and_policies(
        "http://127.0.0.1:9".to_string(),
        "0x12345678",
        protected_content_policy_sources("view", vec![first, second]),
    );
    provider.sleep = record_sleep;
    provider.now_unix_seconds = rights_evidence_now;
    assert_eq!(
        error_code(read_evidence(&mut provider, contract_hex(&operation))),
        "insufficient_rights_observations"
    );
}

// ADV-01 G2 (contract rev 6, §4 step 7): a V2 operation verifies by the
// issuer it declares, so the wallet's consent text is what stops a Runtime
// that is not the configured one. The configured issuer is A = 0x42; B =
// 0x43 declares and signs the operation.

/// The seven-line v1 layout that V2 signed before ADV-01, over the same
/// request hash.
fn v1_layout_text(request: &RightsRequestV2) -> String {
    format!(
        "ElastOS\n\nOpen protected content.\n\nAction:  {action}\nAccount: 0x{account}\nExpires: {expires} (unix seconds)\nRequest: 0x{request}\n",
        action = request.action().label(),
        account = encode_hex(request.binding().wallet().as_bytes()),
        expires = request.expires_at(),
        request = encode_hex(request.request_hash().unwrap().as_bytes()),
    )
}

fn signed_runtime_operation_v2_over(
    runtime_seed: u8,
    text: fn(&RightsRequestV2) -> String,
) -> SignedRuntimeReleaseOperationV2 {
    let statement = signed_runtime_operation_v2_statement_over(
        protected_content_policy_and_request().0,
        runtime_seed,
        7,
        text,
    );
    SignedRuntimeReleaseOperationV2::new(
        statement.clone(),
        sign(
            &SigningKey::from_bytes(&[runtime_seed; 32]),
            &statement.canonical_bytes().unwrap(),
        ),
    )
    .unwrap()
}

#[test]
fn adv01_declared_issuer_b_is_served_only_for_the_v2_consent_text() {
    // (a) The wallet signed the v1 seven-line text over the same request
    // hash. The operation fails its own verification, the provider answers
    // `invalid_runtime_operation`, and no source is read.
    let v1_text = signed_runtime_operation_v2_over(0x43, v1_layout_text);
    assert_eq!(
        v1_text.verify(RuntimeIssuerPolicyV1::Declared, rights_evidence_now()),
        Err(RuntimeReleaseOperationError::Rights(
            RightsError::WalletMismatch
        ))
    );
    let (first, first_reads) = spawn_scripted_rpc_server(finalized_rights_script(&v1_text));
    let (second, second_reads) = spawn_scripted_rpc_server(finalized_rights_script(&v1_text));
    let mut provider = provider_with_rights_rpc_and_policies(
        "http://127.0.0.1:9".to_string(),
        "0x12345678",
        protected_content_policy_sources("view", vec![first, second]),
    );
    provider.sleep = record_sleep;
    provider.now_unix_seconds = rights_evidence_now;
    assert_eq!(
        provider.protected_content_runtime_issuer,
        Some(runtime_issuer(0x42))
    );
    assert_eq!(
        error_code(read_evidence(&mut provider, contract_hex(&v1_text))),
        "invalid_runtime_operation"
    );
    assert_eq!(first_reads.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(second_reads.load(std::sync::atomic::Ordering::SeqCst), 0);

    // (b) The same request with the exact v2 text: finalized evidence.
    let v2_text =
        signed_runtime_operation_v2_over(0x43, |request| request.signing_message().unwrap());
    assert_eq!(
        v1_text.statement().rights_request().request(),
        v2_text.statement().rights_request().request()
    );
    let mut provider = v2_rights_provider(&v2_text);
    let evidence = evidence_of(&ok_data(read_evidence(
        &mut provider,
        contract_hex(&v2_text),
    )));
    assert_eq!(
        evidence.runtime_operation_hash(),
        v2_text.statement().canonical_hash().unwrap()
    );

    // (c) Control: the same request through the configured issuer A.
    let through_a =
        signed_runtime_operation_v2_over(0x42, |request| request.signing_message().unwrap());
    let mut provider = v2_rights_provider(&through_a);
    let evidence = evidence_of(&ok_data(read_evidence(
        &mut provider,
        contract_hex(&through_a),
    )));
    assert_eq!(
        evidence.runtime_operation_hash(),
        through_a.statement().canonical_hash().unwrap()
    );
}

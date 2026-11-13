use std::fs;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use custody_provider::{
    load_state_from_root, parse_runtime_issuer_hex, provision_state_root, PROVISIONING_PROVIDER_ID,
    PROVISIONING_SCHEMA_V1,
};
use ed25519_dalek::{Signer as _, SigningKey};
use elastos_protected_content_contracts::{
    CanonicalContract, ContentAccessIdV1, CustodyApprovedSuitesV1,
    CustodyCommitteeAuthorizationStatementV1, CustodyEpochIssuerKeyV1, CustodyEpochStatementV1,
    CustodyNodeIdentityV1, CustodyNodeProvisioningRecordV1, CustodyPoolFailureDomainIdV1,
    CustodyPoolMemberStateV1, CustodyPoolMemberV1, CustodyPoolOperatorIdV1, CustodyPoolStatementV1,
    Digest32, EncryptedContentIdentityV1, EvmContractAddressV1, EvmFunctionSelectorV1,
    EvmRightsMethodAbiV1, KeyReleaseRequestV1, NodeCustodyPublicKeyV1, NodePublicKey,
    ProtectedContentBindingV1, RecipientKeyAuthorizationStatementV1, RecipientKeyIdentityV1,
    RecipientPublicKeyBytesV1, ReplayNonce16, RightsActionV1, RightsDecisionV1,
    RightsEvaluationEvidenceRequestV1, RightsEvaluationEvidenceV1, RightsObservationFinalityV1,
    RightsPolicyBodyV1, RightsRequestV1, RightsSubjectSourceV1, RuntimeCustodyProvisioningIdV1,
    RuntimeCustodyProvisioningStatementV1, RuntimeOperationIssuerKeyV1, RuntimeReleaseAuditIdV1,
    RuntimeReleaseOperationStatementV1, RuntimeSessionBindingV1,
    SignedCustodyCommitteeAuthorizationV1, SignedCustodyEpochV1, SignedCustodyPoolV1,
    SignedNodeRightsDecisionV1, SignedRecipientKeyAuthorizationV1,
    SignedRuntimeCustodyProvisioningV1, SignedRuntimeReleaseOperationV1, ThresholdV1,
    ValidatedCustodyCommitteeV1, WalletAddress, WalletSignedRightsRequestV1,
    CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
};
use elastos_protected_content_custody::{
    provision_custody_envelope, ContentEncryptionKeyV1, NodeCustodySecretKeyV1,
};
use elastos_protected_content_provider_contracts::{
    CustodyProviderRequestV1, CustodyProviderResponseStatusV1, CustodyProviderResponseV1,
    RightsProviderRequestV1,
};
use elastos_protected_content_rights::PrivateCustodyRightsRequestV1;
use k256::ecdsa::SigningKey as WalletSigningKey;
use sha3::{Digest as _, Keccak256};
use zeroize::Zeroizing;

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn issued_unix_seconds() -> u64 {
    now_unix_seconds().saturating_sub(5)
}

fn expires_unix_seconds() -> u64 {
    now_unix_seconds() + 40
}

const PROCESS_TEST_VALID_RELEASE_LIFETIME_SECS: u64 =
    elastos_protected_content_contracts::MAX_RELEASE_REQUEST_LIFETIME_SECS;

struct ProviderProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl ProviderProcess {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_custody-provider"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
        }
    }

    fn request(&mut self, value: serde_json::Value) -> serde_json::Value {
        serde_json::to_writer(&mut self.stdin, &value).unwrap();
        writeln!(self.stdin).unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn stop(mut self) {
        let _ = self.request(serde_json::json!({"op": "shutdown"}));
        drop(self.stdin);
        let _ = self.child.wait();
    }

    fn shutdown_and_wait_with_stdin_open(mut self) {
        let response = self.request(serde_json::json!({"op": "shutdown"}));
        assert_eq!(response["status"], "ok");
        for _ in 0..50 {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        panic!("custody provider did not exit after shutdown acknowledgement");
    }
}

fn run_provision_command(root: &Path, trusted_runtime_issuer: &str) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_custody-provider"))
        .args([
            "provision",
            "--base-path",
            root.to_str().unwrap(),
            "--trusted-runtime-issuer",
            trusted_runtime_issuer,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "status={:?} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn digest(seed: u8) -> Digest32 {
    Digest32::new([seed; 32])
}

fn node_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn node_public_key(seed: u8) -> NodePublicKey {
    NodePublicKey::new(node_signing_key(seed).verifying_key().to_bytes()).unwrap()
}

fn node_custody_secret(seed: u8) -> NodeCustodySecretKeyV1 {
    NodeCustodySecretKeyV1::from_guarded_bytes(Zeroizing::new([seed; 32])).unwrap()
}

fn recipient_public_key(seed: u8) -> RecipientPublicKeyBytesV1 {
    let public = node_custody_secret(seed).public_key().unwrap();
    RecipientPublicKeyBytesV1::new(*public.as_bytes()).unwrap()
}

fn recipient_identity(seed: u8) -> RecipientKeyIdentityV1 {
    recipient_public_key(seed)
        .key_identity(CUSTODY_X_WING_AES256GCM_SUITE_ID_V1)
        .unwrap()
}

fn custody_policy_key() -> SigningKey {
    SigningKey::from_bytes(&[0x71; 32])
}

fn custody_policy_issuer() -> CustodyEpochIssuerKeyV1 {
    CustodyEpochIssuerKeyV1::new(custody_policy_key().verifying_key().to_bytes()).unwrap()
}

fn custody_member(node_seed: u8) -> CustodyPoolMemberV1 {
    custody_member_with(
        node_public_key(node_seed),
        node_custody_secret(node_seed).public_key().unwrap(),
        node_seed,
    )
}

fn custody_member_with(
    node_public_key: NodePublicKey,
    custody_public_key: NodeCustodyPublicKeyV1,
    node_seed: u8,
) -> CustodyPoolMemberV1 {
    CustodyPoolMemberV1::new(
        node_public_key,
        custody_public_key,
        CustodyPoolOperatorIdV1::new([0x80 + node_seed; 32]),
        CustodyPoolFailureDomainIdV1::new([0x90 + node_seed; 32]),
        CustodyApprovedSuitesV1::new(
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        )
        .unwrap(),
        (issued_unix_seconds(), now_unix_seconds() + 600),
        CustodyPoolMemberStateV1::Active,
    )
    .unwrap()
}

struct ProvisionedProviderNode {
    node_public_key: NodePublicKey,
    custody_public_key: NodeCustodyPublicKeyV1,
    node_signing_key: SigningKey,
}

fn load_provisioned_provider_node(root: &Path) -> ProvisionedProviderNode {
    let loaded = load_state_from_root(root).unwrap();
    ProvisionedProviderNode {
        node_public_key: loaded.node_public_key,
        custody_public_key: loaded.node_custody_secret.public_key().unwrap(),
        node_signing_key: loaded.node_signing_key,
    }
}

fn signed_pool_with_provider(provider: &ProvisionedProviderNode) -> SignedCustodyPoolV1 {
    let key = custody_policy_key();
    let statement = CustodyPoolStatementV1::new(
        custody_policy_issuer(),
        vec![
            custody_member_with(provider.node_public_key, provider.custody_public_key, 1),
            custody_member(2),
            custody_member(3),
        ],
    )
    .unwrap();
    SignedCustodyPoolV1::new(
        statement.clone(),
        key.sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn signed_epoch_with_provider(provider: &ProvisionedProviderNode) -> SignedCustodyEpochV1 {
    let key = custody_policy_key();
    let statement = CustodyEpochStatementV1::new(
        custody_policy_issuer(),
        CustodyApprovedSuitesV1::new(
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        )
        .unwrap(),
        ThresholdV1::new(2, 3).unwrap(),
        vec![
            CustodyNodeIdentityV1::new(
                provider.node_public_key,
                provider.custody_public_key,
                elastos_protected_content_contracts::ShareCoordinateV1::new(1).unwrap(),
            )
            .unwrap(),
            CustodyNodeIdentityV1::new(
                node_public_key(2),
                node_custody_secret(2).public_key().unwrap(),
                elastos_protected_content_contracts::ShareCoordinateV1::new(2).unwrap(),
            )
            .unwrap(),
            CustodyNodeIdentityV1::new(
                node_public_key(3),
                node_custody_secret(3).public_key().unwrap(),
                elastos_protected_content_contracts::ShareCoordinateV1::new(3).unwrap(),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    SignedCustodyEpochV1::new(
        statement.clone(),
        key.sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn validated_committee_with_provider(
    provider: &ProvisionedProviderNode,
) -> ValidatedCustodyCommitteeV1 {
    let pool = signed_pool_with_provider(provider);
    let epoch = signed_epoch_with_provider(provider);
    let key = custody_policy_key();
    let statement = CustodyCommitteeAuthorizationStatementV1::new(
        custody_policy_issuer(),
        pool.pool_identity().unwrap(),
        epoch.epoch_identity().unwrap(),
    )
    .unwrap();
    let authorization = SignedCustodyCommitteeAuthorizationV1::new(
        statement.clone(),
        key.sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    elastos_protected_content_contracts::validate_custody_epoch_against_pool_at(
        custody_policy_issuer(),
        authorization.authorization_identity().unwrap(),
        &pool,
        &epoch,
        &authorization,
        now_unix_seconds(),
    )
    .unwrap()
}

fn wallet(seed: u8) -> WalletAddress {
    let key = WalletSigningKey::from_slice(&[seed; 32]).unwrap();
    let encoded = key.verifying_key().to_encoded_point(false);
    let digest = Keccak256::digest(&encoded.as_bytes()[1..]);
    WalletAddress::new(digest[12..].try_into().unwrap())
}

fn policy_body() -> RightsPolicyBodyV1 {
    RightsPolicyBodyV1::new(
        EncryptedContentIdentityV1::new(Digest32::new([0x11; 32]), 4096).unwrap(),
        ContentAccessIdV1::new([0x41; 16]).unwrap(),
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

fn signed_rights_request(
    binding: ProtectedContentBindingV1,
    issued_at: u64,
    expires_at: u64,
) -> WalletSignedRightsRequestV1 {
    let request = RightsRequestV1::new(
        binding,
        RightsActionV1::View,
        recipient_identity(0x30),
        issued_at,
        expires_at,
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
}

fn signed_release_operation_with_provider(
    record: &CustodyNodeProvisioningRecordV1,
    provider: &ProvisionedProviderNode,
) -> SignedRuntimeReleaseOperationV1 {
    signed_release_operation_with_runtime_seed_and_epoch(
        record,
        0x42,
        signed_epoch_with_provider(provider),
    )
}

fn signed_release_operation_with_runtime_seed_and_epoch(
    record: &CustodyNodeProvisioningRecordV1,
    runtime_seed: u8,
    epoch: SignedCustodyEpochV1,
) -> SignedRuntimeReleaseOperationV1 {
    signed_release_operation_with_runtime_seed_epoch_and_issued_at(
        record,
        runtime_seed,
        epoch,
        issued_unix_seconds(),
    )
}

fn signed_release_operation_with_runtime_seed_epoch_and_issued_at(
    record: &CustodyNodeProvisioningRecordV1,
    runtime_seed: u8,
    epoch: SignedCustodyEpochV1,
    issued_at: u64,
) -> SignedRuntimeReleaseOperationV1 {
    let runtime_key = node_signing_key(runtime_seed);
    let policy = policy_body();
    let expires_at = issued_at + PROCESS_TEST_VALID_RELEASE_LIFETIME_SECS;
    let binding = ProtectedContentBindingV1::new(
        record.manifest().encrypted_content().clone(),
        record.key_envelope_identity().clone(),
        policy.policy_identity().unwrap(),
        elastos_protected_content_contracts::ProfileIdentityV1::from_public_key_bytes(
            node_signing_key(0x26).verifying_key().to_bytes(),
        )
        .unwrap(),
        wallet(7),
        RuntimeSessionBindingV1::new(digest(0x66)).unwrap(),
    )
    .unwrap();
    let rights = signed_rights_request(binding.clone(), issued_at, expires_at);
    let release = KeyReleaseRequestV1::new(
        binding.clone(),
        rights.request().request_hash().unwrap(),
        RightsActionV1::View,
        rights.request().recipient().clone(),
        issued_at,
        expires_at,
        ReplayNonce16::new([0x66; 16]),
    )
    .unwrap();
    let recipient_key = recipient_public_key(0x30);
    let authorization_statement = RecipientKeyAuthorizationStatementV1::new(
        binding.clone(),
        RightsActionV1::View,
        recipient_key,
        rights.request().recipient().clone(),
        RuntimeOperationIssuerKeyV1::new(runtime_key.verifying_key().to_bytes()).unwrap(),
        issued_at,
        expires_at,
    )
    .unwrap();
    let profile_key = node_signing_key(0x26);
    let authorization = SignedRecipientKeyAuthorizationV1::new(
        authorization_statement.clone(),
        profile_key
            .sign(&authorization_statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let evidence_request =
        RightsEvaluationEvidenceRequestV1::new(binding, policy.policy_identity().unwrap()).unwrap();
    let statement = RuntimeReleaseOperationStatementV1::new(
        RuntimeOperationIssuerKeyV1::new(runtime_key.verifying_key().to_bytes()).unwrap(),
        rights,
        release,
        recipient_key,
        authorization,
        policy,
        evidence_request,
        epoch,
        RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap(),
        issued_at,
        expires_at,
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

fn signed_decision_with_provider(
    operation: &SignedRuntimeReleaseOperationV1,
    provider: &ProvisionedProviderNode,
    decision: RightsDecisionV1,
) -> SignedNodeRightsDecisionV1 {
    signed_decision_with_provider_at(operation, provider, decision, now_unix_seconds())
}

fn signed_decision_with_provider_at(
    operation: &SignedRuntimeReleaseOperationV1,
    provider: &ProvisionedProviderNode,
    decision: RightsDecisionV1,
    signed_at: u64,
) -> SignedNodeRightsDecisionV1 {
    let authenticated = operation
        .verify(operation.statement().runtime_operation_issuer(), signed_at)
        .unwrap();
    let statement = elastos_protected_content_contracts::NodeRightsDecisionStatementV1::new(
        authenticated.release_request_hash(),
        authenticated.rights_request_hash(),
        authenticated.binding().clone(),
        authenticated.action(),
        provider.node_public_key,
        decision,
        digest(0x80),
        authenticated.statement().release_request().issued_at(),
        authenticated.statement().release_request().expires_at(),
    )
    .unwrap();
    SignedNodeRightsDecisionV1::new(
        statement.clone(),
        provider
            .node_signing_key
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn signed_decision_with(
    operation: &SignedRuntimeReleaseOperationV1,
    node_seed: u8,
    decision: RightsDecisionV1,
) -> SignedNodeRightsDecisionV1 {
    let authenticated = operation
        .verify(
            operation.statement().runtime_operation_issuer(),
            now_unix_seconds(),
        )
        .unwrap();
    let statement = elastos_protected_content_contracts::NodeRightsDecisionStatementV1::new(
        authenticated.release_request_hash(),
        authenticated.rights_request_hash(),
        authenticated.binding().clone(),
        authenticated.action(),
        node_public_key(node_seed),
        decision,
        digest(0x80),
        authenticated.statement().release_request().issued_at(),
        authenticated.statement().release_request().expires_at(),
    )
    .unwrap();
    SignedNodeRightsDecisionV1::new(
        statement.clone(),
        node_signing_key(node_seed)
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn signed_provisioning(
    record: &CustodyNodeProvisioningRecordV1,
) -> SignedRuntimeCustodyProvisioningV1 {
    signed_provisioning_with_runtime_seed(record, 0x42)
}

fn signed_provisioning_with_runtime_seed(
    record: &CustodyNodeProvisioningRecordV1,
    runtime_seed: u8,
) -> SignedRuntimeCustodyProvisioningV1 {
    signed_provisioning_valid_between(
        record,
        runtime_seed,
        issued_unix_seconds(),
        expires_unix_seconds(),
    )
}

fn signed_provisioning_valid_between(
    record: &CustodyNodeProvisioningRecordV1,
    runtime_seed: u8,
    issued_unix_seconds: u64,
    expires_unix_seconds: u64,
) -> SignedRuntimeCustodyProvisioningV1 {
    let runtime_key = node_signing_key(runtime_seed);
    let statement = RuntimeCustodyProvisioningStatementV1::new(
        RuntimeOperationIssuerKeyV1::new(runtime_key.verifying_key().to_bytes()).unwrap(),
        record.record_identity().unwrap(),
        RuntimeCustodyProvisioningIdV1::new(digest(0xa5)).unwrap(),
        issued_unix_seconds,
        expires_unix_seconds,
    )
    .unwrap();
    SignedRuntimeCustodyProvisioningV1::new(
        statement.clone(),
        runtime_key
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn provisioning_record_with_provider(
    provider: &ProvisionedProviderNode,
) -> CustodyNodeProvisioningRecordV1 {
    provisioning_record_with_committee_and_node(
        &validated_committee_with_provider(provider),
        provider.node_public_key,
    )
}

fn provisioning_record_with_committee_and_node(
    committee: &ValidatedCustodyCommitteeV1,
    selected_node: NodePublicKey,
) -> CustodyNodeProvisioningRecordV1 {
    let envelope = provision_custody_envelope(
        EncryptedContentIdentityV1::new(digest(0x11), 4096).unwrap(),
        &ContentEncryptionKeyV1::generate().unwrap(),
        committee,
    )
    .unwrap();
    CustodyNodeProvisioningRecordV1::new(
        envelope.key_envelope_identity().unwrap(),
        envelope.manifest().clone(),
        selected_node,
        envelope
            .stored_share_for_node(selected_node)
            .unwrap()
            .clone(),
    )
    .unwrap()
}

fn prepare_config(root: &Path) -> serde_json::Value {
    prepare_config_with_seeds(root, 1, 1)
}

fn runtime_issuer_hex(seed: u8) -> String {
    let key = SigningKey::from_bytes(&[seed; 32]);
    format!("0x{}", hex_bytes(&key.verifying_key().to_bytes()))
}

fn prepare_config_with_seeds(root: &Path, custody_seed: u8, signing_seed: u8) -> serde_json::Value {
    use std::os::unix::fs::PermissionsExt;

    let root = fs::canonicalize(root).unwrap();
    let provider_parent = root.join("providers");
    if !provider_parent.exists() {
        fs::create_dir(&provider_parent).unwrap();
        fs::set_permissions(&provider_parent, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let provider_root =
        provider_parent.join(format!("provider-{custody_seed:02x}-{signing_seed:02x}"));
    let runtime_issuer = parse_runtime_issuer_hex(&runtime_issuer_hex(0x42)).unwrap();
    if !provider_root.exists() {
        provision_state_root(&provider_root, runtime_issuer).unwrap();
    }
    if custody_seed != 1 {
        let custody = provider_root.join("node-custody-secret");
        fs::write(&custody, format!("0x{}", hex_bytes(&[custody_seed; 32]))).unwrap();
        fs::set_permissions(&custody, fs::Permissions::from_mode(0o600)).unwrap();
    }
    if signing_seed != 1 {
        let signing = provider_root.join("node-signing-key");
        fs::write(&signing, format!("0x{}", hex_bytes(&[signing_seed; 32]))).unwrap();
        fs::set_permissions(&signing, fs::Permissions::from_mode(0o600)).unwrap();
    }
    serde_json::json!({
        "op": "init",
        "config": {
            "base_path": provider_root,
            "allowed_paths": [],
            "read_only": false,
            "encryption_key": "",
            "extra": null
        }
    })
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn request_value(request: &CustodyProviderRequestV1) -> serde_json::Value {
    serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap()
}

fn sorted_object_keys(value: &serde_json::Value) -> Vec<&str> {
    let mut keys = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys
}

#[test]
fn custody_provider_provision_command_returns_both_public_keys_and_redacts_private_state() {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let root = fs::canonicalize(temp.path()).unwrap().join("provider-root");
    let issuer = runtime_issuer_hex(0x42);
    let response = run_provision_command(&root, &issuer);
    assert_eq!(response["status"], "ok", "{response}");
    assert_eq!(sorted_object_keys(&response), vec!["data", "status"]);
    assert_eq!(
        sorted_object_keys(&response["data"]),
        vec![
            "node_custody_public_key",
            "node_public_key",
            "provider",
            "receipt",
            "schema",
        ]
    );
    assert_eq!(response["data"]["schema"], PROVISIONING_SCHEMA_V1);
    assert_eq!(response["data"]["provider"], PROVISIONING_PROVIDER_ID);

    let loaded = load_state_from_root(&root).unwrap();
    let expected_node_public_key = format!("0x{}", hex_bytes(loaded.node_public_key.as_bytes()));
    let expected_node_custody_public_key = format!(
        "0x{}",
        hex_bytes(loaded.node_custody_secret.public_key().unwrap().as_bytes())
    );
    assert_eq!(
        response["data"]["node_public_key"],
        expected_node_public_key
    );
    assert_eq!(
        response["data"]["node_custody_public_key"],
        expected_node_custody_public_key
    );

    let encoded = serde_json::to_string(&response).unwrap();
    let node_signing_key = fs::read_to_string(root.join("node-signing-key")).unwrap();
    let node_custody_secret = fs::read_to_string(root.join("node-custody-secret")).unwrap();
    assert!(!encoded.contains(temp.path().to_str().unwrap()));
    assert!(!encoded.contains(&node_signing_key));
    assert!(!encoded.contains(&node_custody_secret));
    assert!(!encoded.contains("path"));
    assert!(!encoded.contains("route"));
    assert!(!encoded.contains("carrier"));
    assert!(!encoded.contains("port"));
    assert!(!encoded.contains("credential"));
}

#[test]
fn custody_provider_provision_command_is_idempotent_for_public_identities() {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let root = fs::canonicalize(temp.path()).unwrap().join("provider-root");
    let issuer = runtime_issuer_hex(0x42);
    let first = run_provision_command(&root, &issuer);
    let second = run_provision_command(&root, &issuer);

    assert_eq!(first["status"], "ok", "{first}");
    assert_eq!(second["status"], "ok", "{second}");
    assert_eq!(
        sorted_object_keys(&first["data"]),
        sorted_object_keys(&second["data"])
    );
    assert_eq!(
        first["data"]["node_public_key"],
        second["data"]["node_public_key"]
    );
    assert_eq!(
        first["data"]["node_custody_public_key"],
        second["data"]["node_custody_public_key"]
    );
    assert_eq!(first["data"]["receipt"], second["data"]["receipt"]);
}

#[test]
fn custody_provider_process_keeps_provisioning_issuer_while_buyer_runtime_releases_and_replays() {
    let temp = tempfile::tempdir().unwrap();
    let init_request = prepare_config(temp.path());
    let base_path = Path::new(init_request["config"]["base_path"].as_str().unwrap());
    let provider_node = load_provisioned_provider_node(base_path);
    let record = provisioning_record_with_provider(&provider_node);
    let provisioning = signed_provisioning(&record);
    let provision_request =
        CustodyProviderRequestV1::new_provision_node_share(&record, &provisioning).unwrap();
    let mut provider = ProviderProcess::start();
    let init = provider.request(init_request);
    assert_eq!(init["status"], "ok", "{init}");
    assert_eq!(init["data"]["provider"], PROVISIONING_PROVIDER_ID);
    assert_eq!(init["data"]["configured"], true);

    let provisioned = provider.request(request_value(&provision_request));
    assert_eq!(provisioned["status"], "ok", "{provisioned}");
    let provisioned_response: CustodyProviderResponseV1 =
        serde_json::from_value(provisioned["data"].clone()).unwrap();
    assert_eq!(
        provisioned_response.status(),
        CustodyProviderResponseStatusV1::Provisioned
    );
    assert_eq!(
        provisioned_response.provisioned_record_identity().unwrap(),
        record.record_identity().unwrap()
    );

    let duplicate = provider.request(request_value(&provision_request));
    assert_eq!(duplicate["data"], provisioned["data"]);

    let release_operation = signed_release_operation_with_runtime_seed_and_epoch(
        &record,
        0x43,
        signed_epoch_with_provider(&provider_node),
    );
    let decision = signed_decision_with_provider(
        &release_operation,
        &provider_node,
        RightsDecisionV1::Allowed,
    );
    let release_request =
        CustodyProviderRequestV1::new_release_contribution(&release_operation, &decision).unwrap();

    let contribution = provider.request(request_value(&release_request));
    assert_eq!(contribution["status"], "ok", "{contribution}");
    let contribution_response: CustodyProviderResponseV1 =
        serde_json::from_value(contribution["data"].clone()).unwrap();
    let signed_contribution = contribution_response.signed_node_contribution().unwrap();
    let authenticated = release_operation
        .verify(
            release_operation.statement().runtime_operation_issuer(),
            now_unix_seconds(),
        )
        .unwrap();
    let node_set = signed_epoch_with_provider(&provider_node)
        .statement()
        .node_set()
        .unwrap();
    authenticated
        .verify_node_contribution(&signed_contribution, &node_set, now_unix_seconds())
        .unwrap();

    let replay = provider.request(request_value(&release_request));
    assert_eq!(replay["data"], contribution["data"]);
    provider.stop();

    let mut restarted = ProviderProcess::start();
    assert_eq!(
        restarted.request(prepare_config(temp.path()))["status"],
        "ok"
    );
    let restart_replay = restarted.request(request_value(&release_request));
    assert_eq!(restart_replay["data"], contribution["data"]);
    restarted.stop();

    let mut wrong_secret = ProviderProcess::start();
    assert_eq!(
        wrong_secret.request(prepare_config_with_seeds(temp.path(), 2, 1))["status"],
        "ok"
    );
    let wrong_secret_response =
        serde_json::to_string(&wrong_secret.request(request_value(&provision_request))).unwrap();
    assert!(
        wrong_secret_response.contains("invalid_request"),
        "{wrong_secret_response}"
    );
    assert!(!wrong_secret_response.contains("backend_unavailable"));
    assert!(!wrong_secret_response.contains("0x02"));
    wrong_secret.stop();

    let wrong_signing_operation = signed_release_operation_with_provider(&record, &provider_node);
    let wrong_signing_decision = signed_decision_with_provider(
        &wrong_signing_operation,
        &provider_node,
        RightsDecisionV1::Allowed,
    );
    let wrong_signing_request = CustodyProviderRequestV1::new_release_contribution(
        &wrong_signing_operation,
        &wrong_signing_decision,
    )
    .unwrap();
    let mut wrong_signing = ProviderProcess::start();
    assert_eq!(
        wrong_signing.request(prepare_config_with_seeds(temp.path(), 1, 2))["status"],
        "ok"
    );
    let wrong_signing_response =
        serde_json::to_string(&wrong_signing.request(request_value(&wrong_signing_request)))
            .unwrap();
    assert!(wrong_signing_response.contains("invalid_request"));
    assert!(!wrong_signing_response.contains("0x02"));
    wrong_signing.stop();
}

/// The caller's abort decision reads this code. A statement that expired while
/// the mint was still protecting is refused before the share store is touched —
/// at request validation, which answers `invalid_request` — so the capsule must
/// report it with a code that means "not stored", never `backend_unavailable`,
/// which it also returns from paths that fail after the durable write.
///
/// The assertion is membership rather than one exact string on purpose: what
/// must hold is that the code is one the Runtime treats as proof of no write,
/// whichever layer refuses. Moving expiry down to the store later would change
/// the code to `provisioning_refused` and this test should still pass.
#[test]
fn custody_provider_process_names_a_pre_write_refusal_so_the_caller_can_keep_the_mint() {
    let temp = tempfile::tempdir().unwrap();
    let init_request = prepare_config(temp.path());
    let base_path = Path::new(init_request["config"]["base_path"].as_str().unwrap());
    let provider_node = load_provisioned_provider_node(base_path);
    let record = provisioning_record_with_provider(&provider_node);
    let expired = signed_provisioning_valid_between(
        &record,
        0x42,
        now_unix_seconds().saturating_sub(600),
        now_unix_seconds().saturating_sub(540),
    );
    let expired_request =
        CustodyProviderRequestV1::new_provision_node_share(&record, &expired).unwrap();

    let mut provider = ProviderProcess::start();
    assert_eq!(provider.request(init_request)["status"], "ok");
    let response = provider.request(request_value(&expired_request));
    let rendered = serde_json::to_string(&response).unwrap();

    assert_eq!(response["status"], "error", "{rendered}");
    assert_ne!(
        response["code"], "backend_unavailable",
        "an expired statement is refused before the write and must not be reported \
         with the code that also covers failures after it: {rendered}"
    );
    assert!(
        CUSTODY_PRE_WRITE_REFUSAL_CODES.contains(&response["code"].as_str().unwrap_or_default()),
        "unexpected code for a pre-write refusal: {rendered}"
    );
    assert!(!rendered.contains(temp.path().to_str().unwrap()));
    assert!(!rendered.contains("sealed_share"));

    // The same record with a live statement still provisions, so the refusal
    // above was the expiry and not the record.
    let live_request =
        CustodyProviderRequestV1::new_provision_node_share(&record, &signed_provisioning(&record))
            .unwrap();
    assert_eq!(
        provider.request(request_value(&live_request))["status"],
        "ok"
    );
    provider.stop();
}

/// The codes the Runtime's own closed list treats as proof that nothing was
/// stored, kept here so a change on either side breaks a test rather than
/// silently downgrading a recoverable mint to a dead one.
const CUSTODY_PRE_WRITE_REFUSAL_CODES: [&str; 5] = [
    "invalid_request",
    "provisioning_refused",
    "rights_denied",
    "operation_expired",
    "evidence_expired",
];

fn rights_request_value(
    node_public_key: NodePublicKey,
    operation: &SignedRuntimeReleaseOperationV1,
) -> serde_json::Value {
    serde_json::from_slice(
        &RightsProviderRequestV1::new_evaluate(node_public_key, operation)
            .unwrap()
            .to_json_vec()
            .unwrap(),
    )
    .unwrap()
}

fn private_rights_value(request: &PrivateCustodyRightsRequestV1) -> serde_json::Value {
    serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap()
}

/// Chain evidence for `operation`, valid from `acquired_at` to `expires_at`.
fn chain_evidence_data(
    operation: &SignedRuntimeReleaseOperationV1,
    acquired_at: u64,
    expires_at: u64,
) -> serde_json::Value {
    let statement = operation.statement();
    let request = statement.evidence_request();
    let evidence = RightsEvaluationEvidenceV1::new(
        statement.canonical_hash().unwrap(),
        statement.release_request().request_hash().unwrap(),
        request.binding().clone(),
        request.policy_identity().clone(),
        request.binding().wallet(),
        statement.policy_body().chain_id(),
        42,
        digest(0x77),
        true,
        acquired_at,
        expires_at,
    )
    .unwrap();
    serde_json::json!({
        "schema": "elastos.chain.protected-content-rights-evidence/v1",
        "rights_evaluation_evidence": format!("0x{}", hex_bytes(&evidence.canonical_bytes().unwrap())),
    })
}

/// An operation that ended is named `operation_expired`, at both the rights
/// and the release step, so the Runtime can tell "start again" from a request
/// it got wrong. Both refusals precede any store.
#[test]
fn custody_provider_process_names_an_expired_operation() {
    let temp = tempfile::tempdir().unwrap();
    let init_request = prepare_config(temp.path());
    let base_path = Path::new(init_request["config"]["base_path"].as_str().unwrap());
    let provider_node = load_provisioned_provider_node(base_path);
    let record = provisioning_record_with_provider(&provider_node);
    let issued_at = now_unix_seconds().saturating_sub(120);
    let expired = signed_release_operation_with_runtime_seed_epoch_and_issued_at(
        &record,
        0x42,
        signed_epoch_with_provider(&provider_node),
        issued_at,
    );
    let decision = signed_decision_with_provider_at(
        &expired,
        &provider_node,
        RightsDecisionV1::Allowed,
        issued_at + 1,
    );
    let release_request =
        CustodyProviderRequestV1::new_release_contribution(&expired, &decision).unwrap();
    let prepare = PrivateCustodyRightsRequestV1::new_prepare(rights_request_value(
        provider_node.node_public_key,
        &expired,
    ));

    let mut provider = ProviderProcess::start();
    assert_eq!(provider.request(init_request)["status"], "ok");
    for response in [
        provider.request(request_value(&release_request)),
        provider.request(private_rights_value(&prepare)),
    ] {
        assert_eq!(response["status"], "error", "{response}");
        assert_eq!(response["code"], "operation_expired", "{response}");
        assert!(CUSTODY_PRE_WRITE_REFUSAL_CODES
            .contains(&response["code"].as_str().unwrap_or_default()));
    }
    // The same request shape with a live operation is prepared, so the
    // refusals above were the expiry.
    let live = signed_release_operation_with_provider(&record, &provider_node);
    let live_prepare = PrivateCustodyRightsRequestV1::new_prepare(rights_request_value(
        provider_node.node_public_key,
        &live,
    ));
    let prepared = provider.request(private_rights_value(&live_prepare));
    assert_eq!(prepared["status"], "ok", "{prepared}");
    provider.stop();
}

#[test]
fn custody_provider_process_names_expired_rights_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let init_request = prepare_config(temp.path());
    let base_path = Path::new(init_request["config"]["base_path"].as_str().unwrap());
    let provider_node = load_provisioned_provider_node(base_path);
    let record = provisioning_record_with_provider(&provider_node);
    let operation = signed_release_operation_with_provider(&record, &provider_node);
    let issued_at = operation.statement().issued_at();
    let request = rights_request_value(provider_node.node_public_key, &operation);
    let expired_evidence = PrivateCustodyRightsRequestV1::new_settle(
        request.clone(),
        chain_evidence_data(&operation, issued_at, issued_at + 2),
    );
    let live_evidence = PrivateCustodyRightsRequestV1::new_settle(
        request,
        chain_evidence_data(&operation, issued_at, issued_at + 30),
    );

    let mut provider = ProviderProcess::start();
    assert_eq!(provider.request(init_request)["status"], "ok");
    let response = provider.request(private_rights_value(&expired_evidence));
    assert_eq!(response["status"], "error", "{response}");
    assert_eq!(response["code"], "evidence_expired", "{response}");
    // The same operation settles with evidence that is still live, so the
    // refusal above was the evidence expiry.
    let settled = provider.request(private_rights_value(&live_evidence));
    assert_eq!(settled["status"], "ok", "{settled}");
    provider.stop();
}

#[test]
fn custody_provider_process_shutdown_exits_while_stdin_remains_open() {
    ProviderProcess::start().shutdown_and_wait_with_stdin_open();
}

#[test]
fn custody_provider_process_rejects_wrong_issuer_node_conflict_and_redacts_diagnostics() {
    let temp = tempfile::tempdir().unwrap();
    let init_request = prepare_config(temp.path());
    let base_path = Path::new(init_request["config"]["base_path"].as_str().unwrap());
    let provider_node = load_provisioned_provider_node(base_path);
    let record = provisioning_record_with_provider(&provider_node);
    let provisioning = signed_provisioning(&record);
    let provision_request =
        CustodyProviderRequestV1::new_provision_node_share(&record, &provisioning).unwrap();
    let mut provider = ProviderProcess::start();
    let init = provider.request(init_request);
    assert_eq!(init["status"], "ok", "{init}");
    assert_eq!(
        provider.request(request_value(&provision_request))["status"],
        "ok"
    );

    let mut conflicting_record = record.clone();
    let mut share = conflicting_record.sealed_share().clone();
    share = share.tamper_envelope();
    conflicting_record = CustodyNodeProvisioningRecordV1::new(
        record.key_envelope_identity().clone(),
        record.manifest().clone(),
        record.selected_node_public_key(),
        share,
    )
    .unwrap();
    let conflict_request = CustodyProviderRequestV1::new_provision_node_share(
        &conflicting_record,
        &signed_provisioning(&conflicting_record),
    )
    .unwrap();
    let conflict =
        serde_json::to_string(&provider.request(request_value(&conflict_request))).unwrap();
    assert!(conflict.contains("backend_unavailable"));
    assert!(!conflict.contains(temp.path().to_str().unwrap()));
    assert!(!conflict.contains("sealed_share"));
    assert!(!conflict.contains("stored_share"));
    assert!(!conflict.contains("ciphertext"));
    assert!(!conflict.contains("carrier"));
    assert!(!conflict.contains("port"));

    let wrong_issuer_request = CustodyProviderRequestV1::new_provision_node_share(
        &record,
        &signed_provisioning_with_runtime_seed(&record, 0x43),
    )
    .unwrap();
    let wrong_issuer =
        serde_json::to_string(&provider.request(request_value(&wrong_issuer_request))).unwrap();
    assert!(wrong_issuer.contains("invalid_request"));
    assert!(!wrong_issuer.contains("issuer"));
    assert!(!wrong_issuer.contains("0x43"));

    let wrong_runtime_operation = signed_release_operation_with_provider(&record, &provider_node);
    let wrong_node_decision =
        signed_decision_with(&wrong_runtime_operation, 2, RightsDecisionV1::Allowed);
    let wrong_node_request = CustodyProviderRequestV1::new_release_contribution(
        &wrong_runtime_operation,
        &wrong_node_decision,
    )
    .unwrap();
    let wrong_node =
        serde_json::to_string(&provider.request(request_value(&wrong_node_request))).unwrap();
    assert!(wrong_node.contains("invalid_request"));
    assert!(!wrong_node.contains("selected_node"));

    let denied_decision = signed_decision_with_provider(
        &wrong_runtime_operation,
        &provider_node,
        RightsDecisionV1::Denied,
    );
    let denied_request = CustodyProviderRequestV1::new_release_contribution(
        &wrong_runtime_operation,
        &denied_decision,
    )
    .unwrap();
    let denied = provider.request(request_value(&denied_request));
    assert_eq!(denied["status"], "error", "{denied}");
    assert_eq!(denied["code"], "rights_denied", "{denied}");
    assert!(denied.get("data").is_none());
    let denied_text = serde_json::to_string(&denied).unwrap();
    assert!(!denied_text.contains("backend_unavailable"));
    assert!(!denied_text.contains("signed_node_contribution"));

    let allowed_after_denial = CustodyProviderRequestV1::new_release_contribution(
        &wrong_runtime_operation,
        &signed_decision_with_provider(
            &wrong_runtime_operation,
            &provider_node,
            RightsDecisionV1::Allowed,
        ),
    )
    .unwrap();
    let allowed = provider.request(request_value(&allowed_after_denial));
    assert_eq!(allowed["status"], "ok");
    let allowed_response: CustodyProviderResponseV1 =
        serde_json::from_value(allowed["data"].clone()).unwrap();
    assert_eq!(
        allowed_response.status(),
        CustodyProviderResponseStatusV1::Contribution
    );
    let allowed_replay = provider.request(request_value(&allowed_after_denial));
    assert_eq!(allowed_replay["data"], allowed["data"]);

    // Issue the mismatched operation in a guaranteed-different second so its
    // release request hash can never coincide with the original operation's
    // (the request is otherwise identical when minted in the same second,
    // making the "wrong" decision legitimately verifiable).
    let wrong_decision = signed_decision_with_provider(
        &signed_release_operation_with_runtime_seed_epoch_and_issued_at(
            &record,
            0x44,
            signed_epoch_with_provider(&provider_node),
            issued_unix_seconds().saturating_sub(7),
        ),
        &provider_node,
        RightsDecisionV1::Allowed,
    );
    let bad_release = CustodyProviderRequestV1::new_release_contribution(
        &wrong_runtime_operation,
        &wrong_decision,
    )
    .unwrap();
    let rejected = serde_json::to_string(&provider.request(request_value(&bad_release))).unwrap();
    assert!(rejected.contains("invalid_request"), "{rejected}");
    assert!(!rejected.contains("runtime"), "{rejected}");
    provider.stop();
}

#[test]
fn custody_provider_process_malformed_shutdown_keeps_serving_until_valid_shutdown() {
    let mut provider = ProviderProcess::start();

    let malformed = provider.request(serde_json::json!({
        "op": "shutdown",
        "unexpected": true
    }));
    assert_eq!(malformed["status"], "error");
    assert_eq!(malformed["code"], "invalid_request");

    let status = provider.request(serde_json::json!({"op": "status"}));
    assert_eq!(status["status"], "ok");
    assert_eq!(status["data"]["provider"], PROVISIONING_PROVIDER_ID);
    assert_eq!(status["data"]["configured"], false);

    provider.shutdown_and_wait_with_stdin_open();
}

// ---------------------------------------------------------------------------
// Plan B T1.5: the V2 release gate
// ---------------------------------------------------------------------------

mod pool_release {
    use super::*;
    use elastos_protected_content_contracts::test_fixtures::{
        pool_bundle_with, pool_release_fixture, recipient_attestation_statement, runtime_issuer,
        signed_node_rights_decision, signed_node_rights_decision_for_signed, PoolReleaseFixtureV1,
        PoolReleaseSpecV1, CUSTODY_KEY_SEED_BASE,
    };
    use elastos_protected_content_contracts::{
        CustodyEpochIdentityV1, KeyEnvelopeIdentityV1, PoolRecipientAttestationStatementV2,
        PoolTrustModeV1, RuntimeReleaseOperationAnyV1, SignedNodeContributionV1,
        SignedRuntimeReleaseOperationV2, PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES,
    };
    use elastos_protected_content_custody::{
        provision_custody_envelope_for_exact_nodes, ExactCustodyEnvelopeNodeV1,
    };
    use elastos_protected_content_provider_contracts::{
        PoolCustodyRequestV1, PoolCustodyResponseStatusV1, PoolCustodyResponseV1,
        RightsProviderResponseV1,
    };

    /// The provider is the fixture's pool node 2.
    const POOL_NODE: u8 = 2;

    /// The X-Wing public key whose secret is `[seed; 32]`, as the provider's
    /// custody secret and the fixture's keys are.
    fn xwing_public_key(seed: u8) -> [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
        *NodeCustodySecretKeyV1::from_guarded_bytes(Zeroizing::new([seed; 32]))
            .unwrap()
            .public_key()
            .unwrap()
            .as_bytes()
    }

    struct PoolNode {
        provider: ProviderProcess,
        /// S7-lite: the item's envelope and committee, for pool provisioning.
        envelope: elastos_protected_content_contracts::CustodyEnvelopeV1,
        bundle: elastos_protected_content_contracts::PoolEpochBundleV1,
        key_envelope: KeyEnvelopeIdentityV1,
        now: u64,
        member_window: Option<(u64, u64)>,
        revoked_node: Option<u8>,
    }

    impl PoolNode {
        /// Starts pool node 2 and, when `provision`, gives it its share of one
        /// item kept by the fixture committee.
        fn start(
            temp: &Path,
            member_window: Option<(u64, u64)>,
            revoked_node: Option<u8>,
            provision: bool,
        ) -> Self {
            // Every fixture window is relative to `now`; the operation runs
            // from now + 2 to now + 40.
            let now = now_unix_seconds() - 10;
            let init =
                prepare_config_with_seeds(temp, CUSTODY_KEY_SEED_BASE + POOL_NODE, POOL_NODE);
            let bundle = pool_bundle_with(xwing_public_key, now, member_window, revoked_node);
            let nodes = bundle
                .signed_epoch()
                .statement()
                .nodes()
                .iter()
                .map(|node| {
                    ExactCustodyEnvelopeNodeV1::new(
                        node.node_public_key(),
                        node.custody_public_key(),
                    )
                })
                .collect::<Vec<_>>();
            let envelope = provision_custody_envelope_for_exact_nodes(
                policy_body().encrypted_content().clone(),
                &ContentEncryptionKeyV1::generate().unwrap(),
                bundle.signed_pool().pool_identity().unwrap(),
                bundle.signed_epoch().epoch_identity().unwrap(),
                bundle
                    .signed_committee_authorization()
                    .authorization_identity()
                    .unwrap(),
                &nodes,
            )
            .unwrap();
            let mut provider = ProviderProcess::start();
            assert_eq!(provider.request(init)["status"], "ok");
            if provision {
                let record = CustodyNodeProvisioningRecordV1::new(
                    envelope.key_envelope_identity().unwrap(),
                    envelope.manifest().clone(),
                    node_public_key(POOL_NODE),
                    envelope
                        .stored_share_for_node(node_public_key(POOL_NODE))
                        .unwrap()
                        .clone(),
                )
                .unwrap();
                let provisioned = provider.request(request_value(
                    &CustodyProviderRequestV1::new_provision_node_share(
                        &record,
                        &signed_provisioning(&record),
                    )
                    .unwrap(),
                ));
                assert_eq!(provisioned["status"], "ok", "{provisioned}");
            }
            Self {
                provider,
                key_envelope: envelope.key_envelope_identity().unwrap(),
                envelope,
                bundle,
                now,
                member_window,
                revoked_node,
            }
        }

        fn spec(&self) -> PoolReleaseSpecV1 {
            let mut spec = PoolReleaseSpecV1::new(xwing_public_key, policy_body(), self.now);
            spec.recipients = vec![(9, POOL_NODE)];
            spec.key_envelope = Some(self.key_envelope.clone());
            spec.member_window = self.member_window;
            spec.revoked_node = self.revoked_node;
            spec
        }

        fn release(
            &mut self,
            operation: &SignedRuntimeReleaseOperationV2,
            decision: &SignedNodeRightsDecisionV1,
        ) -> (PoolCustodyRequestV1, serde_json::Value) {
            let request =
                PoolCustodyRequestV1::new_release_pool_contribution(operation, decision).unwrap();
            let response = self
                .provider
                .request(serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap());
            (request, response)
        }

        fn release_fixture(
            &mut self,
            fixture: &PoolReleaseFixtureV1,
        ) -> (PoolCustodyRequestV1, serde_json::Value) {
            let decision = signed_node_rights_decision(
                &fixture.authenticated(),
                POOL_NODE,
                RightsDecisionV1::Allowed,
                self.now,
            );
            self.release(&fixture.operation, &decision)
        }

        fn rights_frame(&mut self, frame: PrivateCustodyRightsRequestV1) -> serde_json::Value {
            self.provider.request(private_rights_value(&frame))
        }
    }

    fn v2_rights_request_value(operation: &SignedRuntimeReleaseOperationV2) -> serde_json::Value {
        serde_json::from_slice(
            &RightsProviderRequestV1::new_evaluate_any(
                node_public_key(POOL_NODE),
                &RuntimeReleaseOperationAnyV1::V2(operation.clone()),
            )
            .unwrap()
            .to_json_vec()
            .unwrap(),
        )
        .unwrap()
    }

    fn contributions_of(
        request: &PoolCustodyRequestV1,
        response: &serde_json::Value,
    ) -> Vec<SignedNodeContributionV1> {
        assert_eq!(response["status"], "ok", "{response}");
        let answer: PoolCustodyResponseV1 =
            serde_json::from_value(response["data"].clone()).unwrap();
        assert_eq!(answer.status(), PoolCustodyResponseStatusV1::Contributions);
        answer
            .validate_against_plain_request_at(
                request,
                node_public_key(POOL_NODE),
                now_unix_seconds(),
            )
            .unwrap();
        answer.signed_node_contributions().unwrap()
    }

    fn error_code(response: &serde_json::Value) -> &str {
        assert_eq!(response["status"], "error", "{response}");
        response["code"].as_str().unwrap()
    }

    #[test]
    fn v2_release_to_member_vouched_recipients_yields_contributions() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = PoolNode::start(temp.path(), None, None, true);

        // One recipient under the default of one server per session.
        let one = pool_release_fixture(&node.spec());
        let (request, response) = node.release_fixture(&one);
        assert_eq!(contributions_of(&request, &response).len(), 1);

        // Two recipients under a descriptor that signs two servers (F5).
        let mut spec = node.spec();
        spec.recipients = vec![(9, POOL_NODE), (10, 3)];
        spec.max_servers_per_session = 2;
        spec.replay_nonce = 0x56;
        spec.audit_request_id = 0x92;
        let two = pool_release_fixture(&spec);
        let (request, response) = node.release_fixture(&two);
        assert_eq!(contributions_of(&request, &response).len(), 2);
        node.provider.stop();
    }

    #[test]
    fn guard_v2_release_to_buyer_made_key_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = PoolNode::start(temp.path(), None, None, true);
        // Node 7 is no pool member: the recipient key is the buyer's own.
        let mut spec = node.spec();
        spec.recipients = vec![(9, 7)];
        let fixture = pool_release_fixture(&spec);
        let decision = signed_node_rights_decision_for_signed(
            &fixture.operation,
            POOL_NODE,
            RightsDecisionV1::Allowed,
            node.now,
        );
        let (_, response) = node.release(&fixture.operation, &decision);
        assert_eq!(error_code(&response), "invalid_request");
        let prepare = node.rights_frame(PrivateCustodyRightsRequestV1::new_prepare(
            v2_rights_request_value(&fixture.operation),
        ));
        assert_eq!(error_code(&prepare), "invalid_request");
        node.provider.stop();
    }

    #[test]
    fn guard_v2_release_with_stale_descriptor_sequence_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = PoolNode::start(temp.path(), None, None, true);
        let mut spec = node.spec();
        spec.descriptor_sequence = 5;
        let (request, response) = node.release_fixture(&pool_release_fixture(&spec));
        contributions_of(&request, &response);

        // An older descriptor is refused at prepare and at release.
        spec.descriptor_sequence = 4;
        spec.replay_nonce = 0x56;
        spec.audit_request_id = 0x92;
        let stale = pool_release_fixture(&spec);
        let prepare = node.rights_frame(PrivateCustodyRightsRequestV1::new_prepare(
            v2_rights_request_value(&stale.operation),
        ));
        assert_eq!(error_code(&prepare), "invalid_request");
        let (_, response) = node.release_fixture(&stale);
        assert_eq!(error_code(&response), "invalid_request");

        // The same or a newer one is accepted.
        spec.descriptor_sequence = 6;
        spec.replay_nonce = 0x57;
        spec.audit_request_id = 0x93;
        let (request, response) = node.release_fixture(&pool_release_fixture(&spec));
        contributions_of(&request, &response);
        node.provider.stop();
    }

    #[test]
    fn guard_unknown_envelope_refused_before_chain_request() {
        let temp = tempfile::tempdir().unwrap();
        // The node holds no share of the item (L8).
        let mut node = PoolNode::start(temp.path(), None, None, false);
        let fixture = pool_release_fixture(&node.spec());
        let prepare = node.rights_frame(PrivateCustodyRightsRequestV1::new_prepare(
            v2_rights_request_value(&fixture.operation),
        ));
        assert_eq!(error_code(&prepare), "unknown_envelope");
        assert!(prepare.get("data").is_none());
        let (_, response) = node.release_fixture(&fixture);
        assert_eq!(error_code(&response), "unknown_envelope");
        node.provider.stop();
    }

    #[test]
    fn guard_attest_recipient_for_another_node_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = PoolNode::start(temp.path(), None, None, true);
        let fixture = pool_release_fixture(&node.spec());
        let now = node.now;
        let statement_for = |server| {
            recipient_attestation_statement(
                xwing_public_key,
                &fixture.bundle,
                &fixture.binding,
                runtime_issuer(0x43),
                9,
                server,
                now,
            )
        };
        let request_for = |server| {
            PoolCustodyRequestV1::new_sign_recipient_attestation(&statement_for(server)).unwrap()
        };
        let other = request_for(3);
        let response = node
            .provider
            .request(serde_json::from_slice(&other.to_json_vec().unwrap()).unwrap());
        assert_eq!(error_code(&response), "invalid_request");

        let own = request_for(POOL_NODE);
        let response = node
            .provider
            .request(serde_json::from_slice(&own.to_json_vec().unwrap()).unwrap());
        assert_eq!(response["status"], "ok", "{response}");
        let answer: PoolCustodyResponseV1 =
            serde_json::from_value(response["data"].clone()).unwrap();
        assert_eq!(
            answer.status(),
            PoolCustodyResponseStatusV1::StatementSignature
        );
        answer
            .validate_against_plain_request_at(&own, node_public_key(POOL_NODE), now_unix_seconds())
            .unwrap();
        node.provider.stop();
    }

    #[test]
    fn guard_attest_recipient_for_a_non_member_server_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = PoolNode::start(temp.path(), None, None, true);
        let fixture = pool_release_fixture(&node.spec());
        // Node 7 is in no committee of the pool.
        let statement = recipient_attestation_statement(
            xwing_public_key,
            &fixture.bundle,
            &fixture.binding,
            runtime_issuer(0x43),
            9,
            7,
            node.now,
        );
        let request = PoolCustodyRequestV1::new_sign_recipient_attestation(&statement).unwrap();
        let response = node
            .provider
            .request(serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap());
        assert_eq!(error_code(&response), "invalid_request");
        node.provider.stop();
    }

    #[test]
    fn term_end_does_not_stop_release() {
        // Every signed member window ended before the node's clock; the
        // descriptor window is open (F1, D5).
        let ended = Some((now_unix_seconds() - 1_000, now_unix_seconds() - 30));
        let temp = tempfile::tempdir().unwrap();
        let mut node = PoolNode::start(temp.path(), ended, None, true);
        let (request, response) = node.release_fixture(&pool_release_fixture(&node.spec()));
        assert_eq!(contributions_of(&request, &response).len(), 1);
        node.provider.stop();

        // The same committee with a revoked member is refused.
        let revoked_temp = tempfile::tempdir().unwrap();
        let mut revoked = PoolNode::start(revoked_temp.path(), ended, Some(3), true);
        let fixture = pool_release_fixture(&revoked.spec());
        let decision = signed_node_rights_decision_for_signed(
            &fixture.operation,
            POOL_NODE,
            RightsDecisionV1::Allowed,
            revoked.now,
        );
        let (_, response) = revoked.release(&fixture.operation, &decision);
        assert_eq!(error_code(&response), "invalid_request");
        revoked.provider.stop();
    }

    #[test]
    fn process_v2_release_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = PoolNode::start(temp.path(), None, None, true);
        let fixture = pool_release_fixture(&node.spec());
        let operation = fixture.authenticated();
        let rights_request = v2_rights_request_value(&fixture.operation);

        // prepare: a chain request for the V2 operation, after every check.
        let prepare = node.rights_frame(PrivateCustodyRightsRequestV1::new_prepare(
            rights_request.clone(),
        ));
        assert_eq!(prepare["status"], "ok", "{prepare}");
        assert_eq!(
            prepare["data"]["signed_runtime_release_operation"],
            format!(
                "0x{}",
                hex_bytes(&fixture.operation.canonical_bytes().unwrap())
            )
        );

        // settle: chain evidence binds the operation hash in both slots (L1).
        let acquired_at = now_unix_seconds();
        let request = fixture.operation.statement().evidence_request();
        let evidence = RightsEvaluationEvidenceV1::new(
            operation.operation_hash(),
            operation.operation_hash(),
            request.binding().clone(),
            request.policy_identity().clone(),
            request.binding().wallet(),
            fixture.operation.statement().policy_body().chain_id(),
            42,
            digest(0x77),
            true,
            acquired_at,
            acquired_at + 20,
        )
        .unwrap();
        let settle = node.rights_frame(PrivateCustodyRightsRequestV1::new_settle(
            rights_request,
            serde_json::json!({
                "schema": "elastos.chain.protected-content-rights-evidence/v1",
                "rights_evaluation_evidence": format!("0x{}", hex_bytes(&evidence.canonical_bytes().unwrap())),
            }),
        ));
        assert_eq!(settle["status"], "ok", "{settle}");
        let decision = serde_json::from_value::<RightsProviderResponseV1>(settle["data"].clone())
            .unwrap()
            .signed_node_rights_decision()
            .unwrap();
        assert_eq!(
            decision.statement().release_request_hash(),
            operation.operation_hash()
        );

        // release: the contribution, then the exact replay.
        let (release_request, release) = node.release(&fixture.operation, &decision);
        let contributions = contributions_of(&release_request, &release);
        assert_eq!(contributions.len(), 1);
        let (_, replay) = node.release(&fixture.operation, &decision);
        assert_eq!(replay["data"], release["data"]);
        node.provider.stop();
    }

    // -----------------------------------------------------------------------
    // Plan B POOL-MINT: a Home that uses the pool provisions this node's share.
    // -----------------------------------------------------------------------

    mod minter {
        use super::*;
        use elastos_protected_content_contracts::test_fixtures::{
            pool_descriptor_signed_by, pool_did, pool_mint_share, runtime_custody_provisioning,
            POOL_AUTHORITY_SEED,
        };
        use elastos_protected_content_contracts::ContentAccessIdV1;

        const MINTER: u8 = 0x44;
        const OTHER_HOME: u8 = 0x45;

        struct Provision {
            kid: ContentAccessIdV1,
            minter: u8,
            /// The share statement carries another Home's signature.
            wrong_signature: bool,
            sequence: u64,
            tamper_share: bool,
        }

        impl Default for Provision {
            fn default() -> Self {
                Self {
                    kid: policy_body().content_access_id(),
                    minter: MINTER,
                    wrong_signature: false,
                    sequence: 1,
                    tamper_share: false,
                }
            }
        }

        fn pool_request(node: &PoolNode, provision: &Provision) -> PoolCustodyRequestV1 {
            let mut share = node
                .envelope
                .stored_share_for_node(node_public_key(POOL_NODE))
                .unwrap()
                .clone();
            if provision.tamper_share {
                share = share.tamper_envelope();
            }
            let record = CustodyNodeProvisioningRecordV1::new(
                node.key_envelope.clone(),
                node.envelope.manifest().clone(),
                node_public_key(POOL_NODE),
                share,
            )
            .unwrap();
            let issued_at = now_unix_seconds() - 1;
            let statement =
                runtime_custody_provisioning(&record, provision.minter, 0xf1, issued_at);
            let mut share = pool_mint_share(
                pool_did(),
                &node.key_envelope,
                provision.kid,
                provision.minter,
            );
            if provision.wrong_signature {
                let other =
                    pool_mint_share(pool_did(), &node.key_envelope, provision.kid, OTHER_HOME);
                share = elastos_protected_content_contracts::SignedPoolMintShareV1::new(
                    share.statement().clone(),
                    other.runtime_signature().to_vec(),
                )
                .unwrap();
            }
            let descriptor = pool_descriptor_signed_by(
                &node.bundle,
                provision.sequence,
                node.now,
                POOL_AUTHORITY_SEED,
            );
            PoolCustodyRequestV1::new_provision_pool_node_share(
                &record,
                &statement,
                &share,
                &descriptor.into(),
            )
            .unwrap()
        }

        fn provision(node: &mut PoolNode, provision: &Provision) -> serde_json::Value {
            let request = pool_request(node, provision);
            node.provider
                .request(serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap())
        }

        fn provisioned(node: &mut PoolNode, request: &Provision) {
            let sent = pool_request(node, request);
            let response = node
                .provider
                .request(serde_json::from_slice(&sent.to_json_vec().unwrap()).unwrap());
            assert_eq!(response["status"], "ok", "{response}");
            let answer: PoolCustodyResponseV1 =
                serde_json::from_value(response["data"].clone()).unwrap();
            assert_eq!(answer.status(), PoolCustodyResponseStatusV1::Provisioned);
            answer
                .validate_against_plain_request_at(
                    &sent,
                    node_public_key(POOL_NODE),
                    now_unix_seconds(),
                )
                .unwrap();
        }

        fn releases(node: &mut PoolNode, nonce: u8) -> bool {
            let mut spec = node.spec();
            spec.replay_nonce = nonce;
            spec.audit_request_id = nonce;
            let (request, response) = node.release_fixture(&pool_release_fixture(&spec));
            if response["status"] != "ok" {
                return false;
            }
            let answer: PoolCustodyResponseV1 =
                serde_json::from_value(response["data"].clone()).unwrap();
            answer.status() == PoolCustodyResponseStatusV1::Contributions
                && answer
                    .validate_against_plain_request_at(
                        &request,
                        node_public_key(POOL_NODE),
                        now_unix_seconds(),
                    )
                    .is_ok()
        }

        #[test]
        fn provisioning_from_a_home_that_uses_the_pool_is_stored() {
            let temp = tempfile::tempdir().unwrap();
            let mut node = PoolNode::start(temp.path(), None, None, false);
            provisioned(&mut node, &Provision::default());
            node.provider.stop();
        }

        #[test]
        fn minter_provisioned_share_loads_for_v2_release() {
            let temp = tempfile::tempdir().unwrap();
            let mut node = PoolNode::start(temp.path(), None, None, false);
            provisioned(&mut node, &Provision::default());
            assert!(releases(&mut node, 0x61));
            node.provider.stop();
        }

        #[test]
        fn process_v2_release_with_the_bound_kid_releases() {
            let temp = tempfile::tempdir().unwrap();
            let mut node = PoolNode::start(temp.path(), None, None, false);
            provisioned(&mut node, &Provision::default());
            assert!(releases(&mut node, 0x62));
            node.provider.stop();
        }

        #[test]
        fn process_v2_release_naming_another_kid_is_refused() {
            let temp = tempfile::tempdir().unwrap();
            let mut node = PoolNode::start(temp.path(), None, None, false);
            provisioned(
                &mut node,
                &Provision {
                    kid: ContentAccessIdV1::new([0x99; 16]).unwrap(),
                    ..Provision::default()
                },
            );
            assert!(!releases(&mut node, 0x63));
            node.provider.stop();
        }

        #[test]
        fn minter_provisioned_share_survives_restart_with_its_kid() {
            let temp = tempfile::tempdir().unwrap();
            let mut node = PoolNode::start(temp.path(), None, None, false);
            provisioned(&mut node, &Provision::default());
            node.provider.stop();
            node.provider = ProviderProcess::start();
            let init = prepare_config_with_seeds(
                temp.path(),
                CUSTODY_KEY_SEED_BASE + POOL_NODE,
                POOL_NODE,
            );
            assert_eq!(node.provider.request(init)["status"], "ok");
            assert!(releases(&mut node, 0x64));
            node.provider.stop();
        }

        #[test]
        fn guard_share_with_a_wrong_minter_signature_is_refused() {
            let temp = tempfile::tempdir().unwrap();
            let mut node = PoolNode::start(temp.path(), None, None, false);
            let response = provision(
                &mut node,
                &Provision {
                    wrong_signature: true,
                    ..Provision::default()
                },
            );
            assert_eq!(error_code(&response), "invalid_request");
            // Nothing was stored.
            let (_, release) = node.release_fixture(&pool_release_fixture(&node.spec()));
            assert_eq!(error_code(&release), "unknown_envelope");
            node.provider.stop();
        }

        #[test]
        fn provisioning_under_a_descriptor_below_the_high_water_mark_is_refused() {
            let temp = tempfile::tempdir().unwrap();
            let mut node = PoolNode::start(temp.path(), None, None, false);
            provisioned(
                &mut node,
                &Provision {
                    sequence: 5,
                    ..Provision::default()
                },
            );
            let response = provision(
                &mut node,
                &Provision {
                    sequence: 4,
                    ..Provision::default()
                },
            );
            assert_eq!(error_code(&response), "provisioning_refused");
            node.provider.stop();
        }

        #[test]
        fn provisioning_after_term_end_is_refused() {
            let ended = Some((now_unix_seconds() - 1_000, now_unix_seconds() - 30));
            let temp = tempfile::tempdir().unwrap();
            let mut node = PoolNode::start(temp.path(), ended, None, false);
            let response = provision(&mut node, &Provision::default());
            assert_eq!(error_code(&response), "invalid_request");
            node.provider.stop();
        }

        #[test]
        fn provisioning_with_a_share_statement_for_another_envelope_is_refused() {
            let temp = tempfile::tempdir().unwrap();
            let mut node = PoolNode::start(temp.path(), None, None, false);
            let own = pool_request(&node, &Provision::default());
            let mut value: serde_json::Value =
                serde_json::from_slice(&own.to_json_vec().unwrap()).unwrap();
            // Another item's share statement, swapped in on the wire.
            let other_envelope = KeyEnvelopeIdentityV1::new(
                elastos_protected_content_contracts::EncryptedContentIdentityV1::new(
                    digest(0x5c),
                    4096,
                )
                .unwrap(),
                node.key_envelope.envelope_sha256(),
                node.key_envelope.envelope_bytes(),
                node.key_envelope.node_set_id(),
                node.key_envelope.threshold(),
                node.key_envelope.custody_pool(),
                node.key_envelope.custody_epoch(),
                node.key_envelope.custody_committee_authorization(),
            )
            .unwrap();
            let other = pool_mint_share(
                pool_did(),
                &other_envelope,
                policy_body().content_access_id(),
                MINTER,
            );
            value["signed_pool_mint_share"] =
                serde_json::to_value(other.canonical_bytes().unwrap()).unwrap();
            let response = node.provider.request(value);
            assert_eq!(error_code(&response), "invalid_request");
            node.provider.stop();
        }

        #[test]
        fn identical_duplicate_share_is_already_stored() {
            let temp = tempfile::tempdir().unwrap();
            let mut node = PoolNode::start(temp.path(), None, None, false);
            provisioned(&mut node, &Provision::default());
            provisioned(&mut node, &Provision::default());
            assert!(releases(&mut node, 0x65));
            node.provider.stop();
        }

        #[test]
        fn guard_different_record_for_an_occupied_slot_is_refused() {
            let temp = tempfile::tempdir().unwrap();
            let mut node = PoolNode::start(temp.path(), None, None, false);
            provisioned(&mut node, &Provision::default());
            let response = provision(
                &mut node,
                &Provision {
                    tamper_share: true,
                    ..Provision::default()
                },
            );
            assert_eq!(error_code(&response), "provisioning_refused");
            assert!(releases(&mut node, 0x66));
            node.provider.stop();
        }

        #[test]
        fn guard_retry_with_another_kid_is_refused() {
            let temp = tempfile::tempdir().unwrap();
            let mut node = PoolNode::start(temp.path(), None, None, false);
            provisioned(&mut node, &Provision::default());
            let response = provision(
                &mut node,
                &Provision {
                    kid: ContentAccessIdV1::new([0x99; 16]).unwrap(),
                    ..Provision::default()
                },
            );
            assert_eq!(error_code(&response), "provisioning_refused");
            node.provider.stop();
        }

        #[test]
        fn status_lists_the_pool_provisioning_op() {
            let temp = tempfile::tempdir().unwrap();
            let mut node = PoolNode::start(temp.path(), None, None, false);
            let status = node.provider.request(serde_json::json!({"op": "status"}));
            assert!(status["data"]["supported_operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|op| op == "provision_pool_node_share"));
            node.provider.stop();
        }
    }

    // -----------------------------------------------------------------------
    // ADV-02: every gate of the node's V2 declared-issuer release path has a
    // must-refuse test and a positive control.
    // -----------------------------------------------------------------------

    /// The settle answer for `has_access` chain evidence of `fixture`'s
    /// operation, after an accepted prepare.
    fn settle_with_access(
        node: &mut PoolNode,
        fixture: &PoolReleaseFixtureV1,
        has_access: bool,
    ) -> serde_json::Value {
        let operation = fixture.authenticated();
        let rights_request = v2_rights_request_value(&fixture.operation);
        let prepare = node.rights_frame(PrivateCustodyRightsRequestV1::new_prepare(
            rights_request.clone(),
        ));
        assert_eq!(prepare["status"], "ok", "{prepare}");
        let acquired_at = now_unix_seconds();
        let request = fixture.operation.statement().evidence_request();
        let evidence = RightsEvaluationEvidenceV1::new(
            operation.operation_hash(),
            operation.operation_hash(),
            request.binding().clone(),
            request.policy_identity().clone(),
            request.binding().wallet(),
            fixture.operation.statement().policy_body().chain_id(),
            42,
            digest(0x77),
            has_access,
            acquired_at,
            acquired_at + 20,
        )
        .unwrap();
        node.rights_frame(PrivateCustodyRightsRequestV1::new_settle(
            rights_request,
            serde_json::json!({
                "schema": "elastos.chain.protected-content-rights-evidence/v1",
                "rights_evaluation_evidence": format!("0x{}", hex_bytes(&evidence.canonical_bytes().unwrap())),
            }),
        ))
    }

    /// Gate (a): the rights request must carry the bound wallet's signature.
    #[test]
    fn guard_adv02_rights_signed_by_another_wallet_are_refused_at_prepare_and_release() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = PoolNode::start(temp.path(), None, None, true);
        let mut spec = node.spec();
        spec.wallet_signer_seed = Some(8);
        let forged = pool_release_fixture(&spec);
        let prepare = node.rights_frame(PrivateCustodyRightsRequestV1::new_prepare(
            v2_rights_request_value(&forged.operation),
        ));
        assert_eq!(error_code(&prepare), "invalid_request");
        let decision = signed_node_rights_decision_for_signed(
            &forged.operation,
            POOL_NODE,
            RightsDecisionV1::Allowed,
            node.now,
        );
        let (_, response) = node.release(&forged.operation, &decision);
        assert_eq!(error_code(&response), "invalid_request");

        // Positive control: the bound wallet's own signature releases.
        let (request, response) = node.release_fixture(&pool_release_fixture(&node.spec()));
        assert_eq!(contributions_of(&request, &response).len(), 1);
        node.provider.stop();
    }

    /// Gate (b): the node releases only on finalized rights evidence that
    /// grants access.
    #[test]
    fn guard_adv02_release_without_granted_rights_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = PoolNode::start(temp.path(), None, None, true);
        let denied = pool_release_fixture(&node.spec());
        let settle = settle_with_access(&mut node, &denied, false);
        assert_eq!(settle["status"], "ok", "{settle}");
        let decision = serde_json::from_value::<RightsProviderResponseV1>(settle["data"].clone())
            .unwrap()
            .signed_node_rights_decision()
            .unwrap();
        // Evidence without access settles to a denied decision, which does
        // not release.
        assert_eq!(decision.statement().decision(), RightsDecisionV1::Denied);
        let (_, response) = node.release(&denied.operation, &decision);
        assert_eq!(error_code(&response), "rights_denied");

        // Positive control: granted rights settle to an allowed decision that
        // releases.
        let mut spec = node.spec();
        spec.replay_nonce = 0x56;
        spec.audit_request_id = 0x92;
        let granted = pool_release_fixture(&spec);
        let settle = settle_with_access(&mut node, &granted, true);
        assert_eq!(settle["status"], "ok", "{settle}");
        let decision = serde_json::from_value::<RightsProviderResponseV1>(settle["data"].clone())
            .unwrap()
            .signed_node_rights_decision()
            .unwrap();
        let (request, response) = node.release(&granted.operation, &decision);
        assert_eq!(contributions_of(&request, &response).len(), 1);
        node.provider.stop();
    }

    /// Gate (c): the V2 operation must carry its declared Runtime's signature.
    #[test]
    fn guard_adv02_operation_with_a_bad_runtime_signature_is_refused_at_prepare_and_release() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = PoolNode::start(temp.path(), None, None, true);
        let fixture = pool_release_fixture(&node.spec());
        let statement = fixture.operation.statement().clone();
        let forged = SignedRuntimeReleaseOperationV2::new(
            statement.clone(),
            SigningKey::from_bytes(&[0x44; 32])
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        let prepare = node.rights_frame(PrivateCustodyRightsRequestV1::new_prepare(
            v2_rights_request_value(&forged),
        ));
        assert_eq!(error_code(&prepare), "invalid_request");
        let decision = signed_node_rights_decision_for_signed(
            &forged,
            POOL_NODE,
            RightsDecisionV1::Allowed,
            node.now,
        );
        let (_, response) = node.release(&forged, &decision);
        assert_eq!(error_code(&response), "invalid_request");

        // Positive control: the same statement with its Runtime's signature.
        let (request, response) = node.release_fixture(&fixture);
        assert_eq!(contributions_of(&request, &response).len(), 1);
        node.provider.stop();
    }

    /// Gate (e): the node signs an attestation only for an item whose epoch
    /// holds this node's share.
    #[test]
    fn guard_adv02_attestation_outside_this_nodes_epoch_is_refused() {
        let sign_request = |node: &mut PoolNode, statement| {
            let request = PoolCustodyRequestV1::new_sign_recipient_attestation(&statement).unwrap();
            node.provider
                .request(serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap())
        };

        // This node holds no share of the item.
        let temp = tempfile::tempdir().unwrap();
        let mut unprovisioned = PoolNode::start(temp.path(), None, None, false);
        let fixture = pool_release_fixture(&unprovisioned.spec());
        let statement = recipient_attestation_statement(
            xwing_public_key,
            &fixture.bundle,
            &fixture.binding,
            runtime_issuer(0x43),
            9,
            POOL_NODE,
            unprovisioned.now,
        );
        let response = sign_request(&mut unprovisioned, statement);
        assert_eq!(error_code(&response), "unknown_envelope");
        unprovisioned.provider.stop();

        // The statement names an epoch other than the item's.
        let temp = tempfile::tempdir().unwrap();
        let mut node = PoolNode::start(temp.path(), None, None, true);
        let fixture = pool_release_fixture(&node.spec());
        let item_epoch = fixture.bundle.epoch_identity().unwrap();
        let other_epoch = PoolRecipientAttestationStatementV2::new(
            elastos_protected_content_contracts::test_fixtures::pool_did(),
            CustodyEpochIdentityV1::new(Digest32::new([0xee; 32]), item_epoch.epoch_bytes())
                .unwrap(),
            node_public_key(POOL_NODE),
            fixture.binding.clone(),
            RightsActionV1::View,
            elastos_protected_content_contracts::test_fixtures::recipient_public_key(
                xwing_public_key,
                9,
            ),
            elastos_protected_content_contracts::test_fixtures::recipient_identity(
                xwing_public_key,
                9,
            ),
            runtime_issuer(0x43),
            node.now,
            node.now + 200,
            PoolTrustModeV1::WciOperated,
            Vec::new(),
        )
        .unwrap();
        let response = sign_request(&mut node, other_epoch);
        assert_eq!(error_code(&response), "invalid_request");

        // Positive control: the item's own epoch, server this node.
        let own = recipient_attestation_statement(
            xwing_public_key,
            &fixture.bundle,
            &fixture.binding,
            runtime_issuer(0x43),
            9,
            POOL_NODE,
            node.now,
        );
        let response = sign_request(&mut node, own);
        assert_eq!(response["status"], "ok", "{response}");
        node.provider.stop();
    }
}

/// Plan B T2.1: one custody-provider process holds one root per pool and
/// routes each request by the node key it names.
mod root_set {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn owner_only_dir(path: &Path) {
        if !path.exists() {
            fs::create_dir(path).unwrap();
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// `<temp>/data/protected-content/custody-provider`, as the Runtime lays
    /// it out.
    fn custody_base(temp: &Path) -> PathBuf {
        let data = fs::canonicalize(temp).unwrap().join("data");
        let base = data.join("protected-content/custody-provider");
        for dir in [
            data.clone(),
            data.join("protected-content"),
            base.clone(),
            base.join("pools"),
        ] {
            owner_only_dir(&dir);
        }
        base
    }

    fn pool_path(fill: char) -> String {
        format!("pools/{}", fill.to_string().repeat(64))
    }

    fn provision_root(base: &Path, path: &str) -> ProvisionedProviderNode {
        let root = base.join(path);
        if !root.exists() {
            provision_state_root(
                &root,
                parse_runtime_issuer_hex(&runtime_issuer_hex(0x42)).unwrap(),
            )
            .unwrap();
        }
        load_provisioned_provider_node(&root)
    }

    fn roots_init(base: &Path, paths: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "op": "init",
            "config": {
                "base_path": base,
                "allowed_paths": [],
                "read_only": false,
                "encryption_key": "",
                "extra": {
                    "roots": paths
                        .iter()
                        .map(|path| serde_json::json!({"path": path}))
                        .collect::<Vec<_>>(),
                    "max_roots": 8,
                }
            }
        })
    }

    fn root_status(provider: &mut ProviderProcess, path: &str) -> serde_json::Value {
        let status = provider.request(serde_json::json!({"op": "status"}));
        status["data"]["roots"]
            .as_array()
            .unwrap()
            .iter()
            .find(|root| root["path"] == path)
            .cloned()
            .unwrap()
    }

    struct HeldItem {
        provision: CustodyProviderRequestV1,
        release: CustodyProviderRequestV1,
        operation: SignedRuntimeReleaseOperationV1,
        epoch: SignedCustodyEpochV1,
    }

    /// One V1 item whose committee names `node`, with its provisioning and
    /// release requests.
    fn held_item(node: &ProvisionedProviderNode) -> HeldItem {
        let record = provisioning_record_with_provider(node);
        let provision = CustodyProviderRequestV1::new_provision_node_share(
            &record,
            &signed_provisioning(&record),
        )
        .unwrap();
        let epoch = signed_epoch_with_provider(node);
        let operation =
            signed_release_operation_with_runtime_seed_and_epoch(&record, 0x43, epoch.clone());
        let decision = signed_decision_with_provider(&operation, node, RightsDecisionV1::Allowed);
        let release =
            CustodyProviderRequestV1::new_release_contribution(&operation, &decision).unwrap();
        HeldItem {
            provision,
            release,
            operation,
            epoch,
        }
    }

    /// The contribution verifies against the item's epoch, so it was signed
    /// by the node the request named.
    fn assert_contribution_from(response: &serde_json::Value, item: &HeldItem) {
        assert_eq!(response["status"], "ok", "{response}");
        let response: CustodyProviderResponseV1 =
            serde_json::from_value(response["data"].clone()).unwrap();
        let contribution = response.signed_node_contribution().unwrap();
        let authenticated = item
            .operation
            .verify(
                item.operation.statement().runtime_operation_issuer(),
                now_unix_seconds(),
            )
            .unwrap();
        authenticated
            .verify_node_contribution(
                &contribution,
                &item.epoch.statement().node_set().unwrap(),
                now_unix_seconds(),
            )
            .unwrap();
    }

    #[test]
    fn process_two_pools_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let base = custody_base(temp.path());
        let pool = pool_path('a');
        let first = provision_root(&base, "inactive");
        let second = provision_root(&base, &pool);
        assert_ne!(first.node_public_key, second.node_public_key);
        let (first_item, second_item) = (held_item(&first), held_item(&second));

        let mut provider = ProviderProcess::start();
        let init = provider.request(roots_init(&base, &["inactive", &pool]));
        assert_eq!(init["status"], "ok", "{init}");
        for item in [&first_item, &second_item] {
            let provisioned = provider.request(request_value(&item.provision));
            assert_eq!(provisioned["status"], "ok", "{provisioned}");
        }
        let first_release = provider.request(request_value(&first_item.release));
        assert_contribution_from(&first_release, &first_item);
        let second_release = provider.request(request_value(&second_item.release));
        assert_contribution_from(&second_release, &second_item);
        assert_eq!(root_status(&mut provider, "inactive")["shares_held"], 1);
        assert_eq!(root_status(&mut provider, &pool)["shares_held"], 1);
        provider.stop();

        // A restart loads both roots again; each replays exactly.
        let mut restarted = ProviderProcess::start();
        assert_eq!(
            restarted.request(roots_init(&base, &["inactive", &pool]))["status"],
            "ok"
        );
        assert_eq!(
            restarted.request(request_value(&first_item.release))["data"],
            first_release["data"]
        );
        assert_eq!(
            restarted.request(request_value(&second_item.release))["data"],
            second_release["data"]
        );
        restarted.stop();
    }

    #[test]
    fn two_roots_release_independently() {
        let temp = tempfile::tempdir().unwrap();
        let base = custody_base(temp.path());
        let pool = pool_path('b');
        let first = provision_root(&base, "inactive");
        let second = provision_root(&base, &pool);
        let (first_item, second_item) = (held_item(&first), held_item(&second));

        let mut provider = ProviderProcess::start();
        assert_eq!(
            provider.request(roots_init(&base, &["inactive", &pool]))["status"],
            "ok"
        );
        // Only the first root holds its item; the second root's share store
        // is broken. The first root still releases.
        assert_eq!(
            provider.request(request_value(&first_item.provision))["status"],
            "ok"
        );
        let shares = base.join(&pool).join("data/node-shares");
        fs::write(&shares, b"not a folder").unwrap();
        let refused = provider.request(request_value(&second_item.provision));
        assert_eq!(refused["status"], "error", "{refused}");
        assert_contribution_from(
            &provider.request(request_value(&first_item.release)),
            &first_item,
        );
        // The second root never held the first item's share.
        assert_eq!(root_status(&mut provider, "inactive")["shares_held"], 1);
        provider.stop();
    }

    /// S2-F1: once the Runtime sends `init` without a stopped root (its
    /// folder set aside), that root signs, provisions and releases nothing,
    /// before any store; the root left still serves.
    #[test]
    fn a_stopped_root_does_no_sign_provision_or_release() {
        use elastos_protected_content_contracts::test_fixtures::{
            pool_release_fixture, recipient_attestation_statement, runtime_issuer,
            PoolReleaseSpecV1, CUSTODY_KEY_SEED_BASE,
        };
        use elastos_protected_content_contracts::PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES;
        use elastos_protected_content_provider_contracts::PoolCustodyRequestV1;
        const STOPPED_NODE: u8 = 1;
        fn xwing_public_key(seed: u8) -> [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
            *NodeCustodySecretKeyV1::from_guarded_bytes(Zeroizing::new([seed; 32]))
                .unwrap()
                .public_key()
                .unwrap()
                .as_bytes()
        }

        let temp = tempfile::tempdir().unwrap();
        let base = custody_base(temp.path());
        let kept = provision_root(&base, "inactive");
        let stopped_path = pool_path('f');
        provision_root(&base, &stopped_path);
        // The stopped root is the fixture's pool node, so a statement can
        // name it.
        for (file, seed) in [
            ("node-signing-key", STOPPED_NODE),
            ("node-custody-secret", CUSTODY_KEY_SEED_BASE + STOPPED_NODE),
        ] {
            let path = base.join(&stopped_path).join(file);
            fs::write(&path, format!("0x{}", hex_bytes(&[seed; 32]))).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let stopped = load_provisioned_provider_node(&base.join(&stopped_path));
        assert_eq!(stopped.node_public_key, node_public_key(STOPPED_NODE));
        let (kept_item, stopped_item) = (held_item(&kept), held_item(&stopped));
        let now = now_unix_seconds() - 10;
        let mut spec = PoolReleaseSpecV1::new(xwing_public_key, policy_body(), now);
        spec.recipients = vec![(9, STOPPED_NODE)];
        let fixture = pool_release_fixture(&spec);
        let sign =
            PoolCustodyRequestV1::new_sign_recipient_attestation(&recipient_attestation_statement(
                xwing_public_key,
                &fixture.bundle,
                &fixture.binding,
                runtime_issuer(0x43),
                9,
                STOPPED_NODE,
                now,
            ))
            .unwrap();
        let sign: serde_json::Value = serde_json::from_slice(&sign.to_json_vec().unwrap()).unwrap();

        let mut provider = ProviderProcess::start();
        assert_eq!(
            provider.request(roots_init(&base, &["inactive", &stopped_path]))["status"],
            "ok"
        );
        // Positive control: while served, each frame reaches the root.
        assert_eq!(
            provider.request(request_value(&stopped_item.provision))["status"],
            "ok"
        );
        assert_contribution_from(
            &provider.request(request_value(&stopped_item.release)),
            &stopped_item,
        );
        let routed = provider.request(sign.clone());
        assert_eq!(routed["code"], "unknown_envelope", "{routed}");

        // Stop serving: the root is set aside and the provider re-inited
        // with the roots left.
        fs::rename(
            base.join(&stopped_path),
            base.join(format!("{stopped_path}.stopped-1")),
        )
        .unwrap();
        assert_eq!(
            provider.request(roots_init(&base, &["inactive"]))["status"],
            "ok"
        );
        for request in [
            request_value(&stopped_item.provision),
            request_value(&stopped_item.release),
            sign,
        ] {
            let response = provider.request(request);
            assert_eq!(response["status"], "error", "{response}");
            assert_eq!(response["code"], "invalid_request", "{response}");
        }
        // The root left still serves.
        assert_eq!(
            provider.request(request_value(&kept_item.provision))["status"],
            "ok"
        );
        assert_contribution_from(
            &provider.request(request_value(&kept_item.release)),
            &kept_item,
        );
        provider.stop();
    }

    #[test]
    fn request_for_unknown_node_key_is_refused_before_any_store() {
        let temp = tempfile::tempdir().unwrap();
        let base = custody_base(temp.path());
        provision_root(&base, "inactive");
        let other_path = pool_path('c');
        let other = provision_root(&base, &other_path);
        let other_item = held_item(&other);

        let mut provider = ProviderProcess::start();
        // The set holds only `inactive`; the request names the other node.
        assert_eq!(
            provider.request(roots_init(&base, &["inactive"]))["status"],
            "ok"
        );
        for request in [&other_item.provision, &other_item.release] {
            let response = provider.request(request_value(request));
            assert_eq!(response["status"], "error", "{response}");
            assert_eq!(response["code"], "invalid_request", "{response}");
        }
        // No store was created in either root.
        for root in ["inactive", other_path.as_str()] {
            let data = base.join(root).join("data");
            assert!(!data.join("node-shares").exists(), "{root}");
            assert!(!data.join("replay").exists(), "{root}");
        }
        assert_eq!(root_status(&mut provider, "inactive")["shares_held"], 0);
        provider.stop();
    }

    /// A root whose node key reads but whose state does not load (here its
    /// trusted issuer file is broken) is listed unconfigured with its key,
    /// and a frame for it answers the unconfigured error before any store.
    #[test]
    fn request_for_an_unconfigured_root_is_refused_before_any_store() {
        let temp = tempfile::tempdir().unwrap();
        let base = custody_base(temp.path());
        provision_root(&base, "inactive");
        let broken_path = pool_path('b');
        let broken = provision_root(&base, &broken_path);
        let broken_item = held_item(&broken);
        let issuer_file = base.join(&broken_path).join("trusted-runtime-issuer");
        std::fs::write(&issuer_file, "not hex").unwrap();
        std::fs::set_permissions(
            &issuer_file,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let mut provider = ProviderProcess::start();
        assert_eq!(
            provider.request(roots_init(&base, &["inactive", &broken_path]))["status"],
            "ok"
        );
        let listed = root_status(&mut provider, &broken_path);
        assert_eq!(listed["configured"], false, "{listed}");
        assert_eq!(
            listed["node_public_key"],
            format!("0x{}", hex_bytes(broken.node_public_key.as_bytes()))
        );
        assert!(listed["shares_held"].is_null());
        for request in [&broken_item.provision, &broken_item.release] {
            let response = provider.request(request_value(request));
            assert_eq!(response["status"], "error", "{response}");
            assert_eq!(response["code"], "backend_unavailable", "{response}");
        }
        let data = base.join(&broken_path).join("data");
        assert!(!data.join("node-shares").exists());
        assert!(!data.join("replay").exists());
        provider.stop();
    }

    #[test]
    fn status_lists_roots_with_their_share_counts() {
        let temp = tempfile::tempdir().unwrap();
        let base = custody_base(temp.path());
        let pool = pool_path('d');
        let first = provision_root(&base, "inactive");
        let second = provision_root(&base, &pool);
        let mut provider = ProviderProcess::start();
        assert_eq!(
            provider.request(roots_init(&base, &["inactive", &pool]))["status"],
            "ok"
        );
        let status = provider.request(serde_json::json!({"op": "status"}));
        assert_eq!(
            status["data"]["roots"],
            serde_json::json!([
                {
                    "path": "inactive",
                    "node_public_key": format!("0x{}", hex_bytes(first.node_public_key.as_bytes())),
                    "configured": true,
                    "shares_held": 0,
                },
                {
                    "path": pool,
                    "node_public_key": format!("0x{}", hex_bytes(second.node_public_key.as_bytes())),
                    "configured": true,
                    "shares_held": 0,
                },
            ])
        );
        assert!(!status.to_string().contains(base.to_str().unwrap()));
        assert_eq!(
            provider.request(request_value(&held_item(&first).provision))["status"],
            "ok"
        );
        assert_eq!(root_status(&mut provider, "inactive")["shares_held"], 1);
        assert_eq!(root_status(&mut provider, &pool)["shares_held"], 0);
        provider.stop();
    }
}

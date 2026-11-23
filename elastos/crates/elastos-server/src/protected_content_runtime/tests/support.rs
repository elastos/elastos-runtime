use super::*;

pub(super) const TEST_VIEWER_LAUNCH_ID: &str = "launch:11111111111111111111111111111111";

pub(super) const TEST_VIEWER_LAUNCH_ID_B: &str = "launch:22222222222222222222222222222222";

pub(super) struct RecordingProvider {
    pub(super) name: &'static str,
    pub(super) requests: Mutex<Vec<Value>>,
    pub(super) response: Value,
}

pub(super) struct SequencedProvider {
    pub(super) name: &'static str,
    pub(super) requests: Mutex<Vec<Value>>,
    pub(super) responses: Mutex<VecDeque<Result<Value, ProviderError>>>,
}

pub(super) struct PrepareOnlyCleanupDecryptProvider {
    pub(super) expected_issuer_seed: u8,
    pub(super) requests: Mutex<Vec<Value>>,
}

pub(super) struct ProcessChainEvidenceProvider {
    pub(super) expected_request: RightsProviderRequestV1,
    pub(super) requests: Mutex<Vec<Value>>,
    pub(super) has_access: bool,
}

#[cfg(unix)]
#[derive(Clone, Copy)]
pub(super) enum TestMediaPreparationResponse {
    Prepared,
    SettledFailure,
    UnknownSettlement,
}

#[cfg(unix)]
pub(super) struct TestMediaPreparationProvider {
    pub(super) staging_root: PathBuf,
    pub(super) requests: Mutex<Vec<String>>,
    pub(super) response: TestMediaPreparationResponse,
}

#[cfg(unix)]
pub(super) const TEST_CUSTODY_PROVIDER_BIN_ENV: &str = "ELASTOS_TEST_CUSTODY_PROVIDER_BIN";

#[cfg(unix)]
pub(super) const TEST_DECRYPT_PROVIDER_BIN_ENV: &str = "ELASTOS_TEST_DECRYPT_PROVIDER_BIN";

#[cfg(unix)]
pub(super) const TEST_PROTECT_PROVIDER_BIN_ENV: &str = "ELASTOS_TEST_PROTECT_PROVIDER_BIN";

#[derive(Clone)]
pub(super) struct ContentAvailabilityTestConfig {
    pub(super) policy: String,
    pub(super) status: String,
    pub(super) replicas: u32,
    pub(super) live_multi_peer_proof: Option<bool>,
    pub(super) checked_at: u64,
    pub(super) receipt_cid: Option<String>,
    pub(super) receipt_object_identity: Option<String>,
    pub(super) receipt_publisher_did: Option<String>,
    pub(super) malformed_receipt: bool,
    pub(super) mutate_fetch_path: Option<String>,
    pub(super) mutate_manifest_extra_file: bool,
}

impl ContentAvailabilityTestConfig {
    pub(super) fn accepted() -> Self {
        Self {
            policy: "protected-content-replication/v1".to_string(),
            status: "network_available".to_string(),
            replicas: 3,
            live_multi_peer_proof: Some(true),
            checked_at: NOW,
            receipt_cid: None,
            receipt_object_identity: None,
            receipt_publisher_did: None,
            malformed_receipt: false,
            mutate_fetch_path: None,
            mutate_manifest_extra_file: false,
        }
    }

    pub(super) fn accepted_now() -> Self {
        Self::accepted_at(crate::auth::now_ts())
    }

    pub(super) fn accepted_at(checked_at: u64) -> Self {
        Self {
            checked_at,
            ..Self::accepted()
        }
    }
}

pub(super) struct ContentAvailabilityTestProvider {
    pub(super) signing_key: SigningKey,
    pub(super) config: ContentAvailabilityTestConfig,
    pub(super) files: Mutex<BTreeMap<String, Vec<u8>>>,
    pub(super) manifest: Mutex<Option<crate::content::ContentObjectManifest>>,
    pub(super) requests: Mutex<Vec<Value>>,
}

impl ContentAvailabilityTestProvider {
    pub(super) const CID: &'static str =
        "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

    pub(super) fn new(seed: u8, config: ContentAvailabilityTestConfig) -> Arc<Self> {
        Self::with_signing_key(elastos_identity::derive_did(&[seed; 32]).0, config)
    }

    pub(super) fn with_signing_key(
        signing_key: SigningKey,
        config: ContentAvailabilityTestConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            signing_key,
            config,
            files: Mutex::new(BTreeMap::new()),
            manifest: Mutex::new(None),
            requests: Mutex::new(Vec::new()),
        })
    }

    pub(super) fn signer_did(&self) -> String {
        crate::crypto::domain_separated_sign(
            &self.signing_key,
            "elastos.content.availability.receipt.v1",
            b"content-availability-test-provider",
        )
        .1
    }

    pub(super) async fn publish(&self, request: &Value) -> Result<Value, ProviderError> {
        let object_identity = request
            .get("object_did")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Provider("missing object identity".to_string()))?;
        let publisher_did = request
            .get("publisher_did")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Provider("missing publisher identity".to_string()))?;
        if request.get("object_kind").and_then(Value::as_str) != Some("protected-content") {
            return Err(ProviderError::Provider("wrong object kind".to_string()));
        }
        let entries = request
            .get("files")
            .and_then(Value::as_array)
            .ok_or_else(|| ProviderError::Provider("missing files".to_string()))?;
        let mut stored = BTreeMap::new();
        let mut manifest_files = Vec::with_capacity(entries.len());
        for entry in entries {
            let path = entry
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| ProviderError::Provider("bad file path".to_string()))?;
            let bytes = entry
                .get("data")
                .and_then(Value::as_str)
                .ok_or_else(|| ProviderError::Provider("missing file data".to_string()))
                .and_then(|encoded| {
                    base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .map_err(|_| ProviderError::Provider("bad file data".to_string()))
                })?;
            if stored.insert(path.to_string(), bytes.clone()).is_some() {
                return Err(ProviderError::Provider("duplicate file".to_string()));
            }
            manifest_files.push(crate::content::ContentObjectFile {
                path: path.to_string(),
                sha256: hex::encode(sha2::Sha256::digest(&bytes)),
                size: bytes.len() as u64,
            });
        }
        manifest_files.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest = crate::content::ContentObjectManifest {
            schema: "elastos.content.object.manifest/v1".to_string(),
            kind: "protected-content".to_string(),
            content_digest: super::super::content_object_digest(&manifest_files),
            files: manifest_files,
            links: Vec::new(),
            object_did: Some(object_identity.to_string()),
            publisher_did: Some(publisher_did.to_string()),
        };
        stored.insert(
            crate::content::CONTENT_OBJECT_MANIFEST_PATH.to_string(),
            serde_json::to_vec(&manifest)
                .map_err(|_| ProviderError::Provider("manifest encode failed".to_string()))?,
        );
        *self.files.lock().await = stored;
        *self.manifest.lock().await = Some(manifest);
        Ok(ok_provider_response(json!({ "cid": Self::CID })))
    }

    pub(super) async fn status(&self) -> Result<Value, ProviderError> {
        if self.config.malformed_receipt {
            return Ok(ok_provider_response(json!({
                "receipt": {
                    "payload": "malformed",
                },
            })));
        }
        let manifest = self
            .manifest
            .lock()
            .await
            .clone()
            .ok_or_else(|| ProviderError::Provider("missing published object".to_string()))?;
        let object_identity = self
            .config
            .receipt_object_identity
            .as_deref()
            .or(manifest.object_did.as_deref())
            .ok_or_else(|| ProviderError::Provider("missing object identity".to_string()))?;
        let publisher_did = self
            .config
            .receipt_publisher_did
            .as_deref()
            .or(manifest.publisher_did.as_deref())
            .ok_or_else(|| ProviderError::Provider("missing publisher identity".to_string()))?;
        let cid = self.config.receipt_cid.as_deref().unwrap_or(Self::CID);
        let payload = crate::content::AvailabilityReceipt {
            schema: "elastos.content.availability.receipt/v1".to_string(),
            cid: cid.to_string(),
            uri: format!("elastos://{cid}"),
            object_did: Some(object_identity.to_string()),
            publisher_did: publisher_did.to_string(),
            provider: "content".to_string(),
            policy: self.config.policy.clone(),
            status: self.config.status.clone(),
            replicas: self.config.replicas,
            peer_selection: self
                .config
                .live_multi_peer_proof
                .map(|live_multi_peer_proof| {
                    json!({
                        "live_multi_peer_proof": live_multi_peer_proof,
                    })
                })
                .unwrap_or_else(|| json!({})),
            quota: json!({}),
            repair_worker: json!({}),
            storage_market: json!({}),
            repair_graph: json!({}),
            abuse_controls: json!({}),
            accounting: json!({}),
            checked_at: self.config.checked_at,
        };
        let payload_bytes = serde_json::to_string(
            &serde_json::to_value(&payload)
                .map_err(|_| ProviderError::Provider("receipt encode failed".to_string()))?,
        )
        .map_err(|_| ProviderError::Provider("receipt encode failed".to_string()))?;
        let (signature, signer_did) = crate::crypto::domain_separated_sign(
            &self.signing_key,
            "elastos.content.availability.receipt.v1",
            payload_bytes.as_bytes(),
        );
        Ok(ok_provider_response(json!({
            "receipt": crate::content::SignedAvailabilityReceipt {
                payload,
                signature,
                signer_did,
            },
        })))
    }

    pub(super) async fn fetch(&self, request: &Value) -> Result<Value, ProviderError> {
        let path = request
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Provider("missing fetch path".to_string()))?;
        let mut bytes = if path == crate::content::CONTENT_OBJECT_MANIFEST_PATH
            && self.config.mutate_manifest_extra_file
        {
            let mut manifest = self
                .manifest
                .lock()
                .await
                .clone()
                .ok_or_else(|| ProviderError::Provider("missing manifest".to_string()))?;
            manifest.files.push(manifest.files[0].clone());
            serde_json::to_vec(&manifest)
                .map_err(|_| ProviderError::Provider("manifest encode failed".to_string()))?
        } else {
            self.files
                .lock()
                .await
                .get(path)
                .cloned()
                .ok_or_else(|| ProviderError::NotFound("content object file".to_string()))?
        };
        if self.config.mutate_fetch_path.as_deref() == Some(path) {
            let first = bytes
                .first_mut()
                .ok_or_else(|| ProviderError::Provider("empty fetch mutation".to_string()))?;
            *first ^= 0x01;
        }
        Ok(ok_provider_response(json!({
            "data": base64::engine::general_purpose::STANDARD.encode(bytes),
        })))
    }

    pub(super) async fn seed_published_protected_content(
        &self,
        directory: &Path,
        object_identity: &str,
        publisher_did: &str,
    ) -> Result<(), ProviderError> {
        let files = super::super::protected_content_directory_files(directory)
            .map_err(|error| ProviderError::Provider(error.to_string()))?
            .into_iter()
            .map(|path| {
                let bytes = fs::read(directory.join(&path))
                    .map_err(|error| ProviderError::Provider(error.to_string()))?;
                Ok(json!({
                    "path": path,
                    "data": base64::engine::general_purpose::STANDARD.encode(bytes),
                }))
            })
            .collect::<Result<Vec<_>, ProviderError>>()?;
        self.publish(&json!({
            "op": "publish",
            "object_kind": "protected-content",
            "object_did": object_identity,
            "publisher_did": publisher_did,
            "files": files,
        }))
        .await?;
        Ok(())
    }

    pub(super) async fn requests(&self) -> Vec<Value> {
        self.requests.lock().await.clone()
    }
}

#[async_trait::async_trait]
impl Provider for ContentAvailabilityTestProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "content availability test provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["content"]
    }

    fn name(&self) -> &'static str {
        "content-availability-test-provider"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.requests.lock().await.push(request.clone());
        match request.get("op").and_then(Value::as_str) {
            Some("publish") => self.publish(request).await,
            Some("ensure") => Ok(ok_provider_response(json!({
                "availability": { "status": self.config.status.clone() },
            }))),
            Some("status") => self.status().await,
            Some("fetch") => self.fetch(request).await,
            _ => Err(ProviderError::Provider(
                "unsupported content operation".to_string(),
            )),
        }
    }
}

pub(super) const NOW: u64 = 2_000_000_000;

pub(super) const MEDIA_MIME_TYPE_V1: &str = "video/mp4";

pub(super) const MEDIA_CODECS_V1: &str = "avc1.640028,mp4a.40.2";

pub(super) const PQ_HYBRID_AEAD_NONCE_BYTES: usize = 12;

pub(super) const PQ_HYBRID_WRAPPED_SHARE_BYTES: usize = 48;

impl RecordingProvider {
    pub(super) fn new(name: &'static str, response: Value) -> Arc<Self> {
        Arc::new(Self {
            name,
            requests: Mutex::new(Vec::new()),
            response,
        })
    }

    pub(super) async fn requests(&self) -> Vec<Value> {
        self.requests.lock().await.clone()
    }
}

impl SequencedProvider {
    pub(super) fn new(
        name: &'static str,
        responses: Vec<Result<Value, ProviderError>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            name,
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(VecDeque::from(responses)),
        })
    }

    pub(super) async fn requests(&self) -> Vec<Value> {
        self.requests.lock().await.clone()
    }
}

impl PrepareOnlyCleanupDecryptProvider {
    pub(super) fn new() -> Arc<Self> {
        Self::with_expected_issuer_seed(0x21)
    }

    pub(super) fn with_expected_issuer_seed(seed: u8) -> Arc<Self> {
        Arc::new(Self {
            expected_issuer_seed: seed,
            requests: Mutex::new(Vec::new()),
        })
    }

    pub(super) async fn requests(&self) -> Vec<Value> {
        self.requests.lock().await.clone()
    }
}

impl ProcessChainEvidenceProvider {
    pub(super) fn new(expected_request: RightsProviderRequestV1, has_access: bool) -> Arc<Self> {
        Arc::new(Self {
            expected_request,
            requests: Mutex::new(Vec::new()),
            has_access,
        })
    }

    pub(super) async fn requests(&self) -> Vec<Value> {
        self.requests.lock().await.clone()
    }
}

#[async_trait::async_trait]
impl Provider for PrepareOnlyCleanupDecryptProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "prepare-only cleanup decrypt provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["decrypt"]
    }

    fn name(&self) -> &'static str {
        "prepare-only-cleanup-decrypt-provider"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.requests.lock().await.push(request.clone());
        let mut inner_request = request.clone();
        inner_request
            .as_object_mut()
            .ok_or_else(|| ProviderError::Provider("invalid decrypt request".to_string()))?
            .remove("_runtime_invocation");
        let validated = ValidatedDecryptProviderRequestV1::decode_and_validate_at(
            &serde_json::to_vec(&inner_request)
                .map_err(|_| ProviderError::Provider("invalid decrypt request".to_string()))?,
            derived_device_runtime_issuer(self.expected_issuer_seed),
            crate::auth::now_ts(),
        )
        .map_err(|_| ProviderError::Provider("invalid decrypt request".to_string()))?;
        match request.get("op").and_then(Value::as_str) {
            Some("prepare_recipient") => Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_prepared_recipient(
                        validated.audit_request_id(),
                        opaque_handle(0x71),
                        recipient_public_key(0x30),
                        &recipient_identity(0x30),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
            Some("close_viewer_session") => Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_viewer_session_already_absent(
                        validated.audit_request_id(),
                        *validated.viewer_session_handle().map_err(|_| {
                            ProviderError::Provider("missing viewer handle".to_string())
                        })?,
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
            Some("cancel_prepared_recipient") => Ok(ok_provider_response(
                serde_json::to_value(
                    DecryptProviderResponseV1::new_cancelled_prepared_recipient(
                        validated.audit_request_id(),
                        *validated.prepared_recipient_handle().map_err(|_| {
                            ProviderError::Provider("missing prepared handle".to_string())
                        })?,
                    )
                    .unwrap(),
                )
                .unwrap(),
            )),
            _ => Err(ProviderError::Provider(
                "unsupported decrypt operation".to_string(),
            )),
        }
    }
}

pub(super) fn digest(byte: u8) -> Digest32 {
    Digest32::new([byte; 32])
}

pub(super) fn encrypted_content(seed: u8) -> EncryptedContentIdentityV1 {
    EncryptedContentIdentityV1::new(digest(seed), 4096).unwrap()
}

pub(super) fn content_access_id(seed: u8) -> ContentAccessIdV1 {
    ContentAccessIdV1::new([seed; 16]).unwrap()
}

pub(super) fn wallet(seed: u8) -> WalletAddress {
    let key = WalletSigningKey::from_slice(&[seed; 32]).unwrap();
    let encoded = key.verifying_key().to_encoded_point(false);
    let digest = Keccak256::digest(&encoded.as_bytes()[1..]);
    WalletAddress::new(digest[12..].try_into().unwrap())
}

pub(super) fn runtime_operation_issuer_for_seed(seed: u8) -> RuntimeOperationIssuerKeyV1 {
    RuntimeOperationIssuerKeyV1::new(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap()
}

pub(super) fn sign_runtime_statement_for_seed_0x21(message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(&[0x21; 32]).sign(message).to_bytes()
}

#[cfg(unix)]
pub(super) fn required_test_binary_path(env_name: &str) -> PathBuf {
    let path = PathBuf::from(
        env::var_os(env_name).unwrap_or_else(|| panic!("missing test binary env: {env_name}")),
    );
    let metadata = fs::metadata(&path)
        .unwrap_or_else(|error| panic!("invalid test binary path {}: {error}", path.display()));
    assert!(
        metadata.is_file(),
        "test binary is not a file: {}",
        path.display()
    );
    assert!(
        metadata.permissions().mode() & 0o111 != 0,
        "test binary is not executable: {}",
        path.display()
    );
    path
}

#[cfg(unix)]
pub(super) fn runtime_issuer_hex(seed: u8) -> String {
    format!(
        "0x{}",
        hex::encode(runtime_operation_issuer_for_seed(seed).as_bytes())
    )
}

pub(super) fn wallet_address_hex(wallet: WalletAddress) -> String {
    format!("0x{}", hex::encode(wallet.as_bytes()))
}

#[cfg(unix)]
pub(super) fn collect_file_bytes(root: &Path, out: &mut Vec<Vec<u8>>) {
    let mut entries = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_file_bytes(&path, out);
        } else if path.is_file() {
            out.push(fs::read(path).unwrap());
        }
    }
}

#[cfg(unix)]
pub(super) fn any_file_contains(root: &Path, needle: &[u8]) -> bool {
    if !root.exists() {
        return false;
    }
    let mut files = Vec::new();
    collect_file_bytes(root, &mut files);
    files.into_iter().any(|bytes| {
        !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle)
    })
}

#[cfg(unix)]
pub(super) async fn invoke_typed_protect_provider(
    registry: &ProviderRegistry,
    op: &str,
    request: &ProtectProviderRequestV1,
) -> ProtectProviderResponseV1 {
    let data = invoke_json_provider(
        registry,
        "protect",
        op,
        serde_json::to_value(request).unwrap(),
    )
    .await
    .unwrap();
    ProtectProviderResponseV1::from_json_slice(&serde_json::to_vec(&data).unwrap()).unwrap()
}

#[cfg(unix)]
pub(super) fn provision_custody_node_public_receipt(
    binary: &Path,
    state_root: &Path,
    runtime_issuer_seed: u8,
) -> ProvisionedCustodyProviderPublicKeys {
    let output = Command::new(binary)
        .args([
            "provision",
            "--base-path",
            state_root.to_str().unwrap(),
            "--trusted-runtime-issuer",
            &runtime_issuer_hex(runtime_issuer_seed),
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
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    parse_and_verify_provisioning_output(
        &response,
        runtime_operation_issuer_for_seed(runtime_issuer_seed),
    )
    .unwrap()
}

pub(super) fn node_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub(super) fn node_public_key(seed: u8) -> NodePublicKey {
    NodePublicKey::new(node_signing_key(seed).verifying_key().to_bytes()).unwrap()
}

pub(super) fn xwing_public_key_bytes(
    seed: u8,
) -> [u8; elastos_protected_content_contracts::PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
    let secret = x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE]);
    secret.encapsulation_key().to_bytes().into()
}

pub(super) fn recipient_public_key(seed: u8) -> RecipientPublicKeyBytesV1 {
    RecipientPublicKeyBytesV1::new(xwing_public_key_bytes(seed.max(9))).unwrap()
}

pub(super) fn recipient_identity(seed: u8) -> RecipientKeyIdentityV1 {
    recipient_public_key(seed)
        .key_identity(CUSTODY_X_WING_AES256GCM_SUITE_ID_V1)
        .unwrap()
}

pub(super) fn node_custody_public_key(seed: u8) -> NodeCustodyPublicKeyV1 {
    NodeCustodyPublicKeyV1::new(xwing_public_key_bytes(seed)).unwrap()
}

pub(super) fn make_box(box_type: &[u8; 4], content: &[u8]) -> Vec<u8> {
    let size = (8 + content.len()) as u32;
    let mut out = Vec::with_capacity(size as usize);
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(box_type);
    out.extend_from_slice(content);
    out
}

pub(super) fn make_fullbox(box_type: &[u8; 4], flags: u32, payload: &[u8]) -> Vec<u8> {
    let mut content = vec![0u8];
    content.extend_from_slice(&flags.to_be_bytes()[1..]);
    content.extend_from_slice(payload);
    make_box(box_type, &content)
}

pub(super) fn make_sinf(original_fourcc: &[u8; 4]) -> Vec<u8> {
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

pub(super) fn make_track(track_id: u32, handler_type: &[u8; 4]) -> Vec<u8> {
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

pub(super) fn make_clear_track(track_id: u32, handler_type: &[u8; 4]) -> Vec<u8> {
    let mut tkhd_payload = vec![0u8; 12];
    tkhd_payload[8..12].copy_from_slice(&track_id.to_be_bytes());
    let tkhd = make_fullbox(b"tkhd", 0, &tkhd_payload);
    let mut hdlr_payload = vec![0u8; 4];
    hdlr_payload.extend_from_slice(handler_type);
    let hdlr = make_fullbox(b"hdlr", 0, &hdlr_payload);
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

pub(super) fn make_segment(track_id: u32, payload: &[u8]) -> Vec<u8> {
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
        .expect("trun box present")
        - 4;
    let trun_data_offset_at = trun_offset + 16;
    moof[trun_data_offset_at..trun_data_offset_at + 4].copy_from_slice(&data_offset.to_be_bytes());
    let mdat = make_box(b"mdat", payload);
    let mut out = moof;
    out.extend_from_slice(&mdat);
    out
}

pub(super) fn make_clear_segment(track_id: u32, payload: &[u8]) -> Vec<u8> {
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
    let mut traf_content = Vec::new();
    traf_content.extend_from_slice(&tfhd);
    traf_content.extend_from_slice(&tfdt);
    traf_content.extend_from_slice(&trun);
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
        .expect("trun box present")
        - 4;
    let trun_data_offset_at = trun_offset + 16;
    moof[trun_data_offset_at..trun_data_offset_at + 4].copy_from_slice(&data_offset.to_be_bytes());
    let mdat = make_box(b"mdat", payload);
    let mut out = moof;
    out.extend_from_slice(&mdat);
    out
}

pub(crate) fn media_components(seed: u8) -> (Vec<u8>, Vec<Vec<u8>>) {
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
    ([ftyp, moov].concat(), encrypted_segments)
}

pub(super) fn clear_media_components(seed: u8) -> (Vec<u8>, Vec<Vec<u8>>) {
    let ftyp = make_box(b"ftyp", b"isom\0\0\0\0isomiso6");
    let trak_video = make_clear_track(1, b"vide");
    let trak_audio = make_clear_track(2, b"soun");
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
    let moov = make_box(b"moov", &moov_content);
    let clear_segments = [0usize, 1]
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
            make_clear_segment(track_id, &payload)
        })
        .collect();
    ([ftyp, moov].concat(), clear_segments)
}

pub(super) fn media_identity(seed: u8) -> CencFmp4MediaIdentityV1 {
    let (init_segment, encrypted_segments) = media_components(seed);
    CencFmp4MediaIdentityV1::new_from_bytes(
        &init_segment,
        &encrypted_segments,
        MEDIA_MIME_TYPE_V1,
        MEDIA_CODECS_V1,
    )
    .unwrap()
}

pub(super) fn protected_content_directory_from_parts(
    init: &[u8],
    segments: &[Vec<u8>],
    media: &CencFmp4MediaIdentityV1,
) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let protected_root = directory.path().join("protected-content/v1/segments");
    fs::create_dir_all(&protected_root).unwrap();
    fs::write(
        directory.path().join("protected-content/v1/identity.bin"),
        media.canonical_bytes().unwrap(),
    )
    .unwrap();
    fs::write(directory.path().join("protected-content/v1/init.mp4"), init).unwrap();
    for (index, segment) in segments.iter().enumerate() {
        fs::write(protected_root.join(format!("{index:08}.m4s")), segment).unwrap();
    }
    directory
}

pub(super) fn availability_requirement(
    expected_provider_did: impl Into<String>,
) -> RuntimeContentAvailabilityRequirement {
    RuntimeContentAvailabilityRequirement::new(
        expected_provider_did,
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#content",
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#publisher",
        "protected-content-replication/v1",
        3,
        60,
        5,
    )
    .unwrap()
}

pub(super) fn protected_content_directory(
    seed: u8,
) -> (tempfile::TempDir, CencFmp4MediaIdentityV1) {
    let (init, segments) = media_components(seed);
    let media = CencFmp4MediaIdentityV1::new_from_bytes(
        &init,
        &segments,
        MEDIA_MIME_TYPE_V1,
        MEDIA_CODECS_V1,
    )
    .unwrap();
    (
        protected_content_directory_from_parts(&init, &segments, &media),
        media,
    )
}

pub(super) async fn publish_protected_content_for_test(
    config: ContentAvailabilityTestConfig,
    expected_provider_did: Option<String>,
    mutate_directory: Option<fn(&Path)>,
) -> anyhow::Result<elastos_protected_content_runtime::RuntimeVerifiedContentAvailability> {
    let (directory, media) = protected_content_directory(0x41);
    if let Some(mutate_directory) = mutate_directory {
        mutate_directory(directory.path());
    }
    let provider = ContentAvailabilityTestProvider::new(0x61, config);
    let expected_provider_did = expected_provider_did.unwrap_or_else(|| provider.signer_did());
    let requirement = availability_requirement(expected_provider_did);
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_sub_provider("content", provider)
        .await
        .unwrap();
    super::super::publish_and_verify_protected_content_availability(
        registry.as_ref(),
        directory.path(),
        &media,
        &requirement,
        || NOW,
    )
    .await
}

pub(super) struct RuntimeCustodyPrebuyAvailabilityHarness {
    pub(super) _temp: tempfile::TempDir,
    pub(super) data_dir: PathBuf,
    pub(super) registry: Arc<ProviderRegistry>,
    pub(super) content_provider: Arc<ContentAvailabilityTestProvider>,
    pub(super) mint_id: Digest32,
}

pub(super) fn runtime_custody_listing_record_for_test(
    mint_id: Digest32,
    publisher_principal_id: &str,
    display_name: &str,
    published_at: u64,
) -> super::super::RuntimeCustodyListingRecord {
    let draft = mint_draft_for_composition_journal_test();
    let publisher_profile_did = derived_device_key_for_seed(0x66).1;
    let content_id = super::super::runtime_protected_content_id(draft.encrypted_content()).unwrap();
    let package = super::super::RuntimePortableListingPackage {
        schema: super::super::RUNTIME_PORTABLE_LISTING_SCHEMA_V1.to_string(),
        mint_id: hex::encode(mint_id.as_bytes()),
        content_id,
        content_access_id: format!("0x{}", hex::encode(draft.content_access_id().as_bytes())),
        content_cid: ContentAvailabilityTestProvider::CID.to_string(),
        metadata_cid: ContentAvailabilityTestProvider::CID.to_string(),
        token_uri: format!(
            "ipfs://{}/metadata.json",
            ContentAvailabilityTestProvider::CID
        ),
        publisher_profile_did,
        display_name: display_name.to_string(),
        media_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.media_identity().canonical_bytes().unwrap()),
        key_envelope_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.key_envelope().canonical_bytes().unwrap()),
        rights_policy_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.policy().canonical_bytes().unwrap()),
        content_key_commitment_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.content_key_commitment().as_bytes()),
        quantity: "0x2".to_string(),
        seller_address: "0x0000000000000000000000000000000000000011".to_string(),
        chain_namespace: "eip155:8453".to_string(),
        network: "base-mainnet".to_string(),
        ledger: "0x0000000000000000000000000000000000000022".to_string(),
        token_id: "0x1".to_string(),
        operative: "0x0000000000000000000000000000000000000033".to_string(),
        price: "0x5".to_string(),
        pay_token: "0x0000000000000000000000000000000000000044".to_string(),
        payment_processor: Some("0x0000000000000000000000000000000000000055".to_string()),
        mint_transaction_hash: format!("0x{}", hex::encode([0x68; 32])),
        published_at,
    };
    super::super::RuntimeCustodyListingRecord {
        schema: super::super::RUNTIME_LISTING_SCHEMA_V1.to_string(),
        origin: super::super::RuntimeCustodyListingOrigin::LocalCreator {
            principal_id: publisher_principal_id.to_string(),
            listing_uri: format!("elastos://{}", ContentAvailabilityTestProvider::CID),
            package_sha256: hex::encode(sha2::Sha256::digest(
                serde_json::to_vec(&package).unwrap(),
            )),
        },
        package,
        availability: super::super::RuntimeCustodyListingAvailabilitySummary {
            checked_at: NOW,
            observed_replicas: 3,
            receipt_digest: hex::encode([0x67; 32]),
        },
    }
}

#[cfg(unix)]
pub(crate) fn make_runtime_custody_listing_imported_without_creator_mint(
    data_dir: &Path,
    mint_id: Digest32,
) {
    let mut listing = super::super::load_runtime_custody_listing(data_dir, mint_id)
        .unwrap()
        .unwrap();
    let (listing_uri, package_sha256) = match &listing.origin {
        super::super::RuntimeCustodyListingOrigin::LocalCreator {
            listing_uri,
            package_sha256,
            ..
        }
        | super::super::RuntimeCustodyListingOrigin::Imported {
            listing_uri,
            package_sha256,
        } => (listing_uri.clone(), package_sha256.clone()),
    };
    listing.origin = super::super::RuntimeCustodyListingOrigin::Imported {
        listing_uri,
        package_sha256,
    };
    super::super::persist_runtime_custody_listing(data_dir, &listing).unwrap();
    fs::remove_dir_all(data_dir.join(super::super::RUNTIME_MINT_JOURNAL_ROOT)).unwrap();
    assert!(!data_dir
        .join(super::super::RUNTIME_MINT_JOURNAL_ROOT)
        .exists());
}

pub(super) async fn runtime_custody_prebuy_availability_harness(
    provider_seed: u8,
    provider_config: ContentAvailabilityTestConfig,
) -> RuntimeCustodyPrebuyAvailabilityHarness {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&data_dir.join("protected-content"));
    write_device_key(&data_dir, 0x61);
    write_library_publish_test_composition(&data_dir);

    let mint_draft = mint_draft_for_composition_journal_test();
    let fixture_now = crate::auth::now_ts();
    let mint_journal = runtime_mint_journal(&data_dir);
    mint_journal.persist_bound(&mint_draft).unwrap();
    for (index, node) in mint_draft.nodes().iter().enumerate() {
        let seed = u8::try_from(index + 1).unwrap();
        mint_journal
            .mark_node_effect_started(mint_draft.mint_id(), node.node_public_key())
            .unwrap();
        mint_journal
            .mark_node_receipt(
                mint_draft.mint_id(),
                RuntimeMintNodeReceipt::new(
                    node.node_public_key(),
                    RuntimeCustodyProvisioningIdV1::new(digest(0x80 + seed)).unwrap(),
                    CustodyNodeProvisioningRecordIdentityV1::new(digest(0xa0 + seed), 128).unwrap(),
                    node.owner_state_root(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let custody_provisioned = mint_journal
        .mark_custody_provisioned(mint_draft.mint_id())
        .unwrap();
    assert_eq!(
        custody_provisioned.custody_terminal(),
        Some(elastos_protected_content_runtime::RuntimeCustodyTerminalKind::CustodyProvisioned)
    );

    let expected_provider_did =
        ContentAvailabilityTestProvider::new(0x61, ContentAvailabilityTestConfig::accepted())
            .signer_did();
    let requirement = RuntimeContentAvailabilityRequirement::new(
        expected_provider_did,
        super::super::runtime_protected_content_id(mint_draft.encrypted_content()).unwrap(),
        derived_device_key_for_seed(0x66).1,
        super::super::PROTECTED_CONTENT_REPLICATION_POLICY,
        super::super::PROTECTED_CONTENT_MIN_REPLICAS,
        super::super::PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
        super::super::PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
    )
    .unwrap();
    let evidence = elastos_protected_content_runtime::RuntimeVerifiedContentAvailability::new(
        ContentAvailabilityTestProvider::CID,
        requirement.expected_object_identity(),
        requirement.expected_publisher_did(),
        &requirement,
        3,
        fixture_now.saturating_sub(1),
        digest(0x71),
        mint_draft.encrypted_content().clone(),
        mint_draft.media_identity().media_manifest_root(),
    )
    .unwrap();
    let available = mint_journal
        .mark_content_available(mint_draft.mint_id(), &requirement, evidence)
        .unwrap();
    assert_eq!(available.draft().mint_id(), mint_draft.mint_id());
    assert!(available.content_availability().is_some());

    let listing = runtime_custody_listing_record_for_test(
        mint_draft.mint_id(),
        "person:local:creator",
        "protected-video.mp4",
        fixture_now.saturating_sub(2),
    );
    super::super::persist_runtime_custody_listing(&data_dir, &listing).unwrap();

    let (init_segment, encrypted_segments) = media_components(0x41);
    let media_identity = CencFmp4MediaIdentityV1::new_from_bytes(
        &init_segment,
        &encrypted_segments,
        MEDIA_MIME_TYPE_V1,
        MEDIA_CODECS_V1,
    )
    .unwrap();
    let protected_directory =
        protected_content_directory_from_parts(&init_segment, &encrypted_segments, &media_identity);
    let content_provider = ContentAvailabilityTestProvider::new(provider_seed, provider_config);
    content_provider
        .seed_published_protected_content(
            protected_directory.path(),
            requirement.expected_object_identity(),
            requirement.expected_publisher_did(),
        )
        .await
        .unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_sub_provider("content", content_provider.clone())
        .await
        .unwrap();

    RuntimeCustodyPrebuyAvailabilityHarness {
        _temp: temp,
        data_dir,
        registry,
        content_provider,
        mint_id: mint_draft.mint_id(),
    }
}

pub(super) fn mutate_protected_content_descriptor(directory: &Path) {
    fs::write(
        directory.join("protected-content/v1/identity.bin"),
        b"not-a-canonical-media-identity",
    )
    .unwrap();
}

pub(super) fn mutate_protected_content_segment(directory: &Path) {
    let path = directory.join("protected-content/v1/segments/00000000.m4s");
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 0x01;
    fs::write(path, bytes).unwrap();
}

pub(super) fn remove_protected_content_descriptor(directory: &Path) {
    fs::remove_file(directory.join("protected-content/v1/identity.bin")).unwrap();
}

pub(super) fn rename_protected_content_descriptor(directory: &Path) {
    fs::rename(
        directory.join("protected-content/v1/identity.bin"),
        directory.join("protected-content/v1/identity-renamed.bin"),
    )
    .unwrap();
}

pub(super) fn remove_protected_content_init(directory: &Path) {
    fs::remove_file(directory.join("protected-content/v1/init.mp4")).unwrap();
}

pub(super) fn rename_protected_content_init(directory: &Path) {
    fs::rename(
        directory.join("protected-content/v1/init.mp4"),
        directory.join("protected-content/v1/init-renamed.mp4"),
    )
    .unwrap();
}

pub(super) fn remove_protected_content_segment(directory: &Path) {
    fs::remove_file(directory.join("protected-content/v1/segments/00000000.m4s")).unwrap();
}

pub(super) fn rename_protected_content_segment(directory: &Path) {
    fs::rename(
        directory.join("protected-content/v1/segments/00000000.m4s"),
        directory.join("protected-content/v1/segments/00000000-renamed.m4s"),
    )
    .unwrap();
}

pub(super) fn reorder_protected_content_segments(directory: &Path) {
    let first = directory.join("protected-content/v1/segments/00000000.m4s");
    let second = directory.join("protected-content/v1/segments/00000001.m4s");
    let first_bytes = fs::read(&first).unwrap();
    let second_bytes = fs::read(&second).unwrap();
    fs::write(first, second_bytes).unwrap();
    fs::write(second, first_bytes).unwrap();
}

pub(super) fn add_protected_content_segment_index_alias(directory: &Path) {
    fs::copy(
        directory.join("protected-content/v1/segments/00000000.m4s"),
        directory.join("protected-content/v1/segments/00000000-copy.m4s"),
    )
    .unwrap();
}

pub(super) fn truncate_protected_content_descriptor(directory: &Path) {
    let path = directory.join("protected-content/v1/identity.bin");
    let mut bytes = fs::read(&path).unwrap();
    bytes.pop().unwrap();
    fs::write(path, bytes).unwrap();
}

pub(super) fn mutate_protected_content_init(directory: &Path) {
    let path = directory.join("protected-content/v1/init.mp4");
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 0x01;
    fs::write(path, bytes).unwrap();
}

pub(super) fn truncate_protected_content_init(directory: &Path) {
    let path = directory.join("protected-content/v1/init.mp4");
    let mut bytes = fs::read(&path).unwrap();
    bytes.pop().unwrap();
    fs::write(path, bytes).unwrap();
}

pub(super) fn truncate_protected_content_segment(directory: &Path) {
    let path = directory.join("protected-content/v1/segments/00000000.m4s");
    let mut bytes = fs::read(&path).unwrap();
    bytes.pop().unwrap();
    fs::write(path, bytes).unwrap();
}

pub(super) fn add_extra_protected_content_file(directory: &Path) {
    fs::write(directory.join("protected-content/v1/extra.bin"), b"extra").unwrap();
}

pub(super) fn sealed_share(seed: u8) -> PqHybridSealedShareV1 {
    let public = x_wing::EncapsulationKey::new_from_slice(&xwing_public_key_bytes(seed)).unwrap();
    let (ciphertext, _) =
        public.encapsulate_deterministic(&[seed; x_wing::ENCAPSULATION_RANDOMNESS_SIZE].into());
    let ciphertext: [u8; X_WING_DRAFT06_CIPHERTEXT_BYTES] = ciphertext.into();
    let mut envelope = Vec::with_capacity(PQ_HYBRID_SEALED_SHARE_ENVELOPE_BYTES);
    envelope.extend_from_slice(&ciphertext);
    envelope.extend_from_slice(&[seed; PQ_HYBRID_AEAD_NONCE_BYTES]);
    envelope.extend_from_slice(&[seed ^ 0x5a; PQ_HYBRID_WRAPPED_SHARE_BYTES]);
    PqHybridSealedShareV1::new(envelope).unwrap()
}

pub(super) fn policy_body_for(
    encrypted_content: EncryptedContentIdentityV1,
    content_access_id: ContentAccessIdV1,
    action: RightsActionV1,
) -> RightsPolicyBodyV1 {
    RightsPolicyBodyV1::new(
        encrypted_content,
        content_access_id,
        action,
        elastos_protected_content_contracts::RightsSubjectSourceV1::WalletAddress,
        11155111,
        EvmContractAddressV1::new([0x11; 20]).unwrap(),
        EvmFunctionSelectorV1::new([0x12, 0x34, 0x56, 0x78]).unwrap(),
        EvmRightsMethodAbiV1::HasAccessByContentIdAddressBytes16,
        RightsObservationFinalityV1::finalized(),
    )
    .unwrap()
}

pub(super) fn policy_body() -> RightsPolicyBodyV1 {
    policy_body_for(
        encrypted_content(0x11),
        content_access_id(0x41),
        RightsActionV1::View,
    )
}

pub(super) fn signed_custody_epoch() -> SignedCustodyEpochV1 {
    signed_custody_epoch_with_first_node(node_public_key(1), node_custody_public_key(1))
}

pub(super) fn signed_custody_epoch_with_first_node(
    first_node_public_key: NodePublicKey,
    first_node_custody_public_key: NodeCustodyPublicKeyV1,
) -> SignedCustodyEpochV1 {
    signed_custody_epoch_for_node_keys([
        (first_node_public_key, first_node_custody_public_key),
        (node_public_key(2), node_custody_public_key(2)),
        (node_public_key(3), node_custody_public_key(3)),
    ])
}

pub(super) fn signed_custody_epoch_for_node_keys(
    nodes: [(NodePublicKey, NodeCustodyPublicKeyV1); 3],
) -> SignedCustodyEpochV1 {
    let issuer_key = SigningKey::from_bytes(&[0x71; 32]);
    let nodes = nodes
        .into_iter()
        .enumerate()
        .map(|(index, (node_public_key, custody_public_key))| {
            elastos_protected_content_contracts::CustodyNodeIdentityV1::new(
                node_public_key,
                custody_public_key,
                ShareCoordinateV1::new(u8::try_from(index + 1).unwrap()).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let statement = CustodyEpochStatementV1::new(
        CustodyEpochIssuerKeyV1::new(issuer_key.verifying_key().to_bytes()).unwrap(),
        CustodyApprovedSuitesV1::new(
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
            CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
        )
        .unwrap(),
        ThresholdV1::new(2, 3).unwrap(),
        nodes,
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

pub(super) fn signed_custody_pool_for_epoch(
    epoch: &SignedCustodyEpochV1,
    active_window: (u64, u64),
) -> SignedCustodyPoolV1 {
    let issuer_key = SigningKey::from_bytes(&[0x71; 32]);
    let members = epoch
        .statement()
        .nodes()
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let node_seed = u8::try_from(index + 1).unwrap();
            CustodyPoolMemberV1::new(
                node.node_public_key(),
                node.custody_public_key(),
                CustodyPoolOperatorIdV1::new([0x80 + node_seed; 32]),
                CustodyPoolFailureDomainIdV1::new([0x90 + node_seed; 32]),
                CustodyApprovedSuitesV1::new(
                    CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
                    CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
                    CUSTODY_X_WING_AES256GCM_SUITE_ID_V1,
                )
                .unwrap(),
                active_window,
                CustodyPoolMemberStateV1::Active,
            )
            .unwrap()
        })
        .collect();
    let statement = CustodyPoolStatementV1::new(
        CustodyEpochIssuerKeyV1::new(issuer_key.verifying_key().to_bytes()).unwrap(),
        members,
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

pub(super) fn signed_committee_authorization_for_epoch(
    pool_identity: CustodyPoolIdentityV1,
    epoch: &SignedCustodyEpochV1,
) -> SignedCustodyCommitteeAuthorizationV1 {
    let issuer_key = SigningKey::from_bytes(&[0x71; 32]);
    let statement = CustodyCommitteeAuthorizationStatementV1::new(
        CustodyEpochIssuerKeyV1::new(issuer_key.verifying_key().to_bytes()).unwrap(),
        pool_identity,
        epoch.epoch_identity().unwrap(),
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

pub(super) fn validated_custody_committee_for_epoch(
    epoch: &SignedCustodyEpochV1,
    now: u64,
) -> ValidatedCustodyCommitteeV1 {
    let pool = signed_custody_pool_for_epoch(epoch, (now.saturating_sub(60), now + 3600));
    let authorization =
        signed_committee_authorization_for_epoch(pool.pool_identity().unwrap(), epoch);
    elastos_protected_content_contracts::validate_custody_epoch_against_pool_at(
        CustodyEpochIssuerKeyV1::new(
            SigningKey::from_bytes(&[0x71; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
        authorization.authorization_identity().unwrap(),
        &pool,
        epoch,
        &authorization,
        now,
    )
    .unwrap()
}

pub(super) fn custody_envelope_for_media(seed: u8) -> CustodyEnvelopeV1 {
    custody_envelope_for_media_with_epoch(seed, &signed_custody_epoch())
}

pub(super) fn custody_envelope_for_media_with_epoch(
    seed: u8,
    epoch: &SignedCustodyEpochV1,
) -> CustodyEnvelopeV1 {
    let media = media_identity(seed);
    let manifest = CustodyEnvelopeManifestV1::new(
        media.encrypted_content().clone(),
        CustodyPoolIdentityV1::new(digest(seed ^ 0x34), 512).unwrap(),
        epoch.epoch_identity().unwrap(),
        CustodyCommitteeAuthorizationIdentityV1::new(digest(seed ^ 0x35), 512).unwrap(),
        ThresholdV1::new(2, 3).unwrap(),
        digest(seed ^ 0x33),
        epoch.statement().nodes().to_vec(),
    )
    .unwrap();
    let shares = [seed ^ 0x50, seed ^ 0x51, seed ^ 0x52]
        .into_iter()
        .map(sealed_share)
        .collect();
    CustodyEnvelopeV1::new(manifest, shares).unwrap()
}

pub(super) fn provisioned_custody_envelope_for_media_with_epoch(
    seed: u8,
    epoch: &SignedCustodyEpochV1,
    now: u64,
) -> CustodyEnvelopeV1 {
    let media = media_identity(seed);
    let content_key =
        elastos_protected_content_custody::ContentEncryptionKeyV1::generate().unwrap();
    let committee = validated_custody_committee_for_epoch(epoch, now);
    provision_custody_envelope(media.encrypted_content().clone(), &content_key, &committee).unwrap()
}

pub(super) fn binding_for_envelope(
    envelope: &CustodyEnvelopeV1,
) -> elastos_protected_content_contracts::ProtectedContentBindingV1 {
    let policy = policy_body();
    elastos_protected_content_contracts::ProtectedContentBindingV1::new(
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

#[cfg(unix)]
pub(super) fn store_profile_signing_passkey(
    data_dir: &Path,
    principal_id: &str,
    credential_id: &str,
) -> String {
    let now = crate::auth::now_ts();
    let binding = elastos_runtime::auth::ProofBinding::passkey_webauthn(
        elastos_runtime::auth::PasskeyWebAuthnBinding {
            credential_id: credential_id.to_string(),
            public_key: "protected-content-release-test-public-key".to_string(),
            sign_count: 1,
            user_verified: true,
            origin: "https://elastos.elacitylabs.com".to_string(),
            rp_id: "elastos.elacitylabs.com".to_string(),
            created_at: now,
            last_used_at: now,
            revoked_at: None,
        },
    );
    crate::auth::upsert_principal_for_binding_as_role_named(
        data_dir,
        binding,
        principal_id.to_string(),
        crate::auth::RuntimePrincipalRole::Admin,
        None,
        now,
    )
    .unwrap()
    .proof_binding_id
}

#[cfg(unix)]
pub(super) fn install_profile_authority_keeping_device_key(
    data_dir: &Path,
    principal_id: &str,
) -> (String, ProfileIdentityV1) {
    let proof_binding_id =
        store_profile_signing_passkey(data_dir, principal_id, "credential-protected-content");
    crate::auth::store_test_principal_root_protection(data_dir, principal_id);
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    let profile = crate::collaboration_profile_authority::update_profile_authority(
        data_dir,
        principal_id,
        &localhost_root,
        &proof_binding_id,
        "Protected Content Test",
        None,
        crate::auth::now_ts(),
    )
    .unwrap();
    let profile_key = crate::crypto::decode_did_key(&profile.document().profile_did).unwrap();
    let profile_identity =
        ProfileIdentityV1::from_public_key_bytes(profile_key.to_bytes()).unwrap();
    (proof_binding_id, profile_identity)
}

#[cfg(unix)]
pub(super) fn load_profile_did_for_test(data_dir: &Path, principal_id: &str) -> String {
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    crate::collaboration_profile_authority::load_profile_authority(
        data_dir,
        principal_id,
        &localhost_root,
    )
    .unwrap()
    .unwrap()
    .document()
    .profile_did
    .clone()
}

#[cfg(unix)]
pub(super) fn persist_runtime_custody_purchase_for_mint(
    data_dir: &Path,
    mint: &PersistedRuntimeMint,
    principal_id: &str,
    profile_did: &str,
    now: u64,
) -> RuntimeCustodyPurchaseRecord {
    let listing = super::super::load_runtime_custody_listing(data_dir, mint.draft().mint_id())
        .unwrap()
        .expect("runtime custody listing");
    let wallet_binding = ValidatedChainOutcomeBindingV1::ManagedSigned {
        signed_transaction_sha256: format!("sha256:{}", hex::encode([0xab; 32])),
    };
    let chain_transaction = format!("0x{}", hex::encode([0xaa; 32]));
    let chain_observation = json!({
        "schema": "elastos.chain.broadcast_receipt/v1",
        "network": "esc-mainnet",
    });
    let record = RuntimeCustodyPurchaseRecord {
        schema: RUNTIME_PURCHASE_SCHEMA_V1.to_string(),
        principal_id: principal_id.to_string(),
        profile_did: profile_did.to_string(),
        mint_id: hex::encode(mint.draft().mint_id().as_bytes()),
        content_id: runtime_protected_content_id(mint.draft().encrypted_content()).unwrap(),
        cid: mint
            .content_availability()
            .unwrap()
            .content_cid()
            .to_string(),
        listing_sha256: listing.portable_package_digest(),
        seller_address: listing.package.seller_address.clone(),
        chain_namespace: listing.package.chain_namespace.clone(),
        network: listing.package.network.clone(),
        ledger: listing.package.ledger.clone(),
        token_id: listing.package.token_id.clone(),
        operative: listing.package.operative.clone(),
        price: listing.package.price.clone(),
        pay_token: listing.package.pay_token.clone(),
        payment_processor: listing.package.payment_processor.clone(),
        availability_receipt_digest: format!(
            "sha256:{}",
            hex::encode(
                mint.content_availability()
                    .unwrap()
                    .receipt_digest()
                    .as_bytes()
            )
        ),
        account_id: "wallet-account-alpha".to_string(),
        address: wallet_address_hex(wallet(7)),
        approval_stage: None,
        buy_stage: RuntimeCustodyPurchaseStageRecord {
            stage: "buy".to_string(),
            effect_id: "runtime-effect:11111111111111111111111111111111".to_string(),
            approval_request_id: "wallet-request:11111111111111111111111111111111".to_string(),
            request_sha256: format!("sha256:{}", hex::encode([0xac; 32])),
            chain_namespace: listing.package.chain_namespace.clone(),
            network: listing.package.network.clone(),
            to: "0x2222222222222222222222222222222222222222".to_string(),
            value: "0x1".to_string(),
            data: "0x".to_string(),
        },
        progress: RuntimeCustodyPurchaseProgress::Complete {
            terminal: RuntimeCustodyTerminalPurchaseRecord {
                chain_transaction,
                wallet_binding,
                chain_observation,
                access_evidence: RuntimeCustodyPurchaseAccessEvidenceRecord {
                    schema: "elastos.chain.protected-content-purchase-access/v1".to_string(),
                    request_id: "purchase-access:test".to_string(),
                    network: listing.package.network.clone(),
                    chain_id: 8453,
                    wallet: wallet_address_hex(wallet(7)),
                    content_access_id: listing.package.content_access_id.clone(),
                    has_access: true,
                    finalized_block_number: 44,
                    finalized_block_hash: format!("0x{}", hex::encode([0xad; 32])),
                    finalized_block_timestamp: now,
                    observed_at: now,
                },
                confirmed_at: now,
                bought_at: now,
            },
        },
        created_at: now,
        updated_at: now,
    };
    write_owner_only_bytes(
        &runtime_purchase_path(data_dir, principal_id, mint.draft().mint_id()),
        &serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    record
}

#[cfg(unix)]
#[allow(
    clippy::too_many_arguments,
    reason = "test helper binds every fixture fact explicitly"
)]
pub(super) fn persist_runtime_custody_active_viewer_for_purchase(
    data_dir: &Path,
    mint: &PersistedRuntimeMint,
    purchase: &RuntimeCustodyPurchaseRecord,
    proof_binding_id: &str,
    session_id: &str,
    grant_id: &str,
    handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    expires_at: u64,
) -> RuntimeViewerSession {
    let binding = super::super::derive_runtime_custody_session_binding(
        &purchase.principal_id,
        &purchase.profile_did,
        TEST_VIEWER_LAUNCH_ID,
        proof_binding_id,
        session_id,
        grant_id,
        mint.draft().mint_id(),
    )
    .unwrap();
    let session = RuntimeViewerSession::from_persisted_parts(
        digest(0x91),
        handle,
        mint.draft().encrypted_content().clone(),
        RightsActionV1::View,
        expires_at,
    )
    .unwrap();
    let record = super::super::RuntimeCustodyViewerRecord::from_active_session(
        &purchase.principal_id,
        &purchase.profile_did,
        mint.draft().mint_id(),
        &purchase.content_id,
        binding,
        &session,
        crate::auth::now_ts(),
    )
    .unwrap();
    super::super::persist_runtime_custody_viewer_record(
        data_dir,
        &purchase.principal_id,
        mint.draft().mint_id(),
        &record,
    )
    .unwrap();
    session
}

#[cfg(unix)]
#[allow(
    clippy::too_many_arguments,
    reason = "test helper binds every fixture fact explicitly"
)]
pub(super) fn persist_runtime_custody_open_pending_viewer_for_purchase(
    data_dir: &Path,
    mint: &PersistedRuntimeMint,
    purchase: &RuntimeCustodyPurchaseRecord,
    proof_binding_id: &str,
    session_id: &str,
    grant_id: &str,
    handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    expires_at: u64,
) -> super::super::RuntimeCustodyViewerRecord {
    let binding = super::super::derive_runtime_custody_session_binding(
        &purchase.principal_id,
        &purchase.profile_did,
        TEST_VIEWER_LAUNCH_ID,
        proof_binding_id,
        session_id,
        grant_id,
        mint.draft().mint_id(),
    )
    .unwrap();
    let record = super::super::RuntimeCustodyViewerRecord::from_open_pending(
        super::super::RuntimeCustodyOpenPendingInput {
            principal_id: &purchase.principal_id,
            profile_did: &purchase.profile_did,
            mint_id: mint.draft().mint_id(),
            content_id: &purchase.content_id,
            runtime_session_binding: binding,
            audit_request_id: digest(0x91),
            viewer_session_handle: handle,
            expires_at,
            now: crate::auth::now_ts(),
        },
    )
    .unwrap();
    super::super::persist_runtime_custody_viewer_record(
        data_dir,
        &purchase.principal_id,
        mint.draft().mint_id(),
        &record,
    )
    .unwrap();
    record
}

#[cfg(unix)]
pub(super) fn install_profile_authority_for_release_test(
    data_dir: &Path,
    principal_id: &str,
) -> (String, String, ProfileIdentityV1) {
    owner_only_dir(data_dir);
    write_device_key(data_dir, 0x42);
    let proof_binding_id =
        store_profile_signing_passkey(data_dir, principal_id, "credential-protected-content");
    crate::auth::store_test_principal_root_protection(data_dir, principal_id);
    let localhost_root = crate::auth::principal_localhost_root(principal_id);
    let profile = crate::collaboration_profile_authority::update_profile_authority(
        data_dir,
        principal_id,
        &localhost_root,
        &proof_binding_id,
        "Protected Content Test",
        None,
        NOW,
    )
    .unwrap();
    let profile_key = crate::crypto::decode_did_key(&profile.document().profile_did).unwrap();
    let profile_identity =
        ProfileIdentityV1::from_public_key_bytes(profile_key.to_bytes()).unwrap();
    (proof_binding_id, localhost_root, profile_identity)
}

pub(super) fn release_operation_assembly_input(
    profile: ProfileIdentityV1,
) -> super::super::RuntimeReleaseOperationAssemblyInput {
    let envelope = custody_envelope_for_media(0x11);
    let policy = policy_body();
    let binding = ProtectedContentBindingV1::new(
        envelope.manifest().encrypted_content().clone(),
        envelope.key_envelope_identity().unwrap(),
        policy.policy_identity().unwrap(),
        profile,
        wallet(7),
        RuntimeSessionBindingV1::new(digest(0x66)).unwrap(),
    )
    .unwrap();
    let recipient_public_key = recipient_public_key(0x30);
    let recipient_identity = recipient_identity(0x30);
    let rights_request = {
        let request = elastos_protected_content_contracts::RightsRequestV1::new(
            binding.clone(),
            RightsActionV1::View,
            recipient_identity.clone(),
            NOW,
            NOW + 180,
            ReplayNonce16::new([0x55; 16]),
        )
        .unwrap();
        let key = WalletSigningKey::from_slice(&[7; 32]).unwrap();
        let (signature, recovery_id) = key
            .sign_prehash_recoverable(&elastos_auth::ethereum_signed_message_hash(
                &request.canonical_bytes().unwrap(),
            ))
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
        NOW + 1,
        NOW + 50,
        ReplayNonce16::new([0x66; 16]),
    )
    .unwrap();
    super::super::RuntimeReleaseOperationAssemblyInput {
        rights_request,
        release_request,
        recipient_public_key,
        recipient_identity,
        policy_body: policy.clone(),
        evidence_request: RightsEvaluationEvidenceRequestV1::new(
            binding,
            policy.policy_identity().unwrap(),
        )
        .unwrap(),
        custody_epoch: signed_custody_epoch(),
        audit_request_id: RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap(),
        issued_at: NOW + 2,
        expires_at: NOW + 40,
    }
}

pub(super) fn make_signed_runtime_release_operation_for_envelope_and_seed(
    seed: u8,
    envelope: &CustodyEnvelopeV1,
) -> SignedRuntimeReleaseOperationV1 {
    make_signed_runtime_release_operation_for_envelope_and_epoch_at(
        seed,
        envelope,
        signed_custody_epoch(),
        NOW,
    )
}

pub(super) fn make_signed_runtime_release_operation_for_envelope_and_epoch_at(
    seed: u8,
    envelope: &CustodyEnvelopeV1,
    custody_epoch: SignedCustodyEpochV1,
    now: u64,
) -> SignedRuntimeReleaseOperationV1 {
    make_signed_runtime_release_operation_for_envelope_and_epoch_and_recipient_at(
        seed,
        envelope,
        custody_epoch,
        recipient_public_key(0x30),
        recipient_identity(0x30),
        RuntimeReleaseAuditIdV1::new(digest(0x91 ^ seed)).unwrap(),
        now,
    )
}

pub(super) fn make_signed_runtime_release_operation_for_envelope_and_epoch_and_recipient_at(
    seed: u8,
    envelope: &CustodyEnvelopeV1,
    custody_epoch: SignedCustodyEpochV1,
    recipient_public: RecipientPublicKeyBytesV1,
    recipient_identity: RecipientKeyIdentityV1,
    audit_request_id: RuntimeReleaseAuditIdV1,
    now: u64,
) -> SignedRuntimeReleaseOperationV1 {
    let runtime_key = SigningKey::from_bytes(&[seed; 32]);
    let binding = binding_for_envelope(envelope);
    let rights_request = {
        let request = elastos_protected_content_contracts::RightsRequestV1::new(
            binding.clone(),
            RightsActionV1::View,
            recipient_identity.clone(),
            now.saturating_sub(5),
            now + 180,
            ReplayNonce16::new([0x55; 16]),
        )
        .unwrap();
        let key = WalletSigningKey::from_slice(&[7; 32]).unwrap();
        let (signature, recovery_id) = key
            .sign_prehash_recoverable(&elastos_auth::ethereum_signed_message_hash(
                &request.canonical_bytes().unwrap(),
            ))
            .unwrap();
        let mut signature_bytes = signature.to_bytes().to_vec();
        signature_bytes.push(recovery_id.to_byte());
        WalletSignedRightsRequestV1::new(request, signature_bytes).unwrap()
    };
    let release_request = KeyReleaseRequestV1::new(
        binding.clone(),
        rights_request.request().request_hash().unwrap(),
        RightsActionV1::View,
        rights_request.request().recipient().clone(),
        now.saturating_sub(4),
        now + 56,
        ReplayNonce16::new([0x66; 16]),
    )
    .unwrap();
    let profile = SigningKey::from_bytes(&[0x26; 32]);
    let authorization_statement = RecipientKeyAuthorizationStatementV1::new(
        binding.clone(),
        RightsActionV1::View,
        recipient_public,
        rights_request.request().recipient().clone(),
        RuntimeOperationIssuerKeyV1::new(runtime_key.verifying_key().to_bytes()).unwrap(),
        now.saturating_sub(5),
        now + 120,
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
        elastos_protected_content_contracts::RightsEvaluationEvidenceRequestV1::new(
            binding.clone(),
            policy.policy_identity().unwrap(),
        )
        .unwrap();
    let statement = RuntimeReleaseOperationStatementV1::new(
        RuntimeOperationIssuerKeyV1::new(runtime_key.verifying_key().to_bytes()).unwrap(),
        rights_request,
        release_request,
        recipient_public,
        authorization,
        policy,
        evidence_request,
        custody_epoch,
        audit_request_id,
        now.saturating_sub(3),
        now + 55,
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

pub(super) fn wallet_request_response_for_release_at(
    operation: &SignedRuntimeReleaseOperationV1,
    profile: &str,
    account_id: &str,
    request_id: &str,
    now: u64,
) -> (Vec<u8>, Vec<u8>) {
    wallet_request_response_for_release_context_at(
        operation,
        profile,
        "runtime-session:alpha",
        Some("proof:alpha"),
        "grant:alpha",
        "launch:alpha",
        account_id,
        request_id,
        now,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "test helper binds every fixture fact explicitly"
)]
pub(super) fn wallet_request_response_for_release_context_at(
    operation: &SignedRuntimeReleaseOperationV1,
    profile: &str,
    runtime_session_id: &str,
    proof_binding: Option<&str>,
    grant_id: &str,
    launch_id: &str,
    account_id: &str,
    request_id: &str,
    now: u64,
) -> (Vec<u8>, Vec<u8>) {
    let context = VerifiedWalletInvocationContext::new(
        profile,
        runtime_session_id,
        proof_binding.map(str::to_string),
        grant_id,
        "runtime",
        launch_id,
    )
    .unwrap();
    let request = WalletProviderRequestV2::new(
        &context,
        request_id,
        now,
        now + 120,
        WalletProviderOperationV2::RequestProtectedContentRightsSignature {
            account_id: account_id.to_string(),
            canonical_rights_request_hex: hex::encode(
                operation
                    .statement()
                    .rights_request()
                    .request()
                    .canonical_bytes()
                    .unwrap(),
            ),
            reason: "Open protected content".to_string(),
        },
    )
    .unwrap();
    let result = ProtectedContentRightsSignatureResultV1::new(
        account_id,
        wallet_address_hex(
            operation
                .statement()
                .rights_request()
                .request()
                .binding()
                .wallet(),
        ),
        hex::encode(
            operation
                .statement()
                .rights_request()
                .canonical_bytes()
                .unwrap(),
        ),
    )
    .unwrap();
    let response = WalletProviderResponseV2::for_request(
        &request,
        WalletResultV2::Ok {
            data: serde_json::to_value(result).unwrap(),
        },
    );
    (
        serde_json::to_vec(&request).unwrap(),
        serde_json::to_vec(&response).unwrap(),
    )
}

pub(super) fn signed_runtime_custody_provisioning_at(
    record: &CustodyNodeProvisioningRecordV1,
    runtime_seed: u8,
    now: u64,
) -> SignedRuntimeCustodyProvisioningV1 {
    let runtime_key = SigningKey::from_bytes(&[runtime_seed; 32]);
    let statement = RuntimeCustodyProvisioningStatementV1::new(
        RuntimeOperationIssuerKeyV1::new(runtime_key.verifying_key().to_bytes()).unwrap(),
        record.record_identity().unwrap(),
        RuntimeCustodyProvisioningIdV1::new(digest(0xa5)).unwrap(),
        now.saturating_sub(5),
        now + 40,
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

pub(super) fn chain_evidence_for_request_at(
    request: &RightsProviderRequestV1,
    now_unix_seconds: u64,
    evidence_now: u64,
    has_access: bool,
) -> Value {
    let validated = ValidatedRightsProviderRequestV1::decode_and_validate_at(
        &request.to_json_vec().unwrap(),
        now_unix_seconds,
    )
    .unwrap();
    let authenticated = validated.authenticated_runtime_release_operation();
    let policy = authenticated.statement().policy_body();
    let evidence_request = authenticated.statement().evidence_request();
    let evidence_issued_at = evidence_now.saturating_sub(1);
    let evidence = RightsEvaluationEvidenceV1::new(
        authenticated.operation_hash(),
        authenticated.release_request_hash(),
        evidence_request.binding().clone(),
        evidence_request.policy_identity().clone(),
        evidence_request.binding().wallet(),
        policy.chain_id(),
        100,
        digest(0x88),
        has_access,
        evidence_issued_at,
        evidence_issued_at + MAX_RIGHTS_EVIDENCE_LIFETIME_SECS,
    )
    .unwrap();
    let bytes = evidence.canonical_bytes().unwrap();
    json!({
        "schema": "elastos.chain.protected-content-rights-evidence/v1",
        "chain_id": evidence.observed_chain_id(),
        "finalized_block_number": evidence.finalized_block_number(),
        "finalized_block_hash": format!(
            "0x{}",
            hex::encode(evidence.finalized_block_hash().as_bytes())
        ),
        "rights_evaluation_evidence": format!("0x{}", hex::encode(&bytes)),
        "rights_evaluation_evidence_hash": format!(
            "0x{}",
            hex::encode(evidence.canonical_hash().unwrap().as_bytes())
        ),
    })
}

pub(super) fn make_signed_node_rights_decision(
    operation: &SignedRuntimeReleaseOperationV1,
    node_seed: u8,
    decision: RightsDecisionV1,
) -> SignedNodeRightsDecisionV1 {
    let authenticated = operation
        .verify(operation.statement().runtime_operation_issuer(), NOW + 3)
        .unwrap();
    let statement = elastos_protected_content_contracts::NodeRightsDecisionStatementV1::new(
        authenticated.release_request_hash(),
        authenticated.rights_request_hash(),
        authenticated.binding().clone(),
        authenticated.action(),
        node_public_key(node_seed),
        decision,
        digest(0x80 ^ node_seed),
        NOW + 4,
        NOW + 40,
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

pub(super) fn make_signed_node_contribution(
    operation: &SignedRuntimeReleaseOperationV1,
    node_seed: u8,
) -> SignedNodeContributionV1 {
    let authenticated = operation
        .verify(operation.statement().runtime_operation_issuer(), NOW + 5)
        .unwrap();
    let decision =
        make_signed_node_rights_decision(operation, node_seed, RightsDecisionV1::Allowed);
    let sealed =
        RecipientSealedContributionV1::new(authenticated.recipient().clone(), vec![node_seed; 96])
            .unwrap();
    let statement = NodeContributionStatementV1::new(
        authenticated.release_request_hash(),
        authenticated.binding().clone(),
        decision,
        sealed,
        NOW + 5,
        NOW + 40,
    )
    .unwrap();
    SignedNodeContributionV1::new(
        statement.clone(),
        node_signing_key(node_seed)
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

pub(super) fn make_signed_terminal_receipt(
    operation: &SignedRuntimeReleaseOperationV1,
    contributions: &[SignedNodeContributionV1],
    issuer_seed: u8,
) -> SignedTerminalReceiptV1 {
    make_signed_terminal_receipt_at(operation, contributions, issuer_seed, NOW + 6)
}

pub(super) fn make_signed_terminal_receipt_at(
    operation: &SignedRuntimeReleaseOperationV1,
    contributions: &[SignedNodeContributionV1],
    issuer_seed: u8,
    now: u64,
) -> SignedTerminalReceiptV1 {
    let authenticated = operation
        .verify(operation.statement().runtime_operation_issuer(), now)
        .unwrap();
    let node_set = operation
        .statement()
        .custody_epoch()
        .statement()
        .node_set()
        .unwrap();
    let verified_contributions = contributions
        .iter()
        .map(|contribution| {
            authenticated
                .verify_node_contribution(contribution, &node_set, now)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let refs = verified_contributions
        .iter()
        .map(NodeContributionRefV1::from)
        .collect::<Vec<_>>();
    let expires_at = contributions
        .iter()
        .map(|contribution| contribution.statement().expires_at())
        .min()
        .unwrap_or_else(|| now.saturating_add(34))
        .min(now.saturating_add(34));
    let issuer_key = SigningKey::from_bytes(&[issuer_seed; 32]);
    let statement = TerminalReceiptStatementV1::new(
        authenticated.release_request_hash(),
        authenticated.binding().clone(),
        TerminalReceiptIssuerKey::new(issuer_key.verifying_key().to_bytes()).unwrap(),
        KeyReleaseOutcomeV1::Released,
        refs,
        now,
        expires_at,
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

pub(super) fn provisioning_record_for_selected_node(
    envelope: &CustodyEnvelopeV1,
    selected_node_public_key: NodePublicKey,
) -> CustodyNodeProvisioningRecordV1 {
    CustodyNodeProvisioningRecordV1::new(
        envelope.key_envelope_identity().unwrap(),
        envelope.manifest().clone(),
        selected_node_public_key,
        envelope
            .stored_share_for_node(selected_node_public_key)
            .unwrap()
            .clone(),
    )
    .unwrap()
}

pub(super) fn opaque_handle(seed: u8) -> [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1] {
    let mut bytes = [0u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
    bytes[0] = seed.max(1);
    bytes[31] = seed ^ 0x5a;
    bytes
}

pub(super) fn decrypt_prepare_request() -> DecryptProviderRequestV1 {
    let envelope = custody_envelope_for_media(0x11);
    DecryptProviderRequestV1::new_prepare_recipient(
        &binding_for_envelope(&envelope),
        RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap(),
        RightsActionV1::View,
        runtime_operation_issuer_for_seed(0x42),
        NOW,
        NOW + 50,
    )
    .unwrap()
}

pub(super) fn decrypt_open_fixture() -> (
    DecryptProviderRequestV1,
    RuntimeReleaseAuditIdV1,
    [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    Vec<u8>,
    Vec<Vec<u8>>,
) {
    let envelope = custody_envelope_for_media(0x11);
    let operation = make_signed_runtime_release_operation_for_envelope_and_seed(0x42, &envelope);
    let contributions = vec![
        make_signed_node_contribution(&operation, 1),
        make_signed_node_contribution(&operation, 2),
    ];
    let terminal = make_signed_terminal_receipt(&operation, &contributions, 0x61);
    let handle = opaque_handle(0x21);
    let (init_segment, encrypted_segments) = media_components(0x11);
    let media = media_identity(0x11);
    let request = DecryptProviderRequestV1::new_open_viewer_session(
        handle,
        &operation,
        terminal.statement().issuer(),
        envelope.manifest().content_key_commitment(),
        &media,
        &init_segment,
        &contributions,
        &terminal,
    )
    .unwrap();
    (
        request,
        operation.statement().audit_request_id(),
        handle,
        init_segment,
        encrypted_segments,
    )
}

pub(super) fn assert_exact_runtime_decrypt_invocation(
    recorded: &Value,
    expected_op: &str,
    expected_request: &Value,
) {
    assert_eq!(recorded["op"], expected_op);
    assert_eq!(
        recorded["_runtime_invocation"]["source"],
        RUNTIME_PROVIDER_ID
    );
    assert_eq!(
        recorded["_runtime_invocation"]["target"],
        PROTECTED_CONTENT_DECRYPT_PROVIDER_ID
    );
    assert_eq!(
        recorded["_runtime_invocation"]["transport"],
        "runtime-local-provider-plane"
    );
    assert_eq!(recorded["_runtime_invocation"]["carrier"], Value::Null);
    assert!(recorded.get("route").is_none());
    assert!(recorded.get("host").is_none());
    assert!(recorded.get("port").is_none());
    assert!(recorded.get("url").is_none());
    let mut stripped = recorded.clone();
    stripped
        .as_object_mut()
        .unwrap()
        .remove("_runtime_invocation");
    assert_eq!(&stripped, expected_request);
}

#[cfg(unix)]
pub(super) struct ProcessCustodyNodeFixture {
    pub(super) registry: Arc<ProviderRegistry>,
    pub(super) adapter: RuntimeCustodyRegistryAdapter,
    pub(super) provisioned: ProvisionedCustodyProviderPublicKeys,
    pub(super) owner_state_root: Digest32,
}

#[cfg(unix)]
pub(super) fn provisioned_process_custody_node_for_issuer(
    binary: &Path,
    temp_root: &Path,
    dir_name: &str,
    runtime_issuer: RuntimeOperationIssuerKeyV1,
    owner_state_root: Digest32,
) -> ProcessCustodyNodeFixture {
    let data_dir = temp_root.join(dir_name);
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(state_root.parent().unwrap());
    let provisioned =
        provision_custody_node_public_receipt_for_issuer(binary, &state_root, runtime_issuer);
    let registry = Arc::new(ProviderRegistry::new());
    ProcessCustodyNodeFixture {
        adapter: RuntimeCustodyRegistryAdapter::new(
            registry.clone(),
            elastos_runtime::provider::ProviderInvocationTransport::Local,
        ),
        registry,
        provisioned,
        owner_state_root,
    }
}

#[cfg(unix)]
pub(super) fn provision_custody_node_public_receipt_for_issuer(
    binary: &Path,
    state_root: &Path,
    runtime_issuer: RuntimeOperationIssuerKeyV1,
) -> ProvisionedCustodyProviderPublicKeys {
    let issuer_hex = format!("0x{}", hex::encode(runtime_issuer.as_bytes()));
    let output = Command::new(binary)
        .args([
            "provision",
            "--base-path",
            state_root.to_str().unwrap(),
            "--trusted-runtime-issuer",
            &issuer_hex,
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
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    parse_and_verify_provisioning_output(&response, runtime_issuer).unwrap()
}

#[cfg(unix)]
pub(super) fn provisioned_process_custody_node(
    binary: &Path,
    temp_root: &Path,
    dir_name: &str,
    runtime_issuer_seed: u8,
    owner_state_root: Digest32,
) -> ProcessCustodyNodeFixture {
    let data_dir = temp_root.join(dir_name);
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(state_root.parent().unwrap());
    let provisioned =
        provision_custody_node_public_receipt(binary, &state_root, runtime_issuer_seed);
    let registry = Arc::new(ProviderRegistry::new());
    ProcessCustodyNodeFixture {
        adapter: RuntimeCustodyRegistryAdapter::new(
            registry.clone(),
            elastos_runtime::provider::ProviderInvocationTransport::Local,
        ),
        registry,
        provisioned,
        owner_state_root,
    }
}

#[cfg(unix)]
pub(super) async fn provision_selected_node_share(
    fixture: &ProcessCustodyNodeFixture,
    envelope: &CustodyEnvelopeV1,
    runtime_seed: u8,
    now: u64,
) {
    let provisioning_record =
        provisioning_record_for_selected_node(envelope, fixture.provisioned.node_public_key);
    let provisioning =
        signed_runtime_custody_provisioning_at(&provisioning_record, runtime_seed, now);
    let request =
        CustodyProviderRequestV1::new_provision_node_share(&provisioning_record, &provisioning)
            .unwrap();
    let response = fixture
        .adapter
        .provision_node_share(&request)
        .await
        .unwrap();
    assert_eq!(
        response.provisioned_record_identity().unwrap(),
        provisioning_record.record_identity().unwrap()
    );
}

#[cfg(unix)]
pub(super) fn runtime_verified_purchase_effect_for_mint(
    mint: &PersistedRuntimeMint,
    principal_id: &str,
    account_id: &str,
    approval_request_id: &str,
    tx_byte: u8,
    now: u64,
) -> RuntimeVerifiedPurchaseEffect {
    RuntimeVerifiedPurchaseEffect::new(
        RuntimeProtectedContentPurchaseIntent::new(
            mint.draft().mint_id(),
            mint.draft().encrypted_content().clone(),
            mint.draft().key_envelope().clone(),
            mint.draft().policy().clone(),
            RightsActionV1::View,
            "eip155:20",
            "esc-mainnet",
            "0x2222222222222222222222222222222222222222",
            "0x1",
            "0x",
        )
        .unwrap(),
        RuntimePurchaseEffectAuthority::new(
            principal_id,
            account_id,
            wallet_address_hex(wallet(7)),
            approval_request_id,
        )
        .unwrap(),
        ValidatedChainOutcomeBindingV1::ManagedSigned {
            signed_transaction_sha256: format!("sha256:{}", hex::encode([tx_byte ^ 1; 32])),
        },
        format!("0x{}", hex::encode([tx_byte; 32])),
        json!({
            "schema": "elastos.chain.broadcast_receipt/v1",
            "network": "esc-mainnet",
        }),
        now,
    )
    .unwrap()
}

pub(super) fn ok_provider_response(value: serde_json::Value) -> serde_json::Value {
    json!({
        "status": "ok",
        "data": value,
    })
}

pub(super) fn ok_typed_protect_provider_response(
    response: ProtectProviderResponseV1,
) -> serde_json::Value {
    ok_provider_response(serde_json::from_slice(&response.to_json_vec().unwrap()).unwrap())
}

#[async_trait::async_trait]
impl Provider for RecordingProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "recording provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![self.name]
    }

    fn name(&self) -> &'static str {
        self.name
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.requests.lock().await.push(request.clone());
        Ok(self.response.clone())
    }
}

#[async_trait::async_trait]
impl Provider for SequencedProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "sequenced provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![self.name]
    }

    fn name(&self) -> &'static str {
        self.name
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.requests.lock().await.push(request.clone());
        self.responses.lock().await.pop_front().unwrap_or_else(|| {
            Err(ProviderError::Provider(
                "sequenced provider response queue is exhausted".to_string(),
            ))
        })
    }
}

#[async_trait::async_trait]
impl Provider for ProcessChainEvidenceProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "process chain evidence provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![CHAIN_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        CHAIN_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.requests.lock().await.push(request.clone());
        let expected = elastos_protected_content_rights::chain_rights_evidence_request(
            &self
                .expected_request
                .signed_runtime_release_operation()
                .map_err(|_| {
                    ProviderError::Provider("expected rights request is invalid".to_string())
                })?,
        )
        .map_err(|_| ProviderError::Provider("expected rights request is invalid".to_string()))?;
        if request["_runtime_invocation"]["source"]
            != Value::String(RUNTIME_PROVIDER_ID.to_string())
            || request["_runtime_invocation"]["target"]
                != Value::String(CHAIN_PROVIDER_ID.to_string())
            || request["_runtime_invocation"]["op"]
                != Value::String(CHAIN_RIGHTS_EVIDENCE_OP.to_string())
            || request["_runtime_invocation"]["transport"]
                != Value::String("runtime-local-provider-plane".to_string())
            || request["_runtime_invocation"]["carrier"] != Value::Null
        {
            return Err(ProviderError::Provider(
                "chain evidence runtime envelope did not match the expected invocation".to_string(),
            ));
        }
        let mut inner_request = request.clone();
        let Some(inner_object) = inner_request.as_object_mut() else {
            return Err(ProviderError::Provider(
                "chain evidence request was not an object".to_string(),
            ));
        };
        inner_object.remove("_runtime_invocation");
        if inner_request != expected {
            return Err(ProviderError::Provider(
                "chain evidence request did not match the expected release operation".to_string(),
            ));
        }
        let evidence_now = crate::auth::now_ts();
        Ok(ok_provider_response(chain_evidence_for_request_at(
            &self.expected_request,
            evidence_now,
            evidence_now,
            self.has_access,
        )))
    }
}

#[cfg(unix)]
#[async_trait::async_trait]
impl Provider for TestMediaPreparationProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "test media provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![MEDIA_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        MEDIA_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let operation_id = request
            .get("operation_id")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Provider("missing operation id".to_string()))?
            .to_string();
        if request["op"] != "prepare"
            || request["_runtime_invocation"]["source"] != RUNTIME_PROVIDER_ID
            || request["_runtime_invocation"]["target"] != MEDIA_PROVIDER_ID
            || request["_runtime_invocation"]["op"] != "prepare"
            || request["_runtime_invocation"]["transport"] != "runtime-local-provider-plane"
            || request["_runtime_invocation"]["carrier"] != Value::Null
        {
            return Err(ProviderError::Provider(
                "media preparation invocation authority is invalid".to_string(),
            ));
        }
        self.requests.lock().await.push(operation_id.clone());
        match self.response {
            TestMediaPreparationResponse::Prepared => {
                let prepared_root = self.staging_root.join(operation_id).join("prepared");
                owner_only_dir(&prepared_root);
                owner_only_dir(&prepared_root.join("segments"));
                let (init, segments) = clear_media_components(0x61);
                fs::write(prepared_root.join("init.mp4"), init).unwrap();
                fs::set_permissions(
                    prepared_root.join("init.mp4"),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
                for (index, segment) in segments.iter().enumerate() {
                    let path = prepared_root
                        .join("segments")
                        .join(format!("{index:08}.m4s"));
                    fs::write(&path, segment).unwrap();
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                Ok(ok_provider_response(json!({
                    "schema": "elastos.media-provider.prepared-media/v1",
                    "mime_type": "video/mp4",
                    "codecs": "avc1.640028",
                })))
            }
            TestMediaPreparationResponse::SettledFailure => Ok(json!({
                "status": "error",
                "code": "internal_error",
                "message": "media preparation failed",
                "data": {"operation_settled": true},
            })),
            TestMediaPreparationResponse::UnknownSettlement => Err(ProviderError::Provider(
                "media preparation transport failed".to_string(),
            )),
        }
    }
}

#[cfg(unix)]
pub(super) fn owner_only_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
pub(super) fn protected_content_root(data_dir: &Path) -> PathBuf {
    data_dir.join("protected-content")
}

#[cfg(unix)]
pub(super) fn custody_composition_config_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join("custody-composition.json")
}

#[cfg(unix)]
pub(super) fn chain_provider_config_path(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join("chain-provider.json")
}

#[cfg(unix)]
pub(super) fn write_chain_provider_config(data_dir: &Path, config: &Value) {
    owner_only_dir(&protected_content_root(data_dir));
    fs::write(
        chain_provider_config_path(data_dir),
        serde_json::to_vec(config).unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        chain_provider_config_path(data_dir),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}

#[cfg(unix)]
pub(super) fn safe_ancestor_tempdir() -> tempfile::TempDir {
    // The media prerequisite import walks every ancestor of the source tool
    // path and rejects world-writable directories. std temp lives under
    // /tmp (mode 1777) on Linux, so fixtures built there are structurally
    // unsafe; anchor them under the build target dir, whose ancestors are
    // developer- or runner-owned.
    let root = option_env!("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target")));
    let base = root.join("media-prereq-test-fixtures");
    fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(&base).unwrap()
}

#[cfg(unix)]
pub(super) fn write_media_prerequisite(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
pub(super) fn media_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join("protected-content/media-provider/config.json")
}

#[cfg(unix)]
pub(super) fn prepare_test_media_prerequisite(data_dir: &Path, root: &Path) {
    owner_only_dir(root);
    write_media_prerequisite(&root.join("ffmpeg"), b"ffmpeg-private-test", 0o700);
    write_media_prerequisite(&root.join("ffprobe"), b"ffprobe-private-test", 0o700);
    prepare_runtime_media_provider_prerequisite(data_dir, root, MediaToolsTrust::MustMatch)
        .unwrap();
}

#[cfg(unix)]
pub(super) fn test_chain_provider_config() -> Value {
    json!({
        "schema": PROTECTED_CONTENT_CHAIN_PROVIDER_CONFIG_SCHEMA_V1,
        "protected_content_network": {
            "id": "esc-mainnet",
            "rpc_url": "https://private-primary.example.invalid"
        }
    })
}

#[cfg(unix)]
pub(super) fn canonical_b64<T: CanonicalContract>(value: &T) -> String {
    base64::engine::general_purpose::STANDARD.encode(value.canonical_bytes().unwrap())
}

#[cfg(unix)]
pub(super) fn raw_b64_32(bytes: [u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(unix)]
pub(super) fn peer_did_for_seed(seed: u8) -> String {
    crate::crypto::encode_signing_key_did(&SigningKey::from_bytes(&[seed; 32]))
}

#[cfg(unix)]
pub(super) fn custody_composition_config(
    now: u64,
    routes: Vec<RuntimeCustodyRouteBindingConfig>,
) -> RuntimeCustodyCompositionConfigFile {
    let epoch = signed_custody_epoch();
    let pool = signed_custody_pool_for_epoch(&epoch, (now.saturating_sub(60), now + 3600));
    let authorization =
        signed_committee_authorization_for_epoch(pool.pool_identity().unwrap(), &epoch);
    RuntimeCustodyCompositionConfigFile {
        schema: CUSTODY_COMPOSITION_SCHEMA_V1.to_string(),
        expected_policy_authority_base64: raw_b64_32(
            SigningKey::from_bytes(&[0x71; 32])
                .verifying_key()
                .to_bytes(),
        ),
        expected_committee_authorization_identity_base64: canonical_b64(
            &authorization.authorization_identity().unwrap(),
        ),
        signed_pool_base64: canonical_b64(&pool),
        signed_epoch_base64: canonical_b64(&epoch),
        signed_committee_authorization_base64: canonical_b64(&authorization),
        routes,
    }
}

#[cfg(unix)]
pub(super) fn custody_route_bindings(
    epoch: &SignedCustodyEpochV1,
    transports: [RuntimeCustodyRouteTransportConfig; 3],
) -> Vec<RuntimeCustodyRouteBindingConfig> {
    epoch
        .statement()
        .nodes()
        .iter()
        .zip(transports)
        .enumerate()
        .map(
            |(index, (node, transport))| RuntimeCustodyRouteBindingConfig {
                node_public_key_base64: raw_b64_32(*node.node_public_key().as_bytes()),
                owner_state_root_base64: raw_b64_32([0x40 + u8::try_from(index).unwrap(); 32]),
                transport,
            },
        )
        .collect()
}

#[cfg(unix)]
pub(super) fn write_owner_only_custody_composition_config(
    data_dir: &Path,
    config: &RuntimeCustodyCompositionConfigFile,
) {
    let root = protected_content_root(data_dir);
    owner_only_dir(&root);
    let path = custody_composition_config_path(data_dir);
    fs::write(
        &path,
        serde_json::to_vec(&serde_json::to_value(config).unwrap()).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(unix)]
pub(super) fn assert_runtime_custody_transports(
    composition: &RuntimeCustodyComposition,
    expected: &[ProviderInvocationTransport],
) {
    assert_eq!(composition.nodes.len(), expected.len());
    for (node, expected_transport) in composition.nodes.iter().zip(expected.iter()) {
        assert_eq!(&node.adapter.transport, expected_transport);
    }
    for window in composition.nodes.windows(2) {
        assert!(Arc::ptr_eq(
            &window[0].adapter.registry,
            &window[1].adapter.registry
        ));
    }
}

#[cfg(unix)]
pub(super) fn mint_draft_for_composition_journal_test() -> RuntimeMintDraft {
    let epoch = signed_custody_epoch();
    let envelope = custody_envelope_for_media_with_epoch(0x41, &epoch);
    let (init_segment, encrypted_segments) = media_components(0x41);
    let mint_nodes = epoch
        .statement()
        .nodes()
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let node_seed = u8::try_from(index + 1).unwrap();
            RuntimeMintNodeBinding::new(
                node.node_public_key(),
                CustodyPoolOperatorIdV1::new([0x80 + node_seed; 32]),
                CustodyPoolFailureDomainIdV1::new([0x90 + node_seed; 32]),
                Digest32::new([0x3f + node_seed; 32]),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    RuntimeMintDraft::new(
        &init_segment,
        &encrypted_segments,
        MEDIA_MIME_TYPE_V1,
        MEDIA_CODECS_V1,
        content_access_id(0x41),
        envelope.key_envelope_identity().unwrap(),
        policy_body().policy_identity().unwrap(),
        envelope.manifest().content_key_commitment(),
        envelope.manifest().threshold(),
        mint_nodes,
    )
    .unwrap()
}

#[cfg(unix)]
pub(super) fn inactive_custody_state_root(data_dir: &Path) -> PathBuf {
    data_dir.join("protected-content/custody-provider/inactive")
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
pub(super) enum ProtectedStartupProvider {
    Protect,
    Custody,
    Decrypt,
}

#[cfg(unix)]
impl ProtectedStartupProvider {
    pub(super) const ALL: [Self; 3] = [Self::Protect, Self::Custody, Self::Decrypt];

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Protect => "protect-provider",
            Self::Custody => "custody-provider",
            Self::Decrypt => "protected-content-decrypt-provider",
        }
    }

    pub(super) fn target(self) -> &'static str {
        match self {
            Self::Protect => PROTECT_PROVIDER_ID,
            Self::Custody => CUSTODY_PROVIDER_ID,
            Self::Decrypt => PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
        }
    }

    pub(super) fn status(self) -> Value {
        match self {
            Self::Protect => json!({
                "status": "ok",
                "data": {
                    "provider": PROTECT_PROVIDER_PROCESS_ID,
                    "version": "0.7.2-alpha.5",
                    "configured": true,
                    "supported_operations": PROTECT_PROVIDER_OPERATIONS,
                    "request_schema": PROTECT_PROVIDER_REQUEST_SCHEMA_V1,
                    "response_schema": PROTECT_PROVIDER_RESPONSE_SCHEMA_V1,
                }
            }),
            Self::Custody => json!({
                "status": "ok",
                "data": {
                    "provider": CUSTODY_PROVIDER_ID,
                    "version": "0.7.2-alpha.5",
                    "configured": true,
                    "supported_operations": CUSTODY_PROVIDER_OPERATIONS,
                    "request_schema": CUSTODY_PROVIDER_REQUEST_SCHEMA_V1,
                    "response_schema": CUSTODY_PROVIDER_RESPONSE_SCHEMA_V1,
                }
            }),
            Self::Decrypt => protected_content_decrypt_provider_status(),
        }
    }

    pub(super) fn prepare_private_config(self, data_dir: &Path) {
        owner_only_dir(data_dir);
        if matches!(self, Self::Custody) {
            owner_only_dir(&inactive_custody_state_root(data_dir));
        }
    }

    pub(super) async fn register(
        self,
        registry: &Arc<ProviderRegistry>,
        binary: &Path,
        data_dir: &Path,
    ) -> anyhow::Result<()> {
        match self {
            Self::Protect => register_protect_provider(registry, binary).await,
            Self::Custody => register_inactive_custody_provider(registry, binary, data_dir).await,
            Self::Decrypt => {
                register_protected_content_decrypt_provider(
                    registry,
                    binary,
                    runtime_operation_issuer_for_seed(0x41),
                )
                .await
            }
        }
    }
}

#[cfg(unix)]
pub(super) fn write_mock_custody_provider(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let binary = root.join("mock-custody-provider.sh");
    let request_log = root.join("mock-custody-provider.requests");
    let pid_file = root.join("mock-custody-provider.pid");
    let script = format!(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" >> '{}'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  case \"$line\" in\n    *'\"op\":\"shutdown\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}'; exit 0 ;;\n    *'\"unexpected\"'* ) printf '%s\\n' '{{\"status\":\"error\",\"code\":\"invalid_request\"}}' ;;\n    *'\"op\":\"status\"'*) printf '%s\\n' '{}' ;;\n    *'\"op\":\"release_contribution\"'*) printf '%s\\n' '{{\"status\":\"ok\",\"data\":{{\"echo\":\"custody\"}}}}' ;;\n    *) printf '%s\\n' '{{\"status\":\"ok\",\"data\":{{\"echo\":\"init\"}}}}' ;;\n  esac\ndone\n",
        pid_file.display(),
        request_log.display(),
        ProtectedStartupProvider::Custody.status(),
    );
    crate::test_support::write_from_child(&binary, &script, 0o700);
    (binary, pid_file, request_log)
}

#[cfg(unix)]
pub(super) fn write_mock_protected_startup_provider(
    root: &Path,
    provider_name: &str,
    status_response: &str,
) -> (PathBuf, PathBuf, PathBuf) {
    write_mock_protected_startup_provider_with_shutdown(
        root,
        provider_name,
        status_response,
        r#"{"status":"ok"}"#,
    )
}

#[cfg(unix)]
pub(super) fn write_mock_protected_startup_provider_with_shutdown(
    root: &Path,
    provider_name: &str,
    status_response: &str,
    shutdown_response: &str,
) -> (PathBuf, PathBuf, PathBuf) {
    let binary = root.join(format!("mock-{provider_name}.sh"));
    let request_log = root.join(format!("mock-{provider_name}.requests"));
    let pid_file = root.join(format!("mock-{provider_name}.pid"));
    let script = format!(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" >> '{}'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  case \"$line\" in\n    *'\"op\":\"shutdown\"'*) printf '%s\\n' '{}'; exit 0 ;;\n    *'\"op\":\"status\"'*) printf '%s\\n' '{}' ;;\n    *'\"op\":\"init\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}' ;;\n    *) printf '%s\\n' '{{\"status\":\"error\",\"code\":\"unexpected\"}}' ;;\n  esac\ndone\n",
        pid_file.display(),
        request_log.display(),
        shutdown_response,
        status_response,
    );
    crate::test_support::write_from_child(&binary, &script, 0o700);
    (binary, pid_file, request_log)
}

#[cfg(unix)]
pub(super) fn create_test_fifo(path: &Path) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
}

#[cfg(unix)]
pub(super) fn write_blocking_protected_status_provider(
    root: &Path,
    provider: ProtectedStartupProvider,
) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let binary = root.join(format!("mock-{}-timeout.sh", provider.name()));
    let request_log = root.join(format!("mock-{}-timeout.requests", provider.name()));
    let pid_file = root.join(format!("mock-{}-timeout.pid", provider.name()));
    let status_signal = root.join(format!("mock-{}-status.signal", provider.name()));
    let status_release = root.join(format!("mock-{}-status.release", provider.name()));
    create_test_fifo(&status_signal);
    create_test_fifo(&status_release);
    let script = format!(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" >> '{}'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  case \"$line\" in\n    *'\"op\":\"shutdown\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}'; exit 0 ;;\n    *'\"op\":\"status\"'*) printf x > '{}'; cat '{}' >/dev/null; printf '%s\\n' '{}' ;;\n    *'\"op\":\"init\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}' ;;\n    *) printf '%s\\n' '{{\"status\":\"error\",\"code\":\"unexpected\"}}' ;;\n  esac\ndone\n",
        pid_file.display(),
        request_log.display(),
        status_signal.display(),
        status_release.display(),
        provider.status(),
    );
    crate::test_support::write_from_child(&binary, &script, 0o700);
    (binary, pid_file, request_log, status_signal, status_release)
}

#[cfg(unix)]
pub(super) fn status_with_field(
    provider: ProtectedStartupProvider,
    field: &str,
    value: Value,
) -> Value {
    let mut status = provider.status();
    status["data"][field] = value;
    status
}

#[cfg(unix)]
pub(super) fn protected_startup_status_mismatches(
    provider: ProtectedStartupProvider,
) -> Vec<(&'static str, Value)> {
    let mut extra_operations = provider.status()["data"]["supported_operations"]
        .as_array()
        .unwrap()
        .clone();
    extra_operations.push(json!("unexpected"));
    let mut reordered_operations = provider.status()["data"]["supported_operations"]
        .as_array()
        .unwrap()
        .clone();
    reordered_operations.swap(0, 1);
    let mut extra_data = provider.status();
    extra_data["data"]["route"] = json!("private");
    let mut extra_top = provider.status();
    extra_top["route"] = json!("private");
    vec![
        (
            "identity",
            status_with_field(provider, "provider", json!("wrong-provider")),
        ),
        (
            "version",
            status_with_field(provider, "version", json!("wrong-version")),
        ),
        (
            "configured",
            status_with_field(provider, "configured", json!(false)),
        ),
        (
            "request-schema",
            status_with_field(provider, "request_schema", json!("wrong-request-schema")),
        ),
        (
            "response-schema",
            status_with_field(provider, "response_schema", json!("wrong-response-schema")),
        ),
        (
            "operations-missing",
            status_with_field(provider, "supported_operations", json!(["status"])),
        ),
        (
            "operations-extra",
            status_with_field(
                provider,
                "supported_operations",
                Value::Array(extra_operations),
            ),
        ),
        (
            "operations-reordered",
            status_with_field(
                provider,
                "supported_operations",
                Value::Array(reordered_operations),
            ),
        ),
        ("extra-data", extra_data),
        ("extra-top", extra_top),
    ]
}

#[cfg(unix)]
pub(super) fn protected_content_decrypt_provider_status() -> Value {
    json!({
        "status": "ok",
        "data": {
            "provider": PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
            "version": "0.7.2-alpha.5",
            "configured": true,
            "supported_operations": PROTECTED_CONTENT_DECRYPT_PROVIDER_OPERATIONS,
            "request_schema": DECRYPT_PROVIDER_REQUEST_SCHEMA_V1,
            "response_schema": DECRYPT_PROVIDER_RESPONSE_SCHEMA_V1,
        }
    })
}

#[cfg(unix)]
pub(super) fn write_mock_protected_content_decrypt_provider(
    root: &Path,
    expected_issuer: RuntimeOperationIssuerKeyV1,
    status: &Value,
) -> (PathBuf, PathBuf, PathBuf) {
    let binary = root.join("mock-protected-content-decrypt-provider.sh");
    let request_log = root.join("mock-protected-content-decrypt-provider.requests");
    let pid_file = root.join("mock-protected-content-decrypt-provider.pid");
    let expected_issuer = format!("0x{}", hex::encode(expected_issuer.as_bytes()));
    let script = format!(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" >> '{}'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  case \"$line\" in\n    *'\"op\":\"shutdown\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}'; exit 0 ;;\n    *'\"op\":\"init\"'*)\n      case \"$line\" in\n        *'\"trusted_runtime_issuer\":\"{}\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}' ;;\n        *) printf '%s\\n' '{{\"status\":\"error\",\"code\":\"invalid_config\",\"message\":\"wrong issuer\"}}' ;;\n      esac ;;\n    *'\"op\":\"status\"'*) printf '%s\\n' '{}' ;;\n    *) printf '%s\\n' '{{\"status\":\"error\",\"code\":\"unexpected\",\"message\":\"unexpected\"}}' ;;\n  esac\ndone\n",
        pid_file.display(),
        request_log.display(),
        expected_issuer,
        status,
    );
    crate::test_support::write_from_child(&binary, &script, 0o700);
    (binary, pid_file, request_log)
}

#[cfg(unix)]
pub(super) fn read_pid(path: &Path) -> u32 {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .last()
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

#[cfg(unix)]
pub(super) fn read_pids(path: &Path) -> Vec<u32> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| line.trim().parse().unwrap())
        .collect()
}

#[cfg(unix)]
pub(super) fn process_is_running(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

#[cfg(unix)]
pub(super) fn inactive_custody_runtime_envelope(op: &str, transport: &str) -> Value {
    let carrier = if transport == "carrier-provider-plane" {
        let endpoint = iroh::SecretKey::from_bytes(&[0x51; 32]).public();
        json!({
            "source_endpoint_did": crate::carrier::public_key_to_did(&endpoint)
                .expect("test endpoint must have a canonical DID"),
        })
    } else {
        Value::Null
    };
    json!({
        "schema": "elastos.provider.invocation/v1",
        "source": RUNTIME_PROVIDER_ID,
        "target": CUSTODY_PROVIDER_ID,
        "op": op,
        "capability": format!("provider:{RUNTIME_PROVIDER_ID}->{CUSTODY_PROVIDER_ID}:{op}"),
        "transport": transport,
        "carrier": carrier,
        "transfer": "json",
        "range": Value::Null,
        "progress": Value::Null,
        "abi": {
            "schema": "elastos.provider.transfer-abi/v1",
            "transfer": "json",
            "transport": transport,
            "range_supported": false,
            "progress_supported": false,
            "progress_mode": "none",
            "transport_native_stream": false,
            "backpressure": "not_applicable",
            "cancel_supported": false,
        }
    })
}

#[cfg(unix)]
pub(super) async fn spawn_inactive_custody_wrapper_for_test(
    binary: &Path,
    data_dir: &Path,
) -> InactiveCustodyProvider {
    let state_root = inactive_custody_state_root(data_dir);
    let bridge = ProviderBridge::spawn(
        binary,
        ProviderConfig {
            base_path: state_root.to_str().unwrap().to_owned(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    InactiveCustodyProvider::new(InactiveCustodyProviderParts {
        bridge: Arc::new(bridge),
        registry: Arc::downgrade(&Arc::new(ProviderRegistry::new())),
    })
}

#[cfg(unix)]
pub(super) fn media_preparation_source_input(
    root: &Path,
    principal_id: &str,
) -> RuntimeCustodyLibrarySourceInput {
    RuntimeCustodyLibrarySourceInput {
        object_uri: format!(
            "{}/Documents/source.mp4",
            crate::auth::principal_localhost_root(principal_id)
        ),
        principal_id: principal_id.to_string(),
        source_file_path: root.join("source.mp4"),
        wallet_account_id: "wallet-account-1".to_string(),
        wallet_account_address: "0x1111111111111111111111111111111111111111".to_string(),
        creator_mint_source_digest: digest(0x71),
        copies: "0x1".to_string(),
        price: "0x5".to_string(),
        source_storage: "protected_principal_root".to_string(),
    }
}

#[cfg(unix)]
pub(super) fn setup_media_preparation_root(temp: &Path) -> (PathBuf, PathBuf) {
    let data_dir = temp.join("data");
    owner_only_dir(&data_dir);
    let protected_root = data_dir.join("protected-content");
    owner_only_dir(&protected_root);
    let provider_root = protected_root.join("media-provider");
    owner_only_dir(&provider_root);
    let staging_root = provider_root.join("staging");
    owner_only_dir(&staging_root);
    let source_path = temp.join("source.mp4");
    fs::write(&source_path, b"bounded source media").unwrap();
    fs::set_permissions(&source_path, fs::Permissions::from_mode(0o600)).unwrap();
    (data_dir, staging_root)
}

#[cfg(unix)]
pub(super) fn library_publish_test_routes(
    epoch: &SignedCustodyEpochV1,
) -> Vec<RuntimeCustodyRouteBindingConfig> {
    custody_route_bindings(
        epoch,
        [
            RuntimeCustodyRouteTransportConfig::Local,
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                peer_did: peer_did_for_seed(0xa1),
            },
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                peer_did: peer_did_for_seed(0xa2),
            },
        ],
    )
}

#[cfg(unix)]
pub(super) fn library_publish_test_input(principal_id: &str) -> RuntimeCustodyLibraryPublishInput {
    let (clear_init_segment, clear_segments) = clear_media_components(0x41);
    RuntimeCustodyLibraryPublishInput {
        object_uri: "localhost://Users/test/Documents/media".to_string(),
        principal_id: principal_id.to_string(),
        mime_type: MEDIA_MIME_TYPE_V1.to_string(),
        codecs: MEDIA_CODECS_V1.to_string(),
        wallet_account_id: "wallet-account-1".to_string(),
        wallet_account_address: "0x1111111111111111111111111111111111111111".to_string(),
        creator_mint_source_digest: digest(0x71),
        copies: "0x1".to_string(),
        price: "0x5".to_string(),
        clear_init_segment,
        clear_segments,
        source_storage: "plain_localhost_root".to_string(),
    }
}

#[cfg(unix)]
pub(super) fn library_publish_request_id(input: &RuntimeCustodyLibraryPublishInput) -> Digest32 {
    RuntimeMintIntent::request_id_for_source(
        &input.principal_id,
        &input.object_uri,
        &input.source_storage,
    )
    .unwrap()
}

#[cfg(unix)]
pub(crate) fn write_library_publish_test_composition(
    data_dir: &Path,
) -> (SignedCustodyEpochV1, u64) {
    let now = crate::auth::now_ts();
    let epoch = signed_custody_epoch();
    write_owner_only_custody_composition_config(
        data_dir,
        &custody_composition_config(now, library_publish_test_routes(&epoch)),
    );
    // Return the clock read used to derive the composition identities: the
    // custody-pool identity is content-addressed over clock-derived windows,
    // so any fixture that must produce the identical pool/committee identity
    // has to reuse this exact value instead of reading the clock again.
    (epoch, now)
}

#[cfg(unix)]
pub(crate) fn library_publish_test_mint_composition(
    data_dir: &Path,
) -> (
    Vec<RuntimeMintNodeBinding>,
    CustodyPoolIdentityV1,
    elastos_protected_content_contracts::CustodyEpochIdentityV1,
    CustodyCommitteeAuthorizationIdentityV1,
) {
    write_library_publish_test_composition(data_dir);
    let registry = Arc::new(ProviderRegistry::new());
    let composition = load_runtime_custody_composition(data_dir, registry)
        .unwrap()
        .unwrap();
    let configured = composition.configured_nodes().unwrap();
    let selected = resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        crate::auth::now_ts(),
        &configured,
    )
    .unwrap();
    let bindings = selected.iter().map(|node| node.binding().clone()).collect();
    let pool = composition.signed_pool.pool_identity().unwrap();
    let epoch = composition.signed_epoch.epoch_identity().unwrap();
    let committee = composition
        .signed_committee_authorization
        .authorization_identity()
        .unwrap();
    (bindings, pool, epoch, committee)
}

/// Seed the exact ELACITY-2307 crash state: a mint intent settled at
/// `SettledBeforeDraft(Closed)` alongside the durable mint work the completion
/// mark never named. `complete` selects the fully terminal record (custody
/// provisioned, availability recorded) or a partial-provision window.
/// Returns the seeded record's mint id.
#[cfg(unix)]
pub(super) fn seed_settled_runtime_custody_mint_record(
    data_dir: &Path,
    input: &RuntimeCustodyLibraryPublishInput,
    complete: bool,
) -> Digest32 {
    let (node_bindings, pool_identity, epoch_identity, committee_identity) =
        library_publish_test_mint_composition(data_dir);
    let journal = runtime_mint_journal(data_dir);
    let (protected_init_segment, protected_segments) = media_components(0x41);
    let threshold = ThresholdV1::new(2, 3).unwrap();
    let node_set = elastos_protected_content_contracts::NodeSetV1::new(
        threshold,
        node_bindings
            .iter()
            .map(|node| node.node_public_key())
            .collect(),
    )
    .unwrap();
    let key_envelope = elastos_protected_content_contracts::KeyEnvelopeIdentityV1::new(
        media_identity(0x41).encrypted_content().clone(),
        digest(0x52),
        256,
        node_set.node_set_id().unwrap(),
        threshold,
        pool_identity,
        epoch_identity,
        committee_identity,
    )
    .unwrap();
    let policy =
        elastos_protected_content_contracts::RightsPolicyIdentityV1::new(digest(0x56), 128)
            .unwrap();
    let draft = RuntimeMintDraft::new(
        &protected_init_segment,
        &protected_segments,
        input.mime_type.clone(),
        input.codecs.clone(),
        ContentAccessIdV1::new([0x51; 16]).unwrap(),
        key_envelope,
        policy,
        digest(0x61),
        threshold,
        node_bindings.clone(),
    )
    .unwrap();
    let intent = RuntimeMintIntent::new(
        input.principal_id.clone(),
        &input.object_uri,
        &input.source_storage,
        input.wallet_account_id.clone(),
        input.wallet_account_address.clone(),
        input.creator_mint_source_digest,
        input.mime_type.clone(),
        input.codecs.clone(),
        &input.clear_init_segment,
        &input.clear_segments,
        draft.content_access_id(),
        draft.pool(),
        draft.epoch(),
        draft.committee(),
        node_bindings.clone(),
    )
    .unwrap();
    let request_id = intent.request_id();
    journal.persist_intent(&intent).unwrap();
    journal
        .mark_intent_protect_effect_started(request_id)
        .unwrap();
    journal
        .mark_intent_protect_closed_before_draft(request_id)
        .unwrap();
    journal.persist_bound(&draft).unwrap();
    if !complete {
        journal
            .mark_node_effect_started(draft.mint_id(), node_bindings[0].node_public_key())
            .unwrap();
        return draft.mint_id();
    }
    for (index, node) in node_bindings.iter().enumerate() {
        journal
            .mark_node_effect_started(draft.mint_id(), node.node_public_key())
            .unwrap();
        journal
            .mark_node_receipt(
                draft.mint_id(),
                RuntimeMintNodeReceipt::new(
                    node.node_public_key(),
                    RuntimeCustodyProvisioningIdV1::new(digest(0x71 + index as u8)).unwrap(),
                    CustodyNodeProvisioningRecordIdentityV1::new(
                        digest(0x81 + index as u8),
                        128 + index as u32,
                    )
                    .unwrap(),
                    node.owner_state_root(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    journal.mark_custody_provisioned(draft.mint_id()).unwrap();
    let content_id = runtime_protected_content_id(draft.encrypted_content()).unwrap();
    let requirement = RuntimeContentAvailabilityRequirement::new(
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe",
        content_id.clone(),
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#publisher",
        "protected-content-replication/v1",
        3,
        600,
        60,
    )
    .unwrap();
    let evidence = elastos_protected_content_runtime::RuntimeVerifiedContentAvailability::new(
        "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        content_id,
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#publisher",
        &requirement,
        3,
        crate::auth::now_ts(),
        digest(0xa1),
        draft.encrypted_content().clone(),
        draft.media_identity().media_manifest_root(),
    )
    .unwrap();
    journal
        .mark_content_available(draft.mint_id(), &requirement, evidence)
        .unwrap();
    draft.mint_id()
}

#[cfg(unix)]
/// The publish input and the later media source must name the same object
/// under the principal's own root: the mint intent request id is derived
/// from the object binding, and a recovery-activated principal can only read
/// objects stored under its protected root.
pub(super) fn pre_dispatch_retry_publish_input() -> RuntimeCustodyLibraryPublishInput {
    let principal_id = "person:local:runtime-custody-pre-dispatch-retry";
    let mut input = library_publish_test_input(principal_id);
    input.object_uri = format!(
        "{}/Documents/media",
        crate::auth::principal_localhost_root(principal_id)
    );
    input
}

pub(super) struct LibraryMintCustodyProvider {
    pub(super) expected_issuer: RuntimeOperationIssuerKeyV1,
    pub(super) nodes: Vec<NodePublicKey>,
}

#[async_trait::async_trait]
impl Provider for LibraryMintCustodyProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "library mint custody provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![CUSTODY_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        CUSTODY_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let mut request = request.clone();
        if let Some(object) = request.as_object_mut() {
            object.remove("_runtime_invocation");
        }
        if request.get("op").and_then(Value::as_str) != Some("provision_node_share") {
            return Err(ProviderError::Provider(
                "library mint custody provider expected provision_node_share".to_string(),
            ));
        }
        let bytes = serde_json::to_vec(&request)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let now = crate::auth::now_ts();
        for node in &self.nodes {
            let Ok(validated) = ValidatedCustodyProviderRequestV1::decode_and_validate_at(
                &bytes,
                self.expected_issuer,
                *node,
                now,
            ) else {
                continue;
            };
            let provision = validated.provision_node_share().map_err(|_| {
                ProviderError::Provider("library mint provision request is invalid".to_string())
            })?;
            let response = CustodyProviderResponseV1::new_provisioned(provision).map_err(|_| {
                ProviderError::Provider("library mint provision response is invalid".to_string())
            })?;
            let response = serde_json::from_slice(
                &response
                    .to_json_vec()
                    .map_err(|error| ProviderError::Provider(error.to_string()))?,
            )
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
            return Ok(ok_provider_response(response));
        }
        Err(ProviderError::Provider(
            "library mint custody provision did not match a selected node".to_string(),
        ))
    }
}

pub(super) struct LibraryMintChainPolicyProvider;

#[async_trait::async_trait]
impl Provider for LibraryMintChainPolicyProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "library mint chain policy provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![CHAIN_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        CHAIN_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let encrypted_content = request
            .get("encrypted_content")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Provider("missing encrypted_content".to_string()))
            .and_then(|value| {
                let hex = value.strip_prefix("0x").ok_or_else(|| {
                    ProviderError::Provider("invalid encrypted_content".to_string())
                })?;
                let bytes = hex::decode(hex).map_err(|_| {
                    ProviderError::Provider("invalid encrypted_content".to_string())
                })?;
                EncryptedContentIdentityV1::from_canonical_bytes(&bytes)
                    .map_err(|_| ProviderError::Provider("invalid encrypted_content".to_string()))
            })?;
        let content_access_id = request
            .get("content_access_id")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::Provider("missing content_access_id".to_string()))
            .and_then(|value| {
                let hex = value.strip_prefix("0x").ok_or_else(|| {
                    ProviderError::Provider("invalid content_access_id".to_string())
                })?;
                let bytes: [u8; 16] = hex::decode(hex)
                    .map_err(|_| ProviderError::Provider("invalid content_access_id".to_string()))?
                    .try_into()
                    .map_err(|_| {
                        ProviderError::Provider("invalid content_access_id".to_string())
                    })?;
                ContentAccessIdV1::new(bytes)
                    .map_err(|_| ProviderError::Provider("invalid content_access_id".to_string()))
            })?;
        if request.get("action").and_then(Value::as_str) != Some("view") {
            return Err(ProviderError::Provider(
                "unexpected policy action".to_string(),
            ));
        }
        let policy = policy_body_for(encrypted_content, content_access_id, RightsActionV1::View);
        Ok(ok_provider_response(json!({
            "schema": CHAIN_PROTECTED_CONTENT_POLICY_SCHEMA_V1,
            "policy_body": format!("0x{}", hex::encode(policy.canonical_bytes().unwrap())),
        })))
    }
}

pub(super) struct LoopbackCustodyCarrierInvoker {
    pub(super) registry: Weak<ProviderRegistry>,
}

#[async_trait::async_trait]
impl ProviderCarrierInvoker for LoopbackCustodyCarrierInvoker {
    async fn invoke_carrier_provider(
        &self,
        route: &ProviderCarrierRoute,
        invocation: &ProviderInvocation,
        mut request: Value,
    ) -> Result<Value, ProviderError> {
        if !matches!(route, ProviderCarrierRoute::PeerDid { .. }) {
            return Err(ProviderError::Provider(
                "library custody loopback requires an endpoint DID route".to_string(),
            ));
        }
        let runtime = request
            .get_mut("_runtime_invocation")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                ProviderError::Provider(
                    "library custody loopback requires a Runtime invocation envelope".to_string(),
                )
            })?;
        runtime.insert(
            "carrier".to_string(),
            json!({"source_endpoint_did": peer_did_for_seed(0xa0)}),
        );
        let registry = self.registry.upgrade().ok_or_else(|| {
            ProviderError::Provider("library mint carrier loopback registry is gone".to_string())
        })?;
        registry
            .send_runtime_provider_target_raw(&invocation.target, &request)
            .await
    }
}

pub(super) struct AllowingProcessChainEvidenceProvider;

#[async_trait::async_trait]
impl Provider for AllowingProcessChainEvidenceProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "allowing process chain evidence provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![CHAIN_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        CHAIN_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        if request["_runtime_invocation"]["source"]
            != Value::String(RUNTIME_PROVIDER_ID.to_string())
            || request["_runtime_invocation"]["target"]
                != Value::String(CHAIN_PROVIDER_ID.to_string())
            || request["_runtime_invocation"]["op"]
                != Value::String(CHAIN_RIGHTS_EVIDENCE_OP.to_string())
            || request["_runtime_invocation"]["transport"]
                != Value::String("runtime-local-provider-plane".to_string())
            || request["_runtime_invocation"]["carrier"] != Value::Null
        {
            return Err(ProviderError::Provider(
                "chain evidence runtime envelope did not match the expected invocation".to_string(),
            ));
        }
        let mut inner_request = request.clone();
        let Some(inner_object) = inner_request.as_object_mut() else {
            return Err(ProviderError::Provider(
                "chain evidence request was not an object".to_string(),
            ));
        };
        inner_object.remove("_runtime_invocation");
        let signed_hex = inner_request
            .get("signed_runtime_release_operation")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProviderError::Provider(
                    "chain evidence request is missing the signed release operation".to_string(),
                )
            })?;
        let signed_bytes = hex::decode(signed_hex.strip_prefix("0x").unwrap_or(signed_hex))
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let operation = SignedRuntimeReleaseOperationV1::from_canonical_bytes(&signed_bytes)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let selected = operation
            .statement()
            .custody_epoch()
            .statement()
            .nodes()
            .first()
            .ok_or_else(|| {
                ProviderError::Provider("signed release operation has no custody nodes".to_string())
            })?
            .node_public_key();
        let expected = RightsProviderRequestV1::new_evaluate(selected, &operation)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let evidence_now = crate::auth::now_ts();
        Ok(ok_provider_response(chain_evidence_for_request_at(
            &expected,
            evidence_now,
            evidence_now,
            true,
        )))
    }
}

pub(super) struct LibraryProcessCustodyDispatcher {
    pub(super) expected_issuer: RuntimeOperationIssuerKeyV1,
    pub(super) nodes: Vec<(NodePublicKey, Arc<ProviderRegistry>)>,
}

impl LibraryProcessCustodyDispatcher {
    pub(super) fn strip_envelope(request: &Value) -> Result<Value, ProviderError> {
        let mut inner = request.clone();
        if let Some(object) = inner.as_object_mut() {
            object.remove("_runtime_invocation");
        }
        Ok(inner)
    }

    pub(super) fn node_registry(
        &self,
        request: &Value,
    ) -> Result<Arc<ProviderRegistry>, ProviderError> {
        let inner = Self::strip_envelope(request)?;
        let op = inner
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let bytes = serde_json::to_vec(&inner)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let now = crate::auth::now_ts();
        match op.as_str() {
            "status" => self
                .nodes
                .first()
                .map(|(_, registry)| registry.clone())
                .ok_or_else(|| {
                    ProviderError::Provider(
                        "library process custody dispatcher has no nodes".to_string(),
                    )
                }),
            "evaluate" => {
                let validated =
                    ValidatedRightsProviderRequestV1::decode_and_validate_at(&bytes, now)
                        .map_err(|error| ProviderError::Provider(error.to_string()))?;
                self.nodes
                    .iter()
                    .find(|(node, _)| *node == validated.selected_node_public_key())
                    .map(|(_, registry)| registry.clone())
                    .ok_or_else(|| {
                        ProviderError::Provider(
                            "library process custody evaluate did not match a selected node"
                                .to_string(),
                        )
                    })
            }
            "provision_node_share" | "release_contribution" => {
                for (node, registry) in &self.nodes {
                    if ValidatedCustodyProviderRequestV1::decode_and_validate_at(
                        &bytes,
                        self.expected_issuer,
                        *node,
                        now,
                    )
                    .is_ok()
                    {
                        return Ok(registry.clone());
                    }
                }
                Err(ProviderError::Provider(
                    "library process custody request did not match a selected node".to_string(),
                ))
            }
            _ => Err(ProviderError::Provider(format!(
                "library process custody dispatcher rejected op {op}"
            ))),
        }
    }
}

#[async_trait::async_trait]
impl Provider for LibraryProcessCustodyDispatcher {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "library process custody dispatcher is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![CUSTODY_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        CUSTODY_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let registry = self.node_registry(request)?;
        registry
            .send_runtime_provider_target_raw(CUSTODY_PROVIDER_ID, request)
            .await
    }
}

pub(super) struct LibraryReleaseWalletProvider;

#[async_trait::async_trait]
impl Provider for LibraryReleaseWalletProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "library release wallet provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["wallet"]
    }

    fn name(&self) -> &'static str {
        "wallet"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let inner = request.get("request").cloned().ok_or_else(|| {
            ProviderError::Provider("wallet request is missing the v2 envelope".to_string())
        })?;
        let bytes = serde_json::to_vec(&inner)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let now = crate::auth::now_ts();
        let wallet_request = WalletProviderRequestV2::decode_at(&bytes, now)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let (account_id, canonical_rights_request_hex) = match &wallet_request.operation {
            WalletProviderOperationV2::RequestProtectedContentRightsSignature {
                account_id,
                canonical_rights_request_hex,
                ..
            } => (account_id.clone(), canonical_rights_request_hex.clone()),
            _ => {
                return Err(ProviderError::Provider(
                    "library release wallet expected a protected-content rights signature"
                        .to_string(),
                ));
            }
        };
        let rights_bytes = hex::decode(&canonical_rights_request_hex)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let rights_request = RightsRequestV1::from_canonical_bytes(&rights_bytes)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let key = WalletSigningKey::from_slice(&[7; 32])
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let (signature, recovery_id) = key
            .sign_prehash_recoverable(&elastos_auth::ethereum_signed_message_hash(&rights_bytes))
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let mut signature_bytes = signature.to_bytes().to_vec();
        signature_bytes.push(recovery_id.to_byte());
        let signed = WalletSignedRightsRequestV1::new(rights_request, signature_bytes)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let result = ProtectedContentRightsSignatureResultV1::new(
            account_id,
            wallet_address_hex(wallet(7)),
            hex::encode(signed.canonical_bytes().unwrap()),
        )
        .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let wallet_response = WalletProviderResponseV2::for_request(
            &wallet_request,
            WalletResultV2::Ok {
                data: serde_json::to_value(result)
                    .map_err(|error| ProviderError::Provider(error.to_string()))?,
            },
        );
        Ok(ok_provider_response(
            serde_json::to_value(wallet_response)
                .map_err(|error| ProviderError::Provider(error.to_string()))?,
        ))
    }
}

/// A managed-account wallet: the rights-signature request first lands as a
/// pending approval; only after `approve` does the exact same request replay
/// the Wallet's stored result inside its approval envelope (the shape the
/// real wallet-provider answers with).
pub(super) struct ManagedReleaseWalletProvider {
    pub(super) approved: std::sync::Mutex<std::collections::HashSet<String>>,
    pub(super) seen: std::sync::Mutex<Vec<String>>,
}

impl ManagedReleaseWalletProvider {
    pub(super) fn new() -> Self {
        Self {
            approved: std::sync::Mutex::new(std::collections::HashSet::new()),
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(super) fn approve(&self, request_id: &str) {
        self.approved.lock().unwrap().insert(request_id.to_string());
    }

    pub(super) fn seen_request_ids(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl Provider for ManagedReleaseWalletProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "managed release wallet provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["wallet"]
    }

    fn name(&self) -> &'static str {
        "wallet"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let inner = request.get("request").cloned().ok_or_else(|| {
            ProviderError::Provider("wallet request is missing the v2 envelope".to_string())
        })?;
        let bytes = serde_json::to_vec(&inner)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        let now = crate::auth::now_ts();
        let wallet_request = WalletProviderRequestV2::decode_at(&bytes, now)
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
        self.seen
            .lock()
            .unwrap()
            .push(wallet_request.request_id.clone());
        let approved = self
            .approved
            .lock()
            .unwrap()
            .contains(&wallet_request.request_id);
        let approval_request = json!({
            "schema": "elastos.wallet.approval_request/v1",
            "request_id": wallet_request.request_id,
            "intent": "protected_content_rights_signature",
            "status": if approved { "completed" } else { "pending" },
        });
        let data = if approved {
            let (account_id, canonical_rights_request_hex) = match &wallet_request.operation {
                WalletProviderOperationV2::RequestProtectedContentRightsSignature {
                    account_id,
                    canonical_rights_request_hex,
                    ..
                } => (account_id.clone(), canonical_rights_request_hex.clone()),
                _ => {
                    return Err(ProviderError::Provider(
                        "managed release wallet expected a protected-content rights signature"
                            .to_string(),
                    ));
                }
            };
            let rights_bytes = hex::decode(&canonical_rights_request_hex)
                .map_err(|error| ProviderError::Provider(error.to_string()))?;
            let rights_request = RightsRequestV1::from_canonical_bytes(&rights_bytes)
                .map_err(|error| ProviderError::Provider(error.to_string()))?;
            let key = WalletSigningKey::from_slice(&[7; 32])
                .map_err(|error| ProviderError::Provider(error.to_string()))?;
            let (signature, recovery_id) = key
                .sign_prehash_recoverable(&elastos_auth::ethereum_signed_message_hash(
                    &rights_bytes,
                ))
                .map_err(|error| ProviderError::Provider(error.to_string()))?;
            let mut signature_bytes = signature.to_bytes().to_vec();
            signature_bytes.push(recovery_id.to_byte());
            let signed = WalletSignedRightsRequestV1::new(rights_request, signature_bytes)
                .map_err(|error| ProviderError::Provider(error.to_string()))?;
            let result = ProtectedContentRightsSignatureResultV1::new(
                account_id,
                wallet_address_hex(wallet(7)),
                hex::encode(signed.canonical_bytes().unwrap()),
            )
            .map_err(|error| ProviderError::Provider(error.to_string()))?;
            json!({
                "approval_request": approval_request,
                "requires_approval": false,
                "signature": Value::Null,
                "signed_result": serde_json::to_value(result)
                    .map_err(|error| ProviderError::Provider(error.to_string()))?,
                "signature_receipt": { "request_id": wallet_request.request_id },
            })
        } else {
            json!({
                "approval_request": approval_request,
                "requires_approval": true,
                "signature": Value::Null,
            })
        };
        let wallet_response =
            WalletProviderResponseV2::for_request(&wallet_request, WalletResultV2::Ok { data });
        Ok(ok_provider_response(
            serde_json::to_value(wallet_response)
                .map_err(|error| ProviderError::Provider(error.to_string()))?,
        ))
    }
}

#[cfg(unix)]
pub(crate) fn write_device_key(data_dir: &Path, seed: u8) {
    let identity = data_dir.join("identity");
    fs::create_dir_all(&identity).unwrap();
    let path = identity.join("device.key");
    fs::write(&path, [seed; 32]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(unix)]
pub(super) fn derived_device_key_for_seed(seed: u8) -> (SigningKey, String) {
    elastos_identity::derive_did(&[seed; 32])
}

#[cfg(unix)]
pub(super) fn derived_device_runtime_issuer(seed: u8) -> RuntimeOperationIssuerKeyV1 {
    let (key, _) = derived_device_key_for_seed(seed);
    RuntimeOperationIssuerKeyV1::new(key.verifying_key().to_bytes()).unwrap()
}

pub(super) fn signed_release_wallet_outcome(
    outcome: super::super::RuntimeReleaseWalletOutcome,
) -> (Vec<u8>, Vec<u8>, WalletSignedRightsRequestV1) {
    match outcome {
        super::super::RuntimeReleaseWalletOutcome::Signed {
            request_bytes,
            response_bytes,
            signed_rights,
        } => (request_bytes, response_bytes, *signed_rights),
        super::super::RuntimeReleaseWalletOutcome::PendingApproval {
            approval_request_id,
            ..
        } => panic!("release wallet unexpectedly pending approval {approval_request_id}"),
    }
}

#[cfg(unix)]
pub(super) fn process_custody_play_routes(
    epoch: &SignedCustodyEpochV1,
    owner_state_roots: [Digest32; 3],
) -> Vec<RuntimeCustodyRouteBindingConfig> {
    epoch
        .statement()
        .nodes()
        .iter()
        .zip(owner_state_roots)
        .zip([
            RuntimeCustodyRouteTransportConfig::Local,
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                peer_did: peer_did_for_seed(0xa1),
            },
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                peer_did: peer_did_for_seed(0xa2),
            },
        ])
        .map(
            |((node, owner_state_root), transport)| RuntimeCustodyRouteBindingConfig {
                node_public_key_base64: raw_b64_32(*node.node_public_key().as_bytes()),
                owner_state_root_base64: raw_b64_32(*owner_state_root.as_bytes()),
                transport,
            },
        )
        .collect()
}

#[cfg(unix)]
pub(super) async fn register_test_decrypt_provider(
    registry: &Arc<ProviderRegistry>,
    runtime_operation_issuer: RuntimeOperationIssuerKeyV1,
) {
    let decrypt_binary = required_test_binary_path(TEST_DECRYPT_PROVIDER_BIN_ENV);
    register_protected_content_decrypt_provider(
        registry,
        &decrypt_binary,
        runtime_operation_issuer,
    )
    .await
    .unwrap();
}

#[cfg(unix)]
pub(crate) struct RuntimeCustodyProcessProviderFixture {
    pub(super) _nodes_temp: tempfile::TempDir,
    pub(super) nodes: Vec<(NodePublicKey, Arc<ProviderRegistry>)>,
    pub(super) composition: RuntimeCustodyCompositionConfigFile,
}

#[cfg(unix)]
pub(crate) fn runtime_custody_gateway_media_output_for_test() -> (Vec<u8>, Vec<Vec<u8>>) {
    clear_media_components(0x61)
}

#[cfg(unix)]
pub(crate) async fn register_runtime_custody_process_providers_for_test_registry(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
) -> RuntimeCustodyProcessProviderFixture {
    let protect_binary = required_test_binary_path(TEST_PROTECT_PROVIDER_BIN_ENV);
    let custody_binary = required_test_binary_path(TEST_CUSTODY_PROVIDER_BIN_ENV);
    let nodes_temp = tempfile::tempdir().unwrap();
    let nodes_root = fs::canonicalize(nodes_temp.path()).unwrap();
    owner_only_dir(data_dir);
    let (runtime_device_key, _) = elastos_identity::load_or_create_did(data_dir).unwrap();
    let runtime_issuer =
        RuntimeOperationIssuerKeyV1::new(runtime_device_key.verifying_key().to_bytes()).unwrap();
    let node1 = provisioned_process_custody_node_for_issuer(
        &custody_binary,
        &nodes_root,
        "node-1",
        runtime_issuer,
        digest(0xa1),
    );
    let node2 = provisioned_process_custody_node_for_issuer(
        &custody_binary,
        &nodes_root,
        "node-2",
        runtime_issuer,
        digest(0xa2),
    );
    let node3 = provisioned_process_custody_node_for_issuer(
        &custody_binary,
        &nodes_root,
        "node-3",
        runtime_issuer,
        digest(0xa3),
    );
    for fixture in [&node1, &node2, &node3] {
        fixture
            .registry
            .register_sub_provider(
                CHAIN_PROVIDER_ID,
                Arc::new(AllowingProcessChainEvidenceProvider),
            )
            .await
            .unwrap();
    }
    register_inactive_custody_provider(
        &node1.registry,
        &custody_binary,
        &nodes_root.join("node-1"),
    )
    .await
    .unwrap();
    register_inactive_custody_provider(
        &node2.registry,
        &custody_binary,
        &nodes_root.join("node-2"),
    )
    .await
    .unwrap();
    register_inactive_custody_provider(
        &node3.registry,
        &custody_binary,
        &nodes_root.join("node-3"),
    )
    .await
    .unwrap();

    let epoch = signed_custody_epoch_for_node_keys([
        (
            node1.provisioned.node_public_key,
            node1.provisioned.node_custody_public_key,
        ),
        (
            node2.provisioned.node_public_key,
            node2.provisioned.node_custody_public_key,
        ),
        (
            node3.provisioned.node_public_key,
            node3.provisioned.node_custody_public_key,
        ),
    ]);
    let fixtures_by_node = BTreeMap::from([
        (node1.provisioned.node_public_key, node1),
        (node2.provisioned.node_public_key, node2),
        (node3.provisioned.node_public_key, node3),
    ]);
    let ordered_fixtures = epoch
        .statement()
        .nodes()
        .iter()
        .map(|node| fixtures_by_node.get(&node.node_public_key()).unwrap())
        .collect::<Vec<_>>();
    let owner_state_roots = [
        ordered_fixtures[0].owner_state_root,
        ordered_fixtures[1].owner_state_root,
        ordered_fixtures[2].owner_state_root,
    ];
    let now = crate::auth::now_ts();
    let pool = signed_custody_pool_for_epoch(&epoch, (now.saturating_sub(60), now + 3_600));
    let authorization =
        signed_committee_authorization_for_epoch(pool.pool_identity().unwrap(), &epoch);
    let composition = RuntimeCustodyCompositionConfigFile {
        schema: CUSTODY_COMPOSITION_SCHEMA_V1.to_string(),
        expected_policy_authority_base64: raw_b64_32(
            SigningKey::from_bytes(&[0x71; 32])
                .verifying_key()
                .to_bytes(),
        ),
        expected_committee_authorization_identity_base64: canonical_b64(
            &authorization.authorization_identity().unwrap(),
        ),
        signed_pool_base64: canonical_b64(&pool),
        signed_epoch_base64: canonical_b64(&epoch),
        signed_committee_authorization_base64: canonical_b64(&authorization),
        routes: process_custody_play_routes(&epoch, owner_state_roots),
    };
    write_owner_only_custody_composition_config(data_dir, &composition);
    let nodes = ordered_fixtures
        .iter()
        .map(|fixture| {
            (
                fixture.provisioned.node_public_key,
                fixture.registry.clone(),
            )
        })
        .collect::<Vec<_>>();

    register_protect_provider(registry, &protect_binary)
        .await
        .unwrap();
    registry
        .register_runtime_provider_target(
            CUSTODY_PROVIDER_ID,
            Arc::new(LibraryProcessCustodyDispatcher {
                expected_issuer: runtime_issuer,
                nodes: nodes.clone(),
            }),
        )
        .await
        .unwrap();
    registry
        .set_carrier_invoker(Arc::new(LoopbackCustodyCarrierInvoker {
            registry: Arc::downgrade(registry),
        }))
        .await;
    register_test_decrypt_provider(registry, runtime_issuer).await;
    RuntimeCustodyProcessProviderFixture {
        _nodes_temp: nodes_temp,
        nodes,
        composition,
    }
}

#[cfg(unix)]
pub(crate) async fn attach_runtime_custody_process_providers_for_buyer_runtime(
    fixture: &RuntimeCustodyProcessProviderFixture,
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
) {
    owner_only_dir(data_dir);
    write_owner_only_custody_composition_config(data_dir, &fixture.composition);
    let (runtime_device_key, _) = elastos_identity::load_or_create_did(data_dir).unwrap();
    let runtime_issuer =
        RuntimeOperationIssuerKeyV1::new(runtime_device_key.verifying_key().to_bytes()).unwrap();
    registry
        .register_runtime_provider_target(
            CUSTODY_PROVIDER_ID,
            Arc::new(LibraryProcessCustodyDispatcher {
                expected_issuer: runtime_issuer,
                nodes: fixture.nodes.clone(),
            }),
        )
        .await
        .unwrap();
    registry
        .set_carrier_invoker(Arc::new(LoopbackCustodyCarrierInvoker {
            registry: Arc::downgrade(registry),
        }))
        .await;
    register_test_decrypt_provider(registry, runtime_issuer).await;
}

#[cfg(unix)]
pub(crate) fn assert_no_unresolved_runtime_custody_release_for_test(data_dir: &Path) {
    let release_root = data_dir.join("protected-content/runtime-release");
    assert!(list_unresolved_runtime_releases(&release_root)
        .unwrap()
        .is_empty());
    assert!(unresolved_release_audit_records(&release_root)
        .unwrap()
        .is_empty());
}

#[cfg(unix)]
pub(crate) async fn register_runtime_custody_mock_media_provider_for_test_registry(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
) {
    let provider_root = data_dir.join("protected-content/media-provider");
    owner_only_dir(&provider_root);
    let staging_root = provider_root.join("staging");
    owner_only_dir(&staging_root);
    registry
        .register_runtime_provider_target(
            MEDIA_PROVIDER_ID,
            Arc::new(TestMediaPreparationProvider {
                staging_root,
                requests: Mutex::new(Vec::new()),
                response: TestMediaPreparationResponse::Prepared,
            }),
        )
        .await
        .unwrap();
}

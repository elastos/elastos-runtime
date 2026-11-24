use super::*;

pub(super) const TEST_VIEWER_LAUNCH_ID: &str = "launch:11111111111111111111111111111111";

pub(super) const TEST_VIEWER_LAUNCH_ID_B: &str = "launch:22222222222222222222222222222222";

/// Every existing test in this file exercises the media/player viewer path;
/// session binding v3 takes the verified executable actor as an explicit
/// parameter instead of a hard-coded constant, so these tests supply the same
/// value the real player launch context would carry.
pub(super) const TEST_VIEWER_EXECUTABLE_ACTOR: &str = "elacity-player";

/// The second viewer capsule session binding v3 admits. Used to prove the
/// kind <-> viewer check denies it on a media mint.
pub(super) const TEST_VIEWER_READER_EXECUTABLE_ACTOR: &str = "elacity-reader";

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

/// One rendition a test media provider prepares: what it declares and how many
/// segments it writes. A test declares a wrong pair on purpose to see it refused.
#[cfg(unix)]
#[derive(Clone, Copy)]
pub(super) struct TestPreparedRendition {
    pub(super) kind: CencDashRenditionKindV2,
    pub(super) mime_type: &'static str,
    pub(super) codecs: &'static str,
    pub(super) segments: usize,
}

#[cfg(unix)]
pub(super) const TEST_PREPARED_VIDEO: TestPreparedRendition = TestPreparedRendition {
    kind: media_dash_fixture::V,
    mime_type: "video/mp4",
    codecs: "avc1.640028",
    segments: 2,
};

#[cfg(unix)]
pub(super) const TEST_PREPARED_AUDIO: TestPreparedRendition = TestPreparedRendition {
    kind: media_dash_fixture::A,
    mime_type: "audio/mp4",
    codecs: "mp4a.40.2",
    segments: 2,
};

#[cfg(unix)]
#[derive(Clone, Copy)]
pub(super) enum TestMediaPreparationResponse {
    Prepared(&'static [TestPreparedRendition]),
    SettledFailure,
    UnknownSettlement,
}

#[cfg(unix)]
impl TestMediaPreparationResponse {
    pub(super) const fn prepared_video_audio() -> Self {
        Self::Prepared(&[TEST_PREPARED_VIDEO, TEST_PREPARED_AUDIO])
    }

    pub(super) const fn prepared_video() -> Self {
        Self::Prepared(&[TEST_PREPARED_VIDEO])
    }

    pub(super) const fn prepared_audio() -> Self {
        Self::Prepared(&[TEST_PREPARED_AUDIO])
    }
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
    /// Stamp each receipt when it is issued, as a real availability provider
    /// does, instead of with `checked_at`. For fixtures that run against the
    /// real clock long enough for a fixed stamp to age past the receipt's
    /// freshness window before it is checked.
    pub(super) stamp_at_issue: bool,
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
            stamp_at_issue: false,
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

pub(crate) struct ContentAvailabilityTestProvider {
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
        let mut reply = json!({ "cid": Self::CID });
        if request["include_file_cids"] == true {
            let file_cids: BTreeMap<_, _> = stored
                .iter()
                .map(|(path, bytes)| (path, fixture_raw_cid(bytes)))
                .collect();
            reply["file_cids"] = json!(file_cids);
        }
        *self.files.lock().await = stored;
        *self.manifest.lock().await = Some(manifest);
        Ok(ok_provider_response(reply))
    }

    /// When the receipt being issued says it was checked.
    pub(super) fn receipt_checked_at(&self) -> u64 {
        if self.config.stamp_at_issue {
            crate::auth::now_ts()
        } else {
            self.config.checked_at
        }
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
            checked_at: self.receipt_checked_at(),
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
        if request.get("path").is_none() {
            let cid = request["cid"].as_str().unwrap_or_default();
            let files = self.files.lock().await;
            let bytes = files
                .values()
                .find(|bytes| fixture_raw_cid(bytes) == cid)
                .ok_or_else(|| ProviderError::NotFound("content object CID".into()))?;
            return Ok(ok_provider_response(json!({
                "data": base64::engine::general_purpose::STANDARD.encode(bytes),
            })));
        }
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

    pub(crate) async fn requests(&self) -> Vec<Value> {
        self.requests.lock().await.clone()
    }
}

pub(crate) async fn register_remote_seal_content_fixture(
    registry: &ProviderRegistry,
    signing_key: SigningKey,
) -> Arc<ContentAvailabilityTestProvider> {
    let content = ContentAvailabilityTestProvider::with_signing_key(
        signing_key,
        ContentAvailabilityTestConfig::accepted_now(),
    );
    registry
        .register_sub_provider("content", content.clone())
        .await
        .unwrap();
    content
}

pub(crate) async fn register_remote_seal_provisional_policy_fixture(registry: &ProviderRegistry) {
    registry
        .register_sub_provider(
            CHAIN_PROVIDER_ID,
            Arc::new(RemoteSealProvisionalPolicyFixture),
        )
        .await
        .unwrap();
}

pub(super) struct RemoteSealProvisionalPolicyFixture;

#[async_trait::async_trait]
impl Provider for RemoteSealProvisionalPolicyFixture {
    async fn handle(&self, _: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "policy fixture is invoke-only".into(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![CHAIN_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        "remote-seal-provisional-policy-fixture"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        assert_eq!(
            request["op"],
            super::super::CHAIN_PROTECTED_CONTENT_POLICY_OP
        );
        assert_eq!(request["action"], "view");
        assert!(request.get("expected_item").is_none());
        let content = EncryptedContentIdentityV1::from_canonical_bytes(
            &super::super::decode_0x_hex(request["encrypted_content"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let kid = ContentAccessIdV1::new(
            super::super::decode_0x_hex(request["content_access_id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let policy = policy_body_for(content, kid, RightsActionV1::View);
        Ok(ok_provider_response(json!({
            "schema": CHAIN_PROTECTED_CONTENT_POLICY_SCHEMA_V1,
            "policy_body": format!("0x{}", hex::encode(policy.canonical_bytes().unwrap())),
        })))
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
            Some(elastos_runtime::provider::STAGED_CONTENT_PUBLISH_OP) => {
                // The fixture bills and signs the same manifest as the JSON
                // fixture path. Its input files are small, unlike production.
                let root = Path::new(request["directory"].as_str().unwrap());
                let mut files = Vec::new();
                crate::ipfs::collect_files_for_ipfs(root, root, &mut files).unwrap();
                let mut request = request.clone();
                request["files"] = Value::Array(files.iter().map(|path| {
                    let bytes = std::fs::read(root.join(path)).unwrap();
                    json!({"path": path, "data": base64::engine::general_purpose::STANDARD.encode(bytes)})
                }).collect());
                self.publish(&request).await
            }
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

pub(crate) const MEDIA_MIME_TYPE_V1: &str = "video/mp4";

pub(crate) const MEDIA_CODECS_V1: &str = "avc1.640028,mp4a.40.2";

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

pub(crate) fn media_identity(seed: u8) -> CencFmp4MediaIdentityV1 {
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
        super::super::PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET,
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

/// What a v1 mint used to do after staging, kept only to publish v1 fixtures:
/// publish the directory and verify what was published with the production v1
/// read-side checks (`verify_protected_content_manifest_and_files` and
/// `verify_protected_content_receipt`). New mints write v2; v1 is still read.
pub(super) async fn publish_and_verify_v1_protected_content_for_test(
    registry: &ProviderRegistry,
    protected_content_dir: &Path,
    media_identity: &CencFmp4MediaIdentityV1,
    requirement: &RuntimeContentAvailabilityRequirement,
    now_unix_seconds: impl Fn() -> u64,
) -> anyhow::Result<elastos_protected_content_runtime::RuntimeVerifiedContentAvailability> {
    super::super::validate_protected_content_availability_requirement(requirement)?;
    let publish_requirements = crate::content::ContentPublishRequirements::new(
        requirement.minimum_replicas(),
        super::super::protected_content_live_proof_required(requirement.minimum_replicas()),
    )?
    .with_availability_policy(requirement.policy())?;
    let content_cid = crate::content::publish_directory_via_provider_with_kind_and_requirements(
        registry,
        protected_content_dir,
        super::super::PROTECTED_CONTENT_OBJECT_KIND,
        Some(requirement.expected_object_identity()),
        Some(requirement.expected_publisher_did()),
        publish_requirements,
    )
    .await?;
    let receipt = super::super::fetch_content_availability_receipt(registry, &content_cid).await?;
    let manifest = crate::content::fetch_content_object_manifest(registry, &content_cid).await?;
    super::super::verify_protected_content_manifest_and_files(
        registry,
        &content_cid,
        &manifest,
        media_identity,
    )
    .await?;
    super::super::verify_protected_content_receipt(
        &content_cid,
        &manifest,
        &receipt,
        media_identity,
        requirement,
        now_unix_seconds(),
        super::super::RuntimeManifestPublisherBinding::Exact,
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
    publish_and_verify_v1_protected_content_for_test(
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

/// Persists a creator's listing for `mint_id` whose package names these
/// three CIDs and which was published at `elastos://<listing_cid>`.
#[cfg(unix)]
pub(crate) fn persist_creator_listing_for_test(
    data_dir: &Path,
    publisher_principal_id: &str,
    mint_id: Digest32,
    content_cid: &str,
    metadata_cid: &str,
    listing_cid: &str,
) {
    owner_only_dir(data_dir);
    owner_only_dir(&data_dir.join("protected-content"));
    let mut listing =
        runtime_custody_listing_record_for_test(mint_id, publisher_principal_id, "Film", NOW);
    listing.package.content_cid = content_cid.to_string();
    listing.package.metadata_cid = metadata_cid.to_string();
    listing.package.token_uri = format!("ipfs://{metadata_cid}");
    listing.origin = super::super::RuntimeCustodyListingOrigin::LocalCreator {
        principal_id: publisher_principal_id.to_string(),
        listing_uri: format!("elastos://{listing_cid}"),
        package_sha256: hex::encode(sha2::Sha256::digest(
            serde_json::to_vec(&listing.package).unwrap(),
        )),
    };
    super::super::persist_runtime_custody_listing(data_dir, &listing).unwrap();
}

pub(crate) fn runtime_custody_listing_record_for_test(
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
        media_identity_base64: Some(
            base64::engine::general_purpose::STANDARD
                .encode(draft.media_identity().unwrap().canonical_bytes().unwrap()),
        ),
        content_identity_base64: None,
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
        mint_transaction_hash: Some(format!("0x{}", hex::encode([0x68; 32]))),
        published_at: Some(published_at),
        pool_mint_share_b64: None,
        sealed_rights_policy_base64: None,
        remote_seal: None,
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
            kind: "receipt".to_string(),
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
        super::super::RuntimeCustodyListingOrigin::Asset { .. }
        | super::super::RuntimeCustodyListingOrigin::Granted { .. } => {
            panic!("an adopted listing has no published package to import")
        }
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
        super::super::PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET,
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
        elastos_protected_content_runtime::RuntimeVerifiedContentIdentityRootV1::for_media(
            mint_draft.media_identity().unwrap(),
        ),
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
        acquisition: super::super::RuntimeCustodyAcquisitionV1::Bought,
        capsule_uri: None,
        acquisition_stage: RuntimeCustodyPurchaseStageRecord {
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
                access_evidence: Some(RuntimeCustodyPurchaseAccessEvidenceRecord {
                    schema: "elastos.chain.protected-content-purchase-access/v1".to_string(),
                    request_id: "purchase-access:test".to_string(),
                    network: listing.package.network.clone(),
                    chain_id: 8453,
                    wallet: wallet_address_hex(wallet(7)),
                    content_access_id: Some(listing.package.content_access_id.clone()),
                    ledger: None,
                    token_id: None,
                    has_access: true,
                    finalized_block_number: 44,
                    finalized_block_hash: format!("0x{}", hex::encode([0xad; 32])),
                    finalized_block_timestamp: now,
                    observed_at: now,
                }),
                confirmed_at: now,
                acquired_at: now,
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
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
        TEST_VIEWER_EXECUTABLE_ACTOR,
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
    let (policy, evidence_request) = match authenticated {
        elastos_protected_content_contracts::AuthenticatedRuntimeReleaseOperationAnyV1::V1(
            operation,
        ) => (
            operation.statement().policy_body(),
            operation.statement().evidence_request(),
        ),
        elastos_protected_content_contracts::AuthenticatedRuntimeReleaseOperationAnyV1::V2(
            operation,
        ) => (
            operation.statement().policy_body(),
            operation.statement().evidence_request(),
        ),
    };
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
            super::super::RuntimeCustodyCallDiagnostics::default(),
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
            super::super::RuntimeCustodyCallDiagnostics::default(),
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
        let expected = elastos_protected_content_rights::chain_rights_evidence_request_any(
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
            TestMediaPreparationResponse::Prepared(renditions) => {
                write_prepared_media_v2(
                    &self.staging_root.join(operation_id),
                    &renditions
                        .iter()
                        .map(|rendition| (rendition.kind, rendition.segments))
                        .collect::<Vec<_>>(),
                );
                Ok(ok_provider_response(json!({
                    "schema": "elastos.media-provider.prepared-media/v2",
                    "renditions": renditions.iter().map(|rendition| json!({
                        "rendition": test_rendition_name(rendition.kind),
                        "mime_type": rendition.mime_type,
                        "codecs": rendition.codecs,
                        "segment_count": rendition.segments,
                    })).collect::<Vec<_>>(),
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
pub(super) fn test_rendition_name(kind: CencDashRenditionKindV2) -> &'static str {
    match kind {
        media_dash_fixture::V => "video",
        media_dash_fixture::A => "audio",
    }
}

#[cfg(unix)]
pub(super) fn write_private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// Lays out a media provider's v2 output under `operation_root`:
/// `prepared/<rendition>/init.mp4` and `segments/NNNNNNNN.m4s`, owner-only,
/// from the fixture's contiguous clear media.
#[cfg(unix)]
pub(super) fn write_prepared_media_v2(
    operation_root: &Path,
    renditions: &[(CencDashRenditionKindV2, usize)],
) {
    let prepared_root = operation_root.join("prepared");
    owner_only_dir(&prepared_root);
    for (kind, segments) in renditions {
        let rendition_dir = prepared_root.join(test_rendition_name(*kind));
        owner_only_dir(&rendition_dir);
        write_private_file(
            &rendition_dir.join("init.mp4"),
            &media_dash_fixture::init(*kind, 1),
        );
        let segments_dir = rendition_dir.join("segments");
        owner_only_dir(&segments_dir);
        for (index, segment) in media_dash_fixture::clear_segments(*kind, *segments)
            .iter()
            .enumerate()
        {
            write_private_file(&segments_dir.join(format!("{index:08}.m4s")), segment);
        }
    }
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
pub(crate) fn mint_draft_for_composition_journal_test() -> RuntimeMintDraft {
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
            Self::Custody => {
                // #388 A1: a custody node Home is a WCI-operated host.
                crate::host_trust::seed_for_test(data_dir, true);
                register_custody_provider(registry, binary, data_dir).await
            }
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
    write_mock_custody_provider_with_status(root, &ProtectedStartupProvider::Custody.status())
}

#[cfg(unix)]
pub(super) fn write_mock_custody_provider_with_status(
    root: &Path,
    status: &Value,
) -> (PathBuf, PathBuf, PathBuf) {
    let binary = root.join("mock-custody-provider.sh");
    let request_log = root.join("mock-custody-provider.requests");
    let pid_file = root.join("mock-custody-provider.pid");
    let script = format!(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" >> '{}'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  case \"$line\" in\n    *'\"op\":\"shutdown\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}'; exit 0 ;;\n    *'\"unexpected\"'* ) printf '%s\\n' '{{\"status\":\"error\",\"code\":\"invalid_request\"}}' ;;\n    *'\"op\":\"status\"'*) printf '%s\\n' '{}' ;;\n    *'\"op\":\"release_contribution\"'*) printf '%s\\n' '{{\"status\":\"ok\",\"data\":{{\"echo\":\"custody\"}}}}' ;;\n    *) printf '%s\\n' '{{\"status\":\"ok\",\"data\":{{\"echo\":\"init\"}}}}' ;;\n  esac\ndone\n",
        pid_file.display(),
        request_log.display(),
        status,
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

/// A self-contained, schema-valid purchase record for exercising the
/// purchase-ledger file-discipline path directly, without standing up the
/// full mint/listing/profile harness that `persist_runtime_custody_purchase_for_mint`
/// requires. `load_runtime_custody_purchase`/`persist_runtime_custody_purchase`
/// only check the record's own schema and principal identity, so this fixture
/// does not need to reference a real listing.
pub(super) fn sample_purchase_record() -> (String, Digest32, RuntimeCustodyPurchaseRecord) {
    let principal_id = "person:local:ledger-fixture".to_string();
    let mint_id = Digest32::new([0x77; 32]);
    let record = RuntimeCustodyPurchaseRecord {
        schema: RUNTIME_PURCHASE_SCHEMA_V1.to_string(),
        principal_id: principal_id.clone(),
        profile_did: "did:key:z6MkFixture".to_string(),
        mint_id: hex::encode(mint_id.as_bytes()),
        content_id: "content:fixture".to_string(),
        cid: "bafyfixture".to_string(),
        listing_sha256: format!("sha256:{}", hex::encode([0x11; 32])),
        seller_address: "0x1111111111111111111111111111111111111111".to_string(),
        chain_namespace: "eip155".to_string(),
        network: "esc-mainnet".to_string(),
        ledger: "erc721".to_string(),
        token_id: "1".to_string(),
        operative: "buy".to_string(),
        price: "1000000000000000000".to_string(),
        pay_token: "0x0000000000000000000000000000000000000000".to_string(),
        payment_processor: None,
        availability_receipt_digest: format!("sha256:{}", hex::encode([0x22; 32])),
        account_id: "wallet-account-fixture".to_string(),
        address: wallet_address_hex(wallet(7)),
        approval_stage: None,
        acquisition: super::super::RuntimeCustodyAcquisitionV1::Bought,
        capsule_uri: None,
        acquisition_stage: RuntimeCustodyPurchaseStageRecord {
            stage: "buy".to_string(),
            effect_id: "runtime-effect:11111111111111111111111111111111".to_string(),
            approval_request_id: "wallet-request:11111111111111111111111111111111".to_string(),
            request_sha256: format!("sha256:{}", hex::encode([0x33; 32])),
            chain_namespace: "eip155".to_string(),
            network: "esc-mainnet".to_string(),
            to: "0x2222222222222222222222222222222222222222".to_string(),
            value: "0x1".to_string(),
            data: "0x".to_string(),
        },
        progress: RuntimeCustodyPurchaseProgress::Complete {
            terminal: RuntimeCustodyTerminalPurchaseRecord {
                chain_transaction: format!("0x{}", hex::encode([0xaa; 32])),
                wallet_binding: ValidatedChainOutcomeBindingV1::ManagedSigned {
                    signed_transaction_sha256: format!("sha256:{}", hex::encode([0xab; 32])),
                },
                chain_observation: json!({
                    "schema": "elastos.chain.broadcast_receipt/v1",
                    "network": "esc-mainnet",
                }),
                access_evidence: Some(RuntimeCustodyPurchaseAccessEvidenceRecord {
                    schema: "elastos.chain.protected-content-purchase-access/v1".to_string(),
                    request_id: "purchase-access:fixture".to_string(),
                    network: "esc-mainnet".to_string(),
                    chain_id: 8453,
                    wallet: wallet_address_hex(wallet(7)),
                    content_access_id: Some("content-access:fixture".to_string()),
                    ledger: None,
                    token_id: None,
                    has_access: true,
                    finalized_block_number: 44,
                    finalized_block_hash: format!("0x{}", hex::encode([0xad; 32])),
                    finalized_block_timestamp: 1,
                    observed_at: 1,
                }),
                confirmed_at: 1,
                acquired_at: 1,
            },
        },
        created_at: 1,
        updated_at: 1,
    };
    (principal_id, mint_id, record)
}

pub(super) fn sample_confirmed_purchase_stage() -> RuntimeCustodyConfirmedPurchaseStage {
    RuntimeCustodyConfirmedPurchaseStage {
        chain_transaction: format!("0x{}", hex::encode([0xaa; 32])),
        wallet_binding: ValidatedChainOutcomeBindingV1::ManagedSigned {
            signed_transaction_sha256: format!("sha256:{}", hex::encode([0xab; 32])),
        },
        chain_observation: json!({
            "schema": "elastos.chain.broadcast_receipt/v1",
            "network": "esc-mainnet",
        }),
        confirmed_at: 1,
    }
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
pub(super) fn custody_runtime_envelope(op: &str, transport: &str) -> Value {
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
pub(super) async fn spawn_custody_wrapper_for_test(
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
        // #388 A1: these wrapper tests run as a WCI-operated host.
        host_trusted: true,
        data_dir: std::env::temp_dir(),
    })
}

#[cfg(unix)]
pub(super) fn write_scripted_custody_provider(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let binary = root.join("scripted-custody-provider.sh");
    let request_log = root.join("scripted-custody-provider.requests");
    let prepare_refusal = root.join("scripted-custody-provider.prepare-refusal");
    // `prepare_evidence` is refused with the code written in the refusal
    // file while it exists, and accepted otherwise.
    let script = r#"#!/bin/sh
set -eu
while IFS= read -r line; do
  printf '%s\n' "$line" >> '@LOG@'
  case "$line" in
    *'"op":"shutdown"'*) printf '%s\n' '{"status":"ok"}'; exit 0 ;;
    *'"op":"status"'*) printf '%s\n' '@STATUS@' ;;
    *'"op":"prepare_evidence"'*)
      if [ -e '@REFUSAL@' ]; then
        printf '{"status":"error","code":"%s","message":"refused"}\n' "$(cat '@REFUSAL@')"
      else
        printf '%s\n' '{"status":"ok","data":{"op":"@CHAIN_OP@"}}'
      fi ;;
    *'"op":"settle_evidence"'*) printf '%s\n' '{"status":"ok","data":{"settled":true}}' ;;
    *) printf '%s\n' '{"status":"ok","data":{"echo":"custody"}}' ;;
  esac
done
"#
    .replace("@LOG@", &request_log.display().to_string())
    .replace("@REFUSAL@", &prepare_refusal.display().to_string())
    .replace("@CHAIN_OP@", CHAIN_RIGHTS_EVIDENCE_OP)
    .replace(
        "@STATUS@",
        &ProtectedStartupProvider::Custody.status().to_string(),
    );
    crate::test_support::write_from_child(&binary, &script, 0o700);
    (binary, request_log, prepare_refusal)
}

/// M0R1-F3: the custody wrapper over `data_dir`, as a member Home runs it,
/// over a capsule script that answers a pool share write `ok` after
/// `delay_secs` (a stored share, or an exact retry answered from it).
#[cfg(unix)]
pub(crate) struct PoolShareWrapperForTest {
    pub(super) _temp: tempfile::TempDir,
    pub(super) answer_path: PathBuf,
    pub(super) registry: Arc<ProviderRegistry>,
    pub(super) provider: Arc<InactiveCustodyProvider>,
}

#[cfg(unix)]
impl PoolShareWrapperForTest {
    /// The capsule answers a pool share write with `answer` (its `data`).
    pub(crate) async fn start(data_dir: &Path, delay_secs: u64, answer: &Value) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        owner_only_dir(&state_root);
        let binary = temp.path().join("pool-share-provider.sh");
        let answer_path = temp.path().join("pool-share-answer.json");
        fs::write(
            &answer_path,
            format!("{}\n", json!({ "status": "ok", "data": answer })),
        )
        .unwrap();
        let script = r#"#!/bin/sh
set -eu
while IFS= read -r line; do
  case "$line" in
    *'"op":"shutdown"'*) printf '%s\n' '{"status":"ok"}'; exit 0 ;;
    *'"op":"status"'*) printf '%s\n' '@STATUS@' ;;
    *'"op":"provision_pool_node_share"'*)
      sleep @DELAY@
      cat '@ANSWER@' ;;
    *) printf '%s\n' '{"status":"ok","data":{}}' ;;
  esac
done
"#
        .replace("@DELAY@", &delay_secs.to_string())
        .replace("@ANSWER@", &answer_path.display().to_string())
        .replace(
            "@STATUS@",
            &ProtectedStartupProvider::Custody.status().to_string(),
        );
        crate::test_support::write_from_child(&binary, &script, 0o700);
        let registry = Arc::new(ProviderRegistry::new());
        let bridge = ProviderBridge::spawn(
            &binary,
            ProviderConfig {
                base_path: state_root.to_str().unwrap().to_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let provider = Arc::new(InactiveCustodyProvider::new(InactiveCustodyProviderParts {
            bridge: Arc::new(bridge),
            registry: Arc::downgrade(&registry),
            host_trusted: true,
            data_dir: data_dir.to_path_buf(),
        }));
        registry
            .register_runtime_provider_target(CUSTODY_PROVIDER_ID, provider.clone())
            .await
            .unwrap();
        Self {
            _temp: temp,
            answer_path,
            registry,
            provider,
        }
    }

    /// The capsule answers the next pool share writes with `answer`.
    pub(crate) fn answer_with(&self, answer: &Value) {
        fs::write(
            &self.answer_path,
            format!("{}\n", json!({ "status": "ok", "data": answer })),
        )
        .unwrap();
    }

    /// The pool share write as the mint coordinator makes it
    /// (`mint.rs` `provision_pool_node`): through the registry adapter
    /// that is its `RuntimeCustodyProvider`, classified as the coordinator
    /// sees it.
    pub(crate) async fn provision_as_the_coordinator(
        &self,
        request: &elastos_protected_content_provider_contracts::PoolCustodyRequestV1,
    ) -> Result<
        elastos_protected_content_provider_contracts::PoolCustodyResponseV1,
        elastos_protected_content_runtime::RuntimeProviderCallError,
    > {
        use elastos_protected_content_runtime::RuntimeCustodyProvider as _;
        RuntimeCustodyRegistryAdapter::new(
            Arc::clone(&self.registry),
            ProviderInvocationTransport::Local,
            super::super::RuntimeCustodyCallDiagnostics::default(),
        )
        .provision_pool_node_share(request)
        .await
    }

    /// A pool share write over Carrier, as a minting Home sends it.
    pub(crate) async fn provision(&self, request: Value) -> Result<Value, ProviderError> {
        let mut request = request;
        request["_runtime_invocation"] = custody_carrier_envelope(
            crate::custody_surface::OP_CUSTODY_PROVISION_POOL_NODE_SHARE,
            0x52,
        );
        self.provider.send_raw(&request).await
    }
}

#[cfg(unix)]
pub(super) struct ScriptedCustodyWrapper {
    pub(super) _temp: tempfile::TempDir,
    pub(super) _registry: Arc<ProviderRegistry>,
    pub(super) provider: InactiveCustodyProvider,
    pub(super) chain: Arc<RecordingProvider>,
    pub(super) request_log: PathBuf,
    pub(super) prepare_refusal: PathBuf,
}

#[cfg(unix)]
impl ScriptedCustodyWrapper {
    /// A wrapper over the scripted capsule, with a counting fake chain
    /// provider in a registry that stays alive for the test.
    pub(super) async fn start() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        owner_only_dir(&data_dir);
        let state_root = inactive_custody_state_root(&data_dir);
        owner_only_dir(&state_root);
        let (binary, request_log, prepare_refusal) = write_scripted_custody_provider(temp.path());
        let registry = Arc::new(ProviderRegistry::new());
        let chain = RecordingProvider::new(
            CHAIN_PROVIDER_ID,
            ok_provider_response(json!({"evidence": "fake"})),
        );
        registry
            .register_sub_provider(CHAIN_PROVIDER_ID, chain.clone())
            .await
            .unwrap();
        let bridge = ProviderBridge::spawn(
            &binary,
            ProviderConfig {
                base_path: state_root.to_str().unwrap().to_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let provider = InactiveCustodyProvider::new(InactiveCustodyProviderParts {
            bridge: Arc::new(bridge),
            registry: Arc::downgrade(&registry),
            host_trusted: true,
            data_dir: temp.path().to_path_buf(),
        });
        Self {
            _temp: temp,
            _registry: registry,
            provider,
            chain,
            request_log,
            prepare_refusal,
        }
    }

    pub(super) fn refuse_prepare(&self, code: &str) {
        fs::write(&self.prepare_refusal, code).unwrap();
    }

    pub(super) fn accept_prepare(&self) {
        fs::remove_file(&self.prepare_refusal).unwrap();
    }

    /// The frames the wrapper forwarded to the capsule after start-up.
    pub(super) fn forwarded(&self) -> Vec<Value> {
        fs::read_to_string(&self.request_log)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|frame| !matches!(frame["op"].as_str(), Some("init" | "status")))
            .collect()
    }

    pub(super) fn forwarded_count(&self, op: &str) -> usize {
        self.forwarded()
            .iter()
            .filter(|frame| frame["op"] == op)
            .count()
    }

    pub(super) async fn chain_reads(&self) -> usize {
        self.chain.requests().await.len()
    }

    pub(super) async fn send(
        &self,
        request: Value,
        envelope: Value,
    ) -> Result<Value, ProviderError> {
        let mut request = request;
        request["_runtime_invocation"] = envelope;
        self.provider.send_raw(&request).await
    }
}

#[cfg(unix)]
pub(super) fn custody_local_envelope(op: &str) -> Value {
    custody_runtime_envelope(op, "runtime-local-provider-plane")
}

#[cfg(unix)]
pub(super) fn custody_carrier_envelope(op: &str, endpoint_seed: u8) -> Value {
    let mut envelope = custody_runtime_envelope(op, "carrier-provider-plane");
    envelope["carrier"] = json!({
        "source_endpoint_did": crate::carrier::public_key_to_did(
            &iroh::SecretKey::from_bytes(&[endpoint_seed; 32]).public(),
        )
        .unwrap(),
    });
    envelope
}

/// One evaluate request carrying a V2 pool operation from the shared
/// contracts fixture, asking the fixture pool's node 1.
#[cfg(unix)]
pub(super) fn custody_v2_evaluate_request() -> Value {
    use elastos_protected_content_contracts::test_fixtures::{
        node_public_key as pool_node_public_key, pool_release_fixture, PoolReleaseSpecV1,
    };
    let fixture = pool_release_fixture(&PoolReleaseSpecV1::new(
        xwing_public_key_bytes,
        policy_body(),
        crate::auth::now_ts(),
    ));
    let request = RightsProviderRequestV1::new_evaluate_any(
        pool_node_public_key(1),
        &elastos_protected_content_contracts::RuntimeReleaseOperationAnyV1::V2(fixture.operation),
    )
    .unwrap();
    serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap()
}

/// One wallet-signed evaluate request (one wallet, one item).
#[cfg(unix)]
pub(super) fn custody_evaluate_request() -> Value {
    let envelope = custody_envelope_for_media(0x11);
    let operation = make_signed_runtime_release_operation_for_envelope_and_seed(0x21, &envelope);
    let request = RightsProviderRequestV1::new_evaluate(node_public_key(1), &operation).unwrap();
    serde_json::from_slice(&request.to_json_vec().unwrap()).unwrap()
}

#[cfg(unix)]
pub(super) fn assert_rate_limited(response: &Value) {
    assert_eq!(response["status"], "error", "{response}");
    assert_eq!(response["code"], "rate_limited", "{response}");
}

#[cfg(unix)]
pub(super) fn endpoint_budget() -> usize {
    crate::custody_release_limits::CUSTODY_NODE_SETTINGS.releases_per_endpoint_per_minute as usize
}

#[cfg(unix)]
pub(super) fn wallet_budget() -> usize {
    crate::custody_release_limits::CUSTODY_NODE_SETTINGS.releases_per_wallet_per_minute as usize
}

/// Plan B POOL-MINT (PM-F2): a WCI-operated custody host whose real provider
/// serves its inactive root behind a script that records the provider's pid,
/// so a test can pause the provider after a share write is dispatched.
#[cfg(unix)]
pub(super) struct HostShareWriteFixture {
    pub(super) _temp: tempfile::TempDir,
    pub(super) data_dir: PathBuf,
    pub(super) provider: Arc<InactiveCustodyProvider>,
    pub(super) pid_file: PathBuf,
    pub(super) node_public_key: NodePublicKey,
    pub(super) custody_epoch: SignedCustodyEpochV1,
}

#[cfg(unix)]
impl HostShareWriteFixture {
    pub(super) async fn start(max_storage_bytes: Option<u64>) -> Self {
        let binary = required_test_binary_path(TEST_CUSTODY_PROVIDER_BIN_ENV);
        let temp = tempfile::tempdir().unwrap();
        let temp_root = fs::canonicalize(temp.path()).unwrap();
        let data_dir = temp_root.join("data");
        owner_only_dir(&data_dir);
        crate::host_trust::write_host_trust(
            &data_dir,
            crate::host_trust::HostTrustModeV1::WciOperated,
            max_storage_bytes,
        )
        .unwrap();
        let state_root = inactive_custody_state_root(&data_dir);
        owner_only_dir(state_root.parent().unwrap());
        let provisioned = provision_custody_node_public_receipt(&binary, &state_root, 0x21);
        let wrapper = temp_root.join("custody-provider.sh");
        let pid_file = temp_root.join("custody-provider.pid");
        crate::test_support::write_from_child(
            &wrapper,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$$\" > '{}'\nexec '{}' \"$@\"\n",
                pid_file.display(),
                binary.display(),
            ),
            0o700,
        );
        let bridge = ProviderBridge::spawn(
            &wrapper,
            super::super::custody_provider_roots_config(&data_dir).unwrap(),
        )
        .await
        .unwrap();
        let provider = Arc::new(InactiveCustodyProvider::new(InactiveCustodyProviderParts {
            bridge: Arc::new(bridge),
            registry: Arc::downgrade(&Arc::new(ProviderRegistry::new())),
            host_trusted: true,
            data_dir: data_dir.clone(),
        }));
        Self {
            _temp: temp,
            data_dir,
            provider,
            pid_file,
            node_public_key: provisioned.node_public_key,
            custody_epoch: signed_custody_epoch_with_first_node(
                provisioned.node_public_key,
                provisioned.node_custody_public_key,
            ),
        }
    }

    pub(super) fn set_storage_maximum(&self, max_storage_bytes: Option<u64>) {
        crate::host_trust::write_host_trust(
            &self.data_dir,
            crate::host_trust::HostTrustModeV1::WciOperated,
            max_storage_bytes,
        )
        .unwrap();
    }

    /// A Runtime-local V1 share write for the media of `seed`.
    pub(super) fn v1_share_request(&self, seed: u8) -> Value {
        let now = crate::auth::now_ts();
        let envelope =
            provisioned_custody_envelope_for_media_with_epoch(seed, &self.custody_epoch, now);
        let record = provisioning_record_for_selected_node(&envelope, self.node_public_key);
        let provisioning = signed_runtime_custody_provisioning_at(&record, 0x21, now);
        let mut request: Value = serde_json::from_slice(
            &CustodyProviderRequestV1::new_provision_node_share(&record, &provisioning)
                .unwrap()
                .to_json_vec()
                .unwrap(),
        )
        .unwrap();
        request["_runtime_invocation"] =
            custody_runtime_envelope("provision_node_share", "runtime-local-provider-plane");
        request
    }

    /// What the wrapper charges a write: its frame without the envelope.
    pub(super) fn charged_bytes(request: &Value) -> u64 {
        let mut frame = request.clone();
        frame.as_object_mut().unwrap().remove("_runtime_invocation");
        u64::try_from(serde_json::to_vec(&frame).unwrap().len()).unwrap()
    }

    pub(super) fn used_bytes(&self) -> u64 {
        super::super::host_custody_storage_bytes(&self.data_dir).unwrap()
    }

    pub(super) fn signal_provider(&self, signal: nix::sys::signal::Signal) {
        let pid: i32 = fs::read_to_string(&self.pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), signal).unwrap();
    }
}

#[cfg(unix)]
pub(super) fn media_preparation_source_input(
    root: &Path,
    principal_id: &str,
) -> RuntimeCustodyLibrarySourceInput {
    RuntimeCustodyLibrarySourceInput {
        listing: None,
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
        price: "5".to_string(),
        channel: "0x0000000000000000000000000000000000000022".to_string(),
        pay_token: String::new(),
        source_storage: "protected_principal_root".to_string(),
        pool_did: None,
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

/// A v2 publish input over a prepared video + audio tree that
/// the REAL loader validated: the files are laid out under the data directory's
/// media-provider staging root, one operation directory per principal, and a
/// second call for the same principal loads the same files again.
#[cfg(unix)]
pub(crate) fn library_publish_test_input(
    data_dir: &Path,
    principal_id: &str,
) -> RuntimeCustodyLibraryPublishInput {
    library_publish_test_input_with_renditions(
        data_dir,
        principal_id,
        &[
            (TEST_PREPARED_VIDEO.kind, TEST_PREPARED_VIDEO.segments),
            (TEST_PREPARED_AUDIO.kind, TEST_PREPARED_AUDIO.segments),
        ],
    )
}

#[cfg(unix)]
pub(crate) fn library_publish_test_input_with_renditions(
    data_dir: &Path,
    principal_id: &str,
    renditions: &[(CencDashRenditionKindV2, usize)],
) -> RuntimeCustodyLibraryPublishInput {
    let operation_root = runtime_media_staging_root(data_dir)
        .join(hex::encode(sha2::Sha256::digest(principal_id.as_bytes())));
    if !operation_root.exists() {
        owner_only_dir(&protected_content_root(data_dir));
        owner_only_dir(&protected_content_root(data_dir).join("media-provider"));
        owner_only_dir(&runtime_media_staging_root(data_dir));
        owner_only_dir(&operation_root);
        write_prepared_media_v2(&operation_root, renditions);
    }
    RuntimeCustodyLibraryPublishInput {
        listing: None,
        object_uri: "localhost://Users/test/Documents/media".to_string(),
        principal_id: principal_id.to_string(),
        wallet_account_id: "wallet-account-1".to_string(),
        wallet_account_address: "0x1111111111111111111111111111111111111111".to_string(),
        creator_mint_source_digest: digest(0x71),
        copies: "0x1".to_string(),
        price: "5".to_string(),
        channel: "0x0000000000000000000000000000000000000022".to_string(),
        pay_token: String::new(),
        media: load_runtime_prepared_media_v2(&operation_root, None).unwrap(),
        source_storage: "plain_localhost_root".to_string(),
        pool_did: None,
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
    let (_, now) = write_library_publish_test_composition(data_dir);
    library_publish_node_bindings_at(data_dir, now)
}

#[cfg(unix)]
pub(super) fn library_publish_node_bindings_at(
    data_dir: &Path,
    now: u64,
) -> (
    Vec<RuntimeMintNodeBinding>,
    CustodyPoolIdentityV1,
    elastos_protected_content_contracts::CustodyEpochIdentityV1,
    CustodyCommitteeAuthorizationIdentityV1,
) {
    let bytes = fs::read(custody_composition_config_path(data_dir)).unwrap();
    let check = super::super::MintCompositionCheck::Provision;
    let config = super::super::parse_runtime_custody_composition_config(bytes, now, check).unwrap();
    let (composition, _) = super::super::build_runtime_custody_composition(
        config,
        Arc::new(ProviderRegistry::new()),
        now,
        check,
    )
    .unwrap();
    let configured = composition.configured_nodes().unwrap();
    let selected = resolve_runtime_mint_selected_nodes(
        composition.expected_policy_authority,
        composition.expected_authorization_identity,
        &composition.signed_pool,
        &composition.signed_epoch,
        &composition.signed_committee_authorization,
        now,
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

/// A prepared media that only DECLARES its layout (video and audio, two
/// segments each) and a receipt derived from `seed`, with nothing on disk. For
/// tests that seed a journal record and never run the mint over these files.
pub(crate) fn declared_prepared_media_for_test(seed: u8) -> super::super::RuntimePreparedMediaV2 {
    super::super::RuntimePreparedMediaV2 {
        operation_root: PathBuf::new(),
        renditions: [DASH_VIDEO, DASH_AUDIO]
            .into_iter()
            .map(|kind| super::super::RuntimePreparedRenditionV2 {
                kind,
                clear_init_segment: Vec::new(),
                timescale: 15360,
                segment_count: 2,
                segment_parts: Vec::new(),
            })
            .collect(),
        preparation_receipt: digest(seed),
        clear_bytes: 0,
        part_reads: Arc::default(),
    }
}

/// The rendition kinds and segment counts a publish input declares.
#[cfg(unix)]
pub(super) fn test_input_layout(
    input: &RuntimeCustodyLibraryPublishInput,
) -> (Vec<CencDashRenditionKindV2>, Vec<usize>) {
    input
        .media
        .renditions
        .iter()
        .map(|rendition| (rendition.kind, rendition.segment_count as usize))
        .unzip()
}

/// A protected package of the same layout as `input` (a fixture head and
/// ciphertext, not tied to the input's own bytes), for tests that seed a mint
/// record rather than run the protect.
#[cfg(unix)]
pub(super) fn protected_dash_components_for_input(
    input: &RuntimeCustodyLibraryPublishInput,
) -> media_dash_fixture::MediaDashComponents {
    let (kinds, counts) = test_input_layout(input);
    media_dash_components(&kinds, &counts)
}

/// The v2 mint intent the production path would persist for `input`, bound to
/// `draft`'s access id and committee.
#[cfg(unix)]
pub(super) fn test_media_dash_intent(
    input: &RuntimeCustodyLibraryPublishInput,
    draft: &RuntimeMintDraft,
    nodes: Vec<RuntimeMintNodeBinding>,
) -> RuntimeMintIntent {
    RuntimeMintIntent::new_media_dash(
        input.principal_id.clone(),
        &input.object_uri,
        &input.source_storage,
        input.wallet_account_id.clone(),
        input.wallet_account_address.clone(),
        input.creator_mint_source_digest,
        input.media.preparation_receipt(),
        input
            .media
            .renditions
            .iter()
            .map(
                |rendition| elastos_protected_content_runtime::RuntimeMintIntentRenditionV2 {
                    kind: rendition.kind,
                    segment_count: rendition.segment_count,
                },
            )
            .collect(),
        draft.content_access_id(),
        draft.pool(),
        draft.epoch(),
        draft.committee(),
        nodes,
    )
    .unwrap()
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
    let (_, now) = write_library_publish_test_composition(data_dir);
    seed_settled_runtime_custody_mint_record_at(data_dir, input, complete, now)
}

#[cfg(unix)]
pub(super) fn seed_settled_runtime_custody_mint_record_at(
    data_dir: &Path,
    input: &RuntimeCustodyLibraryPublishInput,
    complete: bool,
    now: u64,
) -> Digest32 {
    let (node_bindings, pool_identity, epoch_identity, committee_identity) =
        library_publish_node_bindings_at(data_dir, now);
    let journal = runtime_mint_journal(data_dir);
    let components = protected_dash_components_for_input(input);
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
        components.head.encrypted_content().clone(),
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
    let draft = RuntimeMintDraft::new_from_identity(
        RuntimeContentIdentityV1::MediaDash(components.head.clone()),
        components.head.default_kid(),
        key_envelope,
        policy,
        digest(0x61),
        threshold,
        node_bindings.clone(),
    )
    .unwrap();
    let intent = test_media_dash_intent(input, &draft, node_bindings.clone());
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
        elastos_protected_content_runtime::RuntimeVerifiedContentIdentityRootV1::for_media_dash(
            draft.media_dash_identity().unwrap(),
        ),
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
pub(super) fn pre_dispatch_retry_publish_input(
    data_dir: &Path,
) -> RuntimeCustodyLibraryPublishInput {
    let principal_id = "person:local:runtime-custody-pre-dispatch-retry";
    let mut input = library_publish_test_input(data_dir, principal_id);
    input.object_uri = format!(
        "{}/Documents/media",
        crate::auth::principal_localhost_root(principal_id)
    );
    input
}

/// A protect provider that answers from a script, and records what the mint
/// asked of it and how many clear parts the Runtime had read from disk at each
/// `protect_media_segment`, so a test can show a part is read, protected and
/// dropped before the next is read.
#[cfg(unix)]
pub(super) struct MediaDashProtectTestProvider {
    pub(super) responses: Mutex<VecDeque<Result<Value, ProviderError>>>,
    pub(super) requests: Mutex<Vec<Value>>,
    pub(super) part_reads: Option<Arc<std::sync::atomic::AtomicUsize>>,
    pub(super) reads_at_segment_requests: Mutex<Vec<usize>>,
}

#[cfg(unix)]
impl MediaDashProtectTestProvider {
    pub(super) fn new(
        responses: Vec<Result<Value, ProviderError>>,
        part_reads: Option<Arc<std::sync::atomic::AtomicUsize>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
            part_reads,
            reads_at_segment_requests: Mutex::new(Vec::new()),
        })
    }

    pub(super) async fn requests(&self) -> Vec<Value> {
        self.requests.lock().await.clone()
    }

    pub(super) async fn reads_at_segment_requests(&self) -> Vec<usize> {
        self.reads_at_segment_requests.lock().await.clone()
    }
}

#[cfg(unix)]
#[async_trait::async_trait]
impl Provider for MediaDashProtectTestProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "media dash protect test provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![PROTECT_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        PROTECT_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.requests.lock().await.push(request.clone());
        if request["op"] == "protect_media_segment" {
            if let Some(part_reads) = &self.part_reads {
                self.reads_at_segment_requests
                    .lock()
                    .await
                    .push(part_reads.load(std::sync::atomic::Ordering::SeqCst));
            }
        }
        self.responses.lock().await.pop_front().unwrap_or_else(|| {
            Err(ProviderError::Provider(
                "media dash protect test provider script is exhausted".to_string(),
            ))
        })
    }
}

/// The protected package a protect provider honest about `input` would return
/// for `mint_intent`: every init rewritten under the intent's own header
/// (then handed to `steer_init`), every segment protected, the head over it,
/// and a key envelope for its ciphertext.
#[cfg(unix)]
pub(super) fn protect_input_for_test(
    input: &RuntimeCustodyLibraryPublishInput,
    mint_intent: &RuntimeMintIntent,
    epoch: &SignedCustodyEpochV1,
    composition_now: u64,
    steer_init: &dyn Fn(usize, Vec<u8>) -> Vec<u8>,
) -> (media_dash_fixture::MediaDashComponents, CustodyEnvelopeV1) {
    let header = CustodyProtectionHeader::new(
        mint_intent.content_access_id(),
        &mint_intent.custody_pool(),
        &mint_intent.custody_epoch(),
        &mint_intent.custody_committee_authorization(),
        CencMediaSuite::DashV2,
    );
    let (kinds, counts) = test_input_layout(input);
    let components = media_dash_fixture::protect_media_dash_clear(
        mint_intent.content_access_id(),
        &header,
        &media_dash_fixture::clear_media_dash(&kinds, &counts),
        steer_init,
    );
    let committee = validated_custody_committee_for_epoch(epoch, composition_now);
    let content_key =
        elastos_protected_content_custody::ContentEncryptionKeyV1::generate().unwrap();
    let envelope = provision_custody_envelope(
        components.head.encrypted_content().clone(),
        &content_key,
        &committee,
    )
    .unwrap();
    (components, envelope)
}

/// The responses of an honest v2 protect, in the order a mint asks for them:
/// the open, every segment (video first, then audio), then the finalize.
/// The caller appends the settlement (`cancelled` or `closed`).
#[cfg(unix)]
pub(super) fn media_dash_protect_script(
    handle: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
    components: &media_dash_fixture::MediaDashComponents,
    envelope: &CustodyEnvelopeV1,
) -> Vec<Result<Value, ProviderError>> {
    let mut script = vec![Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_opened_v2(handle, &components.protected_inits).unwrap(),
    ))];
    for segments in &components.protected_segments {
        for (index, segment) in segments.iter().enumerate() {
            script.push(Ok(ok_typed_protect_provider_response(
                ProtectProviderResponseV1::new_segment_protected(handle, index as u32, segment)
                    .unwrap(),
            )));
        }
    }
    script.push(Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_finalized_v2(handle, &components.head, envelope).unwrap(),
    )));
    script
}

/// The persisted intent for `input` (what the mint would load or create), so a
/// test can build the protect response that matches its access id.
#[cfg(unix)]
pub(super) fn persisted_test_mint_intent(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    input: &RuntimeCustodyLibraryPublishInput,
) -> RuntimeMintIntent {
    let composition = load_runtime_custody_composition(data_dir, registry.clone())
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
    let mint_nodes = selected
        .iter()
        .map(|node| node.binding().clone())
        .collect::<Vec<_>>();
    load_or_persist_runtime_mint_intent(
        &runtime_mint_journal(data_dir),
        &composition,
        input,
        mint_nodes,
        None,
    )
    .unwrap()
}

/// Drives a full media publish against a protect provider whose protected init
/// segments are rebuilt by `steer`, and returns the resulting error string.
///
/// `steer` receives the mint intent, the rendition's position and the honest
/// protected init segment (the one this session's own identities produce) and
/// hands back the init the provider returns, so a caller can have the header
/// removed, replaced, or changed in one rendition only.
#[cfg(unix)]
pub(super) async fn library_publish_error_with_steered_protection_header(
    principal: &str,
    steer: impl Fn(&RuntimeMintIntent, usize, Vec<u8>) -> Vec<u8>,
) -> String {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let (epoch, composition_now) = write_library_publish_test_composition(&data_dir);
    let registry = Arc::new(ProviderRegistry::new());
    let input = library_publish_test_input(&data_dir, principal);
    let mint_intent = persisted_test_mint_intent(&data_dir, &registry, &input);
    let (components, envelope) = protect_input_for_test(
        &input,
        &mint_intent,
        &epoch,
        composition_now,
        &|position, init| steer(&mint_intent, position, init),
    );
    let handle = [0x4b; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
    let mut script = media_dash_protect_script(handle, &components, &envelope);
    script.push(Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_cancelled(handle).unwrap(),
    )));
    let protect = MediaDashProtectTestProvider::new(script, None);
    registry
        .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect.clone())
        .await
        .unwrap();

    let error = publish_runtime_custody_library_object(&data_dir, registry, input)
        .await
        .expect_err("a protect output whose protection header is wrong must not publish");
    let requests = protect.requests().await;
    assert_eq!(
        requests.last().map(|request| request["op"].clone()),
        Some(serde_json::json!("cancel_protection_session")),
        "the rejected session must still be settled: {requests:?}"
    );
    error.to_string()
}

/// The span `[start, start + size)` of the Elastos protection box in a
/// protected v2 init segment, and the offset of the `moov` box that holds it.
#[cfg(unix)]
pub(super) fn elastos_protection_box_span(protected_init: &[u8]) -> (usize, usize, usize) {
    let writer = PROTECTION.writer().id;
    // A `pssh` box is size(4) type(4) version+flags(4) system id(16).
    let start = protected_init
        .windows(16)
        .position(|window| window == writer.as_bytes())
        .unwrap()
        - 12;
    let size = u32::from_be_bytes(protected_init[start..start + 4].try_into().unwrap()) as usize;
    let mut moov_off = 0;
    while &protected_init[moov_off + 4..moov_off + 8] != b"moov" {
        moov_off +=
            u32::from_be_bytes(protected_init[moov_off..moov_off + 4].try_into().unwrap()) as usize;
    }
    (start, size, moov_off)
}

/// A protected init segment with `replacement` (possibly nothing) in place of
/// its Elastos protection box, and the `moov` size fixed up.
#[cfg(unix)]
pub(super) fn replace_protection_header(protected_init: &[u8], replacement: &[u8]) -> Vec<u8> {
    let (start, size, moov_off) = elastos_protection_box_span(protected_init);
    let mut steered = protected_init[..start].to_vec();
    steered.extend_from_slice(replacement);
    steered.extend_from_slice(&protected_init[start + size..]);
    let moov_size =
        u32::from_be_bytes(protected_init[moov_off..moov_off + 4].try_into().unwrap()) as usize;
    let resized = u32::try_from(moov_size - size + replacement.len()).unwrap();
    steered[moov_off..moov_off + 4].copy_from_slice(&resized.to_be_bytes());
    steered
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
            .sign_prehash_recoverable(
                &rights_request
                    .signing_hash()
                    .map_err(|error| ProviderError::Provider(format!("{error:?}")))?,
            )
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
    /// Requests the person has confirmed but whose signature has not come back
    /// yet. This is the real `approved` state an external wallet sits in
    /// between the person pressing Confirm and the connector posting the
    /// signature, and it answers `requires_approval: false` with no signed
    /// result -- the shape that once read as a hard failure.
    pub(super) confirmed_awaiting_signature: std::sync::Mutex<std::collections::HashSet<String>>,
    pub(super) seen: std::sync::Mutex<Vec<String>>,
}

impl ManagedReleaseWalletProvider {
    pub(super) fn new() -> Self {
        Self {
            approved: std::sync::Mutex::new(std::collections::HashSet::new()),
            confirmed_awaiting_signature: std::sync::Mutex::new(std::collections::HashSet::new()),
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(super) fn approve(&self, request_id: &str) {
        self.approved.lock().unwrap().insert(request_id.to_string());
    }

    /// The person has confirmed; the connector has not answered yet.
    pub(super) fn confirm_awaiting_signature(&self, request_id: &str) {
        self.confirmed_awaiting_signature
            .lock()
            .unwrap()
            .insert(request_id.to_string());
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
        let awaiting_signature = self
            .confirmed_awaiting_signature
            .lock()
            .unwrap()
            .contains(&wallet_request.request_id);
        let approved = self
            .approved
            .lock()
            .unwrap()
            .contains(&wallet_request.request_id);
        let approval_request = json!({
            "schema": "elastos.wallet.approval_request/v1",
            "request_id": wallet_request.request_id,
            "intent": "protected_content_rights_signature",
            "status": if approved {
                "completed"
            } else if awaiting_signature {
                "approved"
            } else {
                "pending"
            },
            // The Wallet names the account the approval belongs to. A managed
            // account completes in place, so the open reports that nobody has
            // to go anywhere; an external one would carry its connector here.
            "proof_type": "managed_evm",
            "connector_id": Value::Null,
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
                .sign_prehash_recoverable(
                    &rights_request
                        .signing_hash()
                        .map_err(|error| ProviderError::Provider(format!("{error:?}")))?,
                )
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
                // False once the person has confirmed, exactly as the real
                // wallet answers: `requires_approval` is `status == Pending`
                // alone, so the approved gap reports false with no signature.
                "requires_approval": !awaiting_signature,
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
pub(crate) fn process_fixture_pool_descriptor_for_test(
    fixture: &RuntimeCustodyProcessProviderFixture,
    runtime_owner: RuntimeOperationIssuerKeyV1,
    now: u64,
) -> elastos_protected_content_contracts::SignedPoolDescriptorAnyV1 {
    use elastos_protected_content_contracts::{
        MintPolicyV1, PoolDescriptorStatementV3, PoolDidV1, PoolEpochBundleV1, PoolMemberRolesV1,
        PoolMemberRouteV2, PoolMemberV2, PoolMemberV3, PoolTrustModeV1, ServePolicyV1,
        SignedPoolDescriptorV3,
    };
    let decode = |text: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .unwrap()
    };
    let pool =
        SignedCustodyPoolV1::from_canonical_bytes(&decode(&fixture.composition.signed_pool_base64))
            .unwrap();
    let epoch = SignedCustodyEpochV1::from_canonical_bytes(&decode(
        &fixture.composition.signed_epoch_base64,
    ))
    .unwrap();
    let authorization = SignedCustodyCommitteeAuthorizationV1::from_canonical_bytes(&decode(
        &fixture.composition.signed_committee_authorization_base64,
    ))
    .unwrap();
    let members = epoch
        .statement()
        .nodes()
        .iter()
        .map(|node| {
            let key =
                ed25519_dalek::VerifyingKey::from_bytes(node.node_public_key().as_bytes()).unwrap();
            PoolMemberV3::new(
                PoolMemberV2::new(
                    node.node_public_key(),
                    PoolMemberRolesV1 {
                        hold: true,
                        serve: true,
                        seal: true,
                    },
                    PoolMemberRouteV2::new(elastos_identity::encode_did_key(&key).unwrap())
                        .unwrap(),
                )
                .unwrap(),
                Vec::new(),
            )
            .unwrap()
        })
        .collect();
    let issuer_key = SigningKey::from_bytes(&[0x71; 32]);
    let statement = PoolDescriptorStatementV3::new(
        PoolDidV1::from_issuer(pool.statement().issuer()),
        1,
        vec![PoolEpochBundleV1::new(pool, epoch, authorization).unwrap()],
        members,
        ServePolicyV1::DEFAULT,
        MintPolicyV1::owner_default(runtime_owner),
        now.saturating_sub(1),
        now + 300,
        PoolTrustModeV1::WciOperated,
    )
    .unwrap();
    let signed = SignedPoolDescriptorV3::new(
        statement.clone(),
        issuer_key
            .sign(&statement.canonical_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    signed.verify(now).unwrap();
    signed.into()
}

#[cfg(unix)]
/// The clear media the gateway tests' mock media provider prepares: per
/// rendition (video, then audio) its init and its segments.
#[allow(clippy::type_complexity)]
pub(crate) fn runtime_custody_gateway_media_output_for_test(
) -> Vec<(CencDashRenditionKindV2, Vec<u8>, Vec<Vec<u8>>)> {
    media_dash_fixture::clear_media_dash(
        &[TEST_PREPARED_VIDEO.kind, TEST_PREPARED_AUDIO.kind],
        &[TEST_PREPARED_VIDEO.segments, TEST_PREPARED_AUDIO.segments],
    )
}

/// The parts a v2 viewer reads, in the interleave `read_viewer` walks: every
/// init in rendition order, then for each segment index the segment of every
/// rendition. Per part `(rendition, segment index or None for an init, the
/// clear bytes it must decrypt to)`.
#[allow(clippy::type_complexity)]
pub(crate) fn runtime_custody_gateway_media_parts_for_test() -> Vec<(u8, Option<u32>, Vec<u8>)> {
    let media = runtime_custody_gateway_media_output_for_test();
    let mut parts = Vec::new();
    for (rendition, (_, init, _)) in media.iter().enumerate() {
        parts.push((rendition as u8, None, init.clone()));
    }
    let longest = media
        .iter()
        .map(|(_, _, segments)| segments.len())
        .max()
        .unwrap_or(0);
    for index in 0..longest {
        for (rendition, (_, _, segments)) in media.iter().enumerate() {
            if let Some(segment) = segments.get(index) {
                parts.push((rendition as u8, Some(index as u32), segment.clone()));
            }
        }
    }
    parts
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
    crate::host_trust::seed_wci_host_for_test(&nodes_root.join("node-1"));
    register_custody_provider(&node1.registry, &custody_binary, &nodes_root.join("node-1"))
        .await
        .unwrap();
    crate::host_trust::seed_wci_host_for_test(&nodes_root.join("node-2"));
    register_custody_provider(&node2.registry, &custody_binary, &nodes_root.join("node-2"))
        .await
        .unwrap();
    crate::host_trust::seed_wci_host_for_test(&nodes_root.join("node-3"));
    register_custody_provider(&node3.registry, &custody_binary, &nodes_root.join("node-3"))
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

/// Make `fixture`'s pool the custody composition this Home runs, as a Home
/// whose pool changed between two presses would.
#[cfg(unix)]
pub(crate) fn install_runtime_custody_composition_for_test(
    fixture: &RuntimeCustodyProcessProviderFixture,
    data_dir: &Path,
) {
    write_owner_only_custody_composition_config(data_dir, &fixture.composition);
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
    register_runtime_custody_mock_media_provider_rendition(
        data_dir,
        registry,
        TestMediaPreparationResponse::prepared_video_audio(),
    )
    .await;
}

#[cfg(unix)]
pub(crate) async fn register_runtime_custody_mock_audio_media_provider_for_test_registry(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
) {
    register_runtime_custody_mock_media_provider_rendition(
        data_dir,
        registry,
        TestMediaPreparationResponse::prepared_audio(),
    )
    .await;
}

#[cfg(unix)]
pub(super) async fn register_runtime_custody_mock_media_provider_rendition(
    data_dir: &Path,
    registry: &Arc<ProviderRegistry>,
    response: TestMediaPreparationResponse,
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
                response,
            }),
        )
        .await
        .unwrap();
}

pub(super) fn test_object_identity(framed_bytes: &[u8]) -> ChunkedPayloadObjectIdentityV1 {
    let ciphertext_sha256 = Digest32::new(sha2::Sha256::digest(framed_bytes).into());
    let encrypted_content =
        EncryptedContentIdentityV1::new(ciphertext_sha256, framed_bytes.len() as u64).unwrap();
    ChunkedPayloadObjectIdentityV1::new(encrypted_content, "application/pdf", 4096, 64).unwrap()
}

pub(super) fn write_object_protected_content_directory(
    directory: &Path,
    object_identity: &ChunkedPayloadObjectIdentityV1,
    framed_bytes: &[u8],
) {
    let tree = directory.join("protected-content/v1");
    fs::create_dir_all(&tree).unwrap();
    fs::write(
        directory.join(PROTECTED_CONTENT_OBJECT_MANIFEST_PATH),
        protected_content_object_manifest_bytes(object_identity).unwrap(),
    )
    .unwrap();
    fs::write(
        directory.join(PROTECTED_CONTENT_OBJECT_EPC1_PATH),
        framed_bytes,
    )
    .unwrap();
}

pub(super) fn fixture_raw_cid(bytes: &[u8]) -> String {
    let hash = cid::multihash::Multihash::<64>::wrap(0x12, &sha2::Sha256::digest(bytes)).unwrap();
    cid::Cid::new_v1(0x55, hash).to_string()
}

#[derive(Default)]
pub(super) struct RemoteSealFinalityFixture {
    pub(super) policy: Mutex<Option<RightsPolicyBodyV1>>,
    pub(super) requests: Mutex<Vec<Value>>,
}

#[async_trait::async_trait]
impl Provider for RemoteSealFinalityFixture {
    async fn handle(&self, _: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "policy fixture is invoke-only".into(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![CHAIN_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        "remote-seal-finality-fixture"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.requests.lock().await.push(request.clone());
        let Some(policy) = self.policy.lock().await.clone() else {
            return Ok(json!({
                "status": "error",
                "code": "item_binding_not_final",
                "message": "fixture binding is not finalized",
            }));
        };
        Ok(ok_provider_response(json!({
            "schema": CHAIN_PROTECTED_CONTENT_POLICY_SCHEMA_V1,
            "policy_body": format!("0x{}", hex::encode(policy.canonical_bytes().unwrap())),
        })))
    }
}

/// A byte-for-byte copy of a real listing file written by the installed
/// Runtime *before* the object widening landed, taken from this machine's
/// installed data directory
/// (`~/Library/Application Support/elastos/protected-content/runtime-listings/
/// 58a70fb16023b740402f180b162fa6683fd9b2d21d9a6c8955e801c0be0e7b3d.json`,
/// stamped 2026-09-06 by the installed end-to-end proof run; one of the 14
/// listings that corpus holds, every one of them carrying
/// `media_identity_base64`).
///
/// It was deliberately NOT regenerated by the current encoder: a fixture the
/// new code can produce proves nothing about the listings already on disk.
pub(super) const REAL_PRE_OBJECT_WIDENING_LISTING_JSON: &[u8] = br#"{"schema":"elastos.library.runtime-custody-listing/v1","origin":{"kind":"local_creator","principal_id":"person:local:b62d976e8b765ee6819e585a6fc69486","listing_uri":"elastos://Qmf4jPsuwJtF4YBBX3LUFpp8Kxqc2LyrFoGtLqes4q7xuf","package_sha256":"81a3de84abe41219508112d5def9a6d82869df653b2be1a7231af65538626716"},"package":{"schema":"elastos.protected-content.portable-listing/v1","mint_id":"58a70fb16023b740402f180b162fa6683fd9b2d21d9a6c8955e801c0be0e7b3d","content_id":"content:5adec06aa185a801d88e440e0054503d2a7c9ff59ad3f999e2b36c5253c99f56","content_cid":"QmUgzoEcj1MtBzCJ4tQxMYJVpMKkjro1pn8Eom43ZSJNtX","metadata_cid":"QmX1bpSqJeXdSQ3gj1yYbazp9zD3EXR3tEtAkCVAgCXunr","token_uri":"ipfs://QmX1bpSqJeXdSQ3gj1yYbazp9zD3EXR3tEtAkCVAgCXunr/metadata.json","publisher_profile_did":"did:key:z6MkgowPpYJhdHT4E6xQcs1PBxvF2YYFuJLdcgcDaWMHoR9Q","display_name":"protected-content-installed-e2e-proof-20260906T071856Z-7576","media_identity_base64":"ZWxhc3Rvcy5wcm90ZWN0ZWQtY29udGVudC5jZW5jLWZtcDQtbWVkaWEtaWRlbnRpdHkvdjEAABZjZW5jLWZtcDQtYWVzMTI4Y3RyL3YxAFdlbGFzdG9zLnByb3RlY3RlZC1jb250ZW50LmVuY3J5cHRlZC1jb250ZW50L3YxACqs+NINPwTniTCHRJp8YEROnvoMMv7cerqTaXxc+EwSAAAAAAABn0vu0fVUIOwTa7f1hALcHFc+gwPUhxdKL+Eld7jnWLGOU8MP6bfu3Mgl5C+MJS0cNdXlouB4LkteryHNEfX6rtm0AAAAAAAAA4MACXZpZGVvL21wNAALYXZjMS42NDAwMjgAAwBXZWxhc3Rvcy5wcm90ZWN0ZWQtY29udGVudC5jZW5jLWZtcDQtc2VnbWVudC92MQCmaDmlEUShdbHpbVD037JOdUoqKQjwh3L3VupHy9r2yQAAAAAAAJBdAFdlbGFzdG9zLnByb3RlY3RlZC1jb250ZW50LmNlbmMtZm1wNC1zZWdtZW50L3YxAEGyspD4GIRJ/oRHjxW1IewpWpy6woVnkFr0G7C+/M9mAAAAAAAAljoAV2VsYXN0b3MucHJvdGVjdGVkLWNvbnRlbnQuY2VuYy1mbXA0LXNlZ21lbnQvdjEAphAM2eZLmC4ciOkcomIjkHCYFen6NE7mhx1ra4A3IrsAAAAAAAB4tA==","content_access_id":"0xd3b75643e2d735d466ba1ceb9aa76e44","key_envelope_identity_base64":"ZWxhc3Rvcy5wcm90ZWN0ZWQtY29udGVudC5rZXktZW52ZWxvcGUvdjEAAFdlbGFzdG9zLnByb3RlY3RlZC1jb250ZW50LmVuY3J5cHRlZC1jb250ZW50L3YxACqs+NINPwTniTCHRJp8YEROnvoMMv7cerqTaXxc+EwSAAAAAAABn0vNRf5pRtXoOz7TAPK1u4TyTdsCC9XxAEEGNC8YI76HHQAAH8EBwgwcBjXemQvazqEIu6nuwvChPMLXqatgtjYJWW3XmgIDAFdlbGFzdG9zLnByb3RlY3RlZC1jb250ZW50LmN1c3RvZHktcG9vbC5pZGVudGl0eS92MQCEOT8R2alUlpWVxgx3n9AS2pd6Ok8Xppb5AWQ+TAKDwgAAFK0AWGVsYXN0b3MucHJvdGVjdGVkLWNvbnRlbnQuY3VzdG9keS1lcG9jaC1pZGVudGl0eS92MQDn9SGB0cbTUlbSJwL9jB1X9Ge3vt5uCZBvY4bfFosrLwAAENcAamVsYXN0b3MucHJvdGVjdGVkLWNvbnRlbnQuY3VzdG9keS1jb21taXR0ZWUtYXV0aG9yaXphdGlvbi5pZGVudGl0eS92MQCCGGc5r/gwRtJY1Co5gfdxiXLXPMEVH3Gbp4JIKRy6/AAAAaI=","rights_policy_identity_base64":"ZWxhc3Rvcy5wcm90ZWN0ZWQtY29udGVudC5yaWdodHMtcG9saWN5LWlkZW50aXR5L3YxABFFBT9Njh7IiiewWpDprkfdHefJL9J/JB/86JXUFDjjAAAA+A==","content_key_commitment_base64":"kSNx+7wd8YimGT4pxpELj2cjeCYachPFmv4uCClpiV4=","seller_address":"0xf36c114c19f96b4174b6d71e392c00db95093a1e","chain_namespace":"eip155:8453","network":"base-mainnet","ledger":"0x0ebac909d31ef0074495e752c0cf4ea49ba13c41","token_id":"0xeaa1578cfda2c9885e4f626cf014c2d42c6be5c71ce64ebc9bda704072b32556","operative":"0xbaec8aa7dbbe6ef205feb93cb83a2bf91d650098","quantity":"0x3","price":"0x38d7ea4c68000","pay_token":"0x0000000000000000000000000000000000000000","mint_transaction_hash":"0xb8f5b500e32c54470ba5b674108da44ec74b3a4c4612b5bbc61cf3b2a85c89d9","published_at":1788679217},"availability":{"checked_at":1788679139,"observed_replicas":3,"receipt_digest":"85811f14bde02cac0498daff517c46f5ddaeb7a539bbe5756d5c6c948eb6aedc"}}"#;

/// The `package_sha256` the real file above already carries, pinned as a
/// literal. `RuntimeCustodyListingRecord::validate` recomputes
/// `sha256(serde_json::to_vec(package))` and compares it to the value stored
/// in the record's own `origin`, so a single changed byte in a media
/// package's re-serialization fails the whole record — this literal makes
/// that pin visible rather than implicit.
pub(super) const REAL_PRE_OBJECT_WIDENING_PACKAGE_SHA256: &str =
    "81a3de84abe41219508112d5def9a6d82869df653b2be1a7231af65538626716";

/// A deterministic object mint draft plus the portable listing package a
/// creator would publish for it: the object twin of
/// `runtime_custody_listing_record_for_test`'s media package, reusing every
/// non-identity field verbatim so the only difference under test is which
/// identity field the package carries.
pub(super) fn object_listing_package_for_test(
    seed: u8,
) -> (
    ChunkedPayloadObjectIdentityV1,
    super::super::RuntimePortableListingPackage,
) {
    let epoch = signed_custody_epoch();
    let framed = vec![seed; 4160];
    let object_identity = ChunkedPayloadObjectIdentityV1::new(
        EncryptedContentIdentityV1::new(
            Digest32::new(sha2::Sha256::digest(&framed).into()),
            framed.len() as u64,
        )
        .unwrap(),
        "application/pdf",
        4096,
        64,
    )
    .unwrap();
    let manifest = CustodyEnvelopeManifestV1::new(
        object_identity.encrypted_content().clone(),
        CustodyPoolIdentityV1::new(digest(seed ^ 0x34), 512).unwrap(),
        epoch.epoch_identity().unwrap(),
        CustodyCommitteeAuthorizationIdentityV1::new(digest(seed ^ 0x35), 512).unwrap(),
        ThresholdV1::new(2, 3).unwrap(),
        digest(seed ^ 0x33),
        epoch.statement().nodes().to_vec(),
    )
    .unwrap();
    let envelope = CustodyEnvelopeV1::new(
        manifest,
        [seed ^ 0x50, seed ^ 0x51, seed ^ 0x52]
            .into_iter()
            .map(sealed_share)
            .collect(),
    )
    .unwrap();
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
    let draft = RuntimeMintDraft::new_from_identity(
        RuntimeContentIdentityV1::Object(object_identity.clone()),
        content_access_id(seed),
        envelope.key_envelope_identity().unwrap(),
        policy_body().policy_identity().unwrap(),
        envelope.manifest().content_key_commitment(),
        envelope.manifest().threshold(),
        mint_nodes,
    )
    .unwrap();
    let media_package = runtime_custody_listing_record_for_test(
        draft.mint_id(),
        "person:local:object-listing",
        "object-listing",
        NOW,
    )
    .package;
    let (media_identity_base64, content_identity_base64) =
        super::super::runtime_portable_identity_fields(draft.content_identity()).unwrap();
    let package = super::super::RuntimePortableListingPackage {
        mint_id: hex::encode(draft.mint_id().as_bytes()),
        content_id: super::super::runtime_protected_content_id(draft.encrypted_content()).unwrap(),
        content_access_id: format!("0x{}", hex::encode(draft.content_access_id().as_bytes())),
        media_identity_base64,
        content_identity_base64,
        key_envelope_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.key_envelope().canonical_bytes().unwrap()),
        rights_policy_identity_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.policy().canonical_bytes().unwrap()),
        content_key_commitment_base64: base64::engine::general_purpose::STANDARD
            .encode(draft.content_key_commitment().as_bytes()),
        ..media_package
    };
    (object_identity, package)
}

/// Exercise the shipping consumer against Runtime-produced rows, rather
/// than copying a JSON fixture whose values could drift from the producer.
pub(crate) fn marketplace_listing_consumer_for_test(payload: &Value) -> Value {
    use std::io::{Read as _, Write as _};
    let mut child = Command::new("node").args(["--input-type=module","-e",r#"
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const { parseRuntimeCustodyListings } = await import(pathToFileURL(`${process.argv[1]}/capsules/marketplace/browser/src/listing.js`));
const payload = JSON.parse(readFileSync(0, 'utf8'));
const parsed = parseRuntimeCustodyListings(payload);
assert.equal(parsed.rejected, 0, 'shipping Marketplace must accept every valid Runtime-produced row');
assert.equal(parsed.listings.length, payload.listings.length);
for (let index = 0; index < parsed.listings.length; index++) {
  assert.equal(parsed.listings[index].publishedAt, payload.listings[index].published_at, 'unknown publication time stays null');
}
console.log(JSON.stringify(parsed));
"#]).arg(concat!(env!("CARGO_MANIFEST_DIR"),"/../../.."))
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped()).spawn().unwrap();
    let input = serde_json::to_vec(payload).unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    // Drain both pipes while polling: even a larger shelf cannot fill a pipe
    // and prevent the child from exiting. All child I/O is owned and joined.
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let drain = |stream: Box<dyn std::io::Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stream.take(1024 * 1024).read_to_end(&mut bytes).unwrap();
            bytes
        })
    };
    let stdout = drain(Box::new(stdout));
    let stderr = drain(Box::new(stderr));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            child.wait().unwrap();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let written = writer.join().unwrap();
    let stdout = stdout.join().unwrap();
    let stderr = stderr.join().unwrap();
    let status =
        status.expect("shipping JS consumer exceeded its 10 second deadline (killed and reaped)");
    written.unwrap();
    assert!(
        status.success(),
        "shipping JS rejected the actual Runtime summary: {}",
        String::from_utf8_lossy(&stderr)
            .chars()
            .take(2048)
            .collect::<String>()
    );
    serde_json::from_slice(&stdout).unwrap()
}

pub(super) const SHARED_PUBLISHER: &str = "0xAB5028BDBB0826AD6F1885478E421DB677B0001A";

/// The four identities a package carries, as the shared document states them.
pub(super) struct SharedIdentities {
    pub(super) kid: String,
    pub(super) content_type: String,
    pub(super) rights_policy: String,
    pub(super) key_envelope: String,
    pub(super) content_key_commitment: String,
    pub(super) content_identity: String,
}

impl SharedIdentities {
    pub(super) fn of_package(
        package: &super::super::RuntimePortableListingPackage,
        content_type: &str,
    ) -> Self {
        Self {
            kid: package.content_access_id.clone(),
            content_type: content_type.to_string(),
            rights_policy: package.rights_policy_identity_base64.clone(),
            key_envelope: package.key_envelope_identity_base64.clone(),
            content_key_commitment: package.content_key_commitment_base64.clone(),
            content_identity: package
                .media_identity_base64
                .clone()
                .or_else(|| package.content_identity_base64.clone())
                .unwrap(),
        }
    }
}

/// The shared `metadata.json` exactly as this Runtime's producer writes it --
/// never hand-written -- for the given identities.
pub(super) fn shared_metadata_from_producer(identities: &SharedIdentities) -> Value {
    let inputs = crate::protected_content_elacity_metadata::ElacityMetadataInputs {
        encrypted_content_cid: ContentAvailabilityTestProvider::CID,
        content_type: &identities.content_type,
        plaintext_bytes: 5,
        kid_0x: &identities.kid,
        publisher_address: SHARED_PUBLISHER,
        chain_id: 8453,
        ledger: "0x0000000000000000000000000000000000000022",
        authority: "",
        copies: 2,
        price: "5",
        image: "",
        protection: crate::protected_content_elacity_metadata::runtime_custody_protection(
            2,
            3,
            crate::protected_content_elacity_metadata::ProtectedContentIdentities {
                rights_policy: &identities.rights_policy,
                key_envelope: &identities.key_envelope,
                content_key_commitment: &identities.content_key_commitment,
                content_identity: &identities.content_identity,
                pool_mint_share: None,
            },
        ),
        fallback_name: "shared-proof.mp4",
        created_at: "2026-09-25T00:00:00Z",
        access_method: elastos_protected_content_runtime::RuntimeMintAccessMethod::BuyOnce,
        reseller_cut: None,
    };
    let files =
        crate::protected_content_elacity_metadata::elacity_metadata_files(None, &inputs).unwrap();
    assert_eq!(files[0].0, "metadata.json");
    serde_json::from_slice(&files[0].1).unwrap()
}

pub(super) fn media_listing_package_for_shared_test() -> super::super::RuntimePortableListingPackage
{
    runtime_custody_listing_record_for_test(
        Digest32::new([0x74; 32]),
        "person:local:shared",
        "shared",
        NOW,
    )
    .package
}

/// An adopted record (origin `Asset`) of the fixture's own package.
pub(super) fn adopted_listing_record_for_test() -> super::super::RuntimeCustodyListingRecord {
    let mut record = runtime_custody_listing_record_for_test(
        Digest32::new([0x76; 32]),
        "person:local:adopted",
        "adopted",
        NOW,
    );
    record.package.mint_transaction_hash = None;
    record.package.published_at = None;
    record.package.publisher_profile_did = format!(
        "did:pkh:eip155:8453:{}",
        SHARED_PUBLISHER.to_ascii_lowercase()
    );
    record.origin = super::super::RuntimeCustodyListingOrigin::Asset {
        asset_uri: format!("elastos://{}", record.package.metadata_cid),
        source_listing: None,
    };
    record
}

/// Re-states a published record's `package_sha256` over its current package,
/// so a check that fails is the one under test and not the digest.
pub(super) fn restate_published_digest(record: &mut super::super::RuntimeCustodyListingRecord) {
    let digest = hex::encode(sha2::Sha256::digest(
        serde_json::to_vec(&record.package).unwrap(),
    ));
    match &mut record.origin {
        super::super::RuntimeCustodyListingOrigin::LocalCreator { package_sha256, .. }
        | super::super::RuntimeCustodyListingOrigin::Imported { package_sha256, .. } => {
            *package_sha256 = digest;
        }
        super::super::RuntimeCustodyListingOrigin::Asset { .. }
        | super::super::RuntimeCustodyListingOrigin::Granted { .. } => {}
    }
}

pub(super) fn granted_listing_record_for_test() -> super::super::RuntimeCustodyListingRecord {
    let mut record = adopted_listing_record_for_test();
    record.origin = super::super::RuntimeCustodyListingOrigin::Granted {
        asset_uri: format!("elastos://{}", record.package.metadata_cid),
    };
    record.package.seller_address = record.package.operative.to_ascii_lowercase();
    record.package.quantity = "0x1".to_string();
    record.package.price = "0x0".to_string();
    record.package.pay_token = super::super::RUNTIME_CUSTODY_ZERO_ADDRESS.to_string();
    record.package.payment_processor = None;
    record
}

pub(super) const FINALITY_WALLET: &str = "0x0000000000000000000000000000000000000007";

pub(super) fn finality_access_answer(request: &Value, has_access: bool) -> Value {
    ok_provider_response(json!({
        "schema": "elastos.chain.protected-content-purchase-access/v1",
        "request_id": request["request_id"],
        "network": "base-mainnet",
        "chain_id": 8453,
        "wallet": FINALITY_WALLET,
        "content_access_id": request["content_access_id"],
        "has_access": has_access,
        "finalized_block_number": 44,
        "finalized_block_hash": format!("0x{}", "cc".repeat(32)),
        "finalized_block_timestamp": 1_000,
        "observed_at": 1_000,
    }))
}

pub(super) fn finality_unbound_answer() -> Value {
    json!({
        "status": "error",
        "code": "unknown_protected_content_object",
        "message": "protected-content content access id is not bound on chain",
    })
}

/// The request the finality check sends, so each answer can echo it.
pub(super) fn finality_request(block: &str) -> Value {
    json!({
        "request_id": format!("open-finality:{block}"),
        "content_access_id": format!("0x{}", hex::encode(content_access_id(0x51).as_bytes())),
    })
}

pub(super) async fn finality_progress_with(
    answers: Vec<Result<Value, ProviderError>>,
    confirmed_at: u64,
    now: u64,
) -> (Option<super::super::RuntimeCustodyOpenProgress>, Vec<Value>) {
    let registry = Arc::new(ProviderRegistry::new());
    let chain = SequencedProvider::new(CHAIN_PROVIDER_ID, answers);
    registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain.clone())
        .await
        .unwrap();
    let progress = super::super::runtime_custody_open_finality_progress(
        registry.as_ref(),
        "base-mainnet",
        FINALITY_WALLET,
        content_access_id(0x51),
        "open-finality",
        confirmed_at,
        now,
    )
    .await;
    (progress, chain.requests().await)
}

/// The typed reason a fail-closed refusal carries, so Creator offers Start over.
pub(super) fn attempt_conflict_reason(
    error: &anyhow::Error,
) -> RuntimeCustodyAttemptConflictReason {
    error
        .downcast_ref::<RuntimeCustodyAttemptConflict>()
        .unwrap_or_else(|| panic!("refusal must carry the attempt conflict as data: {error:#}"))
        .reason()
}

/// Start over, as the gateway does it: the source's current attempt is moved
/// aside and the source is on a new attempt.
pub(super) fn start_over_for_test(
    data_dir: &Path,
    principal_id: &str,
    object_uri: &str,
    source_storage: &str,
) {
    runtime_mint_journal(data_dir)
        .archive_current_attempt(
            principal_id,
            object_uri,
            source_storage,
            &data_dir.join("protected-content/runtime-mint-set-aside-test"),
            b"{}",
        )
        .unwrap();
}

/// Independent of the production path helpers on purpose: a wrong path there
/// must fail a test here.
pub(super) fn dash_dir(
    kind: elastos_protected_content_provider_contracts::CencDashRenditionKindV2,
) -> &'static str {
    match kind {
        DASH_VIDEO => "protected-content/v2/video/avc1",
        DASH_AUDIO => "protected-content/v2/audio/und/mp4a",
    }
}

pub(super) fn dash_init_path(
    kind: elastos_protected_content_provider_contracts::CencDashRenditionKindV2,
) -> String {
    format!("{}/init.mp4", dash_dir(kind))
}

pub(super) fn dash_segment_file(
    kind: elastos_protected_content_provider_contracts::CencDashRenditionKindV2,
    index: usize,
) -> String {
    format!("{}/seg-{}.m4s", dash_dir(kind), index + 1)
}

pub(super) const DASH_IDENTITY_FILE: &str = "protected-content/v2/identity.bin";

pub(super) const DASH_MPD_FILE: &str = "protected-content/v2/stream.mpd";

pub(crate) fn media_dash_components(
    kinds: &[elastos_protected_content_provider_contracts::CencDashRenditionKindV2],
    counts: &[usize],
) -> MediaDashComponents {
    media_dash_fixture::protected_media_dash_components(
        0x41,
        kinds,
        counts,
        &signed_custody_epoch().epoch_identity().unwrap(),
    )
}

/// The v2 package layout (spec section 3) as `(path, bytes)`, sorted by path.
/// The MPD is a stand-in: nothing in the read side reads it, and the real one
/// is T10's writer's.
pub(super) fn dash_package_files(
    head: &elastos_protected_content_provider_contracts::CencDashMediaIdentityV2,
    inits: &[Vec<u8>],
    segments: &[Vec<Vec<u8>>],
) -> Vec<(String, Vec<u8>)> {
    let mut files = vec![
        (
            DASH_IDENTITY_FILE.to_string(),
            head.canonical_bytes().unwrap(),
        ),
        (DASH_MPD_FILE.to_string(), b"<MPD/>".to_vec()),
    ];
    for (rendition, kind) in head.renditions().iter().map(|r| r.kind()).enumerate() {
        files.push((dash_init_path(kind), inits[rendition].clone()));
        for (index, segment) in segments[rendition].iter().enumerate() {
            files.push((dash_segment_file(kind, index), segment.clone()));
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

pub(crate) fn components_package_files(components: &MediaDashComponents) -> Vec<(String, Vec<u8>)> {
    dash_package_files(
        &components.head,
        &components.protected_inits,
        &components.protected_segments,
    )
}

pub(crate) fn dash_manifest_from_files(
    files: &[(String, Vec<u8>)],
) -> crate::content::ContentObjectManifest {
    let entries: Vec<crate::content::ContentObjectFile> = files
        .iter()
        .map(|(path, bytes)| content_object_file_for_test(path, bytes))
        .collect();
    crate::content::ContentObjectManifest {
        schema: "elastos.content.object.manifest/v1".to_string(),
        kind: "protected-content".to_string(),
        content_digest: super::super::content_object_digest(&entries),
        files: entries,
        links: Vec::new(),
        object_did: None,
        publisher_did: None,
    }
}

pub(super) fn content_object_file_for_test(
    path: &str,
    bytes: &[u8],
) -> crate::content::ContentObjectFile {
    crate::content::ContentObjectFile {
        path: path.to_string(),
        sha256: hex::encode(sha2::Sha256::digest(bytes)),
        size: bytes.len() as u64,
    }
}

/// A head over arbitrary bytes (no crypto), for the tests that only need
/// counts and a manifest: `kinds[r]` has `counts[r]` segments.
#[allow(clippy::type_complexity)]
pub(super) fn fake_dash_package(
    kinds: &[elastos_protected_content_provider_contracts::CencDashRenditionKindV2],
    counts: &[usize],
) -> (
    elastos_protected_content_provider_contracts::CencDashMediaIdentityV2,
    Vec<Vec<u8>>,
    Vec<Vec<Vec<u8>>>,
) {
    use elastos_protected_content_provider_contracts::{
        CencDashMediaIdentityV2, CencDashRenditionBytesV2,
    };
    let inits: Vec<Vec<u8>> = kinds
        .iter()
        .map(|kind| format!("init-{kind:?}").into_bytes())
        .collect();
    let segments: Vec<Vec<Vec<u8>>> = counts
        .iter()
        .enumerate()
        .map(|(rendition, count)| {
            (0..*count)
                .map(|index| vec![rendition as u8 + 1, index as u8, 0x5a, 0xa5])
                .collect()
        })
        .collect();
    let bytes: Vec<CencDashRenditionBytesV2<'_>> = kinds
        .iter()
        .enumerate()
        .map(|(index, kind)| CencDashRenditionBytesV2 {
            kind: *kind,
            timescale: 90_000,
            init_segment: &inits[index],
            segments: &segments[index],
        })
        .collect();
    let head = CencDashMediaIdentityV2::new_from_bytes(content_access_id(0x41), &bytes).unwrap();
    (head, inits, segments)
}

/// Per-rendition Merkle leaves, rebuilt from segment bytes alone.
pub(super) fn dash_leaves(
    kind: elastos_protected_content_provider_contracts::CencDashRenditionKindV2,
    segments: &[Vec<u8>],
) -> Vec<Digest32> {
    segments
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            elastos_protected_content_provider_contracts::cenc_dash_segment_leaf_hash(
                kind,
                index as u32,
                Digest32::new(sha2::Sha256::digest(segment).into()),
                segment.len() as u64,
            )
        })
        .collect()
}

pub(super) fn dash_all_leaves(components: &MediaDashComponents) -> Vec<Vec<Digest32>> {
    components
        .kinds
        .iter()
        .zip(&components.protected_segments)
        .map(|(kind, segments)| dash_leaves(*kind, segments))
        .collect()
}

pub(super) fn dash_proof(leaves: &[Digest32], index: usize) -> Vec<Digest32> {
    elastos_protected_content_provider_contracts::cenc_dash_merkle_audit_path(leaves, index)
        .unwrap()
}

pub(super) fn dash_test_record() -> super::super::RuntimeCustodyViewerRecord {
    let principal_id = "person:local:dash-record";
    let profile_did = derived_device_key_for_seed(0x66).1;
    let mint_id = digest(0x77);
    let binding = super::super::derive_runtime_custody_session_binding(
        principal_id,
        &profile_did,
        TEST_VIEWER_EXECUTABLE_ACTOR,
        TEST_VIEWER_LAUNCH_ID,
        "proof:dash",
        "runtime-session:dash",
        "grant:dash",
        mint_id,
    )
    .unwrap();
    let session = RuntimeViewerSession::from_persisted_parts(
        digest(0x91),
        opaque_handle(0x21),
        encrypted_content(0x11),
        RightsActionV1::View,
        crate::auth::now_ts() + 60,
    )
    .unwrap();
    super::super::RuntimeCustodyViewerRecord::from_active_session(
        principal_id,
        &profile_did,
        mint_id,
        "content-id",
        binding,
        &session,
        crate::auth::now_ts(),
    )
    .unwrap()
}

pub(super) fn manifest_error(
    manifest: &crate::content::ContentObjectManifest,
    head: &elastos_protected_content_provider_contracts::CencDashMediaIdentityV2,
) -> String {
    super::super::verify_protected_content_dash_manifest(manifest, head)
        .unwrap_err()
        .to_string()
}

pub(super) fn reseal(manifest: &mut crate::content::ContentObjectManifest) {
    manifest.content_digest = super::super::content_object_digest(&manifest.files);
}

pub(super) fn dash_listing_package_for_test(
    components: &MediaDashComponents,
) -> (
    RuntimeMintDraft,
    super::super::RuntimePortableListingPackage,
) {
    let draft = media_dash_mint_draft(components);
    let record = media_dash_listing_record(&draft, "person:local:creator", "dash", NOW);
    (draft, record.package)
}

pub(crate) fn media_dash_mint_draft(components: &MediaDashComponents) -> RuntimeMintDraft {
    let seed = 0x41;
    let epoch = signed_custody_epoch();
    let head = &components.head;
    let manifest = CustodyEnvelopeManifestV1::new(
        head.encrypted_content().clone(),
        CustodyPoolIdentityV1::new(digest(seed ^ 0x34), 512).unwrap(),
        epoch.epoch_identity().unwrap(),
        CustodyCommitteeAuthorizationIdentityV1::new(digest(seed ^ 0x35), 512).unwrap(),
        ThresholdV1::new(2, 3).unwrap(),
        digest(seed ^ 0x33),
        epoch.statement().nodes().to_vec(),
    )
    .unwrap();
    let envelope = CustodyEnvelopeV1::new(
        manifest,
        [seed ^ 0x50, seed ^ 0x51, seed ^ 0x52]
            .into_iter()
            .map(sealed_share)
            .collect(),
    )
    .unwrap();
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
    RuntimeMintDraft::new_from_identity(
        RuntimeContentIdentityV1::MediaDash(head.clone()),
        content_access_id(seed),
        envelope.key_envelope_identity().unwrap(),
        policy_body_for(
            head.encrypted_content().clone(),
            content_access_id(seed),
            RightsActionV1::View,
        )
        .policy_identity()
        .unwrap(),
        envelope.manifest().content_key_commitment(),
        envelope.manifest().threshold(),
        mint_nodes,
    )
    .unwrap()
}

/// The listing a creator would have published for a v2 draft: the media
/// listing fixture with the identity fields of the draft.
pub(crate) fn media_dash_listing_record(
    draft: &RuntimeMintDraft,
    publisher_principal_id: &str,
    display_name: &str,
    published_at: u64,
) -> super::super::RuntimeCustodyListingRecord {
    let mut record = runtime_custody_listing_record_for_test(
        draft.mint_id(),
        publisher_principal_id,
        display_name,
        published_at,
    );
    let (media_identity_base64, content_identity_base64) =
        super::super::runtime_portable_identity_fields(draft.content_identity()).unwrap();
    let package = &mut record.package;
    package.content_id =
        super::super::runtime_protected_content_id(draft.encrypted_content()).unwrap();
    package.content_access_id = format!("0x{}", hex::encode(draft.content_access_id().as_bytes()));
    package.media_identity_base64 = media_identity_base64;
    package.content_identity_base64 = content_identity_base64;
    package.key_envelope_identity_base64 = base64::engine::general_purpose::STANDARD
        .encode(draft.key_envelope().canonical_bytes().unwrap());
    package.rights_policy_identity_base64 =
        base64::engine::general_purpose::STANDARD.encode(draft.policy().canonical_bytes().unwrap());
    package.content_key_commitment_base64 =
        base64::engine::general_purpose::STANDARD.encode(draft.content_key_commitment().as_bytes());
    record.origin = super::super::RuntimeCustodyListingOrigin::LocalCreator {
        principal_id: publisher_principal_id.to_string(),
        listing_uri: format!("elastos://{}", ContentAvailabilityTestProvider::CID),
        package_sha256: hex::encode(sha2::Sha256::digest(
            serde_json::to_vec(&record.package).unwrap(),
        )),
    };
    record
}

impl ContentAvailabilityTestProvider {
    /// Publishes arbitrary `(path, bytes)` files, bypassing the v1-only
    /// directory walk.
    pub(super) async fn seed_published_files(
        &self,
        files: &[(String, Vec<u8>)],
        object_identity: &str,
        publisher_did: &str,
    ) -> Result<(), ProviderError> {
        let entries = files
            .iter()
            .map(|(path, bytes)| {
                json!({
                    "path": path,
                    "data": base64::engine::general_purpose::STANDARD.encode(bytes),
                })
            })
            .collect::<Vec<_>>();
        self.publish(&json!({
            "op": "publish",
            "object_kind": "protected-content",
            "object_did": object_identity,
            "publisher_did": publisher_did,
            "files": entries,
        }))
        .await?;
        Ok(())
    }

    pub(super) async fn replace_published_file(&self, path: &str, bytes: Vec<u8>) {
        self.files.lock().await.insert(path.to_string(), bytes);
    }

    /// Changes the published manifest, both the one receipts are built from
    /// and the file a fetch returns.
    pub(super) async fn tamper_published_manifest(
        &self,
        edit: impl FnOnce(&mut crate::content::ContentObjectManifest),
    ) {
        let mut guard = self.manifest.lock().await;
        let manifest = guard.as_mut().expect("published manifest");
        edit(manifest);
        self.files.lock().await.insert(
            crate::content::CONTENT_OBJECT_MANIFEST_PATH.to_string(),
            serde_json::to_vec(manifest).unwrap(),
        );
    }

    pub(super) async fn fetched_paths(&self) -> Vec<String> {
        self.requests()
            .await
            .iter()
            .filter(|request| request.get("op").and_then(Value::as_str) == Some("fetch"))
            .filter_map(|request| request.get("path").and_then(Value::as_str))
            .map(str::to_string)
            .collect()
    }
}

/// Journals a v2 draft as provisioned and content-available, the state a
/// published mint is in when a buyer meets it.
pub(super) fn seed_media_dash_mint_journal(
    data_dir: &Path,
    components: &MediaDashComponents,
) -> (RuntimeMintDraft, RuntimeContentAvailabilityRequirement) {
    let data_dir = data_dir.to_path_buf();
    let mint_draft = media_dash_mint_draft(components);
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
    mint_journal
        .mark_custody_provisioned(mint_draft.mint_id())
        .unwrap();

    let expected_provider_did =
        ContentAvailabilityTestProvider::new(0x61, ContentAvailabilityTestConfig::accepted())
            .signer_did();
    let requirement = RuntimeContentAvailabilityRequirement::new(
        expected_provider_did,
        super::super::runtime_protected_content_id(mint_draft.encrypted_content()).unwrap(),
        derived_device_key_for_seed(0x66).1,
        super::super::PROTECTED_CONTENT_REPLICATION_POLICY,
        super::super::PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET,
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
        elastos_protected_content_runtime::RuntimeVerifiedContentIdentityRootV1::for_media_dash(
            &components.head,
        ),
    )
    .unwrap();
    mint_journal
        .mark_content_available(mint_draft.mint_id(), &requirement, evidence)
        .unwrap();
    (mint_draft, requirement)
}

pub(super) struct RuntimeCustodyMediaDashHarness {
    pub(super) base: RuntimeCustodyPrebuyAvailabilityHarness,
    pub(super) components: MediaDashComponents,
}

/// Twin of `runtime_custody_prebuy_availability_harness` for a v2 mint: a
/// `MediaDash` draft journalled as available, its listing, and the real
/// package published to the content test provider.
pub(super) async fn runtime_custody_media_dash_availability_harness(
    components: MediaDashComponents,
    provider_config: ContentAvailabilityTestConfig,
) -> RuntimeCustodyMediaDashHarness {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&data_dir.join("protected-content"));
    write_device_key(&data_dir, 0x61);
    write_library_publish_test_composition(&data_dir);

    let (mint_draft, requirement) = seed_media_dash_mint_journal(&data_dir, &components);
    let fixture_now = crate::auth::now_ts();
    let listing = media_dash_listing_record(
        &mint_draft,
        "person:local:creator",
        "protected-video.mp4",
        fixture_now.saturating_sub(2),
    );
    super::super::persist_runtime_custody_listing(&data_dir, &listing).unwrap();

    let content_provider = ContentAvailabilityTestProvider::new(0x61, provider_config);
    content_provider
        .seed_published_files(
            &components_package_files(&components),
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
    RuntimeCustodyMediaDashHarness {
        base: RuntimeCustodyPrebuyAvailabilityHarness {
            _temp: temp,
            data_dir,
            registry,
            content_provider,
            mint_id: mint_draft.mint_id(),
        },
        components,
    }
}

/// A v2 listing a gateway test can persist and list, over a real protected
/// package of `kinds` with `counts` segments each.
#[cfg(unix)]
pub(crate) fn seeded_media_dash_listing_for_test(
    kinds: &[elastos_protected_content_provider_contracts::CencDashRenditionKindV2],
    counts: &[usize],
) -> super::super::RuntimeCustodyListingRecord {
    let components = media_dash_components(kinds, counts);
    let draft = media_dash_mint_draft(&components);
    media_dash_listing_record(&draft, "person:local:creator", "dash.mp4", NOW)
}

/// Seeds a v2 mint a buyer already owns, in `data_dir`: the journalled mint,
/// its listing and the buyer's purchase. Returns the mint id as hex.
#[cfg(unix)]
pub(crate) fn seed_media_dash_purchase_for_gateway_test(
    data_dir: &Path,
    principal_id: &str,
) -> String {
    let components = media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]);
    let (draft, _) = seed_media_dash_mint_journal(data_dir, &components);
    let listing = media_dash_listing_record(&draft, "person:local:creator", "dash.mp4", NOW);
    super::super::persist_runtime_custody_listing(data_dir, &listing).unwrap();
    let mint = runtime_mint_journal(data_dir)
        .load(draft.mint_id())
        .unwrap();
    persist_runtime_custody_purchase_for_mint(
        data_dir,
        &mint,
        principal_id,
        &load_profile_did_for_test(data_dir, principal_id),
        crate::auth::now_ts(),
    );
    hex::encode(draft.mint_id().as_bytes())
}

/// A harness plus a buyer with an active v2 viewer session, ready to read.
pub(super) struct DashViewer {
    pub(super) harness: RuntimeCustodyMediaDashHarness,
    pub(super) principal_id: String,
    pub(super) proof_binding_id: String,
    pub(super) session: RuntimeViewerSession,
}

#[cfg(unix)]
pub(super) async fn dash_viewer(components: MediaDashComponents, label: &str) -> DashViewer {
    let harness = runtime_custody_media_dash_availability_harness(
        components,
        ContentAvailabilityTestConfig::accepted_now(),
    )
    .await;
    let principal_id = format!("person:local:dash-{label}");
    let (proof_binding_id, _) =
        install_profile_authority_keeping_device_key(&harness.base.data_dir, &principal_id);
    let profile_did = load_profile_did_for_test(&harness.base.data_dir, &principal_id);
    let mint = runtime_mint_journal(&harness.base.data_dir)
        .load(harness.base.mint_id)
        .unwrap();
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.base.data_dir,
        &mint,
        &principal_id,
        &profile_did,
        crate::auth::now_ts(),
    );
    let session = persist_runtime_custody_active_viewer_for_purchase(
        &harness.base.data_dir,
        &mint,
        &purchase,
        &proof_binding_id,
        "runtime-session:alpha",
        "grant:alpha",
        opaque_handle(0x21),
        crate::auth::now_ts() + 60,
    );
    make_runtime_custody_listing_imported_without_creator_mint(
        &harness.base.data_dir,
        mint.draft().mint_id(),
    );
    DashViewer {
        harness,
        principal_id,
        proof_binding_id,
        session,
    }
}

#[cfg(unix)]
impl DashViewer {
    pub(super) fn data_dir(&self) -> &Path {
        &self.harness.base.data_dir
    }

    pub(super) fn mint_id(&self) -> Digest32 {
        self.harness.base.mint_id
    }

    pub(super) async fn read(
        &self,
        segment_index: Option<u32>,
        chunk_index: Option<u32>,
    ) -> anyhow::Result<Value> {
        super::super::read_runtime_custody_viewer(
            self.data_dir(),
            self.harness.base.registry.clone(),
            &self.principal_id,
            &hex::encode(self.mint_id().as_bytes()),
            &hex::encode(self.session.viewer_session_handle()),
            TEST_VIEWER_EXECUTABLE_ACTOR,
            Some(TEST_VIEWER_LAUNCH_ID),
            Some(&self.proof_binding_id),
            Some("runtime-session:alpha"),
            Some("grant:alpha"),
            segment_index,
            chunk_index,
        )
        .await
    }

    pub(super) fn record(&self) -> super::super::RuntimeCustodyViewerRecord {
        super::super::load_runtime_custody_viewer_record(
            self.data_dir(),
            &self.principal_id,
            self.mint_id(),
        )
        .unwrap()
        .unwrap()
    }

    pub(super) fn set_next_part(&self, next: u32) {
        let mut record = self.record();
        record.next_media_part_index = next;
        super::super::persist_runtime_custody_viewer_record(
            self.data_dir(),
            &self.principal_id,
            self.mint_id(),
            &record,
        )
        .unwrap();
    }

    pub(super) fn stage_leaves(&self) {
        super::super::stage_runtime_custody_media_dash_leaves(
            self.data_dir(),
            &self.principal_id,
            self.mint_id(),
            &self.harness.components.head,
            &dash_all_leaves(&self.harness.components),
        )
        .unwrap();
    }

    pub(super) fn leaves_path(&self) -> PathBuf {
        super::super::runtime_viewer_leaves_path(
            self.data_dir(),
            &self.principal_id,
            self.mint_id(),
        )
    }

    /// The reads a full playback performs, in order, as the decrypt provider
    /// must see them: `(selector, clear part it answers with)`.
    pub(super) fn expected_reads(&self) -> Vec<(ViewerMediaPartSelectorV1, Vec<u8>)> {
        let components = &self.harness.components;
        let leaves = dash_all_leaves(components);
        let mut reads = Vec::new();
        for rendition in 0..components.kinds.len() {
            reads.push((
                ViewerMediaPartSelectorV1::init_v2(rendition as u8).unwrap(),
                vec![0x10 + rendition as u8],
            ));
        }
        let longest = components
            .protected_segments
            .iter()
            .map(Vec::len)
            .max()
            .unwrap();
        for index in 0..longest {
            for (rendition, segments) in components.protected_segments.iter().enumerate() {
                if let Some(segment) = segments.get(index) {
                    reads.push((
                        ViewerMediaPartSelectorV1::segment_v2(
                            rendition as u8,
                            index as u32,
                            segment.clone(),
                            dash_proof(&leaves[rendition], index),
                        )
                        .unwrap(),
                        vec![0xc0 + rendition as u8, index as u8],
                    ));
                }
            }
        }
        reads
    }

    /// Registers a decrypt provider that answers `reads` in order, echoing
    /// each selector as the real provider does.
    pub(super) async fn register_decrypt(
        &self,
        reads: &[(ViewerMediaPartSelectorV1, Vec<u8>)],
    ) -> Arc<SequencedProvider> {
        let audit = RuntimeReleaseAuditIdV1::new(self.session.audit_request_id()).unwrap();
        let provider = SequencedProvider::new(
            "decrypt",
            reads
                .iter()
                .map(|(selector, clear)| {
                    Ok(ok_provider_response(
                        serde_json::to_value(
                            DecryptProviderResponseV1::new_viewer_media_part(
                                audit,
                                *self.session.viewer_session_handle(),
                                selector.clone(),
                                clear.clone(),
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    ))
                })
                .collect(),
        );
        self.harness
            .base
            .registry
            .register_runtime_provider_target(
                PROTECTED_CONTENT_DECRYPT_PROVIDER_ID,
                provider.clone(),
            )
            .await
            .unwrap();
        provider
    }

    pub(super) fn assert_decrypt_requests(
        &self,
        recorded: &[Value],
        reads: &[(ViewerMediaPartSelectorV1, Vec<u8>)],
    ) {
        assert_eq!(recorded.len(), reads.len());
        for (recorded, (selector, _)) in recorded.iter().zip(reads) {
            let expected = DecryptProviderRequestV1::new_read_viewer_media_part(
                RuntimeReleaseAuditIdV1::new(self.session.audit_request_id()).unwrap(),
                *self.session.viewer_session_handle(),
                selector.clone(),
            )
            .unwrap();
            assert_exact_runtime_decrypt_invocation(
                recorded,
                "read_viewer_media_part",
                &serde_json::to_value(&expected).unwrap(),
            );
        }
    }
}

pub(super) fn decoded_part(answer: &Value) -> Vec<u8> {
    assert_eq!(
        answer["schema"],
        "elastos.library.runtime-custody-viewer-part/v1"
    );
    base64::engine::general_purpose::STANDARD
        .decode(answer["data"].as_str().unwrap())
        .unwrap()
}

/// What a test media provider says it prepared, as the provider's JSON.
#[cfg(unix)]
pub(super) fn prepared_output_for_test(
    renditions: &[(&str, &str, &str, usize)],
) -> super::super::RuntimePreparedMediaProviderOutputV2 {
    serde_json::from_value(json!({
        "schema": "elastos.media-provider.prepared-media/v2",
        "renditions": renditions.iter().map(|(name, mime, codecs, count)| json!({
            "rendition": name,
            "mime_type": mime,
            "codecs": codecs,
            "segment_count": count,
        })).collect::<Vec<_>>(),
    }))
    .unwrap()
}

#[cfg(unix)]
pub(super) const TEST_VIDEO_DECL: (&str, &str, &str) = ("video", "video/mp4", "avc1.640028");

#[cfg(unix)]
pub(super) const TEST_AUDIO_DECL: (&str, &str, &str) = ("audio", "audio/mp4", "mp4a.40.2");

/// A fresh owner-only operation root holding a prepared v2 tree.
#[cfg(unix)]
pub(super) fn prepared_root_for_test(
    renditions: &[(CencDashRenditionKindV2, usize)],
) -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let operation_root = temp.path().join("operation");
    owner_only_dir(&operation_root);
    write_prepared_media_v2(&operation_root, renditions);
    (temp, operation_root)
}

/// The preparation receipt recomputed from the spec's framing alone: a
/// rendition count, then per rendition its kind code, pinned pair, init length
/// and hash, segment count, and per segment its index, length and hash.
#[cfg(unix)]
pub(super) fn independent_preparation_receipt(
    renditions: &[(CencDashRenditionKindV2, usize)],
) -> Digest32 {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"elastos.protected-content.runtime-media-preparation-receipt/v1");
    hasher.update([renditions.len() as u8]);
    for (kind, count) in renditions {
        let (code, mime, codecs) = match *kind {
            DASH_VIDEO => (1u8, "video/mp4", "avc1.640028"),
            DASH_AUDIO => (2u8, "audio/mp4", "mp4a.40.2"),
        };
        let init = media_dash_fixture::init(*kind, 1);
        hasher.update([code]);
        hasher.update(mime.as_bytes());
        hasher.update([0]);
        hasher.update(codecs.as_bytes());
        hasher.update([0]);
        hasher.update((init.len() as u64).to_be_bytes());
        hasher.update(sha2::Sha256::digest(&init));
        hasher.update((*count as u64).to_be_bytes());
        for (index, segment) in media_dash_fixture::clear_segments(*kind, *count)
            .iter()
            .enumerate()
        {
            hasher.update((index as u64).to_be_bytes());
            hasher.update((segment.len() as u64).to_be_bytes());
            hasher.update(sha2::Sha256::digest(segment));
        }
    }
    Digest32::new(hasher.finalize().into())
}

/// A clear video segment of exactly `len` bytes whose timeline starts at 0.
#[cfg(unix)]
pub(super) fn video_segment_of_len(len: usize) -> Vec<u8> {
    let probe = media_dash_fixture::clear_segment(
        1,
        0,
        &[
            media_dash_fixture::video_sample(1_000),
            media_dash_fixture::video_sample(200),
        ],
    );
    let slice = 1_000 + len - probe.len();
    let segment = media_dash_fixture::clear_segment(
        1,
        0,
        &[
            media_dash_fixture::video_sample(slice),
            media_dash_fixture::video_sample(200),
        ],
    );
    assert_eq!(segment.len(), len);
    segment
}

#[cfg(unix)]
pub(super) fn audio_decl(count: usize) -> (&'static str, &'static str, &'static str, usize) {
    (
        TEST_AUDIO_DECL.0,
        TEST_AUDIO_DECL.1,
        TEST_AUDIO_DECL.2,
        count,
    )
}

/// A mint run end to end over mock protect, custody, chain and content
/// providers, with a real prepared v2 tree under the data directory.
#[cfg(unix)]
pub(super) struct LibraryMintHarness {
    pub(super) _temp: tempfile::TempDir,
    pub(super) data_dir: PathBuf,
    pub(super) registry: Arc<ProviderRegistry>,
    pub(super) epoch: SignedCustodyEpochV1,
    pub(super) composition_now: u64,
    pub(super) input: RuntimeCustodyLibraryPublishInput,
    pub(super) content: Arc<ContentAvailabilityTestProvider>,
}

#[cfg(unix)]
pub(super) const TEST_PROTECT_HANDLE: [u8; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1] =
    [0x4c; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];

#[cfg(unix)]
pub(super) async fn library_mint_harness(
    principal: &str,
    renditions: &[(CencDashRenditionKindV2, usize)],
) -> LibraryMintHarness {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let (epoch, composition_now) = write_library_publish_test_composition(&data_dir);
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(
            CUSTODY_PROVIDER_ID,
            Arc::new(LibraryMintCustodyProvider {
                expected_issuer: derived_device_runtime_issuer(0x21),
                nodes: epoch
                    .statement()
                    .nodes()
                    .iter()
                    .map(|node| node.node_public_key())
                    .collect(),
            }),
        )
        .await
        .unwrap();
    registry
        .set_carrier_invoker(Arc::new(LoopbackCustodyCarrierInvoker {
            registry: Arc::downgrade(&registry),
        }))
        .await;
    registry
        .register_sub_provider(CHAIN_PROVIDER_ID, Arc::new(LibraryMintChainPolicyProvider))
        .await
        .unwrap();
    install_profile_authority_keeping_device_key(&data_dir, principal);
    let (device_key, _) = derived_device_key_for_seed(0x21);
    let content = ContentAvailabilityTestProvider::with_signing_key(
        device_key,
        ContentAvailabilityTestConfig {
            // An 80 MiB object publish can outlast the receipt's freshness
            // window on a slow runner; a stamp taken here would then be stale
            // by the time the receipt is checked.
            stamp_at_issue: true,
            ..ContentAvailabilityTestConfig::accepted()
        },
    );
    registry
        .register_sub_provider("content", content.clone())
        .await
        .unwrap();
    let input = library_publish_test_input_with_renditions(&data_dir, principal, renditions);
    LibraryMintHarness {
        _temp: temp,
        data_dir,
        registry,
        epoch,
        composition_now,
        input,
        content,
    }
}

#[cfg(unix)]
impl LibraryMintHarness {
    /// The persisted intent and the protected package an honest protect
    /// provider would answer it with.
    pub(super) fn honest_protect(
        &self,
    ) -> (
        RuntimeMintIntent,
        media_dash_fixture::MediaDashComponents,
        CustodyEnvelopeV1,
    ) {
        let intent = persisted_test_mint_intent(&self.data_dir, &self.registry, &self.input);
        let (components, envelope) = protect_input_for_test(
            &self.input,
            &intent,
            &self.epoch,
            self.composition_now,
            &|_, init| init,
        );
        (intent, components, envelope)
    }

    pub(super) async fn register_protect(
        &self,
        script: Vec<Result<Value, ProviderError>>,
    ) -> Arc<MediaDashProtectTestProvider> {
        let protect =
            MediaDashProtectTestProvider::new(script, Some(self.input.media.part_reads()));
        self.registry
            .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect.clone())
            .await
            .unwrap();
        protect
    }

    pub(super) async fn publish(
        &self,
    ) -> anyhow::Result<super::super::RuntimeCustodyLibraryPublishFacts> {
        publish_runtime_custody_library_object(
            &self.data_dir,
            self.registry.clone(),
            self.input.clone(),
        )
        .await
    }

    /// No staging directory of a mint is left behind.
    pub(super) fn assert_no_staging(&self) {
        let leftovers: Vec<_> = fs::read_dir(protected_content_root(&self.data_dir))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("publish-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }
}

#[cfg(unix)]
pub(super) fn closed_protect_response() -> Result<Value, ProviderError> {
    Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_closed(TEST_PROTECT_HANDLE).unwrap(),
    ))
}

#[cfg(unix)]
pub(super) fn cancelled_protect_response() -> Result<Value, ProviderError> {
    Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_cancelled(TEST_PROTECT_HANDLE).unwrap(),
    ))
}

#[cfg(unix)]
pub(super) fn uuid_text(bytes: &[u8; 16]) -> String {
    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The MPD of `components` as an independent build: timelines from the clear
/// segments, sizes from the protected ones.
#[cfg(unix)]
pub(super) fn expected_dash_mpd(
    input: &RuntimeCustodyLibraryPublishInput,
    components: &media_dash_fixture::MediaDashComponents,
) -> String {
    let (kinds, counts) = test_input_layout(input);
    let clear = media_dash_fixture::clear_media_dash(&kinds, &counts);
    let segments: Vec<Vec<elastos_protected_content_provider_contracts::CencDashMpdSegmentV2>> =
        clear
            .iter()
            .zip(&components.protected_segments)
            .map(|((_, init, clear_segments), protected)| {
                let session = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
                    init,
                    elastos_protected_content_provider_contracts::CencLayoutProfile::V2,
                )
                .unwrap();
                clear_segments
                    .iter()
                    .zip(protected)
                    .map(|(segment, protected)| {
                        elastos_protected_content_provider_contracts::CencDashMpdSegmentV2 {
                            timeline: session
                                .validate_segment(segment)
                                .unwrap()
                                .timeline()
                                .unwrap(),
                            bytes: protected.len() as u64,
                        }
                    })
                    .collect()
            })
            .collect();
    elastos_protected_content_provider_contracts::build_cenc_dash_mpd_v2(
        &components
            .protected_inits
            .iter()
            .zip(&segments)
            .map(|(protected_init, segments)| {
                elastos_protected_content_provider_contracts::CencDashMpdRenditionV2 {
                    protected_init,
                    segments,
                }
            })
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

/// Everything a refused mint must NOT have left: no draft, no staging, and the
/// protect session settled.
#[cfg(unix)]
pub(super) fn assert_refused_before_any_draft(
    harness: &LibraryMintHarness,
    intent: &RuntimeMintIntent,
    requests: &[Value],
) {
    let scan = runtime_mint_journal(&harness.data_dir)
        .find_mint_record_for_intent(intent.request_id())
        .unwrap();
    assert!(scan.open().is_none() && scan.abandoned().is_empty());
    assert_eq!(
        requests.last().unwrap()["op"],
        "cancel_protection_session",
        "the refused session must still be settled: {requests:?}"
    );
    harness.assert_no_staging();
}

/// The staged package of `components`, written the way the mint stages it.
#[cfg(unix)]
pub(super) fn stage_dash_package(
    components: &media_dash_fixture::MediaDashComponents,
    mpd: &[u8],
) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    for (path, bytes) in components_package_files(components) {
        let bytes = if path == DASH_MPD_FILE {
            mpd.to_vec()
        } else {
            bytes
        };
        let target = directory.path().join(&path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, bytes).unwrap();
    }
    directory
}

/// An in-process protect provider that answers a precomputed script and
/// remembers only the operation names, so an 80 MiB mint does not retain its
/// own request bodies.
#[cfg(unix)]
pub(super) struct ObjectProtectTestProvider {
    pub(super) responses: Mutex<VecDeque<Result<Value, ProviderError>>>,
    pub(super) ops: Mutex<Vec<String>>,
}

#[cfg(unix)]
#[async_trait::async_trait]
impl Provider for ObjectProtectTestProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "object protect test provider is invoke-only".to_string(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![PROTECT_PROVIDER_ID]
    }

    fn name(&self) -> &'static str {
        PROTECT_PROVIDER_ID
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.ops
            .lock()
            .await
            .push(request["op"].as_str().unwrap_or_default().to_string());
        self.responses.lock().await.pop_front().unwrap_or_else(|| {
            Err(ProviderError::Provider(
                "object protect test provider script is exhausted".to_string(),
            ))
        })
    }
}

#[cfg(unix)]
pub(super) struct ObjectMintFixture {
    pub(super) harness: LibraryMintHarness,
    pub(super) input: RuntimeCustodyLibraryPublishObjectInput,
    pub(super) protect: Arc<ObjectProtectTestProvider>,
    pub(super) sealed: UnprovisionedSealedPayloadV1,
    pub(super) plaintext: Vec<u8>,
    pub(super) max_framed_chunk: usize,
}

/// A mint of `plaintext_bytes` through an honest, scripted object protect
/// provider. A real sealer produced every response, so the Runtime's identity
/// and envelope checks run for real. `fail_at_chunk` makes that chunk fail.
#[cfg(unix)]
pub(super) async fn object_mint_fixture(
    principal: &str,
    plaintext_bytes: usize,
    fail_at_chunk: Option<usize>,
) -> ObjectMintFixture {
    let harness = library_mint_harness(principal, &[(DASH_VIDEO, 1)]).await;
    let plaintext: Vec<u8> = (0..plaintext_bytes)
        .map(|index| (index % 251) as u8)
        .collect();
    let (mut sealer, framed_header) =
        PayloadSealerV1::open("application/pdf", plaintext_bytes as u64).unwrap();
    let mut script = vec![Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_object_opened(&framed_header).unwrap(),
    ))];
    let mut max_framed_chunk = 0;
    for (index, chunk) in plaintext.chunks(1_048_576).enumerate() {
        let framed = sealer.seal_chunk(index as u32, chunk).unwrap();
        max_framed_chunk = max_framed_chunk.max(framed.len());
        if fail_at_chunk == Some(index) {
            script.push(Err(ProviderError::Provider("scripted failure".to_string())));
            script.push(cancelled_protect_response());
        }
        if fail_at_chunk.is_some_and(|failed| index >= failed) {
            continue;
        }
        script.push(Ok(ok_typed_protect_provider_response(
            ProtectProviderResponseV1::new_object_chunk_protected(&framed).unwrap(),
        )));
    }
    let sealed = sealer.finish_unprovisioned().unwrap();
    if fail_at_chunk.is_none() {
        let committee =
            validated_custody_committee_for_epoch(&harness.epoch, harness.composition_now);
        let envelope = provision_custody_envelope(
            sealed.encrypted_content_identity().clone(),
            sealed.content_key(),
            &committee,
        )
        .unwrap();
        let identity = ChunkedPayloadObjectIdentityV1::new(
            sealed.encrypted_content_identity().clone(),
            "application/pdf",
            plaintext_bytes as u64,
            u32::try_from(framed_header.len()).unwrap(),
        )
        .unwrap();
        script.push(Ok(ok_typed_protect_provider_response(
            ProtectProviderResponseV1::new_object_finalized(
                &identity,
                envelope.manifest().content_key_commitment(),
                &envelope,
            )
            .unwrap(),
        )));
        script.push(closed_protect_response());
    }
    let protect = Arc::new(ObjectProtectTestProvider {
        responses: Mutex::new(script.into()),
        ops: Mutex::new(Vec::new()),
    });
    harness
        .registry
        .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect.clone())
        .await
        .unwrap();
    let input = RuntimeCustodyLibraryPublishObjectInput {
        object_uri: format!(
            "{}/Documents/large.pdf",
            crate::auth::principal_localhost_root(principal)
        ),
        principal_id: principal.to_string(),
        content_type: "application/pdf".to_string(),
        wallet_account_id: "wallet-account-1".to_string(),
        wallet_account_address: "0x1111111111111111111111111111111111111111".to_string(),
        creator_mint_source_digest: digest(0x71),
        copies: "0x1".to_string(),
        price: "5".to_string(),
        channel: "0x0000000000000000000000000000000000000022".to_string(),
        pay_token: String::new(),
        clear_plaintext: plaintext.clone(),
        source_storage: "plain_localhost_root".to_string(),
        listing: None,
        pool_did: None,
    };
    ObjectMintFixture {
        harness,
        input,
        protect,
        sealed,
        plaintext,
        max_framed_chunk,
    }
}

#[cfg(unix)]
pub(super) async fn object_epc1_fetches(harness: &LibraryMintHarness) -> usize {
    harness
        .content
        .requests()
        .await
        .iter()
        .filter(|request| {
            request["op"] == "fetch" && request["path"] == PROTECTED_CONTENT_OBJECT_EPC1_PATH
        })
        .count()
}

#[cfg(unix)]
pub(super) fn custody_status_with_roots(node_public_key_hex: &str) -> Value {
    let mut status = ProtectedStartupProvider::Custody.status();
    status["data"]["roots"] = json!([{
        "path": "inactive",
        "node_public_key": node_public_key_hex,
        "configured": true,
        "shares_held": 3,
    }]);
    status
}

/// A custody provider stand-in that answers `init` and `status` alike with a
/// status listing one configured root per `"path"` in the last init it was
/// sent, and logs every frame.
#[cfg(unix)]
pub(super) fn write_mock_root_set_custody_provider(root: &Path) -> (PathBuf, PathBuf) {
    let binary = root.join("mock-root-set-custody-provider.sh");
    let request_log = root.join("mock-root-set-custody-provider.requests");
    let base = ProtectedStartupProvider::Custody.status();
    let data = base["data"].clone();
    let script = format!(
        "#!/bin/sh\nset -eu\nroots='[]'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{log}'\n  case \"$line\" in\n    *'\"op\":\"shutdown\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}'; exit 0 ;;\n    *'\"op\":\"init\"'*) roots=$(printf '%s' \"$line\" | sed -n 's/.*\"roots\":\\(\\[[^]]*\\]\\).*/\\1/p' | sed 's/{{\"path\":\\(\"[^\"]*\"\\)}}/{{\"path\":\\1,\"node_public_key\":null,\"configured\":true,\"shares_held\":0}}/g'); [ -n \"$roots\" ] || roots='[]' ;;\n  esac\n  case \"$line\" in\n    *'\"op\":\"init\"'*|*'\"op\":\"status\"'*) printf '{{\"status\":\"ok\",\"data\":{{\"provider\":\"{provider}\",\"version\":\"{version}\",\"configured\":true,\"supported_operations\":%s,\"request_schema\":\"{request}\",\"response_schema\":\"{response}\",\"roots\":%s}}}}\\n' '{ops}' \"$roots\" ;;\n    *) printf '%s\\n' '{{\"status\":\"ok\",\"data\":{{}}}}' ;;\n  esac\ndone\n",
        log = request_log.display(),
        provider = data["provider"].as_str().unwrap(),
        version = data["version"].as_str().unwrap(),
        request = data["request_schema"].as_str().unwrap(),
        response = data["response_schema"].as_str().unwrap(),
        ops = data["supported_operations"],
    );
    crate::test_support::write_from_child(&binary, &script, 0o700);
    (binary, request_log)
}

/// S2-F1: the mock root-set provider, where `init` answers an error while
/// `refuse_init` exists, and `shutdown` exits with `shutdown_exit`.
#[cfg(unix)]
pub(super) fn write_failing_root_set_custody_provider(
    root: &Path,
    refuse_init: &Path,
    shutdown_exit: u8,
) -> PathBuf {
    let (plain, _) = write_mock_root_set_custody_provider(root);
    let script = fs::read_to_string(&plain).unwrap();
    let log_line_end = script.find("\n  case ").unwrap();
    let mut script = format!(
        "{}\n  case \"$line\" in *'\"op\":\"init\"'*) if [ -e '{}' ]; then printf '%s\\n' '{{\"status\":\"error\",\"code\":\"init_failed\",\"message\":\"refused\"}}'; continue; fi ;; esac{}",
        &script[..log_line_end],
        refuse_init.display(),
        &script[log_line_end..],
    );
    script = script.replacen("exit 0 ;;", &format!("exit {shutdown_exit} ;;"), 1);
    let binary = root.join("failing-root-set-custody-provider.sh");
    crate::test_support::write_from_child(&binary, &script, 0o700);
    binary
}

#[cfg(unix)]
pub(super) fn plant_served_entry(data_dir: &Path, hex: &str) {
    crate::custody_consent::update_served_pools(data_dir, |pools| {
        pools.entries.insert(
            format!("sha256:{hex}"),
            crate::custody_consent::ServedPoolEntryV2 {
                owner_home: "did:key:z6MkOwner".to_string(),
                consent: crate::custody_consent::ServedConsentV2 {
                    term_days: 365,
                    signing_key_fingerprint_full: format!("sha256:{hex}"),
                },
                root_path: format!("pools/{hex}"),
                admin_profile_did: Some("did:key:z6MkAdmin".to_string()),
                pool_did: None,
                served_pool: None,
                descriptor: None,
            },
        );
        Ok(())
    })
    .unwrap();
}

#[cfg(unix)]
pub(super) fn refusal_code(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<crate::custody_pool_setup::CustodyRefusal>()
        .unwrap_or_else(|| panic!("expected a custody refusal, got {error:#}"))
        .code()
}

/// A custody target this server did not start (no remembered bridge) whose
/// first shutdown fails, so the registry keeps it Settling.
pub(super) struct SettlingCustodyProvider {
    pub(super) refuse_shutdown: AtomicBool,
}

#[async_trait::async_trait]
impl Provider for SettlingCustodyProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider("invoke-only".to_string()))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["custody"]
    }

    fn name(&self) -> &'static str {
        "custody"
    }

    async fn shutdown(&self) -> Result<(), ProviderError> {
        if self.refuse_shutdown.swap(false, Ordering::SeqCst) {
            return Err(ProviderError::Provider(
                "shutdown did not finish".to_string(),
            ));
        }
        Ok(())
    }
}

/// A serving Home whose Remove stopped after its own root went to the
/// tombstone: the node file and the tombstone are left.
#[cfg(unix)]
pub(super) fn interrupted_removal_home(
    with_served_root: bool,
) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let temp = safe_ancestor_tempdir();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    crate::host_trust::seed_for_test(&data_dir, true);
    elastos_identity::load_or_create_device_key(&data_dir).unwrap();
    let base = inactive_custody_state_root(&data_dir)
        .parent()
        .unwrap()
        .to_path_buf();
    for dir in [
        base.parent().unwrap().to_path_buf(),
        base.clone(),
        base.join("pools"),
    ] {
        owner_only_dir(&dir);
    }
    if with_served_root {
        owner_only_dir(&base.join(format!("pools/{}", "e".repeat(64))));
    }
    let tombstone = base.join(format!("pools/{}.removing", "d".repeat(64)));
    owner_only_dir(&tombstone);
    crate::custody_pool_setup::tests::write_local_node(&data_dir, "Home", "Paris");
    let node_file = crate::custody_pool_setup::local_node_path(&data_dir);
    (temp, data_dir, node_file, tombstone)
}

/// The checked-in viewer contract the Reader and Player tests parse too.
pub(super) const VIEWER_CONTRACT: &str = include_str!("../viewer_contract.json");

/// Values the contract fixes, not just their type.
pub(super) const VIEWER_CONTRACT_CONSTANTS: [&str; 4] =
    ["schema", "content_kind", "encoding", "has_init_segment"];

/// The shape of a reply: every key with its value type, recursively, plus
/// the contract constants by value.
pub(super) fn viewer_reply_shape(value: &Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, field)| {
                    let shape = if VIEWER_CONTRACT_CONSTANTS.contains(&key.as_str()) {
                        field.clone()
                    } else {
                        viewer_reply_shape(field)
                    };
                    (key.clone(), shape)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(viewer_reply_shape).collect()),
        Value::String(_) => json!("string"),
        Value::Number(_) => json!("number"),
        Value::Bool(_) => json!("bool"),
        Value::Null => json!("null"),
    }
}

/// A real custody child plus Runtime wrapper per node. The fixture keeps
/// node-side sequence 2 protection and dispatches from an unrelated Runtime
/// through the receiving Carrier provider boundary, with no peer grants.
#[cfg(unix)]
pub(crate) async fn assert_same_epoch_custody_wrapper_boundary_for_test(
    descriptor: &elastos_protected_content_contracts::SignedPoolDescriptorAnyV1,
    envelope: &CustodyEnvelopeV1,
    now: u64,
) {
    use elastos_protected_content_contracts::test_fixtures as fixture;
    use elastos_protected_content_contracts::{
        RuntimeReleaseOperationAnyV1, RuntimeReleaseOperationStatementV2,
        SignedRuntimeReleaseOperationV2,
    };
    use elastos_protected_content_custody::NodeLocalShareStoreV1;
    let binary = required_test_binary_path(TEST_CUSTODY_PROVIDER_BIN_ENV);
    let temp = crate::protected_content_config::tests::safe_ancestor_tempdir();
    // The evidence fixture observes the current second minus one. Its
    // complete release bundle must already exist at that observation time.
    let operation_time = now.saturating_sub(1);
    let mut spec = fixture::PoolReleaseSpecV1::new(
        xwing_public_key_bytes,
        policy_body_for(
            envelope.manifest().encrypted_content().clone(),
            ContentAccessIdV1::new([0x44; 16]).unwrap(),
            RightsActionV1::View,
        ),
        operation_time,
    );
    spec.runtime_seed = 0x79; // reader Runtime differs from the minter (0x43)
    spec.key_envelope = Some(envelope.key_envelope_identity().unwrap());
    spec.descriptor_sequence = descriptor.sequence();
    let supplied = fixture::pool_release_fixture(&spec);
    let original = supplied.operation.statement();
    // Use the exact descriptor the reader resolved, not one built by the
    // fake Wallet or silently substituted by a release transport.
    let statement = RuntimeReleaseOperationStatementV2::new(
        original.runtime_operation_issuer(),
        original.rights_request().clone(),
        original.recipients().to_vec(),
        original.policy_body().clone(),
        original.evidence_request().clone(),
        descriptor.clone(),
        original.audit_request_id(),
        operation_time,
        original.expires_at(),
    )
    .unwrap();
    let operation = RuntimeReleaseOperationAnyV1::V2(
        SignedRuntimeReleaseOperationV2::new(
            statement.clone(),
            fixture::signing_key(0x79)
                .sign(&statement.canonical_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap(),
    );
    operation
        .verify(
            elastos_protected_content_contracts::RuntimeIssuerPolicyV1::Declared,
            now,
        )
        .unwrap();
    // The first real child may ask for evidence within this same second.
    // Assert the fixture's actual evidence passes the production binding
    // check then, rather than depending on child startup crossing a tick.
    let first_request =
        RightsProviderRequestV1::new_evaluate_any(fixture::node_public_key(1), &operation).unwrap();
    let first_evidence = chain_evidence_for_request_at(&first_request, now, now, true);
    let evidence = RightsEvaluationEvidenceV1::from_canonical_bytes(
        &hex::decode(
            first_evidence["rights_evaluation_evidence"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let validated = ValidatedRightsProviderRequestV1::decode_and_validate_at(
        &first_request.to_json_vec().unwrap(),
        now,
    )
    .unwrap();
    let binding = evidence.validate_against_runtime_release_any_at(
        validated.authenticated_runtime_release_operation(),
        now,
    );
    assert!(
        binding.is_ok(),
        "the real-wrapper fixture must supply valid same-second evidence: {binding:?}"
    );
    let source = iroh::SecretKey::from_bytes(&[0x79; 32]).public();
    let mut decisions = 0;
    let mut outcomes = Vec::new();
    let public_code = |value: &Value| {
        value
            .get("code")
            .or_else(|| value.pointer("/error/code"))
            .or_else(|| value.pointer("/data/code"))
            .and_then(Value::as_str)
            .filter(|code| {
                !code.is_empty()
                    && code.len() <= 64
                    && code
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            })
            .unwrap_or("missing_code")
            .to_string()
    };
    for seed in 1u8..=3 {
        let home = temp.path().join(format!("node-{seed}"));
        owner_only_dir(&home);
        owner_only_dir(&home.join("protected-content"));
        owner_only_dir(&home.join("protected-content/custody-provider"));
        let root = inactive_custody_state_root(&home);
        owner_only_dir(&root);
        let data = root.join("data");
        owner_only_dir(&data);
        write_owner_only_bytes(
            &root.join("node-signing-key"),
            hex::encode([seed; 32]).as_bytes(),
        )
        .unwrap();
        write_owner_only_bytes(
            &root.join("node-custody-secret"),
            hex::encode([fixture::CUSTODY_KEY_SEED_BASE + seed; 32]).as_bytes(),
        )
        .unwrap();
        write_owner_only_bytes(
            &root.join("trusted-runtime-issuer"),
            hex::encode(fixture::runtime_issuer(0x43).as_bytes()).as_bytes(),
        )
        .unwrap();
        let loaded = custody_provider::load_state_from_root(&root).unwrap();
        let node = fixture::node_public_key(seed);
        assert_eq!(loaded.node_public_key, node);
        let record = CustodyNodeProvisioningRecordV1::new(
            envelope.key_envelope_identity().unwrap(),
            envelope.manifest().clone(),
            node,
            envelope.stored_share_for_node(node).unwrap().clone(),
        )
        .unwrap();
        let provisioning = fixture::runtime_custody_provisioning(&record, 0x43, 0xf1, now - 3);
        NodeLocalShareStoreV1::new(node, data.join(custody_provider::NODE_SHARE_STORE_DIR))
            .provision_node_share(
                &record,
                &provisioning,
                fixture::runtime_issuer(0x43),
                &loaded.node_custody_secret,
                now,
            )
            .unwrap();
        let high_water = custody_provider::PoolDescriptorHighWaterV1::new(&data);
        high_water
            .record(descriptor.pool().issuer().as_bytes(), 2)
            .unwrap();
        assert!(!high_water
            .admits(descriptor.pool().issuer().as_bytes(), 1)
            .unwrap());
        crate::host_trust::seed_wci_host_for_test(&home);
        let registry = Arc::new(ProviderRegistry::new());
        let request = RightsProviderRequestV1::new_evaluate_any(node, &operation).unwrap();
        registry
            .register_sub_provider(
                CHAIN_PROVIDER_ID,
                Arc::new(ProcessChainEvidenceProvider {
                    expected_request: request.clone(),
                    requests: Mutex::new(Vec::new()),
                    has_access: true,
                }),
            )
            .await
            .unwrap();
        register_custody_provider(&registry, &binary, &home)
            .await
            .unwrap();
        let invocation = ProviderInvocation {
            source: RUNTIME_PROVIDER_ID.into(),
            target: CUSTODY_PROVIDER_ID.into(),
            op: "evaluate".into(),
            request: serde_json::to_value(&request).unwrap(),
            transfer: ProviderTransfer::Json,
            range: None,
            progress: None,
            transport: ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                peer_did: fixture::pool_did().to_did_key().unwrap(),
                timeout_ms: Some(5000),
                reply_wait_ms: Some(15000),
            }),
        };
        // Registry creates the real outgoing envelope. The invoker calls
        // carrier_provider_invoke_registry with an unrelated peer identity.
        let reader = Arc::new(ProviderRegistry::new());
        reader
            .set_carrier_invoker(Arc::new(
                crate::custody_pool_resolver::tests::DescriptorDispatchCarrier {
                    remote: registry.clone(),
                    remote_home: home,
                    source,
                },
            ))
            .await;
        let answer = reader.invoke_provider(invocation).await;
        match answer {
            Ok(answer) if answer["status"] == "ok" => {
                let parsed = RightsProviderResponseV1::from_json_slice(
                    &serde_json::to_vec(&answer["data"]).unwrap(),
                )
                .unwrap();
                let decision = parsed.signed_node_rights_decision().unwrap();
                assert_eq!(decision.statement().node_public_key(), node);
                decisions += 1;
                outcomes.push((seed, "decision", "ok".to_string()));
            }
            Ok(answer) => outcomes.push((seed, "provider_response", public_code(&answer))),
            Err(ProviderError::Provider(message)) => {
                let code = message
                    .strip_prefix("descriptor dispatch refused: ")
                    .and_then(|json| serde_json::from_str::<Value>(json).ok())
                    .map(|value| public_code(&value))
                    .unwrap_or_else(|| "provider_error".to_string());
                outcomes.push((seed, "invoke_error", code));
            }
            Err(_) => outcomes.push((seed, "invoke_error", "other_provider_error".to_string())),
        }
        assert!(!high_water
            .admits(descriptor.pool().issuer().as_bytes(), 1)
            .unwrap());
        registry
            .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
            .unwrap();
    }
    assert!(decisions >= 2, "independent reader must reach a 2-of-3 rights quorum through the real custody wrappers, got {decisions}; public per-node outcomes: {outcomes:?}");
}

/// The fake provider's two stamping modes, read from the receipt `status`
/// actually issues: a fixed stamp is reported as configured, however old; an
/// issue-time stamp is the clock when the receipt is issued, even when the
/// configured value is already stale.
#[tokio::test]
async fn availability_test_receipts_stamp_fixed_or_at_issue() {
    async fn issued_checked_at(config: ContentAvailabilityTestConfig) -> u64 {
        let provider = ContentAvailabilityTestProvider::new(0x31, config);
        provider
            .publish(&json!({
                "op": "publish",
                "object_kind": "protected-content",
                "object_did": "did:key:object",
                "publisher_did": "did:key:publisher",
                "files": [{
                    "path": "payload.bin",
                    "data": base64::engine::general_purpose::STANDARD.encode(b"payload"),
                }],
            }))
            .await
            .unwrap();
        let status = provider.status().await.unwrap();
        status["data"]["receipt"]["payload"]["checked_at"]
            .as_u64()
            .expect("the issued receipt carries checked_at")
    }

    let stale = ContentAvailabilityTestConfig::accepted_at(1);
    assert_eq!(issued_checked_at(stale.clone()).await, 1);

    let before = crate::auth::now_ts();
    let stamped = issued_checked_at(ContentAvailabilityTestConfig {
        stamp_at_issue: true,
        ..stale
    })
    .await;
    assert!(
        stamped >= before && stamped <= crate::auth::now_ts(),
        "{stamped} is not the issue time"
    );
}

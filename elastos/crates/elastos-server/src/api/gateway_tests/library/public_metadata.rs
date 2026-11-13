//! The creator tail and the public IPFS store (META-PUBLIC §7.0): a new
//! approval is raised only after the mint's metadata is public, and an
//! existing approval settles without any public-store call.

use std::collections::HashMap;

use base64::Engine as _;

use super::*;

// ── Approval request (R2') ──────────────────────────────────────────

/// The hashed approval request is not changed by the public metadata step:
/// for one fixed creator-tail input, the full request binding (the approval
/// reason included), the request SHA-256, the derived effect id and the
/// approval request id equal the values computed on the commit before it.
/// `request_sha256` alone would not do: it is hashed before the reason is
/// added.
#[test]
fn public_approval_request_unchanged() {
    let account_id = "wallet:eip155:8453:0x1111111111111111111111111111111111111111";
    let creator_state = elastos_protected_content_runtime::RuntimeMintCreatorState::new(
        elastos_protected_content_runtime::RuntimeMintCreatorDesiredTerms::new(
            account_id.to_string(),
            "0x2".to_string(),
            "0xf4240".to_string(),
            Vec::new(),
            elastos_protected_content_runtime::RuntimeMintAccessMethod::BuyOnce,
            None,
            "0x0000000000000000000000000000000000000022".to_string(),
            String::new(),
        )
        .unwrap(),
        "bafybeibafe7oi52uk6xjyuigvo3mel5hs6kdb4kvbb3odkepyn6o5xd4qu",
        "ipfs://bafybeibafe7oi52uk6xjyuigvo3mel5hs6kdb4kvbb3odkepyn6o5xd4qu",
    )
    .unwrap();
    let (binding, request_sha256, effect_id, approval_request_id) =
        runtime_custody_creator_approval_request_for_test(
            "principal:public-metadata-golden",
            account_id,
            "0x1111111111111111111111111111111111111111",
            &creator_state,
            [
                "base-mainnet",
                "eip155:8453",
                "0x0000000000000000000000000000000000000022",
                "0x0000000000000000000000000000000000000000",
                "0x00000000000000000000000000000000000000aa",
                "0xdeadbeef",
                "0x0",
            ],
            elastos_protected_content_contracts::Digest32::new([0x5a; 32]),
        )
        .unwrap();
    // Computed on a624e3302, before the public metadata step existed.
    assert_eq!(
        binding.to_string(),
        concat!(
            r#"{"account_id":"wallet:eip155:8453:0x1111111111111111111111111111111111111111","#,
            r#""address":"0x1111111111111111111111111111111111111111","#,
            r#""approval_reason":"Create protected-content creator listing","#,
            r#""chain_namespace":"eip155:8453","data":"0xdeadbeef","#,
            r#""metadata":{"ledger":"0x0000000000000000000000000000000000000022","#,
            r#""metadata_cid":"bafybeibafe7oi52uk6xjyuigvo3mel5hs6kdb4kvbb3odkepyn6o5xd4qu","#,
            r#""pay_token":"0x0000000000000000000000000000000000000000","#,
            r#""product_operation":"protected_content_creator_mint","#,
            r#""token_uri":"ipfs://bafybeibafe7oi52uk6xjyuigvo3mel5hs6kdb4kvbb3odkepyn6o5xd4qu"},"#,
            r#""network":"base-mainnet","source":"native_wallet","#,
            r#""to":"0x00000000000000000000000000000000000000aa","value":"0x0"}"#,
        )
    );
    assert_eq!(
        request_sha256,
        "e9c7b35ba4696058816c9e1ba77a68389c87b3416b60b3b735d4be400aac8515"
    );
    assert_eq!(
        effect_id,
        "transaction-effect:sha256:674464b69aa2a9cef733fda2db95b36d12e8e4eee2eb24fe88534d34a96ec10c"
    );
    assert_eq!(
        approval_request_id,
        "wallet-request:7f9c6e1de5da528841e3134fefd21832"
    );
    // The Inbox line keys on this exact reason.
    assert_eq!(
        RUNTIME_CUSTODY_CREATOR_APPROVAL_REASON,
        "Create protected-content creator listing"
    );
}

// ── Fixture ─────────────────────────────────────────────────────────

use crate::public_metadata_publisher::tests::{
    cover_car, folder_car, FakePrivateIpfs, FakePublicIpfs,
};

/// The private store as the creator tail reaches it: the content plane for
/// everything the legacy mock serves, except the mint's metadata folder and
/// cover, which are added with real CIDs so the private `ipfs` store can
/// export them as CARs, and the folder's files, which it serves back.
struct PrivateContent {
    private: Arc<FakePrivateIpfs>,
    files: std::sync::Mutex<HashMap<String, HashMap<String, Vec<u8>>>>,
}

#[async_trait::async_trait]
impl Provider for PrivateContent {
    async fn handle(&self, request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        MockContentProvider.handle(request).await
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["content"]
    }

    fn name(&self) -> &'static str {
        "public-metadata-private-content"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let answer = |cid: &str| {
            Ok(json!({"status":"ok","data":{
                "cid": cid,
                "uri": format!("elastos://{cid}"),
                "availability": {"status":"local_pinned","provider":"public-metadata-private-content","replicas":1},
                "receipt": {"schema":"elastos.content.availability.receipt/v1","cid":cid},
            }}))
        };
        let decode = |data: &Value| {
            base64::engine::general_purpose::STANDARD
                .decode(data.as_str().unwrap_or_default())
                .unwrap()
        };
        match (request["op"].as_str(), request["kind"].as_str()) {
            (Some("publish"), Some("directory")) if request["object_kind"] == "directory" => {
                let files: Vec<(String, Vec<u8>)> = request["files"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|entry| {
                        (
                            entry["path"].as_str().unwrap().to_string(),
                            decode(&entry["data"]),
                        )
                    })
                    .collect();
                let entries: Vec<(&str, &[u8])> = files
                    .iter()
                    .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
                    .collect();
                let (cid, car) = folder_car(&entries);
                self.private.cars.lock().unwrap().insert(cid.clone(), car);
                self.files
                    .lock()
                    .unwrap()
                    .insert(cid.clone(), files.into_iter().collect());
                answer(&cid)
            }
            (Some("publish"), Some("file")) => {
                let (cid, car) = cover_car(&decode(&request["data"]));
                self.private.cars.lock().unwrap().insert(cid.clone(), car);
                answer(&cid)
            }
            (Some("fetch"), _) => {
                let served = request["cid"].as_str().and_then(|cid| {
                    self.files
                        .lock()
                        .unwrap()
                        .get(cid)
                        .and_then(|files| files.get(request["path"].as_str()?).cloned())
                });
                match served {
                    Some(bytes) => Ok(json!({"status":"ok","data":{
                        "data": base64::engine::general_purpose::STANDARD.encode(bytes)}})),
                    None => MockContentProvider.send_raw(request).await,
                }
            }
            _ => MockContentProvider.send_raw(request).await,
        }
    }
}

/// One creator's mint, ready for its tail, on a Home whose admin has
/// consented and whose public store runs.
struct PublicTail {
    _dir: tempfile::TempDir,
    data_dir: std::path::PathBuf,
    state: GatewayState,
    wallet: Arc<RecordingWalletProvider>,
    registry: Arc<ProviderRegistry>,
    authority: RuntimeWalletAuthority,
    input: crate::protected_content_runtime::RuntimeCustodyLibraryPublishInput,
    facts: crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts,
    private: Arc<FakePrivateIpfs>,
    public: Arc<FakePublicIpfs>,
}

async fn public_tail(seed: u8, name: &str, cover: bool) -> PublicTail {
    let dir = crate::protected_content_config::tests::safe_ancestor_tempdir();
    let data_dir = dir.path().join("data");
    crate::protected_content_config::tests::owner_only_dir(&data_dir);
    let (state, wallet) = wallet_chain_test_state_with_observer(&data_dir).await;
    crate::public_metadata_publisher::test_seams::publish_for_real(&data_dir);
    // A5: these tests publish, so their Home offers sharing.
    crate::public_metadata_consent::tests::open_public_metadata_gate(&data_dir);
    let registry = state.provider_registry.as_ref().unwrap().clone();
    let private = Arc::new(FakePrivateIpfs::default());
    registry
        .register_sub_provider(
            "content",
            Arc::new(PrivateContent {
                private: private.clone(),
                files: Default::default(),
            }),
        )
        .await
        .unwrap();
    registry
        .register_sub_provider("ipfs", private.clone())
        .await
        .unwrap();
    let public = Arc::new(FakePublicIpfs::new());
    registry
        .register_runtime_provider_target(
            crate::public_ipfs_store::PUBLIC_IPFS_TARGET,
            public.clone(),
        )
        .await
        .unwrap();
    crate::public_ipfs_store::tests::record_consent(
        &data_dir,
        crate::public_metadata_consent::ConsentState::Enabled,
    )
    .await;
    reset_mock_content_publish_requests();
    set_mock_runtime_listing_publish_failure(false);
    reset_mock_protected_content_chain_mode();
    reset_mock_protected_content_purchase_fixture();
    let principal = passkey_authority_with_profile(&data_dir, "admin");
    let token = app_token_for_authority(&data_dir, LIBRARY_CAPSULE_ID, &principal);
    let authority = runtime_wallet_authority_for_app_token(&data_dir, LIBRARY_CAPSULE_ID, &token);
    let wallet_account_id = wallet
        .provider
        .seed_managed_evm_account_for_principal(&principal.principal_id)
        .await;
    let uri = format!(
        "{}/Documents/{name}",
        crate::auth::principal_localhost_root(&principal.principal_id)
    );
    let mut input =
        runtime_custody_creator_test_input(&principal.principal_id, &uri, seed, &wallet_account_id);
    if cover {
        input.listing = Some(crate::library::RuntimeCustodyListingTerms {
            title: "Public mint".into(),
            description: String::new(),
            category: String::new(),
            tags: Vec::new(),
            thumbnail: Some(crate::library::RuntimeCustodyListingThumbnail {
                mime: "image/png".into(),
                bytes: b"public cover bytes".to_vec(),
            }),
            royalties: Vec::new(),
            access_method: elastos_protected_content_runtime::RuntimeMintAccessMethod::BuyOnce,
            reseller_cut: None,
            adult: false,
            licensing: None,
            legal_attestation: None,
        });
    }
    let facts = seed_completed_runtime_custody_mint(&data_dir, &input);
    PublicTail {
        _dir: dir,
        data_dir,
        state,
        wallet,
        registry,
        authority,
        input,
        facts,
        private,
        public,
    }
}

impl PublicTail {
    fn facts(&self) -> crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts {
        let facts = &self.facts;
        crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts {
            content_cid: facts.content_cid.clone(),
            mint_id: facts.mint_id,
            content_id: facts.content_id.clone(),
            display_name: facts.display_name.clone(),
            availability: facts.availability.clone(),
            receipt: facts.receipt.clone(),
            content_security: facts.content_security.clone(),
            listing_uri: facts.listing_uri.clone(),
            capsule_uri: facts.capsule_uri.clone(),
        }
    }

    async fn run(
        &self,
    ) -> anyhow::Result<crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts> {
        runtime_custody_publish_creator_tail_for_test(
            &self.state,
            &self.authority,
            self.registry.clone(),
            self.input.clone(),
            self.facts(),
        )
        .await
    }

    async fn resume(
        &self,
    ) -> anyhow::Result<crate::protected_content_runtime::RuntimeCustodyLibraryPublishFacts> {
        runtime_custody_resume_creator_tail_for_test(
            &self.state,
            &self.authority,
            self.registry.clone(),
            self.input.clone(),
            self.facts(),
        )
        .await
    }

    async fn approvals(&self) -> usize {
        self.wallet
            .provider
            .approvals
            .lock()
            .await
            .iter()
            .filter(|approval| approval["intent"] == "transaction_intent")
            .count()
    }

    fn mint(&self) -> elastos_protected_content_runtime::PersistedRuntimeMint {
        crate::protected_content_runtime::runtime_mint_journal(&self.data_dir)
            .load(self.facts.mint_id)
            .unwrap()
    }

    fn folder(&self) -> String {
        self.mint()
            .creator_state()
            .unwrap()
            .metadata_cid()
            .to_string()
    }

    async fn progress(&self) -> RuntimeTransactionEffectProgress {
        let effect_id = self
            .mint()
            .creator_state()
            .and_then(|state| state.effect().map(|effect| effect.effect_id().to_string()))
            .unwrap();
        runtime_transaction_effect_progress(&self.state, &self.authority, &effect_id)
            .await
            .unwrap()
    }

    async fn disable(&self) {
        crate::public_ipfs_store::tests::record_consent(
            &self.data_dir,
            crate::public_metadata_consent::ConsentState::Disabled,
        )
        .await;
    }

    /// The creator's account signs through an external connector, as
    /// `CreatorRecoveryFixture::link_account_to_connector` links it.
    async fn link_connector(&self) {
        for account in self.wallet.provider.accounts.lock().await.iter_mut() {
            account["connector_id"] = json!("metamask");
            account["proof_type"] = json!("siwe");
            account["signing_status"] = json!("external_connector_available");
        }
    }

    fn public_calls(&self) -> usize {
        self.public.calls.lock().unwrap().len()
    }
}

fn public_metadata_code(error: &anyhow::Error) -> Option<String> {
    let envelope = crate::library::provider_error_from_for_test(error);
    envelope["public_metadata"]["code"]
        .as_str()
        .map(ToString::to_string)
}

fn stage_states(progress: &Value) -> Vec<(String, String)> {
    progress["stages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|stage| {
            (
                stage["id"].as_str().unwrap().to_string(),
                stage["state"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

const PENDING: &str = "Runtime custody creator mint is pending exact Wallet or Chain settlement";

// ── New authority ───────────────────────────────────────────────────

#[tokio::test]
async fn public_new_mint_publishes_then_raises_approval() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let tail = public_tail(0xa1, "public-new-mint", true).await;
    let pending = tail.run().await.unwrap_err();
    assert_eq!(pending.to_string(), PENDING);
    assert_eq!(tail.approvals().await, 1);
    let folder = tail.folder();
    let document: Value = serde_json::from_slice(
        &crate::content::fetch_bytes_via_provider(&tail.registry, &folder, Some("metadata.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    let cover = document["image"]
        .as_str()
        .unwrap()
        .strip_prefix("ipfs://")
        .unwrap()
        .to_string();
    assert_eq!(
        *tail.private.exports.lock().unwrap(),
        [folder.clone(), cover.clone()]
    );
    let published: Vec<(String, String)> = tail.public.publication();
    let expected: Vec<(String, String)> = [
        ("runtime_public_import_car", &folder),
        ("runtime_public_import_car", &cover),
        ("runtime_public_pin", &folder),
        ("runtime_public_pin", &cover),
        ("runtime_public_provide", &folder),
        ("runtime_public_provide", &cover),
    ]
    .into_iter()
    .map(|(op, cid)| (op.to_string(), cid.to_string()))
    .collect();
    assert_eq!(published, expected);
    // The content the folder names is never exported or published.
    assert!(!tail
        .private
        .exports
        .lock()
        .unwrap()
        .contains(&tail.facts.content_cid));
}

/// A5 (binding O2): with the gate closed a new mint behaves as on develop:
/// no consent check, no public-store call and no export, and the approval
/// is raised.
#[tokio::test]
async fn public_gate_closed_tail_raises_approval_without_publish() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let tail = public_tail(0xa9, "public-gate-closed", true).await;
    crate::public_metadata_consent::tests::close_public_metadata_gate(&tail.data_dir);
    // Not even the consent is read: a Disabled record changes nothing.
    tail.disable().await;
    let pending = tail.run().await.unwrap_err();
    assert_eq!(pending.to_string(), PENDING);
    assert_eq!(tail.approvals().await, 1);
    assert_eq!(tail.public_calls(), 0, "zero public-store calls");
    assert!(tail.private.exports.lock().unwrap().is_empty());
}

async fn assert_refused_without_approval(tail: &PublicTail, code: &str) {
    let error = tail.run().await.unwrap_err();
    assert_eq!(
        public_metadata_code(&error).as_deref(),
        Some(code),
        "{error:#}"
    );
    assert_eq!(
        tail.approvals().await,
        0,
        "no approval follows a failed publication"
    );
}

#[tokio::test]
async fn public_new_mint_not_ready_returns_error_and_no_approval() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let tail = public_tail(0xa2, "public-not-ready", false).await;
    tail.public
        .alive
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_refused_without_approval(&tail, "not_ready").await;
    assert!(tail.public.publication().is_empty());
    tail.disable().await;
    assert_refused_without_approval(&tail, "disabled").await;
}

#[tokio::test]
async fn public_invalid_car_returns_error_and_no_approval() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let tail = public_tail(0xa3, "public-invalid-car", false).await;
    // The folder exports with a stowaway block appended to its CAR.
    tail.run().await.unwrap_err();
    let folder = tail.folder();
    let (_, stowaway) = folder_car(&[("metadata.json", b"other")]);
    {
        let mut cars = tail.private.cars.lock().unwrap();
        let mut car = cars[&folder].clone();
        let header_len = stowaway[0] as usize + 1;
        car.extend_from_slice(&stowaway[header_len..]);
        cars.insert(folder.clone(), car);
    }
    // Start again from a mint with no approval yet: the approval the first
    // run raised is expired, and re-raising it is new authority.
    tail.wallet
        .provider
        .expire_latest_transaction_approval()
        .await;
    let before = tail.approvals().await;
    let imports = tail.public.publication().len();
    let error = tail.run().await.unwrap_err();
    assert_eq!(
        public_metadata_code(&error).as_deref(),
        Some("invalid_car"),
        "{error:#}"
    );
    assert_eq!(tail.approvals().await, before);
    assert_eq!(
        tail.public.publication().len(),
        imports,
        "nothing was imported"
    );
}

#[tokio::test]
async fn public_import_failure_returns_error_and_no_approval() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let tail = public_tail(0xa4, "public-import-failure", false).await;
    tail.public
        .refuse("runtime_public_import_car", "import_failed");
    assert_refused_without_approval(&tail, "import_failed").await;
}

#[tokio::test]
async fn public_announce_failure_returns_error_and_no_approval() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let tail = public_tail(0xa5, "public-announce-failure", false).await;
    tail.public
        .refuse("runtime_public_provide", "provide_failed");
    assert_refused_without_approval(&tail, "announce_failed").await;
}

#[tokio::test]
async fn public_retry_after_failure_republishes_then_raises() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let tail = public_tail(0xa6, "public-retry", false).await;
    tail.public.refuse("runtime_public_pin", "pin_failed");
    assert_refused_without_approval(&tail, "pin_failed").await;
    tail.public.refusals.lock().unwrap().clear();
    let pending = tail.run().await.unwrap_err();
    assert_eq!(pending.to_string(), PENDING);
    assert_eq!(tail.approvals().await, 1);
    let folder = tail.folder();
    let imports = tail
        .public
        .publication()
        .iter()
        .filter(|call| **call == ("runtime_public_import_car".to_string(), folder.clone()))
        .count();
    assert_eq!(imports, 2, "the retry published again");
    // A further poll settles the approval it raised: no third publication.
    let calls = tail.public_calls();
    assert_eq!(tail.run().await.unwrap_err().to_string(), PENDING);
    assert_eq!(tail.public_calls(), calls);
    assert_eq!(tail.approvals().await, 1);
}

#[tokio::test]
async fn public_resume_before_approval_republishes() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let tail = public_tail(0xa7, "public-resume", false).await;
    // The Home stops before the approval: the store was down.
    tail.public
        .alive
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_refused_without_approval(&tail, "not_ready").await;
    // After the restart the store runs again, and Resume publishes, then
    // raises the approval.
    tail.public
        .alive
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let pending = tail.resume().await.unwrap_err();
    assert_eq!(pending.to_string(), PENDING);
    assert_eq!(tail.approvals().await, 1);
    assert!(tail
        .public
        .publication()
        .contains(&("runtime_public_provide".to_string(), tail.folder())));
}

// ── Settlement ──────────────────────────────────────────────────────

#[tokio::test]
async fn public_settlement_after_withdrawal_reaches_terminal_with_zero_public_calls() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let tail = public_tail(0xa8, "public-settle-after-withdrawal", false).await;
    assert_eq!(tail.run().await.unwrap_err().to_string(), PENDING);
    assert_eq!(tail.approvals().await, 1);
    let calls = tail.public_calls();
    tail.disable().await;
    tail.wallet
        .provider
        .complete_latest_transaction_approval()
        .await;
    let settled = tail.run().await.unwrap();
    assert!(settled.listing_uri.is_some());
    assert!(tail.mint().creator_state().unwrap().terminal().is_some());
    assert_eq!(
        tail.public_calls(),
        calls,
        "settlement makes no public call"
    );
    assert_eq!(tail.approvals().await, 1);
}

#[tokio::test]
async fn public_settlement_with_store_down_after_restart() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let tail = public_tail(0xa9, "public-settle-store-down", false).await;
    assert_eq!(tail.run().await.unwrap_err().to_string(), PENDING);
    let calls = tail.public_calls();
    // Withdrawn, and after a restart the store is not registered at all.
    crate::public_metadata_consent::create_withdrawal_marker(&tail.data_dir, "principal:test")
        .unwrap();
    tail.disable().await;
    tail.registry
        .unregister_runtime_provider_target(crate::public_ipfs_store::PUBLIC_IPFS_TARGET)
        .await
        .unwrap();
    tail.wallet
        .provider
        .complete_latest_transaction_approval()
        .await;
    let settled = tail.resume().await.unwrap();
    assert!(settled.listing_uri.is_some());
    assert!(tail.mint().creator_state().unwrap().terminal().is_some());
    assert_eq!(tail.public_calls(), calls);
    assert_eq!(tail.approvals().await, 1);
}

#[tokio::test]
async fn public_settlement_covers_each_existing_state() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    for (seed, existing) in [
        (0xb1, RuntimeTransactionEffectProgress::AwaitingApproval),
        (
            0xb2,
            RuntimeTransactionEffectProgress::InConnector("metamask".into()),
        ),
        (0xb3, RuntimeTransactionEffectProgress::Signed),
        (0xb4, RuntimeTransactionEffectProgress::Mined),
    ] {
        let tail = public_tail(seed, &format!("public-settle-{seed:x}"), false).await;
        if matches!(existing, RuntimeTransactionEffectProgress::InConnector(_)) {
            tail.link_connector().await;
        }
        assert_eq!(tail.run().await.unwrap_err().to_string(), PENDING);
        match existing {
            RuntimeTransactionEffectProgress::AwaitingApproval
            | RuntimeTransactionEffectProgress::InConnector(_) => {}
            RuntimeTransactionEffectProgress::Signed => {
                tail.wallet
                    .provider
                    .set_latest_transaction_approval_status("approved")
                    .await;
            }
            RuntimeTransactionEffectProgress::Mined => {
                // The chain has the transaction; the mint receipt is not yet
                // readable, so the tail stops after recording it.
                tail.wallet
                    .provider
                    .complete_latest_transaction_approval()
                    .await;
                set_mock_protected_content_chain_receipt_error();
                let _ = tail.run().await.unwrap_err();
                reset_mock_protected_content_chain_mode();
            }
            _ => unreachable!(),
        }
        assert_eq!(tail.progress().await, existing);
        let calls = tail.public_calls();
        tail.disable().await;
        let outcome = tail.run().await;
        if let Err(error) = &outcome {
            assert_eq!(public_metadata_code(error), None, "{existing:?}: {error:#}");
        }
        assert_eq!(tail.public_calls(), calls, "{existing:?}");
        assert_eq!(tail.approvals().await, 1, "{existing:?}");
    }
}

#[tokio::test]
async fn public_expired_unsigned_approval_cannot_be_reraised_while_disabled() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let tail = public_tail(0xaa, "public-expired-disabled", false).await;
    assert_eq!(tail.run().await.unwrap_err().to_string(), PENDING);
    tail.wallet
        .provider
        .expire_latest_transaction_approval()
        .await;
    assert_eq!(
        tail.progress().await,
        RuntimeTransactionEffectProgress::ClosedWithoutSignature
    );
    tail.disable().await;
    let error = tail.run().await.unwrap_err();
    assert_eq!(public_metadata_code(&error).as_deref(), Some("disabled"));
    assert_eq!(
        tail.approvals().await,
        1,
        "the expired approval was not re-raised"
    );
}

/// An expired approval that went to a connector reads as still in the
/// connector, but the approval step raises it again: a reissue, so new
/// authority. Prepare the expired connector approval of one fresh mint.
async fn expired_connector_approval(seed: u8, name: &str) -> PublicTail {
    let tail = public_tail(seed, name, false).await;
    tail.link_connector().await;
    assert_eq!(tail.run().await.unwrap_err().to_string(), PENDING);
    tail.wallet
        .provider
        .expire_latest_transaction_approval()
        .await;
    assert_eq!(
        tail.progress().await,
        RuntimeTransactionEffectProgress::InConnector("metamask".into())
    );
    tail
}

#[tokio::test]
async fn public_expired_connector_approval_republishes_before_reraise() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let tail = expired_connector_approval(0xac, "public-expired-connector").await;
    let provides = |tail: &PublicTail| {
        tail.public
            .publication()
            .iter()
            .filter(|(op, _)| op == "runtime_public_provide")
            .count()
    };
    assert_eq!(provides(&tail), 1);
    assert_eq!(tail.run().await.unwrap_err().to_string(), PENDING);
    assert_eq!(provides(&tail), 2, "the reissue published again first");
    assert_eq!(
        tail.wallet
            .provider
            .latest_transaction_approval_status()
            .await
            .as_deref(),
        Some("pending"),
        "the lapsed approval was asked again"
    );
}

#[tokio::test]
async fn public_expired_connector_approval_cannot_be_reraised_while_disabled() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let tail = expired_connector_approval(0xad, "public-expired-connector-disabled").await;
    let calls = tail.public_calls();
    tail.disable().await;
    let error = tail.run().await.unwrap_err();
    assert_eq!(public_metadata_code(&error).as_deref(), Some("disabled"));
    assert_eq!(tail.public_calls(), calls);
    assert_eq!(
        tail.wallet
            .provider
            .latest_transaction_approval_status()
            .await
            .as_deref(),
        Some("expired"),
        "not asked again"
    );
}

// ── Progress and the Inbox card ─────────────────────────────────────

#[tokio::test]
async fn public_progress_reports_metadata_stage() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let tail = public_tail(0xab, "public-progress", false).await;
    tail.public
        .refuse("runtime_public_provide", "provide_failed");
    let error = tail.run().await.unwrap_err();
    let envelope = crate::library::provider_error_from_for_test(&error);
    assert_eq!(envelope["public_metadata"]["code"], "announce_failed");
    assert_eq!(
        stage_states(&envelope["public_metadata"]["progress"]),
        [
            ("escrow".to_string(), "done".to_string()),
            ("publish".to_string(), "done".to_string()),
            ("public_metadata".to_string(), "failed".to_string()),
            ("listing".to_string(), "active".to_string()),
        ]
    );

    tail.public.refusals.lock().unwrap().clear();
    let pending = tail.run().await.unwrap_err();
    let envelope = crate::library::provider_error_from_for_test(&pending);
    assert_eq!(
        stage_states(&envelope["effect_pending"]["progress"]),
        [
            ("escrow".to_string(), "done".to_string()),
            ("publish".to_string(), "done".to_string()),
            ("public_metadata".to_string(), "done".to_string()),
            ("listing".to_string(), "active".to_string()),
        ]
    );
}

#[test]
fn public_inbox_card_states_public_metadata() {
    let request = |reason: &str| SystemWalletApprovalSummary {
        request_id: format!("wallet-request:{}", reason.len()),
        status: "pending".to_string(),
        intent: "transaction_intent".to_string(),
        capsule_id: "creator".to_string(),
        resource: "elastos://wallet/transaction".to_string(),
        reason: reason.to_string(),
        account_id: "wallet:eip155:8453:0xabc".to_string(),
        address: "0xabc".to_string(),
        proof_type: "managed_evm".to_string(),
        connector_id: None,
        review: None,
        created_at: 10,
        expires_at: 20,
        completed_at: None,
        transaction_hash: None,
    };
    let mut notifications = HomeNotificationsSummary::default();
    append_wallet_approval_notifications(
        &mut notifications,
        vec![
            request(RUNTIME_CUSTODY_CREATOR_APPROVAL_REASON),
            request("Buy protected content"),
        ],
        true,
    );
    let entries = serde_json::to_value(&notifications.entries).unwrap();
    assert_eq!(
        entries[0]["body"],
        "creator requests wallet approval for Create protected-content creator listing. \
         This asset's metadata is public on IPFS."
    );
    assert_eq!(
        entries[1]["body"],
        "creator requests wallet approval for Buy protected content."
    );
}

/// A5 §2.1: the Inbox wallet line shows only while sharing is offered; with
/// the gate closed the creator's approval reads as on develop.
#[test]
fn public_inbox_line_only_when_offered() {
    let mut notifications = HomeNotificationsSummary::default();
    append_wallet_approval_notifications(
        &mut notifications,
        vec![SystemWalletApprovalSummary {
            request_id: "wallet-request:closed".to_string(),
            status: "pending".to_string(),
            intent: "transaction_intent".to_string(),
            capsule_id: "creator".to_string(),
            resource: "elastos://wallet/transaction".to_string(),
            reason: RUNTIME_CUSTODY_CREATOR_APPROVAL_REASON.to_string(),
            account_id: "wallet:eip155:8453:0xabc".to_string(),
            address: "0xabc".to_string(),
            proof_type: "managed_evm".to_string(),
            connector_id: None,
            review: None,
            created_at: 10,
            expires_at: 20,
            completed_at: None,
            transaction_hash: None,
        }],
        false,
    );
    let entries = serde_json::to_value(&notifications.entries).unwrap();
    assert_eq!(
        entries[0]["body"],
        "creator requests wallet approval for Create protected-content creator listing."
    );
}

//! The real Carrier and object-seal codecs, with an isolated receiver installed
//! only in the test registry. Publication itself is exercised separately.

use std::io::Cursor;

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use elastos_protected_content_contracts::test_fixtures::{
    node_public_key, pool_bundle, pool_descriptor_routed, pool_did, runtime_issuer, signing_key,
    CUSTODY_KEY_SEED_BASE, POOL_AUTHORITY_SEED, POOL_NODE_SEEDS,
};
use elastos_protected_content_contracts::{
    CanonicalContract, ClearPartIndexV1, ContentAccessIdV1, CustodyEnvelopeV1,
    CustodyPoolFailureDomainIdV1, CustodyPoolOperatorIdV1, Digest32, RemoteShareAdmissionV1,
    SealCompletedV1, SignedMintRequestV1, SignedPoolDescriptorAnyV1, SignedSealCompletedV1,
    PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES, SEAL_PIECE_MAX_CLEAR_BYTES,
};
use elastos_protected_content_custody::{NodeCustodySecretKeyV1, NodeLocalShareStoreV1};
use elastos_protected_content_runtime::{
    prepare_remote_share_provision_request, upload_remote_seal, PoolRemoteSealTransport,
    PoolSessionSource, PoolTransportError, RemoteSealLocalIdentity, RemoteSealTransport,
    RemoteSealUploadError, RuntimeMintCoordinatorError, RuntimeMintIntent, RuntimeMintJournal,
    RuntimeMintNodeBinding,
};
use protected_content_protect_provider::RemoteObjectUploadsV1;
use zeroize::Zeroizing;

use super::*;
use crate::custody_pool_resolver::RegistryPoolSessionTransport;
use crate::custody_seal_completion::SealerCompletionStore;
use crate::custody_surface::TARGET_CUSTODY_POOL;
use crate::remote_seal_source::{
    prepare_remote_object_mint, RemoteSealObjectBytes, RemoteSealObjectFile,
};

const NOW: u64 = 2_000_000_000;
const SEALER: u8 = 1;

fn node_custody_secret(seed: u8) -> NodeCustodySecretKeyV1 {
    NodeCustodySecretKeyV1::from_guarded_bytes(Zeroizing::new([seed; 32])).unwrap()
}

fn node_custody_key(seed: u8) -> [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
    *node_custody_secret(seed).public_key().unwrap().as_bytes()
}

struct ReceiverState {
    uploads: RemoteObjectUploadsV1<Cursor<Vec<u8>>>,
    discard_next_part_ack: bool,
    discard_next_completion: bool,
    completion_replies: usize,
    envelopes: Vec<CustodyEnvelopeV1>,
}

struct IsolatedSealProvider {
    source: String,
    descriptor: SignedPoolDescriptorAnyV1,
    signing_root: custody_provider::LoadedCustodyProviderState,
    state: StdMutex<ReceiverState>,
}

#[async_trait::async_trait]
impl Provider for IsolatedSealProvider {
    async fn handle(&self, _: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "fixture only accepts seal commands".into(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![TARGET_CUSTODY_POOL]
    }

    fn name(&self) -> &'static str {
        "remote-object-seal-fixture"
    }

    async fn send_raw(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, ProviderError> {
        use serde_json::{json, Value};
        let mut fields = request.as_object().unwrap().clone();
        let invocation = fields.remove("_runtime_invocation").unwrap();
        // Carrier fills this field with the connection identity after rejecting
        // requests that predeclare it. This fixture admits one authorized peer.
        let peer = invocation["carrier"]["source_endpoint_did"]
            .as_str()
            .unwrap();
        let op = fields.remove("op").unwrap();
        let body = serde_json::to_vec(&fields).unwrap();
        let mut state = self.state.lock().unwrap();
        if op == "seal.finalize" {
            let source = PoolSessionSource {
                endpoint_did: peer.into(),
                local: false,
            };
            if let Some(data) = SealerCompletionStore::new(&self.signing_root.data_root)
                .replay_finalize(&source, &body, NOW)
                .unwrap()
            {
                state.completion_replies += 1;
                if std::mem::take(&mut state.discard_next_completion) {
                    return Ok(json!({ "status": "ok", "data": {} }));
                }
                return Ok(json!({ "status": "ok", "data": data }));
            }
        }
        if peer != self.source {
            return Ok(json!({ "status": "error", "code": "seal_session_lost" }));
        }
        let response = match op.as_str().unwrap() {
            "seal.open" => {
                let base64 = base64::engine::general_purpose::STANDARD;
                let bytes = base64
                    .decode(fields["mint_request"].as_str().unwrap())
                    .unwrap();
                let mint = SignedMintRequestV1::from_canonical_bytes(&bytes).unwrap();
                let statement = state
                    .uploads
                    .open_wire(
                        peer,
                        runtime_issuer(POOL_AUTHORITY_SEED),
                        &self.descriptor,
                        &body,
                        NOW,
                        || Ok(Cursor::new(Vec::new())),
                    )
                    .unwrap();
                let attestation = self
                    .signing_root
                    .attest_remote_seal_upload(pool_did(), &self.descriptor, &mint, statement, NOW)
                    .unwrap();
                json!({
                    "seal_session_id": hex::encode(attestation.session_id()),
                    "attestation": base64.encode(attestation.canonical_bytes().unwrap()),
                })
            }
            operation => {
                let mut id = [0; 16];
                hex::decode_to_slice(fields["seal_session_id"].as_str().unwrap(), &mut id).unwrap();
                let session = state.uploads.session(peer, id, NOW).unwrap();
                match operation {
                    "seal.part" => {
                        let ack = session.upload_wire(peer, &body, NOW).unwrap();
                        if std::mem::take(&mut state.discard_next_part_ack) {
                            return Ok(json!({ "status": "ok", "data": {} }));
                        }
                        serde_json::to_value(ack).unwrap()
                    }
                    "seal.resume" => {
                        serde_json::to_value(session.resume_wire(peer, &body, NOW).unwrap())
                            .unwrap()
                    }
                    "seal.finalize" => {
                        let result = session.finish_wire(peer, &body, NOW).unwrap();
                        let envelope = result.custody_envelope.clone();
                        state.envelopes.push(envelope);
                        return Ok(json!({ "status": "error", "code": "publication_unavailable" }));
                    }
                    _ => {
                        return Err(ProviderError::Provider(
                            "unexpected fixture operation".into(),
                        ))
                    }
                }
            }
        };
        assert!(matches!(response, Value::Object(_)));
        Ok(json!({ "status": "ok", "data": response }))
    }
}

#[tokio::test]
async fn remote_seal_object_parts_cross_carrier_and_recover_a_missing_ack() {
    const MINTER_SEED: u8 = 0x34;
    let fixture = peer_did_route_fixture(MINTER_SEED, 0x35).await;
    let (_, source) = elastos_identity::derive_did(&[MINTER_SEED; 32]);
    let bundle = pool_bundle(node_custody_key, NOW);
    let descriptor: SignedPoolDescriptorAnyV1 =
        pool_descriptor_routed(&bundle, 1, NOW, POOL_AUTHORITY_SEED, &|seed| {
            if seed == SEALER {
                fixture.remote_did.clone()
            } else {
                format!("did:key:z6MkPoolNode{seed:02x}")
            }
        })
        .into();
    let node = node_public_key(SEALER);
    let epoch = bundle.epoch_identity().unwrap();
    let sealing_root = fixture._remote_dir.path().join("sealing");
    #[cfg(unix)]
    crate::protected_content_config::tests::owner_only_dir(&sealing_root);
    #[cfg(not(unix))]
    std::fs::create_dir(&sealing_root).unwrap();
    let provider = Arc::new(IsolatedSealProvider {
        source,
        descriptor: descriptor.clone(),
        signing_root: custody_provider::LoadedCustodyProviderState {
            expected_runtime_issuer: runtime_issuer(POOL_AUTHORITY_SEED),
            node_public_key: node,
            node_signing_key: signing_key(SEALER),
            node_custody_secret: node_custody_secret(CUSTODY_KEY_SEED_BASE + SEALER),
            data_root: sealing_root,
        },
        state: StdMutex::new(ReceiverState {
            uploads: RemoteObjectUploadsV1::new(pool_did(), node),
            discard_next_part_ack: true,
            discard_next_completion: true,
            completion_replies: 0,
            envelopes: Vec::new(),
        }),
    });
    fixture
        ._remote_registry
        .register_runtime_provider_target(TARGET_CUSTODY_POOL, provider.clone())
        .await
        .unwrap();
    let transport = PoolRemoteSealTransport(RegistryPoolSessionTransport::new(
        fixture._local_dir.path(),
        fixture.local_registry.clone(),
    ));
    let peer = &fixture.remote_did;
    let clear = vec![0x72; SEAL_PIECE_MAX_CLEAR_BYTES];
    let content_type = "application/octet-stream";
    let local_storage = fixture._local_dir.path().join("mint-source");
    #[cfg(unix)]
    crate::protected_content_config::tests::owner_only_dir(&local_storage);
    #[cfg(not(unix))]
    std::fs::create_dir(&local_storage).unwrap();
    let journal = RuntimeMintJournal::new(local_storage.join("journal"));
    let intent = RuntimeMintIntent::new_object(
        "principal-fixture",
        "elastos://localhost/object-fixture",
        "library",
        "wallet-fixture",
        "0x1111111111111111111111111111111111111111",
        Digest32::new([0x59; 32]),
        content_type,
        &clear,
        ContentAccessIdV1::new([0x53; 16]).unwrap(),
        bundle.signed_pool().pool_identity().unwrap(),
        epoch,
        bundle
            .signed_committee_authorization()
            .authorization_identity()
            .unwrap(),
        POOL_NODE_SEEDS
            .into_iter()
            .map(|seed| {
                RuntimeMintNodeBinding::new(
                    node_public_key(seed),
                    CustodyPoolOperatorIdV1::new([seed; 32]),
                    CustodyPoolFailureDomainIdV1::new([seed; 32]),
                    Digest32::new([seed; 32]),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap();
    journal.persist_intent(&intent).unwrap();
    let request_id = intent.request_id();
    let minter_key = signing_key(POOL_AUTHORITY_SEED);
    let local_nodes = [node_public_key(2), node_public_key(3)];
    let local = || RemoteSealLocalIdentity {
        endpoint_did: &provider.source,
        node_keys: &local_nodes,
    };
    let prepare = |journal: &RuntimeMintJournal, now| {
        prepare_remote_object_mint(
            journal,
            request_id,
            content_type,
            &descriptor,
            &minter_key,
            local(),
            now,
        )
    };
    let intent = prepare(&journal, NOW).unwrap();
    let recorded = intent.remote_seal_request().unwrap();
    assert_eq!(recorded.sealer(), node);
    let request = recorded.request().clone();
    let object_path = local_storage.join("fixture.bin");
    let mut different = clear.clone();
    different[0] ^= 1;
    std::fs::write(&object_path, &different).unwrap();
    assert!(RemoteSealObjectBytes::from_authorized_bytes(&different, &intent).is_err());
    let source_bytes = RemoteSealObjectBytes::from_authorized_bytes(&clear, &intent).unwrap();
    assert!(RemoteSealObjectFile::from_authorized_file(
        std::fs::File::open(&object_path).unwrap(),
        &intent
    )
    .await
    .is_err());
    std::fs::write(&object_path, &clear).unwrap();
    let source_file = RemoteSealObjectFile::from_authorized_file(
        std::fs::File::open(&object_path).unwrap(),
        &intent,
    )
    .await
    .unwrap();
    let minter = request.statement().minter_issuer;
    let now = || NOW;
    let upload = || {
        upload_remote_seal(
            &transport,
            &source_bytes,
            &journal,
            request_id,
            minter,
            &now,
        )
    };
    let recorded_session = || {
        journal
            .load_intent(request_id)
            .unwrap()
            .remote_seal_request()
            .unwrap()
            .session()
            .unwrap()
            .clone()
    };
    std::fs::write(&object_path, &different).unwrap();
    assert!(matches!(
        upload_remote_seal(&transport, &source_file, &journal, request_id, minter, &now).await,
        Err(RemoteSealUploadError::InvalidPart)
    ));
    let session = recorded_session();
    let session_id = session.session_id();
    let opened = transport.open(peer, &request, &descriptor).await.unwrap();
    assert_eq!(opened.session_id, session_id);

    assert!(matches!(
        upload().await,
        Err(RemoteSealUploadError::Transport(
            PoolTransportError::NoExactResult
        ))
    ));
    assert_eq!(recorded_session().last_acked(), None);
    let part = ClearPartIndexV1::ObjectChunk { index: 0 };
    for _ in 0..2 {
        assert!(
            matches!(upload().await, Err(RemoteSealUploadError::Transport(PoolTransportError::Refused(code))) if code == "publication_unavailable")
        );
        let session = recorded_session();
        assert_eq!(session.session_id(), session_id);
        assert_eq!(session.last_acked(), Some(part));
    }
    let envelope = {
        let state = provider.state.lock().unwrap();
        assert_eq!(state.envelopes.len(), 2);
        assert_eq!(state.envelopes[0], state.envelopes[1]);
        state.envelopes[0].clone()
    };
    assert_eq!(
        envelope.key_envelope_identity().unwrap().custody_epoch(),
        epoch
    );
    verify_remote_share_provisioning(&provider, &request, &envelope);

    // Use a fixture publication so this test only exercises delivery. The
    // publication test separately covers the Content provider and signing.
    let statement = SealCompletedV1 {
        pool: pool_did(),
        epoch,
        descriptor_digest: descriptor.canonical_hash().unwrap(),
        sealer_node_public_key: node,
        sealer_device_did: peer.clone(),
        content_publisher_did: peer.clone(),
        mint_request_hash: request.canonical_hash().unwrap(),
        content_access_id: request.statement().content_access_id,
        key_envelope: envelope.key_envelope_identity().unwrap(),
        content_identity: b"fixture object identity".to_vec(),
        content_key_commitment: envelope.manifest().content_key_commitment(),
        package_cid: FIXTURE_CID.into(),
        file_cids: vec![("object.epc1".into(), FIXTURE_CID.into())],
        availability_receipt: b"fixture receipt".to_vec(),
        completed_at: NOW,
    };
    let signature = signing_key(SEALER)
        .sign(&statement.canonical_bytes().unwrap())
        .to_bytes();
    let completion = SignedSealCompletedV1::new(statement, signature).unwrap();
    let owner = PoolSessionSource {
        endpoint_did: provider.source.clone(),
        local: false,
    };
    SealerCompletionStore::new(&provider.signing_root.data_root)
        .commit(
            &owner,
            &descriptor,
            &request,
            &opened.attestation,
            &completion,
            NOW,
        )
        .unwrap();
    assert!(matches!(
        upload().await,
        Err(RemoteSealUploadError::Transport(
            PoolTransportError::NoExactResult
        ))
    ));
    assert_eq!(provider.state.lock().unwrap().completion_replies, 1);
    provider.state.lock().unwrap().uploads = RemoteObjectUploadsV1::new(pool_did(), node);
    let reopened_journal = RuntimeMintJournal::new(local_storage.join("journal"));
    let recovered_intent = prepare(&reopened_journal, NOW + 1).unwrap();
    let recovered = recovered_intent.remote_seal_request().unwrap();
    assert_eq!(recovered.request(), &request);
    assert_eq!(recovered.session().unwrap().session_id(), session_id);
    let replayed = upload_remote_seal(
        &transport,
        &source_bytes,
        &reopened_journal,
        request_id,
        minter,
        &now,
    )
    .await
    .unwrap();
    assert_eq!(
        replayed.canonical_bytes().unwrap(),
        completion.canonical_bytes().unwrap()
    );
    let cached = upload_remote_seal(
        &transport,
        &source_bytes,
        &reopened_journal,
        request_id,
        minter,
        &|| request.statement().expires_at + 1,
    )
    .await
    .unwrap();
    assert_eq!(cached, completion);
    assert_eq!(provider.state.lock().unwrap().completion_replies, 2);

    let foreign = peer_did_route_fixture(0x37, 0x38).await;
    foreign
        .local_node
        .memory_lookup
        .add_endpoint_info(fixture.remote_addr.clone());
    let stranger = PoolRemoteSealTransport(RegistryPoolSessionTransport::new(
        foreign._local_dir.path(),
        foreign.local_registry.clone(),
    ));
    for id in [session_id, [0x42; 16]] {
        assert!(matches!(
            stranger.finalize(peer, id).await,
            Err(PoolTransportError::Refused(code)) if code == "seal_session_lost"
        ));
    }
    shutdown_test_carrier_node(foreign.local_node).await;
    shutdown_test_carrier_node(foreign.remote_node).await;
    shutdown_test_carrier_node(fixture.local_node).await;
    shutdown_test_carrier_node(fixture.remote_node).await;
}

fn verify_remote_share_provisioning(
    provider: &IsolatedSealProvider,
    request: &SignedMintRequestV1,
    envelope: &CustodyEnvelopeV1,
) {
    const LOCAL_ISSUER_SEED: u8 = 0x36;
    let identity = envelope.key_envelope_identity().unwrap();
    let local_issuer = runtime_issuer(LOCAL_ISSUER_SEED);
    let issuer_key = signing_key(LOCAL_ISSUER_SEED);
    let sign = |bytes: &[u8]| issuer_key.sign(bytes).to_bytes();
    let admission = |now| {
        let authorization = provider
            .signing_root
            .authorize_remote_share(
                pool_did(),
                &provider.descriptor,
                request,
                &identity,
                local_issuer,
                now,
            )
            .unwrap();
        RemoteShareAdmissionV1 {
            descriptor: provider.descriptor.clone(),
            request: request.clone(),
            authorization,
        }
    };
    assert!(matches!(
        prepare_remote_share_provision_request(
            admission(NOW),
            envelope,
            node_public_key(SEALER),
            &|_| [0; 64],
            NOW
        ),
        Err(RuntimeMintCoordinatorError::OperationAuthority)
    ));
    assert!(matches!(
        prepare_remote_share_provision_request(
            admission(NOW),
            envelope,
            node_public_key(0x37),
            &sign,
            NOW
        ),
        Err(RuntimeMintCoordinatorError::ProviderSelection)
    ));
    for seed in POOL_NODE_SEEDS {
        let root = tempfile::tempdir().unwrap();
        let data_root = root.path().join("data");
        #[cfg(unix)]
        crate::protected_content_config::tests::owner_only_dir(&data_root);
        #[cfg(not(unix))]
        std::fs::create_dir(&data_root).unwrap();
        let recipient = node_public_key(seed);
        let mut loaded = custody_provider::LoadedCustodyProviderState {
            expected_runtime_issuer: runtime_issuer(POOL_AUTHORITY_SEED),
            node_public_key: recipient,
            node_signing_key: signing_key(seed),
            node_custody_secret: node_custody_secret(CUSTODY_KEY_SEED_BASE + seed),
            data_root: data_root.clone(),
        };
        let first =
            prepare_remote_share_provision_request(admission(NOW), envelope, recipient, &sign, NOW)
                .unwrap();
        let later = NOW + 20;
        let retry = prepare_remote_share_provision_request(
            admission(later),
            envelope,
            recipient,
            &sign,
            later,
        )
        .unwrap();
        assert_eq!(first.record, retry.record);
        assert_eq!(
            first.signed_provisioning.statement().provisioning_id(),
            retry.signed_provisioning.statement().provisioning_id()
        );
        assert_ne!(first.signed_provisioning, retry.signed_provisioning);
        let first = loaded
            .provision_remote_share(pool_did(), &first.to_json_vec().unwrap(), NOW)
            .unwrap();
        assert!(!first.already_stored());
        let replay = loaded
            .provision_remote_share(pool_did(), &retry.to_json_vec().unwrap(), later)
            .unwrap();
        assert!(replay.already_stored());
        assert_eq!(first.provisioned(), replay.provisioned());
        let store = NodeLocalShareStoreV1::new(
            recipient,
            data_root.join(custody_provider::NODE_SHARE_STORE_DIR),
        );
        let stored = store
            .load_node_share(
                &identity,
                loaded.expected_runtime_issuer,
                &loaded.node_custody_secret,
            )
            .unwrap();
        assert_eq!(stored, *first.provisioned());
        assert_eq!(
            stored.node_share().bound_content_access_id(),
            Some(request.statement().content_access_id)
        );
    }
}

use super::*;

#[cfg(unix)]
#[tokio::test]
async fn protected_provider_startup_timeout_sends_shutdown_and_reaps_child() {
    for provider in ProtectedStartupProvider::ALL {
        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        provider.prepare_private_config(&data_dir);
        let (binary, pid_file, request_log, status_signal, status_release) =
            write_blocking_protected_status_provider(temp.path(), provider);
        let registry = Arc::new(ProviderRegistry::new());
        let task_registry = registry.clone();
        let task_data_dir = data_dir.clone();
        let registration = tokio::spawn(async move {
            provider
                .register(&task_registry, &binary, &task_data_dir)
                .await
        });

        let mut signal = tokio::fs::OpenOptions::new()
            .read(true)
            .open(&status_signal)
            .await
            .unwrap();
        let mut marker = [0u8; 1];
        signal.read_exact(&mut marker).await.unwrap();
        assert_eq!(marker, [b'x']);
        tokio::time::pause();
        let release_status = tokio::spawn(async move {
            let release = tokio::time::timeout(
                PROTECTED_CONTENT_PROVIDER_STATUS_TIMEOUT + std::time::Duration::from_millis(1),
                std::future::pending::<()>(),
            )
            .await;
            assert!(release.is_err());
            let mut release = tokio::fs::OpenOptions::new()
                .write(true)
                .open(&status_release)
                .await
                .unwrap();
            release.write_all(b"x").await.unwrap();
        });
        tokio::task::yield_now().await;
        tokio::time::advance(
            PROTECTED_CONTENT_PROVIDER_STATUS_TIMEOUT + std::time::Duration::from_millis(1),
        )
        .await;
        tokio::time::resume();
        release_status.await.unwrap();

        let error = registration.await.unwrap().unwrap_err();
        assert!(
            error.to_string().contains("status timed out"),
            "{provider:?}: {error}"
        );
        let requests = fs::read_to_string(request_log).unwrap();
        assert!(
            !process_is_running(read_pid(&pid_file)),
            "{provider:?}: {error}; requests={requests}"
        );
        assert!(requests.contains(r#""op":"status""#), "{provider:?}");
        assert!(requests.contains(r#""op":"shutdown""#), "{provider:?}");
        assert!(
            !registry
                .has_ready_runtime_provider_target(provider.target())
                .await
        );
    }
}

#[cfg(unix)]
#[test]
fn runtime_custody_composition_loads_valid_owner_only_config_with_local_and_carrier_routes() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let now = crate::auth::now_ts();
    let epoch = signed_custody_epoch();
    let peer_did_1 = peer_did_for_seed(0xa1);
    let peer_did_2 = peer_did_for_seed(0xa2);
    let config = custody_composition_config(
        now,
        custody_route_bindings(
            &epoch,
            [
                RuntimeCustodyRouteTransportConfig::Local,
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_1.clone(),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_2.clone(),
                },
            ],
        ),
    );
    write_owner_only_custody_composition_config(&data_dir, &config);

    let config_text =
        String::from_utf8(fs::read(custody_composition_config_path(&data_dir)).unwrap()).unwrap();
    assert!(config_text.contains(&peer_did_1));
    assert!(config_text.contains(&peer_did_2));
    assert!(config_text.contains(&config.signed_pool_base64));

    let loaded = load_runtime_custody_composition_config(&data_dir)
        .unwrap()
        .unwrap();
    assert_eq!(
        loaded.expected_policy_authority,
        signed_custody_epoch().statement().issuer()
    );
    assert_eq!(
        loaded.signed_pool.canonical_bytes().unwrap(),
        base64::engine::general_purpose::STANDARD
            .decode(&config.signed_pool_base64)
            .unwrap()
    );
    assert!(matches!(
        loaded.routes[0].transport,
        ProviderInvocationTransport::Local
    ));
    assert!(matches!(
        &loaded.routes[1].transport,
        ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
            peer_did,
            timeout_ms: None,
            reply_wait_ms: None,
        }) if peer_did == &peer_did_1
    ));
    assert!(matches!(
        &loaded.routes[2].transport,
        ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
            peer_did,
            timeout_ms: None,
            reply_wait_ms: None,
        }) if peer_did == &peer_did_2
    ));

    let registry = Arc::new(ProviderRegistry::new());
    let composition = load_runtime_custody_composition(&data_dir, registry)
        .unwrap()
        .unwrap();
    assert_runtime_custody_transports(
        &composition,
        &[
            ProviderInvocationTransport::Local,
            ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                peer_did: peer_did_1.clone(),
                timeout_ms: None,
                reply_wait_ms: None,
            }),
            ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                peer_did: peer_did_2.clone(),
                timeout_ms: None,
                reply_wait_ms: None,
            }),
        ],
    );
    let configured = composition.configured_nodes().unwrap();
    assert_eq!(
        resolve_runtime_mint_selected_nodes(
            composition.expected_policy_authority,
            composition.expected_authorization_identity,
            &composition.signed_pool,
            &composition.signed_epoch,
            &composition.signed_committee_authorization,
            now,
            &configured,
        )
        .unwrap()
        .len(),
        3
    );
    assert!(!std::ptr::eq(
        &composition.nodes[0].adapter,
        &composition.nodes[1].adapter
    ));

    let debug = format!("{composition:?}");
    assert!(!debug.contains(&peer_did_1));
    assert!(!debug.contains(&peer_did_2));
    assert!(!debug.contains(&config.signed_pool_base64));
    assert!(!debug.contains(&config.signed_epoch_base64));
    assert!(!debug.contains(&config.signed_committee_authorization_base64));
}

#[cfg(unix)]
#[test]
fn runtime_custody_composition_accepts_three_remote_routes() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let now = crate::auth::now_ts();
    let epoch = signed_custody_epoch();
    let peers = [
        peer_did_for_seed(0xb1),
        peer_did_for_seed(0xb2),
        peer_did_for_seed(0xb3),
    ];
    let config = custody_composition_config(
        now,
        custody_route_bindings(
            &epoch,
            [
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peers[0].clone(),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peers[1].clone(),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peers[2].clone(),
                },
            ],
        ),
    );
    write_owner_only_custody_composition_config(&data_dir, &config);

    let loaded = load_runtime_custody_composition_config(&data_dir)
        .unwrap()
        .unwrap();
    for (route, peer_did) in loaded.routes.iter().zip(peers.iter()) {
        assert!(matches!(
            &route.transport,
            ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                peer_did: actual,
                timeout_ms: None,
                reply_wait_ms: None,
            }) if actual == peer_did
        ));
    }

    let composition =
        load_runtime_custody_composition(&data_dir, Arc::new(ProviderRegistry::new()))
            .unwrap()
            .unwrap();
    assert_runtime_custody_transports(
        &composition,
        &[
            ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                peer_did: peers[0].clone(),
                timeout_ms: None,
                reply_wait_ms: None,
            }),
            ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                peer_did: peers[1].clone(),
                timeout_ms: None,
                reply_wait_ms: None,
            }),
            ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                peer_did: peers[2].clone(),
                timeout_ms: None,
                reply_wait_ms: None,
            }),
        ],
    );
}

#[cfg(unix)]
#[test]
fn runtime_custody_composition_absent_returns_none_without_creating_state() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);

    let config = load_runtime_custody_composition_config(&data_dir).unwrap();
    assert!(config.is_none());
    assert!(!protected_content_root(&data_dir).exists());
}

#[cfg(unix)]
#[test]
fn runtime_custody_composition_rejects_trust_anchor_and_route_mismatches() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let now = crate::auth::now_ts();
    let epoch = signed_custody_epoch();
    let peer_did_1 = peer_did_for_seed(0xc1);
    let peer_did_2 = peer_did_for_seed(0xc2);
    let base_routes = custody_route_bindings(
        &epoch,
        [
            RuntimeCustodyRouteTransportConfig::Local,
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                peer_did: peer_did_1.clone(),
            },
            RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                peer_did: peer_did_2.clone(),
            },
        ],
    );

    let mut wrong_policy = custody_composition_config(now, base_routes.clone());
    wrong_policy.expected_policy_authority_base64 = raw_b64_32(
        SigningKey::from_bytes(&[0x72; 32])
            .verifying_key()
            .to_bytes(),
    );
    write_owner_only_custody_composition_config(&data_dir, &wrong_policy);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected trust-anchor rejection")
        .to_string()
        .contains("trust anchors"));

    let mut wrong_auth = custody_composition_config(now, base_routes.clone());
    wrong_auth.expected_committee_authorization_identity_base64 =
        canonical_b64(&CustodyCommitteeAuthorizationIdentityV1::new(digest(0xfe), 1).unwrap());
    write_owner_only_custody_composition_config(&data_dir, &wrong_auth);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected authorization-identity rejection")
        .to_string()
        .contains("trust anchors"));

    let mut missing_route = custody_composition_config(now, base_routes.clone());
    missing_route.routes.pop();
    write_owner_only_custody_composition_config(&data_dir, &missing_route);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected missing-route rejection")
        .to_string()
        .contains("exactly three selected nodes"));

    let mut extra_route = custody_composition_config(now, base_routes.clone());
    extra_route.routes.push(RuntimeCustodyRouteBindingConfig {
        node_public_key_base64: raw_b64_32(*node_public_key(9).as_bytes()),
        owner_state_root_base64: raw_b64_32([0x99; 32]),
        transport: RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
            peer_did: peer_did_for_seed(0xc9),
        },
    });
    write_owner_only_custody_composition_config(&data_dir, &extra_route);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected extra-route rejection")
        .to_string()
        .contains("exactly three selected nodes"));

    let mut duplicate_route = custody_composition_config(now, base_routes.clone());
    duplicate_route.routes[1].node_public_key_base64 =
        duplicate_route.routes[0].node_public_key_base64.clone();
    write_owner_only_custody_composition_config(&data_dir, &duplicate_route);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected duplicate-node rejection")
        .to_string()
        .contains("duplicated or invalid"));

    let mut duplicate_root = custody_composition_config(now, base_routes.clone());
    duplicate_root.routes[1].owner_state_root_base64 =
        duplicate_root.routes[0].owner_state_root_base64.clone();
    write_owner_only_custody_composition_config(&data_dir, &duplicate_root);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected duplicate-root rejection")
        .to_string()
        .contains("duplicated or invalid"));

    let mut two_local = custody_composition_config(now, base_routes.clone());
    two_local.routes[1].transport = RuntimeCustodyRouteTransportConfig::Local;
    write_owner_only_custody_composition_config(&data_dir, &two_local);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected multi-local rejection")
        .to_string()
        .contains("at most one local"));

    let mut duplicate_peer = custody_composition_config(now, base_routes);
    duplicate_peer.routes[2].transport = RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
        peer_did: peer_did_1,
    };
    write_owner_only_custody_composition_config(&data_dir, &duplicate_peer);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected duplicate-peer rejection")
        .to_string()
        .contains("carrier peer DIDs must be distinct"));

    let mut foreign_node = custody_composition_config(
        now,
        custody_route_bindings(
            &epoch,
            [
                RuntimeCustodyRouteTransportConfig::Local,
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xca),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xcb),
                },
            ],
        ),
    );
    foreign_node.routes[2].node_public_key_base64 = raw_b64_32(*node_public_key(9).as_bytes());
    write_owner_only_custody_composition_config(&data_dir, &foreign_node);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected foreign-node rejection")
        .to_string()
        .contains("signed node set"));
}

#[cfg(unix)]
#[test]
fn runtime_custody_composition_rejects_noncanonical_json_and_base64_and_bad_peer_did() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let now = crate::auth::now_ts();
    let epoch = signed_custody_epoch();
    let mut config = custody_composition_config(
        now,
        custody_route_bindings(
            &epoch,
            [
                RuntimeCustodyRouteTransportConfig::Local,
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xdb),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xdc),
                },
            ],
        ),
    );
    owner_only_dir(&protected_content_root(&data_dir));
    let path = custody_composition_config_path(&data_dir);

    fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected noncanonical-json rejection")
        .to_string()
        .contains("not canonical"));

    write_owner_only_custody_composition_config(&data_dir, &config);
    config.signed_pool_base64.push('\n');
    fs::write(
        &path,
        serde_json::to_vec(&serde_json::to_value(&config).unwrap()).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected base64 rejection")
        .to_string()
        .contains("base64"));

    let mut bad_peer = custody_composition_config(
        now,
        custody_route_bindings(
            &epoch,
            [
                RuntimeCustodyRouteTransportConfig::Local,
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: "not-a-did".to_string(),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xdd),
                },
            ],
        ),
    );
    write_owner_only_custody_composition_config(&data_dir, &bad_peer);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected invalid did:key rejection")
        .to_string()
        .contains("did:key"));

    bad_peer.routes[1].transport = RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
        peer_did: format!("{} ", peer_did_for_seed(0xde)),
    };
    write_owner_only_custody_composition_config(&data_dir, &bad_peer);
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected noncanonical did:key rejection")
        .to_string()
        .contains("did:key"));
}

#[cfg(unix)]
#[test]
fn runtime_custody_composition_rejects_unsafe_or_symlinked_paths() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let now = crate::auth::now_ts();
    let epoch = signed_custody_epoch();
    let config = custody_composition_config(
        now,
        custody_route_bindings(
            &epoch,
            [
                RuntimeCustodyRouteTransportConfig::Local,
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xd1),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xd2),
                },
            ],
        ),
    );

    write_owner_only_custody_composition_config(&data_dir, &config);
    fs::set_permissions(
        custody_composition_config_path(&data_dir),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected unsafe-file-mode rejection")
        .to_string()
        .contains("owner-only"));

    write_owner_only_custody_composition_config(&data_dir, &config);
    fs::set_permissions(
        protected_content_root(&data_dir),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(load_runtime_custody_composition_config(&data_dir)
        .err()
        .expect("expected unsafe-parent-mode rejection")
        .to_string()
        .contains("owner-only"));

    write_owner_only_custody_composition_config(&data_dir, &config);
    let symlink_data_dir = temp.path().join("symlink-data");
    owner_only_dir(&symlink_data_dir);
    let symlink_root_target = symlink_data_dir.join("protected-root-target");
    owner_only_dir(&symlink_root_target);
    std::os::unix::fs::symlink(
        &symlink_root_target,
        protected_content_root(&symlink_data_dir),
    )
    .unwrap();
    let symlink_config_path = symlink_root_target.join("custody-composition.json");
    fs::write(
        &symlink_config_path,
        serde_json::to_vec(&serde_json::to_value(&config).unwrap()).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&symlink_config_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_runtime_custody_composition_config(&symlink_data_dir)
        .err()
        .expect("expected symlink-parent rejection")
        .to_string()
        .contains("owner-only directory"));

    let symlink_file_data_dir = temp.path().join("symlink-file-data");
    owner_only_dir(&symlink_file_data_dir);
    owner_only_dir(&protected_content_root(&symlink_file_data_dir));
    let real_config_dir = temp.path().join("real-config");
    owner_only_dir(&real_config_dir);
    let real_config_path = real_config_dir.join("custody-composition.json");
    fs::write(
        &real_config_path,
        serde_json::to_vec(&serde_json::to_value(&config).unwrap()).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&real_config_path, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(
        &real_config_path,
        custody_composition_config_path(&symlink_file_data_dir),
    )
    .unwrap();
    assert!(
        load_runtime_custody_composition_config(&symlink_file_data_dir)
            .err()
            .expect("expected symlink-file rejection")
            .to_string()
            .contains("unavailable")
    );

    let directory_path_data_dir = temp.path().join("directory-path-data");
    owner_only_dir(&directory_path_data_dir);
    owner_only_dir(&protected_content_root(&directory_path_data_dir));
    std::fs::create_dir(custody_composition_config_path(&directory_path_data_dir)).unwrap();
    fs::set_permissions(
        custody_composition_config_path(&directory_path_data_dir),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert!(
        load_runtime_custody_composition_config(&directory_path_data_dir)
            .err()
            .expect("expected non-regular-file rejection")
            .to_string()
            .contains("regular file")
    );

    let hard_link_data_dir = temp.path().join("hard-link-data");
    owner_only_dir(&hard_link_data_dir);
    owner_only_dir(&protected_content_root(&hard_link_data_dir));
    let hard_link_source_dir = temp.path().join("hard-link-source");
    owner_only_dir(&hard_link_source_dir);
    let hard_link_source = hard_link_source_dir.join("custody-composition.json");
    fs::write(
        &hard_link_source,
        serde_json::to_vec(&serde_json::to_value(&config).unwrap()).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&hard_link_source, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(
        &hard_link_source,
        custody_composition_config_path(&hard_link_data_dir),
    )
    .unwrap();
    assert!(load_runtime_custody_composition_config(&hard_link_data_dir)
        .err()
        .expect("expected hard-link rejection")
        .to_string()
        .contains("hard-linked"));
}

#[cfg(unix)]
#[test]
fn runtime_mint_journal_uses_exact_owner_only_root_and_contains_no_route_or_signed_config() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&protected_content_root(&data_dir));
    let config = custody_composition_config(
        crate::auth::now_ts(),
        custody_route_bindings(
            &signed_custody_epoch(),
            [
                RuntimeCustodyRouteTransportConfig::Local,
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xee),
                },
                RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                    peer_did: peer_did_for_seed(0xef),
                },
            ],
        ),
    );
    write_owner_only_custody_composition_config(&data_dir, &config);
    let loaded = load_runtime_custody_composition_config(&data_dir)
        .unwrap()
        .unwrap();
    let configured_peer_did = match &loaded.routes[1].transport {
        ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
            peer_did, ..
        }) => peer_did.clone(),
        _ => panic!("expected carrier route"),
    };

    let journal = runtime_mint_journal(&data_dir);
    let draft = mint_draft_for_composition_journal_test();
    let persisted = journal.persist_bound(&draft).unwrap();
    assert_eq!(persisted.draft().mint_id(), draft.mint_id());

    let mint_root = protected_content_root(&data_dir).join("runtime-mint");
    assert!(mint_root.is_dir());
    assert_eq!(
        fs::metadata(&mint_root).unwrap().permissions().mode() & 0o777,
        0o700
    );

    assert!(!any_file_contains(
        &mint_root,
        base64::engine::general_purpose::STANDARD
            .decode(&config.signed_pool_base64)
            .unwrap()
            .as_slice()
    ));
    assert!(!any_file_contains(
        &mint_root,
        base64::engine::general_purpose::STANDARD
            .decode(&config.signed_epoch_base64)
            .unwrap()
            .as_slice()
    ));
    assert!(!any_file_contains(
        &mint_root,
        base64::engine::general_purpose::STANDARD
            .decode(&config.signed_committee_authorization_base64)
            .unwrap()
            .as_slice()
    ));
    assert!(!any_file_contains(
        &mint_root,
        configured_peer_did.as_bytes()
    ));
}

#[tokio::test]
async fn runtime_invokes_custody_target_not_any_capsule_sub_provider() {
    let registry = Arc::new(ProviderRegistry::new());
    let custody = RecordingProvider::new(
        "custody",
        json!({"status": "ok", "data": {"echo": "custody"}}),
    );
    let key = RecordingProvider::new(
        "library",
        json!({"status": "ok", "data": {"echo": "unrelated-capsule-provider"}}),
    );
    registry
        .register_sub_provider("library", key.clone())
        .await
        .unwrap();
    register_custody_runtime_provider_target(registry.as_ref(), custody.clone())
        .await
        .unwrap();

    let data = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "release_contribution",
        json!({"op": "release_contribution"}),
    )
    .await
    .unwrap();
    assert_eq!(data["echo"], "custody");

    let custody_requests = custody.requests().await;
    let key_requests = key.requests().await;
    assert_eq!(custody_requests.len(), 1);
    assert!(key_requests.is_empty());
    assert_eq!(
        custody_requests[0]["_runtime_invocation"]["source"],
        RUNTIME_PROVIDER_ID
    );
    assert_eq!(
        custody_requests[0]["_runtime_invocation"]["target"],
        CUSTODY_PROVIDER_ID
    );
    assert_eq!(
        custody_requests[0]["_runtime_invocation"]["carrier"],
        Value::Null
    );
    assert_eq!(
        custody_requests[0]["_runtime_invocation"]["transport"],
        "runtime-local-provider-plane"
    );
}

#[tokio::test]
async fn runtime_custody_invoke_fails_closed_on_provider_errors() {
    let registry = Arc::new(ProviderRegistry::new());
    let custody = RecordingProvider::new(
        "custody",
        json!({"status": "error", "code": "invalid_request"}),
    );
    register_custody_runtime_provider_target(registry.as_ref(), custody)
        .await
        .unwrap();
    let err = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "release_contribution",
        json!({"op": "release_contribution"}),
    )
    .await
    .unwrap_err();
    assert!(err.contains("rejected the request"));
}

#[tokio::test]
async fn custody_target_registration_adds_no_capsule_sub_provider_scheme() {
    let registry = Arc::new(ProviderRegistry::new());
    let custody = RecordingProvider::new(
        "custody",
        json!({"status": "ok", "data": {"echo": "custody"}}),
    );
    let key = RecordingProvider::new(
        "library",
        json!({"status": "ok", "data": {"echo": "unrelated-capsule-provider"}}),
    );
    registry
        .register_sub_provider("library", key)
        .await
        .unwrap();
    register_custody_runtime_provider_target(&registry, custody)
        .await
        .unwrap();
    let mut schemes = registry.sub_provider_schemes().await;
    schemes.sort();
    assert_eq!(schemes, vec!["library".to_string()]);
}

#[cfg(unix)]
#[tokio::test]
async fn custody_registration_passes_the_root_set_from_disk() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(&state_root);
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    crate::host_trust::seed_for_test(&data_dir, true);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    assert!(registry.sub_provider_schemes().await.is_empty());
    assert!(
        registry
            .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
    );

    let response = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "release_contribution",
        json!({"op": "release_contribution"}),
    )
    .await
    .unwrap();
    assert_eq!(response["echo"], "custody");

    let mut requests = fs::read_to_string(&request_log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 3);
    let init: Value = serde_json::from_str(&requests.remove(0)).unwrap();
    assert_eq!(init["op"], "init");
    // Plan B T2.1: the base is the custody-provider folder and `extra`
    // lists the roots found on disk, capped by the node settings.
    assert_eq!(
        init["config"]["base_path"],
        Value::String(state_root.parent().unwrap().to_string_lossy().to_string())
    );
    assert_eq!(init["config"]["allowed_paths"], json!([]));
    assert_eq!(init["config"]["read_only"], false);
    assert_eq!(init["config"]["encryption_key"], "");
    assert_eq!(
        init["config"]["extra"],
        json!({
            "roots": [{"path": "inactive"}],
            "max_roots": crate::custody_release_limits::CUSTODY_NODE_SETTINGS.max_pools,
        })
    );
    let status: Value = serde_json::from_str(&requests.remove(0)).unwrap();
    assert_eq!(status, json!({"op": "status"}));
    let forwarded: Value = serde_json::from_str(&requests.remove(0)).unwrap();
    assert_eq!(forwarded["op"], "release_contribution");
    assert!(forwarded.get("_runtime_invocation").is_none());
    assert!(forwarded.get("_runtime_transfer").is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn custody_wrapper_rejects_public_private_op_and_evidence_injection() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    crate::host_trust::seed_for_test(&data_dir, true);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();

    let private_op_error = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "evaluate_rights",
        json!({ "op": "evaluate_rights" }),
    )
    .await
    .unwrap_err();
    assert!(private_op_error.contains("invocation failed"));

    let evidence_error = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "release_contribution",
        json!({
            "op": "release_contribution",
            "chain_data": {"schema": "forbidden"},
        }),
    )
    .await
    .unwrap_err();
    assert!(evidence_error.contains("invocation failed"));

    let extra_field_error = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "release_contribution",
        json!({
            "op": "release_contribution",
            "unexpected": true,
        }),
    )
    .await
    .unwrap_err();
    assert!(extra_field_error.contains("rejected the request"));

    let carrier_error = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "release_contribution",
        json!({
            "op": "release_contribution",
            "carrier": {"ticket": "forbidden"},
        }),
    )
    .await
    .unwrap_err();
    assert!(carrier_error.contains("invocation failed"));

    let requests = fs::read_to_string(&request_log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 3);
    let init: Value = serde_json::from_str(&requests[0]).unwrap();
    assert_eq!(init["op"], "init");
    let status: Value = serde_json::from_str(&requests[1]).unwrap();
    assert_eq!(status, json!({"op": "status"}));
    let forwarded: Value = serde_json::from_str(&requests[2]).unwrap();
    assert_eq!(forwarded["op"], "release_contribution");
    assert_eq!(forwarded["unexpected"], true);
    assert!(forwarded.get("_runtime_invocation").is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn custody_wrapper_status_surface_matches_public_dispatch() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, _pid_file, _request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    crate::host_trust::seed_for_test(&data_dir, true);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();

    let status = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "status",
        json!({
            "op": "status",
        }),
    )
    .await
    .unwrap();

    assert_eq!(status["provider"], "custody");
    assert!(semver::Version::parse(status["version"].as_str().unwrap()).is_ok());
    assert_eq!(status["configured"], Value::Bool(true));
    assert_eq!(
        status["supported_operations"],
        json!([
            "status",
            "provision_node_share",
            "release_contribution",
            "evaluate",
            "release_pool_contribution",
            "sign_pool_statement",
            "provision_pool_node_share"
        ])
    );
    assert!(status["supported_operations"]
        .as_array()
        .unwrap()
        .iter()
        .all(|value| value != "shutdown"
            && value != "prepare_evidence"
            && value != "settle_evidence"));
    assert_eq!(status["request_schema"], CUSTODY_PROVIDER_REQUEST_SCHEMA_V1);
    assert_eq!(
        status["response_schema"],
        CUSTODY_PROVIDER_RESPONSE_SCHEMA_V1
    );
}

#[cfg(unix)]
#[tokio::test]
async fn custody_wrapper_accepts_local_and_carrier_envelopes() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let provider = spawn_custody_wrapper_for_test(&binary, &data_dir).await;

    for transport in ["runtime-local-provider-plane", "carrier-provider-plane"] {
        let response = provider
            .send_raw(&json!({
                "op": "release_contribution",
                "_runtime_invocation": custody_runtime_envelope(
                    "release_contribution",
                    transport,
                ),
            }))
            .await
            .unwrap();
        assert_eq!(response["status"], "ok");
    }

    let requests = fs::read_to_string(&request_log)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 3);
    for forwarded in requests.iter().skip(1) {
        let forwarded: Value = serde_json::from_str(forwarded).unwrap();
        assert_eq!(forwarded["op"], "release_contribution");
        assert!(forwarded.get("_runtime_invocation").is_none());
        assert!(forwarded.get("carrier").is_none());
        assert!(!forwarded.to_string().contains("source_endpoint_did"));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn custody_wrapper_rejects_invalid_transport_and_injected_carrier_data() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, _pid_file, _request_log) = write_mock_custody_provider(temp.path());
    let provider = spawn_custody_wrapper_for_test(&binary, &data_dir).await;

    let invalid_transport = provider
        .send_raw(&json!({
            "op": "release_contribution",
            "_runtime_invocation": custody_runtime_envelope(
                "release_contribution",
                "unsupported-provider-plane",
            ),
        }))
        .await
        .unwrap_err();
    assert!(invalid_transport
        .to_string()
        .contains("runtime envelope is invalid"));

    let injected_carrier = provider
        .send_raw(&json!({
            "op": "release_contribution",
            "_runtime_invocation": custody_runtime_envelope(
                "release_contribution",
                "carrier-provider-plane",
            ),
            "carrier": {"ticket": "forbidden"},
        }))
        .await
        .unwrap_err();
    assert!(injected_carrier
        .to_string()
        .contains("unsupported injected carrier data"));

    for (name, transport, carrier) in [
        (
            "missing authenticated Carrier endpoint",
            "carrier-provider-plane",
            Value::Null,
        ),
        (
            "invalid Carrier endpoint DID",
            "carrier-provider-plane",
            json!({"source_endpoint_did": "did:key:invalid"}),
        ),
        (
            "extra Carrier metadata",
            "carrier-provider-plane",
            json!({
                "source_endpoint_did": crate::carrier::public_key_to_did(
                    &iroh::SecretKey::from_bytes(&[0x52; 32]).public(),
                )
                .unwrap(),
                "route": "forbidden",
            }),
        ),
        (
            "Carrier metadata on a local request",
            "runtime-local-provider-plane",
            json!({
                "source_endpoint_did": crate::carrier::public_key_to_did(
                    &iroh::SecretKey::from_bytes(&[0x53; 32]).public(),
                )
                .unwrap(),
            }),
        ),
    ] {
        let mut envelope = custody_runtime_envelope("release_contribution", transport);
        envelope["carrier"] = carrier;
        let error = provider
            .send_raw(&json!({
                "op": "release_contribution",
                "_runtime_invocation": envelope,
            }))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("runtime envelope is invalid"),
            "{name}: {error}"
        );
    }
}

#[test]
fn custody_ops_are_declared_in_the_surface() {
    use crate::custody_surface::{declared_ops, OP_CUSTODY_EVALUATE, TARGET_CUSTODY};
    let declared: Vec<&str> = declared_ops(TARGET_CUSTODY).collect();
    // The additional ops are the wrapper's evaluation and the private seal signing commands.
    for op in CUSTODY_PROVIDER_OPERATIONS {
        assert_eq!(declared.contains(op), *op != "shutdown", "{op}");
    }
    for op in &declared {
        assert!(
            matches!(
                *op,
                OP_CUSTODY_EVALUATE
                    | ATTEST_REMOTE_SEAL_UPLOAD_OP
                    | AUTHORIZE_REMOTE_SEAL_SHARE_OP
                    | SIGN_REMOTE_SEAL_COMPLETION_OP
            ) || CUSTODY_PROVIDER_OPERATIONS.contains(op),
            "{op}"
        );
    }
    for code in ["unknown_envelope", "rate_limited"] {
        assert!(
            super::super::CUSTODY_EFFECT_FREE_REFUSAL_CODES.contains(&code),
            "{code}"
        );
        assert!(
            super::super::CUSTODY_REPORTABLE_REFUSAL_CODES.contains(&code),
            "{code}"
        );
    }
}

#[tokio::test]
async fn runtime_custody_registry_adapter_invokes_selected_custody_endpoint_for_rights() {
    let registry = Arc::new(ProviderRegistry::new());
    let envelope = custody_envelope_for_media(0x11);
    let operation = make_signed_runtime_release_operation_for_envelope_and_seed(0x21, &envelope);
    let decision = make_signed_node_rights_decision(&operation, 1, RightsDecisionV1::Allowed);
    let custody = RecordingProvider::new(
        "custody",
        ok_provider_response(
            serde_json::to_value(RightsProviderResponseV1::new_decision(&decision).unwrap())
                .unwrap(),
        ),
    );
    let unrelated = RecordingProvider::new(
        "library",
        ok_provider_response(json!({"echo": "unrelated-capsule-provider"})),
    );
    registry
        .register_runtime_provider_target(CUSTODY_PROVIDER_ID, custody.clone())
        .await
        .unwrap();
    registry
        .register_sub_provider("library", unrelated.clone())
        .await
        .unwrap();

    let adapter = RuntimeCustodyRegistryAdapter::new(
        registry.clone(),
        elastos_runtime::provider::ProviderInvocationTransport::Local,
        super::super::RuntimeCustodyCallDiagnostics::default(),
    );
    let request = RightsProviderRequestV1::new_evaluate(node_public_key(1), &operation).unwrap();

    let response = adapter.evaluate_rights(&request).await.unwrap();
    assert_eq!(
        response.status(),
        elastos_protected_content_provider_contracts::RightsProviderResponseStatusV1::Decision
    );
    let custody_requests = custody.requests().await;
    assert_eq!(custody_requests.len(), 1);
    assert!(unrelated.requests().await.is_empty());
    let recorded = &custody_requests[0];
    assert_eq!(recorded["op"], "evaluate");
    assert_eq!(
        recorded["_runtime_invocation"]["source"],
        RUNTIME_PROVIDER_ID
    );
    assert_eq!(
        recorded["_runtime_invocation"]["target"],
        CUSTODY_PROVIDER_ID
    );
    assert_eq!(
        recorded["_runtime_invocation"]["transport"],
        "runtime-local-provider-plane"
    );
    assert_eq!(recorded["_runtime_invocation"]["carrier"], Value::Null);
    assert!(recorded.get("chain_data").is_none());
    assert!(recorded.get("evidence").is_none());
    let debug = format!("{adapter:?}");
    assert!(!debug.contains("runtime-local-provider-plane"));
    assert!(!debug.contains("ProviderRegistry"));
}

#[tokio::test]
async fn runtime_custody_registry_adapter_invokes_selected_custody_endpoint_for_release() {
    let registry = Arc::new(ProviderRegistry::new());
    let envelope = custody_envelope_for_media(0x11);
    let operation = make_signed_runtime_release_operation_for_envelope_and_seed(0x21, &envelope);
    let decision = make_signed_node_rights_decision(&operation, 1, RightsDecisionV1::Allowed);
    let contribution = make_signed_node_contribution(&operation, 1);
    let custody = RecordingProvider::new(
        "custody",
        ok_provider_response(
            serde_json::to_value(
                CustodyProviderResponseV1::new_contribution(&contribution).unwrap(),
            )
            .unwrap(),
        ),
    );
    let unrelated = RecordingProvider::new(
        "library",
        ok_provider_response(json!({"echo": "unrelated-capsule-provider"})),
    );
    registry
        .register_runtime_provider_target(CUSTODY_PROVIDER_ID, custody.clone())
        .await
        .unwrap();
    registry
        .register_sub_provider("library", unrelated.clone())
        .await
        .unwrap();

    let adapter = RuntimeCustodyRegistryAdapter::new(
        registry.clone(),
        elastos_runtime::provider::ProviderInvocationTransport::Local,
        super::super::RuntimeCustodyCallDiagnostics::default(),
    );
    let request =
        CustodyProviderRequestV1::new_release_contribution(&operation, &decision).unwrap();

    let response = adapter.release_contribution(&request).await.unwrap();
    assert_eq!(
        response.status(),
        elastos_protected_content_provider_contracts::CustodyProviderResponseStatusV1::Contribution
    );
    let custody_requests = custody.requests().await;
    assert_eq!(custody_requests.len(), 1);
    assert!(unrelated.requests().await.is_empty());
    let recorded = &custody_requests[0];
    assert_eq!(recorded["op"], "release_contribution");
    assert_eq!(
        recorded["_runtime_invocation"]["source"],
        RUNTIME_PROVIDER_ID
    );
    assert_eq!(
        recorded["_runtime_invocation"]["target"],
        CUSTODY_PROVIDER_ID
    );
    assert_eq!(
        recorded["_runtime_invocation"]["transport"],
        "runtime-local-provider-plane"
    );
    assert_eq!(recorded["_runtime_invocation"]["carrier"], Value::Null);
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_registry_adapter_process_happy_path_uses_public_provision_receipt() {
    let binary = required_test_binary_path(TEST_CUSTODY_PROVIDER_BIN_ENV);
    let temp = tempfile::tempdir().unwrap();
    let temp_root = fs::canonicalize(temp.path()).unwrap();
    let data_dir = temp_root.join("data");
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(state_root.parent().unwrap());
    let provisioned = provision_custody_node_public_receipt(&binary, &state_root, 0x21);

    let registry = Arc::new(ProviderRegistry::new());
    crate::host_trust::seed_wci_host_for_test(&data_dir);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();

    let custody_epoch = signed_custody_epoch_with_first_node(
        provisioned.node_public_key,
        provisioned.node_custody_public_key,
    );
    let provisioning_now = crate::auth::now_ts();
    let envelope =
        provisioned_custody_envelope_for_media_with_epoch(0x11, &custody_epoch, provisioning_now);
    let provisioning_record =
        provisioning_record_for_selected_node(&envelope, provisioned.node_public_key);
    let provisioning =
        signed_runtime_custody_provisioning_at(&provisioning_record, 0x21, provisioning_now);
    let adapter = RuntimeCustodyRegistryAdapter::new(
        registry.clone(),
        elastos_runtime::provider::ProviderInvocationTransport::Local,
        super::super::RuntimeCustodyCallDiagnostics::default(),
    );

    let provision_request =
        CustodyProviderRequestV1::new_provision_node_share(&provisioning_record, &provisioning)
            .unwrap();
    let provision_response = adapter
        .provision_node_share(&provision_request)
        .await
        .unwrap();
    assert_eq!(
        provision_response.provisioned_record_identity().unwrap(),
        provisioning_record.record_identity().unwrap()
    );

    let operation_now = crate::auth::now_ts();
    let operation = make_signed_runtime_release_operation_for_envelope_and_epoch_at(
        0x21,
        &envelope,
        custody_epoch.clone(),
        operation_now,
    );
    let rights_request =
        RightsProviderRequestV1::new_evaluate(provisioned.node_public_key, &operation).unwrap();
    let chain = ProcessChainEvidenceProvider::new(rights_request.clone(), true);
    registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain.clone())
        .await
        .unwrap();

    let rights_validation_now = crate::auth::now_ts();
    let validated_rights = match ValidatedRightsProviderRequestV1::decode_and_validate_at(
        &rights_request.to_json_vec().unwrap(),
        rights_validation_now,
    ) {
        Ok(validated) => validated,
        Err(error) => panic!("local rights request validation failed: {error:?}"),
    };
    assert_eq!(
        validated_rights.selected_node_public_key(),
        provisioned.node_public_key
    );

    let rights_response = adapter.evaluate_rights(&rights_request).await.unwrap();
    let decision = rights_response.signed_node_rights_decision().unwrap();
    let release_request =
        CustodyProviderRequestV1::new_release_contribution(&operation, &decision).unwrap();
    let release_validation_now = crate::auth::now_ts();
    let validated_release = ValidatedCustodyProviderRequestV1::decode_and_validate_at(
        &release_request.to_json_vec().unwrap(),
        runtime_operation_issuer_for_seed(0x21),
        provisioned.node_public_key,
        release_validation_now,
    )
    .unwrap();
    let validated_release = validated_release.release_contribution().unwrap();
    let authenticated_operation = operation
        .verify(
            operation.statement().runtime_operation_issuer(),
            release_validation_now,
        )
        .unwrap();
    assert_eq!(
        validated_release.authenticated_runtime_release_operation(),
        &authenticated_operation
    );
    assert_eq!(validated_release.signed_node_rights_decision(), &decision);
    let release_response = adapter
        .release_contribution(&release_request)
        .await
        .unwrap();
    if release_response.status()
        == elastos_protected_content_provider_contracts::CustodyProviderResponseStatusV1::Failure
    {
        panic!(
            "release provider failure: {:?}",
            release_response.failure_code().unwrap()
        );
    }
    let contribution = release_response.signed_node_contribution().unwrap();

    let verification_now = crate::auth::now_ts();
    let authenticated = operation
        .verify(
            operation.statement().runtime_operation_issuer(),
            verification_now,
        )
        .unwrap();
    let node_set = custody_epoch.statement().node_set().unwrap();
    authenticated
        .verify_node_contribution(&contribution, &node_set, verification_now)
        .unwrap();

    let chain_requests = chain.requests().await;
    assert_eq!(chain_requests.len(), 1);
    assert_eq!(chain_requests[0]["op"], CHAIN_RIGHTS_EVIDENCE_OP);
    assert_eq!(
        chain_requests[0]["_runtime_invocation"]["source"],
        RUNTIME_PROVIDER_ID
    );
    assert_eq!(
        chain_requests[0]["_runtime_invocation"]["target"],
        CHAIN_PROVIDER_ID
    );
    assert_eq!(
        chain_requests[0]["_runtime_invocation"]["transport"],
        "runtime-local-provider-plane"
    );
    assert_eq!(
        chain_requests[0]["_runtime_invocation"]["carrier"],
        Value::Null
    );
    let mut inner_chain_request = chain_requests[0].clone();
    inner_chain_request
        .as_object_mut()
        .unwrap()
        .remove("_runtime_invocation");
    assert_eq!(
        inner_chain_request,
        chain_rights_evidence_request(&operation).unwrap()
    );
}

/// PM-F2 (a): the host-wide share lock belongs to the write, not to its
/// caller. A caller cancelled after its write was dispatched leaves the lock
/// held until that write has landed, so the next write waits for it and is
/// checked against its bytes: two writes that each fit the maximum alone,
/// not together, never both commit.
#[cfg(unix)]
#[tokio::test]
async fn guard_a_share_write_cancelled_after_dispatch_keeps_the_host_lock_until_it_lands() {
    let host = HostShareWriteFixture::start(None).await;
    let first = host.v1_share_request(0x11);
    let second = host.v1_share_request(0x12);
    let max = HostShareWriteFixture::charged_bytes(&first)
        .max(HostShareWriteFixture::charged_bytes(&second));
    host.set_storage_maximum(Some(max));

    // The paused provider leaves the dispatched write unanswered.
    host.signal_provider(nix::sys::signal::Signal::SIGSTOP);
    let provider = host.provider.clone();
    let cancelled = tokio::spawn(async move { provider.send_raw(&first).await });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    let provider = host.provider.clone();
    let next = tokio::spawn(async move { provider.send_raw(&second).await });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    host.signal_provider(nix::sys::signal::Signal::SIGCONT);

    let answer = next.await.unwrap().unwrap();
    assert_eq!(
        answer["code"],
        crate::host_trust::HOST_STORAGE_FULL,
        "{answer}"
    );
    // The cancelled write landed, and it alone.
    let used = host.used_bytes();
    assert!(used > 0 && used <= max, "used {used} of {max}");
    let store = elastos_protected_content_custody::NodeLocalShareStoreV1::new(
        host.node_public_key,
        custody_provider::node_share_store_dir(&super::super::custody_root_dir(
            &host.data_dir,
            custody_provider::CUSTODY_INACTIVE_ROOT_PATH,
        )),
    );
    assert_eq!(store.count().unwrap(), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_release_coordinator_process_two_of_three_success_stops_before_third_node() {
    let binary = required_test_binary_path(TEST_CUSTODY_PROVIDER_BIN_ENV);
    let temp = tempfile::tempdir().unwrap();
    let temp_root = fs::canonicalize(temp.path()).unwrap();

    let node1 = provisioned_process_custody_node(&binary, &temp_root, "node-1", 0x21, digest(0xa1));
    let node2 = provisioned_process_custody_node(&binary, &temp_root, "node-2", 0x21, digest(0xa2));
    let node3 = provisioned_process_custody_node(&binary, &temp_root, "node-3", 0x21, digest(0xa3));

    crate::host_trust::seed_wci_host_for_test(&temp_root.join("node-1"));
    register_custody_provider(&node1.registry, &binary, &temp_root.join("node-1"))
        .await
        .unwrap();
    crate::host_trust::seed_wci_host_for_test(&temp_root.join("node-2"));
    register_custody_provider(&node2.registry, &binary, &temp_root.join("node-2"))
        .await
        .unwrap();
    crate::host_trust::seed_wci_host_for_test(&temp_root.join("node-3"));
    register_custody_provider(&node3.registry, &binary, &temp_root.join("node-3"))
        .await
        .unwrap();

    let custody_epoch = signed_custody_epoch_for_node_keys([
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
    let ordered_node_keys = custody_epoch
        .statement()
        .nodes()
        .iter()
        .map(|node| node.node_public_key())
        .collect::<Vec<_>>();
    let ordered_fixtures = ordered_node_keys
        .iter()
        .map(|node_public_key| fixtures_by_node.get(node_public_key).unwrap())
        .collect::<Vec<_>>();
    let provisioning_now = crate::auth::now_ts();
    let envelope =
        provisioned_custody_envelope_for_media_with_epoch(0x11, &custody_epoch, provisioning_now);
    for fixture in fixtures_by_node.values() {
        provision_selected_node_share(fixture, &envelope, 0x21, provisioning_now).await;
    }

    let operation_now = crate::auth::now_ts();
    let operation = make_signed_runtime_release_operation_for_envelope_and_epoch_at(
        0x21,
        &envelope,
        custody_epoch.clone(),
        operation_now,
    );
    let rights_request_1 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[0].provisioned.node_public_key,
        &operation,
    )
    .unwrap();
    let rights_request_2 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[1].provisioned.node_public_key,
        &operation,
    )
    .unwrap();
    let rights_request_3 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[2].provisioned.node_public_key,
        &operation,
    )
    .unwrap();
    let chain1 = ProcessChainEvidenceProvider::new(rights_request_1, true);
    let chain2 = ProcessChainEvidenceProvider::new(rights_request_2, true);
    let chain3 = ProcessChainEvidenceProvider::new(rights_request_3, true);
    ordered_fixtures[0]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain1.clone())
        .await
        .unwrap();
    ordered_fixtures[1]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain2.clone())
        .await
        .unwrap();
    ordered_fixtures[2]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain3.clone())
        .await
        .unwrap();

    let runtime_owner_parent = temp_root.join("runtime-owner-only-parent");
    owner_only_dir(&runtime_owner_parent);
    let runtime_data_dir = runtime_owner_parent.join("runtime-release");
    let coordinator = RuntimeReleaseCoordinator::new(
        RuntimeReleaseJournal::new(runtime_data_dir.clone()),
        runtime_operation_issuer_for_seed(0x21),
        vec![
            RuntimeSelectedProvider::new(
                ordered_fixtures[0].provisioned.node_public_key,
                &ordered_fixtures[0].adapter,
                &ordered_fixtures[0].adapter,
            ),
            RuntimeSelectedProvider::new(
                ordered_fixtures[1].provisioned.node_public_key,
                &ordered_fixtures[1].adapter,
                &ordered_fixtures[1].adapter,
            ),
            RuntimeSelectedProvider::new(
                ordered_fixtures[2].provisioned.node_public_key,
                &ordered_fixtures[2].adapter,
                &ordered_fixtures[2].adapter,
            ),
        ],
    )
    .unwrap()
    .with_response_clock(crate::auth::now_ts);
    let wallet_now = crate::auth::now_ts();
    let (wallet_request, wallet_response) = wallet_request_response_for_release_at(
        &operation,
        "profile:alpha",
        "wallet-account-alpha",
        "wallet-request:11111111111111111111111111111111",
        wallet_now,
    );

    let outcome = coordinator
        .release(
            &wallet_request,
            &wallet_response,
            operation.clone().into(),
            crate::auth::now_ts(),
        )
        .await
        .unwrap();
    let signed_node_contributions = match outcome {
        RuntimeReleaseCoordinatorOutcome::Terminal(
            RuntimeReleaseTerminalResult::ContributionsReady {
                signed_node_contributions,
            },
        ) => signed_node_contributions,
        other => panic!("unexpected coordinator outcome: {other:?}"),
    };
    assert_eq!(signed_node_contributions.len(), 2);
    let verification_now = crate::auth::now_ts();
    let authenticated = operation
        .verify(
            operation.statement().runtime_operation_issuer(),
            verification_now,
        )
        .unwrap();
    let node_set = custody_epoch.statement().node_set().unwrap();
    for contribution in &signed_node_contributions {
        authenticated
            .verify_node_contribution(contribution, &node_set, verification_now)
            .unwrap();
    }
    let contributing_nodes: Vec<_> = signed_node_contributions
        .iter()
        .map(|contribution| {
            contribution
                .statement()
                .signed_rights_decision()
                .statement()
                .node_public_key()
        })
        .collect();
    assert_eq!(
        contributing_nodes,
        vec![
            ordered_fixtures[0].provisioned.node_public_key,
            ordered_fixtures[1].provisioned.node_public_key,
        ]
    );
    assert_eq!(chain1.requests().await.len(), 1);
    assert_eq!(chain2.requests().await.len(), 1);
    assert_eq!(chain3.requests().await.len(), 0);
    assert!(list_unresolved_runtime_releases(&runtime_data_dir)
        .unwrap()
        .is_empty());
    assert!(unresolved_release_audit_records(&runtime_data_dir)
        .unwrap()
        .is_empty());
    let terminal_debug = format!(
        "{:?}",
        RuntimeReleaseTerminalResult::ContributionsReady {
            signed_node_contributions,
        }
    );
    assert!(!terminal_debug.contains("node-1"));
    assert!(!terminal_debug.contains("node-2"));
    assert!(!terminal_debug.contains("node-3"));
    assert!(!terminal_debug.contains("carrier-provider-plane"));

    ordered_fixtures[0]
        .registry
        .unregister_sub_provider(CHAIN_PROVIDER_ID)
        .await
        .unwrap();
    ordered_fixtures[1]
        .registry
        .unregister_sub_provider(CHAIN_PROVIDER_ID)
        .await
        .unwrap();
    ordered_fixtures[2]
        .registry
        .unregister_sub_provider(CHAIN_PROVIDER_ID)
        .await
        .unwrap();

    let beta_now = crate::auth::now_ts();
    let beta_operation =
        make_signed_runtime_release_operation_for_envelope_and_epoch_and_recipient_at(
            0x21,
            &envelope,
            custody_epoch.clone(),
            recipient_public_key(0x31),
            recipient_identity(0x31),
            RuntimeReleaseAuditIdV1::new(digest(0xb2)).unwrap(),
            beta_now,
        );
    let (beta_wallet_request, beta_wallet_response) =
        wallet_request_response_for_release_context_at(
            &beta_operation,
            "profile:beta",
            "runtime-session:beta",
            Some("proof:beta"),
            "grant:beta",
            "launch:beta",
            "wallet-account-beta",
            "wallet-request:22222222222222222222222222222222",
            beta_now,
        );
    let beta_rights_request_1 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[0].provisioned.node_public_key,
        &beta_operation,
    )
    .unwrap();
    let beta_rights_request_2 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[1].provisioned.node_public_key,
        &beta_operation,
    )
    .unwrap();
    let beta_rights_request_3 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[2].provisioned.node_public_key,
        &beta_operation,
    )
    .unwrap();
    let beta_chain1 = ProcessChainEvidenceProvider::new(beta_rights_request_1, false);
    let beta_chain2 = ProcessChainEvidenceProvider::new(beta_rights_request_2, false);
    let beta_chain3 = ProcessChainEvidenceProvider::new(beta_rights_request_3, false);
    ordered_fixtures[0]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, beta_chain1.clone())
        .await
        .unwrap();
    ordered_fixtures[1]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, beta_chain2.clone())
        .await
        .unwrap();
    ordered_fixtures[2]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, beta_chain3.clone())
        .await
        .unwrap();

    let beta_outcome = coordinator
        .release(
            &beta_wallet_request,
            &beta_wallet_response,
            beta_operation.clone().into(),
            crate::auth::now_ts(),
        )
        .await
        .unwrap();
    let beta_denied = match beta_outcome {
        RuntimeReleaseCoordinatorOutcome::Terminal(
            RuntimeReleaseTerminalResult::RightsDenied {
                signed_node_rights_decision,
            },
        ) => signed_node_rights_decision,
        other => panic!("unexpected beta coordinator outcome: {other:?}"),
    };
    assert_eq!(beta_denied.statement().decision(), RightsDecisionV1::Denied);
    // The two nodes the threshold needs are asked together, so the denial is
    // whichever of them answered first, and the other may have stopped before
    // its chain read; the third node is never asked.
    assert!([
        ordered_fixtures[0].provisioned.node_public_key,
        ordered_fixtures[1].provisioned.node_public_key,
    ]
    .contains(&beta_denied.statement().node_public_key()));
    let beta_chain_reads = [
        beta_chain1.requests().await.len(),
        beta_chain2.requests().await.len(),
    ];
    assert!(beta_chain_reads.iter().all(|reads| *reads <= 1));
    assert!(beta_chain_reads.iter().sum::<usize>() >= 1);
    assert_eq!(beta_chain3.requests().await.len(), 0);

    let beta_replay = coordinator
        .release(
            &beta_wallet_request,
            &beta_wallet_response,
            beta_operation.clone().into(),
            crate::auth::now_ts(),
        )
        .await
        .unwrap();
    let beta_replay_denied = match beta_replay {
        RuntimeReleaseCoordinatorOutcome::Terminal(
            RuntimeReleaseTerminalResult::RightsDenied {
                signed_node_rights_decision,
            },
        ) => signed_node_rights_decision,
        other => panic!("unexpected beta replay outcome: {other:?}"),
    };
    assert_eq!(beta_replay_denied, beta_denied);
    assert_eq!(
        [
            beta_chain1.requests().await.len(),
            beta_chain2.requests().await.len(),
        ],
        beta_chain_reads,
        "a replayed denial asks no node again"
    );
    assert_eq!(beta_chain3.requests().await.len(), 0);

    let beta_persisted = RuntimeReleaseJournal::new(runtime_data_dir.clone())
        .load(beta_operation.canonical_hash().unwrap())
        .unwrap();
    assert!(matches!(
        beta_persisted.terminal_result(),
        Some(RuntimeReleaseTerminalResult::RightsDenied { .. })
    ));
    assert_eq!(
        beta_persisted
            .terminal_result()
            .unwrap()
            .contribution_count(),
        0
    );
    assert!(list_unresolved_runtime_releases(&runtime_data_dir)
        .unwrap()
        .is_empty());
    assert!(unresolved_release_audit_records(&runtime_data_dir)
        .unwrap()
        .is_empty());
    let beta_terminal_debug = format!(
        "{:?}",
        RuntimeReleaseTerminalResult::RightsDenied {
            signed_node_rights_decision: beta_denied.clone(),
        }
    );
    assert!(!beta_terminal_debug.contains("node-1"));
    assert!(!beta_terminal_debug.contains("node-2"));
    assert!(!beta_terminal_debug.contains("node-3"));
    assert!(!beta_terminal_debug.contains("carrier-provider-plane"));

    for fixture in ordered_fixtures {
        fixture
            .registry
            .unregister_sub_provider(CHAIN_PROVIDER_ID)
            .await
            .unwrap();
        fixture
            .registry
            .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
            .unwrap();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_decrypt_registry_adapter_process_reconstructs_for_prepared_recipient_and_closes_cleanly(
) {
    let custody_binary = required_test_binary_path(TEST_CUSTODY_PROVIDER_BIN_ENV);
    let decrypt_binary = required_test_binary_path(TEST_DECRYPT_PROVIDER_BIN_ENV);
    let protect_binary = required_test_binary_path(TEST_PROTECT_PROVIDER_BIN_ENV);
    let temp = tempfile::tempdir().unwrap();
    let temp_root = fs::canonicalize(temp.path()).unwrap();

    let node1 =
        provisioned_process_custody_node(&custody_binary, &temp_root, "node-1", 0x21, digest(0xa1));
    let node2 =
        provisioned_process_custody_node(&custody_binary, &temp_root, "node-2", 0x21, digest(0xa2));
    let node3 =
        provisioned_process_custody_node(&custody_binary, &temp_root, "node-3", 0x21, digest(0xa3));

    crate::host_trust::seed_wci_host_for_test(&temp_root.join("node-1"));
    register_custody_provider(&node1.registry, &custody_binary, &temp_root.join("node-1"))
        .await
        .unwrap();
    crate::host_trust::seed_wci_host_for_test(&temp_root.join("node-2"));
    register_custody_provider(&node2.registry, &custody_binary, &temp_root.join("node-2"))
        .await
        .unwrap();
    crate::host_trust::seed_wci_host_for_test(&temp_root.join("node-3"));
    register_custody_provider(&node3.registry, &custody_binary, &temp_root.join("node-3"))
        .await
        .unwrap();

    let custody_epoch = signed_custody_epoch_for_node_keys([
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
    let ordered_node_keys = custody_epoch
        .statement()
        .nodes()
        .iter()
        .map(|node| node.node_public_key())
        .collect::<Vec<_>>();
    let ordered_fixtures = ordered_node_keys
        .iter()
        .map(|node_public_key| fixtures_by_node.get(node_public_key).unwrap())
        .collect::<Vec<_>>();

    let provisioning_now = crate::auth::now_ts();
    let signed_pool = signed_custody_pool_for_epoch(
        &custody_epoch,
        (provisioning_now.saturating_sub(10), provisioning_now + 10),
    );
    let signed_committee_authorization = signed_committee_authorization_for_epoch(
        signed_pool.pool_identity().unwrap(),
        &custody_epoch,
    );
    let (clear_init_segment, clear_segments) = clear_media_components(0x11);
    let protect_registry = Arc::new(ProviderRegistry::new());
    let protect_bridge = ProviderBridge::spawn(
        &protect_binary,
        ProviderConfig {
            extra: json!({}),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let protect_provider: Arc<dyn Provider> = Arc::new(CapsuleProvider::with_scheme(
        Arc::new(protect_bridge),
        "protect",
    ));
    protect_registry
        .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect_provider)
        .await
        .unwrap();
    let protect_nodes = ordered_fixtures
        .iter()
        .map(|fixture| {
            ProtectionSessionNodeV1::new(
                fixture.provisioned.node_public_key,
                fixture.provisioned.node_custody_public_key,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let opened = invoke_typed_protect_provider(
        protect_registry.as_ref(),
        "open_protection_session",
        &ProtectProviderRequestV1::new_open_protection_session(
            digest(0xb1),
            content_access_id(0x41),
            signed_pool.pool_identity().unwrap(),
            custody_epoch.epoch_identity().unwrap(),
            signed_committee_authorization
                .authorization_identity()
                .unwrap(),
            MEDIA_MIME_TYPE_V1,
            MEDIA_CODECS_V1,
            u32::try_from(clear_segments.len()).unwrap(),
            &clear_init_segment,
            protect_nodes,
        )
        .unwrap(),
    )
    .await;
    assert_eq!(
        opened.status(),
        ProtectProviderResponseStatusV1::ProtectionSessionOpened
    );
    let protection_session_handle = opened.protection_session_handle().unwrap().unwrap();
    let protected_init_segment = opened.protected_init_segment().unwrap().to_vec();
    let mut encrypted_segments = Vec::with_capacity(clear_segments.len());
    for (segment_index, clear_segment) in clear_segments.iter().enumerate() {
        let protected = invoke_typed_protect_provider(
            protect_registry.as_ref(),
            "protect_media_segment",
            &ProtectProviderRequestV1::new_protect_media_segment(
                protection_session_handle,
                u32::try_from(segment_index).unwrap(),
                clear_segment,
            )
            .unwrap(),
        )
        .await;
        assert_eq!(
            protected.status(),
            ProtectProviderResponseStatusV1::MediaSegmentProtected
        );
        assert_eq!(
            protected.segment_index(),
            Some(u32::try_from(segment_index).unwrap())
        );
        encrypted_segments.push(protected.protected_segment().unwrap().to_vec());
    }
    let finalized = invoke_typed_protect_provider(
        protect_registry.as_ref(),
        "finalize_protection_session",
        &ProtectProviderRequestV1::new_finalize_protection_session(protection_session_handle)
            .unwrap(),
    )
    .await;
    assert_eq!(
        finalized.status(),
        ProtectProviderResponseStatusV1::ProtectionSessionFinalized
    );
    let protected_media_identity = finalized.media_identity().unwrap().unwrap();
    let envelope = finalized.custody_envelope().unwrap().unwrap();
    assert_eq!(
        protected_media_identity,
        CencFmp4MediaIdentityV1::new_from_bytes(
            &protected_init_segment,
            &encrypted_segments,
            MEDIA_MIME_TYPE_V1,
            MEDIA_CODECS_V1,
        )
        .unwrap()
    );
    assert_eq!(
        envelope.manifest().encrypted_content(),
        protected_media_identity.encrypted_content()
    );
    assert_eq!(
        envelope.manifest().custody_pool(),
        signed_pool.pool_identity().unwrap()
    );
    assert_eq!(
        envelope.manifest().custody_epoch(),
        custody_epoch.epoch_identity().unwrap()
    );
    assert_eq!(
        envelope.manifest().custody_committee_authorization(),
        signed_committee_authorization
            .authorization_identity()
            .unwrap()
    );
    assert_eq!(
        envelope.manifest().threshold(),
        ThresholdV1::new(2, 3).unwrap()
    );
    assert_eq!(
        envelope.manifest().nodes(),
        custody_epoch.statement().nodes()
    );
    let protect_closed = invoke_typed_protect_provider(
        protect_registry.as_ref(),
        "close_protection_session",
        &ProtectProviderRequestV1::new_close_protection_session(protection_session_handle).unwrap(),
    )
    .await;
    assert_eq!(
        protect_closed.status(),
        ProtectProviderResponseStatusV1::ProtectionSessionClosed
    );

    let mint_nodes = ordered_fixtures
        .iter()
        .enumerate()
        .map(|(index, fixture)| {
            let node_seed = u8::try_from(index + 1).unwrap();
            RuntimeMintNodeBinding::new(
                fixture.provisioned.node_public_key,
                CustodyPoolOperatorIdV1::new([0x80 + node_seed; 32]),
                CustodyPoolFailureDomainIdV1::new([0x90 + node_seed; 32]),
                fixture.owner_state_root,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let mint_draft = RuntimeMintDraft::new(
        &protected_init_segment,
        &encrypted_segments,
        MEDIA_MIME_TYPE_V1,
        MEDIA_CODECS_V1,
        content_access_id(0x41),
        envelope.key_envelope_identity().unwrap(),
        policy_body().policy_identity().unwrap(),
        envelope.manifest().content_key_commitment(),
        envelope.manifest().threshold(),
        mint_nodes.clone(),
    )
    .unwrap();
    let mint_owner_parent = temp_root.join("runtime-mint-owner-only-parent");
    owner_only_dir(&mint_owner_parent);
    let mint_root = mint_owner_parent.join("runtime-mint");
    let mint_selected = mint_nodes
        .iter()
        .zip(ordered_fixtures.iter())
        .map(|(binding, fixture)| RuntimeMintSelectedNode::new(binding.clone(), &fixture.adapter))
        .collect::<Vec<_>>();
    let mint_coordinator = RuntimeMintCoordinator::new(
        RuntimeMintJournal::new(mint_root.clone()),
        runtime_operation_issuer_for_seed(0x21),
        sign_runtime_statement_for_seed_0x21,
        mint_selected,
    )
    .unwrap();
    let mint_outcome = mint_coordinator
        .provision(&mint_draft, &envelope, provisioning_now)
        .await
        .unwrap();
    match mint_outcome {
        RuntimeMintCoordinatorOutcome::CustodyProvisioned { mint_id } => {
            assert_eq!(mint_id, mint_draft.mint_id());
        }
        other => panic!("unexpected mint outcome: {other:?}"),
    }
    let mint_journal = RuntimeMintJournal::new(mint_root.clone());
    let custody_provisioned = mint_journal.load(mint_draft.mint_id()).unwrap();
    assert!(custody_provisioned.all_receipts_present());
    assert_eq!(
        custody_provisioned.uncertain_node_count(),
        0,
        "every node answered with a receipt, so none is left possibly holding a share"
    );
    assert_eq!(custody_provisioned.accepted_orphans().len(), 3);
    let sealed_share_bytes = envelope.stored_shares()[0].canonical_bytes().unwrap();
    assert!(!any_file_contains(&mint_root, &sealed_share_bytes));
    assert!(!any_file_contains(&mint_root, &protected_init_segment));
    assert!(!any_file_contains(&mint_root, &encrypted_segments[0]));
    assert!(!any_file_contains(&mint_root, &clear_init_segment));
    assert!(!any_file_contains(&mint_root, &clear_segments[0]));

    let content_provider = ContentAvailabilityTestProvider::new(
        0x61,
        ContentAvailabilityTestConfig {
            checked_at: crate::auth::now_ts(),
            ..ContentAvailabilityTestConfig::accepted()
        },
    );
    let requirement = availability_requirement(content_provider.signer_did());
    let content_registry = Arc::new(ProviderRegistry::new());
    content_registry
        .register_sub_provider("content", content_provider)
        .await
        .unwrap();
    let content_directory = protected_content_directory_from_parts(
        &protected_init_segment,
        &encrypted_segments,
        &protected_media_identity,
    );
    let availability_evidence = publish_and_verify_v1_protected_content_for_test(
        content_registry.as_ref(),
        content_directory.path(),
        mint_draft.media_identity().unwrap(),
        &requirement,
        crate::auth::now_ts,
    )
    .await
    .unwrap();
    let availability_outcome = mint_coordinator
        .record_content_availability(&mint_draft, &requirement, availability_evidence)
        .unwrap();
    match availability_outcome {
        RuntimeMintCoordinatorOutcome::ContentAvailable { mint_id } => {
            assert_eq!(mint_id, mint_draft.mint_id());
        }
        other => panic!("unexpected availability outcome: {other:?}"),
    }
    let mint = mint_journal.load(mint_draft.mint_id()).unwrap();
    assert!(mint.content_availability().is_some());

    let purchase_effect = runtime_verified_purchase_effect_for_mint(
        &mint,
        "profile:alpha",
        "wallet-account-alpha",
        "wallet-request:11111111111111111111111111111111",
        0xaa,
        crate::auth::now_ts(),
    );
    let profile = ProfileIdentityV1::from_public_key_bytes(
        SigningKey::from_bytes(&[0x26; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let session_a = RuntimeSessionBindingV1::new(digest(0x66)).unwrap();
    let session_b = RuntimeSessionBindingV1::new(digest(0x67)).unwrap();
    let preliminary_buy = bind_buy(&mint, "profile:alpha", profile, &purchase_effect).unwrap();
    assert_eq!(
        preliminary_buy.binding_for_session(session_a).unwrap(),
        binding_for_envelope(&envelope)
    );
    assert_eq!(preliminary_buy.action(), RightsActionV1::View);

    let decrypt_registry = Arc::new(ProviderRegistry::new());
    register_protected_content_decrypt_provider(
        &decrypt_registry,
        &decrypt_binary,
        runtime_operation_issuer_for_seed(0x21),
    )
    .await
    .unwrap();
    let decrypt = RuntimeDecryptRegistryAdapter::new(decrypt_registry.clone());

    let flow_now = crate::auth::now_ts();
    let audit_a =
        super::super::runtime_open_audit_id("profile:alpha", preliminary_buy.mint_id(), flow_now);
    let audit_b =
        super::super::runtime_open_audit_id("profile:alpha", preliminary_buy.mint_id(), flow_now);
    let prepare_issued_at = flow_now.saturating_sub(5);
    let prepare_expires_at = flow_now + 240;
    let prepared_a = prepare_recipient(
        &decrypt,
        &preliminary_buy,
        session_a,
        audit_a,
        runtime_operation_issuer_for_seed(0x21),
        prepare_issued_at,
        prepare_expires_at,
    )
    .await
    .unwrap();
    let replayed_a = prepare_recipient(
        &decrypt,
        &preliminary_buy,
        session_a,
        audit_a,
        runtime_operation_issuer_for_seed(0x21),
        prepare_issued_at,
        prepare_expires_at,
    )
    .await
    .unwrap();
    assert_eq!(replayed_a, prepared_a);
    let prepared_b = prepare_recipient(
        &decrypt,
        &preliminary_buy,
        session_b,
        audit_b,
        runtime_operation_issuer_for_seed(0x21),
        prepare_issued_at,
        prepare_expires_at,
    )
    .await
    .unwrap();
    assert_ne!(prepared_a.binding(), prepared_b.binding());

    let operation = make_signed_runtime_release_operation_for_envelope_and_epoch_and_recipient_at(
        0x21,
        &envelope,
        custody_epoch.clone(),
        *prepared_a.recipient_public_key(),
        prepared_a.recipient_identity().clone(),
        audit_a,
        flow_now,
    );
    assert_eq!(
        prepared_a.binding(),
        operation.statement().rights_request().request().binding()
    );
    let (wallet_request, wallet_response) = wallet_request_response_for_release_at(
        &operation,
        "profile:alpha",
        "wallet-account-alpha",
        "wallet-request:11111111111111111111111111111111",
        flow_now,
    );
    let buy = bind_buy(&mint, "profile:alpha", profile, &purchase_effect).unwrap();

    let rights_request_1 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[0].provisioned.node_public_key,
        &operation,
    )
    .unwrap();
    let rights_request_2 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[1].provisioned.node_public_key,
        &operation,
    )
    .unwrap();
    let rights_request_3 = RightsProviderRequestV1::new_evaluate(
        ordered_fixtures[2].provisioned.node_public_key,
        &operation,
    )
    .unwrap();
    let chain1 = ProcessChainEvidenceProvider::new(rights_request_1, true);
    let chain2 = ProcessChainEvidenceProvider::new(rights_request_2, true);
    let chain3 = ProcessChainEvidenceProvider::new(rights_request_3, true);
    ordered_fixtures[0]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain1.clone())
        .await
        .unwrap();
    ordered_fixtures[1]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain2.clone())
        .await
        .unwrap();
    ordered_fixtures[2]
        .registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain3.clone())
        .await
        .unwrap();

    let runtime_owner_parent = temp_root.join("runtime-owner-only-parent");
    owner_only_dir(&runtime_owner_parent);
    let runtime_data_dir = runtime_owner_parent.join("runtime-release");
    let coordinator = RuntimeReleaseCoordinator::new(
        RuntimeReleaseJournal::new(runtime_data_dir.clone()),
        runtime_operation_issuer_for_seed(0x21),
        vec![
            RuntimeSelectedProvider::new(
                ordered_fixtures[0].provisioned.node_public_key,
                &ordered_fixtures[0].adapter,
                &ordered_fixtures[0].adapter,
            ),
            RuntimeSelectedProvider::new(
                ordered_fixtures[1].provisioned.node_public_key,
                &ordered_fixtures[1].adapter,
                &ordered_fixtures[1].adapter,
            ),
            RuntimeSelectedProvider::new(
                ordered_fixtures[2].provisioned.node_public_key,
                &ordered_fixtures[2].adapter,
                &ordered_fixtures[2].adapter,
            ),
        ],
    )
    .unwrap()
    .with_response_clock(crate::auth::now_ts);
    let outcome = coordinator
        .release(
            &wallet_request,
            &wallet_response,
            operation.clone().into(),
            crate::auth::now_ts(),
        )
        .await
        .unwrap();
    let signed_node_contributions = match outcome {
        RuntimeReleaseCoordinatorOutcome::Terminal(
            RuntimeReleaseTerminalResult::ContributionsReady {
                signed_node_contributions,
            },
        ) => signed_node_contributions,
        other => panic!("unexpected coordinator outcome: {other:?}"),
    };
    assert_eq!(signed_node_contributions.len(), 2);
    assert_eq!(chain1.requests().await.len(), 1);
    assert_eq!(chain2.requests().await.len(), 1);
    assert_eq!(chain3.requests().await.len(), 0);
    let expected_terminal = RuntimeReleaseCoordinatorOutcome::Terminal(
        RuntimeReleaseTerminalResult::ContributionsReady {
            signed_node_contributions: signed_node_contributions.clone(),
        },
    );
    let replay_coordinator = RuntimeReleaseCoordinator::new(
        RuntimeReleaseJournal::new(runtime_data_dir.clone()),
        runtime_operation_issuer_for_seed(0x21),
        vec![
            RuntimeSelectedProvider::new(
                ordered_fixtures[0].provisioned.node_public_key,
                &ordered_fixtures[0].adapter,
                &ordered_fixtures[0].adapter,
            ),
            RuntimeSelectedProvider::new(
                ordered_fixtures[1].provisioned.node_public_key,
                &ordered_fixtures[1].adapter,
                &ordered_fixtures[1].adapter,
            ),
            RuntimeSelectedProvider::new(
                ordered_fixtures[2].provisioned.node_public_key,
                &ordered_fixtures[2].adapter,
                &ordered_fixtures[2].adapter,
            ),
        ],
    )
    .unwrap()
    .with_response_clock(crate::auth::now_ts);
    let replay_outcome = replay_coordinator
        .release(
            &wallet_request,
            &wallet_response,
            operation.clone().into(),
            crate::auth::now_ts(),
        )
        .await
        .unwrap();
    assert_eq!(replay_outcome, expected_terminal);
    assert_eq!(chain1.requests().await.len(), 1);
    assert_eq!(chain2.requests().await.len(), 1);
    assert_eq!(chain3.requests().await.len(), 0);
    assert!(list_unresolved_runtime_releases(&runtime_data_dir)
        .unwrap()
        .is_empty());
    assert!(unresolved_release_audit_records(&runtime_data_dir)
        .unwrap()
        .is_empty());

    let terminal_receipt = make_signed_terminal_receipt_at(
        &operation,
        &signed_node_contributions,
        0x61,
        crate::auth::now_ts(),
    );

    let wrong_open = open_viewer_session(
        &decrypt,
        &RuntimeOpenViewerSessionInput {
            buy: &buy,
            prepared_recipient: &prepared_b,
            signed_runtime_release_operation: &operation,
            expected_terminal_issuer: terminal_receipt.statement().issuer(),
            content_key_commitment: envelope.manifest().content_key_commitment(),
            content: RuntimeOpenViewerContentV1::Media {
                media_identity: &protected_media_identity,
                protected_init_segment: &protected_init_segment,
            },
            signed_node_contributions: &signed_node_contributions,
            signed_terminal_receipt: &terminal_receipt,
            now_unix_seconds: crate::auth::now_ts(),
        },
    )
    .await;
    assert_eq!(wrong_open, Err(RuntimeOpenError::MintSelection));
    cancel_prepared_recipient(&decrypt, &prepared_b)
        .await
        .unwrap();
    cancel_prepared_recipient(&decrypt, &prepared_b)
        .await
        .unwrap();
    let wrong_media_identity = media_identity(0x41);
    let wrong_object_open = open_viewer_session(
        &decrypt,
        &RuntimeOpenViewerSessionInput {
            buy: &buy,
            prepared_recipient: &prepared_a,
            signed_runtime_release_operation: &operation,
            expected_terminal_issuer: terminal_receipt.statement().issuer(),
            content_key_commitment: envelope.manifest().content_key_commitment(),
            content: RuntimeOpenViewerContentV1::Media {
                media_identity: &wrong_media_identity,
                protected_init_segment: &protected_init_segment,
            },
            signed_node_contributions: &signed_node_contributions,
            signed_terminal_receipt: &terminal_receipt,
            now_unix_seconds: crate::auth::now_ts(),
        },
    )
    .await;
    assert_eq!(wrong_object_open, Err(RuntimeOpenError::DecryptResult));

    let session = open_viewer_session(
        &decrypt,
        &RuntimeOpenViewerSessionInput {
            buy: &buy,
            prepared_recipient: &prepared_a,
            signed_runtime_release_operation: &operation,
            expected_terminal_issuer: terminal_receipt.statement().issuer(),
            content_key_commitment: envelope.manifest().content_key_commitment(),
            content: RuntimeOpenViewerContentV1::Media {
                media_identity: &protected_media_identity,
                protected_init_segment: &protected_init_segment,
            },
            signed_node_contributions: &signed_node_contributions,
            signed_terminal_receipt: &terminal_receipt,
            now_unix_seconds: crate::auth::now_ts(),
        },
    )
    .await
    .unwrap();

    let clear_init = read_viewer_media_part(
        &decrypt,
        &session,
        ViewerMediaPartSelectorV1::init(),
        crate::auth::now_ts(),
    )
    .await
    .unwrap();
    assert_eq!(clear_init.clear_media_part(), clear_init_segment.as_slice());

    let mut tampered_segment = encrypted_segments[1].clone();
    tampered_segment[0] ^= 0x01;
    let tampered_selector = ViewerMediaPartSelectorV1::segment(1, tampered_segment).unwrap();
    assert_eq!(
        read_viewer_media_part(&decrypt, &session, tampered_selector, crate::auth::now_ts(),).await,
        Err(RuntimeOpenError::DecryptResult)
    );

    let selector = ViewerMediaPartSelectorV1::segment(1, encrypted_segments[1].clone()).unwrap();
    let clear_segment =
        read_viewer_media_part(&decrypt, &session, selector.clone(), crate::auth::now_ts())
            .await
            .unwrap();
    let clear_segment_replay =
        read_viewer_media_part(&decrypt, &session, selector.clone(), crate::auth::now_ts())
            .await
            .unwrap();
    assert_eq!(clear_segment.part_selector(), &selector);
    assert_eq!(
        clear_segment.clear_media_part(),
        clear_segment_replay.clear_media_part()
    );
    assert_eq!(
        clear_segment.clear_media_part(),
        clear_segments[1].as_slice()
    );

    close_viewer_session(&decrypt, &session).await.unwrap();
    close_viewer_session(&decrypt, &session).await.unwrap();
    cancel_prepared_recipient(&decrypt, &prepared_a)
        .await
        .unwrap();
    let audit_c =
        super::super::runtime_open_audit_id("profile:alpha", preliminary_buy.mint_id(), flow_now);
    let prepared_c = prepare_recipient(
        &decrypt,
        &preliminary_buy,
        session_a,
        audit_c,
        runtime_operation_issuer_for_seed(0x21),
        prepare_issued_at,
        prepare_expires_at,
    )
    .await
    .unwrap();
    assert_ne!(
        prepared_c.prepared_recipient_handle(),
        session.viewer_session_handle()
    );
    cancel_prepared_recipient(&decrypt, &prepared_c)
        .await
        .unwrap();

    let session_debug = format!("{session:?}");
    let init_debug = format!("{clear_init:?}");
    let segment_debug = format!("{clear_segment:?}");
    assert!(!session_debug.contains("carrier-provider-plane"));
    assert!(!session_debug.contains("node-1"));
    assert!(!session_debug.contains("node-2"));
    assert!(!session_debug.contains("node-3"));
    assert!(!init_debug.contains("share"));
    assert!(!segment_debug.contains("share"));
    assert!(!segment_debug.contains("cek"));

    assert!(!any_file_contains(&runtime_data_dir, &sealed_share_bytes));
    assert!(!any_file_contains(
        &runtime_data_dir,
        &protected_init_segment
    ));
    assert!(!any_file_contains(
        &runtime_data_dir,
        &encrypted_segments[0]
    ));
    assert!(!any_file_contains(&runtime_data_dir, &clear_init_segment));
    assert!(!any_file_contains(&runtime_data_dir, &clear_segments[0]));

    decrypt_registry
        .unregister_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)
        .await
        .unwrap();
    let mut schemes = decrypt_registry.sub_provider_schemes().await;
    schemes.sort();
    assert_eq!(schemes, Vec::<String>::new());
    protect_registry
        .unregister_runtime_provider_target(PROTECT_PROVIDER_ID)
        .await
        .unwrap();
    let mut protect_schemes = protect_registry.sub_provider_schemes().await;
    protect_schemes.sort();
    assert_eq!(protect_schemes, Vec::<String>::new());
    assert_eq!(
        prepare_recipient(
            &decrypt,
            &buy,
            RuntimeSessionBindingV1::new(digest(0x66)).unwrap(),
            RuntimeReleaseAuditIdV1::new(digest(0xaf)).unwrap(),
            runtime_operation_issuer_for_seed(0x21),
            crate::auth::now_ts(),
            crate::auth::now_ts() + 45,
        )
        .await,
        Err(RuntimeOpenError::DecryptResult)
    );

    assert!(list_unresolved_runtime_releases(&runtime_data_dir)
        .unwrap()
        .is_empty());
    assert!(unresolved_release_audit_records(&runtime_data_dir)
        .unwrap()
        .is_empty());

    for fixture in ordered_fixtures {
        fixture
            .registry
            .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
            .unwrap();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn custody_registration_rejects_missing_or_unsafe_root_before_provider_use() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("missing-data");
    owner_only_dir(&data_dir);
    let (binary, pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    let error = register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("missing or unsafe"));
    assert!(!error.to_string().contains(temp.path().to_str().unwrap()));
    assert!(!request_log.exists());
    assert!(!pid_file.exists());

    let unsafe_data_dir = temp.path().join("unsafe-data");
    owner_only_dir(&unsafe_data_dir);
    let unsafe_root = inactive_custody_state_root(&unsafe_data_dir);
    owner_only_dir(&unsafe_root);
    fs::set_permissions(&unsafe_root, fs::Permissions::from_mode(0o755)).unwrap();
    // Plan B T2.1 (user 10:26): the Home's root set names an unsafe root and
    // starts the others (`custody_registration_names_an_unsafe_root_and_starts_the_others`);
    // the custody host's one legacy root is still refused before any use.
    let error = register_custody_host_provider(&registry, &binary, &unsafe_data_dir)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("missing or unsafe"));
    assert!(!error.to_string().contains(temp.path().to_str().unwrap()));
    assert!(!request_log.exists());
    assert!(!pid_file.exists());
}

/// B1 (#624 update hop): a Home that never provisioned custody does not
/// start the provider at boot, so its log carries no "failed to register"
/// warning for a normal state. A present root still starts the provider.
#[cfg(unix)]
#[tokio::test]
async fn custody_boot_start_skips_only_a_home_that_never_provisioned_custody() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("fresh");
    owner_only_dir(&data_dir);
    let (binary, pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    assert_eq!(
        start_custody_provider_at_boot(&registry, &binary, &data_dir)
            .await
            .unwrap(),
        CustodyProviderStartup::NotProvisioned
    );
    assert!(!pid_file.exists());
    assert!(!request_log.exists());

    owner_only_dir(&inactive_custody_state_root(&data_dir));
    crate::host_trust::seed_for_test(&data_dir, true);
    assert_eq!(
        start_custody_provider_at_boot(&registry, &binary, &data_dir)
            .await
            .unwrap(),
        CustodyProviderStartup::Registered
    );
    assert!(process_is_running(read_pid(&pid_file)));
    registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .unwrap();
}

/// Only genuine absence is skipped: a root that is present but malformed,
/// or a custody folder that cannot be read, still fails boot registration
/// (and so still warns), before any provider process starts.
#[cfg(unix)]
#[tokio::test]
async fn custody_boot_start_still_refuses_a_malformed_or_unreadable_root() {
    let temp = tempfile::tempdir().unwrap();
    let (binary, pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    // The inactive root's name is taken by a file.
    let malformed = temp.path().join("malformed");
    owner_only_dir(&malformed);
    let base = custody_provider_base(&malformed);
    fs::create_dir_all(base.parent().unwrap()).unwrap();
    owner_only_dir(&base);
    fs::write(inactive_custody_state_root(&malformed), b"not a root").unwrap();
    let error = start_custody_provider_at_boot(&registry, &binary, &malformed)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("missing or unsafe"), "{error}");

    // The custody folder itself is a file, so nothing under it can be read.
    let unreadable = temp.path().join("unreadable");
    owner_only_dir(&unreadable);
    let base = custody_provider_base(&unreadable);
    fs::create_dir_all(base.parent().unwrap()).unwrap();
    fs::write(&base, b"not a folder").unwrap();
    let error = start_custody_provider_at_boot(&registry, &binary, &unreadable)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("missing or unsafe"), "{error}");

    // The custody folder is a link: dangling, or to an empty folder. Both
    // children read as missing through it, which is not absence.
    for (name, target) in [("dangling", "nowhere"), ("linked-empty", "empty")] {
        let home = temp.path().join(name);
        owner_only_dir(&home);
        let base = custody_provider_base(&home);
        fs::create_dir_all(base.parent().unwrap()).unwrap();
        let target = temp.path().join(target);
        if name == "linked-empty" {
            owner_only_dir(&target);
        }
        std::os::unix::fs::symlink(&target, &base).unwrap();
        let error = start_custody_provider_at_boot(&registry, &binary, &home)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("missing or unsafe"),
            "{name}: {error}"
        );
    }

    assert!(!pid_file.exists());
    assert!(!request_log.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn inactive_custody_registry_unregisters_shutdowns_and_restarts_bridge() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, pid_file, _request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    crate::host_trust::seed_for_test(&data_dir, true);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let first_pid = read_pid(&pid_file);

    registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .unwrap();
    assert!(!process_is_running(first_pid));

    crate::host_trust::seed_for_test(&data_dir, true);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let second_pid = read_pid(&pid_file);
    assert_ne!(first_pid, second_pid);
    let response = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "release_contribution",
        json!({"op": "release_contribution"}),
    )
    .await
    .unwrap();
    assert_eq!(response["echo"], "custody");

    registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .unwrap();
    assert!(!process_is_running(second_pid));
}

#[cfg(unix)]
#[tokio::test]
async fn inactive_custody_duplicate_registration_rejects_and_settles_rejected_child() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, pid_file, _request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    crate::host_trust::seed_for_test(&data_dir, true);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let first_pid = read_pid(&pid_file);

    let error = register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("failed to register inactive custody route"));

    let pids = read_pids(&pid_file);
    assert_eq!(pids.len(), 2);
    let rejected_pid = *pids.last().unwrap();
    assert_ne!(first_pid, rejected_pid);
    assert!(process_is_running(first_pid));
    assert!(!process_is_running(rejected_pid));

    registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn protected_content_decrypt_startup_rejects_invalid_status_and_settles_child() {
    let issuer = runtime_operation_issuer_for_seed(0x41);
    let mut cases = Vec::new();
    let mut wrong_identity = protected_content_decrypt_provider_status();
    wrong_identity["data"]["provider"] = json!("decrypt");
    cases.push(("identity", wrong_identity));
    let mut wrong_request_schema = protected_content_decrypt_provider_status();
    wrong_request_schema["data"]["request_schema"] = json!("wrong-request-schema");
    cases.push(("request-schema", wrong_request_schema));
    let mut wrong_response_schema = protected_content_decrypt_provider_status();
    wrong_response_schema["data"]["response_schema"] = json!("wrong-response-schema");
    cases.push(("response-schema", wrong_response_schema));
    let mut wrong_version = protected_content_decrypt_provider_status();
    wrong_version["data"]["version"] = json!("wrong-version");
    cases.push(("version", wrong_version));
    let mut unconfigured = protected_content_decrypt_provider_status();
    unconfigured["data"]["configured"] = json!(false);
    cases.push(("configured", unconfigured));
    let mut wrong_operations = protected_content_decrypt_provider_status();
    wrong_operations["data"]["supported_operations"] = json!(["status", "shutdown"]);
    cases.push(("operations", wrong_operations));
    let mut extra_data = protected_content_decrypt_provider_status();
    extra_data["data"]["route"] = json!("private");
    cases.push(("extra-data", extra_data));
    let mut extra_top = protected_content_decrypt_provider_status();
    extra_top["route"] = json!("private");
    cases.push(("extra-top", extra_top));

    for (name, status) in cases {
        let temp = tempfile::tempdir().unwrap();
        let case_root = temp.path().join(name);
        fs::create_dir_all(&case_root).unwrap();
        let (binary, pid_file, request_log) =
            write_mock_protected_content_decrypt_provider(&case_root, issuer, &status);
        let registry = Arc::new(ProviderRegistry::new());

        register_protected_content_decrypt_provider(&registry, &binary, issuer)
            .await
            .expect_err("invalid protected-content decrypt status must fail closed");

        assert!(!process_is_running(read_pid(&pid_file)), "case {name}");
        let requests = fs::read_to_string(&request_log).unwrap();
        assert!(requests.contains(r#""op":"status""#), "case {name}");
        assert!(requests.contains(r#""op":"shutdown""#), "case {name}");
        assert!(matches!(
            registry
                .invoke_provider(ProviderInvocation {
                    source: RUNTIME_PROVIDER_ID.to_string(),
                    target: PROTECTED_CONTENT_DECRYPT_PROVIDER_ID.to_string(),
                    op: "status".to_string(),
                    request: json!({"op":"status"}),
                    transfer: ProviderTransfer::Json,
                    range: None,
                    progress: None,
                    transport: ProviderInvocationTransport::Local,
                })
                .await,
            Err(ProviderError::NoProvider(target))
                if target == PROTECTED_CONTENT_DECRYPT_PROVIDER_ID
        ));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn protected_content_decrypt_startup_rejects_wrong_issuer_and_settles_child() {
    let temp = tempfile::tempdir().unwrap();
    let expected_issuer = runtime_operation_issuer_for_seed(0x41);
    let supplied_issuer = runtime_operation_issuer_for_seed(0x42);
    let (binary, pid_file, request_log) = write_mock_protected_content_decrypt_provider(
        temp.path(),
        expected_issuer,
        &protected_content_decrypt_provider_status(),
    );
    let registry = Arc::new(ProviderRegistry::new());

    register_protected_content_decrypt_provider(&registry, &binary, supplied_issuer)
        .await
        .expect_err("a provider that rejects the Runtime issuer must fail closed");

    assert!(!process_is_running(read_pid(&pid_file)));
    let requests = fs::read_to_string(&request_log).unwrap();
    assert!(requests.contains(&format!(
        r#""trusted_runtime_issuer":"0x{}""#,
        hex::encode(supplied_issuer.as_bytes())
    )));
    assert!(requests.contains(r#""op":"shutdown""#));
    assert!(!requests.contains(r#""op":"status""#));
}

#[cfg(unix)]
#[tokio::test]
async fn protected_content_decrypt_duplicate_and_restart_settle_exact_processes() {
    let temp = tempfile::tempdir().unwrap();
    let issuer = runtime_operation_issuer_for_seed(0x41);
    let (binary, pid_file, request_log) = write_mock_protected_content_decrypt_provider(
        temp.path(),
        issuer,
        &protected_content_decrypt_provider_status(),
    );
    let registry = Arc::new(ProviderRegistry::new());

    register_protected_content_decrypt_provider(&registry, &binary, issuer)
        .await
        .unwrap();
    let first_pid = read_pid(&pid_file);
    assert!(process_is_running(first_pid));

    let duplicate = register_protected_content_decrypt_provider(&registry, &binary, issuer)
        .await
        .unwrap_err();
    assert!(duplicate.to_string().contains("already registered"));
    let duplicate_pids = read_pids(&pid_file);
    assert_eq!(duplicate_pids.len(), 2);
    let rejected_pid = duplicate_pids[1];
    assert!(process_is_running(first_pid));
    assert!(!process_is_running(rejected_pid));

    registry
        .unregister_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)
        .await
        .unwrap();
    assert!(!process_is_running(first_pid));

    register_protected_content_decrypt_provider(&registry, &binary, issuer)
        .await
        .unwrap();
    let replacement_pid = read_pid(&pid_file);
    assert_ne!(replacement_pid, first_pid);
    assert_ne!(replacement_pid, rejected_pid);
    assert!(process_is_running(replacement_pid));
    registry
        .unregister_runtime_provider_target(PROTECTED_CONTENT_DECRYPT_PROVIDER_ID)
        .await
        .unwrap();
    assert!(!process_is_running(replacement_pid));

    let requests = fs::read_to_string(&request_log).unwrap();
    assert_eq!(requests.matches(r#""op":"shutdown""#).count(), 3);
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_fails_closed_without_device_key() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let now = crate::auth::now_ts();
    let epoch = signed_custody_epoch();
    write_owner_only_custody_composition_config(
        &data_dir,
        &custody_composition_config(
            now,
            custody_route_bindings(
                &epoch,
                [
                    RuntimeCustodyRouteTransportConfig::Local,
                    RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                        peer_did: peer_did_for_seed(0xa1),
                    },
                    RuntimeCustodyRouteTransportConfig::CarrierPeerDid {
                        peer_did: peer_did_for_seed(0xa2),
                    },
                ],
            ),
        ),
    );
    let error = publish_runtime_custody_library_object(
        &data_dir,
        Arc::new(ProviderRegistry::new()),
        library_publish_test_input(&data_dir, "person:local:runtime-custody-missing-device-key"),
    )
    .await
    .expect_err("missing device key must fail closed");
    assert!(
        error
            .to_string()
            .contains("local Runtime device signing key is missing"),
        "{error}"
    );
    assert!(!data_dir.join("protected-content/runtime-mint").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn completed_local_mint_replays_after_its_retained_composition_expires() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let input = library_publish_test_input(&data_dir, "person:local:expired-composition-replay");
    let then = crate::auth::now_ts() - 7200;
    let epoch = signed_custody_epoch();
    write_owner_only_custody_composition_config(
        &data_dir,
        &custody_composition_config(then, library_publish_test_routes(&epoch)),
    );
    let mint_id = seed_settled_runtime_custody_mint_record_at(&data_dir, &input, true, then);
    let journal = runtime_mint_journal(&data_dir);
    let intent = journal
        .mark_intent_completed(library_publish_request_id(&input), mint_id)
        .unwrap();
    let active = custody_composition_config_path(&data_dir);
    super::super::retain_mint_composition(
        &data_dir,
        intent.custody_committee_authorization(),
        &fs::read(&active).unwrap(),
    )
    .unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    assert!(load_runtime_custody_composition(&data_dir, registry.clone()).is_err());

    // With no provider registered, the completed result can only come from
    // the existing journal. A fresh protect or custody write cannot pass.
    let facts = publish_runtime_custody_library_object(&data_dir, registry.clone(), input.clone())
        .await
        .expect("a completed mint should still replay on its original composition");
    assert_eq!(facts.mint_id, mint_id);
    assert_eq!(journal.load_intent(intent.request_id()).unwrap(), intent);

    let mut changed = input;
    changed.wallet_account_id.push_str("-different");
    let error = publish_runtime_custody_library_object(&data_dir, registry, changed)
        .await
        .expect_err("the expired composition cannot authorize a different wallet");
    assert_eq!(
        attempt_conflict_reason(&error),
        RuntimeCustodyAttemptConflictReason::AuthorityChanged
    );
}

/// The codes the custody capsule emits only from paths that precede its
/// durable write. Everything else — `backend_unavailable` above all, which the
/// capsule returns both for a refusal before the write and for a failure after
/// it — must stay uncertain.
#[test]
fn custody_refusal_codes_claim_no_effect_only_where_the_capsule_proves_it() {
    for code in [
        "invalid_request",
        "provisioning_refused",
        "rights_denied",
        "operation_expired",
        "evidence_expired",
    ] {
        assert_eq!(
            super::super::classify_custody_failure(
                "release_contribution",
                &super::super::ProviderInvocationFailure::Refused {
                    code: code.to_string(),
                    message: "refused".to_string(),
                },
            ),
            RuntimeProviderCallError::RefusedWithoutEffect,
            "{code} is emitted only before the durable write"
        );
    }
    for code in ["backend_unavailable", "invalid_config", "unknown", ""] {
        // `backend_unavailable` is the one that matters here: the capsule
        // returns it both for a refusal before the write and for a failure
        // after it.
        assert_eq!(
            super::super::classify_custody_failure(
                "provision_node_share",
                &super::super::ProviderInvocationFailure::Refused {
                    code: code.to_string(),
                    message: "refused".to_string(),
                },
            ),
            RuntimeProviderCallError::NoExactResult,
            "{code} spans acted and did-not-act paths"
        );
    }
}

/// A custody refusal keeps its code in the Runtime's report when the code is
/// one the capsule emits, and nothing else from the refusal travels with it.
#[test]
fn custody_private_rejection_keeps_only_a_known_code() {
    assert_eq!(
        super::super::custody_private_rejection_message(Some("operation_expired")),
        "custody private request was rejected: operation_expired"
    );
    assert_eq!(
        super::super::custody_private_rejection_message(Some("invalid_request")),
        "custody private request was rejected: invalid_request"
    );
    for code in [
        None,
        Some(""),
        Some("/home/someone/key"),
        Some("0xdeadbeef"),
    ] {
        assert_eq!(
            super::super::custody_private_rejection_message(code),
            "custody private request was rejected"
        );
    }
}

/// A reply that never arrived is not a node that never acted: the capsule can
/// complete its write and then fail to answer.
#[test]
fn a_missing_or_malformed_custody_reply_is_effect_uncertain() {
    assert_eq!(
        super::super::classify_custody_failure(
            "provision_node_share",
            &super::super::ProviderInvocationFailure::NotCompleted {
                detail: "transport closed".to_string(),
            },
        ),
        RuntimeProviderCallError::NoExactResult
    );
    assert_eq!(
        super::super::classify_custody_failure(
            "provision_node_share",
            &super::super::ProviderInvocationFailure::MalformedResponse {
                detail: "custody provider provision_node_share response is missing status"
                    .to_string(),
            },
        ),
        RuntimeProviderCallError::NoExactResult
    );
}

/// Every custody op that touches another party's content key is refused on
/// an everyday host, with that op's existing effect-free code, so a remote
/// coordinator fails over; every statement kind of `sign_pool_statement` is
/// refused alike. Status and the rights evaluation are not gated.
#[test]
fn restart_with_existing_roots_on_an_everyday_host_releases_no_key() {
    use super::super::{custody_host_trust_refusal, CUSTODY_EFFECT_FREE_REFUSAL_CODES};
    use crate::custody_surface::{
        OP_CUSTODY_EVALUATE, OP_CUSTODY_PROVISION_NODE_SHARE, OP_CUSTODY_RELEASE_CONTRIBUTION,
        OP_CUSTODY_RELEASE_POOL_CONTRIBUTION, OP_CUSTODY_SIGN_POOL_STATEMENT, OP_CUSTODY_STATUS,
    };
    for (op, code) in [
        (OP_CUSTODY_RELEASE_CONTRIBUTION, "invalid_request"),
        (OP_CUSTODY_RELEASE_POOL_CONTRIBUTION, "unknown_envelope"),
        (OP_CUSTODY_PROVISION_NODE_SHARE, "provisioning_refused"),
        (OP_CUSTODY_SIGN_POOL_STATEMENT, "invalid_request"),
    ] {
        let refusal = custody_host_trust_refusal(op, false).unwrap_or_else(|| panic!("{op}"));
        assert_eq!(refusal["status"], "error", "{op}");
        assert_eq!(refusal["code"], code, "{op}");
        assert!(CUSTODY_EFFECT_FREE_REFUSAL_CODES.contains(&code), "{op}");
    }
    for op in [OP_CUSTODY_STATUS, OP_CUSTODY_EVALUATE] {
        assert!(custody_host_trust_refusal(op, false).is_none(), "{op}");
    }
}

#[test]
fn switching_to_wci_operated_and_restarting_restores_every_role() {
    use super::super::custody_host_trust_refusal;
    use crate::custody_surface::{
        OP_CUSTODY_EVALUATE, OP_CUSTODY_PROVISION_NODE_SHARE, OP_CUSTODY_RELEASE_CONTRIBUTION,
        OP_CUSTODY_RELEASE_POOL_CONTRIBUTION, OP_CUSTODY_SIGN_POOL_STATEMENT, OP_CUSTODY_STATUS,
    };
    for op in [
        OP_CUSTODY_RELEASE_CONTRIBUTION,
        OP_CUSTODY_RELEASE_POOL_CONTRIBUTION,
        OP_CUSTODY_PROVISION_NODE_SHARE,
        OP_CUSTODY_SIGN_POOL_STATEMENT,
        OP_CUSTODY_STATUS,
        OP_CUSTODY_EVALUATE,
    ] {
        assert!(custody_host_trust_refusal(op, true).is_none(), "{op}");
    }
}

/// The registered wrapper of an everyday host still loads its existing root
/// (Hosting lists it) but never forwards a gated op: the provider sees only
/// its start-up, and the custody root is left byte for byte.
#[cfg(unix)]
#[tokio::test]
async fn existing_roots_shares_replay_and_journals_are_untouched() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(&state_root);
    fs::write(state_root.join("existing-share.bin"), b"share bytes").unwrap();
    let before = fs::read(state_root.join("existing-share.bin")).unwrap();
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());
    crate::host_trust::seed_for_test(&data_dir, false);
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    assert!(
        registry
            .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
    );
    for op in [
        "release_contribution",
        "release_pool_contribution",
        "provision_node_share",
        "sign_pool_statement",
        "provision_pool_node_share",
    ] {
        let refused = invoke_json_provider(
            registry.as_ref(),
            CUSTODY_PROVIDER_ID,
            op,
            json!({"op": op}),
        )
        .await;
        assert!(refused.is_err(), "{op}: {refused:?}");
    }
    let requests = fs::read_to_string(&request_log).unwrap();
    assert_eq!(
        requests.lines().count(),
        2,
        "init and status only: {requests}"
    );
    assert_eq!(
        fs::read(state_root.join("existing-share.bin")).unwrap(),
        before
    );
}

#[cfg(unix)]
#[tokio::test]
async fn custody_host_registration_passes_one_legacy_root() {
    // The custody-host profile keeps the legacy init: the root itself and
    // `extra: null`.
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(&state_root);
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    super::super::register_custody_host_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let init: Value = serde_json::from_str(
        fs::read_to_string(&request_log)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(init["op"], "init");
    assert_eq!(
        init["config"]["base_path"],
        Value::String(state_root.to_string_lossy().to_string())
    );
    assert!(init["config"]["extra"].is_null());
}

#[cfg(unix)]
#[test]
fn custody_roots_come_from_disk() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    assert!(super::super::custody_provider_root_paths(&data_dir)
        .unwrap()
        .is_empty());

    let base = inactive_custody_state_root(&data_dir)
        .parent()
        .unwrap()
        .to_path_buf();
    let pool_b = format!("pools/{}", "b".repeat(64));
    let pool_a = format!("pools/{}", "a".repeat(64));
    for dir in [
        "inactive",
        "pools",
        pool_b.as_str(),
        pool_a.as_str(),
        // Never roots: a tombstone (T2.3), a staging folder, a bad name.
        "pools/.removed-0000",
        "pools/.custody-provider-stage-1-00",
        "pools/ABCD",
    ] {
        owner_only_dir(&base.join(dir));
    }
    fs::write(
        base.join("pools").join("c".repeat(64)),
        b"a file, not a root",
    )
    .unwrap();
    assert_eq!(
        super::super::custody_provider_root_paths(&data_dir).unwrap(),
        vec!["inactive".to_string(), pool_a.clone(), pool_b.clone()]
    );

    // A Home that serves only `pools/<hex>` roots still has roots.
    fs::remove_dir(base.join("inactive")).unwrap();
    assert_eq!(
        super::super::custody_provider_root_paths(&data_dir).unwrap(),
        vec![pool_a, pool_b]
    );
}

#[cfg(unix)]
#[test]
fn custody_status_check_accepts_the_private_root_list() {
    let key = format!("0x{}", "11".repeat(32));
    super::super::require_custody_provider_status(&custody_status_with_roots(&key)).unwrap();
    // A provider without roots (older build) still passes.
    super::super::require_custody_provider_status(&ProtectedStartupProvider::Custody.status())
        .unwrap();
    // A malformed root entry is refused.
    for root in [
        json!({"path": "inactive", "node_public_key": key, "configured": true}),
        json!({"path": "inactive", "node_public_key": key, "configured": true, "shares_held": 1, "more": 1}),
        json!({"path": 7, "node_public_key": key, "configured": true, "shares_held": 1}),
        json!({"path": "inactive", "node_public_key": key, "configured": "yes", "shares_held": 1}),
    ] {
        let mut status = ProtectedStartupProvider::Custody.status();
        status["data"]["roots"] = json!([root]);
        assert!(
            super::super::require_custody_provider_status(&status).is_err(),
            "{root}"
        );
    }
    let mut status = ProtectedStartupProvider::Custody.status();
    status["data"]["roots"] = json!({"path": "inactive"});
    assert!(super::super::require_custody_provider_status(&status).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn public_status_never_lists_roots() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let key = format!("0x{}", "5a".repeat(32));
    let (binary, _pid_file, _request_log) =
        write_mock_custody_provider_with_status(temp.path(), &custody_status_with_roots(&key));
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();

    let status = invoke_json_provider(
        registry.as_ref(),
        CUSTODY_PROVIDER_ID,
        "status",
        json!({"op": "status"}),
    )
    .await
    .unwrap();
    assert_eq!(status["provider"], "custody");
    assert!(status.get("roots").is_none());
    let encoded = status.to_string();
    assert!(!encoded.contains(&key));
    assert!(!encoded.contains("shares_held"));
    assert!(!encoded.contains("inactive"));
}

#[cfg(unix)]
#[tokio::test]
async fn custody_registration_names_an_unsafe_root_and_starts_the_others() {
    // User decision 2026-11-12 10:26: an unsafe root follows the per-root rule.
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(&state_root);
    let pool = format!("pools/{}", "e".repeat(64));
    let unsafe_root = state_root.parent().unwrap().join(&pool);
    owner_only_dir(&unsafe_root);
    fs::set_permissions(&unsafe_root, fs::Permissions::from_mode(0o755)).unwrap();
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let init: Value = serde_json::from_str(
        fs::read_to_string(&request_log)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        init["config"]["extra"]["roots"],
        json!([{"path": "inactive"}, {"path": pool}])
    );
}

#[cfg(unix)]
#[tokio::test]
async fn new_root_reaches_the_running_provider_without_restart() {
    // Plan B T2.2 (S2-Q1, user decision 2026-11-12 10:35): the server keeps
    // the custody bridge and sends a fresh init; no registry change.
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(&state_root);
    let (binary, request_log) = write_mock_root_set_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let pool = format!("pools/{}", "c".repeat(64));
    assert!(!super::super::custody_root_loaded(&data_dir, &pool).await);

    owner_only_dir(&state_root.parent().unwrap().join(&pool));
    let roots = super::super::refresh_custody_roots(&data_dir)
        .await
        .unwrap();
    assert_eq!(
        roots
            .iter()
            .map(|root| root.path.clone().unwrap())
            .collect::<Vec<_>>(),
        vec!["inactive".to_string(), pool.clone()]
    );
    assert!(super::super::custody_root_loaded(&data_dir, &pool).await);
    assert!(super::super::custody_root_loaded(&data_dir, "inactive").await);
    // The same process: one spawn, a second init with both roots.
    let inits: Vec<Value> = fs::read_to_string(&request_log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|request| request["op"] == "init")
        .collect();
    assert_eq!(inits.len(), 2);
    assert_eq!(
        inits[1]["config"]["extra"]["roots"],
        json!([{"path": "inactive"}, {"path": pool}])
    );
    assert!(
        registry
            .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
    );
}

/// S2-F1: with several roots, a refresh the provider refuses leaves the
/// pool served and reports the failure; a later retry stops it, and the
/// provider then holds only the roots left.
#[cfg(unix)]
#[tokio::test]
async fn stop_serving_reports_a_failed_refresh_and_a_retry_finishes() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
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
    let (kept, stopped) = ("a".repeat(64), "b".repeat(64));
    for hex in [&kept, &stopped] {
        owner_only_dir(&base.join(format!("pools/{hex}")));
        plant_served_entry(&data_dir, hex);
    }
    let refuse = temp.path().join("refuse-init");
    let binary = write_failing_root_set_custody_provider(temp.path(), &refuse, 0);
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let stopped_path = format!("pools/{stopped}");
    assert!(super::super::custody_root_loaded(&data_dir, &stopped_path).await);

    fs::write(&refuse, b"").unwrap();
    let write = crate::custody_consent::lock_custody_writes().await;
    let error = crate::custody_pool_setup::stop_serving_pool(
        &write,
        &data_dir,
        Some(&registry),
        &stopped,
        100,
    )
    .await
    .unwrap_err();
    assert_eq!(refusal_code(&error), "stop_failed");
    // Still served, and truthfully so: the provider still holds the root.
    assert!(crate::custody_consent::served_pools(&data_dir)
        .unwrap()
        .entries
        .contains_key(&format!("sha256:{stopped}")));
    assert!(super::super::custody_root_loaded(&data_dir, &stopped_path).await);

    fs::remove_file(&refuse).unwrap();
    crate::custody_pool_setup::stop_serving_pool(&write, &data_dir, Some(&registry), &stopped, 101)
        .await
        .unwrap();
    assert!(!crate::custody_consent::served_pools(&data_dir)
        .unwrap()
        .entries
        .contains_key(&format!("sha256:{stopped}")));
    assert!(!super::super::custody_root_loaded(&data_dir, &stopped_path).await);
    assert!(super::super::custody_root_loaded(&data_dir, &format!("pools/{kept}")).await);
    assert!(!base.join(&stopped_path).exists());
}

/// S2-F1: on the last root, a provider that does not stop cleanly leaves the
/// pool served and the root in place; a later retry stops it.
#[cfg(unix)]
#[tokio::test]
async fn stop_serving_the_last_root_reports_a_failed_unregister_and_a_retry_finishes() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
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
    let only = "c".repeat(64);
    let root = base.join(format!("pools/{only}"));
    owner_only_dir(&root);
    plant_served_entry(&data_dir, &only);
    let binary =
        write_failing_root_set_custody_provider(temp.path(), &temp.path().join("never"), 1);
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();

    let write = crate::custody_consent::lock_custody_writes().await;
    let error = crate::custody_pool_setup::stop_serving_pool(
        &write,
        &data_dir,
        Some(&registry),
        &only,
        100,
    )
    .await
    .unwrap_err();
    assert_eq!(refusal_code(&error), "stop_failed");
    assert!(crate::custody_consent::served_pools(&data_dir)
        .unwrap()
        .entries
        .contains_key(&format!("sha256:{only}")));
    assert!(root.is_dir(), "the root stays until the provider is out");

    crate::custody_pool_setup::stop_serving_pool(&write, &data_dir, Some(&registry), &only, 101)
        .await
        .unwrap();
    assert!(crate::custody_consent::served_pools(&data_dir)
        .unwrap()
        .entries
        .is_empty());
    assert!(!root.exists());
    assert!(
        !registry
            .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
    );
}

/// S2-F1: Remove on a serving Home whose provider refuses the refresh keeps
/// this Home's node and reports the failure; a later retry removes it and
/// the provider then holds only the served root.
#[cfg(unix)]
#[tokio::test]
async fn remove_reports_a_failed_refresh_and_a_retry_finishes() {
    let temp = safe_ancestor_tempdir();
    let data_dir = temp.path().canonicalize().unwrap().join("data");
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
    let (own, served) = (
        format!("pools/{}", "d".repeat(64)),
        format!("pools/{}", "e".repeat(64)),
    );
    owner_only_dir(&base.join(&own));
    owner_only_dir(&base.join(&served));
    crate::collaboration_config::create_owner_only_file(
        &base.join(&own).join("trusted-runtime-issuer"),
        crate::protected_content_config::runtime_issuer_hex(&data_dir)
            .unwrap()
            .as_bytes(),
        "test issuer",
    )
    .unwrap();
    crate::custody_pool_setup::tests::write_local_node(&data_dir, "Home", "Paris");
    let node_file = crate::custody_pool_setup::local_node_path(&data_dir);
    assert!(node_file.exists());
    let refuse = temp.path().join("refuse-init");
    let binary = write_failing_root_set_custody_provider(temp.path(), &refuse, 0);
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    assert!(super::super::custody_root_loaded(&data_dir, &own).await);

    fs::write(&refuse, b"").unwrap();
    let write = crate::custody_consent::lock_custody_writes().await;
    let error = crate::custody_pool_setup::remove_local_node(&write, &data_dir, Some(&registry))
        .await
        .unwrap_err();
    assert_eq!(refusal_code(&error), "remove_failed");
    assert!(
        node_file.exists(),
        "this Home's node stays until the provider is out"
    );
    assert!(super::super::custody_root_loaded(&data_dir, &own).await);

    fs::remove_file(&refuse).unwrap();
    crate::custody_pool_setup::remove_local_node(&write, &data_dir, Some(&registry))
        .await
        .unwrap();
    assert!(!node_file.exists());
    assert!(!super::super::custody_root_loaded(&data_dir, &own).await);
    assert!(super::super::custody_root_loaded(&data_dir, &served).await);
}

/// dkms-reviewer S2-F1: while the provider is Settling (its shutdown did not
/// finish), an interrupted removal with no root left is not reported
/// complete; the tombstone and node file stay, and a retry once the provider
/// is out finishes it.
#[cfg(unix)]
#[tokio::test]
async fn interrupted_removal_is_not_complete_while_the_provider_is_settling() {
    let (temp, data_dir, node_file, tombstone) = interrupted_removal_home(false);
    let binary =
        write_failing_root_set_custody_provider(temp.path(), &temp.path().join("never"), 1);
    // Boot saw the own root, so the provider runs; then the removal set the
    // root aside and the provider's shutdown did not finish.
    let own = tombstone.with_file_name("d".repeat(64));
    fs::rename(&tombstone, &own).unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    fs::rename(&own, &tombstone).unwrap();
    assert!(registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .is_err());
    assert!(
        registry
            .has_runtime_provider_target_registration(CUSTODY_PROVIDER_ID)
            .await
    );
    assert!(
        !registry
            .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
    );

    let write = crate::custody_consent::lock_custody_writes().await;
    let error = crate::custody_pool_setup::remove_local_node(&write, &data_dir, Some(&registry))
        .await
        .unwrap_err();
    assert_eq!(refusal_code(&error), "remove_failed");
    assert!(node_file.exists());
    assert!(tombstone.exists());

    registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .unwrap();
    crate::custody_pool_setup::remove_local_node(&write, &data_dir, Some(&registry))
        .await
        .unwrap();
    assert!(!node_file.exists());
    assert!(!tombstone.exists());
}

/// dkms-reviewer S2-F1: with a custody target this server cannot refresh (no
/// remembered bridge) still registered, Settling, an interrupted removal is
/// not reported complete; once the target is gone a retry finishes it.
#[cfg(unix)]
#[tokio::test]
async fn interrupted_removal_is_not_complete_while_an_unknown_bridge_target_is_settling() {
    let (_temp, data_dir, node_file, tombstone) = interrupted_removal_home(true);
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_runtime_provider_target(
        registry.as_ref(),
        Arc::new(SettlingCustodyProvider {
            refuse_shutdown: AtomicBool::new(true),
        }),
    )
    .await
    .unwrap();
    assert!(!super::super::custody_bridge_known(&data_dir));
    assert!(registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .is_err());
    assert!(
        registry
            .has_runtime_provider_target_registration(CUSTODY_PROVIDER_ID)
            .await
    );

    let write = crate::custody_consent::lock_custody_writes().await;
    let error = crate::custody_pool_setup::remove_local_node(&write, &data_dir, Some(&registry))
        .await
        .unwrap_err();
    assert_eq!(refusal_code(&error), "remove_failed");
    assert!(node_file.exists());
    assert!(tombstone.exists());

    registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .unwrap();
    crate::custody_pool_setup::remove_local_node(&write, &data_dir, Some(&registry))
        .await
        .unwrap();
    assert!(!node_file.exists());
    assert!(!tombstone.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn serves_only_pools_roots_and_still_starts_the_provider() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let base = inactive_custody_state_root(&data_dir)
        .parent()
        .unwrap()
        .to_path_buf();
    let pool = format!("pools/{}", "d".repeat(64));
    owner_only_dir(&base.join(&pool));
    assert!(!inactive_custody_state_root(&data_dir).exists());
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());
    register_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    assert!(
        registry
            .has_ready_runtime_provider_target(CUSTODY_PROVIDER_ID)
            .await
    );
    let init: Value = serde_json::from_str(
        fs::read_to_string(&request_log)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(init["config"]["extra"]["roots"], json!([{"path": pool}]));
}

#[test]
fn custody_child_reports_its_ops_in_order() {
    assert_eq!(
        CUSTODY_PROVIDER_OPERATIONS,
        [
            "status",
            "provision_node_share",
            "release_contribution",
            "release_pool_contribution",
            "sign_pool_statement",
            "provision_pool_node_share",
            "shutdown",
        ]
    );
}

#[cfg(unix)]
#[tokio::test]
async fn inactive_custody_wrapper_refuses_in_a_fixed_order_with_fixed_texts() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, _pid_file, _request_log) = write_mock_custody_provider(temp.path());
    let provider = spawn_custody_wrapper_for_test(&binary, &data_dir).await;

    // Each request also breaks every later rule, so the first refusal wins.
    let cases = [
        (json!("status"), "custody request must be an object"),
        (
            json!({ "_runtime_transfer": {}, "chain_data": {}, "carrier": {}, "op": "evaluate_rights" }),
            "custody request contains an unsupported transfer envelope",
        ),
        (
            json!({ "evidence": {}, "carrier": {}, "op": "evaluate_rights" }),
            "custody request contains unsupported injected evidence",
        ),
        (
            json!({ "carrier": {}, "op": "evaluate_rights" }),
            "custody request contains unsupported injected carrier data",
        ),
        (json!({}), "custody request is missing op"),
        (
            json!({ "op": "evaluate_rights" }),
            "custody request op is private to the node-hosted wrapper",
        ),
        (
            json!({ "op": "prepare_evidence" }),
            "custody request op is private to the node-hosted wrapper",
        ),
        (
            json!({ "op": "settle_evidence" }),
            "custody request op is private to the node-hosted wrapper",
        ),
        (
            json!({ "op": "shutdown" }),
            "custody request op is unsupported",
        ),
        (
            json!({ "op": "status" }),
            "custody request is missing runtime envelope",
        ),
    ];
    for (request, expected) in cases {
        let error = provider.send_raw(&request).await.unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "{request} was refused with {error}, not {expected}"
        );
    }
}

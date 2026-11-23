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
async fn runtime_invokes_custody_not_the_provisional_key_route() {
    let registry = Arc::new(ProviderRegistry::new());
    let custody = RecordingProvider::new(
        "custody",
        json!({"status": "ok", "data": {"echo": "custody"}}),
    );
    let key = RecordingProvider::new("key", json!({"status": "ok", "data": {"echo": "key"}}));
    registry
        .register_sub_provider("key", key.clone())
        .await
        .unwrap();
    register_inactive_custody_runtime_provider_target(registry.as_ref(), custody.clone())
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
    register_inactive_custody_runtime_provider_target(registry.as_ref(), custody)
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
async fn inactive_custody_registration_does_not_replace_key() {
    let registry = Arc::new(ProviderRegistry::new());
    let custody = RecordingProvider::new(
        "custody",
        json!({"status": "ok", "data": {"echo": "custody"}}),
    );
    let key = RecordingProvider::new("key", json!({"status": "ok", "data": {"echo": "key"}}));
    registry.register_sub_provider("key", key).await.unwrap();
    register_inactive_custody_runtime_provider_target(&registry, custody)
        .await
        .unwrap();
    let mut schemes = registry.sub_provider_schemes().await;
    schemes.sort();
    assert_eq!(schemes, vec!["key".to_string()]);
}

#[cfg(unix)]
#[tokio::test]
async fn inactive_custody_registration_passes_only_base_path_and_no_extra_truth() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    let state_root = inactive_custody_state_root(&data_dir);
    owner_only_dir(&state_root);
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    register_inactive_custody_provider(&registry, &binary, &data_dir)
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
    assert_eq!(
        init["config"]["base_path"],
        Value::String(state_root.to_string_lossy().to_string())
    );
    assert_eq!(init["config"]["allowed_paths"], json!([]));
    assert_eq!(init["config"]["read_only"], false);
    assert_eq!(init["config"]["encryption_key"], "");
    assert!(init["config"]["extra"].is_null());
    let status: Value = serde_json::from_str(&requests.remove(0)).unwrap();
    assert_eq!(status, json!({"op": "status"}));
    let forwarded: Value = serde_json::from_str(&requests.remove(0)).unwrap();
    assert_eq!(forwarded["op"], "release_contribution");
    assert!(forwarded.get("_runtime_invocation").is_none());
    assert!(forwarded.get("_runtime_transfer").is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn inactive_custody_wrapper_rejects_public_private_op_and_evidence_injection() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    register_inactive_custody_provider(&registry, &binary, &data_dir)
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
async fn inactive_custody_wrapper_status_surface_matches_public_dispatch() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, _pid_file, _request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    register_inactive_custody_provider(&registry, &binary, &data_dir)
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
            "evaluate"
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
async fn inactive_custody_wrapper_accepts_local_and_carrier_envelopes() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, _pid_file, request_log) = write_mock_custody_provider(temp.path());
    let provider = spawn_inactive_custody_wrapper_for_test(&binary, &data_dir).await;

    for transport in ["runtime-local-provider-plane", "carrier-provider-plane"] {
        let response = provider
            .send_raw(&json!({
                "op": "release_contribution",
                "_runtime_invocation": inactive_custody_runtime_envelope(
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
async fn inactive_custody_wrapper_rejects_invalid_transport_and_injected_carrier_data() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    owner_only_dir(&inactive_custody_state_root(&data_dir));
    let (binary, _pid_file, _request_log) = write_mock_custody_provider(temp.path());
    let provider = spawn_inactive_custody_wrapper_for_test(&binary, &data_dir).await;

    let invalid_transport = provider
        .send_raw(&json!({
            "op": "release_contribution",
            "_runtime_invocation": inactive_custody_runtime_envelope(
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
            "_runtime_invocation": inactive_custody_runtime_envelope(
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
        let mut envelope = inactive_custody_runtime_envelope("release_contribution", transport);
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
    let provisional = RecordingProvider::new(
        "rights",
        ok_provider_response(json!({"echo": "provisional"})),
    );
    registry
        .register_runtime_provider_target(CUSTODY_PROVIDER_ID, custody.clone())
        .await
        .unwrap();
    registry
        .register_sub_provider("rights", provisional.clone())
        .await
        .unwrap();

    let adapter = RuntimeCustodyRegistryAdapter::new(
        registry.clone(),
        elastos_runtime::provider::ProviderInvocationTransport::Local,
    );
    let request = RightsProviderRequestV1::new_evaluate(node_public_key(1), &operation).unwrap();

    let response = adapter.evaluate_rights(&request).await.unwrap();
    assert_eq!(
        response.status(),
        elastos_protected_content_provider_contracts::RightsProviderResponseStatusV1::Decision
    );
    let custody_requests = custody.requests().await;
    assert_eq!(custody_requests.len(), 1);
    assert!(provisional.requests().await.is_empty());
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
    let provisional =
        RecordingProvider::new("key", ok_provider_response(json!({"echo": "provisional"})));
    registry
        .register_runtime_provider_target(CUSTODY_PROVIDER_ID, custody.clone())
        .await
        .unwrap();
    registry
        .register_sub_provider("key", provisional.clone())
        .await
        .unwrap();

    let adapter = RuntimeCustodyRegistryAdapter::new(
        registry.clone(),
        elastos_runtime::provider::ProviderInvocationTransport::Local,
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
    assert!(provisional.requests().await.is_empty());
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
    register_inactive_custody_provider(&registry, &binary, &data_dir)
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

#[cfg(unix)]
#[tokio::test]
async fn runtime_release_coordinator_process_two_of_three_success_stops_before_third_node() {
    let binary = required_test_binary_path(TEST_CUSTODY_PROVIDER_BIN_ENV);
    let temp = tempfile::tempdir().unwrap();
    let temp_root = fs::canonicalize(temp.path()).unwrap();

    let node1 = provisioned_process_custody_node(&binary, &temp_root, "node-1", 0x21, digest(0xa1));
    let node2 = provisioned_process_custody_node(&binary, &temp_root, "node-2", 0x21, digest(0xa2));
    let node3 = provisioned_process_custody_node(&binary, &temp_root, "node-3", 0x21, digest(0xa3));

    register_inactive_custody_provider(&node1.registry, &binary, &temp_root.join("node-1"))
        .await
        .unwrap();
    register_inactive_custody_provider(&node2.registry, &binary, &temp_root.join("node-2"))
        .await
        .unwrap();
    register_inactive_custody_provider(&node3.registry, &binary, &temp_root.join("node-3"))
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
            operation.clone(),
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
            beta_operation.clone(),
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
    assert_eq!(
        beta_denied.statement().node_public_key(),
        ordered_fixtures[0].provisioned.node_public_key
    );
    assert_eq!(beta_chain1.requests().await.len(), 1);
    assert_eq!(beta_chain2.requests().await.len(), 0);
    assert_eq!(beta_chain3.requests().await.len(), 0);

    let beta_replay = coordinator
        .release(
            &beta_wallet_request,
            &beta_wallet_response,
            beta_operation.clone(),
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
    assert_eq!(beta_chain1.requests().await.len(), 1);
    assert_eq!(beta_chain2.requests().await.len(), 0);
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

    register_inactive_custody_provider(&node1.registry, &custody_binary, &temp_root.join("node-1"))
        .await
        .unwrap();
    register_inactive_custody_provider(&node2.registry, &custody_binary, &temp_root.join("node-2"))
        .await
        .unwrap();
    register_inactive_custody_provider(&node3.registry, &custody_binary, &temp_root.join("node-3"))
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
    assert!(custody_provisioned.any_effect_started());
    assert!(custody_provisioned.all_receipts_present());
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
    let availability_evidence = super::super::publish_and_verify_protected_content_availability(
        content_registry.as_ref(),
        content_directory.path(),
        mint_draft.media_identity(),
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
            operation.clone(),
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
            operation.clone(),
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
            media_identity: &protected_media_identity,
            protected_init_segment: &protected_init_segment,
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
            media_identity: &wrong_media_identity,
            protected_init_segment: &protected_init_segment,
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
            media_identity: &protected_media_identity,
            protected_init_segment: &protected_init_segment,
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
async fn inactive_custody_registration_rejects_missing_or_unsafe_root_before_provider_use() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("missing-data");
    owner_only_dir(&data_dir);
    let (binary, pid_file, request_log) = write_mock_custody_provider(temp.path());
    let registry = Arc::new(ProviderRegistry::new());

    let error = register_inactive_custody_provider(&registry, &binary, &data_dir)
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
    let error = register_inactive_custody_provider(&registry, &binary, &unsafe_data_dir)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("missing or unsafe"));
    assert!(!error.to_string().contains(temp.path().to_str().unwrap()));
    assert!(!request_log.exists());
    assert!(!pid_file.exists());
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

    register_inactive_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let first_pid = read_pid(&pid_file);

    registry
        .unregister_runtime_provider_target(CUSTODY_PROVIDER_ID)
        .await
        .unwrap();
    assert!(!process_is_running(first_pid));

    register_inactive_custody_provider(&registry, &binary, &data_dir)
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

    register_inactive_custody_provider(&registry, &binary, &data_dir)
        .await
        .unwrap();
    let first_pid = read_pid(&pid_file);

    let error = register_inactive_custody_provider(&registry, &binary, &data_dir)
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
    let (clear_init_segment, clear_segments) = clear_media_components(0x41);
    let error = publish_runtime_custody_library_object(
        &data_dir,
        Arc::new(ProviderRegistry::new()),
        RuntimeCustodyLibraryPublishInput {
            object_uri: "localhost://Users/test/Documents/media".to_string(),
            principal_id: "person:local:runtime-custody-missing-device-key".to_string(),
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
        },
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

#[test]
fn custody_child_reports_its_ops_in_order() {
    assert_eq!(
        CUSTODY_PROVIDER_OPERATIONS,
        [
            "status",
            "provision_node_share",
            "release_contribution",
            "shutdown"
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
    let provider = spawn_inactive_custody_wrapper_for_test(&binary, &data_dir).await;

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

use super::*;

#[cfg(unix)]
#[test]
fn media_prerequisite_import_is_bounded_private_idempotent_and_never_executes_tools() {
    let temp = safe_ancestor_tempdir();
    let data_dir = temp.path().join("data");
    let source = temp.path().join("source:tools");
    let marker = temp.path().join("executed");
    owner_only_dir(&source);
    write_media_prerequisite(
        &source.join("ffmpeg"),
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()).as_bytes(),
        0o700,
    );
    write_media_prerequisite(
        &source.join("ffprobe"),
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()).as_bytes(),
        0o700,
    );

    prepare_runtime_media_provider_prerequisite(&data_dir, &source, MediaToolsTrust::MustMatch)
        .unwrap();
    let config_path = media_config_path(&data_dir);
    let original_config = fs::read(&config_path).unwrap();
    let original_ffmpeg =
        fs::read(data_dir.join("protected-content/media-provider/tools/ffmpeg")).unwrap();
    prepare_runtime_media_provider_prerequisite(&data_dir, &source, MediaToolsTrust::MustMatch)
        .unwrap();

    assert!(!marker.exists());
    assert_eq!(fs::read(&config_path).unwrap(), original_config);
    assert_eq!(
        fs::read(data_dir.join("protected-content/media-provider/tools/ffmpeg")).unwrap(),
        original_ffmpeg
    );
    let config: Value = serde_json::from_slice(&original_config).unwrap();
    assert_eq!(config["schema"], MEDIA_PROVIDER_CONFIG_SCHEMA_V1);
    assert_eq!(config["timeout_ms"], MEDIA_PROVIDER_TIMEOUT_MS_V1);
    assert_eq!(config["max_input_bytes"], MEDIA_PROVIDER_MAX_INPUT_BYTES_V1);
    assert_eq!(config["max_segment_count"], 512);
    assert_eq!(config["max_total_output_bytes"], 2u64 << 30);
    assert_eq!(
        fs::symlink_metadata(&config_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(fs::symlink_metadata(&config_path).unwrap().nlink(), 1);
    for name in ["ffmpeg", "ffprobe"] {
        let metadata = fs::symlink_metadata(
            data_dir
                .join("protected-content/media-provider/tools")
                .join(name),
        )
        .unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o500);
        assert_eq!(metadata.nlink(), 1);
    }
    let bridge = load_runtime_media_provider_bridge_config(&data_dir)
        .unwrap()
        .expect("generated config must survive restart validation");
    assert_eq!(bridge.extra["provider_id"], "media-provider");

    let mut bounded: Value = serde_json::from_slice(&original_config).unwrap();
    bounded["timeout_ms"] = json!(5_000);
    bounded["max_input_bytes"] = json!(1u64 << 20);
    let bounded_bytes = serde_json::to_vec_pretty(&bounded).unwrap();
    fs::write(&config_path, &bounded_bytes).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    prepare_runtime_media_provider_prerequisite(&data_dir, &source, MediaToolsTrust::MustMatch)
        .unwrap();
    assert_eq!(fs::read(&config_path).unwrap(), bounded_bytes);

    // A differing pair without signed provenance is refused with nothing changed.
    let tools_dir = data_dir.join("protected-content/media-provider/tools");
    let imported_ffmpeg = fs::read(tools_dir.join("ffmpeg")).unwrap();
    let imported_probe = fs::read(tools_dir.join("ffprobe")).unwrap();
    write_media_prerequisite(&source.join("ffmpeg"), b"upgraded ffmpeg", 0o700);
    write_media_prerequisite(&source.join("ffprobe"), b"upgraded ffprobe", 0o700);
    let unchanged = |config: &[u8]| {
        assert_eq!(fs::read(&config_path).unwrap(), config);
        assert_eq!(fs::read(tools_dir.join("ffmpeg")).unwrap(), imported_ffmpeg);
        assert_eq!(fs::read(tools_dir.join("ffprobe")).unwrap(), imported_probe);
        assert_eq!(fs::read_dir(&tools_dir).unwrap().count(), 2);
    };
    let error =
        prepare_runtime_media_provider_prerequisite(&data_dir, &source, MediaToolsTrust::MustMatch)
            .unwrap_err();
    assert!(error
        .to_string()
        .contains("differ from the private imported pair"));
    unchanged(&bounded_bytes);

    // Bytes altered after the signed archive was verified are refused before any rename.
    let signed = MediaToolsTrust::SignedRelease(SignedMediaToolDigests {
        ffmpeg: sha2::Sha256::digest(b"upgraded ffmpeg").into(),
        ffprobe: sha2::Sha256::digest(b"upgraded ffprobe").into(),
    });
    write_media_prerequisite(&source.join("ffprobe"), b"tampered ffprobe", 0o700);
    let error =
        prepare_runtime_media_provider_prerequisite(&data_dir, &source, signed).unwrap_err();
    assert!(error
        .to_string()
        .contains("does not match the signed release media tools"));
    unchanged(&bounded_bytes);

    // A symlinked supplied tool is refused, whatever its target.
    let linked = temp.path().join("linked-source");
    owner_only_dir(&linked);
    write_media_prerequisite(&linked.join("real-ffprobe"), b"upgraded ffprobe", 0o700);
    std::os::unix::fs::symlink(linked.join("real-ffprobe"), linked.join("ffprobe")).unwrap();
    fs::copy(source.join("ffmpeg"), linked.join("ffmpeg")).unwrap();
    let error =
        prepare_runtime_media_provider_prerequisite(&data_dir, &linked, signed).unwrap_err();
    assert!(error.to_string().contains("symbolic link"), "{error}");
    unchanged(&bounded_bytes);
    write_media_prerequisite(&source.join("ffprobe"), b"upgraded ffprobe", 0o700);
    let linked_dir = temp.path().join("linked-dir");
    std::os::unix::fs::symlink(&source, &linked_dir).unwrap();
    let error =
        prepare_runtime_media_provider_prerequisite(&data_dir, &linked_dir, signed).unwrap_err();
    assert!(error.to_string().contains("symbolic link"), "{error}");
    unchanged(&bounded_bytes);
    // Even a root-owned system link (macOS /tmp or /var) on a supplied path is refused.
    if let Some(system_link) = ["/tmp", "/var", "/etc"]
        .into_iter()
        .map(Path::new)
        .find(|path| {
            fs::symlink_metadata(path)
                .is_ok_and(|meta| meta.file_type().is_symlink() && meta.uid() == 0)
        })
    {
        let error = prepare_runtime_media_provider_prerequisite(
            &data_dir,
            &system_link.join("media-tools"),
            signed,
        )
        .unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        unchanged(&bounded_bytes);
    }

    // The signed release's pair is re-imported and tuned limits are kept.
    write_media_prerequisite(&source.join("ffprobe"), b"upgraded ffprobe", 0o700);
    prepare_runtime_media_provider_prerequisite(&data_dir, &source, signed).unwrap();
    let upgraded = || {
        assert_eq!(fs::read(&config_path).unwrap(), bounded_bytes);
        assert_eq!(
            fs::read(tools_dir.join("ffmpeg")).unwrap(),
            b"upgraded ffmpeg"
        );
        assert_eq!(
            fs::read(tools_dir.join("ffprobe")).unwrap(),
            b"upgraded ffprobe"
        );
        for name in ["ffmpeg", "ffprobe"] {
            let metadata = fs::symlink_metadata(tools_dir.join(name)).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o500);
            assert_eq!(metadata.nlink(), 1);
        }
        assert_eq!(fs::read_dir(&tools_dir).unwrap().count(), 2);
    };
    upgraded();
    let bridge = load_runtime_media_provider_bridge_config(&data_dir)
        .unwrap()
        .expect("upgraded config must survive restart validation");
    assert_eq!(bridge.extra["timeout_ms"], 5_000);

    // A pair left half-replaced by an interrupted run is repaired on rerun.
    let probe = tools_dir.join("ffprobe");
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&probe, &imported_probe).unwrap();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o500)).unwrap();
    prepare_runtime_media_provider_prerequisite(&data_dir, &source, signed).unwrap();
    upgraded();
}

#[cfg(unix)]
#[test]
fn media_source_accepts_group_writable_ancestors_and_keeps_file_guards() {
    let temp = safe_ancestor_tempdir();
    let shared = temp.path().join("group-shared");
    owner_only_dir(&shared);
    let tools = shared.join("tools");
    owner_only_dir(&tools);
    let tool = tools.join("ffmpeg");
    write_media_prerequisite(&tool, b"private executable", 0o700);
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o775)).unwrap();
    let mut source = super::super::open_runtime_media_tool(&tools, "ffmpeg").unwrap();
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut source.file, &mut bytes).unwrap();
    assert_eq!(bytes, b"private executable");
    assert_eq!(fs::metadata(&shared).unwrap().mode() & 0o1777, 0o775);
    drop(source);

    for mode in [0o720, 0o777] {
        fs::set_permissions(&tool, fs::Permissions::from_mode(mode)).unwrap();
        assert!(super::super::open_runtime_media_tool(&tools, "ffmpeg").is_err());
        assert_eq!(fs::metadata(&tool).unwrap().mode() & 0o777, mode);
    }
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
    for mode in [0o777, 0o1777] {
        fs::set_permissions(&shared, fs::Permissions::from_mode(mode)).unwrap();
        assert!(super::super::open_runtime_media_tool(&tools, "ffmpeg").is_err());
        assert_eq!(fs::metadata(&shared).unwrap().mode() & 0o1777, mode);
    }
    assert_eq!(fs::read(&tool).unwrap(), b"private executable");
}

#[cfg(unix)]
#[test]
fn media_prerequisite_rejects_missing_unsafe_and_oversized_tools_before_config() {
    let temp = safe_ancestor_tempdir();
    let missing_data = temp.path().join("missing-data");
    let missing = temp.path().join("missing-tools");
    owner_only_dir(&missing);
    write_media_prerequisite(&missing.join("ffmpeg"), b"ffmpeg", 0o700);
    let error = prepare_runtime_media_provider_prerequisite(
        &missing_data,
        &missing,
        MediaToolsTrust::MustMatch,
    )
    .unwrap_err();
    assert!(error.to_string().contains("ffprobe"));
    assert!(!media_config_path(&missing_data).exists());

    let unsafe_data = temp.path().join("unsafe-data");
    let unsafe_tools = temp.path().join("unsafe-tools");
    owner_only_dir(&unsafe_tools);
    write_media_prerequisite(&unsafe_tools.join("ffmpeg"), b"ffmpeg", 0o720);
    write_media_prerequisite(&unsafe_tools.join("ffprobe"), b"ffprobe", 0o700);
    assert!(prepare_runtime_media_provider_prerequisite(
        &unsafe_data,
        &unsafe_tools,
        MediaToolsTrust::MustMatch
    )
    .unwrap_err()
    .to_string()
    .contains("ffmpeg prerequisite"));
    assert!(!media_config_path(&unsafe_data).exists());

    let oversized_data = temp.path().join("oversized-data");
    let oversized_tools = temp.path().join("oversized-tools");
    owner_only_dir(&oversized_tools);
    let oversized = fs::File::create(oversized_tools.join("ffmpeg")).unwrap();
    oversized.set_len((512 * 1024 * 1024) + 1).unwrap();
    fs::set_permissions(
        oversized_tools.join("ffmpeg"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    write_media_prerequisite(&oversized_tools.join("ffprobe"), b"ffprobe", 0o700);
    assert!(prepare_runtime_media_provider_prerequisite(
        &oversized_data,
        &oversized_tools,
        MediaToolsTrust::MustMatch
    )
    .unwrap_err()
    .to_string()
    .contains("exceeds bounds"));
    assert!(!media_config_path(&oversized_data).exists());

    let non_file_data = temp.path().join("non-file-data");
    let non_file_tools = temp.path().join("non-file-tools");
    owner_only_dir(&non_file_tools);
    owner_only_dir(&non_file_tools.join("ffmpeg"));
    write_media_prerequisite(&non_file_tools.join("ffprobe"), b"ffprobe", 0o700);
    assert!(prepare_runtime_media_provider_prerequisite(
        &non_file_data,
        &non_file_tools,
        MediaToolsTrust::MustMatch
    )
    .unwrap_err()
    .to_string()
    .contains("ffmpeg prerequisite"));

    let unsafe_parent_data = temp.path().join("unsafe-parent-data");
    let unsafe_parent_tools = temp.path().join("unsafe-parent-tools");
    owner_only_dir(&unsafe_parent_tools);
    write_media_prerequisite(&unsafe_parent_tools.join("ffmpeg"), b"ffmpeg", 0o700);
    write_media_prerequisite(&unsafe_parent_tools.join("ffprobe"), b"ffprobe", 0o700);
    fs::set_permissions(&unsafe_parent_tools, fs::Permissions::from_mode(0o777)).unwrap();
    let refusal = prepare_runtime_media_provider_prerequisite(
        &unsafe_parent_data,
        &unsafe_parent_tools,
        MediaToolsTrust::MustMatch,
    )
    .unwrap_err()
    .to_string();
    assert!(
        refusal.contains("prerequisite parent is unsafe"),
        "{refusal}"
    );
    assert!(!refusal.contains("chmod"), "{refusal}");
    assert!(!refusal.contains("chown"), "{refusal}");
    assert_eq!(
        fs::metadata(&unsafe_parent_tools)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o777
    );

    let linked_data = temp.path().join("linked-data");
    let linked_tools = temp.path().join("linked-tools");
    owner_only_dir(&linked_tools);
    write_media_prerequisite(&linked_tools.join("ffmpeg"), b"ffmpeg", 0o700);
    fs::hard_link(
        linked_tools.join("ffmpeg"),
        linked_tools.join("ffmpeg-copy"),
    )
    .unwrap();
    write_media_prerequisite(&linked_tools.join("ffprobe"), b"ffprobe", 0o700);
    assert!(prepare_runtime_media_provider_prerequisite(
        &linked_data,
        &linked_tools,
        MediaToolsTrust::MustMatch
    )
    .unwrap_err()
    .to_string()
    .contains("ffmpeg prerequisite"));
}

#[cfg(unix)]
#[test]
fn media_prerequisite_rejects_links_modes_paths_and_unknown_config_fields_without_overwrite() {
    let temp = safe_ancestor_tempdir();
    let source = temp.path().join("source");
    let data_dir = temp.path().join("data");
    prepare_test_media_prerequisite(&data_dir, &source);
    let config_path = media_config_path(&data_dir);
    let valid = fs::read(&config_path).unwrap();

    let mut unknown: Value = serde_json::from_slice(&valid).unwrap();
    unknown["credential"] = json!("private-value");
    fs::write(&config_path, serde_json::to_vec(&unknown).unwrap()).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    let error = load_runtime_media_provider_bridge_config(&data_dir).unwrap_err();
    assert!(!error.to_string().contains("private-value"));
    assert_eq!(
        fs::read(&config_path).unwrap(),
        serde_json::to_vec(&unknown).unwrap()
    );

    fs::write(&config_path, &valid).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(load_runtime_media_provider_bridge_config(&data_dir).is_err());
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    let config_copy = data_dir.join("protected-content/media-provider/config-copy");
    fs::hard_link(&config_path, &config_copy).unwrap();
    assert!(load_runtime_media_provider_bridge_config(&data_dir).is_err());
    fs::remove_file(config_copy).unwrap();

    let mut escaped: Value = serde_json::from_slice(&valid).unwrap();
    escaped["ffmpeg_path"] = json!("/private/tmp/ffmpeg");
    fs::write(&config_path, serde_json::to_vec(&escaped).unwrap()).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_runtime_media_provider_bridge_config(&data_dir).is_err());

    fs::write(&config_path, &valid).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    let ffmpeg = data_dir.join("protected-content/media-provider/tools/ffmpeg");
    let ffmpeg_target = data_dir.join("protected-content/media-provider/tools/ffmpeg-target");
    fs::rename(&ffmpeg, &ffmpeg_target).unwrap();
    std::os::unix::fs::symlink(&ffmpeg_target, &ffmpeg).unwrap();
    assert!(load_runtime_media_provider_bridge_config(&data_dir).is_err());

    let symlink_data = temp.path().join("symlink-data");
    owner_only_dir(&symlink_data);
    owner_only_dir(&symlink_data.join("protected-content/media-provider"));
    std::os::unix::fs::symlink(&config_path, media_config_path(&symlink_data)).unwrap();
    assert!(load_runtime_media_provider_bridge_config(&symlink_data).is_err());

    let race_path = temp.path().join("race-config");
    fs::write(&race_path, b"preserved-race-winner").unwrap();
    assert!(
        super::super::create_private_file_atomically(&race_path, b"loser", 0o600, "config")
            .is_err()
    );
    assert_eq!(fs::read(race_path).unwrap(), b"preserved-race-winner");
}

#[cfg(unix)]
#[test]
fn media_prerequisite_conflict_cleans_only_files_created_by_that_attempt() {
    let temp = safe_ancestor_tempdir();
    let data_dir = temp.path().join("data");
    let source = temp.path().join("source");
    owner_only_dir(&source);
    write_media_prerequisite(&source.join("ffmpeg"), b"ffmpeg-source", 0o700);
    write_media_prerequisite(&source.join("ffprobe"), b"ffprobe-source", 0o700);
    let tools = data_dir.join("protected-content/media-provider/tools");
    owner_only_dir(&data_dir);
    owner_only_dir(&data_dir.join("protected-content"));
    owner_only_dir(&data_dir.join("protected-content/media-provider"));
    owner_only_dir(&tools);
    write_media_prerequisite(&tools.join("ffprobe"), b"preserved-conflict", 0o500);

    let error =
        prepare_runtime_media_provider_prerequisite(&data_dir, &source, MediaToolsTrust::MustMatch)
            .unwrap_err();

    assert!(error.to_string().contains("ffprobe import conflicts"));
    assert_eq!(
        fs::read(tools.join("ffprobe")).unwrap(),
        b"preserved-conflict"
    );
    assert!(!tools.join("ffmpeg").exists());
    assert!(!media_config_path(&data_dir).exists());
}

#[cfg(unix)]
#[test]
fn protected_content_chain_config_loads_owner_only_file_and_accepts_missing_state() {
    let temp = tempfile::tempdir().unwrap();
    let missing_data_dir = temp.path().join("missing");
    owner_only_dir(&missing_data_dir);
    assert!(
        load_runtime_protected_content_chain_provider_config(&missing_data_dir)
            .unwrap()
            .is_none()
    );

    let data_dir = temp.path().join("configured");
    owner_only_dir(&data_dir);
    let config = test_chain_provider_config();
    write_chain_provider_config(&data_dir, &config);

    let loaded = load_runtime_protected_content_chain_provider_config(&data_dir)
        .unwrap()
        .expect("owner-only Chain config");
    assert_eq!(
        loaded.protected_content_network(),
        &config["protected_content_network"]
    );
    assert!(config.get("protected_content_runtime_issuer").is_none());
}

#[cfg(unix)]
#[test]
fn protected_content_chain_config_rejects_unknown_empty_oversized_or_invalid_content() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);

    let mut unknown = test_chain_provider_config();
    unknown["protected_content_runtime_issuer"] = json!("0xoperator-cannot-set-this");
    write_chain_provider_config(&data_dir, &unknown);
    assert!(load_runtime_protected_content_chain_provider_config(&data_dir).is_err());

    for invalid in [
        Vec::new(),
        b"{".to_vec(),
        serde_json::to_vec(&json!({
            "schema": "wrong-schema",
            "protected_content_network": {}
        }))
        .unwrap(),
        serde_json::to_vec(&json!({
            "schema": PROTECTED_CONTENT_CHAIN_PROVIDER_CONFIG_SCHEMA_V1,
            "protected_content_network": []
        }))
        .unwrap(),
        vec![b'x'; MAX_CHAIN_PROVIDER_CONFIG_BYTES + 1],
    ] {
        fs::write(chain_provider_config_path(&data_dir), invalid).unwrap();
        fs::set_permissions(
            chain_provider_config_path(&data_dir),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(load_runtime_protected_content_chain_provider_config(&data_dir).is_err());
    }
}

#[cfg(unix)]
#[test]
fn protected_content_chain_config_rejects_unsafe_or_nonregular_paths() {
    let temp = tempfile::tempdir().unwrap();
    let config = test_chain_provider_config();

    let mode_data_dir = temp.path().join("mode");
    owner_only_dir(&mode_data_dir);
    write_chain_provider_config(&mode_data_dir, &config);
    fs::set_permissions(
        chain_provider_config_path(&mode_data_dir),
        fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    assert!(load_runtime_protected_content_chain_provider_config(&mode_data_dir).is_err());

    fs::set_permissions(
        chain_provider_config_path(&mode_data_dir),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::set_permissions(
        protected_content_root(&mode_data_dir),
        fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    assert!(load_runtime_protected_content_chain_provider_config(&mode_data_dir).is_err());

    let directory_data_dir = temp.path().join("directory");
    owner_only_dir(&directory_data_dir);
    owner_only_dir(&protected_content_root(&directory_data_dir));
    owner_only_dir(&chain_provider_config_path(&directory_data_dir));
    assert!(load_runtime_protected_content_chain_provider_config(&directory_data_dir).is_err());

    let symlink_data_dir = temp.path().join("symlink");
    owner_only_dir(&symlink_data_dir);
    owner_only_dir(&protected_content_root(&symlink_data_dir));
    let symlink_target = temp.path().join("chain-provider-target.json");
    fs::write(&symlink_target, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::set_permissions(&symlink_target, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(
        &symlink_target,
        chain_provider_config_path(&symlink_data_dir),
    )
    .unwrap();
    assert!(load_runtime_protected_content_chain_provider_config(&symlink_data_dir).is_err());

    let symlink_parent_data_dir = temp.path().join("symlink-parent");
    owner_only_dir(&symlink_parent_data_dir);
    let symlink_parent_target = temp.path().join("protected-content-target");
    owner_only_dir(&symlink_parent_target);
    let symlink_parent_config = symlink_parent_target.join("chain-provider.json");
    fs::write(&symlink_parent_config, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::set_permissions(&symlink_parent_config, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(
        &symlink_parent_target,
        protected_content_root(&symlink_parent_data_dir),
    )
    .unwrap();
    assert!(
        load_runtime_protected_content_chain_provider_config(&symlink_parent_data_dir).is_err()
    );

    let hard_link_data_dir = temp.path().join("hard-link");
    owner_only_dir(&hard_link_data_dir);
    owner_only_dir(&protected_content_root(&hard_link_data_dir));
    let hard_link_source = temp.path().join("chain-provider-source.json");
    fs::write(&hard_link_source, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::set_permissions(&hard_link_source, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(
        &hard_link_source,
        chain_provider_config_path(&hard_link_data_dir),
    )
    .unwrap();
    assert!(load_runtime_protected_content_chain_provider_config(&hard_link_data_dir).is_err());
}

#[tokio::test]
async fn runtime_resolve_rights_policy_recomputes_identity_and_rejects_mismatch() {
    let encrypted_content_identity = EncryptedContentIdentityV1::new(digest(0x51), 4096).unwrap();
    let access_id = content_access_id(0x51);
    let policy = policy_body_for(
        encrypted_content_identity.clone(),
        access_id,
        RightsActionV1::View,
    );
    let registry = Arc::new(ProviderRegistry::new());
    let chain = RecordingProvider::new(
        CHAIN_PROVIDER_ID,
        ok_provider_response(json!({
            "schema": CHAIN_PROTECTED_CONTENT_POLICY_SCHEMA_V1,
            "policy_body": format!("0x{}", hex::encode(policy.canonical_bytes().unwrap())),
        })),
    );
    registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain.clone())
        .await
        .unwrap();
    let resolved = resolve_runtime_rights_policy(
        registry.as_ref(),
        &encrypted_content_identity,
        access_id,
        RightsActionV1::View,
    )
    .await
    .unwrap();
    assert_eq!(resolved.body(), &policy);
    assert_eq!(resolved.identity(), &policy.policy_identity().unwrap());

    let invocation = chain.requests().await;
    assert_eq!(invocation.len(), 1);
    assert_eq!(
        invocation[0]["_runtime_invocation"]["target"],
        Value::String(CHAIN_PROVIDER_ID.to_string())
    );
    assert_eq!(
        invocation[0]["op"],
        Value::String("resolve_protected_content_policy".to_string())
    );

    for mismatched_policy in [
        policy_body_for(encrypted_content(0x52), access_id, RightsActionV1::View),
        policy_body_for(
            encrypted_content_identity.clone(),
            content_access_id(0x52),
            RightsActionV1::View,
        ),
        policy_body_for(
            encrypted_content_identity.clone(),
            access_id,
            RightsActionV1::Download,
        ),
    ] {
        let registry = Arc::new(ProviderRegistry::new());
        registry
            .register_sub_provider(
                CHAIN_PROVIDER_ID,
                RecordingProvider::new(
                    CHAIN_PROVIDER_ID,
                    ok_provider_response(json!({
                        "schema": CHAIN_PROTECTED_CONTENT_POLICY_SCHEMA_V1,
                        "policy_body": format!(
                            "0x{}",
                            hex::encode(mismatched_policy.canonical_bytes().unwrap())
                        ),
                    })),
                ),
            )
            .await
            .unwrap();
        assert!(resolve_runtime_rights_policy(
            registry.as_ref(),
            &encrypted_content_identity,
            access_id,
            RightsActionV1::View
        )
        .await
        .is_err());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_requires_reconciliation_for_partial_settled_mint() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let input = library_publish_test_input("person:local:runtime-custody-partial-settled");
    let request_id = library_publish_request_id(&input);
    let mint_id = seed_settled_runtime_custody_mint_record(&data_dir, &input, false);

    let error =
        publish_runtime_custody_library_object(&data_dir, Arc::new(ProviderRegistry::new()), input)
            .await
            .expect_err(
                "partially provisioned settled mint work must fail closed for reconciliation",
            );
    assert!(
        error
            .to_string()
            .contains(RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE),
        "{error}"
    );

    let intent = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert!(intent.protect_terminal_before_draft());
    assert_eq!(intent.completed_mint_id(), None);
    let record = runtime_mint_journal(&data_dir).load(mint_id).unwrap();
    assert_eq!(record.custody_terminal(), None);
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_blocks_exact_retry_after_ambiguous_protect_dispatch() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let _ = write_library_publish_test_composition(&data_dir);
    let protect = SequencedProvider::new(
        PROTECT_PROVIDER_ID,
        vec![
            Err(ProviderError::Provider(
                "simulated protect bridge failure".to_string(),
            )),
            Ok(ok_typed_protect_provider_response(
                ProtectProviderResponseV1::new_opened(
                    [0x51; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
                    b"placeholder-protected-init",
                )
                .unwrap(),
            )),
            Ok(ok_typed_protect_provider_response(
                ProtectProviderResponseV1::new_cancelled(
                    [0x51; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1],
                )
                .unwrap(),
            )),
        ],
    );
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect.clone())
        .await
        .unwrap();
    let input = library_publish_test_input("person:local:runtime-custody-ambiguous-dispatch");
    let request_id = library_publish_request_id(&input);
    let first = publish_runtime_custody_library_object(&data_dir, registry.clone(), input)
        .await
        .expect_err("ambiguous protect dispatch must fail closed");
    assert!(
        first
            .to_string()
            .contains("Runtime custody protect provider is unavailable"),
        "{first}"
    );
    let pending = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert_eq!(pending.protect_state_label(), "open_request_pending");

    let second = publish_runtime_custody_library_object(
        &data_dir,
        registry.clone(),
        library_publish_test_input("person:local:runtime-custody-ambiguous-dispatch"),
    )
    .await
    .expect_err("exact retry must recover and settle the ambiguous open");
    assert!(
        second
            .to_string()
            .contains(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE),
        "{second}"
    );
    let settled = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert!(settled.protect_terminal_before_draft());
    assert_eq!(
        settled.protect_terminal_settlement_label(),
        Some("cancelled")
    );
    let requests = protect.requests().await;
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0]["op"], "open_protection_session");
    assert_eq!(requests[1]["op"], "open_protection_session");
    assert_eq!(requests[0], requests[1]);
    assert_eq!(requests[2]["op"], "cancel_protection_session");
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_recovers_open_handle_by_cancelling_before_redispatch() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let _ = write_library_publish_test_composition(&data_dir);
    let registry = Arc::new(ProviderRegistry::new());
    let input = library_publish_test_input("person:local:runtime-custody-open-handle-recovery");
    let request_id = library_publish_request_id(&input);
    let composition = load_runtime_custody_composition(&data_dir, registry.clone())
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
    let journal = runtime_mint_journal(&data_dir);
    load_or_persist_runtime_mint_intent(&journal, &composition, &input, mint_nodes).unwrap();
    journal
        .mark_intent_protect_effect_started(request_id)
        .unwrap();
    let handle = [0x61; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
    journal
        .mark_intent_protect_opened(request_id, handle)
        .unwrap();

    let protect = SequencedProvider::new(
        PROTECT_PROVIDER_ID,
        vec![Ok(ok_typed_protect_provider_response(
            ProtectProviderResponseV1::new_cancelled(handle).unwrap(),
        ))],
    );
    registry
        .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect.clone())
        .await
        .unwrap();

    let error = publish_runtime_custody_library_object(&data_dir, registry, input)
        .await
        .expect_err("open-handle recovery must settle by cancelling");
    assert!(
        error
            .to_string()
            .contains(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE),
        "{error}"
    );
    let intent = journal.load_intent(request_id).unwrap();
    assert!(intent.protect_terminal_before_draft());
    assert_eq!(
        intent.protect_terminal_settlement_label(),
        Some("cancelled")
    );
    let requests = protect.requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["op"], "cancel_protection_session");
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_library_publish_retains_cleanup_obligation_when_close_fails() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let (epoch, composition_now) = write_library_publish_test_composition(&data_dir);
    let registry = Arc::new(ProviderRegistry::new());
    let input = library_publish_test_input("person:local:runtime-custody-close-failure");
    let request_id = library_publish_request_id(&input);
    let composition = load_runtime_custody_composition(&data_dir, registry.clone())
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
    let mint_intent = load_or_persist_runtime_mint_intent(
        &runtime_mint_journal(&data_dir),
        &composition,
        &input,
        mint_nodes,
    )
    .unwrap();
    let clear_layout =
        ValidatedClearFmp4MediaSessionLayoutV1::new(&input.clear_init_segment).unwrap();
    let (_, protected_segments) = media_components(0x41);
    let protected_init = clear_layout
        .rewrite_protected_init(
            &input.clear_init_segment,
            *mint_intent.content_access_id().as_bytes(),
        )
        .unwrap();
    let protected_media = CencFmp4MediaIdentityV1::new_from_bytes(
        &protected_init,
        &protected_segments,
        MEDIA_MIME_TYPE_V1,
        MEDIA_CODECS_V1,
    )
    .unwrap();
    let committee = validated_custody_committee_for_epoch(&epoch, composition_now);
    let content_key =
        elastos_protected_content_custody::ContentEncryptionKeyV1::generate().unwrap();
    let envelope = provision_custody_envelope(
        protected_media.encrypted_content().clone(),
        &content_key,
        &committee,
    )
    .unwrap();
    let handle = [0x41; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
    let protect = SequencedProvider::new(
        PROTECT_PROVIDER_ID,
        vec![
            Ok(ok_typed_protect_provider_response(
                ProtectProviderResponseV1::new_opened(handle, &protected_init).unwrap(),
            )),
            Ok(ok_typed_protect_provider_response(
                ProtectProviderResponseV1::new_segment_protected(handle, 0, &protected_segments[0])
                    .unwrap(),
            )),
            Ok(ok_typed_protect_provider_response(
                ProtectProviderResponseV1::new_segment_protected(handle, 1, &protected_segments[1])
                    .unwrap(),
            )),
            Ok(ok_typed_protect_provider_response(
                ProtectProviderResponseV1::new_finalized(handle, &protected_media, &envelope)
                    .unwrap(),
            )),
            Ok(ok_typed_protect_provider_response(
                ProtectProviderResponseV1::new_failure(ProviderFailureCodeV1::BackendUnavailable)
                    .unwrap(),
            )),
            Ok(ok_typed_protect_provider_response(
                ProtectProviderResponseV1::new_already_absent(handle).unwrap(),
            )),
        ],
    );
    registry
        .register_runtime_provider_target(PROTECT_PROVIDER_ID, protect.clone())
        .await
        .unwrap();

    let first = publish_runtime_custody_library_object(&data_dir, registry.clone(), input)
        .await
        .expect_err("close failure must retain cleanup ownership");
    assert!(
        first
            .to_string()
            .contains(RUNTIME_CUSTODY_MINT_RECONCILIATION_REQUIRED_MESSAGE),
        "{first}"
    );
    let pending = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert_eq!(
        pending.protect_state_label(),
        "open_handle_pending_close",
        "the close-failure scenario must reach the pending-close obligation; a \
         different label means the fixture was steered into another failure \
         mode: {pending:?}"
    );
    assert_eq!(
        pending.protect_pending_close_handle(),
        Some(handle),
        "{pending:?}"
    );

    let second = publish_runtime_custody_library_object(
        &data_dir,
        registry,
        library_publish_test_input("person:local:runtime-custody-close-failure"),
    )
    .await
    .expect_err("close replay loss must settle via already_absent");
    assert!(
        second
            .to_string()
            .contains(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE),
        "{second}"
    );
    let settled = runtime_mint_journal(&data_dir)
        .load_intent(request_id)
        .unwrap();
    assert!(settled.protect_terminal_before_draft());
    assert_eq!(
        settled.protect_terminal_settlement_label(),
        Some("already_absent")
    );
    let requests = protect.requests().await;
    assert_eq!(requests.len(), 6);
    assert_eq!(requests[4]["op"], "close_protection_session");
    assert_eq!(requests[5]["op"], "close_protection_session");
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_purchase_requires_current_verified_profile_authority() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-profile-check";
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let listing_path =
        super::super::runtime_listing_path(&harness.data_dir, mint.draft().mint_id());
    let listing_before = fs::read(&listing_path).unwrap();
    persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &derived_device_key_for_seed(0x27).1,
        crate::auth::now_ts(),
    );
    let purchase_path = super::super::runtime_purchase_path(
        &harness.data_dir,
        principal_id,
        mint.draft().mint_id(),
    );
    let purchase_json = String::from_utf8(fs::read(&purchase_path).unwrap()).unwrap();
    assert!(!purchase_json.contains("wallet_request_hex"));
    assert!(!purchase_json.contains("wallet_response_hex"));
    assert_eq!(fs::read(&listing_path).unwrap(), listing_before);
    let missing = super::super::load_runtime_custody_profile_did(&harness.data_dir, principal_id);
    assert!(missing.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_custody_purchase_reconstruction_rejects_mismatched_profile_did() {
    let harness = runtime_custody_prebuy_availability_harness(
        0x61,
        ContentAvailabilityTestConfig::accepted(),
    )
    .await;
    let principal_id = "person:local:runtime-custody-profile-check";
    let mint = runtime_mint_journal(&harness.data_dir)
        .load(harness.mint_id)
        .unwrap();
    let (_proof_binding_id, _profile_identity) =
        install_profile_authority_keeping_device_key(&harness.data_dir, principal_id);
    let current_profile_did = load_profile_did_for_test(&harness.data_dir, principal_id);
    let purchase = persist_runtime_custody_purchase_for_mint(
        &harness.data_dir,
        &mint,
        principal_id,
        &derived_device_key_for_seed(0x27).1,
        crate::auth::now_ts(),
    );
    let mismatch = super::super::reconstructed_buy_receipt(
        mint.draft(),
        mint.content_availability().unwrap(),
        &purchase,
        &current_profile_did,
    );
    assert!(mismatch.is_err());
    assert!(mismatch
        .unwrap_err()
        .to_string()
        .contains("Runtime custody chain evidence is invalid"));
}

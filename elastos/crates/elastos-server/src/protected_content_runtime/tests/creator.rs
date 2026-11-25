use super::*;

#[tokio::test]
async fn protected_content_availability_publishes_status_refetches_and_verifies_exact_media() {
    let evidence =
        publish_protected_content_for_test(ContentAvailabilityTestConfig::accepted(), None, None)
            .await
            .unwrap();
    assert_eq!(
        evidence.object_identity(),
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#content"
    );
    assert_eq!(
        evidence.publisher_identity(),
        "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#publisher"
    );
    assert_eq!(
        evidence.required_replicas(),
        super::super::PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET
    );
    assert_eq!(evidence.observed_replicas(), 3);
    let debug = format!("{evidence:?}");
    assert!(!debug.contains("init.mp4"));
    assert!(!debug.contains("segments/"));
}

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

#[test]
fn persist_runtime_custody_purchase_serializes_concurrent_writers() {
    let dir = tempfile::tempdir().unwrap();
    owner_only_dir(dir.path());
    let (principal, mint_id, base_record) = sample_purchase_record();
    // Each thread writes a byte-distinguishable record (not a clone of the
    // same bytes) so the final file can only look intact by virtue of one
    // writer's complete record having won, never by chance identity between
    // writers papering over a torn or interleaved write.
    let account_ids: Vec<String> = (0..8)
        .map(|index| format!("wallet-account-fixture-{index}"))
        .collect();
    let handles: Vec<_> = account_ids
        .iter()
        .cloned()
        .map(|account_id| {
            let dir = dir.path().to_path_buf();
            let mut record = base_record.clone();
            record.account_id = account_id;
            std::thread::spawn(move || persist_runtime_custody_purchase(&dir, &record).unwrap())
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    // The real proof of serialization: no two persist calls for this lock
    // path ever held the critical section at the same time. Content
    // round-tripping alone (checked below) would already pass even with the
    // lock removed, since `fs::rename` is independently atomic per writer.
    assert!(
        !runtime_purchase_lock_test_overlap_detected(&runtime_purchase_lock_path(
            dir.path(),
            &principal
        )),
        "two persist_runtime_custody_purchase calls held the purchase lock concurrently"
    );
    let persisted = load_runtime_custody_purchase(dir.path(), &principal, mint_id)
        .unwrap()
        .expect("a purchase record survives concurrent writers");
    assert!(
        account_ids.contains(&persisted.account_id),
        "persisted record must be exactly one writer's complete record, not a mix"
    );
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
/// A settled attempt that provisioned nothing durable and recorded no
/// availability can neither be rolled forward nor adopted, and its intent
/// settled before any draft existed. Keeping either of them makes the object
/// permanently unmintable, because the intent's identity is the object path.
///
/// This attempt still fails -- there is nothing to hand back -- but it leaves
/// nothing behind, so the creator's next attempt on that file starts from
/// nothing rather than meeting the same wall forever. Observed on Base: a node
/// restart mid-publish, and the file could not be minted again at all.
async fn runtime_custody_library_publish_clears_a_partial_settled_mint_so_the_object_mints_again() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("data");
    owner_only_dir(&data_dir);
    write_device_key(&data_dir, 0x21);
    let input =
        library_publish_test_input(&data_dir, "person:local:runtime-custody-partial-settled");
    let request_id = library_publish_request_id(&input);
    let mint_id = seed_settled_runtime_custody_mint_record(&data_dir, &input, false);

    let error =
        publish_runtime_custody_library_object(&data_dir, Arc::new(ProviderRegistry::new()), input)
            .await
            .expect_err("a settled attempt with nothing durable cannot be handed back");
    assert!(
        error
            .to_string()
            .contains(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE),
        "{error}"
    );

    // Both are gone: nothing is left for the next attempt to collide with.
    assert!(
        runtime_mint_journal(&data_dir).load(mint_id).is_err(),
        "the unfinishable record must be discarded"
    );
    assert!(
        runtime_mint_journal(&data_dir)
            .load_intent(request_id)
            .is_err(),
        "the unmintable intent must be discarded"
    );

    // The object is mintable again: the next attempt gets past the wall that
    // used to be permanent, and fails for want of providers instead.
    let retried = publish_runtime_custody_library_object(
        &data_dir,
        Arc::new(ProviderRegistry::new()),
        library_publish_test_input(&data_dir, "person:local:runtime-custody-partial-settled"),
    )
    .await
    .expect_err("no providers are registered, so the fresh attempt still cannot finish");
    assert!(
        !retried
            .to_string()
            .contains(RUNTIME_CUSTODY_MINT_TERMINAL_ABORT_MESSAGE),
        "a cleared object must no longer abort before it starts: {retried}"
    );
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
    let input =
        library_publish_test_input(&data_dir, "person:local:runtime-custody-ambiguous-dispatch");
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
        library_publish_test_input(&data_dir, "person:local:runtime-custody-ambiguous-dispatch"),
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
    let input = library_publish_test_input(
        &data_dir,
        "person:local:runtime-custody-open-handle-recovery",
    );
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
    load_or_persist_runtime_mint_intent(&journal, &composition, &input, mint_nodes, None).unwrap();
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
    let input = library_publish_test_input(&data_dir, "person:local:runtime-custody-close-failure");
    let request_id = library_publish_request_id(&input);
    let mint_intent = persisted_test_mint_intent(&data_dir, &registry, &input);
    let (components, envelope) =
        protect_input_for_test(&input, &mint_intent, &epoch, composition_now, &|_, init| {
            init
        });
    let handle = [0x41; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
    let mut script = media_dash_protect_script(handle, &components, &envelope);
    script.push(Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_failure(ProviderFailureCodeV1::BackendUnavailable).unwrap(),
    )));
    script.push(Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_already_absent(handle).unwrap(),
    )));
    let protect = MediaDashProtectTestProvider::new(script, None);
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
        library_publish_test_input(&data_dir, "person:local:runtime-custody-close-failure"),
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
    // The open, four segments (two renditions of two), the finalize, and the
    // close that failed and the close that found the session already gone.
    assert_eq!(requests.len(), 8);
    assert_eq!(requests[6]["op"], "close_protection_session");
    assert_eq!(requests[7]["op"], "close_protection_session");
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
        &elastos_protected_content_runtime::RuntimeAvailabilityEvidenceV1::from(
            mint.content_availability().unwrap().clone(),
        ),
        &purchase,
        &current_profile_did,
    );
    assert!(mismatch.is_err());
    assert!(mismatch
        .unwrap_err()
        .to_string()
        .contains("Runtime custody chain evidence is invalid"));
}

#[test]
fn remote_seal_signed_file_table_must_cover_the_fetched_package() {
    let framed_bytes = vec![0x5au8; 4160];
    let files = object_protected_content_files(&test_object_identity(&framed_bytes)).unwrap();
    let manifest = crate::content::ContentObjectManifest {
        schema: "elastos.content.object.manifest/v1".into(),
        kind: super::super::PROTECTED_CONTENT_OBJECT_KIND.into(),
        content_digest: super::super::content_object_digest(&files),
        files,
        links: Vec::new(),
        object_did: None,
        publisher_did: None,
    };
    let cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
    let mut claimed: Vec<(String, String)> = manifest
        .files
        .iter()
        .map(|file| (file.path.clone(), cid.into()))
        .collect();
    assert_eq!(
        super::super::remote_seal_manifest_file_cids(&manifest, &claimed).unwrap(),
        vec![cid; 2]
    );
    assert!(super::super::remote_seal_manifest_file_cids(&manifest, &claimed[..1]).is_err());
    claimed.swap(0, 1);
    assert!(super::super::remote_seal_manifest_file_cids(&manifest, &claimed).is_err());
    claimed.swap(0, 1);
    claimed[1].1 = "ipfs://unparsed".into();
    assert!(super::super::remote_seal_manifest_file_cids(&manifest, &claimed).is_err());
}

#[tokio::test]
async fn remote_seal_publication_requires_finality_and_authorized_manifest_before_package_reads() {
    use elastos_protected_content_contracts::test_fixtures::{
        pool_bundle, pool_descriptor_signed_by, pool_did, runtime_issuer, CUSTODY_KEY_SEED_BASE,
        POOL_AUTHORITY_SEED, POOL_NODE_SEEDS,
    };
    use elastos_protected_content_contracts::{
        ClearLayoutV1, ClearPartIndexV1, MintPieceAadV1, MintRequestV1, RemoteShareAdmissionV1,
        SignedMintRequestV1, SignedPoolDescriptorAnyV1,
    };
    use elastos_protected_content_custody::{
        seal_mint_piece_v1, NodeCustodySecretKeyV1, RemoteObjectSealerV1,
    };
    use elastos_protected_content_runtime::{
        prepare_remote_share_provision_request, verify_remote_seal_output,
        RuntimeMintCreatorTerminalEvidence, RuntimeMintedItemV1,
    };

    let bundle = pool_bundle(xwing_public_key_bytes, NOW);
    let descriptor: SignedPoolDescriptorAnyV1 =
        pool_descriptor_signed_by(&bundle, 1, NOW, POOL_AUTHORITY_SEED).into();
    let node = node_public_key(1);
    let clear = vec![0x91; 4096];
    let kid = content_access_id(0x34);
    let epoch = bundle.epoch_identity().unwrap();
    let request = MintRequestV1 {
        pool: pool_did(),
        epoch,
        minter_issuer: runtime_issuer(POOL_AUTHORITY_SEED),
        content_access_id: kid,
        clear_layout: ClearLayoutV1::Object {
            content_type: "application/pdf".into(),
            length: clear.len() as u64,
        },
        request_nonce: [0x35; 16],
        issued_at: NOW,
        expires_at: NOW + 60,
    };
    let signature = node_signing_key(POOL_AUTHORITY_SEED).sign(&request.canonical_bytes().unwrap());
    let request = SignedMintRequestV1::new(request, signature.to_bytes()).unwrap();
    let (mut sealer, mut framed) =
        RemoteObjectSealerV1::open(&request, &descriptor, node, NOW).unwrap();
    let hash = request.canonical_hash().unwrap();
    let aad = MintPieceAadV1 {
        mint_request_hash: hash,
        part: ClearPartIndexV1::ObjectChunk { index: 0 },
        piece: 0,
        piece_count: 1,
    };
    let session = sealer.attestation_statement().unwrap();
    let sealed = seal_mint_piece_v1(&session.seal_session_public_key, &aad, &clear).unwrap();
    sealer
        .stage_piece(
            &aad,
            Digest32::new(sha2::Sha256::digest(clear).into()),
            &sealed,
            NOW,
            |bytes| {
                framed.extend_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
    let identity = test_object_identity(&framed);
    let envelope = sealer
        .finish(identity.encrypted_content(), NOW)
        .unwrap()
        .custody_envelope;
    let directory = tempfile::tempdir().unwrap();
    write_object_protected_content_directory(directory.path(), &identity, &framed);

    let publisher = peer_did_for_seed(0x37);
    let object = peer_did_for_seed(0x38);
    let content =
        ContentAvailabilityTestProvider::new(0x39, ContentAvailabilityTestConfig::accepted());
    let required = RuntimeContentAvailabilityRequirement::new(
        content.signer_did(),
        object.clone(),
        publisher.clone(),
        super::super::PROTECTED_CONTENT_REPLICATION_POLICY,
        3,
        60,
        5,
    )
    .unwrap();
    let chain = Arc::new(RemoteSealFinalityFixture::default());
    let registry = ProviderRegistry::new();
    registry
        .register_sub_provider(CHAIN_PROVIDER_ID, chain.clone())
        .await
        .unwrap();
    registry
        .register_sub_provider("content", content.clone())
        .await
        .unwrap();
    let custody = tempfile::tempdir().unwrap();
    let mut receipts = Vec::new();
    let custody_root = |seed| {
        let data_root = custody.path().join(format!("node-{seed}"));
        #[cfg(unix)]
        crate::protected_content_config::tests::owner_only_dir(&data_root);
        #[cfg(not(unix))]
        fs::create_dir(&data_root).unwrap();
        custody_provider::LoadedCustodyProviderState {
            expected_runtime_issuer: runtime_issuer(POOL_AUTHORITY_SEED),
            node_public_key: node_public_key(seed),
            node_signing_key: node_signing_key(seed),
            node_custody_secret: NodeCustodySecretKeyV1::from_guarded_bytes(
                zeroize::Zeroizing::new([CUSTODY_KEY_SEED_BASE + seed; 32]),
            )
            .unwrap(),
            data_root,
        }
    };
    let mut roots = POOL_NODE_SEEDS.map(custody_root);
    let local_issuer = runtime_issuer(0x85);
    let authorization = roots[0]
        .authorize_remote_share(
            pool_did(),
            &descriptor,
            &request,
            &envelope.key_envelope_identity().unwrap(),
            local_issuer,
            NOW,
        )
        .unwrap();
    let admission = RemoteShareAdmissionV1 {
        descriptor: descriptor.clone(),
        request: request.clone(),
        authorization,
    };
    let sign = |bytes: &[u8]| node_signing_key(0x85).sign(bytes).to_bytes();
    for root in &mut roots {
        let provision = prepare_remote_share_provision_request(
            admission.clone(),
            &envelope,
            root.node_public_key,
            &sign,
            NOW,
        )
        .unwrap();
        let stored = root
            .provision_remote_share(pool_did(), &provision.to_json_vec().unwrap(), NOW)
            .unwrap();
        receipts.push(
            crate::custody_pool_seal::VerifiedRemoteShareReceipt::from_local_store(
                stored.provisioned().receipt(),
            ),
        );
    }
    let published_identity = RuntimeContentIdentityV1::Object(identity.clone());
    let publish = |receipts| {
        super::super::publish_remote_sealed_content(
            &registry,
            directory.path(),
            &published_identity,
            &envelope,
            receipts,
            &required,
            || NOW,
        )
    };
    assert!(publish(&receipts[..2]).await.is_err());
    let duplicate = vec![receipts[0]; receipts.len()];
    assert!(publish(&duplicate).await.is_err());
    assert!(content.requests().await.is_empty());
    let publication = publish(&receipts).await.unwrap();
    content.requests.lock().await.clear();
    let statement = publication
        .prepare_completion(&descriptor, &request, node, NOW)
        .unwrap();
    assert!(roots[1]
        .sign_remote_seal_completion(pool_did(), &descriptor, &request, statement.clone(), NOW)
        .is_err());
    let mut different_mint = request.statement().clone();
    different_mint.request_nonce = [0x36; 16];
    let signature =
        node_signing_key(POOL_AUTHORITY_SEED).sign(&different_mint.canonical_bytes().unwrap());
    let different_mint = SignedMintRequestV1::new(different_mint, signature.to_bytes()).unwrap();
    let replayed_publication = publication
        .prepare_completion(&descriptor, &different_mint, node, NOW)
        .unwrap();
    assert!(roots[0]
        .sign_remote_seal_completion(
            pool_did(),
            &descriptor,
            &different_mint,
            replayed_publication,
            NOW
        )
        .is_err());
    let mut wrong_commitment = statement.clone();
    wrong_commitment.content_key_commitment = Digest32::new([0x37; 32]);
    assert!(roots[0]
        .sign_remote_seal_completion(pool_did(), &descriptor, &request, wrong_commitment, NOW)
        .is_err());
    let mut changed = statement.clone();
    changed.completed_at = NOW + 1;
    let completed = roots[0]
        .sign_remote_seal_completion(pool_did(), &descriptor, &request, statement, NOW)
        .unwrap();
    let changed = roots[0]
        .sign_remote_seal_completion(pool_did(), &descriptor, &request, changed, NOW + 1)
        .unwrap();
    let attestation = roots[0]
        .attest_remote_seal_upload(pool_did(), &descriptor, &request, session, NOW)
        .unwrap();
    let owner = elastos_protected_content_runtime::PoolSessionSource {
        endpoint_did: peer_did_for_seed(0x81),
        local: false,
    };
    let foreign = elastos_protected_content_runtime::PoolSessionSource {
        endpoint_did: peer_did_for_seed(0x82),
        local: false,
    };
    let store = crate::custody_seal_completion::SealerCompletionStore::new(&roots[0].data_root);
    let session_id = attestation.session_id();
    assert!(store.replay(&owner, session_id, NOW).unwrap().is_none());
    store
        .commit(&owner, &descriptor, &request, &attestation, &completed, NOW)
        .unwrap();
    let restarted = crate::custody_seal_completion::SealerCompletionStore::new(&roots[0].data_root);
    assert_eq!(
        restarted.replay(&owner, session_id, NOW + 1).unwrap(),
        Some(completed.clone())
    );
    assert!(restarted
        .replay(&foreign, session_id, NOW + 1)
        .unwrap()
        .is_none());
    assert!(restarted
        .replay(&owner, session_id, NOW + 60)
        .unwrap()
        .is_none());
    assert!(restarted
        .commit(
            &owner,
            &descriptor,
            &request,
            &attestation,
            &changed,
            NOW + 1
        )
        .is_err());
    restarted
        .commit(
            &owner,
            &descriptor,
            &request,
            &attestation,
            &completed,
            NOW + 1,
        )
        .unwrap();
    let completed = restarted
        .replay(&owner, session_id, NOW + 1)
        .unwrap()
        .unwrap();
    let output =
        verify_remote_seal_output(&completed, &descriptor, &request, node, &envelope, NOW).unwrap();
    let minter_output = elastos_protected_content_runtime::verify_recorded_remote_seal_attestation(
        &completed,
        &descriptor,
        &request,
        node,
    )
    .unwrap();
    let fresh = super::super::verify_fresh_remote_seal_publication(
        &registry,
        &minter_output,
        &required,
        || NOW,
    )
    .await
    .unwrap();
    assert_eq!(fresh.content_cid(), ContentAvailabilityTestProvider::CID);
    let encode = |bytes: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(bytes);
    let proof = super::super::RuntimePortableRemoteSealV1 {
        descriptor_base64: encode(descriptor.canonical_bytes().unwrap()),
        request_base64: encode(request.canonical_bytes().unwrap()),
        completion_base64: encode(completed.canonical_bytes().unwrap()),
    };
    let verified_publisher = |cid, asset, issuer| {
        proof.verify(
            &envelope.key_envelope_identity().unwrap(),
            asset,
            minter_output.identity(),
            envelope.manifest().content_key_commitment(),
            cid,
            issuer,
        )
    };
    assert_eq!(
        verified_publisher(
            fresh.content_cid(),
            kid,
            runtime_issuer(POOL_AUTHORITY_SEED)
        )
        .unwrap(),
        publisher
    );
    assert!(
        verified_publisher("bafysubstituted", kid, runtime_issuer(POOL_AUTHORITY_SEED)).is_err()
    );
    assert!(verified_publisher(fresh.content_cid(), kid, runtime_issuer(0x33)).is_err());
    assert!(verified_publisher(
        fresh.content_cid(),
        ContentAccessIdV1::new([9; 16]).unwrap(),
        runtime_issuer(POOL_AUTHORITY_SEED)
    )
    .is_err());
    let manifest_reads = content.requests().await;
    assert_eq!(manifest_reads.len(), 1);
    assert_eq!(manifest_reads[0]["op"], "fetch");
    assert_eq!(
        manifest_reads[0]["path"],
        crate::content::CONTENT_OBJECT_MANIFEST_PATH
    );
    content.requests.lock().await.clear();
    let verify_manifest = |expected_publisher| {
        super::super::verify_non_holder_content(
            &registry,
            fresh.content_cid(),
            &object,
            minter_output.identity(),
            Some(expected_publisher),
            super::super::NonHolderCheck::ManifestOnly,
            NOW,
        )
    };
    assert!(verify_manifest(&publisher).await.is_ok());
    assert!(verify_manifest(&object).await.is_err());
    content.requests.lock().await.clear();

    let later = NOW + required.max_age_seconds() + 1;
    let minter_registry = ProviderRegistry::new();
    let minter_content = ContentAvailabilityTestProvider::with_signing_key(
        derived_device_key_for_seed(0x79).0,
        ContentAvailabilityTestConfig::accepted_at(later),
    );
    minter_content
        .seed_published_protected_content(directory.path(), &object, &publisher)
        .await
        .unwrap();
    minter_registry
        .register_sub_provider("content", minter_content.clone())
        .await
        .unwrap();
    let minter_did = minter_content.signer_did();
    let (refreshed_requirement, refreshed) = super::super::verify_remote_mint_publication(
        &minter_registry,
        &minter_output,
        required.clone(),
        &minter_did,
        || later,
    )
    .await
    .unwrap();
    assert_eq!(refreshed.content_cid(), fresh.content_cid());
    assert_eq!(refreshed.publisher_identity(), &publisher);
    assert_eq!(refreshed_requirement.expected_provider_did(), minter_did);
    assert_eq!(refreshed.checked_at(), later);
    let refresh_calls = minter_content.requests().await;
    assert!(refresh_calls.iter().any(|call| call["op"] == "ensure"));
    assert_eq!(
        refresh_calls
            .iter()
            .filter(|call| call["op"] == "fetch" && call.get("path").is_none())
            .count(),
        2
    );

    let mut forged = minter_output.statement().clone();
    let mut receipt: Value = serde_json::from_slice(&forged.availability_receipt).unwrap();
    receipt["signature"] = json!("invalid");
    forged.availability_receipt = serde_json::to_vec(&receipt).unwrap();
    let signature = node_signing_key(1).sign(&forged.canonical_bytes().unwrap());
    let forged = elastos_protected_content_contracts::SignedSealCompletedV1::new(
        forged,
        signature.to_bytes(),
    )
    .unwrap();
    let forged = elastos_protected_content_runtime::verify_recorded_remote_seal_attestation(
        &forged,
        &descriptor,
        &request,
        node,
    )
    .unwrap();
    minter_content.requests.lock().await.clear();
    let error = super::super::verify_remote_mint_publication(
        &minter_registry,
        &forged,
        required.clone(),
        &minter_did,
        || later,
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("signature is invalid"),
        "{error:#}"
    );
    let refused_calls = minter_content.requests().await;
    assert_eq!(refused_calls.len(), 1);
    assert_eq!(
        refused_calls[0]["path"],
        crate::content::CONTENT_OBJECT_MANIFEST_PATH
    );

    let terminal = RuntimeMintCreatorTerminalEvidence::new(
        ContentAvailabilityTestProvider::CID,
        format!("ipfs://{}", ContentAvailabilityTestProvider::CID),
        format!("0x{}", "11".repeat(20)),
        "eip155:11155111",
        "sepolia",
        format!("0x{}", "22".repeat(20)),
        "0x7",
        "mint",
        "0x1",
        "0x1",
        format!("0x{}", "00".repeat(20)),
        None,
        format!("0x{}", "33".repeat(32)),
        NOW,
    )
    .unwrap();
    let verify = || {
        super::super::verify_remote_seal_publication(
            &registry,
            &output,
            &terminal,
            &required,
            || NOW,
        )
    };
    assert!(verify()
        .await
        .unwrap_err()
        .is::<super::super::RuntimeMintSealAwaitingFinality>());
    assert!(content.requests().await.is_empty());
    let item = RuntimeMintedItemV1::from_creator_terminal(&terminal).unwrap();
    let policy = policy_body_for(
        identity.encrypted_content().clone(),
        kid,
        RightsActionV1::View,
    )
    .with_expected_item(item.expected_item());
    let wrong_item = RuntimeMintedItemV1::from_parts(
        terminal.chain_namespace(),
        terminal.ledger(),
        "0x8",
        terminal.seller(),
    )
    .unwrap();
    *chain.policy.lock().await = Some(
        policy
            .clone()
            .with_expected_item(wrong_item.expected_item()),
    );
    assert!(verify().await.is_err());
    assert!(content.requests().await.is_empty());
    *chain.policy.lock().await = Some(policy.clone());
    content
        .seed_published_protected_content(directory.path(), &object, &publisher)
        .await
        .unwrap();
    let (verified_policy, _) = verify().await.unwrap();
    assert_eq!(verified_policy, policy);
    let requests = content.requests().await;
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["op"] == "fetch" && r.get("path").is_none())
            .count(),
        2
    );
    assert_eq!(requests[requests.len() - 2]["op"], "ensure");
    assert_eq!(requests[requests.len() - 1]["op"], "status");
    for request in chain.requests.lock().await.iter() {
        assert_eq!(
            request["content_access_id"],
            format!("0x{}", hex::encode(kid.as_bytes()))
        );
        assert_eq!(request["expected_item"]["token_id"], "0x7");
        assert_eq!(request["expected_item"]["channel"], terminal.ledger());
        assert_eq!(request["expected_item"]["creator"], terminal.seller());
    }

    for (published_object, published_by) in [
        (&object, peer_did_for_seed(0x40)),
        (&publisher, publisher.clone()),
    ] {
        content
            .seed_published_protected_content(directory.path(), published_object, &published_by)
            .await
            .unwrap();
        content.requests.lock().await.clear();
        assert!(verify().await.is_err());
        let attempted = content.requests().await;
        assert_eq!(
            attempted.len(),
            1,
            "foreign manifest must refuse before file reads or ensure"
        );
        assert_eq!(
            attempted[0]["path"],
            crate::content::CONTENT_OBJECT_MANIFEST_PATH
        );
    }
}

#[test]
fn publish_object_seals_with_epc1_and_writes_object_manifest() {
    let framed_bytes = vec![0x5au8; 4160];
    let object_identity = test_object_identity(&framed_bytes);
    let directory = tempfile::tempdir().unwrap();
    write_object_protected_content_directory(directory.path(), &object_identity, &framed_bytes);

    verify_protected_content_object_directory(directory.path(), &object_identity)
        .expect("a freshly written object directory must verify");

    let files = object_protected_content_files(&object_identity).unwrap();
    assert_eq!(files.len(), 2);
    assert!(files
        .iter()
        .any(|file| file.path == PROTECTED_CONTENT_OBJECT_EPC1_PATH
            && file.size == framed_bytes.len() as u64
            && file.sha256
                == hex::encode(
                    object_identity
                        .encrypted_content()
                        .ciphertext_sha256()
                        .as_bytes()
                )));
    assert!(files
        .iter()
        .any(|file| file.path == PROTECTED_CONTENT_OBJECT_MANIFEST_PATH));

    let manifest_bytes = fs::read(
        directory
            .path()
            .join(PROTECTED_CONTENT_OBJECT_MANIFEST_PATH),
    )
    .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(
        manifest["schema"],
        "elastos.protected-content.object-manifest/v1"
    );
    assert_eq!(manifest["content_type"], "application/pdf");
    assert_eq!(manifest["plaintext_bytes"], 4096);
    assert_eq!(manifest["framed_header_bytes"], 64);
    assert_eq!(
        manifest["encrypted_content"]["sha256"],
        hex::encode(
            object_identity
                .encrypted_content()
                .ciphertext_sha256()
                .as_bytes()
        )
    );
    assert_eq!(manifest["encrypted_content"]["bytes"], 4160);
}

#[test]
fn object_directory_verify_streams_a_large_file() {
    use std::io::{Seek, SeekFrom, Write};
    let directory = tempfile::tempdir().unwrap();
    let tree = directory.path().join("protected-content/v1");
    fs::create_dir_all(&tree).unwrap();
    let epc1 = directory.path().join(PROTECTED_CONTENT_OBJECT_EPC1_PATH);
    let length = 80 * 1024 * 1024u64;
    let mut file = fs::File::create(&epc1).unwrap();
    file.set_len(length).unwrap();
    for offset in [0u64, 1 << 20, 40 << 20] {
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&[0xa5; 4096]).unwrap();
    }
    drop(file);
    let (sha, bytes) = sha256_file(&epc1).unwrap();
    assert_eq!(bytes, length);
    let identity = ChunkedPayloadObjectIdentityV1::new(
        EncryptedContentIdentityV1::new(sha, length).unwrap(),
        "application/pdf",
        length - 64,
        64,
    )
    .unwrap();
    fs::write(
        directory
            .path()
            .join(PROTECTED_CONTENT_OBJECT_MANIFEST_PATH),
        protected_content_object_manifest_bytes(&identity).unwrap(),
    )
    .unwrap();
    verify_protected_content_object_directory(directory.path(), &identity).unwrap();

    let mut file = fs::OpenOptions::new().write(true).open(&epc1).unwrap();
    file.seek(SeekFrom::Start(75 << 20)).unwrap();
    file.write_all(&[0x01]).unwrap();
    drop(file);
    assert!(verify_protected_content_object_directory(directory.path(), &identity).is_err());
}

#[test]
fn object_framed_staging_sink_hashes_what_it_writes() {
    #[derive(Default)]
    struct CountingWriter {
        total: u64,
        largest_write: usize,
        written: Vec<u8>,
    }
    impl std::io::Write for CountingWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.total += buffer.len() as u64;
            self.largest_write = self.largest_write.max(buffer.len());
            self.written.extend_from_slice(buffer);
            Ok(buffer.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let header = vec![0x01u8; 64];
    let mut expected = header.clone();
    let mut sink = ObjectFramedStagingSink::new(CountingWriter::default());
    sink.push(&header).unwrap();
    for index in 0..70u8 {
        let piece = vec![index; MAX_OBJECT_FRAMED_CHUNK_BYTES_V1];
        expected.extend_from_slice(&piece);
        sink.push(&piece).unwrap();
    }
    let (identity, writer) = sink.finish().unwrap();
    assert_eq!(writer.total, expected.len() as u64);
    assert_eq!(identity.ciphertext_bytes(), expected.len() as u64);
    assert_eq!(
        identity.ciphertext_sha256(),
        Digest32::new(sha2::Sha256::digest(&expected).into())
    );
    assert!(writer.largest_write <= MAX_OBJECT_FRAMED_CHUNK_BYTES_V1);
}

#[test]
fn verify_protected_content_directory_rejects_tampered_object_file() {
    let framed_bytes = vec![0x5au8; 4160];
    let object_identity = test_object_identity(&framed_bytes);
    let directory = tempfile::tempdir().unwrap();
    write_object_protected_content_directory(directory.path(), &object_identity, &framed_bytes);
    verify_protected_content_object_directory(directory.path(), &object_identity).unwrap();

    // Tamper with the framed ciphertext after the fact: the sha256 no longer
    // matches what the object identity commits to.
    let mut tampered = framed_bytes.clone();
    tampered[0] ^= 0xff;
    fs::write(
        directory.path().join(PROTECTED_CONTENT_OBJECT_EPC1_PATH),
        &tampered,
    )
    .unwrap();
    assert!(verify_protected_content_object_directory(directory.path(), &object_identity).is_err());

    // Restore, then tamper with the manifest instead.
    fs::write(
        directory.path().join(PROTECTED_CONTENT_OBJECT_EPC1_PATH),
        &framed_bytes,
    )
    .unwrap();
    fs::write(
        directory.path().join(PROTECTED_CONTENT_OBJECT_MANIFEST_PATH),
        br#"{"schema":"elastos.protected-content.object-manifest/v1","content_type":"text/plain","plaintext_bytes":4096,"framed_header_bytes":64,"encrypted_content":{"sha256":"00","bytes":4160}}"#,
    )
    .unwrap();
    assert!(verify_protected_content_object_directory(directory.path(), &object_identity).is_err());

    // A directory missing the object entirely must also fail closed.
    let empty = tempfile::tempdir().unwrap();
    assert!(verify_protected_content_object_directory(empty.path(), &object_identity).is_err());
}

/// Validation reads the accepted floor and new mints ask for the target. The
/// floor stays at one copy, and the target never goes below it.
#[test]
fn accepted_floor_never_exceeds_new_mint_target() {
    let floor = super::super::PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR;
    let target = super::super::PROTECTED_CONTENT_NEW_MINT_REPLICA_TARGET;
    assert_eq!(floor, 1, "a listing verified with one copy stays valid");
    assert_ne!(
        floor.cmp(&target),
        std::cmp::Ordering::Greater,
        "a new mint asks for at least the copies a listing must keep"
    );
    assert_eq!(
        super::super::protected_content_live_proof_required(target),
        target > 1,
        "a new mint asks for a live proof only when it asks for another copy"
    );
    assert_eq!(
        super::super::protected_content_live_proof_required(floor),
        floor > 1,
        "a re-check at the floor asks for a live proof only when the floor needs another copy"
    );
}

/// R40 (T8-C3): the `did:pkh` publisher relaxation is an explicit choice made
/// only for an adopted listing (origin `Asset`), never inferred from the
/// requirement's DID method; and even there the manifest must name a real
/// `did:key`, not merely something.
#[test]
fn manifest_publisher_binding_is_chosen_by_origin_and_requires_a_did_key() {
    use super::super::{
        content_manifest_binds_publisher, RuntimeManifestPublisherBinding as Binding,
    };
    let did_key = derived_device_key_for_seed(0x66).1;
    let pkh = "did:pkh:eip155:8453:0x00000000000000000000000000000000000000a4";
    let requirement = |publisher: &str| {
        RuntimeContentAvailabilityRequirement::new(
            did_key.clone(),
            "did:key:z6Mkhq7f4c4QAEgwRByrEsmGu3RJRYvpP5UGcWvqBjGW4YRe#content",
            publisher,
            super::super::PROTECTED_CONTENT_REPLICATION_POLICY,
            super::super::PROTECTED_CONTENT_ACCEPTED_REPLICA_FLOOR,
            super::super::PROTECTED_CONTENT_AVAILABILITY_MAX_AGE_SECS,
            super::super::PROTECTED_CONTENT_AVAILABILITY_MAX_FUTURE_SKEW_SECS,
        )
        .unwrap()
    };
    let manifest = |publisher: Option<&str>| crate::content::ContentObjectManifest {
        schema: "elastos.content.object.manifest/v1".to_string(),
        kind: "directory".to_string(),
        content_digest: String::new(),
        files: Vec::new(),
        links: Vec::new(),
        object_did: None,
        publisher_did: publisher.map(str::to_string),
    };
    // An adopted listing: the manifest names the Runtime profile that
    // published the bytes, a well-formed did:key.
    assert!(content_manifest_binds_publisher(
        &manifest(Some(&did_key)),
        &requirement(pkh),
        Binding::AdoptedAttribution,
    ));
    for named in [Some("did:web:example.com"), Some("x"), Some(pkh), None] {
        assert!(
            !content_manifest_binds_publisher(
                &manifest(named),
                &requirement(pkh),
                Binding::AdoptedAttribution,
            ),
            "{named:?} is not a publisher's did:key"
        );
    }
    // The relaxation is never inferred from the requirement's method.
    assert!(!content_manifest_binds_publisher(
        &manifest(Some(&did_key)),
        &requirement(pkh),
        Binding::Exact,
    ));
    assert!(content_manifest_binds_publisher(
        &manifest(Some(&did_key)),
        &requirement(&did_key),
        Binding::Exact,
    ));
    // And an adopted binding still needs the adopted (did:pkh) requirement.
    assert!(!content_manifest_binds_publisher(
        &manifest(Some(&did_key)),
        &requirement(&did_key),
        Binding::AdoptedAttribution,
    ));
    // Only origin `Asset` chooses it.
    assert_eq!(
        Binding::for_origin(&super::super::RuntimeCustodyListingOrigin::Asset {
            asset_uri: "elastos://bafyfixture".to_string(),
            source_listing: None,
        }),
        Binding::AdoptedAttribution
    );
    assert_eq!(
        Binding::for_origin(&super::super::RuntimeCustodyListingOrigin::Imported {
            listing_uri: "elastos://bafyfixture".to_string(),
            package_sha256: "00".repeat(32),
        }),
        Binding::Exact
    );
}

#[test]
fn dash_segment_cap_fits_the_provider_frame() {
    use elastos_protected_content_provider_contracts::MAX_VIEWER_MEDIA_PART_BYTES_V1;
    let cap = super::super::MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2;
    assert_eq!(cap, 2 * 1024 * 1024 - 32 * 1024);
    assert!(cap < MAX_VIEWER_MEDIA_PART_BYTES_V1);
    // The echo carries the segment and a clear part no longer than it, as JSON
    // numbers of up to 4 characters each, plus at most 16 KiB of the rest.
    assert!(8 * cap + 16 * 1024 <= 16 * 1024 * 1024);
}

#[test]
fn dash_manifest_gives_the_leaves_of_an_independent_rebuild() {
    let components = media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]);
    let manifest = dash_manifest_from_files(&components_package_files(&components));
    let leaves =
        super::super::verify_protected_content_dash_manifest(&manifest, &components.head).unwrap();
    assert_eq!(leaves, dash_all_leaves(&components));
    // Every kind set verifies.
    for (kinds, counts) in [
        (vec![DASH_VIDEO], vec![3usize]),
        (vec![DASH_AUDIO], vec![1]),
        (vec![DASH_VIDEO, DASH_AUDIO], vec![3, 2]),
    ] {
        let (head, inits, segments) = fake_dash_package(&kinds, &counts);
        let manifest = dash_manifest_from_files(&dash_package_files(&head, &inits, &segments));
        assert!(super::super::verify_protected_content_dash_manifest(&manifest, &head).is_ok());
    }
}

#[test]
fn dash_manifest_finds_segments_by_path_not_by_position() {
    // `seg-10` sorts before `seg-2`, so position and index disagree from the
    // tenth segment on; the leaf of index 9 must be `seg-10`'s entry.
    let (head, inits, segments) = fake_dash_package(&[DASH_VIDEO], &[12]);
    let manifest = dash_manifest_from_files(&dash_package_files(&head, &inits, &segments));
    let paths: Vec<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
    let seg10 = paths
        .iter()
        .position(|p| p.ends_with("/seg-10.m4s"))
        .unwrap();
    let seg2 = paths
        .iter()
        .position(|p| p.ends_with("/seg-2.m4s"))
        .unwrap();
    assert!(seg10 < seg2, "the fixture must exercise the sort inversion");
    let leaves = super::super::verify_protected_content_dash_manifest(&manifest, &head).unwrap();
    assert_eq!(leaves[0], dash_leaves(DASH_VIDEO, &segments[0]));
    assert_eq!(
        leaves[0][9],
        elastos_protected_content_provider_contracts::cenc_dash_segment_leaf_hash(
            DASH_VIDEO,
            9,
            Digest32::new(sha2::Sha256::digest(&segments[0][9]).into()),
            segments[0][9].len() as u64,
        )
    );
}

#[test]
fn dash_manifest_refuses_every_deviation() {
    const INVALID: &str = "protected content object manifest is invalid";
    let (head, inits, segments) = fake_dash_package(&[DASH_VIDEO, DASH_AUDIO], &[3, 3]);
    let base = dash_manifest_from_files(&dash_package_files(&head, &inits, &segments));
    assert!(super::super::verify_protected_content_dash_manifest(&base, &head).is_ok());
    let video_seg = |n: usize| dash_segment_file(DASH_VIDEO, n);
    let index_of = |manifest: &crate::content::ContentObjectManifest, path: &str| {
        manifest.files.iter().position(|f| f.path == path).unwrap()
    };
    let mut cases: Vec<(&str, crate::content::ContentObjectManifest)> = Vec::new();

    let mut m = base.clone();
    let at = index_of(&m, &video_seg(1));
    m.files.remove(at);
    reseal(&mut m);
    cases.push(("a missing segment", m));

    let mut m = base.clone();
    m.files.push(content_object_file_for_test(
        "protected-content/v2/zzz-extra.bin",
        b"x",
    ));
    reseal(&mut m);
    cases.push(("an extra file", m));

    for (label, renamed) in [
        ("seg-0", format!("{}/seg-0.m4s", dash_dir(DASH_VIDEO))),
        ("seg-01", format!("{}/seg-01.m4s", dash_dir(DASH_VIDEO))),
        ("seg-(count+1)", video_seg(3)),
    ] {
        let mut m = base.clone();
        let at = index_of(&m, &video_seg(if label == "seg-(count+1)" { 2 } else { 0 }));
        m.files[at].path = renamed;
        m.files.sort_by(|l, r| l.path.cmp(&r.path));
        reseal(&mut m);
        cases.push((label, m));
    }

    let mut m = base.clone();
    let at = index_of(&m, &video_seg(0));
    m.files[at].sha256 = hex::encode(sha2::Sha256::digest(b"other"));
    reseal(&mut m);
    cases.push(("a segment sha changed (root mismatch)", m));

    let mut m = base.clone();
    let at = index_of(&m, &video_seg(0));
    m.files[at].size += 1;
    reseal(&mut m);
    cases.push(("a segment size changed (root mismatch)", m));

    let mut m = base.clone();
    let at = index_of(&m, &video_seg(2));
    m.files[at].size = 0;
    reseal(&mut m);
    cases.push(("a zero-size segment", m));

    let mut m = base.clone();
    let at = index_of(&m, &dash_init_path(DASH_AUDIO));
    m.files[at].sha256 = hex::encode(sha2::Sha256::digest(b"other"));
    reseal(&mut m);
    cases.push(("an init sha changed", m));

    let mut m = base.clone();
    let at = index_of(&m, &dash_init_path(DASH_VIDEO));
    m.files[at].size += 1;
    reseal(&mut m);
    cases.push(("an init size changed", m));

    let mut m = base.clone();
    let at = index_of(&m, DASH_IDENTITY_FILE);
    m.files[at].sha256 = hex::encode(sha2::Sha256::digest(b"other"));
    reseal(&mut m);
    cases.push(("an identity sha changed", m));

    let mut m = base.clone();
    m.content_digest = format!("sha256:{}", hex::encode([0u8; 32]));
    cases.push(("a wrong content_digest", m));

    let mut m = base.clone();
    m.links.push(crate::content::ContentObjectLink {
        rel: "x".to_string(),
        cid: ContentAvailabilityTestProvider::CID.to_string(),
    });
    cases.push(("non-empty links", m));

    let mut m = base.clone();
    m.kind = "other".to_string();
    cases.push(("a wrong kind", m));

    let mut m = base.clone();
    m.files.swap(2, 3);
    reseal(&mut m);
    cases.push(("an unsorted path list", m));

    let mut m = base.clone();
    let duplicate = m.files[2].clone();
    m.files.remove(3);
    m.files.insert(2, duplicate);
    reseal(&mut m);
    cases.push(("a duplicate path", m));

    let mut m = base.clone();
    let at = index_of(&m, &video_seg(1));
    m.files[at].sha256 = m.files[at].sha256.to_uppercase();
    reseal(&mut m);
    cases.push(("uppercase hex", m));

    for (label, manifest) in cases {
        assert_eq!(manifest_error(&manifest, &head), INVALID, "{label}");
    }
}

#[test]
fn dash_manifest_refuses_a_segment_over_the_protected_cap() {
    use elastos_protected_content_provider_contracts::{
        CencDashMediaIdentityV2, CencDashRenditionBytesV2,
    };
    let cap = super::super::MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2;
    for (len, accepted) in [(cap, true), (cap + 1, false)] {
        // A head whose roots match the files, so only the size can refuse.
        let segments = vec![vec![0x5a; len]];
        let head = CencDashMediaIdentityV2::new_from_bytes(
            content_access_id(0x41),
            &[CencDashRenditionBytesV2 {
                kind: DASH_VIDEO,
                timescale: 90_000,
                init_segment: b"init",
                segments: &segments,
            }],
        )
        .unwrap();
        let files = dash_package_files(&head, &[b"init".to_vec()], &[segments]);
        let result = super::super::verify_protected_content_dash_manifest(
            &dash_manifest_from_files(&files),
            &head,
        );
        assert_eq!(result.is_ok(), accepted, "{len}");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn dash_read_refuses_a_published_segment_over_the_cap_before_decrypting() {
    let viewer = dash_viewer(
        media_dash_components(&[DASH_VIDEO, DASH_AUDIO], &[2, 2]),
        "cap",
    )
    .await;
    viewer.stage_leaves();
    let reads = viewer.expected_reads();
    let decrypt = viewer.register_decrypt(&reads).await;
    for (selector, _) in reads.iter().take(2) {
        viewer.read(selector.segment_index(), None).await.unwrap();
    }
    viewer
        .harness
        .base
        .content_provider
        .replace_published_file(
            &dash_segment_file(DASH_VIDEO, 0),
            vec![0x7f; super::super::MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2 + 1],
        )
        .await;
    let error = viewer.read(Some(0), None).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "Runtime custody viewer media part is invalid"
    );
    assert_eq!(
        decrypt.requests().await.len(),
        2,
        "only the two inits reached decrypt"
    );
    assert_eq!(viewer.record().next_media_part_index, 2);
}

#[cfg(unix)]
#[tokio::test]
async fn prepared_record_of_a_completed_mint_is_consumed_not_prepared_again() {
    let temp = tempfile::tempdir().unwrap();
    let (data_dir, staging_root) = setup_media_preparation_root(temp.path());
    write_device_key(&data_dir, 0x21);
    let source =
        media_preparation_source_input(temp.path(), "person:local:media-completed-prepared");
    let mut input = library_publish_test_input(&data_dir, &source.principal_id);
    input.object_uri = source.object_uri.clone();
    input.source_storage = source.source_storage.clone();
    let mint_id = seed_settled_runtime_custody_mint_record(&data_dir, &input, true);
    let journal = runtime_mint_journal(&data_dir);
    journal
        .mark_intent_completed(library_publish_request_id(&input), mint_id)
        .unwrap();
    // The v1 preparation of that mint was never consumed before the upgrade.
    let preparation = RuntimeMediaPreparationRecord::new(
        &source.principal_id,
        &source.object_uri,
        &source.source_storage,
        runtime_media_source_digest(b"bounded source media"),
        MEDIA_PROVIDER_ID,
        source.wallet_account_id.clone(),
        source.wallet_account_address.clone(),
        source.creator_mint_source_digest,
    )
    .unwrap();
    journal.persist_media_preparation(&preparation).unwrap();
    journal
        .mark_media_preparation_effect_started(preparation.request_id())
        .unwrap();
    journal
        .mark_media_preparation_prepared(preparation.request_id(), digest(0xd1))
        .unwrap();
    owner_only_dir(&staging_root.join(hex::encode(preparation.operation_id().as_bytes())));
    let registry = Arc::new(ProviderRegistry::new());

    let RuntimeLibraryMediaPreparation::Consumed { record, .. } =
        prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &source)
            .await
            .expect("a completed mint finishes normally")
    else {
        panic!("expected the preparation to be consumed");
    };
    assert_eq!(record.consumed_mint_id(), Some(mint_id));
}

#[cfg(unix)]
#[tokio::test]
async fn media_dash_mint_streams_the_parts_and_publishes_the_v2_package() {
    let harness = library_mint_harness(
        "person:local:dash-mint-happy",
        &[(DASH_VIDEO, 3), (DASH_AUDIO, 3)],
    )
    .await;
    let (intent, components, envelope) = harness.honest_protect();
    let mut script = media_dash_protect_script(TEST_PROTECT_HANDLE, &components, &envelope);
    script.push(closed_protect_response());
    let protect = harness.register_protect(script).await;

    let facts = harness.publish().await.expect("a v2 mint must publish");

    // The order of requests: the open, every segment of the video then of the
    // audio, the finalize, the close.
    let requests = protect.requests().await;
    let mut order = vec!["open_protection_session".to_string()];
    for rendition in 0..2 {
        for index in 0..3 {
            order.push(format!("protect_media_segment {rendition} {index}"));
        }
    }
    order.push("finalize_protection_session".to_string());
    order.push("close_protection_session".to_string());
    let seen: Vec<String> = requests
        .iter()
        .map(|request| match request["op"].as_str().unwrap() {
            "protect_media_segment" => format!(
                "protect_media_segment {} {}",
                request["rendition_index"], request["segment_index"]
            ),
            op => op.to_string(),
        })
        .collect();
    assert_eq!(seen, order);
    // The open: the pinned pair of each rendition, and no foreign boxes.
    let open = &requests[0];
    let representations = open["representations"].as_array().unwrap();
    assert_eq!(representations.len(), 2);
    for (representation, (rendition, mime, codecs)) in representations
        .iter()
        .zip([TEST_VIDEO_DECL, TEST_AUDIO_DECL])
    {
        assert_eq!(representation["rendition"], rendition);
        assert_eq!(representation["mime_type"], mime);
        assert_eq!(representation["codecs"], codecs);
        assert_eq!(representation["segment_count"], 3);
    }
    assert!(open.get("extra_pssh_boxes").is_none_or(Value::is_null));
    assert!(!open["content_access_id"].is_null());

    // The draft is a v2 head, provisioned and available.
    let persisted = runtime_mint_journal(&harness.data_dir)
        .load(facts.mint_id)
        .unwrap();
    assert_eq!(
        persisted.draft().media_dash_identity(),
        Some(&components.head)
    );
    assert!(persisted.draft().media_identity().is_none());
    assert_eq!(
        persisted.draft().content_access_id(),
        intent.content_access_id()
    );
    let evidence = persisted.content_availability().unwrap();
    assert_eq!(
        evidence.content_identity_root(),
        elastos_protected_content_runtime::RuntimeVerifiedContentIdentityRootV1::for_media_dash(
            &components.head
        )
    );
    assert_eq!(
        runtime_mint_journal(&harness.data_dir)
            .load_intent(intent.request_id())
            .unwrap()
            .completed_mint_id(),
        Some(facts.mint_id)
    );

    // What was published is the package of spec section 3, byte for byte.
    let published = harness.content.files.lock().await.clone();
    let mut published_paths: Vec<&str> = published
        .keys()
        .map(String::as_str)
        .filter(|path| *path != crate::content::CONTENT_OBJECT_MANIFEST_PATH)
        .collect();
    published_paths.sort_unstable();
    let package = components_package_files(&components);
    let expected_paths: Vec<&str> = package.iter().map(|(path, _)| path.as_str()).collect();
    assert_eq!(published_paths, expected_paths);
    for (path, bytes) in &package {
        if path != DASH_MPD_FILE {
            assert_eq!(&published[path], bytes, "{path}");
        }
    }
    let mpd = String::from_utf8(published[DASH_MPD_FILE].clone()).unwrap();
    assert_eq!(mpd, expected_dash_mpd(&harness.input, &components));

    // S8: the protection system the inits and the MPD name is the writer
    // binding's, compared with the contracts' own constant.
    let writer = PROTECTION.writer();
    for init in &components.protected_inits {
        let published_init = published
            .values()
            .find(|bytes| *bytes == init)
            .expect("every protected init is published");
        assert!(published_init
            .windows(16)
            .any(|window| window == writer.id.as_bytes()));
    }
    assert!(mpd.contains(&format!(
        "schemeIdUri=\"urn:uuid:{}\" value=\"{}\"",
        uuid_text(writer.id.as_bytes()),
        writer.scheme
    )));
    harness.assert_no_staging();
}

#[cfg(unix)]
#[tokio::test]
async fn media_dash_mint_refuses_too_many_slices_with_a_message_the_creator_can_act_on() {
    let harness = library_mint_harness(
        "person:local:dash-mint-slices",
        &[(DASH_VIDEO, 2), (DASH_AUDIO, 2)],
    )
    .await;
    let (intent, components, envelope) = harness.honest_protect();
    let mut script = media_dash_protect_script(TEST_PROTECT_HANDLE, &components, &envelope);
    script.truncate(1);
    script.push(Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_failure_with_reason(
            ProviderFailureCodeV1::InvalidRequest,
            elastos_protected_content_provider_contracts::ProtectFailureReasonV2::CencTooManySubsamples,
        )
        .unwrap(),
    )));
    script.push(cancelled_protect_response());
    let protect = harness.register_protect(script).await;

    let error = harness
        .publish()
        .await
        .expect_err("too many slices must be refused");

    assert_eq!(
        error.to_string(),
        super::super::RUNTIME_CUSTODY_MEDIA_TOO_MANY_SLICES_MESSAGE
    );
    assert_eq!(
        super::super::RUNTIME_CUSTODY_MEDIA_TOO_MANY_SLICES_MESSAGE,
        "This video has too many slices per frame; re-encode it with fewer slices."
    );
    let requests = protect.requests().await;
    assert_eq!(requests.last().unwrap()["op"], "cancel_protection_session");
    let settled = runtime_mint_journal(&harness.data_dir)
        .load_intent(intent.request_id())
        .unwrap();
    assert_eq!(
        settled.protect_terminal_settlement_label(),
        Some("cancelled")
    );
    harness.assert_no_staging();
}

#[cfg(unix)]
#[tokio::test]
async fn media_dash_mint_refuses_a_prepared_segment_rewritten_after_preparation() {
    let harness = library_mint_harness(
        "person:local:dash-mint-rewritten",
        &[(DASH_VIDEO, 2), (DASH_AUDIO, 2)],
    )
    .await;
    let (intent, components, envelope) = harness.honest_protect();
    let mut script = media_dash_protect_script(TEST_PROTECT_HANDLE, &components, &envelope);
    script.pop();
    script.push(cancelled_protect_response());
    let protect = harness.register_protect(script).await;
    // The segment is rewritten with another valid clear segment after the
    // preparation receipt was taken (the mock provider protects anything).
    let part = harness
        .input
        .media
        .operation_root
        .join("prepared/video/segments/00000001.m4s");
    let mut bytes = fs::read(&part).unwrap();
    *bytes.last_mut().unwrap() ^= 0x01;
    write_private_file(&part, &bytes);

    let error = harness
        .publish()
        .await
        .expect_err("a rewritten part must be refused");

    assert!(
        error
            .to_string()
            .contains("Runtime custody media preparation output changed"),
        "{error}"
    );
    let requests = protect.requests().await;
    assert_eq!(requests.last().unwrap()["op"], "cancel_protection_session");
    let scan = runtime_mint_journal(&harness.data_dir)
        .find_mint_record_for_intent(intent.request_id())
        .unwrap();
    assert!(scan.open().is_none());
    harness.assert_no_staging();
}

#[cfg(unix)]
#[tokio::test]
async fn media_dash_mint_has_no_segment_cap() {
    // Over the old 512 segments: the loader and the protect loop have no count
    // limit, through the mock media provider and a scripted protect.
    static LONG_VIDEO: [TestPreparedRendition; 1] = [TestPreparedRendition {
        kind: DASH_VIDEO,
        mime_type: "video/mp4",
        codecs: "avc1.640028",
        segments: 600,
    }];
    let temp = tempfile::tempdir().unwrap();
    let (data_dir, staging_root) = setup_media_preparation_root(temp.path());
    let source = media_preparation_source_input(temp.path(), "person:local:dash-mint-long-source");
    let provider = Arc::new(TestMediaPreparationProvider {
        staging_root,
        requests: Mutex::new(Vec::new()),
        response: TestMediaPreparationResponse::Prepared(&LONG_VIDEO),
    });
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_runtime_provider_target(MEDIA_PROVIDER_ID, provider)
        .await
        .unwrap();
    let RuntimeLibraryMediaPreparation::Prepared(prepared) =
        prepare_runtime_custody_library_source(&data_dir, registry.as_ref(), &source)
            .await
            .expect("600 segments must prepare")
    else {
        panic!("expected a prepared media");
    };
    assert_eq!(prepared.input.media.renditions[0].segment_count, 600);

    // And the mint streams all 600 through the protect provider.
    let mut harness =
        library_mint_harness("person:local:dash-mint-long-protect", &[(DASH_VIDEO, 600)]).await;
    harness.input.media = prepared.input.media.clone();
    let (_, components, envelope) = harness.honest_protect();
    let mut script = media_dash_protect_script(TEST_PROTECT_HANDLE, &components, &envelope);
    script.push(closed_protect_response());
    let protect = harness.register_protect(script).await;
    harness.publish().await.expect("a long mint must publish");
    assert_eq!(protect.requests().await.len(), 600 + 3);
}

#[cfg(unix)]
#[tokio::test]
async fn media_dash_mint_refuses_a_protected_segment_over_the_cap_and_the_cap_fits_the_frame() {
    let cap = super::super::MAX_CENC_DASH_PROTECTED_SEGMENT_BYTES_V2;
    // Part one: a provider that answers a segment of cap + 1 bytes is refused
    // before anything of it is staged, and the session is settled.
    let harness = library_mint_harness(
        "person:local:dash-mint-over-cap",
        &[(DASH_VIDEO, 2), (DASH_AUDIO, 2)],
    )
    .await;
    let (intent, components, envelope) = harness.honest_protect();
    let mut script = media_dash_protect_script(TEST_PROTECT_HANDLE, &components, &envelope);
    script.truncate(1);
    script.push(Ok(ok_typed_protect_provider_response(
        ProtectProviderResponseV1::new_segment_protected(
            TEST_PROTECT_HANDLE,
            0,
            &vec![0xaa; cap + 1],
        )
        .unwrap(),
    )));
    script.push(cancelled_protect_response());
    let protect = harness.register_protect(script).await;
    let error = harness
        .publish()
        .await
        .expect_err("an over-cap segment must be refused");
    assert!(
        error
            .to_string()
            .contains("a prepared media part exceeds the 2 MiB part limit"),
        "{error}"
    );
    assert_refused_before_any_draft(&harness, &intent, &protect.requests().await);

    // Part two: the worst-case decrypt answer at the cap (4 characters per byte
    // in both the encrypted segment and the clear part, a full proof) fits the
    // provider frame, and the same answer at 2 MiB does not -- so the cap is
    // what keeps a read inside the frame.
    let audit = RuntimeReleaseAuditIdV1::new(digest(0x91)).unwrap();
    let handle = [0x41; MAX_PROVIDER_OPAQUE_HANDLE_BYTES_V1];
    let frame = |len: usize| {
        DecryptProviderResponseV1::new_viewer_media_part(
            audit,
            handle,
            ViewerMediaPartSelectorV1::segment_v2(
                1,
                7,
                vec![0xff; len],
                vec![Digest32::new([0xff; 32]); 32],
            )
            .unwrap(),
            vec![0xff; len],
        )
        .unwrap()
        .to_json_vec()
    };
    let at_cap = frame(cap).expect("the worst case at the cap must encode");
    assert!(
        at_cap.len() <= elastos_protected_content_provider_contracts::MAX_PROVIDER_FRAME_BYTES_V1
    );
    let over = frame(2 * 1024 * 1024);
    assert!(
        over.map_or(true, |bytes| {
            bytes.len() > elastos_protected_content_provider_contracts::MAX_PROVIDER_FRAME_BYTES_V1
        }),
        "the cap must be load-bearing"
    );
}

#[test]
fn dash_directory_check_accepts_the_package_and_refuses_every_deviation() {
    let components = media_dash_components(&[DASH_VIDEO], &[12]);
    let head = &components.head;
    let check = |directory: &Path| {
        super::super::verify_protected_content_dash_directory(directory, head, None)
    };
    let ok = stage_dash_package(&components, b"<MPD/>");
    check(ok.path()).expect("the staged package is accepted");

    // Segments 2 and 10 swapped: by path the roots differ.
    let swapped = stage_dash_package(&components, b"<MPD/>");
    let two = swapped.path().join(dash_segment_file(DASH_VIDEO, 1));
    let ten = swapped.path().join(dash_segment_file(DASH_VIDEO, 9));
    let (two_bytes, ten_bytes) = (fs::read(&two).unwrap(), fs::read(&ten).unwrap());
    fs::write(&two, ten_bytes).unwrap();
    fs::write(&ten, two_bytes).unwrap();
    assert!(check(swapped.path()).is_err(), "swapped segments");

    let extra = stage_dash_package(&components, b"<MPD/>");
    fs::write(extra.path().join("protected-content/v2/extra.bin"), b"x").unwrap();
    assert!(check(extra.path()).is_err(), "an extra file");

    let no_mpd = stage_dash_package(&components, b"<MPD/>");
    fs::remove_file(no_mpd.path().join(DASH_MPD_FILE)).unwrap();
    assert!(check(no_mpd.path()).is_err(), "no stream.mpd");

    let empty_mpd = stage_dash_package(&components, b"");
    assert!(check(empty_mpd.path()).is_err(), "an empty stream.mpd");

    let changed = stage_dash_package(&components, b"<MPD/>");
    let identity = changed.path().join(DASH_IDENTITY_FILE);
    let mut bytes = fs::read(&identity).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&identity, bytes).unwrap();
    assert!(check(changed.path()).is_err(), "a changed identity.bin");

    // A head whose roots match the files, but whose files are not media.
    let (fake_head, fake_inits, fake_segments) = fake_dash_package(&[DASH_VIDEO], &[3]);
    let broken = tempfile::tempdir().unwrap();
    for (path, bytes) in dash_package_files(&fake_head, &fake_inits, &fake_segments) {
        let target = broken.path().join(&path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, bytes).unwrap();
    }
    assert!(
        super::super::verify_protected_content_dash_directory(broken.path(), &fake_head, None)
            .is_err(),
        "a valid-hash package with a broken layout"
    );

    // The timelines the protection must have preserved.
    let (kinds, counts) = (vec![DASH_VIDEO], vec![12usize]);
    let session = ValidatedClearFmp4MediaSessionLayoutV1::new_with_profile(
        &media_dash_fixture::init(DASH_VIDEO, 1),
        elastos_protected_content_provider_contracts::CencLayoutProfile::V2,
    )
    .unwrap();
    let timelines: Vec<Vec<_>> = media_dash_fixture::clear_media_dash(&kinds, &counts)
        .iter()
        .map(|(_, _, segments)| {
            segments
                .iter()
                .map(|segment| {
                    session
                        .validate_segment(segment)
                        .unwrap()
                        .timeline()
                        .unwrap()
                })
                .collect()
        })
        .collect();
    super::super::verify_protected_content_dash_directory(ok.path(), head, Some(&timelines))
        .expect("the recorded timelines match");
    let mut wrong = timelines.clone();
    wrong[0][3].decode_time += 1;
    assert!(
        super::super::verify_protected_content_dash_directory(ok.path(), head, Some(&wrong))
            .is_err(),
        "a timeline that was not preserved"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn object_publish_streams_an_object_above_the_old_cap() {
    let fixture = object_mint_fixture("person:local:object-80mib", 80 * 1024 * 1024, None).await;
    let facts = publish_runtime_custody_library_object_content(
        &fixture.harness.data_dir,
        fixture.harness.registry.clone(),
        fixture.input.clone(),
    )
    .await
    .expect("an object above the old 64 MiB cap must publish");

    let ops = fixture.protect.ops.lock().await.clone();
    assert_eq!(
        ops.iter()
            .filter(|op| op.as_str() == "protect_object_chunk")
            .count(),
        80
    );
    assert!(fixture.max_framed_chunk <= MAX_OBJECT_FRAMED_CHUNK_BYTES_V1);
    let persisted = runtime_mint_journal(&fixture.harness.data_dir)
        .load(facts.mint_id)
        .unwrap();
    let Some(RuntimeContentIdentityV1::Object(identity)) =
        Some(persisted.draft().content_identity())
    else {
        panic!("the draft must carry an object identity");
    };
    assert_eq!(identity.chunk_count(), 80);
    assert_eq!(
        identity.encrypted_content(),
        fixture.sealed.encrypted_content_identity()
    );
    fixture.harness.assert_no_staging();
}

#[cfg(unix)]
#[tokio::test]
async fn object_protect_failure_leaves_no_staging() {
    let fixture = object_mint_fixture("person:local:object-fails", 5 * 1024 * 1024, Some(3)).await;
    assert!(publish_runtime_custody_library_object_content(
        &fixture.harness.data_dir,
        fixture.harness.registry.clone(),
        fixture.input.clone(),
    )
    .await
    .is_err());
    fixture.harness.assert_no_staging();
}

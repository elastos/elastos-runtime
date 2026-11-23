//! #388 A1: the host trust setting. Missing means everyday; anything invalid
//! refuses hosting; the value is captured once per process and changes only
//! at the next clean start.

use std::os::unix::fs::PermissionsExt as _;

use super::*;
use crate::protected_content_config::tests::{owner_only_dir, safe_ancestor_tempdir};

fn home() -> (tempfile::TempDir, PathBuf) {
    let dir = safe_ancestor_tempdir();
    let data_dir = dir.path().join("data");
    owner_only_dir(&data_dir);
    (dir, data_dir)
}

fn plant(data_dir: &Path, bytes: &[u8]) {
    crate::protected_content_runtime::write_owner_only_bytes(&host_trust_path(data_dir), bytes)
        .unwrap();
}

#[test]
fn missing_file_is_everyday() {
    let (_dir, data_dir) = home();
    assert_eq!(read_host_trust(&data_dir), HostTrustReadV1::Everyday);
    assert!(!host_trusted(&data_dir));
}

#[test]
fn invalid_or_unreadable_file_refuses_hosting() {
    let (_dir, data_dir) = home();
    for bytes in [
        &b"not json"[..],
        br#"{"schema":"elastos.protected-content.host-trust/v1","mode":"tee"}"#,
        br#"{"schema":"elastos.protected-content.host-trust/v2","mode":"wci_operated"}"#,
        br#"{"schema":"elastos.protected-content.host-trust/v1","mode":"wci_operated","extra":1}"#,
        br#"{"schema":"elastos.protected-content.host-trust/v1"}"#,
        br#"{"mode":"wci_operated"}"#,
    ] {
        plant(&data_dir, bytes);
        assert_eq!(
            read_host_trust(&data_dir),
            HostTrustReadV1::Refused,
            "{}",
            String::from_utf8_lossy(bytes)
        );
    }
    // Readable by others: refused, even with a valid body.
    plant(
        &data_dir,
        br#"{"schema":"elastos.protected-content.host-trust/v1","mode":"wci_operated"}"#,
    );
    assert_eq!(read_host_trust(&data_dir), HostTrustReadV1::WciOperated);
    std::fs::set_permissions(
        host_trust_path(&data_dir),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_eq!(read_host_trust(&data_dir), HostTrustReadV1::Refused);
    // A refused setting is never trusted.
    let (_other, other_dir) = home();
    plant(&other_dir, b"{}");
    assert!(!host_trusted(&other_dir));
}

#[test]
fn oversized_or_symlinked_file_refuses_hosting() {
    let (_dir, data_dir) = home();
    let mut big =
        br#"{"schema":"elastos.protected-content.host-trust/v1","mode":"wci_operated"}"#.to_vec();
    big.resize(MAX_HOST_TRUST_FILE_BYTES + 1, b' ');
    plant(&data_dir, &big);
    assert_eq!(read_host_trust(&data_dir), HostTrustReadV1::Refused);

    let (_dir, data_dir) = home();
    let target = data_dir.join("elsewhere.json");
    std::fs::write(
        &target,
        br#"{"schema":"elastos.protected-content.host-trust/v1","mode":"wci_operated"}"#,
    )
    .unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    let path = host_trust_path(&data_dir);
    crate::protected_content_config::ensure_owner_only_dir(
        path.parent().unwrap(),
        "protected-content root",
    )
    .unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert_eq!(read_host_trust(&data_dir), HostTrustReadV1::Refused);
}

#[test]
fn setup_flag_writes_the_file_atomically_owner_only() {
    let (_dir, data_dir) = home();
    crate::setup::choose_host_trust_mode(&data_dir, HostTrustModeV1::WciOperated, Some(1 << 30))
        .unwrap();
    let path = host_trust_path(&data_dir);
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let written: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        written,
        serde_json::json!({
            "schema": "elastos.protected-content.host-trust/v1",
            "mode": "wci_operated",
            "max_storage_bytes": 1u64 << 30,
        })
    );
    assert_eq!(read_host_trust(&data_dir), HostTrustReadV1::WciOperated);
    // Setting it back replaces the file whole; no temp file is left.
    crate::setup::choose_host_trust_mode(&data_dir, HostTrustModeV1::Everyday, None).unwrap();
    assert_eq!(read_host_trust(&data_dir), HostTrustReadV1::Everyday);
    let names = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(names, [HOST_TRUST_FILE]);
}

#[test]
fn setting_change_while_running_has_no_effect_until_restart() {
    let (_dir, data_dir) = home();
    assert!(!host_trusted(&data_dir), "captured as everyday");
    crate::setup::choose_host_trust_mode(&data_dir, HostTrustModeV1::WciOperated, Some(1 << 30))
        .unwrap();
    assert!(!host_trusted(&data_dir), "no live upgrade");
    restart_for_test(&data_dir);
    assert!(host_trusted(&data_dir), "the next clean start reads it");
    crate::setup::choose_host_trust_mode(&data_dir, HostTrustModeV1::Everyday, None).unwrap();
    assert!(host_trusted(&data_dir), "no live downgrade either");
    restart_for_test(&data_dir);
    assert!(!host_trusted(&data_dir));
}

/// The setting is an operator setup flag only: declared once as a
/// `Pending173` operator setting, and no route, capsule method, Carrier op
/// or Inbox action names it.
#[test]
fn setting_is_not_writable_by_capsules_routes_or_peers() {
    use crate::custody_surface::{Approval, SurfaceKind, CUSTODY_SURFACE};
    let rows = CUSTODY_SURFACE
        .iter()
        .filter(|item| item.id == crate::custody_surface::OPERATOR_SETTING_HOST_TRUST)
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind, SurfaceKind::OperatorSetting);
    assert_eq!(rows[0].approval, Approval::Pending173);
    assert_eq!(rows[0].stage, "pool-hosting");
    assert!(CUSTODY_SURFACE.iter().all(|item| {
        item.id == crate::custody_surface::OPERATOR_SETTING_HOST_TRUST
            || !item.id.contains("host_trust") && !item.id.contains("host-trust")
    }));
}

/// Plan B POOL-MINT: a WCI-operated host records its storage maximum; setup
/// refuses `wci-operated` without one, and a record without one reads as
/// unset (shares then fail closed).
#[test]
fn wci_operated_setup_requires_a_storage_maximum() {
    let (_dir, data_dir) = home();
    assert!(
        crate::setup::choose_host_trust_mode(&data_dir, HostTrustModeV1::WciOperated, None)
            .is_err()
    );
    assert!(
        crate::setup::choose_host_trust_mode(&data_dir, HostTrustModeV1::WciOperated, Some(0))
            .is_err()
    );
    assert_eq!(
        read_host_trust(&data_dir),
        HostTrustReadV1::Everyday,
        "nothing written"
    );
    crate::setup::choose_host_trust_mode(&data_dir, HostTrustModeV1::WciOperated, Some(4096))
        .unwrap();
    assert_eq!(host_storage_max_bytes(&data_dir), Some(4096));
    // A record written before the maximum existed reads as WCI-operated with
    // no maximum.
    write_host_trust(&data_dir, HostTrustModeV1::WciOperated, None).unwrap();
    assert_eq!(read_host_trust(&data_dir), HostTrustReadV1::WciOperated);
    assert_eq!(host_storage_max_bytes(&data_dir), None);
    crate::setup::choose_host_trust_mode(&data_dir, HostTrustModeV1::Everyday, Some(4096)).unwrap();
    assert_eq!(host_storage_max_bytes(&data_dir), None);
}

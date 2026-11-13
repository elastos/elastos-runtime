//! #388 A1: the host trust setting.
//!
//! Anything that touches a content key that is not this Home's own (custody
//! nodes, pool servers, remote sealers) runs only on a WCI-operated host. The
//! setting is an operator assertion, not TEE evidence:
//! `<data>/protected-content/host-trust.json`, owner-only, written only by
//! `elastos setup --host-trust`. No capsule, app, gateway route or Carrier
//! peer can write it.
//!
//! - A missing file means [`HostTrustReadV1::Everyday`].
//! - An invalid, oversized, symlinked, wrongly permissioned or unreadable
//!   file means [`HostTrustReadV1::Refused`]: hosting is refused, as on an
//!   everyday Home, with a `warn` log.
//! - A WCI-operated host also records its storage maximum (Plan B POOL-MINT,
//!   Anders #388): the most bytes of other parties' custody data it keeps,
//!   across every pool it serves. Setup refuses `wci-operated` without it,
//!   and a host whose record has none refuses pool shares
//!   ([`HOST_STORAGE_MAX_UNSET`]).
//! - The Runtime captures the value once per process for each data dir, at
//!   startup before any request is served ([`capture_at_startup`]), and
//!   keeps it: a change takes effect at the next clean start, so no session,
//!   seal or release in flight ever sees it change.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

pub(crate) const HOST_TRUST_FILE: &str = "host-trust.json";
pub(crate) const HOST_TRUST_SCHEMA_V1: &str = "elastos.protected-content.host-trust/v1";
pub(crate) const MAX_HOST_TRUST_FILE_BYTES: usize = 1024;
/// The refusal of a Hosting step on a host that is not WCI-operated.
pub(crate) const HOST_TRUST_REQUIRED: &str = "host_trust_required";
/// POOL-MINT: a WCI-operated host with no storage maximum refuses shares.
pub(crate) const HOST_STORAGE_MAX_UNSET: &str = "storage_max_unset";
/// POOL-MINT: a share that would take the host past its storage maximum.
pub(crate) const HOST_STORAGE_FULL: &str = "storage_full";

/// What the operator set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostTrustModeV1 {
    Everyday,
    WciOperated,
}

/// What the Runtime read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostTrustReadV1 {
    /// No file.
    Everyday,
    WciOperated,
    /// Invalid, oversized, symlinked, wrongly permissioned or unreadable.
    Refused,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostTrustFileV1 {
    schema: String,
    mode: HostTrustModeV1,
    /// POOL-MINT: the host's storage maximum in bytes, set by its operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_storage_bytes: Option<u64>,
}

pub(crate) fn host_trust_path(data_dir: &Path) -> PathBuf {
    crate::protected_content_runtime::protected_content_root(data_dir).join(HOST_TRUST_FILE)
}

/// Reads the setting: bounded, owner-only regular file, strict parse.
pub(crate) fn read_host_trust(data_dir: &Path) -> HostTrustReadV1 {
    read_host_trust_file(data_dir).0
}

/// POOL-MINT: the storage maximum the operator set for this WCI-operated
/// host, read from the same record; `None` when it is unset, the host is not
/// WCI-operated, or the record is refused.
pub(crate) fn host_storage_max_bytes(data_dir: &Path) -> Option<u64> {
    match read_host_trust_file(data_dir) {
        (HostTrustReadV1::WciOperated, max) => max,
        _ => None,
    }
}

fn read_host_trust_file(data_dir: &Path) -> (HostTrustReadV1, Option<u64>) {
    let path = host_trust_path(data_dir);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (HostTrustReadV1::Everyday, None);
        }
        Err(error) => {
            tracing::warn!(%error, "host trust setting is unreadable; hosting is refused");
            return (HostTrustReadV1::Refused, None);
        }
        Ok(_) => {}
    }
    let read = crate::collaboration_config::read_owner_only_file(
        &path,
        MAX_HOST_TRUST_FILE_BYTES,
        "host trust setting",
    )
    .and_then(|bytes| Ok(serde_json::from_slice::<HostTrustFileV1>(&bytes)?));
    match read {
        Ok(file) if file.schema == HOST_TRUST_SCHEMA_V1 => match file.mode {
            HostTrustModeV1::Everyday => (HostTrustReadV1::Everyday, None),
            HostTrustModeV1::WciOperated => (HostTrustReadV1::WciOperated, file.max_storage_bytes),
        },
        Ok(_) => {
            tracing::warn!("host trust setting has an unknown schema; hosting is refused");
            (HostTrustReadV1::Refused, None)
        }
        Err(error) => {
            tracing::warn!(
                error = %format!("{error:#}"),
                "host trust setting is invalid; hosting is refused"
            );
            (HostTrustReadV1::Refused, None)
        }
    }
}

/// Writes the setting atomically and owner-only. Only the operator's local
/// `elastos setup --host-trust` reaches it (through `setup`).
pub(crate) fn write_host_trust(
    data_dir: &Path,
    mode: HostTrustModeV1,
    max_storage_bytes: Option<u64>,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(&HostTrustFileV1 {
        schema: HOST_TRUST_SCHEMA_V1.to_string(),
        mode,
        max_storage_bytes,
    })?;
    let root = crate::protected_content_runtime::protected_content_root(data_dir);
    crate::protected_content_config::ensure_owner_only_dir(&root, "protected-content root")?;
    crate::auth::atomic_write(&host_trust_path(data_dir), &bytes)
}

fn captured() -> &'static Mutex<HashMap<PathBuf, bool>> {
    static CAPTURED: OnceLock<Mutex<HashMap<PathBuf, bool>>> = OnceLock::new();
    CAPTURED.get_or_init(Default::default)
}

/// Whether this host may take another party's key roles: the setting as it
/// was first read in this process for `data_dir`, and never re-read while
/// running (restart-only activation).
pub(crate) fn host_trusted(data_dir: &Path) -> bool {
    let mut captured = captured()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *captured.entry(data_dir.to_path_buf()).or_insert_with(|| {
        let trusted = read_host_trust(data_dir) == HostTrustReadV1::WciOperated;
        tracing::debug!(trusted, "host trust setting captured");
        trusted
    })
}

/// Captures the setting for this Home's `data_dir` at startup, before any
/// request is served, whether or not a custody provider registers
/// (A388-I1). Later reads return this value until the next clean start.
pub fn capture_at_startup(data_dir: &Path) {
    host_trusted(data_dir);
}

/// Test-only: as if this process had started with `trusted` captured.
#[cfg(test)]
pub(crate) fn seed_for_test(data_dir: &Path, trusted: bool) {
    captured()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(data_dir.to_path_buf(), trusted);
}

/// Test-only: a WCI-operated host as `elastos setup --host-trust wci-operated
/// --max-storage-bytes` leaves it (POOL-MINT: a maximum is set), with the
/// setting captured at start.
#[cfg(all(test, unix))]
pub(crate) fn seed_wci_host_for_test(data_dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let root = crate::protected_content_runtime::protected_content_root(data_dir);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    write_host_trust(data_dir, HostTrustModeV1::WciOperated, Some(1 << 40)).unwrap();
    seed_for_test(data_dir, true);
}

/// Test-only: a clean start, so the next read captures the file again.
#[cfg(test)]
pub(crate) fn restart_for_test(data_dir: &Path) {
    captured()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(data_dir);
}

#[cfg(all(test, unix))]
mod tests;

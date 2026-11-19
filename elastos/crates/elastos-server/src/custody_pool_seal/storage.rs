//! Shared host storage charges for a remote seal's spool and private import.

use std::fs::{self, File};
use std::io::{ErrorKind, Read as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::protected_content_runtime::{
    host_storage_refusal, lock_host_share_writes, protected_content_root,
    validate_owner_only_directory, write_owner_only_bytes,
};

const STORAGE_DIR: &str = "remote-seal-storage";
const STAGING_CHARGE: &str = "staging-bytes";
const IMPORT_CHARGE: &str = "import-bytes";
const IMPORT_SETTLED: &str = "import-settled";
const SPOOL: &str = "publish-payload";
const STORAGE_UNAVAILABLE: &str = "host_storage_unavailable";

/// The last user removes the staging charge only after the spool is gone.
/// The import charge is durable because Kubo can write blocks before an
/// error or a lost reply. It remains part of the host's storage total.
pub(crate) struct RemoteSealStorage {
    root: PathBuf,
    spool: PathBuf,
    staging_bytes: u64,
}

impl RemoteSealStorage {
    pub(crate) async fn reserve(
        data_dir: &Path,
        staging_bytes: u64,
    ) -> Result<Arc<Self>, &'static str> {
        let _guard = lock_host_share_writes().await;
        admit(data_dir, staging_bytes)?;
        let parent = storage_root(data_dir);
        let protected = protected_content_root(data_dir);
        crate::protected_content_config::ensure_owner_only_dir(
            &protected,
            "protected content root",
        )
        .map_err(|_| STORAGE_UNAVAILABLE)?;
        crate::protected_content_config::ensure_owner_only_dir(&parent, "remote seal storage")
            .map_err(|_| STORAGE_UNAVAILABLE)?;
        let mut builder = tempfile::Builder::new();
        builder.prefix("seal-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            builder.permissions(fs::Permissions::from_mode(0o700));
        }
        let directory = builder.tempdir_in(&parent).map_err(storage_unavailable)?;
        crate::protected_content_config::ensure_owner_only_dir(
            &directory.path().join(SPOOL),
            "remote seal spool",
        )
        .map_err(storage_unavailable)?;
        write_owner_only_bytes(
            &directory.path().join(STAGING_CHARGE),
            staging_bytes.to_string().as_bytes(),
        )
        .map_err(storage_unavailable)?;
        #[cfg(unix)]
        for dir in [&parent, &protected, data_dir] {
            File::open(dir)
                .and_then(|file| file.sync_all())
                .map_err(storage_unavailable)?;
        }
        let root = directory.keep();
        let spool = root.join(SPOOL);
        Ok(Arc::new(Self {
            root,
            spool,
            staging_bytes,
        }))
    }

    pub(crate) fn directory(&self) -> &Path {
        &self.spool
    }

    pub(super) fn staging_bytes(&self) -> u64 {
        self.staging_bytes
    }
}

fn storage_unavailable(error: impl std::fmt::Display) -> &'static str {
    tracing::warn!(%error, "remote seal storage reservation failed");
    STORAGE_UNAVAILABLE
}

/// Charge the exact package bytes before Content sends the immutable spool to
/// private IPFS. A retry of the same package uses the existing charge.
pub(crate) async fn reserve_spool_import(
    data_dir: &Path,
    spool: &Path,
    bytes: u64,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        is_remote_seal_spool(data_dir, spool),
        "invalid remote seal spool"
    );
    let root = spool
        .parent()
        .expect("remote seal spool has a charge directory");
    let _guard = lock_host_share_writes().await;
    let staging = read_charge(&root.join(STAGING_CHARGE))?
        .ok_or_else(|| anyhow::anyhow!("remote seal staging charge unavailable"))?;
    anyhow::ensure!(
        bytes <= staging,
        "remote seal staging exceeds its reservation"
    );
    let path = root.join(IMPORT_CHARGE);
    if let Some(held) = read_charge(&path)? {
        anyhow::ensure!(held == bytes, "remote seal import charge changed");
        // Content is about to issue the exact import again. A reply from the
        // earlier attempt does not settle this new use of the spool.
        match fs::remove_file(root.join(IMPORT_SETTLED)) {
            Ok(()) => {
                #[cfg(unix)]
                File::open(root)?.sync_all()?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        return Ok(());
    }
    admit(data_dir, bytes).map_err(anyhow::Error::msg)?;
    write_owner_only_bytes(&path, bytes.to_string().as_bytes())
}

/// Record that the backend returned from the exact import. An uncertain
/// import can still have the spool open, so a lost response retains both
/// charges until the effect can be reconciled.
pub(crate) fn settle_spool_import(data_dir: &Path, spool: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        is_remote_seal_spool(data_dir, spool),
        "invalid remote seal spool"
    );
    let root = spool
        .parent()
        .expect("remote seal spool has a charge directory");
    write_owner_only_bytes(&root.join(IMPORT_SETTLED), b"1")
}

impl Drop for RemoteSealStorage {
    fn drop(&mut self) {
        let import = read_charge(&self.root.join(IMPORT_CHARGE));
        let settled = read_charge(&self.root.join(IMPORT_SETTLED));
        match (import, settled) {
            (Ok(None), Ok(None)) | (Ok(Some(_)), Ok(Some(1))) => {}
            _ => return,
        }
        match fs::remove_dir_all(self.directory()) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(%error, "remote seal staging remains charged after cleanup failed");
                return;
            }
        }
        // Keep the parent even on successful cleanup when an import was
        // dispatched. Never unlink a durable charge for uncertain effects.
        if fs::remove_file(self.root.join(STAGING_CHARGE)).is_ok() {
            let _ = fs::remove_dir(&self.root);
        }
    }
}

pub(super) fn staging_reservation(
    layout: &elastos_protected_content_contracts::ClearLayoutV1,
) -> anyhow::Result<u64> {
    use elastos_protected_content_contracts::ClearLayoutV1;
    use elastos_protected_content_provider_contracts::{
        MAX_OBJECT_FRAMED_CHUNK_BYTES_V1, MAX_OBJECT_FRAMED_HEADER_BYTES_V1,
        MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1, MAX_PROTECT_MEDIA_PART_BYTES_V1,
    };

    let encrypted = match layout {
        ClearLayoutV1::Object { length, .. } => {
            let overhead = MAX_OBJECT_FRAMED_CHUNK_BYTES_V1 - MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1;
            length
                + length.div_ceil(MAX_OBJECT_PLAINTEXT_CHUNK_BYTES_V1 as u64) * overhead as u64
                + MAX_OBJECT_FRAMED_HEADER_BYTES_V1 as u64
        }
        ClearLayoutV1::DashV2 { .. } => {
            // The two extra files are the rebuilt MPD and the identity.
            (layout.parts()?.len() as u64 + 2) * MAX_PROTECT_MEDIA_PART_BYTES_V1 as u64
        }
    };
    Ok(encrypted + crate::content::MAX_LOCAL_OBJECT_MANIFEST_BYTES)
}

fn admit(data_dir: &Path, bytes: u64) -> Result<(), &'static str> {
    match host_storage_refusal(data_dir, bytes) {
        None => Ok(()),
        Some(refusal) => Err(match refusal["code"].as_str() {
            Some(crate::host_trust::HOST_STORAGE_MAX_UNSET) => {
                crate::host_trust::HOST_STORAGE_MAX_UNSET
            }
            Some(crate::host_trust::HOST_STORAGE_FULL) => crate::host_trust::HOST_STORAGE_FULL,
            _ => STORAGE_UNAVAILABLE,
        }),
    }
}

fn storage_root(data_dir: &Path) -> PathBuf {
    protected_content_root(data_dir).join(STORAGE_DIR)
}

pub(crate) fn is_remote_seal_spool(data_dir: &Path, path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == SPOOL)
        && path.parent().is_some_and(|parent| {
            parent.parent() == Some(storage_root(data_dir).as_path())
                && parent
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("seal-"))
        })
}

pub(crate) fn host_remote_seal_storage_bytes(data_dir: &Path) -> anyhow::Result<u64> {
    let root = storage_root(data_dir);
    match fs::symlink_metadata(&root) {
        Ok(_) => validate_owner_only_directory(&root, "remote seal storage")?,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    }
    let mut total = 0_u64;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        anyhow::ensure!(
            entry.file_type()?.is_dir(),
            "invalid remote seal storage entry"
        );
        for charge in [STAGING_CHARGE, IMPORT_CHARGE] {
            total = total.saturating_add(read_charge(&entry.path().join(charge))?.unwrap_or(0));
        }
    }
    Ok(total)
}

fn read_charge(path: &Path) -> anyhow::Result<Option<u64>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "invalid remote seal storage charge"
    );
    let mut bytes = String::new();
    file.take(21).read_to_string(&mut bytes)?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= 20 && bytes.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid remote seal storage charge"
    );
    Ok(Some(bytes.parse()?))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::protected_content_runtime::{guarded_host_share_write, host_custody_storage_bytes};
    use serde_json::json;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn an_inflight_spool_stays_charged_after_the_session_handle_is_released() {
        let home = tempfile::tempdir().unwrap();
        let data_dir = home.path().to_path_buf();
        crate::host_trust::write_host_trust(
            &data_dir,
            crate::host_trust::HostTrustModeV1::WciOperated,
            Some(100),
        )
        .unwrap();
        let storage = RemoteSealStorage::reserve(&data_dir, 100).await.unwrap();
        let path = storage.directory().to_path_buf();
        let inflight = Arc::clone(&storage);
        let (resume, wait) = oneshot::channel();
        let writing = tokio::spawn(async move {
            wait.await.unwrap();
            fs::write(inflight.directory().join("part"), [0; 100]).unwrap();
        });

        // The service map releases an expired session, but the pending part
        // owns the same spool while it can still write.
        drop(storage);
        assert!(path.is_dir());
        let denied = guarded_host_share_write(
            data_dir.clone(),
            1,
            || false,
            || async { Ok(json!({"status": "ok"})) },
        )
        .await
        .unwrap();
        assert_eq!(denied["code"], crate::host_trust::HOST_STORAGE_FULL);
        assert_eq!(host_custody_storage_bytes(&data_dir).unwrap(), 100);

        resume.send(()).unwrap();
        writing.await.unwrap();
        assert!(!path.exists());
        assert_eq!(host_custody_storage_bytes(&data_dir).unwrap(), 0);
    }

    #[tokio::test]
    async fn an_uncertain_import_remains_charged_without_double_charging_a_retry() {
        let home = tempfile::tempdir().unwrap();
        let data_dir = home.path();
        crate::host_trust::write_host_trust(
            data_dir,
            crate::host_trust::HostTrustModeV1::WciOperated,
            Some(100),
        )
        .unwrap();
        let storage = RemoteSealStorage::reserve(data_dir, 60).await.unwrap();
        let spool = storage.directory().to_path_buf();
        assert!(reserve_spool_import(data_dir, &spool, 41).await.is_err());
        reserve_spool_import(data_dir, &spool, 40).await.unwrap();
        settle_spool_import(data_dir, &spool).unwrap();
        reserve_spool_import(data_dir, &spool, 40).await.unwrap();
        assert!(reserve_spool_import(data_dir, &spool, 39).await.is_err());
        assert_eq!(host_custody_storage_bytes(data_dir).unwrap(), 100);
        drop(storage);
        assert!(spool.exists());
        assert_eq!(host_custody_storage_bytes(data_dir).unwrap(), 100);
        assert!(host_storage_refusal(data_dir, 1).is_some());
    }
}

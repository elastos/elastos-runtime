//! Publication of a mint's metadata to the public IPFS store (META-PUBLIC §7).
//!
//! The creator tail calls this only before it would raise a new or reissued
//! mint approval (§7.0). An existing approval settles without it.
//!
//! The roots come from the mint journal alone: the bound metadata folder, plus
//! the cover its `metadata.json` names in `image` when that is not empty
//! (§7.1). Each root is exported from the private store as a CAR, validated in
//! the Runtime before the public store sees a byte of it (§7.2), imported,
//! pinned and announced with an awaited provide (§7.3). Nothing is persisted:
//! every new-authority attempt runs every phase again, and each op is
//! idempotent.
//!
//! Every phase op starts with `phase_allowed` (consent enabled, no withdrawal
//! marker), holds no state lock, and awaits the provider's own bounded answer.
//! A withdrawal that stops the store mid-phase fails the op in flight, so no
//! approval follows it.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use elastos_runtime::provider::ProviderRegistry;
use serde_json::{json, Value};

use crate::public_ipfs_store::{PublicIpfsStore, StoreLiveness};
use crate::public_metadata_car::{validate_public_metadata_car, PublicRootKind, ValidatedCar};
use crate::public_metadata_consent::{phase_allowed, PublicMetadataError, PublicMetadataErrorCode};

/// The CAR cap per root. A cover is at most 2 MiB, and a metadata folder is a
/// few KB of JSON, so both fit with room for the CAR framing.
pub(crate) const PUBLIC_METADATA_CAR_MAX_BYTES: usize = 4 * 1024 * 1024;
/// The private store's whole answer to one export, or to the `metadata.json`
/// read.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the readiness phase waits for the store's single status slot.
const STATUS_BUDGET: Duration = Duration::from_secs(5);
const STATUS_RETRY: Duration = Duration::from_millis(50);
const METADATA_FILE: &str = "metadata.json";

/// The roots one mint publishes: its metadata folder and, when it has one,
/// its cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublishRoots {
    pub folder: String,
    pub cover: Option<String>,
}

impl PublishRoots {
    fn each(&self) -> impl Iterator<Item = (&str, PublicRootKind)> {
        std::iter::once((self.folder.as_str(), PublicRootKind::Folder)).chain(
            self.cover
                .as_deref()
                .map(|cover| (cover, PublicRootKind::File)),
        )
    }
}

/// The roots of the folder `metadata_cid`, given its `metadata.json`. `image`
/// is `""` for a mint without a cover, and otherwise exactly `ipfs://<cid>`
/// with the CID in its canonical text. Anything else is refused: the Runtime
/// writes no other form, so nothing else may choose what is published.
pub(crate) fn public_metadata_roots(
    metadata_cid: &str,
    metadata_json: &[u8],
) -> anyhow::Result<PublishRoots> {
    let document: Value =
        serde_json::from_slice(metadata_json).context("metadata.json is not JSON")?;
    let image = document
        .get("image")
        .and_then(Value::as_str)
        .context("metadata.json names no image")?;
    let cover = match image {
        "" => None,
        image => {
            let cid = image
                .strip_prefix("ipfs://")
                .context("the metadata.json image is not an ipfs:// CID")?;
            let parsed = cid::Cid::try_from(cid)
                .map_err(|_| anyhow::anyhow!("the metadata.json image is not a CID"))?;
            anyhow::ensure!(
                parsed.to_string() == cid,
                "the metadata.json image is not a canonical CID"
            );
            Some(cid.to_string())
        }
    };
    Ok(PublishRoots {
        folder: metadata_cid.to_string(),
        cover,
    })
}

/// The creator tail's new-authority step: read the bound folder's
/// `metadata.json` from the private store, take the roots from it, and
/// publish them. Admission comes first, so a Home that has not consented is
/// told that rather than anything about its private store.
pub(crate) async fn publish_mint_public_metadata(
    registry: &Arc<ProviderRegistry>,
    data_dir: &Path,
    metadata_cid: &str,
) -> Result<(), PublicMetadataError> {
    #[cfg(test)]
    if test_seams::stood_in(data_dir) {
        return Ok(());
    }
    phase_allowed(data_dir)?;
    let unreadable = |reason: String| {
        PublicMetadataError::new(
            PublicMetadataErrorCode::ExportFailed,
            format!("the private store did not give the metadata.json of {metadata_cid}: {reason}"),
        )
    };
    let read = crate::content::fetch_verified_local_bytes_via_provider(
        registry,
        metadata_cid,
        Some(METADATA_FILE),
        PUBLIC_METADATA_CAR_MAX_BYTES,
    );
    let metadata_json = match tokio::time::timeout(EXPORT_TIMEOUT, read).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(error)) => return Err(unreadable(format!("{error:#}"))),
        Err(_) => return Err(unreadable("timed out".to_string())),
    };
    let roots = public_metadata_roots(metadata_cid, &metadata_json).map_err(|error| {
        PublicMetadataError::new(PublicMetadataErrorCode::InvalidCar, format!("{error:#}"))
    })?;
    publish_public_metadata(registry, data_dir, &roots).await
}

/// The approval phase's admission: consent enabled and no withdrawal marker,
/// checked without the state lock right before a new approval is raised.
pub(crate) fn approval_phase_allowed(data_dir: &Path) -> Result<(), PublicMetadataError> {
    #[cfg(test)]
    if test_seams::stood_in(data_dir) {
        return Ok(());
    }
    phase_allowed(data_dir)
}

/// Publish `roots` to the public store: readiness, then per root export and
/// validate, import, pin and an awaited provide. The first failure ends it.
pub(crate) async fn publish_public_metadata(
    registry: &Arc<ProviderRegistry>,
    data_dir: &Path,
    roots: &PublishRoots,
) -> Result<(), PublicMetadataError> {
    tracing::debug!(
        folder = %roots.folder,
        cover = roots.cover.as_deref().unwrap_or(""),
        "public metadata publication began"
    );
    // 1. Readiness.
    phase_allowed(data_dir)?;
    require_ready(registry).await?;
    // 2. Export from the private store and validate, before any import.
    let mut cars: Vec<(&str, ValidatedCar)> = Vec::new();
    for (root, kind) in roots.each() {
        phase_allowed(data_dir)?;
        let bytes = export_car(registry, root).await?;
        let car = validate_public_metadata_car(&bytes, root, kind, PUBLIC_METADATA_CAR_MAX_BYTES)
            .map_err(|refusal| {
            PublicMetadataError::new(
                PublicMetadataErrorCode::InvalidCar,
                format!("the CAR of {root} was refused: {refusal:?}"),
            )
        })?;
        tracing::trace!(%root, blocks = car.blocks, "public metadata CAR validated");
        cars.push((root, car));
    }
    // 3. Import.
    for (root, car) in &cars {
        phase_allowed(data_dir)?;
        PublicIpfsStore::import_car(registry, root, &car.bytes).await?;
    }
    // 4. Pin.
    for (root, _) in &cars {
        phase_allowed(data_dir)?;
        PublicIpfsStore::pin(registry, root).await?;
    }
    // 5. Provide, awaited.
    for (root, _) in &cars {
        phase_allowed(data_dir)?;
        PublicIpfsStore::provide(registry, root).await?;
    }
    tracing::debug!(roots = cars.len(), "public metadata published");
    Ok(())
}

/// Running with at least one peer. A busy status slot is asked again within
/// the budget; a store whose status stays unknown is not ready.
async fn require_ready(registry: &Arc<ProviderRegistry>) -> Result<(), PublicMetadataError> {
    let deadline = tokio::time::Instant::now() + STATUS_BUDGET;
    loop {
        let status = PublicIpfsStore::status(registry).await;
        match status.liveness {
            StoreLiveness::Running if status.ready => return Ok(()),
            StoreLiveness::Running => {
                return Err(PublicMetadataError::not_ready(
                    "the public IPFS store has no peers yet",
                ))
            }
            StoreLiveness::Down => {
                return Err(PublicMetadataError::not_ready(
                    "the public IPFS store is not running",
                ))
            }
            StoreLiveness::Unknown if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(STATUS_RETRY).await;
            }
            StoreLiveness::Unknown => {
                return Err(PublicMetadataError::not_ready(
                    "the public IPFS store did not report its status",
                ))
            }
        }
    }
}

/// One root from the private store, through the typed registry method that
/// reaches only the exact `ipfs` sub-provider.
async fn export_car(
    registry: &ProviderRegistry,
    root: &str,
) -> Result<Vec<u8>, PublicMetadataError> {
    let failed =
        |detail: String| PublicMetadataError::new(PublicMetadataErrorCode::ExportFailed, detail);
    match tokio::time::timeout(
        EXPORT_TIMEOUT,
        registry.send_local_ipfs_export_car(root, PUBLIC_METADATA_CAR_MAX_BYTES as u64),
    )
    .await
    {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(error)) => Err(failed(format!(
            "the private store did not export {root}: {error}"
        ))),
        Err(_) => Err(failed(format!(
            "the private store did not export {root} in time"
        ))),
    }
}

/// A public metadata failure as the creator tail answers it: the typed error
/// and the mint's progress, with the `public_metadata` stage failed.
#[derive(Debug)]
pub(crate) struct PublicMetadataFailure {
    error: PublicMetadataError,
    progress: Value,
}

impl PublicMetadataFailure {
    pub(crate) fn new(error: PublicMetadataError, progress: Value) -> Self {
        Self { error, progress }
    }

    /// The `public_metadata` field of the error envelope.
    pub(crate) fn as_json(&self) -> Value {
        json!({
            "code": self.error.code().as_str(),
            "detail": self.error.detail(),
            "progress": self.progress,
        })
    }
}

impl std::fmt::Display for PublicMetadataFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, f)
    }
}

impl std::error::Error for PublicMetadataFailure {}

#[cfg(test)]
pub(crate) mod test_seams {
    //! The legacy creator-tail fixtures run over a mock private store that
    //! answers every publish with one fixed CID, so no CAR can be exported for
    //! it. Their data dirs stand in the public metadata step: publication and
    //! the approval admission pass. The `public_` tests clear the stand-in
    //! and run the real step against fake `ipfs` and `public-ipfs` providers.

    use std::collections::HashSet;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};

    fn table() -> &'static Mutex<HashSet<PathBuf>> {
        static STOOD_IN: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
        STOOD_IN.get_or_init(Default::default)
    }

    pub(crate) fn stand_in(data_dir: &Path) {
        table()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(data_dir.to_path_buf());
    }

    pub(crate) fn publish_for_real(data_dir: &Path) {
        table()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(data_dir);
    }

    pub(super) fn stood_in(data_dir: &Path) -> bool {
        table()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(data_dir)
    }
}

#[cfg(test)]
pub(crate) mod tests;

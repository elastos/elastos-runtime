//! The Home admin's consent to publish minted assets' metadata on the public
//! IPFS network, the withdrawal marker, and the one cross-process lock that
//! serialises the public store's state changes.
//!
//! Files, all owner-only, under `<data_dir>/public-ipfs/`:
//! - `consent.json`: the [`ConsentRecord`]. It counts as enabled only while
//!   its wording version and SHA-256 equal the current [`CONSENT_WORDING`],
//!   so a reworded release asks again.
//! - `withdraw-requested`: the [`WithdrawalMarker`]. Stop creates it at once,
//!   without the lock; only the withdrawal completion removes it, after the
//!   store is down. While it exists every publication phase is disabled and
//!   enabling is refused.
//! - `state.lock`: the [`PublicStateGuard`] flock, held by enable, the
//!   withdrawal completion and the supervisor tick. Acquisition polls a
//!   non-blocking lock on a blocking-pool thread, so no Tokio worker waits.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Bump with every change to [`CONSENT_WORDING`].
pub(crate) const CONSENT_WORDING_VERSION: u32 = 1;

/// The exact text the admin agrees to (META-PUBLIC design §6, approved by the
/// user 2026-11-10): a title line, one paragraph and four `- ` bullet lines.
pub(crate) const CONSENT_WORDING: &str = "Publish your assets' metadata on IPFS\n\
To list what you mint, your Home runs a public IPFS node. It holds and shares only the metadata \
and cover of the assets you mint: title, description, cover, price, terms and your wallet address. \
It never holds the asset itself, which stays encrypted on your Home.\n\
- Metadata is published just before you approve each mint, so it stays public even if you don't \
finish the mint.\n\
- The public IPFS network records that your Home shares these files, along with your Home's \
network address.\n\
- Anyone may keep copies. Stopping later ends your Home's sharing; it cannot recall what was \
already published.\n\
- The node uses some bandwidth while your Home is on.";

/// The passkey step-up operation that enables the public store.
pub(crate) const ENABLE_OPERATION: &str = "creator.public_ipfs.enable";

/// The ordinary wait for [`acquire_public_state_lock`].
pub(crate) const STATE_LOCK_BUDGET: Duration = Duration::from_secs(10);
/// The withdrawal completion's wait, past one bounded start or stop.
pub(crate) const WITHDRAWAL_LOCK_BUDGET: Duration = Duration::from_secs(120);

const PUBLIC_IPFS_DIR: &str = "public-ipfs";
const CONSENT_FILE: &str = "consent.json";
const WITHDRAWAL_MARKER_FILE: &str = "withdraw-requested";
const STATE_LOCK_FILE: &str = "state.lock";
const MAX_RECORD_BYTES: usize = 4096;
const MAX_STOP_PENDING_CHARS: usize = 512;
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// The failure codes of the public metadata path. The creator tail projects
/// them under the error key `public_metadata`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicMetadataErrorCode {
    Disabled,
    NotReady,
    ExportFailed,
    InvalidCar,
    ImportFailed,
    PinFailed,
    AnnounceFailed,
}

impl PublicMetadataErrorCode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::NotReady => "not_ready",
            Self::ExportFailed => "export_failed",
            Self::InvalidCar => "invalid_car",
            Self::ImportFailed => "import_failed",
            Self::PinFailed => "pin_failed",
            Self::AnnounceFailed => "announce_failed",
        }
    }
}

/// A typed public metadata failure with the Runtime's reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicMetadataError {
    code: PublicMetadataErrorCode,
    detail: String,
}

impl PublicMetadataError {
    pub(crate) fn new(code: PublicMetadataErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub(crate) fn disabled(detail: impl Into<String>) -> Self {
        Self::new(PublicMetadataErrorCode::Disabled, detail)
    }

    pub(crate) fn not_ready(detail: impl Into<String>) -> Self {
        Self::new(PublicMetadataErrorCode::NotReady, detail)
    }

    pub(crate) fn code(&self) -> PublicMetadataErrorCode {
        self.code
    }

    pub(crate) fn detail(&self) -> &str {
        &self.detail
    }
}

impl std::fmt::Display for PublicMetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "public metadata {}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for PublicMetadataError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ConsentState {
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsentRecord {
    pub state: ConsentState,
    pub principal: String,
    pub wording_version: u32,
    pub wording_sha256: String,
    pub changed_at: u64,
    /// 128 random bits in hex, fresh on every write, so admission can tell
    /// two writes apart even when every other field is equal. A record
    /// without one reads as not enabled.
    #[serde(default)]
    pub generation: String,
}

impl ConsentRecord {
    /// Enabled, for the current wording version and SHA-256, with a write
    /// generation.
    pub(crate) fn is_current_enabled(&self) -> bool {
        self.state == ConsentState::Enabled
            && self.wording_version == CONSENT_WORDING_VERSION
            && self.wording_sha256 == consent_wording_sha256()
            && is_generation(&self.generation)
    }
}

const GENERATION_BYTES: usize = 16;

fn is_generation(value: &str) -> bool {
    value.len() == GENERATION_BYTES * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A requested withdrawal. `stop_pending` is the last reason the store could
/// not yet be confirmed down; the completion keeps retrying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WithdrawalMarker {
    pub withdrawal_id: String,
    pub principal: String,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_pending: Option<String>,
}

/// Holds the exclusive flock on `public-ipfs/state.lock`; dropping it
/// releases the lock.
#[derive(Debug)]
pub(crate) struct PublicStateGuard {
    file: std::fs::File,
}

impl Drop for PublicStateGuard {
    fn drop(&mut self) {
        // A child spawned meanwhile may keep this description until its
        // CLOEXEC fd closes at exec, so unlock before closing ours.
        let _ = self.file.unlock();
    }
}

pub(crate) fn consent_wording_sha256() -> String {
    hex::encode(Sha256::digest(CONSENT_WORDING.as_bytes()))
}

/// The exact step-up request of Enable, rebuilt on the server from its own
/// wording, so a capsule cannot supply or alter it.
pub(crate) fn enable_step_up_request() -> serde_json::Value {
    serde_json::json!({
        "wording_version": CONSENT_WORDING_VERSION,
        "wording_sha256": consent_wording_sha256(),
    })
}

fn public_ipfs_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(PUBLIC_IPFS_DIR)
}

fn consent_path(data_dir: &Path) -> PathBuf {
    public_ipfs_dir(data_dir).join(CONSENT_FILE)
}

fn withdrawal_marker_path(data_dir: &Path) -> PathBuf {
    public_ipfs_dir(data_dir).join(WITHDRAWAL_MARKER_FILE)
}

fn state_lock_path(data_dir: &Path) -> PathBuf {
    public_ipfs_dir(data_dir).join(STATE_LOCK_FILE)
}

fn now_secs() -> u64 {
    #[cfg(test)]
    if let Some(now) = test_seams::fixed_now() {
        return now;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

pub(crate) fn read_consent(data_dir: &Path) -> anyhow::Result<Option<ConsentRecord>> {
    read_owner_only_json(&consent_path(data_dir), "public IPFS consent record")
}

/// Enabled, for the current wording version and SHA-256.
pub(crate) fn consent_enabled(data_dir: &Path) -> anyhow::Result<bool> {
    Ok(read_consent(data_dir)?.is_some_and(|record| record.is_current_enabled()))
}

/// Record the admin's choice for the current wording. The guard proves the
/// caller serialised this with the store's start or stop.
pub(crate) fn write_consent(
    data_dir: &Path,
    state: ConsentState,
    principal: &str,
    _guard: &PublicStateGuard,
) -> anyhow::Result<ConsentRecord> {
    let record = ConsentRecord {
        state,
        principal: principal.to_string(),
        wording_version: CONSENT_WORDING_VERSION,
        wording_sha256: consent_wording_sha256(),
        changed_at: now_secs(),
        generation: {
            let mut bytes = [0u8; GENERATION_BYTES];
            rand::thread_rng().fill_bytes(&mut bytes);
            hex::encode(bytes)
        },
    };
    crate::protected_content_runtime::write_owner_only_bytes(
        &consent_path(data_dir),
        &serde_json::to_vec_pretty(&record)?,
    )?;
    tracing::debug!(state = ?record.state, "public IPFS consent recorded");
    Ok(record)
}

/// Take the public store's state lock within `budget`, or `not_ready`. Each
/// attempt is a non-blocking flock on a blocking-pool thread, and the wait
/// between attempts is a Tokio sleep, so no runtime worker ever blocks.
pub(crate) async fn acquire_public_state_lock(
    data_dir: &Path,
    budget: Duration,
) -> Result<PublicStateGuard, PublicMetadataError> {
    let path = state_lock_path(data_dir);
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let attempt_path = path.clone();
        let attempt = tokio::task::spawn_blocking(move || try_lock_state(&attempt_path))
            .await
            .map_err(|error| {
                PublicMetadataError::not_ready(format!("the state lock attempt failed: {error}"))
            })?;
        match attempt {
            Ok(Some(guard)) => return Ok(guard),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "public IPFS state lock is unavailable");
                return Err(PublicMetadataError::not_ready(
                    "the public IPFS state lock is unavailable",
                ));
            }
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            tracing::debug!(?budget, "public IPFS state lock is busy");
            return Err(PublicMetadataError::not_ready(
                "the public IPFS store is busy; try again shortly",
            ));
        }
        tokio::time::sleep(LOCK_POLL_INTERVAL.min(deadline - now)).await;
    }
}

/// One non-blocking attempt: the guard, `None` while another holder has it.
fn try_lock_state(path: &Path) -> anyhow::Result<Option<PublicStateGuard>> {
    let file = open_state_lock(path)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(PublicStateGuard { file })),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
    }
}

#[cfg(unix)]
fn open_state_lock(path: &Path) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    ensure_owner_only_parent(path)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        anyhow::bail!("the public IPFS state lock must be a regular file");
    }
    ensure_owner_only_metadata("public IPFS state lock", &metadata)?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_state_lock(_path: &Path) -> anyhow::Result<std::fs::File> {
    anyhow::bail!("the public IPFS store is unsupported on this platform")
}

pub(crate) fn read_withdrawal_marker(data_dir: &Path) -> anyhow::Result<Option<WithdrawalMarker>> {
    read_owner_only_json(
        &withdrawal_marker_path(data_dir),
        "public IPFS withdrawal marker",
    )
}

/// Record a Stop request at once and without the lock, so a busy store never
/// delays it. The marker appears whole or not at all, and an existing one is
/// kept: the first request stands until its withdrawal completes.
pub(crate) fn create_withdrawal_marker(
    data_dir: &Path,
    principal: &str,
) -> anyhow::Result<WithdrawalMarker> {
    if let Some(existing) = read_withdrawal_marker(data_dir)? {
        // Another Stop may have linked it and not yet synced the directory;
        // acknowledge only a durable marker.
        sync_dir(&public_ipfs_dir(data_dir))?;
        return Ok(existing);
    }
    let marker = new_withdrawal_marker(principal);
    let path = withdrawal_marker_path(data_dir);
    if create_owner_only_once(&path, &serde_json::to_vec_pretty(&marker)?)? {
        tracing::debug!(withdrawal_id = %marker.withdrawal_id, "public IPFS withdrawal requested");
        return Ok(marker);
    }
    // A concurrent Stop created it first; keep that one. The directory was
    // synced after the failed link, so it is durable.
    read_withdrawal_marker(data_dir)?
        .ok_or_else(|| anyhow::anyhow!("the public IPFS withdrawal marker vanished"))
}

fn new_withdrawal_marker(principal: &str) -> WithdrawalMarker {
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    WithdrawalMarker {
        withdrawal_id: format!("withdrawal:{}", hex::encode(nonce)),
        principal: principal.to_string(),
        created_at: now_secs(),
        stop_pending: None,
    }
}

/// What a Stop found when it came to repair an unreadable marker (A45-F5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MarkerRepair {
    /// Another Stop installed a valid marker meanwhile: it is kept unchanged,
    /// its `withdrawal_id` and principal included.
    Kept(WithdrawalMarker),
    /// Still unreadable: replaced by a fresh marker naming the acting admin.
    Replaced(WithdrawalMarker),
    /// A completion removed it: that withdrawal is complete, and neither the
    /// marker nor the consent may be touched, so a later Enable stands.
    AlreadyRemoved,
}

/// Repair an unreadable withdrawal marker under the guard: RE-READ it, keep a
/// valid one, leave a removed one alone, and only a still-unreadable one is
/// replaced, by an atomic owner-only replace (temp file in `public-ipfs/`,
/// fsync, rename over it, fsync the directory; never unlink-then-create).
/// Returns only once the outcome is durable.
pub(crate) fn repair_withdrawal_marker(
    data_dir: &Path,
    principal: &str,
    _guard: &PublicStateGuard,
) -> anyhow::Result<MarkerRepair> {
    match read_withdrawal_marker(data_dir) {
        Ok(Some(marker)) => {
            // Its writer may not have synced the directory yet.
            sync_dir(&public_ipfs_dir(data_dir))?;
            return Ok(MarkerRepair::Kept(marker));
        }
        Ok(None) => return Ok(MarkerRepair::AlreadyRemoved),
        Err(error) => {
            tracing::warn!(
                error = %format!("{error:#}"),
                "public IPFS withdrawal marker is unreadable; replacing it"
            );
        }
    }
    let marker = new_withdrawal_marker(principal);
    replace_owner_only(
        &withdrawal_marker_path(data_dir),
        &serde_json::to_vec_pretty(&marker)?,
    )?;
    tracing::debug!(withdrawal_id = %marker.withdrawal_id, "public IPFS withdrawal marker repaired");
    Ok(MarkerRepair::Replaced(marker))
}

/// Keep the reason the store could not yet be confirmed down, for the
/// Creator to show. Under the guard, so it never races the marker's removal.
pub(crate) fn record_withdrawal_pending(
    data_dir: &Path,
    reason: &str,
    _guard: &PublicStateGuard,
) -> anyhow::Result<()> {
    let Some(mut marker) = read_withdrawal_marker(data_dir)? else {
        return Ok(());
    };
    marker.stop_pending = Some(reason.chars().take(MAX_STOP_PENDING_CHARS).collect());
    crate::protected_content_runtime::write_owner_only_bytes(
        &withdrawal_marker_path(data_dir),
        &serde_json::to_vec_pretty(&marker)?,
    )
}

/// End a withdrawal. Only the withdrawal completion calls this, after
/// Disabled is persisted and the store is confirmed stopped.
pub(crate) fn remove_withdrawal_marker(
    data_dir: &Path,
    _guard: &PublicStateGuard,
) -> anyhow::Result<()> {
    let path = withdrawal_marker_path(data_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    sync_dir(&public_ipfs_dir(data_dir))?;
    tracing::debug!("public IPFS withdrawal completed");
    Ok(())
}

/// Why a Home does not offer public metadata sharing (A5 §2.1).
pub(crate) const NOT_OFFERED_PROTECTED_CONTENT_OFF: &str = "protected content is off";
pub(crate) const NOT_OFFERED_SHARING: &str = "sharing is not offered";
/// The refusal of a start or an Enable while sharing is not offered.
pub(crate) const PUBLIC_METADATA_OFF: &str = "public_metadata_off";

/// Why this Home does not offer public metadata sharing now, or `None` when
/// it does: protected content on AND `public_metadata` set (A5 §2.1). Read
/// fresh on every call, like `protected_content_enabled`, with both flags
/// from one `config.toml` snapshot (MP67-F1), so a config switched between
/// two reads never offers what neither snapshot offers.
pub(crate) fn public_metadata_not_offered(data_dir: &Path) -> Option<&'static str> {
    let config = crate::protected_content_runtime::read_home_config(data_dir);
    #[cfg(test)]
    test_seams::after_offering_read(data_dir);
    if !crate::protected_content_runtime::protected_content_enabled_in(config.as_ref()) {
        return Some(NOT_OFFERED_PROTECTED_CONTENT_OFF);
    }
    let offered = config
        .as_ref()
        .and_then(|config| config.get(crate::custody_surface::PUBLIC_METADATA_CONFIG_KEY))
        .and_then(toml::Value::as_bool)
        .unwrap_or(crate::custody_surface::PUBLIC_METADATA_DEFAULT);
    (!offered).then_some(NOT_OFFERED_SHARING)
}

/// The one offering predicate (A5 §2.1): read by publication admission, the
/// store's start, Enable and the supervisor.
pub(crate) fn public_metadata_offered(data_dir: &Path) -> bool {
    public_metadata_not_offered(data_dir).is_none()
}

/// The admission check at the start of every publication phase and of the
/// approval phase: sharing offered on this Home (A5), consent enabled for the
/// current wording and no withdrawal requested. Anything unreadable fails
/// closed.
///
/// The reads take no lock, so they are ordered to form one consistent
/// snapshot: consent, then the marker, then consent again with the same write
/// generation. Enable writes Enabled only with no marker, and a withdrawal
/// writes Disabled before it removes its marker, so a marker absent between
/// two reads of one Enabled write means both held at the marker read. Each
/// write has a fresh random generation, so an equal record rewritten in the
/// same second is still a different write.
pub(crate) fn phase_allowed(data_dir: &Path) -> Result<(), PublicMetadataError> {
    // A5: no new phase passes once the gate reads closed; the mint fails at
    // this boundary with Retry, and its retry takes the closed path.
    if !public_metadata_offered(data_dir) {
        return Err(PublicMetadataError::disabled(NOT_OFFERED_SHARING));
    }
    let before = enabled_consent(data_dir)?;
    #[cfg(test)]
    test_seams::between_admission_reads(data_dir, test_seams::AdmissionStage::AfterConsent);
    match read_withdrawal_marker(data_dir) {
        Ok(None) => {}
        Ok(Some(_)) => {
            return Err(PublicMetadataError::disabled(
                "public metadata sharing is stopping",
            ))
        }
        Err(error) => {
            return Err(admission_refused(
                "the public IPFS withdrawal marker is unreadable",
                error,
            ))
        }
    }
    #[cfg(test)]
    test_seams::between_admission_reads(data_dir, test_seams::AdmissionStage::AfterMarker);
    if enabled_consent(data_dir)?.generation != before.generation {
        return Err(PublicMetadataError::disabled(
            "public metadata sharing changed; try again",
        ));
    }
    Ok(())
}

/// The consent record, when it is Enabled for the current wording.
fn enabled_consent(data_dir: &Path) -> Result<ConsentRecord, PublicMetadataError> {
    match read_consent(data_dir) {
        Ok(Some(record)) if record.is_current_enabled() => Ok(record),
        Ok(_) => Err(PublicMetadataError::disabled(
            "public metadata sharing is not enabled",
        )),
        Err(error) => Err(admission_refused(
            "the public IPFS consent record is unreadable",
            error,
        )),
    }
}

fn admission_refused(reason: &str, error: anyhow::Error) -> PublicMetadataError {
    tracing::warn!(error = %format!("{error:#}"), "{reason}");
    PublicMetadataError::disabled(reason)
}

/// `None` when the file is absent. A present file must be a regular,
/// owner-only, bounded file holding exactly `T`.
fn read_owner_only_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    label: &str,
) -> anyhow::Result<Option<T>> {
    let Some(bytes) = read_owner_only_bytes(path, label)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| anyhow::anyhow!("{label} is malformed: {error}"))
}

#[cfg(unix)]
fn read_owner_only_bytes(path: &Path, label: &str) -> anyhow::Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(anyhow::anyhow!("{label} is unavailable: {error}")),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        anyhow::bail!("{label} must be a regular file");
    }
    ensure_owner_only_metadata(label, &metadata)?;
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RECORD_BYTES {
        anyhow::bail!("{label} exceeds its bound");
    }
    Ok(Some(bytes))
}

#[cfg(not(unix))]
fn read_owner_only_bytes(_path: &Path, label: &str) -> anyhow::Result<Option<Vec<u8>>> {
    anyhow::bail!("{label} is unsupported on this platform")
}

#[cfg(unix)]
fn ensure_owner_only_metadata(label: &str, metadata: &std::fs::Metadata) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let euid = nix::unistd::geteuid().as_raw();
    if metadata.uid() != euid || metadata.permissions().mode() & 0o077 != 0 {
        anyhow::bail!("{label} must be owner-only");
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_owner_only_parent(path: &Path) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("the public IPFS state path has no parent"))?;
    crate::protected_content_runtime::ensure_owner_only_runtime_storage_parent(parent)
}

/// Create `path` holding `bytes`, owner-only, only if it does not exist yet.
/// The bytes go to a private temporary file first and are then hard-linked
/// into place, which fails when `path` exists, so readers never see a
/// partial file. `false` when `path` already existed.
#[cfg(unix)]
fn create_owner_only_once(path: &Path, bytes: &[u8]) -> anyhow::Result<bool> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    ensure_owner_only_parent(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("the public IPFS state path has no parent"))?;
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let temp = parent.join(format!(".withdraw-requested.tmp-{}", hex::encode(nonce)));
    let written = (|| -> anyhow::Result<bool> {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        match std::fs::hard_link(&temp, path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error.into()),
        }
    })();
    let _ = std::fs::remove_file(&temp);
    let created = written?;
    sync_dir(parent)?;
    Ok(created)
}

#[cfg(not(unix))]
fn create_owner_only_once(_path: &Path, _bytes: &[u8]) -> anyhow::Result<bool> {
    anyhow::bail!("the public IPFS store is unsupported on this platform")
}

/// Replace `path` with `bytes`, owner-only and atomically: a private temp
/// file beside it, written and fsynced, renamed over `path`, then the
/// directory fsynced. A failure before the rename leaves the old file; one
/// after it leaves the new one. Never unlink-then-create.
#[cfg(unix)]
fn replace_owner_only(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    ensure_owner_only_parent(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("the public IPFS state path has no parent"))?;
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let temp = parent.join(format!(".withdraw-requested.repair-{}", hex::encode(nonce)));
    let renamed = (|| -> anyhow::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        #[cfg(test)]
        test_seams::replace_step(parent, test_seams::ReplaceStage::TempSync)?;
        drop(file);
        #[cfg(test)]
        test_seams::replace_step(parent, test_seams::ReplaceStage::Rename)?;
        std::fs::rename(&temp, path)?;
        Ok(())
    })();
    if renamed.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    renamed?;
    #[cfg(test)]
    test_seams::replace_step(parent, test_seams::ReplaceStage::DirSync)?;
    sync_dir(parent)
}

#[cfg(not(unix))]
fn replace_owner_only(_path: &Path, _bytes: &[u8]) -> anyhow::Result<()> {
    anyhow::bail!("the public IPFS store is unsupported on this platform")
}

/// Make a directory's entries durable. Tests may substitute this barrier for
/// one directory to pause or fail it; production always syncs.
fn sync_dir(dir: &Path) -> anyhow::Result<()> {
    #[cfg(test)]
    if let Some(hook) = test_seams::sync_hook(dir) {
        return hook(dir).map_err(Into::into);
    }
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Test-only interleaving points, keyed by path so parallel tests never see
/// each other's hooks. Nothing here is compiled into the Runtime.
#[cfg(test)]
pub(crate) mod test_seams {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, OnceLock};

    pub(crate) type SyncHook = Arc<dyn Fn(&Path) -> std::io::Result<()> + Send + Sync>;
    pub(crate) type ReplaceHook = Arc<dyn Fn(ReplaceStage) -> std::io::Result<()> + Send + Sync>;

    /// The durability steps of the marker repair's atomic replace.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum ReplaceStage {
        /// After the temp file's fsync, before the rename.
        TempSync,
        /// Right before the rename.
        Rename,
        /// After the rename, before the directory fsync.
        DirSync,
    }

    fn replace_hooks() -> &'static Mutex<HashMap<PathBuf, ReplaceHook>> {
        static HOOKS: OnceLock<Mutex<HashMap<PathBuf, ReplaceHook>>> = OnceLock::new();
        HOOKS.get_or_init(Default::default)
    }

    /// Run `hook` at each [`ReplaceStage`] of a marker repair in `data_dir`;
    /// an error fails that step.
    pub(crate) fn set_replace_hook(data_dir: &Path, hook: ReplaceHook) -> HookGuard {
        let dir = super::public_ipfs_dir(data_dir);
        replace_hooks().lock().unwrap().insert(dir.clone(), hook);
        HookGuard(Box::new(move || {
            replace_hooks().lock().unwrap().remove(&dir);
        }))
    }

    pub(super) fn replace_step(dir: &Path, stage: ReplaceStage) -> std::io::Result<()> {
        let hook = replace_hooks().lock().unwrap().get(dir).cloned();
        match hook {
            Some(hook) => hook(stage),
            None => Ok(()),
        }
    }
    pub(crate) type AdmissionHook = Arc<dyn Fn(&Path, AdmissionStage) + Send + Sync>;

    /// Where in `phase_allowed` an admission hook runs.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum AdmissionStage {
        /// After the first consent read, before the marker read.
        AfterConsent,
        /// After the marker read, before the consent re-read.
        AfterMarker,
    }

    thread_local! {
        static FIXED_NOW: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    }

    /// Pin this thread's record clock (whole seconds), so two writes land in
    /// the same second deterministically. Cleared on drop.
    pub(crate) fn fix_now(now: u64) -> FixedNow {
        FIXED_NOW.with(|cell| cell.set(Some(now)));
        FixedNow(())
    }

    pub(crate) struct FixedNow(());

    impl Drop for FixedNow {
        fn drop(&mut self) {
            FIXED_NOW.with(|cell| cell.set(None));
        }
    }

    pub(super) fn fixed_now() -> Option<u64> {
        FIXED_NOW.with(|cell| cell.get())
    }

    fn sync_hooks() -> &'static Mutex<HashMap<PathBuf, SyncHook>> {
        static HOOKS: OnceLock<Mutex<HashMap<PathBuf, SyncHook>>> = OnceLock::new();
        HOOKS.get_or_init(Default::default)
    }

    fn admission_hooks() -> &'static Mutex<HashMap<PathBuf, AdmissionHook>> {
        static HOOKS: OnceLock<Mutex<HashMap<PathBuf, AdmissionHook>>> = OnceLock::new();
        HOOKS.get_or_init(Default::default)
    }

    /// Removes its hook when dropped.
    pub(crate) struct HookGuard(Box<dyn FnOnce() + Send>);

    impl Drop for HookGuard {
        fn drop(&mut self) {
            let remove = std::mem::replace(&mut self.0, Box::new(|| {}));
            remove();
        }
    }

    /// Replace the directory-sync barrier of `data_dir`'s public-ipfs folder.
    pub(crate) fn set_sync_hook(data_dir: &Path, hook: SyncHook) -> HookGuard {
        let dir = super::public_ipfs_dir(data_dir);
        sync_hooks().lock().unwrap().insert(dir.clone(), hook);
        HookGuard(Box::new(move || {
            sync_hooks().lock().unwrap().remove(&dir);
        }))
    }

    /// Run `hook` at each [`AdmissionStage`] of `phase_allowed` for
    /// `data_dir`.
    pub(crate) fn set_admission_hook(data_dir: &Path, hook: AdmissionHook) -> HookGuard {
        let key = data_dir.to_path_buf();
        admission_hooks().lock().unwrap().insert(key.clone(), hook);
        HookGuard(Box::new(move || {
            admission_hooks().lock().unwrap().remove(&key);
        }))
    }

    pub(crate) type OfferingHook = Arc<dyn Fn(&Path) + Send + Sync>;

    fn offering_hooks() -> &'static Mutex<HashMap<PathBuf, OfferingHook>> {
        static HOOKS: OnceLock<Mutex<HashMap<PathBuf, OfferingHook>>> = OnceLock::new();
        HOOKS.get_or_init(Default::default)
    }

    /// Run `hook` in `public_metadata_not_offered` for `data_dir`, right
    /// after its one config read.
    pub(crate) fn set_offering_hook(data_dir: &Path, hook: OfferingHook) -> HookGuard {
        let key = data_dir.to_path_buf();
        offering_hooks().lock().unwrap().insert(key.clone(), hook);
        HookGuard(Box::new(move || {
            offering_hooks().lock().unwrap().remove(&key);
        }))
    }

    pub(super) fn after_offering_read(data_dir: &Path) {
        let hook = offering_hooks().lock().unwrap().get(data_dir).cloned();
        if let Some(hook) = hook {
            hook(data_dir);
        }
    }

    pub(super) fn sync_hook(dir: &Path) -> Option<SyncHook> {
        sync_hooks().lock().unwrap().get(dir).cloned()
    }

    pub(super) fn between_admission_reads(data_dir: &Path, stage: AdmissionStage) {
        let hook = admission_hooks().lock().unwrap().get(data_dir).cloned();
        if let Some(hook) = hook {
            hook(data_dir, stage);
        }
    }
}

#[cfg(all(test, unix))]
pub(crate) mod tests {
    use super::*;
    use crate::protected_content_config::tests::{owner_only_dir, safe_ancestor_tempdir};
    use std::os::unix::fs::PermissionsExt as _;

    /// A Home that offers public metadata sharing (A5): protected content
    /// on and `public_metadata = true`, as a proof Home sets them.
    pub(crate) fn owner_only_data_dir() -> (tempfile::TempDir, PathBuf) {
        let (dir, data_dir) = closed_data_dir();
        open_public_metadata_gate(&data_dir);
        (dir, data_dir)
    }

    /// A Home as it is by default: no config, so nothing is offered.
    pub(crate) fn closed_data_dir() -> (tempfile::TempDir, PathBuf) {
        let dir = safe_ancestor_tempdir();
        let data_dir = dir.path().join("data");
        owner_only_dir(&data_dir);
        (dir, data_dir)
    }

    /// Sets `keys` in `config.toml`, keeping every other key.
    pub(crate) fn set_config_flags(data_dir: &Path, keys: &[(&str, bool)]) {
        let path = data_dir.join("config.toml");
        let mut table = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| text.parse::<toml::Table>().ok())
            .unwrap_or_default();
        for (key, value) in keys {
            table.insert((*key).to_string(), toml::Value::Boolean(*value));
        }
        std::fs::write(&path, toml::to_string(&table).unwrap()).unwrap();
    }

    /// Opens the A5 gate on this Home, as `elastos config set
    /// public_metadata true` does on a proof Home.
    pub(crate) fn open_public_metadata_gate(data_dir: &Path) {
        set_config_flags(
            data_dir,
            &[
                ("protected_content", true),
                (crate::custody_surface::PUBLIC_METADATA_CONFIG_KEY, true),
            ],
        );
    }

    /// Closes the A5 gate again; protected content stays as it is.
    pub(crate) fn close_public_metadata_gate(data_dir: &Path) {
        set_config_flags(
            data_dir,
            &[(crate::custody_surface::PUBLIC_METADATA_CONFIG_KEY, false)],
        );
    }

    #[tokio::test]
    async fn record_round_trips_owner_only() {
        let (_dir, data_dir) = owner_only_data_dir();
        assert_eq!(read_consent(&data_dir).unwrap(), None);
        assert!(!consent_enabled(&data_dir).unwrap());

        let guard = acquire_public_state_lock(&data_dir, STATE_LOCK_BUDGET)
            .await
            .unwrap();
        let written =
            write_consent(&data_dir, ConsentState::Enabled, "principal:a", &guard).unwrap();
        assert_eq!(written.state, ConsentState::Enabled);
        assert_eq!(written.principal, "principal:a");
        assert_eq!(written.wording_version, CONSENT_WORDING_VERSION);
        assert_eq!(written.wording_sha256, consent_wording_sha256());
        assert!(written.changed_at > 0);

        assert_eq!(read_consent(&data_dir).unwrap(), Some(written));
        assert!(consent_enabled(&data_dir).unwrap());
        let mode = std::fs::metadata(consent_path(&data_dir))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = std::fs::metadata(public_ipfs_dir(&data_dir))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    fn public_wording_sha_and_step_up_request_are_server_built() {
        let sha = consent_wording_sha256();
        assert_eq!(sha.len(), 64);
        assert_eq!(
            sha,
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                CONSENT_WORDING.as_bytes()
            ))
        );
        assert_eq!(
            enable_step_up_request(),
            serde_json::json!({ "wording_version": 1, "wording_sha256": sha })
        );
        assert!(CONSENT_WORDING.starts_with("Publish your assets' metadata on IPFS\n"));
        assert_eq!(
            CONSENT_WORDING
                .lines()
                .filter(|line| line.starts_with("- "))
                .count(),
            4
        );
    }

    #[test]
    fn old_wording_sha_reads_not_enabled() {
        let (_dir, data_dir) = owner_only_data_dir();
        let record = ConsentRecord {
            state: ConsentState::Enabled,
            principal: "principal:a".into(),
            wording_version: CONSENT_WORDING_VERSION,
            wording_sha256: hex::encode([7u8; 32]),
            changed_at: 1,
            generation: "0".repeat(32),
        };
        crate::protected_content_runtime::write_owner_only_bytes(
            &consent_path(&data_dir),
            &serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        assert_eq!(read_consent(&data_dir).unwrap(), Some(record.clone()));
        assert!(!consent_enabled(&data_dir).unwrap());

        let old_version = ConsentRecord {
            wording_version: CONSENT_WORDING_VERSION + 1,
            wording_sha256: consent_wording_sha256(),
            ..record
        };
        crate::protected_content_runtime::write_owner_only_bytes(
            &consent_path(&data_dir),
            &serde_json::to_vec(&old_version).unwrap(),
        )
        .unwrap();
        assert!(!consent_enabled(&data_dir).unwrap());
        assert_eq!(
            phase_allowed(&data_dir).unwrap_err().code(),
            PublicMetadataErrorCode::Disabled
        );
    }

    #[tokio::test]
    async fn disabled_reads_not_enabled() {
        let (_dir, data_dir) = owner_only_data_dir();
        let guard = acquire_public_state_lock(&data_dir, STATE_LOCK_BUDGET)
            .await
            .unwrap();
        write_consent(&data_dir, ConsentState::Enabled, "principal:a", &guard).unwrap();
        assert!(phase_allowed(&data_dir).is_ok());
        let disabled =
            write_consent(&data_dir, ConsentState::Disabled, "principal:a", &guard).unwrap();
        assert_eq!(disabled.state, ConsentState::Disabled);
        assert_eq!(disabled.wording_sha256, consent_wording_sha256());
        assert!(!consent_enabled(&data_dir).unwrap());
        assert_eq!(
            phase_allowed(&data_dir).unwrap_err().code(),
            PublicMetadataErrorCode::Disabled
        );
    }

    #[test]
    fn unknown_field_refused() {
        let (_dir, data_dir) = owner_only_data_dir();
        let mut record = serde_json::json!({
            "state": "enabled",
            "principal": "principal:a",
            "wording_version": CONSENT_WORDING_VERSION,
            "wording_sha256": consent_wording_sha256(),
            "changed_at": 1,
            "generation": "0123456789abcdef0123456789abcdef",
        });
        crate::protected_content_runtime::write_owner_only_bytes(
            &consent_path(&data_dir),
            &serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        assert!(consent_enabled(&data_dir).unwrap());

        record["scope"] = serde_json::json!("everything");
        crate::protected_content_runtime::write_owner_only_bytes(
            &consent_path(&data_dir),
            &serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        assert!(read_consent(&data_dir).is_err());
        assert!(consent_enabled(&data_dir).is_err());
        // An unreadable record never admits a phase.
        assert_eq!(
            phase_allowed(&data_dir).unwrap_err().code(),
            PublicMetadataErrorCode::Disabled
        );
    }

    #[test]
    fn public_record_readable_by_others_is_refused() {
        let (_dir, data_dir) = owner_only_data_dir();
        let path = consent_path(&data_dir);
        crate::protected_content_runtime::write_owner_only_bytes(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "state": "enabled",
                "principal": "principal:a",
                "wording_version": CONSENT_WORDING_VERSION,
                "wording_sha256": consent_wording_sha256(),
                "changed_at": 1,
                "generation": "0123456789abcdef0123456789abcdef",
            "generation": "0123456789abcdef0123456789abcdef",
            }))
            .unwrap()
            .as_slice(),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_consent(&data_dir).is_err());
        assert!(phase_allowed(&data_dir).is_err());
    }

    #[tokio::test]
    async fn public_marker_is_created_once_and_removed_under_the_guard() {
        let (_dir, data_dir) = owner_only_data_dir();
        assert_eq!(read_withdrawal_marker(&data_dir).unwrap(), None);
        let first = create_withdrawal_marker(&data_dir, "principal:a").unwrap();
        assert!(first.withdrawal_id.starts_with("withdrawal:"));
        assert_eq!(first.principal, "principal:a");
        assert_eq!(first.stop_pending, None);
        let mode = std::fs::metadata(public_ipfs_dir(&data_dir).join(WITHDRAWAL_MARKER_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        // Idempotent: a second Stop keeps the first request.
        let second = create_withdrawal_marker(&data_dir, "principal:b").unwrap();
        assert_eq!(second, first);

        let guard = acquire_public_state_lock(&data_dir, STATE_LOCK_BUDGET)
            .await
            .unwrap();
        record_withdrawal_pending(&data_dir, "shutdown already settling", &guard).unwrap();
        let pending = read_withdrawal_marker(&data_dir).unwrap().unwrap();
        assert_eq!(pending.withdrawal_id, first.withdrawal_id);
        assert_eq!(
            pending.stop_pending.as_deref(),
            Some("shutdown already settling")
        );

        remove_withdrawal_marker(&data_dir, &guard).unwrap();
        assert_eq!(read_withdrawal_marker(&data_dir).unwrap(), None);
        // Removing again, or recording on no marker, changes nothing.
        remove_withdrawal_marker(&data_dir, &guard).unwrap();
        record_withdrawal_pending(&data_dir, "late", &guard).unwrap();
        assert_eq!(read_withdrawal_marker(&data_dir).unwrap(), None);
    }

    #[tokio::test]
    async fn public_guard_drop_releases_the_lock() {
        let (_dir, data_dir) = owner_only_data_dir();
        let guard = acquire_public_state_lock(&data_dir, STATE_LOCK_BUDGET)
            .await
            .unwrap();
        let busy = acquire_public_state_lock(&data_dir, Duration::from_millis(60))
            .await
            .unwrap_err();
        assert_eq!(busy.code(), PublicMetadataErrorCode::NotReady);
        drop(guard);
        acquire_public_state_lock(&data_dir, Duration::from_millis(60))
            .await
            .unwrap();
    }

    /// Review T3-F1: Stop A has linked the marker but not yet synced its
    /// directory. Stop B sees that marker; it must not succeed until the
    /// marker is durable, and a failed barrier must fail it.
    #[test]
    fn public_existing_marker_is_made_durable_before_success() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{mpsc, Arc, Mutex};

        let (_dir, data_dir) = owner_only_data_dir();
        let (paused_tx, paused_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (paused_tx, release_rx) = (Mutex::new(paused_tx), Mutex::new(release_rx));
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = calls.clone();
        let _hook = test_seams::set_sync_hook(
            &data_dir,
            Arc::new(move |_dir| {
                if hook_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    // Stop A: linked, paused before its barrier.
                    paused_tx.lock().unwrap().send(()).unwrap();
                    release_rx.lock().unwrap().recv().unwrap();
                    Ok(())
                } else {
                    Err(std::io::Error::other("injected sync failure"))
                }
            }),
        );
        let stop_a = std::thread::spawn({
            let data_dir = data_dir.clone();
            move || create_withdrawal_marker(&data_dir, "principal:a")
        });
        paused_rx.recv().unwrap();
        assert!(read_withdrawal_marker(&data_dir).unwrap().is_some());

        let stop_b = create_withdrawal_marker(&data_dir, "principal:b");
        assert!(
            stop_b.is_err(),
            "Stop B succeeded on a marker that is not durable: {stop_b:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2, "Stop B ran no barrier");

        release_tx.send(()).unwrap();
        let first = stop_a.join().unwrap().unwrap();
        assert_eq!(first.principal, "principal:a");
    }

    /// Review T3-F2: consent Disabled and no marker, then between the
    /// admission's two reads Enable (past its guarded marker check) and Stop
    /// interleave: Stop creates its marker, Enable writes Enabled. No instant
    /// had Enabled and no marker, so the phase must be refused.
    #[tokio::test]
    async fn public_admission_refuses_enable_and_stop_between_its_reads() {
        let (_dir, data_dir) = owner_only_data_dir();
        let guard = std::sync::Arc::new(
            acquire_public_state_lock(&data_dir, STATE_LOCK_BUDGET)
                .await
                .unwrap(),
        );
        write_consent(&data_dir, ConsentState::Disabled, "principal:a", &guard).unwrap();
        let enable_guard = guard.clone();
        let _hook = test_seams::set_admission_hook(
            &data_dir,
            std::sync::Arc::new(move |data_dir, stage| {
                if stage != test_seams::AdmissionStage::AfterConsent {
                    return;
                }
                create_withdrawal_marker(data_dir, "principal:stop").unwrap();
                write_consent(
                    data_dir,
                    ConsentState::Enabled,
                    "principal:enable",
                    &enable_guard,
                )
                .unwrap();
            }),
        );
        let refused = phase_allowed(&data_dir).unwrap_err();
        assert_eq!(refused.code(), PublicMetadataErrorCode::Disabled);
    }

    /// The other order's hazard: consent Enabled with a Stop requested, and
    /// the whole withdrawal completes (Disabled, then the marker removed)
    /// between the admission's reads. The phase must still be refused.
    #[tokio::test]
    async fn public_admission_refuses_a_withdrawal_completed_between_its_reads() {
        let (_dir, data_dir) = owner_only_data_dir();
        let guard = std::sync::Arc::new(
            acquire_public_state_lock(&data_dir, STATE_LOCK_BUDGET)
                .await
                .unwrap(),
        );
        write_consent(&data_dir, ConsentState::Enabled, "principal:a", &guard).unwrap();
        create_withdrawal_marker(&data_dir, "principal:a").unwrap();
        let completion_guard = guard.clone();
        let _hook = test_seams::set_admission_hook(
            &data_dir,
            std::sync::Arc::new(move |data_dir, stage| {
                if stage != test_seams::AdmissionStage::AfterConsent {
                    return;
                }
                write_consent(
                    data_dir,
                    ConsentState::Disabled,
                    "principal:a",
                    &completion_guard,
                )
                .unwrap();
                remove_withdrawal_marker(data_dir, &completion_guard).unwrap();
            }),
        );
        let refused = phase_allowed(&data_dir).unwrap_err();
        assert_eq!(refused.code(), PublicMetadataErrorCode::Disabled);
    }

    /// Review T3-F2 (round 2): the phase reads Enabled while Stop A's marker
    /// exists; Stop A completes (Disabled, marker removed) before the marker
    /// read; then a fresh Enable passes its no-marker check, Stop B creates
    /// its marker, and Enable writes a record identical to the first one in
    /// the same second. The re-read must not mistake it for the same write.
    #[tokio::test]
    async fn public_admission_refuses_an_identical_enable_between_its_reads() {
        use test_seams::AdmissionStage;

        let (_dir, data_dir) = owner_only_data_dir();
        let _clock = test_seams::fix_now(1_800_000_000);
        let guard = std::sync::Arc::new(
            acquire_public_state_lock(&data_dir, STATE_LOCK_BUDGET)
                .await
                .unwrap(),
        );
        let first = write_consent(&data_dir, ConsentState::Enabled, "principal:a", &guard).unwrap();
        create_withdrawal_marker(&data_dir, "principal:a").unwrap();
        let hook_guard = guard.clone();
        let _hook = test_seams::set_admission_hook(
            &data_dir,
            std::sync::Arc::new(move |data_dir, stage| match stage {
                AdmissionStage::AfterConsent => {
                    // Stop A's completion.
                    write_consent(data_dir, ConsentState::Disabled, "principal:a", &hook_guard)
                        .unwrap();
                    remove_withdrawal_marker(data_dir, &hook_guard).unwrap();
                }
                AdmissionStage::AfterMarker => {
                    // A fresh Enable passed its guarded check; Stop B lands;
                    // Enable writes Enabled in the same second.
                    assert!(read_withdrawal_marker(data_dir).unwrap().is_none());
                    create_withdrawal_marker(data_dir, "principal:b").unwrap();
                    write_consent(data_dir, ConsentState::Enabled, "principal:a", &hook_guard)
                        .unwrap();
                }
            }),
        );
        let refused = phase_allowed(&data_dir);
        let now = read_consent(&data_dir).unwrap().unwrap();
        assert_eq!(now.state, first.state);
        assert_eq!(now.changed_at, first.changed_at);
        assert!(read_withdrawal_marker(&data_dir).unwrap().is_some());
        assert_eq!(
            refused.unwrap_err().code(),
            PublicMetadataErrorCode::Disabled,
            "admitted while Stop B's marker exists"
        );
    }

    #[tokio::test]
    async fn public_record_without_generation_reads_not_enabled() {
        let (_dir, data_dir) = owner_only_data_dir();
        let guard = acquire_public_state_lock(&data_dir, STATE_LOCK_BUDGET)
            .await
            .unwrap();
        let first = write_consent(&data_dir, ConsentState::Enabled, "principal:a", &guard).unwrap();
        let second =
            write_consent(&data_dir, ConsentState::Enabled, "principal:a", &guard).unwrap();
        assert!(is_generation(&first.generation));
        assert_ne!(first.generation, second.generation);
        assert!(consent_enabled(&data_dir).unwrap());

        // A record written before generations existed: not enabled, so the
        // admin consents again.
        let mut legacy = serde_json::to_value(&second).unwrap();
        legacy.as_object_mut().unwrap().remove("generation");
        crate::protected_content_runtime::write_owner_only_bytes(
            &consent_path(&data_dir),
            &serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        assert_eq!(read_consent(&data_dir).unwrap().unwrap().generation, "");
        assert!(!consent_enabled(&data_dir).unwrap());
        assert_eq!(
            phase_allowed(&data_dir).unwrap_err().code(),
            PublicMetadataErrorCode::Disabled
        );
    }

    #[test]
    fn public_error_codes_are_the_contract() {
        let codes = [
            PublicMetadataErrorCode::Disabled,
            PublicMetadataErrorCode::NotReady,
            PublicMetadataErrorCode::ExportFailed,
            PublicMetadataErrorCode::InvalidCar,
            PublicMetadataErrorCode::ImportFailed,
            PublicMetadataErrorCode::PinFailed,
            PublicMetadataErrorCode::AnnounceFailed,
        ]
        .map(PublicMetadataErrorCode::as_str);
        assert_eq!(
            codes,
            [
                "disabled",
                "not_ready",
                "export_failed",
                "invalid_car",
                "import_failed",
                "pin_failed",
                "announce_failed"
            ]
        );
        let error = PublicMetadataError::not_ready("port 4001 is taken");
        let wrapped = anyhow::Error::new(error.clone());
        assert_eq!(wrapped.downcast_ref::<PublicMetadataError>(), Some(&error));
        assert_eq!(error.detail(), "port 4001 is taken");
    }

    // ── A5: off by default (amendment §2.1) ────────────────────────────

    /// The gate is declared once, closed by default, and opens only with
    /// protected content on and `public_metadata = true`. While it is closed
    /// every phase answers the typed `disabled`, even with consent Enabled.
    #[tokio::test]
    async fn public_gate_closed_by_default() {
        assert_eq!(
            crate::custody_surface::PUBLIC_METADATA_CONFIG_KEY,
            "public_metadata"
        );
        const _: () = assert!(!crate::custody_surface::PUBLIC_METADATA_DEFAULT);

        let (_dir, data_dir) = closed_data_dir();
        assert!(!public_metadata_offered(&data_dir));
        assert_eq!(
            public_metadata_not_offered(&data_dir),
            Some(NOT_OFFERED_PROTECTED_CONTENT_OFF)
        );
        let guard = acquire_public_state_lock(&data_dir, STATE_LOCK_BUDGET)
            .await
            .unwrap();
        write_consent(&data_dir, ConsentState::Enabled, "principal:test", &guard).unwrap();
        drop(guard);
        let refused = phase_allowed(&data_dir).unwrap_err();
        assert_eq!(refused.code(), PublicMetadataErrorCode::Disabled);
        assert_eq!(refused.detail(), NOT_OFFERED_SHARING);

        // Protected content alone does not offer sharing.
        set_config_flags(&data_dir, &[("protected_content", true)]);
        assert!(!public_metadata_offered(&data_dir));
        assert_eq!(
            public_metadata_not_offered(&data_dir),
            Some(NOT_OFFERED_SHARING)
        );
        assert_eq!(
            phase_allowed(&data_dir).unwrap_err().code(),
            PublicMetadataErrorCode::Disabled
        );
        // `public_metadata` alone does not either.
        set_config_flags(
            &data_dir,
            &[
                ("protected_content", false),
                (crate::custody_surface::PUBLIC_METADATA_CONFIG_KEY, true),
            ],
        );
        assert_eq!(
            public_metadata_not_offered(&data_dir),
            Some(NOT_OFFERED_PROTECTED_CONTENT_OFF)
        );
        // Both open it; the consent written while it was closed stands.
        open_public_metadata_gate(&data_dir);
        assert!(public_metadata_offered(&data_dir));
        assert_eq!(public_metadata_not_offered(&data_dir), None);
        phase_allowed(&data_dir).unwrap();
        close_public_metadata_gate(&data_dir);
        assert!(!public_metadata_offered(&data_dir));
        assert!(consent_enabled(&data_dir).unwrap(), "paused, not withdrawn");
    }

    /// MP67-F1: both flags come from one `config.toml` snapshot. A config
    /// switched atomically between {protected content on, sharing off} and
    /// {protected content off, sharing on} never offers sharing: neither
    /// snapshot does.
    #[test]
    fn public_offering_reads_both_flags_from_one_config_snapshot() {
        let (_dir, data_dir) = closed_data_dir();
        let key = crate::custody_surface::PUBLIC_METADATA_CONFIG_KEY;
        set_config_flags(&data_dir, &[("protected_content", true), (key, false)]);
        let _hook = test_seams::set_offering_hook(
            &data_dir,
            std::sync::Arc::new(move |data_dir| {
                let next = data_dir.join("config.toml.next");
                std::fs::write(&next, format!("protected_content = false\n{key} = true\n"))
                    .unwrap();
                std::fs::rename(&next, data_dir.join("config.toml")).unwrap();
            }),
        );
        assert_eq!(
            public_metadata_not_offered(&data_dir),
            Some(NOT_OFFERED_SHARING),
            "the snapshot read first does not offer sharing"
        );
        assert!(!public_metadata_offered(&data_dir));
    }
}

//! A checked release is information; System retains installation authority.
use super::gateway_home_update::{self as update, UpdateCheckCache};
use super::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const SCHEMA: &str = "elastos.update-notice/v1";
const MAX_STATE_BYTES: usize = 64 * 1024;
const FIRST_WAIT: u64 = 3 * 60;
const CHECK_INTERVAL: u64 = 6 * 60 * 60;
const MAX_SPREAD: u64 = 60 * 60;
const SWITCH_LABEL: &str = "Check for updates in the background";
const ON_TEXT: &str = "Home tries a few checks each day; the source can see the internet address and check time, while your name and installed version stay private.";
const OFF_TEXT: &str = "Background checks are off; System checks for updates while it is open.";
const SAVE_ERROR: &str = "Home could not save background checks. On the device that runs Home, check free disk space, write access and private ownership of Local/Shared/System/Updates and its .notice.lock file inside this Home's data folder. Move notice.json aside if it is a folder, then try again.";
const NOTICE_TITLE: &str = "Home update found";
const NOTICE_BODY: &str = "Home {version} was found. Review the update in System.";
const FOLDER_TEXT: &str = "Background checks are off because Home cannot use Local/Shared/System/Updates inside this Home's data folder. On the device that runs Home, check free disk space and write access. Use a real folder and a regular .notice.lock file, both owned by and private to the account that runs Home, then turn this on.";
const INVALID_VERSION_TEXT: &str = "Home cannot check for updates until you repair the installed version. On the device that runs Home, run elastos update --force.";
const UNREADABLE_TEXT: &str = "Background checks are off because Home could not read its settings. On the device that runs Home, repair or move aside Local/Shared/System/Updates/notice.json inside this Home's data folder, then turn this on.";

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Acknowledgement {
    read: bool,
    dismissed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoticeState {
    schema: String,
    background_checks: bool,
    release_cid: Option<String>,
    accounts: BTreeMap<String, Acknowledgement>,
}

impl Default for NoticeState {
    fn default() -> Self {
        Self {
            schema: SCHEMA.into(),
            background_checks: true,
            release_cid: None,
            accounts: BTreeMap::new(),
        }
    }
}

pub(super) fn state_path(data_dir: &Path) -> anyhow::Result<PathBuf> {
    rooted_localhost_fs_path(
        data_dir,
        "localhost://Local/Shared/System/Updates/notice.json",
    )
    .ok_or_else(|| anyhow::anyhow!("update settings path is unavailable"))
}

fn locked_path(data_dir: &Path) -> anyhow::Result<(PathBuf, crate::host_lock::FileLock)> {
    let path = state_path(data_dir)?;
    let root = path.parent().expect("update settings have a parent");
    std::fs::create_dir_all(root.parent().expect("System has a parent"))?;
    crate::collaboration_core::ensure_owner_only_directory(root)?;
    let lock = crate::collaboration_core::lock_owner_only_file(&root.join(".notice.lock"))?;
    Ok((path, lock))
}

fn read_state(path: &Path) -> anyhow::Result<NoticeState> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(NoticeState::default())
        }
        result => {
            result?;
        }
    }
    let bytes = crate::collaboration_config::read_owner_only_file(
        path,
        MAX_STATE_BYTES,
        "update settings",
    )?;
    let state: NoticeState = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(state.schema == SCHEMA, "unknown update settings schema");
    anyhow::ensure!(
        state.accounts.len() <= 256,
        "too many update acknowledgements"
    );
    Ok(state)
}

// All writers hold .notice.lock. The replacement is owner-only and atomic.
fn write_state(path: &Path, state: &NoticeState) -> anyhow::Result<()> {
    use std::io::Write;
    let bytes = serde_json::to_vec(state)?;
    anyhow::ensure!(
        bytes.len() <= MAX_STATE_BYTES,
        "update settings exceed their limit"
    );
    let root = path.parent().expect("update settings have a parent");
    let mut temporary = tempfile::NamedTempFile::new_in(root)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    std::fs::File::open(root)?.sync_all()?;
    Ok(())
}

pub(super) fn preference(data_dir: &Path) -> serde_json::Value {
    let locked = locked_path(data_dir);
    let folder_usable = locked.is_ok();
    let state = locked.and_then(|(path, _lock)| read_state(&path));
    let enabled = state.as_ref().is_ok_and(|state| state.background_checks);
    let invalid_version = crate::sources::load_trusted_sources(data_dir)
        .ok()
        .and_then(|config| config.default_source().cloned())
        .is_some_and(|source| {
            crate::update::installed_release_version(&source.installed_version).is_err()
        });
    let message = if !folder_usable {
        FOLDER_TEXT
    } else if state.is_err() {
        UNREADABLE_TEXT
    } else if invalid_version {
        INVALID_VERSION_TEXT
    } else if enabled {
        ON_TEXT
    } else {
        OFF_TEXT
    };
    serde_json::json!({"enabled":enabled, "readable":state.is_ok(), "label":SWITCH_LABEL,
        "save_error": SAVE_ERROR, "message": message})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BackgroundRequest {
    enabled: bool,
}

pub(super) async fn set_background(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<BackgroundRequest>,
) -> Response {
    let launch =
        match require_home_launch_token_binding(&state.data_dir, &headers, &[SYSTEM_CAPSULE_ID]) {
            Ok(launch) => launch,
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error":"Open System from Home and sign in again."})),
                )
                    .into_response()
            }
        };
    if require_admin_principal(&state.data_dir, &launch.context).is_err() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"Ask the Home owner to change background checks."})),
        )
            .into_response();
    }
    let result = (|| -> anyhow::Result<()> {
        let (path, _lock) = locked_path(&state.data_dir)?;
        let mut settings = match read_state(&path) {
            Ok(settings) => settings,
            Err(_) if input.enabled => NoticeState::default(),
            Err(error) => return Err(error),
        };
        settings.background_checks = input.enabled;
        write_state(&path, &settings)
    })();
    match result {
        Ok(()) => Json(preference(&state.data_dir)).into_response(),
        Err(_) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": SAVE_ERROR})),
        )
            .into_response(),
    }
}

pub(super) async fn notification(
    data_dir: &Path,
    context: &HomeLaunchTokenContext,
) -> Option<HomeNotificationEntrySummary> {
    let cache = update::update_check_cache();
    notification_with_cache(data_dir, context, &cache).await
}

pub(super) async fn notification_with_cache(
    data_dir: &Path,
    context: &HomeLaunchTokenContext,
    cache: &tokio::sync::Mutex<UpdateCheckCache>,
) -> Option<HomeNotificationEntrySummary> {
    let (controller, source, key) = update::update_inputs(data_dir)?;
    let offer = cache.lock().await.confirmed_offer(&key, &source).await?;
    let view = update::update_account_view(
        data_dir,
        context,
        &controller,
        &source,
        Some(&offer.check),
        false,
    )?;
    if view["can_apply"] != true {
        return None;
    }
    let release = offer.check.release_cid.as_deref()?;
    let (path, _lock) = locked_path(data_dir).ok()?;
    let mut state = read_state(&path).ok()?;
    if state.release_cid.as_deref() != Some(release) {
        state.release_cid = Some(release.into());
        state.accounts.clear();
        write_state(&path, &state).ok()?;
    }
    let account = state.accounts.get(&context.principal_id);
    if account.is_some_and(|account| account.dismissed) {
        return None;
    }
    Some(HomeNotificationEntrySummary {
        id: format!("home-update:{release}"),
        source_app: SYSTEM_CAPSULE_ID.into(),
        kind: "home_update_available".into(),
        title: NOTICE_TITLE.into(),
        body: NOTICE_BODY.replace("{version}", &offer.check.latest_version),
        severity: "info".into(),
        read: account.is_some_and(|account| account.read),
        created_at: offer.observed_at,
        action_ref: None,
    })
}

pub(super) async fn acknowledge(
    data_dir: &Path,
    context: &HomeLaunchTokenContext,
    action: &str,
) -> anyhow::Result<String> {
    require_admin_principal(data_dir, context)?;
    let (release, dismiss) =
        if let Some(release) = action.strip_prefix("notification-read:home-update:") {
            (release, false)
        } else if let Some(release) = action.strip_prefix("notification-dismiss:home-update:") {
            (release, true)
        } else {
            anyhow::bail!("unsupported update notice action");
        };
    anyhow::ensure!(
        cid::Cid::try_from(release).is_ok(),
        "invalid update notice identity"
    );
    let (path, _lock) = locked_path(data_dir)?;
    let mut state = read_state(&path)?;
    if state.release_cid.as_deref() == Some(release) {
        anyhow::ensure!(
            state.accounts.contains_key(&context.principal_id) || state.accounts.len() < 256,
            "too many update acknowledgements"
        );
        let account = state
            .accounts
            .entry(context.principal_id.clone())
            .or_default();
        account.read = true;
        account.dismissed |= dismiss;
        write_state(&path, &state)?;
    }
    Ok("Saved update notice choice.".into())
}

pub(super) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) struct UpdateNoticeTask {
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

pub(super) fn start(data_dir: PathBuf) -> UpdateNoticeTask {
    start_with(
        data_dir,
        update::update_check_cache(),
        now_secs,
        || rand::Rng::gen_range(&mut rand::thread_rng(), 0..=3600),
        update::check_current_policy,
    )
}

pub(super) fn start_with<F, O>(
    data_dir: PathBuf,
    cache: std::sync::Arc<tokio::sync::Mutex<UpdateCheckCache>>,
    clock: impl Fn() -> u64 + Send + 'static,
    spread: impl FnMut() -> u64 + Send + 'static,
    work: impl Fn(PathBuf, String, crate::sources::TrustedSource) -> F + Send + Sync + 'static,
) -> UpdateNoticeTask
where
    F: std::future::Future<Output = O> + Send + 'static,
    O: Into<update::CheckOutcome> + Send + 'static,
{
    let (shutdown, receiver) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        run(data_dir.clone(), &cache, receiver, clock, spread, work).await;
        UpdateCheckCache::cancel_for_home(&cache, &data_dir).await;
    });
    UpdateNoticeTask { shutdown, task }
}

impl UpdateNoticeTask {
    pub(super) async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let _ = self.task.await;
    }
}

// The production task and tests use this same loop. Wall time, rather than a
// long timer, makes one overdue check due after sleep; missed turns are skipped.
pub(super) async fn run<F, O>(
    data_dir: PathBuf,
    cache: &tokio::sync::Mutex<UpdateCheckCache>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    clock: impl Fn() -> u64,
    mut spread: impl FnMut() -> u64,
    work: impl Fn(PathBuf, String, crate::sources::TrustedSource) -> F,
) where
    F: std::future::Future<Output = O> + Send + 'static,
    O: Into<update::CheckOutcome> + Send + 'static,
{
    let mut due = clock().saturating_add(FIRST_WAIT + spread().min(MAX_SPREAD) / 20);
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if *shutdown.borrow() {
            return;
        }
        tokio::select! {
            biased;
            changed = shutdown.changed() => { if changed.is_err() || *shutdown.borrow() { return; } }
            _ = tick.tick() => {}
        }
        if clock() < due || preference(&data_dir)["enabled"] != true {
            continue;
        }
        let delay = CHECK_INTERVAL + spread().min(MAX_SPREAD);
        loop {
            let Some((_, source, key)) = update::update_inputs(&data_dir) else {
                break;
            };
            if crate::update::installed_release_version(&source.installed_version).is_err() {
                break;
            }
            let check = UpdateCheckCache::check_and_store(cache, key.clone(), || {
                work(
                    key.data_dir.clone(),
                    key.source_policy_sha256.clone(),
                    source,
                )
            });
            let checked = tokio::select! {
                biased;
                _ = shutdown.changed() => { return; }
                checked = check => checked,
            };
            if preference(&data_dir)["enabled"] != true {
                break;
            }
            if !checked
                || update::update_inputs(&data_dir).is_some_and(|(_, _, current)| current != key)
            {
                continue;
            }
            break;
        }
        due = clock().saturating_add(delay);
    }
}

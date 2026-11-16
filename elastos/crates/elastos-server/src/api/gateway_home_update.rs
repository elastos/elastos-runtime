//! System owners choose an update channel or queue one exact signed update.

use super::*;

const UPDATE_OPERATION: &str = "system.update.apply";
const CHANNEL_OPERATION: &str = "system.source.switch-channel";
const CHECK_CACHE_SECONDS: u64 = 30;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SystemSourceChannelRequest {
    source_name: String,
    channel: String,
    step_up_token: String,
}

pub(super) async fn system_source_switch_channel(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<SystemSourceChannelRequest>,
) -> Response {
    let launch =
        match require_home_launch_token_binding(&state.data_dir, &headers, &[SYSTEM_CAPSULE_ID]) {
            Ok(launch) => launch,
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error":"Open System from Home and sign in again."
                    })),
                )
                    .into_response()
            }
        };
    if require_admin_principal(&state.data_dir, &launch.context).is_err() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error":"Ask the Home owner to choose the update channel."
            })),
        )
            .into_response();
    }
    if crate::sources::validate_update_channel(&input.channel).is_err()
        || input.source_name.is_empty()
        || input.source_name.len() > 512
        || input.source_name.chars().any(char::is_control)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error":"Choose a configured source and a supported update channel."
            })),
        )
            .into_response();
    }
    let intent = serde_json::json!({"source_name":input.source_name, "channel":input.channel});
    if consume_passkey_step_up_token(
        &state.data_dir,
        &input.step_up_token,
        &launch,
        180,
        CHANNEL_OPERATION,
        &intent,
    )
    .is_err()
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error":"Verify your passkey again to change the update channel."
            })),
        )
            .into_response();
    }
    match crate::sources::switch_source_channel(&state.data_dir, Some(&input.source_name),
        &input.channel, crate::sources::source_discovery_uri)
    {
        Ok(source) => Json(serde_json::json!({
            "source_name":source.name, "channel":source.channel,
            "installed_version":source.installed_version,
        })).into_response(),
        Err(_) => (StatusCode::CONFLICT, Json(serde_json::json!({
            "error":"The update channel could not be saved. Wait for any Home update to finish, then open System and try again."
        }))).into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SystemUpdateApplyRequest {
    action: String,
    request_id: String,
    source_name: String,
    channel: String,
    publisher_did: String,
    current_version: String,
    new_version: String,
    head_cid: String,
    release_cid: String,
    step_up_token: String,
}

impl SystemUpdateApplyRequest {
    fn intent(&self) -> serde_json::Value {
        serde_json::json!({
            "action":self.action,
            "request_id":self.request_id,
            "source_name":self.source_name,
            "channel":self.channel,
            "publisher_did":self.publisher_did,
            "current_version":self.current_version,
            "new_version":self.new_version,
            "head_cid":self.head_cid,
            "release_cid":self.release_cid,
        })
    }

    fn request(&self) -> anyhow::Result<crate::update_controller::UpdateRequest> {
        anyhow::ensure!(self.action == "apply", "unsupported Home update action");
        anyhow::ensure!(
            self.request_id.len() == 32
                && self.request_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid Home update request identity"
        );
        for text in [
            &self.source_name,
            &self.channel,
            &self.publisher_did,
            &self.current_version,
            &self.new_version,
            &self.head_cid,
            &self.release_cid,
        ] {
            anyhow::ensure!(
                !text.is_empty() && text.len() <= 512 && !text.chars().any(char::is_control),
                "invalid Home update choice"
            );
        }
        Ok(crate::update_controller::UpdateRequest {
            id: self.request_id.clone(),
            source_name: self.source_name.clone(),
            channel: self.channel.clone(),
            publisher_did: self.publisher_did.clone(),
            current_version: self.current_version.clone(),
            new_version: self.new_version.clone(),
            head_cid: self.head_cid.clone(),
            release_cid: self.release_cid.clone(),
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct UpdateCheckKey {
    pub(super) data_dir: std::path::PathBuf,
    pub(super) source_policy_sha256: String,
}

struct CachedCheck {
    key: UpdateCheckKey,
    completed_at: std::time::Instant,
    check: Option<crate::operator_control::OperatorUpdateCheck>,
    unavailable: bool,
    observed_at: u64,
}

struct RunningCheck {
    key: UpdateCheckKey,
    task: tokio::task::JoinHandle<CachedCheck>,
}

pub(super) enum UpdateCheckSnapshot {
    Checking,
    Completed(Option<Box<crate::operator_control::OperatorUpdateCheck>>),
}

pub(super) enum CheckOutcome {
    Confirmed(Box<crate::operator_control::OperatorUpdateCheck>),
    Unavailable,
    Rejected,
}

impl From<Option<crate::operator_control::OperatorUpdateCheck>> for CheckOutcome {
    fn from(check: Option<crate::operator_control::OperatorUpdateCheck>) -> Self {
        check
            .map(|check| Self::Confirmed(Box::new(check)))
            .unwrap_or(Self::Rejected)
    }
}

#[derive(Clone)]
pub(super) struct ConfirmedOffer {
    key: UpdateCheckKey,
    pub(super) check: crate::operator_control::OperatorUpdateCheck,
    pub(super) observed_at: u64,
}

#[derive(Default)]
pub(super) struct UpdateCheckCache {
    completed: Option<CachedCheck>,
    running: Option<RunningCheck>,
    confirmed: Option<ConfirmedOffer>,
}

impl UpdateCheckCache {
    #[cfg(test)]
    pub(super) fn expire_response(&mut self) {
        self.completed = None;
    }

    /// A request only joins a task which has already finished. Policy changes
    /// keep the current worker until it drains, then admit one new worker.
    pub(super) async fn read<F, O>(
        &mut self,
        key: UpdateCheckKey,
        now: std::time::Instant,
        work: impl FnOnce() -> F,
    ) -> UpdateCheckSnapshot
    where
        F: std::future::Future<Output = O> + Send + 'static,
        O: Into<CheckOutcome> + Send + 'static,
    {
        self.collect_finished(now).await;
        self.reconcile_key(&key);
        if let Some(completed) = self.completed.as_ref().filter(|completed| {
            completed.key == key
                && now.saturating_duration_since(completed.completed_at)
                    < std::time::Duration::from_secs(CHECK_CACHE_SECONDS)
        }) {
            return UpdateCheckSnapshot::Completed(completed.check.clone().map(Box::new));
        }
        if self.running.is_none() {
            let task_key = key.clone();
            let check = work();
            self.running = Some(RunningCheck {
                key,
                task: tokio::spawn(async move {
                    let outcome = check.await.into();
                    let unavailable = matches!(outcome, CheckOutcome::Unavailable);
                    let check = match outcome {
                        CheckOutcome::Confirmed(check) => Some(*check),
                        _ => None,
                    };
                    CachedCheck {
                        key: task_key,
                        completed_at: std::time::Instant::now(),
                        check,
                        unavailable,
                        observed_at: gateway_update_notice::now_secs(),
                    }
                }),
            });
        }
        UpdateCheckSnapshot::Checking
    }

    pub(super) async fn cancel_for_home(
        cache: &tokio::sync::Mutex<Self>,
        data_dir: &std::path::Path,
    ) {
        let task = {
            let mut cache = cache.lock().await;
            if cache
                .running
                .as_ref()
                .is_some_and(|running| running.key.data_dir == data_dir)
            {
                cache.running.take().map(|running| running.task)
            } else {
                None
            }
        };
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }

    async fn collect_finished(&mut self, now: std::time::Instant) {
        if self
            .running
            .as_ref()
            .is_some_and(|running| running.task.is_finished())
        {
            let running = self.running.take().expect("finished update check is owned");
            let completed = running.task.await.unwrap_or(CachedCheck {
                key: running.key,
                completed_at: now,
                check: None,
                unavailable: false,
                observed_at: gateway_update_notice::now_secs(),
            });
            if let Some(check) = &completed.check {
                self.confirmed = Some(ConfirmedOffer {
                    key: completed.key.clone(),
                    check: check.clone(),
                    observed_at: completed.observed_at,
                });
            } else if !completed.unavailable {
                self.confirmed = None;
            }
            self.completed = Some(completed);
        }
    }

    fn reconcile_key(&mut self, key: &UpdateCheckKey) {
        if self
            .confirmed
            .as_ref()
            .is_some_and(|offer| offer.key != *key)
        {
            self.confirmed = None;
        }
    }

    // Await outside the mutex: System keeps its non-blocking read contract.
    pub(super) async fn check_and_store<F, O>(
        cache: &tokio::sync::Mutex<Self>,
        key: UpdateCheckKey,
        work: impl FnOnce() -> F,
    ) where
        F: std::future::Future<Output = O> + Send + 'static,
        O: Into<CheckOutcome> + Send + 'static,
    {
        if matches!(
            cache
                .lock()
                .await
                .read(key.clone(), std::time::Instant::now(), work)
                .await,
            UpdateCheckSnapshot::Completed(_)
        ) {
            return;
        }
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let mut cache = cache.lock().await;
            cache.collect_finished(std::time::Instant::now()).await;
            cache.reconcile_key(&key);
            if cache.running.is_none() {
                return;
            }
        }
    }

    pub(super) async fn confirmed_offer(
        &mut self,
        key: &UpdateCheckKey,
        source: &crate::sources::TrustedSource,
    ) -> Option<ConfirmedOffer> {
        self.collect_finished(std::time::Instant::now()).await;
        self.reconcile_key(key);
        if self
            .confirmed
            .as_ref()
            .is_some_and(|offer| !check_matches_source(source, &offer.check))
        {
            self.confirmed = None;
        }
        self.confirmed.clone()
    }
}

static UPDATE_CHECK: std::sync::OnceLock<std::sync::Arc<tokio::sync::Mutex<UpdateCheckCache>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
tokio::task_local! {
    static TEST_CHECK_CACHE: std::sync::Arc<tokio::sync::Mutex<UpdateCheckCache>>;
}

// A route fixture represents a separate Home process. Its account and task
// journeys share one cache, while parallel fixtures retain their own state.
#[cfg(test)]
pub(super) async fn with_test_check_cache<T>(future: impl std::future::Future<Output = T>) -> T {
    TEST_CHECK_CACHE
        .scope(
            std::sync::Arc::new(tokio::sync::Mutex::new(UpdateCheckCache::default())),
            future,
        )
        .await
}

pub(super) fn update_check_cache() -> std::sync::Arc<tokio::sync::Mutex<UpdateCheckCache>> {
    #[cfg(test)]
    if let Ok(cache) = TEST_CHECK_CACHE.try_with(std::sync::Arc::clone) {
        return cache;
    }
    UPDATE_CHECK
        .get_or_init(|| std::sync::Arc::new(tokio::sync::Mutex::new(UpdateCheckCache::default())))
        .clone()
}

pub(super) fn source_policy_sha256(
    config: &crate::sources::TrustedSourcesConfig,
) -> Option<String> {
    Some(hex::encode(Sha256::digest(
        serde_json::to_vec(config).ok()?,
    )))
}

pub(super) async fn check_current_policy(
    data_dir: std::path::PathBuf,
    policy_sha256: String,
    source: crate::sources::TrustedSource,
) -> CheckOutcome {
    let policy_matches = || {
        crate::sources::load_trusted_sources(&data_dir)
            .ok()
            .and_then(|config| source_policy_sha256(&config))
            .is_some_and(|current| current == policy_sha256)
    };
    if !policy_matches() {
        return CheckOutcome::Rejected;
    }
    let result = crate::operator_control::gather_local_update_check(&data_dir).await;
    if !policy_matches() {
        return CheckOutcome::Rejected;
    }
    checked_outcome(&source, result)
}

pub(super) fn checked_outcome(
    source: &crate::sources::TrustedSource,
    result: anyhow::Result<crate::operator_control::OperatorUpdateCheck>,
) -> CheckOutcome {
    match result {
        Ok(check) if check_matches_source(source, &check) => {
            CheckOutcome::Confirmed(Box::new(check))
        }
        Err(error) if error.is::<crate::update::UpdateSourceUnavailable>() => {
            CheckOutcome::Unavailable
        }
        _ => CheckOutcome::Rejected,
    }
}

pub(super) fn check_matches_source(
    source: &crate::sources::TrustedSource,
    check: &crate::operator_control::OperatorUpdateCheck,
) -> bool {
    // The offer carries its signed channel; the source's policy admits it.
    check.source_name == source.name
        && crate::update::verify_source_channel(source, &check.channel).is_ok()
        && check.current_version == source.installed_version
        && source.publisher_dids.contains(&check.publisher_did)
}

pub(super) async fn system_runtime_update_summary(
    data_dir: &std::path::Path,
    context: &HomeLaunchTokenContext,
) -> Option<serde_json::Value> {
    let cache = update_check_cache();
    system_runtime_update_summary_with_cache(data_dir, context, &cache, check_current_policy).await
}

pub(super) async fn system_runtime_update_summary_with_cache<F, O>(
    data_dir: &std::path::Path,
    context: &HomeLaunchTokenContext,
    cache: &tokio::sync::Mutex<UpdateCheckCache>,
    work: impl FnOnce(std::path::PathBuf, String, crate::sources::TrustedSource) -> F,
) -> Option<serde_json::Value>
where
    F: std::future::Future<Output = O> + Send + 'static,
    O: Into<CheckOutcome> + Send + 'static,
{
    if require_admin_principal(data_dir, context).is_err() {
        return None;
    }
    let (controller, source, key) = update_inputs(data_dir)?;
    if crate::update::installed_release_version(&source.installed_version).is_err() {
        return Some(serde_json::json!({
            "configured":true, "checking":false, "available":false, "can_apply":false,
            "current_version":source.installed_version,
            "message":crate::update::InvalidInstalledVersion.to_string(),
            "background_checks": gateway_update_notice::preference(data_dir),
        }));
    }
    let worker_key = key.clone();
    let worker_source = source.clone();
    let snapshot = cache
        .lock()
        .await
        .read(key, std::time::Instant::now(), || {
            work(
                worker_key.data_dir,
                worker_key.source_policy_sha256,
                worker_source,
            )
        })
        .await;
    let checking = matches!(snapshot, UpdateCheckSnapshot::Checking);
    let check = match &snapshot {
        UpdateCheckSnapshot::Checking => None,
        UpdateCheckSnapshot::Completed(check) => check.as_deref(),
    };
    update_account_view(data_dir, context, &controller, &source, check, checking)
}

pub(super) fn update_inputs(
    data_dir: &std::path::Path,
) -> Option<(
    crate::update_controller::UpdateStatus,
    crate::sources::TrustedSource,
    UpdateCheckKey,
)> {
    let controller = crate::update_controller::status(data_dir).ok()??;
    let config = crate::sources::load_trusted_sources(data_dir).ok()?;
    let source = config.default_source()?.clone();
    if source.installed_version.is_empty() || source.publisher_dids.is_empty() {
        return None;
    }
    let key = UpdateCheckKey {
        data_dir: data_dir.into(),
        source_policy_sha256: source_policy_sha256(&config)?,
    };
    Some((controller, source, key))
}

pub(super) fn update_account_view(
    data_dir: &std::path::Path,
    context: &HomeLaunchTokenContext,
    controller: &crate::update_controller::UpdateStatus,
    source: &crate::sources::TrustedSource,
    check: Option<&crate::operator_control::OperatorUpdateCheck>,
    checking: bool,
) -> Option<serde_json::Value> {
    if require_admin_principal(data_dir, context).is_err() {
        return None;
    }
    // A refused release can never install; offer again only when a different one appears.
    let refused = match check {
        Some(crate::operator_control::OperatorUpdateCheck {
            head_cid: Some(head_cid),
            release_cid: Some(release_cid),
            ..
        }) => crate::update_controller::release_refused(data_dir, head_cid, release_cid).ok()?,
        _ => false,
    };
    let available = !refused && check.is_some_and(|check| check.update_available);
    let can_apply = available
        && require_admin_principal(data_dir, context).is_ok()
        && check.is_some_and(|check| check.head_cid.is_some() && check.release_cid.is_some())
        && controller.host_pid.is_some()
        && crate::update_controller::has_queued_update(data_dir).is_ok_and(|pending| !pending)
        && matches!(
            controller.phase.as_str(),
            "ready" | "updated" | "restored" | "failed"
        )
        && !crate::install_transaction::InstallTransaction::has_pending_recovery(
            std::path::Path::new(&source.install_path),
        );
    Some(serde_json::json!({
        "configured":true,
        "background_checks": gateway_update_notice::preference(data_dir),
        "checking":checking,
        "available":available,
        "can_apply":can_apply,
        "current_version":source.installed_version,
        "new_version":check.map(|check|check.latest_version.as_str()),
        "publisher":check.map(|check|check.publisher_did.as_str()),
        "publisher_did":check.map(|check|check.publisher_did.as_str()),
        "source_name":check.map(|check|check.source_name.as_str()),
        "channel":check.map(|check|check.channel.as_str()),
        "head_cid":check.and_then(|check|check.head_cid.as_deref()),
        "release_cid":check.and_then(|check|check.release_cid.as_deref()),
        "changes":check.map(|check|check.changes.as_slice()).unwrap_or_default(),
        "message":match check {
            None if checking => "Checking for updates.",
            Some(check) if check.update_available && refused => crate::update_controller::REFUSED_MESSAGE,
            Some(check) if check.update_available => "An update is available.",
            Some(check) if check.version_status == crate::operator_control::UpdateVersionStatus::InstalledNewer
                && source.channel == "stable"
                && semver::Version::parse(&check.current_version).is_ok_and(|version| !version.pre.is_empty())
                => "Home has a newer test version than the latest stable release. The next newer stable release will be offered.",
            Some(check) if check.version_status == crate::operator_control::UpdateVersionStatus::InstalledNewer
                => "Home has a newer version than the latest release on this channel. The next newer release will be offered.",
            Some(_) => "Home is up to date.",
            None => "Could not check for updates. Check again when Carrier is connected.",
        },
        "controller":{
            "id":controller.id,
            "phase":controller.phase,
            "current_version":controller.current_version,
            "new_version":controller.new_version,
            "message":controller.message,
            "completed_bytes":controller.completed_bytes,
            "total_bytes":controller.total_bytes,
        },
    }))
}

pub(super) async fn system_update_apply(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<SystemUpdateApplyRequest>,
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
            Json(serde_json::json!({"error":"Ask the Home owner to install this update."})),
        )
            .into_response();
    }
    let result = system_update_apply_inner(&state, &launch, &input).await;
    match result {
        Ok(response) => Json(response).into_response(),
        Err(error) => system_update_failure(&error),
    }
}

pub(super) fn system_update_failure(error: &anyhow::Error) -> Response {
    let (status, message) = if error.is::<crate::update::UpdateSourceUnavailable>() {
        (StatusCode::FAILED_DEPENDENCY, "Home could not reach the update source. Your current version is unchanged. Connect to the internet and select Update again.")
    } else if error.is::<crate::update_controller::UpdateInProgress>() {
        (StatusCode::LOCKED, "Another update was started on this Home. Wait for it to finish, then check the update again.")
    } else if error.is::<crate::update_controller::ApprovalReplaced>() {
        (StatusCode::GONE, "This approval is no longer valid. Check for the update again and approve it once more.")
    } else if error.is::<crate::update::InvalidInstalledVersion>() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error":crate::update::InvalidInstalledVersion.to_string(),
            })),
        )
            .into_response();
    } else {
        (StatusCode::CONFLICT, "The update could not start: the release was refused or verification failed. Select Update again.")
    };
    (status, Json(serde_json::json!({"error":message}))).into_response()
}

async fn system_update_apply_inner(
    state: &GatewayState,
    launch: &RequiredHomeLaunchToken,
    input: &SystemUpdateApplyRequest,
) -> anyhow::Result<serde_json::Value> {
    let sources = crate::sources::load_trusted_sources(&state.data_dir)?;
    if let Some(source) = sources.default_source() {
        crate::update::installed_release_version(&source.installed_version)?;
    }
    let request = input.request()?;
    anyhow::ensure!(
        !crate::update_controller::release_refused(
            &state.data_dir,
            &request.head_cid,
            &request.release_cid
        )?,
        "Home refused this release"
    );
    let intent = input.intent();
    let effect = consume_prepared_passkey_step_up_effect(
        &state.data_dir,
        &input.step_up_token,
        launch,
        180,
        UPDATE_OPERATION,
        &intent,
        |effect| {
            crate::update_controller::reserve_owner_update(
                &state.data_dir,
                &request,
                &effect.step_up_id,
                &effect.request_sha256,
                effect.recovered,
            )
        },
    )?;
    if !crate::update_controller::owner_update_is_queued(
        &state.data_dir,
        &request,
        &effect.step_up_id,
        &effect.request_sha256,
    )? {
        let check = crate::operator_control::gather_local_update_check(&state.data_dir).await?;
        anyhow::ensure!(
            choice_matches(&request, &check),
            "Home update choice changed"
        );
    }
    crate::update_controller::queue_owner_update(
        &state.data_dir,
        request.clone(),
        &effect.step_up_id,
        &effect.request_sha256,
    )?;
    Ok(serde_json::json!({
        "id":request.id,
        "phase":"queued",
        "message":"The update is queued. Home will reconnect after Runtime restarts.",
    }))
}

pub(super) fn choice_matches(
    request: &crate::update_controller::UpdateRequest,
    check: &crate::operator_control::OperatorUpdateCheck,
) -> bool {
    check.update_available
        && request.source_name == check.source_name
        && request.channel == check.channel
        && request.publisher_did == check.publisher_did
        && request.current_version == check.current_version
        && request.new_version == check.latest_version
        && Some(request.head_cid.as_str()) == check.head_cid.as_deref()
        && Some(request.release_cid.as_str()) == check.release_cid.as_deref()
}

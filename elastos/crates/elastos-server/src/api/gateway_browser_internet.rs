//! Home consent and per-launch Browser internet authority. Public records contain no bearer token.
use super::*;
use elastos_runtime::capability::{
    Action, CapabilityManager, CapabilityToken, ResourceId, TokenConstraints,
};
use elastos_runtime::provider::dispatch::DispatchFence;
use std::io::Read;
use tokio::sync::{watch, Mutex};

pub(super) const RESOURCE: &str = "elastos://browser/internet";
pub(super) const GRANT_OPERATION: &str = "browser.internet.grant";
pub(super) const REVOKE_OPERATION: &str = "browser.internet.revoke";
pub(super) const CONSENT_TEXT: &str =
    "Browser opens websites using this computer's internet connection, or another connection you chose in Browser settings. Websites can see that connection's address. You can turn this off at any time here in Inbox.";
const RECORD: &str = "browser-internet.json";
const TOKEN: &str = "browser-internet-token.json";
const REQUEST_TTL: u64 = 1800;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Consent {
    Requested {
        request_id: String,
        expires_at: u64,
        at: u64,
    },
    Granted {
        // Correlates a waiting window with the answer; older grants stay valid.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        token_id: String,
        owner: InternetOwner,
        at: u64,
    },
    Refused {
        request_id: String,
        by_principal_id: String,
        at: u64,
    },
    Revoked {
        token_id: String,
        by_principal_id: String,
        at: u64,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InternetOwner {
    principal_id: String,
    proof_binding_id: String,
}
impl InternetOwner {
    fn validate(&self, data: &FsPath) -> anyhow::Result<()> {
        let principal =
            crate::auth::load_principal_for_proof_binding(data, &self.proof_binding_id)?;
        crate::auth::ensure_proof_binding_not_revoked(&principal)?;
        anyhow::ensure!(
            principal.principal_id == self.principal_id && crate::auth::is_admin(&principal),
            "Browser internet owner must still be an admin"
        );
        Ok(())
    }
}

#[derive(Clone)]
struct Instance {
    principal_id: String,
    session_id: String,
    cancel: watch::Sender<bool>,
    copies: Arc<watch::Sender<usize>>,
}
struct Generation {
    token_id: String,
    fence: DispatchFence,
    instances: BTreeMap<String, Instance>,
}
#[derive(Default)]
pub(crate) struct BrowserInternetService {
    manager: Option<Arc<CapabilityManager>>,
    generation: Mutex<Option<Generation>>,
}
impl BrowserInternetService {
    pub(crate) fn new(manager: Option<Arc<CapabilityManager>>) -> Self {
        Self {
            manager,
            generation: Mutex::new(None),
        }
    }
}

#[derive(Clone)]
pub(super) struct BrowserInternetEffect {
    pub(super) fence: DispatchFence,
    pub(super) cancelled: watch::Receiver<bool>,
    copies: Arc<watch::Sender<usize>>,
}

pub(super) struct InternetCopy(Arc<watch::Sender<usize>>);
impl Drop for InternetCopy {
    fn drop(&mut self) {
        self.0.send_modify(|count| *count -= 1);
    }
}
impl BrowserInternetEffect {
    // The caller holds this read guard through listener registration. Stop owns
    // the write barrier after it signals cancellation, then waits for all copies.
    pub(super) async fn register_copy(
        &self,
    ) -> anyhow::Result<(tokio::sync::OwnedRwLockReadGuard<bool>, InternetCopy)> {
        let guard = self.fence.enter().await.map_err(anyhow::Error::msg)?;
        self.copies.send_modify(|count| *count += 1);
        Ok((guard, InternetCopy(self.copies.clone())))
    }
}
async fn drain_instance(instance: &Instance) -> anyhow::Result<()> {
    let mut copies = instance.copies.subscribe();
    tokio::time::timeout(Duration::from_secs(2), copies.wait_for(|count| *count == 0))
        .await
        .map_err(|_| anyhow::anyhow!("Browser internet copies are still closing"))?
        .map_err(|_| anyhow::anyhow!("Browser internet copy owner disappeared"))?;
    Ok(())
}

async fn retire_generation(generation: &Generation) -> anyhow::Result<()> {
    // Publish cancellation synchronously before any await. Keep the generation
    // registered until every barrier and drain succeeds, including on retry.
    for instance in generation.instances.values() {
        instance.cancel.send_replace(true);
    }
    tokio::time::timeout(Duration::from_secs(2), generation.fence.revoke())
        .await
        .map_err(|_| anyhow::anyhow!("Browser provider dispatch is still stopping"))?;
    for instance in generation.instances.values() {
        drain_instance(instance).await?;
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::api::gateway) fn granted_fixture(
    data: &FsPath,
    principal_id: &str,
    proof_binding_id: &str,
) -> Arc<BrowserInternetService> {
    use elastos_runtime::capability::CapabilityStore;
    use elastos_runtime::primitives::{audit::AuditLog, metrics::MetricsManager};
    let manager = Arc::new(CapabilityManager::new(
        Arc::new(CapabilityStore::new()),
        Arc::new(AuditLog::new()),
        Arc::new(MetricsManager::new()),
    ));
    let token = manager.grant(
        principal_id,
        ResourceId::new(RESOURCE),
        Action::Execute,
        TokenConstraints::default(),
        None,
    );
    crate::auth::atomic_write(
        &data.join(TOKEN),
        &serde_json::to_vec(&token.to_base64().unwrap()).unwrap(),
    )
    .unwrap();
    save(
        data,
        &Consent::Granted {
            request_id: None,
            token_id: token.id().to_string(),
            owner: InternetOwner {
                principal_id: principal_id.into(),
                proof_binding_id: proof_binding_id.into(),
            },
            at: now_ts(),
        },
    )
    .unwrap();
    Arc::new(BrowserInternetService::new(Some(manager)))
}

#[cfg(test)]
pub(in crate::api::gateway) fn transport_fixture() -> BrowserInternetEffect {
    let (keepalive, cancelled) = watch::channel(false);
    BrowserInternetEffect {
        fence: DispatchFence::new(move || {
            let _ = &keepalive;
            Ok(())
        }),
        cancelled,
        copies: Arc::new(watch::channel(0).0),
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &FsPath) -> anyhow::Result<Option<T>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "Browser internet state must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(8193).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 8192, "Browser internet state is too large");
    Ok(Some(serde_json::from_slice(&bytes)?))
}
fn load(data: &FsPath) -> anyhow::Result<Option<Consent>> {
    read_json(&data.join(RECORD))
}
fn save(data: &FsPath, record: &Consent) -> anyhow::Result<()> {
    crate::auth::atomic_write(&data.join(RECORD), &serde_json::to_vec(record)?)
}
fn requested() -> Consent {
    let at = now_ts();
    Consent::Requested {
        request_id: gateway_home_token::uuid_like_token(),
        expires_at: at + REQUEST_TTL,
        at,
    }
}
fn ended_path(data: &FsPath, launch: &str) -> PathBuf {
    data.join("browser-internet-instances").join(format!(
        "{}.json",
        hex::encode(Sha256::digest(launch.as_bytes()))
    ))
}
fn grant_request(record: &Consent) -> anyhow::Result<serde_json::Value> {
    match record {
        Consent::Requested {
            request_id,
            expires_at,
            ..
        } if *expires_at > now_ts() => Ok(serde_json::json!({
            "resource": RESOURCE, "text": CONSENT_TEXT, "request_id": request_id, "expires_at": expires_at,
        })),
        _ => anyhow::bail!("Review the current Browser internet request in Inbox"),
    }
}
fn revoke_request(record: &Consent) -> anyhow::Result<serde_json::Value> {
    match record {
        Consent::Granted { token_id, at, .. } => Ok(serde_json::json!({
            "resource": RESOURCE, "text": "Stop Browser internet access on this computer.",
            "grant_id": token_id, "issued_at": at,
        })),
        _ => anyhow::bail!("Browser internet access is already off"),
    }
}
fn public_record(record: Option<&Consent>) -> serde_json::Value {
    match record {
        None => serde_json::json!({"status":"off"}),
        Some(record @ Consent::Requested { .. }) => {
            serde_json::json!({"status":"requested", "request":grant_request(record).ok()})
        }
        Some(record @ Consent::Granted { request_id, .. }) => {
            serde_json::json!({"status":"granted", "request_id":request_id, "request":revoke_request(record).ok()})
        }
        Some(Consent::Refused { .. }) => serde_json::json!({"status":"refused"}),
        Some(Consent::Revoked { .. }) => serde_json::json!({"status":"revoked"}),
    }
}

/// Begin and consume use the same Runtime-owned request. Caller text has no authority.
pub(super) async fn step_up_request(
    state: &GatewayState,
    launch: &RequiredHomeLaunchToken,
    operation: &str,
) -> anyhow::Result<serde_json::Value> {
    ensure_admin_context(&state.data_dir, &launch.context)?;
    let _guard = state.browser_internet.generation.lock().await;
    let record = load(&state.data_dir)?
        .ok_or_else(|| anyhow::anyhow!("Open Browser to request internet access"))?;
    match operation {
        GRANT_OPERATION => grant_request(&record),
        REVOKE_OPERATION => revoke_request(&record),
        _ => anyhow::bail!("Invalid Browser internet operation"),
    }
}

pub(super) async fn answer(
    state: &GatewayState,
    launch: &RequiredHomeLaunchToken,
    action_id: &str,
    token: Option<&str>,
) -> anyhow::Result<String> {
    ensure_admin_context(&state.data_dir, &launch.context)?;
    anyhow::ensure!(
        launch.launch_context.executable_actor == INBOX_CAPSULE_ID,
        "Inbox launch required"
    );
    if let Some(id) = action_id.strip_prefix("browser-internet-turn-off:") {
        revoke(state, launch, Some(id), token).await?;
        return Ok("Browser cannot open websites. Turned off.".into());
    }
    // Deny, replacement request, step-up consume and grant commit share this lock.
    let _guard = state.browser_internet.generation.lock().await;
    let (allow, id) = if let Some(id) = action_id.strip_prefix("browser-internet-allow:") {
        (true, id)
    } else if let Some(id) = action_id.strip_prefix("browser-internet-deny:") {
        (false, id)
    } else {
        anyhow::bail!("Invalid Browser internet answer")
    };
    let record = load(&state.data_dir)?
        .ok_or_else(|| anyhow::anyhow!("Browser internet request is missing"))?;
    let request = grant_request(&record)?;
    anyhow::ensure!(
        request["request_id"].as_str() == Some(id),
        "Browser internet request has changed"
    );
    if !allow {
        save(
            &state.data_dir,
            &Consent::Refused {
                request_id: id.into(),
                by_principal_id: launch.context.principal_id.clone(),
                at: now_ts(),
            },
        )?;
        return Ok("Not allowed.".into());
    }
    let manager = state
        .browser_internet
        .manager
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Runtime internet authority is unavailable"))?;
    let proof_binding_id = launch
        .context
        .proof_binding_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Owner passkey proof is required"))?;
    consume_passkey_step_up_token(
        &state.data_dir,
        token.unwrap_or_default(),
        launch,
        180,
        GRANT_OPERATION,
        &request,
    )?;
    ensure_admin_context(&state.data_dir, &launch.context)?;
    let capability = manager.grant(
        &launch.context.principal_id,
        ResourceId::new(RESOURCE),
        Action::Execute,
        TokenConstraints::default(),
        None,
    );
    crate::auth::atomic_write(
        &state.data_dir.join(TOKEN),
        &serde_json::to_vec(&capability.to_base64().map_err(anyhow::Error::msg)?)?,
    )?;
    save(
        &state.data_dir,
        &Consent::Granted {
            request_id: Some(id.into()),
            token_id: capability.id().to_string(),
            owner: InternetOwner {
                principal_id: launch.context.principal_id.clone(),
                proof_binding_id,
            },
            at: now_ts(),
        },
    )?;
    Ok("Browser can open websites. Allowed with your passkey.".into())
}

pub(super) fn notification(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
) -> Option<HomeNotificationEntrySummary> {
    ensure_admin_context(&state.data_dir, context).ok()?;
    resolve_capsule_dir(&state.data_dir, BROWSER_CAPSULE_ID)?;
    let record = load(&state.data_dir).ok()??;
    let (at, body, action_id) = match &record {
        Consent::Requested { expires_at, at, .. } if *expires_at <= now_ts() => (
            *at,
            "This expired request was made.",
            "browser-internet-request".into(),
        ),
        Consent::Requested { request_id, at, .. } => {
            let request = grant_request(&record).ok()?;
            return Some(HomeNotificationEntrySummary {
                id: "browser-internet:permission".into(),
                source_app: BROWSER_CAPSULE_ID.into(),
                kind: "browser_internet_request".into(),
                title: "Allow Browser to use the internet?".into(),
                body: request["text"].as_str()?.into(),
                severity: "attention".into(),
                read: false,
                created_at: *at,
                action_ref: Some(HomeNotificationActionSummary {
                    app: INBOX_CAPSULE_ID.into(),
                    action_id: format!("browser-internet-allow:{request_id}"),
                }),
            });
        }
        Consent::Granted { at, token_id, .. } => (
            *at,
            "Browser can open websites. Allowed with your passkey.",
            format!("browser-internet-turn-off:{token_id}"),
        ),
        Consent::Refused { at, .. } => (
            *at,
            "Browser cannot open websites. Not allowed.",
            "browser-internet-request".into(),
        ),
        Consent::Revoked { at, token_id, .. } => (
            *at,
            "Browser cannot open websites. Turned off.",
            if state
                .browser_internet
                .generation
                .try_lock()
                .ok()
                .is_some_and(|live| live.is_some())
            {
                format!("browser-internet-turn-off:{token_id}")
            } else {
                "browser-internet-request".into()
            },
        ),
    };
    Some(HomeNotificationEntrySummary {
        id: "browser-internet:permission".into(),
        source_app: BROWSER_CAPSULE_ID.into(),
        kind: "browser_internet_decision".into(),
        title: "Browser internet access".into(),
        body: body.into(),
        severity: "info".into(),
        read: true,
        created_at: at,
        action_ref: Some(HomeNotificationActionSummary {
            app: INBOX_CAPSULE_ID.into(),
            action_id,
        }),
    })
}

pub(super) async fn effect_for_authority(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    request_missing: bool,
) -> anyhow::Result<BrowserInternetEffect> {
    effect(
        state,
        &authority.home_launch_context(),
        authority.verified_context().actor(),
        authority.verified_context().launch_id(),
        request_missing,
    )
    .await
}

pub(super) async fn effect(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
    actor: &str,
    launch: &str,
    request_missing: bool,
) -> anyhow::Result<BrowserInternetEffect> {
    anyhow::ensure!(
        actor == BROWSER_CAPSULE_ID && !launch.is_empty(),
        "Browser launch authority is required"
    );
    let mut live = state.browser_internet.generation.lock().await;
    let mut record = load(&state.data_dir)?;
    if request_missing
        && (record.is_none()
            || matches!(&record, Some(Consent::Requested {expires_at,..}) if *expires_at <= now_ts()))
    {
        let pending = requested();
        save(&state.data_dir, &pending)?;
        record = Some(pending);
    }
    let Some(Consent::Granted {
        token_id, owner, ..
    }) = record
    else {
        anyhow::bail!("Browser internet permission is required");
    };
    let checked = async {
        owner.validate(&state.data_dir)?;
        let manager = state
            .browser_internet
            .manager
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Runtime internet authority is unavailable"))?;
        let encoded: String = read_json(&state.data_dir.join(TOKEN))?
            .ok_or_else(|| anyhow::anyhow!("Browser internet capability is missing"))?;
        let token = CapabilityToken::from_base64(&encoded).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            token.id().to_string() == token_id,
            "Browser internet grant has changed"
        );
        manager
            .validate(
                &token,
                &owner.principal_id,
                Action::Execute,
                &ResourceId::new(RESOURCE),
                None,
            )
            .await?;
        Ok::<_, anyhow::Error>((manager.clone(), token))
    }
    .await;
    let (manager, token) = match checked {
        Ok(valid) => valid,
        Err(error) => {
            save(
                &state.data_dir,
                &Consent::Revoked {
                    token_id: token_id.clone(),
                    by_principal_id: owner.principal_id.clone(),
                    at: now_ts(),
                },
            )?;
            if let Some(old) = live.as_ref() {
                retire_generation(old).await?;
            }
            *live = None;
            return Err(error);
        }
    };
    anyhow::ensure!(
        read_json::<serde_json::Value>(&ended_path(&state.data_dir, launch))?.is_none(),
        "This Browser instance has ended"
    );
    if live.as_ref().is_none_or(|live| live.token_id != token_id) {
        if let Some(old) = live.as_ref() {
            retire_generation(old).await?;
        }
        let data = state.data_dir.clone();
        let expected = token_id.clone();
        let fence = DispatchFence::new(move || match load(&data).map_err(|e| e.to_string())? {
            Some(Consent::Granted {
                token_id, owner, ..
            }) if token_id == expected => owner.validate(&data).map_err(|e| e.to_string()),
            _ => Err("Browser internet access has stopped".into()),
        });
        let principal = owner.principal_id.clone();
        let fence = fence.with_async_check(move || {
            let manager = manager.clone();
            let token = token.clone();
            let principal = principal.clone();
            Box::pin(async move {
                manager
                    .validate(
                        &token,
                        &principal,
                        Action::Execute,
                        &ResourceId::new(RESOURCE),
                        None,
                    )
                    .await
                    .map_err(|error| error.to_string())
            })
        });
        *live = Some(Generation {
            token_id,
            fence,
            instances: BTreeMap::new(),
        });
    }
    let live = live.as_mut().unwrap();
    live.instances.retain(|_, instance| {
        let active =
            crate::auth::load_active_session_grant(&state.data_dir, &instance.session_id, now_ts())
                .is_ok();
        if !active {
            instance.cancel.send_replace(true);
        }
        (active && !*instance.cancel.borrow()) || *instance.copies.borrow() > 0
    });
    anyhow::ensure!(
        live.instances.contains_key(launch)
            || live
                .instances
                .values()
                .filter(|instance| instance.principal_id == context.principal_id)
                .count()
                < 256,
        "Close an existing Browser instance before opening another"
    );
    let instance = live
        .instances
        .entry(launch.into())
        .or_insert_with(|| Instance {
            principal_id: context.principal_id.clone(),
            session_id: context.session_id.clone(),
            cancel: watch::channel(false).0,
            copies: Arc::new(watch::channel(0).0),
        });
    anyhow::ensure!(
        instance.principal_id == context.principal_id
            && instance.session_id == context.session_id
            && !*instance.cancel.borrow(),
        "Browser instance authority has ended"
    );
    let cancelled = instance.cancel.subscribe();
    let stopped = cancelled.clone();
    let data = state.data_dir.clone();
    let session = context.session_id.clone();
    let principal = context.principal_id.clone();
    let path = ended_path(&data, launch);
    let fence = live.fence.narrow(move || {
        if *stopped.borrow()
            || read_json::<serde_json::Value>(&path)
                .map_err(|e| e.to_string())?
                .is_some()
        {
            return Err("This Browser instance has ended".into());
        }
        let grant = crate::auth::load_active_session_grant(&data, &session, now_ts())
            .map_err(|e| e.to_string())?;
        if grant.principal_id != principal {
            return Err("Browser session has changed".into());
        }
        Ok(())
    });
    Ok(BrowserInternetEffect {
        fence,
        cancelled,
        copies: instance.copies.clone(),
    })
}

pub(super) async fn end_instance(state: &GatewayState, launch: &str) -> anyhow::Result<()> {
    let mut live = state.browser_internet.generation.lock().await;
    crate::auth::atomic_write(
        &ended_path(&state.data_dir, launch),
        &serde_json::to_vec(&serde_json::json!({"launch_id":launch,"ended_at":now_ts()}))?,
    )?;
    if let Some(generation) = live.as_mut() {
        if let Some(instance) = generation.instances.get(launch) {
            instance.cancel.send_replace(true);
        }
        let barrier = tokio::time::timeout(Duration::from_secs(2), generation.fence.barrier())
            .await
            .map_err(|_| anyhow::anyhow!("Browser provider dispatch is still stopping"))?;
        drop(barrier);
        if let Some(instance) = generation.instances.get(launch) {
            drain_instance(instance).await?;
        }
        generation.instances.remove(launch);
    }
    Ok(())
}

pub(super) fn refusal(error: anyhow::Error) -> Response {
    tracing::debug!(%error, "Browser internet operation refused");
    (StatusCode::FORBIDDEN, Json(serde_json::json!({
        "schema":"elastos.browser.open-error/v1", "ok":false, "code":"browser_internet_grant_required", "http_status":403,
        "message":"Browser needs permission to use this computer's internet connection. Review the request in Inbox.",
        "outcome":{"schema":"elastos.browser.open-outcome/v1","state":"terminal_pre_effect_failure","effects":{"page_acquired":false,"vm_acquired":false,"stream_acquired":false}}
    }))).into_response()
}

pub(super) async fn summary(State(state): State<GatewayState>, headers: HeaderMap) -> Response {
    if let Err(error) = require_runtime_wallet_authority(
        &state.data_dir,
        &headers,
        &[BROWSER_CAPSULE_ID, INBOX_CAPSULE_ID],
    ) {
        return refusal(error);
    }
    // Reads, including restored windows and polls, cannot create or renew a request.
    // Explicit Browser actions use the existing owner-checked request action.
    match load(&state.data_dir) {
        Ok(record) => {
            let mut value = public_record(record.as_ref());
            if let Some(Consent::Revoked { token_id, .. }) = record.as_ref() {
                let live = state.browser_internet.generation.lock().await;
                value["stop_pending"] = serde_json::json!(live
                    .as_ref()
                    .is_some_and(|generation| generation.token_id == *token_id));
            }
            Json(value).into_response()
        }
        Err(error) => refusal(error),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InternetAction {
    action: String,
    #[serde(default)]
    step_up_token: Option<String>,
}
pub(super) async fn action(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<InternetAction>,
) -> Response {
    let stopping = matches!(input.action.as_str(), "revoke" | "end");
    match action_inner(&state, &headers, input).await {
        Ok(value) => Json(value).into_response(),
        Err(error) if stopping => {
            tracing::warn!(%error, "Browser internet Stop is incomplete");
            (StatusCode::CONFLICT, Json(serde_json::json!({"status":"stop_incomplete","message":"Stop was not confirmed. Try again."}))).into_response()
        }
        Err(error) => refusal(error),
    }
}
async fn action_inner(
    state: &GatewayState,
    headers: &HeaderMap,
    input: InternetAction,
) -> anyhow::Result<serde_json::Value> {
    let launch = require_home_launch_token_binding(
        &state.data_dir,
        headers,
        &[BROWSER_CAPSULE_ID, INBOX_CAPSULE_ID],
    )?;
    if input.action == "end" {
        // The executable actor identifies the frame, including when Home owns
        // the projection's authority. End only the validated token's launch.
        anyhow::ensure!(
            launch.launch_context.executable_actor == BROWSER_CAPSULE_ID,
            "Browser launch required"
        );
        end_instance(state, &launch.launch_id).await?;
        return Ok(serde_json::json!({"status":"ended"}));
    }
    ensure_admin_context(&state.data_dir, &launch.context)?;
    if input.action == "request" {
        let live = state.browser_internet.generation.lock().await;
        let record = load(&state.data_dir)?;
        anyhow::ensure!(
            !matches!(&record, Some(Consent::Revoked { .. })) || live.is_none(),
            "Finish stopping Browser internet before requesting it again"
        );
        if !matches!(&record, Some(Consent::Granted { .. }))
            && !matches!(&record,Some(Consent::Requested {expires_at,..}) if *expires_at > now_ts())
        {
            save(&state.data_dir, &requested())?;
        }
        return Ok(public_record(load(&state.data_dir)?.as_ref()));
    }
    anyhow::ensure!(input.action == "revoke", "Invalid Browser internet action");
    anyhow::ensure!(
        launch.launch_context.executable_actor == INBOX_CAPSULE_ID,
        "Inbox launch required"
    );
    revoke(state, &launch, None, input.step_up_token.as_deref()).await
}

async fn revoke(
    state: &GatewayState,
    launch: &RequiredHomeLaunchToken,
    expected_id: Option<&str>,
    step_up_token: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    anyhow::ensure!(
        launch.launch_context.executable_actor == INBOX_CAPSULE_ID,
        "Inbox launch required"
    );
    ensure_admin_context(&state.data_dir, &launch.context)?;
    let mut live = state.browser_internet.generation.lock().await;
    let record =
        load(&state.data_dir)?.ok_or_else(|| anyhow::anyhow!("Browser internet access is off"))?;
    let stored_id = match &record {
        Consent::Granted { token_id, .. } | Consent::Revoked { token_id, .. } => token_id,
        _ => anyhow::bail!("Browser internet access is off"),
    };
    anyhow::ensure!(
        expected_id.is_none_or(|id| id == stored_id),
        "Browser internet grant has changed"
    );
    let token_id = match &record {
        Consent::Granted { token_id, .. } => {
            consume_passkey_step_up_token(
                &state.data_dir,
                step_up_token.unwrap_or_default(),
                launch,
                180,
                REVOKE_OPERATION,
                &revoke_request(&record)?,
            )?;
            token_id.clone()
        }
        Consent::Revoked { token_id, .. } => token_id.clone(),
        _ => anyhow::bail!("Browser internet access is off"),
    };
    if !matches!(record, Consent::Revoked { .. }) {
        save(
            &state.data_dir,
            &Consent::Revoked {
                token_id: token_id.clone(),
                by_principal_id: launch.context.principal_id.clone(),
                at: now_ts(),
            },
        )?;
    }
    anyhow::ensure!(
        matches!(load(&state.data_dir)?,Some(Consent::Revoked {token_id:ref stored,..}) if *stored==token_id),
        "Browser internet Stop could not be read back"
    );
    let mut ended: Vec<String> = Vec::new();
    if let Some(generation) = live.as_ref() {
        retire_generation(generation).await?;
        ended.extend(generation.instances.keys().cloned());
    }
    *live = None;
    let token_retired = crate::auth::atomic_write(&state.data_dir.join(TOKEN), b"null").is_ok();
    let persisted = match state.browser_internet.manager.as_ref() {
        Some(manager) => manager
            .revoke(
                elastos_runtime::capability::token::TokenId::from_hex(&token_id)
                    .map_err(anyhow::Error::msg)?,
                "Browser internet stopped",
            )
            .await
            .is_ok(),
        None => false,
    };
    Ok(
        serde_json::json!({"status":"revoked","revoke_list":if persisted {"persisted"} else {"not_persisted"},"ended_launches":ended,"token_retired":token_retired}),
    )
}

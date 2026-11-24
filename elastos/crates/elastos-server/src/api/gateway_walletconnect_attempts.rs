//! Tap-scoped connector transport. Pairing state lives only in this service's RAM.
use super::*;

pub(in crate::api) struct AttemptTransport {
    instance: String,
    revision: u64,
    local: bool,
    source: Option<std::net::IpAddr>,
    session: Option<String>,
    expires_at: u64,
    deadline: Instant,
    values: BTreeMap<String, serde_json::Value>,
    cancel_expiry: watch::Sender<bool>,
}
impl Drop for AttemptTransport {
    fn drop(&mut self) {
        self.cancel_expiry.send_replace(true);
    }
}

pub(in crate::api) fn actor(id: &str) -> String {
    format!("runtime:wallet-attempt:{id}")
}
pub(in crate::api) fn attempt_headers_present(headers: &HeaderMap) -> bool {
    headers.contains_key("x-elastos-wallet-attempt")
        || headers.contains_key("x-elastos-wallet-instance")
}
pub(in crate::api) fn attempt_route(path: &str, method: &axum::http::Method) -> bool {
    matches!(
        (method.as_str(), path),
        ("GET", "/api/apps/wallet-walletconnect/wallet/config")
            | (
                "GET" | "POST" | "DELETE",
                "/api/apps/wallet-walletconnect/storage"
            )
            | ("POST", "/api/apps/wallet-walletconnect/relay-admission")
    )
}
fn header<'a>(headers: &'a HeaderMap, name: &str) -> anyhow::Result<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .and_then(|v| v.to_str().ok())
        .ok_or(crate::auth::wallet_signin::Refused)?;
    anyhow::ensure!(values.next().is_none(), "wallet attempt refused");
    Ok(value)
}
fn context(
    state: &GatewayState,
    headers: &HeaderMap,
) -> anyhow::Result<crate::auth::wallet_signin::AttemptContext> {
    crate::auth::wallet_signin::attempt_context(
        &home_launch_auth_data_dir(&state.data_dir),
        header(headers, "x-elastos-wallet-attempt")?,
        header(headers, "x-elastos-wallet-instance")?,
        now_ts(),
    )
}
pub(in crate::api) async fn admit_attempt(
    state: &GatewayState,
    headers: &HeaderMap,
) -> anyhow::Result<crate::auth::wallet_signin::AttemptContext> {
    let context = context(state, headers)?;
    let inner = state.walletconnect.inner.lock().await;
    let store = inner
        .attempts
        .get(&context.ceremony_id)
        .ok_or(crate::auth::wallet_signin::Refused)?;
    anyhow::ensure!(
        store.instance == context.instance_id
            && store.expires_at > now_ts()
            && store.revision >= context.storage_revision
            && store.session == context.session_id
            && store.deadline > Instant::now(),
        "wallet attempt refused"
    );
    Ok(context)
}

pub(in crate::api) async fn require_attempt(
    state: &GatewayState,
    headers: &HeaderMap,
) -> anyhow::Result<crate::auth::wallet_signin::AttemptContext> {
    let context = admit_attempt(state, headers).await?;
    let inner = state.walletconnect.inner.lock().await;
    let store = inner
        .attempts
        .get(&context.ceremony_id)
        .ok_or(crate::auth::wallet_signin::Refused)?;
    if header(headers, "if-match")? != format!("\"{}\"", store.revision) {
        return Err(StaleRevision.into());
    }
    Ok(context)
}

pub(super) async fn deadline(state: &GatewayState, id: &str) -> anyhow::Result<Instant> {
    state
        .walletconnect
        .inner
        .lock()
        .await
        .attempts
        .get(id)
        .map(|a| a.deadline)
        .ok_or_else(|| crate::auth::wallet_signin::Refused.into())
}
fn absolute_deadline(expires: u64) -> Instant {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Instant::now()
        + Duration::from_secs(expires)
            .saturating_sub(now)
            .min(Duration::from_secs(180))
}

pub(in crate::api) async fn issue_lock(state: &GatewayState) -> tokio::sync::MutexGuard<'_, ()> {
    state.walletconnect.issue_lock.lock().await
}
pub(in crate::api) async fn preflight(
    state: &GatewayState,
    local: bool,
    session: Option<&str>,
    reuse: Option<&str>,
    source: Option<std::net::IpAddr>,
) -> anyhow::Result<()> {
    let mut inner = state.walletconnect.inner.lock().await;
    capacity(&mut inner, local, session, reuse, source)
}
fn capacity(
    inner: &mut Inner,
    local: bool,
    session: Option<&str>,
    reuse: Option<&str>,
    source: Option<std::net::IpAddr>,
) -> anyhow::Result<()> {
    let source = source.map(address_budget_key);
    if let Some(saved) = reuse.and_then(|id| inner.attempts.get(id)) {
        anyhow::ensure!(
            saved.local == local && saved.session.as_deref() == session,
            "wallet attempt transport changed"
        );
        return Ok(());
    }
    let now = Instant::now();
    inner.confirmation_issues.retain(|_, window| {
        window.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        !window.is_empty()
    });
    let mut retry = slot_wait(
        inner
            .attempts
            .values()
            .filter(|a| a.session.as_deref() == session),
        if session.is_some() { 2 } else { 3 },
        now,
    );
    if let Some(session) = session {
        retry = retry.max(window_wait(inner.confirmation_issues.get(session), 4, now));
    } else {
        let pool = usize::from(local);
        inner.attempt_issues[pool].retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        inner.address_issues.retain(|_, window| {
            window.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
            !window.is_empty()
        });
        retry = retry.max(window_wait(
            Some(&inner.attempt_issues[pool]),
            if local { 32 } else { 64 },
            now,
        ));
        retry = retry.max(slot_wait(
            inner
                .attempts
                .values()
                .filter(|a| a.session.is_none() && a.local == local),
            2,
            now,
        ));
        if !local {
            let source = source.ok_or(crate::auth::wallet_signin::Refused)?;
            retry = retry.max(window_wait(inner.address_issues.get(&source), 32, now));
            retry = retry.max(slot_wait(
                inner
                    .attempts
                    .values()
                    .filter(|a| a.session.is_none() && !a.local && a.source == Some(source)),
                1,
                now,
            ));
        }
    }
    if !retry.is_zero() {
        return Err(AttemptCapacity::after(retry).into());
    }
    Ok(())
}

// Wait for every blocking limit, including held slots whose deadline can be
// five minutes away. A caller may release a slot earlier by cancelling it.
fn slot_wait<'a>(
    attempts: impl Iterator<Item = &'a AttemptTransport>,
    limit: usize,
    now: Instant,
) -> Duration {
    let mut deadlines: Vec<_> = attempts.map(|attempt| attempt.deadline).collect();
    if deadlines.len() < limit {
        return Duration::ZERO;
    }
    deadlines.sort_unstable();
    deadlines[deadlines.len() - limit]
        .saturating_duration_since(now)
        .max(Duration::from_millis(1))
}

fn window_wait(
    window: Option<&std::collections::VecDeque<Instant>>,
    limit: usize,
    now: Instant,
) -> Duration {
    window
        .filter(|w| w.len() >= limit)
        .map_or(Duration::ZERO, |w| {
            Duration::from_secs(60).saturating_sub(now.duration_since(w[w.len() - limit]))
        })
}

/// Loopback has 32 issues/minute; remote has 64, at most 32/address budget.
/// IPv6 addresses in the same /64 share that budget.
/// Three anonymous slots reserve one for loopback; each remote address owns one. Renewing the
/// frame credential of the same live attempt costs neither another slot nor time.
pub(in crate::api) async fn install_attempt(
    state: &GatewayState,
    result: &crate::auth::wallet_signin::BeginResult,
    local: bool,
    source: Option<std::net::IpAddr>,
) -> anyhow::Result<()> {
    install(state, result, local, None, source).await
}
pub(in crate::api) async fn install_confirmation(
    state: &GatewayState,
    result: &crate::auth::wallet_signin::BeginResult,
    session: &str,
) -> anyhow::Result<()> {
    install(state, result, false, Some(session), None).await
}
async fn install(
    state: &GatewayState,
    result: &crate::auth::wallet_signin::BeginResult,
    local: bool,
    session: Option<&str>,
    source: Option<std::net::IpAddr>,
) -> anyhow::Result<()> {
    let source = source.map(address_budget_key);
    crate::auth::wallet_signin::set_transport_local(
        &home_launch_auth_data_dir(&state.data_dir),
        &result.ceremony_id,
        local,
    )?;
    let mut inner = state.walletconnect.inner.lock().await;
    // Browser-claim renewal keeps its starting share even after an address
    // change. It gains neither another slot nor a later deadline.
    let source = inner
        .attempts
        .get(&result.ceremony_id)
        .map_or(source, |a| a.source);
    capacity(
        &mut inner,
        local,
        session,
        Some(&result.ceremony_id),
        source,
    )?;
    if !inner.attempts.contains_key(&result.ceremony_id) {
        if let Some(session) = session {
            inner
                .confirmation_issues
                .entry(session.into())
                .or_default()
                .push_back(Instant::now());
        } else {
            inner.attempt_issues[usize::from(local)].push_back(Instant::now());
            if !local {
                inner
                    .address_issues
                    .entry(source.ok_or(crate::auth::wallet_signin::Refused)?)
                    .or_default()
                    .push_back(Instant::now());
            }
        }
    }
    let principal = actor(&result.ceremony_id);
    inner
        .admissions
        .retain(|_, (_, _, owner)| owner != &principal);
    for socket in inner.sockets.values().filter(|s| s.principal == principal) {
        socket.cancel.send_replace(true);
    }
    let deadline = inner.attempts.get(&result.ceremony_id).map_or_else(
        || absolute_deadline(result.expires_at),
        |a| a.deadline.min(absolute_deadline(result.expires_at)),
    );
    let (cancel_expiry, mut expiry_cancelled) = watch::channel(false);
    inner.attempts.insert(
        result.ceremony_id.clone(),
        AttemptTransport {
            instance: result.instance_id.clone(),
            revision: result.storage_revision,
            local,
            source,
            session: session.map(str::to_owned),
            expires_at: result.expires_at,
            deadline,
            values: BTreeMap::new(),
            cancel_expiry,
        },
    );
    drop(inner);
    let state = state.clone();
    let id = result.ceremony_id.clone();
    let instance = result.instance_id.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = expiry_cancelled.changed() => return,
            _ = tokio::time::sleep_until(deadline) => {},
        }
        // Begin/renewal uses this same lock. Keep instance validation and
        // retirement together so a retiring timer cannot remove a new frame.
        let _issue = issue_lock(&state).await;
        let same = state
            .walletconnect
            .inner
            .lock()
            .await
            .attempts
            .get(&id)
            .is_some_and(|a| a.instance == instance && a.deadline <= Instant::now());
        if same {
            // The monotonic timer owns expiry even if wall time went backwards.
            if let Err(_error) = crate::auth::wallet_signin::expire_attempt(
                &home_launch_auth_data_dir(&state.data_dir),
                &id,
                &instance,
            ) {
                tracing::warn!("Wallet attempt expiry persistence failed");
            }
            let _ = retire_attempt(&state, &id).await;
        }
    });
    Ok(())
}
#[derive(Debug)]
pub(in crate::api) struct AttemptCapacity {
    pub(in crate::api) retry_after_secs: u64,
}
impl AttemptCapacity {
    fn after(wait: Duration) -> Self {
        Self {
            retry_after_secs: (wait.as_secs() + u64::from(wait.subsec_nanos() != 0)).max(1),
        }
    }
}
impl std::fmt::Display for AttemptCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Wallet connection attempts are busy. Try again later.")
    }
}
impl std::error::Error for AttemptCapacity {}

#[derive(Debug)]
pub(in crate::api) struct AttemptConfiguration;
impl std::fmt::Display for AttemptConfiguration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Wallet connector configuration is unavailable")
    }
}
impl std::error::Error for AttemptConfiguration {}
async fn response<T: Serialize>(
    result: anyhow::Result<T>,
    route: &'static str,
    stage: &'static str,
) -> Response {
    match result {
        Ok(value) => private_response(Ok(value)),
        Err(error) if error.is::<AttemptCapacity>() => {
            let seconds = error
                .downcast_ref::<AttemptCapacity>()
                .expect("capacity")
                .retry_after_secs;
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", seconds.to_string())],
                error.to_string(),
            )
                .into_response()
        }
        Err(error) if error.is::<AttemptConfiguration>() => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"wallet_transport_unavailable"})),
        )
            .into_response(),
        Err(error) if error.is::<StaleRevision>() => {
            private_response::<serde_json::Value>(Err(error))
        }
        Err(error) => {
            let _ = (route, stage, error);
            (
                StatusCode::FORBIDDEN,
                Json(json!({"error":"wallet_signin_refused"})),
            )
                .into_response()
        }
    }
}

pub(crate) async fn retire_inactive_attempts(state: &GatewayState) -> anyhow::Result<()> {
    for id in
        crate::auth::wallet_signin::inactive_attempts(&home_launch_auth_data_dir(&state.data_dir))?
    {
        retire_attempt(state, &id).await?;
    }
    Ok(())
}

pub(in crate::api) async fn retire_attempt(state: &GatewayState, id: &str) -> anyhow::Result<()> {
    let principal = actor(id);
    let mut inner = state.walletconnect.inner.lock().await;
    inner.attempts.remove(id);
    inner
        .admissions
        .retain(|_, (_, _, owner)| owner != &principal);
    let mut waiting = Vec::new();
    for socket in inner.sockets.values().filter(|s| s.principal == principal) {
        socket.cancel.send_replace(true);
        waiting.push(socket.done.clone());
    }
    drop(inner);
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        for done in &mut waiting {
            let _ = done.wait_for(|done| *done).await;
        }
    })
    .await;
    if closed.is_err() {
        // Authority and keys are already retired. Keep cancelled sockets tracked
        // until their tasks finish, and deliver any session already committed.
        tracing::warn!("Wallet relay close continues after the cleanup response bound");
    }
    state
        .walletconnect
        .inner
        .lock()
        .await
        .sockets
        .retain(|_, s| s.principal != principal || !*s.done.borrow());
    Ok(())
}

pub(in crate::api) async fn attempt_config(state: &GatewayState, headers: &HeaderMap) -> Response {
    let result = async {
        let context = require_attempt(state, headers).await?;
        verify_sdk(state).await.map_err(|_| AttemptConfiguration)?;
        let config = load_walletconnect_connector_config(&state.data_dir).map_err(|_| AttemptConfiguration)?;
        validate_walletconnect_connector_config(&config).map_err(|_| AttemptConfiguration)?;
        require_attempt(state,headers).await?;
        Ok::<_, anyhow::Error>(json!({
            "schema":"elastos.wallet.connector.config/v1", "connector_id":WALLET_WALLETCONNECT_CAPSULE_ID,
            "label":"WalletConnect", "evm_chains":wallet_connector_evm_chains(),
            "instance_id":context.instance_id, "expires_at":context.expires_at,
            "walletconnect": {"project_id":config.project_id,
                "storage_revision":header(headers, "if-match")?,
                "sdk_package":config.sdk_package, "sdk_version":config.sdk_version,
                "sdk_asset_path":"/apps/wallet-walletconnect/vendor/reown-appkit.js", "sdk_sha256":config.sdk_sha256}
        }))
    }.await;
    response(
        result,
        "/api/apps/wallet-walletconnect/wallet/config",
        "connector_config",
    )
    .await
}
pub(in crate::api) async fn storage(
    state: &GatewayState,
    method: axum::http::Method,
    headers: &HeaderMap,
    input: Result<Json<StorageWrite>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let mut revision = None;
    let result = async {
        let context = require_attempt(state, headers).await?;
        let mut inner = state.walletconnect.inner.lock().await;
        // Recheck under the same lock that serializes retirement and writes.
        let current = self::context(state, headers)?;
        let store = inner
            .attempts
            .get_mut(&context.ceremony_id)
            .ok_or(crate::auth::wallet_signin::Refused)?;
        anyhow::ensure!(
            current.instance_id == store.instance && current.expires_at > now_ts(),
            "wallet attempt refused"
        );
        if header(headers, "if-match")? != format!("\"{}\"", store.revision) {
            return Err(StaleRevision.into());
        }
        if method == axum::http::Method::DELETE {
            store.values.clear();
            store.revision = store
                .revision
                .checked_add(1)
                .ok_or(crate::auth::wallet_signin::Refused)?;
        } else if method == axum::http::Method::POST {
            let Json(input) = input.map_err(|_| crate::auth::wallet_signin::Refused)?;
            anyhow::ensure!(
                !input.key.is_empty() && input.key.len() <= 256,
                "Invalid WalletConnect storage key"
            );
            let mut values = store.values.clone();
            if let Some(value) = input.value {
                values.insert(input.key, value);
            } else {
                values.remove(&input.key);
            }
            if values.len() > 256 || serde_json::to_vec(&values)?.len() > MAX_BYTES {
                return Err(AttemptCapacity::after(Duration::from_secs(60)).into());
            }
            store.revision = store
                .revision
                .checked_add(1)
                .ok_or(crate::auth::wallet_signin::Refused)?;
            store.values = values;
        }
        revision = Some(store.revision);
        Ok::<_, anyhow::Error>(store.values.clone())
    }
    .await;
    let mut response = response(
        result,
        "/api/apps/wallet-walletconnect/storage",
        "connector_storage",
    )
    .await;
    if let Some(revision) = revision {
        response.headers_mut().insert(
            "etag",
            HeaderValue::from_str(&format!("\"{revision}\"")).unwrap(),
        );
    }
    response
}
pub(in crate::api) async fn admission(state: &GatewayState, headers: &HeaderMap) -> Response {
    let result = async {
        let context = require_attempt(state, headers).await?;
        verify_sdk(state).await.map_err(|_| AttemptConfiguration)?;
        let mut inner = state.walletconnect.inner.lock().await;
        let current = self::context(state, headers)?;
        let store = inner
            .attempts
            .get(&context.ceremony_id)
            .ok_or(crate::auth::wallet_signin::Refused)?;
        if header(headers, "if-match")? != format!("\"{}\"", store.revision)
            || current.expires_at <= now_ts()
        {
            return Err(StaleRevision.into());
        }
        let principal = actor(&context.ceremony_id);
        inner
            .admissions
            .retain(|_, (expiry, _, _)| *expiry > now_ts());
        anyhow::ensure!(
            inner.admissions.values().all(|(_, _, p)| p != &principal),
            "WalletConnect attempt admission already issued"
        );
        let token = crate::auth::random_secret_hex();
        inner.admissions.insert(
            token.clone(),
            (
                context.expires_at.min(now_ts() + 15),
                headers.clone(),
                principal,
            ),
        );
        Ok::<_, anyhow::Error>(json!({"token":token}))
    }
    .await;
    response(
        result,
        "/api/apps/wallet-walletconnect/relay-admission",
        "relay_admission",
    )
    .await
}
pub(super) fn admit_socket(inner: &Inner, id: &str, local: bool) -> anyhow::Result<()> {
    anyhow::ensure!(
        inner
            .attempts
            .get(id)
            .is_some_and(|a| a.expires_at > now_ts()),
        "WalletConnect attempt ended"
    );
    let actor = actor(id);
    let session = inner.attempts.get(id).and_then(|a| a.session.as_deref());
    let sockets: Vec<_> = inner
        .sockets
        .values()
        .filter(|s| {
            s.principal.starts_with("runtime:wallet-attempt:")
                && inner
                    .attempts
                    .iter()
                    .find(|(id, _)| self::actor(id) == s.principal)
                    .is_none_or(|(_, a)| a.session.as_deref() == session)
        })
        .collect();
    anyhow::ensure!(
        sockets.len() < if session.is_some() { 2 } else { 3 }
            && sockets.iter().all(|s| s.principal != actor),
        "WalletConnect connection quota exceeded"
    );
    if session.is_none() && !local {
        anyhow::ensure!(
            sockets
                .iter()
                .filter(|s| !inner
                    .attempts
                    .iter()
                    .any(|(id, a)| a.local && self::actor(id) == s.principal))
                .count()
                < 2,
            "WalletConnect reserves a local connection"
        );
    }
    Ok(())
}

fn address_budget_key(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip.to_canonical() {
        std::net::IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            std::net::Ipv6Addr::from(octets).into()
        }
        ip => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(inner: &mut Inner, id: &str, source: &str, remaining: u64) {
        let (cancel_expiry, _) = watch::channel(false);
        inner.attempts.insert(
            id.into(),
            AttemptTransport {
                instance: id.into(),
                revision: 0,
                local: false,
                source: Some(source.parse().unwrap()),
                session: None,
                expires_at: now_ts() + remaining,
                deadline: Instant::now() + Duration::from_secs(remaining),
                values: BTreeMap::new(),
                cancel_expiry,
            },
        );
    }

    #[test]
    fn ten_cancelled_pairings_fit_local_and_remote_issue_budgets() {
        for local in [true, false] {
            let mut inner = Inner::default();
            let source = Some("203.0.113.1".parse().unwrap());
            for cycle in 0..32 {
                assert!(
                    capacity(&mut inner, local, None, None, source).is_ok(),
                    "pairing retry {cycle}, local={local}"
                );
                // Cancel releases the held slot; issue debits remain for abuse bounds.
                inner.attempt_issues[usize::from(local)].push_back(Instant::now());
                if !local {
                    inner
                        .address_issues
                        .entry(source.unwrap())
                        .or_default()
                        .push_back(Instant::now());
                }
            }
            let error = capacity(&mut inner, local, None, None, source).unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<AttemptCapacity>()
                    .unwrap()
                    .retry_after_secs,
                60
            );
        }
    }

    #[test]
    fn cancelled_pairings_keep_the_aggregate_remote_limit() {
        let mut inner = Inner::default();
        inner.attempt_issues[0] = std::iter::repeat_n(Instant::now(), 64).collect();
        let error = capacity(
            &mut inner,
            false,
            None,
            None,
            Some("203.0.113.8".parse().unwrap()),
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<AttemptCapacity>()
                .unwrap()
                .retry_after_secs,
            60
        );
        assert!(capacity(&mut inner, true, None, None, None).is_ok());
    }

    #[tokio::test]
    async fn two_remote_slots_refuse_third_with_real_wait_and_keep_loopback() {
        let mut inner = Inner::default();
        held(&mut inner, "first", "203.0.113.1", 300);
        held(&mut inner, "second", "203.0.113.2", 240);
        let error = capacity(
            &mut inner,
            false,
            None,
            None,
            Some("203.0.113.3".parse().unwrap()),
        )
        .unwrap_err();
        let response = response::<serde_json::Value>(Err(error), "test", "capacity").await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["retry-after"], "240");
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "Wallet connection attempts are busy. Try again later."
        );
        assert!(capacity(
            &mut inner,
            true,
            None,
            None,
            Some("127.0.0.1".parse().unwrap())
        )
        .is_ok());
        assert_eq!(
            inner.attempts.len(),
            2,
            "refusal leaves held attempts intact"
        );
    }

    #[test]
    fn retry_waits_for_every_blocking_slot_and_issue_window() {
        let mut inner = Inner::default();
        held(&mut inner, "first", "203.0.113.1", 200);
        held(&mut inner, "second", "203.0.113.2", 20);
        inner.attempt_issues[0] =
            std::iter::repeat_n(Instant::now() - Duration::from_secs(10), 64).collect();
        for (source, expected) in [("203.0.113.3", 50), ("203.0.113.1", 200)] {
            let error =
                capacity(&mut inner, false, None, None, Some(source.parse().unwrap())).unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<AttemptCapacity>()
                    .unwrap()
                    .retry_after_secs,
                expected
            );
        }
        inner.attempts.clear();
        inner.attempt_issues[1] = std::iter::repeat_n(Instant::now(), 32).collect();
        let error = capacity(&mut inner, true, None, None, None).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<AttemptCapacity>()
                .unwrap()
                .retry_after_secs,
            60
        );
        held(&mut inner, "first", "203.0.113.1", 200);
        held(&mut inner, "second", "203.0.113.2", 20);
        for attempt in inner.attempts.values_mut() {
            attempt.session = Some("session".into());
        }
        inner.confirmation_issues.insert(
            "session".into(),
            std::iter::repeat_n(Instant::now(), 4).collect(),
        );
        let error = capacity(&mut inner, false, Some("session"), None, None).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<AttemptCapacity>()
                .unwrap()
                .retry_after_secs,
            60
        );
    }

    #[test]
    fn ipv6_wallet_slot_and_issue_budget_share_the_64_network() {
        let mut inner = Inner::default();
        held(&mut inner, "first", "2001:db8:1:2::", 300);
        assert!(capacity(
            &mut inner,
            false,
            None,
            None,
            Some("2001:db8:1:2::ffff".parse().unwrap())
        )
        .is_err());
        inner.attempts.clear();
        inner.address_issues.insert(
            "2001:db8:1:2::".parse().unwrap(),
            std::iter::repeat_n(Instant::now(), 32).collect(),
        );
        assert!(capacity(
            &mut inner,
            false,
            None,
            None,
            Some("2001:db8:1:2::1234".parse().unwrap())
        )
        .is_err());
        assert!(capacity(
            &mut inner,
            false,
            None,
            None,
            Some("2001:db8:1:3::1".parse().unwrap())
        )
        .is_ok());
    }
}

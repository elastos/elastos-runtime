//! WalletConnect transport consent. Wallet proofs and signing authority stay in wallet-provider.
use super::gateway_browser::provider_response_data;
use super::*;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use elastos_runtime::capability::{Action, CapabilityToken, ResourceId, TokenConstraints};
use serde_json::json;
use std::io::Read;
use tokio::sync::{watch, Mutex};
use tokio::time::Instant;

pub(super) const GRANT: &str = "walletconnect.internet.grant";
pub(super) const REVOKE: &str = "walletconnect.internet.revoke";
const CONSENT: &str = "WalletConnect uses this computer's internet connection to reach the wallet relay. The relay can see the connection address. Your phone wallet holds your keys and approves each request. You can turn this connection off here in Inbox.";
const MAX_BYTES: usize = 1024 * 1024;
const MAX_SOCKETS: usize = 2;
const RESOURCE: &str = "elastos://walletconnect/internet";

#[derive(Default)]
pub(crate) struct WalletConnectService {
    inner: Mutex<Inner>,
    #[cfg(test)]
    pub(in crate::api::gateway) pongs: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    pub(in crate::api::gateway) tls: std::sync::Mutex<Option<Arc<rustls::ClientConfig>>>,
}
#[derive(Default)]
struct Inner {
    sockets: BTreeMap<String, SocketOwner>,
    admissions: BTreeMap<String, (u64, HeaderMap, String)>,
}
struct SocketOwner {
    principal: String,
    cancel: watch::Sender<bool>,
    done: watch::Receiver<bool>,
}
struct SocketCompletion(watch::Sender<bool>);
impl Drop for SocketCompletion {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Consent {
    status: String,
    id: String,
    at: u64,
    principal: Option<String>,
    proof: Option<String>,
    capability: Option<String>,
}

fn root(data: &FsPath) -> PathBuf {
    data.join("ElastOS/SystemServices/WalletConnect")
}
pub(super) fn read_bytes(path: &FsPath, limit: usize) -> anyhow::Result<Option<Vec<u8>>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "WalletConnect state requires a regular file"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= limit,
        "WalletConnect state exceeds its limit"
    );
    Ok(Some(bytes))
}
fn read<T: serde::de::DeserializeOwned>(path: &FsPath, limit: usize) -> anyhow::Result<Option<T>> {
    read_bytes(path, limit)?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
        .transpose()
}
fn load(data: &FsPath) -> anyhow::Result<Option<Consent>> {
    read(&root(data).join("internet.json"), 8192)
}
fn save(data: &FsPath, value: &Consent) -> anyhow::Result<()> {
    crate::auth::atomic_write(
        &root(data).join("internet.json"),
        &serde_json::to_vec(value)?,
    )
}
fn request(c: &Consent) -> anyhow::Result<serde_json::Value> {
    anyhow::ensure!(
        c.status == "granted" || (c.status == "requested" && c.at + 1800 > now_ts()),
        "Review the current WalletConnect request in Inbox"
    );
    Ok(
        json!({"resource":"elastos://walletconnect/internet", "id":c.id, "issued_at":c.at,
        "text":if c.status == "granted" { "Stop WalletConnect relay access on this computer." } else { CONSENT }}),
    )
}
fn public(c: Option<&Consent>) -> serde_json::Value {
    match c {
        Some(c) => json!({"status":c.status, "request":request(c).ok()}),
        None => json!({"status":"off"}),
    }
}
async fn check_owner(state: &GatewayState, audit_success: bool) -> anyhow::Result<()> {
    let data = &state.data_dir;
    let c = load(data)?
        .ok_or_else(|| anyhow::anyhow!("Review WalletConnect internet access in Inbox"))?;
    anyhow::ensure!(
        c.status == "granted",
        "Review WalletConnect internet access in Inbox"
    );
    let owner = crate::auth::load_principal_for_proof_binding(
        data,
        c.proof.as_deref().unwrap_or_default(),
    )?;
    crate::auth::ensure_proof_binding_not_revoked(&owner)?;
    anyhow::ensure!(
        Some(&owner.principal_id) == c.principal.as_ref() && crate::auth::is_admin(&owner),
        "WalletConnect internet consent needs its active owner"
    );
    let token = CapabilityToken::from_base64(c.capability.as_deref().unwrap_or_default())
        .map_err(anyhow::Error::msg)?;
    state
        .browser_internet
        .capability_manager()?
        .validate_recurring(
            &token,
            &owner.principal_id,
            Action::Execute,
            &ResourceId::new(RESOURCE),
            None,
            audit_success,
        )
        .await?;
    Ok(())
}
pub(super) async fn step_up_request(
    state: &GatewayState,
    launch: &RequiredHomeLaunchToken,
    op: &str,
) -> anyhow::Result<serde_json::Value> {
    ensure_admin_context(&state.data_dir, &launch.context)?;
    anyhow::ensure!(
        launch.launch_context.executable_actor == INBOX_CAPSULE_ID,
        "Inbox launch required"
    );
    let _guard = state.walletconnect.inner.lock().await;
    let c = load(&state.data_dir)?.ok_or_else(|| anyhow::anyhow!("Open WalletConnect first"))?;
    anyhow::ensure!(
        (op == GRANT && c.status == "requested") || (op == REVOKE && c.status == "granted"),
        "WalletConnect request has changed"
    );
    request(&c)
}
pub(super) async fn answer(
    state: &GatewayState,
    launch: &RequiredHomeLaunchToken,
    action: &str,
    token: Option<&str>,
) -> anyhow::Result<String> {
    ensure_admin_context(&state.data_dir, &launch.context)?;
    anyhow::ensure!(
        launch.launch_context.executable_actor == INBOX_CAPSULE_ID,
        "Inbox launch required"
    );
    let mut inner = state.walletconnect.inner.lock().await;
    let mut c =
        load(&state.data_dir)?.ok_or_else(|| anyhow::anyhow!("Open WalletConnect first"))?;
    let (verb, id) = action
        .strip_prefix("walletconnect-internet-")
        .and_then(|v| v.split_once(':'))
        .ok_or_else(|| anyhow::anyhow!("Invalid WalletConnect internet action"))?;
    anyhow::ensure!(id == c.id, "WalletConnect request has changed");
    match verb {
        "deny" => {
            anyhow::ensure!(c.status == "requested", "WalletConnect request has changed");
            c.status = "refused".into();
        }
        "allow" | "turn-off" => {
            let stopping = verb == "turn-off";
            if !(stopping && c.status == "revoked") {
                anyhow::ensure!(
                    c.status == if stopping { "granted" } else { "requested" },
                    "WalletConnect request has changed"
                );
                consume_passkey_step_up_token(
                    &state.data_dir,
                    token.unwrap_or_default(),
                    launch,
                    180,
                    if stopping { REVOKE } else { GRANT },
                    &request(&c)?,
                )?;
                c.status = if stopping { "revoked" } else { "granted" }.into();
                c.principal = Some(launch.context.principal_id.clone());
                c.proof = launch.context.proof_binding_id.clone();
                if !stopping {
                    let capability = state.browser_internet.capability_manager()?.grant(
                        &launch.context.principal_id,
                        ResourceId::new(RESOURCE),
                        Action::Execute,
                        TokenConstraints::default(),
                        None,
                    );
                    c.capability = Some(capability.to_base64().map_err(anyhow::Error::msg)?);
                }
                save(&state.data_dir, &c)?;
            }
            if stopping {
                // Registration and Turn Off share this lock. Persist first so a restart
                // also refuses access, then wait until both network ends are dropped.
                inner.admissions.clear();
                for socket in inner.sockets.values() {
                    socket.cancel.send_replace(true);
                }
                if let Some(encoded) = &c.capability {
                    let capability =
                        CapabilityToken::from_base64(encoded).map_err(anyhow::Error::msg)?;
                    state
                        .browser_internet
                        .capability_manager()?
                        .revoke(*capability.id(), "WalletConnect internet stopped")
                        .await?;
                }
                for socket in inner.sockets.values_mut() {
                    tokio::time::timeout(
                        Duration::from_secs(3),
                        socket.done.wait_for(|done| *done),
                    )
                    .await??;
                }
                inner.sockets.clear();
                return Ok("WalletConnect connection turned off.".into());
            }
        }
        _ => anyhow::bail!("Invalid WalletConnect internet action"),
    }
    save(&state.data_dir, &c)?;
    Ok("WalletConnect internet choice saved.".into())
}
pub(super) fn notification(
    state: &GatewayState,
    context: &HomeLaunchTokenContext,
) -> Option<HomeNotificationEntrySummary> {
    ensure_admin_context(&state.data_dir, context).ok()?;
    let c = load(&state.data_dir).ok()??;
    let pending = c.status == "requested" && request(&c).is_ok();
    let active = c.status == "granted"
        || (c.status == "revoked"
            && state
                .walletconnect
                .inner
                .try_lock()
                .ok()
                .is_some_and(|inner| !inner.sockets.is_empty()));
    Some(HomeNotificationEntrySummary {
        id: "walletconnect-internet:permission".into(),
        source_app: WALLET_WALLETCONNECT_CAPSULE_ID.into(),
        kind: if pending {
            "walletconnect_internet_request"
        } else {
            "walletconnect_internet_decision"
        }
        .into(),
        title: "WalletConnect internet access".into(),
        body: if pending {
            CONSENT
        } else if c.status == "granted" {
            "WalletConnect can reach the wallet relay."
        } else {
            "WalletConnect relay access is off."
        }
        .into(),
        severity: if pending { "attention" } else { "info" }.into(),
        read: !pending,
        created_at: c.at,
        action_ref: if pending || active {
            Some(HomeNotificationActionSummary {
                app: INBOX_CAPSULE_ID.into(),
                action_id: format!(
                    "walletconnect-internet-{}:{}",
                    if pending { "allow" } else { "turn-off" },
                    c.id
                ),
            })
        } else {
            None
        },
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InternetAction {
    action: String,
}
pub(super) async fn internet(
    State(state): State<GatewayState>,
    method: axum::http::Method,
    headers: HeaderMap,
    input: Result<Json<InternetAction>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let result = async {
        let authority = require_runtime_wallet_authority(
            &state.data_dir,
            &headers,
            &[WALLET_WALLETCONNECT_CAPSULE_ID, INBOX_CAPSULE_ID],
        )?;
        let inner = state.walletconnect.inner.lock().await;
        if method == axum::http::Method::POST {
            let Json(input) = input.map_err(|_| {
                anyhow::anyhow!("WalletConnect request body is invalid or exceeds its limit")
            })?;
            anyhow::ensure!(
                input.action == "request",
                "Invalid WalletConnect internet action"
            );
            ensure_admin_context(&state.data_dir, &authority.home_launch_context())?;
            ensure_consent_request(&state, &authority.home_launch_context(), &inner)?;
        }
        Ok::<_, anyhow::Error>(public(load(&state.data_dir)?.as_ref()))
    }
    .await;
    match result {
        Ok(v) => Json(v).into_response(),
        Err(e) => system_error_response(e),
    }
}

fn ensure_consent_request(state: &GatewayState, context: &HomeLaunchTokenContext, inner: &Inner) -> anyhow::Result<()> {
    let current = load(&state.data_dir)?;
    if current.as_ref().is_none_or(|c| c.status != "granted" && (c.status != "requested" || c.at + 1800 <= now_ts())) {
        ensure_admin_context(&state.data_dir, context)?;
        anyhow::ensure!(inner.sockets.values().all(|s| *s.done.borrow()), "Finish stopping WalletConnect first");
        save(&state.data_dir, &Consent { status: "requested".into(), id: gateway_home_token::uuid_like_token(),
            at: now_ts(), principal: None, proof: None, capability: None })?;
    }
    Ok(())
}

async fn verify_sdk(state: &GatewayState) -> anyhow::Result<()> {
    let data = state.data_dir.clone();
    tokio::task::spawn_blocking(move || ensure_wallet_connector_configured(&data, WALLET_WALLETCONNECT_CAPSULE_ID)).await??;
    Ok(())
}

fn hosted(state: &GatewayState, headers: &HeaderMap) -> anyhow::Result<RuntimeWalletAuthority> {
    let connector = headers
        .get("x-elastos-walletconnect-connector")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("Home wallet connector authority is required"))?;
    Ok(
        gateway_home_wallet_connector::revalidate_home_wallet_connector_authority(
            state,
            headers,
            "elastos.home.wallet-connector.effect.request/v1",
            WALLET_WALLETCONNECT_CAPSULE_ID,
            connector,
            WALLET_WALLETCONNECT_CAPSULE_ID,
        )?
        .wallet,
    )
}
#[cfg(test)]
pub(in crate::api::gateway) async fn expire_admissions_for_test(state: &GatewayState) {
    for (expiry, _, _) in state
        .walletconnect
        .inner
        .lock()
        .await
        .admissions
        .values_mut()
    {
        *expiry = 0;
    }
}
pub(super) async fn admission(State(state): State<GatewayState>, headers: HeaderMap) -> Response {
    let result = async {
        let authority = hosted(&state, &headers)?;
        verify_sdk(&state).await?;
        let principal = authority.home_launch_context().principal_id;
        let mut inner = state.walletconnect.inner.lock().await;
        check_owner(&state, true).await?;
        inner.admissions.retain(|_, (expiry, _, _)| *expiry > now_ts());
        anyhow::ensure!(
            inner.admissions.len() < 128 && inner.admissions.values().filter(|(_, _, owner)| owner == &principal).count() < 8,
            "WalletConnect admission quota exceeded"
        );
        let token = gateway_home_token::uuid_like_token();
        inner
            .admissions
            .insert(token.clone(), (now_ts() + 15, headers, principal));
        Ok::<_, anyhow::Error>(json!({"token":token}))
    }
    .await;
    private_response(result)
}
pub(super) async fn host_config(
    State(state): State<GatewayState>,
    method: axum::http::Method,
    headers: HeaderMap,
) -> Response {
    let result = async {
        let authority = hosted(&state, &headers)?;
        if method == axum::http::Method::POST { verify_sdk(&state).await?; }
        let inner = state.walletconnect.inner.lock().await;
        if method == axum::http::Method::POST {
            ensure_consent_request(&state, &authority.home_launch_context(), &inner)?;
        }
        let config = load_walletconnect_connector_config(&state.data_dir)?;
        Ok::<_, anyhow::Error>(json!({"projectId":config.project_id, "principal_id":authority.home_launch_context().principal_id,
            "internet":public(load(&state.data_dir)?.as_ref()),
            "sdk_asset_path":"/apps/wallet-walletconnect/vendor/reown-appkit.js"}))
    }.await;
    private_response(result)
}
fn private_response<T: Serialize>(result: anyhow::Result<T>) -> Response {
    let mut response = match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => system_error_response(error),
    };
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

// Only the verified connector can read its principal's SDK key/value state. Keys
// are never path components; the principal's Runtime identity selects the file.
fn storage_path(data: &FsPath, principal: &str) -> PathBuf {
    root(data).join("sessions").join(format!(
        "{}.json",
        hex::encode(Sha256::digest(principal.as_bytes()))
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StorageWrite {
    key: String,
    value: Option<serde_json::Value>,
}
pub(super) async fn storage(
    State(state): State<GatewayState>,
    method: axum::http::Method,
    headers: HeaderMap,
    input: Result<Json<StorageWrite>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let result = async {
        let authority = hosted(&state, &headers)?;
        let _guard = state.walletconnect.inner.lock().await;
        let path = storage_path(
            &state.data_dir,
            &authority.home_launch_context().principal_id,
        );
        let mut values: BTreeMap<String, serde_json::Value> =
            read(&path, MAX_BYTES)?.unwrap_or_default();
        if method == axum::http::Method::POST {
            let Json(input) = input.map_err(|_| {
                anyhow::anyhow!("WalletConnect request body is invalid or exceeds its limit")
            })?;
            anyhow::ensure!(
                !input.key.is_empty() && input.key.len() <= 256,
                "Invalid WalletConnect storage key"
            );
            if let Some(value) = input.value {
                values.insert(input.key, value);
            } else {
                values.remove(&input.key);
            }
            let bytes = serde_json::to_vec(&values)?;
            anyhow::ensure!(
                values.len() <= 256 && bytes.len() <= MAX_BYTES,
                "WalletConnect session storage quota exceeded"
            );
            crate::auth::atomic_write(&path, &bytes)?;
        }
        Ok::<_, anyhow::Error>(values)
    }
    .await;
    private_response(result)
}

fn relay_url(value: &str, project: &str) -> anyhow::Result<url::Url> {
    anyhow::ensure!(
        value.len() <= 8192,
        "WalletConnect relay URL exceeds its limit"
    );
    let url = url::Url::parse(value)?;
    anyhow::ensure!(
        url.scheme() == "wss"
            && url.port_or_known_default() == Some(443)
            && matches!(
                url.host_str(),
                Some("relay.walletconnect.com" | "relay.walletconnect.org")
            )
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "WalletConnect relay is outside the allowlist"
    );
    let ids: Vec<_> = url
        .query_pairs()
        .filter(|(k, _)| k == "projectId")
        .map(|(_, v)| v.into_owned())
        .collect();
    anyhow::ensure!(ids == [project], "WalletConnect relay project has changed");
    Ok(url)
}
fn check_liveness(pong: Duration, activity: Duration) -> anyhow::Result<()> {
    anyhow::ensure!(
        pong < Duration::from_secs(45),
        "WalletConnect heartbeat expired"
    );
    anyhow::ensure!(
        activity < Duration::from_secs(300),
        "WalletConnect idle limit expired"
    );
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayHello {
    token: String,
    relay: String,
}
pub(super) async fn relay(State(state): State<GatewayState>, ws: WebSocketUpgrade) -> Response {
    // Authority travels in the first bounded frame, never in a URL or log.
    ws.max_message_size(64 * 1024)
        .max_frame_size(64 * 1024)
        .on_upgrade(move |mut socket| async move {
            let _ = relay_connection(&state, &mut socket).await;
            // Error messages can contain upstream auth URLs. Keep them private.
            let _ = socket.close().await;
        })
}
async fn relay_connection(state: &GatewayState, socket: &mut WebSocket) -> anyhow::Result<()> {
    let hello = tokio::time::timeout(Duration::from_secs(5), socket.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("WalletConnect transport closed"))??;
    let hello = hello.into_data();
    anyhow::ensure!(
        hello.len() <= 16 * 1024,
        "WalletConnect hello exceeds its limit"
    );
    let hello: RelayHello = serde_json::from_slice(&hello)?;
    let headers = {
        let mut inner = state.walletconnect.inner.lock().await;
        let (expiry, headers, _) = inner
            .admissions
            .remove(&hello.token)
            .ok_or_else(|| anyhow::anyhow!("Home transport admission required"))?;
        anyhow::ensure!(expiry > now_ts(), "WalletConnect admission expired");
        headers
    };
    let authority = hosted(state, &headers)?;
    let config = load_walletconnect_connector_config(&state.data_dir)?;
    let url = relay_url(&hello.relay, &config.project_id)?;
    let principal = authority.home_launch_context().principal_id.clone();
    let id = gateway_home_token::uuid_like_token();
    let (cancel, mut cancelled) = watch::channel(false);
    let (done, finished) = watch::channel(false);
    let completion = SocketCompletion(done);
    {
        let mut inner = state.walletconnect.inner.lock().await;
        check_owner(state, false).await?;
        inner.sockets.retain(|_, s| !*s.done.borrow());
        anyhow::ensure!(
            inner
                .sockets
                .values()
                .filter(|s| s.principal == principal)
                .count()
                < MAX_SOCKETS,
            "WalletConnect connection quota exceeded"
        );
        inner.sockets.insert(
            id.clone(),
            SocketOwner {
                principal,
                cancel,
                done: finished,
            },
        );
    }
    // All network work is inside the cancellation branch, including Exit admission,
    // TLS and the upstream WebSocket handshake. Dropping it closes the transport.
    let result = tokio::select! {
        biased;
        _ = cancelled.changed() => Ok(()),
        result = transport(state, &headers, socket, url) => result,
    };
    if result.is_err() { tracing::warn!("WalletConnect relay transport failed"); }
    let _ = tokio::time::timeout(Duration::from_secs(1), socket.send(Message::Close(None))).await;
    // Turn Off can hold the lock while it waits for done, so signal before removal.
    drop(completion);
    state.walletconnect.inner.lock().await.sockets.remove(&id);
    result
}

#[cfg(unix)]
async fn transport(
    state: &GatewayState,
    headers: &HeaderMap,
    socket: &mut WebSocket,
    url: url::Url,
) -> anyhow::Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::AsyncWriteExt;
    use tokio_tungstenite::tungstenite::{
        client::IntoClientRequest, protocol::WebSocketConfig, Message as Upstream,
    };
    let host = url.host_str().unwrap();
    let authority = hosted(state, headers)?;
    let principal = authority.home_launch_context().principal_id;
    let registry = state
        .provider_registry
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Exit provider is unavailable"))?;
    let target = format!("tls://{host}:443");
    let response = tokio::time::timeout(Duration::from_secs(10), registry.send_raw("exit", &json!({
        "op":"open_stream", "target":target, "principal_id":principal,
        "reason":"WalletConnect relay", "stream_nonce":gateway_home_token::uuid_like_token(),
    }))).await??;
    let receipt = provider_response_data(&response)
        .ok_or_else(|| anyhow::anyhow!("Exit admission failed"))?;
    anyhow::ensure!(
        receipt["schema"] == "elastos.exit.stream-session/v1"
            && receipt["target"] == target
            && receipt["principal_id"] == principal
            && receipt["byte_transport"] == "adapter_ipc"
            && receipt["relay_ipc"]["schema"] == "elastos.exit.relay-ipc/v1"
            && receipt["relay_ipc"]["kind"] == "unix_socket",
        "WalletConnect requires the local Exit transport"
    );
    let path = receipt["relay_ipc"]["path"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Exit relay is unavailable"))?;
    anyhow::ensure!(
        FsPath::new(path).is_absolute(),
        "Exit relay path must be absolute"
    );
    let open = async {
        let mut stream = tokio::net::UnixStream::connect(path).await?;
        stream.write_all(format!("{}\n", json!({"schema":"elastos.exit.relay-open/v1", "stream_id":receipt["stream_id"],
            "target":target,"scheme":"tls","host":host,"principal_id":principal,"reason":"WalletConnect relay"})).as_bytes()).await?;
        let config = WebSocketConfig {
            max_message_size: Some(64 * 1024),
            max_frame_size: Some(64 * 1024),
            ..Default::default()
        };
        // Rustls authenticates the relay hostname using the release's root store;
        // Exit forwards TLS bytes and never holds WalletConnect session keys.
        let config = relay_tls_config();
        #[cfg(test)]
        let config = state.walletconnect.tls.lock().unwrap().clone().unwrap_or(config);
        let connector = Some(tokio_tungstenite::Connector::Rustls(config));
        let mut request = url.as_str().into_client_request()?;
        request.headers_mut().insert(
            "origin",
            gateway_home_token::home_browser_origin(headers)?.parse()?,
        );
        let (upstream, _) = tokio_tungstenite::client_async_tls_with_config(
            request,
            stream,
            Some(config),
            connector,
        )
        .await?;
        Ok::<_, anyhow::Error>(upstream)
    };
    let mut upstream = tokio::time::timeout(Duration::from_secs(15), open).await??;
    socket
        .send(Message::Text("{\"ready\":true}".into()))
        .await?;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    let mut pong = Instant::now();
    let mut activity = Instant::now();
    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                hosted(state, headers)?;
                check_owner(state, false).await?;
                check_liveness(pong.elapsed(), activity.elapsed())?;
                tokio::time::timeout(Duration::from_secs(5), upstream.send(Upstream::Ping(Vec::new()))).await??;
            }
            frame = upstream.next() => match frame.transpose()? {
                Some(Upstream::Text(text)) => {
                    activity = Instant::now();
                    tokio::time::timeout(Duration::from_secs(5), socket.send(Message::Text(text))).await??;
                }
                Some(Upstream::Pong(_)) => {
                    pong = Instant::now();
                    #[cfg(test)]
                    state.walletconnect.pongs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                },
                Some(Upstream::Ping(_)) => { tokio::time::timeout(Duration::from_secs(5), upstream.flush()).await??; }
                Some(Upstream::Close(_)) | None => break,
                _ => anyhow::bail!("WalletConnect relay requires text frames"),
            },
            frame = socket.recv() => match frame.transpose()? {
                Some(Message::Text(text)) => {
                    hosted(state, headers)?;
                    check_owner(state, false).await?;
                    activity = Instant::now();
                    tokio::time::timeout(Duration::from_secs(5), upstream.send(Upstream::Text(text))).await??;
                }
                Some(Message::Close(_)) | None => break,
                Some(Message::Pong(_)) | Some(Message::Ping(_)) => {},
                _ => anyhow::bail!("WalletConnect requires text frames"),
            },
        }
    }
    Ok(())
}
#[cfg(unix)]
fn relay_tls_config() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    )).with_safe_default_protocol_versions().expect("ring TLS versions")
        .with_root_certificates(roots).with_no_client_auth())
}
#[cfg(not(unix))]
async fn transport(
    _state: &GatewayState,
    _headers: &HeaderMap,
    _socket: &mut WebSocket,
    _url: url::Url,
) -> anyhow::Result<()> {
    anyhow::bail!("The local Exit transport is unavailable on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn walletconnect_socket_completion_survives_task_unwind() {
        let (done, finished) = watch::channel(false);
        let completion = SocketCompletion(done);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _completion = completion;
            panic!("fixture task failure");
        }));
        assert!(panic.is_err());
        assert!(*finished.borrow());
    }
    #[test]
    fn walletconnect_heartbeat_and_idle_have_independent_deadlines() {
        assert!(check_liveness(Duration::from_secs(44), Duration::from_secs(299)).is_ok());
        assert!(check_liveness(Duration::from_secs(45), Duration::ZERO)
            .unwrap_err()
            .to_string()
            .contains("heartbeat"));
        assert!(check_liveness(Duration::ZERO, Duration::from_secs(300))
            .unwrap_err()
            .to_string()
            .contains("idle"));
    }
}

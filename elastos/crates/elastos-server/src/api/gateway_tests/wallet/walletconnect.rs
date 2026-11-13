use super::super::*;
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
};

const INTERNET: &str = "/api/apps/wallet-walletconnect/internet";
const STORAGE: &str = "/api/apps/wallet-walletconnect/storage";
const RELAY: &str =
    "wss://relay.walletconnect.org/?projectId=test_walletconnect_project&auth=fixture";

#[path = "walletconnect_real_relay.rs"]
mod real_relay;

async fn persistent_internet(data: &std::path::Path) -> Arc<BrowserInternetService> {
    use elastos_runtime::capability::{CapabilityManager, CapabilityStore};
    use elastos_runtime::primitives::{audit::AuditLog, metrics::MetricsManager};
    let store = Arc::new(
        CapabilityStore::with_persistence(data.join("capability_store"))
            .await
            .unwrap(),
    );
    let manager = Arc::new(CapabilityManager::load_or_generate(
        data,
        store,
        Arc::new(AuditLog::new()),
        Arc::new(MetricsManager::new()),
    ));
    Arc::new(BrowserInternetService::new(Some(manager)))
}

struct Exit {
    path: PathBuf,
    calls: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl Provider for Exit {
    fn name(&self) -> &'static str {
        "walletconnect-fixture-exit"
    }
    fn schemes(&self) -> Vec<&'static str> {
        vec!["exit"]
    }
    async fn handle(&self, _: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider("raw fixture".into()))
    }
    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request["target"], "tls://relay.walletconnect.org:443");
        assert!(request["principal_id"].as_str().is_some());
        Ok(json!({"status":"ok", "data": {
            "schema":"elastos.exit.stream-session/v1", "target":request["target"],
            "stream_id":"stream:wc-fixture", "principal_id":request["principal_id"], "byte_transport":"adapter_ipc",
            "relay_ipc":{"schema":"elastos.exit.relay-ipc/v1","kind":"unix_socket","path":self.path}
        }}))
    }
}

struct Fixture {
    data: tempfile::TempDir,
    state: GatewayState,
    app: Router,
    connector: String,
    inbox: String,
    home: String,
    addr: String,
    calls: Arc<AtomicUsize>,
    pings: Arc<AtomicUsize>,
    pause_tls: Arc<AtomicBool>,
    handshake: Arc<tokio::sync::Notify>,
    resume: Arc<tokio::sync::Notify>,
    gateway: tokio::task::JoinHandle<()>,
    relay: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.gateway.abort();
        self.relay.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        let data = tempfile::Builder::new()
            .prefix("wc-")
            .tempdir_in(if cfg!(target_os = "macos") {
                "/private/tmp"
            } else {
                "/tmp"
            })
            .unwrap();
        let owner = passkey_authority(data.path());
        super::connectors::seed_walletconnect_connector_config(data.path());
        let connector = projection_launch_token_for_authority_context(
            data.path(),
            WALLET_WALLETCONNECT_CAPSULE_ID,
            &owner,
        );
        let inbox = app_token_for_authority(data.path(), INBOX_CAPSULE_ID, &owner);
        let mut state = test_state(data.path());
        state.browser_internet = persistent_internet(data.path()).await;
        let cert =
            rcgen::generate_simple_self_signed(vec!["relay.walletconnect.org".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        *state.walletconnect.tls.lock().unwrap() = Some(Arc::new(client));
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let path = data.path().join("relay.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let pings = Arc::new(AtomicUsize::new(0));
        let observed = pings.clone();
        let pause_tls = Arc::new(AtomicBool::new(false));
        let handshake = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let pause = pause_tls.clone();
        let entered = handshake.clone();
        let proceed = resume.clone();
        let relay = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    connection = listener.accept() => {
                        let (mut connection, _) = connection.unwrap();
                        let acceptor = acceptor.clone(); let pings = observed.clone();
                        let pause = pause.clone(); let entered = entered.clone(); let proceed = proceed.clone();
                        connections.spawn(async move {
                            let mut line = Vec::new();
                            loop {
                                let Ok(byte) = connection.read_u8().await else { return; };
                                if byte == b'\n' { break; }
                                line.push(byte); assert!(line.len() < 16384);
                            }
                            let open: Value = serde_json::from_slice(&line).unwrap();
                            assert_eq!(open["schema"], "elastos.exit.relay-open/v1");
                            assert_eq!(open["target"], "tls://relay.walletconnect.org:443");
                            if pause.load(Ordering::SeqCst) { entered.notify_one(); proceed.notified().await; }
                            let Ok(tls) = acceptor.accept(connection).await else { return; };
                            let Ok(mut socket) = tokio_tungstenite::accept_async(tls).await else { return; };
                            while let Some(Ok(frame)) = socket.next().await {
                                match frame {
                                    Message::Text(_) => { if socket.send(frame).await.is_err() { break; } }
                                    Message::Ping(_) => { pings.fetch_add(1, Ordering::SeqCst); if socket.flush().await.is_err() { break; } }
                                    Message::Close(_) => break,
                                    _ => {}
                                }
                            }
                        });
                    }
                    result = connections.join_next(), if !connections.is_empty() => { result.unwrap().unwrap(); }
                }
            }
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = Arc::new(ProviderRegistry::new());
        registry
            .register_sub_provider(
                "exit",
                Arc::new(Exit {
                    path,
                    calls: calls.clone(),
                }),
            )
            .await
            .unwrap();
        state.provider_registry = Some(registry);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let app = gateway_router_with_api_url(state.clone(), format!("http://{addr}"));
        let served = app.clone();
        let gateway = tokio::spawn(async move {
            axum::serve(listener, served).await.unwrap();
        });
        Self {
            data,
            state,
            app,
            connector,
            inbox,
            home: owner.home_token,
            addr,
            calls,
            pings,
            pause_tls,
            handshake,
            resume,
            gateway,
            relay,
        }
    }
    async fn route(&self, token: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        self.route_as(&self.home, token, path, body).await
    }
    async fn route_as(
        &self,
        _home: &str,
        token: &str,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let origin = "null";
        let revision = require_carried_home_launch_token(
            self.data.path(),
            token,
            &[WALLET_WALLETCONNECT_CAPSULE_ID],
        )
        .ok()
        .and_then(|launch| {
            gateway_walletconnect::storage_revision(self.data.path(), &launch.context.principal_id)
                .ok()
        })
        .unwrap_or_else(|| "\"0\"".into());
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .header(HOST, self.addr.as_str())
                    .header("origin", origin)
                    .uri(path)
                    .method(if body.is_some() { "POST" } else { "GET" })
                    .header("x-elastos-home-token", token)
                    .header("if-match", revision)
                    .header(CONTENT_TYPE, "application/json")
                    .body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| json!({"text":String::from_utf8_lossy(&bytes)})),
        )
    }
    async fn allow(&self) {
        let (status, pending) = self
            .route(&self.connector, INTERNET, Some(json!({"action":"request"})))
            .await;
        assert_eq!(status, StatusCode::OK, "{pending}");
        self.answer(&pending, false).await;
    }
    async fn answer(&self, record: &Value, off: bool) {
        let operation = if off {
            gateway_walletconnect::REVOKE
        } else {
            gateway_walletconnect::GRANT
        };
        let token = gateway_passkey_step_up::issue_passkey_step_up_token_for_test(
            self.data.path(),
            &self.inbox,
            INBOX_CAPSULE_ID,
            operation,
            &record["request"],
        )
        .unwrap();
        let (status, value) = self.route(&self.inbox, "/api/apps/inbox/actions", Some(json!({
            "action_id":format!("walletconnect-internet-{}:{}", if off {"turn-off"} else {"allow"}, record["request"]["id"].as_str().unwrap()),
            "step_up_token":token,
        }))).await;
        assert_eq!(status, StatusCode::OK, "{value}");
    }
    async fn connect(
        &self,
        token: &str,
        relay: &str,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        let (_, admission) = self
            .route(
                token,
                "/api/apps/wallet-walletconnect/relay-admission",
                Some(json!({})),
            )
            .await;
        let ticket = admission["token"].as_str().unwrap_or("refused");
        self.connect_ticket(ticket, relay).await
    }
    async fn connect_ticket(
        &self,
        ticket: &str,
        relay: &str,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        let mut request = format!("ws://{}/api/apps/wallet-walletconnect/relay", self.addr)
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("origin", "null".parse().unwrap());
        let (mut socket, _) = connect_async(request).await.unwrap();
        socket
            .send(Message::Text(
                json!({"token":ticket,"relay":relay}).to_string(),
            ))
            .await
            .unwrap();
        socket
    }
    async fn ready(
        &self,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        let mut socket = self.connect(&self.connector, RELAY).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            Message::Text("{\"ready\":true}".into())
        );
        socket
    }
}

#[tokio::test]
async fn walletconnect_connector_reuses_one_consent_request() {
    let f = Fixture::new().await;
    let (status, first) = f
        .route(&f.connector, INTERNET, Some(json!({"action":"request"})))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, second) = f
        .route(&f.connector, INTERNET, Some(json!({"action":"request"})))
        .await;
    assert_eq!(first["request"]["id"], second["request"]["id"]);
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn walletconnect_admitted_frames_do_not_reread_sdk_but_new_admissions_verify_it() {
    let f = Fixture::new().await;
    f.allow().await;
    let mut socket = f.ready().await;
    let sdk = f.data.path().join(WALLETCONNECT_SDK_PATH);
    std::fs::rename(&sdk, sdk.with_extension("held")).unwrap();
    socket
        .send(Message::Text("admitted-frame".into()))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap(),
        Message::Text("admitted-frame".into())
    );
    let (status, _) = f
        .route(
            &f.connector,
            "/api/apps/wallet-walletconnect/relay-admission",
            Some(json!({})),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn walletconnect_admission_quota_preserves_other_principals() {
    let f = Fixture::new().await;
    f.allow().await;
    let path = "/api/apps/wallet-walletconnect/relay-admission";
    for _ in 0..8 {
        assert_eq!(
            f.route(&f.connector, path, Some(json!({}))).await.0,
            StatusCode::OK
        );
    }
    assert_ne!(
        f.route(&f.connector, path, Some(json!({}))).await.0,
        StatusCode::OK
    );
    let other = passkey_authority_with_name_role_credential(
        f.data.path(),
        Some("quota-other"),
        crate::auth::RuntimePrincipalRole::Admin,
        "quota-other-credential",
    );
    let connector = projection_launch_token_for_authority_context(
        f.data.path(),
        WALLET_WALLETCONNECT_CAPSULE_ID,
        &other,
    );
    assert_eq!(
        f.route_as(&other.home_token, &connector, path, Some(json!({})))
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn walletconnect_websocket_upgrade_requires_opaque_origin_and_first_frame_admission() {
    let f = Fixture::new().await;
    for origin in [
        None,
        Some("http://localhost"),
        Some("https://other.example"),
    ] {
        let mut request = format!("ws://{}/api/apps/wallet-walletconnect/relay", f.addr)
            .into_client_request()
            .unwrap();
        if let Some(origin) = origin {
            request
                .headers_mut()
                .insert("origin", origin.parse().unwrap());
        }
        let result = connect_async(request).await;
        assert!(
            matches!(result, Err(tokio_tungstenite::tungstenite::Error::Http(ref response)) if response.status() == StatusCode::FORBIDDEN)
        );
    }
    // This matches the opaque browser API: null Origin, no custom auth header,
    // and a refused first-frame ticket. Upgrading grants no Exit access.
    let mut socket = f.connect_ticket("refused", RELAY).await;
    assert!(matches!(
        socket.next().await,
        Some(Ok(Message::Close(_))) | None
    ));
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn walletconnect_real_relay_requires_consent_allowlist_and_connector() {
    let f = Fixture::new().await;
    let mut denied = f.connect(&f.connector, RELAY).await;
    assert!(matches!(
        denied.next().await,
        Some(Ok(Message::Close(_))) | None
    ));
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    f.allow().await;
    for (token, url) in [
        (&f.inbox, RELAY),
        (
            &f.connector,
            "wss://evil.example/?projectId=test_walletconnect_project",
        ),
        (
            &f.connector,
            "wss://relay.walletconnect.org:444/?projectId=test_walletconnect_project",
        ),
        (
            &f.connector,
            "wss://relay.walletconnect.org/?projectId=another-project",
        ),
    ] {
        let mut denied = f.connect(token, url).await;
        assert!(matches!(
            denied.next().await,
            Some(Ok(Message::Close(_))) | None
        ));
    }
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    let mut socket = f.ready().await;
    socket
        .send(Message::Text("encrypted-payload".into()))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap(),
        Message::Text("encrypted-payload".into())
    );
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    let (_, granted) = f.route(&f.inbox, INTERNET, None).await;
    // Missing step-up cannot stop an existing grant.
    let (status, _) = f.route(&f.inbox, "/api/apps/inbox/actions", Some(json!({"action_id":format!("walletconnect-internet-turn-off:{}", granted["request"]["id"].as_str().unwrap())}))).await;
    assert_ne!(status, StatusCode::OK);
    f.answer(&granted, true).await;
    assert!(matches!(
        socket.next().await,
        Some(Ok(Message::Close(_))) | None
    ));
    let mut refused = f.connect(&f.connector, RELAY).await;
    assert!(matches!(
        refused.next().await,
        Some(Ok(Message::Close(_))) | None
    ));
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn walletconnect_storage_is_principal_scoped_and_survives_service_restart() {
    let mut f = Fixture::new().await;
    f.allow().await;
    let (status, _) = f
        .route(
            &f.connector,
            STORAGE,
            Some(json!({"key":"session","value":{"expiry":123,"secret":"fixture-only"}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = f.route(&f.inbox, STORAGE, None).await;
    assert_ne!(status, StatusCode::OK);
    let other = passkey_authority_with_name_role_credential(
        f.data.path(),
        Some("other-wc"),
        crate::auth::RuntimePrincipalRole::Admin,
        "other-wc-credential",
    );
    assert_ne!(
        other.principal_id,
        runtime_wallet_authority_for_app_token(
            f.data.path(),
            WALLET_WALLETCONNECT_CAPSULE_ID,
            &f.connector
        )
        .home_launch_context()
        .principal_id
    );
    let token = projection_launch_token_for_authority_context(
        f.data.path(),
        WALLET_WALLETCONNECT_CAPSULE_ID,
        &other,
    );
    let (status, values) = f.route_as(&other.home_token, &token, STORAGE, None).await;
    assert_eq!(status, StatusCode::OK, "{values}");
    assert_eq!(values, json!({}));
    f.state.walletconnect = Default::default();
    f.app = gateway_router_with_api_url(f.state.clone(), format!("http://{}", f.addr));
    let (_, values) = f.route(&f.connector, STORAGE, None).await;
    assert_eq!(values["session"]["secret"], "fixture-only");
    let (status, _) = f
        .route(
            &f.connector,
            STORAGE,
            Some(json!({"key":"too-large", "value":"x".repeat(1024 * 1024)})),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    let (_, values) = f.route(&f.connector, STORAGE, None).await;
    assert!(values.get("too-large").is_none());
}

#[tokio::test]
async fn walletconnect_relay_enforces_quota_and_tls_authentication() {
    let f = Fixture::new().await;
    f.allow().await;
    let mut first = f.ready().await;
    let mut second = f.ready().await;
    let mut third = f.connect(&f.connector, RELAY).await;
    assert!(matches!(
        third.next().await,
        Some(Ok(Message::Close(_))) | None
    ));
    assert_eq!(f.calls.load(Ordering::SeqCst), 2);
    let (_, granted) = f.route(&f.inbox, INTERNET, None).await;
    f.answer(&granted, true).await;
    assert!(matches!(
        first.next().await,
        Some(Ok(Message::Close(_))) | None
    ));
    assert!(matches!(
        second.next().await,
        Some(Ok(Message::Close(_))) | None
    ));
    // Restoring access with an empty root store refuses the fake certificate.
    *f.state.walletconnect.tls.lock().unwrap() = Some(Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth(),
    ));
    f.allow().await;
    let mut refused = f.connect(&f.connector, RELAY).await;
    assert!(matches!(
        refused.next().await,
        Some(Ok(Message::Close(_))) | None
    ));
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        3,
        "TLS refusal happens after Exit admission"
    );
}

#[tokio::test]
async fn walletconnect_relay_heartbeats_and_expires_idle_connection() {
    let f = Fixture::new().await;
    f.allow().await;
    let mut socket = f.ready().await;
    // Pause only after the real TCP/TLS handshakes. Pongs keep heartbeat alive,
    // while only application data extends the separate idle deadline.
    // Keep this runtime runnable so paused time advances only when the test
    // asks it to. Wait for a real upstream pong between every clock step.
    let clock_guard = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    tokio::time::pause();
    let mut pongs = f.state.walletconnect.pongs.load(Ordering::Relaxed);
    for _ in 0..19 {
        tokio::time::advance(Duration::from_secs(15)).await;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while f.state.walletconnect.pongs.load(Ordering::Relaxed) <= pongs {
            assert!(
                std::time::Instant::now() < deadline,
                "upstream pong was not processed"
            );
            tokio::task::yield_now().await;
        }
        pongs = f.state.walletconnect.pongs.load(Ordering::Relaxed);
    }
    // Last pong was at 285 s, within its 45 s limit. Only the 300 s idle
    // deadline can close this connection at the next tick.
    tokio::time::advance(Duration::from_secs(15)).await;
    tokio::time::resume();
    clock_guard.abort();
    assert!(f.pings.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(3), socket.next())
            .await
            .unwrap(),
        Some(Ok(Message::Close(_))) | None
    ));
}

#[tokio::test]
async fn walletconnect_reconnects_after_runtime_service_restart_with_saved_principal_state() {
    let mut f = Fixture::new().await;
    f.allow().await;
    let (status, _) = f
        .route(
            &f.connector,
            STORAGE,
            Some(json!({"key":"pairing", "value":{"topic":"fixture-topic"}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let mut first = f.ready().await;
    first.close(None).await.unwrap();
    f.gateway.abort();
    let _ = (&mut f.gateway).await;
    let tls = f.state.walletconnect.tls.lock().unwrap().clone();
    f.state.walletconnect = Default::default();
    f.state.browser_internet = persistent_internet(f.data.path()).await;
    *f.state.walletconnect.tls.lock().unwrap() = tls;
    let listener = TcpListener::bind(&f.addr).await.unwrap();
    f.app = gateway_router_with_api_url(f.state.clone(), format!("http://{}", f.addr));
    let app = f.app.clone();
    f.gateway = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let (_, stored) = f.route(&f.connector, STORAGE, None).await;
    assert_eq!(stored["pairing"]["topic"], "fixture-topic");
    let mut restored = f.ready().await;
    restored
        .send(Message::Text("restored-session-request".into()))
        .await
        .unwrap();
    assert_eq!(
        restored.next().await.unwrap().unwrap(),
        Message::Text("restored-session-request".into())
    );
    assert_eq!(f.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn walletconnect_refuses_malformed_writes_and_home_authority() {
    let f = Fixture::new().await;
    for body in [
        json!({"key":"session","value":"x","unknown":true}),
        json!({"key":"session","value":"x".repeat(2 * 1024 * 1024)}),
    ] {
        let (status, _) = f.route(&f.connector, STORAGE, Some(body)).await;
        assert_ne!(status, StatusCode::OK);
    }
    let (_, stored) = f.route(&f.connector, STORAGE, None).await;
    assert_eq!(stored, json!({}));
    for path in [
        STORAGE,
        "/api/apps/wallet-walletconnect/relay-admission",
        "/api/apps/wallet-walletconnect/host-config",
    ] {
        let (status, _) = f.route(&f.home, path, None).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "Home owns no WalletConnect authority"
        );
    }
    assert_eq!(
        capsule_route(&f, &f.connector, STORAGE, None).await,
        StatusCode::OK
    );
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn walletconnect_admissions_expire_and_can_be_used_once() {
    let f = Fixture::new().await;
    f.allow().await;
    let (_, admission) = f
        .route(
            &f.connector,
            "/api/apps/wallet-walletconnect/relay-admission",
            Some(json!({})),
        )
        .await;
    let token = admission["token"].as_str().unwrap();
    let mut socket = f.connect_ticket(token, RELAY).await;
    assert_eq!(
        socket.next().await.unwrap().unwrap(),
        Message::Text("{\"ready\":true}".into())
    );
    let mut replay = f.connect_ticket(token, RELAY).await;
    assert!(matches!(
        replay.next().await,
        Some(Ok(Message::Close(_))) | None
    ));
    let (_, admission) = f
        .route(
            &f.connector,
            "/api/apps/wallet-walletconnect/relay-admission",
            Some(json!({})),
        )
        .await;
    gateway_walletconnect::expire_admissions_for_test(&f.state).await;
    let mut expired = f
        .connect_ticket(admission["token"].as_str().unwrap(), RELAY)
        .await;
    assert!(matches!(
        expired.next().await,
        Some(Ok(Message::Close(_))) | None
    ));
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn walletconnect_turn_off_cancels_a_tls_handshake_and_can_reconnect() {
    let f = Fixture::new().await;
    f.allow().await;
    f.pause_tls.store(true, Ordering::SeqCst);
    let mut socket = f.connect(&f.connector, RELAY).await;
    tokio::time::timeout(Duration::from_secs(5), f.handshake.notified())
        .await
        .unwrap();
    let (_, granted) = f.route(&f.inbox, INTERNET, None).await;
    f.answer(&granted, true).await;
    assert!(matches!(
        socket.next().await,
        Some(Ok(Message::Close(_))) | None
    ));
    f.pause_tls.store(false, Ordering::SeqCst);
    f.resume.notify_one();
    f.allow().await;
    let _restored = f.ready().await;
    assert_eq!(f.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn walletconnect_revoked_owner_cannot_send_another_relay_frame() {
    let f = Fixture::new().await;
    f.allow().await;
    let mut socket = f.ready().await;
    let owner = crate::auth::list_passkey_principals(f.data.path())
        .unwrap()
        .into_iter()
        .find(crate::auth::is_admin)
        .unwrap();
    crate::auth::revoke_passkey_binding(f.data.path(), &owner.proof_binding_id, now_ts()).unwrap();
    socket
        .send(Message::Text("refused-after-owner-revoke".into()))
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .unwrap(),
        Some(Ok(Message::Close(_))) | None
    ));
}

// Real frontdoor and app routes, carrying only the capsule launch token.
async fn capsule_route(f: &Fixture, token: &str, path: &str, body: Option<Value>) -> StatusCode {
    let origin = if token == f.home {
        format!("http://{}", f.addr)
    } else {
        "null".into()
    };
    f.app
        .clone()
        .oneshot(
            Request::builder()
                .header(HOST, &f.addr)
                .header("origin", origin)
                .header("x-elastos-home-token", token)
                .header(CONTENT_TYPE, "application/json")
                .uri(path)
                .method(if body.is_some() { "POST" } else { "GET" })
                .body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn walletconnect_capsule_owns_storage_and_admission() {
    let f = Fixture::new().await;
    f.allow().await;
    let context = runtime_wallet_authority_for_app_token(
        f.data.path(),
        WALLET_WALLETCONNECT_CAPSULE_ID,
        &f.connector,
    )
    .home_launch_context();
    let expired = gateway_home_token::issue_expired_home_launch_token_with_context(
        f.data.path(),
        WALLET_WALLETCONNECT_CAPSULE_ID,
        &context,
    )
    .unwrap();
    for (path, body) in [
        (STORAGE, None),
        (STORAGE, Some(json!({"key":"positive","value":true}))),
        (
            "/api/apps/wallet-walletconnect/relay-admission",
            Some(json!({})),
        ),
    ] {
        for token in [&f.home, &f.inbox, &expired] {
            assert_ne!(
                capsule_route(&f, token, path, body.clone()).await,
                StatusCode::OK,
                "{path}: invalid caller"
            );
        }
        assert_eq!(
            capsule_route(&f, &f.connector, path, body).await,
            StatusCode::OK,
            "{path}: capsule owns its resource"
        );
    }
    crate::auth::revoke_session_grant(f.data.path(), &context.session_id, now_ts()).unwrap();
    for (path, body) in [
        (STORAGE, None),
        (STORAGE, Some(json!({"key":"replay","value":true}))),
        (
            "/api/apps/wallet-walletconnect/relay-admission",
            Some(json!({})),
        ),
    ] {
        assert_ne!(
            capsule_route(&f, &f.connector, path, body).await,
            StatusCode::OK,
            "{path}: replay after session revocation"
        );
    }
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn walletconnect_opaque_relay_redeems_once_and_rechecks_launch() {
    let f = Fixture::new().await;
    f.allow().await;
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .header(HOST, &f.addr)
                .header("origin", "null")
                .header("x-elastos-home-token", &f.connector)
                .uri("/api/apps/wallet-walletconnect/relay-admission")
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    let ticket: Value = serde_json::from_slice(&bytes).unwrap();
    let mut request = format!("ws://{}/api/apps/wallet-walletconnect/relay", f.addr)
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("origin", "null".parse().unwrap());
    let (mut socket, _) = connect_async(request.clone()).await.unwrap();
    let hello = json!({"token":ticket["token"], "relay":RELAY}).to_string();
    socket.send(Message::Text(hello.clone())).await.unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap(),
        Message::Text("{\"ready\":true}".into())
    );
    let (mut replay, _) = connect_async(request).await.unwrap();
    replay.send(Message::Text(hello)).await.unwrap();
    assert!(matches!(
        replay.next().await,
        Some(Ok(Message::Close(_))) | None
    ));
    let context = runtime_wallet_authority_for_app_token(
        f.data.path(),
        WALLET_WALLETCONNECT_CAPSULE_ID,
        &f.connector,
    )
    .home_launch_context();
    crate::auth::revoke_session_grant(f.data.path(), &context.session_id, now_ts()).unwrap();
    // The heartbeat must close an idle socket whose launch lost its live session.
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(20), socket.next())
            .await
            .unwrap(),
        Some(Ok(Message::Close(_))) | None
    ));
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn walletconnect_caps_unadmitted_opaque_sockets_and_recovers() {
    let f = Fixture::new().await;
    let mut sockets = Vec::new();
    for _ in 0..16 {
        let mut request = format!("ws://{}/api/apps/wallet-walletconnect/relay", f.addr)
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("origin", "null".parse().unwrap());
        sockets.push(connect_async(request).await.unwrap().0);
    }
    let mut request = format!("ws://{}/api/apps/wallet-walletconnect/relay", f.addr)
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("origin", "null".parse().unwrap());
    assert!(
        matches!(connect_async(request.clone()).await, Err(tokio_tungstenite::tungstenite::Error::Http(ref r)) if r.status() == StatusCode::TOO_MANY_REQUESTS)
    );
    for socket in &mut sockets {
        socket.close(None).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (mut recovered, _) = connect_async(request).await.unwrap();
    recovered.close(None).await.unwrap();
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn walletconnect_disconnect_and_turn_off_clear_sessions_and_refuse_late_writes() {
    let f = Fixture::new().await;
    f.allow().await;
    assert_eq!(
        f.route(
            &f.connector,
            STORAGE,
            Some(json!({"key":"session","value":"fixture"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .header(HOST, &f.addr)
                .header("origin", "null")
                .header("x-elastos-home-token", &f.connector)
                .method("DELETE")
                .uri(STORAGE)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(f.route(&f.connector, STORAGE, None).await.1, json!({}));
    assert_eq!(
        f.route(
            &f.connector,
            STORAGE,
            Some(json!({"key":"session","value":"fixture"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, grant) = f.route(&f.inbox, INTERNET, None).await;
    f.answer(&grant, true).await;
    assert_eq!(f.route(&f.connector, STORAGE, None).await.1, json!({}));
    assert_ne!(
        f.route(
            &f.connector,
            STORAGE,
            Some(json!({"key":"late","value":"refused"}))
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn walletconnect_cleanup_refuses_linked_parent_and_preserves_other_files() {
    let f = Fixture::new().await;
    f.allow().await;
    assert_eq!(
        f.route(
            &f.connector,
            STORAGE,
            Some(json!({"key":"session","value":"fixture"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let data = f.data.path();
    let sessions = data.join("ElastOS/SystemServices/WalletConnect/sessions");
    let other = tempfile::tempdir().unwrap();
    let principal =
        runtime_wallet_authority_for_app_token(data, WALLET_WALLETCONNECT_CAPSULE_ID, &f.connector)
            .home_launch_context()
            .principal_id;
    let name = format!("{}.json", hex::encode(Sha256::digest(principal.as_bytes())));
    std::fs::write(other.path().join(&name), "preserve").unwrap();
    std::fs::rename(&sessions, sessions.with_extension("held")).unwrap();
    std::os::unix::fs::symlink(other.path(), &sessions).unwrap();
    assert!(gateway_walletconnect::clear_principal_storage(data, &principal).is_err());
    assert_eq!(
        std::fs::read_to_string(other.path().join(name)).unwrap(),
        "preserve"
    );
}

#[tokio::test]
async fn walletconnect_guest_uses_an_existing_owner_grant_without_another_approval() {
    let f = Fixture::new().await;
    let guest = passkey_authority_with_name_role_credential(
        f.data.path(),
        Some("wc-guest"),
        crate::auth::RuntimePrincipalRole::Guest,
        "wc-guest-credential",
    );
    let token = projection_launch_token_for_authority_context(
        f.data.path(),
        WALLET_WALLETCONNECT_CAPSULE_ID,
        &guest,
    );
    assert_ne!(
        f.route(&token, INTERNET, Some(json!({"action":"request"})))
            .await
            .0,
        StatusCode::OK
    );
    f.allow().await;
    let (_, before) = f.route(&f.inbox, INTERNET, None).await;
    let (status, after) = f
        .route(&token, INTERNET, Some(json!({"action":"request"})))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(before["request"]["id"], after["request"]["id"]);
    assert_eq!(
        f.route(
            &token,
            STORAGE,
            Some(json!({"key":"session","value":"guest"}))
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn walletconnect_cleanup_fences_old_storage_and_admission_and_removes_crash_temps() {
    let f = Fixture::new().await;
    f.allow().await;
    assert_eq!(
        f.route(
            &f.connector,
            STORAGE,
            Some(json!({"key":"session","value":"fixture"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let principal = runtime_wallet_authority_for_app_token(
        f.data.path(),
        WALLET_WALLETCONNECT_CAPSULE_ID,
        &f.connector,
    )
    .home_launch_context()
    .principal_id;
    let directory = f
        .data
        .path()
        .join("ElastOS/SystemServices/WalletConnect/sessions");
    let name = format!("{}.json", hex::encode(Sha256::digest(principal.as_bytes())));
    std::fs::write(
        directory.join(format!(".{name}.0123456789abcdef.tmp")),
        "fixture-crash-keys",
    )
    .unwrap();
    std::fs::write(directory.join("operator-note.txt"), "preserve").unwrap();
    let (_, grant) = f.route(&f.inbox, INTERNET, None).await;
    f.answer(&grant, true).await;
    assert!(!directory.join(&name).exists());
    assert!(!directory
        .join(format!(".{name}.0123456789abcdef.tmp"))
        .exists());
    assert_eq!(
        std::fs::read_to_string(directory.join("operator-note.txt")).unwrap(),
        "preserve"
    );
    f.allow().await;
    for (path, body) in [
        (STORAGE, json!({"key":"late","value":"old-sdk"})),
        ("/api/apps/wallet-walletconnect/relay-admission", json!({})),
    ] {
        let response = f
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .header(HOST, &f.addr)
                    .header("origin", "null")
                    .header("x-elastos-home-token", &f.connector)
                    .header("if-match", "\"0\"")
                    .header(CONTENT_TYPE, "application/json")
                    .uri(path)
                    .method("POST")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::OK, "stale SDK {path}");
    }
    assert_eq!(
        f.route(
            &f.connector,
            STORAGE,
            Some(json!({"key":"new","value":"fresh-sdk"}))
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn walletconnect_turn_off_keeps_cleanup_retry_in_its_inbox_entry() {
    let f = Fixture::new().await;
    f.allow().await;
    assert_eq!(
        f.route(
            &f.connector,
            STORAGE,
            Some(json!({"key":"session","value":"fixture"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, grant) = f.route(&f.inbox, INTERNET, None).await;
    let sessions = f
        .data
        .path()
        .join("ElastOS/SystemServices/WalletConnect/sessions");
    let held = sessions.with_extension("held");
    std::fs::rename(&sessions, &held).unwrap();
    let other = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(other.path(), &sessions).unwrap();
    let token = gateway_passkey_step_up::issue_passkey_step_up_token_for_test(
        f.data.path(),
        &f.inbox,
        INBOX_CAPSULE_ID,
        gateway_walletconnect::REVOKE,
        &grant["request"],
    )
    .unwrap();
    let action = format!(
        "walletconnect-internet-turn-off:{}",
        grant["request"]["id"].as_str().unwrap()
    );
    assert_ne!(
        f.route(
            &f.inbox,
            "/api/apps/inbox/actions",
            Some(json!({"action_id":action,"step_up_token":token}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let context = runtime_wallet_authority_for_app_token(f.data.path(), INBOX_CAPSULE_ID, &f.inbox)
        .home_launch_context();
    assert!(gateway_walletconnect::notification(&f.state, &context)
        .unwrap()
        .action_ref
        .is_some());
    std::fs::rename(&sessions, sessions.with_extension("refused-link")).unwrap();
    std::fs::rename(&held, &sessions).unwrap();
    assert_eq!(
        f.route(
            &f.inbox,
            "/api/apps/inbox/actions",
            Some(json!({"action_id":action}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(gateway_walletconnect::notification(&f.state, &context)
        .unwrap()
        .action_ref
        .is_none());
}

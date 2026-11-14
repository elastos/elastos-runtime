//! Opt-in network acceptance. The project ID enters only through the operator file.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use elastos_runtime::provider::{BridgeProviderConfig, CapsuleProvider, ProviderBridge};
use std::io::Read;

fn operator_project() -> String {
    let file = std::env::var_os("ELASTOS_WALLETCONNECT_PROJECT_FILE")
        .expect("set ELASTOS_WALLETCONNECT_PROJECT_FILE");
    // The trusted operator input may be a pipe on a rented test machine. Read
    // at most 130 bytes; the driver owns the pipe and the test time limit.
    let mut bytes = Vec::new();
    std::io::Read::take(
        std::fs::File::open(file).expect("open operator project file"),
        130,
    )
    .read_to_end(&mut bytes)
    .expect("read bounded operator project file");
    assert!(
        bytes.len() <= 129,
        "operator project input exceeds its limit"
    );
    let project = std::str::from_utf8(&bytes)
        .expect("operator project file is UTF-8")
        .trim();
    assert!(project.len() >= 8 && project.len() <= 128);
    assert!(project
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    project.to_owned()
}

struct RealFixture {
    fixture: Fixture,
    helper: std::process::Child,
}
impl std::ops::Deref for RealFixture {
    type Target = Fixture;
    fn deref(&self) -> &Fixture {
        &self.fixture
    }
}
impl std::ops::DerefMut for RealFixture {
    fn deref_mut(&mut self) -> &mut Fixture {
        &mut self.fixture
    }
}
impl Drop for RealFixture {
    fn drop(&mut self) {
        // Parent EOF lets the helper release its exact socket and owned children.
        drop(self.helper.stdin.take());
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while self.helper.try_wait().ok().flatten().is_none() {
            if std::time::Instant::now() >= deadline {
                let _ = self.helper.kill();
                let _ = self.helper.wait();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

async fn production_exit(data: &std::path::Path) -> Arc<dyn Provider> {
    let binary = std::env::var_os("ELASTOS_WALLETCONNECT_TEST_EXIT_PROVIDER")
        .expect("set the real exit-provider binary path");
    let platform = crate::setup::detect_platform();
    let (_, config) = crate::setup::walletconnect::local_exit(data, &platform).unwrap();
    let bridge = ProviderBridge::spawn(
        std::path::Path::new(&binary),
        BridgeProviderConfig {
            extra: crate::setup::walletconnect::exit_config(Value::Null, Some(&config)),
            ..Default::default()
        },
    )
    .await
    .expect("real exit-provider accepts the generated config");
    Arc::new(CapsuleProvider::with_scheme(Arc::new(bridge), "exit"))
}

async fn real_fixture(project: &str) -> RealFixture {
    let mut f = Fixture::new().await;
    assert!(!f.addr.ends_with(":8090"));
    let config_path = f.data.path().join(WALLETCONNECT_CONFIG_PATH);
    let mut config: Value = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    config["project_id"] = json!(project);
    crate::auth::atomic_write(&config_path, &serde_json::to_vec(&config).unwrap()).unwrap();
    *f.state.walletconnect.tls.lock().unwrap() = None;
    f.relay.abort();
    let _ = (&mut f.relay).await;
    let (helper_config, _) =
        crate::setup::walletconnect::local_exit(f.data.path(), &crate::setup::detect_platform())
            .unwrap();
    let helper_binary = std::env::var_os("ELASTOS_WALLETCONNECT_TEST_LOCAL_EXIT")
        .expect("set the real browser-local-exit binary path");
    let mut helper = std::process::Command::new(helper_binary)
        .env(
            "ELASTOS_BROWSER_LOCAL_EXIT_CONFIG",
            helper_config.to_string(),
        )
        .env("ELASTOS_BROWSER_LOCAL_EXIT_PARENT_EOF", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let ready = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(
                helper.try_wait().unwrap().is_none(),
                "local Exit exited before readiness"
            );
            if std::fs::symlink_metadata(helper_config["relay_ipc_path"].as_str().unwrap()).is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    ready.expect("real local Exit socket readiness");
    let registry = f.state.provider_registry.as_ref().unwrap();
    registry.unregister_sub_provider("exit").await.unwrap();
    registry
        .register_sub_provider("exit", production_exit(f.data.path()).await)
        .await
        .unwrap();
    RealFixture { fixture: f, helper }
}

// Matches @walletconnect/relay-auth's locked signJWT/encodeIss implementation.
fn relay_auth() -> String {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut public = vec![0xed, 0x01];
    public.extend_from_slice(key.verifying_key().as_bytes());
    let issuer = format!("did:key:z{}", bs58::encode(public).into_string());
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": issuer, "sub": gateway_home_token::uuid_like_token(),
            "aud": "wss://relay.walletconnect.org", "iat": now_ts(), "exp": now_ts() + 300,
        }))
        .unwrap(),
    );
    let data = format!("{header}.{payload}");
    format!(
        "{data}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(data.as_bytes()).to_bytes())
    )
}

#[tokio::test]
#[ignore = "operator acceptance: needs ELASTOS_WALLETCONNECT_PROJECT_FILE and the real relay"]
async fn walletconnect_real_project_opens_through_runtime_and_exit() {
    let project = operator_project();
    let f = real_fixture(&project).await;
    f.allow().await;
    let mut url = url::Url::parse("wss://relay.walletconnect.org/").unwrap();
    url.query_pairs_mut()
        .append_pair("projectId", &project)
        .append_pair("auth", &relay_auth());
    let mut socket = f.connect(&f.connector, url.as_str()).await;
    let first = tokio::time::timeout(Duration::from_secs(30), socket.next()).await;
    assert!(
        matches!(first, Ok(Some(Ok(Message::Text(ref value)))) if value == "{\"ready\":true}"),
        "Runtime did not confirm the authenticated upstream WebSocket upgrade"
    );
    // A successful relay RPC also excludes a post-upgrade authentication close.
    // Reown requires a fresh timestamp-based ID, as the pinned SDK supplies.
    let request_id = now_ts() * 1_000_000;
    socket.send(Message::Text(json!({
        "id": request_id, "jsonrpc": "2.0", "method": "irn_subscribe",
        "params": { "topic": format!("{:x}", Sha256::digest(gateway_home_token::uuid_like_token())) },
    }).to_string())).await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(15), socket.next()).await;
    let Ok(Some(Ok(Message::Text(response)))) = response else {
        panic!("real relay did not answer the subscription through Runtime");
    };
    let response: Value = serde_json::from_str(&response).expect("relay JSON response");
    assert!(
        response["id"] == request_id && response["result"].is_string(),
        "real relay subscription failed"
    );
    socket.close(None).await.unwrap();
    println!("PASS: Runtime -> real exit-provider -> real browser-local-exit -> authenticated Reown WSS upgrade and subscription; project file set; ephemeral localhost port; no 401/403");
}

// A separate process makes restart discard every gateway socket and global.
#[tokio::test]
#[ignore = "private worker for the real-relay paired recovery test"]
async fn walletconnect_gateway_process_worker() {
    let mut bytes = Vec::new();
    std::io::Read::take(std::io::stdin(), 8192)
        .read_to_end(&mut bytes)
        .unwrap();
    let input: Value = serde_json::from_slice(&bytes).unwrap();
    let data = std::path::Path::new(input["data"].as_str().unwrap());
    let addr = input["addr"].as_str().unwrap();
    // Preserve the already staged production documents and adapter on disk.
    // test_state() seeds placeholder capsules, so this worker builds state directly.
    let mut state = GatewayState {
        provider_registry: None,
        collaboration_chat_product_port: None,
        collaboration_presence_product_port: None,
        carrier_endpoint: None,
        collaboration_discovery_service: None,
        browser_internet: persistent_internet(data).await,
        walletconnect: Default::default(),
        identity_manager: Arc::new(std::sync::OnceLock::new()),
        cache_dir: data.to_path_buf(),
        data_dir: data.to_path_buf(),
    };
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_sub_provider("exit", production_exit(data).await)
        .await
        .unwrap();
    state.provider_registry = Some(registry);
    let expected_origin = format!("http://{addr}");
    let expected_host = addr.to_string();
    let refusal_path = data.join("relay-handshake-refusal.json");
    let app = gateway_router_with_api_url(state, expected_origin.clone()).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let refusal_path = refusal_path.clone();
            let relay = request.uri().path() == "/api/apps/wallet-walletconnect/relay";
            let origin_count = request.headers().get_all("origin").iter().count();
            let origin = request.headers().get("origin").and_then(|h|h.to_str().ok());
            let kind = match origin { None=>"missing",Some("null")=>"opaque",Some(value) if value==expected_origin=>"same-home",_=>"other" };
            let host_matches = request.headers().get("host").and_then(|h|h.to_str().ok()) == Some(expected_host.as_str());
            let fetch_metadata = json!({
                "site":request.headers().get("sec-fetch-site").and_then(|v|v.to_str().ok()),
                "mode":request.headers().get("sec-fetch-mode").and_then(|v|v.to_str().ok()),
                "dest":request.headers().get("sec-fetch-dest").and_then(|v|v.to_str().ok()),
            });
            async move {
                if relay {
                    crate::auth::atomic_write(&refusal_path.with_file_name("relay-fetch-metadata.json"), &serde_json::to_vec(&fetch_metadata).unwrap()).unwrap();
                }
                let response = next.run(request).await;
                if relay && response.status()==StatusCode::FORBIDDEN {
                    crate::auth::atomic_write(&refusal_path, &serde_json::to_vec(&json!({"status":403,"origin_kind":kind,"origin_headers":origin_count,"host_matches":host_matches})).unwrap()).unwrap();
                }
                response
            }
        }
    ));
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("WC_GATEWAY_READY");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn start_gateway_process(f: &Fixture) -> tokio::process::Child {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "api::gateway::gateway_tests::wallet::walletconnect::real_relay::walletconnect_gateway_process_worker", "--ignored", "--nocapture"])
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null()).kill_on_drop(true).spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&json!({"data":f.data.path(), "addr":f.addr})).unwrap())
        .await
        .unwrap();
    let mut stdout = tokio::io::BufReader::new(child.stdout.take().unwrap());
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut count = 0;
        loop {
            let mut line = String::new();
            let length = stdout.read_line(&mut line).await.unwrap();
            count += length;
            assert!(
                length > 0 && count <= 32768,
                "gateway worker failed before readiness"
            );
            if line.trim().ends_with("WC_GATEWAY_READY") {
                break;
            }
        }
    })
    .await
    .expect("gateway worker startup timeout");
    child.stdout = Some(stdout.into_inner());
    child
}

#[tokio::test]
#[ignore = "operator acceptance: real relay, pinned SDK, Playwright Chromium and WebKit"]
async fn walletconnect_real_project_opaque_preflight() {
    use tokio::io::AsyncWriteExt;
    let project = operator_project();
    let mut f = real_fixture(&project).await;
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    for name in ["home", "wallet-walletconnect"] {
        let destination = f.data.path().join("capsules").join(name);
        activate_test_capsule(f.data.path(), name);
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::copy(
            repo.join("capsules").join(name).join("capsule.json"),
            destination.join("capsule.json"),
        )
        .unwrap();
        super::super::super::content_sandbox::copy_operator_site(
            &repo.join("capsules").join(name).join("browser"),
            &destination.join("browser"),
        );
        write_test_wasm_entrypoint(f.data.path(), name);
    }
    let capsule = f.data.path().join("capsules/wallet-walletconnect");
    let sdk =
        std::fs::read(repo.join("capsules/wallet-walletconnect/vendor/reown-appkit.js")).unwrap();
    std::fs::write(capsule.join("vendor/reown-appkit.js"), &sdk).unwrap();
    crate::auth::atomic_write(
        &f.data.path().join(WALLETCONNECT_CONFIG_PATH),
        &serde_json::to_vec(&json!({
            "schema": WALLETCONNECT_CONFIG_SCHEMA, "project_id": project,
            "sdk_package": WALLETCONNECT_SDK_PACKAGE, "sdk_version": "2.23.9",
            "sdk_sha256": format!("{:x}", Sha256::digest(&sdk)),
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::copy(
        repo.join("scripts/lib/walletconnect-real-browser-fixture.mjs"),
        capsule.join("browser/wc-real-fixture.js"),
    )
    .unwrap();
    std::fs::write(
        capsule.join("browser/wc-real.html"),
        "<!doctype html><script type=\"module\" src=\"./wc-real-fixture.js\"></script>",
    )
    .unwrap();
    f.allow().await;
    f.gateway.abort();
    let _ = (&mut f.gateway).await;
    let mut gateway_process = start_gateway_process(&f).await;
    let restart_path = f.data.path().join("restart.sock");
    let restart = UnixListener::bind(&restart_path).unwrap();
    let input = serde_json::to_vec(&json!({
        "origin": format!("http://{}", f.addr), "connector": f.connector, "projectId": project, "restart":restart_path,
    }))
    .unwrap();
    let mut child = tokio::process::Command::new("node")
        .arg(repo.join("scripts/walletconnect-real-preflight-smoke.mjs"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&input).await.unwrap();
    let mut waiting = tokio::spawn(async move { child.wait_with_output().await });
    let result = tokio::time::timeout(Duration::from_secs(270), async {
        loop {
            tokio::select! {
                output = &mut waiting => break output.unwrap().unwrap(),
                connection = restart.accept() => {
                    let (mut connection, _) = connection.unwrap();
                    let mut command = [0u8; 7];
                    tokio::time::timeout(Duration::from_secs(3), connection.read_exact(&mut command)).await.unwrap().unwrap();
                    assert_eq!(&command, b"restart");
                    let previous = gateway_process.id();
                    gateway_process.kill().await.unwrap();
                    gateway_process = start_gateway_process(&f).await;
                    assert_ne!(gateway_process.id(), previous, "restart requires a fresh gateway process");
                    connection.write_all(b"ready").await.unwrap();
                }
            }
        }
    }).await;
    if result.is_err() {
        waiting.abort();
    }
    gateway_process.kill().await.unwrap();
    let output = result.expect("real relay paired recovery timeout");
    println!("{}", String::from_utf8_lossy(&output.stdout));
    if let Some(bytes) =
        gateway_walletconnect::read_bytes(&f.data.path().join("relay-handshake-refusal.json"), 1024)
            .unwrap()
    {
        let record: Value = serde_json::from_slice(&bytes).unwrap();
        println!("{}", json!({"relay_handshake_refusal":record}));
    }
    if let Some(bytes) =
        gateway_walletconnect::read_bytes(&f.data.path().join("relay-fetch-metadata.json"), 1024)
            .unwrap()
    {
        println!(
            "{}",
            json!({"relay_fetch_metadata":serde_json::from_slice::<Value>(&bytes).unwrap()})
        );
    }
    // The Node driver emits only bounded, value-free evidence. SDK diagnostics
    // can contain relay credentials, so stderr remains private to this process.
    assert!(
        output.status.success(),
        "real relay opaque preflight failed; see structured evidence (project file set)"
    );
}

//! Opt-in network acceptance. The project ID enters only through the operator file.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use std::io::Read;
use tokio::net::TcpStream;

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

async fn real_fixture(project: &str) -> Fixture {
    let mut f = Fixture::new().await;
    assert!(!f.addr.ends_with(":8090"));
    let config_path = f.data.path().join(WALLETCONNECT_CONFIG_PATH);
    let mut config: Value = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    config["project_id"] = json!(project);
    crate::auth::atomic_write(&config_path, &serde_json::to_vec(&config).unwrap()).unwrap();
    // Use the production root store. This Exit harness forwards raw TLS bytes;
    // Runtime retains relay authentication and the HTTP/WebSocket handshake.
    *f.state.walletconnect.tls.lock().unwrap() = None;
    let path = f.data.path().join("real-relay.sock");
    let listener = UnixListener::bind(&path).unwrap();
    f.relay.abort();
    f.relay = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut stream, _) = accepted.unwrap();
                    connections.spawn(async move {
                        let mut line = Vec::new();
                        loop {
                            let Ok(byte) = stream.read_u8().await else { return; };
                            if byte == b'\n' { break; }
                            line.push(byte);
                            assert!(line.len() < 16384);
                        }
                        let open: Value = serde_json::from_slice(&line).unwrap();
                        assert_eq!(open["schema"], "elastos.exit.relay-open/v1");
                        assert_eq!(open["target"], "tls://relay.walletconnect.org:443");
                        let Ok(Ok(mut remote)) = tokio::time::timeout(
                            Duration::from_secs(10), TcpStream::connect(("relay.walletconnect.org", 443))
                        ).await else { return; };
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut remote).await;
                    });
                }
                result = connections.join_next(), if !connections.is_empty() => { result.unwrap().unwrap(); }
            }
        }
    });
    let registry = f.state.provider_registry.as_ref().unwrap();
    registry.unregister_sub_provider("exit").await.unwrap();
    registry
        .register_sub_provider(
            "exit",
            Arc::new(Exit {
                path,
                calls: f.calls.clone(),
            }),
        )
        .await
        .unwrap();
    f
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
    println!("PASS: Runtime -> Exit harness -> authenticated Reown WSS upgrade and subscription; project file set; ephemeral localhost port; no 401/403");
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
    let mut state = test_state(data);
    state.browser_internet = persistent_internet(data).await;
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .register_sub_provider(
            "exit",
            Arc::new(Exit {
                path: data.join("real-relay.sock"),
                calls: Arc::new(AtomicUsize::new(0)),
            }),
        )
        .await
        .unwrap();
    state.provider_registry = Some(registry);
    let app = gateway_router_with_api_url(state, format!("http://{addr}"));
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
            if line.trim() == "WC_GATEWAY_READY" {
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
    // The Node driver emits only bounded, value-free evidence. SDK diagnostics
    // can contain relay credentials, so stderr remains private to this process.
    assert!(
        output.status.success(),
        "real relay opaque preflight failed; see structured evidence (project file set)"
    );
}

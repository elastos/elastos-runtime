//! Opt-in network acceptance. The project ID enters only through the operator file.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use tokio::net::TcpStream;

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
    let file = std::env::var_os("ELASTOS_WALLETCONNECT_PROJECT_FILE")
        .expect("set ELASTOS_WALLETCONNECT_PROJECT_FILE");
    let bytes = gateway_walletconnect::read_bytes(std::path::Path::new(&file), 129)
        .expect("read bounded operator project file")
        .expect("operator project file exists");
    let project = std::str::from_utf8(&bytes)
        .expect("operator project file is UTF-8")
        .trim();
    assert!(project.len() >= 8 && project.len() <= 128);
    assert!(project
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
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
    f.allow().await;
    let mut url = url::Url::parse("wss://relay.walletconnect.org/").unwrap();
    url.query_pairs_mut()
        .append_pair("projectId", project)
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
    println!("PASS: Runtime -> Exit harness -> authenticated Reown WSS upgrade and subscription; project <project-id>; ephemeral localhost port; no 401/403");
}

//! Relay-only defaults for a configured WalletConnect Home, independent of a Browser VM.
use std::path::Path;

pub fn local_exit(data: &Path, platform: &str) -> Option<(serde_json::Value, serde_json::Value)> {
    crate::api::gateway::ensure_wallet_connector_configured(data, "wallet-walletconnect").ok()?;
    if !matches!(platform, "darwin-arm64" | "linux-amd64" | "linux-arm64") {
        return None;
    }
    let adapter = super::browser_config::runtime_socket_path(data, platform, "wc-adapter");
    let socket = super::browser_config::runtime_socket_path(data, platform, "wc-relay");
    let hosts = ["relay.walletconnect.org", "relay.walletconnect.com"];
    let helper = serde_json::json!({
        "schema":"elastos.browser.local-exit.config/v1", "relay_ipc_path":socket,
        "allowed_hosts":hosts, "allowed_schemes":["tls"], "allowed_ports":[443],
        "replace_existing_socket":true,
    });
    let provider = serde_json::json!({"backends":[{
        "id":"walletconnect-local-exit", "kind":"stream_relay",
        "allowed_hosts":hosts, "allowed_schemes":["tls"], "allowed_ports":[443],
        "adapter_ipc":{"kind":"unix_socket","path":adapter},
        "relay_ipc":{"kind":"unix_socket","path":socket},
    }]});
    Some((helper, provider))
}

/// Keep the owner's existing Exit configuration and add only the relay-local backend.
pub fn merge_exit_config(
    mut existing: serde_json::Value,
    walletconnect: Option<&serde_json::Value>,
    browser_helper_running: bool,
) -> anyhow::Result<serde_json::Value> {
    let Some(walletconnect) = walletconnect else {
        return Ok(existing);
    };
    if existing.is_null() {
        existing = serde_json::json!({});
    }
    let object = existing
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Exit configuration must be an object"))?;
    let backends = object
        .entry("backends")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("Exit backends must be a list"))?;
    let managed = &walletconnect["backends"][0];
    if let Some(index) = backends.iter().position(|b| b["id"] == managed["id"]) {
        anyhow::ensure!(
            &backends[index] == managed,
            "WalletConnect Exit backend has a conflicting route"
        );
        backends.remove(index);
    }
    // Exit matches in list order. A running Browser helper keeps first match.
    // Without it, the relay-only route precedes retained Browser wildcards;
    // every other backend retains its order and its matching policy.
    if browser_helper_running {
        backends.push(managed.clone());
    } else {
        let browser = backends
            .iter()
            .position(|backend| backend["id"] == "source-home-browser-exit")
            .unwrap_or(backends.len());
        backends.insert(browser, managed.clone());
    }
    exit_provider::parse_config(existing.clone()).map_err(anyhow::Error::msg)?;
    Ok(existing)
}

/// Refresh checks the relay used by the generated Browser backend at that moment.
/// Owner backends retain their position regardless of Browser helper state.
pub async fn browser_helper_running(config: &serde_json::Value, platform: &str) -> bool {
    if !super::browser_available(platform) {
        return false;
    }
    #[cfg(unix)]
    if let Some(path) = config["backends"]
        .as_array()
        .and_then(|backends| {
            backends
                .iter()
                .find(|backend| backend["id"] == "source-home-browser-exit")
        })
        .and_then(|backend| backend["relay_ipc"]["path"].as_str())
    {
        return matches!(
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                tokio::net::UnixStream::connect(path),
            )
            .await,
            Ok(Ok(_))
        );
    }
    false
}

/// A refused WalletConnect addition leaves the owner's Exit selection intact.
pub fn exit_config(
    existing: serde_json::Value,
    walletconnect: Option<&serde_json::Value>,
    browser_helper_running: bool,
) -> serde_json::Value {
    match merge_exit_config(existing.clone(), walletconnect, browser_helper_running) {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!(%error, "WalletConnect Exit configuration was refused; starting the existing Exit configuration");
            existing
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn walletconnect_local_exit_needs_pinned_config_and_uses_relay_hosts_only() {
        let data = tempfile::Builder::new()
            .prefix("Application Support ")
            .tempdir()
            .unwrap();
        assert!(local_exit(data.path(), "darwin-arm64").is_none());
        let sdk = data
            .path()
            .join("capsules/wallet-walletconnect/vendor/reown-appkit.js");
        std::fs::create_dir_all(sdk.parent().unwrap()).unwrap();
        std::fs::write(&sdk, "fixture-sdk").unwrap();
        let config = data
            .path()
            .join("ElastOS/SystemServices/WalletConnect/config.json");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({
                "schema":"elastos.walletconnect.connector/v1", "project_id":"fixture-project",
                "sdk_package":"@walletconnect/ethereum-provider", "sdk_version":"2.23.9",
                "sdk_sha256":hex::encode(sha2::Sha256::digest(b"fixture-sdk")),
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(local_exit(data.path(), "windows-amd64").is_none());
        assert!(local_exit(data.path(), "linux-amd64").is_some());
        let (helper, provider) = local_exit(data.path(), "darwin-arm64").unwrap();
        assert_eq!(
            helper["allowed_hosts"],
            serde_json::json!(["relay.walletconnect.org", "relay.walletconnect.com"])
        );
        assert_eq!(helper["allowed_ports"], serde_json::json!([443]));
        assert_eq!(
            provider["backends"][0]["relay_ipc"]["path"],
            helper["relay_ipc_path"]
        );
        assert_eq!(
            provider["backends"][0]["allowed_schemes"],
            serde_json::json!(["tls"])
        );
        let parsed = exit_provider::parse_config(provider.clone()).unwrap();
        assert_ne!(
            parsed.backends[0].adapter_ipc.as_ref().unwrap().path,
            parsed.backends[0].relay_ipc.as_ref().unwrap().path
        );
        assert!(helper["relay_ipc_path"].as_str().unwrap().len() < 104);
        std::fs::write(sdk, "tampered").unwrap();
        assert!(local_exit(data.path(), "darwin-arm64").is_none());
    }

    #[test]
    fn walletconnect_keeps_existing_remote_and_local_exit_configuration() {
        let remote = serde_json::json!({"backends":[], "timeout_secs":12});
        let wc = serde_json::json!({"backends":[{"id":"walletconnect-local-exit", "kind":"stream_relay", "allowed_hosts":["relay.walletconnect.org"]}]});
        let merged = merge_exit_config(remote.clone(), Some(&wc), true).unwrap();
        assert_eq!(merged["timeout_secs"], remote["timeout_secs"]);
        assert_eq!(merged["backends"], wc["backends"]);
        let local = serde_json::json!({"backends":[{"id":"owner-local", "kind":"stream_relay", "allowed_hosts":["*"]}]});
        let merged = merge_exit_config(local.clone(), Some(&wc), true).unwrap();
        assert_eq!(merged["backends"][0], local["backends"][0]);
        assert_eq!(
            merge_exit_config(remote.clone(), None, true).unwrap(),
            remote
        );
        assert!(merge_exit_config(serde_json::json!({"backends":false}), Some(&wc), true).is_err());
    }
    #[test]
    fn owner_local_backend_keeps_first_match_with_browser_stopped() {
        let config = serde_json::json!({"backends":[
            {"id":"owner-local", "kind":"stream_relay", "allowed_hosts":["*"]},
            {"id":"source-home-browser-exit", "kind":"stream_relay", "allowed_hosts":["*"]}
        ]});
        let wc = serde_json::json!({"backends":[{"id":"walletconnect-local-exit", "kind":"stream_relay", "allowed_hosts":["relay.walletconnect.org"]}]});
        for running in [false, true] {
            let merged = merge_exit_config(config.clone(), Some(&wc), running).unwrap();
            let parsed = exit_provider::parse_config(merged.clone()).unwrap();
            assert_eq!(parsed.backends[0].id, "owner-local");
            let target = url::Url::parse("tls://relay.walletconnect.org:443").unwrap();
            assert_eq!(
                parsed
                    .backends
                    .iter()
                    .find(|b| b.allows_target(&target))
                    .unwrap()
                    .id,
                "owner-local"
            );
            assert_eq!(
                merged["backends"][if running { 2 } else { 1 }]["id"],
                "walletconnect-local-exit"
            );
        }
    }

    #[test]
    fn walletconnect_refused_merge_preserves_browser_exit_and_matching_order() {
        let browser = serde_json::json!({"backends":[{"id":"browser", "kind":"stream_relay", "allowed_hosts":["*"]}]});
        let bad = serde_json::json!({"backends":[{"id":"walletconnect-local-exit", "kind":"stream_relay", "allowed_hosts":["relay.walletconnect.org"],
            "adapter_ipc":{"kind":"unix_socket","path":"/tmp/same.sock"}, "relay_ipc":{"kind":"unix_socket","path":"/tmp/same.sock"}}]});
        assert!(merge_exit_config(browser.clone(), Some(&bad), true).is_err());
        assert_eq!(exit_config(browser.clone(), Some(&bad), true), browser);
        let good = serde_json::json!({"backends":[{"id":"walletconnect-local-exit", "kind":"stream_relay", "allowed_hosts":["relay.walletconnect.org"]}]});
        let merged = exit_config(browser, Some(&good), true);
        let parsed = exit_provider::parse_config(merged).unwrap();
        for host in [
            "relay.walletconnect.org",
            "relay.walletconnect.com",
            "example.org",
        ] {
            let target = url::Url::parse(&format!("tls://{host}:443")).unwrap();
            assert_eq!(
                parsed
                    .backends
                    .iter()
                    .find(|b| b.allows_target(&target))
                    .unwrap()
                    .id,
                "browser"
            );
        }
    }

    #[test]
    fn retained_linux_browser_wildcard_uses_walletconnect_when_helper_is_stopped() {
        let platform = "linux-amd64";
        assert!(!super::super::browser_available(platform));
        let data = tempfile::tempdir().unwrap();
        let browser = serde_json::json!({"backends":[{
            "id":"source-home-browser-exit", "kind":"stream_relay",
            "allowed_hosts":["*"], "allowed_schemes":["tcp","tls"],
            "allowed_ports":[80,443],
            "adapter_ipc":{"kind":"unix_socket","path":super::super::browser_config::runtime_socket_path(data.path(), platform, "adapter")},
            "relay_ipc":{"kind":"unix_socket","path":super::super::browser_config::runtime_socket_path(data.path(), platform, "relay")}
        }]});
        let wc = serde_json::json!({"backends":[{
            "id":"walletconnect-local-exit", "kind":"stream_relay",
            "allowed_hosts":["relay.walletconnect.org","relay.walletconnect.com"],
            "allowed_schemes":["tls"], "allowed_ports":[443],
            "adapter_ipc":{"kind":"unix_socket","path":super::super::browser_config::runtime_socket_path(data.path(), platform, "wc-adapter")},
            "relay_ipc":{"kind":"unix_socket","path":super::super::browser_config::runtime_socket_path(data.path(), platform, "wc-relay")}
        }]});
        for running in [false, true] {
            let merged = merge_exit_config(browser.clone(), Some(&wc), running).unwrap();
            assert_eq!(
                merged["backends"][usize::from(!running)],
                browser["backends"][0]
            );
            let parsed = exit_provider::parse_config(merged.clone()).unwrap();
            for (target, expected) in [
                (
                    "tls://relay.walletconnect.org:443",
                    if running {
                        "source-home-browser-exit"
                    } else {
                        "walletconnect-local-exit"
                    },
                ),
                (
                    "tls://relay.walletconnect.com:443",
                    if running {
                        "source-home-browser-exit"
                    } else {
                        "walletconnect-local-exit"
                    },
                ),
                ("tls://example.org:443", "source-home-browser-exit"),
                ("tcp://example.org:80", "source-home-browser-exit"),
                (
                    "tcp://relay.walletconnect.org:443",
                    "source-home-browser-exit",
                ),
                (
                    "tls://relay.walletconnect.org:80",
                    "source-home-browser-exit",
                ),
            ] {
                let target = url::Url::parse(target).unwrap();
                assert_eq!(
                    parsed
                        .backends
                        .iter()
                        .find(|b| b.allows_target(&target))
                        .unwrap()
                        .id,
                    expected
                );
            }
            // Restarting with the other helper state normalises the managed route once.
            let reordered = merge_exit_config(merged, Some(&wc), !running).unwrap();
            assert_eq!(reordered["backends"].as_array().unwrap().len(), 2);
            assert_eq!(
                reordered["backends"][usize::from(running)],
                browser["backends"][0]
            );
        }
    }

    #[test]
    fn refused_merge_logs_parser_error_without_dumping_configuration() {
        #[derive(Clone)]
        struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let bytes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = Capture(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let existing = serde_json::json!({"backends":[]});
        let bad = serde_json::json!({"backends":[{
            "id":"walletconnect-local-exit", "kind":"stream_relay",
            "allowed_hosts":["relay.walletconnect.org"],
            "private_test_payload":"not-to-log"
        }]});
        let error = merge_exit_config(existing.clone(), Some(&bad), false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field"));
        tracing::subscriber::with_default(subscriber, || {
            assert_eq!(exit_config(existing.clone(), Some(&bad), false), existing);
        });
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(output.contains(&error), "parser refusal is logged");
        assert!(
            !output.contains("not-to-log"),
            "configuration values remain private"
        );
    }
}

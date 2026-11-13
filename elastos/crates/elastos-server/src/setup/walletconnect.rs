//! Relay-only defaults for a configured WalletConnect Home, independent of a Browser VM.
use std::path::Path;

pub fn local_exit(data: &Path, platform: &str) -> Option<(serde_json::Value, serde_json::Value)> {
    crate::api::gateway::ensure_wallet_connector_configured(data, "wallet-walletconnect").ok()?;
    if !matches!(platform, "darwin-arm64" | "linux-amd64" | "linux-arm64") {
        return None;
    }
    let sockets = super::browser_config::walletconnect_socket_paths(data, platform).ok()?;
    let adapter = sockets["adapter"].as_str()?;
    let socket = sockets["relay"].as_str()?;
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
    if let Some(previous) = backends.iter().find(|b| b["id"] == managed["id"]) {
        anyhow::ensure!(
            previous == managed,
            "WalletConnect Exit backend has a conflicting route"
        );
    } else {
        // Exit matches local backends in list order. Browser keeps first match;
        // WalletConnect supplies a route only when earlier backends do not match.
        backends.push(managed.clone());
    }
    exit_provider::parse_config(existing.clone()).map_err(anyhow::Error::msg)?;
    Ok(existing)
}

/// A refused WalletConnect addition leaves the owner's Exit selection intact.
pub fn exit_config(
    existing: serde_json::Value,
    walletconnect: Option<&serde_json::Value>,
) -> serde_json::Value {
    match merge_exit_config(existing.clone(), walletconnect) {
        Ok(config) => config,
        Err(_) => {
            tracing::warn!("WalletConnect Exit configuration was refused; starting the existing Exit configuration");
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
        let merged = merge_exit_config(remote.clone(), Some(&wc)).unwrap();
        assert_eq!(merged["timeout_secs"], remote["timeout_secs"]);
        assert_eq!(merged["backends"], wc["backends"]);
        let local = serde_json::json!({"backends":[{"id":"owner-local", "kind":"stream_relay", "allowed_hosts":["*"]}]});
        let merged = merge_exit_config(local.clone(), Some(&wc)).unwrap();
        assert_eq!(merged["backends"][0], local["backends"][0]);
        assert_eq!(merge_exit_config(remote.clone(), None).unwrap(), remote);
        assert!(merge_exit_config(serde_json::json!({"backends":false}), Some(&wc)).is_err());
    }
    #[test]
    fn walletconnect_refused_merge_preserves_browser_exit_and_matching_order() {
        let browser = serde_json::json!({"backends":[{"id":"browser", "kind":"stream_relay", "allowed_hosts":["*"]}]});
        let bad = serde_json::json!({"backends":[{"id":"walletconnect-local-exit", "kind":"stream_relay", "allowed_hosts":["relay.walletconnect.org"],
            "adapter_ipc":{"kind":"unix_socket","path":"/tmp/same.sock"}, "relay_ipc":{"kind":"unix_socket","path":"/tmp/same.sock"}}]});
        assert!(merge_exit_config(browser.clone(), Some(&bad)).is_err());
        assert_eq!(exit_config(browser.clone(), Some(&bad)), browser);
        let good = serde_json::json!({"backends":[{"id":"walletconnect-local-exit", "kind":"stream_relay", "allowed_hosts":["relay.walletconnect.org"]}]});
        let merged = exit_config(browser, Some(&good));
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
}

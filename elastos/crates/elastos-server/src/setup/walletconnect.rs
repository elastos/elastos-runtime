//! Relay-only defaults for a configured WalletConnect Home, independent of a Browser VM.
use std::path::Path;

pub fn local_exit(data: &Path, platform: &str) -> Option<(serde_json::Value, serde_json::Value)> {
    crate::api::gateway::ensure_wallet_connector_configured(data, "wallet-walletconnect").ok()?;
    if !matches!(platform, "darwin-arm64" | "linux-amd64" | "linux-arm64") { return None; }
        let socket = data.join("walletconnect-exit.sock");
        let hosts = ["relay.walletconnect.org", "relay.walletconnect.com"];
        let helper = serde_json::json!({
            "schema":"elastos.browser.local-exit.config/v1", "relay_ipc_path":socket,
            "allowed_hosts":hosts, "allowed_schemes":["tls"], "allowed_ports":[443],
            "replace_existing_socket":true,
        });
        let provider = serde_json::json!({"backends":[{
            "id":"walletconnect-local-exit", "kind":"stream_relay",
            "allowed_hosts":hosts, "allowed_schemes":["tls"], "allowed_ports":[443],
            "adapter_ipc":{"kind":"unix_socket","path":socket},
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
        backends.insert(0, managed.clone());
    }
    Ok(existing)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn walletconnect_local_exit_needs_pinned_config_and_uses_relay_hosts_only() {
        let data = tempfile::tempdir().unwrap();
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
        std::fs::write(sdk, "tampered").unwrap();
        assert!(local_exit(data.path(), "darwin-arm64").is_none());
    }

    #[test]
    fn walletconnect_keeps_existing_remote_and_local_exit_configuration() {
        let remote =
            serde_json::json!({"backends":[], "remote_carrier_exits":[{"id":"owner-remote"}]});
        let wc = serde_json::json!({"backends":[{"id":"walletconnect-local-exit"}]});
        let merged = merge_exit_config(remote.clone(), Some(&wc)).unwrap();
        assert_eq!(
            merged["remote_carrier_exits"],
            remote["remote_carrier_exits"]
        );
        assert_eq!(merged["backends"], wc["backends"]);
        let local = serde_json::json!({"backends":[{"id":"owner-local"}]});
        let merged = merge_exit_config(local.clone(), Some(&wc)).unwrap();
        assert_eq!(merged["backends"][1], local["backends"][0]);
        assert_eq!(merge_exit_config(remote.clone(), None).unwrap(), remote);
        assert!(merge_exit_config(serde_json::json!({"backends":false}), Some(&wc)).is_err());
    }
}

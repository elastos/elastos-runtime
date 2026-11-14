//! Exit configuration parser shared by the provider and Runtime startup.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;
use url::Url;

pub const DEFAULT_REMOTE_CARRIER_EXIT_SERVICE: &str = "elastos://exit/open_stream";
const MAX_CARRIER_CONNECT_TICKET_BYTES: usize = 8192;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitConfig {
    #[serde(default)]
    pub backends: Vec<ExitBackendConfig>,
    #[serde(default)]
    pub remote_carrier_exits: Vec<RemoteCarrierExitConfig>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitBackendConfig {
    pub id: String,
    pub kind: ExitBackendKind,
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub allowed_schemes: Vec<String>,
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
    #[serde(default)]
    pub allow_private_targets: bool,
    #[serde(default)]
    pub allowed_private_targets: Vec<PrivateTargetConfig>,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default)]
    pub adapter_ipc: Option<AdapterIpcConfig>,
    #[serde(default)]
    pub relay_ipc: Option<RelayIpcConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateTargetConfig {
    pub host: String,
    pub ports: Vec<u16>,
    #[serde(default)]
    pub schemes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteCarrierExitConfig {
    pub id: String,
    pub grant_id: String,
    pub peer_did: String,
    #[serde(default = "default_remote_carrier_service")]
    pub carrier_service: String,
    pub allowed_principals: Vec<String>,
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub allowed_schemes: Vec<String>,
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
    #[serde(default = "default_max_active_remote_streams")]
    pub max_active_streams: u64,
    #[serde(default)]
    pub max_active_streams_per_principal: Option<u64>,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub connect_ticket: Option<String>,
}

impl RemoteCarrierExitConfig {
    pub fn allows_target(&self, target: &Url) -> bool {
        let Some(host) = target.host_str() else {
            return false;
        };
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        let host_allowed = self.allowed_hosts.iter().any(|allowed| {
            let allowed = allowed.to_ascii_lowercase();
            if allowed == "*" {
                return true;
            }
            if let Some(suffix) = allowed.strip_prefix("*.") {
                host.ends_with(&format!(".{suffix}"))
            } else {
                host == allowed
            }
        });
        host_allowed
            && self.allows_scheme(target.scheme())
            && self.allows_port(target.port_or_known_default())
    }

    pub fn allows_scheme(&self, scheme: &str) -> bool {
        if self.allowed_schemes.is_empty() {
            return matches!(scheme, "tcp" | "tls");
        }
        self.allowed_schemes.iter().any(|allowed| allowed == scheme)
    }

    pub fn allows_port(&self, port: Option<u16>) -> bool {
        let Some(port) = port else {
            return false;
        };
        self.allowed_ports.is_empty() || self.allowed_ports.contains(&port)
    }

    pub fn allows_principal(&self, principal_id: Option<&str>) -> bool {
        let Some(principal_id) = principal_id else {
            return false;
        };
        self.allowed_principals
            .iter()
            .any(|allowed| allowed == "*" || allowed == principal_id)
    }

    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at
            .map(|expires_at| expires_at <= now)
            .unwrap_or(false)
    }

    pub fn state(&self, now: u64) -> &'static str {
        if self.is_expired(now) {
            "expired"
        } else {
            "active"
        }
    }

    pub fn max_active_streams_per_principal(&self) -> u64 {
        self.max_active_streams_per_principal
            .unwrap_or(self.max_active_streams)
    }
}

impl ExitBackendConfig {
    pub fn allows_target(&self, target: &Url) -> bool {
        if self.allows_private_target(target) {
            return true;
        }
        let Some(host) = target.host_str() else {
            return false;
        };
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        let host_allowed = self.allowed_hosts.iter().any(|allowed| {
            let allowed = allowed.to_ascii_lowercase();
            if allowed == "*" {
                return true;
            }
            if let Some(suffix) = allowed.strip_prefix("*.") {
                host.ends_with(&format!(".{suffix}"))
            } else {
                host == allowed
            }
        });
        host_allowed
            && self.allows_scheme(target.scheme())
            && self.allows_port(target.port_or_known_default())
    }

    pub fn allows_scheme(&self, scheme: &str) -> bool {
        if self.allowed_schemes.is_empty() {
            return match self.kind {
                ExitBackendKind::StreamRelay => matches!(scheme, "tcp" | "tls"),
                ExitBackendKind::HttpFetch => matches!(scheme, "http" | "https"),
            };
        }
        self.allowed_schemes.iter().any(|allowed| allowed == scheme)
    }

    pub fn allows_port(&self, port: Option<u16>) -> bool {
        let Some(port) = port else {
            return false;
        };
        self.allowed_ports.is_empty() || self.allowed_ports.contains(&port)
    }

    pub fn allows_private_target(&self, target: &Url) -> bool {
        let Some(host) = target.host_str() else {
            return false;
        };
        let Some(port) = target.port_or_known_default() else {
            return false;
        };
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        self.allowed_private_targets.iter().any(|private| {
            private
                .host
                .trim_matches(['[', ']'])
                .eq_ignore_ascii_case(&host)
                && private.ports.contains(&port)
                && (private.schemes.is_empty()
                    || private
                        .schemes
                        .iter()
                        .any(|scheme| scheme == target.scheme()))
        })
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExitBackendKind {
    HttpFetch,
    StreamRelay,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterIpcConfig {
    pub kind: AdapterIpcKind,
    pub path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayIpcConfig {
    pub kind: RelayIpcKind,
    pub path: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdapterIpcKind {
    UnixSocket,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayIpcKind {
    UnixSocket,
}

pub fn parse_config(config: Value) -> Result<ExitConfig, String> {
    let mut config = match config.get("extra") {
        Some(extra) if extra.is_null() => json!({}),
        Some(extra) => extra.clone(),
        None if looks_like_bridge_provider_config(&config) => json!({}),
        None => config,
    };
    // Services previously stamped the local relay schema on provider config.
    // Accept that exact released mistake only for a remote-grant config; all
    // remaining fields still pass the strict provider parser.
    if config.get("schema").and_then(Value::as_str) == Some("elastos.browser.local-exit.config/v1")
        && config
            .get("remote_carrier_exits")
            .is_some_and(Value::is_array)
    {
        config
            .as_object_mut()
            .expect("config with fields is an object")
            .remove("schema");
    }
    let config = serde_json::from_value::<ExitConfig>(config).map_err(|err| err.to_string())?;
    if config.timeout_secs == 0 || config.timeout_secs > 60 {
        return Err("exit-provider timeout_secs must be between 1 and 60".to_string());
    }
    for backend in &config.backends {
        validate_backend(backend)?;
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut grants = std::collections::BTreeSet::new();
    for exit in &config.remote_carrier_exits {
        validate_remote_carrier_exit(exit)?;
        if !ids.insert(&exit.id) || !grants.insert(&exit.grant_id) {
            return Err("remote Carrier Exit ids and grant ids must be unique".to_string());
        }
    }
    Ok(config)
}

pub fn looks_like_bridge_provider_config(config: &Value) -> bool {
    config.get("base_path").is_some()
        || config.get("allowed_paths").is_some()
        || config.get("read_only").is_some()
        || config.get("encryption_key").is_some()
}

pub fn validate_backend(backend: &ExitBackendConfig) -> Result<(), String> {
    if !is_safe_id(&backend.id) {
        return Err("exit backend id must be a safe identifier".to_string());
    }
    if backend.allowed_hosts.is_empty() {
        return Err(format!(
            "exit backend '{}' must declare at least one allowed host",
            backend.id
        ));
    }
    if backend.max_body_bytes == 0 || backend.max_body_bytes > 1024 * 1024 {
        return Err(format!(
            "exit backend '{}' max_body_bytes must be between 1 and 1048576",
            backend.id
        ));
    }
    if let Some(adapter_ipc) = &backend.adapter_ipc {
        if backend.kind != ExitBackendKind::StreamRelay {
            return Err(format!(
                "exit backend '{}' adapter_ipc is only valid for stream_relay backends",
                backend.id
            ));
        }
        validate_adapter_ipc(adapter_ipc)?;
    }
    if let Some(relay_ipc) = &backend.relay_ipc {
        if backend.kind != ExitBackendKind::StreamRelay {
            return Err(format!(
                "exit backend '{}' relay_ipc is only valid for stream_relay backends",
                backend.id
            ));
        }
        if backend.adapter_ipc.is_none() {
            return Err(format!(
                "exit backend '{}' relay_ipc requires adapter_ipc",
                backend.id
            ));
        }
        validate_relay_ipc(relay_ipc)?;
    }
    if let (Some(adapter_ipc), Some(relay_ipc)) = (&backend.adapter_ipc, &backend.relay_ipc) {
        if adapter_ipc.path == relay_ipc.path {
            return Err(format!(
                "exit backend '{}' adapter_ipc and relay_ipc paths must differ",
                backend.id
            ));
        }
    }
    for host in &backend.allowed_hosts {
        validate_allowed_host(host)?;
    }
    for scheme in &backend.allowed_schemes {
        validate_allowed_scheme(backend.kind, scheme)?;
    }
    for port in &backend.allowed_ports {
        if *port == 0 {
            return Err(format!(
                "exit backend '{}' allowed_ports must contain TCP ports between 1 and 65535",
                backend.id
            ));
        }
    }
    for target in &backend.allowed_private_targets {
        validate_private_target(&backend.id, backend.kind, target)?;
    }
    Ok(())
}

pub fn validate_private_target(
    backend_id: &str,
    backend_kind: ExitBackendKind,
    target: &PrivateTargetConfig,
) -> Result<(), String> {
    let host = target.host.trim();
    if host.is_empty() || host == "*" || host.starts_with("*.") {
        return Err(format!(
            "exit backend '{backend_id}' allowed_private_targets host must be an exact host"
        ));
    }
    validate_host_shape(host)?;
    if target.ports.is_empty() {
        return Err(format!(
            "exit backend '{backend_id}' allowed_private_targets ports must not be empty"
        ));
    }
    for port in &target.ports {
        if *port == 0 {
            return Err(format!(
                "exit backend '{backend_id}' allowed_private_targets ports must contain TCP ports between 1 and 65535"
            ));
        }
    }
    for scheme in &target.schemes {
        validate_allowed_scheme(backend_kind, scheme)?;
    }
    Ok(())
}

pub fn validate_remote_carrier_exit(exit: &RemoteCarrierExitConfig) -> Result<(), String> {
    if !is_safe_id(&exit.id) {
        return Err("remote Carrier Exit id must be a safe identifier".to_string());
    }
    if !is_safe_id(&exit.grant_id) {
        return Err("remote Carrier Exit grant_id must be a safe identifier".to_string());
    }
    validate_plain_token("remote Carrier Exit peer_did", &exit.peer_did)?;
    validate_carrier_service(&exit.carrier_service)?;
    if exit.allowed_principals.is_empty() {
        return Err(format!(
            "remote Carrier Exit '{}' must declare at least one allowed principal",
            exit.id
        ));
    }
    for principal in &exit.allowed_principals {
        if principal != "*" {
            validate_plain_token("remote Carrier Exit allowed_principals", principal)?;
        }
    }
    if exit.allowed_hosts.is_empty() {
        return Err(format!(
            "remote Carrier Exit '{}' must declare at least one allowed host",
            exit.id
        ));
    }
    for host in &exit.allowed_hosts {
        validate_allowed_host(host)?;
    }
    for scheme in &exit.allowed_schemes {
        validate_allowed_scheme(ExitBackendKind::StreamRelay, scheme)?;
    }
    for port in &exit.allowed_ports {
        if *port == 0 {
            return Err(format!(
                "remote Carrier Exit '{}' allowed_ports must contain TCP ports between 1 and 65535",
                exit.id
            ));
        }
    }
    if exit.max_active_streams == 0 || exit.max_active_streams > 1024 {
        return Err(format!(
            "remote Carrier Exit '{}' max_active_streams must be between 1 and 1024",
            exit.id
        ));
    }
    let max_active_streams_per_principal = exit.max_active_streams_per_principal();
    if max_active_streams_per_principal == 0
        || max_active_streams_per_principal > exit.max_active_streams
    {
        return Err(format!(
            "remote Carrier Exit '{}' max_active_streams_per_principal must be between 1 and max_active_streams",
            exit.id
        ));
    }
    if exit.expires_at == Some(0) {
        return Err(format!(
            "remote Carrier Exit '{}' expires_at must be a positive Unix timestamp",
            exit.id
        ));
    }
    let Some(connect_ticket) = &exit.connect_ticket else {
        return Err(format!(
            "remote Carrier Exit '{}' must declare connect_ticket for Browser Carrier stream dial",
            exit.id
        ));
    };
    validate_carrier_connect_ticket(connect_ticket)?;
    Ok(())
}

pub fn validate_allowed_scheme(kind: ExitBackendKind, scheme: &str) -> Result<(), String> {
    let valid = match kind {
        ExitBackendKind::StreamRelay => matches!(scheme, "tcp" | "tls"),
        ExitBackendKind::HttpFetch => matches!(scheme, "http" | "https"),
    };
    if valid {
        Ok(())
    } else {
        Err(format!(
            "{kind:?} backend allowed_schemes may not contain '{scheme}'"
        ))
    }
}

pub fn validate_plain_token(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(format!("{label} must not be empty or padded"));
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte == b'\0')
    {
        return Err(format!("{label} must not contain whitespace or NUL"));
    }
    Ok(())
}

pub fn validate_carrier_service(service: &str) -> Result<(), String> {
    validate_plain_token("remote Carrier Exit carrier_service", service)?;
    if !service.starts_with("elastos://") {
        return Err("remote Carrier Exit carrier_service must use elastos://".to_string());
    }
    Ok(())
}

pub fn validate_carrier_connect_ticket(ticket: &str) -> Result<(), String> {
    validate_plain_token("remote Carrier Exit connect_ticket", ticket)?;
    if ticket.len() > MAX_CARRIER_CONNECT_TICKET_BYTES {
        return Err(format!(
            "remote Carrier Exit connect_ticket must be at most {MAX_CARRIER_CONNECT_TICKET_BYTES} bytes"
        ));
    }
    Ok(())
}

pub fn validate_remote_exit_selection(value: Option<&str>) -> Result<Option<&str>, String> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.len() > 128 || !is_safe_id(value) {
        return Err("remote_exit_id must be a safe identifier up to 128 bytes".to_string());
    }
    Ok(Some(value))
}

pub fn validate_adapter_ipc(adapter_ipc: &AdapterIpcConfig) -> Result<(), String> {
    validate_ipc_path("adapter_ipc", &adapter_ipc.path)
}

pub fn validate_relay_ipc(relay_ipc: &RelayIpcConfig) -> Result<(), String> {
    validate_ipc_path("relay_ipc", &relay_ipc.path)
}

pub fn validate_ipc_path(label: &str, path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err(format!("{label} path must not be empty"));
    }
    if !path.starts_with('/') {
        return Err(format!("{label} path must be absolute"));
    }
    if path
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte == b'\0')
    {
        return Err(format!("{label} path must not contain whitespace or NUL"));
    }
    Ok(())
}

pub fn validate_allowed_host(host: &str) -> Result<(), String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("allowed host must not be empty".to_string());
    }
    if host == "*" {
        return Ok(());
    }
    let host = host.strip_prefix("*.").unwrap_or(host);
    validate_public_host_shape(host)
}

pub fn validate_public_host(host: &str) -> Result<(), String> {
    let host = host.trim().trim_matches(['[', ']']);
    validate_public_host_shape(host)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return validate_public_ip(ip).map_err(|_| format!("private IP blocked: {host}"));
    }
    Ok(())
}

pub fn validate_public_host_shape(host: &str) -> Result<(), String> {
    validate_host_shape(host)?;
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".local") {
        return Err(format!("private host blocked: {host}"));
    }
    Ok(())
}

pub fn validate_host_shape(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("host must not be empty".to_string());
    }
    if host
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'\\' | b'\0'))
    {
        return Err(format!("invalid host: {host}"));
    }
    Ok(())
}

pub fn validate_public_ip(ip: IpAddr) -> Result<(), &'static str> {
    match ip {
        IpAddr::V4(ip) => {
            if ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
            {
                Err("private IP blocked")
            } else {
                Ok(())
            }
        }
        IpAddr::V6(ip) => {
            if ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
            {
                Err("private IP blocked")
            } else {
                Ok(())
            }
        }
    }
}

pub fn is_safe_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_'))
}

pub fn default_timeout_secs() -> u64 {
    10
}

pub fn default_max_body_bytes() -> usize {
    64 * 1024
}

pub fn default_max_active_remote_streams() -> u64 {
    8
}

pub fn default_remote_carrier_service() -> String {
    DEFAULT_REMOTE_CARRIER_EXIT_SERVICE.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_installed_legacy_config_parses_without_accepting_unknown_schema() {
        let mut config = json!({"remote_carrier_exits":[{
            "id":"services-bob", "grant_id":"services-grant-bob", "peer_did":"did:elastos:bob",
            "connect_ticket":"private-ticket", "allowed_principals":["person:alice"],
            "allowed_hosts":["*"], "allowed_schemes":["tcp","tls"], "allowed_ports":[80,443],
            "max_active_streams":1, "max_active_streams_per_principal":1
        }]});
        config["schema"] = json!("elastos.browser.local-exit.config/v1");
        assert!(
            parse_config(config.clone()).is_ok(),
            "released Services config must parse"
        );
        config["schema"] = json!("elastos.exit.unrecognized/v1");
        assert!(parse_config(config).is_err());
    }

    #[test]
    fn backend_config_rejects_invalid_adapter_ipc() {
        assert!(parse_config(json!({
            "backends": [{
                "id": "bad-http-ipc",
                "kind": "http_fetch",
                "allowed_hosts": ["glidefinance.io"],
                "adapter_ipc": {
                    "kind": "unix_socket",
                    "path": "/tmp/elastos-browser-stream.sock"
                }
            }]
        }))
        .is_err());
        assert!(parse_config(json!({
            "backends": [{
                "id": "bad-http-relay",
                "kind": "http_fetch",
                "allowed_hosts": ["glidefinance.io"],
                "relay_ipc": {
                    "kind": "unix_socket",
                    "path": "/tmp/elastos-exit-relay.sock"
                }
            }]
        }))
        .is_err());
        assert!(parse_config(json!({
            "backends": [{
                "id": "bad-relay-without-adapter",
                "kind": "stream_relay",
                "allowed_hosts": ["glidefinance.io"],
                "relay_ipc": {
                    "kind": "unix_socket",
                    "path": "/tmp/elastos-exit-relay.sock"
                }
            }]
        }))
        .is_err());
        assert!(parse_config(json!({
            "backends": [{
                "id": "bad-shared-ipc",
                "kind": "stream_relay",
                "allowed_hosts": ["glidefinance.io"],
                "adapter_ipc": {
                    "kind": "unix_socket",
                    "path": "/tmp/elastos-browser-stream.sock"
                },
                "relay_ipc": {
                    "kind": "unix_socket",
                    "path": "/tmp/elastos-browser-stream.sock"
                }
            }]
        }))
        .is_err());
        assert!(parse_config(json!({
            "backends": [{
                "id": "bad-relative-ipc",
                "kind": "stream_relay",
                "allowed_hosts": ["glidefinance.io"],
                "adapter_ipc": {
                    "kind": "unix_socket",
                    "path": "relative.sock"
                }
            }]
        }))
        .is_err());
    }

    #[test]
    fn remote_carrier_exit_config_rejects_missing_permission_and_hidden_fields() {
        let valid = json!({"remote_carrier_exits": [{
            "id": "server-exit",
            "grant_id": "operator-grant:server-exit:alice",
            "peer_did": "did:elastos:server",
            "connect_ticket": "carrier-ticket-server-exit-alice",
            "allowed_principals": ["person:local:alice"],
            "allowed_hosts": ["example.com"],
            "max_active_streams": 2
        }]});
        assert!(parse_config(valid.clone()).is_ok());
        for field in ["grant_id", "allowed_principals", "connect_ticket"] {
            let mut config = valid.clone();
            config["remote_carrier_exits"][0]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(parse_config(config).unwrap_err().contains(field));
        }
        for (field, value, expected) in [
            ("raw_socket", json!(true), "unknown field"),
            ("connect_ticket", json!(" ticket-with-padding"), "padded"),
            (
                "max_active_streams_per_principal",
                json!(0),
                "max_active_streams_per_principal",
            ),
            (
                "max_active_streams_per_principal",
                json!(3),
                "max_active_streams_per_principal",
            ),
            ("expires_at", json!(0), "expires_at"),
        ] {
            let mut config = valid.clone();
            config["remote_carrier_exits"][0][field] = value;
            assert!(parse_config(config).unwrap_err().contains(expected));
        }
    }

    #[test]
    fn backend_config_rejects_hidden_fields() {
        let response = parse_config(json!({
            "backends": [{
                "id": "bad",
                "kind": "http_fetch",
                "allowed_hosts": ["example.com"],
                "raw_socket": true
            }]
        }));
        assert!(response.unwrap_err().contains("unknown field"));
    }
}

//! Explicit, off-by-default Carrier relay path. Runtime owns relay selection.

use anyhow::{Context, Result};
use futures_lite::StreamExt as _;
use iroh::address_lookup::{AddressLookup, EndpointInfo, Item};
use iroh::RelayUrl;

/// Shared by every endpoint. The system resolver owns DNS; failure stays local
/// to that policy. Irzhy reviews this choice before discovery is enabled.
pub(super) fn system_dns() -> iroh::dns::DnsResolver {
    iroh::dns::DnsResolver::builder()
        .with_system_defaults()
        .disable_fallback()
        .build()
}

pub(super) fn apply_relay(
    builder: iroh::endpoint::Builder,
    relay: &url::Url,
) -> Result<iroh::endpoint::Builder> {
    anyhow::ensure!(
        matches!(relay.scheme(), "http" | "https")
            && relay.host().is_some()
            && relay.username().is_empty()
            && relay.password().is_none()
            && relay.path() == "/"
            && relay.query().is_none()
            && relay.fragment().is_none(),
        "ELASTOS_RELAY_URL must be an HTTP(S) origin without credentials"
    );
    let relay = RelayUrl::from(relay.clone());
    let quic = (relay.scheme() == "https").then(Default::default);
    Ok(builder
        .relay_mode(iroh::RelayMode::Custom(iroh::RelayMap::from_iter([
            iroh::RelayConfig::new(relay.clone(), quic),
        ])))
        .address_lookup(PinnedRelayLookup(relay)))
}

#[derive(Debug, Clone)]
struct PinnedRelayLookup(RelayUrl);

impl AddressLookup for PinnedRelayLookup {
    fn resolve(
        &self,
        endpoint_id: iroh::EndpointId,
    ) -> Option<futures_lite::stream::Boxed<Result<Item, iroh::address_lookup::Error>>> {
        let info = EndpointInfo::new(endpoint_id).with_relay_url(self.0.clone());
        Some(futures_lite::stream::once(Ok(Item::new(info, "elastos-relay", None))).boxed())
    }
}

/// Startup configuration owns the server; ordinary Homes have no relay role.
pub(super) async fn configured_server(
    data_dir: &std::path::Path,
) -> Result<Option<iroh_relay::server::Server>> {
    let path = data_dir.join("config.toml");
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let config: toml::Table = contents.parse().context("invalid Runtime configuration")?;
    let Some(bind) = config.get("carrier_relay_bind_addr") else {
        return Ok(None);
    };
    anyhow::ensure!(
        config
            .get("gateway_public_publisher_bootstrap")
            .and_then(toml::Value::as_bool)
            == Some(true),
        "Carrier relay requires the explicit public publisher role"
    );
    let bind: std::net::SocketAddr = bind
        .as_str()
        .context("carrier_relay_bind_addr must be a socket address")?
        .parse()
        .context("invalid carrier_relay_bind_addr")?;
    let mut config = iroh_relay::server::ServerConfig::default();
    config.relay = Some(iroh_relay::server::RelayConfig::new(bind));
    Ok(Some(
        iroh_relay::server::Server::spawn(config)
            .await
            .map_err(|error| anyhow::anyhow!("Carrier relay failed to start: {error:#}"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_configuration_requires_an_origin() {
        for raw in [
            "ftp://relay.example/",
            "http://user:secret@relay.example/",
            "http://relay.example/path",
        ] {
            let builder = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal);
            assert!(apply_relay(builder, &raw.parse().unwrap()).is_err());
        }
        let builder = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal);
        assert!(apply_relay(builder, &"https://relay.example/".parse().unwrap()).is_ok());
    }
}

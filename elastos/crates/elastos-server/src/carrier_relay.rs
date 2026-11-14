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

    async fn real_relay() -> (iroh_relay::server::Server, url::Url) {
        let mut config = iroh_relay::server::ServerConfig::default();
        config.relay = Some(iroh_relay::server::RelayConfig::new(
            "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap(),
        ));
        let server = iroh_relay::server::Server::spawn(config).await.unwrap();
        let url = format!("http://{}/", server.http_addr().unwrap())
            .parse()
            .unwrap();
        (server, url)
    }

    #[tokio::test]
    async fn pin_policy_rejects_foreign_explicit_dials() {
        let (pinned, pin) = real_relay().await;
        let (foreign, other) = real_relay().await;
        let endpoint = super::super::short_lived_endpoint_builder(
            iroh::SecretKey::from_bytes(&[210; 32]),
            super::super::CarrierNodeNetwork::Public,
            Some(&pin),
        )
        .unwrap()
        .bind()
        .await
        .unwrap();
        let peer = iroh::SecretKey::from_bytes(&[211; 32]).public();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            endpoint.connect(
                iroh::EndpointAddr::new(peer).with_relay_url(other.as_str().parse().unwrap()),
                b"elastos/test",
            ),
        )
        .await;
        endpoint.close().await;
        foreign.shutdown().await.unwrap();
        pinned.shutdown().await.unwrap();
        assert!(
            result.is_ok_and(|result| result
                .is_err_and(|error| format!("{error:#}").contains("rejected locally"))),
            "a foreign relay must be rejected before a transport dial"
        );
    }

    #[tokio::test]
    async fn pin_policy_filters_memory_and_restores_after_gossip_rebuild() {
        let (pinned, pin) = real_relay().await;
        let (foreign, other) = real_relay().await;
        let directory = tempfile::tempdir().unwrap();
        let (key, did) = elastos_identity::derive_did(&[212; 32]);
        let node = super::super::start_carrier_node_with_network(
            &key,
            &did,
            directory.path().to_path_buf(),
            None,
            super::super::CarrierNetworkPolicy {
                network: super::super::CarrierNodeNetwork::Public,
                relay: Some(pin.clone()),
            },
            Some("127.0.0.1:0".parse().unwrap()),
            &[],
        )
        .await
        .unwrap();
        let peer = iroh::SecretKey::from_bytes(&[213; 32]).public();
        node.memory_lookup.add_endpoint_info(
            iroh::EndpointAddr::new(peer).with_relay_url(other.as_str().parse().unwrap()),
        );
        let mut foreign_seen = false;
        for rebuild in [false, true] {
            if rebuild {
                super::super::rebuild_carrier_gossip(&mut *node.gossip_state.lock().await)
                    .await
                    .unwrap();
            }
            let services = node.endpoint.address_lookup().unwrap();
            let found = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                services.resolve(peer).take(2).collect::<Vec<_>>(),
            )
            .await
            .unwrap();
            foreign_seen |= found
                .into_iter()
                .filter_map(|item| item.ok().and_then(Result::ok))
                .any(|item| {
                    item.into_endpoint_addr()
                        .relay_urls()
                        .any(|relay| relay.as_str() != pin.as_str())
                });
        }
        node.shutdown().await;
        foreign.shutdown().await.unwrap();
        pinned.shutdown().await.unwrap();
        assert!(
            !foreign_seen,
            "memory and rebuilt gossip must retain only the Home's pinned relay"
        );
    }

    #[test]
    fn exported_tickets_without_a_public_ip_keep_only_the_relay() {
        let peer = iroh::SecretKey::from_bytes(&[214; 32]).public();
        let relay: RelayUrl = "https://relay.example/".parse().unwrap();
        let private = [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
        ];
        let address = iroh::EndpointAddr::new(peer).with_addrs(
            private
                .into_iter()
                .map(|ip| {
                    iroh::TransportAddr::Ip(std::net::SocketAddr::new(ip.parse().unwrap(), 0))
                })
                .chain([iroh::TransportAddr::Relay(relay.clone())]),
        );
        let exported = super::super::exported_endpoint_addr(address.clone());
        assert_eq!(exported.id, peer);
        assert_eq!(
            exported.addrs.into_iter().collect::<Vec<_>>(),
            vec![iroh::TransportAddr::Relay(relay)]
        );
        assert_eq!(
            super::super::published_direct_endpoint_addr(address)
                .addrs
                .len(),
            private.len(),
            "local shell tickets retain local IP reachability"
        );
    }

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

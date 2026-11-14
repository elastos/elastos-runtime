//! Explicit, off-by-default Carrier relay path. Runtime owns relay selection.

use anyhow::{Context, Result};
use futures_lite::StreamExt as _;
use iroh::address_lookup::{AddrFilter, AddressLookup, EndpointData, EndpointInfo, Item};
use iroh::endpoint::{BeforeConnectOutcome, EndpointHooks};
use iroh::tls::CaTlsConfig;
use iroh::RelayUrl;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::Arc;

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
    Ok(endpoint_policy(builder, Some(&relay))
        .relay_mode(iroh::RelayMode::Custom(iroh::RelayMap::from_iter([
            iroh::RelayConfig::new(relay.clone(), quic),
        ])))
        .ca_tls_config(pinned_relay_tls(&relay, CaTlsConfig::embedded()))
        .address_lookup(PinnedRelayLookup(relay)))
}

pub(super) fn endpoint_policy(
    builder: iroh::endpoint::Builder,
    relay: Option<&RelayUrl>,
) -> iroh::endpoint::Builder {
    builder
        .addr_filter(AddrFilter::ip_only())
        .hooks(PinnedRelayHook {
            relay: relay.cloned(),
        })
}

#[derive(Debug)]
struct PinnedRelayHook {
    relay: Option<RelayUrl>,
}

impl EndpointHooks for PinnedRelayHook {
    async fn before_connect<'a>(
        &'a self,
        remote: &'a iroh::EndpointAddr,
        _alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        if remote.addrs.iter().all(|transport| match transport {
            iroh::TransportAddr::Ip(_) => true,
            iroh::TransportAddr::Relay(url) => Some(url) == self.relay.as_ref(),
            _ => false,
        }) {
            BeforeConnectOutcome::Accept
        } else {
            BeforeConnectOutcome::Reject
        }
    }
}

#[derive(Debug, Clone)]
struct PinnedLookup<T> {
    relay: Option<RelayUrl>,
    inner: T,
}

impl<T: AddressLookup> AddressLookup for PinnedLookup<T> {
    fn publish(&self, data: &EndpointData) {
        self.inner.publish(data);
    }
    fn resolve(
        &self,
        id: iroh::EndpointId,
    ) -> Option<futures_lite::stream::Boxed<Result<Item, iroh::address_lookup::Error>>> {
        let relay = self.relay.clone();
        Some(
            self.inner
                .resolve(id)?
                .map(move |item| {
                    item.map(|item| {
                        let provenance = item.provenance();
                        let addr = item.into_endpoint_addr();
                        let addrs: Vec<_> = addr
                            .addrs
                            .into_iter()
                            .filter(|transport| match transport {
                                iroh::TransportAddr::Ip(_) => true,
                                iroh::TransportAddr::Relay(url) => Some(url) == relay.as_ref(),
                                _ => false,
                            })
                            .collect();
                        Item::new(
                            EndpointInfo::from_parts(addr.id, EndpointData::new(addrs)),
                            provenance,
                            None,
                        )
                    })
                })
                .boxed(),
        )
    }
}

/// Runtime retains this complete policy across every gossip actor replacement.
/// Gossip's unfiltered peer lookup is replaced by the pinned DID route, memory
/// and mDNS, each of which passes through the same relay filter.
#[derive(Debug, Clone)]
pub(super) struct LookupPolicy {
    pub relay: Option<RelayUrl>,
    pub memory: iroh::address_lookup::memory::MemoryLookup,
    pub mdns: Option<iroh_mdns_address_lookup::MdnsAddressLookup>,
}

impl LookupPolicy {
    pub fn install(&self, endpoint: &iroh::Endpoint) -> Result<()> {
        let services = endpoint
            .address_lookup()
            .context("Carrier closed before relay lookup policy setup")?;
        services.clear();
        if let Some(relay) = &self.relay {
            services.add(PinnedRelayLookup(relay.clone()));
        }
        services.add(PinnedLookup {
            relay: self.relay.clone(),
            inner: self.memory.clone(),
        });
        if let Some(mdns) = &self.mdns {
            services.add(PinnedLookup {
                relay: self.relay.clone(),
                inner: mdns.clone(),
            });
        }
        Ok(())
    }
}

fn pinned_relay_tls(relay: &RelayUrl, roots: CaTlsConfig) -> CaTlsConfig {
    let host = match relay.host() {
        Some(url::Host::Domain(name)) => name.to_string(),
        Some(url::Host::Ipv4(ip)) => ip.to_string(),
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        None => String::new(),
    };
    CaTlsConfig::custom_server_cert_verifier(Arc::new(move |provider| {
        let host = ServerName::try_from(host.clone())
            .map_err(std::io::Error::other)?
            .to_owned();
        Ok(Arc::new(PinnedRelayHost {
            host,
            inner: roots.server_cert_verifier(provider)?,
        }) as Arc<dyn ServerCertVerifier>)
    }))
}

#[derive(Debug)]
struct PinnedRelayHost {
    host: ServerName<'static>,
    inner: Arc<dyn ServerCertVerifier>,
}

impl ServerCertVerifier for PinnedRelayHost {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if *name != self.host {
            return Err(rustls::Error::General(
                "not the pinned Carrier relay".into(),
            ));
        }
        self.inner.verify_server_cert(cert, chain, name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
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
    let mut relay = iroh_relay::server::RelayConfig::new(bind);
    apply_byte_limits(&mut relay, 8 * 1024 * 1024, 1024 * 1024);
    config.relay = Some(relay);
    Ok(Some(
        iroh_relay::server::Server::spawn(config)
            .await
            .map_err(|error| anyhow::anyhow!("Carrier relay failed to start: {error:#}"))?,
    ))
}

fn apply_byte_limits(
    relay: &mut iroh_relay::server::RelayConfig,
    bytes_per_second: u32,
    burst: u32,
) {
    let mut rate = iroh_relay::server::ClientRateLimit::new(
        std::num::NonZeroU32::new(bytes_per_second).expect("nonzero relay rate"),
    );
    rate.max_burst_bytes = std::num::NonZeroU32::new(burst);
    relay.limits.client_rx = Some(rate);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn home_byte_budget_survives_replacement_and_closed_connection_bursts() {
        use futures::SinkExt as _;
        use iroh_relay::protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg};
        const RATE: u32 = 1024;
        const BURST: u32 = 4096;
        let mut relay =
            iroh_relay::server::RelayConfig::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
        apply_byte_limits(&mut relay, RATE, BURST);
        let mut config = iroh_relay::server::ServerConfig::default();
        config.relay = Some(relay);
        let server = iroh_relay::server::Server::spawn(config).await.unwrap();
        let url: RelayUrl = format!("http://{}/", server.http_addr().unwrap())
            .parse()
            .unwrap();
        let tls = CaTlsConfig::embedded()
            .client_config(Arc::new(rustls::crypto::ring::default_provider()))
            .unwrap();
        let build = |key: iroh::SecretKey| {
            iroh_relay::client::ClientBuilder::new(url.clone(), key, system_dns())
                .tls_client_config(tls.clone())
        };
        let receiver_key = iroh::SecretKey::from_bytes(&[220; 32]);
        let mut receiver = build(receiver_key.clone()).connect().await.unwrap();
        let mut measurements = Vec::new();
        for (keep_replaced, key) in [(false, 218), (true, 219)] {
            let key = iroh::SecretKey::from_bytes(&[key; 32]);
            let mut held = Vec::new();
            let mut delivered = 0usize;
            let started = std::time::Instant::now();
            for _ in 0..4 {
                let mut sender = build(key.clone()).connect().await.unwrap();
                sender
                    .send(ClientToRelayMsg::Datagrams {
                        dst_endpoint_id: receiver_key.public(),
                        datagrams: Datagrams::from(vec![42; 2048]),
                    })
                    .await
                    .unwrap();
                delivered += tokio::time::timeout(std::time::Duration::from_secs(20), async {
                    loop {
                        match receiver.next().await.unwrap().unwrap() {
                            RelayToClientMsg::Datagrams {
                                remote_endpoint_id,
                                datagrams,
                            } => {
                                assert_eq!(remote_endpoint_id, key.public());
                                break datagrams.contents.len();
                            }
                            RelayToClientMsg::Ping(value) => {
                                receiver.send(ClientToRelayMsg::Pong(value)).await.unwrap()
                            }
                            _ => {}
                        }
                    }
                })
                .await
                .expect("real relay packet delivery");
                if keep_replaced {
                    held.push(sender);
                } else {
                    let _ = sender.close().await;
                }
            }
            let elapsed = started.elapsed().as_secs_f64();
            let allowed = f64::from(BURST) + f64::from(RATE) * elapsed;
            eprintln!("Home byte budget: replacement={keep_replaced} delivered={delivered} elapsed={elapsed:.3}s allowed={allowed:.0}");
            measurements.push((delivered as f64, allowed));
            for mut sender in held {
                let _ = sender.close().await;
            }
        }
        let _ = receiver.close().await;
        server.shutdown().await.unwrap();
        assert!(
            measurements
                .iter()
                .all(|(delivered, allowed)| delivered <= allowed),
            "fresh sockets must share the Home's byte bucket"
        );
    }

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
            if let Some(policy) = &node.gossip_state.lock().await.relay_lookups {
                assert_eq!(
                    services.len(),
                    2 + usize::from(policy.mdns.is_some()),
                    "the gossip actor must not retain its unfiltered peer lookup"
                );
            }
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
    fn exported_tickets_without_a_public_ip_are_did_only() {
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
        assert!(
            exported.addrs.is_empty(),
            "exported tickets carry public IP hints only; Runtime owns the relay pin"
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
    fn ticket_export_codec_filters_every_endpoint_and_enforces_protocol_bounds() {
        let peer = iroh::SecretKey::from_bytes(&[216; 32]).public();
        let address = iroh::EndpointAddr::new(peer).with_addrs([
            iroh::TransportAddr::Ip("127.0.0.1:0".parse().unwrap()),
            iroh::TransportAddr::Ip("1.1.1.1:0".parse().unwrap()),
            iroh::TransportAddr::Relay("https://relay.example/".parse().unwrap()),
        ]);
        let encode = |endpoints: Vec<iroh::EndpointAddr>| {
            data_encoding::BASE32_NOPAD
                .encode(
                    &serde_json::to_vec(&serde_json::json!({"topic":null,"endpoints":endpoints}))
                        .unwrap(),
                )
                .to_ascii_lowercase()
        };
        let exported =
            super::super::export_connect_ticket(&encode(vec![address.clone(), address.clone()]))
                .unwrap();
        let decoded = super::super::decode_ticket_endpoints(&exported);
        assert_eq!(decoded.len(), 2);
        for endpoint in decoded {
            assert_eq!(
                endpoint.addrs.into_iter().collect::<Vec<_>>(),
                vec![iroh::TransportAddr::Ip("1.1.1.1:0".parse().unwrap())]
            );
        }
        assert!(super::super::export_connect_ticket(&encode(vec![])).is_err());
        assert!(super::super::export_connect_ticket(&encode(vec![
            address;
            crate::collaboration_network::MAX_ENDPOINTS_PER_TICKET
                + 1
        ]))
        .is_err());
        assert!(super::super::export_connect_ticket(
            &"a".repeat(crate::collaboration_network::MAX_CONNECT_TICKET_BYTES + 1)
        )
        .is_err());
    }

    #[test]
    fn pin_policy_https_identity_requires_the_pinned_name_and_trusted_certificate() {
        let (certs, _) = iroh_relay::server::testing::self_signed_tls_certs_and_config();
        let (foreign_certs, _) = iroh_relay::server::testing::self_signed_tls_certs_and_config();
        let relay: RelayUrl = "https://localhost/".parse().unwrap();
        let verifier = pinned_relay_tls(&relay, CaTlsConfig::custom_roots(certs.clone()))
            .server_cert_verifier(Arc::new(rustls::crypto::ring::default_provider()))
            .unwrap();
        let verify = |cert: &CertificateDer<'_>, name: &str| {
            verifier.verify_server_cert(
                cert,
                &[],
                &ServerName::try_from(name.to_string()).unwrap(),
                &[],
                UnixTime::now(),
            )
        };
        assert!(verify(&certs[0], "localhost").is_ok());
        assert!(
            verify(&certs[0], "127.0.0.1").is_err(),
            "a CA-valid alternate SAN is still a different pinned name"
        );
        assert!(
            verify(&foreign_certs[0], "localhost").is_err(),
            "a self-consistent foreign identity grants no trust"
        );
        for (url, name) in [
            ("https://127.0.0.1/", "127.0.0.1"),
            ("https://[::1]/", "::1"),
        ] {
            let verifier = pinned_relay_tls(
                &url.parse().unwrap(),
                CaTlsConfig::custom_roots(certs.clone()),
            )
            .server_cert_verifier(Arc::new(rustls::crypto::ring::default_provider()))
            .unwrap();
            assert!(verifier
                .verify_server_cert(
                    &certs[0],
                    &[],
                    &ServerName::try_from(name.to_string()).unwrap(),
                    &[],
                    UnixTime::now()
                )
                .is_ok());
        }
    }

    #[tokio::test]
    async fn pin_policy_one_lookup_filter_covers_mdns_and_memory_answers() {
        let id = iroh::SecretKey::from_bytes(&[215; 32]).public();
        let pin: RelayUrl = "https://relay.example/".parse().unwrap();
        let foreign: RelayUrl = "https://foreign.example/".parse().unwrap();
        // Both Runtime lookup ingresses use this generic wrapper; this source
        // supplies the same hostile answer without requiring a multicast LAN.
        let source = iroh::address_lookup::memory::MemoryLookup::new();
        source.add_endpoint_info(iroh::EndpointAddr::new(id).with_addrs([
            iroh::TransportAddr::Ip("127.0.0.1:0".parse().unwrap()),
            iroh::TransportAddr::Relay(pin.clone()),
            iroh::TransportAddr::Relay(foreign),
        ]));
        for relay in [None, Some(pin.clone())] {
            let filter = PinnedLookup {
                relay: relay.clone(),
                inner: source.clone(),
            };
            let item = filter
                .resolve(id)
                .unwrap()
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_endpoint_addr();
            assert_eq!(item.ip_addrs().count(), 1);
            assert!(item.relay_urls().all(|found| Some(found) == relay.as_ref()));
        }
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

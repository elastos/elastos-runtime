//! Explicit, off-by-default Carrier relay path. Runtime owns relay selection.

use anyhow::{Context, Result};
use futures_lite::StreamExt as _;
use iroh::address_lookup::{AddrFilter, AddressLookup, EndpointData, EndpointInfo, Item};
use iroh::endpoint::{BeforeConnectOutcome, EndpointHooks};
use iroh::tls::CaTlsConfig;
use iroh::EndpointId;
use iroh::RelayUrl;
use iroh_relay::server::{clients::Clients, Access, AccessControl, ClientRequest, ConnectionId};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

/// Shared by every endpoint. The system resolver owns DNS; failure stays local
/// to that policy. Irzhy reviews this choice before discovery is enabled.
pub(super) fn system_dns() -> iroh::dns::DnsResolver {
    system_dns_builder().build()
}

fn system_dns_builder() -> iroh::dns::Builder {
    iroh::dns::DnsResolver::builder()
        .with_system_defaults()
        .disable_fallback()
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
    // Discovery is a separate, explicit role. Its certificate belongs to the
    // pinned relay origin; HTTP may stay behind the operator's TLS proxy.
    let discovery = config.get("carrier_relay_discovery_bind_addr");
    let cert = config.get("carrier_relay_tls_cert");
    let key = config.get("carrier_relay_tls_key");
    let quic = match (discovery, cert, key) {
        (None, None, None) => None,
        (Some(bind), Some(cert), Some(key)) => {
            let bind: std::net::SocketAddr = bind
                .as_str()
                .context("carrier_relay_discovery_bind_addr must be a socket address")?
                .parse()?;
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let resolver = iroh_relay::server::reloading_resolver(
                &provider,
                cert.as_str()
                    .context("carrier_relay_tls_cert must be a PEM path")?
                    .into(),
                key.as_str()
                    .context("carrier_relay_tls_key must be a PEM path")?
                    .into(),
                iroh_relay::server::DEFAULT_CERT_RELOAD_INTERVAL,
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!("Carrier discovery TLS configuration failed: {error:#}")
            })?;
            let tls = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_cert_resolver(resolver);
            let mut quic = iroh_relay::server::QuicConfig::new(bind);
            quic.server_config = Some(tls);
            Some(quic)
        }
        _ => anyhow::bail!(
            "Carrier discovery needs its bind address and both TLS certificate and key"
        ),
    };
    let mut config = iroh_relay::server::ServerConfig::default();
    config.quic = quic;
    let mut relay = iroh_relay::server::RelayConfig::new(bind);
    apply_byte_limits(&mut relay, 8 * 1024 * 1024, 1024 * 1024);
    let admission = Arc::new(RelayAdmission::default());
    relay.access = admission.clone();
    config.relay = Some(relay);
    let server = iroh_relay::server::Server::spawn(config)
        .await
        .map_err(|error| anyhow::anyhow!("Carrier relay failed to start: {error:#}"))?;
    if let Some(service) = server.relay_service() {
        let _ = admission.clients.set(service.clients().clone());
    }
    Ok(Some(server))
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
    relay.limits.home_rx = Some(
        iroh_relay::server::HomeRateLimit::new(
            rate,
            std::num::NonZeroU32::new(RELAY_CONNECTIONS_TOTAL as u32)
                .expect("nonzero Home capacity"),
        )
        .expect("configured relay byte rate refills each tick"),
    );
}

const RELAY_CONNECTIONS_TOTAL: usize = 4096;
const RELAY_RECONNECT_BURST: f64 = 4.0;
const RELAY_RECONNECT_INTERVAL: Duration = Duration::from_secs(15);
const RELAY_REPLACE_TIMEOUT: Duration = Duration::from_secs(10);
const RELAY_REPLACE_POLL: Duration = Duration::from_millis(5);

#[cfg(test)]
#[derive(Debug)]
struct HeldAdmission {
    home: EndpointId,
    once: std::sync::atomic::AtomicBool,
    admitted: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

/// One Home's relay admission state.
#[derive(Debug)]
struct HomeAdmission {
    /// Every admitted connection until its disconnect, oldest first: the
    /// last is the Home's connection, the others are being replaced.
    connections: Vec<ConnectionId>,
    reconnect_tokens: f64,
    refilled: Instant,
}

/// Admits one relay connection per Home (a new one replaces the old ones),
/// paces each Home's reconnects and caps the relay's total connections.
#[derive(Debug)]
struct RelayAdmission {
    maximum: usize,
    #[cfg(test)]
    held: Option<Arc<HeldAdmission>>,
    homes: Mutex<HashMap<EndpointId, HomeAdmission>>,
    clients: OnceLock<Clients>,
}

impl Default for RelayAdmission {
    fn default() -> Self {
        Self::new(RELAY_CONNECTIONS_TOTAL)
    }
}

impl RelayAdmission {
    fn new(maximum: usize) -> Self {
        Self {
            maximum,
            homes: Mutex::new(HashMap::new()),
            clients: OnceLock::new(),
            #[cfg(test)]
            held: None,
        }
    }

    /// Admits `connection` and returns the Home's older connections, which
    /// it replaces, or the reason it is refused.
    fn admit(
        &self,
        endpoint_id: EndpointId,
        connection: ConnectionId,
        now: Instant,
    ) -> std::result::Result<Vec<ConnectionId>, &'static str> {
        let mut homes = self.homes.lock().expect("relay admission lock");
        for home in homes.values_mut() {
            home.reconnect_tokens = (home.reconnect_tokens
                + now.duration_since(home.refilled).as_secs_f64()
                    / RELAY_RECONNECT_INTERVAL.as_secs_f64())
            .min(RELAY_RECONNECT_BURST);
            home.refilled = now;
        }
        // A Home that is gone and fully paced again needs no state.
        homes.retain(|_, home| {
            !home.connections.is_empty() || home.reconnect_tokens < RELAY_RECONNECT_BURST
        });
        let total: usize = homes.values().map(|home| home.connections.len()).sum();
        if total >= self.maximum {
            return Err("relay is full");
        }
        if !homes.contains_key(&endpoint_id) && homes.len() >= self.maximum {
            return Err("relay Home slots are busy; retry shortly");
        }
        let home = homes.entry(endpoint_id).or_insert(HomeAdmission {
            connections: Vec::new(),
            reconnect_tokens: RELAY_RECONNECT_BURST,
            refilled: now,
        });
        if home.reconnect_tokens < 1.0 {
            return Err("this Home reconnects too often");
        }
        if home.connections.len() >= 2 {
            return Err("this Home's previous replacement is still opening");
        }
        home.reconnect_tokens -= 1.0;
        let older = home.connections.clone();
        home.connections.push(connection);
        Ok(older)
    }

    fn release(&self, endpoint_id: EndpointId, connection: ConnectionId) {
        let mut homes = self.homes.lock().expect("relay admission lock");
        if let Some(home) = homes.get_mut(&endpoint_id) {
            home.connections.retain(|id| *id != connection);
        }
    }

    fn is_admitted(&self, endpoint_id: EndpointId, connection: ConnectionId) -> bool {
        let homes = self.homes.lock().expect("relay admission lock");
        homes
            .get(&endpoint_id)
            .is_some_and(|home| home.connections.contains(&connection))
    }

    /// Admits a connection and closes every connection it replaces. iroh
    /// registers an admitted connection only after its handshake reply, so
    /// a replaced one may not be closable yet: the new connection waits
    /// until it registers (and closes it) or ends.
    async fn connect(&self, endpoint_id: EndpointId, connection: ConnectionId) -> Access {
        let older = match self.admit(endpoint_id, connection, Instant::now()) {
            Ok(older) => older,
            Err(reason) => {
                return Access::Deny {
                    reason: Some(reason.to_string()),
                }
            }
        };
        // iroh reports the disconnect of an allowed connection only; until
        // then a refusal or a dropped handshake releases it here.
        let pending = PendingAdmission {
            admission: self,
            endpoint_id,
            connection: Some(connection),
        };
        #[cfg(test)]
        if let Some(held) = &self.held {
            if held.home == endpoint_id
                && !held.once.swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                held.admitted.notify_one();
                held.release.notified().await;
            }
        }
        if let Some(clients) = self.clients.get() {
            let deadline = tokio::time::Instant::now() + RELAY_REPLACE_TIMEOUT;
            for old in older {
                while self.is_admitted(endpoint_id, old)
                    && !clients.disconnect(endpoint_id, Some(old))
                {
                    if tokio::time::Instant::now() >= deadline {
                        return Access::Deny {
                            reason: Some("this Home's previous connection is still opening".into()),
                        };
                    }
                    tokio::time::sleep(RELAY_REPLACE_POLL).await;
                }
            }
        }
        pending.allow();
        Access::Allow
    }

    #[cfg(test)]
    fn connections(&self, endpoint_id: EndpointId) -> usize {
        let homes = self.homes.lock().expect("relay admission lock");
        homes
            .get(&endpoint_id)
            .map_or(0, |home| home.connections.len())
    }
}

/// An admitted connection before iroh holds its disconnect guard.
struct PendingAdmission<'a> {
    admission: &'a RelayAdmission,
    endpoint_id: EndpointId,
    connection: Option<ConnectionId>,
}

impl PendingAdmission<'_> {
    /// iroh now reports this connection's disconnect.
    fn allow(mut self) {
        self.connection = None;
    }
}

impl Drop for PendingAdmission<'_> {
    fn drop(&mut self) {
        if let Some(connection) = self.connection {
            self.admission.release(self.endpoint_id, connection);
        }
    }
}

impl AccessControl for RelayAdmission {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        if self.clients.get().is_none() {
            return Access::Deny {
                reason: Some("relay is starting".into()),
            };
        }
        self.connect(request.endpoint_id(), request.connection_id())
            .await
    }

    fn on_disconnect(&self, endpoint_id: EndpointId, connection_id: ConnectionId) {
        self.release(endpoint_id, connection_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_configuration_uses_system_defaults_without_any_fallback() {
        let configured = format!("{:?}", system_dns_builder());
        for expected in [
            "use_system_defaults: true",
            "nameservers: []",
            "fallback_mode: Never",
            "fallback_nameservers: []",
        ] {
            assert!(
                configured.contains(expected),
                "DNS policy changed: {expected}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    async fn blocked_dns_probe(resolver: iroh::dns::DnsResolver) {
        assert_eq!(
            std::env::var("ELASTOS_DNS_ISOLATED_PROBE").as_deref(),
            Ok("1"),
            "run through the owned network fixture"
        );
        let started = std::time::Instant::now();
        assert!(resolver
            .lookup_ipv4("carrier-dns-test.example", Duration::from_secs(10))
            .await
            .is_err());
        assert!(
            started.elapsed() < Duration::from_secs(12),
            "DNS failure is bounded"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires the owned blocked-network fixture; scripts/carrier-dns-policy-test.py"]
    async fn dns_probe_system_only() {
        blocked_dns_probe(system_dns()).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "negative trap control in scripts/carrier-dns-policy-test.py"]
    async fn dns_probe_public_fallback_control() {
        blocked_dns_probe(
            iroh::dns::DnsResolver::builder()
                .with_system_defaults()
                .build(),
        )
        .await;
    }

    fn admission_connection(home: EndpointId) -> ConnectionId {
        ClientRequest::new(
            home,
            iroh_relay::http::ProtocolVersion::V2,
            axum::http::Request::new(()).into_parts().0,
        )
        .connection_id()
    }

    #[test]
    fn admission_keeps_exact_ids_paces_reconnects_and_bounds_idle_home_state() {
        let admission = RelayAdmission::new(2);
        let home = iroh::SecretKey::from_bytes(&[226; 32]).public();
        let other = iroh::SecretKey::from_bytes(&[227; 32]).public();
        let third = iroh::SecretKey::from_bytes(&[228; 32]).public();
        let now = Instant::now();
        let first = admission_connection(home);
        let neighbor = admission_connection(other);
        assert!(admission.admit(home, first, now).is_ok());
        assert!(admission.admit(other, neighbor, now).is_ok());
        assert!(
            admission
                .admit(home, admission_connection(home), now)
                .is_err(),
            "replacement owns a capacity slot too"
        );
        admission.release(other, neighbor);
        let next = admission_connection(home);
        assert_eq!(admission.admit(home, next, now).unwrap(), vec![first]);
        admission.release(home, first);
        admission.release(home, first);
        assert_eq!(
            admission.connections(home),
            1,
            "late duplicate disconnect cannot release the replacement"
        );
        drop(PendingAdmission {
            admission: &admission,
            endpoint_id: home,
            connection: Some(next),
        });
        assert_eq!(admission.connections(home), 0);
        assert!(
            admission
                .admit(third, admission_connection(third), now)
                .is_err(),
            "idle identities retain pacing and bounded state"
        );
        let later = now + RELAY_RECONNECT_INTERVAL * 4;
        assert!(admission
            .admit(third, admission_connection(third), later)
            .is_ok());
        assert_eq!(admission.homes.lock().unwrap().len(), 1);
        let mut last = admission_connection(home);
        assert!(admission.admit(home, last, later).is_ok());
        for _ in 1..4 {
            admission.release(home, last);
            last = admission_connection(home);
            assert!(admission.admit(home, last, later).is_ok());
        }
        admission.release(home, last);
        assert!(
            admission
                .admit(home, admission_connection(home), later)
                .is_err(),
            "fresh sockets cannot reset pacing"
        );
    }

    #[tokio::test]
    async fn admission_full_capacity_counts_held_handshakes_and_replacements() {
        use futures_util::SinkExt as _;
        let held_key = iroh::SecretKey::from_bytes(&[224; 32]);
        let held = Arc::new(HeldAdmission {
            home: held_key.public(),
            once: Default::default(),
            admitted: Default::default(),
            release: Default::default(),
        });
        let mut admission = RelayAdmission::new(2);
        admission.held = Some(held.clone());
        let admission = Arc::new(admission);
        let mut relay =
            iroh_relay::server::RelayConfig::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
        relay.access = admission.clone();
        let mut config = iroh_relay::server::ServerConfig::default();
        config.relay = Some(relay);
        let server = iroh_relay::server::Server::spawn(config).await.unwrap();
        admission
            .clients
            .set(server.relay_service().unwrap().clients().clone())
            .ok();
        let url: RelayUrl = format!("http://{}/", server.http_addr().unwrap())
            .parse()
            .unwrap();
        let tls = CaTlsConfig::embedded()
            .client_config(Arc::new(rustls::crypto::ring::default_provider()))
            .unwrap();
        let client = |key: iroh::SecretKey| {
            iroh_relay::client::ClientBuilder::new(url.clone(), key, system_dns())
                .tls_client_config(tls.clone())
        };
        let mut other = client(iroh::SecretKey::from_bytes(&[225; 32]))
            .connect()
            .await
            .unwrap();
        let first = client(held_key.clone());
        let first = tokio::spawn(async move { first.connect().await });
        tokio::time::timeout(Duration::from_secs(3), held.admitted.notified())
            .await
            .unwrap();
        assert_eq!(admission.connections(held_key.public()), 1);
        let replacement = client(held_key);
        let replacement = tokio::spawn(async move { replacement.connect().await });
        let observed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let total: usize = admission
                    .homes
                    .lock()
                    .unwrap()
                    .values()
                    .map(|home| home.connections.len())
                    .sum();
                if total > 2 || replacement.is_finished() {
                    break total;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        eprintln!("Relay admission: capacity=2 observed={observed}");
        replacement.abort();
        let _ = replacement.await;
        first.abort();
        let _ = first.await;
        let _ = other.close().await;
        tokio::time::timeout(Duration::from_secs(3), server.shutdown())
            .await
            .expect("owned held-handshake shutdown")
            .unwrap();
        let remaining: usize = admission
            .homes
            .lock()
            .unwrap()
            .values()
            .map(|home| home.connections.len())
            .sum();
        assert_eq!(
            remaining, 0,
            "cancelled and completed handshakes release their exact admissions"
        );
        assert!(
            observed <= 2,
            "a replacement exceeded total capacity while the old handshake was held: {observed}"
        );
    }

    #[tokio::test]
    async fn home_byte_budget_survives_replacement_and_closed_connection_bursts() {
        use futures_util::SinkExt as _;
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

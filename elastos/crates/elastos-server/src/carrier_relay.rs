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

pub(super) async fn failed_route_reason(
    endpoint: &iroh::Endpoint,
    pin: Option<&RelayUrl>,
) -> &'static str {
    use iroh::Watcher as _;
    if let (Some(pin), Ok(resolver)) = (pin, endpoint.dns_resolver()) {
        let connected = endpoint
            .home_relay_status()
            .get()
            .iter()
            .any(|status| status.url() == pin && status.is_connected());
        if !connected
            && matches!(pin.host(), Some(url::Host::Domain(_)))
            && resolver
                .resolve_host(pin, false, Duration::from_secs(1))
                .await
                .is_err()
        {
            return "carrier_system_dns_unavailable";
        }
    }
    "no verified Carrier route to the requested peer"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RelayPins {
    primary: [u8; 32],
    backup: Option<[u8; 32]>,
}

impl RelayPins {
    fn parse(raw: &str) -> Result<Self> {
        let pins = raw
            .split(',')
            .map(|raw| {
                anyhow::ensure!(
                    raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()),
                    "relay public-key identity must be 64 SHA-256 hex digits"
                );
                let mut pin = [0; 32];
                for (i, byte) in pin.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&raw[2 * i..2 * i + 2], 16)?;
                }
                Ok(pin)
            })
            .collect::<Result<Vec<[u8; 32]>>>()?;
        anyhow::ensure!(
            (1..=2).contains(&pins.len()),
            "relay requires one primary and at most one backup pin"
        );
        Ok(Self {
            primary: pins[0],
            backup: pins.get(1).copied(),
        })
    }

    fn accepts(self, cert: &CertificateDer<'_>) -> bool {
        use sha2::Digest as _;
        let Ok((remaining, parsed)) = x509_parser::parse_x509_certificate(cert.as_ref()) else {
            return false;
        };
        if !remaining.is_empty() {
            return false;
        }
        let actual: [u8; 32] = sha2::Sha256::digest(parsed.public_key().raw).into();
        actual == self.primary || self.backup == Some(actual)
    }
}

/// Release artifacts carry this pair inside their signed binary. Source Homes
/// supply the pair explicitly. The release pair owns selection when present.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ClientSettings {
    pub relay: Option<url::Url>,
    pub certificate: Option<RelayPins>,
}

impl ClientSettings {
    pub fn from_inputs(
        network: Option<&str>,
        url: Option<&str>,
        certificate: Option<&str>,
        release_url: Option<&str>,
        release_certificate: Option<&str>,
    ) -> Result<Self> {
        let network = network.map(str::trim);
        super::parse_elastos_carrier_network(network)?;
        let url = url.map(str::trim);
        let explicit_url = super::parse_elastos_relay_url(url)?;
        anyhow::ensure!(
            release_url.is_some() == release_certificate.is_some(),
            "incomplete release meeting point"
        );
        if network == Some("direct") {
            anyhow::ensure!(
                url.is_none() && certificate.is_none(),
                "direct Carrier rejects relay settings"
            );
            return Ok(Self {
                relay: None,
                certificate: None,
            });
        }
        let released = release_url.is_some();
        if let Some(release_url) = release_url {
            anyhow::ensure!(
                network.is_none_or(|n| n == "relay")
                    && url.is_none_or(|u| u == release_url)
                    && certificate.is_none_or(|p| Some(p) == release_certificate),
                "the signed release owns the meeting point"
            );
        } else {
            anyhow::ensure!(
                matches!(network, None | Some("direct") | Some("relay")),
                "invalid Carrier network"
            );
            if network != Some("relay") {
                anyhow::ensure!(
                    url.is_none() && certificate.is_none(),
                    "direct Carrier rejects relay settings"
                );
                return Ok(Self {
                    relay: None,
                    certificate: None,
                });
            }
        }
        let relay: url::Url = match release_url {
            Some(url) => url.parse()?,
            None => explicit_url.context("relay mode requires its address")?,
        };
        let raw = release_certificate.or(certificate);
        let certificate = raw.map(RelayPins::parse).transpose()?;
        anyhow::ensure!(
            certificate.is_some() || (!released && cfg!(test) && relay.scheme() == "http"),
            "relay mode requires its pinned public-key identity"
        );
        anyhow::ensure!(
            !released || relay.scheme() == "https",
            "released meeting points use HTTPS"
        );
        Ok(Self {
            relay: Some(relay),
            certificate,
        })
    }

    pub fn configured() -> Result<Self> {
        Self::from_inputs(
            std::env::var("ELASTOS_CARRIER_NETWORK").ok().as_deref(),
            std::env::var("ELASTOS_RELAY_URL").ok().as_deref(),
            std::env::var("ELASTOS_RELAY_SPKI_SHA256").ok().as_deref(),
            option_env!("ELASTOS_RELEASE_RELAY_URL"),
            option_env!("ELASTOS_RELEASE_RELAY_SPKI_SHA256"),
        )
    }
}

#[cfg(test)]
pub(super) fn apply_relay(
    builder: iroh::endpoint::Builder,
    relay: &url::Url,
) -> Result<iroh::endpoint::Builder> {
    apply_relay_pinned(builder, relay, None)
}

pub(super) fn apply_relay_pinned(
    builder: iroh::endpoint::Builder,
    relay: &url::Url,
    certificate: Option<RelayPins>,
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
    let http_fixture = cfg!(test)
        && relay.host().is_some_and(|host| match host {
            url::Host::Ipv4(ip) => ip.is_loopback() || ip.is_documentation(),
            url::Host::Ipv6(ip) => ip.is_loopback(),
            url::Host::Domain(_) => false,
        });
    anyhow::ensure!(relay.scheme() == "https" || http_fixture,
        "Carrier relay origins require HTTPS; HTTP is reserved for literal loopback and documentation-network fixtures");
    let relay = RelayUrl::from(relay.clone());
    let quic = (relay.scheme() == "https").then(Default::default);
    Ok(endpoint_policy(builder, Some(&relay))
        .relay_mode(iroh::RelayMode::Custom(iroh::RelayMap::from_iter([
            iroh::RelayConfig::new(relay.clone(), quic),
        ])))
        .ca_tls_config(pinned_relay_identity_tls(
            &relay,
            CaTlsConfig::embedded(),
            certificate,
        ))
        .address_lookup(PinnedRelayLookup(relay)))
}

fn transport_allowed(transport: &iroh::TransportAddr, relay: Option<&RelayUrl>) -> bool {
    match transport {
        iroh::TransportAddr::Ip(_) => true,
        iroh::TransportAddr::Relay(url) => Some(url) == relay,
        _ => false,
    }
}

pub(super) fn lookup_filter(relay: Option<RelayUrl>) -> AddrFilter {
    AddrFilter::new(move |addrs| {
        std::borrow::Cow::Owned(
            addrs
                .iter()
                .filter(|transport| transport_allowed(transport, relay.as_ref()))
                .cloned()
                .collect(),
        )
    })
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
        if remote
            .addrs
            .iter()
            .all(|transport| transport_allowed(transport, self.relay.as_ref()))
        {
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
                            .filter(|transport| transport_allowed(transport, relay.as_ref()))
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
/// The actor installs its filtered gossip lookup after this base policy, so
/// direct route discovery stays available after every rebuild.
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

#[cfg(test)]
fn pinned_relay_tls(relay: &RelayUrl, roots: CaTlsConfig) -> CaTlsConfig {
    pinned_relay_identity_tls(relay, roots, None)
}

fn pinned_relay_identity_tls(
    relay: &RelayUrl,
    roots: CaTlsConfig,
    certificate: Option<RelayPins>,
) -> CaTlsConfig {
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
            certificate,
            inner: roots.server_cert_verifier(provider)?,
        }) as Arc<dyn ServerCertVerifier>)
    }))
}

#[derive(Debug)]
struct PinnedRelayHost {
    certificate: Option<RelayPins>,
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
        if let Some(pin) = self.certificate {
            if !pin.accepts(cert) {
                return Err(rustls::Error::General(
                    "Carrier relay identity changed".into(),
                ));
            }
            // The pinned SPKI is the trust anchor. TLS still verifies the
            // handshake signature through verify_tls12/13_signature below.
            return Ok(ServerCertVerified::assertion());
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
        anyhow::ensure!(
            [
                "carrier_relay_discovery_bind_addr",
                "carrier_relay_tls_cert",
                "carrier_relay_tls_key"
            ]
            .iter()
            .all(|key| !config.contains_key(*key)),
            "Carrier discovery configuration requires the explicit relay role"
        );
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
    // This process terminates TLS and accounts the actual source address.
    let discovery = config.get("carrier_relay_discovery_bind_addr");
    let cert = config.get("carrier_relay_tls_cert");
    let key = config.get("carrier_relay_tls_key");
    let tls = match (cert, key) {
        (Some(cert), Some(key)) => {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            use rustls::pki_types::pem::PemObject as _;
            let certificate = CertificateDer::pem_file_iter(
                cert.as_str()
                    .context("carrier_relay_tls_cert must be a PEM path")?,
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
            anyhow::ensure!(
                !certificate.is_empty(),
                "Carrier relay certificate is empty"
            );
            let private = rustls::pki_types::PrivateKeyDer::from_pem_file(
                key.as_str()
                    .context("carrier_relay_tls_key must be a PEM path")?,
            )?;
            Some(
                rustls::ServerConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()?
                    .with_no_client_auth()
                    .with_single_cert(certificate, private)?,
            )
        }
        (None, None) if cfg!(test) && discovery.is_none() => None,
        _ => anyhow::bail!(
            "Carrier relay needs its TLS certificate and key; it terminates TLS itself"
        ),
    };
    let mut server_config = iroh_relay::server::ServerConfig::default();
    if let Some(discovery) = discovery {
        let bind: std::net::SocketAddr = discovery
            .as_str()
            .context("invalid discovery address")?
            .parse()?;
        anyhow::ensure!(
            cfg!(test) || bind.port() == iroh_relay::defaults::DEFAULT_RELAY_QUIC_PORT,
            "Carrier discovery uses the protocol discovery port"
        );
        let mut quic = iroh_relay::server::QuicConfig::new(bind);
        quic.server_config = tls.clone();
        server_config.quic = Some(quic);
    }
    let mut relay = iroh_relay::server::RelayConfig::new(bind);
    if tls.is_some() {
        relay.http_bind_addr = "127.0.0.1:0".parse()?;
    }
    relay.tls = tls.map(|server_config| {
        iroh_relay::server::TlsConfig::new(
            bind,
            iroh_relay::server::CertConfig::Manual { server_config },
        )
    });
    let mut connections = iroh_relay::server::ConnectionLimits::default();
    connections.total = setting(
        &config,
        "carrier_relay_connections",
        connections.total as u32,
    )? as usize;
    connections.pending =
        setting(&config, "carrier_relay_pending", connections.pending as u32)? as usize;
    connections.per_network = setting(
        &config,
        "carrier_relay_per_network",
        connections.per_network as u32,
    )? as usize;
    connections.pending_per_network = setting(
        &config,
        "carrier_relay_pending_per_network",
        connections.pending_per_network as u32,
    )? as usize;
    anyhow::ensure!(
        connections.validate(),
        "Carrier relay capacity must reserve places for 64 source networks"
    );
    relay.limits.connections = connections;
    let home_rate = setting(&config, "carrier_relay_home_bytes_per_second", 64 * 1024)?;
    let home_burst = setting(&config, "carrier_relay_home_burst_bytes", 128 * 1024)?;
    anyhow::ensure!(
        home_rate >= 10,
        "Home byte rate must refill at least one byte per tick"
    );
    apply_byte_limits(&mut relay, home_rate, home_burst);
    let mut global = iroh_relay::server::ClientRateLimit::new(
        std::num::NonZeroU32::new(setting(
            &config,
            "carrier_relay_bytes_per_second",
            1024 * 1024,
        )?)
        .expect("validated rate"),
    );
    anyhow::ensure!(
        global.bytes_per_second.get() >= 10,
        "global byte rate must refill at least one byte per tick"
    );
    global.max_burst_bytes = std::num::NonZeroU32::new(setting(
        &config,
        "carrier_relay_burst_bytes",
        2 * 1024 * 1024,
    )?);
    anyhow::ensure!(
        global.bytes_per_second.get() >= 640,
        "global byte rate must be at least 640 bytes per second"
    );
    let source = source_byte_limits(&config)?;
    anyhow::ensure!(
        global.max_burst_bytes.expect("configured burst").get() >= 2 * 1024 * 1024,
        "global burst must admit the largest relay frame"
    );
    relay.limits.network_rx = Some(source);
    relay.limits.global_rx = Some(global);
    let admission = Arc::new(RelayAdmission::new(connections.total));
    relay.access = admission.clone();
    server_config.relay = Some(relay);
    let config = server_config;
    let server = iroh_relay::server::Server::spawn(config)
        .await
        .map_err(|error| anyhow::anyhow!("Carrier relay failed to start: {error:#}"))?;
    if let Some(service) = server.relay_service() {
        let _ = admission.clients.set(service.clients().clone());
    }
    Ok(Some(server))
}

fn source_byte_limits(config: &toml::Table) -> Result<iroh_relay::server::ClientRateLimit> {
    let rate = setting(config, "carrier_relay_network_bytes_per_second", 16 * 1024)?;
    anyhow::ensure!(
        rate >= 10,
        "source byte rate must refill at least one byte per tick"
    );
    let mut limit = iroh_relay::server::ClientRateLimit::new(
        std::num::NonZeroU32::new(rate).expect("validated source rate"),
    );
    limit.max_burst_bytes = std::num::NonZeroU32::new(setting(
        config,
        "carrier_relay_network_burst_bytes",
        32 * 1024,
    )?);
    Ok(limit)
}

fn setting(config: &toml::Table, key: &str, default: u32) -> Result<u32> {
    let value = match config.get(key) {
        Some(value) => u32::try_from(
            value
                .as_integer()
                .context("relay capacity must be an integer")?,
        )?,
        None => default,
    };
    anyhow::ensure!(
        value > 0 && value <= 64 * 1024 * 1024,
        "{key} is outside its supported capacity range"
    );
    Ok(value)
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
            std::num::NonZeroU32::new(relay.limits.connections.total as u32)
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
    fn released_and_source_homes_have_one_explicit_trust_owner() {
        let pin = "ab".repeat(32);
        let release = ClientSettings::from_inputs(
            None,
            None,
            None,
            Some("https://relay.example/"),
            Some(&pin),
        )
        .unwrap();
        assert_eq!(release.relay.unwrap().as_str(), "https://relay.example/");
        assert_eq!(
            release.certificate,
            Some(RelayPins {
                primary: [0xab; 32],
                backup: None
            })
        );
        assert!(ClientSettings::from_inputs(
            Some("relay"),
            Some("https://other.example/"),
            Some(&pin),
            Some("https://relay.example/"),
            Some(&pin)
        )
        .is_err());
        assert!(ClientSettings::from_inputs(
            Some("direct"),
            None,
            None,
            Some("https://relay.example/"),
            Some(&pin)
        )
        .unwrap()
        .relay
        .is_none());
        assert!(ClientSettings::from_inputs(
            Some("direct"),
            Some("https://other.example/"),
            None,
            Some("https://relay.example/"),
            Some(&pin)
        )
        .is_err());
        assert!(ClientSettings::from_inputs(None, None, None, None, None)
            .unwrap()
            .relay
            .is_none());
        assert!(ClientSettings::from_inputs(
            Some("relay"),
            Some("https://relay.example/"),
            None,
            None,
            None
        )
        .is_err());
        assert!(ClientSettings::from_inputs(
            Some("relay"),
            Some("https://relay.example/"),
            Some(&pin),
            None,
            None
        )
        .unwrap()
        .relay
        .is_some());
        assert!(ClientSettings::from_inputs(
            None,
            None,
            None,
            Some("http://127.0.0.1/"),
            Some(&pin)
        )
        .is_err());
    }

    #[test]
    fn source_byte_rate_has_independent_defaults_and_settings() {
        let defaults = source_byte_limits(&toml::Table::new()).unwrap();
        assert_eq!(defaults.bytes_per_second.get(), 16 * 1024);
        assert_eq!(defaults.max_burst_bytes.unwrap().get(), 32 * 1024);
        let mut config: toml::Table =
            "carrier_relay_bytes_per_second = 4096\ncarrier_relay_burst_bytes = 2097152"
                .parse()
                .unwrap();
        assert_eq!(
            source_byte_limits(&config).unwrap().bytes_per_second,
            defaults.bytes_per_second
        );
        config.insert(
            "carrier_relay_network_bytes_per_second".into(),
            toml::Value::Integer(65536),
        );
        config.insert(
            "carrier_relay_network_burst_bytes".into(),
            toml::Value::Integer(131072),
        );
        let configured = source_byte_limits(&config).unwrap();
        assert_eq!(configured.bytes_per_second.get(), 65536);
        assert_eq!(configured.max_burst_bytes.unwrap().get(), 131072);
        for invalid in [0, 9, -1, i64::MAX] {
            config.insert(
                "carrier_relay_network_bytes_per_second".into(),
                toml::Value::Integer(invalid),
            );
            assert!(source_byte_limits(&config).is_err());
        }
    }

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
        let relay = url::Url::parse("https://carrier-dns-test.example/").unwrap();
        let endpoint = apply_relay(
            iroh::Endpoint::builder(iroh::endpoint::presets::Minimal).clear_ip_transports(),
            &relay,
        )
        .unwrap()
        .dns_resolver(system_dns())
        .bind()
        .await
        .unwrap();
        let failed_dial = tokio::time::timeout(
            Duration::from_secs(2),
            endpoint.connect(
                iroh::SecretKey::from_bytes(&[240; 32]).public(),
                b"elastos/dns-policy-probe",
            ),
        )
        .await;
        assert!(
            !matches!(failed_dial, Ok(Ok(_))),
            "blocked DNS must not produce a relay path"
        );
        let pin = RelayUrl::from(relay.clone());
        let reason = tokio::time::timeout(
            Duration::from_secs(3),
            failed_route_reason(&endpoint, Some(&pin)),
        )
        .await
        .expect("the owner's DNS diagnosis is bounded");
        assert_eq!(reason, "carrier_system_dns_unavailable");
        endpoint.close().await;
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

    #[tokio::test]
    async fn discovery_requires_complete_explicit_role_configuration() {
        for contents in [
            "carrier_relay_tls_cert = 'fixture.pem'",
            "gateway_public_publisher_bootstrap = true\ncarrier_relay_bind_addr = '127.0.0.1:0'\ncarrier_relay_tls_key = 'fixture.pem'",
            "gateway_public_publisher_bootstrap = true\ncarrier_relay_bind_addr = '127.0.0.1:0'\ncarrier_relay_discovery_bind_addr = '127.0.0.1:0'",
        ] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("config.toml"), contents).unwrap();
            assert!(configured_server(dir.path()).await.is_err());
        }
    }

    #[test]
    fn relay_requires_https_outside_owned_fixture_address_ranges() {
        for origin in [
            "http://relay.example/",
            "http://8.8.8.8/",
            "http://192.168.1.8/",
        ] {
            let result = apply_relay(
                iroh::Endpoint::builder(iroh::endpoint::presets::Minimal),
                &origin.parse().unwrap(),
            );
            assert!(result.is_err(), "{origin}");
        }
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
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn three_source_floods_preserve_another_homes_heartbeats_and_delivery() {
        use futures_util::SinkExt as _;
        use iroh_relay::protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        // This owned CONNECT fixture binds the actual relay-facing TCP source.
        // Its input is bounded and contains no credentials.
        async fn source_proxy(
            source: [u8; 4],
            destination: std::net::SocketAddr,
        ) -> (url::Url, tokio::task::JoinHandle<()>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/", listener.local_addr().unwrap())
                .parse()
                .unwrap();
            let task = tokio::spawn(async move {
                let mut children = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        connection = listener.accept() => {
                            let (mut incoming, _) = connection.unwrap();
                            children.spawn(async move {
                                let mut request = Vec::new();
                                tokio::time::timeout(Duration::from_secs(5), async {
                                    while !request.ends_with(b"\r\n\r\n") {
                                        assert!(request.len() < 2048);
                                        request.push(incoming.read_u8().await.unwrap());
                                    }
                                }).await.unwrap();
                                assert!(request.starts_with(b"CONNECT "));
                                let socket = tokio::net::TcpSocket::new_v4().unwrap();
                                socket.bind((source, 0).into()).unwrap();
                                let mut outgoing = socket.connect(destination).await.unwrap();
                                incoming.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.unwrap();
                                let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
                            });
                        }
                        _ = children.join_next(), if !children.is_empty() => {}
                    }
                }
            });
            (url, task)
        }
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(fixture.path().join("config.toml"),
            "gateway_public_publisher_bootstrap = true\ncarrier_relay_bind_addr = \"127.0.0.1:0\"\n").unwrap();
        let server = configured_server(fixture.path()).await.unwrap().unwrap();
        let address = server.http_addr().unwrap();
        let url: RelayUrl = format!("http://{address}/").parse().unwrap();
        let tls = CaTlsConfig::embedded()
            .client_config(Arc::new(rustls::crypto::ring::default_provider()))
            .unwrap();
        let mut proxies = Vec::new();
        let mut sources = Vec::new();
        for last in [2, 3, 6, 4, 5] {
            let (proxy, task) = source_proxy([127, 0, 0, last], address).await;
            sources.push(proxy);
            proxies.push(task);
        }
        let connect = |key: u8, source: usize| {
            iroh_relay::client::ClientBuilder::new(
                url.clone(),
                iroh::SecretKey::from_bytes(&[key; 32]),
                system_dns(),
            )
            .tls_client_config(tls.clone())
            .proxy_url(sources[source].clone())
        };
        let mut attackers = Vec::new();
        let absent = iroh::SecretKey::from_bytes(&[244; 32]).public();
        for index in 0..96u8 {
            let client = connect(index + 1, usize::from(index / 32))
                .connect()
                .await
                .unwrap();
            let (mut stream, mut sink) = client.split();
            attackers.push(tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                loop {
                    tokio::select! {
                        _ = tick.tick() => {
                            if sink.send(ClientToRelayMsg::Datagrams { dst_endpoint_id: absent, datagrams: Datagrams::from(vec![42; 65500]) }).await.is_err() { break; }
                        }
                        message = stream.next() => match message {
                            Some(Ok(RelayToClientMsg::Ping(ping))) => { if sink.send(ClientToRelayMsg::Pong(ping)).await.is_err() { break; } }
                            Some(Ok(_)) => {}
                            _ => break,
                        }
                    }
                }
            }));
        }
        let (mut h_stream, h_sink) = connect(245, 3).connect().await.unwrap().split();
        let (mut p_stream, p_sink) = connect(246, 4).connect().await.unwrap().split();
        let h_sink = Arc::new(tokio::sync::Mutex::new(h_sink));
        let h_control = h_sink.clone();
        let h_pings = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = h_pings.clone();
        let h_reader = tokio::spawn(async move {
            while let Some(message) = h_stream.next().await {
                if let RelayToClientMsg::Ping(ping) = message.unwrap() {
                    h_control
                        .lock()
                        .await
                        .send(ClientToRelayMsg::Pong(ping))
                        .await
                        .unwrap();
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
            panic!("honest Home disconnected during source floods");
        });
        let (received, mut arrivals) = tokio::sync::mpsc::channel(2);
        let p_reader = tokio::spawn(async move {
            let mut sink = p_sink;
            while let Some(message) = p_stream.next().await {
                match message.unwrap() {
                    RelayToClientMsg::Ping(ping) => {
                        sink.send(ClientToRelayMsg::Pong(ping)).await.unwrap()
                    }
                    RelayToClientMsg::Datagrams { datagrams, .. } => {
                        received.send(datagrams.contents).await.unwrap()
                    }
                    _ => {}
                }
            }
            panic!("honest recipient disconnected during source floods");
        });
        tokio::time::sleep(Duration::from_secs(65)).await;
        let live = !h_reader.is_finished() && !p_reader.is_finished();
        let active_flooders = attackers.iter().filter(|task| !task.is_finished()).count();
        let heartbeats = h_pings.load(std::sync::atomic::Ordering::SeqCst);
        let started = Instant::now();
        let delivered = if live {
            h_sink
                .lock()
                .await
                .send(ClientToRelayMsg::Datagrams {
                    dst_endpoint_id: iroh::SecretKey::from_bytes(&[246; 32]).public(),
                    datagrams: Datagrams::from(vec![7; 1024]),
                })
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(1), arrivals.recv())
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        eprintln!("hostile source floods: sockets=96 networks=3 live={live} heartbeats={heartbeats} delivered={} elapsed_ms={}", delivered.as_ref().map_or(0, |bytes| bytes.len()), started.elapsed().as_millis());
        for task in attackers {
            task.abort();
            let _ = task.await;
        }
        h_reader.abort();
        let _ = h_reader.await;
        p_reader.abort();
        let _ = p_reader.await;
        server.shutdown().await.unwrap();
        for task in proxies {
            task.abort();
            let _ = task.await;
        }
        assert_eq!(
            active_flooders, 96,
            "the hostile load must remain active through the observation"
        );
        assert!(
            live && heartbeats >= 3,
            "healthy Home lost its relay heartbeat under three source floods"
        );
        assert_eq!(
            delivered.as_deref(),
            Some(&vec![7; 1024][..]),
            "another source must deliver within one second"
        );
    }

    #[tokio::test]
    async fn global_byte_budget_survives_many_homes_and_reconnects() {
        use futures_util::SinkExt as _;
        use iroh_relay::protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg};
        const RATE: u32 = 1024;
        const BURST: u32 = 4096;
        let mut relay =
            iroh_relay::server::RelayConfig::new(std::net::SocketAddr::from(([127, 0, 0, 1], 0)));
        let mut rate =
            iroh_relay::server::ClientRateLimit::new(std::num::NonZeroU32::new(RATE).unwrap());
        rate.max_burst_bytes = std::num::NonZeroU32::new(BURST);
        relay.limits.global_rx = Some(rate);
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
        let receiver_key = iroh::SecretKey::from_bytes(&[240; 32]);
        let mut receiver = build(receiver_key.clone()).connect().await.unwrap();
        let mut measurements = Vec::new();
        for (keep_replaced, key) in [(false, 218), (true, 230)] {
            let mut held = Vec::new();
            let mut delivered = 0usize;
            let started = std::time::Instant::now();
            for attempt in 0..4 {
                let key = iroh::SecretKey::from_bytes(&[key + attempt; 32]);
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
            eprintln!("Global byte budget: replacement={keep_replaced} delivered={delivered} elapsed={elapsed:.3}s allowed={allowed:.0}");
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
            "all identities must share the relay byte bucket"
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
    async fn gossip_wire_routes_keep_direct_ips_and_filter_foreign_relays_after_rebuild() {
        use iroh::Watcher as _;
        let (pinned_server, pin) = real_relay().await;
        let (foreign_server, foreign) = real_relay().await;
        let dir = tempfile::tempdir().unwrap();
        let (key, did) = elastos_identity::derive_did(&[232; 32]);
        let node = super::super::start_carrier_node_with_network(
            &key,
            &did,
            dir.path().to_path_buf(),
            None,
            super::super::CarrierNetworkPolicy {
                network: super::super::CarrierNodeNetwork::Public,
                relay: Some(pin),
                certificate: None,
            },
            Some("127.0.0.1:0".parse().unwrap()),
            &[],
        )
        .await
        .unwrap();
        // This peer publishes its foreign relay through the real gossip wire.
        let peer = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(&[233; 32]))
            .addr_filter(AddrFilter::unfiltered())
            .relay_mode(iroh::RelayMode::Custom(iroh::RelayMap::from_iter([
                iroh::RelayConfig::new(foreign.as_str().parse().unwrap(), None),
            ])))
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), peer.online())
            .await
            .unwrap();
        let peer_gossip = iroh_gossip::Gossip::builder().spawn(peer.clone());
        let router = iroh::protocol::Router::builder(peer.clone())
            .accept(iroh_gossip::ALPN, peer_gossip.clone())
            .spawn();
        let topic = super::super::topic_hash("relay-pin-wire");
        let peer_topic = peer_gossip
            .subscribe_with_opts(topic, iroh_gossip::api::JoinOptions::with_bootstrap(vec![]))
            .await
            .unwrap();
        node.memory_lookup
            .add_endpoint_info(peer.watch_addr().get());
        for rebuild in [false, true] {
            if rebuild {
                super::super::rebuild_carrier_gossip(&mut *node.gossip_state.lock().await)
                    .await
                    .unwrap();
            }
            let gossip = node.gossip_state.lock().await.gossip.clone();
            let joined = tokio::time::timeout(
                Duration::from_secs(10),
                gossip.subscribe_and_join(topic, vec![peer.id()]),
            )
            .await
            .unwrap()
            .unwrap();
            let observed = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let mut resolved = node.endpoint.address_lookup().unwrap().resolve(peer.id());
                    while let Some(item) = resolved.next().await {
                        if let Ok(Ok(item)) = item {
                            if item.provenance() == "gossip" {
                                return item.into_endpoint_addr();
                            }
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert!(
                observed.addrs.iter().any(iroh::TransportAddr::is_ip),
                "gossip still discovers useful direct routes"
            );
            assert!(
                observed.addrs.iter().all(|addr| !addr.is_relay()),
                "foreign relay crossed the gossip wire policy"
            );
            drop(joined);
        }
        drop(peer_topic);
        router.shutdown().await.unwrap();
        node.shutdown().await;
        foreign_server.shutdown().await.unwrap();
        pinned_server.shutdown().await.unwrap();
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
                certificate: None,
            },
            Some("127.0.0.1:0".parse().unwrap()),
            &[],
        )
        .await
        .unwrap();
        let peer = iroh::SecretKey::from_bytes(&[213; 32]).public();
        let invoker = super::super::CarrierProviderInvoker::with_carrier_node_and_registry(
            &node,
            std::sync::Weak::new(),
        );
        assert_eq!(
            invoker.relay_pin,
            Some(RelayUrl::from(pin.clone())),
            "provider calls retain the configured pin even without live relay status"
        );
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
                    3 + usize::from(policy.mdns.is_some()),
                    "retain filtered gossip, pinned DID, memory and optional mDNS"
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
    fn relay_pin_survives_certificate_renewal_with_the_same_key() {
        use sha2::Digest as _;
        let key = rcgen::KeyPair::generate().unwrap();
        let first = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let mut renewed = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        renewed.serial_number = Some(42u64.into());
        let renewed = renewed.self_signed(&key).unwrap();
        assert_ne!(first.der(), renewed.der());
        let pin = RelayPins {
            primary: sha2::Sha256::digest(key.public_key_der()).into(),
            backup: None,
        };
        let relay: RelayUrl = "https://localhost/".parse().unwrap();
        let verifier = pinned_relay_identity_tls(&relay, CaTlsConfig::embedded(), Some(pin))
            .server_cert_verifier(Arc::new(rustls::crypto::ring::default_provider()))
            .unwrap();
        for cert in [first.der(), renewed.der()] {
            assert!(verifier
                .verify_server_cert(
                    cert,
                    &[],
                    &ServerName::try_from("localhost").unwrap(),
                    &[],
                    UnixTime::now()
                )
                .is_ok());
        }
    }

    #[test]
    fn backup_spki_pin_accepts_rotation_and_refuses_a_third_key() {
        use sha2::Digest as _;
        let cert = |key: &rcgen::KeyPair| {
            rcgen::CertificateParams::new(vec!["localhost".into()])
                .unwrap()
                .self_signed(key)
                .unwrap()
        };
        let primary = rcgen::KeyPair::generate().unwrap();
        let backup = rcgen::KeyPair::generate().unwrap();
        let foreign = rcgen::KeyPair::generate().unwrap();
        let pins = RelayPins::parse(&format!(
            "{:x},{:x}",
            sha2::Sha256::digest(primary.public_key_der()),
            sha2::Sha256::digest(backup.public_key_der())
        ))
        .unwrap();
        assert!(pins.accepts(cert(&primary).der()));
        assert!(pins.accepts(cert(&backup).der()));
        assert!(!pins.accepts(cert(&foreign).der()));
        assert!(!pins.accepts(&CertificateDer::from(vec![0; 32])));
        assert!(RelayPins::parse("").is_err());
        assert!(RelayPins::parse(&format!("{0},{0},{0}", "ab".repeat(32))).is_err());
    }

    #[test]
    fn relay_certificate_identity_rejects_a_different_key_at_the_same_address() {
        use sha2::Digest as _;
        let (certs, _) = iroh_relay::server::testing::self_signed_tls_certs_and_config();
        let (foreign, _) = iroh_relay::server::testing::self_signed_tls_certs_and_config();
        let relay: RelayUrl = "https://localhost/".parse().unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(certs[0].as_ref()).unwrap();
        let pin = RelayPins {
            primary: sha2::Sha256::digest(parsed.public_key().raw).into(),
            backup: None,
        };
        let verifier = pinned_relay_identity_tls(
            &relay,
            CaTlsConfig::custom_roots(foreign.clone()),
            Some(pin),
        )
        .server_cert_verifier(Arc::new(rustls::crypto::ring::default_provider()))
        .unwrap();
        let verify = |cert: &CertificateDer<'_>, name: &str| {
            verifier.verify_server_cert(
                cert,
                &[],
                &ServerName::try_from(name.to_owned()).unwrap(),
                &[],
                UnixTime::now(),
            )
        };
        assert!(verify(&certs[0], "localhost").is_ok());
        assert!(
            verify(&foreign[0], "localhost").is_err(),
            "a trusted CA cannot replace the pinned identity"
        );
        assert!(
            verify(&certs[0], "127.0.0.1").is_err(),
            "the address is pinned with the identity"
        );
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

//! Internal Carrier transport for one verified collaboration network.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use elastos_runtime::provider::Provider;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::time::Instant;

use crate::collaboration_network::{
    validate_collaboration_bootstrap_peer, CollaborationBootstrapPeer,
    VerifiedCollaborationNetworkProfile,
};
use crate::collaboration_protocol::{
    verify_collaboration_transport_frame, MAX_COLLABORATION_TRANSPORT_FRAME_BYTES,
};

const COLLABORATION_TOPIC_DOMAIN: &[u8] = b"elastos.collaboration.carrier.topic.v1";
const COLLABORATION_TOPIC_PREFIX: &str = "__elastos_internal/collaboration-v1/";
pub(crate) const COLLABORATION_RECEIVE_BATCH_SIZE: usize = 32;
const MAX_RECEIVE_RESPONSE_BYTES: usize =
    MAX_COLLABORATION_TRANSPORT_FRAME_BYTES * COLLABORATION_RECEIVE_BATCH_SIZE + 64 * 1024;
/// How long a joined Home may have no Community peer before it repairs the
/// link. Gossip neighbours come back within seconds of a working dial, and
/// the missing-peer rejoin retries every second, so a minute is a dead link.
pub(crate) const COMMUNITY_LINK_SILENCE: Duration = Duration::from_secs(60);
/// Longest early wait while a Home stays without a Community peer.
const MAX_COMMUNITY_LINK_RETRY: Duration = Duration::from_secs(300);
const COMMUNITY_OUTAGE_FAST_REBUILDS: u32 = 6;
const COMMUNITY_LONG_OUTAGE_RETRY: Duration = Duration::from_secs(900);
const COMMUNITY_ADDRESS_STABILITY: Duration = Duration::from_secs(10);

pub(crate) type CommunityHostAddresses = BTreeSet<IpAddr>;

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn is_community_host_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !ip.is_loopback() && !ip.is_unspecified() && !ip.is_link_local(),
        IpAddr::V6(ip) => !ip.is_loopback() && !ip.is_unspecified() && !ip.is_unicast_link_local(),
    }
}

/// Runtime samples host interfaces as a repair hint, not as connectivity proof.
/// Unsupported hosts and enumeration failures keep the scheduled repair path.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn community_host_addresses() -> Option<CommunityHostAddresses> {
    struct InterfaceList(*mut libc::ifaddrs);
    impl Drop for InterfaceList {
        fn drop(&mut self) {
            // SAFETY: this is the list returned by a successful getifaddrs call,
            // and this guard owns its one matching free.
            if !self.0.is_null() {
                unsafe { libc::freeifaddrs(self.0) };
            }
        }
    }

    let mut head = std::ptr::null_mut();
    // SAFETY: head is a valid output pointer. On success the guard owns the
    // allocated list until every address has been copied into Rust values.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let list = InterfaceList(head);
    let mut current = list.0;
    let mut addresses = CommunityHostAddresses::new();
    while !current.is_null() {
        // SAFETY: getifaddrs owns a linked list of valid ifaddrs records until
        // the guard frees it. Family checks precede the sockaddr casts.
        let interface = unsafe { &*current };
        if !interface.ifa_addr.is_null() {
            let family = unsafe { (*interface.ifa_addr).sa_family } as i32;
            let ip = match family {
                libc::AF_INET => {
                    let addr = unsafe { &*interface.ifa_addr.cast::<libc::sockaddr_in>() };
                    Some(IpAddr::V4(std::net::Ipv4Addr::from(
                        addr.sin_addr.s_addr.to_ne_bytes(),
                    )))
                }
                libc::AF_INET6 => {
                    let addr = unsafe { &*interface.ifa_addr.cast::<libc::sockaddr_in6>() };
                    Some(IpAddr::V6(std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr)))
                }
                _ => None,
            };
            if let Some(ip) = ip.filter(is_community_host_address) {
                addresses.insert(ip);
            }
        }
        current = interface.ifa_next;
    }
    Some(addresses)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn community_host_addresses() -> Option<CommunityHostAddresses> {
    None
}

/// An exact collaboration-network Carrier subscription.
///
/// Its topology, topic, and consumer remain private so send and peek/ack cannot
/// be redirected by a caller after the verified-profile join succeeds.
pub struct JoinedCollaborationNetwork {
    carrier: Arc<dyn Provider>,
    topic: String,
    consumer_id: String,
    bootstrap_node_ids: Vec<String>,
    bootstrap_tickets: Vec<String>,
    pending_join: std::sync::atomic::AtomicBool,
    runtime_node_id: Option<iroh::EndpointId>,
    bootstrap_failure: std::sync::Mutex<Option<&'static str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollaborationCarrierSendOutcome {
    RemoteBroadcast { peer_count: u32 },
    LocalOnlyBuffered,
}

/// Decoded payloads are read-only; the private Carrier range cannot be changed
/// or acknowledged independently of the batch that produced them.
///
/// ```compile_fail
/// use elastos_server::collaboration_carrier::CollaborationCarrierReceiveBatch;
///
/// fn discard_before_ack(batch: &mut CollaborationCarrierReceiveBatch) {
///     batch.envelopes.clear();
/// }
/// ```
#[derive(Clone)]
pub struct CollaborationCarrierReceiveBatch {
    envelopes: Vec<Vec<u8>>,
    rejected_frames: usize,
    consumer_id: String,
    cursor: u64,
    next_cursor: u64,
    limit: usize,
}

impl CollaborationCarrierReceiveBatch {
    pub fn envelopes(&self) -> &[Vec<u8>] {
        &self.envelopes
    }

    pub fn rejected_frames(&self) -> usize {
        self.rejected_frames
    }

    /// The buffer position of the first frame in this batch. The Carrier
    /// replays the batch from here until the Home acknowledges it.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CarrierResponse<T> {
    status: String,
    data: T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RememberPeerData {
    added: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinExactData {
    topic: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalTicketData {
    node_id: String,
    ticket: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TopicPeersData {
    topic: String,
    peers: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TopicHealthData {
    topic: String,
    peer_count: usize,
    received_frames: u64,
    receiver_alive: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RebuildData {
    topics: usize,
}

/// One reading of the Community topic in Carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommunityLinkHealth {
    pub(crate) peer_count: usize,
    /// Frames received from peers since the topic was joined.
    pub(crate) received_frames: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CarrierBroadcast {
    LocalOnly,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendResponse {
    status: String,
    broadcast: Option<CarrierBroadcast>,
    data: SendData,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendData {
    remote_peer_count: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiveData {
    messages: Vec<serde_json::Value>,
    scanned: usize,
    limit: usize,
    cursor: u64,
    next_cursor: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckData {
    cursor: u64,
    next_cursor: u64,
    advanced: bool,
}

/// Raw collaboration-network profiles cannot call this API:
///
/// ```compile_fail
/// use std::sync::Arc;
/// use elastos_runtime::provider::Provider;
/// use elastos_server::collaboration_carrier::join_collaboration_network;
/// use elastos_server::collaboration_network::CollaborationNetworkProfile;
///
/// async fn raw_profile_is_not_authority(
///     carrier: Arc<dyn Provider>,
///     raw_profile: &CollaborationNetworkProfile,
/// ) {
///     join_collaboration_network(carrier, raw_profile).await.unwrap();
/// }
/// ```
pub async fn join_collaboration_network(
    carrier: Arc<dyn Provider>,
    profile: &VerifiedCollaborationNetworkProfile,
) -> anyhow::Result<JoinedCollaborationNetwork> {
    let consumer_id = random_collaboration_consumer_id()?;
    let topic = collaboration_topic(profile);
    let mut peers = Vec::with_capacity(profile.profile().bootstrap_peers.len());

    for bootstrap in &profile.profile().bootstrap_peers {
        let response = carrier
            .send_raw(&serde_json::json!({
                "op": "remember_peer",
                "ticket": bootstrap.connect_ticket,
            }))
            .await
            .context("Carrier remember_peer failed for collaboration bootstrap")?;
        let data: RememberPeerData = require_ok_response(response, "remember_peer")?;
        if data.added.is_empty()
            || data
                .added
                .iter()
                .any(|node_id| node_id != &bootstrap.node_id)
        {
            anyhow::bail!("Carrier remember_peer returned a mismatched collaboration bootstrap");
        }
        peers.push(bootstrap.node_id.clone());
    }

    let response = carrier
        .send_raw(&serde_json::json!({
            "op": "gossip_join_exact",
            "topic": topic,
            "peers": peers,
        }))
        .await
        .context("Carrier gossip_join_exact failed for collaboration network")?;
    let data: JoinExactData = require_ok_response(response, "gossip_join_exact")?;
    if data.topic != topic {
        anyhow::bail!("Carrier gossip_join_exact returned a mismatched collaboration topic");
    }

    Ok(JoinedCollaborationNetwork {
        carrier,
        topic,
        consumer_id,
        bootstrap_node_ids: peers,
        bootstrap_tickets: profile
            .profile()
            .bootstrap_peers
            .iter()
            .map(|peer| peer.connect_ticket.clone())
            .collect(),
        pending_join: std::sync::atomic::AtomicBool::new(false),
        runtime_node_id: None,
        bootstrap_failure: std::sync::Mutex::new(None),
    })
}

impl JoinedCollaborationNetwork {
    /// Runtime already owns the exact device key used to start Carrier. Role
    /// selection can use it even when a local provider call stops answering.
    pub(crate) fn with_runtime_node_id(mut self, node_id: iroh::EndpointId) -> Self {
        self.runtime_node_id = Some(node_id);
        self
    }

    /// A desired, verified subscription can outlive a failed local initial join.
    pub(crate) fn pending(
        carrier: Arc<dyn Provider>,
        profile: &VerifiedCollaborationNetworkProfile,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            carrier,
            topic: collaboration_topic(profile),
            consumer_id: random_collaboration_consumer_id()?,
            bootstrap_node_ids: profile
                .profile()
                .bootstrap_peers
                .iter()
                .map(|peer| peer.node_id.clone())
                .collect(),
            bootstrap_tickets: profile
                .profile()
                .bootstrap_peers
                .iter()
                .map(|peer| peer.connect_ticket.clone())
                .collect(),
            pending_join: std::sync::atomic::AtomicBool::new(true),
            runtime_node_id: None,
            bootstrap_failure: std::sync::Mutex::new(None),
        })
    }

    async fn restore_absent_topic(&self) -> anyhow::Result<()> {
        for (ticket, node_id) in self.bootstrap_tickets.iter().zip(&self.bootstrap_node_ids) {
            let response = self
                .carrier
                .send_raw(&serde_json::json!({"op":"remember_peer", "ticket":ticket}))
                .await?;
            let remembered: RememberPeerData = require_ok_response(response, "remember_peer")?;
            anyhow::ensure!(
                !remembered.added.is_empty()
                    && remembered.added.iter().all(|added| added == node_id),
                "Carrier returned a mismatched collaboration bootstrap"
            );
        }
        let response = self
            .carrier
            .send_raw(&serde_json::json!({
                "op":"gossip_join_exact", "topic":self.topic, "peers":self.bootstrap_node_ids,
            }))
            .await?;
        // A previous caller may have completed its join after its own deadline.
        if response["code"] == "already_joined" {
            return Ok(());
        }
        let joined: JoinExactData = require_ok_response(response, "gossip_join_exact")?;
        anyhow::ensure!(
            joined.topic == self.topic,
            "Carrier returned a mismatched recovery join"
        );
        Ok(())
    }

    async fn topic_peers(&self) -> anyhow::Result<TopicPeersData> {
        let response = self
            .carrier
            .send_raw(&serde_json::json!({
                "op": "list_topic_peers",
                "topic": self.topic,
            }))
            .await
            .context("Carrier peer lookup failed for collaboration network")?;
        require_bounded_response(&response)?;
        let connected: TopicPeersData = require_ok_response(response, "list_topic_peers")?;
        if connected.topic != self.topic {
            anyhow::bail!("Carrier returned a mismatched collaboration topic");
        }
        Ok(connected)
    }

    #[cfg(test)]
    pub(crate) async fn has_remote_peers(&self) -> anyhow::Result<bool> {
        Ok(!self.topic_peers().await?.peers.is_empty())
    }

    async fn local_node_id(&self) -> anyhow::Result<String> {
        let response = self
            .carrier
            .send_raw(&serde_json::json!({ "op": "get_ticket" }))
            .await
            .context("Carrier local endpoint lookup failed for collaboration recovery")?;
        require_bounded_response(&response)?;
        let local: LocalTicketData = require_ok_response(response, "get_ticket")?;
        validate_collaboration_bootstrap_peer(&CollaborationBootstrapPeer {
            node_id: local.node_id.clone(),
            connect_ticket: local.ticket,
        })
        .context("Carrier local endpoint identity is inconsistent")?;
        anyhow::ensure!(
            self.runtime_node_id
                .is_none_or(|id| id.to_string() == local.node_id),
            "Carrier local endpoint identity is inconsistent"
        );
        Ok(local.node_id)
    }

    /// Repair only missing peers from the verified profile. The Runtime owns
    /// the retry cadence; a healthy mesh never receives another Join here.
    pub(crate) async fn restore_missing_bootstrap_peers(&self) -> anyhow::Result<()> {
        if self.pending_join.load(std::sync::atomic::Ordering::Relaxed) {
            anyhow::bail!("not_joined: Community topic is waiting for paced repair");
        }
        if self.bootstrap_node_ids.is_empty() {
            return Ok(());
        }
        let local_node_id = self.local_node_id().await?;
        let connected = self.topic_peers().await?;
        let missing = self
            .bootstrap_node_ids
            .iter()
            .filter(|node_id| *node_id != &local_node_id && !connected.peers.contains(node_id))
            .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(());
        }
        let response = self
            .carrier
            .send_raw(&serde_json::json!({
                "op": "gossip_join_peers",
                "topic": self.topic,
                "peers": missing,
            }))
            .await
            .context("Carrier missing bootstrap join failed for collaboration recovery")?;
        require_bounded_response(&response)?;
        if response["code"] == "not_joined" {
            // A missing sender does not prove that the topic record is absent.
            anyhow::bail!("not_joined: Community topic is waiting for paced repair");
        }
        let joined: JoinExactData = require_ok_response(response, "gossip_join_peers")?;
        if joined.topic != self.topic {
            anyhow::bail!("Carrier returned a mismatched collaboration recovery join");
        }
        Ok(())
    }

    pub(crate) async fn send_gossip(
        &self,
        core: &crate::collaboration_core::CollaborationCore,
        frame: &[u8],
        original: Option<&[u8]>,
    ) -> anyhow::Result<CollaborationCarrierSendOutcome> {
        let allowed = match original {
            Some(original) => core.allows_gossip_receipt(frame, original)?,
            None => core.allows_gossip_frame(frame)?,
        };
        if !allowed {
            anyhow::bail!("this collaboration frame does not travel over gossip");
        }
        self.send_frame(frame).await
    }

    async fn send_frame(&self, frame: &[u8]) -> anyhow::Result<CollaborationCarrierSendOutcome> {
        let message =
            std::str::from_utf8(frame).context("collaboration Carrier frame is not UTF-8")?;
        if frame.len() > MAX_COLLABORATION_TRANSPORT_FRAME_BYTES {
            anyhow::bail!("collaboration Carrier frame exceeds the byte limit");
        }
        let response = self
            .carrier
            .send_raw(&serde_json::json!({
                "op": "gossip_send",
                "topic": self.topic,
                "message": message,
            }))
            .await
            .context("Carrier gossip_send failed for collaboration network")?;
        let response: SendResponse = serde_json::from_value(response)
            .context("malformed Carrier gossip_send response for collaboration network")?;
        if response.status != "ok" {
            anyhow::bail!("Carrier gossip_send rejected the collaboration frame");
        }
        match (response.data.remote_peer_count, response.broadcast) {
            (peer_count, None) if peer_count > 0 => {
                Ok(CollaborationCarrierSendOutcome::RemoteBroadcast { peer_count })
            }
            (_, Some(CarrierBroadcast::LocalOnly)) => {
                Ok(CollaborationCarrierSendOutcome::LocalOnlyBuffered)
            }
            _ => anyhow::bail!("inconsistent Carrier gossip_send collaboration result"),
        }
    }

    pub async fn peek(&self) -> anyhow::Result<CollaborationCarrierReceiveBatch> {
        let response = self
            .carrier
            .send_raw(&serde_json::json!({
                "op": "gossip_peek",
                "topic": self.topic,
                "consumer_id": self.consumer_id,
                "limit": COLLABORATION_RECEIVE_BATCH_SIZE,
            }))
            .await
            .context("Carrier gossip_peek failed for collaboration network")?;
        require_bounded_response(&response)?;
        let data: ReceiveData = require_ok_response(response, "gossip_peek")?;
        let scanned = u64::try_from(data.scanned)
            .context("Carrier gossip_peek scanned count exceeds the cursor range")?;
        if data.limit != COLLABORATION_RECEIVE_BATCH_SIZE
            || data.messages.len() > data.limit
            || data.scanned != data.messages.len()
            || data.next_cursor.checked_sub(data.cursor) != Some(scanned)
        {
            anyhow::bail!("Carrier gossip_peek returned an invalid collaboration batch");
        }

        let mut envelopes = Vec::with_capacity(data.messages.len());
        let mut rejected_frames = 0;
        for frame in data.messages {
            match decode_frame(&frame) {
                Some(envelope) => envelopes.push(envelope),
                None => rejected_frames += 1,
            }
        }
        Ok(CollaborationCarrierReceiveBatch {
            envelopes,
            rejected_frames,
            consumer_id: self.consumer_id.clone(),
            cursor: data.cursor,
            next_cursor: data.next_cursor,
            limit: data.limit,
        })
    }

    pub async fn ack(&self, batch: &CollaborationCarrierReceiveBatch) -> anyhow::Result<()> {
        if batch.consumer_id != self.consumer_id || batch.limit != COLLABORATION_RECEIVE_BATCH_SIZE
        {
            anyhow::bail!("collaboration Carrier batch belongs to another subscription");
        }
        let response = self
            .carrier
            .send_raw(&serde_json::json!({
                "op": "gossip_ack",
                "topic": self.topic,
                "consumer_id": self.consumer_id,
                "cursor": batch.cursor,
                "next_cursor": batch.next_cursor,
            }))
            .await
            .context("Carrier gossip_ack failed for collaboration network")?;
        let data: AckData = require_ok_response(response, "gossip_ack")?;
        if data.cursor != batch.cursor
            || data.next_cursor != batch.next_cursor
            || (data.cursor == data.next_cursor && data.advanced)
        {
            anyhow::bail!("Carrier gossip_ack returned an invalid collaboration range");
        }
        Ok(())
    }
}

/// What the Community link watchdog needs from Carrier.
pub(crate) trait CommunityLink {
    fn record_bootstrap_failure(&self, _reason: Option<&'static str>) {}
    fn bootstrap_failure(&self) -> Option<&'static str> {
        None
    }
    async fn restore_bootstrap(&self) -> anyhow::Result<()> {
        Ok(())
    }
    /// A Home may replace its own actor. A node keeps its actor and restores
    /// only a missing local topic, so existing Homes retain their links.
    async fn recovers_its_link(&self) -> anyhow::Result<bool>;
    fn topic_is_pending(&self) -> bool {
        false
    }
    async fn link_health(&self) -> anyhow::Result<CommunityLinkHealth>;
    fn host_addresses(&self) -> Option<CommunityHostAddresses>;
    /// Leaves the Community topic and joins it again with its bootstrap peers.
    async fn rejoin(&self) -> anyhow::Result<()>;
    /// Replaces Carrier's gossip actor; returns how many topics joined again.
    async fn rebuild_gossip(&self) -> anyhow::Result<usize>;
}

impl CommunityLink for JoinedCollaborationNetwork {
    fn record_bootstrap_failure(&self, reason: Option<&'static str>) {
        *self
            .bootstrap_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = reason;
    }
    fn bootstrap_failure(&self) -> Option<&'static str> {
        *self
            .bootstrap_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn topic_is_pending(&self) -> bool {
        self.pending_join.load(std::sync::atomic::Ordering::Relaxed)
    }
    async fn restore_bootstrap(&self) -> anyhow::Result<()> {
        self.restore_missing_bootstrap_peers().await
    }
    async fn recovers_its_link(&self) -> anyhow::Result<bool> {
        if self.bootstrap_node_ids.is_empty() {
            return Ok(false);
        }
        let local_node_id = match self.runtime_node_id {
            Some(node_id) => node_id.to_string(),
            None => self.local_node_id().await?,
        };
        Ok(!self.bootstrap_node_ids.contains(&local_node_id))
    }

    async fn link_health(&self) -> anyhow::Result<CommunityLinkHealth> {
        let response = self
            .carrier
            .send_raw(&serde_json::json!({
                "op": "gossip_topic_health",
                "topic": self.topic,
            }))
            .await
            .context("Carrier topic health failed for collaboration network")?;
        require_bounded_response(&response)?;
        if response["code"] == "not_joined" {
            // Topic health is authoritative even while a neighbour is remembered.
            // The next paced repair must create the absent subscription.
            self.pending_join
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let health: TopicHealthData = require_ok_response(response, "gossip_topic_health")?;
        if health.topic != self.topic {
            anyhow::bail!("Carrier returned a mismatched collaboration topic health");
        }
        // Only a valid health reply proves that the local topic exists again.
        self.pending_join
            .store(false, std::sync::atomic::Ordering::Relaxed);
        anyhow::ensure!(health.receiver_alive, "Community receiver ended");
        Ok(CommunityLinkHealth {
            peer_count: health.peer_count,
            received_frames: health.received_frames,
        })
    }

    fn host_addresses(&self) -> Option<CommunityHostAddresses> {
        community_host_addresses()
    }

    async fn rejoin(&self) -> anyhow::Result<()> {
        if self.pending_join.load(std::sync::atomic::Ordering::Relaxed) {
            self.restore_absent_topic().await?;
            return Ok(());
        }
        let response = self
            .carrier
            .send_raw(&serde_json::json!({ "op": "gossip_rejoin", "topic": self.topic }))
            .await
            .context("Carrier gossip_rejoin failed for collaboration network")?;
        require_bounded_response(&response)?;
        let joined: JoinExactData = require_ok_response(response, "gossip_rejoin")?;
        if joined.topic != self.topic {
            anyhow::bail!("Carrier returned a mismatched collaboration rejoin");
        }
        Ok(())
    }

    async fn rebuild_gossip(&self) -> anyhow::Result<usize> {
        let response = self
            .carrier
            .send_raw(&serde_json::json!({ "op": "gossip_rebuild" }))
            .await
            .context("Carrier gossip_rebuild failed for collaboration network")?;
        require_bounded_response(&response)?;
        let rebuilt: RebuildData = require_ok_response(response, "gossip_rebuild")?;
        if self.topic_is_pending() {
            // A rebuild restores recorded topics; a missing subscription needs
            // its verified exact join as part of the same paced attempt.
            self.restore_absent_topic().await?;
        }
        Ok(rebuilt.topics)
    }
}

/// Runtime uses the system clock; paused-time fixtures control both clocks.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) enum CommunityWallClock {
    #[default]
    System,
    #[cfg(test)]
    Tokio {
        at: Instant,
        wall_at: std::time::SystemTime,
    },
}

impl CommunityWallClock {
    pub(crate) fn now(self) -> std::time::SystemTime {
        match self {
            Self::System => std::time::SystemTime::now(),
            #[cfg(test)]
            Self::Tokio { at, wall_at } => wall_at + Instant::now().saturating_duration_since(at),
        }
    }
}

/// One Runtime-owned observation supplies both repair and product status.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CommunityRecoveryView {
    pub(crate) connected: bool,
    pub(crate) checked_at: Instant,
    pub(crate) checked_wall_at: std::time::SystemTime,
    pub(crate) wall_clock: CommunityWallClock,
    pub(crate) retry_at: Instant,
    pub(crate) reason: Option<&'static str>,
}

impl Default for CommunityRecoveryView {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            connected: false,
            checked_at: now,
            checked_wall_at: std::time::SystemTime::now(),
            wall_clock: CommunityWallClock::default(),
            retry_at: now,
            reason: Some("starting"),
        }
    }
}

pub(crate) struct CommunityRecoverySnapshot {
    pub(crate) connected: bool,
    pub(crate) state: &'static str,
    pub(crate) detail: String,
    pub(crate) next_retry_seconds: Option<u64>,
}

impl CommunityRecoveryView {
    fn connected_at(&self, now: Instant, wall: std::time::SystemTime) -> bool {
        self.connected
            && now.saturating_duration_since(self.checked_at) <= Duration::from_secs(45)
            && wall
                .duration_since(self.checked_wall_at)
                .is_ok_and(|elapsed| elapsed <= Duration::from_secs(45))
    }

    #[cfg(test)]
    pub(crate) fn connected(&self) -> bool {
        self.connected_at(Instant::now(), self.wall_clock.now())
    }

    pub(crate) fn snapshot(&self) -> CommunityRecoverySnapshot {
        let now = Instant::now();
        let connected = self.connected_at(now, self.wall_clock.now());
        let state = if connected {
            "connected"
        } else if self.reason == Some("starting") {
            "starting"
        } else if self.reason == Some("waiting for Community peers") {
            "waiting_for_peers"
        } else {
            "reconnecting"
        };
        let remaining = self.retry_at.saturating_duration_since(now);
        let next_retry_seconds = if connected || state == "waiting_for_peers" || remaining.is_zero()
        {
            None
        } else {
            Some(
                remaining
                    .as_secs()
                    .saturating_add(u64::from(remaining.subsec_nanos() > 0)),
            )
        };
        let detail = match state {
            "connected" => "Community is connected.".to_string(),
            "starting" => "Home is starting Community. It is checking the link.".to_string(),
            "waiting_for_peers" => "Community is waiting for another Home.".to_string(),
            _ => match next_retry_seconds {
                Some(wait) => {
                    let unit = if wait == 1 { "second" } else { "seconds" };
                    format!("Home is reconnecting to Community. Next check in {wait} {unit}.")
                }
                None => "Home is reconnecting to Community. It is checking the link.".to_string(),
            },
        };
        CommunityRecoverySnapshot {
            connected,
            state,
            detail,
            next_retry_seconds,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommunityLinkStep {
    Rejoin,
    Rebuild,
}

/// Repairs an unhealthy Community link with a topic rejoin followed by actor
/// rebuilds. The per-outage rest doubles to five minutes, then becomes fifteen
/// minutes after six rebuilds. Successful health resets the outage backoff;
/// every repair retains a one-minute rest, including across sleep and leave.
pub(crate) struct CommunityLinkWatchdog {
    silence: Duration,
    no_peers_since: Option<Instant>,
    last_step_at: Option<Instant>,
    steps: u32,
    rebuilds: u32,
    outage_rebuilds: u32,
    addresses: Option<CommunityHostAddresses>,
    address_change: Option<(CommunityHostAddresses, Instant)>,
}

impl CommunityLinkWatchdog {
    pub(crate) fn new(silence: Duration) -> Self {
        Self {
            silence,
            no_peers_since: None,
            last_step_at: None,
            steps: 0,
            rebuilds: 0,
            outage_rebuilds: 0,
            addresses: None,
            address_change: None,
        }
    }

    pub(crate) fn clear_outage(&mut self) {
        self.steps = 0;
        self.outage_rebuilds = 0;
        self.no_peers_since = None;
    }

    pub(crate) fn next_retry(&self, now: Instant) -> Duration {
        let wait = if self.outage_rebuilds >= COMMUNITY_OUTAGE_FAST_REBUILDS {
            COMMUNITY_LONG_OUTAGE_RETRY
        } else {
            self.silence
                .saturating_mul(1 << self.outage_rebuilds.min(8))
                .min(MAX_COMMUNITY_LINK_RETRY)
        };
        let anchor = if self.steps == 0 {
            self.no_peers_since.unwrap_or(now)
        } else {
            self.last_step_at.unwrap_or(now)
        };
        (anchor + wait).saturating_duration_since(now).max(
            self.last_step_at.map_or(Duration::ZERO, |at| {
                (at + self.silence).saturating_duration_since(now)
            }),
        )
    }

    /// Only the caller's verified health observation can clear an outage.
    /// Observation gaps (including sleep) preserve the deadline and retry rest.
    pub(crate) fn observe(
        &mut self,
        health: Option<CommunityLinkHealth>,
        addresses: Option<CommunityHostAddresses>,
        now: Instant,
    ) -> Option<CommunityLinkStep> {
        let healthy = health.is_some_and(|health| health.peer_count > 0);
        let address_changed = self.observe_addresses(addresses, healthy, now);
        if healthy {
            self.clear_outage();
            return None;
        }
        self.no_peers_since.get_or_insert(now);
        let rested = self
            .last_step_at
            .is_none_or(|at| now.duration_since(at) >= self.silence);
        if (!address_changed && !self.next_retry(now).is_zero()) || !rested {
            return None;
        }
        let step = if address_changed || self.steps > 0 {
            self.rebuilds = self.rebuilds.saturating_add(1);
            self.outage_rebuilds = self.outage_rebuilds.saturating_add(1);
            if let Some((addresses, _)) = self.address_change.take() {
                self.addresses = Some(addresses);
            }
            CommunityLinkStep::Rebuild
        } else {
            CommunityLinkStep::Rejoin
        };
        self.steps = self.steps.saturating_add(1);
        self.last_step_at = Some(now);
        Some(step)
    }

    fn observe_addresses(
        &mut self,
        addresses: Option<CommunityHostAddresses>,
        healthy: bool,
        now: Instant,
    ) -> bool {
        let Some(addresses) = addresses else {
            self.address_change = None;
            return false;
        };
        if healthy || addresses.is_empty() || self.addresses.is_none() {
            self.addresses = Some(addresses);
            self.address_change = None;
            return false;
        }
        if self.addresses.as_ref() == Some(&addresses) {
            self.address_change = None;
            return false;
        }
        let (candidate, since) = self
            .address_change
            .get_or_insert_with(|| (addresses.clone(), now));
        if *candidate != addresses {
            *candidate = addresses;
            *since = now;
        }
        now.duration_since(*since) >= COMMUNITY_ADDRESS_STABILITY
    }

    /// Counts the rest before the next step from when this one finished.
    pub(crate) fn step_finished(&mut self, now: Instant) {
        if self.last_step_at.is_some() {
            self.last_step_at = Some(now);
            // A slow repair belongs to this observation window. Its own wait
            // does not mean the Home left Community.
        }
    }
}

#[cfg(test)]
mod recovery_regressions {
    use super::*;

    #[test]
    fn community_recovery_continues_after_120_rebuilds() {
        let start = Instant::now();
        let mut watchdog = CommunityLinkWatchdog::new(COMMUNITY_LINK_SILENCE);
        let mut rebuilds = Vec::new();
        for second in (0..200_000).step_by(5) {
            let now = start + Duration::from_secs(second);
            if let Some(step) = watchdog.observe(None, None, now) {
                if step == CommunityLinkStep::Rebuild {
                    rebuilds.push(second);
                }
                watchdog.step_finished(now);
            }
        }
        assert!(
            rebuilds.len() > 120,
            "repair must continue for unlimited uptime: {}",
            rebuilds.len()
        );
        assert!(rebuilds.windows(2).all(|pair| pair[1] - pair[0] >= 60));
        assert!(rebuilds.last().copied().unwrap() > 190_000);
    }
}

fn random_collaboration_consumer_id() -> anyhow::Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        anyhow::anyhow!("OS entropy unavailable for collaboration consumer: {error}")
    })?;
    Ok(hex::encode(bytes))
}

struct BoundedResponseCounter {
    bytes: usize,
}

impl std::io::Write for BoundedResponseCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(next) = self.bytes.checked_add(bytes.len()) else {
            return Err(std::io::Error::other(
                "collaboration response byte count overflow",
            ));
        };
        if next > MAX_RECEIVE_RESPONSE_BYTES {
            return Err(std::io::Error::other(
                "collaboration response byte limit exceeded",
            ));
        }
        self.bytes = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn require_bounded_response(response: &serde_json::Value) -> anyhow::Result<()> {
    let mut counter = BoundedResponseCounter { bytes: 0 };
    serde_json::to_writer(&mut counter, response)
        .context("Carrier gossip_peek collaboration response exceeds the byte limit")
}

fn collaboration_topic(profile: &VerifiedCollaborationNetworkProfile) -> String {
    // The digest keeps the plaintext network_id out of Carrier topic names. It
    // provides neither secrecy against guessing nor authorization.
    let mut hasher = Sha256::new();
    hasher.update(COLLABORATION_TOPIC_DOMAIN);
    hasher.update(b"\0");
    hasher.update(profile.profile().network_id.as_bytes());
    format!(
        "{COLLABORATION_TOPIC_PREFIX}{}",
        hex::encode(hasher.finalize())
    )
}

fn require_ok_response<T: DeserializeOwned>(
    response: serde_json::Value,
    operation: &str,
) -> anyhow::Result<T> {
    if response["status"] != "ok" {
        // Provider text may contain paths, tickets or keys. Keep only known codes.
        let code = match response["code"].as_str() {
            Some("join_timeout") => "join_timeout",
            Some("join_failed") => "join_failed",
            Some("not_joined") => "not_joined",
            Some("missing_topic") => "missing_topic",
            Some("missing_peers") => "missing_peers",
            Some("recovery_failed") => "recovery_failed",
            Some("recovery_busy") => "recovery_busy",
            Some("recovery_timeout") => "recovery_timeout",
            _ => "provider_rejected",
        };
        anyhow::bail!("Carrier {operation}: {code}");
    }
    let response: CarrierResponse<T> = serde_json::from_value(response)
        .with_context(|| format!("malformed Carrier {operation} collaboration response"))?;
    if response.status != "ok" {
        anyhow::bail!("Carrier {operation} rejected the collaboration operation");
    }
    Ok(response.data)
}

fn decode_frame(frame: &serde_json::Value) -> Option<Vec<u8>> {
    let encoded = frame.as_object()?.get("content")?.as_str()?;
    if encoded.is_empty() || encoded.len() > MAX_COLLABORATION_TRANSPORT_FRAME_BYTES {
        return None;
    }
    let frame = encoded.as_bytes().to_vec();
    verify_collaboration_transport_frame(&frame).ok()?;
    Some(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_addresses(addresses: &[&str]) -> Option<CommunityHostAddresses> {
        Some(
            addresses
                .iter()
                .map(|address| address.parse().unwrap())
                .collect(),
        )
    }

    fn healthy_link() -> Option<CommunityLinkHealth> {
        Some(CommunityLinkHealth {
            peer_count: 1,
            received_frames: 0,
        })
    }

    #[test]
    fn community_link_host_addresses_exclude_link_local_offline_samples() {
        let filtered = |addresses: &[&str]| {
            Some(
                addresses
                    .iter()
                    .map(|address| address.parse::<IpAddr>().unwrap())
                    .filter(is_community_host_address)
                    .collect::<CommunityHostAddresses>(),
            )
        };
        let offline = [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.2",
            "::1",
            "::",
            "fe80::1",
            "febf::1",
        ];
        assert_eq!(filtered(&offline), host_addresses(&[]));
        let online = ["10.0.0.1", "192.0.2.1", "2001:db8::1", "fd00::1"];
        assert_eq!(filtered(&online), host_addresses(&online));

        let mut watchdog = CommunityLinkWatchdog::new(COMMUNITY_LINK_SILENCE);
        let start = Instant::now();
        assert_eq!(
            watchdog.observe(healthy_link(), filtered(&online), start),
            None
        );
        for second in (5..=20).step_by(5) {
            assert_eq!(
                watchdog.observe(
                    None,
                    filtered(&offline),
                    start + Duration::from_secs(second)
                ),
                None
            );
        }
        for second in [25, 30] {
            assert_eq!(
                watchdog.observe(None, filtered(&online), start + Duration::from_secs(second)),
                None
            );
        }
        assert_eq!(
            watchdog.observe(None, filtered(&online), start + Duration::from_secs(35)),
            Some(CommunityLinkStep::Rebuild)
        );
        assert_eq!(
            watchdog.rebuilds, 1,
            "only stable network restoration spends a request"
        );
    }

    #[test]
    fn community_link_watchdog_after_120_rebuilds_backs_off_in_each_new_outage() {
        let mut watchdog = CommunityLinkWatchdog::new(COMMUNITY_LINK_SILENCE);
        watchdog.rebuilds = 120;
        let start = Instant::now();
        for outage_start in [0, 1200] {
            let mut steps = Vec::new();
            for second in (0..=1080).step_by(5) {
                let now = start + Duration::from_secs(outage_start + second);
                if let Some(step) = watchdog.observe(None, None, now) {
                    steps.push((step, second));
                    watchdog.step_finished(now);
                }
            }
            assert_eq!(
                steps,
                [
                    (CommunityLinkStep::Rejoin, 60),
                    (CommunityLinkStep::Rebuild, 120),
                    (CommunityLinkStep::Rebuild, 240),
                    (CommunityLinkStep::Rebuild, 480),
                    (CommunityLinkStep::Rebuild, 780),
                    (CommunityLinkStep::Rebuild, 1080),
                ]
            );
            assert!(watchdog.rebuilds > 120);
            watchdog.observe(
                healthy_link(),
                None,
                start + Duration::from_secs(outage_start + 1085),
            );
        }
    }

    #[test]
    fn community_link_watchdog_address_hint_needs_ten_stable_seconds_and_shared_rest() {
        let mut watchdog = CommunityLinkWatchdog::new(COMMUNITY_LINK_SILENCE);
        let start = Instant::now();
        let observe = |watchdog: &mut CommunityLinkWatchdog, second, addresses| {
            watchdog.observe(None, addresses, start + Duration::from_secs(second))
        };
        assert_eq!(
            watchdog.observe(healthy_link(), host_addresses(&["192.0.2.1"]), start),
            None
        );
        for (second, addresses) in [
            (5, host_addresses(&["192.0.2.2", "2001:db8::1"])),
            (10, host_addresses(&["2001:db8::1", "192.0.2.2"])),
        ] {
            assert_eq!(observe(&mut watchdog, second, addresses), None);
        }
        assert_eq!(
            observe(
                &mut watchdog,
                15,
                host_addresses(&["192.0.2.2", "2001:db8::1"])
            ),
            Some(CommunityLinkStep::Rebuild)
        );
        // A second stable change cannot bypass the rest after this repair.
        watchdog.step_finished(start + Duration::from_secs(20));
        for second in (20..80).step_by(5) {
            assert_eq!(
                observe(&mut watchdog, second, host_addresses(&["192.0.2.3"])),
                None
            );
        }
        assert_eq!(
            observe(&mut watchdog, 80, host_addresses(&["192.0.2.3"])),
            Some(CommunityLinkStep::Rebuild)
        );
        assert_eq!(watchdog.rebuilds, 2);
        assert_eq!(watchdog.outage_rebuilds, 2);
        assert!(watchdog.address_change.is_none());
    }

    #[test]
    fn community_link_watchdog_healthy_churn_seeds_without_a_repair() {
        let mut watchdog = CommunityLinkWatchdog::new(COMMUNITY_LINK_SILENCE);
        let start = Instant::now();
        for second in (0..120).step_by(5) {
            let addresses = host_addresses(&[&format!("192.0.2.{}", second + 1)]);
            assert_eq!(
                watchdog.observe(
                    healthy_link(),
                    addresses,
                    start + Duration::from_secs(second)
                ),
                None
            );
        }
        assert_eq!(watchdog.rebuilds, 0);
        assert!(watchdog.address_change.is_none());
    }

    #[test]
    fn community_link_watchdog_empty_and_unknown_samples_disarm_stability() {
        let mut watchdog = CommunityLinkWatchdog::new(COMMUNITY_LINK_SILENCE);
        let start = Instant::now();
        let samples = [
            (0, host_addresses(&["192.0.2.1"])), // first sample seeds
            (5, host_addresses(&["192.0.2.2"])),
            (10, None), // unknown clears the pending stability window
            (15, host_addresses(&["192.0.2.2"])),
            (20, host_addresses(&[])), // known offline state becomes baseline
            (25, host_addresses(&[])),
            (30, None), // unknown is not an empty-to-nonempty change
            (35, host_addresses(&["192.0.2.1"])),
            (40, host_addresses(&["192.0.2.1"])),
        ];
        for (second, addresses) in samples {
            assert_eq!(
                watchdog.observe(None, addresses, start + Duration::from_secs(second)),
                None
            );
        }
        assert_eq!(
            watchdog.observe(
                None,
                host_addresses(&["192.0.2.1"]),
                start + Duration::from_secs(45)
            ),
            Some(CommunityLinkStep::Rebuild)
        );
        assert_eq!(
            watchdog.rebuilds, 1,
            "only stable restoration consumes a request"
        );
    }

    #[test]
    fn community_link_watchdog_same_ip_and_unknown_hosts_keep_the_timer_fallback() {
        for addresses in [None, host_addresses(&["192.0.2.1"])] {
            let mut watchdog = CommunityLinkWatchdog::new(COMMUNITY_LINK_SILENCE);
            let start = Instant::now();
            let mut steps = Vec::new();
            for second in (0..=240).step_by(5) {
                let now = start + Duration::from_secs(second);
                if let Some(step) = watchdog.observe(None, addresses.clone(), now) {
                    steps.push((step, second));
                    watchdog.step_finished(now);
                }
            }
            assert_eq!(
                steps,
                [
                    (CommunityLinkStep::Rejoin, 60),
                    (CommunityLinkStep::Rebuild, 120),
                    (CommunityLinkStep::Rebuild, 240)
                ]
            );
        }
    }

    #[test]
    fn community_link_watchdog_unstable_address_churn_keeps_the_timer_fallback() {
        let mut watchdog = CommunityLinkWatchdog::new(COMMUNITY_LINK_SILENCE);
        let start = Instant::now();
        let mut steps = Vec::new();
        for second in (0..=240).step_by(5) {
            let now = start + Duration::from_secs(second);
            let addresses = host_addresses(&[&format!("2001:db8::{}", second + 1)]);
            if let Some(step) = watchdog.observe(None, addresses, now) {
                steps.push((step, second));
                watchdog.step_finished(now);
            }
        }
        assert_eq!(
            steps,
            [
                (CommunityLinkStep::Rejoin, 60),
                (CommunityLinkStep::Rebuild, 120),
                (CommunityLinkStep::Rebuild, 240)
            ]
        );
    }

    #[test]
    fn community_link_watchdog_rate_limits_address_and_timer_requests_without_giving_up() {
        let mut watchdog = CommunityLinkWatchdog::new(COMMUNITY_LINK_SILENCE);
        let start = Instant::now();
        let mut repairs = Vec::new();
        for second in (0..=20_000).step_by(5) {
            let now = start + Duration::from_secs(second);
            let addresses = host_addresses(&[&format!("2001:db8::{}", second / 60 + 1)]);
            if let Some(step) = watchdog.observe(None, addresses, now) {
                repairs.push((second, step));
                watchdog.step_finished(now);
            }
        }
        assert!(watchdog.rebuilds > 120);
        assert!(repairs.windows(2).all(|pair| pair[1].0 - pair[0].0 >= 60));
        let count = watchdog.rebuilds;
        watchdog.observe(healthy_link(), None, start + Duration::from_secs(20_005));
        assert_eq!(watchdog.outage_rebuilds, 0);
        // A later outage still gets its own rebuilds.
        for second in (20_600..21_600).step_by(5) {
            let now = start + Duration::from_secs(second);
            if watchdog.observe(None, None, now).is_some() {
                watchdog.step_finished(now);
            }
        }
        assert!(watchdog.rebuilds > count);
    }

    #[test]
    fn community_link_watchdog_pacing_counts_address_attempts_and_saturates() {
        let mut watchdog = CommunityLinkWatchdog::new(COMMUNITY_LINK_SILENCE);
        let start = Instant::now();
        watchdog.observe(None, host_addresses(&[]), start);
        for second in (5..=70).step_by(5) {
            let now = start + Duration::from_secs(second);
            let addresses = host_addresses(&[&format!("192.0.2.{}", second / 15 + 1)]);
            if let Some(step) = watchdog.observe(None, addresses, now) {
                assert_eq!(step, CommunityLinkStep::Rebuild);
                watchdog.step_finished(now);
            }
        }
        assert_eq!(watchdog.outage_rebuilds, 1);
        // Counter saturation keeps a bounded shift and the long-outage wait.
        watchdog.steps = u32::MAX;
        watchdog.outage_rebuilds = u32::MAX;
        let now = start + Duration::from_secs(75);
        assert_eq!(watchdog.observe(None, None, now), None);
        assert_eq!(watchdog.steps, u32::MAX);
    }

    use std::collections::VecDeque;
    use std::sync::Mutex;

    use elastos_runtime::provider::{ProviderError, ResourceRequest, ResourceResponse};
    use elastos_runtime::signature::{generate_keypair, SigningKey};

    use crate::collaboration_network::{
        canonical_collaboration_network_profile_payload_bytes,
        validate_collaboration_network_profile, CollaborationBootstrapPeer,
        CollaborationNetworkProfile, CollaborationNetworkProfileMode,
        SignedCollaborationNetworkProfile, COLLABORATION_NETWORK_PROFILE_SCHEMA,
        COLLABORATION_NETWORK_PROFILE_SIGNATURE_DOMAIN,
    };
    use crate::collaboration_protocol::sign_collaboration_transport_frame;

    enum FakeReply {
        Value(serde_json::Value),
        Error(&'static str),
    }

    struct FakeCarrier {
        requests: Mutex<Vec<serde_json::Value>>,
        replies: Mutex<VecDeque<FakeReply>>,
    }

    impl FakeCarrier {
        fn new(replies: impl IntoIterator<Item = FakeReply>) -> Arc<Self> {
            Arc::new(Self {
                requests: Mutex::new(Vec::new()),
                replies: Mutex::new(replies.into_iter().collect()),
            })
        }

        fn requests(&self) -> Vec<serde_json::Value> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl Provider for FakeCarrier {
        async fn handle(
            &self,
            _request: ResourceRequest,
        ) -> Result<ResourceResponse, ProviderError> {
            Err(ProviderError::Provider(
                "fake Carrier supports raw operations only".to_string(),
            ))
        }

        fn schemes(&self) -> Vec<&'static str> {
            Vec::new()
        }

        fn name(&self) -> &'static str {
            "fake-collaboration-carrier"
        }

        async fn send_raw(
            &self,
            request: &serde_json::Value,
        ) -> Result<serde_json::Value, ProviderError> {
            self.requests.lock().unwrap().push(request.clone());
            match self.replies.lock().unwrap().pop_front() {
                Some(FakeReply::Value(value)) => Ok(value),
                Some(FakeReply::Error(message)) => {
                    Err(ProviderError::Provider(message.to_string()))
                }
                None => Err(ProviderError::Provider(
                    "fake Carrier has no queued response".to_string(),
                )),
            }
        }
    }

    fn ticket_for(secret_byte: u8) -> CollaborationBootstrapPeer {
        let secret = iroh::SecretKey::from_bytes(&[secret_byte; 32]);
        let endpoint = iroh::EndpointAddr::from(secret.public());
        let ticket_json = serde_json::json!({
            "topic": null,
            "endpoints": [endpoint],
        });
        let mut connect_ticket =
            data_encoding::BASE32_NOPAD.encode(&serde_json::to_vec(&ticket_json).unwrap());
        connect_ticket.make_ascii_lowercase();
        CollaborationBootstrapPeer {
            node_id: secret.public().to_string(),
            connect_ticket,
        }
    }

    fn verified_profile(
        signing_key: &SigningKey,
        network_id: &str,
        revision: u64,
        previous: Option<&VerifiedCollaborationNetworkProfile>,
        bootstrap_peers: Vec<CollaborationBootstrapPeer>,
    ) -> VerifiedCollaborationNetworkProfile {
        let signer_did = crate::crypto::encode_signing_key_did(signing_key);
        let payload = CollaborationNetworkProfile {
            schema: COLLABORATION_NETWORK_PROFILE_SCHEMA.to_string(),
            network_id: network_id.to_string(),
            revision,
            previous_profile_sha256: previous.map(|profile| profile.profile_sha256().to_string()),
            signer_did: signer_did.clone(),
            bootstrap_peers,
            default_conversation: None,
        };
        let payload_bytes =
            canonical_collaboration_network_profile_payload_bytes(&payload).unwrap();
        let (signature, envelope_signer) = crate::crypto::domain_separated_sign(
            signing_key,
            COLLABORATION_NETWORK_PROFILE_SIGNATURE_DOMAIN,
            &payload_bytes,
        );
        let envelope = SignedCollaborationNetworkProfile {
            payload,
            signature,
            signer_did: envelope_signer,
        };
        let bytes = serde_json::to_vec(&serde_json::to_value(envelope).unwrap()).unwrap();
        match validate_collaboration_network_profile(
            Some(&bytes),
            network_id,
            &[signer_did],
            previous,
        )
        .unwrap()
        {
            CollaborationNetworkProfileMode::Configured(profile) => profile,
            CollaborationNetworkProfileMode::Isolated => panic!("expected configured profile"),
        }
    }

    fn remember_ok(node_id: &str) -> FakeReply {
        FakeReply::Value(serde_json::json!({
            "status": "ok",
            "data": {"added": [node_id]},
        }))
    }

    fn join_ok(topic: &str) -> FakeReply {
        FakeReply::Value(serde_json::json!({
            "status": "ok",
            "data": {"topic": topic},
        }))
    }

    fn local_ticket(peer: &CollaborationBootstrapPeer) -> FakeReply {
        FakeReply::Value(serde_json::json!({
            "status": "ok",
            "data": {"node_id": peer.node_id, "ticket": peer.connect_ticket},
        }))
    }

    fn topic_peers(topic: &str, peers: &[&str]) -> FakeReply {
        FakeReply::Value(serde_json::json!({
            "status": "ok",
            "data": {"topic": topic, "peers": peers},
        }))
    }

    fn signed_frame(envelope: &[u8]) -> Vec<u8> {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        sign_collaboration_transport_frame(&signing_key, envelope).unwrap()
    }

    fn gossip_frame(envelope: &[u8]) -> serde_json::Value {
        let signed = signed_frame(envelope);
        serde_json::json!({
            "content": std::str::from_utf8(&signed).unwrap(),
        })
    }

    fn peek_ok(cursor: u64, next_cursor: u64, messages: Vec<serde_json::Value>) -> FakeReply {
        let scanned = messages.len();
        FakeReply::Value(serde_json::json!({
            "status": "ok",
            "data": {
                "cursor": cursor,
                "next_cursor": next_cursor,
                "messages": messages,
                "scanned": scanned,
                "limit": COLLABORATION_RECEIVE_BATCH_SIZE,
            },
        }))
    }

    fn ack_ok(cursor: u64, next_cursor: u64, advanced: bool) -> FakeReply {
        FakeReply::Value(serde_json::json!({
            "status": "ok",
            "data": {
                "cursor": cursor,
                "next_cursor": next_cursor,
                "advanced": advanced,
            },
        }))
    }

    #[tokio::test]
    async fn collaboration_carrier_joins_only_verified_profile_peers_in_exact_sequence() {
        let (signing_key, _) = generate_keypair();
        let peer_one = ticket_for(21);
        let peer_two = ticket_for(22);
        let profile = verified_profile(
            &signing_key,
            "collaboration-join-test",
            1,
            None,
            vec![peer_one.clone(), peer_two.clone()],
        );
        let topic = collaboration_topic(&profile);
        let carrier = FakeCarrier::new([
            remember_ok(&peer_one.node_id),
            remember_ok(&peer_two.node_id),
            join_ok(&topic),
        ]);

        let _joined = join_collaboration_network(carrier.clone(), &profile)
            .await
            .unwrap();

        let requests = carrier.requests();
        assert_eq!(
            requests,
            vec![
                serde_json::json!({
                    "op": "remember_peer",
                    "ticket": peer_one.connect_ticket,
                }),
                serde_json::json!({
                    "op": "remember_peer",
                    "ticket": peer_two.connect_ticket,
                }),
                serde_json::json!({
                    "op": "gossip_join_exact",
                    "topic": topic,
                    "peers": [peer_one.node_id, peer_two.node_id],
                }),
            ]
        );
        assert!(requests.iter().all(|request| {
            matches!(
                request["op"].as_str(),
                Some("remember_peer" | "gossip_join_exact")
            )
        }));
    }

    #[tokio::test]
    async fn collaboration_carrier_empty_profile_joins_exact_local_only() {
        let (signing_key, _) = generate_keypair();
        let profile = verified_profile(
            &signing_key,
            "collaboration-empty-test",
            1,
            None,
            Vec::new(),
        );
        let topic = collaboration_topic(&profile);
        let carrier = FakeCarrier::new([join_ok(&topic)]);

        let _joined = join_collaboration_network(carrier.clone(), &profile)
            .await
            .unwrap();

        assert_eq!(
            carrier.requests(),
            vec![serde_json::json!({
                "op": "gossip_join_exact",
                "topic": topic,
                "peers": [],
            })]
        );
    }

    #[tokio::test]
    async fn collaboration_carrier_availability_uses_any_current_topic_peer() {
        let (signer, _) = generate_keypair();
        let bootstrap = ticket_for(20);
        let remaining_peer = ticket_for(21);
        let profile = verified_profile(
            &signer,
            "community-availability",
            1,
            None,
            vec![bootstrap.clone()],
        );
        let topic = collaboration_topic(&profile);
        let carrier = FakeCarrier::new([
            remember_ok(&bootstrap.node_id),
            join_ok(&topic),
            topic_peers(&topic, &[]),
            topic_peers(&topic, &[&remaining_peer.node_id]),
            topic_peers(&topic, &[]),
            topic_peers("foreign-topic", &[&remaining_peer.node_id]),
            FakeReply::Error("unavailable"),
        ]);
        let joined = join_collaboration_network(carrier.clone(), &profile)
            .await
            .unwrap();
        assert!(!joined.has_remote_peers().await.unwrap());
        assert!(joined.has_remote_peers().await.unwrap());
        assert!(!joined.has_remote_peers().await.unwrap());
        assert!(joined.has_remote_peers().await.is_err());
        assert!(joined.has_remote_peers().await.is_err());
        assert_eq!(
            carrier
                .requests()
                .iter()
                .filter(|request| request["op"] == "gossip_join_exact")
                .count(),
            1
        );
        assert!(!carrier
            .requests()
            .iter()
            .any(|request| request["op"] == "gossip_join_peers"));
    }

    #[tokio::test]
    async fn collaboration_carrier_repairs_only_missing_verified_bootstraps() {
        let (signer, _) = generate_keypair();
        let own = ticket_for(20);
        let connected = ticket_for(21);
        let missing = ticket_for(22);
        let unrelated = ticket_for(23);
        let profile = verified_profile(
            &signer,
            "bootstrap-recovery",
            1,
            None,
            vec![own.clone(), connected.clone(), missing.clone()],
        );
        let topic = collaboration_topic(&profile);
        let carrier = FakeCarrier::new([
            remember_ok(&own.node_id),
            remember_ok(&connected.node_id),
            remember_ok(&missing.node_id),
            join_ok(&topic),
            local_ticket(&own),
            topic_peers(&topic, &[&connected.node_id, &unrelated.node_id]),
            join_ok(&topic),
            local_ticket(&own),
            topic_peers(&topic, &[&connected.node_id, &missing.node_id]),
        ]);
        let joined = join_collaboration_network(carrier.clone(), &profile)
            .await
            .unwrap();
        joined.restore_missing_bootstrap_peers().await.unwrap();
        joined.restore_missing_bootstrap_peers().await.unwrap();
        let repair = carrier
            .requests()
            .into_iter()
            .filter(|request| request["op"] == "gossip_join_peers")
            .collect::<Vec<_>>();
        assert_eq!(
            repair,
            [serde_json::json!({
                "op": "gossip_join_peers", "topic": topic, "peers": [missing.node_id],
            })]
        );
    }

    #[tokio::test]
    async fn community_recovery_runtime_key_decides_the_role_without_a_provider_call() {
        let (signer, _) = generate_keypair();
        let bootstrap = ticket_for(71);
        let other = ticket_for(72);
        let profile = verified_profile(&signer, "runtime-role", 1, None, vec![bootstrap.clone()]);
        for (node_id, recovers) in [(&bootstrap.node_id, false), (&other.node_id, true)] {
            let carrier = FakeCarrier::new([]);
            let joined = JoinedCollaborationNetwork::pending(carrier.clone(), &profile)
                .unwrap()
                .with_runtime_node_id(node_id.parse().unwrap());
            assert_eq!(joined.recovers_its_link().await.unwrap(), recovers);
            assert!(carrier.requests().is_empty());
        }
    }

    #[tokio::test]
    async fn community_fix1_missing_sender_does_not_grant_node_topic_repair() {
        let (signer, _) = generate_keypair();
        let own = ticket_for(24);
        let bootstrap = ticket_for(25);
        let profile = verified_profile(&signer, "sender-is-not-topic", 1, None, vec![bootstrap.clone()]);
        let topic = collaboration_topic(&profile);
        let carrier = FakeCarrier::new([
            remember_ok(&bootstrap.node_id),
            join_ok(&topic),
            local_ticket(&own),
            topic_peers(&topic, &[]),
            FakeReply::Value(serde_json::json!({"status":"error", "code":"not_joined", "message":"sender is missing"})),
        ]);
        let joined = join_collaboration_network(carrier.clone(), &profile).await.unwrap();
        assert!(joined.restore_missing_bootstrap_peers().await.is_err());
        assert!(!joined.topic_is_pending(), "only topic health can establish absence");
        assert_eq!(carrier.requests().iter().filter(|request| request["op"] == "gossip_join_exact").count(), 1);
    }

    #[tokio::test]
    async fn collaboration_carrier_retries_missing_bootstrap_after_a_failed_join() {
        let (signer, _) = generate_keypair();
        let own = ticket_for(24);
        let bootstrap = ticket_for(25);
        let profile = verified_profile(&signer, "late-bootstrap", 1, None, vec![bootstrap.clone()]);
        let topic = collaboration_topic(&profile);
        let carrier = FakeCarrier::new([
            remember_ok(&bootstrap.node_id),
            join_ok(&topic),
            local_ticket(&own),
            topic_peers(&topic, &[]),
            FakeReply::Error("offline"),
            local_ticket(&own),
            topic_peers(&topic, &[]),
            join_ok(&topic),
            local_ticket(&own),
            topic_peers(&topic, &[&bootstrap.node_id]),
        ]);
        let joined = join_collaboration_network(carrier.clone(), &profile)
            .await
            .unwrap();
        assert!(joined.restore_missing_bootstrap_peers().await.is_err());
        joined.restore_missing_bootstrap_peers().await.unwrap();
        joined.restore_missing_bootstrap_peers().await.unwrap();
        let repairs = carrier
            .requests()
            .into_iter()
            .filter(|request| request["op"] == "gossip_join_peers")
            .collect::<Vec<_>>();
        assert_eq!(repairs.len(), 2);
        assert!(repairs.iter().all(|request| request["topic"] == topic
            && request["peers"] == serde_json::json!([bootstrap.node_id])));
    }

    #[tokio::test]
    async fn collaboration_carrier_recovery_refuses_mismatched_local_identity_or_topic() {
        let (signer, _) = generate_keypair();
        let own = ticket_for(26);
        let other = ticket_for(27);
        let bootstrap = ticket_for(28);
        let profile = verified_profile(
            &signer,
            "bootstrap-refusal",
            1,
            None,
            vec![bootstrap.clone()],
        );
        let topic = collaboration_topic(&profile);
        for reply in [
            FakeReply::Value(serde_json::json!({"status": "ok", "data": {
                "node_id": other.node_id, "ticket": own.connect_ticket,
            }})),
            FakeReply::Value(serde_json::json!({"status": "ok", "data": {
                "node_id": crate::crypto::encode_signing_key_did(&signer), "ticket": own.connect_ticket,
            }})),
        ] {
            let carrier =
                FakeCarrier::new([remember_ok(&bootstrap.node_id), join_ok(&topic), reply]);
            let joined = join_collaboration_network(carrier.clone(), &profile)
                .await
                .unwrap();
            assert!(joined.restore_missing_bootstrap_peers().await.is_err());
            assert!(!carrier
                .requests()
                .iter()
                .any(|request| request["op"] == "gossip_join_peers"));
        }
        let carrier = FakeCarrier::new([
            remember_ok(&bootstrap.node_id),
            join_ok(&topic),
            local_ticket(&own),
            topic_peers("other-topic", &[]),
        ]);
        let joined = join_collaboration_network(carrier.clone(), &profile)
            .await
            .unwrap();
        assert!(joined.restore_missing_bootstrap_peers().await.is_err());
        assert!(!carrier
            .requests()
            .iter()
            .any(|request| request["op"] == "gossip_join_peers"));
        let carrier = FakeCarrier::new([
            remember_ok(&bootstrap.node_id),
            join_ok(&topic),
            local_ticket(&own),
            topic_peers(&topic, &[]),
            join_ok("other-topic"),
        ]);
        let joined = join_collaboration_network(carrier, &profile).await.unwrap();
        assert!(joined.restore_missing_bootstrap_peers().await.is_err());
    }

    #[test]
    fn collaboration_carrier_topic_is_stable_across_revisions_and_network_separated() {
        let (signing_key, _) = generate_keypair();
        let initial = verified_profile(
            &signing_key,
            "collaboration-topic-test",
            1,
            None,
            Vec::new(),
        );
        let updated = verified_profile(
            &signing_key,
            "collaboration-topic-test",
            2,
            Some(&initial),
            vec![ticket_for(23)],
        );
        let other = verified_profile(
            &signing_key,
            "collaboration-other-test",
            1,
            None,
            Vec::new(),
        );

        let topic = collaboration_topic(&initial);
        assert_eq!(topic, collaboration_topic(&updated));
        assert_ne!(topic, collaboration_topic(&other));
        assert_eq!(topic.len(), COLLABORATION_TOPIC_PREFIX.len() + 64);
        assert!(!topic.contains("collaboration-topic-test"));
        assert!(!topic.contains(initial.profile_sha256()));
    }

    #[tokio::test]
    async fn collaboration_carrier_bootstrap_failures_prevent_exact_join() {
        let (signing_key, _) = generate_keypair();
        let peer = ticket_for(24);
        let profile = verified_profile(
            &signing_key,
            "collaboration-bootstrap-failure",
            1,
            None,
            vec![peer.clone()],
        );
        let cases = [
            vec![FakeReply::Error("remember failed")],
            vec![FakeReply::Value(serde_json::json!({
                "status": "ok",
                "data": {"added": []},
            }))],
            vec![FakeReply::Value(serde_json::json!({
                "status": "ok",
                "data": {"added": [ticket_for(25).node_id]},
            }))],
            vec![FakeReply::Value(serde_json::json!({
                "status": "ok",
                "data": {"added": [peer.node_id], "unexpected": true},
            }))],
        ];

        for replies in cases {
            let carrier = FakeCarrier::new(replies);
            assert!(join_collaboration_network(carrier.clone(), &profile)
                .await
                .is_err());
            let requests = carrier.requests();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0]["op"], "remember_peer");
        }
    }

    #[tokio::test]
    async fn collaboration_carrier_rejects_existing_or_mismatched_exact_join() {
        let (signing_key, _) = generate_keypair();
        let profile = verified_profile(
            &signing_key,
            "collaboration-join-failure",
            1,
            None,
            Vec::new(),
        );
        let topic = collaboration_topic(&profile);
        let responses = [
            FakeReply::Value(serde_json::json!({
                "status": "error",
                "code": "already_joined",
                "message": "already joined",
            })),
            FakeReply::Value(serde_json::json!({
                "status": "ok",
                "data": {"topic": "__elastos_internal/foreign"},
            })),
            FakeReply::Value(serde_json::json!({
                "status": "ok",
                "data": {"topic": topic, "unexpected": true},
            })),
        ];

        for response in responses {
            let carrier = FakeCarrier::new([response]);
            assert!(join_collaboration_network(carrier.clone(), &profile)
                .await
                .is_err());
            assert_eq!(carrier.requests()[0]["op"], "gossip_join_exact");
        }
    }

    #[tokio::test]
    async fn collaboration_carrier_send_preserves_bytes_bounds_and_transport_outcomes() {
        let (signing_key, _) = generate_keypair();
        let profile =
            verified_profile(&signing_key, "collaboration-send-test", 1, None, Vec::new());
        let topic = collaboration_topic(&profile);
        let carrier = FakeCarrier::new([
            join_ok(&topic),
            FakeReply::Value(serde_json::json!({
                "status": "ok",
                "data": {"remote_peer_count": 2},
            })),
            FakeReply::Value(serde_json::json!({
                "status": "ok",
                "broadcast": "local_only",
                "data": {"remote_peer_count": 3},
            })),
            FakeReply::Value(serde_json::json!({
                "status": "ok",
                "data": {"remote_peer_count": 0},
            })),
        ]);
        let joined = join_collaboration_network(carrier.clone(), &profile)
            .await
            .unwrap();
        let envelope = br#"{"frame":"ok"}"#;

        assert_eq!(
            joined.send_frame(envelope).await.unwrap(),
            CollaborationCarrierSendOutcome::RemoteBroadcast { peer_count: 2 }
        );
        assert_eq!(
            joined.send_frame(envelope).await.unwrap(),
            CollaborationCarrierSendOutcome::LocalOnlyBuffered
        );
        let request_count = carrier.requests().len();
        assert!(joined
            .send_frame(&vec![b'x'; MAX_COLLABORATION_TRANSPORT_FRAME_BYTES + 1])
            .await
            .is_err());
        assert_eq!(carrier.requests().len(), request_count);
        assert!(joined.send_frame(envelope).await.is_err());

        for request in &carrier.requests()[1..3] {
            assert_eq!(request["op"], "gossip_send");
            assert_eq!(request["topic"], topic);
            assert_eq!(request["message"].as_str().unwrap().as_bytes(), envelope);
            assert_eq!(request.as_object().unwrap().len(), 3);
        }
    }

    #[tokio::test]
    async fn collaboration_carrier_peek_ack_preserves_exact_ranges() {
        let (signing_key, _) = generate_keypair();
        let profile = verified_profile(&signing_key, "peek-ack-test", 1, None, Vec::new());
        let topic = collaboration_topic(&profile);
        let first_envelope = br#"{"frame":1}"#.to_vec();
        let next_envelope = br#"{"frame":2}"#.to_vec();
        let first_frame = signed_frame(&first_envelope);
        let next_frame = signed_frame(&next_envelope);
        let first_peek = peek_ok(0, 1, vec![gossip_frame(&first_envelope)]);
        let carrier = FakeCarrier::new([
            join_ok(&topic),
            first_peek,
            peek_ok(0, 1, vec![gossip_frame(&first_envelope)]),
            peek_ok(0, 1, vec![gossip_frame(&first_envelope)]),
            ack_ok(0, 1, true),
            ack_ok(0, 1, false),
            peek_ok(1, 2, vec![gossip_frame(&next_envelope)]),
        ]);
        let joined = join_collaboration_network(carrier.clone(), &profile)
            .await
            .unwrap();

        let batch = joined.peek().await.unwrap();
        let repeated = joined.peek().await.unwrap();
        assert_eq!(batch.envelopes(), std::slice::from_ref(&first_frame));
        assert_eq!(repeated.envelopes(), batch.envelopes());
        assert_eq!(repeated.cursor, batch.cursor);
        assert_eq!(repeated.next_cursor, batch.next_cursor);
        assert_eq!(repeated.consumer_id, batch.consumer_id);
        drop(repeated); // Simulated caller crash before durable acceptance.
        let after_append = joined.peek().await.unwrap();
        assert_eq!(after_append.envelopes(), &[first_frame]);
        assert_eq!((after_append.cursor, after_append.next_cursor), (0, 1));

        joined.ack(&batch).await.unwrap();
        joined.ack(&batch).await.unwrap();
        let next = joined.peek().await.unwrap();
        assert_eq!(next.envelopes(), &[next_frame]);
        assert_eq!((next.cursor, next.next_cursor), (1, 2));

        let requests = carrier.requests();
        assert_eq!(
            requests[1..]
                .iter()
                .map(|request| request["op"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "gossip_peek",
                "gossip_peek",
                "gossip_peek",
                "gossip_ack",
                "gossip_ack",
                "gossip_peek",
            ]
        );
        assert!(requests[1..].iter().all(|request| {
            request["consumer_id"].as_str() == Some(joined.consumer_id.as_str())
        }));
    }

    #[tokio::test]
    async fn collaboration_carrier_empty_peek_and_ack_are_exact() {
        let (signing_key, _) = generate_keypair();
        let profile = verified_profile(&signing_key, "empty-peek-test", 1, None, Vec::new());
        let topic = collaboration_topic(&profile);
        let carrier = FakeCarrier::new([
            join_ok(&topic),
            peek_ok(7, 7, Vec::new()),
            ack_ok(7, 7, false),
            peek_ok(7, 7, Vec::new()),
            ack_ok(7, 7, false),
        ]);
        let joined = join_collaboration_network(carrier, &profile).await.unwrap();

        let first = joined.peek().await.unwrap();
        assert!(first.envelopes().is_empty());
        assert_eq!((first.cursor, first.next_cursor), (7, 7));
        joined.ack(&first).await.unwrap();
        let second = joined.peek().await.unwrap();
        assert_eq!((second.cursor, second.next_cursor), (7, 7));
        joined.ack(&second).await.unwrap();
    }

    #[tokio::test]
    async fn collaboration_carrier_consumers_are_random_and_cross_ack_fails_pre_effect() {
        let (signing_key, _) = generate_keypair();
        let profile = verified_profile(&signing_key, "consumer-binding-test", 1, None, Vec::new());
        let topic = collaboration_topic(&profile);
        let first_carrier =
            FakeCarrier::new([join_ok(&topic), peek_ok(0, 1, vec![gossip_frame(b"one")])]);
        let second_carrier = FakeCarrier::new([join_ok(&topic)]);
        let first = join_collaboration_network(first_carrier, &profile)
            .await
            .unwrap();
        let second = join_collaboration_network(second_carrier.clone(), &profile)
            .await
            .unwrap();

        assert_ne!(first.consumer_id, second.consumer_id);
        for consumer_id in [&first.consumer_id, &second.consumer_id] {
            assert_eq!(consumer_id.len(), 32);
            assert!(consumer_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        }
        let foreign_batch = first.peek().await.unwrap();
        assert!(second.ack(&foreign_batch).await.is_err());
        assert_eq!(
            second_carrier.requests().len(),
            1,
            "cross-subscription ack must fail before calling Carrier"
        );
    }

    #[tokio::test]
    async fn collaboration_carrier_peek_counts_invalid_frames_without_metadata_authority() {
        let (signing_key, _) = generate_keypair();
        let profile = verified_profile(&signing_key, "frame-validation-test", 1, None, Vec::new());
        let topic = collaboration_topic(&profile);
        let envelope = br#"{"frame":"valid"}"#.to_vec();
        let oversized = "x".repeat(MAX_COLLABORATION_TRANSPORT_FRAME_BYTES + 1);
        let valid_signed = signed_frame(&envelope);
        let valid_frame = serde_json::json!({
            "content": std::str::from_utf8(&valid_signed).unwrap(),
            "sender_id": {"forged": true},
            "sender_nick": null,
            "signature": "untrusted",
            "ts": "untrusted",
            "nonce": [],
            "sender_session_id": {"untrusted": true},
        });
        let messages = vec![
            valid_frame,
            serde_json::json!({"content": ""}),
            serde_json::json!({
                "content": oversized,
            }),
            serde_json::json!({"sender_id": "missing-content"}),
        ];
        let carrier = FakeCarrier::new([
            join_ok(&topic),
            peek_ok(0, 4, messages.clone()),
            peek_ok(0, 4, messages),
        ]);
        let joined = join_collaboration_network(carrier, &profile).await.unwrap();

        for _ in 0..2 {
            let batch = joined.peek().await.unwrap();
            assert_eq!(batch.envelopes(), std::slice::from_ref(&valid_signed));
            assert_eq!(batch.rejected_frames(), 3);
            assert_eq!((batch.cursor, batch.next_cursor), (0, 4));
        }
    }

    #[tokio::test]
    async fn collaboration_carrier_peek_responses_fail_closed() {
        let (signing_key, _) = generate_keypair();
        let profile = verified_profile(&signing_key, "peek-failure-test", 1, None, Vec::new());
        let topic = collaboration_topic(&profile);
        let too_many = vec![gossip_frame(b"x"); COLLABORATION_RECEIVE_BATCH_SIZE + 1];
        let malformed = [
            serde_json::json!({
                "status":"ok", "data":{
                    "cursor":0, "next_cursor":0, "messages":[], "scanned":0,
                    "limit":COLLABORATION_RECEIVE_BATCH_SIZE, "unexpected":true
                }
            }),
            serde_json::json!({
                "status":"ok", "data":{
                    "cursor":0, "next_cursor":0, "messages":[], "scanned":0,
                    "limit":COLLABORATION_RECEIVE_BATCH_SIZE - 1
                }
            }),
            serde_json::json!({
                "status":"ok", "data":{
                    "cursor":0, "next_cursor":0, "messages":[gossip_frame(b"x")], "scanned":0,
                    "limit":COLLABORATION_RECEIVE_BATCH_SIZE
                }
            }),
            serde_json::json!({
                "status":"ok", "data":{
                    "cursor":0, "next_cursor":COLLABORATION_RECEIVE_BATCH_SIZE + 1,
                    "messages":too_many, "scanned":COLLABORATION_RECEIVE_BATCH_SIZE + 1,
                    "limit":COLLABORATION_RECEIVE_BATCH_SIZE
                }
            }),
            serde_json::json!({
                "status":"ok", "data":{
                    "cursor":9, "next_cursor":8, "messages":[], "scanned":0,
                    "limit":COLLABORATION_RECEIVE_BATCH_SIZE
                }
            }),
            serde_json::json!({
                "status":"ok", "data":{
                    "cursor":u64::MAX, "next_cursor":u64::MAX,
                    "messages":[gossip_frame(b"x")], "scanned":1,
                    "limit":COLLABORATION_RECEIVE_BATCH_SIZE
                }
            }),
            serde_json::json!({
                "status":"ok", "unexpected":true, "data":{
                    "cursor":0, "next_cursor":0, "messages":[], "scanned":0,
                    "limit":COLLABORATION_RECEIVE_BATCH_SIZE
                }
            }),
            serde_json::json!({
                "status":"ok", "data":{
                    "cursor":0, "next_cursor":1,
                    "messages":[{"content":"x".repeat(MAX_RECEIVE_RESPONSE_BYTES)}], "scanned":1,
                    "limit":COLLABORATION_RECEIVE_BATCH_SIZE
                }
            }),
        ];

        for response in malformed {
            let carrier = FakeCarrier::new([join_ok(&topic), FakeReply::Value(response)]);
            let joined = join_collaboration_network(carrier.clone(), &profile)
                .await
                .unwrap();
            assert!(joined.peek().await.is_err());
            assert_eq!(carrier.requests().len(), 2);
            assert_eq!(carrier.requests()[1]["op"], "gossip_peek");
        }

        let carrier = FakeCarrier::new([join_ok(&topic), FakeReply::Error("peek failed")]);
        let joined = join_collaboration_network(carrier, &profile).await.unwrap();
        assert!(joined.peek().await.is_err());
    }

    #[tokio::test]
    async fn collaboration_carrier_ack_responses_fail_closed() {
        let (signing_key, _) = generate_keypair();
        let profile = verified_profile(&signing_key, "ack-failure-test", 1, None, Vec::new());
        let topic = collaboration_topic(&profile);
        let malformed = [
            serde_json::json!({
                "status":"ok", "data":{"cursor":1, "next_cursor":1, "advanced":true}
            }),
            serde_json::json!({
                "status":"ok", "data":{"cursor":0, "next_cursor":2, "advanced":true}
            }),
            serde_json::json!({
                "status":"ok", "data":{
                    "cursor":0, "next_cursor":1, "advanced":true, "unexpected":true
                }
            }),
            serde_json::json!({"status":"error", "data":{}}),
        ];

        for response in malformed {
            let carrier = FakeCarrier::new([
                join_ok(&topic),
                peek_ok(0, 1, vec![gossip_frame(b"x")]),
                FakeReply::Value(response),
            ]);
            let joined = join_collaboration_network(carrier, &profile).await.unwrap();
            let batch = joined.peek().await.unwrap();
            assert!(joined.ack(&batch).await.is_err());
        }

        let empty_advanced = FakeCarrier::new([
            join_ok(&topic),
            peek_ok(4, 4, Vec::new()),
            ack_ok(4, 4, true),
        ]);
        let joined = join_collaboration_network(empty_advanced, &profile)
            .await
            .unwrap();
        let batch = joined.peek().await.unwrap();
        assert!(joined.ack(&batch).await.is_err());

        let provider_error = FakeCarrier::new([
            join_ok(&topic),
            peek_ok(0, 1, vec![gossip_frame(b"x")]),
            FakeReply::Error("ack failed"),
        ]);
        let joined = join_collaboration_network(provider_error, &profile)
            .await
            .unwrap();
        let batch = joined.peek().await.unwrap();
        assert!(joined.ack(&batch).await.is_err());
    }
}

#[cfg(test)]
pub(crate) fn community_core_topic_for_test(
    profile: &crate::collaboration_network::VerifiedCollaborationNetworkProfile,
) -> String {
    collaboration_topic(profile)
}

//! One neighbour that stops reading must not stop the gossip actor.
//!
//! iroh-gossip 0.101.0 dispatches `OutEvent::SendMessage` with
//! `active_send_tx.send(message).await` on a bounded per-peer channel
//! (`SEND_QUEUE_CAP = 64`, net.rs:686). A neighbour whose QUIC stream credit
//! runs out stalls that channel, and a bounded-mpsc `send().await` never
//! returns `Full`, so the single actor loop stops serving every topic. The
//! Community node then keeps its healthy QUIC connections and still admits no
//! new Home. iroh-gossip 0.102.0 replaces the channel with a byte-bounded
//! queue that drops or aborts instead of awaiting.
//!
//! The two assertions are the two symptoms a Community node shows: traffic to
//! the other neighbours keeps flowing, and a fresh join still completes. They
//! run only after the flood completed or stalled with more broadcasts accepted
//! than that stream credit and that channel can hold, which is the load that
//! parks the 0.101.0 actor.

use std::convert::Infallible;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::Bytes;
use futures_lite::StreamExt;
use gossip_rand::rngs::StdRng;
use gossip_rand::SeedableRng;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, TransportAddr};
use iroh_gossip::api::{Event as ApiEvent, GossipReceiver, GossipSender};
use iroh_gossip::net::Gossip;
use iroh_gossip::proto::{
    Command, Config as ProtoConfig, Event as ProtoEvent, InEvent, Message as WireMessage, OutEvent,
    PeerData, State as ProtoState, TopicId,
};
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tokio::time::timeout;

/// Just under the 4096-byte default `max_message_size`, leaving header room.
const PAYLOAD_SIZE: usize = 3800;
/// The per-peer channel that iroh-gossip 0.101.0 awaits on, in messages.
const SEND_QUEUE_CAP: usize = 64;
/// The default QUIC `stream_receive_window` in bytes, which is the credit a
/// neighbour grants on one stream before it reads.
const STREAM_RECEIVE_WINDOW: usize = 1_250_000;
/// The broadcasts that the neighbour's stream credit and the hub's send queue
/// absorb together. A flood that ends at or below this count may never have
/// met a full queue, so it says nothing about the hub.
const PRESSURE_FLOOR: usize = SEND_QUEUE_CAP + STREAM_RECEIVE_WINDOW / PAYLOAD_SIZE;
const FLOOD_MESSAGES: usize = 500;

const PROBE_BUDGET: Duration = Duration::from_secs(15);
const JOIN_BUDGET: Duration = Duration::from_secs(30);
/// iroh-gossip 0.102.0 holds each broadcast for up to 100 ms while the only
/// eager neighbour of its topic is busy (`BROADCAST_WAIT_LIMIT`), so a healthy
/// flood of `FLOOD_MESSAGES` can take up to 50 s.
const FLOOD_BUDGET: Duration = Duration::from_secs(60);
/// Ten of those holds, so a flood that the hub only slows still moves in every
/// sample.
const STALL_SAMPLE: Duration = Duration::from_secs(1);
const QUIET_SAMPLES_IN_A_STALL: u32 = 2;
/// Binding and closing the endpoints, which have no budget of their own. One
/// close takes up to 3 s here.
const UNBUDGETED_MARGIN: Duration = Duration::from_secs(30);
const TEST_DEADLINE: Duration = Duration::from_secs(
    5 * JOIN_BUDGET.as_secs()
        + 2 * PROBE_BUDGET.as_secs()
        + FLOOD_BUDGET.as_secs()
        + UNBUDGETED_MARGIN.as_secs(),
);

#[tokio::test(flavor = "multi_thread")]
async fn a_neighbour_that_stops_reading_leaves_the_actor_serving_other_topics() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();
    let report = timeout(TEST_DEADLINE, serve_others_beside_a_silent_neighbour())
        .await
        .map_err(|_| anyhow!("the test did not finish within {TEST_DEADLINE:?}"))??;
    println!("{report}");
    Ok(())
}

async fn serve_others_beside_a_silent_neighbour() -> Result<String> {
    let flood_topic = TopicId::from_bytes([0xAB; 32]);
    let probe_topic = TopicId::from_bytes([0xCD; 32]);
    let lookup = MemoryLookup::new();

    let silent_endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![iroh_gossip::ALPN.to_vec()])
        .bind()
        .await
        .context("bind the silent neighbour")?;
    let silent_id = silent_endpoint.id();
    lookup.add_endpoint_info(loopback_addr(&silent_endpoint));
    let (went_silent, mut is_silent) = tokio::sync::mpsc::channel(1);
    let mut silent_task = tokio::spawn(run_silent_neighbour(
        silent_endpoint.clone(),
        flood_topic,
        went_silent,
    ));

    let (hub_endpoint, hub, _hub_router) = gossip_node(&lookup).await?;
    let (member_endpoint, member, _member_router) = gossip_node(&lookup).await?;
    let hub_id = hub_endpoint.id();

    let observation = async {
        let member_join = tokio::spawn({
            let member = member.clone();
            async move { member.subscribe_and_join(probe_topic, vec![hub_id]).await }
        });
        let hub_probe = timeout(JOIN_BUDGET, hub.subscribe_and_join(probe_topic, vec![]))
            .await
            .context("the hub did not join the probe topic")??;
        let member_probe = timeout(JOIN_BUDGET, member_join)
            .await
            .context("the member did not join the probe topic")???;
        let (probe_sender, _hub_probe_receiver) = hub_probe.split();
        let (_member_sender, mut member_receiver) = member_probe.split();

        deliver(&probe_sender, &mut member_receiver, b"before the flood")
            .await
            .context("the probe path failed before the flood, so the fixture is wrong")?;

        let (flood_sender, mut flood_receiver) = timeout(
            JOIN_BUDGET,
            hub.subscribe_and_join(flood_topic, vec![silent_id]),
        )
        .await
        .context("the hub did not take the silent neighbour into its active view")??
        .split();
        // Without this the neighbour is still reading, and the flood proves nothing.
        timeout(JOIN_BUDGET, is_silent.recv())
            .await
            .ok()
            .flatten()
            .context("the neighbour never reached the active view, so the fixture is wrong")?;
        tokio::spawn(async move { while flood_receiver.next().await.is_some() {} });
        let flood = flood_until_settled(flood_sender).await?;

        let probe_started = Instant::now();
        let delivery = deliver(&probe_sender, &mut member_receiver, b"during the flood").await;
        let probe_seconds = probe_started.elapsed().as_secs_f32();

        let join_started = Instant::now();
        let (newcomer_endpoint, newcomer, _newcomer_router) = gossip_node(&lookup).await?;
        let fresh_join = timeout(
            JOIN_BUDGET,
            newcomer.subscribe_and_join(probe_topic, vec![hub_id]),
        )
        .await
        .map_err(|_| anyhow!("a fresh join did not complete within {JOIN_BUDGET:?}"))
        .and_then(|joined| joined.map_err(anyhow::Error::from));
        let join_seconds = join_started.elapsed().as_secs_f32();
        newcomer_endpoint.close().await;

        let report = format!(
            "{flood}; delivery to the other neighbour took {probe_seconds:.1} s; \
             the fresh join took {join_seconds:.1} s"
        );
        anyhow::Ok((flood, delivery, fresh_join, report))
    };
    // The neighbour ends only when it fails. A neighbour that lets go of its
    // streams frees a wedged hub, and then both assertions pass.
    let (flood, delivery, fresh_join, report) = tokio::select! {
        biased;
        ended = &mut silent_task => match ended
            .context("the silent neighbour panicked")?
            .context("the silent neighbour failed")? {},
        observed = observation => observed?,
    };

    // A hub that the neighbour frees resumes a parked flood, so stop the flood
    // first.
    let flood_stopped = flood.stop().await;
    silent_task.abort();
    silent_endpoint.close().await;
    member_endpoint.close().await;
    hub_endpoint.close().await;

    flood_stopped?;
    delivery.with_context(|| format!("delivery to the other neighbour stopped: {report}"))?;
    fresh_join.with_context(|| format!("a fresh join stopped: {report}"))?;
    Ok(report)
}

/// A flood that put the hub under pressure. The hub is judged in either state.
enum SettledFlood {
    /// The hub accepted every broadcast.
    Completed,
    /// The hub stopped accepting broadcasts above `PRESSURE_FLOOR`, and the
    /// flood stays parked on the next one.
    Stalled {
        accepted: usize,
        parked: JoinHandle<Result<()>>,
    },
}

/// Broadcasts into a topic whose only neighbour reads nothing, until the flood
/// ends in one of three ways: it completed, it stalled, or the fixture failed.
/// A broadcast error, a panic, and a flood that stays at or below
/// `PRESSURE_FLOOR` are failures of the fixture, so they return the error.
async fn flood_until_settled(sender: GossipSender) -> Result<SettledFlood> {
    let accepted = Arc::new(AtomicUsize::new(0));
    let mut task = tokio::spawn({
        let accepted = accepted.clone();
        async move {
            let payload = Bytes::from(vec![0x5A; PAYLOAD_SIZE]);
            for _ in 0..FLOOD_MESSAGES {
                sender.broadcast(payload.clone()).await?;
                accepted.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        }
    });

    let started = Instant::now();
    let mut last = 0;
    let mut quiet_samples = 0;
    while started.elapsed() < FLOOD_BUDGET {
        if let Ok(ended) = timeout(STALL_SAMPLE, &mut task).await {
            flood_result(ended)?;
            ensure_pressure(accepted.load(Ordering::Relaxed))?;
            return Ok(SettledFlood::Completed);
        }
        let now = accepted.load(Ordering::Relaxed);
        quiet_samples = if now == last { quiet_samples + 1 } else { 0 };
        last = now;
        if now > PRESSURE_FLOOR && quiet_samples >= QUIET_SAMPLES_IN_A_STALL {
            return Ok(SettledFlood::Stalled {
                accepted: now,
                parked: task,
            });
        }
    }
    task.abort();
    ensure_pressure(last)?;
    bail!(
        "the flood neither completed nor stalled within {FLOOD_BUDGET:?}: \
         the hub accepted {last} of {FLOOD_MESSAGES} broadcasts and still accepts more"
    )
}

impl SettledFlood {
    /// Ends a parked flood, and reports what it did if it moved again after
    /// the stall.
    async fn stop(self) -> Result<()> {
        let Self::Stalled { parked, .. } = self else {
            return Ok(());
        };
        parked.abort();
        match parked.await {
            Err(ended) if ended.is_cancelled() => Ok(()),
            ended => flood_result(ended),
        }
    }
}

impl fmt::Display for SettledFlood {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed => write!(f, "the hub accepted all {FLOOD_MESSAGES} flood broadcasts"),
            Self::Stalled { accepted, .. } => write!(
                f,
                "the hub stalled after {accepted} of {FLOOD_MESSAGES} flood broadcasts"
            ),
        }
    }
}

fn flood_result(ended: Result<Result<()>, JoinError>) -> Result<()> {
    ended
        .context("the flood task panicked")?
        .context("a flood broadcast failed")
}

fn ensure_pressure(accepted: usize) -> Result<()> {
    ensure!(
        accepted > PRESSURE_FLOOR,
        "the fixture did not build enough pressure: the flood ended after {accepted} \
         broadcasts, and the silent neighbour's stream credit plus the hub's send queue \
         absorb {PRESSURE_FLOOR}"
    );
    Ok(())
}

async fn gossip_node(lookup: &MemoryLookup) -> Result<(Endpoint, Gossip, Router)> {
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .context("bind a gossip endpoint")?;
    endpoint
        .address_lookup()
        .map_err(|err| anyhow!("{err}"))?
        .add(lookup.clone());
    lookup.add_endpoint_info(loopback_addr(&endpoint));
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let router = Router::builder(endpoint.clone())
        .accept(iroh_gossip::ALPN, gossip.clone())
        .spawn();
    Ok((endpoint, gossip, router))
}

fn loopback_addr(endpoint: &Endpoint) -> EndpointAddr {
    let sockets: Vec<TransportAddr> = endpoint
        .bound_sockets()
        .into_iter()
        .map(|mut socket| {
            if socket.ip().is_unspecified() {
                socket.set_ip(if socket.is_ipv4() {
                    std::net::IpAddr::from([127, 0, 0, 1])
                } else {
                    std::net::IpAddr::from(std::net::Ipv6Addr::LOCALHOST)
                });
            }
            TransportAddr::Ip(socket)
        })
        .collect();
    assert!(!sockets.is_empty(), "endpoint has no bound socket");
    EndpointAddr::from_parts(endpoint.id(), sockets)
}

async fn deliver(
    sender: &GossipSender,
    receiver: &mut GossipReceiver,
    payload: &'static [u8],
) -> Result<()> {
    timeout(PROBE_BUDGET, async {
        sender
            .broadcast(Bytes::from_static(payload))
            .await
            .context("the hub refused the broadcast")?;
        while let Some(event) = receiver.next().await {
            if let Ok(ApiEvent::Received(message)) = event {
                if message.content.as_ref() == payload {
                    return Ok(());
                }
            }
        }
        Err(anyhow!("the event stream ended"))
    })
    .await
    .map_err(|_| anyhow!("no delivery within {PROBE_BUDGET:?}"))?
}

/// Speaks the real membership handshake through the public protocol state, so
/// the hub promotes it into the active view, then holds its streams open and
/// reads nothing. The endpoint driver keeps acknowledging at the transport
/// level, so QUIC stays healthy while the stream credit is never returned.
/// The first connection that fails ends the neighbour with that error.
async fn run_silent_neighbour(
    endpoint: Endpoint,
    topic: TopicId,
    went_silent: tokio::sync::mpsc::Sender<()>,
) -> Result<Infallible> {
    let mut state: ProtoState<EndpointId, StdRng> = ProtoState::new(
        endpoint.id(),
        PeerData::new(Vec::<u8>::new()),
        ProtoConfig::default(),
        StdRng::seed_from_u64(0xB0B),
    );
    state
        .handle(
            InEvent::Command(topic, Command::Join(vec![])),
            tokio::time::Instant::now(),
            None,
        )
        .for_each(drop);
    let state = Arc::new(tokio::sync::Mutex::new(state));

    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let incoming = incoming.context("the silent endpoint closed")?;
                let state = state.clone();
                let went_silent = went_silent.clone();
                connections.spawn(async move {
                    let connection = incoming.await.context("accept a connection")?;
                    let remote = connection.remote_id();
                    go_silent_after_membership(connection, topic, remote, state, went_silent).await
                });
            }
            Some(ended) = connections.join_next() => {
                match ended.context("a silent connection panicked")?? {}
            }
        }
    }
}

async fn go_silent_after_membership(
    connection: Connection,
    topic: TopicId,
    remote: EndpointId,
    state: Arc<tokio::sync::Mutex<ProtoState<EndpointId, StdRng>>>,
    went_silent: tokio::sync::mpsc::Sender<()>,
) -> Result<Infallible> {
    let mut recv = connection.accept_uni().await.context("accept a stream")?;
    // The stream header starts with the bare topic id and has gained fields
    // since 0.101, so match the prefix rather than the whole frame.
    let header = read_frame(&mut recv)
        .await
        .context("read the topic header")?;
    anyhow::ensure!(
        header.starts_with(topic.as_bytes().as_slice()),
        "unexpected topic in the stream header"
    );

    let mut send: Option<SendStream> = None;
    loop {
        let payload = read_frame(&mut recv).await.context("read a frame")?;
        // postcard concatenates struct fields without framing, so the wire
        // message is the 32 topic bytes followed by the frame.
        let mut encoded = Vec::with_capacity(32 + payload.len());
        encoded.extend_from_slice(topic.as_bytes());
        encoded.extend_from_slice(&payload);
        let message: WireMessage<EndpointId> =
            postcard::from_bytes(&encoded).context("decode a gossip message")?;

        let out: Vec<OutEvent<EndpointId>> = state
            .lock()
            .await
            .handle(
                InEvent::RecvMessage(remote, message),
                tokio::time::Instant::now(),
                None,
            )
            .collect();

        let mut in_active_view = false;
        for event in out {
            match event {
                OutEvent::SendMessage(_, message) => {
                    let bytes = postcard::to_stdvec(&message).context("encode a gossip message")?;
                    let stream = match send.as_mut() {
                        Some(stream) => stream,
                        None => {
                            let mut stream =
                                connection.open_uni().await.context("open a stream")?;
                            write_frame(&mut stream, topic.as_bytes()).await?;
                            send.insert(stream)
                        }
                    };
                    write_frame(stream, &bytes[32..]).await?;
                }
                OutEvent::EmitEvent(_, ProtoEvent::NeighborUp(_)) => in_active_view = true,
                _ => {}
            }
        }
        if in_active_view {
            break;
        }
    }

    went_silent.send(()).await.ok();
    std::future::pending().await
}

async fn read_frame(recv: &mut RecvStream) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    recv.read_exact(&mut length).await.context("frame length")?;
    let length = u32::from_be_bytes(length) as usize;
    anyhow::ensure!(
        length <= 1024 * 1024,
        "frame of {length} bytes is too large"
    );
    let mut frame = vec![0u8; length];
    recv.read_exact(&mut frame).await.context("frame body")?;
    Ok(frame)
}

async fn write_frame(send: &mut SendStream, payload: &[u8]) -> Result<()> {
    send.write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .context("frame length")?;
    send.write_all(payload).await.context("frame body")?;
    Ok(())
}

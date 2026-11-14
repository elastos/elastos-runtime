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
//! the other neighbours keeps flowing, and a fresh join still completes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures_lite::StreamExt;
use gossip_rand::rngs::StdRng;
use gossip_rand::SeedableRng;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, TransportAddr};
use iroh_gossip::api::{Event as ApiEvent, GossipReceiver};
use iroh_gossip::net::Gossip;
use iroh_gossip::proto::{
    Command, Config as ProtoConfig, Event as ProtoEvent, InEvent, Message as WireMessage, OutEvent,
    PeerData, State as ProtoState, TopicId,
};
use tokio::time::timeout;

/// Just under the 4096-byte default `max_message_size`, leaving header room.
const PAYLOAD_SIZE: usize = 3800;
/// Enough to exhaust the 1.25 MiB default stream receive window (about 330
/// payloads) and the 64-message send queue, with room to spare.
const FLOOD_MESSAGES: usize = 500;
const PROBE_BUDGET: Duration = Duration::from_secs(15);
const JOIN_BUDGET: Duration = Duration::from_secs(30);

#[tokio::test(flavor = "multi_thread")]
async fn a_neighbour_that_stops_reading_leaves_the_actor_serving_other_topics() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();
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
    let silent_task = tokio::spawn(run_silent_neighbour(
        silent_endpoint.clone(),
        flood_topic,
        went_silent,
    ));

    let (hub_endpoint, hub, _hub_router) = gossip_node(&lookup).await?;
    let (member_endpoint, member, _member_router) = gossip_node(&lookup).await?;
    let hub_id = hub_endpoint.id();

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

    probe_sender
        .broadcast(Bytes::from_static(b"before the flood"))
        .await
        .context("broadcast before the flood")?;
    wait_for(&mut member_receiver, b"before the flood", PROBE_BUDGET)
        .await
        .context("the probe path failed before the flood, so the fixture is wrong")?;

    let flood = timeout(
        JOIN_BUDGET,
        hub.subscribe_and_join(flood_topic, vec![silent_id]),
    )
    .await
    .context("the hub did not take the silent neighbour into its active view")??;
    // Without this the neighbour is still reading, and the flood proves nothing.
    timeout(JOIN_BUDGET, is_silent.recv())
        .await
        .ok()
        .flatten()
        .context("the neighbour never reached the active view, so the fixture is wrong")?;
    let (flood_sender, mut flood_receiver) = flood.split();
    tokio::spawn(async move { while flood_receiver.next().await.is_some() {} });

    // Fire and forget: the flood may stall, and only its collateral matters.
    let sent = Arc::new(AtomicUsize::new(0));
    let flood_task = tokio::spawn({
        let sent = sent.clone();
        async move {
            let payload = Bytes::from(vec![0x5A; PAYLOAD_SIZE]);
            for _ in 0..FLOOD_MESSAGES {
                if flood_sender.broadcast(payload.clone()).await.is_err() {
                    break;
                }
                sent.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    let flooded = wait_until_flood_settles(&flood_task, &sent).await;

    let probe_started = Instant::now();
    let delivery = async {
        probe_sender
            .broadcast(Bytes::from_static(b"during the flood"))
            .await
            .context("broadcast during the flood")?;
        wait_for(&mut member_receiver, b"during the flood", PROBE_BUDGET).await
    }
    .await;
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

    silent_endpoint.close().await;
    flood_task.abort();
    silent_task.abort();
    newcomer_endpoint.close().await;
    member_endpoint.close().await;
    hub_endpoint.close().await;

    let report = format!(
        "{flooded} of {FLOOD_MESSAGES} broadcasts left the hub; \
         delivery to the other neighbour took {probe_seconds:.1} s; \
         the fresh join took {join_seconds:.1} s"
    );
    delivery.with_context(|| format!("delivery to the other neighbour stopped: {report}"))?;
    fresh_join.with_context(|| format!("a fresh join stopped: {report}"))?;
    println!("{report}");
    Ok(())
}

/// Returns the broadcasts the hub accepted once the flood finishes or stops
/// making progress; a stalled flood is the state the assertions run against.
async fn wait_until_flood_settles(
    flood: &tokio::task::JoinHandle<()>,
    sent: &AtomicUsize,
) -> usize {
    let mut last = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let now = sent.load(Ordering::Relaxed);
        if flood.is_finished() || now == last {
            return now;
        }
        last = now;
    }
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

async fn wait_for(receiver: &mut GossipReceiver, expected: &[u8], budget: Duration) -> Result<()> {
    timeout(budget, async {
        while let Some(event) = receiver.next().await {
            if let Ok(ApiEvent::Received(message)) = event {
                if message.content.as_ref() == expected {
                    return Ok(());
                }
            }
        }
        Err(anyhow!("the event stream ended"))
    })
    .await
    .map_err(|_| anyhow!("no delivery within {budget:?}"))?
}

/// Speaks the real membership handshake through the public protocol state, so
/// the hub promotes it into the active view, then holds its streams open and
/// reads nothing. The endpoint driver keeps acknowledging at the transport
/// level, so QUIC stays healthy while the stream credit is never returned.
async fn run_silent_neighbour(
    endpoint: Endpoint,
    topic: TopicId,
    went_silent: tokio::sync::mpsc::Sender<()>,
) -> Result<()> {
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

    while let Some(incoming) = endpoint.accept().await {
        let Ok(connection) = incoming.await else {
            continue;
        };
        let state = state.clone();
        let went_silent = went_silent.clone();
        tokio::spawn(async move {
            let remote = connection.remote_id();
            if let Err(error) =
                go_silent_after_membership(connection, topic, remote, state, went_silent).await
            {
                eprintln!("the silent neighbour stopped: {error:#}");
            }
        });
    }
    Ok(())
}

async fn go_silent_after_membership(
    connection: Connection,
    topic: TopicId,
    remote: EndpointId,
    state: Arc<tokio::sync::Mutex<ProtoState<EndpointId, StdRng>>>,
    went_silent: tokio::sync::mpsc::Sender<()>,
) -> Result<()> {
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
    std::future::pending::<()>().await;
    unreachable!()
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

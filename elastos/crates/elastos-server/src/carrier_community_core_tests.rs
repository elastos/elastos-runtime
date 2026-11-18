//! Real local sockets and the real recovery worker. Only the node's protocol
//! dispatch can pause; its endpoint keeps accepting QUIC. No test is a probe.
use super::*;
use crate::collaboration_network::*;
use crate::collaboration_startup::run_community_core_fixture;
use gossip_rand::{rngs::StdRng, SeedableRng};
use iroh_gossip::proto::Message as WireMessage;
use iroh_gossip::proto::{
    Command, Event, InEvent, OutEvent, PeerData, Scope, State, Timer, TopicId,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::instrument::WithSubscriber;

enum HubInput {
    Connected(
        iroh::EndpointId,
        u64,
        mpsc::Sender<WireMessage<iroh::EndpointId>>,
    ),
    Disconnected(iroh::EndpointId, u64),
    Wire(iroh::EndpointId, u64, WireMessage<iroh::EndpointId>),
    Timer(Timer<iroh::EndpointId>),
    Post(Vec<u8>, oneshot::Sender<()>),
}

struct LocalHub {
    endpoint: Endpoint,
    input: mpsc::Sender<HubInput>,
    stalled: Arc<AtomicBool>,
    accepted: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
    home_shuffle_times: Arc<std::sync::Mutex<std::collections::VecDeque<tokio::time::Instant>>>,
    posts: Arc<std::sync::Mutex<Vec<String>>>,
    traffic: Arc<std::sync::Mutex<std::collections::BTreeMap<String, u64>>>,
    task: tokio::task::JoinHandle<()>,
}

impl LocalHub {
    async fn start(topic: TopicId) -> Self {
        let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .alpns(vec![iroh_gossip::ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let (input, mut receiver) = mpsc::channel(256);
        let stalled = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let home_shuffle_times = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
        let posts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let traffic = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
        let task = tokio::spawn({
            let endpoint = endpoint.clone();
            let input = input.clone();
            let stalled = stalled.clone();
            let accepted = accepted.clone();
            let closed = closed.clone();
            let home_shuffle_times = home_shuffle_times.clone();
            let posts = posts.clone();
            let traffic = traffic.clone();
            async move {
                let mut state: State<iroh::EndpointId, StdRng> = State::new(
                    endpoint.id(),
                    PeerData::new(Vec::new()),
                    Default::default(),
                    StdRng::seed_from_u64(451),
                );
                let mut output =
                    HashMap::<_, (u64, mpsc::Sender<WireMessage<iroh::EndpointId>>)>::new();
                let mut tasks = tokio::task::JoinSet::new();
                let mut events: Vec<_> = state
                    .handle(
                        InEvent::Command(topic, Command::Join(vec![])),
                        tokio::time::Instant::now(),
                        None,
                    )
                    .collect();
                loop {
                    for event in events.drain(..) {
                        match event {
                            OutEvent::SendMessage(peer, message) => {
                                if let Some((_, sender)) = output.get(&peer) {
                                    let _ = sender.try_send(message);
                                }
                            }
                            OutEvent::ScheduleTimer(delay, timer) => {
                                let input = input.clone();
                                tasks.spawn(async move {
                                    tokio::time::sleep(delay).await;
                                    let _ = input.send(HubInput::Timer(timer)).await;
                                });
                            }
                            OutEvent::EmitEvent(_, Event::Received(message)) => {
                                if let Ok(message) =
                                    serde_json::from_slice::<GossipMessage>(&message.content)
                                {
                                    posts.lock().unwrap().push(message.content);
                                }
                            }
                            _ => {}
                        }
                    }
                    let event = tokio::select! {
                        incoming = endpoint.accept() => {
                            let Some(incoming) = incoming else { break; };
                            let input = input.clone();
                            let accepted = accepted.clone();
                            let closed = closed.clone();
                            let traffic = traffic.clone();
                            let home_shuffle_times = home_shuffle_times.clone();
                            tasks.spawn(async move {
                                if let Ok(connection) = incoming.await {
                                    accepted.fetch_add(1, Ordering::SeqCst);
                                    let peer = connection.remote_id();
                                    let id = connection.stable_id() as u64;
                                    let _ = serve_connection(connection, topic, input.clone(), traffic, home_shuffle_times).await;
                                    closed.fetch_add(1, Ordering::SeqCst);
                                    let _ = input.send(HubInput::Disconnected(peer,id)).await;
                                }
                            });
                            continue;
                        }
                        Some(_) = tasks.join_next() => continue,
                        event = receiver.recv() => {
                            let Some(event) = event else { break; };
                            match event {
                                HubInput::Connected(peer,id,sender) => { output.insert(peer, (id,sender)); continue; }
                                HubInput::Disconnected(peer,id) => {
                                    if output.get(&peer).is_none_or(|current|current.0!=id){continue;}
                                    output.remove(&peer); InEvent::PeerDisconnected(peer)
                                }
                                HubInput::Wire(peer,id,message) => {
                                    if output.get(&peer).is_none_or(|current|current.0!=id){continue;}
                                    if stalled.load(Ordering::SeqCst) { continue; }
                                    InEvent::RecvMessage(peer, message)
                                }
                                HubInput::Timer(timer) => {
                                    if stalled.load(Ordering::SeqCst) { continue; }
                                    InEvent::TimerExpired(timer)
                                }
                                HubInput::Post(bytes, reply) => {
                                    let _ = reply.send(());
                                    InEvent::Command(topic, Command::Broadcast(bytes.into(), Scope::Swarm))
                                }
                            }
                        }
                    };
                    events = state
                        .handle(event, tokio::time::Instant::now(), None)
                        .collect();
                }
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
            }
        });
        Self {
            endpoint,
            input,
            stalled,
            accepted,
            closed,
            home_shuffle_times,
            posts,
            traffic,
            task,
        }
    }

    fn bootstrap(&self) -> CollaborationBootstrapPeer {
        let addresses = self
            .endpoint
            .bound_sockets()
            .into_iter()
            .filter(|a| a.is_ipv4())
            .map(|mut a| {
                a.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
                iroh::TransportAddr::Ip(a)
            })
            .collect::<Vec<_>>();
        let endpoint = iroh::EndpointAddr::from_parts(self.endpoint.id(), addresses);
        let bytes =
            serde_json::to_vec(&serde_json::json!({"topic":null,"endpoints":[endpoint]})).unwrap();
        CollaborationBootstrapPeer {
            node_id: self.endpoint.id().to_string(),
            connect_ticket: data_encoding::BASE32_NOPAD
                .encode(&bytes)
                .to_ascii_lowercase(),
        }
    }

    async fn post(&self, text: &str) {
        let bytes = serde_json::to_vec(&GossipMessage {
            sender_id: self.endpoint.id().to_string(),
            sender_nick: "Local test node".into(),
            content: text.into(),
            ts: 1,
            nonce: random_gossip_nonce(),
            signature: None,
            sender_session_id: None,
        })
        .unwrap();
        let (reply, received) = oneshot::channel();
        self.input.send(HubInput::Post(bytes, reply)).await.unwrap();
        received.await.unwrap();
    }

    async fn shutdown(self) {
        self.endpoint.close().await;
        self.task.abort();
        let _ = self.task.await;
    }
}

async fn serve_connection(
    connection: iroh::endpoint::Connection,
    topic: TopicId,
    input: mpsc::Sender<HubInput>,
    traffic: Arc<std::sync::Mutex<std::collections::BTreeMap<String, u64>>>,
    home_shuffle_times: Arc<std::sync::Mutex<std::collections::VecDeque<tokio::time::Instant>>>,
) -> Result<()> {
    let peer = connection.remote_id();
    let id = connection.stable_id() as u64;
    let (output, mut messages) = mpsc::channel::<WireMessage<iroh::EndpointId>>(64);
    input.send(HubInput::Connected(peer, id, output)).await?;
    let mut send = connection.open_uni().await?;
    write_frame(&mut send, topic.as_bytes()).await?;
    let mut recv = connection.accept_uni().await?;
    anyhow::ensure!(
        read_frame(&mut recv, 512)
            .await?
            .starts_with(topic.as_bytes()),
        "fixture topic mismatch"
    );
    loop {
        tokio::select! {
            frame = read_frame(&mut recv,GOSSIP_WIRE_MESSAGE_MAX_BYTES+256) => {
                let mut bytes = topic.as_bytes().to_vec(); bytes.extend_from_slice(&frame?);
                let message: WireMessage<iroh::EndpointId> = postcard::from_bytes(&bytes)?;
                if count_wire(&traffic, "from_home", &message) == "from_home:Swarm:Shuffle" {
                    let mut times = home_shuffle_times.lock().unwrap();
                    if times.len() == 64 { times.pop_front(); }
                    times.push_back(tokio::time::Instant::now());
                }
                input.send(HubInput::Wire(peer,id,message)).await?;
            }
            Some(message) = messages.recv() => {
                let bytes = postcard::to_stdvec(&message)?;
                write_frame(&mut send,&bytes[32..]).await?;
                count_wire(&traffic, "to_home", &message);
            }
        }
    }
}

fn profile(bootstrap: CollaborationBootstrapPeer) -> VerifiedCollaborationNetworkProfile {
    let (key, _) = elastos_identity::derive_did(&[145; 32]);
    let did = crate::crypto::encode_signing_key_did(&key);
    let payload = CollaborationNetworkProfile {
        schema: COLLABORATION_NETWORK_PROFILE_SCHEMA.into(),
        network_id: "test.451.automatic".into(),
        revision: 1,
        previous_profile_sha256: None,
        signer_did: did.clone(),
        bootstrap_peers: vec![bootstrap],
        default_conversation: None,
    };
    let bytes = canonical_collaboration_network_profile_payload_bytes(&payload).unwrap();
    let (signature, signer_did) = crate::crypto::domain_separated_sign(
        &key,
        COLLABORATION_NETWORK_PROFILE_SIGNATURE_DOMAIN,
        &bytes,
    );
    let bytes = serde_json::to_vec(
        &serde_json::to_value(SignedCollaborationNetworkProfile {
            payload,
            signature,
            signer_did,
        })
        .unwrap(),
    )
    .unwrap();
    match validate_collaboration_network_profile(Some(&bytes), "test.451.automatic", &[did], None)
        .unwrap()
    {
        CollaborationNetworkProfileMode::Configured(profile) => profile,
        _ => panic!("local signed fixture profile"),
    }
}

// Framing belongs only to the local fixture node. Home sends exactly the
// library's normal traffic; there is no health endpoint, token or extra dial.
async fn write_frame(send: &mut iroh::endpoint::SendStream, bytes: &[u8]) -> Result<()> {
    anyhow::ensure!(
        bytes.len() <= GOSSIP_WIRE_MESSAGE_MAX_BYTES + 256,
        "fixture frame limit"
    );
    send.write_all(&u32::try_from(bytes.len())?.to_be_bytes())
        .await?;
    send.write_all(bytes).await?;
    Ok(())
}
async fn read_frame(recv: &mut iroh::endpoint::RecvStream, max: usize) -> Result<Vec<u8>> {
    let mut length = [0; 4];
    recv.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    anyhow::ensure!(length <= max, "fixture frame limit");
    let mut bytes = vec![0; length];
    recv.read_exact(&mut bytes).await?;
    Ok(bytes)
}
fn count_wire(
    traffic: &std::sync::Mutex<std::collections::BTreeMap<String, u64>>,
    direction: &str,
    message: &WireMessage<iroh::EndpointId>,
) -> String {
    let value = serde_json::to_value(message).unwrap();
    let outer = value["message"].as_object().unwrap().iter().next().unwrap();
    let inner = outer
        .1
        .as_object()
        .and_then(|m| m.keys().next())
        .map(String::as_str)
        .or_else(|| outer.1.as_str())
        .unwrap_or("other");
    let key = format!("{direction}:{}:{inner}", outer.0);
    *traffic.lock().unwrap().entry(key.clone()).or_default() += 1;
    key
}

#[derive(Default)]
struct Faults {
    join_fails: AtomicBool,
    cached_peer: AtomicBool,
    health_fails: AtomicBool,
    repairs: AtomicUsize,
}
struct FaultProvider {
    real: Arc<CarrierGossipProvider>,
    faults: Arc<Faults>,
}
#[async_trait::async_trait]
impl Provider for FaultProvider {
    fn name(&self) -> &'static str {
        "core-local-fault-fixture"
    }
    fn schemes(&self) -> Vec<&'static str> {
        vec!["peer"]
    }
    async fn handle(
        &self,
        request: ResourceRequest,
    ) -> std::result::Result<ResourceResponse, ProviderError> {
        self.real.handle(request).await
    }
    async fn send_raw(
        &self,
        request: &serde_json::Value,
    ) -> std::result::Result<serde_json::Value, ProviderError> {
        let op = request["op"].as_str().unwrap_or_default();
        if op == "gossip_join_peers" && self.faults.join_fails.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            return Ok(
                serde_json::json!({"status":"error","code":"join_timeout","message":"private-fixture-sentinel"}),
            );
        }
        if op == "gossip_topic_health" && self.faults.health_fails.load(Ordering::SeqCst) {
            return Err(ProviderError::Provider(
                "private-fixture-sentinel health failure".into(),
            ));
        }
        if matches!(op, "gossip_rejoin" | "gossip_rebuild") {
            self.faults.repairs.fetch_add(1, Ordering::SeqCst);
        }
        let mut response = self.real.send_raw(request).await?;
        if op == "list_topic_peers" && self.faults.join_fails.load(Ordering::SeqCst) {
            response["data"]["peers"] = serde_json::json!([]);
        }
        if op == "gossip_topic_health" && self.faults.cached_peer.load(Ordering::SeqCst) {
            response["data"]["peer_count"] = serde_json::json!(1);
        }
        Ok(response)
    }
}
#[derive(Clone)]
struct LogWriter(Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
struct Fixture {
    _root: tempfile::TempDir,
    home: CarrierNode,
    hub: LocalHub,
    provider: Arc<CarrierGossipProvider>,
    faults: Arc<Faults>,
    topic: String,
    connected: Arc<AtomicBool>,
    disconnected: Arc<AtomicUsize>,
    shutdown: watch::Sender<bool>,
    logs: Arc<std::sync::Mutex<Vec<u8>>>,
    worker: tokio::task::JoinHandle<()>,
}
async fn wait_for(test: impl Fn() -> bool, seconds: u64) -> bool {
    tokio::time::timeout(Duration::from_secs(seconds), async {
        while !test() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}
impl Fixture {
    async fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        let placeholder = SecretKey::from_bytes(&[146; 32]);
        let addr = iroh::EndpointAddr::from_parts(
            placeholder.public(),
            [iroh::TransportAddr::Ip("127.0.0.1:12345".parse().unwrap())],
        );
        let ticket = data_encoding::BASE32_NOPAD
            .encode(
                &serde_json::to_vec(&serde_json::json!({"topic":null,"endpoints":[addr]})).unwrap(),
            )
            .to_ascii_lowercase();
        let p = profile(CollaborationBootstrapPeer {
            node_id: placeholder.public().to_string(),
            connect_ticket: ticket,
        });
        let topic = crate::collaboration_carrier::community_core_topic_for_test(&p);
        let hub = LocalHub::start(topic_hash(&topic)).await;
        let (key, did) = elastos_identity::derive_did(&[147; 32]);
        let home = start_isolated_carrier_node_with_registry(&key, &did, root.path().into(), None)
            .await
            .unwrap();
        let provider = Arc::new(CarrierGossipProvider::new(home.gossip_state.clone()));
        let faults = Arc::new(Faults::default());
        let wrapped = Arc::new(FaultProvider {
            real: provider.clone(),
            faults: faults.clone(),
        });
        let link = crate::collaboration_carrier::join_collaboration_network(
            wrapped,
            &profile(hub.bootstrap()),
        )
        .await
        .unwrap();
        let connected = Arc::new(AtomicBool::new(false));
        let disconnected = Arc::new(AtomicUsize::new(0));
        let (shutdown, rx) = watch::channel(false);
        let logs = Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || LogWriter(writer.clone()))
            .finish();
        let worker = tokio::spawn({
            let connected = connected.clone();
            let disconnected = disconnected.clone();
            async move {
                let connected_once = AtomicBool::new(false);
                run_community_core_fixture(rx, &link, |state| {
                    if state {
                        connected_once.store(true, Ordering::SeqCst);
                    } else if connected_once.load(Ordering::SeqCst) {
                        disconnected.fetch_add(1, Ordering::SeqCst);
                    }
                    connected.store(state, Ordering::SeqCst);
                })
                .with_subscriber(subscriber)
                .await;
            }
        });
        assert!(
            wait_for(|| connected.load(Ordering::SeqCst), 50).await,
            "initial local join"
        );
        Self {
            _root: root,
            home,
            hub,
            provider,
            faults,
            topic,
            connected,
            disconnected,
            shutdown,
            logs,
            worker,
        }
    }
    async fn exchange(&self, event: &str) -> Result<()> {
        let outward = format!("fresh Home to node after {event}");
        let result = self
            .provider
            .send_raw(&serde_json::json!({"op":"gossip_send","topic":self.topic,"message":outward}))
            .await?;
        anyhow::ensure!(result["status"] == "ok", "fresh outward send");
        anyhow::ensure!(
            wait_for(|| self.hub.posts.lock().unwrap().contains(&outward), 15).await,
            "fresh outward exact text"
        );
        let inward = format!("fresh node to Home after {event}");
        self.hub.post(&inward).await;
        tokio::time::timeout(Duration::from_secs(15),async {
            loop {
                let r=self.provider.send_raw(&serde_json::json!({"op":"gossip_recv","topic":self.topic,"consumer_id":"core-exact-text","limit":32})).await?;
                if r["data"]["messages"].as_array().unwrap().iter().any(|m|m["content"]==inward){return Ok::<(),anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.context("fresh inward deadline")??;
        Ok(())
    }
    async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = self.worker.await;
        self.hub.shutdown().await;
        self.home.shutdown().await;
    }
}

#[tokio::test]
async fn community_core_real_join_failures_override_a_remembered_peer_then_node_returns() {
    let f = Fixture::start().await;
    f.exchange("initial join").await.unwrap();
    f.hub.stalled.store(true, Ordering::SeqCst);
    f.faults.cached_peer.store(true, Ordering::SeqCst);
    f.faults.join_fails.store(true, Ordering::SeqCst);
    let repaired = wait_for(|| f.faults.repairs.load(Ordering::SeqCst) > 0, 100).await;
    let honest = !f.connected.load(Ordering::SeqCst);
    f.hub.stalled.store(false, Ordering::SeqCst);
    f.faults.join_fails.store(false, Ordering::SeqCst);
    f.faults.cached_peer.store(false, Ordering::SeqCst);
    let healthy = wait_for(|| f.connected.load(Ordering::SeqCst), 40).await;
    let posts = f
        .exchange("remembered neighbour, local join timeouts and node return")
        .await;
    f.stop().await;
    assert!(
        repaired,
        "local failures start repair despite remembered peer"
    );
    assert!(honest, "status reconnects while local failures last");
    assert!(healthy);
    posts.unwrap();
}

#[tokio::test]
async fn community_core_real_ended_receiver_repairs_and_delivers_exact_text() {
    let f = Fixture::start().await;
    f.exchange("initial receiver").await.unwrap();
    f.home.gossip_state.lock().await.receiver_tasks[&f.topic].abort();
    let repaired = wait_for(|| f.faults.repairs.load(Ordering::SeqCst) > 0, 100).await;
    let healthy = wait_for(|| f.connected.load(Ordering::SeqCst), 40).await;
    let posts = f.exchange("ended receiver recovery").await;
    f.stop().await;
    assert!(repaired, "ended receiver overrides cached peer");
    assert!(healthy);
    posts.unwrap();
}

#[tokio::test]
async fn community_core_real_more_than_120_rebuilds_release_owned_resources() {
    let f = Fixture::start().await;
    f.exchange("initial actor").await.unwrap();
    let mut watchdog =
        crate::collaboration_carrier::CommunityLinkWatchdog::new(Duration::from_secs(60));
    let start = tokio::time::Instant::now();
    let mut rebuilt = 0;
    let expected_lookups = f.home.endpoint.address_lookup().unwrap().len();
    let before_sockets = open_socket_count(std::env::consts::OS);
    for n in 0..124 {
        let now = start + Duration::from_secs(n * 900);
        if let Some(step) = watchdog.observe(None, None, now) {
            let (old_actor, old_receivers) = {
                let state = f.home.gossip_state.lock().await;
                (
                    state.gossip.clone(),
                    state
                        .receiver_tasks
                        .values()
                        .map(|task| task.abort_handle())
                        .collect::<Vec<_>>(),
                )
            };
            match step {
                crate::collaboration_carrier::CommunityLinkStep::Rejoin => {
                    f.provider
                        .send_raw(&serde_json::json!({"op":"gossip_rejoin","topic":f.topic}))
                        .await
                        .unwrap();
                }
                crate::collaboration_carrier::CommunityLinkStep::Rebuild => {
                    let r = f
                        .provider
                        .send_raw(&serde_json::json!({"op":"gossip_rebuild"}))
                        .await
                        .unwrap();
                    assert_eq!(r["status"], "ok");
                    rebuilt += 1;
                }
            }
            if step == crate::collaboration_carrier::CommunityLinkStep::Rebuild {
                assert!(
                    old_receivers.iter().all(|task| task.is_finished()),
                    "old receivers are joined before rebuild returns"
                );
                let stopped = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        match old_actor.subscribe(topic_hash(&f.topic), Vec::new()).await {
                            Err(_) => break,
                            Ok(local) => drop(local),
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await;
                assert!(
                    stopped.is_ok(),
                    "the retired actor closes its local control channel within its shutdown bound"
                );
            }
            watchdog.step_finished(now);
        }
    }
    let (lookups, receivers, senders) = {
        let s = f.home.gossip_state.lock().await;
        (
            s.endpoint.address_lookup().unwrap().len(),
            s.receiver_tasks.len(),
            s.senders.len(),
        )
    };
    // Subscribing creates the local channel before asynchronous peer admission.
    // Wait for the new receiver's neighbour, as the product does before Send;
    // the exact posts below remain the proof that the recovered path works.
    let ready = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let health = f
                .provider
                .send_raw(&serde_json::json!({"op":"gossip_topic_health","topic":f.topic}))
                .await
                .unwrap();
            if health["data"]["peer_count"].as_u64().unwrap_or(0) > 0
                && health["data"]["receiver_alive"] == true
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let posts = if ready.is_ok() {
        f.exchange("more than120 actual actor replacements").await
    } else {
        Err(anyhow::anyhow!(
            "new actor did not admit its neighbour within30seconds"
        ))
    };
    let connections_closed = wait_for(
        || {
            f.hub
                .accepted
                .load(Ordering::SeqCst)
                .saturating_sub(f.hub.closed.load(Ordering::SeqCst))
                == 1
        },
        20,
    )
    .await;
    let after_sockets = open_socket_count(std::env::consts::OS);
    f.stop().await;
    posts.unwrap();
    assert!(
        connections_closed,
        "only the current gossip connection remains"
    );
    if let (Some(before), Some(after)) = (before_sockets, after_sockets) {
        assert!(
            after <= before,
            "socket descriptors stay bounded: {before} -> {after}"
        );
    }
    assert!(rebuilt > 120, "rebuilds continue:{rebuilt}");
    assert_eq!(
        (lookups, receivers, senders),
        (expected_lookups, 1, 1),
        "owned state stays bounded"
    );
}

#[tokio::test]
#[ignore = "1001-second production-timer and wire-count proof; run explicitly on local-only Linux"]
async fn community_core_real_quiet_wire_counts_and_status() {
    let f = Fixture::start().await;
    f.exchange("quiet interval start").await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let connections = f.hub.accepted.load(Ordering::SeqCst);
    let before = f.hub.traffic.lock().unwrap().clone();
    let disconnected = f.disconnected.load(Ordering::SeqCst);
    let outcome = async {
        for _ in 0..1001 {
            assert!(f.connected.load(Ordering::SeqCst));
            assert_eq!(f.disconnected.load(Ordering::SeqCst), disconnected);
            assert_eq!(f.faults.repairs.load(Ordering::SeqCst), 0);
            assert_eq!(f.hub.accepted.load(Ordering::SeqCst), connections);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let mut traffic = f.hub.traffic.lock().unwrap().clone();
    for (key, count) in before {
        *traffic.entry(key).or_default() -= count;
    }
    let shuffle_times = f
        .hub
        .home_shuffle_times
        .lock()
        .unwrap()
        .iter()
        .copied()
        .collect::<Vec<_>>();
    // The pinned HyParView backs off through 1, 2, 4, 8, 16, 32 seconds, then
    // schedules 60 seconds with 25% jitter. After the first six sends, every
    // interval is 45..75 seconds. One second covers local scheduling variance;
    // any added Shuffle between normal sends would violate the lower bound.
    let shuffle_gaps_ms = shuffle_times
        .windows(2)
        .skip(6)
        .map(|p| p[1].duration_since(p[0]).as_millis())
        .collect::<Vec<_>>();
    assert!(
        !shuffle_gaps_ms.is_empty(),
        "the production shuffle timer ran"
    );
    assert!(
        shuffle_gaps_ms
            .iter()
            .all(|gap| (44_000..=76_000).contains(gap)),
        "healthy peer-message cadence stays at the pinned protocol interval"
    );
    let report = serde_json::json!({"connections_before":connections,"connections_after":f.hub.accepted.load(Ordering::SeqCst),"quiet_traffic":traffic,"home_shuffle_gaps_ms":shuffle_gaps_ms,"repairs":f.faults.repairs.load(Ordering::SeqCst),"disconnected_views":f.disconnected.load(Ordering::SeqCst)-disconnected});
    if let Ok(path) = std::env::var("COMMUNITY_CORE_QUIET_BASELINE") {
        compare_develop_wire(&report, &path);
    }
    if let Ok(path) = std::env::var("COMMUNITY_CORE_QUIET_RECEIPT") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    println!("COMMUNITY_CORE_QUIET_METRICS={report}");
    let posts = f.exchange("1001-second quiet interval").await;
    f.stop().await;
    outcome.unwrap();
    posts.unwrap();
}

#[tokio::test]
async fn community_core_real_log_rate_keeps_the_reason_without_private_text() {
    let f = Fixture::start().await;
    f.exchange("log-rate initial join").await.unwrap();
    f.logs.lock().unwrap().clear();
    f.faults.cached_peer.store(true, Ordering::SeqCst);
    f.faults.join_fails.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(10)).await;
    let logs = String::from_utf8(f.logs.lock().unwrap().clone()).unwrap();
    f.faults.join_fails.store(false, Ordering::SeqCst);
    f.faults.cached_peer.store(false, Ordering::SeqCst);
    let healthy = wait_for(|| f.connected.load(Ordering::SeqCst), 15).await;
    let posts = f.exchange("paced failure reason").await;
    f.stop().await;
    assert!(healthy);
    posts.unwrap();
    let warnings = logs.lines().filter(|l| l.contains("WARN")).count();
    assert!(
        warnings <= 1,
        "unchanged failure logs once in ten seconds, got{warnings}:{logs}"
    );
    assert!(
        logs.contains("bootstrap join timed out"),
        "bounded reason retained:{logs}"
    );
    assert!(!logs.contains("private-fixture-sentinel"));
    assert!(logs.lines().all(|line| line.len() < 256));
}

fn open_socket_count(platform: &str) -> Option<usize> {
    if platform != "linux" {
        return None;
    }
    Some(
        std::fs::read_dir("/proc/self/fd")
            .ok()?
            .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
            .filter(|target| target.to_string_lossy().starts_with("socket:"))
            .count(),
    )
}

#[tokio::test]
async fn community_core_real_health_query_failures_repair_despite_a_remembered_peer() {
    let f = Fixture::start().await;
    f.exchange("initial health query").await.unwrap();
    f.faults.cached_peer.store(true, Ordering::SeqCst);
    f.faults.health_fails.store(true, Ordering::SeqCst);
    let repaired = wait_for(|| f.faults.repairs.load(Ordering::SeqCst) > 0, 100).await;
    let honest = !f.connected.load(Ordering::SeqCst);
    f.faults.health_fails.store(false, Ordering::SeqCst);
    f.faults.cached_peer.store(false, Ordering::SeqCst);
    let healthy = wait_for(|| f.connected.load(Ordering::SeqCst), 40).await;
    let posts = f.exchange("health-query failure recovery").await;
    f.stop().await;
    assert!(repaired);
    assert!(honest);
    assert!(healthy);
    posts.unwrap();
}

fn compare_develop_wire(current: &serde_json::Value, baseline_path: &str) {
    use sha2::Digest;
    let path = std::path::Path::new(baseline_path);
    assert!(
        path.metadata().unwrap().len() <= 64 * 1024,
        "baseline receipt is bounded"
    );
    let baseline: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(
        baseline["head"].as_str().unwrap().starts_with("8f33f07a9"),
        "committed develop control required"
    );
    let lock =
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock"))
            .unwrap();
    assert_eq!(
        baseline["lock_sha256"],
        hex::encode(sha2::Sha256::digest(lock)),
        "same pinned library and dependencies"
    );
    for value in [current, &baseline] {
        assert_eq!(value["connections_before"], 1);
        assert_eq!(value["connections_after"], 1);
        assert_eq!(value["repairs"], 0);
        assert_eq!(value["disconnected_views"], 0);
    }
    let old = baseline["quiet_traffic"].as_object().unwrap();
    let new = current["quiet_traffic"].as_object().unwrap();
    let kinds = old
        .keys()
        .chain(new.keys())
        .collect::<std::collections::BTreeSet<_>>();
    for kind in kinds {
        let a = old.get(kind).and_then(|v| v.as_u64()).unwrap_or(0);
        let b = new.get(kind).and_then(|v| v.as_u64()).unwrap_or(0);
        assert_eq!(
            a == 0,
            b == 0,
            "no new peer message kind in the quiet period: {kind}"
        );
        if kind.contains(":Gossip:") {
            assert_eq!((a, b), (0, 0), "no quiet application or probe messages");
        } else if kind.ends_with(":Shuffle") || kind.ends_with(":ShuffleReply") {
            // Six startup delays total 47.25..78.75 seconds; later delays
            // are 45..75 seconds. This 1001-second window begins within the
            // first seven seconds, so 14..29 messages includes every normal
            // phase and the one reply that may cross either boundary.
            assert!(
                (14..=29).contains(&a) && (14..=29).contains(&b),
                "both trees keep the pinned jittered shuffle budget: {kind} {a}/{b}"
            );
        } else {
            assert!(
                a.abs_diff(b) <= 1,
                "same control traffic outside the jittered shuffle: {kind} {a}/{b}"
            );
        }
    }
}

//! Real local sockets and the real recovery worker. Only the node's protocol
//! dispatch can pause; its endpoint keeps accepting QUIC. No test is a probe.
use super::*;
use crate::collaboration_carrier::{
    CommunityLink, CommunityLinkHealth, JoinedCollaborationNetwork,
};
use crate::collaboration_network::*;
use crate::collaboration_startup::run_community_core_fixture;
use iroh_gossip::proto::Message as WireMessage;
use gossip_rand::{rngs::StdRng, SeedableRng};
use iroh_gossip::proto::{
    Command, Event, InEvent, OutEvent, PeerData, Scope, State, Timer, TopicId,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::instrument::WithSubscriber;

enum HubInput {
    Connected(
        iroh::EndpointId,
        mpsc::Sender<WireMessage<iroh::EndpointId>>,
    ),
    Disconnected(iroh::EndpointId),
    Wire(iroh::EndpointId, WireMessage<iroh::EndpointId>),
    Timer(Timer<iroh::EndpointId>),
    Post(Vec<u8>, oneshot::Sender<()>),
}

struct LocalHub {
    endpoint: Endpoint,
    input: mpsc::Sender<HubInput>,
    stalled: Arc<AtomicBool>,
    accepted: Arc<AtomicUsize>,
    posts: Arc<std::sync::Mutex<Vec<String>>>,
    traffic: Arc<std::sync::Mutex<std::collections::BTreeMap<String,u64>>>,
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
        let posts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let traffic = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
        let task = tokio::spawn({
            let endpoint = endpoint.clone();
            let input = input.clone();
            let stalled = stalled.clone();
            let accepted = accepted.clone();
            let posts = posts.clone();
            let traffic = traffic.clone();
            async move {
                let mut state: State<iroh::EndpointId, StdRng> = State::new(
                    endpoint.id(),
                    PeerData::new(Vec::new()),
                    Default::default(),
                    StdRng::seed_from_u64(451),
                );
                let mut output = HashMap::<_, mpsc::Sender<WireMessage<iroh::EndpointId>>>::new();
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
                                if let Some(sender) = output.get(&peer) {
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
                            let traffic = traffic.clone();
                            tasks.spawn(async move {
                                if let Ok(connection) = incoming.await {
                                    accepted.fetch_add(1, Ordering::SeqCst);
                                    let peer = connection.remote_id();
                                    let _ = serve_connection(connection, topic, input.clone(), traffic).await;
                                    let _ = input.send(HubInput::Disconnected(peer)).await;
                                }
                            });
                            continue;
                        }
                        Some(_) = tasks.join_next() => continue,
                        event = receiver.recv() => {
                            let Some(event) = event else { break; };
                            match event {
                                HubInput::Connected(peer, sender) => { output.insert(peer, sender); continue; }
                                HubInput::Disconnected(peer) => { output.remove(&peer); InEvent::PeerDisconnected(peer) }
                                HubInput::Wire(peer, message) => {
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
    traffic: Arc<std::sync::Mutex<std::collections::BTreeMap<String,u64>>>,
) -> Result<()> {
    let peer = connection.remote_id();
    let (output, mut messages) = mpsc::channel::<WireMessage<iroh::EndpointId>>(64);
    input.send(HubInput::Connected(peer, output)).await?;
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
                count_wire(&traffic, "from_home", &message);
                input.send(HubInput::Wire(peer,message)).await?;
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
    anyhow::ensure!(bytes.len() <= GOSSIP_WIRE_MESSAGE_MAX_BYTES + 256, "fixture frame limit");
    send.write_all(&u32::try_from(bytes.len())?.to_be_bytes()).await?;
    send.write_all(bytes).await?;
    Ok(())
}
async fn read_frame(recv: &mut iroh::endpoint::RecvStream, max: usize) -> Result<Vec<u8>> {
    let mut length=[0;4];recv.read_exact(&mut length).await?;
    let length=u32::from_be_bytes(length) as usize;
    anyhow::ensure!(length<=max,"fixture frame limit");
    let mut bytes=vec![0;length];recv.read_exact(&mut bytes).await?;Ok(bytes)
}
fn count_wire(traffic: &std::sync::Mutex<std::collections::BTreeMap<String,u64>>, direction: &str, message: &WireMessage<iroh::EndpointId>) {
    let value=serde_json::to_value(message).unwrap();
    let outer=value["message"].as_object().unwrap().iter().next().unwrap();
    let inner=outer.1.as_object().and_then(|m|m.keys().next()).map(String::as_str).or_else(||outer.1.as_str()).unwrap_or("other");
    *traffic.lock().unwrap().entry(format!("{direction}:{}:{inner}",outer.0)).or_default()+=1;
}

#[derive(Default)]
struct Faults {
    join_fails: AtomicBool,
    cached_peer: AtomicBool,
    health_fails: AtomicBool,
    repairs: AtomicUsize,
}
struct FaultProvider { real: Arc<CarrierGossipProvider>, faults: Arc<Faults> }
#[async_trait::async_trait]
impl Provider for FaultProvider {
    fn name(&self)->&'static str { "core-local-fault-fixture" }
    fn schemes(&self)->Vec<&'static str> { vec!["peer"] }
    async fn handle(&self, request:ResourceRequest)->std::result::Result<ResourceResponse,ProviderError>{self.real.handle(request).await}
    async fn send_raw(&self, request:&serde_json::Value)->std::result::Result<serde_json::Value,ProviderError>{
        let op=request["op"].as_str().unwrap_or_default();
        if op=="gossip_join_peers" && self.faults.join_fails.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            return Ok(serde_json::json!({"status":"error","code":"join_timeout","message":"private-fixture-sentinel"}));
        }
        if op=="gossip_topic_health" && self.faults.health_fails.load(Ordering::SeqCst) {
            return Err(ProviderError::Provider("private-fixture-sentinel health failure".into()));
        }
        if matches!(op,"gossip_rejoin"|"gossip_rebuild") { self.faults.repairs.fetch_add(1,Ordering::SeqCst); }
        let mut response=self.real.send_raw(request).await?;
        if op=="list_topic_peers" && self.faults.join_fails.load(Ordering::SeqCst) {
            response["data"]["peers"]=serde_json::json!([]);
        }
        if op=="gossip_topic_health" && self.faults.cached_peer.load(Ordering::SeqCst) {
            response["data"]["peer_count"]=serde_json::json!(1);
        }
        Ok(response)
    }
}
#[derive(Clone)]
struct LogWriter(Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for LogWriter {
    fn write(&mut self, bytes:&[u8])->std::io::Result<usize>{self.0.lock().unwrap().extend_from_slice(bytes);Ok(bytes.len())}
    fn flush(&mut self)->std::io::Result<()>{Ok(())}
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
async fn wait_for(test: impl Fn()->bool, seconds:u64)->bool {
    tokio::time::timeout(Duration::from_secs(seconds),async {
        while !test(){tokio::time::sleep(Duration::from_millis(20)).await;}
    }).await.is_ok()
}
impl Fixture {
    async fn start()->Self {
        let root=tempfile::tempdir().unwrap();
        let placeholder=SecretKey::from_bytes(&[146;32]);
        let addr=iroh::EndpointAddr::from_parts(placeholder.public(),[iroh::TransportAddr::Ip("127.0.0.1:12345".parse().unwrap())]);
        let ticket=data_encoding::BASE32_NOPAD.encode(&serde_json::to_vec(&serde_json::json!({"topic":null,"endpoints":[addr]})).unwrap()).to_ascii_lowercase();
        let p=profile(CollaborationBootstrapPeer{node_id:placeholder.public().to_string(),connect_ticket:ticket});
        let topic=crate::collaboration_carrier::community_core_topic_for_test(&p);
        let hub=LocalHub::start(topic_hash(&topic)).await;
        let (key,did)=elastos_identity::derive_did(&[147;32]);
        let home=start_isolated_carrier_node_with_registry(&key,&did,root.path().into(),None).await.unwrap();
        let provider=Arc::new(CarrierGossipProvider::new(home.gossip_state.clone()));
        let faults=Arc::new(Faults::default());
        let wrapped=Arc::new(FaultProvider{real:provider.clone(),faults:faults.clone()});
        let link=crate::collaboration_carrier::join_collaboration_network(wrapped,&profile(hub.bootstrap())).await.unwrap();
        let connected=Arc::new(AtomicBool::new(false));let disconnected=Arc::new(AtomicUsize::new(0));
        let (shutdown,rx)=watch::channel(false);
        let logs=Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer=logs.clone();
        let subscriber=tracing_subscriber::fmt().with_ansi(false).without_time().with_max_level(tracing::Level::WARN).with_writer(move||LogWriter(writer.clone())).finish();
        let worker=tokio::spawn({let connected=connected.clone();let disconnected=disconnected.clone();async move {
            let connected_once=AtomicBool::new(false);
            run_community_core_fixture(rx,&link,|state|{
                if state {connected_once.store(true,Ordering::SeqCst);} else if connected_once.load(Ordering::SeqCst) {disconnected.fetch_add(1,Ordering::SeqCst);}
                connected.store(state,Ordering::SeqCst);
            }).with_subscriber(subscriber).await;
        }});
        assert!(wait_for(||connected.load(Ordering::SeqCst),50).await,"initial local join");
        Self{_root:root,home,hub,provider,faults,topic,connected,disconnected,shutdown,logs,worker}
    }
    async fn exchange(&self,event:&str)->Result<()> {
        let outward=format!("fresh Home to node after {event}");
        let result=self.provider.send_raw(&serde_json::json!({"op":"gossip_send","topic":self.topic,"message":outward})).await?;
        anyhow::ensure!(result["status"]=="ok","fresh outward send");
        anyhow::ensure!(wait_for(||self.hub.posts.lock().unwrap().contains(&outward),15).await,"fresh outward exact text");
        let inward=format!("fresh node to Home after {event}");self.hub.post(&inward).await;
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
        let _=self.shutdown.send(true);let _=self.worker.await;
        self.hub.shutdown().await;self.home.shutdown().await;
    }
}

#[tokio::test]
async fn community_core_real_join_failures_override_a_remembered_peer_then_node_returns() {
    let f=Fixture::start().await;
    f.exchange("initial join").await.unwrap();
    f.hub.stalled.store(true,Ordering::SeqCst);
    f.faults.cached_peer.store(true,Ordering::SeqCst);
    f.faults.join_fails.store(true,Ordering::SeqCst);
    let repaired=wait_for(||f.faults.repairs.load(Ordering::SeqCst)>0,100).await;
    let honest=!f.connected.load(Ordering::SeqCst);
    f.hub.stalled.store(false,Ordering::SeqCst);f.faults.join_fails.store(false,Ordering::SeqCst);f.faults.cached_peer.store(false,Ordering::SeqCst);
    let healthy=wait_for(||f.connected.load(Ordering::SeqCst),40).await;
    let posts=f.exchange("remembered neighbour, local join timeouts and node return").await;
    f.stop().await;
    assert!(repaired,"local failures start repair despite remembered peer");assert!(honest,"status reconnects while local failures last");assert!(healthy);posts.unwrap();
}

#[tokio::test]
async fn community_core_real_ended_receiver_repairs_and_delivers_exact_text() {
    let f=Fixture::start().await;f.exchange("initial receiver").await.unwrap();
    f.home.gossip_state.lock().await.receiver_tasks[&f.topic].abort();
    let repaired=wait_for(||f.faults.repairs.load(Ordering::SeqCst)>0,100).await;
    let healthy=wait_for(||f.connected.load(Ordering::SeqCst),40).await;
    let posts=f.exchange("ended receiver recovery").await;
    f.stop().await;assert!(repaired,"ended receiver overrides cached peer");assert!(healthy);posts.unwrap();
}

#[tokio::test]
async fn community_core_real_more_than_120_rebuilds_release_owned_resources() {
    let f=Fixture::start().await;f.exchange("initial actor").await.unwrap();
    let mut watchdog=crate::collaboration_carrier::CommunityLinkWatchdog::new(Duration::from_secs(60));
    let start=tokio::time::Instant::now();let mut rebuilt=0;
    for n in 0..124 {
        let now=start+Duration::from_secs(n*900);
        if let Some(step)=watchdog.observe(None,None,now) {
            match step {
                crate::collaboration_carrier::CommunityLinkStep::Rejoin=>{f.provider.send_raw(&serde_json::json!({"op":"gossip_rejoin","topic":f.topic})).await.unwrap();}
                crate::collaboration_carrier::CommunityLinkStep::Rebuild=>{let r=f.provider.send_raw(&serde_json::json!({"op":"gossip_rebuild"})).await.unwrap();assert_eq!(r["status"],"ok");rebuilt+=1;}
            }
            watchdog.step_finished(now);
        }
    }
    let (lookups,receivers,senders)={let s=f.home.gossip_state.lock().await;(s.endpoint.address_lookup().unwrap().len(),s.receiver_tasks.len(),s.senders.len())};
    let posts=f.exchange("more than120 actual actor replacements").await;
    f.stop().await;posts.unwrap();assert!(rebuilt>120,"rebuilds continue:{rebuilt}");
    assert_eq!((lookups,receivers,senders),(2,1,1),"owned state stays bounded");
}

#[tokio::test]
#[ignore="1001-second production-timer and wire-count proof; run explicitly on local-only Linux"]
async fn community_core_real_quiet_wire_counts_and_status() {
    let f=Fixture::start().await;f.exchange("quiet interval start").await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let connections=f.hub.accepted.load(Ordering::SeqCst);
    let before=f.hub.traffic.lock().unwrap().clone();
    let disconnected=f.disconnected.load(Ordering::SeqCst);
    let outcome=async {
        for _ in 0..1001 {
            assert!(f.connected.load(Ordering::SeqCst));
            assert_eq!(f.disconnected.load(Ordering::SeqCst),disconnected);
            assert_eq!(f.faults.repairs.load(Ordering::SeqCst),0);
            assert_eq!(f.hub.accepted.load(Ordering::SeqCst),connections);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Ok::<(),anyhow::Error>(())
    }.await;
    let mut traffic=f.hub.traffic.lock().unwrap().clone();
    for (key,count) in before { *traffic.entry(key).or_default()-=count; }
    let report=serde_json::json!({"connections_before":connections,"connections_after":f.hub.accepted.load(Ordering::SeqCst),"quiet_traffic":traffic,"repairs":f.faults.repairs.load(Ordering::SeqCst),"disconnected_views":f.disconnected.load(Ordering::SeqCst)-disconnected});
    if let Ok(path)=std::env::var("COMMUNITY_CORE_QUIET_RECEIPT"){std::fs::write(path,serde_json::to_vec_pretty(&report).unwrap()).unwrap();}
    println!("COMMUNITY_CORE_QUIET_METRICS={report}");
    let posts=f.exchange("1001-second quiet interval").await;
    f.stop().await;outcome.unwrap();posts.unwrap();
}

#[tokio::test]
async fn community_core_real_log_rate_keeps_the_reason_without_private_text() {
    let f=Fixture::start().await;f.exchange("log-rate initial join").await.unwrap();
    f.logs.lock().unwrap().clear();
    f.faults.cached_peer.store(true,Ordering::SeqCst);f.faults.join_fails.store(true,Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(10)).await;
    let logs=String::from_utf8(f.logs.lock().unwrap().clone()).unwrap();
    f.faults.join_fails.store(false,Ordering::SeqCst);f.faults.cached_peer.store(false,Ordering::SeqCst);
    let healthy=wait_for(||f.connected.load(Ordering::SeqCst),15).await;
    let posts=f.exchange("paced failure reason").await;
    f.stop().await;assert!(healthy);posts.unwrap();
    let warnings=logs.lines().filter(|l|l.contains("WARN")).count();
    assert!(warnings<=1,"unchanged failure logs once in ten seconds, got{warnings}:{logs}");
    assert!(logs.contains("bootstrap join timed out"),"bounded reason retained:{logs}");
    assert!(!logs.contains("private-fixture-sentinel"));
    assert!(logs.lines().all(|line|line.len()<256));
}

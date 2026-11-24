//! AUDIT-REPRO J1 (coll-journey-audit-20261117.md J1-F3): red test only, no
//! fix. The creator's listing placement, as the creator's Carrier
//! availability provider answers it.

use super::*;

/// J1-F3: a listing placement where every member target fails still answers
/// `carrier_announced` (the local pin alone meets `min_replicas = 1`), which
/// the content plane records as a `healthy` repair task, so no repair is
/// ever queued for the members that kept no copy.
#[tokio::test]
async fn audit_j1_f3_a_placement_short_of_its_members_is_queued_for_repair() {
    let cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
    let (local_sk, local_did) = elastos_identity::derive_did(&[61u8; 32]);
    let members: Vec<String> = [62u8, 63]
        .iter()
        .map(|seed| elastos_identity::derive_did(&[*seed; 32]).1)
        .collect();
    let topic_name = content_availability_topic_name(cid);
    let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(iroh::SecretKey::from_bytes(&local_sk.to_bytes()))
        .bind()
        .await
        .unwrap();
    let memory_lookup = MemoryLookup::new();
    endpoint
        .address_lookup()
        .unwrap()
        .add(memory_lookup.clone());
    let gossip = spawn_carrier_gossip(&endpoint);
    let state = Arc::new(Mutex::new(GossipState::new(
        endpoint.clone(),
        gossip,
        memory_lookup,
        Some(local_sk),
        Some(local_did.clone()),
    )));
    {
        let mut guard = state.lock().await;
        guard.joined_topics.insert(topic_name.clone());
        guard
            .buffers
            .lock()
            .await
            .insert(topic_name, test_topic_buffer([], 0));
    }
    let data_dir = tempfile::tempdir().unwrap();
    for did in &members {
        crate::operator_control::upsert_peer(
            data_dir.path(),
            crate::operator_control::OperatorPeer {
                did: did.clone(),
                connect_ticket: format!("ticket-{did}"),
                ..Default::default()
            },
        )
        .unwrap();
    }
    let registry = Arc::new(ProviderRegistry::new());
    // Every member fails its copy (offline, busy, or out of room).
    let invoker = Arc::new(MockCarrierProviderPlaneInvoker {
        fail_ensure: true,
        ..Default::default()
    });
    registry.set_carrier_invoker(invoker.clone()).await;
    register_pinned_ipfs(&registry).await;
    let provider = CarrierAvailabilityProvider::with_provider_registry_and_data_dir(
        state,
        Arc::downgrade(&registry),
        data_dir.path().to_path_buf(),
    );
    let mut pool = members.clone();
    pool.push(local_did.clone());
    // The requirements `runtime_custody_listing_requirements` sends: the
    // new-mint target of 1, no live proof, and the pool's members.
    let response = provider
        .send_raw(&serde_json::json!({
            "op": "ensure",
            "cid": cid,
            "uri": format!("elastos://{cid}"),
            "policy": "network_default",
            "local": {"status": "local_pinned", "provider": "ipfs-provider", "replicas": 1},
            "requirements": {
                "min_replicas": 1,
                "require_live_multi_peer_proof": false,
                "placement_targets": pool,
            },
        }))
        .await
        .unwrap();
    assert_eq!(response["status"], "ok", "{response}");
    let asked = invoker
        .requests
        .lock()
        .await
        .iter()
        .filter(|request| request["op"] == "ensure")
        .count();
    assert_eq!(asked, 2, "precondition: both members were asked and failed");

    let availability = &response["data"]["availability"];
    assert_eq!(
        availability["status"], "repair_needed",
        "J1-F3: a placement that no member kept is reported {} (content records it as a \
         `healthy` repair task), with repair_worker {}",
        availability["status"], availability["repair_worker"]
    );
}

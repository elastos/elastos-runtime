//! AUDIT-REPRO J4 (coll-journey-audit-20261117.md J4-F2, J4-F3(a), J4-F5):
//! red tests only, no fix.

use super::*;

use elastos_protected_content_contracts::test_fixtures::{
    pool_bundle, pool_descriptor_with, runtime_issuer,
};
use elastos_protected_content_contracts::{
    CanonicalContract as _, PoolMemberRouteV2, ServePolicyV1, SignedPoolDescriptorAnyV1,
};
use elastos_protected_content_runtime::{
    PoolCallClass, PoolTransportError, POOL_OP_SESSION_PREPARE,
};

const AUDIT_NOW: u64 = crate::custody_pool_resolver::tests::FIXTURE_NOW;

fn audit_xwing(
    seed: u8,
) -> [u8; elastos_protected_content_contracts::PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
    use x_wing::kem::Decapsulator as _;
    use x_wing::KeyExport as _;
    let secret = x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE]);
    secret.encapsulation_key().to_bytes().into()
}

async fn audit_bind() -> Endpoint {
    Endpoint::builder(iroh::endpoint::presets::Minimal)
        .clear_ip_transports()
        .portmapper_config(iroh::endpoint::PortmapperConfig::Disabled)
        .alpns(vec![CARRIER_ALPN.to_vec()])
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap()
}

/// The pool call the owner Home makes to a member whose card it kept, as
/// `RegistryPoolSessionTransport::call` builds it.
fn audit_pool_call(route: ProviderCarrierRoute) -> ProviderInvocation {
    ProviderInvocation {
        source: crate::protected_content_runtime::RUNTIME_PROVIDER_ID.to_string(),
        target: crate::custody_surface::TARGET_CUSTODY_POOL.to_string(),
        op: POOL_OP_SESSION_PREPARE.to_string(),
        request: serde_json::json!({ "op": POOL_OP_SESSION_PREPARE }),
        transfer: ProviderTransfer::Json,
        range: None,
        progress: None,
        transport: ProviderInvocationTransport::Carrier(route),
    }
}

/// J4-F2: the member is offline. Reached by its kept card's ticket the
/// connect fails, nothing is sent, and the pool client must read it as
/// `Unreachable` so the open moves to the next server (as it does for the
/// same member reached by peer DID).
#[tokio::test]
async fn audit_j4_f2_a_kept_card_member_that_is_offline_reads_as_unreachable() {
    let member = audit_bind().await;
    let consumer = audit_bind().await;
    let ticket = encode_ticket_for(wait_for_direct_endpoint_addr(&member).await);
    let member_did = public_key_to_did(&member.id()).unwrap();
    member.close().await;

    let registry = Arc::new(ProviderRegistry::new());
    registry
        .set_carrier_invoker(Arc::new(CarrierProviderInvoker::with_carrier_endpoint(
            consumer.clone(),
        )))
        .await;
    let route = PoolMemberRouteV2::new(member_did.clone()).unwrap();

    // The same offline member by peer DID (a buyer's route): fails over.
    let by_did = crate::custody_pool_resolver::carrier_route_for(
        &route,
        PoolCallClass::Control,
        &Default::default(),
    );
    assert!(matches!(by_did, ProviderCarrierRoute::PeerDid { .. }));
    let did_error = registry
        .invoke_provider(audit_pool_call(by_did))
        .await
        .unwrap_err();
    let did_mapped =
        crate::custody_pool_resolver::pool_call_failure(POOL_OP_SESSION_PREPARE, &did_error);
    assert!(
        matches!(did_mapped, PoolTransportError::Unreachable),
        "peer DID route: {did_error:?} -> {did_mapped:?}"
    );

    // By the kept card's ticket (the owner Home's route).
    let kept: crate::custody_pool_resolver::KeptCardTickets =
        [(member_did.clone(), ticket)].into_iter().collect();
    let by_ticket =
        crate::custody_pool_resolver::carrier_route_for(&route, PoolCallClass::Control, &kept);
    assert!(matches!(
        by_ticket,
        ProviderCarrierRoute::ConnectTicket { .. }
    ));
    let started = std::time::Instant::now();
    let error = registry
        .invoke_provider(audit_pool_call(by_ticket))
        .await
        .unwrap_err();
    let mapped = crate::custody_pool_resolver::pool_call_failure(POOL_OP_SESSION_PREPARE, &error);
    consumer.close().await;
    assert!(
        matches!(mapped, PoolTransportError::Unreachable),
        "J4-F2: the offline member by ticket failed after {:?} with {error:?}, read as \
         {mapped:?}; prepare_fails_over = {}",
        started.elapsed(),
        crate::protected_content_pool_open::prepare_fails_over(&mapped)
    );
}

/// J4-F3(a): a pool member Home (served pool, no known pool) does not count
/// its fellow members as content holders, so a session server without its
/// own copy cannot find them while the creator is offline.
#[cfg(unix)]
#[tokio::test]
async fn audit_j4_f3a_a_member_counts_its_served_pools_members_as_content_holders() {
    use base64::Engine as _;
    let dir = crate::protected_content_config::tests::safe_ancestor_tempdir();
    let home = dir.path().join("home");
    crate::protected_content_config::tests::owner_only_dir(&home);
    let descriptor: SignedPoolDescriptorAnyV1 = pool_descriptor_with(
        &pool_bundle(audit_xwing, AUDIT_NOW),
        1,
        ServePolicyV1::DEFAULT,
        None,
        runtime_issuer(0x43),
        AUDIT_NOW,
    )
    .into();
    let members: Vec<String> = descriptor
        .verify(AUDIT_NOW)
        .unwrap()
        .members()
        .iter()
        .map(|member| member.route().peer_did().to_string())
        .collect();
    let pool_key =
        crate::custody_node_card::Fingerprint::of(descriptor.pool().issuer().as_bytes()).full;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(descriptor.canonical_bytes().unwrap());
    crate::custody_consent::update_served_pools(&home, |pools| {
        pools.entries.insert(
            pool_key.clone(),
            crate::custody_consent::ServedPoolEntryV2 {
                owner_home: "did:key:z6MkAuditOwnerHome".to_string(),
                consent: crate::custody_consent::ServedConsentV2 {
                    term_days: 365,
                    signing_key_fingerprint_full: pool_key.clone(),
                },
                root_path: "inactive".to_string(),
                admin_profile_did: None,
                pool_did: None,
                served_pool: None,
                descriptor: Some(encoded.clone()),
            },
        );
        Ok(())
    })
    .unwrap();
    // Preconditions: this Home serves the pool, its kept descriptor verifies,
    // and it uses no known pool.
    assert_eq!(
        crate::custody_pool_descriptor::served_descriptors(&home, AUDIT_NOW)
            .unwrap()
            .len(),
        1
    );
    assert!(crate::custody_pool_resolver::known_pool_member_peer_dids(&home, AUDIT_NOW).is_empty());

    let (_self_sk, self_did) = elastos_identity::derive_did(&[0x5a; 32]);
    let mut candidates = Vec::new();
    append_known_pool_member_replica_candidates(
        &mut candidates,
        &home,
        &self_did,
        &std::collections::HashMap::new(),
        AUDIT_NOW,
        None,
    );
    let listed: Vec<String> = candidates
        .iter()
        .map(|replica| replica.node_did.clone())
        .collect();
    assert!(
        members.iter().all(|member| listed.contains(member)),
        "J4-F3(a): the served pool's members {members:?} are not content holder \
         candidates; the candidates are {listed:?}"
    );
}

/// J4-F5: the folder has no `metadata.json` (a legacy listing). One holder
/// says so (`content_not_found`, final for a content-addressed folder); the
/// other is offline. The read must be final, not "try again".
#[tokio::test]
async fn audit_j4_f5_a_folder_holders_not_found_is_final_even_when_another_holder_is_unreachable() {
    let cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
    let invoker = ScriptedHolderInvoker::default();
    invoker.failures.lock().unwrap().extend([
        ticket_route_failure(CARRIER_CONTENT_NOT_FOUND),
        ticket_route_failure("connect failed"),
    ]);
    let (provider, invoker, _registry, _data_dir) = availability_provider_with_announced_holders(
        0xe1,
        cid,
        &[(0xe2, "ticket:a"), (0xe3, "ticket:b")],
        invoker,
    )
    .await;
    let response = provider
        .send_raw(&serde_json::json!({
            "op": "fetch", "cid": cid, "path": "metadata.json", "known_holders_only": true
        }))
        .await
        .unwrap();
    assert_eq!(invoker.asked.lock().unwrap().len(), 2, "both holders asked");
    assert_eq!(
        response["code"], CARRIER_FETCH_FAILED_CODE,
        "J4-F5: a holder's content_not_found with the other holder offline reads as {response}"
    );
}

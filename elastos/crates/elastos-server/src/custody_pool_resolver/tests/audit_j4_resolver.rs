//! Journey regression tests (#388): pool resolution.

use super::*;

use elastos_protected_content_contracts::test_fixtures::{
    pool_bundle_signed_by, pool_bundle_with, pool_descriptor_routed,
};

fn member_dids(signed: &SignedPoolDescriptorAnyV1, now: u64) -> Vec<String> {
    signed
        .verify(now)
        .unwrap()
        .members()
        .iter()
        .map(|member| member.route().peer_did().to_string())
        .collect()
}

/// J4-F7: a buyer that uses four pools of three members each. The item is in
/// the fourth. The content fetch asks the first eight members across all
/// known pools, so the item's own pool is never asked.
#[tokio::test]
async fn audit_j4_f7_the_items_pool_members_are_asked_when_other_known_pools_fill_the_cap() {
    let (_dir, data_dir) = data_dir();
    let write = crate::custody_consent::lock_custody_writes().await;
    let mut pools = Vec::new();
    let mut item_pool_identity = None;
    for authority in [0x81u8, 0x82, 0x83, 0x84] {
        let bundle = pool_bundle_signed_by(xwing, NOW, None, None, authority);
        item_pool_identity = Some(bundle.signed_pool().pool_identity().unwrap());
        let signed: SignedPoolDescriptorAnyV1 =
            pool_descriptor_routed(&bundle, 1, NOW, authority, &|seed| {
                format!("did:key:z6MkAudit{authority:02x}Node{seed:02x}")
            })
            .into();
        keep_known_pool_for_test(
            &write,
            &data_dir,
            &address_for(*signed.pool()),
            &signed,
            NOW,
        )
        .unwrap();
        pools.push(member_dids(&signed, NOW));
    }
    drop(write);
    let item_pool = pools.last().unwrap();
    // STAB-10 (D3): the open/stage fetch passes the item's pool.
    let asked = known_pool_member_peer_dids_for(&data_dir, item_pool_identity, NOW);
    let unasked: Vec<&String> = item_pool
        .iter()
        .filter(|did| !asked.contains(did))
        .collect();
    assert!(
        unasked.is_empty(),
        "J4-F7: the item's pool members {unasked:?} are not content holder candidates; \
         the {} candidates are {asked:?}",
        asked.len()
    );
}

/// J4-F8: a pool's members stay reachable after its owner has been offline
/// for the descriptor's life. Tracked as a #388 follow-up.
#[ignore = "tracked: #388 follow-up"]
#[tokio::test]
async fn audit_j4_f8_members_stay_reachable_after_the_owner_has_been_offline_for_the_descriptor_life(
) {
    // Production term (the fixture's own term is one day; same rule).
    assert_eq!(
        elastos_protected_content_contracts::MAX_POOL_DESCRIPTOR_LIFETIME_SECS,
        30 * 86_400
    );
    let (_dir, data_dir) = data_dir();
    let bundle = pool_bundle_with(xwing, NOW, Some((NOW - 10, NOW + 365 * 86_400)), None);
    let signed: SignedPoolDescriptorAnyV1 = pool_descriptor_with(
        &bundle,
        1,
        ServePolicyV1::DEFAULT,
        None,
        runtime_issuer(0x43),
        NOW,
    )
    .into();
    let members = member_dids(&signed, NOW);
    let write = crate::custody_consent::lock_custody_writes().await;
    keep_known_pool_for_test(&write, &data_dir, &address_for(pool_did()), &signed, NOW).unwrap();
    drop(write);

    let after = signed.expires_at() + 1;
    // The owner is offline: every member answers the same, owner-signed copy.
    let transport = FakeTransport::describing(&[signed.clone(), signed.clone(), signed.clone()]);
    let renewed = refresh_known_pools(&data_dir, &PoolSessionClient::new(&transport), after)
        .await
        .unwrap();
    assert_eq!(renewed, 0, "no member can renew an owner-signed descriptor");

    let reachable = known_pool_member_peer_dids(&data_dir, after);
    let key_envelope = key_envelope_for(
        &bundle,
        &EncryptedContentIdentityV1::new(Digest32::new([0x2b; 32]), 4096).unwrap(),
    );
    let resolved = home_pool_resolver(&data_dir, Arc::new(ProviderRegistry::new()))
        .resolve(&key_envelope, &[], after)
        .await;
    assert!(
        reachable == members && resolved.is_ok(),
        "J4-F8: one second past the descriptor's term ({}) the members {members:?} are \
         reachable as {reachable:?} and the pool resolves as {:?}; the descriptor verifies \
         as {:?}",
        signed.expires_at(),
        resolved.as_ref().map(|resolved| resolved.source).err(),
        signed.verify(after).err()
    );
}

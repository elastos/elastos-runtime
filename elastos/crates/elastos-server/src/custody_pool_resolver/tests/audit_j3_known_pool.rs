//! AUDIT-REPRO J3-F6 (red, no fix): a known pool goes stale after its owner
//! signs a newer epoch.

use super::*;

use elastos_protected_content_contracts::test_fixtures::pool_bundle_with;

/// The owner re-forms its pool: the new descriptor (sequence 2) names only
/// the new epoch (`owner_descriptor` signs `vec![composition.bundle]`,
/// custody_pool_descriptor.rs:349-358). This Home kept sequence 1, which
/// still has more than a day left. An item of the new epoch does not resolve
/// here, and the only refresh -- `refresh_known_pools`, which is also what
/// `refresh_in_background` runs -- asks a known pool only once its kept
/// descriptor has under a day left (`REFRESH_BEFORE_EXPIRY_SECS`); a failed
/// resolve triggers nothing. Owner descriptors live 30 days.
#[tokio::test]
async fn audit_j3_f6_an_item_of_a_newer_epoch_refreshes_the_known_pool() {
    let (_dir, data_dir) = data_dir();
    let address = address_for(pool_did());
    add_answering(&data_dir, &address, descriptor(1)).await;
    // Just after the kept descriptor was signed: more than a day left.
    let now = NOW - 1;

    let newer_bundle = pool_bundle_with(xwing, NOW, Some((NOW - 10, NOW + 2 * 86_400)), None);
    let newer: SignedPoolDescriptorAnyV1 = pool_descriptor_with(
        &newer_bundle,
        2,
        ServePolicyV1::DEFAULT,
        None,
        runtime_issuer(0x43),
        NOW,
    )
    .into();
    let item_of_newer_epoch = key_envelope_for(
        &newer_bundle,
        &EncryptedContentIdentityV1::new(Digest32::new([0x2c; 32]), 4096).unwrap(),
    );
    let registry = Arc::new(ProviderRegistry::new());
    assert!(
        home_pool_resolver(&data_dir, registry)
            .resolve(&item_of_newer_epoch, &[], now)
            .await
            .is_err(),
        "precondition: the item of the newer epoch does not resolve under the kept descriptor"
    );

    // The pool answers its newer descriptor to anyone who asks.
    let transport = FakeTransport::describing(&[newer.clone(), newer]);
    let replaced = refresh_known_pools(&data_dir, &PoolSessionClient::new(&transport), now)
        .await
        .unwrap();
    assert_eq!(
        replaced,
        1,
        "a known pool with an unresolvable item of its own must be asked for its newer descriptor; \
         describe calls made: {}",
        transport.calls.lock().unwrap().len()
    );
}

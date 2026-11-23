//! An independent Home can learn an epoch from a newer signed descriptor.

use super::*;

#[tokio::test]
async fn audit_j3_f6_an_item_of_a_newer_epoch_refreshes_the_known_pool() {
    let now = crate::auth::now_ts();
    let (_reader_dir, reader) = data_dir();
    let (_owner_dir, owner) = data_dir();
    let original = pool_bundle(xwing, now);
    let stale = pool_descriptor_with(
        &original,
        1,
        ServePolicyV1::DEFAULT,
        None,
        runtime_issuer(0x43),
        now,
    );
    let original_item = key_envelope_for(
        &original,
        &EncryptedContentIdentityV1::new(Digest32::new([0x2c; 32]), 4096).unwrap(),
    );
    let successor = pool_bundle(|seed| xwing(seed + 8), now);
    let successor_item = key_envelope_for(&successor, original_item.encrypted_content());
    assert_ne!(successor_item.custody_pool(), original_item.custody_pool());
    let current = sign_successor_for_test(
        &stale,
        successor.clone(),
        stale.statement().members().to_vec(),
    );
    let address = address_for(*current.pool());
    let write = crate::custody_consent::lock_custody_writes().await;
    keep_known_pool_for_test(&write, &reader, &address, &stale.into(), now).unwrap();
    drop(write);
    assert_eq!(known_pools(&reader).unwrap()[0].sequence, 1);
    assert!(
        crate::protected_content_runtime::runtime_custody_pool_for_key_envelope_cached(
            &reader,
            &successor_item,
            now
        )
        .is_err()
    );

    let drops_original = SignedPoolDescriptorAnyV1::from(pool_descriptor_with(
        &successor,
        2,
        ServePolicyV1::DEFAULT,
        None,
        runtime_issuer(0x43),
        now,
    ));
    assert!(drops_original
        .verify(now)
        .unwrap()
        .epoch_for(&successor_item)
        .is_some());
    let answers = vec![drops_original; 4];
    let transport = FakeTransport::describing(&answers);
    assert_eq!(
        refresh_known_pool_entries(
            &reader,
            &PoolSessionClient::new(&transport),
            load_known_pools(&reader).unwrap().pools,
            Some(&successor_item),
            now,
        )
        .await
        .unwrap(),
        0,
        "even an authentic successor that matches the new asset must keep the existing epoch"
    );
    assert!(!transport.calls.lock().unwrap().is_empty());
    assert_eq!(known_pools(&reader).unwrap()[0].sequence, 1);

    let served = Arc::new(CurrentDescriptorProvider {
        descriptor: current,
        describe_calls: Default::default(),
    });
    let remote = Arc::new(ProviderRegistry::new());
    remote
        .register_runtime_provider_target(TARGET_CUSTODY_POOL, served.clone())
        .await
        .unwrap();
    let registry = Arc::new(ProviderRegistry::new());
    registry
        .set_carrier_invoker(Arc::new(DescriptorDispatchCarrier {
            remote,
            remote_home: owner,
            source: iroh::SecretKey::from_bytes(&[0x79; 32]).public(),
        }))
        .await;

    let resolved = home_pool_resolver(&reader, registry)
        .resolve(&successor_item, &[], now)
        .await
        .expect("the resolver must discover the new epoch from an already known pool");
    assert_eq!(resolved.descriptor.sequence(), 2);
    assert_eq!(resolved.epoch, successor);
    assert_eq!(
        crate::protected_content_runtime::runtime_custody_pool_for_key_envelope_cached(
            &reader,
            &original_item,
            now,
        )
        .unwrap()
        .epoch,
        original
    );
}

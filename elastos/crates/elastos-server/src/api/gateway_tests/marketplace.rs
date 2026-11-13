use super::*;

#[tokio::test]
async fn test_marketplace_catalog_route_is_registered_and_auth_gated() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(test_state(dir.path()));

    let denied = app
        .clone()
        .oneshot(
            test_browser_request("localhost:61180", "null")
                .uri("/api/capsules/catalog")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let token = issue_home_launch_token(dir.path(), MARKETPLACE_CAPSULE_ID).unwrap();
    let response = app
        .clone()
        .oneshot(
            test_browser_request("localhost:61180", "null")
                .uri("/api/capsules/catalog")
                .header("x-elastos-home-token", token.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["schema"], "elastos.capsules.catalog/v1");
    assert!(
        payload["capsules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|capsule| capsule["name"] != "bus-v1-conformance"
                && capsule["name"] != "marketplace")
    );

    let marketplace_scoped_response = app
        .oneshot(
            test_browser_request("localhost:61180", "null")
                .uri("/api/apps/marketplace/catalog")
                .header("x-elastos-home-token", token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(marketplace_scoped_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn model_consumers_can_read_catalog_with_current_scoped_authority() {
    let dir = tempfile::tempdir().unwrap();
    let app = gateway_router(test_state(dir.path()));
    let authority = passkey_authority(dir.path());
    for consumer in ["home-agent", "assistant"] {
        let token = app_token_for_authority(dir.path(), consumer, &authority);
        let request = test_browser_request("localhost:61180", "null")
            .header("x-elastos-home-token", token.as_str())
            .body(Body::empty())
            .unwrap();
        let context = super::super::gateway_home_token::require_home_launch_token_context(
            dir.path(),
            request.headers(),
            consumer,
        )
        .unwrap();
        let expired =
            super::super::gateway_home_token::issue_expired_home_launch_token_with_context(
                dir.path(),
                consumer,
                &context,
            )
            .unwrap();
        let unrelated = app_token_for_authority(dir.path(), "documents", &authority);
        for route in [
            "/api/capsules/catalog",
            "/api/capsules/interfaces",
            "/api/apps/marketplace/catalog",
        ] {
            for (candidate, origin, expected) in [
                (Some(token.as_str()), "null", StatusCode::OK),
                (
                    Some(token.as_str()),
                    "https://unrelated.example",
                    StatusCode::FORBIDDEN,
                ),
                (Some(expired.as_str()), "null", StatusCode::FORBIDDEN),
                (Some(unrelated.as_str()), "null", StatusCode::FORBIDDEN),
                (None, "null", StatusCode::FORBIDDEN),
            ] {
                let mut request = test_browser_request("localhost:61180", origin).uri(route);
                if let Some(token) = candidate {
                    request = request.header("x-elastos-home-token", token);
                }
                let response = app
                    .clone()
                    .oneshot(request.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), expected, "{consumer} {route} {origin}");
            }
        }
    }
}

/// Plan B T4.7: Marketplace routes a buy to the item's pool. Buy is allowed
/// for an item of any pool this Home can reach, and refused before payment
/// only when the pool cannot be resolved.
mod plan_b_custody_route {
    use super::*;
    use elastos_protected_content_contracts::test_fixtures::{
        key_envelope_for, pool_bundle, pool_descriptor_with, pool_did, runtime_issuer,
    };
    use elastos_protected_content_contracts::{
        Digest32, EncryptedContentIdentityV1, KeyEnvelopeIdentityV1, PoolAddressV2,
        PoolMemberRouteV2, ServePolicyV1, SignedPoolDescriptorAnyV1,
        PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES,
    };
    use x_wing::kem::Decapsulator as _;
    use x_wing::KeyExport as _;

    const NOW: u64 = 2_000_000_000;

    const LISTING_SOURCE: &str = include_str!("../gateway_marketplace_listing.rs");
    const BUY_SOURCE: &str = include_str!("../gateway_marketplace_buy.rs");
    const RUNTIME_SOURCE: &str = include_str!("../../protected_content_runtime.rs");

    fn xwing(seed: u8) -> [u8; PQ_HYBRID_WRAP_PUBLIC_KEY_BYTES] {
        let secret = x_wing::DecapsulationKey::from([seed; x_wing::DECAPSULATION_KEY_SIZE]);
        secret.encapsulation_key().to_bytes().into()
    }

    /// A fixture pool's descriptor (v3, WCI-operated: #388 A2), and the key
    /// envelope of an item its epoch keeps.
    fn pool_item() -> (SignedPoolDescriptorAnyV1, KeyEnvelopeIdentityV1) {
        let bundle = pool_bundle(xwing, NOW);
        let descriptor = pool_descriptor_with(
            &bundle,
            1,
            ServePolicyV1::DEFAULT,
            None,
            runtime_issuer(0x43),
            NOW,
        )
        .into();
        let key_envelope = key_envelope_for(
            &bundle,
            &EncryptedContentIdentityV1::new(Digest32::new([0x2b; 32]), 4096).unwrap(),
        );
        (descriptor, key_envelope)
    }

    /// A Home with no custody pool of its own and no known pool.
    fn empty_home() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = crate::protected_content_config::tests::safe_ancestor_tempdir();
        let data_dir = dir.path().join("home");
        crate::protected_content_config::tests::owner_only_dir(&data_dir);
        (dir, data_dir)
    }

    async fn add_known_pool(data_dir: &std::path::Path, descriptor: &SignedPoolDescriptorAnyV1) {
        let address = crate::custody_pool_descriptor::encode_pool_address(
            &PoolAddressV2::new(
                pool_did(),
                PoolMemberRouteV2::new("did:key:z6MkPoolNode01".to_string()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let write = crate::custody_consent::lock_custody_writes().await;
        crate::custody_pool_resolver::keep_known_pool_for_test(
            &write, data_dir, &address, descriptor, NOW,
        )
        .unwrap();
    }

    /// What the listing and the buy guard read for `key_envelope` on this
    /// Home, through the one cached route check. The registry has no
    /// provider at all, so nothing here can reach Carrier.
    fn custody_of(
        data_dir: &std::path::Path,
        key_envelope: &KeyEnvelopeIdentityV1,
    ) -> MarketItemCustody {
        market_item_custody_from_route(
            crate::protected_content_runtime::runtime_custody_pool_route_for_key_envelope(
                data_dir,
                &std::sync::Arc::new(ProviderRegistry::new()),
                key_envelope,
                NOW,
            ),
        )
    }

    fn refusal_code(error: &anyhow::Error) -> Option<&'static str> {
        error
            .downcast_ref::<RuntimeMarketBuyRefusal>()
            .map(RuntimeMarketBuyRefusal::code)
    }

    /// The text of `fn <name>(` up to its closing brace at column 0.
    fn fn_body<'a>(source: &'a str, name: &str) -> &'a str {
        let start = source
            .find(&format!("fn {name}("))
            .unwrap_or_else(|| panic!("fn {name} is missing"));
        let end = source[start..]
            .find("\n}\n")
            .unwrap_or_else(|| panic!("fn {name} has no end"));
        &source[start..start + end]
    }

    #[tokio::test]
    async fn buy_guard_allows_item_of_a_known_pool() {
        let (_dir, data_dir) = empty_home();
        let (descriptor, key_envelope) = pool_item();
        // Before the pool is added: unresolved, refused as `custody_elsewhere`.
        assert_eq!(
            custody_of(&data_dir, &key_envelope),
            MarketItemCustody::Unresolved
        );

        add_known_pool(&data_dir, &descriptor).await;
        let custody = custody_of(&data_dir, &key_envelope);
        assert_eq!(custody, MarketItemCustody::Pool);
        runtime_market_buy_custody_verdict(custody).expect("a known pool's item can be bought");
        // An item this Home would not hold at all keeps buying as before.
        runtime_market_buy_custody_verdict(MarketItemCustody::NotHeldHere)
            .expect("a foreign asset can be bought");
    }

    #[test]
    fn buy_guard_refuses_unresolved_before_wallet() {
        let refused = runtime_market_buy_custody_verdict(MarketItemCustody::Unresolved)
            .expect_err("an unresolved pool is refused");
        // The wire code stays; only its words change.
        assert_eq!(refusal_code(&refused), Some("custody_elsewhere"));
        // Custody that cannot be compared now is `unavailable`: the same Buy
        // tries again, and it is not `custody_elsewhere`.
        let unknown = runtime_market_buy_custody_verdict(MarketItemCustody::Unknown)
            .expect_err("unknown custody fails closed");
        assert_eq!(refusal_code(&unknown), None);
        assert_eq!(
            crate::protected_content_runtime::RUNTIME_CUSTODY_ELSEWHERE_MESSAGE,
            "This item's pool cannot be reached from this Home yet. Add the pool in Custody."
        );
        // The guard runs before the purchase is driven, which is where the
        // Wallet is first asked (the end-to-end case is
        // `library::foreign_pool_market_buy_is_refused_before_payment`).
        let guard = BUY_SOURCE
            .find("runtime_market_buy_custody_guard(state, &item, &asset_uri).await?")
            .expect("buy_offer runs the custody guard");
        let drive = BUY_SOURCE
            .find("drive_runtime_market_purchase(state, authority, registry, purchase, buyer_account)")
            .expect("buy_offer drives the purchase");
        assert!(
            guard < drive,
            "the custody guard must run before any Wallet request"
        );
    }

    #[test]
    fn listing_states_custody_route() {
        assert_eq!(market_custody_route(&MarketItemCustody::Pool), Some("pool"));
        assert_eq!(
            market_custody_route(&MarketItemCustody::Unresolved),
            Some("unresolved")
        );
        // Stated only when proven.
        assert_eq!(market_custody_route(&MarketItemCustody::NotHeldHere), None);
        assert_eq!(market_custody_route(&MarketItemCustody::Unknown), None);

        let listing = fn_body(LISTING_SOURCE, "build_market_listing_object");
        assert!(
            listing.contains(r#"object["custody_route"]"#),
            "the listing states custody_route"
        );
        assert!(
            !LISTING_SOURCE.contains(r#"object["custody_elsewhere"]"#),
            "custody_route replaces the custody_elsewhere flag"
        );
    }

    #[tokio::test]
    async fn listing_resolves_from_cached_sources_only() {
        let (_dir, data_dir) = empty_home();
        let (descriptor, key_envelope) = pool_item();
        add_known_pool(&data_dir, &descriptor).await;
        // The kept descriptor alone resolves the item: no member is asked.
        assert_eq!(
            custody_of(&data_dir, &key_envelope),
            MarketItemCustody::Pool
        );

        // The listing reads the sync, cached route check, never the async
        // resolver (which may `describe` or refresh over Carrier).
        let custody = fn_body(LISTING_SOURCE, "verified_market_item_custody");
        assert!(custody.contains("runtime_custody_pool_route_for_shared_dataset("));
        assert!(!custody.contains(".await"));
        for name in [
            "runtime_custody_pool_route_for_shared_dataset",
            "runtime_custody_pool_route_for_key_envelope",
            "runtime_custody_pool_for_key_envelope_cached",
        ] {
            // Sync: it cannot wait on Carrier.
            assert!(
                RUNTIME_SOURCE.contains(&format!("pub(crate) fn {name}(")),
                "{name}"
            );
            let body = fn_body(RUNTIME_SOURCE, name);
            for forbidden in [
                ".await",
                "home_pool_resolver",
                "refresh_known_pools",
                "runtime_custody_pool_for_key_envelope(",
            ] {
                assert!(!body.contains(forbidden), "{name} must not use {forbidden}");
            }
        }
        assert!(fn_body(
            RUNTIME_SOURCE,
            "runtime_custody_pool_route_for_key_envelope"
        )
        .contains("runtime_custody_pool_for_key_envelope_cached("));
    }
}

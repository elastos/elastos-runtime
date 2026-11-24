//! AUDIT-REPRO J2 (red, no fix): a channel-granted copy on another Home.
//! Fixture as `chain_granted_access_downloads_and_opens_without_a_purchase`.

use super::*;

async fn granted_copy() -> (TwoRuntimeMarketAsset, AdoptionBuyer) {
    reset_mock_chain_raw_requests();
    reset_mock_protected_content_chain_mode();
    reset_mock_protected_content_purchase_fixture();
    set_mock_protected_content_purchase_native();
    let asset = publish_two_runtime_market_asset().await;
    let buyer = adoption_buyer(&asset).await;
    let item = adoption_buy_offer_body(&asset.package)["item"].clone();
    let (_, downloaded) = post_library(
        buyer.app.clone(),
        &buyer.library_token,
        "download_owned_copy",
        json!({ "item": item }),
    )
    .await;
    assert_eq!(downloaded["status"], "ok", "{downloaded}");
    assert_eq!(downloaded["data"]["acquisition"], "granted");
    (asset, buyer)
}

/// J2-F7 (and the root of J2-F1). A held Granted copy reaches Explore only
/// through the market catalog: the shelf leaves Granted and Asset listings
/// out (protected_content_runtime.rs:13175-13182), and the catalog is one
/// newest-first page of `MARKET_CATALOG_PAGE_LIMIT` (60) rows. Once the index
/// holds 60 newer items, this person's own copy is on no Explore surface.
#[tokio::test]
async fn audit_j2_f7_a_held_granted_copy_is_listed_by_runtime_not_only_by_the_catalog_page() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let (asset, buyer) = granted_copy().await;
    let (_, shelf) = post_library(
        buyer.app.clone(),
        &buyer.library_token,
        "list_runtime_custody",
        json!({}),
    )
    .await;
    assert_eq!(shelf["status"], "ok", "{shelf}");
    let listed = shelf["data"]["listings"].as_array().is_some_and(|rows| {
        rows.iter()
            .any(|row| row["mint_id"] == asset.package.mint_id)
    });
    assert!(
        listed,
        "this person's held copy must be listed by Runtime, not only by the index's first page: {shelf}"
    );
}

/// Independent audit F9. A Granted copy reads `purchased` for good
/// (`runtime_custody_listing_access_state`: `Granted { .. } => true`,
/// protected_content_runtime.rs:13415). After the channel access ends the
/// open is refused at its finalized grant check (green:
/// `chain_granted_access_downloads_and_opens_without_a_purchase`), but the
/// record stays, so the card and the catalog join keep saying Open.
#[tokio::test]
async fn audit_f9_a_lapsed_grant_card_goes_back_to_buy() {
    let _guard = protected_content_gateway_mock_test_guard().lock().await;
    let (asset, buyer) = granted_copy().await;
    let player_token = projection_launch_token_for_authority_context(
        buyer.runtime.path(),
        ELACITY_PLAYER_CAPSULE_ID_FOR_TEST,
        &buyer.buyer,
    );
    // The channel access ended.
    set_mock_protected_content_purchase_access_denied();
    let (_, refused) = post_library(
        buyer.app.clone(),
        &player_token,
        "open_viewer",
        json!({"mint_id": asset.package.mint_id}),
    )
    .await;
    assert_eq!(refused["status"], "error", "{refused}");
    assert_eq!(
        refused["message"],
        crate::protected_content_runtime::RUNTIME_CUSTODY_OPEN_DENIED_MESSAGE,
        "precondition: the open is refused at the grant check"
    );
    let index = crate::protected_content_runtime::runtime_custody_listing_chain_index(
        buyer.runtime.path(),
        &buyer.buyer.principal_id,
    )
    .unwrap();
    let states: Vec<&str> = index
        .iter()
        .map(|entry| entry.access_state.as_str())
        .collect();
    assert!(
        !states.contains(&"purchased"),
        "after the chain refused the grant, the copy must not still read purchased: {states:?}"
    );
}

//! AUDIT-REPRO J2 (red, no fix): the market catalog and a card's listing
//! read on another Home.

use super::listing_object::*;
use super::*;

/// J2-F2 (= independent audit F5). The index stores a row before it has read
/// the item's `metadata.json` (provide lag, a fetch failure, null metadata:
/// the live 44fe/9c95/994c rows had `kid = null`). The catalog drops such a
/// row (`content_access_id(..)?`, gateway_marketplace_directory.rs:539),
/// although nothing downstream reads the catalog's KID: the page never reads
/// `contentAccessId` and the card's access read sends `{ledger, token_id}`.
/// The item then reaches no other Home's Explore. (Pinned the other way by
/// `test_market_catalog_drops_what_it_cannot_use`, "No content id".)
#[test]
fn audit_j2_f2_a_minted_row_the_index_has_not_read_yet_still_reaches_explore() {
    let usdc = vec![(
        "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".to_string(),
        6u8,
    )];
    let payload = json!({ "data": { "result": { "data": [{
        "contractAddress": "0x1431cf1924654df027d9d7184a9e721b42a10ce4",
        "hexTokenID": "0x9",
        "tokenURI": "ipfs://bafybeigvtuy27cqal6mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/metadata.json",
        "name": "1717998-uhd_3840_2160_25fps",
        "metadata": null
    }] } } });
    let items = market_catalog_from_payload(&payload, &usdc).unwrap();
    assert_eq!(
        items.len(),
        1,
        "a row with a ledger and a token but no KID yet must stay on Explore"
    );
}

/// J2-F4. Inside the finality window a card's listing read asks the head
/// whether the item is minted (`classify_market_listing_finality`). Any
/// error of that read is answered `unbound` (404, gateway_marketplace_listing
/// .rs:896-931), which the page treats as final (market-access.js
/// FINAL_LISTING_CODES), so one failed head read leaves the card
/// "Unavailable" for the life of the page. (Pinned the other way by
/// `listing_object_stays_unbound_when_the_head_cannot_say_otherwise`.)
#[tokio::test]
async fn audit_j2_f4_a_failed_head_read_answers_unavailable_not_unbound() {
    let chain = ListingChainFixture {
        bound_at_head: true,
        item_finality_unavailable: true,
        ..ListingChainFixture::default()
    };
    let env = ListingEnv::new(chain, ListingContentFixture::default()).await;
    let (status, answer) = env.post(item_start()).await;
    assert_eq!(
        (status, answer.clone()),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "code": "unavailable" })
        ),
        "a head read that failed is not a final `unbound`: {answer}"
    );
}

/// J2-F8. The chain already binds the KID to the item and grants this
/// account access, yet a listing read whose document no reachable Home
/// serves answers `no_holder` (the card says "Unavailable") instead of the
/// chain's access answer: the access state is reached only after a Carrier
/// read of the item's folder (gateway_marketplace_listing.rs:439-482).
/// Overlaps STAB S3 cause 1 (`stab_s3_listing_with_unproven_kid_asks_the_chain_by_item_and_answers_held_access`),
/// which is the same gate reached through an unreadable document.
#[tokio::test]
async fn audit_j2_f8_a_chain_bound_kid_answers_access_without_the_document() {
    let mut chain = chain_with_item(LISTING_FOLDER, LISTING_KID);
    chain.has_access = true;
    let mut content = ListingContentFixture::default();
    content
        .holder_answers
        .insert("metadata.json".to_string(), "carrier_fetch_unavailable");
    let env = ListingEnv::new(chain, content).await;
    let (status, object) = env.post(kid_start(LISTING_KID)).await;
    assert_eq!(status, StatusCode::OK, "{object}");
    assert_eq!(object["access_state"], "purchased", "{object}");
}

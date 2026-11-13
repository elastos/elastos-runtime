//! STAB-REPRO S3: an Explore item that the chain grants this account (a
//! channel subscription, say) shows Buy rather than Open. Fixed under D4
//! (STAB-23), with the ADV-19 guard on what an unbound row may say.
//!
//! `market_listing_access_state` asks the chain only by KID
//! (`resolve_protected_content_purchase_access`). When the KID is unproven
//! (the item's document cannot be read from this Home, or the KID's
//! finalized binding cannot be read) it returns `("available", unknown)`
//! without asking the chain anything, although the item-keyed read
//! `resolve_protected_content_item_access` (R50, `AuthorityGateway.hasAccess`)
//! exists for exactly that case and needs no KID.

use super::listing_object::*;
use super::*;

#[tokio::test]
async fn stab_s3_listing_with_unproven_kid_asks_the_chain_by_item_and_answers_held_access() {
    // The chain binds the item and grants this account access to it.
    let mut chain = chain_with_item(LISTING_FOLDER, LISTING_KID);
    chain.has_access = true;
    // This Home cannot read the item's document now, so the KID stays
    // unproven (`listing_object_answers_unknown_readability_when_the_document_is_unreadable`).
    let mut content = content_with(
        LISTING_FOLDER,
        "metadata.json",
        &elastos_v1_metadata(LISTING_KID),
    );
    content.unreadable_paths.push("metadata.json".to_string());
    let env = ListingEnv::new(chain, content).await;

    let (status, object) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{object}");
    assert_eq!(object["item"]["kid"], Value::Null, "precondition: {object}");

    let asked_by_item = env
        .chain
        .lock()
        .unwrap()
        .requests
        .iter()
        .filter(|request| request["op"] == "resolve_protected_content_item_access")
        .count();
    assert_eq!(
        (object["access_state"].as_str(), asked_by_item),
        (Some("purchased"), 1),
        "an account the chain grants the item must be answered as holding it, \
         asked by item when the KID is unproven: {object}"
    );
}

/// D4-A guard (ADV-19, DKMS-14): a row whose KID-to-item binding the chain
/// has not proven -- unbound at the finalized block, or bound at the head
/// only -- is never answered with an `access_state`, whatever the chain says
/// of this account's access. The page then offers neither Open nor an
/// enabled Buy: `unbound` is final, `pending_finality` waits.
#[tokio::test]
async fn guard_an_unbound_row_is_never_answered_as_available_or_held() {
    for (bound_at_head, status, code) in [
        (false, StatusCode::NOT_FOUND, "unbound"),
        (true, StatusCode::CONFLICT, "pending_finality"),
    ] {
        let chain = ListingChainFixture {
            has_access: true,
            bound_at_head,
            ..ListingChainFixture::default()
        };
        let env = ListingEnv::new(chain, ListingContentFixture::default()).await;
        let (got, answer) = env.post(item_start()).await;
        assert_eq!(
            (got, answer["code"].as_str()),
            (status, Some(code)),
            "{answer}"
        );
        assert!(
            answer.get("access_state").is_none(),
            "an unproven binding must carry no access answer: {answer}"
        );
    }
}

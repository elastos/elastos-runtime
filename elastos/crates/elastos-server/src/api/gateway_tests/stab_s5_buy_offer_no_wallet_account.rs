//! STAB-REPRO S5 (no fix): "The purchase did not finish." on Buy.
//!
//! Live (2026-11-17): the only `buy_offer` presses on any demo Home today were
//! on Home-6 (62193) at 08:01:05Z and 08:01:24Z (audit `object.provider.failed`).
//! Each one ended in `resolve_runtime_custody_buyer_account` with
//! `reason="no_transaction_default_for_chain_namespace" wallet_accounts_total=0`:
//! that Home has no Wallet account, so Runtime refused before any Wallet
//! request and before any purchase record was written.
//!
//! This pins the producer side of that answer: a typed refusal, carried as
//! `wallet_default`, under the generic `library_error` code. It passes today.
//! The red half is the page: `stab_s5_buy_offer_wallet_default.test.mjs`
//! shows `parseBuyOfferAnswer` reads this exact answer as the generic
//! `failed`, which the sheet words as "The purchase did not finish."

use super::listing_object::*;
use super::*;

#[tokio::test]
async fn stab_s5_buy_offer_without_a_wallet_account_is_a_typed_wallet_default_refusal() {
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    // Home-6 as it is live: no Wallet account and no transaction default.
    env.wallet.defaults.lock().await.clear();
    env.wallet.accounts.lock().await.clear();

    let body = json!({
        "item": {
            "chain_namespace": "eip155:8453",
            "network": "base-mainnet",
            "ledger": LISTING_LEDGER,
            "token_id": LISTING_TOKEN_ID,
            "kid": LISTING_KID,
        },
        "asset_uri": format!("elastos://{LISTING_FOLDER}"),
        "seller": LISTING_NATIVE_SELLER,
        "agreed": {
            "price": LISTING_NATIVE_PRICE,
            "pay_token": LISTING_NATIVE_PAY_TOKEN,
            "quantity": "0x1",
        },
    });
    let (_, answer) = env.buy_offer(body).await;
    println!("stab_s5 buy_offer answer: {answer}");

    // Nothing was raised and nothing was recorded.
    assert_eq!(env.wallet_transaction_requests().await, 0);
    assert!(env.market_purchase().is_none());
    // The answer the page receives.
    assert_eq!(answer["status"], "error", "{answer}");
    assert_eq!(answer["code"], "library_error", "{answer}");
    assert_eq!(
        answer["message"], "Runtime custody purchase is denied before buy",
        "{answer}"
    );
    assert_eq!(
        answer["wallet_default"]["reason"], "no_transaction_default_for_chain_namespace",
        "{answer}"
    );
    assert_eq!(
        answer["wallet_default"]["chain_namespace"], "eip155:8453",
        "{answer}"
    );
    assert!(answer.get("buy_progress").is_none(), "{answer}");
}

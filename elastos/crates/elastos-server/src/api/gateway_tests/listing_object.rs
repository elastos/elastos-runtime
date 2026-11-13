//! The `ListingObject`: one object, whichever common identifier started it,
//! and only after the three-leg binding check (D15) holds.
//!
//! The chain and content providers are stubbed here rather than through the
//! shared mocks, because every test below is about what the chain and the
//! folder say about ONE item -- and the substitutions this check exists to
//! refuse (a copied folder, a KID lifted from another item, a document naming
//! the wrong KID) are each a different answer from one of those two stubs.

use super::*;

pub(super) const LISTING_LEDGER: &str = "0x0ebac909d31ef0074495e752c0cf4ea49ba13c41";
pub(super) const LISTING_TOKEN_ID: &str =
    "0x59e6d0307920cf2c216ea96905e05a4f453416e2d606e5dda8b84c82d5f10504";
pub(super) const LISTING_OTHER_TOKEN_ID: &str =
    "0x4096fe5aec3c6c021994a8dd3485b9cd58cb0d144687d28e4c4e948c154d5363";
pub(super) const LISTING_OPERATIVE: &str = "0xc0de393e925f1c1e620d347f18594d783c3104e7";
pub(super) const LISTING_OTHER_OPERATIVE: &str = "0x8b0ae79abf9b41dfe8aabf3c791dd52fe7713530";
pub(super) const LISTING_KID: &str = "0xfacabcf1ea699570a8409db83779ae5c";
pub(super) const LISTING_OTHER_KID: &str = "0x9602f6663c1d70fe5e8c696af9437088";
/// The token's own metadata folder: what `tokenURI(operative, 1)` names.
pub(super) const LISTING_FOLDER: &str = "QmcKGaG3CsCw93bc5JgDehrQTM7h1LMF1BQQiLXCvPvfz2";
/// A byte-for-byte copy of someone's folder, pinned under another CID.
pub(super) const LISTING_COPY_FOLDER: &str = "QmXoiArK125qiKmneDN3znp7FsXzvyMZrEWf6DWEuxwK9o";
pub(super) const LISTING_OTHER_FOLDER: &str = "QmZ9TAshFxddqNCCVk3SS2UjkGQMvaXLbwuap2HLSpp1ci";
/// A folder published before the shared document existed: `listing.json` only.
pub(super) const LISTING_LEGACY_FOLDER: &str =
    "bafybeibwzif2r5tn7z7cq4f5a2mmepmab4s4m5a2hqu5v4f4uzkd3t2u7m";
pub(super) const LISTING_COVER: &str = "QmdAtTaLgucnJtMM2HXZqndtqJ475vMKLycLHMkGcoue6n";
pub(super) const LISTING_SELLER: &str = "0xab5028bdbb0826ad6f1885478e421db677b0001a";
pub(super) const LISTING_PAY_TOKEN: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
pub(super) const LISTING_PAYMENT_PROCESSOR: &str = "0x00000000000000000000000000000000000000ff";
pub(super) const LISTING_FINALIZED_BLOCK: u64 = 36_000_123;
/// How far the stub's finalized block trails its head.
pub(super) const LISTING_FINALITY_LAG_SECS: u64 = 900;
/// The chain op only the listing read may ask.
pub(super) const ITEM_FINALITY_OP: &str = "classify_protected_content_item_finality";
pub(super) const LISTING_NATIVE_SELLER: &str = "0x34daf31b99b5a59ceb18e424dbc112fa6e5f3dc3";
pub(super) const LISTING_NATIVE_PAY_TOKEN: &str = "0x0000000000000000000000000000000000000000";

pub(super) fn listing_token_uri(folder: &str) -> String {
    format!("ipfs://{folder}/0000000000000000000000000000000000000000000000000000000000000001.json")
}

pub(super) fn identity(tag: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("elastos.protected-content.{tag}/v1"))
}

/// The shared `metadata.json` an ElastOS mint writes, current scheme, all
/// four identities present. There is no `manifest.json` beside it.
pub(super) fn elastos_v1_metadata(kid: &str) -> Value {
    json!({
        "schema": "elacity.asset/v1",
        "name": "The giants",
        // A real description has lines. The object carries it on one.
        "description": "A film about giants.\nSecond line.",
        "image": format!("ipfs://{LISTING_COVER}"),
        "contentType": "Video",
        "media": {
            "uri": "ipfs://QmdAtTaLgucnJtMM2HXZqndtqJ475vMKLycLHMkGcoue6n",
            "contentType": "Video",
            "mimeType": "video/mp4",
            "protectionType": ["cenc:elastos-pq-hybrid-threshold-v1"],
        },
        "asset": {
            "cid": "QmdAtTaLgucnJtMM2HXZqndtqJ475vMKLycLHMkGcoue6n",
            "mimeType": "video/mp4",
            "protections": [{
                "protectionType": "cenc:elastos-pq-hybrid-threshold-v1",
                "threshold": 2,
                "node_count": 3,
                "rights_policy_identity_base64": identity("rights-policy-identity"),
                "key_envelope_identity_base64": identity("key-envelope-identity"),
                "content_key_commitment_base64": identity("content-key-commitment"),
                "content_identity_base64": identity("encrypted-content"),
            }],
            "kid": kid.trim_start_matches("0x"),
        },
        "properties": {
            "publisher": LISTING_SELLER,
            "kid": kid,
        },
        "kid": kid,
    })
}

/// What an ela.city (Lit) mint writes: no `asset`, a bare-hex `kid`, and the
/// protection named only in `media.protectionType`.
pub(super) fn lit_metadata(kid: &str) -> Value {
    json!({
        "name": "Tradingviewww",
        "description": "",
        "image": "",
        "media": {
            "uri": "ipfs://QmPczy2mXWn2eVeN4e7wsScLEaKgbrEu2BUBGrniNAThFN",
            "contentType": "video",
            "protectionType": ["cenc:lit-aes-gcm-v3"],
        },
        "properties": { "publisher": LISTING_SELLER },
        "kid": kid.trim_start_matches("0x"),
    })
}

#[derive(Default)]
pub(super) struct ListingChainFixture {
    /// `(ledger, token_id)` -> `(operative, tokenURI)`.
    pub(super) items: HashMap<(String, String), (String, String)>,
    /// `kid` -> `(ledger, token_id)`.
    pub(super) bindings: HashMap<String, (String, String)>,
    /// What both access reads answer: by KID
    /// (`resolve_protected_content_purchase_access`) and by item
    /// (`resolve_protected_content_item_access`, R50).
    pub(super) has_access: bool,
    /// Neither access read can answer at all.
    pub(super) access_unanswered: bool,
    /// Overrides the default offers (one ERC-20, one native).
    pub(super) offers: Option<Value>,
    /// The node refuses every buy broadcast as a revert.
    pub(super) revert_broadcast: bool,
    /// The node refuses every broadcast with this sentence of its own.
    pub(super) broadcast_error: Option<String>,
    /// Every transaction receipt reads as mined and reverted (`status` 0x0).
    pub(super) revert_receipt: bool,
    /// Run once, the next time the named op is asked -- to act as another
    /// driver of the same purchase between two steps of this one.
    pub(super) hooks: HashMap<&'static str, Box<dyn FnOnce() + Send>>,
    /// The market source (`describe_protected_content_creator_mint_source`)
    /// cannot be read.
    pub(super) mint_source_unavailable: bool,
    /// The purchase-plan read yields for a while first, so two presses
    /// interleave between "no attempt recorded" and recording one.
    pub(super) slow_purchase_read: bool,
    /// `resolve_protected_content_kid_binding` cannot answer (a rate-limited
    /// RPC, say).
    pub(super) kid_binding_unavailable: bool,
    /// Neither `resolve_protected_content_item_offers` (the listing's read)
    /// nor `resolve_protected_content_purchase` (the buy's read of the same
    /// terms) can answer.
    pub(super) offers_unavailable: bool,
    /// What the head classification read answers for any item: minted and
    /// not final yet (`true`), or not there at the head either.
    pub(super) bound_at_head: bool,
    /// The head classification read cannot answer.
    pub(super) item_finality_unavailable: bool,
    /// The `(ledger, token_id)` the head classification read names in its
    /// answer, when not the one it was asked about.
    pub(super) item_finality_names: Option<(String, String)>,
    /// This op is recorded and then never answered, the way a stalled RPC
    /// leaves a read hanging.
    pub(super) never_answers: Option<&'static str>,
    pub(super) requests: Vec<Value>,
}

impl ListingChainFixture {
    /// Every request the head classification read received.
    pub(super) fn item_finality_requests(&self) -> Vec<Value> {
        self.requests
            .iter()
            .filter(|request| request["op"] == ITEM_FINALITY_OP)
            .cloned()
            .collect()
    }
}

pub(super) fn default_listing_offers() -> Value {
    // What the real op sends: the ERC-20 offer names its processor, the
    // native one carries no key at all.
    json!([
        {
            "seller": LISTING_SELLER,
            "quantity": "0x2710",
            "price": "0xf4240",
            "pay_token": LISTING_PAY_TOKEN,
            "payment_processor": LISTING_PAYMENT_PROCESSOR,
        },
        {
            "seller": LISTING_NATIVE_SELLER,
            "quantity": "0x1",
            "price": "0x2386f26fc10000",
            "pay_token": LISTING_NATIVE_PAY_TOKEN,
        },
    ])
}

/// Where a market buy is sent, and what it calls. Distinct from every other
/// fixture's, so no two tests ever sign the same transaction bytes.
pub(super) const LISTING_MARKET_CONTRACT: &str = "0x00000000000000000000000000000000000000a1";
pub(super) const LISTING_MARKET_BUY_DATA: &str = "0x6d61726b65745f627579";
pub(super) const LISTING_MARKET_APPROVE_DATA: &str = "0x6d61726b65745f617070726f7665";

impl ListingChainFixture {
    /// `resolve_protected_content_purchase`, read from the same offers the
    /// listing object is built from: one fixture, both views of the market.
    fn purchase_answer(&self, request: &Value) -> Value {
        let text = |key: &str| {
            request
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let Some((operative, _)) = self.items.get(&(text("ledger"), text("token_id"))) else {
            return listing_stub_error("unbound_protected_content_item");
        };
        let offers = self.offers.clone().unwrap_or_else(default_listing_offers);
        let offer = offers.as_array().into_iter().flatten().find(|offer| {
            offer["seller"]
                .as_str()
                .is_some_and(|seller| seller.eq_ignore_ascii_case(&text("seller")))
                && offer["quantity"] != "0x0"
        });
        let Some(offer) = offer else {
            return listing_stub_error("protected_content_verified_listing_unavailable");
        };
        let price = offer["price"].as_str().unwrap_or_default();
        let pay_token = offer["pay_token"].as_str().unwrap_or_default();
        let native = pay_token == LISTING_NATIVE_PAY_TOKEN;
        let steps = if native {
            json!([{
                "stage": "buy",
                "to": LISTING_MARKET_CONTRACT,
                "value": price,
                "data": LISTING_MARKET_BUY_DATA,
            }])
        } else {
            json!([
                {
                    "stage": "approval",
                    "to": pay_token,
                    "value": "0x0",
                    "data": LISTING_MARKET_APPROVE_DATA,
                },
                {
                    "stage": "buy",
                    "to": LISTING_MARKET_CONTRACT,
                    "value": "0x0",
                    "data": LISTING_MARKET_BUY_DATA,
                },
            ])
        };
        json!({
            "status": "ok",
            "data": {
                "schema": "elastos.chain.protected-content-purchase/v1",
                "network": text("network"),
                "purchase_quantity": "0x1",
                "verified_listing": {
                    "chain_id": 8453,
                    "seller": text("seller").to_ascii_lowercase(),
                    "ledger": text("ledger"),
                    "token_id": text("token_id"),
                    "operative": operative,
                    "available_quantity": offer["quantity"],
                    "price": price,
                    "pay_token": pay_token,
                    "payment_processor": offer.get("payment_processor").cloned().unwrap_or(Value::Null),
                },
                "steps": steps,
            }
        })
    }
}

#[derive(Default)]
pub(super) struct ListingContentFixture {
    on_fetch: Option<Box<dyn FnOnce() + Send>>,
    /// `cid` -> `path` -> bytes.
    pub(super) folders: HashMap<String, HashMap<String, Vec<u8>>>,
    /// Paths the content plane fails to read for a reason other than absence.
    pub(super) unreadable_paths: Vec<String>,
    /// Paths this Home lacks, with the code Carrier availability answered
    /// for them after the local miss.
    pub(super) holder_answers: HashMap<String, &'static str>,
    /// Paths whose read never answers.
    pub(super) never_answers_paths: Vec<String>,
    /// Paths the content plane fails with exactly this message, as a live
    /// Home logged it (DEMO-ISSUES B).
    pub(super) failure_messages: HashMap<String, String>,
    pub(super) requested: Vec<(String, String)>,
    /// Whether each request asked only the holders known now, in order.
    pub(super) known_holders_only: Vec<bool>,
    /// The byte range each request carried, in request order.
    pub(super) ranges: Vec<Value>,
}

pub(super) struct ListingChainStub(Arc<std::sync::Mutex<ListingChainFixture>>);
pub(super) struct ListingContentStub(Arc<std::sync::Mutex<ListingContentFixture>>);

pub(super) fn listing_stub_error(code: &str) -> Value {
    json!({ "status": "error", "code": code, "message": format!("stub: {code}") })
}

#[async_trait::async_trait]
impl Provider for ListingChainStub {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider("raw requests only".into()))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["elastos"]
    }

    fn name(&self) -> &'static str {
        "listing-chain-stub"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let slow = request.get("op").and_then(Value::as_str)
            == Some("resolve_protected_content_purchase")
            && self.0.lock().unwrap().slow_purchase_read;
        if slow {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let hangs = {
            let mut fixture = self.0.lock().unwrap();
            let hangs = fixture.never_answers.is_some()
                && request.get("op").and_then(Value::as_str) == fixture.never_answers;
            if hangs {
                fixture.requests.push(request.clone());
            }
            hangs
        };
        if hangs {
            std::future::pending::<()>().await;
        }
        // Everything a Wallet effect needs from the chain (gas, nonce,
        // broadcast, receipt) is the shared mock's; this stub owns only what
        // the market itself says.
        match self.answer(request) {
            Some(answer) => Ok(answer),
            None => MockChainProvider.send_raw(request).await,
        }
    }
}

impl ListingChainStub {
    fn answer(&self, request: &Value) -> Option<Value> {
        let mut fixture = self.0.lock().unwrap();
        fixture.requests.push(request.clone());
        if let Some(hook) = request
            .get("op")
            .and_then(Value::as_str)
            .and_then(|op| fixture.hooks.remove(op))
        {
            hook();
        }
        let text = |key: &str| {
            request
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        Some(match request.get("op").and_then(Value::as_str) {
            Some("resolve_protected_content_purchase") if fixture.offers_unavailable => {
                listing_stub_error("upstream_rpc_error")
            }
            Some("resolve_protected_content_purchase") => fixture.purchase_answer(request),
            Some("receipt") if fixture.revert_receipt => json!({
                "status": "ok",
                "data": {
                    "network": text("network"),
                    "hash": text("hash"),
                    "receipt": {
                        "transactionHash": text("hash"),
                        "status": "0x0",
                        "blockNumber": "0x2a",
                        "logs": [],
                    }
                }
            }),
            Some("broadcast_transaction") if fixture.broadcast_error.is_some() => json!({
                "status": "error",
                "code": "upstream_rpc_error",
                "message": fixture.broadcast_error.clone().unwrap_or_default(),
            }),
            Some("broadcast_transaction") if fixture.revert_broadcast => listing_stub_error(
                "upstream_rpc_error: EVM RPC request rejected: eth_sendRawTransaction: code 3: execution reverted",
            ),
            Some("describe_protected_content_creator_mint_source")
                if fixture.mint_source_unavailable =>
            {
                listing_stub_error("upstream_rpc_error")
            }
            Some("describe_protected_content_creator_mint_source") => json!({
                "status": "ok",
                "data": {
                    "schema": "elastos.chain.protected-content-creator-mint-source/v1",
                    "network": "base-mainnet",
                    "chain_namespace": "eip155:8453",
                    "pay_tokens": [{ "symbol": "USDC", "address": LISTING_PAY_TOKEN, "decimals": 6 }],
                    "abi": "elacity_mint_v1",
                    "function": "mint(string,uint16,bytes,bytes)"
                }
            }),
            Some("resolve_protected_content_item") => {
                match fixture.items.get(&(text("ledger"), text("token_id"))) {
                    Some((operative, token_uri)) => json!({
                        "status": "ok",
                        "data": {
                            "schema": "elastos.chain.protected-content-item/v1",
                            "network": text("network"),
                            "chain_id": 8453,
                            "ledger": text("ledger"),
                            "token_id": text("token_id"),
                            "operative": operative,
                            "token_uri": token_uri,
                            "finalized_block_number": LISTING_FINALIZED_BLOCK,
                        }
                    }),
                    None => listing_stub_error("unbound_protected_content_item"),
                }
            }
            Some("resolve_protected_content_kid_binding") if fixture.kid_binding_unavailable => {
                listing_stub_error("upstream_rpc_error")
            }
            Some("resolve_protected_content_kid_binding") => {
                match fixture.bindings.get(&text("content_access_id")) {
                    Some((ledger, token_id)) => json!({
                        "status": "ok",
                        "data": {
                            "schema": "elastos.chain.protected-content-kid-binding/v1",
                            "network": text("network"),
                            "chain_id": 8453,
                            "content_access_id": text("content_access_id"),
                            "ledger": ledger,
                            "token_id": token_id,
                            "finalized_block_number": LISTING_FINALIZED_BLOCK,
                        }
                    }),
                    None => listing_stub_error("unbound_protected_content_kid"),
                }
            }
            Some("resolve_protected_content_item_offers") if fixture.offers_unavailable => {
                listing_stub_error("upstream_rpc_error")
            }
            Some("resolve_protected_content_item_offers") => {
                match fixture.items.get(&(text("ledger"), text("token_id"))) {
                    Some((operative, _)) => json!({
                        "status": "ok",
                        "data": {
                            "schema": "elastos.chain.protected-content-item-offers/v1",
                            "network": text("network"),
                            "chain_id": 8453,
                            "ledger": text("ledger"),
                            "token_id": text("token_id"),
                            "operative": operative,
                            "finalized_block_number": LISTING_FINALIZED_BLOCK,
                            "truncated": false,
                            "offers": fixture.offers.clone().unwrap_or_else(default_listing_offers),
                        }
                    }),
                    None => listing_stub_error("unbound_protected_content_item"),
                }
            }
            Some(ITEM_FINALITY_OP) if fixture.item_finality_unavailable => {
                listing_stub_error("insufficient_protected_content_item_finality_observations")
            }
            Some(ITEM_FINALITY_OP) => {
                let head_at = crate::auth::now_ts().saturating_sub(2);
                let echo = |key: &str| request.get(key).cloned().unwrap_or(Value::Null);
                let (ledger, token_id) = match &fixture.item_finality_names {
                    Some((ledger, token_id)) => (json!(ledger), json!(token_id)),
                    None => (echo("ledger"), echo("token_id")),
                };
                json!({
                    "status": "ok",
                    "data": {
                        "schema": "elastos.chain.protected-content-item-finality/v1",
                        "network": text("network"),
                        "chain_id": 8453,
                        "ledger": ledger,
                        "token_id": token_id,
                        "content_access_id": echo("content_access_id"),
                        "bound_at_head": fixture.bound_at_head,
                        "head_block_number": LISTING_FINALIZED_BLOCK + 450,
                        "head_block_timestamp": head_at,
                        "finalized_block_number": LISTING_FINALIZED_BLOCK,
                        "finalized_block_timestamp": head_at - LISTING_FINALITY_LAG_SECS,
                    }
                })
            }
            Some("resolve_protected_content_item_access") if fixture.access_unanswered => {
                listing_stub_error("stale_protected_content_purchase_access_observation")
            }
            Some("resolve_protected_content_item_access") => json!({
                "status": "ok",
                "data": {
                    "schema": "elastos.chain.protected-content-item-access/v1",
                    "request_id": text("request_id"),
                    "network": text("network"),
                    "chain_id": 8453,
                    "wallet": text("wallet").to_ascii_lowercase(),
                    "ledger": text("ledger").to_ascii_lowercase(),
                    "token_id": text("token_id").to_ascii_lowercase(),
                    "has_access": fixture.has_access,
                    "finalized_block_number": LISTING_FINALIZED_BLOCK,
                    "finalized_block_hash": format!("0x{}", hex::encode([0x44; 32])),
                    "finalized_block_timestamp": crate::auth::now_ts().saturating_sub(5),
                    "observed_at": crate::auth::now_ts(),
                }
            }),
            Some("resolve_protected_content_purchase_access") if fixture.access_unanswered => {
                listing_stub_error("stale_protected_content_purchase_access_observation")
            }
            Some("resolve_protected_content_purchase_access") => json!({
                "status": "ok",
                "data": {
                    "schema": "elastos.chain.protected-content-purchase-access/v1",
                    "request_id": text("request_id"),
                    "network": text("network"),
                    "chain_id": 8453,
                    "wallet": text("wallet").to_ascii_lowercase(),
                    "content_access_id": text("content_access_id").to_ascii_lowercase(),
                    "has_access": fixture.has_access,
                    "finalized_block_number": LISTING_FINALIZED_BLOCK,
                    "finalized_block_hash": format!("0x{}", hex::encode([0x44; 32])),
                    "finalized_block_timestamp": crate::auth::now_ts().saturating_sub(5),
                    "observed_at": crate::auth::now_ts(),
                }
            }),
            _ => return None,
        })
    }
}

#[async_trait::async_trait]
impl Provider for ListingContentStub {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider("raw requests only".into()))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["content"]
    }

    fn name(&self) -> &'static str {
        "listing-content-stub"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        let hangs = {
            let fixture = self.0.lock().unwrap();
            let path = request
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or_default();
            fixture.never_answers_paths.iter().any(|hung| hung == path)
        };
        if hangs {
            std::future::pending::<()>().await;
        }
        let mut fixture = self.0.lock().unwrap();
        let cid = request
            .get("cid")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let path = request
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        fixture.requested.push((cid.clone(), path.clone()));
        if let Some(hook) = fixture.on_fetch.take() {
            hook();
        }
        fixture
            .ranges
            .push(request.get("range").cloned().unwrap_or(Value::Null));
        fixture
            .known_holders_only
            .push(request.get("known_holders_only") == Some(&Value::Bool(true)));
        if fixture.unreadable_paths.contains(&path) {
            return Ok(listing_stub_error("cat_failed: gateway timeout"));
        }
        if let Some(message) = fixture.failure_messages.get(&path) {
            return Ok(json!({
                "status": "error",
                "code": "fetch_failed",
                "message": message,
            }));
        }
        if let Some(code) = fixture.holder_answers.get(&path) {
            // The content plane's own words after a local miss.
            return Ok(json!({
                "status": "error",
                "code": "fetch_failed",
                "message": format!(
                    "content fetch failed: block not found locally; availability fetch failed: \
                     availability fetch failed ({code}): Carrier content fetch failed: \
                     remote content provider fetch failed: this Home does not share this content"
                ),
            }));
        }
        // A folder no one here holds is no answer about its files: nothing
        // can be read from it, which may be slowness. Only a held folder
        // answers that it lacks a file.
        let Some(files) = fixture.folders.get(&cid) else {
            return Ok(listing_stub_error("cat_failed: no holder answered in time"));
        };
        let bytes = files.get(&path).cloned();
        Ok(match bytes {
            Some(bytes) => json!({
                "status": "ok",
                "data": { "data": base64::engine::general_purpose::STANDARD.encode(bytes) }
            }),
            None => listing_stub_error("not_found"),
        })
    }
}

pub(super) struct ListingEnv {
    state: GatewayState,
    pub(super) _dir: tempfile::TempDir,
    pub(super) app: axum::Router,
    pub(super) token: String,
    pub(super) authority: TestPasskeyAuthority,
    pub(super) wallet: Arc<MockWalletProvider>,
    pub(super) buyer_address: String,
    pub(super) chain: Arc<std::sync::Mutex<ListingChainFixture>>,
    pub(super) content: Arc<std::sync::Mutex<ListingContentFixture>>,
}

impl ListingEnv {
    pub(super) async fn new(chain: ListingChainFixture, content: ListingContentFixture) -> Self {
        let dir = tempfile::tempdir().unwrap();
        seed_test_browser_capsules(dir.path());
        let chain = Arc::new(std::sync::Mutex::new(chain));
        let content = Arc::new(std::sync::Mutex::new(content));
        let wallet = Arc::new(MockWalletProvider::default());
        let registry = Arc::new(ProviderRegistry::new());
        registry
            .register_sub_provider("wallet", wallet.clone())
            .await
            .unwrap();
        registry
            .register_sub_provider("chain", Arc::new(ListingChainStub(chain.clone())))
            .await
            .unwrap();
        registry
            .register_sub_provider("content", Arc::new(ListingContentStub(content.clone())))
            .await
            .unwrap();
        let state = GatewayState {
            provider_registry: Some(registry),
            collaboration_chat_product_port: None,
            collaboration_presence_product_port: None,
            carrier_endpoint: None,
            collaboration_discovery_service: None,
            browser_internet: Default::default(),
            identity_manager: Arc::new(std::sync::OnceLock::new()),
            cache_dir: dir.path().to_path_buf(),
            data_dir: dir.path().to_path_buf(),
        };
        let authority = passkey_authority_with_profile(dir.path(), "buyer");
        let token = app_token_for_authority(dir.path(), MARKETPLACE_CAPSULE_ID, &authority);
        let account_id = wallet
            .seed_managed_evm_account_for_principal(&authority.principal_id)
            .await;
        wallet.defaults.lock().await.push(json!({
            "schema": "elastos.wallet.default_account/v1",
            "principal_id": authority.principal_id,
            "chain_namespace": "eip155:8453",
            "intent": "transaction_intent",
            "account_id": account_id,
            "set_at": 10,
        }));
        Self {
            _dir: dir,
            app: gateway_router(state.clone()),
            state,
            token,
            authority,
            wallet,
            buyer_address: mock_managed_evm_address(1).unwrap(),
            chain,
            content,
        }
    }

    pub(super) async fn post(&self, body: Value) -> (StatusCode, Value) {
        let response = self
            .app
            .clone()
            .oneshot(
                test_browser_request("localhost:61180", "null")
                    .method("POST")
                    .uri("/api/apps/marketplace/listing")
                    .header("x-elastos-home-token", &self.token)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, payload)
    }

    pub(super) async fn buy_offer_with_token(
        &self,
        token: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        self.buy_offer_raw(token, serde_json::to_vec(&body).unwrap())
            .await
    }

    /// The request exactly as bytes, the way the page's `fetch` sends it.
    pub(super) async fn buy_offer_raw(&self, token: &str, bytes: Vec<u8>) -> (StatusCode, Value) {
        let response = self
            .app
            .clone()
            .oneshot(
                test_browser_request("localhost:61180", "null")
                    .method("POST")
                    .uri("/api/provider/object/buy_offer")
                    .header("x-elastos-home-token", token)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(bytes))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, payload)
    }

    pub(super) async fn buy_offer(&self, body: Value) -> (StatusCode, Value) {
        let token = self.token.clone();
        self.buy_offer_with_token(&token, body).await
    }

    /// Every transaction request the Wallet was ever asked to approve.
    pub(super) async fn wallet_transaction_requests(&self) -> usize {
        self.wallet
            .approvals
            .lock()
            .await
            .iter()
            .filter(|approval| {
                approval.get("intent").and_then(Value::as_str) == Some("transaction_intent")
            })
            .count()
    }

    pub(super) fn market_purchase(
        &self,
    ) -> Option<crate::protected_content_market::RuntimeMarketPurchaseRecord> {
        crate::protected_content_market::load_runtime_market_purchase(
            self._dir.path(),
            &self.authority.principal_id,
            &listing_market_item(),
        )
        .unwrap()
    }

    pub(super) fn content_paths(&self) -> Vec<String> {
        self.content
            .lock()
            .unwrap()
            .requested
            .iter()
            .map(|(_, path)| path.clone())
            .collect()
    }
}

pub(super) fn chain_with_item(folder: &str, kid: &str) -> ListingChainFixture {
    let mut chain = ListingChainFixture::default();
    chain.items.insert(
        (LISTING_LEDGER.to_string(), LISTING_TOKEN_ID.to_string()),
        (LISTING_OPERATIVE.to_string(), listing_token_uri(folder)),
    );
    chain.bindings.insert(
        kid.to_string(),
        (LISTING_LEDGER.to_string(), LISTING_TOKEN_ID.to_string()),
    );
    chain
}

pub(super) fn content_with(folder: &str, path: &str, document: &Value) -> ListingContentFixture {
    let mut content = ListingContentFixture::default();
    add_file(&mut content, folder, path, document);
    content
}

pub(super) fn add_file(
    content: &mut ListingContentFixture,
    folder: &str,
    path: &str,
    document: &Value,
) {
    content
        .folders
        .entry(folder.to_string())
        .or_default()
        .insert(path.to_string(), serde_json::to_vec(document).unwrap());
}

pub(super) fn item_start() -> Value {
    json!({ "start": { "item": { "ledger": LISTING_LEDGER, "token_id": LISTING_TOKEN_ID } } })
}

pub(super) fn kid_start(kid: &str) -> Value {
    json!({ "start": { "kid": kid } })
}

pub(super) fn token_uri_start(uri: &str) -> Value {
    json!({ "start": { "token_uri": uri } })
}

#[tokio::test]
async fn listing_object_from_item_kid_and_token_uri_is_identical() {
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;

    let mut objects = Vec::new();
    for (start, body) in [
        ("item", item_start()),
        ("kid", kid_start(LISTING_KID)),
        (
            "token_uri",
            token_uri_start(&listing_token_uri(LISTING_FOLDER)),
        ),
        (
            "token_uri",
            token_uri_start(&format!("elastos://{LISTING_FOLDER}")),
        ),
    ] {
        let (status, mut object) = env.post(body).await;
        assert_eq!(status, StatusCode::OK, "{start}: {object}");
        assert_eq!(object["source"]["start"], start);
        object["source"]["start"] = Value::Null;
        objects.push(object);
    }
    assert!(
        objects.windows(2).all(|pair| pair[0] == pair[1]),
        "{objects:#?}"
    );

    let object = &objects[0];
    assert_eq!(object["schema"], "elastos.marketplace.listing/v1");
    assert_eq!(
        object["item"],
        json!({
            "chain_namespace": "eip155:8453",
            "network": "base-mainnet",
            "ledger": LISTING_LEDGER,
            "token_id": LISTING_TOKEN_ID,
            "operative": LISTING_OPERATIVE,
            "kid": LISTING_KID,
        })
    );
    assert_eq!(
        object["asset"]["uri"],
        format!("elastos://{LISTING_FOLDER}")
    );
    assert_eq!(object["asset"]["title"], "The giants");
    assert_eq!(object["asset"]["cover_cid"], LISTING_COVER);
    assert_eq!(object["asset"]["category"], "video");
    assert_eq!(object["asset"]["mime_type"], "video/mp4");
    assert_eq!(
        object["offers"],
        json!([
            {
                "seller": LISTING_SELLER,
                "quantity": "0x2710",
                "price": "0xf4240",
                "pay_token": LISTING_PAY_TOKEN,
                "payment_processor": LISTING_PAYMENT_PROCESSOR,
            },
            {
                // R16: a native offer always carries the key, as `null`.
                "seller": LISTING_NATIVE_SELLER,
                "quantity": "0x1",
                "price": "0x2386f26fc10000",
                "pay_token": LISTING_NATIVE_PAY_TOKEN,
                "payment_processor": null,
            },
        ])
    );
    assert_eq!(object["access_state"], "available");
    assert_eq!(
        object["source"]["read_at_block"],
        format!("0x{LISTING_FINALIZED_BLOCK:x}")
    );
    assert!(object.get("offers_truncated").is_none());
    assert!(object.get("access_unknown").is_none());
}

/// An ERC-20 offer the chain named no processor for cannot be stated
/// honestly, so the object is unavailable rather than guessed at.
#[tokio::test]
async fn listing_object_refuses_an_erc20_offer_without_a_processor() {
    let mut chain = chain_with_item(LISTING_FOLDER, LISTING_KID);
    chain.offers = Some(json!([{
        "seller": LISTING_SELLER,
        "quantity": "0x2710",
        "price": "0xf4240",
        "pay_token": LISTING_PAY_TOKEN,
    }]));
    let env = ListingEnv::new(
        chain,
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let (status, answer) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
}

/// R17: a chain that cannot answer the access question is "unknown", never a
/// quiet "available".
#[tokio::test]
async fn listing_object_marks_access_unknown_when_the_chain_cannot_answer() {
    let mut chain = chain_with_item(LISTING_FOLDER, LISTING_KID);
    chain.access_unanswered = true;
    let env = ListingEnv::new(
        chain,
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let (status, object) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{object}");
    assert_eq!(object["access_state"], "available");
    assert_eq!(object["access_unknown"], true);

    // And a chain that answers "no" is a plain "available".
    env.chain.lock().unwrap().access_unanswered = false;
    let (_, object) = env.post(item_start()).await;
    assert_eq!(object["access_state"], "available");
    assert!(object.get("access_unknown").is_none());
}

#[tokio::test]
async fn listing_object_verifies_an_elastos_protection_without_manifest() {
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let (status, object) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{object}");
    assert_eq!(object["asset"]["readability"], "verified");
    // The shared document alone. `manifest.json` is ElastOS-only and no other
    // marketplace writes it, so asking for it would make a foreign-minted
    // ElastOS asset unreadable for no reason.
    let paths = env.content_paths();
    assert!(!paths.is_empty());
    assert!(
        paths.iter().all(|path| path == "metadata.json"),
        "only the shared document may be fetched: {paths:?}"
    );

    // The same scheme missing an identity is an entry this Home cannot open
    // from: unverified, not verified.
    let mut partial = elastos_v1_metadata(LISTING_KID);
    partial["asset"]["protections"][0]
        .as_object_mut()
        .unwrap()
        .remove("content_identity_base64");
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(LISTING_FOLDER, "metadata.json", &partial),
    )
    .await;
    let (status, object) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{object}");
    assert_eq!(object["asset"]["readability"], "unverified");

    // An older ElastOS scheme is still ElastOS: unverified, never foreign.
    let mut older = elastos_v1_metadata(LISTING_KID);
    older["asset"]["protections"] = json!([{
        "protectionType": "cenc:elastos-pq-hybrid-threshold-v0",
        "algorithm": "x",
        "shares": [],
    }]);
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(LISTING_FOLDER, "metadata.json", &older),
    )
    .await;
    let (_, object) = env.post(item_start()).await;
    assert_eq!(object["asset"]["readability"], "unverified");
}

/// Q-M1: a category is lowercased before it is bounded, so text that grows
/// when lowercased never comes out longer than the bound.
#[tokio::test]
async fn listing_object_bounds_the_category_after_lowercasing() {
    let mut document = elastos_v1_metadata(LISTING_KID);
    // `İ` lowercases to two scalar values.
    document["properties"]["category"] = json!("İ".repeat(256));
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(LISTING_FOLDER, "metadata.json", &document),
    )
    .await;
    let (status, object) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{object}");
    assert_eq!(
        object["asset"]["category"]
            .as_str()
            .unwrap()
            .chars()
            .count(),
        256
    );
}

#[tokio::test]
async fn listing_object_marks_a_non_elastos_protection_foreign() {
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(LISTING_FOLDER, "metadata.json", &lit_metadata(LISTING_KID)),
    )
    .await;
    // A bare-hex `kid` (no `0x`) is the same KID once normalized.
    let (status, object) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{object}");
    assert_eq!(object["asset"]["readability"], "foreign");
    assert_eq!(object["item"]["kid"], LISTING_KID);
    assert_eq!(object["asset"]["cover_cid"], Value::Null);
    assert_eq!(object["asset"]["category"], "video");
    assert_eq!(object["asset"]["mime_type"], "");
}

#[tokio::test]
async fn listing_object_refuses_a_kid_bound_to_another_item() {
    // The item's folder names a real KID -- but the chain binds that KID to a
    // different token. A KID lifted from another item.
    let mut chain = chain_with_item(LISTING_FOLDER, LISTING_KID);
    chain.bindings.insert(
        LISTING_KID.to_string(),
        (
            LISTING_LEDGER.to_string(),
            LISTING_OTHER_TOKEN_ID.to_string(),
        ),
    );
    chain.items.insert(
        (
            LISTING_LEDGER.to_string(),
            LISTING_OTHER_TOKEN_ID.to_string(),
        ),
        (
            LISTING_OTHER_OPERATIVE.to_string(),
            listing_token_uri(LISTING_FOLDER),
        ),
    );
    let env = ListingEnv::new(
        chain,
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let (status, answer) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer, json!({ "code": "asset_mismatch" }));
}

#[tokio::test]
async fn listing_object_refuses_a_link_that_is_not_the_token_folder() {
    // A copy of the token's folder, pinned under another CID. Its document
    // names the real KID, and the KID really is bound -- but the token's own
    // `tokenURI` names the original folder, not this one.
    let mut content = content_with(
        LISTING_FOLDER,
        "metadata.json",
        &elastos_v1_metadata(LISTING_KID),
    );
    add_file(
        &mut content,
        LISTING_COPY_FOLDER,
        "metadata.json",
        &elastos_v1_metadata(LISTING_KID),
    );
    let env = ListingEnv::new(chain_with_item(LISTING_FOLDER, LISTING_KID), content).await;
    for uri in [
        format!("elastos://{LISTING_COPY_FOLDER}"),
        listing_token_uri(LISTING_COPY_FOLDER),
    ] {
        let (status, answer) = env.post(token_uri_start(&uri)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{uri}: {answer}");
        assert_eq!(answer, json!({ "code": "asset_mismatch" }));
    }
}

#[tokio::test]
async fn listing_object_refuses_metadata_whose_kid_disagrees() {
    // The chain binds LISTING_KID to the item, the item's tokenURI names the
    // folder -- and the folder's document names another KID. Only a `kid`
    // start holds all three facts independently, so it is the start that
    // isolates the third leg.
    let mut chain = chain_with_item(LISTING_FOLDER, LISTING_KID);
    chain.bindings.insert(
        LISTING_OTHER_KID.to_string(),
        (
            LISTING_LEDGER.to_string(),
            LISTING_OTHER_TOKEN_ID.to_string(),
        ),
    );
    chain.items.insert(
        (
            LISTING_LEDGER.to_string(),
            LISTING_OTHER_TOKEN_ID.to_string(),
        ),
        (
            LISTING_OTHER_OPERATIVE.to_string(),
            listing_token_uri(LISTING_OTHER_FOLDER),
        ),
    );
    let env = ListingEnv::new(
        chain,
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_OTHER_KID),
        ),
    )
    .await;
    let (status, answer) = env.post(kid_start(LISTING_KID)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer, json!({ "code": "asset_mismatch" }));

    // From the item, the document's KID is the one looked up, and the chain
    // binds it elsewhere.
    let (status, answer) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer, json!({ "code": "asset_mismatch" }));

    // A document whose own KID fields disagree with each other names no KID.
    let mut split = elastos_v1_metadata(LISTING_KID);
    split["properties"]["kid"] = json!(LISTING_OTHER_KID);
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(LISTING_FOLDER, "metadata.json", &split),
    )
    .await;
    let (status, answer) = env.post(kid_start(LISTING_KID)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
}

/// R46: a shared document this Home cannot read, or a KID binding the chain
/// cannot answer, never stands between a buyer and the chain's offers. The
/// object is answered with the offers, `readability: "unknown"` and no KID:
/// only a proven contradiction is `asset_mismatch`.
#[tokio::test]
async fn listing_object_answers_unknown_readability_when_the_document_is_unreadable() {
    let readable = || {
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        )
    };
    let mut unreadable = readable();
    unreadable
        .unreadable_paths
        .push("metadata.json".to_string());
    let mut not_json = ListingContentFixture::default();
    not_json
        .folders
        .entry(LISTING_FOLDER.to_string())
        .or_default()
        .insert(
            "metadata.json".to_string(),
            b"<html>gateway</html>".to_vec(),
        );
    let mut binding_unavailable = chain_with_item(LISTING_FOLDER, LISTING_KID);
    binding_unavailable.kid_binding_unavailable = true;
    let cases = vec![
        (
            "unreadable",
            chain_with_item(LISTING_FOLDER, LISTING_KID),
            unreadable,
        ),
        (
            "absent",
            chain_with_item(LISTING_FOLDER, LISTING_KID),
            ListingContentFixture::default(),
        ),
        (
            "not json",
            chain_with_item(LISTING_FOLDER, LISTING_KID),
            not_json,
        ),
        ("binding unavailable", binding_unavailable, readable()),
    ];
    for (case, chain, content) in cases {
        let env = ListingEnv::new(chain, content).await;
        let (status, object) = env.post(item_start()).await;
        assert_eq!(status, StatusCode::OK, "{case}: {object}");
        assert_eq!(
            object["asset"]["readability"], "unknown",
            "{case}: {object}"
        );
        assert_eq!(object["item"]["kid"], Value::Null, "{case}: {object}");
        assert_eq!(object["item"]["operative"], LISTING_OPERATIVE, "{case}");
        assert_eq!(
            object["asset"]["uri"],
            format!("elastos://{LISTING_FOLDER}"),
            "{case}"
        );
        assert_eq!(
            object["offers"].as_array().map(Vec::len),
            Some(2),
            "{case}: {object}"
        );
    }

    // From a KID the chain finds the item all the same; a document it cannot
    // read leaves the third leg unknown, and the KID with it.
    let mut unreadable = readable();
    unreadable
        .unreadable_paths
        .push("metadata.json".to_string());
    let env = ListingEnv::new(chain_with_item(LISTING_FOLDER, LISTING_KID), unreadable).await;
    let (status, object) = env.post(kid_start(LISTING_KID)).await;
    assert_eq!(status, StatusCode::OK, "{object}");
    assert_eq!(object["asset"]["readability"], "unknown", "{object}");
    assert_eq!(object["item"]["kid"], Value::Null, "{object}");
}

/// R46: the offers are the terms a buyer decides on. Without them there is
/// nothing to buy, so a chain that cannot state them is still `unavailable`.
#[tokio::test]
async fn listing_object_is_unavailable_while_the_offers_cannot_be_read() {
    let mut chain = chain_with_item(LISTING_FOLDER, LISTING_KID);
    chain.offers_unavailable = true;
    let env = ListingEnv::new(
        chain,
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let (status, answer) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    assert_eq!(answer, json!({ "code": "unavailable" }));
}

/// A listing read that hangs in an inner call answers `unavailable` at the
/// overall deadline (30 s, inside the page's 35 s abort), so the card's own
/// retry takes over. The offers read here never answers; the clock is paused
/// and moves only to the next timer.
#[tokio::test(start_paused = true)]
async fn listing_answers_unavailable_at_overall_deadline() {
    let mut chain = chain_with_item(LISTING_FOLDER, LISTING_KID);
    chain.never_answers = Some("resolve_protected_content_item_offers");
    let env = ListingEnv::new(
        chain,
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let started = tokio::time::Instant::now();
    let (status, answer) =
        tokio::time::timeout(std::time::Duration::from_secs(31), env.post(item_start()))
            .await
            .expect("the listing read answers by its 30 s deadline");
    let waited = started.elapsed();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    assert_eq!(answer, json!({ "code": "unavailable" }));
    assert!(
        waited >= std::time::Duration::from_secs(30) && waited < std::time::Duration::from_secs(31),
        "answered after {waited:?}"
    );
    // The read got as far as the offers before it stalled.
    assert!(env
        .chain
        .lock()
        .unwrap()
        .requests
        .iter()
        .any(|request| request["op"] == "resolve_protected_content_item_offers"));
}

/// The deadline changes nothing for a read that answers: the same object,
/// right away.
#[tokio::test(start_paused = true)]
async fn expired_listing_chain_read_never_dispatches_before_a_live_listing() {
    use elastos_runtime::provider::{bridge::ProviderBridge, CapsuleProvider};
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
    use tracing::instrument::WithSubscriber as _;
    use tracing::Instrument as _;
    use tracing_subscriber::prelude::*;

    // Observe the actual detached bridge task reaching its queue; this layer
    // changes neither its dispatch fence nor any provider response.
    struct QueueEvents(tokio::sync::mpsc::UnboundedSender<String>);
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for QueueEvents {
        fn on_event(&self, event: &tracing::Event<'_>, _context: tracing_subscriber::layer::Context<'_, S>) {
            #[derive(Default)]
            struct Fields { op: String, phase: String }
            impl tracing::field::Visit for Fields {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    match field.name() {
                        "op" => self.op = value.to_owned(),
                        "phase" => self.phase = value.to_owned(),
                        _ => {}
                    }
                }
                fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                    if field.name() == "op" { self.op = format!("{value:?}"); }
                }
            }
            let mut fields = Fields::default();
            event.record(&mut fields);
            if fields.phase == "queued" { let _ = self.0.send(fields.op); }
        }
    }

    let env = Arc::new(ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(LISTING_FOLDER, "metadata.json", &elastos_v1_metadata(LISTING_KID)),
    ).await);
    let (client, server) = tokio::io::duplex(64 * 1024);
    let (client_read, client_write) = tokio::io::split(client);
    let (server_read, mut server_write) = tokio::io::split(server);
    let mut server_read = tokio::io::BufReader::new(server_read);
    let bridge = Arc::new(ProviderBridge::from_io(tokio::io::BufReader::new(client_read), client_write));
    let registry = env.state.provider_registry.as_ref().unwrap().clone();
    registry.unregister_sub_provider("chain").await.unwrap();
    registry.register_sub_provider("chain", Arc::new(CapsuleProvider::with_scheme(bridge, "chain"))).await.unwrap();
    let (queued_tx, mut queued_rx) = tokio::sync::mpsc::unbounded_channel();
    let _subscriber = tracing::subscriber::set_default(tracing_subscriber::registry().with(QueueEvents(queued_tx)));
    tracing::callsite::rebuild_interest_cache();

    let expired_env = env.clone();
    let started = tokio::time::Instant::now();
    let expired = tokio::spawn(async move { expired_env.post(item_start()).await }.with_current_subscriber());
    assert_eq!(queued_rx.recv().await.as_deref(), Some("describe_protected_content_creator_mint_source"));
    let mut line = String::new();
    server_read.read_line(&mut line).await.unwrap();
    let source_request: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(source_request["op"], "describe_protected_content_creator_mint_source");

    // Queue a real bridge transaction behind the source description before
    // replying to it. The card's next MarketChain read then waits behind this
    // blocker, whose already-written response remains owned by the bridge.
    let blocker_registry = registry.clone();
    let blocker = tokio::spawn(async move {
        blocker_registry.send_raw("chain", &json!({"op": "fixture_blocker"})).await
    }.instrument(tracing::info_span!("action_trace")).with_current_subscriber());
    assert_eq!(queued_rx.recv().await.as_deref(), Some("fixture_blocker"));
    let source_answer = ListingChainStub(env.chain.clone()).answer(&source_request).unwrap();
    server_write.write_all(format!("{source_answer}\n").as_bytes()).await.unwrap();
    server_write.flush().await.unwrap();
    line.clear();
    server_read.read_line(&mut line).await.unwrap();
    assert_eq!(serde_json::from_str::<Value>(line.trim()).unwrap()["op"], "fixture_blocker");
    assert_eq!(queued_rx.recv().await.as_deref(), Some("resolve_protected_content_item"));

    tokio::time::advance(std::time::Duration::from_secs(30)).await;
    let (status, answer) = expired.await.unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(answer, json!({"code": "unavailable"}));
    assert_eq!(started.elapsed(), std::time::Duration::from_secs(30));

    let live_env = env.clone();
    let mut live = tokio::spawn(async move { live_env.post(item_start()).await }.with_current_subscriber());
    assert_eq!(queued_rx.recv().await.as_deref(), Some("describe_protected_content_creator_mint_source"));
    server_write.write_all(b"{\"status\":\"ok\",\"data\":{\"marker\":\"blocker\"}}\n").await.unwrap();
    server_write.flush().await.unwrap();
    assert_eq!(blocker.await.unwrap().unwrap()["data"]["marker"], "blocker");

    // Fully settle the live HTTP journey before asserting the stale-write
    // boundary, so a failure cannot leave a queued transaction unobserved.
    let mut wire_ops = Vec::new();
    let (status, object) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            line.clear();
            tokio::select! {
                result = &mut live => break result.unwrap(),
                count = server_read.read_line(&mut line) => {
                    assert_ne!(count.unwrap(), 0);
                    let request: Value = serde_json::from_str(line.trim()).unwrap();
                    wire_ops.push(request["op"].as_str().unwrap().to_owned());
                    let response = ListingChainStub(env.chain.clone()).send_raw(&request).await.unwrap();
                    server_write.write_all(format!("{response}\n").as_bytes()).await.unwrap();
                    server_write.flush().await.unwrap();
                }
            }
        }
    }).await.expect("live listing must settle once the blocker is released");
    assert_eq!(status, StatusCode::OK, "{object}");
    assert_eq!(object["item"]["token_id"], LISTING_TOKEN_ID);
    assert_eq!(wire_ops.first().map(String::as_str), Some("describe_protected_content_creator_mint_source"), "expired MarketChain read wrote after its HTTP deadline: {wire_ops:?}");
    assert_eq!(wire_ops.iter().filter(|op| op.as_str() == "resolve_protected_content_item").count(), 1, "only the live listing may read the item: {wire_ops:?}");
}

#[tokio::test]
async fn listing_fast_path_unchanged() {
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let started = std::time::Instant::now();
    let (status, object) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{object}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "a fast read never waits for the deadline"
    );
    assert_eq!(object["schema"], "elastos.marketplace.listing/v1");
    assert_eq!(object["item"]["kid"], LISTING_KID);
    assert_eq!(object["item"]["operative"], LISTING_OPERATIVE);
    assert_eq!(
        object["offers"].as_array().map(Vec::len),
        Some(2),
        "{object}"
    );
    assert_eq!(object["access_state"], "available");
    assert_eq!(object["source"]["start"], "item");
    assert_eq!(
        object["source"]["read_at_block"],
        format!("0x{LISTING_FINALIZED_BLOCK:x}")
    );
}

#[tokio::test]
async fn listing_object_routes_a_listing_json_link_to_legacy_import() {
    let env = ListingEnv::new(
        ListingChainFixture::default(),
        content_with(
            LISTING_LEGACY_FOLDER,
            "listing.json",
            &json!({ "schema": "elastos.protected-content.portable-listing/v1" }),
        ),
    )
    .await;
    let (status, answer) = env
        .post(token_uri_start(&format!(
            "elastos://{LISTING_LEGACY_FOLDER}"
        )))
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer, json!({ "legacy_listing": true }));
}

/// R30 (SM-I3): `listing.json` is asked for only when the folder has no
/// `metadata.json`. A document the content plane could not read for any other
/// reason is `unavailable`, and no second file is read.
#[tokio::test]
async fn listing_object_probes_listing_json_only_when_metadata_is_not_found() {
    let mut content = content_with(
        LISTING_FOLDER,
        "listing.json",
        &json!({ "schema": "elastos.protected-content.portable-listing/v1" }),
    );
    content.unreadable_paths.push("metadata.json".to_string());
    let env = ListingEnv::new(chain_with_item(LISTING_FOLDER, LISTING_KID), content).await;
    let (status, answer) = env
        .post(token_uri_start(&format!("elastos://{LISTING_FOLDER}")))
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    assert_eq!(answer, json!({ "code": "unavailable" }));
    assert_eq!(env.content_paths(), vec!["metadata.json".to_string()]);
}

/// R30 (SM-I3): the shared document is read with its cap inside the fetch, so
/// a hostile folder's oversized file is never held whole; and it is refused:
/// the asset is not described from it, and its readability is unknown (R46).
#[tokio::test]
async fn listing_object_caps_the_shared_document_read() {
    let mut oversized = elastos_v1_metadata(LISTING_KID);
    oversized["description"] = json!("x".repeat(300 * 1024));
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(LISTING_FOLDER, "metadata.json", &oversized),
    )
    .await;
    let (status, answer) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["asset"]["readability"], "unknown", "{answer}");
    assert_eq!(answer["asset"]["title"], "", "{answer}");
    assert_eq!(answer["item"]["kid"], Value::Null, "{answer}");
    let content = env.content.lock().unwrap();
    assert_eq!(
        content.requested,
        vec![(LISTING_FOLDER.to_string(), "metadata.json".to_string())],
        "an oversized document is not a reason to read listing.json"
    );
    assert_eq!(
        content.ranges,
        vec![json!({ "start": 0, "end": 256 * 1024 })],
        "the cap travels with the request"
    );
}

/// DEMO-ISSUES B: the creator's Share link names the listing package folder,
/// which holds `listing.json` and no `metadata.json`. Live (Home-6,
/// 2026-11-16T17:45:14Z, mint 44fe1c5a, old build ce0339465) the holder's
/// Kubo answered "no link named" as a bare 500, its Carrier answer was
/// reduced to `ticket[0] invoke failed` and the read was classed
/// `carrier_fetch_in_transit`, so the link ended in "The market couldn't be
/// reached. Try again." The planes now keep that answer: ipfs-provider types
/// it `not_found`, the holder sends `content_not_found`, and a known-holders
/// read whose holders all answered finally is `carrier_fetch_failed`. This
/// is the answer the content plane then gives for that read (this Home lacks
/// the folder, the holder lacks the file, another Home refuses), and the
/// link reaches the legacy import.
#[tokio::test]
async fn listing_object_routes_a_creator_share_link_to_legacy_import_when_holders_answer_kubo_500()
{
    let folder = LISTING_LEGACY_FOLDER;
    let mut content = content_with(
        folder,
        "listing.json",
        &json!({ "schema": "elastos.protected-content.portable-listing/v1" }),
    );
    let failed = crate::carrier::CARRIER_FETCH_FAILED_CODE;
    let not_found = crate::carrier::CARRIER_CONTENT_NOT_FOUND;
    let refused = crate::carrier::CARRIER_PEER_REFUSED;
    content.failure_messages.insert(
        "metadata.json".to_string(),
        format!(
            "content fetch failed: kubo cat -> http://127.0.0.1:61205/api/v0/cat?arg={folder}%2Fmetadata.json: \
             status code 500: block was not found locally (offline): ipld: could not find {folder} \
             for {folder}/metadata.json; availability fetch failed: provider error: \
             availability fetch failed ({failed}): Carrier content fetch failed: \
             Carrier provider invocation failed: provider error: Carrier provider invocation failed: \
             ticket[0] {not_found} | Carrier provider invocation failed: provider error: \
             Carrier provider invocation failed: ticket[0] {refused}"
        ),
    );
    let env = ListingEnv::new(ListingChainFixture::default(), content).await;
    let (status, answer) = env
        .post(token_uri_start(&format!("elastos://{folder}")))
        .await;
    assert_eq!(
        (status, answer.clone()),
        (StatusCode::OK, json!({ "legacy_listing": true })),
        "content paths read: {:?}",
        env.content_paths()
    );
}

#[derive(Clone)]
pub(super) struct AddListingTraceWriter(pub(super) Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for AddListingTraceWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Exercise the actual HTTP lookup and legacy-import dispatch, with one UI
/// action ID but different server requests. Diagnostics contain public routing
/// facts, never the pasted raw input, provider errors, or other request fields.
#[tokio::test]
async fn add_listing_trace_correlates_legacy_lookup_and_import_without_private_values() {
    let env = ListingEnv::new(
        ListingChainFixture::default(),
        content_with(
            LISTING_LEGACY_FOLDER,
            "listing.json",
            &json!({"schema":"fixture"}),
        ),
    )
    .await;
    let output = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = AddListingTraceWriter(output.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let action = "listing-fixture-42";
    let mut request_ids = Vec::new();
    for (path, body) in [
        (
            "/api/apps/marketplace/listing",
            token_uri_start(&format!("elastos://{LISTING_LEGACY_FOLDER}")),
        ),
        (
            "/api/provider/object/import_runtime_custody",
            json!({"listing_uri":format!("elastos://{LISTING_LEGACY_FOLDER}")}),
        ),
    ] {
        let response = env
            .app
            .clone()
            .oneshot(
                test_browser_request("localhost:61180", "null")
                    .method("POST")
                    .uri(path)
                    .header("x-elastos-home-token", &env.token)
                    .header("x-elastos-action-id", action)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        if path.ends_with("/listing") {
            assert_eq!(response.status(), StatusCode::OK);
        }
        request_ids.push(
            response
                .headers()
                .get("x-elastos-request-id")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string(),
        );
    }
    let logged = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert!(
        request_ids.iter().all(|id| !id.is_empty()),
        "server request IDs must be returned"
    );
    assert_ne!(request_ids[0], request_ids[1]);
    assert!(logged.contains(action), "{logged}");
    assert!(logged.contains(LISTING_LEGACY_FOLDER), "{logged}");
    for expected in [
        "metadata.json",
        "listing.json",
        "legacy_listing",
        "listing_fetch",
        "elapsed_ms",
        "request_started",
        "request_finished",
    ] {
        assert!(logged.contains(expected), "missing {expected}: {logged}");
    }
    assert!(!logged.contains(&env.token));
    assert!(!logged.contains(&env.authority.principal_id));
}

#[tokio::test]
async fn add_listing_trace_replaces_unsafe_action_ids_without_logging_raw_input() {
    let env = ListingEnv::new(
        ListingChainFixture::default(),
        content_with(
            LISTING_LEGACY_FOLDER,
            "listing.json",
            &json!({"schema":"fixture"}),
        ),
    )
    .await;
    let output = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = AddListingTraceWriter(output.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let unsafe_id = "private-ticket=DO-NOT-LOG";
    let response = env
        .app
        .clone()
        .oneshot(
            test_browser_request("localhost:61180", "null")
                .method("POST")
                .uri("/api/apps/marketplace/listing")
                .header("x-elastos-home-token", &env.token)
                .header("x-elastos-action-id", unsafe_id)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&token_uri_start(&format!(
                        "elastos://{LISTING_LEGACY_FOLDER}"
                    )))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let logged = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert!(response.headers().contains_key("x-elastos-request-id"));
    assert!(logged.contains("action_id"), "{logged}");
    assert!(!logged.contains(unsafe_id));
    assert!(!logged.contains("DO-NOT-LOG"));
    assert!(!logged.contains(&env.token));
}

#[tokio::test]
async fn add_listing_trace_header_is_allowed_by_capsule_preflight() {
    let env = ListingEnv::new(
        ListingChainFixture::default(),
        ListingContentFixture::default(),
    )
    .await;
    let response = env
        .app
        .clone()
        .oneshot(
            test_browser_request("localhost:61180", "null")
                .method("OPTIONS")
                .uri("/api/apps/marketplace/listing")
                .header("access-control-request-method", "POST")
                .header(
                    "access-control-request-headers",
                    "content-type,x-elastos-home-token,x-elastos-action-id",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let allowed = response
        .headers()
        .get("access-control-allow-headers")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        allowed
            .split(',')
            .any(|field| field.trim().eq_ignore_ascii_case("x-elastos-action-id")),
        "{allowed}"
    );
}

#[tokio::test(start_paused = true)]
async fn add_listing_trace_names_the_cancelled_stage_at_the_outer_deadline() {
    let mut chain = chain_with_item(LISTING_FOLDER, LISTING_KID);
    chain.never_answers = Some("resolve_protected_content_item_offers");
    let env = ListingEnv::new(
        chain,
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let output = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = AddListingTraceWriter(output.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let (status, _) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let logged = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    for expected in [
        "stage_cancelled",
        "resolve_protected_content_item_offers",
        "chain",
        "request_finished",
        "timeout",
        "action_id",
    ] {
        assert!(logged.contains(expected), "missing {expected}: {logged}");
    }
    assert!(!logged.contains(&env.token));
}

#[tokio::test]
async fn add_listing_trace_finishes_early_handler_refusals_without_changing_responses() {
    let env = ListingEnv::new(
        ListingChainFixture::default(),
        ListingContentFixture::default(),
    )
    .await;
    // Deliberately exercise the handler's authentication boundary. The real
    // frontdoor may refuse an invalid launch token before this handler runs.
    let handler = axum::Router::new()
        .route(
            "/listing",
            axum::routing::post(
                crate::api::gateway::gateway_marketplace_listing::marketplace_listing,
            ),
        )
        .with_state(env.state.clone());
    let output = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = AddListingTraceWriter(output.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let mut refusal_ids = Vec::new();
    for (token, body, expected_status, expected_body) in [
        (
            None,
            "{}",
            StatusCode::FORBIDDEN,
            "missing home launch token",
        ),
        (
            Some(env.token.as_str()),
            "{",
            StatusCode::BAD_REQUEST,
            "{\"code\":\"invalid_start\"}",
        ),
        (
            Some(env.token.as_str()),
            "{\"start\":{\"token_uri\":\"not-a-cid\"}}",
            StatusCode::BAD_REQUEST,
            "{\"code\":\"invalid_start\"}",
        ),
    ] {
        let mut request = test_browser_request("localhost:61180", "null")
            .method("POST")
            .uri("/listing")
            .header(CONTENT_TYPE, "application/json")
            .header("x-elastos-action-id", "listing-early-refusal");
        if let Some(token) = token {
            request = request.header("x-elastos-home-token", token);
        }
        let response = handler
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let request_id = response.headers().get("x-elastos-request-id").cloned();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(status, expected_status);
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected_body);
        refusal_ids.push(request_id);
    }
    let import_handler = axum::Router::new()
        .route(
            "/api/provider/:scheme/:op",
            axum::routing::post(
                crate::api::gateway::gateway_provider_proxy::gateway_provider_proxy,
            ),
        )
        .with_state(env.state.clone());
    let malformed_error = serde_json::from_slice::<Value>(b"{")
        .unwrap_err()
        .to_string();
    for (token, body, expected_status, expected_body) in [
        (
            None,
            "{}",
            StatusCode::FORBIDDEN,
            "missing home launch token",
        ),
        (
            Some(env.token.as_str()),
            "{",
            StatusCode::BAD_REQUEST,
            malformed_error.as_str(),
        ),
        (
            Some(env.token.as_str()),
            "[]",
            StatusCode::BAD_REQUEST,
            "provider request body must be a JSON object",
        ),
    ] {
        let mut request = test_browser_request("localhost:61180", "null")
            .method("POST")
            .uri("/api/provider/object/import_runtime_custody")
            .header(CONTENT_TYPE, "application/json")
            .header("x-elastos-action-id", "listing-early-import-refusal");
        if let Some(token) = token {
            request = request.header("x-elastos-home-token", token);
        }
        let response = import_handler
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let request_id = response.headers().get("x-elastos-request-id").cloned();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(status, expected_status);
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected_body);
        refusal_ids.push(request_id);
    }
    assert!(
        refusal_ids.iter().all(Option::is_some),
        "every returned handler refusal needs a request ID"
    );
    let logged = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert_eq!(
        logged.matches("event=\"request_finished\"").count(),
        6,
        "{logged}"
    );
    assert!(!logged.contains("request_cancelled"), "{logged}");
    assert!(!logged.contains("not-a-cid"));
    assert!(!logged.contains(&env.token));
}

#[tokio::test]
async fn add_listing_trace_finishes_a_postdispatch_audit_failure_as_a_returned_error() {
    let env = ListingEnv::new(
        ListingChainFixture::default(),
        ListingContentFixture::default(),
    )
    .await;
    let root = env._dir.path().to_path_buf();
    let invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let invoked_hook = invoked.clone();
    env.content.lock().unwrap().on_fetch = Some(Box::new(move || {
        let state = crate::auth::load_auth_state(&root).unwrap();
        assert!(state
            .audit
            .iter()
            .any(|event| event.event_type == "object.provider.requested"));
        let path = crate::auth::auth_state_path(&root).unwrap();
        std::fs::rename(&path, path.with_extension("fixture-backup")).unwrap();
        std::fs::create_dir(&path).unwrap();
        invoked_hook.store(true, std::sync::atomic::Ordering::SeqCst);
    }));
    let output = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = AddListingTraceWriter(output.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let response = env
        .app
        .clone()
        .oneshot(
            test_browser_request("localhost:61180", "null")
                .method("POST")
                .uri("/api/provider/object/import_runtime_custody")
                .header("x-elastos-home-token", &env.token)
                .header("x-elastos-action-id", "listing-audit-failure")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(
                        &json!({"listing_uri":format!("elastos://{LISTING_LEGACY_FOLDER}")}),
                    )
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let request_id = response.headers().get("x-elastos-request-id").cloned();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        invoked.load(std::sync::atomic::Ordering::SeqCst),
        "actual dispatch must precede the audit fault"
    );
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let expected_error = crate::auth::load_auth_state(env._dir.path()).unwrap_err();
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        format!("object provider audit failed: {expected_error}")
    );
    let logged = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert_eq!(
        (
            request_id.is_some(),
            logged.contains("request_finished"),
            logged.contains("request_cancelled")
        ),
        (true, true, false),
        "a returned HTTP error needs a finished request, not cancellation"
    );
    assert!(!logged.contains(&env.token));
    assert!(!logged.contains("fixture-backup"));
}

/// DEMO-ISSUES B: a pasted link whose folder holds neither an item's
/// `metadata.json` nor a listing package's `listing.json` is not a market
/// listing. That is a final answer, said plainly, not "The market couldn't
/// be reached. Try again."
#[tokio::test]
async fn listing_object_answers_a_link_that_is_neither_item_nor_package_finally() {
    let folder = LISTING_LEGACY_FOLDER;
    let env = ListingEnv::new(
        ListingChainFixture::default(),
        content_with(folder, "notes.txt", &json!({ "text": "not a listing" })),
    )
    .await;
    let (status, answer) = env
        .post(token_uri_start(&format!("elastos://{folder}")))
        .await;
    assert_eq!(
        (status, answer),
        (StatusCode::NOT_FOUND, json!({ "code": "not_a_listing" })),
    );
    assert_eq!(env.content_paths(), vec!["metadata.json", "listing.json"]);
}

/// PS-M7: a link's folder is read before the market source is asked for, so
/// a legacy `listing.json` link reaches the import even when the market
/// source cannot be read.
#[tokio::test]
async fn listing_object_routes_a_legacy_link_without_the_market_source() {
    let chain = ListingChainFixture {
        mint_source_unavailable: true,
        ..ListingChainFixture::default()
    };
    let env = ListingEnv::new(
        chain,
        content_with(
            LISTING_LEGACY_FOLDER,
            "listing.json",
            &json!({ "schema": "elastos.protected-content.portable-listing/v1" }),
        ),
    )
    .await;
    let (status, answer) = env
        .post(token_uri_start(&format!(
            "elastos://{LISTING_LEGACY_FOLDER}"
        )))
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer, json!({ "legacy_listing": true }));
}

/// R36 (PS-I4): the chain-provider's own answers -- written by its producer
/// test, never by hand -- deserialize into the typed answers this side reads,
/// and an answer carrying a field they do not name is refused.
#[test]
fn chain_market_ops_fixture_deserializes_into_the_typed_answers() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/chain-market-ops.json")).unwrap();
    let item: ResolvedProtectedContentItem =
        serde_json::from_value(fixture["item"].clone()).unwrap();
    assert_eq!(item.schema, "elastos.chain.protected-content-item/v1");
    assert!(item.token_uri.starts_with("ipfs://"));
    let binding: ResolvedProtectedContentKidBinding =
        serde_json::from_value(fixture["kid_binding"].clone()).unwrap();
    assert_eq!(binding.ledger, item.ledger);
    let offers: ResolvedProtectedContentItemOffers =
        serde_json::from_value(fixture["item_offers"].clone()).unwrap();
    assert!(!offers.truncated);
    assert!(offers
        .offers
        .iter()
        .any(|offer| offer.payment_processor.is_none()));
    assert!(offers
        .offers
        .iter()
        .any(|offer| offer.payment_processor.is_some()));
    let truncated: ResolvedProtectedContentItemOffers =
        serde_json::from_value(fixture["item_offers_truncated"].clone()).unwrap();
    assert!(truncated.truncated);
    assert_eq!(truncated.offers.len(), 32);

    let mut extra = fixture["item"].clone();
    extra["surprise"] = json!(true);
    assert!(serde_json::from_value::<ResolvedProtectedContentItem>(extra).is_err());

    // The head classification read is its own answer, and no reader of an
    // item takes it for one.
    let finality: ClassifiedProtectedContentItemFinality =
        serde_json::from_value(fixture["item_finality"].clone()).unwrap();
    assert!(finality.bound_at_head);
    assert_eq!(finality.ledger.as_deref(), Some(item.ledger.as_str()));
    assert!(finality.head_block_timestamp > finality.finalized_block_timestamp);
    assert!(serde_json::from_value::<ResolvedProtectedContentItem>(
        fixture["item_finality"].clone()
    )
    .is_err());
}

#[tokio::test]
async fn listing_object_answers_unbound_and_unavailable() {
    // An item with no operative is not an item on this market.
    let env = ListingEnv::new(
        ListingChainFixture::default(),
        ListingContentFixture::default(),
    )
    .await;
    let (status, answer) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer, json!({ "code": "unbound" }));
    let (status, answer) = env.post(kid_start(LISTING_KID)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");

    // A folder nothing can be read from is not refused as a mismatch: it
    // may be there and slow. From a link, which only its document leads
    // from, it is unavailable; from a KID the chain found the item, and its
    // readability is unknown (R46).
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        ListingContentFixture::default(),
    )
    .await;
    let (status, answer) = env
        .post(token_uri_start(&format!("elastos://{LISTING_FOLDER}")))
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    assert_eq!(answer, json!({ "code": "unavailable" }));
    let (status, answer) = env.post(kid_start(LISTING_KID)).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["asset"]["readability"], "unknown", "{answer}");

    // A start that names nothing at all is the caller's error.
    let (status, _) = env.post(kid_start("0x1234")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = env.post(token_uri_start("https://example.com/x")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, answer) = env
        .post(json!({ "start": { "kid": LISTING_KID }, "seller": LISTING_SELLER }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(answer, json!({ "code": "invalid_start" }));
}

/// The item's document as no Home this one can reach serves it: every
/// holder Carrier knows refused it, or Carrier knows none.
fn document_held_by_no_one(code: &'static str) -> ListingContentFixture {
    let mut content = ListingContentFixture::default();
    content
        .holder_answers
        .insert("metadata.json".to_string(), code);
    content
}

/// C: a document no reachable Home serves is a definite answer. Whichever
/// start the read began from, the listing answers `no_holder` as soon as
/// every known holder has refused, or at once when none is known, and asks
/// for no second file. The read asks only the holders known now.
#[tokio::test(start_paused = true)]
async fn listing_answers_no_holder_at_once_when_no_reachable_home_serves_the_document() {
    let link = format!("elastos://{LISTING_FOLDER}");
    for code in ["carrier_fetch_failed", "carrier_fetch_unavailable"] {
        for start in [item_start(), kid_start(LISTING_KID), token_uri_start(&link)] {
            let env = ListingEnv::new(
                chain_with_item(LISTING_FOLDER, LISTING_KID),
                document_held_by_no_one(code),
            )
            .await;
            let started = tokio::time::Instant::now();
            let (status, answer) = env.post(start.clone()).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{code} {start}: {answer}");
            assert_eq!(answer, json!({ "code": "no_holder" }), "{code} {start}");
            assert!(
                started.elapsed() < std::time::Duration::from_secs(1),
                "{code} {start}: answered after {:?}",
                started.elapsed()
            );
            assert_eq!(env.content_paths(), vec!["metadata.json"], "{code} {start}");
            assert_eq!(
                env.content.lock().unwrap().known_holders_only,
                vec![true],
                "{code} {start}"
            );
        }
    }
}

/// C: one holder that serves the document lists the item, from the same
/// read that asks only the holders known now.
#[tokio::test]
async fn listing_reads_the_document_from_a_holder_that_serves_it() {
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let (status, object) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{object}");
    assert_eq!(object["item"]["kid"], LISTING_KID, "{object}");
    assert_eq!(env.content.lock().unwrap().known_holders_only, vec![true]);
}

/// C: a holder that failed on the way is no answer about the document. The
/// item read from the chain stands with an unknown readability (R46), and a
/// link, which leads only through its document, stays the retryable
/// `unavailable`.
#[tokio::test]
async fn guard_listing_keeps_a_holder_failing_in_transit_retryable() {
    let in_transit = crate::carrier::CARRIER_FETCH_IN_TRANSIT_CODE;
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        document_held_by_no_one(in_transit),
    )
    .await;
    let (status, object) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{object}");
    assert_eq!(object["asset"]["readability"], "unknown", "{object}");
    let (status, answer) = env
        .post(token_uri_start(&format!("elastos://{LISTING_FOLDER}")))
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    assert_eq!(answer, json!({ "code": "unavailable" }));
}

/// C: once the chain has located the item, its document is read beside the
/// offers rather than before them, so offers the chain cannot state answer
/// `unavailable` without waiting for a document that does not come.
#[tokio::test(start_paused = true)]
async fn listing_reads_the_document_beside_the_offers() {
    let mut chain = chain_with_item(LISTING_FOLDER, LISTING_KID);
    chain.offers_unavailable = true;
    let mut content = content_with(
        LISTING_FOLDER,
        "metadata.json",
        &elastos_v1_metadata(LISTING_KID),
    );
    content
        .never_answers_paths
        .push("metadata.json".to_string());
    let env = ListingEnv::new(chain, content).await;
    let started = tokio::time::Instant::now();
    let (status, answer) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    assert_eq!(answer, json!({ "code": "unavailable" }));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "answered after {:?}",
        started.elapsed()
    );
}

/// A new item the finalized block does not reach yet is not "no such item":
/// one read at the head classifies the refusal, and the answer says when to
/// look again -- the head block plus the lag the finalized block trails it
/// by, counted from the head the item was read at.
#[tokio::test]
async fn listing_object_answers_pending_finality_for_an_item_only_the_head_binds() {
    let chain = ListingChainFixture {
        bound_at_head: true,
        ..ListingChainFixture::default()
    };
    let env = ListingEnv::new(
        chain,
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let link = format!("elastos://{LISTING_FOLDER}");
    for start in [item_start(), kid_start(LISTING_KID), token_uri_start(&link)] {
        let now = crate::auth::now_ts();
        let (status, answer) = env.post(start.clone()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{start} {answer}");
        assert_eq!(answer["code"], "pending_finality", "{answer}");
        assert_eq!(answer.as_object().unwrap().len(), 2, "{answer}");
        let ready_at = answer["ready_at"].as_u64().unwrap();
        assert!(
            ready_at + 5 >= now + LISTING_FINALITY_LAG_SECS
                && ready_at <= now + LISTING_FINALITY_LAG_SECS,
            "{ready_at} vs now {now}"
        );
    }
    // Each start asked once, naming exactly what it had: the item, or the
    // KID its own document or the request named.
    let asked = env.chain.lock().unwrap().item_finality_requests();
    assert_eq!(asked.len(), 3, "{asked:?}");
    assert_eq!(asked[0]["ledger"], LISTING_LEDGER);
    assert_eq!(asked[0]["token_id"], LISTING_TOKEN_ID);
    assert!(asked[0].get("content_access_id").is_none());
    for request in &asked[1..] {
        assert_eq!(request["content_access_id"], LISTING_KID);
        assert!(request.get("ledger").is_none());
    }
}

/// Unbound at the head too is the real "no such item". A head read that
/// cannot answer is `unavailable`, which the page asks again (D5, STAB-28),
/// never a final `unbound`.
#[tokio::test]
async fn listing_object_stays_unbound_when_the_head_cannot_say_otherwise() {
    let env = ListingEnv::new(
        ListingChainFixture::default(),
        ListingContentFixture::default(),
    )
    .await;
    let (status, answer) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{answer}");
    assert_eq!(answer, json!({ "code": "unbound" }));
    assert_eq!(env.chain.lock().unwrap().item_finality_requests().len(), 1);

    let chain = ListingChainFixture {
        bound_at_head: true,
        item_finality_unavailable: true,
        ..ListingChainFixture::default()
    };
    let env = ListingEnv::new(chain, ListingContentFixture::default()).await;
    let (status, answer) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    assert_eq!(answer, json!({ "code": "unavailable" }));

    // An answer about another item explains nothing about this one; the same
    // item written in another case is still this one.
    for (names, code) in [
        ((LISTING_LEDGER, LISTING_OTHER_TOKEN_ID), "unbound"),
        (
            (
                &LISTING_LEDGER.to_ascii_uppercase().replacen("0X", "0x", 1)[..],
                LISTING_TOKEN_ID,
            ),
            "pending_finality",
        ),
    ] {
        let chain = ListingChainFixture {
            bound_at_head: true,
            item_finality_names: Some((names.0.to_string(), names.1.to_string())),
            ..ListingChainFixture::default()
        };
        let env = ListingEnv::new(chain, ListingContentFixture::default()).await;
        let (_, answer) = env.post(item_start()).await;
        assert_eq!(answer["code"], code, "{names:?} {answer}");
    }
}

/// A listing the finalized read builds never asks the head: the head read
/// only ever explains an `unbound`.
#[tokio::test]
async fn listing_object_of_a_final_item_never_asks_the_head() {
    let mut chain = chain_with_item(LISTING_FOLDER, LISTING_KID);
    chain.bound_at_head = true;
    let env = ListingEnv::new(
        chain,
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let (status, answer) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(env
        .chain
        .lock()
        .unwrap()
        .item_finality_requests()
        .is_empty());
}

#[test]
fn pending_finality_ready_at_counts_the_finalized_lag_from_the_head() {
    let now = 2_000_000_000;
    let head = now - 2;
    // The lag the chain states now.
    assert_eq!(
        market_pending_finality_ready_at(head, head - 900, now),
        head + 900
    );
    // A lag the chain does not state sensibly -- none, or longer than an
    // acquisition is ever watched for -- is the usual Base lag instead.
    let usual = crate::protected_content_runtime::RUNTIME_CUSTODY_EXPECTED_FINALITY_LAG_SECS;
    assert_eq!(
        market_pending_finality_ready_at(head, head, now),
        head + usual
    );
    assert_eq!(
        market_pending_finality_ready_at(head, head - 5 * 60 * 60, now),
        head + usual
    );
    // A head dated far from this Home's clock is counted from now.
    assert_eq!(
        market_pending_finality_ready_at(now + 7_200, now + 7_200 - 900, now),
        now + 900
    );
    assert_eq!(market_pending_finality_ready_at(0, 0, now), now + usual);
}

/// The head read is classification only: no buy, open, release or rights
/// read can reach it. Outside tests, its op is named in one place -- the
/// listing read's classifier -- and that classifier has one caller, the
/// `/listing` handler, which answers the page and decides nothing.
#[test]
fn item_finality_read_is_reachable_from_the_listing_handler_only() {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut naming = Vec::new();
    let mut stack = vec![crates];
    while let Some(path) = stack.pop() {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        if path.is_dir() {
            if matches!(name.as_str(), "target" | "tests" | "gateway_tests") {
                continue;
            }
            for entry in std::fs::read_dir(&path).unwrap() {
                stack.push(entry.unwrap().path());
            }
            continue;
        }
        if !name.ends_with(".rs") || name == "tests.rs" || name.ends_with("_tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        if text.contains(ITEM_FINALITY_OP) {
            naming.push((name, text));
        }
    }
    assert_eq!(
        naming.len(),
        1,
        "{:?}",
        naming.iter().map(|(name, _)| name).collect::<Vec<_>>()
    );
    let (name, text) = &naming[0];
    assert_eq!(name, "gateway_marketplace_listing.rs");
    assert_eq!(text.matches(ITEM_FINALITY_OP).count(), 1);
    // Defined once, called once, from the private handler body. The public
    // handler's tracing wrapper is that body's only caller.
    assert_eq!(text.matches("classify_market_listing_finality(").count(), 2);
    let handler = &text[text.find("async fn marketplace_listing(").unwrap()..];
    let handler = &handler[..handler.find("\n}\n").unwrap()];
    assert!(handler.contains("marketplace_listing_inner("));
    assert_eq!(text.matches("marketplace_listing_inner(").count(), 2);
    let inner = &text[text.find("\nasync fn marketplace_listing_inner(").unwrap()..];
    let inner = &inner[..inner.find("\n}\n").unwrap()];
    assert!(inner.contains("classify_market_listing_finality("));
}

/// R34 (PS-M5): any body that is not exactly one start is `400
/// {"code":"invalid_start"}` -- never axum's plain-text 422 or 415.
#[tokio::test]
async fn listing_object_answers_invalid_start_for_any_unparseable_body() {
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let doubled =
        format!(r#"{{"start":{{"kid":"{LISTING_KID}"}},"start":{{"kid":"{LISTING_KID}"}}}}"#);
    let two_starts = format!(
        r#"{{"start":{{"kid":"{LISTING_KID}","token_uri":"elastos://{LISTING_FOLDER}"}}}}"#
    );
    for (content_type, body) in [
        (
            "application/json",
            r#"{"start":{"kid":"0x1"},"extra":1}"#.to_string(),
        ),
        ("application/json", r#"{"begin":{"kid":"0x1"}}"#.to_string()),
        ("application/json", doubled),
        ("application/json", two_starts),
        ("application/json", "not json".to_string()),
        ("application/json", String::new()),
        (
            "text/plain",
            format!(r#"{{"start":{{"kid":"{LISTING_KID}"}}}}"#),
        ),
    ] {
        let response = env
            .app
            .clone()
            .oneshot(
                test_browser_request("localhost:61180", "null")
                    .method("POST")
                    .uri("/api/apps/marketplace/listing")
                    .header("x-elastos-home-token", &env.token)
                    .header(CONTENT_TYPE, content_type)
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let answer: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {answer}");
        assert_eq!(answer, json!({ "code": "invalid_start" }), "{body}");
    }
    assert!(env.content_paths().is_empty());
}

#[tokio::test]
async fn listing_object_never_contains_the_buyer_address() {
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let (status, object) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{object}");
    // The account was asked about -- so it was known to Runtime -- and still
    // never reached the page.
    let asked = env
        .chain
        .lock()
        .unwrap()
        .requests
        .iter()
        .filter(|request| request["op"] == "resolve_protected_content_purchase_access")
        .map(|request| {
            request["wallet"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase()
        })
        .collect::<Vec<_>>();
    assert_eq!(asked, vec![env.buyer_address.to_ascii_lowercase()]);
    let serialized = serde_json::to_string(&object).unwrap().to_ascii_lowercase();
    let bare = env
        .buyer_address
        .trim_start_matches("0x")
        .to_ascii_lowercase();
    assert!(
        !serialized.contains(&bare),
        "the page must never learn this Home's account: {serialized}"
    );

    // And access the chain reports is stated as a state, not an address.
    env.chain.lock().unwrap().has_access = true;
    let (_, object) = env.post(item_start()).await;
    assert_eq!(object["access_state"], "purchased");
    assert!(!serde_json::to_string(&object)
        .unwrap()
        .to_ascii_lowercase()
        .contains(&bare));
}

/// The page caches each card's access per account, yet must never learn the
/// account (D14). The object names it only as `access_subject`: an opaque tag
/// that is the same for every answer about the same account, changes when
/// the account does, and contains nothing of the address.
#[tokio::test]
async fn listing_object_names_the_account_only_as_an_opaque_access_subject() {
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let (status, first) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let subject = first["access_subject"]
        .as_str()
        .expect("an answer about an account names its subject")
        .to_string();
    assert_eq!(subject.len(), 32);
    assert!(subject
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    let bare = env
        .buyer_address
        .trim_start_matches("0x")
        .to_ascii_lowercase();
    assert!(!bare.contains(&subject) && !subject.contains(&bare[..8]));
    let (_, again) = env.post(item_start()).await;
    assert_eq!(
        again["access_subject"],
        subject.as_str(),
        "stable for one account"
    );
    // Keyed with this Home's own secret: everything a page could learn about
    // the account -- who, which chain, which account id, all derivable from
    // the address -- is not enough to compute it.
    let account_id = format!(
        "wallet:eip155:8453:{}",
        env.buyer_address.to_ascii_lowercase()
    );
    let unkeyed = {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        for part in [
            "elastos.marketplace.access-subject/v1",
            env.authority.principal_id.as_str(),
            "eip155:8453",
            account_id.as_str(),
        ] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        hex::encode(&hasher.finalize()[..16])
    };
    assert_ne!(
        subject, unkeyed,
        "the subject is not an unkeyed hash of the account"
    );

    // The person makes another account their default.
    let other_account = env
        .wallet
        .seed_managed_evm_account_for_principal_with_index(&env.authority.principal_id, 2)
        .await;
    env.wallet.defaults.lock().await.push(json!({
        "schema": "elastos.wallet.default_account/v1",
        "principal_id": env.authority.principal_id,
        "chain_namespace": "eip155:8453",
        "intent": "transaction_intent",
        "account_id": other_account,
        "set_at": 20,
    }));
    let (_, switched) = env.post(item_start()).await;
    let next = switched["access_subject"].as_str().unwrap();
    assert_ne!(next, subject, "another account is another subject");
}

/// The access subject is keyed per Home and names one account on one chain:
/// another Home's key, another chain or another account is another subject.
#[test]
fn access_subject_depends_on_the_home_key_the_chain_and_the_account() {
    let account = |account_id: &str| RuntimeCustodyCreatorAccount {
        account_id: account_id.to_string(),
        address: "0x00000000000000000000000000000000000000aa".to_string(),
        external_signer: false,
        connector_id: None,
    };
    let subject = |key: u8, principal: &str, chain: &str, account_id: &str| {
        market_listing_access_subject(&[key; 32], principal, chain, &account(account_id))
    };
    let base = subject(1, "person:local:a", "eip155:8453", "wallet:a");
    assert_eq!(
        base,
        subject(1, "person:local:a", "eip155:8453", "wallet:a")
    );
    assert_eq!(base.len(), 32);
    for other in [
        subject(2, "person:local:a", "eip155:8453", "wallet:a"),
        subject(1, "person:local:a", "eip155:20", "wallet:a"),
        subject(1, "person:local:a", "eip155:8453", "wallet:b"),
        subject(1, "person:local:b", "eip155:8453", "wallet:a"),
    ] {
        assert_ne!(base, other);
    }
}

#[test]
fn token_uri_folder_cid_accepts_every_recorded_shape() {
    let v0 = LISTING_FOLDER;
    let v1 = LISTING_LEGACY_FOLDER;
    let accepted = [
        // On-chain `tokenURI(1)`: always the folder form.
        (listing_token_uri(v0), v0),
        // The index's own `tokenURI`, both of its dialects.
        (format!("ipfs://{v0}/metadata.json"), v0),
        (format!("ipfs://{v0}"), v0),
        (format!("ipfs://{v0}/"), v0),
        // A shared link.
        (format!("elastos://{v0}"), v0),
        (format!("elastos://{v1}"), v1),
        (
            format!(
                "ipfs://{v1}/0000000000000000000000000000000000000000000000000000000000000001.json"
            ),
            v1,
        ),
        (format!("  elastos://{v0}  "), v0),
    ];
    for (uri, expected) in accepted {
        assert_eq!(
            token_uri_folder_cid(&uri).as_deref(),
            Some(expected),
            "{uri}"
        );
    }
    for uri in [
        String::new(),
        "ipfs://".to_string(),
        "elastos://".to_string(),
        "ipfs://not-a-cid/metadata.json".to_string(),
        format!("https://ipfs.io/ipfs/{v0}"),
        format!("ipfs://ipfs/{v0}"),
        format!("IPFS://{v0}"),
        v0.to_string(),
        format!("elastos://{v0}/listing.json"),
        format!("ipfs://{v0}0/metadata.json"),
        format!("ipfs://{}/metadata.json", v0.replace('Q', "0")),
    ] {
        assert_eq!(token_uri_folder_cid(&uri), None, "{uri}");
    }
}

/// The `access_subject` a written parser fixture carries.
///
/// The real one is an HMAC under the test Home's device key, over its
/// principal and wallet account, and all three are new on every run -- so the
/// tests below rewrote the tracked fixtures each time they ran. The parser
/// holds the field to its shape only (32 lowercase hex, `ACCESS_SUBJECT` in
/// `market-listing.js`), and `access_subject_depends_on_the_home_key_the_chain_and_the_account`
/// holds the derivation, so a fixture states one fixed value of that shape.
const FIXTURE_ACCESS_SUBJECT: &str = "2ef730f68687b3831bb329e7a167e1a7";

/// `object` as a parser fixture states it: the producer's own answer, with
/// the one per-Home field fixed.
fn parser_fixture_object(mut object: Value) -> Value {
    let subject = object["access_subject"]
        .as_str()
        .expect("a listing for a Home with a buyer account names its access subject");
    assert!(
        subject.len() == 32
            && subject
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{subject}"
    );
    object["access_subject"] = Value::String(FIXTURE_ACCESS_SUBJECT.to_string());
    object
}

/// PS-M12: the `ListingObject`s the main fixture does not show -- truncated
/// offers, an access state the chain could not answer, an unverified and a
/// foreign asset -- written by this producer beside it, for the parser to be
/// held to them too.
#[tokio::test]
async fn listing_object_writes_the_capsule_parser_variants_fixture() {
    let mut variants = serde_json::Map::new();

    let mut chain = chain_with_item(LISTING_FOLDER, LISTING_KID);
    chain.offers = Some(Value::Array(
        (1..=33u8)
            .map(|index| {
                json!({
                    "seller": format!("0x{:040x}", index),
                    "quantity": "0x1",
                    "price": LISTING_NATIVE_PRICE,
                    "pay_token": LISTING_NATIVE_PAY_TOKEN,
                })
            })
            .collect(),
    ));
    let env = ListingEnv::new(
        chain,
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let (status, object) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{object}");
    assert_eq!(object["offers_truncated"], true, "{object}");
    assert_eq!(object["offers"].as_array().unwrap().len(), 32);
    variants.insert("offers_truncated".into(), parser_fixture_object(object));

    let mut chain = chain_with_item(LISTING_FOLDER, LISTING_KID);
    chain.access_unanswered = true;
    let env = ListingEnv::new(
        chain,
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let (_, object) = env.post(item_start()).await;
    assert_eq!(object["access_unknown"], true, "{object}");
    variants.insert("access_unknown".into(), parser_fixture_object(object));

    let mut partial = elastos_v1_metadata(LISTING_KID);
    partial["asset"]["protections"][0]
        .as_object_mut()
        .unwrap()
        .remove("content_identity_base64");
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(LISTING_FOLDER, "metadata.json", &partial),
    )
    .await;
    let (_, object) = env.post(item_start()).await;
    assert_eq!(object["asset"]["readability"], "unverified", "{object}");
    variants.insert("unverified".into(), parser_fixture_object(object));

    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(LISTING_FOLDER, "metadata.json", &lit_metadata(LISTING_KID)),
    )
    .await;
    let (_, object) = env.post(item_start()).await;
    assert_eq!(object["asset"]["readability"], "foreign", "{object}");
    variants.insert("foreign".into(), parser_fixture_object(object));

    // R46: a document this Home cannot read. The offers stand; what the asset
    // is, and its KID, are not known.
    let mut content = content_with(
        LISTING_FOLDER,
        "metadata.json",
        &elastos_v1_metadata(LISTING_KID),
    );
    content.unreadable_paths.push("metadata.json".to_string());
    let env = ListingEnv::new(chain_with_item(LISTING_FOLDER, LISTING_KID), content).await;
    let (status, object) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{object}");
    assert_eq!(object["asset"]["readability"], "unknown", "{object}");
    assert_eq!(object["item"]["kid"], Value::Null, "{object}");
    variants.insert("unknown".into(), parser_fixture_object(object));

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../capsules/marketplace/browser/src/fixtures/market-listing-variants.json");
    let mut bytes = serde_json::to_vec_pretty(&Value::Object(variants)).unwrap();
    bytes.push(b'\n');
    std::fs::write(&path, bytes).unwrap();
}

/// Step 5 of the plan: the capsule's parser fixture is written by this
/// producer, never by hand, so the parser is held to what Runtime really
/// sends.
#[tokio::test]
async fn listing_object_writes_the_capsule_parser_fixture() {
    let env = ListingEnv::new(
        chain_with_item(LISTING_FOLDER, LISTING_KID),
        content_with(
            LISTING_FOLDER,
            "metadata.json",
            &elastos_v1_metadata(LISTING_KID),
        ),
    )
    .await;
    let (status, object) = env.post(item_start()).await;
    assert_eq!(status, StatusCode::OK, "{object}");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../capsules/marketplace/browser/src/fixtures/market-listing.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut bytes = serde_json::to_vec_pretty(&parser_fixture_object(object)).unwrap();
    bytes.push(b'\n');
    std::fs::write(&path, bytes).unwrap();
}

pub(super) const LISTING_NATIVE_PRICE: &str = "0x2386f26fc10000";

pub(super) fn listing_market_item() -> crate::protected_content_market::RuntimeMarketItem {
    crate::protected_content_market::RuntimeMarketItem {
        chain_namespace: "eip155:8453".to_string(),
        network: "base-mainnet".to_string(),
        ledger: LISTING_LEDGER.to_string(),
        token_id: LISTING_TOKEN_ID.to_string(),
        operative: LISTING_OPERATIVE.to_string(),
        kid: None,
    }
}

//! The `ListingObject` (`elastos.marketplace.listing/v1`): one item on the
//! market, built by Runtime from any common identifier (D15).
//!
//! A request starts from whatever a marketplace already has -- a `tokenURI`
//! (or the `ipfs://` / `elastos://` folder CID), a KID, or the chain's own
//! `(ledger, token_id)` -- and every start converges on the same three-leg
//! binding check:
//!
//! 1. `ipReference(kid) == (ledger, token_id)`;
//! 2. the folder of `tokenURI(operative, 1)` is the asset folder;
//! 3. the folder's shared `metadata.json` names that same `kid`.
//!
//! A start supplies only the leg it has; the others are derived, and all
//! three are asserted, so a copied folder, a lying index or a KID lifted from
//! another item each break a leg and nothing passes on one.
//!
//! R46: once the chain has located the item (from a KID or from `(ledger,
//! token_id)`), a leg this Home cannot establish -- a document it cannot
//! read, a binding the chain cannot answer -- no longer refuses the object.
//! The chain's offers stand, `item.kid` is `null` and `asset.readability` is
//! `"unknown"`; only a proven contradiction is `asset_mismatch`. A buy
//! (`buy_offer`) reads the chain alone: `verify_market_item_on_chain`.
//!
//! The shared `metadata.json` is the only document read. `manifest.json` is
//! ElastOS-only, and requiring it would make an ElastOS-protected asset minted
//! elsewhere unreadable for no reason (D4).
//!
//! The account whose `access_state` is reported is resolved here and never
//! returned (D14).
//!
//! Every read above is made at the finalized block. When it finds no item,
//! the listing handler alone reads the chain head once to classify that
//! refusal: an item minted but not final yet answers `pending_finality` with
//! when to look again. That read decides nothing a purchase, an open or a
//! release rests on.

use super::*;
use crate::protected_content_market::{normalize_runtime_market_kid, RuntimeMarketItem};
use elastos_protected_content_provider_contracts::PROTECTION;

pub(crate) const MARKET_LISTING_SCHEMA_V1: &str = "elastos.marketplace.listing/v1";

/// Every ElastOS protection scheme, whichever version, begins with this.
/// An entry that carries it and is not the current, complete scheme is
/// `unverified`; a document with none at all is `foreign` (R12).
const ELASTOS_PROTECTION_SCHEME_PREFIX: &str = "cenc:elastos-";

/// The four identities an open needs, carried in the current scheme's entry.
const ELASTOS_PROTECTION_IDENTITIES: [&str; 4] = [
    "rights_policy_identity_base64",
    "key_envelope_identity_base64",
    "content_key_commitment_base64",
    "content_identity_base64",
];

/// A shared document is a small JSON file. Anything larger is not one. Every
/// read of a folder's `metadata.json` or `listing.json` -- the listing's and
/// adoption's -- is capped at this inside the fetch (R30).
pub(crate) const MARKET_LISTING_DOCUMENT_MAX_BYTES: usize = 256 * 1024;

/// How long a folder read may take before the object is answered
/// `unavailable` rather than left hanging on a slow IPFS lookup.
const MARKET_LISTING_FETCH_TIMEOUT: Duration = Duration::from_secs(20);

/// The whole listing read ends by this, every inner call included. The page
/// aborts its own request at 35 s and retries; this answers `unavailable`
/// before that, so the retry starts from a clear answer.
const MARKET_LISTING_DEADLINE: Duration = Duration::from_secs(30);

/// Logs at debug how long one step of a market read took, so a slow listing
/// names the step that held it.
fn log_market_listing_phase(phase: &str, started: tokio::time::Instant) {
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    tracing::debug!(phase, elapsed_ms, "market listing phase");
}

/// `PROTECTED_CONTENT_OFFERS_MAX` in the chain provider. The provider already
/// bounds its answer; this bounds what this side will carry regardless.
const MARKET_LISTING_OFFERS_MAX: usize = 32;

/// The pay token a native-currency offer is priced in.
const MARKET_NATIVE_PAY_TOKEN: &str = MARKET_ZERO_ADDRESS;

/// The zero address: a native pay token, and an operative that is none.
const MARKET_ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// Exactly one start. Every start is data any marketplace already has;
/// none is ElastOS-specific (D15).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum MarketListingStart {
    /// `ipfs://<cid>/<64-hex>.json`, `ipfs://<cid>`, or `elastos://<cid>`.
    TokenUri(String),
    /// The 16-byte content id, `0x` + 32 hex.
    Kid(String),
    /// The chain's own key.
    Item { ledger: String, token_id: String },
}

impl MarketListingStart {
    /// `source.start`: which identifier the request began from.
    fn label(&self) -> &'static str {
        match self {
            Self::TokenUri(_) => "token_uri",
            Self::Kid(_) => "kid",
            Self::Item { .. } => "item",
        }
    }

    /// The start, canonicalized, or `None` when it names nothing at all.
    fn parse(&self) -> Option<ParsedMarketListingStart> {
        match self {
            Self::TokenUri(uri) => token_uri_folder_cid(uri).map(ParsedMarketListingStart::Folder),
            Self::Kid(kid) => normalize_runtime_market_kid(kid).map(ParsedMarketListingStart::Kid),
            Self::Item { ledger, token_id } => Some(ParsedMarketListingStart::Item {
                ledger: canonical_market_address(ledger)?,
                token_id: canonical_market_uint256(token_id)?,
            }),
        }
    }
}

enum ParsedMarketListingStart {
    Folder(String),
    Kid(String),
    Item { ledger: String, token_id: String },
}

// wire: {"start":{"token_uri":"elastos://…"}} | {"start":{"kid":"0x…"}}
//     | {"start":{"item":{"ledger":"0x…","token_id":"0x…"}}}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::api::gateway) struct MarketListingRequest {
    pub start: MarketListingStart,
}

/// The only way to obtain one is `verify_market_item_binding`.
pub(crate) struct VerifiedMarketItem {
    /// `item.kid` is `Some` exactly when all three legs held (R46): the KID
    /// the chain binds to this item, named by the item's own document.
    pub(crate) item: RuntimeMarketItem,
    pub(crate) folder_cid: String,
    /// The shared `metadata.json`, exactly as fetched; `None` when this Home
    /// could not read it.
    pub(crate) metadata: Option<serde_json::Value>,
    /// The KID is unproven only because something could not be read now --
    /// the document, or the chain's binding of the KID it names -- rather
    /// than because the document names none. A caller that needs the KID
    /// answers "unavailable" for this, never "refused".
    pub(crate) kid_unreadable: bool,
}

/// An item as the chain alone states it: its operative, and the asset folder
/// its own `tokenURI` names. No KID: nothing here reads one (R46).
pub(crate) struct MarketItemOnChain {
    pub(crate) item: RuntimeMarketItem,
    pub(crate) folder_cid: String,
}

#[derive(Debug)]
pub(crate) enum MarketListingRefusal {
    /// A leg of the binding check does not hold, or the start names nothing.
    AssetMismatch,
    /// The chain says the item or the KID is not bound.
    Unbound,
    /// The folder is a legacy `listing.json` link; the existing import
    /// handles it (D12).
    LegacyListing,
    /// The chain or the folder could not be read. The reason is logged, not
    /// answered.
    Unavailable(String),
    /// No Home this one can reach serves the item's folder: every holder
    /// Carrier knows refused it, or Carrier knows none. Unlike `Unavailable`,
    /// asking again soon gives the same answer.
    NoHolder,
}

/// Every leg, whichever start supplied it and whichever were derived.
struct MarketBindingLegs {
    kid: String,
    /// `ipReference(kid)`.
    binding: (String, String),
    /// The item the object is about.
    ledger: String,
    token_id: String,
    chain_item: MarketChainItem,
    folder: String,
    metadata: serde_json::Value,
}

struct MarketChainItem {
    operative: String,
    token_uri: String,
}

/// The same three assertions end a start that holds all three legs (D15).
fn assert_market_binding(legs: &MarketBindingLegs) -> Result<(), MarketListingRefusal> {
    // 1. The chain binds the KID to exactly this item.
    if !legs.binding.0.eq_ignore_ascii_case(&legs.ledger)
        || !legs.binding.1.eq_ignore_ascii_case(&legs.token_id)
    {
        tracing::debug!("market listing refused: kid is bound to another item");
        return Err(MarketListingRefusal::AssetMismatch);
    }
    // 2. The asset folder is the one the token itself names.
    if token_uri_folder_cid(&legs.chain_item.token_uri).as_deref() != Some(legs.folder.as_str()) {
        tracing::debug!("market listing refused: folder is not the token's tokenURI folder");
        return Err(MarketListingRefusal::AssetMismatch);
    }
    // 3. The folder's shared document names the same KID.
    if metadata_market_kid(&legs.metadata).as_deref() != Some(legs.kid.as_str()) {
        tracing::debug!("market listing refused: metadata.json names another kid");
        return Err(MarketListingRefusal::AssetMismatch);
    }
    Ok(())
}

/// The market source's chain: where every market read is made.
struct MarketSourceChain {
    chain_namespace: String,
    network: String,
    chain_id: u64,
}

impl MarketSourceChain {
    async fn resolve(state: &GatewayState) -> Result<Self, MarketListingRefusal> {
        let started = tokio::time::Instant::now();
        let source = resolve_runtime_custody_creator_mint_source(state).await;
        log_market_listing_phase("market_source", started);
        let source =
            source.map_err(|error| MarketListingRefusal::Unavailable(format!("{error:#}")))?;
        let chain_id = source
            .chain_namespace
            .strip_prefix("eip155:")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| MarketListingRefusal::Unavailable("market source chain".into()))?;
        Ok(Self {
            chain_namespace: source.chain_namespace,
            network: source.network,
            chain_id,
        })
    }

    fn chain<'a>(&'a self, state: &'a GatewayState) -> MarketChain<'a> {
        MarketChain {
            state,
            network: &self.network,
            chain_id: self.chain_id,
        }
    }

    /// `(ledger, token_id)` on this chain: its operative, which must be one
    /// (a zero operative is no item), and the folder its `tokenURI` names.
    async fn locate_item(
        &self,
        state: &GatewayState,
        ledger: &str,
        token_id: &str,
    ) -> Result<MarketItemOnChain, MarketListingRefusal> {
        let chain_item = self.chain(state).item(ledger, token_id).await?;
        if chain_item.operative == MARKET_ZERO_ADDRESS {
            tracing::debug!("market item has no operative");
            return Err(MarketListingRefusal::Unbound);
        }
        let folder_cid = token_uri_folder_cid(&chain_item.token_uri).ok_or_else(|| {
            tracing::debug!("market item's tokenURI names no asset folder");
            MarketListingRefusal::AssetMismatch
        })?;
        Ok(MarketItemOnChain {
            item: RuntimeMarketItem {
                chain_namespace: self.chain_namespace.clone(),
                network: self.network.clone(),
                ledger: ledger.to_string(),
                token_id: token_id.to_string(),
                operative: chain_item.operative,
                kid: None,
            },
            folder_cid,
        })
    }
}

/// What a shared document says about its KID (R9).
pub(crate) enum MetadataKid {
    /// Every KID field present names this one KID.
    Named(String),
    /// No KID field, or none that is a KID at all: nothing is claimed.
    Absent,
    /// Two KID fields name two different KIDs: the document contradicts
    /// itself.
    Contradictory,
}

/// The item a buy names, verified from the chain alone (R46): the market
/// source's chain, the item's non-zero operative, and the asset folder its
/// own `tokenURI` names. Neither the KID binding nor any document is read.
pub(crate) async fn verify_market_item_on_chain(
    state: &GatewayState,
    ledger: &str,
    token_id: &str,
) -> Result<MarketItemOnChain, MarketListingRefusal> {
    let ledger = canonical_market_address(ledger).ok_or(MarketListingRefusal::AssetMismatch)?;
    let token_id = canonical_market_uint256(token_id).ok_or(MarketListingRefusal::AssetMismatch)?;
    MarketSourceChain::resolve(state)
        .await?
        .locate_item(state, &ledger, &token_id)
        .await
}

/// Whether the chain binds `kid` to `item` (`ipReference(kid)`), asked on the
/// item's own chain. `Ok(false)` is the chain binding it to another item.
pub(crate) async fn market_kid_binds_to_item(
    state: &GatewayState,
    item: &RuntimeMarketItem,
    kid: &str,
) -> Result<bool, MarketListingRefusal> {
    let chain = MarketChain {
        state,
        network: &item.network,
        chain_id: item
            .chain_id()
            .map_err(|error| MarketListingRefusal::Unavailable(error.to_string()))?,
    };
    let (ledger, token_id) = chain.kid_binding(kid).await?;
    Ok(ledger.eq_ignore_ascii_case(&item.ledger) && token_id.eq_ignore_ascii_case(&item.token_id))
}

/// The item the chain binds `kid` to (`ipReference(kid)`) on `network`, read
/// at the finalized block with every check the listing applies, or `None`
/// when the chain binds the KID to no item.
pub(crate) async fn market_kid_binding(
    state: &GatewayState,
    chain_namespace: &str,
    network: &str,
    kid: &str,
) -> Result<Option<(String, String)>, MarketListingRefusal> {
    let chain_id = chain_namespace
        .strip_prefix("eip155:")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| MarketListingRefusal::Unavailable("kid binding chain".into()))?;
    let chain = MarketChain {
        state,
        network,
        chain_id,
    };
    match chain.kid_binding(kid).await {
        Ok(binding) => Ok(Some(binding)),
        Err(MarketListingRefusal::Unbound) => Ok(None),
        Err(refusal) => Err(refusal),
    }
}

pub(crate) async fn verify_market_item_binding(
    state: &GatewayState,
    start: &MarketListingStart,
) -> Result<VerifiedMarketItem, MarketListingRefusal> {
    LocatedMarketStart::locate(state, start)
        .await?
        .prove(state)
        .await
}

/// A link names a folder, and only its document can lead to the item: the
/// document is read first, and it decides whether this is a market item at
/// all -- a legacy `listing.json` folder goes to the import (D12) without the
/// market source ever being asked for (PS-M7). All three legs must hold.
async fn verify_market_folder_start(
    state: &GatewayState,
    folder: String,
) -> Result<VerifiedMarketItem, MarketListingRefusal> {
    let metadata = fetch_market_shared_metadata(state, &folder).await?;
    let source = MarketSourceChain::resolve(state).await?;
    let chain = source.chain(state);
    let kid = metadata_market_kid(&metadata).ok_or(MarketListingRefusal::AssetMismatch)?;
    let binding = chain.kid_binding(&kid).await?;
    let chain_item = chain.item(&binding.0, &binding.1).await?;
    let legs = MarketBindingLegs {
        ledger: binding.0.clone(),
        token_id: binding.1.clone(),
        kid,
        binding,
        chain_item,
        folder,
        metadata,
    };
    assert_market_binding(&legs)?;
    Ok(VerifiedMarketItem {
        item: RuntimeMarketItem {
            chain_namespace: source.chain_namespace.clone(),
            network: source.network.clone(),
            ledger: legs.ledger,
            token_id: legs.token_id,
            operative: legs.chain_item.operative,
            kid: Some(legs.kid),
        },
        folder_cid: legs.folder,
        metadata: Some(legs.metadata),
        kid_unreadable: false,
    })
}

/// A KID leads to the item through the chain's own binding
/// ([`LocatedMarketStart::locate`]). The item's document then either names
/// that KID (all three legs), contradicts it (`asset_mismatch`), or cannot
/// say -- unread, or naming none -- and the KID stays unproven (R46).
async fn prove_market_kid_document(
    state: &GatewayState,
    kid: String,
    located: MarketItemOnChain,
) -> Result<VerifiedMarketItem, MarketListingRefusal> {
    let read = read_market_shared_metadata(state, &located.folder_cid).await?;
    let kid_unreadable = read == Err(true);
    let metadata = read.ok();
    let proven = match metadata.as_ref().map(classify_metadata_kid) {
        Some(MetadataKid::Named(named)) if named == kid => Some(kid),
        Some(MetadataKid::Named(_) | MetadataKid::Contradictory) => {
            tracing::debug!("market listing refused: metadata.json names another kid");
            return Err(MarketListingRefusal::AssetMismatch);
        }
        Some(MetadataKid::Absent) | None => None,
    };
    Ok(verified_market_item(
        located,
        metadata,
        proven,
        kid_unreadable,
    ))
}

/// The chain's own key leads to the item ([`LocatedMarketStart::locate`]),
/// and its folder to its document.
/// A KID the document names is checked against the chain: bound to another
/// item is `asset_mismatch`; a binding the chain cannot answer, or a
/// document that cannot be read, leaves the KID unproven and the offers
/// stand (R46).
async fn prove_market_item_document(
    state: &GatewayState,
    source: &MarketSourceChain,
    located: MarketItemOnChain,
) -> Result<VerifiedMarketItem, MarketListingRefusal> {
    let read = read_market_shared_metadata(state, &located.folder_cid).await?;
    let mut kid_unreadable = read == Err(true);
    let metadata = read.ok();
    let proven = match metadata.as_ref().map(classify_metadata_kid) {
        Some(MetadataKid::Named(kid)) => match source.chain(state).kid_binding(&kid).await {
            Ok((bound_ledger, bound_token_id))
                if bound_ledger.eq_ignore_ascii_case(&located.item.ledger)
                    && bound_token_id.eq_ignore_ascii_case(&located.item.token_id) =>
            {
                Some(kid)
            }
            Ok(_) => {
                tracing::debug!("market listing refused: kid is bound to another item");
                return Err(MarketListingRefusal::AssetMismatch);
            }
            Err(MarketListingRefusal::Unbound) => {
                tracing::debug!("market listing: the document's kid is not bound; kid unknown");
                None
            }
            Err(MarketListingRefusal::Unavailable(reason)) => {
                tracing::debug!(%reason, "market listing: kid binding unavailable; kid unknown");
                kid_unreadable = true;
                None
            }
            Err(refusal) => return Err(refusal),
        },
        Some(MetadataKid::Contradictory) => {
            tracing::debug!("market listing refused: metadata.json names two kids");
            return Err(MarketListingRefusal::AssetMismatch);
        }
        Some(MetadataKid::Absent) | None => None,
    };
    Ok(verified_market_item(
        located,
        metadata,
        proven,
        kid_unreadable,
    ))
}

fn verified_market_item(
    located: MarketItemOnChain,
    metadata: Option<serde_json::Value>,
    proven_kid: Option<String>,
    kid_unreadable: bool,
) -> VerifiedMarketItem {
    let mut item = located.item;
    item.kid = proven_kid;
    VerifiedMarketItem {
        item,
        folder_cid: located.folder_cid,
        metadata,
        kid_unreadable,
    }
}

/// Whether this Home can reach the pool that keeps an item's keys, as far as
/// it can tell from the item's own document -- proven its own by all three
/// legs (Plan B T4.7: routing replaces the Plan A "here or elsewhere" guard).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MarketItemCustody {
    /// A pool this Home can reach keeps them: its own (owner or holder), one
    /// it serves, or one it added in Custody. A copy can be built and played.
    Pool,
    /// No pool this Home knows keeps them: Buy waits until the pool is added.
    Unresolved,
    /// The document names no ElastOS protection, or names one that cannot
    /// be adopted anyway: nothing here holds the keys, and nothing here was
    /// going to (a foreign asset opens where it was protected).
    NotHeldHere,
    /// Something needed to tell -- the document, the KID's binding, the
    /// custody composition -- could not be read now. The reason is logged.
    Unknown,
}

/// The listing's `custody_route`, stated only when proven.
pub(crate) fn market_custody_route(custody: &MarketItemCustody) -> Option<&'static str> {
    match custody {
        MarketItemCustody::Pool => Some("pool"),
        MarketItemCustody::Unresolved => Some("unresolved"),
        MarketItemCustody::NotHeldHere | MarketItemCustody::Unknown => None,
    }
}

/// [`MarketItemCustody`] for an item the binding check verified.
pub(crate) fn verified_market_item_custody(
    state: &GatewayState,
    verified: &VerifiedMarketItem,
) -> MarketItemCustody {
    let Some(registry) = state.provider_registry.as_ref() else {
        return MarketItemCustody::Unknown;
    };
    let (Some(_), Some(metadata)) = (verified.item.kid.as_deref(), verified.metadata.as_ref())
    else {
        return if verified.kid_unreadable {
            MarketItemCustody::Unknown
        } else {
            MarketItemCustody::NotHeldHere
        };
    };
    let Ok(Some(dataset)) = crate::protected_content_market::shared_read_dataset(metadata) else {
        return MarketItemCustody::NotHeldHere;
    };
    // Cached sources only: the listing runs inside its 30 s deadline (F1)
    // and makes no `describe` call.
    market_item_custody_from_route(
        crate::protected_content_runtime::runtime_custody_pool_route_for_shared_dataset(
            &state.data_dir,
            registry,
            &dataset,
            crate::auth::now_ts(),
        ),
    )
}

/// [`MarketItemCustody`] for the answer of the cached pool-route check.
pub(crate) fn market_item_custody_from_route(route: anyhow::Result<bool>) -> MarketItemCustody {
    match route {
        Ok(true) => MarketItemCustody::Pool,
        Ok(false) => MarketItemCustody::Unresolved,
        Err(error) => {
            tracing::debug!(%error, "market item custody could not be compared");
            MarketItemCustody::Unknown
        }
    }
}

/// Where the keys of an item a buy names are held, read before anything is
/// asked of the Wallet. The item is already verified from the chain alone
/// (operative, and the folder its own `tokenURI` names); this reads only
/// what that did not: the folder's document, and the chain's binding of the
/// KID it names.
pub(crate) async fn runtime_market_buy_item_custody(
    state: &GatewayState,
    item: &RuntimeMarketItem,
    folder_cid: &str,
) -> MarketItemCustody {
    let metadata = match read_market_shared_metadata(state, folder_cid).await {
        Ok(Ok(document)) => document,
        // Unreadable now: nothing says this Home holds the keys.
        Ok(Err(true)) | Err(MarketListingRefusal::NoHolder) => return MarketItemCustody::Unknown,
        Ok(Err(false)) | Err(_) => return MarketItemCustody::NotHeldHere,
    };
    let MetadataKid::Named(kid) = classify_metadata_kid(&metadata) else {
        return MarketItemCustody::NotHeldHere;
    };
    let proven = match market_kid_binds_to_item(state, item, &kid).await {
        Ok(true) => Some(kid),
        // Bound elsewhere, or not bound: adoption refuses such a document on
        // its own; it says nothing about where this item's keys are.
        Ok(false) | Err(MarketListingRefusal::Unbound) => return MarketItemCustody::NotHeldHere,
        Err(refusal) => {
            tracing::debug!(?refusal, "market buy: the kid binding could not be read");
            return MarketItemCustody::Unknown;
        }
    };
    let mut verified_item = item.clone();
    verified_item.kid = proven;
    verified_market_item_custody(
        state,
        &VerifiedMarketItem {
            item: verified_item,
            folder_cid: folder_cid.to_string(),
            metadata: Some(metadata),
            kid_unreadable: false,
        },
    )
}

/// Where a start leads before any document is read: an item the chain has
/// located, whose document is then read beside its offers, or -- from a
/// link, which leads to the item only through its document -- an item
/// already verified.
enum LocatedMarketStart {
    Verified(VerifiedMarketItem),
    Item {
        source: MarketSourceChain,
        located: MarketItemOnChain,
    },
    Kid {
        kid: String,
        located: MarketItemOnChain,
    },
}

impl LocatedMarketStart {
    async fn locate(
        state: &GatewayState,
        start: &MarketListingStart,
    ) -> Result<Self, MarketListingRefusal> {
        match start.parse().ok_or(MarketListingRefusal::AssetMismatch)? {
            ParsedMarketListingStart::Folder(folder) => Ok(Self::Verified(
                verify_market_folder_start(state, folder).await?,
            )),
            ParsedMarketListingStart::Kid(kid) => {
                let source = MarketSourceChain::resolve(state).await?;
                let (ledger, token_id) = source.chain(state).kid_binding(&kid).await?;
                let located = source.locate_item(state, &ledger, &token_id).await?;
                Ok(Self::Kid { kid, located })
            }
            ParsedMarketListingStart::Item { ledger, token_id } => {
                let source = MarketSourceChain::resolve(state).await?;
                let located = source.locate_item(state, &ledger, &token_id).await?;
                Ok(Self::Item { source, located })
            }
        }
    }

    /// The item as the chain states it, before its document is read.
    fn item(&self) -> &RuntimeMarketItem {
        match self {
            Self::Verified(verified) => &verified.item,
            Self::Item { located, .. } | Self::Kid { located, .. } => &located.item,
        }
    }

    async fn prove(self, state: &GatewayState) -> Result<VerifiedMarketItem, MarketListingRefusal> {
        match self {
            Self::Verified(verified) => Ok(verified),
            Self::Item { source, located } => {
                prove_market_item_document(state, &source, located).await
            }
            Self::Kid { kid, located } => prove_market_kid_document(state, kid, located).await,
        }
    }
}

pub(crate) async fn build_market_listing_object(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    start: &MarketListingStart,
) -> Result<serde_json::Value, MarketListingRefusal> {
    let located = LocatedMarketStart::locate(state, start).await?;
    let item = located.item().clone();
    // The document is read beside the offers and the buyer account, not
    // before them: a document no Home serves ends the read at once, and a
    // slow one costs no time the offers did not already take.
    let account = async {
        let started = tokio::time::Instant::now();
        let account =
            resolve_runtime_custody_buyer_account(state, authority, &item.chain_namespace).await;
        log_market_listing_phase("buyer_account", started);
        Ok(match account {
            Ok(account) => Some(account),
            Err(error) => {
                tracing::debug!(%error, "market listing has no buyer account to ask about");
                None
            }
        })
    };
    let (verified, offers, account) = tokio::try_join!(
        located.prove(state),
        resolve_market_item_offers(state, &item),
        account,
    )?;
    let started = tokio::time::Instant::now();
    let (access_state, access_unknown) =
        market_listing_access_state(state, authority, account.as_ref(), &verified.item).await;
    log_market_listing_phase("access_state", started);
    let metadata = verified
        .metadata
        .as_ref()
        .unwrap_or(&serde_json::Value::Null);
    // Readability is advice about the item's own document, and it is given
    // only for a document proven to be this item's (R46).
    let readability = if verified.item.kid.is_some() {
        market_listing_readability(metadata)
    } else {
        "unknown"
    };
    let mut object = serde_json::json!({
        "schema": MARKET_LISTING_SCHEMA_V1,
        "item": {
            "chain_namespace": verified.item.chain_namespace,
            "network": verified.item.network,
            "ledger": verified.item.ledger,
            "token_id": verified.item.token_id,
            "operative": verified.item.operative,
            "kid": verified.item.kid,
        },
        "asset": {
            "uri": format!("elastos://{}", verified.folder_cid),
            "title": market_listing_text(metadata.get("name")),
            "description": market_listing_text(metadata.get("description")),
            "cover_cid": market_listing_cover_cid(metadata.get("image")),
            "category": market_listing_category(metadata),
            "mime_type": market_listing_text(
                metadata
                    .pointer("/media/mimeType")
                    .or_else(|| metadata.pointer("/asset/mimeType")),
            ),
            "readability": readability,
        },
        "offers": offers.offers,
        "access_state": access_state,
        "source": {
            "start": start.label(),
            "read_at_block": format!("0x{:x}", offers.finalized_block_number),
        },
    });
    if offers.truncated {
        object["offers_truncated"] = serde_json::Value::Bool(true);
    }
    if access_unknown {
        object["access_unknown"] = serde_json::Value::Bool(true);
    }
    if let (Some(account), Some(home_key)) = (
        account.as_ref(),
        market_listing_access_subject_key(&state.data_dir),
    ) {
        object["access_subject"] = serde_json::Value::String(market_listing_access_subject(
            &home_key,
            authority.verified_context().principal_id(),
            &verified.item.chain_namespace,
            account,
        ));
    }
    // Stated only when proven (S4-Q18): `pool` when this Home can reach the
    // item's pool, `unresolved` when it cannot, so the page disables Buy,
    // Open and Download only then.
    let started = tokio::time::Instant::now();
    let custody = verified_market_item_custody(state, &verified);
    log_market_listing_phase("custody_check", started);
    if let Some(route) = market_custody_route(&custody) {
        object["custody_route"] = serde_json::Value::String(route.to_string());
    }
    Ok(object)
}

/// `POST /api/apps/marketplace/listing` -- the object a Buy is decided on.
pub(in crate::api::gateway) async fn marketplace_listing(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    request: Result<Json<MarketListingRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(err) = require_home_launch_token_for_any_context(
        &state.data_dir,
        &headers,
        &[MARKETPLACE_CAPSULE_ID, SYSTEM_CAPSULE_ID],
    ) {
        return system_error_response(err);
    }
    let authority = match require_app_runtime_wallet_authority(
        &state.data_dir,
        &headers,
        &[MARKETPLACE_CAPSULE_ID, SYSTEM_CAPSULE_ID],
    ) {
        Ok(authority) => authority,
        Err(err) => return system_error_response(err),
    };
    // A body that is not exactly one start -- not JSON, an unknown or doubled
    // key, a start that names nothing -- is the caller's error, not a
    // mismatch, and it is answered the one way the page reads (R34).
    let invalid_start = || {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "code": "invalid_start" })),
        )
            .into_response()
    };
    let request = match request {
        Ok(Json(request)) => request,
        Err(rejection) => {
            tracing::debug!(%rejection, "market listing request refused");
            return invalid_start();
        }
    };
    if request.start.parse().is_none() {
        return invalid_start();
    }
    // Every read below -- the object and, for an unbound item, the head
    // classification -- runs inside one deadline. A read that has not
    // answered by then is `unavailable`, the same answer as any other
    // unreadable chain or folder.
    let answer = async {
        match build_market_listing_object(&state, &authority, &request.start).await {
            Ok(object) => Json(object).into_response(),
            Err(MarketListingRefusal::AssetMismatch) => (
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "code": "asset_mismatch" })),
            )
                .into_response(),
            // The page is told why, never given a way round it: what it may buy
            // or open is still decided on the finalized block.
            Err(MarketListingRefusal::Unbound) => {
                match classify_market_listing_finality(&state, &request.start).await {
                    Some(ready_at) => (
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({
                            "code": "pending_finality",
                            "ready_at": ready_at,
                        })),
                    )
                        .into_response(),
                    None => (
                        StatusCode::NOT_FOUND,
                        Json(serde_json::json!({ "code": "unbound" })),
                    )
                        .into_response(),
                }
            }
            Err(MarketListingRefusal::LegacyListing) => {
                Json(serde_json::json!({ "legacy_listing": true })).into_response()
            }
            Err(MarketListingRefusal::Unavailable(reason)) => market_listing_unavailable(&reason),
            // Final for now, unlike `unavailable`: the page shows the item as
            // unavailable rather than reading it again.
            Err(MarketListingRefusal::NoHolder) => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "code": "no_holder" })),
            )
                .into_response(),
        }
    };
    let started = tokio::time::Instant::now();
    let answer = tokio::time::timeout(MARKET_LISTING_DEADLINE, answer).await;
    log_market_listing_phase("listing", started);
    answer.unwrap_or_else(|_| {
        market_listing_unavailable(&format!(
            "the listing read passed its {} s deadline",
            MARKET_LISTING_DEADLINE.as_secs()
        ))
    })
}

/// The listing's one `unavailable` answer: the chain or a folder could not
/// be read, or the read passed its deadline. The reason is logged, not
/// answered.
fn market_listing_unavailable(reason: &str) -> Response {
    tracing::warn!(%reason, "market listing unavailable");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "code": "unavailable" })),
    )
        .into_response()
}

/// Classification only: `Some(ready_at)` when the item the finalized read
/// could not find is bound at the chain head -- minted, and waiting for the
/// finalized block to reach it -- and `None` for every other case, which
/// stays `unbound`.
///
/// This is the one place that asks the chain about the head for the market,
/// and the listing handler is its one caller. The answer names no operative,
/// folder or access, so it can only change which refusal the page shows.
async fn classify_market_listing_finality(
    state: &GatewayState,
    start: &MarketListingStart,
) -> Option<u64> {
    let subject = match start.parse()? {
        ParsedMarketListingStart::Item { ledger, token_id } => {
            serde_json::json!({ "ledger": ledger, "token_id": token_id })
        }
        ParsedMarketListingStart::Kid(kid) => serde_json::json!({ "content_access_id": kid }),
        // A link leads to the item only through its document's KID.
        ParsedMarketListingStart::Folder(folder) => {
            let metadata = fetch_market_shared_metadata(state, &folder).await.ok()?;
            serde_json::json!({ "content_access_id": metadata_market_kid(&metadata)? })
        }
    };
    let source = MarketSourceChain::resolve(state).await.ok()?;
    let mut request = subject.clone();
    request["op"] = "classify_protected_content_item_finality".into();
    request["network"] = source.network.clone().into();
    let answer: ClassifiedProtectedContentItemFinality =
        match source.chain(state).call(request).await {
            Ok(answer) => answer,
            Err(refusal) => {
                tracing::debug!(?refusal, "market listing finality could not be classified");
                return None;
            }
        };
    // Each side writes the item in its own canonical form; compare those.
    let echoed = |key: &str, value: &Option<String>, canonical: fn(&str) -> Option<String>| {
        subject.get(key).and_then(serde_json::Value::as_str)
            == value.as_deref().and_then(canonical).as_deref()
    };
    if !echoed("ledger", &answer.ledger, canonical_market_address)
        || !echoed("token_id", &answer.token_id, canonical_market_uint256)
        || !echoed(
            "content_access_id",
            &answer.content_access_id,
            normalize_runtime_market_kid,
        )
    {
        tracing::debug!("market listing finality answer is about another item");
        return None;
    }
    if !answer.bound_at_head {
        return None;
    }
    let ready_at = market_pending_finality_ready_at(
        answer.head_block_timestamp,
        answer.finalized_block_timestamp,
        now_ts(),
    );
    tracing::debug!(ready_at, "market listing item awaits finality");
    Some(ready_at)
}

/// When the finalized block should reach an item only the head binds.
///
/// One read does not say which block minted the item, only that it lies
/// after the finalized block and at or before the head. So the head block
/// stands in for it -- the latest it can be -- and the finalized block
/// reaches it about one current finalized-to-head lag after the head's own
/// timestamp. The estimate is late rather than early, by at most the time
/// the item had already waited. A lag the chain does not state sensibly
/// (none, or longer than an acquisition is ever watched for) is the usual
/// Base lag instead, and a head dated far from this Home's clock is counted
/// from now.
pub(in crate::api::gateway) fn market_pending_finality_ready_at(
    head_timestamp: u64,
    finalized_timestamp: u64,
    now: u64,
) -> u64 {
    use crate::protected_content_runtime::{
        RUNTIME_CUSTODY_EXPECTED_FINALITY_LAG_SECS, RUNTIME_CUSTODY_FINALITY_WATCH_SECS,
    };
    let lag = match head_timestamp.saturating_sub(finalized_timestamp) {
        lag @ 1..=RUNTIME_CUSTODY_FINALITY_WATCH_SECS => lag,
        _ => RUNTIME_CUSTODY_EXPECTED_FINALITY_LAG_SECS,
    };
    let head = if head_timestamp.abs_diff(now) > RUNTIME_CUSTODY_FINALITY_WATCH_SECS {
        now
    } else {
        head_timestamp
    };
    head.saturating_add(lag)
}

/// `ipfs://<cid>/<file>` or `ipfs://<cid>` or `elastos://<cid>` -> `<cid>`;
/// any other shape -> None. Handles every shape Task 0 recorded: the
/// on-chain folder form, the index's `…/metadata.json` and bare forms, and a
/// shared link. The folder is the first path component after the scheme.
pub(crate) fn token_uri_folder_cid(uri: &str) -> Option<String> {
    let uri = uri.trim();
    let cid = if let Some(path) = uri.strip_prefix("ipfs://") {
        path.split('/').next()?
    } else {
        // A shared link names the asset and nothing inside it.
        uri.strip_prefix("elastos://")?.trim_end_matches('/')
    };
    is_market_folder_cid(cid).then(|| cid.to_string())
}

/// CIDv0 (`Qm` + 44 base58) or CIDv1 (`b` + base32) -- exactly the shape the
/// capsule's parser accepts for an asset URI, so what this side emits is
/// always something the page will take.
fn is_market_folder_cid(value: &str) -> bool {
    if let Some(rest) = value.strip_prefix("Qm") {
        return rest.len() == 44
            && rest.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() && !matches!(byte, b'0' | b'I' | b'O' | b'l')
            });
    }
    if let Some(rest) = value.strip_prefix('b') {
        return (45..=95).contains(&rest.len())
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte));
    }
    false
}

/// The KID a shared document names: top-level `kid`, then `properties.kid`,
/// then `asset.kid` (R9). Every one of those that is present must name the
/// same KID; a document that disagrees with itself names none.
fn metadata_market_kid(metadata: &serde_json::Value) -> Option<String> {
    match classify_metadata_kid(metadata) {
        MetadataKid::Named(kid) => Some(kid),
        MetadataKid::Absent | MetadataKid::Contradictory => None,
    }
}

/// What the document's KID fields say (R9). A field that is not a KID at all
/// claims nothing; two fields naming two KIDs are a contradiction.
pub(crate) fn classify_metadata_kid(metadata: &serde_json::Value) -> MetadataKid {
    let mut named: Option<String> = None;
    for pointer in ["/kid", "/properties/kid", "/asset/kid"] {
        let Some(kid) = metadata
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .and_then(normalize_runtime_market_kid)
        else {
            continue;
        };
        match &named {
            Some(first) if first != &kid => return MetadataKid::Contradictory,
            Some(_) => {}
            None => named = Some(kid),
        }
    }
    named.map_or(MetadataKid::Absent, MetadataKid::Named)
}

fn canonical_market_address(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    (value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then_some(value)
}

/// A uint256 as this Home writes one: `0x`, lowercase, no leading zeros.
fn canonical_market_uint256(value: &str) -> Option<String> {
    let digits = value.trim().strip_prefix("0x")?;
    if digits.is_empty()
        || digits.len() > 64
        || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let trimmed = digits.trim_start_matches('0').to_ascii_lowercase();
    Some(if trimmed.is_empty() {
        "0x0".to_string()
    } else {
        format!("0x{trimmed}")
    })
}

/// Advisory, from the shared document only (D8, R12).
fn market_listing_readability(metadata: &serde_json::Value) -> &'static str {
    if !metadata.is_object() {
        return "unverified";
    }
    let mut elastos_scheme = false;
    for entry in metadata
        .pointer("/asset/protections")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let scheme = entry
            .get("protectionType")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if PROTECTION.registry().is_listed_scheme(scheme)
            && ELASTOS_PROTECTION_IDENTITIES
                .iter()
                .all(|field| is_canonical_base64(entry.get(*field)))
        {
            return "verified";
        }
        elastos_scheme |= scheme.starts_with(ELASTOS_PROTECTION_SCHEME_PREFIX);
    }
    let media = metadata.pointer("/media/protectionType");
    let media_schemes: Vec<&str> = match media {
        Some(serde_json::Value::Array(values)) => {
            values.iter().filter_map(|v| v.as_str()).collect()
        }
        Some(serde_json::Value::String(value)) => vec![value.as_str()],
        _ => Vec::new(),
    };
    elastos_scheme |= media_schemes
        .iter()
        .any(|scheme| scheme.starts_with(ELASTOS_PROTECTION_SCHEME_PREFIX));
    if elastos_scheme {
        "unverified"
    } else {
        "foreign"
    }
}

fn is_canonical_base64(value: Option<&serde_json::Value>) -> bool {
    use base64::Engine as _;
    let Some(text) = value.and_then(serde_json::Value::as_str) else {
        return false;
    };
    !text.is_empty()
        && base64::engine::general_purpose::STANDARD
            .decode(text)
            .is_ok_and(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes) == text)
}

/// Text from the shared document, bounded by the same bound as
/// `bounded_directory_text` bounds index text. Control characters become
/// spaces: a description with lines is still one line of text on a card, and
/// the page refuses them.
fn market_listing_text(value: Option<&serde_json::Value>) -> String {
    bounded_market_text(
        value
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim(),
    )
}

fn bounded_market_text(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .take(MARKET_DIRECTORY_MAX_TEXT_CHARS)
        .collect()
}

/// `properties.category`, else `media.contentType`, lowercased BEFORE it is
/// bounded (Q-M1): lowercasing can lengthen text, and a category cut first
/// could come out longer than the bound the page holds it to.
fn market_listing_category(metadata: &serde_json::Value) -> String {
    let category = metadata
        .pointer("/properties/category")
        .or_else(|| metadata.pointer("/media/contentType"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    bounded_market_text(&category)
}

/// `ipfs://<cid>` or a bare CID. Anything else -- a URL, a path inside a
/// folder, an empty string -- is no cover, never a guess.
fn market_listing_cover_cid(value: Option<&serde_json::Value>) -> Option<String> {
    let text = value.and_then(serde_json::Value::as_str)?.trim();
    let cid = text.strip_prefix("ipfs://").unwrap_or(text);
    is_market_folder_cid(cid).then(|| cid.to_string())
}

/// The shared document, or the legacy `listing.json` redirect.
///
/// `listing.json` is asked for only when the folder has no `metadata.json`
/// (R30): a document that is slow, oversized or unreadable is `unavailable`,
/// never a reason to read a second file.
async fn fetch_market_shared_metadata(
    state: &GatewayState,
    folder: &str,
) -> Result<serde_json::Value, MarketListingRefusal> {
    match fetch_market_folder_file(state, folder, "metadata.json").await {
        Ok(bytes) => {
            // A folder whose document is not JSON cannot name this item's KID.
            let document: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| MarketListingRefusal::AssetMismatch)?;
            if !document.is_object() {
                return Err(MarketListingRefusal::AssetMismatch);
            }
            Ok(document)
        }
        Err(MarketFolderFileError::NotFound(reason)) => {
            if fetch_market_folder_file(state, folder, "listing.json")
                .await
                .is_ok()
            {
                return Err(MarketListingRefusal::LegacyListing);
            }
            Err(MarketListingRefusal::Unavailable(reason))
        }
        Err(MarketFolderFileError::Unreadable(reason)) => {
            Err(MarketListingRefusal::Unavailable(reason))
        }
        Err(MarketFolderFileError::NoHolder(reason)) => {
            tracing::debug!(%reason, "market listing: no reachable Home serves the folder");
            Err(MarketListingRefusal::NoHolder)
        }
    }
}

/// The shared document for a start the chain already located (R46), or why
/// there is none: `Err(true)` when this Home cannot read it now,
/// `Err(false)` when it is not a JSON object -- the item is known without it
/// either way. A folder holding only a legacy `listing.json` still goes to
/// the import (D12).
async fn read_market_shared_metadata(
    state: &GatewayState,
    folder: &str,
) -> Result<Result<serde_json::Value, bool>, MarketListingRefusal> {
    match fetch_market_shared_metadata(state, folder).await {
        Ok(document) => Ok(Ok(document)),
        Err(refusal @ (MarketListingRefusal::LegacyListing | MarketListingRefusal::NoHolder)) => {
            Err(refusal)
        }
        Err(MarketListingRefusal::Unavailable(reason)) => {
            tracing::debug!(%reason, "market listing: the shared document is unreadable");
            Ok(Err(true))
        }
        Err(_) => {
            tracing::debug!("market listing: the shared document is not a JSON object");
            Ok(Err(false))
        }
    }
}

/// Why a folder file was not read.
#[derive(Debug)]
enum MarketFolderFileError {
    /// The content plane says the folder has no such file.
    NotFound(String),
    /// No Home this one can reach serves the folder: this Home lacks it, and
    /// every holder Carrier knows refused it, or Carrier knows none.
    NoHolder(String),
    /// Anything else, which asking again may change: a timeout, a holder
    /// that failed on the way, an oversized file, an unreachable plane.
    Unreadable(String),
}

impl MarketFolderFileError {
    /// The one reading of a content-plane failure. The planes state the
    /// reason only in words: Carrier availability's code, which the content
    /// plane names after a local miss, then the stub's and the content
    /// plane's `not_found`, and IPFS's "no link named".
    fn of(error: &anyhow::Error) -> Self {
        let text = format!("{error:#}");
        let availability_code = |code: &str| text.contains(&format!("({code})"));
        if availability_code(crate::carrier::CARRIER_FETCH_IN_TRANSIT_CODE) {
            return Self::Unreadable(text);
        }
        if availability_code(crate::carrier::CARRIER_FETCH_NO_HOLDER_CODE) {
            return Self::NoHolder(text);
        }
        let lowercase = text.to_ascii_lowercase();
        let not_found = |words: &str| {
            ["not_found", "not found", "no link named"]
                .iter()
                .any(|marker| words.contains(marker))
        };
        // Holders that refused, or answered only that the folder lacks the
        // file: their words follow the code.
        let failed = format!("({})", crate::carrier::CARRIER_FETCH_FAILED_CODE);
        if let Some(at) = lowercase.find(&failed) {
            return if not_found(&lowercase[at..]) {
                Self::NotFound(text)
            } else {
                Self::NoHolder(text)
            };
        }
        if not_found(&lowercase) {
            Self::NotFound(text)
        } else {
            Self::Unreadable(text)
        }
    }
}

async fn fetch_market_folder_file(
    state: &GatewayState,
    folder: &str,
    path: &str,
) -> Result<Vec<u8>, MarketFolderFileError> {
    let registry = state.provider_registry.as_ref().ok_or_else(|| {
        MarketFolderFileError::Unreadable("content provider unavailable".to_string())
    })?;
    let started = tokio::time::Instant::now();
    // This Home's own store, then the holders Carrier knows now. A folder
    // no known holder serves is answered as soon as each has refused, rather
    // than after the wait for a holder to announce itself.
    let read = tokio::time::timeout(
        MARKET_LISTING_FETCH_TIMEOUT,
        crate::content::fetch_bytes_from_known_holders_capped(
            registry,
            folder,
            Some(path),
            MARKET_LISTING_DOCUMENT_MAX_BYTES,
        ),
    )
    .await;
    log_market_listing_phase(&format!("folder_read:{path}"), started);
    let bytes = read
        .map_err(|_| {
            MarketFolderFileError::Unreadable("market listing folder read timed out".to_string())
        })?
        .map_err(|error| MarketFolderFileError::of(&error))?;
    if bytes.len() > MARKET_LISTING_DOCUMENT_MAX_BYTES {
        return Err(MarketFolderFileError::Unreadable(
            "market listing document is too large".to_string(),
        ));
    }
    Ok(bytes)
}

/// `resolve_protected_content_item` (R36): the item's operative and token URI
/// at a finalized block. Every field is named; an answer with any other is not
/// this op's answer.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedProtectedContentItem {
    pub(crate) schema: String,
    pub(crate) network: String,
    pub(crate) chain_id: u64,
    pub(crate) ledger: String,
    pub(crate) token_id: String,
    pub(crate) operative: String,
    pub(crate) token_uri: String,
    /// The block the read was made at. Named so the answer is well formed;
    /// only the offers' block is stated to the page (`read_at_block`).
    #[allow(dead_code)]
    pub(crate) finalized_block_number: u64,
}

/// `resolve_protected_content_kid_binding` (R36): `ipReference(kid)`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedProtectedContentKidBinding {
    pub(crate) schema: String,
    pub(crate) network: String,
    pub(crate) chain_id: u64,
    pub(crate) content_access_id: String,
    pub(crate) ledger: String,
    pub(crate) token_id: String,
    /// The block the read was made at. Named so the answer is well formed;
    /// only the offers' block is stated to the page (`read_at_block`).
    #[allow(dead_code)]
    pub(crate) finalized_block_number: u64,
}

/// `resolve_protected_content_item_offers` (R36): every seller's offer, at one
/// finalized block, at most `PROTECTED_CONTENT_OFFERS_MAX` of them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedProtectedContentItemOffers {
    pub(crate) schema: String,
    pub(crate) network: String,
    pub(crate) chain_id: u64,
    pub(crate) ledger: String,
    pub(crate) token_id: String,
    pub(crate) operative: String,
    pub(crate) finalized_block_number: u64,
    pub(crate) truncated: bool,
    pub(crate) offers: Vec<ResolvedProtectedContentItemOffer>,
}

/// One seller's offer. `payment_processor` is named for an ERC-20 offer and
/// absent for a native one.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedProtectedContentItemOffer {
    pub(crate) seller: String,
    pub(crate) quantity: String,
    pub(crate) price: String,
    pub(crate) pay_token: String,
    #[serde(default)]
    pub(crate) payment_processor: Option<String>,
}

/// The head classification read's answer: whether the item is bound at the
/// head, and the two blocks it was read between. It names the item exactly
/// as it was asked about and nothing a decision could rest on.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::api::gateway) struct ClassifiedProtectedContentItemFinality {
    pub(in crate::api::gateway) schema: String,
    pub(in crate::api::gateway) network: String,
    pub(in crate::api::gateway) chain_id: u64,
    pub(in crate::api::gateway) ledger: Option<String>,
    pub(in crate::api::gateway) token_id: Option<String>,
    pub(in crate::api::gateway) content_access_id: Option<String>,
    pub(in crate::api::gateway) bound_at_head: bool,
    /// Named so the answer is well formed; the estimate needs only times.
    #[allow(dead_code)]
    pub(in crate::api::gateway) head_block_number: u64,
    pub(in crate::api::gateway) head_block_timestamp: u64,
    #[allow(dead_code)]
    pub(in crate::api::gateway) finalized_block_number: u64,
    pub(in crate::api::gateway) finalized_block_timestamp: u64,
}

/// What every one of these answers states about where it was read.
trait MarketChainAnswer: serde::de::DeserializeOwned {
    const SCHEMA: &'static str;
    fn schema(&self) -> &str;
    fn network(&self) -> &str;
    fn chain_id(&self) -> u64;
}

impl MarketChainAnswer for ResolvedProtectedContentItem {
    const SCHEMA: &'static str = "elastos.chain.protected-content-item/v1";
    fn schema(&self) -> &str {
        &self.schema
    }
    fn network(&self) -> &str {
        &self.network
    }
    fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

impl MarketChainAnswer for ResolvedProtectedContentKidBinding {
    const SCHEMA: &'static str = "elastos.chain.protected-content-kid-binding/v1";
    fn schema(&self) -> &str {
        &self.schema
    }
    fn network(&self) -> &str {
        &self.network
    }
    fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

impl MarketChainAnswer for ClassifiedProtectedContentItemFinality {
    const SCHEMA: &'static str = "elastos.chain.protected-content-item-finality/v1";
    fn schema(&self) -> &str {
        &self.schema
    }
    fn network(&self) -> &str {
        &self.network
    }
    fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

impl MarketChainAnswer for ResolvedProtectedContentItemOffers {
    const SCHEMA: &'static str = "elastos.chain.protected-content-item-offers/v1";
    fn schema(&self) -> &str {
        &self.schema
    }
    fn network(&self) -> &str {
        &self.network
    }
    fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

/// The chain-provider ops the binding check reads, each answer typed and
/// checked against what was asked.
struct MarketChain<'a> {
    state: &'a GatewayState,
    network: &'a str,
    chain_id: u64,
}

impl MarketChain<'_> {
    async fn call<T: MarketChainAnswer>(
        &self,
        request: serde_json::Value,
    ) -> Result<T, MarketListingRefusal> {
        let phase = request
            .get("op")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("chain_read")
            .to_owned();
        let started = tokio::time::Instant::now();
        let answer = wallet_chain_provider_data(self.state, request).await;
        log_market_listing_phase(&phase, started);
        let answer = answer.map_err(|(status, message)| {
            let code = message.split(':').next().unwrap_or_default().trim();
            if status == StatusCode::BAD_REQUEST
                && matches!(
                    code,
                    "unbound_protected_content_item" | "unbound_protected_content_kid"
                )
            {
                MarketListingRefusal::Unbound
            } else {
                MarketListingRefusal::Unavailable(message)
            }
        })?;
        let answer: T = serde_json::from_value(answer).map_err(|error| {
            MarketListingRefusal::Unavailable(format!("malformed {}: {error}", T::SCHEMA))
        })?;
        if answer.schema() != T::SCHEMA
            || answer.network() != self.network
            || answer.chain_id() != self.chain_id
        {
            return Err(MarketListingRefusal::Unavailable(format!(
                "chain answer is not {} on {} (chain {})",
                T::SCHEMA,
                self.network,
                self.chain_id
            )));
        }
        Ok(answer)
    }

    async fn kid_binding(&self, kid: &str) -> Result<(String, String), MarketListingRefusal> {
        let answer: ResolvedProtectedContentKidBinding = self
            .call(serde_json::json!({
                "op": "resolve_protected_content_kid_binding",
                "network": self.network,
                "content_access_id": kid,
            }))
            .await?;
        let malformed = || MarketListingRefusal::Unavailable("malformed kid binding".into());
        if normalize_runtime_market_kid(&answer.content_access_id).as_deref() != Some(kid) {
            return Err(malformed());
        }
        let ledger = canonical_market_address(&answer.ledger).ok_or_else(malformed)?;
        let token_id = canonical_market_uint256(&answer.token_id).ok_or_else(malformed)?;
        Ok((ledger, token_id))
    }

    async fn item(
        &self,
        ledger: &str,
        token_id: &str,
    ) -> Result<MarketChainItem, MarketListingRefusal> {
        let answer: ResolvedProtectedContentItem = self
            .call(serde_json::json!({
                "op": "resolve_protected_content_item",
                "network": self.network,
                "ledger": ledger,
                "token_id": token_id,
            }))
            .await?;
        let malformed = || MarketListingRefusal::Unavailable("malformed item".into());
        if canonical_market_address(&answer.ledger).as_deref() != Some(ledger)
            || canonical_market_uint256(&answer.token_id).as_deref() != Some(token_id)
        {
            return Err(malformed());
        }
        Ok(MarketChainItem {
            operative: canonical_market_address(&answer.operative).ok_or_else(malformed)?,
            token_uri: answer.token_uri,
        })
    }
}

struct MarketItemOffers {
    offers: Vec<serde_json::Value>,
    truncated: bool,
    finalized_block_number: u64,
}

/// Every live offer, at one finalized block (D6). Sold-out offers are dropped.
async fn resolve_market_item_offers(
    state: &GatewayState,
    item: &RuntimeMarketItem,
) -> Result<MarketItemOffers, MarketListingRefusal> {
    let chain = MarketChain {
        state,
        network: &item.network,
        chain_id: item
            .chain_id()
            .map_err(|error| MarketListingRefusal::Unavailable(error.to_string()))?,
    };
    let answer: ResolvedProtectedContentItemOffers = chain
        .call(serde_json::json!({
            "op": "resolve_protected_content_item_offers",
            "network": item.network,
            "ledger": item.ledger,
            "token_id": item.token_id,
        }))
        .await?;
    let malformed = || MarketListingRefusal::Unavailable("malformed item offers".into());
    // Offers read for another item or operative are not this item's offers.
    if canonical_market_address(&answer.operative).as_deref() != Some(item.operative.as_str())
        || canonical_market_address(&answer.ledger).as_deref() != Some(item.ledger.as_str())
        || canonical_market_uint256(&answer.token_id).as_deref() != Some(item.token_id.as_str())
    {
        return Err(malformed());
    }
    let mut truncated = answer.truncated;
    let mut offers = Vec::with_capacity(answer.offers.len().min(MARKET_LISTING_OFFERS_MAX));
    for entry in &answer.offers {
        let (Some(seller), Some(quantity), Some(price), Some(pay_token)) = (
            canonical_market_address(&entry.seller),
            canonical_market_uint256(&entry.quantity),
            canonical_market_uint256(&entry.price),
            canonical_market_address(&entry.pay_token),
        ) else {
            return Err(malformed());
        };
        if quantity == "0x0" {
            continue;
        }
        if offers.len() == MARKET_LISTING_OFFERS_MAX {
            truncated = true;
            break;
        }
        // Every offer names its processor (R16): `null` for a native-token
        // offer, which pays through none, and the chain's address otherwise.
        // An ERC-20 offer the chain named no processor for is an answer this
        // side cannot state honestly, so it is not guessed at.
        let payment_processor = if pay_token == MARKET_NATIVE_PAY_TOKEN {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(
                entry
                    .payment_processor
                    .as_deref()
                    .and_then(canonical_market_address)
                    .ok_or_else(malformed)?,
            )
        };
        offers.push(serde_json::json!({
            "seller": seller,
            "quantity": quantity,
            "price": price,
            "pay_token": pay_token,
            "payment_processor": payment_processor,
        }));
    }
    Ok(MarketItemOffers {
        offers,
        truncated,
        finalized_block_number: answer.finalized_block_number,
    })
}

/// This Home's key for `access_subject`: derived from its own device signing
/// key under a label of its own, so it never leaves this Home and differs
/// from every other Home's. `None` on a Home without a device key.
fn market_listing_access_subject_key(data_dir: &std::path::Path) -> Option<[u8; 32]> {
    let (device_key, _) =
        crate::collaboration_profile_authority::load_existing_device_signing_key(data_dir)
            .ok()
            .flatten()?;
    let derivation = hkdf::Hkdf::<sha2::Sha256>::new(None, &device_key.to_bytes());
    let mut key = [0u8; 32];
    derivation
        .expand(b"elastos.marketplace.access-subject-key/v1", &mut key)
        .ok()?;
    Some(key)
}

/// The account an object's `access_state` answers for, as the page may know
/// it (D14): HMAC-SHA256, keyed with this Home's own secret, over who asked,
/// on which chain, and which wallet account answered -- truncated to 16
/// bytes. Equal for every answer about the same account on the same chain
/// and different once either changes, so a page can key a cache by it.
/// Every input is derivable from the address; the key is not, so nothing
/// outside this Home can compute it from an address it has seen.
pub(in crate::api::gateway) fn market_listing_access_subject(
    home_key: &[u8; 32],
    principal_id: &str,
    chain_namespace: &str,
    account: &RuntimeCustodyCreatorAccount,
) -> String {
    use hmac::Mac as _;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(home_key)
        .expect("HMAC accepts a key of any length");
    for part in [
        "elastos.marketplace.access-subject/v1",
        principal_id,
        chain_namespace,
        account.account_id.as_str(),
    ] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
    hex::encode(&mac.finalize().into_bytes()[..16])
}

/// `creator`, `purchased` or `available`, and whether that last answer is
/// only "not known to be otherwise". The account is the caller's and never
/// leaves Runtime; `None` when this Home has no buyer account to ask about.
async fn market_listing_access_state(
    state: &GatewayState,
    authority: &RuntimeWalletAuthority,
    account: Option<&RuntimeCustodyCreatorAccount>,
    item: &RuntimeMarketItem,
) -> (&'static str, bool) {
    let principal_id = authority.verified_context().principal_id();
    let mut unknown = false;
    // This person's own listing of the item: minted here, or bought through
    // the existing listing path.
    match crate::protected_content_runtime::runtime_custody_listing_chain_index(
        &state.data_dir,
        principal_id,
    ) {
        Ok(index) => {
            if let Some(local) = index.iter().find(|entry| {
                entry.chain_namespace == item.chain_namespace
                    && entry.ledger.eq_ignore_ascii_case(&item.ledger)
                    && entry.token_id.eq_ignore_ascii_case(&item.token_id)
            }) {
                match local.access_state.as_str() {
                    "creator" => return ("creator", false),
                    "purchased" => return ("purchased", false),
                    _ => {}
                }
            }
        }
        Err(error) => {
            tracing::warn!(%error, "market listing could not read local listings");
            unknown = true;
        }
    }
    // A market purchase this person completed.
    match crate::protected_content_market::load_runtime_market_purchase(
        &state.data_dir,
        principal_id,
        item,
    ) {
        Ok(Some(record))
            if matches!(
                record.progress,
                crate::protected_content_runtime::RuntimeCustodyPurchaseProgress::Complete { .. }
            ) =>
        {
            return ("purchased", false);
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(%error, "market listing could not read the market purchase");
            unknown = true;
        }
    }
    // The chain's own answer for this Home's buyer account.
    let Some(account) = account else {
        return ("available", true);
    };
    // Without a proven KID there is nothing to ask the chain about (R46).
    let Some(kid) = item.kid.as_deref() else {
        return ("available", true);
    };
    let request_id = format!("market-listing:{}:{}", item.ledger, item.token_id);
    // `Ok(None)` is the chain saying no; a chain that could not answer is an
    // error, and the object says it does not know rather than "available".
    match resolve_runtime_custody_item_access(
        state,
        &item.chain_namespace,
        &item.network,
        kid,
        account,
        &request_id,
    )
    .await
    {
        Ok(Some(_)) => ("purchased", false),
        Ok(None) => ("available", unknown),
        Err(error) => {
            tracing::debug!(%error, "market listing purchase access unavailable");
            ("available", true)
        }
    }
}

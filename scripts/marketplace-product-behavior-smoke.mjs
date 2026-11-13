#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

function assert(condition, message, details = undefined) {
  if (!condition) {
    throw new Error(`${message}${details ? `\n${JSON.stringify(details, null, 2)}` : ""}`);
  }
}

const html = readFileSync(resolve("capsules/marketplace/browser/index.html"), "utf8");
const js = readFileSync(resolve("capsules/marketplace/browser/marketplace.js"), "utf8");
// The protected-item listing contract lives in its own module so that the
// tests beside it can import it. This file pins the contract in that module
// and pins marketplace.js to importing it rather than keeping a second copy.
const listingJs = readFileSync(resolve("capsules/marketplace/browser/src/listing.js"), "utf8");
const listingTests = readFileSync(resolve("capsules/marketplace/browser/src/listing.test.mjs"), "utf8");
const css = readFileSync(resolve("capsules/marketplace/browser/marketplace.css"), "utf8");
const marketListingJs = readFileSync(resolve("capsules/marketplace/browser/src/market-listing.js"), "utf8");
const marketListingTests = readFileSync(resolve("capsules/marketplace/browser/src/market-listing.test.mjs"), "utf8");
// The control every Explore card offers lives in its own module, beside its
// render tests.
const cardJs = readFileSync(resolve("capsules/marketplace/browser/src/market-card.js"), "utf8");
const cardTests = readFileSync(resolve("capsules/marketplace/browser/src/market-card.test.mjs"), "utf8");
const marketFinalityJs = readFileSync(resolve("capsules/marketplace/browser/src/market-finality.js"), "utf8");
const layoutSmoke = readFileSync(resolve("scripts/marketplace-product-layout-smoke.mjs"), "utf8");
const vendorScript = readFileSync(resolve("scripts/vendor-ui-tokens.sh"), "utf8");

const letterSpacingValues = [...css.matchAll(/letter-spacing:\s*([^;]+);/g)].map((match) => match[1].trim());

assert(
  html.includes("<title>Marketplace · ElastOS</title>")
    && html.includes('<script src="./elastos-theme.js"></script>')
    && html.includes('<link rel="stylesheet" href="./elastos-ui.css">')
    && html.includes('<div class="store-product-name">Marketplace</div>')
    && html.includes('data-destination="media"'),
  "Marketplace must expose the Apps and Media surfaces and load the canonical shared theme assets.",
);
assert(
  vendorScript.includes("marketplace/browser"),
  "Marketplace must participate in the canonical shared token vendoring list.",
);
assert(
  letterSpacingValues.length > 0 && letterSpacingValues.every((value) => value === "0"),
  "Marketplace UIUX must keep every letter-spacing declaration at 0.",
  { letterSpacingValues },
);
assert(
  js.includes('let homeToken = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("home_token") || "";')
    && !js.includes('params.get("home_token")'),
  "Marketplace must read the Home token from the hash once, not from search params.",
);
assert(
  js.includes("function announceHomeChrome()")
    && js.includes('window.top.postMessage({ type: "home:app-ready", homeToken }, homeParentOrigin);')
    && js.includes("homeChromeReady = true;")
    && js.includes("syncHomeMenuManifest();"),
  "Marketplace must announce Home readiness before syncing the menu manifest.",
);
assert(
  js.includes('type: "home:menu-manifest"')
    && js.includes('title: "File"')
    && js.includes('title: "View"')
    && js.includes('{ label: "New Window", cmd: "__new-window" }')
    && js.includes('{ label: "Close Window", cmd: "__close-window" }')
    && js.includes('{ label: "Refresh", cmd: "refresh" }')
    && js.includes("lastHomeMenuManifestSignature"),
  "Marketplace must publish the accepted Home menu and deduplicate unchanged manifests.",
);
assert(
  js.includes('if (event.origin !== "null" || event.source !== window.parent) {')
    && js.includes('if (data?.type !== "elastos:menu-command" || typeof data.cmd !== "string") {')
    && js.includes('data?.type === "elastos.marketplace.navigate/v1"')
    && js.includes('target: "assistant"')
    && js.includes("function applyModelsLaunch")
    && !js.includes("window.location.origin")
    && !js.includes('event.source !== window.top'),
  "Marketplace must accept inbound Home commands only from the opaque parent boundary.",
);
assert(
  js.includes('fetch("/api/capsules/catalog", { headers: { "x-elastos-home-token": homeToken } })')
    && js.includes('fetch("/api/capsules/interfaces", { headers: { "x-elastos-home-token": homeToken } })')
    && js.includes('postObjectProvider("list_runtime_custody", {})')
    && js.includes('`/api/provider/object/${operation}`')
    && js.includes('postObjectProvider("buy", { mint_id: mintId })')
    && !js.includes("/api/apps/marketplace/catalog")
    && js.includes('type: "home:open-target"')
    // The viewer follows the item. Marketplace used to name the player for
    // everything, which sent pictures and documents to a video surface.
    && js.includes("target: viewerForListing(listing),")
    && !js.includes('target: "elacity-player"'),
  "Marketplace must keep the canonical catalog/interface reads, typed media routes, and Home launch target path.",
);
assert(
  // The kind is Runtime's answer, carried in the row. Deciding it from the
  // MIME instead would be a second rule for a question the open path already
  // enforces, and a second rule can disagree.
  listingJs.includes("export function viewerForListing(listing) {")
    && listingJs.includes("listing?.contentKind === CONTENT_KIND_MEDIA")
    && listingJs.includes('? "elacity-player"')
    && listingJs.includes(': "elacity-reader"')
    && listingJs.includes('export const CONTENT_KIND_MEDIA = "media";')
    && listingJs.includes('export const CONTENT_KIND_OBJECT = "object";')
    && listingJs.includes('"content_kind",')
    && !/viewerForListing[\s\S]{0,200}startsWith\("video\//.test(listingJs)
    && listingTests.includes("an item opens in the viewer its own kind names")
    && listingTests.includes("the kind decides the viewer, and the MIME never overrides it")
    && listingTests.includes("an item whose kind cannot be read opens in the viewer that can say so"),
  "The viewer for a listed item must be chosen by the kind Runtime names, with tests covering both viewers, a disagreeing MIME, and the unreadable case.",
);
assert(
  listingJs.includes('export const RUNTIME_CUSTODY_LISTINGS_RESPONSE_SCHEMA_V1 = "elastos.library.runtime-custody-listings/v1";')
    && listingJs.includes('export const RUNTIME_CUSTODY_LISTING_SCHEMA_V1 = "elastos.library.runtime-custody-listing/v1";')
    && listingJs.includes('export const RUNTIME_CUSTODY_AVAILABILITY_SCHEMA_V1 = "elastos.library.runtime-custody-availability-summary/v1";')
    && listingJs.includes("export const MAX_RUNTIME_CUSTODY_LISTINGS = 128;")
    && listingJs.includes("export const MAX_RUNTIME_CUSTODY_PUBLIC_TEXT_BYTES = 256;")
    && listingJs.includes("const MAX_U32 = 0xffffffff;")
    && listingJs.includes("const UINT256_HEX = /^0x(?:0|[1-9a-f][0-9a-f]{0,63})$/;")
    && listingJs.includes("const ADDRESS_HEX = /^0x[0-9a-f]{40}$/;")
    && listingJs.includes("const SHA256_HEX = /^[0-9a-f]{64}$/;")
    && listingJs.includes("function boundedTimestamp(value) {")
    && listingJs.includes("Number.isSafeInteger(value)")
    && listingJs.includes('typeof value !== "string"')
    && listingJs.includes("new TextEncoder().encode(value).length > maxBytes")
    && listingJs.includes("observedReplicas < requiredReplicas")
    && listingJs.includes("export function uint256Decimal(value) {")
    && listingJs.includes("if (!UINT256_HEX.test(value)) {")
    && listingJs.includes("return BigInt(value).toString(10);")
    && !listingJs.includes("MAX_PUBLISHED_AT_LENGTH"),
  "The protected-item listing contract must keep its canonical Runtime values and validators.",
);
assert(
  // Every field Runtime's own summary emits is named here, including the
  // availability receipt digest whose absence once emptied the whole shelf.
  listingJs.includes('"receipt_digest",')
    && listingJs.includes("const AVAILABILITY_KEYS = [")
    && listingJs.includes("const LISTING_KEYS = [")
    && listingJs.includes("boundedText(value.codecs, MAX_RUNTIME_CUSTODY_PUBLIC_TEXT_BYTES)")
    && listingTests.includes("an object row Runtime publishes today is accepted, empty codecs and all")
    && listingTests.includes("the availability receipt digest is accepted and stays out of the rendered row"),
  "The listing parser must accept exactly what Runtime publishes for both media and object rows, with tests that say so.",
);
assert(
  // An owned copy can always be built again: the chain says whose it is, and
  // the file is made of material anyone can fetch. So a person who holds one
  // is offered that, whether the copy never arrived or they deleted it.
  js.includes('postObjectProvider("download_owned_copy", { mint_id: mintId })')
    && js.includes("async function downloadOwnedCopy(mintId) {")
    && js.includes('data-action="download-copy"')
    && js.includes("const pendingDownloads = new Set();")
    // The gate is that an item still on sale to this person offers no
    // rebuild. The sentence carrying it has changed twice -- an early return,
    // then a branch, now the card's own state -- so the rule is asserted
    // rather than the spelling.
    && /const secondary = !listing\.catalogOnly && \(state === "mine" \|\| state === "owned"\)/.test(js)
    && /data-action="download-copy"/.test(js),
  "Marketplace must let a person rebuild a copy they own, and offer it only on copies they own.",
);
assert(
  // The other half of adding a listing: the person who listed it has the link
  // to pass on. Runtime has answered with it since listings existed and no
  // surface showed it, so reaching an item on another Home meant already
  // knowing its address.
  js.includes("function showShareListing(mintId) {")
    && js.includes('data-action="share-listing"')
    && js.includes('id="share-listing-uri"')
    // The link is selected for the person rather than written to their
    // clipboard: reading that authority from a capsule is a line this app's
    // own gate holds, a few assertions below.
    && js.includes("field?.select();")
    && js.includes("press the copy key")
    && js.includes('listing.accessState !== "creator"')
    && listingJs.includes('"listing_uri",')
    && listingJs.includes("listingUriFromInput(value.listing_uri)")
    && listingTests.includes("a link that is not a listing link"),
  "Marketplace must give the person who listed an item the link others add it by.",
);
assert(
  // A shared asset link reaches Runtime as a `token_uri` start. The app
  // checks the link's shape before asking anything, and `legacy_listing:
  // true` keeps reaching the old import path -- unchanged, and still with
  // the shape Runtime has always required of it.
  js.includes("async function readMarketListing(start) {")
    && js.includes('postObjectProvider("import_runtime_custody", { listing_uri: legacyListingUriFromLink(link) })')
    && js.includes("function marketLinkFromInput(value) {")
    && js.includes("function legacyListingUriFromLink(link) {")
    && js.includes("const MARKET_LINK_URI = ")
    && js.includes("result.legacy")
    && html.includes('id="import-listing-uri"')
    && html.includes('id="import-listing"')
    && listingJs.includes("export function listingUriFromInput(value) {")
    && listingJs.includes("const LISTING_URI = /^elastos:\\/\\/[A-Za-z0-9]{16,128}$/;")
    && listingTests.includes("a listing link is accepted in the shapes Runtime publishes")
    && listingTests.includes("a listing link that is not one is refused before Runtime is asked"),
  "Marketplace must let a person add a listing another Home published, and check the link's shape before asking Runtime.",
);
assert(
  // Buy and read are separate workflows (shared-context.md D1): the offer
  // sheet reads a `ListingObject` and buys through `buy_offer`, never
  // through the mint-keyed `buy` op, and it never learns this Home's account
  // (D14) -- Explore's own Buy sends the chain's own key only.
  js.includes('from "./src/market-listing.js";')
    && js.includes("function openOfferSheet(listing, { properties = false, returnFocus = null } = {}) {")
    && js.includes("function renderOfferSheetContent(listing, options = {}) {")
    && js.includes("async function buyOffer(listing, offer) {")
    && js.includes('postObjectProvider("buy_offer", body)')
    && js.includes("parseBuyOfferAnswer(")
    && js.includes("marketItemKey(listing.item)")
    && js.includes('data-action="buy-listing"')
    && js.includes("async function buyCatalogItem(ledger, tokenId) {")
    && js.includes("{ item: { ledger, token_id: tokenId } }")
    && js.includes("The seller changed the terms. Review and confirm.")
    && js.includes("Not yet verified to open here")
    && js.includes("Opens on ela.city"),
  "Marketplace must buy a market listing -- from a link or from Explore -- through the offer sheet and buy_offer, never through a mint or an account.",
);
assert(
  // A bought item is labelled by what this Home holds: only a copy with a
  // mint of this Home's own is "In your library"; every other bought item
  // is "Purchased" and offers Details, the item's properties read from its
  // own listing. The layout smoke drives all three variants in a browser.
  js.includes("function ownedHolding(listing) {")
    && js.includes('return ownedHolding(listing) === "library" ? "In your library" : "Purchased";')
    && js.includes('data-action="item-details"')
    && js.includes("async function showCatalogDetails(ledger, tokenId) {")
    && js.includes("function itemPropertiesSection(listing) {")
    && !js.includes("Owned — preparing")
    && layoutSmoke.includes("Details on a foreign bought item shows its properties and where it opens, with no offers, no download and no full address")
    && layoutSmoke.includes("A bought market item with no copy here yet says Purchased, keeps its seller, and offers Download copy and Details -- never Buy"),
  "Marketplace must label a bought item by what this Home holds and offer its properties through Details.",
);
assert(
  // What the offer sheet says is decided by typed answers, never by guesses:
  // the item this Home holds or listed is not offered again, a purchase
  // already under way holds every other seller's Buy, and the completion
  // toast promises only as much as adoption delivered. The layout smoke
  // drives each of these in a browser; this pins the pieces it relies on.
  js.includes("function offerSheetOwnershipCopy(accessState) {")
    && js.includes('const OFFER_IN_PROGRESS_COPY = "Another purchase of this item is in progress";')
    && js.includes('outcome.kind === "attempt_in_progress"')
    && js.includes("recordedOfferAttempts.set(key, { offer: outcome.current });")
    && marketListingJs.includes("export function offerCompletionMessage(adoption) {")
    && marketListingJs.includes('"Bought. It opens on ela.city."')
    && marketListingJs.includes('"Bought. Use Download copy to add it to your Library here."')
    // Nothing adopts a pending purchase by itself, so no copy promises it.
    && !js.includes("It will appear in your Library once")
    && js.includes('class="offer-sheet-status" role="status"')
    && js.includes("restoreOfferSheetFocus(focusMark);")
    && js.includes("This offer is no longer available")
    && js.includes("showToast(`${OFFER_IN_PROGRESS_COPY}.`, false);")
    && js.includes("recordedOfferAttempts.delete(marketItemKey(listing.item));")
    && layoutSmoke.includes("The purchase confirmation must open with focus on Cancel, not on Buy")
    && marketListingJs.includes('const BUY_OFFER_OFFER_CODES = ["terms_changed", "attempt_in_progress"];')
    && marketListingTests.includes("attempt_in_progress carries the recorded offer, validated like one")
    && layoutSmoke.includes("attempt_in_progress must mark the recorded seller's row and hold every other row's Buy")
    && layoutSmoke.includes('"/api/apps/marketplace/listing"]'),
  "Marketplace's offer sheet must honour access_state, attempt_in_progress and adoption, and its browser smoke must drive them.",
);
assert(
  // R46: a purchase rests on the chain's terms alone, so a listing whose
  // readability is `unknown` and whose kid is null still sells, says nothing
  // about where it opens, names no kid, and its catalog row reads as "not
  // learned yet". R48: a Buy refused as unavailable says the market could
  // not be reached; "The purchase did not finish." stays for a real failure.
  marketListingJs.includes('export const MARKET_READABILITY_STATES = ["verified", "unverified", "foreign", "unknown"];')
    && marketListingJs.includes('const BUY_OFFER_UNAVAILABLE_MESSAGE = "Runtime custody purchase is unavailable";')
    && marketListingTests.includes("readability unknown (R46) parses, with a null kid, and keeps its offers to buy")
    && marketListingTests.includes("a buy_offer refused as unavailable is its own kind, not a failed purchase (R48)")
    && marketListingTests.includes("marketItemClaim leaves kid out when the listing's kid is null (R46)")
    && js.includes('const MARKET_UNREACHABLE_COPY = "The market couldn’t be reached. Try again.";')
    && js.includes('if (outcome.kind === "unavailable") {')
    && js.includes("showToast(MARKET_UNREACHABLE_COPY, true);")
    && js.includes('"The purchase did not finish."')
    && js.includes('if (listing.asset.readability === "unknown") {\n      marketAssetReadability.delete(key);')
    && layoutSmoke.includes("An item of unknown readability must say nothing about where it opens and keep every Buy enabled")
    && layoutSmoke.includes("A Buy of an item whose kid is null must name no kid, and a Buy refused as unavailable must stay pressable"),
  "Marketplace must sell an item of unknown readability, name no null kid, and word an unreachable market apart from a failed purchase.",
);
assert(
  // R44: a purchase Runtime recorded keeps a Continue row on its recorded
  // terms even when its seller no longer lists the item. R45: a bought item
  // whose adoption is pending has a control that spends nothing -- Download
  // copy, which names the item and lets Runtime rerun adoption.
  js.includes("const offers = offersWithRecordedAttempt(listing.offers, inProgress?.recorded);")
    && marketListingJs.includes("export function offersWithRecordedAttempt(offers, recorded) {")
    && marketListingJs.includes("export function marketItemClaim(item) {")
    && marketListingTests.includes("a recorded attempt whose seller is no longer listed gets its own row, on the recorded terms")
    && js.includes("async function downloadMarketCopy(item, { open = false } = {}) {")
    && js.includes('postObjectProvider("download_owned_copy", { item: marketItemClaim(item) })')
    && js.includes('data-action="download-market-copy"')
    && js.includes("item: marketItemClaim(listing.item),")
    && layoutSmoke.includes("A recorded purchase whose seller no longer lists the item must still offer Continue on its recorded terms")
    && layoutSmoke.includes("Download copy on a held sheet must name the item, pay nothing, and reload media and catalog")
    && layoutSmoke.includes("A refused Download copy must say what is missing and keep the sheet open")
    && marketListingJs.includes('export const DOWNLOAD_NO_ACCESS_COPY = "This account has no access to this item.";')
    && marketListingJs.includes('if (code === "no_access") {\n    return DOWNLOAD_NO_ACCESS_COPY;')
    && marketListingJs.includes('if (code === "access_confirming") {\n    return DOWNLOAD_CONFIRMING_COPY;')
    && marketListingTests.includes("a grant the chain has not finalized yet says the access is still being confirmed")
    && marketListingTests.includes("any other download refusal says the copy could not be downloaded, never that items could not load")
    && (js.match(/showToast\(downloadRefusalCopy\(error\), true\);/g) || []).length === 2
    && !js.includes('publicError(error.message, "That copy could not be downloaded.")')
    && layoutSmoke.includes("A bought market item with no copy here yet says Purchased, keeps its seller, and offers Download copy and Details -- never Buy"),
  "Marketplace must keep a recorded purchase resumable, give a pending adoption a Download copy that never pays, word a refused download by its code, and its browser smoke must drive all three.",
);
assert(
  // The wallet asks for a signature, not for a decision, and it arrives after
  // the availability re-check. A person who has not seen the terms by then has
  // waited minutes to find out what they cost.
  js.includes("function showBuyConfirmation(mintId) {")
    && js.includes('if (action === "confirm-buy") {')
    && js.includes("Your wallet asks you to approve the payment.")
    && js.includes("uint256Decimal(listing.price)")
    && js.includes("uint256Decimal(listing.quantity)")
    && js.includes("abbreviateAddress(listing.sellerAddress)")
    && js.includes("showBuyConfirmation(target.dataset.mint)"),
  "Marketplace must show a purchase's terms, and what follows them, before it spends anything.",
);
assert(
  // A purchase lives in Runtime, not in the page that started it. Saying so is
  // its own field rather than another access_state value, because a new value
  // falls silently into a consumer's default while an unknown field is refused
  // loudly by the parser on the other side of this contract.
  listingJs.includes('"purchase_in_flight",')
    && listingJs.includes("purchaseInFlight: value.purchase_in_flight,")
    && js.includes('data-action="resume-buy"')
    && js.includes("listing.purchaseInFlight")
    && js.includes("A purchase of this is already under way.")
    && listingTests.includes("a purchase already under way survives the page that started it"),
  "Marketplace must show a purchase that is still under way after the page that started it has gone.",
);
assert(
  // A purchase is a sequence of waits. The app reads which one it is in from
  // typed data and keeps asking, instead of posting once and reporting a
  // sentence it filtered away.
  js.includes("buyOutcomeFromAnswer(error.answer)")
    && js.includes("const BUY_POLL_MS = 4000;")
    && js.includes('outcome.kind === "declined"')
    && js.includes('target: "wallet"')
    && js.includes("function buyStateLabel(buyState) {")
    && js.includes("function buyStateNote(buyState) {")
    && js.includes("failure.answer = answer && typeof answer === \"object\" ? answer : {};")
    && !js.includes("const pendingMediaBuys = new Set();")
    && listingJs.includes("export function buyOutcomeFromAnswer(answer) {")
    && listingJs.includes('export const BUY_PROGRESS_SCHEMA_V1 = "elastos.protected-content.buy-progress/v1";')
    && listingTests.includes("a purchase waiting on the person is told apart from one waiting on the network")
    && listingTests.includes("a declined purchase stops, and asking again is the person's choice")
    && listingTests.includes("an answer that carries no progress is a failure, not a wait"),
  "Marketplace must drive a purchase from the typed stage Runtime reports, and stop when the person declined.",
);
assert(
  js.includes('} from "./src/listing.js";')
    && js.includes("uint256Decimal(listing.quantity)")
    && js.includes("uint256Decimal(listing.price)")
    && js.includes("`quantity ${uint256Decimal(listing.quantity)}`")
    // A price is searched as it is shown as well as in full. Both come from
    // `formatMoney`, which reads the uint256 through `uint256Decimal` and
    // scales it by moving digits -- no step of a price is a JavaScript
    // number, which is the rule this line exists to hold.
    && js.includes("const money = formatMoney(listing);")
    && js.includes("`price ${money.value} ${money.title}`")
    && js.includes("const full = uint256Decimal(listing.price);")
    && js.includes("function shiftDecimal(digits, decimals) {")
    && !js.includes("Number(listing.price)")
    && !js.includes("parseFloat")
    && js.includes('postObjectProvider("buy", { mint_id: mintId })')
    && js.includes("state.mediaRejected")
    && !js.includes("function parseRuntimeCustodyListing(")
    && !js.includes("function assertExactKeys("),
  "Marketplace must read the listing contract from its module, keep one copy of it, and say when a row was refused.",
);
assert(
  !js.includes("/api/viewers/")
    && !js.includes("publisher_principal_id")
    && !js.includes("window.open")
    && !js.includes("target=_blank"),
  "Marketplace must keep protected media actions on the typed Runtime path only.",
);
assert(
  js.includes("function isValidCapsuleIconVariant(capsuleName, entry)")
    && js.includes("CAPSULE_ICON_ROUTE")
    && js.includes('route.startsWith(`/apps/${capsuleName}/`)')
    && !js.includes("FIRST_PARTY_ICON_IDS")
    && !js.includes("OWN_ICON_CAPSULES")
    && !js.includes("resolveFirstPartyIconId")
    && !js.includes('id.includes("wallet")')
    && !js.includes('`/apps/${encodeURIComponent(name)}/icons/icon-128.png`'),
  "Marketplace must use only strict declared capsule icon routes and one generic fallback.",
);
assert(
  !html.includes("onerror=")
    && !js.includes("onerror=")
    && js.includes("function bindRasterIconFallbacks(root) {")
    && js.includes('image.addEventListener("error", () => {'),
  "Marketplace must bind raster icon fallback in JavaScript, not with inline event attributes.",
);
assert(
  js.includes('if (!app.iconRoute) {')
    && js.includes("app-icon-glyph")
    && js.includes("No executable actions declared")
    && !js.includes("Install pending")
    && !html.includes("install-modal"),
  "Marketplace must show a generic glyph fallback and must not offer fake install actions.",
);
assert(
  !js.includes("localStorage")
    && !js.includes("sessionStorage")
    && !js.includes("navigator.clipboard")
    && !js.includes("indexedDB")
    && !js.includes("carrier")
    && js.includes("\\b(schema|projection|provider|adapter|capability|affordance|runtime|runtime-owned|launch token|hostcall|request failed|failed to fetch|unauthorized|forbidden|[45]\\d\\d)\\b"),
  "Marketplace must keep browser authority local and redact internal Runtime errors.",
);

// An item Base has not finalized waits with its controls disabled. Its
// control carries no action at all, and its timers belong to one watch that
// keeps them only for items on screen.
assert(
  js.includes('from "./src/market-finality.js";')
    && js.includes('finalityWatch.show(nodes("[data-finality-key]").map((node) => node.dataset.finalityKey));')
    && js.includes("finalityWatch.pause();")
    && js.includes("finalityWatch.resume();")
    && cardJs.includes('disabled aria-disabled="true" data-finality-key=')
    && !/data-finality-key=[^>]*data-action=/.test(js + cardJs)
    && marketFinalityJs.includes('export const PENDING_FINALITY_CODE = "pending_finality";')
    && marketFinalityJs.includes("export function createFinalityWatch(")
    && !/setInterval/.test(marketFinalityJs),
  "Marketplace must keep Buy and Open disabled while Base finalizes an item, with bounded re-checks only for shown items.",
);

// An Explore item this Home holds no copy of asks the chain, lazily and only
// while shown, whether this person has access (minted, bought anywhere, or a
// subscription): access is Open, never Buy; no answer yet is a neutral
// control, never Buy; another Home's custody is neither. Card and sheet read
// one answer, and every market read shares the same two slots.
const cardAccessTests = readFileSync(resolve("capsules/marketplace/browser/src/market-card-access.test.mjs"), "utf8");
const marketAccessJs = readFileSync(resolve("capsules/marketplace/browser/src/market-access.js"), "utf8");
const marketAccessTests = readFileSync(resolve("capsules/marketplace/browser/src/market-access.test.mjs"), "utf8");
assert(
  js.includes('import { createAccessWatch, createReadSlots, listingReadOutcome } from "./src/market-access.js";')
    && js.includes("const marketReadSlots = createReadSlots(FINALITY_CHECK_CONCURRENCY);")
    && js.includes("accessViewport.observe(node);")
    && js.includes("accessWatch.show([...accessOnScreen]);")
    && js.includes("accessWatch.show(accessNodes.map((node) => node.dataset.accessKey));")
    && js.includes("accessWatch.note(key, listing);")
    && js.includes("return catalogCardControl(listing, {")
    && cardJs.includes('case "unknown":\n      // The chain could not say')
    && cardJs.includes('data-action="view-listing"')
    && cardJs.includes('disabled aria-disabled="true" aria-busy="true" ${watch}>Checking')
    && cardJs.includes('const watch = `data-access-key=')
    && cardAccessTests.includes("settled cards are re-read and repainted when the account switches")
    && !/data-access-key=[^>]*data-action=/.test(js + cardJs)
    && cardJs.includes('data-action="open-market-item"')
    && cardTests.includes("no answer yet is a disabled Checking… that names the card for the watch -- never Buy")
    && cardTests.includes("a settled unknown is an enabled View that opens the sheet, never Buy")
    && js.includes("downloadMarketCopy(item, { open: true });")
    && marketAccessJs.includes("export function createAccessWatch(")
    && marketAccessJs.includes("export function createReadSlots(limit) {")
    && marketAccessTests.includes("at most two reads run at once, shared with the finality watch")
    && marketAccessTests.includes("another wallet account invalidates that chain's answers, and the cards are read again")
    && marketAccessTests.includes("two chains keep their own accounts: answers from one never evict the other's")
    && marketAccessTests.includes("a failed read is retried with backoff, then settles as unavailable -- never endlessly"),
  "Marketplace must offer Open for an item the chain grants, never Buy before the answer, and bound its reads.",
);

// One function reads every listing answer into a card state. A listing no
// reachable Home serves, or an item the chain does not name, is a final
// Unavailable with nothing to press; View opens the sheet from the listing
// its card was read from, without a second read; Checking… is shown only
// while a read is due.
assert(
  marketAccessJs.includes("export function listingReadOutcome(")
    && js.includes("return listingReadOutcome({ code: error && error.code });")
    && js.includes('if (action === "view-listing") {')
    && js.includes("const listing = accessWatch.listing(")
    && cardJs.includes('case "unavailable":')
    && !/default:\s*\/\/ Not answered yet/.test(cardJs)
    && cardTests.includes("an unavailable card says Unavailable, disabled, with nothing to press -- never View or Checking…")
    && marketAccessTests.includes("a typed unavailable is final: never read again, after its TTL or back in sight")
    && marketAccessTests.includes("View opens from the listing the card was read from, with no second read")
    && marketAccessTests.includes("a hidden-then-visible card leaves checking, and a retry due while hidden runs once back"),
  "Marketplace cards must settle as Unavailable for a final listing answer and open View without a second read.",
);

// An item whose pool this Home cannot reach is refused before payment, and
// every surface says to add the pool in Custody instead of offering Buy,
// Open or Download.
assert(
  marketListingJs.includes('const TOP_OPTIONAL_KEYS = ["offers_truncated", "access_unknown", "custody_route", "access_subject"];')
    && marketListingJs.includes('export const MARKET_CUSTODY_ROUTES = ["pool", "unresolved"];')
    && marketListingJs.includes('"This item’s pool cannot be reached from this Home yet. Add the pool in Custody."')
    && js.includes('const elsewhere = listing.custodyRoute === "unresolved";')
    && js.includes("notes.push(CUSTODY_ELSEWHERE_COPY);")
    && js.includes("owned: Boolean(ownership) || elsewhere,")
    && cardJs.includes('title="${escapeAttr(CUSTODY_ELSEWHERE_COPY)}">${CUSTODY_UNRESOLVED_LABEL}</span>')
    && cardJs.includes('if (ctx.access === "elsewhere") {\n      return `${elsewhere}${details}`;')
    && marketListingJs.includes('if (adoption === "custody_elsewhere") {\n    return CUSTODY_ELSEWHERE_PURCHASE_COPY;')
    && js.includes('showToast(buyRefusalCopy({ code: outcome.kind }), true);')
    && js.includes('showToast(buyRefusalCopy(error.answer) || publicError(error.message, "The purchase did not finish."), true);'),
  "Marketplace must say an item whose pool this Home cannot reach waits for the pool to be added in Custody.",
);

// A download takes minutes. Its control says so -- disabled, "Downloading…",
// with a status line -- for as long as it runs, across closing and reopening
// the sheet, and it ends on "Saved to your Library" or the honest refusal.
assert(
  marketListingJs.includes("export function downloadControl(downloading) {")
    && marketListingTests.includes("a download in flight is a disabled Downloading… control with a status line")
    && js.includes("const downloadState = downloadControl(download && pendingMarketDownloads.has(catalogLedgerKey(listing.item)));")
    && js.includes("showToast(DOWNLOAD_SAVED_COPY, false);")
    && !js.includes("Downloaded. The copy is in your Library."),
  "Marketplace must show a download in progress until it finishes, wherever the item is shown.",
);

console.log("marketplace-product-behavior-smoke: OK");

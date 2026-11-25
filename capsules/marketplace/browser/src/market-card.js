// The one control an Explore card offers for a catalog item, as markup.
//
// Kept apart from the page so every state can be rendered and checked on its
// own: what the card shows is decided here from what the page already knows,
// and nothing here reads or asks anything.

import {
  CUSTODY_ELSEWHERE_COPY,
  CUSTODY_UNRESOLVED_LABEL,
  NO_REACHABLE_HOLDER_COPY,
  NO_WALLET_ACCOUNT_LABEL,
  downloadControl,
} from "./market-listing.js";

// The format badge: what this item IS, in the shortest true word.
//
// Taken from the MIME's subtype rather than from a table of names, so an
// item of a kind nobody anticipated still gets a badge instead of nothing.
// Deliberately no resolution beside it: the design shows "MP4 · 720p", and
// this Home is told the codec but never the frame size, so it says the part
// it knows rather than a number it guessed.
export function formatBadge(listing) {
  const mime = String(listing.mimeType || "").toLowerCase();
  const subtype = mime.slice(mime.indexOf("/") + 1);
  // A catalog item is told only its kind (`video/*`): the badge names the
  // kind, not the wildcard.
  if (subtype === "*") {
    const kind = mime.slice(0, mime.indexOf("/"));
    return ["video", "image", "audio"].includes(kind) ? kind.toUpperCase() : "FILE";
  }
  const named = {
    "quicktime": "MOV",
    "x-matroska": "MKV",
    "mpeg": mime.startsWith("audio/") ? "MP3" : "MPEG",
    "svg+xml": "SVG",
    "epub+zip": "EPUB",
    "vnd.openxmlformats-officedocument.wordprocessingml.document": "DOCX",
    "plain": "TXT",
    "jpeg": "JPG",
  }[subtype];
  const badge = named || subtype.replace(/^x-/, "").toUpperCase();
  return badge.length > 0 && badge.length <= 6 ? badge : "FILE";
}

/**
 * `listing` is the catalog item (`ledger`, `tokenId`, `accessState`). `ctx`:
 * - `key`: its `<ledger>|<token_id>` key;
 * - `finalityPending`: Base has not finalized it yet;
 * - `access`: the access watch's state for it (`checking` until answered);
 * - `readability`: what a listing read learned of its document;
 * - `hasItem`: a listing read named the whole item, so it can be fetched;
 * - `downloading`: a copy of it is being built now;
 * - `listingLoading`: its listing is being read for a sheet;
 * - `mint`: this Home's own listing of it, when it holds one;
 * - `noHolder`: the access answer said no reachable Home serves its
 *   document, so opening it from its pool cannot succeed now;
 * - `size`: the button size class.
 */
export function catalogCardControl(listing, ctx) {
  const size = ctx.size || "";
  const ledger = escapeAttr(listing.ledger);
  const token = escapeAttr(listing.tokenId);
  const item = `data-ledger="${ledger}" data-token="${token}"`;
  // Every card the chain may still change an answer for names itself to the
  // access watch, so a settled card is re-read on its TTL and after an
  // account switch, not only while it says "Checking…".
  const watch = `data-access-key="${escapeAttr(ctx.key)}"`;
  const mint = ctx.mint && listing.accessState === "available"
    ? `data-mint="${escapeAttr(ctx.mint)}"`
    : "";
  if (ctx.finalityPending) {
    // Disabled and with no action until a listing read says the item is
    // final; the card's note says why. The label is what this account's
    // access says (D5, STAB-25): Open for an account the chain grants the
    // item, Buy only when its access is known to be none, Add a Wallet
    // account when there is no account to ask about, and a neutral
    // "Checking…" while nothing is known yet.
    const finality = `data-finality-key="${escapeAttr(ctx.key)}"`;
    const waiting = (label, style) => `<button class="btn ${style} ${size}" type="button" disabled aria-disabled="true" ${finality}>${label}</button>`;
    const held = listing.accessState === "purchased" || listing.accessState === "creator";
    switch (held ? "held" : ctx.access) {
      case "held":
        return waiting("Open", "btn-ghost");
      case "available":
        return waiting("Buy", "btn-primary");
      case "no_account":
        return `<button class="btn btn-ghost ${size}" type="button" data-action="open-wallet" ${finality}>${NO_WALLET_ACCOUNT_LABEL}</button>`;
      default:
        return waiting("Checking…", "btn-ghost");
    }
  }
  // This Home cannot reach the item's pool: nothing here can be bought,
  // downloaded or opened, held or not, until the pool is added in Custody.
  const elsewhere = `<span class="store-row-state" ${watch} title="${escapeAttr(CUSTODY_ELSEWHERE_COPY)}">${CUSTODY_UNRESOLVED_LABEL}</span>`;
  if (listing.accessState === "purchased" || listing.accessState === "creator") {
    const purchased = listing.accessState === "purchased";
    const details = purchased ? detailsButton(item, size, ctx) : "";
    if (ctx.access === "elsewhere") {
      return `${elsewhere}${details}`;
    }
    if (ctx.readability === "foreign") {
      return `<span class="store-row-state" ${watch}>Opens on ela.city</span>${details}`;
    }
    if (ctx.readability === "verified" || ctx.readability === "unverified") {
      // Bought on the market, and not yet adopted onto this Home's shelf:
      // Download copy reruns adoption and never pays (R45).
      if (listing.accessState === "creator") {
        return `<span class="store-row-state" ${watch}>You listed this</span>`;
      }
      // One node names the card to the watch: Download copy, else Details.
      return ctx.hasItem
        ? `${downloadButton(item, size, ctx, watch)}${details}`
        : detailsButton(item, size, ctx, watch);
    }
    return `<button class="btn btn-ghost ${size}" type="button" data-action="open-listing" ${item} ${watch}>Open</button>${details}`;
  }
  // Nothing held here: the chain's own answer decides.
  switch (ctx.access) {
    case "elsewhere":
      return elsewhere;
    case "held": {
      if (mint) {
        return `<button class="btn btn-primary ${size}" type="button" data-action="open-media" ${mint} ${watch}>Open</button>`;
      }
      if (ctx.noHolder) {
        // Granted, but no reachable Home serves it, and it has no copy here:
        // nothing to press. The card keeps its watch key, so the access read
        // on its TTL brings Open back once a holder serves it again.
        return `<button class="btn btn-ghost ${size}" type="button" disabled aria-disabled="true" title="${escapeAttr(NO_REACHABLE_HOLDER_COPY)}" ${watch}>Unavailable</button>`;
      }
      if (ctx.readability === "foreign") {
        return `<span class="store-row-state" ${watch}>Opens on ela.city</span>`;
      }
      const busy = ctx.downloading ? ' disabled aria-busy="true" aria-disabled="true"' : "";
      return `<button class="btn btn-primary ${size}" type="button" data-action="open-market-item" ${item} ${watch}${busy}>${ctx.downloading ? "Opening…" : "Open"}</button>`;
    }
    case "available": {
      // A local copy uses its mint; both paths require explicit no-access.
      if (mint) {
        return `<button class="btn btn-primary ${size}" type="button" data-action="buy-media" ${mint} ${watch}>Buy</button>`;
      }
      // A known account with no access: Buy opens the sheet.
      const loading = ctx.listingLoading ? ' aria-busy="true" aria-disabled="true"' : "";
      return `<button class="btn btn-primary ${size}" type="button" data-action="buy-listing" ${item} ${watch}${loading}>Buy</button>`;
    }
    case "no_account":
      return walletAccountButton(size, watch);
    case "unknown":
      // The chain could not say, and asking again will not soon change
      // that: the sheet shows what is known, and the card never offers Buy.
      return `<button class="btn btn-ghost ${size}" type="button" data-action="view-listing" ${item} ${watch}>View</button>`;
    case "checking":
    case "pending":
      // A read is running, or the finality watch holds the item.
      return checkingButton(size, watch);
    case "retrying":
      return tryAgainButton(size, watch);
    case "unavailable":
    default:
      // No reachable Home serves it, or the chain names no such item here:
      // final, with nothing to press. A state the card does not know is
      // offered nothing either.
      return `<button class="btn btn-ghost ${size}" type="button" disabled aria-disabled="true" ${watch}>Unavailable</button>`;
  }
}

// "Checking…" only while a read is running, or the finality watch holds the
// item (D5, STAB-26).
function checkingButton(size, watch) {
  return `<button class="btn btn-ghost ${size}" type="button" disabled aria-disabled="true" aria-busy="true" ${watch}>Checking…</button>`;
}

// A read that failed is settled, not "Checking…": the person may ask again
// now, before the watch's own backoff does (D5, STAB-26). The watch key on
// the button names the card to `retry-access`.
function tryAgainButton(size, watch) {
  return `<button class="btn btn-ghost ${size}" type="button" data-action="retry-access" ${watch}>Try again</button>`;
}

// No Wallet account to buy with, or to ask the chain about: the one thing
// to do is add one, as Creator offers (D5, STAB-24).
function walletAccountButton(size, watch) {
  return `<button class="btn btn-ghost ${size}" type="button" data-action="open-wallet" ${watch}>${NO_WALLET_ACCOUNT_LABEL}</button>`;
}

function detailsButton(item, size, ctx, watch = "") {
  const busy = ctx.listingLoading ? ' aria-busy="true" aria-disabled="true"' : "";
  return `<button class="btn btn-ghost ${size}" type="button" data-action="item-details" ${item}${watch ? ` ${watch}` : ""}${busy}>Details</button>`;
}

function downloadButton(item, size, ctx, watch) {
  const control = downloadControl(ctx.downloading);
  const busy = control.busy ? ' disabled aria-busy="true" aria-disabled="true"' : "";
  return `<button class="btn btn-ghost ${size}" type="button" data-action="download-market-copy" ${item} ${watch}${busy}>${escapeHtml(control.label)}</button>`;
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function escapeAttr(value) {
  return escapeHtml(value);
}

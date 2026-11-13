// The one control an Explore card offers for a catalog item, as markup.
//
// Kept apart from the page so every state can be rendered and checked on its
// own: what the card shows is decided here from what the page already knows,
// and nothing here reads or asks anything.

import { CUSTODY_ELSEWHERE_COPY, CUSTODY_UNRESOLVED_LABEL, downloadControl } from "./market-listing.js";

/**
 * `listing` is the catalog item (`ledger`, `tokenId`, `accessState`). `ctx`:
 * - `key`: its `<ledger>|<token_id>` key;
 * - `finalityPending`: Base has not finalized it yet;
 * - `access`: the access watch's state for it (`checking` until answered);
 * - `readability`: what a listing read learned of its document;
 * - `hasItem`: a listing read named the whole item, so it can be fetched;
 * - `downloading`: a copy of it is being built now;
 * - `listingLoading`: its listing is being read for a sheet;
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
  if (ctx.finalityPending) {
    // Disabled and with no action; the card's note says why.
    const buying = listing.accessState === "available";
    return `<button class="btn ${buying ? "btn-primary" : "btn-ghost"} ${size}" type="button" disabled aria-disabled="true" data-finality-key="${escapeAttr(ctx.key)}">${buying ? "Buy" : "Open"}</button>`;
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
      if (ctx.readability === "foreign") {
        return `<span class="store-row-state" ${watch}>Opens on ela.city</span>`;
      }
      const busy = ctx.downloading ? ' disabled aria-busy="true" aria-disabled="true"' : "";
      return `<button class="btn btn-primary ${size}" type="button" data-action="open-market-item" ${item} ${watch}${busy}>${ctx.downloading ? "Opening…" : "Open"}</button>`;
    }
    case "available":
    case "no_account": {
      // No account to ask about is settled too: Buy opens the sheet, which
      // leads to setting one up.
      const loading = ctx.listingLoading ? ' aria-busy="true" aria-disabled="true"' : "";
      return `<button class="btn btn-primary ${size}" type="button" data-action="buy-listing" ${item} ${watch}${loading}>Buy</button>`;
    }
    case "unknown":
      // The chain could not say, and asking again will not soon change
      // that: the sheet shows what is known, and the card never offers Buy.
      return `<button class="btn btn-ghost ${size}" type="button" data-action="view-listing" ${item} ${watch}>View</button>`;
    case "checking":
    case "retrying":
    case "pending":
      // Not answered yet, or a read that failed and is due again.
      return `<button class="btn btn-ghost ${size}" type="button" disabled aria-disabled="true" aria-busy="true" ${watch}>Checking…</button>`;
    case "unavailable":
    default:
      // No reachable Home serves it, or the chain names no such item here:
      // final, with nothing to press. A state the card does not know is
      // offered nothing either.
      return `<button class="btn btn-ghost ${size}" type="button" disabled aria-disabled="true" ${watch}>Unavailable</button>`;
  }
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

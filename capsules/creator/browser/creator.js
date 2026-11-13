// Creator — uploads a file through the Library transport, protects it, and
// lists copies at a price, in one flow.
//
// The upload transport in `providerApi`/`uploadObject*` below is copied
// verbatim from capsules/library/browser/src/api.js:26-103 (minus the
// DELETE-based cancel-on-error step: that route stays Library-only),
// and `decimalIntegerToHexQuantity` from capsules/library/browser/src/model.js:
// 177-190. Capsules are independently sandboxed with no shared module graph,
// so this is a deliberate copy, not an import.
//
// This is a faithful structural port of the dkms Creator UI (title,
// description, cover thumbnail, access-method grid, category, resale
// royalty, royalty split, AI-licensing/adult/legal checkboxes, free-preview
// settings, and the encode/publish tech-progress panel). dkms's separate
// enable-trading step is deliberately NOT ported into the MINT flow: the
// contract fulfils the mint without an ERC-1155 operator approval, so a mint
// raises exactly one wallet effect and there is no second step to offer while
// listing. An operator approval is still how secondary trading works -- an
// owner selling some of the Access Tokens or Royalty Shares they hold must
// authorize the operator that moves them -- so a resale surface will need its
// own equivalent of this step. It just does not belong here.
//
// The publish request carries `protection.listing` with the title,
// description, cover, category and the adult/licensing/legal flags, which
// become the Elacity metadata folder the mint's token URI resolves to. It
// also carries the terms the chain call is built from: the access method, the
// resale cut when that method offers resale, the royalty split, and the
// decimal scale the price was expressed in.
//
// The royalty split is sent only as the creator's own rows and only when they
// name real addresses: see collectRoyaltyUnits. Free-preview is rendered
// without being sent and keeps a hint saying so.
//
// The channel and the currency are both chosen, and both come from the host:
// the channels this creator may publish into, and the tokens a sale may be
// priced in. Neither is invented here, because a form offering a channel the
// mint cannot use, or a six-decimal token to an eighteen-decimal mint, makes a
// promise the chain then breaks -- the second of those listed an asset a
// million times under its intended price. The price is sent as the amount
// typed, and the host scales it by the chosen token's own decimals, so there
// is no scale for this page to declare and none to get wrong.
//
// The one dkms surface omitted outright is the wallet picker: that route does
// not exist here, and the host resolves the publishing account itself.

// How a pending publish is resumed. The person budget is the generous one:
// approving in a connector means leaving this page, finding the wallet and
// coming back. The chain budget is short because nothing is being asked of
// anyone — if Base has not produced evidence in two minutes, something is
// wrong and saying so beats spinning.
const PENDING_POLL_INTERVAL_MS = 3000;
const PENDING_PERSON_BUDGET_MS = 5 * 60 * 1000;
const PENDING_CHAIN_BUDGET_MS = 2 * 60 * 1000;

const CHUNKED_UPLOAD_THRESHOLD_BYTES = 512 * 1024;
const CHUNKED_UPLOAD_BYTES = 512 * 1024;
const CHUNKED_UPLOAD_TRANSPORT = "http-chunk-session";
// This Home's public metadata sharing status (read-only; consent and Stop
// live in Inbox).
const PUBLIC_IPFS_API = "/api/apps/creator/public-ipfs";

const MAX_UINT256 = (1n << 256n) - 1n;
const POSITIVE_DECIMAL_INTEGER_RE = /^[0-9]+$/;
const CONTROL_CHAR_RE = /[\x00-\x1f\x7f]/;

// Extension -> MIME for types browsers report unreliably (often "" or
// octet-stream). Ported from dkms's EXT_MIME table.
const EXT_MIME = {
  epub: "application/epub+zip",
  cbz: "application/vnd.comicbook+zip",
  pdf: "application/pdf",
  svg: "image/svg+xml",
  md: "text/markdown",
  markdown: "text/markdown",
  txt: "text/plain",
  json: "application/json",
  glb: "model/gltf-binary",
  gltf: "model/gltf+json",
  stl: "model/stl",
  obj: "model/obj",
  ply: "model/mesh",
};

// The extensions Runtime can protect. Runtime types a file by its name alone
// (`mime_for_name` in elastos/crates/elastos-server/src/library.rs) and refuses
// to publish anything that table leaves as `application/octet-stream` (see
// RUNTIME_CUSTODY_PUBLISH_UNSUPPORTED_TYPE_MESSAGE there). Library applies the
// same one-value rule to an object's server-reported type; Creator has no
// object yet when a file is picked, so it carries a copy of the table's keys.
// creator.test.mjs reads the Rust table and fails if the two differ.
export const RUNTIME_PROTECTABLE_EXTENSIONS = new Set([
  "md", "txt", "html", "json", "png", "jpg", "jpeg", "gif", "pdf", "tar", "zip",
  "mp4", "m4v", "mov", "3gp", "3g2", "mkv", "mk3d", "webm", "ogv", "asf", "avi",
  "flv", "f4v", "mpg", "mpeg", "vob", "ts", "m2t", "m2ts", "mts", "wmv",
  "mp3", "mp2", "m2a", "mpa", "m4a", "m4b", "aac", "wav", "flac", "ogg", "oga",
  "opus", "mka", "wma",
]);

const UNSUPPORTED_TYPE_MESSAGE =
  "This file type cannot be protected yet. Use an image (PNG, JPG, GIF), a PDF, or a video.";

// The real default primary-sale split applied when an asset is listed: the
// creator receives 950 of 1000 royalty units and the protocol owner 50. The
// rows show both so the running total means something; only the creator's own
// rows are ever sent, and only when they name real addresses.
const DEFAULT_CREATOR_ROYALTY_PERCENT = 95;
const DEFAULT_PROTOCOL_ROYALTY_PERCENT = 5;
const ROYALTY_TOTAL_TARGET_PERCENT = 100;

// The creator's whole share in ERC-1155 ROYALTY_SHARE units: 950 of the 1000
// that exist per asset, the protocol's 50 being minted by the contracts. One
// unit is 0.1% of the sale.
const CREATOR_ROYALTY_UNITS = 950;
const EVM_ADDRESS_RE = /^0x[0-9a-f]{40}$/;

// Decimal places for the currencies this page can name on its own, used by the
// symbol-taking scaler and its tests. The form does not choose from this: the
// host offers the tokens a mint may settle in, each stating its own decimals,
// and those are what a price is scaled by.
const CURRENCY_DECIMALS = {
  ELA: 18,
  ETH: 18,
  USDC: 6,
};

// The pay token every mint from this Runtime settles in: the chain's own coin,
// which is eighteen decimals. The price crosses to the host as an integer of
// that token's smallest unit, so this is also the scale the host is told the
// price was expressed in -- and it refuses a mint whose scale does not match
// the token it will actually settle in.
//
// Offering a six-decimal token here while the mint settles in an
// eighteen-decimal one produced a listing a million times under its intended
// price, so the choice is not offered until the pay token itself is.
const NATIVE_PRICE_DECIMALS = 18;


// The channel option that reveals a typed address. A directory can only offer
// what it knows, and the chain is what decides: a creator who knows a channel
// the list has not surfaced should not be stopped by the list.
const MANUAL_CHANNEL_VALUE = "__manual__";

// ---------------------------------------------------------------------------
// Pure helpers — exported and covered by creator.test.mjs with `node --test`.
// ---------------------------------------------------------------------------

/**
 * Build the Library object URI a chosen file uploads to. Rejects file names
 * that could escape the Creator folder: this is a security boundary, not a
 * display nicety.
 */
export function targetUriFor(rootUri, fileName) {
  const name = String(fileName ?? "");
  if (!name || name === "." || name === "..") {
    throw new Error("Choose a file with a name.");
  }
  if (name.includes("/") || name.includes("..")) {
    throw new Error("File name must not contain a path separator.");
  }
  if (CONTROL_CHAR_RE.test(name)) {
    throw new Error("File name must not contain control characters.");
  }
  const root = String(rootUri || "").replace(/\/+$/, "");
  return `${root}/Creator/${name}`;
}

/**
 * "media" for video/audio (plays in Elacity Player once protected); "object"
 * for everything else (opens in Elacity Reader once protected).
 */
export function classifyProtection(mime) {
  const value = String(mime || "");
  if (value.startsWith("video/") || value.startsWith("audio/")) {
    return "media";
  }
  return "object";
}

/** Verbatim copy of Library's model.js decimalIntegerToHexQuantity. */
export function decimalIntegerToHexQuantity(value) {
  const text = String(value ?? "").trim();
  if (!POSITIVE_DECIMAL_INTEGER_RE.test(text)) {
    throw new Error("Enter a positive whole number.");
  }
  const parsed = BigInt(text);
  if (parsed <= 0n || parsed > MAX_UINT256) {
    throw new Error("Enter a whole number from 1 to 2^256-1.");
  }
  return `0x${parsed.toString(16)}`;
}

/**
 * Reads the server's "this request settled nothing" marker off a publish
 * answer's `content_security`.
 *
 * The server sets `settled_before_this_request` only when the mint was already
 * terminal on arrival: no effect raised, no transaction sent, just the listing
 * re-published from the existing record. Returns null for a fresh mint — and
 * for every server that predates the marker, which is why absence has to mean
 * "fresh" rather than "unknown".
 */
export function settledFrom(contentSecurity) {
  if (!contentSecurity || contentSecurity.settled_before_this_request !== true) {
    return null;
  }
  return {
    before: true,
    at: contentSecurity.settled_at,
    transactionHash: contentSecurity.transaction_hash || "",
    sellerAddress: contentSecurity.settled_seller_address || "",
  };
}

/** Describes how a file of this size will upload, for the status copy. */
export function uploadPlan(size) {
  const bytes = Number(size) || 0;
  if (bytes <= CHUNKED_UPLOAD_THRESHOLD_BYTES) {
    return { mode: "single" };
  }
  return { mode: "chunked" };
}

/** Renders a byte count as a short human-readable size, e.g. "512.0 KB". */
export function humanSize(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) {
    return `${value} B`;
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Resolve the canonical MIME type for a chosen file. Trusts the extension
 * map for types browsers report unreliably (often "" or octet-stream);
 * otherwise falls back to the browser-reported type, then octet-stream.
 * Ported from dkms's resolveMime/EXT_MIME.
 */
export function resolveMime(file) {
  const name = String(file?.name || "");
  const dot = name.lastIndexOf(".");
  const ext = dot >= 0 ? name.slice(dot + 1).toLowerCase() : "";
  if (EXT_MIME[ext]) {
    return EXT_MIME[ext];
  }
  return file?.type || "application/octet-stream";
}

/**
 * The refusal to show when Runtime cannot protect a file with this name, or ""
 * when it can. Decided at pick time so an unsupported file never reaches the
 * upload or the mint. Mirrors `mime_for_name`, two-part suffix included.
 */
export function fileTypeRefusal(fileName) {
  const lower = String(fileName || "").toLowerCase();
  if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) {
    return "";
  }
  const dot = lower.lastIndexOf(".");
  const ext = dot >= 0 ? lower.slice(dot + 1) : "";
  return RUNTIME_PROTECTABLE_EXTENSIONS.has(ext) ? "" : UNSUPPORTED_TYPE_MESSAGE;
}

/**
 * Sums royalty-row percentages and checks whether they total exactly 100%
 * (the default rows already do: 95% creator + 5% protocol). `overLimit`
 * distinguishes "still under 100%" from "already over" so the UI can block
 * an edit that would push the total past 100 with a clear reason, rather
 * than silently clamping it. Cosmetic today: no field in this runtime's
 * publish request carries a royalty split, so this never leaves the browser.
 */
export function summarizeRoyaltyRows(rows) {
  const sum = (rows || []).reduce((total, row) => total + (Number(row?.royalty) || 0), 0);
  const ok = Math.abs(sum - ROYALTY_TOTAL_TARGET_PERCENT) < 0.01;
  const overLimit = sum > ROYALTY_TOTAL_TARGET_PERCENT + 0.01;
  return { sum, target: ROYALTY_TOTAL_TARGET_PERCENT, ok, overLimit };
}

/**
 * Scales a human-entered decimal amount (e.g. "0.001") into the integer
 * base-units string for the given currency, using exact string/BigInt
 * arithmetic — never Number/parseFloat, which loses precision well before
 * 18 decimal places. Splits on ".", pads (or rejects) the fractional part
 * against the currency's decimal count, and returns a plain digit string
 * ready for decimalIntegerToHexQuantity. Throws with a clear message on
 * invalid input, zero, too many fractional digits, or an unknown currency.
 */
export function scalePriceToBaseUnits(amount, currency) {
  const decimals = CURRENCY_DECIMALS[currency];
  if (decimals === undefined) {
    throw new Error(`Unknown currency: ${currency}`);
  }
  return scaleAmountToBaseUnits(amount, decimals, currency);
}

/**
 * The same scaling, told the decimals rather than asked to look them up.
 *
 * The host states each offered token's decimals, because that is what gives a
 * price its meaning and what the mint is checked against. Taking the number
 * directly means a token this page has never heard of still prices correctly,
 * where a symbol lookup would refuse it or -- worse -- fall back to a
 * different scale.
 */
export function scaleAmountToBaseUnits(amount, decimals, label = "This token") {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) {
    throw new Error("Unknown price scale.");
  }
  const currency = label;
  const text = String(amount ?? "").trim();
  if (!/^[0-9]+(\.[0-9]+)?$/.test(text)) {
    throw new Error("Enter a positive amount, e.g. 0.001.");
  }
  const [wholePart, fractionalPart = ""] = text.split(".");
  if (fractionalPart.length > decimals) {
    throw new Error(`${currency} supports at most ${decimals} decimal place${decimals === 1 ? "" : "s"}.`);
  }
  const combinedDigits = `${wholePart}${fractionalPart.padEnd(decimals, "0")}`;
  const scaled = combinedDigits.replace(/^0+/, "") || "0";
  if (scaled === "0") {
    throw new Error("Enter an amount greater than zero.");
  }
  return scaled;
}

/**
 * Builds the exact request body `publishOnce` sends to
 * `/api/provider/object/publish`. This is the one place the publish payload
 * is assembled, kept deliberately narrow and pure so a test can assert its
 * key set never grows: today's server (`LibraryPublishProtectionRequest::
 * RuntimeCustody`) accepts only `copies` and `price`, and rejects unknown
 * fields outright — so if a future edit reads title/description/thumbnail/
 * category/reseller-cut/royalties/checkbox state into this object, publishing
 * breaks immediately and loudly instead of silently leaking form state.
 */
export function buildPublishBody({
  uri,
  ifRevision,
  copies,
  price,
  channel,
  payToken,
  listing,
  newAttempt,
  poolDid,
}) {
  const protection = {
    mode: "runtime_custody",
    copies,
    // The amount a buyer pays for one copy, as the creator typed it. The host
    // scales it into the pay token's base units, because that is where the
    // token's decimals are known -- a page that scaled it first could only
    // declare which decimals it had used, and a wrong declaration priced a
    // sale a million-fold under.
    price,
    // The chain terms of the mint, beside copies and price rather than inside
    // the optional listing: a mint with no marketplace listing still has to
    // settle somewhere, in something.
    channel,
  };
  // Omitted when the creator did not choose one, which means the mint source's
  // own first offered token.
  if (payToken) {
    protection.pay_token = payToken;
  }
  // Omitted rather than sent empty: absent means "no Elacity listing folder",
  // which is a different thing from a listing whose every field is blank.
  if (listing) {
    protection.listing = listing;
  }
  // A new mint of this file, as opposed to a retry or a poll of the one in
  // flight: the host sets any unfinished attempt at it aside first, so an
  // earlier attempt never stands in the way. Sent only on a fresh protect.
  if (newAttempt) {
    protection.new_attempt = true;
  }
  // Plan B POOL-MINT: the chosen custody pool. Omitted takes this Home's
  // own pool, else the only pool it uses.
  if (poolDid) {
    protection.pool_did = poolDid;
  }
  return {
    uri,
    if_revision: ifRevision,
    protection,
  };
}

/**
 * The publish request that resumes the mint already recorded for `uri`.
 *
 * It carries no terms on purpose: a resume continues what was agreed, at the
 * terms the server recorded, and the person types nothing. The server refuses
 * a resume that names any.
 */
export function buildResumeBody({ uri, ifRevision }) {
  return {
    uri,
    if_revision: ifRevision,
    protection: { mode: "runtime_custody_resume" },
  };
}

/**
 * Maps the server's journal-derived publish progress onto this page's stage
 * list.
 *
 * The server names the phases it owns; this page's list also carries
 * "analyze", which is the client's own upload and which no server record
 * describes. Keeping the two vocabularies separate and mapping between them
 * is deliberate: the alternative is the page inventing server-side stage names
 * and drifting from the journal the moment either side changes.
 *
 * Unknown ids are ignored rather than guessed at, so a server that grows a
 * phase this page does not render degrades to showing one stage fewer instead
 * of throwing.
 */
export function stagesFromProgress(progress) {
  const stages = progress && Array.isArray(progress.stages) ? progress.stages : [];
  const byServerId = {
    escrow: "encrypt",
    publish: "publish",
    public_metadata: "public_metadata",
    listing: "assemble",
  };
  // The server's vocabulary is pending/active/done/failed; this page's is the
  // CSS class on the row. They are mapped rather than shared so that a state
  // this page cannot draw is dropped instead of being written into `className`,
  // where it would silently render as nothing at all.
  const byServerState = {
    pending: "pending",
    active: "active",
    done: "done",
    failed: "err",
  };
  const mapped = [];
  for (const stage of stages) {
    const name = byServerId[stage && stage.id];
    const state = byServerState[String((stage && stage.state) || "")];
    if (!name || !state) continue;
    mapped.push({ name, state });
  }
  return mapped;
}

/**
 * Reads the server's typed refusal of a mint already on record.
 *
 * Terms on a mint whose transaction was sent or mined, or that is listed,
 * cannot move, and such an attempt is never started over. This page reads
 * what to offer out of `can_resume` (and `can_start_over`, which the server
 * answers false for every such refusal) instead of out of the sentence.
 *
 * Returns null when the envelope carries no such refusal, including from a
 * server that predates the typed answer.
 */
export function creatorMintFrom(envelope) {
  const blocked = envelope && envelope.creator_mint;
  if (!blocked || typeof blocked !== "object") {
    return null;
  }
  return {
    state: String(blocked.state || ""),
    mintId: String(blocked.mint_id || ""),
    recordedCopies: String(blocked.recorded_copies || ""),
    recordedPrice: String(blocked.recorded_price || ""),
    canStartOver: blocked.can_start_over === true,
    canResume: blocked.can_resume === true,
    // How far the recorded attempt got, and which of its terms this attempt
    // would have changed -- so the refusal can say which, not only that.
    stage: String(blocked.stage || ""),
    differingTerms: Array.isArray(blocked.differing_terms)
      ? blocked.differing_terms.filter((term) => typeof term === "string")
      : [],
  };
}

/**
 * Reads the refusal of an earlier attempt that cannot continue as it stands:
 * the file changed, the account or deployment it started under changed, or a
 * request it sent has an unknown outcome. Each stays refused, and each is
 * answered by Start over.
 */
export function attemptConflictFrom(envelope) {
  const conflict = envelope && envelope.attempt_conflict;
  if (!conflict || typeof conflict !== "object") {
    return null;
  }
  const read = {
    reason: String(conflict.reason || ""),
    canStartOver: conflict.can_start_over === true,
  };
  // Only where the server says so: an earlier approval that cannot be
  // confirmed closed is finished by Resume.
  if (conflict.can_resume === true) read.canResume = true;
  if (typeof conflict.cause === "string" && conflict.cause) read.cause = conflict.cause;
  if (typeof conflict.connector === "string" && conflict.connector) {
    read.connector = conflict.connector;
  }
  return read;
}

/**
 * What a failed protect may offer. An earlier attempt the server kept --
 * its transaction was sent or mined, or it is listed -- is resumed, never
 * started over. Start over is offered only on a refusal the server says it
 * can set aside. Anything else (the network, the wallet's default account) is
 * not the earlier attempt's doing and offers neither.
 */
export function recoveryActionsFor(error) {
  // The metadata stage raised no approval, so the same publish is asked for
  // again.
  if (error?.publicMetadata?.retry) {
    return ["retry"];
  }
  if (error?.creatorMint) {
    return error.creatorMint.canResume ? ["resume"] : [];
  }
  const conflict = error?.attemptConflict;
  if (conflict) {
    const actions = [];
    if (conflict.canResume) actions.push("resume");
    if (conflict.canStartOver) actions.push("start_over");
    return actions;
  }
  return [];
}

/**
 * Reads the server's typed waiting state off an error envelope.
 *
 * A runtime-custody publish that has not settled Wallet/Chain approval is a
 * non-terminal waiting state, not a failure. This used to be detected by
 * testing the message against /pending/i — control flow decided by matching an
 * English word in a sentence written for a person, which no test pinned and
 * which any rewording would have broken silently.
 *
 * `awaitsPerson` is the part that matters: only an external wallet with an
 * outstanding approval needs the creator to do anything. A managed approval and
 * a chain wait both resolve on their own, and telling someone to go and approve
 * something they already approved is how the old shared message misled.
 *
 * Returns null when the envelope carries no waiting state, which includes every
 * server that predates the typed answer — so absence means "not pending"
 * rather than "unknown".
 */
export function effectPendingFrom(envelope) {
  const pending = envelope && envelope.effect_pending;
  if (!pending || typeof pending !== "object") {
    return null;
  }
  return {
    reason: String(pending.reason || ""),
    awaitsPerson: pending.awaits_person === true,
    connectorId: pending.connector_id ? String(pending.connector_id) : "",
  };
}

/**
 * Which wait a pending answer is in, and how long *that wait* has lasted.
 *
 * The budget for a wait has to be measured from the moment that wait began, not
 * from the moment the whole publish began. Getting this wrong had a precise and
 * awful consequence: a metadata pin that took longer than the approval budget
 * spent the entire budget before the wallet request even existed, so the first
 * pending answer arrived already over budget, polling never started once, and
 * the creator was told to go and approve a transaction that had in fact already
 * settled on chain.
 *
 * The two waits are different in kind — one needs the person, one needs the
 * network — so crossing from one to the other starts a fresh clock rather than
 * inheriting the time spent waiting for something else.
 */
export function pendingPhase(previous, pending, nowMs) {
  const reason = pending && pending.awaitsPerson ? "person" : "chain";
  const startedAt = previous && previous.reason === reason ? previous.startedAt : nowMs;
  return { reason, startedAt, waitedMs: Math.max(0, nowMs - startedAt) };
}

/**
 * How long this page will keep asking, for the wait it is actually in.
 */
export function pendingBudgetMs(phase) {
  return phase && phase.reason === "person"
    ? PENDING_PERSON_BUDGET_MS
    : PENDING_CHAIN_BUDGET_MS;
}

/**
 * The breakdown behind a failure, as rows rather than prose.
 *
 * What a creator needs first is one sentence they can act on; what they need
 * when that is not enough — or when they are reporting it to someone else — is
 * everything the server actually said. Those are different audiences for the
 * same failure, so the sentence stays in the status line and this goes behind a
 * disclosure.
 *
 * Every row is drawn from a typed field. Nothing here is parsed out of a
 * message, so a reworded sentence cannot change what is shown, and a field the
 * server did not send is simply absent rather than rendered empty.
 */
// What a creator does when the host had nobody to ask the channel list about.
// The host answers with a stable reason code, and this page says the one step
// that fixes it: approving the list fixes none of them, so the page offers
// Check again instead of the approval.
const CHANNEL_BLOCKER_HINTS = {
  mint_source_unavailable:
    "This Home's Base connection isn't ready. Restart Home, then choose Check again.",
  no_transaction_default_for_chain_namespace:
    "Create an EVM account in Wallet, or set one as the default, then choose Check again.",
  default_account_not_in_wallet_for_chain_namespace:
    "Your default account is no longer in Wallet. Set another EVM account as the default, then choose Check again.",
  ambiguous_transaction_default:
    "Set one EVM account as the default in Wallet, then choose Check again.",
  default_account_signing_unavailable:
    "Your default account's wallet isn't connected. Link it in Wallet, or set a built-in account as the default, then choose Check again.",
  default_account_address_invalid:
    "Your default account can't be used on Base. Set an EVM account as the default in Wallet, then choose Check again.",
};

/**
 * Plan B POOL-MINT: the pools the host offers (this Home's own and the pools
 * it uses), as the picker shows them, each with its DID and label. A row the
 * page cannot read is left out.
 */
export function mintPoolChoices(pools) {
  if (!Array.isArray(pools)) {
    return [];
  }
  return pools
    .filter((pool) => pool && typeof pool.pool_did === "string" && pool.pool_did.startsWith("did:key:"))
    .map((pool) => ({
      poolDid: pool.pool_did,
      label: typeof pool.label === "string" && pool.label ? pool.label : pool.pool_did,
    }));
}

export function channelBlockerHint(reason) {
  return Object.hasOwn(CHANNEL_BLOCKER_HINTS, reason)
    ? CHANNEL_BLOCKER_HINTS[reason]
    : "Channel list unavailable — type the address instead.";
}

// The server's names for mint terms, as a creator reads them.
const TERM_NAMES = {
  account: "account",
  copies: "copies",
  price: "price",
  royalties: "royalty split",
  access_method: "access method",
  reseller_cut: "resale cut",
  channel: "channel",
  pay_token: "currency",
};

// The server's `public_metadata` refusal codes, as a creator reads them.
const PUBLIC_METADATA_FAILURES = {
  disabled: "public metadata sharing is off",
  not_ready: "your public IPFS node is not ready",
  export_failed: "the metadata could not be read from your Home",
  invalid_car: "the metadata package was not valid",
  import_failed: "your public IPFS node could not store the metadata",
  pin_failed: "your public IPFS node could not keep the metadata",
  announce_failed: "your public IPFS node could not announce the metadata",
};

export function failureDetailRows(error) {
  const rows = [];
  const push = (label, value) => {
    const text = value == null ? "" : String(value).trim();
    if (text) rows.push({ label, value: text });
  };

  push("Reported", error?.message);
  // The stable message is the same across many causes; the detail is the
  // sentence written for this one. Showing both is only noise when they agree.
  if (error?.detail && String(error.detail) !== String(error?.message || "")) {
    push("Cause", error.detail);
  }

  const stages = stagesFromProgress(error?.progress);
  if (stages.length) {
    const naming = {
      encrypt: "Encrypt & escrow",
      publish: "Store on your Home",
      public_metadata: "Publish metadata on IPFS",
      assemble: "Assemble listing",
    };
    const reading = { pending: "not started", active: "in progress", done: "done", err: "failed" };
    push(
      "Progress",
      stages.map((stage) => `${naming[stage.name] || stage.name}: ${reading[stage.state] || stage.state}`).join(", "),
    );
  }

  const publicMetadata = error?.publicMetadata;
  if (publicMetadata) {
    const reading = Object.hasOwn(PUBLIC_METADATA_FAILURES, publicMetadata.code)
      ? PUBLIC_METADATA_FAILURES[publicMetadata.code]
      : publicMetadata.code;
    push("Public metadata", `${reading}. No approval was raised, so you can try again`);
  }

  const mint = error?.creatorMint;
  if (mint) {
    const states = {
      recorded_only: "terms recorded, nothing sent to the chain",
      approval_outstanding: "waiting for a wallet approval already raised",
      already_minted: "already minted and listed",
    };
    push("Existing attempt", states[mint.state] || mint.state);
    push("Its listing id", mint.mintId);
    if (mint.recordedCopies || mint.recordedPrice) {
      push("Its recorded terms", `${mint.recordedCopies} copies at ${mint.recordedPrice}`);
    }
    if (mint.differingTerms && mint.differingTerms.length) {
      push(
        "Differs in",
        mint.differingTerms
          .map((term) => (Object.hasOwn(TERM_NAMES, term) ? TERM_NAMES[term] : term))
          .join(", "),
      );
    }
  }

  const pending = error?.pending;
  if (pending) {
    push(
      "Waiting for",
      pending.reason === "chain_settlement"
        ? "the network to confirm the transaction"
        : `a wallet approval${pending.connectorId ? ` in ${pending.connectorId}` : ""}`,
    );
  }

  if (error?.walletDrift) {
    push("Wallet", "the mint is bound to an account your wallet no longer defaults to");
  }
  if (error?.walletDefault) {
    push("Wallet", "no usable default account for this chain");
  }
  const conflict = error?.attemptConflict;
  if (conflict) {
    const reasons = {
      source_changed: "this file is not the one it started from",
      authority_changed: "it started under another account or setup",
      dispatch_uncertain: "a request it sent has an unknown outcome",
      approval_open: "its approval is still open. Decline it in Wallet, then try again, or resume it",
      listing_unreadable: "its listing could not be read, so it is kept as it is",
    };
    // Why an approval could not be confirmed closed changes what helps.
    const causes = {
      wallet_unreachable: "Wallet could not be reached to confirm its approval. Resume it to continue",
      not_on_record: "its approval is not on record here. Resume it to continue",
    };
    let why = Object.hasOwn(reasons, conflict.reason) ? reasons[conflict.reason] : conflict.reason;
    if (conflict.reason === "approval_open" && Object.hasOwn(causes, conflict.cause)) {
      why = causes[conflict.cause];
    }
    if (conflict.reason === "approval_in_connector") {
      why = `its approval went to ${conflict.connector || "an external wallet"}, which may have signed it. Resume it to finish`;
    }
    push(
      "Earlier attempt",
      conflict.canStartOver
        ? `cannot continue: ${why}. Start over to protect it again`
        : `cannot continue: ${why}`,
    );
  }
  if (error?.approvalClosed) {
    push("Approval", "closed without completing, so this attempt can never settle");
  }

  return rows;
}

// Start over: retry only after Runtime confirms it set this exact source
// object's attempt aside.
export async function discardProtectionAndRetry(uri, request, retry) {
  const receipt = await request("discard_protection", { uri });
  if (receipt?.schema !== "elastos.library.protection-discarded/v1" ||
      receipt.uri !== uri || typeof receipt.discarded !== "boolean") {
    throw new Error("Runtime did not confirm that the earlier attempt was set aside. Try again.");
  }
  await retry();
}

// Where an unfinished mint stopped, in the names this page's own progress
// list uses, so "stopped at" points at a row the creator can see.
const UNFINISHED_STAGE_LABELS = {
  escrow_incomplete: "Encrypt & escrow",
  publish_incomplete: "Store on your Home",
  approval_pending: "Wallet approval",
  approval_in_connector: "Wallet approval",
  transaction_sent: "Chain confirmation",
  transaction_unconfirmed: "Chain confirmation",
  transaction_mined: "Assemble listing",
  listing_not_assembled: "Assemble listing",
};

/**
 * The recoverable unfinished mints in the server's answer, normalised.
 *
 * Which attempts are recoverable is the server's rule, and the ones that are
 * not were dropped on its side; this page only refuses to show an entry it
 * could not describe.
 */
export function unfinishedMintsFrom(answer) {
  const entries = answer && Array.isArray(answer.unfinished) ? answer.unfinished : [];
  return entries
    .filter((entry) =>
      entry && entry.recoverable === true &&
      typeof entry.uri === "string" && entry.uri &&
      typeof entry.name === "string" && entry.name)
    .map((entry) => ({
      uri: entry.uri,
      name: entry.name,
      mintId: String(entry.mint_id || ""),
      stage: String(entry.stage || ""),
      resume: entry.resume === "recorded_terms" ? "recorded_terms" : "enter_terms",
      canStartOver: entry.can_start_over === true,
      terms: entry.terms && typeof entry.terms === "object" ? entry.terms : null,
    }));
}

// A base-unit integer as a decimal amount of a token with `decimals` places.
function formatBaseUnits(value, decimals) {
  const units = BigInt(value);
  const scale = 10n ** BigInt(decimals);
  const whole = units / scale;
  const fraction = (units % scale).toString().padStart(decimals, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : `${whole}`;
}

/**
 * The recorded terms as the creator entered them: copies, and the price in
 * the token it was priced in. The server records base units, so the token's
 * own decimals turn them back; a token this page was not offered is shown in
 * base units rather than guessed at.
 */
export function formatRecordedTerms(terms, payTokens) {
  if (!terms || typeof terms !== "object") return "";
  if (terms.access_method === "free") return "Free";
  try {
    const copies = BigInt(terms.copies);
    const copiesText = `${copies} ${copies === 1n ? "copy" : "copies"}`;
    const tokens = Array.isArray(payTokens) ? payTokens : [];
    const wanted = String(terms.pay_token || "").toLowerCase();
    const token = wanted
      ? tokens.find((candidate) => String(candidate.address || "").toLowerCase() === wanted)
      : tokens[0];
    const price = token && Number.isInteger(token.decimals)
      ? `${formatBaseUnits(terms.price, token.decimals)} ${token.symbol}`
      : `${BigInt(terms.price)} base units`;
    return `${copiesText} at ${price}`;
  } catch {
    return "";
  }
}

/**
 * Recorded terms as the form holds them, so a creator who starts over reviews
 * what they entered last time instead of typing it again. Returns null when
 * nothing was recorded. A price in a token this page was not offered is left
 * blank rather than guessed at.
 */
export function formTermsFrom(terms, payTokens) {
  if (!terms || typeof terms !== "object") return null;
  const tokens = Array.isArray(payTokens) ? payTokens : [];
  const wanted = String(terms.pay_token || "").toLowerCase();
  const token = wanted
    ? tokens.find((candidate) => String(candidate.address || "").toLowerCase() === wanted)
    : tokens[0];
  let copies = "";
  let price = "";
  try {
    copies = BigInt(terms.copies).toString();
    if (token && Number.isInteger(token.decimals)) {
      price = formatBaseUnits(terms.price, token.decimals);
    }
  } catch {
    // Left blank for the creator to fill in.
  }
  const cut = Number(terms.reseller_cut);
  return {
    copies,
    price,
    currency: token ? token.symbol : "",
    channel: String(terms.channel || ""),
    accessMethod: String(terms.access_method || "buy_once"),
    resellerCutPercent: Number.isFinite(cut) && terms.reseller_cut != null ? String(cut / 10) : "",
  };
}

/**
 * What the dialog on open says, or null when there is nothing to offer.
 */
export function unfinishedDialogModel(answer, payTokens) {
  const mints = unfinishedMintsFrom(answer);
  if (!mints.length) return null;
  return {
    heading: mints.length === 1
      ? "A protection did not finish"
      : `${mints.length} protections did not finish`,
    items: mints.map((entry) => ({
      entry,
      line: `${entry.name} — protection stopped at ${
        Object.hasOwn(UNFINISHED_STAGE_LABELS, entry.stage)
          ? UNFINISHED_STAGE_LABELS[entry.stage]
          : "an unfinished step"
      }.`,
      termsText: entry.resume === "recorded_terms"
        ? formatRecordedTerms(entry.terms, payTokens)
        : "Its terms were not recorded yet, so you will enter them again.",
      canStartOver: entry.canStartOver,
    })),
  };
}

/**
 * Builds the dialog body. Everything the server named is written as text,
 * never as markup.
 */
export function renderUnfinishedDialog(doc, model, { onResume, onStartOver }) {
  const root = doc.createElement("div");
  root.className = "unfinished";
  const heading = doc.createElement("h2");
  heading.className = "unfinished-heading";
  heading.textContent = model.heading;
  const list = doc.createElement("ul");
  list.className = "unfinished-list";
  for (const item of model.items) {
    const row = doc.createElement("li");
    const line = doc.createElement("p");
    line.className = "unfinished-line";
    line.textContent = item.line;
    row.append(line);
    if (item.termsText) {
      const terms = doc.createElement("p");
      terms.className = "hint";
      terms.textContent = item.termsText;
      row.append(terms);
    }
    const actions = doc.createElement("div");
    actions.className = "success-actions";
    const resume = doc.createElement("button");
    resume.className = "btn";
    resume.type = "button";
    resume.textContent = "Resume";
    resume.addEventListener("click", () => onResume(item.entry));
    actions.append(resume);
    if (item.canStartOver) {
      const startOver = doc.createElement("button");
      startOver.className = "btn btn-secondary";
      startOver.type = "button";
      startOver.textContent = "Start over";
      startOver.addEventListener("click", () => onStartOver(item.entry));
      actions.append(startOver);
    }
    row.append(actions);
    list.append(row);
  }
  root.append(heading, list);
  return root;
}

// ---------------------------------------------------------------------------
// Public metadata on IPFS: the consent gate (META-PUBLIC Task 6, A4/A5).
//
// On a Home that offers sharing, a new listing's public metadata is published
// on this Home's public IPFS node, so the Creator lists new files only while
// the Home admin has agreed to that in Inbox and the node is ready. The
// server owns the consent, the node and the withdrawal; this page only reads
// `GET /api/apps/creator/public-ipfs` and shows the one screen that status
// calls for. A Home that does not offer sharing (`gate_open: false`) opens the
// Creator as on develop. Unfinished mints are offered on every path: the gate
// decides what the form shows, never whether a stopped mint can be recovered.
// ---------------------------------------------------------------------------

function textOf(value) {
  return typeof value === "string" ? value.trim() : "";
}

/**
 * The screen a public-IPFS status calls for. A withdrawal comes first, so a
 * Home that is stopping is never offered Agree; then the admin; then consent.
 * Only a running store that says it is ready opens the Creator: "unknown"
 * liveness is a store that did not answer in time, which is "starting",
 * never "consent".
 */
export function publicIpfsGate(status) {
  const value = status && typeof status === "object" ? status : {};
  // A5: only a Home that offers sharing gates the Creator.
  if (value.gate_open !== true) return "off";
  if (value.withdrawing === true) return "stopping";
  if (value.admin !== true) return "admin_required";
  if (value.consent_enabled !== true) return "consent";
  const store = value.store && typeof value.store === "object" ? value.store : {};
  return store.liveness === "running" && store.ready === true ? "ready" : "starting";
}

/**
 * Reads the server's typed refusal of the `public_metadata` publish stage.
 * Every such refusal raised no approval, so the same publish can simply be
 * asked for again. Returns null when the envelope carries no such refusal.
 */
export function publicMetadataFailure(envelope) {
  const failure = envelope && envelope.public_metadata;
  if (!failure || typeof failure !== "object" || Array.isArray(failure)) return null;
  const code = textOf(failure.code);
  if (!code) return null;
  return { stage: "public_metadata", code, retry: true };
}

function abortReason(signal) {
  if (signal.reason instanceof Error) return signal.reason;
  const error = new Error("The wait was cancelled.");
  error.name = "AbortError";
  return error;
}

function throwIfAborted(signal) {
  if (signal && signal.aborted) throw abortReason(signal);
}

function delay(ms, signal) {
  return new Promise((resolve, reject) => {
    throwIfAborted(signal);
    const onAbort = () => {
      clearTimeout(timer);
      reject(abortReason(signal));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * Polls the status until its gate is `target`: "ready" once consent is given in
 * Inbox or at boot, "consent" after a Stop. Answers `{gate, status}`, or
 * `{gate: "timeout", status}` with the last status read when the budget ends.
 * A failed read is skipped, so a Home that is briefly unreachable is waited
 * out the same way a slow store is. `onStatus(status, gate)` sees every read.
 * An abort rejects with an `AbortError` and stops reading at once.
 */
export async function waitForPublicIpfsGate(
  readStatus,
  target,
  { intervalMs = 2000, timeoutMs = 180000, signal, onStatus } = {},
) {
  const deadline = Date.now() + timeoutMs;
  let status = null;
  for (;;) {
    throwIfAborted(signal);
    let read = null;
    try {
      read = await readStatus();
    } catch {
      read = null;
    }
    throwIfAborted(signal);
    if (read && typeof read === "object") {
      status = read;
      const gate = publicIpfsGate(status);
      if (typeof onStatus === "function") onStatus(status, gate);
      if (gate === target) return { gate, status };
    }
    if (Date.now() >= deadline) return { gate: "timeout", status };
    await delay(intervalMs, signal);
  }
}

const PUBLIC_IPFS_TEXT = {
  consent: "Turn on metadata sharing in Inbox to mint. Your unfinished mints stay available.",
  starting: "Starting your public IPFS node…",
  stopping: "Stopping…",
  notReady: "Your public IPFS node isn't ready yet.",
  adminRequired: "Ask the Home admin to enable public metadata sharing.",
  stillStopping: "your public IPFS node has not stopped yet",
};

/**
 * The gate's journeys over injected ports, so each one is tested without a
 * page. `show(view)` receives `{gate, text, actions, detail?}`, where
 * `actions` names the buttons the screen offers ("open_inbox", "retry").
 * `openCreator(status)` runs on every arrival at "ready" or "off";
 * `openInbox()` asks Home to open Inbox, where consent and Stop live. Every
 * action returns a promise that settles when its wait does.
 */
export function createPublicIpfsGateFlow({
  readStatus,
  show,
  openCreator,
  openInbox,
  offerUnfinished,
  wait = {},
}) {
  let status = null;
  let generation = 0;
  let controller = null;
  let retryWith = null;
  let offered = false;

  function view(gate, text, actions = [], detail = "") {
    show(detail ? { gate, text, actions, detail } : { gate, text, actions });
  }

  function stopWaiting() {
    generation += 1;
    if (controller) controller.abort();
    controller = null;
  }

  // The withdrawal's target: an admin is asked again once it finished; anyone
  // else is told to ask the admin.
  function stopTarget() {
    return status && status.admin === false ? "admin_required" : "consent";
  }

  function showConsent() {
    view("consent", PUBLIC_IPFS_TEXT.consent, ["open_inbox"]);
  }

  // Read-only: Try again lives in Inbox.
  function showStillStopping(current) {
    const reason = textOf(current?.stop_pending).replace(/[.\s]+$/, "") || PUBLIC_IPFS_TEXT.stillStopping;
    view("stopping", `Still stopping: ${reason}. Your Home keeps trying.`);
  }

  function showNotReady() {
    retryWith = () => {
      view("starting", PUBLIC_IPFS_TEXT.starting);
      return waitFor("ready", "starting");
    };
    view("timeout", PUBLIC_IPFS_TEXT.notReady, ["retry"]);
  }

  function route(next) {
    status = next;
    retryWith = null;
    switch (publicIpfsGate(next)) {
      case "off":
        view("off", "");
        openCreator(next);
        return Promise.resolve();
      case "ready":
        view("ready", "");
        openCreator(next);
        return Promise.resolve();
      case "consent":
        // Consent is given in Inbox; this page follows it to "ready".
        showConsent();
        return waitFor("ready", "consent");
      case "admin_required":
        view("admin_required", PUBLIC_IPFS_TEXT.adminRequired);
        return Promise.resolve();
      case "starting":
        view("starting", PUBLIC_IPFS_TEXT.starting);
        return waitFor("ready", "starting");
      default:
        if (textOf(next.stop_pending)) showStillStopping(next);
        else view("stopping", PUBLIC_IPFS_TEXT.stopping);
        return waitFor(stopTarget(), "stopping");
    }
  }

  // Waits from `current` towards `target`. A status that names any other
  // screen (consent withdrawn while starting, another admin's Stop) leaves the
  // wait and shows that screen instead.
  async function waitFor(target, current) {
    stopWaiting();
    const mine = generation;
    const abort = new AbortController();
    controller = abort;
    let reroute = null;
    let result;
    try {
      result = await waitForPublicIpfsGate(readStatus, target, {
        ...wait,
        signal: abort.signal,
        onStatus: (next, gate) => {
          if (mine !== generation) return;
          status = next;
          if (gate !== target && gate !== current) {
            reroute = next;
            abort.abort();
          } else if (current === "stopping" && textOf(next.stop_pending)) {
            showStillStopping(next);
          }
        },
      });
    } catch {
      if (mine !== generation || !reroute) return undefined;
      controller = null;
      return route(reroute);
    }
    if (mine !== generation) return undefined;
    controller = null;
    if (result.gate !== "timeout") return route(result.status);
    if (current === "stopping") {
      showStillStopping(status);
    } else if (current === "consent") {
      showConsent();
    } else {
      showNotReady();
    }
    return undefined;
  }

  return {
    async start() {
      if (!offered) {
        offered = true;
        try {
          Promise.resolve(offerUnfinished()).catch(() => {});
        } catch {
          // Never fatal: a page that cannot list unfinished mints still opens.
        }
      }
      stopWaiting();
      const mine = generation;
      let next;
      try {
        next = await readStatus();
      } catch {
        if (mine === generation) showNotReady();
        return undefined;
      }
      if (mine !== generation) return undefined;
      return route(next);
    },

    retry() {
      if (!retryWith) return Promise.resolve();
      return retryWith();
    },

    openInbox() {
      openInbox();
    },

    cancel() {
      stopWaiting();
    },
  };
}

// ---------------------------------------------------------------------------
// DOM flow — skipped under `node --test` (no `document`/`window` there).
// ---------------------------------------------------------------------------

/**
 * Lets Home renew this frame's launch authority before it expires (#532).
 * Home serves its navigation client at an absolute path, so it is loaded in
 * the browser only, and this module stays importable under `node --test`.
 */
function connectHomeNavigation(options) {
  return import("/apps/home/home-navigation-client.js")
    .then(({ createHomeNavigationClient }) => createHomeNavigationClient(options))
    .catch((error) => {
      console.warn("Home cannot renew this window's access", error);
      return null;
    });
}

function bootCreatorApp() {
  const query = new URLSearchParams(window.location.search);
  let homeToken = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("home_token") || "";
  const homeParentOrigin = query.get("home_origin") || "";
  // Every request below reads the current token, which Home renews.
  connectHomeNavigation({ homeToken, homeOrigin: homeParentOrigin, target: "creator",
    onHomeToken(token) {
      homeToken = token;
    },
  });

  const els = {
    lockedShell: document.querySelector("#locked-shell"),
    shell: document.querySelector("#creator-shell"),

    drop: document.querySelector("#drop"),
    dropTitle: document.querySelector("#drop-title"),
    dropMetaText: document.querySelector("#drop-meta-text"),
    dropBadge: document.querySelector("#drop-badge"),
    fileInput: document.querySelector("#file-input"),

    title: document.querySelector("#title"),
    desc: document.querySelector("#desc"),

    thumbDrop: document.querySelector("#thumb-drop"),
    thumbInput: document.querySelector("#thumb-input"),
    thumbPreviewWrap: document.querySelector("#thumb-preview-wrap"),
    thumbPreviewImg: document.querySelector("#thumb-preview-img"),
    thumbRemove: document.querySelector("#thumb-remove"),

    methodGrid: document.querySelector("#method-grid"),
    methodHint: document.querySelector("#method-hint"),
    priceRow: document.querySelector("#price-row"),
    priceInput: document.querySelector("#price-input"),
    currency: document.querySelector("#currency"),
    poolRow: document.querySelector("#pool-row"),
    poolSelect: document.querySelector("#pool-select"),

    copiesInput: document.querySelector("#copies-input"),
    category: document.querySelector("#category"),

    channel: document.querySelector("#channel"),
    channelManual: document.querySelector("#channel-manual"),
    channelManualInput: document.querySelector("#channel-manual-input"),
    channelHint: document.querySelector("#channel-hint"),
    channelApprove: document.querySelector("#channel-approve"),
    resellField: document.querySelector("#resell-field"),
    resellerCut: document.querySelector("#reseller-cut"),

    royaltyField: document.querySelector("#royalty-field"),
    royaltyRows: document.querySelector("#royalty-rows"),
    royaltyAdd: document.querySelector("#royalty-add"),
    royaltyTotal: document.querySelector("#royalty-total"),

    aiLicensing: document.querySelector("#ai-licensing"),
    adultFlag: document.querySelector("#adult-flag"),
    legalAttest: document.querySelector("#legal-attest"),

    previewSettings: document.querySelector("#preview-settings"),
    previewEnabled: document.querySelector("#preview-enabled"),
    previewControls: document.querySelector("#preview-controls"),
    previewDuration: document.querySelector("#preview-duration"),
    previewDurationDisplay: document.querySelector("#preview-duration-display"),

    submitButton: document.querySelector("#submit-button"),
    progressSteps: document.querySelector("#progress-steps"),
    failureDetails: document.querySelector("#failure-details"),
    failureDetailsList: document.querySelector("#failure-details-list"),
    recoveryActions: document.querySelector("#recovery-actions"),
    statusText: document.querySelector("#status-text"),

    successPanel: document.querySelector("#success-panel"),
    successTitle: document.querySelector("#success-title"),
    successDetail: document.querySelector("#success-detail"),
    mintIdText: document.querySelector("#mint-id-text"),
    openLibraryButton: document.querySelector("#open-library-button"),
    resetButton: document.querySelector("#reset-button"),

    unfinishedDialog: document.querySelector("#unfinished-dialog"),
    unfinishedBody: document.querySelector("#unfinished-body"),
    unfinishedClose: document.querySelector("#unfinished-close"),

    publicIpfsGate: document.querySelector("#public-ipfs-gate"),
    publicIpfsGateText: document.querySelector("#public-ipfs-gate-text"),
    publicIpfsGateDetail: document.querySelector("#public-ipfs-gate-detail"),
    publicIpfsGateActions: document.querySelector("#public-ipfs-gate-actions"),
    publicMetadataStage: document.querySelector('[data-stage="public_metadata"]'),
  };

  let selectedFile = null;
  // What the host says this creator may publish into, and price in. Both start
  // empty and the form stays usable while they are: the channel can be typed,
  // and the price scale comes from whichever token is chosen.
  let offeredChannels = [];
  let offeredPayTokens = [];
  let customThumbnail = null;
  // All three are connected. The method travels with the listing terms and
  // decides the channel's `opType`: free creates no operative at all, buy once
  // creates one, and buy and resell creates one that also carries a resale cut.
  let accessMethod = "buy_once";
  let submitting = false;
  // Interval id while a publish is in flight, so the side-channel progress
  // poll is stopped whether the publish succeeds, fails or throws.
  let progressPoll = null;
  let listed = false;
  let homeChromeReady = false;
  let activeStageName = "";
  // The object this run is protecting, so a recovery action targets the same
  // one the failure was about.
  let lastTargetUri = "";
  // A file already in the Library whose unfinished mint the creator chose to
  // continue: protecting it skips the upload, since its bytes are the ones
  // the mint was started from.
  let resumeTarget = null;
  // Asks for the last run again ("Check again"), whichever kind it was.
  let retryLast = null;
  // Settles once the host has said which tokens a price may be in, which is
  // what a recorded price is read back in.
  let channelsReady = Promise.resolve();
  // The public metadata consent gate; set by boot once there is a token.
  let publicIpfs = null;

  boot();

  function boot() {
    if (!homeToken) {
      els.lockedShell.classList.remove("hidden");
      return;
    }
    els.shell.classList.remove("hidden");
    bindEvents();
    syncMethodUI();
    seedDefaultRoyaltyRows();
    announceHomeChrome();
    // The gate decides whether a new file can be listed. It offers the
    // unfinished mints on every path, ready or not, so Resume and Check again
    // stay available while the Home is starting, stopping or waiting for
    // consent.
    publicIpfs = createPublicIpfsGateFlow({
      readStatus: readPublicIpfsStatus,
      show: showPublicIpfsGate,
      openCreator: () => refreshSubmitEnabled(),
      openInbox: openInboxFromHome,
      offerUnfinished: () =>
        offerUnfinished().catch(() => {
          // Never fatal: a page that cannot list unfinished mints still protects.
        }),
    });
    void publicIpfs.start();
  }

  // -- Public metadata on IPFS ------------------------------------------

  async function readPublicIpfsStatus() {
    const response = await fetch(PUBLIC_IPFS_API, {
      headers: { accept: "application/json", "x-elastos-home-token": homeToken },
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(publicIpfsRefusal(body, response.status));
    }
    return body;
  }

  function publicIpfsRefusal(body, status) {
    return (
      readText(body?.detail)
      || readText(body?.message)
      || readText(body?.error)
      || `Public metadata sharing did not answer (${status}).`
    );
  }

  // Ready and off show the Creator; every other gate shows its screen in
  // place of the new-file form. Progress, status and recovery stay visible,
  // so a resumed mint is still followed while gated. With the gate off the
  // Creator is develop's: no metadata stage either.
  function showPublicIpfsGate(view) {
    const open = view.gate === "ready" || view.gate === "off";
    els.shell.classList.toggle("gated", !open);
    els.publicIpfsGate.classList.toggle("hidden", open);
    els.publicMetadataStage?.classList.toggle("hidden", view.gate === "off");
    if (open) return;
    els.publicIpfsGateText.textContent = view.text || "";
    els.publicIpfsGateDetail.textContent = view.detail || "";
    els.publicIpfsGateDetail.classList.toggle("hidden", !view.detail);
    els.publicIpfsGateActions.replaceChildren(...view.actions.map(publicIpfsGateButton));
  }

  function publicIpfsGateButton(action) {
    const [label, className, run] = {
      open_inbox: ["Open Inbox", "btn btn-primary", () => publicIpfs.openInbox()],
      retry: ["Retry", "btn", () => publicIpfs.retry()],
    }[action];
    const button = document.createElement("button");
    button.type = "button";
    button.className = className;
    button.textContent = label;
    button.addEventListener("click", () => {
      void Promise.resolve(run()).catch(() => {});
    });
    return button;
  }

  // Consent and Stop live in Inbox: Home opens it for the Creator.
  function openInboxFromHome() {
    if (!homeParentOrigin || window.top === window) return;
    window.top.postMessage({ type: "home:open-target", target: "inbox", homeToken }, homeParentOrigin);
  }

  function readText(value) {
    return typeof value === "string" ? value.trim() : "";
  }

  // On open: offer back any mint in the Creator folder that stopped part way
  // and can still be recovered. The server drops the ones that cannot on the
  // way, so a new mint of those files simply proceeds.
  async function offerUnfinished() {
    const roots = await providerApi("roots", {});
    const homeRoot = (roots.roots || []).find((root) => root.id === "home");
    if (!homeRoot) return;
    const folder = `${String(homeRoot.uri).replace(/\/+$/, "")}/Creator`;
    const answer = await providerApi("unfinished_protections", { uri: folder });
    await channelsReady;
    const model = unfinishedDialogModel(answer, offeredPayTokens);
    if (!model || !els.unfinishedDialog) return;
    els.unfinishedBody.replaceChildren(
      renderUnfinishedDialog(document, model, {
        onResume: (entry) => {
          closeUnfinished();
          if (entry.resume === "recorded_terms") {
            void resumeRecorded(entry);
          } else {
            prepareEnterTerms(entry);
          }
        },
        onStartOver: (entry) => {
          closeUnfinished();
          void startOverUnfinished(entry);
        },
      }),
    );
    if (typeof els.unfinishedDialog.showModal === "function") {
      els.unfinishedDialog.showModal();
    } else {
      els.unfinishedDialog.setAttribute("open", "");
    }
  }

  function closeUnfinished() {
    if (!els.unfinishedDialog) return;
    if (typeof els.unfinishedDialog.close === "function") {
      els.unfinishedDialog.close();
    } else {
      els.unfinishedDialog.removeAttribute("open");
    }
  }

  // Start over: the host sets the attempt aside (archived, never deleted)
  // and the file is ready for a new mint, with whatever terms were recorded
  // filled in for the creator to review.
  async function startOverUnfinished(entry) {
    if (submitting) return;
    try {
      await discardProtectionAndRetry(entry.uri, providerApi, async () => {});
    } catch (error) {
      setStatus(String(error?.message || "The earlier attempt could not be set aside."), "err");
      return;
    }
    showResumeTarget(entry, "Already in your Library · enter its terms, then choose Protect and list");
    prefillTerms(entry.terms);
    if (!els.title.value.trim()) {
      els.title.value = entry.name.replace(/\.[^.]+$/, "");
    }
    setStatus("The earlier attempt was set aside. Review the terms, then choose Protect and list.");
    refreshSubmitEnabled();
  }

  // Fill the form from recorded terms. Royalty rows are left as they are: the
  // recorded split is the creator's 950 units, which the rows do not show
  // one-to-one.
  function prefillTerms(terms) {
    const form = formTermsFrom(terms, offeredPayTokens);
    if (!form) return;
    accessMethod = form.accessMethod;
    syncMethodUI();
    if (form.copies) els.copiesInput.value = form.copies;
    if (form.price) els.priceInput.value = form.price;
    if (form.currency) els.currency.value = form.currency;
    if (form.resellerCutPercent) els.resellerCut.value = form.resellerCutPercent;
    if (form.channel) {
      const offered = offeredChannels.find(
        (channel) => String(channel.address || "").toLowerCase() === form.channel,
      );
      els.channel.value = offered ? offered.address : MANUAL_CHANNEL_VALUE;
      if (!offered) els.channelManualInput.value = form.channel;
      els.channelManual.classList.toggle("hidden", Boolean(offered));
    }
  }

  // Show which file a continued mint is about, in the same place a picked
  // file shows.
  function showResumeTarget(entry, meta) {
    selectedFile = null;
    resumeTarget = { uri: entry.uri, name: entry.name };
    lastTargetUri = entry.uri;
    listed = false;
    clearFailureDetails();
    const kind = classifyProtection(resolveMime({ name: entry.name, type: "" }));
    els.dropTitle.textContent = entry.name;
    els.dropMetaText.textContent = meta;
    els.dropBadge.textContent = kind;
    els.dropBadge.classList.remove("hidden");
    const transcodeStage = els.progressSteps.querySelector('li[data-stage="transcode"]');
    if (transcodeStage) transcodeStage.classList.toggle("hidden", kind !== "media");
    resetStages();
    els.successPanel.classList.add("hidden");
  }

  // Resume: re-run the recorded mint at its recorded terms. Nothing is typed
  // and nothing is uploaded; the server continues from where it stopped.
  async function resumeRecorded(entry) {
    if (submitting) return;
    showResumeTarget(entry, "Already in your Library · resuming at its recorded terms");
    retryLast = () => resumeRecorded(entry);
    setStage("analyze", "done");
    try {
      await publishWithProgress(entry.uri, { resume: true });
    } catch (error) {
      if (error?.pending) showPending(error.pending, error);
      else showFailure(error);
    }
  }

  // An attempt that stopped before its terms were recorded continues once the
  // creator enters them: the file is already in the Library and its escrow is
  // kept, so Protect and list picks it up without another upload.
  function prepareEnterTerms(entry) {
    if (submitting) return;
    showResumeTarget(entry, "Already in your Library · enter its terms, then choose Protect and list");
    if (!els.title.value.trim()) {
      els.title.value = entry.name.replace(/\.[^.]+$/, "");
    }
    setStatus("");
    refreshSubmitEnabled();
  }

  function announceHomeChrome() {
    if (homeChromeReady || !homeParentOrigin || window.top === window) {
      return;
    }
    window.top.postMessage({ type: "home:app-ready", homeToken }, homeParentOrigin);
    homeChromeReady = true;
  }

  function bindEvents() {
    els.drop.addEventListener("click", () => els.fileInput.click());
    els.drop.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        els.fileInput.click();
      }
    });
    els.drop.addEventListener("dragenter", (event) => {
      event.preventDefault();
      els.drop.classList.add("over");
    });
    els.drop.addEventListener("dragover", (event) => event.preventDefault());
    els.drop.addEventListener("dragleave", () => els.drop.classList.remove("over"));
    els.drop.addEventListener("drop", (event) => {
      event.preventDefault();
      els.drop.classList.remove("over");
      const file = event.dataTransfer?.files?.[0];
      if (file) onFile(file);
    });
    els.fileInput.addEventListener("change", () => {
      const file = els.fileInput.files?.[0];
      if (file) onFile(file);
    });

    els.thumbDrop.addEventListener("click", () => els.thumbInput.click());
    els.thumbDrop.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        els.thumbInput.click();
      }
    });
    els.thumbDrop.addEventListener("dragenter", (event) => {
      event.preventDefault();
      els.thumbDrop.classList.add("over");
    });
    els.thumbDrop.addEventListener("dragover", (event) => event.preventDefault());
    els.thumbDrop.addEventListener("dragleave", () => els.thumbDrop.classList.remove("over"));
    els.thumbDrop.addEventListener("drop", (event) => {
      event.preventDefault();
      els.thumbDrop.classList.remove("over");
      const file = event.dataTransfer?.files?.[0];
      if (file) setCustomThumbnail(file);
    });
    els.thumbInput.addEventListener("change", () => setCustomThumbnail(els.thumbInput.files?.[0]));
    els.thumbRemove.addEventListener("click", clearCustomThumbnail);

    els.methodGrid.querySelectorAll(".method").forEach((card) => {
      const pick = () => {
        accessMethod = card.dataset.method;
        syncMethodUI();
      };
      card.addEventListener("click", pick);
      card.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          pick();
        }
      });
    });

    els.royaltyAdd.addEventListener("click", () => addRoyaltyRow("", ""));

    els.previewEnabled.addEventListener("change", () => {
      els.previewControls.classList.toggle("hidden", !els.previewEnabled.checked);
    });
    els.previewDuration.addEventListener("input", () => {
      els.previewDurationDisplay.textContent = `${els.previewDuration.value}s`;
    });

    els.copiesInput.addEventListener("input", refreshSubmitEnabled);
    els.priceInput.addEventListener("input", refreshSubmitEnabled);
    els.resellerCut.addEventListener("input", refreshSubmitEnabled);
    // A currency change alone can invalidate an already-typed amount (e.g.
    // more fractional digits than USDC's 6 decimals allow), so re-check.
    els.currency.addEventListener("change", refreshSubmitEnabled);
    els.channel.addEventListener("change", () => {
      els.channelManual.classList.toggle(
        "hidden",
        els.channel.value !== MANUAL_CHANNEL_VALUE,
      );
      refreshSubmitEnabled();
    });
    els.channelManualInput.addEventListener("input", refreshSubmitEnabled);
    els.channelApprove.addEventListener("click", () => {
      // Approving is the Inbox's job, not this page's: it is an operator
      // decision about letting this Home talk to an outside service, and it
      // is recorded there with who allowed it. Asking for the list already
      // raised the request, so this says where it is waiting and then becomes
      // the way back -- rather than making a creator reload the page to find
      // out whether it worked.
      if (els.channelApprove.dataset.recheck === "true") {
        loadChannels().catch(() => {
          renderChannels(
            "Channel list unavailable — type the address instead.",
            "Unavailable",
          );
        });
        return;
      }
      offerChannelRecheck();
      els.channelHint.textContent =
        "Approve “Creator requests your channel list” in your Inbox, then choose Check again.";
    });
    channelsReady = loadChannels().catch(() => {
      // Never fatal: a directory that cannot be read costs the list, not the
      // ability to publish.
      renderChannels("Channel list unavailable — type the address instead.");
    });
    els.unfinishedClose?.addEventListener("click", closeUnfinished);
    els.submitButton.addEventListener("click", () => {
      protectAndList().catch((error) => {
        if (error?.pending) {
          showPending(error.pending, error);
        } else {
          showFailure(error);
        }
      });
    });
    els.openLibraryButton.addEventListener("click", openLibrary);
    els.resetButton.addEventListener("click", resetForAnotherFile);
  }

  function onFile(file) {
    if (!file || submitting) return;
    selectedFile = file;
    resumeTarget = null;
    lastTargetUri = "";
    clearFailureDetails();
    listed = false;
    const mime = resolveMime(file);
    const kind = classifyProtection(mime);
    const opensIn = kind === "media" ? "plays in Elacity Player" : "opens in Elacity Reader";
    els.dropTitle.textContent = file.name;
    els.dropMetaText.textContent = `${humanSize(file.size)} · ${mime} · ${opensIn}`;
    els.dropBadge.textContent = kind;
    els.dropBadge.classList.remove("hidden");
    if (!els.title.value.trim()) {
      els.title.value = file.name.replace(/\.[^.]+$/, "");
    }
    const isMedia = kind === "media";
    els.previewSettings.classList.toggle("hidden", !isMedia);
    els.previewEnabled.checked = isMedia;
    els.previewControls.classList.toggle("hidden", !isMedia);
    // "Transcode & fragment" only applies to media; see the progress-stage
    // mapping notes by setStage/resetStages for what this tracker can and
    // cannot actually observe.
    const transcodeStage = els.progressSteps.querySelector('li[data-stage="transcode"]');
    if (transcodeStage) transcodeStage.classList.toggle("hidden", !isMedia);
    resetStages();
    const refusal = fileTypeRefusal(file.name);
    setStatus(refusal, refusal ? "err" : "");
    els.successPanel.classList.add("hidden");
    refreshSubmitEnabled();
  }

  // The listing a marketplace displays, read from the form.
  //
  // The cover is the only field that is bytes rather than a statement, so it is
  // the only one that has to be read asynchronously; everything else is a
  // value already on the page. Royalties are deliberately absent — see the
  // royalty hint: the rows describe all 1000 units (95 to the creator, 5 to
  // the protocol) while the publish contract takes the creator's 950 alone, so
  // sending them as entered would describe a payout the chain will not make.
  async function collectListing() {
    const listing = {
      title: els.title.value.trim(),
      description: els.desc.value.trim(),
      category: els.category.value.trim(),
      tags: [],
      adult: els.adultFlag.checked,
      licensing: { ai_training: els.aiLicensing.checked },
      legal_attestation: { owns_distribution_rights: els.legalAttest.checked },
    };
    if (customThumbnail) {
      listing.thumbnail = {
        mime: customThumbnail.type,
        bytes_base64: await fileToBase64(customThumbnail),
      };
    }
    listing.access_method = accessMethod;
    // The price scale is NOT here: it is a mint term and travels in
    // `protection`, beside the price it gives meaning to. It sat here while
    // the channel did, and the host rightly refuses a listing that carries it.
    if (accessMethod === "buy_and_resell") {
      listing.reseller_cut = resellerCutDeciPercent();
    }
    // A free mint creates no operative, so there is no royalty share to split.
    const royalties = isPaidMethod() ? collectRoyaltyUnits() : null;
    if (royalties) {
      listing.royalties = royalties;
    }
    return listing;
  }

  /**
   * The creator's own royalty split, as ERC-1155 ROYALTY_SHARE units.
   *
   * The rows show all 1000 units — 950 the creator's, 50 the protocol's, which
   * the contracts mint themselves — so the protocol row is excluded and what
   * remains must come to the creator's 950. One unit is 0.1%, so a row's
   * percent times ten is its units, and no other conversion happens anywhere.
   *
   * The protocol row is excluded and fixed, and the total is capped at 100%,
   * so whenever the rows do add up the rest come to exactly 950.
   *
   * Returns null, meaning "say nothing and let the chain default apply", when
   * the rows are still the seeded default: "You" is a label rather than an
   * address, and the chain default already pays the creator's whole share to
   * the creator. Only a split naming real addresses is worth sending.
   */
  function collectRoyaltyUnits() {
    const rows = Array.from(els.royaltyRows.querySelectorAll(".royalty-row"))
      .filter((row) => row.dataset.protocol !== "true")
      .map((row) => ({
        address: row.querySelector(".ry-addr").value.trim().toLowerCase(),
        units: Math.round((Number.parseFloat(row.querySelector(".ry-pct").value) || 0) * 10),
      }));
    if (!rows.length || !rows.every((row) => EVM_ADDRESS_RE.test(row.address))) {
      return null;
    }
    const total = rows.reduce((sum, row) => sum + row.units, 0);
    if (total !== CREATOR_ROYALTY_UNITS) {
      return null;
    }
    return rows;
  }

  // Base64 without a data: URL round trip, and in chunks: a single
  // String.fromCharCode over a whole image blows the argument limit.
  async function fileToBase64(file) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
    }
    return btoa(binary);
  }

  // -- Cover thumbnail: local preview only (see #thumb-drop's hint) --------

  function setCustomThumbnail(file) {
    if (!file || !file.type.startsWith("image/")) return;
    customThumbnail = file;
    els.thumbPreviewImg.src = URL.createObjectURL(file);
    els.thumbPreviewWrap.classList.remove("hidden");
    els.thumbDrop.classList.add("hidden");
  }

  function clearCustomThumbnail() {
    customThumbnail = null;
    els.thumbInput.value = "";
    els.thumbPreviewWrap.classList.add("hidden");
    els.thumbDrop.classList.remove("hidden");
  }

  // -- Access method ---------------------------------------------------------

  function isPaidMethod() {
    return accessMethod === "buy_once" || accessMethod === "buy_and_resell";
  }

  function syncMethodUI() {
    els.methodGrid.querySelectorAll(".method").forEach((card) => {
      const selected = card.dataset.method === accessMethod;
      card.classList.toggle("sel", selected);
      card.setAttribute("aria-pressed", String(selected));
    });
    els.priceRow.classList.toggle("hidden", !isPaidMethod());
    els.resellField.classList.toggle("hidden", accessMethod !== "buy_and_resell");
    els.royaltyField.classList.toggle("hidden", !isPaidMethod());
    // What each method actually does on chain, since the difference is not
    // cosmetic: a free asset has no operative, so nobody buys it and access
    // comes from the channel instead.
    els.methodHint.textContent = {
      free: "Free mints no sale and no access token — the channel decides who can open it.",
      buy_once: "One sale per copy. Resale is not offered.",
      buy_and_resell: "Sold, then resellable, with the resale royalty below.",
    }[accessMethod] || "";
    refreshSubmitEnabled();
  }

  // -- Royalty split (see #royalty-field's hint and collectRoyaltyUnits) --
  //
  // Seeded with the chain's real default distribution (95% creator / 5%
  // protocol — see DEFAULT_CREATOR_ROYALTY_PERCENT above) so "+ Add payee"
  // starts from a running total that already means something, instead of an
  // empty, confusing control. The total may never exceed 100%: an edit that
  // would push it over is reverted (enforceRoyaltyCap), with a visible reason
  // rather than a silent clamp. There is no wallet integration to resolve the
  // creator's own address client-side, so that row is honestly labeled "You"
  // rather than carrying an invented 0x address.

  function addRoyaltyRow(address, percent, isProtocol = false) {
    const row = document.createElement("div");
    row.className = "royalty-row";
    // The protocol's share is minted by the contracts themselves; it is shown
    // so the running total means something, and never sent as a payee.
    if (isProtocol) {
      row.dataset.protocol = "true";
    }
    const addr = document.createElement("input");
    addr.type = "text";
    addr.className = "ry-addr";
    addr.placeholder = "0x… payee address";
    addr.value = address || "";
    const pct = document.createElement("input");
    pct.type = "number";
    pct.className = "ry-pct";
    pct.min = "0";
    pct.max = String(ROYALTY_TOTAL_TARGET_PERCENT);
    pct.step = "0.1";
    pct.placeholder = "%";
    const initialPercent = percent != null && percent !== "" ? String(percent) : "";
    pct.value = initialPercent;
    pct.dataset.lastValue = initialPercent || "0";
    const del = document.createElement("button");
    del.type = "button";
    del.className = "ry-del";
    del.textContent = "×";
    del.title = "Remove payee";
    del.addEventListener("click", () => {
      row.remove();
      refreshRoyaltyTotal();
    });
    if (isProtocol) {
      // The contracts mint this share from CentralStorage.protocolShares()
      // whatever the creator does, so an input that accepted edits would be
      // lying — and an edit would silently change what the other rows have to
      // come to. Shown, counted in the total, and fixed.
      addr.readOnly = true;
      pct.readOnly = true;
      del.disabled = true;
      del.title = "The protocol share is set by the contract";
      row.append(addr, pct, del);
    } else {
      addr.addEventListener("input", refreshRoyaltyTotal);
      pct.addEventListener("input", refreshRoyaltyTotal);
      pct.addEventListener("change", () => enforceRoyaltyCap(pct));
      row.append(addr, pct, del);
    }
    els.royaltyRows.appendChild(row);
    refreshRoyaltyTotal();
  }

  function seedDefaultRoyaltyRows() {
    els.royaltyRows.innerHTML = "";
    addRoyaltyRow("You", DEFAULT_CREATOR_ROYALTY_PERCENT);
    addRoyaltyRow("Elacity", DEFAULT_PROTOCOL_ROYALTY_PERCENT, true);
  }

  function collectRoyaltyRows() {
    return Array.from(els.royaltyRows.querySelectorAll(".royalty-row"))
      .map((row) => ({
        address: row.querySelector(".ry-addr").value.trim(),
        royalty: Number.parseFloat(row.querySelector(".ry-pct").value) || 0,
      }))
      .filter((row) => row.address || row.royalty);
  }

  // Reverts a percent field to its last accepted value if the committed edit
  // (on blur/enter, not every keystroke — so typing isn't interrupted) would
  // push the group total over 100%, and says so plainly rather than clamping
  // the number to whatever happened to fit.
  function enforceRoyaltyCap(pctInput) {
    const { overLimit } = summarizeRoyaltyRows(collectRoyaltyRows());
    if (!overLimit) {
      pctInput.dataset.lastValue = pctInput.value || "0";
      // Always re-render on commit, not just on rejection: a `change` event
      // can fire without a preceding `input` (e.g. a scripted value set), and
      // without this an earlier rejection message would linger stale.
      refreshRoyaltyTotal();
      return;
    }
    pctInput.value = pctInput.dataset.lastValue || "0";
    refreshRoyaltyTotal();
    els.royaltyTotal.textContent = "That amount would push the total over 100% — change reverted.";
    els.royaltyTotal.className = "royalty-total bad";
  }

  function refreshRoyaltyTotal() {
    const rows = collectRoyaltyRows();
    if (!rows.length) {
      els.royaltyTotal.textContent = "";
      els.royaltyTotal.className = "royalty-total";
      return;
    }
    const { sum, ok, overLimit } = summarizeRoyaltyRows(rows);
    let text;
    let variant = "";
    if (overLimit) {
      text = `Total royalty is ${sum.toFixed(1)}% — must not exceed 100%.`;
      variant = "bad";
    } else if (ok) {
      text = "Total royalty is 100% ✓";
      variant = "ok";
    } else {
      text = `Total royalty is ${sum.toFixed(1)}% of 100%.`;
    }
    els.royaltyTotal.textContent = text;
    els.royaltyTotal.className = `royalty-total ${variant}`.trim();
  }

  // -- Submission gate -------------------------------------------------------

  // The resale royalty in deci-percent, the unit the operative factory decodes
  // (90% is 900), so nothing converts between the number shown and the number
  // encoded. An empty field means the default rather than nothing: a creator
  // who cleared it has not thereby chosen to earn zero on every resale.
  const RESELLER_CUT_DEFAULT = 900;
  const RESELLER_CUT_MAX = 1000;

  // Asks the host which channels this creator may publish into, and what a
  // sale may be priced in.
  //
  // The host resolves the account itself, so this page never names one -- it
  // could only name the wrong one, and a list for the wrong account is a list
  // of channels the mint would refuse.
  async function loadChannels() {
    const response = await fetch("/api/creator/channels", {
      // The same launch token every other call from this page carries: the
      // capability comes from the token, never from the route.
      headers: { accept: "application/json", "x-elastos-home-token": homeToken },
    });
    if (!response.ok) {
      renderChannels("Channel list unavailable — type the address instead.");
      return;
    }
    const answer = await response.json();
    offeredChannels = Array.isArray(answer.channels) ? answer.channels : [];
    offeredPayTokens = Array.isArray(answer.payTokens) ? answer.payTokens : [];
    renderPayTokens();
    renderPools(mintPoolChoices(answer.pools));
    if (typeof answer.reason === "string" && answer.reason) {
      offerChannelRecheck();
      renderChannels(channelBlockerHint(answer.reason), "Not available yet");
      return;
    }
    if (answer.needsApproval) {
      els.channelApprove.classList.remove("hidden");
      renderChannels(
        "Allow the channel list to see the channels you can publish into, or type an address.",
        "Not available yet",
      );
      return;
    }
    if (answer.unavailable) {
      renderChannels(
        "Channel list unavailable — type the address instead.",
        "Unavailable",
      );
      return;
    }
    els.channelApprove.classList.add("hidden");
    renderChannels(
      answer.stale
        ? "Showing the last channel list this Home saw."
        : "Where this publishes.",
    );
  }

  // The approval button becomes the way back once there is something to do
  // elsewhere, so a creator never reloads the page to see whether it worked.
  function offerChannelRecheck() {
    els.channelApprove.classList.remove("hidden");
    els.channelApprove.textContent = "Check again";
    els.channelApprove.dataset.recheck = "true";
  }

  // `emptyLabel` is what the closed select reads when there is nothing to
  // offer. It matters: "No channels found" is a different statement from "the
  // list is not switched on", and only one of them is the creator's problem.
  function renderChannels(hint, emptyLabel = "No channels found") {
    const chosen = els.channel.value;
    els.channel.replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = offeredChannels.length
      ? "Choose a channel…"
      : emptyLabel;
    els.channel.append(placeholder);
    for (const channel of offeredChannels) {
      const option = document.createElement("option");
      option.value = channel.address;
      // The name is the directory's, the address is what is published into.
      // Both are shown so a creator can tell two similarly named channels
      // apart.
      option.textContent = channel.name
        ? `${channel.name} — ${shortAddress(channel.address)}`
        : channel.address;
      els.channel.append(option);
    }
    const manual = document.createElement("option");
    manual.value = MANUAL_CHANNEL_VALUE;
    manual.textContent = "Type an address…";
    els.channel.append(manual);
    // Keep a selection the creator already made across a refresh.
    if (chosen) {
      els.channel.value = chosen;
    }
    els.channelManual.classList.toggle(
      "hidden",
      els.channel.value !== MANUAL_CHANNEL_VALUE,
    );
    els.channelHint.textContent = hint;
    refreshSubmitEnabled();
  }

  // The currencies the host offers, in its order: the first is the default,
  // which is a product decision the host makes rather than this page.
  function renderPayTokens() {
    if (!offeredPayTokens.length) {
      // Nothing to price in, and nothing this page may invent: say so where
      // the creator is looking rather than refusing at the end.
      els.currency.replaceChildren();
      const none = document.createElement("option");
      none.value = "";
      none.textContent = "Unavailable";
      els.currency.append(none);
      refreshSubmitEnabled();
      return;
    }
    els.currency.replaceChildren();
    for (const token of offeredPayTokens) {
      const option = document.createElement("option");
      option.value = token.symbol;
      option.textContent = token.symbol;
      els.currency.append(option);
    }
    els.currency.value = offeredPayTokens[0].symbol;
    refreshSubmitEnabled();
  }

  // Plan B POOL-MINT: the pools this Home mints into. Shown only when there
  // is a choice to make; one pool needs no picker.
  function renderPools(pools) {
    if (!els.poolSelect || !els.poolRow) {
      return;
    }
    els.poolSelect.replaceChildren();
    for (const pool of pools) {
      const option = document.createElement("option");
      option.value = pool.poolDid;
      option.textContent = pool.label;
      els.poolSelect.append(option);
    }
    els.poolRow.classList.toggle("hidden", pools.length < 2);
  }

  function selectedPoolDid() {
    if (!els.poolSelect || els.poolRow?.classList.contains("hidden")) {
      return "";
    }
    return els.poolSelect.value || "";
  }

  function shortAddress(address) {
    return `${address.slice(0, 6)}…${address.slice(-4)}`;
  }

  // The channel this publishes into. The sentinel reveals a typed address,
  // which is the fallback for a channel the directory has not surfaced -- the
  // server verifies whatever is chosen either way.
  function selectedChannel() {
    const value = els.channel ? els.channel.value : "";
    if (value === MANUAL_CHANNEL_VALUE) {
      const typed = (els.channelManualInput.value || "").trim().toLowerCase();
      return EVM_ADDRESS_RE.test(typed) ? typed : "";
    }
    return EVM_ADDRESS_RE.test(value) ? value : "";
  }

  // The token a sale is priced in, and what its price means. Offered by the
  // host from configuration, so the form never invents a token the mint would
  // not settle in -- which is how a six-decimal price once reached an
  // eighteen-decimal mint.
  function selectedPayToken() {
    const selected = els.currency ? els.currency.value : "";
    const found = offeredPayTokens.find((token) => token.symbol === selected);
    return found || offeredPayTokens[0] || null;
  }

  function resellerCutDeciPercent() {
    const entered = parseFloat(els.resellerCut && els.resellerCut.value);
    if (!Number.isFinite(entered)) {
      return RESELLER_CUT_DEFAULT;
    }
    return Math.round(entered * 10);
  }

  // A cut larger than the whole sale is not a share, and the server refuses
  // it. Caught here so the creator sees the field rather than a failed mint.
  function validResellerCut() {
    if (accessMethod !== "buy_and_resell") {
      return true;
    }
    const cut = resellerCutDeciPercent();
    return cut >= 0 && cut <= RESELLER_CUT_MAX;
  }

  function validCopiesAndPrice() {
    // Nowhere to publish is not a mint. The server refuses one too, so this is
    // the form saying so first rather than the only thing saying so.
    const channel = selectedChannel();
    if (!channel) {
      return null;
    }
    // Until the host says what a sale may be priced in, there is no scale to
    // price in. Guessing one is how a six-decimal amount reached an
    // eighteen-decimal mint, so the form waits instead.
    const token = selectedPayToken();
    if (!token) {
      return null;
    }
    const chainTerms = { channel, payToken: token.address, poolDid: selectedPoolDid() };
    // A free mint sells nothing, so there is no supply to set and no price to
    // read: both are zero, and the chain call encodes neither.
    if (!isPaidMethod()) {
      return { copies: "0x0", price: "0", ...chainTerms };
    }
    try {
      const copies = decimalIntegerToHexQuantity(els.copiesInput.value);
      // Scaled only to CHECK it: an amount more precise than its token is
      // refused here so a creator sees it while typing rather than after
      // pressing Protect. The result is discarded -- what is sent is the
      // amount itself, and the host does the conversion that counts.
      scaleAmountToBaseUnits(els.priceInput.value, token.decimals, token.symbol);
      return { copies, price: els.priceInput.value.trim(), ...chainTerms };
    } catch {
      return null;
    }
  }

  function refreshSubmitEnabled() {
    const source = selectedFile || resumeTarget;
    els.submitButton.disabled =
      submitting ||
      !source ||
      !!fileTypeRefusal(source.name) ||
      listed ||
      !validResellerCut() ||
      !validCopiesAndPrice();
  }

  // -- Progress tracker -------------------------------------------------------
  //
  // One tracker, sequenced by content kind (see onFile's transcode toggle):
  //   media:     Analyze source -> Transcode & fragment -> Encrypt & escrow
  //              -> Store on your Home -> Assemble listing
  //   non-media: the same minus Transcode & fragment
  //
  // The upload is driven from here ("analyze"). Everything after it happens
  // inside one blocking request, so the rest is driven by what the server
  // says rather than by what this page can see: while the publish is in
  // flight `publish_progress` is polled on the side and reports escrow,
  // publish and listing straight from the mint journal; the response then
  // confirms all three at once.
  //
  // "transcode" still has no stage of its own on the server and does not need
  // one -- any progress at all implies fragmenting finished (see
  // applyServerProgress).

  function setStage(name, state) {
    if (state === "active") activeStageName = name;
    const li = els.progressSteps.querySelector(`li[data-stage="${name}"]`);
    if (li) li.className = state || "";
  }

  // Paint what the server's journal says, rather than what this page guessed.
  // "pending" leaves the dot untouched: a stage the server has not started is
  // not a stage this page should mark, and blanking it would undo "analyze",
  // which the server does not describe at all.
  function applyServerProgress(progress) {
    const mapped = stagesFromProgress(progress);
    if (!mapped.length) return;
    // "Transcode & fragment" has no stage of its own on the server, and it does
    // not need one: a mint record exists only once protection produced an
    // encrypted content identity, so the arrival of any progress at all is
    // itself the proof that fragmenting finished. That is why this row no
    // longer carries a "(not tracked)" note -- it is tracked, by implication
    // rather than by a field. Non-media never shows the row.
    setStage("transcode", "done");
    for (const stage of mapped) {
      if (stage.state === "pending") continue;
      setStage(stage.name, stage.state);
    }
  }

  function resetStages() {
    activeStageName = "";
    ["analyze", "transcode", "encrypt", "publish", "public_metadata", "assemble"].forEach((stage) =>
      setStage(stage, ""),
    );
  }

  function setStatus(text, kind) {
    els.statusText.textContent = text || "";
    els.statusText.className = `status${kind ? ` ${kind}` : ""}`;
  }

  async function protectAndList() {
    const source = selectedFile || resumeTarget;
    if (submitting || !source || fileTypeRefusal(source.name)) return;
    const terms = validCopiesAndPrice();
    if (!terms) return;
    submitting = true;
    refreshSubmitEnabled();
    setStatus("");
    clearFailureDetails();

    let targetUri = "";
    try {
      terms.listing = await collectListing();
      // "Analyze source" covers everything up to and including the upload:
      // this client did inspect the file (resolveMime/classifyProtection)
      // and transport it to Library storage.
      setStage("analyze", "active");
      if (selectedFile) {
        const roots = await providerApi("roots", {});
        const homeRoot = (roots.roots || []).find((root) => root.id === "home");
        if (!homeRoot) {
          throw new Error("Could not find your Library folder.");
        }
        targetUri = targetUriFor(homeRoot.uri, selectedFile.name);
        // Held so a recovery action can name the same object without
        // recomputing it from a file input the creator may have changed since.
        lastTargetUri = targetUri;
        const mime = resolveMime(selectedFile);
        const plan = uploadPlan(selectedFile.size);
        setStatus(
          plan.mode === "single"
            ? `Uploading ${selectedFile.name}...`
            : `Uploading ${selectedFile.name} in parts...`,
        );
        await uploadObject({ uri: targetUri, file: selectedFile, mime });
      } else {
        // A continued mint: its file is already in the Library.
        targetUri = resumeTarget.uri;
        lastTargetUri = targetUri;
      }
      // A freshly picked file is a new mint: the host sets any unfinished
      // attempt at it aside first. Everything after this first request --
      // polls, "Check again" -- continues the attempt it started.
      terms.newAttempt = Boolean(selectedFile);
      const continued = { ...terms, newAttempt: false };
      retryLast = () => publishWithProgress(targetUri, continued);
      setStage("analyze", "done");
    } catch (error) {
      submitting = false;
      refreshSubmitEnabled();
      throw error;
    }
    submitting = false;
    await publishWithProgress(targetUri, terms);
  }

  // Everything after the file is in the Library: the publish itself, with the
  // server's own account of how far it has got painted while it runs. Shared by
  // a fresh protect and a resume, which differ only in what the request says
  // about terms.
  async function publishWithProgress(targetUri, terms) {
    if (submitting) return;
    submitting = true;
    refreshSubmitEnabled();
    setStatus("");
    clearFailureDetails();
    try {
      // "Encrypt & escrow" starts active because at this instant it is: the
      // request has just been sent and escrow is the first thing the server
      // does. What it must not do is STAY active for the whole round trip.
      // Encryption and escrow take milliseconds; storing and verifying
      // the ciphertext take the rest, and a creator watching this page was
      // being told the wrong one was slow.
      //
      // The server has always known better -- it records custody as
      // provisioned before the publish begins -- but the publish is one
      // blocking request, so the page has to ask on the side. `publish_progress`
      // reads the mint journal and reports the same three stages the response
      // would, while the response is still outstanding.
      setStage("encrypt", "active");
      setStatus("Protecting and listing...");
      progressPoll = window.setInterval(() => {
        // Never allowed to disturb the publish: a failed poll means this tick
        // says nothing, not that the publish is in trouble. The next tick, or
        // the response itself, carries the truth.
        providerApi("publish_progress", { uri: targetUri })
          .then((data) => applyServerProgress(data?.progress))
          .catch(() => {});
      }, PENDING_POLL_INTERVAL_MS);
      const published = await publishUntilSettled(targetUri, terms);
      // A returned listing is the proof for all three server stages at once:
      // the escrow settled, the ciphertext is verifiably available, and the
      // listing projected. "publish" is no longer exempt from this.
      setStage("encrypt", "done");
      setStage("publish", "done");
      setStage("public_metadata", "done");
      setStage("assemble", "done");

      const mintId = published?.content_security?.mint_id || "";
      resumeTarget = null;
      showSuccess(mintId, settledFrom(published?.content_security));
    } finally {
      if (progressPoll !== null) {
        window.clearInterval(progressPoll);
        progressPoll = null;
      }
      submitting = false;
      refreshSubmitEnabled();
    }
  }

  // Resume a pending publish on its own instead of asking for another click.
  //
  // A publish that comes back pending is not finished and not failed: the
  // wallet approval or the chain evidence is still outstanding. The Creator
  // used to stop here and tell the creator to click "Protect and list" again,
  // which is work the page can do itself — and which read as a dead end,
  // because the same message appeared whether the creator had something to do
  // or not.
  //
  // So: poll the same publish. Say whose turn it is, from the server's typed
  // answer rather than from the prose. Stop at a bound rather than forever,
  // and when the bound is reached say plainly that the listing will finish on
  // its own and can be picked up by protecting the same file again — which is
  // true, because the mint keeps its identity across retries.
  async function publishUntilSettled(targetUri, terms) {
    let phase = null;
    let attempt = terms;
    for (;;) {
      try {
        return await publishWithRevisionRetry(targetUri, attempt);
      } catch (error) {
        // Only the first request starts a new mint; the rest continue it.
        attempt = { ...terms, newAttempt: false };
        const pending = error?.pending;
        if (!pending) {
          throw error;
        }
        // Before any decision about whether to keep asking. The answer carries
        // the journal's own account of how far this got, and that account is
        // true whether or not this page goes on polling -- showing a settled
        // escrow as still running, because the budget happened to be spent, is
        // how a finished stage came to look unfinished.
        applyServerProgress(error.progress);
        phase = pendingPhase(phase, pending, Date.now());
        if (phase.waitedMs >= pendingBudgetMs(phase)) {
          // Say what actually happened: this page stopped asking. The wait may
          // well be over by now, and claiming otherwise from a stale answer is
          // what told a creator to approve a transaction that had settled.
          error.pollingPaused = phase;
          throw error;
        }
        setStatus(pendingStatusText(pending, phase.waitedMs));
        await sleep(PENDING_POLL_INTERVAL_MS);
      }
    }
  }

  function pendingStatusText(pending, waitedMs) {
    const seconds = Math.round(waitedMs / 1000);
    const elapsed = seconds >= 5 ? ` (${seconds}s)` : "";
    if (pending.awaitsPerson) {
      const where = pending.connectorId || "your wallet";
      return `Waiting for you to approve this transaction in ${where}${elapsed}...`;
    }
    if (pending.reason === "chain_settlement") {
      return `Approved. Waiting for the network to confirm the transaction${elapsed}...`;
    }
    return `Completing the wallet approval${elapsed}...`;
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function publishWithRevisionRetry(targetUri, terms) {
    const stat = await providerApi("stat", { uri: targetUri });
    try {
      return await publishOnce(targetUri, stat.object?.revision, terms);
    } catch (error) {
      if (!/revision/i.test(String(error?.message || ""))) {
        throw error;
      }
      const freshStat = await providerApi("stat", { uri: targetUri });
      return await publishOnce(targetUri, freshStat.object?.revision, terms);
    }
  }

  async function publishOnce(targetUri, revision, terms) {
    const response = await providerApiEnvelope(
      "publish",
      terms.resume
        ? buildResumeBody({ uri: targetUri, ifRevision: revision })
        : buildPublishBody({
          uri: targetUri,
          ifRevision: revision,
          copies: terms.copies,
          price: terms.price,
          channel: terms.channel,
          payToken: terms.payToken,
          listing: terms.listing,
          newAttempt: terms.newAttempt,
          poolDid: terms.poolDid,
        }),
    );
    if (response.status === "error") {
      const message = response.message || "Protecting this file failed.";
      const error = new Error(message);
      // The actionable sentence the server puts beneath the stable one. Set
      // before any branch below returns, so every failure carries it.
      if (response.detail) {
        error.detail = String(response.detail);
      }
      // Typed refusals an app can act on rather than re-read.
      if (response.wallet_default) {
        error.walletDefault = response.wallet_default;
      }
      if (response.wallet_drift) {
        error.walletDrift = response.wallet_drift;
      }
      const attemptConflict = attemptConflictFrom(response);
      if (attemptConflict) {
        error.attemptConflict = attemptConflict;
      }
      // A mint already on record, with what this page may offer to do about it.
      const creatorMint = creatorMintFrom(response);
      if (creatorMint) {
        error.creatorMint = creatorMint;
      }
      // The public metadata stage refused before any approval was raised; its
      // progress names that stage as the failed one.
      const publicMetadata = publicMetadataFailure(response);
      if (publicMetadata) {
        error.publicMetadata = publicMetadata;
        error.progress = response.public_metadata.progress;
        if (!error.detail && response.public_metadata.detail) {
          error.detail = String(response.public_metadata.detail);
        }
      }
      // A closed approval is terminal, and deliberately NOT read as pending:
      // polling on it would wait out the whole budget for something that can
      // never complete.
      if (response.approval_closed) {
        error.approvalClosed = response.approval_closed;
        throw error;
      }
      const pending = effectPendingFrom(response);
      if (pending) {
        error.pending = pending;
        // Rides the pending answer, which is the poll response — see
        // RuntimeCustodyEffectPending's own note on why it is not a second
        // channel.
        error.progress = response.effect_pending.progress;
      }
      throw error;
    }
    return response.data || {};
  }

  // `settledBefore` means the server raised no effect and sent no transaction:
  // the mint was already terminal when this request arrived, and all that
  // happened was the listing being re-published from the existing record.
  //
  // Saying "Listed for sale" for that is what made a replay read as fresh
  // work. The listing IS live either way, so this is not an error -- but the
  // creator has to be able to tell the two apart, especially since a mint
  // keeps the account it started with and that account may no longer be the
  // one they would choose today.
  function showSuccess(mintId, settled) {
    listed = true;
    if (settled && settled.before) {
      setStatus("Already listed.", "ok");
      els.successTitle.textContent = "Already listed.";
      els.successDetail.textContent = settledDetail(settled);
      els.successDetail.hidden = false;
    } else {
      setStatus("Listed for sale.", "ok");
      els.successTitle.textContent = "Listed for sale.";
      els.successDetail.textContent = "";
      els.successDetail.hidden = true;
    }
    els.mintIdText.textContent = mintId ? `Listing ${mintId}` : "";
    els.successPanel.classList.remove("hidden");
    refreshSubmitEnabled();
  }

  // Seconds since the epoch, as the mint journal records it.
  function settledDetail(settled) {
    const when = Number(settled.at);
    const on = Number.isFinite(when) && when > 0
      ? ` on ${new Date(when * 1000).toLocaleString()}`
      : "";
    const tx = settled.transactionHash
      ? ` Transaction ${settled.transactionHash}.`
      : "";
    // A settled mint is never refused over a changed transaction default --
    // the chain effect is done -- so naming the account it minted on is the
    // only way a creator who has switched wallets since can see that this
    // listing is not on the account they would pick today.
    const seller = settled.sellerAddress
      ? ` It was minted on ${settled.sellerAddress}.`
      : "";
    return `This file was already minted${on}, so nothing new was sent to the chain.${seller}${tx}`;
  }


  // Reached only after the poll budget is spent, so this is "still waiting",
  // not "your turn and nobody told you". The Protect step stays in its
  // in-progress state and the file, copies and price stay in place, so
  // protecting the same file again picks the same mint back up — the mint
  // keeps its identity across retries, which is what makes that safe.
  function showPending(pending, error) {
    // This page stopped asking; that is not the same as the wait still being
    // on. The last answer is as old as the moment polling stopped, and stating
    // it as current is how a creator was told to approve a transaction that had
    // already settled on chain. Say what is actually known -- what it was
    // waiting for, and that checking paused -- and offer to look again.
    const paused = Boolean(error && error.pollingPaused);
    const where = pending && pending.connectorId ? pending.connectorId : "your wallet";
    const was =
      pending && pending.awaitsPerson
        ? `an approval in ${where}`
        : "the network to confirm the transaction";
    if (paused) {
      setStatus(
        `Checking paused. The last thing this was waiting for was ${was}; it may have finished since. Check again to pick up the same listing.`,
      );
    } else if (pending && pending.awaitsPerson) {
      setStatus(`Waiting for ${was}. The listing continues on its own once you approve it.`);
    } else {
      setStatus("The transaction is approved and the network has not confirmed it yet.");
    }
    clearFailureDetails();
    renderFailureDetails(error);
    renderResumeAction();
  }

  // Resuming is protecting the same file again, which picks the same mint back
  // up: the mint keeps its identity across retries, so this raises no second
  // effect and signs nothing new. That is what makes offering it safe, and it
  // is what the old message asked the creator to do by hand.
  function renderResumeAction() {
    const retry = retryLast;
    if (!retry) return;
    const resume = document.createElement("button");
    resume.className = "btn";
    resume.type = "button";
    resume.textContent = "Check again";
    resume.addEventListener("click", () => {
      resume.disabled = true;
      void Promise.resolve(retry())
        .catch((error) => {
          if (error?.pending) showPending(error.pending, error);
          else showFailure(error);
        })
        .finally(() => {
          resume.disabled = false;
        });
    });
    els.recoveryActions.append(resume);
    els.recoveryActions.classList.remove("hidden");
  }

  /**
   * Blame the stage that actually failed.
   *
   * This page drives one stage active -- "encrypt" -- for the whole
   * protect-and-list round trip, because from here that is a single request.
   * So `activeStageName` is only ever a guess, and for a listing failure it is
   * a wrong one: it painted "Encrypt & escrow" red for a mint whose escrow had
   * settled perfectly. When the server sends its progress with the refusal,
   * that guess is replaced by the journal's own account, and the failed stage
   * is the first one the server does not call done.
   */
  function failedStageFrom(progress) {
    const mapped = stagesFromProgress(progress);
    if (!mapped.length) return activeStageName;
    const explicit = mapped.find((stage) => stage.state === "err");
    if (explicit) return explicit.name;
    const unfinished = mapped.find((stage) => stage.state !== "done");
    return unfinished ? unfinished.name : activeStageName;
  }

  function clearFailureDetails() {
    els.failureDetailsList.replaceChildren();
    els.failureDetails.classList.add("hidden");
    els.failureDetails.open = false;
    els.recoveryActions.replaceChildren();
    els.recoveryActions.classList.add("hidden");
  }

  function renderFailureDetails(error) {
    const rows = failureDetailRows(error);
    if (!rows.length) return;
    for (const row of rows) {
      const term = document.createElement("dt");
      term.textContent = row.label;
      const description = document.createElement("dd");
      description.textContent = row.value;
      els.failureDetailsList.append(term, description);
    }
    els.failureDetails.classList.remove("hidden");
  }

  // Only offer what there is a working operation behind. A button that
  // explains itself and then does nothing is worse than no button, and the
  // three blocked states genuinely differ: one can be discarded, one is
  // waiting on an approval that is already out, and one is simply done.
  function renderRecoveryActions(error) {
    if (!lastTargetUri) return;
    const actions = recoveryActionsFor(error);
    // Nothing was raised for approval, so asking for the same publish again
    // is the way on.
    if (actions.includes("retry")) {
      renderResumeAction();
      return;
    }
    // The earlier attempt is the one that holds this file now, so the way on
    // is to finish it at its own terms rather than a dead end.
    if (actions.includes("resume")) {
      const targetUri = lastTargetUri;
      const name = resumeTarget?.name || selectedFile?.name || targetUri.split("/").pop();
      const resume = document.createElement("button");
      resume.className = "btn";
      resume.type = "button";
      resume.textContent = "Resume the earlier attempt";
      resume.addEventListener("click", () => {
        void resumeRecorded({ uri: targetUri, name });
      });
      els.recoveryActions.append(resume);
      els.recoveryActions.classList.remove("hidden");
    }
    // Whatever stopped this attempt, setting it aside and protecting again is
    // always open -- except for a mint that is already listed.
    if (!actions.includes("start_over")) return;
    const targetUri = lastTargetUri;
    const sourceFile = selectedFile;
    const discard = document.createElement("button");
    discard.className = "btn";
    discard.type = "button";
    discard.textContent = "Start over";
    discard.addEventListener("click", () => {
      void discardAndRetry(discard, targetUri, sourceFile);
    });
    els.recoveryActions.append(discard);
    els.recoveryActions.classList.remove("hidden");
  }

  async function discardAndRetry(button, targetUri, sourceFile) {
    if (submitting || button.disabled || selectedFile !== sourceFile || lastTargetUri !== targetUri) return;
    if (!validCopiesAndPrice()) {
      setStatus("Enter valid copies and a price before starting over.", "err");
      return;
    }
    submitting = true;
    button.disabled = true;
    refreshSubmitEnabled();
    try {
      setStatus("Setting the earlier attempt aside...");
      await discardProtectionAndRetry(targetUri, providerApi, async () => {
        clearFailureDetails();
        resetStages();
        // Hand the same operation guard to the retry before its first await.
        submitting = false;
        await protectAndList();
      });
    } catch (error) {
      if (error?.pending) showPending(error.pending, error);
      else showFailure(error);
    } finally {
      submitting = false;
      button.disabled = false;
      refreshSubmitEnabled();
    }
  }

  // Prefer the server's actionable sentence over its stable one: the stable
  // message is deliberately the same across many causes, so on its own it
  // tells the creator nothing they can act on. Everything else the server said
  // goes behind the disclosure rather than into the sentence.
  function showFailure(error) {
    // Paint how far it got before blaming a stage, so the stages that did
    // finish keep saying so.
    applyServerProgress(error?.progress);
    const failed = failedStageFrom(error?.progress);
    if (failed) setStage(failed, "err");
    const actionable = error?.detail || error?.message;
    setStatus(String(actionable || error || "Protecting this file failed."), "err");
    clearFailureDetails();
    renderFailureDetails(error);
    renderRecoveryActions(error);
  }

  function resetForAnotherFile() {
    if (submitting) return;
    selectedFile = null;
    resumeTarget = null;
    retryLast = null;
    listed = false;
    els.fileInput.value = "";
    els.dropTitle.textContent = "Choose a file";
    els.dropMetaText.textContent = "Any file · click or drop";
    els.dropBadge.textContent = "";
    els.dropBadge.classList.add("hidden");
    els.drop.classList.remove("over");

    els.title.value = "";
    els.desc.value = "";
    clearCustomThumbnail();
    els.category.value = "";

    accessMethod = "buy_once";
    syncMethodUI();

    els.copiesInput.value = "";
    els.priceInput.value = "";
    els.currency.value = "ELA";
    els.resellerCut.value = "90";
    seedDefaultRoyaltyRows();

    els.aiLicensing.checked = false;
    els.adultFlag.checked = false;
    els.legalAttest.checked = false;

    els.previewSettings.classList.add("hidden");
    els.previewControls.classList.add("hidden");
    els.previewEnabled.checked = false;
    els.previewDuration.value = "15";
    els.previewDurationDisplay.textContent = "15s";

    const transcodeStage = els.progressSteps.querySelector('li[data-stage="transcode"]');
    if (transcodeStage) transcodeStage.classList.add("hidden");

    els.successPanel.classList.add("hidden");
    lastTargetUri = "";
    clearFailureDetails();
    resetStages();
    setStatus("");
    refreshSubmitEnabled();
  }

  function openLibrary() {
    if (homeParentOrigin && window.top && window.top !== window) {
      window.top.postMessage({ type: "home:open-target", target: "library", homeToken }, homeParentOrigin);
    }
  }

  // -- Library upload transport, copied verbatim (see file header) --------

  async function providerApiEnvelope(op, payload) {
    const response = await fetch(`/api/provider/object/${encodeURIComponent(op)}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-elastos-home-token": homeToken,
      },
      body: JSON.stringify(payload || {}),
    });
    const envelope = await response.json().catch(() => ({}));
    if (!response.ok && envelope.status !== "error") {
      throw new Error(envelope.message || envelope.error || `Creator request failed: ${response.status}`);
    }
    return envelope;
  }

  async function providerApi(op, payload) {
    const envelope = await providerApiEnvelope(op, payload);
    if (envelope.status === "error") {
      throw new Error(envelope.message || "Runtime object provider failed.");
    }
    return envelope.data || envelope;
  }

  function uploadObject({ uri, file, mime }) {
    if (file?.size > CHUNKED_UPLOAD_THRESHOLD_BYTES) {
      return uploadObjectChunked({ uri, file, mime });
    }
    return uploadObjectRaw({ uri, file, mime });
  }

  function uploadObjectRaw({ uri, file, mime }) {
    return new Promise((resolve, reject) => {
      const url = new URL("/api/provider/object/upload", window.location.origin);
      url.searchParams.set("uri", uri);
      const xhr = new XMLHttpRequest();
      xhr.open("PUT", url.pathname + url.search);
      xhr.setRequestHeader("x-elastos-home-token", homeToken);
      xhr.setRequestHeader("content-type", mime || file?.type || "application/octet-stream");
      xhr.onerror = () => reject(new Error("Upload failed before Runtime accepted the object."));
      xhr.onload = () => {
        let envelope = {};
        try {
          envelope = JSON.parse(xhr.responseText || "{}");
        } catch {
          envelope = { message: xhr.responseText || "" };
        }
        if (xhr.status < 200 || xhr.status >= 300) {
          reject(new Error(uploadFailureMessage(xhr, envelope)));
          return;
        }
        if (envelope.status === "error") {
          reject(new Error(envelope.message || "Runtime object provider upload failed."));
          return;
        }
        resolve(envelope.data || envelope);
      };
      xhr.send(file);
    });
  }

  async function uploadObjectChunked({ uri, file, mime }) {
    const contentType = mime || file?.type || "application/octet-stream";
    const start = await uploadJsonRequest("/api/provider/object/upload/start", {
      uri,
      mime: contentType,
      size_bytes: file.size,
      transport: CHUNKED_UPLOAD_TRANSPORT,
    });
    const uploadId = start.upload_id;
    try {
      let offset = 0;
      while (offset < file.size) {
        const end = Math.min(offset + CHUNKED_UPLOAD_BYTES, file.size);
        const chunk = file.slice(offset, end, contentType);
        await uploadChunkRequest({ uploadId, offset, chunk, mime: contentType });
        offset = end;
      }
      return await uploadJsonRequest(`/api/provider/object/upload/${encodeURIComponent(uploadId)}/finish`, null);
    } catch (error) {
      // Library's copied transport cancels the upload session here, but the
      // DELETE upload route stays Library-only (Creator is not in its
      // allowlist, by design). A cancel call from Creator would only ever
      // 403, so Creator relies on Runtime's stale-session expiry instead.
      throw error;
    }
  }

  async function uploadJsonRequest(path, payload) {
    const response = await fetch(path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-elastos-home-token": homeToken,
      },
      body: payload ? JSON.stringify(payload) : undefined,
    });
    const text = await response.text();
    const envelope = parseEnvelope(text);
    if (!response.ok || envelope.status === "error") {
      throw new Error(uploadFailureMessage(responseLike(response, text), envelope));
    }
    return envelope.data || envelope;
  }

  function uploadChunkRequest({ uploadId, offset, chunk, mime }) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("PUT", `/api/provider/object/upload/${encodeURIComponent(uploadId)}/chunk`);
      xhr.setRequestHeader("x-elastos-home-token", homeToken);
      xhr.setRequestHeader("x-elastos-upload-offset", String(offset));
      xhr.setRequestHeader("content-type", mime || "application/octet-stream");
      xhr.onerror = () => reject(new Error("Upload chunk failed before Runtime accepted the object."));
      xhr.onload = () => {
        const envelope = parseEnvelope(xhr.responseText || "");
        if (xhr.status < 200 || xhr.status >= 300 || envelope.status === "error") {
          reject(new Error(uploadFailureMessage(xhr, envelope)));
          return;
        }
        resolve(envelope.data || envelope);
      };
      xhr.send(chunk);
    });
  }

  function parseEnvelope(text) {
    try {
      return JSON.parse(text || "{}");
    } catch {
      return { message: text || "" };
    }
  }

  function responseLike(response, text) {
    return { status: response.status, responseText: text };
  }

  function uploadFailureMessage(xhr, envelope) {
    const body = String(envelope.message || envelope.error || xhr.responseText || "");
    if (xhr.status === 413 || /request entity too large|nginx/i.test(body)) {
      return "This file is too large for the current upload service.";
    }
    return body || `Upload failed: ${xhr.status}`;
  }
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  bootCreatorApp();
}

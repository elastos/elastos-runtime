import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  buildPublishBody,
  mintPoolChoices,
  attemptConflictFrom,
  buildResumeBody,
  formatRecordedTerms,
  recoveryActionsFor,
  formTermsFrom,
  renderUnfinishedDialog,
  unfinishedDialogModel,
  unfinishedMintsFrom,
  channelBlockerHint,
  discardProtectionAndRetry,
  classifyProtection,
  decimalIntegerToHexQuantity,
  humanSize,
  effectPendingFrom,
  resolveMime,
  scalePriceToBaseUnits,
  creatorMintFrom,
  pendingBudgetMs,
  pendingPhase,
  failureDetailRows,
  fileTypeRefusal,
  RUNTIME_PROTECTABLE_EXTENSIONS,
  stagesFromProgress,
  settledFrom,
  summarizeRoyaltyRows,
  targetUriFor,
  uploadPlan,
} from "./creator.js";
import * as creator from "./creator.js";

test("targetUriFor builds a Creator-folder object URI", () => {
  assert.equal(
    targetUriFor("localhost://principal/did-key-abc", "clip.mp4"),
    "localhost://principal/did-key-abc/Creator/clip.mp4",
  );
});

test("targetUriFor strips a trailing slash from the root URI", () => {
  assert.equal(
    targetUriFor("localhost://principal/did-key-abc/", "clip.mp4"),
    "localhost://principal/did-key-abc/Creator/clip.mp4",
  );
});

test("targetUriFor rejects an empty file name", () => {
  assert.throws(() => targetUriFor("localhost://root", ""));
});

test("targetUriFor rejects a bare dot-dot file name", () => {
  assert.throws(() => targetUriFor("localhost://root", ".."));
});

test("targetUriFor rejects a file name containing a path traversal segment", () => {
  assert.throws(() => targetUriFor("localhost://root", "../secret.txt"));
});

test("targetUriFor rejects a file name containing a path separator", () => {
  assert.throws(() => targetUriFor("localhost://root", "a/b.txt"));
});

test("targetUriFor rejects a file name containing a control character", () => {
  const newline = String.fromCharCode(10);
  const nul = String.fromCharCode(0);
  const del = String.fromCharCode(127);
  assert.throws(() => targetUriFor("localhost://root", `clip${newline}name.mp4`));
  assert.throws(() => targetUriFor("localhost://root", `clip${nul}name.mp4`));
  assert.throws(() => targetUriFor("localhost://root", `clip${del}name.mp4`));
});

test("classifyProtection treats video as media", () => {
  assert.equal(classifyProtection("video/mp4"), "media");
});

test("classifyProtection treats audio as media", () => {
  assert.equal(classifyProtection("audio/mpeg"), "media");
});

test("classifyProtection treats everything else as object", () => {
  assert.equal(classifyProtection("application/pdf"), "object");
  assert.equal(classifyProtection(""), "object");
  assert.equal(classifyProtection(undefined), "object");
});

test("decimalIntegerToHexQuantity converts a positive decimal integer to hex", () => {
  assert.equal(decimalIntegerToHexQuantity("1"), "0x1");
  assert.equal(decimalIntegerToHexQuantity("255"), "0xff");
});

test("decimalIntegerToHexQuantity rejects zero", () => {
  assert.throws(() => decimalIntegerToHexQuantity("0"));
});

test("decimalIntegerToHexQuantity rejects a non-numeric value", () => {
  assert.throws(() => decimalIntegerToHexQuantity("abc"));
  assert.throws(() => decimalIntegerToHexQuantity("1.5"));
  assert.throws(() => decimalIntegerToHexQuantity("-1"));
});

test("decimalIntegerToHexQuantity rejects a value above uint256 max", () => {
  const tooLarge = (1n << 256n).toString(10);
  assert.throws(() => decimalIntegerToHexQuantity(tooLarge));
});

test("uploadPlan chooses a single request at or under the threshold", () => {
  assert.deepEqual(uploadPlan(0), { mode: "single" });
  assert.deepEqual(uploadPlan(512 * 1024), { mode: "single" });
});

test("uploadPlan chooses chunked upload above the threshold", () => {
  assert.deepEqual(uploadPlan(512 * 1024 + 1), { mode: "chunked" });
});

test("effectPendingFrom reads an external approval that is waiting on the person", () => {
  const pending = effectPendingFrom({
    status: "error",
    message: "Runtime custody creator mint is pending exact Wallet or Chain settlement",
    effect_pending: {
      schema: "elastos.protected-content.effect-pending/v1",
      reason: "wallet_approval",
      awaits_person: true,
      external_signer: true,
      connector_id: "metamask",
    },
  });
  assert.deepEqual(pending, {
    reason: "wallet_approval",
    awaitsPerson: true,
    connectorId: "metamask",
  });
});

test("effectPendingFrom reads a chain wait as needing nobody", () => {
  // The distinction that matters: this one must never tell the creator to go
  // and approve something. It is already approved.
  const pending = effectPendingFrom({
    status: "error",
    message: "Runtime custody creator mint is pending exact Wallet or Chain settlement",
    effect_pending: {
      schema: "elastos.protected-content.effect-pending/v1",
      reason: "chain_settlement",
      awaits_person: false,
    },
  });
  assert.equal(pending.reason, "chain_settlement");
  assert.equal(pending.awaitsPerson, false);
  assert.equal(pending.connectorId, "");
});

test("effectPendingFrom treats a managed approval as needing nobody", () => {
  const pending = effectPendingFrom({
    effect_pending: {
      reason: "wallet_approval",
      awaits_person: false,
      external_signer: false,
      connector_id: null,
    },
  });
  assert.equal(pending.awaitsPerson, false);
  assert.equal(pending.connectorId, "");
});

test("effectPendingFrom treats an unrelated failure, and any older server, as not pending", () => {
  // A real failure carries no waiting state.
  assert.equal(
    effectPendingFrom({
      status: "error",
      message: "Runtime custody media preparation provider is unavailable",
    }),
    null,
  );
  // Absence must mean "not pending", never "unknown": an older server sends no
  // effect_pending at all, and treating that as pending would spin forever.
  assert.equal(effectPendingFrom({}), null);
  assert.equal(effectPendingFrom(undefined), null);
  assert.equal(effectPendingFrom(null), null);
  // Only a real object counts; the old detector matched a bare word anywhere
  // in the prose, which is exactly what this replaces.
  assert.equal(effectPendingFrom({ effect_pending: "pending" }), null);
  assert.equal(effectPendingFrom({ message: "something pending happened" }), null);
});

test("humanSize renders sub-kilobyte counts in bytes", () => {
  assert.equal(humanSize(0), "0 B");
  assert.equal(humanSize(1023), "1023 B");
});

test("humanSize renders sub-megabyte counts in kilobytes", () => {
  assert.equal(humanSize(1024), "1.0 KB");
  assert.equal(humanSize(1024 * 1024 - 1), "1024.0 KB");
});

test("humanSize renders megabyte-and-above counts in megabytes", () => {
  assert.equal(humanSize(1024 * 1024), "1.0 MB");
  assert.equal(humanSize(5 * 1024 * 1024), "5.0 MB");
});

test("humanSize treats a non-numeric size as zero", () => {
  assert.equal(humanSize(undefined), "0 B");
  assert.equal(humanSize(null), "0 B");
  assert.equal(humanSize("not a number"), "0 B");
});

test("resolveMime trusts the extension map for types browsers report unreliably", () => {
  assert.equal(resolveMime({ name: "book.epub", type: "" }), "application/epub+zip");
  assert.equal(resolveMime({ name: "comic.cbz", type: "application/zip" }), "application/vnd.comicbook+zip");
  assert.equal(resolveMime({ name: "model.glb", type: "" }), "model/gltf-binary");
  assert.equal(resolveMime({ name: "notes.md", type: "" }), "text/markdown");
});

test("resolveMime falls back to the browser-reported type for unmapped extensions", () => {
  assert.equal(resolveMime({ name: "clip.mp4", type: "video/mp4" }), "video/mp4");
});

test("resolveMime falls back to octet-stream when nothing else is known", () => {
  assert.equal(resolveMime({ name: "mystery", type: "" }), "application/octet-stream");
  assert.equal(resolveMime({ name: "", type: "" }), "application/octet-stream");
  assert.equal(resolveMime(undefined), "application/octet-stream");
});

const UNSUPPORTED_TYPE_COPY =
  "This file type cannot be protected yet. Use an image (PNG, JPG, GIF), a PDF, or a video.";

test("fileTypeRefusal refuses a .webp pick before anything is uploaded", () => {
  assert.equal(fileTypeRefusal("cover.webp"), UNSUPPORTED_TYPE_COPY);
});

test("fileTypeRefusal allows the types Runtime can protect", () => {
  assert.equal(fileTypeRefusal("photo.png"), "");
  assert.equal(fileTypeRefusal("clip.mp4"), "");
  assert.equal(fileTypeRefusal("paper.pdf"), "");
  assert.equal(fileTypeRefusal("song.mp3"), "");
});

test("fileTypeRefusal reads the extension case-insensitively, as Runtime does", () => {
  assert.equal(fileTypeRefusal("PHOTO.PNG"), "");
  assert.equal(fileTypeRefusal("Clip.Mp4"), "");
  assert.equal(fileTypeRefusal("COVER.WEBP"), UNSUPPORTED_TYPE_COPY);
});

test("fileTypeRefusal refuses a name Runtime cannot type", () => {
  assert.equal(fileTypeRefusal("mystery"), UNSUPPORTED_TYPE_COPY);
  assert.equal(fileTypeRefusal("book.epub"), UNSUPPORTED_TYPE_COPY);
  assert.equal(fileTypeRefusal("archive.gz"), UNSUPPORTED_TYPE_COPY);
  assert.equal(fileTypeRefusal(""), UNSUPPORTED_TYPE_COPY);
  assert.equal(fileTypeRefusal(undefined), UNSUPPORTED_TYPE_COPY);
});

test("fileTypeRefusal knows Runtime's two-part archive suffix", () => {
  assert.equal(fileTypeRefusal("backup.tar.gz"), "");
  assert.equal(fileTypeRefusal("BACKUP.TGZ"), "");
});

// The extension set is a copy of Runtime's `mime_for_name` table, which
// decides the type the publish refusal tests. Read the table itself so the
// copy cannot drift from it unnoticed.
test("RUNTIME_PROTECTABLE_EXTENSIONS matches Runtime's mime_for_name table", () => {
  const source = readFileSync(
    new URL("../../../elastos/crates/elastos-server/src/library.rs", import.meta.url),
    "utf8",
  );
  const start = source.indexOf("fn mime_for_name(");
  const end = source.indexOf('_ => "application/octet-stream"', start);
  assert.ok(start >= 0 && end > start, "mime_for_name's match table is where this test expects it");
  const known = new Set();
  for (const line of source.slice(start, end).split("\n")) {
    const arm = line.match(/^\s*("[^"]+"(?:\s*\|\s*"[^"]+")*)\s*=>/);
    if (!arm) continue;
    for (const [, extension] of arm[1].matchAll(/"([^"]+)"/g)) known.add(extension);
  }
  assert.ok(known.has("png") && known.has("mp4"), "the table parsed");
  assert.deepEqual([...RUNTIME_PROTECTABLE_EXTENSIONS].sort(), [...known].sort());
});

test("summarizeRoyaltyRows reports ok when rows total exactly 100% (the chain's real default split)", () => {
  const result = summarizeRoyaltyRows([{ royalty: 95 }, { royalty: 5 }]);
  assert.equal(result.sum, 100);
  assert.equal(result.target, 100);
  assert.equal(result.ok, true);
  assert.equal(result.overLimit, false);
});

test("summarizeRoyaltyRows reports not-ok (but not overLimit) when the total is under 100%", () => {
  const result = summarizeRoyaltyRows([{ royalty: 50 }]);
  assert.equal(result.sum, 50);
  assert.equal(result.ok, false);
  assert.equal(result.overLimit, false);
});

test("summarizeRoyaltyRows flags overLimit distinctly when the total exceeds 100%", () => {
  const result = summarizeRoyaltyRows([{ royalty: 95 }, { royalty: 10 }]);
  assert.equal(result.sum, 105);
  assert.equal(result.ok, false);
  assert.equal(result.overLimit, true);
});

test("summarizeRoyaltyRows treats an empty or missing row list as a zero sum", () => {
  assert.equal(summarizeRoyaltyRows([]).sum, 0);
  assert.equal(summarizeRoyaltyRows(undefined).sum, 0);
  assert.equal(summarizeRoyaltyRows([{ royalty: "not a number" }]).sum, 0);
});

test("scalePriceToBaseUnits scales a whole amount at 18 decimals (ETH, ELA)", () => {
  assert.equal(scalePriceToBaseUnits("1", "ETH"), "1000000000000000000");
  assert.equal(scalePriceToBaseUnits("1", "ELA"), "1000000000000000000");
});

test("scalePriceToBaseUnits scales a fractional amount at 18 decimals", () => {
  assert.equal(scalePriceToBaseUnits("0.001", "ETH"), "1000000000000000");
});

test("scalePriceToBaseUnits scales a whole and a fractional amount at 6 decimals (USDC)", () => {
  assert.equal(scalePriceToBaseUnits("100", "USDC"), "100000000");
  assert.equal(scalePriceToBaseUnits("1.5", "USDC"), "1500000");
});

test("scalePriceToBaseUnits accepts exactly the currency's maximum fractional digits", () => {
  assert.equal(scalePriceToBaseUnits("0.123456", "USDC"), "123456");
  assert.equal(scalePriceToBaseUnits("0.123456789012345678", "ETH"), "123456789012345678");
});

test("scalePriceToBaseUnits rejects more fractional digits than the currency allows", () => {
  assert.throws(() => scalePriceToBaseUnits("0.1234567", "USDC"));
  assert.throws(() => scalePriceToBaseUnits("0.1234567890123456789", "ETH"));
});

test("scalePriceToBaseUnits rejects zero, however it is spelled", () => {
  assert.throws(() => scalePriceToBaseUnits("0", "ETH"));
  assert.throws(() => scalePriceToBaseUnits("0.000000000000000000", "ETH"));
});

test("scalePriceToBaseUnits does not lose precision on a large 18-decimal amount (no float path)", () => {
  // Number("12345678.123456789012345678") already rounds in an IEEE-754
  // double well before the 18th fractional digit; the string/BigInt path
  // must return the exact integer.
  assert.equal(
    scalePriceToBaseUnits("12345678.123456789012345678", "ETH"),
    "12345678123456789012345678",
  );
});

test("scalePriceToBaseUnits rejects an unknown currency", () => {
  assert.throws(() => scalePriceToBaseUnits("1", "DOGE"));
});

test("scalePriceToBaseUnits rejects non-numeric or negative input", () => {
  assert.throws(() => scalePriceToBaseUnits("abc", "ETH"));
  assert.throws(() => scalePriceToBaseUnits("-1", "ETH"));
  assert.throws(() => scalePriceToBaseUnits("", "ETH"));
});

test("buildPublishBody carries exactly uri, if_revision, and protection", () => {
  const body = buildPublishBody({ uri: "localhost://root/Creator/clip.mp4", ifRevision: 3, copies: "0x1", price: "1" });
  assert.deepEqual(Object.keys(body).sort(), ["if_revision", "protection", "uri"]);
  assert.equal(body.uri, "localhost://root/Creator/clip.mp4");
  assert.equal(body.if_revision, 3);
});

// The protection block is the mint's own terms: what is sold, where it
// settles, and in what. The pay token is the one optional member -- omitted
// means the mint source's first offered token.
//
// `price` is the amount as typed, NOT base units. The host scales it by the
// chosen token's decimals, which is the only place they are stated, so this
// page has no scale to declare and none to get wrong: 0.11 USDC scaled here
// as an eighteen-decimal amount is exactly how a sale was once listed a
// million-fold under its intended price.
test("buildPublishBody's protection block carries the mint's terms", () => {
  const body = buildPublishBody({
    uri: "localhost://root/Creator/clip.mp4",
    ifRevision: 3,
    copies: "0x1",
    price: "1",
    channel: "0x0ebac909d31ef0074495e752c0cf4ea49ba13c41",
  });
  assert.deepEqual(Object.keys(body.protection).sort(), [
    "channel",
    "copies",
    "mode",
    "price",
  ]);
  assert.equal(body.protection.mode, "runtime_custody");
  assert.equal(body.protection.copies, "0x1");
  assert.equal(body.protection.price, "1");
  assert.equal(body.protection.channel, "0x0ebac909d31ef0074495e752c0cf4ea49ba13c41");
});

test("buildPublishBody names a pay token only when one was chosen", () => {
  const withToken = buildPublishBody({
    uri: "localhost://root/Creator/clip.mp4",
    ifRevision: 3,
    copies: "0x1",
    price: "0x1",
    channel: "0x0ebac909d31ef0074495e752c0cf4ea49ba13c41",
    payToken: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
  });
  assert.equal(
    withToken.protection.pay_token,
    "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
  );
});

test("buildPublishBody never carries unwired form state (title, category, royalties, ...)", () => {
  const body = buildPublishBody({
    uri: "localhost://root/Creator/clip.mp4",
    ifRevision: 1,
    copies: "0x1",
    price: "0x1",
    // Extra keys a careless caller might pass through from form state must
    // never appear in the built body — buildPublishBody only reads the four
    // named parameters above.
    title: "My asset",
    description: "What is it?",
    category: "video",
    thumbnailB64: "not-actually-sent",
    royalties: [{ address: "0xabc", royalty: 50 }],
    isAdult: true,
  });
  assert.deepEqual(Object.keys(body).sort(), ["if_revision", "protection", "uri"]);
  assert.deepEqual(Object.keys(body.protection).sort(), [
    "channel",
    "copies",
    "mode",
    "price",
  ]);
});

// A mint that was already terminal when the request arrived raised no effect
// and sent no transaction. Reporting that as "Listed for sale" is what made a
// replay read as fresh work, so the marker has to survive the trip intact.
test("settledFrom reports a mint that was already settled before this request", () => {
  const settled = settledFrom({
    schema: "elastos.library.published-content-security/v1",
    mint_id: "620b246a",
    settled_before_this_request: true,
    settled_at: 1789479788,
    transaction_hash: "0x0994b5af",
    settled_seller_address: "0x7ba979fa244b930c01bdc84de851e5bca64b9f81",
  });
  assert.deepEqual(settled, {
    before: true,
    at: 1789479788,
    transactionHash: "0x0994b5af",
    sellerAddress: "0x7ba979fa244b930c01bdc84de851e5bca64b9f81",
  });
});

test("settledFrom treats a fresh mint, and any server without the marker, as fresh", () => {
  // A fresh mint: the server omits the marker entirely.
  assert.equal(settledFrom({ mint_id: "620b246a" }), null);
  // Absent content_security at all.
  assert.equal(settledFrom(undefined), null);
  assert.equal(settledFrom(null), null);
  // Only the exact boolean true counts. Anything else is not a claim that the
  // mint predates this request, and must not suppress the fresh-mint report.
  assert.equal(settledFrom({ settled_before_this_request: false }), null);
  assert.equal(settledFrom({ settled_before_this_request: "true" }), null);
  assert.equal(settledFrom({ settled_before_this_request: 1 }), null);
});

test("settledFrom tolerates a settled mint with no transaction hash", () => {
  const settled = settledFrom({
    settled_before_this_request: true,
    settled_at: 1789479788,
  });
  assert.equal(settled.before, true);
  assert.equal(settled.transactionHash, "");
  assert.equal(settled.sellerAddress, "");
});

// The publish stage used to be a dot labelled "(not tracked)" while the two
// around it went green — the client had no way to know, because the whole
// server pipeline ran inside one request. It is journal-derived now.
test("stagesFromProgress maps the server's phases onto this page's stages", () => {
  const mapped = stagesFromProgress({
    schema: "elastos.protected-content.creator-progress/v1",
    stages: [
      { id: "escrow", state: "done" },
      { id: "publish", state: "done" },
      { id: "listing", state: "active" },
    ],
  });
  assert.deepEqual(mapped, [
    { name: "encrypt", state: "done" },
    { name: "publish", state: "done" },
    { name: "assemble", state: "active" },
  ]);
});

test("stagesFromProgress ignores a phase this page does not render", () => {
  // A server that grows a phase must degrade to one stage fewer, never throw
  // and never invent a name for it.
  const mapped = stagesFromProgress({
    stages: [
      { id: "escrow", state: "active" },
      { id: "some-future-phase", state: "done" },
    ],
  });
  assert.deepEqual(mapped, [{ name: "encrypt", state: "active" }]);
});

test("stagesFromProgress tolerates a missing or malformed progress block", () => {
  // Absent on every server that predates it, so this must be empty rather
  // than an error.
  assert.deepEqual(stagesFromProgress(undefined), []);
  assert.deepEqual(stagesFromProgress(null), []);
  assert.deepEqual(stagesFromProgress({}), []);
  assert.deepEqual(stagesFromProgress({ stages: "escrow" }), []);
  assert.deepEqual(stagesFromProgress({ stages: [null, {}, { state: "done" }] }), []);
});

// The listing block is what turns a completed mint into a listing a
// marketplace can show. Absent it, the mint still works and publishes no
// Elacity folder — which is why absence has to be distinguishable from a
// listing whose fields are blank.
test("buildPublishBody carries listing terms when given", () => {
  const body = buildPublishBody({
    uri: "localhost://root/Creator/clip.png",
    ifRevision: 1,
    copies: "0x1",
    price: "0x1",
    listing: {
      title: "My asset",
      description: "What it is",
      category: "art",
      tags: [],
      adult: false,
      licensing: { ai_training: true },
      legal_attestation: { owns_distribution_rights: true },
    },
  });
  assert.deepEqual(Object.keys(body.protection).sort(), [
    "channel",
    "copies",
    "listing",
    "mode",
    "price",
  ]);
  assert.equal(body.protection.listing.title, "My asset");
  assert.equal(body.protection.listing.licensing.ai_training, true);
});

test("buildPublishBody omits the listing entirely when there is none", () => {
  const body = buildPublishBody({
    uri: "localhost://root/Creator/clip.png",
    ifRevision: 1,
    copies: "0x1",
    price: "0x1",
  });
  assert.deepEqual(Object.keys(body.protection).sort(), [
    "channel",
    "copies",
    "mode",
    "price",
  ]);
  assert.equal("listing" in body.protection, false);
});

// A royalty split reaches the server as ERC-1155 ROYALTY_SHARE units, which is
// the chain's own denomination: 1 unit = 0.1%, the creator's share is 950, and
// the protocol's 50 are minted by the contract and never sent as a payee.
test("buildPublishBody carries a royalty split in chain units", () => {
  const body = buildPublishBody({
    uri: "localhost://root/Creator/clip.png",
    ifRevision: 1,
    copies: "0x1",
    price: "0x1",
    listing: {
      title: "My asset",
      royalties: [
        { address: "0xab5028bdbb0826ad6f1885478e421db677b0001a", units: 900 },
        { address: "0x7ba979fa244b930c01bdc84de851e5bca64b9f81", units: 50 },
      ],
    },
  });
  const total = body.protection.listing.royalties.reduce((sum, row) => sum + row.units, 0);
  assert.equal(total, 950, "a split must come to the creator share exactly");
});

test("stagesFromProgress carries a failed stage across as the error class", () => {
  // The server gained "failed" when an aborted custody terminal stopped being
  // read as success. Without a mapping it would reach className verbatim and
  // render as nothing at all, which is how a dead mint looked fine.
  const mapped = stagesFromProgress({
    stages: [
      { id: "escrow", state: "failed" },
      { id: "publish", state: "pending" },
      { id: "listing", state: "pending" },
    ],
  });
  assert.deepEqual(mapped, [
    { name: "encrypt", state: "err" },
    { name: "publish", state: "pending" },
    { name: "assemble", state: "pending" },
  ]);
});

test("stagesFromProgress drops a state this page cannot draw", () => {
  const mapped = stagesFromProgress({
    stages: [
      { id: "escrow", state: "done" },
      { id: "publish", state: "quantum" },
    ],
  });
  assert.deepEqual(mapped, [{ name: "encrypt", state: "done" }]);
});

test("creatorMintFrom reads the typed refusal, not the sentence", () => {
  assert.deepEqual(
    creatorMintFrom({
      status: "error",
      message: "An earlier attempt to protect this file is still on record at different terms",
      creator_mint: {
        schema: "elastos.protected-content.creator-mint-blocked/v1",
        state: "recorded_only",
        mint_id: "ab12",
        recorded_copies: "3",
        recorded_price: "0.001",
        can_start_over: false,
        can_resume: true,
      },
    }),
    {
      state: "recorded_only",
      mintId: "ab12",
      recordedCopies: "3",
      recordedPrice: "0.001",
      canStartOver: false,
      canResume: true,
      stage: "",
      differingTerms: [],
    },
  );
});

test("creatorMintFrom names the terms that differ and how far the recorded attempt got", () => {
  const mint = creatorMintFrom({
    status: "error",
    creator_mint: {
      state: "approval_outstanding",
      stage: "approval_pending",
      differing_terms: ["price", "channel", 7],
      can_resume: true,
    },
  });
  assert.equal(mint.stage, "approval_pending");
  assert.deepEqual(mint.differingTerms, ["price", "channel"]);
  assert.equal(mint.canResume, true);
  const rows = failureDetailRows({ message: "refused", creatorMint: mint });
  assert.deepEqual(
    rows.find((row) => row.label === "Differs in"),
    { label: "Differs in", value: "price, channel" },
  );
});

test("creatorMintFrom returns null when the server sent no such refusal", () => {
  assert.equal(creatorMintFrom({ status: "error", message: "nope" }), null);
  assert.equal(creatorMintFrom(null), null);
});

test("failureDetailRows breaks a failure down from typed fields only", () => {
  const rows = failureDetailRows({
    message: "Runtime custody creator mint is unavailable",
    detail: "Discard the recorded terms to start over.",
    progress: {
      stages: [
        { id: "escrow", state: "done" },
        { id: "publish", state: "done" },
        { id: "listing", state: "failed" },
      ],
    },
    creatorMint: {
      state: "recorded_only",
      mintId: "ab12",
      recordedCopies: "3",
      recordedPrice: "0.001",
      canStartOver: false,
      canResume: true,
    },
  });
  assert.deepEqual(rows, [
    { label: "Reported", value: "Runtime custody creator mint is unavailable" },
    { label: "Cause", value: "Discard the recorded terms to start over." },
    {
      label: "Progress",
      value: "Encrypt & escrow: done, Store on your Home: done, Assemble listing: failed",
    },
    { label: "Existing attempt", value: "terms recorded, nothing sent to the chain" },
    { label: "Its listing id", value: "ab12" },
    { label: "Its recorded terms", value: "3 copies at 0.001" },
  ]);
});

test("failureDetailRows does not repeat the stable message as its own cause", () => {
  const rows = failureDetailRows({
    message: "Protecting this file failed.",
    detail: "Protecting this file failed.",
  });
  assert.deepEqual(rows, [{ label: "Reported", value: "Protecting this file failed." }]);
});

test("failureDetailRows names what a wait is waiting for", () => {
  assert.deepEqual(
    failureDetailRows({
      message: "pending",
      pending: { reason: "wallet_approval", awaitsPerson: true, connectorId: "metamask" },
    }),
    [
      { label: "Reported", value: "pending" },
      { label: "Waiting for", value: "a wallet approval in metamask" },
    ],
  );
  assert.deepEqual(
    failureDetailRows({
      message: "pending",
      pending: { reason: "chain_settlement", awaitsPerson: false, connectorId: "" },
    }),
    [
      { label: "Reported", value: "pending" },
      { label: "Waiting for", value: "the network to confirm the transaction" },
    ],
  );
});

test("failureDetailRows omits a field the server did not send", () => {
  assert.deepEqual(failureDetailRows({}), []);
  assert.deepEqual(failureDetailRows(null), []);
});


test("discard retries only after a receipt for the selected source", async () => {
  const calls = [];
  await discardProtectionAndRetry("localhost://owner/Creator/a.txt", async (op, body) => {
    calls.push([op, body]);
    return { schema: "elastos.library.protection-discarded/v1", uri: body.uri, discarded: true };
  }, async () => calls.push("retry"));
  assert.deepEqual(calls, [["discard_protection", { uri: "localhost://owner/Creator/a.txt" }], "retry"]);
});

test("discard refusal and malformed receipts never retry", async () => {
  let retries = 0;
  const retry = async () => { retries += 1; };
  await assert.rejects(discardProtectionAndRetry("source", async () => { throw new Error("approval outstanding"); }, retry), /approval outstanding/);
  for (const receipt of [{}, { schema: "elastos.library.protection-discarded/v1", uri: "other", discarded: true }, { schema: "elastos.library.protection-discarded/v1", uri: "source" }]) {
    await assert.rejects(discardProtectionAndRetry("source", async () => receipt, retry), /confirm/);
  }
  assert.equal(retries, 0);
});

test("already discarded receipt safely permits retry", async () => {
  let retried = false;
  await discardProtectionAndRetry("source", async () => ({ schema: "elastos.library.protection-discarded/v1", uri: "source", discarded: false }), async () => { retried = true; });
  assert.equal(retried, true);
});

// Acceptance case: a publish that takes longer than the approval budget, then a
// first approval-pending answer. The wait for the person must still get its own
// budget -- this is the defect that told a creator to approve a transaction
// which had already settled on Base.
test("a long publish does not spend the approval budget before approval begins", () => {
  const person = { awaitsPerson: true, reason: "wallet_approval", connectorId: "metamask" };
  // 310s of encrypting, uploading and pinning happened before this answer.
  const first = pendingPhase(null, person, 310_000);
  assert.equal(first.reason, "person");
  assert.equal(first.waitedMs, 0, "the approval wait starts when approval starts");
  assert.ok(first.waitedMs < pendingBudgetMs(first), "polling must not be over before it begins");
});

test("pendingPhase accumulates only the time spent in the same wait", () => {
  const person = { awaitsPerson: true };
  const first = pendingPhase(null, person, 1_000);
  const later = pendingPhase(first, person, 4_000);
  assert.equal(later.startedAt, first.startedAt);
  assert.equal(later.waitedMs, 3_000);
});

// Acceptance case: the person-to-chain transition.
test("crossing from waiting on a person to waiting on the chain starts a fresh clock", () => {
  const person = { awaitsPerson: true };
  const chain = { awaitsPerson: false, reason: "chain_settlement" };
  const waited = pendingPhase(pendingPhase(null, person, 0), person, 290_000);
  assert.equal(waited.waitedMs, 290_000, "nearly the whole person budget is spent");

  const crossed = pendingPhase(waited, chain, 290_000);
  assert.equal(crossed.reason, "chain");
  assert.equal(crossed.waitedMs, 0, "the chain wait does not inherit the person's spent time");
  assert.ok(crossed.waitedMs < pendingBudgetMs(crossed));
});

test("each wait has its own budget", () => {
  assert.equal(pendingBudgetMs({ reason: "person" }), 5 * 60 * 1000);
  assert.equal(pendingBudgetMs({ reason: "chain" }), 2 * 60 * 1000);
});

test("a wait that really does exceed its own budget still stops", () => {
  const person = { awaitsPerson: true };
  const started = pendingPhase(null, person, 0);
  const expired = pendingPhase(started, person, 5 * 60 * 1000);
  assert.ok(expired.waitedMs >= pendingBudgetMs(expired));
});

// A price is an integer of some token's smallest unit, and which token decides
// what that integer means. Scaling for a six-decimal token while the mint
// settles in an eighteen-decimal one agrees on the digits and disagrees by a
// factor of a million: a 0.11 USDC listing settled as 110000 wei, which is
// about a ten-trillionth of the intended price.
//
// So the scale travels with the price and the host refuses a mismatch. These
// pin the page's half of that.
test("the publish body states the scale the price was expressed in", () => {
  const body = buildPublishBody({
    uri: "localhost://Local/Home/Files/clip.mp4",
    ifRevision: 3,
    copies: "0xa",
    price: "0x186a0",
    listing: { title: "A clip" },
  });
  assert.equal(body.protection.listing.title, "A clip");
});

test("a six-decimal amount and an eighteen-decimal one are not the same price", () => {
  // The exact confusion that produced the bad listing: same human amount,
  // integers a million apart.
  assert.equal(scalePriceToBaseUnits("0.11", "USDC"), "110000");
  assert.equal(scalePriceToBaseUnits("0.11", "ETH"), "110000000000000000");
  assert.notEqual(
    scalePriceToBaseUnits("0.11", "USDC"),
    scalePriceToBaseUnits("0.11", "ETH"),
  );
});

test("channelBlockerHint names the Wallet step for a missing default account", () => {
  assert.match(
    channelBlockerHint("no_transaction_default_for_chain_namespace"),
    /Wallet.*Check again/,
  );
  assert.match(channelBlockerHint("mint_source_unavailable"), /Restart Home/);
});

test("channelBlockerHint falls back for an unknown or inherited reason", () => {
  const fallback = "Channel list unavailable — type the address instead.";
  assert.equal(channelBlockerHint("something_new"), fallback);
  assert.equal(channelBlockerHint("toString"), fallback);
  assert.equal(channelBlockerHint(undefined), fallback);
});

// -- Unfinished mints on open -------------------------------------------------

const PAY_TOKENS = [
  { symbol: "ELA", address: "0x00000000000000000000000000000000000000e1", decimals: 18 },
  { symbol: "USDC", address: "0x00000000000000000000000000000000000000c6", decimals: 6 },
];

function unfinishedEntry(overrides = {}) {
  return {
    uri: "localhost://Users/p/Creator/clip.mp4",
    name: "clip.mp4",
    mint_id: "ab12",
    stage: "approval_pending",
    recoverable: true,
    resume: "recorded_terms",
    can_start_over: true,
    terms: {
      copies: "0xa",
      price: "0xde0b6b3a7640000",
      pay_token: "",
      channel: "0x0000000000000000000000000000000000000022",
      access_method: "buy_once",
      reseller_cut: null,
      royalties: [],
    },
    ...overrides,
  };
}

test("unfinishedDialogModel has nothing to show when nothing is unfinished", () => {
  assert.equal(unfinishedDialogModel({ unfinished: [] }, PAY_TOKENS), null);
  assert.equal(unfinishedDialogModel(null, PAY_TOKENS), null);
  // Only what the server calls recoverable is offered; anything else was
  // dropped on its side and is not this page's to bring back.
  assert.equal(
    unfinishedDialogModel({ unfinished: [unfinishedEntry({ recoverable: false })] }, PAY_TOKENS),
    null,
  );
});

test("unfinishedDialogModel names each file and where its protection stopped", () => {
  const model = unfinishedDialogModel(
    {
      unfinished: [
        unfinishedEntry(),
        unfinishedEntry({
          uri: "localhost://Users/p/Creator/book.pdf",
          name: "book.pdf",
          stage: "publish_incomplete",
          resume: "enter_terms",
          terms: null,
        }),
      ],
    },
    PAY_TOKENS,
  );
  assert.equal(model.items.length, 2);
  assert.equal(model.items[0].line, "clip.mp4 — protection stopped at Wallet approval.");
  assert.equal(model.items[0].termsText, "10 copies at 1 ELA");
  assert.equal(model.items[0].canStartOver, true);
  assert.equal(model.items[1].line, "book.pdf — protection stopped at Store on your Home.");
  assert.match(model.items[1].termsText, /enter them again/);
});

test("unfinishedMintsFrom keeps only well-formed recoverable entries", () => {
  const mints = unfinishedMintsFrom({
    unfinished: [unfinishedEntry(), { recoverable: true, name: 3 }, "nope"],
  });
  assert.equal(mints.length, 1);
  assert.equal(mints[0].uri, "localhost://Users/p/Creator/clip.mp4");
  assert.equal(mints[0].resume, "recorded_terms");
});

test("formatRecordedTerms reads the recorded base units back in the token's own scale", () => {
  assert.equal(formatRecordedTerms(unfinishedEntry().terms, PAY_TOKENS), "10 copies at 1 ELA");
  assert.equal(
    formatRecordedTerms(
      { copies: "0x2", price: "0x1adb0", pay_token: PAY_TOKENS[1].address.toUpperCase() },
      PAY_TOKENS,
    ),
    "2 copies at 0.11 USDC",
  );
  // A token this page was not offered is never guessed at.
  assert.equal(
    formatRecordedTerms(
      { copies: "0x1", price: "0x5", pay_token: "0x00000000000000000000000000000000000000ff" },
      PAY_TOKENS,
    ),
    "1 copy at 5 base units",
  );
  assert.equal(formatRecordedTerms({ access_method: "free", copies: "0x0", price: "0x0" }, PAY_TOKENS), "Free");
  assert.equal(formatRecordedTerms(null, PAY_TOKENS), "");
});

test("buildResumeBody asks for the recorded mint and carries no terms of its own", () => {
  assert.deepEqual(
    buildResumeBody({ uri: "localhost://Users/p/Creator/clip.mp4", ifRevision: "r1" }),
    {
      uri: "localhost://Users/p/Creator/clip.mp4",
      if_revision: "r1",
      protection: { mode: "runtime_custody_resume" },
    },
  );
});

// The smallest document this dialog needs: enough to build it, and a trap on
// innerHTML so that any markup path fails the test outright.
function fakeDocument() {
  class FakeElement {
    constructor(tag) {
      this.tag = tag;
      this.children = [];
      this.listeners = {};
      this.textContent = "";
      this.className = "";
      this.type = "";
      this.hidden = false;
    }
    set innerHTML(_value) {
      throw new Error("innerHTML must never be used for server-provided text");
    }
    append(...nodes) {
      this.children.push(...nodes);
    }
    addEventListener(name, handler) {
      this.listeners[name] = handler;
    }
    click() {
      this.listeners.click?.();
    }
    all() {
      return [this, ...this.children.flatMap((child) => child.all())];
    }
  }
  return { createElement: (tag) => new FakeElement(tag) };
}

test("renderUnfinishedDialog writes names as text and Resume posts the recorded mint", () => {
  const hostile = "<img src=x onerror=alert(1)>.mp4";
  const model = unfinishedDialogModel(
    { unfinished: [unfinishedEntry({ name: hostile })] },
    PAY_TOKENS,
  );
  const resumed = [];
  const root = renderUnfinishedDialog(fakeDocument(), model, {
    onResume: (entry) => resumed.push(entry),
    onStartOver: () => assert.fail("Resume must not start over"),
  });
  const nodes = root.all();
  assert.ok(nodes.some((node) => node.textContent === `${hostile} — protection stopped at Wallet approval.`));
  assert.ok(!nodes.some((node) => node.tag === "img"));
  const buttons = nodes.filter((node) => node.tag === "button");
  assert.deepEqual(buttons.map((button) => button.textContent), ["Resume", "Start over"]);
  buttons[0].click();
  assert.equal(resumed.length, 1);
  assert.equal(resumed[0].uri, "localhost://Users/p/Creator/clip.mp4");
  assert.equal(resumed[0].resume, "recorded_terms");
});

test("renderUnfinishedDialog offers Start over beside Resume, and only when the server allows it", () => {
  const startedOver = [];
  const offered = renderUnfinishedDialog(
    fakeDocument(),
    unfinishedDialogModel({ unfinished: [unfinishedEntry()] }, PAY_TOKENS),
    {
      onResume: () => assert.fail("Start over must not resume"),
      onStartOver: (entry) => startedOver.push(entry),
    },
  );
  const buttons = offered.all().filter((node) => node.tag === "button");
  buttons[1].click();
  assert.equal(startedOver.length, 1);
  assert.equal(startedOver[0].uri, "localhost://Users/p/Creator/clip.mp4");

  const withheld = renderUnfinishedDialog(
    fakeDocument(),
    unfinishedDialogModel(
      { unfinished: [unfinishedEntry({ can_start_over: false })] },
      PAY_TOKENS,
    ),
    { onResume: () => {}, onStartOver: () => {} },
  );
  assert.deepEqual(
    withheld.all().filter((node) => node.tag === "button").map((button) => button.textContent),
    ["Resume"],
  );
});

test("buildPublishBody asks for a new mint only when told to", () => {
  const base = { uri: "localhost://u/Creator/a.mp4", ifRevision: "r", copies: "0x1", price: "1", channel: "0x0000000000000000000000000000000000000022" };
  assert.equal(buildPublishBody(base).protection.new_attempt, undefined);
  assert.equal(buildPublishBody({ ...base, newAttempt: true }).protection.new_attempt, true);
});

test("formTermsFrom turns recorded terms back into what the form holds", () => {
  assert.deepEqual(formTermsFrom(unfinishedEntry().terms, PAY_TOKENS), {
    copies: "10",
    price: "1",
    currency: "ELA",
    channel: "0x0000000000000000000000000000000000000022",
    accessMethod: "buy_once",
    resellerCutPercent: "",
  });
  assert.deepEqual(
    formTermsFrom(
      {
        copies: "0x2",
        price: "0x1adb0",
        pay_token: PAY_TOKENS[1].address,
        channel: "",
        access_method: "buy_and_resell",
        reseller_cut: 900,
      },
      PAY_TOKENS,
    ),
    {
      copies: "2",
      price: "0.11",
      currency: "USDC",
      channel: "",
      accessMethod: "buy_and_resell",
      resellerCutPercent: "90",
    },
  );
  // A token this page was not offered leaves the price for the creator.
  assert.equal(
    formTermsFrom({ copies: "0x1", price: "0x5", pay_token: "0x00000000000000000000000000000000000000ff" }, PAY_TOKENS).price,
    "",
  );
  assert.equal(formTermsFrom(null, PAY_TOKENS), null);
});

test("each fail-closed refusal of an earlier attempt offers Start over, never a dead end", () => {
  for (const reason of ["source_changed", "authority_changed", "dispatch_uncertain"]) {
    const conflict = attemptConflictFrom({
      status: "error",
      message: "refused",
      attempt_conflict: {
        schema: "elastos.protected-content.attempt-conflict/v1",
        reason,
        can_start_over: true,
      },
    });
    assert.deepEqual(conflict, { reason, canStartOver: true });
    assert.deepEqual(recoveryActionsFor({ attemptConflict: conflict }), ["start_over"], reason);
    const rows = failureDetailRows({ message: "refused", attemptConflict: conflict });
    assert.ok(rows.some((row) => row.label === "Earlier attempt"), reason);
  }
  assert.equal(attemptConflictFrom({ status: "error" }), null);
});

test("Start over is offered only where the server says the attempt can be set aside", () => {
  // A minted attempt -- sent, mined or listed -- is resumed, never started over.
  for (const state of ["approval_outstanding", "already_minted"]) {
    assert.deepEqual(
      recoveryActionsFor({ creatorMint: { state, canResume: true } }),
      ["resume"],
      state,
    );
  }
  // A refusal over an attempt that cannot be set aside offers nothing.
  for (const reason of ["source_changed", "approval_open", "listing_unreadable"]) {
    assert.deepEqual(
      recoveryActionsFor({ attemptConflict: { reason, canStartOver: false } }),
      [],
      reason,
    );
  }
  // Network, wallet-default and other failures are not the attempt's fault.
  assert.deepEqual(recoveryActionsFor({ message: "Runtime custody mint failed" }), []);
  assert.deepEqual(recoveryActionsFor({ walletDefault: { reason: "x" } }), []);
});

test("an approval still open in Wallet is explained, not started over", () => {
  const conflict = attemptConflictFrom({
    status: "error",
    message: "An earlier approval for this file is still open in Wallet. Decline it there, then try again.",
    attempt_conflict: { reason: "approval_open", can_start_over: false },
  });
  assert.deepEqual(recoveryActionsFor({ attemptConflict: conflict }), []);
  const rows = failureDetailRows({ message: "refused", attemptConflict: conflict });
  assert.ok(
    rows.some((row) => row.label === "Earlier attempt" && /Decline it in Wallet/.test(row.value)),
    JSON.stringify(rows),
  );
});

test("an approval that cannot be confirmed closed offers Resume, never Start over", () => {
  for (const [attempt_conflict, phrase] of [
    [{ reason: "approval_open", cause: "still_open", can_resume: true }, /Decline it in Wallet/],
    [{ reason: "approval_open", cause: "wallet_unreachable", can_resume: true }, /could not be reached/],
    [{ reason: "approval_open", cause: "not_on_record", can_resume: true }, /not on record/],
    [{ reason: "approval_in_connector", connector: "metamask", can_resume: true }, /went to metamask/],
  ]) {
    const conflict = attemptConflictFrom({ status: "error", attempt_conflict });
    assert.equal(conflict.canResume, true);
    assert.deepEqual(recoveryActionsFor({ attemptConflict: conflict }), ["resume"]);
    const rows = failureDetailRows({ message: "refused", attemptConflict: conflict });
    assert.ok(
      rows.some((row) => row.label === "Earlier attempt" && phrase.test(row.value)),
      JSON.stringify(rows),
    );
  }
});

test("a connector approval is listed as waiting in the external wallet", () => {
  const model = unfinishedDialogModel(
    { unfinished: [unfinishedEntry({ stage: "approval_in_connector", can_start_over: false })] },
    PAY_TOKENS,
  );
  assert.equal(model.items[0].line, "clip.mp4 — protection stopped at Wallet approval.");
  assert.equal(model.items[0].canStartOver, false);
});

// ---------------------------------------------------------------------------
// META-PUBLIC Task 6 (A4/A5): the Creator reads the public metadata status and
// stays locked for new mints without consent; consent and Stop live in Inbox.
// While the Home does not offer sharing (`gate_open: false`) the Creator opens
// as on develop. The `public_metadata` publish stage and its typed failure.
// ---------------------------------------------------------------------------

const readCreatorSource = () => readFileSync(new URL("./creator.js", import.meta.url), "utf8");

/** One `GET /api/apps/creator/public-ipfs` body, with the server's names. */
function ipfsStatus(overrides = {}) {
  const { store, ...rest } = overrides;
  return {
    admin: true,
    gate_open: true,
    consent_enabled: false,
    withdrawing: false,
    stop_pending: null,
    store: { liveness: "down", ready: false, peers: 0, ...(store || {}) },
    ...rest,
  };
}

const READY = ipfsStatus({ consent_enabled: true, store: { liveness: "running", ready: true, peers: 8 } });
const NOT_READY = ipfsStatus({ consent_enabled: true, store: { liveness: "running", ready: false } });
const FAST = { intervalMs: 1, timeoutMs: 200 };

/** Answers each read with the next status; the last one repeats. */
function statusSequence(...statuses) {
  const reads = { count: 0 };
  const read = async () => {
    const status = statuses[Math.min(reads.count, statuses.length - 1)];
    reads.count += 1;
    if (status instanceof Error) throw status;
    return structuredClone(status);
  };
  return { read, reads };
}

async function until(predicate, what, ms = 2000) {
  const deadline = Date.now() + ms;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

/** The gate flow over fake ports; every port call is recorded. */
function gateHarness(t, statuses, { read, wait = FAST } = {}) {
  const sequence = statusSequence(...statuses);
  const calls = { opened: [], offered: 0, inbox: 0 };
  const views = [];
  const flow = creator.createPublicIpfsGateFlow({
    readStatus: read || sequence.read,
    show: (view) => views.push(view),
    openCreator: (status) => {
      calls.opened.push(status);
    },
    openInbox: () => {
      calls.inbox += 1;
    },
    offerUnfinished: async () => {
      calls.offered += 1;
    },
    wait,
  });
  t.after(() => flow.cancel());
  const last = () => views[views.length - 1];
  return { flow, calls, views, last, reads: sequence.reads };
}

test("publicIpfsGate maps each status", () => {
  const { publicIpfsGate } = creator;
  assert.equal(publicIpfsGate(ipfsStatus()), "consent");
  assert.equal(publicIpfsGate(NOT_READY), "starting");
  assert.equal(publicIpfsGate(READY), "ready");
  // Review Focus 4: a principal who is not the admin is never sent to agree.
  assert.equal(publicIpfsGate(ipfsStatus({ admin: false })), "admin_required");
  assert.equal(
    publicIpfsGate({ ...READY, admin: false }),
    "admin_required",
    "admin comes before consent",
  );
  // A5: a Home that does not offer sharing opens the Creator as on develop,
  // whatever else the status says.
  for (const status of [
    ipfsStatus({ gate_open: false }),
    ipfsStatus({ gate_open: false, admin: false }),
    ipfsStatus({ gate_open: false, withdrawing: true }),
  ]) {
    assert.equal(publicIpfsGate(status), "off");
  }
  // Only an explicit `true` opens the gate.
  assert.equal(publicIpfsGate({ ...ipfsStatus(), gate_open: undefined }), "off");
});

test("publicIpfsGate shows stopping while withdrawing, even with consent false", () => {
  const { publicIpfsGate } = creator;
  assert.equal(publicIpfsGate(ipfsStatus({ withdrawing: true })), "stopping");
  assert.equal(publicIpfsGate({ ...READY, withdrawing: true }), "stopping");
  assert.equal(publicIpfsGate(ipfsStatus({ withdrawing: true, admin: false })), "stopping");
});

test("unknown liveness stays starting", () => {
  const { publicIpfsGate } = creator;
  const unknown = ipfsStatus({ consent_enabled: true, store: { liveness: "unknown", ready: true } });
  assert.equal(publicIpfsGate(unknown), "starting");
  assert.equal(
    publicIpfsGate(ipfsStatus({ consent_enabled: true, store: { liveness: "down", ready: false } })),
    "starting",
  );
  // A missing or malformed store block is not ready, never "consent".
  assert.equal(publicIpfsGate({ ...READY, store: null }), "starting");
});

test("stagesFromProgress maps public_metadata", () => {
  const mapped = stagesFromProgress({
    stages: [
      { id: "escrow", state: "done" },
      { id: "publish", state: "done" },
      { id: "public_metadata", state: "failed" },
      { id: "listing", state: "pending" },
    ],
  });
  assert.deepEqual(mapped, [
    { name: "encrypt", state: "done" },
    { name: "publish", state: "done" },
    { name: "public_metadata", state: "err" },
    { name: "assemble", state: "pending" },
  ]);
});

test("publicMetadataFailure reads the typed error", () => {
  const { publicMetadataFailure } = creator;
  const envelope = {
    status: "error",
    message: "Runtime custody creator mint is unavailable",
    public_metadata: {
      code: "announce_failed",
      detail: "The public IPFS node could not announce the metadata.",
      progress: { stages: [{ id: "public_metadata", state: "failed" }] },
    },
  };
  assert.deepEqual(publicMetadataFailure(envelope), {
    stage: "public_metadata",
    code: "announce_failed",
    retry: true,
  });
  assert.equal(publicMetadataFailure({ status: "error", message: "other" }), null);
  assert.equal(publicMetadataFailure({ public_metadata: "announce_failed" }), null);
  assert.equal(publicMetadataFailure({ public_metadata: { detail: "no code" } }), null);
  assert.equal(publicMetadataFailure(null), null);
  // The page offers the same Check again a pending publish offers.
  const error = { message: "refused", publicMetadata: publicMetadataFailure(envelope) };
  assert.deepEqual(recoveryActionsFor(error), ["retry"]);
  const rows = failureDetailRows({
    ...error,
    progress: { stages: [{ id: "public_metadata", state: "failed" }] },
  });
  assert.ok(
    rows.some((row) => row.label === "Progress" && /Publish metadata on IPFS: failed/.test(row.value)),
    JSON.stringify(rows),
  );
  assert.ok(rows.some((row) => row.label === "Public metadata"), JSON.stringify(rows));
});

test("the stage list includes public_metadata between publish and assemble", () => {
  const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
  const stages = [...html.matchAll(/<li data-stage="([a-z_]+)"/g)].map((match) => match[1]);
  assert.deepEqual(stages, ["analyze", "transcode", "encrypt", "publish", "public_metadata", "assemble"]);
  assert.match(html, /<li data-stage="public_metadata"[^>]*>[\s\S]*?Publish metadata on IPFS<\/li>/);
  // The page reloads the new module, not a cached one.
  assert.doesNotMatch(html, /creator\.js\?v=creator-20261110a/);
  // resetStages clears the new row with the others.
  assert.match(readCreatorSource(), /\["analyze", "transcode", "encrypt", "publish", "public_metadata", "assemble"\]/);
});

test("boot still offers unfinished mints when gated", () => {
  const source = readCreatorSource();
  const start = source.indexOf("  function boot() {");
  const end = source.indexOf("\n  }\n", start);
  assert.ok(start >= 0 && end > start, "boot is where this test expects it");
  const boot = source.slice(start, end);
  // The gate decides what the form shows; it never decides whether
  // unfinished mints are offered.
  assert.match(boot, /createPublicIpfsGateFlow\(/);
  assert.match(boot, /offerUnfinished/);
  assert.doesNotMatch(boot, /if \([^)]*ready[^)]*\)[^;]*offerUnfinished/);
});

test("consent gate offers Open Inbox, never Agree", async (t) => {
  const h = gateHarness(t, [ipfsStatus()]);
  await h.flow.start();
  assert.equal(h.last().gate, "consent");
  assert.equal(
    h.last().text,
    "Turn on metadata sharing in Inbox to mint. Your unfinished mints stay available.",
  );
  assert.deepEqual(h.last().actions, ["open_inbox"]);
  assert.equal(h.calls.offered, 1, "unfinished-mint recovery is still offered");
  assert.deepEqual(h.calls.opened, []);
  h.flow.openInbox();
  assert.equal(h.calls.inbox, 1);
  // The Creator holds no enable or stop path of its own (A4, D1-D2).
  for (const removed of ["agree", "notNow", "review", "stopSharing"]) {
    assert.equal(h.flow[removed], undefined, removed);
  }
  assert.equal(creator.PUBLIC_IPFS_ENABLE_OPERATION, undefined);
  const source = readCreatorSource();
  assert.doesNotMatch(source, /requestHomePasskeyStepUp|passkey-step-up\.request/);
  assert.doesNotMatch(source, /public-ipfs\/(enable|disable)/);
  const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
  assert.doesNotMatch(html, /stop-sharing-button|Stop sharing metadata/);
});

test("consent given in Inbox opens the Creator once the node is ready", async (t) => {
  const h = gateHarness(t, [ipfsStatus(), ipfsStatus(), NOT_READY, READY], {
    wait: { intervalMs: 1, timeoutMs: 2000 },
  });
  await h.flow.start();
  await until(() => h.last()?.gate === "ready", "the ready gate");
  assert.ok(h.views.some((view) => view.gate === "starting"));
  assert.equal(h.calls.opened.length, 1);
});

test("gate_open false opens the Creator", async (t) => {
  const closed = ipfsStatus({ gate_open: false });
  const h = gateHarness(t, [closed]);
  await h.flow.start();
  assert.equal(h.last().gate, "off");
  assert.deepEqual(h.calls.opened, [closed], "the Creator opens as on develop");
  assert.equal(h.calls.offered, 1);
  assert.equal(h.reads.count, 1, "no waiting on a Home that does not share");
});

test("the Home shell lets the Creator open Inbox and asks no passkey for it", () => {
  const host = readFileSync(new URL("../../home/browser/home-shell-host.js", import.meta.url), "utf8");
  const creatorTargets = host.split("\n").find((text) => text.trim().startsWith("creator: new Set("));
  assert.ok(creatorTargets, "the Creator's open targets are declared");
  assert.match(creatorTargets, /"inbox"/);
  const stepUps = host.split("\n").find((text) => text.startsWith("const PASSKEY_STEP_UP_TARGETS"));
  assert.ok(stepUps, "PASSKEY_STEP_UP_TARGETS is declared");
  assert.doesNotMatch(stepUps, /"creator"/);
});

test("waitForPublicIpfsGate opens when the store becomes ready", async (t) => {
  // IP6: a Home restarted with consent already enabled starts its node again
  // on its own; the page only waits.
  const direct = statusSequence(NOT_READY, NOT_READY, READY);
  const result = await creator.waitForPublicIpfsGate(direct.read, "ready", FAST);
  assert.equal(result.gate, "ready");
  assert.equal(result.status.store.ready, true);
  assert.equal(direct.reads.count, 3);

  const h = gateHarness(t, [NOT_READY, NOT_READY, NOT_READY, READY]);
  await h.flow.start();
  assert.equal(h.views[0].gate, "starting");
  assert.equal(h.last().gate, "ready");
  assert.equal(h.calls.opened.length, 1);
  assert.equal(h.calls.offered, 1);
});

test("a principal who is not the admin is asked to ask the admin", async (t) => {
  const h = gateHarness(t, [ipfsStatus({ admin: false })]);
  await h.flow.start();
  assert.equal(h.last().gate, "admin_required");
  assert.equal(h.last().text, "Ask the Home admin to enable public metadata sharing.");
  assert.deepEqual(h.last().actions, []);
  assert.equal(h.calls.offered, 1, "unfinished-mint recovery is still offered");
});

test("waitForPublicIpfsGate after Stop waits for withdrawal to finish", async (t) => {
  const withdrawing = { ...READY, withdrawing: true };
  const withdrawn = ipfsStatus({ store: { liveness: "down", ready: false } });
  const direct = statusSequence(withdrawing, withdrawing, withdrawing, withdrawn);
  const result = await creator.waitForPublicIpfsGate(direct.read, "consent", FAST);
  assert.equal(result.gate, "consent");
  assert.equal(direct.reads.count, 4);

  // Stopped from Inbox while the Creator is open: it follows the withdrawal
  // read-only, then shows the consent gate.
  const h = gateHarness(t, [withdrawing, withdrawing, withdrawing, withdrawn]);
  await h.flow.start();
  const stopping = h.views.find((view) => view.gate === "stopping");
  assert.equal(stopping.text, "Stopping…");
  assert.deepEqual(stopping.actions, [], "stopping is read-only in the Creator");
  assert.equal(h.last().gate, "consent");
  assert.deepEqual(h.last().actions, ["open_inbox"]);
});

test("stop_pending surfaces a read-only stopping state", async (t) => {
  let current = ipfsStatus({ withdrawing: true, stop_pending: "the IPFS node is still busy" });
  const h = gateHarness(t, [], {
    read: async () => structuredClone(current),
    wait: { intervalMs: 1, timeoutMs: 5000 },
  });
  const started = h.flow.start();
  await until(() => h.last()?.text?.startsWith("Still stopping"), "the still-stopping view");
  assert.equal(h.last().gate, "stopping");
  assert.equal(h.last().text, "Still stopping: the IPFS node is still busy. Your Home keeps trying.");
  assert.deepEqual(h.last().actions, [], "Try again lives in Inbox");
  current = ipfsStatus();
  await started;
  assert.equal(h.last().gate, "consent");
});

test("a timed-out stop stays read-only", async (t) => {
  const withdrawing = ipfsStatus({ withdrawing: true });
  const h = gateHarness(t, [withdrawing]);
  await h.flow.start();
  assert.equal(h.last().gate, "stopping");
  assert.match(h.last().text, /^Still stopping: .+\. Your Home keeps trying\.$/);
  assert.deepEqual(h.last().actions, []);
});

test("boot during withdrawal shows stopping and still offers unfinished mints", async (t) => {
  const withdrawing = { ...READY, withdrawing: true };
  const h = gateHarness(t, [withdrawing, withdrawing, ipfsStatus()]);
  await h.flow.start();
  assert.equal(h.views[0].gate, "stopping");
  assert.equal(h.calls.offered, 1);
  assert.deepEqual(h.calls.opened, [], "the Creator does not open during a withdrawal");
  assert.equal(h.last().gate, "consent");
});

test("waitForPublicIpfsGate times out to a retryable state", async (t) => {
  const direct = statusSequence(NOT_READY);
  const result = await creator.waitForPublicIpfsGate(direct.read, "ready", { intervalMs: 1, timeoutMs: 20 });
  assert.equal(result.gate, "timeout");
  assert.equal(result.status.store.ready, false);

  // A read error is treated like the timeout, and Retry runs the wait again.
  const h = gateHarness(t, [new Error("Home is restarting"), NOT_READY, READY]);
  await h.flow.start();
  assert.equal(h.last().gate, "timeout");
  assert.equal(h.last().text, "Your public IPFS node isn't ready yet.");
  assert.deepEqual(h.last().actions, ["retry"]);
  await h.flow.retry();
  assert.equal(h.last().gate, "ready");
  assert.equal(h.calls.offered, 1, "Retry does not offer the unfinished mints twice");
});

test("waitForPublicIpfsGate is cancellable", async () => {
  const direct = statusSequence(NOT_READY);
  const controller = new AbortController();
  const waiting = creator.waitForPublicIpfsGate(direct.read, "ready", {
    intervalMs: 5,
    timeoutMs: 10_000,
    signal: controller.signal,
  });
  await until(() => direct.reads.count >= 2, "two reads");
  controller.abort();
  await assert.rejects(waiting, (error) => error.name === "AbortError");
  const reads = direct.reads.count;
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(direct.reads.count, reads, "no read after the abort");

  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(
    creator.waitForPublicIpfsGate(direct.read, "ready", { signal: aborted.signal }),
    (error) => error.name === "AbortError",
  );
});

// Plan B POOL-MINT: Creator offers the pools this Home uses and sends the
// chosen one.
test("creator lists the used pools and sends pool_did", () => {
  const pools = mintPoolChoices([
    { pool_did: "did:key:z6MkOwnPool", label: "This Home's pool", own: true },
    { pool_did: "did:key:z6MkOtherPool", label: "Pool AB12", own: false },
    { pool_did: "not-a-did", label: "x" },
    null,
  ]);
  assert.deepEqual(pools, [
    { poolDid: "did:key:z6MkOwnPool", label: "This Home's pool" },
    { poolDid: "did:key:z6MkOtherPool", label: "Pool AB12" },
  ]);
  assert.deepEqual(mintPoolChoices(undefined), []);
  const chosen = buildPublishBody({
    uri: "localhost://root/Creator/clip.mp4",
    ifRevision: 3,
    copies: "0x1",
    price: "1",
    channel: "0x0000000000000000000000000000000000000022",
    poolDid: "did:key:z6MkOtherPool",
  });
  assert.equal(chosen.protection.pool_did, "did:key:z6MkOtherPool");
  const defaulted = buildPublishBody({
    uri: "localhost://root/Creator/clip.mp4",
    ifRevision: 3,
    copies: "0x1",
    price: "1",
    channel: "0x0000000000000000000000000000000000000022",
  });
  assert.equal(Object.hasOwn(defaulted.protection, "pool_did"), false);
});

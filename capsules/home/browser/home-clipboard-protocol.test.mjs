import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_HOME_CLIPBOARD_IDENTIFIER_UTF8_BYTES,
  MAX_HOME_CLIPBOARD_PURPOSE_CODE_UNITS,
  MAX_HOME_CLIPBOARD_TEXT_UTF8_BYTES,
  homeClipboardOperationAllowed,
  homeClipboardPolicyFor,
  homeClipboardTargetSupported,
  homeClipboardValidWriteText,
} from "./home-clipboard-protocol.js";

test("target and purpose lookup accepts own policy entries only", () => {
  assert.equal(homeClipboardTargetSupported("browser"), true);
  assert.equal(homeClipboardTargetSupported("chat-room"), true);
  assert.equal(homeClipboardTargetSupported("assistant"), true);
  assert.equal(
    homeClipboardOperationAllowed(
      "chat-room",
      "conversation.invite",
      "write",
    ),
    true,
  );
  assert.equal(
    homeClipboardOperationAllowed(
      "chat-room",
      "conversation.invite",
      "read",
    ),
    false,
  );
  assert.equal(
    homeClipboardOperationAllowed("library", "resource.identifier", "write"),
    true,
  );
  assert.equal(
    homeClipboardOperationAllowed("library", "resource.uri", "write"),
    true,
  );
  assert.equal(
    homeClipboardOperationAllowed(
      "assistant",
      "transcript.markdown",
      "write",
    ),
    true,
  );
  assert.equal(
    homeClipboardOperationAllowed(
      "assistant",
      "transcript.markdown",
      "read",
    ),
    false,
  );
  assert.equal(
    homeClipboardOperationAllowed("assistant", "message.text", "write"),
    true,
  );
  assert.equal(
    homeClipboardOperationAllowed("assistant", "message.text", "read"),
    false,
  );

  for (const inheritedName of ["__proto__", "constructor", "toString"]) {
    assert.doesNotThrow(() => homeClipboardTargetSupported(inheritedName));
    assert.equal(homeClipboardTargetSupported(inheritedName), false);
    assert.equal(homeClipboardPolicyFor(inheritedName, "browser.text"), null);
    assert.equal(homeClipboardPolicyFor("browser", inheritedName), null);
    assert.equal(
      homeClipboardOperationAllowed("browser", inheritedName, "write"),
      false,
    );
  }

  assert.equal(
    homeClipboardPolicyFor(
      "browser",
      "x".repeat(MAX_HOME_CLIPBOARD_PURPOSE_CODE_UNITS + 1),
    ),
    null,
  );
});

test("code-unit bounds reject before UTF-8 encoding while byte bounds stay exact", () => {
  class MustNotEncode {
    constructor() {
      throw new Error("oversized text reached TextEncoder");
    }
  }

  assert.equal(
    homeClipboardValidWriteText(
      "browser",
      "browser.text",
      "a".repeat(MAX_HOME_CLIPBOARD_TEXT_UTF8_BYTES + 1),
      MustNotEncode,
    ),
    false,
  );
  assert.equal(
    homeClipboardValidWriteText(
      "library",
      "resource.identifier",
      "a".repeat(MAX_HOME_CLIPBOARD_IDENTIFIER_UTF8_BYTES + 1),
      MustNotEncode,
    ),
    false,
  );
  assert.equal(
    homeClipboardValidWriteText(
      "assistant",
      "transcript.markdown",
      "a".repeat(MAX_HOME_CLIPBOARD_TEXT_UTF8_BYTES + 1),
      MustNotEncode,
    ),
    false,
  );
  assert.equal(
    homeClipboardValidWriteText(
      "assistant",
      "message.text",
      "a".repeat(MAX_HOME_CLIPBOARD_TEXT_UTF8_BYTES + 1),
      MustNotEncode,
    ),
    false,
  );

  const exactUtf8Text = "é".repeat(MAX_HOME_CLIPBOARD_TEXT_UTF8_BYTES / 2);
  assert.equal(
    homeClipboardValidWriteText("browser", "browser.text", exactUtf8Text),
    true,
  );
  assert.equal(
    homeClipboardValidWriteText(
      "browser",
      "browser.text",
      `${exactUtf8Text}a`,
    ),
    false,
  );
  assert.equal(
    homeClipboardValidWriteText(
      "assistant",
      "transcript.markdown",
      exactUtf8Text,
    ),
    true,
  );
  assert.equal(
    homeClipboardValidWriteText("assistant", "message.text", exactUtf8Text),
    true,
  );
  assert.equal(
    homeClipboardValidWriteText("assistant", "message.text", `${exactUtf8Text}a`),
    false,
  );
});

test("Library identifiers are bounded, write-only, and not arbitrary text", () => {
  const exactIdentifier = "a".repeat(
    MAX_HOME_CLIPBOARD_IDENTIFIER_UTF8_BYTES,
  );
  for (const identifier of [
    "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
    "revision:object-head-1",
    "localhost://Users/alice/Documents/report.txt",
    exactIdentifier,
  ]) {
    assert.equal(
      homeClipboardValidWriteText(
        "library",
        "resource.identifier",
        identifier,
      ),
      true,
    );
  }
  for (const denied of [
    "",
    "identifier with spaces",
    "identifier\nwith-control",
    `a${"é".repeat(MAX_HOME_CLIPBOARD_IDENTIFIER_UTF8_BYTES / 2)}`,
  ]) {
    assert.equal(
      homeClipboardValidWriteText(
        "library",
        "resource.identifier",
        denied,
      ),
      false,
    );
  }
  assert.equal(
    homeClipboardOperationAllowed("library", "resource.identifier", "read"),
    false,
  );
  assert.equal(
    homeClipboardOperationAllowed("documents", "resource.identifier", "write"),
    false,
  );
});

for (const target of ["people", "chat-room"]) {
  test(`${target} can copy a bounded Profile DID but cannot read the clipboard`, () => {
    assert.equal(homeClipboardOperationAllowed(target, "profile.id", "write"), true);
    assert.equal(homeClipboardOperationAllowed(target, "profile.id", "read"), false);
    assert.equal(homeClipboardValidWriteText(target, "profile.id", "did:key:zProfile"), true);
    assert.equal(homeClipboardValidWriteText(target, "profile.id", "x".repeat(2049)), false);
    assert.equal(homeClipboardValidWriteText(target, "profile.id", "did:key:zProfile\nextra"), false);
    assert.equal(homeClipboardOperationAllowed("browser", "profile.id", "write"), false);
  });
}

test("Custody identifiers and fingerprints are bounded and write-only", () => {
  const identifiers = [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "0x3f2a9c4b7e1d5a6f8b0c2e4d6a8f1b3c5e7d9a0b",
    // A Carrier connect ticket: lowercase base32, no padding.
    "vqaaaamgf5g3ak7wq2mbtqefxk7kfqsxz6hkd3dk5pf2kqz4mfm5vxuaaeaqaa2abrgaqb",
    "a".repeat(MAX_HOME_CLIPBOARD_IDENTIFIER_UTF8_BYTES),
  ];
  for (const identifier of identifiers) {
    assert.equal(
      homeClipboardValidWriteText("custody", "custody.identifier", identifier),
      true,
    );
  }
  for (const denied of [
    "",
    " did:key:z6Mk",
    "did:key:z6Mk\n",
    "did:key:z6Mk with-space",
    // Bidi overrides, zero-width and other non-ASCII characters.
    "did:key:z6Mk\u202Eevil",
    "did:key:z6Mk\u200Bx",
    "did:key:z6Mké",
    "a".repeat(MAX_HOME_CLIPBOARD_IDENTIFIER_UTF8_BYTES + 1),
  ]) {
    assert.equal(
      homeClipboardValidWriteText("custody", "custody.identifier", denied),
      false,
      JSON.stringify(denied),
    );
  }

  // Only the whole digest: "sha256:" and 64 lowercase hex.
  const digest = "1a2b3c4d" + "e".repeat(48) + "4f2a91c0";
  for (const fingerprint of [`sha256:${digest}`, `sha256:${"0".repeat(64)}`]) {
    assert.equal(
      homeClipboardValidWriteText("custody", "custody.fingerprint", fingerprint),
      true,
    );
  }
  for (const denied of [
    "",
    // The short display form is never copied.
    "1A2B 3C4D \u2026 4F2A 91C0",
    `sha256:${digest.toUpperCase()}`,
    `sha256:${digest.slice(1)}`,
    `sha256:${digest}0`,
    digest,
    `SHA256:${digest}`,
    `sha256:${digest}\n`,
    ` sha256:${digest}`,
    `sha256:${digest.slice(0, 32)}\n${digest.slice(32)}`,
    `sha256:${digest.slice(0, 63)}\u202E`,
    "Send your recovery key to this address to confirm",
    "x".repeat(72),
  ]) {
    assert.equal(
      homeClipboardValidWriteText("custody", "custody.fingerprint", denied),
      false,
      JSON.stringify(denied),
    );
  }

  for (const purpose of ["custody.identifier", "custody.fingerprint"]) {
    assert.equal(homeClipboardOperationAllowed("custody", purpose, "write"), true);
    assert.equal(homeClipboardOperationAllowed("custody", purpose, "read"), false);
  }
  // Custody's purposes are its own, and it has no others.
  assert.equal(homeClipboardOperationAllowed("library", "custody.identifier", "write"), false);
  assert.equal(homeClipboardOperationAllowed("custody", "browser.text", "read"), false);
  assert.equal(homeClipboardOperationAllowed("custody", "resource.identifier", "write"), false);
});

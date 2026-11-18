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

test("WalletConnect alone can copy a bounded connection link, with write authority only", () => {
  const purpose = "wallet.connection-link";
  const uri = `wc:${"01".repeat(32)}@2?symKey=${"02".repeat(32)}&relay-protocol=irn&expiryTimestamp=1800000000`;
  assert.equal(homeClipboardOperationAllowed("wallet-walletconnect", purpose, "write"), true);
  assert.equal(homeClipboardOperationAllowed("wallet-walletconnect", purpose, "read"), false);
  assert.equal(homeClipboardValidWriteText("wallet-walletconnect", purpose, uri), true);
  for (const target of ["wallet", "wallet-metamask", "wallet-unisat", "browser"]) {
    assert.equal(homeClipboardOperationAllowed(target, purpose, "write"), false);
  }
  for (const text of ["", "https://example.test", uri + "\n", " " + uri, uri + "x".repeat(2048)]) {
    assert.equal(homeClipboardValidWriteText("wallet-walletconnect", purpose, text), false);
  }
});

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

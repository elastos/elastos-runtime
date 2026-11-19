import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const security = read("SECURITY.md");
const browser = read("elastos/crates/elastos-server/src/api/gateway_browser.rs");

// Path-name and source-descriptor checks only. These do not prove write-time
// encryption for every row, successful import, or installed behavior.
test("Security storage path parts occur in source literals (not a write or encryption check)", () => {
  const server = "elastos/crates/elastos-server/src/";
  const sources = [
    ["Home recovery authority", "auth.rs"],
    ["Assistant conversations", "api/gateway_assistant_workspace_v2.rs"],
    ["Direct messages", "collaboration_direct_messages.rs"],
    ["Community history", "collaboration_core.rs"],
    ["Contacts and Profile", "collaboration_contact_store.rs", "collaboration_profile_authority.rs"],
    ["Documents:", "documents.rs", "../../../../capsules/ipfs-provider/src/main.rs"],
    ["Library files", "library.rs", "../../../../capsules/ipfs-provider/src/main.rs"],
    ["Notifications:", "notifications.rs"],
    ["Built-in Wallet", "../../../../capsules/wallet-provider/src/main.rs"],
    ["Browser profile", "api/gateway_browser.rs"],
    ["Model run records", "api/model_provider_config.rs"],
    ["Model provider credentials", "api/model_provider_config.rs"],
    ["Home settings", "api/gateway_home_system.rs"],
  ];
  const table = security.split("| Data and storage path |", 2)[1].split("\n\n", 1)[0];
  const rows = table.split("\n").filter((line) => /^\| [A-Z]/.test(line));
  assert.equal(rows.length, sources.length, "cover each storage row");
  for (const [name, ...paths] of sources) {
    const row = rows.find((line) => line.startsWith(`| ${name}`));
    assert.ok(row, `find the ${name} row`);
    const literals = [...paths, "auth.rs"].flatMap((path) => [...read(server + path).matchAll(/"([^"\n]+)"/g)]
      .map((match) => match[1]));
    for (const [, path] of row.split("|")[1].matchAll(/`([^`]+)`/g)) {
      // Variable person/document parts are explained above the table.
      // This checks fixed path parts, not assembly or write-time protection.
      for (const part of path.split("/")) {
        if (/^<.*>$/.test(part)) continue;
        const pattern = new RegExp(`(?:^|/)${part.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*")}(?:/|$)`);
        assert.ok(literals.some((literal) => pattern.test(literal)), `${name}: source names ${part}`);
      }
    }
  }
});

// Source contract only: this does not prove installed encryption or recovery.
function checkBrowserRow(document) {
  const row = document.split("\n").find((line) => line.startsWith("| Browser profile:"));
  assert.ok(row, "Security must describe Browser profile storage");
  const [, data, encrypted, key, recovery] = row.split("|").map((cell) => cell.trim());
  const profilePath = browser.match(/let profile_uri = format!\("\{principal_root\}([^"\n]+)"\)/)?.[1];
  assert.ok(profilePath, "find the Browser profile path in its launch descriptor");
  assert.ok(data.includes(`\`Users/<person>${profilePath}\``), "document the path used by Browser launch");
  for (const flag of ["encrypted", "recoverable"]) {
    assert.match(browser, new RegExp(`\\b${flag}: false,`),
      `Browser ${flag} changed; review the storage table`);
  }
  assert.equal(encrypted, "No", "match the Browser encrypted flag");
  assert.equal(key, "None", "the unencrypted Browser disk has no storage key");
  assert.equal(recovery, "Omitted", "match Browser recovery exclusion");
  assert.match(read("elastos/crates/elastos-server/src/api/auth_gateway.rs"),
    /BrowserProfiles are VM lifecycle artifacts[\s\S]*?Neither is a principal-root protected object/);
}

test("Security Browser storage row matches the source descriptor", () => checkBrowserRow(security));

test("the storage check rejects false Browser path, encryption, and recovery claims", () => {
  const row = security.split("\n").find((line) => line.startsWith("| Browser profile:"));
  for (const falseRow of [
    row.replace("profile.ext4", "missing.ext4"),
    row.replace("| No |", "| Yes |"),
    row.replace("Omitted", "Data key; files separate"),
  ]) {
    assert.throws(() => checkBrowserRow(security.replace(row, falseRow)));
  }
});

function checkRecoveryCoverage(document) {
  const table = document.split("| Data and storage path |", 2)[1].split("\n\n", 1)[0];
  assert.match(table, /\| Recovery Kit restores \|/);
  for (const [name, coverage] of [
    ["Home recovery authority", "Home recovery authority and data key"],
    ["Contacts and Profile", "Profile identity and contacts present at export"],
    ["Built-in Wallet", "Built-in Wallet keys present at export"],
  ]) {
    const row = table.split("\n").find((line) => line.startsWith(`| ${name}`));
    assert.ok(row, `find the ${name} row`);
    const actual = row.split("|")[4].trim();
    if (name === "Home recovery authority") {
      assert.ok(actual.includes(coverage), `${name}: single-file export coverage`);
      assert.match(actual, /\bnot passkeys or sessions\b/i, "exclude sign-in state from recovery");
    } else {
      assert.equal(actual, coverage, `${name}: single-file export coverage`);
    }
  }
}

test("Security Recovery Kit coverage matches System's single-file export and product name", () => {
  const system = read("capsules/system/browser/system.js");
  const gateway = read("elastos/crates/elastos-server/src/api/gateway.rs");
  const auth = read("elastos/crates/elastos-server/src/api/auth_gateway.rs");
  assert.match(system, /setRecoveryButton\("Download Recovery Kit", false\)/);
  assert.match(system, /fetchJson\("\/api\/auth\/recovery\/full-export"/);
  for (const schema of ["elastos.full-recovery-bundle/v1", "elastos.full-recovery-bundle.package/v1"]) {
    assert.ok(system.includes(`importedSchema === "${schema}"`), `System imports ${schema}`);
  }
  assert.deepEqual([...gateway.matchAll(/"\/api\/auth\/recovery\/([^"\n]+)"/g)].map((match) => match[1]),
    ["status", "full-export", "full-import"]);
  assert.match(auth, /"data_kit": kit,/);
  assert.match(auth, /"wallet_recovery_keys": wallet_recovery_keys,/);
  assert.match(auth, /\.insert\("people_identity"\.to_string\(\), people_identity\)/);
  checkRecoveryCoverage(security);
  for (const path of ["SECURITY.md", "docs/INSTALL.md", "docs/GLOSSARY.md", "docs/STORAGE_AND_ACCESS.md"]) {
    assert.doesNotMatch(read(path), /full (?:recovery )?bundle/i,
      `${path}: use System's Recovery Kit name for the recovery file`);
  }
});

test("the recovery coverage check rejects the internal-record-only description", () => {
  assert.throws(() => checkRecoveryCoverage(security.replace(
    "Profile identity and contacts present at export", "Data key; files separate",
  )));
});

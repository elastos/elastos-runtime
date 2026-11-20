import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const security = read("SECURITY.md");
const browser = read("elastos/crates/elastos-server/src/api/gateway_browser.rs");

const STORAGE_TABLE_ROWS = [
  {
    name: "Home recovery authority",
    encrypted: "Recovery material only; other auth state is plain",
    recovery: "Home recovery authority and data key (not passkeys or sessions)",
    recoveryPartial: true,
  },
  {
    name: "Assistant conversations",
    encrypted: "Yes; answers also appear in model run records",
    recovery: "Data key; files separate",
  },
  {
    name: "Direct messages",
    encrypted: "Yes",
    recovery: "Data key; files separate",
  },
  {
    name: "Community history",
    encrypted: "No",
    recovery: "Omitted",
  },
  {
    name: "Contacts and Profile",
    encrypted: "Yes",
    recovery: "Profile identity and contacts present at export",
  },
  {
    name: "Documents:",
    encrypted:
      "Bodies Home writes after protection exists; existing files over 16 MiB and over batch limits stay plain until re-written; metadata and published bytes are plain",
    recovery: "Data key; files separate",
  },
  {
    name: "Library files",
    encrypted:
      "Private files/records Library writes after protection exists; earlier plain files outside declared migration folders can remain plain until Library migrates or rewrites them; published bytes and shared index are plain",
    recovery: "Data key; files separate",
  },
  {
    name: "Notifications:",
    encrypted: "No",
    recovery: "Omitted",
  },
  {
    name: "Built-in Wallet",
    encrypted: "Signing keys only; account and approval records are plain",
    recovery:
      "Active built-in Wallet account keys at export; export a key before removing an account",
  },
  {
    name: "Browser profile:",
    encrypted: "No",
    recovery: "Omitted",
  },
  {
    name: "Model run records:",
    encrypted: "No; retains answers, events, and a hash of the input under its retention policy",
    recovery: "Omitted",
  },
  {
    name: "Model provider credentials:",
    encrypted: "No; files restricted to the host account",
    recovery: "Omitted",
  },
  {
    name: "Home settings:",
    encrypted:
      "Settings Home writes after protection exists; same in-place limits as Documents; browser preferences are separate",
    recovery: "Data key; files separate",
  },
];

function storageTable(document) {
  const table = document.split("| Data and storage path |", 2)[1].split("\n\n", 1)[0];
  assert.match(table, /\| Recovery Kit restores \|/);
  return table;
}

function rowCells(document, rowPrefix) {
  const table = storageTable(document);
  const row = table.split("\n").find((line) => line.startsWith(`| ${rowPrefix}`));
  assert.ok(row, `find the ${rowPrefix} row`);
  const cells = row.split("|").map((cell) => cell.trim());
  return { row, encrypted: cells[2], recovery: cells[4] };
}

export function checkStorageTableCells(document) {
  for (const expected of STORAGE_TABLE_ROWS) {
    const { encrypted, recovery } = rowCells(document, expected.name);
    assert.equal(encrypted, expected.encrypted, `${expected.name}: encrypted column`);
    if (expected.recoveryPartial) {
      assert.ok(recovery.includes("Home recovery authority and data key"), `${expected.name}: recovery`);
      assert.match(recovery, /\bnot passkeys or sessions\b/i, "exclude sign-in state from recovery");
    } else {
      assert.equal(recovery, expected.recovery, `${expected.name}: recovery column`);
    }
  }
}

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
  const table = securityTableSlice(security);
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

function securityTableSlice(document) {
  return document.split("| Data and storage path |", 2)[1].split("\n\n", 1)[0];
}

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

test("Security storage table locked encrypted and recovery cells", () => checkStorageTableCells(security));

test("the storage table check rejects false encrypted and recovery cells", () => {
  const documents = rowCells(security, "Documents:");
  const mutatedEncrypted = security.replace(
    documents.row,
    documents.row.replace(documents.encrypted, "All document files encrypted on disk"),
  );
  assert.throws(() => checkStorageTableCells(mutatedEncrypted), /encrypted column/);

  const community = rowCells(security, "Community history");
  const mutatedRecovery = security.replace(
    community.row,
    community.row.replace(community.recovery, "All community history"),
  );
  assert.throws(() => checkStorageTableCells(mutatedRecovery), /recovery column/);
});

test("Security Recovery Kit export markers, product name, and storage table cells", () => {
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
  assert.doesNotMatch(auth, /"community_history"/,
    "full export must not claim Community history in the bundle object");
  checkStorageTableCells(security);
  for (const path of ["SECURITY.md", "docs/INSTALL.md", "docs/GLOSSARY.md", "docs/STORAGE_AND_ACCESS.md"]) {
    assert.doesNotMatch(read(path), /full (?:recovery )?bundle/i,
      `${path}: use System's Recovery Kit name for the recovery file`);
    assert.match(
      read(path),
      /new passkey[\s\S]{0,120}does not[\s\S]{0,24}replace/i,
      `${path}: passkey does not rotate Profile or Wallet keys restored from the Kit`,
    );
  }
});

test("the recovery coverage check rejects the internal-record-only description", () => {
  assert.throws(() => checkStorageTableCells(security.replace(
    "Profile identity and contacts present at export", "Data key; files separate",
  )));
});
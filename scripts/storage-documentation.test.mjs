// Exact storage-table cell comparison is the strong check. Wording lists reject
// known false sentences only; a pass does not prove every recovery sentence true.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(resolve(repo, path), "utf8");

export function trackedDocumentationPaths() {
  const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: repo })
    .toString()
    .split("\0")
    .filter(Boolean);
  return tracked.filter(
    (path) =>
      (path.endsWith(".md") && path !== "elastos/CHANGELOG.md")
      || path.startsWith("website/"),
  );
}
const security = read("SECURITY.md");
const browser = read("elastos/crates/elastos-server/src/api/gateway_browser.rs");

const PRINCIPAL_ROOT_ENCRYPTION_LEAD =
  "After protection exists, Home encrypts a write only when the write goes through\nprincipal-root protection.";

const UPLOAD_STAGING_WARNING =
  "An interrupted upload over 512 KiB can leave a readable copy in Home's `Runtime/ObjectUploadSessions/<id>/payload.bin`; finish or restart it, and the next chunked upload after 24 hours of inactivity attempts cleanup.";

// Exact wording check only; this does not exercise upload cleanup or encryption.
function checkUploadStagingWarning(document) {
  assert.ok(document.replace(/\s+/g, " ").includes(UPLOAD_STAGING_WARNING),
    "Library re-upload advice must include the qualified upload staging warning");
}

const STORAGE_TABLE_ROWS = [
  {
    name: "Home recovery authority",
    encrypted: "Recovery material only; other auth state is plain",
    recovery: "Home recovery authority and data key (not passkeys or sessions)",
  },
  {
    name: "Assistant conversations",
    encrypted: "Yes; answers also appear in model run records",
    recovery: "Data key; files separate",
  },
  {
    name: "Direct messages",
    encrypted: "Yes for a Chat service write. A copied plain file at this path stays plain, and Home still starts.",
    recovery: "Data key; files separate",
  },
  {
    name: "Community history",
    encrypted: "No",
    recovery: "Omitted",
  },
  {
    name: "Contacts and Profile",
    encrypted: "Yes for Home-written bodies; a copied plain file stays plain until re-written",
    recovery: "Profile identity and contacts present at export",
  },
  {
    name: "Documents:",
    encrypted:
      "Bodies Home writes after protection exists use principal-root protection; existing files stay plain if over 16 MiB or if the batch is over 64 files or 64 MiB until re-written; only plain files inside scanned roots for these reasons block Kit export; metadata and published bytes are plain",
    recovery: "Data key; files separate",
  },
  {
    name: "Library files",
    encrypted:
      "Private files and records Library writes after protection exists use principal-root protection; an earlier plain file stays plain if it is over 16 MiB, if its batch is over 64 files or 64 MiB, or if it is outside the migration folders; only plain files inside scanned roots block Kit export; files outside those roots remain unchecked and may stay plain; published bytes and shared index are plain",
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
      "Settings Home writes after protection exists use principal-root protection, including `preferences.json`; same in-place limits as Documents; the Browser profile disk stays plain",
    recovery: "Data key; files separate",
  },
];

const STOLEN_DEVICE_FORBIDDEN = /stolen device or profile key requires a new identity/i;
const PASSKEY_DOES_NOT_REPLACE =
  /new passkey[\s\S]{0,120}does not[\s\S]{0,24}replace/i;
const KIT_REJECT_COMBINED_USER_ROOT_EVERY_KEY_WORDINGS =
  /restores the encrypted user root and every|encrypted user root and every recoverable/i;
const KIT_REJECT_USER_FILE_RESTORE_WORDINGS =
  /(?:Recovery Kit|The Recovery Kit)\s+(?:restores|(?:will|can)\s+restore)\s+(?:all\s+)?(?:your\s+)?(?:(?:Library|library)\s+)?files\b|(?:Recovery Kit|The Recovery Kit)\s+restores\s+(?:all\s+)?(?:your\s+)?(?:documents|photos|Desktop files|files|everything|the\s+Library|the\s+whole\s+Home)\b|(?:Recovery Kit|The Recovery Kit)\s+restores\s+every\s+file\s+in\s+the\s+encrypted\s+user\s+root/i;
const KIT_REJECT_EXTERNAL_WALLET_LINK_WORDINGS =
  /(?:Recovery Kit|The Recovery Kit)\s+restores[^.\n]{0,200}\b(?:MetaMask|WalletConnect|Ledger|Essentials|UniSat|Brave|Phantom|external[- ]wallet)\b[^.\n]{0,120}\blinks?\b|(?:Recovery Kit|The Recovery Kit)\s+can\s+restore\s+(?:your\s+)?(?:MetaMask|WalletConnect|Ledger|Essentials|UniSat|Brave|Phantom)\s+links?\b|restore only their links(?:\/metadata)?/i;
const UNINSTALL_REJECT_WHOLE_COMPUTER_DELETION_WORDING =
  /deletes your identity, wallets,?\s+and recovery material on this computer/i;

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
    assert.equal(recovery, expected.recovery, `${expected.name}: recovery column`);
  }
}

export function checkPrincipalRootEncryptionLead(document) {
  assert.ok(
    document.includes(PRINCIPAL_ROOT_ENCRYPTION_LEAD),
    "SECURITY must name principal-root protection instead of whole-Home encryption",
  );
  assert.doesNotMatch(
    document,
    /After protection exists, Home encrypts each file it writes/,
    "SECURITY must not promise encryption for every write",
  );
}

export function checkRecoveryStolenDeviceStatements(
  paths = trackedDocumentationPaths(),
  readDocument = read,
) {
  for (const path of paths) {
    const document = readDocument(path);
    assert.doesNotMatch(
      document,
      STOLEN_DEVICE_FORBIDDEN,
      `${path}: stolen-device recovery must not require a new identity`,
    );
    if (
      !/Recovery Kit restores the same Profile|a Recovery Kit copy was stolen|stolen device or profile key/i.test(
        document,
      )
    ) {
      continue;
    }
    assert.match(
      document,
      PASSKEY_DOES_NOT_REPLACE,
      `${path}: passkey does not rotate Profile or Wallet keys restored from the Kit`,
    );
  }
}

export function checkRejectsListedKitCombinedUserRootEveryKeyWordings(
  paths = trackedDocumentationPaths(),
  readDocument = read,
) {
  for (const path of paths) {
    const document = readDocument(path);
    assert.doesNotMatch(
      document,
      KIT_REJECT_COMBINED_USER_ROOT_EVERY_KEY_WORDINGS,
      `${path}: Rejects the two listed combined encrypted-user-root/every-key wording patterns.`,
    );
  }
}

export function checkRejectsListedKitUserFileRestoreWordings(
  paths = trackedDocumentationPaths(),
  readDocument = read,
) {
  for (const path of paths) {
    const document = readDocument(path);
    assert.doesNotMatch(
      document,
      KIT_REJECT_USER_FILE_RESTORE_WORDINGS,
      `${path}: rejects these listed wordings about the Recovery Kit restoring user, Library, or whole-Home files`,
    );
  }
}

/** @deprecated use checkRejectsListedKitUserFileRestoreWordings */
export const checkKitMustNotClaimUserFileRestore = checkRejectsListedKitUserFileRestoreWordings;

export function checkRejectsListedKitExternalWalletLinkWordings(
  paths = trackedDocumentationPaths(),
  readDocument = read,
) {
  for (const path of paths) {
    const document = readDocument(path);
    assert.doesNotMatch(
      document,
      KIT_REJECT_EXTERNAL_WALLET_LINK_WORDINGS,
      `${path}: rejects these listed wordings about the Recovery Kit restoring external-wallet links`,
    );
  }
}

/** @deprecated use checkRejectsListedKitExternalWalletLinkWordings */
export const checkKitMustNotClaimExternalWalletLinkRestore = checkRejectsListedKitExternalWalletLinkWordings;

export const checkExternalWalletLinksNotRestoredByKit = checkRejectsListedKitExternalWalletLinkWordings;

export function checkRejectsListedUninstallWholeComputerDeletionWordings(
  paths = trackedDocumentationPaths(),
  readDocument = read,
) {
  for (const path of paths) {
    const document = readDocument(path);
    assert.doesNotMatch(
      document,
      UNINSTALL_REJECT_WHOLE_COMPUTER_DELETION_WORDING,
      `${path}: rejects these listed wordings about uninstall deleting every recovery file on the computer`,
    );
  }
}

/** @deprecated use checkRejectsListedUninstallWholeComputerDeletionWordings */
export const checkUninstallScopeHonest = checkRejectsListedUninstallWholeComputerDeletionWordings;

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

test("Security storage table locks every encrypted and recovery cell exactly", () => {
  checkStorageTableCells(security);
  checkPrincipalRootEncryptionLead(security);
});

test("Library re-upload advice includes the exact upload staging warning in both documents", () => {
  for (const path of ["SECURITY.md", "docs/PROTECTED_CONTENT.md"]) {
    checkUploadStagingWarning(read(path));
  }
});

test("the upload warning wording check rejects missing and overstated cleanup advice", () => {
  for (const warning of [
    "",
    UPLOAD_STAGING_WARNING.replace("over 512 KiB", "of any size"),
    UPLOAD_STAGING_WARNING.replace("finish or restart it, and ", ""),
    UPLOAD_STAGING_WARNING.replace("next chunked upload", "next upload"),
    UPLOAD_STAGING_WARNING.replace("after 24 hours of inactivity", "immediately"),
    UPLOAD_STAGING_WARNING.replace("attempts cleanup", "always removes it"),
  ]) {
    assert.throws(() => checkUploadStagingWarning(warning), /upload staging warning/);
  }
});

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

  const messages = rowCells(security, "Direct messages");
  const unqualifiedMessages = security.replace(
    messages.row,
    messages.row.replace(messages.encrypted, "Yes"),
  );
  assert.throws(() => checkStorageTableCells(unqualifiedMessages), /Direct messages: encrypted column/);

  const home = rowCells(security, "Home recovery authority");
  const mutatedHomeRecovery = security.replace(
    home.row,
    home.row.replace(home.recovery, `${home.recovery}; restores all document files`),
  );
  assert.throws(() => checkStorageTableCells(mutatedHomeRecovery), /recovery column/);

  const library = rowCells(security, "Library files");
  const mutatedLibraryEncrypted = security.replace(
    library.row,
    library.row.replace(library.encrypted, "All Library files encrypted on disk"),
  );
  assert.throws(() => checkStorageTableCells(mutatedLibraryEncrypted), /encrypted column/);

  const strongerLead = security.replace(
    PRINCIPAL_ROOT_ENCRYPTION_LEAD,
    "After protection exists, Home encrypts each file it writes.",
  );
  assert.throws(() => checkPrincipalRootEncryptionLead(strongerLead));
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
  assert.match(
    auth,
    /download_password[\s\S]*?filter\(\|value\| !value\.is_empty\(\)\)[\s\S]*?None => bundle,/,
    "empty Kit password writes plain JSON",
  );
  assert.match(
    security,
    /leave the password empty[\s\S]{0,120}plain JSON that includes Wallet private keys, the recovery phrase/,
  );
  checkStorageTableCells(security);
  checkPrincipalRootEncryptionLead(security);
  checkRecoveryStolenDeviceStatements();
  checkRejectsListedKitCombinedUserRootEveryKeyWordings();
  checkRejectsListedKitUserFileRestoreWordings();
  checkRejectsListedKitExternalWalletLinkWordings();
  checkRejectsListedUninstallWholeComputerDeletionWordings();
  for (const path of ["SECURITY.md", "docs/INSTALL.md", "docs/GLOSSARY.md", "docs/STORAGE_AND_ACCESS.md"]) {
    assert.doesNotMatch(read(path), /full (?:recovery )?bundle/i,
      `${path}: use System's Recovery Kit name for the recovery file`);
  }
});

test("the recovery coverage check rejects the internal-record-only description", () => {
  assert.throws(() => checkStorageTableCells(security.replace(
    "Profile identity and contacts present at export", "Data key; files separate",
  )));
});

test("the recovery stolen-device check rejects a restored new-identity claim", () => {
  const path = "docs/ARCHITECTURE.md";
  const mutated = `${read(path)}\nRecovery from a stolen device or profile key requires a new identity.`;
  assert.throws(
    () => checkRecoveryStolenDeviceStatements([path], () => mutated),
    /stolen-device recovery/,
  );
});

test("The stolen-device wording check scans tracked Markdown except elastos/CHANGELOG.md, plus tracked website files.", () => {
  checkRecoveryStolenDeviceStatements();
  assert.ok(!trackedDocumentationPaths().includes("elastos/CHANGELOG.md"));
  const outsideEight = trackedDocumentationPaths().find(
    (path) => !["SECURITY.md", "docs/INSTALL.md", "docs/GLOSSARY.md", "docs/STORAGE_AND_ACCESS.md",
      "docs/ARCHITECTURE.md", "docs/CAPSULE_MODEL.md", "docs/CAPSULE_AUTHORING.md", "README.md"].includes(path)
      && path.endsWith(".md"),
  );
  assert.ok(outsideEight, "find a tracked markdown file outside the original eight");
  const mutated = `${read(outsideEight)}\nRecovery from a stolen device or profile key requires a new identity.`;
  assert.throws(
    () => checkRecoveryStolenDeviceStatements([outsideEight], () => mutated),
    /stolen-device recovery/,
  );
});

test("the Kit wording check rejects the two listed combined encrypted-user-root/every-key patterns", () => {
  checkRejectsListedKitCombinedUserRootEveryKeyWordings();
  const probe = "docs/WALLET_PROVIDER.md";
  for (const wording of [
    "The Recovery Kit restores the encrypted user root and every built-in Wallet key.",
    "The Recovery Kit contains the encrypted user root and every recoverable key.",
  ]) {
    assert.throws(
      () => checkRejectsListedKitCombinedUserRootEveryKeyWordings([probe], () => wording),
      /Rejects the two listed combined encrypted-user-root\/every-key wording patterns/,
    );
  }
  for (const wording of [
    "The Recovery Kit restores the encrypted user root.",
    "The Recovery Kit restores every recoverable key.",
  ]) {
    assert.doesNotThrow(
      () => checkRejectsListedKitCombinedUserRootEveryKeyWordings([probe], () => wording),
      "separate claims are outside this wording list; acceptance here is not a truth verdict",
    );
  }
});

test("the Kit user-file wording list rejects round-six counterexamples", () => {
  const probe = "docs/STORAGE_AND_ACCESS.md";
  const variants = [
    "The Recovery Kit restores all your documents.",
    "The Recovery Kit can restore all your Library files.",
    "The Recovery Kit restores your photos.",
    "The Recovery Kit restores your Desktop files.",
    "The Recovery Kit will restore your files.",
    "The Recovery Kit restores every file in the encrypted user root.",
    "The Recovery Kit restores your documents.",
    "The Recovery Kit restores the Library.",
    "The Recovery Kit restores everything.",
    "The Recovery Kit restores the whole Home.",
    "The Recovery Kit restores your files.",
    "The Recovery Kit restores all your Library files.",
  ];
  for (const sentence of variants) {
    const mutated = `${read(probe)}\n${sentence}`;
    assert.throws(
      () => checkRejectsListedKitUserFileRestoreWordings([probe], () => mutated),
      /listed wordings about the Recovery Kit restoring user/,
      sentence,
    );
  }
  checkRejectsListedKitUserFileRestoreWordings();
});

test("the Kit external-wallet wording list rejects round-six counterexamples", () => {
  const probe = "docs/WALLET_PROVIDER.md";
  const variants = [
    "The Recovery Kit restores your external-wallet links.",
    "The Recovery Kit restores your external wallet links.",
    "The Recovery Kit restores Brave and Phantom links.",
    "The Recovery Kit can restore your MetaMask links.",
    "The Recovery Kit restores your MetaMask and WalletConnect links.",
    "External wallets such as MetaMask restore only their links/metadata because their private keys stay in those wallets.",
  ];
  for (const sentence of variants) {
    const mutated = `${read(probe)}\n${sentence}`;
    assert.throws(
      () => checkRejectsListedKitExternalWalletLinkWordings([probe], () => mutated),
      /listed wordings about the Recovery Kit restoring external-wallet links/,
      sentence,
    );
  }
  checkRejectsListedKitExternalWalletLinkWordings();
});

test("the uninstall wording list rejects the round-six whole-computer deletion sentence", () => {
  checkRejectsListedUninstallWholeComputerDeletionWordings();
  const probe = "docs/INSTALL.md";
  for (const sentence of [
    "This deletes your identity, wallets and recovery material on this computer.",
    "Uninstall deletes your identity, wallets, and recovery material on this computer.",
  ]) {
    const mutated = `${read(probe)}\n${sentence}`;
    assert.throws(
      () => checkRejectsListedUninstallWholeComputerDeletionWordings([probe], () => mutated),
      /listed wordings about uninstall deleting every recovery file/,
      sentence,
    );
  }
});

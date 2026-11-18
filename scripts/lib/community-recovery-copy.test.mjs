import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { assertCommunityRecoveryCopy } from "./community-recovery-copy.mjs";

for (const text of [
  "Chat shows **Community can't connect. Restart Home to reconnect.**",
  "Chat shows Community can’t connect. Restart Home to reconnect.",
  "Home has used up\nits repairs (#451).",
  "Each process requests at most\n120 replacements. Runtime counts each request.",
  "The limit is 120 replacements per process.",
]) {
  test(`standing Community guidance rejects retired copy: ${text}`, () => {
    assert.throws(() => assertCommunityRecoveryCopy("standing.md", text), /permanent Community repair exhaustion/);
  });
}

test("standing Community guidance permits paced recovery and the silent-neighbour limitation", () => {
  assert.doesNotThrow(() => assertCommunityRecoveryCopy("standing.md",
    "Home is reconnecting to Community. Next check in 5 seconds. Repair continues for the life of Home. A silent remembered neighbour remains open."));
});

for (const path of ["docs/COLLABORATION_NETWORK_PROFILE.md", "docs/TROUBLESHOOTING.md"]) {
  test(`the real copy checker enforces Community recovery guidance in ${path}`, t => {
    const root = mkdtempSync(join(tmpdir(), "community-copy-"));
    t.after(() => rmSync(root, { recursive: true }));
    const shim = join(root, "old-guidance.mjs");
    writeFileSync(shim, `import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
const read = fs.readFileSync;
fs.readFileSync = (path, ...args) => String(path).endsWith(${JSON.stringify(`/${path}`)})
  ? "Home has used up its repairs (#451)." : read(path, ...args);
syncBuiltinESMExports();\n`);
    const result = spawnSync(process.execPath, ["--import", pathToFileURL(shim).href,
      new URL("../public-copy-entropy-check.mjs", import.meta.url).pathname],
    { encoding: "utf8", timeout: 10000 });
    assert.equal(result.status, 1, result.stderr || result.stdout);
    assert.ok(result.stderr.includes(`${path} restores permanent Community repair exhaustion`), result.stderr);
  });
}

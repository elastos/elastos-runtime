import assert from "node:assert/strict";
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

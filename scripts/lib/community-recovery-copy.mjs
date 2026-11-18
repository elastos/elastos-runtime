const retiredRecoveryCopy = /Community (?:can't|can’t) connect\. Restart Home to reconnect\.|Home has used up its repairs|Each process requests at most \d+ replacements|\d+ replacements per process/i;

export function assertCommunityRecoveryCopy(path, text) {
  const plain = text.replace(/\*+/g, "").replace(/\s+/g, " ");
  if (retiredRecoveryCopy.test(plain)) {
    throw new Error(`${path} restores permanent Community repair exhaustion or restart guidance`);
  }
}

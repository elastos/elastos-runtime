import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

// Fixture keys name the original commit and path; runtime tests need no Git history.
const { files } = JSON.parse(readFileSync(new URL('../fixtures/historical-test-sources.json', import.meta.url), 'utf8'));
export function historicalTestSource(key) {
  const file = files[key];
  assert.ok(file, `Missing historical fixture: ${key}`);
  assert.equal(createHash('sha256').update(file.source).digest('hex'), file.sha256, key);
  return file.source;
}

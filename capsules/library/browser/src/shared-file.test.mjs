import assert from 'node:assert/strict';
import test from 'node:test';
import * as shared from './shared-file.js';

test('Library shows the exact local CID with a download control', () => {
  const cid = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3w2pz3hftb5xg3mh5g4xq7y5u';
  const markup = shared.sharedFileMarkup(cid);
  assert.ok(markup.includes(`elastos://${cid}`));
  assert.ok(markup.includes('data-shared-download>Download file</button>'));
});

test('Library escapes link text and never links the frame to /content', () => {
  const markup = shared.sharedFileMarkup('bad"/><script>');
  assert.ok(!markup.includes('<script>'));
  assert.ok(!markup.includes('href='));
  assert.ok(!markup.includes('download='));
});

test('Library shows known shared-file sizes with the common decimal rule', () => {
  for (const [bytes, label] of [[0, '0 B'], [999, '999 B'], [1000, '1.0 KB'], [1000000, '1.0 MB'], [144834897, '144.8 MB'], [1500000000, '1.50 GB']]) {
    assert.ok(shared.sharedFileMarkup('cid', String(bytes)).includes(`<p>Size: ${label}</p>`));
  }
  for (const size of [null, undefined, '', 'bad', '-1']) {
    assert.ok(!shared.sharedFileMarkup('cid', size).includes('<p>Size:'));
  }
});

import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { scenarios, caseIds } from './scenarios.mjs';
import { projectCase } from './recording-source.mjs';

export function importRecordings(bytes) {
  const raw = JSON.parse(bytes);
  const ids = new Set(Object.values(scenarios).flatMap(caseIds));
  for (const id of ['R2-MM-independent-confirm', 'R2-MM-independent-late75', 'R2-MM-independent-queue']) ids.add(id);
  const cases = [...ids].map((id) => {
    const matches = raw.cases.filter((c) => c.id === id);
    if (matches.length !== 1) throw new Error(`Expected one raw case: ${id}`);
    return projectCase(matches[0]);
  });
  return {
    schema: 'elastos.test.wallet-extension-replay/v1',
    source: { sha256: createHash('sha256').update(bytes).digest('hex'), caseCount: raw.cases.length,
      productCommit: raw.provenance.product_commit,
      extensions: [...raw.provenance.extensions, ...raw.round2.extensions].filter((v, i, a) => a.findIndex((x) => x.name === v.name) === i)
        .map(({ name, version, sha256 }) => ({ name, version, sha256 })),
      clock: 'Virtual milliseconds from each call; negative since_call_ms is prior history. Action marks are observation times, not exact click times.',
      limits: ['Only recorded parameters and finite request sequences are supported.',
        'Pending-only calls remain pending; no eventual response was recorded.',
        'Recorded stack property names are preserved; stack text was not captured.',
        'Configured Brave Wallet, mobile WalletConnect and malformed UniSat chain enums have no replay.'],
    }, cases,
  };
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  if (process.argv.length !== 3) throw new Error('Usage: node import-recordings.mjs <original-recordings.json>');
  const fixture = importRecordings(await readFile(process.argv[2]));
  await writeFile(new URL('../fixtures/wallet-extension-replay.json', import.meta.url), `${JSON.stringify(fixture, null, 2)}\n`);
  console.log(`Imported ${fixture.cases.length} raw cases; source SHA-256 ${fixture.source.sha256}`);
}

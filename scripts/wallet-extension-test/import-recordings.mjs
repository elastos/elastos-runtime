import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { scenarios, caseIds } from './scenarios.mjs';
import { approvedRawSha256, projectCase, providerBindings, recordedProvider, recordedActionPins, validateScenarios } from './recording-source.mjs';

export function importRecordings(bytes) {
  const raw = JSON.parse(bytes);
  for (const c of raw.cases) for (const s of c.snapshots) {
    if (s.call) recordedProvider(s.call.target || s.call.kind);
    for (const event of s.events || []) recordedProvider(event.provider);
    const observation = s.observation;
    if (observation && typeof observation === 'object') for (const key of ['announcements', 'new_announcements'])
      for (const announcement of observation[key] || []) recordedProvider(announcement.info.rdns);
  }
  const ids = new Set(Object.values(scenarios).flatMap(caseIds));
  for (const id of ['R2-MM-independent-confirm', 'R2-MM-independent-late75', 'R2-MM-independent-queue']) ids.add(id);
  ids.add('R2-BOTH-legacy-shape');
  const cases = [...ids].map((id) => {
    const matches = raw.cases.filter((c) => c.id === id);
    if (matches.length !== 1) throw new Error(`Expected one raw case: ${id}`);
    return projectCase(matches[0]);
  });
  const fixture = {
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
    }, providerBindings,
    surfaces: Object.fromEntries([['unisat', 'US-10-presence'], ['legacy', 'R2-BOTH-legacy-shape']].map(([provider, id]) => {
      const observation = raw.cases.find((c) => c.id === id).snapshots.find((s) => s.observation).observation;
      return [provider, { caseId: id, keys: observation.keys, methods: observation.methods ?? null }];
    })), cases,
  };
  validateScenarios(fixture, scenarios, recordedActionPins(raw.cases, scenarios));
  return fixture;
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  if (process.argv.length !== 3) throw new Error('Usage: node import-recordings.mjs <original-recordings.json>');
  const fixture = importRecordings(await readFile(process.argv[2]));
  const bytes = `${JSON.stringify(fixture, null, 2)}\n`;
  const pinUrl = new URL('./recording-pin.json', import.meta.url);
  if (fixture.source.sha256 !== approvedRawSha256) throw new Error('Raw recording differs from the approved capture; review before updating the raw pin');
  await writeFile(new URL('../fixtures/wallet-extension-replay.json', import.meta.url), bytes);
  await writeFile(pinUrl, `${JSON.stringify({ rawSha256: fixture.source.sha256,
    fixtureSha256: createHash('sha256').update(bytes).digest('hex'),
    scenariosSha256: createHash('sha256').update(JSON.stringify(scenarios)).digest('hex'),
    rejections: Object.fromEntries(fixture.cases.flatMap((entry) => {
      const call = entry.snapshots.filter((s) => s.call).at(-1)?.call;
      return call?.state === 'rejected' ? [[entry.id, createHash('sha256').update(JSON.stringify(call.error)).digest('hex')]] : [];
    })), actions: recordedActionPins(fixture.cases, scenarios) }, null, 2)}\n`);
  console.log(`Imported ${fixture.cases.length} raw cases; source SHA-256 ${fixture.source.sha256}`);
}

import { readFile } from 'node:fs/promises';
import { scenarios } from './scenarios.mjs';
import { createHash } from 'node:crypto';
import { approvedRawSha256, validateScenarios } from './recording-source.mjs';
export { installScriptedExtension } from './replay.mjs';
export { scenarios } from './scenarios.mjs';

export async function replayInput(name) {
  if (!Object.hasOwn(scenarios, name)) throw new Error(`Unrecorded scenario: ${name}`);
  const bytes = await readFile(new URL('../fixtures/wallet-extension-replay.json', import.meta.url));
  const pin = JSON.parse(await readFile(new URL('./recording-pin.json', import.meta.url), 'utf8'));
  if (createHash('sha256').update(bytes).digest('hex') !== pin.fixtureSha256) throw new Error('Replay fixture integrity failure: regenerate with the approved raw capture');
  if (createHash('sha256').update(JSON.stringify(scenarios)).digest('hex') !== pin.scenariosSha256) throw new Error('Scenario mapping integrity failure: regenerate with the approved raw capture');
  const fixture = JSON.parse(bytes.toString('utf8'));
  if (fixture.source.sha256 !== approvedRawSha256 || pin.rawSha256 !== approvedRawSha256) throw new Error('Raw source pin mismatch');
  validateScenarios(fixture, scenarios, pin.actions);
  return { fixture, spec: scenarios[name] };
}

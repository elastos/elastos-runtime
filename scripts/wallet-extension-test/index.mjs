import { readFile } from 'node:fs/promises';
import { scenarios } from './scenarios.mjs';
export { installScriptedExtension } from './replay.mjs';
export { scenarios } from './scenarios.mjs';

export async function replayInput(name) {
  if (!Object.hasOwn(scenarios, name)) throw new Error(`Unrecorded scenario: ${name}`);
  const fixture = JSON.parse(await readFile(new URL('../fixtures/wallet-extension-replay.json', import.meta.url), 'utf8'));
  return { fixture, spec: scenarios[name] };
}

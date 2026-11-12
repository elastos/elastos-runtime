#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// -B prevents writes but still permits cache loads. A prefix beneath the
// root-owned /dev/null device cannot contain files, so source cache lookup
// always misses, including before a Home exists. CPython handles ENOTDIR as a
// cache miss. Legacy module.pyc bypasses the prefix and is refused separately.
function refuseSourceless(directory) {
  let root;
  try { root = fs.lstatSync(directory); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (!root.isDirectory()) throw new Error(`Python release directory requires repair: ${directory}`);
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      if (entry.name.endsWith('.pyc') || fs.statSync(file).isDirectory()) {
        throw new Error(`Python release link requires repair: ${file}`);
      }
    } else if (entry.isDirectory()) {
      refuseSourceless(file);
    } else if (entry.name.endsWith('.pyc') && path.basename(directory) !== '__pycache__') {
      throw new Error(`Python release contains sourceless byte-code: ${file}. Restore its source from the verified release.`);
    }
  }
}

export function browserPythonCommand(dataDir, command, args) {
  const data = path.resolve(dataDir);
  const barrier = fs.lstatSync('/dev/null');
  if (!barrier.isCharacterDevice() || barrier.uid !== 0) {
    throw new Error('Python cache protection requires the root-owned /dev/null device.');
  }
  const cache = '/dev/null/elastos-python';
  for (const relative of ['libexec/browser/python3', 'capsules/python3', 'scripts']) {
    refuseSourceless(path.join(data, relative));
  }
  // Setup can inspect a bundle from another Home before its destination exists.
  const candidates = command.includes('/') ? [path.resolve(command)]
    : (process.env.PATH ?? '').split(path.delimiter).map(dir => path.resolve(dir || '.', command));
  for (const candidate of candidates) {
    try { fs.accessSync(candidate, fs.constants.X_OK); } catch { continue; }
    if (!fs.statSync(candidate).isFile()) continue;
    const interpreter = fs.realpathSync(candidate);
    if (interpreter.includes('/libexec/browser/python3/') || interpreter.includes('/capsules/python3/')) {
      refuseSourceless(path.dirname(path.dirname(interpreter)));
    }
    break;
  }
  return { command, args: ['-I', '-B', '-X', `pycache_prefix=${cache}`, ...args] };
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [, , data, python, ...args] = process.argv;
    const command = browserPythonCommand(data, python, args);
    const result = spawnSync(command.command, command.args, { stdio: 'inherit' });
    if (result.error) throw result.error;
    process.exitCode = result.status ?? 1;
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

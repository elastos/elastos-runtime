import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

// Run the shipped entry point, including its interpreter and cache policy.
test('bundled Python ignores old adjacent caches and refuses sourceless bytecode', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bundled-python-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const data = path.join(root, 'home');
  const release = path.join(data, 'libexec/browser/python3/fixture');
  fs.mkdirSync(path.join(release, 'bin'), { recursive: true });
  const lib = path.join(release, 'lib');
  fs.mkdirSync(lib);
  const python = path.join(release, 'bin/python3');
  const real = spawnSync('sh', ['-c', 'command -v python3'], { encoding: 'utf8' }).stdout.trim();
  fs.writeFileSync(python, `#!/bin/sh\nexec '${real}' "$@"\n`, { mode: 0o755 });
  const module = path.join(lib, 'victim.py');
  fs.writeFileSync(module, "value = 'cache!'\n");
  const compile = spawnSync(real, ['-I', '-c', 'import py_compile,sys; py_compile.compile(sys.argv[1], doraise=True)', module], { encoding: 'utf8' });
  assert.equal(compile.status, 0, compile.stderr);
  const mtime = fs.statSync(module).mtime;
  fs.writeFileSync(module, "value = 'source'\n");
  fs.utimesSync(module, mtime, mtime);
  fs.writeFileSync(path.join(lib, 'uncached.py'), "value = 42\n");
  const code = `import sys; sys.path.insert(0, ${JSON.stringify(lib)}); import victim, uncached; print(victim.value); import json, urllib.request`;
  const run = () => spawnSync(process.execPath, ['scripts/browser-python.mjs', data, python, '-c', code], { encoding: 'utf8' });
  const snapshot = () => fs.readdirSync(path.join(lib, '__pycache__')).map(n => [n, fs.readFileSync(path.join(lib, '__pycache__', n)).toString('hex')]);
  const before = snapshot();
  const output = run();
  assert.equal(output.status, 0, output.stderr);
  assert.equal(output.stdout.trim(), 'source');
  assert.deepEqual(snapshot(), before);
  const cached = path.join(lib, '__pycache__', fs.readdirSync(path.join(lib, '__pycache__'))[0]);
  fs.copyFileSync(cached, path.join(lib, 'victim.pyc'));
  fs.unlinkSync(module);
  const sourceless = run();
  assert.notEqual(sourceless.status, 0);
  assert.match(sourceless.stderr, /sourceless byte-code/);
  assert.equal(sourceless.stdout, '');
  const beforeInstall = spawnSync(process.execPath, ['scripts/browser-python.mjs', path.join(root, 'absent-home'), python, '-c', code], { encoding: 'utf8' });
  assert.notEqual(beforeInstall.status, 0, 'the selected bundle is checked even before the destination Home exists');
  assert.match(beforeInstall.stderr, /sourceless byte-code/);
  const viaPath = spawnSync(process.execPath, ['scripts/browser-python.mjs', path.join(root, 'absent-home'), 'python3', '-c', code], {
    encoding: 'utf8', env: { ...process.env, PATH: `${path.dirname(python)}${path.delimiter}${process.env.PATH}` },
  });
  assert.notEqual(viaPath.status, 0);
  assert.match(viaPath.stderr, /sourceless byte-code/);
});

test('the Python cache prefix cannot contain bytecode files', async t => {
  const { browserPythonCommand } = await import('./browser-python.mjs');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'python-cache-barrier-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const invocation = browserPythonCommand(root, 'python3', ['-c', 'pass']);
  const prefix = invocation.args[3].slice('pycache_prefix='.length);
  assert.throws(() => fs.openSync(path.join(prefix, 'cached.pyc'), 'wx'), { code: 'ENOTDIR' });
  assert.deepEqual(fs.readdirSync(root), []);
});

test('pre-install Python verification leaves an absent Home untouched', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'python-before-home-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, 'absent-home');
  const result = spawnSync(process.execPath, ['scripts/browser-python.mjs', home, 'python3', '-c',
    'import sys; print(sys.pycache_prefix)'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.existsSync(home), false);
  assert.equal(fs.existsSync(result.stdout.trim()), false, 'temporary cache was retired');
});

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const workflow = readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
const job = workflow.split('  test-elastos:\n')[1].split('\n  test-capsules:')[0];
const recipes = readFileSync(new URL('../justfile', import.meta.url), 'utf8');
const recipe = recipes.split('\nproduct-ui-capsule-browser:\n')[1].split('\n\n')[0];

function assertWorkspaceSelection(source) {
  const commands = [...source.matchAll(/cargo test ([^\n]+)/g)].map(match => match[1]);
  assert.ok(commands.length > 0, 'Cargo test commands exist');
  for (const command of commands) {
    assert.match(command, /^--workspace(?: |$)/, 'reuse the workspace feature graph');
    assert.doesNotMatch(command, /(?:^| )(?:-p\S*|-F\S*|--(?:package|exclude|features|no-default-features|all-features|profile|release)(?:=\S*)?)(?: |$)/,
      'keep the same package, feature and profile selection');
  }
}

test('capsule browser CI and recipe reuse the workspace test build', () => {
  assertWorkspaceSelection(job);
  assertWorkspaceSelection(recipe);
  const unit = job.indexOf('run: cargo test --workspace --no-fail-fast');
  const install = job.indexOf('- name: install content boundary browser fixture');
  const browser = job.indexOf('run: cargo test --workspace content_sandbox_browser -- --ignored --nocapture');
  assert.ok(unit >= 0 && install > unit && browser > install, 'unit build, engine install, then cached browser tests');
});

test('a package-only browser invocation changes the feature graph', () => {
  assert.throws(() => assertWorkspaceSelection('cargo test -p elastos-server content_sandbox_browser -- --ignored'),
    /reuse the workspace feature graph/);
});

test('feature and profile flag variants also change the build selection', () => {
  for (const flag of ['--features=x', '-F x', '--profile=release', '-pelastos-server']) {
    assert.throws(() => assertWorkspaceSelection(`cargo test --workspace ${flag} content_sandbox_browser -- --ignored`),
      /keep the same package, feature and profile selection/);
  }
});

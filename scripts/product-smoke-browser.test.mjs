import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { existsSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  behaviourInputsDir,
  playwrightCoreDir,
  productSmokeLaunchOptions,
} from "./product-smoke-browser.mjs";

test("behaviour cache paths follow test-behaviour.sh", () => {
  assert.equal(
    behaviourInputsDir({ HOME: "/home/tester" }),
    "/home/tester/.cache/elastos-runtime/behaviour",
  );
  assert.equal(
    behaviourInputsDir({ HOME: "/home/tester", RUNNER_TEMP: "/runner" }),
    "/runner/behaviour",
  );
  assert.equal(
    behaviourInputsDir({ BEHAVIOUR_INPUTS: "/inputs", RUNNER_TEMP: "/runner", HOME: "/home/tester" }),
    "/inputs",
  );
  assert.equal(
    playwrightCoreDir({ BEHAVIOUR_INPUTS: "/inputs" }),
    "/inputs/core/node_modules/playwright-core",
  );
  assert.equal(
    playwrightCoreDir({ BROWSER_OPERATOR_PLAYWRIGHT_CORE: "/core", BEHAVIOUR_INPUTS: "/inputs" }),
    "/core",
  );
});

test("BRAVE_BIN is the product smoke executable", () => {
  let called = false;
  const options = productSmokeLaunchOptions({ BRAVE_BIN: "/opt/brave" }, () => {
    called = true;
    return "/chromium";
  });
  assert.deepEqual(options, { executablePath: "/opt/brave" });
  assert.equal(called, false);
});

test("an empty BRAVE_BIN is not an explicit browser", () => {
  const dir = mkdtempSync(join(tmpdir(), "product-smoke-browser-"));
  const executablePath = join(dir, "chromium");
  writeFileSync(executablePath, "");
  try {
    assert.deepEqual(
      productSmokeLaunchOptions({ BRAVE_BIN: "" }, () => executablePath),
      { executablePath },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a missing Playwright Chromium leaves the executable unset", () => {
  assert.deepEqual(
    productSmokeLaunchOptions({}, () => join(tmpdir(), "missing-chromium-560")),
    {},
  );
});

test("a missing behaviour cache leaves the executable unset", () => {
  const error = new Error("Cannot find module");
  error.code = "MODULE_NOT_FOUND";
  assert.deepEqual(productSmokeLaunchOptions({}, () => { throw error; }), {});
});

test("a Playwright lookup failure other than a missing module is reported", () => {
  assert.throws(
    () => productSmokeLaunchOptions({}, () => { throw new Error("broken registry"); }),
    /broken registry/,
  );
});

function browserInstallDir(executablePath) {
  let dir = dirname(executablePath);
  while (!/^chromium(?:_headless_shell)?-\d+$/.test(basename(dir))) {
    const parent = dirname(dir);
    assert.notEqual(parent, dir, executablePath);
    dir = parent;
  }
  return dir;
}

function chooseFromInstallDir(browserDir, executable) {
  const scratch = mkdtempSync(join(tmpdir(), "behaviour-browsers-"));
  try {
    symlinkSync(browserDir, join(scratch, basename(browserDir)));
    assert.deepEqual(readdirSync(scratch), [basename(browserDir)]);
    const expected = join(scratch, basename(browserDir), relative(browserDir, executable));
    assert.equal(existsSync(expected), true, expected);
    const helper = pathToFileURL(fileURLToPath(new URL("./product-smoke-browser.mjs", import.meta.url))).href;
    const env = { ...process.env, PLAYWRIGHT_BROWSERS_PATH: scratch };
    delete env.BRAVE_BIN;
    const result = spawnSync(process.execPath, [
      "--input-type=module",
      "-e",
      `import { productSmokeLaunchOptions } from ${JSON.stringify(helper)};
       process.stdout.write(JSON.stringify(productSmokeLaunchOptions()));`,
    ], { env, encoding: "utf8", timeout: 15_000 });
    assert.equal(result.status, 0, result.stderr);
    return { options: JSON.parse(result.stdout), expected };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

test("unset BRAVE_BIN uses the installed behaviour-cache Chromium", () => {
  const env = {};
  for (const key of ["HOME", "RUNNER_TEMP", "BEHAVIOUR_INPUTS", "BROWSER_OPERATOR_PLAYWRIGHT_CORE", "PLAYWRIGHT_BROWSERS_PATH"]) {
    if (process.env[key]) env[key] = process.env[key];
  }
  const core = playwrightCoreDir(env);
  const packageJson = join(core, "package.json");
  const options = productSmokeLaunchOptions(env);
  if (!existsSync(packageJson)) {
    assert.deepEqual(options, {});
    return;
  }
  const requireFromCore = createRequire(packageJson);
  const executablePath = requireFromCore(core).chromium.executablePath();
  const shell = requireFromCore(join(core, "lib/server/registry/index.js")).registry
    .findExecutable("chromium-headless-shell").executablePath();
  if (existsSync(executablePath)) {
    assert.deepEqual(options, { executablePath });
    assert.notEqual(executablePath, shell);
  } else {
    assert.deepEqual(options, {});
  }
});

function registryExecutable(kind, browsersPath) {
  const core = playwrightCoreDir(process.env);
  const packageJson = join(core, "package.json");
  assert.equal(existsSync(packageJson), true, "behaviour inputs are not installed");
  const env = { ...process.env };
  delete env.BRAVE_BIN;
  if (browsersPath === undefined) delete env.PLAYWRIGHT_BROWSERS_PATH;
  else env.PLAYWRIGHT_BROWSERS_PATH = browsersPath;
  const executableExpression = kind === "shell"
    ? `req(join(core, "lib/server/registry/index.js")).registry.findExecutable("chromium-headless-shell").executablePath()`
    : `req(core).chromium.executablePath()`;
  const result = spawnSync(process.execPath, [
    "--input-type=module",
    "-e",
    `import { createRequire } from "node:module";
     import { join } from "node:path";
     const core = ${JSON.stringify(core)};
     const req = createRequire(join(core, "package.json"));
     process.stdout.write(${executableExpression});`,
  ], { env, encoding: "utf8", timeout: 15_000 });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}

function installedExecutable(kind) {
  if (process.env.PLAYWRIGHT_BROWSERS_PATH) {
    const current = registryExecutable(kind, process.env.PLAYWRIGHT_BROWSERS_PATH);
    if (existsSync(current)) return current;
  }
  const fallback = registryExecutable(kind, undefined);
  assert.equal(existsSync(fallback), true, fallback);
  return fallback;
}

test("a cache with only the installed full Chromium is the product smoke browser", () => {
  const full = installedExecutable("chromium");
  const chosen = chooseFromInstallDir(browserInstallDir(full), full);
  assert.deepEqual(chosen.options, { executablePath: chosen.expected });
});

test("a cache with only the headless shell is not the product smoke browser", () => {
  const shell = installedExecutable("shell");
  assert.deepEqual(chooseFromInstallDir(browserInstallDir(shell), shell).options, {});
});

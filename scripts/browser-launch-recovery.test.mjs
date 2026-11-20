import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const product = new URL("./product-smoke-browser.mjs", import.meta.url).href;
const runner = fileURLToPath(new URL("./run-node-tests.mjs", import.meta.url));
const harnessRunner = fileURLToPath(new URL("./run-browser-launch-harness.mjs", import.meta.url));
const recovery = new URL("./lib/browser-launch-recovery.mjs", import.meta.url).href;

// Scan calls, independent of how a module obtains Playwright: static import,
// dynamic import, require, and environment-selected paths all face this gate.
const launchCalls = /\.\s*(?:launch|launchPersistentContext|connectOverCDP)\s*\(/;
const boundaries = /withBrowserLaunchRecovery\s*\(|(?:require|import)ProductSmokePlaywright\s*\(|from\s*["'][^"']*system-uiux-fixture\.mjs["']/;
const exceptions = new Map([
  ["browser-launch-measure.mjs", "raw failure-rate control"],
  ["browser-hosted-product-navigation-smoke.mjs", "CDP attaches an existing browser; preserve its first result"],
  ["browser-window-close-handshake.test.mjs", "Home launch routing fixture, not a native browser"],
  ["browser-launch-recovery.test.mjs", "injected launch fixtures exercise this boundary"],
  ["lib/browser-launch-recovery.test.mjs", "fake engines verify the recovery boundary"],
  ["lib/browser-launch-recovery.mjs", "the single native launch implementation"],
]);
function checkLaunchCoverage(directory, prefix = "", testsOnly = false) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const relative = prefix + entry.name;
    const path = new URL(entry.name, directory);
    if (entry.isDirectory() && entry.name !== "node_modules") {
      checkLaunchCoverage(new URL(entry.name + "/", directory), relative + "/", testsOnly);
    } else if (entry.isFile() && /\.[cm]?js$/.test(entry.name) && (!testsOnly || entry.name.endsWith(".test.mjs"))) {
      const source = readFileSync(path, "utf8");
      if (launchCalls.test(source) && !exceptions.has(relative)) assert.match(source, boundaries, relative);
    }
  }
}

test("native Playwright test launch imports use the shared recovery boundary", () => {
  checkLaunchCoverage(new URL("./", import.meta.url));
  checkLaunchCoverage(new URL("../capsules/", import.meta.url), "capsules/", true);
  checkLaunchCoverage(new URL("../elastos/esp/", import.meta.url), "elastos/esp/", true);
});

for (const [form, acquisition] of [
  ["static import", 'import { chromium } from "playwright";'],
  ["dynamic core import", 'const { chromium } = await import(corePath);'],
  ["environment core require", 'const { chromium } = require(process.env.BROWSER_OPERATOR_PLAYWRIGHT_CORE);'],
  ["dynamic environment import", 'const { chromium } = await import(process.env.ELASTOS_PLAYWRIGHT_MODULE);'],
]) test(`coverage guard discovers a new ${form} launch without a filename list`, t => {
  const root = mkdtempSync(join(tmpdir(), "browser-launch-coverage-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const directory = pathToFileURL(root + "/");
  mkdirSync(join(root, "nested"));
  for (const method of ["launch", "launchPersistentContext", "connectOverCDP"]) {
    writeFileSync(join(root, "nested/new-launch.mjs"), `${acquisition}\nawait chromium.${method}({});`);
    assert.throws(() => checkLaunchCoverage(directory), /new-launch\.mjs/);
    writeFileSync(join(root, "nested/new-launch.mjs"), `${acquisition}\nconst recovered = withBrowserLaunchRecovery({chromium});\nawait recovered.chromium.${method}({});`);
    assert.doesNotThrow(() => checkLaunchCoverage(directory));
  }
});
test("coverage guard catches a second raw Playwright import beside a wrapped import", t => {
  const root = mkdtempSync(join(tmpdir(), "browser-launch-coverage-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeFileSync(join(root, "second-import.mjs"), `
    const {chromium} = withBrowserLaunchRecovery(await import('playwright'));
    await chromium.launch({});
    import {chromium as rawChromium} from 'playwright';
    await rawChromium.launch({});`);
  assert.throws(() => checkLaunchCoverage(pathToFileURL(root + "/")), /second-import\.mjs/);
});

test("coverage guard catches a computed chromium launch", t => {
  const root = mkdtempSync(join(tmpdir(), "browser-launch-coverage-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeFileSync(join(root, "computed-launch.mjs"), `
    import {chromium} from 'playwright';
    await chromium["launch"]({});`);
  assert.throws(() => checkLaunchCoverage(pathToFileURL(root + "/")), /computed-launch\.mjs/);
});

for (const [crashes, smokeExit] of [[[2, 1], 0], [[2, 2], 0], [[1, 0], 7]]) {
  test(`Rust harness shares relaunches ${crashes} and reports captured output with exit ${smokeExit}`, t => {
    const root = mkdtempSync(join(tmpdir(), "browser-launch-harness-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const smoke = join(root, "smoke.mjs");
    writeFileSync(smoke, `import {withBrowserLaunchRecovery} from ${JSON.stringify(recovery)};
      let attempts=0;
      const {chromium}=withBrowserLaunchRecovery({chromium:{name:()=> 'chromium',async launch(){
        if(++attempts%2)throw Error('<process did exit: exitCode=null, signal=SIGSEGV>');
        return {close:async()=>{}};
      }}});
      for(let i=0;i<Number(process.argv[2]);i++)await (await chromium.launch()).close();
      process.exitCode=Number(process.argv[3]);`);
    const harness = join(root, "harness.mjs");
    // Like command.output() in Rust, this caller captures successful stdout.
    // Its smokes inherit the harness environment without clearing the ledger.
    writeFileSync(harness, `import {spawnSync} from 'node:child_process';
      let failed=0;
      for(const crashes of ${JSON.stringify(crashes)}){
        const r=spawnSync(process.execPath,[${JSON.stringify(smoke)},String(crashes),${JSON.stringify(String(smokeExit))}],
          {encoding:'utf8',timeout:10000});
        if(r.error)throw r.error;
        if(r.status!==0)failed=r.status??1;
      }
      process.exitCode=failed;`);
    const env = { ...process.env };
    delete env.ELASTOS_BROWSER_LAUNCH_LEDGER;
    const r = spawnSync(process.execPath, [harnessRunner, process.execPath, harness], {
      env, encoding: "utf8", timeout: 30_000,
    });
    assert.ifError(r.error);
    const count = crashes.reduce((a, b) => a + b, 0);
    const output = r.stdout + r.stderr;
    assert.equal(r.status, count > 3 ? 1 : smokeExit, output);
    assert.equal((output.match(/Browser launch relaunch:/g) ?? []).length, count, output);
    assert.match(output, new RegExp(`Browser launch summary: ${count} relaunch\\(es\\); limit 3; ${count > 3 ? "FAIL" : "PASS"}`));
    assert.match(output, /engine=chromium; signal=SIGSEGV; attempt=2\/2/);
    console.log(`Rust harness proof: crashes=${crashes}; child exit=${smokeExit}; run exit=${r.status}\n${output}`);
  });
}

function fixture(t, scenario, files = 1) {
  const root = mkdtempSync(join(tmpdir(), "browser-launch-recovery-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const module = join(root, "playwright.cjs");
  writeFileSync(module, `let attempts=0;
    const engine={name(){return 'chromium'},executablePath(){return '/fixture/chromium'},
      async launch(options){
        if(this!==engine||options.headless!==true)throw Error('receiver or options changed');
        console.log('FIXTURE launch='+ ++attempts);
        if(${JSON.stringify(scenario)}==='timeout'){
          const error=Error('browserType.launch: Timeout 30ms exceeded. Target page, context or browser has been closed; signal=SIGSEGV');
          error.name='TimeoutError';throw error;
        }
        if(${JSON.stringify(scenario)}==='missing')throw Error("browserType.launch: Executable doesn't exist at /missing");
        if(attempts<=${scenario === "twice" ? 2 : scenario === "once" ? 1 : 0})
          throw Error('browserType.launch: Target page, context or browser has been closed\\nBrowser logs:\\n<launched> pid=123\\ncrash-'+attempts+'\\n<process did exit: exitCode=null, signal=SIGSEGV>');
        return {async newPage(){console.log('FIXTURE page created');return {async goto(){
          if(${JSON.stringify(scenario)}==='page')throw Error('Target page, context or browser has been closed AFTER_PAGE');
        }}},async newContext(){throw Error('Target page, context or browser has been closed AFTER_CONTEXT')},async close(){}};
      }};module.exports={chromium:engine};`);
  const paths = [];
  for (let i = 0; i < files; i++) {
    const path = join(root, `case-${i}.mjs`);
    writeFileSync(path, `import test from 'node:test';
      import {requireProductSmokePlaywright} from ${JSON.stringify(product)};
      test('injected ${scenario} ${i}', async()=>{
        const {chromium}=requireProductSmokePlaywright();
        const browser=await chromium.launch({headless:true});
        try { ${scenario === "context" ? "await browser.newContext();" : "const page=await browser.newPage();await page.goto('about:blank');"} }
        finally {await browser.close()}
      });`);
    paths.push(path);
  }
  const env = { ...process.env, ELASTOS_PLAYWRIGHT_MODULE: module };
  delete env.NODE_TEST_CONTEXT;
  delete env.ELASTOS_BROWSER_LAUNCH_LEDGER;
  const run = ({ nested = false } = {}) => {
    let entrypoints = paths;
    if (nested) {
      const orchestrator = join(root, "nested.mjs");
      writeFileSync(orchestrator, `import test from 'node:test';import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';
        test('nested real test supervisors',()=>{
          const env={...process.env};delete env.NODE_TEST_CONTEXT;
          for(const file of ${JSON.stringify(paths)}){
            const r=spawnSync(process.execPath,[${JSON.stringify(runner)},'--timeout=10000',file],{env,encoding:'utf8',timeout:20000});
            assert.ifError(r.error);assert.equal(r.status,0,r.stdout+r.stderr);
          }
        });`);
      entrypoints = [orchestrator];
    }
    const result = spawnSync(process.execPath, [runner, "--timeout=10000", ...entrypoints], {
      env, encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024,
    });
    assert.ifError(result.error);
    return { ...result, output: result.stdout + result.stderr };
  };
  return { run, root };
}

test("one native startup crash relaunches once and names the test, engine, signal and total", t => {
  const r = fixture(t, "once").run();
  assert.equal(r.status, 0, r.output);
  assert.match(r.stdout, /Browser launch relaunch:.*injected once 0.*chromium.*SIGSEGV/);
  assert.match(r.output, /FIXTURE launch=2/);
  assert.match(r.stdout, /Browser launch summary: 1 relaunch\(es\); limit 3; PASS/);
});

test("two startup crashes fail with both browser logs", t => {
  const r = fixture(t, "twice").run();
  assert.notEqual(r.status, 0, r.output);
  assert.match(r.output, /crash-1/);
  assert.match(r.output, /crash-2/);
  assert.doesNotMatch(r.output, /FIXTURE launch=3/);
  assert.match(r.output, /Browser launch summary: 1 relaunch/);
});

for (const scenario of ["page", "context", "timeout", "missing"]) test(`${scenario} errors keep their first failure`, t => {
  const r = fixture(t, scenario).run();
  assert.notEqual(r.status, 0, r.output);
  assert.match(r.output, /FIXTURE launch=1/);
  assert.doesNotMatch(r.output, /FIXTURE launch=2|Browser launch relaunch:/);
  assert.match(r.output, /Browser launch summary: 0 relaunch/);
});

for (const files of [3, 4]) test(`the run counts relaunches across ${files} test processes`, t => {
  const r = fixture(t, "once", files).run();
  assert.equal(r.status, files > 3 ? 1 : 0, r.output);
  assert.match(r.output, new RegExp(`Browser launch summary: ${files} relaunch\\(es\\); limit 3; ${files > 3 ? "FAIL" : "PASS"}`));
  assert.match(r.output, new RegExp(`Node test guard: ${files > 3 ? "FAIL" : "PASS"}`));
});

test("nested supervisors charge real browser relaunches to the outer suite", t => {
  const r = fixture(t, "once", 4).run({ nested: true });
  assert.equal(r.status, 1, r.output);
  assert.match(r.stdout, /Browser launch summary: 4 relaunch\(es\); limit 3; FAIL/);
  assert.match(r.stdout, /Node test guard: FAIL/);
});

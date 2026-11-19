import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const product = new URL("./product-smoke-browser.mjs", import.meta.url).href;
const runner = fileURLToPath(new URL("./run-node-tests.mjs", import.meta.url));
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
  const run = () => {
    const result = spawnSync(process.execPath, [runner, "--timeout=10000", ...paths], {
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
  assert.match(r.output, /Browser launch relaunch:.*injected once 0.*chromium.*SIGSEGV/);
  assert.match(r.output, /FIXTURE launch=2/);
  assert.match(r.output, /Browser launch summary: 1 relaunch\(es\); limit 3; PASS/);
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

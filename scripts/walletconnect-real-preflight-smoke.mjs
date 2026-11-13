// Opt-in admission preflight before paired recovery. Private fixture options
// enter through stdin; browser evidence contains resource names and status.
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { importProductSmokePlaywright } from './product-smoke-browser.mjs';
let input = '';
for await (const chunk of process.stdin) { input += chunk; assert.ok(input.length < 16384); }
const options = JSON.parse(input);
const result = { project:'project file set', runs:[] };
const evidence = process.env.WALLETCONNECT_SCREENSHOTS;
const emit = console.log.bind(console);
console.log = console.warn = console.error = () => {};
const deadline = setTimeout(() => { result.timeout = true; emit(JSON.stringify(result)); process.exit(1); }, 120000);
const expectedCsp = `sandbox allow-scripts allow-forms allow-downloads; default-src ${options.origin}; script-src 'self' 'wasm-unsafe-eval' ${options.origin}; style-src ${options.origin} 'unsafe-inline'; img-src ${options.origin} blob: data:; connect-src ${options.origin} ${options.origin.replace(/^http/, 'ws')}; frame-src ${options.origin}; object-src 'none'; base-uri 'none'; form-action ${options.origin}`;
try {
  const playwright = await importProductSmokePlaywright();
  for (const engine of ['chromium', 'webkit']) {
    const run = { engine, paired:false, network:[] };
    result.runs.push(run);
    let browser, frame;
    try {
      run.phase = 'browser';
      browser = await playwright[engine].launch({headless:true, timeout:15000});
      run.version = browser.version();
      const context = await browser.newContext();
      // Fixture provisioning only; Runtime APIs still receive the capsule token.
      await context.exposeBinding('walletConnectTestOptions', source => {
        assert.equal(source.frame.url(), `${options.origin}/apps/wallet-walletconnect/wc-real.html`);
        return options;
      });
      await context.route('**/*', route => new URL(route.request().url()).origin === options.origin ? route.continue() : route.abort());
      context.on('response', response => {
        const path = new URL(response.url()).pathname;
        if (path.startsWith('/api/apps/wallet-walletconnect/') && run.network.length < 128) {
          run.network.push({resource:path.split('/').at(-1), status:response.status()});
        }
      });
      const page = await context.newPage();
      run.phase = 'home';
      assert.equal((await page.goto(`${options.origin}/apps/home/`, {timeout:10000})).status(), 200);
      run.phase = 'capsule';
      const document = page.waitForResponse(response => response.url() === `${options.origin}/apps/wallet-walletconnect/wc-real.html`, {timeout:10000});
      await page.evaluate(origin => {
        const frame = window.document.createElement('iframe');
        frame.id = 'wc-real-preflight';
        frame.sandbox = 'allow-downloads allow-forms allow-modals allow-pointer-lock allow-scripts';
        frame.src = `${origin}/apps/wallet-walletconnect/wc-real.html`;
        window.document.body.append(frame);
      }, options.origin);
      run.csp = (await (await document).allHeaders())['content-security-policy'];
      assert.equal(run.csp, expectedCsp);
      frame = await (await page.waitForSelector('#wc-real-preflight', {timeout:10000})).contentFrame();
      assert.ok(frame);
      run.phase = 'runtime-store';
      await frame.waitForFunction(() => window.failed || document.querySelector('dialog[open] canvas')?.width > 0, null, {timeout:20000});
      assert.equal(await frame.evaluate(() => window.failed), undefined);
      assert.equal(await frame.evaluate(() => self.origin), 'null');
      assert.equal(await frame.locator('dialog[open] canvas').count(), 1);
      run.status = 'PASS';
    } catch {
      run.status = 'FAIL';
    } finally {
      if (frame) {
        try {
          run.state = await Promise.race([
            frame.evaluate(() => ({origin:self.origin, phase:window.phase, refusal:window.refusal,
              errorName:window.errorName, runtimeTrace:window.runtimeTrace, storageTrace:window.storageTrace})),
            new Promise((_, reject) => setTimeout(() => reject(new Error('state timeout')), 3000)),
          ]);
        } catch { run.stateUnavailable = true; }
      }
      await browser?.close();
    }
    // Stop at the first Chromium blocker, as required by the round's brief.
    if (engine === 'chromium' && run.status !== 'PASS') break;
  }
} catch { result.setup = 'FAIL'; }
if (evidence) {
  await mkdir(evidence, {recursive:true});
  await writeFile(`${evidence}/real-preflight.json`, JSON.stringify(result,null,2));
}
clearTimeout(deadline);
emit(JSON.stringify(result));
process.exit(result.runs.length === 2 && result.runs.every(run => run.status === 'PASS') ? 0 : 1);

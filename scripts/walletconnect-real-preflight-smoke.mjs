// Opt-in preflight before paired recovery: use real Runtime resources and relay.
// The Rust source gateway supplies private options through stdin.
// SDK logs stay in process memory. Evidence contains resource names and status.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, writeFile } from 'node:fs/promises';
import { importProductSmokePlaywright } from './product-smoke-browser.mjs';
const require = createRequire(new URL('./walletconnect/package.json', import.meta.url));
const { SignClient } = require('@walletconnect/sign-client');
const { privateKeyToAccount, generatePrivateKey } = require('viem/accounts');
let input = '';
for await (const chunk of process.stdin) { input += chunk; assert.ok(input.length < 16384); }
const options = JSON.parse(input);
const result = { project: 'project file set', runs: [] };
const evidence = process.env.WALLETCONNECT_SCREENSHOTS;
let rejections = 0;
const logger = Object.fromEntries(['trace','debug','info','warn','error','fatal'].map(level => [level, () => {}]));
logger.child = () => logger; logger.level = 'silent';
process.on('unhandledRejection', () => rejections++);
// Prevent third-party diagnostic output from exposing URLs or credentials.
const emit = console.log.bind(console);
console.log = console.warn = console.error = () => {};
let exitCode = 1;
try {
  const playwright = await importProductSmokePlaywright();
  for (const engine of ['chromium', 'webkit']) {
    const run = { engine, walletReady:false, paired:false };
    result.runs.push(run);
    let browser, wallet;
    try {
      const signer = privateKeyToAccount(generatePrivateKey());
      wallet = await SignClient.init({ projectId:options.projectId, logger, telemetryEnabled:false,
        metadata:{name:'Disposable test wallet', description:'Isolated recovery fixture', url:'http://localhost', icons:[]} });
      run.walletReady = true;
      wallet.on('session_proposal', async proposal => {
        const approval = await wallet.approve({ id:proposal.id, namespaces:{eip155:{
          chains:['eip155:1'], accounts:[`eip155:1:${signer.address}`],
          methods:['personal_sign','eth_sendTransaction'], events:['accountsChanged','chainChanged'],
        }} });
        await approval.acknowledged();
        run.paired = true;
      });
      wallet.on('session_request', async event => {
        const request = event.params.request;
        assert.equal(request.method, 'personal_sign');
        const signature = await signer.signMessage({message:{raw:request.params[0]}});
        await wallet.respond({ topic:event.topic, response:{id:event.id,jsonrpc:'2.0',result:signature} });
      });
      browser = await playwright[engine].launch({headless:true});
      run.version = browser.version();
      const context = await browser.newContext();
      await context.exposeBinding('walletConnectTestOptions', () => options);
      await context.route('**/*', route => new URL(route.request().url()).origin === options.origin ? route.continue() : route.abort());
      const page = await context.newPage();
      const home = await page.goto(`${options.origin}/apps/home/`);
      assert.equal(home.status(), 200);
      const response = await fetch(`${options.origin}/apps/wallet-walletconnect/wc-real.html`);
      run.csp = response.headers.get('content-security-policy');
      assert.ok(run.csp.startsWith('sandbox allow-scripts allow-forms allow-downloads;'));
      await page.evaluate(origin => {
        const frame = document.createElement('iframe');
        frame.sandbox = 'allow-downloads allow-forms allow-modals allow-pointer-lock allow-scripts';
        frame.src = `${origin}/apps/wallet-walletconnect/wc-real.html`;
        document.body.append(frame);
      }, options.origin);
      await page.waitForFunction(() => document.querySelector('iframe')?.contentWindow != null);
      let frame;
      for (let i=0; i<100 && !frame; i++) { frame=page.frames().find(f => f.url().endsWith('/wc-real.html')); if (!frame) await new Promise(resolve => setTimeout(resolve,50)); }
      assert.ok(frame);
      // The initial Runtime-backed keychain read precedes any pairing proposal.
      await frame.waitForFunction(() => window.failed || document.querySelector('dialog[open] canvas')?.width > 0, null, {timeout:30000});
      run.state = await frame.evaluate(() => ({origin:self.origin,phase:window.phase,
        refusal:window.refusal, runtimeTrace:window.runtimeTrace, storageTrace:window.storageTrace}));
      assert.equal(run.state.origin, 'null');
      assert.equal(run.state.refusal, undefined, 'connector launch token must admit the Runtime SDK store');
      assert.ok(await frame.locator('dialog[open] canvas').count());
      run.status = 'PASS';
    } catch {
      run.status = 'FAIL';
    } finally {
      await browser?.close();
      if (wallet) {
        for (const session of wallet.session.getAll()) await wallet.disconnect({topic:session.topic,reason:{code:6000,message:'Test ended'}}).catch(() => {});
        await wallet.core.relayer.transportClose().catch(() => {});
      }
    }
    // The brief requires an immediate stop at the first Chromium blocker.
    if (engine === 'chromium' && run.status !== 'PASS') break;
  }
} catch { result.setup = 'FAIL'; }
exitCode = result.runs.length === 2 && result.runs.every(run => run.status === 'PASS') ? 0 : 1;
if (evidence) {
  await mkdir(evidence, {recursive:true});
  await writeFile(`${evidence}/real-preflight.json`, JSON.stringify(result,null,2));
}
emit(JSON.stringify(result));
process.exit(exitCode);

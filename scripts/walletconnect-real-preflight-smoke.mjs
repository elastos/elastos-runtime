// Opt-in admission preflight before paired recovery. Private fixture options
// enter through stdin; browser evidence contains resource names and status.
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { connect } from 'node:net';
import { importProductSmokePlaywright } from './product-smoke-browser.mjs';
let input = '';
for await (const chunk of process.stdin) { input += chunk; assert.ok(input.length < 16384); }
const options = JSON.parse(input);
const result = { project:'project file set', runs:[] };
const evidence = process.env.WALLETCONNECT_SCREENSHOTS;
const emit = console.log.bind(console);
console.log = console.warn = console.error = () => {};
const deadline = setTimeout(() => { result.timeout = true; emit(JSON.stringify(result)); process.exit(1); }, 240000);
const bounded = (promise, ms = 20000) => Promise.race([promise, new Promise((_, reject) => { const timer = setTimeout(() => reject(new Error('step timeout')), ms); timer.unref(); })]);
const restart = () => bounded(new Promise((resolve, reject) => { const socket = connect(options.restart); socket.setTimeout(10000, () => socket.destroy(new Error('restart timeout'))); socket.on('error', reject); socket.on('connect', () => socket.end('restart')); socket.on('data', data => data.toString() === 'ready' ? resolve() : reject(new Error('restart refused'))); }));
const expectedCsp = `sandbox allow-scripts allow-forms allow-downloads; default-src ${options.origin}; script-src 'self' 'wasm-unsafe-eval' ${options.origin}; style-src ${options.origin} 'unsafe-inline'; img-src ${options.origin} blob: data:; connect-src ${options.origin} ${options.origin.replace(/^http/, 'ws')}; frame-src ${options.origin}; object-src 'none'; base-uri 'none'; form-action ${options.origin}`;
try {
  const playwright = await importProductSmokePlaywright();
  const { SignClient } = createRequire(new URL('./walletconnect/package.json', import.meta.url))('@walletconnect/sign-client');
  for (const engine of ['chromium', 'webkit']) {
    const run = { engine, paired:false, network:[] };
    result.runs.push(run);
    let browser, frame, wallet;
    try {
      run.phase = 'test-wallet';
      wallet = await bounded(SignClient.init({projectId:options.projectId, logger:'silent',
        customStoragePrefix:`wc-recovery-${engine}-${Date.now()}`, storageOptions:{database:':memory:'},
        metadata:{name:'Disposable scripted wallet', description:'Pairing recovery only', url:'https://localhost', icons:[]}}));
      let proposals = 0;
      let approve;
      const approved = new Promise((resolve, reject) => { approve = {resolve, reject}; });
      wallet.on('session_proposal', async proposal => {
        proposals++;
        try {
          const session = await wallet.approve({id:proposal.id, namespaces:{eip155:{
            accounts:[`eip155:1:0x${'12'.repeat(20)}`], methods:['personal_sign','eth_sendTransaction'],
            events:['accountsChanged','chainChanged']}}});
          approve.resolve(await session.acknowledged());
        } catch { approve.reject(new Error('scripted wallet approval failed')); }
      });
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
      context.on('request', request => {
        const path = new URL(request.url()).pathname;
        if (path === '/api/apps/wallet-walletconnect/storage' && request.method() === 'POST') {
          const key = request.postDataJSON().key;
          run.runtimeWrites ??= {pairing:0, keychain:0, session:0, other:0};
          const kind = key.endsWith('//pairing') ? 'pairing' : key.endsWith('//keychain') ? 'keychain'
            : /session|ethereum_provider/.test(key) ? 'session' : 'other';
          run.runtimeWrites[kind]++;
        }
      });
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
      await frame.waitForFunction(() => window.failed || document.querySelector('dialog[open] canvas')?.width === 280, null, {timeout:20000});
      assert.equal(await frame.evaluate(() => window.failed), undefined);
      assert.equal(await frame.evaluate(() => self.origin), 'null');
      assert.equal(await frame.locator('dialog[open] canvas').count(), 1);
      run.qr = 'PASS';
      run.phase = 'pairing';
      await frame.waitForFunction(() => typeof window.pairingUri === 'string', null, {timeout:10000});
      const uri = await frame.evaluate(() => window.pairingUri);
      await bounded(wallet.core.pairing.pair({uri}));
      const session = await bounded(approved, 30000);
      await frame.waitForFunction(() => window.provider?.connected || window.failed, null, {timeout:20000});
      assert.equal(await frame.evaluate(() => window.failed), undefined);
      assert.equal(await frame.evaluate(() => window.provider.session.topic), session.topic);
      await bounded(wallet.ping({topic:session.topic}));
      run.paired = true;
      run.pairing = 'PASS';
      for (const phase of ['reload', 'homeRestart']) {
        run.phase = phase;
        if (phase === 'homeRestart') await restart();
        await frame.evaluate(() => location.reload());
        await frame.waitForFunction(() => window.provider?.connected || window.failed, null, {timeout:30000});
        assert.equal(await frame.evaluate(() => window.failed), undefined);
        assert.equal(await frame.evaluate(() => window.provider.session.topic), session.topic);
        assert.equal(await frame.locator('dialog[open] canvas').count(), 0);
        await bounded(wallet.ping({topic:session.topic}));
        assert.equal(proposals, 1);
        run[phase] = 'PASS';
      }
      const trace = await frame.evaluate(() => window.storageTrace);
      assert.ok(trace.every(entry => !entry.protocol));
      run.protocolInShim = false;
      for (const kind of ['pairing', 'keychain', 'session']) assert.ok(run.runtimeWrites[kind] > 0, `${kind} persisted through Runtime`);
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
      try {
        for (const session of wallet?.session.getAll() || []) await bounded(wallet.disconnect({topic:session.topic, reason:{code:6000, message:'Test complete'}}), 5000);
        await wallet?.core.relayer.transportClose();
      } catch { run.walletCleanup = 'transport closed at process exit'; }
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

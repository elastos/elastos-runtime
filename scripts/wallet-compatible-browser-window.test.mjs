import { windowTestOptions } from './lib/walletconnect-window-resources.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { requireProductSmokePlaywright } from './product-smoke-browser.mjs';
import { fixture } from './lib/wallet-extension-window-fixture.mjs';

const playwright = requireProductSmokePlaywright();
const engineSkip = (engine) => windowTestOptions(engine).skip;

for (const engine of ['chromium']) {
  test(`${engine} metamask: Home-issued picker for two alt wallets announced in Home only`, { timeout: 60000, skip: engineSkip(engine) }, async () => {
    const browser = await playwright[engine].launch({ headless: true });
    try {
      const f = await fixture(browser, 'metamask', { dualAlt: true });
      try {
        await f.top.evaluate(() => window.dispatchEvent(new Event('eip6963:requestProvider')));
        await f.frame.locator('main[data-state="ready"] [data-action="connect"]').click();
        await f.state('extension-choose-wallet');
        const names = await f.frame.locator('.connection-wallet-choice').allTextContents();
        assert.deepEqual(names.sort(), ['Brave Wallet', 'Rabby Wallet']);
        const choiceKey = await f.frame.locator('.connection-wallet-choice', { hasText: 'Brave Wallet' })
          .getAttribute('data-focus-key');
        assert.match(choiceKey, /^select-wallet:wchoice-/);
        await f.frame.locator(`[data-focus-key="${choiceKey}"]`).click();
        await f.state('linked');
        const action = await f.top.evaluate(() => testState.effects.at(-1)?.action);
        assert.equal(action?.walletChoiceId, choiceKey.slice('select-wallet:'.length));
        assert.equal((await f.top.evaluate(() => testState.calls.find((row) => row.wallet === 'com.brave.wallet')?.method)), 'eth_requestAccounts');
      } finally {
        await f.close();
      }
    } finally {
      await browser.close();
    }
  });
}
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
const A = '0x' + '1'.repeat(40), B = '0x' + '2'.repeat(40);
const mm = {rdns:'io.metamask',uuid:'mm',name:'MetaMask'};
const rabby = {rdns:'io.rabby',uuid:'rabby',name:'Rabby Wallet'};
const icon = 'data:image/svg+xml;base64,' + Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32"><rect width="32" height="32" fill="#7355ef"/></svg>').toString('base64');
async function windowCase(options, check, kind='metamask') {
  const browser=await playwright.chromium.launch({headless:true});
  try { const f=await fixture(browser,kind,options);try {await check(f);}finally{await f.close();} }finally{await browser.close();}
}
async function click(f,action,state) {await f.action(action).click();await f.state(state);}
async function namedCalls(f) {return f.top.evaluate(()=>testState.calls.filter(c=>c.wallet));}

test('V2-1 Home-only choice is a whole-row button and completes the chosen link',async()=>windowCase({dualAlt:true},async f=>{
  assert.equal(await f.top.evaluate(()=>testState.effects.length),0);
  await click(f,'connect','extension-choose-wallet');
  assert.match(await f.frame.evaluate(()=>document.activeElement.dataset.focusKey),/^select-wallet:/);
  assert.deepEqual(await f.frame.locator('.connection-wallet-choice').allTextContents(),['Brave Wallet','Rabby Wallet']);
  assert.equal(await f.action('close-window').count(),1);assert.equal(await f.action('refresh-status').count(),1);
  assert.deepEqual(await namedCalls(f),[]);
  await f.frame.getByRole('button',{name:'Rabby Wallet',exact:true}).click();await f.state('linked');
  assert.equal((await namedCalls(f))[0].wallet,'io.rabby');
  assert.equal(await f.frame.locator('.connection-account-name').innerText(),'Rabby Wallet');
}));

test('V2-2 MetaMask alone keeps the build request bytes and has no list',async()=>{
  const traces=[];
  for(const hostSource of [execFileSync('git',['show','9b855f6ca:capsules/home/browser/home-wallet-connector-host.js'],{encoding:'utf8'}),undefined]) {
    await windowCase({hostSource,mutate:hostSource?source=>source.replace("if (kind === 'metamask') action = {...action,includeWallet:true};",''):undefined},async f=>{
      await click(f,'connect','linked');
      traces.push(await f.top.evaluate(()=>({calls:testState.calls,receipts:testState.receipts,runtime:testState.runtimeCalls})));
      assert.equal(await f.frame.locator('.connection-wallet-choice').count(),0);
      assert.equal(await f.frame.locator('h1').textContent(),'MetaMask');
    });
  }
  assert.deepEqual(traces[1],traces[0]);
});

test('V2-3 MetaMask plus another wallet connects to MetaMask without a question',async()=>windowCase({wallets:[rabby,mm]},async f=>{
  assert.equal(await f.frame.locator('h1').textContent(),'MetaMask');
  await click(f,'connect','linked');assert((await namedCalls(f)).every(c=>c.wallet==='io.metamask'));
  assert.equal(await f.frame.locator('.connection-wallet-choice').count(),0);
  assert.equal(await f.frame.locator('h1').textContent(),'MetaMask');
}));

test('V2-4 approval finds the linked account before handoff and keeps an unmatched request pending',async()=>{
  await windowCase({wallets:[{...rabby,accounts:[A]}]},async f=>{
    await click(f,'connect','linked');
    await f.top.evaluate(mm=>{
      testState.calls=[];
      testState.wallets.push({...mm,accounts:['0x'+'2'.repeat(40)]});
      testState.requests=[{request_id:'approval-1',status:'pending',intent:'browser_personal_sign',proof_type:'siwe',capsule_id:'browser',reason:'Test signing',requesting_origin:'https://shop.example.com',connector_id:'wallet-metamask',address:testState.address,chain_namespace:'eip155:1',expires_at:Math.floor(Date.now()/1000)+300}];
    },mm);
    const url=new URL(f.frame.url());url.searchParams.set('approve','1');await f.frame.goto(url.href);await f.state('request-waiting');
    await click(f,'send-request','request-done');
    const calls=await namedCalls(f);assert.equal(calls.find(c=>c.method==='personal_sign').wallet,'io.rabby');
    assert.equal(calls.filter(c=>c.method==='eth_accounts').length,3); // two probes, then existing signer check
    assert.equal(await f.frame.locator('.connection-wallet-choice').count(),0);
  });
  await windowCase({saved:true,requests:true,wallets:[{...rabby,accounts:[B]}, {...mm,accounts:[]}]},async f=>{
    await f.state('request-waiting');await click(f,'send-request','request-unsendable');
    assert.equal(await f.frame.locator('.connection-status').innerText(),'Home cannot confirm access to the account this request needs in your wallet.');
    assert.deepEqual(await f.top.evaluate(()=>testState.requests.map(r=>r.status)),['pending']);
    assert.equal(await f.top.evaluate(()=>testState.runtimeCalls?.filter(c=>c.url.endsWith('/handoff')).length||0),0);
    assert((await namedCalls(f)).every(c=>c.method==='eth_accounts'));
    assert.equal(await f.frame.locator('img').count(),0);
    await f.top.evaluate(A=>testState.wallets[0].accounts=[A],A);
    await click(f,'refresh-status','request-waiting');await click(f,'send-request','request-done');
  });
});

test('V2-5 forged brands, markup, direction controls and reserved names are refused',async()=>{
  for(const name of ['MetaMask','Brave Wallet','UniSat','WalletConnect','Home security','Wallet','Inbox notice','ElastOS help','<b>Rabby</b>','Rabby\u202e']) {
    await windowCase({wallets:[{...rabby,name}]},async f=>{
      await click(f,'connect','link-error');assert.equal(await f.top.evaluate(()=>testState.calls.length),0,name);
    });
  }
});

test('V2-6 saved cards have no mark; only a wallet linked in this window supplies name and icon',async()=>windowCase({wallets:[{...rabby,icon}]},async f=>{
  await f.state('ready');
  await click(f,'connect','linked');
  assert.equal(await f.frame.locator('.connection-account-name').innerText(),'Rabby Wallet');
  assert.equal(await f.frame.locator('.connection-account-header img').getAttribute('src'),icon);
  const url=new URL(f.frame.url());url.searchParams.set('fresh','1');await f.frame.goto(url.href);await f.state('linked');
  assert.equal(await f.frame.locator('img').count(),0);
  assert.equal(await f.frame.locator('.connection-account-name').innerText(),'Your wallet');
  assert.equal(await f.frame.locator('.connection-status').innerText(),'Account saved in Wallet.');
}));

test('V2-7 UniSat window has no Ethereum discovery or calls',async()=>windowCase({wallets:[rabby]},async f=>{
  await f.state('ready');await click(f,'connect','linked');
  assert.equal(await f.frame.evaluate(()=>window.__ethereumDiscoveryRequests),0);
  assert.equal(await f.top.evaluate(()=>testState.discoveryRequests||0),0);
  assert.equal(await f.top.evaluate(()=>testState.calls.some(c=>c.method.startsWith('eth_'))),false);
  assert.equal(await f.frame.evaluate(()=>document.title),'UniSat · ElastOS');
  for(const kind of ['metamask','unisat'])assert.doesNotMatch(await readFile(`capsules/wallet-${kind}/browser/extension-window.mjs`,'utf8'),/eip6963|requestProvider/);
} ,'unisat'));

test('V2-8 four shared copies and the switched extension controller are byte identical',async()=>{
  for(const file of ['wallet-connection-view.mjs','wallet-connection-screens.mjs','wallet-connection-view.css']) {
    const shared=await readFile('capsules/_shared/'+file);
    for(const kind of ['metamask','unisat','walletconnect'])assert.deepEqual(await readFile(`capsules/wallet-${kind}/browser/${file}`),shared);
  }
  assert.deepEqual(await readFile('capsules/wallet-unisat/browser/extension-window.mjs'),await readFile('capsules/wallet-metamask/browser/extension-window.mjs'));
  assert.match(process.env.COMPAT_WALLET_PRODUCT_REF ? execFileSync('git',['show',process.env.COMPAT_WALLET_PRODUCT_REF+':capsules/wallet/browser/wallet-preferences.js'],{encoding:'utf8'}) : await readFile('capsules/wallet/browser/wallet-preferences.js','utf8'),/MetaMask or another wallet in this browser/);
});

async function addApproval(f,id,address) {
  await f.top.evaluate(({id,address})=>testState.requests.push({request_id:id,status:'pending',intent:'browser_personal_sign',proof_type:'siwe',capsule_id:'browser',reason:'Test signing',requesting_origin:'https://shop.example.com',connector_id:'wallet-metamask',address,chain_namespace:'eip155:1',expires_at:Math.floor(Date.now()/1000)+300}),{id,address});
  await f.frame.evaluate(()=>dispatchEvent(new Event('focus')));
}
test('review: a consumed chooser handle never accompanies a later approval in the same window',async()=>windowCase({dualAlt:true},async f=>{
  await click(f,'connect','extension-choose-wallet');await f.frame.getByRole('button',{name:'Rabby Wallet',exact:true}).click();await f.state('linked');
  await addApproval(f,'same-window',A);await f.state('request-waiting');
  await click(f,'send-request','request-done');
  const action=await f.top.evaluate(()=>testState.effects.at(-1).action);assert.equal(action.walletChoiceId,undefined);
}));
test('review: a new queued request clears the prior wallet identity and shows its actual signer on success',async()=>windowCase({saved:true,requests:true,wallets:[{...mm,accounts:[A]},{...rabby,icon,accounts:[B]}]},async f=>{
  await f.state('request-waiting');await click(f,'send-request','request-done');
  await f.top.evaluate(A=>emitWallet('accountsChanged',[A]),A);
  await addApproval(f,'second-wallet',B);
  // A completed local outcome intentionally stays until the person selects the new request.
  await f.action('select-request').click();await f.state('request-waiting');
  await f.top.evaluate(A=>emitWallet('accountsChanged',[A]),A);
  await f.state('request-waiting');
  assert.doesNotMatch(await f.action('send-request').innerText(),/MetaMask/);
  await f.frame.evaluate(()=>{window.probeEvents=0;window.probeBarrier=false;addEventListener('message',e=>{if(e.data?.type==='home:wallet-connector-event')probeEvents++;if(e.data?.type==='fixture:wallet-event-barrier')probeBarrier=true;});});
  await f.top.evaluate(()=>{testState.calls=[];testState.wallets[0].probePending=true;});
  await f.top.clock.pauseAt(new Date(await f.top.evaluate(()=>Date.now())+10000));
  await f.action('send-request').click();
  await f.top.waitForFunction(()=>testState.calls.filter(c=>c.wallet&&c.method==='eth_accounts').length===2);
  await f.top.evaluate(A=>{emitWallet('accountsChanged',[A]);document.querySelector('iframe').contentWindow.postMessage({type:'fixture:wallet-event-barrier'},'*');},A);
  await f.frame.waitForFunction(()=>probeBarrier);
  assert.equal(await f.frame.evaluate(()=>probeEvents),0,'Home retires the old provider while selecting the next one');
  await f.top.clock.runFor(1001);await f.state('request-done');
  assert.equal((await namedCalls(f)).filter(c=>c.method==='personal_sign').at(-1).wallet,'io.rabby');
  assert.equal(await f.frame.locator('.connection-request-account img').count(),1);
  assert.equal(await f.frame.locator('.connection-request-account img').getAttribute('src'),icon);
}));
test('review: approval discovery failure offers Check again while its Runtime request stays pending',async()=>windowCase({saved:true,requests:true,wallets:Array.from({length:33},(_,i)=>({rdns:'io.wallet'+i,uuid:'wallet-'+i,name:'Test wallet '+i}))},async f=>{
  await f.state('request-waiting');await click(f,'send-request','link-error');
  assert.equal(await f.top.evaluate(()=>testState.requests[0].status),'pending');
  assert.equal(await f.top.evaluate(()=>testState.calls.length),0);
  assert.equal(await f.frame.locator('.connection-status').innerText(),'Home could not confirm the connection.');
  await f.top.evaluate(()=>testState.wallets.length=1);
  await click(f,'refresh-status','request-done');
}));

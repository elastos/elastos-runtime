import test from 'node:test';
import assert from 'node:assert/strict';
import {browserFixture} from './lib/wallet-connection-browser-fixture.mjs';
for(const engine of ['chromium','webkit'])for(const kind of ['metamask','unisat'])test(`linked ${kind} has useful copy and controls in ${engine}`,async t=>{
 const f=await browserFixture(engine);t.after(()=>f.close());
 const shown=await f.page.evaluate(async kind=>{
  const {connectionView,renderConnection}=await import(`/capsules/wallet-${kind}/browser/wallet-connection-view.mjs`);
  const view=connectionView({window:kind,stage:'linked',homeOrigin:'https://home.example',account:{name:kind==='metamask'?'MetaMask':'UniSat',mark:kind,accounts:[{address:kind==='metamask'?'0x'+'12'.repeat(20):'bc1q'+'a'.repeat(38),networks:[kind==='metamask'?'Ethereum':'Bitcoin']}]},supportedActions:['close-window','copy-address'],localSafety:false});
  document.querySelector('#mount').replaceChildren(renderConnection(document,view));
  return {text:document.querySelector('main').innerText,actions:view.actions};
 },kind);
 assert.doesNotMatch(shown.text,/review this request|Back to connection|Manage in Inbox/i);
 assert.ok(shown.actions.every(a=>!['connect','start-over','inbox','back-to-connection'].includes(a.id)));
 assert.ok(shown.actions.every(a=>!a.primary||a.id==='close-window'));
});

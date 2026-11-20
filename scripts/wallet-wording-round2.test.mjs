import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {connectionView, reduceSummary, stageNames, connectionActionIds, viewText} from '../capsules/_shared/wallet-connection-view.mjs';
import {shared} from './wallet-connection-view-fixtures.mjs';

const seed=shared.n7PrivateSummaries.find(r=>r.id==='site-wallet-metamask').summary;
const qrData='data:image/png;base64,'+readFileSync(new URL('./fixtures/wallet-connection-view-qr.png',import.meta.url)).toString('base64');
export function wordingInputs(window){
  return stageNames[window].flatMap(stage=>[true,false].flatMap(close=>[false,true,null].map(localSafety=>({
    window,stage,localSafety,waitSeconds:300,qrData,
    summary:reduceSummary({...seed,connector_id:'wallet-'+window,intent:stage.startsWith('transaction-')?'transaction_intent':'browser_personal_sign'},{connector:'wallet-'+window}),
    supportedActions:connectionActionIds.filter(id=>close||id!=='close-window'),
  }))));
}
for(const window of ['metamask','unisat','walletconnect'])test('wording R2: every '+window+' state keeps sentence case with and without Close',()=>{
  for(const input of wordingInputs(window)){
    const view=connectionView(input);
    for(const field of ['status','notice','afterNote'])assert.doesNotMatch(viewText(view[field]),/,\s+(?:Then|Choose|Open|Return|Check|Start|Close)\b/,JSON.stringify(input));
  }
});
test('wording R2: MetaMask has one stop-sharing instruction',()=>{
  const v=connectionView({window:'metamask',stage:'linked'});
  assert.equal(viewText(v.afterNote),'');
  assert.equal(viewText(v.notice),"To stop sharing with Home, remove this Home's connection in your wallet. Your account stays in Wallet.");
});
test('wording R2: S237 directs a sent transaction to Activity',()=>{
  const input=wordingInputs('metamask').find(r=>r.stage==='transaction-done'&&!r.supportedActions.includes('close-window'));
  input.supportedActions=[];
  assert.match(viewText(connectionView(input).notice),/Open Wallet from Home and check Activity for this transaction\./);
});
test('wording R2: unknown app names stay labels outside sentences',()=>{
  for(const window of ['metamask','unisat','walletconnect'])for(const requesting_app_name of [undefined,'']){
    const summary=reduceSummary({...seed,connector_id:'wallet-'+window,requesting_app_name},{connector:'wallet-'+window});
    assert.equal(summary.app,'Requesting app');
    const v=connectionView({window,stage:'request-unavailable',summary});
    assert.doesNotMatch(viewText(v.status)+viewText(v.notice),/in Requesting app|to Requesting app/);
  }
});
test('wording R2: shared copy uses straight apostrophes',()=>{
  for(const window of ['metamask','unisat','walletconnect'])for(const input of wordingInputs(window)){
    const v=connectionView(input);
    for(const field of ['status','notice','afterNote','connectionNotice'])assert.doesNotMatch(viewText(v[field]),/’/);
  }
});

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
    provider:{providerId:null,alternatives:[],availability:'unknown',firstAccount:null,requiredAccountAvailable:null,network:null,networkIssue:null,access:'unknown',busy:false,paymentPending:localSafety},
    summary:reduceSummary({...seed,connector_id:'wallet-'+window,intent:stage.startsWith('transaction-')?'transaction_intent':'browser_personal_sign'},{connector:'wallet-'+window}),
    supportedActions:connectionActionIds.filter(id=>close||id!=='close-window'),
  }))));
}
for(const window of ['metamask','unisat','walletconnect'])test('wording R2: every '+window+' state keeps sentence case with and without Close',()=>{
  for(const input of wordingInputs(window)){
    const view=connectionView(input);
    for(const field of ['status','notice','afterNote'])assert.doesNotMatch(viewText(view[field]),/,\s+(?!(?:MetaMask|Brave|UniSat|Wallet|Home|Activity|Browser|Ethereum|Elastos|Base|Sepolia|Bitcoin)\b)[A-Z]/,JSON.stringify(input));
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

for(const engine of ['chromium','webkit'])test('wording R2: render all three windows in '+engine,async t=>{
  const {windowTestOptions}=await import('./lib/walletconnect-window-resources.mjs');
  const options=windowTestOptions(engine);
  if(options.skip){t.skip(options.skip);return;}
  const {browserFixture}=await import('./lib/wallet-connection-browser-fixture.mjs');
  const f=await browserFixture(engine);
  try{
    for(const window of ['metamask','unisat','walletconnect']){
      const rows=wordingInputs(window);
      const result=await f.page.evaluate(async rows=>{
        const m=await import('/capsules/_shared/wallet-connection-view.mjs');
        return rows.map(input=>{
          const v=m.connectionView(input),root=m.renderConnection(document,v);
          document.querySelector('#mount').replaceChildren(root);
          return {stage:input.stage,close:input.supportedActions.includes('close-window'),text:root.textContent};
        });
      },rows);
      for(const row of result)assert.doesNotMatch(row.text,/,\s+(?!(?:MetaMask|Brave|UniSat|Wallet|Home|Activity|Browser|Ethereum|Elastos|Base|Sepolia|Bitcoin)\b)[A-Z]/,window+'/'+row.stage+'/'+row.close);
      t.diagnostic(window+': '+result.length+' rendered states');
    }
  }finally{await f.close();}
});

test('wording R2: strict title oracle rejects every old Inbox heading',async()=>{
  const {assertTitleSources,canonicalRequestTitles,currentTitleSources,rustTitlePath}=await import('./lib/wallet-connection-title-oracle.mjs');
  const sources=structuredClone(currentTitleSources);
  sources[rustTitlePath].source='fn wallet_approval_title(intent: &str) -> String {\n    match intent {\n'+Object.entries(canonicalRequestTitles).map(([intent,title])=>'        '+(intent==='unknown_kind'?'_':JSON.stringify(intent))+' => '+JSON.stringify(title)+'.to_string(),').join('\n')+'\n    }\n}';
  const reduce=intent=>reduceSummary({...seed,intent},{connector:'wallet-metamask'}).title;
  await assertTitleSources(reduce,sources);
  for(const [settled,old] of [['Review sign-in request','Wallet sign-in request'],['Review access request','Wallet access request'],['Sign a credential','Credential signing request'],['Review publishing request','Publish approval request'],['Share your wallet address with this site','Browser account access request'],['Confirm this Bitcoin account is yours','Bitcoin proof request'],['Review request','Wallet approval request']]){
    const broken=structuredClone(sources);
    broken[rustTitlePath].source=broken[rustTitlePath].source.replace(settled,old);
    await assert.rejects(()=>assertTitleSources(reduce,broken),assert.AssertionError);
  }
});

import { viewText } from '../../capsules/_shared/wallet-connection-view.mjs';

// Independent acceptance facts: contract W:986, H:755-775; design's receipt stages.
// These facts use the supplied input, never product answered/paymentRisk flags.
const approvalStages={walletconnect:['request-waiting','request-multiple','transaction-waiting','request-selected-second'],metamask:['request-network-declined','request-waiting','request-multiple','request-unsendable','request-typed-data','transaction-waiting','request-selected-second','access-wrong-account'],unisat:['request-waiting','request-multiple','request-unsendable','request-selected-second'],panel:[]};
const receipts = new Set(['request-done','request-declined','request-access-error','request-wallet-error','request-expired','request-late-ignored','request-sent-wallet-removed','request-unavailable','request-next','transaction-done','transaction-declined','transaction-access-error','transaction-late-result']);
const unresolved = new Set(['transaction-phone','transaction-extension','transaction-timeout','transaction-cancelled','transaction-reopened','transaction-wallet-error','transaction-wallet-removed','link-error','request-wallet-error']);
const stopped = new Set(['preparing-qr','internet-clearing','disconnecting','extension-busy','link-busy','request-busy','transaction-busy','link-timeout','request-timeout','transaction-timeout','link-cancelled','request-cancelled','transaction-cancelled']);
export function ruleFacts(row, shared, expected) {
  const packet=id=>shared?.messages.find(r=>r.id===id)?.message;
  const message=packet(row.provider),safety=packet(row.safety)?.snapshot?.paymentPending;
  const request=row.summaryInput || shared?.n7PrivateSummaries.find(r=>r.id===(row.summary||row.summarySeed))?.summary;
  const disposition=message?.settled?.result || ({declined:'declined',request_not_authorized:'refused'}[message?.outcome]);
  const notSent=['declined','refused'].includes(disposition);
  const payment=(row.window==='walletconnect'?(Object.hasOwn(row.local,'paymentPending')?row.local.paymentPending:false):safety??null)!==false || request?.intent==='transaction_intent'&&!notSent&&unresolved.has(row.stage);
  const answered=receipts.has(row.stage)||message?.outcome==='request_unavailable'||request?.intent==='transaction_intent'&&!!message?.settled?.receipt;
  const guardedAccount=!!row.local.account && (['site-access-ended','account-unavailable','link-wait','linked'].includes(row.stage)||expected?.inventory.some(text=>['Account to confirm','Required account'].includes(text)));
  const approval=approvalStages[row.window].includes(row.stage)&&request?.capsule_id==='browser'&&!!request.requesting_origin;
  const linkedFocus=['walletconnect','metamask','unisat'].includes(row.window)&&['linked','linked-multiple'].includes(row.stage)?row.window==='walletconnect'?'outcome':'close-window':undefined;
  return {approval,wait:!!expected?.wait&&!answered&&!approval&&row.stage!=='request-list',payment,answered,notSent,capability:row.window!=='metamask'||!!request||guardedAccount,needsExit:stopped.has(row.stage),focus:linkedFocus??(approval?'close-window':answered?'outcome':expected?.focus)};
}
export function ruleFailures(view, {row,shared,expected,facts}={}) {
  const f=facts || (row ? ruleFacts(row,shared,expected) : {});
  const failures=[];
  const text=[viewText(view.status),viewText(view.notice),viewText(view.afterNote)].join(' ');
  const ids=view.actions.map(a=>a.id);
  const exits=['close-window','start-over','open-request-app','open-wallet-activity','inbox','cancel','stop-waiting','connect','finish','send-message','restore-access'];
  if(f.needsExit&&!ids.some(id=>exits.includes(id)))failures.push('exit');
  const homeCopy=[...view.status,...view.notice,...view.afterNote].filter(p=>p.kind==='copy').map(p=>p.text).join(' ');
  if(f.payment&&(/reload/i.test(homeCopy)||view.window==='metamask'&&/QR code|also available/i.test(homeCopy)||ids.includes('use-walletconnect')))failures.push('payment');
  if(f.notSent&&/result unknown|still waiting|has not answered/i.test(text))failures.push('known-result');
  if(f.capability&&ids.includes('use-walletconnect'))failures.push('capability');
  if(ids.includes('check-access')&&text.includes('has not answered')&&view.actions.some(a=>a.primary&&a.id==='start-over')&&!text.includes('new QR code'))failures.push('sentence');
  if(!['linked','linked-multiple'].includes(view.stage)&&view.actions.some(a=>a.primary&&a.id==='close-window')&&!/close (this )?window/i.test(text))failures.push('sentence');
  if(f.answered&&(!view.request?.id||!view.request?.app||!view.status.length||view.wait!==null||ids.includes('send-request')||view.focus!=='outcome'))failures.push('answered');
  if(/home:|fixture-carried-token|wallet-connector-effect|invalid_request|0xdeadbeef|\bN[1-7]\b/.test(text))failures.push('internal');
  if([...view.status,...view.notice,...view.afterNote].some(p=>!['copy','wallet','app','site','home','network'].includes(p.kind)))failures.push('isolation');
  return failures;
}
export function layoutFailures(view, observed, facts={}) {
  const failures=[];
  if(observed.scrollWidth>observed.width+1)failures.push('horizontal');
  for(const name of observed.names)if(name.dir!=='auto'||name.bidi!=='isolate'||(name.kind==='site'?(name.whiteSpace!=='normal'||name.textOverflow==='ellipsis'):(name.clipOverflow!=='hidden'||name.whiteSpace!=='nowrap')))failures.push('isolation');
  if(facts.wait||facts.answered||facts.needsExit){
    if(observed.feedback.some(f=>!f.visible))failures.push('feedback');
    if(!facts.answered&&!observed.controls.some(b=>b.visible&&['cancel','stop-waiting','close-window','start-over','open-wallet-activity','open-request-app','open-wallet','connect','finish','send-message','restore-access','inbox'].includes(b.id)))failures.push('exit');
  }
  return failures;
}

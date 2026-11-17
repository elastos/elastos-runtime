import { ruleFacts } from './wallet-connection-view-rules.mjs';
import { shared } from '../wallet-connection-view-fixtures.mjs';
// Independent expected copy starts at the captured design receipt, not product templates.
export function contractCopy(expected, row, view) {
  const facts=ruleFacts(row,shared,expected);
  const name=row.local.account?.name||(row.window==='unisat'?'UniSat':'MetaMask');
  const seed=row.summaryInput||shared.n7PrivateSummaries.find(r=>r.id===(row.summary||row.summarySeed))?.summary;
  const raw={...seed,...(!row.summary?row.provisionalSummary:{})};
  const app=raw?.requesting_app_name||({browser:'Browser',notes:'Notes'}[raw?.capsule_id])||'Browser',site=raw?.requesting_origin||'the requesting site';
  const network=row.provisionalInput?.targetNetwork||row.local.account?.accounts[0].networks[0]||'the requested network';
  const replace=text=>text.replaceAll('MetaMask',name).replaceAll('UniSat',name).replaceAll('Browser',app).replaceAll('Notes',app).replaceAll('example.org',site)
    .replace(/You declined this (transaction|message) in ([^.]+)\./g,'$2 did not approve this $1.')
    .replaceAll(`return to ${site} in ${app}`,`return to ${app}`).replaceAll(`Start it again on ${site} in ${app}`,`Start it again in ${app}`)
    .replace('Available: 0x2aB5…a4C2. ','').replace('Connect on Ethereum to',`Connect on ${network} to`).replace('supports Base and',`supports ${network} and`);
  const result=Object.fromEntries(Object.entries(expected.copy).map(([key,value])=>[key,replace(value)]));
  if(row.summaryInput?.intent==='transaction_intent'&&facts.notSent&&row.provider?.includes('refused')){
    result.status=`${name} did not allow this transaction.`;
    result.notice='Review Wallet activity before starting a new request.';
  }
  if(facts.payment){
    if(result.notice.includes('If '))result.notice=result.notice.split('If ')[0];
    if(result.notice.startsWith('Enable '))result.notice='Close this window and check your wallet.';
  }
  if(view.actions.some(a=>a.primary&&a.id==='close-window')&&!/close (this )?window/i.test(`${result.status} ${result.notice}`))result.notice=`Close this window. ${result.notice}`.trim();
  if(row.stage==='disconnecting')result.notice='Disconnecting continues after you close this window.';
  return result;
}

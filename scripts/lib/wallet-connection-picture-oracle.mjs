import { ruleFacts } from './wallet-connection-view-rules.mjs';
import { shared } from '../wallet-connection-view-fixtures.mjs';
// Independent expected copy starts at the captured design receipt, not product templates.
export function contractCopy(expected, row, view) {
  const facts=ruleFacts(row,shared,expected);
  const provider=shared.messages.find(r=>r.id===row.provider)?.message.snapshot;
  const known=provider?.availability==='found'?({'io.metamask':'MetaMask','com.brave.wallet':'Brave Wallet',unisat:'UniSat'}[provider.providerId]):null;
  const name=row.window==='walletconnect'?row.local.account?.name||'WalletConnect':known||'your browser wallet';
  const seed=row.summaryInput||shared.n7PrivateSummaries.find(r=>r.id===(row.summary||row.summarySeed))?.summary;
  const raw={...seed,...(!row.summary?row.provisionalSummary:{})};
  const app=raw?.requesting_app_name||({browser:'Browser',notes:'Notes'}[raw?.capsule_id])||'Browser',site=raw?.requesting_origin||'the requesting site';
  const network=row.provisionalInput?.targetNetwork||row.local.account?.accounts[0].networks[0]||'the requested network';
  const replace=text=>text.replaceAll('MetaMask',name).replaceAll('UniSat',name).replaceAll('Browser',app).replaceAll('Notes',app).replaceAll('example.org',site)
    .replace(/You declined this (transaction|message) in ([^.]+)\./g,'$2 did not approve this $1.')
    .replaceAll(`return to ${site} in ${app}`,`return to ${app}`).replaceAll(`Start it again on ${site} in ${app}`,`Start it again in ${app}`)
    .replace(/^your browser wallet/,'Your browser wallet')
    .replace('Available: 0x2aB5…a4C2. ','').replace('Connect on Ethereum to',`Connect on ${network} to`).replace('supports Base and',`supports ${network} and`);
  const result=Object.fromEntries(Object.entries(expected.copy).map(([key,value])=>[key,replace(value)]));
  if(row.summaryInput?.intent==='transaction_intent'&&facts.notSent&&row.provider?.includes('refused')){
    result.status=`${name==='your browser wallet'?'Your browser wallet':name} did not allow this transaction.`;
    result.notice='Review Wallet activity before starting a new request.';
  }
  if(facts.payment){
    if(result.notice.includes('If '))result.notice=result.notice.split('If ')[0];
    if(result.notice.startsWith('Enable '))result.notice=result.notice.split(', then reload Home')[0]+'. Open '+name+' again from Wallet.';
  }
  // R5: absence does not prove that an extension can be enabled, W926-944.
  if(['metamask','unisat'].includes(row.window)&&['extension-missing','extensions-unavailable','other-ethereum-wallet'].includes(row.stage)){result.status='Your browser wallet was not found here.';result.notice='Open this connection from Wallet in a browser where your wallet is available.';}
  if(['metamask','unisat'].includes(row.window)&&[`To try again, return to ${app}.`,`Start a new request in ${app} to try again.`].includes(result.notice))result.notice=`To try again, return to ${app} and make a new request.`;
  if(facts.payment&&row.window==='metamask'&&row.stage==='ready-multiple')result.notice='Connect will use '+name+'.';
  if(view.actions.some(a=>a.primary&&a.id==='close-window')&&!/close (this )?window/i.test(`${result.status} ${result.notice}`))result.notice=`Close this window. ${result.notice}`.trim();
  if(row.stage==='disconnecting')result.notice='Disconnecting continues after you close this window.';
  return result;
}

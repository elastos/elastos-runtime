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
    result.notice='Review Activity in Wallet before starting a new request.';
  }
  if(facts.payment){
    if(result.notice.includes('If '))result.notice=result.notice.split('If ')[0];
    if(result.notice.startsWith('Enable '))result.notice=result.notice.split(', then reload Home')[0]+'. Open '+name+' again from Wallet.';
  }
  // R5: absence does not prove that an extension can be enabled, W926-944.
  if(['metamask','unisat'].includes(row.window)&&['extension-missing','extensions-unavailable','other-ethereum-wallet'].includes(row.stage)){result.status='Your browser wallet was not found here.';result.notice='Open this connection from Wallet in a browser where your wallet is available.';}
  if(['metamask','unisat'].includes(row.window)&&[`To try again, return to ${app}.`,`Start a new request in ${app} to try again.`].includes(result.notice))result.notice=`To try again, return to ${app} and make a new request.`;
  if(facts.payment&&row.window==='metamask'&&row.stage==='ready-multiple')result.notice='Connect will use '+name+'.';
  if(row.window==='walletconnect'&&row.stage==='internet-refused')result.notice='Connect a wallet to ask Home for internet access again.';
  if(row.window==='walletconnect'&&row.stage==='disconnected')result.notice='';
  if(row.window==='walletconnect'){
    const copy={
      'internet-off':{notice:'Connect again to ask for internet access, then answer in Inbox.'},
      'internet-refused':{status:'Internet access for WalletConnect is off.'},
      'internet-clearing':{status:'Internet access for WalletConnect is off.'},
      'link-wait':{status:`Open ${name} and sign the message to confirm this account is yours.`,notice:`If you stop waiting, Home disconnects from ${name}. The request may still be waiting there.`},
      'link-declined':{status:'Your wallet declined to sign the message.',notice:'Send another message to confirm this account.'},
      'request-phone':{notice:`Check the message in ${name}. If you stop waiting, Home disconnects from ${name}. The request may still be waiting there.`},
      'transaction-phone':{notice:`Check the transaction in ${name}. If you stop waiting, Home disconnects from ${name}. The transaction may still be waiting there or may already have been sent.`},
      'transaction-deadline':{notice:`Start a new transaction in ${app}.`},
      'transaction-declined':{notice:`To try again, go back to ${app}. In Wallet, choose Dismiss to clear this request.`},
      'request-internet-off':{status:'Internet access for WalletConnect is off.',notice:'Choose Back to connection and connect again to ask for internet access. Allow it in Inbox, then return to this request and send it.'},
      'request-internet-pending':{notice:'Allow internet access in Inbox to continue with this request.'},
      'guest-access':{status:'You cannot turn on internet access for WalletConnect.',notice:'Ask an admin of this Home to open WalletConnect, choose Connect wallet, then allow internet access in Inbox.'},
      'request-unavailable':{status:`This request is unavailable here. To try again, start a new request in ${app}.`},
    }[row.stage];
    Object.assign(result,copy);
    result.status=result.status.replace('Internet access is off for WalletConnect.','Internet access for WalletConnect is off.').replace('Transaction result unknown.','Home could not confirm the transaction result.').replace('You stopped waiting. Result unknown.','You stopped waiting. The transaction may have been sent.');
    if(['transaction-timeout','transaction-cancelled','transaction-wallet-error','transaction-reopened','transaction-wallet-removed'].includes(row.stage))result.notice=`Before you send again, check ${name} and Activity in Wallet.`;
    if(result.notice===`To try again, return to ${app}.`)result.notice=`To try again, start a new request in ${app}.`;
  }
  if(!['linked','linked-multiple'].includes(row.stage)&&view.actions.some(a=>a.primary&&a.id==='close-window')&&!/close (this )?window/i.test(`${result.status} ${result.notice}`))result.notice=`Close this window. ${result.notice}`.trim();
  if(row.stage==='disconnecting')result.notice='Disconnecting continues after you close this window.';
  return result;
}

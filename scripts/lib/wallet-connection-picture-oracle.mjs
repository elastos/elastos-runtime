import { ruleFacts } from './wallet-connection-view-rules.mjs';
import { shared } from '../wallet-connection-view-fixtures.mjs';
// Independent expected copy starts at the captured design receipt, not product templates.
export function contractCopy(expected, row, view) {
  const facts=ruleFacts(row,shared,expected);
  const provider=shared.messages.find(r=>r.id===row.provider)?.message.snapshot;
  const known=provider?.availability==='found'?({'io.metamask':'MetaMask','com.brave.wallet':'Brave Wallet',unisat:'UniSat'}[provider.providerId]):null;
  const name=row.window==='walletconnect'?row.local.account?.name||'your wallet':known||(row.window==='unisat'?'UniSat':'your wallet');
  const seed=row.summaryInput||shared.n7PrivateSummaries.find(r=>r.id===(row.summary||row.summarySeed))?.summary;
  const raw={...seed,...(!row.summary?row.provisionalSummary:{})};
  const app=raw?.requesting_app_name||({browser:'Browser',notes:'Notes'}[raw?.capsule_id])||'Browser',site=raw?.requesting_origin||'the requesting site';
  const network=row.provisionalInput?.targetNetwork||row.local.account?.accounts[0].networks[0]||'the requested network';
  const replace=text=>text.replaceAll('MetaMask',name).replaceAll('UniSat',name).replaceAll('Browser',app).replaceAll('Notes',app).replaceAll('example.org',site)
    .replace(/You declined this (transaction|message) in ([^.]+)\./g,'$2 did not approve this $1.')
    .replaceAll(`return to ${site} in ${app}`,`return to ${app}`).replaceAll(`Start it again on ${site} in ${app}`,`Start it again in ${app}`)
    .replace(/^your wallet/,'Your wallet').replaceAll('Wallet activity','Activity in Wallet')
    .replace('Available: 0x2aB5…a4C2. ','').replace('Connect on Ethereum to',`Connect on ${network} to`).replace('supports Base and',`supports ${network} and`);
  const result=Object.fromEntries(Object.entries(expected.copy).map(([key,value])=>[key,replace(value)]));
  if(row.summaryInput?.intent==='transaction_intent'&&facts.notSent&&row.provider?.includes('refused')){
    result.status=`${name==='your wallet'?'Your wallet':name} did not allow this transaction.`;
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
  if(['metamask','unisat'].includes(row.window)){
    const metamask=row.window==='metamask';
    if(['ready','focus'].includes(row.stage))result.notice=metamask?`Choose an account in ${name}, then sign the message.`:'Choose an account in UniSat, then sign a message.';
    if(['extension-missing','extensions-unavailable','other-ethereum-wallet'].includes(row.stage)){
      result.status=metamask?'Home could not find MetaMask or Brave Wallet in this browser.':'Home could not find UniSat in this browser.';
      result.notice=metamask?'Close this window. Open Home in a browser with MetaMask or Brave Wallet, then choose MetaMask in Wallet.':'Close this window. Open Home in a browser where UniSat is available, then open this connection from Wallet.';
    }
    if(['extension-wait','link-wait'].includes(row.stage))result.notice=`Find ${name} in your browser's extensions menu. Unlock it if asked. Stopping here does not cancel the request in ${name}.`;
    if(row.stage==='request-extension')result.notice=`Open ${name} from your browser's extensions menu. Stopping here does not cancel the request in ${name}.`;
    if(row.stage==='account-unavailable')result.status=metamask?`Home cannot confirm access to this account in ${name}.`:'Home cannot use this UniSat account right now.';
    if(row.stage==='request-unsendable')result.status=metamask?`Home cannot confirm access to the account this request needs in ${name}.`:'Home cannot use the UniSat account this request needs.';
    if(metamask){
      if(row.stage==='linked'){result.status='Account saved in Wallet.';result.notice=`To stop sharing with Home, remove this Home's connection in ${name}. Your account stays in Wallet.`;}
      if(row.stage==='request-network-declined')result.status=`Home could not confirm the requested network in ${name}.`;
      if(row.stage==='transaction-extension')result.notice=`Check the transaction in ${name}. Stopping here does not cancel the request in ${name}.`;
      if(row.stage==='transaction-timeout')result.status='Home does not know if the transaction was sent.';
      if(row.stage==='transaction-cancelled')result.status='You stopped waiting. The transaction may have been sent.';
      if(['transaction-timeout','transaction-cancelled','transaction-wallet-error'].includes(row.stage))result.notice=`Before you send again, check ${name}, then open Wallet from Home and check Activity. Closing this window does not cancel the request in ${name}.`;
      if(row.stage==='window-expired')result.notice='Close this window, then open Wallet from Home and choose MetaMask.';
      if(row.stage==='link-error')result.status='Home could not confirm the connection.';
      if(row.stage==='request-unavailable')result.status=`Home cannot use this request. Go back to ${app} and start a new request.`;
    } else if(row.stage==='request-unavailable')result.status='This request is unavailable. Return to the app and make a new request.';
    if([`To try again, return to ${app}.`,`Start a new request in ${app} to try again.`,`To try again, return to ${app} and make a new request.`].includes(result.notice))result.notice=metamask?`To try again, go back to ${app} and start a new request.`:`To try again, return to ${app} and make a new request.`;
  }
  if(!['linked','linked-multiple'].includes(row.stage)&&view.actions.some(a=>a.primary&&a.id==='close-window')&&!/close (this )?window/i.test(`${result.status} ${result.notice}`))result.notice=`Close this window. ${result.notice}`.trim();
  if(row.stage==='disconnecting')result.notice='Disconnecting continues after you close this window.';
  return result;
}

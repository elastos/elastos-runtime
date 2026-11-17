// Independent expected copy starts at the captured design receipt, not product templates.
export function contractCopy(expected, row, view) {
  const name=view.account?.name||(row.window==='unisat'?'UniSat':'MetaMask');
  const app=view.request?.app||'Browser',site=view.request?.site||'the requesting site';
  const network=row.provisionalInput?.targetNetwork||row.local.account?.accounts[0].networks[0]||'the requested network';
  const replace=text=>text.replaceAll('MetaMask',name).replaceAll('UniSat',name).replaceAll('Browser',app).replaceAll('Notes',app).replaceAll('example.org',site)
    .replace(/You declined this (transaction|message) in ([^.]+)\./g,'$2 did not approve this $1.')
    .replace('Available: 0x2aB5…a4C2. ','').replace('Connect on Ethereum to',`Connect on ${network} to`).replace('supports Base and',`supports ${network} and`);
  const result=Object.fromEntries(Object.entries(expected.copy).map(([key,value])=>[key,replace(value)]));
  if(view.request?.transaction&&view.walletResult?.disposition==='refused'){
    result.status=`${name} did not allow this transaction.`;
    result.notice='Review Wallet activity before starting a new request.';
  }
  if(view.paymentRisk)result.notice=result.notice.replace(/If .*?Reload control\./g,'').replace(/Enable .*?Open .*? from Wallet\./g,'Close this window and check your wallet.');
  if(view.actions.some(a=>a.primary&&a.id==='close-window')&&!/close (this )?window/i.test(`${result.status} ${result.notice}`))result.notice=`Close this window. ${result.notice}`.trim();
  return result;
}

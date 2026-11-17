import { viewText } from '../../capsules/_shared/wallet-connection-view.mjs';

// Acceptance rules inspect rendered models, independently of stage implementation.
export function ruleFailures(view) {
  const failures = [];
  const text = [viewText(view.status), viewText(view.notice), viewText(view.afterNote)].join(' ');
  const actions = view.actions;
  const ids = actions.map(a => a.id);
  const endsSituation = ['close-window','start-over','open-request-app','open-wallet-activity','inbox','cancel','stop-waiting','connect','finish','send-message','restore-access'];
  if (/busy|timeout|cancelled|disconnecting|preparing/.test(view.stage) && !ids.some(id => endsSituation.includes(id))) failures.push('exit');
  if (view.paymentRisk && (/reload/i.test(text) || ids.includes('use-walletconnect'))) failures.push('payment');
  if(['declined','refused'].includes(view.walletResult?.disposition)&&/result unknown|still waiting|has not answered/i.test(text))failures.push('known-result');
  if ((view.window === 'unisat' || view.request || view.showAccount) && ids.includes('use-walletconnect')) failures.push('capability');
  const primary = actions.find(a => a.primary);
  if(primary?.id==='close-window'&&!/close (this )?window/i.test(text))failures.push('sentence');
  if (ids.includes('check-access') && /has not answered/.test(text) && primary) {
    if (primary.id === 'close-window' && !/close this window/i.test(text) || primary.id === 'start-over' && !/new QR code/i.test(text)) failures.push('sentence');
  }
  if (view.answered && (!view.request?.id || !view.request?.app || !view.status.length || view.wait !== null || ids.includes('send-request'))) failures.push('answered');
  if (/home:|fixture-carried-token|wallet-connector-effect|invalid_request|0xdeadbeef|\bN[1-7]\b/.test(text)) failures.push('internal');
  if ([...view.status,...view.notice,...view.afterNote].some(p => !['copy','wallet','app','site','home','network'].includes(p.kind))) failures.push('isolation');
  return failures;
}

export function layoutFailures(view, observed) {
  const failures=[];
  if(observed.scrollWidth>observed.width+1)failures.push('horizontal');
  for(const name of observed.names)if(name.dir!=='auto'||name.bidi!=='isolate'||name.overflow!=='hidden'||name.whiteSpace!=='nowrap')failures.push('isolation');
  if(view.wait||view.answered||/busy|timeout|cancelled|preparing|disconnecting/.test(view.stage)){
    if(observed.feedback.some(f=>!f.visible))failures.push('feedback');
    if(!view.answered&&!observed.controls.some(b=>b.visible&&['cancel','stop-waiting','close-window','start-over','open-wallet-activity','open-request-app','open-wallet','connect','finish','send-message','restore-access','inbox'].includes(b.id)))failures.push('exit');
  }
  return failures;
}

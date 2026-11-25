// Home owns the sign-in ceremony; this view presents System's account operation.
const names = {metamask:'MetaMask',unisat:'UniSat',walletconnect:'WalletConnect'};
const node = (tag,value,className='') => {const el=document.createElement(tag);el.textContent=value;el.className=className;return el;};
export function renderWalletSigninManagement(body, footer, state, {account, choose, confirm, approve, cancel, retry, methods}) {
  const heading=node('h2', state.stage==='options' ? 'Add wallet for sign-in' : 'Turn on sign-in');heading.id='wallet-signin-title';body.append(heading);
  const button=(label,action,primary=false)=>{const b=node('button',label,'el-button'+(primary?' el-button-primary':''));b.type='button';b.onclick=action;return b;};
  if(state.stage==='options') {
    body.append(node('p','Sign in to this Home','one-step'));
    const list=node('div','','connection-card connection-options-list');
    for(const choice of methods) {
      const row=button('',()=>choose(choice.providerId?`${choice.connector}:${choice.providerId}`:choice.connector));row.className='connection-option';
      const icon=document.createElement('img');icon.src=`./connection-${choice.connector}.png`;icon.alt='';
      const label=node('span',choice.label||names[choice.connector]);
      if(choice.connector==='walletconnect')label.append(node('small','Rainbow, Trust and other phone wallets'));
      if(choice.used){label.append(node('small','Already signs in'));row.disabled=true;}
      row.append(icon,label,node('span','›'));list.append(row);
    }
    body.append(list);
  } else {
    const signing=['review','signing'].includes(state.stage);
    body.append(node('p',signing?'1 of 2 · Wallet signature':'2 of 2 · Passkey','one-step'));
    if(!signing && ['approval','passkey','completing'].includes(state.stage))body.append(node('p','✓ Wallet signature received','one-completed'));
    if(state.wallet) {
      const card=node('div','','one-proof-wallet'), identity=node('div','','one-identity');
      const icon=document.createElement('img');icon.className='one-logo';icon.alt='';icon.src=`./connection-${state.wallet.connector}.png`;
      const copy=node('div',''),name=node('strong',state.wallet.displayName||names[state.wallet.connector]);name.dir='auto';
      const meta=node('div','','one-meta'),address=node('code',state.wallet.address.startsWith('bc1')?`${state.wallet.address.slice(0,8)}…${state.wallet.address.slice(-6)}`:`${state.wallet.address.slice(0,6)}…${state.wallet.address.slice(-4)}`);
      const network=state.wallet.connector==='unisat'?'Bitcoin':({20:'ESC',8453:'Base'}[state.wallet.chain_id]||`Chain ${state.wallet.chain_id}`);
      meta.append(address,node('span',network));copy.append(name,meta);identity.append(icon,copy);card.append(identity);body.append(card);
    }
    if(signing) {
      body.append(node('div','Add this wallet as a way to sign in to this Home.','one-message'));
      const fields=node('dl','','one-proof-fields');
      for(const[label,value]of [['Home',`${account}’s Home`],['Account',account],['Requested by','System']]){const row=node('div','');row.append(node('dt',label),node('dd',value));fields.append(row);}body.append(fields);
    } else if(['approval','passkey'].includes(state.stage)) body.append(node('p',`Allow this wallet to sign in to ${account}'s account.`));
    if(state.approvalNotice)body.append(node('p',state.approvalNotice,'connection-note'));
    if(state.message){const message=node('p',state.message,'connection-note');message.setAttribute('role','status');body.append(message);}
  }
  const actions=node('div','','connection-actions');
  if(!['completing','unknown'].includes(state.stage))actions.append(button('Cancel',cancel));
  if(state.stage==='review')actions.append(button('Sign message',confirm,true));
  if(state.stage==='approval')actions.append(button('Approve with passkey',approve,true));
  if(['error','list-error','unknown'].includes(state.stage))actions.append(button(state.stage==='unknown'?'Check again':'Try again',retry,true));
  footer.append(actions);
}

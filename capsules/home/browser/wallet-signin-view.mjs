import {createWalletSigninFlow,connectorName,walletNetwork,walletSigninOriginAllowed} from './wallet-signin-flow.mjs';
import {copyHomeWalletConnectionLink} from './home-clipboard-host.js?v=home-20260726a';
import {selectSigninWallet} from './wallet-signin-signers.mjs';
const titles={signin:'Sign in with wallet',add:'Add wallet',enable:'Turn on wallet sign-in',disable:'Turn off wallet sign-in',remove:'Remove wallet'};
const effects={signin:'This wallet opens your existing Home account. Approvals need your passkey.',add:'Home will add this wallet to your account with Sign in off.',enable:'This wallet will be able to sign in to your Home account.',disable:'Home will turn off sign-in for this wallet and end its sign-in sessions. Wallet keeps its payment connections.',remove:'Home will remove this sign-in method and end its sign-in sessions. Wallet keeps its payment connections.'};
function node(tag,text,className) {const el=document.createElement(tag);if(text)el.textContent=text;if(className)el.className=className;return el;}
export async function walletSigninApi(path,body,token='') {
  const response=await fetch(path,{
    method:body===undefined?'GET':'POST',cache:'no-store',signal:AbortSignal.timeout(15000),
    headers:{'content-type':'application/json',...(token?{'x-elastos-home-token':token}:{})},
    ...(body===undefined?{}:{body:JSON.stringify(body)}),
  });
  if(!response.ok)throw Object.assign(new Error('Home refused the wallet request'),{status:response.status});
  return response.json();
}
export function createHomeWalletSignin({approve,onSignin,onPasskey,onChanged=()=>{}}) {
  let dialog,previousFocus,token='',initial={},resolveRequest,ticker;
  let currentState;
  const flow=createWalletSigninFlow({
    api:(path,body)=>walletSigninApi(path,body,token),select:selectSigninWallet,
    approve:(approval,options)=>approve(token,approval.operation,approval.request,options),render,
    onComplete:async(result,action)=>{
      if(action==='signin') {close();await onSignin(result);}
      else {onChanged();resolveRequest?.({status:'complete'});resolveRequest=null;}
    },
  });
  function close() {
    clearInterval(ticker);dialog?.close();dialog?.remove();dialog=null;previousFocus?.focus();
    resolveRequest?.({status:'cancelled'});resolveRequest=null;
  }
  function button(text,action,secondary=false) {
    const el=node('button',text,secondary?'signin-button signin-secondary':'signin-button');el.type='button';el.onclick=action;return el;
  }
  function render(state) {
    currentState=state;
    if(state.stage==='closed'){close();return;}
    if(!dialog) {
      previousFocus=document.activeElement;dialog=node('dialog',null,'signin-dialog');
      dialog.setAttribute('aria-labelledby','wallet-signin-title');
      dialog.addEventListener('cancel',event=>{event.preventDefault();void flow.cancel();});
      document.body.append(dialog);dialog.showModal();
    }
    const hadFocus=dialog.contains(document.activeElement);
    dialog.dataset.state=state.stage;dialog.replaceChildren();
    dialog.append(node('p','Home','signin-eyebrow'));
    const title=node('h2',titles[state.action]);title.id='wallet-signin-title';dialog.append(title);
    if(state.stage==='choice') {
      dialog.append(node('p',state.action==='signin'?'Choose a wallet you added to your account.':'Choose the wallet to add. Sign in starts off.'));
      const choices=node('div',null,'signin-choices');
      for(const connector of ['walletconnect','metamask','unisat']) {
        const choice=button(connectorName(connector),()=>flow.choose(connector),true);
        if(connector==='metamask')choice.append(node('small','Compatible browser wallets'));
        if(connector==='walletconnect' && state.walletconnectAvailable!==true) {
          choice.disabled=true;
          choice.append(node('small',state.walletconnectAvailable===null?'Checking wallet sign-in availability…':'Add a wallet for Elastos Smart Chain or Base and turn Sign in on first.'));
        }
        choices.append(choice);
      }
      dialog.append(choices);
    } else if(state.stage==='internet-notice') {
      dialog.append(node('p','Home reaches your wallet over the internet through WalletConnect. The relay service can see this Home computer’s internet address.'));
      dialog.append(button('Continue',()=>flow.connect()));
    } else if(state.stage==='wallet-choice') {
      dialog.append(node('p','Choose a browser wallet.'));
      for(const choice of state.choices)dialog.append(button(choice.name,choice.choose,true));
    } else if(state.stage==='pairing') {
      dialog.append(node('p','Scan with your wallet, then approve the connection.'));
      const image=node('img',null,'signin-qr');image.alt='WalletConnect QR code';image.src=state.pairing.qr;dialog.append(image);
      const copyStatus=node('p',null,'signin-note');copyStatus.setAttribute('role','status');
      dialog.append(button('Copy link',async event=>{
        event.currentTarget.disabled=true;
        try{await copyHomeWalletConnectionLink(state.pairing.uri);copyStatus.textContent='Link copied.';}
        catch{copyStatus.textContent='Could not copy. Try again.';}
        finally{if(event.target.isConnected)event.target.disabled=false;}
      },true),copyStatus);
    }
    if(['review','signing','approval','passkey','completing','unknown'].includes(state.stage)) {
      const details=node('dl',null,'signin-details');
      for(const [label,value]of [['Account',state.account],['Home',location.origin],['Wallet',state.wallet.displayName||connectorName(state.wallet.connector)],['Address',state.wallet.address],['Network',walletNetwork(state.wallet)]]) {
        if(!value)continue;
        const row=node('div');row.append(node('dt',label),node('dd',value));details.append(row);
      }
      dialog.append(details,node('p',effects[state.action]));
      if(state.approvalNotice)dialog.append(node('p',state.approvalNotice,'signin-note'));
      if(state.stage==='review') {
        if(state.action==='signin')dialog.append(node('p','Continue only if you started this sign-in in this browser.','signin-note'));
        if(['signin','add','enable'].includes(state.action)) {
          dialog.append(node('p','Review the message before signing.','signin-note'));
          const message=node('details');message.append(node('summary','Message'),node('pre',flowMessage()));dialog.append(message);
        }
        dialog.append(button(['disable','remove'].includes(state.action)?'Use passkey':state.action==='signin'?'Sign in with wallet':'Sign message',()=>flow.confirm()));
      } else if(state.stage==='approval')dialog.append(button('Use passkey',()=>flow.approve()));
      else if(state.stage==='unknown')dialog.append(button('Check again',()=>flow.retry()));
    }
    const statuses={connecting:state.connector==='walletconnect'?'Connecting to WalletConnect…':'Select an account in your wallet.',signing:'Sign the message in your wallet.',approval:'Confirm this change with your passkey.',passkey:'Confirm with your passkey.',completing:state.action==='signin'?'Checking sign-in…':'Saving change…',done:({add:'Wallet added. Sign in is off.',enable:'Wallet sign-in is on.',disable:'Wallet sign-in is off.',remove:'Wallet removed.'})[state.action]};
    const status=node('p',state.message||statuses[state.stage]||'',state.stage==='error'?'signin-error':'signin-note');status.setAttribute('role','status');dialog.append(status);
    if(state.stage==='error') {
      if(state.refresh)dialog.append(button('Refresh',()=>flow.cancel()));
      if(state.retryable!==false)dialog.append(button('Try again',()=>flow.start(initial),state.refresh));
      if(state.action==='signin' && onPasskey && state.allowPasskey!==false)dialog.append(button('Use passkey',()=>{void flow.cancel();onPasskey();},true));
    }
    if(state.stage==='done')dialog.append(button('Done',close));
    else dialog.append(button('Cancel',()=>flow.cancel(),true));
    const expiry=node('p',null,'signin-expiry');dialog.append(expiry);
    clearInterval(ticker);
    if(!['error','done'].includes(state.stage)) {
      const update=()=>{if(initial.isCurrent && !initial.isCurrent()){void flow.cancel();return;}const seconds=Math.max(0,Math.ceil((flow.state.expiresAt||Date.now()/1000+180)-Date.now()/1000));expiry.textContent=`Expires in ${Math.floor(seconds/60)}:${String(seconds%60).padStart(2,'0')}`;};
      update();ticker=setInterval(update,1000);
    }
    if(hadFocus)dialog.querySelector('button')?.focus();
  }
  function flowMessage(){return currentState.signingMessage||'';}
  return {
    get active(){return Boolean(dialog);},
    async start(options={}) {
      if(dialog)return {status:'busy'};
      if(!walletSigninOriginAllowed(location.href)){
        token=options.token||'';initial=options;render({stage:'error',action:options.action||'signin',message:'Open this Home with HTTPS to sign in with a wallet.',retryable:false,allowPasskey:false});return {status:'failed'};
      }
      token=options.token||'';initial=options;
      let result;
      if(options.action && options.action!=='signin')result=new Promise(resolve=>{resolveRequest=resolve;});
      await flow.start(options);
      return result;
    },
    cancel:()=>flow.cancel(),
  };
}

import {createWalletSigninFlow,connectorName,walletNetwork,shortWalletAddress,walletSigninOriginAllowed} from './wallet-signin-flow.mjs';
import {copyHomeWalletConnectionLink} from './home-clipboard-host.js?v=home-20260726a';
import {selectSigninWallet} from './wallet-signin-signers.mjs';
import {readSigninOptions,readSigninChoice,saveSigninChoice,saveSigninOptions,optionId} from './wallet-signin-options.mjs';
import {connectionView,renderConnection} from './wallet-connection-view.mjs';
const titles={signin:'Sign in',add:'Add wallet',add_signin:'Add wallet',enable:'Use to sign in',disable:'Turn off sign-in',remove:'Remove wallet'};
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
  let dialog,previousFocus,token='',initial={},resolveRequest,ticker,watcher,epoch=0,remember=false,currentState;
  const flow=createWalletSigninFlow({
    api:(path,body)=>{if(initial.isCurrent&&!initial.isCurrent()&&!path.endsWith('/cancel'))throw new Error('Home session changed');return walletSigninApi(path,body,token);},
    select:async(connector,options)=>{
      if(connector!=='walletconnect'||!initial.selectWalletConnect)return selectSigninWallet(connector,options);
      dialog?.close();
      try {
        const signer=await initial.selectWalletConnect(options);
        return {...signer,sign:async message=>{dialog?.close();try{return await signer.sign(message);}finally{if(dialog&&!dialog.open)dialog.showModal();}}};
      }finally{if(dialog&&!dialog.open)dialog.showModal();}
    },
    approve:(approval,options)=>approve(token,approval.operation,approval.request,options),render,
    onComplete:async(result,action)=>{
      if(action==='signin') {close();await onSignin(result);}
      else {if(['add_signin','enable'].includes(action)&&initial.method)saveSigninOptions([...readSigninOptions().filter(row=>optionId(row)!==optionId(initial.method)),{...initial.method,sign_in_enabled:true}],undefined,{preferProvided:true});const done=resolveRequest;resolveRequest=null;close();onChanged();done?.({status:'complete'});}
    },
  });
  function close() {
    epoch++;clearInterval(ticker);clearInterval(watcher);dialog?.close();dialog?.remove();dialog=null;previousFocus?.focus();
    resolveRequest?.({status:'cancelled'});resolveRequest=null;
  }
  function button(text,action,quiet=false) {
    const el=node('button',text,quiet?'el-button el-button-quiet connection-quiet':'el-button el-button-primary');el.type='button';el.onclick=action;return el;
  }
  function option(label,detail,kind,action) {
    const el=button('',action);el.className='connection-option';
    if(kind){const icon=node('img');icon.alt='';icon.src=`/apps/home/connection-${kind}.png`;el.append(icon);}
    const copy=node('span');copy.append(node('span',label,'connection-option-label'));if(detail)copy.append(node('span',detail,'connection-note'));el.append(copy,node('span','›'));return el;
  }
  async function chooseSignin(method) {
    const id=method?optionId(method):'passkey';saveSigninChoice(remember?id:'');
    if(!method){close();onPasskey?.();return;}
    initial={...initial,action:'signin',method,automatic:true};await flow.start(initial);
  }
  function chooseConnected(method) {initial={...initial,action:initial.action==='add'?'add':method.paymentOnly?'add_signin':'enable',method,automatic:true,delegateWalletConnect:Boolean(initial.selectWalletConnect)};return flow.start(initial);}
  function options(methods) {
    render({stage:'options',action:initial.action,methods});
  }
  async function connected() {
    const request=epoch;
    try{const methods=await initial.loadConnected();if(request===epoch&&dialog)options(methods);}
    catch{if(request===epoch&&dialog)render({stage:'list-error',action:initial.action,message:'Home could not load your wallets.'});}
  }
  async function openConnector(kind) {
    const request=epoch,known=new Set(currentState.methods?.map(optionId));
    try {
      dialog.close();const opened=await initial.openConnector(`wallet-${kind}`),until=Date.now()+180000;
      // Wallet owns connection completion. Read its saved accounts before returning.
      clearInterval(ticker);let loading=false;
      ticker=setInterval(async()=>{
        if(request!==epoch||!dialog||loading)return;
        if(initial.isCurrent&&!initial.isCurrent()){void flow.cancel();return;}
        loading=true;
        try{const methods=await initial.loadConnected();if(request===epoch&&dialog&&(methods.some(m=>!known.has(optionId(m)))||opened?.isOpen?.()===false||Date.now()>until)){clearInterval(ticker);dialog.showModal();options(methods);}}
        catch{}finally{loading=false;}
      },1000);
    } catch {if(request===epoch&&dialog){dialog.showModal();render({stage:'list-error',action:initial.action,message:'Home could not open this wallet.'});}}
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
    if(state.stage==='pairing') {
      // The connector's shared QR screen owns its markup and controls.
      const view=connectionView({window:'walletconnect',stage:'qr-shown',qrData:state.pairing.qr});
      const shared=renderConnection(document,view);
      shared.querySelector('h2').id='wallet-signin-title';
      const qrDialog=shared.querySelector('.connection-dialog');qrDialog.removeAttribute('role');qrDialog.removeAttribute('aria-modal');qrDialog.removeAttribute('aria-label');
      shared.addEventListener('click',async event=>{
        const action=event.target.closest('[data-action]')?.dataset.action;
        if(action==='cancel')void flow.cancel();
        if(action==='copy-link') {
          const control=event.target.closest('button');control.disabled=true;
          try{await copyHomeWalletConnectionLink(state.pairing.uri);control.textContent='Link copied.';}
          catch{control.textContent='Try copying again';}finally{control.disabled=false;}
        }
      });
      dialog.append(shared);
    } else {
      const title=node('h2',titles[state.action]||'Sign in');title.id='wallet-signin-title';dialog.append(title);
      if(state.stage==='options') {
        const list=node('div',null,'connection-card connection-options-list');
        if(state.action==='signin'){const passkey=option('Passkey','','',()=>chooseSignin(null));passkey.disabled=!window.PublicKeyCredential;list.append(passkey);}
        for(const method of state.methods||[])list.append(option(method.displayName||connectorName(method.connector),`${shortWalletAddress(method.address)} · ${walletNetwork(method)}`,method.connector==='metamask'&&method.providerId&&method.providerId!=='io.metamask'?'wallet':method.connector,()=>state.action==='signin'?chooseSignin(method):chooseConnected(method)));
        if(state.action!=='signin')list.append(option('New wallet','','wallet',()=>render({...state,stage:'new-wallet'})));
        dialog.append(list);
        if(state.action==='signin') {
          const label=node('label',null,'signin-remember'),input=node('input');input.type='checkbox';input.checked=remember;input.onchange=()=>{remember=input.checked;if(!remember)saveSigninChoice('');};label.append(input,document.createTextNode('Remember my choice'));dialog.append(label);
        }
      } else if(state.stage==='new-wallet') {
        const list=node('div',null,'connection-card connection-options-list');
        for(const kind of ['metamask','unisat','walletconnect'])list.append(option(connectorName(kind),'',kind,()=>openConnector(kind)));
        dialog.append(list);
      } else if(state.stage==='wallet-choice') {
        for(const choice of state.choices)dialog.append(option(choice.name,'','',choice.choose));
      } else if(state.stage==='internet-notice') {
        dialog.append(node('p','Home reaches your wallet over the internet through WalletConnect. The relay service can see this Home computer’s internet address.','connection-note'));
        dialog.append(button('Continue',()=>flow.connect()));
      } else if(state.stage==='review'&&!state.automatic) {
        dialog.append(node('p',state.action==='disable'?'Home will turn off sign-in for this wallet and end its sign-in sessions.':'Home will remove this sign-in method and end its sign-in sessions.','connection-note'));
        dialog.append(button('Use passkey',()=>flow.confirm()));
      }
      if(state.wallet&&state.stage!=='review')dialog.append(node('p',`${connectorName(state.wallet.connector)} · ${shortWalletAddress(state.wallet.address)} · ${walletNetwork(state.wallet)}`,'connection-note'));
      const statuses={loading:'Loading wallets…',connecting:'Open your wallet.',signing:'Sign the message in your wallet.',approval:'Confirm with your passkey.',passkey:'Confirm with your passkey.',completing:state.action==='signin'?'Checking sign-in…':'Saving change…'};
      if(state.message||statuses[state.stage]){const status=node('p',state.message||statuses[state.stage],'connection-note');status.setAttribute('role','status');dialog.append(status);}
      if(state.approvalNotice)dialog.append(node('p',state.approvalNotice,'connection-note'));
      if(state.signingMessage) {
        const details=node('details');details.append(node('summary','Details'),node('p',location.origin),node('pre',state.signingMessage));dialog.append(details);
      }
      if(state.stage==='approval')dialog.append(button('Use passkey',()=>flow.approve()));
      if(state.stage==='unknown')dialog.append(button('Check again',()=>flow.retry()));
      if(state.stage==='error'||state.stage==='list-error') {
        if(state.retryable!==false)dialog.append(button('Try again',()=>state.stage==='list-error'?connected():flow.start(initial)));
        if(state.action==='signin'&&onPasskey&&state.allowPasskey!==false)dialog.append(button('Use passkey',()=>chooseSignin(null),true));
      }
      const actions=node('div',null,'connection-actions');
      if(state.stage==='new-wallet')actions.append(button('Back',()=>connected(),true));
      actions.append(button('Cancel',()=>flow.cancel(),true));dialog.append(actions);
    }
    if(state.action==='signin')dialog.append(node('p','Continue only if you started this sign-in in this browser.','connection-note signin-presence'));
    if(hadFocus)dialog.querySelector('button')?.focus();
  }
  return {
    get active(){return Boolean(dialog);},
    async start(optionsInput={}) {
      if(dialog)return {status:'busy'};
      token=optionsInput.token||'';initial={...optionsInput,automatic:true};remember=Boolean(readSigninChoice());
      if(!walletSigninOriginAllowed(location.href)){
        render({stage:'error',action:initial.action||'signin',message:'Open this Home with HTTPS to sign in with a wallet.',retryable:false,allowPasskey:false});return {status:'failed'};
      }
      if(!initial.action||initial.action==='signin') {
        initial.action='signin';const methods=readSigninOptions();
        if(!methods.length){onPasskey?.();return;}
        const saved=readSigninChoice(),method=methods.find(m=>optionId(m)===saved);
        if(!initial.otherOptions&&(saved==='passkey'||method))return chooseSignin(method||null);
        options(methods);return;
      }
      const result=new Promise(resolve=>{resolveRequest=resolve;});
      watcher=setInterval(()=>{if(initial.isCurrent&&!initial.isCurrent())void flow.cancel();},500);
      if(initial.method){initial.delegateWalletConnect=Boolean(initial.selectWalletConnect);void flow.start(initial);}
      else {render({stage:'loading',action:initial.action});void connected();}
      return result;
    },
    cancel:()=>flow.cancel(),
  };
}

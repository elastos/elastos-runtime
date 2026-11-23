import {createWalletSigninFlow,connectorName,walletNetwork,shortWalletAddress,walletSigninOriginAllowed} from './wallet-signin-flow.mjs';
import {copyHomeWalletConnectionLink} from './home-clipboard-host.js?v=home-20260726a';
import {signinBrowserWallets} from './home-wallet-connector-host.js?v=home-wallpaper-20261030b';
import {selectSigninWallet} from './wallet-signin-signers.mjs';
import {readSigninChoice,saveSigninChoice,optionId,availableSigninOptions} from './wallet-signin-options.mjs';
import {connectionView,renderConnection} from './wallet-connection-view.mjs';
const titles={signin:'Sign in',add:'Add wallet',remove:'Remove wallet'};
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
      else {const done=resolveRequest;resolveRequest=null;close();onChanged();done?.({status:'complete'});}
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
    if(kind==='passkey'){const icon=node('span','⚿','signin-passkey-icon');icon.setAttribute('aria-hidden','true');el.append(icon);}else if(kind){const icon=node('img');icon.alt='';icon.src=`./connection-${kind}.png`;el.append(icon);}
    const copy=node('span');copy.append(node('span',label,'connection-option-label'));if(detail)copy.append(node('span',detail,'connection-note'));el.append(copy,node('span','›'));return el;
  }
  async function chooseSignin(method) {
    const id=method?.chooseConnector?method.connector:method?optionId(method):'passkey';saveSigninChoice(remember?id:'');
    if(!method){close();onPasskey?.();return;}
    initial={...initial,action:'signin',method:method.chooseConnector?null:method,chooseConnector:method.chooseConnector?method.connector:null,automatic:true};await restart();
  }
  async function restart() {const options=initial;await flow.start(options);if(options.chooseConnector)await flow.choose(options.chooseConnector);}
  function chooseConnected(method) {initial={...initial,action:'add',method,automatic:true,delegateWalletConnect:Boolean(initial.selectWalletConnect)};return flow.start(initial);}
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
      dialog.close();const opened=await initial.openConnector(kind==='wallet'?'wallet':`wallet-${kind}`),until=Date.now()+180000;
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
        if(state.action==='signin'&&initial.availability?.passkey!==false){const passkey=option('Passkey','','passkey',()=>chooseSignin(null));passkey.disabled=!window.PublicKeyCredential;list.append(passkey);}
        for(const method of state.methods||[])list.append(option(state.action==='signin'?(method.connector==='walletconnect'?'Phone wallet':connectorName(method.connector)):(method.displayName||connectorName(method.connector)),state.action==='signin'?(method.connector==='walletconnect'?initial.availability?.relayNotice||'':''):`${shortWalletAddress(method.address)} · ${walletNetwork(method)}`,method.connector==='metamask'&&method.providerId&&method.providerId!=='io.metamask'?'wallet':method.connector,()=>state.action==='signin'?chooseSignin(method):chooseConnected(method)));
        if(state.action!=='signin')list.append(option('New wallet','','wallet',()=>openConnector('wallet')));
        dialog.append(list);
        if(state.action==='signin') {
          const label=node('label',null,'signin-remember'),input=node('input');input.type='checkbox';input.checked=remember;input.onchange=()=>{remember=input.checked;if(!remember)saveSigninChoice('');};label.append(input,document.createTextNode('Remember my choice'));dialog.append(label);
        }
      }
      if(state.wallet&&state.stage!=='review')dialog.append(node('p',`${connectorName(state.wallet.connector)} · ${shortWalletAddress(state.wallet.address)} · ${walletNetwork(state.wallet)}`,'connection-note'));
      const statuses={loading:'Loading wallets…',connecting:'Open your wallet.',signing:'Sign the message in your wallet.',approval:'Confirm with your passkey.',passkey:state.action==='remove'?'Confirm with your passkey to remove this wallet and end its sign-in sessions.':'Confirm with your passkey.',completing:state.action==='signin'?'Checking sign-in…':'Saving change…'};
      if(state.message||statuses[state.stage]){const status=node('p',state.message||statuses[state.stage],'connection-note');status.setAttribute('role','status');dialog.append(status);}
      if(state.approvalNotice&&state.wallet?.connector==='walletconnect')dialog.append(node('p',state.approvalNotice,'connection-note'));
      if(state.signingMessage) {
        const details=node('details');details.append(node('summary','Details'),node('p',location.origin),node('pre',state.signingMessage));dialog.append(details);
      }
      if(state.stage==='approval')dialog.append(button('Use passkey',()=>flow.approve()));
      if(state.stage==='unknown')dialog.append(button('Check again',()=>flow.retry()));
      if(state.stage==='error'||state.stage==='list-error') {
        if(state.retryable!==false)dialog.append(button('Try again',()=>state.stage==='list-error'?connected():restart()));
        if(state.action==='signin'&&onPasskey&&state.allowPasskey!==false&&initial.availability?.passkey!==false)dialog.append(button('Use passkey',()=>chooseSignin(null),true));
      }
      const actions=node('div',null,'connection-actions');
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
        initial.action='signin';let providers=[];try{providers=signinBrowserWallets();}catch{}
        const methods=availableSigninOptions(initial.availability?.connectors,{providers,unisatAvailable:typeof window.unisat?.signMessage==='function',walletconnectAvailable:initial.availability?.walletconnect===true});
        if(!methods.length){onPasskey?.();return;}
        const saved=readSigninChoice(),method=methods.find(m=>(m.chooseConnector?m.connector:optionId(m))===saved);
        if(!initial.otherOptions&&(saved==='passkey'&&initial.availability?.passkey!==false||method))return chooseSignin(method||null);
        options(methods);return;
      }
      const result=new Promise(resolve=>{resolveRequest=resolve;});
      watcher=setInterval(()=>{if(initial.isCurrent&&!initial.isCurrent())void flow.cancel();},500);
      if(initial.method&&['add'].includes(initial.action)&&initial.loadConnected) {
        render({stage:'loading',action:initial.action});const request=epoch;
        try {
          const methods=await initial.loadConnected();if(request!==epoch)return result;
          const connectedMethod=methods.find(method=>optionId(method)===optionId(initial.method));
          if(connectedMethod){initial.method=connectedMethod;}
          else{render({stage:'list-error',action:initial.action,message:'Refresh the wallet list and choose a connected wallet.'});return result;}
        }catch{if(request===epoch)render({stage:'list-error',action:initial.action,message:'Home could not load your wallets.'});return result;}
      }
      if(initial.method){initial.delegateWalletConnect=Boolean(initial.selectWalletConnect);void flow.start(initial);}
      else {render({stage:'loading',action:initial.action});void connected();}
      return result;
    },
    cancel:()=>flow.cancel(),
  };
}

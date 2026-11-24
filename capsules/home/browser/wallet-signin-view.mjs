import {createWalletSigninFlow,connectorName,walletNetwork,shortWalletAddress,walletSigninOriginAllowed} from './wallet-signin-flow.mjs';
import {copyHomeWalletConnectionLink} from './home-clipboard-host.js?v=home-20260726a';
import {signinBrowserWallets} from './home-wallet-connector-host.js?v=home-wallpaper-20261030b';
import {selectSigninWallet} from './wallet-signin-signers.mjs';
import {readSigninChoice,saveSigninChoice,signinChoiceId,optionId,availableSigninOptions} from './wallet-signin-options.mjs';
import {walletSigninRequestTimeoutMs} from './wallet-signin-methods.mjs';
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
  let dialog,previousFocus,token='',initial={},resolveRequest,ticker,watcher,managementTimer,epoch=0,remember=false,currentState;
  const flow=createWalletSigninFlow({
    api:(path,body)=>{if(initial.isCurrent&&!initial.isCurrent()&&!path.endsWith('/cancel'))throw new Error('Home session changed');return walletSigninApi(path,body,token);},
    select:async(connector,options)=>{
      if(initial.action==='add'&&connector!=='walletconnect'&&initial.selectExtension)return initial.selectExtension(connector,options);
      if(connector!=='walletconnect'||!initial.selectWalletConnect)return selectSigninWallet(connector,options);
      dialog?.close();
      return initial.selectWalletConnect(options);
    },
    approve:(approval,options)=>approve(token,approval.operation,approval.request,options),render,
    onComplete:async(result,action)=>{
      if(action==='signin') {close();await onSignin(result);}
      else {const done=resolveRequest;resolveRequest=null;close();onChanged();done?.({status:'complete'});}
    },
  });
  function close() {
    epoch++;clearInterval(ticker);clearInterval(watcher);clearTimeout(managementTimer);dialog?.close();dialog?.remove();dialog=null;previousFocus?.focus();
    resolveRequest?.({status:'cancelled'});resolveRequest=null;
  }
  function button(text,action,quiet=false) {
    const el=node('button',text,quiet?'el-button el-button-quiet connection-quiet':'el-button el-button-primary');el.type='button';el.onclick=action;return el;
  }
  function option(label,detail,kind,action) {
    const el=button('',action);el.className='connection-option';
    if(kind==='passkey'){const icon=document.createElementNS('http://www.w3.org/2000/svg','svg');icon.setAttribute('viewBox','0 0 24 24');icon.setAttribute('class','signin-passkey-icon');icon.setAttribute('aria-hidden','true');icon.innerHTML='<circle cx="8" cy="8" r="5"/><path d="m11.5 11.5 8 8m-3-3 3-3m-6 0 3-3"/>';el.append(icon);}else if(kind){const icon=node('img');icon.alt='';icon.src=`./connection-${kind}.png`;el.append(icon);}
    const copy=node('span');copy.append(node('span',label,'connection-option-label'));if(detail)copy.append(node('span',detail,'connection-note'));el.append(copy,node('span','›'));return el;
  }
  async function chooseSignin(method,{saveChoice=true}={}) {
    const id=method?.chooseConnector?signinChoiceId(method):method?optionId(method):'passkey';if(saveChoice)saveSigninChoice(remember?id:'');
    if(!method){close();onPasskey?.();return;}
    if(!dialog?.querySelector('.connection-options-list'))options(initial.signinMethods||[method]);
    initial={...initial,waitingId:method.chooseConnector?signinChoiceId(method):optionId(method),waitingLabel:method.connector==='walletconnect'?'Phone wallet':method.displayName||connectorName(method.connector),action:'signin',method:method.chooseConnector?null:method,chooseConnector:method.chooseConnector?method.connector:null,providerId:method.providerId,automatic:true};await restart();
  }
  async function restart() {if(initial.action==='signin'&&!dialog?.querySelector('.connection-options-list'))options(initial.signinMethods);const config=initial;await flow.start(config);if(config.chooseConnector)await flow.choose(config.chooseConnector);}
  function chooseConnected(method) {initial={...initial,action:'add',method,automatic:true,delegateWalletConnect:Boolean(initial.selectWalletConnect)};return flow.start(initial);}
  function options(methods) {
    render({stage:'options',action:initial.action,methods});
  }
  async function connected() {
    const request=epoch;
    try{const methods=await initial.loadConnected();if(request===epoch&&dialog){if(initial.action==='add'&&!methods.length){render({stage:'connect',action:initial.action,methods});}else options(methods);}}
    catch{if(request===epoch&&dialog)render({stage:'list-error',action:initial.action,message:'Home could not load your wallets.'});}
  }
  async function openConnector(kind) {
    const request=epoch,known=new Set(currentState.methods?.map(optionId));
    try {
      dialog.close();const opened=await initial.openConnector(`wallet-${kind}`),until=Date.now()+180000;
      if(request!==epoch||!dialog)return;
      // Wallet owns connection completion. Read its saved accounts before returning.
      clearInterval(ticker);let loading=false;
      ticker=setInterval(async()=>{
        if(request!==epoch||!dialog)return;
        if(opened?.isOpen?.()===false||Date.now()>until){clearInterval(ticker);render({stage:'connect',action:initial.action,methods:currentState.methods||[]});return;}
        if(loading)return;
        if(initial.isCurrent&&!initial.isCurrent()){void flow.cancel();return;}
        loading=true;
        try{const methods=await initial.loadConnected();if(request===epoch&&dialog&&(methods.some(m=>m.connector===kind&&!known.has(optionId(m)))||opened?.isOpen?.()===false||Date.now()>until)){clearInterval(ticker);const added=methods.find(m=>m.connector===kind&&!known.has(optionId(m)));if(added){await chooseConnected(added);}else{dialog.showModal();render({stage:'connect',action:initial.action,methods});}}}
        catch{if(request===epoch&&dialog){clearInterval(ticker);render({stage:'list-error',action:initial.action,message:'Home could not load your wallets.'});}}finally{loading=false;}
      },1000);
    } catch {if(request===epoch&&dialog){dialog.showModal();render({stage:'list-error',action:initial.action,message:'Home could not open this wallet.'});}}
  }
  function render(state) {
    currentState=state;
    if(state.action==='signin'&&['choice','connecting','review','signing','completing'].includes(state.stage)&&dialog?.querySelector('.connection-options-list')){
      dialog.dataset.state=state.stage;
      for(const row of dialog.querySelectorAll('.connection-option')){row.disabled=true;const label=row.querySelector('.connection-option-label');if(label&&row.dataset.choice===initial.waitingId){label.dataset.waiting='true';label.textContent=`Waiting for ${initial.waitingLabel}…`;}}
      return;
    }
    if(state.stage==='closed'){close();return;}
    if(state.action==='add'&&['choice','connecting','review','signing','approval','passkey','completing','done'].includes(state.stage)&&!state.message){dialog?.close();return;}
    if(!dialog) {
      previousFocus=document.activeElement;dialog=node('dialog',null,'signin-dialog');
      dialog.setAttribute('aria-labelledby','wallet-signin-title');
      dialog.addEventListener('cancel',event=>{event.preventDefault();void flow.cancel();});
      document.body.append(dialog);dialog.showModal();
    }
    const hadFocus=dialog.contains(document.activeElement);
    if(!dialog.open)dialog.showModal();
    dialog.dataset.state=state.stage;dialog.replaceChildren();
    const body=node('div',null,'signin-body'),footer=node('footer',null,'signin-footer');dialog.append(body,footer);
    if(state.stage==='pairing') {
      // Reuse the connector QR with Home's sign-in context and fixed controls.
      const view=connectionView({window:'walletconnect',stage:'qr-shown',qrData:state.pairing.qr});
      const shared=renderConnection(document,view);
      const title=shared.querySelector('h2');title.id='wallet-signin-title';title.textContent=titles[state.action]||'Sign in';
      title.after(node('p',location.origin,'signin-destination'));
      const instructions=shared.querySelectorAll('.connection-dialog > p:not(.signin-destination)');
      instructions[0].textContent='Scan with your wallet, or paste the copied link into your wallet.';instructions[1].remove();
      footer.append(shared.querySelector('.connection-actions'));
      const qrDialog=shared.querySelector('.connection-dialog');qrDialog.removeAttribute('role');qrDialog.removeAttribute('aria-modal');qrDialog.removeAttribute('aria-label');
      footer.addEventListener('click',async event=>{
        const action=event.target.closest('[data-action]')?.dataset.action;
        if(action==='cancel')void flow.cancel();
        if(action==='copy-link') {
          const control=event.target.closest('button');control.disabled=true;
          try{await copyHomeWalletConnectionLink(state.pairing.uri);control.textContent='Link copied.';}
          catch{control.textContent='Try copying again';}finally{control.disabled=false;}
        }
      });
      body.append(shared);
    } else {
      const title=node('h2',titles[state.action]||'Sign in');title.id='wallet-signin-title';body.append(title);
      if(state.stage==='options') {
        const list=node('div',null,'connection-card connection-options-list');
        if(state.action==='signin'&&initial.availability?.passkey!==false){const passkey=option('Passkey','','passkey',()=>chooseSignin(null));passkey.disabled=!window.PublicKeyCredential;list.append(passkey);}
        const phoneNotice=initial.availability?.relayNotice?"Connects through a relay that can see this computer's internet address.":'';
        for(const method of state.methods||[]){const row=option(state.action==='signin'?(method.connector==='walletconnect'?'Phone wallet':method.displayName||connectorName(method.connector)):(method.displayName||connectorName(method.connector)),state.action==='signin'?(method.connector==='walletconnect'?phoneNotice:''):`${shortWalletAddress(method.address)} · ${walletNetwork(method)}`,method.connector==='metamask'&&method.providerId&&method.providerId!=='io.metamask'?'wallet':method.connector,()=>state.action==='signin'?chooseSignin(method):chooseConnected(method));row.dataset.choice=method.chooseConnector?signinChoiceId(method):optionId(method);list.append(row);}
        if(state.action!=='signin')list.append(option('Connect another wallet','','wallet',()=>render({stage:'connect',action:initial.action,methods:state.methods})));
        body.append(list);
        if(state.action==='signin') {
          const label=node('label',null,'signin-remember'),input=node('input');input.type='checkbox';input.checked=remember;input.onchange=()=>{remember=input.checked;if(!remember)saveSigninChoice('');};label.append(input,document.createTextNode('Remember my choice'));body.append(label);
        }
      }
      if(state.stage==='connect'){
        title.textContent='Connect wallet';
        body.append(node('p','Connect MetaMask, UniSat or a phone wallet.','connection-note'));
        const list=node('div',null,'connection-card connection-options-list');
        for(const [kind,label] of [['metamask','MetaMask'],['unisat','UniSat'],['walletconnect','Phone wallet']])list.append(option(label,'',kind,()=>openConnector(kind)));
        body.append(list);
      }
      if(state.wallet&&state.stage!=='review')body.append(node('p',`${connectorName(state.wallet.connector)} · ${shortWalletAddress(state.wallet.address)} · ${walletNetwork(state.wallet)}`,'connection-note'));
      const connector=state.wallet?.connector||state.connector;
      const walletName=connector==='walletconnect'?'your phone wallet':state.wallet?.displayName||state.method?.displayName||connectorName(connector);
      const statuses={choice:'Opening wallet…',loading:'Loading wallets…',connecting:`Continue in ${walletName}`,signing:`Continue in ${walletName}`,approval:'Confirm with your passkey.',passkey:state.action==='remove'?'Confirm with your passkey to remove this wallet and end its sign-in sessions.':'Confirm with your passkey.',completing:state.action==='signin'?'Checking sign-in…':'Saving change…'};
      if(state.message||statuses[state.stage]){const status=node('p',state.message||statuses[state.stage],'connection-note');status.setAttribute('role','status');body.append(status);}
      if(state.approvalNotice&&state.wallet?.connector==='walletconnect')body.append(node('p',state.approvalNotice,'connection-note'));
      const actions=node('div',null,'connection-actions');
      if(state.stage==='approval')actions.append(button('Use passkey',()=>flow.approve()));
      if(state.stage==='unknown')actions.append(button('Check again',()=>flow.retry()));
      if(state.stage==='error'||state.stage==='list-error') {
        if(state.retryable!==false)actions.append(button('Try again',()=>state.stage==='list-error'?connected():restart()));
        if(state.action==='signin'&&onPasskey&&state.allowPasskey!==false&&initial.availability?.passkey!==false)actions.append(button('Use passkey',()=>chooseSignin(null,{saveChoice:false}),true));
      }
      actions.append(button('Cancel',()=>flow.cancel(),true));footer.append(actions);
    }
    if(state.action==='signin')footer.append(node('p','Continue only if you started this sign-in in this browser.','connection-note signin-presence'));
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
        initial.signinMethods=methods;
        if(!methods.length){onPasskey?.();return;}
        const saved=readSigninChoice(),method=methods.find(m=>(m.chooseConnector?signinChoiceId(m):optionId(m))===saved);
        if(!initial.otherOptions&&(saved==='passkey'&&initial.availability?.passkey!==false||method))return chooseSignin(method||null);
        options(methods);return;
      }
      const result=new Promise(resolve=>{resolveRequest=resolve;});
      managementTimer=setTimeout(()=>void flow.cancel(),walletSigninRequestTimeoutMs-15000);
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

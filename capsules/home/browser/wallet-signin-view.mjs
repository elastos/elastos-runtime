import {renderWalletSigninManagement} from './wallet-signin-management.mjs';
import {createWalletSigninFlow,connectorName,walletNetwork,shortWalletAddress,walletSigninOriginAllowed} from './wallet-signin-flow.mjs';
import {copyHomeWalletConnectionLink} from './home-clipboard-host.js?v=home-20260726a';
import {signinBrowserWallets} from './home-wallet-connector-host.js?v=home-wallpaper-20261030b';
import {selectSigninWallet,currentConnectedSigninMethods} from './wallet-signin-signers.mjs';
import {readSigninChoice,saveSigninChoice,signinChoiceId,optionId,availableSigninOptions} from './wallet-signin-options.mjs';
import {walletSigninRequestTimeoutMs} from './wallet-signin-methods.mjs';
import {connectionView,renderConnection} from './wallet-connection-view.mjs';
const titles={signin:'Sign in',add:'Add wallet',remove:'Remove wallet'};
function node(tag,text,className) {const el=document.createElement(tag);if(text)el.textContent=text;if(className)el.className=className;return el;}
export async function walletSigninApi(path,body,token='',{signal}={}) {
  // Own the controller until the response body settles. WebKit can collect an
  // inline combined AbortSignal while fetch still depends on it.
  const controller=new AbortController(),abort=()=>controller.abort();
  const timer=setTimeout(abort,15000);
  signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
  try {
    const response=await fetch(path,{
      method:body===undefined?'GET':'POST',cache:'no-store',signal:controller.signal,
      headers:{'content-type':'application/json',...(token?{'x-elastos-home-token':token}:{})},
      ...(body===undefined?{}:{body:JSON.stringify(body)}),
    });
    if(!response.ok)throw Object.assign(new Error('Home refused the wallet request'),{status:response.status,retryAfter:Number(response.headers.get('retry-after'))});
    return await response.json();
  } finally {clearTimeout(timer);signal?.removeEventListener('abort',abort);}

}
export function createHomeWalletSignin({approve,onSignin,onPasskey,onChanged=()=>{}}) {
  let passkeyController,passkeyFinished=Promise.resolve();
  let dialog,previousFocus,token='',initial={},watcher,managementTimer,epoch=0,remember=false,currentState,management={kind:'idle'};
  const flow=createWalletSigninFlow({
    api:(path,body,options)=>{const finishingRead=path==='/api/auth/wallet-methods'&&body===undefined&&initial.sessionCurrent?.();if(initial.isCurrent&&!initial.isCurrent()&&!path.endsWith('/cancel')&&!finishingRead)throw new Error('Home session changed');return walletSigninApi(path,body,token,options);},
    select:async(connector,options)=>{
      let wallet;options={...options,method:initial.connectedMethod||options.method,opened:focus=>{initial.focusCurrent=focus;}};
      if(connector==='walletconnect'&&initial.delegateWalletConnect&&initial.selectWalletConnect){dialog?.close();wallet=await initial.selectWalletConnect(options);}
      else wallet=await selectSigninWallet(connector,options);
      if(initial.action==='add') {
        try {
          if(initial.connectedMethod&&optionId(initial.connectedMethod)!==optionId(wallet))throw Object.assign(new Error('Wallet account changed'),{code:'changed'});
          const methods=await initial.loadConnected();
          if(methods.some(m=>m.sign_in_enabled&&optionId(m)===optionId(wallet)))throw Object.assign(new Error('Wallet already signs in'),{code:'already-added'});
        }catch(error){wallet.close?.();throw error;}
      }
      initial.focusCurrent=wallet.focus||initial.focusCurrent;return wallet;
    },
    approve:(approval,options)=>approve(token,approval.operation,approval.request,options),render,
    onComplete:async(result,action)=>{
      if(action==='signin') {close();await onSignin(result);}
      else {const done=management.resolve;if(management.kind==='active')management.resolve=null;close();onChanged();done?.({status:'complete'});}
    },
  });
  function close() {
    passkeyController?.abort();passkeyController=null;
    const pending=management;management={kind:'idle'};
    epoch++;clearInterval(watcher);clearTimeout(managementTimer);dialog?.close();dialog?.remove();dialog=null;previousFocus?.focus();
    pending.resolve?.({status:'cancelled'});
  }
  function button(text,action,quiet=false) {
    const el=node('button',text,quiet?'el-button el-button-quiet connection-quiet':'el-button el-button-primary');el.type='button';el.onclick=action;return el;
  }
  function option(label,detail,kind,action) {
    const el=button('',action);el.className='connection-option';
    if(kind==='passkey'){const icon=document.createElementNS('http://www.w3.org/2000/svg','svg');icon.setAttribute('viewBox','0 0 24 24');icon.setAttribute('class','signin-passkey-icon');icon.setAttribute('aria-hidden','true');icon.innerHTML='<circle cx="8" cy="8" r="5"/><path d="m11.5 11.5 8 8m-3-3 3-3m-6 0 3-3"/>';el.append(icon);}else if(kind){const icon=node('img');icon.alt='';icon.src=`./connection-${kind}.png`;el.append(icon);}
    const copy=node('span');copy.append(node('span',label,'connection-option-label'));if(detail)copy.append(node('span',detail,'connection-note'));el.append(copy,node('span','›'));return el;
  }
  async function chooseSignin(method) {
    const id=method?.chooseConnector?signinChoiceId(method):method?optionId(method):'passkey';saveSigninChoice(remember?id:'');
    passkeyController?.abort();passkeyController=null;
    if(!method){
      void flow.cancel();options(initial.signinMethods);
      const request=++epoch,controller=passkeyController=new AbortController(),previous=passkeyFinished;let failure;
      initial.waitingId='passkey';initial.waitingLabel='Passkey';
      render({stage:'passkey-signin',action:'signin'});
      passkeyFinished=(async()=>{await previous;if(!controller.signal.aborted)await onPasskey?.({signal:controller.signal});})()
        .catch(error=>{failure=error;})
        .finally(()=>{if(request===epoch&&dialog){passkeyController=null;options(initial.signinMethods,failure?.message||'');}});
      return passkeyFinished;
    }
    options(initial.signinMethods||[method]);
    initial={...initial,waitingId:method.chooseConnector?signinChoiceId(method):optionId(method),waitingLabel:method.connector==='walletconnect'?'WalletConnect':method.displayName||connectorName(method.connector),action:'signin',method:method.chooseConnector?null:method,chooseConnector:method.chooseConnector?method.connector:null,providerId:method.providerId,automatic:true};await restart();
  }
  async function restart() {if(initial.action==='signin'&&!dialog?.querySelector('.connection-options-list'))options(initial.signinMethods);const request=++epoch,config=initial;await flow.start(config);if(request===epoch&&config.chooseConnector)await flow.choose(config.chooseConnector);}
  function signinOptions(body,methods) {
    const list=node('div',null,'connection-card connection-options-list');
    if(initial.action==='signin'&&initial.availability?.passkey!==false){const passkey=option('Passkey','','passkey',()=>chooseSignin(null));passkey.dataset.choice='passkey';passkey.disabled=!window.PublicKeyCredential;list.append(passkey);}
    const phoneNotice=initial.availability?.relayNotice?"Connects through a relay that can see this computer's internet address.":'';
    for(const method of methods||[]){const row=option(initial.action==='signin'?(method.connector==='walletconnect'?'WalletConnect':method.displayName||connectorName(method.connector)):(method.displayName||connectorName(method.connector)),initial.action==='signin'?(method.connector==='walletconnect'?phoneNotice:''):`${shortWalletAddress(method.address)} · ${walletNetwork(method)}`,method.connector==='metamask'&&method.providerId&&method.providerId!=='io.metamask'?'wallet':method.connector,()=>chooseSignin(method));row.dataset.choice=method.chooseConnector?signinChoiceId(method):optionId(method);list.append(row);}

    body.append(list);
    if(initial.action==='signin') {
      const label=node('label',null,'signin-remember'),input=node('input');input.type='checkbox';input.checked=remember;input.onchange=()=>{remember=input.checked;if(!remember)saveSigninChoice('');};label.append(input,document.createTextNode('Remember my choice'));body.append(label);
    }
  }
  function cancel() {
    if(initial.action==='add'&&['completing','unknown'].includes(currentState?.stage))return;
    if(passkeyController){epoch++;passkeyController.abort();passkeyController=null;options(initial.signinMethods);return;}
    if(initial.action==='signin'&&currentState?.stage==='options'){close();return;}
    epoch++;void flow.cancel();
  }
  function options(methods,message='') {render({stage:'options',action:initial.action,methods,message});}
  async function chooseAdd(choice) {
    const [kind,providerId='']=choice.split(':');
    const request=++epoch;
    initial={...initial,method:null,connectedMethod:null,chooseConnector:kind,providerId,focusCurrent:null};
    render({stage:'loading',action:'add'});
    try {
      let methods=await currentConnectedSigninMethods(await initial.loadConnected());if(request!==epoch)return;
      let method=methods.find(m=>m.connector===kind&&(!providerId||m.providerId===providerId)&&!m.sign_in_enabled)||methods.find(m=>m.connector===kind&&(!providerId||m.providerId===providerId));
      if(method?.sign_in_enabled){await connected();return;}
      initial.focusCurrent=null;
      initial={...initial,method:null,connectedMethod:method,chooseConnector:kind,providerId:providerId||method?.providerId||'',delegateWalletConnect:Boolean(method&&kind==='walletconnect')};
      await restart();
    }catch{if(request===epoch)render({stage:'list-error',action:'add',message:'Home could not load your wallets.'});}
  }
  async function connected() {
    const request=epoch,stage=currentState?.stage;
    try{const methods=await currentConnectedSigninMethods(await initial.loadConnected());if(request===epoch&&currentState?.stage===stage)render({stage:'options',action:'add',methods});}
    catch{if(request===epoch&&currentState?.stage===stage)render({stage:'list-error',action:'add',message:'Home could not load your wallets.'});}
  }
  function chooserAction(action) {
    if(action==='cancel'){void flow.cancel();return;}
    if(action==='confirm'){void flow.confirm();return;}
    if(action==='approve'){void flow.approve();return;}
    if(action==='check'){void flow.retry();return;}
    if(action==='retry'){if(currentState?.stage==='error'&&!currentState.refresh&&initial.chooseConnector)void chooseAdd(initial.providerId?`${initial.chooseConnector}:${initial.providerId}`:initial.chooseConnector);else void connected();return;}
    if(action==='refresh'&&currentState?.stage==='options'){void connected();return;}
    if(currentState?.stage==='options')void chooseAdd(action);
  }
  function render(state) {
    if(state.action==='signin'&&['review','signing','completing'].includes(state.stage)&&(!dialog?.querySelector('.connection-options-list')||currentState?.stage==='pairing')&&initial.signinMethods)options(initial.signinMethods);
    if(state.stage==='closed'){if(initial.action==='signin'&&dialog&&initial.signinMethods){options(initial.signinMethods);return;}close();return;}
    currentState=state;if(management.kind==='active')management.stage=state.stage;
    if(state.action==='add'&&initial.delegateWalletConnect&&['connecting','signing'].includes(state.stage)&&!state.message) {
      if(dialog){dialog.dataset.state=state.stage;dialog.close();}
      initial.focusCurrent?.();return;
    }
    if(state.action==='signin'&&['choice','connecting','review','signing','completing','passkey-signin'].includes(state.stage)&&dialog?.querySelector('.connection-options-list')){
      dialog.dataset.state=state.stage;
      for(const row of dialog.querySelectorAll('.connection-option')){row.disabled=row.dataset.choice===initial.waitingId||row.dataset.choice==='passkey'&&!window.PublicKeyCredential;const label=row.querySelector('.connection-option-label');if(label&&row.dataset.choice===initial.waitingId){label.dataset.waiting='true';label.textContent=`Waiting for ${initial.waitingLabel}…`;}}
      return;
    }
    if(!dialog) {
      previousFocus=document.activeElement;dialog=node('dialog',null,'signin-dialog');
      dialog.setAttribute('aria-labelledby','wallet-signin-title');
      dialog.addEventListener('cancel',event=>{event.preventDefault();cancel();});
      document.body.append(dialog);dialog.showModal();
    }
    const hadFocus=dialog.contains(document.activeElement);
    if(!dialog.open)dialog.showModal();
    dialog.dataset.state=state.stage;dialog.dataset.purpose=state.action;dialog.replaceChildren();
    const body=node('div',null,'signin-body'),footer=node('footer',null,'signin-footer');dialog.append(body,footer);
    if(state.action==='add'&&state.stage!=='pairing') {
      dialog.classList.add('one-dialog');
      const choices=[...(signinBrowserWallets().length?signinBrowserWallets().map(p=>({connector:'metamask',providerId:p.rdns,label:p.name})):[{connector:'metamask'}]),{connector:'unisat'},{connector:'walletconnect'}].map(choice=>{
        const rows=(state.methods||[]).filter(m=>m.connector===choice.connector&&(!choice.providerId||m.providerId===choice.providerId));return {...choice,used:rows.length>0&&rows.every(m=>m.sign_in_enabled)};
      });
      renderWalletSigninManagement(body,footer,state,{account:initial.account||'Your account',methods:choices,choose:chooseAdd,confirm:()=>flow.confirm(),approve:()=>flow.approve(),cancel,retry:()=>chooserAction(state.stage==='unknown'?'check':'retry')});
      if(hadFocus)dialog.querySelector('button')?.focus();
      return;
    }
    if(state.stage==='pairing') {
      // Reuse the connector QR with Home's sign-in context and fixed controls.
      const view=connectionView({window:'walletconnect',stage:'qr-shown',qrData:state.pairing.qr});
      const shared=renderConnection(document,view);
      const title=shared.querySelector('h2'),mark=title.querySelector('img');title.id='wallet-signin-title';title.textContent=titles[state.action]||'Sign in';if(mark)title.prepend(mark);
      const destination=node('p',location.origin,'signin-destination');title.after(destination);
      const instructions=shared.querySelectorAll('.connection-dialog > p:not(.signin-destination)');
      instructions[0].textContent='Scan with your wallet, or paste the copied link into your wallet.';instructions[1].remove();
      footer.append(shared.querySelector('.connection-actions'));
      const qrDialog=shared.querySelector('.connection-dialog');qrDialog.removeAttribute('role');qrDialog.removeAttribute('aria-modal');qrDialog.removeAttribute('aria-label');
      footer.addEventListener('click',async event=>{
        const action=event.target.closest('[data-action]')?.dataset.action;
        if(action==='cancel'||action==='close-window')cancel();
        if(action==='copy-link') {
          const control=event.target.closest('button');control.disabled=true;
          try{await copyHomeWalletConnectionLink(state.pairing.uri);control.textContent='Copied';}
          catch{control.textContent='Try copying again';}finally{control.disabled=false;}
        }
      });
      if(state.action==='signin'){body.append(title,destination);signinOptions(body,initial.signinMethods);for(const row of body.querySelectorAll('.connection-option'))if(row.dataset.choice===initial.waitingId){row.disabled=true;row.querySelector('.connection-option-label').textContent=`Waiting for ${initial.waitingLabel}…`;}}
      body.append(node('p',"Connects through a relay that can see this computer's internet address.",'connection-note'),shared);
    } else {
      const title=node('h2',titles[state.action]||'Sign in');title.id='wallet-signin-title';body.append(title);
      if(state.stage==='options') {
        signinOptions(body,state.methods);
      }
      if(state.wallet&&state.stage!=='review')body.append(node('p',`${connectorName(state.wallet.connector)} · ${shortWalletAddress(state.wallet.address)} · ${walletNetwork(state.wallet)}`,'connection-note'));
      const connector=state.wallet?.connector||state.connector;
      const walletName=state.wallet?.displayName||state.method?.displayName||connectorName(connector);
      const statuses={choice:'Opening wallet…',loading:'Loading wallets…',connecting:`Continue in ${walletName}`,signing:`Continue in ${walletName}`,approval:'Confirm with your passkey.',passkey:state.action==='remove'?'Confirm with your passkey to remove this wallet and end its sign-in sessions.':'Confirm with your passkey.',completing:state.action==='signin'?'Checking sign-in…':'Saving change…'};
      if(state.message||statuses[state.stage]){const status=node('p',state.message||statuses[state.stage],'connection-note');status.setAttribute('role','status');body.append(status);}
      if(state.approvalNotice&&state.wallet?.connector==='walletconnect')body.append(node('p',state.approvalNotice,'connection-note'));
      const actions=node('div',null,'connection-actions');
      if(state.stage==='approval')actions.append(button('Use passkey',()=>flow.approve()));
      if(state.stage==='unknown')actions.append(button('Check again',()=>flow.retry()));
      if(state.stage==='error'||state.stage==='list-error'||state.stage==='unknown') {
        if(state.stage!=='unknown'&&state.retryable!==false)actions.append(button('Try again',()=>state.stage==='list-error'?connected():restart()));
        if(state.action==='signin'&&onPasskey&&state.allowPasskey!==false&&initial.availability?.passkey!==false)actions.append(button('Use passkey',()=>chooseSignin(null),true));
      }
      if(!['completing','unknown'].includes(state.stage)||state.action==='signin')actions.append(button('Cancel',cancel,true));footer.append(actions);
    }
    if(state.action==='signin')footer.append(node('p','Continue only if you started this sign-in in this browser.','connection-note signin-presence'));
    if(hadFocus)dialog.querySelector('button')?.focus();
  }
  return {
    get active(){return Boolean(dialog||management.kind==='active');},
    async start(optionsInput={}) {
      if(management.kind==='active' && ((optionsInput.action||'signin')!==management.action || (optionsInput.method?.method_id||'')!==management.methodId))return {status:'busy'};
      if(management.kind==='active'){if(management.stage==='unknown'){render(currentState);void flow.retry();}else if(['connecting','review','signing','passkey','completing'].includes(management.stage)&&initial.focusCurrent)initial.focusCurrent();else {dialog?.showModal();dialog?.querySelector('button')?.focus();}return management.result;}
      if(dialog){dialog.showModal();return {status:'cancelled'};}
      token=optionsInput.token||'';initial={...optionsInput,automatic:optionsInput.action!=='add'};remember=Boolean(readSigninChoice());
      if(!walletSigninOriginAllowed(location.href)){
        render({stage:'error',action:initial.action||'signin',message:'Open this Home with HTTPS to sign in with a wallet.',retryable:false,allowPasskey:false});return {status:'failed'};
      }
      if(!initial.action||initial.action==='signin') {
        initial.action='signin';let providers=[];try{providers=signinBrowserWallets();}catch{}
        const methods=availableSigninOptions(initial.availability?.connectors,{providers,unisatAvailable:typeof window.unisat?.signMessage==='function',walletconnectAvailable:initial.availability?.walletconnect===true});
        initial.signinMethods=methods;
        if(!methods.length)return chooseSignin(null);
        const saved=readSigninChoice(),method=methods.find(m=>(m.chooseConnector?signinChoiceId(m):optionId(m))===saved);
        options(methods);
        if(saved==='passkey'&&initial.availability?.passkey!==false||method)return chooseSignin(method||null);
        return;
      }
      let resolve;const result=new Promise(done=>{resolve=done;});management={kind:'active',action:initial.action,methodId:initial.method?.method_id||'',stage:'options',result,resolve};
      managementTimer=setTimeout(()=>void flow.cancel(),walletSigninRequestTimeoutMs-15000);
      watcher=setInterval(()=>{if(initial.sessionCurrent&&!initial.sessionCurrent()){void flow.sessionEnded().then(done=>{if(!done)void flow.cancel();});}else if(initial.isCurrent&&!initial.isCurrent())void flow.cancel();},500);
      if(initial.action==='add') {
        void connected();
      }else if(initial.method){void flow.start(initial);}
      return result;
    },
    cancel:()=>{const retiring=flow.cancel();if(initial.action==='signin')close();return retiring;},
  };
}

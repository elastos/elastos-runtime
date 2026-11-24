import {createWalletSigninFlow,connectorName,walletNetwork,shortWalletAddress,walletSigninOriginAllowed} from './wallet-signin-flow.mjs';
import {copyHomeWalletConnectionLink} from './home-clipboard-host.js?v=home-20260726a';
import {signinBrowserWallets} from './home-wallet-connector-host.js?v=home-wallpaper-20261030b';
import {selectSigninWallet,currentConnectedSigninMethods} from './wallet-signin-signers.mjs';
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
  let dialog,previousFocus,token='',initial={},watcher,managementTimer,epoch=0,remember=false,currentState,chooser,management={kind:'idle'};
  const flow=createWalletSigninFlow({
    api:(path,body)=>{const finishingRead=path==='/api/auth/wallet-methods'&&body===undefined&&initial.sessionCurrent?.();if(initial.isCurrent&&!initial.isCurrent()&&!path.endsWith('/cancel')&&!finishingRead)throw new Error('Home session changed');return walletSigninApi(path,body,token);},
    select:async(connector,options)=>{
      let wallet;options={...options,method:initial.connectedMethod||options.method,opened:focus=>{initial.focusCurrent=focus;}};
      if(connector==='walletconnect'&&initial.selectWalletConnect){dialog?.close();wallet=await initial.selectWalletConnect(options);}
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
    const pending=management;management={kind:'idle'};chooser?.close();chooser=null;
    epoch++;clearInterval(watcher);clearTimeout(managementTimer);dialog?.close();dialog?.remove();dialog=null;previousFocus?.focus();
    pending.resolve?.({status:'cancelled',...(initial.restarting?{refocus:false}:{})});
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
  function options(methods) {render({stage:'options',action:initial.action,methods});}
  async function chooseAdd(kind) {
    const request=++epoch;
    initial={...initial,method:null,connectedMethod:null,chooseConnector:kind,focusCurrent:null};
    render({stage:'loading',action:'add'});
    try {
      let methods=await currentConnectedSigninMethods(await initial.loadConnected());if(request!==epoch)return;
      let method=methods.find(m=>m.connector===kind&&!m.sign_in_enabled)||methods.find(m=>m.connector===kind);
      if(method?.sign_in_enabled){await connected();return;}
      initial.chooseConnector=kind;
      if(!method) {
        render({stage:'connecting',action:'add'});
        const opened=await initial.openConnector(`wallet-${kind}`);initial.focusCurrent=opened.focus;
        while(request===epoch&&!method&&opened.isOpen()) {
          await new Promise(resolve=>setTimeout(resolve,500));
          methods=await currentConnectedSigninMethods(await initial.loadConnected());if(request!==epoch)return;
          method=methods.find(m=>m.connector===kind);
        }
        if(request!==epoch)return;
        if(!method){await connected();chooser?.focus();return;}
        if(kind!=='walletconnect')opened.close?.();
      }
      initial.focusCurrent=null;chooser?.focus();
      render({stage:'loading',action:'add',methods});
      initial={...initial,method:null,connectedMethod:method,chooseConnector:kind,providerId:method?.providerId||'',delegateWalletConnect:true};
      await restart();
    }catch{if(request===epoch)render({stage:'list-error',action:'add',message:'Home could not load your wallets.'});}
  }
  async function connected() {
    const request=epoch,stage=currentState?.stage;
    try{const methods=await currentConnectedSigninMethods(await initial.loadConnected());if(request===epoch&&chooser&&currentState?.stage===stage)render({stage:'options',action:'add',methods});}
    catch{if(request===epoch&&currentState?.stage===stage)render({stage:'list-error',action:'add',message:'Home could not load your wallets.'});}
  }
  function chooserAction(action) {
    if(action==='cancel'){void flow.cancel();return;}
    if(action==='approve'){void flow.approve();return;}
    if(action==='check'){void flow.retry();return;}
    if(action==='retry'){if(currentState?.stage==='error'&&!currentState.refresh&&initial.chooseConnector)void chooseAdd(initial.chooseConnector);else void connected();return;}
    if(action==='refresh'&&currentState?.stage==='options'){void connected();return;}
    if(currentState?.stage==='options')void chooseAdd(action);
  }
  function render(state) {
    if(state.action==='signin'&&['review','signing','completing'].includes(state.stage)&&!dialog?.querySelector('.connection-options-list')&&initial.signinMethods)options(initial.signinMethods);
    if(state.stage==='closed'){close();return;}
    currentState=state;if(management.kind==='active')management.stage=state.stage;
    if(state.action==='add'&&chooser){if(state.message||['error','list-error','unknown'].includes(state.stage))chooser.focus();chooser.render({stage:state.stage,message:state.message||'',methods:Array.isArray(state.methods)?['metamask','unisat','walletconnect'].map(connector=>{const rows=state.methods.filter(m=>m.connector===connector);return {connector,connected:rows.length>0,used:rows.length>0&&rows.every(m=>m.sign_in_enabled)};}):undefined});return;}
    if(state.action==='signin'&&['choice','connecting','review','signing','completing'].includes(state.stage)&&dialog?.querySelector('.connection-options-list')){
      dialog.dataset.state=state.stage;
      for(const row of dialog.querySelectorAll('.connection-option')){row.disabled=true;const label=row.querySelector('.connection-option-label');if(label&&row.dataset.choice===initial.waitingId){label.dataset.waiting='true';label.textContent=`Waiting for ${initial.waitingLabel}…`;}}
      return;
    }
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
          try{await copyHomeWalletConnectionLink(state.pairing.uri);control.textContent='Copied';}
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
        for(const method of state.methods||[]){const row=option(state.action==='signin'?(method.connector==='walletconnect'?'Phone wallet':method.displayName||connectorName(method.connector)):(method.displayName||connectorName(method.connector)),state.action==='signin'?(method.connector==='walletconnect'?phoneNotice:''):`${shortWalletAddress(method.address)} · ${walletNetwork(method)}`,method.connector==='metamask'&&method.providerId&&method.providerId!=='io.metamask'?'wallet':method.connector,()=>chooseSignin(method));row.dataset.choice=method.chooseConnector?signinChoiceId(method):optionId(method);list.append(row);}

        body.append(list);
        if(state.action==='signin') {
          const label=node('label',null,'signin-remember'),input=node('input');input.type='checkbox';input.checked=remember;input.onchange=()=>{remember=input.checked;if(!remember)saveSigninChoice('');};label.append(input,document.createTextNode('Remember my choice'));body.append(label);
        }
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
      if(!['completing','unknown'].includes(state.stage)||state.action==='signin')actions.append(button('Cancel',()=>flow.cancel(),true));footer.append(actions);
    }
    if(state.action==='signin')footer.append(node('p','Continue only if you started this sign-in in this browser.','connection-note signin-presence'));
    if(hadFocus)dialog.querySelector('button')?.focus();
  }
  return {
    get active(){return Boolean(dialog||management.kind==='active');},
    async start(optionsInput={}) {
      if(management.kind==='active' && ((optionsInput.action||'signin')!==management.action || (optionsInput.method?.method_id||'')!==management.methodId))return {status:'busy'};
      if(management.kind==='active'&&chooser&&!chooser.isOpen()&&management.stage!=='unknown'){initial.restarting=true;await flow.cancel();}
      if(management.kind==='active'){if(management.stage==='unknown'){if(!chooser?.isOpen()){chooser?.close();chooser=await initial.openChooser(chooserAction);}render(currentState);chooser?.focus();void flow.retry();}else if(['connecting','review','signing','passkey','completing'].includes(management.stage)&&initial.focusCurrent)initial.focusCurrent();else chooser?.focus();return management.result;}
      if(dialog){dialog.showModal();return {status:'cancelled'};}
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
      let resolve;const result=new Promise(done=>{resolve=done;});management={kind:'active',action:initial.action,methodId:initial.method?.method_id||'',stage:'options',result,resolve};
      const request=epoch;
      managementTimer=setTimeout(()=>void flow.cancel(),walletSigninRequestTimeoutMs-15000);
      watcher=setInterval(()=>{if(initial.sessionCurrent&&!initial.sessionCurrent()){void flow.sessionEnded().then(done=>{if(!done)void flow.cancel();});}else if(initial.isCurrent&&!initial.isCurrent())void flow.cancel();},500);
      if(initial.action==='add') {
        try{const opened=await initial.openChooser(chooserAction);if(request!==epoch){opened.close();return result;}chooser=opened;void connected();}
        catch{const done=management.resolve;if(management.kind==='active')management.resolve=null;close();done?.({status:'failed'});}
      }else if(initial.method){void flow.start(initial);}
      return result;
    },
    cancel:()=>flow.cancel(),
  };
}

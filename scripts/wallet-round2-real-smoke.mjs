// Real extension prompts against an isolated, scripted Runtime boundary.
// This never dispatches a payment. It signs harmless test messages only.
import assert from 'node:assert/strict';
import {cp,readFile,mkdir,writeFile,chmod} from 'node:fs/promises';
import {join,basename} from 'node:path';
import {fixture} from './lib/wallet-extension-window-fixture.mjs';
import {temporaryDirectory} from './lib/wallet-connection-test-temp.mjs';
import {requireProductSmokePlaywright,productSmokeLaunchOptions} from './product-smoke-browser.mjs';

process.env.PW_TEST_SCREENSHOT_NO_FONTS_READY='1';
const pictures=process.env.WALLET_ROUND2_PICTURES,source=process.env.WALLET_TEST_PROFILE;
const extensions=process.env.WALLET_TEST_EXTENSIONS,passwordFile=process.env.WALLET_TEST_PASSWORD_FILE;
assert(pictures&&source&&extensions&&passwordFile,'supply isolated test profile, extension, password-file and picture paths');
let password=(await readFile(passwordFile,'utf8')).trim();
const scratch=temporaryDirectory('wallet-round2-real-');await chmod(scratch.path,0o700);
await mkdir(pictures,{recursive:true});
const records=[];
async function shot(page,name,caption){
  try{await page.screenshot({path:join(pictures,name+'.png'),animations:'disabled',timeout:5000});}catch(error){if(page.isClosed())return false;throw error;}
  records.push({file:name+'.png',caption});
  await writeFile(join(pictures,'real-'+(process.env.WALLET_TEST_KINDS||'all')+'-index.json'),JSON.stringify(records,null,2));
  return true;
}
const extensionIds={metamask:'fahggfellgfmaipmbahaikhklihepmdg',unisat:'ojipfahngkjpkiggjokmcladcfhfefnp'};
const metamaskPopup=JSON.parse(await readFile(join(extensions,'metamask','manifest.json'),'utf8')).action.default_popup;
async function prompt(context,kind){
  const until=Date.now()+25000;
  while(Date.now()<until){
    const pages=context.pages().filter(p=>!p.isClosed()&&p.url().includes(extensionIds[kind]));
    const page=pages.findLast(p=>p.url().includes('notification'))||pages.findLast(p=>p.url().includes('popup'))||pages.findLast(p=>p.url().includes('home.html'));
    if(page)return page;
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  throw Error(kind+' did not open a test prompt');
}
async function answer(context,kind,name,{reject=false,close=false}={}){
  const end=Date.now()+30000;let openedPopup=false;
  while(Date.now()<end){
    const page=await prompt(context,kind);await page.bringToFront();
    const unlock=kind==='metamask'?page.getByRole('button',{name:'Unlock',exact:true}):page.getByText('Unlock',{exact:true});
    if(await unlock.isVisible().catch(()=>false)){await shot(page,name+'-unlock',kind+' asks to unlock the disposable test wallet.');await page.locator('input[type=password]').fill(password);await unlock.click();await page.locator('input[type=password]').waitFor({state:'hidden',timeout:5000}).catch(error=>{if(!page.isClosed())throw error;});await new Promise(resolve=>setTimeout(resolve,150));continue;}
    const connect=page.getByText('Connect',{exact:true});
    if(await connect.isVisible().catch(()=>false)){if(!await shot(page,name+'-connect',kind+' asks to share the disposable test address.'))continue;await connect.click().catch(error=>{if(!page.isClosed())throw error;});continue;}
    const accept=kind==='metamask'?page.getByRole('button',{name:'Confirm',exact:true}):page.getByText('Sign',{exact:true});
    const decline=kind==='metamask'?page.getByRole('button',{name:'Cancel',exact:true}):page.getByText('Reject',{exact:true});
    if(await accept.isVisible().catch(()=>false)){
      if(!await shot(page,name+'-prompt',kind+(reject?' refusal':' signature')+' in the real extension.'))continue;
      if(close){const toolbar=kind==='metamask'&&page.url().includes('popup');await page.close();return {toolbar};}
      await (reject?decline:accept).click().catch(error=>{if(!page.isClosed())throw error;});
      await accept.waitFor({state:'hidden',timeout:5000}).catch(error=>{if(!page.isClosed())throw error;});return;
    }
    if(kind==='metamask'&&!openedPopup&&page.url().includes('/home.html')&&Date.now()>end-28000){
      // Open the toolbar surface named by the installed extension's manifest.
      openedPopup=true;const popup=await context.newPage();await popup.goto('chrome-extension://'+extensionIds.metamask+'/'+metamaskPopup);continue;
    }
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  await shot(await prompt(context,kind),name+'-unhandled',kind+' prompt needs a test control update.');
  throw Error(kind+' test prompt has no signing control');
}
const results=[];
try{
  for(const kind of (process.env.WALLET_TEST_KINDS||'metamask,unisat').split(',')){
    const profile=join(scratch.path,kind);
    if(!(kind==='unisat'&&process.env.WALLET_TEST_FRESH_UNISAT))await cp(source,profile,{recursive:true,filter:path=>!['SingletonLock','SingletonSocket','SingletonCookie','Cache','Code Cache','GPUCache','Crashpad'].includes(basename(path))});
    const {chromium}=requireProductSmokePlaywright();
    const ext=['metamask','unisat'].map(name=>join(extensions,name)).join(',');
    const context=await chromium.launchPersistentContext(profile,{headless:false,...productSmokeLaunchOptions(),...(process.env.WALLET_TEST_CHROMIUM_BIN?{executablePath:process.env.WALLET_TEST_CHROMIUM_BIN}:{}),ignoreDefaultArgs:['--disable-extensions'],viewport:{width:480,height:560},args:['--disable-extensions-except='+ext,'--load-extension='+ext]});
    // The shared fixture closes its owned context, including the real extensions.
    let f;
    try{
      if(kind==='unisat'&&process.env.WALLET_TEST_FRESH_UNISAT){
        password='Fixture!'+crypto.randomUUID();
        const setup=await context.newPage();await setup.goto('chrome-extension://'+extensionIds.unisat+'/index.html#/welcome');
        await setup.getByText('Create new wallet',{exact:true}).click();
        let form;const deadline=Date.now()+10000;while(!form&&Date.now()<deadline){form=context.pages().find(p=>p.url().includes('/account/create-password'));if(!form)await new Promise(r=>setTimeout(r,50));}assert(form,'UniSat opened its password form');await form.locator('input').first().waitFor();
        await form.locator('input').nth(0).fill(password);await form.locator('input').nth(1).fill(password);
        await form.getByText('Continue',{exact:true}).click();
        // Fixture seed words stay inside the extension and are never read or captured.
        await form.getByText('I saved My Secret Recovery Phrase',{exact:true}).click();await form.getByText('Continue',{exact:true}).click();
        await form.getByText('Address Type',{exact:true}).waitFor();await form.getByText('Continue',{exact:true}).click();
        await form.getByText('Receive',{exact:true}).waitFor();
      }
      // Both unpacked extensions can open their startup tab asynchronously.
      // Let those owned tabs settle before a notification can be dismissed by it.
      await new Promise(resolve=>setTimeout(resolve,2000));
      for(const page of context.pages())await page.close();
      f=await fixture({newContext:async()=>context},kind,{realExtension:true,pictures:false});
      await f.top.evaluate(()=>{
        testState.rpc=[];const seen=new WeakSet();
        const watch=(provider,method)=>{const call=provider?.[method];if(typeof call!=='function')return;provider[method]=async function(...args){const name=method==='request'?args[0]?.method:method;testState.rpc.push({method:name,phase:'start'});try{const result=await call.apply(this,args);testState.rpc.push({method:name,phase:'done'});return result;}catch(error){testState.rpc.push({method:name,phase:'error',code:error?.code});throw error;}};};
        addEventListener('eip6963:announceProvider',event=>{if(seen.has(event.detail.provider))return;seen.add(event.detail.provider);watch(event.detail.provider,'request');});dispatchEvent(new Event('eip6963:requestProvider'));
        for(const method of ['requestAccounts','getAccounts','getNetwork','signMessage'])watch(window.unisat,method);
      });
      await shot(f.top,'real-'+kind+'-ready',kind+' is ready to connect to Wallet.');
      await f.action('connect').click();
      await shot(f.top,'real-'+kind+'-connecting',kind+' waits for the real extension.');
      await answer(context,kind,'real-'+kind+'-ownership');
      await f.state('linked');
      assert.equal(await f.top.evaluate(()=>testState.receipts.length),1);
      await shot(f.top,'real-'+kind+'-linked',kind+' account saved in Wallet for ordinary use.');
      const request=async id=>{
        await f.top.evaluate(({id,kind})=>{testState.requests=[{request_id:id,status:'pending',intent:kind==='metamask'?'browser_personal_sign':'bitcoin_bip322_proof',proof_type:kind==='metamask'?'siwe':'bip322_simple',capsule_id:'browser',reason:'Sign a harmless test message',requesting_origin:'https://shop.example.com',connector_id:'wallet-'+kind,address:testState.address,chain_namespace:testState.chainNamespace,expires_at:Math.floor(Date.now()/1000)+300}];},{id,kind});
        const url=new URL(f.frame.url());url.searchParams.set('fixture_case',id);await f.frame.goto(url.href);
        await f.frame.evaluate(()=>window.dispatchEvent(new Event('focus')));
        await f.frame.locator('[data-action=send-request]').waitFor();
      };
      await request('ordinary-signature');
      await shot(f.top,'real-'+kind+'-request',kind+' reviews an app signature request.');
      await f.action('send-request').click();await answer(context,kind,'real-'+kind+'-app-signature');
      await f.state('request-done');await shot(f.top,'real-'+kind+'-signed',kind+' completed the app signature.');
      await request('ordinary-refusal');await f.action('send-request').click();
      await answer(context,kind,'real-'+kind+'-refusal',{reject:true});
      await f.state('request-declined');await shot(f.top,'real-'+kind+'-declined',kind+' refusal is shown as a declined request.');
      await request('ordinary-cancel');await f.action('send-request').click();
      const waiting=await prompt(context,kind);await f.state('request-extension');
      await shot(f.top,'real-'+kind+'-waiting',kind+' waits for a signature with Stop waiting.');
      await f.action('stop-waiting').click();await f.state('request-cancelled');
      await shot(f.top,'real-'+kind+'-stopped',kind+' stopped waiting and keeps the uncertain request visible.');
      await answer(context,kind,'real-'+kind+'-cancel-prompt',{reject:true});
      await f.state('request-declined');
      await request('ordinary-close');await f.action('send-request').click();
      const {toolbar}=await answer(context,kind,'real-'+kind+'-before-close',{close:true});
      await f.top.waitForTimeout(150);
      if(toolbar&&await f.frame.locator('main').getAttribute('data-state')!=='request-declined'){await f.action('stop-waiting').click();await f.state('request-cancelled');const popup=await context.newPage();await popup.goto('chrome-extension://'+extensionIds.metamask+'/'+metamaskPopup);await answer(context,kind,'real-'+kind+'-closed-toolbar-refusal',{reject:true});}
      await f.state('request-declined');
      await shot(f.top,'real-'+kind+'-closed-prompt',kind+' closed extension prompt is shown as a declined request.');
      await request('ordinary-expiry');
      await f.top.evaluate(()=>testState.requests[0].expires_at=Math.floor(Date.now()/1000)-1);await f.frame.evaluate(()=>window.dispatchEvent(new Event('focus')));await f.state('request-expired');
      await shot(f.top,'real-'+kind+'-expired',kind+' expired request keeps a clear exit.');
      results.push({kind,result:'PASS',remaining:'Installed Runtime and Home acceptance stays with the release walk.',extensionDiagnostics:f.extensionDiagnostics,boundary:'Real extension, scripted Runtime receipts, harmless messages; no payment broadcast'});
      console.log(kind+': ordinary connect, signature, refusal recovery, stop, prompt close and expiry walked; refusals are classified');
    }catch(error){console.error((kind+': '+error.stack).replaceAll(password,'[test secret]'));console.error(JSON.stringify({pages:context.pages().map(p=>{const u=new URL(p.url());return u.protocol+'//'+u.host+u.pathname;}),stage:await f?.frame.locator('main').getAttribute('data-state').catch(()=>null),rpc:await f?.top.evaluate(()=>testState.rpc?.slice(-32)).catch(()=>null)}));throw error;}finally{if(f)await f.close();else await context.close();}
  }
}finally{
  await writeFile(join(pictures,'real-results.json'),JSON.stringify(results,null,2));
  scratch.cleanup();
}

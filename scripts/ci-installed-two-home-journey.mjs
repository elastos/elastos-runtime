import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {writeFileSync, readFileSync, renameSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
export function assertCommunityMessage(poll, id, text) {
  const message = poll.objects.find(row => row.message_id === id);
  assert(message && message.body === text && !message.from_current_session, 'Community exact text from the other Home');
  return message;
}
export function assertReceivedDirect(messages, id, text) {
  const message = messages.find(row => row.message_id === id);
  assert(message && message.direction === 'incoming' && message.text === text && message.delivery_state === 'received', 'recipient exact direct message');
  return message;
}
export function assertSenderDelivery(message, detail) {
  assert(message?.direction === 'outgoing' && message.delivery_state === 'receipt_settled', 'sender receipt settled');
  const time = new Date(message.created_at * 1000).toISOString().slice(11, 16);
  assert.equal(detail, time, 'sender shows the message time, with neither Sending nor Expired');
}
async function run() {
  const require = createRequire(import.meta.url);
  const {chromium} = require(process.env.BROWSER_OPERATOR_PLAYWRIGHT_CORE || '../elastos/tools/browser-playwright-engine/node_modules/playwright');
  const [baseA, baseB, evidence, control] = process.argv.slice(2);
  const bases = [baseA, baseB];
  assert(bases.every(base => new URL(base).hostname === 'localhost'), 'installed journey uses localhost for passkeys');
  const result = {stage:'sign_in', results:{}, negative_controls:{}, observations:[], browser_cross_home_http_requests:0};
  let sequence = 0;
  async function runtime(action) {
    const id = ++sequence;
    writeFileSync(join(control, 'request.json.next'), JSON.stringify({id, action}), {flag:'wx', mode:0o600});
    renameSync(join(control, 'request.json.next'), join(control, 'request.json'));
    await until('owned Runtime action', async () => {
      let reply;
      try {reply = JSON.parse(readFileSync(join(control, 'response.json'), 'utf8'));}
      catch (error) {if (error.code !== 'ENOENT') throw error;}
      return reply?.id === id && reply.status === 'passed';
    }, 120000);
  }
  const sleep = ms => new Promise(resolve=>setTimeout(resolve,ms));
  async function until(label, fn, ms=150000) {
    const end=Date.now()+ms;
    while(Date.now()<end) {const value=await fn(); if(value) return value; await sleep(500);}
    throw new Error(label+' deadline');
  }
  let browser;
  try {
    result.stage='browser_launch';
    browser = await chromium.launch({headless:true});
    const homes=[];
    for(const [i,base] of bases.entries()) {
      const context=await browser.newContext({timezoneId:'UTC', serviceWorkers:'block', viewport:{width:1440,height:900}});
      await context.route('**/*', route => {
        const url = new URL(route.request().url());
        if (['http:', 'https:'].includes(url.protocol) && url.origin !== base) {
          result.browser_cross_home_http_requests++;
          return route.abort();
        }
        return route.continue();
      });
      const page=await context.newPage();
      const cdp=await context.newCDPSession(page);
      await cdp.send('WebAuthn.enable');
      await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
      result.stage='home_frontdoor_'+i;
      await page.goto(base+'/home/',{waitUntil:'domcontentloaded'});
      result.stage='home_name_'+i;
      await page.locator('#home-unlock-name').fill('Two Home '+(i?'B':'A'),{timeout:60000});
      result.stage='passkey_registration_'+i;
      const registered=page.waitForResponse(r=>r.url().endsWith('/api/auth/passkey/register/complete'));
      await page.locator('#home-unlock-primary').click();
      const registration = await registered;
      result.registration_http_status = registration.status();
      if (!registration.ok()) throw new Error('passkey registration HTTP '+registration.status()+' '+await registration.text());
      result.stage='home_ready_'+i;
      await page.waitForFunction(()=>document.body.dataset.homeStatus==='ready'&&document.body.dataset.homeAuthority==='signed',null,{timeout:60000});
      async function app(target,query={}) {
        const launch=await page.evaluate(async ({target,query})=>{
          const {fetchJson}=await import('/home/shell-core.js?v=home-wallpaper-20261030b');
          return fetchJson('/api/apps/home/launch',{method:'POST',body:JSON.stringify({target,query:{...query,home_origin:location.origin}})});
        },{target,query});
        const tab=await context.newPage();
        await tab.goto(new URL(launch.route,base).href,{waitUntil:'domcontentloaded'});
        return tab;
      }
      result.stage='people_launch_'+i;
      const people=await app('people');
      homes.push({context,page,people,app,base});
    }
    async function api(page,path,body) {
      return page.evaluate(async ({path,body})=>{
        const token=new URLSearchParams(location.hash.slice(1)).get('home_token');
        const r=await fetch(path,{method:body===undefined?'GET':'POST',headers:{'content-type':'application/json','x-elastos-home-token':token},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(30000)});
        if(!r.ok) throw new Error('product API '+path+' HTTP '+r.status);
        return r.json();
      },{path,body});
    }
    const [a,b]=homes;
    const communityA=await a.app('chat-room'), communityB=await b.app('chat-room');
    result.stage='community_post';
    await communityA.locator('#message-input:enabled').waitFor({timeout:90000});
    await api(communityB, '/api/apps/chat-room/session/start', {});
    const postText='Two Home Community '+crypto.randomUUID();
    const posted=await api(communityA, '/api/apps/chat-room/objects/send', {request_id:'two-home:'+crypto.randomUUID(),body:postText});
    let communityPoll;
    await until('Community exact text at B', async()=>{
      communityPoll=await api(communityB, '/api/apps/chat-room/poll', {since:0,mark_read:false});
      return communityPoll.objects.some(row=>row.message_id===posted.message_id && row.body===postText);
    });
    assertCommunityMessage(communityPoll, posted.message_id, postText);
    result.results.community_post='passed';
    result.community_text=postText;
    await communityB.screenshot({path:join(evidence,'community-b-desktop.png'),fullPage:true});
    const profile=await api(b.people,'/api/apps/people/summary');
    assert(profile.profile_id,'B profile available');
    result.stage='contact_request';
    const request=await api(a.people,'/api/apps/people/contacts/request',{profile_id:profile.profile_id});
    result.observations.push({step:'contact_request',status:request.status});
    const inbox=await b.app('inbox');
    function action(value) {
      if(!value||typeof value!=='object') return null;
      if(typeof value.action_id==='string'&&value.action_id.startsWith('contact-accept-request:')) return value.action_id;
      return Object.values(value).map(action).find(Boolean);
    }
    result.stage='contact_accept';
    const accept=await until('contact Inbox arrival',async()=>action(await api(inbox,'/api/apps/inbox/summary')));
    await api(inbox,'/api/apps/inbox/actions',{action_id:accept});
    result.observations.push({step:'contact_accept',status:'accepted'});
    const ac=await a.app('chat-room'), bc=await b.app('chat-room');
    result.stage='direct_conversation';
    const conversation=await until('A contact conversation',async()=> (await api(ac,'/api/apps/chat-room/direct/conversations')).conversations.find(c=>!c.removed));
    await until('B contact conversation',async()=> (await api(bc,'/api/apps/chat-room/direct/conversations')).conversations.find(c=>c.conversation_id===conversation.conversation_id));
    const text='Two Home direct '+crypto.randomUUID();
    result.stage='direct_send';
    const sent=await api(ac,'/api/apps/chat-room/direct/messages/send',{request_id:'two-home:'+crypto.randomUUID(),conversation_id:conversation.conversation_id,text});
    result.observations.push({step:'direct_send',status:sent.status,text});
    const path='/api/apps/chat-room/direct/conversations/'+encodeURIComponent(conversation.conversation_id)+'/messages';
    result.stage='direct_receive';
    let receivedMessages;
    const received=await until('B direct exact text',async()=> {
      receivedMessages=(await api(bc,path)).messages;
      return receivedMessages.find(m=>m.text===text&&m.direction==='incoming'&&m.delivery_state==='received');
    });
    assertReceivedDirect(receivedMessages, received.message_id, text);
    result.results.direct_received='passed';
    const senderMessage=async expected=> (await api(ac,path)).messages.find(m=>m.text===expected&&m.direction==='outgoing');
    const settled=await until('A settled receipt',async()=> {
      const message=await senderMessage(text);
      return message?.delivery_state==='receipt_settled' && message;
    });
    const direct=await a.app('chat-room',{conversation_id:conversation.conversation_id});
    async function detail(expected) {
      const row=direct.locator('#message-list li.message.self-message').filter({has:direct.locator('.message-body').filter({hasText:expected})});
      await row.waitFor({state:'visible',timeout:60000});
      assert.equal(await row.locator('.message-body').innerText(),expected);
      return row.locator('.message-meta > span').last().innerText();
    }
    const senderDetail=await until('A delivered time',async()=>{
      const value=await detail(text);
      return /^\d{2}:\d{2}$/.test(value)&&value;
    });
    assertSenderDelivery(settled,senderDetail);
    result.results.sender_delivered='passed';
    result.direct={text,recipient_state:received.delivery_state,sender_state:settled.delivery_state,sender_detail:senderDetail};
    result.stage='offline_pending';
    // Close B's projections before stopping its owned Runtime; retain only its passkey context.
    for(const page of b.context.pages()) if(page!==b.page) await page.close();
    await runtime('stop_b');
    const offlineText='Two Home recovery '+crypto.randomUUID();
    const pendingSend=await api(ac,'/api/apps/chat-room/direct/messages/send',{request_id:'two-home:'+crypto.randomUUID(),conversation_id:conversation.conversation_id,text:offlineText});
    assert.equal(pendingSend.status,'pending');
    let pending;
    await until('A Sending line',async()=>{
      pending=await senderMessage(offlineText);
      return pending?.delivery_state==='pending' && await detail(offlineText)==='Sending';
    });
    for(let sample=0;sample<3;sample++) {
      pending=await senderMessage(offlineText);
      const value=await detail(offlineText);
      assert.equal(pending.delivery_state,'pending');
      assert.equal(value,'Sending');
      assert.throws(()=>assertSenderDelivery(pending,value),{name:'AssertionError'});
      await sleep(500);
    }
    result.negative_controls.sender_delivered={assertion_rejected:true,broken_input:'B stopped before send',api_state:'pending',ui_detail:'Sending',samples:3};
    result.results.offline_pending='passed';
    result.stage='restart_delivery';
    await runtime('start_b');
    await b.page.reload({waitUntil:'domcontentloaded'});
    await b.page.waitForFunction(()=>document.body.dataset.homeStatus==='ready'||document.querySelector('#home-unlock')?.hidden===false,null,{timeout:60000});
    if(await b.page.locator('#home-unlock-primary').isVisible()) await b.page.locator('#home-unlock-primary').click();
    await b.page.waitForFunction(()=>document.body.dataset.homeStatus==='ready'&&document.body.dataset.homeAuthority==='signed',null,{timeout:60000});
    const restarted=await b.app('chat-room',{conversation_id:conversation.conversation_id});
    const recovered=await until('B receives after restart',async()=> (await api(restarted,path)).messages.find(m=>m.text===offlineText&&m.direction==='incoming'&&m.delivery_state==='received'));
    const settledAfterRestart=await until('A receipt settles after restart',async()=>{
      const message=await senderMessage(offlineText);
      return message?.delivery_state==='receipt_settled' && message;
    });
    const recoveredDetail=await until('A time replaces Sending',async()=> {
      const value=await detail(offlineText);
      return /^\d{2}:\d{2}$/.test(value) && value;
    });
    assertReceivedDirect([recovered],recovered.message_id,offlineText);
    assertSenderDelivery(settledAfterRestart,recoveredDetail);
    result.recovery={text:offlineText,recipient_state:recovered.delivery_state,sender_state:settledAfterRestart.delivery_state,sender_detail:recoveredDetail};
    result.results.restart_delivery='passed';
    await direct.screenshot({path:join(evidence,'direct-a-desktop.png'),fullPage:true});
    await direct.setViewportSize({width:390,height:844});
    await direct.screenshot({path:join(evidence,'direct-a-phone.png'),fullPage:true});
    assert.equal(result.browser_cross_home_http_requests,0,'browser calls only its own Home; peer delivery belongs to Carrier');
    result.status='passed';
  } catch(error) {
    result.status='failed';
    result.failure=['AssertionError','TimeoutError'].includes(error.name)?error.name:'journey_failed';
    writeFileSync(join(control,'error.private.txt'),String(error.stack),{mode:0o600});
    process.exitCode=1;
  } finally {
    if(browser) await browser.close();
    writeFileSync(join(evidence,'two-home-ui.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});
    console.log(JSON.stringify({stage:result.stage,status:result.status}));
  }

}
if (process.argv[1] === fileURLToPath(import.meta.url)) await run();

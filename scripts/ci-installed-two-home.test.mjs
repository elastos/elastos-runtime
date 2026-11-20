import assert from 'node:assert/strict';
import test from 'node:test';
import {assertCommunityMessage, assertReceivedDirect, assertSenderDelivery, assertMessageOrigins, registrationRefusal, browserOptions} from './ci-installed-two-home-journey.mjs';

test('Each namespace browser keeps Playwright control on its pipe and reaches its own loopback', () => {
  const chromium = {executablePath:()=> '/fixture/chromium'};
  const a = browserOptions(chromium,'namespace-a','fixture', {PATH:'/fixture/bin'});
  const b = browserOptions(chromium,'namespace-b','fixture', {PATH:'/fixture/bin'});
  assert(a.executablePath.endsWith('/ci-two-home-browser.sh'));
  assert.equal(a.env.ELASTOS_BROWSER_NAMESPACE,'namespace-a');
  assert.equal(b.env.ELASTOS_BROWSER_NAMESPACE,'namespace-b');
  assert.equal(a.env.ELASTOS_BROWSER_EXECUTABLE,'/fixture/chromium');
  assert.deepEqual(browserOptions(chromium,null,'fixture'),{headless:true,args:['--two-home-fixture=fixture']});
});

test('Registration refusal retains a plain-text reason within the receipt bound', async () => {
  const response = {url:()=> 'http://localhost/api/auth/passkey/register/begin', ok:()=>false,
    request:()=>({method:()=> 'POST'}), status:()=>403, text:async()=> 'local owner required'};
  assert.deepEqual(await registrationRefusal(response,0), {home:0,method:'POST',
    path:'/api/auth/passkey/register/begin',status:403,reason:'local owner required'});
  assert.equal((await registrationRefusal({...response,text:async()=> 'x'.repeat(1000)},1)).reason.length,512);
  assert.equal(await registrationRefusal({...response,ok:()=>true},0),undefined);
  assert.equal(await registrationRefusal({...response,url:()=> 'http://localhost/api/other'},0),undefined);
});

test('Community proof rejects wrong text, wrong identity and the receiving Home own post', () => {
  const message = {message_id:'post:one', body:'fresh post', from_current_session:false};
  assertCommunityMessage({objects:[message]}, 'post:one', 'fresh post');
  for (const broken of [{body:'other text'}, {message_id:'post:two'}, {from_current_session:true}]) {
    assert.throws(() => assertCommunityMessage({objects:[{...message,...broken}]}, 'post:one', 'fresh post'), assert.AssertionError);
  }
});

test('Direct receive proof requires the exact incoming message and received state', () => {
  const message = {message_id:'dm:one', text:'fresh direct', direction:'incoming', delivery_state:'received'};
  assertReceivedDirect([message], 'dm:one', 'fresh direct');
  for (const broken of [{text:'other text'}, {message_id:'dm:two'}, {direction:'outgoing'}, {delivery_state:'pending'}]) {
    assert.throws(() => assertReceivedDirect([{...message,...broken}], 'dm:one', 'fresh direct'), assert.AssertionError);
  }
});

test('Sender delivered requires both the settled API state and the exact message time', () => {
  const message = {direction:'outgoing', delivery_state:'receipt_settled', created_at:42};
  assertSenderDelivery(message, '00:00');
  for (const detail of ['Sending', 'Expired', '', 'Delivered', '01:00']) {
    assert.throws(() => assertSenderDelivery(message, detail), assert.AssertionError);
  }
  for (const state of ['pending','expired','received']) {
    assert.throws(() => assertSenderDelivery({...message,delivery_state:state}, '00:00'), assert.AssertionError);
  }
});

test('Home origins use the arrangement browser host and reject a mismatch', () => {
  assertMessageOrigins(['http://localhost/','http://localhost/'], 'localhost');
  assertMessageOrigins(['http://127.0.0.1/','http://127.0.0.1/'], '127.0.0.1');
  assert.throws(()=>assertMessageOrigins(['http://localhost/','http://127.0.0.1/'], 'localhost'), assert.AssertionError);
  assert.throws(()=>assertMessageOrigins(['http://localhost/'], undefined), assert.AssertionError);
});

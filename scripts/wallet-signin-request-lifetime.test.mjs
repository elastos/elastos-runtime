import test from 'node:test';
import assert from 'node:assert/strict';
import {requestWalletSigninChange,walletSigninRequestTimeoutMs} from '../capsules/home/browser/wallet-signin-methods.mjs';

test('the Accounts wait deadline reports an unknown outcome instead of a failed change',async t=>{
  t.mock.timers.enable({apis:['setTimeout']});
  const previous=globalThis.window,listen=new EventTarget();let request;
  globalThis.window=listen;listen.top={postMessage:message=>{request=message;}};
  t.after(()=>{globalThis.window=previous;});
  const waiting=requestWalletSigninChange({action:'add',token:'fixture',origin:'https://home.example'});
  t.mock.timers.tick(walletSigninRequestTimeoutMs);
  assert.deepEqual(await waiting,{status:'unknown'});assert.equal(request.action,'add');
});

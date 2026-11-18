import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {walletConnectRelayFixture,walletConnectFixtureRequire as require} from './lib/walletconnect-relay-fixture.mjs';
const {WebSocket}=require('ws');

test('the test relay preserves empty optional attestation on delivery and queued redelivery',async t=>{
 const server=http.createServer(),{relay}=walletConnectRelayFixture(server);await new Promise(r=>server.listen(0,'127.0.0.1',r));const sockets=[];
 t.after(async()=>{for(const s of sockets)s.terminate();await new Promise(r=>relay.close(r));server.closeAllConnections();await new Promise(r=>server.close(r));});
 const open=async()=>{const s=new WebSocket(`ws://127.0.0.1:${server.address().port}`);sockets.push(s);await new Promise(r=>s.once('open',r));return s;};
 const sender=await open(),receiver=await open();let id=1;
 const send=(s,method,params)=>s.send(JSON.stringify({jsonrpc:'2.0',id:id++,method,params}));
 const next=s=>new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('Relay fixture message timeout')),2000);s.once('message',raw=>{clearTimeout(timer);resolve(JSON.parse(String(raw)));});});
 let reply=next(receiver);send(receiver,'irn_subscribe',{topic:'fixture-topic'});await reply;
 reply=next(receiver);send(sender,'irn_publish',{topic:'fixture-topic',message:'encrypted-fixture-message',attestation:''});const delivered=(await reply).params.data;
 assert.equal(Object.hasOwn(delivered,'attestation'),true);assert.equal(delivered.attestation,'');
 const replay=await open();const messages=[];replay.on('message',raw=>messages.push(JSON.parse(String(raw))));send(replay,'irn_subscribe',{topic:'fixture-topic'});
 for(let i=0;i<100&&!messages.some(m=>m.method==='irn_subscription');i++)await new Promise(r=>setTimeout(r,10));
 const cached=messages.find(m=>m.method==='irn_subscription')?.params.data;assert.ok(cached);assert.equal(Object.hasOwn(cached,'attestation'),true);assert.equal(cached.attestation,'');
});

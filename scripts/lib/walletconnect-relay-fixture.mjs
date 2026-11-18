import {createRequire} from 'node:module';
import {existsSync} from 'node:fs';
import {join} from 'node:path';
import {behaviourInputsDir} from '../product-smoke-browser.mjs';
const cached = join(behaviourInputsDir(),'walletconnect/package.json');
export const walletConnectFixtureRequire = createRequire(existsSync(cached) ? cached : new URL('../walletconnect/package.json',import.meta.url));
const {WebSocketServer} = walletConnectFixtureRequire('ws');

// Implements only the pinned SDK relay messages, within a disposable local test.
export function walletConnectRelayFixture(server) {
    const relay = new WebSocketServer({server});
    const subscriptions = new Map(),messages = new Map();let id=1;const methods=[];
    const deliver = (socket,topic,entry) => socket.send(JSON.stringify({jsonrpc:'2.0',id:id++,method:'irn_subscription',params:{id:`fixture-${topic}`,data:{topic,...entry,publishedAt:Date.now()}}}));
    relay.on('connection',socket => socket.on('message',raw => {
      const rpc = JSON.parse(String(raw));
      if (rpc.token) {socket.send('{"ready":true}');return;}
      if (!rpc.method) return;methods.push(rpc.method);
      let result = true;
      if (rpc.method.endsWith('batchSubscribe') || rpc.method.endsWith('subscribe')) {
        const topics = rpc.params.topics || [rpc.params.topic];
        for (const topic of topics) {if(!subscriptions.has(topic))subscriptions.set(topic,new Set());subscriptions.get(topic).add(socket);}
        result = rpc.method.endsWith('batchSubscribe') ? topics.map(topic=>`fixture-${topic}`) : `fixture-${topics[0]}`;
        socket.send(JSON.stringify({jsonrpc:'2.0',id:rpc.id,result}));
        for(const topic of topics)for(const message of messages.get(topic)||[])deliver(socket,topic,message);
        return;
      }
      if (rpc.method === 'wc_proposeSession' || rpc.method === 'wc_approveSession') {
        const topic=rpc.method === 'wc_proposeSession' ? rpc.params.pairingTopic : rpc.params.sessionTopic;
        if(!subscriptions.has(topic))subscriptions.set(topic,new Set());subscriptions.get(topic).add(socket);
      }
      if (rpc.method === 'wc_approveSession') {
        for (const [topic,message] of [[rpc.params.pairingTopic,rpc.params.sessionProposalResponse],[rpc.params.sessionTopic,rpc.params.sessionSettlementRequest]]) {
          const entry={message,attestation:rpc.params.attestation};
          if(!messages.has(topic))messages.set(topic,[]);messages.get(topic).push(entry);
          for(const peer of subscriptions.get(topic)||[])if(peer!==socket&&peer.readyState===1)deliver(peer,topic,entry);
        }
      }
      if (rpc.method.endsWith('publish') || rpc.method === 'wc_proposeSession') {
        const topic = rpc.params.topic || rpc.params.pairingTopic;
        const message = rpc.params.message || rpc.params.sessionProposal;
        const entry={message,attestation:rpc.params.attestation};
        if(!messages.has(topic))messages.set(topic,[]);messages.get(topic).push(entry);
        for(const peer of subscriptions.get(topic)||[])if(peer!==socket&&peer.readyState===1)deliver(peer,topic,entry);
      }
      socket.send(JSON.stringify({jsonrpc:'2.0',id:rpc.id,result}));
    }));
  return {relay,methods};
}

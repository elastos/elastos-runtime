import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
export const titleSources=JSON.parse(readFileSync(new URL('../fixtures/wallet-connection-title-sources.json',import.meta.url)));
export const rustTitlePath='elastos/crates/elastos-server/src/api/gateway_inbox.rs';
export const walletTitlePath='capsules/wallet/browser/wallet-format.js';
export function rustRequestTitles(source){
 const body=source.match(/fn wallet_approval_title\(intent: &str\) -> String \{([\s\S]*?)\n\}/)?.[1];assert(body,'read the actual Rust title function');
 const pairs=[...body.matchAll(/("[a-z0-9_]+"|_)\s*=>\s*"([^"]+)"\.to_string\(\)/g)].map(m=>[m[1]==='_'?'unknown_kind':JSON.parse(m[1]),m[2]]);assert.equal(pairs.length,11,'all ten Runtime kinds and its fallback');return Object.fromEntries(pairs);
}
// The settled names are the contract. Historical blobs remain provenance only.
export const canonicalRequestTitles=Object.freeze({
 auth_challenge:'Review sign-in request',capability_grant:'Review access request',
 credential:'Sign a credential',publish_envelope:'Review publishing request',
 transaction_intent:'Send transaction',browser_account_access:'Share your wallet address with this site',
 browser_personal_sign:'Sign a message',browser_typed_data_sign:'Sign typed data',
 bitcoin_bip322_proof:'Confirm this Bitcoin account is yours',revocation:'Review request',unknown_kind:'Review request',
});
export const currentTitleSources=Object.fromEntries([rustTitlePath,walletTitlePath].map(path=>[path,{source:readFileSync(new URL('../../'+path,import.meta.url),'utf8')} ]));
export async function assertTitleSources(reduce,sources=currentTitleSources){
 const rust=rustRequestTitles(sources[rustTitlePath].source);
 // Import the complete Wallet module; compare exact producer values.
 const wallet=await import('data:text/javascript;base64,'+Buffer.from(sources[walletTitlePath].source).toString('base64'));
 assert.deepEqual(Object.keys(rust).sort(),Object.keys(canonicalRequestTitles).sort());
 for(const[intent,title]of Object.entries(canonicalRequestTitles)){
  assert.equal(wallet.requestTitle({intent}),rust[intent],'Wallet and Inbox source title: '+intent);
  assert.equal(rust[intent],title,'Inbox and settled title: '+intent);
  assert.equal(reduce(intent),title,'shared view title: '+intent);
 }
}
export function assertTitleSourceBlobs(){
 assert.equal(titleSources.commit.slice(0,9),'ac08f5942');
 for(const{source,blob}of Object.values(titleSources.files))assert.equal(createHash('sha1').update('blob '+Buffer.byteLength(source)+'\0').update(source).digest('hex'),blob,'unmodified source blob at the supplied pin');
}

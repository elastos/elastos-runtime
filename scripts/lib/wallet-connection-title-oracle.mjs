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
// Slice 0 settles the names. The pinned receipt remains historical evidence;
// Inbox is updated by its own lane and can still supply the previous labels.
const settledTitle = title => ({
 'Wallet sign-in request':'Review sign-in request', 'Wallet access request':'Review access request',
 'Credential signing request':'Sign a credential', 'Publish approval request':'Review publishing request',
 'Browser account access request':'Share your wallet address with this site',
 'Bitcoin proof request':'Confirm this Bitcoin account is yours',
 'Revocation approval request':'Review request', 'Wallet approval request':'Review request',
})[title] || title;
export const canonicalRequestTitles=Object.freeze(Object.fromEntries(Object.entries(rustRequestTitles(titleSources.files[rustTitlePath].source)).map(([intent,title])=>[intent,settledTitle(title)])));
export async function assertTitleSources(reduce,sources=titleSources.files){
 const rust=rustRequestTitles(sources[rustTitlePath].source);
 // Execute the complete pinned Wallet module, not an extracted function body.
 const wallet=await import('data:text/javascript;base64,'+Buffer.from(sources[walletTitlePath].source).toString('base64'));
 for(const[intent,title]of Object.entries(rust)){assert.equal(settledTitle(wallet.requestTitle({intent})),settledTitle(title),'Wallet and Inbox source title: '+intent);assert.equal(reduce(intent),settledTitle(title),'shared view title: '+intent);}
}
export function assertTitleSourceBlobs(){
 assert.equal(titleSources.commit.slice(0,9),'ac08f5942');
 for(const{source,blob}of Object.values(titleSources.files))assert.equal(createHash('sha1').update('blob '+Buffer.byteLength(source)+'\0').update(source).digest('hex'),blob,'unmodified source blob at the supplied pin');
}

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
export const canonicalRequestTitles=Object.freeze(rustRequestTitles(titleSources.files[rustTitlePath].source));
export async function assertTitleSources(reduce,sources=titleSources.files){
 const rust=rustRequestTitles(sources[rustTitlePath].source);
 // Execute the complete pinned Wallet module, not an extracted function body.
 const wallet=await import('data:text/javascript;base64,'+Buffer.from(sources[walletTitlePath].source).toString('base64'));
 for(const[intent,title]of Object.entries(rust)){assert.equal(wallet.requestTitle({intent}),title,'Wallet and Inbox source title: '+intent);assert.equal(reduce(intent),title,'shared view title: '+intent);}
}
export function assertTitleSourceBlobs(){
 assert.equal(titleSources.commit.slice(0,9),'ac08f5942');
 for(const{source,blob}of Object.values(titleSources.files))assert.equal(createHash('sha1').update('blob '+Buffer.byteLength(source)+'\0').update(source).digest('hex'),blob,'unmodified source blob at the supplied pin');
}

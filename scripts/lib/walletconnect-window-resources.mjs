import {existsSync} from 'node:fs';
import {windowFixture} from './walletconnect-phone-window-fixture.mjs';
import {scriptedPhoneWallet} from './walletconnect-phone-wallet.mjs';
import {requireProductSmokePlaywright,productSmokeLaunchOptions} from '../product-smoke-browser.mjs';

const engines=requireProductSmokePlaywright();
export function windowTestOptions(engine,timeout){
 return {timeout,skip:engine==='webkit'&&!existsSync(engines.webkit.executablePath())&&!process.env.ELASTOS_PLAYWRIGHT_MODULE?'WebKit is not installed on this machine':false};
}
export async function windowResources(t,engine,launch=()=>engines[engine].launch({headless:true,...(engine==='chromium'?productSmokeLaunchOptions():{})})){
 const cleanup=[];
 // Register before acquisition so a failed peer or engine launch also releases its predecessors.
 t.after(async()=>{
  const errors=[];
  for(const close of cleanup.reverse())try{await close();}catch(error){errors.push(error);}
  if(errors.length)throw new AggregateError(errors,'Wallet window cleanup failed');
 });
 const fixture=await windowFixture();cleanup.push(()=>fixture.stop());
 const peer=await scriptedPhoneWallet({projectId:'fixture-project',relayUrl:fixture.origin.replace('http','ws')});cleanup.push(()=>peer.stop());
 const browser=await launch();cleanup.push(()=>browser.close());
 return {fixture,peer,browser,defer:close=>cleanup.push(close)};
}

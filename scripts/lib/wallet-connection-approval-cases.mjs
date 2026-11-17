import {readFileSync} from 'node:fs';
import {states,shared,fixtureArguments} from '../wallet-connection-view-fixtures.mjs';
export const approvalCatalog=JSON.parse(readFileSync(new URL('../fixtures/wallet-connection-approval-stages.json',import.meta.url)));
export const reviewOrigin='https://accounts.example.com.secure-login-verify-session.signin-confirmation-required.wallet-authorization.account-recovery.attacker-domain.net';
// Explicit provisional boundary cases; the canonical shared fixture stays unchanged.
export function approvalArguments(row,{origin=reviewOrigin,compact=true,transaction,previousFocus}={}){
 const fixture=states.find(r=>r.window===row.window&&r.stage===row.stage),args=fixtureArguments(fixture,{compact,previousFocus});
 const seed=args[1].summary||shared.n7PrivateSummaries.find(r=>r.id==='site-wallet-metamask').summary;
 const summary={...seed,request_id:'r4-'+row.window+'-'+row.stage,capsule_id:'browser',requesting_app_name:'Browser',connector_id:'wallet-'+row.window,requesting_origin:origin,reason:'Sign in to the app.',status:'pending',intent:transaction===true||row.stage==='transaction-waiting'||row.stage==='request-network-declined'?'transaction_intent':row.stage==='request-typed-data'?'browser_typed_data_sign':'browser_personal_sign'};
 if(row.window==='walletconnect'){args[1].message=undefined;args[0].localSafety=false;}
 else if(!['network-changed','network-fractal','network-unknown'].includes(row.stage))args[1].message=shared.messages.find(r=>r.id===(row.window==='unisat'?'state-unisat':'state-io.metamask')).message;
 args[1].safetyMessage=shared.messages.find(r=>r.id==='state-payment-false').message;
 if(row.kind==='context'){args[1].summary=undefined;args[1].contextSummary=summary;}else args[1].summary=summary;
 args[0].stage=row.stage;return args;
}

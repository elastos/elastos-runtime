import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,globSync,mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,relative,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';

const root=fileURLToPath(new URL('../',import.meta.url));
const self=fileURLToPath(import.meta.url);
const reason='WebKit is not installed on this machine';

// Follow the suite's actual globs, imports and child-smoke paths. Reading a
// source file as test data does not put that source on the execution path.
function executionPaths(path,source,base){
 return [...source.matchAll(/(?:\bfrom\s*|\bimport\s*(?:\(\s*)?)["'](\.[^"']+\.mjs)["']|["'](scripts\/[^"']+-smoke\.mjs)["']/g)]
  .map(match=>match[1]?resolve(dirname(path),match[1]):resolve(base,match[2]))
  .filter(target=>existsSync(target));
}

function reachesPlaywright(path,base,seen=new Set()){
 if(seen.has(path))return false;seen.add(path);
 const source=readFileSync(path,'utf8');
 if(/\bfrom\s*["']playwright(?:-core)?["']/.test(source))return true;
 for(const match of source.matchAll(/\b(?:import|require|createRequire)\s*\(([^)]*)\)/g)){
  const argument=match[1].trim();
  // An expression-selected module may load Playwright through an environment
  // path or corePath. Literal node imports and fake engine objects cannot.
  if(!/^["'`]/.test(argument)||/^["']playwright(?:-core)?["']/.test(argument))return true;
 }
 return executionPaths(path,source,base).some(target=>reachesPlaywright(target,base,seen));
}

function webkitEntries(base=root,entrypoints){
 const suite=readFileSync(resolve(root,'scripts/test-behaviour.sh'),'utf8');
 const command=suite.split('\n').find(line=>line.startsWith('exec node scripts/run-node-tests.mjs '));
 assert.ok(command,'the behaviour suite exposes its entry points');
 const pending=entrypoints?entrypoints.map(path=>resolve(base,path)):command.trim().split(/\s+/).slice(3).flatMap(pattern=>globSync(pattern,{cwd:base})).map(path=>resolve(base,path));
 const seen=new Set(),entries=[];
 while(pending.length){
  const path=pending.pop();if(seen.has(path)||path===self)continue;seen.add(path);
  const source=readFileSync(path,'utf8');
  // This entry invokes the real smoke with a generated fake SDK that stops
  // at launch. Its child graph does not require an installed browser.
  if(path.endsWith('/home-phone-layout-launch.test.mjs'))continue;
  pending.push(...executionPaths(path,source,base));
  // This helper's regression deliberately injects an invalid executable to
  // prove cleanup after failed acquisition; it is not an optional engine run.
  if(path.endsWith('/walletconnect-window-resources.test.mjs'))continue;
  const selectsWebKit=/\[[^\]\n]*["']webkit["'][^\]\n]*\]|\bwebkit\.launch\s*\(|\b\w*ENGINE\w*\s*:\s*["']webkit["']/.test(source);
  if(/(?:\.test|-smoke)\.mjs$/.test(path)&&selectsWebKit&&reachesPlaywright(path,base))entries.push({path,source});
 }
 return entries.sort((a,b)=>a.path.localeCompare(b.path));
}

function checkMissingEngineRule(entries){
 for(const {path,source} of entries){
  assert.match(source,/import\s*\{[^}]*\bwindowTestOptions\b[^}]*\}\s*from\s*["'][^"']*walletconnect-window-resources\.mjs["']/,relative(root,path));
  assert.match(source,/\bwindowTestOptions\s*\(/,relative(root,path)+' applies the rule');
  assert.doesNotMatch(source,/existsSync\([^\n]*webkit/,relative(root,path)+' delegates availability');
 }
}

function probe(args,env){
 const result=spawnSync(process.execPath,args,{cwd:root,env,encoding:'utf8',timeout:120000,maxBuffer:8*1024*1024});
 assert.equal(result.error,undefined,'missing-engine probe completes');
 assert.equal(result.status,0,result.stdout+result.stderr);
 return result.stdout;
}

test('the phone launch mock SDK fixture needs no installed WebKit',t=>{
 const base=mkdtempSync(resolve(tmpdir(),'webkit-phone-launch-discovery-'));
 t.after(()=>rmSync(base,{recursive:true,force:true}));
 mkdirSync(resolve(base,'scripts'));
 writeFileSync(resolve(base,'scripts/home-phone-layout-launch.test.mjs'),readFileSync(resolve(root,'scripts/home-phone-layout-launch.test.mjs')));
 writeFileSync(resolve(base,'scripts/home-phone-layout-smoke.mjs'),"import {webkit} from 'playwright';await webkit.launch({});");
 assert.deepEqual(webkitEntries(base,['scripts/home-phone-layout-launch.test.mjs']),[]);
});

test('every behaviour-suite WebKit entry uses the shared missing-engine rule',{timeout:180000},()=>{
 const entries=webkitEntries();assert.ok(entries.length>0,'WebKit entries were discovered');
 checkMissingEngineRule(entries);
 const env={...process.env,PLAYWRIGHT_BROWSERS_PATH:'/missing-wallet-test-browsers'};
 delete env.ELASTOS_PLAYWRIGHT_MODULE;delete env.NODE_TEST_CONTEXT;
 const files=entries.filter(({path})=>path.endsWith('.test.mjs')).map(({path})=>path);
 // Import the real modules through node:test. All their WebKit callbacks must
 // remain skipped even on a developer machine that has WebKit installed.
 const output=probe(['--test','--test-concurrency=1','--test-reporter=tap','--test-name-pattern=webkit|WebKit',...files],env);
 const results=[...output.matchAll(/^ *ok .*?(?:webkit|WebKit).*$/gm)];
 const skips=[];
 assert.ok(results.length>0,'WebKit cases report their results');
 for(const result of results){
  const details=output.slice(result.index+result[0].length).split('...')[0];
  if(!result[0].includes('# SKIP')&&/type: '?suite'?/.test(details))continue;
  assert.ok(result[0].endsWith('# SKIP '+reason),result[0]);skips.push(result);
 }
 assert.ok(skips.length>0,'WebKit cases report their skip reason');
 for(const {path,source} of entries.filter(({path})=>path.endsWith('-smoke.mjs'))){
  const variable=source.match(/process\.env\.(\w*ENGINE\w*)/);
  assert.ok(variable,relative(root,path)+' exposes its engine selection');
  assert.match(probe([path],{...env,[variable[1]]:'webkit'}),new RegExp('# SKIP '+reason));
 }
 console.log('WebKit rule covers '+entries.map(({path})=>relative(root,path)).join(', '));
 console.log(`WebKit absence probe: ${skips.length} cases skipped with the standard reason`);
});

for(const [form,acquisition,selection] of [
 ['static import',`import {webkit} from 'playwright';const engines=withBrowserLaunchRecovery({webkit});`,'await engines.webkit.launch({});'],
 ['dynamic import',`const engines=withBrowserLaunchRecovery(await import('playwright'));`,'await engines.webkit.launch({});'],
 ['core path import',`const engines=withBrowserLaunchRecovery(await import(corePath));`,'await engines.webkit.launch({});'],
 ['environment require',`const engines=withBrowserLaunchRecovery(require(process.env.BROWSER_OPERATOR_PLAYWRIGHT_CORE));`,'await engines.webkit.launch({});'],
 ['one-line engine list',`import {engines} from './engines.mjs';`,`for(const name of ['chromium','firefox','webkit'])await engines[name].launch({});`],
 ['dynamic local helper',`const {engines}=await import('./engines.mjs');`,'await engines.webkit.launch({});'],
 ['child smoke',`import {spawnSync} from 'node:child_process';`,`spawnSync(process.execPath,['scripts/new-smoke.mjs'],{env:{BROWSER_ENGINE:'webkit'}});`],
])test(`discovery enforces the missing-engine rule for a ${form}`,t=>{
 const base=mkdtempSync(resolve(tmpdir(),'webkit-discovery-'));
 t.after(()=>rmSync(base,{recursive:true,force:true}));
 // These files are inspected, never imported: no fixture launches a browser.
 writeFileSync(resolve(base,'engines.mjs'),`import './cycle.mjs';import {webkit} from 'playwright-core';export const engines=withBrowserLaunchRecovery({webkit});`);
 writeFileSync(resolve(base,'cycle.mjs'),`export {engines} from './engines.mjs';`);
 if(form==='child smoke'){
  mkdirSync(resolve(base,'scripts'));
  writeFileSync(resolve(base,'scripts/new-smoke.mjs'),`import {engines} from '../engines.mjs';await engines[process.env.BROWSER_ENGINE].launch({});`);
 }
 const path=resolve(base,'new.test.mjs');
 writeFileSync(path,acquisition+'\n'+selection);
 const entries=webkitEntries(base,['new.test.mjs']);
 assert.deepEqual(entries.map(entry=>entry.path),[path]);
 assert.throws(()=>checkMissingEngineRule(entries),/new\.test\.mjs/);
 writeFileSync(path,`import {windowTestOptions} from './walletconnect-window-resources.mjs';\nwindowTestOptions('webkit',1000);\n`+acquisition+'\n'+selection);
 assert.doesNotThrow(()=>checkMissingEngineRule(webkitEntries(base,['new.test.mjs'])));
});

test('discovery distinguishes stand-in engines and source data from Playwright access',t=>{
 const base=mkdtempSync(resolve(tmpdir(),'webkit-discovery-'));
 t.after(()=>rmSync(base,{recursive:true,force:true}));
 writeFileSync(resolve(base,'fake.mjs'),`import {readFileSync} from 'node:fs';export const webkit={launch:async()=>({})};`);
 writeFileSync(resolve(base,'fake.test.mjs'),`import {webkit} from './fake.mjs';for(const name of ['chromium','firefox','webkit'])await webkit.launch({});`);
 writeFileSync(resolve(base,'data.test.mjs'),`import {readFileSync} from 'node:fs';readFileSync(new URL('./real-smoke.mjs',import.meta.url));for(const name of ['webkit']){};`);
 writeFileSync(resolve(base,'real-smoke.mjs'),`import {webkit} from 'playwright';await withBrowserLaunchRecovery({webkit}).webkit.launch({});`);
 assert.deepEqual(webkitEntries(base,['fake.test.mjs','data.test.mjs']),[]);
 assert.equal(reachesPlaywright(resolve(root,'scripts/lib/browser-launch-recovery.test.mjs'),root),false);
});

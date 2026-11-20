import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,globSync,readFileSync} from 'node:fs';
import {dirname,relative,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';

const root=fileURLToPath(new URL('../',import.meta.url));
const self=fileURLToPath(import.meta.url);
const reason='WebKit is not installed on this machine';

// Follow the suite's actual globs, imports and child-smoke paths. Reading a
// source file as test data does not put that source on the execution path.
function webkitEntries(){
 const suite=readFileSync(resolve(root,'scripts/test-behaviour.sh'),'utf8');
 const command=suite.split('\n').find(line=>line.startsWith('exec node scripts/run-node-tests.mjs '));
 assert.ok(command,'the behaviour suite exposes its entry points');
 const pending=command.trim().split(/\s+/).slice(3).flatMap(pattern=>globSync(pattern,{cwd:root})).map(path=>resolve(root,path));
 const seen=new Set(),entries=[];
 while(pending.length){
  const path=pending.pop();if(seen.has(path)||path===self)continue;seen.add(path);
  const source=readFileSync(path,'utf8');
  for(const match of source.matchAll(/(?:\bfrom\s*|\bimport\s*(?:\(\s*)?)["'](\.[^"']+\.mjs)["']|["'](scripts\/[^"']+-smoke\.mjs)["']/g)){
   const target=match[1]?resolve(dirname(path),match[1]):resolve(root,match[2]);
   if(existsSync(target))pending.push(target);
  }
  // This helper's regression deliberately injects an invalid executable to
  // prove cleanup after failed acquisition; it is not an optional engine run.
  if(path.endsWith('/walletconnect-window-resources.test.mjs'))continue;
  if(/(?:\.test|-smoke)\.mjs$/.test(path)&&/["']webkit["']/.test(source))entries.push({path,source});
 }
 return entries.sort((a,b)=>a.path.localeCompare(b.path));
}

function probe(args,env){
 const result=spawnSync(process.execPath,args,{cwd:root,env,encoding:'utf8',timeout:120000,maxBuffer:8*1024*1024});
 assert.equal(result.error,undefined,'missing-engine probe completes');
 assert.equal(result.status,0,result.stdout+result.stderr);
 return result.stdout;
}

test('every behaviour-suite WebKit entry uses the shared missing-engine rule',{timeout:180000},()=>{
 const entries=webkitEntries();assert.ok(entries.length>0,'WebKit entries were discovered');
 for(const {path,source} of entries){
  assert.match(source,/import\s*\{[^}]*\bwindowTestOptions\b[^}]*\}\s*from\s*["'][^"']*walletconnect-window-resources\.mjs["']/,relative(root,path));
  assert.match(source,/\bwindowTestOptions\s*\(/,relative(root,path)+' applies the rule');
  assert.doesNotMatch(source,/existsSync\([^\n]*webkit/,relative(root,path)+' delegates availability');
 }
 const env={...process.env,PLAYWRIGHT_BROWSERS_PATH:'/missing-wallet-test-browsers'};
 delete env.ELASTOS_PLAYWRIGHT_MODULE;delete env.NODE_TEST_CONTEXT;
 const files=entries.filter(({path})=>path.endsWith('.test.mjs')).map(({path})=>path);
 // Import the real modules through node:test. All their WebKit callbacks must
 // remain skipped even on a developer machine that has WebKit installed.
 const output=probe(['--test','--test-concurrency=1','--test-reporter=tap','--test-name-pattern=webkit|WebKit',...files],env);
 const skips=[...output.matchAll(/^\s*ok .*?(?:webkit|WebKit).*?# SKIP (.*)$/gm)];
 assert.ok(skips.length>0,'WebKit cases report their skip reason');
 for(const [,skip] of skips)assert.equal(skip,reason);
 for(const {path,source} of entries.filter(({path})=>path.endsWith('-smoke.mjs'))){
  const variable=source.match(/process\.env\.(\w*ENGINE\w*)/);
  assert.ok(variable,relative(root,path)+' exposes its engine selection');
  assert.match(probe([path],{...env,[variable[1]]:'webkit'}),new RegExp('# SKIP '+reason));
 }
 console.log('WebKit rule covers '+entries.map(({path})=>relative(root,path)).join(', '));
 console.log(`WebKit absence probe: ${skips.length} cases skipped with the standard reason`);
});

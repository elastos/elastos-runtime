import assert from 'node:assert/strict';
import {lstatSync,mkdtempSync,realpathSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join,parse} from 'node:path';

// Delete only the exact directory this test created, with unchanged parents.
export function temporaryDirectory(prefix){
 const path=mkdtempSync(join(realpathSync(tmpdir()),prefix));
 assert(!path.split('/').includes('Users'));
 const identity=[];
 for(let parent=path;;parent=dirname(parent)){
  const stat=lstatSync(parent);assert(stat.isDirectory()&&!stat.isSymbolicLink());
  identity.push({path:parent,dev:stat.dev,ino:stat.ino});if(parent===parse(parent).root)break;
 }
 let removed=false;
 const cleanup=()=>{
  if(removed)return;
  for(const entry of identity){const stat=lstatSync(entry.path);assert(stat.isDirectory()&&!stat.isSymbolicLink()&&stat.dev===entry.dev&&stat.ino===entry.ino,'temporary directory identity changed');}
  rmSync(path,{recursive:true,force:false});removed=true;process.removeListener('exit',cleanup);
 };
 process.once('exit',cleanup);return {path,cleanup};
}

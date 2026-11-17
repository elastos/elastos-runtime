import {readFile,writeFile} from 'node:fs/promises';
import {temporaryDirectory} from './wallet-connection-test-temp.mjs';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {screens} from '../../capsules/_shared/wallet-connection-screens.mjs';
// Import the entire real module with owned definitions; never mutate product exports.
export async function withTestView({editScreens=()=>{},mutateSource=s=>s}={},run){
 const temporary=temporaryDirectory('wallet-view-test-module-'),scratch=temporary.path;
 try{
  const definitions=structuredClone(screens);editScreens(definitions);
  const source=await readFile(new URL('../../capsules/_shared/wallet-connection-view.mjs',import.meta.url),'utf8');
  await writeFile(join(scratch,'wallet-connection-screens.mjs'),'export const screens = '+JSON.stringify(definitions)+';\n');
  await writeFile(join(scratch,'wallet-connection-view.mjs'),mutateSource(source));
  return await run(await import(pathToFileURL(join(scratch,'wallet-connection-view.mjs'))));
 }finally{temporary.cleanup();}
}

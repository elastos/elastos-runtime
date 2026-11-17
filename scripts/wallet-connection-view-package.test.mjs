import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import {temporaryDirectory} from './lib/wallet-connection-test-temp.mjs';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { walletViewAssets, validateWalletViewAssets } from './check-product-data.mjs';

test('real release staging and archives carry identical inactive view bytes in all three capsules', () => {
  validateWalletViewAssets(resolve('.'));
  const temporary=temporaryDirectory('wallet-view-package-'),scratch=temporary.path;
  const hashes={};
  try{
    for(const name of ['wallet-metamask','wallet-unisat','wallet-walletconnect']){
      // Source the real release functions, including all their helpers. No publisher runs.
      const result=spawnSync('bash',['-c','source scripts/publish-release.sh\nstage_wasm_capsule "$1" "capsules/$1" "$2/stage/$1"\ncreate_capsule_tar "$2/$1.tar.gz" "$2/stage" "$1"','wallet-view-package',name,scratch],{encoding:'utf8',timeout:30000});
      assert.equal(result.status,0,result.stderr);
      hashes[name]={};
      for(const asset of walletViewAssets){
        const member=`${name}/browser/${asset}`;
        const unpacked=spawnSync('tar',['-xOf',join(scratch,`${name}.tar.gz`),member],{timeout:10000,maxBuffer:2*1024*1024});
        assert.equal(unpacked.status,0,`${member}: archive member`);
        assert.deepEqual(unpacked.stdout,readFileSync(`capsules/_shared/${asset}`),member);
        hashes[name][asset]=createHash('sha256').update(unpacked.stdout).digest('hex');
      }
      const entry=readFileSync(`capsules/${name}/browser/index.html`,'utf8');
      const controller=readFileSync(`capsules/${name}/browser/${name}.js`,'utf8');
      assert(!entry.includes('wallet-connection-view')&&!controller.includes('wallet-connection-view'),'live window stays on its existing controller');
    }
    const receipt=process.env.WALLET_VIEW_PACKAGE_RECEIPT||join(scratch,'receipt.json');
    mkdirSync(dirname(receipt),{recursive:true});
    writeFileSync(receipt,JSON.stringify(hashes,null,2)+'\n');
  }finally{temporary.cleanup();}
});

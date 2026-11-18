import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import {temporaryDirectory} from './lib/wallet-connection-test-temp.mjs';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { walletViewAssets, validateWalletViewAssets } from './check-product-data.mjs';

test('real release staging and archives carry identical shared view bytes in all three capsules', () => {
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

    }
    const receipt=process.env.WALLET_VIEW_PACKAGE_RECEIPT||join(scratch,'receipt.json');
    mkdirSync(dirname(receipt),{recursive:true});
    writeFileSync(receipt,JSON.stringify(hashes,null,2)+'\n');
  }finally{temporary.cleanup();}
});


// The window owners refresh their generated copies at integration. This separate
// staging proof uses the exact canonical bytes and keeps the repository gate above strict.
test('canonical shared assets survive real staging and archives for each connector',()=>{
  const temporary=temporaryDirectory('wallet-view-canonical-package-'),scratch=temporary.path,hashes={};
  try{
    const fixture=join(scratch,'fixture');mkdirSync(join(fixture,'capsules/_shared'),{recursive:true});
    for(const asset of walletViewAssets)cpSync(`capsules/_shared/${asset}`,join(fixture,'capsules/_shared',asset));
    for(const name of ['wallet-metamask','wallet-unisat','wallet-walletconnect']){
      const dir=join(fixture,'capsules',name);mkdirSync(dir,{recursive:true});
      cpSync(`capsules/${name}/capsule.json`,join(dir,'capsule.json'));cpSync(`capsules/${name}/browser`,join(dir,'browser'),{recursive:true});
      for(const asset of walletViewAssets)cpSync(`capsules/_shared/${asset}`,join(dir,'browser',asset));
    }
    validateWalletViewAssets(fixture);
    for(const name of ['wallet-metamask','wallet-unisat','wallet-walletconnect']){
      const result=spawnSync('bash',['-c','source scripts/publish-release.sh\nstage_wasm_capsule "$1" "$2/capsules/$1" "$3/stage/$1"\ncreate_capsule_tar "$3/$1.tar.gz" "$3/stage" "$1"','wallet-view-canonical',name,fixture,scratch],{encoding:'utf8',timeout:30000});
      assert.equal(result.status,0,result.stderr);hashes[name]={};
      for(const asset of walletViewAssets){const member=`${name}/browser/${asset}`,unpacked=spawnSync('tar',['-xOf',join(scratch,`${name}.tar.gz`),member],{timeout:10000,maxBuffer:2*1024*1024});assert.equal(unpacked.status,0);assert.deepEqual(unpacked.stdout,readFileSync(`capsules/_shared/${asset}`));hashes[name][asset]=createHash('sha256').update(unpacked.stdout).digest('hex');}
    }
    const receipt=process.env.WALLET_VIEW_PACKAGE_RECEIPT&&process.env.WALLET_VIEW_PACKAGE_RECEIPT.replace(/\.json$/,'-canonical.json');if(receipt)writeFileSync(receipt,JSON.stringify(hashes,null,2)+'\n');
  }finally{temporary.cleanup();}
});

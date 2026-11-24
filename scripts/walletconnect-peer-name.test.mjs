import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createWalletConnectClient } from '../capsules/wallet-walletconnect/browser/walletconnect-client.mjs';

for (const addAccount of [false, true]) {
  for (const [kind, name, expectedName] of [
    ['reported', 'Scripted wallet', 'Scripted wallet'],
    ['long', 'x'.repeat(2000), 'x'.repeat(80)],
    ['missing', undefined, undefined],
    ['plain text', '<img src=x onerror=alert(1)>\u0000phone', '<img src=x onerror=alert(1)>phone'],
    ['whole Unicode characters', 'a'.repeat(79) + '😀tail', 'a'.repeat(79) + '😀'],
    ['isolated surrogate', '\ud800Phone', 'Phone'],
    ['wrong type', 42, undefined],
  ]) {
    test(`wallet peer name reaches verify (${addAccount ? 'Add account' : 'Connect'}, ${kind})`, async () => {
      const address = `0x${'12'.repeat(20)}`;
      const provider = Object.assign(new EventEmitter(), {
        chainId: 8453, accounts: [address], connected: true,
        session: { expiry: Math.floor(Date.now() / 1000) + 3600,
          peer: { metadata: { name } }, namespaces: { eip155: { accounts: [`eip155:8453:${address}`] } } },
        request: async ({ method }) => method === 'eth_accounts' ? [address] : method === 'eth_chainId' ? 8453 : `0x${'ab'.repeat(65)}`,
      });
      let verified;
      const api = async (path, input) => {
        if (path === 'internet') return { status: 'granted' };
        if (path === 'wallet/config') return { walletconnect: { project_id: 'fixture', storage_revision: '"0"' } };
        if (path === 'storage') return {};
        if (path === 'wallet/accounts') return { accounts: [] };
        if (path.endsWith('/challenge')) return { message: 'Ownership fixture', expires_at: Math.floor(Date.now() / 1000) + 300 };
        if (path.endsWith('/verify')) { verified = JSON.parse(input.body); return {}; }
        throw new Error(`Unexpected resource ${path}`);
      };
      const client = createWalletConnectClient({ api, origin: 'http://localhost', loadAdapter: async () => ({ connectWalletConnectEvm: async () => provider }) });
      assert.deepEqual(await client.effect({ kind: 'link', addAccount }), { status: 'linked' });
      assert.equal(verified.wallet_peer_name, expectedName);
      assert.equal(verified.message, 'Ownership fixture');
      assert.equal(verified.signature, `0x${'ab'.repeat(65)}`);
    });
  }
}

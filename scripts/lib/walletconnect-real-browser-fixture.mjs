// This fixture uses the production routes with this frame's own launch token.
import { installWalletConnectStorage } from './walletconnect-storage.mjs';
window.storageTrace = [];
installWalletConnectStorage(window, entry => window.storageTrace.push(entry));
window.runtimeTrace = [];
window.phase = 'options';
const options = await window.walletConnectTestOptions();
const origin = new URL(import.meta.url).origin;
const api = async (resource, input = {}) => {
  const response = await fetch(`${origin}/api/apps/wallet-walletconnect/${resource}`, {
    ...input, headers: { 'content-type':'application/json', 'x-elastos-home-token':options.connector },
  });
  window.runtimeTrace.push({ resource, status:response.status });
  if (!response.ok) {
    window.refusal = { resource, status:response.status };
    throw new Error('Runtime refused the connector resource');
  }
  return response.json();
};
try {
  window.phase = 'import';
  const { connectWalletConnectEvm } = await import('./vendor/reown-appkit.js');
  window.phase = 'connect';
  window.provider = await connectWalletConnectEvm({
    contextKey:'wallet-walletconnect', projectId:options.projectId, chains:[1], api,
    runtimeUrl:`${origin}/api/apps/wallet-walletconnect`,
    relayUrl:`${origin.replace(/^http/, 'ws')}/api/apps/wallet-walletconnect/relay`,
    metadata:{name:'Isolated recovery test', description:'Throwaway test wallet', url:origin, icons:[]},
  });
  window.phase = 'connected';
} catch {
  window.failed = true;
}

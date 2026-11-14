// Load the real adapter with deterministic SDK fixtures for lifecycle tests.
// The browser suite separately exercises the locked, bundled SDK itself.
export async function resolve(specifier, context, nextResolve) {
  if (context.parentURL?.includes("/scripts/walletconnect/adapter.mjs")) {
    const source = specifier === "@walletconnect/ethereum-provider"
      ? "export const EthereumProvider = { init: options => globalThis.walletConnectSdkFixture(options) };"
      : specifier === "qrcode" ? "export default { toCanvas: async () => {} };" : null;
    if (source) return { url: `data:text/javascript,${encodeURIComponent(source)}`, shortCircuit: true };
  }
  return nextResolve(specifier, context);
}

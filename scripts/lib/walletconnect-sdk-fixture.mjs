export async function connectWalletConnectEvm(options) {
  if (new URL(options.runtimeUrl).origin !== globalThis.location.origin) throw new Error("SDK RPC URLs require the Home origin");
  globalThis.__wcFixtureOptions = options;
  return globalThis.__wcFixtureProvider;
}

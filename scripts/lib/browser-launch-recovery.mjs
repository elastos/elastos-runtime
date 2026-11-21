import { webkitMacOSLaunchOptions } from "./webkit-macos-sandbox.mjs";

// Keep the build branch's launch-boundary API for its unchanged regression tests.
// Develop makes one attempt per launch; this boundary only prepares Mac WebKit.
const wrapped = new WeakMap();
export function withBrowserLaunchRecovery(playwright, { platform = process.platform, cacheRoot } = {}) {
  if (wrapped.has(playwright)) return wrapped.get(playwright);
  const types = new Map();
  const result = new Proxy(playwright, { get(target, key) {
    if (key !== "webkit") return Reflect.get(target, key);
    if (!types.has(key)) {
      const type = Reflect.get(target, key);
      if (!type) return type;
      types.set(key, new Proxy(type, { get(browserType, method) {
        if (method === "launch") return async options => browserType.launch(
          webkitMacOSLaunchOptions(browserType, options, { platform, cacheRoot }));
        if (method === "launchPersistentContext") return async (userDataDir, options) => browserType.launchPersistentContext(userDataDir,
          webkitMacOSLaunchOptions(browserType, options, { platform, cacheRoot }));
        const value = Reflect.get(browserType, method);
        return typeof value === "function" ? value.bind(browserType) : value;
      } }));
    }
    return types.get(key);
  } });
  wrapped.set(playwright, result);
  wrapped.set(result, result);
  return result;
}

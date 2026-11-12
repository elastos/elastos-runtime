// Resolve the capsule's served asset import while importing its whole real module.
export function resolve(specifier, context, next) {
  if (specifier.startsWith("/apps/home/home-clipboard-client.js?")) {
    return next(new URL("../../capsules/home/browser/home-clipboard-client.js", import.meta.url).href, context);
  }
  return next(specifier, context);
}

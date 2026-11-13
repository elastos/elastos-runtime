// Product smokes launch one browser.
// BRAVE_BIN, when set, is that executable.
// Otherwise the executable is full Playwright Chromium from the core pin
// that scripts/test-behaviour.sh inputs installs, when that file is on disk.
// The headless shell misses clicks in Home iframes, so it is not this binary.
// A missing file leaves the executable to the Playwright module.

import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export function behaviourInputsDir(env = process.env) {
  if (env.BEHAVIOUR_INPUTS) return env.BEHAVIOUR_INPUTS;
  const root = env.RUNNER_TEMP || join(env.HOME || homedir(), ".cache", "elastos-runtime");
  return join(root, "behaviour");
}

export function playwrightCoreDir(env = process.env) {
  if (env.BROWSER_OPERATOR_PLAYWRIGHT_CORE) return env.BROWSER_OPERATOR_PLAYWRIGHT_CORE;
  return join(behaviourInputsDir(env), "core", "node_modules", "playwright-core");
}

function specifierPath(spec) {
  return spec.startsWith("file:") ? fileURLToPath(spec) : spec;
}

function withChromium(loaded) {
  const module = loaded && loaded.chromium ? loaded : loaded?.default;
  if (!module?.chromium) throw new Error("Playwright module has no chromium export");
  return module;
}

function loadPlaywrightPackage(env) {
  if (env.ELASTOS_PLAYWRIGHT_MODULE) {
    const spec = specifierPath(env.ELASTOS_PLAYWRIGHT_MODULE);
    return createRequire(spec)(spec);
  }
  const behaviourDir = join(behaviourInputsDir(env), "browser", "node_modules", "playwright");
  if (existsSync(join(behaviourDir, "package.json"))) {
    return createRequire(join(behaviourDir, "package.json"))(behaviourDir);
  }
  return createRequire(new URL("../elastos/tools/browser-playwright-engine/package.json", import.meta.url))("playwright");
}

export function requireProductSmokePlaywright(env = process.env) {
  return withChromium(loadPlaywrightPackage(env));
}

export async function importProductSmokePlaywright(env = process.env) {
  if (env.ELASTOS_PLAYWRIGHT_MODULE) {
    const spec = env.ELASTOS_PLAYWRIGHT_MODULE;
    const href = spec.startsWith("file:") ? spec : pathToFileURL(spec).href;
    return withChromium(await import(href));
  }
  return requireProductSmokePlaywright(env);
}

function playwrightChromiumExecutable(env) {
  const core = playwrightCoreDir(env);
  const loaded = createRequire(join(core, "package.json"))(core);
  return withChromium(loaded).chromium.executablePath();
}

export function productSmokeLaunchOptions(env = process.env, resolveChromium = playwrightChromiumExecutable) {
  if (env.BRAVE_BIN) return { executablePath: env.BRAVE_BIN };
  let executablePath;
  try {
    executablePath = resolveChromium(env);
  } catch (error) {
    if (error?.code === "MODULE_NOT_FOUND") return {};
    throw error;
  }
  if (executablePath && existsSync(executablePath)) return { executablePath };
  return {};
}

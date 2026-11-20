import assert from "node:assert/strict";
import test from "node:test";
import { startupCrashSignal, withBrowserLaunchRecovery } from "./browser-launch-recovery.mjs";

test("startup classification requires the launch closure or the browser process signal", () => {
  assert.equal(startupCrashSignal(new Error("browserType.launch: Target page, context or browser has been closed\nBrowser logs:")), "unreported (browser closed)");
  assert.equal(startupCrashSignal(new Error("browserType.launch: Browser closed.")), "unreported (browser closed)");
  assert.equal(startupCrashSignal(new Error("<process did exit: exitCode=null, signal=SIGSEGV>")), "SIGSEGV");
  assert.equal(startupCrashSignal(new Error("<launched> pid=123\nReceived signal 11 SI_KERNEL")), "signal 11");
  for (const message of ["Target page, context or browser has been closed", "page.goto: Target page, context or browser has been closed", "signal=SIGSEGV", "browserType.launch: Executable doesn't exist", "browserType.launch: proxy authentication failed"]) {
    assert.equal(startupCrashSignal(new Error(message)), null, message);
  }
  for (const name of ["TimeoutError", "AssertionError"]) {
    const error = new Error("browserType.launch: Target page, context or browser has been closed\n<process did exit: exitCode=null, signal=SIGSEGV>");
    error.name = name;
    assert.equal(startupCrashSignal(error), null);
  }
});

test("the shared wrapper preserves engine options, receivers, identities and existing contexts", async () => {
  for (const name of ["chromium", "firefox", "webkit"]) {
    const options = { headless: true, args: ["--fixture"] };
    const browser = { contexts: () => [] };
    let persistentAttempts = 0;
    const type = {
      name: () => name,
      executablePath() { assert.equal(this, type); return "/fixture/browser"; },
      async launch(actual) { assert.equal(this, type); assert.equal(actual, options); return browser; },
      async launchPersistentContext() { persistentAttempts++; throw new Error("browserType.launchPersistentContext: Target page, context or browser has been closed AFTER_CONTEXT"); },
    };
    const raw = { [name]: type, request: {} };
    const wrapped = withBrowserLaunchRecovery(raw);
    assert.equal(withBrowserLaunchRecovery(raw), wrapped);
    assert.equal(withBrowserLaunchRecovery(wrapped), wrapped);
    assert.equal(wrapped[name], wrapped[name]);
    assert.equal(wrapped.request, raw.request);
    assert.equal(wrapped[name].executablePath(), "/fixture/browser");
    assert.equal(await wrapped[name].launch(options), browser);
    await assert.rejects(wrapped[name].launchPersistentContext(), /AFTER_CONTEXT/);
    assert.equal(persistentAttempts, 1);
  }
});

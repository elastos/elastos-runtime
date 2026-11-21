import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { withBrowserLaunchRecovery } from "./browser-launch-recovery.mjs";
import { webkitMacOSLaunchOptions } from "./webkit-macos-sandbox.mjs";

const profilePath = "WebKit.framework/Versions/A/Resources/com.apple.WebKit.NetworkProcess.sb";
const webProfilePath = "WebKit.framework/Versions/A/Resources/com.apple.WebProcess.sb";
const rules = ['(allow mach-lookup (global-name "com.apple.analyticsd"))', '(allow mach-lookup (global-name "com.apple.ReportMemoryException"))'].join("\n");
const webRule = '(allow mach-lookup (global-name "com.apple.tccd"))';
const profile = '(version 3)\n(deny default)\n(with-filter (system-attribute apple-internal)\n  (allow mach-lookup (global-name "com.apple.analyticsd")))\n';
const webProfile = '(version 3)\n(deny default)\n(deny mach-lookup (global-name "com.apple.tccd.system"))\n';

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "webkit-macos-sandbox-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const source = join(root, "webkit-2287");
  mkdirSync(dirname(join(source, profilePath)), { recursive: true });
  writeFileSync(join(source, profilePath), profile);
  writeFileSync(join(source, webProfilePath), webProfile);
  writeFileSync(join(source, "pw_run.sh"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  symlinkSync("A", join(source, "WebKit.framework/Versions/Current"));
  const type = { name: () => "webkit", executablePath: () => join(source, "pw_run.sh") };
  return { source, type, config: { platform: "darwin", cacheRoot: join(root, "cache") } };
}

test("Mac WebKit gets three initialization service rules in a private, reusable engine copy", t => {
  const { source, type, config } = fixture(t);
  const options = { headless: true, args: ["--fixture"] };
  const actual = webkitMacOSLaunchOptions(type, options, config);
  assert.notEqual(actual.executablePath, type.executablePath());
  assert.deepEqual(actual, { ...options, executablePath: actual.executablePath });
  const target = dirname(actual.executablePath);
  assert.equal(readFileSync(join(target, profilePath), "utf8"), `${profile}\n; ElastOS test engine: allow macOS initialization service lookups.\n${rules}\n`);
  assert.equal(readFileSync(join(target, webProfilePath), "utf8"), `${webProfile}\n; ElastOS test engine: allow macOS initialization service lookups.\n${webRule}\n`, "the system TCC denial stays in place");
  assert.equal(readFileSync(join(source, profilePath), "utf8"), profile, "shared profile keeps its bytes");
  assert.equal(readFileSync(join(source, webProfilePath), "utf8"), webProfile);
  assert.equal(readlinkSync(join(target, "WebKit.framework/Versions/Current")), "A", "framework links stay relative to the private copy");
  assert.deepEqual(webkitMacOSLaunchOptions(type, options, config), actual);
  assert.deepEqual(readdirSync(config.cacheRoot), [target.split("/").at(-1)]);
  writeFileSync(join(source, profilePath), profile + "; new source\n");
  assert.notEqual(webkitMacOSLaunchOptions(type, options, config).executablePath, actual.executablePath, "source changes invalidate the cached copy");
});

test("other hosts, engines, explicit executables and absent engines retain their options", t => {
  const { source, type, config } = fixture(t);
  const options = { headless: true };
  for (const platform of ["linux", "win32"]) {
    assert.equal(webkitMacOSLaunchOptions(type, options, { ...config, platform }), options);
  }
  for (const name of ["chromium", "firefox"]) {
    assert.equal(webkitMacOSLaunchOptions({ name: () => name }, options, config), options);
  }
  const explicit = { executablePath: "/operator/browser" };
  assert.equal(webkitMacOSLaunchOptions(type, explicit, config), explicit);
  assert.equal(webkitMacOSLaunchOptions({ ...type, executablePath: () => "/missing/pw_run.sh" }, options, config), options);
  assert.equal(existsSync(config.cacheRoot), false);
  writeFileSync(join(source, profilePath), profile + rules + "\n");
  writeFileSync(join(source, webProfilePath), webProfile + webRule + "\n");
  assert.equal(webkitMacOSLaunchOptions(type, options, config), options, "upstream service rules need no copy");
});

test("both local WebKit launch methods use the copy; persistent launch keeps its single attempt", async t => {
  const { type, config } = fixture(t);
  const calls = [];
  type.launch = async function(options) { assert.equal(this, type); calls.push(options); return "browser"; };
  type.launchPersistentContext = async function(directory, options) {
    assert.equal(this, type); assert.equal(directory, "/fixture/profile"); calls.push(options); throw new Error("AFTER_CONTEXT");
  };
  const { webkit } = withBrowserLaunchRecovery({ webkit: type }, config);
  assert.equal(await webkit.launch({ headless: true }), "browser");
  await assert.rejects(webkit.launchPersistentContext("/fixture/profile", { headless: false }), /AFTER_CONTEXT/);
  assert.equal(calls.length, 2);
  assert.ok(calls[0].executablePath);
  assert.equal(calls[0].executablePath, calls[1].executablePath);
  assert.notEqual(calls[0].executablePath, type.executablePath());
  assert.equal(calls[1].headless, false);
});

test("concurrent processes publish a complete copy and retire their scratch directories", async t => {
  const { type, config } = fixture(t);
  const module = new URL("./webkit-macos-sandbox.mjs", import.meta.url).href;
  const code = `import {webkitMacOSLaunchOptions} from ${JSON.stringify(module)};
    const type={name:()=>"webkit",executablePath:()=>${JSON.stringify(type.executablePath())}};
    console.log(JSON.stringify(webkitMacOSLaunchOptions(type,{},${JSON.stringify(config)})));`;
  const results = await Promise.all(Array.from({ length: 4 }, () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", code], { stdio: ["ignore", "pipe", "pipe"], timeout: 10000 });
    let output = "", errors = "";
    child.stdout.on("data", data => { output += data; });
    child.stderr.on("data", data => { errors += data; });
    child.on("error", reject);
    child.on("close", code => code === 0 ? resolve(JSON.parse(output)) : reject(new Error(errors)));
  })));
  for (const result of results) assert.deepEqual(result, results[0]);
  assert.equal(readdirSync(config.cacheRoot).length, 1);
  assert.ok(readFileSync(join(dirname(results[0].executablePath), profilePath), "utf8").endsWith(rules + "\n"));
  assert.ok(readFileSync(join(dirname(results[0].executablePath), webProfilePath), "utf8").endsWith(webRule + "\n"));
});

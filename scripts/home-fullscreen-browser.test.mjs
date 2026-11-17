import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { extname } from "node:path";
import test from "node:test";
import { importProductSmokePlaywright } from "./product-smoke-browser.mjs";

const root = new URL("../", import.meta.url);
const playwright = await importProductSmokePlaywright();
// Reproduce a pinned tree with the same test, without changing the checkout.
function sourceFile(path) {
  return process.env.HOME_FULLSCREEN_REF
    ? execFileSync('git', ['show', `${process.env.HOME_FULLSCREEN_REF}:${path}`], { cwd: root, timeout: 5000 })
    : readFile(new URL(path, root));
}
const sandbox = "allow-downloads allow-forms allow-modals allow-pointer-lock allow-scripts";
const shellScript = `
import { iframeAllowForLaunch, iframeSandboxForLaunch } from '/gui/shell-windows.js';
import { bindFullscreenToggle } from '/gui/shell-fullscreen.js';
bindFullscreenToggle(document.querySelector('#toggle'));
const frame = document.createElement('iframe');
frame.id = 'app';
frame.setAttribute('sandbox', iframeSandboxForLaunch({ target: 'elacity-player' }));
frame.setAttribute('allow', iframeAllowForLaunch());
frame.src = '/app';
document.body.append(frame);
window.systemSandbox = iframeSandboxForLaunch({ target: 'system' });
`;
const appScript = `
import { bindFullscreenToggle } from '/gui/shell-fullscreen.js';
bindFullscreenToggle(document.querySelector('#toggle'));
`;

// Use ports below the host's ephemeral range, away from installed Homes and
// staging fixtures. Try the next port only if another process owns this one.
async function listen(server, firstPort) {
  for (let port = firstPort; port < firstPort + 20; port++) {
    try {
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, '127.0.0.1', resolve);
      });
      server.removeAllListeners('error');
      return `http://127.0.0.1:${port}`;
    } catch (error) {
      server.removeAllListeners('error');
      if (error.code !== 'EADDRINUSE') throw error;
    }
  }
  throw new Error('Fullscreen fixture ports are occupied');
}

async function close(server) {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}

for (const engine of ['webkit', 'chromium']) {
  const missingWebKit = engine === 'webkit' && !existsSync(playwright.webkit.executablePath());
  test(`Home shell and nested app fullscreen in ${engine}`, {
    // The behaviour job installs Chromium. The content-sandbox job imports this
    // test with ELASTOS_PLAYWRIGHT_MODULE and installs both engines: require it.
    skip: missingWebKit && !process.env.ELASTOS_PLAYWRIGHT_MODULE
      ? 'WebKit is installed and required by the content-sandbox CI job' : false,
    timeout: 45000,
  }, async t => {
    let foreignRequests = 0;
    const foreign = createServer((_request, response) => {
      foreignRequests++;
      response.end('<body>foreign document</body>');
    });
    let origin;
    const server = createServer(async (request, response) => {
      try {
        const path = new URL(request.url, 'http://fixture').pathname;
        let body;
        let type = 'text/html';
        if (path === '/home/') {
          body = await sourceFile('capsules/home/browser/index.html');
          response.setHeader('content-security-policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
        } else if (path === '/shell' || path === '/app') {
          body = `<button id="toggle">Full screen</button><script type="module" src="${path}.js"></script>`;
          // Match Runtime's shell/app policy, including its extra CSP sandbox.
          response.setHeader('content-security-policy', `sandbox allow-scripts allow-forms allow-downloads; default-src ${origin}; script-src 'self' 'wasm-unsafe-eval' ${origin}; style-src ${origin} 'unsafe-inline'; img-src ${origin} blob: data:; connect-src ${origin} ${origin.replace('http:', 'ws:')}; frame-src ${origin}; object-src 'none'; base-uri 'none'; form-action ${origin}`);
        } else if (path === '/shell.js' || path === '/app.js') {
          body = path === '/shell.js' ? shellScript : appScript;
          type = 'text/javascript';
        } else if (/^\/gui\/[a-z0-9-]+\.js$/.test(path)) {
          body = await sourceFile(`capsules/home-gui/browser/${path.slice(5)}`);
          type = 'text/javascript';
        } else {
          // Home boot is outside this frame-policy fixture. Keep its HTML
          // intact and give its boot scripts empty responses.
          response.writeHead(200, { 'content-type': extname(path) === '.js' ? 'text/javascript' : 'text/plain' });
          response.end();
          return;
        }
        response.writeHead(200, { 'content-type': type,
          'access-control-allow-origin': 'null', 'cache-control': 'no-store' });
        response.end(body);
      } catch (error) {
        response.writeHead(500);
        response.end(String(error));
      }
    });
    let browser;
    try {
      origin = await listen(server, 42173);
      const foreignOrigin = await listen(foreign, 42203);
      browser = await playwright[engine].launch({ headless: true });
      const control = await browser.newPage();
      await control.goto(foreignOrigin);
      assert.ok(foreignRequests > 0, 'foreign navigation control is reachable');
      await control.close();
      const beforeForeignNavigation = foreignRequests;
      const page = await browser.newPage();
      page.setDefaultTimeout(5000);
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.goto(`${origin}/home/`);
      await page.evaluate(() => {
        document.querySelector('#active-shell-root').hidden = false;
        document.querySelector('#home-shell-boot-mask').remove();
        document.querySelector('#active-shell-frame').src = '/shell';
      });
      const shell = await (await page.locator('#active-shell-frame').elementHandle()).contentFrame();
      await shell.locator('#app').waitFor();
      const app = await (await shell.locator('#app').elementHandle()).contentFrame();
      await app.locator('#toggle[aria-pressed]').waitFor();
      assert.deepEqual(errors, [], 'real modules load without script errors');
      assert.equal(await page.locator('#active-shell-frame').getAttribute('sandbox'), sandbox);
      assert.equal(await shell.locator('#app').getAttribute('sandbox'), sandbox);
      const outerAllow = await page.locator('#active-shell-frame').getAttribute('allow');
      assert.match(outerAllow, /^autoplay; fullscreen(?: \*)?$/, 'only autoplay and fullscreen are delegated');
      assert.equal(await shell.locator('#app').getAttribute('allow'), outerAllow);
      assert.equal(await shell.evaluate(() => window.systemSandbox), `${sandbox} allow-top-navigation-by-user-activation allow-top-navigation-to-custom-protocols`);
      const result = { engine, version: browser.version() };
      for (const [name, frame] of [['shell', shell], ['app', app]]) {
        result[name] = await frame.evaluate(() => ({ enabled: document.fullscreenEnabled,
          origin: self.origin, api: typeof document.documentElement.requestFullscreen }));
        assert.equal(result[name].origin, 'null', `${name} retains its opaque origin`);
        if (result[name].enabled) {
          await frame.locator('#toggle').click();
          if (engine === 'chromium' || process.platform === 'darwin') {
            await frame.waitForFunction(() => !!document.fullscreenElement);
            await frame.locator('#toggle').click();
            await frame.waitForFunction(() => !document.fullscreenElement);
            result[name].enterExit = 'passed';
          } else {
            // Some headless WebKit backends expose permission without window
            // fullscreen. macOS WebKit and Chromium must actually enter/exit.
            let entered = false;
            try {
              await frame.waitForFunction(() => !!document.fullscreenElement, null, { timeout: 1000 });
              entered = true;
            } catch {
              assert.equal(await frame.evaluate(() => !!document.fullscreenElement), false);
              result[name].enterExit = 'headless WebKit did not enter';
            }
            if (entered) {
              await frame.locator('#toggle').click();
              await frame.waitForFunction(() => !document.fullscreenElement);
              result[name].enterExit = 'passed';
            }
          }
        } else result[name].enterExit = 'permission refused';
      }
      t.diagnostic(JSON.stringify(result));
      // Wait for an enforced rejection from each frame's owner. A request
      // counter alone could pass before a slow foreign navigation arrives.
      for (const [owner, frame] of [[shell, app], [page, shell]]) {
        await owner.evaluate(() => {
          window.fullscreenNavigationRejections = [];
          document.addEventListener('securitypolicyviolation', event => {
            window.fullscreenNavigationRejections.push({
              directive: event.effectiveDirective,
              disposition: event.disposition,
              blockedURI: event.blockedURI,
            });
          });
        });
        await frame.evaluate(url => { location.href = url; }, foreignOrigin);
        await owner.waitForFunction(origin => window.fullscreenNavigationRejections.some(event =>
          event.directive === 'frame-src' && event.disposition === 'enforce' &&
          new URL(event.blockedURI).origin === origin), foreignOrigin);
      }
      assert.equal(foreignRequests, beforeForeignNavigation, 'Home frame-src blocks foreign documents');
      assert.equal(result.shell.enabled, true, `${engine}: shell fullscreen permission`);
      assert.equal(result.app.enabled, true, `${engine}: nested app fullscreen permission`);
    } finally {
      await browser?.close();
      await Promise.all([close(server), close(foreign)]);
    }
  });
}

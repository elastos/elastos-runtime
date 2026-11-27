import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, statfs } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, resolve, sep } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { importProductSmokePlaywright, productSmokeLaunchOptions } from './product-smoke-browser.mjs';
import { inertSystemApiResponse, makeAppearanceRecord, makeSystemSummary } from './system-uiux-fixture.mjs';
import { windowTestOptions } from './lib/walletconnect-window-resources.mjs';

// Full Home admission/relay, GUI window manager, Assistant click handler and
// System navigation handshake. Only Runtime APIs are fixtures. No installed Home.
// ASSISTANT_ROUTE_REF pins product assets for fail-before evidence without
// changing the checkout. ASSISTANT_ROUTE_OUT retains JSON and screenshots.
const root = fileURLToPath(new URL('../', import.meta.url));
const output = process.env.ASSISTANT_ROUTE_OUT;
const sourceRef = process.env.ASSISTANT_ROUTE_REF;
const playwright = await importProductSmokePlaywright();
const version = 'home-20261101d';
const files = new Map();
const appearance = makeAppearanceRecord({ accent: 'blue', dock_auto_hide: false });
const targets = [['system', 'System'], ['chat-room', 'Chat'], ['assistant', 'Assistant']]
  .map(([target, title]) => ({ target, title, description: title, role: 'app',
    target_kind: 'app', attach_kind: 'iframe', window_policy: 'single' }));
const summary = {
  home: { route: '/apps/home/', attach_kind: 'iframe' }, app: { id: 'home', route: '/apps/home/' },
  identity: { device_did: null,
    profile_readiness: { schema: 'elastos.profile.readiness/v1', status: 'ready' },
    recovery_readiness: { schema: 'elastos.recovery.readiness/v1', status: 'ready' } },
  authority: { signed_in: true, principal_id: 'person:route-fixture', session_id: 'route-session',
    proof_binding_id: 'proof:passkey:route-fixture', wallet_connected: false },
  browser_state: { schema: 'elastos.home.browser-state/v1', principal_id: 'person:route-fixture',
    localhost_root: 'localhost://fixture', layout: null, recent_targets: [],
    session: { browser_context_id: '', root_shell: 'home-gui', windows: [] } },
  active_shell: { schema: 'elastos.home.active-shell/v1', active: 'home-gui', candidates: [
    { name: 'home-gui', title: 'Desktop', description: 'Desktop', route: '/apps/home-gui/',
      role: 'shell', trust_state: 'trusted', launchable: true } ] },
  appearance, runtime: { running: true, kind: 'local', version: 'fixture', running_capsules: [] },
  site: { staged: false, root_uri: '', path: '', release_count: 0 },
  room: { room_slug: 'fixture', title: '', member_count: 0, active_member_count: 0, pending_count: 0,
    active_session_count: 0, browser_access_allowed: true, pending_requests: [], active_sessions: [] },
  people: { schema: 'elastos.people.contacts/v1', contact_count: 0, contacts: [], service_offers: [] },
  services: { schema: 'elastos.runtime.services/v1', local_offers: [], remote_offers: [],
    available_local_offers: [], available_remote_offers: [] },
  notifications: { unread_count: 0, attention_count: 0, entries: [] },
  desktop_objects: { schema: 'elastos.home.desktop-objects/v1', uri: 'localhost://fixture/Desktop', objects: [], stale: false },
  capsule_catalog: { schema: 'elastos.capsules.catalog/v1', capsules: [], counts: {}, policy: {} },
  capsule_interfaces: { schema: 'elastos.capsules.interfaces/v1', interfaces: [], counts: {}, policy: {} }, targets,
};

async function diskGuard() {
  const disk = await statfs(root);
  assert.ok(disk.bavail * disk.bsize / 1024 >= 56663253, 'Stop: free disk is below 56,663,253 KiB');
}
async function source(path) {
  if (!files.has(path)) files.set(path, sourceRef
    ? execFileSync('git', ['show', `${sourceRef}:${path}`], { cwd: root, timeout: 5000 })
    : await readFile(resolve(root, path)));
  return files.get(path);
}

async function fixture() {
  const errors = [], launches = [], streams = new Set();
  let workspace = { schema: 'elastos.assistant.workspace/v2', revision: 0, document: {}, legacy: {} };
  const headers = { 'access-control-allow-origin': '*', 'cache-control': 'no-store' };
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://fixture');
    const json = (value, status = 200) => {
      res.writeHead(status, { ...headers, 'content-type': 'application/json' });
      res.end(JSON.stringify(value));
    };
    try {
      if (req.method === 'OPTIONS') {
        res.writeHead(204, { ...headers, 'access-control-allow-headers': 'content-type,x-elastos-home-token',
          'access-control-allow-methods': 'GET,POST,PUT,OPTIONS' }); res.end(); return;
      }
      if (url.pathname.startsWith('/api/')) {
        let raw = ''; for await (const chunk of req) raw += chunk;
        const input = raw ? JSON.parse(raw) : {};
        switch (url.pathname) {
          case '/api/auth/sessions/refresh': return json({ home_token: 'fixture-home-token' });
          case '/api/apps/home/summary': return json(summary);
          case '/api/apps/home/runtime/ensure': return json({ running: true });
          case '/api/apps/home/events': return json({ schema: 'elastos.home.events/v1', cursor: 'fixture', events: [], retry_after_ms: 60000 });
          case '/api/apps/home/events/stream':
            res.writeHead(200, { ...headers, 'content-type': 'text/event-stream' });
            res.write(': open\n\n'); streams.add(res); res.on('close', () => streams.delete(res)); return;
          case '/api/apps/home/state': return json({ saved: true });
          case '/api/apps/home/launch': {
            launches.push(input);
            assert.ok(['home-gui', 'assistant', 'system', 'chat-room'].includes(input.target));
            const query = new URLSearchParams(input.query);
            return json({ target: input.target, title: targets.find(t => t.target === input.target)?.title || 'Desktop',
              attach_kind: 'iframe', launch_status: 'launched', window_policy: 'single',
              route: `/apps/${input.target}/?${query}#home_token=fixture-${input.target}` });
          }
          case '/api/apps/system/summary': return json(makeSystemSummary(appearance));
          case '/api/apps/assistant/workspace-v2':
            if (req.method === 'PUT') workspace = { ...workspace, revision: workspace.revision + 1, document: input.document };
            return json(workspace);
          case '/api/provider/model/offers_list': return json({ offers: [] });
        }
        const inert = inertSystemApiResponse(url.pathname);
        if (inert !== null) return json(inert);
        throw Error(`Unexpected API: ${req.method} ${url.pathname}`);
      }
      if (url.pathname === '/favicon.ico') { res.writeHead(204); res.end(); return; }
      const match = /^\/apps\/(home|home-gui|system|assistant|chat-room)\/(.*)$/.exec(url.pathname);
      assert.ok(match, `Unexpected asset: ${url.pathname}`);
      // Chat is a visible background window, not part of this action's route.
      if (match[1] === 'chat-room') { res.writeHead(200, { ...headers, 'content-type': 'text/html' }); res.end('<h1>Chat fixture</h1>'); return; }
      const base = resolve(root, 'capsules', match[1], 'browser');
      const path = resolve(base, decodeURIComponent(match[2]) || 'index.html');
      assert.ok(path.startsWith(base + sep));
      res.writeHead(200, { ...headers, 'content-type': ({ '.html': 'text/html', '.js': 'text/javascript',
        '.mjs': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png',
        '.webp': 'image/webp', '.woff2': 'font/woff2', '.json': 'application/json' })[extname(path)] || 'application/octet-stream' });
      res.end(await source(path.slice(root.length)));
    } catch (error) { errors.push(error.message); if (!res.headersSent) json({ error: error.message }, 500); else res.end(); }
  });
  await new Promise((done, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', done); });
  return { errors, launches, origin: `http://127.0.0.1:${server.address().port}`,
    async close() { for (const stream of streams) stream.destroy(); server.closeAllConnections(); await new Promise(done => server.close(done)); } };
}

for (const engine of ['chromium', 'webkit']) {
  for (const width of [1440, 390]) {
    for (const state of ['closed', 'windowed', 'maximized', 'minimized', 'other-desktop', 'minimized-other-desktop']) {
      test(`${engine} ${width}: Manage models with System ${state}`, windowTestOptions(engine, 45000), async t => {
        await diskGuard();
        const f = await fixture();
        t.after(() => f.close());
        const browser = await playwright[engine].launch({ headless: true,
          ...(engine === 'chromium' ? productSmokeLaunchOptions() : {}) });
        t.after(() => browser.close());
        const page = await browser.newPage({ viewport: { width, height: width === 390 ? 844 : 960 },
          reducedMotion: 'no-preference', hasTouch: width === 390, isMobile: width === 390 });
        const pageErrors = [];
        page.on('pageerror', error => pageErrors.push(error.message));
        t.after(() => { if (f.errors.length || pageErrors.length) t.diagnostic(JSON.stringify({ errors: f.errors, pageErrors })); });
        page.setDefaultTimeout(8000);
        await page.route('**/*', route => new URL(route.request().url()).origin === f.origin
          ? route.continue() : route.abort());
        await page.goto(`${f.origin}/apps/home/`);
        await page.waitForFunction(() => document.body.dataset.homeStatus === 'ready');
        await page.evaluate(() => {
          window.routeRequests = [];
          addEventListener('message', event => {
            if (event.data?.type === 'home:open-target') window.routeRequests.push({ target: event.data.target, query: event.data.query });
          });
        });
        const shell = page.frameLocator('#active-shell-frame');
        const frame = await (await page.locator('#active-shell-frame').elementHandle()).contentFrame();
        await frame.waitForFunction(() => document.body.dataset.homeStatus === 'ready');
        await frame.evaluate(async ({ version, state }) => {
          const windows = await import(`./shell-windows.js?v=${version}`);
          const stages = await import(`./shell-stages.js?v=${version}`);
          const { shellState } = await import(`./shell-core.js?v=${version}`);
          window.routeFixture = { windows, stages, shellState, messages: [], stageChanges: [] };
          new MutationObserver(records => {
            const changes = records.filter(record => record.attributeName === 'data-active-stage');
            changes.forEach((_, i) => window.routeFixture.stageChanges.push(
              changes[i + 1]?.oldValue ?? document.body.dataset.activeStage));
          }).observe(document.body, { attributes: true, attributeOldValue: true, attributeFilter: ['data-active-stage'] });
          addEventListener('message', event => {
            if (event.data?.type === 'home:gui-command') window.routeFixture.messages.push(event.data);
          });
          if (state.endsWith('other-desktop')) { shellState.extraDesktops = ['desk-route']; stages.setActiveStage('desk-route'); }
          windows.openTarget('chat-room');
        }, { version, state });
        await shell.locator('.window[data-target="chat-room"]').waitFor();
        if (state !== 'closed') {
          await frame.evaluate(() => window.routeFixture.windows.openTarget('system', { query: { settings: 'personalization' } }));
          await shell.locator('.window[data-target="system"]').waitFor();
          const system = shell.frameLocator('iframe[title="System"]');
          await system.locator('.settings-sidebar-item[data-settings="personalization"].active').waitFor({ state: 'attached' });
          if (state === 'maximized') {
            if (width === 390) {
              // Phone chrome hides Maximize; exercise an existing fullscreen
              // Space through the same operation as the desktop green button.
              await frame.evaluate(() => window.routeFixture.stages.toggleFullscreenStage(window.routeFixture.shellState.activeWindowId));
            } else {
              await frame.waitForFunction(() => Number(document.querySelector('.window[data-target="system"]').dataset.controlGuardUntil) <= performance.now());
              await shell.locator('.window[data-target="system"] [data-action="maximize"]').click();
            }
            await frame.waitForFunction(() => [...window.routeFixture.shellState.windows.values()].find(e => e.targetId === 'system')?.fullscreenStage);
          } else if (state.startsWith('minimized')) {
            await frame.evaluate(() => window.routeFixture.windows.minimizeWindow(window.routeFixture.shellState.activeWindowId));
          }
        }
        await frame.evaluate(() => window.routeFixture.windows.openTarget('assistant'));
        const assistant = shell.frameLocator('#assistant-space-frame');
        await frame.waitForFunction(() => document.body.dataset.activeStage === 'agent'
          && !document.querySelector('.taskbar')?.dataset.assistantMorph);
        await assistant.locator('#agent-model-picker').click();
        await frame.evaluate(() => { window.routeFixture.stageChanges = []; });
        await assistant.locator('#agent-model-action-open-ai-provider-settings').click();
        await frame.waitForFunction(() => window.routeFixture.messages.some(m => m.command === 'open-target' && m.target === 'system'));
        const system = shell.frameLocator('iframe[title="System"]');
        await system.locator('.settings-sidebar-item[data-settings="models"].active').waitFor({ state: 'attached' });
        await frame.waitForFunction(() => !document.querySelector('.taskbar')?.dataset.assistantMorph);
        const result = await frame.evaluate(() => {
          const { shellState: s, stages, messages, stageChanges } = window.routeFixture;
          const entry = [...s.windows.values()].find(e => e.targetId === 'system');
          const rect = entry.node.getBoundingClientRect();
          return { stage: stages.getActiveStageId(), expectedStage: entry.fullscreenStage ? entry.id : entry.desktopSpaceId,
            activeTarget: s.windows.get(s.activeWindowId)?.targetId, systemCount: [...s.windows.values()].filter(e => e.targetId === 'system').length,
            hidden: entry.node.classList.contains('hidden'), inert: entry.node.inert, ariaHidden: entry.node.getAttribute('aria-hidden'),
            spaceVisible: stages.windowVisibleOnActiveSpace(entry), spaceVisibleAttribute: entry.node.dataset.spaceVisible ?? null,
            foreground: entry.node.contains(document.elementFromPoint(
              Math.max(1, Math.min(innerWidth - 1, rect.x + rect.width / 2)),
              Math.max(1, Math.min(innerHeight - 1, rect.y + rect.height / 2)))),
            rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
            commands: messages.filter(m => m.command === 'open-target'), stageChanges };
        });
        result.requests = await page.evaluate(() => window.routeRequests);
        t.diagnostic(JSON.stringify(result));
        if (output) {
          await mkdir(output, { recursive: true });
          const name = `${engine}-${width}-${state}`;
          await writeFile(resolve(output, `${name}.json`), JSON.stringify({ engine, width, state, sourceRef: sourceRef || 'working-tree',
            browserVersion: browser.version(), ...result, launches: f.launches, errors: f.errors, pageErrors,
            sources: Object.fromEntries([...files].map(([path, bytes]) => [path, createHash('sha256').update(bytes).digest('hex')])) }, null, 2));
          await page.screenshot({ path: resolve(output, `${name}.png`) });
        }
        assert.deepEqual(result.commands.at(-1).query, { settings: 'models' });
        assert.deepEqual(result.requests.at(-1), { target: 'system', query: { settings: 'models' } });
        assert.equal(result.stage, result.expectedStage, 'System owns the selected Space');
        if (state === 'maximized' || state.endsWith('other-desktop')) {
          assert.equal(result.stageChanges.includes('desktop'), false, 'Existing System opens directly in its own Space');
        }
        assert.equal(result.activeTarget, 'system');
        assert.equal(result.systemCount, 1, 'System keeps its single window');
        assert.equal(result.hidden, false);
        assert.equal(result.inert, false);
        assert.equal(result.ariaHidden, 'false');
        assert.equal(result.spaceVisible, true);
        assert.equal(result.foreground, true, 'System receives input above Chat and Assistant');
        await system.locator('.settings-content[data-settings="models"] #ai-provider-add').waitFor({ state: 'visible' });
        assert.deepEqual(f.errors, [], 'Runtime fixture serves every requested API');
        assert.deepEqual(pageErrors, [], 'real product modules finish without page errors');
        await diskGuard();
      });
    }
  }
}

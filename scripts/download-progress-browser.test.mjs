import assert from "node:assert/strict";
import test from "node:test";
import { readFile, mkdir } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { chromium, jsonResponse, makeAppearanceRecord, makeSystemSummary, startSystemFixtureServer } from "./system-uiux-fixture.mjs";
import { productSmokeLaunchOptions } from "./product-smoke-browser.mjs";

function transferContrast(node) {
  const parse = value => {
    const numbers = value.match(/[\d.]+/g)?.map(Number) || [0, 0, 0, 0];
    return [...numbers.slice(0, 3), numbers[3] ?? 1];
  };
  const over = (front, back) => front.slice(0, 3).map((value, index) => value * front[3] + back[index] * (1 - front[3]));
  const parents = [];
  for (let parent = node; parent; parent = parent.parentElement) parents.unshift(parent);
  const back = parents.reduce((back, parent) => over(parse(getComputedStyle(parent).backgroundColor), back), [255, 255, 255]);
  const fore = over(parse(getComputedStyle(node).color), back);
  const luminance = rgb => rgb.map(value => value / 255).map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
    .reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
  const values = [luminance(fore), luminance(back)].sort((a, b) => b - a);
  return { ratio: (values[0] + 0.05) / (values[1] + 0.05), theme: document.documentElement.dataset.elTheme };
}

// Real capsule documents and controllers, with fixture API data only.
test("System, model and Library transfer states stay accessible in light and dark", { timeout: 55000 }, async () => {
  const root = resolve(new URL("../", import.meta.url).pathname);
  const screenshots = process.env.DOWNLOAD_PROGRESS_SCREENSHOTS;
  if (screenshots) await mkdir(screenshots, { recursive: true });
  const cid = `bafybei${"a".repeat(52)}`;
  const preparation = { operation_id: "fixture-model", cid, state: "preparing", total_bytes: 2000000000,
    completed_bytes: 750000000, cancel_requested: false, admitted: false, activation_pending: false, failure_class: null };
  const runtime = { admitted: false, kept: false, dispatch_ready: false, offer_id: null, preparation };
  const manifest = JSON.parse(await readFile(resolve(root, "capsules/system/capsule.json"), "utf8"));
  let workspace = { schema: "elastos.assistant.workspace/v2", revision: 0, document: null };
  let assistantView = false;
  let theme = "light", completed = 25000000, total = 100000000;
  const fixture = await startSystemFixtureServer({ title: "Download progress fixture", async onApiRequest({ request, response, url }) {
    const json = value => { jsonResponse(response, value); return true; };
    if (url.pathname === "/assistant-fixture") {
      response.writeHead(200, { "content-type": "text/html" });
      response.end(`<!doctype html><style>html,body,iframe{margin:0;border:0;width:100%;height:100%}</style><iframe title="Assistant" sandbox="allow-scripts allow-forms" src="/apps/assistant/?home_origin=${encodeURIComponent(fixture.baseUrl)}#home_token=fixture"></iframe><script>addEventListener('message',event=>{if(event.data?.type==='home-agent:ready'){event.source.postMessage({type:'home-agent:open'},'*');event.source.postMessage({type:'home-agent:shelf-handover',on:true},'*');}});</script>`);
      return true;
    }
    if (url.pathname === "/api/apps/assistant/workspace-v2") {
      if (request.method === "PUT") {
        let body = ""; for await (const chunk of request) body += chunk;
        workspace = { ...workspace, revision: workspace.revision + 1, document: JSON.parse(body).document };
      }
      return json(workspace);
    }
    if (url.pathname === "/api/provider/model/offers_list") return json({ offers: [] });
    if (url.pathname === "/api/apps/system/summary") return json({ ...makeSystemSummary(makeAppearanceRecord({ theme })),
      runtime_update: { configured: true, available: false, can_apply: false, current_version: "2.0.1",
        controller: { id: "fixture-update", current_version: "2.0.1", new_version: "2.0.2", phase: "downloading",
          message: "Downloading the update. Home restarts when the update is ready.", completed_bytes: completed, total_bytes: total } } });
    if (url.pathname === "/api/capsules/catalog") return json({ schema: "elastos.capsules.catalog/v1", model_catalog_state: "verified", capsules: [
      { name: "fixture-model", title: assistantView ? "A long model name for the Assistant download on a narrow screen" : "Fixture model", role: "content", source: "signed-model-catalog", installed: false, launchable: false,
        cid, publisher_did: "did:key:zFixture", content_size_bytes: preparation.total_bytes, signature_state: "catalog-signature-verified",
        model_memory_fit: "fits", model_runtime: runtime },
    ] });
    if (url.pathname === "/api/capsules/interfaces") return json({ interfaces: manifest.interfaces.map(iface => ({ capsule: "system", interface: iface,
      bindings: iface.methods.map(method => ({ method: method.id, executable: true })) })) });
    if (url.pathname === "/api/capsules/interfaces/invoke") {
      let body = ""; for await (const chunk of request) body += chunk;
      const input = JSON.parse(body);
      return json({ ...input, schema: "elastos.capsules.invoke-result/v1", status: "ok", output: { ...runtime, ...preparation } });
    }
    if (url.pathname.startsWith("/api/provider/object/")) {
      if (url.pathname.endsWith("/events/stream")) { response.writeHead(204); response.end(); return true; }
      return json({ status: "ok", data: { roots: [{ schema: "elastos.library.root/v1", id: "documents", label: "Documents", uri: "localhost://Users/fixture/Documents", kind: "directory" }],
        objects: [], object: { schema: "elastos.library.object/v1", metadata: { readonly: false }, uri: "localhost://Users/fixture/Documents", name: "Documents", kind: "directory", capabilities: ["open", "upload", "properties"] } } });
    }
    if (url.pathname.startsWith("/apps/")) {
      const match = url.pathname.match(/^\/apps\/([^/]+)\/(.*)$/);
      const path = resolve(root, "capsules", match[1], "browser", match[2] || "index.html");
      assert(path.startsWith(`${root}${sep}capsules${sep}`));
      const bytes = await readFile(path);
      response.writeHead(200, { "access-control-allow-origin": "null", "content-type": ({ ".js": "text/javascript", ".mjs": "text/javascript", ".woff2": "font/woff2", ".css": "text/css", ".html": "text/html", ".svg": "image/svg+xml" })[extname(path)] || "application/octet-stream" });
      response.end(bytes); return true;
    }
    return false;
  } });
  const browser = await chromium.launch({ headless: true, ...productSmokeLaunchOptions() });
  const page = await browser.newPage({ viewport: { width: 1100, height: 800 } });
  const errors = [];
  page.on("pageerror", error => errors.push(String(error)));
  const screenshot = async name => { if (screenshots) await page.screenshot({ path: `${screenshots}/${name}.png` }); };
  try {
    for (theme of ["light", "dark"]) {
      completed = 25000000; total = 100000000;
      await page.goto(`${fixture.baseUrl}/fixture?settings=about`);
      const system = page.frameLocator("#system-frame");
      const progress = system.locator("#runtime-update-progress");
      await progress.getByText("25.0 MB of 100.0 MB · 25%", { exact: true }).waitFor();
      const colors = await progress.locator(".transfer-progress span").evaluate(transferContrast);
      assert.equal(colors.theme, theme);
      assert(colors.ratio >= 4.5, `System ${theme} progress contrast: ${colors.ratio}`);
      assert.equal(await progress.getByRole("progressbar").getAttribute("aria-valuetext"), "25.0 MB of 100.0 MB · 25%");
      await screenshot(`system-update-${theme}`);
      completed = 75000000;
      await progress.getByText("75.0 MB of 100.0 MB · 75%", { exact: true }).waitFor({ timeout: 9000 });
      total = null;
      await progress.getByText("75.0 MB received", { exact: true }).waitFor({ timeout: 9000 });
      assert.equal(await progress.locator("progress").getAttribute("value"), null);
      await system.getByRole("button", { name: "Models", exact: true }).click();
      await system.locator("[data-model-management]").getByText("0.8 GB of 2.0 GB · 37%", { exact: true }).waitFor();
      assert((await system.locator("[data-model-management] .transfer-progress span").evaluate(transferContrast)).ratio >= 4.5);
      await screenshot(`model-download-${theme}`);
      await page.goto(`${fixture.baseUrl}/apps/library/?uri=localhost%3A%2F%2FUsers%2Ffixture%2FDocuments#home_token=fixture`);
      await page.locator("#file-input").waitFor({ state: "attached" });
      await page.waitForFunction(() => window.__libraryPerf?.contentRenderCount > 0);
      assert.equal(await page.getByText("Library could not open", { exact: true }).count(), 0);
      await page.evaluate(async theme => {
        document.documentElement.setAttribute("data-el-theme", theme);
        const { createLibraryUploads } = await import("./src/uploads.js");
        createLibraryUploads({ container: document.querySelector("#upload-progress"), perf: { uploadRenderCount: 0 },
          state: { uploads: [{ id: "fixture", name: "Project files.zip", status: "Uploading", completed_bytes: 3750000, total_bytes: 10000000 }] } }).renderUploads();
      }, theme);
      await page.getByText("3.8 MB of 10.0 MB · 37%", { exact: true }).waitFor();
      assert.equal(await page.getByRole("progressbar").getAttribute("aria-label"), "Upload progress");
      assert((await page.locator(".upload-meter .transfer-progress span").evaluate(transferContrast)).ratio >= 4.5);
      await screenshot(`library-upload-${theme}`);
      await page.setViewportSize({ width: 390, height: 844 });
      assert.equal(await page.locator("#upload-progress").evaluate(node => node.scrollWidth <= node.clientWidth), true);
      await screenshot(`library-upload-phone-${theme}`);
      await page.setViewportSize({ width: 1100, height: 800 });
      assistantView = true;
      await page.goto(`${fixture.baseUrl}/assistant-fixture`);
      const assistant = page.frameLocator("iframe");
      await assistant.locator(".agent-model-download").getByText("0.8 GB of 2.0 GB · 37%", { exact: true }).waitFor();
      await assistant.locator("html").evaluate((node, theme) => node.setAttribute("data-el-theme", theme), theme);
      assert((await assistant.locator(".agent-model-download .transfer-progress span").evaluate(transferContrast)).ratio >= 4.5);
      await screenshot(`assistant-model-download-${theme}`);
      await page.setViewportSize({ width: 390, height: 844 });
      await assistant.locator("html").evaluate(node => node.setAttribute("data-el-form-factor", "phone"));
      assert.equal(await assistant.locator(".agent-model-download").evaluate(node => {
        const box = node.getBoundingClientRect();
        return node.scrollWidth <= node.clientWidth && box.left >= 0 && box.right <= innerWidth && box.bottom <= innerHeight;
      }), true);
      await screenshot(`assistant-model-download-phone-${theme}`);
      await page.setViewportSize({ width: 1100, height: 800 });
      assistantView = false;
    }
    assert.deepEqual(errors, []);
    assert.deepEqual(fixture.requestFailures, []);
  } finally {
    await browser.close();
    await fixture.close();
  }
});

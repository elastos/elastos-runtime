import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { inspectMetadata } from "./carrier-dependency-generation-check.mjs";

function compatibleGraph() {
  const entries = [
    ["iroh", "1.4.1"],
    ["iroh-base", "1.4.1"],
    ["iroh-dns", "1.4.1"],
    ["iroh-relay", "1.4.1"],
    ["iroh-gossip", "0.102.0"],
    ["iroh-mdns-address-lookup", "0.4.0"],
    ["hickory-proto", "0.26.2"],
    ["n0-dns-resolver", "0.1.0"],
    ["ed25519-dalek", "2.2.0"],
    ["ed25519-dalek", "3.0.0-rc.0"],
    ["crossbeam-epoch", "0.9.20"],
    ["quinn", "0.11.9"],
    ["quinn-proto", "0.11.19"],
    ["quick-xml", "0.41.0"],
    ["bincode", "1.3.3"],
    ["elastos-identity", "2.0.1"],
  ];
  const packages = entries.map(([name, version]) => ({ name, version, id: `${name}@${version}` }));
  const edges = new Map([
    ["iroh@1.4.1", ["ed25519-dalek@3.0.0-rc.0"]],
    ["elastos-identity@2.0.1", ["ed25519-dalek@2.2.0"]],
  ]);
  return {
    packages,
    resolve: { nodes: packages.map(({ id }) => ({ id, deps: (edges.get(id) || []).map(pkg => ({ pkg })) })) },
  };
}

for (const linked of [false, true]) {
  test(`CLI rejects a wrong iroh version through a ${linked ? "symlink" : "direct path"}`, (t) => {
    const root = mkdtempSync(join(realpathSync(tmpdir()), "carrier-generation-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    for (const file of [
      "scripts/carrier-dependency-generation-check.mjs",
      "rust-toolchain.toml",
      "elastos/Cargo.toml",
      ".github/workflows/ci.yml",
      "scripts/setup-source-home.sh",
      "README.md",
      "docs/GETTING_STARTED.md",
      "elastos/README.md",
      "elastos/crates/elastos-server/Cargo.toml",
      "elastos/crates/elastos-server/src/carrier.rs",
    ]) {
      const target = join(root, file);
      mkdirSync(dirname(target), { recursive: true });
      copyFileSync(new URL(`../${file}`, import.meta.url), target);
    }
    const graph = compatibleGraph();
    graph.packages.find(pkg => pkg.name === "iroh").version = "1.0.2";
    const bin = join(root, "bin");
    mkdirSync(bin);
    writeFileSync(join(bin, "cargo"), `#!/usr/bin/env node\nprocess.stdout.write(${JSON.stringify(JSON.stringify(graph))});\n`, { mode: 0o755 });
    const script = join(root, "scripts/carrier-dependency-generation-check.mjs");
    const entry = linked ? join(root, "check.mjs") : script;
    if (linked) symlinkSync(script, entry);
    const result = spawnSync(process.execPath, [entry], {
      encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
      timeout: 10_000,
    });
    assert.equal(result.status, 1, result.stderr || result.stdout);
    assert.match(result.stderr, /resolves iroh as \[1\.0\.2\], expected \[1\.4\.1\]/);
  });
}

test("accepts iroh 1.4.1 with gossip and no topic tracker", () => {
  assert.deepEqual(inspectMetadata(compatibleGraph(), "fixture").iroh, ["1.4.1"]);
});

for (const name of [
  "iroh",
  "iroh-base",
  "iroh-dns",
  "iroh-relay",
  "iroh-gossip",
  "iroh-mdns-address-lookup",
  "hickory-proto",
  "n0-dns-resolver",
]) {
  test(`rejects an incompatible ${name} version`, () => {
    const graph = compatibleGraph();
    graph.packages.find(pkg => pkg.name === name).version = "0.0.0";
    assert.throws(() => inspectMetadata(graph, "fixture"), new RegExp(`resolves ${name} as`));
  });
}

test("rejects a second iroh generation", () => {
  const graph = compatibleGraph();
  graph.packages.push({ name: "iroh", version: "1.0.2", id: "iroh@1.0.2" });
  assert.throws(() => inspectMetadata(graph, "fixture"), /resolves iroh as/);
});

test("rejects the retired DNS resolver", () => {
  const graph = compatibleGraph();
  graph.packages.push({ name: "hickory-resolver", version: "0.26.1", id: "hickory-resolver@0.26.1" });
  assert.throws(() => inspectMetadata(graph, "fixture"), /resolves hickory-resolver as/);
});

for (const source of ["elastos-identity@2.0.1", "iroh@1.4.1"]) {
  test(`rejects a disconnected ${source}`, () => {
    const graph = compatibleGraph();
    graph.resolve.nodes.find(node => node.id === source).deps = [];
    assert.throws(() => inspectMetadata(graph, "fixture"), /does not connect/);
  });
}

for (const version of ["0.3.5", "0.4.0"]) {
  test(`rejects retired distributed-topic-tracker ${version}`, () => {
    const graph = compatibleGraph();
    graph.packages.push({ name: "distributed-topic-tracker", version, id: `distributed-topic-tracker@${version}` });
    assert.throws(() => inspectMetadata(graph, "fixture"), /resolves distributed-topic-tracker as/);
  });
}

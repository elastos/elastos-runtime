import assert from "node:assert/strict";
import test from "node:test";
import { inspectMetadata } from "./carrier-dependency-generation-check.mjs";

function compatibleGraph() {
  const entries = [
    ["iroh", "1.4.1"],
    ["iroh-base", "1.4.1"],
    ["iroh-dns", "1.4.1"],
    ["iroh-relay", "1.4.1"],
    ["iroh-gossip", "0.101.0"],
    ["iroh-mdns-address-lookup", "0.4.0"],
    ["distributed-topic-tracker", "0.3.5"],
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
    ["distributed-topic-tracker@0.3.5", ["iroh@1.4.1", "iroh-gossip@0.101.0"]],
    ["iroh@1.4.1", ["ed25519-dalek@3.0.0-rc.0"]],
    ["elastos-identity@2.0.1", ["ed25519-dalek@2.2.0"]],
  ]);
  return {
    packages,
    resolve: { nodes: packages.map(({ id }) => ({ id, deps: (edges.get(id) || []).map(pkg => ({ pkg })) })) },
  };
}

test("accepts iroh 1.4.1 with the retained gossip and tracker", () => {
  assert.deepEqual(inspectMetadata(compatibleGraph(), "fixture").iroh, ["1.4.1"]);
});

for (const name of [
  "iroh",
  "iroh-base",
  "iroh-dns",
  "iroh-relay",
  "iroh-gossip",
  "iroh-mdns-address-lookup",
  "distributed-topic-tracker",
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

for (const source of ["distributed-topic-tracker@0.3.5", "elastos-identity@2.0.1", "iroh@1.4.1"]) {
  test(`rejects a disconnected ${source}`, () => {
    const graph = compatibleGraph();
    graph.resolve.nodes.find(node => node.id === source).deps = [];
    assert.throws(() => inspectMetadata(graph, "fixture"), /does not connect/);
  });
}

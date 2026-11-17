import test from "node:test";
test("blocked event loop", () => { while (true) {} });

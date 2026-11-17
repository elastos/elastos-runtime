import test from "node:test";
test("hung test", async () => { await new Promise(() => { setInterval(() => {}, 1000); }); });

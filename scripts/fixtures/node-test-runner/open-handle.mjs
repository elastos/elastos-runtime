import test from "node:test";
test("test with leaked interval", () => { setInterval(() => {}, 1000); });

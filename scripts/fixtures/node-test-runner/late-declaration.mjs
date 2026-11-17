import test from "node:test";
test("immediate test", () => {});
setTimeout(() => test("later declared test", () => {}), 30);

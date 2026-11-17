import test from "node:test";
test("declared before module exit", () => {});
process.exit(0);

import test from "node:test";
test("reported before cutoff", () => {});
test("first unfinished test", async () => {
  await new Promise(resolve => setTimeout(resolve, 20));
  process.exit(0);
});
test("declared after cutoff", () => {});

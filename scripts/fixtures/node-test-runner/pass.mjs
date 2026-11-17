import test, { describe } from "node:test";
test("duplicate name", () => {});
test("duplicate name", () => {});
test.skip("accepted skip", () => {});
test.todo("accepted todo");
describe("nested suite", () => { test("nested test", () => {}); });

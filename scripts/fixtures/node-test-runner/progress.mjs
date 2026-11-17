import test from "node:test";
for (let index = 0; index < 8; index++) {
  test(`progress ${index}`, async () => { await new Promise(resolve => setTimeout(resolve, 500)); });
}

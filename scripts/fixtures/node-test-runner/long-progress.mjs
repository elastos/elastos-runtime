import test from "node:test";
for (let index = 0; index < 16; index++) {
  test(`long progress ${index}`, async () => { await new Promise(resolve => setTimeout(resolve, 500)); });
}

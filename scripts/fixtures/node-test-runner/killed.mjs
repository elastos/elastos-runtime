import test from "node:test";
test("killed test", async () => {
  await new Promise(resolve => setTimeout(resolve, 20));
  process.kill(process.pid, "SIGKILL");
});

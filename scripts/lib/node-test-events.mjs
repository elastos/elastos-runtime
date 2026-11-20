// A separate pipe keeps test stdout and the spec display out of the guard protocol.
import { appendFileSync, writeSync } from "node:fs";
import { tracingChannel } from "node:diagnostics_channel";

// The synchronous start record survives a test blocking the event loop before
// Node's asynchronous reporter can flush its enqueue/dequeue events.
if (process.env.NODE_TEST_CONTEXT === "child-v8" && process.env.NODE_TEST_GUARD_STARTS) {
  // Plain assertion scripts also need a normal beforeExit summary. Importing
  // node:test here makes an early process.exit distinguishable from completion.
  const { after } = await import("node:test");
  after(() => {});
  tracingChannel("node.test").subscribe({ start({ name, file, type }) {
    if (type === "test" && name !== "<root>") {
      appendFileSync(process.env.NODE_TEST_GUARD_STARTS, `${JSON.stringify({ name: name.slice(0, 160), file, startedAt: Date.now() })}\n`);
    }
  } });
}
export default async function* events(source) {
  for await (const { type, data } of source) {
    if (["test:enqueue", "test:dequeue", "test:pass", "test:fail", "test:complete", "test:summary", "test:stdout", "test:stderr"].includes(type)) {
      writeSync(3, `${JSON.stringify({ type, data })}\n`);
    }
  }
}

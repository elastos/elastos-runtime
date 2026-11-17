import test from 'node:test';
import { spawn } from 'node:child_process';
// Stall only this fixture's owning Node runner; the helper always resumes it.
if (process.env.NODE_TEST_CONTEXT !== 'child-v8') throw new Error('run through node --test');
test('pause the owning runner to fill its result pipe', async () => {
  await new Promise(r => setTimeout(r, 30));
  spawn(process.execPath, ['-e', 'setTimeout(() => process.kill(Number(process.argv[1]), "SIGCONT"), 300)', String(process.ppid)], {stdio:'ignore'}).unref();
  process.kill(process.ppid, 'SIGSTOP');
});
for (let i = 0; i < 1000; i++) test(`declared ${i} ${'x'.repeat(1000)}`, () => {});

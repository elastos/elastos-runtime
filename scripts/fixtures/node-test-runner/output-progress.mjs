for (let index = 0; index < 8; index++) {
  process[process.env.NODE_TEST_GUARD_OUTPUT ?? "stdout"].write(`script progress ${index}\n`);
  await new Promise(resolve => setTimeout(resolve, 500));
}

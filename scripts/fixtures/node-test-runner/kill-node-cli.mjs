// This test file's parent is the Node CLI started by its owned worker leader.
process.kill(process.ppid, "SIGKILL");

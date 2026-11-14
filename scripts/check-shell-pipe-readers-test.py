#!/usr/bin/env python3
"""Exercise the real source guard against isolated repository fixtures."""

from pathlib import Path
import os
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest


GUARD = Path(__file__).with_name("check-shell-pipe-readers.py")
PIPE = " | "


def fixture_environment(cwd):
    names = subprocess.check_output(
        ["git", "rev-parse", "--local-env-vars"], cwd=cwd, text=True, timeout=10,
    ).splitlines()
    environment = {key: value for key, value in os.environ.items() if key not in names}
    environment.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
    return environment


class PipeReadersTest(unittest.TestCase):
    def test_rejects_untracked_guard(self):
        with tempfile.TemporaryDirectory(prefix="pipe-readers-test-") as scratch:
            root = Path(scratch)
            (root / "scripts").mkdir()
            guard = root / "scripts" / GUARD.name
            shutil.copyfile(GUARD, guard)
            environment = fixture_environment(root)
            subprocess.run(["git", "init", "-q"], cwd=root, env=environment, check=True, timeout=10)
            result = subprocess.run([sys.executable, str(guard)], env=environment, capture_output=True, text=True, timeout=10)
            self.assertNotIn("Shell pipeline readers consume full input", result.stdout)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def check_source(self, relative, source, untracked=None):
        with tempfile.TemporaryDirectory(prefix="pipe-readers-test-") as scratch:
            root = Path(scratch)
            (root / "scripts").mkdir()
            (root / ".githooks").mkdir()
            guard = root / "scripts" / GUARD.name
            shutil.copyfile(GUARD, guard)
            fixture = root / relative
            fixture.parent.mkdir(parents=True, exist_ok=True)
            fixture.write_text(source)
            environment = fixture_environment(root)
            subprocess.run(["git", "init", "-q"], cwd=root, env=environment, check=True, timeout=10)
            subprocess.run(["git", "add", "scripts", ".githooks"], cwd=root, env=environment, check=True, timeout=10)
            for name, content in (untracked or {}).items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            return subprocess.run([sys.executable, str(guard)], env=environment, capture_output=True, text=True, timeout=10)

    def test_only_checks_tracked_files(self):
        forbidden = "set -euo pipefail\nproducer" + PIPE + "grep -q match\n"
        for untracked in (
            {"scripts/stray": b"\x7fELF\xa0"},
            {".gitignore": b"scripts/ignored\n", "scripts/ignored": b"\x7fELF\xa0"},
            {"scripts/untracked.sh": forbidden.encode()},
        ):
            with self.subTest(files=list(untracked)):
                result = self.check_source("scripts/tracked.sh", "set -euo pipefail\n", untracked)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                result = self.check_source("scripts/tracked.sh", forbidden, untracked)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("scripts/tracked.sh:2:", result.stderr)

    def test_rejects_early_readers(self):
        readers = (
            "grep -q match", "grep -Eq match", "grep --quiet match",
            "grep -m 1 match", "rg --max-count=1 match", "head -n 1",
            "grep -l match", "rg --files-with-matches match",
            "/usr/bin/grep -q match", "grep -F -q match",
            "sed '1q'", "sed -n '1p; 1q'", "sed '/match/q'", "awk 'NR == 1 { print; exit }'",
        )
        for reader in readers:
            with self.subTest(reader=reader):
                result = self.check_source("scripts/probe.sh", "set -euo pipefail\nproducer" + PIPE + reader + "\n")
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("scripts/probe.sh:2:", result.stderr)

    def test_rejects_split_pipeline(self):
        for separator in ("\n    ", "\\\n    "):
            with self.subTest(separator=separator):
                result = self.check_source("scripts/dev/sign.sh", "set -euo pipefail\nproducer" + PIPE + separator + "grep -q match\n")
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("scripts/dev/sign.sh:2:", result.stderr)

    def test_checks_hooks_and_generated_shell(self):
        for relative, source in (
            (".githooks/pre-push", "set -euo pipefail\nproducer" + PIPE + "grep -q match\n"),
            ("scripts/generated.mjs", 'const lines = ["set -euo pipefail", "producer' + PIPE + '/usr/bin/grep -q match"];\n'),
            ("scripts/generated.py", 'shell = """set -euo pipefail\nproducer' + PIPE + 'grep -q match\n"""\n'),
            ("scripts/sourced.sh", "producer" + PIPE + "grep -q match\n"),
        ):
            with self.subTest(relative=relative):
                result = self.check_source(relative, source)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(relative + ":", result.stderr)

    def test_accepts_draining_readers_and_file_inputs(self):
        source = """set -euo pipefail
producer | grep match >/dev/null
producer | /usr/bin/grep match >/dev/null
producer |
    grep match >/dev/null
producer | sed -n 1p
producer | sed 's/q/r/'
producer | awk 'NR == 1 { print }'
grep -q match input.txt
head -n 1 input.txt | cat
awk 'NR == 1 { print; exit }' input.txt
grep -q match <<<"$output"
# producer | grep -q match
"""
        result = self.check_source("scripts/drain.sh", source)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_draining_reader_preserves_match_and_producer_errors(self):
        # A write larger than the pipe buffer makes the quiet-reader failure
        # independent of scheduling. Restore SIGPIPE for a normal shell status.
        producer = ("import signal, sys; signal.signal(signal.SIGPIPE, signal.SIG_DFL); "
                    "sys.stdout.write('match\\n' + 'x' * (4 * 1024 * 1024)); sys.stdout.flush()")
        command = shlex.quote(sys.executable) + " -c " + shlex.quote(producer)
        for reader, expected in (
            ("grep -q match", 141),
            ("grep match >/dev/null", 0),
            ("grep missing >/dev/null", 1),
        ):
            with self.subTest(reader=reader):
                result = subprocess.run(["bash", "-o", "pipefail", "-c", command + PIPE + reader], timeout=10)
                self.assertEqual(result.returncode, expected)
        failed_producer = "{ printf 'match\\n'; exit 23; }"
        result = subprocess.run(["bash", "-o", "pipefail", "-c", failed_producer + PIPE + "grep match >/dev/null"], timeout=10)
        self.assertEqual(result.returncode, 23)


if __name__ == "__main__":
    unittest.main()

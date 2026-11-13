#!/usr/bin/env python3
"""Reject early-exit pipeline readers in shell scripts and generated shell."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parent.parent
# Scan across newlines: a pipe can end a physical line, and shell commands
# embedded in launchers can use absolute executable paths.
EARLY_READER = re.compile(
    r"(?<!\|)\|(?!\|)\s*(?:\\\n\s*)?(?:/[^\s\"'|;]+/)?(?:"
    r"(?:grep|rg)\s+(?:-[A-Za-z]+\s+)*"
    r"(?:-[A-Za-z]*[qml][A-Za-z]*\d*\b|--(?:quiet|max-count|files-with-matches)\b)"
    r"|head(?:\s|$)"
    r"|(?:g?awk)\s+(?:-[A-Za-z]+\s+)*['\"][^'\"]*\bexit\b"
    r"|sed\s+(?:-[A-Za-z]+\s+)*['\"](?:[^'\"\n]*[;{]\s*)?"
    r"(?:\d+|\$|/[^/'\"\n]*/)?\s*q\d*\b"
    r")"
)
failures = []
for directory in (ROOT / "scripts", ROOT / ".githooks"):
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.suffix not in (".sh", ".mjs", ".py", ""):
            continue
        source = path.read_text()
        # Sourced shell files inherit pipefail from their caller.
        if path.suffix in (".mjs", ".py") and "pipefail" not in source:
            continue
        # Keep line positions while removing full-line comments from the scan.
        source = "\n".join("" if line.lstrip().startswith("#") else line
                           for line in source.splitlines())
        for match in EARLY_READER.finditer(source):
            number = source.count("\n", 0, match.start()) + 1
            failures.append(f"{path.relative_to(ROOT)}:{number}: {match.group().strip()}")

if failures:
    print("Pipeline readers must consume the full input under pipefail:", file=sys.stderr)
    print("\n".join(failures), file=sys.stderr)
    sys.exit(1)
print("Shell pipeline readers consume full input")

#!/usr/bin/env python3
"""Reject early-exit pipeline readers in shell scripts and generated shell."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parent.parent
EARLY_READER = re.compile(
    r"(?<!\|)\|(?!\|)\s*(?:(?:grep|rg)\s+(?:-[A-Za-z]+\s+)*"
    r"(?:-[A-Za-z]*[qm][A-Za-z]*\d*\b|--(?:quiet|max-count)\b)|head\s)"
)
failures = []
for directory in (ROOT / "scripts", ROOT / ".githooks"):
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.suffix not in (".sh", ".mjs", ""):
            continue
        source = path.read_text()
        # Sourced shell files inherit pipefail from their caller.
        if path.suffix == ".mjs" and "pipefail" not in source:
            continue
        for number, line in enumerate(source.splitlines(), 1):
            if not line.lstrip().startswith("#") and EARLY_READER.search(line):
                failures.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")

if failures:
    print("Pipeline readers must consume the full input under pipefail:", file=sys.stderr)
    print("\n".join(failures), file=sys.stderr)
    sys.exit(1)
print("Shell pipeline readers consume full input")

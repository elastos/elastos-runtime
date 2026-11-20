#!/usr/bin/env python3
"""Check Carrier fork identity and audit the actual product graph as registry crates."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "elastos/vendor/carrier-provenance.json"
LOCKS = ("elastos/Cargo.lock", "capsules/object-provider/Cargo.lock")


def fingerprint(directory):
    files = {}
    for path in sorted(directory.rglob("*")):
        if any(part in {"target", ".git"} for part in path.relative_to(directory).parts):
            continue
        if path.is_symlink():
            raise ValueError("Carrier vendor source contains a link")
        if path.is_file():
            files[path.relative_to(directory).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files


def check(root, manifest):
    for crate in manifest:
        if fingerprint(root / "elastos/vendor" / crate["name"]) != crate["files"]:
            raise ValueError(f"{crate['name']} differs from its reviewed provenance")
    for lock in LOCKS:
        packages = tomllib.loads((root / lock).read_text())["package"]
        for crate in manifest:
            matches = [package for package in packages if package["name"] == crate["name"]]
            if len(matches) != 1 or matches[0]["version"] != crate["version"] or "source" in matches[0]:
                raise ValueError(f"{lock}: Carrier fork drift for {crate['name']}")


def audit_lock(text, manifest):
    """Restore upstream identity only in an audit projection, preserving every dependency."""
    def project(match):
        block = match.group(0)
        package = tomllib.loads(block)["package"][0]
        for crate in manifest:
            if package["name"] == crate["name"]:
                if package["version"] != crate["version"] or "source" in package:
                    raise ValueError("unexpected Carrier fork in audit graph")
                marker = f'version = "{crate["version"]}"'
                block = block.replace(marker, marker + '\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + crate["registry_checksum"] + '"', 1)
        return block
    return re.sub(r'\[\[package\]\][\s\S]*?(?=\n\[\[package\]\]|\Z)', project, text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", action="store_true")
    parser.add_argument("--record-provenance", action="store_true", help="record deliberately reviewed vendor source after formatting")
    parser.add_argument("--db")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    if args.record_provenance:
        for crate in manifest:
            crate["files"] = fingerprint(ROOT / "elastos/vendor" / crate["name"])
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    check(ROOT, manifest)
    if args.audit:
        with tempfile.TemporaryDirectory(prefix="carrier-audit-") as temporary:
            for index, lock in enumerate(LOCKS):
                projected = Path(temporary) / f"{index}.lock"
                projected.write_text(audit_lock((ROOT / lock).read_text(), manifest))
                command = ["cargo-audit", "audit", "--file", str(projected)]
                if args.db:
                    command += ["--db", args.db]
                subprocess.run(command, cwd=ROOT / "elastos", check=True, timeout=300)
    print(f"Carrier vendor provenance: PASS ({len(manifest)} forks, {len(LOCKS)} product graphs)")


if __name__ == "__main__":
    main()

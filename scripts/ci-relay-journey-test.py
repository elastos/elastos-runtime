#!/usr/bin/env python3
"""Validate fixture packaging with the shared source-installation validator.

The byte fixture supplies checksum input only; this test executes no Runtime.
The network journey builds and installs the actual native executables.
"""
from pathlib import Path
import json
import os
import runpy
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = runpy.run_path(str(ROOT / "scripts/ci-relay-journey.py"))
INSTALL = runpy.run_path(str(ROOT / "scripts/install-source-home-runtime.py"))


class FixtureManifestTests(unittest.TestCase):
    def test_runtime_input_preserves_bytes_and_passes_the_single_link_artifact_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            built = root / "cargo-output"
            built.write_bytes(b"checksum fixture only; never executed")
            built.chmod(0o755)
            os.link(built, root / "cargo-deps-twin")
            with self.assertRaises(INSTALL["InstallError"]):
                INSTALL["hash_file"](built, 1024, executable=True, trusted_runtime=True)
            staged = FIXTURE["stage_runtime_input"](built, root / "runtime-input")
            self.assertEqual(staged.stat().st_nlink, 1)
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o700)
            self.assertEqual(staged.read_bytes(), built.read_bytes())
            INSTALL["hash_file"](staged, 1024, executable=True, trusted_runtime=True)

    def test_fixture_contains_only_copied_apps_and_passes_the_shared_source_validator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            data = root / "data"
            (data / "bin").mkdir(parents=True)
            binary = root / "checksum-input"
            binary.write_bytes(b"fixture for hashing only; this is never executed")
            FIXTURE["prepare_assets"](ROOT, data, binary)
            manifest = json.loads((data / "components.json").read_text())
            self.assertEqual(set(manifest["capsules"]), set(FIXTURE["CAPSULES"]))
            INSTALL["validate_source_components"](manifest, "linux-amd64")
            # A stray source capsule from the full catalogue reopens the gap.
            manifest["capsules"]["uninstalled"] = {
                "entrypoint_sha256": "sha256:" + "a" * 64, "sha256": "", "cid": ""}
            manifest["external"]["uninstalled"] = {
                "platforms": {"linux-amd64": {"checksum": "sha256:" + "b" * 64}}}
            with self.assertRaises(INSTALL["InstallError"]):
                INSTALL["validate_source_components"](manifest, "linux-amd64")


if __name__ == "__main__":
    unittest.main()

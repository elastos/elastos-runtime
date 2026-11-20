#!/usr/bin/env python3
import copy
import importlib.util
from pathlib import Path
import tempfile
import tomllib
import unittest

spec = importlib.util.spec_from_file_location("carrier_vendor", Path(__file__).with_name("check-carrier-vendor.py"))
vendor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vendor)


class VendorIdentity(unittest.TestCase):
    def test_audit_projection_keeps_dependencies_and_restores_advisory_identity(self):
        source = 'version = 4\n\n[[package]]\nname = "iroh-relay"\nversion = "1.4.1"\ndependencies = ["bytes"]\n\n[[package]]\nname = "bytes"\nversion = "1.0.0"\n'
        manifest = [{"name": "iroh-relay", "version": "1.4.1", "registry_checksum": "a" * 64}]
        packages = tomllib.loads(vendor.audit_lock(source, manifest))["package"]
        self.assertEqual(packages[0]["dependencies"], ["bytes"])
        self.assertEqual(packages[0]["source"], "registry+https://github.com/rust-lang/crates.io-index")
        self.assertEqual(packages[0]["checksum"], "a" * 64)
        self.assertEqual(packages[1], tomllib.loads(source)["package"][1])

    def test_file_changes_additions_and_removals_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "elastos/vendor/example"
            source.mkdir(parents=True)
            (source / "code.rs").write_text("original")
            manifest = [{"name": "example", "version": "1", "files": vendor.fingerprint(source)}]
            for lock in vendor.LOCKS:
                path = root / lock
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('version = 4\n[[package]]\nname = "example"\nversion = "1"\n')
            vendor.check(root, manifest)
            (source / "code.rs").write_text("changed")
            with self.assertRaises(ValueError): vendor.check(root, manifest)
            (source / "code.rs").write_text("original")
            (source / "extra.rs").write_text("extra")
            with self.assertRaises(ValueError): vendor.check(root, manifest)
            (source / "extra.rs").unlink()
            (source / "code.rs").unlink()
            with self.assertRaises(ValueError): vendor.check(root, manifest)

    def test_registry_fallback_and_extra_version_fail(self):
        manifest = __import__("json").loads(vendor.MANIFEST.read_text())
        vendor.check(vendor.ROOT, manifest)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for crate in manifest:
                (root / "elastos/vendor" / crate["name"]).mkdir(parents=True)
            fixtures = copy.deepcopy(manifest)
            for fixture in fixtures: fixture["files"] = {}
            text = "version = 4\n" + "".join(f'[[package]]\nname = "{c["name"]}"\nversion = "{c["version"]}"\n' for c in fixtures)
            for lock in vendor.LOCKS:
                path = root / lock
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            vendor.check(root, fixtures)
            path.write_text(text + '[[package]]\nname = "iroh-relay"\nversion = "1.5.0"\n')
            with self.assertRaises(ValueError): vendor.check(root, fixtures)
            path.write_text(text.replace('version = "1.4.1"', 'version = "1.4.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"'))
            with self.assertRaises(ValueError): vendor.check(root, fixtures)


if __name__ == "__main__":
    unittest.main()

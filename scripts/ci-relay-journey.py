#!/usr/bin/env python3
"""Install the message journey's source prerequisites into a fresh test Home.

The shared installer and capsule stamper bind the real installed bytes to HEAD.
This reduced fixture proves messaging only; it makes no full-install claim.
"""
import argparse
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile


CAPSULES = ("home", "home-gui", "people", "inbox", "chat-room", "system")


def stage_runtime_input(source, destination):
    # Cargo's uplifted Linux executable has a deps/ hardlink. Match the source
    # installer's private-copy procedure while keeping its single-link gate.
    shutil.copyfile(source, destination)
    destination.chmod(0o700)
    digest = runpy.run_path(str(Path(__file__).with_name("ci-installed-journeys.py")))["digest"]
    assert digest(source) == digest(destination), "Runtime input copy changed its bytes"
    return destination


def prepare_assets(root, data, binary):
    journey = runpy.run_path(str(root / "scripts/ci-installed-journeys.py"))
    names = CAPSULES
    manifest = json.loads((root / "components.json").read_text())
    shutil.copy2(binary, data / "bin/localhost-provider")
    native = manifest["external"]["localhost-provider"]["platforms"]["linux-amd64"]
    native["checksum"] = "sha256:" + journey["digest"](binary)
    native["size"] = binary.stat().st_size
    manifest["capsules"] = {name: entry for name, entry in manifest["capsules"].items() if name in names}
    manifest["profiles"]["source-home"] = {"components": ["localhost-provider", *names]}
    (data / "components.json").write_text(json.dumps(manifest))
    for name in names:
        shutil.copytree(root / "capsules" / name, data / "capsules" / name,
                        ignore=shutil.ignore_patterns("target", "node_modules", ".git", ".DS_Store"))
    capsule_args = [arg for name in names for arg in ("--capsule", name)]
    subprocess.run(["python3", "scripts/stamp-source-home-capsule-metadata.py", "--components", str(data / "components.json"),
                    "--data-dir", str(data), "--root", str(root), "--platform", "linux-amd64",
                    "--managed-state", str(data / "receipts/source-home-capsules.json"), *capsule_args], check=True, timeout=60)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--network-arrangement", choices=("two-nat", "forced-relay", "relay-to-direct"), required=True)
    args = parser.parse_args()
    root = Path.cwd().resolve()
    journey = runpy.run_path(str(root / "scripts/ci-installed-journeys.py"))
    journey["require_disk_space"](root, 4 * 1024 ** 3)
    # Fresh stable storage outside the checkout; no existing Home is consulted.
    work = Path(tempfile.mkdtemp(prefix="carrier-journey-", dir=Path.home()))
    home = work / "source"
    data = home / ".local/share/elastos"
    data.mkdir(parents=True, mode=0o700)
    (data / "bin").mkdir(mode=0o700)
    (data / "receipts").mkdir(mode=0o700)
    try:
        prepare_assets(root, data, root / "elastos/target/release/localhost-provider")
        runtime_input = stage_runtime_input(root / "elastos/target/release/elastos", work / "runtime-input")
        subprocess.run(["python3", "scripts/install-source-home-runtime.py", "--source-root", str(root), "--data-dir", str(data),
                        "--built-runtime", str(runtime_input), "--platform", "linux-amd64"], check=True, timeout=60)
        # All changes to links, routers and packet filters stay inside these
        # namespaces. Their lifetime ends with this one subprocess.
        setup = 'set -eu; mount --make-rprivate /; mount -t tmpfs tmpfs /run; mkdir /run/netns; exec "$@"'
        command = ["unshare", "--user", "--map-root-user", "--mount", "--net", "sh", "-c", setup, "journey",
                   "python3", "scripts/ci-installed-journeys.py", str(home), str(data), str(work / "evidence"),
                   "--two-home-messages", "--network-arrangement", args.network_arrangement]
        result = subprocess.run(command, timeout=660, check=False)
        receipt_path = work / "evidence/installed-journeys.json"
        if receipt_path.exists():
            record = json.loads(receipt_path.read_text())
            print(json.dumps({key: record.get(key) for key in (
                "candidate", "source_tree", "installed_runtime_sha256", "network_arrangement", "results",
                "route_observations", "visible_failure", "delivery_warning_count", "all_carrier_paths_blocked", "promotion_setup", "status", "failure", "browser_failure", "registration_refusals", "process_cleanup", "fixture_removed")}), flush=True)
        if result.returncode:
            raise RuntimeError("real two-NAT installed journey failed")
        print("two-NAT installed message journey: PASS", flush=True)
    finally:
        # The shared removal guard checks parent links and live fixture processes.
        journey["remove_message_fixture"](work)


if __name__ == "__main__":
    main()

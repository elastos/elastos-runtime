#!/usr/bin/env python3
"""Install the message journey's source prerequisites into a fresh test Home.

The shared installer and capsule stamper bind the real installed bytes to HEAD.
This reduced fixture proves messaging only; it makes no full-install claim.
"""
import argparse
import hashlib
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


def require_message_receipt(path):
    if not path.is_file():
        raise RuntimeError("installed message journey has no receipt")
    with path.open("rb") as stream:
        encoded = stream.read(1024 * 1024 + 1)
    if len(encoded) > 1024 * 1024:
        raise RuntimeError("installed message receipt exceeds its bound")
    return json.loads(encoded)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--network-arrangement", choices=("same-host", "two-nat", "forced-relay", "relay-to-direct"), default="two-nat")
    parser.add_argument("--matrix", action="store_true")
    parser.add_argument("--evidence-dir", type=Path)
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
        # One disposable signed-build input pair serves the complete matrix.
        # Runtime receives neither a client URL nor a client pin in its environment.
        certificate, key = work / "relay.crt", work / "relay.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", str(key),
            "-out", str(certificate), "-days", "1", "-subj", "/CN=carrier-release-fixture", "-addext", "subjectAltName=IP:203.0.113.1"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=20)
        key.chmod(0o600)
        der = subprocess.run(["openssl", "x509", "-in", str(certificate), "-outform", "DER"], check=True, capture_output=True, timeout=10).stdout
        origin = "https://203.0.113.1:4433/"
        build_environment = dict(os.environ, ELASTOS_RELEASE_RELAY_URL=origin,
                                 ELASTOS_RELEASE_RELAY_CERT_SHA256=hashlib.sha256(der).hexdigest())
        subprocess.run(["cargo", "build", "--locked", "--release", "-p", "elastos-server", "-p", "localhost-provider"],
                       cwd=root / "elastos", env=build_environment, check=True, timeout=1800)
        target = Path(os.environ.get("CARGO_TARGET_DIR", str(root / "elastos/target")))
        if not target.is_absolute():
            target = root / "elastos" / target
        prepare_assets(root, data, target / "release/localhost-provider")
        runtime_input = stage_runtime_input(target / "release/elastos", work / "runtime-input")
        subprocess.run(["python3", "scripts/install-source-home-runtime.py", "--source-root", str(root), "--data-dir", str(data),
                        "--built-runtime", str(runtime_input), "--platform", "linux-amd64"], check=True, timeout=60)
        fixture_environment = dict(os.environ, ELASTOS_RELAY_FIXTURE_RELEASE="1", ELASTOS_RELAY_FIXTURE_URL=origin,
                                   ELASTOS_RELAY_FIXTURE_CERT=str(certificate), ELASTOS_RELAY_FIXTURE_KEY=str(key))
        setup = 'set -eu; mount --make-rprivate /; mount -t tmpfs tmpfs /run; mkdir /run/netns; ip link set lo up; exec "$@"'
        arrangements = ("two-nat", "forced-relay", "relay-to-direct", "same-host") if args.matrix else (args.network_arrangement,)
        for arrangement in arrangements:
            evidence = work / ("evidence-" + arrangement)
            command = ["unshare", "--user", "--map-root-user", "--mount", "--net", "sh", "-c", setup, "journey",
                       "python3", "scripts/ci-installed-journeys.py", str(home), str(data), str(evidence),
                       "--two-home-messages", "--network-arrangement", arrangement]
            result = subprocess.run(command, env=fixture_environment, timeout=1020, check=False)
            receipt_path = evidence / "installed-journeys.json"
            if result.returncode == 0 or receipt_path.exists():
                record = require_message_receipt(receipt_path)
                print(json.dumps({key: record.get(key) for key in (
                    "candidate", "source_tree", "installed_runtime_sha256", "network_arrangement", "relay_selection", "results",
                    "route_observations", "meeting_point", "discovery_packets", "automatic_direct", "transitions", "visible_failure",
                    "delivery_warning_count", "all_carrier_paths_blocked", "promotion_setup", "status", "failure", "browser_failure",
                    "registration_refusals", "process_cleanup", "fixture_removed")}), flush=True)
                if result.returncode == 0:
                    assert journey["two_home_receipt_valid"](record, journey["installed_message_identity"](data), arrangement), "installed relay receipt failed its complete acceptance guard"
                    if arrangement != "same-host":
                        assert record["relay_selection"] == "compiled_release_default"
            if result.returncode:
                raise RuntimeError("installed message journey failed: " + arrangement)
            if args.evidence_dir:
                destination = args.evidence_dir.resolve() / arrangement
                destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                for name in ("installed-journeys.json", "two-home-ui.json", "direct-unconfirmed-desktop.png", "direct-unconfirmed-phone.png"):
                    if (evidence / name).is_file():
                        shutil.copy2(evidence / name, destination / name)
            print("installed message journey: PASS " + arrangement, flush=True)
    finally:
        # The shared removal guard checks parent links and live fixture processes.
        journey["remove_message_fixture"](work)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Community link across Runtime versions: a node and Homes built from different trees.

Homes and the Community node update at different times, so a release must
hold for every pairing. Each arrangement starts one Community node and two
Homes from the named builds, joins them to one Community, then restarts the
node and brings up a fresh Home against it.

The fixture needs only the Runtime and the localhost provider, so it runs on a
machine without the media tools that the full source Home installs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
JOURNEY = runpy.run_path(str(ROOT / "scripts/ci-installed-journeys.py"))
free_port = JOURNEY["free_port"]
wait_healthy = JOURNEY["wait_healthy"]
cleanup_runtime = JOURNEY["cleanup_runtime"]
digest = JOURNEY["digest"]

STAGED_PROVIDERS = ("localhost-provider",)
JOIN_LINE = "carrier: gossip_join"
DEAD_LINE = "Community link looks dead"
REBUILD_LINE = "rebuilding Carrier gossip"
#: A joined Home repairs after one silence window, so a pass must outlast it.
DEFAULT_SETTLE_SECONDS = 90


def platform_key():
    machine = {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine)
    if sys.platform != "linux" or machine is None:
        raise RuntimeError("the mixed-version journey runs on Linux amd64 or arm64")
    return f"linux-{machine}"


class Build:
    """One Runtime tree: its source checkout and its own release target dir."""

    def __init__(self, name, source, target):
        self.name = name
        self.source = Path(source).resolve()
        self.target = Path(target).resolve()
        self.runtime = self.target / "release/elastos"
        self.manifest = self.source / "components.json"
        for path in (self.runtime, self.manifest):
            if not path.exists():
                raise RuntimeError(f"build {name} has no {path.name}: build it first")
        self.runtime_sha256 = digest(self.runtime)

    def provider(self, provider):
        return self.target / "release" / provider


def stage_home(build, root, carrier_address):
    """One disposable data root that the Runtime's own checksum check accepts."""
    data = root / ".local/share/elastos"
    (data / "bin").mkdir(mode=0o700, parents=True)
    # The shared process census owns a Runtime by its data-root path, so each
    # Home runs its own copy of the binary from its own bin directory.
    runtime = data / "bin/elastos"
    shutil.copy2(build.runtime, runtime)
    runtime.chmod(0o700)
    manifest = json.loads(build.manifest.read_text())
    for provider in STAGED_PROVIDERS:
        staged = data / "bin" / provider
        shutil.copy2(build.provider(provider), staged)
        staged.chmod(0o700)
        blob = staged.read_bytes()
        entry = manifest["external"][provider]["platforms"][platform_key()]
        entry["install_path"] = f"bin/{provider}"
        entry["checksum"] = "sha256:" + hashlib.sha256(blob).hexdigest()
        entry["size"] = len(blob)
    (data / "components.json").write_text(json.dumps(manifest, indent=2))
    (data / "config.toml").write_text(
        f'dev_mode = true\ntrusted_keys = []\ncarrier_bind_addr = "{carrier_address}"\n'
    )
    return data


class Home:
    """One Runtime process with its own Home, data root and log."""

    def __init__(self, name, build, root, bind_host):
        self.name = name
        self.build = build
        self.root = root
        self.log = root / "runtime.private.log"
        self.carrier_address = f"{bind_host}:{free_port(socket.SOCK_DGRAM)}"
        self.api_address = f"{bind_host}:{free_port()}"
        self.data = stage_home(build, root, self.carrier_address)
        self.runtime = self.data / "bin/elastos"
        self.child = None

    def environment(self):
        return {
            "PATH": os.environ["PATH"],
            "HOME": str(self.root),
            "XDG_DATA_HOME": str(self.data.parent),
            "ELASTOS_QUIET_RUNTIME_NOTICES": "1",
        }

    def start(self):
        assert self.child is None, "Home already has a Runtime"
        with self.log.open("ab") as log:
            self.child = subprocess.Popen(
                [str(self.runtime), "gateway", "--addr", self.api_address],
                env=self.environment(),
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
        wait_healthy(self.child, self.api_address, f"mixed-version {self.name}")

    def stop(self):
        if self.child is None:
            return {"status": "passed", "after": {}}
        row = cleanup_runtime(self.child, self.data)
        self.child = None
        return row

    def configure(self, *arguments):
        with (self.root / "configuration.private.log").open("ab") as log:
            subprocess.run(
                [str(self.runtime), "collaboration-config", *map(str, arguments)],
                env=self.environment(),
                stdout=log,
                stderr=log,
                check=True,
                timeout=120,
            )

    def lines(self, needle):
        if not self.log.exists():
            return []
        text = self.log.read_text(errors="replace")
        return [line for line in text.splitlines() if needle in line]


def observe(home, started):
    """What an operator reads off one Home after the settle window."""
    return {
        "home": home.name,
        "build": home.build.name,
        "joined": bool(home.lines(JOIN_LINE)),
        "link_dead": len(home.lines(DEAD_LINE)),
        "gossip_rebuilds": len(home.lines(REBUILD_LINE)),
        "seconds": round(time.monotonic() - started),
    }


def run_arrangement(node_build, home_build, root, bind_host, settle):
    """One node version against one Home version, with a fresh join after restart."""
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    homes, record = {}, {
        "node_build": node_build.name,
        "home_build": home_build.name,
        "node_runtime_sha256": node_build.runtime_sha256,
        "home_runtime_sha256": home_build.runtime_sha256,
        "observations": [],
        "process_cleanup": [],
    }
    try:
        for name, build in (("community", node_build), ("a", home_build), ("b", home_build)):
            homes[name] = Home(name, build, root / name, bind_host)
        node = homes["community"]
        node.start()
        node.configure("create-authority-key", "--key", root / "authority.key")
        node.configure(
            "export-local-bootstrap-receipt",
            "--data-root", node.data,
            "--runtime-kind", "gateway",
            "--output", root / "bootstrap.json",
        )
        node.configure(
            "generate-initial",
            "--authority-key", root / "authority.key",
            "--network-id", "ci.gossip-mixed",
            "--conversation-id", "community",
            "--bootstrap-peer", root / "bootstrap.json",
            "--output", root / "network.json",
        )
        node.configure("verify", "--input", root / "network.json")
        record["process_cleanup"].append(node.stop())

        def admit(home):
            target = home.data / "collaboration-network-v1.json"
            shutil.copy2(root / "network.json", target)
            target.chmod(0o600)

        for home in homes.values():
            admit(home)
        started = time.monotonic()
        for home in homes.values():
            home.start()
        time.sleep(settle)
        record["observations"] += [observe(homes[name], started) for name in ("a", "b")]

        # The node restarts, as an updated node does; the Homes keep running.
        record["process_cleanup"].append(homes["community"].stop())
        homes["community"].start()
        fresh = Home("c", home_build, root / "c", bind_host)
        homes["c"] = fresh
        admit(fresh)
        fresh_started = time.monotonic()
        fresh.start()
        time.sleep(settle)
        record["observations"].append(observe(fresh, fresh_started))
        record["observations"] += [observe(homes[name], started) for name in ("a", "b")]
        record["status"] = (
            "passed"
            if all(row["joined"] and row["link_dead"] == 0 for row in record["observations"])
            else "failed"
        )
    except Exception as error:
        record["status"] = "failed"
        record["failure"] = f"{type(error).__name__}: {error}"[:300]
    finally:
        for home in homes.values():
            try:
                record["process_cleanup"].append(home.stop())
            except Exception as error:  # a stuck cleanup still leaves a result
                record["process_cleanup"].append(
                    {"status": "failed", "error": f"{type(error).__name__}: {error}"[:200]}
                )
        if record.get("status") != "passed":
            # The fixture tree goes away, so a failure keeps its own last words.
            record["log_tails"] = {
                home.name: home.lines("")[-12:] for home in homes.values()
            }
        shutil.rmtree(root, ignore_errors=True)
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--released-source", type=Path, required=True)
    parser.add_argument("--released-target", type=Path, required=True)
    parser.add_argument("--develop-source", type=Path, required=True)
    parser.add_argument("--develop-target", type=Path, required=True)
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--bind-host", default="127.0.0.1")
    parser.add_argument("--settle-seconds", type=int, default=DEFAULT_SETTLE_SECONDS)
    parser.add_argument("--receipt", type=Path)
    arguments = parser.parse_args()
    builds = {
        "released": Build("released", arguments.released_source, arguments.released_target),
        "develop": Build("develop", arguments.develop_source, arguments.develop_target),
    }
    receipt = {"platform": platform_key(), "arrangements": []}
    for node in ("released", "develop"):
        for home in ("released", "develop"):
            root = arguments.fixture_root / f"node-{node}-homes-{home}"
            receipt["arrangements"].append(
                run_arrangement(
                    builds[node], builds[home], root,
                    arguments.bind_host, arguments.settle_seconds,
                )
            )
    receipt["status"] = (
        "passed"
        if all(row["status"] == "passed" for row in receipt["arrangements"])
        else "failed"
    )
    if arguments.receipt:
        arguments.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    for row in receipt["arrangements"]:
        print(f"node={row['node_build']:<9} homes={row['home_build']:<9} {row['status']}"
              + (f"  {row['failure']}" if "failure" in row else ""))
        for name, tail in row.get("log_tails", {}).items():
            for line in tail:
                print(f"  [{name}] {line[:200]}")
        for observation in row["observations"]:
            print(
                f"  {observation['home']} joined={observation['joined']} "
                f"link_dead={observation['link_dead']} "
                f"rebuilds={observation['gossip_rebuilds']} "
                f"after={observation['seconds']}s"
            )
    print("mixed-version status:", receipt["status"])
    raise SystemExit(0 if receipt["status"] == "passed" else 1)


if __name__ == "__main__":
    main()

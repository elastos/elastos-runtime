#!/usr/bin/env python3
"""Exercise the real system resolver in an owned, disconnected Linux namespace.

Argument: the elastos-server lib test executable for the candidate. The negative
control proves that the packet counters detect the upstream public fallback.
"""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile


def command(*args):
    return subprocess.run(list(args), check=True, text=True, capture_output=True, timeout=30).stdout


def counters(tool, chain):
    return sum(int(line.split()[0]) for line in command(tool, "-nvxL", chain).splitlines()
               if line.split() and line.split()[0].isdigit())


def inside(binary, root):
    command("mount", "--make-rprivate", "/")
    command("mount", "--bind", str(root / "resolv.conf"), "/etc/resolv.conf")
    command("ip", "link", "set", "lo", "up")
    command("ip", "link", "add", "dns-trap", "type", "dummy")
    command("ip", "addr", "add", "203.0.113.2/24", "dev", "dns-trap")
    command("ip", "link", "set", "dns-trap", "up")
    command("ip", "route", "add", "default", "dev", "dns-trap")
    command("ip", "-6", "addr", "add", "2001:db8::2/64", "dev", "dns-trap", "nodad")
    command("ip", "-6", "route", "add", "default", "dev", "dns-trap")
    for tool, loopback in (("iptables", "127.0.0.0/8"), ("ip6tables", "::1/128")):
        for chain in ("DNS_SYSTEM_QUERY", "DNS_PUBLIC_QUERY"):
            command(tool, "-N", chain)
            command(tool, "-A", chain, "-j", "DROP")
        for protocol in ("udp", "tcp"):
            command(tool, "-A", "OUTPUT", "-d", loopback, "-p", protocol, "--dport", "53", "-j", "DNS_SYSTEM_QUERY")
            command(tool, "-A", "OUTPUT", "!", "-d", loopback, "-p", protocol, "-j", "DNS_PUBLIC_QUERY")
    results = {}
    for name in ("public_fallback_control", "system_only"):
        for tool in ("iptables", "ip6tables"):
            command(tool, "-Z", "DNS_SYSTEM_QUERY")
            command(tool, "-Z", "DNS_PUBLIC_QUERY")
        environment = {**os.environ, "ELASTOS_DNS_ISOLATED_PROBE": "1"}
        subprocess.run([str(binary), "--exact", "carrier::relay::tests::dns_probe_" + name,
                        "--ignored", "--nocapture", "--test-threads=1"], check=True, timeout=25, env=environment)
        results[name] = {chain: sum(counters(tool, chain) for tool in ("iptables", "ip6tables"))
                         for chain in ("DNS_SYSTEM_QUERY", "DNS_PUBLIC_QUERY")}
    assert results["public_fallback_control"]["DNS_PUBLIC_QUERY"] > 0, "trap must detect the public-fallback control"
    assert results["system_only"]["DNS_SYSTEM_QUERY"] > 0, "system DNS was actually attempted"
    assert results["system_only"]["DNS_PUBLIC_QUERY"] == 0, "production resolver attempted a public query"
    print("Blocked system DNS policy: PASS " + json.dumps(results), flush=True)


def main():
    if sys.argv[1:2] == ["--inside"]:
        inside(Path(sys.argv[2]), Path(sys.argv[3]))
        return
    if len(sys.argv) != 2 or sys.platform != "linux":
        raise SystemExit("usage: carrier-dns-policy-test.py ELASTOS_SERVER_LIB_TEST_EXECUTABLE (Linux)")
    binary = Path(sys.argv[1]).resolve(strict=True)
    journey = runpy.run_path(str(Path(__file__).with_name("ci-installed-journeys.py")))
    journey["require_disk_space"](Path.home(), 1024 * 1024)
    root = Path(tempfile.mkdtemp(prefix="carrier-dns-", dir=Path.home())).resolve()
    try:
        (root / "resolv.conf").write_text("nameserver 127.0.0.1\noptions timeout:1 attempts:1\n")
        subprocess.run(["unshare", "--user", "--map-root-user", "--mount", "--net", sys.executable,
                        str(Path(__file__).resolve()), "--inside", str(binary), str(root)], check=True, timeout=90)
    finally:
        journey["remove_message_fixture"](root)


if __name__ == "__main__":
    main()

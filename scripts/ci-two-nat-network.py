#!/usr/bin/env python3
"""Linux namespace setup for the existing installed two-Home assertions.

Run in a fresh user/mount/network namespace. All network changes belong to that
namespace. Browsers and HTTP management run inside their Home's namespace;
only Carrier crosses the MASQUERADE routers. The fixture owns the namespaces.
"""
import os
from pathlib import Path
import json
import secrets
import subprocess
import sys
import urllib.request


def command(*args):
    return subprocess.run(list(args), check=True, timeout=15, stdout=subprocess.DEVNULL,
                          stderr=subprocess.PIPE)


class MessageNetwork:
    def __init__(self, arrangement):
        if arrangement not in ("two-nat", "forced-relay", "relay-to-direct") or os.geteuid() != 0:
            raise RuntimeError("two-NAT journey requires an isolated Linux user/network namespace")
        self.names = {name: "carrier-" + secrets.token_hex(4) for name in ("nat-a", "nat-b", "a", "b")}
        self.created = []
        self.home_ips = {"community": "203.0.113.1", "a": "10.0.1.2", "b": "10.0.2.2"}
        self.router_ips = {"a": "203.0.113.11", "b": "203.0.113.12"}
        try:
            command("ip", "link", "set", "lo", "up")
            command("iptables", "-N", "carrier-qad")
            command("iptables", "-A", "INPUT", "-p", "udp", "--dport", "7842", "-j", "carrier-qad")
            for address in self.router_ips.values():
                command("iptables", "-A", "carrier-qad", "-s", address, "-j", "ACCEPT")
            command("ip", "link", "add", "wan", "type", "bridge")
            command("ip", "addr", "add", "203.0.113.1/24", "dev", "wan")
            command("ip", "link", "set", "wan", "up")
            for name, namespace in self.names.items():
                command("ip", "netns", "add", namespace)
                self.created.append(namespace)
                self.run(name, "ip", "link", "set", "lo", "up")
            for index, side in enumerate(("a", "b"), 1):
                nat = "nat-" + side
                command("ip", "link", "add", "wan-" + side, "type", "veth", "peer", "name", "wan0", "netns", self.names[nat])
                command("ip", "link", "set", "wan-" + side, "master", "wan", "up")
                self.run(nat, "ip", "addr", "add", self.router_ips[side] + "/24", "dev", "wan0")
                self.run(nat, "ip", "link", "set", "wan0", "up")
                command("ip", "link", "add", "lan", "netns", self.names[nat], "type", "veth", "peer", "name", "eth0", "netns", self.names[side])
                self.run(nat, "ip", "addr", "add", f"10.0.{index}.1/24", "dev", "lan")
                self.run(nat, "ip", "link", "set", "lan", "up")
                self.run(side, "ip", "addr", "add", self.home_ips[side] + "/24", "dev", "eth0")
                self.run(side, "ip", "link", "set", "eth0", "up")
                self.run(side, "ip", "route", "add", "default", "via", f"10.0.{index}.1")
                self.run(nat, "sysctl", "-qw", "net.ipv4.ip_forward=1")
                self.run(nat, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "wan0", "-j", "MASQUERADE")
                self.run(nat, "iptables", "-P", "FORWARD", "DROP")
                self.run(nat, "iptables", "-P", "INPUT", "DROP")
                self.run(nat, "iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
                if arrangement in ("forced-relay", "relay-to-direct"):
                    self.run(nat, "iptables", "-A", "FORWARD", "-p", "udp", "-j", "DROP")
                self.run(nat, "iptables", "-A", "FORWARD", "-i", "lan", "-o", "wan0", "-j", "ACCEPT")
                self.run(nat, "iptables", "-A", "FORWARD", "-i", "wan0", "-o", "lan", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
                self.run(side, "ping", "-c", "1", "-W", "2", "203.0.113.1")
            for side, other in (("a", "b"), ("b", "a")):
                result = subprocess.run(self.prefix(side) + ["ping", "-c", "1", "-W", "1", self.home_ips[other]],
                                        timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode == 0:
                    raise RuntimeError("Homes have an unintended direct private route")
        except BaseException:
            self.close()
            raise

    def prefix(self, name):
        return [] if name == "community" else ["ip", "netns", "exec", self.names[name]]

    def run(self, name, *args):
        return command(*self.prefix(name), *args)

    def block_paths(self, blocked):
        # This rule affects Carrier across the owned NAT only. The browser and
        # gateway share loopback and stay available throughout the failure.
        for side in ("a", "b"):
            self.run("nat-" + side, "iptables", "-I" if blocked else "-D", "FORWARD",
                     *( ["1"] if blocked else [] ), "-j", "DROP")

    def discovery_packets(self):
        output = subprocess.run(["iptables", "-nvxL", "carrier-qad"], check=True, capture_output=True, text=True, timeout=15).stdout
        return sum(int(parts[0]) for line in output.splitlines() if (parts := line.split()) and parts[0].isdigit())

    def blocked_packets(self):
        packets = 0
        for side in ("a", "b"):
            output = subprocess.run([*self.prefix("nat-" + side), "iptables", "-nvxL", "FORWARD"],
                check=True, capture_output=True, text=True, timeout=15).stdout
            rows = [line.split() for line in output.splitlines() if line.split() and line.split()[0].isdigit()]
            assert rows and rows[0][2] == "DROP", "the owned block must be first"
            packets += int(rows[0][0])
        return packets

    def promote(self, fixtures):
        # Simulate a router opening a public UDP mapping after relay fallback.
        # Carrier receives operator-owned route hints; the apps still use DIDs.
        for side in ("a", "b"):
            port = fixtures[side][3].rsplit(":", 1)[1]
            nat = "nat-" + side
            self.run(nat, "iptables", "-D", "FORWARD", "-p", "udp", "-j", "DROP")
            self.run(nat, "iptables", "-I", "FORWARD", "1", "-p", "udp", "-d", self.home_ips[side],
                     "--dport", port, "-j", "ACCEPT")
            self.run(nat, "iptables", "-t", "nat", "-A", "PREROUTING", "-i", "wan0", "-p", "udp",
                     "--dport", port, "-j", "DNAT", "--to-destination", fixtures[side][3])
            self.run(nat, "iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-o", "wan0", "-p", "udp",
                     "-s", self.home_ips[side], "--sport", port, "-j", "SNAT",
                     "--to-source", self.router_ips[side] + ":" + port)

    def http_json(self, name, url, body=None, token=None, health=False):
        # Secret input stays on stdin. The HTTP socket belongs to this Home's
        # network namespace, like the browser's socket, with no TCP forwards.
        value = {"url": url, "body": body, "token": token, "health": health}
        result = subprocess.run([*self.prefix(name), sys.executable, str(Path(__file__).resolve()), "--http"],
                                input=json.dumps(value), capture_output=True, text=True, check=True,
                                timeout=3 if health else 65)
        return json.loads(result.stdout)

    def close(self):
        for namespace in reversed(self.created):
            command("ip", "netns", "delete", namespace)
        self.created.clear()


def namespace_http():
    encoded = sys.stdin.buffer.read(65537)
    if len(encoded) > 65536:
        raise RuntimeError("fixture HTTP input exceeds its bound")
    value = json.loads(encoded)
    headers = {"Content-Type": "application/json"}
    if value["token"]:
        headers["Authorization"] = "Bearer " + value["token"]
    body = json.dumps(value["body"]).encode() if value["body"] is not None else None
    request = urllib.request.Request(value["url"], body, headers)
    with urllib.request.urlopen(request, timeout=1 if value["health"] else 60) as response:
        encoded = response.read(1024 * 1024 + 1)
        if len(encoded) > 1024 * 1024:
            raise RuntimeError("fixture HTTP response exceeds its bound")
        print(json.dumps(response.status if value["health"] else json.loads(encoded)))


if __name__ == "__main__":
    if sys.argv[1:] != ["--http"]:
        raise SystemExit("fixture helper expects --http")
    namespace_http()

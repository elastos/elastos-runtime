#!/usr/bin/env python3
"""Linux namespace setup for the existing installed two-Home assertions.

Run in a fresh user/mount/network namespace. All network changes belong to that
namespace. HTTP management crosses explicit TCP forwards; Carrier UDP crosses
two independent MASQUERADE routers. The fixture owns every process and namespace.
"""
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import time
import urllib.parse


def command(*args):
    return subprocess.run(list(args), check=True, timeout=15, stdout=subprocess.DEVNULL,
                          stderr=subprocess.PIPE)


class MessageNetwork:
    def __init__(self, arrangement):
        if arrangement not in ("two-nat", "forced-relay") or os.geteuid() != 0:
            raise RuntimeError("two-NAT journey requires an isolated Linux user/network namespace")
        self.names = {name: "carrier-" + secrets.token_hex(4) for name in ("nat-a", "nat-b", "a", "b")}
        self.created = []
        self.proxies = []
        self.home_ips = {"community": "203.0.113.1", "a": "10.0.1.2", "b": "10.0.2.2"}
        self.router_ips = {"a": "203.0.113.11", "b": "203.0.113.12"}
        try:
            command("ip", "link", "set", "lo", "up")
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
                if arrangement == "forced-relay":
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

    def free_port(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]

    def proxy(self, prefix, listen_host, port, target_host, target_port):
        child = subprocess.Popen(prefix + ["socat", f"TCP-LISTEN:{port},bind={listen_host},reuseaddr,fork",
                                           f"TCP:{target_host}:{target_port}"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.proxies.append(child)
        time.sleep(.05)
        if child.poll() is not None:
            raise RuntimeError("namespace HTTP management proxy failed")

    def forward(self, side, port, loopback=False):
        if side == "community":
            return port
        home_port = port
        if loopback:
            home_port = self.free_port()
            self.proxy(self.prefix(side), self.home_ips[side], home_port, "127.0.0.1", port)
        nat = "nat-" + side
        self.run(nat, "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", str(home_port),
                 "-j", "DNAT", "--to-destination", f"{self.home_ips[side]}:{home_port}")
        self.run(nat, "iptables", "-I", "FORWARD", "-p", "tcp", "--dport", str(home_port),
                 "-d", self.home_ips[side], "-j", "ACCEPT")
        public_port = self.free_port() if loopback else port
        self.proxy([], "127.0.0.1", public_port, self.router_ips[side], home_port)
        return public_port

    def api_url(self, side, api):
        parsed = urllib.parse.urlsplit(api)
        return f"http://127.0.0.1:{self.forward(side, parsed.port, loopback=True)}"

    def close(self):
        for child in reversed(self.proxies):
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=3)
        self.proxies.clear()
        for namespace in reversed(self.created):
            command("ip", "netns", "delete", namespace)
        self.created.clear()

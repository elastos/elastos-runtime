#!/usr/bin/env python3
"""Community link across Runtime versions: a node and Homes installed from different trees.

Homes and the Community node update at different times, so a release must
hold for every pairing. Each arrangement runs the installed two-Home journey
with one build as the Community node and one build as the Homes. That journey
owns the transitions, their evidence and the clean-up; this driver chooses the
builds and keeps one receipt for the four arrangements.
"""
import argparse
import json
from pathlib import Path
import runpy

JOURNEY = runpy.run_path(str(Path(__file__).with_name("ci-installed-journeys.py")))
BUILDS = ("released", "candidate")
ARRANGEMENTS = [(node, homes) for node in BUILDS for homes in BUILDS]


def run_arrangement(node, homes, evidence, fixture_root):
    """One node build against one Home build; the journey's own receipt decides the verdict."""
    row = {"node": {"build": node.name, **node.identity}, "homes": {"build": homes.name, **homes.identity}}
    try:
        JOURNEY["two_home_messages"](homes, evidence, fixture_root=fixture_root, node_build=node)
    # A deadline ends one arrangement; SIGTERM and Ctrl-C end the run.
    except (Exception, JOURNEY["MessageDeadline"]) as error:
        row["failure"] = JOURNEY["observer_failure"](
            "two_home_messages", error, [str(fixture_root), str(node.home), str(homes.home)])
    receipt = evidence / "installed-journeys.json"
    row["journey"] = json.loads(receipt.read_text()) if receipt.exists() else {}
    row["status"] = "passed" if "failure" not in row and JOURNEY["two_home_receipt_valid"](
        row["journey"], homes.identity, node_identity=node.identity) else "failed"
    return row


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for build in BUILDS:
        parser.add_argument(f"--{build}-home", type=Path, required=True,
                            help=f"isolated HOME of the installed {build} source Home")
        parser.add_argument(f"--{build}-data", type=Path, required=True, help="its elastos data root")
        parser.add_argument(f"--{build}-repo", type=Path, required=True, help="the checkout it was installed from")
    parser.add_argument("--evidence", type=Path, required=True, help="fresh directory for receipts and screenshots")
    parser.add_argument("--fixture-root", type=Path, required=True, help="fresh disposable fixture path")
    arguments = parser.parse_args(argv)
    builds = {build: JOURNEY["installed_build"](build, *(getattr(arguments, f"{build}_{part}")
                                                       for part in ("home", "data", "repo"))) for build in BUILDS}
    evidence, fixture_root = arguments.evidence.resolve(), arguments.fixture_root.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    fixture_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    receipt = {"arrangements": []}
    try:
        with JOURNEY["message_termination"]():
            for node, homes in ARRANGEMENTS:
                name = f"node-{node}-homes-{homes}"
                receipt["arrangements"].append({"arrangement": name, **run_arrangement(
                    builds[node], builds[homes], evidence / name, fixture_root / name)})
    finally:
        # rmdir refuses a directory that still holds a fixture, so a leftover fails the run.
        try:
            fixture_root.rmdir()
            receipt["fixture_root_removed"] = True
        except OSError:
            receipt["fixture_root_removed"] = False
        receipt["status"] = "passed" if (
            receipt["fixture_root_removed"] and len(receipt["arrangements"]) == len(ARRANGEMENTS)
            and all(row["status"] == "passed" for row in receipt["arrangements"])) else "failed"
        (evidence / "mixed-version-journey.json").write_text(json.dumps(receipt, indent=2) + "\n")
    for row in receipt["arrangements"]:
        failure = row.get("failure") or row["journey"].get("failure") or {}
        print(f"{row['arrangement']}: {row['status']}" + (f"  {failure['message']}" if failure else ""))
        for name, transition in row["journey"].get("transitions", {}).items():
            homes = ", ".join(f"{home}={'carrier' if state['carrier_ticket_length'] else 'silent'}"
                              for home, state in transition.get("homes", {}).items())
            print(f"  {name}: {homes}; Community posts read {len(transition.get('community', []))}; "
                  f"direct {'read' if 'direct' in transition else 'missing'}")
    print("mixed-version status:", receipt["status"])
    raise SystemExit(0 if receipt["status"] == "passed" else 1)


if __name__ == "__main__":
    main()

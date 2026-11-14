#!/usr/bin/env bash
set -euo pipefail
umask 022
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Linux ]] || { echo "two-NAT journey needs Linux" >&2; exit 1; }
for tool in ip iptables ping unshare mount node python3; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done
python3 - <<'PY'
import os
s = os.statvfs('.')
assert s.f_bavail * s.f_frsize >= 12 * 1024 ** 3, 'build needs 10 GiB plus 2 GiB reserve'
PY
(cd elastos && cargo build --locked --release -p elastos-server -p localhost-provider)
scripts/test-behaviour.sh inputs
export NODE_PATH="${BEHAVIOUR_INPUTS:-${HOME}/.cache/elastos-runtime/behaviour}/browser/node_modules"
export BROWSER_OPERATOR_PLAYWRIGHT_CORE="${BEHAVIOUR_INPUTS:-${HOME}/.cache/elastos-runtime/behaviour}/core/node_modules/playwright-core"
python3 scripts/ci-relay-journey.py --network-arrangement "${1:-two-nat}"

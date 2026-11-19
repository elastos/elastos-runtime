#!/usr/bin/env bash
# The one behaviour suite: CI test-behaviour, `just test-behaviour` and the
# local pre-push gate all run this file.
#   test-behaviour.sh inputs  installs the pinned Browser and wallet test inputs (network)
#   test-behaviour.sh         runs the suite offline; the spec reporter ends
#                             with the failing tests by name
# The completion supervisor prints "Node test guard:" messages for missing
# results, early exits and timeouts, with the file and first unfinished test.
# Its closing PASS means exit 0: every file completed and every test reported.
# Its closing FAIL means exit 1: a test failed or completion was incomplete.
# Plain smokes finish naturally; use process.exitCode instead of process.exit.
# Each file also has a fixed 20-minute upper limit, unaffected by output.
# Slowest measured file: release-publish.test.mjs, 577.5s of sequential tests.
# The full Mac run's 628.1s bounds its elapsed time; 1200s gives >=91% headroom.
# Both platforms use this cap; short --timeout fixture budgets scale it down.
set -euo pipefail
cd "$(dirname "$0")/.."

inputs="${BEHAVIOUR_INPUTS:-${RUNNER_TEMP:-${HOME}/.cache/elastos-runtime}/behaviour}"
browser="${inputs}/browser" core="${inputs}/core" walletconnect="${inputs}/walletconnect"
installed() { # prefix package version
  [ "$(node -p "try { require('$1/node_modules/$2/package.json').version } catch { '' }")" = "$3" ]
}

if [ "${1:-}" = inputs ]; then
  installed "$browser" playwright 1.60.0 ||
    npm install --prefix "$browser" --no-save --package-lock=false playwright@1.60.0
  if ! installed "$core" playwright-core 1.59.1 || ! installed "$core" node 24.21.0; then
    npm install --prefix "$core" --no-save --package-lock=false playwright-core@1.59.1 node@24.21.0
  fi
  # The scripted wallet uses the same locked graph as the shipped adapter.
  if ! installed "$walletconnect" @walletconnect/sign-client 2.23.9 ||
      ! cmp -s scripts/walletconnect/package-lock.json "$walletconnect/package-lock.json"; then
    mkdir -p "$walletconnect"
    cp scripts/walletconnect/package.json scripts/walletconnect/package-lock.json "$walletconnect/"
    npm ci --prefix "$walletconnect" --ignore-scripts --no-audit --no-fund
  fi
  # Tests use both SDK pins; keep both browser builds in the shared cache.
  # The 1.60 pin installs the headless shell. Default headless launches use it.
  # The core pin installs full Chromium. Product smokes click through that binary.
  # The same install keeps the matching headless shell. Launches that do not
  # name an executable use that shell.
  export PLAYWRIGHT_SKIP_BROWSER_GC=1
  # --with-deps installs Linux system libraries and needs root; CI only.
  "${browser}/node_modules/.bin/playwright" install chromium --only-shell ${CI:+--with-deps}
  # The 1.59.1 installer stalls extracting Chromium under Node 26.
  "${core}/node_modules/node/bin/node" "${core}/node_modules/playwright-core/cli.js" install chromium
  exit 0
fi

if ! installed "$browser" playwright 1.60.0 || ! installed "$core" playwright-core 1.59.1; then
  echo "Browser test inputs are missing: run \`just test-behaviour-inputs\` first." >&2
  exit 1
fi
export NODE_PATH="${browser}/node_modules"
export BROWSER_OPERATOR_PLAYWRIGHT_CORE="${core}/node_modules/playwright-core"
exec node scripts/run-node-tests.mjs elastos/esp/projections.test.mjs scripts/*.test.mjs scripts/build/*.test.mjs scripts/lib/*.test.mjs capsules/*/browser/*.test.mjs capsules/*/browser/src/*.test.mjs scripts/home-fixture-contracts-smoke.mjs scripts/documents-save-conflict-smoke.mjs scripts/gba-save-conflict-smoke.mjs scripts/assistant-shell-smoke.mjs scripts/model-preparation-failure-smoke.mjs scripts/model-management-browser-smoke.mjs scripts/assistant-message-copy-browser-smoke.mjs scripts/assistant-reply-layout-browser-smoke.mjs scripts/assistant-follow-input-browser-smoke.mjs scripts/home-update-reload-browser-smoke.mjs scripts/browser-text-select-smoke.mjs scripts/wallet-product-layout-smoke.mjs scripts/wallet-connectors-uiux-layout-smoke.mjs scripts/wallet-inbox-account-consent-smoke.mjs scripts/wallet-connector-transaction-smoke.mjs

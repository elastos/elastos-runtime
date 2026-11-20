#!/usr/bin/env bash
set -euo pipefail
# Playwright retains its inherited control pipe across exec and the namespace.
exec ip netns exec "$ELASTOS_BROWSER_NAMESPACE" "$ELASTOS_BROWSER_EXECUTABLE" "$@"

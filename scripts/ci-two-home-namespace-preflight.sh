#!/usr/bin/env bash
# Check the same rootless namespace combination used by the two-Home matrix.
set -euo pipefail
if ! unshare --user --map-root-user --mount --net true; then
    echo 'two-Home matrix requires user, mapped-root, mount and network namespaces; the runner refused the preflight.' >&2
    echo 'On the disposable Ubuntu CI runner, set kernel.apparmor_restrict_unprivileged_userns=0 before this check.' >&2
    exit 1
fi
echo 'two-Home namespace preflight: PASS'

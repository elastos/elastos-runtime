#!/usr/bin/env bash
# Install one checkout into its own isolated Home for the mixed-version gate.
#
# The gate pairs two Runtime versions, so one runner installs two source Homes.
# Each build keeps private intermediates and releases them before the next
# build starts; a hosted runner holds one set of release intermediates, not two.
set -euo pipefail
umask 022

SOURCE="$(cd "${1:?Set the checkout to install from}" && pwd)"
TARGET="${2:?Set the isolated HOME to install into}"
NAME="$(basename "$TARGET")"
SCRATCH="${RUNNER_TEMP:?Set RUNNER_TEMP}/${NAME}-cargo"

test ! -e "$TARGET"
test ! -e "$SCRATCH"
install -d -m 700 "$TARGET" "$TARGET/.local/share" "$SCRATCH/target" "$SCRATCH/build"

: "${SETUP_SOURCE_HOME_MEDIA_TOOLS_DIR:?Set the reviewed media tools directory}"
: "${ELASTOS_NODE_BIN:?Set the Node executable the Browser component uses}"
: "${ELASTOS_BROWSER_VM_TURNSERVER_BIN:?Set the TURN executable}"

# Cargo and rustup stay in the runner's own home; only the product installs here.
cd "$SOURCE"
env HOME="$TARGET" XDG_DATA_HOME="$TARGET/.local/share" \
    CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
    CARGO_TARGET_DIR="$SCRATCH/target" CARGO_BUILD_BUILD_DIR="$SCRATCH/build" \
    PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH" \
    SETUP_SOURCE_HOME_INSTALL_LLAMA_SERVER=0 SETUP_SOURCE_HOME_INSTALL_KUBO=0 \
    ELASTOS_QUIET_RUNTIME_NOTICES=1 \
    scripts/setup-source-home.sh

rm -rf "$SCRATCH"
df -Pk .

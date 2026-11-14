#!/usr/bin/env bash
# Install a second checkout into its own isolated Home, beside the candidate.
#
# The mixed-version Community gate pairs two Runtime versions, so one job
# installs two source Homes. Both share the job's build directories, so the
# second build reuses every dependency the first one compiled.
set -euo pipefail
umask 022

SOURCE="$(cd "${1:?Set the checkout to install from}" && pwd)"
TARGET="${2:?Set the isolated HOME to install into}"
MEDIA_TOOLS_DIR="${TARGET}-media-tools"

test ! -e "$TARGET"
install -d -m 700 "$TARGET" "$TARGET/.local/share" "$MEDIA_TOOLS_DIR"
for tool in ffmpeg ffprobe; do
    install -m 700 "$(command -v "$tool")" "$MEDIA_TOOLS_DIR/$tool"
done

NODE_BIN="$(command -v node)"
TURNSERVER_BIN="$(command -v turnserver)"

# Cargo and rustup stay in the runner's own home; only the product installs here.
cd "$SOURCE"
env HOME="$TARGET" XDG_DATA_HOME="$TARGET/.local/share" \
    CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
    PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH" \
    SETUP_SOURCE_HOME_MEDIA_TOOLS_DIR="$MEDIA_TOOLS_DIR" \
    ELASTOS_NODE_BIN="$NODE_BIN" ELASTOS_BROWSER_VM_TURNSERVER_BIN="$TURNSERVER_BIN" \
    SETUP_SOURCE_HOME_INSTALL_LLAMA_SERVER=0 SETUP_SOURCE_HOME_INSTALL_KUBO=0 \
    ELASTOS_QUIET_RUNTIME_NOTICES=1 \
    scripts/setup-source-home.sh
df -Pk .

#!/bin/sh
# Immutable executable; each test owns its output and deadline data files.
[ "$1" = --host-capabilities ] || exit 2
if [ -f "$ELASTOS_BROWSER_VM_DATA_DIR/probe-hang" ]; then
    while :; do :; done
fi
exec /bin/cat "$ELASTOS_BROWSER_VM_DATA_DIR/probe-output"

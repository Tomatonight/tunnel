#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# A root-launched GUI can inherit an AT-SPI socket under /root.  The GUI does
# not use accessibility integration; remove the stale address before Python or
# GTK/WebKit is imported.
if [ "$(id -u)" -eq 0 ]; then
    export NO_AT_BRIDGE=1
    unset AT_SPI_BUS_ADDRESS AT_SPI_BUS
fi
sh "$ROOT/stop-gui.sh" --quiet
exec "${PYTHON:-python3}" "$ROOT/tools/launch_gui.py" "$@"

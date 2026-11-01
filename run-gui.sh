#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON=${PYTHON:-python3}
if [ -x "$ROOT/.venv-gui/bin/python" ]; then
    PYTHON="$ROOT/.venv-gui/bin/python"
else
    echo "GUI dependencies are not prepared. Run ./build.sh first (or create .venv-gui from gui/requirements.txt)." >&2
    exit 1
fi
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    echo "No graphical display is available. Run this from the Linux desktop session, or preserve DISPLAY/WAYLAND_DISPLAY when using sudo." >&2
    exit 1
fi
exec "$PYTHON" "$ROOT/gui/main.py" --binary "$ROOT/build/tunnel" "$@"

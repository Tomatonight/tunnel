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
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_UID:-}" ] && [ -d "/run/user/$SUDO_UID" ]; then
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$SUDO_UID}"
    export XDG_RUNTIME_DIR
    if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] && [ -S "$XDG_RUNTIME_DIR/bus" ]; then
        DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
        export DBUS_SESSION_BUS_ADDRESS
    fi
fi
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ] && [ -S "${XDG_RUNTIME_DIR:-}/wayland-0" ]; then
    WAYLAND_DISPLAY=wayland-0
    export WAYLAND_DISPLAY
fi
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    for socket in /tmp/.X11-unix/X*; do
        if [ -S "$socket" ]; then
            DISPLAY=":${socket##*X}"
            export DISPLAY
            break
        fi
    done
fi
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    echo "No graphical display is available. Run this from the Linux desktop session, or preserve DISPLAY/WAYLAND_DISPLAY when using sudo." >&2
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1; then
        echo "This GUI needs root/CAP_NET_ADMIN for the tunnel core, but sudo is not installed." >&2
        exit 1
    fi
    exec sudo --preserve-env=DISPLAY,WAYLAND_DISPLAY,XDG_RUNTIME_DIR,DBUS_SESSION_BUS_ADDRESS bash "$0" "$@"
fi
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_UID:-}" ] && [ -n "${DISPLAY:-}" ] && command -v sudo >/dev/null 2>&1 && command -v xhost >/dev/null 2>&1; then
    # X11 authorizes the logged-in user, not root. Grant root only for this
    # GUI lifetime so the elevated core can create TUN devices and routes.
    if sudo -u "#$SUDO_UID" env DISPLAY="$DISPLAY" xhost +SI:localuser:root >/dev/null 2>&1; then
        cleanup_xhost() {
            sudo -u "#$SUDO_UID" env DISPLAY="$DISPLAY" xhost -SI:localuser:root >/dev/null 2>&1 || true
        }
        trap cleanup_xhost EXIT INT TERM
    fi
fi
exec "$PYTHON" "$ROOT/gui/main.py" --binary "$ROOT/build/tunnel" "$@"

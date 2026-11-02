#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$#" -gt 0 ]; then
    if [ ! -x "$ROOT/build/tunnel" ]; then
        echo "CLI core is missing; running bash build.sh." >&2
        bash "$ROOT/build.sh"
    fi
    if [ "$(uname -s)" = "Linux" ] && [ "${TUNNEL_SKIP_KERNEL_MODULE:-0}" != "1" ]; then
        KERNEL_RELEASE=$(uname -r)
        KERNEL_MODULE="$ROOT/build/kernel/tunnel_kmod.ko"
        KERNEL_INFO="$ROOT/build/kernel/build-info.json"
        if [ ! -f "$KERNEL_MODULE" ]; then
            echo "Linux kernel module is missing; running bash build.sh (including tunnel_kmod.ko)." >&2
            bash "$ROOT/build.sh"
        elif [ -f "$KERNEL_INFO" ] && ! grep -Fq "\"kernel_release\": \"$KERNEL_RELEASE\"" "$KERNEL_INFO"; then
            echo "Linux kernel module targets a different kernel; running bash build.sh." >&2
            bash "$ROOT/build.sh"
        fi
    fi
fi
if [ "$#" -eq 0 ]; then
    exec python3 "$ROOT/tools/tunnel_cli.py" --help
fi
exec python3 "$ROOT/tools/tunnel_cli.py" --binary "$ROOT/build/tunnel" "$@"

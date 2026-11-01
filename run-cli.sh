#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$#" -eq 0 ]; then
    exec python3 "$ROOT/tools/tunnel_cli.py" --help
fi
exec python3 "$ROOT/tools/tunnel_cli.py" --binary "$ROOT/build/tunnel" "$@"

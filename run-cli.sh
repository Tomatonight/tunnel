#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
die() { echo "$*" >&2; exit 1; }
if [ "$#" -eq 0 ]; then
    exec python3 "$ROOT/tools/tunnel_cli.py" --help
fi
[ -x "$ROOT/build/tunnel" ] || die "找不到核心程序，请先执行：sh \"$ROOT/build.sh\""
exec python3 "$ROOT/tools/tunnel_cli.py" --binary "$ROOT/build/tunnel" "$@"

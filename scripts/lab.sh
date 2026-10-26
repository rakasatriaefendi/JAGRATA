#!/usr/bin/env bash
# Bash 3.2+; forward every argument without eval or GNU utilities.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN=''
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -B -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' >/dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done
if [ -z "$PYTHON_BIN" ]; then
    printf '%s\n' '[LAB] FAIL: Python 3.8+ is required; no dependencies were installed.' >&2
    exit 1
fi
exec "$PYTHON_BIN" -B "$SCRIPT_DIR/guard_lab.py" "$@"

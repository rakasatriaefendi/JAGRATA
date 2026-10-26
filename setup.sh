#!/usr/bin/env bash
set -euo pipefail
GUARD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v node >/dev/null 2>&1; then
    printf '%s\n' '[GUARD] Node.js 24+ is required; install prerequisites separately.' >&2
    exit 1
fi
if ! node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 24 ? 0 : 1)'; then
    printf '%s\n' '[GUARD] A working Node.js 24+ is required.' >&2
    exit 1
fi
exec node "$GUARD_ROOT/installer/cli.ts" setup "$@"

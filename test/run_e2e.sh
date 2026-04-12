#!/bin/bash
# end-to-end test: single-command launcher mode
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
MEMVIS="$ROOT/engine/target/release/memvis"
TARGET="$SCRIPT_DIR/target"

# clean stale shm
rm -f /dev/shm/memvis_* 2>/dev/null

# single command: launcher discovers drrun, forks tracer, runs consumer
$MEMVIS --once --min-events 50000 "$TARGET" 2>&1
EXIT=$?

echo ""
echo "=== E2E result: exit=$EXIT ==="

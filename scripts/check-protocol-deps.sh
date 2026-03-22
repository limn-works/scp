#!/usr/bin/env bash
# Verify scp-protocol has no async runtime dependencies in production.
set -euo pipefail

echo "Checking scp-protocol dependency tree..."

banned="tokio|async-trait|scp-platform|openmls"
matches=$(cargo tree -p scp-protocol --no-dev 2>/dev/null | grep -iE "$banned" || true)

if [ -n "$matches" ]; then
    echo "ERROR: scp-protocol has banned dependencies:"
    echo "$matches"
    exit 1
fi

echo "scp-protocol dependency check passed: no async runtime deps."

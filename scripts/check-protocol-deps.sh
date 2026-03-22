#!/usr/bin/env bash
# Verify scp-protocol has no async runtime dependencies in production.
set -euo pipefail

echo "Checking scp-protocol dependency tree..."

# async-trait is excluded: it's a proc-macro that generates trait impls at
# compile time and does not pull in an async runtime at run time.
banned="tokio|scp-platform|openmls"
output=$(cargo tree -p scp-protocol --edges no-dev 2>&1) || { echo "ERROR: cargo tree failed: $output"; exit 1; }
matches=$(echo "$output" | grep -iE "$banned" || true)

if [ -n "$matches" ]; then
    echo "ERROR: scp-protocol has banned dependencies:"
    echo "$matches"
    exit 1
fi

echo "scp-protocol dependency check passed: no async runtime deps."

#!/usr/bin/env bash
# Verify scp-core facade re-exports all public items from scp-protocol and scp-runtime.
set -euo pipefail

echo "Checking facade completeness..."

# Build docs for all three crates
cargo doc --no-deps --package scp-protocol --package scp-runtime --package scp-core 2>/dev/null

# Compare module lists
protocol=$(find target/doc/scp_protocol -maxdepth 1 -name "*.html" ! -name "index.html" -exec basename {} .html \; 2>/dev/null | sort)
runtime=$(find target/doc/scp_runtime -maxdepth 1 -name "*.html" ! -name "index.html" -exec basename {} .html \; 2>/dev/null | sort)
core=$(find target/doc/scp_core -maxdepth 1 -name "*.html" ! -name "index.html" -exec basename {} .html \; 2>/dev/null | sort)

missing=0
for mod in $protocol $runtime; do
  if ! echo "$core" | grep -q "^${mod}$"; then
    echo "MISSING from scp-core facade: $mod"
    missing=$((missing + 1))
  fi
done

if [ "$missing" -gt 0 ]; then
  echo "ERROR: $missing modules not re-exported through scp-core facade"
  exit 1
fi
echo "Facade completeness check passed."

#!/usr/bin/env bash
LOOM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
touch "$LOOM_DIR/.stop"

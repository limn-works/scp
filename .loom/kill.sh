#!/usr/bin/env bash
LOOM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="$(basename "$(dirname "$LOOM_DIR")")"
tmux kill-session -t "loom-${PROJECT_NAME}" 2>/dev/null && echo "Loom killed." || echo "Loom is not running."

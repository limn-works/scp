#!/usr/bin/env bash
# Docker convenience wrapper for SCP services.
# Usage:
#   ./scripts/docker.sh relay up     # Start bare relay
#   ./scripts/docker.sh node up      # Start full node
#   ./scripts/docker.sh relay logs   # View relay logs
#   ./scripts/docker.sh down         # Stop all services
#   ./scripts/docker.sh build        # Build Docker image

set -euo pipefail

SERVICE="${1:-}"
ACTION="${2:-}"

case "$SERVICE" in
  relay|node)
    docker compose "$ACTION" "$SERVICE" "${@:3}"
    ;;
  down)
    docker compose down "${@:2}"
    ;;
  build)
    docker compose build "${@:2}"
    ;;
  *)
    echo "Usage: $0 {relay|node} {up|logs|...} | down | build"
    exit 1
    ;;
esac

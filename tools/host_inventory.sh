#!/bin/sh
# Read-only helper: run on the PHYSICAL hypervisor too, not only inside each VM.
set -eu
uname -srmo
getconf _NPROCESSORS_ONLN
free -h
df -h /
if command -v docker >/dev/null 2>&1; then
  docker version --format '{{.Server.Version}}' || true
  docker compose version || true
fi
sysctl vm.max_map_count

#!/usr/bin/env bash
# Samaritan local Docker deployment helper.
# No hostnames, account names, SSH destinations or credentials are embedded.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker Engine and the Compose plugin first." >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required (docker compose)." >&2
  exit 1
fi
if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example. Set SCANNER_KEY before continuing." >&2
fi

SCANNER_KEY_VALUE="$(sed -n 's/^SCANNER_KEY=//p' .env | tail -n 1 | tr -d '\r')"
if [[ ${#SCANNER_KEY_VALUE} -lt 32 || "$SCANNER_KEY_VALUE" == change-this* ]]; then
  echo "SCANNER_KEY must be a unique secret of at least 32 characters." >&2
  echo "Generate one with: openssl rand -hex 32" >&2
  exit 1
fi

exec docker compose up -d --build

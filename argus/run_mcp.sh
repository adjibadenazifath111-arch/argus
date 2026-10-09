#!/bin/bash
# Lanceur du serveur MCP ARGUS (sécurité : secrets via .elklab_env)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOME_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
SECRETS="$HOME_DIR/.elklab_env"

if [ ! -f "$SECRETS" ]; then
    echo "ERREUR: secrets absents ($SECRETS)" >&2
    exit 1
fi

set -a
source "$SECRETS"
set +a

exec "$SCRIPT_DIR/venv/bin/python" "$SCRIPT_DIR/mcp_server.py"

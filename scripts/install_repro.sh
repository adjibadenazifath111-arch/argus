#!/bin/bash
# ============================================================================
#  install_repro.sh — Déploie la couche "ARGUS" (MCP/Email/Chat)
#  Issue du kit de reproduction ARGUS. A exécuter sur la machine cible (root).
#
#  Prérequis (à faire AVANT) :
#    1. Docker + réseau elk-network + ELK 9.1.3 opérationnel
#       (voir 10_reproduction_architecture.md sections 4-7)
#    2. venv deja cree : python3 -m venv /home/<user>/elklab/soc-mcp/venv
#    3. Secrets deja remplis : tpl/*.template -> copies reelles, chmod 600
#    4. Config beats/fleet OK (sections 8-9)
#
#  Utilisation :  sudo ./install_repro.sh <user>          (ex: ubuntu2)
# ============================================================================
set -euo pipefail

USER="${1:?Usage: $0 <user>}"
HOME_DIR="/home/$USER"
ROOT="$HOME_DIR/elklab"
SERVICE_USER="$USER"

echo "==> Deploiement ARGUS pour utilisateur '$USER'"

[ -d "$ROOT/soc-mcp/venv" ] || { echo "ERREUR: venv absent ($ROOT/soc-mcp/venv)"; exit 1; }
[ -f "/home/$USER/.elklab_env" ] || { echo "ERREUR: secrets .elklab_env absents"; exit 1; }

echo "==> Creation arborescence"
mkdir -p "$ROOT/soc-mcp"

echo "==> Copie des scripts applicatifs"
cp scripts/mcp_server.py          "$ROOT/soc-mcp/mcp_server.py"
cp scripts/chat_soc.py            "$ROOT/soc-mcp/chat_soc.py"
cp scripts/run_mcp.sh             "$ROOT/soc-mcp/run_mcp.sh"
cp scripts/soc_email_agent_mcp.py "$ROOT/soc_email_agent_mcp.py"

echo "==> Permissions"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$ROOT"
chmod 600 "/home/$USER/.elklab_env"
chmod +x "$ROOT/soc-mcp/run_mcp.sh" "$ROOT/soc_email_agent_mcp.py" "$ROOT/soc-mcp/mcp_server.py"

echo "==> Installation des unites systemd (avec substitution <user>)"
for unit in units/*.service; do
  sed "s/__USER__/$USER/g" "$unit" > "/etc/systemd/system/$(basename "$unit")"
done

if [ -f "/etc/argus-email-mcp.env" ] && [ -f "/etc/argus-chat.env" ]; then
  chmod 600 /etc/argus-email-mcp.env /etc/argus-chat.env
fi

echo "==> Reload systemd + demarrage des services"
systemctl daemon-reload
systemctl enable --now argus-mcp
sleep 3
systemctl enable --now argus-email-mcp argus-chat

echo "==> Verification"
sleep 3
systemctl is-active argus-mcp argus-email-mcp argus-chat

echo "==> Smoke test (chat doit repondre 401 sans creds, 200 avec)"
# a renseigner manuellement : voir tpl/chat.env.template

echo "DONE. Services MCP/Email/Chat deployes."
echo "Ouvrir le chat : http://<IP_SERVEUR>:8001  (login: tpl/chat.env.template)"
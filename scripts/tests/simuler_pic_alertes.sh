#!/usr/bin/env bash
# ============================================================================
#  simuler_pic_alertes.sh — Pic d'alertes "ARGUS - DNS suspect" à la demande
#
#  Émet de VRAIES requêtes DNS depuis la VM capteur (ubuntu-noa) dont le
#  trafic est collecté par l'intégration Fleet "Network Packet Capture" et le
#  packetbeat autonome. Les requêtes portent des domaines de TYPOSQUATTING
#  (imitation leetspeak de marques + TLD présents dans les campagnes) qui
#  déclenchent la règle ES|QL "ARGUS - DNS suspect" v2 (heuristiques).
#
#  Usage :  sudo ./simuler_pic_alertes.sh [nb_requetes] [prefixe]
#           (défauts : 25 requêtes, préfixe "argus-demo")
#
#  Pré-requis : fichier d'accès SSH de la VM (lignes 1 et 2 : cible / mot de
#  passe), chemin par défaut /opt/argus/vm_ssh_creds (chmod 600), surchargeable
#  avec la variable ARGUS_VM_CREDS, ou variables ARGUS_VM_HOST / ARGUS_VM_PASS.
#  Les alertes apparaissent dans Kibana sous ~1 minute (intervalle des règles).
# ============================================================================
set -euo pipefail

NB="${1:-25}"
PREFIX="${2:-argus-demo}"

CREDS="${ARGUS_VM_CREDS:-/opt/argus/vm_ssh_creds}"

if [ -z "${ARGUS_VM_HOST:-}" ]; then

    if [ ! -r "$CREDS" ]; then
        echo "ERREUR : accès VM absent. Créez $CREDS (cible en ligne 1, mot de passe en ligne 2, chmod 600)." >&2
        exit 1
    fi
    read -r ARGUS_VM_HOST < <(sed -n '1p' "$CREDS")
    read -r ARGUS_VM_PASS   < <(sed -n '2p' "$CREDS")
fi

command -v sshpass >/dev/null || { echo "ERREUR : sshpass requis." >&2; exit 1; }

NAMES="g00gle-login.xyz faceb00k-secure.top micr0s0ft-update.icu am4zon-billing.gq payp4l-verification.xyz netfl1x-account.click gma1l-verify.ml inst4gr4m-auth.top 0utlook-support.xyz 0kta-portal.icu"

REMOTE=(
    "DOMS=($NAMES);"
    "T=\${#DOMS[@]};"
    "i=1;"
    "while [ \$i -le $NB ]; do"
    "  d=\${DOMS[\$(( (i-1) % T ))]};"
    "  dig +time=1 +tries=1 +short $PREFIX-\$i.\$d >/dev/null 2>&1;"
    "  i=\$((i+1));"
    "  sleep 0.1;"
    "done;"
    "echo PIC_TERMINE"
)

echo "==> ${NB} requêtes DNS (typosquatting) émises depuis ${ARGUS_VM_HOST} (préfixe ${PREFIX})"

sshpass -p "$ARGUS_VM_PASS" ssh \
    -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=10 \
    -o ServerAliveInterval=30 \
    -o LogLevel=ERROR \
    "$ARGUS_VM_HOST" "${REMOTE[*]}"

echo "==> Queries envoyées. La règle 'ARGUS - DNS suspect' s'exécute toutes les 60 s."
echo "==> Pic visible dans Kibana : Security -> Alerts, ou via l'outil MCP"
echo "==>     recuperer_alertes_siem dans les ~2 minutes."
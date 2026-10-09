# Kit de reproduction ARGUS — manifeste

Contenu du dossier `repro_kit/` (à copier tel quel sur la machine cible) :

| Chemin | Contenu | Destination cible |
|--------|---------|-------------------|
| `scripts/mcp_server.py` | Serveur MCP (4 outils, interroge ELK + Groq) | `/home/<user>/elklab/soc-mcp/mcp_server.py` |
| `scripts/chat_soc.py` | Web app analyste (Basic Auth, port 8001) | `/home/<user>/elklab/soc-mcp/chat_soc.py` |
| `scripts/run_mcp.sh` | Lanceur MCP (source les secrets `.elklab_env`) | `/home/<user>/elklab/soc-mcp/run_mcp.sh` |
| `scripts/soc_email_agent_mcp.py` | Agent e-mail (notification via MCP) | `/home/<user>/elklab/soc_email_agent_mcp.py` |
| `configs/logstash.conf` | Pipeline Logstash (beats + snort → `logs-*`) | `/home/<user>/logstash.conf` (bind docker) |
| `configs/packetbeat.yml.example` | Packetbeat (flows, protocoles) | `/etc/packetbeat/packetbeat.yml` |
| `configs/filebeat.yml.example` | Filebeat (snort.alert → 5044) | `/etc/filebeat/filebeat.yml` |
| `units/*.service` | 3 unités systemd (MCP/email/chat) | `/etc/systemd/system/` (sed `__USER__`) |
| `tpl/*.template` | Secrets anonymisés (à remplir) | `.elklab_env`, `/etc/argus-{email-mcp,chat}.env` |
| `install_repro.sh` | Script de déploiement tout-en-un | exécuter en root |

## Ordre d'installation (rappel)
1. Lire `10_reproduction_architecture.md` (4 conteneurs docker + réseau + certs Fleet).
2. Configurer beats/fleet + règle SIEM `argus-detect-network-scan`.
3. Créer le venv : `python3 -m venv /home/<user>/elklab/soc-mcp/venv`
4. Remplir les 3 templates secrets (chemins ci-dessus, chmod 600).
5. `sudo ./install_repro.sh <user>`

## Garanties
- **Aucun secret réel** dans ce kit (les mots de passe API key / Groq / ES / SMTP sont des placeholders `__…__` ou `<…>`).
- Fichiers applicatifs **identiques** à ceux du lab (`10.0.26.136`, dossier `/home/ubuntu2/elklab`).
- L'IP / le hostname / le cert Fleet sont à adapter (chaîne `soc-lab.local`, SAN).

## Secrets requérants (dans le fichier confidentiel, hors kit)
- Elastic API key (lecture + monitor) — `ELASTIC_API_KEY_ID` / `ELASTIC_API_KEY`
- Groq API key + modèle `openai/gpt-oss-20b`
- SMTP (host/port/user/pass/from/to)
- Chat : `CHAT_USER` / `CHAT_PASS`
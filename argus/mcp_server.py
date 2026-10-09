#!/usr/bin/env python3
import os
import sys
import json
import requests
from elasticsearch import Elasticsearch
from mcp.server.mcpserver import MCPServer, Context

# ============================================================
# 1. CONFIGURATION (secrets via variables d'environnement)
#    Variables attendues (définies dans /home/ubuntu2/.elklab_env
#    ou passées par le service systemd) :
#      ELASTIC_API_KEY_ID, ELASTIC_API_KEY, GROQ_API_KEY, GROQ_MODEL
#    Ne jamais écrire de secret en clair dans ce fichier.
# ============================================================
ES_HOST = os.environ.get("ES_HOST", "https://localhost:9200")
ES_CA_CERTS = os.environ.get("ES_CA_CERTS", "")
ES_API_KEY_ID = os.environ.get("ELASTIC_API_KEY_ID", "") or os.environ.get("ES_API_KEY_ID", "")
ES_API_KEY = os.environ.get("ELASTIC_API_KEY", "") or os.environ.get("ES_API_KEY", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b")

# Transport / réseau (par défaut stdio pour l'Inspecteur ; le service
# systemd peut forcer streamable-http sur MCP_HOST:MCP_PORT)
MCP_TRANSPORT = os.environ.get("MCP_TRANSPORT", "stdio")
MCP_HOST = os.environ.get("MCP_HOST", "127.0.0.1")
MCP_PORT = int(os.environ.get("MCP_PORT", "8700"))

# ============================================================
# 2. INDEX DU LAB SOC
# ============================================================
ALERT_INDEX = ".alerts-security.alerts-default*"
PROCESS_INDEX = "logs-endpoint.events.process-*"

# Initialisation du serveur MCP (Syntaxe v2)
mcp = MCPServer("Elastic-SOC-Lab")

def get_es_client():
    if not ES_API_KEY_ID or not ES_API_KEY:
        raise ValueError("Erreur : variables ELASTIC_API_KEY_ID / ELASTIC_API_KEY non définies dans l'environnement.")
    kwargs = dict(hosts=[ES_HOST], api_key=(ES_API_KEY_ID, ES_API_KEY), request_timeout=30)
    if ES_HOST.startswith("https://"):
        if not ES_CA_CERTS:
            raise ValueError("Erreur : ES_CA_CERTS absent alors que ES_HOST est en https.")
        kwargs.update(ca_certs=ES_CA_CERTS, verify_certs=True)
    return Elasticsearch(**kwargs)

def get_nested(data, *keys):
    if not isinstance(data, dict):
        return None
    flat = ".".join(keys)
    if flat in data:
        return data[flat]
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current

def get_threshold_term(data, *candidates):
    result = get_nested(data, "kibana", "alert", "threshold_result")
    if not isinstance(result, dict):
        return None
    for term in result.get("terms") or []:
        field = term.get("field", "")
        for candidate in candidates:
            if field == candidate or field.startswith(candidate + "."):
                return term.get("value")
    return None

def extract_alert_information(alert):
    return {
        "rule_name": get_nested(alert, "kibana", "alert", "rule", "name") or "N/A",
        "severity": get_nested(alert, "kibana", "alert", "severity") or "N/A",
        "risk_score": get_nested(alert, "kibana", "alert", "risk_score") or "N/A",
        "host": get_nested(alert, "host", "name") or "N/A",
        "source_ip": get_nested(alert, "source", "ip") or get_threshold_term(alert, "source.ip") or "N/A",
        "process_name": get_nested(alert, "process", "name") or "N/A",
        "process_command": get_nested(alert, "process", "command_line") or "N/A",
        "user_name": get_nested(alert, "user", "name") or "N/A",
        "timestamp": alert.get("@timestamp") or "N/A",
        "reason": get_nested(alert, "kibana", "alert", "reason") or alert.get("message") or "N/A"
    }

# ============================================================
# 3. OUTILS MCP (Accessibles par l'IA ou l'Inspecteur)
# ============================================================

@mcp.tool()
def verifier_status_elastic() -> str:
    """Vérifie la connexion avec le cluster Elasticsearch du Lab SOC."""
    try:
        es = get_es_client()
        result = es.count(index="logs-*")
        return f"Connexion OK. Nombre total de logs dans le lab : {result.get('count', 0)}"
    except Exception as e:
        return f"Erreur de connexion à Elasticsearch : {str(e)}"

@mcp.tool()
def recuperer_statistiques_cluster() -> str:
    """Récupère les statistiques réelles du cluster Elasticsearch : santé, noeuds,
    indices, shards, documents (Cluster Health + Cat Indices du lab)."""
    try:
        es = get_es_client()
        health = es.cluster.health() or {}
        indices = es.cat.indices(index="logs-*", format="json", h="index,docs.count,store.size,pri") or []
        total_docs = sum(int(i.get("docs.count") or 0) for i in indices)
        total_indices = len(indices)
        summary = {
            "cluster_status": health.get("status", "N/A"),
            "nb_noeuds": health.get("number_of_nodes", "N/A"),
            "nb_indices_logs": total_indices,
            "nb_documents_logs": total_docs,
            "shards_actifs": health.get("active_shards", "N/A"),
            "shards_relocalises": health.get("relocating_shards", "N/A"),
            "shards_initialisants": health.get("initializing_shards", "N/A"),
            "documents_non_assignes": health.get("unassigned_shards", "N/A"),
        }
        return json.dumps(summary, indent=2, ensure_ascii=False)
    except Exception as e:
        return f"Erreur lors de la récupération des statistiques cluster : {str(e)}"

@mcp.tool()
def recuperer_alertes_siem(limit: int = 5) -> str:
    """Récupère les dernières alertes de sécurité d'Elastic SIEM."""
    try:
        es = get_es_client()
        query = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"event.kind": ["alert", "signal"]}}
                    ],
                    "must_not": [
                        {"term": {"process.name": "cat"}}
                    ]
                }
            }
        }

        response = es.search(index=ALERT_INDEX, body=query)
        hits = response.get("hits", {}).get("hits", [])
        if not hits:
            return "Aucune alerte de sécurité trouvée dans l'index SIEM."

        alerts = [extract_alert_information(hit.get("_source", {})) for hit in hits]
        return json.dumps(alerts, indent=2, ensure_ascii=False)
    except Exception as e:
        return f"Erreur lors de la récupération des alertes : {str(e)}"

@mcp.tool()
def analyser_alerte_avec_groq(donnees_alerte_json: str) -> str:
    """Envoie les données d'une alerte à l'API Groq pour obtenir l'analyse détaillée d'un analyste SOC virtuel."""
    if not GROQ_API_KEY:
        return "Erreur : la variable GROQ_API_KEY n'est pas définie dans l'environnement."
    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
        prompt = f"Agis en tant qu'analyste SOC. Analyse cette alerte technique et donne : 1. Explication, 2. Gravité, 3. Actions recommandées :\n{donnees_alerte_json}"

        data = {
            "model": GROQ_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2
        }
        response = requests.post(url, headers=headers, json=data, timeout=30)
        if response.status_code != 200:
            return f"Erreur API Groq ({response.status_code}) : {response.text[:200]}"
        data = response.json()
        message = data.get("choices", [{}])[0].get("message", {})
        return (
            message.get("content")
            or message.get("reasoning")
            or "Aucune analyse retournée."
        )
    except Exception as e:
        return f"Erreur lors de l'appel à l'API Groq : {str(e)}"

if __name__ == "__main__":
    mcp.run(
        transport=MCP_TRANSPORT,
        host=MCP_HOST,
        port=MCP_PORT,
    )
#!/usr/bin/env python3

import os
import json
import time
import smtplib
import traceback

from datetime import datetime, timezone

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from elasticsearch import Elasticsearch


# ============================================================
# CONFIGURATION ELASTICSEARCH
# ============================================================

ES_HOST = os.getenv(
    "ES_HOST",
    "https://localhost:9200"
)

ES_CA_CERTS = os.getenv(
    "ES_CA_CERTS",
    ""
)

ES_API_KEY_ID = os.getenv("ELASTIC_API_KEY_ID")
ES_API_KEY = os.getenv("ELASTIC_API_KEY")

ALERT_INDEX = ".alerts-security.alerts-default*"

POLL_INTERVAL = int(
    os.getenv("POLL_INTERVAL", "30")
)

ALERT_LOOKBACK = os.getenv(
    "ALERT_LOOKBACK",
    "5m"
)

STATE_FILE = os.getenv(
    "STATE_FILE",
    os.path.expanduser(
        "~/elklab/.soc_email_last_alert"
    )
)

# Cooldown par regle : au plus un e-mail par regle toutes les N minutes.
# Les alertes intermediaires sont comptabilisees et résumées dans l'e-mail
# suivant (au lieu d'etre envoyees une par une).
RULE_COOLDOWN_MINUTES = float(
    os.getenv(
        "RULE_COOLDOWN_MINUTES",
        "10"
    )
)


# ============================================================
# CONFIGURATION GROQ
# ============================================================

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

GROQ_MODEL = os.getenv(
    "GROQ_MODEL",
    "openai/gpt-oss-20b"
)


# ============================================================
# CONFIGURATION SMTP
# ============================================================

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(
    os.getenv("SMTP_PORT", "587")
)

SMTP_USERNAME = os.getenv(
    "SMTP_USERNAME"
)

SMTP_PASSWORD = os.getenv(
    "SMTP_PASSWORD"
)

SMTP_FROM = os.getenv(
    "SMTP_FROM"
)

SMTP_TO = os.getenv(
    "SMTP_TO"
)

SMTP_STARTTLS = os.getenv(
    "SMTP_STARTTLS",
    "true"
).lower() == "true"


# ============================================================
# ELASTICSEARCH
# ============================================================

def create_elasticsearch_client():

    if not ES_API_KEY_ID or not ES_API_KEY:
        raise RuntimeError(
            "ELASTIC_API_KEY_ID ou ELASTIC_API_KEY absent."
        )

    kwargs = dict(
        hosts=[ES_HOST],
        api_key=(ES_API_KEY_ID, ES_API_KEY),
        request_timeout=30
    )

    if ES_HOST.startswith("https://"):

        if not ES_CA_CERTS:
            raise RuntimeError(
                "ES_CA_CERTS absent alors que ES_HOST est en https."
            )

        kwargs.update(
            ca_certs=ES_CA_CERTS,
            verify_certs=True
        )

    return Elasticsearch(**kwargs)


es = create_elasticsearch_client()


# ============================================================
# VERIFICATION CONFIGURATION
# ============================================================

def check_configuration():

    required = {
        "GROQ_API_KEY": GROQ_API_KEY,
        "SMTP_HOST": SMTP_HOST,
        "SMTP_USERNAME": SMTP_USERNAME,
        "SMTP_PASSWORD": SMTP_PASSWORD,
        "SMTP_FROM": SMTP_FROM,
        "SMTP_TO": SMTP_TO,
    }

    missing = [
        name
        for name, value in required.items()
        if not value
    ]

    if missing:

        raise RuntimeError(
            "Configuration manquante : "
            + ", ".join(missing)
        )


# ============================================================
# ETAT DE LA DERNIERE ALERTE
# ============================================================

def load_state():

    """Etat de traitement : horodatage de la derniere alerte traitee
    et identifiants deja traites a cet horodatage."""

    try:

        if os.path.exists(STATE_FILE):

            with open(
                STATE_FILE,
                "r",
                encoding="utf-8"
            ) as f:

                raw = f.read().strip()

            if raw.startswith("{"):

                data = json.loads(raw)

                if isinstance(data, dict) and data.get("ts"):

                    return {
                        "ts": data["ts"],
                        "ids": set(data.get("ids") or []),
                        "rules": data.get("rules") or {}
                    }

            # Ancien format (identifiant seul) : on repart proprement
            # plutot que de risquer des doublons.

            return None

    except Exception:

        traceback.print_exc()

    return None


def save_state(state):

    directory = os.path.dirname(
        STATE_FILE
    )

    if directory:
        os.makedirs(
            directory,
            exist_ok=True
        )

    temporary = STATE_FILE + ".tmp"

    with open(
        temporary,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            {
                "ts": state["ts"],
                "ids": sorted(state["ids"]),
                "rules": state.get("rules") or {}
            },
            f
        )

    os.replace(
        temporary,
        STATE_FILE
    )


def _parse_ts(value):

    try:

        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

    except Exception:

        return datetime.min.replace(
            tzinfo=timezone.utc
        )


def _mark_seen(state, timestamp, alert_id):

    """Avance l'horodatage de l'etat, sans jamais revenir en
    arriere : ce qui est plus ancien que l'etat courant est deja
    couvert par le filtre de requete."""

    if not state.get("ts"):

        state["ts"] = timestamp
        state["ids"] = {alert_id}
        return

    if timestamp == state["ts"]:

        state["ids"].add(alert_id)
        return

    if _parse_ts(timestamp) > _parse_ts(state["ts"]):

        state["ts"] = timestamp
        state["ids"] = {alert_id}


# ============================================================
# EXTRACTION
# ============================================================

def get_nested(data, *keys):

    if not isinstance(data, dict):
        return None

    # Cas 1 : champ aplati renvoye par le _source filtering
    # (ex : "kibana.alert.rule.name" est une cle a plat dans _source)
    flat = ".".join(keys)

    if flat in data:
        return data[flat]

    # Cas 2 : champ reellement imbrique (host.name, process.name, ...)
    current = data

    for key in keys:

        if not isinstance(current, dict):
            return None

        current = current.get(key)

    return current


def get_threshold_term(data, *candidates):

    # Les alertes de type "threshold" (agregation) ne stockent pas
    # forcement l'IP dans source.ip : la valeur du regroupement est
    # dans kibana.alert.threshold_result.terms
    # (ex : {"field": "source.ip.keyword", "value": "10.0.26.205"}).

    result = get_nested(
        data,
        "kibana",
        "alert",
        "threshold_result"
    )

    if not isinstance(result, dict):

        return None

    for term in result.get("terms") or []:

        field = term.get("field", "")

        for candidate in candidates:

            if field == candidate or field.startswith(candidate + "."):

                return term.get("value")

    return None


def extract_alert(source):

    return {

        "rule_name":
            get_nested(
                source,
                "kibana",
                "alert",
                "rule",
                "name"
            ) or "N/A",

        "severity":
            get_nested(
                source,
                "kibana",
                "alert",
                "severity"
            ) or "N/A",

        "risk_score":
            get_nested(
                source,
                "kibana",
                "alert",
                "risk_score"
            ) or "N/A",

        "status":
            get_nested(
                source,
                "kibana",
                "alert",
                "status"
            ) or "N/A",

        "reason":
            get_nested(
                source,
                "kibana",
                "alert",
                "reason"
            ) or source.get(
                "message",
                "N/A"
            ),

        "timestamp":
            source.get(
                "@timestamp",
                "N/A"
            ),

        "host":
            get_nested(
                source,
                "host",
                "name"
            ) or "N/A",

        "source_ip":
            get_nested(
                source,
                "source",
                "ip"
            ) or get_threshold_term(
                source,
                "source.ip"
            ) or "N/A",

        "source_port":
            get_nested(
                source,
                "source",
                "port"
            ) or "N/A",

        "destination_ip":
            get_nested(
                source,
                "destination",
                "ip"
            ) or "N/A",

        "destination_port":
            get_nested(
                source,
                "destination",
                "port"
            ) or "N/A",

        "transport":
            get_nested(
                source,
                "network",
                "transport"
            ) or "N/A",

        "process":
            get_nested(
                source,
                "process",
                "name"
            ) or "N/A",

        "command":
            get_nested(
                source,
                "process",
                "command_line"
            ) or "N/A",

        "user":
            get_nested(
                source,
                "user",
                "name"
            ) or "N/A",
    }


# ============================================================
# RECHERCHE DES NOUVELLES ALERTES
# ============================================================

def get_new_alerts(state=None):

    conditions = [

        {
            "range": {
                "@timestamp": {
                    "gte":
                        f"now-{ALERT_LOOKBACK}"
                }
            }
        },

        {
            "exists": {
                "field":
                    "kibana.alert.rule.name"
            }
        }
    ]

    # On ne reprend qu'a partir de la derniere alerte traitee
    # (et on garde la fenetre de lookback comme borne haute).
    if state and state.get("ts"):

        conditions.append(
            {
                "range": {
                    "@timestamp": {
                        "gte": state["ts"]
                    }
                }
            }
        )

    query = {

        "size": 50,

        "sort": [
            {
                "@timestamp": {
                    "order": "asc"
                }
            }
        ],

        "_source": [
            "@timestamp",

            "kibana.alert.rule.name",
            "kibana.alert.severity",
            "kibana.alert.risk_score",
            "kibana.alert.reason",
            "kibana.alert.status",
            "kibana.alert.threshold_result",

            "host.name",

            "source.ip",
            "source.port",

            "destination.ip",
            "destination.port",

            "network.transport",

            "process.name",
            "process.command_line",

            "user.name",

            "message"
        ],

        "query": {

            "bool": {

                "filter": conditions
            }
        }
    }

    response = es.search(
        index=ALERT_INDEX,
        body=query
    )

    return response.get(
        "hits",
        {}
    ).get(
        "hits",
        []
    )


# ============================================================
# ANALYSE GROQ
# ============================================================

def ask_groq_via_mcp(mcp_url, alert):

    import asyncio
    import json as _json

    def _run():
        import requests  # noqa: F401  (import local pour ne pas casser si absent)

        from mcp import Client

        async def main():
            async with Client(mcp_url) as client:
                alert_json = _json.dumps(
                    alert,
                    ensure_ascii=False,
                    default=str
                )
                result = await client.call_tool(
                    "analyser_alerte_avec_groq",
                    {"donnees_alerte_json": alert_json}
                )
                if hasattr(result, "content"):
                    texts = [
                        c.text for c in result.content
                        if getattr(c, "text", None)
                    ]
                    return "\n".join(texts) if texts else str(result)
                return str(result)

        return asyncio.run(main())

    print(f"[MCP] Appel de l'outil MCP local ({mcp_url})...")

    analysis = _run()

    print("[MCP] Analyse retournée par le serveur MCP.")

    return analysis


def ask_groq(alert):

    import requests

    mcp_url = os.getenv(
        "MCP_URL",
        "http://127.0.0.1:8700/mcp"
    ).strip()

    if mcp_url:
        try:
            return ask_groq_via_mcp(mcp_url, alert)
        except Exception as e:
            print(f"[MCP] Echec de l'analyse via MCP ({e}), repli API directe.")

    url = (
        "https://api.groq.com/"
        "openai/v1/chat/completions"
    )

    prompt = f"""
Tu es un analyste SOC.

Analyse cette alerte Elastic Security.

REGLE :
{alert['rule_name']}

SEVERITE :
{alert['severity']}

RISK SCORE :
{alert['risk_score']}

MACHINE :
{alert['host']}

DATE :
{alert['timestamp']}

IP SOURCE :
{alert['source_ip']}

PORT SOURCE :
{alert['source_port']}

IP DESTINATION :
{alert['destination_ip']}

PORT DESTINATION :
{alert['destination_port']}

TRANSPORT :
{alert['transport']}

PROCESSUS :
{alert['process']}

COMMANDE :
{alert['command']}

UTILISATEUR :
{alert['user']}

RAISON ELASTIC :
{alert['reason']}

IMPORTANT :
- N'invente aucune information.
- Si une donnée vaut N/A, indique qu'elle n'est pas fournie.
- Le risk score n'est PAS une probabilité.
- Distingue toujours détection et interprétation IA.
- Ne considère pas automatiquement l'événement comme une attaque confirmée.

Réponds en français avec :

1. EXPLICATION
2. GRAVITE
3. INDICATEURS SUSPECTS
4. HYPOTHESES
5. ACTIONS SOC
6. CONCLUSION
"""

    headers = {
        "Authorization":
            f"Bearer {GROQ_API_KEY}",

        "Content-Type":
            "application/json"
    }

    data = {

        "model": GROQ_MODEL,

        "messages": [

            {
                "role": "system",
                "content":
                    "Tu es un analyste SOC professionnel."
            },

            {
                "role": "user",
                "content": prompt
            }
        ],

        "temperature": 0.2,

        "max_completion_tokens": 1500
    }

    response = requests.post(
        url,
        headers=headers,
        json=data,
        timeout=60
    )

    response.raise_for_status()

    result = response.json()

    return result["choices"][0]["message"]["content"]


# ============================================================
# CONSTRUCTION DU MAIL
# ============================================================

def build_email(alert, analysis, count=1, suppressed=0):

    subject = (
        f"[ARGUS] "
        f"[{alert['severity'].upper()}] "
        f"{alert['rule_name']}"
    )

    aggregation = ""

    if count > 1 or suppressed:

        aggregation = f"""
------------------------------------------------------------
AGRÉGATION
------------------------------------------------------------

Alertes dans ce lot :
{count}

Alertes antérieures non notifiées (cooldown) :
{suppressed}

Rappel : au plus un e-mail par règle toutes les
{RULE_COOLDOWN_MINUTES:g} minutes.
"""

    body = f"""
ARGUS
============================================================

🚨 ALERTE DE SECURITE
{aggregation}
Règle :
{alert['rule_name']}

Sévérité :
{alert['severity']}

Risk Score :
{alert['risk_score']}

Statut :
{alert['status']}

Machine :
{alert['host']}

Timestamp :
{alert['timestamp']}

------------------------------------------------------------
INDICATEURS
------------------------------------------------------------

IP source :
{alert['source_ip']}

Port source :
{alert['source_port']}

IP destination :
{alert['destination_ip']}

Port destination :
{alert['destination_port']}

Transport :
{alert['transport']}

Processus :
{alert['process']}

Commande :
{alert['command']}

Utilisateur :
{alert['user']}

------------------------------------------------------------
RAISON DE LA DETECTION ELASTIC
------------------------------------------------------------

{alert['reason']}

------------------------------------------------------------
ANALYSE ARGUS / GROQ
------------------------------------------------------------

{analysis}

============================================================
Notification automatique ARGUS
============================================================
"""

    return subject, body


# ============================================================
# ENVOI SMTP
# ============================================================

def send_email(subject, body):

    message = MIMEMultipart()

    message["From"] = SMTP_FROM
    message["To"] = SMTP_TO
    message["Subject"] = subject

    message.attach(
        MIMEText(
            body,
            "plain",
            "utf-8"
        )
    )

    with smtplib.SMTP(
        SMTP_HOST,
        SMTP_PORT,
        timeout=30
    ) as server:

        if SMTP_STARTTLS:

            server.starttls()

        server.login(
            SMTP_USERNAME,
            SMTP_PASSWORD
        )

        server.sendmail(
            SMTP_FROM,
            SMTP_TO,
            message.as_string()
        )


# ============================================================
# TRAITEMENT
# ============================================================

def process_alert(hit, count=1, suppressed=0):

    alert_id = hit.get("_id")

    source = hit.get(
        "_source",
        {}
    )

    alert = extract_alert(
        source
    )

    print()
    print("=" * 70)
    print("NOTIFICATION D'ALERTE ELASTIC SECURITY")
    print("=" * 70)

    print(
        f"ID        : {alert_id}"
    )

    print(
        f"Règle     : {alert['rule_name']}"
    )

    if count > 1 or suppressed:

        print(
            "Agrégation : "
            f"{count} alerte(s) dans ce lot"
            + (
                f", {suppressed} alerte(s) précédente(s) non notifiée(s)"
                if suppressed else ""
            )
        )

    print(
        f"Sévérité  : {alert['severity']}"
    )

    print(
        f"Risque    : {alert['risk_score']}"
    )

    print(
        f"Machine   : {alert['host']}"
    )

    print(
        f"Source IP : {alert['source_ip']}"
    )

    print()
    print("Analyse Groq...")

    analysis = ask_groq(
        alert
    )

    print("Analyse Groq terminée.")

    subject, body = build_email(
        alert,
        analysis,
        count=count,
        suppressed=suppressed
    )

    print("Envoi du mail...")

    send_email(
        subject,
        body
    )

    print("OK - Mail envoyé.")

    return alert_id


# ============================================================
# BOUCLE PRINCIPALE
# ============================================================

def main():

    print("=" * 70)
    print("      ARGUS - EMAIL MONITOR")
    print("=" * 70)

    check_configuration()


    print()
    print(
        f"Surveillance : {ALERT_INDEX}"
    )

    print(
        f"Intervalle   : {POLL_INTERVAL} secondes"
    )

    print(
        f"Destinataire : {SMTP_TO}"
    )

    print()
    print(
        "Service prêt. Surveillance automatique..."
    )

    state = load_state()

    while True:

        try:

            hits = get_new_alerts(state)

            # Premier demarrage sans etat : on se cale sur la
            # derniere alerte du lot (les hits sont tries par
            # horodatage croissant) pour ne pas re-envoyer tout
            # le backlog historique.
            if state is None:

                if hits:

                    newest = hits[-1]

                    state = {
                        "ts": (
                            newest.get("_source") or {}
                        ).get("@timestamp", ""),
                        "ids": {
                            newest.get("_id")
                        } - {None},
                        "rules": {}
                    }

                    save_state(state)

                    print(
                        "Etat initialise a l'horodatage :",
                        state["ts"]
                    )

                time.sleep(
                    POLL_INTERVAL
                )

                continue

            grouped = {}

            for hit in hits:

                alert_id = hit.get("_id")

                if not alert_id:
                    continue

                timestamp = (
                    hit.get("_source") or {}
                ).get("@timestamp", "")

                if (
                    timestamp == state["ts"]
                    and alert_id in state["ids"]
                ):
                    continue

                rule_name = extract_alert(
                    hit.get("_source") or {}
                )["rule_name"]

                grouped.setdefault(rule_name, []).append(
                    (hit, timestamp, alert_id)
                )

            if not grouped:

                time.sleep(POLL_INTERVAL)
                continue

            abort = False

            for rule_name, items in grouped.items():

                meta = state.setdefault(
                    "rules", {}
                ).setdefault(
                    rule_name,
                    {"last_sent": "", "suppressed": 0}
                )

                cooldown_ok = True

                if meta.get("last_sent"):

                    try:

                        sent_at = datetime.fromisoformat(
                            meta["last_sent"].replace(
                                "Z", "+00:00"
                            )
                        )

                        elapsed = (
                            datetime.now(timezone.utc) - sent_at
                        ).total_seconds()

                        cooldown_ok = (
                            elapsed
                            >= RULE_COOLDOWN_MINUTES * 60
                        )

                    except Exception:

                        cooldown_ok = True

                if cooldown_ok:

                    try:

                        process_alert(
                            items[-1][0],
                            count=len(items),
                            suppressed=meta.get("suppressed", 0)
                        )

                    except Exception as e:

                        print()
                        print(
                            "ERREUR traitement alerte :"
                        )

                        print(e)

                        traceback.print_exc()

                        # On ne valide PAS l'alerte comme
                        # traitée si l'envoi a échoué.
                        abort = True
                        break

                    meta["last_sent"] = (
                        datetime.now(timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z")
                    )
                    meta["suppressed"] = 0

                else:

                    meta["suppressed"] = (
                        meta.get("suppressed", 0)
                        + len(items)
                    )

                    print(
                        "[COOLDOWN] "
                        f"{rule_name} : "
                        f"{len(items)} alerte(s) en attente "
                        "(reportées dans le prochain envoi)"
                    )

                for _, timestamp, alert_id in items:
                    _mark_seen(
                        state,
                        timestamp,
                        alert_id
                    )

                save_state(state)

            if abort:

                time.sleep(POLL_INTERVAL)
                continue

            time.sleep(
                POLL_INTERVAL
            )

        except KeyboardInterrupt:

            print()
            print(
                "Arrêt demandé."
            )

            break

        except Exception as e:

            print()
            print(
                "ERREUR surveillance Elasticsearch :"
            )

            print(e)

            traceback.print_exc()

            time.sleep(
                POLL_INTERVAL
            )


# ============================================================
# POINT D'ENTREE
# ============================================================

if __name__ == "__main__":
    main()

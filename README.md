<h1 align="center">🛡️ ARGUS</h1>
<p align="center">
  <b>Analyse et Réponse Globales Unifiées pour la Sécurité</b><br>
  <i>SOC léger augmenté par IA pour un système d'information hospitalier</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Elastic%20Stack-9.1.3-005571?logo=elasticstack&logoColor=white">
  <img src="https://img.shields.io/badge/Docker-28.5.2-2496ED?logo=docker&logoColor=white">
  <img src="https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/LLM-Groq%20·%20gpt--oss--20b-F55036?logo=openai&logoColor=white">
  <img src="https://img.shields.io/badge/TLS-de%20bout%20en%20bout-success">
  <img src="https://img.shields.io/badge/données-laboratoire%20·%20test-informational">
</p>

> **Projet de fin de parcours — Analyste en cybersécurité, École des Métiers du Numérique (EMN).**
> Prototype fonctionnel né d'un stage au service SSI du **na**, reconstruit et validé en laboratoire personnel.
> ⚠️ Toutes les données sont **générées en environnement de test** — aucune donnée réelle, aucun secret réel n'est présent dans ce dépôt.

---

## 🎯 Le problème

Un hôpital dépend de systèmes qui doivent rester disponibles : une intrusion ou un rançongiciel peut bloquer la prise en charge des patients. Les équipes de surveillance, présentes 24h/24, doivent **comprendre vite chaque alerte**, alors que la majorité du bruit n'en est pas.

**Comment aider une équipe de surveillance à qualifier plus vite et plus sûrement les alertes, grâce à des outils ouverts et à une IA qui explique chaque alerte ?**

## 💡 La solution

Un serveur **Kali Linux** héberge la suite **Elastic 9.1.3** (Elasticsearch, Kibana, Fleet Server) dans Docker, avec chiffrement **TLS de bout en bout**. Il supervise deux postes (Ubuntu et Windows). Kibana exécute **chaque minute 7 règles de détection** (ES|QL). La couche **ARGUS** lit les alertes, les fait analyser par un **LLM (Groq, `gpt-oss-20b`)** via un **serveur MCP**, puis envoie un courriel à l'analyste. Un **chat** permet aussi d'interroger les données en langage naturel. **L'IA aide l'analyste sans jamais bloquer l'alerte.**

## 🏗️ Architecture

```
          Attaques encadrées (scan · brute SSH · DNS piégé · HTTP clair · service Windows)
                               │
        ┌──────────────────────┴───────────────────────┐
   Poste ubuntu-noa                              Poste desktop-k6eb242 (Windows)
   Elastic Agent + Elastic Defend                Elastic Agent + Elastic Defend
        └──────────────── journaux ────────────────────┘
                               ▼
   ┌───────────────── Serveur Kali Linux (Docker + systemd) ─────────────────┐
   │  Fleet Server   ·   Packetbeat (capteur réseau)   ·   Elasticsearch 9.1.3 │
   │                                        │ (stockage, TLS)                   │
   │                                        ▼                                   │
   │                         Kibana — Elastic Security                         │
   │                         (7 règles de détection ES|QL)                     │
   └────────────────────────────────┬──────────────────────────────────────────┘
                                     │ lecture des alertes
   ┌───────────────── Couche ARGUS (services systemd) ──────────────────────┐
   │   Serveur MCP (4 outils)  ──►  Groq · openai/gpt-oss-20b (API externe)  │
   │        │                                                                │
   │   Agent de notification (courriel)      Chat web (langage naturel)      │
   └────────────────────────────────┬──────────────────────────────────────┘
                                     ▼
                               Analyste SOC
```

*(Schéma détaillé dans `docs/` — Livrable 3, figure 1.)*

## 🧩 Composants et versions

| Composant | Version | Rôle | Emplacement |
|---|---|---|---|
| Elasticsearch | 9.1.3 | Stockage, recherche, moteur d'alerte | Docker · `127.0.0.1:9200` |
| Kibana (Elastic Security) | 9.1.3 | Règles, alertes, tableaux de bord, Fleet | Docker · `127.0.0.1:5601` |
| Fleet Server | 9.1.3 | Enrôlement et pilotage des agents | Docker · `8220` |
| Packetbeat | 9.1.3 | Capteur réseau (flux, DNS, HTTP, TLS) | Serveur + poste Ubuntu |
| Elastic Agent | 9.1.3 | Collecte réseau + journaux système (dont Windows) | Postes Ubuntu & Windows |
| Elastic Defend | 9.1.3 | Protection des postes et événements process | Postes Ubuntu & Windows |
| Docker / Compose | 28.5.2 / 5.0.2 | Conteneurisation de la plateforme | Serveur |
| Python | 3.13 | Services ARGUS (MCP, chat, notification) | Serveur (venv) |
| Modèle de langage | `openai/gpt-oss-20b` | Analyse des alertes, compréhension des questions | Groq (API externe) |

> **Logstash a été retiré volontairement** : il ne faisait plus que découper des journaux déjà structurés par Packetbeat / Elastic Agent. Son retrait libère ~900 Mo de RAM (utile sur un serveur de 11 Gio) ; son rôle est repris par un pipeline d'ingestion Elasticsearch.

## 🔍 Moteur de détection — 7 règles ES|QL

| Règle | Détecte | Sévérité | MITRE |
|---|---|---|---|
| `argus-port-scan-host` | Scan de ports vu par le capteur du serveur | Élevée | T1046 |
| `argus-port-scan-vm` | Scan de ports depuis le poste Ubuntu | Élevée | T1046 |
| `argus-ssh-bruteforce-net` | Force brute SSH (volume vers le port 22) | Élevée | T1110 |
| `argus-ransomware-service-creation` | Service Windows créé depuis un dossier utilisateur | **Critique** | T1543.003 |
| `argus-dns-suspect` | Nom de domaine piégé (typosquatting) | Moyenne | T1071 |
| `argus-http-cleartext` | Données sensibles en HTTP non chiffré | Moyenne | — |
| `argus-sensitive-services` | Connexions vers des services sensibles | Élevée | — |

> Les règles sont **fondées sur le comportement** : un scan se reconnaît au nombre de **ports distincts** contactés, pas au volume de trafic — ce qui évite les faux positifs sur le trafic légitime.

## 📊 Résultats mesurés

| Indicateur | Résultat |
|---|---|
| Volume collecté | **11,7 millions** de documents (2 → 8 octobre 2026) |
| Scan contrôlé | **150 / 150 ports** retrouvés · **0 faux positif** sur 4 sources analysées |
| Délai de détection | **57 secondes** pour un scan de 302 ports |
| Autres attaques | Force brute SSH, HTTP en clair et domaine piégé **détectés** |
| Poste Windows | **19 alertes critiques** sur la création d'un service suspect |
| Chaîne complète | Attaque → alerte → analyse IA → courriel : **validée ✅** |

> Sur 11 930 alertes enregistrées, **11 834 provenaient de la première version (trop large) de la règle DNS**. Après correction, le vrai signal représente **96 alertes**. 👉 *Une règle qui se déclenche n'est pas forcément une bonne règle : il faut distinguer doublons mécaniques, bruit de fond et vraie détection.*

## 🔐 Sécurité & exposition réseau

- **TLS partout** : autorité de certification de laboratoire (RSA 2048, validité 825 j) ; chaque composant a son propre certificat. Une connexion en HTTP simple est **refusée**.
- **Exposition minimale** : la plupart des services n'écoutent que sur `127.0.0.1`. Les postes joignent le serveur par un **nom stable** (`argus-srv.lab` → `10.50.17.91`) porté par une interface virtuelle, indépendant du Wi-Fi ou du réseau VMware.
- **Secrets hors du code** ; clé de lecture seule pour les services ARGUS.

## ⚖️ Analyse des risques (ISO 27005)

Risque le plus fort pour le SI simulé : le **rançongiciel** (critique, 16). Viennent ensuite l'absence de supervision, l'exposition des services et la saturation disque (élevés, 12). Pour l'outil lui-même : les **faux négatifs**, l'**exposition du chat** (HTTP, à passer en HTTPS) et la **souveraineté des données** envoyées à un service d'IA externe — acceptable en laboratoire, à régler avant tout usage réel.

## 🚀 Installation (laboratoire)

```bash
# 1. Dépendances Python
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Secrets (ne jamais committer — voir elk/.env.example)
cp elk/.env.example elk/.env   # puis renseigner les valeurs

# 3. Plateforme Elastic (Docker)
cd elk && docker compose up -d

# 4. Services ARGUS (MCP, chat, notification)
sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now argus-*.service

# 5. Importer les règles de détection dans Kibana
#    regles/argus_rules.ndjson  →  Kibana > Security > Rules > Import
```

Simuler une vague d'attaques pour tester la chaîne :
```bash
bash scripts/tests/simuler_pic_alertes.sh
```

## 📁 Organisation du dépôt

```
argus/      code de l'application (serveur MCP, chat, agent de notification)
elk/        docker-compose, configurations, .env.example
regles/     export des règles SIEM (argus_rules.ndjson)
scripts/    scripts de déploiement et de test (dont tests/)
systemd/    unités de service
docs/       documentation technique et schémas
```

## 🧭 Limites & suites

Prototype limité : un seul nœud (cluster en état *yellow*), licence gratuite sans dédoublonnage des alertes, 7 règles, tests incomplets sur le poste Windows, chat en HTTP, matériel modeste.
**Prochaines étapes :** rejouer les scénarios sur Windows · harmoniser les données · ajouter une alerte « agent hors ligne » · héberger un modèle d'IA en local · entraîner un modèle **Isolation Forest** pour la détection d'anomalies.

---

<p align="center">
  <b>Nazifath ADJIBADE</b> — Analyste en cybersécurité · École des Métiers du Numérique · 2025-2026<br>
  <a href="https://www.linkedin.com/in/nazifath-adjibade-a30035272">LinkedIn</a>
</p>

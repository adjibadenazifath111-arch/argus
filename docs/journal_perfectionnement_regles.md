# Journal de perfectionnement des règles de détection

Document de traçabilité destiné à la soutenance. Il conserve **volontairement** les
résultats initiaux et les erreurs commises, afin de démontrer la démarche
d'analyse plutôt qu'un état final « propre et sans histoire ».

Stack : Elastic 9.1.3 / Kibana 9.1.3 — **licence Basic**.

---

## 1. Ce que nécessite la création d'une règle de détection sur cette stack

Sept prérequis, testés un par un. Les trois premiers sont ceux qui font échouer
la majorité des implémentations.

| # | Prérequis | Conséquence si ignoré |
|---|---|---|
| 1 | Vérifier qu'un champ existe **en documents**, pas seulement dans le mapping | `winlog.event_data.CommandLine`, `process.executable`, `file.extension` sont mappés mais comptent **0 document** |
| 2 | Valider la syntaxe ES|QL **côté serveur** avant de créer la règle | `+` est l'addition arithmétique, pas la concaténation : il faut `CONCAT()` |
| 3 | Aligner la fenêtre de recherche sur l'intervalle d'exécution | fenêtre 24 min + intervalle 1 min ⇒ l'événement est vu ~24 fois |
| 4 | Établir un **baseline à 0 faux positif** avant d'ajouter la logique de détection | impossible de distinguer une vraie détection du bruit ambiant |
| 5 | Cibler le **bon data stream** | les données réelles sont dans `logs-network_traffic.*`, pas `packetbeat.*` |
| 6 | Connaître l'**index de destination des alertes** | `.internal.alerts-security.alerts-default-000001`, et non l'index de paramètres |
| 7 | Vérifier les **capacités de la licence** | la déduplication d'alertes et la purge sont indisponibles en Basic |

---

## 2. Règle ransomware — avant / après

Règle : `argus-ransomware-service-creation`
UUID : `b062b7e7-450c-4737-91ed-4f804dde62e9`
MITRE : T1543.003 — *Create or Modify System Process: Windows Service*

### 2.1 Résultat initial

Le premier jets de la règle a produit **une alerte par minute**, pour un unique
service créé :

```
04:09:11  alerte 1
04:10:11  alerte 2
04:11:11  alerte 3
04:12:11  alerte 4
04:13:11  alerte 5
```

Lecture naïve : « la règle fonctionne ». **Interprétation erronée.** Le
comportement observé est la conséquence mécanique d'une fenêtre de 6 minutes
exécutée toutes les minutes : le même événement reste visible dans 5 fenêtres
successives, donc il est remonté 5 fois.

### 2.2 Hypothèses testées et écartées

| Hypothèse | Test | Verdict |
|---|---|---|
| La requête est en cause | ajout de `\| EVAL kibana.alert.group.by = CONCAT(...)` | **écartée** — 4 exécutions produisent toujours 4 alertes |
| `STATS ... BY` déduplique | inspection des 12 alertes des règles scan (qui utilisent `STATS`) | **écartée** — 6 exécutions = 6 alertes, 1 par source |
| Un index d'alertes mal ciblé masque les alertes | lecture de `.kibana_alerting_cases_9.1.3_001` | **écartée** — cet index ne contient que les paramètres des règles, pas les alertes |
| `last_run.alerts_count` reflète l'état | lecture du `last_run` de 04:18 | **écartée** — il ne décrit que la **dernière** exécution |

### 2.3 Cause racine

Licence **Basic**. Confirmé par deux sources :

- `/api/_license` → `type: basic`
- chaînes de traduction Kibana :
  `alertSuppressionRuleDetails.upsell` → *« La suppression d'alertes est
  configurée mais elle ne sera pas appliquée en raison d'une licence
  insuffisante »*

La déduplication d'alertes n'est donc pas activable. Trois tentatives de purge
ont échoué, toutes pour la même raison structurelle :

| Méthode | Résultat | Cause |
|---|---|---|
| `_delete_by_query` direct sur l'index d'alertes | `http=000` | écriture réinitialisée sur index système `hidden` |
| `/api/saved_objects/alert/{id}` | `404` | les alertes ne sont pas des saved objects en 9.1 |
| `/internal/alerting/alerts/_bulk_untrack_by_query` | `400` | *« pas disponible avec la configuration actuelle »* — **licence** |

L'écriture Elasticsearch par ailleurs fonctionne (`200` sur index de test), ce
qui exclut un problème de droits.

### 2.4 Résultat après perfectionnement

| Paramètre | Avant | Après |
|---|---|---|
| Fenêtre | `now-6m`, puis `now-24h` en diagnostic | **`now-6m`** (révision 2) |
| Intervalle | `1m` | `1m` |
| Clé de regroupement | absente | `CONCAT` + `COALESCE` sur champs nuls |
| Volume d'alertes | 1/minute, **19 au total** | stable, plus aucune génération |

### 2.5 Vérification de l'arrêt des doublons

L'événement de test date de `04:08:03`. Une fois la fenêtre revenue à `now-6m`,
il sort du périmètre de recherche :

```
T0      : 19 alertes
T0+2min : 19 alertes   -> stable
```

La fenêtre `now-24h` ne génère plus rien. Les **19 alertes sont conservées**
comme trace de l'état initial.

---

## 3. Le cas du champ inexistant — exemple de raisonnement à montrer

C'est l'exemple le plus parlant pour la soutenance : une règle pansée pour
détecter du ransomware et qui **n'aurait rien détecté du tout**.

Les champs nécessaires à une détection « ransom + IOC de ligne de commande »
ont été testés sur le poste réel :

| Champ recherché | Documents | Conséquence |
|---|---|---|
| `winlog.event_data.CommandLine` | **0** | les IOC `vssadmin delete shadows` et `wbadmin delete catalog` sont **inobservables** |
| `event.code: 4663` (accès aux objets) | **0** | la détection du chiffrement de masse est **impossible** |
| `process.executable` | **0** | aucun chemin d'exécutable à corréler |
| `file.extension` | **0** | aucune extension à filtrer |
| `process.name` | absent | aucune détection par nom de processus |

Les champs existent dans le mapping, donc une vérification par simple lecture du
mapping les aurait déclarés disponibles. **Le comptage de documents les a
révélés vides.**

Conséquence assumée : la règle détecte **uniquement** la persistance
(Event ID 7045), qui est le seul signal réellement disponible sur ce poste.
Les 21 services légitimes observés sont tous sous `C:\Program Files\`,
`C:\Windows\system32\` ou `\SystemRoot\` ; aucun ne provient d'un répertoire
modifiable par un utilisateur.

---

## 4. Le cas de la donnée network inexistante

Une règle d'exfiltration « > 500 Mo » a été écrite puis **abandonnée** :

| Mesure | Valeur |
|---|---|
| Flux sortants vers IP publique > 1 Mo | **0** |
| Flux > 500 Mo | 1, **entrant** : `185.125.190.27 → 172.16.182.246` (617 Mo) |
| `network.direction` interrogeable | **0 document** |

La règle ne aurait donc jamais alerté. Elle a été remplacée par une approche
détection/corrélation, et un transfert sortant réel doit être généré pour la
valider.

---

## 5. Enseignements retenus

1. **Un champ mappé n'est pas un champ populé.** Compter les documents avant
   d'écrire la condition.
2. **Valider la requête sur le serveur avant de créer la règle.** Une règle
   invalide est acceptée par l'API puis échoue silencieusement à l'exécution.
3. **Dimensionner la fenêtre sur l'intervalle**, ou accepter des doublons en
   série.
4. **Connaître sa licence.** Elle détermine ce qui est activable, pas le
   code écrit.
5. **Un baseline à 0** avant toute logique de détection.
6. **Un diagnostic peut dégrader la production.** La fenêtre `now-24h` a été un
   instrument de diagnostic qu'il fallait remettre en état ensuite.

---


## 7. Bruit environnemental identifié et conservé à des fins de démonstration

### 7.1 Bruit DNS – domaine `yaallah.rom`

Les requêtes cycliques observées vers le domaine `yaallah.rom` sont **des artefacts légitimes** issus d'anciens exercices Active Directory personnels. Elles ne constituent pas un indicateur de compromission.

**Patterns observés :**

| Requête | Signification |
|---|---|
| `wpad.yaallah.rom` | WPAD (Web Proxy Auto-Discovery) – recherche automatique d'un proxy |
| `DESKTOP-K6EB242.yaallah.rom` | Résolution du nom FQDN de la machine avec son suffixe DNS |
| `_ldap._tcp.*.dc._msdcs.yaallah.rom` | Recherches SRV Active Directory pour localiser un contrôleur de domaine (DC) |

**Caractéristiques techniques :**

- **Réponses** : systématiquement `NXDOMAIN` (Non-Existent Domain)
- **Fréquence** : cyclique, toutes les 1–2 minutes
- **Source unique** : `172.16.182.253` (VM Windows `DESKTOP-K6EB242`)
- **Aucun serveur DNS autoritaire** pour `yaallah.rom` dans l'environnement

**Décision de conservation volontaire**

Ce bruit est **conservé volontairement** dans notre jeu de données. L'objectif est d'illustrer lors de la soutenance la **phase de triage et de levée de doute** à laquelle un analyste SIEM est confronté au quotidien.

L'enjeu démonstratif est le suivant : face à un domaine non résolu apparaissant de manière répétitive, l'analyste doit savoir :

1. **Qualifier** le contexte (suffixe DNS de lab, découverte Windows)
2. **Vérifier** la nature des requêtes (WPAD/AD discovery vs. résolution vers un domaine externe suspect)
3. **Justifier** l'exclusion ou la surveillance en s'appuyant sur les faits observés

**Conclusion** : `yaallah.rom` est un artefact de configuration du laboratoire, non un IOC. Le conserver permet de montrer cette démarche critique de raisonnement analytique.

---

## 6. État figé au 2026-10-06

- Licence : **Basic**
- Règles créées : 3 (`argus-ransomware-service-creation`,
  `argus-port-scan-host`, `argus-port-scan-vm`, `argus-dns-suspect`, `argus-sensitive-services`, `argus-http-cleartext`)
- Alertes en base : **31** (19 ransomware, 12 scan) — **conservées volontairement**
- Règle ransomware : fenêtre `now-6m`, intervalle `1m`, révision 2
- Aucune action de notification configurée sur les règles

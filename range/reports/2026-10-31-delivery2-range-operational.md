# Rapport de livraison 2 — le laboratoire AETHERION est opérationnel

**Date :** 2026-10-31 · **Branche :** `arena/5f8d8b29-prism` (base `da6980a`)
**Machine :** 2 vCPU / 3 939 MB / Debian 12 · noyau 6.1.158+ / 21 GB disque
**Objet :** remplacer la conclusion « L1–L7 non constructibles » de la
livraison 1 par un laboratoire réellement exécuté, scénarisé et mesuré.

> Correction de périmètre, assumée : la livraison 1 concluait qu'aucun
> laboratoire n'était constructible faute de moteur de conteneurs. C'était vrai
> pour une conception à base de conteneurs. Ce n'était pas vrai pour le noyau :
> les *user namespaces* non privilégiés sont autorisés ici, et permettent de
> construire une isolation L3 réelle avec `unshare` + veth. Le laboratoire décrit
> ci-dessous existe, tourne, et refuse réellement des paquets.

Tout ce qui suit provient de commandes exécutées sur cette machine. Les
artefacts bruts sont versionnés dans `range/reports/artifacts/`.

---

## 1. Architecture déployée

```
                          (Internet réel : INJOIGNABLE)
                                     ║
  wan 10.10.0.2 ─────────────── dmz 10.60.0.10 ──────┬── mon 10.50.0.10
   decoy:9999                  proxy:8080            │    collector:9090
                                     │                │
                              corp 10.30.0.10 ────────┤
                               ci:8081                │
                                     │                │
                              edge 10.20.0.10 ────────┤
                        idp:8080, secrets:8090        │
                                     │                │
                              prod 10.40.0.10 ────────┘
        gateway:8080  tx:8081  wallet:8082  policy:8083
                          │                    │
             signer 10.40.3.10 ──── hsm 10.40.1.10      chain 10.40.2.10
                  signer:8084           hsm:8085        relayer:8086 + Anvil:8545
```

* **9 zones**, **12 liens**, construites par `range/lab/netlab.py` dans un seul
  arbre de processus `unshare -Urmn --map-root-user`.
* Chaque zone est un processus ancre `unshare -n sleep 86400` ; toutes les
  opérations passent par `nsenter -t <pid> -n`. (`ip netns add` est
  **inutilisable** ici : `/run/netns` n'est pas inscriptible même en root mappé.)
* Chaque lien est une paire veth avec des adresses de transit `/30` ; chaque
  côté installe **exactement une route `/32`** vers l'adresse canonique du pair.
  Aucune route par défaut, aucun forwarding, aucune route agrégée.
* Les adresses canoniques `/32` sont posées sur `lo` dans la zone, ce qui donne
  à chaque zone une identité stable sans dépendre de l'interface de sortie.
* **14 processus** : 13 services HTTP + 1 nœud Anvil.

Invariants réellement vérifiés (pas déclarés) :

| Invariant | Preuve |
| --- | --- |
| `hsm` n'a qu'un seul voisin (`signer`) | `/v1/isolation` : `hsm → signer` = `routed`, 7 autres = `unreachable` |
| `wan` ne parle qu'à `dmz` | idem, ligne `wan` |
| `mon` est une feuille stricte | `mon` joint 4 zones, aucune ne joint `mon` en retour hors liens déclarés |
| aucun accès Internet | `/v1/egress` : 9 zones × 3 cibles = 27 tentatives, **0 fuite** |
| matrice déclarée == matrice noyau | 72 paires, **0 écart** |

---

## 2. Inventaire des composants et versions

| Composant | Version / origine | Emplacement |
| --- | --- | --- |
| Debian GNU/Linux | 12 (bookworm), noyau 6.1.158+ | hôte |
| Python | 3.11.2 | hôte |
| OpenSSL | 3.0.20 (7 avr. 2026) | hôte, utilisé par signer/hsm/relayer |
| iproute2 | 6.1.0 (libbpf 1.1.2) | hôte |
| util-linux (`unshare`,`nsenter`) | 2.38.1 | hôte |
| SQLite | 3.40.1 (via `sqlite3` de la stdlib) | base `range/state/lab.db` |
| Anvil (Foundry) | **1.7.1** (`@foundry-rs/anvil`, npm) | `range/state/tools/anvil` |
| `range/lab/*` | ce dépôt, `__version__ = 1.0.0` | `range/lab/` |

Versions épinglées : `range/lab/tools/install-anvil.sh` (paramètre
`ANVIL_VERSION`, défaut 1.7.1, choisi pour rester comparable aux artefacts D2.5
gelés). Aucune dépendance Python externe : uniquement la bibliothèque standard.

---

## 3. État opérationnel de chaque composant

Statuts employés sans ambiguïté : **opérationnel** (testé de bout en bout),
**partiel** (fonctionne, périmètre réduit et documenté), **simulé**
(comportement imité, pas le logiciel réel), **documenté non déployé**.

| Composant | Zone | Statut | Preuve / limite |
| --- | --- | --- | --- |
| Tissu réseau (netns + veth) | toutes | **opérationnel** | 72 paires balayées, 0 écart ; `hsm`/`wan` confinés |
| `idp` | edge | **opérationnel** | login mot de passe + TOTP RFC-6238, JWT HS256 signé et vérifié, révocation, introspection |
| `secrets` | edge | **partiel** | stockage fichier 0400 + baux ; pas de KMS/OpenBao, pas de chiffrement au repos |
| `ci` | corp | **partiel** | pipeline local réel (sous-processus `git`/`make`), pas Gitea/Woodpecker |
| `dmz` | dmz | **opérationnel** | proxy HTTP réel, en-têtes `X-Forwarded-By`/`X-Real-IP` |
| `gateway` | prod | **opérationnel** | validation JWT, contrôle de scope, fixtures W-GW-1/2 |
| `tx` | prod | **opérationnel** | logique métier + chemin interne W-TX-1 |
| `wallet` | prod | **opérationnel** | registre SQLite, fenêtre de course réelle de 150 ms |
| `policy` | prod | **partiel** | ré-implémentation Python de la sémantique `tx.rego` ; OPA n'est pas présent |
| `signer` | signer | **opérationnel** | signature ECDSA P-256 via `openssl`, appelle le HSM |
| `hsm` | hsm | **simulé** | clés EC sur fichier + attributs applicatifs (`CKA_EXTRACTABLE=false`) ; **ce n'est pas un HSM matériel** |
| `relayer` | chain | **opérationnel** | vérifie la signature (`openssl dgst -verify`), refuse un digest déjà soumis, soumet le tx |
| Anvil | chain | **opérationnel** | nœud EVM réel, tx minée, reçu `status: 0x1` |
| `mon` | mon | **partiel** | ingestion + 9 règles d'alerte ; pas de moteur de corrélation SIEM |
| `decoy` | wan | **simulé** | collecteur isolé pour tentatives d'exfiltration |
| Kubernetes / k3s | — | **documenté non déployé** | aucun runtime de conteneurs sur l'hôte |
| Suricata / Zeek / osquery | — | **documenté non déployé** | pas de capture paquet ni de sonde noyau dans l'userns |
| SoftHSM2 | — | **documenté non déployé** | aucun binaire disponible ; remplacé par le magasin d'attributs ci-dessus |

---

## 4. Scénarios et niveau de complexité

| ID | Scénario | Chaîne traversée | Complexité | Cause publiée ? |
| --- | --- | --- | --- | --- |
| S1 | Rejeu de session entre zones | corp → dmz → gateway | moyen | oui |
| S2 | Scope CI trop large → signature de production | corp → dmz → gateway → tx → signer → hsm | **élevé** | oui |
| S3 | Double dépense concurrente sur le portefeuille | edge → tx → wallet | **élevé** | oui |
| S4 | Atteinte latérale DMZ → ports internes | dmz → tx | moyen | oui |
| S5 | Isolation HSM + attributs de clé | prod ↛ hsm ; signer → hsm | contrôle | oui |
| S6 | **Usurpation d'acteur par en-tête de debug** | corp → dmz → gateway → tx | **cause non divulguée** | **non** |
| S7 | Règlement de bout en bout vers la chaîne | prod → signer → hsm → chain | contrôle | oui |

Chaque scénario combine plusieurs familles de défauts : S2 réunit un scope
excessif, un défaut d'autorisation (`/v1/sign-only` authentifie sans autoriser)
et une gestion de secret trop grossière ; S3 réunit une erreur de logique
métier et une course d'état ; S6 réunit un en-tête de debug oublié et une
attribution d'audit fausse.

Tous les scénarios s'exécutent **dans** la zone concernée (`nsenter`), donc le
chemin réseau testé est le vrai : une zone sans lien ne peut pas atteindre la
cible, le noyau jette le paquet.

Procédure de chaque scénario : restauration du jeu de données initial
(soldes, registre, fenêtre de vélocité, révocation de clés) → exécution →
scellé de preuve (`scenario.json` + `alerts.jsonl` + `SHA256SUMS`).

---

## 5. Tests et résultats

Campagne complète : `python3 range/lab/campaign.py` → **code de sortie 0**,
20,3 s, 7 étapes. Rapport brut :
`range/reports/artifacts/campaign-2026-10-31.json`.

### 5.1 Démarrage à froid et santé

```
== 0. rebuild from scratch (destruction + restore)
   health: 13 | chain: True
   up -> up | health: 13 | chain: True
```

`up` retourne les 4 comptes Anvil : `0xf39f…2266` (source),
`0x7099…79c8` (destination), chain-id 31337.

### 5.2 Isolation (balayage actif, pas déclaratif)

```
== 2. isolation sweep
   consistent: True | pairs: 72 | mismatches: 0
```

Extrait observé (port fermé : `routed` = le noyau livrerait le paquet,
`unreachable` = aucune route) :

```
wan    {'dmz': 'routed'}
hsm    {'signer': 'routed'}
signer {'prod': 'routed', 'hsm': 'routed'}
mon    {'dmz','edge','corp','prod': 'routed'}   (et aucune route entrante)
```

### 5.3 Confinement Internet

```
== 2b. egress containment
   zones probed: 9 | leaks: 0 | isolated: True
```

27 tentatives TCP (1.1.1.1:443, 8.8.8.8:53, 93.184.216.34:80) depuis les
9 zones : toutes en `OSError`. Aucun paquet ne sort de l'hôte.

### 5.4 Scénarios — deux passes, reproductibilité

```
S1  attack_possible  / attack_possible  STABLE
S2  attack_possible  / attack_possible  STABLE
S3  attack_possible  / attack_possible  STABLE
S4  attack_possible  / attack_possible  STABLE
S6  attack_possible  / attack_possible  STABLE
S5  protected        / protected        STABLE
S7  protected        / protected        STABLE
```

Preuves vérifiables extraites des exécutions :

* **S2** — identité CI `ci-runner` (scope `ci:run secrets:read transfer:write`)
  obtient une signature de production :
  `signed_payload: FORGED-TRANSFER:3dbce9…`, `signature_prefix: 304502210097bccb…`,
  `policy_checked: false`.
* **S3** — deux débits concurrents acceptés sur un seul solde :
  `start 100 → observed 100`, deux réponses `200 mode=racy`, solde final 20,
  **`ledger_consistency: false`** (le destinataire est crédité deux fois, le
  portefeuille débité une fois).
* **S6** — l'acteur enregistré est `alice` alors que l'authentification est
  `user:ops1` : la piste d'audit désigne un innocent.
* **S5** — `prod → hsm` = port 0 (aucune route) et export de clé
  `HTTP 403 CKA_EXTRACTABLE=false`, alors que la signature via `signer` répond 200.
* **S7** — hash de transaction réel
  `0x5e3aef90…cd43c`, reçu `status: 0x1`, bloc `0x4`.

### 5.5 Mitigations — une à la fois, avec réversion

```
S1  fix=session_binding         -> blocked   (réverté: attack_possible)
S2  fix=gateway_sign_only_authz -> blocked   (réverté: attack_possible)
S3  fix=wallet_atomic           -> blocked   (réverté: attack_possible)
S4  fix=dmz_port_isolation      -> blocked   (réverté: attack_possible)
S6  fix=gateway_debug_header    -> blocked   (réverté: attack_possible)
```

Chaque correctif est un drapeau d'exécution réversible : aucune modification de
code entre la démonstration de la faille et sa correction, donc l'attribution
est démontrable. La réversion prouve que le correctif est bien la cause du
blocage, et non une coïncidence.

### 5.6 Destruction et restauration

```
== 5. reset
   health after reset: 13 | S2 regressed to: attack_possible
   restored: {'health': True, 'ephemeral_findings_cleared': True,
              'vulnerability_present_again': True}
```

`reset` détruit tous les namespaces, efface base, preuves, journaux, secrets,
drapeaux, puis reconstruit : 13 services sains, la vulnérabilité réapparaît.
Vérifié aussi au niveau processus : après `run.sh stop`, aucun `lab.services`,
aucun `labd`, aucun `anvil`, aucun socket résiduel.

### 5.7 Collecte de preuves et journalisation

```
(cd range/state/evidence/…/S2-… && sha256sum -c SHA256SUMS)
alerts.jsonl: OK
scenario.json: OK
```

Alertes réellement déclenchées pendant S2 :
`coarse_secret_read` (medium, 2×), `sign_without_policy` (high, 1×).
Chaque service émet un JSON par événement (fichier local + POST vers le
collecteur), le collecteur applique 9 règles et alimente `alerts.jsonl`.

### 5.8 Préservation du dépôt

```
== 8. preservation (tracked files untouched)
   changed tracked files: 0 | clean: True
```

48 fichiers suivis (hors `range/`) hachés en SHA-256 avant et après la
campagne : aucun changement, aucun ajout, aucune suppression. Ni le cœur PRISM
ni un dépôt CIEL ne sont touchés.

---

## 6. Limites d'isolation et de sécurité

| # | Limite | Conséquence | Atténuation en place |
| --- | --- | --- | --- |
| L-1 | Pas de filtrage paquet (nftables/iptables indisponibles dans l'userns) | la politique par **port** entre zones liées n'est pas appliquée par le noyau ; elle l'est par l'application (source autorisée, scope). S4 le démontre. | routes `/32` uniquement + contrôle d'origine applicatif (correctif `dmz_port_isolation`) |
| L-2 | Isolation logique, pas physique : même noyau | une faille noyau non publiée reste théoriquement franchissable | aucune charge hostile de type exploit noyau n'est autorisée dans le périmètre |
| L-3 | Services écrits pour le laboratoire | réalisme protocolaire, pas fidélité produit | chaque service documente sa fixture ; les produits réels restent « documenté non déployé » |
| L-4 | HSM simulé par fichiers de clés + attributs applicatifs | pas de protection matérielle, pas de PKCS#11 | export refusé et journalisé ; clé en 0400 |
| L-5 | Pas de capture réseau (Suricata/Zeek) | pas de détection L7 par sonde | journaux applicatifs + règles du collecteur |
| L-6 | CI simplifiée | pas de chaîne d'approvisionnement complète (artefacts, signatures, registre) | pipeline local réel, incident S2 reproductible |
| L-7 | Échelle mono-acteur, 2 vCPU | pas de charge concurrente réaliste au-delà de quelques requêtes | fenêtre de course réglée à 150 ms pour rester observable |
| L-8 | Aucun egress Internet | scénarios d'exfiltration limités à `decoy` | confinement mesuré (`/v1/egress`, 0 fuite) |
| L-9 | `reset` détruit les preuves | perte si l'export n'est pas fait | export versionné dans `range/reports/artifacts/` |
| L-10 | Secrets en clair sur disque (0400) | l'hôte est de confiance | aucun secret réel, aucun fonds réel, aucune clé réelle |

Aucun système de production n'est joignable, aucun portefeuille réel n'est
utilisé, aucune infrastructure tierce n'est contactée : le confinement a été
mesuré, pas supposé.

---

## 7. Ressources (mesurées)

| Ressource | Valeur mesurée |
| --- | --- |
| Processus | 14 (13 services + Anvil) |
| RSS total des services | **294,3 MB** |
| RSS par service | 19,5 – 21,3 MB |
| CPU | charge 1 min ≈ 0,22 en fonctionnement ; construction du tissu 1,1 s |
| RAM hôte | 3 940 MB au total, 3 517 MB disponibles pendant la campagne |
| Disque — état complet | 44,6 MB (dont 40 MB le binaire Anvil) |
| Disque — base SQLite | 57 KB |
| Disque — journaux | 5,9 KB par campagne |
| Disque — preuves | 6,2 KB par campagne |
| Réseau | 9 zones, 12 liens veth, 24 adresses de transit `/30`, 0 route par défaut |
| Durée | `up` ≈ 6 s ; campagne complète (7 étapes, 25 exécutions) ≈ 20 s ; `reset` ≈ 6 s |

Le laboratoire tient donc dans **< 512 MB de RAM** et **< 100 MB de disque**,
hors binaires d'outils.

---

## 8. Procédures : lancer, arrêter, réinitialiser, restaurer

```bash
# 1. Outil de chaîne (une seule fois, idempotent)
./range/lab/tools/install-anvil.sh

# 2. Démarrer le superviseur (arbre unshare, socket de contrôle)
./range/lab/run.sh start

# 3. Construire le tissu + démarrer 13 services + Anvil
./range/lab/ctl.py up

# 4. Vérifier
./range/lab/ctl.py status
./range/lab/ctl.py isolation
./range/lab/ctl.py egress
./range/lab/ctl.py metrics

# 5. Exécuter un scénario
./range/lab/ctl.py run S2

# 6. Appliquer / révoquer un correctif
./range/lab/ctl.py fix wallet_atomic
./range/lab/ctl.py fix wallet_atomic off

# 7. Détruire et reconstruire (restauration)
./range/lab/ctl.py reset

# 8. Campagne d'acceptation complète
python3 range/lab/campaign.py

# 9. Arrêt d'urgence (détruit namespaces, processus, socket)
./range/lab/run.sh stop
```

Restaurer depuis zéro : `run.sh stop && rm -rf range/state && run.sh start &&
ctl.py up && tools/install-anvil.sh`. Aucun état n'est conservé hors de
`range/state/`.

Arrêt d'urgence vérifié : après `run.sh stop`, `ps` ne montre plus ni
`lab.services`, ni `labd`, ni `anvil`, et `range/state/control.sock` a disparu.

---

## 9. Interface d'intégration AETHERION

Contrat complet et versionné : `docs/cyber-range/10-aetherion-interface.md`.
Résumé :

* **Transport** : socket UNIX `range/state/control.sock` (0600), HTTP/1.1 + JSON.
  Un socket UNIX est un objet de système de fichiers : l'orchestrateur le joint
  alors que le laboratoire reste injoignable depuis le réseau, y compris depuis
  ses propres zones.
* **Cycle de vie** : `POST /v1/up`, `/v1/down`, `/v1/reset` ; `GET /v1/health`.
* **Scénarios** : `GET /v1/scenarios`, `POST /v1/scenarios/{id}/run`.
* **Observation** : `GET /v1/status`, `/v1/topology`, `/v1/isolation`,
  `/v1/egress`, `/v1/metrics`, `/v1/evidence`, `/v1/notes`.
* **Correctifs** : `POST /v1/fix/{flag}` avec `{"enable": bool}`.
* **Vérification indépendante** : `POST /v1/verify` (relance S2/S3/S4 deux fois
  et compare les verdicts).
* **Verdicts** : `attack_possible`, `blocked`, `protected`, `inconclusive`.
* Aucune exécution de commande arbitraire, aucune lecture de fichier, aucun
  identifiant transporté : seules les actions énumérées existent.

Aucune modification de CIEL ni du cœur PRISM n'est nécessaire. Le contrat est
stable en `/v1` ; toute rupture imposera `/v2`.

---

## 10. Blocages restants et actions requises

| # | Blocage / action | Impact | Action requise |
| --- | --- | --- | --- |
| B-1 | Aucun runtime de conteneurs | Kubernetes, k3s, Cilium, Falco restent « documenté non déployé » | fournir un hôte avec Docker/containerd **ou** accepter la variante netns seule (celle livrée) |
| B-2 | Pas de filtrage paquet dans l'userns | politique par port non noyau (L-1) | hôte avec `CAP_NET_ADMIN` réel → nftables, puis rejouer S4 |
| B-3 | Suricata/Zeek/core d'osquery absents | détection réseau et hôte non démontrée | installer les paquets sur l'hôte de production du range |
| B-4 | HSM simulé | confiance cryptographique non matérielle | SoftHSM2 (paquet Debian) ou HSM réseau fictif à ajouter en zone `hsm` |
| B-5 | `build.sh` (conception conteneurs) refuse toujours sur cet hôte | la voie conteneurs reste non exécutable | même action que B-1 |
| B-6 | Preuves détruites par `reset` | perte si non exporté | export automatique avant `reset` (proposition : drapeau `--export`) |
| B-7 | Échelle mono-acteur | pas de test de charge réaliste | hôte ≥ 4 vCPU pour une campagne concurrente |
| B-8 | Interface non encore consommée par un orchestrateur réel | intégration non prouvée côté client | brancher CIEL/AETHERION sur `/v1` avec le client de référence `ctl.py` |

---

## Annexe — artefacts

| Fichier | Contenu |
| --- | --- |
| `range/lab/netlab.py` | zones, matrice, `Fabric` |
| `range/lab/common.py` | JWT, TOTP, bus de journaux, schéma SQLite, HTTP |
| `range/lab/services.py` | 13 services et fixtures W-* |
| `range/lab/scenarios.py` | 7 scénarios exécutables |
| `range/lab/labd.py` | superviseur + plan de contrôle v1 |
| `range/lab/ctl.py` | client de référence |
| `range/lab/campaign.py` | campagne d'acceptation (8 étapes) |
| `range/lab/run.sh` | cycle de vie |
| `range/lab/tools/install-anvil.sh` | installation épinglée d'Anvil |
| `range/reports/artifacts/campaign-2026-10-31.json` | résultats bruts de la campagne |
| `range/reports/artifacts/evidence-S2/`, `evidence-S6/` | preuves scellées + `SHA256SUMS` |

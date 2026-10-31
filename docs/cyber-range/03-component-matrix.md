# 03 — Matrice comparative des composants open source

**Version :** 1.0 — 2026-10-31
**Source de vérité :** `range/versions.lock.json` (épinglage) et `range/budget/tier-budget.json` (empreinte).
**Règle :** un composant absent de cette matrice ne peut pas entrer dans le laboratoire. Le vérificateur (`G1`) fait échouer la CI si un composant épinglé n'est pas mentionné ici.

## 1. Méthode de comparaison

Chaque famille a été comparée sur cinq critères, dans cet ordre :

1. **Fidélité** — le composant fait-il le vrai travail (protocole, format, sémantique), ou seulement semblant ?
2. **Coût** — RAM/CPU/disque sur un hôte ordinaire ; c'est le critère éliminatoire le plus fréquent.
3. **Licence** — compatible avec une étude et une redistribution documentaire (pas de BUSL/SSPL).
4. **Épinglabilité** — version et digest récupérables, donc reproductibles.
5. **Valeur pédagogique** — le composant produit-il des erreurs, journaux et comportements réels ?

Une option moins fidèle mais dix fois moins chère est retenue **si et seulement si** l'écart de fidélité est documenté (voir `08-realism-limits.md`).

## 2. Inventaire épinglé par couche


### L0

| Composant | Rôle | Version épinglée | Licence | Statut | RAM estimée |
| --- | --- | --- | --- | --- | --- |
| **Debian GNU/Linux** | Hypervisor-adjacent host OS for the whole range | 12 (bookworm) — or 13 at first build, decision recorded in the install log | DFSG-free | chosen | — |
| **Docker Engine (moby)** | Container runtime for layers L1–L4 | 29.9.2 | Apache-2.0 | chosen | — |

### L1

| Composant | Rôle | Version épinglée | Licence | Statut | RAM estimée |
| --- | --- | --- | --- | --- | --- |
| **Keycloak** | OIDC/SAML identity provider, TOTP and WebAuthn MFA, session and role model | 26.8.1 | Apache-2.0 | chosen for Tier B/C | — |
| **Authelia** | Lightweight SSO + TOTP/WebAuthn portal for Tier A | v4.39.28 | Apache-2.0 | chosen for Tier A | — |
| **Authentik** | Alternative IdP | 2026.8.5 | reported as NOASSERTION by the GitHub API; core is MIT with separately licensed enterprise features | alternative | — |
| **step-ca (smallstep)** | Internal CA: service mTLS certificates and short-lived SSH user certificates | v0.30.2 | Apache-2.0 | chosen | — |
| **OpenBao** | Secrets manager: dynamic DB credentials, PKI, transit, token/session revocation | v2.7.2 | MPL-2.0 | chosen (replaces HashiCorp Vault) | — |
| **SOPS + age** | Encrypted configuration secrets in git | sops v3.13.3 / age v1.3.2 | MPL-2.0 / BSD-3-Clause | chosen | — |

### L2

| Composant | Rôle | Version épinglée | Licence | Statut | RAM estimée |
| --- | --- | --- | --- | --- | --- |
| **k3s** | Kubernetes control plane for the app/sign/chain workloads | v1.37.1+k3s1 | Apache-2.0 | chosen for Tier B/C only | — |
| **k0s** | Alternative Kubernetes distribution | v1.37.1+k0s.0 | reported NOASSERTION | alternative | — |
| **kind** | Ephemeral Kubernetes for CI-side policy tests | v0.33.0 | Apache-2.0 | chosen (test-only) | — |
| **Cilium** | Network policy enforcement and flow visibility | v1.20.4 | Apache-2.0 | chosen when k3s is used | — |
| **Kyverno** | Admission policy on the cluster | v1.19.2 | Apache-2.0 | chosen | — |

### L3

| Composant | Rôle | Version épinglée | Licence | Statut | RAM estimée |
| --- | --- | --- | --- | --- | --- |
| **Gitea** | Internal source control with real team/permission model | v28.2.0 | MIT | chosen | — |
| **Woodpecker CI** | CI runner executing real pipelines with real secrets | v3.20.1 | Apache-2.0 | chosen | — |
| **Distribution (registry:2)** | Internal image registry | registry:2 (pin digest at first pull) | Apache-2.0 | chosen ⚠ pin non vérifié | — |
| **Trivy** | Image and dependency vulnerability scanning in the pipeline | v0.76.1 | Apache-2.0 | chosen | — |
| **gitleaks** | Secret scanning gate | v8.30.1 | MIT | chosen | — |
| **cosign (sigstore)** | Artifact signing and verification (keyless or key-based) | v3.1.4 | Apache-2.0 | chosen | — |

### L4

| Composant | Rôle | Version épinglée | Licence | Statut | RAM estimée |
| --- | --- | --- | --- | --- | --- |
| **Open Policy Agent** | Business authorisation policy for transactions (amount, destination, quorum, velocity) | v1.22.0 | Apache-2.0 | chosen | — |
| **SoftHSM v2** | PKCS#11 cryptographic module emulating an HSM (key objects, sessions, CKA_EXTRACTABLE, CKA_SENSITIVE) | 2.6.1 | BSD-2-Clause | chosen ⚠ pin non vérifié | — |

### L5

| Composant | Rôle | Version épinglée | Licence | Statut | RAM estimée |
| --- | --- | --- | --- | --- | --- |
| **Anvil (Foundry)** | Local EVM chain with deterministic state, snapshots and time control | 1.7.1 (forge/anvil/cast), same build used for D2.5 Stage 1 | Apache-2.0 / MIT | chosen | — |
| **Alchemy Modular Account v2.0.0** | Programmable account (ERC-4337 / ERC-6900, incl. EIP-7702 variant) under study | bd75c9eca7ff5a66aaebc3cf2dab43ddc4622482 | GPL-3.0 | chosen, REUSED UNMODIFIED | — |
| **eth-infinitism/account-abstraction** | ERC-4337 EntryPoint and account interfaces | v0.7.0 (commit d99245ddb2d7bde4d2132757c4394818f1d11da0) | GPL-3.0 | chosen | — |
| **Alto (Pimlico)** | ERC-4337 bundler / relayer | @pimlico/alto@0.0.19 | GPL-3.0 | chosen | — |

### L6

| Composant | Rôle | Version épinglée | Licence | Statut | RAM estimée |
| --- | --- | --- | --- | --- | --- |
| **Suricata** | Network intrusion detection on the zone-to-zone links | 8.0.8 | GPL-2.0 | chosen | — |
| **Zeek** | Connection/protocol metadata and file extraction | v9.0.1 | BSD-3-Clause | Tier B/C only | — |
| **Falco** | Runtime detection in containers/Kubernetes | agent/0.85.1 | Apache-2.0 | chosen | — |
| **osquery** | Host state inventory and periodic telemetry | 5.24.0 | Apache-2.0 / GPL-2.0 dual | chosen | — |
| **Grafana Loki** | Log aggregation | v3.7.9 | AGPL-3.0 | chosen | — |
| **Grafana** | Dashboards and alerting | v13.3.0 | AGPL-3.0 | chosen | — |
| **Prometheus** | Metrics and detection-latency measurement | v3.15.1 | Apache-2.0 | chosen | — |
| **Grafana Alloy** | Log/metric collection agent | v1.21.3 | Apache-2.0 | chosen | — |
| **Wazuh** | Full SIEM/HIDS alternative (manager + indexer + dashboard) | v4.14.9 | GPL-2.0 | alternative, Tier C only | — |
| **tcpdump / tshark** | Packet capture and PCAP forensics | host-distribution pinned versions (recorded in the install log) | BSD-3-Clause / GPL-2.0 | chosen ⚠ pin non vérifié | — |

### L7

| Composant | Rôle | Version épinglée | Licence | Statut | RAM estimée |
| --- | --- | --- | --- | --- | --- |
| **Velociraptor** | Endpoint forensic collection and hunting | v0.77.3 | AGPL-3.0 | Tier B/C only | — |

## 3. Comparaisons détaillées des familles critiques

### 3.1 Fournisseur d'identité : Keycloak vs Authentik vs Authelia

| Critère | **Keycloak** 26.8.1 | Authentik 2026.8.5 | **Authelia** 4.39.28 |
| --- | --- | --- | --- |
| Fidélité entreprise (RBAC fin, fédération, mappers) | très élevée | élevée | moyenne |
| RAM | 700–1400 MB | 500–900 MB | **40–120 MB** |
| Licence | Apache-2.0 | MIT + modules entreprise séparés | Apache-2.0 |
| Verdict | **Tier B/C** | écarté par défaut | **Tier A** |

**Décision :** Tier A utilise Authelia (même surface OIDC/WebAuthn/TOTP pour 5 % du coût) ; Tier B/C utilise Keycloak. Les expériences de granularité de rôles et d'administration déléguée n'existent **que** sur Tier B/C — c'est écrit dans les limites, pas caché.

### 3.2 Gestionnaire de secrets : Vault vs OpenBao

| Critère | HashiCorp Vault 2.2.1 | **OpenBao** 2.7.2 |
| --- | --- | --- |
| Licence | BUSL-1.1 → **incompatible politique** | **MPL-2.0** |
| API | référence | compatible (fork MPL) |
| Verdict | écarté | **retenu** |

Même API, mêmes mécanismes (tokens, baux, révocation, moteur PKI, transit), licence propre. La révocation — cœur des scénarios de réponse — est donc testée sur un vrai moteur de baux.

### 3.3 CI/CD : GitLab CE vs Gitea + Woodpecker

GitLab CE apporte la fidélité maximale mais consomme **≥ 6 GB de RAM à lui seul**, soit 40 % du Tier A et 20 % du Tier B. Gitea (MIT) + Woodpecker (Apache-2.0) reproduisent le problème d'autorisation qui nous intéresse — identités de service, clés de déploiement, portée des secrets, runner avec droits de déploiement — pour ~0,5 GB.

**Écart assumé :** pas de « protected branches + code owners » aussi profonds que GitLab, pas de runners autoscalés. Documenté en L-6.

### 3.4 SIEM : Wazuh vs pile Loki/Prometheus/Grafana

| Critère | Wazuh 4.14.9 | **Loki + Prometheus + Grafana + Alloy** |
| --- | --- | --- |
| Sémantique SIEM (décodeurs, règles, listes CDB) | riche | partielle : requêtes LogQL/PromQL |
| RAM | 4000–8000 MB | 700–1900 MB |
| Verdict | **Tier C** | **Tier A/B** |

**Décision :** le Tier A/B mesure la latence de détection avec les règles écrites côté Suricata/Falco et des alertes Grafana — donc de vraies règles, mais sans la couche de corrélation d'un SIEM complet. Les métriques MTTD restent valides pour les détections implémentées, et ne doivent pas être extrapolées aux détections non implémentées.

### 3.5 Émulation HSM : SoftHSM v2

Seule option libre sérieuse pour PKCS#11. Elle implémente réellement les objets de clé, les sessions, `CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_ALWAYS_AUTHENTICATE` et les rôles SO/user. Elle **ne** fournit pas : anti-extraction matérielle, résistance aux canaux auxiliaires, attestation, ni destruction physique. Conséquence directe : un scénario ne peut pas prouver qu'une clé est inexportable ; il peut seulement vérifier que la politique PKCS#11 et l'usage applicatif respectent les attributs configurés.

### 3.6 Chaîne et comptes : réutilisation de la cible D2.5

Anvil (Foundry 1.7.1) + Alchemy Modular Account v2.0.0 (`bd75c9e…`) + EntryPoint `v0.7.0` + Alto `0.0.19`.

| Choix | Motif |
| --- | --- |
| Anvil plutôt que geth/besu | démarrage instantané, snapshots, contrôle du temps, même toolchain que D2.5 |
| Compte modulaire v2.0.0 | déjà validé : 228 fichiers compilés, 292 tests, artefacts reproductibles |
| EntryPoint v0.7.0 et non v0.9.0 | c'est exactement la version du `pnpm-lock.yaml` de la cible : on hérite d'un graphe validé au lieu d'en inventer un |
| Alto | bundler maintenu ; l'alternative eth-infinitism (v0.6.0, 2023) est plus ancienne que l'EntryPoint |

Le compte modulaire est traité comme **dépendance tierce en lecture seule** : jamais édité, jamais vendu au dépôt, jamais patché. Le vérificateur `H3` refuse de valider si l'arbre de la cible est modifié.

## 4. Composants écartés et motif


* **HashiCorp Vault** (v2.2.1 (2026-10-22)) — BUSL-1.1 licence conflicts with the open-source-only policy; OpenBao provides the same API under MPL-2.0.
* **HashiCorp Terraform** (v1.17.1 (2026-10-28)) — BUSL-1.1; OpenTofu v1.13.5 (MPL-2.0) is the drop-in alternative if infrastructure-as-code is adopted in L2.
* **Security Onion** — Needs 16 GB+ RAM minimum for a usable deployment; excluded from all tiers but kept in the matrix as the ceiling reference.
* **GitLab CE** — 6 GB+ RAM alone; the same CI-authorisation findings are obtainable with Gitea + Woodpecker at ~0.5 GB.
* **Cloud HSM / real HSM** — Cost and third-party dependency; explicitly out of scope. SoftHSM emulation is documented as the fidelity gap, not papered over.

## 5. Ce que la matrice ne prouve pas

* Les empreintes RAM sont des **estimations** issues de la documentation des projets et de l'ordre de grandeur mesuré en D2.5, pas des mesures de ce laboratoire. Elles seront remplacées par des mesures réelles après le premier build (`range/reports/`).
* Trois pins ne sont pas vérifiés par une source d'API (SoftHSM v2, `registry:2`, tcpdump/tshark). Ils sont marqués `unverified` et ne peuvent pas entrer dans une couche validée sans résolution du digest/checksum à la construction.
* La présence d'un composant dans cette matrice ne signifie pas qu'il est configuré de façon sûre : la configuration initiale est volontairement **imparfaite** (voir fixtures) pour que les scénarios aient un objet.


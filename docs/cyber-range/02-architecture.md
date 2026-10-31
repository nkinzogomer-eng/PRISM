# 02 — Architecture technique du PRISM Cyber Range

**Version :** 1.0 (conception) — 2026-10-31
**Portée :** architecture cible, indépendante de la machine de conception.
**Règle :** ce document et `range/network/nftables-range.nft` doivent rester d'accord. Le vérificateur échoue en cas de dérive.

---

## 1. Principe directeur

Le laboratoire doit reproduire les **mécanismes** d'une plateforme centralisée d'actifs numériques — identité, autorisation, signature, chaîne, télémétrie — pas son échelle. Chaque couche est donc construite avec le vrai logiciel du marché, à la plus petite taille qui conserve le mécanisme.

Trois conséquences assumées :

1. **Peu de composants, mais de vrais composants.** Un OPA, un vrai IdP OIDC, un vrai module PKCS#11 valent mieux que dix services factices.
2. **Les erreurs de configuration sont des données de scénario**, versionnées, pas des applications écrites pour être vulnérables (voir `30-fixture-rbac-misconfig.yaml`).
3. **Ce qui n'est pas modélisé est déclaré** (`08-realism-limits.md`), jamais imité en silence.

## 2. Couches

| Couche | Contenu | Réalité | Rôle vis-à-vis des scénarios |
| --- | --- | --- | --- |
| **L0** | Hôte Debian, moteur de conteneurs, SOPS+age, horloge unique | réel | socle, horodatage, hygiène des secrets |
| **L1** | IdP OIDC (Keycloak/Authelia), PKI interne (step-ca), secrets (OpenBao), accès (jump SSH), postes | réel | point de départ de la chaîne : identité et session |
| **L2** | Kubernetes (k3s), Cilium, Kyverno | réel | RBAC, admission, politique réseau interne |
| **L3** | Forge (Gitea), CI (Woodpecker), registre, analyse (Trivy, gitleaks, cosign) | réel | chaîne d'approvisionnement, identités de service |
| **L4** | Transaction, wallet, signer, SoftHSM (PKCS#11), OPA, PostgreSQL | réel + 1 émulation | autorisation et signature |
| **L5** | Anvil, compte modulaire (cible D2.5, non modifiée), EntryPoint, bundler Alto, relayer | réel local | transaction et règlement |
| **L6** | Suricata, Zeek, Falco, osquery, Loki, Prometheus, Grafana, Alloy | réel | détection, latence, journaux partiels |
| **L7** | Velociraptor, PCAP, tcpdump/tshark, playbooks de réponse | réel | forensique, confinement, récupération |

## 3. Zones de confiance

Six zones, chacune un pont réseau Docker avec son sous-réseau, plus un plan de gestion hors laboratoire.

| Zone | Sous-réseau | Contenu | Niveau de confiance |
| --- | --- | --- | --- |
| `rg-wan` | 10.10.0.0/24 | « monde extérieur » simulé : RPC de chaîne, leurres, exfiltration vers un écouteur factice | **non fiable, hostile** |
| `rg-edge` | 10.20.0.0/24 | jump SSH, IdP, PKI, secrets | semi-fiable : point d'entrée des humains |
| `rg-corp` | 10.30.0.0/24 | postes dev/admin, forge, CI, registre | semi-fiable : compromission attendue |
| `rg-prod` | 10.40.0.0/24 | transaction, wallet, signer, HSM, chaîne, bundler, relayer | **cœur de valeur** |
| `rg-mon` | 10.50.0.0/24 | SIEM, logs, métriques, collecte forensique | fiable, en lecture seule vers les autres |
| `rg-dmz` | 10.60.0.0/24 | proxy inverse exposant l'« API publique d'échange » | exposé |
| `rg-mgmt` | 10.99.0.0/24 | administration de l'hôte | hors scénarios |

## 4. Matrice de flux (résumé)

Autorisé, et rien d'autre :

| De | Vers | Ports | Justification |
| --- | --- | --- | --- |
| `rg-corp` | `rg-edge` | 443, 9091 | SSO, PKI |
| `rg-corp` | `rg-dmz` | 443 | API publique |
| `rg-edge` | `rg-corp`, `rg-dmz`, `rg-mon` | selon service | administration, télémétrie |
| `rg-edge` | `rg-prod` (hors HSM) | 8080/8081/8545 | proxy d'exploitation |
| `rg-dmz` | `rg-prod` (hors HSM) | 8080, 8081, 8545 | API → services |
| `rg-prod` interne | signer → HSM | 5657 | **seul flux autorisé vers le HSM** |
| `rg-mon` | toutes zones | 9100, 514, 5778 | collecte en lecture seule |
| `rg-wan` | toutes zones internes | — | **explicitement refusé** (initiation entrante) |

Invariants encodés dans le jeu de règles : `I1` refus par défaut partout, `I2` aucune zone ne joint Internet réel (seuls DNS/NTP internes sortent), `I3` `rg-prod` n'accepte que `rg-edge` et `rg-mon`, `I4` `rg-corp` ne joint jamais `rg-prod` directement, `I5` le HSM n'accepte que le signer, `I6` la supervision est en lecture seule.

## 5. Chaîne de référence (scénario Binance)

```
[poste compromis] --session OIDC--> [IdP] --token--> [API interne]
       |                                |                 |
       |                                v                 v
       |                          [secrets/signer] --> [autorisation OPA]
       |                                                    |
       v                                                    v
[CI / forge / registre] --------------------------> [signature PKCS#11]
                                                            |
                                                            v
                                          [chaîne locale Anvil] --> [transfert]
                                                            |
                                                            v
                                              [télémétrie L6] --> [réponse L7]
```

Les cinq maillons testables séparément : identité → services internes → autorisation → signature → transfert, puis détection/réponse. `07-scenario-catalogue.md` leur associe S1–S5, et S6–S8 couvrent la vérification indépendante.

## 6. Séparation des plans

| Plan | Contenu | Accessible depuis |
| --- | --- | --- |
| Données | `rg-prod`, `rg-mon` | services uniquement |
| Gestion | `rg-mgmt` (hôte, hyperviseur) | opérateur uniquement, hors scénarios |
| Attaque | postes `rg-corp` compromis | scénarios uniquement |
| Preuve | journaux L6/L7 + captures | vérificateur indépendant |

Le vérificateur indépendant ne partage **aucune** identité avec la Red Team ni la Blue Team : il lit les preuves, rejoue les scénarios et recalcule les métriques sur des données brutes (`06-security-boundaries.md` §5).

## 7. Deux anneaux d'isolation, volontairement différents

C'est un choix de conception, pas un oubli :

* **Anneau externe — nftables** (`range/network/nftables-range.nft`) : s'applique au trafic entre ponts. Un pod `hostNetwork`, une image compromise ou un conteneur privilégié **ne peut pas** le contourner.
* **Anneau interne — NetworkPolicy Kubernetes** (`range/k8s/10-network-policy.yaml`) : s'applique entre pods. Il **peut** être contourné (hostNetwork, kube-proxy, cas particuliers).

Ce différentiel est un objet d'étude : la Blue Team doit découvrir que sa politique interne ne suffit pas, et la Red Team doit pouvoir le prouver. Uniformiser les deux anneaux supprimerait une leçon de sécurité réelle.

## 8. Segmentation temporelle : snapshots et concurrence

* Chaîne : `anvil_snapshot`/`anvil_revert` et `--state-interval` pour rejouer un état exact.
* Tokens : TTL courts (5–15 min) pour que la fenêtre d'usage d'un jeton volé soit mesurable.
* Base : transactions PostgreSQL + jeu de données de départ figé (`fixtures/`, généré par script, checksum dans le registre).
* Horloge : **une seule** source NTP interne. Sans cela, MTTD/MTTR ne sont pas comparables entre scénarios.

## 9. Ce que l'architecture n'inclut pas, et pourquoi

| Absent | Raison | Où c'est dit |
| --- | --- | --- |
| HSM matériel / cloud HSM | coût, dépendance tierce | `08-realism-limits.md` L-1 |
| Chaînes réelles, RPC publics, forks mainnet | interdiction explicite ; aucune interaction réelle | `06-security-boundaries.md` §1 |
| Wazuh par défaut | 4–8 GB à lui seul | `03-component-matrix.md` |
| Kubernetes en Tier A | budget | `04-resource-budget.md` |
| Applications « intentionnellement vulnérables » | exigence de fidélité | §1 règle 2 |
| CIEL | orchestrateur futur, jamais dépendance du noyau | `09-risks.md` R-7 |

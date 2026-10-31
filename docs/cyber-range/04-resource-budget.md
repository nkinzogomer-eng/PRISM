# 04 — Budget de ressources et coûts

**Version :** 1.0 — 2026-10-31
**Source :** `range/budget/tier-budget.json` (machine-lisible, vérifié par `B2`).
**Nature des chiffres :** **estimations de dimensionnement**, pas des mesures de ce laboratoire, sauf la ligne D2.5 explicitement mesurée.

---

## 1. Trois paliers, un seul objectif : pouvoir commencer petit

| Palier | Cible matérielle | Ce qu'on peut y faire | Ce qu'on ne peut pas y faire |
| --- | --- | --- | --- |
| **A — Analyste** | 8 vCPU / 16 GB / 200 GB | Compose, SSO léger, PKCS#11, OPA, chaîne, bundler, télémétrie légère | Kubernetes, RBAC/admission, Zeek, forensique étendue |
| **B — Laboratoire** | 16 vCPU / 32 GB / 400 GB | + k3s/Cilium/Kyverno, Suricata, Zeek, Falco, Velociraptor | Wazuh complet, 2 VM isolées |
| **C — Complet** | 24 vCPU / 64 GB / 1 TB | tout, y compris Wazuh et isolation par VM | — |

## 2. Sommes vérifiées automatiquement

Somme des empreintes hautes des services par palier, comparée à la capacité utile (RAM totale − réserve hôte) :

| Palier | RAM min → max (est.) | Capacité utile | CPU (parts) | Disque (est.) |
| --- | --- | --- | --- | --- |
| A | 3,3 → **8,1 GB** | 14,0 GB | 42 parts / 8 vCPU | ~190 GB |
| B | 6,2 → **14,1 GB** | 29,0 GB | 62 parts / 16 vCPU | ~370 GB |
| C | 10,1 → **21,9 GB** | 58,0 GB | 68 parts / 24 vCPU | ~700 GB |

Lecture importante : le **maximum** (tous les scénarios actifs simultanément) tient dans chaque palier, avec une marge de 40–60 %. La réserve hôte (2–6 GB) couvre le noyau, le moteur de conteneurs et les pics de compilation.

**Les « CPU parts » ne sont pas des vCPU.** Ce sont des poids relatifs d'allocation ; un hôte 8 vCPU avec 42 parts fonctionne parce que tous les services ne sont jamais saturés ensemble. La contrainte réelle est la RAM, et c'est elle qui définit les paliers.

## 3. Postes les plus coûteux (et pourquoi ils sont justifiés)

| Service | RAM max | Palier | Justification du coût |
| --- | --- | --- | --- |
| Wazuh (suite) | 8,0 GB | C | SIEM complet ; exclu par défaut |
| Keycloak | 1,4 GB | B/C | IdP d'entreprise avec mappers et RBAC fin |
| k3s + Cilium + Kyverno | 2,25 GB | B/C | vrai plan de contrôle, vraie politique |
| Zeek | 0,8 GB | B/C | métadonnées de protocole, journaux partiels réalistes |
| Loki + Prometheus + Grafana + Alloy | 1,95 GB | A/B/C | télémétrie minimale crédible |
| Suricata | 0,7 GB | B/C | détection réseau réelle |
| Services métier L4/L5 | ~2,4 GB cumulés | A/B/C | cœur de la chaîne |

Décision structurante : **Wazuh n'est pas dans le chemin critique**. Un laboratoire qui exige 8 GB de SIEM avant de produire un seul résultat n'est pas un laboratoire, c'est un projet d'infrastructure.

## 4. Disque : ce qui grossit vraiment

| Poste | GB | Remarque |
| --- | --- | --- |
| Images de conteneurs | ~25 GB | épinglées, en cache local |
| PCAP | 40 GB | 1 h de trafic de laboratoire ≈ 0,5–2 GB selon verbosité |
| Logs Loki (rétention 14 j) | 60 GB | compressés |
| PostgreSQL | 20 GB | suffisant pour des dizaines de milliers de transactions fictives |
| Chaîne Anvil | 5 GB | état local, snapshots |
| Registre interne | 15 GB | quelques images |
| Système + outils | ~30 GB | |

**Politique de rétention :** PCAP 7 jours glissants, logs 14 jours, snapshots de chaîne conservés avec les rapports de scénario (petits). Sans purge, un labororatoire de 400 GB se remplit en trois semaines de scénarios intensifs.

## 5. Mesure de référence réellement disponible

La seule mesure solide dont nous disposons vient de D2.5 étape 1, sur **2 vCPU / 4 GB** :

| Tâche | Durée mesurée | Empreinte |
| --- | --- | --- |
| Compilation complète de la cible (228 fichiers, solc 0.8.26) | 31,7 s | < 4 GB, 2 vCPU |
| Suite de tests de référence (292 tests) | 18,5 s | idem |
| Profil profond (fuzz 10 000 / invariant 5 000×32) | 428,8 s | idem |

Conséquence : **la couche L5 est bon marché**. Le coût du laboratoire vient de l'identité, du SIEM et de Kubernetes, pas de la chaîne.

## 6. Coûts monétaires

| Option | Palier | €/mois | Note |
| --- | --- | --- | --- |
| Machine de conception existante | aucun | 0 | ne peut pas exécuter le laboratoire |
| Station possédée (16–32 GB) | A/B | **2,5–6,5** | électricité seule (35 W veille → 95 W charge, 120 h/mois, 0,30 €/kWh) |
| Cloud CX42 (8 vCPU/16 GB) | A | 16,4–41,5 | prix republiés en 2026, d'où la fourchette |
| Cloud CX52 (16 vCPU/32 GB) | B | 33,1–41,5 | meilleur rapport pour Tier B |
| Cloud CPX52 US | C | 100,5–120,5 | référence : le repricing 2026 rend l'AMD/US 3× plus cher que CX |

**Recommandation :** construire sur une station possédée si elle existe (coût marginal ≈ 0), sinon CX52. Ne pas louer pour Tier C avant d'avoir un besoin mesuré.

## 7. Ce que ce budget ne couvre pas

* Le **temps humain** (installation, écriture de scénarios, analyse) — le poste le plus cher, et le moins compressible.
* Le **coût de la dette de fidélité** : chaque composant simulé doit être re-vérifié à chaque montée de version.
* Les **pics de compilation** (via-IR sur 118 fichiers ≈ 60 s de CPU plein) qui peuvent saturer un hôte 8 vCPU pendant un scénario.
* Le **stockage des preuves** au-delà de 14 jours.

## 8. Seuils d'alerte à surveiller dès la construction

| Indicateur | Seuil | Action |
| --- | --- | --- |
| RAM utilisée / capacité utile | > 80 % pendant 10 min | réduire la rétention, arrêter Zeek |
| Disque libre | < 15 % | purger PCAP, archiver les rapports |
| Latence d'écriture Loki | > 2 s p95 | le scénario n'est plus mesurable, arrêter |
| vCPU steal (si cloud partagé) | > 10 % | MTTD non comparable, noter l'incident |

Le dernier point est un piège classique : sur un cloud à vCPU partagés, la latence de détection mesure parfois la contention de l'hôte, pas la détection. Les mesures doivent porter l'empreinte CPU de la machine.

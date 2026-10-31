# PRISM Cyber Range — conception et construction progressive

**Version :** 1.0 — 2026-10-31
**Statut :** **livraison 1 (conception)** terminée et vérifiée automatiquement. **Aucune couche n'est construite.** Cette distinction est volontaire et doit le rester.
**Piste :** D3, indépendante de la piste SCM et de la cible D2.5 (qui n'est ni modifiée ni réutilisée autrement qu'en lecture seule).

---

## 1. Ce que cette livraison contient

| Exigence de la mission | Livrable | État |
| --- | --- | --- |
| 1. Inventaire matériel et logiciel | [`01-inventaire.md`](01-inventaire.md) + `range/scripts/preflight.sh` (exécuté, sortie réelle) | **fait** |
| 2. Architecture technique détaillée | [`02-architecture.md`](02-architecture.md) + `range/network/nftables-range.nft` | **fait** |
| 3. Comparaison des composants open source | [`03-component-matrix.md`](03-component-matrix.md) + `range/versions.lock.json` (36 composants épinglés) | **fait** |
| 4. Estimation RAM / CPU / stockage / coûts | [`04-resource-budget.md`](04-resource-budget.md) + `range/budget/tier-budget.json` | **fait** |
| 5. Plan d'installation reproductible | [`05-installation.md`](05-installation.md) | **fait (plan)** ; scripts d'exécution à venir |
| 6. Frontières de sécurité | [`06-security-boundaries.md`](06-security-boundaries.md) | **fait** |
| 7. Scénarios de validation et critères d'acceptation | [`07-scenario-catalogue.md`](07-scenario-catalogue.md) (S1–S8) | **fait** |
| 8. Limites de fidélité au réel | [`08-realism-limits.md`](08-realism-limits.md) (L-1 … L-12) | **fait** |
| Registre des risques | [`09-risks.md`](09-risks.md) | **fait** |
| Configurations, politiques, fixtures | `range/compose/tier-a.yml`, `range/k8s/*.yaml`, `range/policies/tx.rego` | **fait (artefacts de conception)** |
| Vérification automatique des artefacts | `range/scripts/verify_artifacts.py` — **26 contrôles, 26 passent** | **fait** |

## 2. Ce que cette livraison ne contient pas, et pourquoi

* **Aucune couche n'est lancée.** La machine de conception a 2 vCPU / 4 GB, aucun runtime de conteneurs, pas de `/dev/kvm` : elle ne peut pas héberger le laboratoire. Le dire est plus utile que le simuler.
* **Aucune image métier `prism/range-*` n'est écrite.** Les services L4/L5 seront écrits couche par couche, avec leurs propres tests.
* **Aucune mesure de MTTD/MTTR.** Il n'y a rien à mesurer tant que L1–L7 ne tourne pas.
* **Aucune affirmation sur l'incident Binance du 29 octobre 2026.** Le catalogue réutilise des motifs *rapportés publiquement* en les marquant comme tels (`07` §10).

## 3. Vérifier cette livraison

```bash
# 1. Ce que cet hôte peut réellement héberger (lecture seule, aucun effet de bord)
./range/scripts/preflight.sh            # 0 = Tier B+, 10 = Tier A, 20 = conception seule

# 2. Cohérence des artefacts (schémas, réseau, hygiène des secrets, non-régression D2.5)
python3 -m venv .venv && .venv/bin/pip install pyyaml
.venv/bin/python range/scripts/verify_artifacts.py

# 3. La documentation ne promet rien qu'elle ne tienne
grep -n "26 contrôles" docs/cyber-range/README.md
```

Le vérificateur contrôle notamment :

* `A4` **aucune licence BUSL/SSPL** dans les composants retenus ;
* `B2` **les budgets RAM tiennent dans chaque palier**, cas le plus défavorable inclus ;
* `D1–D3` **refus par défaut** partout, sortie Internet bloquée sauf DNS/NTP internes ;
* `F1` **aucun secret** dans le dépôt ;
* `G1` **traçabilité** : chaque composant épinglé apparaît dans la matrice ;
* `H1–H4` **non-régression** : D2.5 intact, cible Alchemy non modifiée, noyau PRISM sans dépendance au laboratoire ;
* `I1–I3` **chaque scénario a hypothèse, préconditions, preuves, critères** et la chaîne Binance est couverte de bout en bout.

## 4. Ordre de construction (livraisons suivantes)

| Étape | Contenu | Condition d'entrée | Condition de sortie |
| --- | --- | --- | --- |
| **2** | L5 seul : Anvil + EntryPoint 0.7.0 + compte modulaire v2.0.0 + Alto + relayer, sur l'hôte de conception **ou** n'importe quel poste | rien (déjà validé en D2.5) | transaction minée, rejeu refusé, preuve par hash |
| **3** | L1 : IdP + PKI + secrets + jump ; S1 exécuté | hôte Tier A | S1 : avant/après correctif, 5/5 mesurés |
| **4** | L4 : transaction/wallet/signer/SoftHSM/OPA ; S4 + S5 | L1 opérationnel | décisions OPA reproductibles, PKCS#11 vérifié |
| **5** | L3 + L6 : forge/CI, télémétrie ; S2, S6, S8 | L4 opérationnel | MTTD mesuré avec horloge unique |
| **6** | L2 : k3s + Cilium + Kyverno ; S3 | hôte Tier B | chemin CI→clés avant/après correctif |
| **7** | L7 + S7 : forensique et vérificateur indépendant | L1–L6 stables | rejeu 3×, matrice de confusion, coûts |

Aucune étape ne peut démarrer si l'étape précédente n'a pas satisfait ses critères d'acceptation : c'est la règle qui empêche le laboratoire de devenir une démonstration.

## 5. Contraintes respectées, avec leur preuve

| Contrainte de la mission | Preuve dans cette livraison |
| --- | --- |
| Gratuit / open source d'abord | `03` : 33 composants retenus, 0 BUSL/SSPL (`A4`), 2 remplacements motivés (Vault→OpenBao, Terraform→OpenTofu) |
| Local d'abord | `02` §3 : six zones sur ponts internes ; `I2` interdit la sortie Internet |
| Aucun système réel sans autorisation | `06` X1–X3 + `nftables` `policy drop` sur `output` |
| Aucun portefeuille/fonds réel | `06` X2/X4 ; clés Anvil de test marquées fictives (`L-5`) |
| Isolation réseau stricte | `D1–D3` : trois chaînes en `drop`, `rg-wan` en `drop` entrant |
| Ressources maîtrisées | `04` : trois paliers, sommes vérifiées (`B2`), coût 0–41 €/mois |
| Reproductibilité | versions épinglées + digests, manifestes de preuves, scripts idempotents (`05` §7) |
| PRISM indépendant des modèles IA | `H4` : aucun import d'IA dans `prism/` ; le laboratoire n'en introduit aucun |
| CIEL non-dépendance | `R-7` : orchestrateur externe optionnel uniquement |
| Ne pas modifier la cible D2.5 | `H2`/`H3` : D2.5 intacts, `HEAD` de la cible toujours `bd75c9e…` |

## 6. Ce que le laboratoire ne sera jamais

Un environnement où l'on « démontre » une attaque sans preuve reproductible, ni une reconstitution de l'incident réel, ni un substitut à un audit d'une plateforme en production. Sa valeur est de rendre certaines chaînes **testables** et certains échecs **mesurables** — rien de plus.

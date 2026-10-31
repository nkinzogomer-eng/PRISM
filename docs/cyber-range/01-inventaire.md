# 01 — Inventaire des ressources disponibles

**Date de mesure :** 2026-10-31
**Méthode :** `range/scripts/preflight.sh` (lecture seule) + inspection manuelle des binaires, des réseaux et des permissions.
**Statut de ce document :** instantané. Il doit être re-mesuré sur la machine qui hébergera réellement le laboratoire avant toute construction.

---

## 1. Résultat de l'inventaire automatique

Sortie réelle de `./range/scripts/preflight.sh` sur la machine de conception :

```
vCPU                 2
RAM                  3939 MB
Disque libre (/)     20 GB
Virtualisation       kvm (rapporté) — /dev/kvm ABSENT
docker               absent
podman               absent
nerdctl               absent
runtime utilisable   NONE
kubectl / helm / k3s / ansible / opentofu / terraform   absents
jq, python3, openssl, git                               présents
nft / iptables                                          ABSENTS
privilèges           non-root (groupe sudo)
verdict              Tier "none" — hôte de conception uniquement
code de sortie       20
```

## 2. Ce que cette machine permet réellement

| Capacité | Verdict | Conséquence sur la livraison 1 |
| --- | --- | --- |
| Rédiger, versionner, relire l'architecture | **oui** | documents complets |
| Vérifier la cohérence des artefacts (schémas, YAML, matrice réseau, hygiène des secrets) | **oui** | `verify_artifacts.py` s'exécute ici, 26 contrôles |
| Compiler/tester des contrats Solidity (L5) | **oui** — déjà prouvé en D2.5 étape 1 (forge 1.7.1 + solc 0.8.26 natif, 292 tests, 18,5 s) | la chaîne L5 est la seule couche exécutable ici |
| Lancer un conteneur (L1–L7) | **non** | aucune image ne peut être démarrée |
| KVM / VM par zone | **non** (`/dev/kvm` absent) | segmentation par conteneurs + nftables uniquement |
| Filtrer des paquets (`nft`, `iptables`) | **non** | l'isolation ne peut pas être *appliquée* ici, seulement spécifiée et validée syntaxiquement |
| Accès sortant | restreint à GitHub, npm, PyPI | les images depuis Docker Hub/GHCR **ne sont pas** téléchargeables ici ; elles le seront sur l'hôte cible |

**Conclusion honnête :** cette machine ne peut pas exécuter le laboratoire. Elle peut produire et vérifier ses artefacts, et exécuter la couche L5. Toute la construction L1–L7 doit se faire sur un hôte Tier A minimum (voir `04-resource-budget.md`).

## 3. Inventaire logiciel disponible (mesuré)

| Outil | Version | Usage dans le projet |
| --- | --- | --- |
| git | 2.39.5 | clones épinglés, sous-modules |
| Python | 3.11.2 (+ 3.12 ailleurs) | vérificateur d'artefacts, outillage PRISM |
| Node.js | v22.22.3 | solcjs de secours, outillage bundler |
| npm | 10.9.8 | installation de forge/pnpm (voir D2.5) |
| OpenSSL | 3.0.20 | génération de CA de test, inspection X.509 |
| jq | 1.6 | inspection JSON/SIEM |
| curl | système | API GitHub pour l'épinglage des versions |
| PyYAML | 6.x (venv dédié) | validation syntaxique des manifestes |

Absents et nécessaires à la construction : Docker/Podman, nftables, k3s, Helm, ansible/opentofu, Zeek, Suricata, Falco, osquery, Loki/Prometheus/Grafana, SoftHSM, Alto, Trivy, cosign, gitleaks.

## 4. Inventaire matériel

| Poste | CPU | RAM | Disque | Coût mensuel | Verdict |
| --- | --- | --- | --- | --- | --- |
| Machine de conception actuelle | 2 vCPU | 4 GB | 20 GB libres | 0 € | conception + L5 uniquement |
| Portable 16 GB (hypothèse Tier A) | 8 vCPU | 16 GB | 200 GB | ~2,5–6,5 € d'électricité | **Tier A complet** |
| Station 32 GB (hypothèse Tier B) | 16 vCPU | 32 GB | 400 GB | ~2,5–6,5 € si possédée, 33–42 € si louée (CX52) | **Tier B complet** |
| Serveur 64 GB (hypothèse Tier C) | 24 vCPU | 64 GB | 1 TB | 100 €+ en cloud | Tier C, non requis au départ |

Les postes Tier A/B/C ne sont **pas** mesurés ici : ce sont des profils de cible, chiffrés dans `04-resource-budget.md`. Les marquer comme tels évite de confondre une hypothèse de dimensionnement avec un fait.

## 5. Ce qui manque et bloque quoi

| Manque | Bloque | Contournement retenu |
| --- | --- | --- |
| Runtime de conteneurs | toutes les couches sauf L5 | construction différée sur hôte cible ; artefacts validés statiquement ici |
| `/dev/kvm` | isolation par VM (frontière la plus forte) | isolation par ponts Docker + nftables, limite documentée (L-2) |
| nftables | application réelle de la politique de zones | règles écrites et validées ici, appliquées à la construction |
| Registre d'images accessible | pull des images épinglées | digests résolus au premier build (`pin_images.sh`) |
| 16+ GB de RAM | Tier A/B/C | aucun contournement : c'est une contrainte dure |
| HSM matériel | fidélité de la signature | SoftHSM v2, écart documenté (L-1) |

## 6. Décisions que cet inventaire impose

1. **La livraison 1 est une conception vérifiable, pas un déploiement.** Le prétendre autrement serait faux.
2. **L'ordre de construction commence par L5**, seule couche exécutable ici et déjà validée par D2.5 : la chaîne locale (Anvil + compte modulaire + bundler) peut être testée avant que le reste du laboratoire existe.
3. **Les critères d'acceptation sont écrits pour être exécutables sur l'hôte cible**, jamais pour être « vérifiés par lecture ».
4. **Aucun composant n'est retenu s'il ne peut pas être épinglé** ; les trois cas non résolus (SoftHSM, registry:2, tcpdump/tshark) sont marqués `unverified` dans `range/versions.lock.json` et ne peuvent pas entrer dans une couche validée sans résolution du pin.

# 09 — Registre des risques et des limites

**Version :** 1.0 — 2026-10-31
**Objet :** consigner les risques du laboratoire lui-même — techniques, scientifiques, juridiques et organisationnels — avec probabilité, impact et mitigation vérifiable.

---

## 1. Risques techniques

| ID | Risque | P | I | Mitigation | Signal d'alerte |
| --- | --- | --- | --- | --- | --- |
| R-1 | Évasion de conteneur atteignant l'hôte de recherche | faible | élevé | hôte dédié sans données personnelles ; pas de montage de `/` ni de socket Docker là où ce n'est pas nécessaire (exception : runner CI, documentée) ; nftables en anneau externe | processus inattendu sur l'hôte, écriture hors `range/state/` |
| R-2 | Fuite de secret de laboratoire dans git | moyenne | moyen | SOPS + age, vérificateur `F1` en CI, revue du `git diff` du verrou | `F1` échoue, secret dans un journal de build |
| R-3 | Compromission de l'hôte via un service exposé | faible | élevé | aucune exposition publique : ports publiés sur `127.0.0.1` uniquement ; pas de proxy exposé à Internet | port visible depuis l'extérieur |
| R-4 | Dérive de version silencieuse (image `latest`) | **élevée** sans discipline | élevé | `pin_images.sh` + revue obligatoire du diff de `versions.lock.json` ; `E1`/CI | un `latest` apparaît dans un compose |
| R-5 | Rupture de la séparation des preuves | moyenne | élevé | manifestes signés, preuves en écriture seule, vérificateur sur identité distincte | un rapport contient une preuve non scellée |
| R-6 | Épuisement des ressources (disque/RAM) en cours de scénario | moyenne | moyen | seuils d'alerte (`04` §8), purge PCAP/logs, plafonds mémoire par service | disque < 15 %, OOM kills |
| R-7 | Dépendance future à CIEL | faible | moyen | CIEL reste un orchestrateur externe optionnel ; aucune interface requise par le noyau PRISM (`H4` vérifie l'absence d'import) | un import CIEL dans `prism/` |

## 2. Risques scientifiques

| ID | Risque | P | I | Mitigation |
| --- | --- | --- | --- | --- |
| S-1 | **Surinterprétation** : présenter une démonstration en laboratoire comme une preuve sur un système réel | **élevée** | **élevé** | §4 de `08-realism-limits.md` fixe les formulations autorisées ; chaque rapport cite ses limites ; séparation explicite entre « confirmé », « inconnu », « hypothèse » |
| S-2 | **Biais du banc** : les fixtures sont écrites par la même personne qui écrit les scénarios ; on trouve ce qu'on a caché | élevée | élevé | fixtures = configurations réalistes documentées, jamais des applications « spécialement vulnérables » ; écriture des scénarios par une passe distincte de celle des fixtures ; jeu de contrôle négatif en S7 |
| S-3 | **Métriques non comparables** (horloges, charge, vCPU partagés) | moyenne | élevé | horloge unique NTP, empreinte CPU consignée, mesures répétées 3×, médiane + dispersion publiées |
| S-4 | **Couverture surestimée** : on publie un pourcentage unique au lieu d'une matrice | élevée | moyen | `07` S7 critère 3 impose « règles implémentées / techniques » avec la liste des trous |
| S-5 | **Résultats négatifs enterrés** (aucune détection) | moyenne | élevé | un scénario non détecté est un résultat à publier ; la CI de rapport exige un champ « non détecté » explicite |
| S-6 | **Dérive de la cible D2.5** (patches opportunistes sur le compte modulaire) | faible | élevé | cible en lecture seule, `H3` vérifie `HEAD == bd75c9e…` et l'absence de modifications ; tout besoin de patch devient un scénario, pas un commit |

## 3. Risques juridiques et éthiques

| ID | Risque | P | I | Mitigation |
| --- | --- | --- | --- | --- |
| J-1 | Usage des techniques trouvées contre un système réel | faible mais catastrophique | très élevé | laboratoire sans accès à des systèmes tiers ; publication des scénarios sous forme de mécanismes et de configurations, pas de chaînes d'exploitation prêtes à l'emploi ; rappel explicite dans chaque rapport |
| J-2 | Reproduction d'outils d'attaque utilisables hors laboratoire | moyenne | élevé | les fixtures sont des configurations et des services métier ; pas de code d'exploit générique, pas d'outil d'évasion |
| J-3 | Implication d'un tiers réel (Binance, émetteurs de stablecoins) | moyenne | élevé | aucune adresse réelle, aucune connexion, aucune affirmation sur l'incident réel ; `07` §10 sépare statut factuel et hypothèses |
| J-4 | Licence d'un composant contredisant la politique open source | faible | moyen | `A4` refuse BUSL/SSPL ; Vault et Terraform remplacés par OpenBao/OpenTofu |
| J-5 | Données personnelles | faible | moyen | jeux de données synthétiques uniquement, identités fictives |

## 4. Risques organisationnels

| ID | Risque | P | I | Mitigation |
| --- | --- | --- | --- | --- |
| O-1 | Le laboratoire devient un projet d'infrastructure permanent et ne produit aucun résultat | **élevée** | moyen | paliers A/B/C ; Tier A doit produire un premier scénario avant tout achat ; aucune amélioration de fidélité avant une question qui l'exige (`08` §3) |
| O-2 | Coût de maintenance sous-estimé (montées de version, dette) | élevée | moyen | versions épinglées, cycle de revue trimestriel, 3 pins seulement non vérifiés, chacun avec une procédure |
| O-3 | Perte de reproductibilité après un `git push --force` ou un nettoyage de cache | moyenne | moyen | verrou + manifestes d'artefacts ; un rapport sans manifeste valide est rejeté |
| O-4 | Concentration : une seule personne sait reconstruire le laboratoire | élevée | moyen | scripts idempotents + ce jeu de documents comme source de vérité ; objectif : un tiers reconstruit Tier A en suivant `05` |

## 5. Risques spécifiques à l'usage de PRISM

| ID | Risque | Mitigation |
| --- | --- | --- |
| P-1 | Confondre les capacités PRISM avec celles du laboratoire (le labo trouve une faille → « PRISM est validé ») | aucun résultat PRISM n'est produit dans cette livraison ; les scénarios sont des **bancs d'essai** pour PRISM, pas des preuves de PRISM |
| P-2 | Adapter le laboratoire pour flatter PRISM (choisir des scénarios que PRISM réussit) | catalogue S1–S8 fixé **avant** toute mesure PRISM ; modification = nouvelle version documentée, avec motif |
| P-3 | Introduction d'une dépendance IA | le noyau reste sans modèle ; si CIEL est ajouté plus tard, il reste externe et optionnel |
| P-4 | Le laboratoire dépend d'un service payant (cloud, HSM) | Tier A/B fonctionnent hors ligne sur matériel possédé ; aucun service tiers n'est requis |

## 6. Risques acceptés explicitement

1. **Pas de frontière noyau** (L-2) : accepté sur un hôte de recherche dédié, sans données personnelles.
2. **Pas de HSM matériel** (L-1) : accepté ; toute conclusion sur l'inextractibilité des clés est interdite.
3. **Échelle réduite** (L-7) : accepté ; aucune extrapolation de MTTD.
4. **Services métier écrits pour le laboratoire** (L-3) : accepté ; l'absence de faille n'est jamais une preuve de sécurité.

## 7. Revue

* Ce registre est revu à chaque fin de palier (A, B, C) et à chaque montée de version majeure.
* Un risque nouveau découvert pendant un scénario entre ici **avant** la publication du rapport, pas après.
* Un risque accepté peut être retiré de cette liste seulement si la limite correspondante de `08-realism-limits.md` est levée avec preuve.

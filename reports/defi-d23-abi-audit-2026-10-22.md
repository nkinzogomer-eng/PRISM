# D2.3 — Audit contradictoire et résultat réel, 22 octobre 2026

**Statut technique : PASS. Statut scientifique de supériorité : NON DÉMONTRÉ (NO-GO).**

## Provenance des observations

- [GitHub Actions 39847974523 : succès](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39847974523), commit `6e8c741ac2b6d532dbb6ad131b83581213b87023`.
- [Rapports bruts, compilateur ABI, 12 tests Solidity et résultats de fuzzer](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39847974523/artifacts/12456590937).
- [PR expérimentale #24](https://github.com/nkinzogomer-eng/PRISM/pull/24), basée sur la PR #23 ; branche `main` inchangée.
- 19 tests adversariaux D2.3 et 12 tests D2.2 passés, Python 3.12, Foundry v1.3.6, Solidity 0.8.24.
- Compilation d'ABI vérifiable par `forge inspect`, sélection des candidats **avant** les observations EVM, puis génération automatique de 12 tests EVM.

## Ce qui a véritablement fonctionné

Le compilateur `prism.defi_property_compiler` prend uniquement les ABI de rôles `oracle`, `lender`, `asset`. Sans label de variante, il trouve la présence de fonctions/signatures suffisantes pour suggérer **trois hypothèses** :

1. `ORACLE_AUTH` : seul le propriétaire peut changer le prix.
2. `WITHDRAW_SOLVENCY` : un retrait ne doit pas rendre la dette supérieure à la limite d'emprunt.
3. `REPAY_CONSERVATION` : un remboursement qui réduit la dette doit produire le transfert d'actifs correspondant.

Toute fonction absente ou incompatible aboutit à `UNKNOWN`, jamais à la conclusion « sûr ». Le test généré trouve une violation dans la variante `c1`, `c2` et `c3`, et aucune dans `c0` sur les propriétés correspondantes, soit **TP=3, FP=0, FN=0, TN=9** (12 cellules de développement). Les échecs Foundry sont filtrés par une **raison précise** et comparés à la vérité seulement lors de la notation postérieure. Le test EVM des probes générées a mesuré **0,2644 s mur / 0,2755 s CPU enfants** sur une exécution ; il ne comprend ni l'installation, ni l'écriture des patrons, ni l'ensemble des coûts de compilation, recherche et vérification.

La suite D2.2 indépendante (recherche par modèle, replay EVM, état de référence via handler Foundry) confirme elle aussi TP=3/FP=0/FN=0/TN=9. **Foundry sait déjà retrouver les mêmes trois violations.**

## Contre-exemple structurel majeur : la même ABI peut couvrir sûr et vulnérable

Les quatre variantes locales sont des *configurations comportementales du même contrat Solidity*. Elles partagent donc **exactement les mêmes interfaces ABI** alors que le comportement diffère. Un compilateur qui n'observe **que des noms et types ABI** ne peut pas inférer lesquelles sont vulnérables. Dans cette expérience, les trois hypothèses sont sélectionnées identiquement pour toutes les variantes ; le résultat de vulnérabilité provient des tests comportementaux EVM, pas de l'ABI.

Le générateur de probes reçoit de plus un manifeste de déploiement dont les **valeurs booléennes exposent les contrôles de sécurité activés ou désactivés**. Ce n'est pas un test aveugle d'interprétation de contrats tiers, même si le générateur n'utilise pas directement l'oracle de vérité du scorer. Il serait donc incorrect de présenter cette mécanique comme ayant identifié des bogues « inconnus » à partir du seul code.

La variante `c0` protégée passant ces probes n'est pas prouvée sûre sur toutes les transactions, configurations, coûts, oracles externes ou états. Les trois cas positifs ne sont pas des zero-days, ni des vulnérabilités réelles de protocole, et ne portent pas de label de gravité critique.

## Comparaison honnête et limite des gains

| Méthode | TP | FP | FN | TN | Origine des propriétés |
|---|---:|---:|---:|---:|---|
| PRISM, hypothèses depuis ABI + probes EVM | 3 | 0 | 0 | 9 | Trois patrons financiers classiques préécrits |
| PRISM, modèle borné D2.2 + replay EVM | 3 | 0 | 0 | 9 | Modèle et heuristiques écrits à la main |
| Foundry avec handlers d'invariants stateful | 3 | 0 | 0 | 9 | Même cahier de propriétés, handlers indépendants |

**Différence en découvertes confirmées : zéro.** Comparaison CPU/temps entre ces lignes invalidée par budgets, précomputation et couverture différents. Le 100 % est une observation sur un ensemble de développement fabriqué en connaissant l'objectif, pas une estimation de rappel futur.

## Décision

D2.3 a livré une vraie amélioration technique : **sélection préalable, auditée et fail-closed d'hypothèses de sécurité à partir des interfaces**, puis vérification automatisée EVM. Mais cela reste un compilateur de patrons classiques, non une nouvelle méthode de découverte ayant dépassé l'état de l'art.

**GO limité** : conserver comme générateur de candidats sous contraintes explicites.

**NO-GO scientifique** : pas d'allégation de 8/10, 18/20, meilleure précision générale, meilleur calcul EVM, contrats historiques inconnus, preuve de sûreté ou discovery de zero-day.

## Prochaine expérience capable de départager la recherche

D2.4 doit commencer par un **ensemble de contrats tiers gelés**, comportant des mécanismes non conçus par les auteurs du moteur. Séparer entrées publiques (sources / interfaces / exigences légitimes) des labels de vérité ; ne jamais donner un manifeste de configuration qui expose les corrections au détecteur. Figer *avant l'évaluation* le budget par cible, le comptage par cause racine et les règles TP/FP/FN.

Exiger des baselines qui disposent des mêmes exigences : Foundry stateful invariants, Echidna / Medusa et Halmos si leur environnement fonctionne. Tester explicitement l'impact *supplémentaire* du planificateur SCM par ablation, à propriétés et preuves égales. Ne compter les preuves que si une séquence EVM indépendante et les contrôles corrigés confirment les hypothèses. Publier les échecs et toutes les dépenses CPU/RSS/humaines.

C'est le **seul type de résultat** qui pourrait commencer à soutenir une supériorité scientifique ; il n'est pas encore obtenu.

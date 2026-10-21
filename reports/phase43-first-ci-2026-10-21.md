# Phase 4.3A — première mesure CI réelle, 21 octobre 2026

**État : PASS pour l'intégrité de la décision binaire de développement ; gain de la stratégie séquentielle observé ; avantage SCM/PRISM sur cette stratégie NON DÉMONTRÉ.**

- [CI Linux réussi, run 39633734342](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39633734342)
- [PR #15 (draft)](https://github.com/nkinzogomer-eng/PRISM/pull/15)
- GitHub Actions Ubuntu, Python 3.12.15 ; Bandit 1.8.6 et Semgrep 1.181.0, règles à `17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9`.
- OWASP Python v0.1, 1 230 modules au commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. Manifeste byte-for-byte du checkout CI Linux : `fe0ec67dcc328feb33d592b790563add38c721af4b89abcf839e56bc9e3b9b9d`. Une ancienne valeur de manifeste issue des tests Windows ne correspond pas à celle de Linux ; la raison exacte n'est pas isolée. Les deux expériences utilisent la référence de dépôt épinglée ; les hash bruts des extractions doivent rester séparés.
- 9 tests de contrat passés avant l'exécution. Le premier run a rejeté le mauvais hash de provenance ; un run suivant a intercepté un commentaire mal échappé ; tous deux ont été corrigés avant le run réussi.
- Trois politiques, chacune répétée deux fois, avec ordre tournant. Toutes les durées ci-dessous sont celles de nouveaux processus réels et incluent copie/vérification/nettoyage, mais excluent installation et sérialisation du rapport final.

## Mesures (secondes)

| Politique | Répétition 0 | Répétition 1 | Médiane du temps total | CPU enfant rép. 0 / rép. 1 |
|---|---:|---:|---:|---:|
| Bandit + Semgrep complet | 26,910 | 24,600 | 25,755 | 60,42 / 56,75 |
| Bandit puis Semgrep seulement sur cas non signalés (fixe) | 20,594 | 20,374 | 20,484 | 47,16 / 47,16 |
| Sélecteur PRISM déterministe | 20,481 | 20,368 | 20,425 | 47,46 / 47,28 |

Le séquentiel fixe économise environ **20,5 %** du temps mural médian par rapport au complet, tandis que le bras PRISM économise environ **20,7 %**. La différence entre PRISM et le fixe (environ **0,06 s**) est trop faible et trop bruitée pour une conclusion ; les deux bras appliquent exactement la même politique. Il n'y a **aucun gain propre à PRISM établi**.

Le calculateur figé avait prédit `full=26.41s`, `sequential=20.4002s`, donc une amélioration relative prévue de 22,76 %. Il a choisi `sequential` sans accéder aux résultats des exécutions courantes ni à leurs labels. Cet accord apparent des ordres de grandeur ne calibre pas encore le prédicteur.

## Vérification et portée

- Bandit analyse les 1 230 modules ; il en signale 352 dans l'inventaire de cette expérience. Le second outil passe de 1 230 modules complets à **878 modules** en séquentiel.
- Les trois politiques produisent la même décision « au moins une alerte d'un des deux scanners » pour les 1 230 modules : **469 modules positifs**, aucune divergence binaire constatée dans les répétitions.
- Le vérificateur a aussi retrouvé les mêmes identités `(règle, ligne)` d'alertes Semgrep sur les 878 modules effectivement rescannés. L'ensemble des alertes Semgrep des 352 modules déjà positifs sous Bandit **n'est pas conservé** par la politique séquentielle, et n'est pas couvert par l'équivalence.
- Les scanners peuvent manquer une vulnérabilité réelle ou produire des faux positifs. « 469 positifs » signifie 469 modules signalés, **pas 469 vulnérabilités confirmées**.
- Le score par labels, s'il est employé, est « une alerte quelconque par module » et ne démontre pas que le CWE ou le sink visé a été détecté.
- Aucun corpus indépendant n'a été utilisé. Les données, la logique de sélection et les métriques sont de développement.

## Coûts non couverts et limites

Les temps comprennent la préparation/copie/scanners/vérification/nettoyage d'un run ; ils excluent installations, réseau et sérialisation du JSON final. Des mesures de mémoire maximale, d'énergie et du coût monétaire ne sont pas disponibles ; ces coûts ne sont **pas zéro**. Deux répétitions sur un runner partagé ne permettent aucune inférence statistique stable, ni sur la médiane ni sur le p95. Aucun gain sur CodeQL ou Semgrep utilisé seul n'est déduit.

## Décision de recherche

1. **Accepter le banc expérimental et le résultat sur la décision binaire OR comme preuve d'ingénierie très limitée.** Le seuil indicatif de 10 % face à une analyse complète est franchi sur ce seul protocole.
2. **Refuser toute revendication de supériorité propre à SCM** : un simple séquentiel préexistant obtient le même résultat pratique, ce qui était un contre-modèle explicite.
3. **Ne pas déployer ni fusionner** sur cette seule base. PR #15 reste en brouillon ; Phase 4 n'est pas validée.
4. Suite recommandée : 4.3B, fixer une tâche de qualité précise (CWE/ligne et complétude exigée) et comparer sur des données indépendantes une politique PRISM réellement différente à la meilleure politique séquentielle simple, en instrumentant RSS et plusieurs répétitions.
5. Si SCM ne bat pas ces baselines, limiter ses claims et tester un autre mécanisme présentant une valeur distincte : réutilisation incrémentale contrôlée ou réduction de règle à garantie sémantique.

Les sorties brutes et `measurement.json` sont archivés en tant qu'[artefacts du run CI](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39633734342/artifacts/12359648608).

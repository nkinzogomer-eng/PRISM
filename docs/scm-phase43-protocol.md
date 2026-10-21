# SCM–PRISM Phase 4.3A — coût réel d'une décision OR

**Statut : expérience de développement lancée, pas un résultat de supériorité.**
**Date : 2026-10-21.** Base : PR #13 au commit `9e84b53`. La PR #14 reste une expérience négative indépendante : son filtrage AST ne doit pas être activé.

## Hypothèse et question vérifiable

Pour la **seule décision binaire au niveau du module** « Bandit **OU** Semgrep a-t-il émis au moins une alerte ? », l'exécution Bandit sur tous les fichiers, suivie de Semgrep uniquement sur les modules sans alerte Bandit, peut-elle conserver la même décision que l'exécution des deux scanners sur tous les fichiers, avec un coût total inférieur ?

Ce contrat ne garantit ni la conservation de toutes les alertes individuelles, ni la vérité d'une vulnérabilité, ni l'absence de faux négatifs provenant des scanners. Si Semgrep dépend d'informations entre modules, l'équivalence peut échouer ; la comparaison réelle avec une analyse complète doit le détecter. Les modules non couverts en raison d'erreurs deviennent inconnus et invalident la mesure, jamais négatifs.

## Bras comparés

1. `full` : Bandit puis Semgrep, chaque fois sur les 1 230 modules.
2. `fixed_sequential` : Bandit complet puis Semgrep seulement sur les cas sans alerte Bandit. Politique classique fixe à battre.
3. `prism` : choix conservateur entre `full` et `sequential` au moyen d'un modèle déterministe figé en amont. Ce contrôleur utilise uniquement des valeurs du **développement antérieur**, jamais les labels ni résultats de la répétition courante.

L'estimateur figé utilise Bandit 5,41 s, Semgrep 21,00 s et une proportion de 352/1230 modules signalés dans un ancien pilote. Il exige une économie estimée d'au moins 10 % pour sélectionner l'exécution séquentielle. Ce n'est qu'une prédiction ; les temps Linux et les résultats réels ont priorité. Si PRISM choisit la même politique que la baseline fixe, **aucune nouveauté ni supériorité sur celle-ci ne doit être revendiquée.**

La décision OR peut autoriser l'arrêt après une alerte positive pour un module, mais les alertes supplémentaires qu'aurait données Semgrep sur ce module ne sont pas préservées. Elles sont comptabilisées séparément. Ce mode ne doit jamais alimenter un rapport exigeant l'inventaire complet des vulnérabilités ou une réparation exhaustive.

## Mesures et contrôles

- Benchmark développement **OWASP Python v0.1** au commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`, inventaire et manifeste SHA-256 verrouillés.
- Bandit `1.8.6`, Semgrep `1.181.0`, règles communautaires à `17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9`, dossiers `python/lang/security` et `python/flask/security`.
- Deux répétitions réelles, avec rotation de l'ordre des trois bras ; chaque bras relit et recopie les fichiers inchangés, lance de nouveaux processus, valide code de sortie, JSON et inventaire, puis nettoie.
- Coûts : temps mural bout-en-bout (jusqu'au nettoyage), CPU enfant, coûts par scanner, copie/préparation, vérification. Installation et réseau hors chronométrage ; mémoire maximale, coût monétaire et sérialisation finale non mesurés, non assimilés à zéro.
- Vérification indépendante du score : identité des modules OR positifs et des alertes Semgrep **uniquement sur les modules réellement rescannés** par la politique ; toute différence invalide l'expérience.
- Pour mémoire seulement : TP/FP/FN/F1 calculés sur les labels de développement en utilisant « n'importe quelle alerte dans le module ». Ce score grossier **n'est pas une vérification CWE/ligne et ne mesure pas la découverte de vulnérabilités inédites**.
- Les sorties brutes JSON et le rapport `measurement.json` sont conservés en artefacts CI. Les mesures Linux ne doivent pas être mélangées aux temps Windows de la phase 4.2.

## Critères de décision fixés avant mesure

**PASS de l'intégrité :** toutes les exécutions complètes, aucun module manquant, même décision OR par module, pas d'écart entre alertes observées sur modules communs, aucune erreur de scanner.

**Signal de gain économique :** réduction d'au moins 10 % du temps total médian par rapport au bras `full`, sans coût caché attribué à zéro. Avec deux répétitions seulement, il s'agit d'une indication exploratoire, pas d'une preuve statistique.

**Gain propre à PRISM :** temps total meilleur que la politique fixe séquentielle à qualité et couverture identiques, sur des données bloquées indépendantes, avec un coût de planification inclus. Si PRISM et le filtre fixe prennent la même décision, ce critère n'est pas satisfait même si tous deux battent `full`.

## Prochaines portes

4.3B : figer des familles et un jeu de données indépendants, améliorer la précision CWE/ligne, comparer aux optimisations natives des scanners et à une vraie politique séquentielle forte ; collecter mémoire maximale et distribution p95 sur un nombre suffisant de répétitions.

4.3C : tester les mécanismes SCM réellement distinctifs (élimination de calculs dominés sous conditions vérifiables, incrémentalité à invalidation prouvée, partition de règles/objets quand l'analyseur le permet), avec baselines natives. Aucun holdout indépendant ne doit être consommé pour ajuster le contrôleur.

## Reproduction

```sh
python -m unittest discover -s tests -p 'test_phase43_cost_policy.py' -v
python scripts/measure_phase43.py \
  --source-dir benchmark/testcode \
  --labels benchmark/expectedresults-0.1.csv \
  --semgrep-config semgrep-rules/python/lang/security \
  --semgrep-config semgrep-rules/python/flask/security \
  --output reports/phase43-development --repeats 2
```

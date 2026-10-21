# SCM/PRISM Phase 4.4 — premier cycle de découverte guidée par un objectif

**Date : 2026-10-21.** **Statut : succès exploratoire sur des comportements de test contrôlés ; supériorité générale ou découverte de failles critiques réelles NON DÉMONTRÉES.** PR #18 doit rester en brouillon ; ne pas fusionner.

## Nouveau critère d'optimisation

Ne plus minimiser seulement le coût nécessaire pour reproduire les décisions d'un autre scanner. Viser des **faits de sécurité vérifiables** : « une entrée utilisateur atteint-elle réellement une opération de fichiers hors du répertoire attendu ? » (CWE-22). Chercher le calcul suffisant pour générer, sélectionner puis vérifier l'hypothèse, avec coût comptabilisé et inconnus explicites.

Le but futur « 8 failles réelles sur 10 » signifie **8 failles indépendamment confirmées**, sans sévérité extrapolée à partir d'alertes. La cible mesurée ici est bien plus étroite : un accès à une sentinelle synthétique observé durant une requête locale sur un benchmark OWASP connu, et non une faille critique dans un produit réel.

## Source, contrôle, procédure

- OWASP Benchmark Python v0.1 (jeu de **développement** déjà consulté), source fixe `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` et manifeste vérifié des 1 230 modules.
- [CI final réussi — run 39647947430](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39647947430). **24 tests unitaires/adversariaux Phase 4.4 + 15 tests historiques réussis.**
- [Résultats, fiches par cas et sorties JSON du même run](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39647947430/artifacts/12367358459).
- Le détecteur analyse les sources et puits en AST ; décompose conditionnels constants et une partie des contenants ; signale explicitement appels dynamiques, importations et protections non résolues. Il parcourt **les 1 230 fichiers sans consulter leurs labels**.
- Le rejeu construit un Flask test client **local sans serveur réseau**, insère le même chemin relatif de test dans les canaux d'une requête, et instrumente des opérations filesystem vers une sentinelle qui est hors du dossier `TESTFILES_DIR`, mais dans une racine temporaire possédée par le test. Les fichiers originaux du benchmark restent inchangés.
- L'analyseur statique et le rejeu écrivent leurs résultats AVANT les programmes d'évaluation qui lisent le CSV officiel. Une non-observation n'est pas une preuve d'absence de vulnérabilité.

## Mesure statique — comparaison aux étiquettes de développement

Le cas `pathtraver` contient 168 tests, dont 65 étiquetés vulnérables et 103 étiquetés non vulnérables.

| Nombre de cas | Résultat |
|---|---:|
| Hypothèses candidates après les corrections | 36 |
| Correspondant à des étiquettes positives | 33 |
| Correspondant à des étiquettes négatives | 3 |
| Inconnus non forcés en négatifs | 39 |
| Cas du domaine avec résultat exploitable pour score grossier | 129 |
| Étiquettes positives ratées dans les 129 cas évalués | 16 |
| Précision sur les **étiquettes** des candidats (33/36) | 91,7 % |
| Rappel sur les **positifs évalués** (33/49) | 67,3 % |

Ces chiffres **ne sont pas** des scores de vulnérabilités indépendamment confirmées ; 39 inconnus sont exclus du dénominateur 33/49 et doivent toujours être signalés. Une amélioration itérative a identifié les conditions `if`, les flux conditionnels, les cartes/listes/configurations, les valeurs d'entrée encapsulées et surtout les puits `with open(...)`. Ils sont désormais testés. Ce processus reste un ajustement sur données de développement déjà examinées.

## Preuves comportementales — comparatif plus pertinent

| Stratégie de sélection pour le rejeu | Modules rejoués / 1 230 | Observations d'accès hors racine | Dont ouvertures réussies | Dont `exists` ou métadonnées | Cas positifs du benchmark correspondants |
|---|---:|---:|---:|---:|---:|
| Contrôle initial à catégorie connue (URL `pathtraver`) | 168 | 54 | 42 | 12 | 54 / 65 (83,1 %) |
| **Sélection sans nom de catégorie, à partir des puits du code** | **448** | **54** | **42** | **12** | **54 / 65 (83,1 %)** |

Les **54 opérations observées** concernent toutes des cas étiquetés positifs dans ce jeu ; aucun des 103 cas étiquetés négatifs ne présente une opération vers la sentinelle lors de l'unique requête essayée. **Ce n'est pas une estimation générale de taux de faux positifs ni de rappel** : le scénario de test est spécifique, les labels sont discutables, et aucun contre-exemple de production n'a été validé.

- **42 cas** : une opération de type `open`, `codecs.open` ou `Path.open` a réussi sur la sentinelle située hors du dossier autorisé synthétique. Cela prouve une primitive d'accès à un fichier de test, pas la gravité critique d'une vulnérabilité réelle.
- **12 cas** : une vérification `exists` a retourné vrai pour la sentinelle ; cela peut démontrer une divulgation d'existence ou une capacité de métadonnées, **pas une lecture arbitraire du contenu**.
- Dans la sélection à catégorie connue, **19 erreurs d'exécution** (17 `NameError`, 1 `IsADirectoryError`, 1 `UnboundLocalError`) et **95 cas sans accès observé**. Ce sont des inconnus quant à l'existence réelle d'une faiblesse, pas des « sûrs ».
- Dans la sélection guidée par le code, **148 erreurs** (principalement **129 `ModuleNotFoundError`** sur des modules d'autres familles OWASP) et **246 cas sans accès observé**. Ces frais et échecs montrent que le sélecteur doit encore être amélioré. Aucun de ces résultats ne justifie de fausse certification négative.

### Test contradictoire à retenir

Le premier sélecteur qui n'utilisait plus les noms de catégories n'avait choisi que 426 modules et ne reproduisait que **44** cas positifs sur 65 (67,7 %). En ajoutant le contrôle des ressources `with open(...)` dans l'AST, le sélecteur purement dérivé du code choisit 448 modules et retrouve **les dix observations manquées**, portant ce résultat à 54/65. Un nouveau test régressif échoue si l'accès `with open(request_controlled_name)` redevient invisible.

C'est la meilleure preuve d'ingénierie obtenue ici : un défaut général de la chaîne objectif→puits a été diagnostiqué, corrigé et vérifié avec conservation des résultats dynamiques. Cela ne démontre pas que SCM dépasse un moteur SAST/DAST moderne, mais détermine **quelles distinctions computationnelles étaient nécessaires**.

## Coût observé, pas coût total de production

Sur la CI finale Linux partagée, analyse statique de 1 230 modules : ~0,92 s ; rejeu de 448 modules : ~1,06 s (processus avec Flask chargé, hors installation et provisionnement). Ces deux mesures ne constituent pas un coût complet : dépendances, préparation, maintien des outils, mémoire maximale, CI, adjudication de gravité, répétitions robustes et fonctionnement sur un logiciel inconnu restent à mesurer. Le jeu OWASP v0.1 et les routes standardisées facilitent le fonctionnement.

## Ce que l'expérience NE prouve PAS

1. **Aucune réussite « 8/10 failles critiques » sur une application inconnue.** Le numérateur 54 mesure une primitive locale contrôlée. Seulement 42 sont des ouvertures de fichier ; aucun CVSS ou impact de production n'est établi.
2. **Aucune supériorité contre l'état de l'art.** On doit comparer à des SAST/DAST spécialisés et correctement configurés (notamment CodeQL, Semgrep et des scanners dynamiques), pas seulement au Bandit historique ; leurs tâches et coûts doivent être comparables. L'absence de détection path traversal par Bandit dans le pilote précédent est un angle mort d'un outil donné, pas une nouvelle loi informatique.
3. **Pas de découverte de famille de vulnérabilité sans objectif prédéfini.** Nous avions défini `CWE-22` et construit une sonde adaptée. Supprimer le nom de catégorie du sélecteur est un progrès méthodologique, pas une généralisation à toutes les classes.
4. **Pas de véritable holdout indépendant.** Les cas ont été inspectés et les règles améliorées après chaque passage. Nous ne devons pas mesurer la généralisation sur cette même collection. Les contre-exemples et les défauts de labels d'OWASP v0.1 restent à adjudicer.
5. **Aucune conclusion d'absence de faille à partir d'une seule sonde.** Les inconnus incluent les erreurs d'environnement et les chemins qui requièrent d'autres valeurs d'entrée ou un autre état.

## Décision et prochaine étape

**GO pour poursuivre la recherche 4.4C**, mais **NO-GO pour déployer, fusionner ou faire une annonce de performance générale**.

Étape suivante : figer un corpus réellement inconnu au détecteur, sans noms de routes révélant le CWE ; détecter de façon autonome les classes de puits, prioriser les fonctions et dépendances inter-fichiers, augmenter les preuves (fichiers ouverts contre simples tests d'existence), corriger le traitement des erreurs d'environnement, et comparer à des moteurs SAST/DAST modernes avec des budgets équivalents. Les labels restent cachés jusqu'à la fin et les résultats négatifs sont conservés.

Les 65 labels positifs d'OWASP v0.1 ne sont pas tous nécessairement des failles critiques ni un oracle indépendant. Le résultat actuel est **une capacité de découverte/proposition et de rejeu local ciblée avec des limites explicites**.

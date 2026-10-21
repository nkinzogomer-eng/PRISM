# Phase 4 — audit et itération du 21 octobre 2026

## Conclusion scientifique

OWASP Python v0.1 reste exclusivement un jeu de développement. Cette itération corrige la fiabilité de l'évaluation et ajoute un prototype explicatif structurel ; elle ne démontre ni une amélioration de détection de PRISM, ni une supériorité SCM. Aucune évaluation indépendante, réparation de vulnérabilité ou validation de sécurité réelle n'a été effectuée. Les ablations sont exploratoires et ne sont pas préenregistrées.

## Provenance et CodeQL complet

- Dépôt initial : `52dbf14d21b4e2090e4c3b52c2bedc4c69fe91a1`, branche de la [PR #13](https://github.com/nkinzogomer-eng/PRISM/pull/13).
- Benchmark épinglé : `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`, 1 230 cas, 452 positifs, 778 négatifs. Les sources et labels n'ont pas été modifiés.
- [Artefact statique](https://github.com/nkinzogomer-eng/PRISM/actions/runs/38976414571), ID `12079292080` ; Bandit 1.8.6, Semgrep 1.181.0, règles épinglées selon le workflow existant.
- [CodeQL complet sur push](https://github.com/nkinzogomer-eng/PRISM/actions/runs/38975740094), commit `19ccb1c4eb8d4a9ca009ca5ee72eb8c8d78b0038`. Artefacts `12078133580` (default) et `12079226380` (security-extended). CodeQL 2.27.2 ; pack Python 1.8.12. Les deux jobs réussissent, SARIF `executionSuccessful=true`, overlay désactivé, diagnostics confirmant **1 230/1 230 modules étiquetés extraits**, sans module manquant. Les 319 alertes de chaque suite touchent 297 cas et produisent les mêmes prédictions binaires. Cela ne prouve pas que les suites exécutent les mêmes requêtes.
- Empreintes SHA-256 des quatre sorties brutes, des labels et du manifeste source : [audit.json](phase4-audit-2026-10-21/audit.json). Les ZIP récupérés sont archivés localement hors du dépôt ; les IDs permettent de retrouver les originaux tant qu'ils sont conservés par GitHub.

## Comparaison sur les sorties archivées

Score grossier historique : au moins une alerte dans le fichier du cas. Résultats relatifs aux labels officiels, sans adjudication sémantique exhaustive.

| Politique | TP | FP | TN | FN | Rappel | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Bandit | 224 | 128 | 650 | 228 | 49,56 % | 55,72 % |
| Semgrep | 173 | 198 | 580 | 279 | 38,27 % | 42,04 % |
| CodeQL default | 129 | 168 | 610 | 323 | 28,54 % | 34,45 % |
| CodeQL security-extended | 129 | 168 | 610 | 323 | 28,54 % | 34,45 % |
| Bandit OR Semgrep | 262 | 207 | 571 | 190 | 57,96 % | 56,89 % |
| Union des quatre sorties | 327 | 313 | 465 | 125 | 72,35 % | 59,89 % |

L'union complète ajoute 65 TP et 106 FP à Bandit OR Semgrep. Elle donne le meilleur F1 parmi ces politiques fixes, tandis que Bandit seul a la meilleure précision. Aucun optimum universel n'est défini sans coût explicite des erreurs. Ce résultat est un rejeu de sorties existantes, pas une nouvelle exécution des scanners. Les offres commerciales, outils à modèle et autres configurations non exécutées ne sont pas comparés ; « meilleure baseline » signifie ici meilleure parmi les bras effectivement mesurés.

## Diagnostic des erreurs

Le registre [findings.json](phase4-audit-2026-10-21/findings.json) contient outil, règle, cas, ligne, CWE déclaré, CWE attendu et contexte structurel pour chacune des 1 749 localisations d'alertes. Toutes ces lignes existent dans le fichier épinglé ; cela ne démontre pas qu'elles visent le puits attendu.

- **Contamination par une alerte hors sujet :** 360/533 alertes Bandit, 358/578 Semgrep et 40/319 par suite CodeQL n'ont pas de correspondance CWE exacte. Cela inclut des taxonomies plus générales ou différentes : un désaccord CWE n'est pas automatiquement un faux positif. Exemple : les 71 alertes Bandit B324 sur les cas de hachage ne correspondent pas exactement au CWE du label. Un filtre exact peut donc retirer une détection pertinente.
- **Exemple vérifié, `BenchmarkTest00008` :** le label épinglé est `pathtraver,true,22`. Le cookie alimente `bar` via une branche déterminée par une constante, puis un chemin à la ligne 52. Semgrep signale le cookie ligne 26 (CWE-614), pas ce chemin ; CodeQL signale `py/path-injection` ligne 52 avec CWE-22. Bandit ne signale pas ce cas. La préoccupation historique sur le label ne justifie aucune exclusion de cette version positive.
- **Règles locales et imports :** les alertes Bandit B405/B314 et les règles Semgrep `use-defused-xml*` peuvent signaler l'usage d'une API ou un import sans résoudre le flux du cas. Cela explique une partie de la contamination intercatégories ; il faut lire le flux pour attribuer une cause à chaque FP, plutôt que confondre simple API dangereuse et entrée exploitable.
- **Faux négatifs grossiers :** Bandit ne trouve aucun positif path traversal (65), LDAP (16), redirect (13), secure cookie (24), trust boundary (18), XSS (31). Semgrep manque 61/65 path traversal et 91/99 weak randomness ; aucun TP XSS. CodeQL manque tous les positifs hash (71), weak randomness (99), LDAP (16), SQLi (5), trust boundary (18), XSS (31). Ces nombres décrivent les configurations testées, pas une impossibilité générale des outils.
- **FP persistants même après CWE :** CodeQL trouve 45 TP mais 65 FP grossiers sur path traversal ; XPath donne 19 TP/40 FP. La correspondance de catégorie ne résout pas les branches constantes, écrasements et flux sûrs. L'attribution sémantique exhaustive de ces erreurs reste à réaliser ; elle n'est pas remplacée par ce diagnostic agrégé.

## Ablations et prototype minimal

| Filtre exact sur métadonnées CWE | TP | FP | FN | F1 |
|---|---:|---:|---:|---:|
| Bandit | 108 | 25 | 344 | 36,92 % |
| Semgrep | 69 | 71 | 383 | 23,31 % |
| CodeQL, chaque suite | 114 | 150 | 338 | 31,84 % |

**Résultat négatif :** filtrer strictement les CWE réduit le bruit et dégrade le rappel/F1. Ce filtre n'est donc pas activé comme correction du détecteur. Les scores grossiers restent disponibles pour la continuité ; les deux variantes figurent par catégorie dans le JSON.

`decision_context` construit un contexte AST autour de la ligne de décision et remonte les définitions des noms utilisés dans la fonction. Il ne reçoit ni label ni catégorie. Il conserve volontairement les branches englobantes et toutes les définitions candidates, sans éliminer une alerte. Il réduit le contexte agrégé de 36 471 à 13 266 occurrences d'instructions (63,63 %), doublons d'alertes inclus. **Aucune décision ne change**, aucun gain de précision ou temps du scanner n'est revendiqué. L'extraction ne résout pas imports, appels, alias, mutations, contrôle interprocédural ou sanitizers ; ce n'est ni un programme exécutable réduit ni une preuve de sûreté. Les tests couvrent la dépendance transitive, le maintien de l'incertitude et l'absence de certification. Un véritable sélecteur PRISM qui supprime des analyses serait prématuré avant adjudication et vérification indépendantes.

## Corrections techniques

- Un JSON valide ne suffit plus : codes de sortie, erreurs et inventaires des fichiers scannés sont vérifiés. Une analyse partielle n'alimente plus les politiques OR/AND comme si elle était complète.
- CodeQL : SARIF sans run/résultats ou avec invocation échouée rejeté. Les absences d'alerte restent `unsupported` sans attestation explicite de scan complet. L'attestation exige les diagnostics d'extraction de tous les modules ; le workflow push/manuel la fournit après succès de l'analyse.
- Correspondance de chemin bornée au nom de fichier, décodage URI, règles SARIF dans les extensions et localisations par index d'artefact pris en charge dans l'audit. Les localisations de trace ne sont pas converties en alertes indépendantes.
- Workflows : tests Phase 4 élargis et dépendances de chemins ajoutées pour les nouveaux modules.

## Coûts et limites de comptabilité

- Artefact statique retenu : Bandit **5,41 s**, Semgrep **21,00 s** ; union fixe **26,41 s** de temps outil. Les autres timings historiques (dont 20,61/17,19 s) appartiennent à d'autres runs et ne sont pas mélangés à cette mesure.
- CodeQL : default **184 s de job**, dont 56 s initialisation et 103 s analyse ; extended **187 s**, dont 53 s et 107 s. Total des deux jobs **371 secondes-runner**, parallélisme possible. Ce sont des durées de job incluant préparation/nettoyage, pas des temps CPU. La résolution à la seconde affiche parfois 0 s pour normalisation/tests : cela ne signifie pas un coût nul.
- Union Bandit/Semgrep/CodeQL : coûts des composants déclarés séparément ; pas de total comparable end-to-end mesuré sur une même machine. L'extended n'apporte aucun cas supplémentaire dans ce rejeu.
- Rejeu local : durée mesurée dans `audit.json`, incluant lecture des données, normalisation, scoring et contexte ; temps du contexte avec lecture des sources également ventilé par outil. La sérialisation finale n'est pas incluse dans ce chronomètre ; téléchargements, installation, développement, mémoire maximale, consommation CPU, facturation et tokens de l'agent ne sont pas entièrement observables. Ils sont déclarés **inconnus**, pas gratuits. Aucun ratio d'accélération end-to-end n'est démontré.

## Validation et reproduction

Suite locale : **66 tests, succès avec 1 échec attendu préexistant**, Python Windows avec `PYTHONUTF8=1`. Sans UTF-8, un test Phase 3 échoue déjà avant les modifications sur l'affichage d'une flèche ; c'est une contrainte de console, pas une régression scientifique. Contrôle de diff sans erreur. La CI GitHub doit être vérifiée séparément après publication.

```text
python -m unittest discover -s tests -v
python scripts/audit_phase4.py --labels benchmark/expectedresults-0.1.csv --source-dir benchmark/testcode --input bandit=artifacts/bandit-raw.json --input semgrep=artifacts/semgrep-raw.json --input codeql-default=artifacts/default/python.sarif --input codeql-extended=artifacts/extended/python.sarif --output reports/phase4-audit-2026-10-21
```

Les répertoires `artifacts` désignent les fichiers des IDs ci-dessus décompressés ; le benchmark doit être au commit épinglé. Le rejeu accepte des sorties archivées : leur complétude doit être vérifiée avant une interprétation des scores, comme fait ici pour les deux jobs CodeQL. Le runner principal applique désormais les contrôles de complétude.

## Porte indépendante préservée

Aucune donnée indépendante n'a été ouverte ou réglée dans cette itération. Avant une revendication comparative : choisir et épingler un corpus Python indépendant, figer les familles, les règles de correspondance sémantique et les coûts, adjudiquer des alertes positives et des absences, puis exécuter les politiques figées avec répétitions et intervalles par famille. Java/Juliet peut constituer une réplication séparée, pas une preuve directe de performance Python. La Phase 4 reste ouverte.

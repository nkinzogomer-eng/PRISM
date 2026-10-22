# PRISM D2.4 — protocole indépendant et limites de cette première livraison

**Gel initial 22 octobre 2026.** Première expérimentation sur des **références extérieures à notre code**. Aucun signalement de vulnérabilité n'est encore attribué à PRISM. Phase D2.4A = prérequis vérifiés ; D2.4B = audit/mesure de découvertes effectives sur de vraies cibles, NON encore effectué.

## Source externe figée AVANT mesure

- Projet de benchmark indépendant : `scfuzzbench/scfuzzbench`, commit catalogue **`de70065957a32fc5dd5fba3e53bb60f8564c722c`**.
- Fichiers à charger : `benchmarks/targets.json` et `benchmarks/known_bugs.json`, exclusivement via URLs de ce commit ; inscrire leur SHA-256.
- Cinq cibles de protocoles indépendants : Aave v4, Superform v2 Periphery, Liquity v2 Governance, Origin Dollar (OUSD) et Drips. Chaque cible possède un commit Git 40 hex figé et un chemin de propriétés. Vérifier l'identité cible/révision de la table de vérité.
- Premier test de compatibilité source réel : `scfuzzbench/origin-dollar-scfuzzbench` au commit **`299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4`**. Compilation locale de l'ABI de son contrat `OUSD` avec Foundry épinglé.
- **13 issues documentées** dans le catalogue : 12 sur OUSD, 1 sur Drips ; **10 canaries exclues** : deux par cible. Les trois autres cibles ne possèdent pas encore d'issues confirmées dans cette version du catalogue. Cela **ne prouve pas qu'elles sont dépourvues de vulnérabilités**. Les alias de fuzzers sont dédupliqués par ID de cause racine.
- Les preuves d'une issue et ses alias doivent être ancrés à l'exacte révision cible. Rejeter références flottantes, contradictions de révisions et doublons. Un crash, une canary, un alias ou un échec de compilation ne vaut pas vulnérabilité.

## Séparation des informations et de l'évaluation

Le préparateur produit deux fichiers distincts :
- **`detector-public-targets.json`** : URL, commit et chemin des propriétés. Aucun ID de vulnérabilité ni preuve d'attaque. Seul ce fichier peut devenir une entrée de PRISM lors d'une future campagne.
- **`judge-only-known-bugs.json`** : registre d'évaluation contenant les identifiants, alias de scanners et canaries ; réservé au rapprochement postérieur aux tests. Les fichiers résident dans le même environnement CI pour cette phase : séparation de logique, **pas un véritable secret ni un holdout cryptographiquement scellé**.

Le compilateur de propriétés D2.3 se limite aux patrons `oracle`, `lender` et `asset`. Appliqué au contrat OUSD seul (rôle `asset`), il doit indiquer les rôles absents comme **UNKNOWN** et ne jamais requalifier un jeton en oracle ou prêteur. Cette expérience peut donc révéler une **non-généralisation** des patrons à un produit réel qui possède du rebasing.

## Définitions scientifiques à ne pas contourner

- **Échantillon externe connu** : bug observé par des chercheurs tiers avant ce projet. Les labels sont publics, donc pas *blind holdout* ; même avec séparation des fichiers il peut exister contamination par connaissances publiques.
- **Éligibilité** : seuls les issues pour lesquels une propriété vérifiable et un environnement local reproductible sont spécifiés *avant* le test entrent dans le dénominateur de rappel. Ne pas convertir « outil inapplicable / non exécuté » en faux négatif, vrai négatif ou résultat nul.
- **Succès de découverte** : une hypothèse générée sans connaître son label aboutit à une **exécution EVM indépendante** qui confirme la violation et une comparaison à l'état protégé ou à un invariant pertinent ; le rapport contient transaction, sévérité contextualisée, code et versions épinglés, journal brut et coût total. Lire une étiquette historique n'est PAS une découverte.
- **Comparaison** : Foundry stateful, Echidna, Medusa et éventuellement outils symboliques, avec propriétés identiques, budgets identiques, instances équivalentes, plusieurs runs et distributions ; appliquer un oracle de confirmation uniforme. Les canaries sont des contrôles d'instrumentation hors statistiques de vulnérabilité.
- **Ablation SCM** : mêmes propriétés et même vérificateur, comparer planning SCM, politique FIFO, et approche coût/information conventionnelle. Métriques : TP/FP/FN/TN par cause racine, taux d'abstention, preuves confirmées, coûts EVM et CPU/RSS, temps humain de conception des propriétés, temps total incluant compilation/chargement.

## Jalons exécutables de cette PR

1. Tester un parseur indépendant de catalogue et ses rejets adversariaux (ancien SHA, faux domaine GitHub, doublons, canary comptée comme vulnérabilité, preuve sans SHA cible).
2. Télécharger/valider les deux catalogues au commit indépendant, produire un registre de cibles public séparé du juge et enregistrer les SHA.
3. Cloner OUSD **à la révision exact** ; compiler ABI du contrat réel sans aucune métadonnée de faille dans les entrées ; tester si le compilateur D2.3 peut s'appliquer sans inventer de rôles.
4. Rapporter honnêtement PASS/FAIL et les coûts réels. Si Foundry ne peut pas compiler OUSD sur le runner, l'erreur est un obstacle mesuré, pas une observation de vulnérabilité.

**Les étapes 1–4 ne produisent PAS encore de test d'attaque, d'audit ou de classement comparatif.** Les exposer comme « 0/13 », « 13/13 » ou supériorité scientifique serait trompeur.

## Conditions de passage D2.4B

Après préflight réussi, choisir quelques propriétés indépendantes et *exécutables* sur le matériel disponible, déterminer les capacités de déploiement sans RPC de production, construire l'environnement EVM local et un oracle de vérité par propriété, puis exécuter la première comparaison complète. Si OUSD est trop coûteux, sélectionner un sous-protocole externe moins lourd par règles déclarées avant examen des résultats, documenter le remplacement et ne pas dissimuler l'abandon.

**NO-GO pour déclaration de supériorité tant qu'aucune découverte additionnelle EVM-confirmée contre une baseline équitable sur ces cibles indépendantes n'existe.**

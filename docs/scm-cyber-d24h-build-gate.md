# SCM/PRISM D2.4H — unprompted source-based security hypotheses

**26 octobre 2026. Reconstruction orientée capacité et résultats. Ciel reste gelé.**

## Hypothèse technique

PRISM doit recevoir **seulement un fichier Python local autorisé**, sans indication de vulnérabilité, de propriété à vérifier, de CVE, de version corrigée ni de famille de détecteur. Le compilateur AST extrait lui-même les opérations sensibles du programme, les organise en hypothèses explicites, alloue un budget et déclenche un adaptateur isolé *seulement* lorsqu'une implémentation reconnue peut être confrontée à un oracle de sécurité distinct.

Premières familles, sans garantie sémantique : (1) limites de racines de fichiers, (2) dépendance des entrées externes vers un shell/évaluateur, (3) secrets possiblement transmis à des journaux. L'exécution réelle est limitée à des méthodes de chemins tiers sûres et isolées ; les autres familles **restent HYPOTHESIS_UNVERIFIED** plutôt que devenir de fausses découvertes. Les heuristiques lexicales et de taint ne sont pas une analyse complète des alias, des graphes multi-fichiers, des appels dynamiques ou des permissions.

## Critères opérationnels

1. Signaux AST attribués à une fonction et une ligne, compilation de plusieurs familles de propriétés *sans cible préspécifiée*.
2. Tests adversariaux contre les faux positifs (subprocess avec shell=False, logs sans secret), les erreurs de syntaxe, l'absence de preuve et les budgets insuffisants.
3. Vrai code tiers Starlette et Werkzeug sur anciennes versions, avec génération automatique de l'hypothèse chemin puis rejouage ; versions corrigées *analysées séparément*, aucune fuite du correctif vers le moteur.
4. Source actuelle Django analysée avec la même interface. Un résultat sans témoin indique **aucune violation observée pour les essais exécutés**, jamais une certification générale de sécurité.
5. JSON brut, provenance, ressources, limites, incertitude, historique explicite ; pas de revendication nouvelle zero-day.
6. Aucun commit sur la branche principale. Aucun développement ni modification du dépôt Ciel.

## Ce que D2.4H ne démontre pas

La sélection des deux cibles historiques reste biaisée par les expériences passées. De plus, les tests de chemins reprennent la même famille de problèmes : la généralité de découverte d'erreurs imprévues n'est pas encore prouvée. Les familles shell et secret vérifient surtout la **génération de candidats**, pas des exploitations réelles. La prochaine véritable étape consiste à fournir, sans connaissance de cause racine ni de correctif, un ensemble indépendant de programmes autorisés et d'oracles, puis à ajouter des vérificateurs concrets pour les nouvelles familles et la compréhension multi-modules.

**Un pipeline vert n'est pas une percée. Le prochain GO scientifique exige une violation indépendante d'un cas non utilisé pour choisir nos règles.**

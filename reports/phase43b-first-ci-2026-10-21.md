# SCM / PRISM Phase 4.3B — rapport de la première exécution (2026-10-21)

**Décision scientifique :** VALIDATION D'INGÉNIERIE PARTIELLE (conservation exacte des alertes normalisées sur le benchmark de développement) ; **aucun avantage propre à SCM face au cache SHA-256 classique n'est établi**. La PR #16 reste en brouillon.

## Références, reproductibilité et limites

- [CI Linux réussi — run 39636258329](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39636258329).
- [Sorties brutes JSON et mesures](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39636258329/artifacts/12362395316).
- [PR #16](https://github.com/nkinzogomer-eng/PRISM/pull/16).
- 14 tests unitaires/adversariaux Phase 4.3B réussis ; 9 tests Phase 4.3A réussis.
- Corpus de développement : OWASP Python v0.1, 1 230 modules, référence de source `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. Manifeste exact d'octets du checkout Linux `fe0ec67dcc328feb33d592b790563add38c721af4b89abcf839e56bc9e3b9b9d`.
- Bandit 1.8.6 ; Semgrep CE 1.181.0 ; règles immuables `17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9` (security Python + Flask). Deux répétitions par scénario, ordre tournant sur Linux hébergé.
- Modifications synthétiques sur des copies des modules : un ajout de commentaire, ou un appel `eval("1 + 1")` pour un module modifié sur huit. Aucun programme tiers n'est exécuté et les labels originaux ne sont PAS utilisés pour scorer la sécurité des copies modifiées.
- Les durées d'analyse sont de véritables processus, incluant dans chaque bras la lecture, les empreintes, la préparation, la sélection, la copie, l'analyse, le contrôle d'inventaire, la fusion des alertes et le nettoyage. Installation/réseau et sérialisation finale exclus ; mémoire maximale, énergie et argent non mesurés, non supposés nuls.

## Résultats de coût end-to-end

Médianes de **deux répétitions** seulement, en secondes :

| Fichiers modifiés | Analyse complète | Cache SHA-256 classique | Contrôleur PRISM | Gain PRISM vs complète | Gain cache classique vs complète |
|---|---:|---:|---:|---:|---:|
| 1 / 1 230 | 16,098 | 5,195 | 5,117 | 68,2 % | 67,7 % |
| 123 / 1 230 | 15,715 | 6,308 | 6,086 | 61,3 % | 59,9 % |
| 1 230 / 1 230 | 15,833 | 15,688 | 15,766 | 0,4 % | 0,9 % |

Interprétation de la dernière ligne : les différences inférieures à 1 % ne sont pas un gain démontré ; variation de runner et ordre peuvent les expliquer. Le contrôleur a choisi la même analyse incrémentale que le cache conventionnel sur 1 et 123 fichiers modifiés, et une analyse complète lorsque tous les fichiers étaient modifiés. Une variation de quelques dixièmes de seconde entre le contrôleur et le cache ne prouve **aucune supériorité SCM**.

Construction initiale du cache complet : Bandit **3,384 s** et Semgrep **12,599 s**, environ **15,983 s** combinés, hors coûts exclus précédemment. Toute revendication d'économies sur le cycle de vie doit amortir cette construction sur plusieurs mises à jour ; une exécution unique n'en profite pas gratuitement. Dans des missions où un scan initial complet est déjà nécessaire, il peut servir au cache sans invocation supplémentaire, mais son coût existe quand même.

## Vérification des résultats des scanners

- **12 comparaisons appariées exactes sur 12 réussies** (3 volumes de modifications × 2 répétitions × 2 politiques incrémentales contre le scan complet).
- Pour la modification d'un fichier, les trois politiques conservent **534 résultats normalisés Bandit** et **578 résultats normalisés Semgrep**.
- Pour 123 fichiers modifiés : **549 résultats Bandit**, **578 résultats Semgrep**.
- Pour 1 230 fichiers modifiés : **687 résultats Bandit**, **578 résultats Semgrep**.
- Les identités des alertes comparent module, outil, règle, ligne, colonne, message, sévérité, et pour Bandit confiance. La multiplicité est préservée. **Ce n'est pas une identité byte-for-byte de tous les champs JSON bruts** ; les chemins temporaires et certaines métadonnées non essentielles ne sont pas conservés.
- Le cache classique et SCM réanalysent exactement 1, 123 ou 1 230 fichiers pour chaque scanner dans les scénarios respectifs. Le contrôleur ne supprime aucune analyse au-delà de ce que réalise déjà le cache classique.

## Causes et conclusions

1. **Le gain énorme face à la réanalyse complète provient de l'incrémentalité par empreinte connue**, pas d'une nouvelle primitive SCM. C'est utile opérationnellement sur des missions avec petites mises à jour, mais banal scientifiquement.
2. **Le verrou dur de SCM reste l'unité de calcul** : le fichier entier. Pour surpasser un cache par fichier, nous devons réutiliser de façon justifiée du travail même quand des octets changent, par exemple à l'échelle des règles, fonctions, dépendances ou preuves partielles, puis l'évaluer contre les caches natifs.
3. **Sûreté insuffisante pour le déploiement** : les tests appariés montrent l'équivalence empirique sur ce corpus, mais ne prouvent pas qu'un scanner soit indépendant des autres fichiers, ni qu'aucune importation, règle inter-fichier, métadonnée, configuration ou entrée environnementale cachée ne puisse affecter le résultat. Une utilisation en production doit revenir à une analyse complète quand ces dépendances sont inconnues.
4. **La nouvelle baseline forte est fixée** : tout futur gain SCM doit battre le cache exact SHA-256 (et ensuite un cache natif équivalent) à qualité des résultats comparable, en intégrant coûts de découverte, planification, invalidation et vérification.
5. **Validation indépendante toujours ouverte** : aucune donnée indépendante/holdout n'a été ouverte. Les variations mesurées sur deux répétitions sont exploratoires et ne permettent ni intervalle de confiance robuste ni inférence p95.
6. **Aucune conclusion sur les zero-days ni sur la qualité de détection** : les alertes des scanners ne sont pas des vulnérabilités validées. Les labels OWASP ne décrivent pas les fichiers synthétiquement modifiés.

## Prochaine expérience — Phase 4.3C (non encore validée)

Rechercher une **preuve de non-pertinence d'un changement par rapport à une propriété/règle** permettant d'éviter une analyse autrement forcée par le hash-cache. Tester d'abord les contre-exemples : directives de suppression `nosec`/`nosemgrep`, règles sur commentaires/texte brut, modifications de lignes et d'offsets, imports/alias, propagation inter-fichier, règles et options de scanners qui changent. Si aucune preuve bornée n'est disponible, retourner `UNKNOWN` et exécuter le scanner ; jamais annoncer une absence de vulnérabilité.

Comparer en aveugle contre le cache classique et les optimisations natives pertinentes. Si seules des heuristiques empiriques fonctionnent, les appeler des heuristiques et ne pas les activer pour une garantie de conservation complète. Maintenir la PR #16 en brouillon.

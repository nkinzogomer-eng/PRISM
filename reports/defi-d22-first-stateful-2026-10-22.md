# SCM / PRISM — DeFi D2.2: résultats scientifiques vérifiés (22 octobre 2026)

**Décision : PASS de la chaîne technique et des témoins EVM ; NO-GO pour toute revendication d'avantage de découverte SCM sur une baseline compétente, de performance réelle supérieure ou de zero-day.** Ne pas fusionner ni déployer.

## Exécution et provenance

- [CI GitHub Actions réussie, run 39844671643](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39844671643).
- [Artefacts complets générés et bruts](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39844671643/artifacts/12453593681) : `candidate-and-model.json`, `evaluation.json`, 5 sorties `forge test --json` (tests générés, oracle, retrait, remboursement, variante protégée) et journaux stderr, tests Solidity générés.
- [PR #23](https://github.com/nkinzogomer-eng/PRISM/pull/23) ; branche `research/defi-d22-multi-property-stateful`, basée sur D2.1 #22, ni D2.0 ni `main` modifiés.
- Environnement CI GitHub Linux, Python 3.12, Solidity 0.8.24, Foundry v1.3.6 ; fuzzing stateful configuré **256 campagnes × 64 appels** dans `foundry.toml`, `fail_on_revert=false`.
- **12 tests D2.2 + 11 tests D2.1 + 11 tests D2.0 réussis** ; 6 tests Solidity générés réussis sur EVM ; 4 campagnes stateful natives, chacune avec quatre invariants (conservation + 3 propriétés). Les trois campagnes vulnérables *échouent intentionnellement pour le motif spécifique attendu*, tandis que toutes les autres propriétés et le contrôle protégé réussissent.

## Matrice des 12 observations — dev synthétique exclusivement

Les trois familles sont : autorisation de changement de prix d'oracle (`ORACLE_AUTH`), solvabilité lors d'un retrait de collatéral (`WITHDRAW_SOLVENCY`), contrepartie en jetons d'un remboursement de dette (`REPAY_CONSERVATION`).

| Variante testée | Oracle AUTH | Retrait SOLVENCY | Remboursement CONSERVATION |
|---|---|---|---|
| Oracle sans contrôle d'accès | **Violation confirmée** | Pas de violation détectée | Pas de violation détectée |
| Retrait sans contrôle de garantie | Pas de violation détectée | **Violation confirmée** | Pas de violation détectée |
| Remboursement sans transfert | Pas de violation détectée | Pas de violation détectée | **Violation confirmée** |
| Variante protégée (3 contrôles) | Pas de violation détectée | Pas de violation détectée | Pas de violation détectée |

Le modèle PRISM orienté propriété, son contrôle exhaustif BFS et le fuzz **stateful à handler réellement indépendant** renvoient, pour les **12 cellules de ce corpus de développement** : `TP=3, FP=0, FN=0, TN=9`, `précision=100 %` et `rappel=100 %`. **Ces pourcentages concernent exclusivement les défauts volontairement injectés et connus des concepteurs**. Un résultat `Success` du fuzz ou une absence de témoin dans la recherche de profondeur 4 n'est **pas** une preuve de sûreté universelle ; « TN » ici veut dire « étiquette de développement négative sans violation observée sous ces propriétés et budgets ».

Les contrôles EVM générés sont particulièrement utiles : chaque témoin de modèle est converti en trace Solidity et vérifie soldes des jetons, collatéral bloqué, dettes et prix ; une variante sûre est exécutée en contrôle dans un deuxième test. Le moteur Python ne dépend pas de l'EVM pour calculer les candidats ; l'EVM réfute ou confirme ensuite. Un faux positif de modèle aurait dû interrompre le pipeline.

## Effort de recherche dans le modèle abstrait

| Défaillance cible | États BFS développés avant témoin | États guidés avant témoin |
|---|---:|---:|
| Oracle sans contrôle | 4 | 2 |
| Retrait non garanti | 19 | 4 |
| Remboursement non financé | 19 | 4 |

Pour les neuf cas négatifs de développement, l'explorateur guidé n'a pas réduit le nombre d'états par rapport à BFS ; chaque recherche s'est terminée dans sa profondeur 4, sans épuisement de budget. Ces chiffres décrivent **uniquement un petit modèle mathématique codé à la main**. Le classement était déjà adapté aux propriétés ; il ne traduit ni le nombre de chemins EVM, ni le temps total d'un audit, ni la découverte d'une nouvelle famille.

## Temps réels observés sur CI, une seule exécution

| Processus Foundry | Temps mur (s) | CPU cumulée enfants (s) | Sortie |
|---|---:|---:|---|
| 6 tests EVM générés | 1,1366 | 0,3419 | Succès |
| Stateful oracle non protégé | 1,5259 | 3,1698 | Violation attendue |
| Stateful retrait non protégé | 1,1273 | 2,7128 | Violation attendue |
| Stateful remboursement non protégé | 1,1113 | 2,6706 | Violation attendue |
| Stateful tous contrôles sûrs | 1,3123 | 4,5853 | Tous les invariants passent |

**Ne pas comparer directement la première ligne au fuzz à quatre variantes :** compilation, objectifs et couverture diffèrent ; le premier test exploite trois traces déjà construites, tandis que les autres recherchent leurs propres séquences. La durée de spécification manuelle des propriétés, l'écriture du modèle et l'installation ne sont pas mesurées ; la CPU accumulée reflète potentiellement plusieurs threads de l'analyseur. Une seule exécution CI ne permet ni intervalle de confiance ni gain général.

## Résultat négatif décisif

**Foundry stateful trouve les mêmes trois défauts de manière indépendante.** PRISM n'a découvert aucune violation supplémentaire confirmée par rapport à cette baseline correctement configurée sur cette suite. C'est la limite majeure, et non un détail à masquer derrière le taux de rappel parfait.

Les vulnérabilités sont **injectées artificiellement** dans un marché fictif ; propriétés, modèle abstrait, heuristique et labels ont été conçus dans le même projet. **Contamination développement intrinsèque : le test ne mesure pas la capacité de PRISM à détecter des défauts inconnus dans des contrats tiers.** Les jetons ne sont pas de vrais ERC-20, les marchés n'ont ni liquidation, ni intérêts, ni règles d'oracle réalistes, ni acteurs multiples complexes.

Le monitoring du fuzz stateful a été écrit à partir des mêmes *propriétés publiques* que PRISM, mais pas de ses plans. Ce test montre que l'approche concurrente peut produire des contre-exemples sans suivre le chemin du planificateur SCM.

## GO / NO-GO / prochaine recherche

- **GO technique :** D2.2 produit trois violations de mécanismes différents, les confirme sur une EVM réelle locale, vérifie des variantes corrigées et exécute une référence stateful contradictoire sur les mêmes propriétés.
- **NO-GO scientifique :** aucune avance en couverture, précision ou coût total démontrée face à Foundry. Ne pas faire de déclaration d'état de l'art, de zero-day, de vulnérabilité « critique » ou de sécurité production.
- **D2.3 recommandée :** cesser de coder à la main les mêmes propriétés dans les deux systèmes comme objectif final. Tester une sélection **automatique** des propriétés à partir des contrats et de leurs invariants financiers déclarés indépendamment, ainsi que des interactions temporelles plus profondes (multi-utilisateurs, prix, intérêts, liquidation, frais). Geler un protocole, des budgets et un holdout avec défauts non conçus par le moteur. Comparer les avantages à un fuzz de séquences, un fuzz invariant et des outils symboliques correctement paramétrés, avec temps humain/computation/confirmation et coûts d'installation séparés.

Aucune conclusion positive sur une nouvelle capacité SCM ne sera acceptée avant la confrontation indépendante hors développement.

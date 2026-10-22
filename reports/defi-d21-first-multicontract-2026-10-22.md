# PRISM DeFi D2.1 — première expérimentation multi-contrats vérifiée (22 octobre 2026)

**Verdict : PASS technique de la chaîne modèle→transactions→EVM, NON pour la supériorité de découverte et NON pour tout déploiement réel.** Résultat **synthétique de développement**, un seul mécanisme de vulnérabilité.

## Périmètre et exécution

- PR brouillon : [#21](https://github.com/nkinzogomer-eng/PRISM/pull/21), branche `research/defi-d21-multicontract-lending`, basée sur la branche D2.0 ; `main` et le précédent travail restent préservés.
- [Exécution GitHub Actions réussie 39839491633](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39839491633) à l'état du code `9bf3e2e856aedce28d2674d83fc28cbe0472ddf9`, [artefacts bruts](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39839491633/artifacts/12452990785). Versions : Foundry v1.3.6, Solidity 0.8.24, Python 3.12.
- 15 tests Python passés ; 9 tests EVM de la suite de validation/contrôle passés (dont fuzz de contrôle et invariants gardés).
- Foundry fuzz conventionnel sur variante vulnérable : échec **attendu** `D21_FAIR_LTV_WITNESS`. L'échec est accepté comme preuve que **la baseline a elle aussi découvert le défaut**.
- Foundry invariant **stateful avec handler** sur variante vulnérable : deux propriétés évaluées, violation de juste collatéral détectée avec motif `D21_FAIR_LTV_WITNESS`, propriété de conservation maintenue. La variante protégée passe les contrôles exécutés.
- L'expérience ne lit aucun protocole déployé, ne fork pas de réseau réel, et n'utilise que des jetons fictifs à émission libre pour initialiser les comptes.

## Propriété financière et scénario proposé par le moteur

Le protocole local rassemble un pool constant-product simplifié (source de spot), une garde de garantie autonome, un prêteur et un acteur. Dans le contrôle, le prêteur évalue la garantie à **1 quote / 1 collatéral** ; dans la variante vulnérable, il dépend du spot du pool. LTV = 75 %. Ces choix sont des **hypothèses artificielles du laboratoire**, pas des règles générales pour un protocole DeFi réel.

Trace candidate générée **par le moteur** (pas codée directement comme test de découverte) et confirmée ensuite par le test EVM :

1. `pledge(10)` — 10 collatéraux bloqués.
2. `pump(100)` — achat local avec 100 quotes, réserves du pool 100/100 → 200/50 ; prix spot passe de 100 à 400 en unités de 1/100.
3. `borrow(20)` — accepté par le prêteur dépendant du spot gonflé : le crédit autorisé temporairement est 30, alors que la référence permet au plus **7** unités entières.
4. `unwind(50)` — revente de 50 collatéraux ; réserves reviennent à **100/100**, spot = 100. La dette de 20 subsiste, contre une garantie de valeur 10 et un plafond de crédit de 7.

La recherche a prédit et Foundry a vérifié les soldes de l'acteur après la séquence : **220 quotes, 90 collatéraux liquides, 10 collatéraux bloqués, dette 20**, réserve prêteur 480 quotes, pool restauré 100/100. Les avoirs liquides correspondent à 310 contre 300 initialement **à la valeur de référence fixée dans le laboratoire** ; en abandonnant le collatéral (défaut hypothétique, pas une opération implémentée), les actifs liquides excéderaient ceux du départ de 10, tandis que le prêteur aurait une exposition non couverte. Les frais, intérêt, liquidations, exécution du défaut et toute valeur de marché sont hors modèle : **aucune rentabilité ou exploitabilité réelle n'est démontrée**.

La variante de contrôle indépendante refuse `borrow(20)` après le même préfixe, sans transférer de quotes ni enregistrer une dette. Cela résout la propriété de référence testée, et **ne garantit aucune sécurité universelle du contrôle**.

## Coût de recherche sur le modèle fini

Observé en une seule exécution CI, profondeur maximum 4, alphabet partagé de 11 actions, plafond 30 000 états :

| Variante | Politique | Témoin | États explorés | Transitions essayées | Temps modèle |
|---|---|---|---:|---:|---:|
| Spot vulnérable | BFS | oui | 463 | 2 222 | 0,00994 s |
| Spot vulnérable | classement orienté propriété | oui | **14** | **66** | 0,00039 s |
| Prix ancré | BFS | non | 693 | 2 101 | 0,00780 s |
| Prix ancré | classement orienté propriété | non | 693 | 2 101 | 0,00924 s |

Sur le scénario vulnérable : **97,0 % d'états en moins (463 → 14)** et **97,0 % de transitions en moins (2 222 → 66)** par rapport au BFS simple. Ces résultats concernent le classement d'états abstraits dans un modèle écrit à la main, **et non** le nombre de vulnérabilités détectées ni un audit Solidity complet. Sur la variante corrigée, **aucun avantage en états** et un surcoût temporel observé ; aucune preuve d'absence de failles en dehors de cette abstraction et de la profondeur 4.

Le classement est hand-crafted à partir de la propriété/du mécanisme attendu. Sa performance ne peut pas être généralisée sans évaluation indépendante et comparaison à des méthodes de recherche plus fortes que BFS.

## Contre-épreuve : baselines compétentes

- `D21FuzzVulnerableTest` trouve indépendamment le crédit supérieur à la couverture juste, en variant le spot, le collatéral et le montant emprunté. Le test contrôlé échoue pour **la raison attendue**.
- `D21StatefulVulnerableTest` enchaîne des opérations aléatoires `pump`, `pledge`, `borrow`, `unwind` sur le même déploiement à travers un handler, avec le budget Foundry **64 runs × 40 calls**. Il trouve **lui aussi** la violation, sans reprendre le candidat ni la politique de PRISM.
- Les variantes de contrôle de fuzz/invariant réussissent ; le rapport EVM observe les conservation des actifs. Les résultats bruts et métriques processus sont archivés.
- **Conclusion adverse : PRISM ne présente ici aucune vulnérabilité confirmée que des fuzzers Foundry correctement dotés de la même propriété ne savent découvrir.** Il serait faux d'annoncer une détection supérieure, un zero-day, une faille critique réelle ou une nouvelle classe de vulnérabilités.

## Limites scientifiques majeures

1. Le modèle de contrats et l'invariant ont été conçus autour d'une faiblesse connue (prix spot manipulable). Les instructions manuelles facilitent fortement la recherche ; pas de découverte automatique d'une propriété inconnue.
2. La source de prix « indépendante » du contrôle est un prix constant artificiel ; les vrais oracles exposent latence, confiance, adversaires et dynamiques de marché.
3. Une seule vulnérabilité de référence et son contrôle corrigé ; impossible d'estimer rappel, précision, faux positifs ou performance relative générale sur la DeFi.
4. BFS n'est pas l'état de l'art. Le comparateur Foundry stateful découvre lui-même la violation. Echidna, Halmos et moteurs inter-contrats ne sont pas encore exécutés dans D2.1.
5. Les coûts d'installation, contrats écrits à la main, découverte de propriété et intervention humaine ne sont pas amortis ; le temps du modèle Python n'est pas le temps total d'audit. CPU/RSS par étape sont fournis en artefacts CI, pas extrapolés à un audit réel.
6. **Sécurité** : aucun endpoint RPC externe, pas d'actifs ou contrats de tiers, pas de stratégie applicable par affirmation à un protocole existant.

## Décision

**GO restreint** pour conserver le pipeline multi-contrats vérifié comme infrastructure expérimentale. **NO-GO** pour prétendre que PRISM dépasse les outils existants.

**D2.2 :** préparer plusieurs familles de violations indépendantes (oracle, comptabilité de parts, contrôle d'accès, précision/arrondis, liquidation), contrats hétérogènes vulnérables/corrigés, propriétés cachées au moteur lorsqu'elles doivent être inférées, et un holdout historique gelé. Évaluer alors des **vulnérabilités distinctes confirmées par budget total** avec des baselines natives stateful et, lorsque possible, symboliques. L'heuristique doit être gelée avant consultation de cas hors développement et le coût de vérification compté.

## Revalidation indépendante du rapport (seconde exécution CI)

La CI a été relancée **sans modification de l'algorithme ou du protocole**, uniquement après ajout de l'affichage des ressources dans les journaux : [run 39839785798 — succès](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39839785798), [artefacts détaillés](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39839785798/artifacts/12453220748).

- 15 tests Python réussis, 9 contrôles EVM réussis, deux baselines vulnérables déclenchant explicitement `D21_FAIR_LTV_WITNESS`. Candidat identique : `pledge(10) → pump(100) → borrow(20) → unwind(50)`.
- Reproduction du nombre d'états : **463 vs 14** sur le vulnérable et **693 vs 693** sur le protégé. Transitions identiques à la première CI (**2 222 vs 66**, **2 101 vs 2 101**). Aucun gain de couverture des défauts démontré.
- Délais de parcours *sur cette seconde machine* : BFS vulnérable **0,006134 s**, recherche orientée **0,000241 s** ; contrôle BFS **0,004866 s**, classement orienté **0,005911 s**. Les différences sous la milliseconde ne prouvent pas une accélération robuste.
- Mesures wall/CPU/RSS de processus (même runner, outils chauds et compilation incluse dans la première commande EVM) : génération candidate **0,04 s / ~18,5 MiB RSS** ; EVM contrôles avec compilation **1,26 s / ~105 MiB RSS** ; fuzz paramétrique en échec attendu **0,02 s / ~59 MiB RSS** ; fuzz stateful en échec attendu **0,18 s / ~67 MiB RSS**. **Ces durées ne sont pas une comparaison de performance équitable entre moteurs** : compilation, tests, objectifs et caches diffèrent. Pas de mesure du coût humain ni du temps de dérivation de l'invariant.
- Résultat final reste **NO-GO pour avantage distinctif SCM**, **GO pour infrastructure multi-contrats candidate→EVM**.

Note méthodologique : les résultats de Foundry sur l'invariant pris isolément ne prouvent pas le profit financier ; seule une violation de l'hypothèse de couverture de référence est attestée. Le scénario de défaut et le coût d'une liquidation ne sont pas exécutés.

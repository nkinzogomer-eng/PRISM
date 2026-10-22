# SCM / PRISM — DeFi D2.4B : premiers tests exécutés sur le véritable OUSD

**22 octobre 2026 — PASS technique de vérification externe ; NO-GO scientifique pour la supériorité de découverte.** Aucun exploit connu retrouvé ou nouveau défaut de sécurité attribué à PRISM.

## Preuves vérifiées

- **CI finale réussie** : https://github.com/nkinzogomer-eng/PRISM/actions/runs/39855417282, commit de code testé `60f996c03901f058d19876b578d14f8660756882`.
- **Résultats EVM bruts, ABI, empreintes SHA-256, CPU et temps d'exécution** : https://github.com/nkinzogomer-eng/PRISM/actions/runs/39855417282/artifacts/12458657930.
- [PR #27](https://github.com/nkinzogomer-eng/PRISM/pull/27) encore en brouillon, basée sur D2.4A PR #25. `main` et D2.4A inchangées.
- Contrat tierce partie `scfuzzbench/origin-dollar-scfuzzbench` au commit **`299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4`** ; compilation du vrai contrat OUSD via Foundry v1.3.6, déploiement de son vrai environnement Echidna via une petite interface d'observation locale (pas de modification du code OUSD).
- **15 tests unitaires/adversariaux Python passés**. Le système refuse les mauvaises signatures ABI, répétitions, informations de juge en entrée et conclusions `SAFE` à la génération.

## Résultat réel sur code tiers

D'après les ABI compilées, deux **patrons génériques existants** ont été activés : `TRANSFER_SUPPLY_PRESERVED` (offre inchangée par un transfert réussi sans autre mint/burn/rebase) et `APPROVE_ALLOWANCE_OVERWRITE` (autorisation ERC20 écrite correctement). Le générateur a créé de vrais tests Solidity pour le code OUSD et les a exécutés, sans consulter les problèmes historiques du benchmark.

Deux exécutions de chaque méthode, sans échec de propriété :

| Méthode | Propriétés contrôlées | Répétitions | Résultat EVM | Temps mur `run0` / `run1` |
|---|---|---:|---|---:|
| Tests génériques PRISM `testFuzz` | 2 propriétés ERC20 | 2 | 2 tests `Success` dans chaque exécution | 3,2408 s / 0,5769 s |
| Foundry natif *stateful handler* indépendant | Conservation de `totalSupply` après transferts ; contrôle d'autorisation pendant les appels | 2 | 1 invariant `Success` dans chaque exécution | 2,3259 s / 1,2271 s |

CPU enfants : PRISM `3,2132` s puis `0,6244` s ; Foundry stateful `2,3667` s puis `1,2685` s. Les deux méthodes utilisent Foundry : l'appellation PRISM désigne ici **le choix/génération des propriétés**, et non un nouvel exécuteur EVM.

**Aucune vulnérabilité confirmée** : aucune violation de ces deux propriétés n'a été observée dans ces campagnes. Cela ne montre pas qu'il n'existe aucune faille dans OUSD : les propriétés sont étroites, et Foundry teste les mêmes comportements avec un autre espace de séquences.

## Bilan scientifique opposable

**Ce que cette expérience valide réellement** : (1) entrée de code externe à révision exacte, (2) compilation réelle ABI, (3) sélection automatique de deux contrôles génériques, (4) test EVM reproduit, (5) référence indépendante *stateful*, (6) preuves et coûts observables, (7) échec des hypothèses annoncé comme UNKNOWN plutôt qu'une sûreté prouvée.

**Ce qu'elle ne valide pas** :
- Aucune des 13 issues cataloguées en D2.4A n'a été cherchée via une hypothèse spécifique de cause racine et aucune de ces 13 n'a été confirmée. Le dénominateur d'un taux de rappel est donc **NON ÉVALUÉ**, pas `0/13`, et non un taux de vrais négatifs.
- Le code de source des tests upstream est public, et les modèles génériques ont été décidés par les chercheurs ; **pas de holdout aveugle**. Lire un manifest externe connu ne suffit pas à créer un test indépendant.
- Les tests PRISM sont *fuzz* à une transaction alors que le témoin Foundry est *stateful* multitransaction ; les budgets, propriétés et coûts de génération ne sont **pas équivalents**. Les temps ne soutiennent aucune victoire de performance.
- Le moteur ne dérive toujours pas de modèle comportemental financier depuis la totalité du code Solidity ; il infère des possibilités de tests depuis les signatures ABI.
- Les réussites d'invariants bornés ne prouvent aucune sécurité universelle ; absence de fuzz Echidna/Medusa/Halmos comparatif et d'évaluation multi-protocoles.

## Décision

**GO technique** : D2.4B dispose maintenant d'un chemin reproductible `source tierce → ABI → candidat générique → test EVM réel → comparaison stateful native`.

**NO-GO pour avantage scientifique** : zéro vulnérabilité additionnelle démontrée, aucune cause racine tierce nouvellement identifiée ; aucun taux de rappel/précision défendable.

**Prochaine mesure décisive D2.4C :** sur des révisions externes et entrées non connues de l'outil, geler les familles de propriétés, attribuer des identifiants distincts de cause racine **après** la vérification, comparer à des fuzzers stateful et symboliques avec budget d'observation égal, et enregistrer TP/FP/FN/UNKNOWN par propriété. La priorité doit être une **violation économique multi-transaction EVM-confirmée sur code non authored par nous**, non un autre résultat parfait sur des sources de laboratoire.

Toutes les limites et résultats négatifs doivent être conservés dans le rapport final.

# D2.1 — protocole multi-contrats et recherche d'une violation de solvabilité

**22 octobre 2026. Statut : développement local autorisé, non production.**

## Propriété fixée avant la CI

Avec un collatéral verrouillé `C`, un prix d'oracle `P`, un facteur de garantie `1/2`, et une dette `D`, on veut vérifier le prédicat d'état `D <= floor(C*P/2)` à l'issue de toute transaction. Le problème étudié est une **mise à jour non autorisée du prix**, suivie d'un emprunt puis du rétablissement du prix. On recherche un état où `D > floor(C*P/2)` et le solde d'actif emprunté a augmenté.

La propriété de solvabilité globale est simplifiée : le modèle **n'inclut ni liquidations, ni mouvements de marché légitimes, ni remboursements, ni prix temporels réels**. Dans un protocole réel, une sous-collatéralisation peut arriver sans intrusion via des mouvements de marché ; cette expérience cible spécifiquement l'élévation temporaire d'un oracle contrôlé par une partie non autorisée. Ne pas assimiler cette propriété simplifiée à l'invariant complet d'un protocole de prêt.

## Système de test indépendant du modèle Python

Trois composants Solidity au minimum : `DemoPriceOracle` (autorisation de mise à jour configurable), `DemoLender` (dépôt, dette, plafond), `DemoAsset` (actif de garantie et de prêt), plus `DemoTrader` pour distinguer l'émetteur de l'appel du propriétaire de l'oracle. Contrat local, jetons fictifs non ERC-20, aucun fork et aucun transfert réel.

Version vulnérable : tout appelant peut modifier le prix. Version protégée : seul le propriétaire du contrat d'oracle peut modifier le prix. Cette correction vise **cette seule propriété**, sans prouver une défense contre la mauvaise gouvernance de l'oracle, l'erreur du propriétaire, la volatilité ni des prix de référence compromis.

## Recherche et contrôles

Un alphabet fini `deposit(10|20)`, `change_price(20|2)`, `borrow(10|100)`, profondeur 4, états entiers, budget 100 000 ; BFS et une heuristique de pertinence écrite à la main visitent les **mêmes transitions** et appliquent les mêmes prédicats. L'état suit collatéral détenu/verrouillé, jetons de prêt détenus par le trader et le pool, dette et prix. Conservation des unités de chaque actif testée à chaque transition.

Le générateur produit une trace candidate et un **test Solidity indépendant** vérifiant tous les soldes attendus, la dette, le prix, la violation de limite d'emprunt et l'échec du même scénario sur la version protégée. L'EVM n'utilise pas le calculateur Python comme source de ses règles.

Un test `testFuzz` Foundry, sans appeler PRISM, reçoit la **même propriété** et cherche indépendamment un contre-exemple sur le contrat vulnérable ; l'échec attendu doit contenir exactement `D21_UNDERCOLLATERALIZED`. Le test fuzz de la version protégée doit réussir. Il s'agit de fuzz **paramétrique sur une séquence déjà définie** ; ce n'est pas un fuzz stateful à handlers, ni une baseline Echidna ou Halmos. Ne pas surévaluer cette concurrence.

## Critères GO/NO-GO

- **GO technique** seulement si le modèle produit la violation, si l'EVM confirme les balances et la dette, si la protection bloque la mutation non autorisée, et si la baseline fuzz est exécutée et sa raison d'échec contrôlée.
- **NO-GO** pour toute supériorité de PRISM si le fuzz indépendant retrouve le même témoin, si les heuristiques sont adaptées à l'incident, ou si seuls les états du modèle sont économisés.
- Aucune vulnérabilité « critique », zero-day ni système public compromis. Aucune preuve de complétude sur des contrats Solidity arbitraires.
- Suite prioritaire : génération de propriétés indépendante du modèle, événements/actions dynamiques, séquences non fixées, corpus réaliste scellé, Foundry stateful handlers avec mêmes budgets, Slither/Echidna/Halmos si applicable, coût de tout le cycle et audit des FN/FP.

## Reproduction

```sh
python -m unittest discover -s tests -p 'test_d21_*.py' -v
python -m scripts.d21_explore --root benchmarks/defi/d21 --output reports/d21-local
cd benchmarks/defi/d21
forge test --match-contract D21GeneratedReplayTest -vv
forge test --match-contract D21GuardedFuzzControlTest -vv
# Doit échouer avec D21_UNDERCOLLATERALIZED :
forge test --match-contract D21ConventionalFuzzBaselineTest -vv
```

Comparer des fractions d'états sur ce modèle à des temps CPU d'un fuzzer EVM serait invalide. Les temps d'installation, compilation et vérification ne sont pas intégrés dans ces chiffres de recherche.

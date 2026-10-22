# PRISM DeFi D2.1 — résultats de première CI locale (22 octobre 2026)

**PASS technique restreint ; NO-GO pour revendiquer davantage de vulnérabilités trouvées que les outils existants.**

## Sources vérifiables

- [Workflow GitHub Actions réussi 39842035061](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39842035061).
- [PR #22](https://github.com/nkinzogomer-eng/PRISM/pull/22), branche `research/defi-d21-cross-contract-lending`, parente PR #20, `main` inchangé.
- Contrat Solidity local de 4 composants (`DemoPriceOracle`, `DemoLender`, `DemoAsset`, `DemoTrader`), Solidity 0.8.24, Foundry v1.3.6, Python 3.12.
- 11 tests unitaires D2.1 plus 11 régressions D2.0 réussis ; **2 tests EVM générés réussis** ; fuzz paramétrique conventionnel reproduit indépendamment l'absence de garantie : échec attendu `D21_UNDERCOLLATERALIZED`, code de sortie non nul et raison vérifiée ; fuzz de la variante protégée réussi.

## Témoin proposé par le modèle et vérifié en EVM

```text
deposit(10)
change_price(20)     # modification non autorisée du prix
borrow(100)
change_price(2)
```

Après ces quatre appels, la dette de l'acteur vaut 100 pour 10 garanties et un prix revenu à 2 ; le plafond de prêt est `10 * 2 / 2 = 10`. L'EVM vérifie la dette, la source de prix, les réserves et les soldes attendus ; les actifs sont fictifs. Le contrôle d'accès sur `setPrice` interdit cette séquence à l'acteur non propriétaire et la variante corrigée passe les contrôles.

La cible reste une **propriété définie et un modèle inventé par les chercheurs**. Aucun mécanisme de découverte automatique d'une règle de solvabilité ou d'interprétation de contrats tiers n'est validé.

## Comparaison sur les états du modèle (une exécution)

| Version | Politique | Témoin | États développés | Transitions tentées |
|---|---|---|---:|---:|
| Oracle non protégé | BFS | oui | 63 | 216 |
| Oracle non protégé | guidage de propriété | oui | 5 | 24 |
| Oracle protégé | BFS | non, profondeur <= 4 | 28 | 96 |
| Oracle protégé | guidage de propriété | non, profondeur <= 4 | 28 | 96 |

Réduction des états **92,1 %** et des transitions **88,9 %** par rapport à BFS sur le modèle vulnérable ; **zéro gain** sur le modèle protégé. Comparaison sans intérêt pour démontrer une nouvelle méthode : une heuristique spécialisée après connaissance de la propriété ne dépasse pas automatiquement le stateful fuzz, une réduction de graphe existante ou un SMT solveur. Aucun benchmark complet de performance CPU/mémoire n'a été réalisé.

**Contre-exemple à toute prétention d'avance en détection :** le fuzz conventionnel trouve la violation de l'invariant indépendamment et échoue pour le motif voulu. Cela interdit de compter ce scénario comme une vulnérabilité supplémentaire propre à PRISM.

## Décision et obstacles

Ce premier D2.1 prouve une chaîne de travail multi-contrats : planificateur déterministe -> candidat -> test EVM local -> contre-factuel sécurisé -> baseline fuzz contradictoire. Mais son univers est minuscule et sa mise à jour de prix non autorisée est artificielle, sans liquidations, taux variables, actifs ERC-20 réels, MEV, états on-chain ni hypothèses de prix robustes.

**NO-GO** pour la supériorité DeFi, l'audit de contrats réels, les chiffres « 8 sur 10 », les affirmations de criticité ou de zero-day.

**Suite :** D2.2 devra tester des propriétés économiques indépendantes du planificateur, fuzz *stateful* à handlers et séquences générées indépendamment, incluant cas où le modèle se trompe ; mesurer plusieurs vulnérabilités distinctes et certifiées, FP/FN, coût total, budgets et holdout. Fixer protocole avant tests et conserver les échecs.

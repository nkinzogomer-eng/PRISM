# DeFi D2.1 — protocole gelé de découverte multi-contrats

Date : 22 octobre 2026. Statut : développement exploratoire, aucun résultat tant que les tests ne sont pas exécutés.

## Objectif et modèle de menace

Chercher, sur un protocole *strictement synthétique et local*, un scénario où un prix spot manipulable donne un crédit excessif sur la base d'une garantie déposée dans un module différent. La propriété économique est **spécifiée séparément du sélecteur d'actions** : à une valeur de référence figée (1 collatéral = 1 unité quote) et LTV 75 %, toute dette devrait satisfaire `debt <= 75% * collateralLocked`. Le témoin fort nécessite également que les réserves du spot aient retrouvé leur valeur initiale et que les actifs liquides de l'emprunteur après défaut hypothétique dépassent leurs avoirs initiaux.

Il ne s'agit ni d'un incident historique, ni d'un exploit possible sur des contrats réels, ni d'une découverte de zero-day ou d'une classification « critique ». Le gain après défaut est **hypothétique**, exclut les liquidations, les frais, l'intérêt, l'arbitrage, les agents tiers, la solvabilité réelle du jeton et l'évolution des prix de référence.

## Composants, hypothèses et preuves

- `SpotPricePool`: jouet constant-product avec deux réserves initiales 100/100, quote et collatéral fictifs.
- `CollateralCustody`: contrat distinct détenant les garanties et le registre des fonds bloqués.
- `LendingMarket`: calcule la limite d'emprunt à partir soit du spot courant (variante vulnérable), soit d'un prix de référence indépendant figé à 100 (contrôle).
- `CreditTrader`: acteur distinct détenant 100 collatéraux et 200 quotes ; le marché de prêt contient 500 quotes fictives. Ces fournitures sont attribuées au déploiement local et ne représentent pas de dépôts d'utilisateurs réels.
- Limite LTV de 75 %, sans mécanisme de remboursement ni de liquidation. La correction du contrôle n'est pas généralisable à un protocole de production et ne traite qu'un mécanisme d'overborrow.
- Modèle Python écrit **manuellement**, actions `pump(50/100)`, `pledge(10/20/40)`, `borrow(10/20/40/60)`, `unwind(25/50)`, profondeur max 4, limite 30 000 états. La recherche ne lit pas de labels EVM ni de code d'incident connu. Le modèle n'est pas une analyse statique de Solidity et peut diverger de l'EVM.
- Plan candidat Python rendu en test Solidity. L'EVM vérifie séparément tous les soldes et réserves, la garantie, la dette, la perte de couverture de référence, le retour du spot, la conservation totale des jetons, et le rejet par la variante protégée.

## Baselines et contrôles

1. Parcours BFS exhaustif sur le **même modèle et le même alphabet**, sans information de priorité. États examinés et transitions tentées publiés.
2. Classement orienté propriété, **heuristique manuelle** (statut risqué, dette, garantie, spot, etc.). Cet ordre est a priori donné par le mécanisme de défaut étudié et ne prouve aucune découverte automatique, supériorité générale ni réduction de calcul minimale.
3. **Foundry testFuzz indépendant** avec paramètres générés, sur les variantes vulnérable et corrigée, propriétés d'emprunt basées sur la référence indépendante. Un échec de la variante vulnérable indiquant précisément `D21_FAIR_LTV_WITNESS` est considéré comme une découverte concurrente, non comme un échec de la recherche.
4. **Foundry invariant stateful, handler indépendant**, avec les quatre catégories de fonctions, dans un vrai enchaînement de transactions sur les mêmes contrats. `[invariant] runs=64, depth=40`, `[fuzz] runs=256`; mêmes assertions de dette juste référencée et conservation d'actifs. Le fuzz stateful est une baseline bien plus adaptée qu'une simple recherche brute.
5. Contrôles de fonctionnalité : prêt normal avec et sans garde, marchés et comptes conservés, prêt excessif confirmé, garde refuse sans débiter d'argent. Les erreurs Solidity, compilation, timeouts, JSON manquant et mauvais motifs d'échec invalident la mesure.

## Validation et métriques

Succès D2.1 limité = **un** témoin multi-contrat proposé et confirmé par EVM + garde rejette + conservation valide, sans omission d'une baseline concurrente fonctionnelle.

Rapporter `expanded`, `attempted`, `generated`, temps de calcul Python, script de génération, temps complet du `forge test`, nombre de tests, traces EVM, échec de fuzz attendu et raison précise, et résultats stateful. Collecter les sorties brutes JSON et l'empreinte du code. Un gain en états Python ne remplace pas un coût complet du moteur : pas de déclarations SOTA si toutes les étapes et comparateurs ne sont pas mesurés.

**Vérification négative:** le moteur peut ne trouver aucun témoin sur le contrôle. Dans ce cas, uniquement `depth<=4` et cet alphabet sont couverts ; aucune certification globale de sécurité du contrat.

**Décision à l'issue:** GO pour développer un oracle de propriétés plus riche uniquement si aucune divergence modèle/EVM n'apparaît ; NO-GO pour « plus de failles que les outils existants » tant que le rappel/precision sur un corpus indépendant de diverses vulnérabilités n'est pas mesuré contre stateful fuzz, Slither, Echidna, Halmos et tests de correction.

La PR doit rester brouillon et la branche principale intacte. Les stratégies d'exploration et budgets sont **figés avant la première exécution CI de D2.1**. Les corrections de bogues ultérieures doivent être reportées comme amendements, pas présentées comme protocole pré-enregistré inchangé.

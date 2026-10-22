# D2.0 — protocole et statut scientifique de la découverte DeFi

Date : 2026-10-22. Cette expérience est un **développement exploratoire** après D1.0. Elle n'est ni un audit de sécurité, ni une preuve de supériorité sur l'état de l'art, ni un holdout.

## Hypothèse et objectif mesurable

Sous un espace d'actions borné et une propriété financière explicitement connue, un classement par pertinence peut-il générer **plus vite** un témoin de violation qu'un parcours exhaustif sur les **mêmes états**, sans produire de faux témoin lors de sa vérification dans une vraie EVM locale ?

L'objectif de sécurité testé est : **« un dépôt accepté de quantité positive ne doit pas créer zéro part »**, et, dans le scénario de perte, une personne tierce ne doit pas réaliser de profit strict au détriment du déposant, sans risque lié à un actif externe.

### Système expérimental

- Contrat Solidity 0.8.24, coffre de dépôt `LocalVault`, actif `LocalAsset` et deux acteurs `LocalActor`. Entièrement synthétiques, déployés *uniquement* dans les tests Foundry locaux. Pas de fork, d'argent réel, de protocole tiers ni d'accès réseau on-chain.
- Variante non protégée : `shares = floor(assets * totalSupply / totalAssets)` pour le coffre non vide, **accepte** un dépôt créant zéro part.
- Variante protégée : refuse l'opération lorsque `shares == 0`, ce qui ferme cette violation précise. Cela **ne constitue pas** une correction complète de tous les risques ERC-4626, inflation, mécanismes de donation, arrondis ou tokens non standard. Le token fictif permet librement `mint`, ce qui invalide toute extrapolation économique à des actifs ERC-20 réels.
- Comptes initiaux du modèle : 200 unités par acteur. Seuls les actes `deposit_attacker`, `donate`, `deposit_victim`, `redeem_attacker` sont modélisés, avec un alphabet fini d'entrées (1, 10, 100) et profondeur max 4.
- Propriété recherchée dans le modèle : `zero_share_victim_deposit` ET `attacker_wallet > 200` ET `victim_wallet < 200`. Les autres scénarios et dépendances ne sont **pas** certifiés sûrs.
- `breadth_first` et `goal_first` partagent toutes les transitions et le même plafond, mais le second utilise une heuristique **rédigée à la main**, à partir de la connaissance de la formule de calcul des parts. Cette connaissance est l'une des limites scientifiques majeures du test.
- Le plan choisi est généré par `scripts/d20_explore.py` puis incorporé à un test Solidity temporaire, sans le coder directement dans ce test. L'EVM vérifie les soldes exacts prédits et le rejet à l'étape prévue par la variante protégée. La preuve expérimentale dépend de l'indépendance partielle de cette exécution, pas d'une preuve formelle générale.

### Cinq barrières contre l'illusion de performance

1. Distinguer plan **candidat de modèle** et scénario **confirmé sur l'EVM**.
2. Les assertions EVM contrôlent soldes d'acteurs, réserve du vault, parts de chacun et offre totale. Une divergence invalide l'expérience.
3. Les tests de comportement d'une variante corrigée doivent réussir ; le scénario proposé doit échouer à lui faire perdre les fonds.
4. Comparer au moins à la recherche exhaustive simple **et** à un test fuzz natif Foundry, qui est un outil existant compétent lorsqu'on lui donne la propriété. Comparaison avec Echidna/Halmos/Slither non encore effectuée : aucun résultat de supériorité générale.
5. Exécuter et conserver l'échec attendu du fuzz Foundry sur le contrat vulnérable, en vérifiant **explicitement le motif de l'échec** plutôt que de compter toute défaillance de la CI comme un résultat.

### Ce que l'expérience ne mesure pas

Détection sur un protocole réel inconnu ; diversité de vulnérabilités ; classement de criticité ; rappel/précision sur plusieurs labels ; état global multi-contrats au-delà du vault simple ; coût de découverte de la propriété elle-même ; complexité d'audit, collecte de prix externes ou fork EVM ; temps total de comparaison de fuzz standard à couverture égale ; CPU/RSS ; coût des installations/outils ; robustesse statistique. La performance sur cette unique simulation synthétique ne permet pas d'extrapoler « 18 failles sur 20 » ou « state of the art ».

### Pour exécuter sur un poste isolé avec Foundry

```bash
python -m unittest discover -s tests -p 'test_d20_*.py' -v
python -m scripts.d20_explore --root benchmarks/defi/d20 --output reports/d20-local
cd benchmarks/defi/d20
forge test --match-contract 'VaultBehaviorTest|GeneratedDiscoveryTest|FuzzPatchedControlTest' -vv
# Cette commande DOIT échouer en révélant D20_ZERO_SHARE_WITNESS :
forge test --match-contract FuzzBaselineTest -vv
```

Le workflow GitHub D2.0 exécute ces commandes, archive le plan, les rapports de l'EVM et le fuzz indépendant. Version figée du moteur : Foundry v1.3.6 ; compilateur solc 0.8.24 ; Python 3.12.

### Critère de progression D2.1

Après D2.0, introduire un système plus discriminant (vault + oracle/prêteur ou protocole multi-composants), un inventaire de propriétés **indépendant de l'implémentation de PRISM**, et des changements réalistes. Distinguer l'étape où la propriété est donnée de l'étape où le moteur doit identifier la propriété et concevoir sa vérification. Comparer à fuzz stateful Foundry avec **handlers**, à Echidna et à Halmos/Slither selon les classes de propriétés, puis mettre le code et les seuils sous gel avant l'évaluation sur cas historiques/holdout.

**La revendication visée : plus de violations confirmées par budget total fixé.** Un changement de vitesse dans une recherche de modèle borné ne prouve pas cette revendication.

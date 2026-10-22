# DeFi D2.3 — pré-enregistrement de la découverte de propriétés à partir des interfaces

Date : 2026-10-22. **Aucun chiffre n'est attribué à D2.3 tant que sa CI n'a pas réussi.**

## Problème précis

En D2.0–D2.2, les propriétés et heuristiques de recherche étaient renseignées à la main, en connaissant les vulnérabilités artificiellement injectées. Ce raccourci rend la couverture observée peu informative : Foundry retrouve tous les témoins dans D2.2.

D2.3 étudie une étape préalable : peut-on sélectionner les propriétés financières candidates **sans recevoir d'étiquettes de vulnérabilité, sans lire un scénario d'exploitation ni le rapport EVM** ? La réponse doit être validée contre de vraies ABI compilées, avec refus explicite pour tout composant manquant.

## Condition d'entrée et propriété d'isolation

- Le script `scripts/d23_compile.py` reçoit seulement le chemin du projet Solidity et lance `forge inspect ... abi --json` pour `D22Oracle`, `D22Credit` et `D22Coin`. Il lit les ABI, les signatures typées et les sommes SHA-256 ; pas de fixtures `oracle_bug`, `withdraw_bug`, `repay_bug`, pas d'oracle de vérité, pas de données d'exécution.
- Les *candidats* proposés sont : contrôle du propriétaire de l'oracle si `owner/price/update` sont présents ; limites d'emprunt avant/après retrait si `debt/limit/locked/withdraw` sont exposés ; conservation économique des remboursements si `debt/repay/loanAsset/balanceOf` sont exposés.
- Ce ne sont **pas** des invariants prouvés par le compilateur : ce sont trois patrons manuels génériques déclenchés automatiquement par ABI. Toute signature incompatible produit `UNKNOWN`; aucune propriété absente n'est inférée sûre.
- Les hypothèses doivent être générées **avant** l'exécution EVM des labels connus ; le journal d'analyse `d23_audit.py` rapproche ensuite les propriétés candidates des 12 observations indépendantes existantes. Les trois hypothèses ne doivent jamais dépendre des flags des variantes.
- Les tests adversariaux manipulent types, surcharges, fonctions manquantes, doublons, ABI malformées et ordre des fonctions ; la certitude négative est interdite.

## Critères d'échec et de progrès

- NO-GO technique : ABI mal décodée, propriété sélectionnée malgré des observations manquantes, classes sans vérification EVM, résultats de comparaison modifiés ou sources / SHA incohérentes.
- GO technique restreint : trois hypothèses candidates génériques sélectionnées, toutes les observations nécessaires présentes, et EVM stateful + témoins générés cohérents avec D2.2.
- **NO-GO pour la supériorité scientifique**, même avec 3/3, si l'évaluateur et le modèle comportemental restent codés en connaissant les défauts, si un compilateur classique d'interfaces peut émettre les mêmes tests, ou si Foundry obtient le même rappel et la même précision.
- Le temps cumulé de compilation des ABI, de la sélection, de la recherche et de l'exécution EVM doit être rapporté distinctement ; compilation initiale, installation, coût humain d'écriture de patrons et de contrat, énergie et mémoire sont des coûts réels non couverts par un simple chronométrage interne.

## Baselines externes prévues, PAS exécutées ici

Pour prétendre à un niveau supérieur, sélectionner des cibles indépendantes **avant de modifier encore le moteur**, en dehors du corpus synthétique que nous fabriquons : [SCFuzzBench](https://scfuzzbench.com/) pour des fuzzers à invariants sur des projets réalistes, [CyberChainBench](https://defai-labs.github.io/CyberChainBench/) pour des incidents historiques réels, et éventuellement [DeFiVulnLabs](https://github.com/SunWeb3Sec/DeFiVulnLabs) pour l'étalonnage développement seulement. Choisir des versions et licences reproductibles, isoler les labels et exploits, figer l'oracle de confirmation, comparer à Foundry **avec les mêmes propriétés disponibles** et outils renforcés (Echidna, Medusa, Halmos selon compatibilité), et publier aussi les cas négatifs. Les collections historiques publiques ne sont pas automatiquement des holdouts aveugles : vérifier contamination et accès au RPC/archive au préalable.

**L'objectif à terme est un meilleur TP / FP / FN confirmé pour un budget complet fixé, sur une partition gelée indépendante.** Ce document ne fait aucune promesse de dépasser les approches existantes ou de découverte de zero-day.

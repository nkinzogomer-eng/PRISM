# PRISM — D2.4A : premier test sur du code DeFi indépendant (22 octobre 2026)

**Verdict scientifique : PASS du préflight externe ; D2.3 ne se généralise PAS aux propriétés de rebasing d'OUSD ; NO-GO pour revendiquer une meilleure découverte de vulnérabilités.** La suite de benchmark compétitif reste D2.4B.

## Exécutions reproductibles

- [CI finale réussie, deux jobs, run 39851813221](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39851813221). Les deux jobs sont au vert, y compris la compilation du vrai contrat Solidity et un smoke test EVM Foundry de son harness indépendant.
- [Artefacts du catalogue externe](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39851813221) : attestation de préparation, manifeste public, dossier de vérité séparé et empreintes de provenance.
- [Artefacts du contrat réel](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39851813221/artifacts/12458415078) : ABI OUSD compilée, modèle d'applicabilité, temps de `forge inspect`, sortie native Foundry `invariant_noop()` et stderr.
- [PR #25](https://github.com/nkinzogomer-eng/PRISM/pull/25), branche `research/defi-d24-external-ground-truth`, parent D2.3 #24 ; aucune fusion dans `main`.

## 1. Base de vérité provenant réellement de tiers

Catalogue SCFuzzBench gelé : commit `de70065957a32fc5dd5fba3e53bb60f8564c722c`. Les cinq cibles épinglées sont **Aave v4, Superform v2 Periphery, Liquity v2 Governance, Origin Dollar (OUSD) et Drips**.

- **13 problèmes historiquement documentés** par le benchmark : 12 pour OUSD, 1 pour Drips. Aucun de ces 13 n'est une découverte de PRISM.
- **10 canaries** (deux par cible) sont distinguées et exclues de tout comptage de vulnérabilités.
- **Une des 13 références**, pour Drips, est un lien de pull request et non une preuve source liée directement au commit cible. La référence reste inventoriée mais porte le drapeau **`evidence_requires_human_review`** ; **12** autres issues disposent de liens source alignés sur le commit. Ce détail a fait échouer le premier contrôle strict ; nous avons modifié l'ingestion pour **marquer l'incertitude sans blanchir la preuve**.
- SHA-256 brut `targets.json` : `49ddac5f89b01a77ce8460df5bfe050ed630d12d94026252d14639b3b5b2c171`.
- SHA-256 brut `known_bugs.json` : `0f91d65ca592f6dd546fe3a444f3393946ae3c9e9d62667fbe80646f2d88243e`.
- **18 tests unitaires/adversariaux ont réussi** sur l'ingestion du catalogue, la séparation detector/judge, les doublons, les canaries, les mauvais commits, les fausses sources et les rôles absents.

Les données sont publiques, connues auparavant et présentes dans un même workflow : le juge est séparé des entrées autorisées au détecteur **logiquement seulement**, pas un holdout aveugle réel.

## 2. Contrat réel compilé depuis une révision publique immuable

Dépôt cible : `scfuzzbench/origin-dollar-scfuzzbench`, commit **`299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4`**, téléchargé et vérifié par `git rev-parse HEAD`, avec ses sous-modules.

- Le contrat de production `contracts/contracts/token/OUSD.sol:OUSD` a été **réellement compilé par Foundry**, et non imité par une ABI artificielle.
- L'ABI comporte **34 signatures de fonctions**.
- La sélection de propriétés D2.3 (autorisation d'oracle, solvabilité après retrait, transfert effectif de remboursement de prêt) aboutit sur ce contrat à **trois `UNKNOWN_INAPPLICABLE`**, parce que cet actif à rebasing n'est pas une interface oracle, prêteur ni marché de collatéral. Cette abstention est **correcte** ; forcer les rôles aurait créé de fausses preuves.
- La compilation seule ne garantit pas l'absence de faille ni ne réfute les 12 problèmes historiques. Il serait faux de rapporter ce résultat comme `FN=12`, `TP=0` ou `TN=12` : aucune recherche de ces propriétés n'a encore été exécutée.

## 3. Vérification que le harness EVM tiers peut s'exécuter localement

Pour la première fois dans ce programme, la CI a exécuté un test natif du **harness tiers non réécrit** sur le commit OUSD épinglé, via `forge test --match-contract CryticToFoundry --match-test invariant_noop --json` :

- **Un résultat EVM : `invariant_noop() = Success`**, code de sortie 0.
- Budget volontairement réduit à 20 runs et profondeur 32 pour un **smoke test**, pas une campagne SCFuzzBench comparable. Le harness contient par ailleurs des canaries intentionnellement défaillantes, mais **ce test précis est un invariant no-op** et ne détecte aucune faille.
- Aucun scénario de vulnérabilité ne peut être crédité ni à Foundry ni à PRISM à partir de ce résultat. **Aucune comparaison de rappel ni de vitesse à qualité égale n'est possible**.

## 4. Résultat réfutant notre ancien système

La limitation D2.3 n'était pas seulement l'absence de jeu indépendant : ses patrons codés pour oracle, retrait et remboursement **ne sont pas adaptés au modèle économique du premier vrai protocole étudié**. Sur un véritable token à rebasing, ils ne savent même pas construire des hypothèses pertinentes.

Ce résultat est utile précisément parce qu'il est négatif et non mis en scène pour flatter PRISM. Il montre que la prochaine innovation utile doit porter sur la **formalisation et la génération de propriétés économiques par familles**, y compris l'identité entre offre/rebasing/crédits, plutôt que sur le guidage d'un scénario dont la propriété est déjà connue.

Attention : il serait **scientifiquement contaminant** de copier directement les fonctions `testChangeSupply`, `testMintBalance`, etc. du manifeste public dans le générateur PRISM, puis de publier ces mêmes cas comme des « découvertes ». Pour les données historiques publiques, ces résultats ne peuvent être présentés au mieux que comme une **reproduction** à propriété donnée ; une évaluation indépendante doit avoir une partition non utilisée pour développer ces patrons.

## 5. Décision et étape D2.4B

**GO :** acquisition d'un banc externe de cinq protocoles ; classification correcte des issues vs canaries ; compilation et exécution EVM sur du code réel ; incapacité de généralisation de D2.3 rendue mesurable.

**NO-GO :** zéro benchmark de découverte compétitif réalisé, zéro faille tiers nouvellement confirmée par PRISM, aucune preuve de supériorité, aucun zero-day, aucune exploitation de protocole réel. Le statut de découverte est **NON ÉVALUÉ**, pas « zéro vulnérabilité ».

**D2.4B :** formaliser des propriétés génériques de tokenisation à rebasing **sans injecter les labels et exemples OUSD** ; isoler leur validation sur un groupe d'autres protocoles (ou des éditions indépendantes), avec le même budget de propriétés pour Foundry/Echidna/Medusa, preuves EVM et métriques par cause racine. Le problème de contamination doit être audité avant d'ouvrir les labels ; ne pas annoncer de sensibilité estimée sans échantillon indépendant.

Notre prochain indicateur à viser n'est pas un chiffre fabuleux de taux de rappel sur cette expérience : c'est **au moins une propriété utile dérivée du code tiers et une preuve de comportement valide**, comparée à une baseline convenable — sans connaître a priori le scénario de faille.

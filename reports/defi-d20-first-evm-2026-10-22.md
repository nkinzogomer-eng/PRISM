# PRISM DeFi D2.0 — premier résultat exécuté, 22 octobre 2026

**Verdict : PASS de l'intégration recherche→preuve EVM ; NO-GO pour la revendication de meilleur détecteur DeFi que les approches actuelles.** Aucun merge ni usage pour des protocoles réels.

## Exécution et provenance

- GitHub Actions avec code [commit 95456a0bc5dc24aad8d2cb36715a5993fae48d9e](https://github.com/nkinzogomer-eng/PRISM/commit/95456a0bc5dc24aad8d2cb36715a5993fae48d9e).
- [Run complet réussi 39834861020](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39834861020), [artefacts bruts](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39834861020/artifacts/12449478885).
- 11 tests Python de recherche et de limitations du modèle : réussis. 6 tests EVM de comportement, reproduction de candidat et contrôle protégé : réussis. 1 test fuzz Foundry **échoue volontairement pour la bonne raison** : `D20_ZERO_SHARE_WITNESS`, sur la variante vulnérable ; son échec est enregistré et contrôlé indépendamment. Le fuzz de la version protégée réussit.
- Foundry v1.3.6, Solidity 0.8.24, Python 3.12, CI GitHub Actions `ubuntu-latest`. Toutes les transactions se déroulent uniquement dans la machine virtuelle locale de test.

## Trace de quatre transactions proposée puis confirmée par l'EVM

1. `deposit_attacker(1)` : l'attaquant reçoit initialement 1 part.
2. `donate(100)` : l'attaquant transfère 100 unités directement à la trésorerie, sans émission de parts.
3. `deposit_victim(100)` : le modèle indique `floor(100 * 1 / 101) = 0` part. Le vault expérimental accepte pourtant le transfert de 100 unités.
4. `redeem_attacker(0)` : le paramètre de modèle 0 signifie « redeem toutes les parts », soit 1 part encore détenue.

État final exact vérifié par les assertions Solidity : **attaquant 300 au lieu de 200, victime 100 au lieu de 200, vault 0, offre de parts 0**. Le gain net de 100 unités de l'attaquant est la perte nette de 100 de la victime. Ce sont des **unités fictives**. L'opération `deposit_victim(100)` est rejetée sur la variante protégée : le fonds de la victime reste inchangé à l'étape de rejet. Un succès de ce test ne prouve pas que le vault protégé est universellement sûr.

## Coût de recherche dans le modèle borné (une exécution, aucun intervalle d'incertitude)

| Variante et politique | Témoin trouvé dans profondeur 4 ? | États dépilés | Transitions tentées | Temps de recherche affiché |
|---|---|---:|---:|---:|
| Vault non protégé — BFS exhaustif | oui | 455 | 2 870 | 0,009372 s |
| Vault non protégé — objectif pertinent | oui | **5** | **40** | 0,000206 s |
| Vault protégé — BFS exhaustif | non | 1 140 | 2 610 | 0,007181 s |
| Vault protégé — objectif pertinent | non | 1 140 | 2 610 | 0,010240 s |

- **98,9 % d'états dépilés en moins** et 98,6 % de transitions en moins *pour ce témoin vulnérable*, par rapport à cette BFS simple. Le différentiel microscopique de durée n'est ni fiable statistiquement ni assimilable au coût complet de découverte.
- Le moteur guidé n'apporte **aucun** gain d'états sur la variante protégée et a un **surcoût temporel** dans l'exécution observée. L'absence de témoin avec ces 1 140 états dans le modèle et profondeur 4 n'est pas une preuve d'absence de vulnérabilité dans tout programme Solidity.
- La politique de pertinence est **écrite à la main**, fortement adaptée à cette propriété et aux opérations connues. La recherche BFS est une comparaison jouet ; il existe des méthodes incrémentales/fuzz/symboliques bien plus fortes, auxquelles nous n'avons pas encore comparé la couverture des vulnérabilités.

## Contre-épreuve importante : Foundry détecte lui-même le défaut

Le test fuzz `FuzzBaselineTest.testFuzzUnguardedMustMintShares` emploie la même propriété « dépôt accepté → parts strictement positives », mais **n'appelle pas PRISM** : il génère ses propres entrées et échoue avec `D20_ZERO_SHARE_WITNESS`, motif vérifié par le pipeline. La variante protégée passe un fuzz analogue.

**Conclusion négative : PRISM n'a trouvé ici aucune vulnérabilité supplémentaire qu'une baseline compétente correctement programmée ne savait détecter.** Le gain ne concerne que l'ordre de visite d'un graphe abstrait fortement simplifié et non la couverture réelle, la complexité de l'audit ni une découverte nouvelle. Il ne faut pas revendiquer une nouvelle faille critique, un zero-day, un protocole réel compromis ou un état de l'art dépassé.

## Problèmes scientifiques à résoudre

1. L'explorateur utilise un **modèle de la formule de création des parts** écrit à la main : il n'extrait pas automatiquement sa représentation du bytecode ni ne dérive seul les propriétés. Cela introduit un risque de connaissance préalable de la vulnérabilité.
2. L'heuristique est construite après observation d'un mauvais résultat initial (**529 états guidés contre 455 BFS** sur le même cas). Le nouveau chiffre 5 est donc un résultat de développement *post-hoc*. Il serait incorrect de le traiter comme une validation indépendante.
3. La preuve EVM est indépendante de la simulation Python au niveau de la machine d'exécution, mais elle ne réalise pas un audit universel ; elle vérifie seulement les transactions proposées.
4. Le fuzz de référence possède une propriété explicitement donnée et retrouve la vulnérabilité. La vraie compétition portera sur la **diversité de violations vérifiées**, le coût de recherche de propriétés et la profondeur transactionnelle à budget fixé.
5. L'actif `LocalAsset` est un jouet avec `mint` libre ; absence de contraintes économiques, liquidations, frais, tokens atypiques, permissions, oracles, callbacks, proxies, multi-chaînes et marchés externes. Aucun code n'est prêt pour un déploiement financier.
6. Pas de réplications matériel identique, de mesure CPU/RSS, de coût installation, de distributions d'éditions naturelles, ni d'un holdout DeFi indépendant. Les métriques de modèle ne doivent pas être assimilées au temps CPU du processus forge.

## Décision

- **GO technique restreint :** nous savons obtenir automatiquement un candidat de violation dans une abstraction, le transformer en test EVM et confirmer les soldes ainsi que l'effet d'une correction.
- **NO-GO recherche :** aucune nouveauté ou meilleure détection que Foundry prouvée sur ce cas.
- **Étape D2.1 proposée :** multiple contracts (vault/prêteur/oracle), propriétés inter-contrats et séquences de plusieurs transactions non évidentes ; propriétés spécifiées séparément de l'explorateur ; corpus vulnérable/corrigé, contrôles de correction, fuzz Foundry stateful **avec handlers**, Echidna / Halmos selon les classes, puis évaluation hors développement gelée et incidents historiques autorisés. Fixer les budgets et un vrai TP/FP/FN par propriété avant l'évaluation.

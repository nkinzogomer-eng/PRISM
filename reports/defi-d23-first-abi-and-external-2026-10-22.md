# PRISM / SCM — D2.3 : propriété dérivée d'ABI, tests EVM auto-générés et contrôle externe (22 octobre 2026)

**Verdict : PASS d'une capacité technique supplémentaire ; NO-GO pour la supériorité scientifique sur les analyseurs existants.** Le progrès établi est l'automatisation d'une étape de sélection de propriétés et de création de tests dans un laboratoire très restreint. Aucune détection indépendante de nouvelles failles n'a été démontrée.

## 1. Résultats effectivement exécutés (protocole interne)

- [Dernière CI de compilation, génération et vérification EVM réussie](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39848878420), [données brutes et Solidity auto-généré](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39848878420/artifacts/12457135514).
- [PR #24 en brouillon](https://github.com/nkinzogomer-eng/PRISM/pull/24) — branche `research/defi-d23-source-derived-properties` empilée sur D2.2 ; `main` non modifié.
- **27 tests D2.3 + 12 tests D2.2 réussis**. Deux tests d'intégration CI distincts : ABI → 3 hypothèses ; ABI → 12 tests Solidity générés → exécution sur EVM locale. Des tests de modèle et un fuzz stateful Foundry indépendants reproduisent les résultats D2.2.
- Compilation Solidity: Foundry v1.3.6, Solidity 0.8.24, Python 3.12, sur machine GitHub Actions Linux. Empreinte SHA-256 canonique du lot d'ABI : `dd678b8f131e56b33f4fe46a08aadd0392b68f073bb1d7e4eaa10e8e682a1061`.
- Entrées du compilateur : ABI obtenues par `forge inspect` pour le contrat d'oracle, le contrat de prêt et l'actif. **Aucune étiquette des variantes, aucun témoin d'exploitation ni résultat de fuzz n'est lu par le compilateur.** Les champs ABI exigés sont contrôlés, et l'absence d'un observateur déclenche `UNKNOWN`.

### Matrice effectivement vérifiée : trois propriétés × quatre configurations

| Hypothèse générique issue des ABI | Configuration violant la propriété | Test généré EVM | Fuzz stateful indépendant |
|---|---|---|---|
| Seul le propriétaire peut mettre à jour l'oracle | Un oracle autorisant une mise à jour externe | Identifie violation | Identifie violation |
| Un retrait ne doit pas créer un déficit de collatéral | Retrait sans garde de dette | Identifie violation | Identifie violation |
| Un remboursement doit être financé par un transfert d'actif | Réduction de dette sans transfert | Identifie violation | Identifie violation |

Pour les 12 cellules *du corpus artificiel dont nous connaissons la construction* : `TP=3, FP=0, FN=0, TN=9`, pour les sondes générées ET Foundry stateful. Les 12 sondes EVM exécutées ont une durée murale **0,2704 s** et une CPU cumulée de processus fils de **0,2815 s** sur le dernier passage. Ce n'est **pas** le coût d'un audit complet : compilation initiale, découverte des contrats/dépendances, préparation des hypothèses et comparaison à des fuzzers explorant des milliers de séquences sont différents et non réconciliés.

Les tests de propriété sondent des séquences financières **prédéfinies par des patrons de domaine**, tout en omettant les plans du modèle de recherche. Le fichier des configurations comporte directement les trois commutateurs de protection, sans étiquette `vulnérable` ; cet encodage est facile à comprendre et ne constitue pas une épreuve véritablement aveugle. Il reste impossible de déclarer que PRISM a « inféré » le comportement réel des fonctions uniquement depuis l'ABI : seules leurs signatures ont déclenché des hypothèses fabriquées à la main.

### Les tests adversariaux et leurs limites

Les essais D2.3 vérifient les entrées ABI malformées, les signatures en surcharge de mauvais type, les doublons, les observateurs manquants, les entrées de configuration avec « vulnerability_label », les tests EVM manquants, les mauvaises raisons d'échec et les mauvaises hypothèses. **Une propriété inconnue n'est jamais considérée prouvée sûre.**

Le passage initial du nouveau banc de tests a échoué **après** les 12 observations correctes parce que son assertion comparait un dictionnaire complet `{tp,fp,fn,tn,precision,recall}` à quatre clés seulement. L'assertion a été corrigée sans modifier les résultats du moteur ; les CI suivantes ont réussi. Une erreur d'évaluateur n'est pas une erreur de découverte et doit être archivée honnêtement.

## 2. Première épreuve d'indépendance du corpus

- [CI de provenance externe réussie](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39848930018) et [artefact de préparation](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39848930018/artifacts/12455304302).
- Contrôle réellement exécuté sur deux dépôts externes figés : `scfuzzbench/scfuzzbench@de70065957a32fc5dd5fba3e53bb60f8564c722c` pour le catalogue des cibles et les labels ; `scfuzzbench/origin-dollar-scfuzzbench@299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4` pour le code source Solidity réel d'Origin Dollar.
- Le catalogue comprend **12 défauts documentés** associés à Origin Dollar et **2 canaris de bonne santé des fuzzers**. Les canaris sont explicitement exclus du dénominateur des vulnérabilités, et le code source a été lu et identifié au commit figé.
- **DÉTECTION PRISM SUR ORIGIN DOLLAR : NON ÉVALUÉE.** Ce contrôle vérifie l'identité du corpus et sa disponibilité, pas la détection des douze vulnérabilités. Les problèmes de crédit d'une stablecoin à rebasing exigent des propriétés de supply, balance et credits-per-token que notre bibliothèque de trois patrons (oracle/prêt/remboursement) ne modélise pas encore.
- Les labels publics externes ne constituent pas automatiquement un holdout aveugle. Toute observation de leurs descriptions ou des scripts de reproduction par le moteur devra être évitée ou comptée comme contamination du jeu de test.

## 3. Hypothèse falsifiée et obstacles qui subsistent

**Hypothèse forte « PRISM surpasse déjà Foundry en découverte DeFi » : NON démontrée.** Les deux retrouvent les trois violations locales, avec zéro faux positif observé. Une petite bibliothèque conventionnelle de patrons d'interface peut aussi produire les mêmes hypothèses. La durée du petit groupe de sondes automatiques ne doit pas être opposée à un fuzz stateful complet en la traitant comme une compétition à puissance de vérification égale.

Une partie du raisonnement reste encodée par les chercheurs : reconnaissance de noms/signatures financières, choix des quatre configurations, valeur des montants d'essai, représentation des états dans l'ancien modèle D2.2, conception et catégorisation des propriétés. La véritable nouvelle question est : **comment dériver puis vérifier des propriétés de protocoles inconnus, au meilleur coût global, sans réintroduire les étiquettes dans les heuristiques ?**

## 4. Décision et seuil de passage

- **GO engineering :** pipeline déterministe sans LLM, ABI → hypothèses documentées → tests Solidity → EVM → TP/FP/FN/TN, avec refus des capacités manquantes, CI et preuves brutes. Auparavant, les propriétés et les séquences avaient toutes été données par l'expérimentateur.
- **NO-GO pour SOTA :** 12 cellules trop homogènes et créées localement, propriétés codées à la main, absence de vraie généralisation, baseline stateful ayant déjà la même couverture.
- **D2.4 réelle :** créer des familles de propriétés de comptabilité des parts, rebasing, supply et de crédit, prendre des fonctions et interactions sur la cible Origin Dollar figée, générer des tests sur une EVM locale, puis les comparer aux fuzzers et aux 12 défauts documentés avec labels séparés. Il faudra d'abord mesurer les cas où PRISM répond `UNKNOWN`, puis les premiers TP/FP réels; exclure les canaris, maintenir les états non testés comme inconnus.
- Exiger une amélioration reproductible contre des méthodes sérieuses **à propriétés et budgets comparables**, sur un jeu externe réellement pré-enregistré, avant toute revendication de supériorité scientifique.

**La PR reste en brouillon ; `main` et les bases D2.0–D2.2 restent préservées.**

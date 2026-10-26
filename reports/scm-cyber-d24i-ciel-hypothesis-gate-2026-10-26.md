# PRISM D2.4I — checkpoint vérification d'hypothèses proposées par Ciel

26 octobre 2026. Branche `research/scm-cyber-d24i-independent-holdout`.

## Évidence du premier commit CI

- [GitHub Actions #40279105382](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40279105382) : **SUCCÈS**, 11/11 tests D2.4I et 28/28 tests D2.4H.
- 4 sources Python indépendantes et préenregistrées, 348 438 octets au total,
  **0 hypothèse produite**, 0 témoin, 0 vulnérabilité confirmée.
- CPU CI : 0,235281 s ; mur CI : 0,235302 s ; RSS de processus maximum
  **28 836 KiB**. La faible dépense ne prouve pas une bonne détection sur un
  lot qui ne présente aucun candidat.
- Les valeurs diffèrent de la mesure locale : elles sont dépendantes du
  matériel et de l'environnement. Les sources préenregistrées n'ont pas été
  modifiées après l'observation du résultat.

## Extension expérimentale postérieure au premier run

`prism/hypothesis_contract.py` introduit le schéma
`scm.prism.hypothesis-request.v1` ; le moteur accepte des propriétés
**fournies par Ciel ou un autre générateur**, sous forme de prédicats de
traces finies. Les familles nommées ne sont pas prédéfinies, mais la
sémantique supportée est strictement bornée : comparaisons/arithmetic
entière sur variables d'observation. Ce n'est pas un solveur Solidity.

Contrôles principaux : autorisation de lecture locale, chemin et SHA-256,
interdiction d'injecter code/oracle/preuve/observations dans la requête,
contrôle de budget et de double provenance, rejet d'un observateur portant
le même identifiant que le proposant, hachage de l'entrée et des preuves,
réévaluation de l'empreinte après observation, statuts distinguant témoin
local, absence de témoin et inconnues.

En sortie, `scm.prism.ciel-capability.v2` n'établit **jamais** `VERIFIED` ni
une nouvelle vulnérabilité. L'interface est compatible conceptuellement
avec `nkinzogomer-eng/ciel/base44/shared/ciel/interfaces/capability.ts` ;
elle n'a pas été intégrée ou enregistrée dans le runtime Ciel gelé.

## Tests réalisés localement après cette extension

- 25/25 tests D2.4I passés (dont 14 tests supplémentaires du contrat Ciel).
- 306 tests de la suite complète passés, **1 expected failure historique**
  documenté ; aucune régression introduite.
- L'hypothèse "assets >= liabilities" produit un contre-exemple sur une
  trace de fixture simulée. Ce **n'est pas** une attaque réelle ou une
  propriété économique déjà établie du protocole OUSD.

## NO-GO scientifique toujours en vigueur

Un opérateur de prédicats générique ne découvre pas automatiquement les
invariants vrais d'un contrat ni ne prouve qu'un observateur produit des
traces authentiques. Sans modèles économiques validés, exécution isolée
sur vraie source/EVM, indépendance/attestation de l'observateur, reproduction
sur seconde implémentation et cohorte aveugle étiquetée, PRISM ne peut
prétendre ni découverte de zero-day, ni supériorité face aux autres outils.

Le rôle plausible de Ciel est désormais une proposition structurée et
budgétée des hypothèses et des expériences, plus apprentissage/planification
à partir des échecs. Le juge et la validation restent indépendants.

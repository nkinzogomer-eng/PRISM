# D2.4D — Noyau SCM transversal aux domaines cyber

**Protocole figé le 24 octobre 2026, avant la CI. Aucun avantage scientifique supposé.**

## Hypothèse vérifiable
Pour un système à transitions **fini et explicitement modélisé**, avec des dépendances lecture/écriture complètes, le slicing rétrospectif depuis un objectif et le quotient des états sur les variables pertinentes peuvent réduire le nombre d'opérations tentées et d'états explorés sans perdre les violations atteignables. Le slicing et l'abstraction d'état sont des techniques **déjà connues** ; une victoire contre BFS naïf ne serait pas une découverte scientifique originale.

## Périmètre d'expérience
Trois familles de modèles distinctes :
- **Autorisation web** : accès privé via fallback incorrect contre version protégée (simulation écrite pour la recherche).
- **Entrée non fiable vers sink** : absence de sanitation contre version protégée (simulation).
- **DeFi** : intégration du modèle PRISM D2.2 existant (oracle, retrait de collatéral et remboursement, en variantes vulnérables et corrigées). **Ce n'est pas l'exécution du véritable OUSD.**

Les 80 cas sont 8 permutations fixes (graines 0–7) × 10 couples famille/scénario. Profondeur 5, budget 20 000 états développés, mêmes actions et oracle d'atteignabilité pour les trois politiques.

## Comparateurs
1. BFS conventionnel avec l'ensemble des actions et identité complète de l'état.
2. BFS après slicing statique rétrograde traditionnel, avec identité complète.
3. « SCM pilot » : **le même slicing**, puis quotient de l'état sur la fermeture des dépendances. Ce troisième système combine des méthodes connues ; un concurrent implémentant exactement la même combinaison aurait les mêmes propriétés théoriques.

On conserve toutes les données par essai : vérification indépendante de la trace, verdict FOUND / NOT_FOUND_IN_FINITE_MODEL / UNKNOWN_BUDGET, transitions tentées, états développés, produits et temps écoulé. Si une stratégie et la recherche exhaustive divergent, ou si une stratégie épuise son budget, la CI échoue au lieu de déclarer la variante sûre.

## Tests adversariaux et limites
- Audit dynamique des champs effectivement modifiés ; métadonnées manquantes = erreur / UNKNOWN.
- Contre-exemple explicite démontrant qu'une **dépendance lue mais non déclarée** peut rendre le quotient faussement négatif. L'audit dynamique des écritures **ne démontre pas** la complétude des lectures.
- Aucun modèle n'analyse automatiquement la sémantique de Solidity, Python ou JavaScript ; toute l'information de transition et de sécurité est fournie par les chercheurs.
- Aucune découverte de vulnérabilité tierce réelle, aucun CVE/zero-day, aucun rappel du corpus SCFuzzBench, aucune preuve de vitesse d'audit complète.
- Mesures de temps Python très courtes et sensibles au système ; mesurer et rapporter les nombres d'opérations en premier, sans omettre CPU, préparation humaine et surcoûts éventuels.

## Critère de passage
**PASS ingénierie** si les 80 cas finissent sans épuisement, que tous les résultats concordent avec BFS exhaustif sur le modèle, que les traces sont rejouées, que les négatifs sont explorés jusqu'au bout, et que l'audit adversarial passe.

**NO-GO scientifique** pour la supériorité finale tant que l'on ne dérive pas automatiquement les effets à partir de vrais dépôts cyber en plusieurs langages, avec gestion conservatrice des effets dynamiques, preuves sur code exécutable tiers, corpus indépendant et outils puissants (symbolique, fuzzing dirigé, slicing éprouvé) sous ressources et effort de spécification comparables.

Après ce pilote : brancher de véritables adaptateurs source/bytecode, puis confronter l'algorithme SCM à des vulnérabilités tierces indépendantes sans consulter leurs étiquettes avant les essais.

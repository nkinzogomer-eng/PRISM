# Consigne de revue indépendante — à transmettre à Perplexity

Tu dois agir en **évaluateur scientifique contradictoire** du projet SCM/PRISM, pas en partenaire commercial. Lis d'abord intégralement le dossier :

**https://github.com/nkinzogomer-eng/PRISM/blob/research/prism-review-package-2026-10-27/docs/prism-external-review-2026-10-27.md**

Puis inspecte autant que nécessaire le dépôt public, les rapports cités, les fichiers du moteur, les tests et les sorties GitHub Actions de cette branche.

## Question

Comment transformer PRISM — un contrôleur structural déterministe aujourd'hui surtout limité à des propriétés, candidats et adaptateurs déjà définis — en un moteur réellement capable de **proposer lui-même des obligations de sécurité et des contre-exemples inattendus**, puis de les **confirmer indépendamment sur des codes tiers jamais vus**, avec une meilleure efficacité vérifiée sur CPU ordinaire, sans GPU ni API payante ?

L'objectif ambitieux est de détecter des vulnérabilités graves de wallets, bibliothèques crypto et DeFi, éventuellement des pertes de trésorerie sans capital initial ; les contraintes excluent les essais sur fonds ou cibles non autorisés. **Aucun zéro-day n'a été confirmé.** Les résultats positifs récents sont soit synthétiques, soit des familles historiques connues, soit des proxys volontairement non initialisés.

## Règles d'évaluation

- Réfute explicitement chaque affirmation non étayée. Ne considère pas un test vert, une hypothèse générée ou un compte non initialisé comme une découverte de zéro-day.
- Distingue : (a) transfert sur mock-tokens, (b) authentique violation de code original sous conditions de déploiement valides, (c) nouvelle faille reportable, (d) nouvelle classe, (e) coût externe réellement nul.
- Cite la recherche primaire et les outils concurrents appropriés : symbolic execution, model checking, invariant mining, program synthesis, taint/CFG/SSA, Slither, Echidna, Medusa, Foundry, etc. Distingue ce que les références prouvent de tes inférences.
- Cherche activement des contre-exemples et des erreurs de sélection/contamination du holdout. Vérifie la couverture des ABI, l'attribution exact-target contre dépendances, le coût humain et la validité de l'oracle.
- Privilégie **trois prochaines expériences falsifiables** : code à ajouter, propriétés dérivées *sans lecture préalable de la cible*, corpus de développement, source holdout, contrôles positifs/négatifs, baselines, limite de RAM, mesure de temps et conditions d'échec.
- Estime honnêtement l'effort, le principal goulot et les risques de chaque expérience. Ne promets ni succès garanti, ni « imbattable », ni découverte nécessaire d'un zéro-day.
- Si une partie du repo, des artefacts ou des liens est inaccessible, dis laquelle au lieu d'imaginer ses résultats.

## Format attendu

1. **Verdict global et confiance**, avec tableau « démontré / partiel / non démontré ».
2. **Audit technique** de 5 à 10 blocages racines, hiérarchisés par sévérité et coût de correction.
3. **Contre-arguments scientifiques** : méthodes déjà connues, anomalies d'évaluation, scénarios où PRISM échouera.
4. **Plan opérationnel de trois étapes**, chacune avec interface du module, preuve attendue, jeu de tests strictement aveugle, coût cible et critère d'arrêt.
5. **Expérience décisive proposée** pour établir pour la première fois un gain quantifié sur des vraies causes racines inconnues de PRISM.
6. **Questions essentielles laissées ouvertes** et ressources primaires pertinentes.

Merci de répondre en **français**, avec rigueur et franchise. Un résultat négatif bien établi vaut plus qu'une déclaration de supériorité sans preuve.

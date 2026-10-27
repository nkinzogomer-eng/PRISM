# PRISM / SCM — Dossier de revue scientifique externe

**État arrêté au 27 octobre 2026.** Version de lecture pour Perplexity ou un évaluateur indépendant. Ce document est un **inventaire de preuves et de limites**, pas une annonce de découverte de zéro-day. Les liens GitHub pointent vers des sources ou essais vérifiables ; les objectifs futurs ne doivent pas être confondus avec des capacités acquises.

## 1. Résumé honnête en trente secondes

PRISM est le prototype expérimental du *Structural Computation Model* (SCM). Le projet vise un noyau de raisonnement et de vérification **déterministe, sans dépendance obligatoire aux LLM**, qui découvre quelles distinctions et quelles opérations sont strictement nécessaires à une décision vérifiable. Son domaine expérimental prioritaire est maintenant la recherche défensive de vulnérabilités dans des protocoles DeFi, des wallets et leurs bibliothèques.

**Acquis :** contrôles structuraux prouvés sur des univers finis ; génération bornée de scénarios EVM ; vérification native sur code tiers exact ; reproduction de défauts historiques connus et de configurations de wallets volontairement dangereuses ; abstentions explicites ; tests automatisés et artefacts auditables.

**Non acquis :** invention autonome d'une famille de faille inconnue ; zéro-day indépendant confirmé ; capacité de vider une véritable trésorerie ; transfert « sans dépenser un centime » frais compris ; couverture ouverte de toutes les classes de failles ; amélioration significative contre des baselines de référence à coût égal ; autonomie zéro-shot sur un logiciel jamais inspecté par aucun adaptateur spécialisé.

**Bilan confirmé à cette date : 0 nouveau zéro-day, 0 nouvelle famille de vulnérabilité vérifiée, 0 faille inédite exploitable sur une trésorerie de production.** Cela n'annule pas les progrès techniques, mais empêche toute revendication prématurée de supériorité.

## 2. Objectif de recherche et définition de la réussite

### 2.1. SCM et *Minimal Sufficient Computation* (MSC)

L'intuition SCM n'est pas seulement d'optimiser une boucle ou de juxtaposer des scanners. Pour un objectif, le système tente de **transformer la représentation, l'espace des états et le plan de calcul**, sans perdre les distinctions nécessaires pour statuer et justifier le résultat.

Une spécification de décision peut s'écrire `S = (Φ, Y, P, V, B)` : domaine/prédicat du problème, espace de réponses, propriétés pertinentes, exigences de vérification, budget. Une computation `C` est suffisante si son résultat satisfait la question, si le certificat est accepté par `V` **dans la portée de ses hypothèses**, et si les coûts restent dans `B`. On recherche une computation suffisante moins coûteuse, sans confondre un certificat sur un modèle incomplet avec une vérité sur le monde.

Composants visés : équivalence de décisions, frontière de décision, raffinement progressif, contraintes et dépendances, slicing orienté propriété, calcul incrémental, mémoire de preuves, transformations à préconditions vérifiées, sélection coût/qualité et abstention.

### 2.2. Application cyber recherchée

La cible finale ambitieuse, **encore hypothétique**, est de découvrir puis **prouver** des failles réelles auparavant non reconnues, y compris des familles inconnues du moteur, avec de meilleurs résultats de rappel, de précision, de temps et de coût que les approches compétentes existantes. Les cibles d'intérêt incluent smart contracts, protocoles DeFi, composants wallet/compte, signatures, encodage/transmission des transactions et dépendances entre bibliothèques et protocoles.

Une catégorie d'impact particulièrement étudiée est une perte partielle ou totale de trésorerie **sans capital initial détenu par l'attaquant**. Trois notions doivent cependant être séparées :

1. `attacker_initial_assets = 0` : absence de tokens de départ dans la simulation ;
2. `attacker_external_spend = 0` : absence démontrée de paiement de frais, gaz, infrastructure, capital emprunté non remboursé, sponsoring, coûts de transaction ;
3. `net_economic_profit > 0` : gain mesuré après tous les coûts pertinents, sur un chemin d'exécution admissible.

Les expériences actuelles montrent parfois (1), **jamais (2) de manière exhaustive**, et ne démontrent pas une stratégie rentable de drainage d'une trésorerie réelle. Des prêts flash ou du gaz sponsorisé ne doivent pas être comptabilisés gratuitement par hypothèse.

## 3. Contraintes non négociables

| Dimension | Condition de recherche |
|---|---|
| Matériel | Exécutable sur CPU ordinaire, y compris une VM Kali d'environ **4,1 Gio de RAM** ; pas de GPU obligatoire. |
| Modèles IA | Noyau utilisable avec `AI_ENABLED=false` ; modèles externes optionnels, non vérificateurs souverains. Un seul fournisseur peut suffire si on l'utilise ; aucun modèle requis. |
| Argent | Éviter les API payantes, cloud coûteux et dépenses répétées ; mesurer coût total réel, pas seulement le temps d'une fonction. |
| Temps | Priorité à des étapes rapides et à une première mission réalisable en **moins de 48 h** ; mesurer aussi le coût humain d'adaptation, de préparation et de validation. |
| Qualité | Résultats attestés par source épinglée, observations indépendantes, contre-exemples, contrôles négatifs et positifs. `UNKNOWN` vaut mieux que `SAFE` injustifié. |
| Cadre | Uniquement code public analysé localement ou cible avec autorisation ; pas de transactions malveillantes sur mainnet, fonds réels, clés privées ou exploitation non autorisée. |
| Ingénierie | Préserver les versions et tests fonctionnels ; ajouter des capacités avec régressions, branches expérimentales, journal et CI ; pas de modifications silencieuses de `main`. |
| Science | Geler moteurs/seuils/jeu de tests avant les vrais holdouts ; divulguer fuite d'information, échecs, cas inconnus et limitations de l'oracle. |
| Comparaison | Baselines fortes sous conditions égales ; compter prétraitement, dépendances, temps humain, CPU, pic RSS, compilation, planification, vérification et coûts externes. |

L'intégration à **Nexus Ciel** demeure une étape ultérieure. Ciel pourra gérer mission, hypothèses, priorités, mémoire et récupération ; **PRISM doit vérifier indépendamment** toute hypothèse générée par Ciel. Finir/mesurer le noyau avant d'étendre le corps est la décision actuelle.

## 4. État technique réellement atteint

Le noyau historique contient des modèles finis de décision/suffisance, des sélecteurs adaptatifs, et des transformations vérifiées (quotient d'équivalence et suppression d'observation dominée). Les essais cyber ajoutent des générateurs de candidats structuraux, des parseurs/graphes Solidity limités, des adaptateurs Python et des tests EVM Foundry/Hardhat dans des laboratoires isolés. Les certificats et observations ont une portée locale déclarée.

Phases selon [le registre existant](scm-phase-status.md) : phases **0–3** considérées terminées sur leurs *critères d'ingénierie étroits* ; phase **4** cyber en cours de recherche, **non validée** dans son ambition générale ; Ciel et généralisation multi-domaines ultérieurs. L'intitulé d'une phase « cochée » **n'est pas une preuve de supériorité de SCM**.

Exemple phase 3 : [500 cas synthétiques contrôlés](../reports/phase-3-controlled-dominance-2026-10-16.md), vérificateur/preservation des décisions 500/500, mais **gain moyen du coût exact d'exécution : zéro** dans cinq régimes. Certaines réductions de représentation sont réelles ; une accélération universelle ne l'est pas.

### 4.1. Résultats cyber — ne pas additionner comme des failles distinctes

| Essai et lien probant | Observation exacte | Conclusion correcte |
|---|---|---|
| [D2.4F — Werkzeug & Starlette](../reports/scm-cyber-d24f-two-real-historical-root-causes-2026-10-25.md) | Deux causes **historiques connues**, 23 entrées, 11 comportements pré-correctif opposés aux correctifs. | Reproduction comportementale, pas 11 failles ni 2 zéro-days ; sélection rétrospective non aveugle. |
| [D2.4L — AST typé/Slither](../reports/scm-cyber-d24l-compiler-baseline-holdout-2026-10-26.md) | Détecteur et Slither trouvent tous deux la faille artificielle, pas le contrôle corrigé. Holdout Aave Pool : 0 candidat attribuable au contrat, 228/379 fonctions de la fermeture non entièrement prises en charge. | Analyse incomplète, aucune supériorité établie ; OpenZeppelin holdout bloqué par mismatch de compilateur. |
| [D2.4O — Euler V1 historique](../reports/scm-cyber-d24o-euler-postdebit-hypothesis-2026-10-26.md) | Génère une anomalie de garde post-débit ; la vraie source historique viole le contrôle de santé, contrôle réparé humainement rejette l'opération. | Reproduction d'un mécanisme **déjà connu**, adaptateur influencé par lecture du code ; aucun drainage/profit complet. |
| [D2.4P — labo synthétique](../reports/scm-cyber-d24p-autonomous-native-lab-2026-10-26.md) | **63 instances** générées à partir de seulement **7 modèles sémantiques**, **1 134** essais EVM, **18 observations positives et 45 négatives**, aucune erreur dans cette population. | Automatisation bornée réelle en laboratoire ; pas un nouveau type de faille et pas une généralisation sur code tiers. |
| [D2.4Q — Solmate ERC4626 original](../reports/scm-cyber-d24q-unseen-solmate-2026-10-26.md) | **27 séquences** générées avant inspection du source, **8** transferts économiques défavorables à une victime dans un coffre dérivé minimal. | Famille d'inflation/arrondi **connue**, nécessite donation/capital, pas de preuve de vulnérabilité d'un protocole déployé. |
| [D2.4R — Safe initialisé](../reports/scm-cyber-d24r-safe-treasury-zero-capital-2026-10-26.md) | **12 hypothèses pré-enregistrées**, **0** sortie non autorisée d'un Safe correctement initialisé. | Résultat négatif borné ; aucune preuve de sûreté générale. |
| D2.4S — Safe proxy sans setup (même rapport R/S) | **24** cas exploratoires après inspection ; **3** prises de contrôle et transferts de tokens simulés sur proxy financé **avant** initialisation. | Condition de déploiement **déjà documentée** par Safe ; pas un bypass des multisignatures correctement configurées. |
| [D2.4T — ERC-4337 SimpleAccount v0.7.0](../reports/scm-cyber-d24t-held-out-erc4337-2026-10-27.md) | **18/18** traces EVM attestées ; **9** essais officiels factory-initialisés sans sortie indue ; **3/9** preuves de contrôle/vidage sur proxy créé séparément non initialisé ; **3 tests EVM** réussis. | Cible nouvelle pour PRISM, mais **adaptateur créé après lecture du code** et famille déjà explorée ; zéro-shot **non prouvé**, nouveau zéro-day **0**. |

**Attention méthodologique :** les dénominateurs ci-dessus sont des séquences/scénarios, pas une mesure de rappel sur toutes les vraies failles existantes. Les nombres positifs comptent des variantes d'un phénomène, **pas des CVE distinctes**. Les contrôles artificiellement vulnérables ne deviennent pas des découvertes tierces.

### 4.2. Trace publique récente prioritaire

- [CI D2.4T verte — run 40528339551](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40528339551) : original ERC-4337 v0.7.0 épinglé, hachages de fichiers attestés, 18 journaux de scénarios distincts, Foundry 3/3.
- [Artefacts D2.4T](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40528339551/artifacts/12745660321) : logs native-EVM, plan de scénarios, vérifications de sources et classifications ; soumis à la durée de rétention GitHub.
- [CI D2.4R/S verte — run 40413838243](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40413838243) : contrôles Safe natifs.
- [CI D2.4Q verte — run 40345956053](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40345956053) : Solmate ERC4626 original.
- [CI D2.4P verte — run 40341982493](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40341982493) : lots synthétiques avec témoins indépendants.
- [CI D2.4O verte — run 40335609330](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40335609330) : conséquence historique Euler.
- D2.4T : **445 tests Python locaux**, **1 échec attendu**, **0 échec inattendu** au dernier passage consigné ; ce n'est pas un audit complet externe sur machine personnelle de 4 Gio.

Le [README historique](../README.md), [le protocole D1](scm-goal-driven-vulnerability-discovery.md), [la feuille de route SCM](scm-roadmap.md) et [la règle d'indépendance IA](ai-independence.md) sont utiles, mais certaines pages de planification datent d'avant D2.4T ; **ce dossier prévaut pour le constat expérimental du 27 octobre** sans modifier rétrospectivement les registres antérieurs.

## 5. Blocages racines et diagnostics falsifiables

1. **La cible change, pas assez la classe cherchée.** D2.4Q cherchait une économie ERC4626 connue ; D2.4R/S/T un axe initialisé/non initialisé connu. Changer de dépôt sans changer le mécanisme ne prouve pas la découverte de classes inattendues.
2. **Absence d'un extracteur de propriétés de sécurité suffisamment général.** PRISM ne construit pas encore, depuis un programme inédit, des obligations inédites du type « qui a droit à quel effet sur quel actif, sous quelles séquences et signatures ? » Il manque une représentation fiable acteur/capacité/ressource/état/effet/autorisation.
3. **Sémantique du programme incomplète.** Modifiers, héritage, contrôles de flux, alias, appels intercontrats, proxies, transactions asynchrones, signature/domaine/nonce et dépendances DeFi sont partiellement ou non couverts. Exemple quantifié : 228/379 fonctions non pleinement prises en charge dans le holdout Aave D2.4L.
4. **« Zero-shot » fragile.** Une cible peut être inconnue jusqu'à sa sélection, mais si l'adaptateur, les hypothèses ou les assertions sont adaptés *après lecture*, on a un essai exploratoire, pas une évaluation indépendante aveugle. Le protocole doit geler le moteur **avant** de choisir et lire les cibles de test.
5. **Le verdict dépend du monde modélisé.** Une propriété supposée, une étiquette erronée, une fonction non supportée ou un état de déploiement artificiel peut fabriquer un faux signal. D2.4P a précisément corrigé une erreur initiale de *ground truth* après contre-épreuve Solidity 0.8 ; c'est un contrôle précieux, pas une défaillance à masquer.
6. **Oracles économiques incomplets.** Le gain brut en mock-tokens ne chiffre pas le gaz, le sponsoring, la liquidité, les taux de change, les remboursements de prêts, la faisabilité des liquidations, la concurrence/MEV ou les ressources réellement contrôlées.
7. **Absence de vérité exhaustive et de baselines fortes.** Sans corpus indépendant étiqueté au niveau des *causes racines*, ni Slither/Echidna/Medusa/fuzzing dirigé équitablement paramétrés, impossible de chiffrer le rappel des failles inconnues ou la supériorité de PRISM.
8. **Pipelines très spécialisés, coût total non borné.** Sources originales et CI passent, mais l'effort de fabrication des adaptateurs, la compilation, les faux positifs triés à la main, les pics de RAM et les contraintes de la VM ne sont pas mesurés end-to-end sur les cibles complexes.

Il est plausible que certains gains viennent d'intégrations déjà décrites dans la littérature (analyse abstraite, slicing, fuzzing guidé, invariant mining, model checking, vérification différentielle). **La nouveauté algorithmique de SCM doit être une hypothèse falsifiable, pas un slogan.**

## 6. Prochaine expérience décisive — contrat proposé, pas travail déjà livré

Ne pas masquer les échecs en multipliant des scénarios proches. Le prochain saut doit tester **la génération autonome de propriétés qui n'ont pas été préécrites pour la cible**.

1. **Préparer sur un corpus de développement distinct** une représentation intermédiaire (principal, rôles/capacités, signatures et nonces, actifs, flux de valeur, droits, effets d'état, frontières entre composants). Générer des candidats d'invariants et des séquences d'actions à partir de cette représentation et des interfaces, avec refus explicite des formes non prises en charge.
2. **Vérificateur natif indépendant :** oracle d'effets observables et de consentement, contrôle positif vulnérable, contrôle négatif corrigé, états de déploiement réalistes, minimisation des contre-exemples, attestation d'originalité du code. Séparer automatiquement `HYPOTHESIS`, `WITNESS`, `CONFIRMED_ROOT_CAUSE` et `NOVELTY_UNVERIFIED`.
3. **Geler l'outil avant le holdout :** commit immuable du moteur, paramètres, adaptateurs génériques, modèle de menace, budgets, métriques et critères d'abstention. Un tiers choisit ensuite **plusieurs** bibliothèques/protocoles inconnus du développeur et cache leurs étiquettes. Toute réparation après inspection fait basculer ces cibles dans le corpus de développement et oblige à choisir de nouveaux holdouts.
4. **Comparer à travail égal :** compilation identique, mêmes ABI/sources, même matériel, même budget CPU/RAM/temps et effort humain enregistré ; comparer un moteur sans SCM, des outils spécialisés solides et leurs unions. Mesurer `TP/FN/FP` *par cause racine* et `time-to-first-confirmed`, temps total, pic mémoire, coût des vérifications, abstentions.
5. **Seuil de conclusion :** au minimum un comportement tiers imprévu identifié par une hypothèse générée à l'aveugle, reproduit sur **source originale non modifiée**, invalidé par une correction/contre-exemple indépendant, puis vérifié pour son caractère connu/inconnu et son impact. Sans cela, conclure `non démontré` ; pas de titre « zéro-day » avant investigation indépendante et divulgation responsable.

Une version *strictement* sans capital initial et sans frais exige de **prouver séparément** les soldes initiaux, les transferts, les coûts externes, le paymaster/gaz et l'économie finale ; un test EVM local sans prix du gaz ne suffit pas.

## 7. Ce que nous demandons à l'évaluateur externe

Nous souhaitons **une revue adversariale et sourcée**, pas une validation de courtoisie :

1. Quels composants représentent de la recherche nouvelle, et lesquels sont des variantes de méthodes établies ? Citer des travaux concurrents précis.
2. Quelle faiblesse empêche le plus directement de passer d'une violation connue à la **génération autonome de classes inédites** ? Prioriser, avec démonstration ou contre-exemple.
3. Quel protocole de holdout éliminerait réellement les fuites du code cible vers les règles, les prompts et les adaptateurs ?
4. Quel pipeline minimal de compilation, IR, invariant mining, exploration d'états et preuve EVM est viable sur CPU et ~4 Gio de RAM ? Quelles familles resteraient inatteignables ?
5. Quels corpus tiers autorisés, corrections historiques et benchmarks réalistes disposent de vrais labels (cause racine, original/corrigé) et empêchent une étude complaisante ?
6. Quelles baselines et métriques suffisent à réfuter ou confirmer un **gain substantiel** contre des outils compétents ?
7. Quels cas négatifs ou pathologiques feraient s'effondrer l'approche actuelle (proxy, intercontrats, multicall, rebase, flash-loans, signatures, dépendances de prix) ?
8. Dans quel ordre implémenter **3 expériences maximisant l'information par coût**, sans rendre le noyau dépendant de Ciel ou d'une IA payante ?
9. À quel stade peut-on parler de vulnérabilité authentique, de faille nouvelle, de classe nouvelle et de zéro-day, sans confondre hypothèse et preuve ?

**Instruction à Perplexity :** si les liens fournis sont insuffisants, demander des fichiers/artefacts précis ; signaler les conclusions non vérifiées ; ne pas inférer un zéro-day du simple succès des tests.

## 8. Chemin de lecture reproductible

1. [Protocole objectif cyber](scm-goal-driven-vulnerability-discovery.md) et [indépendance IA](ai-independence.md).
2. [Code des hypothèses D2.4T](../prism/d24t_unseen_wallet_frontier.py), [exécuteur EVM D2.4T](../scripts/d24t_unseen_erc4337_native.py), [tests D2.4T](../tests/test_d24t_unseen_wallet.py), [CI](../.github/workflows/d24t-unseen-erc4337-wallet.yml) et [rapport D2.4T](../reports/scm-cyber-d24t-held-out-erc4337-2026-10-27.md).
3. [Rapport D2.4R/S Safe](../reports/scm-cyber-d24r-safe-treasury-zero-capital-2026-10-26.md), [D2.4Q Solmate](../reports/scm-cyber-d24q-unseen-solmate-2026-10-26.md), [D2.4O Euler](../reports/scm-cyber-d24o-euler-postdebit-hypothesis-2026-10-26.md).
4. [Graphes AST et holdout D2.4L](../reports/scm-cyber-d24l-compiler-baseline-holdout-2026-10-26.md), [Phase 3](../reports/phase-3-controlled-dominance-2026-10-16.md) et [registre des phases](scm-phase-status.md).

**Audit de portée :** il s'agit de la photographie publiée des expériences disponibles au 27 octobre 2026, avec leurs propres méthodes et limites. Les références à des « succès » de laboratoire n'établissent ni fiabilité de production, ni taux universel de détection.

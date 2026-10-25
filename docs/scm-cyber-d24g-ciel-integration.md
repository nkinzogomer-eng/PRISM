# D2.4G — Construction orientée découverte et interface Ciel

Date : 25 octobre 2026. Hypothèses décidées avant la première exécution D2.4G.

## Fonctionnalité livrée

Le noyau `prism/cyber_discovery.py` reçoit un objectif de sécurité, des expériences dérivées d'un adaptateur de code réel, un oracle de comportement et un budget d'exécution. Il produit un verdict `LOCAL_PROPERTY_WITNESS` ou `NO_WITNESS_NOT_SAFE`, une liste de contre-exemples minimisés, les observations vérifiables, les empreintes SHA-256 et les coûts. Un statut UNKNOWN/erreur doit rester distinct de la sûreté.

`scripts/d24g_source_only_discover.py` exécute dans un environnement isolé les deux adaptateurs Python. **Le scanner ne reçoit ni CVE, ni diff, ni code corrigé.** Il prend uniquement un fichier source en entrée, une classe d'API autorisée et un budget explicite. Il confronte un appel à un oracle local de propriété. Les versions corrigées sont téléchargées et testées dans des étapes de CI distinctes **après la phase de découverte**.

**Limite expérimentale majeure :** ces deux projets et leurs versions ont été sélectionnés par les chercheurs en connaissant déjà les vulnérabilités historiques de D2.4F. Il s'agit d'un essai **aveugle aux étiquettes dans l'algorithme**, pas d'un holdout aveugle pour les chercheurs, et certainement pas d'une découverte prospective d'un zero-day. Les adaptateurs de propriétés sont spécialisés ; PRISM n'est pas encore un scanner universel.

## Intégration prévue pour le vrai Ciel

Dépot Ciel examiné : `nkinzogomer-eng/ciel`, dont l'interface `base44/shared/ciel/interfaces/capability.ts` déclare `manifest`, `execute(params,ctx)` et une vérification facultative. Le registre impose les permissions et les exigences de runtime.

Contrat JSON `scm.prism.ciel-capability.v1` :
- `mission_id` et `task_id` obligatoires ;
- `execution_policy=LOCAL_READ_ONLY` et `requires_external_runtime=true` ;
- `capability=prism.cyber.discovery` ;
- `observation` inclut le code source SHA-256, le budget, les entrées, les résultats et un `replay_sha256` ;
- `ciel_verification_state=UNVERIFIED`, `needs_independent_attestation=true` ;
- `claim_of_new_vulnerability=false`, indépendamment de l'enthousiasme du modèle ;
- export uniquement avec autorisation explicite `--authorized-local`.

La présence de ce JSON **ne signifie pas que Ciel exécute actuellement PRISM**. Il faut un adaptateur EXTERNAL dans le dépôt Ciel, l'autorisation de mission, la supervision du processus isolé, un vérificateur indépendant et des checkpoints. Ne pas cacher une dépendance à un LLM.

Architecture cible : **CIEL** possède les objectifs, politiques, ressources, journalisation, mémoire, vérification et récupération ; **PRISM** possède les modèles structurels, la génération d'hypothèses, les requêtes coûteuses et les candidats de preuve. Le modèle externe n'est qu'un accélérateur facultatif. L'invalidation par empreinte des sources protège la réutilisation des résultats.

## Critères de livraison

- Tests adversariaux : budget strict, observations invalides rejetées, provenance, refus d'export non autorisé, impossibilité de confondre absence de preuve et preuve de sûreté.
- Deux sources tierces réelles vulnérables anciennes génèrent des témoins **sans lire le correctif pendant l'analyse**.
- Deux sources tierces corrigées testées ensuite donnent `NO_WITNESS_NOT_SAFE`, jamais `SAFE`.
- Artéfacts bruts, exécutions déterministes, coûts CPU/wall, enveloppe Ciel explicite et métadonnées sur le biais de sélection.
- Scientifiquement : deux causes historiques connues reproduites et **zéro nouvelle vulnérabilité inconnue démontrée**, jusqu'à preuve contraire.

Étape utile suivante : cible nouvelle autorisée/non présélectionnée, moteur d'hypothèses multi-fichiers/cross-module, validation de l'adaptateur dans Ciel, et essai sur un vrai historique indépendant où la réponse n'est pas disponible lors de la découverte.
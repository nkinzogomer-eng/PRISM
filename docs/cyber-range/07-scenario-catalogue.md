# 07 — Catalogue des scénarios et critères d'acceptation

**Version :** 1.0 — 2026-10-31
**Objet :** rendre chaque affirmation testable. Un scénario n'existe que s'il a une hypothèse, des préconditions, des preuves et des critères d'acceptation exécutables.
**Règle :** aucun scénario ne doit être « validé par lecture ». Chaque critère indique la commande ou l'artefact qui le tranche.

Rappel de portée : ces scénarios étudient une **chaîne de type** Binance. Ils ne reconstituent pas l'incident du 29 octobre 2026, dont la chronologie publique est partielle et contradictoire (§10).

---

## S1 — Poste compromis → identité et session

**Hypothèse :** depuis un poste de la zone `rg-corp`, un attaquant peut obtenir un jeton OIDC utilisable depuis une autre machine, tant que l'IdP n'impose ni *binding* d'appareil ni preuve de possession.

**Préconditions :** IdP opérationnel (Authelia en Tier A, Keycloak en Tier B/C) ; un compte `ops1` avec TOTP ; durée de vie d'accès fixée par configuration ; postes `rg-corp` instrumentés (osquery + Falco).

**Preuves attendues :** (a) jeton d'accès capturé, (b) requête réussie depuis une seconde adresse IP de la même zone, (c) journaux d'authentification de l'IdP, (d) absence ou présence d'alerte côté `rg-mon`, (e) horodatages UTC des deux côtés.

**Critères d'acceptation :**
1. dans la configuration initiale, l'usage du jeton depuis un second hôte réussit ≥ 1 fois sur 5 tentatives ;
2. après activation du *binding* (DPoP ou mTLS + `acr`), le même rejeu échoue 5/5 ;
3. le scénario est reproductible : deux exécutions produisent les mêmes étapes (comparaison des traces), hors horodatages ;
4. le temps entre l'usage du jeton volé et la première alerte est mesuré (valeur et méthode dans le rapport, pas seulement « rapide »).

**Limites :** un poste réel ajoute EDR, disque chiffré, gestion de parc. Le poste du laboratoire est un conteneur instrumenté, pas un Windows géré (L-4).

---

## S2 — Services internes et permissions composées

**Hypothèse :** des combinaisons de permissions prises isolément anodines (lecture de secrets + appel d'API interne) suffisent à atteindre le service de transaction sans jamais toucher à une clé.

**Préconditions :** OpenBao avec politiques par service ; `svc-transaction` exposé en `rg-prod` ; un jeton de service de faible privilège dans `rg-corp` ; OPA en mode décision.

**Preuves attendues :** graphe de dépendances effectivement emprunté ; requêtes HTTP réelles avec codes de retour ; entrées de bail OpenBao ; décisions OPA (`decision.reasons`).

**Critères d'acceptation :**
1. le chemin est décrit comme une séquence reproductible de commandes, exécutable par un tiers ;
2. chaque arête du chemin est justifiée par une entrée de journal ou une réponse applicative — aucune arête « supposée » ;
3. une contre-mesure (réduction de portée du jeton, scission du service) fait échouer le chemin 5/5, sans casser le fonctionnement nominal (test de non-régression : les 292 tests de la cible restent verts, plus les tests de service) ;
4. les permissions réellement nécessaires sont listées et comparées aux permissions accordées (écart quantifié).

**Limites :** les services métier `svc-*` sont écrits pour ce laboratoire (voir L-3) ; ils exposent de vraies interfaces HTTP et une vraie base, mais leur code n'est pas un code d'échange réel.

---

## S3 — Chaîne d'approvisionnement : CI → clés

**Hypothèse :** une identité CI sur-privilégiée (fixture `30-fixture-rbac-misconfig.yaml`) et un jeton de service à durée illimitée permettent d'atteindre le plan de signature depuis une étendue de travail, sans exploiter de faille logicielle.

**Préconditions :** k3s (Tier B/C) ; fixture `deploy-bot` + `ClusterRoleBinding` cluster-admin + secret de jeton ; runner Woodpecker capable de lancer des conteneurs.

**Preuves attendues :** identité utilisée, requêtes d'API Kubernetes, tentative d'accès au signer, décisions Kyverno, alertes Falco, journaux d'audit k8s.

**Critères d'acceptation :**
1. le chemin réussit **avant** correctif (fixture), avec preuve d'API (objet créé/lu, pas seulement un message) ;
2. après application du correctif (`31-fixture-rbac-fixed.yaml` : rôle minimal, jeton projeté avec TTL, fédération OIDC), le chemin échoue 5/5 ;
3. Kyverno en `Enforce` bloque la tentative avec un message identifiable dans les journaux ;
4. le temps de détection est mesuré ; si aucune détection n'existe, c'est un **résultat négatif** à publier, pas un critère à assouplir.

**Limites :** pas de Tier A (pas de Kubernetes). Sur Tier A, seul le volet « jeton CI mal stocké » est testable.

---

## S4 — Autorisation de transaction

**Hypothèse :** la politique OPA peut être contournée non par une faille Rego, mais par un chemin d'appel qui ne consulte pas la décision (drift entre politique et implémentation), ou par une évaluation par approbateur au lieu de par compte.

**Préconditions :** `range/policies/tx.rego` déployée ; jeu de données de limites, destinations, révocation et vélocité ; un second chemin d'appel (`/internal/transfer`) volontairement présent comme le ferait un service historique.

**Preuves attendues :** requêtes et décisions complètes (`allow`, `reasons`) ; enregistrements de vélocité ; entrées en base ; comparaison entre les deux chemins.

**Critères d'acceptation :**
1. les tests de politique (`range/policies/tx_test.rego`) passent 6/6 sur un hôte avec OPA — sinon le correctif est considéré comme cassé ;
2. le contournement identifié réussit 5/5 avant correctif, avec preuve d'écriture en base ;
3. après correctif (point d'autorisation unique, contrôle de vélocité par compte), réussite 0/5 et non-régression nominale ;
4. les montants, destinations et approbations utilisés sont **fictifs** et marqués comme tels dans les rapports.

**Limites :** un vrai système aurait des dizaines de chemins et d'actifs ; ici le jeu est réduit et la couverture est donc surestimée si on l'extrapole.

---

## S5 — Signature et transfert

**Hypothèse :** la boucle autorisation → signature → transfert peut être rompue à trois endroits distincts et inégalement détectés : politique PKCS#11 du jeton, absence d'`ALWAYS_AUTHENTICATE`, et absence de contrôle de nonce/replay côté chaîne.

**Préconditions :** SoftHSM v2 initialisé avec deux jetons (signer, ops) ; `svc-signer` seul autorisé vers le HSM ; Anvil + EntryPoint `0.7.0` + compte modulaire v2.0.0 non modifié ; bundler Alto ; relayer.

**Preuves attendues :** attributs d'objet (`pkcs11-tool --list-objects`), journaux de session HSM, transactions Anvil (hash, bloc, statut), décisions OPA, traces Suricata/Zeek sur la zone `rg-prod`.

**Critères d'acceptation :**
1. la signature nominale fonctionne et une transaction est minée sur Anvil (preuve par hash de transaction et receipt, pas par message applicatif) ;
2. une extraction de clé est **refusée** par le module quand `CKA_EXTRACTABLE=false` (preuve : code retour PKCS#11, pas seulement un log applicatif) ;
3. un rejeu de la même charge signée est rejeté par la chaîne ou par le relayer (preuve : erreur et hash) ;
4. chaque échec/correctif est daté sur une horloge unique pour permettre les mesures de latence.

**Limites :** aucune garantie matérielle (L-1) ; l'« attaquant » peut lire la mémoire du processus signataire, ce qui serait impossible avec un HSM physique correctement isolé.

---

## S6 — Détection, réponse, révocation

**Hypothèse :** il est possible de mesurer un MTTD et un MTTR reproductibles avec une horloge unique, et d'identifier au moins un point d'interruption *avant* le transfert.

**Préconditions :** Suricata et/ou Falco actifs ; règles versionnées ; journal centralisé ; procédure de révocation (jeton OIDC, bail OpenBao, certificat step-ca, clé PKCS#11).

**Preuves attendues :** horodatages (attaque, première alerte, première action de confinement), diff des règles appliquées, journaux de révocation (token `revoke`, bail `revoke`, CRL), état final vérifié.

**Critères d'acceptation :**
1. MTTD mesuré pour chaque scénario S1–S5, avec la règle exacte qui a déclenché — ou la mention explicite « non détecté » ;
2. au moins une mesure de MTTR avec preuve que la révocation a effectivement bloqué l'usage ultérieur (test après révocation, 5/5 refus) ;
3. les règles de détection sont versionnées et leur diff apparaît dans le rapport ;
4. une mesure sans règle correspondante n'est pas publiée comme « détection ».

**Limites :** MTTD dépend de la charge et du volume ; les valeurs ne sont pas transférables à une plateforme réelle (L-7).

---

## S7 — Vérification indépendante

**Hypothèse :** un vérificateur sans identité partagée avec Red/Blue Team peut rejouer les scénarios et recalculer faux positifs, faux négatifs, couverture et coûts à partir des preuves brutes.

**Préconditions :** journaux bruts exportés (pas les tableaux de bord) ; scénarios scriptés et idempotents ; jeu de contrôle négatif (trafic et actions légitimes).

**Preuves attendues :** script de rejeu, résultats comparés exécution/exécution, matrice de confusion par règle, coût (CPU minutes, RAM, Go écrits, EUR).

**Critères d'acceptation :**
1. le rejeu reproduit le même verdict (attaque possible / bloquée) sur 3 exécutions consécutives ;
2. faux positifs et faux négatifs sont calculés par règle, sur un jeu de contrôle incluant des actions légitimes dérivées des tests de non-régression ;
3. la couverture est exprimée comme « règles implémentées / techniques de la matrice » avec la liste des trous — jamais un pourcentage unique ;
4. les coûts (temps, RAM, disque, électricité ou EUR) sont reportés par scénario et comparés au budget de `04-resource-budget.md`.

**Limites :** le vérificateur partage l'infrastructure ; il est indépendant en identité et en code, pas en matériel (L-8).

---

## S8 — Chaîne d'approvisionnement logicielle

**Hypothèse :** sans vérification de signature en `Enforce`, une image non signée construite par la CI peut être déployée en `rg-prod` ; avec `cosign` + Kyverno en `Enforce`, elle est rejetée.

**Préconditions :** registre interne ; CI construisant et signant une image ; politique `rg-require-signed-images` (démarre en `Audit`, par conception).

**Preuves attendues :** manifeste d'image, sortie `cosign verify`, décision d'admission Kyverno, événements d'audit.

**Critères d'acceptation :**
1. en mode `Audit`, le déploiement non signé **passe** et l'événement est journalisé (preuve du trou) ;
2. en mode `Enforce`, il est refusé 5/5 avec message identifiable ;
3. Trivy et gitleaks bloquent au moins une construction volontairement fautive (CVE connue du jeu de test, secret factice) ;
4. aucune clé de signature réelle n'est utilisée : paire de clés générée localement, jamais publiée.

**Limites :** pas de transparence publique (Rekor) joignable depuis le laboratoire ; la vérification est locale, donc ne prouve rien sur l'identité de l'éditeur au sens de la supply chain publique.

---

## 9. Matrice de couverture des capacités demandées

| Capacité exigée | Scénarios | Preuve de couverture |
| --- | --- | --- |
| Cartographie actifs/dépendances/frontières | S2, S3 | graphe reproductible + entrées de journal par arête |
| Chemins d'attaque | S1, S2, S3 | séquences exécutables par un tiers |
| Combinaisons de permissions / erreurs de configuration | S2, S3, S8 | écart permissions accordées/exigées, fixtures |
| Interactions entre services | S2, S5 | traces HTTP/PKCS#11 corrélées |
| Détection | S6 | MTTD par règle versionnée |
| Points d'interruption | S5, S6 | refus vérifié 5/5 après correction |
| Délais de détection/réaction | S6, S7 | horloge unique, mesures répétées |
| Rejeu indépendant | S7 | 3 exécutions, même verdict |
| Faux positifs/négatifs/couverture/coûts | S7 | matrice de confusion + coûts mesurés |
| Révocation/confinement/récupération | S6, S5 | token/bail/CRL/clé, état final vérifié |

## 10. Statut factuel de l'incident de référence (2026-10-29)

Ce que les sources publiques (TRM Labs, TechCrunch, analyses de chaîne) rapportent, et qui doit rester séparé de nos hypothèses :

| Élément | Statut | Utilisation dans le laboratoire |
| --- | --- | --- |
| Mouvement de milliards d'USD depuis des portefeuilles Binance sur ~10 chaînes, ~20 minutes | rapporté par plusieurs sources | ordre de grandeur et *timing* seulement |
| Implication d'une infrastructure de signature *chaude* | rapporté, non confirmé officiellement | motif de S4/S5 |
| Compromission d'un poste d'ingénieur DevOps comme origine | **rapporté, préliminaire, non confirmé** | hypothèse de S1, testée séparément |
| Délégation EIP-7702 vers un contrat *sweeper* | rapporté par analyses on-chain | motif d'étude du chemin de signature (S5) |
| Absence de fuite de clés selon l'exploitant | déclaration de l'exploitant | contre-hypothèse à tester en S5 |
| Gels d'émetteurs de stablecoins | rapporté | motif de S6 (révocation externe) |

**Règle de séparation :** aucun rapport de ce laboratoire ne pourra écrire « voici comment Binance a été piraté ». Formulation autorisée : « dans un laboratoire reproduisant la classe de mécanismes concernée, tel chemin a été validé ou invalidé ».

# 08 — Limites de fidélité au réel

**Version :** 1.0 — 2026-10-31
**Objet :** lister, sans les atténuer, tout ce que ce laboratoire **ne reproduit pas**. Chaque limite a un identifiant, un impact sur les conclusions possibles, et un test qui permettrait de la lever.

---

## 1. Règle de lecture

Une conclusion tirée du laboratoire est valide dans le périmètre `L-1 … L-8`. Au-delà, elle doit être reformulée. Le tableau ci-dessous est la seule référence autorisée dans les rapports.

| ID | Limite | Ce que le laboratoire fait | Ce que le réel fait | Impact sur les conclusions | Ce qui lèverait la limite |
| --- | --- | --- | --- | --- | --- |
| **L-1** | HSM émulé (SoftHSM v2), pas matériel | PKCS#11 réel, attributs réels (`CKA_EXTRACTABLE`, `CKA_SENSITIVE`, `ALWAYS_AUTHENTICATE`) | clé non extractible physiquement, anti-canaux auxiliaires, attestation, destruction | impossible de prouver qu'une clé est inexportable ; seulement que la politique PKCS#11 et l'usage applicatif la respectent | HSM matériel (YubiHSM 2, Nitrokey HSM) ou service KMS réel, à ajouter en Tier C |
| **L-2** | Isolation par conteneurs, pas par VM | ponts Docker + nftables | hyperviseur, noyau séparé par machine | une évasion de conteneur atteint l'hôte ; les scénarios ne « contiennent » pas un attaquant au niveau noyau | `/dev/kvm` + microVM (Firecracker/Kata) ou machines séparées — indisponible sur l'hôte de conception |
| **L-3** | Services métier `svc-transaction`, `svc-wallet`, `svc-signer`, `svc-relayer` écrits pour le laboratoire | vraies interfaces HTTP, vraie base, vrai client PKCS#11, vraies décisions OPA | code d'exchange de plusieurs millions de lignes, dette technique, chemins historiques oubliés | les chemins d'attaque trouvés sont **représentatifs**, pas exhaustifs ; l'absence de faille ne prouve rien | injecter un service open source réel (par ex. un nœud de règlement) en plus — coûteux en RAM |
| **L-4** | Postes de travail simulés par des conteneurs instrumentés | osquery, Falco, journaux, sessions réelles | Windows/macOS gérés, EDR commercial, chiffrement de disque, gestion de parc | les techniques dépendant de l'OS de bureau ne sont pas couvertes ; MTTD côté poste est optimiste | VM Windows/Linux + agent EDR open source (Wazuh agent) — Tier C |
| **L-5** | Clés de test Anvil publiques | comptes déterministes, soldes fictifs | aucune clé publique connue ne contrôle de fonds | risque de confusion ; aucune conclusion sur la gestion réelle des clés de test | discipline documentaire + marquage systématique `FICTIF` dans les rapports |
| **L-6** | CI simplifiée (Gitea + Woodpecker) | identités de service, portée des secrets, runners avec droits de déploiement | GitHub Actions/GitLab CI avec OIDC fédéré, environnements protégés, approbations | certaines classes de contournement CI ne sont pas représentables | ajouter une fédération OIDC locale (Keycloak → k8s) en Tier B, déjà prévue |
| **L-7** | Échelle | dizaines de transactions, 2 utilisateurs, une chaîne | millions de transactions, dizaines de chaînes, milliers d'utilisateurs | MTTD/MTTR ne sont **pas** transférables ; seule la *structure* des mesures l'est | banc de charge (k6) + jeu de données de 10^6 transactions — coûteux, à faire seulement si une question l'exige |
| **L-8** | Vérificateur indépendant mais co-localisé | identités et code séparés, preuves en écriture seule | organisations distinctes, audits externes | la neutralité est une propriété de processus, pas une garantie technique | exécution du vérificateur sur un hôte distinct, par un opérateur différent |
| **L-9** | Pas de contreparties externes réelles (émetteurs de stablecoins, gel de fonds) | révocation simulée localement (liste noire dans OPA, gel du relayer) | émetteurs réels capables de geler des fonds en minutes | les délais de réponse « externe » sont des hypothèses, pas des mesures | impossible sans tiers réel — donc jamais affirmé |
| **L-10** | Pas de pression opérationnelle réelle | pas d'astreinte, pas de pertes financières, pas de direction | décisions sous stress, informations incomplètes, réputation | les temps de réaction humains ne sont pas mesurés, seulement les temps techniques | exercices chronométrés avec opérateurs, protocole séparé |
| **L-11** | Chaîne locale unique (Anvil, chain-id 31337) | EVM complète, snapshots, contrôle du temps | 10 chaînes hétérogènes, finalité variable, réorganisations | les comportements multi-chaînes (cohérence inter-chaînes) ne sont pas modélisés | ajouter un second nœud + un pont simulé — Tier C |
| **L-12** | Journaux plus complets que dans la réalité | toutes les couches journalisent | journaux manquants, non synchronisés, corrompus, rétention courte | surestimation de la détection | introduire une perte de journal contrôlée (échantillonnage, panne de collecteur) comme scénario S6-bis |

## 2. Composants dont le pin n'est pas vérifié

Ces trois composants ne peuvent pas entrer dans une couche validée tant que leur version/digest n'est pas figé par une source vérifiable (détail dans `range/versions.lock.json`, champ `pin_confidence`) :

| Composant | Pourquoi | Résolution prévue |
| --- | --- | --- |
| SoftHSM v2 | aucune release exposée par l'API GitHub | archive signée du fournisseur : SHA-256 + signature GPG consignées à la construction |
| `registry:2` | étiquette d'image grossière | digest résolu au premier `pull`, écrit dans le verrou |
| tcpdump / tshark | paquets de distribution | versions exactes écrites dans `journal-install-10-system.log` |

## 3. Ce que la fidélité « maximale » coûterait

| Amélioration | Gain de fidélité | Coût |
| --- | --- | --- |
| HSM matériel | L-1 levée | ~60–300 € par module, plus gestion physique |
| MicroVM par zone | L-2 levée | 3–5× la RAM, `/dev/kvm` obligatoire |
| Wazuh + Velociraptor par défaut | L-12 partiellement levée | +8 GB RAM, +150 GB disque |
| 10^6 transactions | L-7 levée | +100 GB, génération longue, MTTD plus lent |
| Second hôte pour le vérificateur | L-8 levée | un hôte supplémentaire, même modeste |

**Décision de conception :** aucune de ces améliorations n'est achetée avant qu'une question de recherche précise ne l'exige. Le laboratoire doit rester un instrument, pas une fin.

## 4. Formulations autorisées / interdites

| Interdit | Autorisé |
| --- | --- |
| « Un attaquant peut voler les clés du HSM » | « avec SoftHSM, une clé marquée non extractible est refusée à l'export par le module ; cela ne prouve rien sur un HSM matériel » |
| « La détection prend 45 secondes chez Binance » | « dans ce laboratoire, la règle X a déclenché 43 s après l'action, sur un hôte 8 vCPU, avec un jeu de données de N transactions » |
| « Le correctif empêche l'attaque » | « le correctif a fait échouer le scénario S3 5/5 ; les variantes S3-b à S3-d n'ont pas été testées » |
| « Voici la chaîne de l'incident du 29 octobre » | « dans un laboratoire reproduisant cette classe de mécanismes, la chaîne suivante est possible » |

## 5. Tenue dans le temps

Une limite n'est pas une excuse permanente :

* chaque limite a un test de levée identifié (§3) ;
* une montée de version majeure d'un composant rouvre la limite concernée ;
* un rapport de scénario doit citer les limites **effectivement rencontrées**, pas la liste complète par précaution.

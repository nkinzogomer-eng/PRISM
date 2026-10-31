# 06 — Frontières de sécurité

**Version :** 1.0 — 2026-10-31
**Objet :** définir ce que le laboratoire isole, comment, et ce qu'il ne peut pas garantir. Ce document est contraignant : une expérience qui l'enfreint n'est pas publiée.

---

## 1. Interdictions absolues

| # | Interdiction | Vérification |
| --- | --- | --- |
| X1 | Aucune interaction avec un système réel, une chaîne publique, un RPC externe, un fork mainnet | `grep -rE 'fork-url\|rpc_url\|mainnet\|infura\|alchemy\.com/v2'` doit être vide hors documentation ; aucune sortie réseau n'est possible (`I2`) |
| X2 | Aucun portefeuille, clé, fonds ou infrastructure de tiers | toutes les clés sont générées localement ; les comptes Anvil par défaut sont des clés de test publiques, jamais des secrets |
| X3 | Aucune cible hors laboratoire, même « pour tester » | la seule sortie autorisée est DNS/NTP interne et le pont `rg-wan` (isolé) |
| X4 | Aucune valeur monétaire réelle, aucun stablecoin réel, aucune adresse de contrat mainnet dans une transaction | jeux de données fictifs, adresses générées localement |
| X5 | Aucun code exploitable contre un système réellement déployé | les fixtures sont des configurations et des services de laboratoire, publiés avec le laboratoire |

## 2. Isolation en quatre anneaux

| Anneau | Mécanisme | Force | Limite |
| --- | --- | --- | --- |
| 1 | Ponts Docker `internal: true` (aucun NAT sortant) | forte : pas d'IP routable | un conteneur `--privileged` peut modifier les routes de l'hôte |
| 2 | nftables (`policy drop` sur `input`/`output`/`forward`) | forte et hors d'atteinte des conteneurs | nécessite root sur l'hôte |
| 3 | NetworkPolicy Kubernetes + Kyverno | moyenne : contournable par `hostNetwork` | ne protège que le trafic pod-à-pod |
| 4 | Machine dédiée, sans accès aux données personnelles du projet | forte | dépend de l'opérateur |

**Règle de conception :** l'anneau 2 est la vraie frontière. Les anneaux 1 et 3 existent pour produire des scénarios (un attaquant peut les franchir, et c'est le sujet), l'anneau 2 pour empêcher la sortie.

## 3. Gestion des secrets dans le laboratoire

| Secret | Où il vit | Ce qui le protège | Ce qui le compromettrait |
| --- | --- | --- | --- |
| Identité age (chiffrement des configs) | `~/.config/prism-range/age.key` (hôte, hors git) | permissions 0600, hors sauvegarde du dépôt | copie dans un conteneur, log de build |
| PIN SoftHSM (token `prism-signer`) | secret SOPS → variable de service | monté en fichier 0400, jamais en argument | `ps aux`, dump mémoire du conteneur |
| Jetons OIDC | émis à la volée, TTL 5–15 min | courte durée, révocation | vol de session (objet de S1) |
| Jetons de service CI | secret CI Woodpecker | portée limitée | fixture `deploy-bot` (objet de S3) |
| Clés de signature d'images (cosign) | paire locale générée au build | jamais publiée | signature d'images malveillantes |
| Clés Anvil de test | publiques, dans la config | rien — ce ne sont pas des secrets | confusion avec de vraies clés (risque documenté L-5) |

**Règle :** aucun secret ne transite par un argument de ligne de commande, par une variable d'environnement visible dans `docker inspect`, ni par un journal. Le vérificateur `F1` refuse le dépôt si un motif de clé apparaît.

## 4. Frontières entre rôles

| Rôle | Peut | Ne peut pas |
| --- | --- | --- |
| **Red Team** | opérer depuis `rg-corp`/`rg-wan`, tester permissions et configurations | accéder au plan de gestion `rg-mgmt`, aux sauvegardes de preuves |
| **Blue Team** | lire toute la télémétrie, déployer détections et politiques | modifier les preuves brutes, effacer des journaux |
| **Vérificateur indépendant** | lire les preuves brutes, rejouer depuis des snapshots, recalculer les métriques | réutiliser une identité Red ou Blue, modifier la scène pendant un rejeu |
| **Opérateur** | construire, démarrer, restaurer, appliquer nftables | intervenir pendant une mesure sans le consigner |

Séparation effective : trois identités distinctes, trois espaces de travail, et **des preuves en écriture seule** pour la Blue Team (WORM ou export signé).

## 5. Intégrité des preuves

1. Chaque scénario produit un dossier horodaté contenant : commandes exécutées, journaux bruts, captures, hash de transaction, décisions de politique, empreinte de la configuration (`sha256` de `versions.lock.json` + des fichiers de politique).
2. Le dossier est scellé par un manifeste `sha256` signé (cosign, clé locale).
3. Le vérificateur recalcule le manifeste avant de rejouer. Un manifeste invalide → le rejeu est refusé.
4. Les journaux bruts ne sont jamais édités ; les analyses sont des fichiers **dérivés**, avec la commande qui les a produits.

## 6. Sortie de données (exfiltration simulée)

L'invariant `I2` empêche toute sortie vers Internet, ce qui est nécessaire mais insuffisant : un scénario d'exfiltration a besoin d'une destination. Solution : un écouteur factice dans `rg-wan` (`10.10.0.0/24`, pont isolé). Il enregistre ce qui arrive et **ne relaie rien** vers l'extérieur. Une exfiltration réussie signifie « données arrivées à un écouteur isolé », jamais « données sorties du laboratoire ».

## 7. Données personnelles et juridique

* Aucune donnée réelle d'utilisateur, aucun identifiant de personne réelle : jeux de données synthétiques (`alice`, `ops1`, soldes fictifs).
* Aucune adresse de portefeuille réelle ; les adresses sont générées par Anvil ou dérivées d'une graine de laboratoire documentée.
* Les rapports ne doivent contenir aucune adresse réelle, même « pour illustrer ».
* Le laboratoire ne se connecte à rien : il n'y a donc pas de question de conformité d'accès à un système tiers. La seule question restante est celle de l'usage des résultats, traitée en `09-risks.md` R-8.

## 8. Arrêt d'urgence

| Situation | Action | Commande |
| --- | --- | --- |
| Comportement réseau inattendu vers l'extérieur | couper la sortie | `sudo nft flush ruleset && sudo nft -f range/network/nftables-range.nft --define EGRESS=deny` |
| Scénario qui « déborde » (service en boucle, disque qui se remplit) | arrêt des seuls services du scénario | `docker compose -f range/compose/tier-a.yml stop <svc>` |
| Soupçon de clé réelle utilisée par erreur | arrêt total + revue | `docker compose down -v` puis revue des journaux avant toute reprise |
| Perte de la séparation des preuves | invalider le scénario | pas de publication ; reconstruire depuis le snapshot |

Un scénario interrompu n'est **jamais** complété « à la main » : il est rejoué depuis son snapshot, sinon la mesure n'a pas de valeur.

## 9. Ce que ces frontières ne garantissent pas

* Un opérateur root sur l'hôte peut tout casser : ce n'est pas une frontière de sécurité contre l'administrateur, c'est une frontière contre le code exécuté dans le laboratoire.
* `SoftHSM` ne protège pas contre la lecture mémoire du processus signataire ; la frontière « la clé ne sort jamais du HSM » est **fausse** dans ce laboratoire (L-1).
* Les ponts Docker ne sont pas une frontière de noyau : une évasion de conteneur atteindrait l'hôte. Sur un hôte de recherche dédié, le risque est accepté et consigné (R-3).

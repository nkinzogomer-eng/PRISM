# PRISM D2.4H — Moteur d'hypothèses de sécurité construites depuis le code

**26 octobre 2026 — livraison technique vérifiée ; aucune vulnérabilité inconnue confirmée.**

## Sources et preuves d'exécution

- [PR #34 (brouillon)](https://github.com/nkinzogomer-eng/PRISM/pull/34) ; dernière version de code testée : `849dce405c8c69d86bf50946d53732de16f3b2dc`. Aucun changement à `main`.
- [GitHub Actions #40255300448 — SUCCÈS](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40255300448). **28/28 tests unitaires/adversariaux** ; cinq versions de code tiers sur la famille chemins + code tiers Solidity et autorisations.
- Données brutes, empreintes SHA-256 des sources, mesures `/usr/bin/time`, hypothèses, inconnues et observations : artefact GitHub Actions **`d24h-autonomous-source-hypothesis-evidence`** (rétention 30 jours).

## Capacité nouvelle, distincte de D2.4G

`prism/cyber_hypotheses.py` classe le fichier source Python sans CVE, correctif, propriété ou adaptateur choisis par l'utilisateur. Quatre familles de propositions :
1. sécurité des chemins et sorties de racine de confiance ;
2. entrées potentiellement liées à l'exécution de commandes ou d'expressions ;
3. secrets susceptibles de circuler dans les journaux ;
4. opérations web modifiant l'état sans preuve d'autorisation localement visible.

Les heuristiques AST ne sont pas des preuves. Les deux familles commande et journalisation sont pour l'instant **UNVERIFIED** et n'ont reçu que des tests de détection/contre-exemples synthétiques. Le détecteur d'autorisation prend désormais en compte l'ordre des gardes avant/après les écritures, afin de ne pas masquer une écriture prématurée par un contrôle tardif.

`scripts/d24h_autonomous_discover.py` choisit une expérience parmi les familles exécutables, gère strictement les budgets et laisse les autres hypothèses à `UNVERIFIED` / `INCOMPLETE_UNKNOWN`. Une absence de témoin n'est jamais présentée comme une preuve de sûreté.

## Vraies sources Python : hypothèses et exécutions locales

| Source tierce, version figée | Hypothèses exécutables de chemin | Tests de chemin exécutés | Témoin pour l'ancienne propriété |
|---|---:|---:|---|
| Starlette 0.26.1 (vulnérabilité historique publique) | 1 | 14 | OUI |
| Starlette 0.27.0 (corrigée) | 1 | 14 | NON |
| Werkzeug 3.1.5 (vulnérabilité historique publique) | 1 | 17 | OUI |
| Werkzeug 3.1.6 (corrigée) | 1 | 17 | NON |
| Django, SHA `0e128d524d0a7c55a955570d6e5da983ac6ce6c7` | 1 | 7 | NON |

L'exploration Starlette dispose d'une **nouvelle grammaire métamorphique de 14 entrées** : chemins simples, normalisation, variantes de noms voisins, sorties de répertoire et liens symboliques. La proposition des entrées est indépendante des CVE et des différences entre les sources, mais les deux versions historiques ont été choisies en ayant connaissance des anciens défauts. **Il ne s'agit pas d'une découverte à l'aveugle.** Le résultat sur Django couvre seulement sept propriétés locales : aucun verdict général de sûreté.

## Vrai code actuel FastAPI : autre famille vérifiée

Source réelle du modèle FastAPI à SHA `b1125d8839482cb7bbae603ddc6d0081bf87532e` : `backend/app/api/routes/items.py` et `backend/app/api/deps.py`.

- Le moteur automatique a construit **deux hypothèses d'autorisation**, sans qu'on lui indique la vulnérabilité recherchée.
- Un nouveau vérificateur a résolu la dépendance source `CurrentUser = Annotated[User, Depends(get_current_user)]` dans un **autre module**, puis a extrait et exécuté la vraie méthode `delete_item` avec une base et des utilisateurs fictifs locaux.
- **Quatre contrôles comportementaux sur quatre réussis** : refus 403 sans écriture pour un non-propriétaire, suppression et commit pour le propriétaire, permission administrateur, refus 404 sans écriture si l'objet manque.
- Une mutation contrôlée qui exécutait la suppression avant le contrôle a été détectée dans les tests internes. C'est un contrôle synthétique de sensibilité, pas une vulnérabilité découverte dans FastAPI.
- L'autre hypothèse d'autorisation reste non vérifiée : **statut global `INCOMPLETE_UNKNOWN`**, à juste titre.

**Restriction :** le code original de la méthode de route a été exécuté, mais pas le serveur HTTP, ni le moteur d'authentification JWT lui-même, ni une vraie base de données. La résolution intermodulaire de la dépendance est statique ; aucune absence globale de faille d'autorisation n'a été démontrée.

## Source Solidity : nouveaux travaux candidats, vérificateur manquant

Sur OUSD réellement publié, SHA `299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4`, l'analyse lexicale a extrait **32 fonctions et 12 hypothèses** :
- **5** hypothèses de conservation de balances/offre ;
- **7** hypothèses de frontières d'autorisation ;
- **0** hypothèse sur les appels externes à partir des motifs détectés.

**12/12 sont non vérifiées**, et ne représentent ni 12 anomalies, ni 12 découvertes. Des tests EVM stateful antérieurs existent dans D2.4C/D2.4E mais aucun lien sémantique d'inférence et de vérification n'a encore été validé pour ces hypothèses D2.4H.

## Bilan et décision

- Capacité démontrée : génération de plusieurs *familles d'hypothèses depuis le code seul*, exploration de chemins plus variée, vérification locale de deux cas historiques et vérification comportementale d'une route d'autorisation actuelle sous dépendances simulées.
- **Causes racines historiques reproduites : 2 ; vulnérabilités inédites indépendamment confirmées : 0.**
- Aucun résultat ne démontre encore 29–50 fois plus de découvertes/vitesse ou une réduction globale de coût de 80 %. Aucune généralité scientifique démontrée.
- Ciel est **gelé**, conformément à la décision du projet. Son interface JSON existante reste disponible mais aucune nouvelle modification Ciel n'a été faite pendant D2.4H.

**Prochain GO nécessaire :** un lot indépendant de logiciels autorisés non présélectionnés pour leur cause racine, vérificateurs reproductibles pour commande/logs et Solidity multi-fichiers, analyse réelle des effets/alias et expériences jusqu'à une violation indépendante confirmée. Ne pas fusionner `main` avant revue de sécurité du code et du périmètre d'exécution.

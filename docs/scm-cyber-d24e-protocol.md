# SCM D2.4E — code source réel, deux écosystèmes cyber

Protocole figé le 24 octobre 2026 avant exécution en CI. La supériorité scientifique est une hypothèse à tester et éventuellement réfuter.

## Cibles indépendantes, révisions immuables

- Python, sécurité applicative : pallets/werkzeug, SHA 6c4c680f5392342a68065114987f39160388064c ; fichier src/werkzeug/security.py ; fonctions safe_join et check_password_hash.
- Solidity, crypto DeFi : scfuzzbench/origin-dollar-scfuzzbench, SHA 299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4 ; fichier contracts/contracts/token/OUSD.sol ; scénarios transactionnels D2.4C.

Toutes deux sont des sources externes réelles. Leurs commits doivent être vérifiés avant mesure. Aucun serveur public ni actif n'est attaqué.

## Méthodes, références et hypothèses

- Analyse de syntaxe Python avec ast : appels directs locaux et inconnus explicitement marqués. Aucune prétention à l'inférence automatique complète des propriétés de sécurité.
- Analyse Solidity au niveau lexical du fichier : fonctions et graphe d'appels approximatifs ; héritage, effets externes, proxies et appels dynamiques inconnus.
- Quatre racines préfixées : safe_join ; check_password_hash ; transferFrom/approve/allowance ; mint/burn/changeSupply/transfer.
- Comparateur indépendant : fermeture des appels Python par BFS direct sur le même AST, telle que les outils classiques le font déjà. Si les résultats sont identiques, on conclut ex æquo, pas un gain scientifique.
- Exécution réelle de safe_join, sept chemins sûrs ou traversants et oracle externe basé sur commonpath POSIX. Cet oracle ne couvre ni les symlinks ni Windows ni les droits d'accès.
- Mutation volontaire, uniquement en mémoire sur un code externe temporaire, supprimant la condition de refus des chemins parents ; le module original n'est pas modifié. C'est un test de sensibilité artificiel, pas une faille découverte.
- Reprise des contrôles OUSD EVM propre, référence indépendante Foundry, invariant stateful et mutant artificiel, avec les sorties brutes et les coûts.

## Critères prédéfinis

PASS ingénierie : les commits des deux sources sont vérifiés, la syntaxe est extraite, les quatre frontières sont validées, neuf tests adversariaux réussissent, les sept cas Python concordent avec l'oracle, la mutation est détectée, six exécutions EVM OUSD restent vertes, trois témoins Foundry détectent la mutation artificielle.

NO-GO scientifique tant que ne sont pas démontrées des découvertes nouvelles de causes racines sur des tiers indépendants, avec effet et flux de données déduits du code exécutable, vérification indépendante et performance contre de bonnes références traditionnelles sur ressources comparables.

Les techniques d'AST, callgraph et slicing sont anciennes. Les améliorations contre une analyse exhaustive naïve ne sont pas une preuve d'originalité scientifique. La D2.4D n'avait apporté aucun gain additionnel par rapport au slicing classique.

## Étape nécessaire pour une supériorité

Implémenter les effets de lecture/écriture et flux interprocéduraux de manière conservative pour au moins deux familles de vrais projets, confirmer des violations réelles avec des tests tiers, et comparer planification orientée décision à des outils conventionnels puissants avec budgets, effort humain et taux de preuve contrôlés.
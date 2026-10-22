# D1.0 — premier résultat vérifié : oracle de vulnérabilités comportemental

**22 octobre 2026 · statut : GO pour passer à D1.1 (baselines), NON pour annoncer des performances de découverte SCM.**

## Source et exécution

- [GitHub Actions réussi — exécution 39726281112](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39726281112).
- [Artefacts reproductibles](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39726281112/artifacts/12402498519), comprenant les 24 sources générées, le manifeste public, l'oracle de développement, les résultats détaillés des témoins et le test de notation à prédictions vides.
- Révision de code testée `79e9ac2403b1b04006157dbcf2fd68c45ca44011`.
- Empreinte SHA-256 du manifeste public de cas : `8de0f9adc7bc1c99805a8ae90c39a3878521b473756f2f043d12325d7c967c08`.
- Python 3.12, uniquement bibliothèque standard pour corpus, oracle et notation ; aucun scanner tiers ni aucun LLM nécessaire.
- **18 tests unitaires et adversariaux réussis**.

## Inventaire de vérité effectivement validé

| Famille de propriété | Variantes avec violation reproduite | Variantes corrigées validées | Total |
|---|---:|---:|---:|
| `SQLI_UNEXPECTED_OWNER` | 6 | 6 | 12 |
| `BAC_CROSS_TENANT_READ` | 6 | 6 | 12 |
| **Total** | **12** | **12** | **24** |

Pour l'injection SQL, les fixtures utilisent une base `sqlite3` **exclusivement en mémoire** contenant un enregistrement `alice` et un `bob`. Les témoins de test fournissent une entrée hors contrôle ; l'oracle atteste que la réponse divulgue l'enregistrement de `bob` sans le demander légitimement. Un contrôle séparé confirme que les demandes autorisées pour `alice` et `bob` continuent de fonctionner.

Pour le contrôle d'accès, un utilisateur `alice` tente de lire une entrée appartenant à `bob` via une fonction locale. Les versions exposées renvoient le marqueur `BOB_SECRET`, tandis que les variantes corrigées exigent une correspondance entre l'identité et le propriétaire. Les accès légitimes `alice → a-doc` et `bob → b-doc` doivent fonctionner dans les deux variantes.

Chaque paire diffère par un mécanisme de protection : construction de requête, transmission via fonction auxiliaire, paramètres SQL, échappement, liste blanche, contrôle de propriétaire, etc. L'oracle vérifie des **propriétés définies sur des traces concrètes**, pas l'absence universelle de vulnérabilités.

## Protocole de notation vérifié

Une proposition n'est un vrai positif que si elle fournit : (1) un identifiant de cas dans le manifeste gelé, (2) la famille de propriété correcte, (3) un témoin d'entrée qui entraîne la violation observée par un **oracle séparé du détecteur**, et (4) des contrôles fonctionnels normaux qui réussissent.

- Tentative sans preuve fonctionnelle : classée non étayée, ne peut pas augmenter les vrais positifs.
- Doublons : ne peuvent jamais gonfler le rappel ; ils sont pénalisés et rapportés.
- Mauvaise famille de propriété ou périmètre invalide : rejeté ou compté comme rapport erroné, jamais TP.
- Source modifiée après scellement ou manifeste incohérent : arrêt de l'évaluation.
- Nouvelle preuve de violation sur une version étiquetée corrigée : **conflit de vérité** nécessitant un arbitrage ; ne pas le masquer en faux positif.
- `precision` indéfinie lorsqu'il n'y a aucune prédiction ; `rappel = 0` par convention lorsqu'il existe des vulnérabilités positives de référence mais aucun signalement.
- Coût du détecteur : **NON MESURÉ**, explicitement distinct du coût d'exécution de l'oracle et de la notation.

Le contrôle de notation avec un fichier de prédictions vide donne `TP=0, FP=0, FN=12, TN=12, rappel=0`. **C'est un test de cohérence de l'évaluateur et non une baseline de détection compétitive.** Les tests qui injectent les réponses de l'oracle dans le score ne peuvent en aucun cas être cités comme une capacité de PRISM.

## Limites fondamentales

1. Corpus synthétique de développement, petit et délibérément créé pour la reproductibilité. Il ne mesure ni la prévalence naturelle ni le rappel réel sur du code tiers.
2. Les labels de l'oracle sont séparés du manifeste public, mais présents dans le dépôt accessible ; il ne s'agit donc PAS d'un holdout aveugle.
3. Toutes les violations sont des divulgations de propriété simulées dans des programmes locaux. **Aucune de ces 12 violations n'est attribuée à une gravité « critique ».**
4. Des tests par témoin ne prouvent pas qu'une version corrigée est sûre dans tous les états ou pour toutes les entrées.
5. Il n'y a **aucun détecteur de PRISM implémenté/mesuré par D1.0**. Aucun gain de rappel, de précision, de coût ou de découvertes inédites n'est démontré.
6. L'oracle charge exclusivement son code d'exemple généré et vérifié par empreintes ; il n'est pas un environnement isolé pour exécuter du code non fiable.
7. Les budgets globaux (CPU, mémoire, énergie, coût humain) et les baselines natives doivent être ajoutés dans les phases suivantes.

## Étape suivante D1.1, sous contrôle

Exécuter des baselines correctement configurées (SAST pour SQLi, tests d'autorisation dynamiques pour BAC), enregistrer leurs rapports bruts, écrire un adaptateur vers le format de prédictions et demander au même oracle une confirmation réelle. Le code des détecteurs devra recevoir exclusivement le **manifeste public et les fichiers sources**, jamais `oracle.json` ou le manifeste de vérité `validation`.

Fixer un budget et la granularité de propriété identiques, compter FP/FN réels et séparer le temps de découverte du temps de preuve. Une fois ces baselines auditées, démarrer D1.2 : le premier moteur PRISM orienté propriétés, déterministe et sans LLM.

**Critère de passage** : aucun chiffre supérieur à une baseline réelle tant que D1.1 et D1.2 n'ont pas été exécutés à budget comparable, puis confrontés à un jeu indépendant gelé.

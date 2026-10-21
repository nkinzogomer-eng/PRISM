# SCM/PRISM Phase 4.3C — résultats mesurés et audit scientifique (21 octobre 2026)

**Décision :** PASS de l'intégrité technique étroitement définie ; **NO-GO pour toute revendication de supériorité SCM sur les approches conventionnelles**. Ne pas fusionner ou déployer. La phase générale 4 reste ouverte.

## Provenance et périmètre exact

- Branche expérimentale `research/phase-4-3c-property-sufficiency`, PR #17 (draft), empilée sur PR #16 (draft) ; les branches précédentes et `main` restent inchangées.
- [Première CI réussie à quatre bras (run 39640226343)](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39640226343) : 24/24 comparaisons de préservation passées. Ses temps Linux ont varié par rapport aux passages suivants ; ne pas mélanger des mesures issues de différentes exécutions.
- [CI réussie incluant le comparateur conventionnel indépendant (run 39640789602)](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39640789602) et [artefacts bruts](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39640789602/artifacts/12364632856).
- 14 tests adversariaux 4.3C + 14 tests incrémentaux 4.3B réussis. Le passage de comparaison a obtenu 32/32 égalités de résultats normalisés pour quatre modifications × deux répétitions × quatre politiques réutilisant des résultats face à un scan complet.
- Corpus OWASP Benchmark Python v0.1, 1 230 fichiers de développement, sources épinglées au commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` et manifeste d'octets Linux contrôlé par `source_inventory`.
- Analyseur unique Bandit 1.8.6 avec `-t B307` : appels directs à `eval`, avec directives `# nosec` interprétées par l'analyseur. **Aucun résultat ici n'est une conclusion sur les autres règles Bandit, sur Semgrep ou sur une vulnérabilité réellement exploitable.**
- Construction initiale séparée du cache B307 : **2,0243 s**, 26 alertes normalisées. Elle doit être amortie pour comparer des coûts sur plusieurs mises à jour.

## Chronométrage du comparatif le plus strict

Médianes **deux répétitions** en secondes. Chaque ligne est un benchmark avec exécution réelle de Bandit quand nécessaire. Les coûts incluent lecture des sources, modification synthétique en mémoire, vérification du changement (preuve ou comparaison AST), préparation, scan, normalisation/contrôle, fusion des alertes et nettoyage. N'inclut pas installation, réseau, sérialisation finale, consommation d'énergie ou coût matériel. Ce ne sont pas des chiffres robustes de production.

| Scénario | Scan complet | Cache fichier exact | Cache AST+directives | Différence conventionnelle en suffixe | Certificat SCM étiqueté |
|---|---:|---:|---:|---:|---:|
| 1 230 commentaires ajoutés | 2,0622 | 2,0698 | 1,7905 | 0,0198 | 0,0183 |
| 90 % commentaires, 10 % nouveaux appels eval | 2,0752 | 2,0692 | 2,1393 | 0,3372 | 0,3375 |
| 80 % commentaires, 10 % eval, 10 % eval avec nosec | 2,0926 | 2,0936 | 2,4044 | 0,5489 | 0,5538 |
| 123 lignes initiales ajoutées | 2,0778 | 0,3322 | 0,5219 | 0,3312 | 0,3329 |

- Dans le scénario des seuls commentaires, les 1 230 sources ont changé en octets, mais la modification entière est certifiée comme ajout de commentaire terminal prescrit. Le cache exact de fichiers refait 1 230 analyses ; les deux variantes en suffixe en font zéro. Un gain proche de **99 % face au scan complet** ne dépasse pourtant pas le contrôleur classique de suffixes.
- Scénario mixte : les deux variantes de suffixe analysent 123 modules modifiés par appels effectifs à `eval`, et réutilisent les 1 107 autres. 26 alertes B307 avant édition, **149 après** ; correspondances normalisées vérifiées. Gain du bras SCM `(2.0752-0.3375)/2.0752 = 83.7 %` contre le complet, mais aucun avantage sur le diff conventionnel (0,3372 s).
- Scénario adversarial : les deux variantes analysent 246 fichiers contenant des changements de code (dont `# nosec B307`), réutilisent les autres commentaires, et préservent les 149 alertes B307 normalisées du scanner complet. Gain SCM ~73,5 % contre le complet mais comparable au diff conventionnel.
- Décalages de lignes : les deux preuves de suffixe **refusent** la réutilisation des 123 modules modifiés ; elles n'améliorent pas la baseline exacte (toutes trois ~0,33 s). Le nombre de détections peut être identique tandis que les emplacements diffèrent ; l'égalité est établie sur identités normalisées.

## Qu'a-t-on appris ?

**Résultat positif très limité :** un certificat d'édition très local et un choix conditionnel de calcul peuvent être extrêmement peu coûteux par rapport à parser tous les fichiers. Conserver les preuves de provenance et les alertes vérifiées permet de ne recalculer que les cas où l'hypothèse d'inertie est refusée.

**Contre-exemple à la prétention de nouveauté :** le comparateur indépendant `conventional_suffix_diff` applique le même contrat de modification et obtient le même bénéfice. C'est une optimisation connue de type diff/incrémentalité. Les 0,1–5 ms de différence sont du bruit et ne justifient aucune revendication SCM.

**Problème restant :** nous avons construit des changements favorables (`# SCM43C-INERT-...`) artificiellement reconnus. Cette étude ne montre pas que SCM saurait *découvrir* les bonnes réductions sur un changement réel inconnu, ni battre un moteur incrémental établi, ni maintenir des résultats complets de SAST inter-fichier. Il ne faut pas confondre une optimisation spécialisée valide dans son contrat avec un paradigme de calcul nouveau.

**Sûreté du certificat :** l'ancien source doit avoir été scanné sans erreur, finir par une nouvelle ligne et rester un préfixe exact ; un seul commentaire terminal expressément autorisé est permis. Les autres modifications conduisent au scan complet du fichier ; aucune absence de vulnérabilité n'est certifiée. Malgré ces garanties de construction, la conservation des alertes d'un outil tiers n'est vérifiée qu'empiriquement sur ce programme, cette version et ces entrées ; un changement de la configuration ou du moteur invaliderait la réutilisation.

**Coût initial:** 2,0243 s pour la constitution du cache du passage à cinq bras ; sur une unique mise à jour, il peut annuler le gain apparent. Ne jamais le traiter comme nul.

## Décision sur la suite

- Garder la PR #17 en **draft**, aucun merge.
- Passer de l'étude d'un suffixe artificiellement favorable à une tâche plus discriminante : **changements réalistes touchant des fonctions**, conséquences vérifiables sur plusieurs propriétés, et sélection/invalidations conscientes des dépendances.
- Comparer impérativement des optimisations déjà connues : AST diff, caches de fonction/règle, analyse incrémentale native et filtrage par dépendances, avec une baseline de diff ayant accès aux mêmes modifications et informations.
- Seule une amélioration end-to-end **au-delà de ces baselines** à garanties égales, sur données gelées hors développement et après répétitions suffisantes, justifierait de parler de progrès distinctif SCM.
- Ne pas ouvrir le holdout indépendant avant gel de l'algorithme, de l'évaluateur et du protocole.

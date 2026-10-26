# PRISM D2.4I — pré-exécution locale de la cohorte préenregistrée

Date : 26 octobre 2026. Branche expérimentale D2.4I, Ciel et `main` intacts.

## Mesure constatée avant GitHub CI

- Entrée : manifeste `benchmarks/cyber/d24i/holdout_v1.json` gelant quatre
  versions de modules tiers (Click, Requests, HTTPX, Pydantic), sans sélection
  par CVE connue. Les sources viennent des révisions Git exactes indiquées.
- Python local : 3.12.14 ; un seul processus CPU, sans modèle externe ni GPU.
- 4 fichiers analysés ; **0 hypothèse source-dérivée** par les familles D2.4H ;
  par conséquent **0 vérification de flux réellement exercée sur ces quatre
  logiciels**. Pas d'omission de fichiers ; leur code n'a pas été exécuté.
- 0 témoin de flux modélisé et **0 vulnérabilité inédite confirmée**.
- CPU processus : **0,216968 s** ; temps mur : **0,217001 s** ; pic RSS du
  processus Linux : **21 448 KiB** (~20,9 MiB). Ces chiffres ne constituent
  pas une comparaison de coûts, une mesure de débit de détection ou une preuve
  de supériorité scientifique.
- 11/11 tests D2.4I et 28/28 tests D2.4H réussis localement. Les nouveaux
  tests utilisent des cas artificiels de flux commande/log, y compris un
  faux positif syntaxique désambiguïsé, et montrent l'abstention sur code
  non modélisé. Ils ne prouvent pas une vulnérabilité sur source tierce.

## Interprétation négative

Ce lot généraliste ne couvre presque aucun puits pertinent pour nos quatre
familles et les règles de compilation sont trop locales. Les gains de temps
constatés ne doivent PAS être interprétés comme une découverte efficace :
**aucune découverte n'a eu lieu**. Cette cohorte reste figée ; ajuster le
détecteur sur ces mêmes fichiers puis les qualifier de « holdout aveugle »
introduirait une fuite de données expérimentales.

## GO / NO-GO

- GO ingénierie local : interpréteur AST borné, tests et mesures fonctionnent.
- NO-GO scientifique : aucune classe inédite, aucune faille, aucune mesure de
  rappel ou de précision, aucun gain démontré sur fuzzing/analyse statique,
  aucune preuve économique de moindre coût.
- Étape nécessaire : cohorte stratifiée indépendante avec programmes qui
  exposent des opérations de sécurité, sans choisir leurs défauts ; oracles
  comportementaux reproductibles ; baselines sous budget identique ; examen
  du coût de génération et de vérification, pas seulement analyse syntaxique.

Les mesures CI suivantes peuvent varier selon la machine. Ne pas remplacer
les résultats locaux ni changer les cohortes pour produire un chiffre vert.

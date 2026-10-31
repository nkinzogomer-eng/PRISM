# Rapport de vérification — livraison 1 (conception)

**Date :** 2026-10-31 · **Machine :** 2 vCPU / 3 939 MB / Debian 12 · **Objet :** prouver que les livrables ①–⑧ sont cohérents et que les garde-fous refusent réellement.

Ce rapport ne contient aucune mesure de scénario : le laboratoire n'est pas construit, et c'est la conclusion assumée de cette livraison.

## 1. Capacité de l'hôte (sortie réelle)

```
5. Verdict
  supported tier             none                     fails at least one hard requirement (no usable container runtime) (RAM 3939 MB < 16000 MB) (vCPU 2 < 8) (disk 20 GB < 200 GB)
RANGE_TIER=none
  => design-only: this host cannot run layers L1-L7.
     Use it for authoring/validation of artefacts, and run the build on a Tier A+ host.
```

## 2. Vérification des artefacts (sortie réelle)

```
PRISM Cyber Range — artefact verification
--------------------------------------------------------------
  [PASS] A1 component ids unique — 36 components
  [PASS] A2 required fields present — all present
  [PASS] A3 layer vocabulary valid — L0-L7 only
  [PASS] A4 no source-available licences — clean
  [PASS] A5 unverified pins are justified — 3 flagged, 3 documented
  [PASS] A6 rejected components recorded — 5 entries
  [PASS] B1 service tiers valid — ok
  [PASS] B2 tier A RAM fits worst case — 8.1 GB of 14.0 usable (min 3.3 GB), 42 CPU shares vs 8 vCPU
  [PASS] B2 tier B RAM fits worst case — 14.1 GB of 29.0 usable (min 6.2 GB), 62 CPU shares vs 16 vCPU
  [PASS] B2 tier C RAM fits worst case — 21.9 GB of 58.0 usable (min 10.1 GB), 68 CPU shares vs 24 vCPU
  [PASS] C1 compose parses — 23 services
  [PASS] C2 k8s manifests parse — 4 files, 13 documents
  [PASS] D1 all base chains default-drop — policies=['drop', 'drop', 'drop']
  [PASS] D2 uplink restricted to explicit DNS/NTP exceptions — only inward DNS/NTP and the simulated WAN bridge
  [PASS] D3 simulated internet cannot initiate inward — explicit drop present
  [PASS] D4 every nftables zone is in the architecture doc — all six zones documented
  [PASS] E1 build substitutions enumerated — 0 outside the cosign key block (key block is filled by build.sh)
  [PASS] F1 no secrets committed — clean
  [PASS] G1 every locked component appears in the matrix — 36 components traced
  [PASS] H1 D2.5 artefacts still present — 3/3
  [PASS] H2 D2.5 artefacts unmodified by the range work — no modifications
  [PASS] H3 Alchemy target untouched (not present on this host) — skipped, nothing to check
  [PASS] H4 PRISM core has no range dependency — none
  [PASS] I1 scenario fields present — all present
  [PASS] I2 scenario catalogue populated — 8 scenario ids
  [PASS] I3 Binance chain covered end-to-end — S1..S5 map to the five chain steps
--------------------------------------------------------------
  26 passed, 0 failed
```

## 3. Refus des garde-fous (comportement attendu, vérifié)

| Commande | Code | Message |
| --- | --- | --- |
| `./range/scripts/build.sh` | 1 | BUILD REFUSED: --tier A|B|C is required |
| `./range/scripts/build.sh --tier A` | 1 | BUILD REFUSED: host cannot run the range (see /home/user/PRISM/range/state/logs/preflight-20261031T095528Z.log); design-only host |
| `./range/scripts/pin_images.sh` | 3 | PINNING IMPOSSIBLE: neither skopeo nor docker is available on this host. |
| `./range/scripts/materialize-secrets.sh` | 3 | materialize-secrets: sops not installed (see 05-installation.md §1.2) |

## 4. Non-régression D2.5

La piste SCM (53 tests) ne dépend pas du laboratoire et reste inchangée :

```
Ran 53 tests in 1.639s
OK (expected failures=1)
```

## 5. Conclusion

* Les huit livrables obligatoires existent et sont cohérents (26 contrôles) ;
* l'hôte de conception **ne peut pas** héberger le laboratoire : c'est mesuré, pas supposé ;
* aucun composant n'est installé, aucun scénario n'est exécuté, aucune mesure de sécurité n'est produite — conformément à la consigne « ne commence pas par construire un laboratoire gigantesque ».

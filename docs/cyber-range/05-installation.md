# 05 — Plan d'installation reproductible

**Version :** 1.0 — 2026-10-31
**Statut :** plan + scripts partiels. **Rien n'a été installé** : la machine de conception ne dispose ni de runtime de conteneurs ni des 16 GB requis (voir `01-inventaire.md`). Ce document décrit exactement ce qui sera exécuté sur l'hôte cible, dans l'ordre, avec les points de contrôle.

---

## 0. Règles non négociables

1. **Aucun `latest`.** Chaque image est référencée par version + digest ; chaque binaire par version + somme de contrôle.
2. **Aucun réseau réel.** Le laboratoire ne sort pas (invariant `I2`).
3. **Idempotence.** Chaque étape vérifie l'état avant d'agir ; deux exécutions successives ne diffèrent pas.
4. **Traçabilité.** Chaque étape écrit un journal horodaté UTC dans `range/state/logs/install-<étape>.log`.
5. **Retour arrière.** Chaque étape indique comment être annulée.

## 1. Préparation de l'hôte (L0)

```bash
# 1.1 Vérifier le palier supportable — échoue proprement si l'hôte est trop petit
./range/scripts/preflight.sh          # code 0 = Tier B+, 10 = Tier A, 20 = conception seule

# 1.2 Dépendances système (Debian 12+), versions consignées dans le journal
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  ca-certificates curl git jq nftables sqlite3 tcpdump tshark \
  age openssl python3 python3-venv
dpkg -l | grep -E 'nftables|tcpdump|openssl' > range/state/logs/install-10-system.log

# 1.3 Moteur de conteneurs (28.x/29.x épinglé)
#     Rootless Podman est l'alternative documentée si le modèle démon Docker est refusé.
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo tee /etc/apt/keyrings/docker.asc >/dev/null
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin
docker version > range/state/logs/install-11-docker.log

# 1.4 Isolation : appliquer la politique de zones AVANT de démarrer un service
sudo nft -f range/network/nftables-range.nft
sudo nft list table inet prism_range > range/state/logs/install-12-nft.log
```

**Point de contrôle 1 :** `nft list ruleset | grep -c drop` ≥ 3 et `curl -m 3 https://example.com` **échoue** depuis un conteneur de test. Si Internet répond, on s'arrête : l'invariant d'isolation n'est pas tenu.

## 2. Secrets et configuration (L0/L1)

```bash
# 2.1 Créer l'identité age (jamais dans git ; .sops.yaml référence la clé publique)
age-keygen -o ~/.config/prism-range/age.key && chmod 600 ~/.config/prism-range/age.key

# 2.2 Déposer les secrets chiffrés
sops --encrypt --in-place range/config/secrets.enc.yaml

# 2.3 Générer les fichiers de secrets montés dans les conteneurs
./range/scripts/materialize-secrets.sh      # écrit sous range/state/secrets/, mode 0400
```

**Point de contrôle 2 :** `git grep -nE 'BEGIN .*PRIVATE KEY|AGE-SECRET-KEY' -- range/` ne renvoie **rien** (le vérificateur `F1` le contrôle aussi en CI).

## 3. Épinglage des images

```bash
./range/scripts/pin_images.sh               # résout tag -> digest et met à jour versions.lock.json
git diff range/versions.lock.json           # revue obligatoire : c'est le verrou
```

**Règle :** un `git diff` non revu sur `versions.lock.json` invalide toute mesure produite ensuite. Le fichier est le seul endroit où un changement de version est autorisé.

## 4. Montée des couches (Tier A d'abord)

```bash
# Étape A — identité et PKI (L1)
docker compose -f range/compose/tier-a.yml up -d authelia step-ca openbao jump-ssh
./range/scripts/checks/check-l1.sh          # OIDC discovery, TOTP enroll, cert issuance, revoke

# Étape B — forge et CI (L3)
docker compose -f range/compose/tier-a.yml up -d postgres gitea woodpecker-server woodpecker-agent registry
./range/scripts/checks/check-l3.sh          # login, clone, pipeline, scan Trivy/gitleaks

# Étape C — services de transaction et signatures (L4)
docker compose -f range/compose/tier-a.yml up -d svc-transaction svc-wallet svc-signer softhsm2 opa
./range/scripts/checks/check-l4.sh          # PKCS#11 list-objects, decision OPA allow/deny, écriture en base

# Étape D — chaîne (L5) : la seule couche déjà prouvée
docker compose -f range/compose/tier-a.yml up -d anvil bundler-alto relayer
./range/scripts/checks/check-l5.sh          # tx minée, receipt, compte modulaire déployé, rejeu refusé

# Étape E — télémétrie (L6) puis forensique (L7)
docker compose -f range/compose/tier-a.yml up -d loki prometheus grafana alloy osquery tcpdump-wan
./range/scripts/checks/check-l6.sh          # une alerte de test génère un événement daté
```

**Point de contrôle 3 (fin Tier A) :** les huit scénarios S1, S2, S4, S5, S6 (volet jeton CI), S7, S8 s'exécutent ; S3 et le volet Kubernetes de S6 sont marqués « non applicables — Tier A ».

## 5. Montée Tier B (Kubernetes)

```bash
# k3s sans Traefik (le proxy du laboratoire est explicite), Cilium en remplacement du CNI par défaut
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=v1.37.1+k3s1 \
  sh -s - server --flannel-backend=none --disable-network-policy --disable=traefik --write-kubeconfig-mode 600

kubectl apply -f range/k8s/00-namespace.yaml
kubectl apply -f range/k8s/10-network-policy.yaml
kubectl apply -f range/k8s/20-kyverno-policies.yaml
kubectl apply -f range/k8s/30-fixture-rbac-misconfig.yaml    # fixture : état "avant"
./range/scripts/checks/check-l2.sh          # default-deny effectif, Kyverno Enforce, fixture présente
```

**Point de contrôle 4 :** un pod de test sans label dans `rg-prod` ne peut joindre **ni** le signer **ni** la chaîne (prouvé par trois `nc -zv` en échec), et sa création avec `hostNetwork: true` est refusée par Kyverno avec un message identifiable.

## 6. Ce que le script d'installation doit refuser de faire

| Refus | Motif |
| --- | --- |
| Démarrer si `preflight.sh` renvoie 20 | l'hôte ne peut pas porter le laboratoire |
| Continuer si un secret est présent en clair | fuite garantie dans les journaux du build |
| Puller une image sans digest résolu | non-reproductibilité |
| Appliquer nftables après les services | fenêtre d'exposition |
| Utiliser un `--fork-url` ou un RPC public | interdiction explicite |
| Écrire hors de `range/state/` | le dépôt reste propre |

## 7. Reproductibilité : critères mesurables

1. **Installation identique :** deux hôtes Debian 12 exécutant le plan produisent le même `versions.lock.json` (digests compris) — vérifié par `sha256sum`.
2. **Démarrage à froid :** `docker compose down -v && up -d` puis `check-l*.sh` en vert en ≤ 240 s sur Tier A.
3. **État de chaîne reproductible :** après `anvil_snapshot` puis `revert`, deux exécutions d'un même scénario donnent les mêmes hashes de transactions.
4. **Horloge :** tous les composants en UTC, une seule source NTP ; l'écart mesuré entre `mon` et `prod` doit être < 50 ms.

## 8. État des scripts et ce qui reste à écrire

**Déjà écrit et testé (garde-fous réels, refus vérifiés) :**

| Script | Comportement actuel | Preuve |
| --- | --- | --- |
| `range/scripts/preflight.sh` | mesure l'hôte, classe le palier, code de sortie 0/10/20, émet `RANGE_TIER=` | exécuté ici : `RANGE_TIER=none`, exit 20 |
| `range/scripts/build.sh` | refuse sans `--tier`, refuse un hôte de conception, refuse un artefact incohérent, refuse un secret en clair, refuse une image sans digest, refuse de démarrer sans nftables appliqué | 5 refus testés, chacun avec exit 1 et message précis |
| `range/scripts/pin_images.sh` | résout tag → digest (skopeo/docker) et n'écrit qu'avec `--write`, après revue | sur un hôte sans outil : exit 3, message explicite |
| `range/scripts/materialize-secrets.sh` | déchiffre SOPS vers `state/secrets/` en 0400 | sans `sops` : exit 3, message explicite |
| `range/scripts/verify_artifacts.py` | 26 contrôles de cohérence | 26/26 verts |

**Reste à écrire (livraisons suivantes) :**

* la logique de montée de couche dans `build.sh` (§1–§5 ci-dessus) ;
* les `checks/check-l1.sh` … `check-l7.sh`, un par couche, avec leurs critères de sortie ;
* les images locales `prism/range-*` (services L4/L5) et leurs tests.
* Les images locales `prism/range-*` (services L4/L5) : elles seront de petits services HTTP + clients PKCS#11, écrits pour exposer de vrais mécanismes, pas pour être vulnérables.
* Les fixtures de base de données (transactions fictives, soldes fictifs, marqués comme tels dans chaque enregistrement).

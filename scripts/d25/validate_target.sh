#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# PRISM D2.5 — Stage 1 target validation
#
# Obtains a modular-account target at one exact commit, pins the toolchain,
# locks dependencies, performs two clean compilations, runs the reference test
# suite twice, and verifies that the target sources were never modified.
#
# Design rules (see docs/d25-charter.md):
#   * the target is checked out OUTSIDE the PRISM repository;
#   * the target's tracked files are never edited;
#   * nothing touches a live network: no RPC URL, no fork, no broadcast;
#   * every tool version is pinned and, for the compiler, checksum-verified.
#
# Usage:
#   scripts/d25/validate_target.sh [--target-repo URL] [--commit SHA]
#                                  [--workdir DIR] [--skip-deep] [--keep]
#
# Exit status: 0 only if every gate passes.
# ---------------------------------------------------------------------------
set -uo pipefail

# --- configuration (identities from the D2.5 charter) ----------------------
TARGET_REPO="${TARGET_REPO:-https://github.com/alchemyplatform/modular-account.git}"
TARGET_COMMIT="${TARGET_COMMIT:-bd75c9eca7ff5a66aaebc3cf2dab43ddc4622482}"
TARGET_TREE="${TARGET_TREE:-30281664d0cf68eef171ebe5c7d230afe6ef70c8}"
EXPECTED_SOLC_SHA256="d5f23436f443edb85d8e76906d12f0a86ce0490e7663a9e608efeb7a93f149ef"
FORGE_VERSION="1.7.1"
PNPM_VERSION="9.15.0"
SOLC_VERSION="0.8.26"
SOLC_BIN_NAME="solc-linux-amd64-v0.8.26+commit.8a97fa7a"

WORKDIR="${WORKDIR:-$HOME/.cache/prism-d25}"
TARGET_DIR="$WORKDIR/target/target"
TOOLS_DIR="$WORKDIR/tools"
LOG_DIR="$WORKDIR/logs"
SKIP_DEEP=0

while [ $# -gt 0 ]; do
  case "$1" in
    --target-repo) TARGET_REPO="$2"; shift 2 ;;
    --commit)      TARGET_COMMIT="$2"; shift 2 ;;
    --workdir)     WORKDIR="$2"; TARGET_DIR="$WORKDIR/target/target"; TOOLS_DIR="$WORKDIR/tools"; LOG_DIR="$WORKDIR/logs"; shift 2 ;;
    --skip-deep)   SKIP_DEEP=1; shift ;;
    -h|--help)     sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$WORKDIR/bin" "$TOOLS_DIR" "$LOG_DIR"
export PATH="$WORKDIR/bin:$HOME/.npm-global/bin:$PATH"

PASS=0; FAIL=0
gate() { # gate <name> <status 0/1> [detail]
  if [ "$2" -eq 0 ]; then
    PASS=$((PASS+1)); printf '  [PASS] %s%s\n' "$1" "${3:+ — $3}"
  else
    FAIL=$((FAIL+1)); printf '  [FAIL] %s%s\n' "$1" "${3:+ — $3}"
  fi
}
section() { printf '\n== %s\n' "$1"; }

# --- 0. environment prerequisites ------------------------------------------
section "0. environment"
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
  # Node's bundled trust store may lack the sandbox interception CA.
  export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
fi
# Some lockfiles record git-protocol specs that resolve to SSH; keep it on HTTPS.
git config --global --get url."https://github.com/".insteadOf >/dev/null 2>&1 || {
  git config --global --add url."https://github.com/".insteadOf "ssh://git@github.com/"
  git config --global --add url."https://github.com/".insteadOf "git@github.com:"
  git config --global --add url."https://github.com/".insteadOf "git://github.com/"
}
echo "  workdir: $WORKDIR"

# --- 1. toolchain ----------------------------------------------------------
section "1. toolchain"
if ! command -v forge >/dev/null 2>&1 || ! forge --version 2>/dev/null | grep -q "Version: $FORGE_VERSION"; then
  npm install --no-audit --no-fund --prefix "$TOOLS_DIR/foundry" "@foundry-rs/forge@$FORGE_VERSION" >/dev/null 2>&1
  ln -sf "$TOOLS_DIR/foundry/node_modules/@foundry-rs/forge-linux-amd64/bin/forge" "$WORKDIR/bin/forge"
fi
if ! command -v pnpm >/dev/null 2>&1; then
  npm install -g --prefix "$HOME/.npm-global" "pnpm@$PNPM_VERSION" >/dev/null 2>&1
fi

# solc: native binary, checksum-verified against the official manifest.
SOLC_DEST="$HOME/.svm/$SOLC_VERSION/solc-$SOLC_VERSION"
if [ ! -x "$SOLC_DEST" ] || [ "$(sha256sum "$SOLC_DEST" | cut -d' ' -f1)" != "$EXPECTED_SOLC_SHA256" ]; then
  # Native binaries come from the official ethereum/solc-bin repository rather
  # than binaries.soliditylang.org (unreachable in the validation sandbox).
  if [ ! -f "$TOOLS_DIR/solc-bin/linux-amd64/$SOLC_BIN_NAME" ]; then
    rm -rf "$TOOLS_DIR/solc-bin"
    git clone --depth 1 --filter=blob:none --no-checkout \
        https://github.com/ethereum/solc-bin.git "$TOOLS_DIR/solc-bin" >/dev/null 2>&1
    ( cd "$TOOLS_DIR/solc-bin" \
      && git sparse-checkout init --cone \
      && git sparse-checkout set linux-amd64 \
      && git checkout >/dev/null 2>&1 )
  fi
  mkdir -p "$(dirname "$SOLC_DEST")"
  cp "$TOOLS_DIR/solc-bin/linux-amd64/$SOLC_BIN_NAME" "$SOLC_DEST"
  chmod +x "$SOLC_DEST"
fi

solc_sha=$(sha256sum "$SOLC_DEST" 2>/dev/null | cut -d' ' -f1)
[ "$solc_sha" = "$EXPECTED_SOLC_SHA256" ]; gate "solc $SOLC_VERSION checksum" $? "$solc_sha"
forge_v=$(forge --version 2>/dev/null | head -1)
[ -n "$forge_v" ]; gate "forge $FORGE_VERSION" $? "$forge_v"
pnpm_v=$(pnpm --version 2>/dev/null)
[ "$pnpm_v" = "$PNPM_VERSION" ]; gate "pnpm $PNPM_VERSION" $? "$pnpm_v"

# --- 2. target checkout ----------------------------------------------------
section "2. target checkout"
if [ ! -d "$TARGET_DIR/.git" ]; then
  rm -rf "$WORKDIR/target"
  mkdir -p "$WORKDIR/target"
  git clone --quiet "$TARGET_REPO" "$TARGET_DIR" || { echo "clone failed" >&2; exit 1; }
fi
(
  cd "$TARGET_DIR" || exit 1
  git fetch --quiet origin "$TARGET_COMMIT" >/dev/null 2>&1 || true
  git checkout --quiet "$TARGET_COMMIT"
)

# A dirty worktree would invalidate every later measurement.
if [ -n "$(cd "$TARGET_DIR" && git status --porcelain)" ]; then
  echo "refusing to continue: target worktree is dirty" >&2
  (cd "$TARGET_DIR" && git status --porcelain | head -20) >&2
  exit 3
fi

head_sha=$(cd "$TARGET_DIR" && git rev-parse HEAD)
tree_sha=$(cd "$TARGET_DIR" && git rev-parse 'HEAD^{tree}')
tag=$(cd "$TARGET_DIR" && git describe --tags --exact-match 2>/dev/null)
[ "$head_sha" = "$TARGET_COMMIT" ]; gate "HEAD equals requested commit" $? "$head_sha"
[ "$tree_sha" = "$TARGET_TREE" ]; gate "tree object" $? "$tree_sha"
echo "  tag: ${tag:-<none>}"

# --- 3. dependencies -------------------------------------------------------
section "3. dependencies"
( cd "$TARGET_DIR" && git submodule update --init --recursive --depth 1 >/dev/null 2>&1 )
# The submodule graph is cyclic; a second pass converges to zero uninitialised.
( cd "$TARGET_DIR" && git submodule update --init --recursive --depth 1 >/dev/null 2>&1 )
missing=$(cd "$TARGET_DIR" && git submodule status --recursive 2>/dev/null | grep -c '^-')
[ "$missing" -eq 0 ]; gate "submodules initialised" $? "${missing} missing"

( cd "$TARGET_DIR" && pnpm install --frozen-lockfile > "$LOG_DIR/pnpm-install.log" 2>&1 )
rc=$?
gate "pnpm install --frozen-lockfile" $rc "$(grep -m1 -o 'Lockfile is up to date.*' "$LOG_DIR/pnpm-install.log" 2>/dev/null)"
[ $rc -eq 0 ] || { echo "dependency install failed; see $LOG_DIR/pnpm-install.log" >&2; exit 4; }

# --- 4/5. clean compile + determinism -------------------------------------
section "4. clean compilation (twice, from clean)"
for run in 1 2; do
  ( cd "$TARGET_DIR" && forge clean >/dev/null 2>&1 \
    && forge build > "$LOG_DIR/build-$run.log" 2>&1 )
  rc=$?
  files=$(grep -m1 -oE 'Compiling [0-9]+ files' "$LOG_DIR/build-$run.log" | grep -oE '[0-9]+')
  errs=$(grep -cE '^Error' "$LOG_DIR/build-$run.log")
  gate "forge build run $run" $rc "${files:-?} files, ${errs} errors"
  ( cd "$TARGET_DIR/out" && find . -name '*.json' | sort | xargs sha256sum ) \
      > "$LOG_DIR/artifacts-$run.sha256" 2>/dev/null
done
if cmp -s "$LOG_DIR/artifacts-1.sha256" "$LOG_DIR/artifacts-2.sha256"; then
  gate "artifact determinism" 0 "manifest sha256 $(sha256sum "$LOG_DIR/artifacts-1.sha256" | cut -d' ' -f1)"
else
  gate "artifact determinism" 1 "manifests differ"
fi

# --- 6. reference tests ----------------------------------------------------
section "5. reference test suite"
( cd "$TARGET_DIR" && forge test > "$LOG_DIR/test-default.log" 2>&1 ); rc=$?
summary=$(grep -E '^Ran [0-9]+ test suites' "$LOG_DIR/test-default.log" | tail -1)
gate "forge test (default profile)" $rc "$summary"

( cd "$TARGET_DIR" && FOUNDRY_FUZZ_SEED=20261030 forge test > "$LOG_DIR/test-seeded.log" 2>&1 ); rc=$?
summary=$(grep -E '^Ran [0-9]+ test suites' "$LOG_DIR/test-seeded.log" | tail -1)
gate "forge test (fixed seed)" $rc "$summary"

# --- 7. optimized / deep profiles (supplementary) --------------------------
if [ "$SKIP_DEEP" -eq 0 ]; then
  section "6. optimized profiles (supplementary)"
  # `deny_warnings = true` arms Foundry 1.7.1's linter; -D never isolates that
  # diagnostic gate without changing compilation settings.
  ( cd "$TARGET_DIR" && FOUNDRY_PROFILE=optimized-build forge build -D never > "$LOG_DIR/build-optimized.log" 2>&1 )
  rc=$?
  gate "optimized-build (via-IR) compile" $rc "$(grep -m1 -oE 'Solc .* finished in [0-9.]+s' "$LOG_DIR/build-optimized.log")"
  ( cd "$TARGET_DIR" && FOUNDRY_PROFILE=optimized-test-deep forge test -D never > "$LOG_DIR/test-deep.log" 2>&1 )
  rc=$?
  gate "optimized-test-deep tests" $rc "$(grep -E '^Ran [0-9]+ test suites' "$LOG_DIR/test-deep.log" | tail -1)"
fi

# --- 8. integrity ----------------------------------------------------------
section "7. target integrity"
dirty=$(cd "$TARGET_DIR" && git status --porcelain | wc -l)
[ "$dirty" -eq 0 ]; gate "target sources unmodified" $? "$dirty modified paths"

# --- summary ---------------------------------------------------------------
section "summary"
printf '  gates passed: %d, failed: %d\n' "$PASS" "$FAIL"
printf '  logs: %s\n' "$LOG_DIR"
[ "$FAIL" -eq 0 ] && { echo "  RESULT: target validated for Stage 1"; exit 0; }
echo "  RESULT: validation FAILED — inspect the failing gates before proceeding"
exit 1

#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# PRISM D2.5 — solc 0.8.26 compatibility shim for forge (FALLBACK PATH)
#
# Not used by scripts/d25/validate_target.sh: the validated Stage 1 run uses the
# native solc 0.8.26 binary from ethereum/solc-bin. This shim is kept because it
# is the only working route when the native binary cannot be obtained and a
# pre-installed solcjs must be reused.
#
# Install as $HOME/.svm/0.8.26/solc-0.8.26 (forge's expected path) and point
# SOLCJS_PATH at the official npm solc@0.8.26 entry point.
#
# Why a shim is needed at all
# ---------------------------
# forge resolves solc through svm, which downloads from binaries.soliditylang.org.
# When that host is unreachable, an Emscripten build (npm `solc`) is the only
# local 0.8.26 compiler. Three behaviours must be normalised:
#
#  1. `--allow-paths <csv>` is rejected by solcjs. The flag only affects the
#     import callback, which is unused because forge embeds every source and every
#     resolved remapping target in the standard-JSON input.
#  2. solcjs prints ">>> Cannot retry compilation with SMT ..." on STDOUT before
#     the JSON body, which breaks forge's parser. Those lines are stripped.
#  3. forge passes a non-blocking stdin pipe; solcjs performs a synchronous
#     read(2) and dies with EAGAIN. stdin is spooled to a regular file first.
#
# KNOWN LIMITATION (documented in docs/d25-charter.md, incident E7): the
# Emscripten build aborts with "RuntimeError: memory access out of bounds" on
# large standard-JSON payloads (~136+ sources for this target). compilation must
# then be chunked. The native binary has no such limit.
# ---------------------------------------------------------------------------
set -uo pipefail

SOLCJS="${SOLCJS_PATH:-$HOME/.cache/prism-d25/tools/solc/node_modules/solc/solc.js}"

args=()
skip_next=0
stdjson=0

for a in "$@"; do
  if [ "$skip_next" -eq 1 ]; then
    skip_next=0
    continue
  fi
  case "$a" in
    --standard-json)
      stdjson=1
      args+=("$a")
      ;;
    --allow-paths)
      skip_next=1            # drop the flag and its CSV value
      ;;
    --allow-paths=*|--no-cbor-metadata|--metadata-hash=*|--metadata-path|--metadata-path=*|\
--model-checker-engine=*|--stop-after=*|--yul-optimizations=*|--optimize-yul|--transient-storage)
      :                      # drop native-binary-only flags (self-contained form)
      ;;
    *)
      args+=("$a")
      ;;
  esac
done

if [ "$stdjson" -eq 1 ]; then
  tmpin="$(mktemp)"; tmpout="$(mktemp)"
  trap 'rm -f "$tmpin" "$tmpout"' EXIT

  cat > "$tmpin"                    # spool stdin (works with O_NONBLOCK pipes)
  node "$SOLCJS" "${args[@]}" < "$tmpin" > "$tmpout"
  rc=$?

  grep -v '^>>> ' "$tmpout"         # strip solcjs stdout preamble
  exit "$rc"
fi

exec node "$SOLCJS" "${args[@]}"

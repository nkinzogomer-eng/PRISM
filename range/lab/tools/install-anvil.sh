#!/usr/bin/env bash
# Install the pinned Anvil node used as the range's chain, inside the repo's
# ignored state directory (no global install, no sudo).
#
#   ./range/lab/tools/install-anvil.sh
#
# Pin: @foundry-rs/anvil 1.7.1 (same major as the Foundry 1.8.7 used elsewhere,
# kept at 1.7.1 for comparability with the frozen D2.5 artefacts).
set -euo pipefail
VERSION="${ANVIL_VERSION:-1.7.1}"
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="${RANGE_STATE_DIR:-$HERE/../../state}"
DEST="$STATE/tools/anvil"
mkdir -p "$STATE/tools"
if [ -x "$DEST" ] && "$DEST" --version 2>/dev/null | grep -q "$VERSION"; then
  echo "anvil $VERSION already installed at $DEST"; exit 0
fi
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "installing @foundry-rs/anvil@$VERSION ..."
npm install --silent --prefix "$TMP" "@foundry-rs/anvil@$VERSION" >/dev/null
cp "$TMP/node_modules/@foundry-rs/anvil-linux-amd64/bin/anvil" "$DEST"
chmod +x "$DEST"
"$DEST" --version | head -1
echo "installed: $DEST"

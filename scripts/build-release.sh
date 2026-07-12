#!/usr/bin/env bash
# Build a release tarball (+ SHA-256) that bootstrap.sh downloads and installs.
# The archive contains a single top-level linkmoth-<version>/ directory holding
# exactly the files produced by build-dist.sh.
#
# Usage: scripts/build-release.sh <version>     e.g. scripts/build-release.sh v0.1.0
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: $0 <version>" >&2; exit 2; }

bash "$ROOT/scripts/build-dist.sh"

OUT="$ROOT/dist-release"
NAME="linkmoth-$VERSION"
case "$OUT" in
  "$ROOT/dist-release") ;;
  *) echo "refusing unsafe output path: $OUT" >&2; exit 1 ;;
esac

rm -rf -- "$OUT"
mkdir -p "$OUT/$NAME"
cp -a "$ROOT/dist/." "$OUT/$NAME/"

cd "$OUT"
# Deterministic tarball so the published checksum is reproducible.
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@0" \
    -czf "$NAME.tar.gz" "$NAME"

if command -v sha256sum >/dev/null; then
  sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256"
else
  shasum -a 256 "$NAME.tar.gz" > "$NAME.tar.gz.sha256"
fi

echo "built $OUT/$NAME.tar.gz"
cat "$OUT/$NAME.tar.gz.sha256"

# The bootstrap is a separate, versioned release asset.  It is signed alongside
# the archive by the release workflow; users verify it before running as root.
cp "$ROOT/bootstrap.sh" "$OUT/$NAME-bootstrap.sh"
echo "built $OUT/$NAME-bootstrap.sh"

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
python3 - "$VERSION" <<'PY' || { echo "version must be a semantic version such as v1.2.3" >&2; exit 2; }
import re, sys
raise SystemExit(not bool(re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", sys.argv[1])))
PY

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
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
python3 - "$OUT/$NAME/linkmoth-build.json" "$VERSION" "$COMMIT" <<'PY'
import json, sys
path, version, commit = sys.argv[1:]
with open(path, "w", encoding="utf-8") as f:
    json.dump({"schema": 1, "version": version, "release_commit": commit}, f, sort_keys=True)
    f.write("\n")
PY

# This signed inventory binds the archive layout and every installable byte.
python3 "$ROOT/scripts/generate-sbom.py" --root "$OUT/$NAME" --version "$VERSION" \
  --output "$OUT/$NAME.spdx.json"
python3 - "$OUT/$NAME" "$OUT/$NAME.manifest.json" <<'PY'
import hashlib, json, os, stat, sys
root, output = sys.argv[1:]
entries = []
for base, dirs, files in os.walk(root):
    dirs.sort(); files.sort()
    for name in files:
        path = os.path.join(base, name)
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        mode = stat.S_IMODE(os.stat(path).st_mode)
        digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
        entries.append({"path": rel, "mode": mode, "size": os.path.getsize(path), "sha256": digest})
with open(output, "w", encoding="utf-8") as handle:
    json.dump({"version": os.path.basename(root).removeprefix("linkmoth-"), "files": entries}, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY

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
sed "s/@LINKMOTH_VERSION@/$VERSION/g" "$ROOT/bootstrap.sh" > "$OUT/$NAME-bootstrap.sh"
chmod 755 "$OUT/$NAME-bootstrap.sh"
echo "built $OUT/$NAME-bootstrap.sh"

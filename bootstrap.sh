#!/usr/bin/env bash
# Linkmoth verified release bootstrap installer.
#
# Downloads a versioned Linkmoth release archive from GitHub Releases, verifies
# its SHA-256 checksum, extracts it, and runs the full install.sh from inside.
#
# Download this versioned file from a GitHub Release, verify its Sigstore
# bundle as described in README.md, then run it locally:
#   sudo bash linkmoth-v0.1.0-bootstrap.sh
#
# Environment overrides:
#   LINKMOTH_REPO     owner/repo to fetch releases from   (default: benukas/linkmoth)
#   LINKMOTH_VERSION  release tag to install, e.g. v0.1.0 (default: latest)
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV PYTHONPATH PYTHONHOME

REPO="${LINKMOTH_REPO:-benukas/linkmoth}"
VERSION="${LINKMOTH_VERSION:-latest}"

die() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: sudo bash linkmoth-<version>-bootstrap.sh"
command -v curl >/dev/null || die "curl is required"
command -v tar  >/dev/null || die "tar is required"
command -v sha256sum >/dev/null || command -v shasum >/dev/null \
  || die "sha256sum or shasum is required"
command -v cosign >/dev/null || die "cosign is required to verify a Linkmoth release"

# Linkmoth is pure Python, so a single architecture-independent archive serves
# every target (Raspberry Pi / ARM, x86 mini PCs, ...). There is deliberately
# no per-CPU download to pick here.

if [ "$VERSION" = latest ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  [ -n "$VERSION" ] || die "could not determine the latest release tag for $REPO"
fi

ASSET="linkmoth-$VERSION.tar.gz"
BASE="https://github.com/$REPO/releases/download/$VERSION"
IDENTITY="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$VERSION"
ISSUER="https://token.actions.githubusercontent.com"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

echo "downloading $ASSET ($REPO $VERSION)..."
curl -fSL -o "$ASSET"        "$BASE/$ASSET"        || die "download failed: $BASE/$ASSET"
curl -fSL -o "$ASSET.sha256" "$BASE/$ASSET.sha256" || die "checksum download failed: $BASE/$ASSET.sha256"
curl -fSL -o "$ASSET.bundle" "$BASE/$ASSET.bundle" || die "signature bundle download failed: $BASE/$ASSET.bundle"
curl -fSL -o "$ASSET.sha256.bundle" "$BASE/$ASSET.sha256.bundle" || die "checksum signature bundle download failed"

echo "verifying Sigstore signatures..."
cosign verify-blob --bundle "$ASSET.bundle" \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" \
  "$ASSET" >/dev/null || die "archive signature verification failed"
cosign verify-blob --bundle "$ASSET.sha256.bundle" \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" \
  "$ASSET.sha256" >/dev/null || die "checksum signature verification failed"

echo "verifying SHA-256 checksum..."
EXPECTED="$(awk '{print $1}' "$ASSET.sha256" | head -n1)"
[ -n "$EXPECTED" ] || die "malformed checksum file"
if command -v sha256sum >/dev/null; then
  ACTUAL="$(sha256sum "$ASSET" | awk '{print $1}')"
else
  ACTUAL="$(shasum -a 256 "$ASSET" | awk '{print $1}')"
fi
[ "$EXPECTED" = "$ACTUAL" ] \
  || die "checksum mismatch (expected $EXPECTED, got $ACTUAL) - refusing to install"
echo "checksum OK"

echo "extracting..."
tar -xzf "$ASSET"
DIR="$(tar -tzf "$ASSET" | head -n1 | cut -d/ -f1)"
[ -n "$DIR" ] && [ -d "$DIR" ] || die "unexpected archive layout"
[ -f "$DIR/install.sh" ] || die "install.sh not found in downloaded archive"

echo "running installer..."
cd "$DIR"
exec bash install.sh "$@"

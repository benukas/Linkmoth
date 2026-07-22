#!/usr/bin/env bash
# Linkmoth versioned release bootstrap installer. This file is generated during
# release construction; do not run the repository copy directly.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV PYTHONPATH PYTHONHOME LINKMOTH_REPO LINKMOTH_VERSION
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY no_proxy

OFFICIAL_REPO="benukas/Linkmoth"
RELEASE_VERSION="@LINKMOTH_VERSION@"

die() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: sudo bash linkmoth-<version>-bootstrap.sh"
command -v curl >/dev/null || die "curl is required"
command -v python3 >/dev/null || die "python3 is required"
python3 - "$RELEASE_VERSION" <<'PY' || die "use a generated bootstrap with a strict semantic release version"
import re, sys
raise SystemExit(not bool(re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", sys.argv[1])))
PY

VERIFY_SIGSTORE=0
INSTALL_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --sigstore-verified)
      VERIFY_SIGSTORE=1
      shift
      ;;
    --insecure-skip-verify|--allow-repository-override)
      die "$1 is not supported; checksum verification and the official repository are mandatory"
      ;;
    *)
      INSTALL_ARGS+=("$1")
      shift
      ;;
  esac
done
if [ "$VERIFY_SIGSTORE" -eq 1 ]; then
  command -v cosign >/dev/null || die "cosign is required only for --sigstore-verified"
fi

ASSET="linkmoth-$RELEASE_VERSION.tar.gz"
MANIFEST="linkmoth-$RELEASE_VERSION.manifest.json"
BASE="https://github.com/$OFFICIAL_REPO/releases/download/$RELEASE_VERSION"
IDENTITY="https://github.com/$OFFICIAL_REPO/.github/workflows/release.yml@refs/tags/$RELEASE_VERSION"
ISSUER="https://token.actions.githubusercontent.com"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
cd "$TMP"

download() {
  local output="$1" source="$2" response status redirect target second_status
  local partial="$1.part"
  [ "$source" = "$BASE/$output" ] || {
    echo "ERROR: refusing unexpected release asset source: $source" >&2
    return 1
  }
  rm -f -- "$partial"
  response="$(curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --noproxy '*' --retry 3 --connect-timeout 10 --max-time 300 \
    --output "$partial" --write-out $'%{http_code}\n%{redirect_url}' "$source")" || {
      rm -f -- "$partial"
      return 1
    }
  status="${response%%$'\n'*}"
  redirect="${response#*$'\n'}"
  case "$status" in
    200) target="$source" ;;
    301|302|303|307|308)
      target="$redirect"
      rm -f -- "$partial"
      python3 - "$source" "$target" <<'PY' || return 1
import sys
from urllib.parse import urlsplit

source, target = sys.argv[1:]
origin = urlsplit(source)
redirect = urlsplit(target)
if (origin.scheme != "https" or origin.hostname != "github.com"
        or origin.port not in (None, 443) or origin.username or origin.password
        or origin.fragment):
    raise SystemExit("ERROR: unexpected release source location")
if (redirect.scheme != "https"
        or redirect.hostname != "release-assets.githubusercontent.com"
        or redirect.port not in (None, 443)
        or redirect.username or redirect.password or redirect.fragment
        or not redirect.path.startswith("/github-production-release-asset/")):
    raise SystemExit("ERROR: release asset redirected to an unexpected location")
PY
      second_status="$(curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
        --noproxy '*' --retry 3 --connect-timeout 10 --max-time 300 \
        --output "$partial" --write-out '%{http_code}' "$target")" || {
          rm -f -- "$partial"
          return 1
        }
      [ "$second_status" = 200 ] || {
        rm -f -- "$partial"
        return 1
      }
      ;;
    *)
      rm -f -- "$partial"
      return 1
      ;;
  esac
  mv -- "$partial" "$output"
}
echo "downloading $ASSET ($OFFICIAL_REPO $RELEASE_VERSION)..."
download "$ASSET" "$BASE/$ASSET" || die "archive download failed"
download "$ASSET.sha256" "$BASE/$ASSET.sha256" || die "checksum download failed"
download "$MANIFEST" "$BASE/$MANIFEST" || die "manifest download failed"
if [ "$VERIFY_SIGSTORE" -eq 1 ]; then
  download "$ASSET.bundle" "$BASE/$ASSET.bundle" || die "archive signature bundle download failed"
  download "$ASSET.sha256.bundle" "$BASE/$ASSET.sha256.bundle" || die "checksum signature bundle download failed"
  download "$MANIFEST.bundle" "$BASE/$MANIFEST.bundle" || die "manifest signature bundle download failed"
  echo "verifying Sigstore publisher identity and signatures..."
  for file in "$ASSET" "$ASSET.sha256" "$MANIFEST"; do
    cosign verify-blob --bundle "$file.bundle" --certificate-identity "$IDENTITY" \
      --certificate-oidc-issuer "$ISSUER" "$file" >/dev/null || die "signature verification failed: $file"
  done
else
  echo "checking the published release checksum..."
fi

EXPECTED="$(python3 - "$ASSET.sha256" "$ASSET" <<'PY'
import hashlib, os, re, sys

checksum_path, expected_name = sys.argv[1:]
try:
    if os.path.getsize(checksum_path) > 4096:
        raise ValueError("checksum file is too large")
    text = open(checksum_path, "rb").read().decode("ascii")
except (OSError, UnicodeDecodeError, ValueError) as exc:
    raise SystemExit("ERROR: malformed checksum file: " + str(exc))
lines = text.splitlines()
if len(lines) != 1:
    raise SystemExit("ERROR: checksum file must contain exactly one entry")
match = re.fullmatch(r"([0-9A-Fa-f]{64})[ \t]+\*?([^\s]+)", lines[0])
if not match or match.group(2) != expected_name:
    raise SystemExit("ERROR: checksum file does not name the exact release archive")
expected = match.group(1).lower()
try:
    digest = hashlib.sha256()
    with open(expected_name, "rb") as archive:
        for chunk in iter(lambda: archive.read(1024 * 1024), b""):
            digest.update(chunk)
except OSError as exc:
    raise SystemExit("ERROR: archive could not be read: " + str(exc))
if digest.hexdigest() != expected:
    raise SystemExit("ERROR: archive checksum mismatch")
print(expected)
PY
)" || die "archive checksum verification failed"

echo "validating complete archive before extraction..."
python3 - "$ASSET" "$MANIFEST" "$RELEASE_VERSION" "$TMP/extracted" <<'PY'
import hashlib, json, os, posixpath, stat, sys, tarfile

archive, manifest_path, version, destination = sys.argv[1:]
root = "linkmoth-" + version
def fail(message): raise SystemExit("ERROR: unsafe release archive: " + message)
try:
    manifest = json.load(open(manifest_path, encoding="utf-8"))
except (OSError, ValueError) as exc: fail("invalid manifest: " + str(exc))
if manifest.get("version") != version or not isinstance(manifest.get("files"), list): fail("manifest version or file list is invalid")
expected = {}
for item in manifest["files"]:
    if not isinstance(item, dict): fail("manifest entry is invalid")
    path, mode, size, digest = (item.get(k) for k in ("path", "mode", "size", "sha256"))
    if not isinstance(path, str) or not path or path.startswith("/") or ".." in path.split("/") or "\\" in path: fail("unsafe manifest path")
    if path in expected or not isinstance(mode, int) or mode & 0o022 or not isinstance(size, int) or size < 0 or not isinstance(digest, str) or len(digest) != 64: fail("invalid manifest metadata")
    expected[path] = (mode, size, digest)
if not expected: fail("manifest has no files")
try:
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()  # force a full archive scan before writing anything
        names = set()
        actual = {}
        for member in members:
            name = member.name.rstrip("/")
            if not name or name in names or name.startswith("/") or ".." in name.split("/") or "\\" in name: fail("unsafe or duplicate member name")
            names.add(name)
            if name == root:
                if not member.isdir(): fail("top-level member is not a directory")
                continue
            prefix = root + "/"
            if not name.startswith(prefix): fail("unexpected top-level directory")
            relative = name[len(prefix):]
            if member.isdir():
                if member.mode & 0o022: fail("unsafe directory mode")
                continue
            if not member.isreg(): fail("links, devices, FIFOs, and special files are not permitted")
            if relative not in expected or member.mode != expected[relative][0] or member.size != expected[relative][1] or member.mode & 0o022: fail("member does not match manifest")
            handle = tar.extractfile(member)
            if handle is None: fail("unreadable archive member")
            digest = hashlib.sha256(handle.read()).hexdigest()
            if digest != expected[relative][2]: fail("member digest does not match manifest")
            actual[relative] = True
        if set(actual) != set(expected): fail("archive and manifest file sets differ")
        os.mkdir(destination, 0o700)
        if hasattr(tarfile, "data_filter"):
            tar.extractall(destination, members=members, filter="data")
        else:
            # Manifest, path, type, mode, size, and digest validation above
            # already rejects unsafe archive contents on interpreters without
            # native extraction-filter support (pre-3.9.17/3.10.12/3.11.4).
            tar.extractall(destination, members=members)
except (OSError, tarfile.TarError) as exc: fail(str(exc))
installed = os.path.join(destination, root)
if not os.path.isfile(os.path.join(installed, "install.sh")): fail("install.sh is missing")
PY

echo "running installer..."
cd "$TMP/extracted/linkmoth-$RELEASE_VERSION"
bash install.sh "${INSTALL_ARGS[@]}"
VERIFICATION="checksum-verified"
[ "$VERIFY_SIGSTORE" -eq 1 ] && VERIFICATION="sigstore-verified"
python3 - "/etc/linkmoth" "linkmoth-build.json" "$RELEASE_VERSION" "$EXPECTED" "$VERIFICATION" <<'PY'
import json, os, re, stat, sys, tempfile, time
etc, metadata_path, version, archive_sha256, verification = sys.argv[1:]
try:
    metadata = json.load(open(metadata_path, encoding="utf-8"))
    commit = metadata["release_commit"]
    if metadata.get("schema") != 1 or metadata.get("version") != version or not re.fullmatch(r"[0-9a-f]{40}", str(commit)): raise ValueError
except (OSError, ValueError, KeyError): raise SystemExit("ERROR: invalid release build metadata")
os.makedirs(etc, mode=0o750, exist_ok=True)
etc_stat = os.lstat(etc)
if (stat.S_ISLNK(etc_stat.st_mode) or not stat.S_ISDIR(etc_stat.st_mode)
        or etc_stat.st_uid != 0 or etc_stat.st_mode & 0o022):
    raise SystemExit("ERROR: unsafe installation record directory")
path = os.path.join(etc, "installation.json")
try:
    st = os.lstat(path)
    if stat.S_ISDIR(st.st_mode): raise SystemExit("ERROR: installation record path is a directory")
except FileNotFoundError: pass
if verification not in {"checksum-verified", "sigstore-verified"}:
    raise SystemExit("ERROR: invalid installation verification state")
try:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise SystemExit("ERROR: installation record is not a regular file")
except FileNotFoundError: pass
record = {"schema": 1, "version": version, "release_commit": commit, "archive_sha256": archive_sha256.lower(), "verification": verification, "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
fd, tmp = tempfile.mkstemp(prefix=".installation-", dir=etc)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(record, f, sort_keys=True); f.write("\n"); f.flush(); os.fsync(f.fileno())
os.chown(tmp, 0, 0); os.chmod(tmp, 0o644); os.replace(tmp, path)
directory_fd = os.open(etc, os.O_RDONLY | os.O_DIRECTORY)
try: os.fsync(directory_fd)
finally: os.close(directory_fd)
PY
if [ "$VERIFY_SIGSTORE" -eq 1 ]; then
  echo "installation provenance: Sigstore-verified release"
else
  echo "installation provenance: Checksum-verified release"
fi

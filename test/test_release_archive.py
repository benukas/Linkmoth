"""Regression tests for the signed release archive format."""
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def validator_script():
    text = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
    start = text.index("import hashlib, json, os, posixpath, stat, sys, tarfile")
    end = text.index("\nPY\n\necho \"running installer", start)
    return text[start:end]


def checksum_validator_script():
    text = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
    start = text.index("import hashlib, os, re, sys")
    end = text.index("\nPY\n)\" || die \"archive checksum verification failed\"", start)
    return text[start:end]


def redirect_validator_script():
    text = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
    start = text.index("import sys\nfrom urllib.parse import urlsplit")
    end = text.index("\nPY\n      second_status=", start)
    return text[start:end]


def sigstore_verification_block():
    text = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
    start = text.index('  for file in "$ASSET" "$ASSET.sha256" "$MANIFEST"; do')
    end = text.index("\n  done", start) + len("\n  done")
    return text[start:end]


class ReleaseArchiveTests(unittest.TestCase):
    def make_archive(self, mutate=None):
        temp = tempfile.TemporaryDirectory()
        base = Path(temp.name)
        root = "linkmoth-v1.2.3"
        payload = b"#!/bin/sh\n"
        entry = {"path": "install.sh", "mode": 0o755, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        manifest = {"version": "v1.2.3", "files": [entry]}
        (base / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        archive = base / "release.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            directory = tarfile.TarInfo(root); directory.type = tarfile.DIRTYPE; directory.mode = 0o755; tar.addfile(directory)
            info = tarfile.TarInfo(root + "/install.sh"); info.mode = 0o755; info.size = len(payload)
            import io
            tar.addfile(info, io.BytesIO(payload))
            if mutate: mutate(tar, root)
        return temp, archive, base / "manifest.json"

    def run_validator(self, archive, manifest):
        output = archive.parent / "out"
        return subprocess.run([sys.executable, "-c", validator_script(), str(archive), str(manifest), "v1.2.3", str(output)], text=True, capture_output=True)

    def test_valid_archive_is_accepted(self):
        temp, archive, manifest = self.make_archive()
        with temp:
            result = self.run_validator(archive, manifest)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_path_traversal_archive_is_rejected_before_extraction(self):
        def mutate(tar, root):
            info = tarfile.TarInfo(root + "/../escape"); info.size = 1; tar.addfile(info, __import__("io").BytesIO(b"x"))
        temp, archive, manifest = self.make_archive(mutate)
        with temp:
            result = self.run_validator(archive, manifest)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((archive.parent / "out").exists())

    def test_symlink_archive_is_rejected_before_extraction(self):
        def mutate(tar, root):
            info = tarfile.TarInfo(root + "/link"); info.type = tarfile.SYMTYPE; info.linkname = "/etc/shadow"; tar.addfile(info)
        temp, archive, manifest = self.make_archive(mutate)
        with temp:
            result = self.run_validator(archive, manifest)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((archive.parent / "out").exists())

    def test_bootstrap_is_versioned_and_disallows_implicit_override(self):
        text = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        self.assertIn('RELEASE_VERSION="@LINKMOTH_VERSION@"', text)
        self.assertIn('BASE="https://github.com/$OFFICIAL_REPO/releases/download/$RELEASE_VERSION"', text)
        self.assertNotIn('REPO="$OFFICIAL_REPO"', text)
        self.assertGreaterEqual(text.count("re.fullmatch"), 3)
        self.assertNotIn("releases/latest", text)


class ReleaseChecksumTests(unittest.TestCase):
    def run_validator(self, checksum_contents=None, archive_contents=b"release", checksum_name="linkmoth-v1.2.3.tar.gz.sha256"):
        temp = tempfile.TemporaryDirectory()
        base = Path(temp.name)
        archive = base / "linkmoth-v1.2.3.tar.gz"
        archive.write_bytes(archive_contents)
        checksum = base / checksum_name
        if checksum_contents is not None:
            checksum.write_text(checksum_contents, encoding="ascii")
        result = subprocess.run(
            [sys.executable, "-c", checksum_validator_script(), checksum.name, archive.name],
            cwd=base, text=True, capture_output=True,
        )
        return temp, result

    def test_exact_checksum_is_accepted(self):
        digest = hashlib.sha256(b"release").hexdigest()
        temp, result = self.run_validator(f"{digest}  linkmoth-v1.2.3.tar.gz\n")
        with temp:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), digest)

    def test_checksum_mismatch_fails(self):
        temp, result = self.run_validator(f"{'0' * 64}  linkmoth-v1.2.3.tar.gz\n")
        with temp:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("checksum mismatch", result.stderr)

    def test_missing_checksum_fails(self):
        temp, result = self.run_validator(None)
        with temp:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("malformed checksum file", result.stderr)

    def test_malformed_checksum_fails(self):
        temp, result = self.run_validator("not-a-sha256  linkmoth-v1.2.3.tar.gz\n")
        with temp:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not name the exact release archive", result.stderr)

    def test_checksum_for_wrong_release_version_fails(self):
        digest = hashlib.sha256(b"release").hexdigest()
        temp, result = self.run_validator(f"{digest}  linkmoth-v1.2.4.tar.gz\n")
        with temp:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exact release archive", result.stderr)


class ReleaseRedirectTests(unittest.TestCase):
    SOURCE = "https://github.com/benukas/Linkmoth/releases/download/v1.2.3/linkmoth-v1.2.3.tar.gz"

    def run_validator(self, target):
        return subprocess.run(
            [sys.executable, "-c", redirect_validator_script(), self.SOURCE, target],
            text=True, capture_output=True,
        )

    def test_expected_github_release_asset_redirect_is_accepted(self):
        result = self.run_validator(
            "https://release-assets.githubusercontent.com/github-production-release-asset/123/asset?token=pinned"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_arbitrary_redirect_host_is_rejected(self):
        result = self.run_validator("https://example.test/github-production-release-asset/123/asset")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected location", result.stderr)

    def test_wrong_release_asset_path_is_rejected(self):
        result = self.run_validator("https://release-assets.githubusercontent.com/unexpected/asset")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected location", result.stderr)


@unittest.skipIf(os.name == "nt", "shell integration runs on the Linux release platform")
class SigstoreShellIntegrationTests(unittest.TestCase):
    EXPECTED_IDENTITY = (
        "https://github.com/benukas/Linkmoth/.github/workflows/"
        "release.yml@refs/tags/v1.2.3"
    )

    def run_block(self, identity, path):
        script = f'''set -euo pipefail
PATH={path}
die() {{ echo "ERROR: $*" >&2; exit 1; }}
ASSET=linkmoth-v1.2.3.tar.gz
MANIFEST=linkmoth-v1.2.3.manifest.json
IDENTITY={identity!r}
ISSUER=https://token.actions.githubusercontent.com
{sigstore_verification_block()}
'''
        return subprocess.run(
            ["/bin/bash", "-c", script], text=True, capture_output=True,
        )

    def test_unavailable_cosign_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_block(self.EXPECTED_IDENTITY, directory)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature verification failed", result.stderr)

    def test_wrong_sigstore_identity_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            cosign = Path(directory) / "cosign"
            cosign.write_text(
                "#!/bin/sh\n"
                f"case \" $* \" in *\"--certificate-identity {self.EXPECTED_IDENTITY}\"*) exit 0 ;; esac\n"
                "exit 1\n",
                encoding="utf-8",
            )
            cosign.chmod(0o755)
            result = self.run_block(
                self.EXPECTED_IDENTITY.replace("benukas/Linkmoth", "attacker/Linkmoth"),
                directory,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature verification failed", result.stderr)


if __name__ == "__main__":
    unittest.main()

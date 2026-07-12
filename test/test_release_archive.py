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
        self.assertIn("--allow-repository-override", text)
        self.assertGreaterEqual(text.count("re.fullmatch"), 2)
        self.assertNotIn("releases/latest", text)


if __name__ == "__main__":
    unittest.main()

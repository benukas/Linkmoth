"""Public-release metadata and distributable integrity tests."""
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
DIST_FILES = {
    "linkmoth.py",
    "linkmoth_auth.py",
    "linkmoth_discord.py",
    "linkmoth_kuma_proxy.py",
    "linkmoth_outage.py",
    "linkmoth_push.py",
    "linkmoth_notify.py",
    "linkmoth_devices.py",
    "linkmoth_webhooks.py",
    "dashboard.html",
    "linkmoth.svg",
    "linkmoth-white.svg",
    "linkmoth-mark-white.svg",
    "linkmoth-white.ico",
    "sw.js",
    "manifest.webmanifest",
    "config.example.json",
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "TRADEMARKS.md",
    "LICENSE",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "install.sh",
    "uninstall.sh",
    "renew-cert.sh",
    "linkmoth.service",
    "linkmoth-cert-renew.service",
    "linkmoth-cert-renew.timer",
}


class PublicReleaseTests(unittest.TestCase):
    def test_public_project_metadata_exists(self):
        for name in (
            "LICENSE",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "THIRD_PARTY_NOTICES.md",
            ".github/workflows/ci.yml",
        ):
            self.assertTrue((ROOT / name).is_file(), name)

    def test_qr_attribution_is_accurate(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        self.assertNotIn("Nayuki (public domain)", dashboard)
        self.assertIn("MIT-licensed Project Nayuki", dashboard)
        self.assertIn("Copyright © 2025 Project Nayuki", notices)

    def test_release_bootstrap_requires_sigstore_and_is_not_pipe_to_root(self):
        bootstrap = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("cosign verify-blob", bootstrap)
        self.assertIn('OFFICIAL_REPO="benukas/Linkmoth"', bootstrap)
        self.assertNotIn("raw.githubusercontent.com/benukas/linkmoth/main/bootstrap.sh", bootstrap)
        self.assertIn("sigstore/cosign-installer", workflow)
        self.assertIn("cosign sign-blob", workflow)

    def test_quick_start_uses_a_verified_versioned_release(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("git clone https://github.com/benukas/linkmoth.git", readme)
        self.assertIn("VERSION=v0.2.0", readme)
        self.assertIn("cosign verify-blob", readme)
        self.assertIn("linkmoth-$VERSION-bootstrap.sh", readme)
        self.assertIn("https://github.com/benukas/Linkmoth/releases/download/$VERSION", readme)
        self.assertIn("https://github.com/benukas/Linkmoth/.github/workflows/release.yml@refs/tags/$VERSION", readme)

    def test_installer_never_kills_processes_by_name(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertNotIn("pkill -f", installer)
        self.assertIn("--bind", installer)
        self.assertIn("--doctor", installer)
        self.assertNotIn("migrate_vamner_install", installer)

    def test_dist_contains_only_declared_release_files(self):
        actual = {
            path.relative_to(DIST).as_posix()
            for path in DIST.rglob("*")
            if path.is_file()
        }
        self.assertEqual(actual, DIST_FILES)

    def test_dist_matches_release_sources(self):
        for name in sorted(DIST_FILES):
            self.assertEqual(
                (ROOT / name).read_bytes(),
                (DIST / name).read_bytes(),
                name,
            )


if __name__ == "__main__":
    unittest.main()

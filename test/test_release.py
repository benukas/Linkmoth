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

    def test_dashboard_utility_controls_stay_aligned(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn(
            ".packet-actions .action-btn {\n"
            "  min-height: 48px; width: auto; margin-top: 0; padding: 12px 18px;",
            dashboard,
        )

    def test_sign_out_lives_in_settings_not_the_header(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        header = dashboard.split("<header>", 1)[1].split("</header>", 1)[0]
        self.assertNotIn("logout-btn", header)
        settings_tab = dashboard.split('id="tab-settings"', 1)[1].split("</section>", 1)[0]
        self.assertIn(
            '<button id="logout-btn" type="button" class="action-btn hidden">Sign out</button>',
            settings_tab,
        )

    def test_release_bootstrap_keeps_sigstore_optional_and_is_not_pipe_to_root(self):
        bootstrap = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("cosign verify-blob", bootstrap)
        self.assertIn("VERIFY_SIGSTORE=0", bootstrap)
        self.assertIn("--sigstore-verified", bootstrap)
        self.assertIn('command -v cosign >/dev/null || die "cosign is required only for --sigstore-verified"', bootstrap)
        self.assertIn('OFFICIAL_REPO="benukas/Linkmoth"', bootstrap)
        self.assertNotIn("raw.githubusercontent.com/benukas/linkmoth/main/bootstrap.sh", bootstrap)
        self.assertIn("sigstore/cosign-installer", workflow)
        self.assertIn("cosign sign-blob", workflow)

    def test_bootstrap_record_is_root_owned_atomic_and_rejects_symlinks(self):
        bootstrap = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        self.assertIn('"installation.json"', bootstrap)
        self.assertIn("os.lstat(etc)", bootstrap)
        self.assertIn("stat.S_ISLNK", bootstrap)
        self.assertIn("tempfile.mkstemp", bootstrap)
        self.assertIn("os.fsync(f.fileno())", bootstrap)
        self.assertIn("os.replace(tmp, path)", bootstrap)
        self.assertIn("os.chown(tmp, 0, 0)", bootstrap)
        self.assertIn("os.chmod(tmp, 0o644)", bootstrap)
        self.assertIn('if verification != "sigstore-verified"', bootstrap)
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('chown root:linkmoth "$ETC"', installer)
        self.assertIn('chmod 750 "$ETC"', installer)
        self.assertIn('APP_FILES="$APP_FILES linkmoth-build.json"', installer)

    def test_quick_start_uses_a_versioned_release_without_cosign_by_default(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("git clone https://github.com/benukas/linkmoth.git", readme)
        self.assertIn("VERSION=v0.2.1", readme)
        self.assertIn("cosign verify-blob", readme)
        self.assertIn("sudo bash linkmoth-v0.2.1-bootstrap.sh", readme)
        self.assertIn("No Git checkout, package manager, or Cosign installation is", readme)
        self.assertIn("--sigstore-verified", readme)
        self.assertIn("linkmoth-$VERSION-bootstrap.sh", readme)
        self.assertIn("https://github.com/benukas/Linkmoth/releases/download/$VERSION", readme)
        self.assertIn("https://github.com/benukas/Linkmoth/.github/workflows/release.yml@refs/tags/$VERSION", readme)

    def test_installer_never_kills_processes_by_name(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertNotIn("pkill -f", installer)
        self.assertIn("--bind", installer)
        self.assertIn("--doctor", installer)
        self.assertNotIn("migrate_vamner_install", installer)
        self.assertNotIn("polkit.addRule", installer)
        self.assertNotIn("--no-polkit", installer)
        self.assertIn("rm -f /etc/polkit-1/rules.d/51-linkmoth.rules", installer)

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

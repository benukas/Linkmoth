"""Public-release metadata and distributable integrity tests."""
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
DIST_FILES = {
    "linkmoth.py",
    "linkmoth_core.py",
    "linkmoth_probes.py",
    "linkmoth_engine.py",
    "linkmoth_handler.py",
    "linkmoth_backup.py",
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
    "linkmoth-maskable.svg",
    "linkmoth-icon-180.png",
    "linkmoth-icon-192.png",
    "linkmoth-icon-512.png",
    "linkmoth-white.ico",
    "sw.js",
    "manifest.webmanifest",
    "config.example.json",
    "README.md",
    "ADVANCED.md",
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
    def test_retention_reduction_warns_before_irreversible_cleanup(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn(
            "Lowering this permanently deletes older history during the next cleanup",
            dashboard,
        )
        self.assertIn("function confirmRetentionReduction(nextDays)", dashboard)
        save_handler = dashboard.index('$("save-settings").addEventListener')
        confirmation = dashboard.index(
            "if (!confirmRetentionReduction(nextRetentionDays))", save_handler
        )
        request = dashboard.index('fetch("/api/settings"', save_handler)
        self.assertLess(confirmation, request)
        self.assertIn("payload._confirm_retention_reduction = true", dashboard)

    def test_pwa_has_standard_opaque_apple_touch_icon(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        source = (ROOT / "linkmoth_core.py").read_text(encoding="utf-8")
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        service_worker = (ROOT / "sw.js").read_text(encoding="utf-8")
        icon = (ROOT / "linkmoth-icon-180.png").read_bytes()
        self.assertIn(
            '<link rel="apple-touch-icon" sizes="180x180" '
            'href="/linkmoth-icon-180.png">',
            dashboard,
        )
        self.assertIn('"/linkmoth-icon-180.png"', source)
        self.assertIn("linkmoth-icon-180.png", installer)
        self.assertIn('"/linkmoth-icon-180.png"', service_worker)
        self.assertEqual(icon[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", icon[16:24]), (180, 180))
        self.assertEqual(icon[25], 2)  # PNG truecolour, no alpha channel

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

    def test_network_misconfig_warnings_surface_above_the_verdict(self):
        """The whole value of the check is that a duplicate IP is seen before
        the verdict, so the block must render on Today, ahead of #verdict."""
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn('<div id="network-notes"', dashboard)
        self.assertIn("renderNetworkNotes(s.network_notes)", dashboard)
        self.assertLess(
            dashboard.index('id="network-notes"'), dashboard.index('id="verdict"'))

    def test_user_visible_times_are_local_and_do_not_expose_iso_z(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertNotIn(".toISOString()", dashboard)
        self.assertIn("function fmtFullTs(ts)", dashboard)
        self.assertIn("Initial diagnosis (local time): ${fmtFullTs(run.ts)}", dashboard)
        self.assertIn("Incident started (local time): ${fmtFullTs(inc.started)}", dashboard)
        self.assertIn("published ${fmtDateValue(data.published_at)}", dashboard)

    def test_accountability_window_uses_custom_button_selector(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn('id="report-days-trigger"', dashboard)
        self.assertIn('class="action-btn custom-select-trigger" id="report-days-trigger"', dashboard)
        self.assertIn('id="report-days-menu" role="listbox"', dashboard)
        self.assertIn('id="report-days" class="sr-only"', dashboard)
        self.assertIn('wrapId: "report-days-wrap"', dashboard)

    def test_stat_cards_keep_primary_metrics_visually_prominent(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn(
            ".stat .v { min-height: 40px; margin-top: 2px; font-size: 30px;",
            dashboard,
        )

    def test_bufferbloat_load_test_result_omits_download_speed(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn('id="q-load-results"', dashboard)
        self.assertIn('id="q-load-grade"', dashboard)
        self.assertIn('id="q-load-bloat"', dashboard)
        self.assertNotIn('id="q-download"', dashboard)
        self.assertNotIn("download speed (est.)", dashboard)
        self.assertNotIn(
            "Download speed is an estimate from the bounded test transfer.",
            dashboard,
        )

    def test_live_history_refresh_preserves_expanded_content(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn("let historyLoading = false;", dashboard)
        self.assertIn("let reportLoading = false;", dashboard)
        self.assertIn("const openPackets = new Map();", dashboard)
        self.assertIn("renderPacketSlot(slot, packetCache[id]);", dashboard)
        self.assertIn("const openDeviceIds = new Set(", dashboard)
        self.assertIn("historyRefreshes.push(loadDeviceHistory(details, true));", dashboard)
        history_refresh = dashboard.split(
            'if (!$("tab-history").classList.contains("hidden")) {', 1,
        )[1].split("}", 1)[0]
        self.assertIn("loadHistory(true);", history_refresh)
        self.assertIn("loadReport();", history_refresh)
        self.assertNotIn(
            'if (silent && $("device-list").querySelector("details[open]"))',
            dashboard,
        )

    def test_expanded_history_uses_elapsed_time_and_token_help_matches_api(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn("(timestamps[i] - minTs) / (maxTs - minTs)", dashboard)
        self.assertIn("show(nearestIndexAtRatio(ratio));", dashboard)
        self.assertIn(
            "A token can only GET /api/status, /api/quality, /api/report, and /api/history",
            dashboard,
        )

    def test_expanded_history_adds_context_and_centers_close_icon(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn(
            ".modal-close {\n"
            "  display: grid; place-items: center; width: 40px; height: 40px;",
            dashboard,
        )
        self.assertIn('<svg viewBox="0 0 20 20" aria-hidden="true"', dashboard)
        for control in (
            'id="history-modal-overview"',
            'id="history-modal-stats"',
            'id="history-modal-range-label"',
        ):
            self.assertIn(control, dashboard)
        for metric in ("Recorded checks", "Data gaps", "Median", "95th pct", "Peak"):
            self.assertIn(metric, dashboard)
        self.assertIn("function niceLatencyCeil(value)", dashboard)
        self.assertIn("function historyGapCount(hist)", dashboard)
        self.assertIn("if (gapBefore) pen = false;", dashboard)
        self.assertIn("showLatest();", dashboard)

    def test_expanded_history_ranges_use_custom_selector_for_network_and_devices(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn(
            'class="action-btn custom-select-trigger" id="history-modal-range-trigger"',
            dashboard,
        )
        self.assertIn('id="history-modal-range-menu" role="listbox"', dashboard)
        self.assertIn('id="history-modal-range" class="sr-only"', dashboard)
        self.assertIn('historyModalRangeControl = initCustomSelect({', dashboard)
        self.assertIn(
            "if (historyModalRangeControl) historyModalRangeControl.refresh();",
            dashboard,
        )
        self.assertIn('kind === "network" ? NETWORK_HISTORY_RANGES : DEVICE_HISTORY_RANGES', dashboard)
        self.assertNotIn('class="modal-range-select"', dashboard)

    def test_expanded_history_color_swatches_respect_style_csp(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertNotIn('<i style="background:${s.color}">', dashboard)
        self.assertIn('.hist-swatch-line { background: var(--line); }', dashboard)
        self.assertIn('.hist-swatch-line2 { background: var(--line2); }', dashboard)
        self.assertIn(
            'class="hist-swatch-${esc(s.swatch || "line")}"',
            dashboard,
        )

    def test_fire_drill_prompt_state_is_shared_by_the_installation(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        engine_source = (ROOT / "linkmoth_engine.py").read_text(encoding="utf-8")
        handler_source = (ROOT / "linkmoth_handler.py").read_text(encoding="utf-8")
        self.assertIn('"fire_drill": fire_drill_status()', engine_source)
        self.assertIn('elif path == "/api/fire-drill":', handler_source)
        self.assertIn("WHERE kind IN ('manual', 'verify')", engine_source)
        self.assertIn('const serverDrill = s.fire_drill || {};', dashboard)
        self.assertIn('rememberFireDrill(localDrillState);', dashboard)
        self.assertIn('rememberFireDrill("seen");', dashboard)
        self.assertIn('rememberFireDrill("completed");', dashboard)

    def test_settings_subtabs_match_the_main_navigation_treatment(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn(
            ".subnav-btn {\n"
            "  flex: 1; min-width: 0; padding: 13px 8px;\n"
            "  font-size: 19px; font-weight: 600; line-height: normal; white-space: nowrap; cursor: pointer;\n"
            "  border: 1px solid var(--border); border-radius: 12px;\n"
            "  background: var(--card); color: var(--muted);",
            dashboard,
        )
        self.assertIn(".subnav-btn:active { transform: scale(0.98); }", dashboard)
        self.assertIn(".subnav-btn.active { color: var(--text); border-color: var(--text); }", dashboard)
        self.assertIn(
            '<div class="k">Incidents</div><div class="v">${st.incidents_30d}</div><small>',
            dashboard,
        )
        self.assertIn(
            '<div class="k">Downtime</div><div class="v">${st.downtime_s ? fmtDur(st.downtime_s) : "0"}</div><small>last 30 days</small>',
            dashboard,
        )

    def test_healthy_verdict_hides_incident_actions(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn('run.severity === "ok" && evidenceStates.length > 0', dashboard)
        self.assertIn(
            'evidenceStates.every((state) => state === "passed" || state === "skipped")',
            dashboard,
        )
        self.assertIn('if (!everythingAnswers && openInc && openInc.ref)', dashboard)
        self.assertIn('.action-bar.hidden { display: none; }', dashboard)

    def test_incident_reports_separate_recovery_close_and_downtime(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        source = (ROOT / "linkmoth.py").read_text(encoding="utf-8")
        for label in (
            "Network recovered:",
            "Incident closed:",
            "Observed downtime:",
            "Incident duration:",
        ):
            self.assertIn(label, dashboard)
        for stale_plural in (
            "incident(s)", "false alarm(s)", "recorded run(s)", "time(s)",
        ):
            self.assertNotIn(stale_plural, dashboard)
            self.assertNotIn(stale_plural, source)

    def test_push_buttons_follow_this_device_subscription(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn('enableBtn.disabled = Notification.permission === "denied";', dashboard)
        self.assertIn('reg.pushManager.getSubscription()', dashboard)
        self.assertIn('disableBtn.classList.toggle("hidden", !sub);', dashboard)

    def test_quiet_hours_controls_and_settings_are_wired(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        source = (ROOT / "linkmoth_core.py").read_text(encoding="utf-8")
        config = (ROOT / "config.example.json").read_text(encoding="utf-8")
        for control in (
            'id="s-quiet-enabled"',
            'id="s-quiet-start"',
            'id="s-quiet-end"',
            'id="s-quiet-status"',
        ):
            self.assertIn(control, dashboard)
        for setting in (
            "quiet_hours_enabled",
            "quiet_hours_start",
            "quiet_hours_end",
        ):
            self.assertIn(setting, dashboard)
            self.assertIn(setting, source)
            self.assertIn(setting, config)

    def test_ladder_keeps_probe_details_compact_and_nonduplicative(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        # Each check (row + its evidence) is wrapped in one .ladder-check block,
        # and the divider sits on that block – never between a check and its own
        # evidence, and never trailing after the last check.
        self.assertIn('.ladder-check { border-top: 1px solid var(--border); }', dashboard)
        self.assertIn('.ladder-check:first-child, .ladder-group + .ladder-check { border-top: none; }', dashboard)
        self.assertIn('return `<div class="ladder-check">${html}</div>`;', dashboard)
        self.assertIn('.row.with-probes { padding-bottom: 6px; }', dashboard)
        self.assertNotIn('.row.with-probes { padding-bottom: 6px; border-bottom:', dashboard)
        self.assertIn('detail = state === "passed" ? "All test targets responded."', dashboard)

    def test_sign_out_lives_in_settings_not_the_header(self):
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        header = dashboard.split("<header>", 1)[1].split("</header>", 1)[0]
        self.assertNotIn("logout-btn", header)
        settings_tab = dashboard.split('id="tab-settings"', 1)[1].split("</section>", 1)[0]
        self.assertIn(
            '<button id="logout-btn" type="button" class="action-btn hidden">Sign out</button>',
            settings_tab,
        )

    def test_release_bootstrap_defaults_to_checksum_with_optional_sigstore(self):
        bootstrap = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        builder = (ROOT / "scripts" / "build-release.sh").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("cosign verify-blob", bootstrap)
        self.assertIn("VERIFY_SIGSTORE=0\nINSTALL_ARGS=()", bootstrap)
        self.assertIn("--sigstore-verified", bootstrap)
        self.assertIn(
            'command -v cosign >/dev/null || die "cosign is required only for --sigstore-verified"',
            bootstrap,
        )
        self.assertLess(bootstrap.index("command -v cosign"), bootstrap.index('TMP="$(mktemp -d)"'))
        self.assertIn("checksum verification and the official repository are mandatory", bootstrap)
        self.assertIn('download "$ASSET.bundle"', bootstrap)
        self.assertIn('download "$ASSET.sha256.bundle"', bootstrap)
        self.assertIn('download "$MANIFEST.bundle"', bootstrap)
        self.assertIn('OFFICIAL_REPO="benukas/Linkmoth"', bootstrap)
        self.assertIn("release-assets.githubusercontent.com", bootstrap)
        self.assertIn('[ "$source" = "$BASE/$output" ]', bootstrap)
        self.assertIn("--noproxy '*'", bootstrap)
        self.assertNotIn("curl --fail --location", bootstrap)
        self.assertNotIn("raw.githubusercontent.com/benukas/linkmoth/main/bootstrap.sh", bootstrap)
        self.assertIn("sigstore/cosign-installer", workflow)
        self.assertIn("cosign sign-blob", workflow)
        self.assertIn("hashlib.sha256()", builder)
        self.assertIn('handle.write(f"{digest.hexdigest()}  {os.path.basename(archive)}\\n")', builder)
        self.assertNotIn("sha256sum", builder)
        self.assertNotIn("shasum -a", builder)

    def test_tagged_bootstrap_derives_only_a_strict_versioned_filename(self):
        bootstrap = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        self.assertIn('case "$RELEASE_VERSION" in\n  @*)', bootstrap)
        self.assertIn('linkmoth-v*-bootstrap.sh)', bootstrap)
        self.assertIn('RELEASE_VERSION="${BOOTSTRAP_NAME#linkmoth-}"', bootstrap)
        self.assertIn('RELEASE_VERSION="${RELEASE_VERSION%-bootstrap.sh}"', bootstrap)
        self.assertIn("save the tagged bootstrap as linkmoth-vX.Y.Z-bootstrap.sh", bootstrap)

    def test_sigstore_mode_pins_identity_and_fails_closed(self):
        bootstrap = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        self.assertIn(
            'IDENTITY="https://github.com/$OFFICIAL_REPO/.github/workflows/release.yml@refs/tags/$RELEASE_VERSION"',
            bootstrap,
        )
        self.assertIn('--certificate-identity "$IDENTITY"', bootstrap)
        self.assertIn('--certificate-oidc-issuer "$ISSUER"', bootstrap)
        self.assertIn('|| die "signature verification failed: $file"', bootstrap)
        self.assertIn('VERIFICATION="checksum-verified"', bootstrap)
        self.assertIn('[ "$VERIFY_SIGSTORE" -eq 1 ] && VERIFICATION="sigstore-verified"', bootstrap)

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
        self.assertIn('verification not in {"checksum-verified", "sigstore-verified"}', bootstrap)
        self.assertIn('"verification": verification', bootstrap)
        self.assertIn('bash install.sh "${INSTALL_ARGS[@]}"', bootstrap)
        self.assertNotIn('if ! bash install.sh', bootstrap)
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        uninstaller = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn('chown root:linkmoth "$ETC"', installer)
        self.assertIn('chmod 750 "$ETC"', installer)
        self.assertIn('APP_FILES="$APP_FILES linkmoth-build.json"', installer)
        self.assertIn('rm -f -- "$ETC/installation.json"', installer)
        self.assertIn('rm -f -- /etc/linkmoth/installation.json', uninstaller)

    def test_quick_start_uses_a_checksum_verified_versioned_release(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        self.assertNotIn("git clone https://github.com/benukas/linkmoth.git", readme)
        self.assertNotIn("cosign verify-blob", readme)
        self.assertIn('&& sudo bash linkmoth-v0.5.0-bootstrap.sh', readme)
        self.assertIn(
            "https://raw.githubusercontent.com/benukas/Linkmoth/v0.5.0/bootstrap.sh",
            readme,
        )
        self.assertIn("Checksum-verified release", readme)
        self.assertIn("does not require Cosign", readme)
        self.assertIn("--max-redirs 0", readme)
        self.assertNotIn("--proto-redir", readme)
        self.assertNotIn("--insecure-skip-verify", readme)
        self.assertIn("# Changelog\n\n## Unreleased\n", changelog)
        self.assertIn("normal pinned-release installation no longer requires Cosign", changelog)
        self.assertIn("Backup and restore", changelog)
        self.assertLess(changelog.index("## Unreleased"), changelog.index("## 0.5.0"))
        self.assertLess(changelog.index("## 0.5.0"), changelog.index("## 0.4.12"))
        self.assertLess(changelog.index("## 0.4.12"), changelog.index("## 0.4.11"))
        self.assertLess(changelog.index("## 0.4.11"), changelog.index("## 0.4.10"))
        self.assertLess(changelog.index("## 0.4.10"), changelog.index("## 0.4.9"))
        self.assertLess(changelog.index("## 0.4.9"), changelog.index("## 0.4.8"))
        self.assertLess(changelog.index("## 0.4.8"), changelog.index("## 0.4.7"))
        self.assertIn('"checksum-verified": "Checksum-verified release"', dashboard)
        self.assertIn("Optional Sigstore-verified command", dashboard)
        self.assertIn("data.sigstore_update_command", dashboard)

    def test_advanced_docs_cover_both_verified_install_modes(self):
        advanced = (ROOT / "ADVANCED.md").read_text(encoding="utf-8")
        self.assertIn("VERSION=v0.5.0", advanced)
        self.assertIn("## Checksum-verified installation", advanced)
        self.assertIn("## Optional Sigstore-verified installation", advanced)
        self.assertIn("cosign verify-blob", advanced)
        self.assertNotIn("--insecure-skip-verify", advanced)
        self.assertIn('sudo bash "linkmoth-$VERSION-bootstrap.sh" --sigstore-verified', advanced)
        self.assertIn("linkmoth-$VERSION-bootstrap.sh", advanced)
        self.assertIn("https://raw.githubusercontent.com/benukas/Linkmoth/$VERSION/bootstrap.sh", advanced)
        self.assertIn("--max-redirs 0", advanced)
        self.assertIn("https://github.com/benukas/Linkmoth/releases/download/$VERSION", advanced)
        self.assertIn("https://github.com/benukas/Linkmoth/.github/workflows/release.yml@refs/tags/$VERSION", advanced)

    def test_installer_never_kills_processes_by_name(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertNotIn("pkill -f", installer)
        self.assertIn("--bind", installer)
        self.assertIn("--doctor", installer)
        self.assertNotIn("migrate_vamner_install", installer)
        self.assertNotIn("polkit.addRule", installer)
        self.assertNotIn("--no-polkit", installer)
        self.assertIn("rm -f /etc/polkit-1/rules.d/51-linkmoth.rules", installer)

    def test_failed_fresh_install_undoes_its_own_state(self):
        # A fresh install that fails must not leave a trusted CA anchor, service
        # units, or the service user behind (there is no previous version to
        # restore, so the update-rollback branch does not cover it).
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('elif [ "$IS_UPDATE" -eq 0 ]', installer)
        # remove_ca_trust must be defined in install.sh (ported from uninstall.sh)
        # and invoked from the fresh-install cleanup branch.
        self.assertIn("remove_ca_trust() {", installer)
        self.assertIn('[ "$CA_TRUST_INSTALLED" -eq 1 ] && remove_ca_trust', installer)
        self.assertIn("CA_TRUST_INSTALLED=1", installer)
        self.assertIn("UNITS_COPIED=1", installer)
        self.assertIn("USER_CREATED=1", installer)
        self.assertIn('[ "$USER_CREATED" -eq 1 ] && userdel linkmoth', installer)
        # The two rollback branches stay mutually exclusive: updates restore, a
        # fresh failure undoes.
        self.assertIn("update failed - restoring the previous working version", installer)
        self.assertIn("fresh install failed - undoing changes made so far", installer)

    def test_installer_sets_ownership_without_following_symlinks(self):
        # A planted symlink at a managed path must not redirect chown/chmod onto
        # an arbitrary file; the installer opens with O_NOFOLLOW and operates on
        # the fd instead of the path.
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("secure_regular_file() {", installer)
        self.assertIn("O_NOFOLLOW", installer)
        self.assertIn('secure_regular_file "$ETC/config.json" root linkmoth 640', installer)
        self.assertIn('secure_regular_file "$STATE/auth.json" linkmoth linkmoth 600', installer)
        # The old symlink-following forms must be gone.
        self.assertNotIn('chown root:linkmoth "$ETC/config.json"', installer)
        self.assertNotIn('chmod 640 "$ETC/config.json"', installer)
        self.assertNotIn('chmod 600 "$STATE/auth.json"', installer)

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

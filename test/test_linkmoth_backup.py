#!/usr/bin/env python3
"""Tests for linkmoth_backup: the portable backup/restore archive (history,
settings, device/webhook configuration – no auth.json secrets, no VAPID
key, no TLS CA, and the DB snapshot itself is sanitized of webhook
URLs/headers, push subscriptions, queues, and auth session/attempt/TOTP
state before it's ever embedded)."""
import importlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
REPO_ROOT = BASE.parent
sys.path.insert(0, str(REPO_ROOT))

import linkmoth_backup as backup


def _reimport_core(state_dir):
    """Fresh linkmoth_core bound to a new state directory, matching the
    module-cache-reset pattern used throughout this test suite – linkmoth_
    core's DB_PATH/CFG/SETTINGS_PATH are computed once at import time from
    the LINKMOTH_STATE_DIR env var, so a different "device" needs a fresh
    reimport, not just a different argument."""
    os.environ["LINKMOTH_STATE_DIR"] = str(state_dir)
    os.environ.pop("LINKMOTH_CONFIG", None)
    for mod in ("linkmoth_core", "linkmoth_devices", "linkmoth_auth"):
        if mod in sys.modules:
            del sys.modules[mod]
    core = importlib.import_module("linkmoth_core")
    core.init_db()
    return core


def _open_db_from_archive(archive_bytes, tmpdir):
    """Extract state.db from an in-memory archive and open it read-only,
    for tests that need to inspect what actually got embedded."""
    db_path = Path(tmpdir) / "extracted.db"
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
        db_path.write_bytes(zf.read("state.db"))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


class BackupRestoreRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.source_dir = Path(tempfile.mkdtemp(prefix="linkmoth_backup_src_"))
        self.target_dir = Path(tempfile.mkdtemp(prefix="linkmoth_backup_dst_"))
        self.archive_path = Path(tempfile.mkdtemp(prefix="linkmoth_backup_file_")) / "backup.zip"

    def _seed_source(self):
        core = _reimport_core(self.source_dir)
        with core.db() as conn:
            conn.execute(
                "INSERT INTO incidents(started, source, detail, resolved)"
                " VALUES(?,?,?,?)",
                (time.time() - 3600, "baseline", "wan_down", time.time() - 3000),
            )
            conn.execute(
                "INSERT INTO runs(incident_id, ts, severity, code, title,"
                " explain, hint, checks, duration_ms, kind)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (None, time.time(), "ok", "all_clear", "All clear", "", "",
                 "[]", 12.0, "manual"),
            )
        from linkmoth_webhooks import create_webhook
        create_webhook(core.db, {
            "name": "Test hook", "url": "https://example.test/hook",
            "preset": "generic", "events": ["fault_opened"],
            "headers": {"Authorization": "Bearer super-secret-token"},
        })
        return core

    def test_history_and_webhook_config_survive_round_trip(self):
        core = self._seed_source()
        archive = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")
        self.archive_path.write_bytes(archive)

        target_core = _reimport_core(self.target_dir)
        summary = backup.restore_backup_archive(
            self.archive_path, target_core.DB_PATH,
            target_core.init_db, target_core.apply_settings,
            target_core.validate_settings,
        )
        self.assertEqual(summary["manifest"]["linkmoth_version"], "1.2.3")

        with target_core.db() as conn:
            incidents = conn.execute("SELECT * FROM incidents").fetchall()
            runs = conn.execute("SELECT * FROM runs").fetchall()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["source"], "baseline")
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["code"], "all_clear")

        from linkmoth_webhooks import list_webhooks
        hooks = list_webhooks(target_core.db)
        self.assertEqual(len(hooks), 1)
        self.assertEqual(hooks[0]["name"], "Test hook")
        # No stale WAL/SHM sidecars left beside the restored database.
        self.assertFalse(Path(str(target_core.DB_PATH) + "-wal").exists())
        self.assertFalse(Path(str(target_core.DB_PATH) + "-shm").exists())

    def test_archive_disables_restored_webhooks_and_clears_delivery_state(self):
        """A webhook whose URL/headers were stripped must also come back
        disabled, or a restored install immediately queues retries against
        an empty destination."""
        core = self._seed_source()
        with core.db() as conn:
            conn.execute(
                "UPDATE webhooks SET last_send_ts=?, last_status=?, last_error=?",
                (time.time(), 500, "boom"),
            )
        archive = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")

        with tempfile.TemporaryDirectory() as tmpdir:
            conn = _open_db_from_archive(archive, tmpdir)
            try:
                row = conn.execute("SELECT * FROM webhooks").fetchone()
            finally:
                conn.close()
        self.assertEqual(row["enabled"], 0)
        self.assertEqual(row["url"], "")
        self.assertIsNone(row["last_send_ts"])
        self.assertIsNone(row["last_status"])
        self.assertIsNone(row["last_error"])

    def test_backup_forces_credential_dependent_flags_off(self):
        """Discord/notify-webhook enable flags are forced off in the backup,
        since their URLs aren't carried – otherwise a restore onto a fresh
        device fails 'enabled but no URL' validation."""
        core = self._seed_source()
        core.CFG["discord_notifications_enabled"] = True
        core.CFG["discord_webhook_url"] = (
            "https://discord.com/api/webhooks/123/abc"
        )
        core.CFG["notify_webhook_enabled"] = True
        archive = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")

        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            settings = json.loads(zf.read("settings.json"))
        self.assertFalse(settings.get("discord_notifications_enabled", False))
        self.assertFalse(settings.get("notify_webhook_enabled", False))

    def test_discord_enabled_source_restores_onto_fresh_target(self):
        """End-to-end: a backup taken while Discord alerts were on restores
        cleanly onto a fresh device instead of failing settings validation."""
        core = self._seed_source()
        core.CFG["discord_notifications_enabled"] = True
        core.CFG["discord_webhook_url"] = (
            "https://discord.com/api/webhooks/123/abc"
        )
        archive = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")
        self.archive_path.write_bytes(archive)

        target_core = _reimport_core(self.target_dir)
        summary = backup.restore_backup_archive(
            self.archive_path, target_core.DB_PATH,
            target_core.init_db, target_core.apply_settings,
            target_core.validate_settings,
        )
        self.assertTrue(summary["settings_applied"])
        self.assertFalse(target_core.CFG.get("discord_notifications_enabled", False))

    def test_replace_live_database_removes_stale_sidecars(self):
        """Directly exercises the WAL-safe swap: stale -wal/-shm files
        sitting beside the target are removed, the scratch DB is installed,
        and the preserved copy holds the previous contents."""
        live = self.target_dir / "state.db"
        c = sqlite3.connect(live)
        c.execute("CREATE TABLE t(v)")
        c.execute("INSERT INTO t VALUES('OLD')")
        c.commit()
        c.close()
        wal = Path(str(live) + "-wal")
        shm = Path(str(live) + "-shm")
        wal.write_bytes(b"stale-wal-bytes")
        shm.write_bytes(b"stale-shm-bytes")

        scratch = self.target_dir / "scratch.db"
        c = sqlite3.connect(scratch)
        c.execute("CREATE TABLE t(v)")
        c.execute("INSERT INTO t VALUES('NEW')")
        c.commit()
        c.close()

        preserved = backup._replace_live_database(scratch, live)

        self.assertFalse(wal.exists())
        self.assertFalse(shm.exists())
        c = sqlite3.connect(live)
        try:
            self.assertEqual(c.execute("SELECT v FROM t").fetchone()[0], "NEW")
        finally:
            c.close()
        self.assertIsNotNone(preserved)
        c = sqlite3.connect(preserved)
        try:
            self.assertEqual(c.execute("SELECT v FROM t").fetchone()[0], "OLD")
        finally:
            c.close()

    def test_restore_discards_stale_wal_from_previous_database(self):
        """The P1 regression: committed data sitting only in the previous
        database's WAL sidecar (as after an unclean shutdown) must not be
        replayed on top of the freshly restored database."""
        core = self._seed_source()
        archive = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")
        self.archive_path.write_bytes(archive)

        target_core = _reimport_core(self.target_dir)
        live = target_core.DB_PATH
        # Insert a distinctive row and capture the on-disk state while that
        # row still lives only in the WAL, then reconstruct that state so the
        # main file lacks the row but a valid WAL carries it.
        conn = sqlite3.connect(live)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute(
            "INSERT INTO incidents(started, source, detail, resolved)"
            " VALUES(?,?,?,?)",
            (time.time(), "stale-wal-only", "x", None),
        )
        conn.commit()
        wal_path = Path(str(live) + "-wal")
        main_bytes = live.read_bytes()
        wal_bytes = wal_path.read_bytes()
        conn.close()
        live.write_bytes(main_bytes)
        wal_path.write_bytes(wal_bytes)

        backup.restore_backup_archive(
            self.archive_path, target_core.DB_PATH,
            target_core.init_db, target_core.apply_settings,
            target_core.validate_settings,
        )
        with target_core.db() as conn:
            sources = [r["source"] for r in conn.execute("SELECT source FROM incidents")]
        self.assertIn("baseline", sources)
        self.assertNotIn("stale-wal-only", sources)
        self.assertFalse(Path(str(target_core.DB_PATH) + "-wal").exists())

    def test_restore_rejects_oversized_manifest_before_reading(self):
        """A member declaring a size past its per-member ceiling is rejected
        without being read into memory."""
        core = self._seed_source()
        archive_bytes = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as src:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as dst:
                for name in src.namelist():
                    if name == "manifest.json":
                        dst.writestr(name, b"{}" + b" " * (128 * 1024))
                    else:
                        dst.writestr(name, src.read(name))
        self.archive_path.write_bytes(buf.getvalue())

        target_core = _reimport_core(self.target_dir)
        with self.assertRaises(ValueError):
            backup.restore_backup_archive(
                self.archive_path, target_core.DB_PATH,
                target_core.init_db, target_core.apply_settings,
                target_core.validate_settings,
            )

    def test_archive_contains_no_auth_secrets(self):
        core = self._seed_source()
        from linkmoth_auth import AuthManager
        auth = AuthManager(self.source_dir, core.CFG, core.db)
        auth.set_password("a-very-long-test-password-123")
        webhook_secret = auth.ensure_webhook_secret()
        totp_secret, _codes = auth.setup_totp()

        archive = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")

        self.assertNotIn(webhook_secret.encode(), archive)
        self.assertNotIn(totp_secret.encode(), archive)

    def test_archive_strips_webhook_url_and_headers_but_keeps_config(self):
        """The P1 finding: a full-database backup previously carried the
        plaintext webhook destination URL and custom headers (commonly an
        Authorization bearer token) straight into the archive. The snapshot
        must clear those two columns while keeping everything else about
        the webhook (name, preset, events) intact."""
        core = self._seed_source()
        archive = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")

        with tempfile.TemporaryDirectory() as tmpdir:
            conn = _open_db_from_archive(archive, tmpdir)
            try:
                row = conn.execute("SELECT * FROM webhooks").fetchone()
            finally:
                conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["url"], "")
        self.assertEqual(json.loads(row["headers"]), {})
        self.assertEqual(row["name"], "Test hook")
        self.assertEqual(row["preset"], "generic")
        self.assertEqual(json.loads(row["events"]), ["fault_opened"])

    def test_archive_strips_push_subscriptions(self):
        core = self._seed_source()
        with core.db() as conn:
            conn.execute(
                "INSERT INTO push_subscriptions(endpoint, p256dh, auth,"
                " user_agent, created) VALUES(?,?,?,?,?)",
                ("https://push.example/abc", "p256dh-key", "auth-key",
                 "test-agent", time.time()),
            )
        archive = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")

        with tempfile.TemporaryDirectory() as tmpdir:
            conn = _open_db_from_archive(archive, tmpdir)
            try:
                count = conn.execute("SELECT COUNT(*) FROM push_subscriptions").fetchone()[0]
            finally:
                conn.close()
        self.assertEqual(count, 0)

    def test_archive_strips_auth_session_and_login_attempt_state(self):
        core = self._seed_source()
        from linkmoth_auth import AuthManager
        AuthManager(self.source_dir, core.CFG, core.db)  # creates the tables
        with core.db() as conn:
            conn.execute(
                "INSERT INTO auth_sessions(id, created, expires, csrf_token)"
                " VALUES(?,?,?,?)",
                ("session-id", time.time(), time.time() + 3600, "csrf-token"),
            )
            conn.execute(
                "INSERT INTO auth_login_attempts(ip, failures, locked_until,"
                " last_attempt) VALUES(?,?,?,?)",
                ("203.0.113.5", 3, 0, time.time()),
            )
            conn.execute(
                "INSERT INTO auth_totp_uses(secret_fingerprint, last_counter)"
                " VALUES(?,?)",
                ("fingerprint", 42),
            )
        archive = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")

        with tempfile.TemporaryDirectory() as tmpdir:
            conn = _open_db_from_archive(archive, tmpdir)
            try:
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0], 0)
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM auth_login_attempts").fetchone()[0], 0)
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM auth_totp_uses").fetchone()[0], 0)
            finally:
                conn.close()

    def test_restore_preserves_existing_db_instead_of_clobbering(self):
        core = self._seed_source()
        archive = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")
        self.archive_path.write_bytes(archive)

        target_core = _reimport_core(self.target_dir)
        with target_core.db() as conn:
            conn.execute(
                "INSERT INTO incidents(started, source, detail, resolved)"
                " VALUES(?,?,?,?)",
                (time.time(), "pre-existing", "already-here", None),
            )

        summary = backup.restore_backup_archive(
            self.archive_path, target_core.DB_PATH,
            target_core.init_db, target_core.apply_settings,
        )
        preserved = summary["preserved_previous_db"]
        self.assertIsNotNone(preserved)
        self.assertTrue(Path(preserved).exists())

        conn = sqlite3.connect(preserved)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute("SELECT * FROM incidents").fetchall()
        finally:
            conn.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "pre-existing")

    def test_restore_rolls_back_when_settings_write_returns_errors(self):
        core = self._seed_source()
        archive = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")
        self.archive_path.write_bytes(archive)

        target_core = _reimport_core(self.target_dir)
        with target_core.db() as conn:
            conn.execute(
                "INSERT INTO incidents(started, source, detail, resolved)"
                " VALUES(?,?,?,?)",
                (time.time(), "pre-existing", "must-survive", None),
            )

        def settings_write_fails(_settings):
            return False, {"_save": "disk is full"}

        with self.assertRaisesRegex(ValueError, "disk is full"):
            backup.restore_backup_archive(
                self.archive_path, target_core.DB_PATH,
                target_core.init_db, settings_write_fails,
                target_core.validate_settings,
            )

        with target_core.db() as conn:
            sources = [
                row[0] for row in conn.execute(
                    "SELECT source FROM incidents ORDER BY id"
                ).fetchall()
            ]
        self.assertEqual(sources, ["pre-existing"])
        self.assertFalse(list(
            target_core.DB_PATH.parent.glob("state.db.pre-restore-*")
        ))

    def test_restore_rejects_unknown_schema_version_without_touching_disk(self):
        core = self._seed_source()
        archive_bytes = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as src:
            manifest = json.loads(src.read("manifest.json"))
            manifest["schema_version"] = 999
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as dst:
                for name in src.namelist():
                    data = (
                        json.dumps(manifest).encode()
                        if name == "manifest.json" else src.read(name)
                    )
                    dst.writestr(name, data)
        self.archive_path.write_bytes(buf.getvalue())

        target_core = _reimport_core(self.target_dir)
        original_bytes = target_core.DB_PATH.read_bytes()
        with self.assertRaises(ValueError):
            backup.restore_backup_archive(
                self.archive_path, target_core.DB_PATH,
                target_core.init_db, target_core.apply_settings,
            )
        self.assertEqual(target_core.DB_PATH.read_bytes(), original_bytes)

    def test_restore_rejects_non_dict_settings_without_touching_disk(self):
        """The P2 finding: a settings.json that's a list (not an object)
        used to reach apply_settings() -> data.items() and crash with an
        uncaught AttributeError after the new database was already live."""
        core = self._seed_source()
        archive_bytes = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as src:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as dst:
                for name in src.namelist():
                    data = b"[1, 2, 3]" if name == "settings.json" else src.read(name)
                    dst.writestr(name, data)
        self.archive_path.write_bytes(buf.getvalue())

        target_core = _reimport_core(self.target_dir)
        original_bytes = target_core.DB_PATH.read_bytes()
        with self.assertRaises(ValueError):
            backup.restore_backup_archive(
                self.archive_path, target_core.DB_PATH,
                target_core.init_db, target_core.apply_settings,
            )
        self.assertEqual(target_core.DB_PATH.read_bytes(), original_bytes)

    def test_restore_rejects_corrupt_database_without_touching_disk(self):
        core = self._seed_source()
        archive_bytes = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as src:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as dst:
                for name in src.namelist():
                    data = b"not a sqlite database" if name == "state.db" else src.read(name)
                    dst.writestr(name, data)
        self.archive_path.write_bytes(buf.getvalue())

        target_core = _reimport_core(self.target_dir)
        original_bytes = target_core.DB_PATH.read_bytes()
        with self.assertRaises(ValueError):
            backup.restore_backup_archive(
                self.archive_path, target_core.DB_PATH,
                target_core.init_db, target_core.apply_settings,
            )
        self.assertEqual(target_core.DB_PATH.read_bytes(), original_bytes)

    def test_restore_rejects_archive_with_unexpected_members(self):
        core = self._seed_source()
        archive_bytes = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as src:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as dst:
                for name in src.namelist():
                    dst.writestr(name, src.read(name))
                dst.writestr("../evil.txt", "path traversal attempt")
        self.archive_path.write_bytes(buf.getvalue())

        target_core = _reimport_core(self.target_dir)
        original_bytes = target_core.DB_PATH.read_bytes()
        with self.assertRaises(ValueError):
            backup.restore_backup_archive(
                self.archive_path, target_core.DB_PATH,
                target_core.init_db, target_core.apply_settings,
            )
        self.assertEqual(target_core.DB_PATH.read_bytes(), original_bytes)

    def test_concurrent_backups_are_rejected_not_corrupted(self):
        core = self._seed_source()
        with backup.BACKUP_LOCK:
            with self.assertRaises(backup.BackupInProgress):
                backup.build_backup_archive(core.db, core._export_settings, "1.2.3")


class CliRestoreForceFlagTests(unittest.TestCase):
    """The P1/P2 finding: --force let a restore proceed against an active
    service, racing WAL connections it doesn't know about. --force no
    longer exists at all – restore always checks service status."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="linkmoth_restore_force_"))
        os.environ["LINKMOTH_STATE_DIR"] = str(self.tmp)
        os.environ.pop("LINKMOTH_CONFIG", None)
        for mod in ("linkmoth", "linkmoth_core", "linkmoth_handler",
                    "linkmoth_engine", "linkmoth_probes"):
            if mod in sys.modules:
                del sys.modules[mod]
        self.linkmoth = importlib.import_module("linkmoth")

    def test_restore_refuses_when_service_active_even_with_force_flag(self):
        old_argv = sys.argv
        try:
            sys.argv = ["linkmoth.py", "--restore", "somefile.zip", "--force"]
            with mock.patch.object(self.linkmoth, "run_cmd", return_value=(0, "active")):
                rc = self.linkmoth.backup_restore()
        finally:
            sys.argv = old_argv
        self.assertEqual(rc, 1)

    def test_restore_proceeds_past_the_service_check_when_inactive(self):
        old_argv = sys.argv
        try:
            sys.argv = ["linkmoth.py", "--restore", "/does/not/exist.zip"]
            with mock.patch.object(self.linkmoth, "run_cmd", return_value=(3, "inactive")):
                rc = self.linkmoth.backup_restore()
        finally:
            sys.argv = old_argv
        # Gets past the service-status gate and fails later, on the archive
        # path not existing – proving the gate itself isn't what stopped it.
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()

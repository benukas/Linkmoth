#!/usr/bin/env python3
"""Tests for linkmoth_backup: the portable, secret-free backup/restore
archive (history, settings, device/webhook config -- no auth.json secrets,
no VAPID key, no TLS CA)."""
import importlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
REPO_ROOT = BASE.parent
sys.path.insert(0, str(REPO_ROOT))

import linkmoth_backup as backup


def _reimport_core(state_dir):
    """Fresh linkmoth_core bound to a new state directory, matching the
    module-cache-reset pattern used throughout this test suite -- linkmoth_
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

    def test_archive_contains_no_secrets(self):
        core = self._seed_source()
        from linkmoth_auth import AuthManager
        auth = AuthManager(self.source_dir, core.CFG, core.db)
        auth.set_password("a-very-long-test-password-123")
        webhook_secret = auth.ensure_webhook_secret()
        totp_secret, _codes = auth.setup_totp()

        archive = backup.build_backup_archive(core.db, core._export_settings, "1.2.3")

        self.assertNotIn(webhook_secret.encode(), archive)
        self.assertNotIn(totp_secret.encode(), archive)

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

        import sqlite3
        conn = sqlite3.connect(preserved)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute("SELECT * FROM incidents").fetchall()
        finally:
            conn.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "pre-existing")

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


if __name__ == "__main__":
    unittest.main()

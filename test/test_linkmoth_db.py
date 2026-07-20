#!/usr/bin/env python3
"""Tests for SQLite maintenance helpers and API."""
import importlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))


class DbMaintenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = Path(tempfile.mkdtemp(prefix="linkmoth_db_"))
        os.environ["LINKMOTH_STATE_DIR"] = str(cls.state)
        for _mod in ("linkmoth", 'linkmoth_core', 'linkmoth_probes', 'linkmoth_engine', 'linkmoth_handler'):
            if _mod in sys.modules:
                del sys.modules[_mod]
        cls.linkmoth = importlib.import_module("linkmoth")
        global linkmoth_core
        linkmoth_core = importlib.import_module("linkmoth_core")
        cls.linkmoth.init_db()

    def test_db_info_reports_auto_vacuum(self):
        info = self.linkmoth.db_maintenance_info()
        self.assertTrue(info["exists"])
        self.assertGreater(info["size_bytes"], 0)
        self.assertIn(info["auto_vacuum_label"], ("NONE", "FULL", "INCREMENTAL"))
        self.assertEqual(info["journal_mode"], "WAL")
        self.assertEqual(info["busy_timeout_ms"], self.linkmoth.DB_BUSY_TIMEOUT_MS)

    def test_init_db_upgrades_an_existing_delete_journal_to_wal(self):
        legacy_path = self.state / "legacy-delete-journal.db"
        conn = sqlite3.connect(legacy_path)
        try:
            conn.execute("PRAGMA journal_mode = DELETE")
            conn.execute("CREATE TABLE legacy_data(value TEXT)")
            conn.commit()
        finally:
            conn.close()

        original_path = linkmoth_core.DB_PATH
        try:
            linkmoth_core.DB_PATH = legacy_path
            self.linkmoth.init_db()
            self.assertEqual(
                self.linkmoth.db_maintenance_info()["journal_mode"], "WAL"
            )
        finally:
            linkmoth_core.DB_PATH = original_path

    @unittest.skipIf(os.name == "nt", "Windows does not expose POSIX mode bits")
    def test_state_database_is_owner_readable_only(self):
        self.assertEqual(self.linkmoth.DB_PATH.stat().st_mode & 0o777, 0o600)

    def test_vacuum_succeeds_on_fresh_db(self):
        engine = self.linkmoth.Engine()
        ok, result = self.linkmoth.vacuum_database(engine)
        self.assertTrue(ok)
        self.assertIn("size_after_bytes", result)
        self.assertGreaterEqual(result["bytes_reclaimed"], 0)

    def test_vacuum_blocks_during_diagnosis(self):
        engine = self.linkmoth.Engine()
        engine.run_in_progress = True
        ok, result = self.linkmoth.vacuum_database(engine)
        self.assertFalse(ok)
        self.assertIn("diagnosis in progress", result["error"])

    def test_vacuum_reclaims_space_after_bulk_delete(self):
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO runs(incident_id, ts, severity, code, title, explain, hint, checks, duration_ms)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (None, 1.0, "ok", "all_clear", "t", "", "", "[]", 1.0),
            )
        size_before = self.linkmoth.DB_PATH.stat().st_size
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM runs")
        engine = self.linkmoth.Engine()
        ok, result = self.linkmoth.vacuum_database(engine)
        self.assertTrue(ok)
        self.assertLessEqual(self.linkmoth.DB_PATH.stat().st_size, size_before)

    def test_ensure_auto_vacuum_reports_mode(self):
        mode, _ = self.linkmoth.ensure_auto_vacuum()
        info = self.linkmoth.db_maintenance_info()
        self.assertEqual(mode, info["auto_vacuum"])
        self.assertEqual(info["auto_vacuum"], self.linkmoth.AUTO_VACUUM_MODE)

    def test_auto_vacuum_skips_when_no_freelist(self):
        engine = self.linkmoth.Engine()
        self.linkmoth.auto_vacuum(engine)  # should not raise


if __name__ == "__main__":
    unittest.main()

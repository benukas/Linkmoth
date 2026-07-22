#!/usr/bin/env python3
"""Tests for SQLite maintenance helpers and API."""
import importlib
import json
import os
import sqlite3
import sys
import tempfile
import time
import traceback
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


class ReentrantDbTests(unittest.TestCase):
    """db() reuses an already-open connection on the same thread, so
    composed read paths stop paying a connect/close round trip per helper.
    The outermost block keeps ownership of commit, rollback and close."""

    @classmethod
    def setUpClass(cls):
        cls.state = Path(tempfile.mkdtemp(prefix="linkmoth_reentrant_"))
        os.environ["LINKMOTH_STATE_DIR"] = str(cls.state)
        # Purge every linkmoth module, not just the handful this test names
        # directly. status() fans out through linkmoth_outage, _push and
        # _notify too; if those are left bound to an earlier test's now-stale
        # linkmoth_core, their db() sees a different thread-local than the one
        # status() populated and opens a second connection. Reloading the
        # whole graph together reproduces production, where nothing reloads
        # and every module shares one core.
        for _mod in [m for m in list(sys.modules) if m.startswith("linkmoth")]:
            del sys.modules[_mod]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.core = importlib.import_module("linkmoth_core")
        cls.linkmoth.init_db()

    def test_nested_block_reuses_the_same_connection(self):
        with self.core.db() as outer:
            with self.core.db() as inner:
                self.assertIs(inner, outer)

    def test_outer_block_commits_work_done_in_a_nested_block(self):
        with self.core.db() as conn:
            conn.execute("DELETE FROM app_meta WHERE key='reentrant'")
        with self.core.db():
            with self.core.db() as inner:
                inner.execute(
                    "INSERT INTO app_meta(key, value) VALUES('reentrant','yes')")
        with self.core.db() as conn:
            row = conn.execute(
                "SELECT value FROM app_meta WHERE key='reentrant'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["value"], "yes")

    def test_failure_in_a_nested_block_rolls_the_whole_thing_back(self):
        with self.core.db() as conn:
            conn.execute("DELETE FROM app_meta WHERE key='rollback'")
        with self.assertRaises(RuntimeError):
            with self.core.db() as outer:
                outer.execute(
                    "INSERT INTO app_meta(key, value) VALUES('rollback','x')")
                with self.core.db():
                    raise RuntimeError("nested failure")
        with self.core.db() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM app_meta WHERE key='rollback'").fetchone()[0]
        self.assertEqual(count, 0)

    def test_connection_state_is_cleared_after_the_outer_block(self):
        with self.core.db():
            pass
        self.assertIsNone(getattr(self.core._DB_REENTRANT, "active", None))

    def test_each_thread_gets_its_own_connection(self):
        import threading
        seen, lock = {}, threading.Lock()

        def worker(index):
            with self.core.db() as conn:
                with lock:
                    seen[index] = id(conn)
                time.sleep(0.05)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(set(seen.values())), 4)

    def test_a_different_target_still_opens_its_own_connection(self):
        other = self.state / "other.db"
        with self.core.db() as outer:
            with self.core.db(other) as inner:
                self.assertIsNot(inner, outer)

    def test_status_uses_a_single_connection(self):
        """The reason the re-entrancy exists: /api/status is polled every
        few seconds and used to fan out to a dozen connections."""
        engine = self.linkmoth.Engine()
        engine.status()
        opened = []
        real_connect = sqlite3.connect

        def counting(*args, **kwargs):
            # Record where each connection came from. A bare count tells you
            # the fan-out regressed but not which helper stopped reusing the
            # open connection, which is the only thing worth knowing here.
            opened.append(traceback.extract_stack()[:-1])
            return real_connect(*args, **kwargs)

        sqlite3.connect = counting
        try:
            engine.status()
        finally:
            sqlite3.connect = real_connect
        self.assertEqual(len(opened), 1, self._describe_connections(opened))

    @staticmethod
    def _describe_connections(opened):
        lines = []
        for index, stack in enumerate(opened, 1):
            caller = next(
                (f for f in reversed(stack) if "linkmoth" in f.filename), None)
            lines.append(
                f"connection {index} opened from "
                + (f"{Path(caller.filename).name}:{caller.lineno} "
                   f"in {caller.name}()" if caller else "unknown"))
        return "status() opened more than one connection:\n" + "\n".join(lines)


if __name__ == "__main__":
    unittest.main()

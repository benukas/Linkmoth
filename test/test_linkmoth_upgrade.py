#!/usr/bin/env python3
"""Upgrading an existing installation must migrate, not break.

Every release runs init_db() against whatever database the previous version
left behind. That path had no test starting from a genuinely old schema, so a
new column or table could be added without anything catching that upgrades
from an early install stopped working – and the failure would land on users
mid-upgrade, with their history already on disk.

This builds the earliest known schema (runs without `kind`; incidents without
ref, false_alarm, diagnosis_*, or recovered_at; none of the later tables),
migrates it, and then drives the read paths an upgraded install hits
immediately: the dashboard status payload, history, patterns, the
accountability report and its exports, the health score, and warnings.
"""
import importlib
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent))

# The schema as it shipped before `kind`, incident refs, false alarms,
# historical diagnosis fields, recovery timestamps, and every later table.
OLDEST_SCHEMA = """
CREATE TABLE incidents(
  id INTEGER PRIMARY KEY, started REAL NOT NULL, resolved REAL,
  source TEXT, detail TEXT, verdict_code TEXT, verdict_title TEXT);
CREATE TABLE runs(
  id INTEGER PRIMARY KEY, incident_id INTEGER, ts REAL NOT NULL,
  severity TEXT NOT NULL, code TEXT NOT NULL, title TEXT NOT NULL,
  explain TEXT, hint TEXT, checks TEXT NOT NULL, duration_ms REAL);
"""

ADDED_INCIDENT_COLUMNS = ("ref", "false_alarm", "diagnosis_code",
                          "diagnosis_title", "recovered_at")
ADDED_TABLES = ("quality_samples", "load_tests", "incident_outage_segments",
                "dismissed_warnings", "webhooks", "devices")


class UpgradeFromOldestSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = Path(tempfile.mkdtemp(prefix="linkmoth_upgrade_"))
        db_path = cls.state / "state.db"
        cls.now = time.time()
        conn = sqlite3.connect(db_path)
        conn.executescript(OLDEST_SCHEMA)
        conn.execute(
            "INSERT INTO incidents(started, resolved, source, detail,"
            " verdict_code, verdict_title) VALUES(?,?,?,?,?,?)",
            (cls.now - 7200, cls.now - 3600, "baseline", "pre-upgrade",
             "wan_down", "Internet is dead beyond the router"),
        )
        conn.execute(
            "INSERT INTO runs(incident_id, ts, severity, code, title, explain,"
            " hint, checks, duration_ms) VALUES(?,?,?,?,?,?,?,?,?)",
            (1, cls.now - 7200, "bad", "wan_down", "WAN down", "dead", "check",
             json.dumps([{"id": "raw_ping", "label": "Internet ping",
                          "ok": False, "detail": "no reply"}]), 5.0),
        )
        conn.commit()
        conn.close()

        os.environ["LINKMOTH_STATE_DIR"] = str(cls.state)
        os.environ.pop("LINKMOTH_CONFIG", None)
        for mod in [m for m in list(sys.modules) if m.startswith("linkmoth")]:
            del sys.modules[mod]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.probes = importlib.import_module("linkmoth_probes")
        cls.linkmoth.init_db()  # the upgrade under test
        cls.engine = cls.linkmoth.Engine()

    def test_missing_columns_and_tables_are_added(self):
        with self.linkmoth.db() as conn:
            columns = {r[1] for r in conn.execute("PRAGMA table_info(incidents)")}
            run_columns = {r[1] for r in conn.execute("PRAGMA table_info(runs)")}
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        for column in ADDED_INCIDENT_COLUMNS:
            self.assertIn(column, columns, f"incidents.{column} not migrated")
        self.assertIn("kind", run_columns)
        for table in ADDED_TABLES:
            self.assertIn(table, tables, f"{table} not created on upgrade")

    def test_existing_history_is_preserved_and_backfilled(self):
        """Pre-upgrade rows keep their evidence and gain the derived fields
        the new code reads, rather than being dropped or left half-populated."""
        with self.linkmoth.db() as conn:
            inc = dict(conn.execute(
                "SELECT * FROM incidents WHERE id=1").fetchone())
            segments = conn.execute(
                "SELECT COUNT(*) FROM incident_outage_segments").fetchone()[0]
        self.assertEqual(inc["verdict_code"], "wan_down")
        self.assertTrue(inc["ref"], "incident reference was not backfilled")
        # The historical diagnosis is derived from the existing attribution,
        # never invented.
        self.assertEqual(inc["diagnosis_code"], "wan_down")
        self.assertEqual(segments, 1, "outage segments were not backfilled")

    def test_the_dashboard_status_payload_builds_after_upgrade(self):
        status = self.engine.status()
        self.assertEqual(len(status["incidents"]), 1)
        self.assertTrue(status["last_run"])
        self.assertEqual(status["stats"]["incidents_30d"], 1)

    def test_reports_and_exports_build_after_upgrade(self):
        report = self.engine.isp_report(30)
        self.assertEqual(report["incident_count"], 1)
        self.assertTrue(self.probes.isp_report_letter(report))
        self.assertTrue(self.probes.isp_report_csv(report))

    def test_newer_read_paths_tolerate_pre_upgrade_data(self):
        """Features added after this schema must not assume their own tables
        were populated by anything."""
        self.assertEqual(self.engine.warnings_list(), [])
        self.assertFalse(
            self.probes.connection_score(use_cache=False)["graded"])
        self.assertTrue(self.engine.patterns(code="wan_down"))
        self.assertEqual(len(self.engine.history()), 1)

    def test_migration_is_idempotent(self):
        """init_db runs on every start, not just the first after an upgrade."""
        self.linkmoth.init_db()
        self.linkmoth.init_db()
        with self.linkmoth.db() as conn:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 1)
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM incident_outage_segments").fetchone()[0],
                1, "backfill duplicated rows on a second run")


if __name__ == "__main__":
    unittest.main()

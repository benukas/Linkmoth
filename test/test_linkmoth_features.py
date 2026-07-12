#!/usr/bin/env python3
"""Tests for guided-troubleshooting verify and outage-correlation patterns."""
import importlib
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))


def make_checks(**overrides):
    base = {
        "power": True, "link": True, "gateway": True, "router_wlan": None,
        "pihole_dns": True, "upstream_dns": True, "raw_ping": True, "https": True,
    }
    base.update(overrides)
    return [
        {"id": cid, "label": cid, "ok": ok, "detail": "d", "ms": None, "micro": []}
        for cid, ok in base.items()
    ]


def ts_at_hour(hour, day_offset=0):
    now = time.localtime()
    lt = (now.tm_year, now.tm_mon, now.tm_mday - day_offset, hour, 0, 0, 0, 0, -1)
    return time.mktime(lt)


class VerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_verify_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def setUp(self):
        from linkmoth_outage import OUTAGE_TRACKER
        OUTAGE_TRACKER._consecutive_clear = 0
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM runs")
            conn.execute("DELETE FROM incidents")

    def tearDown(self):
        from linkmoth_outage import OUTAGE_TRACKER
        OUTAGE_TRACKER._consecutive_clear = 0

    def test_force_bypasses_populated_cache(self):
        engine = self.linkmoth.Engine()
        checks = make_checks()
        engine._store_ladder_cache(checks, 1.0, self.linkmoth.verdict(checks))
        calls = []

        def fake_ladder():
            calls.append(1)
            return make_checks(), 2.0

        with mock.patch.object(self.linkmoth, "run_ladder", side_effect=fake_ladder):
            engine.diagnose_once(kind="manual", force=False)
            self.assertEqual(len(calls), 0)  # fresh cache reused
            engine.diagnose_once(kind="verify", force=True)
            self.assertEqual(len(calls), 1)  # forced past the cache

    def test_verify_fix_persists_verify_run(self):
        engine = self.linkmoth.Engine()
        with mock.patch.object(self.linkmoth, "run_ladder",
                               return_value=(make_checks(), 1.0)):
            result = engine.verify_fix()
        self.assertIsNotNone(result)
        v, checks = result
        self.assertEqual(v["code"], "all_clear")
        with self.linkmoth.db() as conn:
            row = conn.execute(
                "SELECT kind FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["kind"], "verify")

    def test_verify_cooldown(self):
        engine = self.linkmoth.Engine()
        self.assertEqual(engine.verify_cooldown_remaining(), 0.0)
        self.assertGreater(engine.verify_cooldown_remaining(), 0.0)


class PatternTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_pat_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def setUp(self):
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM incidents")

    def _add(self, started, resolved, code="wan_down"):
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO incidents(started, source, detail, resolved,"
                " verdict_code, verdict_title, ref) VALUES(?,?,?,?,?,?,?)",
                (started, "test", "", resolved, code, "t", None),
            )

    def test_single_incident_has_no_pattern_tier(self):
        self._add(ts_at_hour(3), ts_at_hour(3) + 120)
        p = self.linkmoth.Engine().patterns(code="wan_down")
        self.assertEqual(p["count"], 1)
        self.assertIsNone(p["tier"])
        self.assertIsNone(p["clusters_hour_range"])

    def test_two_incidents_are_recurrence_not_pattern(self):
        self._add(ts_at_hour(3, 0), ts_at_hour(3, 0) + 60)
        self._add(ts_at_hour(3, 1), ts_at_hour(3, 1) + 180)
        p = self.linkmoth.Engine().patterns(code="wan_down")
        self.assertEqual(p["count"], 2)
        self.assertEqual(p["tier"], "recurrence")
        self.assertIsNone(p["clusters_hour_range"])
        self.assertIsNotNone(p["median_duration_s"])
        self.assertIsNotNone(p["median_gap_s"])

    def test_three_spread_has_no_time_cluster(self):
        for h, d in ((2, 0), (10, 1), (18, 2)):
            self._add(ts_at_hour(h, d), ts_at_hour(h, d) + 100)
        p = self.linkmoth.Engine().patterns(code="wan_down")
        self.assertEqual(p["count"], 3)
        self.assertEqual(p["tier"], "pattern")
        self.assertIsNone(p["clusters_hour_range"])

    def test_three_clustered_reports_time_range(self):
        for d in (0, 1, 2):
            self._add(ts_at_hour(3, d), ts_at_hour(3, d) + 100)
        p = self.linkmoth.Engine().patterns(code="wan_down")
        self.assertEqual(p["tier"], "pattern")
        self.assertIsNotNone(p["clusters_hour_range"])
        # The reported 4h window must actually contain the 03:00 cluster.
        start_h = int(p["clusters_hour_range"][:2])
        self.assertLessEqual(start_h, 3)
        self.assertLess(3, start_h + 4)

    def test_all_clear_excluded_from_patterns(self):
        self._add(ts_at_hour(3), ts_at_hour(3) + 60, code="all_clear")
        self.assertIsNone(self.linkmoth.Engine().patterns(code="all_clear"))


if __name__ == "__main__":
    unittest.main()

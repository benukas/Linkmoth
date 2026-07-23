#!/usr/bin/env python3
"""Tests for warnings_list: faults that were seen but never became incidents.

A warning must not open an incident – an incident means an actual fault, and
letting warnings create them would corrupt uptime, downtime and the
accountability report. But every diagnosis is already stored in `runs` with its
full evidence ladder, so a warning that never escalated was recorded and simply
had nowhere to be read. These tests pin that it is now readable, and that it
stays out of the incident record.
"""
import importlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent))

LADDER = json.dumps([{"id": "power", "label": "Host power",
                      "detail": "undervoltage now", "ok": False}])


class WarningsListTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = Path(tempfile.mkdtemp(prefix="linkmoth_warn_"))
        os.environ["LINKMOTH_STATE_DIR"] = str(cls.state)
        os.environ.pop("LINKMOTH_CONFIG", None)
        for mod in [m for m in list(sys.modules) if m.startswith("linkmoth")]:
            del sys.modules[mod]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def setUp(self):
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM runs")
            conn.execute("DELETE FROM incidents")
        self.engine = self.linkmoth.Engine()
        self.now = time.time()

    def _run(self, ts, severity="warn", code="host_power", incident_id=None,
             title="Linkmoth host power is unstable"):
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO runs(incident_id, ts, severity, code, title, explain,"
                " hint, checks, kind) VALUES(?,?,?,?,?,?,?,?,?)",
                (incident_id, ts, severity, code, title, "explain", "hint",
                 LADDER, "baseline"))

    def _incident(self):
        with self.linkmoth.db() as conn:
            return conn.execute(
                "INSERT INTO incidents(started, source, detail) VALUES(?,?,?)",
                (self.now - 500, "baseline", "x")).lastrowid

    def test_a_warning_that_never_escalated_is_readable(self):
        self._run(self.now - 300)
        found = self.engine.warnings_list()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["code"], "host_power")
        self.assertEqual(found[0]["severity"], "warn")
        self.assertEqual(found[0]["count"], 1)

    def test_the_evidence_ladder_is_carried_so_it_can_be_opened(self):
        """The whole complaint was seeing that a warning happened with no way
        to read it, so the stored ladder must come along."""
        self._run(self.now - 300)
        checks = self.engine.warnings_list()[0]["checks"]
        self.assertTrue(checks)
        self.assertEqual(checks[0]["detail"], "undervoltage now")

    def test_runs_belonging_to_an_incident_are_not_listed_as_warnings(self):
        """Those are incidents; they already have a home in History."""
        self._run(self.now - 300, severity="bad", code="wan_down",
                  incident_id=self._incident())
        self.assertEqual(self.engine.warnings_list(), [])

    def test_healthy_runs_are_not_listed(self):
        self._run(self.now - 300, severity="ok", code="all_clear")
        self.assertEqual(self.engine.warnings_list(), [])

    def test_a_persistent_warning_collapses_into_one_episode(self):
        """Re-diagnosed every baseline interval, one fault would otherwise be
        hundreds of identical rows."""
        for i in range(12):
            self._run(self.now - 3600 + i * 300)
        found = self.engine.warnings_list()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["count"], 12)
        self.assertLess(found[0]["first_ts"], found[0]["last_ts"])

    def test_a_different_warning_in_between_does_not_split_an_episode(self):
        """Two warnings can be active at once and the baseline interleaves
        them; grouping by adjacency would tear one episode in half."""
        for i in range(12):
            self._run(self.now - 3600 + i * 300)
        self._run(self.now - 1800, code="link_degraded",
                  title="Host Ethernet link is degraded")
        by_code = {w["code"]: w for w in self.engine.warnings_list()}
        self.assertEqual(by_code["host_power"]["count"], 12)
        self.assertEqual(by_code["link_degraded"]["count"], 1)

    def test_the_same_code_after_a_long_gap_is_a_separate_episode(self):
        self._run(self.now - 300)
        self._run(self.now - 30000)
        found = [w for w in self.engine.warnings_list() if w["code"] == "host_power"]
        self.assertEqual(len(found), 2)

    def test_newest_episode_comes_first(self):
        self._run(self.now - 30000, code="link_degraded")
        self._run(self.now - 300, code="host_power")
        self.assertEqual(self.engine.warnings_list()[0]["code"], "host_power")

    def test_limit_is_respected(self):
        for i in range(8):
            self._run(self.now - i * 30000, code=f"code_{i}")
        self.assertEqual(len(self.engine.warnings_list(limit=3)), 3)

    def test_no_warnings_is_an_empty_list_not_an_error(self):
        self.assertEqual(self.engine.warnings_list(), [])


if __name__ == "__main__":
    unittest.main()

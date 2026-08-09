#!/usr/bin/env python3
"""What the uptime figure is measured over, and how that is described.

The uptime percentage is computed across a fixed thirty day window, and the
downtime feeding it is clipped to the same window. That pairing is correct and
has to stay: if the divisor were the full recorded history while the dividend
counted only thirty days, a long-running install would report an uptime far
better than it had.

The reported interval is therefore capped at thirty days too. Once an install
is older than that the figure stops moving, which is right, but the dashboard
called it "720.0 h monitored" and it read as an odometer that had jammed. A
number that never changes has to say why, so the payload now states whether it
sits at the cap rather than leaving the reader to infer it from a magic value.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent))

os.environ.setdefault("LINKMOTH_STATE_DIR",
                      tempfile.mkdtemp(prefix="linkmoth_uptime_"))
os.environ.pop("LINKMOTH_CONFIG", None)

import linkmoth  # noqa: E402
import linkmoth_core as core  # noqa: E402

DAY = 86400.0
WINDOW = 30 * DAY


class UptimeWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        linkmoth.init_db()

    def setUp(self):
        with core.db() as conn:
            for table in ("runs", "incidents", "incident_outage_segments"):
                conn.execute("DELETE FROM " + table)

    def history(self, days, outage_s=0):
        """Lay down a first run `days` ago and a check just now."""
        now = time.time()
        with core.db() as conn:
            for ts in (now - days * DAY, now - 60):
                conn.execute(
                    "INSERT INTO runs(incident_id, ts, severity, code, title,"
                    " explain, hint, checks, duration_ms, kind)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (None, ts, "ok", "all_ok", "ok", "", "", "[]", 10.0, "check"))
            if outage_s:
                started = now - 2 * DAY
                cur = conn.execute(
                    "INSERT INTO incidents(started, resolved, source, detail,"
                    " verdict_code, verdict_title) VALUES(?,?,?,?,?,?)",
                    (started, started + outage_s, "self-check", "auto",
                     "wan_down", "Internet is dead beyond the router"))
                conn.execute(
                    "INSERT INTO incident_outage_segments(incident_id, started,"
                    " ended) VALUES(?,?,?)",
                    (cur.lastrowid, started, started + outage_s))
        return linkmoth.ENGINE.stats()

    def test_a_young_install_reports_its_real_age(self):
        st = self.history(10)
        self.assertAlmostEqual(st["monitoring_interval_s"], 10 * DAY, delta=120)
        self.assertFalse(st["monitoring_capped"])

    def test_an_install_just_short_of_the_window_is_not_capped(self):
        st = self.history(29)
        self.assertAlmostEqual(st["monitoring_interval_s"], 29 * DAY, delta=120)
        self.assertFalse(st["monitoring_capped"])

    def test_an_older_install_stops_at_the_window_and_says_so(self):
        """The reported figure had frozen at exactly 720 hours with nothing to
        explain it, which is what prompted this."""
        for age in (31, 60, 400):
            with self.subTest(days=age):
                st = self.history(age)
                self.assertAlmostEqual(
                    st["monitoring_interval_s"], WINDOW, delta=120)
                self.assertTrue(
                    st["monitoring_capped"],
                    f"{age} days of history sits at the cap and did not say so")

    def test_the_uptime_percentage_still_divides_by_the_window(self):
        """The cap is load bearing. Dividing a window's worth of downtime by a
        year of history would report an uptime the install never had."""
        outage = 3 * 3600.0
        st = self.history(400, outage_s=outage)
        self.assertAlmostEqual(st["downtime_s"], outage, delta=5)
        expected = 100.0 * (1 - outage / WINDOW)
        self.assertAlmostEqual(st["uptime_pct"], round(expected, 2), delta=0.02)

    def test_an_install_with_no_history_reports_nothing_rather_than_zero(self):
        st = linkmoth.ENGINE.stats()
        self.assertEqual(st["monitoring_interval_s"], 0)
        self.assertIsNone(st["uptime_pct"])
        self.assertFalse(st["monitoring_capped"])


if __name__ == "__main__":
    unittest.main()

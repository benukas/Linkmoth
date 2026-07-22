#!/usr/bin/env python3
"""Tests for connection_score: the daily connection-health grade.

It is deliberately a pure read-only aggregation over evidence already
stored (quality_samples, load_tests, incident outage segments) – it must
never probe the network, and it must refuse to invent a grade for a day
that does not have enough samples behind it.
"""
import importlib
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
REPO_ROOT = BASE.parent
sys.path.insert(0, str(REPO_ROOT))


def _fresh(state_dir):
    os.environ["LINKMOTH_STATE_DIR"] = str(state_dir)
    os.environ.pop("LINKMOTH_CONFIG", None)
    for mod in ("linkmoth_core", "linkmoth_probes", "linkmoth_devices",
                "linkmoth_auth"):
        if mod in sys.modules:
            del sys.modules[mod]
    core = importlib.import_module("linkmoth_core")
    core.init_db()
    probes = importlib.import_module("linkmoth_probes")
    return core, probes


class ConnectionScoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="linkmoth_score_"))
        self.core, self.probes = _fresh(self.tmp)

    def _pinned_noon(self):
        """A clock pinned to local noon today, so tests that place an outage
        "an hour ago" stay inside the current local day. With a live clock the
        suite fails whenever it happens to run within an hour of midnight: the
        outage then lands in yesterday's bucket and today's grade never sees
        it. Seeding and scoring must share this same pinned now."""
        noon = self.probes._day_start(time.time()) + 12 * 3600
        return mock.patch.object(self.probes.time, "time", return_value=noon)

    def _seed(self, days=30, latency=18.0, jitter=2.0, loss=0.0,
              per_day=24, override=None):
        """Fill quality_samples with `per_day` samples for each of the last
        `days` local days. `override` maps days-ago -> latency for a
        degraded stretch.

        Samples are spread across each day's own elapsed window rather than
        offset by a flat 86400s from now, so every sample lands in the local
        day it belongs to. A flat offset smears samples across the midnight
        boundary and quietly dilutes the day being tested.
        """
        override = override or {}
        now = time.time()
        today_start = self.probes._day_start(now)
        with self.core.db() as conn:
            for ago in range(days - 1, -1, -1):
                day_start = self.probes._shift_day_start(today_start, -ago)
                next_start = self.probes._shift_day_start(today_start, -ago + 1)
                day_end = min(next_start - 1, now)
                span = max(1.0, day_end - day_start)
                value = override.get(ago, latency)
                for index in range(per_day):
                    ts = day_start + span * (index / max(1, per_day))
                    conn.execute(
                        "INSERT INTO quality_samples(ts, latency_ms, jitter_ms,"
                        " loss_pct, state) VALUES(?,?,?,?,?)",
                        (ts, value, jitter, loss, "good"),
                    )

    def test_empty_database_is_ungraded_and_does_not_raise(self):
        result = self.probes.connection_score()
        self.assertFalse(result["graded"])
        self.assertIsNone(result["score"])
        self.assertEqual(result["headline"], "Not enough data yet today.")
        self.assertEqual(len(result["history"]), 30)

    def test_steady_line_scores_well(self):
        self._seed()
        result = self.probes.connection_score()
        self.assertTrue(result["graded"])
        self.assertGreaterEqual(result["score"], 90)
        self.assertTrue(result["grade"].startswith("A"))

    def test_slow_but_steady_line_still_scores_well(self):
        """The grade is relative to this connection's own normal, so a
        consistently high-latency link is not permanently failed."""
        self._seed(latency=180.0)
        result = self.probes.connection_score()
        self.assertTrue(result["graded"])
        self.assertGreaterEqual(result["score"], 90)

    def test_latency_spike_against_baseline_lowers_todays_score(self):
        self._seed(latency=18.0, override={0: 90.0})
        result = self.probes.connection_score()
        self.assertTrue(result["graded"])
        self.assertLess(result["score"], 85)
        self.assertLessEqual(result["factors"]["latency"], -10)
        self.assertIn("latency", result["headline"])

    def test_packet_loss_is_penalised(self):
        self._seed(loss=3.0)
        result = self.probes.connection_score()
        self.assertLessEqual(result["factors"]["loss"], -20)
        self.assertLess(result["score"], 85)

    def test_day_below_sample_floor_is_ungraded_not_guessed(self):
        self._seed(days=30, per_day=1)  # 1 sample/day, under MIN_SCORE_SAMPLES
        result = self.probes.connection_score()
        self.assertFalse(result["graded"])
        self.assertTrue(all(d["score"] is None for d in result["history"]))

    def test_baseline_only_appears_once_there_is_enough_history(self):
        self._seed(days=3)
        short = self.probes.connection_score()
        self.assertIsNone(short["baseline_score"])
        self.assertIsNone(short["trend"])

        self.setUp()
        self._seed(days=30)
        full = self.probes.connection_score()
        self.assertIsNotNone(full["baseline_score"])
        self.assertIn(full["trend"], ("steady", "above", "below"))

    def test_bufferbloat_result_feeds_the_score(self):
        self._seed()
        clean = self.probes.connection_score(use_cache=False)["score"]
        with self.core.db() as conn:
            conn.execute(
                "INSERT INTO load_tests(ts, idle_ms, loaded_ms, bloat_ms, grade)"
                " VALUES(?,?,?,?,?)",
                (time.time(), 18.0, 400.0, 380.0, "F"),
            )
        bloated = self.probes.connection_score(use_cache=False)
        self.assertLess(bloated["score"], clean)
        self.assertLessEqual(bloated["factors"]["bufferbloat"], -15)

    def test_outage_time_is_penalised(self):
        with self._pinned_noon():
            self._seed()
            clean = self.probes.connection_score(use_cache=False)["score"]
            now = time.time()
            with self.core.db() as conn:
                cur = conn.execute(
                    "INSERT INTO incidents(started, source, detail, resolved)"
                    " VALUES(?,?,?,?)",
                    (now - 3600, "baseline", "wan_down", now - 1800),
                )
                conn.execute(
                    "INSERT INTO incident_outage_segments(incident_id, started, ended)"
                    " VALUES(?,?,?)",
                    (cur.lastrowid, now - 3600, now - 1800),
                )
            degraded = self.probes.connection_score(use_cache=False)
        self.assertLess(degraded["score"], clean)
        self.assertLessEqual(degraded["factors"]["downtime"], -20)

    def test_false_alarm_incident_does_not_count_as_downtime(self):
        with self._pinned_noon():
            self._seed()
            clean = self.probes.connection_score(use_cache=False)["score"]
            now = time.time()
            with self.core.db() as conn:
                cur = conn.execute(
                    "INSERT INTO incidents(started, source, detail, resolved,"
                    " false_alarm) VALUES(?,?,?,?,?)",
                    (now - 3600, "baseline", "wan_down", now - 1800, 1),
                )
                conn.execute(
                    "INSERT INTO incident_outage_segments(incident_id, started, ended)"
                    " VALUES(?,?,?)",
                    (cur.lastrowid, now - 3600, now - 1800),
                )
            degraded = self.probes.connection_score(use_cache=False)["score"]
        self.assertEqual(degraded, clean)

    def test_result_is_cached_between_status_polls(self):
        """/api/status is polled every few seconds by every open dashboard,
        but the grade is a per-day figure. Recomputing a 30-day aggregate on
        every poll would burn real CPU on a Pi for an answer that changes
        once a day, so repeat calls must be served from cache."""
        self._seed()
        first = self.probes.connection_score()
        with mock.patch.object(self.probes, "db") as db_mock:
            second = self.probes.connection_score()
        db_mock.assert_not_called()
        self.assertEqual(second, first)

    def test_cache_can_be_bypassed(self):
        self._seed()
        self.probes.connection_score()
        with mock.patch.object(self.probes, "db", wraps=self.core.db) as db_mock:
            self.probes.connection_score(use_cache=False)
        self.assertTrue(db_mock.called)

    def test_cache_is_keyed_by_window(self):
        self._seed()
        thirty = self.probes.connection_score(30)
        seven = self.probes.connection_score(7)
        self.assertEqual(len(thirty["history"]), 30)
        self.assertEqual(len(seven["history"]), 7)

    def test_out_of_range_timestamp_does_not_break_the_score(self):
        """A host without an RTC can record samples before NTP fixes its
        clock. localtime/mktime raise on those rows, and this runs inside
        /api/status – one bad row must not take the dashboard down."""
        self._seed()
        with self.core.db() as conn:
            for bad in (10**18, -8640000, 10**12):
                conn.execute(
                    "INSERT INTO quality_samples(ts, latency_ms, jitter_ms,"
                    " loss_pct, state) VALUES(?,?,?,?,?)",
                    (bad, 18.0, 2.0, 0.0, "good"),
                )
        result = self.probes.connection_score(use_cache=False)
        self.assertTrue(result["graded"])
        self.assertGreaterEqual(result["score"], 90)

    def test_unusable_timestamp_returns_none_rather_than_raising(self):
        for bad in (10**18, -8640000, 10**12):
            self.assertIsNone(self.probes._day_start(bad))
        self.assertIsNotNone(self.probes._day_start(time.time()))

    @unittest.skipUnless(hasattr(time, "tzset"), "requires POSIX timezone control")
    def test_calendar_days_remain_graded_across_dst_transition(self):
        old_tz = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "America/New_York"
            time.tzset()
            now = time.mktime((2025, 3, 10, 12, 0, 0, 0, 0, -1))
            today_start = self.probes._day_start(now)
            boundaries = [
                self.probes._shift_day_start(today_start, offset)
                for offset in (-2, -1, 0, 1)
            ]
            self.assertEqual(boundaries[2] - boundaries[1], 23 * 3600)

            with self.core.db() as conn:
                for start, end in zip(boundaries, boundaries[1:]):
                    end = min(end, now)
                    for index in range(6):
                        ts = start + (end - start) * ((index + 1) / 7)
                        conn.execute(
                            "INSERT INTO quality_samples(ts, latency_ms, jitter_ms,"
                            " loss_pct, state) VALUES(?,?,?,?,?)",
                            (ts, 18.0, 2.0, 0.0, "good"),
                        )

            with mock.patch.object(self.probes.time, "time", return_value=now):
                result = self.probes.connection_score(3, use_cache=False)
            self.assertEqual(
                [day["day"] for day in result["history"]],
                ["2025-03-08", "2025-03-09", "2025-03-10"],
            )
            self.assertTrue(all(day["score"] is not None for day in result["history"]))
        finally:
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
            time.tzset()

    def test_score_never_probes_the_network(self):
        """The whole premise of the feature: it reads stored evidence only."""
        self._seed()
        with mock.patch.object(self.probes, "run_cmd") as run_cmd, \
                mock.patch.object(self.probes, "measure_quality") as measure, \
                mock.patch.object(self.probes, "http_get") as http_get:
            self.probes.connection_score()
        run_cmd.assert_not_called()
        measure.assert_not_called()
        http_get.assert_not_called()

    def test_days_argument_is_clamped(self):
        self._seed(days=5)
        self.assertEqual(len(self.probes.connection_score(1)["history"]), 2)
        self.assertEqual(len(self.probes.connection_score(500)["history"]), 90)
        self.assertEqual(len(self.probes.connection_score(None)["history"]), 30)

    def test_zero_latency_baseline_does_not_divide_by_zero(self):
        self._seed(latency=0.0)
        result = self.probes.connection_score()
        self.assertTrue(result["graded"])
        self.assertEqual(result["factors"]["latency"], 0)


if __name__ == "__main__":
    unittest.main()

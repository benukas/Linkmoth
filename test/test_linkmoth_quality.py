#!/usr/bin/env python3
"""Tests for connection-quality parsing, classification, and measurement."""
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

GOOD_PING = """\
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=59 time=8.11 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=59 time=8.45 ms

--- 1.1.1.1 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 2718ms
rtt min/avg/max/mdev = 7.984/8.456/9.123/0.412 ms
"""

LOSSY_PING = """\
--- 8.8.8.8 ping statistics ---
10 packets transmitted, 7 received, 30% packet loss, time 9000ms
rtt min/avg/max/mdev = 20.0/45.5/120.0/30.2 ms
"""

DEAD_PING = """\
--- 8.8.8.8 ping statistics ---
10 packets transmitted, 0 received, 100% packet loss, time 9000ms
"""


class ParsePingStatsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_q_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.lm = importlib.import_module("linkmoth")

    def test_parses_full_stats(self):
        s = self.lm.parse_ping_stats(GOOD_PING)
        self.assertEqual(s["sent"], 10)
        self.assertEqual(s["received"], 10)
        self.assertEqual(s["loss_pct"], 0.0)
        self.assertAlmostEqual(s["min_ms"], 7.984)
        self.assertAlmostEqual(s["avg_ms"], 8.456)
        self.assertAlmostEqual(s["max_ms"], 9.123)
        self.assertAlmostEqual(s["jitter_ms"], 0.412)

    def test_parses_loss(self):
        s = self.lm.parse_ping_stats(LOSSY_PING)
        self.assertEqual(s["loss_pct"], 30.0)
        self.assertAlmostEqual(s["avg_ms"], 45.5)
        self.assertAlmostEqual(s["jitter_ms"], 30.2)

    def test_total_loss_has_no_latency(self):
        s = self.lm.parse_ping_stats(DEAD_PING)
        self.assertEqual(s["loss_pct"], 100.0)
        self.assertEqual(s["received"], 0)
        self.assertIsNone(s["avg_ms"])
        self.assertIsNone(s["jitter_ms"])

    def test_empty_output_is_all_none(self):
        s = self.lm.parse_ping_stats("")
        self.assertIsNone(s["avg_ms"])
        self.assertIsNone(s["loss_pct"])


class ClassifyQualityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_q_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.lm = importlib.import_module("linkmoth")
        cls.q = cls.lm.quality_config()

    def classify(self, latency, jitter, loss):
        return self.lm.classify_quality(latency, jitter, loss, self.q)["state"]

    def test_good(self):
        self.assertEqual(self.classify(8.0, 0.4, 0.0), "good")

    def test_elevated_latency_is_fair(self):
        self.assertEqual(self.classify(100.0, 0.4, 0.0), "fair")

    def test_bad_latency_is_poor(self):
        self.assertEqual(self.classify(250.0, 5.0, 0.0), "poor")

    def test_warn_loss_is_fair(self):
        self.assertEqual(self.classify(8.0, 0.4, 3.0), "fair")

    def test_bad_loss_is_poor(self):
        self.assertEqual(self.classify(8.0, 0.4, 30.0), "poor")

    def test_warn_jitter_is_fair(self):
        self.assertEqual(self.classify(8.0, 25.0, 0.0), "fair")

    def test_worst_signal_wins(self):
        # good latency but terrible loss -> poor
        self.assertEqual(self.classify(8.0, 0.4, 50.0), "poor")

    def test_no_measurement_is_unknown(self):
        v = self.lm.classify_quality(None, None, None, self.q)
        self.assertEqual(v["state"], "unknown")

    def test_reasons_are_reported(self):
        v = self.lm.classify_quality(300.0, 0.4, 0.0, self.q)
        self.assertTrue(any("latency" in r for r in v["reasons"]))


class MeasureQualityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_q_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.lm = importlib.import_module("linkmoth")

    def test_picks_best_responding_target(self):
        def fake_run_cmd(cmd, timeout=None):
            host = cmd[-1]
            return (0, GOOD_PING if host == "1.1.1.1" else LOSSY_PING)

        with mock.patch.object(self.lm, "run_cmd", side_effect=fake_run_cmd):
            sample = self.lm.measure_quality(["8.8.8.8", "1.1.1.1"], count=10)
        self.assertIsNotNone(sample)
        self.assertEqual(sample["target"], "1.1.1.1")
        self.assertAlmostEqual(sample["latency_ms"], 8.456)
        self.assertEqual(sample["loss_pct"], 0.0)

    def test_none_when_all_dead(self):
        with mock.patch.object(self.lm, "run_cmd", return_value=(1, "")):
            self.assertIsNone(self.lm.measure_quality(["1.1.1.1"], count=3))


class LoadTestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(
            prefix="linkmoth_load_"
        )
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.lm = importlib.import_module("linkmoth")
        cls.lm.init_db()

    def setUp(self):
        with self.lm.db() as conn:
            conn.execute("DELETE FROM load_tests")

    def test_url_must_be_public_https(self):
        with self.assertRaises(ValueError):
            self.lm._validate_load_url("http://speed.example.com/file")
        with self.assertRaises(ValueError):
            self.lm._validate_load_url("")
        # localhost resolves to loopback — must be refused.
        with self.assertRaises(ValueError):
            self.lm._validate_load_url("https://localhost/file")
        with mock.patch.object(
            self.lm.socket, "getaddrinfo",
            return_value=[(2, 1, 6, "", ("104.16.0.1", 443))],
        ):
            self.assertEqual(
                self.lm._validate_load_url("https://speed.example.com/file"),
                "https://speed.example.com/file",
            )

    def test_run_load_test_grades_and_stores(self):
        idle = {"latency_ms": 20.0, "jitter_ms": 2.0, "loss_pct": 0.0,
                "target": "1.1.1.1"}
        loaded = {"latency_ms": 70.0, "jitter_ms": 9.0, "loss_pct": 0.0,
                  "target": "1.1.1.1"}

        def fake_downloader(url, addresses, seconds, max_bytes, stats, stop):
            stats["bytes"] = 10 * 1024 * 1024
            stats["elapsed"] = 2.0

        with mock.patch.object(
            self.lm, "measure_quality", side_effect=[idle, loaded],
        ), mock.patch.object(
            self.lm, "_load_downloader", side_effect=fake_downloader,
        ), mock.patch.object(
            self.lm, "_resolve_load_target",
            return_value=(
                self.lm.urlparse("https://speed.example.com/file"),
                ["104.16.0.1"],
            ),
        ), mock.patch.object(self.lm.time, "sleep"):
            result = self.lm.run_load_test()
        self.assertEqual(result["grade"], "B")  # +50 ms bloat
        self.assertEqual(result["bloat_ms"], 50.0)
        self.assertEqual(result["idle_ms"], 20.0)
        self.assertEqual(result["loaded_ms"], 70.0)
        self.assertAlmostEqual(result["throughput_mbps"], 41.9, places=1)
        stored = self.lm.latest_load_test()
        self.assertIsNotNone(stored)
        self.assertEqual(stored["grade"], "B")

    def test_run_load_test_none_when_idle_unmeasurable(self):
        with mock.patch.object(
            self.lm, "measure_quality", return_value=None,
        ), mock.patch.object(
            self.lm, "_resolve_load_target",
            return_value=(
                self.lm.urlparse("https://speed.example.com/file"),
                ["104.16.0.1"],
            ),
        ):
            self.assertIsNone(self.lm.run_load_test())
        self.assertIsNone(self.lm.latest_load_test())

    def test_downloader_pins_validated_address_and_caps_exactly(self):
        response = mock.MagicMock()
        response.status = 200
        response.read.side_effect = [b"x" * 8, b"ignored"]
        conn = mock.MagicMock()
        conn.getresponse.return_value = response
        stats = {"bytes": 0, "elapsed": 0.0, "error": None}
        with mock.patch.object(
            self.lm, "_PinnedHTTPSConnection", return_value=conn,
        ) as pinned:
            self.lm._load_downloader(
                "https://speed.example.com/file?size=8",
                ["104.16.0.1"], 10, 8, stats, self.lm.threading.Event(),
            )
        self.assertEqual(pinned.call_args.args, ("speed.example.com", "104.16.0.1"))
        self.assertEqual(pinned.call_args.kwargs["port"], 443)
        conn.request.assert_called_once()
        self.assertEqual(conn.request.call_args.args[:2], ("GET", "/file?size=8"))
        self.assertEqual(stats["bytes"], 8)
        self.assertIsNone(stats["error"])
        self.assertEqual(response.read.call_count, 1)

    def test_downloader_rejects_redirects(self):
        response = mock.MagicMock()
        response.status = 302
        conn = mock.MagicMock()
        conn.getresponse.return_value = response
        stats = {"bytes": 0, "elapsed": 0.0, "error": None}
        with mock.patch.object(
            self.lm, "_PinnedHTTPSConnection", return_value=conn,
        ):
            self.lm._load_downloader(
                "https://speed.example.com/file", ["104.16.0.1"],
                10, 1024, stats, self.lm.threading.Event(),
            )
        self.assertEqual(stats["error"], "HTTP 302")
        self.assertEqual(stats["bytes"], 0)
        response.read.assert_not_called()

    def test_summary_carries_load_test(self):
        with self.lm.db() as conn:
            conn.execute(
                "INSERT INTO load_tests(ts, idle_ms, loaded_ms, bloat_ms,"
                " grade, throughput_mbps, bytes, seconds)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (1000.0, 20.0, 45.0, 25.0, "A", 88.2, 9999, 10.0),
            )
        summary = self.lm.quality_summary(limit=5)
        self.assertEqual(summary["load_test"]["grade"], "A")

    def test_summary_load_test_present_without_a_current_sample(self):
        # A fresh install (or baseline_minutes=0 "explainer" role) may have
        # no periodic ping sample yet — the load-test result must still be
        # reported so the dashboard isn't blocked from showing it.
        with self.lm.db() as conn:
            conn.execute("DELETE FROM quality_samples")
            conn.execute(
                "INSERT INTO load_tests(ts, idle_ms, loaded_ms, bloat_ms,"
                " grade, throughput_mbps, bytes, seconds)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (1000.0, 20.0, 45.0, 25.0, "A", 88.2, 9999, 10.0),
            )
        summary = self.lm.quality_summary(limit=5)
        self.assertIsNone(summary["current"])
        self.assertEqual(summary["load_test"]["grade"], "A")

    def test_summary_carries_load_test_config(self):
        summary = self.lm.quality_summary(limit=5)
        cfg = summary["load_test_config"]
        self.assertEqual(cfg["host"], "speed.cloudflare.com")
        self.assertEqual(cfg["max_mb"], 25)
        self.assertEqual(cfg["seconds"], 10)


class QualityFindingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(
            prefix="linkmoth_qfind_"
        )
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.lm = importlib.import_module("linkmoth")
        cls.lm.init_db()

    def setUp(self):
        with self.lm.db() as conn:
            conn.execute("DELETE FROM quality_samples")

    def _local_ts(self, days_ago, hour):
        import time as _time
        lt = _time.localtime(_time.time() - days_ago * 86400)
        stamp = (lt.tm_year, lt.tm_mon, lt.tm_mday, hour, 0, 0, 0, 0, -1)
        return _time.mktime(stamp)

    def _add(self, ts, latency, loss=0.0, state="good", jitter=2.0):
        with self.lm.db() as conn:
            conn.execute(
                "INSERT INTO quality_samples(ts, latency_ms, jitter_ms,"
                " loss_pct, state) VALUES(?,?,?,?,?)",
                (ts, latency, jitter, loss, state),
            )

    def test_too_few_samples_yield_no_findings(self):
        for i in range(5):
            self._add(self._local_ts(1, 9 + i % 3), 10.0)
        result = self.lm.quality_findings(7)
        self.assertEqual(result["findings"], [])

    def test_evening_degradation_is_called_out(self):
        for day in (1, 2, 3):
            for hour in (8, 9, 10):
                self._add(self._local_ts(day, hour), 15.0)
            for hour in (19, 20, 21):
                self._add(self._local_ts(day, hour), 90.0, state="fair")
        result = self.lm.quality_findings(7)
        text = " ".join(result["findings"])
        self.assertIn("Evening", text)
        self.assertIn("worse than morning", text)
        self.assertIn("evening", result["dayparts"])
        self.assertIn("morning", result["dayparts"])

    def test_loss_concentration_is_called_out(self):
        for day in (1, 2, 3):
            for hour in (8, 9, 10):
                self._add(self._local_ts(day, hour), 12.0, loss=0.0)
            for hour in (19, 20, 21):
                self._add(self._local_ts(day, hour), 14.0, loss=8.0,
                          state="poor")
        result = self.lm.quality_findings(7)
        text = " ".join(result["findings"])
        self.assertIn("Packet loss concentrates in the evening", text)

    def test_healthy_week_reports_all_clear(self):
        for day in (1, 2, 3):
            for hour in (8, 12, 16, 20):
                self._add(self._local_ts(day, hour), 11.0)
        result = self.lm.quality_findings(7)
        self.assertEqual(len(result["findings"]), 1)
        self.assertIn("No recurring quality problems", result["findings"][0])

    def test_summary_carries_findings(self):
        for day in (1, 2, 3):
            for hour in (8, 12, 16, 20):
                self._add(self._local_ts(day, hour), 11.0)
        summary = self.lm.quality_summary(limit=10)
        self.assertIn("findings", summary)
        self.assertEqual(summary["findings"]["sample_count"], 12)


if __name__ == "__main__":
    unittest.main()

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


if __name__ == "__main__":
    unittest.main()

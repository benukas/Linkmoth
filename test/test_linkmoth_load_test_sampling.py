#!/usr/bin/env python3
"""Latency-under-load sampling on connections of very different speeds.

The bufferbloat test only counts a ping that overlaps growing download bytes,
which is the right rule: a ping taken after the transfer finished measures an
idle network and would understate bloat. But the sampling loop paused a fixed
0.3 s between pings while the transfer is bounded by a total byte budget, so on
a fast line the budget was spent before a second ping could overlap it.

Measured on a real 650 Mbps link: the default 25 MB budget was gone in 0.31 s,
one sample overlapped, and the "at least two samples" guard rejected the run.
The feature could not produce a result at all above roughly 400 Mbps, and said
nothing about why.

These tests drive the real sampling loop on a simulated clock, so a transfer
that lasts 0.31 s and one that lasts the whole window are both exercised
without waiting or touching the network.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent))

os.environ.setdefault("LINKMOTH_STATE_DIR", tempfile.mkdtemp(prefix="linkmoth_lt_"))
os.environ.pop("LINKMOTH_CONFIG", None)

import linkmoth_probes as probes  # noqa: E402

PING_SECONDS = 0.006  # a 6 ms reply, matching the measured Pi
CHUNK = 65536


class FakeClock:
    """monotonic() only advances when something actually spends time."""

    def __init__(self):
        self.t = 0.0

    def monotonic(self):
        return self.t

    def sleep(self, duration):
        self.t += max(0.0, float(duration))


class LoadedSamplingTests(unittest.TestCase):
    def sample_loaded(self, transfer_seconds, window=10.0):
        """Run the real loop against a transfer that stops after N seconds."""
        clock = FakeClock()
        stats = {"bytes": 0}

        def fake_measure(targets, count=1):
            # A ping costs time; bytes only keep growing while the transfer
            # is still running, exactly as the downloader thread behaves.
            clock.t += PING_SECONDS
            if clock.t <= transfer_seconds:
                stats["bytes"] += CHUNK
            return {
                "latency_ms": 20.0, "jitter_ms": 1.0, "loss_pct": 0.0,
                "target": "1.1.1.1",
            }

        with mock.patch.object(probes, "time", clock), \
                mock.patch.object(probes, "measure_quality", fake_measure):
            result = probes._measure_loaded_quality("1.1.1.1", stats, window)
        return result, clock, stats

    def test_a_fast_line_that_spends_its_budget_quickly_still_measures(self):
        """The reported failure: 25 MB gone in 0.31 s on a 650 Mbps link."""
        result, _, _ = self.sample_loaded(transfer_seconds=0.31)
        self.assertIsNotNone(
            result, "a 0.31 s transfer produced no loaded measurement")
        self.assertGreaterEqual(result["active_samples"], 2)
        self.assertEqual(result["latency_ms"], 20.0)

    def test_an_extremely_fast_line_still_measures(self):
        """Twice as fast again: the budget is gone in 0.05 s."""
        result, _, _ = self.sample_loaded(transfer_seconds=0.05)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result["active_samples"], 2)

    def test_a_slow_line_that_loads_the_whole_window_still_measures(self):
        result, _, _ = self.sample_loaded(transfer_seconds=10.0)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result["active_samples"], 2)

    def test_sampling_does_not_flood_the_target_on_a_long_transfer(self):
        """Removing the pause must not turn a 10 s test into a ping flood."""
        result, _, _ = self.sample_loaded(transfer_seconds=10.0)
        self.assertLessEqual(
            result["active_samples"], 60,
            "the loop should cap how many probes a single test sends")

    def test_a_finished_transfer_stops_the_loop_early(self):
        """Once bytes stop growing there is no load left to measure, so the
        loop must not keep pinging an idle network until the deadline."""
        _, clock, _ = self.sample_loaded(transfer_seconds=0.31, window=10.0)
        self.assertLess(
            clock.t, 5.0,
            "kept sampling long after the transfer ended")

    def test_a_transfer_that_never_starts_yields_nothing(self):
        """No bytes ever move, so every ping measures an idle network. A grade
        built from those would be a fabricated result."""
        result, _, _ = self.sample_loaded(transfer_seconds=0.0)
        self.assertIsNone(result)

    def test_the_measured_load_window_is_reported(self):
        """How long the link was actually saturated decides how much the grade
        is worth, so the caller has to be able to see it."""
        result, _, _ = self.sample_loaded(transfer_seconds=0.31)
        self.assertIn("load_seconds", result)
        self.assertGreater(result["load_seconds"], 0.0)
        self.assertLessEqual(result["load_seconds"], 0.35)


class LoadTestReasonTests(unittest.TestCase):
    """Every way the test can fail has to say which one it was.

    The route logged a reason only when run_load_test() raised. Its three
    silent `return None` paths produced a generic "check connectivity" message
    and an empty journal, so a failure was reported truthfully and made
    undiagnosable at the same time.
    """

    URL = "https://speed.example.com/file"

    def run_test(self, *, targets=("1.1.1.1",), idle=True, loaded=None,
                 stats_after=None):
        cfg = {
            "targets": list(targets), "load_test_url": self.URL,
            "load_test_seconds": 10, "load_test_max_mb": 25,
        }
        idle_sample = (
            {"latency_ms": 8.0, "jitter_ms": 1.0, "loss_pct": 0.0,
             "target": "1.1.1.1"} if idle else None
        )

        def fake_downloader(url, addresses, seconds, max_bytes, stats, stop):
            stats.update(stats_after or {"bytes": 0, "elapsed": 0.0})

        with mock.patch.object(probes, "quality_config", return_value=cfg), \
                mock.patch.dict(probes.CFG, {"ping_targets": []}), \
                mock.patch.object(probes, "measure_quality",
                                  return_value=idle_sample), \
                mock.patch.object(probes, "_measure_loaded_quality",
                                  return_value=loaded), \
                mock.patch.object(probes, "_load_downloader",
                                  side_effect=fake_downloader), \
                mock.patch.object(probes, "_resolve_load_target",
                                  return_value=(probes.urlparse(self.URL),
                                                ["104.16.0.1"])), \
                mock.patch.object(probes.time, "sleep"):
            return probes.run_load_test(store=False)

    def assert_reason(self, fragment, **kwargs):
        with self.assertRaises(probes.LoadTestError) as caught:
            self.run_test(**kwargs)
        self.assertIn(fragment, str(caught.exception).lower())
        return str(caught.exception)

    def test_no_configured_targets_says_so(self):
        self.assert_reason("no ping targets", targets=())

    def test_unmeasurable_idle_latency_says_so(self):
        self.assert_reason("idle latency", idle=False)

    def test_an_unreachable_test_server_reports_the_transport_error(self):
        reason = self.assert_reason(
            "test server",
            stats_after={"bytes": 0, "elapsed": 0.0, "error": "HTTP 403"})
        self.assertIn("HTTP 403", reason)

    def test_a_transfer_that_never_started_says_so(self):
        self.assert_reason(
            "never started",
            stats_after={"bytes": 0, "elapsed": 0.0, "error": None})

    def test_a_transfer_too_short_to_measure_tells_the_user_what_to_change(self):
        """The reported case: the budget was spent before latency could be
        sampled. Naming the setting is the difference between a dead end and
        something the operator can act on."""
        reason = self.assert_reason(
            "load_test_max_mb",
            stats_after={"bytes": 25 * 1024 * 1024, "elapsed": 0.31,
                         "error": None})
        self.assertIn("25 MB", reason)
        self.assertIn("0.31", reason)

    def test_a_result_measured_over_a_brief_load_is_flagged_as_such(self):
        """A grade drawn from a third of a second is not worth as much as one
        drawn from the full window, and must not be presented as though it
        were."""
        loaded = {"latency_ms": 30.0, "jitter_ms": 2.0, "loss_pct": 0.0,
                  "target": "1.1.1.1", "active_samples": 10,
                  "load_seconds": 0.3}
        result = self.run_test(
            loaded=loaded,
            stats_after={"bytes": 25 * 1024 * 1024, "elapsed": 0.31,
                         "error": None})
        self.assertTrue(result["budget_limited"])
        self.assertEqual(result["load_seconds"], 0.3)
        self.assertEqual(result["grade"], "A")

    def test_a_result_from_a_full_window_is_not_flagged(self):
        loaded = {"latency_ms": 30.0, "jitter_ms": 2.0, "loss_pct": 0.0,
                  "target": "1.1.1.1", "active_samples": 60,
                  "load_seconds": 9.4}
        result = self.run_test(
            loaded=loaded,
            stats_after={"bytes": 12 * 1024 * 1024, "elapsed": 9.6,
                         "error": None})
        self.assertFalse(result["budget_limited"])


class ByteBudgetTests(unittest.TestCase):
    """The budget has to be able to reach a fast link.

    A gigabit line spends 25 MB in a third of a second. The default is now
    large enough to keep such a link loaded long enough to sample, and the
    ceiling leaves room to configure more. On a slow line none of this costs
    anything: the time limit is reached first and the budget is never
    approached.
    """

    URL = "https://speed.example.com/file"

    def budget_for(self, configured):
        seen = {}

        def fake_downloader(url, addresses, seconds, max_bytes, stats, stop):
            seen["max_bytes"] = max_bytes
            stats.update({"bytes": 1024, "elapsed": 1.0, "error": None})

        cfg = {"targets": ["1.1.1.1"], "load_test_url": self.URL,
               "load_test_seconds": 10, "load_test_max_mb": configured}
        loaded = {"latency_ms": 9.0, "jitter_ms": 1.0, "loss_pct": 0.0,
                  "target": "1.1.1.1", "active_samples": 6, "load_seconds": 5.0}
        with mock.patch.object(probes, "quality_config", return_value=cfg), \
                mock.patch.object(probes, "measure_quality",
                                  return_value={"latency_ms": 8.0,
                                                "jitter_ms": 1.0,
                                                "loss_pct": 0.0,
                                                "target": "1.1.1.1"}), \
                mock.patch.object(probes, "_measure_loaded_quality",
                                  return_value=loaded), \
                mock.patch.object(probes, "_load_downloader",
                                  side_effect=fake_downloader), \
                mock.patch.object(probes, "_resolve_load_target",
                                  return_value=(probes.urlparse(self.URL),
                                                ["104.16.0.1"])), \
                mock.patch.object(probes.time, "sleep"):
            probes.run_load_test(store=False)
        return seen["max_bytes"] / (1024 * 1024)

    def test_the_default_budget_can_load_a_gigabit_link(self):
        """25 MB was spent in 0.31 s on the 650 Mbps link that reported this,
        which left no window to sample latency in."""
        self.assertEqual(self.budget_for(None), 100)
        seconds_of_load = (100 * 1024 * 1024) / (1000e6 / 8)
        self.assertGreater(
            seconds_of_load, 0.8,
            "the default budget still empties too fast to sample against")

    def test_a_larger_budget_is_honoured_up_to_the_ceiling(self):
        self.assertEqual(self.budget_for(400), 400)

    def test_an_absurd_budget_is_capped(self):
        self.assertEqual(self.budget_for(100000), 500)

    def test_a_nonsense_budget_falls_back_to_the_default(self):
        self.assertEqual(self.budget_for("lots"), 100)


if __name__ == "__main__":
    unittest.main()

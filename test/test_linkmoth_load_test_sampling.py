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
    def sample_loaded(self, transfer_seconds, window=10.0, starts_at=0.0,
                      lose_every=0, gateway=None, gateway_replies=True):
        """Run the real loop against a transfer that stops after N seconds.

        `starts_at` models the gap before the first byte arrives: the
        downloader has to complete a TCP connect, a TLS handshake and
        certificate validation first, which on a small board is not instant.
        """
        clock = FakeClock()
        stats = {"bytes": 0}

        probes_sent = {"n": 0}

        def fake_measure(targets, count=1):
            # A ping costs time; bytes only grow once the transfer has
            # actually begun and while it is still running, exactly as the
            # downloader thread behaves.
            clock.t += PING_SECONDS
            if starts_at <= clock.t <= transfer_seconds:
                stats["bytes"] += CHUNK
            elif clock.t > transfer_seconds:
                # The downloader thread sets this in its finally block once
                # the transfer is genuinely over.
                stats["done"] = True
            if gateway is not None and list(targets) == [gateway]:
                # The follow-up probe to the local gateway.
                return {
                    "latency_ms": 0.4, "jitter_ms": 0.1, "loss_pct": 0.0,
                    "target": gateway,
                } if gateway_replies else None
            probes_sent["n"] += 1
            if lose_every and probes_sent["n"] % lose_every == 0:
                # measure_quality returns None when the ping gets no reply.
                return None
            return {
                "latency_ms": 20.0, "jitter_ms": 1.0, "loss_pct": 0.0,
                "target": "1.1.1.1",
            }

        with mock.patch.object(probes, "time", clock), \
                mock.patch.object(probes, "measure_quality", fake_measure):
            result = probes._measure_loaded_quality(
                "1.1.1.1", stats, window, local_target=gateway)
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

    def test_a_slow_handshake_does_not_kill_the_transfer(self):
        """The reported failure: "the transfer never started, so there was no
        load to measure". The early exit counts probes that saw no byte
        progress, but before the first byte there is never any progress, so a
        TLS handshake slower than three probes made the sampler give up and
        stop the download before it had read anything."""
        result, _, _ = self.sample_loaded(
            transfer_seconds=3.0, starts_at=0.4)
        self.assertIsNotNone(
            result, "gave up before the transfer produced its first byte")
        self.assertGreaterEqual(result["active_samples"], 2)

    def test_a_very_slow_handshake_is_still_waited_out(self):
        result, _, _ = self.sample_loaded(
            transfer_seconds=6.0, starts_at=2.5)
        self.assertIsNotNone(result)

    def test_a_transfer_that_never_starts_yields_nothing(self):
        """No bytes ever move, so every ping measures an idle network. A grade
        built from those would be a fabricated result."""
        result, _, _ = self.sample_loaded(transfer_seconds=0.0)
        self.assertIsNone(result)

    def test_packets_dropped_under_load_are_reported_as_loss(self):
        """A connection that starts dropping packets when it is busy is a
        classic symptom, sometimes plainer than latency inflation. The loaded
        result hardcoded zero loss, so a probe that got no reply was dropped
        from the sample set and the run reported a clean 0%."""
        result, _, _ = self.sample_loaded(transfer_seconds=3.0, lose_every=4)
        self.assertIsNotNone(result)
        self.assertGreater(
            result["loss_pct"], 0.0,
            "packets were lost under load and the result claimed none")
        # One in four probes got no reply.
        self.assertAlmostEqual(result["loss_pct"], 25.0, delta=6.0)

    def test_loss_that_also_hits_the_local_gateway_is_recorded_as_such(self):
        """A packet to your own router never reaches the ISP, so losing one
        cannot be the line's doing. Measured on real hardware: a load test
        saturating a Pi lost 8% to the internet and 4% to the router on the
        same run, while latency did not move at all. Reporting that as loss
        under load invites exactly the wrong conclusion."""
        result, _, _ = self.sample_loaded(
            transfer_seconds=3.0, lose_every=4,
            gateway="192.168.1.1", gateway_replies=False)
        self.assertGreater(result["loss_pct"], 0.0)
        self.assertGreater(
            result["local_loss_pct"], 0.0,
            "the gateway was unreachable too and the result did not say so")

    def test_loss_that_spares_the_local_gateway_is_recorded_as_such(self):
        """The gateway answers throughout, so the loss is beyond it."""
        result, _, _ = self.sample_loaded(
            transfer_seconds=3.0, lose_every=4,
            gateway="192.168.1.1", gateway_replies=True)
        self.assertGreater(result["loss_pct"], 0.0)
        self.assertEqual(result["local_loss_pct"], 0.0)

    def test_a_clean_run_never_probes_the_gateway(self):
        """The follow-up probe exists to attribute a loss. With nothing lost
        there is nothing to attribute, and spending probes during a
        measurement is not free."""
        result, _, _ = self.sample_loaded(
            transfer_seconds=3.0, gateway="192.168.1.1",
            gateway_replies=False)
        self.assertEqual(result["loss_pct"], 0.0)
        self.assertEqual(result["local_loss_pct"], 0.0)

    def test_no_known_gateway_leaves_the_loss_unattributed(self):
        result, _, _ = self.sample_loaded(transfer_seconds=3.0, lose_every=4)
        self.assertGreater(result["loss_pct"], 0.0)
        self.assertEqual(result["local_loss_pct"], 0.0)

    def test_a_clean_run_reports_no_loss(self):
        result, _, _ = self.sample_loaded(transfer_seconds=3.0)
        self.assertEqual(result["loss_pct"], 0.0)

    def test_losing_every_probe_cannot_be_graded(self):
        """Nothing replied, so there is no latency to compare. A grade built
        from no measurements would be invented."""
        result, _, _ = self.sample_loaded(transfer_seconds=3.0, lose_every=1)
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


class DefaultLoadUrlTests(unittest.TestCase):
    """The shipped test URL has to be one the endpoint will actually serve.

    Raising the byte budget in 0.6.4 also raised the size requested from
    speed.cloudflare.com to exactly 100000000, which that endpoint refuses
    with HTTP 403 – measured: 99000000 returns 200, 100000000 returns 403. The
    load test then failed on every install with "the test server could not be
    reached (HTTP 403)".

    The per-request size does not need to equal the budget: the downloader
    already re-requests until the budget or the time limit is reached, so a
    smaller response simply means more of them.
    """

    # Below the endpoint's documented refusal point, with room to spare.
    SAFE_MAX_BYTES = 90_000_000

    def default_url(self):
        from linkmoth_core import DEFAULT_CONFIG
        return DEFAULT_CONFIG["quality"]["load_test_url"]

    def test_the_default_request_size_is_one_the_endpoint_serves(self):
        from urllib.parse import urlparse, parse_qs
        requested = parse_qs(urlparse(self.default_url()).query).get("bytes")
        self.assertTrue(requested, "the default URL no longer requests a size")
        self.assertLessEqual(
            int(requested[0]), self.SAFE_MAX_BYTES,
            "the default asks for more than the test server will serve")

    def test_the_default_url_is_still_the_pinned_https_endpoint(self):
        self.assertTrue(self.default_url().startswith("https://"))


class DebugLogVisibilityTests(unittest.TestCase):
    """A failed load test must leave a trace in the debug command log.

    The log exists so an operator can see what Linkmoth just did. Every other
    probe is a subprocess and lands there through run_cmd, but the bufferbloat
    transfer speaks HTTP directly, so a load test that failed with HTTP 403
    showed nothing whatsoever – the one place someone would look was empty.
    """

    URL = "https://speed.example.com/file"

    @staticmethod
    def core_globals():
        """The namespace record_http actually reads, not one that shares a name.

        Another test module reloads the linkmoth package, so both
        `import linkmoth_core` and sys.modules can hand back a second,
        unrelated instance whose CFG and ring buffer nothing reads. Patching
        that one silently tests nothing, which is how these passed alone and
        failed in the full suite. The function's own globals cannot be wrong.
        """
        return probes.record_http.__globals__

    def drive_downloader(self, status=200, body=b"x" * 4096, raises=None):
        core = self.core_globals()
        core["clear_command_log"]()
        response = mock.MagicMock()
        response.status = status
        response.read.side_effect = [body, b""]
        conn = mock.MagicMock()
        conn.getresponse.return_value = response
        if raises is not None:
            conn.request.side_effect = raises
        stats = {"bytes": 0, "elapsed": 0.0, "error": None,
                 "deadline": probes.time.monotonic() + 5}
        stop = probes.threading.Event()
        with mock.patch.dict(core["CFG"], {"debug_command_log": True}), \
                mock.patch.object(probes, "_PinnedHTTPSConnection",
                                  return_value=conn):
            probes._load_downloader(self.URL, ["104.16.0.1"], 5,
                                    8 * 1024 * 1024, stats, stop)
        return core["command_log"]()["entries"], stats

    def test_a_refused_request_is_recorded_with_its_status(self):
        entries, stats = self.drive_downloader(status=403)
        self.assertEqual(stats["error"], "HTTP 403")
        self.assertTrue(entries, "the refusal left no trace in the debug log")
        joined = " ".join(e["command"] + " " + e["output"] for e in entries)
        self.assertIn("403", joined)
        self.assertIn(self.URL, joined)

    def test_a_successful_transfer_is_recorded_with_its_size(self):
        entries, _ = self.drive_downloader(status=200)
        self.assertTrue(entries)
        self.assertIn("MB", " ".join(e["output"] for e in entries))

    def test_a_transport_failure_is_recorded(self):
        entries, stats = self.drive_downloader(raises=OSError("boom"))
        self.assertEqual(stats["error"], "OSError")
        self.assertIn("OSError", " ".join(e["output"] for e in entries))

    def test_nothing_is_recorded_while_the_toggle_is_off(self):
        """The log is opt-in and must stay silent otherwise."""
        core = self.core_globals()
        core["clear_command_log"]()
        response = mock.MagicMock()
        response.status = 403
        conn = mock.MagicMock()
        conn.getresponse.return_value = response
        stats = {"bytes": 0, "elapsed": 0.0, "error": None,
                 "deadline": probes.time.monotonic() + 5}
        with mock.patch.dict(core["CFG"], {"debug_command_log": False}), \
                mock.patch.object(probes, "_PinnedHTTPSConnection",
                                  return_value=conn):
            probes._load_downloader(self.URL, ["104.16.0.1"], 5,
                                    8 * 1024 * 1024, stats,
                                    probes.threading.Event())
        self.assertEqual(core["command_log"]()["entries"], [])


class SlowStartIntegrationTests(unittest.TestCase):
    """The sampler and the downloader thread, driven together.

    The failure that produced "the transfer never started, so there was no
    load to measure" lived in the interaction, not in either half: the sampler
    gave up while the downloader was still completing its TLS handshake, then
    set the stop flag, so the transfer was cancelled before it read a byte and
    the run blamed the transfer for never starting. Real threads and a real
    delay, with the sample limits shrunk so it stays quick.
    """

    URL = "https://speed.example.com/file"

    def test_a_download_that_takes_time_to_begin_is_not_cancelled(self):
        import threading
        import time as real_time

        started_producing = threading.Event()

        def slow_downloader(url, addresses, seconds, max_bytes, stats, stop):
            # Stand in for connect + TLS + certificate validation.
            real_time.sleep(0.30)
            began = real_time.monotonic()
            while not stop.is_set() and stats["bytes"] < max_bytes:
                stats["bytes"] += 65536
                started_producing.set()
                real_time.sleep(0.005)
            stats["elapsed"] = real_time.monotonic() - began
            stats["error"] = None
            stats["done"] = True

        cfg = {"targets": ["1.1.1.1"], "load_test_url": self.URL,
               "load_test_seconds": 5, "load_test_max_mb": 100}
        sample = {"latency_ms": 12.0, "jitter_ms": 1.0, "loss_pct": 0.0,
                  "target": "1.1.1.1"}

        def timed_ping(targets, count=1):
            # A real reply takes milliseconds, which is the window the
            # sampler compares byte counts across. An instant mock would
            # never observe progress and would test nothing.
            real_time.sleep(0.01)
            return sample

        with mock.patch.object(probes, "quality_config", return_value=cfg), \
                mock.patch.object(probes, "measure_quality",
                                  side_effect=timed_ping), \
                mock.patch.object(probes, "_load_downloader",
                                  side_effect=slow_downloader), \
                mock.patch.object(probes, "_resolve_load_target",
                                  return_value=(probes.urlparse(self.URL),
                                                ["104.16.0.1"])), \
                mock.patch.object(probes, "_LOADED_MAX_SAMPLES", 6), \
                mock.patch.object(probes, "_LOADED_SAMPLE_PAUSE", 0.01):
            result = probes.run_load_test(store=False)

        self.assertTrue(
            started_producing.is_set(),
            "the transfer was cancelled before it produced any bytes")
        self.assertIsNotNone(result)
        self.assertGreater(result["bytes"], 0)
        self.assertGreaterEqual(result["active_samples"], 2)


class TimedByteCounter:
    """A download counter that advances on the transfer's schedule.

    http.client's read(n) blocks until it has n bytes, so on a slow line the
    counter jumps by a whole chunk every few hundred milliseconds rather than
    creeping up continuously. Modelling that matters: whether a jump happens
    to land inside the milliseconds a ping is in flight is not something the
    measurement should depend on.
    """

    def __init__(self, clock, starts_at, ends_at, jump_every):
        self.clock = clock
        self.starts_at = starts_at
        self.ends_at = ends_at
        self.jump_every = jump_every

    def get(self, key, default=None):
        if key == "done":
            return self.clock.t > self.ends_at
        if key != "bytes":
            return default
        moment = min(self.clock.t, self.ends_at)
        if moment < self.starts_at:
            return 0
        return CHUNK * int((moment - self.starts_at) / self.jump_every)


class SlowLinkSamplingTests(unittest.TestCase):
    """A slow line is the case this product exists for.

    Progress was judged only across the milliseconds a ping was in flight. At
    1 Mbps the byte counter moves roughly every half second, so that window
    catches a jump about one time in ninety, and the run could report that
    nothing was downloading while the transfer was running perfectly.
    """

    def sample_at(self, mbps, window=10.0):
        clock = FakeClock()
        jump_every = CHUNK / (mbps * 1e6 / 8)
        stats = TimedByteCounter(clock, 0.2, window, jump_every)

        def fake_measure(targets, count=1):
            clock.t += PING_SECONDS
            return {"latency_ms": 20.0, "jitter_ms": 1.0, "loss_pct": 0.0,
                    "target": "1.1.1.1"}

        with mock.patch.object(probes, "time", clock), \
                mock.patch.object(probes, "measure_quality", fake_measure):
            return probes._measure_loaded_quality("1.1.1.1", stats, window)

    def assert_stable(self, mbps):
        """Enough samples for an average worth publishing, not the bare two.

        The code sets _LOADED_MIN_SAMPLES as its own definition of enough
        evidence, so that is the bar. Judging progress only across a ping
        scrapes exactly two samples at 0.5 Mbps and three at 1 Mbps: one
        unlucky reply short of no result, and far too few to average.
        """
        result = self.sample_at(mbps)
        self.assertIsNotNone(
            result, f"a {mbps} Mbps transfer looked like no transfer at all")
        self.assertGreaterEqual(
            result["active_samples"], probes._LOADED_MIN_SAMPLES,
            f"only {result['active_samples']} samples at {mbps} Mbps")
        return result

    def test_a_half_megabit_line_is_still_measured(self):
        self.assert_stable(0.5)

    def test_a_one_megabit_line_is_still_measured(self):
        self.assert_stable(1)

    def test_a_five_megabit_line_is_still_measured(self):
        self.assert_stable(5)

    def test_a_fast_line_is_unaffected(self):
        result = self.sample_at(650)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result["active_samples"], 2)


class DownloaderCompletionTests(unittest.TestCase):
    """The real downloader has to announce that it finished.

    The sampler stops on that signal. Nothing else can tell the ordinary gap
    between chunk arrivals on a slow line from a transfer that is genuinely
    over, and guessing cut those runs short mid-transfer.
    """

    URL = "https://speed.example.com/file"

    def drive(self, status=200, raises=None):
        response = mock.MagicMock()
        response.status = status
        response.read.side_effect = [b"x" * 4096, b""]
        conn = mock.MagicMock()
        conn.getresponse.return_value = response
        if raises is not None:
            conn.request.side_effect = raises
        stats = {"bytes": 0, "elapsed": 0.0, "error": None, "done": False,
                 "deadline": probes.time.monotonic() + 5}
        with mock.patch.object(probes, "_PinnedHTTPSConnection",
                               return_value=conn):
            probes._load_downloader(self.URL, ["104.16.0.1"], 5,
                                    8 * 1024 * 1024, stats,
                                    probes.threading.Event())
        return stats

    def test_a_completed_transfer_is_marked_done(self):
        self.assertTrue(self.drive()["done"])

    def test_a_refused_transfer_is_marked_done(self):
        """Otherwise the sampler waits out the whole window for a transfer
        that will never send a byte."""
        stats = self.drive(status=403)
        self.assertTrue(stats["done"])
        self.assertEqual(stats["error"], "HTTP 403")

    def test_a_transfer_that_raised_is_marked_done(self):
        stats = self.drive(raises=OSError("boom"))
        self.assertTrue(stats["done"])
        self.assertEqual(stats["error"], "OSError")


class GatewayWiringTests(unittest.TestCase):
    """The attribution is only worth anything if the gateway reaches it.

    The sampling tests call _measure_loaded_quality directly and pass a
    gateway themselves, so they cannot notice run_load_test failing to look
    one up or forgetting to hand it over. A mutation that dropped the argument
    left every one of them green.
    """

    URL = "https://speed.example.com/file"

    def run_with(self, route):
        seen = {}

        def capture(target, stats, deadline, local_target=None):
            seen["local_target"] = local_target
            return {"latency_ms": 9.0, "jitter_ms": 1.0, "loss_pct": 0.0,
                    "local_loss_pct": 0.0, "target": target,
                    "active_samples": 6, "load_seconds": 2.0}

        def fake_downloader(url, addresses, seconds, max_bytes, stats, stop):
            stats.update({"bytes": 1024, "elapsed": 1.0, "error": None,
                          "done": True})

        cfg = {"targets": ["1.1.1.1"], "load_test_url": self.URL,
               "load_test_seconds": 10, "load_test_max_mb": 100}
        with mock.patch.object(probes, "quality_config", return_value=cfg), \
                mock.patch.object(probes, "default_route", return_value=route), \
                mock.patch.object(probes, "measure_quality",
                                  return_value={"latency_ms": 8.0,
                                                "jitter_ms": 1.0,
                                                "loss_pct": 0.0,
                                                "target": "1.1.1.1"}), \
                mock.patch.object(probes, "_measure_loaded_quality", capture), \
                mock.patch.object(probes, "_load_downloader",
                                  side_effect=fake_downloader), \
                mock.patch.object(probes, "_resolve_load_target",
                                  return_value=(probes.urlparse(self.URL),
                                                ["104.16.0.1"])), \
                mock.patch.object(probes.time, "sleep"):
            probes.run_load_test(store=False)
        return seen.get("local_target")

    def test_the_default_gateway_is_handed_to_the_sampler(self):
        self.assertEqual(self.run_with(("192.168.1.1", "eth0")), "192.168.1.1")

    def test_no_default_route_is_handled(self):
        """A host with no default route has nothing to attribute against, and
        that must not break the run."""
        self.assertIsNone(self.run_with((None, None)))

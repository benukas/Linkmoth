#!/usr/bin/env python3
"""The incident recheck loop must survive the host clock being stepped.

A Raspberry Pi has no RTC. It can run for minutes after boot with a badly
wrong clock before NTP corrects it, and that correction is a step, not a
drift. If an incident is open across that step, scheduling the recheck loop
on wall-clock time gets both directions wrong:

  forward step  – time.time() overshoots the loop's deadline, so the loop
                   exits at once and finalises the incident as though
                   incident_max_hours had elapsed: stopping rechecks on a
                   still-faulting network and closing without the two
                   consecutive all-clears that mean recovery.
  backward step – the next recheck is scheduled at `t0 + offset`, which is
                   now that far in the future, so the loop sleeps for roughly
                   the size of the jump and stops rechecking a live incident.

Elapsed time and scheduling therefore come from the monotonic clock. Stored
timestamps stay wall-clock: what the host believed at the time is the honest
thing to record, and a clock that was wrong when a row was written cannot be
corrected retroactively.
"""
import contextlib
import importlib
import io
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent))

BAD = {"severity": "bad", "code": "wan_down", "title": "WAN down",
       "explain": "dead", "hint": "check WAN"}


class _Clocks:
    """A wall clock that can be stepped, and a monotonic clock that advances
    only when the loop sleeps – which is how real time passes in this loop."""

    def __init__(self, wall_base):
        self.wall_base = wall_base
        self.wall_offset = 0.0
        self.mono = 1000.0
        self.sleeps = []

    def step_wall(self, seconds):
        self.wall_offset += seconds

    def time(self):
        return self.wall_base + self.wall_offset

    def monotonic(self):
        return self.mono

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.mono += max(0.0, float(seconds))


class IncidentLoopClockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = Path(tempfile.mkdtemp(prefix="linkmoth_clock_"))
        os.environ["LINKMOTH_STATE_DIR"] = str(cls.state)
        os.environ.pop("LINKMOTH_CONFIG", None)
        for mod in [m for m in list(sys.modules) if m.startswith("linkmoth")]:
            del sys.modules[mod]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def setUp(self):
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM incidents")
            conn.execute("DELETE FROM runs")
        self.engine = self.linkmoth.Engine()

    def _open_incident(self, started):
        with self.linkmoth.db() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail) VALUES(?,?,?)",
                (started, "test", "clock"),
            )
            return cur.lastrowid

    def _incident(self, inc_id):
        with self.linkmoth.db() as conn:
            return dict(conn.execute(
                "SELECT * FROM incidents WHERE id=?", (inc_id,)).fetchone())

    def _run_loop(self, inc_id, clocks, on_call):
        def fake_diagnose(incident_id=None, kind=None):
            on_call()
            return dict(BAD)

        with mock.patch.dict(
            self.linkmoth.CFG,
            # recheck_repeat drives the monotonic clock forward, so the
            # incident_max_hours bound is reached in a bounded number of
            # iterations instead of real time.
            {"recheck_seconds": [0, 0, 0], "recheck_repeat": 600,
             "incident_max_hours": 2},
        ), mock.patch.object(
            self.linkmoth.time, "time", side_effect=clocks.time,
        ), mock.patch.object(
            self.linkmoth.time, "monotonic", side_effect=clocks.monotonic,
        ), mock.patch.object(
            self.linkmoth.time, "sleep", side_effect=clocks.sleep,
        ), mock.patch.object(
            self.engine, "diagnose_once", side_effect=fake_diagnose,
        ), mock.patch.object(
            self.engine, "_discord_notify",
        ), mock.patch.object(
            self.engine, "_emit_webhook",
        ):
            self.engine._loop(inc_id)

    def test_a_forward_clock_step_does_not_stop_rechecking_a_live_incident(self):
        """The damaging case: the network is still down, but a forward step
        makes a wall-clock-bounded loop believe incident_max_hours elapsed."""
        base = time.time()
        inc_id = self._open_incident(base)
        clocks = _Clocks(base)
        calls = {"n": 0}

        def on_call():
            calls["n"] += 1
            if calls["n"] == 1:
                clocks.step_wall(10 * 86400)  # NTP corrects a 10-day-wrong clock
            if calls["n"] >= 4:
                # End deterministically the way a real external close would:
                # the loop returns without finalising.
                with self.linkmoth.db() as conn:
                    conn.execute(
                        "UPDATE incidents SET resolved=? WHERE id=?",
                        (clocks.time(), inc_id),
                    )

        self._run_loop(inc_id, clocks, on_call)
        self.assertGreaterEqual(
            calls["n"], 4,
            "the recheck loop stopped after the clock step instead of"
            " continuing to recheck a still-faulting incident",
        )

    def test_a_forward_step_does_not_record_a_timeout_as_a_recovery(self):
        """Reaching the incident_max_hours bound is not a recovery, and a
        clock step must not turn it into one."""
        base = time.time()
        inc_id = self._open_incident(base)
        clocks = _Clocks(base)
        calls = {"n": 0}

        def on_call():
            calls["n"] += 1
            if calls["n"] == 1:
                clocks.step_wall(10 * 86400)

        self._run_loop(inc_id, clocks, on_call)

        # The loop ran to its real (monotonic) bound rather than exiting on
        # the step: incident_max_hours of 2 at 600s per recheck.
        self.assertGreater(calls["n"], 10)
        inc = self._incident(inc_id)
        self.assertTrue(inc.get("resolved"))
        self.assertFalse(
            inc.get("recovered_at"),
            "a max-hours timeout was recorded as a confirmed recovery",
        )

    def test_a_span_inflated_by_a_clock_step_is_reported_as_unreliable(self):
        """A duration cannot be repaired once the clock has moved: `started`
        was measured against a clock that no longer exists, and the true start
        was never observed. Linkmoth's whole purpose is evidence for an ISP
        dispute, so an impossible span must at least be flagged rather than
        silently presented as fact."""
        base = time.time()
        inc_id = self._open_incident(base)
        clocks = _Clocks(base)
        calls = {"n": 0}

        def on_call():
            calls["n"] += 1
            if calls["n"] == 1:
                clocks.step_wall(10 * 86400)

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self._run_loop(inc_id, clocks, on_call)
        message = err.getvalue()
        self.assertIn(str(inc_id), message)
        self.assertIn("clock", message.lower())

    def test_a_normal_incident_is_not_flagged(self):
        """The warning must only fire on an impossible span, never on an
        ordinary long incident."""
        base = time.time()
        inc_id = self._open_incident(base)
        clocks = _Clocks(base)

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self._run_loop(inc_id, clocks, lambda: None)
        self.assertNotIn("clock", err.getvalue().lower())

    def test_an_incident_resumed_after_a_restart_is_not_flagged(self):
        """resume_after_startup picks up an incident that legitimately began
        before this process, so its span exceeding what this loop observed is
        expected and proves nothing about the clock."""
        base = time.time()
        inc_id = self._open_incident(base - 6 * 3600)  # opened long before
        clocks = _Clocks(base)

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self._run_loop(inc_id, clocks, lambda: None)
        self.assertNotIn(
            "clock", err.getvalue().lower(),
            "a resumed incident was misreported as a clock step",
        )

    def test_a_backward_clock_step_does_not_stall_the_next_recheck(self):
        """A backward step must not push the next scheduled recheck that far
        into the future and leave a live incident unchecked."""
        base = time.time()
        inc_id = self._open_incident(base)
        clocks = _Clocks(base)
        calls = {"n": 0}

        def on_call():
            calls["n"] += 1
            if calls["n"] == 1:
                clocks.step_wall(-86400)  # clock corrected backwards by a day
            if calls["n"] >= 4:
                with self.linkmoth.db() as conn:
                    conn.execute(
                        "UPDATE incidents SET resolved=? WHERE id=?",
                        (clocks.time(), inc_id),
                    )

        self._run_loop(inc_id, clocks, on_call)
        self.assertTrue(clocks.sleeps)
        self.assertLess(
            max(clocks.sleeps), 3600,
            f"a recheck was scheduled {max(clocks.sleeps)}s out after a"
            " backward clock step",
        )


if __name__ == "__main__":
    unittest.main()

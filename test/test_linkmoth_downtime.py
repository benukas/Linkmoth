#!/usr/bin/env python3
"""The downtime arithmetic behind every reported figure.

`_outage_seconds` produces the number a user puts in front of their ISP: total
downtime, the longest outage, the blame breakdown, and the daily health score
all reduce to it. It had no direct tests, so the window clipping and the
open-segment handling were only exercised incidentally.

Two properties matter beyond simple addition. Healthy time between faults must
not count as downtime, since an incident deliberately stays open through its
recovery-confirmation window. And overlapping intervals must be merged rather
than added: the callers' invariants mean overlap should not arise, but summing
blindly inflates downtime, which is precisely what would discredit a report.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent))

os.environ.setdefault("LINKMOTH_STATE_DIR", tempfile.mkdtemp(prefix="linkmoth_dt_"))
os.environ.pop("LINKMOTH_CONFIG", None)

import linkmoth_core as core  # noqa: E402

NOW = 10_000.0


def seg(started, ended):
    return {"started": started, "ended": ended}


class OutageSecondsTests(unittest.TestCase):
    def total(self, segments, window_start=None, window_end=None):
        return core._outage_seconds(
            segments, window_start=window_start, window_end=window_end, now=NOW)

    def test_a_closed_segment_counts_its_own_length(self):
        self.assertAlmostEqual(self.total([seg(1000, 1600)]), 600)

    def test_a_still_open_segment_counts_up_to_now(self):
        self.assertAlmostEqual(self.total([seg(9000, None)]), 1000)

    def test_a_segment_is_clipped_to_the_reporting_window(self):
        self.assertAlmostEqual(self.total([seg(1000, 1600)], window_start=1200), 400)
        self.assertAlmostEqual(self.total([seg(1000, 1600)], window_end=1400), 400)

    def test_a_segment_outside_the_window_contributes_nothing(self):
        self.assertAlmostEqual(self.total([seg(1000, 1600)], window_start=2000), 0)
        self.assertAlmostEqual(self.total([seg(5000, 5600)], window_end=4000), 0)

    def test_healthy_time_between_faults_is_not_downtime(self):
        """An incident stays open through its recovery-confirmation window, so
        the gap between a recovery and a relapse must not be charged as
        downtime – the documented reason segments exist at all."""
        self.assertAlmostEqual(
            self.total([seg(1000, 1200), seg(1500, 1900)]), 600)

    def test_adjacent_segments_are_not_double_counted_at_the_join(self):
        self.assertAlmostEqual(
            self.total([seg(1000, 1200), seg(1200, 1400)]), 400)

    def test_a_zero_length_or_inverted_segment_contributes_nothing(self):
        self.assertAlmostEqual(self.total([seg(1000, 1000)]), 0)
        self.assertAlmostEqual(self.total([seg(1600, 1000)]), 0)

    def test_overlapping_segments_are_merged_not_added(self):
        """Overlap should not arise: one incident is open at a time, one
        segment is open per incident, and segments are sequential within one.
        Adding them anyway would silently inflate downtime if any of those ever
        slipped, and an inflated figure is the one that discredits a report."""
        self.assertAlmostEqual(self.total([seg(1000, 1600), seg(1200, 1800)]), 800)

    def test_a_segment_wholly_contained_in_another_adds_nothing(self):
        self.assertAlmostEqual(self.total([seg(1000, 2000), seg(1200, 1400)]), 1000)

    def test_merging_is_independent_of_input_order(self):
        unordered = [seg(1500, 1900), seg(1000, 1600), seg(1800, 2000)]
        self.assertAlmostEqual(self.total(unordered), 1000)

    def test_no_segments_is_no_downtime(self):
        self.assertAlmostEqual(self.total([]), 0)


if __name__ == "__main__":
    unittest.main()

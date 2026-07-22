#!/usr/bin/env python3
"""Tests for config_efficiency_notes: advisory notes about a configured
cadence that costs more than it returns.

Nothing here is enforced -- the settings stay valid. The notes only have to
be accurate, silent for sensible configurations, and free of any probing.
"""
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent))


class ConfigEfficiencyNoteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="linkmoth_notes_"))
        os.environ["LINKMOTH_STATE_DIR"] = str(self.tmp)
        os.environ.pop("LINKMOTH_CONFIG", None)
        for mod in ("linkmoth_core", "linkmoth_probes"):
            if mod in sys.modules:
                del sys.modules[mod]
        self.core = importlib.import_module("linkmoth_core")
        self.probes = importlib.import_module("linkmoth_probes")

    def _notes_for(self, **cfg):
        quality = cfg.pop("quality", None)
        self.core.CFG.update(cfg)
        if quality is not None:
            self.core.CFG["quality"] = quality
        return {n["setting"]: n for n in self.probes.config_efficiency_notes()}

    def test_shipped_defaults_produce_no_notes(self):
        """A sensible configuration must stay silent, or the advice becomes
        noise people learn to ignore."""
        self.assertEqual(self.probes.config_efficiency_notes(), [])

    def test_hourly_load_tests_warn_with_the_monthly_data_estimate(self):
        notes = self._notes_for(
            quality={"load_test_hours": 1, "load_test_max_mb": 25, "sample_count": 10})
        note = notes.get("quality.load_test_hours")
        self.assertIsNotNone(note)
        self.assertEqual(note["level"], "warn")
        # 24 runs/day * 30 days * 25 MB = 18000 MB = 17.6 GB
        self.assertIn("17.6 GB", note["message"])

    def test_occasional_load_tests_stay_silent(self):
        notes = self._notes_for(
            quality={"load_test_hours": 24, "load_test_max_mb": 25, "sample_count": 10})
        self.assertNotIn("quality.load_test_hours", notes)

    def test_load_tests_off_by_default_never_warn(self):
        notes = self._notes_for(
            quality={"load_test_hours": 0, "load_test_max_mb": 25, "sample_count": 10})
        self.assertNotIn("quality.load_test_hours", notes)

    def test_one_minute_sampling_reports_the_daily_check_count(self):
        notes = self._notes_for(history_sample_minutes=1)
        note = notes.get("history_sample_minutes")
        self.assertIsNotNone(note)
        self.assertIn("1,440", note["message"])

    def test_five_minute_sampling_is_silent(self):
        notes = self._notes_for(history_sample_minutes=5)
        self.assertNotIn("history_sample_minutes", notes)

    def test_disabled_sampling_is_silent(self):
        notes = self._notes_for(history_sample_minutes=0)
        self.assertNotIn("history_sample_minutes", notes)

    def test_aggressive_baseline_is_flagged_but_disabled_is_not(self):
        self.assertIn("baseline_minutes", self._notes_for(baseline_minutes=2))
        self.setUp()
        self.assertNotIn("baseline_minutes", self._notes_for(baseline_minutes=0))
        self.setUp()
        self.assertNotIn("baseline_minutes", self._notes_for(baseline_minutes=60))

    def test_fastest_refresh_explains_it_does_not_change_checking(self):
        note = self._notes_for(ui_refresh_seconds=2).get("ui_refresh_seconds")
        self.assertIsNotNone(note)
        self.assertIn("not how often the network is checked", note["message"])

    def test_notes_never_probe_the_network_or_touch_the_database(self):
        self._notes_for(history_sample_minutes=1, baseline_minutes=1,
                        ui_refresh_seconds=2,
                        quality={"load_test_hours": 1, "load_test_max_mb": 25})
        with mock.patch.object(self.probes, "run_cmd") as run_cmd, \
                mock.patch.object(self.probes, "db") as db_mock, \
                mock.patch.object(self.probes, "measure_quality") as measure:
            self.probes.config_efficiency_notes()
        run_cmd.assert_not_called()
        db_mock.assert_not_called()
        measure.assert_not_called()

    def test_every_note_carries_a_level_setting_and_message(self):
        notes = self.probes.config_efficiency_notes({
            "history_sample_minutes": 1, "baseline_minutes": 1,
            "ui_refresh_seconds": 2,
        })
        self.assertTrue(notes)
        for note in notes:
            self.assertIn(note["level"], ("info", "warn"))
            self.assertTrue(note["setting"])
            self.assertTrue(note["message"].endswith("."))

    def test_data_formatting_switches_between_mb_and_gb(self):
        self.assertEqual(self.probes._format_data(512), "512 MB")
        self.assertEqual(self.probes._format_data(2048), "2 GB")
        self.assertEqual(self.probes._format_data(18000), "17.6 GB")


if __name__ == "__main__":
    unittest.main()

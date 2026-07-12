"""Tests for lightweight Linkmoth-host health telemetry."""
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))


class HostStatsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_host_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")

    def test_stats_are_best_effort_and_include_dashboard_fields(self):
        first = self.linkmoth.host_stats()
        second = self.linkmoth.host_stats()
        for key in (
            "cpu_percent", "temperature_c", "memory_percent", "disk_percent",
            "memory_used_bytes", "memory_total_bytes", "disk_used_bytes",
            "disk_total_bytes", "load_1m", "uptime_seconds", "cpu_cores",
        ):
            self.assertIn(key, first)
            self.assertIn(key, second)
        self.assertGreaterEqual(second["cpu_cores"], 1)
        for key in ("cpu_percent", "memory_percent", "disk_percent"):
            self.assertTrue(second[key] is None or isinstance(second[key], float))

    def test_status_includes_host_telemetry(self):
        self.linkmoth.init_db()
        engine = self.linkmoth.Engine()
        with mock.patch.object(self.linkmoth, "host_stats", return_value={"cpu_percent": 12.5}):
            self.assertEqual(engine.status()["host"], {"cpu_percent": 12.5})


if __name__ == "__main__":
    unittest.main()

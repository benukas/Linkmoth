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

    def test_cpu_sampler_uses_moving_average_and_excludes_guest_time(self):
        self.linkmoth.HOST_CPU_SAMPLE = None
        self.linkmoth.HOST_CPU_VALUES.clear()
        self.linkmoth.HOST_CPU_VALUE = None
        self.linkmoth.HOST_CPU_UPDATED_AT = None
        with mock.patch.object(self.linkmoth, "_cpu_totals", side_effect=[
            (100, 80),  # seed
            (200, 80),  # 100% instantaneous
            (300, 180), # 0% instantaneous; 50% two-sample average
        ]):
            self.assertIsNone(self.linkmoth.sample_host_cpu())
            self.assertEqual(self.linkmoth.sample_host_cpu(), 100.0)
            self.assertEqual(self.linkmoth.sample_host_cpu(), 50.0)

        with mock.patch.object(self.linkmoth.Path, "read_text", return_value=(
            "cpu 100 20 30 800 10 0 0 0 999 999\n"
        )):
            total, idle = self.linkmoth._cpu_totals()
        self.assertEqual(total, 960)  # guest and guest_nice are excluded
        self.assertEqual(idle, 810)

    def test_status_reads_one_host_snapshot(self):
        self.linkmoth.init_db()
        engine = self.linkmoth.Engine()
        host = {"cpu_percent": 12.5, "disk_percent": 1, "memory_percent": 1,
                "temperature_c": 1}
        database = {"exists": True, "journal_mode": "WAL", "lock_retries": 0}
        with mock.patch.object(self.linkmoth, "host_stats", return_value=host) as stats, \
             mock.patch.object(self.linkmoth, "db_maintenance_info", return_value=database):
            status = engine.status()
        self.assertEqual(status["host"], host)
        self.assertEqual(stats.call_count, 1)


if __name__ == "__main__":
    unittest.main()

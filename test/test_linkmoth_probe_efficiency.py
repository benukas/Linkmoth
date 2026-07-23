#!/usr/bin/env python3
"""Tests for probe work that must not repeat itself.

Both cases here were found by reading the debug command log from a real
Raspberry Pi: `ip -o -4 addr show` ran on every /api/status poll, and
`vcgencmd get_throttled` was re-spawned on every ladder run despite failing
identically every time. Neither is expensive alone; both are pure waste on a
small always-on box, and both drown the command log in noise.
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

DEVICE_HIDDEN = (255, "Can't open device file: /dev/vcio_gencmd")


class ProbeEfficiencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="linkmoth_probeeff_"))
        os.environ["LINKMOTH_STATE_DIR"] = str(self.tmp)
        os.environ.pop("LINKMOTH_CONFIG", None)
        for mod in ("linkmoth_core", "linkmoth_probes"):
            if mod in sys.modules:
                del sys.modules[mod]
        self.core = importlib.import_module("linkmoth_core")
        self.core.init_db()
        self.probes = importlib.import_module("linkmoth_probes")
        self._reset_globals()

    def tearDown(self):
        # Module-level latches leak between test files in one process.
        self._reset_globals()

    def _reset_globals(self):
        self.probes._VCGENCMD_UNAVAILABLE = False
        self.probes._LOCAL_IPV4_CACHE["expires"] = 0.0
        self.probes._LOCAL_IPV4_CACHE["addresses"] = frozenset()

    # ---- local address lookup -------------------------------------------
    def test_repeated_status_polls_share_one_address_lookup(self):
        """local_dns_is_same_host runs inside Engine.status(), so an open
        dashboard reached it every few seconds and spawned `ip` each time."""
        spawned = []

        def counting(args, **kwargs):
            spawned.append(args[0])
            return 0, "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255"

        with mock.patch.object(self.probes, "run_cmd", counting):
            for _ in range(10):
                self.probes.local_dns_is_same_host("192.168.1.10")
        self.assertEqual(spawned.count("ip"), 1)

    def test_the_cached_answer_is_still_correct(self):
        addresses = "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255"
        with mock.patch.object(self.probes, "run_cmd", return_value=(0, addresses)):
            self.assertTrue(self.probes.local_dns_is_same_host("192.168.1.10"))
            self.assertTrue(self.probes.local_dns_is_same_host("127.0.0.1"))
            self.assertFalse(self.probes.local_dns_is_same_host("192.168.1.99"))

    def test_the_cache_expires_so_a_changed_address_is_noticed(self):
        spawned = []

        def counting(args, **kwargs):
            spawned.append(args[0])
            return 0, "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255"

        with mock.patch.object(self.probes, "run_cmd", counting):
            self.probes.local_dns_is_same_host("192.168.1.10")
            self.probes._LOCAL_IPV4_CACHE["expires"] = 0.0  # simulate the TTL passing
            self.probes.local_dns_is_same_host("192.168.1.10")
        self.assertEqual(spawned.count("ip"), 2)

    def test_a_failed_lookup_is_not_cached_as_the_truth(self):
        """If `ip` fails, loopback is still known; the next call should retry
        rather than serve a permanently impoverished answer."""
        with mock.patch.object(self.probes, "run_cmd", return_value=(-2, "tool missing")):
            self.assertTrue(self.probes.local_dns_is_same_host("127.0.0.1"))

    # ---- vcgencmd --------------------------------------------------------
    def test_a_hidden_videocore_device_is_probed_once_not_every_run(self):
        """PrivateDevices=true in the unit file hides /dev/vcio, which cannot
        change without restarting the service."""
        spawned = []

        def failing(args, **kwargs):
            spawned.append(args[0])
            return DEVICE_HIDDEN

        with mock.patch.object(self.probes, "run_cmd", failing):
            for _ in range(8):
                self.assertIsNone(self.probes._vcgencmd_throttled())
        self.assertEqual(len(spawned), 1)

    def test_a_missing_binary_is_also_probed_only_once(self):
        spawned = []

        def missing(args, **kwargs):
            spawned.append(args[0])
            return -2, "tool missing"

        with mock.patch.object(self.probes, "run_cmd", missing):
            for _ in range(5):
                self.probes._vcgencmd_throttled()
        self.assertEqual(len(spawned), 1)

    def test_a_transient_failure_keeps_being_retried(self):
        """Only failures that cannot resolve while the process runs may latch;
        latching on any non-zero code would disable the check permanently
        after one blip."""
        spawned = []

        def flaky(args, **kwargs):
            spawned.append(args[0])
            return 1, "temporary glitch"

        with mock.patch.object(self.probes, "run_cmd", flaky):
            for _ in range(4):
                self.probes._vcgencmd_throttled()
        self.assertEqual(len(spawned), 4)

    def test_a_working_vcgencmd_is_still_read_normally(self):
        with mock.patch.object(self.probes, "run_cmd", return_value=(0, "throttled=0x0")):
            self.assertEqual(self.probes._vcgencmd_throttled(), "throttled=0x0")
            ok, detail = self.probes.check_power()
        self.assertTrue(ok)
        self.assertIn("healthy", detail)

    def test_undervoltage_is_still_reported_when_vcgencmd_works(self):
        with mock.patch.object(self.probes, "run_cmd", return_value=(0, "throttled=0x1")):
            ok, detail = self.probes.check_power()
        self.assertFalse(ok)
        self.assertIn("undervoltage now", detail)

    def test_the_hwmon_fallback_still_runs_when_vcgencmd_is_unusable(self):
        """Skipping vcgencmd must not cost undervoltage detection on a Pi that
        exposes the rpi_volt sensor."""
        hwmon = Path("/fake/hwmon0")
        contents = {hwmon / "name": "rpi_volt", hwmon / "in0_lcrit_alarm": "1"}

        def read_text(self, *args, **kwargs):
            if self in contents:
                return contents[self]
            raise OSError("not here")

        with mock.patch.object(self.probes, "run_cmd", return_value=DEVICE_HIDDEN), \
                mock.patch.object(self.probes, "_read_power_supplies",
                                  return_value=(None, "", False)), \
                mock.patch.object(Path, "glob", return_value=[hwmon / "name"]), \
                mock.patch.object(Path, "read_text", read_text):
            ok, detail = self.probes.check_power()
        self.assertFalse(ok)
        self.assertIn("undervoltage", detail)


if __name__ == "__main__":
    unittest.main()

"""Tests for global outage tracking and recovery notifications."""
import importlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
REPO_ROOT = BASE.parent
sys.path.insert(0, str(REPO_ROOT))

import linkmoth_kuma_proxy as proxy
import linkmoth_outage


class EffectiveGlobalOutageTests(unittest.TestCase):
    def test_wan_code_is_global(self):
        self.assertTrue(proxy.is_effective_global_outage({"code": "wan_down"}, []))

    def test_compound_wan_with_wlan_probe_fail(self):
        checks = [
            {"id": "gateway", "ok": True},
            {"id": "upstream_dns", "ok": False},
            {"id": "raw_ping", "ok": False},
            {"id": "router_wlan", "ok": False},
        ]
        self.assertTrue(
            proxy.is_effective_global_outage({"code": "router_wlan_down"}, checks),
        )

    def test_wlan_only_not_global(self):
        checks = [
            {"id": "gateway", "ok": True},
            {"id": "upstream_dns", "ok": True},
            {"id": "raw_ping", "ok": True},
            {"id": "router_wlan", "ok": False},
        ]
        self.assertFalse(
            proxy.is_effective_global_outage({"code": "router_wlan_down"}, checks),
        )

    def test_working_https_prevents_compound_false_global_outage(self):
        checks = [
            {"id": "gateway", "ok": True},
            {"id": "upstream_dns", "ok": False},
            {"id": "raw_ping", "ok": False},
            {"id": "https", "ok": True},
            {"id": "router_wlan", "ok": False},
        ]
        self.assertFalse(
            proxy.is_effective_global_outage({"code": "router_wlan_down"}, checks),
        )


class OutageTrackerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="linkmoth_outage_")
        cls.state = Path(cls.tmp) / "state"
        cls.state.mkdir()
        cls.config_path = Path(cls.tmp) / "config.json"
        cls.config_path.write_text(json.dumps({
            "bind": "127.0.0.1",
            "port": 0,
            "push_notifications_enabled": False,
            "discord_notifications_enabled": False,
        }))
        os.environ["LINKMOTH_CONFIG"] = str(cls.config_path)
        os.environ["LINKMOTH_STATE_DIR"] = str(cls.state)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        os.environ.pop("LINKMOTH_CONFIG", None)
        os.environ.pop("LINKMOTH_STATE_DIR", None)

    def setUp(self):
        import linkmoth
        importlib.reload(linkmoth)
        self.linkmoth = linkmoth
        linkmoth.init_db()
        self.tracker = linkmoth_outage.OutageTracker()
        self.recoveries = []

    def _notify(self, **kwargs):
        self.recoveries.append(kwargs)

    def test_enter_and_recover_after_two_clear_runs(self):
        wan = {
            "severity": "bad",
            "code": "wan_down",
            "title": "WAN down",
            "explain": "outside dead",
            "hint": "check cable",
        }
        checks = [
            {"id": "gateway", "ok": True, "label": "Router (LAN)", "detail": "ok"},
            {"id": "upstream_dns", "ok": False, "label": "Upstream DNS", "detail": "dead"},
            {"id": "raw_ping", "ok": False, "label": "Raw internet (ping)", "detail": "dead"},
        ]
        ok = {
            "severity": "ok",
            "code": "all_clear",
            "title": "All clear",
            "explain": "fine",
            "hint": "",
        }
        self.tracker.observe(wan, checks, self.linkmoth.CFG, self.linkmoth.db, self._notify)
        self.assertTrue(self.tracker.is_active(self.linkmoth.db))
        with self.linkmoth.db() as conn:
            n = conn.execute("SELECT COUNT(*) AS c FROM suppressed_alerts").fetchone()["c"]
        self.assertGreaterEqual(n, 1)

        self.tracker.observe(ok, checks, self.linkmoth.CFG, self.linkmoth.db, self._notify)
        self.assertTrue(self.tracker.is_active(self.linkmoth.db))
        self.assertEqual(len(self.recoveries), 0)

        self.tracker.observe(ok, checks, self.linkmoth.CFG, self.linkmoth.db, self._notify)
        self.assertFalse(self.tracker.is_active(self.linkmoth.db))
        self.assertEqual(len(self.recoveries), 1)
        self.assertEqual(self.recoveries[0]["prior_fault"]["code"], "wan_down")


class VerdictOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="linkmoth_verdict_")
        cls.state = Path(cls.tmp) / "state"
        cls.state.mkdir()
        cls.config_path = Path(cls.tmp) / "config.json"
        cls.config_path.write_text(json.dumps({"bind": "127.0.0.1", "port": 0}))
        os.environ["LINKMOTH_CONFIG"] = str(cls.config_path)
        os.environ["LINKMOTH_STATE_DIR"] = str(cls.state)
        import linkmoth
        importlib.reload(linkmoth)
        cls.linkmoth = linkmoth

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        os.environ.pop("LINKMOTH_CONFIG", None)
        os.environ.pop("LINKMOTH_STATE_DIR", None)

    def test_wan_beats_router_wlan(self):
        checks = [
            {"id": "link", "ok": True, "detail": "ok"},
            {"id": "gateway", "ok": True, "detail": "ok"},
            {"id": "router_wlan", "ok": False, "detail": "wlan timeout"},
            {"id": "power", "ok": True, "detail": "ok"},
            {"id": "pihole_dns", "ok": True, "detail": "ok"},
            {"id": "upstream_dns", "ok": False, "detail": "dead"},
            {"id": "raw_ping", "ok": False, "detail": "dead"},
            {"id": "https", "ok": False, "detail": "dead"},
        ]
        v = self.linkmoth.verdict(checks)
        self.assertEqual(v["code"], "wan_down")


if __name__ == "__main__":
    unittest.main()

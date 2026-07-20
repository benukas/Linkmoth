#!/usr/bin/env python3
"""Tests for Uptime Kuma webhook proxy gateway."""
import importlib
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

WEBHOOK = "https://discord.com/api/webhooks/123456789/abcdefghijklmnop"
KUMA_DOWN = json.dumps({
    "heartbeat": {"status": 0},
    "monitor": {"name": "Home Assistant"},
    "msg": "Request failed",
}).encode()


class KumaProxyLogicTests(unittest.TestCase):
    def test_global_outage_codes(self):
        import linkmoth_kuma_proxy as proxy
        self.assertTrue(proxy.is_global_outage({"code": "wan_down"}))
        self.assertTrue(proxy.is_global_outage({"code": "router_down"}))
        self.assertFalse(proxy.is_global_outage({"code": "pihole_broken"}))
        self.assertFalse(proxy.is_global_outage({"code": "all_clear"}))

    def test_outage_digest_lines(self):
        import linkmoth_kuma_proxy as proxy
        now = time.time()
        rows = [
            {
                "ts": now - 720,
                "kuma_status": 0,
                "monitor_detail": "HomeAssistant: timeout",
                "payload": json.dumps({"monitor": {"name": "HomeAssistant"}}),
            },
            {
                "ts": now - 700,
                "kuma_status": 0,
                "monitor_detail": "Plex: timeout",
                "payload": json.dumps({"monitor": {"name": "Plex"}}),
            },
            {
                "ts": now - 600,
                "kuma_status": 0,
                "monitor_detail": "HomeAssistant: still down",
                "payload": json.dumps({"monitor": {"name": "HomeAssistant"}}),
            },
        ]
        lines = proxy.build_outage_digest_lines(rows, recovery_ts=now)
        self.assertEqual(len(lines), 2)
        self.assertIn("HomeAssistant", lines[0])
        self.assertIn("12m", lines[0])
        self.assertIn("Plex", lines[1])

    def test_flush_clears_queue(self):
        import linkmoth_kuma_proxy as proxy
        import linkmoth
        tmp = tempfile.mkdtemp()
        try:
            state = Path(tmp) / "state"
            state.mkdir()
            os.environ["LINKMOTH_STATE_DIR"] = str(state)
            for _mod in ("linkmoth", 'linkmoth_core', 'linkmoth_probes', 'linkmoth_engine', 'linkmoth_handler'):
                if _mod in sys.modules:
                    del sys.modules[_mod]
            linkmoth = importlib.import_module("linkmoth")
            linkmoth.init_db()
            payload = {"monitor": {"name": "Plex"}, "heartbeat": {"status": 0}}
            proxy.record_suppressed(
                linkmoth.db, 0, "Plex: down", {"code": "wan_down"},
                payload, "test",
            )
            lines = proxy.flush_suppression_digest(linkmoth.db, recovery_ts=time.time())
            self.assertEqual(len(lines), 1)
            with linkmoth.db() as conn:
                n = conn.execute("SELECT COUNT(*) AS c FROM suppressed_alerts").fetchone()["c"]
            self.assertEqual(n, 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            os.environ.pop("LINKMOTH_STATE_DIR", None)

    def test_suppressed_alerts_are_minimized_and_capped(self):
        import linkmoth_kuma_proxy as proxy
        tmp = tempfile.mkdtemp()
        try:
            state = Path(tmp) / "state"
            state.mkdir()
            os.environ["LINKMOTH_STATE_DIR"] = str(state)
            for _mod in ("linkmoth", 'linkmoth_core', 'linkmoth_probes', 'linkmoth_engine', 'linkmoth_handler'):
                if _mod in sys.modules:
                    del sys.modules[_mod]
            linkmoth = importlib.import_module("linkmoth")
            linkmoth.init_db()
            with mock.patch.object(proxy, "MAX_SUPPRESSED_ALERTS", 3):
                for i in range(5):
                    proxy.record_suppressed(
                        linkmoth.db, 0, f"Service {i}: down", {"code": "wan_down"},
                        {
                            "monitor": {"name": f"Service {i}"},
                            "msg": "secret-payload-value",
                            "authorization": "Bearer must-not-persist",
                        },
                        "test",
                    )
            with linkmoth.db() as conn:
                rows = conn.execute(
                    "SELECT payload FROM suppressed_alerts ORDER BY id"
                ).fetchall()
            self.assertEqual(len(rows), 3)
            stored = " ".join(row["payload"] for row in rows)
            self.assertNotIn("secret-payload-value", stored)
            self.assertNotIn("must-not-persist", stored)
            self.assertIn("Service 4", stored)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            os.environ.pop("LINKMOTH_STATE_DIR", None)


class KumaProxyHandlerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="linkmoth_kuma_proxy_")
        self.state = Path(self.tmp) / "state"
        self.state.mkdir()
        self.config_path = Path(self.tmp) / "config.json"
        self.config = {
            "bind": "127.0.0.1",
            "port": 0,
            "discord_webhook_url": WEBHOOK,
            "discord_notifications_enabled": True,
        }
        self.config_path.write_text(json.dumps(self.config))
        os.environ["LINKMOTH_CONFIG"] = str(self.config_path)
        os.environ["LINKMOTH_STATE_DIR"] = str(self.state)
        for mod in ("linkmoth", 'linkmoth_core', 'linkmoth_probes', 'linkmoth_engine', 'linkmoth_handler', "linkmoth_kuma_proxy", "linkmoth_discord"):
            if mod in sys.modules:
                del sys.modules[mod]
        self.linkmoth = importlib.import_module("linkmoth")
        self.linkmoth.init_db()
        self.proxy = importlib.import_module("linkmoth_kuma_proxy")
        self.engine = self.linkmoth.Engine()
        self.discord_sent = []
        self.discord_patch = mock.patch(
            "linkmoth_kuma_proxy.send_kuma_discord_alert",
            side_effect=lambda data, cfg=None: self.discord_sent.append(data) or True,
        )
        self.discord_patch.start()

    def tearDown(self):
        self.discord_patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)
        os.environ.pop("LINKMOTH_CONFIG", None)
        os.environ.pop("LINKMOTH_STATE_DIR", None)

    def _seed_run(self, code="all_clear", severity="ok", incident_id=None):
        v = {
            "all_clear": ("ok", "All clear"),
            "wan_down": ("bad", "WAN down"),
            "pihole_broken": ("bad", "Pi-hole broken"),
        }[code]
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO runs(incident_id, ts, severity, code, title, explain, hint, checks, duration_ms, kind)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    incident_id, time.time(), severity, code, v[1],
                    "detail", "hint", json.dumps([
                        {"id": "raw_ping", "label": "Raw internet (ping)", "ok": code == "all_clear", "detail": "x"},
                    ]), 1.0, "baseline",
                ),
            )

    def test_suppresses_when_wan_down(self):
        self._seed_run("wan_down", "bad")
        result = self.proxy.handle_kuma_webhook(
            KUMA_DOWN, self.engine, self.config, self.linkmoth.db,
        )
        self.assertEqual(result["action"], "suppressed")
        self.assertEqual(result["reason"], "global_outage")
        self.assertEqual(len(self.discord_sent), 0)
        with self.linkmoth.db() as conn:
            n = conn.execute("SELECT COUNT(*) AS c FROM suppressed_alerts").fetchone()["c"]
        self.assertEqual(n, 1)

    def test_forwards_when_network_healthy(self):
        self._seed_run("all_clear", "ok")
        trigger_patch = mock.patch.object(self.engine, "trigger", return_value=1)
        with trigger_patch as trig:
            result = self.proxy.handle_kuma_webhook(
                KUMA_DOWN, self.engine, self.config, self.linkmoth.db,
            )
        self.assertEqual(result["action"], "forwarded")
        self.assertTrue(result["forwarded_discord"])
        self.assertEqual(len(self.discord_sent), 1)
        trig.assert_called_once()

    def test_quiet_hours_defer_healthy_kuma_forward(self):
        self._seed_run("all_clear", "ok")
        with mock.patch.object(self.engine, "trigger", return_value=1), mock.patch(
            "linkmoth_notify.defer_notification_if_quiet", return_value=True,
        ):
            result = self.proxy.handle_kuma_webhook(
                KUMA_DOWN, self.engine, self.config, self.linkmoth.db,
            )
        self.assertEqual(result["action"], "deferred")
        self.assertTrue(result["quiet_hours_deferred"])
        self.assertFalse(result["forwarded_discord"])
        self.assertEqual(self.discord_sent, [])

    def test_forwards_pihole_fault_not_global_outage(self):
        self._seed_run("pihole_broken", "bad")
        with mock.patch.object(self.engine, "trigger", return_value=1):
            result = self.proxy.handle_kuma_webhook(
                KUMA_DOWN, self.engine, self.config, self.linkmoth.db,
            )
        self.assertEqual(result["action"], "forwarded")
        self.assertEqual(len(self.discord_sent), 1)

    def test_compound_outage_suppresses(self):
        checks = [
            {"id": "gateway", "ok": True, "label": "Router (LAN)", "detail": "ok"},
            {"id": "upstream_dns", "ok": False, "label": "Upstream DNS", "detail": "dead"},
            {"id": "raw_ping", "ok": False, "label": "Raw internet (ping)", "detail": "dead"},
            {"id": "router_wlan", "ok": False, "label": "Router Wireless (WLAN)", "detail": "timeout"},
        ]
        with mock.patch.object(
            self.engine, "evaluate_network_for_proxy",
            return_value=(
                {"code": "wan_down", "title": "WAN down", "severity": "bad"},
                checks,
                False,
            ),
        ):
            result = self.proxy.handle_kuma_webhook(
                KUMA_DOWN, self.engine, self.config, self.linkmoth.db,
            )
        self.assertEqual(result["action"], "suppressed")
        self.assertEqual(len(self.discord_sent), 0)

    def test_active_incident_outage_suppresses_without_fresh_ladder(self):
        with self.linkmoth.db() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail) VALUES(?,?,?)",
                (time.time(), "baseline", "wan"),
            )
            inc_id = cur.lastrowid
        self._seed_run("wan_down", "bad", incident_id=inc_id)
        self._seed_run("all_clear", "ok")
        result = self.proxy.handle_kuma_webhook(
            KUMA_DOWN, self.engine, self.config, self.linkmoth.db,
        )
        self.assertEqual(result["action"], "suppressed")
        self.assertEqual(len(self.discord_sent), 0)


class InboundPayloadTests(unittest.TestCase):
    def test_parses_generic_shape(self):
        import linkmoth_kuma_proxy as proxy
        status, detail, source, raw = proxy.parse_inbound_payload(json.dumps({
            "source": "uptime-kuma",
            "event": "monitor_down",
            "monitor": "Cloudflare HTTPS",
            "severity": "critical",
            "message": "timeout",
        }).encode())
        self.assertIsNone(status)  # monitor_down is not a known up/down word
        self.assertEqual(source, "uptime-kuma")
        self.assertIn("Cloudflare HTTPS", detail)
        self.assertIn("timeout", detail)

    def test_status_words(self):
        import linkmoth_kuma_proxy as proxy
        for word in ("down", "alert", "fault", "problem", "firing"):
            self.assertEqual(
                proxy.parse_inbound_payload(json.dumps({"event": word}).encode())[0],
                0,
            )
        for word in ("up", "recovered", "resolved", "ok"):
            self.assertEqual(
                proxy.parse_inbound_payload(json.dumps({"event": word}).encode())[0],
                1,
            )

    def test_source_sanitized_and_garbage_tolerated(self):
        import linkmoth_kuma_proxy as proxy
        status, detail, source, _ = proxy.parse_inbound_payload(
            json.dumps({"source": "My Grafana!! <x>", "event": "down"}).encode()
        )
        self.assertEqual(status, 0)
        self.assertEqual(source, "mygrafanax")
        status, detail, source, _ = proxy.parse_inbound_payload(b"not json")
        self.assertIsNone(status)
        self.assertEqual(source, "external")
        self.assertEqual(detail, "external: webhook")


class InboundHandlerTests(KumaProxyHandlerTests):
    """Same fixtures as the Kuma handler tests, exercising the generic path."""

    def test_inbound_triggers_diagnosis_when_healthy(self):
        self._seed_run("all_clear", "ok")
        body = json.dumps({
            "source": "grafana", "event": "down",
            "monitor": "WAN probe", "message": "no route",
        }).encode()
        with mock.patch.object(self.engine, "trigger", return_value=1) as trig:
            result = self.proxy.handle_inbound_webhook(
                body, self.engine, self.config, self.linkmoth.db,
            )
        self.assertEqual(result["action"], "triggered")
        self.assertFalse(result["forwarded_discord"])
        self.assertEqual(len(self.discord_sent), 0)  # no Discord for generic inbound
        trig.assert_called_once()
        self.assertEqual(trig.call_args[0][0], "grafana-down")

    def test_inbound_suppressed_during_outage(self):
        self._seed_run("wan_down", "bad")
        body = json.dumps({"source": "zabbix", "event": "problem"}).encode()
        result = self.proxy.handle_inbound_webhook(
            body, self.engine, self.config, self.linkmoth.db,
        )
        self.assertEqual(result["action"], "suppressed")
        with self.linkmoth.db() as conn:
            n = conn.execute("SELECT COUNT(*) AS c FROM suppressed_alerts").fetchone()["c"]
        self.assertEqual(n, 1)


class KumaProxyRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="linkmoth_kuma_route_")
        self.state = Path(self.tmp) / "state"
        self.state.mkdir()
        self.config_path = Path(self.tmp) / "config.json"
        self.config = {
            "bind": "127.0.0.1",
            "port": 0,
            "discord_webhook_url": WEBHOOK,
            "discord_notifications_enabled": True,
        }
        self.config_path.write_text(json.dumps(self.config))
        os.environ["LINKMOTH_CONFIG"] = str(self.config_path)
        os.environ["LINKMOTH_STATE_DIR"] = str(self.state)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        os.environ.pop("LINKMOTH_CONFIG", None)
        os.environ.pop("LINKMOTH_STATE_DIR", None)

    def test_route_requires_bearer(self):
        from test_linkmoth_auth import http, LinkmothTestBase
        case = LinkmothTestBase()
        case.setUp()
        self.addCleanup(case.tearDown)
        case.auth.set_password("secret-pass-12")
        webhook = case.auth.ensure_webhook_secret()
        code, body, _, _ = http(
            "POST",
            f"{case.base}/api/webhooks/kuma",
            json.loads(KUMA_DOWN.decode()),
        )
        self.assertEqual(code, 401)
        with mock.patch("linkmoth_kuma_proxy.handle_kuma_webhook", return_value={"action": "forwarded"}):
            code, body, _, _ = http(
                "POST",
                f"{case.base}/api/webhooks/kuma",
                json.loads(KUMA_DOWN.decode()),
                headers={"Authorization": f"Bearer {webhook}"},
            )
        self.assertEqual(code, 200)
        self.assertEqual(body["action"], "forwarded")

    def test_inbound_route_requires_bearer(self):
        from test_linkmoth_auth import http, LinkmothTestBase
        case = LinkmothTestBase()
        case.setUp()
        self.addCleanup(case.tearDown)
        case.auth.set_password("secret-pass-12")
        webhook = case.auth.ensure_webhook_secret()
        payload = {"source": "test", "event": "down", "monitor": "WAN"}
        code, body, _, _ = http(
            "POST", f"{case.base}/api/webhooks/inbound", payload,
        )
        self.assertEqual(code, 401)
        with mock.patch(
            "linkmoth_kuma_proxy.handle_inbound_webhook",
            return_value={"action": "triggered"},
        ):
            code, body, _, _ = http(
                "POST",
                f"{case.base}/api/webhooks/inbound",
                payload,
                headers={"Authorization": f"Bearer {webhook}"},
            )
        self.assertEqual(code, 200)
        self.assertEqual(body["action"], "triggered")


if __name__ == "__main__":
    unittest.main()

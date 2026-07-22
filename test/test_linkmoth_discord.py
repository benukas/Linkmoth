#!/usr/bin/env python3
"""Tests for Linkmoth Discord webhook notifications."""
import importlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

import linkmoth_discord


WEBHOOK = "https://discord.com/api/webhooks/123456789/abcdefghijklmnop"

SAMPLE_CHECKS = [
    {"id": "link", "label": "Host network link", "ok": True, "detail": "eth0: link up"},
    {"id": "gateway", "label": "Router (LAN)", "ok": True, "detail": "192.168.1.1: 2 ms"},
    {"id": "upstream_dns", "label": "Upstream DNS (direct)", "ok": False,
     "detail": "@1.1.1.1: no answer"},
    {"id": "raw_ping", "label": "Raw internet (ping)", "ok": False,
     "detail": "1.1.1.1: no reply"},
]


class DiscordEmbedTests(unittest.TestCase):
    def test_partial_probe_evidence_is_amber_and_expanded(self):
        lines = linkmoth_discord.format_ladder_lines([{
            "id": "upstream_dns",
            "label": "Upstream DNS (direct)",
            "ok": True,
            "state": "partial",
            "detail": "1/2 targets answered",
            "probes": [
                {"target": "1.1.1.1", "ok": True, "detail": "answered"},
                {"target": "8.8.8.8", "ok": False, "detail": "no answer"},
            ],
        }])
        self.assertIn("🟡 Upstream DNS (direct)", lines)
        self.assertIn("↳ 🔴 8.8.8.8: no answer", lines)

    def test_fault_embed_with_ladder(self):
        data = linkmoth_discord.incident_payload(
            {"id": 7, "ref": "INC-20260705-0007", "started": time.time(), "source": "kuma-down", "detail": "WAN monitor"},
            {
                "severity": "bad",
                "code": "wan_down",
                "title": "Internet is dead beyond the router",
                "explain": "LAN and router are fine, but nothing outside answers (DNS by IP, ping).",
                "hint": "Check the router's WAN cable and WAN light, then your internet provider's status page.",
            },
            "fault",
            checks=SAMPLE_CHECKS,
        )
        embed = linkmoth_discord.build_embed(data, "fault")
        self.assertIn("🚨", embed["title"])
        self.assertIn("Internet is dead beyond the router", embed["title"])
        self.assertEqual(embed["color"], 0xE74C3C)
        ref_field = next(f for f in embed["fields"] if f["name"] == "Reference")
        self.assertEqual(ref_field["value"], "INC-20260705-0007")
        self.assertIn("INC-20260705-0007", embed["footer"]["text"])
        ladder = next(f for f in embed["fields"] if f["name"] == "Fault ladder")
        self.assertIn("🟢 Host network link", ladder["value"])
        self.assertIn("🔴 Upstream DNS (direct): @1.1.1.1: no answer", ladder["value"])
        self.assertIn("Next step", embed["description"])

    def test_recovery_embed_with_ladder(self):
        data = linkmoth_discord.incident_payload(
            {"id": 3, "ref": "INC-20260705-0003", "started": time.time() - 120, "source": "kuma-down", "detail": "test"},
            {
                "severity": "ok",
                "code": "all_clear",
                "title": "All clear – everything answers",
                "explain": "Router, upstream DNS, ping and HTTPS all respond normally.",
                "hint": "",
            },
            "recovery",
            prior_fault={"code": "wan_down", "title": "Internet is dead beyond the router"},
            checks=[
                {"id": "link", "label": "Host network link", "ok": True, "detail": "eth0: link up"},
                {"id": "raw_ping", "label": "Raw internet (ping)", "ok": True, "detail": "1.1.1.1: 12 ms"},
            ],
        )
        embed = linkmoth_discord.build_embed(data, "recovery")
        self.assertIn("✅", embed["title"])
        self.assertEqual(embed["color"], 0x2ECC71)
        inc_field = next(f for f in embed["fields"] if f["name"] == "Incident")
        self.assertEqual(inc_field["value"], "INC-20260705-0003")
        self.assertIn("INC-20260705-0003", embed["footer"]["text"])
        ladder = next(f for f in embed["fields"] if f["name"] == "Fault ladder")
        self.assertIn("🟢 Raw internet (ping)", ladder["value"])

    def test_recovery_embed_prefers_fault_checks_over_healthy_checks(self):
        # This is the reported bug: a WAN-down recovery notification with
        # only the just-confirmed *healthy* ladder tells the reader nothing
        # about what was actually wrong. When fault_checks is available it
        # must be what's shown, not the all-green closing run.
        data = linkmoth_discord.incident_payload(
            {"id": None, "ref": None, "started": time.time() - 2820,
             "source": "linkmoth", "detail": "Global outage cleared"},
            {"severity": "ok", "code": "all_clear", "title": "All network checks passed",
             "explain": "Router, local DNS, upstream DNS, ping and HTTPS all respond normally.",
             "hint": ""},
            "recovery",
            prior_fault={"code": "wan_down", "title": "Internet is dead beyond the router"},
            checks=[
                {"id": "raw_ping", "label": "Internet ping", "ok": True, "detail": "1.1.1.1: 11 ms"},
                {"id": "gateway", "label": "Router", "ok": True, "detail": "1 ms"},
            ],
            fault_checks=[
                {"id": "raw_ping", "label": "Internet ping", "ok": False, "detail": "1.1.1.1: no reply"},
                {"id": "gateway", "label": "Router", "ok": True, "detail": "1 ms"},
            ],
        )
        embed = linkmoth_discord.build_embed(data, "recovery")
        ladder = next(f for f in embed["fields"] if f["name"].startswith("Fault ladder"))
        self.assertEqual(ladder["name"], "Fault ladder (at time of fault)")
        self.assertIn("🔴 Internet ping: 1.1.1.1: no reply", ladder["value"])
        self.assertNotIn("🟢 Internet ping", ladder["value"])

    def test_recovery_embed_without_fault_checks_falls_back_to_current(self):
        data = linkmoth_discord.incident_payload(
            {"id": 9, "ref": "INC-20260710-0009", "started": time.time() - 120,
             "source": "incident-loop", "detail": "test"},
            {"severity": "ok", "code": "all_clear", "title": "All clear", "explain": "", "hint": ""},
            "recovery",
            checks=[{"id": "raw_ping", "label": "Internet ping", "ok": True, "detail": "ok"}],
        )
        embed = linkmoth_discord.build_embed(data, "recovery")
        ladder = next(f for f in embed["fields"] if f["name"].startswith("Fault ladder"))
        self.assertEqual(ladder["name"], "Fault ladder")

    def test_recovery_embed_omits_incident_field_for_global_outage(self):
        # The outage tracker's recovery has no real incidents-table row –
        # a bare "Incident: –" field is noise, not information.
        data = linkmoth_discord.incident_payload(
            {"id": None, "ref": None, "started": time.time() - 60,
             "source": "linkmoth", "detail": "Global outage cleared"},
            {"severity": "ok", "code": "all_clear", "title": "All clear", "explain": "", "hint": ""},
            "recovery",
            prior_fault={"code": "wan_down", "title": "WAN down"},
        )
        embed = linkmoth_discord.build_embed(data, "recovery")
        self.assertFalse(any(f["name"] == "Incident" for f in embed["fields"]))
        duration_field = next(f for f in embed["fields"] if f["name"] == "Duration")
        self.assertNotEqual(duration_field["value"], "–")

    def test_recovery_embed_includes_suppressed_digest(self):
        data = linkmoth_discord.incident_payload(
            {"id": 5, "started": time.time() - 900, "source": "kuma-down", "detail": "wan"},
            {"severity": "ok", "code": "all_clear", "title": "All clear", "explain": "", "hint": ""},
            "recovery",
            suppressed_digest=[
                "• HomeAssistant (Down for 12m)",
                "• Plex (Down for 10m)",
            ],
        )
        embed = linkmoth_discord.build_embed(data, "recovery")
        digest = next(f for f in embed["fields"] if "Services Affected" in f["name"])
        self.assertIn("HomeAssistant", digest["value"])
        self.assertIn("Plex", digest["value"])

class DiscordConfigTests(unittest.TestCase):
    def test_env_overrides_config(self):
        cfg = {"discord_webhook_url": "https://discord.com/api/webhooks/1/a"}
        with mock.patch.dict(os.environ, {"LINKMOTH_DISCORD_WEBHOOK_URL": WEBHOOK}):
            self.assertEqual(linkmoth_discord.discord_webhook_url(cfg), WEBHOOK)

    def test_invalid_webhook_rejected(self):
        self.assertFalse(linkmoth_discord.is_valid_discord_webhook("http://discord.com/api/webhooks/1/a"))
        self.assertFalse(linkmoth_discord.is_valid_discord_webhook("https://evil.example/webhook"))

    def test_webhook_authority_is_parsed_without_userinfo_confusion(self):
        self.assertTrue(linkmoth_discord.is_valid_discord_webhook(WEBHOOK))
        self.assertTrue(linkmoth_discord.is_valid_discord_webhook(
            "https://discord.com:443/api/webhooks/1/a?wait=true",
        ))
        self.assertFalse(linkmoth_discord.is_valid_discord_webhook(
            "https://discord.com:443@127.0.0.1:9443/api/webhooks/1/a",
        ))
        self.assertFalse(linkmoth_discord.is_valid_discord_webhook(
            "https://discord.com:8443/api/webhooks/1/a",
        ))
        self.assertFalse(linkmoth_discord.is_valid_discord_webhook(
            "https://discord.com:not-a-port/api/webhooks/1/a",
        ))
        self.assertFalse(linkmoth_discord.is_valid_discord_webhook(
            "https://discord.com/api/webhooks/1/a#fragment",
        ))


class DiscordSendTests(unittest.TestCase):
    def test_send_spawns_background_thread(self):
        started = threading.Event()

        def fake_sync(url, data, status_type):
            started.set()

        with mock.patch.object(linkmoth_discord, "_send_sync", side_effect=fake_sync):
            ok = linkmoth_discord.send_discord_alert(
                {"incident_id": 1, "verdict": {"title": "x"}},
                "fault",
                {"discord_webhook_url": WEBHOOK, "discord_notifications_enabled": True},
            )
        self.assertTrue(ok)
        self.assertTrue(started.wait(2))

    def test_disabled_notifications_is_noop(self):
        with mock.patch.object(linkmoth_discord, "_send_sync") as fake_sync:
            ok = linkmoth_discord.send_discord_alert(
                {"incident_id": 1, "verdict": {"title": "x"}},
                "fault",
                {"discord_webhook_url": WEBHOOK, "discord_notifications_enabled": False},
            )
        self.assertFalse(ok)
        fake_sync.assert_not_called()

    def test_alerts_active_requires_enabled_and_valid_url(self):
        cfg = {"discord_webhook_url": WEBHOOK, "discord_notifications_enabled": True}
        self.assertTrue(linkmoth_discord.discord_alerts_active(cfg))
        self.assertFalse(linkmoth_discord.discord_alerts_active(
            {"discord_webhook_url": WEBHOOK, "discord_notifications_enabled": False},
        ))
        self.assertFalse(linkmoth_discord.discord_alerts_active(
            {"discord_webhook_url": "", "discord_notifications_enabled": True},
        ))

    def test_send_errors_do_not_propagate(self):
        with mock.patch.object(linkmoth_discord, "_post_webhook", side_effect=TimeoutError("slow")):
            err = StringIO()
            with mock.patch("sys.stderr", err):
                linkmoth_discord._send_sync(
                    WEBHOOK,
                    {"incident_id": 1, "verdict": {}, "checks": []},
                    "fault",
                )
            self.assertIn("discord alert failed", err.getvalue())

    def test_empty_url_is_noop(self):
        self.assertFalse(linkmoth_discord.send_discord_alert({}, "fault", {}))

    def test_quiet_hours_digest_is_one_summary(self):
        sent = threading.Event()
        captured = []

        def fake_send(url, payload, label):
            captured.append((url, payload, label))
            sent.set()

        cfg = {
            "discord_webhook_url": WEBHOOK,
            "discord_notifications_enabled": True,
            "quiet_hours_start": "22:00",
            "quiet_hours_end": "07:00",
        }
        with mock.patch.object(
            linkmoth_discord, "_send_payload_sync", side_effect=fake_send,
        ):
            self.assertTrue(linkmoth_discord.send_quiet_hours_digest_alert(
                ["• Printer is down", "• WAN recovered"], 2, cfg,
            ))
            self.assertTrue(sent.wait(2))
        self.assertEqual(len(captured), 1)
        embed = captured[0][1]["embeds"][0]
        self.assertIn("Quiet-hours summary", embed["title"])
        self.assertIn("Printer is down", embed["description"])
        self.assertIn("22:00 to 07:00", embed["description"])


class EngineDiscordIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="linkmoth_discord_")
        self.state = Path(self.tmp) / "state"
        self.state.mkdir()
        self.config_path = Path(self.tmp) / "config.json"
        self.config = {
            "bind": "127.0.0.1",
            "port": 0,
            "recheck_seconds": [0],
            "recheck_repeat": 9999,
            "baseline_minutes": 0,
            "discord_webhook_url": WEBHOOK,
            "discord_notifications_enabled": True,
        }
        self.config_path.write_text(json.dumps(self.config))
        os.environ["LINKMOTH_CONFIG"] = str(self.config_path)
        os.environ["LINKMOTH_STATE_DIR"] = str(self.state)
        for mod in ("linkmoth", 'linkmoth_core', 'linkmoth_probes', 'linkmoth_engine', 'linkmoth_handler', "linkmoth_discord"):
            if mod in sys.modules:
                del sys.modules[mod]
        self.linkmoth = importlib.import_module("linkmoth")
        self.linkmoth.init_db()
        self.engine = self.linkmoth.Engine()
        self.sent = []
        import linkmoth_notify
        linkmoth_notify._recovery_sent_mono.clear()
        # OUTAGE_TRACKER is a process-wide singleton; reset its in-memory
        # counter so state from an earlier test file can't leak in.
        from linkmoth_outage import OUTAGE_TRACKER
        OUTAGE_TRACKER._consecutive_clear = 0
        self._patch = mock.patch(
            "linkmoth_discord.send_discord_alert",
            side_effect=self._capture,
        )
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)
        os.environ.pop("LINKMOTH_CONFIG", None)
        os.environ.pop("LINKMOTH_STATE_DIR", None)

    def _capture(self, incident_data, status_type, cfg=None):
        self.sent.append((status_type, incident_data))
        return True

    def _open_incident(self):
        with self.linkmoth.db() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail) VALUES(?,?,?)",
                (time.time(), "test", "integration"),
            )
            return cur.lastrowid

    def test_fault_on_first_bad_ladder_run(self):
        inc_id = self._open_incident()
        verdicts = [
            {"severity": "bad", "code": "wan_down", "title": "WAN down",
             "explain": "dead", "hint": "check WAN"},
            {"severity": "ok", "code": "all_clear", "title": "All clear",
             "explain": "fine", "hint": ""},
            {"severity": "ok", "code": "all_clear", "title": "All clear",
             "explain": "fine", "hint": ""},
        ]

        def fake_diagnose(incident_id=None, kind=None):
            v = verdicts.pop(0)
            with self.linkmoth.db() as conn:
                conn.execute(
                    "INSERT INTO runs(incident_id, ts, severity, code, title, explain, hint, checks, duration_ms, kind)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (incident_id, time.time(), v["severity"], v["code"], v["title"],
                     v["explain"], v["hint"], json.dumps(SAMPLE_CHECKS), 1.0, kind or "incident"),
                )
            self.engine._observe_network(v, SAMPLE_CHECKS, kind or "incident")
            return v

        with mock.patch.object(self.engine, "diagnose_once", side_effect=fake_diagnose):
            with mock.patch("linkmoth.time.sleep"):
                self.engine._loop(inc_id)

        types = [t for t, _ in self.sent]
        self.assertEqual(types, ["recovery"])
        self.assertEqual(self.sent[0][1]["prior_fault"]["code"], "wan_down")
        self.assertTrue(self.sent[0][1]["checks"])

    def test_no_fault_alert_on_false_alarm(self):
        inc_id = self._open_incident()
        ok = {"severity": "ok", "code": "all_clear", "title": "All clear",
              "explain": "fine", "hint": ""}

        def fake_diagnose(incident_id=None, kind=None):
            with self.linkmoth.db() as conn:
                conn.execute(
                    "INSERT INTO runs(incident_id, ts, severity, code, title, explain, hint, checks, duration_ms, kind)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (incident_id, time.time(), ok["severity"], ok["code"], ok["title"],
                     ok["explain"], ok["hint"], json.dumps(SAMPLE_CHECKS), 1.0, kind or "incident"),
                )
            return dict(ok)

        with mock.patch.object(self.engine, "diagnose_once", side_effect=fake_diagnose):
            with mock.patch("linkmoth.time.sleep"):
                self.engine._loop(inc_id)

        types = [t for t, _ in self.sent]
        self.assertEqual(types, ["recovery"])

    def test_incident_loop_survives_transient_diagnose_error(self):
        """A transient failure during a recheck (e.g. a DB lock that exhausts
        its retry budget) must not kill the recheck thread and leave the
        incident stuck open forever -- the loop logs it and keeps going."""
        inc_id = self._open_incident()
        ok = {"severity": "ok", "code": "all_clear", "title": "All clear",
              "explain": "fine", "hint": ""}
        calls = {"n": 0}

        def fake_diagnose(incident_id=None, kind=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise sqlite3.OperationalError("database is locked")
            with self.linkmoth.db() as conn:
                conn.execute(
                    "INSERT INTO runs(incident_id, ts, severity, code, title, explain, hint, checks, duration_ms, kind)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (incident_id, time.time(), ok["severity"], ok["code"], ok["title"],
                     ok["explain"], ok["hint"], json.dumps(SAMPLE_CHECKS), 1.0, kind or "incident"),
                )
            return dict(ok)

        with mock.patch.object(self.engine, "diagnose_once", side_effect=fake_diagnose):
            with mock.patch("linkmoth.time.sleep"):
                # Must not propagate the transient error out of the loop.
                self.engine._loop(inc_id)

        # Kept running past the error (reached the two healthy rechecks) and
        # closed the incident rather than leaving it open forever.
        self.assertGreater(calls["n"], 1)
        with self.linkmoth.db() as conn:
            row = conn.execute(
                "SELECT resolved FROM incidents WHERE id=?", (inc_id,)
            ).fetchone()
        self.assertIsNotNone(row["resolved"])

    def test_recovery_flushes_suppressed_digest(self):
        import linkmoth_kuma_proxy as proxy
        now = time.time()
        proxy.record_suppressed(
            self.linkmoth.db, 0, "HomeAssistant: down", {"code": "wan_down"},
            {"monitor": {"name": "HomeAssistant"}, "heartbeat": {"status": 0}},
            "global network outage – alert silenced",
        )
        proxy.record_suppressed(
            self.linkmoth.db, 0, "Plex: down", {"code": "wan_down"},
            {"monitor": {"name": "Plex"}, "heartbeat": {"status": 0}},
            "global network outage – alert silenced",
        )
        inc_id = self._open_incident()
        ok = {"severity": "ok", "code": "all_clear", "title": "All clear",
              "explain": "fine", "hint": ""}

        def fake_diagnose(incident_id=None, kind=None):
            with self.linkmoth.db() as conn:
                conn.execute(
                    "INSERT INTO runs(incident_id, ts, severity, code, title, explain, hint, checks, duration_ms, kind)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (incident_id, time.time(), ok["severity"], ok["code"], ok["title"],
                     ok["explain"], ok["hint"], json.dumps(SAMPLE_CHECKS), 1.0, kind or "incident"),
                )
            return dict(ok)

        with mock.patch.object(self.engine, "diagnose_once", side_effect=fake_diagnose):
            with mock.patch("linkmoth.time.sleep"):
                self.engine._loop(inc_id)

        recovery = [p for t, p in self.sent if t == "recovery"]
        self.assertEqual(len(recovery), 1)
        self.assertIn("HomeAssistant", recovery[0]["suppressed_digest"][0])
        with self.linkmoth.db() as conn:
            n = conn.execute("SELECT COUNT(*) AS c FROM suppressed_alerts").fetchone()["c"]
        self.assertEqual(n, 0)


class SettingsValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="linkmoth_settings_")
        self.state = Path(self.tmp) / "state"
        self.state.mkdir()
        os.environ["LINKMOTH_STATE_DIR"] = str(self.state)
        for _mod in ("linkmoth", 'linkmoth_core', 'linkmoth_probes', 'linkmoth_engine', 'linkmoth_handler'):
            if _mod in sys.modules:
                del sys.modules[_mod]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        os.environ.pop("LINKMOTH_STATE_DIR", None)

    def test_enable_without_url_rejected(self):
        import linkmoth
        ok, result = linkmoth.apply_settings({
            "discord_notifications_enabled": True,
            "discord_webhook_url": "",
        })
        self.assertFalse(ok)
        self.assertIn("discord_webhook_url", result)

    def test_non_dict_settings_rejected_cleanly(self):
        """A restored backup's settings.json (or any other caller) handing
        apply_settings something other than an object used to reach
        data.items() and raise an uncaught AttributeError instead of the
        normal (False, errors) result every other invalid input gets."""
        import linkmoth
        for bad in ([1, 2, 3], "not an object", None, 42):
            ok, result = linkmoth.apply_settings(bad)
            self.assertFalse(ok)
            self.assertIn("_settings", result)

    def test_valid_discord_settings_saved(self):
        import linkmoth
        ok, result = linkmoth.apply_settings({
            "discord_notifications_enabled": True,
            "discord_webhook_url": WEBHOOK,
        })
        self.assertTrue(ok)
        self.assertTrue(result["discord_notifications_enabled"])
        self.assertEqual(result["discord_webhook_url"], linkmoth.SETTINGS_SECRET_MASK)
        self.assertEqual(linkmoth.CFG["discord_webhook_url"], WEBHOOK)
        self.assertEqual(
            json.loads(linkmoth.SETTINGS_PATH.read_text())["discord_webhook_url"],
            WEBHOOK,
        )
        if os.name == "posix":
            self.assertEqual(linkmoth.SETTINGS_PATH.stat().st_mode & 0o777, 0o600)

        ok, _ = linkmoth.apply_settings({
            "discord_notifications_enabled": True,
            "discord_webhook_url": linkmoth.SETTINGS_SECRET_MASK,
        })
        self.assertTrue(ok)
        self.assertEqual(linkmoth.CFG["discord_webhook_url"], WEBHOOK)


if __name__ == "__main__":
    unittest.main()

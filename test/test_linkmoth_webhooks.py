"""Tests for the outbound webhook engine: presets, templates, queue, migration."""
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
REPO_ROOT = BASE.parent
sys.path.insert(0, str(REPO_ROOT))

import linkmoth_webhooks as wh


class WebhookDbCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="linkmoth_webhooks_"))
        self.db_path = self.tmp / "state.db"
        with self.db() as conn:
            wh.init_webhook_db(conn)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS network_outage(
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    active INTEGER NOT NULL DEFAULT 0,
                    code TEXT, title TEXT, explain TEXT, started REAL, updated REAL
                )
                """
            )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @contextmanager
    def db(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def make_webhook(self, **overrides):
        data = {
            "name": "Test hook",
            "url": "https://example.test/hook",
            "preset": "generic",
            "events": ["fault_opened", "fault_recovered"],
        }
        data.update(overrides)
        return wh.create_webhook(self.db, data)


class ValidationTests(WebhookDbCase):
    def test_create_and_list(self):
        created = self.make_webhook()
        hooks = wh.list_webhooks(self.db)
        self.assertEqual(len(hooks), 1)
        self.assertEqual(hooks[0]["id"], created["id"])
        self.assertEqual(created["url"], wh.MASK)
        self.assertEqual(hooks[0]["url"], wh.MASK)
        self.assertEqual(
            wh.get_webhook(self.db, created["id"], mask=False)["url"],
            "https://example.test/hook",
        )
        self.assertEqual(hooks[0]["queued"], 0)

    def test_rejects_bad_url(self):
        for url in (
            "", "ftp://x", "http://user:pw@host/x", "not a url",
            "https://host:bad/hook", "https://host/hook#secret",
            "https://host\\@127.0.0.1/hook", "https://host/unsafe path",
            "http://example.test/hook",
        ):
            with self.assertRaises(ValueError):
                self.make_webhook(url=url)

    def test_accepts_explicit_private_ipv4_webhook(self):
        hook = self.make_webhook(url="http://192.168.1.20/hook")
        self.assertEqual(hook["url"], wh.MASK)

    def test_delivery_rejects_hostname_that_resolves_private(self):
        fake_result = [(None, None, None, None, ("127.0.0.1", 443))]
        with mock.patch.object(wh.socket, "getaddrinfo", return_value=fake_result):
            with self.assertRaises(ValueError):
                wh._validate_delivery_target("https://example.test/hook")

    def test_rejects_loopback_literal_webhook_at_creation(self):
        # An authenticated admin must not be able to point a webhook at the
        # host's own loopback services (SSRF) – for any 127.0.0.0/8 address,
        # over either scheme.
        for url in (
            "http://127.0.0.1/hook",
            "https://127.0.0.1/hook",
            "http://127.0.0.5:22/hook",
            "https://127.255.255.254/hook",
        ):
            with self.assertRaises(ValueError):
                self.make_webhook(url=url)

    def test_delivery_rejects_loopback_literal(self):
        # The same rejection must also hold at delivery time, not just creation.
        with self.assertRaises(ValueError):
            wh._resolve_pinned_target("https://127.0.0.1:22/")

    def test_still_accepts_explicit_private_ipv4_over_http(self):
        # Removing the loopback allowance must not affect legitimate RFC1918 use.
        hook = self.make_webhook(url="http://10.1.2.3:9000/hook")
        self.assertEqual(hook["url"], wh.MASK)

    def test_rejects_unknown_preset_and_event(self):
        with self.assertRaises(ValueError):
            self.make_webhook(preset="jinja")
        with self.assertRaises(ValueError):
            self.make_webhook(events=["fault_opened", "made_up"])

    def test_rejects_forbidden_and_malformed_headers(self):
        with self.assertRaises(ValueError):
            self.make_webhook(headers={"Host": "evil"})
        with self.assertRaises(ValueError):
            self.make_webhook(headers={"X Bad Name": "x"})
        with self.assertRaises(ValueError):
            self.make_webhook(headers={"X-Ctl": "a\r\nInjected: yes"})
        with self.assertRaises(ValueError):
            self.make_webhook(headers={f"X-{i}": "v" for i in range(11)})

    def test_custom_preset_requires_json_template(self):
        with self.assertRaises(ValueError):
            self.make_webhook(preset="custom")
        with self.assertRaises(ValueError):
            self.make_webhook(preset="custom", template='{"title": {{title}}')
        hook = self.make_webhook(
            preset="custom", template='{"title": "{{title}}"}',
        )
        self.assertEqual(hook["preset"], "custom")

    def test_custom_template_non_json_content_type_skips_json_check(self):
        hook = self.make_webhook(
            preset="custom",
            template="event={{event}} title={{title}}",
            headers={"Content-Type": "text/plain"},
        )
        self.assertEqual(hook["preset"], "custom")

    def test_webhook_limit(self):
        for i in range(wh.MAX_WEBHOOKS):
            self.make_webhook(name=f"hook {i}")
        with self.assertRaises(wh.WebhookLimitReached):
            self.make_webhook(name="one too many")


class HeaderSecretTests(WebhookDbCase):
    def test_headers_masked_in_api_output(self):
        token = "Bearer super-secret-token-abcd"
        hook = self.make_webhook(headers={"Authorization": token})
        self.assertEqual(hook["headers"]["Authorization"], "••••••••abcd")
        raw = wh.get_webhook(self.db, hook["id"], mask=False)
        self.assertEqual(raw["headers"]["Authorization"], token)

    def test_masked_value_round_trip_keeps_secret(self):
        token = "Bearer super-secret-token-abcd"
        hook = self.make_webhook(headers={"Authorization": token})
        masked = hook["headers"]["Authorization"]
        updated = wh.update_webhook(
            self.db, hook["id"],
            {"name": "renamed", "headers": {"Authorization": masked}},
        )
        self.assertEqual(updated["name"], "renamed")
        raw = wh.get_webhook(self.db, hook["id"], mask=False)
        self.assertEqual(raw["headers"]["Authorization"], token)

    def test_new_value_replaces_secret(self):
        hook = self.make_webhook(headers={"Authorization": "Bearer old-token-1234"})
        wh.update_webhook(
            self.db, hook["id"], {"headers": {"Authorization": "Bearer new-token-9999"}},
        )
        raw = wh.get_webhook(self.db, hook["id"], mask=False)
        self.assertEqual(raw["headers"]["Authorization"], "Bearer new-token-9999")

    def test_short_values_fully_masked(self):
        self.assertEqual(wh.mask_header_value("abc"), "••••••••")

    def test_masked_url_round_trip_keeps_secret(self):
        hook = self.make_webhook(url="https://secret.example/hooks/token-value")
        self.assertEqual(hook["url"], wh.MASK)
        wh.update_webhook(self.db, hook["id"], {"name": "renamed", "url": wh.MASK})
        raw = wh.get_webhook(self.db, hook["id"], mask=False)
        self.assertEqual(raw["url"], "https://secret.example/hooks/token-value")


class TemplateTests(unittest.TestCase):
    def test_substitution_and_json_escaping(self):
        ctx = {"title": 'He said "boom"\nline2', "duration_seconds": 62,
               "delayed": True, "missing_ok": "x"}
        rendered = wh.render_template(
            '{"t": "{{title}}", "d": {{duration_seconds}}, "late": {{delayed}},'
            ' "gone": "{{unknown}}"}',
            ctx,
        )
        parsed = json.loads(rendered)
        self.assertEqual(parsed["t"], 'He said "boom"\nline2')
        self.assertEqual(parsed["d"], 62)
        self.assertIs(parsed["late"], True)
        self.assertEqual(parsed["gone"], "")

    def test_no_logic_no_attribute_access(self):
        ctx = {"title": "T"}
        self.assertEqual(
            wh.render_template("{{ title.upper() }}", ctx), "{{ title.upper() }}",
        )
        self.assertEqual(
            wh.render_template("{% for x in y %}", ctx), "{% for x in y %}",
        )
        self.assertEqual(wh.render_template("{{title|upper}}", ctx), "{{title|upper}}")


class ContextTests(unittest.TestCase):
    def test_fault_context_fields(self):
        ctx = wh.build_event_context(
            "fault_opened",
            verdict={"severity": "bad", "code": "wan_down",
                     "title": "WAN down", "explain": "No route", "hint": "check"},
            incident={"ref": "INC-20260707-0001", "started": 1000.0, "source": "kuma-down"},
            checks=[{"id": "link", "ok": True}],
        )
        self.assertEqual(ctx["event"], "fault_opened")
        self.assertEqual(ctx["status"], "fault")
        self.assertEqual(ctx["affected_layer"], "wan")
        self.assertEqual(ctx["incident_id"], "INC-20260707-0001")
        self.assertEqual(ctx["confidence"], "high")
        self.assertEqual(ctx["summary"], "No route")

    def test_affected_layers(self):
        cases = {"pi_link": "host", "host_power": "host", "router_down": "lan", "router_wlan_down": "wlan",
                 "wan_down": "wan", "restricted_connectivity": "wan",
                 "local_dns_broken": "dns", "web_broken": "web",
                 "all_clear": "none"}
        for code, layer in cases.items():
            self.assertEqual(wh.affected_layer_for("fault_opened", code), layer)
        self.assertEqual(wh.affected_layer_for("device_down", None), "device")

    def test_delayed_annotation(self):
        base = wh.build_event_context("fault_opened", verdict={"title": "x"})
        fresh = wh._finalize_context(base, queued_ts=1000.0, now=1030.0)
        self.assertFalse(fresh["delayed"])
        late = wh._finalize_context(base, queued_ts=1000.0, now=1100.0)
        self.assertTrue(late["delayed"])
        self.assertTrue(late["queued_at"].startswith("1970-01-01T00:16:40"))


class PresetRenderTests(unittest.TestCase):
    def ctx(self, **overrides):
        base = wh.build_event_context(
            "fault_opened",
            verdict={"severity": "bad", "code": "wan_down",
                     "title": "WAN down", "explain": "No route out.", "hint": ""},
            incident={"ref": "INC-1", "started": 1000.0, "source": "test"},
        )
        base = wh._finalize_context(base, queued_ts=time.time())
        base.update(overrides)
        return base

    def test_generic_payload_shape(self):
        body, ct, extra = wh.render_payload({"preset": "generic"}, self.ctx())
        self.assertEqual(ct, "application/json")
        self.assertEqual(extra, {})
        payload = json.loads(body)
        for key in ("event", "incident_id", "verdict", "severity", "confidence",
                    "duration_seconds", "affected_layer", "source", "title",
                    "body", "message", "timestamp", "delayed", "queued_at"):
            self.assertIn(key, payload)
        self.assertEqual(payload["verdict"], "wan_down")
        self.assertEqual(payload["message"], "WAN down\nNo route out.")

    def test_home_assistant_and_n8n_alias_generic(self):
        expected = wh.render_payload({"preset": "generic"}, self.ctx())[0]
        for preset in ("home_assistant", "n8n"):
            self.assertEqual(
                json.loads(wh.render_payload({"preset": preset}, self.ctx())[0]),
                json.loads(expected),
            )

    def test_public_exposure_detected_event_renders_without_an_incident(self):
        # Built exactly as Handler._reject_if_publicly_exposed does: no
        # incident, no checks, just a bare verdict-shaped warning.
        ctx = wh.build_event_context(
            "public_exposure_detected",
            verdict={
                "title": "Linkmoth rejected a public-internet connection",
                "explain": "Check your router's port-forwarding rules.",
                "severity": "warn",
            },
        )
        ctx = wh._finalize_context(ctx, queued_ts=time.time())
        self.assertIn("public_exposure_detected", wh.EVENT_IDS)
        self.assertEqual(wh.event_status("public_exposure_detected", "warn"), "info")
        for preset in ("generic", "discord", "slack", "ntfy", "gotify"):
            body, ct, extra = wh.render_payload({"preset": preset}, ctx)
            self.assertTrue(body)

    def test_ntfy_headers(self):
        body, ct, extra = wh.render_payload({"preset": "ntfy"}, self.ctx())
        self.assertTrue(ct.startswith("text/plain"))
        self.assertEqual(extra["X-Priority"], "5")
        self.assertEqual(extra["X-Tags"], "rotating_light")
        self.assertEqual(extra["X-Title"], "WAN down")
        self.assertIn(b"No route out.", body)

    def test_gotify_priorities(self):
        body, ct, _ = wh.render_payload({"preset": "gotify"}, self.ctx())
        self.assertEqual(json.loads(body)["priority"], 8)
        warn = self.ctx(severity="warn")
        self.assertEqual(
            json.loads(wh.render_payload({"preset": "gotify"}, warn)[0])["priority"], 5,
        )

    def test_discord_embed(self):
        body, ct, _ = wh.render_payload({"preset": "discord"}, self.ctx())
        payload = json.loads(body)
        embed = payload["embeds"][0]
        self.assertEqual(embed["color"], 0xE53935)
        names = [f["name"] for f in embed["fields"]]
        self.assertIn("Incident", names)
        self.assertIn("Verdict", names)

    def test_slack_text(self):
        body, ct, _ = wh.render_payload({"preset": "slack"}, self.ctx())
        text = json.loads(body)["text"]
        self.assertIn("*WAN down*", text)
        self.assertIn("INC-1", text)

    def test_custom_template(self):
        webhook = {"preset": "custom", "template": '{"s": "{{severity}}"}'}
        body, ct, _ = wh.render_payload(webhook, self.ctx())
        self.assertEqual(json.loads(body)["s"], "bad")


class QueueTests(WebhookDbCase):
    def test_emit_filters_by_subscription_and_enabled(self):
        subscribed = self.make_webhook(name="subscribed")
        self.make_webhook(name="other events", events=["device_down"])
        disabled = self.make_webhook(name="disabled", enabled=False)
        ctx = wh.build_event_context("fault_opened", verdict={"title": "x"})
        queued = wh.emit_event(self.db, "fault_opened", ctx)
        self.assertEqual(queued, 1)
        with self.db() as conn:
            rows = conn.execute("SELECT webhook_id FROM webhook_queue").fetchall()
        self.assertEqual([r["webhook_id"] for r in rows], [subscribed["id"]])
        self.assertNotEqual(rows[0]["webhook_id"], disabled["id"])

    def test_emit_rejects_unknown_event(self):
        with self.assertRaises(ValueError):
            wh.emit_event(self.db, "nope", {})

    def test_drain_success_deletes_and_records(self):
        hook = self.make_webhook()
        wh.emit_event(self.db, "fault_opened",
                      wh.build_event_context("fault_opened", verdict={"title": "x"}))
        with mock.patch.object(wh, "_post", return_value=200) as post:
            sent, failed = wh.drain_queue_once(self.db)
        self.assertEqual((sent, failed), (1, 0))
        self.assertEqual(post.call_count, 1)
        with self.db() as conn:
            remaining = conn.execute("SELECT COUNT(*) FROM webhook_queue").fetchone()[0]
        self.assertEqual(remaining, 0)
        refreshed = wh.get_webhook(self.db, hook["id"])
        self.assertEqual(refreshed["last_status"], 200)
        self.assertIsNone(refreshed["last_error"])

    def test_drain_failure_backs_off(self):
        self.make_webhook()
        wh.emit_event(self.db, "fault_opened",
                      wh.build_event_context("fault_opened", verdict={"title": "x"}))
        now = time.time()
        with mock.patch.object(wh, "_post", side_effect=OSError("boom")):
            sent, failed = wh.drain_queue_once(self.db, now=now)
        self.assertEqual((sent, failed), (0, 1))
        with self.db() as conn:
            row = conn.execute("SELECT * FROM webhook_queue").fetchone()
        self.assertEqual(row["attempts"], 1)
        self.assertAlmostEqual(row["next_attempt"], now + wh.BACKOFF_SECONDS[0], delta=1)
        # Second failure moves to the next backoff step.
        with mock.patch.object(wh, "_post", side_effect=OSError("boom")):
            wh.drain_queue_once(self.db, now=row["next_attempt"] + 1)
        with self.db() as conn:
            row2 = conn.execute("SELECT * FROM webhook_queue").fetchone()
        self.assertEqual(row2["attempts"], 2)
        self.assertAlmostEqual(
            row2["next_attempt"], row["next_attempt"] + 1 + wh.BACKOFF_SECONDS[1],
            delta=1,
        )

    def test_drain_gives_up_after_max_attempts(self):
        self.make_webhook()
        wh.emit_event(self.db, "fault_opened",
                      wh.build_event_context("fault_opened", verdict={"title": "x"}))
        now = time.time()
        with mock.patch.object(wh, "_post", side_effect=OSError("boom")):
            for _ in range(wh.MAX_ATTEMPTS):
                wh.drain_queue_once(self.db, now=now)
                with self.db() as conn:
                    row = conn.execute("SELECT next_attempt FROM webhook_queue").fetchone()
                if row is None:
                    break
                now = row["next_attempt"] + 1
        with self.db() as conn:
            remaining = conn.execute("SELECT COUNT(*) FROM webhook_queue").fetchone()[0]
        self.assertEqual(remaining, 0)

    def test_gone_endpoint_drops_early(self):
        self.make_webhook()
        wh.emit_event(self.db, "fault_opened",
                      wh.build_event_context("fault_opened", verdict={"title": "x"}))
        now = time.time()
        http_410 = mock.patch.object(
            wh, "_post",
            side_effect=wh.urlerror.HTTPError("u", 410, "Gone", {}, None),
        )
        with http_410:
            for _ in range(wh.GONE_MAX_ATTEMPTS):
                wh.drain_queue_once(self.db, now=now)
                with self.db() as conn:
                    row = conn.execute("SELECT next_attempt FROM webhook_queue").fetchone()
                if row is None:
                    break
                now = row["next_attempt"] + 1
        with self.db() as conn:
            remaining = conn.execute("SELECT COUNT(*) FROM webhook_queue").fetchone()[0]
        self.assertEqual(remaining, 0)

    def test_expired_rows_dropped(self):
        self.make_webhook()
        wh.emit_event(self.db, "fault_opened",
                      wh.build_event_context("fault_opened", verdict={"title": "x"}))
        with mock.patch.object(wh, "_post", return_value=200) as post:
            wh.drain_queue_once(self.db, now=time.time() + wh.MAX_AGE_SECONDS + 60)
        self.assertEqual(post.call_count, 0)
        with self.db() as conn:
            remaining = conn.execute("SELECT COUNT(*) FROM webhook_queue").fetchone()[0]
        self.assertEqual(remaining, 0)

    def test_max_escalation_delivery_not_expired_the_moment_it_becomes_due(self):
        # A 1440-minute (24h) escalation holds the row undelivered for
        # exactly MAX_AGE_SECONDS before it's ever due. The expiry check
        # must not count that hold time against the row's retry budget, or a
        # maximally-escalated fault would expire before its first attempt.
        wh_data = self.make_webhook()
        wh.update_webhook(self.db, wh_data["id"], {"escalation_minutes": 1440})
        ctx = wh.build_event_context("fault_opened", verdict={"title": "x"})
        wh.emit_event(self.db, "fault_opened", ctx)
        with self.db() as conn:
            row = conn.execute("SELECT * FROM webhook_queue").fetchone()
        self.assertAlmostEqual(row["escalation_seconds"], wh.MAX_AGE_SECONDS, delta=2)
        due_at = row["next_attempt"]
        # The drain loop only wakes periodically, so "now" at drain time is
        # always a little past the exact due instant – simulate that.
        with mock.patch.object(wh, "_post", return_value=200) as post:
            wh.drain_queue_once(self.db, now=due_at + 15)
        self.assertEqual(post.call_count, 1)
        with self.db() as conn:
            remaining = conn.execute("SELECT COUNT(*) FROM webhook_queue").fetchone()[0]
        self.assertEqual(remaining, 0)  # delivered and removed, not expired

    def test_max_escalation_delivery_still_expires_after_full_retry_budget(self):
        # Escalation-held rows must still expire eventually – the fix only
        # adds back the hold time, it doesn't grant unlimited retries.
        wh_data = self.make_webhook()
        wh.update_webhook(self.db, wh_data["id"], {"escalation_minutes": 1440})
        ctx = wh.build_event_context("fault_opened", verdict={"title": "x"})
        wh.emit_event(self.db, "fault_opened", ctx)
        with self.db() as conn:
            row = conn.execute("SELECT * FROM webhook_queue").fetchone()
        far_future = row["created"] + wh.MAX_AGE_SECONDS + row["escalation_seconds"] + 60
        with mock.patch.object(wh, "_post", return_value=200) as post:
            wh.drain_queue_once(self.db, now=far_future)
        self.assertEqual(post.call_count, 0)
        with self.db() as conn:
            remaining = conn.execute("SELECT COUNT(*) FROM webhook_queue").fetchone()[0]
        self.assertEqual(remaining, 0)  # dropped as expired

    def test_queue_cap_drops_oldest(self):
        self.make_webhook()
        ctx = wh.build_event_context("fault_opened", verdict={"title": "x"})
        with self.db() as conn:
            for i in range(wh.QUEUE_CAP):
                conn.execute(
                    "INSERT INTO webhook_queue(webhook_id, event, context, created,"
                    " next_attempt) VALUES(?,?,?,?,?)",
                    ("w", "fault_opened", "{}", i, i),
                )
        wh.emit_event(self.db, "fault_opened", ctx)
        with self.db() as conn:
            total = conn.execute("SELECT COUNT(*) FROM webhook_queue").fetchone()[0]
        self.assertEqual(total, wh.QUEUE_CAP)

    def test_escalation_delays_fault_delivery(self):
        wh_data = self.make_webhook()
        wh.update_webhook(self.db, wh_data["id"], {"escalation_minutes": 10})
        ctx = wh.build_event_context("fault_opened", verdict={"title": "x"})
        now = time.time()
        wh.emit_event(self.db, "fault_opened", ctx)
        with self.db() as conn:
            row = conn.execute("SELECT * FROM webhook_queue").fetchone()
        self.assertAlmostEqual(row["next_attempt"], now + 600, delta=2)
        # Not yet due: a drain right now must not deliver it.
        with mock.patch.object(wh, "_post", return_value=200) as post:
            wh.drain_queue_once(self.db, now=now)
        self.assertEqual(post.call_count, 0)

    def test_recovery_cancels_held_escalation(self):
        wh_data = self.make_webhook()
        wh.update_webhook(
            self.db, wh_data["id"],
            {"escalation_minutes": 10,
             "events": ["fault_opened", "fault_recovered"]},
        )
        wh.emit_event(
            self.db, "fault_opened",
            wh.build_event_context(
                "fault_opened", verdict={"title": "x"},
                incident={"ref": "INC-A"},
            ),
        )
        wh.emit_event(
            self.db, "fault_recovered",
            wh.build_event_context(
                "fault_recovered", verdict={"title": "ok"},
                incident={"ref": "INC-A"},
            ),
        )
        with self.db() as conn:
            events = [
                r["event"] for r in conn.execute(
                    "SELECT event FROM webhook_queue ORDER BY id"
                )
            ]
        # The held fault vanished; only the recovery remains queued.
        self.assertEqual(events, ["fault_recovered"])

    def test_recovery_keeps_other_incident_escalations(self):
        wh_data = self.make_webhook()
        wh.update_webhook(
            self.db, wh_data["id"],
            {"escalation_minutes": 10,
             "events": ["fault_opened", "false_alarm_marked"]},
        )
        wh.emit_event(
            self.db, "fault_opened",
            wh.build_event_context(
                "fault_opened", verdict={"title": "active"},
                incident={"ref": "INC-ACTIVE"},
            ),
        )
        wh.emit_event(
            self.db, "false_alarm_marked",
            wh.build_event_context(
                "false_alarm_marked", verdict={"title": "historical"},
                incident={"ref": "INC-HISTORICAL"},
            ),
        )
        with self.db() as conn:
            queued = [
                (row["event"], json.loads(row["context"])["incident_id"])
                for row in conn.execute(
                    "SELECT event, context FROM webhook_queue ORDER BY id"
                )
            ]
        self.assertEqual(queued, [
            ("fault_opened", "INC-ACTIVE"),
            ("false_alarm_marked", "INC-HISTORICAL"),
        ])

    def test_zero_escalation_keeps_immediate_delivery(self):
        self.make_webhook()
        now = time.time()
        wh.emit_event(
            self.db, "fault_opened",
            wh.build_event_context("fault_opened", verdict={"title": "x"}),
        )
        with self.db() as conn:
            row = conn.execute("SELECT * FROM webhook_queue").fetchone()
        self.assertAlmostEqual(row["next_attempt"], now, delta=2)

    def test_escalation_validation_bounds(self):
        with self.assertRaises(ValueError):
            wh._clean_escalation(-1)
        with self.assertRaises(ValueError):
            wh._clean_escalation(1441)
        with self.assertRaises(ValueError):
            wh._clean_escalation("soon")
        self.assertEqual(wh._clean_escalation(None), 0)
        self.assertEqual(wh._clean_escalation("15"), 15)

    def test_queue_cap_evicts_noisiest_webhook_not_others(self):
        # A full backlog from one noisy webhook must not evict another
        # webhook's only queued delivery.
        self.make_webhook()
        ctx = wh.build_event_context("fault_opened", verdict={"title": "x"})
        with self.db() as conn:
            conn.execute(
                "INSERT INTO webhook_queue(webhook_id, event, context, created,"
                " next_attempt) VALUES(?,?,?,?,?)",
                ("quiet", "fault_opened", "{}", 0, 0),
            )
            for i in range(wh.QUEUE_CAP - 1):
                conn.execute(
                    "INSERT INTO webhook_queue(webhook_id, event, context, created,"
                    " next_attempt) VALUES(?,?,?,?,?)",
                    ("noisy", "fault_opened", "{}", i + 1, i + 1),
                )
        wh.emit_event(self.db, "fault_opened", ctx)
        with self.db() as conn:
            total = conn.execute("SELECT COUNT(*) FROM webhook_queue").fetchone()[0]
            quiet = conn.execute(
                "SELECT COUNT(*) FROM webhook_queue WHERE webhook_id='quiet'"
            ).fetchone()[0]
            noisy_oldest = conn.execute(
                "SELECT MIN(created) FROM webhook_queue WHERE webhook_id='noisy'"
            ).fetchone()[0]
        self.assertEqual(total, wh.QUEUE_CAP)
        self.assertEqual(quiet, 1)
        self.assertGreater(noisy_oldest, 1)

    def test_delayed_flag_reaches_payload(self):
        self.make_webhook()
        wh.emit_event(self.db, "fault_opened",
                      wh.build_event_context("fault_opened", verdict={"title": "x"}))
        captured = {}

        def fake_post(url, body, headers, timeout=10):
            captured["payload"] = json.loads(body)
            return 200

        with mock.patch.object(wh, "_post", side_effect=fake_post):
            wh.drain_queue_once(self.db, now=time.time() + 3600)
        self.assertTrue(captured["payload"]["delayed"])

    def test_queue_visible_in_list(self):
        hook = self.make_webhook()
        wh.emit_event(self.db, "fault_opened",
                      wh.build_event_context("fault_opened", verdict={"title": "x"}))
        listed = wh.list_webhooks(self.db)[0]
        self.assertEqual(listed["id"], hook["id"])
        self.assertEqual(listed["queued"], 1)
        self.assertIsNotNone(listed["next_attempt"])


class TestSendTests(WebhookDbCase):
    def test_https_delivery_pins_the_validated_address(self):
        # Only one DNS resolution happens (the validation one) – the actual
        # connection reuses that answer instead of re-resolving the hostname,
        # closing the gap where a later DNS answer could redirect delivery
        # to a different address than the one just validated.
        fake_result = [(None, None, None, None, ("93.184.216.34", 443))]
        response = mock.MagicMock()
        response.status = 204
        response.reason = "No Content"
        response.getheaders.return_value = []
        response.read.return_value = b""
        conn = mock.MagicMock()
        conn.getresponse.return_value = response
        with (
            mock.patch.object(wh.socket, "getaddrinfo", return_value=fake_result) as getaddrinfo,
            mock.patch.object(wh, "_PinnedHTTPSConnection", return_value=conn) as pinned,
        ):
            status = wh._post("https://example.test/hook", b"{}", {})
        self.assertEqual(status, 204)
        self.assertEqual(getaddrinfo.call_count, 1)
        self.assertEqual(pinned.call_args.args, ("example.test", "93.184.216.34"))
        conn.request.assert_called_once_with("POST", "/hook", body=b"{}", headers={})
        response.read.assert_not_called()
        response.close.assert_called_once_with()
        conn.close.assert_called_once_with()

    def test_dual_stack_delivery_prefers_validated_ipv4(self):
        fake_result = [
            (None, None, None, None, ("2606:4700:4700::1111", 443, 0, 0)),
            (None, None, None, None, ("93.184.216.34", 443)),
        ]
        with mock.patch.object(wh.socket, "getaddrinfo", return_value=fake_result):
            target = wh._resolve_pinned_target("https://example.test/hook")
        self.assertEqual(target[-1], "93.184.216.34")

    def test_delivery_never_follows_a_redirect(self):
        fake_result = [(None, None, None, None, ("93.184.216.34", 443))]
        response = mock.MagicMock()
        response.status = 302
        response.reason = "Found"
        response.getheaders.return_value = [("Location", "http://internal.example/")]
        response.read.return_value = b""
        conn = mock.MagicMock()
        conn.getresponse.return_value = response
        with (
            mock.patch.object(wh.socket, "getaddrinfo", return_value=fake_result),
            mock.patch.object(wh, "_PinnedHTTPSConnection", return_value=conn),
        ):
            with self.assertRaises(wh.urlerror.HTTPError) as cm:
                wh._post("https://example.test/hook", b"{}", {})
        self.assertEqual(cm.exception.code, 302)
        conn.request.assert_called_once()
        response.read.assert_not_called()
        response.close.assert_called_once_with()
        conn.close.assert_called_once_with()
        # Mirrors _send_now's own defensive close(): a mocked HTTPError on
        # Python 3.9 can raise from an already-consumed temp file on close.
        try:
            cm.exception.close()
        except Exception:
            pass

    def test_send_test_uses_render_path(self):
        hook = self.make_webhook(preset="ntfy")
        captured = {}

        def fake_post(url, body, headers, timeout=10):
            captured["headers"] = headers
            captured["body"] = body
            return 200

        with mock.patch.object(wh, "_post", side_effect=fake_post):
            out = wh.send_test(self.db, hook["id"], "fault")
        self.assertTrue(out["ok"])
        self.assertEqual(out["status"], 200)
        self.assertEqual(captured["headers"]["X-Priority"], "5")

    def test_send_test_failure_reported(self):
        hook = self.make_webhook()
        with mock.patch.object(wh, "_post", side_effect=OSError("refused")):
            out = wh.send_test(self.db, hook["id"], "recovery")
        self.assertFalse(out["ok"])
        self.assertIn("refused", out["error"])
        refreshed = wh.get_webhook(self.db, hook["id"])
        self.assertIn("refused", refreshed["last_error"])

    def test_custom_headers_win_over_preset(self):
        hook = self.make_webhook(headers={"Content-Type": "application/xml",
                                          "Authorization": "Bearer tok-12345678"})
        captured = {}

        def fake_post(url, body, headers, timeout=10):
            captured["headers"] = headers
            return 200

        with mock.patch.object(wh, "_post", side_effect=fake_post):
            wh.send_test(self.db, hook["id"], "fault")
        self.assertEqual(captured["headers"]["Content-Type"], "application/xml")
        self.assertEqual(captured["headers"]["Authorization"], "Bearer tok-12345678")


class MigrationTests(WebhookDbCase):
    def test_migrates_once(self):
        settings = self.tmp / "settings.json"
        cfg = {"notify_webhook_url": "https://old.example/hook",
               "notify_webhook_enabled": True}
        self.assertTrue(wh.migrate_legacy_webhook(cfg, self.db, settings))
        hooks = wh.list_webhooks(self.db)
        self.assertEqual(len(hooks), 1)
        self.assertEqual(hooks[0]["url"], wh.MASK)
        self.assertEqual(
            wh.get_webhook(self.db, hooks[0]["id"], mask=False)["url"],
            "https://old.example/hook",
        )
        self.assertTrue(hooks[0]["enabled"])
        self.assertEqual(hooks[0]["events"], wh.LEGACY_EVENTS)
        self.assertTrue(json.loads(settings.read_text())[wh.MIGRATION_MARKER])
        # Second run is a no-op.
        self.assertFalse(wh.migrate_legacy_webhook(cfg, self.db, settings))
        self.assertEqual(len(wh.list_webhooks(self.db)), 1)
        if os.name == "posix":
            self.assertEqual(settings.stat().st_mode & 0o777, 0o600)

    def test_no_url_only_writes_marker(self):
        settings = self.tmp / "settings.json"
        self.assertFalse(wh.migrate_legacy_webhook({}, self.db, settings))
        self.assertEqual(wh.list_webhooks(self.db), [])
        self.assertTrue(json.loads(settings.read_text())[wh.MIGRATION_MARKER])

    def test_preserves_existing_settings_keys(self):
        settings = self.tmp / "settings.json"
        settings.write_text(json.dumps({"ui_refresh_seconds": 9}))
        wh.migrate_legacy_webhook({}, self.db, settings)
        data = json.loads(settings.read_text())
        self.assertEqual(data["ui_refresh_seconds"], 9)
        self.assertTrue(data[wh.MIGRATION_MARKER])


if __name__ == "__main__":
    unittest.main()

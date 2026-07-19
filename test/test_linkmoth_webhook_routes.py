"""End-to-end tests for the webhook manager routes and false-alarm flow."""
import ipaddress
import json
import sys
import threading
import time
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE = Path(__file__).resolve().parent
REPO_ROOT = BASE.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(BASE))

from test_linkmoth_auth import LinkmothTestBase, http


class _Catcher(BaseHTTPRequestHandler):
    received = []
    respond_with = 200

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        _Catcher.received.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
        })
        self.send_response(_Catcher.respond_with)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class WebhookRouteTests(LinkmothTestBase):
    @classmethod
    def setUpClass(cls):
        cls.catcher = ThreadingHTTPServer(("127.0.0.1", 0), _Catcher)
        threading.Thread(target=cls.catcher.serve_forever, daemon=True).start()
        cls.catcher_url = f"http://127.0.0.1:{cls.catcher.server_address[1]}/hook"

    @classmethod
    def tearDownClass(cls):
        cls.catcher.shutdown()
        cls.catcher.server_close()

    def setUp(self):
        super().setUp()
        # These tests deliver to a real loopback catcher to exercise the CRUD,
        # masking, queue, and lifecycle machinery. The product rejects loopback
        # webhook targets (SSRF hardening -- covered by the dedicated unit tests
        # in test_linkmoth_webhooks); here we permit only loopback literals at
        # creation and mock the delivery-time guard, keeping all other URL
        # validation intact.
        import linkmoth_webhooks as _wh

        real_clean_url = _wh._clean_url

        def clean_allowing_loopback(value):
            host = urlparse(str(value or "").strip()).hostname or ""
            try:
                addr = ipaddress.ip_address(host)
            except ValueError:
                addr = None
            if isinstance(addr, ipaddress.IPv4Address) and addr.is_loopback:
                return str(value).strip()
            return real_clean_url(value)

        self._clean_url_guard = mock.patch.object(
            _wh, "_clean_url", side_effect=clean_allowing_loopback,
        )
        self._clean_url_guard.start()
        self.addCleanup(self._clean_url_guard.stop)

        # The real delivery path (and _validate_delivery_target) call
        # _resolve_pinned_target to pin the address to connect to; allow the
        # loopback catcher there too while delegating everything else.
        real_resolve = _wh._resolve_pinned_target

        def resolve_allowing_loopback(url):
            parsed = urlparse(str(url))
            host = parsed.hostname or ""
            try:
                addr = ipaddress.ip_address(host)
            except ValueError:
                addr = None
            if isinstance(addr, ipaddress.IPv4Address) and addr.is_loopback:
                scheme = parsed.scheme
                port = parsed.port or (443 if scheme == "https" else 80)
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
                return scheme, host, port, path, str(addr)
            return real_resolve(url)

        self._target_guard = mock.patch.object(
            _wh, "_resolve_pinned_target", side_effect=resolve_allowing_loopback,
        )
        self._target_guard.start()
        self.addCleanup(self._target_guard.stop)
        _Catcher.received = []
        _Catcher.respond_with = 200
        self._configure_auth()
        code, body, self.cookie, self.csrf = self._login()
        self.assertEqual(code, 200)

    def _authed(self, method, path, data=None, headers=None):
        request_headers = {"X-CSRF-Token": self.csrf}
        request_headers.update(headers or {})
        return http(
            method, f"{self.base}{path}", data,
            headers=request_headers,
            cookies={"__Host-linkmoth_session": self.cookie},
        )

    def _create(self, **overrides):
        payload = {
            "name": "Catcher",
            "url": self.catcher_url,
            "preset": "generic",
            "events": ["fault_opened", "fault_closed", "false_alarm_marked"],
        }
        payload.update(overrides)
        code, body, _, _ = self._authed("POST", "/api/webhooks", payload)
        self.assertEqual(code, 201, body)
        return body["webhook"]

    def test_crud_masking_and_secret_round_trip(self):
        token = "Bearer super-secret-token-abcd"
        created = self._create(headers={"Authorization": token})
        self.assertEqual(created["url"], "••••••••")
        self.assertEqual(created["headers"]["Authorization"], "••••••••abcd")

        code, listing, _, _ = self._authed("GET", "/api/webhooks")
        self.assertEqual(code, 200)
        hook = listing["webhooks"][0]
        self.assertEqual(hook["headers"]["Authorization"], "••••••••abcd")
        self.assertEqual(hook["queued"], 0)
        self.assertTrue(listing["events"])
        self.assertTrue(listing["presets"])

        # Re-save with the masked value untouched: the stored secret must survive,
        # proven by the header the catcher receives on a test send.
        code, body, _, _ = self._authed(
            "PUT", f"/api/webhooks/{hook['id']}",
            {"name": "Renamed", "headers": {"Authorization": "••••••••abcd"}},
        )
        self.assertEqual(code, 200, body)
        code, out, _, _ = self._authed(
            "POST", f"/api/webhooks/{hook['id']}/test", {"kind": "fault"},
        )
        self.assertEqual(code, 200)
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["status"], 200)
        sent = _Catcher.received[-1]
        self.assertEqual(sent["headers"]["Authorization"], token)
        payload = json.loads(sent["body"])
        self.assertEqual(payload["event"], "fault_opened")
        self.assertEqual(payload["incident_id"], "INC-TEST-0000")

        code, body, _, _ = self._authed("DELETE", f"/api/webhooks/{hook['id']}")
        self.assertEqual(code, 200)
        code, listing, _, _ = self._authed("GET", "/api/webhooks")
        self.assertEqual(listing["webhooks"], [])

    def test_validation_errors_return_400(self):
        code, body, _, _ = self._authed("POST", "/api/webhooks", {
            "name": "bad", "url": "ftp://nope", "preset": "generic", "events": [],
        })
        self.assertEqual(code, 400)
        self.assertIn("url", body["error"])

    def test_test_send_failure_is_reported_not_500(self):
        hook = self._create(url="http://127.0.0.1:9/hook")  # closed port
        code, out, _, _ = self._authed(
            "POST", f"/api/webhooks/{hook['id']}/test", {"kind": "recovery"},
        )
        self.assertEqual(code, 200)
        self.assertFalse(out["ok"])
        self.assertTrue(out["error"])

    def test_queue_visibility_after_failed_delivery(self):
        import linkmoth_webhooks as wh
        hook = self._create(url="http://127.0.0.1:9/hook")
        ctx = wh.build_event_context("fault_opened", verdict={"title": "x"})
        self.assertEqual(wh.emit_event(self.linkmoth.db, "fault_opened", ctx), 1)
        wh.drain_queue_once(self.linkmoth.db)
        code, listing, _, _ = self._authed("GET", "/api/webhooks")
        row = listing["webhooks"][0]
        self.assertEqual(row["queued"], 1)
        self.assertIsNotNone(row["next_attempt"])
        self.assertTrue(row["last_error"])

    def test_false_alarm_route_closes_and_emits(self):
        self._create()
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO incidents(started, source, detail, ref)"
                " VALUES(?,?,?,?)",
                (time.time(), "test", "seeded", "INC-20260710-0001"),
            )
        code, body, _, _ = self._authed("POST", "/api/incident/false-alarm", {})
        self.assertEqual(code, 200, body)
        self.assertTrue(body["marked"])
        with self.linkmoth.db() as conn:
            inc = conn.execute("SELECT * FROM incidents").fetchone()
            events = [
                r["event"] for r in conn.execute(
                    "SELECT event FROM webhook_queue ORDER BY id"
                ).fetchall()
            ]
        self.assertEqual(inc["false_alarm"], 1)
        self.assertIsNotNone(inc["resolved"])
        self.assertEqual(inc["verdict_title"], "Marked as false alarm")
        self.assertEqual(events, ["false_alarm_marked", "fault_closed"])
        # No open incident left → second call conflicts.
        code, body, _, _ = self._authed("POST", "/api/incident/false-alarm", {})
        self.assertEqual(code, 409)

    def test_false_alarm_by_ref_flags_resolved_incident(self):
        resolved_at = time.time()
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO incidents(started, source, detail, ref, resolved,"
                " verdict_code, verdict_title) VALUES(?,?,?,?,?,?,?)",
                (time.time() - 100, "test", "seeded", "INC-20260710-0002",
                 resolved_at, "wan_down", "WAN down"),
            )
        code, body, _, _ = self._authed(
            "POST", "/api/incident/false-alarm", {"ref": "INC-20260710-0002"},
        )
        self.assertEqual(code, 200, body)
        with self.linkmoth.db() as conn:
            inc = conn.execute("SELECT * FROM incidents").fetchone()
        self.assertEqual(inc["false_alarm"], 1)
        # The verdict is rewritten so the incident stops counting as a
        # blamed fault in stats/patterns/filters…
        self.assertEqual(inc["verdict_code"], "all_clear")
        # …but the original resolution timestamp is untouched.
        self.assertAlmostEqual(inc["resolved"], resolved_at, delta=0.01)

    def test_inbound_info_returns_secret_and_curl(self):
        code, body, _, _ = self._authed("GET", "/api/webhooks/inbound-info")
        self.assertEqual(code, 200)
        self.assertEqual(body["secret"], self.webhook)
        self.assertIn("/api/webhooks/inbound", body["url"])
        self.assertIn(body["secret"], body["curl_example"])
        self.assertIn("curl", body["curl_example"])

    def test_inbound_info_rejects_shell_metacharacters_in_host(self):
        code, body, _, _ = self._authed(
            "GET",
            "/api/webhooks/inbound-info",
            headers={"Host": "linkmoth.local$(id)"},
        )
        self.assertEqual(code, 200)
        self.assertNotIn("$(", body["url"])
        self.assertNotIn("$(", body["curl_example"])
        self.assertIn("linkmoth.local", body["url"])

    def test_incident_loop_emits_lifecycle_events(self):
        from unittest import mock
        self._create(events=[
            "fault_opened", "fault_updated", "fault_recovered", "fault_closed",
        ])
        self.linkmoth.CFG["recheck_seconds"] = [0, 0, 0, 0, 0]
        engine = self.linkmoth.Engine()
        verdicts = [
            {"severity": "bad", "code": "wan_down", "title": "WAN down",
             "explain": "no route", "hint": ""},
            {"severity": "warn", "code": "link_degraded", "title": "Link degraded",
             "explain": "100 Mb/s", "hint": ""},
            {"severity": "ok", "code": "all_clear", "title": "All clear",
             "explain": "", "hint": ""},
            {"severity": "ok", "code": "all_clear", "title": "All clear",
             "explain": "", "hint": ""},
        ]
        with self.linkmoth.db() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail, ref) VALUES(?,?,?,?)",
                (time.time(), "test", "loop", "INC-20260710-0003"),
            )
            inc_id = cur.lastrowid
        with mock.patch.object(engine, "diagnose_once", side_effect=verdicts):
            with mock.patch.object(engine, "_discord_notify"):
                engine._loop(inc_id)
        with self.linkmoth.db() as conn:
            rows = conn.execute(
                "SELECT event, context FROM webhook_queue ORDER BY id"
            ).fetchall()
            inc = conn.execute(
                "SELECT * FROM incidents WHERE id=?", (inc_id,)
            ).fetchone()
        events = [r["event"] for r in rows]
        self.assertEqual(events, [
            "fault_opened", "fault_updated", "fault_recovered", "fault_closed",
        ])
        self.assertIsNotNone(inc["resolved"])
        opened_ctx = json.loads(rows[0]["context"])
        self.assertEqual(opened_ctx["verdict"], "wan_down")
        self.assertEqual(opened_ctx["incident_id"], "INC-20260710-0003")
        updated_ctx = json.loads(rows[1]["context"])
        self.assertEqual(updated_ctx["verdict"], "link_degraded")
        self.assertEqual(inc["verdict_code"], "wan_down")

    def test_loop_stops_when_incident_closed_externally(self):
        from unittest import mock
        self._create(events=["fault_opened", "fault_closed", "false_alarm_marked"])
        self.linkmoth.CFG["recheck_seconds"] = [0, 0, 0, 0, 0]
        engine = self.linkmoth.Engine()
        bad = {"severity": "bad", "code": "wan_down", "title": "WAN down",
               "explain": "", "hint": ""}
        with self.linkmoth.db() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail, ref) VALUES(?,?,?,?)",
                (time.time(), "test", "loop", "INC-20260710-0004"),
            )
            inc_id = cur.lastrowid

        calls = {"n": 0}

        def fake_diagnose(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return dict(bad)
            # Simulate the user marking a false alarm mid-loop.
            engine.mark_false_alarm()
            return dict(bad)

        with mock.patch.object(engine, "diagnose_once", side_effect=fake_diagnose):
            with mock.patch.object(engine, "_discord_notify"):
                engine._loop(inc_id)
        with self.linkmoth.db() as conn:
            inc = conn.execute(
                "SELECT * FROM incidents WHERE id=?", (inc_id,)
            ).fetchone()
            events = [r["event"] for r in conn.execute(
                "SELECT event FROM webhook_queue ORDER BY id"
            ).fetchall()]
        # The loop must not clobber the false-alarm resolution.
        self.assertEqual(inc["false_alarm"], 1)
        self.assertEqual(inc["verdict_title"], "Marked as false alarm")
        self.assertEqual(events, [
            "fault_opened", "false_alarm_marked", "fault_closed",
        ])

    def test_webhook_routes_require_auth(self):
        code, _, _, _ = http("GET", f"{self.base}/api/webhooks")
        self.assertEqual(code, 401)
        code, _, _, _ = http("POST", f"{self.base}/api/webhooks", {"name": "x"})
        self.assertEqual(code, 401)
        # Session but no CSRF → 403.
        code, _, _, _ = http(
            "POST", f"{self.base}/api/webhooks", {"name": "x"},
            cookies={"__Host-linkmoth_session": self.cookie},
        )
        self.assertEqual(code, 403)


class MetricsRouteTests(LinkmothTestBase):
    def setUp(self):
        super().setUp()
        self._configure_auth()

    def test_metrics_requires_webhook_bearer(self):
        code, _, _, _ = http("GET", f"{self.base}/metrics")
        self.assertEqual(code, 401)
        code, _, _, _ = http(
            "GET", f"{self.base}/metrics",
            headers={"Authorization": "Bearer wrong-secret"},
        )
        self.assertEqual(code, 401)

    def test_metrics_exposes_read_only_gauges(self):
        code, body, _, headers = http(
            "GET", f"{self.base}/metrics",
            headers={"Authorization": f"Bearer {self.webhook}"},
        )
        self.assertEqual(code, 200)
        text = body.decode("utf-8") if isinstance(body, bytes) else str(body)
        self.assertIn("text/plain", headers.get("Content-Type", ""))
        self.assertIn("linkmoth_info{version=", text)
        self.assertIn("linkmoth_incident_open 0", text)
        self.assertIn("linkmoth_incidents_30d", text)
        # No secrets in the exposition.
        self.assertNotIn(self.webhook, text)

    def test_metrics_reflects_open_incident_and_rungs(self):
        with self.linkmoth.db() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail) VALUES(?,?,?)",
                (time.time() - 120, "test", "metrics"),
            )
            inc_id = cur.lastrowid
            checks = json.dumps([
                {"id": "gateway", "label": "Router", "ok": True,
                 "detail": "ok", "ms": 1.0, "micro": []},
                {"id": "raw_ping", "label": "Internet ping", "ok": False,
                 "detail": "timeout", "ms": None, "micro": []},
            ])
            conn.execute(
                "INSERT INTO runs(incident_id, ts, severity, code, title,"
                " checks) VALUES(?,?,?,?,?,?)",
                (inc_id, time.time(), "bad", "wan_down", "WAN down", checks),
            )
        code, body, _, _ = http(
            "GET", f"{self.base}/metrics",
            headers={"Authorization": f"Bearer {self.webhook}"},
        )
        self.assertEqual(code, 200)
        text = body.decode("utf-8") if isinstance(body, bytes) else str(body)
        self.assertIn("linkmoth_incident_open 1", text)
        self.assertIn("linkmoth_incident_open_duration_seconds", text)
        self.assertIn('linkmoth_rung_ok{rung="gateway"} 1', text)
        self.assertIn('linkmoth_rung_ok{rung="raw_ping"} 0', text)
        self.assertIn('linkmoth_last_verdict_severity{code="wan_down"} 2', text)


if __name__ == "__main__":
    unittest.main()

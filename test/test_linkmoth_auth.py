#!/usr/bin/env python3
"""Automated tests for Linkmoth mandatory local authentication."""
import importlib
import json
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import MagicMock, patch

BASE = Path(__file__).resolve().parent
REPO_ROOT = BASE.parent
sys.path.insert(0, str(REPO_ROOT))


def sqlite_connector(path):
    @contextmanager
    def connect():
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    return connect


def http(method, url, data=None, headers=None, cookies=None):
    hdrs = dict(headers or {})
    if cookies:
        hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    body = None
    if data is not None:
        body = json.dumps(data).encode() if not isinstance(data, bytes) else data
        hdrs.setdefault("Content-Type", "application/json")
    req = Request(url, data=body, headers=hdrs, method=method)
    try:
        with urlopen(req, timeout=5) as resp:
            raw = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            parsed = json.loads(raw) if "json" in ctype else raw
            set_cookie = resp.headers.get("Set-Cookie")
            cookie_val = None
            if set_cookie and "__Host-linkmoth_session=" in set_cookie:
                part = set_cookie.split("__Host-linkmoth_session=", 1)[1]
                cookie_val = part.split(";", 1)[0]
            return resp.status, parsed, cookie_val, dict(resp.headers)
    except HTTPError as e:
        try:
            raw = e.read()
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = raw
            set_cookie = e.headers.get("Set-Cookie")
            cookie_val = None
            if set_cookie and "__Host-linkmoth_session=" in set_cookie:
                part = set_cookie.split("__Host-linkmoth_session=", 1)[1]
                cookie_val = part.split(";", 1)[0]
            return e.code, parsed, cookie_val, dict(e.headers)
        finally:
            e.close()


class LinkmothTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="linkmoth_test_")
        self.state = Path(self.tmp) / "state"
        self.state.mkdir()
        self.config_path = Path(self.tmp) / "config.json"
        self.config = {
            "bind": "127.0.0.1",
            "port": 0,
            "recheck_seconds": [0],
            "recheck_repeat": 9999,
            "baseline_minutes": 0,
            "auth": {},
        }
        self.config_path.write_text(json.dumps(self.config))
        os.environ["LINKMOTH_CONFIG"] = str(self.config_path)
        os.environ["LINKMOTH_STATE_DIR"] = str(self.state)

        for mod in ("linkmoth", 'linkmoth_core', 'linkmoth_probes', 'linkmoth_engine', 'linkmoth_handler', "linkmoth_auth"):
            if mod in sys.modules:
                del sys.modules[mod]
        import linkmoth
        self.linkmoth = importlib.reload(linkmoth)
        global linkmoth_core
        linkmoth_core = importlib.import_module("linkmoth_core")
        global linkmoth_handler
        linkmoth_handler = importlib.import_module("linkmoth_handler")
        global linkmoth_probes
        linkmoth_probes = importlib.import_module("linkmoth_probes")
        global linkmoth_engine
        linkmoth_engine = importlib.import_module("linkmoth_engine")
        self.linkmoth.init_db()
        self.auth = self.linkmoth.get_auth()

        # Route tests exercise trigger authorization and incident creation,
        # not the long-running recheck scheduler. Keep any spawned loop alive
        # until tearDown, then release and join it before deleting this test's
        # temporary database so it cannot leak into the next module reload.
        self.incident_loop_release = threading.Event()

        def held_incident_loop(_inc_id):
            self.incident_loop_release.wait(timeout=30)

        self.incident_loop_patch = patch.object(
            self.linkmoth.ENGINE, "_loop", new=held_incident_loop,
        )
        self.incident_loop_patch.start()

        self.port = self._free_port()
        self.config["port"] = self.port
        self.config_path.write_text(json.dumps(self.config))
        self.linkmoth.CFG["port"] = self.port
        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), self.linkmoth.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"
        time.sleep(0.05)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.incident_loop_release.set()
        loop_thread = self.linkmoth.ENGINE.loop_thread
        if loop_thread is not None:
            loop_thread.join(timeout=2)
        self.incident_loop_patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)
        os.environ.pop("LINKMOTH_CONFIG", None)
        os.environ.pop("LINKMOTH_STATE_DIR", None)

    def _free_port(self):
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def _configure_auth(self, totp=False, session_ttl=86400):
        self.config["auth"] = {
            "totp_enabled": totp,
            "session_ttl_seconds": session_ttl,
            "login_max_attempts": 3,
            "login_lockout_seconds": 60,
        }
        self.config_path.write_text(json.dumps(self.config))
        self.linkmoth.CFG["auth"] = dict(self.config["auth"])
        self.auth = self.linkmoth.get_auth()
        self.auth.set_password("secret-passphrase")
        self.webhook = self.auth.ensure_webhook_secret()

    def _login(self, password="secret-passphrase", totp_code=None):
        code, body, cookie, _ = http("POST", f"{self.base}/api/auth/login",
                                     {"password": password})
        csrf = body.get("csrf_token")
        if body.get("needs_totp") and totp_code:
            code, body, cookie2, _ = http(
                "POST", f"{self.base}/api/auth/totp", {"code": totp_code},
                headers={"X-CSRF-Token": csrf},
                cookies={"__Host-linkmoth_session": cookie},
            )
            csrf = body.get("csrf_token", csrf)
            cookie = cookie2 or cookie
        return code, body, cookie, csrf


class OnboardingTests(LinkmothTestBase):
    def test_health_open(self):
        code, body, _, _ = http("GET", f"{self.base}/health")
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])

    def test_data_api_requires_auth_before_onboarding(self):
        code, _, _, _ = http("GET", f"{self.base}/api/status")
        self.assertEqual(code, 401)

    def test_trigger_always_requires_bearer(self):
        code, _, _, _ = http(
            "POST",
            f"{self.base}/trigger",
            {"heartbeat": {"status": 0}},
        )
        self.assertEqual(code, 401)

    def test_diagnose_requires_auth_before_onboarding(self):
        code, _, _, _ = http("POST", f"{self.base}/api/diagnose")
        self.assertEqual(code, 401)

    def test_auth_status_requires_onboarding(self):
        code, body, _, _ = http("GET", f"{self.base}/api/auth/status")
        self.assertEqual(code, 200)
        self.assertTrue(body["enabled"])
        self.assertTrue(body["onboarding_required"])
        self.assertFalse(body["authenticated"])
        self.assertNotIn("token", json.dumps(body).lower())

    def test_dashboard_serves_onboarding_gate(self):
        code, page, _, _ = http("GET", f"{self.base}/")
        self.assertEqual(code, 200)
        self.assertIn(b'id="auth-onboarding-step"', page)
        self.assertIn(b'id="auth-setup-token"', page)
        self.assertIn(b'id="auth-new-password"', page)
        self.assertIn(b'id="sec-totp-qr"', page)
        self.assertIn(b'id="sec-totp-activated"', page)
        self.assertIn(b"Your recovery codes appear after you activate.", page)

    def test_invalid_onboarding_token_is_rejected(self):
        self.auth.ensure_onboarding_token()
        code, body, _, _ = http(
            "POST",
            f"{self.base}/api/auth/setup",
            {
                "token": "wrong-token",
                "password": "a-secure-passphrase",
                "confirm": "a-secure-passphrase",
            },
        )
        self.assertEqual(code, 401)
        self.assertEqual(body["error"], "invalid or expired setup token")

    def test_onboarding_creates_admin_and_session(self):
        token = self.auth.ensure_onboarding_token()
        code, body, cookie, _ = http(
            "POST",
            f"{self.base}/api/auth/setup",
            {
                "token": token,
                "password": "a-secure-passphrase",
                "confirm": "a-secure-passphrase",
            },
        )
        self.assertEqual(code, 201)
        self.assertTrue(body["authenticated"])
        self.assertFalse(body["onboarding_required"])
        self.assertTrue(cookie)
        raw_store = self.auth.auth_path.read_text()
        self.assertNotIn(token, raw_store)
        self.assertNotIn("onboarding_token", raw_store)
        self.assertNotIn(token, json.dumps(self.auth.audit_events()))
        code, _, _, _ = http(
            "GET",
            f"{self.base}/api/status",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)

    def test_onboarding_is_one_time(self):
        token = self.auth.ensure_onboarding_token()
        payload = {
            "token": token,
            "password": "a-secure-passphrase",
            "confirm": "a-secure-passphrase",
        }
        code, _, _, _ = http("POST", f"{self.base}/api/auth/setup", payload)
        self.assertEqual(code, 201)
        code, body, _, _ = http("POST", f"{self.base}/api/auth/setup", payload)
        self.assertEqual(code, 409)
        self.assertEqual(body["error"], "onboarding is already complete")

    def test_expired_onboarding_token_is_rejected(self):
        token = self.auth.ensure_onboarding_token()
        store = self.auth.load_store()
        store["onboarding_expires"] = time.time() - 1
        self.auth.save_store(store)
        code, _, _, _ = http(
            "POST",
            f"{self.base}/api/auth/setup",
            {
                "token": token,
                "password": "a-secure-passphrase",
                "confirm": "a-secure-passphrase",
            },
        )
        self.assertEqual(code, 401)

    def test_onboarding_password_confirmation_is_required(self):
        token = self.auth.ensure_onboarding_token()
        code, body, _, _ = http(
            "POST",
            f"{self.base}/api/auth/setup",
            {
                "token": token,
                "password": "a-secure-passphrase",
                "confirm": "a-different-passphrase",
            },
        )
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], "passwords do not match")

    def test_onboarding_attempts_are_rate_limited(self):
        self.auth.ensure_onboarding_token()
        payload = {
            "token": "wrong-token",
            "password": "a-secure-passphrase",
            "confirm": "a-secure-passphrase",
        }
        for _ in range(5):
            code, _, _, _ = http(
                "POST",
                f"{self.base}/api/auth/setup",
                payload,
            )
            self.assertEqual(code, 401)
        code, body, _, _ = http(
            "POST",
            f"{self.base}/api/auth/setup",
            payload,
        )
        self.assertEqual(code, 429)
        self.assertIn("retry_after", body)

    def test_cross_site_onboarding_is_rejected_without_consuming_token(self):
        token = self.auth.ensure_onboarding_token()
        payload = {
            "token": token,
            "password": "a-secure-passphrase",
            "confirm": "a-secure-passphrase",
        }
        code, _, _, _ = http(
            "POST",
            f"{self.base}/api/auth/setup",
            payload,
            headers={
                "Origin": "https://attacker.invalid",
                "Sec-Fetch-Site": "cross-site",
            },
        )
        self.assertEqual(code, 403)
        code, body, cookie, _ = http(
            "POST", f"{self.base}/api/auth/setup", payload,
        )
        self.assertEqual(code, 201)
        self.assertTrue(body["authenticated"])
        self.assertTrue(cookie)

    def test_expired_token_is_replaced_locally(self):
        old = self.auth.ensure_onboarding_token()
        store = self.auth.load_store()
        store["onboarding_expires"] = time.time() - 1
        self.auth.save_store(store)
        new = self.auth.ensure_onboarding_token()
        self.assertNotEqual(old, new)


class PublicExposureGuardRouteTests(LinkmothTestBase):
    """Integration coverage for Handler._reject_if_publicly_exposed: the test
    client always connects over loopback, so the peer classification itself
    is mocked to simulate a request arriving from a public IP address."""

    def test_get_is_rejected_when_peer_looks_public(self):
        with patch.object(linkmoth_handler, "_peer_is_trusted_local", return_value=False):
            code, body, _, _ = http("GET", f"{self.base}/health")
        self.assertEqual(code, 403)
        self.assertIn("LAN-only", body["error"])

    def test_post_is_rejected_before_touching_auth_state(self):
        with patch.object(linkmoth_handler, "_peer_is_trusted_local", return_value=False):
            code, body, _, _ = http(
                "POST", f"{self.base}/api/auth/login", {"password": "wrong"},
            )
        self.assertEqual(code, 403)
        self.assertIn("LAN-only", body["error"])

    def test_normal_lan_request_is_unaffected(self):
        code, body, _, _ = http("GET", f"{self.base}/health")
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])

    def test_rejection_is_audited_and_surfaced_in_security_posture(self):
        self._configure_auth()
        with patch.object(linkmoth_handler, "_peer_is_trusted_local", return_value=False):
            code, _, _, _ = http("GET", f"{self.base}/health")
        self.assertEqual(code, 403)
        events = self.auth.audit_events(limit=10)
        self.assertTrue(any(e["event"] == "public_exposure_blocked" for e in events))

        _, _, cookie, csrf = self._login()
        code, posture, _, _ = http(
            "GET", f"{self.base}/api/auth/security",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertEqual(posture["public_exposure_recent"]["count"], 1)
        self.assertIsNotNone(posture["public_exposure_recent"]["last_ts"])

    def test_peer_classified_as_trusted_is_not_rejected(self):
        # The trusted_proxy_cidrs allowlist behavior itself is covered at the
        # unit level in test_linkmoth_bind_exposure.py; this just confirms the
        # do_GET wiring actually respects a "trusted" verdict from the guard.
        with patch.object(linkmoth_handler, "_peer_is_trusted_local", return_value=True):
            code, body, _, _ = http("GET", f"{self.base}/health")
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])


class AuthenticatedTests(LinkmothTestBase):
    def setUp(self):
        super().setUp()
        self._configure_auth()

    def test_api_requires_login(self):
        code, _, _, _ = http("GET", f"{self.base}/api/status")
        self.assertEqual(code, 401)

    def test_health_still_open(self):
        code, body, _, _ = http("GET", f"{self.base}/health")
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])

    def test_login_and_access(self):
        code, body, cookie, csrf = self._login()
        self.assertEqual(code, 200)
        self.assertTrue(body["authenticated"])
        code, status, _, _ = http(
            "GET", f"{self.base}/api/status",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertTrue(status["auth"]["authenticated"])

    def test_fire_drill_state_persists_across_browser_sessions(self):
        _, _, cookie, csrf = self._login()
        code, status, _, _ = http(
            "GET", f"{self.base}/api/status",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertEqual(status["fire_drill"], {"seen": False, "completed": False})

        code, _, _, _ = http(
            "POST", f"{self.base}/api/fire-drill", {"state": "seen"},
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 403)
        code, state, _, _ = http(
            "POST", f"{self.base}/api/fire-drill", {"state": "seen"},
            headers={"X-CSRF-Token": csrf},
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertEqual(state, {"seen": True, "completed": False})

        _, _, second_cookie, second_csrf = self._login()
        code, status, _, _ = http(
            "GET", f"{self.base}/api/status",
            cookies={"__Host-linkmoth_session": second_cookie},
        )
        self.assertEqual(code, 200)
        self.assertTrue(status["fire_drill"]["seen"])
        code, state, _, _ = http(
            "POST", f"{self.base}/api/fire-drill", {"state": "completed"},
            headers={"X-CSRF-Token": second_csrf},
            cookies={"__Host-linkmoth_session": second_cookie},
        )
        self.assertEqual(code, 200)
        self.assertEqual(state, {"seen": True, "completed": True})

    def test_fire_drill_state_migrates_from_prior_manual_run(self):
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO runs(incident_id, ts, severity, code, title,"
                " explain, hint, checks, duration_ms, kind)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (None, time.time(), "ok", "all_clear", "All clear", "", "",
                 "[]", 1, "manual"),
            )
        _, _, cookie, _ = self._login()
        code, status, _, _ = http(
            "GET", f"{self.base}/api/status",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertEqual(status["fire_drill"], {"seen": True, "completed": False})
        self.assertEqual(self.linkmoth._get_meta("fire_drill_seen"), "1")

    def test_bad_password_rate_limit(self):
        for _ in range(3):
            code, _, _, _ = http("POST", f"{self.base}/api/auth/login", {"password": "wrong"})
            self.assertEqual(code, 401)
        code, body, _, _ = http("POST", f"{self.base}/api/auth/login", {"password": "wrong"})
        self.assertEqual(code, 429)
        self.assertIn("retry_after", body)

    def test_saturated_password_hash_slots_fail_fast(self):
        acquired = [self.linkmoth.AUTH_VERIFY_SLOTS.acquire(blocking=False) for _ in range(2)]
        self.assertEqual(acquired, [True, True])
        started = time.monotonic()
        try:
            code, body, _, headers = http(
                "POST", f"{self.base}/api/auth/login",
                {"password": "secret-passphrase"},
            )
        finally:
            for held in acquired:
                if held:
                    self.linkmoth.AUTH_VERIFY_SLOTS.release()
        self.assertEqual(code, 503)
        self.assertEqual(body["error"], "authentication service busy")
        self.assertEqual(headers.get("Retry-After"), "1")
        self.assertLess(time.monotonic() - started, 1.0)

    def test_cross_site_and_form_logins_cannot_force_lockout(self):
        for _ in range(3):
            code, _, _, _ = http(
                "POST",
                f"{self.base}/api/auth/login",
                b"password=wrong",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://attacker.invalid",
                },
            )
            self.assertEqual(code, 415)
        for _ in range(3):
            code, _, _, _ = http(
                "POST",
                f"{self.base}/api/auth/login",
                {"password": "wrong"},
                headers={
                    "Origin": "https://attacker.invalid",
                    "Sec-Fetch-Site": "cross-site",
                },
            )
            self.assertEqual(code, 403)
        code, body, _, _ = http(
            "POST",
            f"{self.base}/api/auth/login",
            {"password": "secret-passphrase"},
        )
        self.assertEqual(code, 200)
        self.assertTrue(body["authenticated"])

    def test_same_origin_login_is_accepted(self):
        code, body, _, _ = http(
            "POST",
            f"{self.base}/api/auth/login",
            {"password": "secret-passphrase"},
            headers={
                "Origin": self.base,
                "Sec-Fetch-Site": "same-origin",
            },
        )
        self.assertEqual(code, 200)
        self.assertTrue(body["authenticated"])

    def test_forwarded_for_cannot_bypass_rate_limit(self):
        for i in range(3):
            code, _, _, _ = http(
                "POST",
                f"{self.base}/api/auth/login",
                {"password": "wrong"},
                headers={"X-Forwarded-For": f"192.0.2.{i + 1}"},
            )
            self.assertEqual(code, 401)
        code, _, _, _ = http(
            "POST",
            f"{self.base}/api/auth/login",
            {"password": "wrong"},
            headers={"X-Forwarded-For": "192.0.2.99"},
        )
        self.assertEqual(code, 429)

    def test_distributed_login_failures_only_throttle_their_sources(self):
        attackers = [{"Remote-Addr": f"192.168.1.{i}"} for i in range(1, 21)]
        for attacker in attackers:
            for _ in range(3):
                self.auth.record_login_failure(attacker)
            allowed, retry_after = self.auth.login_allowed(attacker)
            self.assertFalse(allowed)
            self.assertGreater(retry_after, 0)

        clean_source = {"Remote-Addr": "192.168.1.200"}
        self.assertEqual(self.auth.login_allowed(clean_source), (True, 0))
        self.assertTrue(self.auth.verify_login_password("secret-passphrase"))

    def test_csrf_required_on_diagnose(self):
        _, _, cookie, _ = self._login()
        code, _, _, _ = http(
            "POST", f"{self.base}/api/diagnose",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 403)
        _, _, cookie, csrf = self._login()
        code, body, _, _ = http(
            "POST", f"{self.base}/api/diagnose",
            headers={"X-CSRF-Token": csrf},
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertTrue(body.get("started"))

    def test_manual_update_check_requires_admin_session_and_csrf(self):
        code, _, _, _ = http("POST", f"{self.base}/api/update/check", {})
        self.assertEqual(code, 401)
        _, _, cookie, _ = self._login()
        code, _, _, _ = http(
            "POST", f"{self.base}/api/update/check", {},
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 403)
        _, _, cookie, csrf = self._login()
        result = {
            "installed_version": "0.2.0", "latest_version": "0.2.1",
            "update_available": True, "published_at": "2026-07-13T00:00:00Z",
            "release_url": "https://github.com/benukas/Linkmoth/releases/tag/v0.2.1",
            "update_command": "VERSION=v0.2.1",
            "verified_update_command": "VERSION=v0.2.1",
        }
        with patch.object(linkmoth_handler, "manual_update_check", return_value=result):
            code, body, _, _ = http(
                "POST", f"{self.base}/api/update/check", {},
                headers={"X-CSRF-Token": csrf},
                cookies={"__Host-linkmoth_session": cookie},
            )
        self.assertEqual(code, 200)
        self.assertEqual(body["latest_version"], "0.2.1")

    def test_evidence_exports_require_auth_but_not_csrf(self):
        code, _, _, _ = http("GET", f"{self.base}/api/evidence-export?tier=detailed")
        self.assertEqual(code, 401)
        _, _, cookie, _ = self._login()
        code, body, _, _ = http(
            "GET", f"{self.base}/api/evidence-export?tier=support-safe",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertEqual(body["tier"], "support-safe")
        self.assertNotIn("discord_webhook_url", body["configuration"])

    def test_backup_download_requires_auth_and_is_a_zip_with_no_secrets(self):
        code, _, _, _ = http("GET", f"{self.base}/api/backup")
        self.assertEqual(code, 401)
        _, _, cookie, _ = self._login()
        code, body, _, headers = http(
            "GET", f"{self.base}/api/backup",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertIn("attachment", headers.get("Content-Disposition", ""))
        secret = self.auth.ensure_webhook_secret()
        self.assertNotIn(secret.encode(), body)

    def test_csrf_rejected_without_token(self):
        _, _, cookie, _ = self._login()
        code, _, _, _ = http(
            "POST", f"{self.base}/api/settings",
            {"ui_refresh_seconds": 10},
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 403)

    def test_csrf_required_on_settings(self):
        _, _, cookie, csrf = self._login()
        code, body, _, _ = http(
            "POST", f"{self.base}/api/settings",
            {"ui_refresh_seconds": 10},
            headers={"X-CSRF-Token": csrf},
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertTrue(body.get("saved"))

    def test_quiet_hours_settings_validate_and_apply(self):
        _, _, cookie, csrf = self._login()
        auth = {"X-CSRF-Token": csrf}
        code, body, _, _ = http(
            "POST", f"{self.base}/api/settings",
            {
                "quiet_hours_enabled": True,
                "quiet_hours_start": "22:30",
                "quiet_hours_end": "06:45",
            },
            headers=auth,
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertTrue(body["settings"]["quiet_hours_enabled"])
        self.assertEqual(body["settings"]["quiet_hours_start"], "22:30")
        code, body, _, _ = http(
            "POST", f"{self.base}/api/settings",
            {"quiet_hours_start": "22:00", "quiet_hours_end": "22:00"},
            headers=auth,
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 400)
        self.assertIn("quiet_hours_end", body["errors"])

    def test_device_api_requires_auth_and_csrf(self):
        payload = {
            "name": "Printer",
            "address": "192.168.1.40",
            "preset": "printer",
            "enabled": True,
            "interval_seconds": 0,
            "alerts": {"discord": False, "push": False, "webhook": False},
            "settings": {},
        }
        code, _, _, _ = http("GET", f"{self.base}/api/devices")
        self.assertEqual(code, 401)
        _, _, cookie, _ = self._login()
        code, _, _, _ = http(
            "POST", f"{self.base}/api/devices", payload,
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 403)
        _, _, cookie, csrf = self._login()
        code, body, _, _ = http(
            "POST", f"{self.base}/api/devices", payload,
            headers={"X-CSRF-Token": csrf},
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 201)
        device_id = body["device"]["id"]
        code, listed, _, _ = http(
            "GET", f"{self.base}/api/devices",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertEqual(listed["devices"][0]["id"], device_id)

    def test_device_api_rejects_public_target_and_supports_crud(self):
        _, _, cookie, csrf = self._login()
        headers = {"X-CSRF-Token": csrf}
        payload = {
            "name": "Bad target",
            "address": "8.8.8.8",
            "preset": "generic",
            "enabled": True,
            "interval_seconds": 0,
            "alerts": {"discord": False, "push": False, "webhook": False},
            "settings": {},
        }
        code, _, _, _ = http(
            "POST", f"{self.base}/api/devices", payload,
            headers=headers, cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 400)
        payload["address"] = "10.0.0.20"
        code, body, _, _ = http(
            "POST", f"{self.base}/api/devices", payload,
            headers=headers, cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 201)
        device_id = body["device"]["id"]
        code, body, _, _ = http(
            "PUT", f"{self.base}/api/devices/{device_id}",
            {"name": "Renamed target"},
            headers=headers, cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertEqual(body["device"]["name"], "Renamed target")
        code, body, _, _ = http(
            "DELETE", f"{self.base}/api/devices/{device_id}",
            headers=headers, cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertTrue(body["deleted"])

    def test_manual_device_run_does_not_advance_monitor_state(self):
        _, _, cookie, csrf = self._login()
        headers = {"X-CSRF-Token": csrf}
        payload = {
            "name": "TV",
            "address": "192.168.1.60",
            "preset": "generic",
            "enabled": True,
            "interval_seconds": 300,
            "alerts": {"discord": False, "push": False, "webhook": False},
            "settings": {},
        }
        code, body, _, _ = http(
            "POST", f"{self.base}/api/devices", payload,
            headers=headers, cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 201)
        device_id = body["device"]["id"]
        with patch.object(
            self.linkmoth.DEVICES,
            "ping_func",
            return_value=(False, "no reply", None),
        ):
            code, body, _, _ = http(
                "POST", f"{self.base}/api/devices/{device_id}/run", {},
                headers=headers, cookies={"__Host-linkmoth_session": cookie},
            )
        self.assertEqual(code, 200)
        self.assertEqual(body["result"]["state"], "down")
        self.assertEqual(body["device"]["stable_state"], "unknown")
        self.assertEqual(body["device"]["failure_streak"], 0)

    def test_logout_invalidates_session(self):
        _, _, cookie, csrf = self._login()
        code, _, _, _ = http(
            "POST", f"{self.base}/api/auth/logout", {},
            headers={"X-CSRF-Token": csrf},
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        code, _, _, _ = http(
            "GET", f"{self.base}/api/status",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 401)

    def test_session_expiry(self):
        self._configure_auth(session_ttl=1)
        _, _, cookie, csrf = self._login()
        time.sleep(1.2)
        code, _, _, _ = http(
            "GET", f"{self.base}/api/status",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 401)

    def test_webhook_bearer_required(self):
        code, _, _, _ = http("POST", f"{self.base}/trigger", {"heartbeat": {"status": 0}})
        self.assertEqual(code, 401)
        code, body, _, _ = http(
            "POST", f"{self.base}/trigger",
            {"heartbeat": {"status": 0}},
            headers={"Authorization": f"Bearer {self.webhook}"},
        )
        self.assertEqual(code, 200)
        self.assertTrue(body.get("triggered"))

    def test_webhook_get_requires_bearer(self):
        code, _, _, _ = http("GET", f"{self.base}/trigger")
        self.assertEqual(code, 401)
        code, body, _, _ = http(
            "GET", f"{self.base}/trigger",
            headers={"Authorization": f"Bearer {self.webhook}"},
        )
        self.assertEqual(code, 200)

    def test_webhook_rotation_invalidates_old_secret(self):
        old = self.webhook
        new = self.auth.rotate_webhook_secret()
        self.assertNotEqual(old, new)
        code, _, _, _ = http(
            "POST",
            f"{self.base}/trigger",
            {"heartbeat": {"status": 0}},
            headers={"Authorization": f"Bearer {old}"},
        )
        self.assertEqual(code, 401)
        code, _, _, _ = http(
            "POST",
            f"{self.base}/trigger",
            {"heartbeat": {"status": 0}},
            headers={"Authorization": f"Bearer {new}"},
        )
        self.assertEqual(code, 200)

    def test_password_change_invalidates_existing_sessions(self):
        _, _, cookie, _ = self._login()
        self.auth.set_password("a-new-secure-passphrase")
        code, _, _, _ = http(
            "GET",
            f"{self.base}/api/status",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 401)

    def test_session_id_is_hashed_in_database(self):
        _, _, cookie, _ = self._login()
        with self.linkmoth.db() as conn:
            stored = conn.execute("SELECT id FROM auth_sessions").fetchone()["id"]
        self.assertNotEqual(stored, cookie)
        self.assertEqual(len(stored), 64)

    def test_session_cookie_is_always_secure(self):
        code, _, _, headers = http(
            "POST",
            f"{self.base}/api/auth/login",
            {"password": "secret-passphrase"},
        )
        self.assertEqual(code, 200)
        self.assertIn("Secure", headers["Set-Cookie"])

    def test_hsts_is_sent(self):
        code, _, _, headers = http("GET", f"{self.base}/health")
        self.assertEqual(code, 200)
        self.assertIn("max-age=31536000", headers["Strict-Transport-Security"])

    def test_server_banner_hides_runtime_details(self):
        code, _, _, headers = http("GET", f"{self.base}/health")
        self.assertEqual(code, 200)
        self.assertEqual(headers["Server"], "Linkmoth")
        self.assertNotIn("Python", headers["Server"])
        self.assertNotIn("BaseHTTP", headers["Server"])

    def test_tls_context_requires_certificate_files(self):
        self.linkmoth.CFG["tls_cert"] = str(self.state / "missing.crt")
        self.linkmoth.CFG["tls_key"] = str(self.state / "missing.key")
        with self.assertRaises(RuntimeError):
            self.linkmoth.build_tls_context()

    def test_tls_context_enforces_tls_1_2_minimum(self):
        cert = self.state / "server.crt"
        key = self.state / "server.key"
        cert.touch()
        key.touch()
        self.linkmoth.CFG["tls_cert"] = str(cert)
        self.linkmoth.CFG["tls_key"] = str(key)
        fake_context = MagicMock()
        with patch.object(
            self.linkmoth.ssl,
            "SSLContext",
            return_value=fake_context,
        ):
            context = self.linkmoth.build_tls_context()
        self.assertIs(context, fake_context)
        self.assertEqual(
            fake_context.minimum_version,
            self.linkmoth.ssl.TLSVersion.TLSv1_2,
        )
        fake_context.load_cert_chain.assert_called_once_with(
            certfile=cert,
            keyfile=key,
        )

    def test_request_body_size_is_bounded(self):
        code, body, _, _ = http(
            "POST",
            f"{self.base}/api/auth/login",
            b"x" * (64 * 1024 + 1),
            headers={"Content-Type": "application/octet-stream"},
        )
        self.assertEqual(code, 413)
        self.assertEqual(body["error"], "request body too large")

    def test_non_object_json_does_not_crash_auth_or_webhook(self):
        code, body, _, _ = http(
            "POST",
            f"{self.base}/api/auth/login",
            [],
        )
        self.assertEqual(code, 401)
        self.assertEqual(body["error"], "invalid credentials")
        code, body, _, _ = http(
            "POST",
            f"{self.base}/trigger",
            [],
            headers={"Authorization": f"Bearer {self.webhook}"},
        )
        self.assertEqual(code, 200)
        self.assertTrue(body["triggered"])


class TotpAuthTests(LinkmothTestBase):
    def setUp(self):
        super().setUp()
        self._configure_auth(totp=True)
        secret, self.recovery = self.auth.setup_totp()
        from linkmoth_auth import _totp_at
        self.valid_code = _totp_at(secret, int(time.time()) // 30)

    def test_totp_required_after_password(self):
        code, body, cookie, csrf = self._login()
        self.assertEqual(code, 200)
        self.assertTrue(body["needs_totp"])
        self.assertFalse(body["authenticated"])
        code, _, _, _ = http(
            "GET", f"{self.base}/api/status",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 401)
        code, body, cookie, csrf = self._login(totp_code=self.valid_code)
        self.assertTrue(body["authenticated"])
        code, status, _, _ = http(
            "GET", f"{self.base}/api/status",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)

    def test_recovery_code_works_once(self):
        code, body, cookie, csrf = self._login()
        recovery = self.recovery[0]
        code, body, _, _ = http(
            "POST", f"{self.base}/api/auth/totp", {"code": recovery},
            headers={"X-CSRF-Token": csrf},
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertTrue(body["authenticated"])
        _, _, cookie2, csrf2 = self._login()
        code, _, _, _ = http(
            "POST", f"{self.base}/api/auth/totp", {"code": recovery},
            headers={"X-CSRF-Token": csrf2},
            cookies={"__Host-linkmoth_session": cookie2},
        )
        self.assertEqual(code, 401)

    def test_totp_requires_csrf(self):
        _, _, cookie, _ = self._login()
        code, _, _, _ = http(
            "POST",
            f"{self.base}/api/auth/totp",
            {"code": self.valid_code},
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 403)

    def test_totp_attempts_are_rate_limited(self):
        _, _, cookie, csrf = self._login()
        invalid_code = str((int(self.valid_code) + 1) % 1000000).zfill(6)
        for _ in range(3):
            code, _, _, _ = http(
                "POST",
                f"{self.base}/api/auth/totp",
                {"code": invalid_code},
                headers={"X-CSRF-Token": csrf},
                cookies={"__Host-linkmoth_session": cookie},
            )
            self.assertEqual(code, 401)
        code, body, _, _ = http(
            "POST",
            f"{self.base}/api/auth/totp",
            {"code": invalid_code},
            headers={"X-CSRF-Token": csrf},
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 429)
        self.assertIn("retry_after", body)

    def test_new_password_step_does_not_reset_totp_failures(self):
        _, _, cookie, csrf = self._login()
        invalid_code = str((int(self.valid_code) + 1) % 1000000).zfill(6)
        for _ in range(2):
            code, _, _, _ = http(
                "POST",
                f"{self.base}/api/auth/totp",
                {"code": invalid_code},
                headers={"X-CSRF-Token": csrf},
                cookies={"__Host-linkmoth_session": cookie},
            )
            self.assertEqual(code, 401)
        _, _, cookie2, csrf2 = self._login()
        code, _, _, _ = http(
            "POST",
            f"{self.base}/api/auth/totp",
            {"code": invalid_code},
            headers={"X-CSRF-Token": csrf2},
            cookies={"__Host-linkmoth_session": cookie2},
        )
        self.assertEqual(code, 401)
        code, _, _, _ = http(
            "POST",
            f"{self.base}/api/auth/totp",
            {"code": invalid_code},
            headers={"X-CSRF-Token": csrf2},
            cookies={"__Host-linkmoth_session": cookie2},
        )
        self.assertEqual(code, 429)

    def test_totp_code_cannot_be_replayed(self):
        _, _, cookie1, csrf1 = self._login()
        _, _, cookie2, csrf2 = self._login()
        code, _, _, _ = http(
            "POST",
            f"{self.base}/api/auth/totp",
            {"code": self.valid_code},
            headers={"X-CSRF-Token": csrf1},
            cookies={"__Host-linkmoth_session": cookie1},
        )
        self.assertEqual(code, 200)
        code, _, _, _ = http(
            "POST",
            f"{self.base}/api/auth/totp",
            {"code": self.valid_code},
            headers={"X-CSRF-Token": csrf2},
            cookies={"__Host-linkmoth_session": cookie2},
        )
        self.assertEqual(code, 401)

    def test_enabling_totp_does_not_grandfather_password_only_session(self):
        # This class enables TOTP in setUp; start from a clean password-only state.
        self.auth.disable_totp()
        _, _, cookie, _ = self._login()
        code, _, _, _ = http(
            "GET",
            f"{self.base}/api/status",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        # Enabling 2FA must invalidate the pre-existing password-only session.
        self.auth.setup_totp()
        code, _, _, _ = http(
            "GET",
            f"{self.base}/api/status",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 401)


class AuthCryptoTests(unittest.TestCase):
    def test_scrypt_hash_verify(self):
        from linkmoth_auth import hash_password, verify_password
        h, s = hash_password("hunter2")
        self.assertTrue(verify_password("hunter2", s, h))
        self.assertFalse(verify_password("wrong", s, h))

    def test_no_plaintext_in_auth_store(self):
        tmp = tempfile.mkdtemp()
        try:
            state = Path(tmp)
            cfg = {"auth": {}}
            from linkmoth_auth import AuthManager
            auth = AuthManager(state, cfg, sqlite_connector(state / "auth-test.db"))
            auth.set_password("my-secure-password")
            raw = (state / "auth.json").read_text()
            self.assertNotIn("my-secure-password", raw)
            self.assertIn("password_hash", raw)
            if os.name != "nt":
                self.assertEqual(
                    stat.S_IMODE((state / "auth.json").stat().st_mode),
                    0o600,
                )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_short_password_is_rejected(self):
        from linkmoth_auth import AuthManager
        tmp = tempfile.mkdtemp()
        try:
            state = Path(tmp)
            auth = AuthManager(
                state,
                {"auth": {}},
                sqlite_connector(state / "auth-test.db"),
            )
            with self.assertRaises(ValueError):
                auth.set_password("too-short")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_totp_enabled_derives_from_store_not_config(self):
        from linkmoth_auth import AuthManager
        tmp = tempfile.mkdtemp()
        try:
            state = Path(tmp)
            # Legacy config flag on, but NO secret in the store.
            auth = AuthManager(
                state,
                {"auth": {"totp_enabled": True}},
                sqlite_connector(state / "auth-test.db"),
            )
            auth.set_password("my-secure-password")
            # Store-derived: no secret => 2FA is OFF and fails safe (no raise).
            self.assertFalse(auth.totp_enabled)
            self.assertFalse(auth.verify_second_factor("123456"))
            auth.validate_configuration()
            # Once a real secret is provisioned, 2FA reads as ON.
            auth.setup_totp()
            self.assertTrue(auth.totp_enabled)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_audit_events_do_not_contain_secrets(self):
        from linkmoth_auth import AuthManager
        tmp = tempfile.mkdtemp()
        try:
            state = Path(tmp)
            auth = AuthManager(
                state,
                {"auth": {}},
                sqlite_connector(state / "auth-test.db"),
            )
            auth.set_password("my-secure-password")
            secret = auth.rotate_webhook_secret()
            events = json.dumps(auth.audit_events())
            self.assertIn("password_changed", events)
            self.assertIn("webhook_rotated", events)
            self.assertNotIn("my-secure-password", events)
            self.assertNotIn(secret, events)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_trusted_proxy_chain_uses_nearest_untrusted_address(self):
        from linkmoth_auth import AuthManager
        tmp = tempfile.mkdtemp()
        try:
            state = Path(tmp)
            auth = AuthManager(
                state,
                {
                    "auth": {
                        "trusted_proxy_cidrs": ["127.0.0.1/32", "192.0.2.0/24"],
                    }
                },
                sqlite_connector(state / "auth-test.db"),
            )
            headers = {
                "Remote-Addr": "127.0.0.1",
                "X-Forwarded-For": "198.51.100.9, 203.0.113.7, 192.0.2.10",
            }
            self.assertEqual(auth._client_ip(headers), "203.0.113.7")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_ipv4_mapped_ipv6_normalizes_to_one_bucket(self):
        # ::ffff:198.51.100.7 and 198.51.100.7 are the same host; they must key
        # the same rate-limit bucket, not two independent lockout budgets.
        from linkmoth_auth import AuthManager
        tmp = tempfile.mkdtemp()
        try:
            state = Path(tmp)
            auth = AuthManager(
                state,
                {"auth": {"trusted_proxy_cidrs": ["10.0.0.1/32"]}},
                sqlite_connector(state / "auth-test.db"),
            )
            # Direct peer presented in mapped form collapses to plain IPv4.
            self.assertEqual(
                auth._client_ip({"Remote-Addr": "::ffff:198.51.100.7"}),
                "198.51.100.7",
            )
            # And the same through a trusted-proxy X-Forwarded-For hop.
            self.assertEqual(
                auth._client_ip({
                    "Remote-Addr": "10.0.0.1",
                    "X-Forwarded-For": "::ffff:198.51.100.7",
                }),
                "198.51.100.7",
            )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_ipv4_mapped_ipv6_shares_lockout_bucket(self):
        # Alternating the two representations must not double the failure budget.
        from linkmoth_auth import AuthManager
        tmp = tempfile.mkdtemp()
        try:
            state = Path(tmp)
            auth = AuthManager(
                state, {}, sqlite_connector(state / "auth-test.db"),
            )
            plain = {"Remote-Addr": "198.51.100.7"}
            mapped = {"Remote-Addr": "::ffff:198.51.100.7"}
            limit = auth._max_attempts()
            for i in range(limit):
                headers = plain if i % 2 == 0 else mapped
                auth.record_login_failure(headers)
            # Reaching the limit locks both representations, not just one.
            self.assertFalse(auth.login_allowed(plain)[0])
            self.assertFalse(auth.login_allowed(mapped)[0])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_auth_cannot_be_disabled_by_legacy_config(self):
        from linkmoth_auth import AuthManager
        tmp = tempfile.mkdtemp()
        try:
            state = Path(tmp)
            auth = AuthManager(
                state,
                {"auth": {"enabled": False}},
                sqlite_connector(state / "auth-test.db"),
            )
            self.assertTrue(auth.enabled)
            self.assertTrue(auth.public_status(None)["onboarding_required"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_installer_uses_https_and_certificate_renewal(self):
        installer = (REPO_ROOT / "install.sh").read_text()
        renewal = (REPO_ROOT / "renew-cert.sh").read_text()
        self.assertIn('https://$HEALTH_HOST:$PORT/health', installer)
        self.assertIn("openssl req -x509", installer)
        self.assertIn("linkmoth-cert-renew.timer", installer)
        self.assertIn("linkmoth.svg", installer)
        self.assertIn("detect_pkg_manager", installer)
        self.assertIn("iproute2", installer)
        self.assertIn("/ca.crt", installer)
        self.assertNotIn("bind9-dnsutils", installer)
        self.assertIn("openssl verify", renewal)
        self.assertIn("systemctl restart linkmoth.service", renewal)

    def test_installer_protects_configuration_secrets(self):
        installer = (REPO_ROOT / "install.sh").read_text()
        self.assertIn('chown root:root "$APP"', installer)
        self.assertIn('chmod 755 "$APP"', installer)
        self.assertIn('chown root:linkmoth "$ETC"', installer)
        self.assertIn('chmod 750 "$ETC"', installer)
        # config.json is secured root:linkmoth 640 via a symlink-safe helper
        # (open O_NOFOLLOW + fchown/fchmod the fd) rather than a path chown/chmod.
        self.assertIn('secure_regular_file "$ETC/config.json" root linkmoth 640', installer)
        self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin", installer)
        self.assertIn("pywebpush==2.3.0", installer)
        self.assertIn("http-ece==1.2.1", installer)
        self.assertIn("--only-binary=:all:", installer)
        self.assertIn("--no-binary=http-ece", installer)
        self.assertIn("runuser -u linkmoth", installer)

    def test_server_refuses_invalid_configuration(self):
        import linkmoth
        # main() reads its own bootstrap-bound copies of CONFIG_ERROR/init_db
        # (re-exported from linkmoth_core at import time), so the patch must
        # target linkmoth itself, not linkmoth_core, to intercept that call.
        with patch.object(linkmoth, "CONFIG_ERROR", "broken config"), patch.object(
            linkmoth.sys, "argv", ["linkmoth.py"]
        ), patch.object(linkmoth, "init_db") as init:
            with self.assertRaises(SystemExit) as stopped:
                linkmoth.main()
        self.assertEqual(stopped.exception.code, 1)
        init.assert_not_called()


def _ladder_checks(**overrides):
    base = {
        "power": True, "link": True, "gateway": True, "router_wlan": None,
        "pihole_dns": True, "upstream_dns": True, "raw_ping": True, "https": True,
    }
    base.update(overrides)
    return [
        {"id": cid, "label": cid, "ok": ok, "detail": "d", "ms": None, "micro": []}
        for cid, ok in base.items()
    ]


class CaCertTests(LinkmothTestBase):
    def test_ca_cert_served_without_auth(self):
        ca = self.state / "tls" / "ca.crt"
        ca.parent.mkdir(parents=True, exist_ok=True)
        ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n")
        code, body, _, headers = http("GET", f"{self.base}/ca.crt")
        self.assertEqual(code, 200)
        self.assertEqual(body, ca.read_bytes())
        self.assertIn("x-x509-ca-cert", headers.get("Content-Type", ""))

    def test_ca_cert_missing_is_404(self):
        code, _, _, _ = http("GET", f"{self.base}/ca.crt")
        self.assertEqual(code, 404)


class GuidedVerifyTests(LinkmothTestBase):
    def setUp(self):
        super().setUp()
        self._configure_auth()
        from linkmoth_outage import OUTAGE_TRACKER
        OUTAGE_TRACKER._consecutive_clear = 0

    def tearDown(self):
        from linkmoth_outage import OUTAGE_TRACKER
        OUTAGE_TRACKER._consecutive_clear = 0
        super().tearDown()

    def _seed_before_run(self, checks=None, **overrides):
        checks = checks or _ladder_checks(**overrides)
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO runs(incident_id, ts, severity, code, title, explain,"
                " hint, checks, duration_ms, kind) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (None, time.time(), "bad", "router_down", "t", "", "",
                 json.dumps(checks), 1.0, "manual"),
            )

    def test_verify_reports_fixed_rung(self):
        self._seed_before_run(gateway=False)
        _, _, cookie, csrf = self._login()
        with patch.object(linkmoth_engine, "run_ladder",
                          return_value=(_ladder_checks(), 1.0)):
            code, body, _, _ = http(
                "POST", f"{self.base}/api/verify", {},
                headers={"X-CSRF-Token": csrf},
                cookies={"__Host-linkmoth_session": cookie},
            )
        self.assertEqual(code, 200)
        self.assertEqual(body["fixed"], ["gateway"])
        self.assertEqual(body["still_bad"], [])
        self.assertEqual(body["verdict"]["severity"], "ok")

    def test_verify_reports_still_bad(self):
        self._seed_before_run(gateway=False)
        _, _, cookie, csrf = self._login()
        with patch.object(linkmoth_engine, "run_ladder",
                          return_value=(_ladder_checks(gateway=False), 1.0)):
            code, body, _, _ = http(
                "POST", f"{self.base}/api/verify", {},
                headers={"X-CSRF-Token": csrf},
                cookies={"__Host-linkmoth_session": cookie},
            )
        self.assertEqual(code, 200)
        self.assertIn("gateway", body["still_bad"])
        self.assertEqual(body["fixed"], [])

    def test_verify_reports_improved_redundant_evidence_with_human_label(self):
        before = _ladder_checks()
        before_dns = next(c for c in before if c["id"] == "upstream_dns")
        before_dns["state"] = "partial"
        before_dns["label"] = "Upstream DNS (direct)"
        self._seed_before_run(checks=before)
        after = _ladder_checks()
        after_dns = next(c for c in after if c["id"] == "upstream_dns")
        after_dns["state"] = "passed"
        after_dns["label"] = "Upstream DNS (direct)"
        _, _, cookie, csrf = self._login()
        with patch.object(linkmoth_engine, "run_ladder", return_value=(after, 1.0)):
            code, body, _, _ = http(
                "POST", f"{self.base}/api/verify", {},
                headers={"X-CSRF-Token": csrf},
                cookies={"__Host-linkmoth_session": cookie},
            )
        self.assertEqual(code, 200)
        self.assertEqual(body["improved"], ["upstream_dns"])
        self.assertEqual(body["improved_labels"], ["Upstream DNS (direct)"])
        self.assertEqual(body["regressed"], [])

    def test_verify_requires_csrf(self):
        _, _, cookie, _ = self._login()
        code, _, _, _ = http(
            "POST", f"{self.base}/api/verify", {},
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 403)

    def test_verify_cooldown_returns_429(self):
        self._seed_before_run(gateway=False)
        _, _, cookie, csrf = self._login()
        with patch.object(linkmoth_engine, "run_ladder",
                          return_value=(_ladder_checks(), 1.0)):
            first, _, _, _ = http(
                "POST", f"{self.base}/api/verify", {},
                headers={"X-CSRF-Token": csrf},
                cookies={"__Host-linkmoth_session": cookie},
            )
            second, body, _, _ = http(
                "POST", f"{self.base}/api/verify", {},
                headers={"X-CSRF-Token": csrf},
                cookies={"__Host-linkmoth_session": cookie},
            )
        self.assertEqual(first, 200)
        self.assertEqual(second, 429)


SC = "__Host-linkmoth_session"


class SecurityManagementTests(LinkmothTestBase):
    def setUp(self):
        super().setUp()
        self._configure_auth()

    def _totp_login(self, secret):
        from linkmoth_auth import _totp_at
        code = _totp_at(secret, int(time.time()) // 30)
        return self._login(totp_code=code)

    def test_session_cookie_uses_host_prefix(self):
        code, _, _, headers = http(
            "POST", f"{self.base}/api/auth/login",
            {"password": "secret-passphrase"})
        self.assertEqual(code, 200)
        self.assertIn("__Host-linkmoth_session=", headers.get("Set-Cookie", ""))

    def test_security_posture_flags_wildcard_bind_over_tunnel(self):
        _, _, cookie, _ = self._login()
        fake_ifaces = [
            {"iface": "eth0", "address": "192.168.1.10", "kind": "lan"},
            {"iface": "wg0", "address": "10.8.0.2", "kind": "tunnel"},
        ]
        with patch.object(linkmoth_probes, "classify_network_interfaces",
                          return_value=fake_ifaces):
            with patch.dict(self.linkmoth.CFG, {"bind": "0.0.0.0"}):
                code, body, _, _ = http(
                    "GET", f"{self.base}/api/auth/security",
                    cookies={"__Host-linkmoth_session": cookie})
        self.assertEqual(code, 200)
        self.assertEqual(len(body["tunnel_exposure"]), 1)
        self.assertEqual(body["tunnel_exposure"][0]["iface"], "wg0")

    def test_security_posture_no_warning_for_narrow_bind(self):
        _, _, cookie, _ = self._login()
        fake_ifaces = [
            {"iface": "wg0", "address": "10.8.0.2", "kind": "tunnel"},
        ]
        with patch.object(linkmoth_probes, "classify_network_interfaces",
                          return_value=fake_ifaces):
            with patch.dict(self.linkmoth.CFG, {"bind": "192.168.1.10"}):
                code, body, _, _ = http(
                    "GET", f"{self.base}/api/auth/security",
                    cookies={"__Host-linkmoth_session": cookie})
        self.assertEqual(code, 200)
        self.assertEqual(body["tunnel_exposure"], [])

    def test_change_password_requires_current_and_logs_out(self):
        _, _, cookie, csrf = self._login()
        # Wrong current password is rejected.
        code, _, _, _ = http(
            "POST", f"{self.base}/api/auth/change-password",
            {"current": "wrong-passphrase", "new": "a-fresh-strong-passphrase"},
            headers={"X-CSRF-Token": csrf}, cookies={SC: cookie})
        self.assertEqual(code, 401)
        # Correct current password succeeds and invalidates all sessions.
        code, body, _, _ = http(
            "POST", f"{self.base}/api/auth/change-password",
            {"current": "secret-passphrase", "new": "a-fresh-strong-passphrase"},
            headers={"X-CSRF-Token": csrf}, cookies={SC: cookie})
        self.assertEqual(code, 200)
        code, _, _, _ = http("GET", f"{self.base}/api/status", cookies={SC: cookie})
        self.assertEqual(code, 401)
        # The new password works.
        code, body, _, _ = http(
            "POST", f"{self.base}/api/auth/login",
            {"password": "a-fresh-strong-passphrase"})
        self.assertEqual(code, 200)
        self.assertTrue(body["authenticated"])

    def test_change_password_requires_csrf(self):
        _, _, cookie, _ = self._login()
        code, _, _, _ = http(
            "POST", f"{self.base}/api/auth/change-password",
            {"current": "secret-passphrase", "new": "a-fresh-strong-passphrase"},
            cookies={SC: cookie})
        self.assertEqual(code, 403)

    def test_totp_setup_requires_csrf(self):
        _, _, cookie, _ = self._login()
        code, _, _, _ = http(
            "POST", f"{self.base}/api/auth/totp/setup", {},
            cookies={SC: cookie})
        self.assertEqual(code, 403)
        self.assertNotIn("pending_totp_secret", self.auth.load_store())

    def test_totp_setup_then_activate_enables_2fa(self):
        _, _, cookie, csrf = self._login()
        code, body, _, _ = http(
            "POST", f"{self.base}/api/auth/totp/setup", {},
            headers={"X-CSRF-Token": csrf}, cookies={SC: cookie})
        self.assertEqual(code, 200)
        secret = body["secret"]
        self.assertNotIn("recovery_codes", body)
        pending_store = self.auth.load_store()
        self.assertNotIn("recovery_hashes", pending_store)
        self.assertNotIn("pending_recovery_hashes", pending_store)
        self.assertFalse(self.auth.totp_enabled)  # still pending
        # A wrong code leaves 2FA pending (not enabled).
        from linkmoth_auth import _totp_at
        now_counter = int(time.time()) // 30
        valid_window = {
            _totp_at(secret, counter)
            for counter in range(now_counter - 1, now_counter + 2)
        }
        invalid = next(
            f"{candidate:06d}"
            for candidate in range(1_000_000)
            if f"{candidate:06d}" not in valid_window
        )
        code, _, _, _ = http(
            "POST", f"{self.base}/api/auth/totp/activate", {"code": invalid},
            headers={"X-CSRF-Token": csrf}, cookies={SC: cookie})
        self.assertEqual(code, 400)
        self.assertFalse(self.auth.totp_enabled)
        self.assertNotIn("recovery_hashes", self.auth.load_store())
        # The correct code activates 2FA and invalidates the old session.
        valid = _totp_at(secret, int(time.time()) // 30)
        code, body, _, _ = http(
            "POST", f"{self.base}/api/auth/totp/activate", {"code": valid},
            headers={"X-CSRF-Token": csrf}, cookies={SC: cookie})
        self.assertEqual(code, 200)
        self.assertEqual(len(body["recovery_codes"]), 10)
        self.assertTrue(self.auth.totp_enabled)
        code, _, _, _ = http("GET", f"{self.base}/api/status", cookies={SC: cookie})
        self.assertEqual(code, 401)

    def test_totp_pending_setup_expires_without_issuing_recovery_codes(self):
        _, _, cookie, csrf = self._login()
        code, body, _, _ = http(
            "POST", f"{self.base}/api/auth/totp/setup", {},
            headers={"X-CSRF-Token": csrf}, cookies={SC: cookie})
        self.assertEqual(code, 200)
        store = self.auth.load_store()
        store["pending_totp_created"] = time.time() - 601
        self.auth.save_store(store)
        from linkmoth_auth import _totp_at
        valid = _totp_at(body["secret"], int(time.time()) // 30)
        code, expired, _, _ = http(
            "POST", f"{self.base}/api/auth/totp/activate", {"code": valid},
            headers={"X-CSRF-Token": csrf}, cookies={SC: cookie})
        self.assertEqual(code, 400)
        self.assertIn("expired", expired["error"])
        final_store = self.auth.load_store()
        self.assertNotIn("pending_totp_secret", final_store)
        self.assertNotIn("totp_secret", final_store)
        self.assertNotIn("recovery_hashes", final_store)

    def test_totp_activation_failures_are_rate_limited(self):
        _, _, cookie, csrf = self._login()
        code, body, _, _ = http(
            "POST", f"{self.base}/api/auth/totp/setup", {},
            headers={"X-CSRF-Token": csrf}, cookies={SC: cookie})
        self.assertEqual(code, 200)
        from linkmoth_auth import _totp_at
        now_counter = int(time.time()) // 30
        valid_window = {
            _totp_at(body["secret"], counter)
            for counter in range(now_counter - 1, now_counter + 2)
        }
        invalid = next(
            f"{candidate:06d}"
            for candidate in range(1_000_000)
            if f"{candidate:06d}" not in valid_window
        )
        for _ in range(3):
            code, _, _, _ = http(
                "POST", f"{self.base}/api/auth/totp/activate", {"code": invalid},
                headers={"X-CSRF-Token": csrf}, cookies={SC: cookie})
            self.assertEqual(code, 400)
        code, limited, _, _ = http(
            "POST", f"{self.base}/api/auth/totp/activate", {"code": invalid},
            headers={"X-CSRF-Token": csrf}, cookies={SC: cookie})
        self.assertEqual(code, 429)
        self.assertIn("retry_after", limited)

    def test_totp_disable_requires_reauth(self):
        secret, _ = self.auth.setup_totp()
        _, _, cookie, csrf = self._totp_login(secret)
        # Wrong re-auth is rejected; 2FA stays on.
        code, _, _, _ = http(
            "POST", f"{self.base}/api/auth/totp/disable", {"password": "nope"},
            headers={"X-CSRF-Token": csrf}, cookies={SC: cookie})
        self.assertEqual(code, 401)
        self.assertTrue(self.auth.totp_enabled)
        # Correct password disables it.
        code, body, _, _ = http(
            "POST", f"{self.base}/api/auth/totp/disable",
            {"password": "secret-passphrase"},
            headers={"X-CSRF-Token": csrf}, cookies={SC: cookie})
        self.assertEqual(code, 200)
        self.assertFalse(self.auth.totp_enabled)

    def test_regenerate_recovery_codes_requires_password(self):
        secret, first = self.auth.setup_totp()
        _, _, cookie, csrf = self._totp_login(secret)
        code, _, _, _ = http(
            "POST", f"{self.base}/api/auth/totp/recovery-codes",
            {"password": "nope"},
            headers={"X-CSRF-Token": csrf}, cookies={SC: cookie})
        self.assertEqual(code, 401)
        code, body, _, _ = http(
            "POST", f"{self.base}/api/auth/totp/recovery-codes",
            {"password": "secret-passphrase"},
            headers={"X-CSRF-Token": csrf}, cookies={SC: cookie})
        self.assertEqual(code, 200)
        self.assertTrue(body["recovery_codes"])
        self.assertNotEqual(set(body["recovery_codes"]), set(first))

    def test_audit_endpoint_returns_events_without_secrets(self):
        _, _, cookie, csrf = self._login()
        # Generate an auditable failure, then read the log back.
        http("POST", f"{self.base}/api/auth/change-password",
             {"current": "wrong", "new": "another-strong-passphrase"},
             headers={"X-CSRF-Token": csrf}, cookies={SC: cookie})
        code, body, _, _ = http(
            "GET", f"{self.base}/api/auth/audit?limit=50", cookies={SC: cookie})
        self.assertEqual(code, 200)
        self.assertTrue(body["events"])
        blob = json.dumps(body["events"])
        self.assertNotIn("secret-passphrase", blob)

    def test_audit_requires_auth(self):
        code, _, _, _ = http("GET", f"{self.base}/api/auth/audit")
        self.assertEqual(code, 401)


class SessionIdleTests(unittest.TestCase):
    def test_idle_timeout_expires_session(self):
        from linkmoth_auth import AuthManager
        tmp = tempfile.mkdtemp()
        try:
            state = Path(tmp)
            db = sqlite_connector(state / "auth.db")
            auth = AuthManager(
                state,
                {"auth": {"session_idle_seconds": 100, "session_ttl_seconds": 100000}},
                db,
            )
            auth.set_password("my-secure-password")
            sess = auth.create_session(totp_verified=True)
            sid = sess["cookie_id"]
            self.assertIsNotNone(auth.get_session(sid))  # within idle
            # Age the session past the idle window (absolute lifetime untouched).
            with db() as conn:
                conn.execute("UPDATE auth_sessions SET last_activity=?",
                             (time.time() - 200,))
            self.assertIsNone(auth.get_session(sid))  # idle-expired
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_absolute_lifetime_still_enforced(self):
        from linkmoth_auth import AuthManager
        tmp = tempfile.mkdtemp()
        try:
            state = Path(tmp)
            db = sqlite_connector(state / "auth.db")
            auth = AuthManager(
                state,
                {"auth": {"session_idle_seconds": 100000, "session_ttl_seconds": 100}},
                db,
            )
            auth.set_password("my-secure-password")
            sess = auth.create_session(totp_verified=True)
            sid = sess["cookie_id"]
            with db() as conn:
                conn.execute("UPDATE auth_sessions SET expires=?",
                             (time.time() - 1,))
            self.assertIsNone(auth.get_session(sid))  # absolute-expired
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class ReadonlyTokenTests(LinkmothTestBase):
    def setUp(self):
        super().setUp()
        self._configure_auth()

    def test_token_lifecycle_and_hashed_storage(self):
        value, entry = self.auth.create_readonly_token("widget")
        self.assertTrue(value.startswith("lmro_"))
        listed = self.auth.list_readonly_tokens()
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["name"], "widget")
        self.assertNotIn("hash", listed[0])
        # The plain value never lands in the store.
        raw = self.auth.auth_path.read_text(encoding="utf-8")
        self.assertNotIn(value, raw)
        self.assertTrue(self.auth.verify_readonly_token(f"Bearer {value}"))
        self.assertFalse(self.auth.verify_readonly_token("Bearer lmro_wrong"))
        self.assertFalse(self.auth.verify_readonly_token(None))
        self.assertTrue(self.auth.revoke_readonly_token(entry["id"]))
        self.assertFalse(self.auth.verify_readonly_token(f"Bearer {value}"))
        self.assertFalse(self.auth.revoke_readonly_token(entry["id"]))

    def test_token_limit_enforced(self):
        for i in range(self.auth.READONLY_TOKEN_LIMIT):
            self.auth.create_readonly_token(f"t{i}")
        with self.assertRaises(ValueError):
            self.auth.create_readonly_token("one too many")

    def test_webhook_secret_is_not_a_readonly_token(self):
        self.assertFalse(
            self.auth.verify_readonly_token(f"Bearer {self.webhook}")
        )

    def test_token_reads_status_but_nothing_else(self):
        value, _ = self.auth.create_readonly_token("widget")
        headers = {"Authorization": f"Bearer {value}"}
        for path in ("/api/status", "/api/quality", "/api/report", "/api/history"):
            code, body, _, _ = http("GET", f"{self.base}{path}", headers=headers)
            self.assertEqual(code, 200, path)
        # Status via token must not carry a CSRF token.
        code, body, _, _ = http("GET", f"{self.base}/api/status", headers=headers)
        self.assertNotIn("csrf_token", body.get("auth", {}))
        # Outside the allowlist: 401.
        for path in ("/api/incidents?limit=5", "/api/auth/tokens",
                     "/api/auth/audit", "/api/webhooks"):
            code, _, _, _ = http("GET", f"{self.base}{path}", headers=headers)
            self.assertEqual(code, 401, path)
        # Never for POST, even on an allowlisted-looking path.
        code, _, _, _ = http(
            "POST", f"{self.base}/api/diagnose", {}, headers=headers,
        )
        self.assertEqual(code, 401)

    def test_token_routes_require_session(self):
        code, _, _, _ = http("GET", f"{self.base}/api/auth/tokens")
        self.assertEqual(code, 401)
        _, _, cookie, csrf = self._login()
        code, body, _, _ = http(
            "POST", f"{self.base}/api/auth/tokens", {"name": "from ui"},
            headers={"X-CSRF-Token": csrf},
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertTrue(body["token"].startswith("lmro_"))
        code, listing, _, _ = http(
            "GET", f"{self.base}/api/auth/tokens",
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertEqual(len(listing["tokens"]), 1)
        code, _, _, _ = http(
            "DELETE", f"{self.base}/api/auth/tokens/{body['id']}",
            headers={"X-CSRF-Token": csrf},
            cookies={"__Host-linkmoth_session": cookie},
        )
        self.assertEqual(code, 200)
        self.assertEqual(self.auth.list_readonly_tokens(), [])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Tests for isolated, RFC1918-only LAN device monitoring."""
import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import linkmoth_devices


def connector(path):
    @contextmanager
    def connect():
        conn = sqlite3.connect(path, timeout=10)
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


def device_payload(address="192.168.1.40", preset="generic", settings=None):
    return {
        "name": "Test device",
        "address": address,
        "preset": preset,
        "enabled": True,
        "interval_seconds": 0,
        "alerts": {"discord": False, "push": False, "webhook": False},
        "settings": settings or {},
    }


class DeviceValidationTests(unittest.TestCase):
    def test_accepts_all_three_rfc1918_ranges(self):
        for address in (
            "10.0.0.1", "10.255.255.254",
            "172.16.0.1", "172.31.255.254",
            "192.168.0.1", "192.168.255.254",
        ):
            with self.subTest(address=address):
                clean = linkmoth_devices.validate_device(device_payload(address))
                self.assertEqual(clean["address"], address)

    def test_rejects_every_other_address_class_and_hostnames(self):
        for address in (
            "device.local", "localhost", "127.0.0.1", "169.254.1.1",
            "172.15.255.255", "172.32.0.1", "224.0.0.1", "0.0.0.0",
            "8.8.8.8", "::1", "fc00::1", "2001:4860:4860::8888",
        ):
            with self.subTest(address=address):
                with self.assertRaises(ValueError):
                    linkmoth_devices.validate_device(device_payload(address))

    def test_only_fixed_presets_and_settings_are_accepted(self):
        with self.assertRaises(ValueError):
            linkmoth_devices.validate_device(device_payload(preset="custom"))
        with self.assertRaises(ValueError):
            linkmoth_devices.validate_device(
                device_payload(settings={"command": "echo unsafe"})
            )
        clean = linkmoth_devices.validate_device(device_payload(
            preset="web_ui",
            settings={
                "scheme": "https",
                "port": 8443,
                "path": "/health",
                "expected_status": 204,
                "body_contains": "",
                "verify_tls": False,
            },
        ))
        self.assertFalse(clean["settings"]["verify_tls"])

    def test_untrusted_certificate_toggle_is_https_only(self):
        clean = linkmoth_devices.validate_device(device_payload(
            preset="web_ui",
            settings={
                "scheme": "http",
                "port": 80,
                "path": "/",
                "expected_status": 200,
                "body_contains": "",
                "verify_tls": False,
            },
        ))
        self.assertTrue(clean["settings"]["verify_tls"])


class DeviceStateTests(unittest.TestCase):
    def test_service_success_is_up_even_when_ping_is_blocked(self):
        device = linkmoth_devices.validate_device(device_payload(
            preset="tcp_service", settings={"port": 1234},
        ))
        ping = mock.Mock(return_value=(False, "no ping", None))
        with mock.patch.object(
            linkmoth_devices, "_tcp_check",
            return_value={"kind": "tcp", "ok": True, "detail": "open", "ms": 1},
        ):
            result = linkmoth_devices.execute_device(device, ping)
        self.assertEqual(result["state"], "up")

    def test_ping_only_with_failed_service_is_degraded(self):
        device = linkmoth_devices.validate_device(device_payload(
            preset="tcp_service", settings={"port": 1234},
        ))
        ping = mock.Mock(return_value=(True, "ping ok", 1))
        with mock.patch.object(
            linkmoth_devices, "_tcp_check",
            return_value={"kind": "tcp", "ok": False, "detail": "closed", "ms": None},
        ):
            result = linkmoth_devices.execute_device(device, ping)
        self.assertEqual(result["state"], "degraded")

    def test_no_ping_or_service_is_down(self):
        device = linkmoth_devices.validate_device(device_payload(
            preset="tcp_service", settings={"port": 1234},
        ))
        ping = mock.Mock(return_value=(False, "no ping", None))
        with mock.patch.object(
            linkmoth_devices, "_tcp_check",
            return_value={"kind": "tcp", "ok": False, "detail": "closed", "ms": None},
        ):
            result = linkmoth_devices.execute_device(device, ping)
        self.assertEqual(result["state"], "down")

    def test_unexpected_monitor_failure_is_error(self):
        device = linkmoth_devices.validate_device(device_payload())
        ping = mock.Mock(side_effect=RuntimeError("broken runner"))
        result = linkmoth_devices.execute_device(device, ping)
        self.assertEqual(result["state"], "error")


class DeviceNotificationTests(unittest.TestCase):
    def test_only_opted_in_channels_are_called(self):
        device = {
            "id": "device-id",
            "name": "Printer",
            "address": "192.168.1.40",
            "preset": "printer",
            "alerts": {"discord": False, "push": True, "webhook": False},
        }
        result = {"state": "down", "summary": "no response", "results": []}
        with mock.patch(
            "linkmoth_discord.send_device_discord_alert"
        ) as discord:
            with mock.patch("linkmoth_push.send_push_async") as push:
                with mock.patch(
                    "linkmoth_webhooks.emit_event"
                ) as webhook:
                    linkmoth_devices.notify_device_event(
                        {}, Path("."), lambda: None,
                        device, result, "fault",
                    )
        discord.assert_not_called()
        push.assert_called_once()
        webhook.assert_not_called()

    def test_webhook_channel_emits_device_event(self):
        device = {
            "id": "device-id",
            "name": "Printer",
            "address": "192.168.1.40",
            "preset": "printer",
            "alerts": {"discord": False, "push": False, "webhook": True},
        }
        result = {"state": "down", "summary": "no response", "results": []}
        with mock.patch("linkmoth_webhooks.emit_event") as webhook:
            linkmoth_devices.notify_device_event(
                {}, Path("."), lambda: None, device, result, "fault",
            )
        webhook.assert_called_once()
        self.assertEqual(webhook.call_args[0][1], "device_down")
        ctx = webhook.call_args[0][2]
        self.assertEqual(ctx["source"], "Printer")
        self.assertEqual(ctx["affected_layer"], "device")


class _HttpFixture(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
            return
        if self.path == "/large":
            body = b"x" * (linkmoth_devices.MAX_HTTP_BODY + 1)
        else:
            body = b"healthy"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class DeviceHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _HttpFixture)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def settings(self, path, status=200, body=""):
        return {
            "scheme": "http",
            "port": self.port,
            "path": path,
            "expected_status": status,
            "body_contains": body,
            "verify_tls": True,
        }

    def test_http_status_and_body_match(self):
        result = linkmoth_devices._http_check(
            "127.0.0.1", self.settings("/ok", body="healthy")
        )
        self.assertTrue(result["ok"])

    def test_redirect_is_not_followed(self):
        result = linkmoth_devices._http_check(
            "127.0.0.1", self.settings("/redirect")
        )
        self.assertFalse(result["ok"])
        self.assertIn("302", result["detail"])

    def test_body_is_capped(self):
        result = linkmoth_devices._http_check(
            "127.0.0.1", self.settings("/large")
        )
        self.assertFalse(result["ok"])
        self.assertIn("64 KiB", result["detail"])

    def test_environment_proxies_are_disabled(self):
        real_build = linkmoth_devices.urlrequest.build_opener
        captured = []

        def record_handlers(*handlers):
            captured.extend(handlers)
            return real_build(*handlers)

        with mock.patch.object(
            linkmoth_devices.urlrequest,
            "build_opener",
            side_effect=record_handlers,
        ):
            linkmoth_devices._http_check("127.0.0.1", self.settings("/ok"))
        proxies = [
            handler.proxies for handler in captured
            if isinstance(handler, linkmoth_devices.urlrequest.ProxyHandler)
        ]
        self.assertTrue(proxies)
        self.assertTrue(all(proxy == {} for proxy in proxies))


class DeviceManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="linkmoth_devices_")
        self.path = Path(self.tmp.name) / "state.db"
        self.connect = connector(self.path)
        with self.connect() as conn:
            linkmoth_devices.init_device_db(conn)
            conn.execute(
                "CREATE TABLE network_runs(id INTEGER PRIMARY KEY, marker TEXT)"
            )
            conn.execute("INSERT INTO network_runs(marker) VALUES('untouched')")
        self.ping_ok = False
        self.raise_ping = False
        self.events = []

        def ping(address, count=1, timeout=2):
            if self.raise_ping:
                raise RuntimeError("runner failed")
            return self.ping_ok, "ping ok" if self.ping_ok else "no ping", (
                1.0 if self.ping_ok else None
            )

        def notify(cfg, state_dir, db_connect, device, result, event):
            self.events.append((device["id"], result["state"], event))

        self.manager = linkmoth_devices.DeviceManager(
            self.connect, ping, {}, Path(self.tmp.name), notify_func=notify,
        )

    def tearDown(self):
        self.manager._executor.shutdown(wait=True)
        self.tmp.cleanup()

    def create(self, interval=0):
        payload = device_payload()
        payload["interval_seconds"] = interval
        return self.manager.create_device(payload)

    def test_crud_and_device_history_are_isolated(self):
        created = self.create()
        self.assertEqual(len(self.manager.list_devices()), 1)
        updated = self.manager.update_device(created["id"], {"name": "Renamed"})
        self.assertEqual(updated["name"], "Renamed")
        self.manager.run_device(created["id"], source="manual")
        self.assertEqual(len(self.manager.history(created["id"])), 1)
        with self.connect() as conn:
            row = conn.execute("SELECT marker FROM network_runs").fetchone()
        self.assertEqual(row["marker"], "untouched")
        self.manager.delete_device(created["id"])
        self.assertEqual(self.manager.list_devices(), [])

    def test_manual_runs_do_not_advance_debounce(self):
        device = self.create(interval=300)
        self.manager.run_device(device["id"], source="manual")
        current = self.manager.get_device(device["id"])
        self.assertEqual(current["stable_state"], "unknown")
        self.assertEqual(current["failure_streak"], 0)
        self.assertEqual(self.events, [])

    def test_two_failures_and_two_successes_drive_alerts(self):
        device = self.create(interval=300)
        self.manager.run_device(device["id"], source="scheduled")
        first = self.manager.get_device(device["id"])
        self.assertEqual(first["failure_streak"], 1)
        self.assertEqual(first["stable_state"], "unknown")
        self.manager.run_device(device["id"], source="scheduled")
        second = self.manager.get_device(device["id"])
        self.assertEqual(second["stable_state"], "down")
        self.assertEqual(self.events[-1][2], "fault")

        self.ping_ok = True
        self.manager.run_device(device["id"], source="scheduled")
        self.assertEqual(self.manager.get_device(device["id"])["stable_state"], "down")
        self.manager.run_device(device["id"], source="scheduled")
        recovered = self.manager.get_device(device["id"])
        self.assertEqual(recovered["stable_state"], "up")
        self.assertEqual(self.events[-1][2], "recovery")

    def test_error_does_not_advance_counters(self):
        device = self.create(interval=300)
        self.manager.run_device(device["id"], source="scheduled")
        before = self.manager.get_device(device["id"])
        self.raise_ping = True
        result = self.manager.run_device(device["id"], source="scheduled")
        after = self.manager.get_device(device["id"])
        self.assertEqual(result["state"], "error")
        self.assertEqual(after["failure_streak"], before["failure_streak"])
        self.assertEqual(after["success_streak"], before["success_streak"])

    def test_recent_history_is_bounded(self):
        device = self.create()
        for _ in range(linkmoth_devices.MAX_DEVICE_RUNS + 3):
            self.manager.run_device(device["id"], source="manual")
        self.assertEqual(
            len(self.manager.history(device["id"], linkmoth_devices.MAX_DEVICE_RUNS)),
            linkmoth_devices.MAX_DEVICE_RUNS,
        )

    def test_due_device_runs_as_scheduled(self):
        device = self.create(interval=300)
        self.ping_ok = True
        with self.connect() as conn:
            conn.execute(
                "UPDATE devices SET next_run=0 WHERE id=?", (device["id"],)
            )
        self.assertEqual(self.manager.process_due(now=10), 1)
        deadline = time.time() + 3
        current = self.manager.get_device(device["id"])
        while current["last_run_ts"] is None and time.time() < deadline:
            time.sleep(0.02)
            current = self.manager.get_device(device["id"])
        self.assertIsNotNone(current["last_run_ts"])
        self.assertEqual(self.manager.history(device["id"])[0]["source"], "scheduled")
        self.assertGreater(current["next_run"], 10)

    def test_four_check_concurrency_limit_includes_manual_runs(self):
        release = threading.Event()
        started = threading.Event()
        count_lock = threading.Lock()
        started_count = 0

        def blocking_ping(address, count=1, timeout=2):
            nonlocal started_count
            with count_lock:
                started_count += 1
                if started_count == linkmoth_devices.MAX_CONCURRENT_CHECKS:
                    started.set()
            release.wait(3)
            return True, "ok", 1

        self.manager.ping_func = blocking_ping
        devices = [self.create() for _ in range(5)]
        workers = [
            threading.Thread(
                target=self.manager.run_device,
                args=(item["id"], "manual"),
            )
            for item in devices[:4]
        ]
        for worker in workers:
            worker.start()
        self.assertTrue(started.wait(2))
        with self.assertRaises(linkmoth_devices.DeviceBusy):
            self.manager.run_device(devices[4]["id"], source="manual")
        release.set()
        for worker in workers:
            worker.join(3)

    def test_device_count_is_capped(self):
        for index in range(linkmoth_devices.MAX_DEVICES):
            payload = device_payload(address=f"10.0.0.{index + 1}")
            payload["name"] = f"Device {index}"
            self.manager.create_device(payload)
        with self.assertRaises(linkmoth_devices.DeviceLimitReached):
            self.manager.create_device(device_payload(address="10.0.1.1"))


if __name__ == "__main__":
    unittest.main()

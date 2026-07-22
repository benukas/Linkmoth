"""Simple, isolated LAN device monitoring for Linkmoth.

Device checks deliberately have no connection to the network diagnosis ladder,
incidents, blame, or network history.
"""
import ipaddress
import json
import re
import socket
import sqlite3
import ssl
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib import error as urlerror
from urllib import request as urlrequest


ALLOWED_INTERVALS = frozenset({0, 300, 900, 1800, 3600})
ALLOWED_PRESETS = frozenset({"generic", "printer", "web_ui", "tcp_service"})
MAX_DEVICES = 50
MAX_CONCURRENT_CHECKS = 4
MAX_DEVICE_RUNS = 200
DEVICE_SPARK_SAMPLES = 60
MAX_HTTP_BODY = 64 * 1024
HTTP_TIMEOUT = 10
TCP_TIMEOUT = 5
RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class DeviceNotFound(LookupError):
    pass


class DeviceBusy(RuntimeError):
    pass


class DeviceLimitReached(RuntimeError):
    pass


def init_device_db(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS devices(
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            preset TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            interval_seconds INTEGER NOT NULL DEFAULT 0,
            alerts TEXT NOT NULL,
            settings TEXT NOT NULL,
            created REAL NOT NULL,
            updated REAL NOT NULL,
            last_run_ts REAL,
            last_state TEXT,
            last_summary TEXT,
            last_result TEXT,
            last_success REAL,
            last_failure REAL,
            stable_state TEXT NOT NULL DEFAULT 'unknown',
            success_streak INTEGER NOT NULL DEFAULT 0,
            failure_streak INTEGER NOT NULL DEFAULT 0,
            next_run REAL
        );
        CREATE TABLE IF NOT EXISTS device_runs(
            id INTEGER PRIMARY KEY,
            device_id TEXT NOT NULL,
            ts REAL NOT NULL,
            source TEXT NOT NULL,
            state TEXT NOT NULL,
            summary TEXT NOT NULL,
            duration_ms REAL NOT NULL,
            results TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_device_runs_device_id
            ON device_runs(device_id, id DESC);
        CREATE INDEX IF NOT EXISTS idx_devices_next_run
            ON devices(enabled, next_run);
        """
    )


def is_rfc1918_ipv4(value):
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return (
        isinstance(address, ipaddress.IPv4Address)
        and any(address in network for network in RFC1918_NETWORKS)
    )


def _clean_name(value):
    name = str(value or "").strip()
    if not name or len(name) > 80 or any(ord(ch) < 32 for ch in name):
        raise ValueError("name must be 1–80 printable characters")
    return name


def _clean_address(value):
    address = str(value or "").strip()
    if not is_rfc1918_ipv4(address):
        raise ValueError(
            "address must be an RFC1918 IPv4 address "
            "(10/8, 172.16/12, or 192.168/16)"
        )
    return str(ipaddress.IPv4Address(address))


def _clean_bool(value, field):
    if isinstance(value, bool):
        return value
    raise ValueError(f"{field} must be true or false")


def _clean_port(value, field="port"):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be an integer") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"{field} must be between 1 and 65535")
    return port


def _clean_alerts(value):
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("alerts must be an object")
    unknown = set(value) - {"discord", "push", "webhook"}
    if unknown:
        raise ValueError("unknown alert channel")
    return {
        "discord": _clean_bool(value.get("discord", False), "alerts.discord"),
        "push": _clean_bool(value.get("push", False), "alerts.push"),
        "webhook": _clean_bool(value.get("webhook", False), "alerts.webhook"),
    }


def _clean_settings(preset, value):
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("settings must be an object")
    if preset in ("generic", "printer"):
        if value:
            raise ValueError(f"{preset} does not accept additional settings")
        return {}
    if preset == "tcp_service":
        if set(value) - {"port"}:
            raise ValueError("tcp_service accepts only port")
        return {"port": _clean_port(value.get("port"))}
    if preset != "web_ui":
        raise ValueError("unknown preset")

    allowed = {
        "scheme", "port", "path", "expected_status", "body_contains",
        "verify_tls",
    }
    if set(value) - allowed:
        raise ValueError("web_ui contains an unknown setting")
    scheme = str(value.get("scheme") or "http").strip().lower()
    if scheme not in ("http", "https"):
        raise ValueError("scheme must be http or https")
    default_port = 443 if scheme == "https" else 80
    port = _clean_port(value.get("port", default_port))
    path = str(value.get("path") or "/").strip()
    if (
        not path.startswith("/")
        or path.startswith("//")
        or len(path) > 512
        or not re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*", path)
    ):
        raise ValueError("path must be an ASCII local URL path beginning with /")
    try:
        expected_status = int(value.get("expected_status", 200))
    except (TypeError, ValueError):
        raise ValueError("expected_status must be an integer") from None
    if not 100 <= expected_status <= 599:
        raise ValueError("expected_status must be between 100 and 599")
    body_contains = str(value.get("body_contains") or "")
    if len(body_contains) > 256 or any(ord(ch) < 32 and ch not in "\t" for ch in body_contains):
        raise ValueError("body_contains must be at most 256 printable characters")
    verify_tls = _clean_bool(value.get("verify_tls", True), "verify_tls")
    if scheme != "https":
        verify_tls = True
    return {
        "scheme": scheme,
        "port": port,
        "path": path,
        "expected_status": expected_status,
        "body_contains": body_contains,
        "verify_tls": verify_tls,
    }


def validate_device(data):
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    allowed = {
        "name", "address", "preset", "enabled", "interval_seconds",
        "alerts", "settings",
    }
    if set(data) - allowed:
        raise ValueError("device contains an unknown field")
    preset = str(data.get("preset") or "generic").strip().lower()
    if preset not in ALLOWED_PRESETS:
        raise ValueError("unknown device preset")
    try:
        interval = int(data.get("interval_seconds", 0))
    except (TypeError, ValueError):
        raise ValueError("interval_seconds must be an integer") from None
    if interval not in ALLOWED_INTERVALS:
        raise ValueError("interval_seconds must be 0, 300, 900, 1800, or 3600")
    return {
        "name": _clean_name(data.get("name")),
        "address": _clean_address(data.get("address")),
        "preset": preset,
        "enabled": _clean_bool(data.get("enabled", True), "enabled"),
        "interval_seconds": interval,
        "alerts": _clean_alerts(data.get("alerts")),
        "settings": _clean_settings(preset, data.get("settings")),
    }


def _json_dict(value):
    try:
        result = json.loads(value or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}
    return result if isinstance(result, dict) else {}


def _row_to_device(row, running=False):
    item = dict(row)
    item["enabled"] = bool(item["enabled"])
    item["alerts"] = _json_dict(item.pop("alerts"))
    item["settings"] = _json_dict(item.pop("settings"))
    item["latest"] = _json_dict(item.pop("last_result"))
    item["running"] = running
    return item


def _tcp_check(address, port):
    started = time.monotonic()
    try:
        with socket.create_connection((address, port), timeout=TCP_TIMEOUT):
            elapsed = (time.monotonic() - started) * 1000
            return {
                "kind": "tcp",
                "ok": True,
                "detail": f"TCP {port} answered in {elapsed:.0f} ms",
                "ms": round(elapsed, 1),
            }
    except (OSError, socket.timeout) as exc:
        return {
            "kind": "tcp",
            "ok": False,
            "detail": f"TCP {port} did not answer ({exc.__class__.__name__})",
            "ms": None,
        }


class _NoRedirect(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_check(address, settings):
    scheme = settings["scheme"]
    port = settings["port"]
    path = settings["path"]
    expected = settings["expected_status"]
    body_contains = settings["body_contains"]
    url = f"{scheme}://{address}:{port}{path}"
    handlers = [urlrequest.ProxyHandler({}), _NoRedirect()]
    if scheme == "https":
        context = (
            ssl.create_default_context()
            if settings["verify_tls"]
            else ssl._create_unverified_context()
        )
        handlers.append(urlrequest.HTTPSHandler(context=context))
    opener = urlrequest.build_opener(*handlers)
    req = urlrequest.Request(
        url,
        headers={"User-Agent": "linkmoth-device/1.0"},
        method="GET",
    )
    started = time.monotonic()
    response = None
    try:
        response = opener.open(req, timeout=HTTP_TIMEOUT)
    except urlerror.HTTPError as exc:
        response = exc
    except (urlerror.URLError, ssl.SSLError, OSError, socket.timeout) as exc:
        reason = getattr(exc, "reason", None)
        label = reason.__class__.__name__ if reason else exc.__class__.__name__
        return {
            "kind": "http",
            "ok": False,
            "detail": f"{scheme.upper()} did not answer ({label})",
            "ms": None,
        }
    try:
        status = int(getattr(response, "status", response.getcode()))
        body = response.read(MAX_HTTP_BODY + 1)
    finally:
        response.close()
    elapsed = (time.monotonic() - started) * 1000
    if len(body) > MAX_HTTP_BODY:
        return {
            "kind": "http",
            "ok": False,
            "detail": f"HTTP {status}, response exceeds 64 KiB",
            "ms": round(elapsed, 1),
        }
    if status != expected:
        return {
            "kind": "http",
            "ok": False,
            "detail": f"HTTP {status}, expected {expected}",
            "ms": round(elapsed, 1),
        }
    if body_contains:
        text = body.decode("utf-8", errors="replace")
        if body_contains not in text:
            return {
                "kind": "http",
                "ok": False,
                "detail": f"HTTP {status}, expected text not found",
                "ms": round(elapsed, 1),
            }
    tls_note = ""
    if scheme == "https" and not settings["verify_tls"]:
        tls_note = " (certificate not verified)"
    return {
        "kind": "http",
        "ok": True,
        "detail": f"HTTP {status} in {elapsed:.0f} ms{tls_note}",
        "ms": round(elapsed, 1),
    }


def execute_device(device, ping_func):
    started = time.monotonic()
    address = device["address"]
    try:
        ping_ok, ping_detail, ping_ms = ping_func(address, count=1, timeout=2)
        results = [{
            "kind": "ping",
            "ok": bool(ping_ok),
            "detail": ping_detail,
            "ms": round(ping_ms, 1) if ping_ms is not None else None,
        }]
        service = None
        if device["preset"] == "printer":
            service = _tcp_check(address, 9100)
        elif device["preset"] == "tcp_service":
            service = _tcp_check(address, device["settings"]["port"])
        elif device["preset"] == "web_ui":
            service = _http_check(address, device["settings"])
        if service is not None:
            results.append(service)
        if service is None:
            state = "up" if ping_ok else "down"
        elif service["ok"]:
            state = "up"
        elif ping_ok:
            state = "degraded"
        else:
            state = "down"
        if state == "up":
            summary = service["detail"] if service is not None else ping_detail
        elif state == "degraded":
            summary = f"Reachable, but {service['detail']}"
        else:
            failed = service["detail"] if service is not None else ping_detail
            summary = f"No usable response – {failed}"
    except Exception as exc:
        state = "error"
        results = [{
            "kind": "monitor",
            "ok": None,
            "detail": f"check error: {exc.__class__.__name__}",
            "ms": None,
        }]
        summary = "Linkmoth could not complete this device check"
    return {
        "state": state,
        "summary": summary,
        "duration_ms": round((time.monotonic() - started) * 1000, 1),
        "results": results,
    }


def notify_device_event(cfg, state_dir, db_connect, device, result, event):
    alerts = device.get("alerts") or {}
    if not any(alerts.values()):
        return
    recovery = event == "recovery"
    state = result.get("state") or "unknown"
    title = (
        f"✅ {device['name']} recovered"
        if recovery
        else f"🔴 {device['name']} is {state}"
    )
    body = f"{device['address']} · {result.get('summary') or state}"
    from linkmoth_notify import defer_notification_if_quiet
    deferred = defer_notification_if_quiet(
        cfg, db_connect, title, body,
        discord=bool(alerts.get("discord")),
        push=bool(alerts.get("push")),
    )
    if alerts.get("discord") and not deferred:
        from linkmoth_discord import send_device_discord_alert
        send_device_discord_alert(device, result, recovery, cfg)
    if alerts.get("push") and not deferred:
        from linkmoth_push import send_push_async
        send_push_async(
            state_dir, db_connect, cfg, title, body,
            tag=f"linkmoth-device-{device['id']}",
        )
    if alerts.get("webhook"):
        from linkmoth_webhooks import build_event_context, emit_event
        emit_event(
            db_connect,
            "device_recovered" if recovery else "device_down",
            build_event_context(
                "device_recovered" if recovery else "device_down",
                verdict={
                    "severity": "ok" if recovery else "bad",
                    "title": title,
                    "explain": body,
                },
                source=device["name"],
            ),
        )


class DeviceManager:
    def __init__(self, db_connect, ping_func, cfg, state_dir, notify_func=None):
        self.db_connect = db_connect
        self.ping_func = ping_func
        self.cfg = cfg
        self.state_dir = state_dir
        self.notify_func = notify_func or notify_device_event
        self._executor = ThreadPoolExecutor(
            max_workers=MAX_CONCURRENT_CHECKS,
            thread_name_prefix="linkmoth-device",
        )
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT_CHECKS)
        self._running = set()
        self._running_lock = threading.Lock()

    def _is_running(self, device_id):
        with self._running_lock:
            return device_id in self._running

    def _begin_run(self, device_id):
        with self._running_lock:
            if device_id in self._running:
                raise DeviceBusy("device check already running")
            if not self._slots.acquire(blocking=False):
                raise DeviceBusy("all device check slots are busy")
            self._running.add(device_id)

    def _end_run(self, device_id):
        with self._running_lock:
            self._running.discard(device_id)
            self._slots.release()

    def list_devices(self):
        with self.db_connect() as conn:
            rows = conn.execute("SELECT * FROM devices ORDER BY name COLLATE NOCASE").fetchall()
            devices = []
            for row in rows:
                item = _row_to_device(row, self._is_running(row["id"]))
                item["latency"] = self._latency_series(conn, row["id"])
                devices.append(item)
        return devices

    def _latency_series(self, conn, device_id, limit=DEVICE_SPARK_SAMPLES):
        """Recent check latencies (oldest→newest) for the per-device sparkline."""
        rows = conn.execute(
            "SELECT ts, state, duration_ms FROM device_runs "
            "WHERE device_id=? ORDER BY id DESC LIMIT ?",
            (device_id, limit),
        ).fetchall()
        return [
            {"ts": row["ts"], "state": row["state"], "ms": row["duration_ms"]}
            for row in reversed(rows)
        ]

    def get_device(self, device_id):
        with self.db_connect() as conn:
            row = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if not row:
            raise DeviceNotFound("no such device")
        return _row_to_device(row, self._is_running(device_id))

    def create_device(self, data):
        clean = validate_device(data)
        now = time.time()
        device_id = str(uuid.uuid4())
        next_run = (
            now + clean["interval_seconds"]
            if clean["enabled"] and clean["interval_seconds"] > 0
            else None
        )
        with self.db_connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            if count >= MAX_DEVICES:
                raise DeviceLimitReached(f"device limit reached ({MAX_DEVICES})")
            conn.execute(
                """
                INSERT INTO devices(
                    id, name, address, preset, enabled, interval_seconds,
                    alerts, settings, created, updated, next_run
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    device_id, clean["name"], clean["address"], clean["preset"],
                    int(clean["enabled"]), clean["interval_seconds"],
                    json.dumps(clean["alerts"]), json.dumps(clean["settings"]),
                    now, now, next_run,
                ),
            )
        return self.get_device(device_id)

    def update_device(self, device_id, data):
        current = self.get_device(device_id)
        base = {
            key: current[key]
            for key in (
                "name", "address", "preset", "enabled", "interval_seconds",
                "alerts", "settings",
            )
        }
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        base.update(data)
        clean = validate_device(base)
        monitor_changed = any(
            clean[key] != current[key]
            for key in ("address", "preset", "settings")
        )
        schedule_changed = any(
            clean[key] != current[key]
            for key in ("enabled", "interval_seconds")
        )
        now = time.time()
        next_run = (
            now + clean["interval_seconds"]
            if clean["enabled"] and clean["interval_seconds"] > 0
            else None
        )
        reset = monitor_changed or schedule_changed
        with self.db_connect() as conn:
            conn.execute(
                """
                UPDATE devices SET
                    name=?, address=?, preset=?, enabled=?, interval_seconds=?,
                    alerts=?, settings=?, updated=?, next_run=?,
                    stable_state=CASE WHEN ? THEN 'unknown' ELSE stable_state END,
                    success_streak=CASE WHEN ? THEN 0 ELSE success_streak END,
                    failure_streak=CASE WHEN ? THEN 0 ELSE failure_streak END,
                    last_run_ts=CASE WHEN ? THEN NULL ELSE last_run_ts END,
                    last_state=CASE WHEN ? THEN NULL ELSE last_state END,
                    last_summary=CASE WHEN ? THEN NULL ELSE last_summary END,
                    last_result=CASE WHEN ? THEN NULL ELSE last_result END,
                    last_success=CASE WHEN ? THEN NULL ELSE last_success END,
                    last_failure=CASE WHEN ? THEN NULL ELSE last_failure END
                WHERE id=?
                """,
                (
                    clean["name"], clean["address"], clean["preset"],
                    int(clean["enabled"]), clean["interval_seconds"],
                    json.dumps(clean["alerts"]), json.dumps(clean["settings"]),
                    now, next_run,
                    int(reset), int(reset), int(reset), int(monitor_changed),
                    int(monitor_changed), int(monitor_changed), int(monitor_changed),
                    int(monitor_changed), int(monitor_changed), device_id,
                ),
            )
        return self.get_device(device_id)

    def delete_device(self, device_id):
        if self._is_running(device_id):
            raise DeviceBusy("device check is running")
        with self.db_connect() as conn:
            found = conn.execute(
                "SELECT 1 FROM devices WHERE id=?", (device_id,)
            ).fetchone()
            if not found:
                raise DeviceNotFound("no such device")
            conn.execute("DELETE FROM device_runs WHERE device_id=?", (device_id,))
            conn.execute("DELETE FROM devices WHERE id=?", (device_id,))

    def history(self, device_id, limit=100):
        self.get_device(device_id)
        limit = max(1, min(MAX_DEVICE_RUNS, int(limit)))
        with self.db_connect() as conn:
            rows = conn.execute(
                """
                SELECT ts, source, state, summary, duration_ms, results
                FROM device_runs WHERE device_id=? ORDER BY id DESC LIMIT ?
                """,
                (device_id, limit),
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            try:
                item["results"] = json.loads(item["results"])
            except (json.JSONDecodeError, TypeError):
                item["results"] = []
            out.append(item)
        return out

    def run_device(self, device_id, source="manual"):
        self._begin_run(device_id)
        try:
            device = self.get_device(device_id)
            if not device["enabled"]:
                raise DeviceBusy("device is disabled")
            result = execute_device(device, self.ping_func)
            event = self._record_result(device, result, source)
            if event:
                try:
                    self.notify_func(
                        self.cfg, self.state_dir, self.db_connect,
                        device, result, event,
                    )
                except Exception as exc:
                    print(
                        f"device notification error: {exc}",
                        file=sys.stderr,
                        flush=True,
                    )
            return result
        finally:
            self._end_run(device_id)

    def _record_result(self, device, result, source):
        now = time.time()
        state = result["state"]
        event = None
        with self.db_connect() as conn:
            row = conn.execute(
                """
                SELECT stable_state, success_streak, failure_streak
                FROM devices WHERE id=?
                """,
                (device["id"],),
            ).fetchone()
            if not row:
                raise DeviceNotFound("device was deleted")
            stable = row["stable_state"]
            success_streak = int(row["success_streak"])
            failure_streak = int(row["failure_streak"])
            if source == "scheduled":
                if state == "up":
                    success_streak += 1
                    failure_streak = 0
                    if success_streak >= 2:
                        if stable in ("degraded", "down"):
                            event = "recovery"
                        stable = "up"
                elif state in ("degraded", "down"):
                    failure_streak += 1
                    success_streak = 0
                    if failure_streak >= 2:
                        if stable not in ("degraded", "down"):
                            event = "fault"
                        stable = state
                elif state == "error":
                    # A probe that errors is still a failed observation: count
                    # it so a device whose checks persistently raise cannot
                    # sit in its old stable state forever. The threshold is
                    # one higher than for a clean "down" so an isolated probe
                    # hiccup never flips the state on its own.
                    failure_streak += 1
                    success_streak = 0
                    if failure_streak >= 3:
                        if stable not in ("degraded", "down"):
                            event = "fault"
                        stable = "down"
            last_success = now if state == "up" else device.get("last_success")
            last_failure = (
                now if state in ("degraded", "down") else device.get("last_failure")
            )
            conn.execute(
                """
                UPDATE devices SET
                    last_run_ts=?, last_state=?, last_summary=?, last_result=?,
                    last_success=?, last_failure=?, stable_state=?,
                    success_streak=?, failure_streak=?
                WHERE id=?
                """,
                (
                    now, state, result["summary"], json.dumps(result),
                    last_success, last_failure, stable, success_streak,
                    failure_streak, device["id"],
                ),
            )
            conn.execute(
                """
                INSERT INTO device_runs(
                    device_id, ts, source, state, summary, duration_ms, results
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    device["id"], now, source, state, result["summary"],
                    result["duration_ms"], json.dumps(result["results"]),
                ),
            )
            conn.execute(
                """
                DELETE FROM device_runs
                WHERE device_id=? AND id NOT IN (
                    SELECT id FROM device_runs
                    WHERE device_id=? ORDER BY id DESC LIMIT ?
                )
                """,
                (device["id"], device["id"], MAX_DEVICE_RUNS),
            )
        return event

    def _run_scheduled_safe(self, device_id):
        try:
            self.run_device(device_id, source="scheduled")
        except (DeviceBusy, DeviceNotFound):
            return
        except Exception as exc:
            print(
                f"scheduled device check failed: {exc}",
                file=sys.stderr,
                flush=True,
            )

    def process_due(self, now=None):
        now = time.time() if now is None else float(now)
        with self.db_connect() as conn:
            rows = conn.execute(
                """
                SELECT id, interval_seconds FROM devices
                WHERE enabled=1 AND interval_seconds>0
                  AND next_run IS NOT NULL AND next_run<=?
                ORDER BY next_run LIMIT ?
                """,
                (now, MAX_DEVICES),
            ).fetchall()
            for row in rows:
                conn.execute(
                    "UPDATE devices SET next_run=? WHERE id=?",
                    (now + int(row["interval_seconds"]), row["id"]),
                )
        for row in rows:
            self._executor.submit(self._run_scheduled_safe, row["id"])
        return len(rows)

    def scheduler_loop(self):
        time.sleep(5)
        while True:
            # Any unhandled error (not just sqlite3.Error) must not kill this
            # thread, or scheduled device checks silently stop.
            try:
                self.process_due()
            except Exception as exc:
                print(f"device scheduler: {exc}", file=sys.stderr, flush=True)
            time.sleep(10)

    def api_metadata(self):
        from linkmoth_discord import discord_alerts_active
        from linkmoth_push import push_available
        from linkmoth_webhooks import webhook_channel_active
        return {
            "presets": sorted(ALLOWED_PRESETS),
            "intervals": sorted(ALLOWED_INTERVALS),
            "max_devices": MAX_DEVICES,
            "channels": {
                "discord": discord_alerts_active(self.cfg),
                "push": bool(
                    self.cfg.get("push_notifications_enabled", True)
                    and push_available(self.state_dir)
                ),
                "webhook": webhook_channel_active(self.db_connect),
            },
        }

"""Linkmoth HTTP layer: the request handler (every /api/* route, static
asset serving, session/CSRF/CSP enforcement) and the --doctor CLI dump.

Looks up linkmoth's own module object as `linkmoth.ENGINE`/`linkmoth.DEVICES`/
`linkmoth.get_auth()` etc. (created in linkmoth_engine.py and imported by
linkmoth.py's bootstrap) rather than `from linkmoth import ...`, since
linkmoth.py imports names back from this module -- a module-level
`import linkmoth` here would be circular for any caller that imports this
module before linkmoth.py has run (linkmoth.py's own bootstrap works around
that for itself by aliasing `sys.modules["linkmoth"]` to `__main__` before
its own imports run, but that trick is specific to being __main__, so it
doesn't help a caller that imports linkmoth_handler directly or first). The
`linkmoth` global below is a lazy proxy (_LazyLinkmothModule) that only
performs the real `import linkmoth` the first time something reads an
attribute off it -- always at request time, well after linkmoth.py has
actually finished loading, regardless of who constructed the server.
"""
import ipaddress
import json
import os
import re
import secrets
import select
import shlex
import shutil
import socket
import sqlite3
import ssl
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from linkmoth_core import (
    BASE, CONFIG_ERROR, CONFIG_PATH, FAVICON_PATH, ICON_PATH, MANIFEST_PATH,
    MASKABLE_ICON_PATH, MAX_HTTP_CONNECTIONS, PNG_ICON_PATHS, SW_PATH,
    REQUEST_HEADER_DEADLINE_SECONDS, TLS_HANDSHAKE_TIMEOUT_SECONDS, VERSION,
    WHITE_LOGO_PATH, WHITE_MARK_PATH, BoundedTLSServer, CFG, STATE_DIR,
    _ca_cert_path, _export_settings, _safe_request_host, apply_settings,
    build_tls_context, db, db_maintenance_info, init_db, manual_update_check,
    run_cmd, tls_paths, vacuum_database,
)
from linkmoth_backup import BackupInProgress, build_backup_archive_to_path
from linkmoth_engine import _set_meta, fire_drill_status, prometheus_metrics
from linkmoth_probes import (
    _LOAD_TEST_LOCK, _count_phrase, _validate_load_url, bind_exposure_risk,
    classify_network_interfaces, default_route, isp_report_csv,
    connection_score, quality_config, quality_summary, run_load_test,
    wifi_wired_differential,
)

class _LazyLinkmothModule:
    """Defers `import linkmoth` until the first actual attribute access
    (e.g. `linkmoth.ENGINE`) instead of this module's own import time -- see
    the module docstring for why an eager import here is circular for a
    caller that imports linkmoth_handler before linkmoth.py has run. Every
    Handler method reads through this at request time, always well after
    linkmoth.py has actually finished loading regardless of how the caller
    got here (normal `__main__` startup, or a test that wires this module's
    Handler into its own server without ever calling create_server())."""
    __slots__ = ("_module",)

    def __init__(self):
        self._module = None

    def __getattr__(self, name):
        module = self._module
        if module is None:
            import linkmoth as module
            object.__setattr__(self, "_module", module)
        return getattr(module, name)


linkmoth = _LazyLinkmothModule()


def create_server():
    return BoundedTLSServer(
        (CFG["bind"], CFG["port"]), Handler, build_tls_context(),
    )

def _peer_is_trusted_local(peer_ip):
    """True if a request's direct TCP peer is LAN/loopback, or an explicitly
    configured trusted-proxy address.

    Linkmoth is LAN-only by design; this backs a request-level guard against
    an accidental router port-forward, not just documentation. A configured
    `trusted_proxy_cidrs` entry is the opt-in for a deliberate reverse-proxy
    or remote-access setup (e.g. a VPN overlay) — anything else reaching a
    public/global address is refused outright.
    """
    try:
        peer = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    if not peer.is_global:
        return True
    for cidr in CFG.get("auth", {}).get("trusted_proxy_cidrs", []) or []:
        try:
            if peer in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


def _public_exposure_notify_allowed():
    """At most one proactive alert per cooldown window, so a port scan or
    internet-wide sweep can't turn into a notification flood."""
    global _LAST_PUBLIC_EXPOSURE_NOTIFY_MONO
    with _PUBLIC_EXPOSURE_NOTIFY_LOCK:
        now = time.monotonic()
        if now - _LAST_PUBLIC_EXPOSURE_NOTIFY_MONO < PUBLIC_EXPOSURE_NOTIFY_COOLDOWN_SECONDS:
            return False
        _LAST_PUBLIC_EXPOSURE_NOTIFY_MONO = now
        return True



MAX_REQUEST_BODY = 64 * 1024
REQUEST_TIMEOUT_SECONDS = 15
# Longest a single low-level header read may block before the wall-clock
# deadline is re-checked. Keeps a drip-feed client (one byte at a time, each
# under a per-recv timeout) from stretching one readline() call past the
# deadline: total overrun is bounded by this poll interval, not by
# REQUEST_TIMEOUT_SECONDS.
HEADER_POLL_SECONDS = 0.5
MAX_HTTP_HEADER_BYTES = 32 * 1024
MAX_HTTP_HEADER_COUNT = 64

AUTH_VERIFY_SLOTS = threading.BoundedSemaphore(2)



class _HeaderReadError(Exception):
    response = b""


class _HeaderReadTimeout(_HeaderReadError):
    response = (
        b"HTTP/1.1 408 Request Timeout\r\n"
        b"Connection: close\r\nContent-Length: 0\r\n\r\n"
    )


class _HeaderLimitExceeded(_HeaderReadError):
    response = (
        b"HTTP/1.1 431 Request Header Fields Too Large\r\n"
        b"Connection: close\r\nContent-Length: 0\r\n\r\n"
    )


class _BoundedHeaderReader:
    """Apply an accept-to-headers deadline and independent header caps.

    The deadline is a true wall-clock bound. A socket timeout only limits each
    individual ``recv()``, so delegating a whole line to the underlying
    ``BufferedReader.readline()`` (which loops over many ``recv()`` calls) would
    let a client that drips one byte at a time — each byte arriving before the
    per-recv timeout — hold a worker far past the deadline. Instead we fill from
    small ``read1()`` chunks and re-check the deadline before every chunk, so no
    pacing of bytes can extend a request past ``deadline + HEADER_POLL_SECONDS``.

    Over-read bytes (a chunk can span a line boundary, or reach past the final
    blank line into the body) are held in ``self._buf`` and served by this
    wrapper's own ``readline``/``read``/``read1`` — never pulled out where the
    body read (``rfile.read(length)``) could lose them.
    """

    def __init__(self, reader, connection, deadline):
        self._reader = reader
        self._connection = connection
        self._deadline = deadline
        self._active = True
        self._bytes = 0
        self._lines = 0
        self._saw_request_line = False
        self._buf = bytearray()
        # A real socket fd we can select() on for the deadline wait; None for
        # in-memory test streams that never block.
        self._select_fd = None
        fileno = getattr(connection, "fileno", None)
        if callable(fileno):
            try:
                fd = fileno()
            except (OSError, ValueError):
                fd = None
            if isinstance(fd, int) and fd >= 0:
                self._select_fd = fd

    def _read_bounded_line(self, bounded_size):
        """Return one line (through ``\\n``) or up to ``bounded_size`` bytes,
        enforcing the absolute wall-clock deadline.

        Readiness is awaited with ``select`` rather than a timed-out socket
        read: a socket read that times out latches ``SocketIO`` so every later
        read raises ``OSError: cannot read from timed out object``. ``select``
        lets us re-check the deadline on every poll without poisoning the socket,
        and we only read once data is actually available.
        """
        while True:
            newline = self._buf.find(b"\n")
            if newline != -1 and newline + 1 <= bounded_size:
                end = newline + 1
            elif len(self._buf) >= bounded_size:
                end = bounded_size
            else:
                remaining = self._deadline - time.monotonic()
                if remaining <= 0:
                    raise _HeaderReadTimeout()
                # Wait for readability against the deadline. Already-decrypted
                # TLS bytes are not visible to select on the underlying fd, so
                # read those without waiting. In-memory streams (tests) have no
                # fd and never block, so fall through to the read directly.
                if self._select_fd is not None and not self._ssl_pending():
                    try:
                        ready, _, _ = select.select(
                            [self._select_fd], [], [],
                            max(0.0, min(HEADER_POLL_SECONDS, remaining)),
                        )
                    except (OSError, ValueError):
                        raise _HeaderReadTimeout()
                    if not ready:
                        # Poll expired with no data; re-check the deadline.
                        continue
                # Data is ready. Bound the read by whatever deadline remains so a
                # partial TLS record cannot block past it (a timeout here latches
                # the socket, but we are closing the connection anyway).
                self._connection.settimeout(
                    max(0.001, self._deadline - time.monotonic())
                )
                try:
                    chunk = self._reader.read1(bounded_size - len(self._buf))
                except (socket.timeout, TimeoutError, OSError):
                    raise _HeaderReadTimeout()
                if not chunk:
                    # EOF: return whatever partial line remains (may be b"").
                    line = bytes(self._buf)
                    del self._buf[:]
                    return line
                self._buf.extend(chunk)
                continue
            line = bytes(self._buf[:end])
            del self._buf[:end]
            return line

    def _ssl_pending(self):
        pending = getattr(self._connection, "pending", None)
        if not callable(pending):
            return False
        try:
            return pending() > 0
        except (OSError, ValueError):
            return False

    def readline(self, size=-1):
        if not self._active:
            return self._plain_readline(size)
        capacity = MAX_HTTP_HEADER_BYTES - self._bytes
        bounded_size = capacity + 1
        if size is not None and size >= 0:
            bounded_size = min(size, bounded_size)
        line = self._read_bounded_line(bounded_size)
        self._bytes += len(line)
        if self._bytes > MAX_HTTP_HEADER_BYTES:
            raise _HeaderLimitExceeded()
        if self._saw_request_line:
            if line not in (b"", b"\n", b"\r\n"):
                self._lines += 1
                if self._lines > MAX_HTTP_HEADER_COUNT:
                    raise _HeaderLimitExceeded()
        else:
            self._saw_request_line = True
        return line

    def _plain_readline(self, size):
        if not self._buf:
            return self._reader.readline(size)
        newline = self._buf.find(b"\n")
        if newline != -1:
            end = newline + 1
        elif size is not None and size >= 0 and len(self._buf) >= size:
            end = size
        else:
            data = bytes(self._buf)
            del self._buf[:]
            rest = -1 if size is None or size < 0 else max(0, size - len(data))
            return data + self._reader.readline(rest)
        if size is not None and size >= 0:
            end = min(end, size)
        line = bytes(self._buf[:end])
        del self._buf[:end]
        return line

    def read(self, size=-1):
        if not self._buf:
            return self._reader.read(size)
        if size is None or size < 0:
            data = bytes(self._buf)
            del self._buf[:]
            return data + self._reader.read()
        if size <= len(self._buf):
            data = bytes(self._buf[:size])
            del self._buf[:size]
            return data
        data = bytes(self._buf)
        del self._buf[:]
        return data + (self._reader.read(size - len(data)) or b"")

    def read1(self, size=-1):
        if not self._buf:
            return self._reader.read1(size)
        if size is None or size < 0:
            size = len(self._buf)
        take = min(size, len(self._buf))
        data = bytes(self._buf[:take])
        del self._buf[:take]
        return data

    def finish_headers(self):
        self._active = False
        self._connection.settimeout(REQUEST_TIMEOUT_SECONDS)

    def __getattr__(self, name):
        return getattr(self._reader, name)



PUBLIC_EXPOSURE_NOTIFY_COOLDOWN_SECONDS = 3600
_PUBLIC_EXPOSURE_NOTIFY_LOCK = threading.Lock()
_LAST_PUBLIC_EXPOSURE_NOTIFY_MONO = 0.0


# /metrics also accepts a read-only token, but is handled earlier in do_GET
# (unauthenticated-by-default text/plain content, plus webhook-bearer
# backward compatibility) so it isn't part of this generic session-fallback
# set.
READONLY_TOKEN_GET_PATHS = frozenset({
    "/api/status", "/api/quality", "/api/report", "/api/history", "/api/score",
})

# Selectable windows for the expanded latency-history view (hours).

def parse_kuma(body):
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    hb = data.get("heartbeat") or {}
    if not isinstance(hb, dict):
        hb = {}
    status = hb.get("status")
    monitor_data = data.get("monitor") or {}
    if not isinstance(monitor_data, dict):
        monitor_data = {}
    monitor = monitor_data.get("name") or ""
    msg = data.get("msg") or ""
    return status, (f"{monitor}: {msg}"[:200] if (monitor or msg) else "webhook")


class Handler(BaseHTTPRequestHandler):
    server_version = "Linkmoth"
    sys_version = ""

    def version_string(self):
        return self.server_version

    def setup(self):
        super().setup()
        deadline_getter = getattr(self.server, "current_header_deadline", None)
        deadline = deadline_getter() if deadline_getter else None
        if deadline is None:
            deadline = time.monotonic() + REQUEST_HEADER_DEADLINE_SECONDS
        self.rfile = _BoundedHeaderReader(self.rfile, self.connection, deadline)

    def handle(self):
        try:
            super().handle()
        except _HeaderReadError as exc:
            self.close_connection = True
            try:
                # The header-poll timeout shrinks toward zero as the deadline
                # approaches; give the bounded error response a normal write
                # window so it is actually delivered instead of timing out.
                self.connection.settimeout(REQUEST_TIMEOUT_SECONDS)
                self.wfile.write(exc.response)
                self.wfile.flush()
            except (OSError, ssl.SSLError):
                pass

    def parse_request(self):
        try:
            return super().parse_request()
        finally:
            self.rfile.finish_headers()

    def log_message(self, *a):
        pass

    def _hdrs(self):
        h = {k: v for k, v in self.headers.items()}
        h["Remote-Addr"] = self.client_address[0]
        return h

    def _session(self):
        auth = linkmoth.get_auth()
        sid = auth.session_cookie_value(self)
        return auth.get_session(sid)

    def _require_auth(self):
        auth = linkmoth.get_auth()
        session = self._session()
        if auth.is_fully_authenticated(session):
            return True, session
        return False, session

    def _require_csrf(self, session):
        return linkmoth.get_auth().verify_csrf(session, self._hdrs())

    def _require_webhook(self):
        return linkmoth.get_auth().verify_webhook_bearer(
            self.headers.get("Authorization")
        )

    def _reject_if_publicly_exposed(self):
        """Refuse any request whose direct peer isn't LAN/loopback/trusted-proxy.

        Linkmoth is documented as LAN-only, but an accidental router
        port-forward would otherwise still be served normally. This is a
        second, independent guard: every request is checked, before routing,
        against the actual TCP peer address. True means the request was
        rejected and the caller must return immediately.
        """
        if _peer_is_trusted_local(self.client_address[0]):
            return False
        auth = linkmoth.get_auth()
        auth.audit_event(
            "public_exposure_blocked", self._hdrs(), self.client_address[0],
        )
        if _public_exposure_notify_allowed():
            try:
                from linkmoth_webhooks import build_event_context, emit_event
                ctx = build_event_context(
                    "public_exposure_detected",
                    verdict={
                        "title": "Linkmoth rejected a public-internet connection",
                        "explain": (
                            "Linkmoth is a LAN-only tool and just refused a "
                            "request from a public IP address. If this wasn't "
                            "intentional, check your router's port-forwarding "
                            "rules."
                        ),
                        "severity": "warn",
                    },
                )
                emit_event(db, "public_exposure_detected", ctx)
            except Exception:
                pass
        self._send(403, {
            "error": (
                "Linkmoth is a LAN-only tool and does not accept connections "
                "from the public internet. If this wasn't intentional, check "
                "your router's port-forwarding rules."
            ),
        })
        return True

    def _begin_auth_verification(self):
        """Reject excess expensive-hash work without queueing handler threads."""
        if AUTH_VERIFY_SLOTS.acquire(blocking=False):
            return True
        self._send(
            503,
            {"error": "authentication service busy", "retry_after": 1},
            extra_headers=[("Retry-After", "1")],
        )
        return False

    def _send(self, code, body, ctype="application/json", extra_headers=None,
              csp_nonce=None):
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Strict-Transport-Security",
            "max-age=31536000",
        )
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        )
        if ctype.startswith("text/html"):
            # The dashboard's single <script> and <style> block both carry this
            # per-response nonce; there are no inline style= attributes, so the
            # policy no longer needs style-src 'unsafe-inline'.
            src = f"'nonce-{csp_nonce}'" if csp_nonce else "'unsafe-inline'"
            self.send_header(
                "Content-Security-Policy",
                f"default-src 'none'; style-src {src}; "
                f"script-src {src}; connect-src 'self'; img-src 'self'; "
                "worker-src 'self'; manifest-src 'self'; "
                "base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            )
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _send_file(self, code, file_path, ctype, extra_headers=None, chunk_size=262144):
        """Like _send, but streams `file_path`'s contents in chunks instead
        of holding the whole body in memory -- used for the backup archive,
        which can be multiple megabytes on a long-lived install."""
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(os.path.getsize(file_path)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        )
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        with open(file_path, "rb") as f:
            shutil.copyfileobj(f, self.wfile, chunk_size)

    def _send_json(self, code, body, session=None, set_cookie=None, clear_cookie=False):
        extra = []
        auth = linkmoth.get_auth()
        if set_cookie:
            extra.append((
                "Set-Cookie",
                auth.session_cookie_header(
                    set_cookie["cookie_id"], set_cookie["expires"]
                ),
            ))
        if clear_cookie:
            extra.append((
                "Set-Cookie",
                auth.clear_session_cookie_header(),
            ))
        self._send(code, body, extra_headers=extra or None)

    def _serve_dashboard(self):
        page = (BASE / "dashboard.html").read_bytes()
        nonce = secrets.token_urlsafe(16)
        nonce_attr = b' nonce="' + nonce.encode("ascii") + b'"'
        page = page.replace(b"<script>", b"<script" + nonce_attr + b">", 1)
        page = page.replace(b"<style>", b"<style" + nonce_attr + b">", 1)
        self._send(200, page, "text/html; charset=utf-8", csp_nonce=nonce)

    def _read_body(self):
        if self.headers.get("Transfer-Encoding"):
            self._send(400, {"error": "transfer encoding is not supported"})
            return None
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return b""
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            self._send(400, {"error": "invalid content length"})
            return None
        if length < 0:
            self._send(400, {"error": "invalid content length"})
            return None
        if length > MAX_REQUEST_BODY:
            self._send(413, {"error": "request body too large"})
            return None
        return self.rfile.read(length) if length else b""

    def _json_object(self, body):
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            raise ValueError("expected a JSON object") from None
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        return data

    def _json_object_safe(self, body):
        """Lenient parse — returns {} on missing/invalid input (no raise)."""
        try:
            data = json.loads(body) if body else {}
        except (json.JSONDecodeError, TypeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _require_same_origin_json(self):
        """Block form-based cross-site attempts before they affect auth state."""
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0]
        if content_type.strip().lower() != "application/json":
            self._send(415, {"error": "application/json required"})
            return False
        if (self.headers.get("Sec-Fetch-Site") or "").strip().lower() == "cross-site":
            self._send(403, {"error": "cross-site authentication request rejected"})
            return False
        origin = (self.headers.get("Origin") or "").strip()
        if not origin:
            return True
        try:
            parsed = urlparse(origin)
        except ValueError:
            self._send(403, {"error": "cross-site authentication request rejected"})
            return False
        expected_scheme = (
            "https" if isinstance(self.connection, ssl.SSLSocket) else "http"
        )
        expected_host = (self.headers.get("Host") or "").strip().lower()
        if (
            parsed.scheme.lower() != expected_scheme
            or parsed.netloc.lower() != expected_host
            or parsed.path not in ("", "/")
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            self._send(403, {"error": "cross-site authentication request rejected"})
            return False
        return True

    def _send_device_exception(self, exc):
        from linkmoth_devices import (
            DeviceBusy, DeviceLimitReached, DeviceNotFound,
        )
        if isinstance(exc, DeviceNotFound):
            self._send(404, {"error": str(exc)})
        elif isinstance(exc, (DeviceBusy, DeviceLimitReached)):
            self._send(409, {"error": str(exc)})
        elif isinstance(exc, ValueError):
            self._send(400, {"error": str(exc)})
        elif isinstance(exc, sqlite3.OperationalError) and (
            "locked" in str(exc).lower() or "busy" in str(exc).lower()
        ):
            self._send(
                503, {"error": "database temporarily busy", "retry_after": 1},
                extra_headers=[("Retry-After", "1")],
            )
        else:
            print(f"device API error: {exc}", file=sys.stderr, flush=True)
            self._send(500, {"error": "device operation failed"})

    def _send_webhook_exception(self, exc):
        from linkmoth_webhooks import WebhookLimitReached, WebhookNotFound
        if isinstance(exc, WebhookNotFound):
            self._send(404, {"error": str(exc)})
        elif isinstance(exc, WebhookLimitReached):
            self._send(409, {"error": str(exc)})
        elif isinstance(exc, ValueError):
            self._send(400, {"error": str(exc)})
        elif isinstance(exc, sqlite3.OperationalError) and (
            "locked" in str(exc).lower() or "busy" in str(exc).lower()
        ):
            self._send(
                503, {"error": "database temporarily busy", "retry_after": 1},
                extra_headers=[("Retry-After", "1")],
            )
        else:
            print(f"webhook API error: {exc}", file=sys.stderr, flush=True)
            self._send(500, {"error": "webhook operation failed"})

    def _handle_auth_login(self, body):
        if not self._require_same_origin_json():
            return
        auth = linkmoth.get_auth()
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        password = str(data.get("password") or "")
        allowed, retry_after = auth.login_allowed(self._hdrs())
        if not allowed:
            auth.audit_event("login_rate_limited", self._hdrs())
            self._send(
                429, {"error": "too many attempts", "retry_after": retry_after},
                extra_headers=[("Retry-After", str(retry_after))],
            )
            return
        if not self._begin_auth_verification():
            return
        try:
            if not auth.has_password():
                self._send(409, {"error": "complete onboarding first"})
                return
            if not auth.verify_login_password(password):
                auth.record_login_failure(self._hdrs())
                auth.audit_event(
                    "login_failure", self._hdrs(), "invalid credentials"
                )
                self._send(401, {"error": "invalid credentials"})
                return
            totp_ok = not auth.totp_enabled
            if totp_ok:
                auth.clear_login_failures(self._hdrs())
            sess = auth.create_session(totp_verified=totp_ok)
        finally:
            AUTH_VERIFY_SLOTS.release()
        auth.audit_event(
            "login_success",
            self._hdrs(),
            "password only" if totp_ok else "password accepted; TOTP pending",
        )
        status = auth.public_status(sess)
        self._send_json(200, {"ok": True, **status}, set_cookie=sess)

    def _handle_auth_setup(self, body):
        if not self._require_same_origin_json():
            return
        auth = linkmoth.get_auth()
        if not auth.onboarding_required():
            self._send(409, {"error": "onboarding is already complete"})
            return
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        token = str(data.get("token") or "").strip()
        password = str(data.get("password") or "")
        confirm = str(data.get("confirm") or "")
        if password != confirm:
            self._send(400, {"error": "passwords do not match"})
            return
        allowed, retry_after = auth.login_allowed(self._hdrs())
        if not allowed:
            auth.audit_event("onboarding_rate_limited", self._hdrs())
            self._send(
                429, {"error": "too many attempts", "retry_after": retry_after},
                extra_headers=[("Retry-After", str(retry_after))],
            )
            return
        if not self._begin_auth_verification():
            return
        try:
            try:
                auth.complete_onboarding(token, password)
            except PermissionError:
                auth.record_login_failure(self._hdrs())
                auth.audit_event(
                    "onboarding_failure", self._hdrs(), "invalid bootstrap token"
                )
                self._send(401, {"error": "invalid or expired setup token"})
                return
            except ValueError as e:
                self._send(400, {"error": str(e)})
                return
            except RuntimeError as e:
                self._send(409, {"error": str(e)})
                return
            auth.clear_login_failures(self._hdrs())
            sess = auth.create_session(totp_verified=True)
        finally:
            AUTH_VERIFY_SLOTS.release()
        status = auth.public_status(sess)
        self._send_json(201, {"ok": True, **status}, set_cookie=sess)

    def _handle_auth_totp(self, body, session):
        auth = linkmoth.get_auth()
        if not session:
            self._send(401, {"error": "login required"})
            return
        if not self._require_csrf(session):
            auth.audit_event("csrf_rejected", self._hdrs(), "TOTP")
            self._send(403, {"error": "csrf required"})
            return
        if not auth.totp_enabled:
            self._send(400, {"error": "totp not enabled"})
            return
        if session.get("totp_verified"):
            self._send(200, auth.public_status(session))
            return
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        code = str(data.get("code") or "")
        if not self._begin_auth_verification():
            return
        try:
            allowed, retry_after = auth.login_allowed(self._hdrs())
            if not allowed:
                auth.audit_event("totp_rate_limited", self._hdrs())
                self._send(
                    429,
                    {"error": "too many attempts", "retry_after": retry_after},
                )
                return
            method = auth.verify_second_factor_method(code)
            if not method:
                auth.record_login_failure(self._hdrs())
                auth.audit_event(
                    "totp_failure", self._hdrs(), "invalid second factor"
                )
                self._send(401, {"error": "invalid code"})
                return
            auth.clear_login_failures(self._hdrs())
            fingerprint = auth.upgrade_session_totp(session["id"])
        finally:
            AUTH_VERIFY_SLOTS.release()
        if not fingerprint:
            self._send(401, {"error": "session expired"})
            return
        session = dict(session)
        session["totp_verified"] = 1
        session["totp_fingerprint"] = fingerprint
        auth.audit_event(
            "recovery_code_used" if method == "recovery" else "totp_success",
            self._hdrs(),
            "second factor accepted",
        )
        self._send_json(200, {"ok": True, **auth.public_status(session)})

    def _handle_auth_logout(self, session):
        auth = linkmoth.get_auth()
        if session:
            if not self._require_csrf(session):
                auth.audit_event("csrf_rejected", self._hdrs(), "logout")
                self._send(403, {"error": "csrf required"})
                return
            auth.audit_event("logout", self._hdrs(), "session invalidated")
            auth.destroy_session(session["id"])
        self._send_json(200, {"ok": True}, clear_cookie=True)

    def _handle_security_post(self, path, body):
        """Auth-management routes (already behind auth + CSRF). Secret/password
        checks are rate-limited with the same slots + lockout as login, and
        never echo secrets on error."""
        auth = linkmoth.get_auth()
        data = self._json_object_safe(body)
        try:
            if path == "/api/auth/totp/setup":
                # No secret verification here — just stage a pending enrollment.
                # Recovery codes are withheld until the user activates.
                secret, uri = auth.begin_totp_setup()
                self._send(200, {"secret": secret, "otpauth_uri": uri})
                return
            # The remaining routes verify a password or code → rate-limit them.
            if not self._begin_auth_verification():
                return
            try:
                allowed, retry_after = auth.login_allowed(self._hdrs())
                if not allowed:
                    auth.audit_event("security_rate_limited", self._hdrs(), path)
                    self._send(429, {"error": "too many attempts",
                                     "retry_after": retry_after})
                    return
                if path == "/api/auth/change-password":
                    auth.change_password(
                        str(data.get("current") or ""), str(data.get("new") or ""))
                    result = {"ok": True, "logged_out": True}
                elif path == "/api/auth/totp/activate":
                    codes = auth.activate_totp(str(data.get("code") or ""))
                    result = {"ok": True, "totp_enabled": True,
                              "logged_out": True, "recovery_codes": codes}
                elif path == "/api/auth/totp/disable":
                    auth.disable_totp_verified(
                        str(data.get("password") or data.get("code") or ""))
                    result = {"ok": True, "totp_enabled": False, "logged_out": True}
                elif path == "/api/auth/totp/recovery-codes":
                    codes = auth.regenerate_recovery_codes(
                        str(data.get("password") or ""))
                    result = {"ok": True, "recovery_codes": codes}
                else:
                    self._send(404, {"error": "not found"})
                    return
                auth.clear_login_failures(self._hdrs())
            finally:
                AUTH_VERIFY_SLOTS.release()
            self._send(200, result)
        except PermissionError as exc:
            auth.record_login_failure(self._hdrs())
            auth.audit_event("security_reauth_failed", self._hdrs(), path)
            self._send(401, {"error": str(exc)})
        except ValueError as exc:
            if path == "/api/auth/totp/activate":
                auth.record_login_failure(self._hdrs())
                auth.audit_event("totp_setup_failed", self._hdrs(), "code rejected")
            self._send(400, {"error": str(exc)})

    def _security_posture(self, auth):
        ac = CFG.get("auth") or {}
        bind_addr = CFG.get("bind", "127.0.0.1")
        tunnels = [
            i for i in bind_exposure_risk(bind_addr) if i["kind"] == "tunnel"
        ]
        recent_public = [
            e for e in auth.audit_events(limit=200)
            if e["event"] == "public_exposure_blocked"
        ]
        return {
            "totp_enabled": auth.totp_enabled,
            "recovery_codes_remaining": auth.recovery_codes_remaining(),
            "session_idle_seconds": int(ac.get("session_idle_seconds", 1800)),
            "session_ttl_seconds": int(ac.get("session_ttl_seconds", 86400)),
            "tls": True,
            "bind": bind_addr,
            "tunnel_exposure": [
                {"iface": i["iface"], "address": i["address"]} for i in tunnels
            ],
            "public_exposure_recent": {
                "count": len(recent_public),
                "last_ts": recent_public[0]["ts"] if recent_public else None,
            },
            "internet_note": (
                "Linkmoth does not create cloud access, tunnels, or router "
                "port forwards. It is intended for local-network access "
                "only."
            ),
            "database": db_maintenance_info(),
        }

    def do_GET(self):
        if self._reject_if_publicly_exposed():
            return
        url = urlparse(self.path)
        qs = parse_qs(url.query)
        auth = linkmoth.get_auth()
        if url.path == "/health":
            self._send(200, {"ok": True})
            return
        if url.path == "/linkmoth.svg":
            if ICON_PATH.is_file():
                self._send(200, ICON_PATH.read_bytes(), "image/svg+xml")
            else:
                self._send(404, {"error": "not found"})
            return
        if url.path == "/linkmoth-white.svg":
            if WHITE_LOGO_PATH.is_file():
                self._send(200, WHITE_LOGO_PATH.read_bytes(), "image/svg+xml")
            else:
                self._send(404, {"error": "not found"})
            return
        if url.path == "/linkmoth-mark-white.svg":
            if WHITE_MARK_PATH.is_file():
                self._send(200, WHITE_MARK_PATH.read_bytes(), "image/svg+xml")
            else:
                self._send(404, {"error": "not found"})
            return
        if url.path == "/linkmoth-maskable.svg":
            if MASKABLE_ICON_PATH.is_file():
                self._send(200, MASKABLE_ICON_PATH.read_bytes(), "image/svg+xml")
            else:
                self._send(404, {"error": "not found"})
            return
        if url.path in PNG_ICON_PATHS:
            icon = PNG_ICON_PATHS[url.path]
            if icon.is_file():
                self._send(200, icon.read_bytes(), "image/png")
            else:
                self._send(404, {"error": "not found"})
            return
        if url.path in ("/favicon.ico", "/linkmoth-white.ico"):
            if FAVICON_PATH.is_file():
                self._send(200, FAVICON_PATH.read_bytes(), "image/x-icon")
            elif ICON_PATH.is_file():
                self._send(200, ICON_PATH.read_bytes(), "image/svg+xml")
            else:
                self._send(404, {"error": "not found"})
            return
        if url.path in ("/ca.crt", "/linkmoth-ca.crt"):
            # Unauthenticated so a fresh device can fetch the CA to trust it.
            ca = _ca_cert_path()
            if ca and ca.is_file():
                self._send(
                    200, ca.read_bytes(), "application/x-x509-ca-cert",
                    extra_headers=[(
                        "Content-Disposition",
                        'attachment; filename="linkmoth-ca.crt"',
                    )],
                )
            else:
                self._send(404, {"error": "CA certificate not found"})
            return
        if url.path == "/sw.js":
            if SW_PATH.is_file():
                self._send(200, SW_PATH.read_bytes(), "application/javascript; charset=utf-8")
            else:
                self._send(404, {"error": "not found"})
            return
        if url.path == "/manifest.webmanifest":
            if MANIFEST_PATH.is_file():
                self._send(200, MANIFEST_PATH.read_bytes(),
                            "application/manifest+json; charset=utf-8")
            else:
                self._send(404, {"error": "not found"})
            return
        if url.path == "/api/auth/status":
            session = self._session()
            self._send(200, linkmoth.get_auth().public_status(session))
            return
        if url.path == "/trigger":
            if not self._require_webhook():
                self._send(401, {"error": "webhook authorization required"})
                return
            linkmoth.ENGINE.trigger("manual-get", "GET /trigger")
            self._send(200, {"triggered": True})
            return
        if url.path == "/metrics":
            # Prometheus can't hold a browser session. Accept a read-only
            # token first — it's strictly less powerful than the webhook
            # bearer (it can never reach /trigger or the inbound webhook
            # routes to create diagnostic activity), so a scraper only
            # needs least privilege here. The webhook bearer is still
            # accepted for configs set up before the read-only token type
            # existed.
            if not (
                auth.verify_readonly_token(self.headers.get("Authorization"))
                or self._require_webhook()
            ):
                self._send(401, {"error": "read-only token or webhook authorization required"})
                return
            self._send(
                200, prometheus_metrics().encode("utf-8"),
                "text/plain; version=0.0.4; charset=utf-8",
            )
            return
        ok, session = self._require_auth()
        if not ok:
            # Read-only API tokens are accepted ONLY on these GET endpoints:
            # current status/quality and the accountability report. They can
            # never reach settings, auth, devices, webhooks, or any POST.
            if url.path in READONLY_TOKEN_GET_PATHS and auth.verify_readonly_token(
                self.headers.get("Authorization")
            ):
                session = None
            # /setup is an alias for the dashboard; the UI shows the onboarding
            # gate when a setup code is required, so a beginner can land there
            # straight from the installer's printed address.
            elif url.path in ("/", "/index.html", "/setup"):
                self._serve_dashboard()
                return
            else:
                self._send(401, {"error": "authentication required"})
                return
        if url.path in ("/", "/index.html", "/setup"):
            self._serve_dashboard()
        elif url.path == "/api/status":
            payload = linkmoth.ENGINE.status()
            payload["auth"] = auth.public_status(session)
            payload["quality"] = quality_summary(limit=120)
            payload["score"] = connection_score()
            payload["wifi_note"] = wifi_wired_differential(
                linkmoth.ENGINE.last_run_checks()
            )
            self._send(200, payload)
        elif url.path == "/api/score":
            try:
                days = int(qs.get("days", ["30"])[0])
            except (ValueError, TypeError):
                days = 30
            self._send(200, connection_score(days))
        elif url.path == "/api/auth/audit":
            try:
                limit = int(qs.get("limit", ["50"])[0])
            except (ValueError, TypeError):
                limit = 50
            limit = max(20, min(200, limit))  # aggressive clamp; newest-first in the query
            self._send(200, {"events": auth.audit_events(limit)})
        elif url.path == "/api/auth/tokens":
            self._send(200, {"tokens": auth.list_readonly_tokens()})
        elif url.path == "/api/evidence-export":
            tier = str(qs.get("tier", ["detailed"])[0])
            try:
                exported = linkmoth.ENGINE.evidence_export(tier)
            except ValueError:
                self._send(400, {"error": "tier must be detailed, readable, or support-safe"})
                return
            auth.audit_event("evidence_export", self._hdrs(), tier)
            if tier == "readable":
                self._send(200, exported, "text/plain; charset=utf-8")
            else:
                self._send(200, exported)
        elif url.path == "/api/backup":
            fd, tmp_name = tempfile.mkstemp(prefix="linkmoth-backup-", suffix=".zip")
            os.close(fd)
            tmp_path = Path(tmp_name)
            try:
                try:
                    build_backup_archive_to_path(tmp_path, db, _export_settings, VERSION)
                except BackupInProgress:
                    self._send(429, {
                        "error": "a backup is already being created; try again shortly",
                    })
                    return
                auth.audit_event("backup_downloaded", self._hdrs(), "")
                filename = f"linkmoth-backup-{time.strftime('%Y%m%d-%H%M%S')}.zip"
                self._send_file(
                    200, tmp_path, "application/zip",
                    extra_headers=[(
                        "Content-Disposition", f'attachment; filename="{filename}"',
                    )],
                )
            finally:
                tmp_path.unlink(missing_ok=True)
        elif url.path == "/api/auth/security":
            self._send(200, self._security_posture(auth))
        elif url.path == "/api/devices":
            self._send(200, {
                "devices": linkmoth.DEVICES.list_devices(),
                **linkmoth.DEVICES.api_metadata(),
            })
        elif re.fullmatch(
            r"/api/devices/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}/history",
            url.path,
        ):
            device_id = url.path.split("/")[3]
            try:
                limit = int(qs.get("limit", ["100"])[0])
                self._send(200, {
                    "device": linkmoth.DEVICES.get_device(device_id),
                    "history": linkmoth.DEVICES.history(device_id, limit),
                })
            except Exception as exc:
                self._send_device_exception(exc)
        elif url.path == "/api/webhooks":
            from linkmoth_webhooks import api_metadata, list_webhooks
            self._send(200, {"webhooks": list_webhooks(db), **api_metadata()})
        elif url.path == "/api/webhooks/inbound-info":
            secret = auth.ensure_webhook_secret()
            try:
                host = _safe_request_host(self.headers.get("Host"))
            except ValueError:
                port = int(CFG.get("port", 8686))
                host = "linkmoth.local" if port == 443 else f"linkmoth.local:{port}"
            inbound_url = f"https://{host}/api/webhooks/inbound"
            curl_example = (
                f"curl -k -X POST {shlex.quote(inbound_url)} \\\n"
                f"  -H {shlex.quote(f'Authorization: Bearer {secret}')} \\\n"
                "  -H \"Content-Type: application/json\" \\\n"
                "  -d '{\"source\":\"test\",\"event\":\"down\","
                "\"monitor\":\"WAN\",\"message\":\"manual test\"}'"
            )
            self._send(200, {
                "url": inbound_url,
                "secret": secret,
                "curl_example": curl_example,
            })
        elif url.path == "/api/incidents":
            try:
                limit = int(qs.get("limit", ["50"])[0])
            except ValueError:
                limit = 50
            code = (qs.get("code", [None])[0]) or None
            payload = {"incidents": linkmoth.ENGINE.incidents_list(limit, code)}
            if code:
                payload["pattern"] = linkmoth.ENGINE.patterns(code=code)
            self._send(200, payload)
        elif url.path == "/api/incident":
            ref = (qs.get("ref", [None])[0] or "").strip() or None
            if ref:
                detail = linkmoth.ENGINE.incident_detail(ref=ref)
            else:
                try:
                    inc_id = int(qs.get("id", ["0"])[0])
                except ValueError:
                    inc_id = 0
                detail = linkmoth.ENGINE.incident_detail(inc_id=inc_id)
            if detail is None:
                self._send(404, {"error": "no such incident"})
            else:
                self._send(200, detail)
        elif url.path == "/api/quality":
            try:
                limit = int(qs.get("limit", ["288"])[0])
            except ValueError:
                limit = 288
            limit = max(1, min(2000, limit))
            self._send(200, quality_summary(limit))
        elif url.path == "/api/history":
            try:
                hours = int(qs.get("hours", ["24"])[0])
            except ValueError:
                hours = 24
            self._send(200, linkmoth.ENGINE.history_range(hours))
        elif url.path == "/api/report":
            try:
                days = int(qs.get("days", ["30"])[0])
            except ValueError:
                days = 30
            self._send(200, linkmoth.ENGINE.isp_report(days))
        elif url.path == "/api/report.csv":
            try:
                days = int(qs.get("days", ["30"])[0])
            except ValueError:
                days = 30
            csv_text = isp_report_csv(linkmoth.ENGINE.isp_report(days))
            self._send(200, csv_text.encode("utf-8"), "text/csv; charset=utf-8")
        elif url.path == "/api/push/vapid-key":
            from linkmoth_push import push_available, vapid_public_key_b64
            if not push_available(STATE_DIR):
                self._send(503, {"error": "browser push unavailable — run: sudo bash install.sh --with-push"})
                return
            key = vapid_public_key_b64(STATE_DIR)
            if not key:
                self._send(503, {"error": "could not load VAPID public key"})
                return
            self._send(200, {"publicKey": key})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self._reject_if_publicly_exposed():
            return
        body = self._read_body()
        if body is None:
            return
        path = urlparse(self.path).path
        auth = linkmoth.get_auth()
        if path == "/api/auth/setup":
            self._handle_auth_setup(body)
            return
        if path == "/api/auth/login":
            self._handle_auth_login(body)
            return
        if path == "/api/auth/totp":
            session = self._session()
            self._handle_auth_totp(body, session)
            return
        if path == "/trigger":
            if not self._require_webhook():
                self._send(401, {"error": "webhook authorization required"})
                return
            status, detail = parse_kuma(body)
            if status == 1:
                inc = linkmoth.ENGINE.open_incident()
                if inc:
                    linkmoth.ENGINE.trigger("kuma-up", detail)
                self._send(200, {"noted": "recovery"})
            else:
                linkmoth.ENGINE.trigger("kuma-down" if status == 0 else "webhook", detail)
                self._send(200, {"triggered": True})
            return
        if path == "/api/webhooks/kuma":
            if not self._require_webhook():
                self._send(401, {"error": "webhook authorization required"})
                return
            from linkmoth_kuma_proxy import handle_kuma_webhook
            result = handle_kuma_webhook(body, linkmoth.ENGINE, CFG, db)
            self._send(200, result)
            return
        if path == "/api/webhooks/inbound":
            if not self._require_webhook():
                self._send(401, {"error": "webhook authorization required"})
                return
            from linkmoth_kuma_proxy import handle_inbound_webhook
            result = handle_inbound_webhook(body, linkmoth.ENGINE, CFG, db)
            self._send(200, result)
            return
        if path == "/api/auth/logout":
            self._handle_auth_logout(self._session())
            return
        ok, session = self._require_auth()
        if not ok:
            self._send(401, {"error": "authentication required"})
            return
        if not self._require_csrf(session):
            auth.audit_event("csrf_rejected", self._hdrs(), path)
            self._send(403, {"error": "csrf required"})
            return
        if path in (
            "/api/auth/change-password", "/api/auth/totp/setup",
            "/api/auth/totp/activate", "/api/auth/totp/disable",
            "/api/auth/totp/recovery-codes",
        ):
            self._handle_security_post(path, body)
            return
        if path == "/api/devices":
            try:
                created = linkmoth.DEVICES.create_device(self._json_object(body))
                auth.audit_event(
                    "device_created", self._hdrs(),
                    f"{created['id']} {created['address']}",
                )
                self._send(201, {"device": created})
            except Exception as exc:
                self._send_device_exception(exc)
        elif path == "/api/webhooks":
            from linkmoth_webhooks import create_webhook
            try:
                created = create_webhook(db, self._json_object(body))
                auth.audit_event(
                    "webhook_created", self._hdrs(),
                    f"{created['id']} {created['preset']}",
                )
                self._send(201, {"webhook": created})
            except Exception as exc:
                self._send_webhook_exception(exc)
        elif path == "/api/fire-drill":
            state = str(self._json_object_safe(body).get("state") or "")
            if state not in ("seen", "completed"):
                self._send(400, {"error": "state must be seen or completed"})
                return
            _set_meta("fire_drill_seen", "1")
            if state == "completed":
                _set_meta("fire_drill_completed", "1")
            auth.audit_event("fire_drill_" + state, self._hdrs(), "")
            self._send(200, fire_drill_status())
        elif re.fullmatch(
            r"/api/webhooks/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}/test",
            path,
        ):
            from linkmoth_webhooks import send_test
            webhook_id = path.split("/")[3]
            kind = str(self._json_object_safe(body).get("kind") or "fault")
            try:
                result = send_test(db, webhook_id, kind)
                self._send(200, result)
            except Exception as exc:
                self._send_webhook_exception(exc)
        elif path == "/api/incident/false-alarm":
            ref = str(self._json_object_safe(body).get("ref") or "").strip() or None
            ok, result = linkmoth.ENGINE.mark_false_alarm(ref)
            if ok:
                auth.audit_event(
                    "incident_false_alarm", self._hdrs(),
                    str(result.get("ref") or result.get("id")),
                )
                self._send(200, {"marked": True, "incident": result})
            else:
                self._send(409, {"error": result})
        elif re.fullmatch(
            r"/api/devices/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}/run",
            path,
        ):
            device_id = path.split("/")[3]
            try:
                result = linkmoth.DEVICES.run_device(device_id, source="manual")
                self._send(200, {
                    "result": result,
                    "device": linkmoth.DEVICES.get_device(device_id),
                })
            except Exception as exc:
                self._send_device_exception(exc)
        elif path == "/api/diagnose":
            def one_shot():
                v = linkmoth.ENGINE.diagnose_once()
                if v and v["severity"] != "ok" and linkmoth.ENGINE.open_incident() is None:
                    linkmoth.ENGINE.trigger("dashboard", f"manual run found: {v['code']}")
            threading.Thread(target=one_shot, daemon=True).start()
            self._send(200, {"started": True})
        elif path == "/api/quality/load-test":
            try:
                _validate_load_url(quality_config().get("load_test_url"))
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return
            if not _LOAD_TEST_LOCK.acquire(blocking=False):
                self._send(409, {"error": "a load test is already running"})
                return

            def run_and_release():
                try:
                    run_load_test()
                except Exception as exc:
                    print(f"load test failed: {exc}", file=sys.stderr, flush=True)
                finally:
                    _LOAD_TEST_LOCK.release()

            threading.Thread(target=run_and_release, daemon=True).start()
            self._send(200, {"started": True})
        elif path == "/api/update/check":
            try:
                result = manual_update_check()
            except ValueError as exc:
                # The audit deliberately records no response content or network
                # identifiers: it is only evidence that a manual check was tried.
                auth.audit_event("manual_update_check", self._hdrs(), "failed")
                self._send(503, {"error": str(exc)})
            else:
                auth.audit_event("manual_update_check", self._hdrs(), "update" if result["update_available"] else "current")
                self._send(200, result)
        elif path == "/api/verify":
            remaining = linkmoth.ENGINE.verify_cooldown_remaining()
            if remaining > 0:
                self._send(429, {"error": "wait a few seconds and try again",
                                 "retry_after": round(remaining)})
                return
            before = {c["id"]: c for c in linkmoth.ENGINE.last_run_checks()}
            result = linkmoth.ENGINE.verify_fix()
            if result is None:
                self._send(409, {"error": "a diagnosis is already running"})
                return
            v, after_checks = result
            fixed, still_bad, improved, regressed = [], [], [], []

            def evidence_state(check):
                if check.get("state"):
                    return check["state"]
                if check.get("ok") is None:
                    return "skipped"
                return "failed" if check.get("ok") is False else "passed"

            for c in after_checks:
                b = before.get(c["id"])
                if c["ok"] is False:
                    still_bad.append(c["id"])
                elif b is not None and b.get("ok") is False and c["ok"] is not False:
                    fixed.append(c["id"])
                elif b is not None:
                    old_state = evidence_state(b)
                    new_state = evidence_state(c)
                    if old_state in ("partial", "degraded") and new_state == "passed":
                        improved.append(c["id"])
                    elif old_state == "passed" and new_state in ("partial", "degraded"):
                        regressed.append(c["id"])

            labels = {c["id"]: c.get("label") or c["id"] for c in after_checks}
            human = lambda ids: [labels.get(cid, cid) for cid in ids]
            self._send(200, {"verdict": v, "checks": after_checks,
                             "fixed": fixed, "still_bad": still_bad,
                             "improved": improved, "regressed": regressed,
                             "fixed_labels": human(fixed),
                             "still_bad_labels": human(still_bad),
                             "improved_labels": human(improved),
                             "regressed_labels": human(regressed)})
        elif path == "/api/auth/tokens":
            try:
                data = json.loads(body) if body else {}
                if not isinstance(data, dict):
                    raise ValueError
            except (json.JSONDecodeError, ValueError):
                self._send(400, {"error": "expected a JSON object"})
                return
            try:
                value, entry = auth.create_readonly_token(data.get("name"))
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return
            # The plain token value appears in this response only; after
            # this, only its hash exists server-side.
            self._send(200, {"token": value, **entry})
        elif path == "/api/settings":
            try:
                data = json.loads(body)
                if not isinstance(data, dict):
                    raise ValueError
            except (json.JSONDecodeError, ValueError):
                self._send(400, {"errors": {"_body": "expected a JSON object"}})
                return
            if data.get("action") == "vacuum":
                ok, result = vacuum_database(linkmoth.ENGINE)
                if ok:
                    auth.audit_event(
                        "db_vacuum",
                        self._hdrs(),
                        f"reclaimed {result.get('bytes_reclaimed', 0)} bytes",
                    )
                    self._send(200, {
                        "vacuum": True,
                        "database": db_maintenance_info(),
                        **result,
                    })
                elif result.get("error", "").startswith("diagnosis in progress"):
                    self._send(409, {"vacuum": False, **result})
                else:
                    self._send(500, {"vacuum": False, **result})
                return
            saved, result = apply_settings(data)
            if saved:
                self._send(200, {"saved": True, "settings": result})
            else:
                self._send(400, {"errors": result})
        elif path == "/api/incident/recheck":
            v, err = linkmoth.ENGINE.recheck_open_incident()
            if err:
                self._send(409, {"error": err})
            else:
                self._send(200, {"verdict": v})
        elif path == "/api/incident/close":
            ok, result = linkmoth.ENGINE.close_open_incident()
            if ok:
                self._send(200, {"closed": True, "incident": result})
            else:
                self._send(409, {"error": result})
        elif path == "/api/push/subscribe":
            from linkmoth_push import push_available, save_subscription
            if not push_available(STATE_DIR):
                self._send(503, {"error": "browser push unavailable — run: sudo bash install.sh --with-push"})
                return
            try:
                sub = json.loads(body)
                if not isinstance(sub, dict):
                    raise ValueError
            except (json.JSONDecodeError, ValueError):
                self._send(400, {"error": "expected push subscription JSON"})
                return
            try:
                save_subscription(db, sub, self.headers.get("User-Agent", ""))
            except ValueError as e:
                self._send(400, {"error": str(e)})
                return
            self._send(200, {"subscribed": True})
        elif path == "/api/push/unsubscribe":
            try:
                sub = json.loads(body)
                endpoint = str((sub or {}).get("endpoint") or "").strip()
            except (json.JSONDecodeError, ValueError):
                self._send(400, {"error": "expected subscription JSON with endpoint"})
                return
            if not endpoint:
                self._send(400, {"error": "endpoint required"})
                return
            from linkmoth_push import delete_subscription
            delete_subscription(db, endpoint)
            self._send(200, {"unsubscribed": True})
        else:
            self._send(404, {"error": "not found"})

    def do_PUT(self):
        if self._reject_if_publicly_exposed():
            return
        body = self._read_body()
        if body is None:
            return
        path = urlparse(self.path).path
        ok, session = self._require_auth()
        if not ok:
            self._send(401, {"error": "authentication required"})
            return
        if not self._require_csrf(session):
            linkmoth.get_auth().audit_event("csrf_rejected", self._hdrs(), path)
            self._send(403, {"error": "csrf required"})
            return
        webhook_match = re.fullmatch(
            r"/api/webhooks/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12})",
            path,
        )
        if webhook_match:
            from linkmoth_webhooks import update_webhook
            try:
                updated = update_webhook(
                    db, webhook_match.group(1), self._json_object(body)
                )
                linkmoth.get_auth().audit_event(
                    "webhook_updated", self._hdrs(),
                    f"{updated['id']} {updated['preset']}",
                )
                self._send(200, {"webhook": updated})
            except Exception as exc:
                self._send_webhook_exception(exc)
            return
        match = re.fullmatch(
            r"/api/devices/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12})",
            path,
        )
        if not match:
            self._send(404, {"error": "not found"})
            return
        try:
            updated = linkmoth.DEVICES.update_device(
                match.group(1), self._json_object(body)
            )
            linkmoth.get_auth().audit_event(
                "device_updated", self._hdrs(),
                f"{updated['id']} {updated['address']}",
            )
            self._send(200, {"device": updated})
        except Exception as exc:
            self._send_device_exception(exc)

    def do_DELETE(self):
        if self._reject_if_publicly_exposed():
            return
        path = urlparse(self.path).path
        ok, session = self._require_auth()
        if not ok:
            self._send(401, {"error": "authentication required"})
            return
        if not self._require_csrf(session):
            linkmoth.get_auth().audit_event("csrf_rejected", self._hdrs(), path)
            self._send(403, {"error": "csrf required"})
            return
        token_match = re.fullmatch(r"/api/auth/tokens/([0-9a-f]{8})", path)
        if token_match:
            if linkmoth.get_auth().revoke_readonly_token(token_match.group(1)):
                self._send(200, {"revoked": True})
            else:
                self._send(404, {"error": "no such token"})
            return
        webhook_match = re.fullmatch(
            r"/api/webhooks/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12})",
            path,
        )
        if webhook_match:
            from linkmoth_webhooks import delete_webhook
            try:
                webhook_id = webhook_match.group(1)
                delete_webhook(db, webhook_id)
                linkmoth.get_auth().audit_event(
                    "webhook_deleted", self._hdrs(), webhook_id,
                )
                self._send(200, {"deleted": True})
            except Exception as exc:
                self._send_webhook_exception(exc)
            return
        match = re.fullmatch(
            r"/api/devices/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12})",
            path,
        )
        if not match:
            self._send(404, {"error": "not found"})
            return
        try:
            device_id = match.group(1)
            linkmoth.DEVICES.delete_device(device_id)
            linkmoth.get_auth().audit_event(
                "device_deleted", self._hdrs(), device_id,
            )
            self._send(200, {"deleted": True})
        except Exception as exc:
            self._send_device_exception(exc)



def doctor(json_output=False):
    problems = 0
    checks = []

    def report(name, healthy, detail=""):
        nonlocal problems
        checks.append({
            "name": name,
            "status": "ok" if healthy else "fail",
            "detail": detail,
        })
        if not json_output:
            print(f"[{'ok' if healthy else 'FAIL'}] {name}"
                  + (f" — {detail}" if detail else ""))
        if not healthy:
            problems += 1

    def info(name, detail=""):
        checks.append({"name": name, "status": "info", "detail": detail})
        if not json_output:
            print(f"[--] {name}" + (f" — {detail}" if detail else ""))

    report("python >= 3.9", sys.version_info >= (3, 9), sys.version.split()[0])
    # DNS is resolved with a stdlib socket now — no `dig` binary required.
    for tool in ("ping", "ip", "systemctl"):
        path = shutil.which(tool)
        report(f"tool: {tool}", path is not None, path or "not found")
    trust_tool = next(
        (t for t in ("update-ca-certificates", "update-ca-trust", "trust")
         if shutil.which(t)),
        None,
    )
    info("CA trust mechanism",
         trust_tool or "none found — clients trust the CA manually")
    report("config", CONFIG_ERROR is None, CONFIG_ERROR or str(CONFIG_PATH))
    report("state dir writable", os.access(STATE_DIR, os.W_OK), str(STATE_DIR))
    try:
        # Doctor is also an upgrade preflight. Initialize a fresh database or
        # persistently move an older one to WAL before checking its health.
        init_db()
        db_info = db_maintenance_info()
        report(
            "database journal",
            db_info["journal_mode"] == "WAL",
            f"{db_info['journal_mode']}; busy timeout {db_info['busy_timeout_ms']} ms; "
            f"lock retries {db_info['lock_retries']}",
        )
    except (OSError, sqlite3.Error, RuntimeError) as exc:
        report("database journal", False, str(exc))
    report("dashboard.html present", (BASE / "dashboard.html").exists(), str(BASE))
    report("linkmoth.svg present", ICON_PATH.is_file(), str(ICON_PATH))
    report("linkmoth-white.svg present", WHITE_LOGO_PATH.is_file(), str(WHITE_LOGO_PATH))
    report("linkmoth-mark-white.svg present", WHITE_MARK_PATH.is_file(), str(WHITE_MARK_PATH))
    report("linkmoth-maskable.svg present", MASKABLE_ICON_PATH.is_file(), str(MASKABLE_ICON_PATH))
    for png_path in PNG_ICON_PATHS.values():
        report(f"{png_path.name} present", png_path.is_file(), str(png_path))
    report("browser icon present", FAVICON_PATH.is_file(), str(FAVICON_PATH))
    try:
        import linkmoth_push  # noqa: F401  (adds the optional push venv to sys.path)
        import pywebpush  # noqa: F401
        report("browser push (optional)", True, "pywebpush available")
    except ImportError:
        info("browser push (optional)",
             "off — run: sudo bash install.sh --with-push (uses /opt/linkmoth/venv, not system pip)")
    rc_ntp, ntp = run_cmd(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    if rc_ntp == 0 and ntp.strip() == "yes":
        report("clock synchronized (NTP)", True)
    elif rc_ntp == 0 and ntp.strip() == "no":
        info("clock synchronized (NTP)",
             "NOT synced — TOTP codes and HTTPS need accurate time; check: timedatectl")
    else:
        info("clock synchronized (NTP)", "could not determine")
    try:
        cert, key = tls_paths()
        build_tls_context()
        report("TLS certificate", True, f"{cert} (key: {key})")
    except RuntimeError as e:
        report("TLS certificate", False, str(e))
    gw, dev = default_route()
    report("default route", gw is not None,
           f"via {gw} on {dev}" if gw else "none — is the network up?")
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind((CFG["bind"], CFG["port"]))
        probe.close()
        report(f"port {CFG['port']} free", True)
    except OSError:
        report(f"port {CFG['port']} free", False,
               "in use (linkmoth already running, or another service)")
    ifaces = classify_network_interfaces()
    risky = bind_exposure_risk(CFG["bind"], ifaces)
    tunnels = [i for i in risky if i["kind"] == "tunnel"]
    containers = [i for i in risky if i["kind"] == "container"]
    if tunnels:
        names = ", ".join(f"{i['iface']} ({i['address']})" for i in tunnels)
        report(
            "bind exposure", False,
            f"bind=0.0.0.0 also listens on a VPN/tunnel interface: {names}. "
            f"This reaches beyond your LAN over that tunnel. Set \"bind\" in "
            f"{CONFIG_PATH} to your LAN IP (not 0.0.0.0) and restart.",
        )
    else:
        report("bind exposure", True)
    if containers:
        names = ", ".join(f"{i['iface']} ({i['address']})" for i in containers)
        info(
            "container bridge interfaces",
            f"{names} — host-local, not normally reachable from outside; "
            f"narrow \"bind\" if you want to exclude them too",
        )
    if json_output:
        print(json.dumps({
            "schema": 1,
            "version": VERSION,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "problems": problems,
            "checks": checks,
        }, indent=2))
    else:
        print("all good" if problems == 0 else f"{_count_phrase(problems, 'problem')} found")
    return 0 if problems == 0 else 1



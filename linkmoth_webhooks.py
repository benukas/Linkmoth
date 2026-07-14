"""Outbound webhook engine: presets, templates, persistent retry queue, inbound helpers.

Webhooks are stored in SQLite (not settings.json) and always send through the
queue: emit_event() enqueues one row per subscribed webhook and wakes the drain
thread, which renders the payload at send time so late deliveries can be
annotated. During a global outage nothing is attempted — rows wait for WAN
recovery.
"""
import http.client
import json
import ipaddress
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from urllib import error as urlerror
from urllib.parse import urlparse

MAX_WEBHOOKS = 20
MAX_HEADERS = 10
MAX_TEMPLATE_BYTES = 8 * 1024
HTTP_TIMEOUT = 10
USER_AGENT = "linkmoth-notify/1.0"

QUEUE_CAP = 500
MAX_ATTEMPTS = 10
GONE_MAX_ATTEMPTS = 3  # 404/410 — endpoint is gone, give up early
MAX_AGE_SECONDS = 24 * 3600
BACKOFF_SECONDS = [30, 120, 600, 1800, 3600]
DRAIN_BATCH = 20
DRAIN_IDLE_SECONDS = 15
DELAYED_THRESHOLD_SECONDS = 60

MASK = "••••••••"
FORBIDDEN_HEADERS = frozenset({
    "connection", "content-length", "host", "keep-alive",
    "proxy-authenticate", "proxy-authorization", "te", "trailer",
    "transfer-encoding", "upgrade",
})

RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

# Ordered: this is also the order the dashboard shows the checkboxes in.
EVENT_TYPES = (
    ("fault_opened", "Fault opened"),
    ("fault_updated", "Fault updated"),
    ("fault_recovered", "Fault recovered"),
    ("fault_closed", "Fault closed"),
    ("degradation_detected", "Degradation detected"),
    ("diagnosis_run", "Diagnosis run"),
    ("false_alarm_marked", "False alarm marked"),
    ("device_down", "Device down"),
    ("device_recovered", "Device recovered"),
    ("public_exposure_detected", "Public exposure detected"),
)
EVENT_IDS = tuple(ev for ev, _ in EVENT_TYPES)
EVENT_LABELS = dict(EVENT_TYPES)

_FAULT_EVENTS = frozenset({
    "fault_opened", "fault_updated", "degradation_detected", "device_down",
})
_RECOVERY_EVENTS = frozenset({"fault_recovered", "fault_closed", "device_recovered"})

PRESETS = (
    ("generic", "Generic JSON"),
    ("ntfy", "ntfy"),
    ("gotify", "Gotify"),
    ("home_assistant", "Home Assistant"),
    ("discord", "Discord"),
    ("slack", "Slack"),
    ("n8n", "n8n / Node-RED"),
    ("custom", "Custom template"),
)
PRESET_IDS = tuple(p for p, _ in PRESETS)

TEMPLATE_VARIABLES = (
    "event", "event_label", "status", "severity", "verdict", "verdict_title",
    "title", "body", "summary", "hint", "incident_id", "incident_started",
    "source", "confidence", "duration_seconds", "affected_layer",
    "timestamp", "timestamp_unix", "delayed", "queued_at",
)
# Substituted raw (valid JSON on their own); everything else is JSON-escaped text.
_RAW_VARIABLES = frozenset({"duration_seconds", "timestamp_unix", "delayed"})

AFFECTED_LAYERS = {
    "pi_link": "host",
    "link_degraded": "host",
    "host_power": "host",
    "router_down": "lan",
    "router_wlan_down": "wlan",
    "wan_down": "wan",
    "partial_routing": "wan",
    "restricted_connectivity": "wan",
    "local_dns_broken": "dns",
    "upstream_dns_down": "dns",
    "web_broken": "web",
    "all_clear": "none",
}

DRAIN_WAKE = threading.Event()


def _atomic_write_private_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = None
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            json.dump(value, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


class WebhookNotFound(LookupError):
    pass


class WebhookLimitReached(RuntimeError):
    pass


def init_webhook_db(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS webhooks(
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            url TEXT NOT NULL,
            preset TEXT NOT NULL DEFAULT 'generic',
            headers TEXT NOT NULL DEFAULT '{}',
            events TEXT NOT NULL DEFAULT '[]',
            template TEXT,
            created REAL NOT NULL,
            updated REAL NOT NULL,
            last_send_ts REAL,
            last_status INTEGER,
            last_error TEXT
        );
        CREATE TABLE IF NOT EXISTS webhook_queue(
            id INTEGER PRIMARY KEY,
            webhook_id TEXT NOT NULL,
            event TEXT NOT NULL,
            context TEXT NOT NULL,
            created REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt REAL NOT NULL,
            last_error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_webhook_queue_next
            ON webhook_queue(next_attempt);
        """
    )


# ---------------------------------------------------------------------------
# Validation / secrets


def mask_header_value(value):
    value = str(value)
    if len(value) > 8:
        return MASK + value[-4:]
    return MASK


def mask_url(value):
    """Webhook URLs commonly contain bearer tokens in their path or query."""
    return MASK if str(value or "") else ""


def mask_headers(headers):
    return {name: mask_header_value(value) for name, value in headers.items()}


def _clean_name(value):
    name = str(value or "").strip()
    if not name or len(name) > 64 or any(ord(ch) < 32 for ch in name):
        raise ValueError("name must be 1–64 printable characters")
    return name


def _clean_url(value):
    url = str(value or "").strip()
    if not url or len(url) > 2000:
        raise ValueError("url must be 1–2000 characters")
    if "\\" in url or any(ord(ch) < 33 or ord(ch) == 127 for ch in url):
        raise ValueError("url contains an unsafe character")
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        raise ValueError("url has an invalid authority") from None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("url must be an http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("url must not contain credentials")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("url has an invalid port")
    if parsed.fragment:
        raise ValueError("url must not contain a fragment")
    host = parsed.hostname
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if parsed.scheme != "https":
            raise ValueError("HTTP webhooks require an RFC1918 IPv4 address")
    else:
        is_local = (
            isinstance(address, ipaddress.IPv4Address)
            and (address.is_loopback or any(address in network for network in RFC1918_NETWORKS))
        )
        if not is_local and not address.is_global:
            raise ValueError("url must not target a loopback, link-local, or reserved address")
        if not is_local and parsed.scheme != "https":
            raise ValueError("public webhooks must use HTTPS")
    return url


def _resolve_pinned_target(url):
    """Validate a delivery URL and return the exact address the request must use.

    Hostnames are HTTPS-only and must currently resolve entirely to global IPs;
    local delivery is limited to an explicit private or loopback IPv4 literal.
    Returns (scheme, host, port, path, address) — callers must connect to
    `address` directly rather than re-resolving `host`, or a DNS answer that
    changes between this check and the actual delivery could redirect the
    request to a different address than the one just validated.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    scheme = parsed.scheme
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            addresses = {
                info[4][0]
                for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            }
        except OSError as exc:
            raise ValueError("webhook host could not be resolved safely") from exc
        parsed_addresses = {ipaddress.ip_address(a) for a in addresses}
        if not parsed_addresses or any(not a.is_global for a in parsed_addresses):
            raise ValueError("webhook hostname resolved to a non-public address")
        return scheme, host, port, path, sorted(addresses)[0]
    is_local = (
        isinstance(address, ipaddress.IPv4Address)
        and (address.is_loopback or any(address in network for network in RFC1918_NETWORKS))
    )
    if not is_local and not address.is_global:
        raise ValueError("webhook address is not permitted")
    return scheme, host, port, path, str(address)


def _validate_delivery_target(url):
    """Reject unsafe destinations again immediately before every delivery."""
    _resolve_pinned_target(url)


def _clean_bool(value, field):
    if isinstance(value, bool):
        return value
    raise ValueError(f"{field} must be true or false")


def _clean_events(value):
    if value is None:
        value = []
    if not isinstance(value, list):
        raise ValueError("events must be a list")
    events = []
    for item in value:
        ev = str(item).strip()
        if ev not in EVENT_IDS:
            raise ValueError(f"unknown event type: {ev[:40]}")
        if ev not in events:
            events.append(ev)
    return events


def _clean_headers(value, stored=None):
    """Validate custom headers; masked values round-trip to the stored secret."""
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("headers must be an object")
    if len(value) > MAX_HEADERS:
        raise ValueError(f"at most {MAX_HEADERS} headers allowed")
    stored = stored or {}
    stored_by_lower = {name.lower(): (name, val) for name, val in stored.items()}
    clean = {}
    seen = set()
    for name, raw in value.items():
        name = str(name).strip()
        if not re.fullmatch(r"[A-Za-z0-9-]+", name):
            raise ValueError("header names may contain only letters, digits, and dashes")
        lower_name = name.lower()
        if lower_name in FORBIDDEN_HEADERS:
            raise ValueError(f"header {name} is not allowed")
        if lower_name in seen:
            raise ValueError("header names must be unique ignoring case")
        seen.add(lower_name)
        val = str(raw).strip()
        if not val or len(val) > 1000:
            raise ValueError("header values must be 1–1000 characters")
        if any(ord(ch) < 32 for ch in val):
            raise ValueError("header values must not contain control characters")
        stored_item = stored_by_lower.get(lower_name)
        if stored_item and val == mask_header_value(stored_item[1]):
            name, val = stored_item  # unchanged masked value → keep the stored secret
        clean[name] = val
    return clean


def _clean_template(preset, value):
    if preset != "custom":
        return None
    template = str(value or "")
    if not template.strip():
        raise ValueError("custom preset requires a template")
    if len(template.encode("utf-8")) > MAX_TEMPLATE_BYTES:
        raise ValueError("template must be at most 8 KB")
    return template


def validate_webhook(data, stored_headers=None, stored_url=None):
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    allowed = {"name", "enabled", "url", "preset", "headers", "events", "template"}
    if set(data) - allowed:
        raise ValueError("webhook contains an unknown field")
    preset = str(data.get("preset") or "generic").strip().lower()
    if preset not in PRESET_IDS:
        raise ValueError("unknown preset")
    raw_url = data.get("url")
    if stored_url and str(raw_url or "").strip() == MASK:
        raw_url = stored_url
    clean = {
        "name": _clean_name(data.get("name")),
        "enabled": _clean_bool(data.get("enabled", True), "enabled"),
        "url": _clean_url(raw_url),
        "preset": preset,
        "headers": _clean_headers(data.get("headers"), stored=stored_headers),
        "events": _clean_events(data.get("events")),
        "template": _clean_template(preset, data.get("template")),
    }
    if preset == "custom":
        _check_template_output(clean)
    return clean


def _check_template_output(clean):
    """A custom template must render to valid JSON unless the user overrides Content-Type."""
    content_type = None
    for name, value in clean["headers"].items():
        if name.lower() == "content-type":
            content_type = value
    if content_type is not None and "json" not in content_type.lower():
        return
    rendered = render_template(clean["template"], sample_context("fault"))
    try:
        json.loads(rendered)
    except json.JSONDecodeError as e:
        raise ValueError(f"template does not render to valid JSON: {e}") from None


# ---------------------------------------------------------------------------
# CRUD


def _json_or(value, default):
    try:
        out = json.loads(value or "")
    except (json.JSONDecodeError, TypeError):
        return default
    return out if isinstance(out, type(default)) else default


def _row_to_webhook(row, mask=True):
    item = dict(row)
    item["enabled"] = bool(item["enabled"])
    item["headers"] = _json_or(item["headers"], {})
    item["events"] = _json_or(item["events"], [])
    if mask:
        item["url"] = mask_url(item["url"])
        item["headers"] = mask_headers(item["headers"])
    return item


def list_webhooks(db_connect, mask=True):
    """Webhooks with queue visibility fields (queued count, next retry)."""
    with db_connect() as conn:
        rows = conn.execute(
            """
            SELECT w.*, COUNT(q.id) AS queued, MIN(q.next_attempt) AS next_attempt,
                   MAX(q.last_error) AS queue_error
            FROM webhooks w LEFT JOIN webhook_queue q ON q.webhook_id = w.id
            GROUP BY w.id ORDER BY w.name COLLATE NOCASE
            """
        ).fetchall()
    return [_row_to_webhook(row, mask=mask) for row in rows]


def get_webhook(db_connect, webhook_id, mask=True):
    with db_connect() as conn:
        row = conn.execute(
            "SELECT * FROM webhooks WHERE id=?", (webhook_id,)
        ).fetchone()
    if not row:
        raise WebhookNotFound("no such webhook")
    return _row_to_webhook(row, mask=mask)


def create_webhook(db_connect, data):
    clean = validate_webhook(data)
    now = time.time()
    webhook_id = str(uuid.uuid4())
    with db_connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM webhooks").fetchone()[0]
        if count >= MAX_WEBHOOKS:
            raise WebhookLimitReached(f"webhook limit reached ({MAX_WEBHOOKS})")
        conn.execute(
            "INSERT INTO webhooks(id, name, enabled, url, preset, headers,"
            " events, template, created, updated) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                webhook_id, clean["name"], int(clean["enabled"]), clean["url"],
                clean["preset"], json.dumps(clean["headers"]),
                json.dumps(clean["events"]), clean["template"], now, now,
            ),
        )
    return get_webhook(db_connect, webhook_id)


def update_webhook(db_connect, webhook_id, data):
    current = get_webhook(db_connect, webhook_id, mask=False)
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    base = {
        key: current[key]
        for key in ("name", "enabled", "url", "preset", "headers", "events", "template")
    }
    base.update(data)
    clean = validate_webhook(
        base,
        stored_headers=current["headers"],
        stored_url=current["url"],
    )
    with db_connect() as conn:
        conn.execute(
            "UPDATE webhooks SET name=?, enabled=?, url=?, preset=?, headers=?,"
            " events=?, template=?, updated=? WHERE id=?",
            (
                clean["name"], int(clean["enabled"]), clean["url"], clean["preset"],
                json.dumps(clean["headers"]), json.dumps(clean["events"]),
                clean["template"], time.time(), webhook_id,
            ),
        )
    return get_webhook(db_connect, webhook_id)


def delete_webhook(db_connect, webhook_id):
    with db_connect() as conn:
        found = conn.execute(
            "SELECT 1 FROM webhooks WHERE id=?", (webhook_id,)
        ).fetchone()
        if not found:
            raise WebhookNotFound("no such webhook")
        conn.execute("DELETE FROM webhook_queue WHERE webhook_id=?", (webhook_id,))
        conn.execute("DELETE FROM webhooks WHERE id=?", (webhook_id,))


def webhook_channel_active(db_connect):
    """True when any enabled webhook subscribes to device events."""
    with db_connect() as conn:
        rows = conn.execute("SELECT events FROM webhooks WHERE enabled=1").fetchall()
    return any(
        ev in _json_or(row["events"], [])
        for row in rows
        for ev in ("device_down", "device_recovered")
    )


def api_metadata():
    return {
        "events": [{"id": ev, "label": label} for ev, label in EVENT_TYPES],
        "presets": [{"id": p, "label": label} for p, label in PRESETS],
        "template_variables": list(TEMPLATE_VARIABLES),
        "max_webhooks": MAX_WEBHOOKS,
    }


# ---------------------------------------------------------------------------
# Event context


def _iso(ts):
    if not ts:
        return ""
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def event_status(event, severity="info"):
    if event in _RECOVERY_EVENTS:
        return "recovery"
    if event in _FAULT_EVENTS:
        return "fault"
    if event == "diagnosis_run" and severity in ("warn", "bad"):
        return "fault"
    return "info"


def affected_layer_for(event, code):
    if event in ("device_down", "device_recovered"):
        return "device"
    return AFFECTED_LAYERS.get(code or "", "none")


def build_event_context(event, verdict=None, incident=None, checks=None,
                        duration_s=None, source=None, extra=None):
    verdict = verdict or {}
    incident = incident or {}
    severity = str(verdict.get("severity") or "info")
    code = str(verdict.get("code") or "")
    title = str(verdict.get("title") or EVENT_LABELS.get(event, event))
    body = str(verdict.get("explain") or verdict.get("hint") or "")
    confidence = ""
    if checks:
        confidence = _confidence_from_checks(checks)
    ctx = {
        "event": event,
        "event_label": EVENT_LABELS.get(event, event),
        "status": event_status(event, severity),
        "severity": severity,
        "verdict": code,
        "verdict_title": str(verdict.get("title") or ""),
        "title": title,
        "body": body,
        "hint": str(verdict.get("hint") or ""),
        "incident_id": str(incident.get("ref") or ""),
        "incident_started": _iso(incident.get("started")),
        "source": str(source or incident.get("source") or "linkmoth"),
        "confidence": confidence,
        "duration_seconds": int(duration_s or 0),
        "affected_layer": affected_layer_for(event, code),
    }
    if extra:
        ctx.update(extra)
    ctx.setdefault("summary", ctx["body"])
    return ctx


def _confidence_from_checks(checks):
    # Mirrors linkmoth.confidence_from_checks; duplicated to keep this module
    # importable without the daemon.
    c = {ch.get("id"): ch for ch in checks}
    if c.get("link", {}).get("ok") is False:
        return "low"
    if c.get("power", {}).get("ok") is False:
        return "medium"
    if c.get("router_wlan", {}).get("ok") is False:
        return "medium"
    if any(
        c.get(cid, {}).get("state") == "partial"
        for cid in ("router_wlan", "upstream_dns", "raw_ping", "https")
    ):
        return "medium"
    return "high"


def _finalize_context(ctx, queued_ts, now=None):
    """Stamp render-time fields: timestamps and the delayed-delivery flag."""
    now = now if now is not None else time.time()
    out = dict(ctx)
    out["timestamp"] = _iso(now)
    out["timestamp_unix"] = round(float(now), 3)
    out["queued_at"] = _iso(queued_ts)
    out["delayed"] = bool(queued_ts and now - float(queued_ts) > DELAYED_THRESHOLD_SECONDS)
    out.setdefault("summary", out.get("body", ""))
    return out


def sample_context(kind="fault", now=None):
    """Canned context for the test buttons and template validation."""
    now = now if now is not None else time.time()
    if kind == "recovery":
        ctx = build_event_context(
            "fault_recovered",
            verdict={
                "severity": "ok", "code": "all_clear",
                "title": "All network checks passed",
                "explain": "Test recovery sent from the Linkmoth dashboard.",
                "hint": "",
            },
            incident={"ref": "INC-TEST-0000", "started": now - 754, "source": "test"},
            duration_s=754,
        )
    else:
        ctx = build_event_context(
            "fault_opened",
            verdict={
                "severity": "bad", "code": "wan_down",
                "title": "Internet (WAN) is down",
                "explain": "Test fault sent from the Linkmoth dashboard.",
                "hint": "This is only a test.",
            },
            incident={"ref": "INC-TEST-0000", "started": now, "source": "test"},
            duration_s=0,
        )
    return _finalize_context(ctx, queued_ts=now, now=now)


# ---------------------------------------------------------------------------
# Rendering

_TEMPLATE_RE = re.compile(r"\{\{\s*(\w+)\s*\}\}")


def render_template(template, ctx):
    """Dumb placeholder substitution only — no logic, loops, or expressions."""
    def repl(match):
        key = match.group(1)
        if key not in ctx:
            return ""
        value = ctx[key]
        if key in _RAW_VARIABLES:
            if isinstance(value, bool):
                return "true" if value else "false"
            return json.dumps(value)
        # JSON-escaped without surrounding quotes so `"x": "{{y}}"` stays valid.
        return json.dumps(str(value))[1:-1]
    return _TEMPLATE_RE.sub(repl, template)


def _delayed_note(ctx):
    if ctx.get("delayed"):
        return f"\n(delayed delivery — event occurred {ctx.get('queued_at')})"
    return ""


def _render_generic(ctx):
    payload = {
        "event": ctx["event"],
        "incident_id": ctx["incident_id"],
        "verdict": ctx["verdict"],
        "severity": ctx["severity"],
        "confidence": ctx["confidence"],
        "duration_seconds": ctx["duration_seconds"],
        "affected_layer": ctx["affected_layer"],
        "source": ctx["source"],
        "title": ctx["title"],
        "body": ctx["body"],
        "message": f"{ctx['title']}\n{ctx['body']}".strip(),
        "timestamp": ctx["timestamp"],
        "delayed": ctx["delayed"],
        "queued_at": ctx["queued_at"],
    }
    return json.dumps(payload).encode("utf-8"), "application/json", {}


def _render_ntfy(ctx):
    body = (ctx["body"] or ctx["title"]) + _delayed_note(ctx)
    if ctx["severity"] == "bad":
        priority = "5"
    elif ctx["severity"] == "warn":
        priority = "4"
    else:
        priority = "3"
    if ctx["event"] == "degradation_detected":
        tags = "warning"
    elif ctx["status"] == "fault":
        tags = "rotating_light"
    elif ctx["status"] == "recovery":
        tags = "white_check_mark"
    else:
        tags = "information_source"
    headers = {"X-Title": ctx["title"], "X-Priority": priority, "X-Tags": tags}
    return body.encode("utf-8"), "text/plain; charset=utf-8", headers


def _render_gotify(ctx):
    if ctx["severity"] == "bad":
        priority = 8
    elif ctx["severity"] == "warn":
        priority = 5
    else:
        priority = 3
    payload = {
        "title": ctx["title"],
        "message": (ctx["body"] or ctx["title"]) + _delayed_note(ctx),
        "priority": priority,
    }
    return json.dumps(payload).encode("utf-8"), "application/json", {}


def _render_discord(ctx):
    if ctx["status"] == "recovery":
        color = 0x43A047
    elif ctx["severity"] == "bad":
        color = 0xE53935
    elif ctx["severity"] == "warn":
        color = 0xFFB300
    else:
        color = 0x546E7A
    fields = []
    if ctx["incident_id"]:
        fields.append({"name": "Incident", "value": ctx["incident_id"], "inline": True})
    if ctx["verdict"]:
        fields.append({"name": "Verdict", "value": ctx["verdict"], "inline": True})
    if ctx["affected_layer"] not in ("", "none"):
        fields.append({"name": "Layer", "value": ctx["affected_layer"], "inline": True})
    if ctx["confidence"]:
        fields.append({"name": "Confidence", "value": ctx["confidence"], "inline": True})
    if ctx["status"] == "recovery" and ctx["duration_seconds"]:
        minutes, seconds = divmod(int(ctx["duration_seconds"]), 60)
        fields.append({
            "name": "Duration",
            "value": f"{minutes}m {seconds}s" if minutes else f"{seconds}s",
            "inline": True,
        })
    footer = "Linkmoth" + (" · delayed delivery" if ctx["delayed"] else "")
    embed = {
        "title": f"{ctx['event_label']}: {ctx['title']}"[:256],
        "description": (ctx["body"] or "")[:2048],
        "color": color,
        "timestamp": ctx["timestamp"],
        "fields": fields,
        "footer": {"text": footer},
    }
    payload = {"username": "Linkmoth", "embeds": [embed]}
    return json.dumps(payload).encode("utf-8"), "application/json", {}


def _render_slack(ctx):
    meta = " · ".join(
        part for part in (ctx["incident_id"], ctx["verdict"], ctx["affected_layer"])
        if part and part != "none"
    )
    text = f"*{ctx['title']}*\n{ctx['body']}".strip()
    if meta:
        text += f"\n_{meta}_"
    text += _delayed_note(ctx)
    return json.dumps({"text": text}).encode("utf-8"), "application/json", {}


def render_payload(webhook, ctx):
    """Render (body, content_type, auto_headers) for a webhook's preset."""
    preset = webhook.get("preset") or "generic"
    if preset == "custom":
        body = render_template(webhook.get("template") or "", ctx)
        return body.encode("utf-8"), "application/json", {}
    if preset == "ntfy":
        return _render_ntfy(ctx)
    if preset == "gotify":
        return _render_gotify(ctx)
    if preset == "discord":
        return _render_discord(ctx)
    if preset == "slack":
        return _render_slack(ctx)
    return _render_generic(ctx)  # generic, home_assistant, n8n


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that connects to a pre-validated address only.

    Never re-resolves the hostname at connect time, so a DNS answer that
    changes between validation and delivery cannot redirect the request to a
    different address than the one `_resolve_pinned_target` just checked.
    """
    def __init__(self, host, address, **kwargs):
        super().__init__(host, **kwargs)
        self._address = address

    def connect(self):
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _post(url, body, headers, timeout=HTTP_TIMEOUT):
    """POST bytes to a pinned address; returns the HTTP status. Raises on network errors.

    Never follows redirects (the response is returned as-is, Location is not
    read) and never consults environment proxies (a raw socket connection is
    made directly to the validated address).
    """
    scheme, host, port, path, address = _resolve_pinned_target(url)
    if scheme == "https":
        conn = _PinnedHTTPSConnection(
            host, address, port=port, timeout=timeout,
            context=ssl.create_default_context(),
        )
    else:
        conn = http.client.HTTPConnection(address, port=port, timeout=timeout)
    try:
        conn.request("POST", path, body=body, headers=headers)
        response = conn.getresponse()
        try:
            response.read()
        finally:
            response.close()
        if not (200 <= response.status < 300):
            raise urlerror.HTTPError(
                url, response.status, response.reason,
                dict(response.getheaders()), None,
            )
        return int(response.status)
    finally:
        conn.close()


def _safe_network_error(exc):
    message = str(exc).replace("\r", " ").replace("\n", " ")
    message = re.sub(r"https?://\S+", "<redacted-url>", message, flags=re.I)
    return f"{exc.__class__.__name__}: {message}"[:200]


def _send_now(webhook, ctx):
    """Render and POST one payload. Returns (status, error) — error None on success."""
    body, content_type, auto_headers = render_payload(webhook, ctx)
    headers = {"Content-Type": content_type, "User-Agent": USER_AGENT}
    headers.update(auto_headers)
    headers.update(webhook.get("headers") or {})
    try:
        status = _post(webhook["url"], body, headers)
        return status, None
    except urlerror.HTTPError as e:
        code = int(e.code)
        # A mocked HTTPError on Python 3.9 can contain an already-consumed
        # temporary file and raise during close. Delivery status is already
        # known, so cleanup must never turn a handled HTTP failure into 500.
        try:
            e.close()
        except Exception:
            pass
        return code, f"HTTP {code}"
    except Exception as e:
        return None, _safe_network_error(e)


# ---------------------------------------------------------------------------
# Queue + drain


def wake_drain():
    DRAIN_WAKE.set()


def emit_event(db_connect, event, ctx):
    """Queue one delivery per enabled webhook subscribed to this event."""
    if event not in EVENT_IDS:
        raise ValueError(f"unknown event type: {event}")
    now = time.time()
    queued = 0
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT id, events FROM webhooks WHERE enabled=1"
        ).fetchall()
        targets = [
            row["id"] for row in rows
            if event in _json_or(row["events"], [])
        ]
        for webhook_id in targets:
            conn.execute(
                "INSERT INTO webhook_queue(webhook_id, event, context, created, next_attempt)"
                " VALUES(?,?,?,?,?)",
                (webhook_id, event, json.dumps(ctx), now, now),
            )
            queued += 1
        if queued:
            overflow = conn.execute(
                "SELECT COUNT(*) FROM webhook_queue"
            ).fetchone()[0] - QUEUE_CAP
            if overflow > 0:
                conn.execute(
                    "DELETE FROM webhook_queue WHERE id IN ("
                    " SELECT id FROM webhook_queue ORDER BY id ASC LIMIT ?)",
                    (overflow,),
                )
                print(
                    f"webhook queue full — dropped {overflow} oldest deliveries",
                    file=sys.stderr, flush=True,
                )
    if queued:
        wake_drain()
    return queued


def _record_send_result(db_connect, webhook_id, status, error):
    with db_connect() as conn:
        conn.execute(
            "UPDATE webhooks SET last_send_ts=?, last_status=?, last_error=? WHERE id=?",
            (time.time(), status, error, webhook_id),
        )


def drain_queue_once(db_connect, now=None):
    """Attempt due deliveries. Returns (sent, failed) counts."""
    now = now if now is not None else time.time()
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT * FROM webhook_queue WHERE next_attempt<=? ORDER BY id LIMIT ?",
            (now, DRAIN_BATCH),
        ).fetchall()
        webhooks = {
            row["id"]: _row_to_webhook(row, mask=False)
            for row in conn.execute("SELECT * FROM webhooks").fetchall()
        }
    sent = failed = 0
    for row in rows:
        row = dict(row)
        webhook = webhooks.get(row["webhook_id"])
        if webhook is None or not webhook["enabled"]:
            with db_connect() as conn:
                conn.execute("DELETE FROM webhook_queue WHERE id=?", (row["id"],))
            continue
        if now - float(row["created"]) > MAX_AGE_SECONDS:
            with db_connect() as conn:
                conn.execute("DELETE FROM webhook_queue WHERE id=?", (row["id"],))
            _record_send_result(
                db_connect, webhook["id"], None,
                "delivery expired after 24h of retries",
            )
            failed += 1
            continue
        ctx = _finalize_context(
            _json_or(row["context"], {}), queued_ts=row["created"], now=now,
        )
        status, error = _send_now(webhook, ctx)
        if error is None and status is not None and status < 400:
            with db_connect() as conn:
                conn.execute("DELETE FROM webhook_queue WHERE id=?", (row["id"],))
            _record_send_result(db_connect, webhook["id"], status, None)
            sent += 1
            continue
        failed += 1
        attempts = int(row["attempts"]) + 1
        give_up = attempts >= MAX_ATTEMPTS or (
            status in (404, 410) and attempts >= GONE_MAX_ATTEMPTS
        )
        with db_connect() as conn:
            if give_up:
                conn.execute("DELETE FROM webhook_queue WHERE id=?", (row["id"],))
            else:
                backoff = BACKOFF_SECONDS[min(attempts - 1, len(BACKOFF_SECONDS) - 1)]
                conn.execute(
                    "UPDATE webhook_queue SET attempts=?, next_attempt=?, last_error=?"
                    " WHERE id=?",
                    (attempts, now + backoff, error, row["id"]),
                )
        _record_send_result(db_connect, webhook["id"], status, error)
    return sent, failed


def drain_loop(db_connect):
    """Background drain: paused while a global outage is active."""
    from linkmoth_outage import OUTAGE_TRACKER
    while True:
        DRAIN_WAKE.wait(timeout=DRAIN_IDLE_SECONDS)
        DRAIN_WAKE.clear()
        try:
            if OUTAGE_TRACKER.is_active(db_connect):
                continue  # WAN is down — let deliveries wait for recovery
            drain_queue_once(db_connect)
        except Exception as e:
            print(f"webhook drain error: {e}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Test send + migration


def send_test(db_connect, webhook_id, kind="fault"):
    """Synchronous test delivery through the exact production render path."""
    webhook = get_webhook(db_connect, webhook_id, mask=False)
    ctx = sample_context("recovery" if kind == "recovery" else "fault")
    status, error = _send_now(webhook, ctx)
    ok = error is None and status is not None and status < 400
    _record_send_result(db_connect, webhook_id, status, error)
    body, content_type, _auto = render_payload(webhook, ctx)
    return {
        "ok": ok,
        "status": status,
        "error": error,
        "content_type": content_type,
        "url": mask_url(webhook["url"]),
        "preview": body.decode("utf-8", errors="replace")[:2000],
    }


MIGRATION_MARKER = "webhooks_migrated"
LEGACY_EVENTS = [
    "fault_opened", "degradation_detected", "fault_recovered",
    "device_down", "device_recovered",
]


def migrate_legacy_webhook(cfg, db_connect, settings_path):
    """One-time: turn the old single notify_webhook_url into a webhook row."""
    current = {}
    if settings_path.exists():
        try:
            current = json.loads(settings_path.read_text())
            if not isinstance(current, dict):
                raise ValueError
        except (json.JSONDecodeError, OSError, TypeError, ValueError):
            current = {}
    if current.get(MIGRATION_MARKER):
        return False
    migrated = False
    url = str(cfg.get("notify_webhook_url") or "").strip()
    if url:
        try:
            create_webhook(db_connect, {
                "name": "Generic JSON (migrated)",
                "enabled": bool(cfg.get("notify_webhook_enabled", False)),
                "url": url,
                "preset": "generic",
                "events": list(LEGACY_EVENTS),
            })
            migrated = True
        except (ValueError, WebhookLimitReached) as e:
            print(f"legacy webhook not migrated: {e}", file=sys.stderr, flush=True)
    current[MIGRATION_MARKER] = True
    try:
        _atomic_write_private_json(settings_path, current)
    except OSError as e:
        print(f"could not write migration marker: {e}", file=sys.stderr, flush=True)
    return migrated

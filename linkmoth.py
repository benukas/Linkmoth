#!/usr/bin/env python3
"""Linkmoth: event-driven network fault diagnosis with a LAN-only dashboard.

Sits idle until triggered (Uptime Kuma webhook, dashboard button, or CLI),
then runs a layered fault ladder several times over a few minutes and records
the incident with a plain verdict of who is to blame.
"""
import json
import ipaddress
import os
import re
import secrets
import shlex
import shutil
import socket
import sqlite3
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib import request as urlrequest
from urllib.parse import parse_qs, urlparse

BASE = Path(__file__).resolve().parent
ICON_PATH = BASE / "linkmoth.svg"
WHITE_LOGO_PATH = BASE / "linkmoth-white.svg"
WHITE_MARK_PATH = BASE / "linkmoth-mark-white.svg"
FAVICON_PATH = BASE / "linkmoth-white.ico"
SW_PATH = BASE / "sw.js"
MANIFEST_PATH = BASE / "manifest.webmanifest"
VERSION = "1.0.0"
VERIFY_COOLDOWN_SECONDS = 5
GITHUB_REPO = "https://github.com/benukas/linkmoth"
CHANGELOG_URL = f"{GITHUB_REPO}/blob/main/CHANGELOG.md"
SYSTEM_INSTALL = BASE == Path("/opt/linkmoth")
DEFAULT_CONFIG_PATH = (
    Path("/etc/linkmoth/config.json") if SYSTEM_INSTALL else BASE / "config.json"
)
DEFAULT_STATE_DIR = Path("/var/lib/linkmoth") if SYSTEM_INSTALL else BASE
CONFIG_PATH = Path(
    os.environ.get("LINKMOTH_CONFIG")
    or os.environ.get("VAMNER_CONFIG")
    or DEFAULT_CONFIG_PATH
)
STATE_DIR = Path(
    os.environ.get("STATE_DIRECTORY")
    or os.environ.get("LINKMOTH_STATE_DIR")
    or os.environ.get("VAMNER_STATE_DIR")
    or DEFAULT_STATE_DIR
)
DEFAULT_TLS_DIR = Path("/etc/linkmoth/tls") if SYSTEM_INSTALL else STATE_DIR / "tls"
LOCAL_DNS_DEFAULT = {
    "mode": "auto",
    "address": "127.0.0.1",
    "provider": "auto",
}
LOCAL_DNS_PROVIDERS = frozenset({
    "auto", "generic", "pihole", "unbound", "dnsmasq",
})
RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _allowed_local_dns_address(value):
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return (
        isinstance(address, ipaddress.IPv4Address)
        and (
            address.is_loopback
            or any(address in network for network in RFC1918_NETWORKS)
        )
    )


def normalize_local_dns_config(value):
    """Accept the old bool/string shape and return the stable object shape."""
    if value is False:
        return {**LOCAL_DNS_DEFAULT, "mode": "disabled"}
    if value is True:
        return {**LOCAL_DNS_DEFAULT, "mode": "enabled"}
    if value == "auto" or value is None:
        return dict(LOCAL_DNS_DEFAULT)
    if not isinstance(value, dict):
        raise ValueError("local_dns must be an object, 'auto', true, or false")
    if set(value) - {"mode", "address", "provider"}:
        raise ValueError("local_dns contains an unknown field")
    mode = str(value.get("mode") or "auto").strip().lower()
    provider = str(value.get("provider") or "auto").strip().lower()
    address = str(value.get("address") or "127.0.0.1").strip()
    if mode not in ("auto", "enabled", "disabled"):
        raise ValueError("local_dns.mode must be auto, enabled, or disabled")
    if provider not in LOCAL_DNS_PROVIDERS:
        raise ValueError(
            "local_dns.provider must be auto, generic, pihole, unbound, or dnsmasq"
        )
    if not _allowed_local_dns_address(address):
        raise ValueError("local_dns.address must be loopback or RFC1918 IPv4")
    return {
        "mode": mode,
        "address": str(ipaddress.IPv4Address(address)),
        "provider": provider,
    }

DEFAULT_CONFIG = {
    "bind": "127.0.0.1",
    "port": 8686,
    "dns_test_domain": "gstatic.com",
    "local_dns": dict(LOCAL_DNS_DEFAULT),
    "upstream_dns": ["1.1.1.1", "8.8.8.8"],
    "ping_targets": ["1.1.1.1", "8.8.8.8"],
    "https_targets": [
        "https://connectivitycheck.gstatic.com/generate_204",
        "https://www.cloudflare.com/cdn-cgi/trace",
    ],
    "recheck_seconds": [0, 30, 60, 120, 300],
    "recheck_repeat": 600,
    "incident_max_hours": 24,
    "baseline_minutes": 60,
    "history_sample_minutes": 5,
    "ladder_cache_seconds": 10,
    "retention_days": 90,
    "kuma_url": "auto",
    "ui_refresh_seconds": 5,
    "tls_cert": str(DEFAULT_TLS_DIR / "server.crt"),
    "tls_key": str(DEFAULT_TLS_DIR / "server.key"),
    "tls_ca": str(DEFAULT_TLS_DIR / "ca.crt"),
    "auth": {
        "session_ttl_seconds": 86400,
        "session_idle_seconds": 1800,
        "totp_enabled": False,  # deprecated: 2FA state now lives in the auth store
        "login_max_attempts": 5,
        "login_lockout_seconds": 300,
        "trusted_proxy_cidrs": [],
    },
    "discord_webhook_url": "",
    "discord_notifications_enabled": False,
    "push_notifications_enabled": True,
    "notify_webhook_url": "",
    "notify_webhook_enabled": False,
    "target_wifi_clients": [],
    # Connection quality: periodically measure internet latency, jitter, and
    # packet loss (not just up/down) and classify good/fair/poor. Thresholds are
    # in milliseconds / percent. "targets" empty means reuse ping_targets.
    "quality": {
        "enabled": True,
        "targets": [],
        "sample_count": 10,
        "latency_warn_ms": 80,
        "latency_bad_ms": 200,
        "jitter_warn_ms": 20,
        "jitter_bad_ms": 60,
        "loss_warn_pct": 2,
        "loss_bad_pct": 10,
    },
}

SETTINGS_PATH = STATE_DIR / "settings.json"
MAX_REQUEST_BODY = 64 * 1024
REQUEST_TIMEOUT_SECONDS = 15
TLS_HANDSHAKE_TIMEOUT_SECONDS = 5
MAX_HTTP_CONNECTIONS = 16
DB_BUSY_TIMEOUT_MS = 10_000
DB_LOCK_RETRIES = 0
DB_LOCK_RETRIES_LOCK = threading.Lock()
HOST_STATS_LOCK = threading.Lock()
HOST_CPU_SAMPLE = None
AUTH_VERIFY_SLOTS = threading.BoundedSemaphore(2)

CONFIG_ERROR = None

SETTINGS_SECRET_MASK = "••••••••"
SETTINGS_SECRET_KEYS = frozenset({
    "discord_webhook_url",
    "notify_webhook_url",
})


def _atomic_write_private_json(path, value):
    """Atomically write sensitive runtime JSON with owner-only permissions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = None
    try:
        fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            json.dump(value, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
        os.chmod(path, 0o600)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _ensure_private_state_file(path):
    """Create a state file as 0600 and reject symlink/non-file targets."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    created = False
    flags = os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise RuntimeError(f"refusing unsafe state file: {path}") from exc
    else:
        created = True
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError(f"refusing unsafe state file: {path}")
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    return created


def load_config():
    global CONFIG_ERROR
    CONFIG_ERROR = None
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            loaded = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("top-level configuration must be a JSON object")
            cfg.update(loaded)
        except (json.JSONDecodeError, OSError, TypeError, ValueError) as e:
            CONFIG_ERROR = f"{CONFIG_PATH}: {e}"
            print(f"config error, using defaults: {CONFIG_ERROR}",
                  file=sys.stderr, flush=True)
    elif CONFIG_PATH == BASE / "config.json":
        try:
            _atomic_write_private_json(CONFIG_PATH, cfg)
        except OSError:
            pass
    else:
        CONFIG_ERROR = f"{CONFIG_PATH}: not found"
        print(f"config not found, using defaults: {CONFIG_PATH}",
              file=sys.stderr, flush=True)
    if SETTINGS_PATH.exists():
        try:
            overlay = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            if not isinstance(overlay, dict):
                raise ValueError("settings overlay must be a JSON object")
            cfg.update(overlay)
        except (json.JSONDecodeError, OSError, TypeError, ValueError) as e:
            print(f"settings overlay ignored: {e}", file=sys.stderr, flush=True)
    try:
        cfg["local_dns"] = normalize_local_dns_config(cfg.get("local_dns"))
    except ValueError as e:
        CONFIG_ERROR = f"{CONFIG_PATH}: {e}"
        cfg["local_dns"] = dict(LOCAL_DNS_DEFAULT)
        print(f"config error, using default Local DNS: {e}",
              file=sys.stderr, flush=True)
    return cfg


CFG = load_config()
DB_PATH = STATE_DIR / "state.db"


def _str_list(v):
    if isinstance(v, str):
        v = [p.strip() for p in v.split(",")]
    if not isinstance(v, list):
        raise ValueError
    v = [str(x).strip() for x in v if str(x).strip()]
    if not v:
        raise ValueError
    return v


def _valid_hostname(value):
    value = str(value).strip().rstrip(".")
    if not value or len(value) > 253:
        return False
    return all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in value.split(".")
    )


def _network_targets(v):
    targets = _str_list(v)
    for target in targets:
        try:
            ipaddress.ip_address(target)
        except ValueError:
            if not _valid_hostname(target):
                raise ValueError
    return targets


def _dns_servers(v):
    servers = _str_list(v)
    try:
        for server in servers:
            ipaddress.ip_address(server)
    except ValueError:
        raise ValueError
    return servers


def _optional_ip_list(v):
    if v is None:
        return []
    if isinstance(v, str) and not v.strip():
        return []
    if isinstance(v, list) and not v:
        return []
    targets = _str_list(v)
    for target in targets:
        ipaddress.ip_address(target)
    return targets


def _dns_domain(v):
    value = str(v).strip()
    if not _valid_hostname(value):
        raise ValueError
    return value


def _kuma_url(v):
    value = str(v).strip()
    if value in ("", "auto"):
        return value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError
    if parsed.username or parsed.password:
        raise ValueError
    return value


def _safe_request_host(value):
    """Return a normalized HTTP Host value safe for URLs and shell examples."""
    raw = str(value or "").strip()
    if not raw or any(ord(ch) < 33 or ord(ch) == 127 for ch in raw):
        raise ValueError
    if "\\" in raw:
        raise ValueError
    try:
        parsed = urlparse("//" + raw)
        port = parsed.port
    except ValueError:
        raise ValueError from None
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError
    hostname = parsed.hostname
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if not _valid_hostname(hostname):
            raise ValueError from None
        normalized = hostname.lower()
    else:
        normalized = f"[{address}]" if address.version == 6 else str(address)
    return f"{normalized}:{port}" if port is not None else normalized


def _bool_setting(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("1", "true", "yes", "on"):
            return True
        if s in ("0", "false", "no", "off", ""):
            return False
    if isinstance(v, int):
        return bool(v)
    raise ValueError


def _discord_webhook_url(v):
    value = str(v).strip()
    if not value:
        return ""
    from linkmoth_discord import is_valid_discord_webhook
    if not is_valid_discord_webhook(value):
        raise ValueError
    return value


SETTABLE = {
    "kuma_url": _kuma_url,
    "ui_refresh_seconds": lambda v: max(2, min(120, int(v))),
    "baseline_minutes": lambda v: max(0, min(1440, int(v))),
    "history_sample_minutes": lambda v: max(0, min(1440, int(v))),
    "retention_days": lambda v: max(1, min(3650, int(v))),
    "dns_test_domain": _dns_domain,
    "local_dns": normalize_local_dns_config,
    "upstream_dns": _dns_servers,
    "ping_targets": _network_targets,
    "target_wifi_clients": _optional_ip_list,
    "discord_webhook_url": _discord_webhook_url,
    "discord_notifications_enabled": _bool_setting,
    "push_notifications_enabled": _bool_setting,
    "notify_webhook_url": lambda v: str(v).strip()[:2000],
    "notify_webhook_enabled": _bool_setting,
}


def apply_settings(data):
    """Validate and persist dashboard-editable settings; applied live."""
    clean, errors = {}, {}
    for key, value in data.items():
        if key not in SETTABLE:
            errors[key] = "unknown setting"
            continue
        if key in SETTINGS_SECRET_KEYS and str(value).strip() == SETTINGS_SECRET_MASK:
            clean[key] = str(CFG.get(key) or "")
            continue
        try:
            clean[key] = SETTABLE[key](value)
        except (ValueError, TypeError):
            errors[key] = "invalid value"
    if errors:
        return False, errors
    enabled = clean.get(
        "discord_notifications_enabled",
        CFG.get("discord_notifications_enabled", False),
    )
    webhook = clean.get("discord_webhook_url", CFG.get("discord_webhook_url", ""))
    if enabled:
        from linkmoth_discord import is_valid_discord_webhook
        if not webhook or not is_valid_discord_webhook(str(webhook).strip()):
            return False, {
                "discord_webhook_url": "valid Discord webhook URL required when alerts are enabled",
            }
    current = {}
    if SETTINGS_PATH.exists():
        try:
            current = json.loads(SETTINGS_PATH.read_text())
            if not isinstance(current, dict):
                raise ValueError
        except (json.JSONDecodeError, OSError, TypeError, ValueError):
            current = {}
    current.update(clean)
    try:
        _atomic_write_private_json(SETTINGS_PATH, current)
    except OSError as e:
        return False, {"_save": f"could not write {SETTINGS_PATH}: {e}"}
    CFG.update(clean)
    return True, public_settings()


def public_settings():
    out = {k: CFG.get(k) for k in SETTABLE}
    for key in SETTINGS_SECRET_KEYS:
        if out.get(key):
            out[key] = SETTINGS_SECRET_MASK
    return out


@contextmanager
def db():
    global DB_LOCK_RETRIES
    _ensure_private_state_file(DB_PATH)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {DB_BUSY_TIMEOUT_MS}")
    try:
        yield conn
        for delay in (0.0, 0.025, 0.05, 0.1, 0.2, 0.4):
            try:
                conn.commit()
                break
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                    raise
                with DB_LOCK_RETRIES_LOCK:
                    DB_LOCK_RETRIES += 1
                if delay == 0.4:
                    raise
                time.sleep(delay)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def tls_paths():
    cert = Path(
        os.environ.get("LINKMOTH_TLS_CERT")
        or os.environ.get("VAMNER_TLS_CERT")
        or CFG.get("tls_cert")
    )
    key = Path(
        os.environ.get("LINKMOTH_TLS_KEY")
        or os.environ.get("VAMNER_TLS_KEY")
        or CFG.get("tls_key")
    )
    return cert, key


def _ca_cert_path():
    override = (
        os.environ.get("LINKMOTH_TLS_CA")
        or os.environ.get("VAMNER_TLS_CA")
        or CFG.get("tls_ca")
    )
    if override:
        return Path(override)
    return DEFAULT_TLS_DIR / "ca.crt"


def build_tls_context():
    cert, key = tls_paths()
    if not cert.is_file():
        raise RuntimeError(f"TLS certificate not found: {cert}")
    if not key.is_file():
        raise RuntimeError(f"TLS private key not found: {key}")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    try:
        context.load_cert_chain(certfile=cert, keyfile=key)
    except (OSError, ssl.SSLError) as e:
        raise RuntimeError(f"could not load TLS certificate/key: {e}") from e
    return context


def create_server():
    return BoundedTLSServer(
        (CFG["bind"], CFG["port"]), Handler, build_tls_context(),
    )


class BoundedTLSServer(HTTPServer):
    """A fixed-size TLS server that never handshakes in the accept loop.

    `ThreadingHTTPServer` combined with an SSL-wrapped listening socket can
    block its sole accept loop on an unfinished client handshake and creates an
    unbounded thread per request.  Keep raw accepts cheap, then perform the
    bounded handshake and request work in a fixed worker pool instead.
    """
    allow_reuse_address = True

    def __init__(self, address, handler_class, tls_context):
        self.tls_context = tls_context
        self._slots = threading.BoundedSemaphore(MAX_HTTP_CONNECTIONS)
        self._workers = ThreadPoolExecutor(
            max_workers=MAX_HTTP_CONNECTIONS,
            thread_name_prefix="linkmoth-http",
        )
        super().__init__(address, handler_class)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                pass
            return
        self._workers.submit(self._handle_tls_request, request, client_address)

    def _handle_tls_request(self, request, client_address):
        tls_request = None
        try:
            request.settimeout(TLS_HANDSHAKE_TIMEOUT_SECONDS)
            tls_request = self.tls_context.wrap_socket(request, server_side=True)
            self.finish_request(tls_request, client_address)
        except (OSError, ssl.SSLError, socket.timeout):
            pass
        finally:
            try:
                self.shutdown_request(tls_request or request)
            except OSError:
                pass
            self._slots.release()

    def server_close(self):
        super().server_close()
        self._workers.shutdown(wait=False, cancel_futures=True)


AUTO_VACUUM_NAMES = {0: "NONE", 1: "FULL", 2: "INCREMENTAL"}
AUTO_VACUUM_MODE = 2  # INCREMENTAL — reclaims pages on delete; manual VACUUM still repacks fully


def init_db():
    fresh = _ensure_private_state_file(DB_PATH)
    if fresh:
        conn = sqlite3.connect(str(DB_PATH), timeout=10)
        try:
            conn.isolation_level = None
            conn.execute(f"PRAGMA auto_vacuum = {AUTO_VACUUM_MODE}")
        finally:
            conn.close()
    with db() as conn:
        # WAL permits readers during the short writes made by the dashboard,
        # scheduler, auth and webhook threads.  SQLite preserves this setting
        # in the database, so this also upgrades existing installations.
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS incidents(
                id INTEGER PRIMARY KEY,
                started REAL NOT NULL,
                source TEXT NOT NULL,
                detail TEXT,
                resolved REAL,
                verdict_code TEXT,
                verdict_title TEXT
            );
            CREATE TABLE IF NOT EXISTS runs(
                id INTEGER PRIMARY KEY,
                incident_id INTEGER,
                ts REAL NOT NULL,
                severity TEXT NOT NULL,
                code TEXT NOT NULL,
                title TEXT NOT NULL,
                explain TEXT,
                hint TEXT,
                checks TEXT NOT NULL,
                duration_ms REAL
            );
            CREATE TABLE IF NOT EXISTS suppressed_alerts(
                id INTEGER PRIMARY KEY,
                ts REAL NOT NULL,
                kuma_status INTEGER,
                monitor_detail TEXT,
                verdict_code TEXT,
                verdict_title TEXT,
                payload TEXT NOT NULL,
                reason TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS quality_samples(
                id INTEGER PRIMARY KEY,
                ts REAL NOT NULL,
                latency_ms REAL,
                jitter_ms REAL,
                loss_pct REAL,
                state TEXT
            );
            """
        )
        try:
            conn.execute("ALTER TABLE runs ADD COLUMN kind TEXT DEFAULT 'incident'")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE incidents ADD COLUMN ref TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute(
                "ALTER TABLE incidents ADD COLUMN false_alarm INTEGER DEFAULT 0"
            )
        except sqlite3.OperationalError:
            pass
        backfill_incident_refs(conn)
        from linkmoth_outage import init_outage_db
        from linkmoth_push import init_push_db
        from linkmoth_devices import init_device_db
        from linkmoth_webhooks import init_webhook_db
        init_outage_db(conn)
        init_push_db(conn)
        init_device_db(conn)
        init_webhook_db(conn)
    # SQLite can recreate the main file while enabling WAL on some platforms;
    # restore the private state-file mode after schema/journal initialization.
    try:
        os.chmod(DB_PATH, 0o600)
    except (AttributeError, OSError):
        pass


def make_incident_ref(inc_id, started_ts):
    day = time.strftime("%Y%m%d", time.localtime(started_ts))
    return f"INC-{day}-{int(inc_id):04d}"


def backfill_incident_refs(conn):
    rows = conn.execute(
        "SELECT id, started FROM incidents WHERE ref IS NULL OR ref = ''"
    ).fetchall()
    for row in rows:
        conn.execute(
            "UPDATE incidents SET ref=? WHERE id=?",
            (make_incident_ref(row["id"], row["started"]), row["id"]),
        )


def ensure_auto_vacuum():
    """Enable AUTO_VACUUM on new databases (SQLite only allows this before tables exist)."""
    if not DB_PATH.is_file():
        return 0, False
    with db() as conn:
        current = int(conn.execute("PRAGMA auto_vacuum").fetchone()[0])
    return current, False


def _run_incremental_vacuum():
    conn = sqlite3.connect(str(DB_PATH), timeout=60)
    try:
        conn.isolation_level = None
        conn.execute("PRAGMA incremental_vacuum(1000)")
    finally:
        conn.close()


def db_maintenance_info():
    """SQLite file stats and AUTO_VACUUM mode (does not replace manual VACUUM)."""
    info = {
        "path": str(DB_PATH),
        "exists": DB_PATH.is_file(),
        "size_bytes": 0,
        "auto_vacuum": 0,
        "auto_vacuum_label": "NONE",
        "page_count": 0,
        "page_size": 0,
        "freelist_count": 0,
        "journal_mode": "unknown",
        "busy_timeout_ms": DB_BUSY_TIMEOUT_MS,
        "lock_retries": 0,
    }
    if not info["exists"]:
        return info
    info["size_bytes"] = DB_PATH.stat().st_size
    with db() as conn:
        av = int(conn.execute("PRAGMA auto_vacuum").fetchone()[0])
        info["auto_vacuum"] = av
        info["auto_vacuum_label"] = AUTO_VACUUM_NAMES.get(av, str(av))
        info["page_count"] = int(conn.execute("PRAGMA page_count").fetchone()[0])
        info["page_size"] = int(conn.execute("PRAGMA page_size").fetchone()[0])
        info["freelist_count"] = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
        info["journal_mode"] = str(conn.execute("PRAGMA journal_mode").fetchone()[0]).upper()
    with DB_LOCK_RETRIES_LOCK:
        info["lock_retries"] = DB_LOCK_RETRIES
    return info


def vacuum_database(engine):
    """Repack SQLite pages. Blocks other engine DB work for the duration."""
    if not DB_PATH.is_file():
        return False, {"error": "database file not found"}
    with engine.lock:
        if engine.run_in_progress:
            return False, {"error": "diagnosis in progress — try again shortly"}
        size_before = DB_PATH.stat().st_size
        conn = sqlite3.connect(str(DB_PATH), timeout=60)
        try:
            conn.isolation_level = None
            conn.execute("VACUUM")
        except sqlite3.Error as exc:
            return False, {"error": str(exc)}
        finally:
            conn.close()
    size_after = DB_PATH.stat().st_size
    refreshed = db_maintenance_info()
    return True, {
        "size_before_bytes": size_before,
        "size_after_bytes": size_after,
        "bytes_reclaimed": max(0, size_before - size_after),
        "auto_vacuum": refreshed["auto_vacuum"],
        "auto_vacuum_label": refreshed["auto_vacuum_label"],
        "freelist_count": refreshed["freelist_count"],
        "page_count": refreshed["page_count"],
    }


def auto_vacuum(engine):
    """Background reclaim after janitor deletes — incremental when enabled, else occasional full VACUUM."""
    if not DB_PATH.is_file():
        return
    info = db_maintenance_info()
    if info["freelist_count"] <= 0:
        return
    mode = info["auto_vacuum"]
    try:
        if mode == 2:
            with engine.lock:
                if engine.run_in_progress:
                    return
                _run_incremental_vacuum()
        elif mode == 1 or (mode == 0 and info["freelist_count"] >= 200):
            vacuum_database(engine)
    except sqlite3.Error as exc:
        print(f"auto_vacuum: {exc}", file=sys.stderr, flush=True)


def run_cmd(args, timeout=10):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except FileNotFoundError:
        return -2, "tool missing"


def host_stats():
    """Return cheap, best-effort health data for the Linkmoth host.

    These readings help an operator distinguish a real network fault from a
    Pi that is hot, memory-starved, or out of disk.  All Linux-specific probes
    are optional so the dashboard remains usable on a normal Debian host.
    """
    global HOST_CPU_SAMPLE
    out = {
        "cpu_percent": None,
        "temperature_c": None,
        "memory_percent": None,
        "memory_used_bytes": None,
        "memory_total_bytes": None,
        "disk_percent": None,
        "disk_used_bytes": None,
        "disk_total_bytes": None,
        "load_1m": None,
        "uptime_seconds": None,
        "cpu_cores": os.cpu_count() or 1,
    }
    try:
        fields = (Path("/proc/stat").read_text().splitlines()[0]).split()[1:]
        values = [int(item) for item in fields]
        total = sum(values)
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        with HOST_STATS_LOCK:
            previous = HOST_CPU_SAMPLE
            HOST_CPU_SAMPLE = (total, idle)
        if previous:
            total_delta, idle_delta = total - previous[0], idle - previous[1]
            if total_delta > 0:
                out["cpu_percent"] = round(100.0 * (1 - idle_delta / total_delta), 1)
    except (OSError, ValueError, IndexError):
        pass
    try:
        mem = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            mem[key] = int(value.strip().split()[0]) * 1024
        total = mem.get("MemTotal")
        available = mem.get("MemAvailable")
        if total and available is not None:
            used = max(0, total - available)
            out.update({
                "memory_total_bytes": total,
                "memory_used_bytes": used,
                "memory_percent": round(100.0 * used / total, 1),
            })
    except (OSError, ValueError, IndexError):
        pass
    readings = []
    for sensor in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
        try:
            raw = int(sensor.read_text().strip())
            value = raw / 1000.0 if raw > 1000 else float(raw)
            if -20 <= value <= 150:
                readings.append(value)
        except (OSError, ValueError):
            continue
    if readings:
        out["temperature_c"] = round(max(readings), 1)
    try:
        usage = shutil.disk_usage("/")
        out.update({
            "disk_total_bytes": usage.total,
            "disk_used_bytes": usage.used,
            "disk_percent": round(100.0 * usage.used / usage.total, 1),
        })
    except OSError:
        pass
    try:
        out["load_1m"] = round(os.getloadavg()[0], 2)
    except (AttributeError, OSError):
        pass
    try:
        out["uptime_seconds"] = round(float(Path("/proc/uptime").read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        pass
    return out


def default_route():
    rc, out = run_cmd(["ip", "route", "show", "default"])
    if rc != 0 or not out:
        return None, None
    m = re.search(r"default via (\S+) dev (\S+)", out)
    return (m.group(1), m.group(2)) if m else (None, None)


def check_power():
    supply_ok, supply_detail, supply_bad = _read_power_supplies()
    rc, out = run_cmd(["vcgencmd", "get_throttled"])
    throttle_ok = None
    throttle_detail = ""
    if rc == 0:
        try:
            flags = int(out.split("=")[1], 16)
        except (IndexError, ValueError):
            throttle_ok = None
            throttle_detail = out
        else:
            now_bits = []
            if flags & 0x1:
                now_bits.append("undervoltage now")
            if flags & 0x4:
                now_bits.append("throttled now")
            past = flags & 0x50000
            if now_bits:
                throttle_ok = False
                throttle_detail = ", ".join(now_bits)
            elif past:
                throttle_ok = True
                throttle_detail = "ok now (undervoltage/throttling happened since boot)"
            else:
                throttle_ok = True
                throttle_detail = "power ok"
    if throttle_ok is None:
        for name_file in Path("/sys/class/hwmon").glob("hwmon*/name"):
            try:
                if name_file.read_text().strip() != "rpi_volt":
                    continue
                alarm = (name_file.parent / "in0_lcrit_alarm").read_text().strip()
                if alarm == "1":
                    throttle_ok = False
                    throttle_detail = "undervoltage now (hwmon)"
                else:
                    throttle_ok = True
                    throttle_detail = "power ok (hwmon)"
                break
            except OSError:
                continue
        if throttle_ok is None:
            throttle_ok = None
            throttle_detail = "no power sensor available"

    parts = [p for p in (throttle_detail, supply_detail) if p]
    detail = " · ".join(parts) if parts else "no power sensor available"

    if throttle_ok is False or supply_bad:
        return False, detail
    if throttle_ok is None and supply_ok is None:
        return None, detail
    if supply_ok is False:
        return False, detail
    return True, detail


def _read_power_supply_file(path):
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _read_power_supplies():
    """Read /sys/class/power_supply for PoE/USB-PD telemetry."""
    root = Path("/sys/class/power_supply")
    if not root.is_dir():
        return None, "", False
    notes = []
    any_online = False
    any_bad = False
    for supply in sorted(root.iterdir()):
        if not supply.is_dir():
            continue
        ptype = (_read_power_supply_file(supply / "type") or "").lower()
        if ptype == "battery":
            continue
        name = supply.name
        online_s = _read_power_supply_file(supply / "online")
        status = _read_power_supply_file(supply / "status") or ""
        if online_s == "0":
            any_bad = True
            notes.append(f"{name} offline")
            continue
        if online_s == "1":
            any_online = True
        status_l = status.lower()
        if status_l in ("discharging", "not charging", "unknown") and ptype in (
            "mains", "usb", "usb_hvdcp", "usb_pd", "usb_c", "ups",
        ):
            any_bad = True
            notes.append(f"{name} {status}")
        volt_note = ""
        volt_raw = _read_power_supply_file(supply / "voltage_now")
        if volt_raw and volt_raw.lstrip("-").isdigit():
            volts = int(volt_raw) / 1_000_000.0
            volt_note = f"{volts:.1f}V"
            if 0 < volts < 4.5 and ptype in ("usb", "usb_hvdcp", "usb_pd", "usb_c", "mains"):
                any_bad = True
                notes.append(f"{name} low {volt_note}")
        if not any_bad and (online_s == "1" or status_l == "charging"):
            label = ptype or name
            notes.append(f"{label} online" + (f" {volt_note}" if volt_note else ""))
    if not notes:
        return None, "", False
    if any_bad:
        return False, " · ".join(notes), True
    if any_online:
        return True, " · ".join(notes), False
    return None, " · ".join(notes), False


def check_link(dev):
    if not dev:
        return False, "no default route"
    try:
        carrier = (Path(f"/sys/class/net/{dev}/carrier").read_text().strip() == "1")
    except OSError:
        carrier = False
    if not carrier:
        return False, f"{dev}: no carrier"
    detail = f"{dev}: link up"
    warn = False
    if dev.startswith("wl"):
        try:
            for line in Path("/proc/net/wireless").read_text().splitlines():
                if line.strip().startswith(dev):
                    sig = float(line.split()[3].rstrip("."))
                    detail = f"{dev}: signal {sig:.0f} dBm"
                    if sig < -80:
                        return False, detail + " (very weak)"
        except (OSError, ValueError, IndexError):
            pass
    else:
        speed, duplex = _read_link_speed_duplex(dev)
        if speed is not None and speed > 0:
            detail = f"{dev}: link up, {speed} Mb/s"
            if speed < 1000:
                warn = True
        if duplex == "half":
            warn = True
        if warn:
            if speed is not None and 0 < speed < 1000:
                detail = f"⚠️ {dev}: link up, downgraded to {speed} Mb/s"
            elif duplex == "half":
                base = f"{speed} Mb/s" if speed and speed > 0 else "link up"
                detail = f"⚠️ {dev}: {base}, half-duplex"
            else:
                detail = f"⚠️ {detail}"
    return True, detail


def _read_link_speed_duplex(dev):
    speed = None
    duplex = None
    try:
        speed_s = Path(f"/sys/class/net/{dev}/speed").read_text().strip()
        if speed_s.lstrip("-").isdigit():
            val = int(speed_s)
            if val > 0:
                speed = val
    except OSError:
        pass
    try:
        duplex_s = Path(f"/sys/class/net/{dev}/duplex").read_text().strip().lower()
        if duplex_s in ("full", "half"):
            duplex = duplex_s
    except OSError:
        pass
    if speed is not None and duplex is not None:
        return speed, duplex
    ethtool_speed, ethtool_duplex = _ethtool_link(dev)
    return speed if speed is not None else ethtool_speed, duplex if duplex is not None else ethtool_duplex


def _ethtool_link(dev):
    rc, out = run_cmd(["ethtool", dev])
    if rc != 0 or not out:
        return None, None
    speed = None
    duplex = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Speed:"):
            m = re.search(r"(\d+)\s*Mb/s", line, re.I)
            if m:
                speed = int(m.group(1))
        elif line.startswith("Duplex:"):
            if "full" in line.lower():
                duplex = "full"
            elif "half" in line.lower():
                duplex = "half"
    return speed, duplex


def check_router_wlan(gateway_ok, include_evidence=False):
    """Use configured Wi-Fi clients as witnesses, not as monitored devices.

    A single reply proves that at least one radio/path is working.  Silent
    clients are kept as disagreement evidence because phones sleep and many
    operating systems block ping; they must not be presented as proof that a
    radio has crashed.
    """
    clients = CFG.get("target_wifi_clients") or []
    if not clients:
        result = (None, "not configured — skipped")
        return (*result, {}) if include_evidence else result
    if not gateway_ok:
        result = (None, "router LAN unreachable — skipped")
        return (*result, {}) if include_evidence else result
    ok, detail, _ms, evidence = probe_group([
        (client, ping(client, count=2, timeout=1)) for client in clients
    ])
    passed = evidence["probe_summary"]["passed"]
    attempted = evidence["probe_summary"]["attempted"]
    if ok:
        detail = f"{passed}/{attempted} configured Wi-Fi witnesses replied · {detail}"
    else:
        detail = (
            f"No configured Wi-Fi witness replied ({attempted} tried). "
            "This suggests a Wi-Fi problem, but sleeping clients or blocked "
            "ping can look the same."
        )
    result = (ok, detail)
    return (*result, evidence) if include_evidence else result


def ping(host, count=3, timeout=2):
    try:
        _network_targets([host])
    except ValueError:
        return False, "invalid ping target", None
    rc, out = run_cmd(
        ["ping", "-c", str(count), "-W", str(timeout), "-i", "0.3", "--", host],
        timeout=count * (timeout + 1) + 3,
    )
    if rc != 0:
        return False, f"{host}: no reply", None
    stats = parse_ping_stats(out)
    avg_ms = stats["avg_ms"]
    avg = f"{avg_ms:.0f} ms" if avg_ms is not None else "?"
    loss_s = f"{stats['loss_pct']:.0f}% loss" if stats["loss_pct"] else ""
    return True, f"{host}: {avg} {loss_s}".strip(), avg_ms


def parse_ping_stats(out):
    """Extract latency and loss from `ping -c` output.

    Returns min/avg/max/jitter in milliseconds (jitter = mdev, the round-trip
    deviation) and packet loss as a percentage; any field absent from the
    output comes back as None. Pure text parsing so it is easy to test.
    """
    stats = {
        "sent": None, "received": None, "loss_pct": None,
        "min_ms": None, "avg_ms": None, "max_ms": None, "jitter_ms": None,
    }
    counts = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out)
    if counts:
        stats["sent"] = int(counts.group(1))
        stats["received"] = int(counts.group(2))
    loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    if loss:
        stats["loss_pct"] = float(loss.group(1))
    rtt = re.search(
        r"=\s*([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))?\s*ms", out)
    if rtt:
        stats["min_ms"] = float(rtt.group(1))
        stats["avg_ms"] = float(rtt.group(2))
        stats["max_ms"] = float(rtt.group(3))
        if rtt.group(4) is not None:
            stats["jitter_ms"] = float(rtt.group(4))
    return stats


def measure_quality(targets, count=10, timeout=2):
    """Ping each target `count` times and return the best path's quality.

    Uses the lowest-loss / lowest-latency responding target as the
    representative sample (a single distant server should not, on its own, make
    the local connection look bad). Returns {latency_ms, jitter_ms, loss_pct,
    target} or None when nothing answered.
    """
    best = None
    for target in targets:
        try:
            _network_targets([target])
        except ValueError:
            continue
        rc, out = run_cmd(
            ["ping", "-c", str(count), "-W", str(timeout), "-i", "0.3", "--", target],
            timeout=count * (timeout + 1) + 5,
        )
        if rc != 0:
            continue
        s = parse_ping_stats(out)
        if s["avg_ms"] is None:
            continue
        sample = {
            "latency_ms": s["avg_ms"],
            "jitter_ms": s["jitter_ms"],
            "loss_pct": s["loss_pct"] if s["loss_pct"] is not None else 0.0,
            "target": str(target),
        }
        key = (sample["loss_pct"], sample["latency_ms"])
        if best is None or key < (best["loss_pct"], best["latency_ms"]):
            best = sample
    return best


def classify_quality(latency_ms, jitter_ms, loss_pct, qcfg):
    """Grade a quality sample as good/fair/poor with human reasons. Pure."""
    order = {"good": 0, "fair": 1, "poor": 2}
    state = "good"
    reasons = []

    def worse(level, why):
        nonlocal state
        if order[level] > order[state]:
            state = level
        reasons.append(why)

    if loss_pct is not None:
        if loss_pct >= qcfg["loss_bad_pct"]:
            worse("poor", f"{loss_pct:.0f}% packet loss")
        elif loss_pct >= qcfg["loss_warn_pct"]:
            worse("fair", f"{loss_pct:.0f}% packet loss")
    if latency_ms is not None:
        if latency_ms >= qcfg["latency_bad_ms"]:
            worse("poor", f"high latency {latency_ms:.0f} ms")
        elif latency_ms >= qcfg["latency_warn_ms"]:
            worse("fair", f"elevated latency {latency_ms:.0f} ms")
    if jitter_ms is not None:
        if jitter_ms >= qcfg["jitter_bad_ms"]:
            worse("poor", f"high jitter {jitter_ms:.0f} ms")
        elif jitter_ms >= qcfg["jitter_warn_ms"]:
            worse("fair", f"jitter {jitter_ms:.0f} ms")
    if latency_ms is None and jitter_ms is None and loss_pct is None:
        return {"state": "unknown", "reasons": ["no measurement"]}
    return {"state": state, "reasons": reasons}


def quality_config():
    """Quality settings merged over defaults (config.json may set a subset)."""
    merged = dict(DEFAULT_CONFIG["quality"])
    q = CFG.get("quality")
    if isinstance(q, dict):
        merged.update(q)
    return merged


def _dns_query_a(server, domain, timeout=2.0):
    """Stdlib UDP DNS A-record query. Returns True if the server answered.

    Uses a connected socket so the kernel drops any datagram not from
    server:53, and validates the transaction id + QR bit, so stray LAN UDP
    traffic (broadcast/multicast) can never be mistaken for a DNS answer.
    Only a yes/no is needed, not the resolved address.
    """
    labels = [l for l in domain.split(".") if l]
    if not labels or any(len(l) > 63 for l in labels):
        return False
    txn = secrets.token_bytes(2)
    header = txn + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0)  # RD set, QDCOUNT=1
    try:
        qname = b"".join(
            struct.pack("B", len(l)) + l.encode("ascii") for l in labels
        ) + b"\x00"
    except (UnicodeEncodeError, struct.error):
        return False
    query = header + qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.connect((server, 53))
        sock.send(query)
        resp = sock.recv(512)
    except (socket.timeout, OSError):
        return False
    finally:
        sock.close()
    if len(resp) < 12 or resp[0:2] != txn:
        return False
    flags_hi, flags_lo = resp[2], resp[3]
    if not (flags_hi & 0x80):        # QR bit — must be a response, not an echo
        return False
    if (flags_lo & 0x0F) != 0:       # RCODE — must be no-error
        return False
    ancount = struct.unpack(">H", resp[6:8])[0]
    truncated = bool(flags_hi & 0x02)  # TC — server answered, just over UDP size
    return ancount >= 1 or truncated


def dig(server, domain):
    try:
        ipaddress.ip_address(server)
        domain = _dns_domain(domain)
    except ValueError:
        return False, "invalid DNS target", None
    start = time.monotonic()
    answered = _dns_query_a(server, domain)
    ms = (time.monotonic() - start) * 1000
    if answered:
        return True, f"@{server}: answered in {ms:.0f} ms", ms
    return False, f"@{server}: no answer", None


def http_get(url, timeout=5):
    start = time.monotonic()
    try:
        parsed = urlparse(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return False, "invalid HTTPS target", None
        target = _https_probe_label(url)
        req = urlrequest.Request(url, headers={"User-Agent": "linkmoth/1.0"})
        class NoRedirect(urlrequest.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urlrequest.build_opener(
            urlrequest.ProxyHandler({}),
            NoRedirect(),
        )
        with opener.open(req, timeout=timeout) as r:
            ms = (time.monotonic() - start) * 1000
            return True, f"{target}: HTTP {r.status} in {ms:.0f} ms", ms
    except Exception as e:
        return False, f"{_https_probe_label(url)}: {e.__class__.__name__}", None


def any_ok(triples):
    ok = any(t[0] for t in triples)
    ms_values = [t[2] for t in triples if t[0] and t[2] is not None]
    return ok, "; ".join(t[1] for t in triples), (min(ms_values) if ms_values else None)


def probe_group(named_triples):
    """Summarize redundant probes without throwing away disagreements.

    The rung's traditional ``ok`` value remains true when any target answers,
    preserving fault attribution.  ``state`` and ``probes`` retain whether all
    targets agreed, so operators can distinguish a healthy redundant check
    from one surviving target masking another failed target.
    """
    results = list(named_triples)
    probes = []
    ms_values = []
    for target, result in results:
        ok, detail, ms = result
        if ok and ms is not None:
            ms_values.append(ms)
        probes.append({
            "target": str(target)[:253],
            "ok": bool(ok),
            "detail": str(detail)[:500],
            "ms": round(ms, 1) if ms is not None else None,
        })
    attempted = len(probes)
    passed = sum(1 for probe in probes if probe["ok"])
    failed = attempted - passed
    if passed == 0:
        state = "failed"
    elif failed:
        state = "partial"
    else:
        state = "passed"
    evidence = {
        "state": state,
        "probe_summary": {
            "attempted": attempted,
            "passed": passed,
            "failed": failed,
        },
        "probes": probes,
    }
    detail = "; ".join(probe["detail"] for probe in probes if probe["detail"])
    return passed > 0, detail, (min(ms_values) if ms_values else None), evidence


def _https_probe_label(url):
    """Return a credential-free label for configured HTTPS evidence."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or "HTTPS target"
        port = parsed.port
    except (TypeError, ValueError):
        return "HTTPS target"
    return f"{host}:{port}" if port not in (None, 443) else host


def _micro_step(label, ok, detail):
    return {"label": label, "ok": ok, "detail": detail}


def check_disk_pressure(path="/"):
    try:
        usage = shutil.disk_usage(path)
    except OSError as exc:
        return None, f"disk check unavailable: {exc}"
    if usage.total <= 0:
        return None, "disk size unknown"
    pct = usage.used * 100.0 / usage.total
    if usage.free <= 0 or pct >= 99.9:
        return False, f"disk {pct:.0f}% full on {path}"
    return True, f"disk {pct:.0f}% used on {path}"


LOCAL_DNS_ADAPTERS = {
    "pihole": {
        "name": "Pi-hole",
        "service": "pihole-FTL",
    },
    "unbound": {
        "name": "Unbound",
        "service": "unbound",
    },
    "dnsmasq": {
        "name": "dnsmasq",
        "service": "dnsmasq",
    },
}
_LOCAL_DNS_DETECT_LOCK = threading.Lock()
_LOCAL_DNS_DETECT_CACHE = {"expires": 0.0, "active": []}


def _local_ipv4_addresses():
    addresses = {"127.0.0.1"}
    try:
        for info in socket.getaddrinfo(
            socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM
        ):
            addresses.add(info[4][0])
    except OSError:
        pass
    rc, out = run_cmd(["ip", "-o", "-4", "addr", "show"])
    if rc == 0:
        for match in re.finditer(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", out):
            addresses.add(match.group(1))
    return addresses


# Interface name prefixes for non-LAN network kinds. Checked in order — a
# tunnel/VPN interface is the higher-severity case (typically routable from a
# remote network over the internet); a container bridge is host-local and
# lower severity. Anything not matched is treated as a normal LAN interface.
# NordVPN's WireGuard interface is named "nordlynx"; most other VPN clients
# use "tun"/"tap"/"wg"/"ppp"/"ipsec"/"utun" by convention.
_TUNNEL_IFACE_PREFIXES = (
    "tun", "tap", "wg", "tailscale", "zt", "ppp", "nordlynx", "wgcf", "ipsec", "utun",
)
_CONTAINER_IFACE_PREFIXES = ("docker", "br-", "veth", "podman", "virbr", "cni", "flannel", "cali")


def _classify_iface(iface, address):
    try:
        if ipaddress.IPv4Address(address).is_loopback or iface == "lo":
            return "loopback"
    except ipaddress.AddressValueError:
        pass
    lowered = iface.lower()
    if lowered.startswith(_TUNNEL_IFACE_PREFIXES):
        return "tunnel"
    if lowered.startswith(_CONTAINER_IFACE_PREFIXES):
        return "container"
    return "lan"


def classify_network_interfaces(raw_output=None):
    """List (iface, address, kind) for every IPv4 address on the host.

    kind is one of "lan", "tunnel", "container", "loopback". Used to warn
    when binding to 0.0.0.0 would expose Linkmoth beyond the LAN — e.g. over
    an active WireGuard/Tailscale/NordVPN interface, which is not something
    Linkmoth can otherwise see or rule out.
    """
    if raw_output is None:
        rc, raw_output = run_cmd(["ip", "-o", "-4", "addr", "show"])
        if rc != 0:
            return []
    results = []
    for match in re.finditer(
        r"^\d+:\s+(\S+?)(?:@\S+)?\s+inet\s+(\d+\.\d+\.\d+\.\d+)/",
        raw_output, re.MULTILINE,
    ):
        iface, address = match.group(1), match.group(2)
        results.append({
            "iface": iface, "address": address,
            "kind": _classify_iface(iface, address),
        })
    return results


def bind_exposure_risk(bind_addr, interfaces=None):
    """Return the list of non-LAN interfaces exposed by the given bind
    address, or [] if the bind is already narrow enough to avoid them."""
    if bind_addr not in ("0.0.0.0", "::"):
        return []  # a specific address only ever exposes that one interface
    if interfaces is None:
        interfaces = classify_network_interfaces()
    return [i for i in interfaces if i["kind"] in ("tunnel", "container")]


def local_dns_is_same_host(address):
    try:
        parsed = ipaddress.IPv4Address(address)
    except ipaddress.AddressValueError:
        return False
    return parsed.is_loopback or str(parsed) in _local_ipv4_addresses()


def _active_local_dns_adapters(refresh=False):
    now = time.monotonic()
    with _LOCAL_DNS_DETECT_LOCK:
        if not refresh and now < _LOCAL_DNS_DETECT_CACHE["expires"]:
            return list(_LOCAL_DNS_DETECT_CACHE["active"])
        active = []
        for key, adapter in LOCAL_DNS_ADAPTERS.items():
            rc, state = run_cmd(["systemctl", "is-active", adapter["service"]])
            if rc == 0 and state.strip() == "active":
                active.append(key)
        _LOCAL_DNS_DETECT_CACHE["active"] = list(active)
        _LOCAL_DNS_DETECT_CACHE["expires"] = now + 30
        return active


def local_dns_runtime_info(refresh=False):
    configured = normalize_local_dns_config(CFG.get("local_dns"))
    same_host = local_dns_is_same_host(configured["address"])
    requested = configured["provider"]
    effective = "generic"
    detected = False
    if same_host:
        if requested == "auto":
            active = _active_local_dns_adapters(refresh=refresh)
            if len(active) == 1:
                effective = active[0]
                detected = True
        else:
            effective = requested
    return {
        "configured": configured,
        "same_host": same_host,
        "provider_editable": same_host,
        "effective_provider": effective,
        "provider_detected": detected,
        "provider_name": (
            LOCAL_DNS_ADAPTERS.get(effective, {}).get("name")
            if effective != "generic" else None
        ),
        "remote_note": (
            None if same_host
            else "Remote resolvers are checked by DNS response only and always use generic guidance."
        ),
    }


def micro_local_dns(provider):
    """Same-host provider evidence. Never called for a remote resolver."""
    adapter = LOCAL_DNS_ADAPTERS.get(provider)
    if not adapter:
        return []
    service = adapter["service"]
    name = adapter["name"]
    steps = []
    rc, load_state = run_cmd(
        ["systemctl", "show", "-p", "LoadState", "--value", service]
    )
    if rc != 0 or load_state.strip() != "loaded":
        steps.append(_micro_step(
            f"{name} service", False,
            "systemd service not found — it may run in a container",
        ))
    else:
        rc, svc = run_cmd(["systemctl", "is-active", service])
        rc, sub = run_cmd(
            ["systemctl", "show", "-p", "SubState", "--value", service]
        )
        svc = svc.strip() or "unknown"
        sub = sub.strip() or "unknown"
        steps.append(_micro_step(
            f"{name} service",
            svc == "active",
            "service active" if svc == "active" else f"service {svc} ({sub})",
        ))
    disk_ok, disk_detail = check_disk_pressure("/")
    steps.append(_micro_step("Root disk space", disk_ok, disk_detail))
    return steps


def micro_pihole_dns():
    """Compatibility wrapper for callers of the old helper."""
    return micro_local_dns("pihole")


def _local_dns_failure_hint(check):
    provider = check.get("provider") or "generic"
    adapter = LOCAL_DNS_ADAPTERS.get(provider)
    micro = check.get("micro") or []
    for step in micro:
        if step.get("ok") is not False:
            continue
        label = (step.get("label") or "").lower()
        detail = (step.get("detail") or "").lower()
        if "disk" in label:
            suffix = (
                f", then restart {adapter['name']}"
                if adapter else ""
            )
            return f"Free disk space on the Linkmoth host{suffix}."
        if adapter and "service" in label:
            if "not found" in detail:
                return (
                    f"Check the {adapter['name']} service or container on the "
                    "Linkmoth host and confirm it is listening on port 53."
                )
            return (
                "SSH to the Linkmoth host and run: "
                f"sudo systemctl restart {adapter['service']}"
            )
    return (
        "Check the local resolver service and confirm it is listening on "
        f"{check.get('address') or 'the configured address'} port 53."
    )


def run_ladder():
    started = time.monotonic()
    gw, dev = default_route()
    checks = []

    def add(cid, label, ok, detail, ms=None, micro=None, **extra):
        state = extra.pop("state", None)
        if state is None:
            state = "skipped" if ok is None else ("passed" if ok else "failed")
        entry = {
            "id": cid,
            "label": label,
            "ok": ok,
            "state": state,
            "detail": detail,
            "ms": (round(ms, 1) if ms is not None else None),
        }
        if micro:
            entry["micro"] = micro
        entry.update(extra)
        checks.append(entry)

    ok, detail = check_power()
    add("power", "Host power", ok, detail)
    ok, detail = check_link(dev)
    add(
        "link", "Host network link", ok, detail,
        state=("degraded" if ok and "⚠️" in detail else None),
        interface=dev,
    )
    gw_ok = False
    if gw:
        gw_ok, detail, ms = ping(gw)
        add("gateway", "Router (LAN)", gw_ok, detail, ms, target=gw)
    else:
        add("gateway", "Router (LAN)", False, "no default gateway")
    wlan_result = check_router_wlan(gw_ok, include_evidence=True)
    # Keep lightweight monkey-patches and older embedders that return the
    # historical two-value shape working during the richer-evidence upgrade.
    if len(wlan_result) == 3:
        wlan_ok, wlan_detail, wlan_evidence = wlan_result
    else:
        wlan_ok, wlan_detail = wlan_result
        wlan_evidence = {}
    if wlan_ok is None:
        add("router_wlan", "Router Wireless (WLAN)", None, wlan_detail)
    else:
        add(
            "router_wlan", "Router Wireless (WLAN)", wlan_ok, wlan_detail,
            **wlan_evidence,
        )
    dns_runtime = local_dns_runtime_info(refresh=True)
    dns_cfg = dns_runtime["configured"]
    if dns_cfg["mode"] == "disabled":
        add(
            "local_dns", "Local DNS resolver", None, "disabled in config",
            address=dns_cfg["address"], provider="generic",
        )
    else:
        address = dns_cfg["address"]
        ok, detail, ms = dig(address, CFG["dns_test_domain"])
        provider = dns_runtime["effective_provider"]
        provider_name = dns_runtime["provider_name"]
        if (
            dns_cfg["mode"] == "auto"
            and dns_runtime["same_host"]
            and provider == "generic"
            and not ok
        ):
            add(
                "local_dns", "Local DNS resolver", None,
                "no same-host DNS resolver detected — skipped",
                address=address, provider="generic",
            )
        else:
            if provider_name:
                detail = f"{provider_name} · {detail}"
            micro = (
                micro_local_dns(provider)
                if ok is False and dns_runtime["same_host"] and provider_name
                else None
            )
            add(
                "local_dns", "Local DNS resolver", ok, detail, ms,
                micro=micro, address=address, provider=provider,
                provider_name=provider_name,
            )
    ok, detail, ms, evidence = probe_group([
        (server, dig(server, CFG["dns_test_domain"]))
        for server in CFG["upstream_dns"]
    ])
    add("upstream_dns", "Upstream DNS (direct)", ok, detail, ms, **evidence)
    ok, detail, ms, evidence = probe_group([
        (target, ping(target)) for target in CFG["ping_targets"]
    ])
    add("raw_ping", "Raw internet (ping)", ok, detail, ms, **evidence)
    ok, detail, ms, evidence = probe_group([
        (_https_probe_label(url), http_get(url)) for url in CFG["https_targets"]
    ])
    add("https", "Web (HTTPS)", ok, detail, ms, **evidence)

    duration_ms = (time.monotonic() - started) * 1000
    return checks, duration_ms


def normalize_stored_check(check):
    """Translate the old Pi-hole-shaped rung without rewriting history."""
    item = dict(check)
    if item.get("id") == "pihole_dns":
        item["id"] = "local_dns"
        old_label = str(item.get("label") or "")
        item["label"] = "Local DNS resolver"
        if "pi-hole" in old_label.lower():
            item.setdefault("provider", "pihole")
            item.setdefault("provider_name", "Pi-hole")
        else:
            item.setdefault("provider", "generic")
    if "state" not in item:
        if item.get("ok") is None:
            item["state"] = "skipped"
        elif item.get("ok") is False:
            item["state"] = "failed"
        elif item.get("id") == "link" and "⚠️" in str(item.get("detail") or ""):
            item["state"] = "degraded"
        else:
            item["state"] = "passed"
    return item


def normalize_stored_checks(checks):
    return [normalize_stored_check(check) for check in (checks or [])]


def normalize_stored_verdict(item):
    """Return a copy with neutral Local DNS identifiers and title."""
    out = dict(item)
    if out.get("code") == "pihole_broken":
        out["code"] = "local_dns_broken"
        out["title"] = "Local DNS resolver stopped answering — internet itself is fine"
    if out.get("verdict_code") == "pihole_broken":
        out["verdict_code"] = "local_dns_broken"
        out["verdict_title"] = (
            "Local DNS resolver stopped answering — internet itself is fine"
        )
    return out


def verdict(checks):
    checks = normalize_stored_checks(checks)
    c = {ch["id"]: ch for ch in checks}

    def ok(cid):
        return c[cid]["ok"] is not False

    if not ok("link"):
        v = ("bad", "pi_link", "Linkmoth's own network connection is unavailable",
             "I can't see the network at all, so I can't judge anyone else. " + c["link"]["detail"],
             "Check the Linkmoth host's cable, Wi-Fi, and default route first; downstream verdicts are unreliable.")
    elif not ok("gateway"):
        v = ("bad", "router_down", "Router isn't answering on the LAN",
             "Linkmoth's own link is fine but the router doesn't reply. Everything in the house will look down.",
             "Check router power and cables, then give it a reboot.")
    elif not ok("upstream_dns") and not ok("raw_ping") and not ok("https"):
        v = ("bad", "wan_down",
             "Internet is dead beyond the router — likely internet provider outage or router WAN cable fault",
             "LAN and router are fine, but direct DNS, ping, and HTTPS all fail beyond them.",
             "Check the router's WAN cable and WAN light, then your internet provider's status page.")
    elif not ok("upstream_dns") and not ok("raw_ping"):
        v = (
            "warn", "restricted_connectivity",
            "Web access works, but direct DNS and ping are being blocked",
            "HTTPS succeeds, so the internet is not down. Direct DNS and ping both fail, which points to filtering, a VPN, or network policy.",
            "Do not reboot everything yet; check VPN, firewall, parental-control, or guest-network settings first.",
        )
    elif not ok("local_dns") and ok("upstream_dns"):
        local = c["local_dns"]
        micro = local.get("micro") or []
        hint = _local_dns_failure_hint(local)
        explain = (
            "Router and upstream DNS respond, but the configured local DNS "
            "resolver does not. Devices that use it may lose name resolution."
        )
        provider_name = local.get("provider_name")
        if provider_name:
            explain += f" The same-host resolver is {provider_name}."
        failed = [m["detail"] for m in micro if m.get("ok") is False]
        if failed:
            explain += " Likely cause: " + "; ".join(failed) + "."
        v = (
            "bad", "local_dns_broken",
            "Local DNS resolver stopped answering — internet itself is fine",
            explain, hint,
        )
    elif not ok("upstream_dns"):
        v = ("bad", "upstream_dns_down", "Routing works but public DNS resolvers don't answer",
             "Ping to the outside works, yet 1.1.1.1/8.8.8.8 won't answer DNS. Unusual — possibly ISP DNS interference.",
             "Try again in a few minutes; if it persists, contact your internet provider.")
    elif not ok("raw_ping"):
        v = ("warn", "partial_routing", "DNS answers but ping to the internet fails",
             "Could be ICMP filtering or flaky routing. Web may still work.",
             "Watch the next re-checks; if HTTPS stays green this is cosmetic.")
    elif not ok("https"):
        v = ("warn", "web_broken", "DNS and routing are fine but HTTPS fetches fail",
             "Name resolution and ping work, yet web requests don't complete.",
             "Could be a captive portal, filtering, or a transient. Re-check will confirm.")
    elif c["power"]["ok"] is False:
        v = (
            "warn", "host_power", "Linkmoth host power is unstable",
            "The network path answers, but the host reports " + c["power"]["detail"]
            + ". This can make later network evidence unreliable.",
            "Fix the host's power supply or cable, then run the diagnosis again.",
        )
    elif "⚠️" in (c["link"].get("detail") or ""):
        v = ("warn", "link_degraded", "Host Ethernet link is degraded",
             "The link is up but negotiated below gigabit or half-duplex: " + c["link"]["detail"],
             "Try another cable or switch port; bad cabling often drops speed before the link drops entirely.")
    elif c.get("router_wlan", {}).get("ok") is False:
        v = ("warn", "router_wlan_down", "Configured Wi-Fi witnesses are not answering",
             c["router_wlan"]["detail"],
             "Confirm one witness is awake and accepts ping before changing or rebooting the router.")
    else:
        partial = [
            ch.get("label") or ch.get("id") or "check" for ch in checks
            if ch.get("state") == "partial"
            and ch.get("id") in ("router_wlan", "upstream_dns", "raw_ping", "https")
        ]
        if partial:
            names = ", ".join(partial)
            v = (
                "ok", "all_clear", "Network path works, but test targets disagree",
                "Every required layer has a working path. Some redundant targets did not answer: "
                + names + ".",
                "Run one fresh diagnosis. If the same target keeps failing, replace that diagnostic target instead of treating it as a network outage.",
            )
        else:
            v = ("ok", "all_clear", "All clear — everything answers",
                 "Router, local DNS, upstream DNS, ping and HTTPS all respond normally.",
                 "")
    sev, code, title, explain, hint = v
    if c["power"]["ok"] is False and code != "host_power":
        sev = "bad" if sev == "bad" else "warn"
        explain += " Also: the host reports " + c["power"]["detail"] + " — a weak power supply causes ghost problems."
    return {"severity": sev, "code": code, "title": title, "explain": explain, "hint": hint}


def confidence_assessment(checks):
    """Return a verdict confidence level and the evidence behind that limit."""
    c = {ch["id"]: ch for ch in checks}
    if c.get("link", {}).get("ok") is False:
        return {
            "level": "low",
            "reason": "Linkmoth's own network link failed, so it cannot reliably judge anything beyond the host.",
        }
    if c.get("power", {}).get("ok") is False:
        return {
            "level": "medium",
            "reason": "The host reports a power problem; undervoltage can create misleading network symptoms.",
        }
    if c.get("router_wlan", {}).get("ok") is False:
        return {
            "level": "medium",
            "reason": "Wi-Fi witnesses disagreed; they are supporting evidence, not a definitive router verdict.",
        }
    if any(
        c.get(cid, {}).get("state") == "partial"
        for cid in ("router_wlan", "upstream_dns", "raw_ping", "https")
    ):
        return {
            "level": "medium",
            "reason": "Redundant targets disagreed, so Linkmoth found a usable path but not unanimous evidence.",
        }
    return {
        "level": "high",
        "reason": "The Linkmoth host was healthy and the relevant independent checks agreed.",
    }


def confidence_from_checks(checks):
    """Compatibility helper for callers that need only the confidence level."""
    return confidence_assessment(checks)["level"]


class Engine:
    def __init__(self):
        self.state_dir = STATE_DIR
        self.lock = threading.Lock()
        self.loop_thread = None
        self.run_in_progress = False
        self._ladder_cache = None
        self._ladder_cache_lock = threading.Lock()
        self._ladder_cache_cond = threading.Condition(self._ladder_cache_lock)
        self._ladder_inflight = False
        self._last_verify_mono = 0.0

    def resume_after_startup(self):
        """Continue recheck loop for an open incident left by a prior process."""
        inc = self.open_incident()
        if not inc:
            return
        with self.lock:
            alive = self.loop_thread is not None and self.loop_thread.is_alive()
            if alive:
                return
            self.loop_thread = threading.Thread(
                target=self._loop, args=(inc["id"],), daemon=True,
            )
            self.loop_thread.start()
        label = inc.get("ref") or f"#{inc['id']}"
        print(f"resumed open incident {label}", flush=True)

    def _ladder_cache_ttl(self):
        return max(1, int(CFG.get("ladder_cache_seconds", 10)))

    def _store_ladder_cache(self, checks, duration_ms, v):
        with self._ladder_cache_cond:
            self._ladder_cache = {
                "mono_ts": time.monotonic(),
                "checks": checks,
                "duration_ms": duration_ms,
                "verdict": dict(v),
            }

    def run_ladder_cached(self, force=False):
        """Run fault ladder with optional TTL cache and singleflight coalescing."""
        ttl = self._ladder_cache_ttl()
        if not force:
            with self._ladder_cache_cond:
                hit = self._ladder_cache
                if hit and (time.monotonic() - hit["mono_ts"]) <= ttl:
                    return hit["checks"], hit["duration_ms"], dict(hit["verdict"]), True
                while self._ladder_inflight:
                    self._ladder_cache_cond.wait(timeout=max(0.1, ttl))
                    hit = self._ladder_cache
                    if hit and (time.monotonic() - hit["mono_ts"]) <= ttl:
                        return hit["checks"], hit["duration_ms"], dict(hit["verdict"]), True
                self._ladder_inflight = True
        try:
            with self.lock:
                if self.run_in_progress:
                    if not force:
                        with self._ladder_cache_cond:
                            hit = self._ladder_cache
                            if hit:
                                return hit["checks"], hit["duration_ms"], dict(hit["verdict"]), True
                    return None
                self.run_in_progress = True
            try:
                checks, duration_ms = run_ladder()
                v = verdict(checks)
                self._store_ladder_cache(checks, duration_ms, v)
                return checks, duration_ms, v, False
            finally:
                self.run_in_progress = False
        finally:
            if not force:
                with self._ladder_cache_cond:
                    self._ladder_inflight = False
                    self._ladder_cache_cond.notify_all()

    def open_incident(self):
        with db() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE resolved IS NULL ORDER BY id DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None

    def evaluate_network_for_proxy(self, max_age=300):
        """Recent ladder verdict or a fresh run for Uptime Kuma alert proxy decisions."""
        from linkmoth_outage import OUTAGE_TRACKER
        if OUTAGE_TRACKER.is_active(db):
            max_age = min(max_age, 30)
        with db() as conn:
            row = conn.execute(
                "SELECT ts, severity, code, title, explain, hint, checks FROM runs"
                " ORDER BY id DESC LIMIT 1"
            ).fetchone()

        def _verdict_from_row(r):
            return normalize_stored_verdict({
                "severity": r["severity"],
                "code": r["code"],
                "title": r["title"],
                "explain": r["explain"],
                "hint": r["hint"],
            })

        now = time.time()
        if row and (now - row["ts"]) <= max_age:
            try:
                checks = normalize_stored_checks(json.loads(row["checks"]))
            except (json.JSONDecodeError, TypeError):
                checks = []
            return _verdict_from_row(row), checks, True

        out = self.run_ladder_cached(force=False)
        if out is None:
            if row:
                try:
                    checks = normalize_stored_checks(json.loads(row["checks"]))
                except (json.JSONDecodeError, TypeError):
                    checks = []
                return _verdict_from_row(row), checks, True
            return {
                "severity": "ok",
                "code": "all_clear",
                "title": "No recent data",
                "explain": "",
                "hint": "",
            }, [], False

        checks, duration_ms, v, cached = out
        if not cached:
            with db() as conn:
                conn.execute(
                    "INSERT INTO runs(incident_id, ts, severity, code, title, explain, hint, checks, duration_ms, kind)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (None, time.time(), v["severity"], v["code"], v["title"],
                     v["explain"], v["hint"], json.dumps(checks), duration_ms, "kuma-proxy"),
                )
            self._observe_network(v, checks, "kuma-proxy")
        return v, checks, cached

    def has_active_global_outage(self):
        from linkmoth_kuma_proxy import is_effective_global_outage
        from linkmoth_outage import OUTAGE_TRACKER
        if OUTAGE_TRACKER.is_active(db):
            return True
        inc = self.open_incident()
        if not inc:
            return False
        with db() as conn:
            row = conn.execute(
                "SELECT code, checks FROM runs WHERE incident_id=? ORDER BY id DESC LIMIT 1",
                (inc["id"],),
            ).fetchone()
        if not row:
            return False
        try:
            checks = normalize_stored_checks(json.loads(row["checks"]))
        except (json.JSONDecodeError, TypeError):
            checks = []
        return is_effective_global_outage(
            normalize_stored_verdict({"code": row["code"]}), checks
        )

    def _notify_outage_recovery(
        self,
        prior_fault,
        recovery_verdict,
        checks,
        digest,
        cfg,
        duration_s,
    ):
        from linkmoth_notify import notify_recovery
        notify_recovery(
            cfg, STATE_DIR, db,
            prior_fault=prior_fault,
            recovery_verdict=recovery_verdict,
            checks=checks,
            digest=digest,
            duration_s=duration_s,
            incident=None,
            source="outage-tracker",
        )
        # WAN is back — deliver webhook events that queued during the outage.
        from linkmoth_webhooks import wake_drain
        wake_drain()

    def open_incident_meta(self):
        inc = self.open_incident()
        if not inc:
            return None
        with db() as conn:
            runs = [
                normalize_stored_verdict(dict(r)) for r in conn.execute(
                    "SELECT ts, severity, code, title FROM runs"
                    " WHERE incident_id=? ORDER BY id",
                    (inc["id"],),
                )
            ]
        last = runs[-1] if runs else None
        return {
            "id": inc["id"],
            "ref": inc.get("ref"),
            "started": inc["started"],
            "source": inc.get("source"),
            "detail": inc.get("detail"),
            "run_count": len(runs),
            "diagnosing": (
                self.run_in_progress
                or (self.loop_thread is not None and self.loop_thread.is_alive())
            ),
            "last_run": last,
        }

    def recheck_open_incident(self):
        inc = self.open_incident()
        if not inc:
            return None, "no open incident"
        return self.diagnose_once(inc["id"], kind="incident"), None

    def verify_cooldown_remaining(self):
        """Atomically check-and-stamp the verify cooldown; 0.0 means allowed."""
        with self.lock:
            now = time.monotonic()
            elapsed = now - self._last_verify_mono
            if elapsed < VERIFY_COOLDOWN_SECONDS:
                return VERIFY_COOLDOWN_SECONDS - elapsed
            self._last_verify_mono = now
            return 0.0

    def verify_fix(self):
        """Fresh, uncached diagnosis for guided troubleshooting. Attaches to
        the currently-open incident if any, else runs standalone. Returns
        (verdict, checks) or None if a diagnosis is already running."""
        inc = self.open_incident()
        return self.diagnose_once(
            incident_id=inc["id"] if inc else None, kind="verify",
            force=True, return_checks=True,
        )

    def last_run_checks(self):
        with db() as conn:
            row = conn.execute(
                "SELECT checks FROM runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if not row:
            return []
        try:
            return normalize_stored_checks(json.loads(row["checks"]))
        except (json.JSONDecodeError, TypeError):
            return []

    def close_open_incident(self):
        inc = self.open_incident()
        if not inc:
            return False, "no open incident"
        inc_id = inc["id"]
        recovery_verdict = {
            "severity": "ok",
            "code": "all_clear",
            "title": "Manually closed — all clear",
            "explain": "Closed from the dashboard.",
            "hint": "",
        }
        with db() as conn:
            cur = conn.execute(
                "UPDATE incidents SET resolved=?, verdict_code=?, verdict_title=?"
                " WHERE id=? AND resolved IS NULL",
                (time.time(), recovery_verdict["code"], recovery_verdict["title"], inc_id),
            )
        if cur.rowcount:
            self._emit_webhook(inc_id, "fault_closed", recovery_verdict)
        return True, dict(inc)

    def mark_false_alarm(self, ref=None):
        """Flag an incident as a false alarm; closes it if still open."""
        false_alarm_verdict = {
            "severity": "ok",
            "code": "all_clear",
            "title": "Marked as false alarm",
            "explain": "Marked as a false alarm from the dashboard.",
            "hint": "",
        }
        if ref:
            with db() as conn:
                row = conn.execute(
                    "SELECT * FROM incidents WHERE ref=?", (ref,)
                ).fetchone()
            if not row:
                return False, "no incident with that reference"
            inc = dict(row)
        else:
            inc = self.open_incident()
            if not inc:
                return False, "no open incident"
        inc_id = inc["id"]
        with db() as conn:
            conn.execute(
                "UPDATE incidents SET false_alarm=1 WHERE id=?", (inc_id,)
            )
            cur = conn.execute(
                "UPDATE incidents SET resolved=?, verdict_code=?, verdict_title=?"
                " WHERE id=? AND resolved IS NULL",
                (
                    time.time(), false_alarm_verdict["code"],
                    false_alarm_verdict["title"], inc_id,
                ),
            )
        self._emit_webhook(inc_id, "false_alarm_marked", false_alarm_verdict)
        if cur.rowcount:
            self._emit_webhook(inc_id, "fault_closed", false_alarm_verdict)
        return True, dict(inc)

    def _observe_network(self, verdict, checks, kind):
        from linkmoth_outage import OUTAGE_TRACKER
        OUTAGE_TRACKER.observe(
            verdict, checks, CFG, db, self._notify_outage_recovery,
        )

    def diagnose_once(self, incident_id=None, kind=None, force=None,
                      return_checks=False):
        kind = kind or ("incident" if incident_id else "manual")
        if force is None:
            force = kind in ("incident", "manual")
        out = self.run_ladder_cached(force=force)
        if out is None:
            return None
        checks, duration_ms, v, _cached = out
        with db() as conn:
            conn.execute(
                "INSERT INTO runs(incident_id, ts, severity, code, title, explain, hint, checks, duration_ms, kind)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (incident_id, time.time(), v["severity"], v["code"], v["title"],
                 v["explain"], v["hint"], json.dumps(checks), duration_ms, kind),
            )
        self._observe_network(v, checks, kind)
        if kind in ("manual", "verify"):
            self._emit_webhook(incident_id, "diagnosis_run", v, checks=checks)
        if return_checks:
            return v, checks
        return v

    def _incident_by_id(self, inc_id):
        with db() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id=?", (inc_id,)).fetchone()
            return normalize_stored_verdict(dict(row)) if row else None

    def _latest_run_checks(self, inc_id):
        with db() as conn:
            row = conn.execute(
                "SELECT checks FROM runs WHERE incident_id=? ORDER BY id DESC LIMIT 1",
                (inc_id,),
            ).fetchone()
        if not row:
            return []
        try:
            return normalize_stored_checks(json.loads(row["checks"]))
        except (json.JSONDecodeError, TypeError):
            return []

    def _emit_webhook(self, inc_id, event, verdict, checks=None, duration_s=None):
        """Queue an outbound webhook event; never raises, never suppressed
        during outages (deliveries wait in the queue for WAN recovery)."""
        try:
            from linkmoth_webhooks import build_event_context, emit_event
            inc = self._incident_by_id(inc_id) if inc_id else None
            if checks is None:
                checks = self._latest_run_checks(inc_id) if inc_id else []
            if duration_s is None and inc and event in (
                "fault_recovered", "fault_closed", "false_alarm_marked",
            ):
                duration_s = max(
                    0.0, time.time() - float(inc.get("started") or time.time())
                )
            ctx = build_event_context(
                event, verdict=verdict, incident=inc, checks=checks,
                duration_s=duration_s,
            )
            emit_event(db, event, ctx)
        except Exception as e:
            print(f"webhook emit error: {e}", file=sys.stderr, flush=True)

    def _discord_notify(self, inc_id, status_type, verdict, prior_fault=None):
        try:
            from linkmoth_kuma_proxy import flush_suppression_digest, is_effective_global_outage
            from linkmoth_notify import notify_fault, notify_recovery
            from linkmoth_outage import is_global_fault_code
            inc = self._incident_by_id(inc_id)
            if not inc:
                return
            checks = self._latest_run_checks(inc_id)
            if status_type == "fault":
                if is_effective_global_outage(verdict, checks):
                    return
                notify_fault(CFG, STATE_DIR, db, inc, verdict, checks)
                return
            if status_type == "recovery":
                if is_global_fault_code((prior_fault or {}).get("code")):
                    return
                digest = flush_suppression_digest(db, recovery_ts=time.time())
                notify_recovery(
                    CFG, STATE_DIR, db,
                    prior_fault=prior_fault or {},
                    recovery_verdict=verdict,
                    checks=checks,
                    digest=digest,
                    duration_s=max(0.0, time.time() - float(inc.get("started") or time.time())),
                    incident=inc,
                    source="incident-loop",
                )
        except Exception as e:
            print(f"notify error: {e}", file=sys.stderr, flush=True)

    def trigger(self, source, detail=""):
        inc = self.open_incident()
        if inc is None:
            started = time.time()
            with db() as conn:
                cur = conn.execute(
                    "INSERT INTO incidents(started, source, detail) VALUES(?,?,?)",
                    (started, source, detail),
                )
                inc_id = cur.lastrowid
                ref = make_incident_ref(inc_id, started)
                conn.execute("UPDATE incidents SET ref=? WHERE id=?", (ref, inc_id))
        else:
            inc_id = inc["id"]
            with db() as conn:
                conn.execute(
                    "UPDATE incidents SET detail = detail || ' | ' || ? WHERE id=?",
                    (f"{source}: {detail}"[:300], inc_id),
                )
        with self.lock:
            alive = self.loop_thread is not None and self.loop_thread.is_alive()
            if not alive:
                self.loop_thread = threading.Thread(
                    target=self._loop, args=(inc_id,), daemon=True
                )
                self.loop_thread.start()
        return inc_id

    def _loop(self, inc_id):
        consecutive_ok = 0
        worst = None
        fault_notified = False
        last_emitted = None
        deadline = time.time() + CFG["incident_max_hours"] * 3600
        schedule = list(CFG["recheck_seconds"])
        step = 0
        t0 = time.time()
        while time.time() < deadline:
            target = t0 + schedule[step] if step < len(schedule) else None
            if target:
                time.sleep(max(0.0, target - time.time()))
                step += 1
            else:
                time.sleep(CFG["recheck_repeat"])
            inc = self._incident_by_id(inc_id)
            if not inc or inc.get("resolved"):
                return  # closed externally (manual close / false alarm)
            v = self.diagnose_once(inc_id, kind="incident")
            if v is None:
                continue
            if v["severity"] == "ok":
                consecutive_ok += 1
                if consecutive_ok >= 2:
                    recovery_verdict = {
                        "severity": "ok",
                        "code": "all_clear",
                        "title": "All clear — everything answers",
                        "explain": v.get("explain", ""),
                        "hint": "",
                    }
                    self._discord_notify(
                        inc_id, "recovery", recovery_verdict,
                        prior_fault=worst if fault_notified else None,
                    )
                    self._emit_webhook(inc_id, "fault_recovered", recovery_verdict)
                    break
            else:
                consecutive_ok = 0
                # Preserve the incident's strongest confirmed attribution.
                # A later warning often means partial recovery; it must not
                # overwrite an earlier bad WAN/router fault in the final
                # incident record or recovery handoff.
                rank = {"ok": 0, "warn": 1, "bad": 2}
                if (
                    worst is None
                    or rank.get(v.get("severity"), 0)
                    >= rank.get(worst.get("severity"), 0)
                ):
                    worst = v
                if not fault_notified:
                    fault_notified = True
                    self._discord_notify(inc_id, "fault", v)
                    event = (
                        "degradation_detected" if v["severity"] == "warn"
                        else "fault_opened"
                    )
                    self._emit_webhook(inc_id, event, v)
                    last_emitted = (v["code"], v["severity"])
                elif (v["code"], v["severity"]) != last_emitted:
                    self._emit_webhook(inc_id, "fault_updated", v)
                    last_emitted = (v["code"], v["severity"])
        final = worst or {"severity": "ok", "code": "all_clear",
                          "title": "Nothing wrong seen from the network side"}
        with db() as conn:
            cur = conn.execute(
                "UPDATE incidents SET resolved=?, verdict_code=?, verdict_title=?"
                " WHERE id=? AND resolved IS NULL",
                (time.time(), final["code"], final["title"], inc_id),
            )
        if cur.rowcount:
            self._emit_webhook(inc_id, "fault_closed", final)

    def status(self):
        with db() as conn:
            last = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
            incidents = conn.execute(
                "SELECT i.*, (SELECT COUNT(*) FROM runs r WHERE r.incident_id=i.id) AS run_count"
                " FROM incidents i ORDER BY i.id DESC LIMIT 20"
            ).fetchall()
            runs_of_open = []
            open_inc = self.open_incident()
            if open_inc:
                runs_of_open = [
                    normalize_stored_verdict(dict(r)) for r in conn.execute(
                        "SELECT ts, severity, code, title FROM runs WHERE incident_id=? ORDER BY id",
                        (open_inc["id"],),
                    )
                ]
        last_d = None
        patterns = None
        if last:
            last_d = normalize_stored_verdict(dict(last))
            last_d["checks"] = normalize_stored_checks(json.loads(last_d["checks"]))
            if last_d.get("severity") != "ok" and last_d.get("code"):
                patterns = self.patterns(code=last_d["code"])
        try:
            kuma_url = _kuma_url(CFG.get("kuma_url", "auto"))
        except ValueError:
            kuma_url = ""
        from linkmoth_outage import OUTAGE_TRACKER
        from linkmoth_push import list_subscriptions, push_available
        return {
            "now": time.time(),
            "diagnosing": self.run_in_progress or (
                self.loop_thread is not None and self.loop_thread.is_alive()
            ),
            "open_incident": (
                normalize_stored_verdict(open_inc) if open_inc else None
            ),
            "open_incident_meta": self.open_incident_meta(),
            "open_incident_runs": runs_of_open,
            "last_run": last_d,
            "patterns": patterns,
            "incidents": [
                normalize_stored_verdict(dict(i)) for i in incidents
            ],
            "stats": self.stats(),
            "history": self.history(),
            "history_meta": self.history_meta(),
            "kuma_url": kuma_url,
            "settings": public_settings(),
            "local_dns": local_dns_runtime_info(),
            "database": db_maintenance_info(),
            "host": host_stats(),
            "outage_active": OUTAGE_TRACKER.summary(db),
            "push": {
                "available": push_available(STATE_DIR),
                "enabled": bool(CFG.get("push_notifications_enabled", True)),
                "subscribers": len(list_subscriptions(db)),
            },
            "app": {
                "version": VERSION,
                "github": GITHUB_REPO,
                "changelog": CHANGELOG_URL,
            },
        }

    def stats(self):
        now = time.time()
        cutoff = now - 30 * 86400
        with db() as conn:
            first_run = conn.execute("SELECT MIN(ts) AS t FROM runs").fetchone()["t"]
            inc = [dict(r) for r in conn.execute(
                "SELECT * FROM incidents WHERE started > ?", (cutoff,))]
        period = max(now - max(first_run or now, cutoff), 3600)
        downtime = 0.0
        blame = {}
        false_alarms = 0
        for i in inc:
            code = normalize_stored_verdict(i).get("verdict_code")
            if i["resolved"] is None:
                downtime += now - i["started"]
            elif code and code != "all_clear":
                downtime += i["resolved"] - i["started"]
                blame[code] = blame.get(code, 0) + 1
            elif code == "all_clear":
                false_alarms += 1
        return {
            "incidents_30d": len(inc),
            "false_alarms_30d": false_alarms,
            "downtime_s": round(downtime),
            "uptime_pct": round(max(0.0, 100.0 * (1 - downtime / period)), 2),
            "blame": blame,
        }

    @staticmethod
    def _pattern_for(incs):
        """Correlation summary for one verdict code, with an honest
        minimum-sample rule so 1–2 incidents never read as a 'pattern'."""
        count = len(incs)
        durations = sorted(
            i["resolved"] - i["started"] for i in incs
            if i["resolved"] is not None and i["resolved"] >= i["started"]
        )
        median = None
        if durations:
            n = len(durations)
            median = (durations[n // 2] if n % 2
                      else (durations[n // 2 - 1] + durations[n // 2]) / 2.0)
        latest = max(incs, key=lambda i: i["started"])
        oldest = min(incs, key=lambda i: i["started"])
        starts = sorted(i["started"] for i in incs)
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        median_gap = None
        if gaps:
            middle = len(gaps) // 2
            median_gap = gaps[middle] if len(gaps) % 2 else (gaps[middle - 1] + gaps[middle]) / 2.0
        result = {
            "count": count,
            "tier": None,
            "median_duration_s": round(median) if median is not None else None,
            "last_ref": latest.get("ref"),
            "last_started": latest["started"],
            "first_started": oldest["started"],
            "median_gap_s": round(median_gap) if median_gap is not None else None,
            "clusters_hour_range": None,
        }
        if count < 2:
            return result
        if count == 2:
            result["tier"] = "recurrence"
            return result
        # count >= 3: only claim a time-of-day pattern if >=3 land in one window.
        result["tier"] = "pattern"
        hours = [0] * 24
        for i in incs:
            hours[time.localtime(i["started"]).tm_hour] += 1
        best_start, best_sum = 0, -1
        for start in range(24):
            s = sum(hours[(start + k) % 24] for k in range(4))
            if s > best_sum:
                best_sum, best_start = s, start
        if best_sum >= 3:
            end = (best_start + 4) % 24
            result["clusters_hour_range"] = f"{best_start:02d}:00–{end:02d}:00"
        return result

    def patterns(self, code=None, days=90):
        now = time.time()
        cutoff = now - days * 86400
        with db() as conn:
            rows = [dict(r) for r in conn.execute(
                "SELECT verdict_code, started, resolved, ref FROM incidents"
                " WHERE started > ? AND verdict_code IS NOT NULL",
                (cutoff,))]
        by_code = {}
        for r in rows:
            c = normalize_stored_verdict(r).get("verdict_code")
            if not c or c == "all_clear":
                continue
            by_code.setdefault(c, []).append(r)
        if code == "pihole_broken":
            code = "local_dns_broken"
        if code is not None:
            incs = by_code.get(code)
            return self._pattern_for(incs) if incs else None
        return {c: self._pattern_for(incs) for c, incs in by_code.items()}

    def incidents_list(self, limit=50, code=None):
        q = ("SELECT i.*, (SELECT COUNT(*) FROM runs r WHERE r.incident_id=i.id) AS run_count"
             " FROM incidents i")
        args = []
        if code == "open":
            q += " WHERE i.resolved IS NULL"
        elif code:
            if code == "local_dns_broken":
                q += " WHERE i.verdict_code IN (?, ?)"
                args.extend(("local_dns_broken", "pihole_broken"))
            else:
                q += " WHERE i.verdict_code = ?"
                args.append(code)
        q += " ORDER BY i.id DESC LIMIT ?"
        args.append(max(1, min(200, limit)))
        with db() as conn:
            return [
                normalize_stored_verdict(dict(r))
                for r in conn.execute(q, args)
            ]

    def incident_detail(self, inc_id=None, ref=None):
        with db() as conn:
            if ref:
                row = conn.execute(
                    "SELECT * FROM incidents WHERE ref=?", (ref.strip(),),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM incidents WHERE id=?", (inc_id,),
                ).fetchone()
            if not row:
                return None
            inc = normalize_stored_verdict(dict(row))
            inc_id = inc["id"]
            runs = [dict(r) for r in conn.execute(
                "SELECT * FROM runs WHERE incident_id=? ORDER BY id", (inc_id,))]
            base = conn.execute(
                "SELECT * FROM runs WHERE ts < ? AND severity='ok' ORDER BY id DESC LIMIT 1",
                (inc["started"],),
            ).fetchone()
        for r in runs:
            translated = normalize_stored_verdict(r)
            r.update(translated)
            r["checks"] = normalize_stored_checks(json.loads(r["checks"]))
            assessment = confidence_assessment(r["checks"])
            r["confidence"] = assessment["level"]
            r["confidence_reason"] = assessment["reason"]
        baseline = None
        if base:
            baseline = dict(base)
            baseline = normalize_stored_verdict(baseline)
            baseline["checks"] = normalize_stored_checks(
                json.loads(baseline["checks"])
            )
        first_bad = next((r for r in runs if r["severity"] != "ok"), None)
        ref = first_bad or (runs[-1] if runs else None)
        sim_code = inc.get("verdict_code") or (first_bad["code"] if first_bad else None)
        similar = []
        if sim_code:
            with db() as conn:
                similar_codes = (
                    ("local_dns_broken", "pihole_broken")
                    if sim_code == "local_dns_broken" else (sim_code,)
                )
                placeholders = ",".join("?" for _ in similar_codes)
                for r in conn.execute(
                    "SELECT ref, started, resolved FROM incidents"
                    f" WHERE verdict_code IN ({placeholders}) AND id != ?"
                    " ORDER BY id DESC LIMIT 3",
                    (*similar_codes, inc_id)):
                    d = dict(r)
                    dur = (d["resolved"] - d["started"]) if d["resolved"] else None
                    similar.append({
                        "ref": d["ref"], "started": d["started"],
                        "duration_s": round(dur) if dur is not None else None,
                    })
        first_failure = None
        diff = []
        if first_bad:
            for ch in first_bad["checks"]:
                if ch["ok"] is False or ch.get("state") == "degraded":
                    first_failure = {"id": ch["id"], "label": ch["label"],
                                     "detail": ch["detail"]}
                    break
            if baseline:
                before = {b["id"]: b for b in baseline["checks"]}
                for ch in first_bad["checks"]:
                    b = before.get(ch["id"])
                    if not b:
                        continue
                    flipped = (b["ok"] is not False) and (ch["ok"] is False)
                    evidence_changed = b.get("state") != ch.get("state")
                    ms_jump = (
                        b.get("ms") is not None and ch.get("ms") is not None
                        and abs(ch["ms"] - b["ms"]) >= max(20.0, b["ms"] * 0.5)
                    )
                    if flipped or evidence_changed or ms_jump:
                        diff.append({"id": ch["id"], "label": ch["label"],
                                     "before": b["detail"], "after": ch["detail"],
                                     "flipped": flipped,
                                     "evidence_changed": evidence_changed})
        if not baseline:
            comparison_summary = "No earlier healthy run is stored, so Linkmoth cannot make a before/after comparison yet."
        elif not diff:
            comparison_summary = "No ladder evidence changed from the last healthy run; this weakens the case for a network-wide fault."
        else:
            flipped_labels = [item["label"] for item in diff if item["flipped"]]
            if flipped_labels:
                comparison_summary = "New failures appeared in " + ", ".join(flipped_labels) + "."
            else:
                comparison_summary = "The path still worked, but its evidence changed (timing or target agreement)."
        return {
            "incident": inc,
            "runs": runs,
            "baseline_before": (
                {"ts": baseline["ts"], "checks": baseline["checks"]} if baseline else None
            ),
            "first_failure": first_failure,
            "first_failure_note": (
                "First failed rung in dependency order; downstream checks depend on it."
                if first_failure else None
            ),
            "stayed_healthy": (
                [ch["label"] for ch in ref["checks"] if ch["ok"] is True] if ref else []
            ),
            "diff": diff,
            "comparison_summary": comparison_summary,
            "confidence": (first_bad or ref or {}).get("confidence"),
            "confidence_reason": (first_bad or ref or {}).get("confidence_reason"),
            "pattern": self.patterns(sim_code) if sim_code else None,
            "similar": similar,
        }

    def history(self, limit=144):
        with db() as conn:
            rows = conn.execute(
                "SELECT ts, severity, kind, checks FROM runs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out = []
        for r in reversed(rows):
            ms = {}
            for ch in normalize_stored_checks(json.loads(r["checks"])):
                if ch.get("ms") is not None:
                    ms[ch["id"]] = ch["ms"]
            out.append({"ts": r["ts"], "severity": r["severity"],
                        "kind": r["kind"], "ms": ms})
        return out

    def history_meta(self):
        history = self.history(limit=1)
        sample = int(CFG.get("history_sample_minutes", 5) or 0)
        baseline = int(CFG.get("baseline_minutes", 0) or 0)
        if sample <= 0 and baseline > 0:
            sample = baseline
        return {
            "last_ts": history[-1]["ts"] if history else None,
            "sample_minutes": sample,
            "baseline_minutes": baseline,
            "refresh_seconds": int(CFG.get("ui_refresh_seconds", 5) or 5),
        }


ENGINE = Engine()

from linkmoth_devices import DeviceManager

DEVICES = DeviceManager(db, ping, CFG, STATE_DIR)

AUTH = None


def get_auth():
    global AUTH
    if AUTH is None:
        from linkmoth_auth import AuthManager
        AUTH = AuthManager(STATE_DIR, CFG, db)
    return AUTH


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
        self.connection.settimeout(REQUEST_TIMEOUT_SECONDS)

    def log_message(self, *a):
        pass

    def _hdrs(self):
        h = {k: v for k, v in self.headers.items()}
        h["Remote-Addr"] = self.client_address[0]
        return h

    def _session(self):
        auth = get_auth()
        sid = auth.session_cookie_value(self)
        return auth.get_session(sid)

    def _require_auth(self):
        auth = get_auth()
        session = self._session()
        if auth.is_fully_authenticated(session):
            return True, session
        return False, session

    def _require_csrf(self, session):
        return get_auth().verify_csrf(session, self._hdrs())

    def _require_webhook(self):
        return get_auth().verify_webhook_bearer(
            self.headers.get("Authorization")
        )

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

    def _send_json(self, code, body, session=None, set_cookie=None, clear_cookie=False):
        extra = []
        auth = get_auth()
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
        auth = get_auth()
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
        auth = get_auth()
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
        auth = get_auth()
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
        auth = get_auth()
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
        auth = get_auth()
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
            "internet_note": (
                "Linkmoth does not create cloud access, tunnels, or router "
                "port forwards. It is intended for local-network access "
                "only."
            ),
            "database": db_maintenance_info(),
        }

    def do_GET(self):
        url = urlparse(self.path)
        qs = parse_qs(url.query)
        auth = get_auth()
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
            self._send(200, get_auth().public_status(session))
            return
        if url.path == "/trigger":
            if not self._require_webhook():
                self._send(401, {"error": "webhook authorization required"})
                return
            ENGINE.trigger("manual-get", "GET /trigger")
            self._send(200, {"triggered": True})
            return
        ok, session = self._require_auth()
        if not ok:
            # /setup is an alias for the dashboard; the UI shows the onboarding
            # gate when a setup code is required, so a beginner can land there
            # straight from the installer's printed address.
            if url.path in ("/", "/index.html", "/setup"):
                self._serve_dashboard()
            else:
                self._send(401, {"error": "authentication required"})
            return
        if url.path in ("/", "/index.html", "/setup"):
            self._serve_dashboard()
        elif url.path == "/api/status":
            payload = ENGINE.status()
            payload["auth"] = auth.public_status(session)
            payload["quality"] = quality_summary(limit=120)
            self._send(200, payload)
        elif url.path == "/api/auth/audit":
            try:
                limit = int(qs.get("limit", ["50"])[0])
            except (ValueError, TypeError):
                limit = 50
            limit = max(20, min(200, limit))  # aggressive clamp; newest-first in the query
            self._send(200, {"events": auth.audit_events(limit)})
        elif url.path == "/api/auth/security":
            self._send(200, self._security_posture(auth))
        elif url.path == "/api/devices":
            self._send(200, {
                "devices": DEVICES.list_devices(),
                **DEVICES.api_metadata(),
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
                    "device": DEVICES.get_device(device_id),
                    "history": DEVICES.history(device_id, limit),
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
            payload = {"incidents": ENGINE.incidents_list(limit, code)}
            if code:
                payload["pattern"] = ENGINE.patterns(code=code)
            self._send(200, payload)
        elif url.path == "/api/incident":
            ref = (qs.get("ref", [None])[0] or "").strip() or None
            if ref:
                detail = ENGINE.incident_detail(ref=ref)
            else:
                try:
                    inc_id = int(qs.get("id", ["0"])[0])
                except ValueError:
                    inc_id = 0
                detail = ENGINE.incident_detail(inc_id=inc_id)
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
        body = self._read_body()
        if body is None:
            return
        path = urlparse(self.path).path
        auth = get_auth()
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
                inc = ENGINE.open_incident()
                if inc:
                    ENGINE.trigger("kuma-up", detail)
                self._send(200, {"noted": "recovery"})
            else:
                ENGINE.trigger("kuma-down" if status == 0 else "webhook", detail)
                self._send(200, {"triggered": True})
            return
        if path == "/api/webhooks/kuma":
            if not self._require_webhook():
                self._send(401, {"error": "webhook authorization required"})
                return
            from linkmoth_kuma_proxy import handle_kuma_webhook
            result = handle_kuma_webhook(body, ENGINE, CFG, db)
            self._send(200, result)
            return
        if path == "/api/webhooks/inbound":
            if not self._require_webhook():
                self._send(401, {"error": "webhook authorization required"})
                return
            from linkmoth_kuma_proxy import handle_inbound_webhook
            result = handle_inbound_webhook(body, ENGINE, CFG, db)
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
                created = DEVICES.create_device(self._json_object(body))
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
            ok, result = ENGINE.mark_false_alarm(ref)
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
                result = DEVICES.run_device(device_id, source="manual")
                self._send(200, {
                    "result": result,
                    "device": DEVICES.get_device(device_id),
                })
            except Exception as exc:
                self._send_device_exception(exc)
        elif path == "/api/diagnose":
            def one_shot():
                v = ENGINE.diagnose_once()
                if v and v["severity"] != "ok" and ENGINE.open_incident() is None:
                    ENGINE.trigger("dashboard", f"manual run found: {v['code']}")
            threading.Thread(target=one_shot, daemon=True).start()
            self._send(200, {"started": True})
        elif path == "/api/verify":
            remaining = ENGINE.verify_cooldown_remaining()
            if remaining > 0:
                self._send(429, {"error": "wait a few seconds and try again",
                                 "retry_after": round(remaining)})
                return
            before = {c["id"]: c for c in ENGINE.last_run_checks()}
            result = ENGINE.verify_fix()
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
        elif path == "/api/settings":
            try:
                data = json.loads(body)
                if not isinstance(data, dict):
                    raise ValueError
            except (json.JSONDecodeError, ValueError):
                self._send(400, {"errors": {"_body": "expected a JSON object"}})
                return
            if data.get("action") == "vacuum":
                ok, result = vacuum_database(ENGINE)
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
            v, err = ENGINE.recheck_open_incident()
            if err:
                self._send(409, {"error": err})
            else:
                self._send(200, {"verdict": v})
        elif path == "/api/incident/close":
            ok, result = ENGINE.close_open_incident()
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
        body = self._read_body()
        if body is None:
            return
        path = urlparse(self.path).path
        ok, session = self._require_auth()
        if not ok:
            self._send(401, {"error": "authentication required"})
            return
        if not self._require_csrf(session):
            get_auth().audit_event("csrf_rejected", self._hdrs(), path)
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
                get_auth().audit_event(
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
            updated = DEVICES.update_device(
                match.group(1), self._json_object(body)
            )
            get_auth().audit_event(
                "device_updated", self._hdrs(),
                f"{updated['id']} {updated['address']}",
            )
            self._send(200, {"device": updated})
        except Exception as exc:
            self._send_device_exception(exc)

    def do_DELETE(self):
        path = urlparse(self.path).path
        ok, session = self._require_auth()
        if not ok:
            self._send(401, {"error": "authentication required"})
            return
        if not self._require_csrf(session):
            get_auth().audit_event("csrf_rejected", self._hdrs(), path)
            self._send(403, {"error": "csrf required"})
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
                get_auth().audit_event(
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
            DEVICES.delete_device(device_id)
            get_auth().audit_event(
                "device_deleted", self._hdrs(), device_id,
            )
            self._send(200, {"deleted": True})
        except Exception as exc:
            self._send_device_exception(exc)


def doctor():
    problems = 0

    def report(name, healthy, detail=""):
        nonlocal problems
        print(f"[{'ok' if healthy else 'FAIL'}] {name}"
              + (f" — {detail}" if detail else ""))
        if not healthy:
            problems += 1

    def info(name, detail=""):
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
    if DB_PATH.is_file():
        try:
            db_info = db_maintenance_info()
            report(
                "database journal",
                db_info["journal_mode"] == "WAL",
                f"{db_info['journal_mode']}; busy timeout {db_info['busy_timeout_ms']} ms; "
                f"lock retries {db_info['lock_retries']}",
            )
        except sqlite3.Error as exc:
            report("database journal", False, str(exc))
    else:
        info("database journal", "database will be initialized on first start")
    report("dashboard.html present", (BASE / "dashboard.html").exists(), str(BASE))
    report("linkmoth.svg present", ICON_PATH.is_file(), str(ICON_PATH))
    report("linkmoth-white.svg present", WHITE_LOGO_PATH.is_file(), str(WHITE_LOGO_PATH))
    report("linkmoth-mark-white.svg present", WHITE_MARK_PATH.is_file(), str(WHITE_MARK_PATH))
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
    print("all good" if problems == 0 else f"{problems} problem(s) found")
    return 0 if problems == 0 else 1


def record_quality_sample():
    """Measure and store one connection-quality sample. Best-effort."""
    qcfg = quality_config()
    if not qcfg.get("enabled", True):
        return None
    targets = qcfg.get("targets") or CFG.get("ping_targets") or []
    if not targets:
        return None
    try:
        sample = measure_quality(targets, count=int(qcfg.get("sample_count", 10) or 10))
    except Exception as e:
        print(f"quality sample failed: {e}", file=sys.stderr, flush=True)
        return None
    if not sample:
        return None
    verdict = classify_quality(
        sample["latency_ms"], sample["jitter_ms"], sample["loss_pct"], qcfg)
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO quality_samples(ts, latency_ms, jitter_ms, loss_pct, state)"
                " VALUES(?,?,?,?,?)",
                (time.time(), sample["latency_ms"], sample["jitter_ms"],
                 sample["loss_pct"], verdict["state"]),
            )
    except sqlite3.Error as e:
        print(f"quality store failed: {e}", file=sys.stderr, flush=True)
        return None
    return {**sample, **verdict}


def quality_summary(limit=288):
    """Recent quality samples (oldest first) plus the latest verdict."""
    qcfg = quality_config()
    rows = []
    try:
        with db() as conn:
            rows = conn.execute(
                "SELECT ts, latency_ms, jitter_ms, loss_pct, state"
                " FROM quality_samples ORDER BY ts DESC LIMIT ?", (limit,),
            ).fetchall()
    except sqlite3.Error as e:
        print(f"quality read failed: {e}", file=sys.stderr, flush=True)
    samples = [
        {"ts": r["ts"], "latency_ms": r["latency_ms"], "jitter_ms": r["jitter_ms"],
         "loss_pct": r["loss_pct"], "state": r["state"]}
        for r in rows
    ][::-1]  # chronological for sparklines
    current = None
    if samples:
        last = samples[-1]
        verdict = classify_quality(
            last["latency_ms"], last["jitter_ms"], last["loss_pct"], qcfg)
        current = {**last, **verdict}
    return {
        "enabled": bool(qcfg.get("enabled", True)),
        "current": current,
        "samples": samples,
        "thresholds": {
            "latency_warn_ms": qcfg["latency_warn_ms"],
            "latency_bad_ms": qcfg["latency_bad_ms"],
            "jitter_warn_ms": qcfg["jitter_warn_ms"],
            "jitter_bad_ms": qcfg["jitter_bad_ms"],
            "loss_warn_pct": qcfg["loss_warn_pct"],
            "loss_bad_pct": qcfg["loss_bad_pct"],
        },
    }


def janitor_loop():
    while True:
        cutoff = time.time() - CFG.get("retention_days", 90) * 86400
        try:
            with db() as conn:
                conn.execute("DELETE FROM runs WHERE ts < ?", (cutoff,))
                conn.execute("DELETE FROM quality_samples WHERE ts < ?", (cutoff,))
                conn.execute(
                    "DELETE FROM incidents WHERE resolved IS NOT NULL AND resolved < ?",
                    (cutoff,),
                )
        except sqlite3.Error as e:
            print(f"janitor: {e}", file=sys.stderr, flush=True)
        try:
            auto_vacuum(ENGINE)
        except Exception as e:
            print(f"janitor auto_vacuum: {e}", file=sys.stderr, flush=True)
        time.sleep(86400)


def auth_set_password():
    import getpass
    init_db()
    auth = get_auth()
    idx = sys.argv.index("--auth-set-password")
    if idx + 1 < len(sys.argv) and not sys.argv[idx + 1].startswith("--"):
        print(
            "do not put passwords on the command line; run "
            "--auth-set-password and enter it at the hidden prompt",
            file=sys.stderr,
        )
        return 2
    pw = getpass.getpass("New admin password: ")
    confirm = getpass.getpass("Confirm: ")
    if pw != confirm:
        print("passwords do not match", file=sys.stderr)
        return 1
    try:
        auth.set_password(pw)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 1
    secret = auth.ensure_webhook_secret()
    print(f"admin password set; webhook secret: {secret}")
    return 0


def auth_setup_totp():
    init_db()
    auth = get_auth()
    if not auth.has_password():
        print("set admin password first (--auth-set-password)", file=sys.stderr)
        return 1
    secret, codes = auth.setup_totp()
    uri = auth.totp_provisioning_uri()
    print("TOTP secret (base32):", secret)
    print("Provisioning URI:", uri)
    print("Recovery codes (store safely, shown once):")
    for c in codes:
        print(" ", c)
    return 0


def auth_show_webhook():
    init_db()
    auth = get_auth()
    print(auth.ensure_webhook_secret())
    return 0


def auth_onboarding_token():
    init_db()
    token = get_auth().ensure_onboarding_token()
    if token:
        print(token)
    return 0


def auth_rotate_webhook():
    init_db()
    auth = get_auth()
    print(auth.rotate_webhook_secret())
    print("webhook secret rotated; update every /trigger client now", file=sys.stderr)
    return 0


def auth_show_audit():
    init_db()
    auth = get_auth()
    idx = sys.argv.index("--auth-audit")
    try:
        limit = int(sys.argv[idx + 1]) if idx + 1 < len(sys.argv) else 50
    except ValueError:
        print("--auth-audit limit must be an integer", file=sys.stderr)
        return 2
    for event in auth.audit_events(limit):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event["ts"]))
        detail = f" — {event['detail']}" if event["detail"] else ""
        print(f"{stamp}  {event['ip']:<39}  {event['event']}{detail}")
    return 0


def main():
    if "--doctor" in sys.argv:
        sys.exit(doctor())
    if "--auth-set-password" in sys.argv:
        sys.exit(auth_set_password())
    if "--auth-setup-totp" in sys.argv:
        sys.exit(auth_setup_totp())
    if "--auth-show-webhook" in sys.argv:
        sys.exit(auth_show_webhook())
    if "--auth-onboarding-token" in sys.argv:
        sys.exit(auth_onboarding_token())
    if "--auth-rotate-webhook" in sys.argv:
        sys.exit(auth_rotate_webhook())
    if "--auth-audit" in sys.argv:
        sys.exit(auth_show_audit())
    if CONFIG_ERROR is not None:
        print(
            f"refusing to start with invalid configuration: {CONFIG_ERROR}",
            file=sys.stderr,
        )
        sys.exit(1)
    init_db()
    auth = get_auth()
    try:
        auth.validate_configuration()
    except RuntimeError as e:
        print(f"auth configuration error: {e}", file=sys.stderr)
        sys.exit(1)
    auth.purge_expired_sessions()
    if auth.onboarding_required():
        print(
            "onboarding required: run linkmoth.py --auth-onboarding-token "
            "as the linkmoth service user",
            flush=True,
        )
    if "--once" in sys.argv:
        checks, ms = run_ladder()
        v = verdict(checks)
        print(json.dumps({"verdict": v, "checks": checks, "ms": round(ms)}, indent=2))
        return
    def baseline_loop():
        time.sleep(15)
        last_incident_probe = 0.0
        while True:
            sample_m = int(CFG.get("history_sample_minutes", 5) or 0)
            baseline_m = int(CFG.get("baseline_minutes", 0) or 0)
            if sample_m <= 0 and baseline_m <= 0:
                time.sleep(300)
                continue
            if sample_m <= 0:
                sample_m = baseline_m
            if (not ENGINE.run_in_progress and ENGINE.open_incident() is None):
                v = ENGINE.diagnose_once(kind="baseline")
                now = time.time()
                if (baseline_m > 0 and v and v["severity"] == "bad"
                        and now - last_incident_probe >= baseline_m * 60):
                    ENGINE.trigger("baseline", f"self-detected: {v['code']}")
                    last_incident_probe = now
                record_quality_sample()
            time.sleep(max(60, sample_m * 60))
    from linkmoth_webhooks import drain_loop, migrate_legacy_webhook
    migrate_legacy_webhook(CFG, db, SETTINGS_PATH)
    threading.Thread(target=baseline_loop, daemon=True).start()
    threading.Thread(target=janitor_loop, daemon=True).start()
    threading.Thread(target=DEVICES.scheduler_loop, daemon=True).start()
    threading.Thread(target=drain_loop, args=(db,), daemon=True).start()
    ENGINE.resume_after_startup()
    try:
        server = create_server()
    except RuntimeError as e:
        print(f"TLS configuration error: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"linkmoth listening with TLS on {CFG['bind']}:{CFG['port']}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

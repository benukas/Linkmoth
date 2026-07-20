"""Linkmoth core: state/config paths, config loading and validation, the
SQLite connection and schema, TLS context, and host stats.

Foundational -- every other Linkmoth module depends on this one, directly
or indirectly (following the project's existing convention: this module
never imports from any of them).
"""
import http.client
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import HTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE = Path(__file__).resolve().parent
ICON_PATH = BASE / "linkmoth.svg"
WHITE_LOGO_PATH = BASE / "linkmoth-white.svg"
WHITE_MARK_PATH = BASE / "linkmoth-mark-white.svg"
MASKABLE_ICON_PATH = BASE / "linkmoth-maskable.svg"
PNG_ICON_PATHS = {
    "/linkmoth-icon-192.png": BASE / "linkmoth-icon-192.png",
    "/linkmoth-icon-512.png": BASE / "linkmoth-icon-512.png",
}
FAVICON_PATH = BASE / "linkmoth-white.ico"
SW_PATH = BASE / "sw.js"
MANIFEST_PATH = BASE / "manifest.webmanifest"
def _build_version():
    try:
        meta = json.loads((BASE / "linkmoth-build.json").read_text(encoding="utf-8"))
        value = meta.get("version")
        if isinstance(value, str) and re.fullmatch(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", value): return value.removeprefix("v")
    except (OSError, ValueError, json.JSONDecodeError): pass
    return "development"
VERSION = _build_version()
INSTALLATION_RECORD = Path("/etc/linkmoth/installation.json")
VERIFY_COOLDOWN_SECONDS = 5
GITHUB_REPO = "https://github.com/benukas/Linkmoth"
GITHUB_API_HOST = "api.github.com"
GITHUB_RELEASE_HOST = "github.com"
GITHUB_RELEASE_PATH = "/repos/benukas/Linkmoth/releases/latest"
GITHUB_UPDATE_USER_AGENT = "Linkmoth-manual-update-check/0.2"
UPDATE_CHECK_TIMEOUT_SECONDS = 4
UPDATE_CHECK_MAX_BYTES = 32 * 1024
CHANGELOG_URL = f"{GITHUB_REPO}/blob/main/CHANGELOG.md"
SYSTEM_INSTALL = BASE == Path("/opt/linkmoth")
DEFAULT_CONFIG_PATH = (
    Path("/etc/linkmoth/config.json") if SYSTEM_INSTALL else BASE / "config.json"
)
DEFAULT_STATE_DIR = Path("/var/lib/linkmoth") if SYSTEM_INSTALL else BASE
CONFIG_PATH = Path(
    os.environ.get("LINKMOTH_CONFIG")
    or DEFAULT_CONFIG_PATH
)
STATE_DIR = Path(
    os.environ.get("STATE_DIRECTORY")
    or os.environ.get("LINKMOTH_STATE_DIR")
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

def installation_provenance():
    """Read local provenance without inferring trust from a version or remote."""
    if not SYSTEM_INSTALL:
        return {"state": "unverified-manual", "detail": "source checkout or manual installation"}
    try:
        st = os.lstat(INSTALLATION_RECORD)
        if (stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode)
                or st.st_uid != 0 or st.st_gid != 0
                or stat.S_IMODE(st.st_mode) & 0o022):
            raise ValueError
        record = json.loads(INSTALLATION_RECORD.read_text(encoding="utf-8"))
        metadata = json.loads((BASE / "linkmoth-build.json").read_text(encoding="utf-8"))
        if (record.get("schema") != 1
                or record.get("verification") != "sigstore-verified"
                or not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", str(record.get("version", "")))
                or not re.fullmatch(r"[0-9a-f]{40}", str(record.get("release_commit", "")))
                or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("archive_sha256", "")))
                or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", str(record.get("installed_at", "")))
                or metadata.get("schema") != 1
                or metadata.get("version") != record.get("version")
                or metadata.get("release_commit") != record.get("release_commit")):
            raise ValueError
        return {"state": "sigstore-verified", "record": {k: record.get(k) for k in ("version", "release_commit", "archive_sha256", "installed_at")}}
    except FileNotFoundError:
        build_metadata = BASE / "linkmoth-build.json"
        try:
            metadata = json.loads(build_metadata.read_text(encoding="utf-8"))
            if (metadata.get("schema") != 1
                    or not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", str(metadata.get("version", "")))
                    or not re.fullmatch(r"[0-9a-f]{40}", str(metadata.get("release_commit", "")))):
                raise ValueError
            return {"state": "unverified-manual", "detail": "versioned release installed without publisher verification"}
        except FileNotFoundError:
            return {"state": "legacy-unavailable"}
        except (OSError, ValueError, json.JSONDecodeError):
            return {"state": "unverified-manual", "detail": "manual installation with unavailable build metadata"}
    except (OSError, ValueError, json.JSONDecodeError):
        return {"state": "invalid"}


_SEMVER_RE = re.compile(r"v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?")


def _strict_version(value):
    """Return a normalised semantic version, or None. No version inference."""
    match = _SEMVER_RE.fullmatch(str(value or ""))
    if not match:
        return None
    return ".".join(match.group(i) for i in range(1, 4)) + (
        f"-{match.group(4)}" if match.group(4) else ""
    )


def _globally_routable(address):
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False



class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that never delegates DNS or proxy choice to urllib."""
    def __init__(self, host, address, **kwargs):
        super().__init__(host, **kwargs)
        self._address = address

    def connect(self):
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        peer = self.sock.getpeername()[0]
        if not _globally_routable(peer):
            self.close()
            raise OSError("connected peer is not globally routable")


def manual_update_check():
    """Fetch only the official latest-release metadata, on an admin request."""
    installed = _strict_version(VERSION)
    if not installed:
        raise ValueError("installed version is not a supported release version")
    try:
        candidates = sorted({item[4][0] for item in socket.getaddrinfo(
            GITHUB_API_HOST, 443, type=socket.SOCK_STREAM
        )})
    except OSError as exc:
        raise ValueError("official release service could not be resolved") from exc
    candidates = [address for address in candidates if _globally_routable(address)]
    if not candidates:
        raise ValueError("official release service did not resolve to a public address")
    context = ssl.create_default_context()
    last_error = None
    raw = None
    for address in candidates:
        conn = _PinnedHTTPSConnection(
            GITHUB_API_HOST, address, timeout=UPDATE_CHECK_TIMEOUT_SECONDS,
            context=context,
        )
        try:
            conn.request("GET", GITHUB_RELEASE_PATH, headers={
                "Host": GITHUB_API_HOST,
                "Accept": "application/vnd.github+json",
                "User-Agent": GITHUB_UPDATE_USER_AGENT,
                "Connection": "close",
            })
            response = conn.getresponse()
            if response.status != 200:
                raise ValueError("official release service returned an unexpected response")
            length = response.getheader("Content-Length")
            if length and (not length.isdigit() or int(length) > UPDATE_CHECK_MAX_BYTES):
                raise ValueError("official release response was too large")
            raw = response.read(UPDATE_CHECK_MAX_BYTES + 1)
            if len(raw) > UPDATE_CHECK_MAX_BYTES:
                raise ValueError("official release response was too large")
            break
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
            last_error = exc
        finally:
            conn.close()
    if raw is None:
        raise ValueError("official release service could not be reached") from last_error
    try:
        source = json.loads(raw.decode("utf-8"))
        latest = _strict_version(source.get("tag_name"))
        release_url = source.get("html_url")
        published_at = source.get("published_at")
        expected_url = f"https://{GITHUB_RELEASE_HOST}/benukas/Linkmoth/releases/tag/v{latest}"
        if (not latest or release_url != expected_url or not isinstance(published_at, str)
                or len(published_at) > 40):
            raise ValueError
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        raise ValueError("official release response was invalid")
    return {
        "installed_version": installed,
        "latest_version": latest,
        "update_available": _version_tuple(latest) > _version_tuple(installed),
        "published_at": published_at,
        "release_url": expected_url,
        "update_command": (
            f"VERSION=v{latest}; curl -fsSLO {GITHUB_REPO}/releases/download/$VERSION/"
            f"linkmoth-$VERSION-bootstrap.sh && sudo bash linkmoth-$VERSION-bootstrap.sh"
        ),
        "verified_update_command": (
            f"VERSION=v{latest}; curl -fsSLO {GITHUB_REPO}/releases/download/$VERSION/"
            f"linkmoth-$VERSION-bootstrap.sh; curl -fsSLO {GITHUB_REPO}/releases/download/$VERSION/"
            f"linkmoth-$VERSION-bootstrap.sh.bundle; cosign verify-blob --bundle "
            f"linkmoth-$VERSION-bootstrap.sh.bundle --certificate-identity "
            f"https://github.com/benukas/Linkmoth/.github/workflows/release.yml@refs/tags/$VERSION "
            f"--certificate-oidc-issuer https://token.actions.githubusercontent.com "
            f"linkmoth-$VERSION-bootstrap.sh && sudo bash linkmoth-$VERSION-bootstrap.sh --sigstore-verified"
        ),
    }



def _version_tuple(value):
    parsed = _strict_version(value)
    core, _, prerelease = parsed.partition("-")
    # Stable releases sort after prereleases with the same numeric version.
    return tuple(int(piece) for piece in core.split(".")) + (1 if not prerelease else 0, prerelease)


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
    "quiet_hours_enabled": False,
    "quiet_hours_start": "22:00",
    "quiet_hours_end": "07:00",
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
        # Latency-under-load (bufferbloat) testing. Downloads are bounded by
        # load_test_seconds AND load_test_max_mb, whichever ends first.
        # Scheduled runs are off by default (load_test_hours = 0) because
        # they consume real data; the dashboard button always works.
        "load_test_url": "https://speed.cloudflare.com/__down?bytes=25000000",
        "load_test_hours": 0,
        "load_test_seconds": 10,
        "load_test_max_mb": 25,
    },
}


SETTINGS_PATH = STATE_DIR / "settings.json"

DB_BUSY_TIMEOUT_MS = 10_000
DB_LOCK_RETRIES = 0
DB_LOCK_RETRIES_LOCK = threading.Lock()
HOST_STATS_LOCK = threading.Lock()
HOST_CPU_SAMPLE = None
HOST_CPU_VALUES = deque(maxlen=5)
HOST_CPU_VALUE = None
HOST_CPU_UPDATED_AT = None
HOST_CPU_SAMPLER_STARTED = False

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


def _coerce_config_types(cfg):
    """Guard config keys that daemon threads consume with hard subscripts.

    The dashboard settings path validates types before writing, but a
    hand-edited config.json does not: a "recheck_seconds": 30 (number
    instead of list) used to raise inside the incident recheck thread and
    silently kill it, leaving the incident open forever. Wrong-typed keys
    fall back to the shipped default with a stderr warning, matching how
    an invalid local_dns block is handled.
    """
    def fallback(key, why):
        cfg[key] = json.loads(json.dumps(DEFAULT_CONFIG[key]))
        print(f"config error, using default {key}: {why}",
              file=sys.stderr, flush=True)

    def is_number(v):
        return isinstance(v, (int, float)) and not isinstance(v, bool)

    for key in ("upstream_dns", "ping_targets", "https_targets",
                "target_wifi_clients", "recheck_seconds"):
        v = cfg.get(key)
        if not isinstance(v, list):
            fallback(key, "must be a JSON list")
        elif key == "recheck_seconds" and (
            not v or not all(is_number(x) and x >= 0 for x in v)
        ):
            fallback(key, "must be a non-empty list of seconds")
        elif key != "recheck_seconds" and not all(isinstance(x, str) for x in v):
            fallback(key, "must be a list of strings")
    for key in ("port", "recheck_repeat", "incident_max_hours",
                "baseline_minutes", "history_sample_minutes",
                "ladder_cache_seconds", "retention_days",
                "ui_refresh_seconds"):
        if not is_number(cfg.get(key)):
            fallback(key, "must be a number")
    for key in ("auth", "quality"):
        if not isinstance(cfg.get(key), dict):
            fallback(key, "must be a JSON object")


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
    _coerce_config_types(cfg)
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


def _quiet_time(v):
    from linkmoth_notify import validate_quiet_time
    return validate_quiet_time(v)


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
    "quiet_hours_enabled": _bool_setting,
    "quiet_hours_start": _quiet_time,
    "quiet_hours_end": _quiet_time,
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
    quiet_enabled = clean.get(
        "quiet_hours_enabled", CFG.get("quiet_hours_enabled", False)
    )
    quiet_start = clean.get(
        "quiet_hours_start", CFG.get("quiet_hours_start", "22:00")
    )
    quiet_end = clean.get(
        "quiet_hours_end", CFG.get("quiet_hours_end", "07:00")
    )
    if quiet_enabled and quiet_start == quiet_end:
        return False, {
            "quiet_hours_end": "end time must differ from start time",
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
        or CFG.get("tls_cert")
    )
    key = Path(
        os.environ.get("LINKMOTH_TLS_KEY")
        or CFG.get("tls_key")
    )
    return cert, key


def _ca_cert_path():
    override = (
        os.environ.get("LINKMOTH_TLS_CA")
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
    # AEAD ciphers only: excludes CBC-mode TLS 1.2 suites (Lucky13-class
    # padding-oracle risk). TLS 1.3 is unaffected — it has no CBC suites.
    context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
    try:
        context.load_cert_chain(certfile=cert, keyfile=key)
    except (OSError, ssl.SSLError) as e:
        raise RuntimeError(f"could not load TLS certificate/key: {e}") from e
    return context


MAX_HTTP_CONNECTIONS = 16
REQUEST_HEADER_DEADLINE_SECONDS = 10
TLS_HANDSHAKE_TIMEOUT_SECONDS = 5


class BoundedTLSServer(HTTPServer):
    """A fixed-size TLS server that never handshakes in the accept loop.

    `ThreadingHTTPServer` combined with an SSL-wrapped listening socket can
    block its sole accept loop on an unfinished client handshake and creates an
    unbounded thread per request.  Keep raw accepts cheap, then perform the
    bounded handshake and request work in a fixed worker pool instead.
    """
    allow_reuse_address = True
    # Match the listen backlog to the worker-pool size so a burst of up to
    # MAX_HTTP_CONNECTIONS simultaneous clients is accepted (and, if the pool is
    # full, cleanly slot-rejected) rather than SYN-dropped at the default
    # backlog of 5 and forced into a multi-second TCP retry.
    request_queue_size = MAX_HTTP_CONNECTIONS

    def __init__(self, address, handler_class, tls_context):
        self.tls_context = tls_context
        self._request_context = threading.local()
        self._slots = threading.BoundedSemaphore(MAX_HTTP_CONNECTIONS)
        self._workers = ThreadPoolExecutor(
            max_workers=MAX_HTTP_CONNECTIONS,
            thread_name_prefix="linkmoth-http",
        )
        super().__init__(address, handler_class)

    def process_request(self, request, client_address):
        accepted_at = time.monotonic()
        if not self._slots.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                pass
            return
        self._workers.submit(
            self._handle_tls_request, request, client_address, accepted_at,
        )

    def _handle_tls_request(self, request, client_address, accepted_at):
        tls_request = None
        try:
            deadline = accepted_at + REQUEST_HEADER_DEADLINE_SECONDS
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            request.settimeout(min(TLS_HANDSHAKE_TIMEOUT_SECONDS, remaining))
            tls_request = self.tls_context.wrap_socket(request, server_side=True)
            self._request_context.header_deadline = deadline
            self.finish_request(tls_request, client_address)
        except (OSError, ssl.SSLError, socket.timeout):
            pass
        finally:
            try:
                self.shutdown_request(tls_request or request)
            except OSError:
                pass
            self._slots.release()

    def current_header_deadline(self):
        return getattr(self._request_context, "header_deadline", None)

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
            CREATE TABLE IF NOT EXISTS app_meta(
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS load_tests(
                id INTEGER PRIMARY KEY,
                ts REAL NOT NULL,
                idle_ms REAL,
                loaded_ms REAL,
                bloat_ms REAL,
                grade TEXT,
                throughput_mbps REAL,
                bytes INTEGER,
                seconds REAL,
                error TEXT
            );
            CREATE TABLE IF NOT EXISTS incident_outage_segments(
                id INTEGER PRIMARY KEY,
                incident_id INTEGER NOT NULL,
                started REAL NOT NULL,
                ended REAL,
                CHECK(ended IS NULL OR ended >= started)
            );
            CREATE INDEX IF NOT EXISTS incident_outage_segments_incident
                ON incident_outage_segments(incident_id, started);
            CREATE UNIQUE INDEX IF NOT EXISTS incident_outage_segments_one_open
                ON incident_outage_segments(incident_id) WHERE ended IS NULL;
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
        for column, definition in (
            ("diagnosis_code", "TEXT"),
            ("diagnosis_title", "TEXT"),
            ("recovered_at", "REAL"),
        ):
            try:
                conn.execute(f"ALTER TABLE incidents ADD COLUMN {column} {definition}")
            except sqlite3.OperationalError:
                pass
        # Existing records predate separate historical diagnosis fields. Their
        # final attribution is the best evidence available, never a new claim.
        conn.execute(
            "UPDATE incidents SET diagnosis_code=verdict_code, diagnosis_title=verdict_title "
            "WHERE diagnosis_code IS NULL AND verdict_code IS NOT NULL"
        )
        backfill_incident_refs(conn)
        backfill_incident_outage_segments(conn)
        from linkmoth_outage import init_outage_db
        from linkmoth_push import init_push_db
        from linkmoth_devices import init_device_db
        from linkmoth_webhooks import init_webhook_db
        from linkmoth_notify import init_notification_db
        init_outage_db(conn)
        init_push_db(conn)
        init_device_db(conn)
        init_webhook_db(conn)
        init_notification_db(conn)
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


def _derive_outage_segments(incident, runs):
    """Reconstruct observed fault intervals from an incident's ordered runs.

    The first failing observation inherits the incident start because the
    trigger itself is the earliest evidence. A fault that returns after a
    healthy observation starts a new segment at that failing run.
    """
    incident_started = float(incident["started"])
    segments = []
    open_started = None
    for index, run in enumerate(runs):
        observed_at = max(incident_started, float(run["ts"]))
        if run.get("severity") != "ok":
            if open_started is None:
                open_started = incident_started if index == 0 else observed_at
        elif open_started is not None:
            segments.append({
                "started": open_started,
                "ended": max(open_started, observed_at),
            })
            open_started = None
    if open_started is not None:
        ended = incident.get("recovered_at") or incident.get("resolved")
        segments.append({
            "started": open_started,
            "ended": max(open_started, float(ended)) if ended is not None else None,
        })
    if not segments and not runs:
        code = incident.get("diagnosis_code") or incident.get("verdict_code")
        if not incident.get("false_alarm") and code and code != "all_clear":
            ended = incident.get("recovered_at") or incident.get("resolved")
            segments.append({
                "started": incident_started,
                "ended": max(incident_started, float(ended)) if ended is not None else None,
            })
    return segments


def backfill_incident_outage_segments(conn):
    """Build segments once for pre-segment databases from retained run history."""
    incidents = conn.execute(
        "SELECT * FROM incidents WHERE NOT EXISTS"
        " (SELECT 1 FROM incident_outage_segments s WHERE s.incident_id=incidents.id)"
    ).fetchall()
    for row in incidents:
        incident = dict(row)
        runs = [dict(run) for run in conn.execute(
            "SELECT ts, severity FROM runs WHERE incident_id=? ORDER BY id",
            (incident["id"],),
        )]
        segments = _derive_outage_segments(incident, runs)
        for segment in segments:
            conn.execute(
                "INSERT INTO incident_outage_segments(incident_id, started, ended)"
                " VALUES(?,?,?)",
                (incident["id"], segment["started"], segment["ended"]),
            )
        # Older Linkmoth versions wrote the incident-close time into
        # recovered_at. When retained runs prove an earlier final recovery,
        # repair that timestamp as part of the one-time segment migration.
        if (
            segments
            and segments[-1]["ended"] is not None
            and runs
            and runs[-1]["severity"] == "ok"
        ):
            recovered_at = float(segments[-1]["ended"])
            conn.execute(
                "UPDATE incidents SET recovered_at=? WHERE id=?"
                " AND (recovered_at IS NULL OR"
                " (resolved IS NOT NULL AND ABS(recovered_at - resolved) < 0.001))",
                (recovered_at, incident["id"]),
            )


def _incident_outage_segments(conn, incident):
    """Return stored segments, with a read-only fallback for legacy fixtures."""
    rows = [dict(row) for row in conn.execute(
        "SELECT started, ended FROM incident_outage_segments"
        " WHERE incident_id=? ORDER BY started, id",
        (incident["id"],),
    )]
    if rows:
        return rows
    runs = [dict(run) for run in conn.execute(
        "SELECT ts, severity FROM runs WHERE incident_id=? ORDER BY id",
        (incident["id"],),
    )]
    return _derive_outage_segments(incident, runs)


def _outage_seconds(segments, window_start=None, window_end=None, now=None):
    """Sum non-overlapping observed outage segments inside an optional window."""
    now = time.time() if now is None else float(now)
    start_limit = float(window_start) if window_start is not None else None
    end_limit = float(window_end) if window_end is not None else now
    total = 0.0
    for segment in segments:
        started = float(segment["started"])
        ended = float(segment["ended"]) if segment.get("ended") is not None else now
        if start_limit is not None:
            started = max(started, start_limit)
        ended = min(ended, end_limit)
        total += max(0.0, ended - started)
    return total


def _record_incident_observation(conn, incident_id, observed_at, severity):
    """Advance outage segments for one newly stored incident diagnosis run."""
    if incident_id is None:
        return
    incident = conn.execute(
        "SELECT id, started, resolved FROM incidents WHERE id=?", (incident_id,)
    ).fetchone()
    if not incident or incident["resolved"] is not None:
        return
    observed_at = float(observed_at)
    if severity == "ok":
        conn.execute(
            "UPDATE incident_outage_segments SET ended=?"
            " WHERE incident_id=? AND ended IS NULL",
            (observed_at, incident_id),
        )
        conn.execute(
            "UPDATE incidents SET recovered_at=COALESCE(recovered_at, ?)"
            " WHERE id=? AND resolved IS NULL",
            (observed_at, incident_id),
        )
        return
    open_segment = conn.execute(
        "SELECT id FROM incident_outage_segments"
        " WHERE incident_id=? AND ended IS NULL",
        (incident_id,),
    ).fetchone()
    if open_segment is None:
        segment_count = conn.execute(
            "SELECT COUNT(*) FROM incident_outage_segments WHERE incident_id=?",
            (incident_id,),
        ).fetchone()[0]
        run_count = conn.execute(
            "SELECT COUNT(*) FROM runs WHERE incident_id=?", (incident_id,)
        ).fetchone()[0]
        segment_started = (
            float(incident["started"])
            if segment_count == 0 and run_count == 1
            else observed_at
        )
        conn.execute(
            "INSERT INTO incident_outage_segments(incident_id, started) VALUES(?,?)",
            (incident_id, segment_started),
        )
    conn.execute(
        "UPDATE incidents SET recovered_at=NULL WHERE id=? AND resolved IS NULL",
        (incident_id,),
    )


def _close_open_outage_segment(conn, incident_id, ended_at):
    conn.execute(
        "UPDATE incident_outage_segments SET ended=?"
        " WHERE incident_id=? AND ended IS NULL",
        (float(ended_at), incident_id),
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


def _cpu_totals():
    """Read aggregate Linux CPU counters without double-counting guest time."""
    fields = (Path("/proc/stat").read_text().splitlines()[0]).split()[1:]
    values = [int(item) for item in fields]
    if len(values) < 4:
        raise ValueError("incomplete /proc/stat CPU counters")
    # guest and guest_nice are already included in user and nice respectively.
    total = sum(values[:8])
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return total, idle


def sample_host_cpu():
    """Update the cached CPU figure. Called only by the one-second sampler."""
    global HOST_CPU_SAMPLE, HOST_CPU_VALUE, HOST_CPU_UPDATED_AT
    try:
        total, idle = _cpu_totals()
    except (OSError, ValueError, IndexError):
        return None
    with HOST_STATS_LOCK:
        previous = HOST_CPU_SAMPLE
        HOST_CPU_SAMPLE = (total, idle)
        HOST_CPU_UPDATED_AT = time.monotonic()
        if previous:
            total_delta, idle_delta = total - previous[0], idle - previous[1]
            if total_delta > 0:
                instant = max(0.0, min(100.0, 100.0 * (1 - idle_delta / total_delta)))
                HOST_CPU_VALUES.append(instant)
                HOST_CPU_VALUE = round(sum(HOST_CPU_VALUES) / len(HOST_CPU_VALUES), 1)
        return HOST_CPU_VALUE


def start_host_cpu_sampler():
    """Start one process-local sampler; API reads never reset its baseline."""
    global HOST_CPU_SAMPLER_STARTED
    with HOST_STATS_LOCK:
        if HOST_CPU_SAMPLER_STARTED:
            return
        HOST_CPU_SAMPLER_STARTED = True
    def loop():
        while True:
            sample_host_cpu()
            time.sleep(1)
    threading.Thread(target=loop, name="linkmoth-cpu-sampler", daemon=True).start()


def host_stats():
    """Return cheap, best-effort health data for the Linkmoth host.

    These readings help an operator distinguish a real network fault from a
    Pi that is hot, memory-starved, or out of disk.  All Linux-specific probes
    are optional so the dashboard remains usable on a normal Debian host.
    """
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
    with HOST_STATS_LOCK:
        out["cpu_percent"] = HOST_CPU_VALUE
        if HOST_CPU_UPDATED_AT is not None:
            out["cpu_sample_age_s"] = round(max(0.0, time.monotonic() - HOST_CPU_UPDATED_AT), 1)
        else:
            out["cpu_sample_age_s"] = None
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


def observer_health_warnings(last_run_ts=None, host=None, database=None):
    """Bounded, evidence-based limits on what this host can conclude."""
    host = host if host is not None else host_stats()
    database = database if database is not None else db_maintenance_info()
    warnings = []
    if (host.get("disk_percent") or 0) >= 90:
        warnings.append("Disk pressure may prevent evidence or settings from being recorded.")
    if not database.get("exists"):
        warnings.append("Evidence database is unavailable, so persistence cannot be confirmed.")
    if database.get("journal_mode") != "WAL":
        warnings.append("Database journal mode is not WAL; concurrent evidence reads may be less reliable.")
    if database.get("lock_retries", 0) > 0:
        warnings.append("Database lock contention was observed; some persistence work may have been delayed.")
    if CONFIG_ERROR:
        warnings.append("Configuration persistence is uncertain because the active configuration has an error.")
    if os.name == "posix" and not Path("/run/systemd/timesync/synchronized").exists():
        warnings.append("Clock synchronization status is unavailable; certificate and timeline times may be uncertain.")
    cert = Path(str(CFG.get("tls_cert") or ""))
    if cert and not cert.is_file():
        warnings.append("TLS certificate is unavailable; certificate renewal needs attention.")
    elif cert.is_file():
        try:
            decoded = ssl._ssl._test_decode_cert(str(cert))
            expiry = time.mktime(time.strptime(decoded["notAfter"], "%b %d %H:%M:%S %Y %Z"))
            if expiry - time.time() < 7 * 86400:
                warnings.append("TLS certificate expires within seven days; certificate renewal needs attention.")
        except (AttributeError, KeyError, OSError, ValueError):
            warnings.append("TLS certificate expiry could not be checked; certificate renewal risk is uncertain.")
    if last_run_ts is not None:
        stale_after = max(300, int(CFG.get("history_sample_minutes", 5) or 5) * 180)
        if time.time() - float(last_run_ts) > stale_after:
            warnings.append("Probe evidence is stale; a fresh diagnosis may be needed before acting.")
    if (host.get("memory_percent") or 0) >= 92 or (host.get("cpu_percent") or 0) >= 95:
        warnings.append("Host resource exhaustion can reduce observer reliability.")
    if (host.get("temperature_c") or 0) >= 80:
        warnings.append("High host temperature can reduce observer reliability.")
    return warnings


def _export_settings():
    """Configuration suitable for evidence exports: credentials are omitted."""
    forbidden = set(SETTINGS_SECRET_KEYS) | {"auth", "webhook_secret", "tls_key"}
    return {
        key: value for key, value in public_settings().items()
        if key not in forbidden and not any(token in key.lower() for token in ("secret", "token", "password", "credential", "webhook"))
    }


class _SupportPseudonyms:
    def __init__(self):
        self._private_networks = {}
        self._identifiers = {"HOST": {}, "DEVICE": {}}

    def identifier(self, kind, value):
        values = self._identifiers[kind]
        if value not in values:
            values[value] = f"{kind}-{len(values) + 1}"
        return values[value]

    def replace(self, value):
        if not isinstance(value, str):
            return value
        def private(match):
            address = match.group(0)
            try:
                is_private = ipaddress.ip_address(address).is_private
            except ValueError:
                is_private = False
            if not is_private:
                return address
            if address not in self._private_networks:
                self._private_networks[address] = f"PRIVATE-NET-{len(self._private_networks) + 1}"
            return self._private_networks[address]
        # The trailing guard rejects longer dotted continuations ("1.2.3.4.5",
        # "10.0.0.1.example") but tolerates sentence punctuation — an address
        # at the end of a sentence ("replied from 10.0.0.1.") must still be
        # pseudonymized.
        return re.sub(
            r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w)(?!\.\w)", private, value
        )

    def scrub(self, value):
        if isinstance(value, dict):
            out = {}
            for key, item in value.items():
                lowered = key.lower()
                if isinstance(item, str) and lowered in ("host", "hostname", "host_name"):
                    out[key] = self.identifier("HOST", item)
                elif isinstance(item, str) and lowered in ("device", "device_name"):
                    out[key] = self.identifier("DEVICE", item)
                else:
                    out[key] = self.scrub(item)
            return out
        if isinstance(value, list):
            return [self.scrub(item) for item in value]
        return self.replace(value)



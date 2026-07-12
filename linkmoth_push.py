"""Browser Web Push notifications (VAPID). Requires optional pywebpush package."""
import base64
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional
from urllib.parse import urlparse

VAPID_SUBJECT = "mailto:linkmoth@localhost"
PUSH_TIMEOUT = 10
MAX_PUSH_SUBSCRIPTIONS = 100
_VAPID_KEY_LOCK = threading.Lock()


def _enable_optional_venv() -> None:
    """Make the opt-in push virtualenv (install.sh --with-push) importable.

    The core service runs on Debian's system Python; pywebpush lives in
    venv/ next to this file so pip never touches system packages. Appended
    (not prepended) so the venv can never shadow the standard library.
    """
    base = Path(__file__).resolve().parent
    for site in sorted(base.glob("venv/lib/python3.*/site-packages")):
        path = str(site)
        if site.is_dir() and path not in sys.path:
            sys.path.append(path)


_enable_optional_venv()


def init_push_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS push_subscriptions(
            id INTEGER PRIMARY KEY,
            endpoint TEXT NOT NULL UNIQUE,
            p256dh TEXT NOT NULL,
            auth TEXT NOT NULL,
            user_agent TEXT,
            created REAL NOT NULL
        );
        """
    )


def ensure_vapid_keys(state_dir: Path) -> Path:
    """Create an EC P-256 VAPID key pair under state_dir if missing."""
    state_dir.mkdir(parents=True, exist_ok=True)
    priv = state_dir / "vapid_private.pem"
    with _VAPID_KEY_LOCK:
        if priv.is_symlink():
            raise RuntimeError(f"refusing symlinked VAPID key: {priv}")
        if priv.is_file():
            os.chmod(priv, 0o600)
            return priv
        temp = priv.with_name(f".{priv.name}.{secrets.token_hex(8)}.tmp")
        fd = None
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            fd = None
            subprocess.run(
                [
                    "openssl", "ecparam", "-genkey", "-name", "prime256v1",
                    "-noout", "-out", str(temp),
                ],
                check=True,
                capture_output=True,
            )
            os.chmod(temp, 0o600)
            os.replace(temp, priv)
            os.chmod(priv, 0o600)
        finally:
            if fd is not None:
                os.close(fd)
            try:
                temp.unlink()
            except FileNotFoundError:
                pass
    return priv


def vapid_public_key_b64(state_dir: Path) -> Optional[str]:
    """Return URL-safe base64 public key for PushManager.subscribe()."""
    priv = ensure_vapid_keys(state_dir)
    try:
        der = subprocess.run(
            ["openssl", "ec", "-in", str(priv), "-pubout", "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
        if len(der) < 65:
            return None
        return _b64url(der[-65:])
    except (subprocess.CalledProcessError, OSError) as e:
        print(f"vapid public key export failed: {e}", file=sys.stderr, flush=True)
        return None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def push_available(state_dir: Path) -> bool:
    try:
        import pywebpush  # noqa: F401
    except ImportError:
        return False
    return vapid_public_key_b64(state_dir) is not None


def list_subscriptions(db_connect: Callable) -> List[dict]:
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT endpoint, p256dh, auth FROM push_subscriptions ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


def save_subscription(db_connect: Callable, sub: dict, user_agent: str = "") -> None:
    if not isinstance(sub, dict):
        raise ValueError("invalid push subscription")
    keys = sub.get("keys") or {}
    if not isinstance(keys, dict):
        raise ValueError("invalid push subscription")
    endpoint = str(sub.get("endpoint") or "").strip()
    p256dh = str(keys.get("p256dh") or "").strip()
    auth_key = str(keys.get("auth") or "").strip()
    if not endpoint or not p256dh or not auth_key:
        raise ValueError("invalid push subscription")
    if (
        len(endpoint) > 2048
        or "\\" in endpoint
        or any(ord(ch) < 33 or ord(ch) == 127 for ch in endpoint)
    ):
        raise ValueError("invalid push endpoint")
    try:
        parsed = urlparse(endpoint)
        port = parsed.port
    except ValueError:
        raise ValueError("invalid push endpoint") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("push endpoint must be an HTTPS URL")
    if len(p256dh) > 256 or len(auth_key) > 128:
        raise ValueError("invalid push subscription keys")
    with db_connect() as conn:
        exists = conn.execute(
            "SELECT 1 FROM push_subscriptions WHERE endpoint=?", (endpoint,)
        ).fetchone()
        if not exists:
            count = conn.execute("SELECT COUNT(*) FROM push_subscriptions").fetchone()[0]
            if count >= MAX_PUSH_SUBSCRIPTIONS:
                raise ValueError(
                    f"push subscription limit reached ({MAX_PUSH_SUBSCRIPTIONS})"
                )
        conn.execute(
            "INSERT INTO push_subscriptions(endpoint, p256dh, auth, user_agent, created)"
            " VALUES(?,?,?,?,?)"
            " ON CONFLICT(endpoint) DO UPDATE SET"
            " p256dh=excluded.p256dh, auth=excluded.auth, user_agent=excluded.user_agent",
            (endpoint, p256dh, auth_key, user_agent[:500], time.time()),
        )


def delete_subscription(db_connect: Callable, endpoint: str) -> None:
    with db_connect() as conn:
        conn.execute("DELETE FROM push_subscriptions WHERE endpoint=?", (endpoint.strip(),))


def _send_one(
    subscription: dict,
    payload: dict,
    priv_path: Path,
) -> Optional[str]:
    from pywebpush import WebPushException, webpush

    info = {
        "endpoint": subscription["endpoint"],
        "keys": {"p256dh": subscription["p256dh"], "auth": subscription["auth"]},
    }
    try:
        webpush(
            subscription_info=info,
            data=json.dumps(payload),
            vapid_private_key=str(priv_path),
            vapid_claims={"sub": VAPID_SUBJECT},
            timeout=PUSH_TIMEOUT,
        )
        return None
    except WebPushException as e:
        status = getattr(getattr(e, "response", None), "status_code", None)
        if status in (404, 410):
            return subscription["endpoint"]
        print(
            f"web push failed: HTTP {status}" if status else "web push failed",
            file=sys.stderr,
            flush=True,
        )
        return None
    except Exception as e:
        print(f"web push error: {e.__class__.__name__}", file=sys.stderr, flush=True)
        return None


def broadcast_push(
    state_dir: Path,
    db_connect: Callable,
    cfg: dict,
    title: str,
    body: str,
    tag: str = "linkmoth",
    url: str = "/",
) -> int:
    """Send a push to all subscribers; returns count delivered."""
    if not cfg.get("push_notifications_enabled", True):
        return 0
    try:
        import pywebpush  # noqa: F401
    except ImportError:
        return 0
    priv = ensure_vapid_keys(state_dir)
    subs = list_subscriptions(db_connect)
    if not subs:
        return 0
    payload = {"title": title, "body": body, "tag": tag, "url": url}
    stale = []
    sent = 0
    for sub in subs:
        dead = _send_one(sub, payload, priv)
        if dead:
            stale.append(dead)
        else:
            sent += 1
    for endpoint in stale:
        delete_subscription(db_connect, endpoint)
    return sent


def send_push_async(
    state_dir: Path,
    db_connect: Callable,
    cfg: dict,
    title: str,
    body: str,
    tag: str = "linkmoth",
    url: str = "/",
) -> None:
    threading.Thread(
        target=broadcast_push,
        args=(state_dir, db_connect, cfg, title, body, tag, url),
        daemon=True,
        name="linkmoth-push",
    ).start()

"""Mandatory local authentication and first-run onboarding for Linkmoth."""
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import math
import os
import secrets
import sqlite3
import struct
import time
from pathlib import Path
from typing import List, Optional, Tuple

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SESSION_COOKIE = "__Host-linkmoth_session"
CSRF_HEADER = "X-CSRF-Token"
DEFAULT_SESSION_TTL = 86400
DEFAULT_SESSION_IDLE = 1800
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_LOCKOUT_SECONDS = 300
RECOVERY_CODE_COUNT = 10
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024
MAX_AUDIT_EVENTS = 1000
AUDIT_RETENTION_SECONDS = 90 * 86400
ONBOARDING_TOKEN_TTL = 24 * 3600
PENDING_TOTP_TTL_SECONDS = 10 * 60


def _header(headers: dict, name: str) -> Optional[str]:
    lower = name.lower()
    for k, v in headers.items():
        if k.lower() == lower:
            return v
    return None


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    if salt is None:
        salt = secrets.token_bytes(32)
    key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    return _b64e(key), _b64e(salt)


def verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    try:
        salt = _b64d(salt_b64)
        expected = _b64d(hash_b64)
        if not 16 <= len(salt) <= 64 or len(expected) != SCRYPT_DKLEN:
            return False
        key = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=SCRYPT_DKLEN,
        )
    except (ValueError, TypeError, MemoryError):
        return False
    return hmac.compare_digest(key, expected)


def hash_token(token: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    return hash_password(token, salt)


def verify_token(token: str, salt_b64: str, hash_b64: str) -> bool:
    return verify_password(token, salt_b64, hash_b64)


def _totp_at(secret_b32: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def verify_totp(secret_b32: str, code: str, window: int = 1) -> bool:
    if not code or not code.isdigit() or len(code) != 6:
        return False
    now = int(time.time()) // 30
    for step in range(now - window, now + window + 1):
        try:
            if hmac.compare_digest(_totp_at(secret_b32, step), code):
                return True
        except (ValueError, TypeError, binascii.Error):
            return False
    return False


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> List[str]:
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(8)
        codes.append("-".join(raw[i : i + 4] for i in range(0, len(raw), 4)))
    return codes


class AuthManager:
    """Session-based auth with optional TOTP and webhook bearer secret."""

    def __init__(self, state_dir: Path, cfg: dict, db_connect):
        self.state_dir = Path(state_dir)
        self.cfg = cfg
        self._db_connect = db_connect
        self.auth_path = self.state_dir / "auth.json"
        self._lock = __import__("threading").RLock()
        self._ensure_tables()

    @property
    def enabled(self) -> bool:
        """Authentication is mandatory; retained for handler compatibility."""
        return True

    @property
    def totp_enabled(self) -> bool:
        # Derived from the writable auth store (not the read-only config file),
        # so the dashboard can enable/disable 2FA at runtime. 2FA is "on" iff
        # an active TOTP secret exists. The legacy auth.totp_enabled config flag
        # is deprecated and no longer consulted.
        return bool(self.load_store().get("totp_secret"))

    def _auth_cfg(self) -> dict:
        value = self.cfg.get("auth") or {}
        if not isinstance(value, dict):
            raise RuntimeError("auth configuration must be a JSON object")
        return value

    def _session_ttl(self) -> int:
        return max(1, int(self._auth_cfg().get("session_ttl_seconds", DEFAULT_SESSION_TTL)))

    def _session_idle(self) -> int:
        return max(60, int(self._auth_cfg().get("session_idle_seconds", DEFAULT_SESSION_IDLE)))

    def _max_attempts(self) -> int:
        return max(1, int(self._auth_cfg().get("login_max_attempts", DEFAULT_MAX_ATTEMPTS)))

    def _lockout_seconds(self) -> int:
        return max(30, int(self._auth_cfg().get("login_lockout_seconds", DEFAULT_LOCKOUT_SECONDS)))

    def _ensure_tables(self):
        with self._db_connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS auth_sessions(
                    id TEXT PRIMARY KEY,
                    created REAL NOT NULL,
                    expires REAL NOT NULL,
                    csrf_token TEXT NOT NULL,
                    totp_verified INTEGER NOT NULL DEFAULT 0,
                    totp_fingerprint TEXT
                );
                CREATE TABLE IF NOT EXISTS auth_login_attempts(
                    ip TEXT PRIMARY KEY,
                    failures INTEGER NOT NULL DEFAULT 0,
                    locked_until REAL NOT NULL DEFAULT 0,
                    last_attempt REAL NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS auth_totp_uses(
                    secret_fingerprint TEXT PRIMARY KEY,
                    last_counter INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_events(
                    id INTEGER PRIMARY KEY,
                    ts REAL NOT NULL,
                    event TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_auth_events_ts ON auth_events(ts);
                """
            )
            session_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(auth_sessions)")
            }
            if "totp_fingerprint" not in session_columns:
                conn.execute(
                    "ALTER TABLE auth_sessions ADD COLUMN totp_fingerprint TEXT"
                )
            if "last_activity" not in session_columns:
                conn.execute(
                    "ALTER TABLE auth_sessions ADD COLUMN last_activity REAL"
                )

    def _load_store_unlocked(self) -> dict:
        if not self.auth_path.exists():
            return {}
        try:
            store = json.loads(self.auth_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise RuntimeError(f"could not read auth store {self.auth_path}: {e}") from e
        if not isinstance(store, dict):
            raise RuntimeError(f"auth store {self.auth_path} must contain a JSON object")
        return store

    def load_store(self) -> dict:
        with self._lock:
            return self._load_store_unlocked()

    def _save_store_unlocked(self, store: dict):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        temp_path = self.auth_path.with_name(
            f".{self.auth_path.name}.{secrets.token_hex(8)}.tmp"
        )
        fd = None
        try:
            fd = os.open(
                temp_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                fd = None
                json.dump(store, f, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, self.auth_path)
            os.chmod(self.auth_path, 0o600)
        finally:
            if fd is not None:
                os.close(fd)
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass

    def save_store(self, store: dict):
        with self._lock:
            self._save_store_unlocked(store)

    def ensure_webhook_secret(self) -> str:
        with self._lock:
            store = self._load_store_unlocked()
            secret = store.get("webhook_secret")
            if not isinstance(secret, str) or len(secret) < 32:
                secret = secrets.token_urlsafe(32)
                store["webhook_secret"] = secret
                self._save_store_unlocked(store)
            return secret

    def rotate_webhook_secret(self) -> str:
        with self._lock:
            store = self._load_store_unlocked()
            secret = secrets.token_urlsafe(32)
            store["webhook_secret"] = secret
            self._save_store_unlocked(store)
        self.audit_event("webhook_rotated", detail="local CLI")
        return secret

    def onboarding_required(self) -> bool:
        return not self.has_password()

    def ensure_onboarding_token(self) -> Optional[str]:
        now = time.time()
        with self._lock:
            store = self._load_store_unlocked()
            if store.get("password_hash") and store.get("password_salt"):
                return None
            token = store.get("onboarding_token")
            expires = store.get("onboarding_expires")
            if (
                isinstance(token, str)
                and len(token) >= 32
                and isinstance(expires, (int, float))
                and expires > now
            ):
                return token
            token = secrets.token_urlsafe(32)
            store["onboarding_token"] = token
            store["onboarding_expires"] = now + ONBOARDING_TOKEN_TTL
            if (
                not isinstance(store.get("webhook_secret"), str)
                or len(store["webhook_secret"]) < 32
            ):
                store["webhook_secret"] = secrets.token_urlsafe(32)
            self._save_store_unlocked(store)
        self.audit_event("onboarding_token_created", detail="expires in 24 hours")
        return token

    def complete_onboarding(self, token: str, password: str) -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
        if len(password) > MAX_PASSWORD_LENGTH:
            raise ValueError(f"password must be at most {MAX_PASSWORD_LENGTH} characters")
        if self.totp_enabled:
            raise RuntimeError(
                "set auth.totp_enabled to false until password onboarding is complete"
            )
        now = time.time()

        def token_is_valid(store):
            expected = store.get("onboarding_token")
            expires = store.get("onboarding_expires")
            return (
                isinstance(expected, str)
                and isinstance(expires, (int, float))
                and expires > now
                and bool(token)
                and hmac.compare_digest(token, expected)
            )

        with self._lock:
            initial_store = self._load_store_unlocked()
            if initial_store.get("password_hash") and initial_store.get("password_salt"):
                raise RuntimeError("onboarding is already complete")
            if not token_is_valid(initial_store):
                raise PermissionError("invalid or expired onboarding token")

        pw_hash, salt = hash_password(password)
        with self._lock:
            store = self._load_store_unlocked()
            if store.get("password_hash") and store.get("password_salt"):
                raise RuntimeError("onboarding is already complete")
            if not token_is_valid(store):
                raise PermissionError("invalid or expired onboarding token")
            store["password_hash"] = pw_hash
            store["password_salt"] = salt
            store.pop("onboarding_token", None)
            store.pop("onboarding_expires", None)
            if (
                not isinstance(store.get("webhook_secret"), str)
                or len(store["webhook_secret"]) < 32
            ):
                store["webhook_secret"] = secrets.token_urlsafe(32)
            self._save_store_unlocked(store)
        self.destroy_all_sessions()
        self.audit_event("onboarding_completed", detail="admin password created")

    def set_password(self, password: str) -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
        if len(password) > MAX_PASSWORD_LENGTH:
            raise ValueError(f"password must be at most {MAX_PASSWORD_LENGTH} characters")
        pw_hash, salt = hash_password(password)
        with self._lock:
            store = self._load_store_unlocked()
            store["password_hash"] = pw_hash
            store["password_salt"] = salt
            store.pop("onboarding_token", None)
            store.pop("onboarding_expires", None)
            if (
                not isinstance(store.get("webhook_secret"), str)
                or len(store["webhook_secret"]) < 32
            ):
                store["webhook_secret"] = secrets.token_urlsafe(32)
            self._save_store_unlocked(store)
        self.destroy_all_sessions()
        self.audit_event("password_changed", detail="all sessions invalidated")

    def has_password(self) -> bool:
        store = self.load_store()
        return bool(store.get("password_hash") and store.get("password_salt"))

    def verify_login_password(self, password: str) -> bool:
        store = self.load_store()
        ph = store.get("password_hash")
        ps = store.get("password_salt")
        if not ph or not ps:
            return False
        return verify_password(password, ps, ph)

    def _recovery_hashes(self, codes: List[str]) -> Tuple[List[str], List[str]]:
        hashes, salts = [], []
        for code in codes:
            h, s = hash_token(self._normalize_recovery_code(code))
            hashes.append(h)
            salts.append(s)
        return hashes, salts

    def setup_totp(self) -> Tuple[str, List[str]]:
        """Immediate activation — for the trusted CLI/console path only."""
        secret = generate_totp_secret()
        codes = generate_recovery_codes()
        hashes, salts = self._recovery_hashes(codes)
        with self._lock:
            store = self._load_store_unlocked()
            store["totp_secret"] = secret
            store["recovery_hashes"] = hashes
            store["recovery_salts"] = salts
            self._clear_pending_totp(store)
            self._save_store_unlocked(store)
        with self._db_connect() as conn:
            conn.execute("DELETE FROM auth_totp_uses")
        self.destroy_all_sessions()
        self.audit_event("totp_configured", detail="all sessions invalidated")
        return secret, codes

    @staticmethod
    def _clear_pending_totp(store: dict) -> None:
        store.pop("pending_totp_secret", None)
        store.pop("pending_recovery_hashes", None)
        store.pop("pending_recovery_salts", None)
        store.pop("pending_totp_created", None)

    def begin_totp_setup(self) -> Tuple[str, str]:
        """Dashboard 2FA enrollment, phase 1: stage a pending secret.

        2FA is not active until activate_totp() proves the user enrolled the
        secret. Only one pending setup exists at a time — this overwrites any
        prior pending state atomically. Recovery codes do not exist yet.
        """
        secret = generate_totp_secret()
        with self._lock:
            store = self._load_store_unlocked()
            store["pending_totp_secret"] = secret
            store["pending_totp_created"] = time.time()
            # Recovery codes are NOT generated yet — they are issued only once
            # the user proves enrollment by entering a valid code (activate).
            store.pop("pending_recovery_hashes", None)
            store.pop("pending_recovery_salts", None)
            self._save_store_unlocked(store)
        self.audit_event("totp_setup_started", detail="pending enrollment")
        return secret, self._provisioning_uri(secret)

    def activate_totp(self, code: str) -> List[str]:
        """Dashboard 2FA enrollment, phase 2: verify a code, go live, and
        return the one-time recovery codes (revealed only now)."""
        expired = False
        with self._lock:
            store = self._load_store_unlocked()
            pending = store.get("pending_totp_secret")
            if not pending:
                raise ValueError("no pending 2FA setup — start setup first")
            try:
                created = float(store.get("pending_totp_created"))
            except (TypeError, ValueError):
                created = 0
            now = time.time()
            if created <= 0 or created > now + 60 or now - created > PENDING_TOTP_TTL_SECONDS:
                self._clear_pending_totp(store)
                self._save_store_unlocked(store)
                expired = True
        if expired:
            self.audit_event("totp_setup_expired", detail="pending enrollment cleared")
            raise ValueError("2FA setup expired — start again")
        if not self._consume_totp(pending, (code or "").strip()):
            raise ValueError("invalid code")
        codes = generate_recovery_codes()
        hashes, salts = self._recovery_hashes(codes)
        expired = False
        with self._lock:
            store = self._load_store_unlocked()
            # Re-read under lock; pending must still be the same secret.
            if store.get("pending_totp_secret") != pending:
                raise ValueError("2FA setup changed — start again")
            try:
                created = float(store.get("pending_totp_created"))
            except (TypeError, ValueError):
                created = 0
            now = time.time()
            if created <= 0 or created > now + 60 or now - created > PENDING_TOTP_TTL_SECONDS:
                self._clear_pending_totp(store)
                self._save_store_unlocked(store)
                expired = True
            else:
                store["totp_secret"] = pending
                store["recovery_hashes"] = hashes
                store["recovery_salts"] = salts
                self._clear_pending_totp(store)
                self._save_store_unlocked(store)
        if expired:
            self.audit_event("totp_setup_expired", detail="pending enrollment cleared")
            raise ValueError("2FA setup expired — start again")
        self.destroy_all_sessions()
        self.audit_event("totp_enabled", detail="all sessions invalidated")
        return codes

    def disable_totp(self):
        with self._lock:
            store = self._load_store_unlocked()
            store.pop("totp_secret", None)
            store.pop("recovery_hashes", None)
            store.pop("recovery_salts", None)
            self._clear_pending_totp(store)
            self._save_store_unlocked(store)
        with self._db_connect() as conn:
            conn.execute("DELETE FROM auth_totp_uses")
        self.destroy_all_sessions()
        self.audit_event("totp_disabled", detail="all sessions invalidated")

    def disable_totp_verified(self, reauth: str) -> None:
        """Disable 2FA, but only after re-proving identity (password or code)."""
        if not self.totp_enabled:
            raise ValueError("2FA is not enabled")
        reauth = (reauth or "").strip()
        if not reauth:
            raise PermissionError("password or authenticator code required")
        if not (self.verify_login_password(reauth) or self.verify_second_factor(reauth)):
            raise PermissionError("re-authentication failed")
        self.disable_totp()

    def change_password(self, current: str, new: str) -> None:
        """Change the admin password after verifying the current one."""
        if not self.verify_login_password(current or ""):
            raise PermissionError("current password is incorrect")
        # set_password validates length, writes the new hash atomically,
        # destroys all sessions, and audits "password_changed".
        self.set_password(new)

    def regenerate_recovery_codes(self, password: str) -> List[str]:
        """Issue a fresh set of one-time recovery codes (password-gated)."""
        if not self.totp_enabled:
            raise ValueError("enable 2FA before generating recovery codes")
        if not self.verify_login_password(password or ""):
            raise PermissionError("password is incorrect")
        codes = generate_recovery_codes()
        hashes, salts = self._recovery_hashes(codes)
        with self._lock:
            store = self._load_store_unlocked()
            store["recovery_hashes"] = hashes
            store["recovery_salts"] = salts
            self._save_store_unlocked(store)
        self.audit_event("recovery_codes_regenerated", detail="previous codes invalidated")
        return codes

    def recovery_codes_remaining(self) -> int:
        return len(self.load_store().get("recovery_hashes") or [])

    @staticmethod
    def _normalize_recovery_code(code: str) -> str:
        return (code or "").strip().replace("-", "").replace(" ", "").lower()

    def _consume_recovery_code(self, code: str) -> bool:
        normalized = self._normalize_recovery_code(code)
        if len(normalized) not in (8, 16):
            return False
        if any(ch not in "0123456789abcdef" for ch in normalized):
            return False
        with self._lock:
            store = self._load_store_unlocked()
            hashes = store.get("recovery_hashes") or []
            salts = store.get("recovery_salts") or []
            for i, (token_hash, salt) in enumerate(zip(hashes, salts)):
                if verify_token(normalized, salt, token_hash):
                    del hashes[i]
                    del salts[i]
                    store["recovery_hashes"] = hashes
                    store["recovery_salts"] = salts
                    self._save_store_unlocked(store)
                    return True
        return False

    def _consume_totp(self, secret: str, code: str, window: int = 1) -> bool:
        if not code.isdigit() or len(code) != 6:
            return False
        now = int(time.time()) // 30
        matched_counter = None
        for counter in range(now - window, now + window + 1):
            try:
                if hmac.compare_digest(_totp_at(secret, counter), code):
                    matched_counter = counter
                    break
            except (ValueError, TypeError, binascii.Error):
                return False
        if matched_counter is None:
            return False
        fingerprint = hashlib.sha256(secret.encode("ascii", "ignore")).hexdigest()
        with self._db_connect() as conn:
            cur = conn.execute(
                "INSERT INTO auth_totp_uses(secret_fingerprint, last_counter) VALUES(?,?)"
                " ON CONFLICT(secret_fingerprint) DO UPDATE SET"
                " last_counter=excluded.last_counter"
                " WHERE auth_totp_uses.last_counter < excluded.last_counter",
                (fingerprint, matched_counter),
            )
            return cur.rowcount > 0

    def verify_second_factor_method(self, code: str) -> Optional[str]:
        store = self.load_store()
        secret = store.get("totp_secret")
        if not secret:
            return None
        normalized = (code or "").strip().replace(" ", "")
        if self._consume_totp(secret, normalized):
            return "totp"
        if self._consume_recovery_code(normalized):
            return "recovery"
        return None

    def verify_second_factor(self, code: str) -> bool:
        return self.verify_second_factor_method(code) is not None

    @staticmethod
    def _provisioning_uri(secret: str, issuer: str = "Linkmoth") -> str:
        # algorithm=SHA1, digits=6, period=30 are the key-uri-format defaults,
        # so they are omitted to keep the URI short enough for a simple QR.
        label = "admin"
        return f"otpauth://totp/{issuer}:{label}?secret={secret}&issuer={issuer}"

    def totp_provisioning_uri(self, issuer: str = "Linkmoth") -> Optional[str]:
        secret = self.load_store().get("totp_secret")
        if not secret:
            return None
        return self._provisioning_uri(secret, issuer)

    def _client_ip(self, headers: dict) -> str:
        remote = (_header(headers, "Remote-Addr") or "unknown").strip()
        try:
            remote_ip = ipaddress.ip_address(remote)
        except ValueError:
            return remote[:64]
        trusted_networks = []
        for cidr in self._auth_cfg().get("trusted_proxy_cidrs", []) or []:
            try:
                trusted_networks.append(
                    ipaddress.ip_network(str(cidr), strict=False)
                )
            except ValueError:
                continue
        is_trusted = lambda address: any(
            address in network for network in trusted_networks
        )
        if is_trusted(remote_ip):
            forwarded = _header(headers, "X-Forwarded-For")
            if forwarded:
                candidates = []
                for item in forwarded.split(","):
                    try:
                        candidates.append(ipaddress.ip_address(item.strip()))
                    except ValueError:
                        continue
                for candidate in reversed(candidates):
                    if not is_trusted(candidate):
                        return str(candidate)
        return str(remote_ip)

    def audit_event(self, event: str, headers: Optional[dict] = None, detail: str = ""):
        ip = self._client_ip(headers or {"Remote-Addr": "local"})
        safe_event = "".join(ch for ch in event.lower() if ch.isalnum() or ch == "_")[:64]
        safe_detail = "".join(
            ch if ch.isprintable() else " " for ch in str(detail)
        )[:200]
        now = time.time()
        try:
            with self._db_connect() as conn:
                conn.execute(
                    "INSERT INTO auth_events(ts, event, ip, detail) VALUES(?,?,?,?)",
                    (now, safe_event or "unknown", ip, safe_detail),
                )
                conn.execute(
                    "DELETE FROM auth_events WHERE ts<?",
                    (now - AUDIT_RETENTION_SECONDS,),
                )
                conn.execute(
                    "DELETE FROM auth_events WHERE id NOT IN"
                    " (SELECT id FROM auth_events ORDER BY id DESC LIMIT ?)",
                    (MAX_AUDIT_EVENTS,),
                )
        except sqlite3.Error:
            # Authentication remains available if optional audit recording fails.
            pass

    def audit_events(self, limit: int = 50) -> List[dict]:
        limit = max(1, min(500, int(limit)))
        with self._db_connect() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    "SELECT ts, event, ip, detail FROM auth_events"
                    " ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
            ]

    def login_allowed(self, headers: dict) -> Tuple[bool, int]:
        ip = self._client_ip(headers)
        now = time.time()
        with self._db_connect() as conn:
            row = conn.execute(
                "SELECT failures, locked_until FROM auth_login_attempts WHERE ip=?",
                (ip,),
            ).fetchone()
            if row and row["locked_until"] > now:
                return False, max(1, math.ceil(row["locked_until"] - now))
        return True, 0

    def record_login_failure(self, headers: dict):
        ip = self._client_ip(headers)
        now = time.time()
        with self._db_connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT failures, locked_until FROM auth_login_attempts WHERE ip=?",
                (ip,),
            ).fetchone()
            if row and row["locked_until"] > now:
                return
            failures = (row["failures"] if row else 0) + 1
            locked_until = 0.0
            if failures >= self._max_attempts():
                locked_until = now + self._lockout_seconds()
                failures = 0
            conn.execute(
                "INSERT INTO auth_login_attempts(ip, failures, locked_until, last_attempt)"
                " VALUES(?,?,?,?) ON CONFLICT(ip) DO UPDATE SET"
                " failures=excluded.failures, locked_until=excluded.locked_until,"
                " last_attempt=excluded.last_attempt",
                (ip, failures, locked_until, now),
            )

    def clear_login_failures(self, headers: dict):
        ip = self._client_ip(headers)
        with self._db_connect() as conn:
            conn.execute("DELETE FROM auth_login_attempts WHERE ip=?", (ip,))

    def create_session(self, totp_verified: bool = False) -> dict:
        sid = secrets.token_urlsafe(32)
        stored_id = self._session_id_hash(sid)
        csrf = secrets.token_urlsafe(32)
        now = time.time()
        expires = now + self._session_ttl()
        with self._db_connect() as conn:
            conn.execute(
                "INSERT INTO auth_sessions(id, created, expires, csrf_token,"
                " totp_verified, last_activity) VALUES(?,?,?,?,?,?)",
                (stored_id, now, expires, csrf, 1 if totp_verified else 0, now),
            )
        return {
            "id": stored_id,
            "cookie_id": sid,
            "csrf_token": csrf,
            "expires": expires,
            "totp_verified": totp_verified,
        }

    @staticmethod
    def _session_id_hash(sid: str) -> str:
        return hashlib.sha256(sid.encode("utf-8")).hexdigest()

    def get_session(self, sid: Optional[str]) -> Optional[dict]:
        if not sid:
            return None
        stored_id = self._session_id_hash(sid)
        now = time.time()
        idle = self._session_idle()
        with self._db_connect() as conn:
            row = conn.execute(
                "SELECT * FROM auth_sessions WHERE id=?", (stored_id,),
            ).fetchone()
            if not row:
                return None
            # Enforce both the absolute lifetime and a server-side idle timeout.
            last_activity = row["last_activity"] if row["last_activity"] is not None else row["created"]
            if row["expires"] <= now or (now - last_activity) > idle:
                conn.execute("DELETE FROM auth_sessions WHERE id=?", (stored_id,))
                return None
            # Slide the idle window, but avoid a write on every request.
            if now - last_activity > 60:
                conn.execute(
                    "UPDATE auth_sessions SET last_activity=? WHERE id=?",
                    (now, stored_id),
                )
            session = dict(row)
            session["last_activity"] = now
            return session

    def _totp_fingerprint(self) -> Optional[str]:
        secret = self.load_store().get("totp_secret")
        if not isinstance(secret, str) or not secret:
            return None
        return hashlib.sha256(secret.encode("ascii", "ignore")).hexdigest()

    def upgrade_session_totp(self, sid: str) -> Optional[str]:
        fingerprint = self._totp_fingerprint()
        if not fingerprint:
            return None
        with self._db_connect() as conn:
            cur = conn.execute(
                "UPDATE auth_sessions SET totp_verified=1, totp_fingerprint=?"
                " WHERE id=? AND expires>?",
                (fingerprint, sid, time.time()),
            )
            return fingerprint if cur.rowcount > 0 else None

    def destroy_session(self, sid: Optional[str]):
        if not sid:
            return
        with self._db_connect() as conn:
            conn.execute("DELETE FROM auth_sessions WHERE id=?", (sid,))

    def destroy_all_sessions(self):
        with self._db_connect() as conn:
            conn.execute("DELETE FROM auth_sessions")

    def purge_expired_sessions(self):
        now = time.time()
        idle = self._session_idle()
        with self._db_connect() as conn:
            conn.execute("DELETE FROM auth_sessions WHERE expires<=?", (now,))
            conn.execute(
                "DELETE FROM auth_sessions"
                " WHERE COALESCE(last_activity, created) < ?",
                (now - idle,),
            )
            conn.execute(
                "DELETE FROM auth_login_attempts WHERE last_attempt<?",
                (now - 7 * 86400,),
            )

    def session_cookie_value(self, handler) -> Optional[str]:
        cookie = handler.headers.get("Cookie") or ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith(SESSION_COOKIE + "="):
                return part.split("=", 1)[1].strip()
        return None

    def session_cookie_header(self, sid: str, expires: float) -> str:
        max_age = max(0, int(expires - time.time()))
        return (
            f"{SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Strict; "
            f"Max-Age={max_age}; Secure"
        )

    def clear_session_cookie_header(self) -> str:
        return (
            f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; "
            f"Max-Age=0; Secure"
        )

    def is_fully_authenticated(self, session: Optional[dict]) -> bool:
        if not session:
            return False
        if self.totp_enabled:
            expected = self._totp_fingerprint()
            actual = session.get("totp_fingerprint")
            if (
                not session.get("totp_verified")
                or not expected
                or not isinstance(actual, str)
                or not hmac.compare_digest(actual, expected)
            ):
                return False
        return True

    def verify_csrf(self, session: Optional[dict], headers: dict) -> bool:
        if not session:
            return False
        token = _header(headers, CSRF_HEADER)
        if not token:
            return False
        expected = session.get("csrf_token")
        if not expected:
            return False
        return hmac.compare_digest(token, expected)

    def verify_webhook_bearer(self, auth_header: Optional[str]) -> bool:
        if not auth_header or not auth_header.startswith("Bearer "):
            return False
        token = auth_header[7:].strip()
        expected = self.ensure_webhook_secret()
        return hmac.compare_digest(token, expected)

    def public_status(self, session: Optional[dict]) -> dict:
        out = {
            "enabled": True,
            "authenticated": self.is_fully_authenticated(session),
            "needs_totp": bool(
                session and self.totp_enabled
                and not self.is_fully_authenticated(session)
            ),
            "has_password": self.has_password(),
            "onboarding_required": self.onboarding_required(),
            "totp_enabled": self.totp_enabled,
        }
        if session and self.is_fully_authenticated(session):
            out["csrf_token"] = session.get("csrf_token")
        elif session and out["needs_totp"]:
            out["csrf_token"] = session.get("csrf_token")
        return out

    def validate_configuration(self):
        try:
            self._session_ttl()
            self._session_idle()
            self._max_attempts()
            self._lockout_seconds()
        except (TypeError, ValueError) as e:
            raise RuntimeError(f"invalid numeric auth setting: {e}") from e
        proxy_cidrs = self._auth_cfg().get("trusted_proxy_cidrs", [])
        if not isinstance(proxy_cidrs, list):
            raise RuntimeError("auth.trusted_proxy_cidrs must be a JSON array")
        for cidr in proxy_cidrs:
            try:
                ipaddress.ip_network(str(cidr), strict=False)
            except ValueError as e:
                raise RuntimeError(f"invalid trusted proxy CIDR: {cidr}") from e
        store = self.load_store()
        if not store.get("password_hash") or not store.get("password_salt"):
            self.ensure_onboarding_token()
            self.ensure_webhook_secret()
            return
        # 2FA is on iff an active secret exists (store-derived). Validate it.
        secret = store.get("totp_secret")
        if secret:
            try:
                _totp_at(secret, 0)
            except (ValueError, TypeError, binascii.Error) as e:
                raise RuntimeError("the stored TOTP secret is invalid") from e
        self.ensure_webhook_secret()

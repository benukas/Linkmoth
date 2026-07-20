"""Linkmoth backup/restore: a portable, secret-free snapshot of history,
settings, and device/webhook configuration, for moving to new hardware.

Deliberately excludes everything in auth.json (the password hash is fine at
rest -- scrypt -- but the TOTP seed and webhook bearer token are stored
plaintext, since the server must be able to read them back) and the VAPID
push key, plus the TLS CA (its private key is just as sensitive as those
excluded secrets: anyone holding it can mint certificates any already-
trusting browser will accept, and a fresh install already generates its own
CA). Restoring onto a new device means redoing the existing one-time setup
(--auth-onboarding-token -> --auth-set-password, re-enroll TOTP if used, note
the freshly generated webhook secret) -- a one-time inconvenience in exchange
for a backup file that is never sensitive enough to need encrypting or
handling like a credential.

Same convention as every other Linkmoth companion module: functions take
`db`, paths, and callables as arguments rather than importing linkmoth.py or
its siblings, so this module can be tested and reasoned about in isolation.
"""
import io
import json
import shutil
import socket
import sqlite3
import tempfile
import time
import zipfile
from pathlib import Path

SCHEMA_VERSION = 1
MANIFEST_NAME = "manifest.json"
DB_NAME = "state.db"
SETTINGS_NAME = "settings.json"


def _snapshot_db_bytes(conn):
    """A consistent point-in-time copy of a live SQLite connection's data,
    via the stdlib backup API -- safe even while the source is being written
    to under WAL, unlike a raw file copy which could grab a torn file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        snapshot_path = Path(tmpdir) / "snapshot.db"
        snapshot = sqlite3.connect(snapshot_path)
        try:
            conn.backup(snapshot)
        finally:
            snapshot.close()
        return snapshot_path.read_bytes()


def build_backup_archive(db_connect, export_settings, version):
    """Return a backup archive as zip bytes: manifest + DB snapshot +
    redacted settings. `export_settings` is a zero-arg callable returning a
    dict already stripped of secrets (linkmoth_core._export_settings)."""
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "linkmoth_version": version,
        "created_at": time.time(),
        "source_hostname": socket.gethostname(),
    }
    with db_connect() as conn:
        db_bytes = _snapshot_db_bytes(conn)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2))
        zf.writestr(DB_NAME, db_bytes)
        zf.writestr(SETTINGS_NAME, json.dumps(export_settings(), indent=2))
    return buf.getvalue()


def read_backup_manifest(archive_path):
    """Read just the manifest, without restoring anything -- lets a caller
    validate/display a backup before committing to the restore."""
    with zipfile.ZipFile(archive_path) as zf:
        return json.loads(zf.read(MANIFEST_NAME))


def restore_backup_archive(archive_path, db_path, init_db, apply_settings):
    """Restore history and settings from a backup archive.

    `db_path` is replaced with the archived snapshot (the previous file, if
    any, is renamed aside rather than deleted); `init_db` is then called
    against it so any schema migrations added since the backup was taken
    apply automatically, the same way a normal startup self-migrates.
    `apply_settings` validates and applies the archived settings the same
    way a dashboard save would, rather than overwriting blind.

    Returns a summary dict. Raises ValueError for a malformed or
    incompatible archive before anything on disk is touched.
    """
    archive_path = Path(archive_path)
    with zipfile.ZipFile(archive_path) as zf:
        try:
            manifest = json.loads(zf.read(MANIFEST_NAME))
        except (KeyError, json.JSONDecodeError) as e:
            raise ValueError(f"not a Linkmoth backup archive: {e}") from None
        if manifest.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported backup schema_version {manifest.get('schema_version')!r} "
                f"(this Linkmoth understands {SCHEMA_VERSION})"
            )
        try:
            db_bytes = zf.read(DB_NAME)
            settings = json.loads(zf.read(SETTINGS_NAME))
        except (KeyError, json.JSONDecodeError) as e:
            raise ValueError(f"backup archive is incomplete or corrupt: {e}") from None

    db_path = Path(db_path)
    preserved = None
    if db_path.exists():
        preserved = db_path.with_name(f"{db_path.name}.pre-restore-{int(time.time())}")
        shutil.move(str(db_path), str(preserved))
    db_path.write_bytes(db_bytes)
    init_db()

    settings_ok, settings_result = apply_settings(settings)

    return {
        "manifest": manifest,
        "preserved_previous_db": str(preserved) if preserved else None,
        "settings_applied": settings_ok,
        "settings_errors": None if settings_ok else settings_result,
    }

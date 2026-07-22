"""Linkmoth backup/restore: a portable snapshot of history, settings, and
device/webhook configuration, for moving to new hardware.

Deliberately excludes everything in auth.json (the password hash is fine at
rest -- scrypt -- but the TOTP seed and webhook bearer token are stored
plaintext, since the server must be able to read them back) and the VAPID
push key, plus the TLS CA (its private key is just as sensitive as those
excluded secrets: anyone holding it can mint certificates any already-
trusting browser will accept, and a fresh install already generates its own
CA). Restoring onto a new device means redoing the existing one-time setup
(--auth-onboarding-token -> --auth-set-password, re-enroll TOTP if used, note
the freshly generated webhook secret) -- a one-time inconvenience in exchange
for a backup file that never carries an active credential.

The database snapshot itself is also sanitized before it's embedded (see
_sanitize_snapshot): outbound webhook destination URLs and custom headers
(commonly bearer tokens), browser push subscriptions, queued deliveries, and
authentication session/login-attempt/TOTP-replay state are all stripped.
Webhook names, presets, event selections, templates, and escalation timing
survive the round trip; destination URLs and any credentials must be
re-entered after restore, the same as everything else in auth.json.

Same convention as every other Linkmoth companion module: functions take
`db`, paths, and callables as arguments rather than importing linkmoth.py or
its siblings, so this module can be tested and reasoned about in isolation.
"""
import json
import os
import shutil
import socket
import sqlite3
import tempfile
import threading
import time
import zipfile
from pathlib import Path

SCHEMA_VERSION = 1
MANIFEST_NAME = "manifest.json"
DB_NAME = "state.db"
SETTINGS_NAME = "settings.json"
ARCHIVE_MEMBERS = frozenset({MANIFEST_NAME, DB_NAME, SETTINGS_NAME})

# Per-member ceilings, checked (against the ZIP-declared uncompressed size)
# before any member is read into memory, so a hostile or corrupt archive is
# rejected cheaply instead of expanding a tiny compressed blob into gigabytes
# of RAM. The manifest and settings are small JSON documents read wholesale;
# the database is streamed to disk, but is still bounded well above any
# realistic long-lived Raspberry Pi history.
MEMBER_MAX_BYTES = {
    MANIFEST_NAME: 64 * 1024,
    SETTINGS_NAME: 1 * 1024 * 1024,
    DB_NAME: 4 * 1024 * 1024 * 1024,
}

# Settings flags whose paired credential (a webhook URL) is stripped from
# every backup -- so the flag must be forced off, or a restore onto a fresh
# device fails validation ("enabled but no URL") for a backup that was
# perfectly valid on the source.
_BACKUP_DISABLED_SETTING_FLAGS = (
    "discord_notifications_enabled",
    "notify_webhook_enabled",
)

# Statements that strip secrets and device-specific state from a DB snapshot
# before it's embedded in a backup archive. Table names are hardcoded, not
# user input, so the string formatting here isn't building SQL from
# untrusted data -- but each statement is still guarded individually so a
# schema that predates one of these tables (a very old backup) doesn't fail
# the whole snapshot. Outbound webhooks are also disabled (enabled=0) and
# their last-delivery bookkeeping cleared: their destination URL/headers are
# gone, so leaving them enabled would make a restored install immediately
# queue and retry deliveries against empty destinations.
_SANITIZE_STATEMENTS = (
    "UPDATE webhooks SET url = '', headers = '{}', enabled = 0,"
    " last_send_ts = NULL, last_status = NULL, last_error = NULL",
    "DELETE FROM webhook_queue",
    "DELETE FROM push_subscriptions",
    "DELETE FROM auth_sessions",
    "DELETE FROM auth_login_attempts",
    "DELETE FROM auth_totp_uses",
)


def _sanitize_snapshot(conn):
    """Strip secrets and device-specific state from a DB snapshot in place.
    Runs only against the already-detached backup copy, never the live
    database."""
    for stmt in _SANITIZE_STATEMENTS:
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError:
            pass  # table doesn't exist in this schema version yet
    conn.commit()
    # Reclaims freed pages so deleted secrets don't linger in the snapshot
    # file's slack space before it's embedded in the archive.
    conn.execute("VACUUM")


def _sanitize_backup_settings(settings):
    """Force credential-dependent flags off in a settings dict, since the
    matching webhook URLs are never carried in a backup. Applied both when
    building an archive (so the stored settings.json is honest) and again at
    restore (so even an older backup, made before this existed, still
    validates cleanly before the database is swapped)."""
    if not isinstance(settings, dict):
        return settings
    cleaned = dict(settings)
    for flag in _BACKUP_DISABLED_SETTING_FLAGS:
        if flag in cleaned:
            cleaned[flag] = False
    return cleaned


class BackupInProgress(RuntimeError):
    pass


def _snapshot_db_to_path(conn, dest_path):
    """Write a consistent, sanitized point-in-time copy of a live SQLite
    connection's data to `dest_path`, via the stdlib backup API -- safe
    even while the source is being written to under WAL, unlike a raw file
    copy which could grab a torn file."""
    snapshot = sqlite3.connect(dest_path)
    try:
        conn.backup(snapshot)
        _sanitize_snapshot(snapshot)
    finally:
        snapshot.close()


# Only one backup operation runs at a time: build_backup_archive_to_path
# already needs a full extra copy of the database on disk momentarily, and
# the HTTP endpoint can't stop a second authenticated request from arriving
# mid-backup, so this bounds worst-case concurrent disk/CPU use to one.
BACKUP_LOCK = threading.Lock()


def build_backup_archive_to_path(archive_path, db_connect, export_settings, version):
    """Write a backup archive (manifest + sanitized DB snapshot + redacted
    settings) directly to a 0600 file at `archive_path`, without ever
    holding more than one copy of the database in memory -- so a caller
    (the HTTP endpoint) can stream the result back to a client afterward
    instead of returning several database-sizes of bytes in one response."""
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "linkmoth_version": version,
        "created_at": time.time(),
        "source_hostname": socket.gethostname(),
    }
    archive_path = Path(archive_path)
    if not BACKUP_LOCK.acquire(blocking=False):
        raise BackupInProgress("a backup is already being created")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            snapshot_path = Path(tmpdir) / "snapshot.db"
            with db_connect() as conn:
                _snapshot_db_to_path(conn, snapshot_path)
            archive_path.touch(exist_ok=True)
            os.chmod(archive_path, 0o600)
            settings = _sanitize_backup_settings(export_settings())
            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2))
                zf.write(snapshot_path, arcname=DB_NAME)
                zf.writestr(SETTINGS_NAME, json.dumps(settings, indent=2))
    finally:
        BACKUP_LOCK.release()


def build_backup_archive(db_connect, export_settings, version):
    """Return a backup archive as zip bytes (CLI/test convenience -- the
    HTTP endpoint uses build_backup_archive_to_path to stream instead of
    holding the whole archive in memory)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        archive_path = Path(tmpdir) / "backup.zip"
        build_backup_archive_to_path(archive_path, db_connect, export_settings, version)
        return archive_path.read_bytes()


def read_backup_manifest(archive_path):
    """Read just the manifest, without restoring anything -- lets a caller
    validate/display a backup before committing to the restore."""
    with zipfile.ZipFile(archive_path) as zf:
        return json.loads(zf.read(MANIFEST_NAME))


def _ensure_db_not_in_use(db_path):
    """Best-effort check that nothing else holds the live database open,
    beyond whatever process-manager check the caller already did -- catches
    a Linkmoth run manually (not via systemd) that a service-status check
    would miss entirely."""
    db_path = Path(db_path)
    if not db_path.exists():
        return
    conn = sqlite3.connect(db_path, timeout=0)
    try:
        conn.execute("BEGIN EXCLUSIVE")
        conn.execute("COMMIT")
    except sqlite3.OperationalError as e:
        raise ValueError(
            "the Linkmoth database appears to be in use by another process "
            "-- stop the linkmoth service first: " + str(e)
        ) from None
    finally:
        conn.close()


def _validate_archive_members(zf):
    """Check the archive's member list and per-member size before reading
    anything, so a corrupt or hostile archive fails cheaply."""
    names = zf.namelist()
    if len(names) != len(set(names)):
        raise ValueError("backup archive contains duplicate members")
    if set(names) != ARCHIVE_MEMBERS:
        raise ValueError(
            f"backup archive members {sorted(names)!r} do not match the "
            f"expected set {sorted(ARCHIVE_MEMBERS)!r}"
        )
    for info in zf.infolist():
        limit = MEMBER_MAX_BYTES.get(info.filename)
        if limit is not None and info.file_size > limit:
            raise ValueError(
                f"{info.filename} ({info.file_size} bytes) exceeds its "
                f"maximum allowed backup member size ({limit} bytes)"
            )


def _db_sidecars(db_path):
    """The WAL-mode sidecar files SQLite keeps beside the main database."""
    return (
        db_path.with_name(db_path.name + "-wal"),
        db_path.with_name(db_path.name + "-shm"),
    )


def _replace_live_database(scratch_path, db_path):
    """Swap the migrated scratch database in for the live one, safely under
    WAL mode.

    Linkmoth runs the database in WAL mode, so committed data can be sitting
    in `state.db-wal` rather than the main file, and a stale `-wal`/`-shm`
    left by an unclean shutdown will be replayed on top of whatever main
    file it finds next to it. Moving only `state.db` aside would therefore
    both (a) let the old WAL silently override the freshly installed
    database, and (b) leave the preserved `.pre-restore-*` copy missing any
    records that lived only in that WAL. So: checkpoint the live database
    first (folding the WAL into the main file), preserve the now-complete
    main file, delete both sidecars, then atomically rename the scratch file
    into place. Returns the preserved copy's path, or None if there was no
    existing database.
    """
    preserved = None
    wal, shm = _db_sidecars(db_path)
    if db_path.exists():
        try:
            conn = sqlite3.connect(db_path)
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                conn.close()
        except sqlite3.DatabaseError:
            # Corrupt or unreadable live database: nothing to fold in, and
            # we're replacing it anyway. Preserve whatever bytes exist.
            pass
        preserved = db_path.with_name(f"{db_path.name}.pre-restore-{int(time.time())}")
        shutil.move(str(db_path), str(preserved))
        wal.unlink(missing_ok=True)
        shm.unlink(missing_ok=True)
    try:
        os.replace(scratch_path, db_path)
    except OSError:
        if preserved is not None:
            shutil.move(str(preserved), str(db_path))
        raise
    return preserved


def _rollback_live_database(db_path, preserved):
    """Remove a failed restore and put the exact previous database back."""
    db_path.unlink(missing_ok=True)
    for sidecar in _db_sidecars(db_path):
        sidecar.unlink(missing_ok=True)
    if preserved is not None:
        shutil.move(str(preserved), str(db_path))


def restore_backup_archive(archive_path, db_path, init_db, apply_settings,
                           validate_settings=None):
    """Restore history and settings from a backup archive.

    Everything is validated and migrated against a scratch copy in a
    temporary directory -- on the same filesystem as `db_path`, so the final
    swap is an atomic rename -- before the live database is touched at all.
    `init_db` runs schema creation/migration against that scratch copy first
    (it accepts an optional path, same as linkmoth_core.init_db). The
    archived settings are validated up front too, via `validate_settings`
    (linkmoth_core.validate_settings) when provided, so a settings payload
    that can't be applied refuses the restore before the database is
    touched rather than leaving a swapped-in database with settings that
    silently didn't take. Only once both the database and the settings check
    out does the scratch file replace the live one (WAL-safely, preserving
    the previous database as `.pre-restore-*`); `apply_settings` then writes
    the settings. If that final write fails, whether by raising or by returning
    validation/write errors, the previous database is put back rather than
    left half-restored.

    Returns a summary dict. Raises ValueError for a malformed, oversized, or
    incompatible archive, an unapplyable settings payload, or a database
    currently in use, before anything on disk is touched.
    """
    archive_path = Path(archive_path)
    db_path = Path(db_path)

    with zipfile.ZipFile(archive_path) as zf:
        _validate_archive_members(zf)
        try:
            manifest = json.loads(zf.read(MANIFEST_NAME))
        except json.JSONDecodeError as e:
            raise ValueError(f"not a Linkmoth backup archive: {e}") from None
        if not isinstance(manifest, dict):
            raise ValueError("backup manifest is not a valid JSON object")
        if manifest.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported backup schema_version {manifest.get('schema_version')!r} "
                f"(this Linkmoth understands {SCHEMA_VERSION})"
            )
        try:
            settings = json.loads(zf.read(SETTINGS_NAME))
        except json.JSONDecodeError as e:
            raise ValueError(f"backup archive is incomplete or corrupt: {e}") from None
        if not isinstance(settings, dict):
            raise ValueError("backup settings.json is not a valid settings object")

        # Re-force credential-dependent flags off even for an older backup
        # made before the builder did this, then validate the result up
        # front -- so a settings payload that can't be applied refuses the
        # restore now, before the database is swapped, instead of leaving a
        # restored database with settings that silently never took.
        settings = _sanitize_backup_settings(settings)
        if validate_settings is not None:
            ok, result = validate_settings(settings)
            if not ok:
                raise ValueError(f"backup settings failed validation: {result}")

        _ensure_db_not_in_use(db_path)

        # Same directory as db_path (not the system temp dir) so the final
        # swap below is a same-filesystem, and therefore atomic, rename.
        with tempfile.TemporaryDirectory(
            prefix=".linkmoth-restore-", dir=db_path.parent
        ) as tmp:
            scratch_path = Path(tmp) / "restore.db"
            try:
                with zf.open(DB_NAME) as src, open(scratch_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
            except KeyError as e:
                raise ValueError(f"backup archive is incomplete or corrupt: {e}") from None
            try:
                os.chmod(scratch_path, 0o600)
            except (AttributeError, OSError):
                pass

            conn = sqlite3.connect(scratch_path)
            try:
                row = conn.execute("PRAGMA quick_check").fetchone()
            except sqlite3.DatabaseError as e:
                raise ValueError(f"backup database is not a valid SQLite file: {e}") from None
            finally:
                conn.close()
            if not row or row[0] != "ok":
                raise ValueError(
                    f"backup database failed integrity check: "
                    f"{row[0] if row else 'no result'}"
                )

            # Migrate the scratch copy first -- a failure here never
            # touches the live database at all.
            try:
                init_db(scratch_path)
            except Exception as e:
                raise ValueError(f"backup database failed migration: {e}") from None

            # A migration under WAL mode leaves committed data in a -wal
            # sidecar; checkpoint it back into the single main file, since
            # only that file gets moved into place below.
            conn = sqlite3.connect(scratch_path)
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                conn.close()

            preserved = _replace_live_database(scratch_path, db_path)

    try:
        settings_ok, settings_result = apply_settings(settings)
    except Exception as e:
        # Leave the current installation untouched rather than half-restored:
        # put the previous database back if applying settings blew up in a
        # way apply_settings itself doesn't turn into a clean (False, errors).
        # Pre-swap validation makes this path unlikely, but keep it exact.
        _rollback_live_database(db_path, preserved)
        raise ValueError(f"settings could not be applied to the restored archive: {e}") from None
    if not settings_ok:
        _rollback_live_database(db_path, preserved)
        raise ValueError(
            "settings could not be applied to the restored archive: "
            f"{settings_result}"
        )

    return {
        "manifest": manifest,
        "preserved_previous_db": str(preserved) if preserved else None,
        "settings_applied": settings_ok,
        "settings_errors": None if settings_ok else settings_result,
    }

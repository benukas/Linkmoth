"""Unified outbound notifications: Discord and browser push.

Generic/preset webhooks moved to linkmoth_webhooks (multi-webhook engine with a
persistent retry queue); this module remains the Discord + push facade.
"""
import re
import sqlite3
import threading
import time
from collections import Counter
from typing import List, Optional

RECOVERY_DEDUPE_SECONDS = 45
MAX_QUIET_EVENTS = 500
MAX_IN_APP_NOTIFICATIONS = 500
MAX_IN_APP_NOTIFICATION_PAGE = 100
QUIET_SCHEDULER_SECONDS = 30
_lock = threading.Lock()
# Recovery dedupe is keyed per incident/fault so two *different* recoveries
# inside the window both notify; only true duplicates of the same recovery
# (e.g. retriggered digests for one outage) are suppressed.
_recovery_sent_mono = {}


def init_notification_db(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS quiet_hour_events(
            id INTEGER PRIMARY KEY,
            ts REAL NOT NULL,
            title TEXT NOT NULL,
            detail TEXT NOT NULL,
            send_discord INTEGER NOT NULL DEFAULT 0,
            send_push INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_quiet_hour_events_ts
            ON quiet_hour_events(ts);
        CREATE TABLE IF NOT EXISTS in_app_notifications(
            id INTEGER PRIMARY KEY,
            event_key TEXT NOT NULL UNIQUE,
            created REAL NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            detail TEXT NOT NULL,
            source_kind TEXT NOT NULL,
            source_id TEXT NOT NULL,
            source_ref TEXT,
            read_at REAL
        );
        CREATE INDEX IF NOT EXISTS idx_in_app_notifications_created
            ON in_app_notifications(id DESC);
        CREATE INDEX IF NOT EXISTS idx_in_app_notifications_unread
            ON in_app_notifications(read_at, id DESC);
        """
    )


def record_in_app_notification(
    db_connect,
    *,
    event_key: str,
    event_type: str,
    severity: str,
    title: str,
    detail: str = "",
    source_kind: str,
    source_id: str,
    source_ref: Optional[str] = None,
    created: Optional[float] = None,
) -> bool:
    """Store one authenticated-dashboard event without affecting delivery.

    The unique event key makes incident transitions safe to replay after a
    process restart. The table is deliberately bounded like the other local
    queues so a forgotten dashboard can never grow state.db without limit.
    """
    event_key = str(event_key or "").strip()[:300]
    event_type = str(event_type or "").strip()[:80]
    severity = str(severity or "unknown").strip()[:20]
    title = str(title or "Linkmoth alert").strip()[:200]
    detail = str(detail or "").strip()[:500]
    source_kind = str(source_kind or "linkmoth").strip()[:40]
    source_id = str(source_id or "linkmoth").strip()[:200]
    source_ref = str(source_ref or "").strip()[:100] or None
    if not event_key or not event_type:
        raise ValueError("event_key and event_type are required")
    stamp = time.time() if created is None else float(created)
    with db_connect() as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO in_app_notifications("
            "event_key, created, event_type, severity, title, detail, "
            "source_kind, source_id, source_ref) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                event_key, stamp, event_type, severity, title, detail,
                source_kind, source_id, source_ref,
            ),
        )
        inserted = bool(cur.rowcount)
        if inserted:
            conn.execute(
                "DELETE FROM in_app_notifications WHERE id NOT IN "
                "(SELECT id FROM in_app_notifications ORDER BY id DESC LIMIT ?)",
                (MAX_IN_APP_NOTIFICATIONS,),
            )
    return inserted


def list_in_app_notifications(db_connect, limit: int = 50) -> dict:
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        raise ValueError("limit must be an integer") from None
    limit = max(1, min(MAX_IN_APP_NOTIFICATION_PAGE, limit))
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT id, created, event_type, severity, title, detail, "
            "source_kind, source_id, source_ref, read_at "
            "FROM in_app_notifications ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        unread = int(conn.execute(
            "SELECT COUNT(*) FROM in_app_notifications WHERE read_at IS NULL"
        ).fetchone()[0])
    return {
        "notifications": [dict(row) for row in rows],
        "unread_count": unread,
    }


def read_in_app_notifications(
    db_connect,
    *,
    ids: Optional[List[int]] = None,
    all_notifications: bool = False,
    now: Optional[float] = None,
) -> dict:
    if all_notifications and ids:
        raise ValueError("choose ids or all, not both")
    if not all_notifications:
        if not isinstance(ids, list) or not ids:
            raise ValueError("ids must be a non-empty array")
        if len(ids) > MAX_IN_APP_NOTIFICATION_PAGE:
            raise ValueError("too many notification ids")
        clean_ids = []
        for value in ids:
            if isinstance(value, bool):
                raise ValueError("notification ids must be positive integers")
            try:
                item_id = int(value)
            except (TypeError, ValueError):
                raise ValueError(
                    "notification ids must be positive integers"
                ) from None
            if item_id <= 0:
                raise ValueError("notification ids must be positive integers")
            clean_ids.append(item_id)
        ids = sorted(set(clean_ids))
    stamp = time.time() if now is None else float(now)
    with db_connect() as conn:
        if all_notifications:
            cur = conn.execute(
                "UPDATE in_app_notifications SET read_at=? WHERE read_at IS NULL",
                (stamp,),
            )
        else:
            placeholders = ",".join("?" for _ in ids)
            cur = conn.execute(
                f"UPDATE in_app_notifications SET read_at=? "
                f"WHERE read_at IS NULL AND id IN ({placeholders})",
                (stamp, *ids),
            )
        unread = int(conn.execute(
            "SELECT COUNT(*) FROM in_app_notifications WHERE read_at IS NULL"
        ).fetchone()[0])
    return {"marked": int(cur.rowcount), "unread_count": unread}


def validate_quiet_time(value) -> str:
    value = str(value or "").strip()
    match = re.fullmatch(r"([01][0-9]|2[0-3]):([0-5][0-9])", value)
    if not match:
        raise ValueError
    return value


def _clock_minutes(value: str) -> int:
    hour, minute = validate_quiet_time(value).split(":")
    return int(hour) * 60 + int(minute)


def quiet_hours_active(cfg: dict, now: Optional[float] = None) -> bool:
    if not cfg.get("quiet_hours_enabled", False):
        return False
    try:
        start = _clock_minutes(cfg.get("quiet_hours_start", "22:00"))
        end = _clock_minutes(cfg.get("quiet_hours_end", "07:00"))
    except ValueError:
        return False
    if start == end:
        return False
    local = time.localtime(time.time() if now is None else float(now))
    current = local.tm_hour * 60 + local.tm_min
    if start < end:
        return start <= current < end
    return current >= start or current < end


def defer_notification_if_quiet(
    cfg: dict,
    db_connect,
    title: str,
    detail: str = "",
    *,
    discord: bool = False,
    push: bool = False,
    now: Optional[float] = None,
) -> bool:
    """Persist a safe summary when requested channels are inside quiet hours."""
    if not quiet_hours_active(cfg, now):
        return False
    if discord:
        from linkmoth_discord import discord_alerts_active
        discord = discord_alerts_active(cfg)
    push = bool(push and cfg.get("push_notifications_enabled", True))
    if not discord and not push:
        return False
    stamp = time.time() if now is None else float(now)
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO quiet_hour_events"
            "(ts, title, detail, send_discord, send_push) VALUES(?,?,?,?,?)",
            (
                stamp,
                str(title or "Linkmoth alert").strip()[:200],
                str(detail or "").strip()[:500],
                int(discord),
                int(push),
            ),
        )
        conn.execute(
            "DELETE FROM quiet_hour_events WHERE id NOT IN "
            "(SELECT id FROM quiet_hour_events ORDER BY id DESC LIMIT ?)",
            (MAX_QUIET_EVENTS,),
        )
    return True


def quiet_hours_status(cfg: dict, db_connect, now: Optional[float] = None) -> dict:
    pending = 0
    try:
        with db_connect() as conn:
            pending = int(
                conn.execute("SELECT COUNT(*) FROM quiet_hour_events").fetchone()[0]
            )
    except sqlite3.Error:
        pass
    local = time.localtime(time.time() if now is None else float(now))
    zone_index = 1 if local.tm_isdst > 0 and len(time.tzname) > 1 else 0
    return {
        "enabled": bool(cfg.get("quiet_hours_enabled", False)),
        "active": quiet_hours_active(cfg, now),
        "start": str(cfg.get("quiet_hours_start", "22:00")),
        "end": str(cfg.get("quiet_hours_end", "07:00")),
        "pending": pending,
        "timezone": time.tzname[zone_index] if time.tzname else "local time",
        # Current time on the Linkmoth host, so the dashboard can show which
        # clock quiet hours is actually evaluated against (the Pi's own zone).
        "now": f"{local.tm_hour:02d}:{local.tm_min:02d}",
    }


def _digest_lines(rows) -> List[str]:
    counts = Counter(
        (
            str(row["title"] or "Linkmoth alert"),
            str(row["detail"] or ""),
        )
        for row in rows
    )
    lines = []
    for (title, detail), count in counts.most_common(12):
        summary = title + (f" – {detail}" if detail else "")
        lines.append(f"• {summary}" + (f" ({count} times)" if count > 1 else ""))
    if len(counts) > len(lines):
        lines.append(f"• {len(counts) - len(lines)} more alert type(s)")
    return lines


def flush_quiet_hours_digest(
    cfg: dict,
    state_dir,
    db_connect,
    now: Optional[float] = None,
) -> bool:
    """Send and clear one morning summary once quiet hours and outages end."""
    if quiet_hours_active(cfg, now):
        return False
    try:
        with db_connect() as conn:
            outage = conn.execute(
                "SELECT active FROM network_outage WHERE id=1"
            ).fetchone()
            if outage and outage[0]:
                return False
            rows = conn.execute(
                "SELECT * FROM quiet_hour_events ORDER BY id"
            ).fetchall()
            if not rows:
                return False
    except sqlite3.Error as exc:
        print(f"quiet-hours digest error: {exc}", flush=True)
        return False

    lines = _digest_lines(rows)
    count = len(rows)
    send_discord = any(bool(row["send_discord"]) for row in rows)
    send_push = any(bool(row["send_push"]) for row in rows)
    # Dispatch before clearing. These events were cleared first, so a
    # transient failure at the moment of the morning flush discarded the whole
    # overnight digest permanently. Keeping them until the summary has gone
    # out means the next scheduler pass retries instead.
    try:
        if send_discord:
            from linkmoth_discord import send_quiet_hours_digest_alert
            send_quiet_hours_digest_alert(lines, count, cfg)
        if send_push and cfg.get("push_notifications_enabled", True):
            from linkmoth_push import send_push_async
            preview = "; ".join(line[2:] for line in lines[:3])
            body = f"{count} alert(s) arrived overnight."
            if preview:
                body += f" {preview}"
            send_push_async(
                state_dir, db_connect, cfg,
                "Quiet-hours summary", body,
                tag="linkmoth-quiet-hours",
            )
    except Exception as exc:
        print(
            f"quiet-hours digest send failed, keeping {count} event(s)"
            f" to retry: {exc.__class__.__name__}",
            flush=True,
        )
        return False

    # Delete exactly the rows that were summarised, by id: anything deferred
    # while the summary was being sent belongs to the next digest. A failure
    # here re-sends rather than loses, which is the right way round.
    try:
        with db_connect() as conn:
            conn.executemany(
                "DELETE FROM quiet_hour_events WHERE id=?",
                [(int(row["id"]),) for row in rows],
            )
    except sqlite3.Error as exc:
        print(f"quiet-hours digest cleanup error: {exc}", flush=True)
        return False
    return True


def quiet_hours_scheduler_loop(cfg: dict, state_dir, db_connect) -> None:
    time.sleep(5)
    while True:
        try:
            flush_quiet_hours_digest(cfg, state_dir, db_connect)
        except Exception as exc:
            print(
                f"quiet-hours scheduler error: {exc.__class__.__name__}",
                flush=True,
            )
        time.sleep(QUIET_SCHEDULER_SECONDS)


def _recovery_dedupe_key(incident: Optional[dict]) -> str:
    """Incident recoveries dedupe per incident; every non-incident recovery
    (outage tracker, Kuma digest) shares one 'global' key so the same
    network-wide recovery reported by two paths still sends only once."""
    if incident and incident.get("id") is not None:
        return f"inc:{incident['id']}"
    return "global"


def _recovery_recently_sent(key: str) -> bool:
    with _lock:
        sent = _recovery_sent_mono.get(key)
        return sent is not None and (time.monotonic() - sent) < RECOVERY_DEDUPE_SECONDS


def _mark_recovery_sent(key: str) -> None:
    with _lock:
        now = time.monotonic()
        _recovery_sent_mono[key] = now
        for stale in [
            k for k, ts in _recovery_sent_mono.items()
            if now - ts >= RECOVERY_DEDUPE_SECONDS
        ]:
            del _recovery_sent_mono[stale]


def notify_recovery(
    cfg: dict,
    state_dir,
    db_connect,
    prior_fault: dict,
    recovery_verdict: dict,
    checks: List[dict],
    digest: List[str],
    duration_s: float,
    incident: Optional[dict] = None,
    source: str = "linkmoth",
    fault_checks: Optional[List[dict]] = None,
) -> bool:
    """Single recovery path for outage tracker, incident loop, and Kuma digest.

    `checks` is the just-confirmed *healthy* ladder that triggered recovery –
    by definition it can't show what broke. `fault_checks`, when available,
    is the ladder from when the fault was actually confirmed (or last
    reconfirmed), and is what the "what was actually wrong" fields in the
    notification should be built from; callers fall back to `checks` when
    they have no historical snapshot to offer.
    """
    dedupe_key = _recovery_dedupe_key(incident)
    if _recovery_recently_sent(dedupe_key):
        return False
    from linkmoth_discord import (
        outage_recovery_push_text,
        send_discord_alert,
        send_outage_recovery_alert,
    )
    from linkmoth_push import send_push_async

    title, body = outage_recovery_push_text(prior_fault, digest, duration_s)
    if defer_notification_if_quiet(
        cfg, db_connect, title, body,
        discord=True, push=True,
    ):
        _mark_recovery_sent(dedupe_key)
        return True

    sent = False
    if incident:
        from linkmoth_discord import incident_payload
        prior = {
            "code": prior_fault.get("code"),
            "title": prior_fault.get("title"),
        }
        payload = incident_payload(
            incident, recovery_verdict, "recovery", prior_fault=prior,
            checks=checks, suppressed_digest=digest,
            fault_checks=fault_checks,
        )
        if send_discord_alert(payload, "recovery", cfg):
            sent = True
    elif send_outage_recovery_alert(
        prior_fault, recovery_verdict, checks, digest, cfg, duration_s,
        fault_checks=fault_checks,
    ):
        sent = True

    if send_push_async(state_dir, db_connect, cfg, title, body, tag="linkmoth-recovery"):
        sent = True

    if sent or digest:
        _mark_recovery_sent(dedupe_key)
    return sent or bool(digest)


def notify_fault(
    cfg: dict,
    state_dir,
    db_connect,
    incident: dict,
    verdict: dict,
    checks: List[dict],
) -> bool:
    """Non-global fault: Discord embed + push."""
    from linkmoth_discord import incident_payload, send_discord_alert
    from linkmoth_push import send_push_async

    title = verdict.get("title") or "Network fault"
    body = verdict.get("explain") or verdict.get("hint") or ""
    if defer_notification_if_quiet(
        cfg, db_connect, title, body,
        discord=True, push=True,
    ):
        return True

    payload = incident_payload(
        incident, verdict, "fault", checks=checks,
    )
    sent = send_discord_alert(payload, "fault", cfg)
    send_push_async(state_dir, db_connect, cfg, f"🚨 {title}", body, tag="linkmoth-fault")
    return sent

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
QUIET_SCHEDULER_SECONDS = 30
_lock = threading.Lock()
_last_recovery_mono = 0.0


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
        """
    )


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
            ids = [int(row["id"]) for row in rows]
            conn.executemany(
                "DELETE FROM quiet_hour_events WHERE id=?",
                [(item_id,) for item_id in ids],
            )
    except sqlite3.Error as exc:
        print(f"quiet-hours digest error: {exc}", flush=True)
        return False

    lines = _digest_lines(rows)
    count = len(rows)
    send_discord = any(bool(row["send_discord"]) for row in rows)
    send_push = any(bool(row["send_push"]) for row in rows)
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


def _recovery_recently_sent() -> bool:
    with _lock:
        return (time.monotonic() - _last_recovery_mono) < RECOVERY_DEDUPE_SECONDS


def _mark_recovery_sent() -> None:
    global _last_recovery_mono
    with _lock:
        _last_recovery_mono = time.monotonic()


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
) -> bool:
    """Single recovery path for outage tracker, incident loop, and Kuma digest."""
    if _recovery_recently_sent():
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
        _mark_recovery_sent()
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
        )
        if send_discord_alert(payload, "recovery", cfg):
            sent = True
    elif send_outage_recovery_alert(
        prior_fault, recovery_verdict, checks, digest, cfg, duration_s,
    ):
        sent = True

    if send_push_async(state_dir, db_connect, cfg, title, body, tag="linkmoth-recovery"):
        sent = True

    if sent or digest:
        _mark_recovery_sent()
    return True


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

"""Unified outbound notifications: Discord and browser push.

Generic/preset webhooks moved to linkmoth_webhooks (multi-webhook engine with a
persistent retry queue); this module remains the Discord + push facade.
"""
import threading
import time
from typing import List, Optional

RECOVERY_DEDUPE_SECONDS = 45
_lock = threading.Lock()
_last_recovery_mono = 0.0


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

    title, body = outage_recovery_push_text(prior_fault, digest, duration_s)
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

    payload = incident_payload(
        incident, verdict, "fault", checks=checks,
    )
    sent = send_discord_alert(payload, "fault", cfg)
    title = verdict.get("title") or "Network fault"
    body = verdict.get("explain") or verdict.get("hint") or ""
    send_push_async(state_dir, db_connect, cfg, f"🚨 {title}", body, tag="linkmoth-fault")
    return sent

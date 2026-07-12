"""Inbound webhook handling: Uptime Kuma proxy plus a generic inbound endpoint.

Both share one core: silence service alerts during global network outages,
otherwise trigger Linkmoth's own diagnosis.
"""
import json
import re
import time
from typing import Optional

from linkmoth_discord import send_kuma_discord_alert

# Verdict codes where the path to the internet is broken — not a single-service fault.
GLOBAL_OUTAGE_CODES = frozenset({"pi_link", "router_down", "wan_down"})
OUTAGE_EVAL_MAX_AGE = 300
MAX_SUPPRESSED_ALERTS = 500


def _suppressed_payload_summary(payload: dict) -> dict:
    """Keep only fields needed for a recovery digest, not arbitrary input data."""
    if not isinstance(payload, dict):
        return {}
    summary = {}
    source = str(payload.get("source") or "")[:32]
    if source:
        summary["source"] = source
    monitor = payload.get("monitor")
    if isinstance(monitor, dict):
        name = str(monitor.get("name") or "")[:200]
    else:
        name = str(monitor or "")[:200]
    if name:
        summary["monitor"] = {"name": name}
    if source == "linkmoth" and isinstance(payload.get("verdict"), dict):
        verdict = payload["verdict"]
        summary["verdict"] = {
            "code": str(verdict.get("code") or "")[:64],
            "title": str(verdict.get("title") or "")[:200],
        }
    return summary


def parse_kuma_payload(body: bytes):
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
    detail = f"{monitor}: {msg}"[:200] if (monitor or msg) else "webhook"
    return status, detail, data


def is_global_outage(verdict: Optional[dict]) -> bool:
    if not verdict:
        return False
    return verdict.get("code") in GLOBAL_OUTAGE_CODES


def is_effective_global_outage(verdict: Optional[dict], checks: Optional[list] = None) -> bool:
    """True when the path beyond the LAN is broken (WAN/router/host), even if WLAN probe fails too."""
    if not verdict:
        return False
    if verdict.get("severity") == "ok" or verdict.get("code") == "all_clear":
        return False
    if is_global_outage(verdict):
        return True
    if not checks:
        return False
    by_id = {ch.get("id"): ch for ch in checks}
    gw_ok = by_id.get("gateway", {}).get("ok") is not False
    upstream_dead = by_id.get("upstream_dns", {}).get("ok") is False
    ping_dead = by_id.get("raw_ping", {}).get("ok") is False
    # A successful HTTPS request proves that the WAN still has a usable path,
    # even when direct DNS and ICMP are filtered.  Missing HTTPS evidence is
    # treated as unknown for compatibility with older stored ladder runs.
    https_works = by_id.get("https", {}).get("ok") is True
    return gw_ok and upstream_dead and ping_dead and not https_works


def record_suppressed(db_connect, kuma_status, detail, verdict, payload: dict, reason: str):
    payload_summary = _suppressed_payload_summary(payload)
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO suppressed_alerts("
            " ts, kuma_status, monitor_detail, verdict_code, verdict_title, payload, reason"
            ") VALUES(?,?,?,?,?,?,?)",
            (
                time.time(),
                kuma_status,
                detail[:500],
                (verdict or {}).get("code"),
                (verdict or {}).get("title"),
                json.dumps(payload_summary),
                reason[:200],
            ),
        )
        conn.execute(
            "DELETE FROM suppressed_alerts WHERE id NOT IN ("
            " SELECT id FROM suppressed_alerts ORDER BY id DESC LIMIT ?)",
            (MAX_SUPPRESSED_ALERTS,),
        )


def fetch_suppressed_alerts(db_connect):
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT id, ts, kuma_status, monitor_detail, payload FROM suppressed_alerts"
            " ORDER BY ts ASC"
        ).fetchall()
    return [dict(r) for r in rows]


def clear_suppressed_alerts(db_connect):
    with db_connect() as conn:
        conn.execute("DELETE FROM suppressed_alerts")


def _format_outage_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{seconds // 60}m"
    return f"{seconds / 3600:.1f}h"


def extract_service_name(row: dict) -> str:
    try:
        payload = json.loads(row.get("payload") or "{}")
        if isinstance(payload, dict):
            if payload.get("source") == "linkmoth":
                v = payload.get("verdict") or {}
                return str(v.get("title") or v.get("code") or "Linkmoth outage").strip()
            monitor = (payload.get("monitor") or {}).get("name")
            if monitor:
                return str(monitor).strip()
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass
    detail = str(row.get("monitor_detail") or "").strip()
    if detail.startswith("Linkmoth detected:"):
        return detail.replace("Linkmoth detected:", "", 1).strip() or "Linkmoth outage"
    if ":" in detail:
        return detail.split(":", 1)[0].strip()
    return detail or "Unknown service"


def build_outage_digest_lines(rows, recovery_ts: Optional[float] = None) -> list:
    """Build bullet lines for services suppressed during a global outage."""
    recovery_ts = recovery_ts or time.time()
    services = {}
    for row in rows:
        if row.get("kuma_status") not in (0, None):
            continue
        name = extract_service_name(row)
        ts = float(row["ts"])
        if name not in services or ts < services[name]:
            services[name] = ts
    lines = []
    for name, started in sorted(services.items(), key=lambda item: item[1]):
        dur = _format_outage_duration(recovery_ts - started)
        lines.append(f"• {name} (Down for {dur})")
    return lines


def flush_suppression_digest(db_connect, recovery_ts: Optional[float] = None):
    """Build digest lines from suppressed alerts and clear the queue."""
    rows = fetch_suppressed_alerts(db_connect)
    if not rows:
        return []
    lines = build_outage_digest_lines(rows, recovery_ts)
    clear_suppressed_alerts(db_connect)
    return lines


def parse_inbound_payload(body: bytes):
    """Parse the generic inbound shape: {source, event, monitor, severity, message}."""
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    event = str(data.get("event") or "").strip().lower()
    if event in ("up", "recovered", "resolved", "ok"):
        status = 1
    elif event in ("down", "alert", "fault", "problem", "firing"):
        status = 0
    else:
        status = None
    source = re.sub(
        r"[^a-z0-9_-]", "", str(data.get("source") or "").strip().lower()
    )[:32] or "external"
    monitor = str(data.get("monitor") or "").strip()
    message = str(data.get("message") or data.get("detail") or "").strip()
    parts = [p for p in (monitor, message) if p]
    detail = f"{source}: {' — '.join(parts)}"[:300] if parts else f"{source}: webhook"
    return status, detail, source, data


def handle_inbound_alert(status, detail, raw, engine, cfg: dict, db_connect,
                         forward_discord: bool = False,
                         source_prefix: str = "inbound") -> dict:
    """Shared core: suppress during global outages, else trigger diagnosis.

    status: 1 = the external monitor recovered, 0 = it went down, None = unknown.
    """
    verdict, checks, ladder_cached = engine.evaluate_network_for_proxy()
    outage = (
        is_effective_global_outage(verdict, checks)
        or engine.has_active_global_outage()
    )
    open_inc = engine.open_incident()

    if outage:
        record_suppressed(
            db_connect,
            status,
            detail,
            verdict,
            raw,
            "global network outage — alert silenced",
        )
        return {
            "action": "suppressed",
            "reason": "global_outage",
            "verdict_code": verdict.get("code") if verdict else None,
            "verdict_title": verdict.get("title") if verdict else None,
            "detail": detail,
            "ladder_cached": ladder_cached,
        }

    forwarded = False
    if forward_discord:
        forwarded = send_kuma_discord_alert(
            {
                "kuma_status": status,
                "detail": detail,
                "monitor": detail,
                "payload": raw,
                "checks": checks,
                "verdict": verdict,
                "incident_ref": (open_inc or {}).get("ref"),
            },
            cfg,
        )

    if status == 1:
        digest = flush_suppression_digest(db_connect, recovery_ts=time.time())
        if digest:
            from linkmoth_notify import notify_recovery
            notify_recovery(
                cfg,
                engine.state_dir,
                db_connect,
                prior_fault={
                    "code": "global_outage",
                    "title": "Global network outage cleared",
                    "started": time.time() - 60,
                },
                recovery_verdict=verdict or {
                    "severity": "ok",
                    "code": "all_clear",
                    "title": "Network path healthy",
                    "explain": "",
                    "hint": "",
                },
                checks=checks or [],
                digest=digest,
                duration_s=0,
                source=f"{source_prefix}-recovery",
            )
        inc = engine.open_incident()
        if inc:
            engine.trigger(f"{source_prefix}-up", detail)
        action = "forwarded_recovery" if forwarded else "noted_recovery"
    else:
        engine.trigger(
            f"{source_prefix}-down" if status == 0 else f"{source_prefix}-proxy",
            detail,
        )
        action = "forwarded" if forwarded else "triggered"

    inc = engine.open_incident()
    return {
        "action": action,
        "forwarded_discord": forwarded,
        "verdict_code": verdict.get("code") if verdict else None,
        "detail": detail,
        "incident_ref": (inc or {}).get("ref"),
        "ladder_cached": ladder_cached,
    }


def handle_kuma_webhook(body: bytes, engine, cfg: dict, db_connect) -> dict:
    """Evaluate network state and forward or suppress an Uptime Kuma notification."""
    kuma_status, detail, raw = parse_kuma_payload(body)
    return handle_inbound_alert(
        kuma_status, detail, raw, engine, cfg, db_connect,
        forward_discord=True, source_prefix="kuma",
    )


def handle_inbound_webhook(body: bytes, engine, cfg: dict, db_connect) -> dict:
    """Generic inbound webhook (Grafana/Zabbix/scripts): triggers diagnosis."""
    status, detail, source, raw = parse_inbound_payload(body)
    return handle_inbound_alert(
        status, detail, raw, engine, cfg, db_connect,
        forward_discord=False, source_prefix=source,
    )

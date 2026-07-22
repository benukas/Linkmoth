"""Outbound Discord webhook alerts for Linkmoth incident state changes."""
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import List, Optional
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlparse

WEBHOOK_TIMEOUT = 10
DISCORD_HOSTS = frozenset({
    "discord.com",
    "discordapp.com",
    "canary.discord.com",
    "ptb.discord.com",
})

FAULT_COLOR = 0xE74C3C      # #E74C3C – active faults
RECOVERY_COLOR = 0x2ECC71    # #2ECC71 – recovery / all clear

def discord_notifications_enabled(cfg: Optional[dict] = None) -> bool:
    if cfg is None:
        return False
    return bool(cfg.get("discord_notifications_enabled", False))


def discord_webhook_url(cfg: Optional[dict] = None) -> str:
    env = os.environ.get("LINKMOTH_DISCORD_WEBHOOK_URL", "").strip()
    if env:
        return env
    if cfg is None:
        return ""
    return str(cfg.get("discord_webhook_url") or "").strip()


def discord_alerts_active(cfg: Optional[dict] = None) -> bool:
    """True when notifications are enabled and a valid webhook URL is configured."""
    if not discord_notifications_enabled(cfg):
        return False
    url = discord_webhook_url(cfg)
    return bool(url) and is_valid_discord_webhook(url)


def is_valid_discord_webhook(url: str) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme != "https":
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    host = (parsed.hostname or "").lower()
    if host not in DISCORD_HOSTS:
        return False
    if port not in (None, 443):
        return False
    if parsed.fragment:
        return False
    return parsed.path.startswith("/api/webhooks/")


class _NoRedirect(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _network_error_label(exc: Exception) -> str:
    """Avoid putting credential-bearing webhook URLs into service logs."""
    if isinstance(exc, urlerror.HTTPError):
        code = exc.code
        exc.close()
        return f"HTTP {code}"
    reason = getattr(exc, "reason", None)
    return (reason or exc).__class__.__name__


def incident_payload(
    incident: dict,
    verdict: dict,
    status_type: str,
    prior_fault: Optional[dict] = None,
    checks: Optional[List[dict]] = None,
    suppressed_digest: Optional[List[str]] = None,
    fault_checks: Optional[List[dict]] = None,
) -> dict:
    """Build a plain dict passed to send_discord_alert.

    `fault_checks`, when given, is the fault ladder from when the problem was
    actually confirmed – used in place of `checks` for a recovery message's
    ladder display, since `checks` there is the healthy run that just closed
    the incident and can't show what was down.
    """
    return {
        "incident_id": incident.get("id"),
        "incident_ref": incident.get("ref"),
        "started": incident.get("started"),
        "source": incident.get("source"),
        "detail": incident.get("detail"),
        "status_type": status_type,
        "verdict": dict(verdict),
        "prior_fault": dict(prior_fault) if prior_fault else None,
        "checks": list(checks or []),
        "fault_checks": list(fault_checks) if fault_checks else None,
        "suppressed_digest": list(suppressed_digest or []),
    }


def _ladder_icon(ok, state=None) -> str:
    if ok is False:
        return "🔴"
    if state in ("partial", "degraded"):
        return "🟡"
    if ok is True:
        return "🟢"
    return "⚪"


def format_ladder_lines(checks: List[dict]) -> str:
    """Dashboard-style fault ladder lines for Discord embed fields."""
    lines = []
    for ch in checks:
        label = str(ch.get("label") or ch.get("id") or "Check")
        detail = str(ch.get("detail") or "")
        icon = _ladder_icon(ch.get("ok"), ch.get("state"))
        if detail:
            lines.append(f"{icon} {label}: {detail}")
        else:
            lines.append(f"{icon} {label}")
        for probe in ch.get("probes") or []:
            target = str(probe.get("target") or "Target")
            pd = str(probe.get("detail") or "")
            pi = _ladder_icon(probe.get("ok"))
            lines.append(f"  ↳ {pi} {target}" + (f": {pd}" if pd else ""))
        for step in ch.get("micro") or []:
            sl = str(step.get("label") or "Check")
            sd = str(step.get("detail") or "")
            si = _ladder_icon(step.get("ok"))
            lines.append(f"  ↳ {si} {sl}: {sd}")
    return "\n".join(lines)


def _truncate(text: str, limit: int = 1024) -> str:
    text = str(text or "").strip()
    if len(text) <= limit:
        return text or "–"
    return text[: limit - 1] + "…"


def _embed_title(verdict: dict, status_type: str) -> str:
    if status_type == "recovery":
        return "✅ All clear – network recovered"
    raw = str(verdict.get("title") or "Network fault confirmed")
    severity = verdict.get("severity")
    if severity == "bad":
        return f"🚨 {raw}"
    if severity == "warn":
        return f"⚠️ {raw}"
    return raw


def _embed_description(verdict: dict, status_type: str, prior_fault: Optional[dict]) -> str:
    if status_type == "recovery":
        if prior_fault:
            prev = str(prior_fault.get("title") or prior_fault.get("code") or "fault")
            base = (
                f"Previous fault: **{prev}**. "
                "Linkmoth saw two consecutive healthy ladder runs."
            )
        else:
            base = "Linkmoth saw two consecutive healthy ladder runs and closed the incident."
        explain = str(verdict.get("explain") or "")
        if explain:
            return _truncate(f"{base}\n\n{explain}", 4096)
        return _truncate(base, 4096)

    explain = str(verdict.get("explain") or "Linkmoth confirmed a network issue.")
    hint = str(verdict.get("hint") or "")
    if hint:
        return _truncate(f"{explain}\n\n**Next step:** {hint}", 4096)
    return _truncate(explain, 4096)


def build_embed(incident_data: dict, status_type: str) -> dict:
    verdict = incident_data.get("verdict") or {}
    prior = incident_data.get("prior_fault")
    checks = incident_data.get("checks") or []
    inc_id = incident_data.get("incident_id")
    inc_ref = incident_data.get("incident_ref")
    inc_label = inc_ref or (f"#{inc_id}" if inc_id else None)
    source = incident_data.get("source") or "unknown"
    detail = incident_data.get("detail") or ""
    started = incident_data.get("started")

    color = RECOVERY_COLOR if status_type == "recovery" else FAULT_COLOR
    title = _embed_title(verdict, status_type)
    description = _embed_description(verdict, status_type, prior)

    fields = []
    # On recovery, `checks` is the just-confirmed *healthy* ladder – showing
    # it would mean every rung reads green right under "network recovered",
    # telling the reader nothing about what was actually wrong. Prefer the
    # ladder captured when the fault was last confirmed, if one was recorded.
    ladder_source = checks
    showing_fault_ladder = False
    if status_type == "recovery" and incident_data.get("fault_checks"):
        ladder_source = incident_data["fault_checks"]
        showing_fault_ladder = True
    ladder_text = format_ladder_lines(ladder_source)
    if ladder_text:
        fields.append({
            "name": "Fault ladder (at time of fault)" if showing_fault_ladder else "Fault ladder",
            "value": _truncate(ladder_text, 1024),
            "inline": False,
        })

    if status_type == "fault":
        if inc_label:
            fields.append({
                "name": "Reference",
                "value": inc_label,
                "inline": True,
            })
        fields.append({
            "name": "Severity",
            "value": str(verdict.get("severity") or "unknown"),
            "inline": True,
        })
        fields.append({
            "name": "Code",
            "value": str(verdict.get("code") or "unknown"),
            "inline": True,
        })
    else:
        duration = "–"
        if started:
            secs = max(0, int(time.time() - started))
            if secs < 90:
                duration = f"{secs}s"
            elif secs < 5400:
                duration = f"{secs // 60} min"
            else:
                duration = f"{secs / 3600:.1f} h"
        # A network-wide outage recovery has no incidents-table row behind it
        # (it's tracked separately by OutageTracker), so there is nothing
        # meaningful to put in an "Incident" field – showing a bare "–" is
        # noise, not information. Only include it when there's a real one.
        if inc_label:
            fields.append({
                "name": "Incident",
                "value": inc_label,
                "inline": True,
            })
        fields.append({
            "name": "Duration",
            "value": duration,
            "inline": True,
        })

    fields.append({
        "name": "Trigger",
        "value": _truncate(f"{source}: {detail}", 256),
        "inline": False,
    })

    digest = incident_data.get("suppressed_digest") or []
    if status_type == "recovery" and digest:
        fields.insert(0, {
            "name": "📦 Services Affected During Outage",
            "value": _truncate("\n".join(digest), 1024),
            "inline": False,
        })

    embed = {
        "title": _truncate(title, 256),
        "description": description,
        "color": color,
        "fields": fields,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "footer": {"text": f"Linkmoth {inc_label}" if inc_label else "Linkmoth"},
    }
    return embed


def _post_webhook(url: str, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    req = urlrequest.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "linkmoth-discord/1.0",
        },
        method="POST",
    )
    opener = urlrequest.build_opener(urlrequest.ProxyHandler({}), _NoRedirect())
    with opener.open(req, timeout=WEBHOOK_TIMEOUT) as resp:
        if resp.status >= 400:
            raise urlerror.HTTPError(url, resp.status, resp.reason, resp.headers, None)


def _send_sync(url: str, incident_data: dict, status_type: str) -> None:
    try:
        embed = build_embed(incident_data, status_type)
        _post_webhook(url, {"embeds": [embed]})
    except Exception as e:
        print(
            f"discord alert failed ({status_type}): {_network_error_label(e)}",
            file=sys.stderr,
            flush=True,
        )


def send_discord_alert(
    incident_data: dict,
    status_type: str,
    cfg: Optional[dict] = None,
) -> bool:
    """Fire-and-forget Discord notification; never raises to callers."""
    if status_type not in ("fault", "recovery"):
        print(f"discord alert skipped: invalid status_type {status_type!r}",
              file=sys.stderr, flush=True)
        return False
    if not discord_alerts_active(cfg):
        return False
    url = discord_webhook_url(cfg)
    data = dict(incident_data)
    data["status_type"] = status_type
    threading.Thread(
        target=_send_sync,
        args=(url, data, status_type),
        daemon=True,
        name=f"discord-{status_type}-{data.get('incident_id')}",
    ).start()
    return True


def _send_device_sync(url: str, device: dict, result: dict, recovery: bool) -> None:
    try:
        state = str(result.get("state") or "unknown")
        title = (
            f"✅ {device.get('name') or 'Device'} recovered"
            if recovery
            else f"🔴 {device.get('name') or 'Device'} is {state}"
        )
        fields = [{
            "name": "Device",
            "value": _truncate(str(device.get("address") or "–"), 256),
            "inline": True,
        }, {
            "name": "Preset",
            "value": _truncate(str(device.get("preset") or "generic"), 256),
            "inline": True,
        }]
        checks = []
        for check in result.get("results") or []:
            mark = _ladder_icon(check.get("ok"))
            checks.append(
                f"{mark} {check.get('kind') or 'check'}: "
                f"{check.get('detail') or 'no detail'}"
            )
        if checks:
            fields.append({
                "name": "Checks",
                "value": _truncate("\n".join(checks), 1024),
                "inline": False,
            })
        embed = {
            "title": _truncate(title, 256),
            "description": _truncate(result.get("summary") or state, 4096),
            "color": RECOVERY_COLOR if recovery else FAULT_COLOR,
            "fields": fields,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "footer": {"text": "Linkmoth · LAN device"},
        }
        _post_webhook(url, {"embeds": [embed]})
    except Exception as e:
        print(
            f"discord device alert failed: {_network_error_label(e)}",
            file=sys.stderr,
            flush=True,
        )


def send_device_discord_alert(
    device: dict,
    result: dict,
    recovery: bool,
    cfg: Optional[dict] = None,
) -> bool:
    """Send a device-only alert without constructing a network incident."""
    if not discord_alerts_active(cfg):
        return False
    url = discord_webhook_url(cfg)
    threading.Thread(
        target=_send_device_sync,
        args=(url, dict(device), dict(result), bool(recovery)),
        daemon=True,
        name=f"discord-device-{device.get('id')}",
    ).start()
    return True


def build_kuma_service_embed(alert_data: dict) -> dict:
    """Discord embed for a forwarded Uptime Kuma service alert."""
    kuma_status = alert_data.get("kuma_status")
    detail = str(alert_data.get("detail") or "Service status change")
    is_up = kuma_status == 1
    title = f"{'✅' if is_up else '🔴'} Uptime Kuma: {detail}"
    description = "Linkmoth verified the network path is healthy – this looks service-specific."
    if is_up:
        description = "Service recovered. Linkmoth confirmed the network path is still healthy."
    fields = []
    checks = alert_data.get("checks") or []
    ladder_text = format_ladder_lines(checks)
    if ladder_text:
        fields.append({
            "name": "Network check (Linkmoth)",
            "value": _truncate(ladder_text, 1024),
            "inline": False,
        })
    v = alert_data.get("verdict") or {}
    if v.get("title"):
        fields.append({
            "name": "Network verdict",
            "value": _truncate(v["title"], 256),
            "inline": False,
        })
    footer = "Linkmoth · Uptime Kuma proxy"
    inc_ref = alert_data.get("incident_ref")
    if inc_ref:
        footer = f"Linkmoth · {inc_ref}"
    return {
        "title": _truncate(title, 256),
        "description": _truncate(description, 4096),
        "color": RECOVERY_COLOR if is_up else FAULT_COLOR,
        "fields": fields,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "footer": {"text": footer},
    }


def _send_kuma_sync(url: str, alert_data: dict) -> None:
    try:
        embed = build_kuma_service_embed(alert_data)
        _post_webhook(url, {"embeds": [embed]})
    except Exception as e:
        print(
            f"discord kuma alert failed: {_network_error_label(e)}",
            file=sys.stderr,
            flush=True,
        )


def _send_payload_sync(url: str, payload: dict, label: str) -> None:
    try:
        _post_webhook(url, payload)
    except Exception as exc:
        print(
            f"discord {label} failed: {_network_error_label(exc)}",
            file=sys.stderr,
            flush=True,
        )


def send_kuma_discord_alert(alert_data: dict, cfg: Optional[dict] = None) -> bool:
    """Forward an Uptime Kuma service alert to Discord when the network path is healthy."""
    if not discord_alerts_active(cfg):
        return False
    url = discord_webhook_url(cfg)
    threading.Thread(
        target=_send_kuma_sync,
        args=(url, dict(alert_data)),
        daemon=True,
        name="discord-kuma-proxy",
    ).start()
    return True


def _format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{seconds // 60} min"
    return f"{seconds / 3600:.1f} h"


def send_suppression_digest_alert(digest: List[str], verdict: dict, cfg: Optional[dict] = None) -> bool:
    """Discord summary of services that were down during a global outage."""
    if not digest or not discord_alerts_active(cfg):
        return False
    url = discord_webhook_url(cfg)
    title = "📦 Services affected during outage"
    body_lines = [
        "Network path is healthy again. These were held while Linkmoth could not reach Discord:",
        "",
        "\n".join(digest),
    ]
    vtitle = str((verdict or {}).get("title") or "")
    if vtitle:
        body_lines.insert(0, f"**{vtitle}**")
    payload = {
        "embeds": [{
            "title": title,
            "description": _truncate("\n".join(body_lines), 4096),
            "color": RECOVERY_COLOR,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "footer": {"text": "Linkmoth · outage recovery"},
        }],
    }
    threading.Thread(
        target=_send_payload_sync,
        args=(url, payload, "outage digest"),
        daemon=True,
        name="discord-outage-digest",
    ).start()
    return True


def send_quiet_hours_digest_alert(
    lines: List[str],
    count: int,
    cfg: Optional[dict] = None,
) -> bool:
    """Send one summary after the configured quiet period ends."""
    if not lines or not discord_alerts_active(cfg):
        return False
    url = discord_webhook_url(cfg)
    start = str((cfg or {}).get("quiet_hours_start", "22:00"))
    end = str((cfg or {}).get("quiet_hours_end", "07:00"))
    payload = {
        "embeds": [{
            "title": "☀️ Quiet-hours summary",
            "description": _truncate(
                f"{int(count)} alert(s) were held from {start} to {end} "
                f"(Linkmoth host local time).\n\n" + "\n".join(lines),
                4096,
            ),
            "color": RECOVERY_COLOR,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "footer": {"text": "Linkmoth · quiet hours"},
        }],
    }
    threading.Thread(
        target=_send_payload_sync,
        args=(url, payload, "quiet-hours digest"),
        daemon=True,
        name="discord-quiet-hours-digest",
    ).start()
    return True


def send_monthly_digest_alert(
    lines: List[str],
    month_label: str,
    cfg: Optional[dict] = None,
) -> bool:
    """One summary of the previous month's network health."""
    if not lines or not discord_alerts_active(cfg):
        return False
    url = discord_webhook_url(cfg)
    payload = {
        "embeds": [{
            "title": f"📊 Network report – {month_label}",
            "description": _truncate("\n".join(lines), 4096),
            "color": RECOVERY_COLOR,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "footer": {"text": "Linkmoth · monthly report"},
        }],
    }
    threading.Thread(
        target=_send_payload_sync,
        args=(url, payload, "monthly digest"),
        daemon=True,
        name="discord-monthly-digest",
    ).start()
    return True


def send_outage_recovery_alert(
    prior_fault: dict,
    recovery_verdict: dict,
    checks: List[dict],
    digest: List[str],
    cfg: Optional[dict],
    duration_s: float,
    fault_checks: Optional[List[dict]] = None,
) -> bool:
    """Recovery alert after a global outage – first message that can reach Discord."""
    if not discord_alerts_active(cfg):
        return False
    synthetic = {
        "id": None,
        "ref": None,
        "started": prior_fault.get("started"),
        "source": "linkmoth",
        "detail": "Global outage cleared",
    }
    prior = {
        "code": prior_fault.get("code"),
        "title": prior_fault.get("title"),
    }
    payload = incident_payload(
        synthetic,
        recovery_verdict,
        "recovery",
        prior_fault=prior,
        checks=checks,
        suppressed_digest=digest,
        fault_checks=fault_checks,
    )
    return send_discord_alert(payload, "recovery", cfg)


def outage_recovery_push_text(prior_fault: dict, digest: List[str], duration_s: float) -> tuple:
    title = "Network recovered"
    prev = str(prior_fault.get("title") or prior_fault.get("code") or "Outage")
    dur = _format_duration(duration_s)
    body = f"{prev} cleared after {dur}."
    if digest:
        body += f" {len(digest)} service(s) were affected."
    return title, body

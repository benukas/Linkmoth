#!/usr/bin/env python3
"""Linkmoth: event-driven network fault diagnosis with a LAN-only dashboard.

Sits idle until triggered (Uptime Kuma webhook, dashboard button, or CLI),
then runs a layered fault ladder several times over a few minutes and records
the incident with a plain verdict of who is to blame.

This file is now just the bootstrap: it wires together linkmoth_core (state/
config/db/TLS), linkmoth_probes (network checks), linkmoth_engine (the
Engine/DEVICES/AUTH singletons), and linkmoth_handler (the HTTP routes), then
exposes the CLI entrypoints (--doctor, --auth-*, --once, and the foreground
server loop).
"""
import json
import os
import shutil
import socket
import sqlite3
import ssl
import stat
import sys
import threading
import time
from pathlib import Path
from urllib import request as urlrequest
from urllib.parse import urlparse

# When run directly (`python linkmoth.py`), this module executes as
# "__main__", not "linkmoth" -- so linkmoth_handler.py's `import linkmoth`
# (used for its own lazy, circular-import-safe access to ENGINE/DEVICES/
# get_auth) would otherwise trigger a second, fresh top-to-bottom execution
# of this whole file under the separate name "linkmoth". Register this
# already-running module under that name first so the later import just
# finds it, partially initialized, instead of re-running it.
if __name__ == "__main__":
    sys.modules.setdefault("linkmoth", sys.modules[__name__])

# Re-exports the full public surface of the four split-out modules so
# `import linkmoth; linkmoth.X` keeps working for every name the codebase
# (tests, docs, external tooling) referenced before the split -- this file
# is a thin bootstrap, but it's still the one importable entry point.
from linkmoth_core import (
    AUTO_VACUUM_MODE, AUTO_VACUUM_NAMES, BASE, BoundedTLSServer, CFG,
    CHANGELOG_URL, CONFIG_ERROR, CONFIG_PATH, DB_BUSY_TIMEOUT_MS,
    DB_LOCK_RETRIES, DB_LOCK_RETRIES_LOCK, DB_PATH, DEFAULT_CONFIG,
    DEFAULT_CONFIG_PATH, DEFAULT_STATE_DIR, DEFAULT_TLS_DIR, FAVICON_PATH,
    GITHUB_API_HOST, GITHUB_RELEASE_HOST, GITHUB_RELEASE_PATH, GITHUB_REPO,
    GITHUB_UPDATE_USER_AGENT, HOST_CPU_SAMPLE, HOST_CPU_SAMPLER_STARTED,
    HOST_CPU_UPDATED_AT, HOST_CPU_VALUE, HOST_CPU_VALUES, HOST_STATS_LOCK,
    ICON_PATH, INSTALLATION_RECORD, LOCAL_DNS_DEFAULT, LOCAL_DNS_PROVIDERS,
    MANIFEST_PATH, MASKABLE_ICON_PATH, MAX_HTTP_CONNECTIONS, PNG_ICON_PATHS,
    REQUEST_HEADER_DEADLINE_SECONDS, RFC1918_NETWORKS, SETTABLE,
    SETTINGS_PATH, SETTINGS_SECRET_KEYS, SETTINGS_SECRET_MASK, STATE_DIR,
    SW_PATH, SYSTEM_INSTALL, TLS_HANDSHAKE_TIMEOUT_SECONDS,
    UPDATE_CHECK_MAX_BYTES, UPDATE_CHECK_TIMEOUT_SECONDS,
    VERIFY_COOLDOWN_SECONDS, VERSION, WHITE_LOGO_PATH, WHITE_MARK_PATH,
    _PinnedHTTPSConnection, _SEMVER_RE, _SupportPseudonyms,
    _allowed_local_dns_address, _atomic_write_private_json, _bool_setting,
    _build_version, _ca_cert_path, _close_open_outage_segment,
    _coerce_config_types, _cpu_totals, _derive_outage_segments,
    _discord_webhook_url, _dns_domain, _dns_servers,
    _ensure_private_state_file, _export_settings, _globally_routable,
    _incident_outage_segments, _kuma_url, _network_targets, _optional_ip_list,
    _outage_seconds, _quiet_time, _record_incident_observation,
    _run_incremental_vacuum, _safe_request_host, _str_list, _strict_version,
    _valid_hostname, _version_tuple, apply_settings, auto_vacuum,
    backfill_incident_outage_segments, backfill_incident_refs,
    build_tls_context, db, db_maintenance_info, ensure_auto_vacuum,
    host_stats, init_db, installation_provenance, load_config,
    make_incident_ref, manual_update_check, normalize_local_dns_config,
    observer_health_warnings, public_settings, run_cmd, sample_host_cpu,
    start_host_cpu_sampler, tls_paths, vacuum_database,
)
from linkmoth_probes import (
    HISTORY_RANGE_HOURS, ISP_ATTRIBUTABLE_CODES, LOCAL_DNS_ADAPTERS,
    MAX_HISTORY_POINTS, QUALITY_DAYPARTS, REPORT_WINDOWS,
    _CONTAINER_IFACE_PREFIXES, _LOAD_TEST_LOCK, _LOCAL_DNS_DETECT_CACHE,
    _LOCAL_DNS_DETECT_LOCK, _STORY_SOURCES, _TUNNEL_IFACE_PREFIXES,
    _active_local_dns_adapters, _classify_iface, _count_phrase, _dns_query_a,
    _ethtool_link, _https_probe_label, _human_duration, _load_downloader,
    _local_dns_failure_hint, _local_ipv4_addresses, _median, _micro_step,
    _ms_text, _read_link_speed_duplex, _read_power_supplies,
    _read_power_supply_file, _resolve_load_target, _validate_load_url, any_ok,
    bind_exposure_risk, check_disk_pressure, check_link, check_power,
    check_router_wlan, classify_network_interfaces, classify_quality,
    confidence_assessment, confidence_from_checks, default_route, dig,
    http_get, incident_story, isp_report_csv, isp_report_letter,
    latest_load_test, local_dns_is_same_host, local_dns_runtime_info,
    measure_quality, micro_local_dns, micro_pihole_dns,
    normalize_stored_check, normalize_stored_checks, normalize_stored_verdict,
    parse_ping_stats, ping, probe_group, quality_config, quality_findings,
    quality_summary, record_quality_sample, run_ladder, run_load_test,
    verdict, wifi_wired_differential,
)
from linkmoth_engine import (
    AUTH, DEVICES, ENGINE, Engine, _get_meta, _month_bounds, _set_meta,
    get_auth, janitor_loop, janitor_sweep, maybe_send_monthly_digest,
    monthly_digest_lines, prometheus_metrics,
)
from linkmoth_handler import (
    AUTH_VERIFY_SLOTS, HEADER_POLL_SECONDS, Handler, MAX_HTTP_HEADER_BYTES,
    MAX_HTTP_HEADER_COUNT, MAX_REQUEST_BODY,
    PUBLIC_EXPOSURE_NOTIFY_COOLDOWN_SECONDS, READONLY_TOKEN_GET_PATHS,
    REQUEST_TIMEOUT_SECONDS, _BoundedHeaderReader, _HeaderLimitExceeded,
    _HeaderReadError, _HeaderReadTimeout, _LAST_PUBLIC_EXPOSURE_NOTIFY_MONO,
    _PUBLIC_EXPOSURE_NOTIFY_LOCK, _peer_is_trusted_local,
    _public_exposure_notify_allowed, create_server, doctor, parse_kuma,
)
from linkmoth_backup import build_backup_archive, restore_backup_archive


def auth_set_password():
    import getpass
    init_db()
    auth = get_auth()
    idx = sys.argv.index("--auth-set-password")
    if idx + 1 < len(sys.argv) and not sys.argv[idx + 1].startswith("--"):
        print(
            "do not put passwords on the command line; run "
            "--auth-set-password and enter it at the hidden prompt",
            file=sys.stderr,
        )
        return 2
    pw = getpass.getpass("New admin password: ")
    confirm = getpass.getpass("Confirm: ")
    if pw != confirm:
        print("passwords do not match", file=sys.stderr)
        return 1
    try:
        auth.set_password(pw)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 1
    secret = auth.ensure_webhook_secret()
    # Intentional one-time CLI reveal to the operator running this flag by
    # hand -- not a persisted log.
    # codeql[py/clear-text-logging-sensitive-data]
    print(f"admin password set; webhook secret: {secret}")
    return 0


def auth_setup_totp():
    init_db()
    auth = get_auth()
    if not auth.has_password():
        print("set admin password first (--auth-set-password)", file=sys.stderr)
        return 1
    secret, codes = auth.setup_totp()
    uri = auth.totp_provisioning_uri()
    # Intentional one-time CLI reveal to the operator running this flag by
    # hand -- not a persisted log.
    # codeql[py/clear-text-logging-sensitive-data]
    print("TOTP secret (base32):", secret)
    # codeql[py/clear-text-logging-sensitive-data]
    print("Provisioning URI:", uri)
    print("Recovery codes (store safely, shown once):")
    for c in codes:
        print(" ", c)
    return 0


def auth_show_webhook():
    init_db()
    auth = get_auth()
    # Intentional one-time CLI reveal to the operator running this flag by
    # hand -- not a persisted log; this flag's entire purpose is to print it.
    # codeql[py/clear-text-logging-sensitive-data]
    print(auth.ensure_webhook_secret())
    return 0


def auth_onboarding_token():
    init_db()
    token = get_auth().ensure_onboarding_token()
    if token:
        print(token)
    return 0


def auth_rotate_webhook():
    init_db()
    auth = get_auth()
    # Intentional one-time CLI reveal to the operator running this flag by
    # hand -- not a persisted log; this flag's entire purpose is to print it.
    # codeql[py/clear-text-logging-sensitive-data]
    print(auth.rotate_webhook_secret())
    print("webhook secret rotated; update every /trigger client now", file=sys.stderr)
    return 0


def auth_show_audit():
    init_db()
    auth = get_auth()
    idx = sys.argv.index("--auth-audit")
    try:
        limit = int(sys.argv[idx + 1]) if idx + 1 < len(sys.argv) else 50
    except ValueError:
        print("--auth-audit limit must be an integer", file=sys.stderr)
        return 2
    for event in auth.audit_events(limit):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event["ts"]))
        detail = f" — {event['detail']}" if event["detail"] else ""
        print(f"{stamp}  {event['ip']:<39}  {event['event']}{detail}")
    return 0


def backup_create():
    init_db()
    idx = sys.argv.index("--backup")
    path = None
    if idx + 1 < len(sys.argv) and not sys.argv[idx + 1].startswith("--"):
        path = sys.argv[idx + 1]
    if not path:
        path = f"linkmoth-backup-{time.strftime('%Y%m%d-%H%M%S')}.zip"
    archive = build_backup_archive(db, _export_settings, VERSION)
    Path(path).write_bytes(archive)
    print(f"backup written to {path} ({len(archive)} bytes)")
    return 0


def backup_restore():
    idx = sys.argv.index("--restore")
    if idx + 1 >= len(sys.argv) or sys.argv[idx + 1].startswith("--"):
        print("--restore requires a path to a backup archive", file=sys.stderr)
        return 2
    path = sys.argv[idx + 1]
    if "--force" not in sys.argv:
        rc, _ = run_cmd(["systemctl", "is-active", "linkmoth"])
        if rc == 0:
            print(
                "linkmoth service is active; stop it first "
                "(systemctl stop linkmoth) or pass --force",
                file=sys.stderr,
            )
            return 1
    try:
        summary = restore_backup_archive(path, DB_PATH, init_db, apply_settings)
    except (ValueError, OSError) as e:
        print(f"restore failed: {e}", file=sys.stderr)
        return 1
    created = time.strftime(
        "%Y-%m-%d %H:%M:%S", time.localtime(summary["manifest"]["created_at"])
    )
    print(f"restored from a backup created {created}")
    if summary["preserved_previous_db"]:
        print(f"previous database preserved at {summary['preserved_previous_db']}")
    if not summary["settings_applied"]:
        print(
            f"some settings could not be restored: {summary['settings_errors']}",
            file=sys.stderr,
        )
    print(
        "\nFinish setup on this device:\n"
        "  1. python3 linkmoth.py --auth-onboarding-token   # then --auth-set-password\n"
        "  2. Re-enroll TOTP if you used it before: --auth-setup-totp\n"
        "  3. Note the freshly generated webhook secret: --auth-show-webhook\n"
        "     and update any Kuma/Prometheus/webhook configs pointing at the old one"
    )
    return 0


def main():
    if "--doctor" in sys.argv:
        sys.exit(doctor(json_output="--json" in sys.argv))
    if "--auth-set-password" in sys.argv:
        sys.exit(auth_set_password())
    if "--auth-setup-totp" in sys.argv:
        sys.exit(auth_setup_totp())
    if "--auth-show-webhook" in sys.argv:
        sys.exit(auth_show_webhook())
    if "--auth-onboarding-token" in sys.argv:
        sys.exit(auth_onboarding_token())
    if "--auth-rotate-webhook" in sys.argv:
        sys.exit(auth_rotate_webhook())
    if "--auth-audit" in sys.argv:
        sys.exit(auth_show_audit())
    if "--backup" in sys.argv:
        sys.exit(backup_create())
    if "--restore" in sys.argv:
        sys.exit(backup_restore())
    if CONFIG_ERROR is not None:
        print(
            f"refusing to start with invalid configuration: {CONFIG_ERROR}",
            file=sys.stderr,
        )
        sys.exit(1)
    init_db()
    auth = get_auth()
    try:
        auth.validate_configuration()
    except RuntimeError as e:
        print(f"auth configuration error: {e}", file=sys.stderr)
        sys.exit(1)
    auth.purge_expired_sessions()
    if auth.onboarding_required():
        print(
            "onboarding required: run linkmoth.py --auth-onboarding-token "
            "as the linkmoth service user",
            flush=True,
        )
    if "--once" in sys.argv:
        checks, ms = run_ladder()
        v = verdict(checks)
        print(json.dumps({"verdict": v, "checks": checks, "ms": round(ms)}, indent=2))
        return
    def baseline_loop():
        time.sleep(15)
        last_incident_probe = 0.0
        while True:
            sample_m = int(CFG.get("history_sample_minutes", 5) or 0)
            baseline_m = int(CFG.get("baseline_minutes", 0) or 0)
            if sample_m <= 0 and baseline_m <= 0:
                time.sleep(300)
                continue
            if sample_m <= 0:
                sample_m = baseline_m
            if (not ENGINE.run_in_progress and ENGINE.open_incident() is None):
                v = ENGINE.diagnose_once(kind="baseline")
                now = time.time()
                if (baseline_m > 0 and v and v["severity"] == "bad"
                        and now - last_incident_probe >= baseline_m * 60):
                    ENGINE.trigger("baseline", f"self-detected: {v['code']}")
                    last_incident_probe = now
                record_quality_sample()
                # Scheduled bufferbloat runs are opt-in (load_test_hours > 0)
                # and never start while an incident is open or another test
                # is already running.
                try:
                    load_hours = int(quality_config().get("load_test_hours", 0) or 0)
                except (TypeError, ValueError):
                    load_hours = 0
                if load_hours > 0 and _LOAD_TEST_LOCK.acquire(blocking=False):
                    try:
                        last_test = latest_load_test()
                        if (not last_test
                                or now - float(last_test["ts"]) >= load_hours * 3600):
                            run_load_test()
                    except Exception as e:
                        print(f"scheduled load test: {e}",
                              file=sys.stderr, flush=True)
                    finally:
                        _LOAD_TEST_LOCK.release()
            time.sleep(max(60, sample_m * 60))
    from linkmoth_notify import quiet_hours_scheduler_loop
    from linkmoth_webhooks import drain_loop, migrate_legacy_webhook
    migrate_legacy_webhook(CFG, db, SETTINGS_PATH)
    start_host_cpu_sampler()
    threading.Thread(target=baseline_loop, daemon=True).start()
    threading.Thread(target=janitor_loop, daemon=True).start()
    threading.Thread(target=DEVICES.scheduler_loop, daemon=True).start()
    threading.Thread(target=drain_loop, args=(db,), daemon=True).start()
    threading.Thread(
        target=quiet_hours_scheduler_loop,
        args=(CFG, STATE_DIR, db),
        daemon=True,
        name="linkmoth-quiet-hours",
    ).start()
    ENGINE.resume_after_startup()
    try:
        server = create_server()
    except RuntimeError as e:
        print(f"TLS configuration error: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"linkmoth listening with TLS on {CFG['bind']}:{CFG['port']}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

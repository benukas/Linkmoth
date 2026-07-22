"""Linkmoth engine: the Engine class (the stateful diagnosis/incident
orchestrator) and the singletons/background jobs that operate on it -- the
monthly digest, Prometheus metrics, and the nightly janitor sweep.

Owns the ENGINE/DEVICES/AUTH runtime singletons (rather than linkmoth.py's
bootstrap) so linkmoth_handler.py can import them directly without a
circular import back into linkmoth.py.
"""
import json
import sqlite3
import sys
import threading
import time

from linkmoth_core import (
    CFG, CHANGELOG_URL, GITHUB_REPO, STATE_DIR, VERIFY_COOLDOWN_SECONDS,
    VERSION, _SupportPseudonyms, _close_open_outage_segment,
    _export_settings, _incident_outage_segments, _kuma_url,
    _outage_seconds, _record_incident_observation, auto_vacuum, db,
    db_maintenance_info, host_stats, installation_provenance,
    make_incident_ref, observer_health_warnings, public_settings,
)
from linkmoth_devices import DeviceManager
from linkmoth_probes import (
    HISTORY_RANGE_HOURS, ISP_ATTRIBUTABLE_CODES, MAX_HISTORY_POINTS,
    REPORT_WINDOWS, _count_phrase, _human_duration, _median,
    confidence_assessment, incident_story, isp_report_letter,
    local_dns_runtime_info, normalize_stored_checks, normalize_stored_verdict,
    ping, run_ladder, verdict,
)

class Engine:
    def __init__(self):
        self.state_dir = STATE_DIR
        self.lock = threading.Lock()
        self.loop_thread = None
        self.run_in_progress = False
        self._ladder_cache = None
        self._ladder_cache_lock = threading.Lock()
        self._ladder_cache_cond = threading.Condition(self._ladder_cache_lock)
        self._ladder_inflight = False
        self._last_verify_mono = 0.0

    def resume_after_startup(self):
        """Continue recheck loop for an open incident left by a prior process."""
        inc = self.open_incident()
        if not inc:
            return
        with self.lock:
            alive = self.loop_thread is not None and self.loop_thread.is_alive()
            if alive:
                return
            self.loop_thread = threading.Thread(
                target=self._loop, args=(inc["id"],), daemon=True,
            )
            self.loop_thread.start()
        label = inc.get("ref") or f"#{inc['id']}"
        print(f"resumed open incident {label}", flush=True)

    def _ladder_cache_ttl(self):
        return max(1, int(CFG.get("ladder_cache_seconds", 10)))

    def _store_ladder_cache(self, checks, duration_ms, v):
        with self._ladder_cache_cond:
            self._ladder_cache = {
                "mono_ts": time.monotonic(),
                "checks": checks,
                "duration_ms": duration_ms,
                "verdict": dict(v),
            }

    def run_ladder_cached(self, force=False):
        """Run fault ladder with optional TTL cache and singleflight coalescing."""
        ttl = self._ladder_cache_ttl()
        if not force:
            with self._ladder_cache_cond:
                hit = self._ladder_cache
                if hit and (time.monotonic() - hit["mono_ts"]) <= ttl:
                    return hit["checks"], hit["duration_ms"], dict(hit["verdict"]), True
                while self._ladder_inflight:
                    self._ladder_cache_cond.wait(timeout=max(0.1, ttl))
                    hit = self._ladder_cache
                    if hit and (time.monotonic() - hit["mono_ts"]) <= ttl:
                        return hit["checks"], hit["duration_ms"], dict(hit["verdict"]), True
                self._ladder_inflight = True
        try:
            with self.lock:
                if self.run_in_progress:
                    if not force:
                        with self._ladder_cache_cond:
                            hit = self._ladder_cache
                            if hit:
                                return hit["checks"], hit["duration_ms"], dict(hit["verdict"]), True
                    return None
                self.run_in_progress = True
            try:
                checks, duration_ms = run_ladder()
                v = verdict(checks)
                self._store_ladder_cache(checks, duration_ms, v)
                return checks, duration_ms, v, False
            finally:
                self.run_in_progress = False
        finally:
            if not force:
                with self._ladder_cache_cond:
                    self._ladder_inflight = False
                    self._ladder_cache_cond.notify_all()

    def open_incident(self):
        with db() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE resolved IS NULL ORDER BY id DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None

    def evaluate_network_for_proxy(self, max_age=300):
        """Recent ladder verdict or a fresh run for Uptime Kuma alert proxy decisions."""
        from linkmoth_outage import OUTAGE_TRACKER
        if OUTAGE_TRACKER.is_active(db):
            max_age = min(max_age, 30)
        with db() as conn:
            row = conn.execute(
                "SELECT ts, severity, code, title, explain, hint, checks FROM runs"
                " ORDER BY id DESC LIMIT 1"
            ).fetchone()

        def _verdict_from_row(r):
            return normalize_stored_verdict({
                "severity": r["severity"],
                "code": r["code"],
                "title": r["title"],
                "explain": r["explain"],
                "hint": r["hint"],
            })

        now = time.time()
        if row and (now - row["ts"]) <= max_age:
            try:
                checks = normalize_stored_checks(json.loads(row["checks"]))
            except (json.JSONDecodeError, TypeError):
                checks = []
            return _verdict_from_row(row), checks, True

        out = self.run_ladder_cached(force=False)
        if out is None:
            if row:
                try:
                    checks = normalize_stored_checks(json.loads(row["checks"]))
                except (json.JSONDecodeError, TypeError):
                    checks = []
                return _verdict_from_row(row), checks, True
            return {
                "severity": "ok",
                "code": "all_clear",
                "title": "No recent data",
                "explain": "",
                "hint": "",
            }, [], False

        checks, duration_ms, v, cached = out
        if not cached:
            with db() as conn:
                conn.execute(
                    "INSERT INTO runs(incident_id, ts, severity, code, title, explain, hint, checks, duration_ms, kind)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (None, time.time(), v["severity"], v["code"], v["title"],
                     v["explain"], v["hint"], json.dumps(checks), duration_ms, "kuma-proxy"),
                )
            self._observe_network(v, checks, "kuma-proxy")
        return v, checks, cached

    def has_active_global_outage(self):
        from linkmoth_kuma_proxy import is_effective_global_outage
        from linkmoth_outage import OUTAGE_TRACKER
        if OUTAGE_TRACKER.is_active(db):
            return True
        inc = self.open_incident()
        if not inc:
            return False
        with db() as conn:
            row = conn.execute(
                "SELECT code, checks FROM runs WHERE incident_id=? ORDER BY id DESC LIMIT 1",
                (inc["id"],),
            ).fetchone()
        if not row:
            return False
        try:
            checks = normalize_stored_checks(json.loads(row["checks"]))
        except (json.JSONDecodeError, TypeError):
            checks = []
        return is_effective_global_outage(
            normalize_stored_verdict({"code": row["code"]}), checks
        )

    def _notify_outage_recovery(
        self,
        prior_fault,
        recovery_verdict,
        checks,
        digest,
        cfg,
        duration_s,
        fault_checks=None,
    ):
        from linkmoth_notify import notify_recovery
        notify_recovery(
            cfg, STATE_DIR, db,
            prior_fault=prior_fault,
            recovery_verdict=recovery_verdict,
            checks=checks,
            digest=digest,
            duration_s=duration_s,
            incident=None,
            source="outage-tracker",
            fault_checks=fault_checks,
        )
        # WAN is back – deliver webhook events that queued during the outage.
        from linkmoth_webhooks import wake_drain
        wake_drain()

    def open_incident_meta(self):
        inc = self.open_incident()
        if not inc:
            return None
        with db() as conn:
            runs = [
                normalize_stored_verdict(dict(r)) for r in conn.execute(
                    "SELECT ts, severity, code, title FROM runs"
                    " WHERE incident_id=? ORDER BY id",
                    (inc["id"],),
                )
            ]
        last = runs[-1] if runs else None
        return {
            "id": inc["id"],
            "ref": inc.get("ref"),
            "started": inc["started"],
            "source": inc.get("source"),
            "detail": inc.get("detail"),
            "run_count": len(runs),
            "diagnosing": (
                self.run_in_progress
                or (self.loop_thread is not None and self.loop_thread.is_alive())
            ),
            "last_run": last,
        }

    def recheck_open_incident(self):
        inc = self.open_incident()
        if not inc:
            return None, "no open incident"
        return self.diagnose_once(inc["id"], kind="incident"), None

    def verify_cooldown_remaining(self):
        """Seconds until the next verify is allowed; 0.0 means allowed.
        Read-only – the cooldown is stamped by verify_fix() only when a
        diagnosis actually starts, so a verify rejected because another
        diagnosis is already running does not burn the caller's window."""
        with self.lock:
            elapsed = time.monotonic() - self._last_verify_mono
            if elapsed < VERIFY_COOLDOWN_SECONDS:
                return VERIFY_COOLDOWN_SECONDS - elapsed
            return 0.0

    def verify_fix(self):
        """Fresh, uncached diagnosis for guided troubleshooting. Attaches to
        the currently-open incident if any, else runs standalone. Returns
        (verdict, checks) or None if a diagnosis is already running."""
        inc = self.open_incident()
        result = self.diagnose_once(
            incident_id=inc["id"] if inc else None, kind="verify",
            force=True, return_checks=True,
        )
        if result is not None:
            with self.lock:
                self._last_verify_mono = time.monotonic()
        return result

    def last_run_checks(self):
        with db() as conn:
            row = conn.execute(
                "SELECT checks FROM runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if not row:
            return []
        try:
            return normalize_stored_checks(json.loads(row["checks"]))
        except (json.JSONDecodeError, TypeError):
            return []

    def close_open_incident(self):
        inc = self.open_incident()
        if not inc:
            return False, "no open incident"
        inc_id = inc["id"]
        recovery_verdict = {
            "severity": "ok",
            "code": "all_clear",
            "title": "Manually closed – all clear",
            "explain": "Closed from the dashboard.",
            "hint": "",
        }
        closed_at = time.time()
        with db() as conn:
            _close_open_outage_segment(conn, inc_id, closed_at)
            cur = conn.execute(
                "UPDATE incidents SET resolved=? WHERE id=? AND resolved IS NULL",
                (closed_at, inc_id),
            )
        if cur.rowcount:
            self._emit_webhook(inc_id, "fault_closed", recovery_verdict)
        return True, dict(inc)

    def mark_false_alarm(self, ref=None):
        """Flag an incident as a false alarm; closes it if still open."""
        false_alarm_verdict = {
            "severity": "ok",
            "code": "all_clear",
            "title": "Marked as false alarm",
            "explain": "Marked as a false alarm from the dashboard.",
            "hint": "",
        }
        if ref:
            with db() as conn:
                row = conn.execute(
                    "SELECT * FROM incidents WHERE ref=?", (ref,)
                ).fetchone()
            if not row:
                return False, "no incident with that reference"
            inc = dict(row)
        else:
            inc = self.open_incident()
            if not inc:
                return False, "no open incident"
        inc_id = inc["id"]
        closed_at = time.time()
        with db() as conn:
            # Rewrite the verdict unconditionally – an already-closed incident
            # marked as a false alarm must stop counting as a blamed fault in
            # stats, patterns, and filters. The historical diagnosis is
            # preserved separately in diagnosis_code/diagnosis_title.
            conn.execute(
                "UPDATE incidents SET false_alarm=1, verdict_code=?,"
                " verdict_title=? WHERE id=?",
                (false_alarm_verdict["code"], false_alarm_verdict["title"],
                 inc_id),
            )
            _close_open_outage_segment(conn, inc_id, closed_at)
            cur = conn.execute(
                "UPDATE incidents SET resolved=? WHERE id=? AND resolved IS NULL",
                (closed_at, inc_id),
            )
        self._emit_webhook(inc_id, "false_alarm_marked", false_alarm_verdict)
        if cur.rowcount:
            self._emit_webhook(inc_id, "fault_closed", false_alarm_verdict)
        return True, dict(inc)

    def _observe_network(self, verdict, checks, kind):
        from linkmoth_outage import OUTAGE_TRACKER
        OUTAGE_TRACKER.observe(
            verdict, checks, CFG, db, self._notify_outage_recovery,
        )

    def diagnose_once(self, incident_id=None, kind=None, force=None,
                      return_checks=False):
        kind = kind or ("incident" if incident_id else "manual")
        if force is None:
            force = kind in ("incident", "manual")
        out = self.run_ladder_cached(force=force)
        if out is None:
            return None
        checks, duration_ms, v, _cached = out
        observed_at = time.time()
        with db() as conn:
            conn.execute(
                "INSERT INTO runs(incident_id, ts, severity, code, title, explain, hint, checks, duration_ms, kind)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (incident_id, observed_at, v["severity"], v["code"], v["title"],
                 v["explain"], v["hint"], json.dumps(checks), duration_ms, kind),
            )
            _record_incident_observation(
                conn, incident_id, observed_at, v["severity"]
            )
        self._observe_network(v, checks, kind)
        if kind in ("manual", "verify"):
            self._emit_webhook(incident_id, "diagnosis_run", v, checks=checks)
        if return_checks:
            return v, checks
        return v

    def _incident_by_id(self, inc_id):
        with db() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id=?", (inc_id,)).fetchone()
            return normalize_stored_verdict(dict(row)) if row else None

    def _latest_run_checks(self, inc_id):
        with db() as conn:
            row = conn.execute(
                "SELECT checks FROM runs WHERE incident_id=? ORDER BY id DESC LIMIT 1",
                (inc_id,),
            ).fetchone()
        if not row:
            return []
        try:
            return normalize_stored_checks(json.loads(row["checks"]))
        except (json.JSONDecodeError, TypeError):
            return []

    def _first_bad_run_checks(self, inc_id):
        """The fault ladder from this incident's first non-ok run – what was
        actually broken, as opposed to _latest_run_checks() which by the time
        of a recovery notification is always the healthy closing run."""
        with db() as conn:
            row = conn.execute(
                "SELECT checks FROM runs WHERE incident_id=? AND severity != 'ok'"
                " ORDER BY id ASC LIMIT 1",
                (inc_id,),
            ).fetchone()
        if not row:
            return []
        try:
            return normalize_stored_checks(json.loads(row["checks"]))
        except (json.JSONDecodeError, TypeError):
            return []

    def _emit_webhook(self, inc_id, event, verdict, checks=None, duration_s=None):
        """Queue an outbound webhook event; never raises, never suppressed
        during outages (deliveries wait in the queue for WAN recovery)."""
        try:
            from linkmoth_webhooks import build_event_context, emit_event
            inc = self._incident_by_id(inc_id) if inc_id else None
            if checks is None:
                checks = self._latest_run_checks(inc_id) if inc_id else []
            if duration_s is None and inc and event in (
                "fault_recovered", "fault_closed", "false_alarm_marked",
            ):
                with db() as conn:
                    duration_s = _outage_seconds(
                        _incident_outage_segments(conn, inc), now=time.time()
                    )
            ctx = build_event_context(
                event, verdict=verdict, incident=inc, checks=checks,
                duration_s=duration_s,
            )
            emit_event(db, event, ctx)
        except Exception as e:
            print(f"webhook emit error: {e}", file=sys.stderr, flush=True)

    def _discord_notify(self, inc_id, status_type, verdict, prior_fault=None):
        try:
            from linkmoth_kuma_proxy import flush_suppression_digest, is_effective_global_outage
            from linkmoth_notify import notify_fault, notify_recovery
            from linkmoth_outage import is_global_fault_code
            inc = self._incident_by_id(inc_id)
            if not inc:
                return
            checks = self._latest_run_checks(inc_id)
            if status_type == "fault":
                if is_effective_global_outage(verdict, checks):
                    return
                notify_fault(CFG, STATE_DIR, db, inc, verdict, checks)
                return
            if status_type == "recovery":
                if is_global_fault_code((prior_fault or {}).get("code")):
                    return
                digest = flush_suppression_digest(db, recovery_ts=time.time())
                with db() as conn:
                    downtime_s = _outage_seconds(
                        _incident_outage_segments(conn, inc), now=time.time()
                    )
                notify_recovery(
                    CFG, STATE_DIR, db,
                    prior_fault=prior_fault or {},
                    recovery_verdict=verdict,
                    checks=checks,
                    digest=digest,
                    duration_s=downtime_s,
                    incident=inc,
                    source="incident-loop",
                    fault_checks=self._first_bad_run_checks(inc_id),
                )
        except Exception as e:
            print(f"notify error: {e}", file=sys.stderr, flush=True)

    def trigger(self, source, detail=""):
        # The whole check-then-create runs under self.lock: two concurrent
        # triggers (webhook + baseline loop) must not both see "no open
        # incident" and create one each – the second would never get a
        # recheck loop and stay open forever. The INSERT is additionally
        # guarded in SQL so even a writer outside this process can't race a
        # second open incident into existence.
        with self.lock:
            inc = self.open_incident()
            if inc is None:
                started = time.time()
                with db() as conn:
                    cur = conn.execute(
                        "INSERT INTO incidents(started, source, detail)"
                        " SELECT ?,?,? WHERE NOT EXISTS"
                        " (SELECT 1 FROM incidents WHERE resolved IS NULL)",
                        (started, source, detail),
                    )
                    if cur.rowcount:
                        inc_id = cur.lastrowid
                        ref = make_incident_ref(inc_id, started)
                        conn.execute(
                            "UPDATE incidents SET ref=? WHERE id=?", (ref, inc_id)
                        )
                if not cur.rowcount:
                    # Lost the (out-of-process) race: someone else opened an
                    # incident between our check and insert. Attach to it. If
                    # it already resolved again, fall back to a plain insert –
                    # there is no open incident left to duplicate.
                    inc = self.open_incident()
                    if inc is None:
                        with db() as conn:
                            cur = conn.execute(
                                "INSERT INTO incidents(started, source, detail)"
                                " VALUES(?,?,?)",
                                (started, source, detail),
                            )
                            inc_id = cur.lastrowid
                            ref = make_incident_ref(inc_id, started)
                            conn.execute(
                                "UPDATE incidents SET ref=? WHERE id=?",
                                (ref, inc_id),
                            )
            if inc is not None:
                inc_id = inc["id"]
                with db() as conn:
                    conn.execute(
                        "UPDATE incidents SET detail = detail || ' | ' || ? WHERE id=?",
                        (f"{source}: {detail}"[:300], inc_id),
                    )
            alive = self.loop_thread is not None and self.loop_thread.is_alive()
            if not alive:
                self.loop_thread = threading.Thread(
                    target=self._loop, args=(inc_id,), daemon=True
                )
                self.loop_thread.start()
        return inc_id

    def _loop(self, inc_id):
        initial = self._incident_by_id(inc_id)
        consecutive_ok = 1 if initial and initial.get("recovered_at") else 0
        worst = None
        fault_notified = False
        last_emitted = None
        deadline = time.time() + CFG["incident_max_hours"] * 3600
        schedule = list(CFG["recheck_seconds"])
        step = 0
        t0 = time.time()
        while time.time() < deadline:
            target = t0 + schedule[step] if step < len(schedule) else None
            if target:
                time.sleep(max(0.0, target - time.time()))
                step += 1
            else:
                time.sleep(CFG["recheck_repeat"])
            # Guard the whole recheck body: a transient failure (a DB lock that
            # exhausts its retry budget, a probe raising unexpectedly) must not
            # kill this thread, or the incident would never be rechecked and
            # would hang open forever. Sleeps stay outside the guard so a
            # persistent error still paces instead of spin-looping; the outer
            # `deadline` still bounds the incident overall.
            try:
                inc = self._incident_by_id(inc_id)
                if not inc or inc.get("resolved"):
                    return  # closed externally (manual close / false alarm)
                v = self.diagnose_once(inc_id, kind="incident")
                if v is None:
                    continue
                if v["severity"] == "ok":
                    consecutive_ok += 1
                    if consecutive_ok >= 2:
                        recovery_verdict = {
                            "severity": "ok",
                            "code": "all_clear",
                            "title": "All network checks passed",
                            "explain": v.get("explain", ""),
                            "hint": "",
                        }
                        self._discord_notify(
                            inc_id, "recovery", recovery_verdict,
                            prior_fault=worst if fault_notified else None,
                        )
                        self._emit_webhook(
                            inc_id,
                            "fault_recovered",
                            recovery_verdict,
                            checks=self._first_bad_run_checks(inc_id),
                        )
                        break
                else:
                    consecutive_ok = 0
                    # Preserve the incident's strongest confirmed attribution.
                    # A later warning often means partial recovery; it must not
                    # overwrite an earlier bad WAN/router fault in the final
                    # incident record or recovery handoff.
                    rank = {"ok": 0, "warn": 1, "bad": 2}
                    if (
                        worst is None
                        or rank.get(v.get("severity"), 0)
                        >= rank.get(worst.get("severity"), 0)
                    ):
                        worst = v
                        with db() as conn:
                            conn.execute(
                                "UPDATE incidents SET diagnosis_code=?, diagnosis_title=?, verdict_code=?, verdict_title=? "
                                "WHERE id=? AND resolved IS NULL",
                                (v["code"], v["title"], v["code"], v["title"], inc_id),
                            )
                    if not fault_notified:
                        fault_notified = True
                        self._discord_notify(inc_id, "fault", v)
                        event = (
                            "degradation_detected" if v["severity"] == "warn"
                            else "fault_opened"
                        )
                        self._emit_webhook(inc_id, event, v)
                        last_emitted = (v["code"], v["severity"])
                    elif (v["code"], v["severity"]) != last_emitted:
                        self._emit_webhook(inc_id, "fault_updated", v)
                        last_emitted = (v["code"], v["severity"])
            except Exception as e:
                print(f"incident recheck loop (incident {inc_id}): {e}",
                      file=sys.stderr, flush=True)
        recovery_confirmed = consecutive_ok >= 2
        final = worst or {"severity": "ok", "code": "all_clear",
                          "title": "Nothing wrong seen from the network side"}
        closed_at = time.time()
        with db() as conn:
            _close_open_outage_segment(conn, inc_id, closed_at)
            cur = conn.execute(
                "UPDATE incidents SET resolved=?,"
                " recovered_at=CASE WHEN ? THEN COALESCE(recovered_at, ?)"
                " ELSE recovered_at END, verdict_code=?, verdict_title=?,"
                " diagnosis_code=?, diagnosis_title=?"
                " WHERE id=? AND resolved IS NULL",
                (closed_at, recovery_confirmed, closed_at,
                 final["code"], final["title"],
                 final["code"], final["title"], inc_id),
            )
        if cur.rowcount:
            self._emit_webhook(inc_id, "fault_closed", final)

    def status(self):
        from linkmoth_outage import OUTAGE_TRACKER
        from linkmoth_push import list_subscriptions, push_available
        from linkmoth_notify import quiet_hours_status
        # Everything that does not touch the database happens first, so the
        # connection below is never held open across it. local_dns_runtime_
        # info() in particular shells out to `systemctl is-active` whenever
        # its 30s detection cache expires.
        host = host_stats()
        local_dns = local_dns_runtime_info()
        settings = public_settings()
        provenance = installation_provenance()
        try:
            kuma_url = _kuma_url(CFG.get("kuma_url", "auto"))
        except ValueError:
            kuma_url = ""
        # One connection for the whole payload. db() is re-entrant, so every
        # helper below (stats, history, meta, push, quiet hours, ...) reuses
        # this one instead of opening its own -- this endpoint is polled
        # every few seconds by every open dashboard, and the connect/close
        # round trips dominated it. It also means the whole payload is read
        # from a single consistent snapshot.
        with db() as conn:
            last = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
            incidents = conn.execute(
                "SELECT i.*, (SELECT COUNT(*) FROM runs r WHERE r.incident_id=i.id) AS run_count"
                " FROM incidents i ORDER BY i.id DESC LIMIT 20"
            ).fetchall()
            runs_of_open = []
            open_inc = self.open_incident()
            if open_inc:
                runs_of_open = [
                    normalize_stored_verdict(dict(r)) for r in conn.execute(
                        "SELECT ts, severity, code, title FROM runs WHERE incident_id=? ORDER BY id",
                        (open_inc["id"],),
                    )
                ]
            last_d = None
            patterns = None
            if last:
                last_d = normalize_stored_verdict(dict(last))
                last_d["checks"] = normalize_stored_checks(json.loads(last_d["checks"]))
                if last_d.get("severity") != "ok" and last_d.get("code"):
                    patterns = self.patterns(code=last_d["code"])
            database = db_maintenance_info()
            return {
                "now": time.time(),
                "diagnosing": self.run_in_progress or (
                    self.loop_thread is not None and self.loop_thread.is_alive()
                ),
                "open_incident": (
                    normalize_stored_verdict(open_inc) if open_inc else None
                ),
                "open_incident_meta": self.open_incident_meta(),
                "open_incident_runs": runs_of_open,
                "last_run": last_d,
                "patterns": patterns,
                "incidents": [
                    normalize_stored_verdict(dict(i)) for i in incidents
                ],
                "stats": self.stats(),
                "history": self.history(),
                "history_meta": self.history_meta(),
                "fire_drill": fire_drill_status(),
                "kuma_url": kuma_url,
                "settings": settings,
                "local_dns": local_dns,
                "database": database,
                "host": host,
                "observer_health": {
                    "warnings": observer_health_warnings(last_d.get("ts") if last_d else None, host, database),
                },
                "outage_active": OUTAGE_TRACKER.summary(db),
                "push": {
                    "available": push_available(STATE_DIR),
                    "enabled": bool(CFG.get("push_notifications_enabled", True)),
                    "subscribers": len(list_subscriptions(db)),
                },
                "quiet_hours": quiet_hours_status(CFG, db),
                "app": {
                    "version": VERSION,
                    "github": GITHUB_REPO,
                    "changelog": CHANGELOG_URL,
                    "provenance": provenance,
                },
            }

    def stats(self):
        now = time.time()
        cutoff = now - 30 * 86400
        with db() as conn:
            first_run = conn.execute("SELECT MIN(ts) AS t FROM runs").fetchone()["t"]
            # Any incident overlapping the window counts – including ones
            # that started before it and are still open (or resolved inside
            # it). A week-long outage that began before the window must
            # still show up as downtime inside it.
            inc = [dict(r) for r in conn.execute(
                "SELECT * FROM incidents WHERE started > ?"
                " OR resolved IS NULL OR resolved > ?",
                (cutoff, cutoff))]
            segments_by_incident = {
                item["id"]: _incident_outage_segments(conn, item)
                for item in inc
            }
        monitoring_started = max(float(first_run), cutoff) if first_run else None
        period = max(0.0, now - monitoring_started) if monitoring_started else 0.0
        downtime = 0.0
        blame = {}
        false_alarms = 0
        for i in inc:
            code = normalize_stored_verdict(i).get("verdict_code")
            # The false_alarm flag wins over any stored verdict code:
            # incidents marked false alarm before the code rewrite existed
            # still carry their original code.
            if i.get("false_alarm") or code == "all_clear":
                false_alarms += 1
                continue
            # Clamp each incident's contribution to the 30-day window so an
            # incident spanning the cutoff neither vanishes nor contributes
            # more downtime than the window holds.
            downtime += _outage_seconds(
                segments_by_incident[i["id"]],
                window_start=cutoff, window_end=now, now=now,
            )
            if i["resolved"] is not None and code:
                blame[code] = blame.get(code, 0) + 1
        return {
            "incidents_30d": len(inc) - false_alarms,
            "false_alarms_30d": false_alarms,
            "downtime_s": round(downtime),
            "monitoring_interval_s": round(period),
            "uptime_pct": (
                round(max(0.0, 100.0 * (1 - downtime / period)), 2)
                if period > 0 else None
            ),
            "blame": blame,
        }

    def isp_report(self, days=30):
        """Accountability report over the stored incident history: what
        failed, for how long, whose layer it was, plus a plain-language
        evidence letter for an ISP support ticket. Read-only."""
        from linkmoth_webhooks import AFFECTED_LAYERS
        days = days if days in REPORT_WINDOWS else 30
        now = time.time()
        cutoff = now - days * 86400
        with db() as conn:
            first_run = conn.execute("SELECT MIN(ts) AS t FROM runs").fetchone()["t"]
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM incidents WHERE started > ? OR resolved IS NULL"
                " OR resolved > ? ORDER BY started ASC",
                (cutoff, cutoff))]
            segments_by_incident = {
                row["id"]: _incident_outage_segments(conn, row)
                for row in rows
            }
        monitoring_started = max(float(first_run), cutoff) if first_run else None
        observed_s = max(0.0, now - monitoring_started) if monitoring_started else 0.0
        incidents = []
        blame = {}
        total_downtime = 0.0
        longest = None
        false_alarms = 0
        for row in rows:
            inc = normalize_stored_verdict(row)
            code = inc.get("diagnosis_code") or inc.get("verdict_code") or ""
            if inc.get("false_alarm") or code == "all_clear":
                false_alarms += 1
                continue
            started = float(inc["started"])
            resolved = float(inc["resolved"]) if inc.get("resolved") else None
            segments = segments_by_incident[inc["id"]]
            downtime = _outage_seconds(segments, now=now)
            window_downtime = _outage_seconds(
                segments, window_start=cutoff, window_end=now, now=now,
            )
            incident_duration = max(0.0, (resolved or now) - started)
            entry = {
                "ref": inc.get("ref"),
                "started": started,
                "recovered_at": inc.get("recovered_at"),
                "resolved": resolved,
                # duration_s historically meant incident span. Keep the field
                # for clients, but correct its semantics to observed downtime.
                "duration_s": round(downtime),
                "downtime_s": round(downtime),
                "incident_duration_s": round(incident_duration),
                "window_downtime_s": round(window_downtime),
                "outage_segments": [
                    {
                        "started": segment["started"],
                        "ended": segment.get("ended"),
                    }
                    for segment in segments
                ],
                "open": resolved is None,
                "code": code or None,
                "title": inc.get("diagnosis_title") or inc.get("verdict_title"),
                "layer": AFFECTED_LAYERS.get(code, "none") if code else "none",
                "isp_attributable": code in ISP_ATTRIBUTABLE_CODES,
            }
            incidents.append(entry)
            if code:
                bucket = blame.setdefault(code, {"count": 0, "downtime_s": 0})
                bucket["count"] += 1
                bucket["downtime_s"] += round(window_downtime)
            total_downtime += window_downtime
            if (
                longest is None
                or entry["window_downtime_s"] > longest["window_downtime_s"]
            ):
                longest = entry
        wan = [item for item in incidents if item["isp_attributable"]]
        peak = None
        if len(wan) >= 3:
            wan_hours = [0] * 24
            for item in wan:
                wan_hours[time.localtime(item["started"]).tm_hour] += 1
            best_start, best_count = 0, -1
            for hour in range(24):
                count = sum(wan_hours[(hour + k) % 24] for k in range(3))
                if count > best_count:
                    best_start, best_count = hour, count
            # Only call it a cluster when the peak window holds at least
            # half of the outages – 3 incidents spread across a day are
            # not a pattern.
            if best_count >= max(3, (len(wan) + 1) // 2):
                peak = {
                    "start_hour": best_start,
                    "end_hour": (best_start + 3) % 24,
                    "count": best_count,
                }
        report = {
            "days": days,
            "generated_at": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(now)
            ),
            "monitoring_since": monitoring_started,
            "observed_s": round(observed_s),
            "incident_count": len(incidents),
            "false_alarms": false_alarms,
            "downtime_s": round(total_downtime),
            "uptime_pct": (
                round(max(0.0, 100.0 * (1 - total_downtime / observed_s)), 2)
                if observed_s > 0 else None
            ),
            "blame": blame,
            "longest": longest,
            "isp": {
                "count": len(wan),
                "downtime_s": sum(item["window_downtime_s"] for item in wan),
                "peak_hours": peak,
            },
            "incidents": incidents,
        }
        report["letter"] = isp_report_letter(report)
        return report

    @staticmethod
    def _pattern_for(incs):
        """Correlation summary for one verdict code, with an honest
        minimum-sample rule so 1–2 incidents never read as a 'pattern'."""
        count = len(incs)
        durations = sorted(
            i["outage_duration_s"] for i in incs
            if i.get("outage_duration_s") is not None
        )
        median = None
        if durations:
            n = len(durations)
            median = (durations[n // 2] if n % 2
                      else (durations[n // 2 - 1] + durations[n // 2]) / 2.0)
        latest = max(incs, key=lambda i: i["started"])
        oldest = min(incs, key=lambda i: i["started"])
        starts = sorted(i["started"] for i in incs)
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        median_gap = None
        if gaps:
            middle = len(gaps) // 2
            median_gap = gaps[middle] if len(gaps) % 2 else (gaps[middle - 1] + gaps[middle]) / 2.0
        result = {
            "count": count,
            "tier": None,
            "median_duration_s": round(median) if median is not None else None,
            "last_ref": latest.get("ref"),
            "last_started": latest["started"],
            "first_started": oldest["started"],
            "median_gap_s": round(median_gap) if median_gap is not None else None,
            "clusters_hour_range": None,
        }
        if count < 2:
            return result
        if count == 2:
            result["tier"] = "recurrence"
            return result
        # count >= 3: only claim a time-of-day pattern if >=3 land in one window.
        result["tier"] = "pattern"
        hours = [0] * 24
        for i in incs:
            hours[time.localtime(i["started"]).tm_hour] += 1
        best_start, best_sum = 0, -1
        for start in range(24):
            s = sum(hours[(start + k) % 24] for k in range(4))
            if s > best_sum:
                best_sum, best_start = s, start
        if best_sum >= 3:
            end = (best_start + 4) % 24
            result["clusters_hour_range"] = f"{best_start:02d}:00–{end:02d}:00"
        return result

    def patterns(self, code=None, days=90):
        now = time.time()
        cutoff = now - days * 86400
        with db() as conn:
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM incidents"
                " WHERE started > ? AND verdict_code IS NOT NULL"
                " AND COALESCE(false_alarm, 0) = 0",
                (cutoff,))]
            for row in rows:
                row["outage_duration_s"] = (
                    _outage_seconds(_incident_outage_segments(conn, row), now=now)
                    if row.get("resolved") is not None else None
                )
        by_code = {}
        for r in rows:
            c = normalize_stored_verdict(r).get("verdict_code")
            if not c or c == "all_clear":
                continue
            by_code.setdefault(c, []).append(r)
        if code == "pihole_broken":
            code = "local_dns_broken"
        if code is not None:
            incs = by_code.get(code)
            return self._pattern_for(incs) if incs else None
        return {c: self._pattern_for(incs) for c, incs in by_code.items()}

    def incidents_list(self, limit=50, code=None):
        q = ("SELECT i.*, (SELECT COUNT(*) FROM runs r WHERE r.incident_id=i.id) AS run_count"
             " FROM incidents i")
        args = []
        if code == "open":
            q += " WHERE i.resolved IS NULL"
        elif code == "all_clear":
            # Include incidents flagged false-alarm before the verdict
            # rewrite existed; they may still carry their original code.
            q += " WHERE (i.verdict_code = ? OR COALESCE(i.false_alarm, 0) = 1)"
            args.append(code)
        elif code:
            if code == "local_dns_broken":
                q += " WHERE i.verdict_code IN (?, ?)"
                args.extend(("local_dns_broken", "pihole_broken"))
            else:
                q += " WHERE i.verdict_code = ?"
                args.append(code)
            q += " AND COALESCE(i.false_alarm, 0) = 0"
        q += " ORDER BY i.id DESC LIMIT ?"
        args.append(max(1, min(200, limit)))
        with db() as conn:
            incidents = []
            timing_now = time.time()
            for row in conn.execute(q, args):
                incident = normalize_stored_verdict(dict(row))
                segments = _incident_outage_segments(conn, incident)
                incident["observed_downtime_s"] = round(
                    _outage_seconds(segments, now=timing_now)
                )
                incident["incident_duration_s"] = round(max(
                    0.0,
                    float(incident.get("resolved") or timing_now)
                    - float(incident["started"]),
                ))
                incident["outage_segment_count"] = len(segments)
                incidents.append(incident)
            return incidents

    def incident_detail(self, inc_id=None, ref=None):
        with db() as conn:
            if ref:
                row = conn.execute(
                    "SELECT * FROM incidents WHERE ref=?", (ref.strip(),),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM incidents WHERE id=?", (inc_id,),
                ).fetchone()
            if not row:
                return None
            inc = normalize_stored_verdict(dict(row))
            inc_id = inc["id"]
            segments = _incident_outage_segments(conn, inc)
            timing_now = time.time()
            inc["observed_downtime_s"] = round(
                _outage_seconds(segments, now=timing_now)
            )
            inc["incident_duration_s"] = round(max(
                0.0,
                float(inc.get("resolved") or timing_now) - float(inc["started"]),
            ))
            runs = list(reversed([dict(r) for r in conn.execute(
                "SELECT * FROM runs WHERE incident_id=? ORDER BY id DESC LIMIT 100", (inc_id,))]))
            base = conn.execute(
                "SELECT * FROM runs WHERE ts < ? AND severity='ok' ORDER BY id DESC LIMIT 1",
                (inc["started"],),
            ).fetchone()
        for r in runs:
            translated = normalize_stored_verdict(r)
            r.update(translated)
            r["checks"] = normalize_stored_checks(json.loads(r["checks"]))
            assessment = confidence_assessment(r["checks"])
            r["confidence"] = assessment["level"]
            r["confidence_reason"] = assessment["reason"]
        baseline = None
        if base:
            baseline = dict(base)
            baseline = normalize_stored_verdict(baseline)
            baseline["checks"] = normalize_stored_checks(
                json.loads(baseline["checks"])
            )
        first_bad = next((r for r in runs if r["severity"] != "ok"), None)
        ref = first_bad or (runs[-1] if runs else None)
        sim_code = inc.get("verdict_code") or (first_bad["code"] if first_bad else None)
        similar = []
        if sim_code:
            with db() as conn:
                similar_codes = (
                    ("local_dns_broken", "pihole_broken")
                    if sim_code == "local_dns_broken" else (sim_code,)
                )
                placeholders = ",".join("?" for _ in similar_codes)
                for r in conn.execute(
                    "SELECT * FROM incidents"
                    f" WHERE verdict_code IN ({placeholders}) AND id != ?"
                    " AND COALESCE(false_alarm, 0) = 0"
                    " ORDER BY id DESC LIMIT 3",
                    (*similar_codes, inc_id)):
                    d = dict(r)
                    dur = _outage_seconds(
                        _incident_outage_segments(conn, d), now=timing_now,
                    )
                    similar.append({
                        "ref": d["ref"], "started": d["started"],
                        "duration_s": round(dur),
                    })
        first_failure = None
        diff = []
        if first_bad:
            for ch in first_bad["checks"]:
                if ch["ok"] is False or ch.get("state") == "degraded":
                    first_failure = {"id": ch["id"], "label": ch["label"],
                                     "detail": ch["detail"]}
                    break
            if baseline:
                before = {b["id"]: b for b in baseline["checks"]}
                for ch in first_bad["checks"]:
                    b = before.get(ch["id"])
                    if not b:
                        continue
                    flipped = (b["ok"] is not False) and (ch["ok"] is False)
                    evidence_changed = b.get("state") != ch.get("state")
                    ms_jump = (
                        b.get("ms") is not None and ch.get("ms") is not None
                        and abs(ch["ms"] - b["ms"]) >= max(20.0, b["ms"] * 0.5)
                    )
                    if flipped or evidence_changed or ms_jump:
                        diff.append({"id": ch["id"], "label": ch["label"],
                                     "before": b["detail"], "after": ch["detail"],
                                     "flipped": flipped,
                                     "evidence_changed": evidence_changed})
        if not baseline:
            comparison_summary = "No earlier healthy run is stored, so Linkmoth cannot make a before/after comparison yet."
        elif not diff:
            comparison_summary = "No ladder evidence changed from the last healthy run; this weakens the case for a network-wide fault."
        else:
            flipped_labels = [item["label"] for item in diff if item["flipped"]]
            if flipped_labels:
                comparison_summary = "New failures appeared in " + ", ".join(flipped_labels) + "."
            else:
                comparison_summary = "The path still worked, but its evidence changed (timing or target agreement)."
        result = {
            "incident": inc,
            "outage_segments": segments,
            "downtime_s": inc["observed_downtime_s"],
            "incident_duration_s": inc["incident_duration_s"],
            "runs": runs,
            "baseline_before": (
                {"ts": baseline["ts"], "checks": baseline["checks"]} if baseline else None
            ),
            "first_failure": first_failure,
            "first_failure_note": (
                "First failed rung in dependency order; downstream checks depend on it."
                if first_failure else None
            ),
            "stayed_healthy": (
                [ch["label"] for ch in ref["checks"] if ch["ok"] is True] if ref else []
            ),
            "diff": diff,
            "comparison_summary": comparison_summary,
            "confidence": (first_bad or ref or {}).get("confidence"),
            "confidence_reason": (first_bad or ref or {}).get("confidence_reason"),
            "pattern": self.patterns(sim_code) if sim_code else None,
            "similar": similar,
        }
        result["story"] = incident_story(result)
        return result

    def evidence_export(self, tier="detailed"):
        """Build a bounded, credential-free local evidence package."""
        if tier not in ("detailed", "readable", "support-safe"):
            raise ValueError("unknown export tier")
        with db() as conn:
            rows = conn.execute(
                "SELECT id FROM incidents ORDER BY id DESC LIMIT 50"
            ).fetchall()
            last = conn.execute("SELECT ts FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        incidents = [self.incident_detail(inc_id=row["id"]) for row in reversed(rows)]
        host = host_stats()
        database = db_maintenance_info()
        package = {
            "schema": 1,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tier": tier,
            "scope": "Observed from this Linkmoth host; evidence can narrow possible causes but cannot distinguish every cause.",
            "configuration": _export_settings(),
            "observer_health": {
                "warnings": observer_health_warnings(last["ts"] if last else None, host, database),
                "host": host,
                "database": database,
            },
            "incidents": incidents,
        }
        if tier == "support-safe":
            package = _SupportPseudonyms().scrub(package)
            package["scope"] = "Support-safe export. Identifiers are pseudonymized consistently within this export."
        if tier == "readable":
            lines = ["Linkmoth local evidence export", package["scope"], ""]
            for detail in incidents:
                incident = detail["incident"]
                lines.append(
                    f"{incident.get('ref') or incident['id']} | {incident.get('lifecycle')} | "
                    f"{incident.get('diagnosis_title') or incident.get('verdict_title') or 'No confirmed diagnosis'}"
                )
                lines.append("  " + detail["comparison_summary"])
                if detail.get("confidence_reason"):
                    lines.append("  Confidence limit: " + detail["confidence_reason"])
            if package["observer_health"]["warnings"]:
                lines.extend(["", "Observer-health warnings:"] + [
                    "- " + warning for warning in package["observer_health"]["warnings"]
                ])
            return "\n".join(lines) + "\n"
        return package

    def history(self, limit=144):
        with db() as conn:
            rows = conn.execute(
                "SELECT ts, severity, kind, checks FROM runs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out = []
        for r in reversed(rows):
            ms = {}
            for ch in normalize_stored_checks(json.loads(r["checks"])):
                if ch.get("ms") is not None:
                    ms[ch["id"]] = ch["ms"]
            out.append({"ts": r["ts"], "severity": r["severity"],
                        "kind": r["kind"], "ms": ms})
        return out

    def history_range(self, hours=24):
        """Latency history for the expanded modal view, over a caller-chosen
        window instead of the fixed-count sparkline. Raw per-rung timings are
        returned when the window is small; a long window (weeks/months) is
        averaged into MAX_HISTORY_POINTS fixed-width time buckets first, so
        the response and the chart stay cheap regardless of range.
        """
        hours = hours if hours in HISTORY_RANGE_HOURS else 24
        now = time.time()
        cutoff = now - hours * 3600
        with db() as conn:
            rows = conn.execute(
                "SELECT ts, severity, kind, checks FROM runs WHERE ts > ?"
                " ORDER BY id ASC",
                (cutoff,),
            ).fetchall()
        samples = []
        for r in rows:
            ms = {}
            for ch in normalize_stored_checks(json.loads(r["checks"])):
                if ch.get("ms") is not None:
                    ms[ch["id"]] = ch["ms"]
            samples.append({"ts": r["ts"], "severity": r["severity"],
                            "kind": r["kind"], "ms": ms})
        if len(samples) <= MAX_HISTORY_POINTS:
            return {"hours": hours, "bucketed": False, "bucket_seconds": None,
                    "samples": samples}
        severity_rank = {"ok": 0, "warn": 1, "degraded": 1, "bad": 2}
        span = max(1.0, (now - cutoff) / MAX_HISTORY_POINTS)
        buckets = [[] for _ in range(MAX_HISTORY_POINTS)]
        for s in samples:
            idx = min(MAX_HISTORY_POINTS - 1, int((s["ts"] - cutoff) / span))
            buckets[idx].append(s)
        bucketed = []
        for i, bucket in enumerate(buckets):
            if not bucket:
                continue
            keys = set()
            for s in bucket:
                keys.update(s["ms"].keys())
            ms = {}
            for key in keys:
                values = [s["ms"][key] for s in bucket if key in s["ms"]]
                if values:
                    ms[key] = sum(values) / len(values)
            worst = max(bucket, key=lambda s: severity_rank.get(s["severity"], 0))
            bucketed.append({
                "ts": cutoff + (i + 0.5) * span,
                "severity": worst["severity"],
                "kind": "bucket",
                "ms": ms,
                "sample_count": len(bucket),
            })
        return {"hours": hours, "bucketed": True, "bucket_seconds": round(span),
                "samples": bucketed}

    def history_meta(self):
        history = self.history(limit=1)
        sample = int(CFG.get("history_sample_minutes", 5) or 0)
        baseline = int(CFG.get("baseline_minutes", 0) or 0)
        if sample <= 0 and baseline > 0:
            sample = baseline
        return {
            "last_ts": history[-1]["ts"] if history else None,
            "sample_minutes": sample,
            "baseline_minutes": baseline,
            "refresh_seconds": int(CFG.get("ui_refresh_seconds", 5) or 5),
        }



ENGINE = Engine()

from linkmoth_devices import DeviceManager

DEVICES = DeviceManager(db, ping, CFG, STATE_DIR)

AUTH = None



def get_auth():
    global AUTH
    if AUTH is None:
        from linkmoth_auth import AuthManager
        AUTH = AuthManager(STATE_DIR, CFG, db)
    return AUTH



def _get_meta(key):
    with db() as conn:
        row = conn.execute(
            "SELECT value FROM app_meta WHERE key=?", (key,)
        ).fetchone()
    return row["value"] if row else None


def _set_meta(key, value):
    with db() as conn:
        conn.execute(
            "INSERT INTO app_meta(key, value) VALUES(?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def fire_drill_status():
    completed = _get_meta("fire_drill_completed") == "1"
    seen = completed or _get_meta("fire_drill_seen") == "1"
    if not seen and _get_meta("fire_drill_migration_checked") != "1":
        with db() as conn:
            prior_manual_run = conn.execute(
                "SELECT 1 FROM runs WHERE kind IN ('manual', 'verify') LIMIT 1"
            ).fetchone()
        _set_meta("fire_drill_migration_checked", "1")
        if prior_manual_run:
            _set_meta("fire_drill_seen", "1")
            seen = True
    return {
        "seen": seen,
        "completed": completed,
    }


def _month_bounds(year, month):
    start = time.mktime((year, month, 1, 0, 0, 0, 0, 0, -1))
    next_year, next_month = (year + 1, 1) if month == 12 else (year, month + 1)
    end = time.mktime((next_year, next_month, 1, 0, 0, 0, 0, 0, -1))
    return start, end


def _monitoring_started():
    """Timestamp of the first-ever diagnosis run, or None if there isn't
    one yet. Same signal Engine.stats()/isp_report() use to avoid crediting
    uptime for time before Linkmoth was even installed."""
    with db() as conn:
        first_run = conn.execute("SELECT MIN(ts) AS t FROM runs").fetchone()["t"]
    return float(first_run) if first_run else None


def monthly_digest_lines(year, month):
    """Plain-language summary lines for one calendar month (local time)."""
    start, end = _month_bounds(year, month)
    end = min(end, time.time())
    monitoring_started = _monitoring_started()
    # If Linkmoth was installed partway through this month, the days before
    # that are not "uptime" – they were never observed – so the window used
    # for every downtime/uptime calculation below starts no earlier than
    # monitoring actually began.
    effective_start = max(start, monitoring_started) if monitoring_started else start
    prev_year, prev_month = (year - 1, 12) if month == 1 else (year, month - 1)
    prev_start, prev_end = _month_bounds(prev_year, prev_month)
    with db() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM incidents WHERE started < ?"
            " AND (resolved IS NULL OR resolved > ?)",
            (end, effective_start))]
        segments_by_incident = {
            row["id"]: _incident_outage_segments(conn, row)
            for row in rows
        }
        latencies = [r["latency_ms"] for r in conn.execute(
            "SELECT latency_ms FROM quality_samples WHERE ts >= ? AND ts < ?",
            (effective_start, end))]
        prev_latencies = [r["latency_ms"] for r in conn.execute(
            "SELECT latency_ms FROM quality_samples WHERE ts >= ? AND ts < ?",
            (prev_start, prev_end))]
    faults = 0
    false_alarms = 0
    downtime = 0.0
    blame = {}
    longest = None
    for row in rows:
        inc = normalize_stored_verdict(row)
        code = inc.get("diagnosis_code") or inc.get("verdict_code") or ""
        if inc.get("false_alarm") or code == "all_clear":
            false_alarms += 1
            continue
        faults += 1
        started = float(inc["started"])
        resolved = float(inc["resolved"]) if inc.get("resolved") else None
        clamped = _outage_seconds(
            segments_by_incident[inc["id"]],
            window_start=effective_start, window_end=end, now=end,
        )
        downtime += clamped
        if code:
            blame[code] = blame.get(code, 0) + 1
        if longest is None or clamped > longest[0]:
            longest = (clamped, inc.get("ref"))
    span = max(1.0, end - effective_start)
    uptime_pct = round(max(0.0, 100.0 * (1 - downtime / span)), 2)
    lines = [
        f"{_count_phrase(faults, 'incident')},"
        f" {_count_phrase(false_alarms, 'false alarm')}."
    ]
    if faults:
        lines.append(
            f"Downtime {_human_duration(downtime)} – {uptime_pct}% uptime."
        )
        if blame:
            top_code = max(blame, key=blame.get)
            lines.append(
                f"Most common fault: {top_code} ({blame[top_code]}×)."
            )
        if longest:
            ref = f" ({longest[1]})" if longest[1] else ""
            lines.append(
                f"Longest outage: {_human_duration(longest[0])}{ref}."
            )
    else:
        lines.append("No network faults were confirmed – a clean month.")
    med = _median(latencies)
    if med is not None:
        line = f"Median internet latency: {round(med)} ms"
        prev_med = _median(prev_latencies)
        if prev_med is not None and prev_med > 0:
            change = (med - prev_med) / prev_med * 100
            if abs(change) >= 10:
                line += (
                    f" ({'up' if change > 0 else 'down'}"
                    f" {abs(round(change))}% vs the month before)"
                )
        lines.append(line + ".")
    return lines


def maybe_send_monthly_digest(now=None):
    """Send one previous-month summary when the local month rolls over.
    Called from the daily janitor; the sent-marker in app_meta makes it
    restart-safe and at-most-once per month."""
    now = now if now is not None else time.time()
    lt = time.localtime(now)
    current_month = f"{lt.tm_year:04d}-{lt.tm_mon:02d}"
    last = _get_meta("monthly_digest_sent")
    if last == current_month:
        return False
    if last is None:
        # First ever run: arm the marker without sending – there is no
        # fully-observed previous month to summarize yet.
        _set_meta("monthly_digest_sent", current_month)
        return False
    prev_year, prev_month = (
        (lt.tm_year - 1, 12) if lt.tm_mon == 1 else (lt.tm_year, lt.tm_mon - 1)
    )
    prev_start, _ = _month_bounds(prev_year, prev_month)
    monitoring_started = _monitoring_started()
    if monitoring_started and monitoring_started > prev_start:
        # Monitoring began partway through the month that would be reported
        # (e.g. installed on the 20th) – the "first ever run" branch above
        # only catches the install month itself, not this one, since a full
        # calendar month has now rolled over. A report where most of the
        # month predates Linkmoth even running would undermine the whole
        # point of this being credible evidence; skip it and wait for the
        # first fully-observed month instead.
        _set_meta("monthly_digest_sent", current_month)
        return False
    lines = monthly_digest_lines(prev_year, prev_month)
    month_label = time.strftime(
        "%B %Y", time.localtime(_month_bounds(prev_year, prev_month)[0])
    )
    title = f"Monthly network report – {month_label}"
    from linkmoth_notify import defer_notification_if_quiet
    if defer_notification_if_quiet(
        CFG, db, title, "\n".join(lines), discord=True, push=True,
    ):
        _set_meta("monthly_digest_sent", current_month)
        return True
    from linkmoth_discord import send_monthly_digest_alert
    send_monthly_digest_alert(lines, month_label, CFG)
    if CFG.get("push_notifications_enabled", True):
        from linkmoth_push import send_push_async
        send_push_async(
            STATE_DIR, db, CFG, title, " ".join(lines[:2]),
            tag="linkmoth-monthly",
        )
    _set_meta("monthly_digest_sent", current_month)
    return True


def prometheus_metrics():
    """Read-only Prometheus text exposition of current state. Served behind
    the webhook bearer; label values are fixed enum-like strings – never
    secrets, hostnames, or LAN addresses."""
    out = []

    def gauge(name, value, help_text, labels=None):
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} gauge")
        label_str = ""
        if labels:
            inner = ",".join(f'{k}="{v}"' for k, v in labels.items())
            label_str = "{" + inner + "}"
        out.append(f"{name}{label_str} {value}")

    severity_map = {"ok": 0, "warn": 1, "degraded": 1, "bad": 2, "critical": 2}
    gauge("linkmoth_info", 1, "Linkmoth build information.",
          {"version": VERSION})
    last = None
    with db() as conn:
        row = conn.execute(
            "SELECT severity, code, ts FROM runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row:
            last = dict(row)
        qrow = conn.execute(
            "SELECT latency_ms, jitter_ms, loss_pct, state"
            " FROM quality_samples ORDER BY ts DESC LIMIT 1"
        ).fetchone()
    if last:
        code = normalize_stored_verdict(last).get("code") or "unknown"
        gauge(
            "linkmoth_last_verdict_severity",
            severity_map.get(last["severity"], -1),
            "Last diagnosis severity (0 ok, 1 degraded, 2 bad, -1 unknown).",
            {"code": code},
        )
        gauge("linkmoth_last_run_timestamp_seconds", round(last["ts"], 3),
              "Unix time of the last diagnosis run.")
    inc = ENGINE.open_incident()
    gauge("linkmoth_incident_open", 1 if inc else 0,
          "Whether a network incident is currently open.")
    if inc:
        gauge("linkmoth_incident_open_duration_seconds",
              round(time.time() - float(inc["started"])),
              "Age of the currently open incident.")
    stats = ENGINE.stats()
    gauge("linkmoth_incidents_30d", stats["incidents_30d"],
          "Incidents recorded in the last 30 days.")
    gauge("linkmoth_false_alarms_30d", stats["false_alarms_30d"],
          "False alarms recorded in the last 30 days.")
    gauge("linkmoth_downtime_seconds_30d", stats["downtime_s"],
          "Downtime recorded in the last 30 days.")
    if stats["uptime_pct"] is not None:
        gauge("linkmoth_uptime_percent_30d", stats["uptime_pct"],
              "Uptime percentage over the last 30 days.")
    checks = ENGINE.last_run_checks()
    if checks:
        out.append("# HELP linkmoth_rung_ok Rung state from the last"
                   " diagnosis (1 ok, 0 failed, -1 skipped).")
        out.append("# TYPE linkmoth_rung_ok gauge")
        for check in checks:
            value = -1 if check.get("ok") is None else (1 if check["ok"] else 0)
            out.append(f'linkmoth_rung_ok{{rung="{check["id"]}"}} {value}')
    if qrow:
        state_map = {"good": 0, "fair": 1, "poor": 2}
        if qrow["latency_ms"] is not None:
            gauge("linkmoth_quality_latency_ms", qrow["latency_ms"],
                  "Most recent internet-path latency sample.")
        if qrow["jitter_ms"] is not None:
            gauge("linkmoth_quality_jitter_ms", qrow["jitter_ms"],
                  "Most recent internet-path jitter sample.")
        if qrow["loss_pct"] is not None:
            gauge("linkmoth_quality_loss_percent", qrow["loss_pct"],
                  "Most recent internet-path packet-loss sample.")
        gauge("linkmoth_quality_state", state_map.get(qrow["state"], -1),
              "Most recent quality classification"
              " (0 good, 1 fair, 2 poor, -1 unknown).")
    host = host_stats()
    for key, metric, help_text in (
        ("cpu_percent", "linkmoth_host_cpu_percent",
         "Linkmoth host CPU usage."),
        ("temperature_c", "linkmoth_host_temperature_celsius",
         "Linkmoth host temperature."),
        ("memory_percent", "linkmoth_host_memory_percent",
         "Linkmoth host memory usage."),
        ("disk_percent", "linkmoth_host_disk_percent",
         "Linkmoth host root-disk usage."),
    ):
        if host.get(key) is not None:
            gauge(metric, host[key], help_text)
    return "\n".join(out) + "\n"


def janitor_sweep():
    cutoff = time.time() - CFG.get("retention_days", 90) * 86400
    try:
        with db() as conn:
            # Keep runs that belong to a still-open incident regardless of
            # age: they are the incident's evidence trail, and the incident
            # row itself is only pruned after it resolves.
            conn.execute(
                "DELETE FROM runs WHERE ts < ? AND (incident_id IS NULL"
                " OR incident_id NOT IN"
                " (SELECT id FROM incidents WHERE resolved IS NULL))",
                (cutoff,),
            )
            conn.execute("DELETE FROM quality_samples WHERE ts < ?", (cutoff,))
            conn.execute(
                "DELETE FROM incident_outage_segments WHERE incident_id IN"
                " (SELECT id FROM incidents"
                " WHERE resolved IS NOT NULL AND resolved < ?)",
                (cutoff,),
            )
            conn.execute(
                "DELETE FROM incidents WHERE resolved IS NOT NULL AND resolved < ?",
                (cutoff,),
            )
    except sqlite3.Error as e:
        print(f"janitor: {e}", file=sys.stderr, flush=True)
    try:
        auto_vacuum(ENGINE)
    except Exception as e:
        print(f"janitor auto_vacuum: {e}", file=sys.stderr, flush=True)
    try:
        maybe_send_monthly_digest()
    except Exception as e:
        print(f"monthly digest: {e}", file=sys.stderr, flush=True)


def janitor_loop():
    while True:
        janitor_sweep()
        time.sleep(86400)



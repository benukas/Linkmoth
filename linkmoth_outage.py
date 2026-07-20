"""Track global network outages and notify only when the path can deliver (recovery)."""
import json
import threading
import time
from typing import Callable, Optional

from linkmoth_kuma_proxy import (
    GLOBAL_OUTAGE_CODES,
    flush_suppression_digest,
    is_effective_global_outage,
    record_suppressed,
)

RECOVERY_CLEAR_RUNS = 2


class OutageTracker:
    """Detect WAN/router/host outages from Linkmoth itself; defer outbound alerts until recovery."""

    def __init__(self):
        self._lock = threading.Lock()
        self._consecutive_clear = 0

    def observe(
        self,
        verdict: Optional[dict],
        checks: list,
        cfg: dict,
        db_connect: Callable,
        notify_recovery,
    ) -> None:
        """Call after every ladder run that produced a verdict."""
        if not verdict:
            return
        with self._lock:
            active = self._load(db_connect)
            is_global = is_effective_global_outage(verdict, checks)

            if is_global:
                self._consecutive_clear = 0
                if not active:
                    self._enter(db_connect, verdict, checks)
                else:
                    self._touch(db_connect, verdict, checks)
                return

            if active:
                self._consecutive_clear += 1
                if self._consecutive_clear >= RECOVERY_CLEAR_RUNS:
                    self._recover(active, verdict, checks, cfg, db_connect, notify_recovery)
                    self._consecutive_clear = 0
            else:
                self._consecutive_clear = 0

    def is_active(self, db_connect: Callable) -> bool:
        return self._load(db_connect) is not None

    def active_code(self, db_connect: Callable) -> Optional[str]:
        row = self._load(db_connect)
        return row.get("code") if row else None

    def summary(self, db_connect: Callable):
        row = self._load(db_connect)
        if not row:
            return None
        return {
            "code": row.get("code"),
            "title": row.get("title"),
            "started": row.get("started"),
        }

    def _load(self, db_connect):
        with db_connect() as conn:
            row = conn.execute(
                "SELECT code, title, explain, started, updated, checks"
                " FROM network_outage WHERE id=1 AND active=1"
            ).fetchone()
        return dict(row) if row else None

    def _enter(self, db_connect, verdict: dict, checks: list):
        now = time.time()
        checks_json = json.dumps(checks)
        with db_connect() as conn:
            conn.execute(
                "INSERT INTO network_outage(id, active, code, title, explain,"
                " started, updated, checks)"
                " VALUES(1, 1, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(id) DO UPDATE SET"
                " active=1, code=excluded.code, title=excluded.title,"
                " explain=excluded.explain, started=excluded.started,"
                " updated=excluded.updated, checks=excluded.checks",
                (
                    verdict.get("code"),
                    verdict.get("title"),
                    verdict.get("explain"),
                    now,
                    now,
                    checks_json,
                ),
            )
        record_suppressed(
            db_connect,
            None,
            f"Linkmoth detected: {verdict.get('title') or verdict.get('code')}",
            verdict,
            {"source": "linkmoth", "verdict": verdict, "checks": checks},
            "global outage detected by Linkmoth — alerts deferred until recovery",
        )

    def _touch(self, db_connect, verdict: dict, checks: list):
        # Keep the most recently observed *broken* fault ladder, not just the
        # onset one — a long outage can shift which rung is failing, and the
        # eventual recovery notification should reflect the latest bad state.
        with db_connect() as conn:
            conn.execute(
                "UPDATE network_outage SET updated=?, code=?, title=?,"
                " explain=?, checks=? WHERE id=1",
                (
                    time.time(),
                    verdict.get("code"),
                    verdict.get("title"),
                    verdict.get("explain"),
                    json.dumps(checks),
                ),
            )

    def _recover(self, active, verdict, checks, cfg, db_connect, notify_recovery):
        recovery_ts = time.time()
        digest = flush_suppression_digest(db_connect, recovery_ts=recovery_ts)
        prior = {
            "code": active.get("code"),
            "title": active.get("title"),
            "explain": active.get("explain"),
            "started": active.get("started"),
        }
        try:
            fault_checks = json.loads(active.get("checks") or "null")
        except (json.JSONDecodeError, TypeError):
            fault_checks = None
        with db_connect() as conn:
            conn.execute(
                "UPDATE network_outage SET active=0, updated=? WHERE id=1",
                (recovery_ts,),
            )
        notify_recovery(
            prior_fault=prior,
            recovery_verdict=verdict,
            checks=checks,
            fault_checks=fault_checks,
            digest=digest,
            cfg=cfg,
            duration_s=max(0.0, recovery_ts - float(active.get("started") or recovery_ts)),
        )


def is_global_fault_code(code: Optional[str]) -> bool:
    return bool(code and code in GLOBAL_OUTAGE_CODES)


def init_outage_db(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS network_outage(
            id INTEGER PRIMARY KEY CHECK (id = 1),
            active INTEGER NOT NULL DEFAULT 0,
            code TEXT,
            title TEXT,
            explain TEXT,
            started REAL,
            updated REAL,
            checks TEXT
        );
        """
    )
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(network_outage)")}
    if "checks" not in columns:
        conn.execute("ALTER TABLE network_outage ADD COLUMN checks TEXT")


OUTAGE_TRACKER = OutageTracker()

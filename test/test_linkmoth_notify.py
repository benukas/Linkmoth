"""Tests for unified notifications and incident resume."""
import importlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
REPO_ROOT = BASE.parent
sys.path.insert(0, str(REPO_ROOT))

import linkmoth_notify


def local_stamp(hour, minute=0):
    return time.mktime((2026, 7, 14, hour, minute, 0, -1, -1, -1))


class QuietHoursTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="linkmoth_quiet_")
        self.path = Path(self.tmp) / "state.db"
        with self.db() as conn:
            linkmoth_notify.init_notification_db(conn)
            conn.execute(
                "CREATE TABLE network_outage("
                "id INTEGER PRIMARY KEY, active INTEGER NOT NULL DEFAULT 0)"
            )
            conn.execute("INSERT INTO network_outage(id, active) VALUES(1, 0)")
        self.cfg = {
            "quiet_hours_enabled": True,
            "quiet_hours_start": "22:00",
            "quiet_hours_end": "07:00",
            "push_notifications_enabled": True,
            "discord_notifications_enabled": False,
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @contextmanager
    def db(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def test_overnight_window_and_validation(self):
        self.assertTrue(linkmoth_notify.quiet_hours_active(
            self.cfg, local_stamp(23),
        ))
        self.assertTrue(linkmoth_notify.quiet_hours_active(
            self.cfg, local_stamp(6, 59),
        ))
        self.assertFalse(linkmoth_notify.quiet_hours_active(
            self.cfg, local_stamp(7),
        ))
        self.assertEqual(linkmoth_notify.validate_quiet_time("09:05"), "09:05")
        with self.assertRaises(ValueError):
            linkmoth_notify.validate_quiet_time("9:05")

    def test_deferred_push_survives_and_flushes_once(self):
        deferred = linkmoth_notify.defer_notification_if_quiet(
            self.cfg, self.db, "Printer is down", "No response",
            push=True, now=local_stamp(23),
        )
        self.assertTrue(deferred)
        status = linkmoth_notify.quiet_hours_status(
            self.cfg, self.db, local_stamp(23),
        )
        self.assertTrue(status["active"])
        self.assertEqual(status["pending"], 1)
        with mock.patch("linkmoth_push.send_push_async") as push:
            self.assertTrue(linkmoth_notify.flush_quiet_hours_digest(
                self.cfg, Path(self.tmp), self.db, local_stamp(8),
            ))
            self.assertFalse(linkmoth_notify.flush_quiet_hours_digest(
                self.cfg, Path(self.tmp), self.db, local_stamp(8),
            ))
        push.assert_called_once()
        self.assertEqual(
            linkmoth_notify.quiet_hours_status(self.cfg, self.db)["pending"],
            0,
        )

    def test_global_outage_keeps_morning_digest_queued(self):
        self.assertTrue(linkmoth_notify.defer_notification_if_quiet(
            self.cfg, self.db, "WAN down", push=True, now=local_stamp(23),
        ))
        with self.db() as conn:
            conn.execute("UPDATE network_outage SET active=1 WHERE id=1")
        with mock.patch("linkmoth_push.send_push_async") as push:
            self.assertFalse(linkmoth_notify.flush_quiet_hours_digest(
                self.cfg, Path(self.tmp), self.db, local_stamp(8),
            ))
        push.assert_not_called()
        self.assertEqual(
            linkmoth_notify.quiet_hours_status(self.cfg, self.db)["pending"],
            1,
        )

    def test_network_fault_is_queued_instead_of_sent(self):
        incident = {"id": 4, "ref": "INC-20260714-0004"}
        verdict = {
            "severity": "bad",
            "code": "wan_down",
            "title": "WAN down",
            "explain": "No internet response",
            "hint": "Check the router",
        }
        with mock.patch.object(
            linkmoth_notify, "quiet_hours_active", return_value=True,
        ), mock.patch(
            "linkmoth_discord.send_discord_alert",
        ) as discord, mock.patch(
            "linkmoth_push.send_push_async",
        ) as push:
            self.assertTrue(linkmoth_notify.notify_fault(
                self.cfg, Path(self.tmp), self.db,
                incident, verdict, [],
            ))
        discord.assert_not_called()
        push.assert_not_called()
        self.assertEqual(
            linkmoth_notify.quiet_hours_status(self.cfg, self.db)["pending"],
            1,
        )


class NotifyRecoveryDedupeTests(unittest.TestCase):
    def setUp(self):
        linkmoth_notify._recovery_sent_mono.clear()

    def test_dedupe_blocks_second_recovery(self):
        cfg = {"discord_notifications_enabled": False, "notify_webhook_enabled": False}
        prior = {"code": "wan_down", "title": "WAN down", "started": time.time() - 60}
        recovery = {"severity": "ok", "code": "all_clear", "title": "All clear",
                    "explain": "", "hint": ""}
        with mock.patch("linkmoth_discord.send_outage_recovery_alert", return_value=True):
            self.assertTrue(linkmoth_notify.notify_recovery(
                cfg, Path("/tmp"), lambda: None, prior, recovery, [], ["• svc"], 60,
            ))
            self.assertFalse(linkmoth_notify.notify_recovery(
                cfg, Path("/tmp"), lambda: None, prior, recovery, [], ["• svc"], 60,
            ))

    def test_distinct_incident_recoveries_both_notify(self):
        cfg = {"discord_notifications_enabled": False, "notify_webhook_enabled": False}
        prior = {"code": "router_down", "title": "Router down", "started": time.time() - 60}
        recovery = {"severity": "ok", "code": "all_clear", "title": "All clear",
                    "explain": "", "hint": ""}
        with mock.patch(
            "linkmoth_discord.send_discord_alert", return_value=True,
        ), mock.patch(
            "linkmoth_discord.incident_payload", return_value={},
        ):
            self.assertTrue(linkmoth_notify.notify_recovery(
                cfg, Path("/tmp"), lambda: None, prior, recovery, [], [], 60,
                incident={"id": 1}, source="incident-loop",
            ))
            self.assertTrue(linkmoth_notify.notify_recovery(
                cfg, Path("/tmp"), lambda: None, prior, recovery, [], [], 60,
                incident={"id": 2}, source="incident-loop",
            ))
            self.assertFalse(linkmoth_notify.notify_recovery(
                cfg, Path("/tmp"), lambda: None, prior, recovery, [], [], 60,
                incident={"id": 1}, source="incident-loop",
            ))

    def test_incident_recovery_does_not_block_global_recovery(self):
        cfg = {"discord_notifications_enabled": False, "notify_webhook_enabled": False}
        prior = {"code": "router_down", "title": "Router down", "started": time.time() - 60}
        recovery = {"severity": "ok", "code": "all_clear", "title": "All clear",
                    "explain": "", "hint": ""}
        with mock.patch(
            "linkmoth_discord.send_discord_alert", return_value=True,
        ), mock.patch(
            "linkmoth_discord.incident_payload", return_value={},
        ), mock.patch(
            "linkmoth_discord.send_outage_recovery_alert", return_value=True,
        ):
            self.assertTrue(linkmoth_notify.notify_recovery(
                cfg, Path("/tmp"), lambda: None, prior, recovery, [], [], 60,
                incident={"id": 1}, source="incident-loop",
            ))
            self.assertTrue(linkmoth_notify.notify_recovery(
                cfg, Path("/tmp"), lambda: None, prior, recovery, [], ["• svc"], 60,
                source="outage-tracker",
            ))

    def test_returns_false_when_nothing_sent(self):
        cfg = {"discord_notifications_enabled": False, "notify_webhook_enabled": False}
        prior = {"code": "wan_down", "title": "WAN down", "started": time.time() - 60}
        recovery = {"severity": "ok", "code": "all_clear", "title": "All clear",
                    "explain": "", "hint": ""}
        with mock.patch(
            "linkmoth_discord.send_outage_recovery_alert", return_value=False,
        ), mock.patch(
            "linkmoth_push.send_push_async", return_value=False,
        ):
            self.assertFalse(linkmoth_notify.notify_recovery(
                cfg, Path("/tmp"), lambda: None, prior, recovery, [], [], 60,
            ))
        # Nothing was sent, so nothing should be deduped away next time.
        with mock.patch("linkmoth_discord.send_outage_recovery_alert", return_value=True):
            self.assertTrue(linkmoth_notify.notify_recovery(
                cfg, Path("/tmp"), lambda: None, prior, recovery, [], ["• svc"], 60,
            ))


class ResumeIncidentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="linkmoth_resume_")
        cls.state = Path(cls.tmp) / "state"
        cls.state.mkdir()
        cls.config_path = Path(cls.tmp) / "config.json"
        cls.config_path.write_text(json.dumps({
            "bind": "127.0.0.1",
            "port": 0,
            "recheck_seconds": [9999],
            "recheck_repeat": 9999,
            "discord_notifications_enabled": False,
        }))
        os.environ["LINKMOTH_CONFIG"] = str(cls.config_path)
        os.environ["LINKMOTH_STATE_DIR"] = str(cls.state)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        os.environ.pop("LINKMOTH_CONFIG", None)
        os.environ.pop("LINKMOTH_STATE_DIR", None)

    def setUp(self):
        import linkmoth
        importlib.reload(linkmoth)
        self.linkmoth = linkmoth
        linkmoth.init_db()
        self.engine = linkmoth.Engine()

    def test_resume_starts_loop_for_open_incident(self):
        with self.linkmoth.db() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail) VALUES(?,?,?)",
                (time.time(), "test", "open"),
            )
            self.assertIsNotNone(cur.lastrowid)
        started = threading.Event()
        release = threading.Event()

        def held_loop(_inc_id):
            started.set()
            release.wait(timeout=5)

        with mock.patch.object(self.engine, "_loop", side_effect=held_loop):
            self.engine.resume_after_startup()
            self.assertTrue(started.wait(timeout=2))
            self.assertTrue(self.engine.loop_thread is not None)
            self.assertTrue(self.engine.loop_thread.is_alive())
            release.set()
            self.engine.loop_thread.join(timeout=2)
        self.assertFalse(self.engine.loop_thread.is_alive())


class CloseIncidentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="linkmoth_close_")
        cls.state = Path(cls.tmp) / "state"
        cls.state.mkdir()
        cls.config_path = Path(cls.tmp) / "config.json"
        cls.config_path.write_text(json.dumps({"bind": "127.0.0.1", "port": 0}))
        os.environ["LINKMOTH_CONFIG"] = str(cls.config_path)
        os.environ["LINKMOTH_STATE_DIR"] = str(cls.state)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        os.environ.pop("LINKMOTH_CONFIG", None)
        os.environ.pop("LINKMOTH_STATE_DIR", None)

    def setUp(self):
        import linkmoth
        importlib.reload(linkmoth)
        self.linkmoth = linkmoth
        linkmoth.init_db()
        self.engine = linkmoth.Engine()

    def test_close_open_incident(self):
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO incidents(started, source, detail) VALUES(?,?,?)",
                (time.time(), "test", "manual"),
            )
        ok, inc = self.engine.close_open_incident()
        self.assertTrue(ok)
        self.assertIsNone(self.engine.open_incident())


if __name__ == "__main__":
    unittest.main()

"""Tests for unified notifications and incident resume."""
import importlib
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
REPO_ROOT = BASE.parent
sys.path.insert(0, str(REPO_ROOT))

import linkmoth_notify


class NotifyRecoveryDedupeTests(unittest.TestCase):
    def setUp(self):
        linkmoth_notify._last_recovery_mono = 0.0

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
            inc_id = cur.lastrowid
        self.engine.resume_after_startup()
        self.assertTrue(self.engine.loop_thread is not None)
        self.assertTrue(self.engine.loop_thread.is_alive())
        self.engine.loop_thread.join(timeout=2)


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

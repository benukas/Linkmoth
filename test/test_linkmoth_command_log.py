#!/usr/bin/env python3
"""Tests for the debug command log.

Every command Linkmoth runs on the host passes through run_cmd, so the log is
recorded there. It exists to make a silent Raspberry Pi debuggable, which means
it must stay off unless asked for, must never change what callers receive, and
must never be able to break the probe it is observing.
"""
import importlib
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent))

OK = [sys.executable, "-c", "print('probe ok')"]
FAILS = [sys.executable, "-c",
         "import sys; sys.stderr.write('why it failed'); sys.exit(2)"]


class CommandLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="linkmoth_cmdlog_"))
        os.environ["LINKMOTH_STATE_DIR"] = str(self.tmp)
        os.environ.pop("LINKMOTH_CONFIG", None)
        for mod in ("linkmoth_core", "linkmoth_probes"):
            if mod in sys.modules:
                del sys.modules[mod]
        self.core = importlib.import_module("linkmoth_core")
        self.core.init_db()

    def _enable(self):
        self.core.CFG["debug_command_log"] = True

    def test_it_is_off_by_default_and_records_nothing(self):
        """A debugging aid nobody asked for is just a hidden buffer of host
        command output, so it stays off until it is switched on."""
        self.assertFalse(self.core.CFG.get("debug_command_log"))
        self.core.run_cmd(OK)
        log = self.core.command_log()
        self.assertFalse(log["enabled"])
        self.assertEqual(log["entries"], [])

    def test_enabling_records_command_exit_code_and_output(self):
        self._enable()
        self.core.run_cmd(OK)
        entries = self.core.command_log()["entries"]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertIn("probe ok", entry["output"])
        self.assertEqual(entry["rc"], 0)
        self.assertIn("-c", entry["command"])
        self.assertGreaterEqual(entry["duration_ms"], 0)
        self.assertFalse(entry["truncated"])

    def test_a_failure_records_stderr_without_changing_what_callers_get(self):
        """Callers only ever receive stdout and that contract is unchanged,
        but stderr is usually the only thing that explains a failure, so the
        log keeps it."""
        self._enable()
        rc, out = self.core.run_cmd(FAILS)
        self.assertEqual(rc, 2)
        self.assertNotIn("why it failed", out)
        logged = self.core.command_log()["entries"][-1]
        self.assertEqual(logged["rc"], 2)
        self.assertIn("why it failed", logged["output"])

    def test_missing_tool_is_recorded_rather_than_lost(self):
        self._enable()
        rc, _ = self.core.run_cmd(["linkmoth-no-such-binary"])
        self.assertEqual(rc, -2)
        self.assertEqual(self.core.command_log()["entries"][-1]["rc"], -2)

    def test_since_returns_only_newer_entries(self):
        """The dashboard polls every couple of seconds; replaying the whole
        buffer each time would be wasteful, so it asks for what it lacks."""
        self._enable()
        self.core.run_cmd(OK)
        first = self.core.command_log()
        self.core.run_cmd(OK)
        later = self.core.command_log(first["seq"])
        self.assertEqual(len(later["entries"]), 1)
        self.assertGreater(later["entries"][0]["seq"], first["seq"])
        self.assertEqual(self.core.command_log(later["seq"])["entries"], [])

    def test_a_bad_since_value_does_not_raise(self):
        self._enable()
        self.core.run_cmd(OK)
        for bad in (None, "abc", "", [1]):
            self.assertEqual(len(self.core.command_log(bad)["entries"]), 1)

    def test_the_buffer_is_bounded(self):
        """It runs forever on a small always-on box, so it cannot grow
        without limit."""
        self._enable()
        with mock.patch.object(self.core, "COMMAND_LOG_MAX", 5):
            self.core._COMMAND_LOG = self.core.deque(maxlen=5)
            for _ in range(9):
                self.core.run_cmd(OK)
            entries = self.core.command_log()["entries"]
        self.assertEqual(len(entries), 5)
        # The survivors are the newest, and the sequence keeps counting.
        self.assertEqual([e["seq"] for e in entries], sorted(e["seq"] for e in entries))
        self.assertEqual(entries[-1]["seq"], 9)

    def test_long_output_is_truncated_and_flagged(self):
        self._enable()
        self.core.run_cmd([sys.executable, "-c", "print('x' * 10000)"])
        entry = self.core.command_log()["entries"][-1]
        self.assertTrue(entry["truncated"])
        self.assertLessEqual(len(entry["output"]), self.core.COMMAND_LOG_OUTPUT_MAX)

    def test_clearing_empties_the_buffer(self):
        self._enable()
        self.core.run_cmd(OK)
        self.core.clear_command_log()
        self.assertEqual(self.core.command_log()["entries"], [])

    def test_recording_never_breaks_the_command_being_observed(self):
        """The log is a debugging aid. If it ever fails it must not take the
        probe down with it, or enabling it would break the very thing being
        investigated."""
        self._enable()
        with mock.patch.object(self.core, "_COMMAND_LOG_LOCK") as lock:
            lock.__enter__ = mock.Mock(side_effect=RuntimeError("log exploded"))
            rc, out = self.core.run_cmd(OK)
        self.assertEqual(rc, 0)
        self.assertIn("probe ok", out)

    def test_it_is_settable_and_survives_a_round_trip(self):
        ok, result = self.core.apply_settings({"debug_command_log": True})
        self.assertTrue(ok, result)
        self.assertTrue(self.core.CFG["debug_command_log"])
        self.assertTrue(self.core.public_settings()["debug_command_log"])
        ok, _ = self.core.apply_settings({"debug_command_log": False})
        self.assertTrue(ok)
        self.assertFalse(self.core.CFG["debug_command_log"])

    def test_a_scoped_readonly_token_cannot_reach_the_command_log(self):
        """Read-only tokens exist for dashboard widgets and Home Assistant
        sensors. Host command output is a full-session admin view, so the
        route must stay outside the token's allowed set."""
        handler = importlib.import_module("linkmoth_handler")
        self.assertNotIn("/api/debug/commands", handler.READONLY_TOKEN_GET_PATHS)
        self.assertNotIn(
            "/api/debug/commands/clear", handler.READONLY_TOKEN_GET_PATHS)

    def test_concurrent_commands_do_not_lose_or_duplicate_entries(self):
        """run_cmd is called from several probe threads at once."""
        self._enable()
        threads = [threading.Thread(target=self.core.run_cmd, args=(OK,))
                   for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        entries = self.core.command_log()["entries"]
        self.assertEqual(len(entries), 12)
        self.assertEqual(len({e["seq"] for e in entries}), 12)


if __name__ == "__main__":
    unittest.main()

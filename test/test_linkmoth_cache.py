#!/usr/bin/env python3
"""Tests for fault ladder cache and incident reference IDs."""
import importlib
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))


class LadderCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = Path(tempfile.mkdtemp(prefix="linkmoth_cache_"))
        os.environ["LINKMOTH_STATE_DIR"] = str(cls.state)
        for _mod in ("linkmoth", 'linkmoth_core', 'linkmoth_probes', 'linkmoth_engine', 'linkmoth_handler'):
            if _mod in sys.modules:
                del sys.modules[_mod]
        cls.linkmoth = importlib.import_module("linkmoth")
        global linkmoth_engine
        linkmoth_engine = importlib.import_module("linkmoth_engine")
        cls.linkmoth.init_db()

    def test_second_call_uses_cache(self):
        engine = self.linkmoth.Engine()
        calls = []

        def fake_ladder():
            calls.append(1)
            return [{"id": "link", "ok": True, "detail": "ok"}], 1.0

        with mock.patch.object(linkmoth_engine, "run_ladder", side_effect=fake_ladder):
            with mock.patch.object(linkmoth_engine, "verdict", return_value={
                "severity": "ok", "code": "all_clear", "title": "ok", "explain": "", "hint": "",
            }):
                engine.run_ladder_cached(force=False)
                engine.run_ladder_cached(force=False)
        self.assertEqual(len(calls), 1)

    def test_force_bypasses_cache(self):
        engine = self.linkmoth.Engine()
        calls = []

        def fake_ladder():
            calls.append(1)
            return [], 1.0

        with mock.patch.object(linkmoth_engine, "run_ladder", side_effect=fake_ladder):
            with mock.patch.object(linkmoth_engine, "verdict", return_value={
                "severity": "ok", "code": "all_clear", "title": "ok", "explain": "", "hint": "",
            }):
                engine.run_ladder_cached(force=False)
                engine.run_ladder_cached(force=True)
        self.assertEqual(len(calls), 2)

    def test_concurrent_calls_coalesce(self):
        engine = self.linkmoth.Engine()
        calls = []
        started = threading.Barrier(3)

        def fake_ladder():
            calls.append(1)
            time.sleep(0.05)
            return [], 2.0

        def worker():
            started.wait()
            engine.run_ladder_cached(force=False)

        with mock.patch.object(linkmoth_engine, "run_ladder", side_effect=fake_ladder):
            with mock.patch.object(linkmoth_engine, "verdict", return_value={
                "severity": "ok", "code": "all_clear", "title": "ok", "explain": "", "hint": "",
            }):
                threads = [threading.Thread(target=worker) for _ in range(3)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=5)
        self.assertEqual(len(calls), 1)


class IncidentRefTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = Path(tempfile.mkdtemp(prefix="linkmoth_ref_"))
        os.environ["LINKMOTH_STATE_DIR"] = str(cls.state)
        for _mod in ("linkmoth", 'linkmoth_core', 'linkmoth_probes', 'linkmoth_engine', 'linkmoth_handler'):
            if _mod in sys.modules:
                del sys.modules[_mod]
        cls.linkmoth = importlib.import_module("linkmoth")
        global linkmoth_engine
        linkmoth_engine = importlib.import_module("linkmoth_engine")
        cls.linkmoth.init_db()

    def test_make_incident_ref_format(self):
        started = time.mktime(time.strptime("2026-07-05 12:00:00", "%Y-%m-%d %H:%M:%S"))
        ref = self.linkmoth.make_incident_ref(42, started)
        self.assertEqual(ref, "INC-20260705-0042")

    def test_trigger_assigns_ref(self):
        engine = self.linkmoth.Engine()
        inc_id = engine.trigger("test", "unit test")
        inc = engine._incident_by_id(inc_id)
        self.assertTrue(inc["ref"].startswith("INC-"))
        self.assertTrue(inc["ref"].endswith(f"-{inc_id:04d}"))

    def test_incident_detail_by_ref(self):
        engine = self.linkmoth.Engine()
        inc_id = engine.trigger("test", "lookup")
        inc = engine._incident_by_id(inc_id)
        detail = engine.incident_detail(ref=inc["ref"])
        self.assertIsNotNone(detail)
        self.assertEqual(detail["incident"]["id"], inc_id)
        self.assertEqual(detail["incident"]["ref"], inc["ref"])


if __name__ == "__main__":
    unittest.main()

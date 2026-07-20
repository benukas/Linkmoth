#!/usr/bin/env python3
"""Tests for guided-troubleshooting verify and outage-correlation patterns."""
import importlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))


def make_checks(**overrides):
    base = {
        "power": True, "link": True, "gateway": True, "router_wlan": None,
        "pihole_dns": True, "upstream_dns": True, "raw_ping": True, "https": True,
    }
    base.update(overrides)
    return [
        {"id": cid, "label": cid, "ok": ok, "detail": "d", "ms": None, "micro": []}
        for cid, ok in base.items()
    ]


def ts_at_hour(hour, day_offset=0):
    now = time.localtime()
    lt = (now.tm_year, now.tm_mon, now.tm_mday - day_offset, hour, 0, 0, 0, 0, -1)
    return time.mktime(lt)


class VerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_verify_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def setUp(self):
        from linkmoth_outage import OUTAGE_TRACKER
        OUTAGE_TRACKER._consecutive_clear = 0
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM runs")
            conn.execute("DELETE FROM incident_outage_segments")
            conn.execute("DELETE FROM incidents")

    def tearDown(self):
        from linkmoth_outage import OUTAGE_TRACKER
        OUTAGE_TRACKER._consecutive_clear = 0

    def test_force_bypasses_populated_cache(self):
        engine = self.linkmoth.Engine()
        checks = make_checks()
        engine._store_ladder_cache(checks, 1.0, self.linkmoth.verdict(checks))
        calls = []

        def fake_ladder():
            calls.append(1)
            return make_checks(), 2.0

        with mock.patch.object(self.linkmoth, "run_ladder", side_effect=fake_ladder):
            engine.diagnose_once(kind="manual", force=False)
            self.assertEqual(len(calls), 0)  # fresh cache reused
            engine.diagnose_once(kind="verify", force=True)
            self.assertEqual(len(calls), 1)  # forced past the cache

    def test_verify_fix_persists_verify_run(self):
        engine = self.linkmoth.Engine()
        with mock.patch.object(self.linkmoth, "run_ladder",
                               return_value=(make_checks(), 1.0)):
            result = engine.verify_fix()
        self.assertIsNotNone(result)
        v, checks = result
        self.assertEqual(v["code"], "all_clear")
        with self.linkmoth.db() as conn:
            row = conn.execute(
                "SELECT kind FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["kind"], "verify")

    def test_verify_cooldown_starts_when_verify_runs(self):
        engine = self.linkmoth.Engine()
        # Checking the cooldown is read-only: it never starts the window.
        self.assertEqual(engine.verify_cooldown_remaining(), 0.0)
        self.assertEqual(engine.verify_cooldown_remaining(), 0.0)
        with mock.patch.object(self.linkmoth, "run_ladder",
                               return_value=(make_checks(), 1.0)):
            self.assertIsNotNone(engine.verify_fix())
        self.assertGreater(engine.verify_cooldown_remaining(), 0.0)

    def test_rejected_verify_does_not_burn_cooldown(self):
        engine = self.linkmoth.Engine()
        with mock.patch.object(engine, "diagnose_once", return_value=None):
            self.assertIsNone(engine.verify_fix())
        self.assertEqual(engine.verify_cooldown_remaining(), 0.0)

    def test_concurrent_triggers_open_single_incident(self):
        import threading

        engine = self.linkmoth.Engine()
        # Keep the recheck loop inert so it can't resolve the incident
        # while the trigger threads race.
        with mock.patch.object(engine, "_loop", lambda inc_id: None):
            threads = [
                threading.Thread(target=engine.trigger, args=(f"t{i}", "race"))
                for i in range(8)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)
        with self.linkmoth.db() as conn:
            open_count = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE resolved IS NULL"
            ).fetchone()[0]
        self.assertEqual(open_count, 1)


class PatternTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_pat_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def setUp(self):
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM incident_outage_segments")
            conn.execute("DELETE FROM incidents")

    def _add(self, started, resolved, code="wan_down"):
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO incidents(started, source, detail, resolved,"
                " verdict_code, verdict_title, ref) VALUES(?,?,?,?,?,?,?)",
                (started, "test", "", resolved, code, "t", None),
            )

    def test_single_incident_has_no_pattern_tier(self):
        self._add(ts_at_hour(3), ts_at_hour(3) + 120)
        p = self.linkmoth.Engine().patterns(code="wan_down")
        self.assertEqual(p["count"], 1)
        self.assertIsNone(p["tier"])
        self.assertIsNone(p["clusters_hour_range"])

    def test_two_incidents_are_recurrence_not_pattern(self):
        self._add(ts_at_hour(3, 0), ts_at_hour(3, 0) + 60)
        self._add(ts_at_hour(3, 1), ts_at_hour(3, 1) + 180)
        p = self.linkmoth.Engine().patterns(code="wan_down")
        self.assertEqual(p["count"], 2)
        self.assertEqual(p["tier"], "recurrence")
        self.assertIsNone(p["clusters_hour_range"])
        self.assertIsNotNone(p["median_duration_s"])
        self.assertIsNotNone(p["median_gap_s"])

    def test_three_spread_has_no_time_cluster(self):
        for h, d in ((2, 0), (10, 1), (18, 2)):
            self._add(ts_at_hour(h, d), ts_at_hour(h, d) + 100)
        p = self.linkmoth.Engine().patterns(code="wan_down")
        self.assertEqual(p["count"], 3)
        self.assertEqual(p["tier"], "pattern")
        self.assertIsNone(p["clusters_hour_range"])

    def test_three_clustered_reports_time_range(self):
        for d in (0, 1, 2):
            self._add(ts_at_hour(3, d), ts_at_hour(3, d) + 100)
        p = self.linkmoth.Engine().patterns(code="wan_down")
        self.assertEqual(p["tier"], "pattern")
        self.assertIsNotNone(p["clusters_hour_range"])
        # The reported 4h window must actually contain the 03:00 cluster.
        start_h = int(p["clusters_hour_range"][:2])
        self.assertLessEqual(start_h, 3)
        self.assertLess(3, start_h + 4)

    def test_all_clear_excluded_from_patterns(self):
        self._add(ts_at_hour(3), ts_at_hour(3) + 60, code="all_clear")
        self.assertIsNone(self.linkmoth.Engine().patterns(code="all_clear"))


class LifecycleAndExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_export_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def setUp(self):
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM runs")
            conn.execute("DELETE FROM incident_outage_segments")
            conn.execute("DELETE FROM incidents")

    def test_lifecycle_keeps_diagnosis_when_closed(self):
        now = time.time()
        with self.linkmoth.db() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail, diagnosis_code, diagnosis_title, verdict_code, verdict_title) "
                "VALUES(?,?,?,?,?,?,?)",
                (now, "test", "", "wan_down", "Observed WAN interruption", "wan_down", "Observed WAN interruption"),
            )
            inc_id = cur.lastrowid
            conn.execute("UPDATE incidents SET ref=? WHERE id=?", ("INC-TEST-1", inc_id))
        ok, _ = self.linkmoth.Engine().close_open_incident()
        self.assertTrue(ok)
        detail = self.linkmoth.Engine().incident_detail(inc_id=inc_id)
        self.assertEqual(detail["incident"]["lifecycle"], "closed")
        self.assertEqual(detail["incident"]["diagnosis_code"], "wan_down")
        self.assertIsNone(detail["incident"]["recovered_at"])
        self.assertIn("a healthy recovery was not recorded", detail["story"])

    def test_support_safe_export_excludes_secrets_and_stabilizes_private_networks(self):
        now = time.time()
        checks = [{"id": "gateway", "label": "Router", "ok": False,
                   "detail": "192.168.1.1 did not reply to 192.168.1.2", "ms": None, "micro": []}]
        with self.linkmoth.db() as conn:
            cur = conn.execute("INSERT INTO incidents(started, source, detail) VALUES(?,?,?)", (now, "test", "host 192.168.1.2"))
            inc_id = cur.lastrowid
            conn.execute("UPDATE incidents SET ref=?, diagnosis_code=?, diagnosis_title=? WHERE id=?", ("INC-TEST-2", "router_down", "Router unavailable", inc_id))
            conn.execute("INSERT INTO runs(incident_id, ts, severity, code, title, checks, kind) VALUES(?,?,?,?,?,?,?)", (inc_id, now, "bad", "router_down", "Router unavailable", __import__("json").dumps(checks), "incident"))
        exported = self.linkmoth.Engine().evidence_export("support-safe")
        raw = __import__("json").dumps(exported)
        self.assertNotIn("192.168.1.", raw)
        self.assertIn("PRIVATE-NET-1", raw)
        self.assertNotIn("discord_webhook_url", exported["configuration"])
        scrubbed = self.linkmoth._SupportPseudonyms().scrub({
            "host": "office-pi", "hostname": "office-pi", "device": "router",
        })
        self.assertEqual(scrubbed["host"], "HOST-1")
        self.assertEqual(scrubbed["hostname"], "HOST-1")
        self.assertEqual(scrubbed["device"], "DEVICE-1")


class InstallationProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")

    def test_versioned_build_without_record_is_unverified_manual(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "linkmoth-build.json").write_text(
                '{"schema":1,"version":"v0.2.0","release_commit":"' + "a" * 40 + '"}',
                encoding="utf-8",
            )
            with mock.patch.object(self.linkmoth, "SYSTEM_INSTALL", True), \
                 mock.patch.object(self.linkmoth, "BASE", base), \
                 mock.patch.object(self.linkmoth, "INSTALLATION_RECORD", base / "installation.json"):
                result = self.linkmoth.installation_provenance()
        self.assertEqual(result["state"], "unverified-manual")

    def test_install_without_record_or_build_metadata_is_legacy(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with mock.patch.object(self.linkmoth, "SYSTEM_INSTALL", True), \
                 mock.patch.object(self.linkmoth, "BASE", base), \
                 mock.patch.object(self.linkmoth, "INSTALLATION_RECORD", base / "installation.json"):
                result = self.linkmoth.installation_provenance()
        self.assertEqual(result["state"], "legacy-unavailable")

    def test_malformed_installation_record_is_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            record = base / "installation.json"
            record.write_text("{}", encoding="utf-8")
            record.chmod(0o644)
            with mock.patch.object(self.linkmoth, "SYSTEM_INSTALL", True), \
                 mock.patch.object(self.linkmoth, "BASE", base), \
                 mock.patch.object(self.linkmoth, "INSTALLATION_RECORD", record):
                result = self.linkmoth.installation_provenance()
        self.assertEqual(result["state"], "invalid")

    def test_verified_record_must_match_installed_build(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            commit = "b" * 40
            metadata = {"schema": 1, "version": "v0.2.0", "release_commit": commit}
            record_data = {
                **metadata,
                "archive_sha256": "c" * 64,
                "verification": "sigstore-verified",
                "installed_at": "2026-07-13T12:00:00Z",
            }
            import json
            (base / "linkmoth-build.json").write_text(json.dumps(metadata), encoding="utf-8")
            record = base / "installation.json"
            record.write_text(json.dumps(record_data), encoding="utf-8")
            safe_stat = mock.Mock(
                st_mode=self.linkmoth.stat.S_IFREG | 0o644, st_uid=0, st_gid=0,
            )
            patches = (
                mock.patch.object(self.linkmoth, "SYSTEM_INSTALL", True),
                mock.patch.object(self.linkmoth, "BASE", base),
                mock.patch.object(self.linkmoth, "INSTALLATION_RECORD", record),
                mock.patch.object(self.linkmoth.os, "lstat", return_value=safe_stat),
            )
            with patches[0], patches[1], patches[2], patches[3]:
                self.assertEqual(self.linkmoth.installation_provenance()["state"], "sigstore-verified")
            metadata["release_commit"] = "d" * 40
            (base / "linkmoth-build.json").write_text(json.dumps(metadata), encoding="utf-8")
            with patches[0], patches[1], patches[2], patches[3]:
                self.assertEqual(self.linkmoth.installation_provenance()["state"], "invalid")


class ManualUpdateCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_update_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")

    def _response(self, payload, status=200):
        response = mock.Mock(status=status)
        response.getheader.return_value = str(len(payload))
        response.read.return_value = payload
        return response

    def test_update_check_constructs_only_validated_fields_and_command(self):
        payload = b'{"tag_name":"v0.2.1","published_at":"2026-07-13T00:00:00Z","html_url":"https://github.com/benukas/Linkmoth/releases/tag/v0.2.1","ignored":"secret"}'
        conn = mock.Mock()
        conn.getresponse.return_value = self._response(payload)
        self.linkmoth.VERSION = "0.2.0"
        with mock.patch.object(self.linkmoth.socket, "getaddrinfo", return_value=[(None, None, None, None, ("140.82.112.5", 443))]), \
             mock.patch.object(self.linkmoth, "_PinnedHTTPSConnection", return_value=conn):
            result = self.linkmoth.manual_update_check()
        self.assertEqual(result["latest_version"], "0.2.1")
        self.assertTrue(result["update_available"])
        self.assertNotIn("ignored", result)
        self.assertIn("VERSION=v0.2.1", result["update_command"])
        self.assertNotIn("cosign", result["update_command"])
        self.assertIn("VERSION=v0.2.1", result["verified_update_command"])
        self.assertIn("cosign verify-blob", result["verified_update_command"])
        self.assertIn("--sigstore-verified", result["verified_update_command"])

    def test_update_check_rejects_wrong_release_url(self):
        payload = b'{"tag_name":"v0.2.1","published_at":"2026-07-13T00:00:00Z","html_url":"https://example.test/release"}'
        conn = mock.Mock()
        conn.getresponse.return_value = self._response(payload)
        self.linkmoth.VERSION = "0.2.0"
        with mock.patch.object(self.linkmoth.socket, "getaddrinfo", return_value=[(None, None, None, None, ("140.82.112.5", 443))]), \
             mock.patch.object(self.linkmoth, "_PinnedHTTPSConnection", return_value=conn):
            with self.assertRaisesRegex(ValueError, "invalid"):
                self.linkmoth.manual_update_check()

    def test_update_check_rejects_private_dns_before_connecting(self):
        self.linkmoth.VERSION = "0.2.0"
        with mock.patch.object(self.linkmoth.socket, "getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 443))]), \
             mock.patch.object(self.linkmoth, "_PinnedHTTPSConnection") as connect:
            with self.assertRaisesRegex(ValueError, "public address"):
                self.linkmoth.manual_update_check()
        connect.assert_not_called()

    def test_update_check_rejects_redirect_and_oversized_response(self):
        self.linkmoth.VERSION = "0.2.0"
        for response in (
            self._response(b"{}", status=302),
            mock.Mock(status=200, getheader=mock.Mock(return_value="999999")),
        ):
            conn = mock.Mock(); conn.getresponse.return_value = response
            with mock.patch.object(self.linkmoth.socket, "getaddrinfo", return_value=[(None, None, None, None, ("140.82.112.5", 443))]), \
                 mock.patch.object(self.linkmoth, "_PinnedHTTPSConnection", return_value=conn):
                with self.assertRaises(ValueError):
                    self.linkmoth.manual_update_check()
            conn.request.assert_called_once()
            self.assertEqual(conn.request.call_args.args[:2], ("GET", self.linkmoth.GITHUB_RELEASE_PATH))
            self.assertNotIn("Authorization", conn.request.call_args.kwargs["headers"])

    def test_pinned_connection_rejects_private_connected_peer(self):
        wrapped = mock.Mock(); wrapped.getpeername.return_value = ("127.0.0.1", 443)
        context = mock.Mock(); context.wrap_socket.return_value = wrapped
        raw_socket = mock.Mock()
        connection = self.linkmoth._PinnedHTTPSConnection("api.github.com", "140.82.112.5", timeout=1, context=context)
        with mock.patch.object(self.linkmoth.socket, "create_connection", return_value=raw_socket):
            with self.assertRaisesRegex(OSError, "not globally routable"):
                connection.connect()
        raw_socket.connect.assert_not_called()


class FirstBadRunChecksTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_fbr_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def setUp(self):
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM incidents")
            conn.execute("DELETE FROM runs")

    def _add_run(self, inc_id, ts, severity, checks):
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO runs(incident_id, ts, severity, code, title, checks)"
                " VALUES(?,?,?,?,?,?)",
                (inc_id, ts, severity, "wan_down" if severity != "ok" else "all_clear",
                 "t", json.dumps(checks)),
            )

    def test_returns_the_broken_ladder_not_the_healthy_closing_run(self):
        now = time.time()
        with self.linkmoth.db() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail) VALUES(?,?,?)",
                (now - 600, "baseline", ""),
            )
            inc_id = cur.lastrowid
        broken = [{"id": "raw_ping", "label": "Internet ping", "ok": False, "detail": "dead"}]
        recheck_broken = [{"id": "raw_ping", "label": "Internet ping", "ok": False, "detail": "still dead"}]
        healthy = [{"id": "raw_ping", "label": "Internet ping", "ok": True, "detail": "ok"}]
        self._add_run(inc_id, now - 600, "bad", broken)
        self._add_run(inc_id, now - 300, "bad", recheck_broken)
        self._add_run(inc_id, now - 60, "ok", healthy)
        result = self.linkmoth.ENGINE._first_bad_run_checks(inc_id)
        self.assertEqual(result[0]["detail"], "dead")  # the *first* bad run, not the latest
        self.assertFalse(result[0]["ok"])

    def test_empty_when_incident_has_no_bad_runs(self):
        with self.linkmoth.db() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail) VALUES(?,?,?)",
                (time.time(), "baseline", ""),
            )
            inc_id = cur.lastrowid
        self._add_run(inc_id, time.time(), "ok", [{"id": "raw_ping", "ok": True, "detail": "ok"}])
        self.assertEqual(self.linkmoth.ENGINE._first_bad_run_checks(inc_id), [])

    def test_recovery_webhook_receives_fault_ladder(self):
        now = time.time()
        with self.linkmoth.db() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail) VALUES(?,?,?)",
                (now - 120, "baseline", ""),
            )
            inc_id = cur.lastrowid
        broken = [
            {"id": "raw_ping", "label": "Internet ping", "ok": False,
             "detail": "dead"},
        ]
        self._add_run(inc_id, now - 120, "bad", broken)
        healthy = {
            "severity": "ok", "code": "all_clear", "title": "All clear",
            "explain": "fine", "hint": "",
        }
        engine = self.linkmoth.Engine()
        with mock.patch.dict(
            self.linkmoth.CFG,
            {"recheck_seconds": [0, 0], "recheck_repeat": 0},
        ), mock.patch.object(
            self.linkmoth.time, "sleep",
        ), mock.patch.object(
            engine, "diagnose_once", side_effect=[healthy, healthy],
        ), mock.patch.object(
            engine, "_discord_notify",
        ), mock.patch.object(
            engine, "_emit_webhook",
        ) as emit:
            engine._loop(inc_id)

        recovery_calls = [
            call for call in emit.call_args_list
            if len(call.args) > 1 and call.args[1] == "fault_recovered"
        ]
        self.assertEqual(len(recovery_calls), 1)
        self.assertEqual(recovery_calls[0].kwargs["checks"][0]["detail"], "dead")
        self.assertFalse(recovery_calls[0].kwargs["checks"][0]["ok"])


class IncidentStoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_story_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def setUp(self):
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM incident_outage_segments")
            conn.execute("DELETE FROM incidents")
            conn.execute("DELETE FROM runs")

    def _make_incident(self, resolved=None, false_alarm=0, source="baseline"):
        started = time.time() - 600
        recovered_at = started + 240 if resolved is not None else None
        with self.linkmoth.db() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail, resolved, recovered_at,"
                " verdict_code, verdict_title, ref, false_alarm)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (started, source, "self-detected: wan_down", resolved, recovered_at,
                 "wan_down", "Internet is dead beyond the router",
                 "INC-20260717-0001", false_alarm),
            )
            inc_id = cur.lastrowid
            checks = json.dumps([
                {"id": "gateway", "label": "Router", "ok": True,
                 "detail": "replied", "ms": 2.0, "micro": []},
                {"id": "raw_ping", "label": "Internet ping", "ok": False,
                 "detail": "timeout", "ms": None, "micro": []},
            ])
            conn.execute(
                "INSERT INTO runs(incident_id, ts, severity, code, title, checks)"
                " VALUES(?,?,?,?,?,?)",
                (inc_id, started, "bad", "wan_down",
                 "Internet is dead beyond the router", checks),
            )
            if recovered_at is not None:
                conn.execute(
                    "INSERT INTO runs(incident_id, ts, severity, code, title, checks)"
                    " VALUES(?,?,?,?,?,?)",
                    (inc_id, recovered_at, "ok", "all_clear",
                     "Nothing wrong seen from the network side", "[]"),
                )
        return inc_id

    def test_closed_incident_story_reads_naturally(self):
        inc_id = self._make_incident(resolved=time.time() - 60)
        detail = self.linkmoth.Engine().incident_detail(inc_id=inc_id)
        story = detail["story"]
        self.assertIn("Linkmoth's own background check noticed a problem", story)
        self.assertIn("The first rung to fail was Internet ping", story)
        self.assertIn("Verdict: Internet is dead beyond the router", story)
        self.assertIn("Network connectivity returned at", story)
        self.assertIn("approximately 4 min of observed downtime", story)
        self.assertIn("closed it at", story)
        self.assertIn("after the recovery remained stable", story)
        self.assertIn("rechecked 1 more time", story)
        self.assertNotIn("time(s)", story)
        self.assertIn("INC-20260717-0001", story)

    def test_open_incident_story_says_still_open(self):
        inc_id = self._make_incident(resolved=None)
        detail = self.linkmoth.Engine().incident_detail(inc_id=inc_id)
        self.assertIn("still open", detail["story"])

    def test_false_alarm_story(self):
        inc_id = self._make_incident(resolved=time.time() - 60, false_alarm=1)
        detail = self.linkmoth.Engine().incident_detail(inc_id=inc_id)
        self.assertIn("false alarm", detail["story"])

    def test_human_duration(self):
        hd = self.linkmoth._human_duration
        self.assertEqual(hd(42), "42 s")
        self.assertEqual(hd(180), "3 min")
        self.assertEqual(hd(3600), "1 h")
        self.assertEqual(hd(5400), "1 h 30 min")
        self.assertEqual(hd(90000), "1 d 1 h")


class OutageSegmentAccountingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_segments_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def setUp(self):
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM incident_outage_segments")
            conn.execute("DELETE FROM runs")
            conn.execute("DELETE FROM incidents")

    def _new_incident(self, started):
        with self.linkmoth.db() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail, verdict_code,"
                " verdict_title, diagnosis_code, diagnosis_title, ref)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (started, "baseline", "self-detected: wan_down", "wan_down",
                 "Internet is dead beyond the router", "wan_down",
                 "Internet is dead beyond the router", "INC-SEGMENTS-1"),
            )
            return cur.lastrowid

    def _observe(self, inc_id, observed_at, severity):
        code = "all_clear" if severity == "ok" else "wan_down"
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO runs(incident_id, ts, severity, code, title, checks)"
                " VALUES(?,?,?,?,?,?)",
                (inc_id, observed_at, severity, code, code, "[]"),
            )
            self.linkmoth._record_incident_observation(
                conn, inc_id, observed_at, severity
            )

    def test_returning_fault_adds_segment_without_extending_downtime(self):
        started = time.time() - 1800
        inc_id = self._new_incident(started)
        self._observe(inc_id, started, "bad")
        self._observe(inc_id, started + 180, "bad")
        self._observe(inc_id, started + 240, "ok")
        self._observe(inc_id, started + 600, "bad")
        self._observe(inc_id, started + 630, "ok")
        self._observe(inc_id, started + 900, "ok")
        with self.linkmoth.db() as conn:
            conn.execute(
                "UPDATE incidents SET resolved=? WHERE id=?",
                (started + 900, inc_id),
            )

        engine = self.linkmoth.Engine()
        detail = engine.incident_detail(inc_id=inc_id)
        self.assertEqual(len(detail["outage_segments"]), 2)
        self.assertEqual(detail["downtime_s"], 270)
        self.assertEqual(detail["incident_duration_s"], 900)
        self.assertEqual(detail["incident"]["recovered_at"], started + 630)
        self.assertEqual(detail["incident"]["resolved"], started + 900)
        self.assertIn("approximately 4 min of observed downtime", detail["story"])
        self.assertIn("across 2 outage segments", detail["story"])

        report = engine.isp_report(30)
        item = report["incidents"][0]
        self.assertEqual(report["downtime_s"], 270)
        self.assertEqual(report["longest"]["downtime_s"], 270)
        self.assertEqual(item["duration_s"], 270)
        self.assertEqual(item["incident_duration_s"], 900)
        self.assertEqual(len(item["outage_segments"]), 2)
        self.assertIn("network recovered", report["letter"])
        self.assertIn("incident closed", report["letter"])

    def test_backfill_repairs_close_time_masquerading_as_recovery(self):
        started = time.time() - 1800
        resolved = started + 900
        inc_id = self._new_incident(started)
        with self.linkmoth.db() as conn:
            conn.execute(
                "UPDATE incidents SET resolved=?, recovered_at=? WHERE id=?",
                (resolved, resolved, inc_id),
            )
            for observed_at, severity in (
                (started, "bad"),
                (started + 240, "ok"),
                (resolved, "ok"),
            ):
                conn.execute(
                    "INSERT INTO runs(incident_id, ts, severity, code, title, checks)"
                    " VALUES(?,?,?,?,?,?)",
                    (inc_id, observed_at, severity,
                     "all_clear" if severity == "ok" else "wan_down",
                     severity, "[]"),
                )
            self.linkmoth.backfill_incident_outage_segments(conn)
            incident = conn.execute(
                "SELECT recovered_at FROM incidents WHERE id=?", (inc_id,)
            ).fetchone()
            segments = conn.execute(
                "SELECT started, ended FROM incident_outage_segments"
                " WHERE incident_id=? ORDER BY started", (inc_id,)
            ).fetchall()
        self.assertEqual(incident["recovered_at"], started + 240)
        self.assertEqual(len(segments), 1)
        self.assertEqual(segments[0]["started"], started)
        self.assertEqual(segments[0]["ended"], started + 240)


class StatsWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_stats_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def setUp(self):
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM incident_outage_segments")
            conn.execute("DELETE FROM incidents")
            conn.execute("DELETE FROM runs")

    def _add_incident(self, started, resolved, code="wan_down"):
        with self.linkmoth.db() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail, resolved,"
                " verdict_code, verdict_title, ref) VALUES(?,?,?,?,?,?,?)",
                (started, "test", "", resolved, code, "t", None),
            )
            return cur.lastrowid

    def _add_run(self, ts, incident_id=None):
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO runs(incident_id, ts, severity, code, title,"
                " checks) VALUES(?,?,?,?,?,?)",
                (incident_id, ts, "ok", "all_clear", "t", "[]"),
            )

    def test_open_incident_older_than_window_still_counts_downtime(self):
        now = time.time()
        self._add_run(now - 40 * 86400)  # monitoring since before the window
        self._add_incident(now - 40 * 86400, None)
        stats = self.linkmoth.Engine().stats()
        # Clamped to the 30-day window: huge, but never more than the window.
        self.assertGreater(stats["downtime_s"], 29 * 86400)
        self.assertLessEqual(stats["downtime_s"], 30 * 86400 + 60)
        self.assertEqual(stats["uptime_pct"], 0.0)

    def test_resolved_incident_spanning_cutoff_is_clamped(self):
        now = time.time()
        self._add_run(now - 40 * 86400)
        # Started 35 days ago, resolved 29 days ago: only the last day of it
        # overlaps the window.
        self._add_incident(now - 35 * 86400, now - 29 * 86400)
        stats = self.linkmoth.Engine().stats()
        self.assertEqual(stats["incidents_30d"], 1)
        self.assertAlmostEqual(stats["downtime_s"], 86400, delta=60)


class IspReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_report_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def setUp(self):
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM incident_outage_segments")
            conn.execute("DELETE FROM incidents")
            conn.execute("DELETE FROM runs")

    def _add(self, started, resolved, code="wan_down", ref=None, false_alarm=0):
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO incidents(started, source, detail, resolved,"
                " verdict_code, verdict_title, ref, false_alarm)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (started, "baseline", "", resolved, code,
                 "Internet is dead beyond the router" if code == "wan_down"
                 else code, ref, false_alarm),
            )
            conn.execute(
                "INSERT INTO runs(ts, severity, code, title, checks)"
                " VALUES(?,?,?,?,?)",
                (started - 60, "ok", "all_clear", "ok", "[]"),
            )

    def test_report_summarizes_and_writes_letter(self):
        now = time.time()
        self._add(now - 3 * 86400, now - 3 * 86400 + 1800, ref="INC-A")
        self._add(now - 2 * 86400, now - 2 * 86400 + 600, ref="INC-B")
        self._add(now - 86400, now - 86400 + 300, code="router_down", ref="INC-C")
        self._add(now - 4 * 86400, now - 4 * 86400 + 60, code="all_clear",
                  ref="INC-FA", false_alarm=1)
        report = self.linkmoth.Engine().isp_report(30)
        self.assertEqual(report["incident_count"], 3)
        self.assertEqual(report["false_alarms"], 1)
        self.assertEqual(report["isp"]["count"], 2)
        self.assertEqual(report["isp"]["downtime_s"], 2400)
        self.assertEqual(report["blame"]["wan_down"]["count"], 2)
        self.assertEqual(report["longest"]["ref"], "INC-A")
        letter = report["letter"]
        self.assertIn("Provider-path outages: 2", letter)
        self.assertIn("INC-A", letter)
        self.assertNotIn("INC-C", letter)  # router fault is not ISP evidence
        self.assertIn("Methodology", letter)

    def test_report_without_isp_faults_says_so(self):
        now = time.time()
        self._add(now - 86400, now - 86400 + 300, code="router_down")
        report = self.linkmoth.Engine().isp_report(30)
        self.assertEqual(report["isp"]["count"], 0)
        self.assertIn("No provider-attributable outages", report["letter"])

    def test_report_csv_lists_every_incident(self):
        now = time.time()
        self._add(now - 86400, now - 86400 + 300, ref="INC-A")
        self._add(now - 3600, None, code="router_down", ref="INC-B")
        report = self.linkmoth.Engine().isp_report(30)
        csv_text = self.linkmoth.isp_report_csv(report)
        lines = csv_text.strip().splitlines()
        self.assertEqual(len(lines), 3)  # header + 2 incidents
        self.assertIn("ref,started_local", lines[0])
        self.assertIn("INC-A", csv_text)
        self.assertIn("INC-B", csv_text)
        self.assertIn("yes", csv_text)  # the open incident is marked ongoing

    def test_bad_days_value_falls_back_to_30(self):
        report = self.linkmoth.Engine().isp_report(12345)
        self.assertEqual(report["days"], 30)


class FalseAlarmAccountingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_fa_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def setUp(self):
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM incident_outage_segments")
            conn.execute("DELETE FROM incidents")
            conn.execute("DELETE FROM runs")

    def _add(self, code="wan_down", resolved=True, false_alarm=0, ref=None):
        now = time.time()
        with self.linkmoth.db() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail, resolved,"
                " verdict_code, verdict_title, ref, false_alarm)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (now - 3600, "test", "", (now - 60) if resolved else None,
                 code, code, ref, false_alarm),
            )
            conn.execute(
                "INSERT INTO runs(ts, severity, code, title, checks)"
                " VALUES(?,?,?,?,?)",
                (now - 7200, "ok", "all_clear", "ok", "[]"),
            )
            return cur.lastrowid

    def test_marking_closed_incident_false_alarm_moves_the_stats(self):
        # The user's exact report: one CLOSED incident, marked false alarm
        # from History, must show 0 incidents / 1 false alarm — not 1 / 0.
        self._add(code="wan_down", resolved=True, ref="INC-FA-1")
        engine = self.linkmoth.Engine()
        before = engine.stats()
        self.assertEqual(before["incidents_30d"], 1)
        self.assertEqual(before["false_alarms_30d"], 0)
        ok, _ = engine.mark_false_alarm(ref="INC-FA-1")
        self.assertTrue(ok)
        after = engine.stats()
        self.assertEqual(after["incidents_30d"], 0)
        self.assertEqual(after["false_alarms_30d"], 1)
        self.assertEqual(after["downtime_s"], 0)
        self.assertEqual(after["blame"], {})
        with self.linkmoth.db() as conn:
            row = conn.execute(
                "SELECT verdict_code, false_alarm FROM incidents"
            ).fetchone()
        self.assertEqual(row["verdict_code"], "all_clear")
        self.assertEqual(row["false_alarm"], 1)

    def test_legacy_false_alarm_rows_count_correctly(self):
        # Rows flagged before the verdict rewrite existed keep their old
        # code — the flag alone must move them to the false-alarm column.
        self._add(code="wan_down", resolved=True, false_alarm=1)
        stats = self.linkmoth.Engine().stats()
        self.assertEqual(stats["incidents_30d"], 0)
        self.assertEqual(stats["false_alarms_30d"], 1)
        self.assertEqual(stats["blame"], {})

    def test_false_alarms_leave_patterns_and_filters(self):
        self._add(code="wan_down", resolved=True, false_alarm=1, ref="INC-L1")
        self._add(code="wan_down", resolved=True, ref="INC-R1")
        engine = self.linkmoth.Engine()
        pattern = engine.patterns(code="wan_down")
        self.assertEqual(pattern["count"], 1)
        wan = engine.incidents_list(code="wan_down")
        self.assertEqual([i["ref"] for i in wan], ["INC-R1"])
        fa = engine.incidents_list(code="all_clear")
        self.assertEqual([i["ref"] for i in fa], ["INC-L1"])

    def test_false_alarm_excluded_from_isp_report(self):
        self._add(code="wan_down", resolved=True, false_alarm=1)
        report = self.linkmoth.Engine().isp_report(30)
        self.assertEqual(report["isp"]["count"], 0)
        self.assertEqual(report["false_alarms"], 1)


class JanitorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_jan_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def test_sweep_keeps_runs_of_open_incident(self):
        old = time.time() - (self.linkmoth.CFG["retention_days"] + 5) * 86400
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM incident_outage_segments")
            conn.execute("DELETE FROM incidents")
            conn.execute("DELETE FROM runs")
            cur = conn.execute(
                "INSERT INTO incidents(started, source, detail) VALUES(?,?,?)",
                (old, "test", "still open"),
            )
            open_id = cur.lastrowid
            conn.execute(
                "INSERT INTO runs(incident_id, ts, severity, code, title,"
                " checks) VALUES(?,?,?,?,?,?)",
                (open_id, old, "critical", "wan_down", "t", "[]"),
            )
            conn.execute(
                "INSERT INTO runs(incident_id, ts, severity, code, title,"
                " checks) VALUES(?,?,?,?,?,?)",
                (None, old, "ok", "all_clear", "t", "[]"),
            )
        self.linkmoth.janitor_sweep()
        with self.linkmoth.db() as conn:
            kept = conn.execute(
                "SELECT COUNT(*) FROM runs WHERE incident_id=?", (open_id,)
            ).fetchone()[0]
            unattached = conn.execute(
                "SELECT COUNT(*) FROM runs WHERE incident_id IS NULL"
            ).fetchone()[0]
        self.assertEqual(kept, 1)
        self.assertEqual(unattached, 0)


class MonthlyDigestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_month_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def setUp(self):
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM incident_outage_segments")
            conn.execute("DELETE FROM incidents")
            conn.execute("DELETE FROM quality_samples")
            conn.execute("DELETE FROM app_meta")

    def _prev_month(self):
        lt = time.localtime()
        return (lt.tm_year - 1, 12) if lt.tm_mon == 1 else (lt.tm_year, lt.tm_mon - 1)

    def test_first_run_arms_without_sending(self):
        with mock.patch("linkmoth_discord.send_monthly_digest_alert") as discord:
            self.assertFalse(self.linkmoth.maybe_send_monthly_digest())
        discord.assert_not_called()
        self.assertIsNotNone(self.linkmoth._get_meta("monthly_digest_sent"))

    def test_month_rollover_sends_once(self):
        prev_year, prev_month = self._prev_month()
        start, _ = self.linkmoth._month_bounds(prev_year, prev_month)
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO incidents(started, source, detail, resolved,"
                " verdict_code, verdict_title, ref) VALUES(?,?,?,?,?,?,?)",
                (start + 3600, "baseline", "", start + 5400,
                 "wan_down", "Internet is dead beyond the router", "INC-M1"),
            )
        # Pretend the digest was last sent for the previous month.
        prev_key = f"{prev_year:04d}-{prev_month:02d}"
        self.linkmoth._set_meta("monthly_digest_sent", prev_key)
        with mock.patch(
            "linkmoth_discord.send_monthly_digest_alert", return_value=True,
        ) as discord, mock.patch(
            "linkmoth_push.send_push_async", return_value=False,
        ):
            self.assertTrue(self.linkmoth.maybe_send_monthly_digest())
            self.assertFalse(self.linkmoth.maybe_send_monthly_digest())
        discord.assert_called_once()
        lines = discord.call_args.args[0]
        self.assertTrue(any("1 incident, 0 false alarms." in line for line in lines))
        self.assertFalse(any("(s)" in line for line in lines))
        self.assertTrue(any("Downtime" in line for line in lines))
        lt = time.localtime()
        self.assertEqual(
            self.linkmoth._get_meta("monthly_digest_sent"),
            f"{lt.tm_year:04d}-{lt.tm_mon:02d}",
        )

    def test_clean_month_reports_clean(self):
        prev_year, prev_month = self._prev_month()
        lines = self.linkmoth.monthly_digest_lines(prev_year, prev_month)
        self.assertTrue(any("clean month" in line for line in lines))

    def test_partial_first_month_is_skipped_not_reported_as_full_uptime(self):
        # Reproduces the reported bug: Linkmoth installed on day 20 of the
        # previous month. Even though the marker was armed that month and a
        # full calendar month has now rolled over, reporting on it would
        # credit ~19 days of pre-install time as uptime. It must be skipped.
        prev_year, prev_month = self._prev_month()
        start, end = self.linkmoth._month_bounds(prev_year, prev_month)
        mid_month = start + 19 * 86400
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO runs(ts, severity, code, title, checks)"
                " VALUES(?,?,?,?,?)",
                (mid_month, "ok", "all_clear", "t", "[]"),
            )
        prev_key = f"{prev_year:04d}-{prev_month:02d}"
        self.linkmoth._set_meta("monthly_digest_sent", prev_key)
        with mock.patch(
            "linkmoth_discord.send_monthly_digest_alert",
        ) as discord:
            result = self.linkmoth.maybe_send_monthly_digest()
        self.assertFalse(result)
        discord.assert_not_called()
        lt = time.localtime()
        self.assertEqual(
            self.linkmoth._get_meta("monthly_digest_sent"),
            f"{lt.tm_year:04d}-{lt.tm_mon:02d}",
        )
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM runs")

    def test_uptime_denominator_clamped_to_monitoring_started(self):
        # Direct check of the math fix, independent of the send/skip
        # decision: monitoring started 19 days into the month, with a
        # 1-hour fault on day 20. Uptime must be computed against the
        # ~11-12 observed days, not the full ~31-day calendar month.
        prev_year, prev_month = self._prev_month()
        start, end = self.linkmoth._month_bounds(prev_year, prev_month)
        monitoring_started = start + 19 * 86400
        with self.linkmoth.db() as conn:
            conn.execute(
                "INSERT INTO runs(ts, severity, code, title, checks)"
                " VALUES(?,?,?,?,?)",
                (monitoring_started, "ok", "all_clear", "t", "[]"),
            )
            conn.execute(
                "INSERT INTO incidents(started, source, detail, resolved,"
                " verdict_code, verdict_title, ref) VALUES(?,?,?,?,?,?,?)",
                (monitoring_started + 3600, "baseline", "",
                 monitoring_started + 7200, "wan_down", "WAN down", "INC-M2"),
            )
        lines = self.linkmoth.monthly_digest_lines(prev_year, prev_month)
        observed_span_days = (end - monitoring_started) / 86400
        # 1 hour of downtime over the observed span, not the full month.
        expected_uptime = round(
            max(0.0, 100.0 * (1 - 3600 / (observed_span_days * 86400))), 2
        )
        uptime_line = next(line for line in lines if "uptime" in line)
        self.assertIn(f"{expected_uptime}%", uptime_line)
        # The bug's signature: computed over the full calendar month, uptime
        # would round to 99.87% or higher; over ~11-12 observed days it's
        # meaningfully lower.
        self.assertLess(expected_uptime, 99.7)
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM runs")


class HistoryRangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_hr_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")
        cls.linkmoth.init_db()

    def setUp(self):
        with self.linkmoth.db() as conn:
            conn.execute("DELETE FROM runs")

    def _seed(self, count, spacing_s, start_offset_s):
        now = time.time()
        with self.linkmoth.db() as conn:
            for i in range(count):
                checks = json.dumps([
                    {"id": "raw_ping", "label": "Internet ping", "ok": True,
                     "detail": "d", "ms": 10.0 + (i % 5), "micro": []},
                ])
                conn.execute(
                    "INSERT INTO runs(ts, severity, code, title, checks, kind)"
                    " VALUES(?,?,?,?,?,?)",
                    (now - start_offset_s + i * spacing_s, "ok", "all_clear",
                     "t", checks, "baseline"),
                )

    def test_small_window_returns_raw_samples(self):
        self._seed(20, spacing_s=60, start_offset_s=20 * 60)
        result = self.linkmoth.ENGINE.history_range(6)
        self.assertFalse(result["bucketed"])
        self.assertIsNone(result["bucket_seconds"])
        self.assertEqual(len(result["samples"]), 20)
        self.assertAlmostEqual(
            result["samples"][0]["ms"]["raw_ping"], 10.0, delta=5
        )

    def test_large_window_is_bucketed_and_bounded(self):
        # 3000 one-minute samples spanning 50 hours, well past the
        # 300-point cap for a 30-day window.
        self._seed(3000, spacing_s=60, start_offset_s=3000 * 60)
        result = self.linkmoth.ENGINE.history_range(24 * 30)
        self.assertTrue(result["bucketed"])
        self.assertIsNotNone(result["bucket_seconds"])
        self.assertLessEqual(len(result["samples"]), self.linkmoth.MAX_HISTORY_POINTS)
        self.assertGreater(len(result["samples"]), 0)
        for sample in result["samples"]:
            self.assertIn("sample_count", sample)
            self.assertGreaterEqual(sample["sample_count"], 1)
            self.assertIn("raw_ping", sample["ms"])

    def test_invalid_hours_falls_back_to_default(self):
        result = self.linkmoth.ENGINE.history_range(12345)
        self.assertEqual(result["hours"], 24)

    def test_bucket_severity_takes_the_worst_in_the_bucket(self):
        now = time.time()
        with self.linkmoth.db() as conn:
            for i in range(400):
                severity = "bad" if i == 200 else "ok"
                checks = json.dumps([
                    {"id": "raw_ping", "label": "Internet ping",
                     "ok": severity != "bad", "detail": "d", "ms": 10.0,
                     "micro": []},
                ])
                conn.execute(
                    "INSERT INTO runs(ts, severity, code, title, checks, kind)"
                    " VALUES(?,?,?,?,?,?)",
                    (now - (400 - i) * 5, severity,
                     "wan_down" if severity == "bad" else "all_clear",
                     "t", checks, "baseline"),
                )
        result = self.linkmoth.ENGINE.history_range(6)
        self.assertTrue(result["bucketed"])
        self.assertTrue(any(s["severity"] == "bad" for s in result["samples"]))


class DoctorJsonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_doc_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")

    def test_doctor_json_emits_machine_readable_checks(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self.linkmoth.doctor(json_output=True)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["schema"], 1)
        self.assertIsInstance(payload["checks"], list)
        self.assertGreater(len(payload["checks"]), 5)
        self.assertIn(rc, (0, 1))
        statuses = {c["status"] for c in payload["checks"]}
        self.assertTrue(statuses <= {"ok", "fail", "info"})


class ConfigCoercionTests(unittest.TestCase):
    def _load_with(self, config):
        import json as _json
        tmp = Path(tempfile.mkdtemp(prefix="linkmoth_cfg_"))
        (tmp / "config.json").write_text(_json.dumps(config))
        os.environ["LINKMOTH_CONFIG"] = str(tmp / "config.json")
        os.environ["LINKMOTH_STATE_DIR"] = str(tmp)
        try:
            if "linkmoth" in sys.modules:
                del sys.modules["linkmoth"]
            return importlib.import_module("linkmoth")
        finally:
            os.environ.pop("LINKMOTH_CONFIG", None)

    def test_wrong_typed_keys_fall_back_to_defaults(self):
        lm = self._load_with({
            "recheck_seconds": 30,
            "ping_targets": "1.1.1.1",
            "incident_max_hours": "24",
            "auth": [],
        })
        self.assertEqual(
            lm.CFG["recheck_seconds"], lm.DEFAULT_CONFIG["recheck_seconds"]
        )
        self.assertEqual(lm.CFG["ping_targets"], lm.DEFAULT_CONFIG["ping_targets"])
        self.assertEqual(
            lm.CFG["incident_max_hours"], lm.DEFAULT_CONFIG["incident_max_hours"]
        )
        self.assertEqual(lm.CFG["auth"], lm.DEFAULT_CONFIG["auth"])
        # These errors are recoverable: main() must not refuse to start after
        # the invalid values have been replaced by safe shipped defaults.
        self.assertIsNone(lm.CONFIG_ERROR)

    def test_valid_config_is_untouched(self):
        lm = self._load_with({
            "recheck_seconds": [5, 10],
            "ping_targets": ["9.9.9.9"],
            "incident_max_hours": 12,
        })
        self.assertEqual(lm.CFG["recheck_seconds"], [5, 10])
        self.assertEqual(lm.CFG["ping_targets"], ["9.9.9.9"])
        self.assertEqual(lm.CFG["incident_max_hours"], 12)
        self.assertIsNone(lm.CONFIG_ERROR)


if __name__ == "__main__":
    unittest.main()

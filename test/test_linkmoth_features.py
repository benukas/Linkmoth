#!/usr/bin/env python3
"""Tests for guided-troubleshooting verify and outage-correlation patterns."""
import importlib
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

    def test_verify_cooldown(self):
        engine = self.linkmoth.Engine()
        self.assertEqual(engine.verify_cooldown_remaining(), 0.0)
        self.assertGreater(engine.verify_cooldown_remaining(), 0.0)


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


if __name__ == "__main__":
    unittest.main()

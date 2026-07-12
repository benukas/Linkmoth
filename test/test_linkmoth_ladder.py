#!/usr/bin/env python3
"""Tests for Linkmoth fault ladder link and WLAN checks."""
import importlib
import os
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))


class _FakeDNSSocket:
    """Stand-in for socket.socket that replays a crafted DNS response."""

    def __init__(self, mode="ok"):
        self.mode = mode
        self.sent = b""

    def settimeout(self, t):
        pass

    def connect(self, addr):
        pass

    def send(self, data):
        self.sent = data
        return len(data)

    def recv(self, n):
        if self.mode == "timeout":
            raise socket.timeout()
        txn = self.sent[0:2]
        if self.mode == "badid":
            txn = bytes([txn[0] ^ 0xFF, txn[1]])
        flags_hi = 0x80  # QR set, no truncation
        flags_lo = 0x00  # RCODE 0 (no error)
        header = txn + bytes([flags_hi, flags_lo]) + struct.pack(">HHHH", 1, 1, 0, 0)
        return header + b"\x00" * 8  # a (bogus) answer record — not parsed

    def close(self):
        pass


class DnsResolverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_dns_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")

    def test_valid_answer_reports_success(self):
        with mock.patch.object(self.linkmoth.socket, "socket",
                               return_value=_FakeDNSSocket("ok")):
            ok, detail, ms = self.linkmoth.dig("1.1.1.1", "gstatic.com")
        self.assertTrue(ok)
        self.assertIsNotNone(ms)
        self.assertIn("answered", detail)

    def test_mismatched_transaction_id_is_rejected(self):
        # A spoofed/stray datagram with the wrong id must not count as an answer.
        with mock.patch.object(self.linkmoth.socket, "socket",
                               return_value=_FakeDNSSocket("badid")):
            ok, detail, ms = self.linkmoth.dig("1.1.1.1", "gstatic.com")
        self.assertFalse(ok)
        self.assertIsNone(ms)

    def test_timeout_reports_failure(self):
        with mock.patch.object(self.linkmoth.socket, "socket",
                               return_value=_FakeDNSSocket("timeout")):
            ok, detail, ms = self.linkmoth.dig("1.1.1.1", "gstatic.com")
        self.assertFalse(ok)
        self.assertIn("no answer", detail)


class ProbeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_probes_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")

    def test_partial_group_keeps_each_target_result(self):
        ok, detail, ms, evidence = self.linkmoth.probe_group([
            ("first", (True, "first answered", 12.0)),
            ("second", (False, "second timed out", None)),
        ])
        self.assertTrue(ok)
        self.assertEqual(ms, 12.0)
        self.assertEqual(evidence["state"], "partial")
        self.assertEqual(evidence["probe_summary"], {
            "attempted": 2, "passed": 1, "failed": 1,
        })
        self.assertEqual([p["target"] for p in evidence["probes"]], ["first", "second"])
        self.assertIn("second timed out", detail)

    def test_all_failed_group_remains_failed(self):
        ok, _detail, ms, evidence = self.linkmoth.probe_group([
            ("first", (False, "no reply", None)),
            ("second", (False, "no reply", None)),
        ])
        self.assertFalse(ok)
        self.assertIsNone(ms)
        self.assertEqual(evidence["state"], "failed")

    def test_https_probe_labels_never_include_url_credentials(self):
        label = self.linkmoth._https_probe_label(
            "https://diagnostic-user:diagnostic-pass@example.com/check"
        )
        self.assertEqual(label, "example.com")

    def test_https_probe_rejects_userinfo_before_network_access(self):
        with mock.patch.object(self.linkmoth.urlrequest, "build_opener") as opener:
            ok, detail, ms = self.linkmoth.http_get(
                "https://diagnostic-user:diagnostic-pass@example.com/check"
            )
        self.assertFalse(ok)
        self.assertEqual(detail, "invalid HTTPS target")
        self.assertIsNone(ms)
        opener.assert_not_called()


class LinkNegotiationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_ladder_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")

    def test_downgraded_speed_shows_warning(self):
        with mock.patch.object(self.linkmoth, "_read_link_speed_duplex", return_value=(100, "full")):
            with mock.patch.object(Path, "read_text", return_value="1"):
                ok, detail = self.linkmoth.check_link("eth0")
        self.assertTrue(ok)
        self.assertIn("⚠️", detail)
        self.assertIn("downgraded to 100 Mb/s", detail)

    def test_gigabit_full_duplex_is_clean(self):
        with mock.patch.object(self.linkmoth, "_read_link_speed_duplex", return_value=(1000, "full")):
            with mock.patch.object(Path, "read_text", return_value="1"):
                ok, detail = self.linkmoth.check_link("eth0")
        self.assertTrue(ok)
        self.assertNotIn("⚠️", detail)
        self.assertIn("1000 Mb/s", detail)

    def test_half_duplex_shows_warning(self):
        with mock.patch.object(self.linkmoth, "_read_link_speed_duplex", return_value=(1000, "half")):
            with mock.patch.object(Path, "read_text", return_value="1"):
                ok, detail = self.linkmoth.check_link("eth0")
        self.assertTrue(ok)
        self.assertIn("⚠️", detail)
        self.assertIn("half-duplex", detail)


class RouterWlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_ladder_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")

    def test_skipped_when_not_configured(self):
        self.linkmoth.CFG["target_wifi_clients"] = []
        ok, detail = self.linkmoth.check_router_wlan(True)
        self.assertIsNone(ok)
        self.assertIn("skipped", detail)

    def test_skipped_when_gateway_down(self):
        self.linkmoth.CFG["target_wifi_clients"] = ["192.168.1.50"]
        ok, detail = self.linkmoth.check_router_wlan(False)
        self.assertIsNone(ok)
        self.assertIn("unreachable", detail)

    def test_fails_when_all_clients_silent(self):
        self.linkmoth.CFG["target_wifi_clients"] = ["192.168.1.50", "192.168.1.51"]
        with mock.patch.object(self.linkmoth, "ping", return_value=(False, "no reply", None)):
            ok, detail = self.linkmoth.check_router_wlan(True)
        self.assertFalse(ok)
        self.assertIn("No configured Wi-Fi witness replied", detail)
        self.assertIn("sleeping clients", detail)

    def test_passes_when_any_client_replies(self):
        self.linkmoth.CFG["target_wifi_clients"] = ["192.168.1.50", "192.168.1.51"]
        with mock.patch.object(
            self.linkmoth,
            "ping",
            side_effect=[(False, "192.168.1.50: no reply", None), (True, "192.168.1.51: 3 ms", 3.0)],
        ):
            ok, detail = self.linkmoth.check_router_wlan(True)
        self.assertTrue(ok)
        self.assertIn("192.168.1.51", detail)

    def test_wlan_disagreement_is_retained_as_partial_evidence(self):
        self.linkmoth.CFG["target_wifi_clients"] = ["192.168.1.50", "192.168.1.51"]
        with mock.patch.object(
            self.linkmoth,
            "ping",
            side_effect=[(False, "first asleep", None), (True, "second replied", 3.0)],
        ):
            ok, detail, evidence = self.linkmoth.check_router_wlan(
                True, include_evidence=True,
            )
        self.assertTrue(ok)
        self.assertIn("1/2", detail)
        self.assertEqual(evidence["state"], "partial")


class VerdictIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if "linkmoth" in sys.modules:
            cls.linkmoth = sys.modules["linkmoth"]
        else:
            os.environ.setdefault("LINKMOTH_STATE_DIR", tempfile.mkdtemp(prefix="linkmoth_ladder_"))
            cls.linkmoth = importlib.import_module("linkmoth")

    def _base_checks(self, **overrides):
        checks = [
            {"id": "power", "ok": True, "detail": "power ok"},
            {"id": "link", "ok": True, "detail": "eth0: link up, 1000 Mb/s"},
            {"id": "gateway", "ok": True, "detail": "192.168.1.1: 2 ms"},
            {"id": "router_wlan", "ok": None, "detail": "not configured — skipped"},
            {"id": "pihole_dns", "ok": True, "detail": "ok"},
            {"id": "upstream_dns", "ok": True, "detail": "ok"},
            {"id": "raw_ping", "ok": True, "detail": "ok"},
            {"id": "https", "ok": True, "detail": "ok"},
        ]
        by_id = {c["id"]: c for c in checks}
        for key, val in overrides.items():
            by_id[key].update(val)
        return list(by_id.values())

    def test_router_wlan_down_verdict(self):
        checks = self._base_checks(
            router_wlan={"ok": False, "detail": "❌ Wireless client timeout — Router 2.4/5GHz radios may have crashed"},
        )
        v = self.linkmoth.verdict(checks)
        self.assertEqual(v["code"], "router_wlan_down")
        self.assertEqual(v["severity"], "warn")
        self.assertEqual(self.linkmoth.confidence_from_checks(checks), "medium")

    def test_weak_wlan_witness_does_not_hide_confirmed_dns_fault(self):
        checks = self._base_checks(
            router_wlan={"ok": False, "detail": "no witnesses replied"},
            pihole_dns={"ok": False, "detail": "resolver did not answer"},
        )
        v = self.linkmoth.verdict(checks)
        self.assertEqual(v["code"], "local_dns_broken")
        self.assertEqual(v["severity"], "bad")

    def test_https_success_prevents_false_total_wan_outage(self):
        checks = self._base_checks(
            upstream_dns={"ok": False}, raw_ping={"ok": False},
            https={"ok": True},
        )
        v = self.linkmoth.verdict(checks)
        self.assertEqual(v["code"], "restricted_connectivity")
        self.assertEqual(v["severity"], "warn")

    def test_total_wan_outage_requires_https_failure_too(self):
        checks = self._base_checks(
            upstream_dns={"ok": False}, raw_ping={"ok": False},
            https={"ok": False},
        )
        self.assertEqual(self.linkmoth.verdict(checks)["code"], "wan_down")

    def test_power_only_fault_is_not_all_clear(self):
        checks = self._base_checks(
            power={"ok": False, "detail": "undervoltage now"},
        )
        v = self.linkmoth.verdict(checks)
        self.assertEqual(v["code"], "host_power")
        self.assertEqual(v["severity"], "warn")

    def test_partial_redundant_evidence_reduces_confidence_without_outage(self):
        checks = self._base_checks(
            upstream_dns={"ok": True, "state": "partial"},
        )
        v = self.linkmoth.verdict(checks)
        self.assertEqual(v["code"], "all_clear")
        self.assertIn("disagree", v["title"])
        self.assertEqual(self.linkmoth.confidence_from_checks(checks), "medium")
        assessment = self.linkmoth.confidence_assessment(checks)
        self.assertEqual(assessment["level"], "medium")
        self.assertIn("disagreed", assessment["reason"])

    def test_observer_link_failure_explains_low_confidence(self):
        checks = self._base_checks(link={"ok": False, "detail": "no carrier"})
        assessment = self.linkmoth.confidence_assessment(checks)
        self.assertEqual(assessment["level"], "low")
        self.assertIn("own network link", assessment["reason"])

    def test_partial_wifi_witness_evidence_is_honestly_medium_confidence(self):
        checks = self._base_checks(
            router_wlan={"ok": True, "state": "partial"},
        )
        v = self.linkmoth.verdict(checks)
        self.assertEqual(v["code"], "all_clear")
        self.assertIn("disagree", v["title"])
        self.assertEqual(self.linkmoth.confidence_from_checks(checks), "medium")

    def test_link_degraded_verdict(self):
        checks = self._base_checks(
            link={"ok": True, "detail": "⚠️ eth0: link up, downgraded to 100 Mb/s"},
        )
        v = self.linkmoth.verdict(checks)
        self.assertEqual(v["code"], "link_degraded")
        self.assertEqual(v["severity"], "warn")

    def test_degraded_but_working_link_does_not_hide_confirmed_dns_fault(self):
        checks = self._base_checks(
            link={"ok": True, "detail": "⚠️ eth0: downgraded to 100 Mb/s"},
            pihole_dns={"ok": False, "detail": "resolver did not answer"},
        )
        self.assertEqual(self.linkmoth.verdict(checks)["code"], "local_dns_broken")


class SettingsTests(unittest.TestCase):
    def test_optional_ip_list_accepts_empty(self):
        import linkmoth
        self.assertEqual(linkmoth._optional_ip_list(""), [])
        self.assertEqual(linkmoth._optional_ip_list([]), [])
        self.assertEqual(linkmoth._optional_ip_list("192.168.1.10"), ["192.168.1.10"])


class MicroStepTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_micro_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")

    def test_disk_full_flags_failure(self):
        usage = type("U", (), {"total": 100, "used": 100, "free": 0})()
        with mock.patch.object(self.linkmoth.shutil, "disk_usage", return_value=usage):
            ok, detail = self.linkmoth.check_disk_pressure("/")
        self.assertFalse(ok)
        self.assertIn("100% full", detail)

    def test_micro_pihole_runs_service_and_disk_checks(self):
        with mock.patch.object(
            self.linkmoth,
            "run_cmd",
            side_effect=[(0, "loaded"), (0, "inactive"), (0, "dead"), (0, ""), (0, "")],
        ):
            with mock.patch.object(self.linkmoth, "check_disk_pressure", return_value=(True, "disk 42% used on /")):
                steps = self.linkmoth.micro_pihole_dns()
        self.assertEqual(len(steps), 2)
        self.assertFalse(steps[0]["ok"])
        self.assertIn("inactive", steps[0]["detail"])

    def test_pihole_pass_skips_micro_steps(self):
        with mock.patch.object(self.linkmoth, "default_route", return_value=("192.168.1.1", "eth0")):
            with mock.patch.object(self.linkmoth, "check_power", return_value=(True, "ok")):
                with mock.patch.object(self.linkmoth, "check_link", return_value=(True, "eth0: link up, 1000 Mb/s")):
                    with mock.patch.object(self.linkmoth, "ping", return_value=(True, "gw ok", 1.0)):
                        with mock.patch.object(self.linkmoth, "check_router_wlan", return_value=(None, "skipped")):
                            with mock.patch.object(self.linkmoth, "dig", return_value=(True, "dns ok", 1.0)):
                                with mock.patch.object(
                                    self.linkmoth,
                                    "run_cmd",
                                    return_value=(0, "loaded"),
                                ):
                                    with mock.patch.object(self.linkmoth, "micro_local_dns") as micro:
                                        with mock.patch.object(self.linkmoth, "http_get", return_value=(True, "ok", 1.0)):
                                            checks, _ = self.linkmoth.run_ladder()
        micro.assert_not_called()
        local_dns = next(c for c in checks if c["id"] == "local_dns")
        self.assertNotIn("micro", local_dns)

    def test_pihole_fail_runs_micro_steps(self):
        with mock.patch.object(self.linkmoth, "default_route", return_value=("192.168.1.1", "eth0")):
            with mock.patch.object(self.linkmoth, "check_power", return_value=(True, "ok")):
                with mock.patch.object(self.linkmoth, "check_link", return_value=(True, "eth0: link up, 1000 Mb/s")):
                    with mock.patch.object(self.linkmoth, "ping", return_value=(True, "gw ok", 1.0)):
                        with mock.patch.object(self.linkmoth, "check_router_wlan", return_value=(None, "skipped")):
                            def dig_side_effect(server, domain):
                                if server == "127.0.0.1":
                                    return (False, "@127.0.0.1: no answer", None)
                                return (True, "upstream ok", 1.0)

                            with mock.patch.dict(
                                self.linkmoth.CFG,
                                {"local_dns": {
                                    "mode": "enabled",
                                    "address": "127.0.0.1",
                                    "provider": "pihole",
                                }},
                            ):
                                with mock.patch.object(self.linkmoth, "dig", side_effect=dig_side_effect):
                                    with mock.patch.object(
                                        self.linkmoth,
                                        "micro_local_dns",
                                        return_value=[
                                            {"label": "Pi-hole service", "ok": False, "detail": "service inactive (dead)"},
                                            {"label": "Root disk space", "ok": True, "detail": "disk 40% used on /"},
                                        ],
                                    ):
                                        with mock.patch.object(self.linkmoth, "http_get", return_value=(True, "ok", 1.0)):
                                            checks, _ = self.linkmoth.run_ladder()
        local_dns = next(c for c in checks if c["id"] == "local_dns")
        self.assertFalse(local_dns["ok"])
        self.assertEqual(len(local_dns["micro"]), 2)

    def test_verdict_uses_disk_micro_hint(self):
        checks = [
            {"id": "power", "ok": True, "detail": "ok"},
            {"id": "link", "ok": True, "detail": "ok"},
            {"id": "gateway", "ok": True, "detail": "ok"},
            {"id": "router_wlan", "ok": None, "detail": "skipped"},
            {"id": "pihole_dns", "ok": False, "detail": "no answer", "micro": [
                {"label": "Root disk space", "ok": False, "detail": "disk 100% full on /"},
            ]},
            {"id": "upstream_dns", "ok": True, "detail": "ok"},
            {"id": "raw_ping", "ok": True, "detail": "ok"},
            {"id": "https", "ok": True, "detail": "ok"},
        ]
        v = self.linkmoth.verdict(checks)
        self.assertEqual(v["code"], "local_dns_broken")
        self.assertIn("disk 100% full", v["explain"])
        self.assertIn("Free disk space", v["hint"])


class LocalDnsProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_local_dns_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")

    def _checks(self, provider="generic"):
        return [
            {"id": "power", "ok": True, "detail": "ok"},
            {"id": "link", "ok": True, "detail": "ok"},
            {"id": "gateway", "ok": True, "detail": "ok"},
            {"id": "router_wlan", "ok": None, "detail": "skipped"},
            {
                "id": "local_dns", "ok": False, "detail": "no answer",
                "provider": provider,
                "provider_name": (
                    self.linkmoth.LOCAL_DNS_ADAPTERS.get(provider, {}).get("name")
                ),
                "address": "127.0.0.1",
            },
            {"id": "upstream_dns", "ok": True, "detail": "ok"},
            {"id": "raw_ping", "ok": True, "detail": "ok"},
            {"id": "https", "ok": True, "detail": "ok"},
        ]

    def test_legacy_local_dns_config_is_preserved(self):
        self.assertEqual(
            self.linkmoth.normalize_local_dns_config("auto"),
            {"mode": "auto", "address": "127.0.0.1", "provider": "auto"},
        )
        self.assertEqual(
            self.linkmoth.normalize_local_dns_config(False)["mode"],
            "disabled",
        )

    def test_old_history_ids_translate_at_read_time(self):
        checks = self.linkmoth.normalize_stored_checks([{
            "id": "pihole_dns",
            "label": "Local DNS (Pi-hole)",
            "ok": False,
            "detail": "no answer",
        }])
        self.assertEqual(checks[0]["id"], "local_dns")
        self.assertEqual(checks[0]["label"], "Local DNS resolver")
        self.assertEqual(checks[0]["provider"], "pihole")
        verdict = self.linkmoth.normalize_stored_verdict({
            "code": "pihole_broken",
            "title": "Pi-hole stopped answering",
        })
        self.assertEqual(verdict["code"], "local_dns_broken")
        self.assertNotIn("Pi-hole", verdict["title"])

    def test_remote_resolver_forces_generic_without_detection(self):
        cfg = {
            "mode": "enabled",
            "address": "192.168.1.53",
            "provider": "pihole",
        }
        with mock.patch.dict(self.linkmoth.CFG, {"local_dns": cfg}):
            with mock.patch.object(
                self.linkmoth, "local_dns_is_same_host", return_value=False
            ):
                with mock.patch.object(
                    self.linkmoth, "_active_local_dns_adapters"
                ) as detect:
                    info = self.linkmoth.local_dns_runtime_info()
        detect.assert_not_called()
        self.assertFalse(info["same_host"])
        self.assertEqual(info["effective_provider"], "generic")
        self.assertIsNone(info["provider_name"])

    def test_remote_ladder_uses_dns_query_only_and_generic_output(self):
        cfg = {
            "mode": "enabled",
            "address": "192.168.1.53",
            "provider": "pihole",
        }
        with mock.patch.dict(self.linkmoth.CFG, {"local_dns": cfg}):
            with mock.patch.object(
                self.linkmoth, "default_route",
                return_value=("192.168.1.1", "eth0"),
            ):
                with mock.patch.object(
                    self.linkmoth, "check_power", return_value=(True, "ok")
                ), mock.patch.object(
                    self.linkmoth, "check_link", return_value=(True, "ok")
                ), mock.patch.object(
                    self.linkmoth, "check_router_wlan",
                    return_value=(None, "skipped"),
                ), mock.patch.object(
                    self.linkmoth, "ping", return_value=(True, "ok", 1.0)
                ), mock.patch.object(
                    self.linkmoth, "http_get", return_value=(True, "ok", 1.0)
                ), mock.patch.object(
                    self.linkmoth, "local_dns_is_same_host", return_value=False
                ), mock.patch.object(
                    self.linkmoth, "_active_local_dns_adapters"
                ) as detect, mock.patch.object(
                    self.linkmoth, "micro_local_dns"
                ) as micro, mock.patch.object(
                    self.linkmoth, "dig", return_value=(False, "no answer", None)
                ) as dig:
                    checks, _ = self.linkmoth.run_ladder()
        local = next(check for check in checks if check["id"] == "local_dns")
        self.assertEqual(local["provider"], "generic")
        self.assertNotIn("Pi-hole", local["detail"])
        self.assertIn(
            mock.call("192.168.1.53", self.linkmoth.CFG["dns_test_domain"]),
            dig.call_args_list,
        )
        detect.assert_not_called()
        micro.assert_not_called()

    def test_auto_detection_requires_exactly_one_active_adapter(self):
        cfg = {
            "mode": "auto",
            "address": "127.0.0.1",
            "provider": "auto",
        }
        with mock.patch.dict(self.linkmoth.CFG, {"local_dns": cfg}):
            with mock.patch.object(
                self.linkmoth, "local_dns_is_same_host", return_value=True
            ):
                with mock.patch.object(
                    self.linkmoth,
                    "_active_local_dns_adapters",
                    return_value=["unbound"],
                ):
                    one = self.linkmoth.local_dns_runtime_info()
                with mock.patch.object(
                    self.linkmoth,
                    "_active_local_dns_adapters",
                    return_value=["pihole", "unbound"],
                ):
                    ambiguous = self.linkmoth.local_dns_runtime_info()
        self.assertEqual(one["effective_provider"], "unbound")
        self.assertTrue(one["provider_detected"])
        self.assertEqual(ambiguous["effective_provider"], "generic")

    def test_provider_does_not_change_verdict_identity(self):
        generic = self.linkmoth.verdict(self._checks("generic"))
        pihole = self.linkmoth.verdict(self._checks("pihole"))
        unbound = self.linkmoth.verdict(self._checks("unbound"))
        dnsmasq = self.linkmoth.verdict(self._checks("dnsmasq"))
        for result in (pihole, unbound, dnsmasq):
            self.assertEqual(result["code"], generic["code"])
            self.assertEqual(result["title"], generic["title"])

    def test_generic_verdict_has_no_product_wording(self):
        result = self.linkmoth.verdict(self._checks("generic"))
        text = " ".join(
            str(result.get(key) or "")
            for key in ("title", "explain", "hint")
        ).lower()
        self.assertNotIn("pi-hole", text)
        self.assertNotIn("unbound", text)
        self.assertNotIn("dnsmasq", text)

    def test_supported_adapters_use_their_own_service(self):
        for provider, service in (
            ("pihole", "pihole-FTL"),
            ("unbound", "unbound"),
            ("dnsmasq", "dnsmasq"),
        ):
            with self.subTest(provider=provider):
                with mock.patch.object(
                    self.linkmoth,
                    "run_cmd",
                    side_effect=[
                        (0, "loaded"), (0, "active"), (0, "running"),
                    ],
                ) as run:
                    with mock.patch.object(
                        self.linkmoth,
                        "check_disk_pressure",
                        return_value=(True, "disk ok"),
                    ):
                        steps = self.linkmoth.micro_local_dns(provider)
                self.assertTrue(steps[0]["ok"])
                self.assertEqual(run.call_args_list[0].args[0][-1], service)


class PowerSupplyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_power_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")

    def test_poe_offline_fails(self):
        supply = Path("/fake/usb-pd")
        files = {
            supply / "type": "USB",
            supply / "online": "0",
            supply / "status": "Discharging",
        }
        with mock.patch.object(Path, "is_dir", return_value=True):
            with mock.patch.object(Path, "iterdir", return_value=[supply]):
                with mock.patch.object(
                    self.linkmoth,
                    "_read_power_supply_file",
                    side_effect=lambda p: files.get(p),
                ):
                    with mock.patch.object(self.linkmoth, "run_cmd", return_value=(0, "throttled=0x0")):
                        ok, detail = self.linkmoth.check_power()
        self.assertFalse(ok)
        self.assertIn("offline", detail)

    def test_poe_online_appends_detail(self):
        supply = Path("/fake/usb-pd")
        files = {
            supply / "type": "USB",
            supply / "online": "1",
            supply / "status": "Charging",
            supply / "voltage_now": "5100000",
        }
        with mock.patch.object(Path, "is_dir", return_value=True):
            with mock.patch.object(Path, "iterdir", return_value=[supply]):
                with mock.patch.object(
                    self.linkmoth,
                    "_read_power_supply_file",
                    side_effect=lambda p: files.get(p),
                ):
                    with mock.patch.object(self.linkmoth, "run_cmd", return_value=(0, "throttled=0x0")):
                        ok, detail = self.linkmoth.check_power()
        self.assertTrue(ok)
        self.assertIn("5.1V", detail)


if __name__ == "__main__":
    unittest.main()

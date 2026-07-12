#!/usr/bin/env python3
"""Tests for classify_network_interfaces/bind_exposure_risk — the check that
warns when binding to 0.0.0.0 would expose Linkmoth beyond the LAN over a
VPN/tunnel or container-bridge interface."""
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

SAMPLE_IP_OUTPUT = (
    '1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n'
    '2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\\       valid_lft forever preferred_lft forever\n'
    '3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever\n'
    '4: br-abc123def456    inet 172.18.0.1/16 scope global br-abc123def456\\       valid_lft forever preferred_lft forever\n'
    '5: wg0    inet 10.8.0.2/24 scope global wg0\\       valid_lft forever preferred_lft forever\n'
    '6: tailscale0    inet 100.101.102.103/32 scope global tailscale0\\       valid_lft forever preferred_lft forever\n'
    '7: nordlynx    inet 10.5.0.2/32 scope global nordlynx\\       valid_lft forever preferred_lft forever\n'
    '8: eth0.100@eth0    inet 192.168.100.1/24 scope global eth0.100\\       valid_lft forever preferred_lft forever\n'
)


class BindExposureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_bindexp_")
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")

    def _classify(self):
        return self.linkmoth.classify_network_interfaces(SAMPLE_IP_OUTPUT)

    def test_loopback_classified(self):
        by_iface = {i["iface"]: i for i in self._classify()}
        self.assertEqual(by_iface["lo"]["kind"], "loopback")

    def test_plain_lan_interface_classified(self):
        by_iface = {i["iface"]: i for i in self._classify()}
        self.assertEqual(by_iface["eth0"]["kind"], "lan")
        self.assertEqual(by_iface["eth0"]["address"], "192.168.1.10")

    def test_vlan_subinterface_strips_at_suffix(self):
        by_iface = {i["iface"]: i for i in self._classify()}
        self.assertIn("eth0.100", by_iface)
        self.assertEqual(by_iface["eth0.100"]["kind"], "lan")

    def test_docker_and_custom_bridge_classified_as_container(self):
        by_iface = {i["iface"]: i for i in self._classify()}
        self.assertEqual(by_iface["docker0"]["kind"], "container")
        self.assertEqual(by_iface["br-abc123def456"]["kind"], "container")

    def test_vpn_interfaces_classified_as_tunnel(self):
        by_iface = {i["iface"]: i for i in self._classify()}
        for iface in ("wg0", "tailscale0", "nordlynx"):
            self.assertEqual(by_iface[iface]["kind"], "tunnel", iface)

    def test_specific_bind_address_has_no_exposure_risk(self):
        # A narrow bind only ever exposes that one address, regardless of
        # what other interfaces exist on the host.
        risk = self.linkmoth.bind_exposure_risk("192.168.1.10", self._classify())
        self.assertEqual(risk, [])

    def test_wildcard_bind_flags_tunnel_and_container_interfaces(self):
        risk = self.linkmoth.bind_exposure_risk("0.0.0.0", self._classify())
        kinds = {i["kind"] for i in risk}
        ifaces = {i["iface"] for i in risk}
        self.assertEqual(kinds, {"tunnel", "container"})
        self.assertIn("wg0", ifaces)
        self.assertIn("tailscale0", ifaces)
        self.assertIn("nordlynx", ifaces)
        self.assertIn("docker0", ifaces)
        self.assertNotIn("eth0", ifaces)
        self.assertNotIn("lo", ifaces)

    def test_wildcard_bind_with_only_lan_interfaces_has_no_risk(self):
        lan_only = (
            '1: lo    inet 127.0.0.1/8 scope host lo\n'
            '2: eth0    inet 192.168.1.10/24 scope global eth0\n'
        )
        interfaces = self.linkmoth.classify_network_interfaces(lan_only)
        risk = self.linkmoth.bind_exposure_risk("0.0.0.0", interfaces)
        self.assertEqual(risk, [])

    def test_ipv6_wildcard_bind_also_checked(self):
        risk = self.linkmoth.bind_exposure_risk("::", self._classify())
        self.assertTrue(any(i["iface"] == "wg0" for i in risk))


if __name__ == "__main__":
    unittest.main()

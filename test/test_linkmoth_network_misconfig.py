#!/usr/bin/env python3
"""Tests for network_misconfig_warnings: naming local foot-guns that would
otherwise be misread as a network fault.

The whole pitch of Linkmoth is saying who is at fault. Two interfaces sharing
an address, or no default route, produce symptoms identical to a router or WAN
outage – so a diagnostic tool that blamed the router for them would be wrong
in the most on-brand way possible. These must fire on the real foot-guns and
stay completely silent on healthy hosts, or they become noise.
"""
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent))

import linkmoth_probes  # noqa: E402  (pure function under test; no DB, no app graph)

DUP = (
    "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n"
    "3: wlan0    inet 192.168.1.10/24 brd 192.168.1.255 scope global wlan0"
)
TWO_DEFAULTS = (
    "default via 192.168.1.1 dev eth0 proto static metric 100\n"
    "default via 192.168.1.1 dev wlan0 proto static metric 600"
)
HEALTHY_ADDR = "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0"
HEALTHY_ROUTE = "default via 192.168.1.1 dev eth0 proto dhcp metric 100"


class NetworkMisconfigTests(unittest.TestCase):
    # network_misconfig_warnings is a pure function over the strings these
    # tests inject: it never opens the database, so there is nothing to set up
    # and no reason to reload the app graph (doing so desynced module state for
    # other tests). Just start each test from a cold cache.
    def setUp(self):
        self.probes = linkmoth_probes
        self.probes._NETWORK_NOTES_CACHE["expires"] = 0.0
        self.probes._NETWORK_NOTES_CACHE["warnings"] = []

    def _warn(self, addr, route, route_ok=True):
        return {w["code"]: w for w in self.probes.network_misconfig_warnings(
            addr, route, route_ok=route_ok, use_cache=False)}

    # ---- the real foot-guns -------------------------------------------------
    def test_duplicate_address_is_named_as_a_bad_issue(self):
        """The exact case that reads as an intermittent router fault."""
        codes = self._warn(DUP, TWO_DEFAULTS)
        self.assertIn("duplicate_address", codes)
        note = codes["duplicate_address"]
        self.assertEqual(note["level"], "bad")
        self.assertIn("192.168.1.10", note["detail"])
        self.assertIn("eth0", note["detail"])
        self.assertIn("wlan0", note["detail"])

    def test_duplicate_address_does_not_also_pile_on_the_route_warning(self):
        """Same root cause named once: the two default routes are a symptom of
        the duplicate, so only the headline issue is shown."""
        codes = self._warn(DUP, TWO_DEFAULTS)
        self.assertIn("duplicate_address", codes)
        self.assertNotIn("multiple_default_routes", codes)

    def test_different_addresses_on_one_subnet_warn_more_softly(self):
        addr = (
            "2: eth0    inet 192.168.1.10/24 scope global eth0\n"
            "3: wlan0    inet 192.168.1.11/24 scope global wlan0"
        )
        codes = self._warn(addr, HEALTHY_ROUTE)
        self.assertIn("overlapping_subnet", codes)
        self.assertEqual(codes["overlapping_subnet"]["level"], "warn")
        self.assertNotIn("duplicate_address", codes)

    def test_no_default_route_is_flagged_instead_of_looking_like_an_outage(self):
        codes = self._warn(HEALTHY_ADDR, "")
        self.assertIn("no_default_route", codes)
        self.assertEqual(codes["no_default_route"]["level"], "bad")

    def test_multiple_default_routes_without_an_address_clash_still_warn(self):
        """Two default routes on genuinely different subnets is still an
        asymmetric-routing risk, and no addressing warning suppresses it."""
        addr = (
            "2: eth0    inet 192.168.1.10/24 scope global eth0\n"
            "3: wwan0    inet 10.20.0.5/24 scope global wwan0"
        )
        route = (
            "default via 192.168.1.1 dev eth0 metric 100\n"
            "default via 10.20.0.1 dev wwan0 metric 200"
        )
        codes = self._warn(addr, route)
        self.assertIn("multiple_default_routes", codes)
        self.assertEqual(codes["multiple_default_routes"]["level"], "warn")

    # ---- must stay silent (false positives are worse than nothing) ---------
    def test_a_healthy_wired_host_is_silent(self):
        self.assertEqual(self._warn(HEALTHY_ADDR, HEALTHY_ROUTE), {})

    def test_docker_and_tailscale_alongside_the_lan_are_silent(self):
        """Extra interfaces on their own subnets are normal and must not warn."""
        addr = (
            "2: eth0    inet 192.168.1.10/24 scope global eth0\n"
            "3: docker0    inet 172.17.0.1/16 scope global docker0\n"
            "4: tailscale0    inet 100.101.102.103/32 scope global tailscale0"
        )
        self.assertEqual(self._warn(addr, HEALTHY_ROUTE), {})

    def test_a_failed_route_command_does_not_claim_no_route(self):
        """If `ip route` fails we cannot tell, so we must not invent a
        no-default-route warning."""
        codes = self._warn(HEALTHY_ADDR, "", route_ok=False)
        self.assertNotIn("no_default_route", codes)

    def test_loopback_is_never_treated_as_a_duplicate(self):
        addr = (
            "1: lo    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0    inet 192.168.1.10/24 scope global eth0"
        )
        self.assertEqual(self._warn(addr, HEALTHY_ROUTE), {})

    # ---- robustness ---------------------------------------------------------
    def test_garbage_address_output_yields_no_warnings_and_does_not_raise(self):
        # route_ok=False so the route side stays quiet and this isolates
        # address parsing; unparseable address lines must simply yield nothing.
        for junk in ("", "not ip output at all", "2: eth0 inet notanip/24"):
            self.assertEqual(
                self.probes.network_misconfig_warnings(
                    junk, "", route_ok=False, use_cache=False), [])

    def test_result_is_cached_for_repeated_status_polls(self):
        spawned = []
        real = self.probes.run_cmd

        def counting(args, **kwargs):
            spawned.append(args[0])
            return real(args, **kwargs)

        import unittest.mock as mock
        with mock.patch.object(self.probes, "run_cmd", counting):
            for _ in range(6):
                self.probes.network_misconfig_warnings()  # cache on
        # Two ip calls for the first computation, then served from cache.
        self.assertLessEqual(spawned.count("ip"), 2)


if __name__ == "__main__":
    unittest.main()

"""Linkmoth network-check/diagnostic layer: ping, DNS, HTTP, wifi/power/link
probes, the fault ladder, verdicts, confidence scoring, the ISP report, and
bufferbloat/throughput sampling.

Self-contained: stdlib plus read-only access to linkmoth_core's CFG. Called
by linkmoth_engine.py and linkmoth.py's CLI, never calls back into either.
"""
import ipaddress
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import struct
import sys
import threading
import time
from pathlib import Path
from urllib import request as urlrequest
from urllib.parse import urlparse

from linkmoth_core import (
    CFG, DEFAULT_CONFIG, _PinnedHTTPSConnection, _dns_domain,
    _incident_outage_segments, _network_targets, _outage_seconds, db,
    normalize_local_dns_config, run_cmd,
)

def default_route():
    rc, out = run_cmd(["ip", "route", "show", "default"])
    if rc != 0 or not out:
        return None, None
    m = re.search(r"default via (\S+) dev (\S+)", out)
    return (m.group(1), m.group(2)) if m else (None, None)


def check_power():
    supply_ok, supply_detail, supply_bad = _read_power_supplies()
    rc, out = run_cmd(["vcgencmd", "get_throttled"])
    throttle_ok = None
    throttle_detail = ""
    if rc == 0:
        try:
            flags = int(out.split("=")[1], 16)
        except (IndexError, ValueError):
            throttle_ok = None
            throttle_detail = out
        else:
            now_bits = []
            if flags & 0x1:
                now_bits.append("undervoltage now")
            if flags & 0x4:
                now_bits.append("throttled now")
            past = flags & 0x50000
            if now_bits:
                throttle_ok = False
                throttle_detail = ", ".join(now_bits)
            elif past:
                throttle_ok = True
                throttle_detail = "ok now (undervoltage/throttling happened since boot)"
            else:
                throttle_ok = True
                throttle_detail = "Host power healthy"
    if throttle_ok is None:
        for name_file in Path("/sys/class/hwmon").glob("hwmon*/name"):
            try:
                if name_file.read_text().strip() != "rpi_volt":
                    continue
                alarm = (name_file.parent / "in0_lcrit_alarm").read_text().strip()
                if alarm == "1":
                    throttle_ok = False
                    throttle_detail = "undervoltage now (hwmon)"
                else:
                    throttle_ok = True
                    throttle_detail = "Host power healthy"
                break
            except OSError:
                continue
        if throttle_ok is None:
            throttle_ok = None
            throttle_detail = "no power sensor available"

    parts = [p for p in (throttle_detail, supply_detail) if p]
    detail = " · ".join(parts) if parts else "no power sensor available"

    if throttle_ok is False or supply_bad:
        return False, detail
    if throttle_ok is None and supply_ok is None:
        return None, detail
    if supply_ok is False:
        return False, detail
    return True, detail


def _read_power_supply_file(path):
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _read_power_supplies():
    """Read /sys/class/power_supply for PoE/USB-PD telemetry."""
    root = Path("/sys/class/power_supply")
    if not root.is_dir():
        return None, "", False
    notes = []
    any_online = False
    any_bad = False
    for supply in sorted(root.iterdir()):
        if not supply.is_dir():
            continue
        ptype = (_read_power_supply_file(supply / "type") or "").lower()
        if ptype == "battery":
            continue
        name = supply.name
        online_s = _read_power_supply_file(supply / "online")
        status = _read_power_supply_file(supply / "status") or ""
        if online_s == "0":
            any_bad = True
            notes.append(f"{name} offline")
            continue
        if online_s == "1":
            any_online = True
        status_l = status.lower()
        if status_l in ("discharging", "not charging", "unknown") and ptype in (
            "mains", "usb", "usb_hvdcp", "usb_pd", "usb_c", "ups",
        ):
            any_bad = True
            notes.append(f"{name} {status}")
        volt_note = ""
        volt_raw = _read_power_supply_file(supply / "voltage_now")
        if volt_raw and volt_raw.lstrip("-").isdigit():
            volts = int(volt_raw) / 1_000_000.0
            volt_note = f"{volts:.1f}V"
            if 0 < volts < 4.5 and ptype in ("usb", "usb_hvdcp", "usb_pd", "usb_c", "mains"):
                any_bad = True
                notes.append(f"{name} low {volt_note}")
        if not any_bad and (online_s == "1" or status_l == "charging"):
            label = ptype or name
            notes.append(f"{label} online" + (f" {volt_note}" if volt_note else ""))
    if not notes:
        return None, "", False
    if any_bad:
        return False, " · ".join(notes), True
    if any_online:
        return True, " · ".join(notes), False
    return None, " · ".join(notes), False


def check_link(dev):
    if not dev:
        return False, "no default route"
    try:
        carrier = (Path(f"/sys/class/net/{dev}/carrier").read_text().strip() == "1")
    except OSError:
        carrier = False
    if not carrier:
        return False, f"{dev}: no carrier"
    detail = f"{dev}: link up"
    warn = False
    if dev.startswith("wl"):
        try:
            for line in Path("/proc/net/wireless").read_text().splitlines():
                if line.strip().startswith(dev):
                    sig = float(line.split()[3].rstrip("."))
                    detail = f"{dev}: signal {sig:.0f} dBm"
                    if sig < -80:
                        return False, detail + " (very weak)"
        except (OSError, ValueError, IndexError):
            pass
    else:
        speed, duplex = _read_link_speed_duplex(dev)
        if speed is not None and speed > 0:
            detail = f"{dev}: link up, {speed} Mb/s"
            if speed < 1000:
                warn = True
        if duplex == "half":
            warn = True
        if warn:
            if speed is not None and 0 < speed < 1000:
                detail = f"⚠️ {dev}: link up, downgraded to {speed} Mb/s"
            elif duplex == "half":
                base = f"{speed} Mb/s" if speed and speed > 0 else "link up"
                detail = f"⚠️ {dev}: {base}, half-duplex"
            else:
                detail = f"⚠️ {detail}"
    return True, detail


def _read_link_speed_duplex(dev):
    speed = None
    duplex = None
    try:
        speed_s = Path(f"/sys/class/net/{dev}/speed").read_text().strip()
        if speed_s.lstrip("-").isdigit():
            val = int(speed_s)
            if val > 0:
                speed = val
    except OSError:
        pass
    try:
        duplex_s = Path(f"/sys/class/net/{dev}/duplex").read_text().strip().lower()
        if duplex_s in ("full", "half"):
            duplex = duplex_s
    except OSError:
        pass
    if speed is not None and duplex is not None:
        return speed, duplex
    ethtool_speed, ethtool_duplex = _ethtool_link(dev)
    return speed if speed is not None else ethtool_speed, duplex if duplex is not None else ethtool_duplex


def _ethtool_link(dev):
    rc, out = run_cmd(["ethtool", dev])
    if rc != 0 or not out:
        return None, None
    speed = None
    duplex = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Speed:"):
            m = re.search(r"(\d+)\s*Mb/s", line, re.I)
            if m:
                speed = int(m.group(1))
        elif line.startswith("Duplex:"):
            if "full" in line.lower():
                duplex = "full"
            elif "half" in line.lower():
                duplex = "half"
    return speed, duplex


def check_router_wlan(gateway_ok, include_evidence=False):
    """Use configured Wi-Fi clients as witnesses, not as monitored devices.

    A single reply proves that at least one radio/path is working.  Silent
    clients are kept as disagreement evidence because phones sleep and many
    operating systems block ping; they must not be presented as proof that a
    radio has crashed.
    """
    clients = CFG.get("target_wifi_clients") or []
    if not clients:
        result = (None, "not configured")
        return (*result, {}) if include_evidence else result
    if not gateway_ok:
        result = (None, "router LAN unreachable — skipped")
        return (*result, {}) if include_evidence else result
    ok, detail, _ms, evidence = probe_group([
        (client, ping(client, count=2, timeout=1)) for client in clients
    ])
    passed = evidence["probe_summary"]["passed"]
    attempted = evidence["probe_summary"]["attempted"]
    if ok:
        detail = f"{passed}/{attempted} configured Wi-Fi witnesses replied · {detail}"
    else:
        detail = (
            f"No configured Wi-Fi witness replied ({attempted} tried). "
            "This suggests a Wi-Fi problem, but sleeping clients or blocked "
            "ping can look the same."
        )
    result = (ok, detail)
    return (*result, evidence) if include_evidence else result


def wifi_wired_differential(checks):
    """One plain-language sentence when Wi-Fi witnesses disagree with a
    healthy wired path — "it's your Wi-Fi, not your provider" — or None
    when there is nothing defensible to say. Pure over one run's checks."""
    by_id = {ch["id"]: ch for ch in normalize_stored_checks(checks)}
    wlan = by_id.get("router_wlan")
    gateway = by_id.get("gateway")
    internet = by_id.get("raw_ping") or by_id.get("https")
    if not wlan or not gateway or not internet:
        return None
    if gateway.get("ok") is not True or internet.get("ok") is not True:
        return None
    if wlan.get("ok") is False:
        return (
            "The wired path and the internet look healthy while no Wi-Fi"
            " witness replied — this points at Wi-Fi (radio, access point,"
            " or sleeping witnesses), not your provider."
        )
    wlan_ms = wlan.get("ms")
    gateway_ms = gateway.get("ms")
    if (wlan.get("ok") is True and wlan_ms is not None
            and gateway_ms is not None and gateway_ms > 0
            and wlan_ms >= 100 and wlan_ms >= 10 * gateway_ms):
        return (
            f"Wi-Fi witnesses reply far slower than the wired router path"
            f" ({round(wlan_ms)} ms vs {round(gateway_ms)} ms) — that gap"
            f" is on the radio side, not your provider."
        )
    return None


def ping(host, count=3, timeout=2):
    try:
        _network_targets([host])
    except ValueError:
        return False, "invalid ping target", None
    rc, out = run_cmd(
        ["ping", "-c", str(count), "-W", str(timeout), "-i", "0.3", "--", host],
        timeout=count * (timeout + 1) + 3,
    )
    if rc != 0:
        return False, f"{host}: no reply", None
    stats = parse_ping_stats(out)
    avg_ms = stats["avg_ms"]
    avg = f"{avg_ms:.0f} ms" if avg_ms is not None else "?"
    loss_s = f"{stats['loss_pct']:.0f}% loss" if stats["loss_pct"] else ""
    return True, f"{host}: {avg} {loss_s}".strip(), avg_ms


def parse_ping_stats(out):
    """Extract latency and loss from `ping -c` output.

    Returns min/avg/max/jitter in milliseconds (jitter = mdev, the round-trip
    deviation) and packet loss as a percentage; any field absent from the
    output comes back as None. Pure text parsing so it is easy to test.
    """
    stats = {
        "sent": None, "received": None, "loss_pct": None,
        "min_ms": None, "avg_ms": None, "max_ms": None, "jitter_ms": None,
    }
    counts = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out)
    if counts:
        stats["sent"] = int(counts.group(1))
        stats["received"] = int(counts.group(2))
    loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    if loss:
        stats["loss_pct"] = float(loss.group(1))
    rtt = re.search(
        r"=\s*([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))?\s*ms", out)
    if rtt:
        stats["min_ms"] = float(rtt.group(1))
        stats["avg_ms"] = float(rtt.group(2))
        stats["max_ms"] = float(rtt.group(3))
        if rtt.group(4) is not None:
            stats["jitter_ms"] = float(rtt.group(4))
    return stats


def measure_quality(targets, count=10, timeout=2):
    """Ping each target `count` times and return the best path's quality.

    Uses the lowest-loss / lowest-latency responding target as the
    representative sample (a single distant server should not, on its own, make
    the local connection look bad). Returns {latency_ms, jitter_ms, loss_pct,
    target} or None when nothing answered.
    """
    best = None
    for target in targets:
        try:
            _network_targets([target])
        except ValueError:
            continue
        rc, out = run_cmd(
            ["ping", "-c", str(count), "-W", str(timeout), "-i", "0.3", "--", target],
            timeout=count * (timeout + 1) + 5,
        )
        if rc != 0:
            continue
        s = parse_ping_stats(out)
        if s["avg_ms"] is None:
            continue
        sample = {
            "latency_ms": s["avg_ms"],
            "jitter_ms": s["jitter_ms"],
            "loss_pct": s["loss_pct"] if s["loss_pct"] is not None else 0.0,
            "target": str(target),
        }
        key = (sample["loss_pct"], sample["latency_ms"])
        if best is None or key < (best["loss_pct"], best["latency_ms"]):
            best = sample
    return best


def classify_quality(latency_ms, jitter_ms, loss_pct, qcfg):
    """Grade a quality sample as good/fair/poor with human reasons. Pure."""
    order = {"good": 0, "fair": 1, "poor": 2}
    state = "good"
    reasons = []

    def worse(level, why):
        nonlocal state
        if order[level] > order[state]:
            state = level
        reasons.append(why)

    if loss_pct is not None:
        if loss_pct >= qcfg["loss_bad_pct"]:
            worse("poor", f"{loss_pct:.0f}% packet loss")
        elif loss_pct >= qcfg["loss_warn_pct"]:
            worse("fair", f"{loss_pct:.0f}% packet loss")
    if latency_ms is not None:
        if latency_ms >= qcfg["latency_bad_ms"]:
            worse("poor", f"high latency {latency_ms:.0f} ms")
        elif latency_ms >= qcfg["latency_warn_ms"]:
            worse("fair", f"elevated latency {latency_ms:.0f} ms")
    if jitter_ms is not None:
        if jitter_ms >= qcfg["jitter_bad_ms"]:
            worse("poor", f"high jitter {jitter_ms:.0f} ms")
        elif jitter_ms >= qcfg["jitter_warn_ms"]:
            worse("fair", f"jitter {jitter_ms:.0f} ms")
    if latency_ms is None and jitter_ms is None and loss_pct is None:
        return {"state": "unknown", "reasons": ["no measurement"]}
    return {"state": state, "reasons": reasons}


def quality_config():
    """Quality settings merged over defaults (config.json may set a subset)."""
    merged = dict(DEFAULT_CONFIG["quality"])
    q = CFG.get("quality")
    if isinstance(q, dict):
        merged.update(q)
    return merged


def _dns_query_a(server, domain, timeout=2.0):
    """Stdlib UDP DNS A-record query. Returns True if the server answered.

    Uses a connected socket so the kernel drops any datagram not from
    server:53, and validates the transaction id + QR bit, so stray LAN UDP
    traffic (broadcast/multicast) can never be mistaken for a DNS answer.
    Only a yes/no is needed, not the resolved address.
    """
    labels = [l for l in domain.split(".") if l]
    if not labels or any(len(l) > 63 for l in labels):
        return False
    txn = secrets.token_bytes(2)
    header = txn + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0)  # RD set, QDCOUNT=1
    try:
        qname = b"".join(
            struct.pack("B", len(l)) + l.encode("ascii") for l in labels
        ) + b"\x00"
    except (UnicodeEncodeError, struct.error):
        return False
    query = header + qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.connect((server, 53))
        sock.send(query)
        resp = sock.recv(512)
    except (socket.timeout, OSError):
        return False
    finally:
        sock.close()
    if len(resp) < 12 or resp[0:2] != txn:
        return False
    flags_hi, flags_lo = resp[2], resp[3]
    if not (flags_hi & 0x80):        # QR bit — must be a response, not an echo
        return False
    if (flags_lo & 0x0F) != 0:       # RCODE — must be no-error
        return False
    ancount = struct.unpack(">H", resp[6:8])[0]
    truncated = bool(flags_hi & 0x02)  # TC — server answered, just over UDP size
    return ancount >= 1 or truncated


def _ms_text(ms):
    """Human-readable latency. Sub-millisecond timings round to 0 with a plain
    '{:.0f} ms' format, which reads as an impossible '0 ms'; show '<1 ms'."""
    return "<1 ms" if ms < 0.5 else f"{ms:.0f} ms"


def dig(server, domain):
    try:
        ipaddress.ip_address(server)
        domain = _dns_domain(domain)
    except ValueError:
        return False, "invalid DNS target", None
    start = time.monotonic()
    answered = _dns_query_a(server, domain)
    ms = (time.monotonic() - start) * 1000
    if answered:
        return True, f"Resolver at {server}: answered in {_ms_text(ms)}", ms
    return False, f"Resolver at {server}: no answer", None


def http_get(url, timeout=5):
    start = time.monotonic()
    try:
        parsed = urlparse(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return False, "invalid HTTPS target", None
        target = _https_probe_label(url)
        req = urlrequest.Request(url, headers={"User-Agent": "linkmoth/1.0"})
        class NoRedirect(urlrequest.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urlrequest.build_opener(
            urlrequest.ProxyHandler({}),
            NoRedirect(),
        )
        with opener.open(req, timeout=timeout) as r:
            ms = (time.monotonic() - start) * 1000
            return True, f"{target}: HTTP {r.status} in {_ms_text(ms)}", ms
    except Exception as e:
        return False, f"{_https_probe_label(url)}: {e.__class__.__name__}", None


def any_ok(triples):
    ok = any(t[0] for t in triples)
    ms_values = [t[2] for t in triples if t[0] and t[2] is not None]
    return ok, "; ".join(t[1] for t in triples), (min(ms_values) if ms_values else None)


def probe_group(named_triples):
    """Summarize redundant probes without throwing away disagreements.

    The rung's traditional ``ok`` value remains true when any target answers,
    preserving fault attribution.  ``state`` and ``probes`` retain whether all
    targets agreed, so operators can distinguish a healthy redundant check
    from one surviving target masking another failed target.
    """
    results = list(named_triples)
    probes = []
    ms_values = []
    for target, result in results:
        ok, detail, ms = result
        if ok and ms is not None:
            ms_values.append(ms)
        probes.append({
            "target": str(target)[:253],
            "ok": bool(ok),
            "detail": str(detail)[:500],
            "ms": round(ms, 1) if ms is not None else None,
        })
    attempted = len(probes)
    passed = sum(1 for probe in probes if probe["ok"])
    failed = attempted - passed
    if passed == 0:
        state = "failed"
    elif failed:
        state = "partial"
    else:
        state = "passed"
    evidence = {
        "state": state,
        "probe_summary": {
            "attempted": attempted,
            "passed": passed,
            "failed": failed,
        },
        "probes": probes,
    }
    detail = "; ".join(probe["detail"] for probe in probes if probe["detail"])
    return passed > 0, detail, (min(ms_values) if ms_values else None), evidence


def _https_probe_label(url):
    """Return a credential-free label for configured HTTPS evidence."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or "HTTPS target"
        port = parsed.port
    except (TypeError, ValueError):
        return "HTTPS target"
    return f"{host}:{port}" if port not in (None, 443) else host


def _micro_step(label, ok, detail):
    return {"label": label, "ok": ok, "detail": detail}


def check_disk_pressure(path="/"):
    try:
        usage = shutil.disk_usage(path)
    except OSError as exc:
        return None, f"disk check unavailable: {exc}"
    if usage.total <= 0:
        return None, "disk size unknown"
    pct = usage.used * 100.0 / usage.total
    if usage.free <= 0 or pct >= 99.9:
        return False, f"disk {pct:.0f}% full on {path}"
    return True, f"disk {pct:.0f}% used on {path}"


LOCAL_DNS_ADAPTERS = {
    "pihole": {
        "name": "Pi-hole",
        "service": "pihole-FTL",
    },
    "unbound": {
        "name": "Unbound",
        "service": "unbound",
    },
    "dnsmasq": {
        "name": "dnsmasq",
        "service": "dnsmasq",
    },
}
_LOCAL_DNS_DETECT_LOCK = threading.Lock()
_LOCAL_DNS_DETECT_CACHE = {"expires": 0.0, "active": []}


def _local_ipv4_addresses():
    addresses = {"127.0.0.1"}
    try:
        for info in socket.getaddrinfo(
            socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM
        ):
            addresses.add(info[4][0])
    except OSError:
        pass
    rc, out = run_cmd(["ip", "-o", "-4", "addr", "show"])
    if rc == 0:
        for match in re.finditer(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", out):
            addresses.add(match.group(1))
    return addresses


# Interface name prefixes for non-LAN network kinds. Checked in order — a
# tunnel/VPN interface is the higher-severity case (typically routable from a
# remote network over the internet); a container bridge is host-local and
# lower severity. Anything not matched is treated as a normal LAN interface.
# NordVPN's WireGuard interface is named "nordlynx"; most other VPN clients
# use "tun"/"tap"/"wg"/"ppp"/"ipsec"/"utun" by convention.
_TUNNEL_IFACE_PREFIXES = (
    "tun", "tap", "wg", "tailscale", "zt", "ppp", "nordlynx", "wgcf", "ipsec", "utun",
)
_CONTAINER_IFACE_PREFIXES = ("docker", "br-", "veth", "podman", "virbr", "cni", "flannel", "cali")


def _classify_iface(iface, address):
    try:
        if ipaddress.IPv4Address(address).is_loopback or iface == "lo":
            return "loopback"
    except ipaddress.AddressValueError:
        pass
    lowered = iface.lower()
    if lowered.startswith(_TUNNEL_IFACE_PREFIXES):
        return "tunnel"
    if lowered.startswith(_CONTAINER_IFACE_PREFIXES):
        return "container"
    return "lan"


def classify_network_interfaces(raw_output=None):
    """List (iface, address, kind) for every IPv4 address on the host.

    kind is one of "lan", "tunnel", "container", "loopback". Used to warn
    when binding to 0.0.0.0 would expose Linkmoth beyond the LAN — e.g. over
    an active WireGuard/Tailscale/NordVPN interface, which is not something
    Linkmoth can otherwise see or rule out.
    """
    if raw_output is None:
        rc, raw_output = run_cmd(["ip", "-o", "-4", "addr", "show"])
        if rc != 0:
            return []
    results = []
    for match in re.finditer(
        r"^\d+:\s+(\S+?)(?:@\S+)?\s+inet\s+(\d+\.\d+\.\d+\.\d+)/",
        raw_output, re.MULTILINE,
    ):
        iface, address = match.group(1), match.group(2)
        results.append({
            "iface": iface, "address": address,
            "kind": _classify_iface(iface, address),
        })
    return results


def bind_exposure_risk(bind_addr, interfaces=None):
    """Return the list of non-LAN interfaces exposed by the given bind
    address, or [] if the bind is already narrow enough to avoid them."""
    if bind_addr not in ("0.0.0.0", "::"):
        return []  # a specific address only ever exposes that one interface
    if interfaces is None:
        interfaces = classify_network_interfaces()
    return [i for i in interfaces if i["kind"] in ("tunnel", "container")]


def local_dns_is_same_host(address):
    try:
        parsed = ipaddress.IPv4Address(address)
    except ipaddress.AddressValueError:
        return False
    return parsed.is_loopback or str(parsed) in _local_ipv4_addresses()


def _active_local_dns_adapters(refresh=False):
    now = time.monotonic()
    with _LOCAL_DNS_DETECT_LOCK:
        if not refresh and now < _LOCAL_DNS_DETECT_CACHE["expires"]:
            return list(_LOCAL_DNS_DETECT_CACHE["active"])
        active = []
        for key, adapter in LOCAL_DNS_ADAPTERS.items():
            rc, state = run_cmd(["systemctl", "is-active", adapter["service"]])
            if rc == 0 and state.strip() == "active":
                active.append(key)
        _LOCAL_DNS_DETECT_CACHE["active"] = list(active)
        _LOCAL_DNS_DETECT_CACHE["expires"] = now + 30
        return active


def local_dns_runtime_info(refresh=False):
    configured = normalize_local_dns_config(CFG.get("local_dns"))
    same_host = local_dns_is_same_host(configured["address"])
    requested = configured["provider"]
    effective = "generic"
    detected = False
    if same_host:
        if requested == "auto":
            active = _active_local_dns_adapters(refresh=refresh)
            if len(active) == 1:
                effective = active[0]
                detected = True
        else:
            effective = requested
    return {
        "configured": configured,
        "same_host": same_host,
        "provider_editable": same_host,
        "effective_provider": effective,
        "provider_detected": detected,
        "provider_name": (
            LOCAL_DNS_ADAPTERS.get(effective, {}).get("name")
            if effective != "generic" else None
        ),
        "remote_note": (
            None if same_host
            else "Remote resolvers are checked by DNS response only and always use generic guidance."
        ),
    }


def micro_local_dns(provider):
    """Same-host provider evidence. Never called for a remote resolver."""
    adapter = LOCAL_DNS_ADAPTERS.get(provider)
    if not adapter:
        return []
    service = adapter["service"]
    name = adapter["name"]
    steps = []
    rc, load_state = run_cmd(
        ["systemctl", "show", "-p", "LoadState", "--value", service]
    )
    if rc != 0 or load_state.strip() != "loaded":
        steps.append(_micro_step(
            f"{name} service", False,
            "systemd service not found — it may run in a container",
        ))
    else:
        rc, svc = run_cmd(["systemctl", "is-active", service])
        rc, sub = run_cmd(
            ["systemctl", "show", "-p", "SubState", "--value", service]
        )
        svc = svc.strip() or "unknown"
        sub = sub.strip() or "unknown"
        steps.append(_micro_step(
            f"{name} service",
            svc == "active",
            "service active" if svc == "active" else f"service {svc} ({sub})",
        ))
    disk_ok, disk_detail = check_disk_pressure("/")
    steps.append(_micro_step("Root disk space", disk_ok, disk_detail))
    return steps


def micro_pihole_dns():
    """Compatibility wrapper for callers of the old helper."""
    return micro_local_dns("pihole")


def _local_dns_failure_hint(check):
    provider = check.get("provider") or "generic"
    adapter = LOCAL_DNS_ADAPTERS.get(provider)
    micro = check.get("micro") or []
    for step in micro:
        if step.get("ok") is not False:
            continue
        label = (step.get("label") or "").lower()
        detail = (step.get("detail") or "").lower()
        if "disk" in label:
            suffix = (
                f", then restart {adapter['name']}"
                if adapter else ""
            )
            return f"Free disk space on the Linkmoth host{suffix}."
        if adapter and "service" in label:
            if "not found" in detail:
                return (
                    f"Check the {adapter['name']} service or container on the "
                    "Linkmoth host and confirm it is listening on port 53."
                )
            return (
                "SSH to the Linkmoth host and run: "
                f"sudo systemctl restart {adapter['service']}"
            )
    return (
        "Check the local resolver service and confirm it is listening on "
        f"{check.get('address') or 'the configured address'} port 53."
    )


def run_ladder():
    started = time.monotonic()
    gw, dev = default_route()
    checks = []

    def add(cid, label, ok, detail, ms=None, micro=None, **extra):
        state = extra.pop("state", None)
        if state is None:
            state = "skipped" if ok is None else ("passed" if ok else "failed")
        entry = {
            "id": cid,
            "label": label,
            "ok": ok,
            "state": state,
            "detail": detail,
            "ms": (round(ms, 1) if ms is not None else None),
        }
        if micro:
            entry["micro"] = micro
        entry.update(extra)
        checks.append(entry)

    ok, detail = check_power()
    add("power", "Host power", ok, detail)
    ok, detail = check_link(dev)
    add(
        "link", "Host network link", ok, detail,
        state=("degraded" if ok and "⚠️" in detail else None),
        interface=dev,
    )
    gw_ok = False
    if gw:
        gw_ok, detail, ms = ping(gw)
        add("gateway", "Router (LAN)", gw_ok, detail, ms, target=gw)
    else:
        add("gateway", "Router (LAN)", False, "no default gateway")
    wlan_result = check_router_wlan(gw_ok, include_evidence=True)
    # Keep lightweight monkey-patches and older embedders that return the
    # historical two-value shape working during the richer-evidence upgrade.
    if len(wlan_result) == 3:
        wlan_ok, wlan_detail, wlan_evidence = wlan_result
    else:
        wlan_ok, wlan_detail = wlan_result
        wlan_evidence = {}
    if wlan_ok is None:
        add("router_wlan", "Router Wi-Fi", None, wlan_detail)
    else:
        add(
            "router_wlan", "Router Wi-Fi", wlan_ok, wlan_detail,
            **wlan_evidence,
        )
    dns_runtime = local_dns_runtime_info(refresh=True)
    dns_cfg = dns_runtime["configured"]
    if dns_cfg["mode"] == "disabled":
        add(
            "local_dns", "Local DNS resolver", None, "disabled in config",
            address=dns_cfg["address"], provider="generic",
        )
    else:
        address = dns_cfg["address"]
        ok, detail, ms = dig(address, CFG["dns_test_domain"])
        provider = dns_runtime["effective_provider"]
        provider_name = dns_runtime["provider_name"]
        if (
            dns_cfg["mode"] == "auto"
            and dns_runtime["same_host"]
            and provider == "generic"
            and not ok
        ):
            add(
                "local_dns", "Local DNS resolver", None,
                "no same-host DNS resolver detected — skipped",
                address=address, provider="generic",
            )
        else:
            if provider_name:
                detail = f"{provider_name} · {detail}"
            micro = (
                micro_local_dns(provider)
                if ok is False and dns_runtime["same_host"] and provider_name
                else None
            )
            add(
                "local_dns", "Local DNS resolver", ok, detail, ms,
                micro=micro, address=address, provider=provider,
                provider_name=provider_name,
            )
    ok, detail, ms, evidence = probe_group([
        (server, dig(server, CFG["dns_test_domain"]))
        for server in CFG["upstream_dns"]
    ])
    add("upstream_dns", "Upstream DNS (direct)", ok, detail, ms, **evidence)
    ok, detail, ms, evidence = probe_group([
        (target, ping(target)) for target in CFG["ping_targets"]
    ])
    add("raw_ping", "Raw internet (ping)", ok, detail, ms, **evidence)
    ok, detail, ms, evidence = probe_group([
        (_https_probe_label(url), http_get(url)) for url in CFG["https_targets"]
    ])
    add("https", "Web (HTTPS)", ok, detail, ms, **evidence)

    duration_ms = (time.monotonic() - started) * 1000
    return checks, duration_ms


def normalize_stored_check(check):
    """Translate the old Pi-hole-shaped rung without rewriting history."""
    item = dict(check)
    if item.get("id") == "pihole_dns":
        item["id"] = "local_dns"
        old_label = str(item.get("label") or "")
        item["label"] = "Local DNS resolver"
        if "pi-hole" in old_label.lower():
            item.setdefault("provider", "pihole")
            item.setdefault("provider_name", "Pi-hole")
        else:
            item.setdefault("provider", "generic")
    if "state" not in item:
        if item.get("ok") is None:
            item["state"] = "skipped"
        elif item.get("ok") is False:
            item["state"] = "failed"
        elif item.get("id") == "link" and "⚠️" in str(item.get("detail") or ""):
            item["state"] = "degraded"
        else:
            item["state"] = "passed"
    return item


def normalize_stored_checks(checks):
    return [normalize_stored_check(check) for check in (checks or [])]


def normalize_stored_verdict(item):
    """Return a copy with neutral Local DNS identifiers and title."""
    out = dict(item)
    if out.get("code") == "pihole_broken":
        out["code"] = "local_dns_broken"
        out["title"] = "Local DNS resolver stopped answering — internet itself is fine"
    if out.get("verdict_code") == "pihole_broken":
        out["verdict_code"] = "local_dns_broken"
        out["verdict_title"] = (
            "Local DNS resolver stopped answering — internet itself is fine"
        )
    if out.get("diagnosis_code") == "pihole_broken":
        out["diagnosis_code"] = "local_dns_broken"
    if out.get("false_alarm"):
        out["lifecycle"] = "false-alarm"
    elif out.get("resolved") is not None:
        out["lifecycle"] = "closed"
    elif out.get("recovered_at") is not None:
        out["lifecycle"] = "recovered-awaiting-confirmation"
    else:
        out["lifecycle"] = "active"
    return out


# Verdict codes whose failure point is beyond the router — the set a user
# can reasonably hold their internet provider accountable for.
ISP_ATTRIBUTABLE_CODES = frozenset({
    "wan_down", "partial_routing", "restricted_connectivity",
})
REPORT_WINDOWS = (7, 30, 90)

# GET endpoints a scoped read-only API token may access (widgets, Home
# Assistant REST sensors). Everything else still requires a full session.

HISTORY_RANGE_HOURS = (6, 24, 24 * 7, 24 * 30)
# However long the requested window, never hand the frontend more raw points
# than this — beyond it, samples are averaged into fixed-width time buckets
# so a 30-day chart stays as cheap to render as a 6-hour one.
MAX_HISTORY_POINTS = 300


def _human_duration(seconds):
    seconds = max(0, int(round(float(seconds))))
    if seconds < 60:
        return f"{seconds} s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours} h {minutes} min" if minutes else f"{hours} h"
    days, hours = divmod(hours, 24)
    return f"{days} d {hours} h" if hours else f"{days} d"


def _count_phrase(count, singular, plural=None):
    count = int(count)
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


_STORY_SOURCES = {
    "baseline": "Linkmoth's own background check noticed a problem",
    "dashboard": "a manual diagnosis from the dashboard found a problem",
    "manual-get": "a manual trigger request asked Linkmoth to check the network",
    "webhook": "an external monitor's alert asked Linkmoth to check the network",
    "kuma": "an Uptime Kuma alert asked Linkmoth to check the network",
}


def incident_story(detail):
    """Render one incident's evidence packet as a short plain-language
    narrative — the paragraph a person would paste into a chat to explain
    what happened. Pure rendering over data already in the packet; no
    credentials, no raw addresses beyond what rung details already show."""
    inc = detail.get("incident") or {}
    started = float(inc.get("started") or 0)
    when = time.strftime("%H:%M on %Y-%m-%d", time.localtime(started))
    source = str(inc.get("source") or "").strip()
    opener = None
    for prefix, text in _STORY_SOURCES.items():
        if source == prefix or source.startswith(prefix):
            opener = text
            break
    if opener is None:
        opener = (
            f"an alert from {source} asked Linkmoth to check the network"
            if source else "Linkmoth opened an incident"
        )
    sentences = [f"At {when}, {opener}."]
    first_failure = detail.get("first_failure")
    if first_failure:
        line = (
            f"The first rung to fail was {first_failure['label']}:"
            f" {first_failure['detail']}"
        )
        healthy = [
            label for label in (detail.get("stayed_healthy") or [])
            if label != first_failure.get("label")
        ]
        if healthy:
            line += f" — while {', '.join(healthy[:3])} stayed healthy"
        sentences.append(line + ".")
    title = inc.get("diagnosis_title") or inc.get("verdict_title")
    if title:
        line = f"Verdict: {title}"
        if detail.get("confidence"):
            line += f" ({detail['confidence']} confidence)"
        sentences.append(line + ".")
    runs = detail.get("runs") or []
    if len(runs) > 1:
        rechecks = len(runs) - 1
        sentences.append(
            f"Linkmoth rechecked {rechecks} more"
            f" {'time' if rechecks == 1 else 'times'} and retained every result."
        )
    lifecycle = inc.get("lifecycle")
    if lifecycle == "false-alarm":
        sentences.append(
            "It was marked a false alarm: nothing wrong was seen from the network side."
        )
    elif lifecycle == "closed" and inc.get("resolved"):
        closed = time.strftime("%H:%M", time.localtime(float(inc["resolved"])))
        downtime = _human_duration(detail.get("downtime_s") or 0)
        recovered_at = inc.get("recovered_at")
        if recovered_at:
            recovered = time.strftime("%H:%M", time.localtime(float(recovered_at)))
            segment_count = len(detail.get("outage_segments") or [])
            segment_note = (
                f" across {_count_phrase(segment_count, 'outage segment')}"
                if segment_count > 1 else ""
            )
            sentences.append(
                f"Network connectivity returned at {recovered} after approximately"
                f" {downtime} of observed downtime{segment_note}."
            )
            sentences.append(
                f"Linkmoth continued monitoring the incident and closed it at"
                f" {closed} after the recovery remained stable."
            )
        else:
            sentences.append(
                f"Linkmoth closed the incident at {closed} after {downtime} of"
                " observed downtime; a healthy recovery was not recorded."
            )
    elif lifecycle == "recovered-awaiting-confirmation":
        recovered = time.strftime(
            "%H:%M", time.localtime(float(inc["recovered_at"]))
        )
        downtime = _human_duration(detail.get("downtime_s") or 0)
        sentences.append(
            f"Network connectivity returned at {recovered} after approximately"
            f" {downtime} of observed downtime. Linkmoth is continuing the"
            " recovery monitoring window before closing the incident."
        )
    else:
        sentences.append(
            f"The incident is still open after {_human_duration(time.time() - started)}."
        )
    pattern = detail.get("pattern") or {}
    if pattern.get("count", 0) > 1 and pattern.get("tier"):
        sentences.append(
            f"This fault has now been recorded {pattern['count']} times."
        )
    ref = inc.get("ref")
    tail = (
        f" (Incident {ref}; generated locally by Linkmoth, credentials excluded.)"
        if ref else ""
    )
    return " ".join(sentences) + tail


def isp_report_letter(report):
    """Plain-language, credential-free evidence text for an ISP support
    ticket. Contains incident references, local times, durations, and
    verdict titles — never LAN addresses or secrets."""
    days = report["days"]
    isp = report["isp"]
    lines = ["Internet reliability evidence — generated locally by Linkmoth"]
    window = f"Window: last {days} days"
    if report.get("monitoring_since"):
        since = time.strftime(
            "%Y-%m-%d", time.localtime(report["monitoring_since"])
        )
        window += f" (monitoring since {since})"
    lines.extend([window, ""])
    if not isp["count"]:
        lines.append(
            f"No provider-attributable outages were recorded in the last"
            f" {days} days."
        )
    else:
        lines.append(
            f"Provider-path {'outage' if isp['count'] == 1 else 'outages'}:"
            f" {isp['count']}"
        )
        lines.append(
            "Downtime on the provider path: "
            + _human_duration(isp["downtime_s"])
        )
        longest = report.get("longest")
        if longest and longest.get("isp_attributable"):
            when = time.strftime(
                "%Y-%m-%d %H:%M", time.localtime(longest["started"])
            )
            downtime = _human_duration(longest["window_downtime_s"])
            incident_duration = _human_duration(longest["incident_duration_s"])
            recovered = (
                time.strftime(
                    "%Y-%m-%d %H:%M", time.localtime(longest["recovered_at"])
                ) if longest.get("recovered_at") else "not yet observed"
            )
            closed = (
                time.strftime(
                    "%Y-%m-%d %H:%M", time.localtime(longest["resolved"])
                ) if longest.get("resolved") else "still open"
            )
            lines.append(
                f"Longest single outage: {when} local time, {downtime} observed"
                f" downtime; incident duration {incident_duration}; network"
                f" recovered {recovered}; incident closed {closed}."
            )
        peak = isp.get("peak_hours")
        if peak:
            lines.append(
                f"Outages cluster between {peak['start_hour']:02d}:00 and"
                f" {peak['end_hour']:02d}:00 local time"
                f" ({peak['count']} of {isp['count']})."
            )
        lines.extend(["", "Incidents (local time):"])
        for item in report["incidents"]:
            if not item["isp_attributable"]:
                continue
            when = time.strftime(
                "%Y-%m-%d %H:%M", time.localtime(item["started"])
            )
            downtime = _human_duration(item["window_downtime_s"])
            incident_duration = _human_duration(item["incident_duration_s"])
            recovered = (
                time.strftime(
                    "%Y-%m-%d %H:%M", time.localtime(item["recovered_at"])
                ) if item.get("recovered_at") else "not yet observed"
            )
            closed = (
                time.strftime(
                    "%Y-%m-%d %H:%M", time.localtime(item["resolved"])
                ) if item.get("resolved") else "still open"
            )
            timing = (
                f"{downtime} observed downtime; incident duration"
                f" {incident_duration}; network recovered {recovered};"
                f" incident closed {closed}"
            )
            lines.append(
                f"- {item['ref'] or '(no ref)'} — {when}, {timing} — "
                + (item["title"] or item["code"] or "outage")
            )
    lines.extend([
        "",
        "Methodology: Linkmoth checks host, own link, router, local DNS,"
        " upstream DNS, raw internet reachability, and HTTPS in dependency"
        " order on a fixed schedule, and rechecks repeatedly during"
        " incidents. A provider-path verdict requires this LAN and router to"
        " be healthy while independent internet probes all fail, so local"
        " faults are not misattributed to the provider.",
    ])
    return "\n".join(lines)


def isp_report_csv(report):
    """CSV of every incident in the report window (all layers, not only
    provider-attributable ones), for spreadsheets or support attachments."""
    import csv
    import io
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow([
        "ref", "started_local", "network_recovered_local",
        "incident_closed_local", "duration_seconds",
        "observed_downtime_seconds", "incident_duration_seconds",
        "outage_segments", "ongoing", "verdict_code", "verdict_title",
        "layer", "isp_attributable",
    ])
    for item in report["incidents"]:
        writer.writerow([
            item["ref"] or "",
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item["started"])),
            (time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(item["recovered_at"])
            ) if item["recovered_at"] else ""),
            (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item["resolved"]))
             if item["resolved"] else ""),
            item["duration_s"],
            item["downtime_s"],
            item["incident_duration_s"],
            len(item["outage_segments"]),
            "yes" if item["open"] else "no",
            item["code"] or "",
            item["title"] or "",
            item["layer"],
            "yes" if item["isp_attributable"] else "no",
        ])
    return buf.getvalue()


def verdict(checks):
    checks = normalize_stored_checks(checks)
    c = {ch["id"]: ch for ch in checks}

    def ok(cid):
        return c[cid]["ok"] is not False

    if not ok("link"):
        v = ("bad", "pi_link", "Linkmoth's own network connection is unavailable",
             "I can't see the network at all, so I can't judge anyone else. " + c["link"]["detail"],
             "Check the Linkmoth host's cable, Wi-Fi, and default route first; downstream verdicts are unreliable.")
    elif not ok("gateway"):
        v = ("bad", "router_down", "Router isn't answering on the LAN",
             "Linkmoth's own link is fine but the router doesn't reply. Everything in the house will look down.",
             "Check router power and cables, then give it a reboot.")
    elif not ok("upstream_dns") and not ok("raw_ping") and not ok("https"):
        v = ("bad", "wan_down",
             "Internet is dead beyond the router — likely internet provider outage or router WAN cable fault",
             "LAN and router are fine, but direct DNS, ping, and HTTPS all fail beyond them.",
             "Check the router's WAN cable and WAN light, then your internet provider's status page.")
    elif not ok("upstream_dns") and not ok("raw_ping"):
        v = (
            "warn", "restricted_connectivity",
            "Web access works, but direct DNS and ping are being blocked",
            "HTTPS succeeds, so the internet is not down. Direct DNS and ping both fail, which points to filtering, a VPN, or network policy.",
            "Do not reboot everything yet; check VPN, firewall, parental-control, or guest-network settings first.",
        )
    elif not ok("local_dns") and ok("upstream_dns"):
        local = c["local_dns"]
        micro = local.get("micro") or []
        hint = _local_dns_failure_hint(local)
        explain = (
            "Router and upstream DNS respond, but the configured local DNS "
            "resolver does not. Devices that use it may lose name resolution."
        )
        provider_name = local.get("provider_name")
        if provider_name:
            explain += f" The same-host resolver is {provider_name}."
        failed = [m["detail"] for m in micro if m.get("ok") is False]
        if failed:
            explain += " Likely cause: " + "; ".join(failed) + "."
        v = (
            "bad", "local_dns_broken",
            "Local DNS resolver stopped answering — internet itself is fine",
            explain, hint,
        )
    elif not ok("upstream_dns"):
        v = ("bad", "upstream_dns_down", "Routing works but public DNS resolvers don't answer",
             "Ping to the outside works, yet 1.1.1.1/8.8.8.8 won't answer DNS. Unusual — possibly ISP DNS interference.",
             "Try again in a few minutes; if it persists, contact your internet provider.")
    elif not ok("raw_ping"):
        v = ("warn", "partial_routing", "DNS answers but ping to the internet fails",
             "Could be ICMP filtering or flaky routing. Web may still work.",
             "Watch the next re-checks; if HTTPS stays green this is cosmetic.")
    elif not ok("https"):
        v = ("warn", "web_broken", "DNS and routing are fine but HTTPS fetches fail",
             "Name resolution and ping work, yet web requests don't complete.",
             "Could be a captive portal, filtering, or a transient. Re-check will confirm.")
    elif c["power"]["ok"] is False:
        v = (
            "warn", "host_power", "Linkmoth host power is unstable",
            "The network path answers, but the host reports " + c["power"]["detail"]
            + ". This can make later network evidence unreliable.",
            "Fix the host's power supply or cable, then run the diagnosis again.",
        )
    elif "⚠️" in (c["link"].get("detail") or ""):
        v = ("warn", "link_degraded", "Host Ethernet link is degraded",
             "The Ethernet link is connected, but it negotiated a reduced mode "
             "(below gigabit, or half-duplex): " + c["link"]["detail"],
             "Try another cable or switch port. A damaged cable or poor connection "
             "can reduce the negotiated speed without disconnecting completely.")
    elif c.get("router_wlan", {}).get("ok") is False:
        v = ("warn", "router_wlan_down", "Configured Wi-Fi witnesses are not answering",
             c["router_wlan"]["detail"],
             "Confirm one witness is awake and accepts ping before changing or rebooting the router.")
    else:
        partial = [
            ch.get("label") or ch.get("id") or "check" for ch in checks
            if ch.get("state") == "partial"
            and ch.get("id") in ("router_wlan", "upstream_dns", "raw_ping", "https")
        ]
        if partial:
            names = ", ".join(partial)
            v = (
                "ok", "all_clear", "Network path works, but test targets disagree",
                "Every required layer has a working path. Some redundant targets did not answer: "
                + names + ".",
                "Run one fresh diagnosis. If the same target keeps failing, replace that diagnostic target instead of treating it as a network outage.",
            )
        else:
            v = ("ok", "all_clear", "All network checks passed",
                 "Router, local DNS, upstream DNS, ping and HTTPS all respond normally.",
                 "")
    sev, code, title, explain, hint = v
    if c["power"]["ok"] is False and code != "host_power":
        sev = "bad" if sev == "bad" else "warn"
        explain += " Also: the host reports " + c["power"]["detail"] + " — a weak power supply causes ghost problems."
    return {"severity": sev, "code": code, "title": title, "explain": explain, "hint": hint}


def confidence_assessment(checks):
    """Return a verdict confidence level and the evidence behind that limit."""
    c = {ch["id"]: ch for ch in checks}
    if c.get("link", {}).get("ok") is False:
        return {
            "level": "low",
            "reason": "Linkmoth's own network link failed, so it cannot reliably judge anything beyond the host.",
        }
    if c.get("power", {}).get("ok") is False:
        return {
            "level": "medium",
            "reason": "The host reports a power problem; undervoltage can create misleading network symptoms.",
        }
    if c.get("router_wlan", {}).get("ok") is False:
        return {
            "level": "medium",
            "reason": "Wi-Fi witnesses disagreed; they are supporting evidence, not a definitive router verdict.",
        }
    if any(
        c.get(cid, {}).get("state") == "partial"
        for cid in ("router_wlan", "upstream_dns", "raw_ping", "https")
    ):
        return {
            "level": "medium",
            "reason": "Redundant targets disagreed, so Linkmoth found a usable path but not unanimous evidence.",
        }
    return {
        "level": "high",
        "reason": "The Linkmoth host was healthy and the relevant independent checks agreed.",
    }


def confidence_from_checks(checks):
    """Compatibility helper for callers that need only the confidence level."""
    return confidence_assessment(checks)["level"]



def record_quality_sample():
    """Measure and store one connection-quality sample. Best-effort."""
    qcfg = quality_config()
    if not qcfg.get("enabled", True):
        return None
    targets = qcfg.get("targets") or CFG.get("ping_targets") or []
    if not targets:
        return None
    try:
        sample = measure_quality(targets, count=int(qcfg.get("sample_count", 10) or 10))
    except Exception as e:
        print(f"quality sample failed: {e}", file=sys.stderr, flush=True)
        return None
    if not sample:
        return None
    verdict = classify_quality(
        sample["latency_ms"], sample["jitter_ms"], sample["loss_pct"], qcfg)
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO quality_samples(ts, latency_ms, jitter_ms, loss_pct, state)"
                " VALUES(?,?,?,?,?)",
                (time.time(), sample["latency_ms"], sample["jitter_ms"],
                 sample["loss_pct"], verdict["state"]),
            )
    except sqlite3.Error as e:
        print(f"quality store failed: {e}", file=sys.stderr, flush=True)
        return None
    return {**sample, **verdict}


_LOAD_TEST_LOCK = threading.Lock()


def _resolve_load_target(url):
    """A load-test URL must be a public HTTPS host. This feature generates
    real outbound traffic on purpose; it must never be aimable at the LAN
    (no internal port probing, no loopback services)."""
    parsed = urlparse(str(url or "").strip())
    if (
        parsed.scheme != "https" or not parsed.hostname
        or parsed.username is not None or parsed.password is not None
    ):
        raise ValueError("load test URL must be https://")
    try:
        infos = socket.getaddrinfo(
            parsed.hostname, parsed.port or 443,
            type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
        )
    except OSError as exc:
        raise ValueError(f"load test host did not resolve: {exc}") from exc
    addresses = sorted({info[4][0] for info in infos})
    if not addresses or any(
        not ipaddress.ip_address(address).is_global for address in addresses
    ):
        raise ValueError(
            "load test host must resolve to public addresses only"
        )
    return parsed, addresses


def _validate_load_url(url):
    parsed, _addresses = _resolve_load_target(url)
    return parsed.geturl()


def _load_downloader(url, addresses, seconds, max_bytes, stats, stop):
    start = time.monotonic()
    deadline = float(stats.get("deadline") or (start + seconds))
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.params:
        path += ";" + parsed.params
    if parsed.query:
        path += "?" + parsed.query
    host_header = parsed.hostname or ""
    if ":" in host_header:
        host_header = f"[{host_header}]"
    if parsed.port and parsed.port != 443:
        host_header += f":{parsed.port}"
    headers = {
        "Host": host_header,
        "User-Agent": "Linkmoth-load-test",
        "Accept-Encoding": "identity",
        "Cache-Control": "no-cache",
        "Connection": "close",
    }
    context = ssl.create_default_context()

    def still_going():
        return (
            time.monotonic() < deadline
            and stats["bytes"] < max_bytes
            and not stop.is_set()
        )

    try:
        # A fast line can finish one bounded response before loaded latency is
        # sampled. Keep requesting separately bounded responses for the test
        # duration so the measurement cannot quietly become an idle ping test.
        # max_bytes bounds the WHOLE test's transfer, not each response —
        # stats["bytes"] (shared across every request) is what still_going()
        # checks, so repeating requests can never inflate total data used
        # beyond the configured, documented cap.
        while still_going():
            completed_request = False
            for address in addresses:
                conn = _PinnedHTTPSConnection(
                    parsed.hostname, address, port=parsed.port or 443,
                    timeout=10, context=context,
                )
                try:
                    conn.request("GET", path, headers=headers)
                    resp = conn.getresponse()
                    # http.client never follows redirects. Treat every non-2xx
                    # response as a failed target instead of downloading an
                    # error page or trusting an unvalidated Location.
                    if not 200 <= resp.status < 300:
                        stats["error"] = f"HTTP {resp.status}"
                        return
                    while still_going():
                        chunk = resp.read(min(65536, max_bytes - stats["bytes"]))
                        if not chunk:
                            break
                        stats["bytes"] += len(chunk)
                    stats["error"] = None
                    completed_request = True
                    break
                except Exception as exc:
                    stats["error"] = exc.__class__.__name__
                finally:
                    conn.close()
            if not completed_request:
                return
    finally:
        stats["elapsed"] = max(0.0, time.monotonic() - start)


def _measure_loaded_quality(target, stats, deadline):
    """Measure only pings that overlap active download byte progress."""
    active = []
    while time.monotonic() < deadline:
        before = int(stats.get("bytes") or 0)
        sample = measure_quality([target], count=1)
        after = int(stats.get("bytes") or 0)
        if sample and sample.get("latency_ms") is not None and after > before:
            active.append(sample)
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.3, remaining))
    # One coincidental overlap is not enough evidence for a confident grade.
    if len(active) < 2:
        return None
    latencies = [float(sample["latency_ms"]) for sample in active]
    average = sum(latencies) / len(latencies)
    jitter = (
        (sum((value - average) ** 2 for value in latencies) / len(latencies)) ** 0.5
        if len(latencies) > 1 else 0.0
    )
    return {
        "latency_ms": average,
        "jitter_ms": jitter,
        "loss_pct": 0.0,
        "target": str(target),
        "active_samples": len(active),
    }


def run_load_test(store=True):
    """Latency-under-load (bufferbloat) measurement.

    Ping the quality target at idle, then again while a bounded download
    saturates the link, and grade the latency inflation the way the
    dslreports scale does (A under +30 ms … F above +400 ms). The transfer
    stops at load_test_seconds or load_test_max_mb — whichever comes first —
    and keeps requesting fresh responses in between so a fast connection that
    finishes one response early doesn't go idle for the rest of the window.
    Only pings that overlap increasing downloaded bytes contribute to the
    loaded result.
    Returns the result dict, or None when nothing could be measured.
    """
    qcfg = quality_config()
    parsed, addresses = _resolve_load_target(qcfg.get("load_test_url"))
    url = parsed.geturl()
    targets = qcfg.get("targets") or CFG.get("ping_targets") or []
    if not targets:
        return None
    idle = measure_quality(targets, count=5)
    if not idle or idle.get("latency_ms") is None:
        return None
    try:
        seconds = int(qcfg.get("load_test_seconds", 10))
    except (TypeError, ValueError):
        seconds = 10
    seconds = max(5, min(20, seconds))
    try:
        max_mb = int(qcfg.get("load_test_max_mb", 25))
    except (TypeError, ValueError):
        max_mb = 25
    max_bytes = max(1, min(100, max_mb)) * 1024 * 1024
    deadline = time.monotonic() + seconds
    stats = {"bytes": 0, "elapsed": 0.0, "error": None, "deadline": deadline}
    stop = threading.Event()
    worker = threading.Thread(
        target=_load_downloader,
        args=(url, addresses, seconds, max_bytes, stats, stop),
        daemon=True,
    )
    worker.start()
    loaded = _measure_loaded_quality(idle["target"], stats, deadline)
    stop.set()
    worker.join(timeout=seconds + 10)
    if not loaded or loaded.get("latency_ms") is None:
        return None
    bloat = max(0.0, loaded["latency_ms"] - idle["latency_ms"])
    grade = (
        "A" if bloat < 30 else "B" if bloat < 60
        else "C" if bloat < 200 else "D" if bloat < 400 else "F"
    )
    throughput = None
    # monotonic() has sub-second precision, so a fast connection that reaches
    # the byte cap in under half a second still provides a valid estimate.
    if stats["bytes"] and stats["elapsed"] > 0:
        throughput = round(stats["bytes"] * 8 / stats["elapsed"] / 1e6, 1)
    result = {
        "ts": time.time(),
        "idle_ms": round(idle["latency_ms"], 1),
        "loaded_ms": round(loaded["latency_ms"], 1),
        "bloat_ms": round(bloat, 1),
        "grade": grade,
        "throughput_mbps": throughput,
        "bytes": int(stats["bytes"]),
        "seconds": round(stats["elapsed"], 1),
        "error": stats["error"],
        "active_samples": int((loaded or {}).get("active_samples") or 0),
    }
    if store:
        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO load_tests(ts, idle_ms, loaded_ms, bloat_ms,"
                    " grade, throughput_mbps, bytes, seconds, error)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (result["ts"], result["idle_ms"], result["loaded_ms"],
                     result["bloat_ms"], result["grade"],
                     result["throughput_mbps"], result["bytes"],
                     result["seconds"], result["error"]),
                )
        except sqlite3.Error as e:
            print(f"load test store failed: {e}", file=sys.stderr, flush=True)
    return result


def latest_load_test():
    try:
        with db() as conn:
            row = conn.execute(
                "SELECT * FROM load_tests ORDER BY id DESC LIMIT 1"
            ).fetchone()
    except sqlite3.Error:
        return None
    result = dict(row) if row else None
    if (
        result
        and result.get("throughput_mbps") is None
        and result.get("bytes")
        and result.get("seconds")
        and result["seconds"] > 0
    ):
        # Recover estimates discarded by versions that treated sub-0.5 s
        # transfers as too short, using the retained transfer measurements.
        result["throughput_mbps"] = round(
            result["bytes"] * 8 / result["seconds"] / 1e6, 1
        )
    return result


def _median(values):
    values = sorted(v for v in values if v is not None)
    if not values:
        return None
    mid = len(values) // 2
    return values[mid] if len(values) % 2 else (values[mid - 1] + values[mid]) / 2.0


QUALITY_DAYPARTS = (
    ("night", 0, 6),
    ("morning", 6, 12),
    ("afternoon", 12, 18),
    ("evening", 18, 24),
)


def quality_findings(days=7):
    """Plain-language recurring-pattern findings over recent quality
    samples: time-of-day comparisons, loss concentration, and trend. Pure
    analytics over data already stored — the sentences a user can point at
    when saying "the internet is always bad in the evening"."""
    qcfg = quality_config()
    cutoff = time.time() - days * 86400
    rows = []
    try:
        with db() as conn:
            rows = conn.execute(
                "SELECT ts, latency_ms, jitter_ms, loss_pct, state"
                " FROM quality_samples WHERE ts > ? ORDER BY ts ASC",
                (cutoff,),
            ).fetchall()
    except sqlite3.Error as e:
        print(f"quality findings read failed: {e}", file=sys.stderr, flush=True)
    samples = [dict(r) for r in rows]
    result = {
        "days": days,
        "sample_count": len(samples),
        "findings": [],
        "dayparts": {},
    }
    # Below a dozen samples any "pattern" is noise, not evidence.
    if len(samples) < 12:
        return result
    buckets = {}
    for sample in samples:
        hour = time.localtime(sample["ts"]).tm_hour
        for name, lo, hi in QUALITY_DAYPARTS:
            if lo <= hour < hi:
                buckets.setdefault(name, []).append(sample)
                break
    daypart_stats = {}
    for name, _, _ in QUALITY_DAYPARTS:
        bucket = buckets.get(name) or []
        if len(bucket) < 3:
            continue
        daypart_stats[name] = {
            "samples": len(bucket),
            "median_latency_ms": _median([b["latency_ms"] for b in bucket]),
            "mean_loss_pct": round(
                sum(b["loss_pct"] or 0 for b in bucket) / len(bucket), 2
            ),
            "poor_share": round(
                sum(1 for b in bucket if b["state"] == "poor") / len(bucket), 2
            ),
        }
    result["dayparts"] = daypart_stats
    findings = []
    rated = {
        name: st for name, st in daypart_stats.items()
        if st["median_latency_ms"] is not None
    }
    if len(rated) >= 2:
        worst = max(rated, key=lambda n: rated[n]["median_latency_ms"])
        best = min(rated, key=lambda n: rated[n]["median_latency_ms"])
        worst_ms = rated[worst]["median_latency_ms"]
        best_ms = rated[best]["median_latency_ms"]
        if best_ms > 0 and worst_ms >= best_ms * 1.5 and worst_ms - best_ms >= 20:
            findings.append(
                f"{worst.capitalize()} latency is {worst_ms / best_ms:.1f}×"
                f" worse than {best} (median {round(worst_ms)} ms vs"
                f" {round(best_ms)} ms)."
            )
    if daypart_stats:
        worst_loss = max(
            daypart_stats, key=lambda n: daypart_stats[n]["mean_loss_pct"]
        )
        worst_loss_pct = daypart_stats[worst_loss]["mean_loss_pct"]
        other_losses = [
            st["mean_loss_pct"] for name, st in daypart_stats.items()
            if name != worst_loss
        ]
        if worst_loss_pct >= float(qcfg["loss_warn_pct"]) and (
            not other_losses
            or worst_loss_pct >= 2 * max(max(other_losses), 0.01)
        ):
            findings.append(
                f"Packet loss concentrates in the {worst_loss}"
                f" (average {worst_loss_pct}%)."
            )
    half = len(samples) // 2
    first_half = _median([s["latency_ms"] for s in samples[:half]])
    second_half = _median([s["latency_ms"] for s in samples[half:]])
    if first_half and second_half:
        if second_half >= first_half * 1.25 and second_half - first_half >= 15:
            findings.append(
                f"Latency worsened across the window (median"
                f" {round(first_half)} ms → {round(second_half)} ms)."
            )
        elif first_half >= second_half * 1.25 and first_half - second_half >= 15:
            findings.append(
                f"Latency improved across the window (median"
                f" {round(first_half)} ms → {round(second_half)} ms)."
            )
    if not findings:
        overall = _median([s["latency_ms"] for s in samples])
        good_share = sum(1 for s in samples if s["state"] == "good") / len(samples)
        if overall is not None and good_share >= 0.9:
            findings.append(
                f"No recurring quality problems in the last {days} days —"
                f" median latency {round(overall)} ms,"
                f" {round(good_share * 100)}% of samples good."
            )
    result["findings"] = findings
    return result


# Score bands. Deliberately generous at the top: the grade answers "was the
# line fine today", not "is this a datacentre link".
SCORE_GRADES = (
    (97, "A+"), (93, "A"), (90, "A-"), (87, "B+"), (83, "B"), (80, "B-"),
    (77, "C+"), (73, "C"), (70, "C-"), (60, "D"), (0, "F"),
)
# Below this many samples in a day there is not enough evidence to grade it.
MIN_SCORE_SAMPLES = 6
# Days needing a grade before a personal baseline means anything.
MIN_BASELINE_DAYS = 5


def _score_grade(score):
    for floor, letter in SCORE_GRADES:
        if score >= floor:
            return letter
    return "F"


def _bloat_penalty(bloat_ms):
    if bloat_ms is None:
        return 0.0
    for limit, penalty in ((30, 0.0), (60, 3.0), (120, 7.0), (250, 12.0)):
        if bloat_ms < limit:
            return penalty
    return 18.0


def _score_one_day(samples, bloat_ms, downtime_s, baseline_latency):
    """Score a single day from its own samples. Starts at 100 and subtracts;
    latency is judged against `baseline_latency` (this line's own normal)
    rather than an absolute target, so a stable slow link is not permanently
    failed and a fast link that degrades is still caught."""
    latencies = [s["latency_ms"] for s in samples if s["latency_ms"] is not None]
    jitters = [s["jitter_ms"] for s in samples if s["jitter_ms"] is not None]
    losses = [s["loss_pct"] or 0.0 for s in samples]
    median_latency = _median(latencies)
    median_jitter = _median(jitters)
    median_loss = _median(losses) or 0.0

    loss_penalty = min(40.0, median_loss * 8.0)
    jitter_penalty = min(15.0, (median_jitter or 0.0) / 2.0)
    latency_penalty = 0.0
    if baseline_latency and median_latency is not None and baseline_latency > 0:
        excess = max(0.0, median_latency - baseline_latency)
        latency_penalty = min(25.0, excess / baseline_latency * 40.0)
    bloat_penalty = _bloat_penalty(bloat_ms)
    downtime_penalty = min(40.0, (downtime_s or 0.0) / 60.0 * 2.0)

    factors = {
        "latency": -round(latency_penalty),
        "jitter": -round(jitter_penalty),
        "loss": -round(loss_penalty),
        "bufferbloat": -round(bloat_penalty),
        "downtime": -round(downtime_penalty),
    }
    total = (loss_penalty + jitter_penalty + latency_penalty
             + bloat_penalty + downtime_penalty)
    score = int(round(max(0.0, 100.0 - total)))
    return score, factors, median_latency


_FACTOR_PHRASES = {
    "latency": "latency ran above your normal",
    "jitter": "jitter was unsettled",
    "loss": "packets were dropping",
    "bufferbloat": "the line bloated under load",
    "downtime": "the connection dropped out",
}


def _day_start(ts):
    """Local midnight for `ts`, or None if the timestamp is not a real date.

    A host without an RTC (every Raspberry Pi) can record samples before NTP
    corrects its clock, leaving rows dated 1970 or far in the future.
    localtime/mktime raise on those, and this runs inside /api/status -- an
    unguarded raise here would take the whole dashboard down over one bad
    row, so such rows are reported unusable and skipped by callers."""
    try:
        lt = time.localtime(ts)
        return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1))
    except (OSError, OverflowError, ValueError):
        return None


_SCORE_CACHE_LOCK = threading.Lock()
_SCORE_CACHE = {}
# The grade is a per-day figure, but /api/status is polled every
# ui_refresh_seconds (as low as 2s) by every open dashboard. Recomputing a
# 30-day aggregate over tens of thousands of rows on every poll would burn
# real CPU on a Raspberry Pi to produce an answer that changes once a day,
# so results are cached briefly. New samples only land every
# history_sample_minutes anyway.
SCORE_CACHE_SECONDS = 60


def connection_score(days=30, use_cache=True):
    """A daily connection-health grade built only from evidence already
    stored -- quality samples, any bufferbloat tests that were run, and
    recorded outage segments. Read-only: it never probes the network, so
    calling it costs nothing but a few SQLite reads.

    Today's grade is compared against this line's own recent baseline
    rather than an absolute target, which is what lets a slow-but-steady
    connection score well and a fast one that degrades still get flagged.
    Days with too little evidence are reported ungraded instead of being
    given a number that would not mean anything.
    """
    days = max(2, min(90, int(days or 30)))
    now = time.time()
    if use_cache:
        with _SCORE_CACHE_LOCK:
            hit = _SCORE_CACHE.get(days)
            if hit and hit["expires"] > now:
                return hit["value"]
    today_start = _day_start(now)
    if today_start is None:
        return {"days": days, "history": [], "sample_count": 0, "graded": False,
                "score": None, "grade": None, "factors": None,
                "baseline_score": None, "baseline_grade": None, "trend": None,
                "headline": "Host clock is not set, so days cannot be graded."}
    window_start = today_start - (days - 1) * 86400
    samples, segments_by_incident, load_rows = [], {}, []
    try:
        with db() as conn:
            samples = [dict(r) for r in conn.execute(
                "SELECT ts, latency_ms, jitter_ms, loss_pct FROM quality_samples"
                " WHERE ts >= ? ORDER BY ts ASC", (window_start,),
            )]
            load_rows = [dict(r) for r in conn.execute(
                "SELECT ts, bloat_ms FROM load_tests"
                " WHERE ts >= ? AND bloat_ms IS NOT NULL ORDER BY ts ASC",
                (window_start,),
            )]
            incidents = [dict(r) for r in conn.execute(
                "SELECT * FROM incidents WHERE started >= ?"
                " OR resolved IS NULL OR resolved >= ?",
                (window_start, window_start),
            )]
            for incident in incidents:
                if incident.get("false_alarm"):
                    continue
                segments_by_incident[incident["id"]] = _incident_outage_segments(
                    conn, incident)
    except sqlite3.Error as e:
        print(f"connection score read failed: {e}", file=sys.stderr, flush=True)

    by_day, bloat_by_day = {}, {}
    for sample in samples:
        key = _day_start(sample["ts"])
        if key is not None:
            by_day.setdefault(key, []).append(sample)
    for row in load_rows:
        key = _day_start(row["ts"])
        if key is not None:
            bloat_by_day[key] = row["bloat_ms"]
    all_segments = [s for group in segments_by_incident.values() for s in group]

    history, latency_by_day = [], {}
    for index in range(days):
        start = window_start + index * 86400
        end = start + 86400
        day_samples = by_day.get(start, [])
        entry = {"day": time.strftime("%Y-%m-%d", time.localtime(start)),
                 "samples": len(day_samples)}
        if len(day_samples) < MIN_SCORE_SAMPLES:
            entry.update({"score": None, "grade": None})
            history.append(entry)
            continue
        downtime = _outage_seconds(
            all_segments, window_start=start, window_end=min(end, now), now=now)
        median = _median([s["latency_ms"] for s in day_samples
                          if s["latency_ms"] is not None])
        if median is not None:
            latency_by_day[start] = median
        # Baseline for a given day is the median of the graded days before
        # it, so the series is not scored against its own future.
        prior = [latency_by_day[key] for key in sorted(latency_by_day) if key < start]
        baseline_latency = _median(prior) if len(prior) >= MIN_BASELINE_DAYS else median
        score, factors, _ = _score_one_day(
            day_samples, bloat_by_day.get(start), downtime, baseline_latency)
        entry.update({"score": score, "grade": _score_grade(score),
                      "factors": factors})
        history.append(entry)

    graded = [item for item in history if item["score"] is not None]
    today = history[-1] if history else {"score": None, "samples": 0}
    result = {
        "days": days,
        "history": [{"day": i["day"], "score": i["score"]} for i in history],
        "sample_count": today.get("samples", 0),
        "graded": today.get("score") is not None,
        "score": today.get("score"),
        "grade": today.get("grade"),
        "factors": today.get("factors"),
        "baseline_score": None,
        "baseline_grade": None,
        "trend": None,
        "headline": "",
    }
    def _cache(value):
        with _SCORE_CACHE_LOCK:
            _SCORE_CACHE[days] = {"value": value,
                                  "expires": now + SCORE_CACHE_SECONDS}
        return value

    if not result["graded"]:
        result["headline"] = "Not enough data yet today."
        return _cache(result)

    earlier = [item["score"] for item in graded[:-1]]
    if len(earlier) >= MIN_BASELINE_DAYS:
        baseline = int(round(_median(earlier)))
        result["baseline_score"] = baseline
        result["baseline_grade"] = _score_grade(baseline)
        delta = result["score"] - baseline
        result["trend"] = ("steady" if abs(delta) <= 3
                           else "above" if delta > 0 else "below")
    worst = min(result["factors"].items(), key=lambda item: item[1])
    if worst[1] <= -3:
        result["headline"] = (
            f"Today {_FACTOR_PHRASES[worst[0]]}."
        )
    else:
        result["headline"] = "No problems worth flagging today."
    return _cache(result)


def quality_summary(limit=288):
    """Recent quality samples (oldest first) plus the latest verdict."""
    qcfg = quality_config()
    rows = []
    try:
        with db() as conn:
            rows = conn.execute(
                "SELECT ts, latency_ms, jitter_ms, loss_pct, state"
                " FROM quality_samples ORDER BY ts DESC LIMIT ?", (limit,),
            ).fetchall()
    except sqlite3.Error as e:
        print(f"quality read failed: {e}", file=sys.stderr, flush=True)
    samples = [
        {"ts": r["ts"], "latency_ms": r["latency_ms"], "jitter_ms": r["jitter_ms"],
         "loss_pct": r["loss_pct"], "state": r["state"]}
        for r in rows
    ][::-1]  # chronological for sparklines
    current = None
    if samples:
        last = samples[-1]
        verdict = classify_quality(
            last["latency_ms"], last["jitter_ms"], last["loss_pct"], qcfg)
        current = {**last, **verdict}
    try:
        load_test_host = urlparse(str(qcfg.get("load_test_url") or "")).hostname
    except ValueError:
        load_test_host = None
    return {
        "enabled": bool(qcfg.get("enabled", True)),
        "current": current,
        "samples": samples,
        "findings": quality_findings(),
        "load_test": latest_load_test(),
        "load_test_config": {
            "host": load_test_host,
            "max_mb": qcfg.get("load_test_max_mb"),
            "seconds": qcfg.get("load_test_seconds"),
        },
        "thresholds": {
            "latency_warn_ms": qcfg["latency_warn_ms"],
            "latency_bad_ms": qcfg["latency_bad_ms"],
            "jitter_warn_ms": qcfg["jitter_warn_ms"],
            "jitter_bad_ms": qcfg["jitter_bad_ms"],
            "loss_warn_pct": qcfg["loss_warn_pct"],
            "loss_bad_pct": qcfg["loss_bad_pct"],
        },
    }



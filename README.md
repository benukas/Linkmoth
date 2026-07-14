# Linkmoth

<img src="linkmoth-white.svg" alt="Linkmoth" width="180">

[![CI](https://github.com/benukas/linkmoth/actions/workflows/ci.yml/badge.svg)](https://github.com/benukas/linkmoth/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-3776AB.svg)](https://www.python.org/)
[![Status: Early Access / Beta](https://img.shields.io/badge/status-early--access%20%2F%20beta-orange.svg)](CHANGELOG.md)

A network flight recorder for your home LAN. When something breaks, it
tells you **whose fault it is** in plain language:

- *"Local DNS resolver stopped answering — internet itself is fine"*
- *"Internet is dead beyond the router — likely internet provider outage or router WAN cable fault"*
- *"Router isn't answering on the LAN"*
- *"Nothing wrong seen from the network side"* (false alarm)

It works standalone, checking the network itself every few minutes. If you
already run a watcher, [Uptime Kuma](https://github.com/louislam/uptime-kuma)
or any other tool that can send a webhook, Linkmoth can pair with it instead:
your monitor notices *that* something is down, Linkmoth works out *why*, and
both show up on a simple LAN-only dashboard.

**Linkmoth is early access / beta.** It's actively developed by a single
maintainer; expect rough edges, and please report what you find (see
[Reporting issues](#reporting-issues) below). Local and dependency-free: no
cloud account, no telemetry, standard-library Python only. See
[CHANGELOG.md](CHANGELOG.md) for recent changes.

| OS | Status |
| --- | --- |
| Raspberry Pi OS (Raspberry Pi 5) | Tested |
| Debian | Expected to work (same systemd/apt base) — not independently verified |
| Ubuntu | Expected to work (same systemd/apt base) — not independently verified |

This table will grow as real users report successful installs on other
distributions (see [supported platforms](ADVANCED.md#supported-platforms)
for the full detail, and [CONTRIBUTING.md](CONTRIBUTING.md) to send a
compatibility report).

## Quick start

You need: a supported Pi/Debian/Ubuntu host that stays powered on, and about
five minutes.

**1. SSH into the host** (skip this if it has its own screen and keyboard):

```bash
ssh user@192.168.1.50
```

**2. Install the latest release:**

```bash
curl -fLO https://github.com/benukas/Linkmoth/releases/download/v0.2.5/linkmoth-v0.2.5-bootstrap.sh
sudo bash linkmoth-v0.2.5-bootstrap.sh
```

This checks your environment, sets up a hardened systemd service, and prints
the dashboard address and a one-time setup token when it's done.
No Git checkout, package manager, or Cosign installation is needed. Want the
build cryptographically verified instead of just checksum-checked? See
[ADVANCED.md](ADVANCED.md#sigstore-verified-installation).

**3. Open the dashboard** at the address the installer printed
(`https://<host-ip>:8686`). Your browser will warn about the certificate;
that's expected for a brand-new install. Before trusting it, compare the
fingerprint the installer printed against what the browser shows; full
step-by-step instructions per device are in
[ADVANCED.md](ADVANCED.md#tls-certificates). Then paste the setup token,
pick a password (12+ characters), and press **Diagnose now**. You should see
a green "All clear" within a few seconds.

That's it. Linkmoth already checks the network on its own and opens
incidents when it finds a fault.

**4. Already run a monitor? Connect it (optional).** Uptime Kuma, Zabbix,
Grafana alerting, or any tool/script that can send a webhook works (tested
primarily with Uptime Kuma). In your monitor, add a webhook notification
pointed at the same address printed by the installer, replacing `/setup`
with `/trigger`: `https://<host-ip>:8686/trigger`. A LAN address can be used
by monitors on this host or elsewhere on the LAN. If the installer printed
`127.0.0.1`, only software running on the Linkmoth host can reach it. Use
content type `application/json`, header
`Authorization: Bearer <webhook-secret>` (the installer printed this secret;
reprint it with `sudo -u linkmoth python3 /opt/linkmoth/linkmoth.py
--auth-show-webhook`). Now any monitor going down makes Linkmoth diagnose
the network too. A richer, alert-suppressing integration (including a
dedicated Uptime Kuma endpoint) is in
[ADVANCED.md](ADVANCED.md#connecting-a-monitor-uptime-kuma-or-anything-else).

## What makes it different

Most monitors just answer "is it down?" Linkmoth checks host power, local
link, router, local DNS, upstream DNS, raw internet reachability, and HTTPS
in dependency order (plus Wi-Fi client pings, if you configure them), so it
can tell you where the failure actually started.

A few other things it does:

- Shows Linkmoth's own CPU, temperature, RAM, and disk use in the header, so
  an overloaded Pi doesn't get mistaken for a network fault.
- Keeps a full evidence trail per incident: the trigger, rechecks, which
  rungs changed, the recovery, and a readable reference number.
- Defers noisy service alerts during a confirmed network-wide outage and
  summarizes them once it recovers.

## Scope and security

Linkmoth is built for **one administrator on a trusted home LAN** — it is
not intended for multi-tenant use, and it should not be directly exposed to
the internet (no port forwards, no public tunnels). It refuses direct
requests from a public/global source IP as a safety net (see
[Security posture](ADVANCED.md#security-posture)), but that guard is an
application-layer check, not a substitute for your own firewall or
reverse-proxy configuration — it doesn't make internet exposure safe on its
own.

**Before a major upgrade, back up `/var/lib/linkmoth`** (and `/etc/linkmoth`
for its configuration); see
[backup and restore](ADVANCED.md#backup-and-restore) for the exact commands.

## Learn more

[ADVANCED.md](ADVANCED.md) covers everything that didn't fit here:
configuration reference, the full Uptime Kuma/Discord/webhook integration,
TLS certificate trust (do this properly, since it's the one step where a LAN
attacker could trick you), the CLI, security posture, updating, backups,
uninstalling, and troubleshooting.

## Reporting issues

- **Bugs and compatibility reports:** open a
  [GitHub Issue](https://github.com/benukas/linkmoth/issues) — see
  [CONTRIBUTING.md](CONTRIBUTING.md) for what makes a report useful (version,
  distribution, safe reproduction steps).
- **Security vulnerabilities:** do **not** use a public issue. Follow the
  private reporting process in [SECURITY.md](SECURITY.md) instead.

Before filing a **public** bug report, attach the dashboard's
**Download support-safe JSON** export (Settings → Evidence exports) — it
removes credentials and pseudonymizes private-network identifiers, unlike
the plain support summary below. For **private** security reports or direct
maintainer contact, a plain-text support summary (Settings → **Copy support
summary**, or the same button on any incident) is also useful; it excludes
credentials but can still show real LAN IPs and network layout, so keep it
out of public issues. It looks like this:

```
Linkmoth support summary
Time: 2026-07-14T09:12:03.000Z
Incident: LM-2026-0142
Verdict: Router isn't answering on the LAN (router_down, critical)
Confidence: high
Why: Three consecutive router probes timed out after local DNS also failed.
Next step: Power-cycle the router; if it stays down, contact your ISP.

Fault ladder:
- [FAIL] Router: no response on 3/3 probes
  - FAIL 192.168.1.1: timeout
- [SKIP] Local DNS: not reached (router already failed)

Generated locally by Linkmoth. Credentials are excluded; this summary may include local network addresses.
```

`sudo -u linkmoth python3 /opt/linkmoth/linkmoth.py --doctor` (environment
and health check, no secrets) is also useful to attach for either audience.

## License, attribution, and official development

- Copyright © 2026 **Benas Urniežius**. Linkmoth is released under the
  [GNU Affero General Public License v3.0 only](LICENSE) (AGPL-3.0-only):
  public modified versions must remain under AGPL, including when offered to
  users over a network. The software is provided without warranty or liability
  to the extent the law allows.
- Linkmoth does **not** accept external code contributions into the official
  project. Pull requests will be closed without review; see
  [Reporting issues](#reporting-issues) above for bug reports.
- The Linkmoth name and logos are not granted by the AGPL. Forks must not imply
  that they are official Linkmoth releases; see [TRADEMARKS.md](TRADEMARKS.md).
- Third-party code and algorithm acknowledgements are recorded in
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- This repository is the public source for the official project. Future
  commercial editions may be offered separately under different terms by the
  copyright holder; already released AGPL versions remain AGPL.

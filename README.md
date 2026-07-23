# Linkmoth

<img src="linkmoth-white.svg" alt="Linkmoth" width="180">

[![CI](https://github.com/benukas/Linkmoth/actions/workflows/ci.yml/badge.svg)](https://github.com/benukas/Linkmoth/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-3776AB.svg)](https://www.python.org/)
[![Status: Early Access / Beta](https://img.shields.io/badge/status-early--access%20%2F%20beta-orange.svg)](CHANGELOG.md)

**A flight recorder for your home internet.** Linkmoth runs on a small
always-on Linux box (a Raspberry Pi is perfect), watches the network by
itself, and when something breaks it tells you **whose fault it is** in
plain language:

- *"Local DNS resolver stopped answering – internet itself is fine"*
- *"Internet is dead beyond the router – likely internet provider outage or router WAN cable fault"*
- *"Router isn't answering on the LAN"*
- *"Nothing wrong seen from the network side"* (false alarm)

<!-- TODO: 15-second demo GIF here – fault appears, ladder pinpoints it,
     verdict + evidence packet, recovery. Worth more than any paragraph. -->

Everything runs and stays on your LAN: no cloud account, no telemetry, no
subscription, standard-library Python only.

## What it does, on its own

Linkmoth is a standalone appliance. It needs no other monitoring software –
though it will happily [pair with one you already run](#already-running-a-monitor-optional).

- **Finds the failing layer, not just "it's down."** Host power, own link,
  router, router Wi-Fi, local DNS, upstream DNS, raw internet reachability,
  and HTTPS are checked in dependency order, so the verdict points at where
  the failure *started* – and every verdict comes with a "what to do next"
  playbook, safest steps first.
- **Keeps evidence.** Every incident gets a readable reference
  (`INC-20260705-0042`), its trigger, every recheck, which rungs changed,
  the recovery, an honest confidence statement, and a plain-language story
  paragraph you can paste into a chat – exportable with credentials removed.
- **Turns history into ammunition.** The accountability report totals your
  downtime, blames the right layer, spots time-of-day clustering, and writes
  a copyable evidence letter for your ISP support ticket (CSV export
  included).
- **Watches connection quality, not just up/down.** Latency, jitter, and
  packet loss are sampled continuously, classified good/fair/poor, and
  summarized in plain language ("evening latency is 3× worse than
  morning") – plus an on-demand **bufferbloat test** that grades how your
  line holds up under load.
- **Monitors your LAN devices** – printer, NAS, access point – with
  debounced up/down alerts that never pollute the network verdict.
- **Tells you – or politely doesn't.** Discord, browser push, ntfy, Gotify,
  Slack, Home Assistant, n8n, or any webhook. Quiet hours hold alerts
  overnight and deliver one morning digest.
- **Knows when the messenger is down.** During a confirmed network-wide
  outage, outbound alerts queue in SQLite and deliver the moment the WAN
  returns, marked as delayed.
- **Shows its own health** (CPU, temperature, RAM, disk) in the header, so
  an overloaded Pi doesn't get mistaken for a network fault.
- **Fits your homelab.** A Prometheus `/metrics` endpoint and scoped
  read-only API tokens (for Homepage/Glance widgets and Home Assistant
  sensors) – both read-only and token-gated.

**Linkmoth is early access / beta.** It's actively developed by a single
maintainer; expect rough edges, and please report what you find (see
[Reporting issues](#reporting-issues) below). See
[CHANGELOG.md](CHANGELOG.md) for recent changes.

| OS | Status |
| --- | --- |
| Raspberry Pi OS (Raspberry Pi 5) | Tested |
| Debian | Expected to work (same systemd/apt base) – not independently verified |
| Ubuntu | Expected to work (same systemd/apt base) – not independently verified |

This table will grow as real users report successful installs on other
distributions (see [supported platforms](ADVANCED.md#supported-platforms)
for the full detail, and [CONTRIBUTING.md](CONTRIBUTING.md) to send a
compatibility report).

## Quick start

You need: a supported Pi/Debian/Ubuntu host that stays powered on and about
five minutes. The normal installation does not require Cosign.

**1. SSH into the host** (skip this if it has its own screen and keyboard):

```bash
ssh user@<host-ip>
```

**2. Install the latest release:**

```bash
curl -fsSLo linkmoth-v0.4.11-bootstrap.sh --proto '=https' --noproxy '*' --max-redirs 0 https://raw.githubusercontent.com/benukas/Linkmoth/v0.4.11/bootstrap.sh && sudo bash linkmoth-v0.4.11-bootstrap.sh
```

The bootstrap comes directly from the exact protected `v0.4.11` tag and refuses
redirects. It downloads the exact `v0.4.11` archive and its published
SHA-256 file from the official GitHub Release, validates the checksum before
extracting the archive or running its installer, and records the result as a
**Checksum-verified release**. It also validates the complete archive against
the release manifest before it installs a hardened systemd service. It prints
the dashboard address and a one-time setup token when it's done. No Git checkout,
separate package-manager command, or Cosign binary is needed. See
[ADVANCED.md](ADVANCED.md#checksum-verified-installation) for the security model
and the optional Sigstore-verified mode.

**3. Open the dashboard** at the address the installer printed
(`https://<host-ip>:8686`). Your browser will warn about the certificate;
that's expected for a brand-new install. Before trusting it, compare the
fingerprint the installer printed against what the browser shows; full
step-by-step instructions per device are in
[ADVANCED.md](ADVANCED.md#tls-certificates). Then paste the setup token,
pick a password (12+ characters), and press **Diagnose now**. You should see
a green "All clear" within a few seconds.

That's it. Linkmoth is already checking the network on its own, opens
incidents when it finds a fault, and keeps the evidence.

## Already running a monitor? (optional)

Linkmoth diagnoses the network without any help. But if you already run
Uptime Kuma, Zabbix, Grafana alerting, or any tool/script that can send a
webhook, you can point it at Linkmoth so that when *your* monitor notices
something is down, Linkmoth immediately works out *why* – and suppresses the
noisy per-service alerts during a confirmed network-wide outage, summarizing
them once after recovery.

In your monitor, add a webhook notification pointed at the address the
installer printed, replacing `/setup` with `/trigger`:
`https://<host-ip>:8686/trigger`. Use content type `application/json` and the
header `Authorization: Bearer <webhook-secret>` (the installer printed this
secret; reprint it with `sudo -u linkmoth python3 /opt/linkmoth/linkmoth.py
--auth-show-webhook`). If the installer printed `127.0.0.1`, only software on
the Linkmoth host itself can reach it.

The richer integration – including a dedicated Uptime Kuma endpoint that
understands its native payload and forwards clean alerts to Discord – is in
[ADVANCED.md](ADVANCED.md#connecting-a-monitor-uptime-kuma-or-anything-else).

## What makes it different

Most tools answer "is it down?" Your ISP's app answers "have you tried
rebooting the router?" Linkmoth answers the question you actually have at
11 pm: **what, specifically, is broken – and is it something I can fix, or
something I should be on the phone about?**

It does that by checking the network in dependency order (plus Wi-Fi client
pings, if you configure them), keeping a full evidence trail per incident,
and refusing to guess: verdicts state their confidence and its limits, a
lone ambiguous witness is a warning rather than proof, and "nothing wrong
seen from the network side" is a first-class answer.

## Scope and security

Linkmoth is built for **one administrator on a trusted home LAN** – it is
not intended for multi-tenant use, and it should not be directly exposed to
the internet (no port forwards, no public tunnels). It refuses direct
requests from a public/global source IP as a safety net (see
[Security posture](ADVANCED.md#security-posture)), but that guard is an
application-layer check, not a substitute for your own firewall or
reverse-proxy configuration – it doesn't make internet exposure safe on its
own.

**Before a major upgrade, back up `/var/lib/linkmoth`** (and `/etc/linkmoth`
for its configuration); see
[backup and restore](ADVANCED.md#backup-and-restore) for the exact commands.

## Learn more

[ADVANCED.md](ADVANCED.md) covers everything that didn't fit here:
configuration reference, how the fault ladder works, LAN device monitoring,
connecting an existing monitor, outbound webhooks, TLS certificate trust (do
this properly, since it's the one step where a LAN attacker could trick
you), the CLI, security posture, updating, backups, uninstalling, and
troubleshooting.

## Reporting issues

- **Bugs and compatibility reports:** open a
  [GitHub Issue](https://github.com/benukas/Linkmoth/issues) – see
  [CONTRIBUTING.md](CONTRIBUTING.md) for what makes a report useful (version,
  distribution, safe reproduction steps).
- **Security vulnerabilities:** do **not** use a public issue. Follow the
  private reporting process in [SECURITY.md](SECURITY.md) instead.

Before filing a **public** bug report, attach the dashboard's
**Download support-safe JSON** export (Settings → Evidence exports) – it
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

## Supporting Linkmoth

If Linkmoth called an outage correctly for you – or better, helped you win
an argument with your ISP – the most useful things you can do today are
starring the repository, reporting a compatibility result for your
distribution, and telling the story where other people with flaky internet
will find it.

<!-- TODO: add a funding link here (GitHub Sponsors / Ko-fi / Liberapay)
     and a .github/FUNDING.yml so the repo shows a Sponsor button. -->

## License, attribution, and official development

- Copyright © 2026 **Benas Urniežius**. Linkmoth is released under the
  [GNU Affero General Public License v3.0 only](LICENSE) (AGPL-3.0-only):
  public modified versions must remain under AGPL, including when offered to
  users over a network. The software is provided without warranty or liability
  to the extent the law allows.
- Linkmoth accepts external pull requests, but review happens at the
  maintainer's own pace and merging is not guaranteed. A good pull request
  may ship in a future update – there's no promise of if or when; see
  [CONTRIBUTING.md](CONTRIBUTING.md).
- The Linkmoth name and logos are not granted by the AGPL. Forks must not imply
  that they are official Linkmoth releases; see [TRADEMARKS.md](TRADEMARKS.md).
- Third-party code and algorithm acknowledgements are recorded in
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- This repository is the public source for the official project. Future
  commercial editions may be offered separately under different terms by the
  copyright holder; already released AGPL versions remain AGPL.

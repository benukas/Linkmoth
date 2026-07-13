# Linkmoth

<img src="linkmoth-white.svg" alt="Linkmoth" width="180">

[![CI](https://github.com/benukas/linkmoth/actions/workflows/ci.yml/badge.svg)](https://github.com/benukas/linkmoth/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-3776AB.svg)](https://www.python.org/)

A network flight recorder for your home LAN. It sits idle until something
breaks, then runs a layered fault ladder and tells you **whose fault it is**
in plain language:

- *"Local DNS resolver stopped answering — internet itself is fine"*
- *"Internet is dead beyond the router — likely internet provider outage or router WAN cable fault"*
- *"Router isn't answering on the LAN"*
- *"Nothing wrong seen from the network side"* (false alarm)

It is the diagnosis layer that pairs with a watcher like
[Uptime Kuma](https://github.com/louislam/uptime-kuma): Uptime Kuma notices *that*
something is down and pokes Linkmoth, which then works out *why*, records
the whole incident timeline, and shows it on a simple LAN-only dashboard.

Linkmoth is currently supported on always-on **Raspberry Pi OS, Debian, and
Ubuntu** systemd hosts. Fedora, Arch, and openSUSE are best-effort only until
they are covered by release testing. Requires **systemd**, **`ip`**
(iproute2/iproute), and **root** for install. Alpine, OpenWrt, containers, and
NAS appliances are not supported yet.
Board-specific extras (power telemetry) switch off when the hardware does not
expose them.

Everything is local and dependency-free: the core runs on the Python
standard library alone — the installer never touches pip. (Browser push is
the one optional extra; `install.sh --with-push` sets it up in a private
virtualenv.) The only packets that leave your network are the connectivity
probes themselves and notification webhooks you configure.

See [CHANGELOG.md](CHANGELOG.md) for the current unreleased security,
authentication, onboarding, and TLS changes.

## Quick start

You need: a supported **Raspberry Pi OS, Debian, or Ubuntu** host on your home
network that stays powered on, and about five minutes.

### 1. Open a terminal on the box

If it has a keyboard and screen, open its Terminal app. Otherwise
connect from another computer on the same network:

```bash
ssh user@192.168.1.50
```

Replace `user` with the machine's login name and the address with its LAN IP
or hostname (`hostname -I` on the box, or your router's device list). On
**Raspberry Pi OS**, the default user is often `pi` and `raspberrypi.local`
may work via mDNS; enable SSH in `raspi-config` if it is disabled.

### 2. Install the signed release

Install [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/)
once from its official instructions, then run these commands on the Linkmoth
host. They download the versioned bootstrap script, verify its Sigstore
signature, and only then start the installer:

```bash
VERSION=v0.2.0
BASE="https://github.com/benukas/Linkmoth/releases/download/$VERSION"
curl -fLO "$BASE/linkmoth-$VERSION-bootstrap.sh"
curl -fLO "$BASE/linkmoth-$VERSION-bootstrap.sh.bundle"
cosign verify-blob \
  --bundle "linkmoth-$VERSION-bootstrap.sh.bundle" \
  --certificate-identity "https://github.com/benukas/Linkmoth/.github/workflows/release.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "linkmoth-$VERSION-bootstrap.sh"
sudo bash "linkmoth-$VERSION-bootstrap.sh"
```

Enter your password if asked. The installer checks your environment
(`--doctor`), installs any missing tools, creates a dedicated service user,
sets up a hardened systemd service that starts on boot, and finishes by
printing the dashboard address. If anything is wrong it says exactly what
and stops before touching your system.

### 3. Open the dashboard

From any device at home, browse to `https://<host-ip>:8686` (the installer
printed the exact address). You should see the Linkmoth logo in the browser tab and page header once the page loads. First import and verify the CA certificate as
described under **TLS certificates** below; do not enter a password through a
certificate warning. On first launch, paste the one-time setup token
printed by the installer and create an admin password of at least 12
characters. The token expires after 24 hours and is destroyed as soon as setup
finishes. Then press **Diagnose now** — you should see a green "All clear"
verdict with the full fault ladder within a few seconds.

### 5. Connect Uptime Kuma (optional but recommended)

If Uptime Kuma runs on the same host, open it and go to
**Settings → Notifications → Setup Notification → Webhook**, set the URL to
`https://127.0.0.1:8686/trigger`, content type `application/json`, and tick
*Default enabled*. Add `Authorization: Bearer <webhook-secret>` to the
webhook's request headers — the installer printed this secret at the end of
setup; reprint it anytime with `sudo -u linkmoth python3 /opt/linkmoth/linkmoth.py
--auth-show-webhook` (see **CLI** below). From then on, any monitor going
down makes Linkmoth diagnose the network automatically — that's the whole point.

For richer integration (service alerts forwarded to Discord only when the
network path is healthy, and silenced during WAN/router outages), point a
second webhook at `https://127.0.0.1:8686/api/webhooks/kuma` with the same
bearer header. See **Uptime Kuma integration** below.

## What makes it different

Most monitors answer **"is it down?"** Linkmoth is built to answer **"where did
the failure begin, and what evidence supports that?"**

- **Layered fault attribution:** host power, local link, router, Wi-Fi, local
  DNS, upstream DNS, raw internet reachability, and HTTPS are evaluated in
  dependency order instead of collapsed into one red/green check.
- **Observer-aware confidence:** Linkmoth records when its own host or link is
  unhealthy, so downstream conclusions are not presented with false certainty.
- **Host health at a glance:** the header shows Linkmoth’s CPU use, hottest
  thermal sensor, RAM use, and root-disk use. This helps distinguish a network
  fault from an overloaded or overheating Pi; absent sensors display as `—`.
- **Incident evidence, not just alerts:** each incident keeps its trigger,
  rechecks, changed rungs, recovery, and a readable reference number.
- **Outage-aware alert mediation:** the Uptime Kuma proxy can defer noisy
  service alerts during a confirmed network-wide outage and summarize them
  after recovery.
- **Local-first operation:** the core is standard-library Python, has no cloud
  account or telemetry, and keeps diagnosis history on the appliance.

## How it works

On a trigger (Uptime Kuma webhook, dashboard button, or a background baseline
run) Linkmoth runs the fault ladder — host power (including PoE/USB-PD telemetry
when present) → own link (speed/duplex negotiation) → router → optional
router Wi-Fi client pings → Local DNS resolver → upstream DNS by IP → raw
ping → HTTPS — and maps the evidence pattern to one verdict. Redundant DNS,
ping, HTTPS, and Wi-Fi-witness probes keep every target result: an amber rung
means a usable path exists but the targets disagree. A successful HTTPS probe
also prevents filtered ping/direct-DNS traffic from being called a total WAN
outage. During an incident it re-checks at +30 s, +1 m,
+2 m, +5 m, then every 10 min until two consecutive all-clears, and stores
every run.

Each incident gets a human-readable reference such as `INC-20260705-0042`
(shown in the dashboard, Discord alerts, and searchable from the History tab).
When a ladder step fails, Linkmoth can drill down with **micro-steps**. The
Local DNS rung is provider-neutral: same-host Pi-hole, Unbound, and dnsmasq
installations can add service evidence and an appropriate repair hint, while
every other resolver uses generic DNS guidance. The selected adapter never
changes the rung result or network verdict.

Background **latency history** samples run on a separate interval from
**baseline** incident detection: sparklines update from the history interval;
baseline only controls how often Linkmoth may auto-open an incident when idle.
Set `baseline_minutes` to `0` to disable unsolicited incident opening.

When many Uptime Kuma monitors fire at once, a **10-second ladder cache**
(with request coalescing) reuses the first diagnosis instead of hammering the
network with duplicate pings.

The dashboard has five tabs: **Today** (current verdict, open-incident
reference, fault ladder, latency trends, blame board), **History** (filterable
timeline — paste an incident reference to jump straight to its evidence
packet: verdict confidence **and why it is limited**, the first failed
dependency, what Linkmoth ruled out, a plain-English diff vs the last healthy
check, and repeat-fault evidence (typical duration and recurrence timing), and
every diagnosis run with raw per-rung timings), **Devices** (independent LAN
device status), **Settings** (including Discord webhooks, Wi-Fi client IPs,
and SQLite maintenance), and **Security**. Today and incident packets can copy
a credential-free plain-text support summary with the verdict, confidence,
per-target evidence, and timeline.

## LAN devices

The **Devices** tab watches selected LAN equipment without feeding those
results into network blame, incidents, network statistics, or network
History. Device monitoring is deliberately smaller than the fixed network
ladder:

- **Generic** — ping.
- **Printer** — ping plus TCP port 9100.
- **Web UI** — ping plus an HTTP or HTTPS status and optional body check.
- **TCP service** — ping plus one configured TCP port.

Targets must be literal RFC1918 IPv4 addresses in `10.0.0.0/8`,
`172.16.0.0/12`, or `192.168.0.0/16`. Linkmoth rejects hostnames, IPv6,
loopback, link-local, multicast, unspecified, and public targets. This keeps
the feature LAN-only and avoids DNS rebinding and hostname-based SSRF.

Automatic checks are off by default. Available intervals are 5, 15, 30, and
60 minutes. Two consecutive scheduled failures are required before a device
is considered unhealthy; two consecutive successes confirm recovery. Manual
**Run now** checks update the displayed result and short history but never
advance alert counters.

Per-device Discord, browser-push, and generic-webhook alerts are also off by
default and work only when the corresponding global integration is enabled.
Device runs have a bounded recent log rather than incidents.

HTTP checks do not follow redirects, stop after 64 KiB, and time out within
10 seconds. HTTPS certificate verification is on by default. The Web UI
preset can explicitly allow an untrusted certificate for a self-signed LAN
appliance, but doing so encrypts traffic without verifying the appliance's
identity; the dashboard displays this as an unsafe mode.

## Uptime Kuma integration

**Important:** point Uptime Kuma at Linkmoth on the **LAN**, not over WAN:

```text
https://127.0.0.1:8686/api/webhooks/kuma
```

Kuma monitors need the internet to check external sites, but **webhook delivery
to Linkmoth uses localhost** and works while WAN is down. During a WAN outage,
**Linkmoth** (not Kuma) detects the fault and queues suppressed service alerts;
Discord/push/generic webhooks fire when the link returns.

| Endpoint | Purpose |
| --- | --- |
| `POST /trigger` | Diagnose-only: Uptime Kuma pokes Linkmoth; no Discord proxy logic |
| `POST /api/webhooks/kuma` | Smart proxy: runs the fault ladder, **suppresses** service alerts when the WAN/router/host link is down (queues them for a recovery digest), **forwards** to Discord when the network path looks healthy |
| `POST /api/webhooks/inbound` | Generic inbound: Grafana, Zabbix, or any script triggers a Linkmoth diagnosis (same suppression logic, no Discord forwarding) |

All require `Authorization: Bearer <webhook-secret>`. When Uptime Kuma sends
many alerts in a burst, Linkmoth shares one ladder result for 10 seconds
(`ladder_cache_seconds`) so the Linkmoth host is not overwhelmed.

### Generic inbound webhook

Anything that can POST JSON can ask Linkmoth "is it the network, or just you?":

```bash
curl -k -X POST https://linkmoth.local:8686/api/webhooks/inbound \
  -H "Authorization: Bearer $(sudo -u linkmoth python3 /opt/linkmoth/linkmoth.py --auth-show-webhook)" \
  -H "Content-Type: application/json" \
  -d '{"source":"grafana","event":"down","monitor":"Cloudflare HTTPS","message":"probe timeout"}'
```

`event` words `down`/`alert`/`fault`/`problem`/`firing` open (or feed) an
incident; `up`/`recovered`/`resolved`/`ok` note a recovery. During a global
outage the alert is suppressed into the recovery digest instead. The Settings
tab has a **Copy curl test** button that produces this command with the secret
filled in.

Optional **Discord notifications** (Settings → Notification Integrations)
send rich embeds on confirmed faults and recoveries, including the fault
ladder, incident reference, and a digest of services that were down during a
global outage. **Global outages defer outbound alerts** until recovery.

**Browser push** (Settings → Browser push) is opt-in: run
`sudo bash install.sh --with-push` once to set it up (it installs
`pywebpush` into a private virtualenv, leaving system Python untouched).
Works on desktop and Android in the browser. On iPhone/iPad you must install
the dashboard to the Home Screen first (Share → Add to Home Screen), open it
from the icon, then enable push — Safari tabs cannot subscribe. iOS also
requires **both** steps of CA trust (profile install **and** Certificate Trust
Settings); desktop browsers are often more forgiving, which is why push can
work on a laptop but fail on a phone with the same hostname.

### Outbound webhooks

**Settings → Outbound webhooks** manages up to 20 outbound integrations, each
with its own preset, event subscriptions, custom headers, and test buttons
(**Send test fault** / **Send test recovery**).

Presets: **Generic JSON**, **ntfy** (title/priority/tags headers), **Gotify**
(title/message/priority), **Home Assistant** (webhook trigger), **Discord**
(embed), **Slack** (also fits Mattermost/Rocket.Chat), **n8n / Node-RED**, and
**Custom template**.

Event types you can subscribe to per webhook: `fault_opened`, `fault_updated`,
`fault_recovered`, `fault_closed`, `degradation_detected`, `diagnosis_run`,
`false_alarm_marked`, `device_down`, `device_recovered`.

The Generic JSON payload carries machine-readable fields alongside the human
text:

```json
{
  "event": "fault_opened",
  "incident_id": "INC-20260707-0001",
  "verdict": "wan_down",
  "severity": "bad",
  "confidence": "high",
  "duration_seconds": 0,
  "affected_layer": "wan",
  "source": "linkmoth",
  "title": "Internet (WAN) is down",
  "body": "…",
  "message": "…",
  "timestamp": "2026-07-07T12:00:00Z",
  "delayed": false,
  "queued_at": "2026-07-07T12:00:00Z"
}
```

**Custom templates** are plain placeholder substitution (no logic):
`{{event}}`, `{{event_label}}`, `{{status}}`, `{{severity}}`, `{{verdict}}`,
`{{verdict_title}}`, `{{title}}`, `{{body}}`, `{{summary}}`, `{{hint}}`,
`{{incident_id}}`, `{{incident_started}}`, `{{source}}`, `{{confidence}}`,
`{{duration_seconds}}`, `{{affected_layer}}`, `{{timestamp}}`,
`{{timestamp_unix}}`, `{{delayed}}`, `{{queued_at}}`. Values are JSON-escaped;
`duration_seconds`, `timestamp_unix`, and `delayed` are inserted raw.

**Retry queue.** Linkmoth is about outages, so webhook deliveries never rely on
the network being up: every event is queued in SQLite and a background sender
delivers it. Failures back off (30 s → 2 m → 10 m → 30 m → 1 h, up to 10
attempts, dropped after 24 h), and while a **global outage** is active nothing
is attempted — the queue drains the moment the WAN recovers, with late
deliveries marked `"delayed": true` / a delayed-delivery note. Queue state
("3 queued · next retry in 2 min") is visible on each webhook in Settings.

**Webhook URLs and custom headers** (for example `Authorization: Bearer xxx`)
are stored server-side and treated as secrets: after saving, the API and UI
show the URL as `••••••••` and header values as `••••••••abcd`. Leave a masked
value untouched when editing to keep the stored secret. Delivery connections
ignore environment proxies and do not follow redirects, preventing credentials
from being forwarded to another destination.

The old single "Generic webhook" setting is migrated automatically on upgrade
into one **Generic JSON** webhook subscribed to the events it used to receive.

## Configuration — /etc/linkmoth/config.json

| Field | Default | Meaning |
| --- | --- | --- |
| `bind`, `port` | auto-detected LAN IP (otherwise loopback), `8686` | Where the dashboard/API listens — see below |
| `tls_cert`, `tls_key` | `/etc/linkmoth/tls/server.crt`, `server.key` | Required TLS certificate and private key |
| `tls_ca` | `/etc/linkmoth/tls/ca.crt` | CA certificate served (unauthenticated) at `/ca.crt` for device trust |
| `dns_test_domain` | `gstatic.com` | Domain used for DNS checks |
| `local_dns` | object | Local resolver `mode`, IPv4 `address`, and same-host `provider`; see below |
| `upstream_dns` | `1.1.1.1`, `8.8.8.8` | Resolvers queried directly, bypassing local DNS |
| `ping_targets` | `1.1.1.1`, `8.8.8.8` | Raw-connectivity ping targets |
| `https_targets` | gstatic, cloudflare | URLs fetched for the web check |
| `recheck_seconds` | `0,30,60,120,300` | Re-check schedule after a trigger |
| `recheck_repeat` | `600` | Interval after the schedule is exhausted |
| `incident_max_hours` | `24` | Safety cap on one incident's re-check loop |
| `baseline_minutes` | `60` | How often idle Linkmoth may auto-open an incident (`0` = off) |
| `history_sample_minutes` | `5` | Background diagnosis interval for latency graphs (`0` = use baseline only) |
| `ladder_cache_seconds` | `10` | In-memory reuse window when many webhooks hit at once |
| `retention_days` | `90` | History kept in SQLite before cleanup |
| `kuma_url` | `"auto"` | Dashboard Uptime Kuma link: `auto` = same host port 3001, `""` = hide, or a full URL |
| `ui_refresh_seconds` | `5` | How often the dashboard re-fetches data (not new network checks) |
| `target_wifi_clients` | `[]` | Always-on Wi-Fi device IPs; silent clients after router LAN check → WLAN rung fails |
| `discord_webhook_url` | `""` | Discord webhook for fault/recovery alerts (optional) |
| `discord_notifications_enabled` | `false` | Enable Discord alerts (requires valid webhook URL) |
| `push_notifications_enabled` | `true` | Enable browser push notifications |
| `notify_webhook_url` | `""` | Legacy single-webhook URL — migrated once into Settings → Outbound webhooks, then unused |
| `notify_webhook_enabled` | `false` | Legacy flag for the above (kept so old configs stay valid) |

Restart after editing `/etc/linkmoth/config.json`: `sudo systemctl restart linkmoth`

### Bind address: why not always `0.0.0.0`

`0.0.0.0` listens on **every** network interface the host has — not just the
LAN one. On a host that also runs a VPN client (WireGuard, Tailscale,
NordVPN's `nordlynx`), that means Linkmoth becomes reachable over that tunnel
too, with no router port-forward involved and nothing for Linkmoth to detect
after the fact.

`install.sh` handles this automatically on a fresh install: it inspects the
host's interfaces, excludes loopback, VPN/tunnel, and container-bridge
(Docker/Podman) interfaces, and — if exactly one LAN interface remains —
binds to that address instead of `0.0.0.0`. If detection is ambiguous (zero
or multiple candidates, e.g. a genuinely multi-homed host), guided setup
defaults to `127.0.0.1`; non-interactive setup stops and requires
`--bind <LAN IPv4>`. Choosing `0.0.0.0` requires explicit confirmation.

`--doctor` (and therefore `install.sh`, which runs it as a gate) **fails**
if `bind` is `0.0.0.0` and a VPN/tunnel interface is present on the host —
this is treated as a real gap, not just a warning, so it has to be resolved
before install completes. Container bridges are lower severity (host-local,
not normally reachable from outside) and only produce an informational
note. The Security tab's posture panel shows the same check on every load,
so a VPN added *after* install doesn't go unnoticed.

Local DNS uses this shape:

```json
"local_dns": {
  "mode": "auto",
  "address": "127.0.0.1",
  "provider": "auto"
}
```

`mode` is `auto`, `enabled`, or `disabled`. `provider` is `auto`, `generic`,
`pihole`, `unbound`, or `dnsmasq`. Provider-specific behaviour is permitted
only when `address` belongs to the Linkmoth host. A remote private resolver is
always treated as generic—even if its configuration names a provider—because
Linkmoth can trust only its DNS response, not its remote service state. Linkmoth
never fingerprints or probes a remote resolver beyond the configured DNS
query. Legacy `"local_dns": "auto"` and `false` values remain accepted.

**Most settings don't need the file at all**: the dashboard **Settings** tab
covers the Uptime Kuma link, auto-refresh vs history sampling, baseline
interval, retention, Local DNS, upstream targets, Wi-Fi client IPs, Discord integration, and
**database maintenance** (file size, `AUTO_VACUUM` mode, manual **VACUUM**
button). Changes save privately (`0600`) to `/var/lib/linkmoth/settings.json`, override the config
file, and apply immediately — no restart. Network binding and authentication
options require editing `/etc/linkmoth/config.json` by hand and restarting
Linkmoth.

SQLite history and integration credentials live in the mode-`0600`
`/var/lib/linkmoth/state.db`. New databases enable
`AUTO_VACUUM=INCREMENTAL` and WAL journal mode; the daily janitor reclaims free pages after
retention cleanup. Manual **Run VACUUM** fully repacks the file when you
need to shrink it after bulk deletes.

## Network assumptions

- The host has a working default route (wired strongly recommended — a
  monitor on flaky WiFi blames the internet for its own hiccups).
- The ladder always calls the rung **Local DNS resolver**. Same-host Pi-hole,
  Unbound, and dnsmasq may provide extra local service evidence. Remote and
  unknown resolvers always receive generic guidance.
- Ethernet link speed and duplex are read from sysfs (with `ethtool` fallback);
  sub-gigabit or half-duplex links produce a warning without failing the rung.
- The host does **not** need to be the network's DNS server — it's a witness,
  not a dependency.
- `ping`, `ip`, and `systemctl` must exist (the installer handles most of this).
  DNS checks use a built-in resolver — no `dig` binary required.

## CLI

```bash
python3 linkmoth.py --doctor   # check environment without starting anything
python3 linkmoth.py --once     # run one diagnosis, print JSON verdict
python3 linkmoth.py            # run the server (dev mode: state/config in ./)
python3 linkmoth.py --auth-onboarding-token # show/create the first-run setup token
python3 linkmoth.py --auth-set-password   # set admin password (stored scrypt-hashed)
python3 linkmoth.py --auth-setup-totp     # generate TOTP secret + one-time recovery codes
python3 linkmoth.py --auth-show-webhook   # print webhook bearer secret for /trigger
python3 linkmoth.py --auth-rotate-webhook # rotate it and invalidate the old secret
python3 linkmoth.py --auth-audit 50       # show recent login/security events
```

## Ports and endpoints

- HTTPS `:8686` — dashboard (`/`), `GET /api/status`, `GET /api/incidents`,
  `GET /api/incident?id=N` or `?ref=INC-YYYYMMDD-NNNN` (full evidence packet),
  `POST /api/diagnose`, `POST /api/settings` (including `{ "action": "vacuum" }`
  for SQLite maintenance), `POST /trigger` (Uptime Kuma diagnose webhook),
  `POST /api/webhooks/kuma` (Uptime Kuma smart proxy),
  `POST /api/webhooks/inbound` (generic inbound trigger), `GET /health`
  (monitor this in Uptime Kuma).
- Devices: `GET/POST /api/devices`, `PUT/DELETE /api/devices/{id}`,
  `POST /api/devices/{id}/run`, and `GET /api/devices/{id}/history`.
- Outbound webhooks: `GET/POST /api/webhooks`, `PUT/DELETE /api/webhooks/{id}`,
  `POST /api/webhooks/{id}/test`, `GET /api/webhooks/inbound-info`, and
  `POST /api/incident/false-alarm`.
- Authentication: `GET /api/auth/status`, one-time `POST /api/auth/setup`,
  `POST /api/auth/login`, `POST /api/auth/totp`, `POST /api/auth/logout`.
- Security management (session + CSRF): `POST /api/auth/change-password`,
  `POST /api/auth/totp/{setup,activate,disable,recovery-codes}`;
  read-only `GET /api/auth/audit` and `GET /api/auth/security`.

## Authentication and first-time onboarding

Authentication is mandatory and cannot be disabled. Its `config.json` block
controls session and optional TOTP behavior:

```json
"auth": {
  "session_ttl_seconds": 86400,
  "session_idle_seconds": 1800,
  "login_max_attempts": 5,
  "login_lockout_seconds": 300,
  "trusted_proxy_cidrs": []
}
```

Sessions expire on two independent clocks, both enforced server-side: an
**idle timeout** (`session_idle_seconds`, default 30 min) and an **absolute
lifetime** (`session_ttl_seconds`, default 24 h). The session cookie is named
`__Host-linkmoth_session` (Secure, host-only, `Path=/`). The legacy
`auth.totp_enabled` flag is deprecated and ignored — 2FA state now lives in the
auth store and is toggled from the dashboard (below).

The former `auth.enabled` setting is ignored for safe upgrades; remove it from
older configuration files. An installation with no password enters onboarding
instead of exposing the dashboard.

The installer prints a random, one-use onboarding token. Open the dashboard,
paste that token, and choose a password of at least 12 characters. The token is
kept in the mode-`0600` auth store, expires after 24 hours, and is deleted after
successful setup. A random visitor cannot claim a fresh installation without
the token.

If the token expires or the installer output is lost, create another locally:

```bash
sudo -u linkmoth python3 /opt/linkmoth/linkmoth.py --auth-onboarding-token
```

For an intentional password reset, use `--auth-set-password`. Passwords must be
entered at the hidden prompt; Linkmoth rejects command-line password values so
they do not leak through shell history or process listings.

Dashboard data, history, diagnosis, and settings APIs always require a browser
session;
`/health` stays open for Uptime Kuma; `/trigger` requires
`Authorization: Bearer <webhook-secret>` (not the login cookie). Authenticated
state-changing POSTs require a CSRF header (`X-CSRF-Token`) matching the
session; the one-time setup POST uses the bootstrap token instead.

### Managing security from the dashboard

The **Security** tab manages everything without SSH:

- **Change password** (requires the current password).
- **Two-factor (TOTP)**: "Set up 2FA" displays an offline-generated QR code
  (with the secret and setup link as fallbacks), then asks for the first
  authenticator code. Recovery codes are generated and shown only after that
  code proves enrollment; save them before signing in again. Pending enrollment
  expires after 10 minutes. Disabling 2FA or regenerating recovery codes
  requires your password. Enabling/disabling 2FA and changing the password sign
  you out of all sessions on every device.
- **Audit log** of recent auth events, and a **posture** panel (network
  exposure, HTTPS, session timeouts, CA-certificate download).

The CLI path still works for headless/console recovery:

```bash
sudo -u linkmoth python3 /opt/linkmoth/linkmoth.py --auth-setup-totp   # immediate activation
```

TOTP codes cannot be replayed after successful use. Recovery codes are
single-use and stored hashed in `/var/lib/linkmoth/auth.json`.

Rotate a leaked or routinely aged webhook secret with:

```bash
sudo -u linkmoth python3 /opt/linkmoth/linkmoth.py --auth-rotate-webhook
```

The old secret stops working immediately. Update every Uptime Kuma webhook
before its next notification. To review recent auth activity:

```bash
sudo -u linkmoth python3 /opt/linkmoth/linkmoth.py --auth-audit 100
```

The audit contains timestamps, client addresses, and event names for login
success/failure, TOTP/recovery use, CSRF rejection, logout, and credential
changes—never passwords, TOTP values, recovery codes, cookies, or bearer
secrets. It is capped at 1,000 events and 90 days in `state.db`.

## TLS certificates

TLS is mandatory: Linkmoth refuses to listen if its certificate or private key
is missing or invalid, requires TLS 1.2 or newer, always marks session cookies
`Secure`, and sends HSTS.

The installer creates a private **Linkmoth Local CA** in `/etc/linkmoth/tls`, adds
that CA to the **host's** system trust store when possible, and issues a server
certificate covering `localhost`, the machine's hostnames, and its current IP
addresses. A hardened monthly systemd timer renews and verifies the server
certificate, keeps the same trusted CA, and restarts Linkmoth. If the host's IP
or hostname changes, renew immediately with:

```bash
sudo systemctl start linkmoth-cert-renew.service
```

Other devices must trust the Linkmoth CA **before** entering the password.
**This is the one step where a LAN attacker could trick you** — if you install
the wrong CA, every later check (green padlock, HSTS) is meaningless.

**Do not trust `/ca.crt` until you verify the fingerprint.** The installer
prints a line like:

```text
CA fingerprint: SHA256 Fingerprint=AA:BB:…
```

On each new phone, laptop, or tablet:

1. On a **trusted path** (SSH session on the Linkmoth host, or the installer
   scrollback you saved), note that SHA-256 fingerprint.
2. From the client device, download the CA only over the LAN — e.g. open
   **`https://<host-ip>:8686/ca.crt`**. The browser will warn because the
   cert is not trusted yet; that warning is expected.
3. **Before installing/trusting the downloaded file**, compute its SHA-256
   fingerprint on the client and confirm it **exactly matches** the installer
   output (see per-OS steps below). If it does not match, stop — something on
   the network may be intercepting you.
4. Only after the fingerprint matches, install the CA as a trusted root on
   that device.
5. Browse to **`https://<host-ip>:8686`** — the warning should not return on
   that device. Then sign in.

The installer repeats this at the end of every install. The sign-in page links
to `/ca.crt` for convenience, but **convenience is not verification** — always
check the fingerprint.

**Alternative:** copy the CA file from the Linkmoth host over SSH (same trust
assumption as step 1):

```bash
scp user@192.168.1.50:/usr/local/share/ca-certificates/linkmoth-local-ca.crt linkmoth-ca.crt
```

Verify the fingerprint of `linkmoth-ca.crt` the same way before importing.

**Checking the fingerprint**

```bash
# Linux / macOS (OpenSSL)
openssl x509 -in linkmoth-ca.crt -noout -fingerprint -sha256

# Windows (PowerShell)
(Get-Content linkmoth-ca.crt -Raw | openssl x509 -noout -fingerprint -sha256)
```

Compare character-for-character with the installer's `CA fingerprint:` line.
Do not bypass a certificate warning and enter credentials — a warning on the
dashboard (after you thought you trusted the CA) means the device still does
not recognize your Linkmoth instance.

### Per-OS trust (after fingerprint matches)

- **iOS / iPadOS:** install the profile, then Settings → General → About →
  Certificate Trust Settings → enable full trust for the Linkmoth CA.
- **Android:** Settings → Security → Install a certificate → CA certificate.
- **macOS:** Keychain Access → import → set the CA to *Always Trust* for SSL.
- **Windows:** certmgr → Trusted Root Certification Authorities → import.
- **Desktop browsers:** use the OS store when possible; Firefox may need its
  own Authorities import.

Native tools on the Linkmoth host trust the CA system-wide once the installer
runs. Uptime Kuma, containers, and other hosts may use a separate runtime
trust store; add the same CA there (for Node.js, `NODE_EXTRA_CA_CERTS` is one
option). Avoid disabling certificate verification except for a strictly
same-host loopback webhook. If you already operate a trusted certificate, set
`tls_cert` and `tls_key` to those files instead; the service user must be able
to read the key. Disable `linkmoth-cert-renew.timer` when using certificates
managed elsewhere.

### Reverse proxies (optional)

Proxy-supplied client addresses are ignored by default. If rate limiting must
distinguish clients behind a reverse proxy, configure that proxy to use HTTPS
to Linkmoth and trust the Linkmoth CA, then set:

```json
"trusted_proxy_cidrs": ["127.0.0.1/32", "::1/128"]
```

Only list networks that contain an actual trusted reverse proxy. Linkmoth accepts
`X-Forwarded-For` only when the immediate connection comes from one of those
networks; broad entries would let clients spoof their address and weaken login
throttling. Configure TLS versions, certificates, HSTS, and any remote-access
policy on the proxy. A VPN is still preferable to public internet exposure.

## Verified releases

Do not pipe an unversioned script from a branch into `sudo`. Every release
publishes a versioned bootstrap script, archive, checksum, and Sigstore bundles.
Install `cosign` from its official distribution, download the assets from the
chosen GitHub Release, verify the bootstrap bundle with the pinned GitHub
workflow identity, then run the verified local file with `sudo bash`. The
bootstrap repeats Sigstore verification for the archive and checksum before it
extracts or installs anything. Verification failure is a hard stop.

## Branding

The project icon is [`linkmoth.svg`](linkmoth.svg) (500×500 SVG) used as the
dashboard favicon and in the page header. [`linkmoth.svg`](linkmoth.svg) is
the same mark for contexts that don't support SVG (this README, social previews).
Linkmoth serves the following without authentication:

- `/linkmoth.svg` — preferred SVG favicon (modern browsers)
- `/favicon.ico` — legacy tab/bookmark icon, served from `linkmoth-white.ico`
- `/linkmoth.svg` — browser and PWA icon (SVG)

After the page loads, the browser tab and dashboard header show the Linkmoth logo. Re-run
`install.sh` after upgrading if an icon file was added in a newer release.

## Security posture

Linkmoth is a local-first appliance: no cloud account, no telemetry, and it does
not create cloud access, tunnels, or router port forwards on its own. It is
intended for local-network access only — Linkmoth cannot know whether a router
forward, reverse proxy, or IPv6 exposure has been added elsewhere on your
network, so don't rely on it to make internet exposure impossible. One case
Linkmoth *can* see and actively guards against: its own host running a VPN
client. `--doctor` refuses to pass, and the Security tab keeps warning, if
`bind` is `0.0.0.0` while a WireGuard/Tailscale/NordVPN-style interface is
present — see **Bind address** above.
The web UI ships with a restrictive Content-Security-Policy, clickjacking and
MIME-sniff protection, and escapes all externally-influenced strings before
rendering.

Authentication cannot be disabled. A single local admin account uses
scrypt-hashed passwords, server-side sessions with hashed session IDs
(HttpOnly, Secure, SameSite=Strict cookies), CSRF tokens on
state-changing POSTs, bounded request bodies, fail-fast bounded password-hash
work, login/onboarding/TOTP rate limiting, TOTP replay prevention, and a separate webhook bearer for
`/trigger`. Password or TOTP changes invalidate all sessions.

Secrets live in `/var/lib/linkmoth/auth.json` (the active onboarding token before
setup, password hash, webhook secret, optional TOTP seed, and hashed recovery
codes). Writes are atomic and Linkmoth
sets the file to mode `0600`; the systemd service also uses `UMask=0077`.
Backups containing this file are sensitive because the webhook secret and TOTP
seed must be available to the server in usable form.

The remaining trust boundary is deliberate: this is one shared admin account,
not multi-user authorization. The dashboard HTML/login shell is served before
login, but all diagnosis, history, and settings data stays behind the API
session check. `/health` remains public by design. Do not port-forward Linkmoth
directly.

Device endpoints use the same authentication and CSRF protections. Device
targets are restricted to the three RFC1918 IPv4 ranges; HTTP checks connect
directly without environment proxies or redirects, cap response size and
timeouts, and store no device credentials, headers, or executable content.

## Layout

- `/opt/linkmoth/` — code, dashboard, and `linkmoth.svg` (site icon)
- `/etc/linkmoth/config.json` — settings (`0640`, owned by `root:linkmoth`)
- `/etc/linkmoth/tls/` — local CA, server certificate, and private keys
- `linkmoth-cert-renew.timer` — monthly server-certificate renewal
- `/var/lib/linkmoth/state.db` — history and integration secrets (`0600`; protect backups)
- `/var/lib/linkmoth/auth.json` — auth secrets (`0600`; protect its backups)
- Runs as the dedicated no-login user `linkmoth` under systemd with
  `NoNewPrivileges` and filesystem protections; `CAP_NET_RAW` is granted so
  `ping` works despite the sandbox.

The installer also adds a polkit rule letting sudo-group users restart
`linkmoth.service` without a password (deploy convenience); pass
`--no-polkit` to skip it.

## License, attribution, and official development

- Copyright © 2026 **Benas Urniežius**. Linkmoth is released under the
  [GNU Affero General Public License v3.0 only](LICENSE) (AGPL-3.0-only):
  public modified versions must remain under AGPL, including when offered to
  users over a network. The software is provided without warranty or liability
  to the extent the law allows.
- Linkmoth does **not** accept external code contributions into the official
  project. Bug reports and reproducible issue reports are welcome; pull
  requests will be closed without review. See [CONTRIBUTING.md](CONTRIBUTING.md).
- The Linkmoth name and logos are not granted by the AGPL. Forks must not imply
  that they are official Linkmoth releases; see [TRADEMARKS.md](TRADEMARKS.md).
- Third-party code and algorithm acknowledgements are recorded in
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- Please report security issues privately following [SECURITY.md](SECURITY.md);
  do not publish working exploit details in a public issue.
- This repository is the public source for the official project. Future
  commercial editions may be offered separately under different terms by the
  copyright holder; already released AGPL versions remain AGPL.

## Updating

Get the new code (`git pull` in the cloned folder, or re-copy it), then
re-run the installer — it's safe to run repeatedly and never touches your
config or data:

```bash
cd linkmoth && git pull && sudo bash install.sh
```

When upgrading an installation that has no admin password, the dashboard is
locked immediately and the installer prints a first-time setup token. Existing
authenticated installations keep their password.

## Uninstall

```bash
sudo bash uninstall.sh          # keeps config + data
sudo bash uninstall.sh --purge  # removes everything
```

## Troubleshooting

**Network problems**: every fault verdict on the dashboard has a
**"What to do next — safest steps first"** playbook right under it (also
inside each incident's evidence packet in History). It starts with
non-disruptive checks, labels steps that interrupt users, states what success
should look like, and puts escalation last. Dynamic Local DNS and missing-route
evidence can insert a more specific first action. Run verification after each
change and stop when the linked rung turns green. Below is the recovery guide
for Linkmoth itself.

### First moves, always

- `journalctl -u linkmoth -f` — live logs
- `python3 /opt/linkmoth/linkmoth.py --doctor` — full environment check
  (tools, config, TLS, clock sync, port)

### Dashboard unreachable

1. Is the service alive? `systemctl status linkmoth`
2. Right address? It's `https://` (not `http://`) on port 8686.
3. Port taken by something else? `--doctor` tells you.
4. Service crash-looping? `journalctl -u linkmoth -n 50` shows why; TLS is
   fail-closed, so missing/broken certificates stop startup on purpose —
   re-run `sudo bash install.sh` to regenerate them.

### Setup token expired or lost

```bash
sudo -u linkmoth python3 /opt/linkmoth/linkmoth.py --auth-onboarding-token
```

Prints a fresh 24-hour token (only works while no password exists yet).

### Forgot the admin password

```bash
sudo -u linkmoth python3 /opt/linkmoth/linkmoth.py --auth-set-password
```

Sets a new one at a hidden prompt. All sessions are logged out; requires
SSH/physical access to the Linkmoth host — that's the design: whoever owns the box
owns the account.

### Lost your phone (TOTP)

Log in with one of the recovery codes you saved during 2FA setup (each
works once). No codes left? On the Linkmoth host:

```bash
sudo -u linkmoth python3 /opt/linkmoth/linkmoth.py --auth-setup-totp
```

regenerates the secret and a fresh set of recovery codes.

### Certificate warning on a new device

Expected until that device trusts your Linkmoth CA. Follow **TLS certificates**
above: download or copy the CA, **verify the SHA-256 fingerprint matches the
installer output**, then import. Never enter your password through a warning
you have not cleared by fingerprint-verified trust.

### iPhone push shows an HTTPS or certificate error

Desktop push can work while iPhone still fails — iOS is stricter about TLS and
where Web Push is allowed.

1. **Trust the CA fully on iOS** — installing the profile alone is not enough.
   After the fingerprint check, go to Settings → General → About → **Certificate
   Trust Settings** and enable full trust for the Linkmoth CA. Reopen the app.
2. **Use the Home Screen app, not Safari** — in Safari, tap Share → **Add to
   Home Screen**, then open Linkmoth from the new icon. Settings → Browser push
   only works from that standalone app (iOS 16.4+).
3. Confirm the dashboard loads without a certificate warning in the Home Screen
   app before tapping **Enable push on this device**.
4. If it still fails, check that `install.sh --with-push` was run on the host
   (Settings will say push is unavailable otherwise).

### Host IP or hostname changed

The certificate lists the addresses it was created with. Re-issue it:

```bash
sudo /usr/local/lib/linkmoth/renew-cert.sh
```

(Also runs automatically every month via `linkmoth-cert-renew.timer`.)

### Wrong verdicts

Check the fault ladder's evidence lines — every verdict shows exactly which
rungs failed and why. Two classic causes of misleading verdicts: the Linkmoth host's
own link being flaky (playbook: "Linkmoth host link"), and undervoltage from a
weak power supply (the host power rung warns about this).

# Changelog

## Unreleased

## 0.2.6

### Installer

- Browser-push setup now installs its pinned source-only `http-ece` dependency
  while keeping every other Python dependency wheel-only and unprivileged.

### Notifications

- Added configurable local-time quiet hours for Discord and browser push, with
  restart-safe SQLite deferral and one morning digest after quiet hours end.
- Morning digests wait through global outages, while outbound webhooks continue
  using their normal retry queue.

### Documentation

- Quick-start and Advanced installation commands now install v0.2.6.

## 0.2.5

### Dashboard

- Hidden incident controls now remain hidden when no incident is open.
- Browser-push controls now follow this browser's actual subscription rather
  than notification permission alone.
- Fault-ladder target evidence is compact and paired with plain-language
  summaries instead of repeated endpoint details.

### Documentation

- Quick-start and Advanced installation commands now install v0.2.5.

## 0.2.4

### Dashboard and PWA

- Refined the dark and white themes, dashboard controls, device views, and
  installable app assets.
- A fully healthy diagnosis now hides incident controls, even when an older
  incident has legacy metadata.
- Dashboard copy now uses shorter en dashes consistently.

### Documentation

- Quick-start and Advanced installation commands now install v0.2.4.

## 0.2.3

### Security and exposure hardening

- Webhook delivery is pinned to the validated address; TLS is restricted to AEAD
  ciphers only.
- Connections from public IP addresses are refused, with dashboard warnings and
  alerts when accidental exposure is detected.

### Dashboard and PWA

- Sign out now lives in Settings instead of the header.
- Added a PWA install prompt, offline app-shell caching, and a theme toggle with
  Cream, Dark, and White options.

### Documentation

- Simplified the main README and moved detailed guidance to `ADVANCED.md`.
- Quick-start install docs and the Sigstore-verified path are pinned to v0.2.3.
- Release builds fail when install docs do not match the tagged version.

### 0.2.1 feature beta: dashboard control alignment

- Sign out now uses a clearly framed, centered control instead of appearing as
  a detached arrow in the dashboard header.
- History recheck and support-summary actions now use matching height,
  padding, and label alignment.

### 0.2.0 feature beta: provenance and manual updates

- Signed release builds now embed their exact source commit. The normal,
  checksum-checked bootstrap needs no Cosign and is reported honestly as an
  unverified/manual installation. Optional `--sigstore-verified` mode verifies
  the pinned workflow identity and is the only path that writes the root-owned,
  atomic verified-provenance record.
- Settings now reports installation provenance and provides a strictly manual,
  authenticated, CSRF-protected update check. It connects only to the fixed
  official GitHub endpoint over verified HTTPS, rejects redirects and proxies,
  limits DNS/peer addresses to public routes, and exposes a validated,
  version-pinned update command with no Cosign dependency. The verified command
  remains available as an optional advanced path. No automatic update actions
  occur.
- Incident lifecycle now preserves historical diagnosis independently of
  recovery and exposes Active, Recovered awaiting confirmation, Closed, and
  False alarm states. Uptime now uses the actual recorded monitoring interval.
- Added authenticated local evidence exports: bounded detailed JSON, readable
  text, and support-safe JSON. Support-safe exports omit secret classes and
  pseudonymize private-network identifiers consistently within each export.

### Evidence-aware ladder and safer response playbooks

- Redundant upstream-DNS, ping, HTTPS, and Wi-Fi-witness probes now retain
  per-target results plus passed/failed counts. A surviving target still keeps
  the rung operational, while the dashboard marks disagreement amber and
  lowers verdict confidence instead of hiding it.
- Fixed two attribution errors: a host power fault can no longer be stored as
  `all_clear`, and working HTTPS prevents blocked ICMP/direct-DNS traffic from
  being classified as a total WAN outage. The latter now receives the
  `restricted_connectivity` verdict and filtering/VPN guidance.
- Wi-Fi witnesses are treated as fallible evidence. Silent phones and blocked
  ping now produce a warning that asks the operator to wake and verify a
  witness before rebooting the router.
- The ladder UI is grouped into observer health, local network, name
  resolution, and internet path. Redundant targets can be expanded without
  turning them into independent monitors.
- Playbooks now put safe checks before disruptive changes, label interruption
  and escalation steps, state what success looks like, warn against accidental
  factory resets, and insert targeted Local DNS/default-route steps from
  micro-evidence.
- Guided verification reports human rung names and detects improved or newly
  disagreeing redundant evidence in addition to fixed/failed rungs.
- Incident closure preserves the strongest confirmed verdict, so a severe WAN
  or router failure cannot be overwritten by a later partial-recovery warning.
- Today and History can copy a credential-free text support summary containing
  incident reference, verdict confidence, ladder evidence, probe details, and
  the diagnosis timeline.

### Security hardening

- Replaced the unbounded threaded HTTPS listener with a fixed 16-connection
  TLS worker pool. TLS handshakes have a five-second deadline and happen away
  from the accept loop, so slow clients cannot block every new connection.
- Added systemd task, file-descriptor, memory, and CPU ceilings; the installer
  no longer kills processes by filename and instead requires unmanaged legacy
  processes to be stopped deliberately.
- Fresh ambiguous installs now default to loopback in guided mode and require
  `--bind <IPv4>` in non-interactive mode. Wildcard binding needs explicit
  confirmation.
- Added a global SQLite-backed password-verification budget alongside per-IP
  lockouts, WAL journal mode, a busy timeout, and visible database health data.
- Versioned release assets are signed with Sigstore. Verification remains
  available without making Cosign an installation dependency; the normal path
  checks the exact release archive against its SHA-256 and never pipes an
  unversioned branch script into root.
- CA enrollment UI now requires fingerprint comparison from a trusted path and
  explicitly rejects guest/shared/untrusted network use.
- Webhook URLs and legacy Discord URLs are now masked in API/UI responses;
  masked values round-trip without replacing the stored credential.
- Outbound webhook and Discord delivery ignores environment proxies and
  refuses redirects so authorization headers and credential-bearing URLs
  cannot be forwarded to a different destination.
- Suppressed inbound alerts retain only digest fields and are capped at 500;
  arbitrary webhook payloads can no longer grow the database without bound.
- Expensive password/TOTP verification rejects excess concurrent work instead
  of queueing unbounded HTTP handler threads.
- Runtime databases, settings, and generated VAPID keys are created atomically
  with mode `0600`; unsafe state-file and VAPID-key symlinks are rejected.
- The server now fails closed on a missing or invalid production configuration.
  Generated curl examples validate the request Host before interpolation.
- Installer scripts use a fixed system PATH, clear interpreter-injection
  environment variables, pin the optional `pywebpush` version, accept wheels
  only, and run package installation as the unprivileged service user.
- Expanded systemd sandboxing and added a least-privilege, dependency-free CI
  workflow.

### Outbound webhook engine (presets, templates, retry queue)

- **Multiple outbound webhooks** replace the single "Generic webhook"
  setting. Each webhook (up to 20) has a name, preset, URL, custom headers,
  event subscriptions, and an optional payload template. Managed from
  **Settings → Outbound webhooks** or the new `GET/POST /api/webhooks`,
  `PUT/DELETE /api/webhooks/{id}` API. The old `notify_webhook_url` setting
  is migrated automatically into one Generic JSON webhook on first start.
- **Presets:** Generic JSON, ntfy, Gotify, Home Assistant, Discord, Slack
  (also fits Mattermost/Rocket.Chat), n8n / Node-RED, and Custom template.
  Custom templates are strict `{{placeholder}}` substitution — no logic, no
  expressions — with JSON-safe escaping.
- **Richer event model:** `fault_opened`, `fault_updated` (verdict changed
  mid-incident), `fault_recovered`, `fault_closed`, `degradation_detected`
  (warn-severity faults), `diagnosis_run` (manual/verify runs),
  `false_alarm_marked`, `device_down`, `device_recovered`. Payloads carry
  structured machine fields (`event`, `incident_id`, `verdict`, `severity`,
  `confidence`, `duration_seconds`, `affected_layer`, …) next to the human
  `title`/`body`.
- **Persistent retry queue:** every delivery goes through a SQLite-backed
  queue with exponential backoff (30 s → 1 h, max 10 attempts, 24 h max age).
  During a global outage nothing is attempted; the queue drains on WAN
  recovery and late deliveries are annotated (`"delayed": true` plus a note
  in text presets). Queue state is visible per webhook in Settings
  ("3 queued · last failed: timeout · next retry in 2 min").
- **Header secrets are write-only:** custom header values (bearer tokens
  etc.) come back masked (`••••••••abcd`) from the API and UI; resubmitting
  the masked value keeps the stored secret.
- **Test buttons:** per-webhook "Send test fault" / "Send test recovery"
  deliver a sample payload through the exact production render path and show
  the HTTP result inline.
- **Generic inbound webhook:** `POST /api/webhooks/inbound` (same bearer
  secret as the Kuma proxy) lets Grafana, Zabbix, or any script trigger a
  Linkmoth diagnosis with `{"source","event","monitor","message"}`. Alerts
  arriving during a global outage are suppressed into the recovery digest,
  like Kuma alerts. Settings has a **Copy curl test** helper.
- **Mark as false alarm:** open incidents can be closed as a false alarm
  from the dashboard (and resolved incidents flagged retroactively via
  `POST /api/incident/false-alarm`); flagged incidents show a badge in
  history and emit `false_alarm_marked`.
- Fixed: an incident loop finishing no longer overwrites the resolution of
  an incident that was already closed manually.

### Bind-address exposure check

- Added `classify_network_interfaces()`/`bind_exposure_risk()`: detects
  VPN/tunnel interfaces (WireGuard, Tailscale, NordVPN's `nordlynx`, and
  similar) and container bridges (Docker/Podman) on the host.
- `install.sh` now auto-detects a single unambiguous LAN interface on a
  fresh install and binds to it instead of `0.0.0.0`, so Linkmoth does not
  default to listening on every interface. Falls back to `0.0.0.0` (and
  says so) when detection is ambiguous.
- `--doctor` (and therefore `install.sh`, which gates on it) now **fails**
  if `bind` is `0.0.0.0` while a VPN/tunnel interface is present — this
  would otherwise make Linkmoth reachable over that tunnel with no router
  port-forward involved. Container bridges are informational only (lower
  risk, host-local). The check never runs as part of normal service
  startup, only `--doctor`/install, so a VPN connecting or disconnecting
  at runtime cannot make the service flap.
- The Security tab's posture panel shows the same warning on every load,
  so a VPN added after install is still caught.

### Dashboard security management and session hardening

- Added a **Security** tab to the dashboard so 2FA, the admin password, the
  audit log, and security posture can all be managed without SSH.
- **Two-factor (TOTP)** can now be enabled and disabled from the dashboard.
  Enrollment uses an offline-generated QR code and is two-phase: only a
  pending secret is staged; one-time recovery codes are generated and revealed
  after the first authenticator code is verified. Pending enrollment expires
  after 10 minutes, so 2FA is never left half-enabled. Only one pending
  enrollment exists at a time. Disabling 2FA and regenerating recovery codes
  both require re-authentication.
- 2FA state now derives from the auth store (presence of an active secret)
  instead of the read-only config file; the legacy `auth.totp_enabled` flag is
  deprecated and ignored.
- Added an authenticated **change-password** flow that requires the current
  password. Enabling/disabling 2FA and changing the password sign out all
  sessions on every device (stated clearly in the UI before the action).
- Added a read-only **audit-log** view and a **posture** panel (network
  exposure, HTTPS status, session timeouts, CA-certificate download link).
- New routes, all behind the existing auth + CSRF gate (password/code checks
  reuse the login rate-limit + lockout): `POST /api/auth/change-password`,
  `/api/auth/totp/{setup,activate,disable,recovery-codes}`; plus auth-only
  `GET /api/auth/audit` (limit clamped 20–200, newest-first) and
  `GET /api/auth/security`.
- **Session hardening:** added a server-enforced idle timeout
  (`auth.session_idle_seconds`, default 1800s) alongside the existing absolute
  lifetime, with a sliding `last_activity` (written at most once per minute).
  Renamed the session cookie to `__Host-linkmoth_session` (Secure, host-only,
  Path=/), which browsers pin to HTTPS.

### Provider-neutral Local DNS

- Replaced the product-specific `pihole_dns` rung and `pihole_broken` verdict
  with `local_dns` and `local_dns_broken`.
- Added same-host adapters for Pi-hole, Unbound, and dnsmasq, with a strictly
  generic fallback. Remote resolvers are never fingerprinted and always use
  generic DNS-response evidence and repair guidance.
- Added dashboard settings for Local DNS mode, private/loopback IPv4 address,
  and same-host provider. Legacy configuration and Pi-hole-shaped history are
  translated at read time without rewriting the database.

### LAN devices

- Added an independent Devices tab with generic ping, printer TCP 9100, Web
  UI, and configurable TCP-service presets.
- Restricted device targets to literal RFC1918 IPv4 addresses; HTTP checks
  disable proxies and redirects, cap bodies at 64 KiB, time out within
  10 seconds, and verify HTTPS certificates by default.
- Added bounded per-device history, optional 5/15/30/60-minute scheduling,
  two-failure/two-success debounce, manual runs, and opt-in Discord, browser
  push, and generic-webhook alerts.
- Device results are stored separately and never affect network incidents,
  blame, statistics, or network History.

### Mainstream Linux portability, TLS trust UX, guided troubleshooting, correlation

- **Stdlib DNS resolver** replaces the external `dig` binary (connected UDP
  socket, cryptographically random transaction IDs, response validation).
  `doctor()` and `install.sh` no longer require `bind9-dnsutils`.
- **Distro-neutral installer** (`detect_pkg_manager` for apt/dnf/pacman/zypper),
  explicit **`iproute2`/`iproute`** install, multi-distro CA trust store
  updates, and matching `uninstall.sh` cleanup.
- **`GET /ca.crt`** serves the local CA without auth (`application/x-x509-ca-cert`)
  so each client device can trust Linkmoth in one step; the installer prints a
  boxed reminder and the sign-in page links to it.
- **Guided troubleshooting**: `POST /api/verify` re-runs the ladder with cache
  bypass, diffs rungs (`fixed` / `still_bad`), and the dashboard adds an
  **"I tried this — check again"** button (or **"Run a fresh diagnosis"** on
  closed incidents).
- **Outage correlation**: `Engine.patterns()` with an honest minimum-sample
  rule; Today footnotes, History filter stats, and **Similar incidents** in
  evidence packets.

### Fix playbooks and platform neutrality

- Added per-verdict **"How to fix this — step by step" playbooks** under the
  Today verdict card and inside every incident evidence packet: router down,
  ISP/WAN outage, Pi-hole broken, router Wi-Fi crash, degraded link, DNS
  failures, captive portals, and false alarms ("the network was innocent").
  Power-supply steps are appended automatically when undervoltage is seen.
- Made all user-facing wording **platform-neutral**: Linkmoth targets **mainstream
  systemd Linux** (Debian/Ubuntu/Raspberry Pi OS, Fedora, Arch, openSUSE), not
  only Raspberry Pi. Ladder rungs are now "Host power" / "Host network link",
  verdicts say "Linkmoth host", and the README states the supported platforms.
  Verdict codes are unchanged, so existing history and filters keep working.
- Expanded the README troubleshooting section into a recovery guide: lost
  admin password, lost TOTP device, expired setup token, CA trust on new
  devices, changed IP/hostname, unreachable dashboard.

### Installer and dependency hygiene

- The core install is **pip-free**: browser push is opt-in via
  `install.sh --with-push`, which installs `pywebpush` into a private
  virtualenv (`/opt/linkmoth/venv`) so Debian's externally managed system
  Python (PEP 668) is never touched. `linkmoth_push` discovers the venv
  automatically; the service always runs on the system interpreter.
- A failed push setup can no longer break or block installation.
- Doctor: missing `pywebpush` is now informational instead of a failure
  (previously it aborted every no-push install at the preflight gate), and a
  clock-sync (NTP) check was added since TOTP and TLS depend on accurate time.

### Web security (second round)

- Replaced `script-src 'unsafe-inline'` with **per-request CSP nonces**; the
  dashboard script only runs with the nonce minted for that page load.
- Added `worker-src`/`manifest-src 'self'` — the previous policy silently
  blocked the service worker and PWA manifest, so browser push could never
  activate.
- Logout now works for password-accepted-but-TOTP-pending sessions instead of
  requiring full authentication.

### Dashboard polish

- Sign-in gate shows the Linkmoth logo and wordmark; error line collapses when
  empty; logo paths made relative so previews work too.

### Authentication and onboarding

- Made authentication mandatory; legacy `auth.enabled: false` is ignored.
- Added a one-time browser onboarding flow for creating the admin password.
- Added a random 24-hour setup token that is printed by the installer, rate
  limited, removed after use, and never returned by the API or audit log.
- Added scrypt password hashing, a 12-character minimum, and hidden CLI
  password entry.
- Added SQLite-backed expiring sessions, hashed session IDs, logout
  invalidation, and session invalidation after password or TOTP changes.
- Added CSRF protection to authenticated state-changing requests.
- Added optional TOTP, single-use hashed recovery codes, replay prevention,
  and rate limiting that cannot be reset by repeating the password step.
- Added a separately rotatable bearer secret for `/trigger`.
- Added a bounded, secret-free audit trail for login, TOTP, recovery, logout,
  CSRF, onboarding, and credential-change events.

### TLS and transport security

- Made TLS mandatory and fail-closed when the certificate or key is missing or
  invalid.
- Required TLS 1.2 or newer and enabled HSTS.
- Made session cookies always `Secure`, `HttpOnly`, and `SameSite=Strict`.
- Added installer-generated local CA and server certificates covering
  localhost, current hostnames, and current IP addresses.
- Added a hardened monthly systemd timer that renews and verifies the server
  certificate while retaining the trusted local CA.
- Added support for custom certificate and key paths.
- Added unauthenticated **`GET /ca.crt`** for one-step client CA trust
  (`application/x-x509-ca-cert`).
- Changed dashboard, health-check, onboarding, and webhook instructions to
  HTTPS.

### Security and reliability

- Enforced atomic mode-`0600` writes for `auth.json` and `UMask=0077` for the
  service.
- Fixed spoofable proxy-address handling; forwarded addresses are accepted
  only from configured trusted proxies.
- Added bounded request bodies, connection timeouts, and bounded concurrent
  password verification.
- Made login-attempt updates atomic and fixed TOTP throttling bypasses.
- Prevented password-only sessions from bypassing TOTP when it is enabled
  later.
- Validated dashboard URLs and configurable network targets.
- Handled malformed JSON without crashing request handlers.
- Closed SQLite connections reliably and removed resource leaks.
- Restored Python 3.9 syntax compatibility.

### Installation and operations

- Fixed the installer so it deploys `linkmoth_auth.py`.
- Added OpenSSL and certificate generation to installation checks.
- Added automatic host trust-store installation for the Linkmoth local CA.
- Added certificate and trust-anchor cleanup during uninstall.
- Fixed installed CLI defaults to use `/etc/linkmoth` and `/var/lib/linkmoth`.
- Added CLI helpers for onboarding tokens, password changes, TOTP setup,
  webhook display/rotation, and audit review.
- Updated `README.md` and `config.example.json` for mandatory authentication,
  HTTPS onboarding, CA trust, certificate renewal, proxy configuration, and
  the remaining LAN/shared-admin trust boundary.
- Installer now deploys `linkmoth_discord.py`, `linkmoth_kuma_proxy.py`, and
  `linkmoth.svg` alongside the core app.

### Fault ladder and host telemetry

- Added **micro-steps**: when a ladder step fails (Pi-hole first), Linkmoth runs
  sub-diagnostics only then (e.g. `pihole-FTL` service state and root disk
  usage) and enriches the verdict hint from the result.
- Added Ethernet **link negotiation** checks via sysfs/`ethtool` — warns on
  sub-gigabit or half-duplex without failing the rung (`link_degraded`).
- Added optional **router Wi-Fi client** pings (`target_wifi_clients`) after
  the LAN gateway check (`router_wlan_down` when the router answers but every
  client is silent).
- Extended **host power** with `/sys/class/power_supply/` telemetry (PoE/USB-PD
  online, voltage, offline/low-voltage) alongside `vcgencmd get_throttled` on
  Raspberry Pi hardware.

### Performance and caching

- Added a **10-second in-memory ladder cache** with request coalescing
  (`ladder_cache_seconds`, default `10`) so Uptime Kuma alert bursts reuse one
  diagnosis instead of hammering the network.
- Manual and in-incident re-checks bypass the cache; background baseline
  sampling may share it.
- Kept the existing 300-second DB reuse window in the Uptime Kuma proxy path.

### Incidents and history

- Added human-readable incident references (`INC-YYYYMMDD-NNNN`) stored in
  SQLite, shown in the dashboard and Discord, and searchable from History via
  `GET /api/incident?ref=…`.
- Split **latency history sampling** (`history_sample_minutes`) from **baseline
  incident opening** (`baseline_minutes`) so dashboard sparklines update
  independently of auto-open rate.

### Uptime Kuma integration and Discord

- Added **`POST /api/webhooks/kuma`**: smart proxy that suppresses service
  alerts during global outages (WAN/router/host link), queues them for a recovery
  digest, and forwards to Discord when the network path looks healthy.
- Added optional **Discord fault/recovery embeds** with fault ladder, incident
  reference, and suppressed-service digest on recovery (`linkmoth_discord.py`).
- Dashboard **Settings** covers Discord webhook URL and enable toggle; env
  override `LINKMOTH_DISCORD_WEBHOOK_URL` supported.
- User-facing copy uses **Uptime Kuma** consistently (dashboard link label,
  docs, Discord embeds).

### Database maintenance

- Added a `database` block on `GET /api/status` (file size, freelist pages,
  `AUTO_VACUUM` mode).
- Added SQLite maintenance in Settings: file size, `AUTO_VACUUM` mode, and a
  manual **Run VACUUM** button (`POST /api/settings` with
  `{ "action": "vacuum" }`).
- New databases enable `AUTO_VACUUM=INCREMENTAL` at creation; the daily janitor
  runs `auto_vacuum()` after retention cleanup.

### Dashboard and branding

- Added [`linkmoth.svg`](linkmoth.svg) (500×500) as favicon (`/linkmoth.svg`,
  `/favicon.ico`) and header logo; served without authentication.
- History tab shows incident references and a **Find** box to load evidence
  packets by ref; Today tab shows the open-incident reference.
- Ladder UI renders **micro-step** sub-rows when a check fails.

### Global outage tracking and recovery alerts

- Linkmoth detects WAN/router/host outages itself (baseline, manual, incident loop)
  — not only via Uptime Kuma webhooks.
- Outbound Discord/push/webhook alerts are **deferred during global outages**
  and sent on recovery with a suppressed-services digest.
- **WAN verdict takes priority** over WLAN when upstream/ping are dead.
- Open incidents **resume automatically** after service restart.

### Browser push and generic webhook

- Added **Web Push** (VAPID, service worker, Settings UI); optional
  `pywebpush` via `install.sh --with-push` (private venv, never touches system
  pip).
- Added **generic webhook** for ntfy/Gotify/Home Assistant
  (`notify_webhook_url`, `notify_webhook_enabled`).
- Unified recovery notifications via [`linkmoth_notify.py`](linkmoth_notify.py)
  with deduplication across outage tracker, incident loop, and Kuma proxy.

### Dashboard improvements

- Today tab **open-incident banner** with loop status; **Recheck** and
  **Close incident** buttons.
- **Global outage banner** when alerts are deferred.
- PWA [`manifest.webmanifest`](manifest.webmanifest) for installable dashboard
  (required for iOS push).
- WLAN failure hint when Wi-Fi client probes fail.
- **Guided verify** UI: playbook **check again** / **fresh diagnosis** buttons,
  ladder chips for fixed vs still-bad rungs, pattern footnotes, and similar
  incidents in History packets.
- Sign-in gate **TLS trust banner** linking to `/ca.crt`.

### Verification

- Expanded the automated suite to **173 tests** in `test/`.
- Verified authentication, onboarding, CSRF, sessions, webhook bearer
  protection, TOTP, recovery codes, rate limits, proxy handling, TLS
  configuration, HSTS, Secure cookies, and installer renewal behavior.
- Added coverage for stdlib DNS resolver, `/ca.crt` and `/api/verify` routes,
  outage correlation (`patterns`, similar incidents), Discord embeds, Uptime
  Kuma proxy, ladder micro-steps, ladder cache coalescing, incident references,
  SQLite maintenance, and installer assets.
- The full suite passes with resource warnings treated as errors.
- Python 3.9 grammar and patch-integrity checks pass.

### Remaining operational note

- Each **client device** (phone, laptop, tablet) must trust the Linkmoth local CA
  before users enter credentials — open `https://<host>:8686/ca.crt` once per
  device, or import the CA file manually (see README TLS section). The CA
  private key and server private key must never be copied off the Linkmoth host.

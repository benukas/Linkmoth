# Linkmoth value roadmap

Deferred ideas for adding value beyond the current feature set.

**Shipped since this list was written** (see CHANGELOG "Unreleased"):
connection quality incl. bufferbloat/throughput, ISP accountability report
with CSV + evidence letter (#1, PDF still open), Prometheus `/metrics` (#2),
escalation tiers (part of #3; verdict-driven *actions* still open), incident
stories, plain-language quality findings, Wi-Fi vs wired differential,
monthly network report, read-only API tokens, fire drill, `--doctor --json`.

Context that shaped this list:
- Notifiers are already broad (Discord, push, ntfy, Home Assistant, Slack, n8n,
  generic webhook) — adding more chat targets is low value.
- All integrations today are **push**; there is no pull/scrape endpoint.
- Every incident is already recorded with timestamps and a blame verdict, but
  almost nothing is extracted from that history yet.

---

## 1. ISP accountability reporting  (high value, low-moderate effort)
Turn the incident log we already keep into a shareable record.

- A `/report` view + export (CSV first, PDF later): incident count, total
  downtime, blame breakdown (WAN vs router vs WLAN vs DNS), longest outage,
  time-of-day pattern.
- "Copy evidence for ISP support" — a timestamped, plain-language list of
  WAN-blamed incidents suitable to paste into a complaint.
- Once connection quality lands, extend this into a **quality SLA report**
  (not just uptime: latency/bufferbloat percentiles over the month).
- Emotionally resonant and differentiated; a natural output of existing data.

## 2. Prometheus `/metrics` endpoint  (moderate value, low effort)
A scrape endpoint so Grafana/Prometheus users can graph and alert.

- `GET /metrics` in Prometheus text format: current verdict/severity, per-rung
  up/down gauges, incident counters, and (after quality work) latency/loss/
  jitter/throughput gauges.
- Decide auth: either allow unauthenticated on the LAN bind, or a bearer token
  reusing the webhook secret. Keep it read-only.
- Small surface, big homelab ecosystem reach; complements the push integrations.

## 3. Verdict-driven actions / escalation  (high value, moderate effort)
Move from *notify* to *respond*.

- Rules like "if WAN is dead > N minutes, run <action>" — e.g. pulse a smart
  plug (Home Assistant / Tado / generic HTTP) to power-cycle the modem.
- Escalation policy: notify channel A immediately, channel B if still down after
  N minutes.
- Guardrails required: max attempts, cooldown, dry-run, and never loop-reboot.

## 4. Fleet view / multi-node aggregation  (high value for a niche, higher effort)
One pane aggregating several Linkmoth nodes.

- For the person who runs the network for family + a couple of friends.
- A node reports its status/incidents to a chosen "hub" Linkmoth (or a small
  aggregator), authenticated with a shared token.
- Central dashboard: per-site status, recent incidents, quick drill-in.

## 5. Guided certificate-trust wizard  (removes #1 adoption friction)
The private-CA trust step is the biggest beginner hurdle.

- An in-dashboard `/setup` step that detects the device OS and gives exact,
  copy-along trust instructions: iOS (profile install **and** Certificate Trust
  Settings), Android, macOS, Windows, and Firefox's separate store.
- Detect current trust state where possible and confirm success.
- Pairs with the installer, which now points users at `/setup`.

---

### Explicitly not prioritized
- More chat integrations (already broad).
- Desktop GUI installer (headless SSH is the real target; correctly rejected).
- "Compare to regional ISP outage" data (privacy-sensitive, external
  dependency, weak ROI).

---

## Brainstorm — standalone value (2026-07-17)

Ideas from the standalone-first repositioning, each checked against the
LAN-only threat model. Grouped by security cost. Unreviewed; prune freely.

### Zero new attack surface (pure rendering/analytics over existing data)

- **Monthly network health digest** — auto-summary through the existing
  notify channels: uptime, incident count, blame breakdown, quality trend
  vs last month. Turns silent good months into visible delivered value.
- **Plain-language quality findings** — "evenings are 3× worse than
  mornings", "loss spikes recur daily after 20:00". Analytics over
  `quality_samples`; feeds the ISP report.
- **Incident story paragraph** — on close, render the evidence trail as one
  human-readable narrative ("At 21:14 the router stopped answering; local
  DNS had already failed 40 s earlier…") with a copy button. This is the
  text people paste into chats/forums — organic marketing surface.
- **Wi-Fi vs wired differential verdicts** — when `target_wifi_clients` are
  configured, compare their loss against the wired baseline to say "your
  Wi-Fi is the problem, not your ISP" explicitly.
- **First-run confidence builder** — guided "pull your WAN cable now" test
  during onboarding; Linkmoth catches it live. Proves the product in
  minute one instead of waiting weeks for a real outage.
- **`--doctor --json`** — machine-readable environment output for bug
  reports and future tooling.

### Small, well-understood new surface (needs the usual care, no new class of risk)

- **Prometheus `/metrics`** (roadmap #2) — read-only text endpoint; reuse
  webhook bearer or LAN-bind-only; never expose secrets in labels.
- **Scoped read-only API token** — a separate token class that can only GET
  status/quality (never settings, incidents detail optional), for Homepage/
  Glance/kiosk widgets and Home Assistant REST sensors. Distinct from both
  the admin session and the webhook secret; revocable from Settings.
- **Bufferbloat / latency-under-load score** — measure ping inflation while
  saturating the link briefly against the configured HTTPS targets. Opt-in
  (data caps), bounded transfer size, outbound-only to already-configured
  targets; no listening surface. The single most *felt* daily-value metric
  for gamers and video calls.
- **Throughput trend sampling** — same opt-in/bounded framing; a trend line,
  not a speedtest brand.

### Real new capability = real guardrails required (design docs first)

- **Verdict-driven actions** (roadmap #3) — e.g. pulse a smart plug to
  power-cycle the modem when WAN is dead > N minutes. Requires: RFC1918
  target validation (reuse device rules), max attempts + cooldown, dry-run
  mode, never act on low confidence, off by default, action log in the
  incident trail.
- **Escalation tiers** — notify channel A immediately, channel B if still
  down after N minutes. Mostly reuses the outbound queue; the care point is
  clear state so recoveries cancel pending escalations.

### Repo/infra (no code)

- `.github/FUNDING.yml` + a funding link in README's Supporting section.
- Demo GIF for the README hero (placeholder comment already in place).
- A "caught it" discussion thread/pinned issue inviting incident stories —
  each one is a testimonial.

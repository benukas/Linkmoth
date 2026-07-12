# Linkmoth value roadmap

Deferred ideas for adding value beyond the current feature set. Connection
quality (latency / jitter / bufferbloat / throughput) is being built now; the
rest are captured here so they aren't lost.

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

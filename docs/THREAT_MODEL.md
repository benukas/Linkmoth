# Linkmoth threat model

## Scope and supported deployment

Linkmoth is a local-first diagnostic appliance for one administrator on a trusted home LAN. The safe default is loopback or one explicit LAN IPv4 address. Direct WAN exposure, port forwarding, cloud tunnels, automatic port forwarding, shared/untrusted networks, and unaudited reverse proxies are unsupported.

## Assets and actors

Assets: admin password verifier, session and CSRF secrets, TOTP seed/recovery-code hashes, webhook bearer, TLS private key/local CA, configuration, diagnostic history, webhook queue, backups, and release signing identity.

Actors: local administrator; LAN browser/client; bearer-token webhook sender; configured outbound webhook receiver; local unprivileged user; root installer operator; CI maintainer/release approver; network attacker able to influence LAN/DNS; and a compromised dependency or release artifact producer.

## Entry points and boundaries

| Flow | Boundary and controls |
|---|---|
| Browser to HTTPS dashboard/API | LAN client to authenticated service; TLS, password, secure host cookie, CSRF, TOTP, rate limits. |
| `/health`, `/ca.crt` | Intentionally unauthenticated discovery/trust material; contains no secret. CA fingerprint must be verified out of band. |
| Inbound webhooks | Untrusted HTTP body to bearer-protected trigger/Kuma routes; bounded parsing and separate bearer. |
| Outbound webhooks/push | Stored administrator configuration to remote endpoint; URL validation, HTTPS/public-address restrictions, queue limits. Optional push dependencies are isolated from core. |
| Root installer/renewal | Release archive to root filesystem; signed assets, manifest validation, staging, service sandbox. |
| SQLite/config/backups | Service-local sensitive data; file modes, service account, local storage. Backups remain sensitive. |
| Reverse proxies/VPN interfaces | Advanced deployments crossing a trust boundary; explicitly configured trusted proxy ranges and narrow bind are required. |

## Abuse cases and mitigations

- A LAN client attempts credential stuffing or cross-site state changes: rate limits, CSRF, secure cookies, and TOTP reduce exposure; a trusted LAN is still required.
- A leaked webhook bearer triggers diagnosis: bearer rotation invalidates it; route access remains possible until rotation.
- A malicious release archive attempts traversal, links, special files, or partial extraction: signature, signed manifest, pre-extraction validation, temporary staging, and installer rollback reduce risk.
- An outbound webhook targets internal services through DNS: URL/address checks restrict destination classes; DNS can change after validation, so administrators should use trusted endpoints and network egress controls.
- A tunnel/VPN makes wildcard binding reachable: installer and doctor warn; use a single explicit LAN address.
- A local user abuses Polkit or host CA trust: these are convenience choices, not a remote vulnerability; future releases should make them opt-in.

## Design limitations

The public health endpoint, CA distribution endpoint, `CAP_NET_RAW`, and optional outbound notification are intentional capabilities, not independently demonstrated vulnerabilities. They require deployment-specific review. The local CA cannot make an untrusted LAN safe; backups and root-host compromise remain outside the application security boundary.

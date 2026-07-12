# Security policy

## Supported versions

Until the first tagged stable release, security fixes are made on the default
branch only. After releases begin, the latest release and the default branch
will be supported.

## Reporting a vulnerability

Please do not open a public issue containing exploit details, credentials,
private network information, or other sensitive material.

Use GitHub's private vulnerability reporting for this repository when it is
available. If that option is not visible, open a minimal public issue titled
`Security contact request` with no technical details; the maintainer will
arrange a private channel.

Include, privately:

- the affected version or commit;
- prerequisites and realistic impact;
- minimal reproduction steps;
- whether the issue has been disclosed elsewhere; and
- any suggested mitigation.

You should receive an acknowledgement within seven days. Target initial
responses are 72 hours for critical/high reports, seven days for medium, and
14 days for low/informational reports. Fix and coordinated-disclosure timelines
depend on severity, reproducibility, and affected deployment scope.

Enable GitHub private vulnerability reporting, secret-scanning alerts, and push
protection in repository settings. Push protection complements review; never
place release credentials, webhook bearers, private keys, or real backups in
the repository.

## Safe research

Test only systems you own or are explicitly authorized to assess. Avoid
privacy violations, persistence, destructive actions, service disruption, and
access to other people's data. A good-faith report does not require exploiting
beyond the minimum needed to demonstrate impact.

## Scope reminders

Linkmoth is designed for a trusted local network and one shared administrator.
Internet exposure, router port forwarding, third-party reverse proxies, host
compromise, and insecure backups can invalidate that model. See the README's
Security posture section for the complete boundary.

Do not enroll the Linkmoth local CA on a guest, shared, or untrusted network.
Before importing `/ca.crt`, compare its SHA-256 fingerprint with a value from a
trusted installer session or SSH connection. Direct HTTPS is the supported
deployment; reverse proxies are advanced, separately secured deployments.

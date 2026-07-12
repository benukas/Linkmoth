# Release remediation plan

## Release blockers

1. Enforce the separated, protected release workflow and configure protected `main`, protected signed tags, required checks, and two-person `production-release` approval in GitHub.
2. Ship only generated, version-embedded bootstraps and signed archive manifests; verify malicious-archive tests on supported Linux.
3. Run an independent review of root installer and release workflow before publishing a public beta.

## Public-beta requirements

1. Enable Dependabot, CodeQL, secret-scanning alerts, and push protection in GitHub; add `pip-audit` plus a hash-locked optional `pywebpush` dependency set if push support remains distributed.
2. Establish coverage, mutation, property/fuzz, concurrency, and resource-leak gates with initially measured thresholds.
3. Create Debian, Ubuntu, and Raspberry Pi OS ARM64 install/upgrade/rollback/uninstall VM tests; do not claim platforms that have not passed.
4. Publish the threat model, release checklist, issue templates, supported-version window, and severity response targets.

## Stable-release requirements

1. Run network-namespace scenarios for gateway/DNS disagreement, filtered ICMP, captive portal, TLS failure, latency/loss, and incomplete evidence confidence.
2. Exercise disk-full, read-only filesystem, corrupted state, SQLite recovery, power interruption, reboot, clock skew, and certificate renewal/hostname changes.
3. Complete accelerated multi-day soak testing for descriptors, threads, memory, queues, and SQLite growth on ARM hardware.
4. Decide, document, and test explicit opt-in behaviour for host CA trust and Polkit.

## Longer-term improvements

1. Add reproducible optional-dependency SBOM vulnerability reporting and reviewed update automation.
2. Maintain upgrade fixtures for every supported historical configuration/database version.
3. Reassess systemd capability and sandbox policy from observed required operations; reduce privileges only with integration evidence.

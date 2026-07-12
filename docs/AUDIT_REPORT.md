# Public-beta security and release audit

Audit date: 2026-07-13. Scope: repository source and workflows only. No claim below establishes exploitability without the stated prerequisite. Real Linux, ARM, GitHub settings, and network behaviour were not exercised.

## Critical

### AR-01 — release credentials execute tagged repository code

- **Location:** `.github/workflows/release.yml`, original `release` job.
- **Boundary / prerequisite:** an attacker must cause a tag to point to a commit containing a malicious test or build script, or a maintainer must tag such a commit. The original job gave that code `contents: write` and `id-token: write`.
- **Impact:** the job could create or alter releases and obtain a Sigstore identity for the release workflow.
- **Reasoning:** the job checked out the tag then executed tests and `scripts/build-release.sh` before signing and publishing.
- **Correction:** untrusted checkout/build jobs receive only `contents: read`; a protected-environment publication job consumes their artifact and does not check out or execute tag code.
- **Regression:** `test/test_release_pipeline.py` rejects unpinned Actions, write/OIDC permissions before publication, and a publication job without an environment or all prerequisite jobs.
- **Residual risk:** a human with permission to approve the protected environment can still publish a malicious, but fully tested, protected-main commit. Require a second human approver and protected tags.

## High

### AR-02 — bootstrap accepted mutable `latest` and implicit repository inputs

- **Location:** `bootstrap.sh`, original `LINKMOTH_REPO` and `LINKMOTH_VERSION` handling.
- **Boundary / prerequisite:** root runs an official bootstrap while an environment variable is set, or uses the documented default `latest`; a substituted upstream release can then be selected.
- **Impact:** the root installer may fetch a different release from the file it purports to represent.
- **Reasoning:** the original script resolved `latest` through the API and honored both environment variables before download.
- **Correction:** release construction embeds a semantic version; official bootstraps refuse the source template and accept a repository override only through an explicit advanced flag with strict validation.
- **Regression:** `ReleaseArchiveTests.test_bootstrap_is_versioned_and_disallows_implicit_override` fails if `latest` returns or the version placeholder/explicit override guard disappears.
- **Residual risk:** an explicit fork override deliberately changes the trust root; it is warned and is for maintainers only.

### AR-03 — signed archive was extracted without a complete safe-layout check

- **Location:** `bootstrap.sh`, original `tar -xzf` path.
- **Boundary / prerequisite:** an attacker must provide an archive that passes the existing signature verification (for example through a compromised signing workflow/repository) or a maintainer must intentionally publish it.
- **Impact:** root extraction could create files outside the temporary directory through traversal or links, or create unsafe special files.
- **Reasoning:** extraction occurred before enumerating the archive and the only layout check used its first listed member.
- **Correction:** signed manifest verification plus a full pre-extraction Python `tarfile` scan rejects duplicate/absolute/traversal paths, special files, links, unsafe modes, unexpected entries, altered sizes, and altered digests; extraction is into a fresh temporary directory only after validation.
- **Regression:** `test/test_release_archive.py` creates traversal and symlink tarballs and proves they fail before the destination is created.
- **Residual risk:** this depends on Python's standard `tarfile` implementation and filesystem semantics; validate on each supported Linux distribution before shipping.

## Medium

### AR-04 — no machine-enforced action dependency or static security analysis maintenance

- **Location:** `.github/` (missing Dependabot and CodeQL workflows).
- **Boundary / prerequisite:** a known vulnerability or compromised transitive GitHub Action must be introduced or remain unreviewed.
- **Impact:** delayed detection and remediation of CI supply-chain and Python-code issues.
- **Reasoning:** CI already pinned some Actions but no automated update channel or CodeQL scan existed.
- **Correction:** add Dependabot for Actions and pip, plus a pinned CodeQL workflow.
- **Regression:** review the workflow pin test and GitHub Actions run; Dependabot and CodeQL require GitHub execution to prove operation.
- **Residual risk:** CodeQL is not a substitute for review; Dependabot PRs need human verification.

### AR-05 — release readiness has no VM/ARM or fault-injection evidence

- **Location:** CI/release policy; no automated VM, ARM64, namespace, power-loss, or long-running soak jobs found.
- **Boundary / prerequisite:** deployment reaches a supported OS/architecture or degraded network/storage state not represented by unit tests.
- **Impact:** install rollback, systemd sandbox, certificate renewal, database recovery, and diagnosis confidence may fail in production.
- **Reasoning:** repository CI runs unit tests and distribution reproducibility checks only.
- **Correction:** add isolated Debian/Ubuntu/Raspberry Pi OS ARM64 VM matrices with install/upgrade/uninstall/rollback and network-namespace fault suites before stable support claims.
- **Regression:** each supported-platform claim must map to a passing VM job; add fault scenarios with assertions that incomplete evidence reduces confidence.
- **Residual risk:** VM coverage does not replace real Raspberry Pi hardware and router/network interoperability tests.

## Low / informational

### AR-06 — host-wide CA trust and Polkit remain broad convenience defaults

- **Location:** `install.sh` `install_ca_trust` and Polkit setup.
- **Boundary / prerequisite:** a local user who can use the installed trust/Polkit path or an administrator accepting the guided default.
- **Impact:** increased host trust surface and less explicit service-control delegation; this is a design trade-off, not a demonstrated bypass.
- **Reasoning:** installer documentation confirms automatic CA trust installation and a sudo-group Polkit rule unless disabled.
- **Correction:** make both explicit opt-ins in a future compatibility-reviewed installer revision; retain current flags as interim controls.
- **Regression:** installer integration tests should assert neither file is created without a positive opt-in.
- **Residual risk:** an administrator may still deliberately opt in; this is expected.

### AR-07 — coverage, mutation, fuzz, and resource-leak gates are absent

- **Location:** CI configuration.
- **Boundary / prerequisite:** a security-relevant edge case reaches untested code.
- **Impact:** regressions in auth, CSRF, authorization, URL validation, TLS, and incident classification could ship undetected.
- **Reasoning:** existing unit tests are substantial but no coverage threshold, mutation campaign, property/fuzz jobs, warning-as-error policy, or long-running concurrency tests were found.
- **Correction:** establish justified branch/statement thresholds from a baseline, then add mutation and targeted property/concurrency jobs as public-beta gates.
- **Regression:** CI should fail on coverage drop, surviving security mutations, ResourceWarning, leaked threads/sockets, and focused fuzz corpus failures.
- **Residual risk:** automated tests cannot prove all network or timing behaviour.

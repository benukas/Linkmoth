# Release checklist

- [ ] Release commit is on protected `main`; tag is signed and protected.
- [ ] Required Python 3.9, 3.11, 3.13, and 3.14 checks, shell checks, reproducibility, integration/security gates have passed.
- [ ] README, changelog, versioned bootstrap, manifest, SBOM, and release archive agree.
- [ ] Two maintainers approved the protected `production-release` environment.
- [ ] Archive, checksum, manifest, bootstrap, SBOM, provenance, and GitHub attestations are present and verified.
- [ ] Independent human review has covered installer, release workflow, and diff.
- [ ] Supported VM/ARM and real-network evidence is linked; unsupported platforms are not claimed.
- [ ] Security disclosure contact and private vulnerability reporting are enabled.

Never use manually maintained test-count claims; report CI output or generate counts from the test runner.

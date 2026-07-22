# Linkmoth maintenance and release guide

This file is the operating guide for Benas and any coding assistant working on
the official Linkmoth repository. Follow it before making, publishing, or
releasing a change.

## Ownership and attribution

- The official project is maintained by **Benas Urniežius** (`benukas`). Read
  [CONTRIBUTING.md](CONTRIBUTING.md) before treating outside work as a
  contribution.
- Do not add an AI assistant, tool, or agent as an author, co-author,
  contributor, or release-note credit. Use the authenticated maintainer's Git
  identity only.
- Never expose, commit, print, or upload secrets, local configuration, TLS
  material, or runtime data. `config.json`, `settings.json`, `auth.json`,
  `state.db`, `tls/`, and private keys are intentionally ignored.

## Working on a change

1. Start by checking `git status -sb` and the current branch. Preserve any
   unrelated local edits.
2. Branch from current `origin/main` using `release/<short-description>` for
   maintenance or release work. Do not commit directly to `main`.
3. Make the smallest scoped change. Do not edit ignored local-agent folders
   (`.agents/`, `.claude/`, `.codex/`) or `docs/` unless the maintainer
   explicitly asks.
4. Keep release sources in sync: when a tracked release file changes, its
   `dist/` counterpart must match. The tests enforce this.
5. Stage explicit paths, inspect the staged diff, and create a signed commit:

   ```bash
   git add <intended-files>
   git diff --cached --check
   git commit -S -m "Short imperative summary"
   ```

6. Confirm the signature before pushing when practical:

   ```bash
   git log -1 --show-signature
   ```

## Validation

- Run the smallest relevant test first, then run the full suite for changes
  that affect source, installation, packaging, security, or release logic:

  ```bash
  python -m unittest discover -s test -v
  ```

- For installer or workflow shell changes, also run syntax checks matching the
  changed files, for example `bash -n install.sh bootstrap.sh`.
- For README/release guidance changes, at minimum run:

  ```bash
  python -m unittest discover -s test -p test_release.py -v
  ```

## Pull requests and protected main

1. Push the signed branch with tracking:

   ```bash
   git push -u origin <branch>
   ```

2. Open a PR from that branch into `main`. Give it a concise title, explain
   what changed and why, and record the checks run.
3. Wait for every required GitHub check and the configured approval rule.
   Do not bypass protection, force-push, or merge a failing PR.
4. Merge only after GitHub shows the PR is mergeable and all required checks
   have passed. Confirm the resulting `main` commit is verified when GitHub
   shows a signature badge.

The exact required checks and approval count are controlled by GitHub's branch
protection/rulesets and may change. Treat the PR checks page as authoritative.

## Versioned releases

Release tags are protected and must be signed. A release tag is created only
from the final merged commit on `main`.

1. Before opening the release PR, choose the exact new version and perform
   this **mandatory version sweep**. Do not tag until every applicable item is
   updated and reviewed:

   - public quick-start commands in `README.md`, including every release URL
     and bootstrap filename;
   - versioned commands in `ADVANCED.md`, including the checksum-verified
     default install path and optional `--sigstore-verified` path;
   - the top-level `CHANGELOG.md` entry for the new version (do not rewrite
     historical entries);
   - release-version assertions in `test/test_release.py` and any other
     version-specific tests;
   - every matching tracked `dist/` counterpart, rebuilt from the source
     files.

   Run `rg -n "v<previous-version>|<previous-version>"` across release
   sources and `dist/` to distinguish stale current-install references from
   intentional historical changelog entries. Run the release tests after the
   sweep; they must confirm that `dist/` exactly matches its sources.
2. Commit the version sweep on its own signed `release/<version>` branch,
   push it, and open a PR into `main`. A version bump is not complete merely
   because a prior feature PR was merged.
3. Ensure the release PR is merged and all required checks and approvals are
   green. Verify the merge on GitHub and do not assume a user statement about
   check status is enough to authorize a protected tag.
4. Fetch current refs and verify the target is the final merged `origin/main`
   commit, not a local branch or a PR head:

   ```bash
   git fetch origin --tags
   git rev-parse origin/main
   ```

5. Create and verify an annotated signed tag (replace the version and message):

   ```bash
   git tag -s vX.Y.Z -m "Linkmoth vX.Y.Z"
   git tag -v vX.Y.Z
   git push origin vX.Y.Z
   ```

6. The protected `v*` tag triggers the release workflow. Wait for it to finish
   successfully, then verify the GitHub release contains the archive,
   bootstrap script, manifest, SBOM, checksum, and their Sigstore bundles.
7. Never delete, move, or recreate a published tag merely to retry a workflow.
   Investigate and fix the workflow through a PR first. Any exception requires
   explicit maintainer approval and restoration of all tag-protection rules.

## Installation documentation

- The public quick start must install a versioned GitHub Release, not clone
  `main` or pipe an unversioned remote script into `sudo`.
- The normal bootstrap must be downloaded locally and only then run with
  `sudo bash`. By default it downloads the exact pinned release archive and
  published SHA-256 file from the official repository, verifies the checksum
  before extraction or installation, and writes a checksum-verified
  installation record. Optional `--sigstore-verified` mode requires Cosign and
  verifies the pinned release-workflow identity before writing a
  Sigstore-verified record. There is no checksum-verification bypass.
- Update the quick-start version when publishing a newer stable release.
  This is part of the mandatory version sweep above, together with Advanced
  commands, changelog, release tests, and matching `dist/` files.

## Final handoff

Report the branch, signed commit, PR/release link, and checks run. State any
remaining user action plainly. Do not claim a merge, release, signature, or
protection setting unless it was verified.

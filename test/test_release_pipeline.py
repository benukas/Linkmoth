"""Static regression checks for least-privilege release workflow boundaries."""
import re
import unittest
from pathlib import Path


WORKFLOW = (Path(__file__).resolve().parent.parent / ".github/workflows/release.yml").read_text(encoding="utf-8")


class ReleasePipelineTests(unittest.TestCase):
    def test_every_action_is_pinned_to_an_immutable_sha(self):
        for action in re.findall(r"^\s*- uses: ([^\s#]+)", WORKFLOW, re.M):
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$", action)

    def test_untrusted_jobs_cannot_publish_or_mint_oidc_tokens(self):
        before_publish = WORKFLOW.split("  publish:\n", 1)[0]
        self.assertNotIn("contents: write", before_publish)
        self.assertNotIn("id-token: write", before_publish)
        self.assertIn("persist-credentials: false", before_publish)

    def test_publication_is_isolated_and_environment_protected(self):
        publish = WORKFLOW.split("  publish:\n", 1)[1]
        self.assertIn("environment: production-release", publish)
        self.assertIn("contents: write", publish)
        self.assertIn("id-token: write", publish)
        self.assertIn("artifact-metadata: write", publish)
        self.assertIn("needs: [verify-release-ref, test, checks]", publish)
        self.assertIn("actions/attest@", publish)
        self.assertIn("GH_REPO: ${{ github.repository }}", publish)
        self.assertIn('for file in dist-release/linkmoth-*; do', publish)
        self.assertIn('gh release create "${GITHUB_REF_NAME}" "${assets[@]}"', publish)

    def test_release_file_loops_skip_directories(self):
        self.assertEqual(WORKFLOW.count('[ -f "$file" ] || continue'), 3)

    def test_checks_job_fails_release_if_install_docs_are_stale(self):
        checks = WORKFLOW.split("  checks:\n", 1)[1].split("  publish:\n", 1)[0]
        self.assertIn('grep -qF "VERSION=$tag" ADVANCED.md', checks)
        self.assertIn(
            'grep -qF "releases/download/$tag/linkmoth-$tag-bootstrap.sh" README.md',
            checks,
        )


if __name__ == "__main__":
    unittest.main()

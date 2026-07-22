#!/usr/bin/env python3
"""House style rules that are cheap to break and tedious to catch by eye.

Linkmoth uses the en dash (-- U+2013) and never the em dash (U+2014), in
source strings, dashboard copy, and documentation alike. This is enforced
here rather than left to review because it had to be corrected by hand
several times: every new string is another chance to reintroduce one.
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EM_DASH = chr(0x2014)  # escaped so this guard does not flag its own source

# Linkmoth's own source, copy and documentation. Third-party material is
# deliberately excluded: vendored dependencies, build output, external
# tooling definitions, and the security-engagement reports, which are
# someone else's documents and must not be edited to match our style.
SEARCH_GLOBS = (
    "linkmoth*.py",
    "test/*.py",
    "*.md",
    "docs/*.md",
    "dashboard.html",
    "sw.js",
    "*.sh",
    "config.example.json",
    "site/public/**/*.html",
)


def _tracked_files():
    seen = set()
    for pattern in SEARCH_GLOBS:
        for path in ROOT.glob(pattern):
            if not path.is_file():
                continue
            parts = set(path.relative_to(ROOT).parts)
            if parts & {"worktrees", "dist", "node_modules", ".git", ".agents"}:
                continue
            seen.add(path)
    return sorted(seen)


class HouseStyleTests(unittest.TestCase):
    def test_no_em_dashes_anywhere_in_our_own_files(self):
        offenders = []
        for path in _tracked_files():
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for number, line in enumerate(text.splitlines(), 1):
                if EM_DASH in line:
                    offenders.append(
                        f"{path.relative_to(ROOT)}:{number}: {line.strip()[:90]}"
                    )
        self.assertEqual(
            offenders, [],
            "em dash (U+2014) found; use an en dash (U+2013) instead:\n"
            + "\n".join(offenders[:40]),
        )

    def test_the_check_actually_scans_the_files_that_matter(self):
        """A guard whose file list silently went empty would pass forever."""
        names = {p.name for p in _tracked_files()}
        for expected in ("dashboard.html", "linkmoth_probes.py", "README.md"):
            self.assertIn(expected, names)


if __name__ == "__main__":
    unittest.main()

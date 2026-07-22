#!/usr/bin/env python3
"""House style rules that are cheap to break and tedious to catch by eye.

Linkmoth writes prose with the en dash (U+2013) and never the em dash
(U+2014). It also never uses a spaced ASCII double hyphen as a stand-in for
that dash in comments or docstrings, the way some tooling emits by default.
Both are enforced here rather than left to review because each had to be
corrected by hand several times: every new string is another chance to
reintroduce one.

The offending characters are built from codepoints and hyphen counts so this
guard never flags its own source.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EM_DASH = chr(0x2014)  # escaped so this guard does not flag its own source
_HH = "-" * 2  # a spaced form of this is the ASCII dash we reject

# An em dash can also hide as an escape sequence that only becomes U+2014 at
# runtime, which the literal-character check above never sees: the octal or
# hex UTF-8 bytes emitted by a shell printf, or a unicode escape in Python or
# JavaScript. Each sequence is assembled from a lone backslash and separate
# digit chunks so the whole thing never appears literally in this file, the
# same reason EM_DASH is escaped rather than written out.
_BS = chr(92)
EM_DASH_ESCAPES = (
    _BS + "342" + _BS + "200" + _BS + "224",  # octal UTF-8 bytes (printf)
    _BS + "xe2" + _BS + "x80" + _BS + "x94",  # hex UTF-8 bytes (printf)
    _BS + "u2014",                            # Python / JavaScript escape
)

# A double hyphen used as sentence punctuation: a non-space, space, the two
# hyphens, space, a non-space. Assembled from _HH so the literal spaced form
# never appears in this file.
PROSE_DASH = re.compile(r"(?<=\S) " + _HH + r" (?=\S)")
# Legitimate spaced double hyphens that are not prose: a shell end-of-options
# marker before an argument ("$/quote/path), the runuser wrapper, and the
# "-- env" it hands off to. These are real command syntax, not house style.
SHELL_DOUBLE_HYPHEN = re.compile(_HH + r" ['\"$/]|runuser|" + _HH + " env")

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

    def test_no_ascii_double_hyphen_used_as_a_prose_dash(self):
        offenders = []
        for path in _tracked_files():
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for number, line in enumerate(text.splitlines(), 1):
                if PROSE_DASH.search(line) and not SHELL_DOUBLE_HYPHEN.search(line):
                    offenders.append(
                        f"{path.relative_to(ROOT)}:{number}: {line.strip()[:90]}"
                    )
        self.assertEqual(
            offenders, [],
            "a spaced ASCII double hyphen is standing in for a dash; use an "
            "en dash (U+2013) instead:\n" + "\n".join(offenders[:40]),
        )

    def test_no_em_dash_hidden_as_an_escape_sequence(self):
        """install.sh shipped an em dash as \\342\\200\\224 in a printf, which
        the literal-character check never sees but the terminal still renders
        as U+2014. Catch the escaped byte forms too."""
        offenders = []
        for path in _tracked_files():
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for number, line in enumerate(text.splitlines(), 1):
                if any(seq in line for seq in EM_DASH_ESCAPES):
                    offenders.append(
                        f"{path.relative_to(ROOT)}:{number}: {line.strip()[:90]}"
                    )
        self.assertEqual(
            offenders, [],
            "an em dash is encoded as an escape sequence; encode an en dash "
            "instead:\n" + "\n".join(offenders[:40]),
        )

    def test_the_check_actually_scans_the_files_that_matter(self):
        """A guard whose file list silently went empty would pass forever."""
        names = {p.name for p in _tracked_files()}
        for expected in ("dashboard.html", "linkmoth_probes.py", "README.md"):
            self.assertIn(expected, names)


if __name__ == "__main__":
    unittest.main()

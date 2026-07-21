#!/usr/bin/env python3
"""Every linkmoth_*.py module must be importable on its own, in a fresh
process, regardless of what (if anything) imported it first.

linkmoth_handler.py in particular used to do `import linkmoth` at its own
module scope while linkmoth.py imports names back from linkmoth_handler --
importing linkmoth_handler directly, before linkmoth.py had ever run, hit a
circular import (`ImportError: cannot import name 'AUTH_VERIFY_SLOTS' from
partially initialized module 'linkmoth_handler'`). The existing HTTP-focused
tests never caught this because they always import linkmoth (or reload it)
before touching linkmoth_handler. Running each module in its own subprocess
here is the only way to test "imported first, nothing else has run yet"
without every other test's already-populated sys.modules leaking in.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

MODULES = sorted(
    p.stem for p in REPO_ROOT.glob("linkmoth*.py")
)


class StandaloneModuleImportTests(unittest.TestCase):
    def _import_in_fresh_process(self, module_name):
        with tempfile.TemporaryDirectory(prefix="linkmoth_import_test_") as tmp:
            env = dict(os.environ)
            env["LINKMOTH_STATE_DIR"] = tmp
            env.pop("LINKMOTH_CONFIG", None)
            result = subprocess.run(
                [sys.executable, "-c", f"import {module_name}"],
                cwd=str(REPO_ROOT), env=env,
                capture_output=True, text=True, timeout=30,
            )
        return result

    def test_every_module_imports_standalone(self):
        failures = []
        for module_name in MODULES:
            result = self._import_in_fresh_process(module_name)
            if result.returncode != 0:
                failures.append((module_name, result.stderr.strip().splitlines()[-1:]))
        if failures:
            self.fail(
                "these modules failed to import standalone, in a fresh "
                f"process, as the first thing imported: {failures}"
            )

    def test_linkmoth_handler_imports_standalone_before_linkmoth(self):
        """The exact regression this file exists to catch."""
        result = self._import_in_fresh_process("linkmoth_handler")
        self.assertEqual(
            result.returncode, 0,
            f"linkmoth_handler failed to import standalone: {result.stderr}",
        )


if __name__ == "__main__":
    unittest.main()

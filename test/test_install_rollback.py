#!/usr/bin/env python3
"""Fault injection against the installer's rollback path.

`cleanup_and_rollback` is the installer's last line of defence: it runs from an
EXIT trap, so it executes on every failure, including ones nobody anticipated.
It was the least verified code in the project because exercising it for real
needs root and systemd on a Linux host, so it had only ever been read.

This harness extracts the real function out of install.sh and runs it against a
temporary APP/ETC/STATE tree with `systemctl`, `userdel` and the CA trust tools
replaced by stubs that record their arguments. Failure is injected at each
stage of the state machine, which lets the properties that actually matter be
asserted rather than reasoned about:

  - a failure before the file swap leaves a working install untouched,
  - a failed update restores the previous version and its prior enable/active
    state,
  - a failed fresh install undoes the CA trust anchor, the units and the
    service user, since leaving those behind is a security problem,
  - a failed fresh install keeps a pre-existing config or state directory,
    which is the difference between a clean abort and data loss,
  - and it undoes only what that run created.

The one concession to safety: `remove_ca_trust` writes to absolute paths under
/etc and /usr/local. The state machine tests stub it out and assert only that
it was called; a single dedicated test runs its real body with those paths
rewritten into a sandbox, and is marked as such.
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent
INSTALL_SH = BASE.parent / "install.sh"

BASH = shutil.which("bash")

STUBS = ("systemctl", "userdel", "update-ca-certificates", "update-ca-trust",
         "trust")


def extract_function(name, text):
    """Pull one shell function out of install.sh verbatim."""
    match = re.search(
        r"^%s\(\) \{$.*?^\}$" % re.escape(name), text, re.S | re.M)
    if match is None:
        raise AssertionError("install.sh no longer defines %s()" % name)
    return match.group(0)


@unittest.skipIf(BASH is None, "bash is not available on this host")
class InstallRollbackTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        source = INSTALL_SH.read_text(encoding="utf-8")
        cls.rollback = extract_function("cleanup_and_rollback", source)
        cls.remove_ca_trust = extract_function("remove_ca_trust", source)

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="linkmoth_rollback_"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.calls_file = self.root / "calls.log"
        self.stub_bin = self.root / "bin"
        self.stub_bin.mkdir()
        for name in STUBS:
            stub = self.stub_bin / name
            stub.write_text(
                '#!/bin/sh\necho "%s $*" >> "$LINKMOTH_CALLS"\nexit 0\n' % name,
                encoding="utf-8")
            stub.chmod(0o755)

    # harness.

    def make_tree(self, *, app_contents="new"):
        """Build the directory layout the installer would be operating on.

        Config and state directories always exist by the time the trap can
        fire; whether they predate this run is what ETC_EXISTED and
        STATE_EXISTED record, and that is the flag the tests vary.
        """
        paths = {
            "APP": self.root / "app",
            "ETC": self.root / "etc",
            "STATE": self.root / "state",
            "UNIT": self.root / "units" / "linkmoth.service",
            "RENEW_UNIT": self.root / "units" / "linkmoth-cert-renew.service",
            "RENEW_TIMER": self.root / "units" / "linkmoth-cert-renew.timer",
            "RENEW_SCRIPT": self.root / "renew.sh",
            "STAGE": self.root / "stage",
        }
        paths["UNIT"].parent.mkdir()
        for key in ("APP", "ETC", "STATE", "STAGE"):
            paths[key].mkdir()
        (paths["APP"] / "linkmoth.py").write_text(app_contents, encoding="utf-8")
        paths["UNIT"].write_text("unit=%s" % app_contents, encoding="utf-8")
        paths["RENEW_UNIT"].write_text("renew", encoding="utf-8")
        paths["RENEW_TIMER"].write_text("timer", encoding="utf-8")
        paths["RENEW_SCRIPT"].write_text("#!/bin/sh\n", encoding="utf-8")
        return paths

    def make_backup(self, contents="old"):
        backup_app = self.root / "backup_app"
        backup_app.mkdir()
        (backup_app / "linkmoth.py").write_text(contents, encoding="utf-8")
        backup_unit = self.root / "backup_unit"
        backup_unit.write_text("unit=%s" % contents, encoding="utf-8")
        return backup_app, backup_unit

    def run_rollback(self, paths, *, rc=1, real_ca_trust=False, **state):
        """Invoke the real rollback function with failure already in flight."""
        defaults = {
            "ROLLBACK_STATE": "prepare",
            "IS_UPDATE": "0",
            "BACKUP_APP": "",
            "BACKUP_UNIT": "",
            "PREV_ACTIVE": "inactive",
            "PREV_ENABLED": "disabled",
            "USER_CREATED": "0",
            "CA_TRUST_INSTALLED": "0",
            "UNITS_COPIED": "0",
            "ETC_EXISTED": "0",
            "STATE_EXISTED": "0",
        }
        defaults.update({k: str(v) for k, v in state.items()})

        if real_ca_trust:
            ca = self.remove_ca_trust.replace('rm -f /', 'rm -f "$FAKEROOT"/')
            # Without this guard a future change to the path form in install.sh
            # would silently stop the sandboxing and let the test delete the
            # real trust anchors on whatever host is running it.
            self.assertEqual(
                ca.count('rm -f "$FAKEROOT"/'), 3,
                "remove_ca_trust paths changed shape; sandbox rewrite failed")
            self.assertNotIn(
                "rm -f /", ca, "an absolute removal escaped the sandbox")
        else:
            ca = ('remove_ca_trust() {\n'
                  '  echo "remove_ca_trust" >> "$LINKMOTH_CALLS"\n}')

        assigns = "\n".join(
            '%s=%s' % (k, shell_quote(v)) for k, v in defaults.items())
        path_assigns = "\n".join(
            '%s=%s' % (k, shell_quote(str(v))) for k, v in paths.items())

        script = "\n".join([
            "set -u",
            'PATH="$STUB_BIN:$PATH"',
            'FAKEROOT="$LINKMOTH_FAKEROOT"',
            ca,
            self.rollback,
            path_assigns,
            assigns,
            # Enter the trap the way a real failure would, so that the
            # function's own `local rc=$?` sees a genuine exit status.
            "( exit %d ); cleanup_and_rollback" % rc,
        ])
        script_path = self.root / "harness.sh"
        script_path.write_text(script, encoding="utf-8")

        fakeroot = self.root / "fakeroot"
        fakeroot.mkdir(exist_ok=True)
        env = dict(os.environ)
        env["LINKMOTH_CALLS"] = str(self.calls_file)
        env["STUB_BIN"] = str(self.stub_bin)
        env["LINKMOTH_FAKEROOT"] = str(fakeroot)
        proc = subprocess.run(
            [BASH, str(script_path)], env=env, capture_output=True, text=True)
        return proc

    def calls(self):
        if not self.calls_file.exists():
            return []
        return [line for line in
                self.calls_file.read_text(encoding="utf-8").splitlines() if line]

    # success.

    def test_a_successful_run_only_removes_its_own_scratch_space(self):
        paths = self.make_tree()
        backup_app, backup_unit = self.make_backup()
        proc = self.run_rollback(
            paths, rc=0, ROLLBACK_STATE="done", IS_UPDATE=1,
            BACKUP_APP=backup_app, BACKUP_UNIT=backup_unit)

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(paths["STAGE"].exists())
        self.assertFalse(backup_app.exists())
        self.assertFalse(backup_unit.exists())
        # The installed tree survives untouched.
        self.assertEqual(
            (paths["APP"] / "linkmoth.py").read_text(encoding="utf-8"), "new")
        self.assertTrue(paths["ETC"].exists())
        self.assertTrue(paths["STATE"].exists())
        self.assertEqual(self.calls(), [])

    # update failures.

    def test_a_failed_update_restores_the_previous_version(self):
        paths = self.make_tree(app_contents="new")
        backup_app, backup_unit = self.make_backup("old")
        proc = self.run_rollback(
            paths, rc=1, ROLLBACK_STATE="activating", IS_UPDATE=1,
            BACKUP_APP=backup_app, BACKUP_UNIT=backup_unit,
            PREV_ACTIVE="active", PREV_ENABLED="enabled")

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(
            (paths["APP"] / "linkmoth.py").read_text(encoding="utf-8"), "old")
        self.assertEqual(
            paths["UNIT"].read_text(encoding="utf-8"), "unit=old")
        calls = self.calls()
        self.assertIn("systemctl daemon-reload", calls)
        self.assertIn("systemctl enable linkmoth", calls)
        self.assertIn("systemctl start linkmoth", calls)
        self.assertIn("restoring the previous working version", proc.stderr)

    def test_a_failed_update_does_not_start_a_service_that_was_stopped(self):
        """Restoring must reinstate the prior state, not impose a running one."""
        paths = self.make_tree()
        backup_app, backup_unit = self.make_backup("old")
        self.run_rollback(
            paths, rc=1, ROLLBACK_STATE="activating", IS_UPDATE=1,
            BACKUP_APP=backup_app, BACKUP_UNIT=backup_unit,
            PREV_ACTIVE="inactive", PREV_ENABLED="disabled")

        calls = self.calls()
        self.assertNotIn("systemctl start linkmoth", calls)
        self.assertNotIn("systemctl enable linkmoth", calls)

    def test_a_failure_before_the_swap_leaves_the_install_untouched(self):
        """The riskiest case: aborting early must not damage a working install."""
        paths = self.make_tree(app_contents="new")
        backup_app, backup_unit = self.make_backup("old")
        proc = self.run_rollback(
            paths, rc=1, ROLLBACK_STATE="prepare", IS_UPDATE=1,
            BACKUP_APP=backup_app, BACKUP_UNIT=backup_unit,
            PREV_ACTIVE="active", PREV_ENABLED="enabled")

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(
            (paths["APP"] / "linkmoth.py").read_text(encoding="utf-8"), "new")
        self.assertTrue(paths["ETC"].exists())
        self.assertTrue(paths["STATE"].exists())
        self.assertTrue(paths["UNIT"].exists())
        self.assertEqual(self.calls(), [])
        # Scratch space still goes away.
        self.assertFalse(paths["STAGE"].exists())
        self.assertFalse(backup_app.exists())

    def test_a_failed_update_never_removes_config_or_state(self):
        paths = self.make_tree()
        backup_app, backup_unit = self.make_backup("old")
        self.run_rollback(
            paths, rc=1, ROLLBACK_STATE="activating", IS_UPDATE=1,
            BACKUP_APP=backup_app, BACKUP_UNIT=backup_unit,
            # Even with the fresh-install flags wrongly set, IS_UPDATE wins.
            ETC_EXISTED=0, STATE_EXISTED=0, USER_CREATED=1,
            CA_TRUST_INSTALLED=1, UNITS_COPIED=1)

        self.assertTrue(paths["ETC"].exists())
        self.assertTrue(paths["STATE"].exists())
        self.assertNotIn("remove_ca_trust", self.calls())
        self.assertNotIn("userdel linkmoth", self.calls())

    def test_an_update_that_failed_before_its_backup_existed_is_left_alone(self):
        """If taking the backup is itself what failed, BACKUP_APP is empty and
        neither rollback branch matches. That silent fall-through is only safe
        because the backup completes before anything is swapped, so there is
        nothing to undo. Pin the ordering that makes it safe."""
        paths = self.make_tree(app_contents="new")
        proc = self.run_rollback(
            paths, rc=1, ROLLBACK_STATE="activating", IS_UPDATE=1,
            BACKUP_APP="", BACKUP_UNIT="",
            PREV_ACTIVE="active", PREV_ENABLED="enabled")

        self.assertEqual(proc.returncode, 1)
        self.assertEqual(
            (paths["APP"] / "linkmoth.py").read_text(encoding="utf-8"), "new")
        self.assertTrue(paths["ETC"].exists())
        self.assertTrue(paths["STATE"].exists())
        self.assertEqual(self.calls(), [])

    def test_the_backup_is_taken_before_anything_is_overwritten(self):
        """The ordering the previous test depends on, enforced in install.sh
        itself: if the swap ever moved above the backup, a failed update could
        leave a half written install with nothing to restore from."""
        source = INSTALL_SH.read_text(encoding="utf-8")
        backup = source.index('BACKUP_APP="$(mktemp -d)"')
        swap = source.index('swapping in the new version')
        self.assertLess(
            backup, swap,
            "the backup must be complete before the first file is overwritten")

    # fresh install failures.

    def test_a_failed_fresh_install_undoes_everything_it_created(self):
        paths = self.make_tree()
        proc = self.run_rollback(
            paths, rc=1, ROLLBACK_STATE="activating", IS_UPDATE=0,
            USER_CREATED=1, CA_TRUST_INSTALLED=1, UNITS_COPIED=1,
            ETC_EXISTED=0, STATE_EXISTED=0)

        self.assertEqual(proc.returncode, 1)
        self.assertFalse(paths["APP"].exists())
        self.assertFalse(paths["ETC"].exists())
        self.assertFalse(paths["STATE"].exists())
        self.assertFalse(paths["UNIT"].exists())
        self.assertFalse(paths["RENEW_UNIT"].exists())
        self.assertFalse(paths["RENEW_TIMER"].exists())
        self.assertFalse(paths["RENEW_SCRIPT"].exists())
        calls = self.calls()
        self.assertIn("systemctl disable --now linkmoth", calls)
        self.assertIn("systemctl disable --now linkmoth-cert-renew.timer", calls)
        self.assertIn("remove_ca_trust", calls)
        self.assertIn("userdel linkmoth", calls)

    def test_a_failed_fresh_install_keeps_a_pre_existing_config_and_state(self):
        """The data-loss guard: a config or database that predates this run is
        not this run's to delete."""
        paths = self.make_tree()
        (paths["ETC"] / "config.json").write_text("{}", encoding="utf-8")
        (paths["STATE"] / "linkmoth.db").write_text("db", encoding="utf-8")
        self.run_rollback(
            paths, rc=1, ROLLBACK_STATE="activating", IS_UPDATE=0,
            USER_CREATED=1, CA_TRUST_INSTALLED=1, UNITS_COPIED=1,
            ETC_EXISTED=1, STATE_EXISTED=1)

        self.assertTrue((paths["ETC"] / "config.json").exists())
        self.assertTrue((paths["STATE"] / "linkmoth.db").exists())
        # The half-built application directory still goes.
        self.assertFalse(paths["APP"].exists())

    def test_a_failed_fresh_install_undoes_only_what_it_actually_did(self):
        """Nothing was reached, so nothing should be torn down: no unit removal,
        no CA trust change, no account deletion."""
        paths = self.make_tree()
        self.run_rollback(
            paths, rc=1, ROLLBACK_STATE="prepare", IS_UPDATE=0,
            USER_CREATED=0, CA_TRUST_INSTALLED=0, UNITS_COPIED=0)

        calls = self.calls()
        self.assertNotIn("remove_ca_trust", calls)
        self.assertNotIn("userdel linkmoth", calls)
        self.assertEqual(
            [c for c in calls if c.startswith("systemctl disable")], [])
        self.assertTrue(paths["UNIT"].exists())
        # The partial application directory is still removed.
        self.assertFalse(paths["APP"].exists())

    def test_the_installer_exit_status_is_preserved_for_the_caller(self):
        paths = self.make_tree()
        proc = self.run_rollback(paths, rc=7, ROLLBACK_STATE="prepare",
                                 IS_UPDATE=0)
        self.assertEqual(proc.returncode, 7)

    # CA trust removal.

    def test_removing_the_ca_trust_anchor_covers_every_trust_store(self):
        """Runs the real body of remove_ca_trust with its absolute paths
        rewritten into a sandbox, so the Debian, Red Hat and Arch anchor
        locations are all proven to be cleared."""
        paths = self.make_tree()
        fakeroot = self.root / "fakeroot"
        anchors = [
            fakeroot / "usr/local/share/ca-certificates/linkmoth-local-ca.crt",
            fakeroot / "etc/pki/ca-trust/source/anchors/linkmoth-local-ca.crt",
            fakeroot / "etc/ca-certificates/trust-source/anchors/linkmoth-local-ca.crt",
        ]
        for anchor in anchors:
            anchor.parent.mkdir(parents=True, exist_ok=True)
            anchor.write_text("cert", encoding="utf-8")

        self.run_rollback(
            paths, rc=1, ROLLBACK_STATE="activating", IS_UPDATE=0,
            CA_TRUST_INSTALLED=1, real_ca_trust=True)

        for anchor in anchors:
            self.assertFalse(anchor.exists(), "%s was left trusted" % anchor)
        # Deleting the file is not enough: each distribution caches a bundle
        # that has to be rebuilt, or the certificate stays trusted in practice.
        invoked = " ".join(self.calls())
        self.assertIn("update-ca-certificates", invoked)
        self.assertIn("update-ca-trust extract", invoked)
        self.assertIn("trust extract-compat", invoked)


def shell_quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


if __name__ == "__main__":
    unittest.main()

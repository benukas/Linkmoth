"""Security-focused tests for optional browser push storage and VAPID keys."""
import os
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import linkmoth_push as push


class PushSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="linkmoth_push_"))
        self.db_path = self.tmp / "state.db"
        with self.db() as conn:
            push.init_push_db(conn)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @contextmanager
    def db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def subscription(endpoint="https://push.example.test/sub/one"):
        return {
            "endpoint": endpoint,
            "keys": {"p256dh": "public-key", "auth": "auth-key"},
        }

    def test_subscription_requires_https_and_is_capped(self):
        for endpoint in (
            "http://push.example.test/sub",
            "file:///tmp/sub",
            "https://user:pass@push.example.test/sub",
            "https://push.example.test/sub#fragment",
        ):
            with self.assertRaises(ValueError):
                push.save_subscription(self.db, self.subscription(endpoint))
        with mock.patch.object(push, "MAX_PUSH_SUBSCRIPTIONS", 1):
            push.save_subscription(self.db, self.subscription())
            with self.assertRaises(ValueError):
                push.save_subscription(
                    self.db,
                    self.subscription("https://push.example.test/sub/two"),
                )

    def test_broadcast_counts_only_confirmed_deliveries(self):
        subscriptions = [
            {"endpoint": "https://push.example.test/ok"},
            {"endpoint": "https://push.example.test/transient"},
            {"endpoint": "https://push.example.test/stale"},
        ]
        with (
            mock.patch.dict("sys.modules", {"pywebpush": mock.Mock()}),
            mock.patch.object(push, "ensure_vapid_keys", return_value=self.tmp / "key"),
            mock.patch.object(push, "list_subscriptions", return_value=subscriptions),
            mock.patch.object(
                push, "_send_one",
                side_effect=[
                    (True, None),
                    (False, None),
                    (False, "https://push.example.test/stale"),
                ],
            ),
            mock.patch.object(push, "delete_subscription") as delete,
        ):
            delivered = push.broadcast_push(
                self.tmp, self.db, {"push_notifications_enabled": True},
                "Title", "Body",
            )

        self.assertEqual(delivered, 1)
        delete.assert_called_once_with(
            self.db, "https://push.example.test/stale"
        )

    @unittest.skipIf(os.name == "nt", "Windows does not expose POSIX file modes")
    def test_vapid_key_is_written_atomically_with_private_mode(self):
        def fake_run(args, **kwargs):
            output = Path(args[args.index("-out") + 1])
            output.write_text("PRIVATE KEY")
            return mock.Mock(stdout=b"")

        with mock.patch.object(push.subprocess, "run", side_effect=fake_run):
            key = push.ensure_vapid_keys(self.tmp)
        self.assertEqual(key.read_text(), "PRIVATE KEY")
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertFalse(any(self.tmp.glob(".vapid_private.pem.*.tmp")))

    @unittest.skipIf(os.name == "nt", "Windows symlinks require Developer Mode or elevation")
    def test_symlinked_vapid_key_is_rejected(self):
        target = self.tmp / "target"
        target.write_text("not a key")
        (self.tmp / "vapid_private.pem").symlink_to(target)
        with self.assertRaises(RuntimeError):
            push.ensure_vapid_keys(self.tmp)


if __name__ == "__main__":
    unittest.main()

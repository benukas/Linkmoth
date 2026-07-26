#!/usr/bin/env python3
"""End-to-end tests for POST /api/quality/load-test.

The route used to answer {"started": true} immediately and let a background
thread run the test, with the client guessing a fixed delay before re-reading
/api/status. If the test silently failed to gather enough samples (a
transient DNS/network hiccup) nothing new was stored, and the dashboard
redisplayed whatever the *previous* successful test had left in the database
as though it were the one just requested – a stale result presented as
fresh, with no indication anything had gone wrong. The route is now
synchronous and answers with the real outcome, success or failure, in the
same response.
"""
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parent))
sys.path.insert(0, str(BASE))

from test_linkmoth_auth import LinkmothTestBase, http, SC  # noqa: E402


def _result(**overrides):
    base = {
        "ts": time.time(), "idle_ms": 10.0, "loaded_ms": 40.0, "bloat_ms": 30.0,
        "grade": "A", "throughput_mbps": None, "bytes": 0, "seconds": 5.0,
        "error": None, "active_samples": 3,
    }
    base.update(overrides)
    return base


class LoadTestRouteTests(LinkmothTestBase):
    def setUp(self):
        super().setUp()
        self._configure_auth()
        _, _, self.cookie, self.csrf = self._login()
        import linkmoth_handler as handler
        self.handler_module = handler

    def _post(self):
        return http(
            "POST", f"{self.base}/api/quality/load-test",
            headers={"X-CSRF-Token": self.csrf}, cookies={SC: self.cookie},
        )

    def test_success_returns_the_real_result_in_the_same_response(self):
        result = _result(grade="B", bloat_ms=45.0)
        with mock.patch.object(self.handler_module, "run_load_test",
                               return_value=result):
            code, body, _, _ = self._post()
        self.assertEqual(code, 200)
        self.assertEqual(body["result"]["grade"], "B")
        self.assertEqual(body["result"]["bloat_ms"], 45.0)

    def test_a_failed_test_reports_an_explicit_error_not_a_stale_success(self):
        """The exact bug reported: run_load_test() returning None (nothing
        new stored) must surface as a clear failure, never as a silent reuse
        of whatever the previous successful test left behind."""
        with mock.patch.object(self.handler_module, "run_load_test",
                               return_value=None):
            code, body, _, _ = self._post()
        self.assertEqual(code, 502)
        self.assertIn("error", body)
        self.assertNotIn("result", body)

    def test_an_unexpected_exception_is_also_reported_as_a_failure(self):
        with mock.patch.object(self.handler_module, "run_load_test",
                               side_effect=RuntimeError("boom")):
            code, body, _, _ = self._post()
        self.assertEqual(code, 502)
        self.assertIn("error", body)

    def test_the_lock_is_released_after_a_failure_so_the_next_test_can_run(self):
        with mock.patch.object(self.handler_module, "run_load_test",
                               return_value=None):
            self._post()
        with mock.patch.object(self.handler_module, "run_load_test",
                               return_value=_result()):
            code, body, _, _ = self._post()
        self.assertEqual(code, 200)
        self.assertIn("result", body)

    def test_an_invalid_load_test_url_is_rejected_before_the_lock(self):
        self.handler_module.CFG.setdefault("quality", {})["load_test_url"] = (
            "http://127.0.0.1:1/not-https"
        )
        code, body, _, _ = self._post()
        self.assertEqual(code, 400)
        self.assertIn("error", body)

    def test_unauthenticated_request_is_refused(self):
        code, _, _, _ = http("POST", f"{self.base}/api/quality/load-test")
        self.assertEqual(code, 401)


if __name__ == "__main__":
    unittest.main()

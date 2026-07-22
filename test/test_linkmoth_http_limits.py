"""Regression tests for bounded TLS connection handling."""
import importlib
import io
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))


class _BlockingTLSContext:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()

    def wrap_socket(self, request, server_side=True):
        self.started.set()
        self.release.wait(2)
        raise OSError("simulated unfinished TLS handshake")


class _PassthroughTLSContext:
    def __init__(self):
        self._condition = threading.Condition()
        self._count = 0

    def wrap_socket(self, request, server_side=True):
        with self._condition:
            self._count += 1
            self._condition.notify_all()
        return request

    def wait_for_count(self, expected, timeout):
        deadline = time.monotonic() + timeout
        with self._condition:
            while self._count < expected:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
        return True


class _TimeoutRecorder:
    def settimeout(self, value):
        self.timeout = value


class BoundedTLSServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LINKMOTH_STATE_DIR"] = tempfile.mkdtemp(prefix="linkmoth_http_")
        for _mod in ("linkmoth", 'linkmoth_core', 'linkmoth_probes', 'linkmoth_engine', 'linkmoth_handler'):
            if _mod in sys.modules:
                del sys.modules[_mod]
        cls.linkmoth = importlib.import_module("linkmoth")

        global linkmoth_core
        linkmoth_core = importlib.import_module("linkmoth_core")
        global linkmoth_handler
        linkmoth_handler = importlib.import_module("linkmoth_handler")
    def test_connection_cap_rejects_excess_slow_handshakes(self):
        context = _BlockingTLSContext()
        server = self.linkmoth.BoundedTLSServer(
            ("127.0.0.1", 0), self.linkmoth.Handler, context,
        )
        peers = []
        try:
            for _ in range(self.linkmoth.MAX_HTTP_CONNECTIONS):
                request, peer = socket.socketpair()
                peers.append(peer)
                server.process_request(request, ("127.0.0.1", 1))
            self.assertTrue(context.started.wait(1))

            excess_request, excess_peer = socket.socketpair()
            try:
                server.process_request(excess_request, ("127.0.0.1", 1))
                excess_peer.settimeout(1)
                self.assertEqual(excess_peer.recv(1), b"")
            finally:
                excess_peer.close()
        finally:
            context.release.set()
            for peer in peers:
                peer.close()
            time.sleep(0.05)
            server.server_close()

    def test_rejected_worker_submission_closes_socket_and_releases_slot(self):
        server = self.linkmoth.BoundedTLSServer(
            ("127.0.0.1", 0), self.linkmoth.Handler, _PassthroughTLSContext(),
        )
        request, peer = socket.socketpair()
        try:
            with mock.patch.object(
                server._workers, "submit", side_effect=RuntimeError("shutting down"),
            ):
                server.process_request(request, ("127.0.0.1", 1))
            peer.settimeout(1)
            self.assertEqual(peer.recv(1), b"")

            acquired = 0
            while server._slots.acquire(blocking=False):
                acquired += 1
            self.assertEqual(acquired, self.linkmoth.MAX_HTTP_CONNECTIONS)
            for _ in range(acquired):
                server._slots.release()
        finally:
            peer.close()
            server.server_close()

    def test_partial_headers_release_all_workers_after_total_deadline(self):
        context = _PassthroughTLSContext()

        class HealthyHandler(self.linkmoth.Handler):
            def do_GET(self):
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()

        peers = []
        with mock.patch.object(
            linkmoth_core, "REQUEST_HEADER_DEADLINE_SECONDS", 0.3,
        ):
            server = self.linkmoth.BoundedTLSServer(
                ("127.0.0.1", 0), HealthyHandler, context,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for _ in range(self.linkmoth.MAX_HTTP_CONNECTIONS):
                    peer = socket.create_connection(server.server_address, timeout=1)
                    peer.settimeout(2)
                    peer.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Stall:")
                    peers.append(peer)
                self.assertTrue(
                    context.wait_for_count(self.linkmoth.MAX_HTTP_CONNECTIONS, 2)
                )
                time.sleep(0.4)
                # Each stalled connection must be terminated past the deadline: a
                # 408, a clean close, or a reset all show the worker was released.
                # Only a recv that blocks to its own timeout means the connection
                # was still being serviced – the bug this guards against.
                for peer in peers:
                    try:
                        data = peer.recv(256)
                    except socket.timeout:
                        self.fail("stalled connection was not released after the deadline")
                    except (ConnectionError, OSError):
                        continue
                    self.assertTrue(data == b"" or b" 408 " in data, data)

                time.sleep(0.05)
                fresh = socket.create_connection(server.server_address, timeout=1)
                try:
                    fresh.settimeout(2)
                    fresh.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    self.assertIn(b" 204 ", fresh.recv(256))
                finally:
                    fresh.close()
            finally:
                for peer in peers:
                    peer.close()
                server.shutdown()
                thread.join(2)
                server.server_close()

    def test_drip_fed_headers_cannot_extend_the_deadline(self):
        # A client that trickles one byte at a time, faster than any per-read
        # timeout, must be cut off at the total wall-clock deadline: neither held
        # open past it (the slow-loris bypass) NOR closed early on the first read
        # gap (which would collapse the deadline to the poll interval and break
        # legitimate slow clients). This guards both failure modes.
        context = _PassthroughTLSContext()

        class HealthyHandler(self.linkmoth.Handler):
            def do_GET(self):
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()

        deadline_s = 0.6
        with mock.patch.object(
            linkmoth_core, "REQUEST_HEADER_DEADLINE_SECONDS", deadline_s,
        ), mock.patch.object(linkmoth_handler, "HEADER_POLL_SECONDS", 0.1):
            server = self.linkmoth.BoundedTLSServer(
                ("127.0.0.1", 0), HealthyHandler, context,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                peer = socket.create_connection(server.server_address, timeout=1)
                peer.settimeout(2)
                peer.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Stall:")

                # Drip one byte every 0.1s (well under the 0.1s poll) and watch
                # how long the connection stays writable and when it terminates.
                t0 = time.monotonic()
                survived_drips = 0
                terminated_at = None
                for _ in range(30):  # up to ~3s
                    time.sleep(0.1)
                    try:
                        peer.sendall(b"a")
                        survived_drips += 1
                    except OSError:
                        terminated_at = time.monotonic() - t0
                        break
                    peer.settimeout(0.02)
                    try:
                        if peer.recv(64):
                            terminated_at = time.monotonic() - t0
                            break
                    except socket.timeout:
                        pass
                    except OSError:
                        terminated_at = time.monotonic() - t0
                        break
                    peer.settimeout(2)
                peer.close()

                # It must have survived clearly more than one poll interval: a
                # deadline that collapsed to the poll would close it on the first
                # gap. Deadline 0.6s / drip 0.1s leaves room for several drips.
                self.assertGreaterEqual(
                    survived_drips, 3,
                    "connection closed too early – deadline collapsed to the poll",
                )
                # And it must have been terminated near the deadline, not held
                # open for the whole drip (the slow-loris bypass).
                self.assertIsNotNone(
                    terminated_at, "drip-fed connection was never terminated",
                )
                self.assertLess(terminated_at, deadline_s + 1.5)

                # Pool released: a fresh, well-formed request is served now.
                fresh = socket.create_connection(server.server_address, timeout=1)
                try:
                    fresh.settimeout(2)
                    fresh.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    self.assertIn(b" 204 ", fresh.recv(256))
                finally:
                    fresh.close()
            finally:
                server.shutdown()
                thread.join(2)
                server.server_close()

    def test_body_after_over_read_headers_is_preserved(self):
        # A read1() chunk can span the blank line into the body; the wrapper must
        # serve those buffered body bytes from read(), not lose them.
        connection = _TimeoutRecorder()
        raw = (
            b"POST /x HTTP/1.1\r\nHost: localhost\r\n"
            b"Content-Length: 11\r\n\r\nhello world"
        )
        reader = self.linkmoth._BoundedHeaderReader(
            io.BytesIO(raw), connection, time.monotonic() + 5,
        )
        # Drain the request line + headers exactly as the stdlib parser does.
        self.assertEqual(reader.readline(), b"POST /x HTTP/1.1\r\n")
        while True:
            line = reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
        reader.finish_headers()
        self.assertEqual(reader.read(11), b"hello world")

    def test_total_header_bytes_are_capped(self):
        connection = _TimeoutRecorder()
        reader = self.linkmoth._BoundedHeaderReader(
            io.BytesIO(b"GET / HTTP/1.1\r\nX-Long: " + b"a" * 80 + b"\r\n"),
            connection,
            time.monotonic() + 1,
        )
        with mock.patch.object(linkmoth_handler, "MAX_HTTP_HEADER_BYTES", 64):
            reader.readline()
            with self.assertRaises(self.linkmoth._HeaderLimitExceeded):
                reader.readline()

    def test_header_count_is_capped(self):
        connection = _TimeoutRecorder()
        reader = self.linkmoth._BoundedHeaderReader(
            io.BytesIO(b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n"),
            connection,
            time.monotonic() + 1,
        )
        with mock.patch.object(linkmoth_handler, "MAX_HTTP_HEADER_COUNT", 2):
            reader.readline()
            reader.readline()
            reader.readline()
            with self.assertRaises(self.linkmoth._HeaderLimitExceeded):
                reader.readline()


if __name__ == "__main__":
    unittest.main()

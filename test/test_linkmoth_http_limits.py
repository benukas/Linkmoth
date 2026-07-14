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
        if "linkmoth" in sys.modules:
            del sys.modules["linkmoth"]
        cls.linkmoth = importlib.import_module("linkmoth")

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

    def test_partial_headers_release_all_workers_after_total_deadline(self):
        context = _PassthroughTLSContext()

        class HealthyHandler(self.linkmoth.Handler):
            def do_GET(self):
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()

        peers = []
        with mock.patch.object(
            self.linkmoth, "REQUEST_HEADER_DEADLINE_SECONDS", 0.3,
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
                for peer in peers:
                    self.assertIn(b" 408 ", peer.recv(256))

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

    def test_total_header_bytes_are_capped(self):
        connection = _TimeoutRecorder()
        reader = self.linkmoth._BoundedHeaderReader(
            io.BytesIO(b"GET / HTTP/1.1\r\nX-Long: " + b"a" * 80 + b"\r\n"),
            connection,
            time.monotonic() + 1,
        )
        with mock.patch.object(self.linkmoth, "MAX_HTTP_HEADER_BYTES", 64):
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
        with mock.patch.object(self.linkmoth, "MAX_HTTP_HEADER_COUNT", 2):
            reader.readline()
            reader.readline()
            reader.readline()
            with self.assertRaises(self.linkmoth._HeaderLimitExceeded):
                reader.readline()


if __name__ == "__main__":
    unittest.main()

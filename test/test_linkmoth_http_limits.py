"""Regression tests for bounded TLS connection handling."""
import importlib
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()

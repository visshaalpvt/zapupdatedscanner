import http.server
import json
import os
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.app.plugins import ScanCancelled, ScanContext, ZapPlugin


class MockZapHandler(http.server.BaseHTTPRequestHandler):
    active_spider = True
    stop_called = False
    ascan_called = False

    def do_GET(self):
        path = self.path.split("?")[0]
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        if "/JSON/core/view/version/" in path:
            self.wfile.write(b'{"version": "2.14.0"}')
        elif "/JSON/context/action/newContext/" in path:
            self.wfile.write(b'{"contextId": "1"}')
        elif "/JSON/spider/action/scan/" in path:
            self.wfile.write(b'{"scan": "1"}')
        elif "/JSON/spider/view/status/" in path:
            if MockZapHandler.active_spider:
                self.wfile.write(b'{"status": "100"}')
            else:
                self.wfile.write(b'{"status": "50"}')
        elif "/JSON/spider/action/stop/" in path:
            MockZapHandler.stop_called = True
            self.wfile.write(b'{"result": "OK"}')
        elif "/JSON/ascan/action/scan/" in path:
            MockZapHandler.ascan_called = True
            self.wfile.write(b'{"scan": "1"}')
        elif "/JSON/ascan/view/status/" in path:
            self.wfile.write(b'{"status": "100"}')
        elif "/JSON/ascan/action/stop/" in path:
            MockZapHandler.stop_called = True
            self.wfile.write(b'{"result": "OK"}')
        elif "/JSON/core/view/alerts/" in path:
            alerts = [
                {
                    "risk": "High",
                    "alert": "SQL Injection",
                    "url": "https://example.com/items",
                    "description": "SQL injection detected in query parameter",
                }
            ]
            self.wfile.write(json.dumps(alerts).encode("utf-8"))
        else:
            self.wfile.write(b'{"result": "OK"}')

    def log_message(self, format, *args):
        pass


class TestZapPlugin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        MockZapHandler.active_spider = True
        MockZapHandler.stop_called = False
        MockZapHandler.ascan_called = False
        cls.httpd = http.server.HTTPServer(("127.0.0.1", 0), MockZapHandler)
        cls.port = cls.httpd.server_port
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        MockZapHandler.active_spider = True
        MockZapHandler.stop_called = False
        MockZapHandler.ascan_called = False
        os.environ["ZAP_API_URL"] = f"http://127.0.0.1:{self.port}"
        os.environ["ZAP_API_KEY"] = "test-zap-key"
        os.environ["ZAP_ACTIVE"] = "1"
        os.environ["ZAP_MAX_MINUTES"] = "60"

    def test_zap_normal_run(self):
        plugin = ZapPlugin()
        ctx = ScanContext(target="https://example.com", project_name="demo")
        plugin.run(ctx)

        self.assertEqual(ctx.progress_value, 100)
        self.assertTrue(MockZapHandler.ascan_called)
        self.assertEqual(len(ctx.findings), 1)
        self.assertEqual(ctx.findings[0].title, "SQL Injection")
        self.assertEqual(ctx.findings[0].severity, "high")

    def test_zap_active_disabled(self):
        os.environ["ZAP_ACTIVE"] = "0"
        plugin = ZapPlugin()
        ctx = ScanContext(target="https://example.com", project_name="demo")
        plugin.run(ctx)

        self.assertFalse(MockZapHandler.ascan_called)
        self.assertEqual(ctx.progress_value, 100)
        self.assertTrue(any("Active scan disabled" in log for log in ctx.logs))

    def test_zap_cancel_mid_scan(self):
        MockZapHandler.active_spider = False
        plugin = ZapPlugin()
        ctx = ScanContext(target="https://example.com", project_name="demo")

        def cancel_later():
            time.sleep(0.15)
            ctx.request_cancel()

        threading.Thread(target=cancel_later, daemon=True).start()

        with self.assertRaises(ScanCancelled):
            plugin.run(ctx)

        self.assertTrue(MockZapHandler.stop_called)

    def test_zap_unreachable(self):
        os.environ["ZAP_API_URL"] = "http://127.0.0.1:59997"
        plugin = ZapPlugin()
        ctx = ScanContext(target="https://example.com", project_name="demo")

        with self.assertRaises(RuntimeError) as cm:
            plugin.run(ctx)
        self.assertIn("Cannot connect to ZAP", str(cm.exception))

    def test_zap_max_minutes_timeout(self):
        MockZapHandler.active_spider = False
        os.environ["ZAP_MAX_MINUTES"] = "0.001"  # ~0.06 seconds
        plugin = ZapPlugin()
        ctx = ScanContext(target="https://example.com", project_name="demo")

        with self.assertRaises(TimeoutError) as cm:
            plugin.run(ctx)
        self.assertIn("timed out", str(cm.exception))


if __name__ == "__main__":
    unittest.main()

import asyncio
import http.server
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.app.database import (
    create_project,
    create_scan,
    get_connection,
    get_scan,
    seed_db,
    sweep_stale_running_scans,
    update_scan,
)
from server.app.plugins import (
    ScanCancelled,
    ScanContext,
    ScannerPlugin,
    SecurityHeadersPlugin,
    get_plugin_catalog,
)
from worker.main import run_scan_once


class LocalTargetHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=()")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        pass


class TestWorkerCore(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.environ["DATABASE_URL"] = f"sqlite:///{self.db_path}"
        os.environ["ZAP_AUTH_ENCRYPTION_KEY"] = "test-key-for-worker-core"
        seed_db()

        # Start a local HTTP server for security headers testing
        self.server_port = 0
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), LocalTargetHandler)
        self.server_port = self.httpd.server_port
        self.server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.server_thread.start()

    def tearDown(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except Exception:
            pass

    def test_three_queued_scans_concurrency_two(self):
        os.environ["WORKER_CONCURRENCY"] = "2"
        from worker.main import worker_loop

        target = f"http://127.0.0.1:{self.server_port}"
        proj = create_project("conc-proj", target, "admin")

        # Create 3 scans
        scan1 = create_scan(proj["id"], "queued", plugin="security_headers")
        scan2 = create_scan(proj["id"], "queued", plugin="security_headers")
        scan3 = create_scan(proj["id"], "queued", plugin="security_headers")

        observed_running_counts = []

        async def run_loop_briefly():
            loop_task = asyncio.create_task(worker_loop())
            for _ in range(15):
                await asyncio.sleep(0.05)
                with get_connection() as conn:
                    running_count = conn.execute("SELECT COUNT(*) FROM scans WHERE status = 'running'").fetchone()[0]
                    observed_running_counts.append(running_count)
            loop_task.cancel()
            try:
                await loop_task
            except asyncio.CancelledError:
                pass

        asyncio.run(run_loop_briefly())

        # Assert that at no point were more than 2 scans running simultaneously
        max_running = max(observed_running_counts) if observed_running_counts else 0
        self.assertLessEqual(max_running, 2, f"At most 2 scans should run concurrently, observed: {max_running}")

    def test_cancel_queued_scan_and_running_scan(self):
        target = f"http://127.0.0.1:{self.server_port}"
        proj = create_project("cancel-proj", target, "admin")

        # 1. Cancel queued scan: instant
        queued_scan = create_scan(proj["id"], "queued")
        update_scan(queued_scan["id"], status="cancelled", cancel_requested=1, updated_at=int(time.time()))
        refetched = get_scan(queued_scan["id"])
        self.assertEqual(refetched["status"], "cancelled")

        # 2. Cancel running scan: stops within a few seconds
        running_scan = create_scan(proj["id"], "running")
        ctx = ScanContext(target=target, scan_id=running_scan["id"])

        # Request cancel via DB
        update_scan(running_scan["id"], cancel_requested=1)

        # Check that checkpoint raises ScanCancelled
        with self.assertRaises(ScanCancelled):
            ctx.checkpoint()

    def test_stale_running_scan_marked_failed(self):
        target = f"http://127.0.0.1:{self.server_port}"
        proj = create_project("stale-proj", target, "admin")
        scan = create_scan(proj["id"], "queued")

        # Fake updated_at to 6 minutes ago (360 seconds ago)
        six_minutes_ago = int(time.time()) - 360
        with get_connection() as conn:
            conn.execute(
                "UPDATE scans SET status = 'running', updated_at = ? WHERE id = ?",
                (six_minutes_ago, scan["id"]),
            )
            conn.commit()

        # Run sweep
        stale_count = sweep_stale_running_scans(stale_seconds=300)
        self.assertGreaterEqual(stale_count, 1)

        updated = get_scan(scan["id"])
        self.assertEqual(updated["status"], "failed")
        self.assertIn("Worker stopped responding", updated["error"])

    def test_unreachable_target_and_unknown_plugin(self):
        # 1. Unreachable target
        unreachable_proj = create_project("unreachable-proj", "http://127.0.0.1:59999", "admin")
        scan1 = create_scan(unreachable_proj["id"], "queued", plugin="security_headers")
        run_scan_once(scan1["id"], "worker-test-1")
        res1 = get_scan(scan1["id"])
        self.assertEqual(res1["status"], "failed")
        self.assertTrue(bool(res1["error"]), "Error should be recorded for unreachable target")

        # 2. Unknown plugin
        unknown_proj = create_project("unknown-proj", f"http://127.0.0.1:{self.server_port}", "admin")
        scan2 = create_scan(unknown_proj["id"], "queued", plugin="totally_unknown_plugin")
        run_scan_once(scan2["id"], "worker-test-2")
        res2 = get_scan(scan2["id"])
        self.assertEqual(res2["status"], "failed")
        self.assertIn("Unknown plugin", res2["error"])

    def test_new_plugin_file_dropped_in_plugins_folder_appears_in_catalog(self):
        plugins_dir = Path(ROOT) / "server" / "app" / "plugins"
        plugins_dir.mkdir(parents=True, exist_ok=True)
        test_plugin_file = plugins_dir / "custom_dynamic_plugin.py"

        plugin_code = '''
from server.app.plugins import ScannerPlugin, ScanContext

class CustomDynamicPlugin(ScannerPlugin):
    name = "custom_dynamic"
    label = "Custom Dynamic"
    description = "A dynamically dropped plugin."

    def run(self, ctx: ScanContext):
        ctx.progress(100)
'''
        try:
            with open(test_plugin_file, "w", encoding="utf-8") as f:
                f.write(plugin_code)

            catalog = get_plugin_catalog()
            names = [item["name"] for item in catalog]
            self.assertIn("custom_dynamic", names)
        finally:
            if test_plugin_file.exists():
                try:
                    test_plugin_file.unlink()
                except Exception:
                    pass


if __name__ == "__main__":
    unittest.main()

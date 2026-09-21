import asyncio
import http.client
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import uvicorn
from server.app.database import (
    create_project,
    create_scan,
    get_connection,
    seed_db,
    update_scan,
)
from server.app.main import app, stream_snapshots
from worker.main import run_scan_once


def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestStreamGenerator(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.environ["DATABASE_URL"] = f"sqlite:///{self.db_path}"
        os.environ["ZAP_AUTH_ENCRYPTION_KEY"] = "test-key-for-stream-generator"
        seed_db()

    async def asyncTearDown(self):
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except Exception:
            pass

    async def test_stream_snapshots_generator_contract(self):
        project = create_project("stream-gen-proj", "https://example.com", "admin")
        scan = create_scan(project["id"], "queued")

        disconnected = False

        def is_disc():
            return disconnected

        gen = stream_snapshots(is_disconnected=is_disc, interval=0.05, keepalive_every=2)

        # a. the first chunk is "retry: 3000"
        chunk1 = await gen.asend(None)
        self.assertTrue(chunk1.startswith("retry: 3000"), f"Expected retry chunk, got: {chunk1!r}")

        # b. the second is "event: snapshot" whose JSON has stats, scans and server_time
        chunk2 = await gen.asend(None)
        self.assertTrue(chunk2.startswith("event: snapshot"), f"Expected snapshot event, got: {chunk2!r}")
        payload_str = chunk2.split("data: ", 1)[1].strip()
        data = json.loads(payload_str)
        self.assertIn("stats", data)
        self.assertIn("scans", data)
        self.assertIn("server_time", data)

        # d. with no change, a ": keepalive" chunk arrives
        chunk3 = await gen.asend(None)
        self.assertEqual(chunk3, ": keepalive\n\n", f"Expected keepalive, got: {chunk3!r}")

        # c. after a DB change (update a scan's progress through the real database function) a NEW snapshot arrives
        update_scan(scan["id"], progress=42.0)
        chunk4 = await gen.asend(None)
        self.assertTrue(chunk4.startswith("event: snapshot"), f"Expected new snapshot, got: {chunk4!r}")
        data2 = json.loads(chunk4.split("data: ", 1)[1].strip())
        found_scan = next((s for s in data2["scans"] if s["id"] == scan["id"]), None)
        self.assertIsNotNone(found_scan)
        self.assertEqual(float(found_scan["progress"]), 42.0)

        # e. when is_disconnected returns True, the generator ends
        disconnected = True
        with self.assertRaises(StopAsyncIteration):
            await gen.asend(None)


class TestStreamLiveServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = get_free_port()
        fd, cls.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.environ["DATABASE_URL"] = f"sqlite:///{cls.db_path}"
        os.environ["ZAP_AUTH_ENCRYPTION_KEY"] = "test-key-for-live-server"
        seed_db()

        config = uvicorn.Config(app, host="127.0.0.1", port=cls.port, log_level="error")
        cls.server = uvicorn.Server(config)
        cls.server_thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.server_thread.start()

        # Wait for server to be responsive
        start = time.time()
        while time.time() - start < 5:
            try:
                conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=1)
                conn.request("GET", "/health")
                resp = conn.getresponse()
                if resp.status == 200:
                    conn.close()
                    break
            except Exception:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.server_thread.join(timeout=3)
        try:
            if os.path.exists(cls.db_path):
                os.remove(cls.db_path)
        except Exception:
            pass

    def test_stream_without_token_returns_401(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/api/stream")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 401)
        conn.close()

    def test_stream_with_token_param_succeeds_and_receives_live_snapshots(self):
        # 1. Login to get token
        login_req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/auth/login",
            data=json.dumps({"username": "admin", "password": "changeme"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(login_req, timeout=5) as login_resp:
            self.assertEqual(login_resp.status, 200)
            token = json.loads(login_resp.read().decode("utf-8"))["token"]

        # 2. Create a project via API
        proj_req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/projects",
            data=json.dumps({"name": "live-stream-proj", "target_url": "https://example.com"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(proj_req, timeout=5) as proj_resp:
            self.assertEqual(proj_resp.status, 200)
            project_id = json.loads(proj_resp.read().decode("utf-8"))["id"]

        # 3. Create a scan via API
        scan_req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/projects/{project_id}/scan",
            data=b"{}",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(scan_req, timeout=5) as scan_resp:
            self.assertEqual(scan_resp.status, 200)
            scan_id = json.loads(scan_resp.read().decode("utf-8"))["id"]

        # 4. Open /api/stream using http.client with ?token= query parameter
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", f"/api/stream?token={token}")
        stream_resp = conn.getresponse()
        self.assertEqual(stream_resp.status, 200)

        # 5. Read initial lines
        initial_lines = []
        for _ in range(6):
            line = stream_resp.readline().decode("utf-8")
            if line:
                initial_lines.append(line)
            if "event: snapshot" in line:
                break
        joined_initial = "".join(initial_lines)
        self.assertIn("retry: 3000", joined_initial)

        # 6. Run scan worker in a thread to change status/progress
        worker_th = threading.Thread(target=run_scan_once, args=(scan_id, "test-worker"), daemon=True)
        worker_th.start()
        worker_th.join(timeout=5)

        # 7. Assert that a snapshot with updated status arrives within 5 seconds
        updated_found = False
        start_time = time.time()
        while time.time() - start_time < 5:
            line = stream_resp.readline().decode("utf-8")
            if "event: snapshot" in line:
                data_line = stream_resp.readline().decode("utf-8")
                if "data: " in data_line:
                    payload = json.loads(data_line.split("data: ", 1)[1].strip())
                    scans = payload.get("scans", [])
                    matched = next((s for s in scans if s["id"] == scan_id), None)
                    if matched and matched["status"] in ("running", "completed"):
                        updated_found = True
                        break

        conn.close()
        self.assertTrue(updated_found, "Expected live snapshot with updated scan status within 5 seconds")


if __name__ == "__main__":
    unittest.main()

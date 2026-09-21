import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from starlette.testclient import TestClient

from server.app.database import (
    claim_idle_zap_node,
    create_project,
    create_project_attachment,
    create_scan,
    get_connection,
    get_engine,
    get_scan,
    list_project_attachments,
    release_zap_node,
    seed_db,
    update_scan,
    verify_password,
)


class TestMvpCore(unittest.TestCase):
    def setUp(self):
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
        os.environ["ZAP_AUTH_ENCRYPTION_KEY"] = "test-local-key-for-zap-auth"
        self.db_path = db_path
        seed_db()
        from server.app.main import app
        self.client = TestClient(app)

    def tearDown(self):
        try:
            self.client.close()
        except Exception:
            pass
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except PermissionError:
            pass

    def test_seed_creates_admin_user(self):
        self.assertTrue(verify_password("admin", "changeme"))

    def test_projects_require_auth_and_login_returns_token(self):
        unauth_resp = self.client.get("/projects")
        self.assertEqual(unauth_resp.status_code, 401)

        login_resp = self.client.post(
            "/auth/login",
            json={"username": "admin", "password": "changeme"},
        )
        self.assertEqual(login_resp.status_code, 200)
        token = login_resp.json()["token"]
        self.assertIn("token:", token)

        authed = self.client.get(
            "/projects",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(authed.status_code, 200)

    def test_target_credentials_are_not_persisted_by_default_but_scan_override_is(self):
        login_resp = self.client.post(
            "/auth/login",
            json={"username": "admin", "password": "changeme"},
        )
        token = login_resp.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        project_resp = self.client.post(
            "/projects",
            json={
                "name": "credential-test-project",
                "target_url": "https://example.com",
                "auth_config": {
                    "requires_auth": True,
                    "login_url": "https://example.com/login",
                    "username_field": "email",
                    "password_field": "password",
                    "username": "alice@example.com",
                    "password": "super-secret",
                },
            },
            headers=headers,
        )
        self.assertEqual(project_resp.status_code, 200)
        project = project_resp.json()
        saved_auth = project.get("auth_config")
        self.assertIsInstance(saved_auth, dict)
        self.assertEqual(saved_auth.get("username", ""), "***")
        self.assertEqual(saved_auth.get("password", ""), "***")
        self.assertFalse(saved_auth.get("encrypted", False))

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT auth_config FROM projects WHERE id = ?", (project["id"],)).fetchone()
            stored_project_auth = json.loads(row[0] or "{}")
            self.assertNotIn("alice@example.com", json.dumps(stored_project_auth))
            self.assertNotIn("super-secret", json.dumps(stored_project_auth))

        scan_resp = self.client.post(
            f"/projects/{project['id']}/scan",
            json={
                "auth_config": {
                    "requires_auth": True,
                    "login_url": "https://example.com/login",
                    "username_field": "email",
                    "password_field": "password",
                    "username": "scan-user@example.com",
                    "password": "scan-secret",
                }
            },
            headers=headers,
        )
        self.assertEqual(scan_resp.status_code, 200)
        scan = scan_resp.json()
        scan_auth = scan.get("auth_config")
        self.assertIsInstance(scan_auth, dict)
        self.assertEqual(scan_auth["username"], "***")
        self.assertEqual(scan_auth["password"], "***")
        self.assertNotIn("scan-user@example.com", json.dumps(scan_auth))
        self.assertNotIn("scan-secret", json.dumps(scan_auth))

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT auth_config FROM scans WHERE id = ?", (scan["id"],)).fetchone()
            stored_scan_auth = json.loads(row[0] or "{}")
            self.assertNotIn("scan-user@example.com", json.dumps(stored_scan_auth))
            self.assertNotIn("scan-secret", json.dumps(stored_scan_auth))
            self.assertTrue(stored_scan_auth.get("encrypted", False))

        self.client.post(
            f"/projects/{project['id']}/scan",
            json={
                "auth_config": {
                    "requires_auth": True,
                    "login_url": "https://example.com/login",
                    "username_field": "email",
                    "password_field": "password",
                    "username": "final-user@example.com",
                    "password": "final-secret",
                }
            },
            headers=headers,
        )

    def test_encrypt_and_decrypt_round_trip_for_scan_credentials(self):
        project_name = f"roundtrip-project-{uuid.uuid4().hex[:8]}"
        project = create_project(project_name, "https://example.com", "admin")
        auth = {
            "requires_auth": True,
            "login_url": "https://example.com/login",
            "username_field": "email",
            "password_field": "password",
            "username": "roundtrip@example.com",
            "password": "roundtrip-secret",
        }

        created = create_scan(project["id"], "queued", auth_config=auth)
        self.assertEqual(created["auth_config"]["username"], "***")
        self.assertEqual(created["auth_config"]["password"], "***")

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT auth_config FROM scans WHERE id = ?", (created["id"],)).fetchone()
            stored = json.loads(row[0] or "{}")
            self.assertNotIn("roundtrip@example.com", json.dumps(stored))
            self.assertNotIn("roundtrip-secret", json.dumps(stored))
            self.assertTrue(stored.get("encrypted", False))

    def test_scan_result_uses_real_alert_counts_and_worker_phase_strings(self):
        from unittest.mock import patch

        from server.app import zap_client as zap_client_module

        class FakeCore:
            @staticmethod
            def alerts_summary(baseurl=None):
                return {"1": 2, "2": 3, "3": 1}

        class FakeZap:
            def __init__(self):
                self.core = FakeCore()

            def urlopen(self, url):
                return None

        messages = []
        auth_config = {
            "requires_auth": True,
            "login_url": "https://example.com/login",
            "username_field": "email",
            "password_field": "password",
            "username": "demo@example.com",
            "password": "demo-secret",
        }

        with patch.object(zap_client_module, "connect_zap", return_value=FakeZap()), \
             patch.object(zap_client_module, "setup_context_and_auth", return_value=(1, 2)) as mock_setup, \
             patch.object(zap_client_module, "run_spider"), \
             patch.object(zap_client_module, "run_ajax_spider"), \
             patch.object(zap_client_module, "run_active_scan"), \
             patch.object(zap_client_module, "save_html_report", return_value="/tmp/demo-report.html"), \
             patch.object(zap_client_module, "PROJECTS_DIR", ROOT):
            result = zap_client_module.run_full_scan(
                "http://zap1:8080",
                "https://example.com",
                auth_config,
                lambda msg: messages.append(msg),
            )

        self.assertEqual(result["low_count"], 2)
        self.assertEqual(result["medium_count"], 3)
        self.assertEqual(result["high_count"], 1)
        phase_prefixes = ("Spidering", "Running AJAX", "Running active", "Generating")
        emitted_phase_messages = [msg for msg in messages if msg.startswith(phase_prefixes)]
        self.assertEqual(len(emitted_phase_messages), 4)
        self.assertTrue(any(msg.startswith("Spidering") for msg in emitted_phase_messages))
        self.assertTrue(any(msg.startswith("Running AJAX") for msg in emitted_phase_messages))
        self.assertTrue(any(msg.startswith("Running active") for msg in emitted_phase_messages))
        self.assertTrue(any(msg.startswith("Generating") for msg in emitted_phase_messages))
        self.assertEqual(mock_setup.call_args[0][4], auth_config)

    def test_scan_events_store_phase_and_message_for_worker_streams(self):
        project = create_project(f"stream-project-{uuid.uuid4().hex[:8]}", "https://example.com", "admin")
        scan = create_scan(project["id"], "running")

        from server.app.database import append_scan_event, list_scan_events

        append_scan_event(scan["id"], "Spidering target https://example.com", phase="Spidering")
        append_scan_event(scan["id"], "Running AJAX spider against https://example.com", phase="Running AJAX")

        events = list_scan_events(scan["id"])
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["phase"], "Spidering")
        self.assertIn("Spidering target", events[0]["message"])
        self.assertEqual(events[1]["phase"], "Running AJAX")
        self.assertIn("Running AJAX", events[1]["message"])

    def test_worker_raw_fetch_path_decrypts_real_credentials(self):
        project = create_project(
            f"worker-fetch-project-{uuid.uuid4().hex[:8]}", "https://example.com", "admin"
        )
        auth = {
            "requires_auth": True,
            "login_url": "https://example.com/login",
            "username_field": "email",
            "password_field": "password",
            "username": "raw-fetch@example.com",
            "password": "raw-fetch-secret",
        }
        scan = create_scan(project["id"], "queued", auth_config=auth)

        fetched_via_public = get_scan(scan["id"])
        self.assertEqual(fetched_via_public["auth_config"]["username"], "***")
        self.assertEqual(fetched_via_public["auth_config"]["password"], "***")

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ?",
                (scan["id"],),
            ).fetchone()
            raw_scan = dict(row)

        raw_auth_config = raw_scan.get("auth_config")
        self.assertIsInstance(raw_auth_config, str)
        self.assertNotIn("***", raw_auth_config)
        self.assertNotIn("raw-fetch@example.com", raw_auth_config)
        self.assertNotIn("raw-fetch-secret", raw_auth_config)

        auth_config = raw_scan.get("auth_config")
        if isinstance(auth_config, str):
            auth_config = json.loads(auth_config)
        from server.app.database import normalize_auth_config
        decrypted = normalize_auth_config(auth_config) if isinstance(auth_config, (dict, str)) else None

        self.assertIsNotNone(decrypted)
        self.assertEqual(decrypted["username"], "raw-fetch@example.com")
        self.assertEqual(decrypted["password"], "raw-fetch-secret")

    def test_worker_decrypts_scan_auth_before_running_scan(self):
        project = create_project(f"decrypt-project-{uuid.uuid4().hex[:8]}", "https://example.com", "admin")
        auth = {
            "requires_auth": True,
            "login_url": "https://example.com/login",
            "username_field": "email",
            "password_field": "password",
            "username": "worker@example.com",
            "password": "worker-secret",
        }
        scan = create_scan(project["id"], "queued", auth_config=auth)

        self.assertEqual(scan["auth_config"]["username"], "***")
        self.assertEqual(scan["auth_config"]["password"], "***")

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT auth_config FROM scans WHERE id = ?", (scan["id"],)).fetchone()
            stored = json.loads(row[0] or "{}")
            self.assertNotIn("worker@example.com", json.dumps(stored))
            self.assertNotIn("worker-secret", json.dumps(stored))

        from server.app.database import normalize_auth_config
        stored_row = json.loads(json.dumps({
            "encrypted": True,
            "username": stored["username"],
            "password": stored["password"],
            "save_credentials": True,
        }))
        restored = normalize_auth_config(stored_row)
        self.assertEqual(restored["username"], "worker@example.com")
        self.assertEqual(restored["password"], "worker-secret")

    def test_update_scan_current_timestamp_is_sql_expression_not_literal(self):
        project = create_project(f"ts-project-{uuid.uuid4().hex[:8]}", "https://example.com", "admin")
        scan = create_scan(project["id"], "queued")

        update_scan(scan["id"], status="done", finished_at="CURRENT_TIMESTAMP")

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT finished_at FROM scans WHERE id = ?", (scan["id"],)).fetchone()
            self.assertIsNotNone(row)
            self.assertIsNotNone(row[0])
            self.assertNotEqual(row[0], "CURRENT_TIMESTAMP")
            self.assertRegex(str(row[0]), r"\d{4}-\d{2}-\d{2}")

    def test_create_project_and_scan(self):
        project_name = f"demo-project-{uuid.uuid4().hex[:8]}"
        project = create_project(project_name, "https://example.com", "admin")
        self.assertEqual(project["name"], project_name)
        scan = create_scan(project["id"], "queued")
        self.assertEqual(scan["status"], "queued")

    def test_create_and_list_project_attachments(self):
        project_name = f"attachment-project-{uuid.uuid4().hex[:8]}"
        project = create_project(project_name, "https://example.com", "admin")
        link = create_project_attachment(project["id"], "link", "Figma", "https://example.com/figma", "admin")
        file = create_project_attachment(project["id"], "file", "notes.txt", "/tmp/notes.txt", "admin")

        attachments = list_project_attachments(project["id"])
        self.assertEqual(len(attachments), 2)
        self.assertEqual(link["type"], "link")
        self.assertEqual(file["type"], "file")
        self.assertEqual(attachments[0]["project_id"], project["id"])

    def test_attachment_upload_list_delete_and_unauthorized_delete(self):
        project = create_project(f"attachment-api-project-{uuid.uuid4().hex[:8]}", "https://example.com", "admin")
        login_resp = self.client.post(
            "/auth/login",
            json={"username": "admin", "password": "changeme"},
        )
        token = login_resp.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        upload_resp = self.client.post(
            f"/projects/{project['id']}/attachments",
            files={"file": ("../../notes.txt", b"hello world", "text/plain")},
            data={"label": "notes.txt"},
            headers=headers,
        )
        self.assertEqual(upload_resp.status_code, 200)
        uploaded = upload_resp.json()
        self.assertEqual(uploaded["type"], "file")
        self.assertEqual(uploaded["label"], "notes.txt")
        self.assertNotIn("..", uploaded["url_or_path"])

        file_get_resp = self.client.get(
            f"/projects/{project['id']}/attachments/{uploaded['id']}",
            headers=headers,
        )
        self.assertEqual(file_get_resp.status_code, 200)
        self.assertEqual(file_get_resp.content, b"hello world")

        link_resp = self.client.post(
            f"/projects/{project['id']}/attachments",
            json={"label": "Figma", "url": "https://example.com/figma"},
            headers=headers,
        )
        self.assertEqual(link_resp.status_code, 200)
        link_data = link_resp.json()
        self.assertEqual(link_data["type"], "link")

        list_resp = self.client.get(f"/projects/{project['id']}/attachments", headers=headers)
        self.assertEqual(list_resp.status_code, 200)
        attachments = list_resp.json()
        self.assertEqual(len(attachments), 2)

        delete_resp = self.client.delete(
            f"/projects/{project['id']}/attachments/{link_data['id']}",
            headers=headers,
        )
        self.assertEqual(delete_resp.status_code, 200)

        delete_resp = self.client.delete(
            f"/projects/{project['id']}/attachments/{uploaded['id']}",
        )
        self.assertEqual(delete_resp.status_code, 401)

    def test_claim_idle_zap_node_is_atomic(self):
        with get_connection() as conn:
            conn.execute("UPDATE zap_nodes SET status = 'idle' WHERE name = 'zap1'")
            conn.commit()

        results = []
        barrier = threading.Barrier(2)

        def worker():
            barrier.wait()
            results.append(claim_idle_zap_node())

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(sum(1 for item in results if item is not None), 1)
        self.assertEqual(len([item for item in results if item == "zap1"]), 1)
        release_zap_node("zap1")


if __name__ == "__main__":
    unittest.main()

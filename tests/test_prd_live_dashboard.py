import os
import tempfile
import unittest

from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in os.sys.path:
    os.sys.insert(0, ROOT)

from server.app.database import seed_db
from server.app.plugins import ScanContext, SecurityHeadersPlugin, get_plugin_catalog
from server.app.main import app


class TestPRDLiveDashboard(unittest.TestCase):
    def setUp(self):
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
        os.environ["ZAP_AUTH_ENCRYPTION_KEY"] = "test-local-key-for-zap-auth"
        seed_db()
        self.client = TestClient(app)

    def test_security_headers_plugin_creates_findings(self):
        plugin = SecurityHeadersPlugin()
        ctx = ScanContext(target="https://example.com", project_name="demo")
        plugin.run(ctx)
        self.assertTrue(ctx.findings)
        titles = "\n".join(item.title.lower() for item in ctx.findings)
        self.assertIn("content security policy", titles)

    def test_plugin_catalog_includes_security_headers(self):
        catalog = get_plugin_catalog()
        names = {item["name"] for item in catalog}
        self.assertIn("security_headers", names)

    def test_api_stream_route_exists_and_requires_auth(self):
        resp = self.client.get("/api/stream")
        self.assertEqual(resp.status_code, 401)

    def test_api_stream_emits_snapshot_payload(self):
        login = self.client.post('/auth/login', json={'username': 'admin', 'password': 'changeme'})
        token = login.json()['token']
        project = self.client.post('/projects', json={'name': 'stream-project', 'target_url': 'https://example.com'}, headers={'Authorization': f'Bearer {token}'})
        self.client.post(f"/projects/{project.json()['id']}/scan", headers={'Authorization': f'Bearer {token}'})

        import asyncio
        from server.app.main import stream_snapshots

        async def collect():
            chunks = []
            async for chunk in stream_snapshots(interval=0.01, max_events=2):
                chunks.append(chunk)
            return chunks

        chunks = asyncio.run(collect())
        joined = ''.join(chunks)
        self.assertIn('event: snapshot', joined)
        self.assertIn('"stats"', joined)
        self.assertIn('"scans"', joined)
        self.assertIn('"server_time"', joined)

    def test_legacy_routes_still_work_after_plugin_fix(self):
        login = self.client.post('/auth/login', json={'username': 'admin', 'password': 'changeme'})
        token = login.json()['token']
        headers = {'Authorization': f'Bearer {token}'}

        health = self.client.get('/health')
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()['status'], 'ok')

        projects = self.client.get('/projects', headers=headers)
        self.assertEqual(projects.status_code, 200)

        project = self.client.post('/projects', json={'name': 'legacy-route-project', 'target_url': 'https://example.com'}, headers=headers)
        self.assertEqual(project.status_code, 200)
        project_id = project.json()['id']

        created = self.client.post(f'/projects/{project_id}/scan', headers=headers)
        self.assertEqual(created.status_code, 200)
        scan_id = created.json()['id']

        scan_list = self.client.get(f'/projects/{project_id}/scans', headers=headers)
        self.assertEqual(scan_list.status_code, 200)
        self.assertTrue(len(scan_list.json()) >= 1)

        scan_detail = self.client.get(f'/api/scans/{scan_id}', headers=headers)
        self.assertEqual(scan_detail.status_code, 200)


if __name__ == "__main__":
    unittest.main()

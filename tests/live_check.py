import http.client
import http.server
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
PYTHON_EXE = sys.executable


def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TargetHandler(http.server.BaseHTTPRequestHandler):
    delay = 0.0

    def do_GET(self):
        if TargetHandler.delay > 0:
            time.sleep(TargetHandler.delay)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        pass


def kill_proc(proc):
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def wait_for_health(port, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", "/health")
            resp = conn.getresponse()
            if resp.status == 200:
                conn.close()
                return True
        except Exception:
            time.sleep(0.1)
    return False


def read_sse_event(resp, timeout_seconds=5):
    start = time.time()
    event_type = None
    data = None
    while time.time() - start < timeout_seconds:
        line = resp.readline().decode("utf-8")
        if not line:
            time.sleep(0.05)
            continue
        line_str = line.strip()
        if line_str.startswith("event: "):
            event_type = line_str.split("event: ", 1)[1]
        elif line_str.startswith("data: "):
            data = line_str.split("data: ", 1)[1]
        elif line_str == "" and event_type and data:
            return event_type, json.loads(data)
        elif line_str.startswith(": keepalive"):
            return "keepalive", None
    return None, None


def main():
    print("=" * 70)
    print("STARTING REAL PROCESS LIVE CHECKS (Rules 3a - 3g)")
    print("=" * 70)

    # 1. Setup temp DB & Target Server
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["ZAP_AUTH_ENCRYPTION_KEY"] = "live-check-secret-key"

    target_httpd = http.server.HTTPServer(("127.0.0.1", 0), TargetHandler)
    target_port = target_httpd.server_port
    target_thread = threading.Thread(target=target_httpd.serve_forever, daemon=True)
    target_thread.start()

    from server.app.database import seed_db
    seed_db()

    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute(
            "INSERT INTO projects (name, target_url, created_by) VALUES (?, ?, ?)",
            ("live_project", f"http://127.0.0.1:{target_port}", 1),
        )
        conn.commit()

    api_port = get_free_port()
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["DATABASE_URL"] = f"sqlite:///{db_path}"
    env["DASHBOARD_TOKEN"] = "changeme"
    env["ZAP_AUTH_ENCRYPTION_KEY"] = "live-check-secret-key"

    api_proc = None
    worker_proc = None
    worker_proc2 = None

    try:
        # Start real API process
        print(f"\n[INIT] Starting real uvicorn API process on port {api_port}...")
        api_proc = subprocess.Popen(
            [PYTHON_EXE, "-m", "uvicorn", "server.app.main:app", "--host", "127.0.0.1", "--port", str(api_port), "--log-level", "warning"],
            cwd=str(ROOT),
            env=env,
        )
        if not wait_for_health(api_port, timeout=10):
            raise RuntimeError("API failed to become healthy")
        print(f"[INIT] API process running (PID: {api_proc.pid})")

        # -------------------------------------------------------------
        # CHECK A: Stream reads directly from SQLite
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("CHECK A: Open /api/stream and insert a scan directly via sqlite3 (not API)")
        print("-" * 70)
        conn = http.client.HTTPConnection("127.0.0.1", api_port, timeout=5)
        conn.request("GET", "/api/stream?token=changeme")
        stream_resp = conn.getresponse()
        assert stream_resp.status == 200, f"Stream status: {stream_resp.status}"

        # Initial snapshot
        ev, snapshot0 = read_sse_event(stream_resp, timeout_seconds=5)
        print(f"[{time.strftime('%H:%M:%S')}] Initial stream event: {ev} (scans={len(snapshot0.get('scans', []))})")

        # Insert scan directly with sqlite3
        insert_time = int(time.time())
        with sqlite3.connect(db_path) as db:
            cur = db.execute(
                "INSERT INTO scans (project_id, plugin, status, phase, progress, updated_at) VALUES (1, 'security_headers', 'queued', 'queued', 0, ?)",
                (insert_time,),
            )
            db.commit()
            scan_a_id = cur.lastrowid

        print(f"[{time.strftime('%H:%M:%S')}] Inserted scan id={scan_a_id} directly via sqlite3 module into DB")

        # A snapshot containing that scan must arrive within 3 seconds
        start_wait = time.time()
        scan_a_found = False
        snapshot_a = None
        while time.time() - start_wait < 3.0:
            ev, snap = read_sse_event(stream_resp, timeout_seconds=3)
            if ev == "snapshot" and snap:
                scans = snap.get("scans", [])
                if any(s["id"] == scan_a_id for s in scans):
                    scan_a_found = True
                    snapshot_a = snap
                    break

        print(f"[{time.strftime('%H:%M:%S')}] Snapshot received within {time.time() - start_wait:.2f}s:")
        print(f"RAW SNAPSHOT: {json.dumps(snapshot_a)}")
        assert scan_a_found, "Check A Failed: Scan did not appear in stream within 3s"
        print("CHECK A RESULT: PASS")

        # -------------------------------------------------------------
        # CHECK B: Real worker runs the scan -> sequence of snapshots
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("CHECK B: Start real worker process and observe snapshot sequence")
        print("-" * 70)
        worker_proc = subprocess.Popen(
            [PYTHON_EXE, "worker/main.py"],
            cwd=str(ROOT),
            env=env,
        )
        print(f"[WORKER] Started worker process (PID: {worker_proc.pid})")

        observed_sequence = []
        start_wait = time.time()
        while time.time() - start_wait < 8.0:
            ev, snap = read_sse_event(stream_resp, timeout_seconds=3)
            if ev == "snapshot" and snap:
                for s in snap.get("scans", []):
                    if s["id"] == scan_a_id:
                        entry = (time.strftime("%H:%M:%S"), s["status"], s.get("progress", 0))
                        if not observed_sequence or observed_sequence[-1][1:] != entry[1:]:
                            observed_sequence.append(entry)
                            print(f"[{entry[0]}] Snapshot -> scan id={scan_a_id}, status={entry[1]}, progress={entry[2]}%")
                if any(s["id"] == scan_a_id and s["status"] in ("completed", "done") for s in snap.get("scans", [])):
                    break

        print(f"Observed state sequence: {observed_sequence}")
        assert any(item[1] in ("completed", "done") for item in observed_sequence), "Scan never completed"
        print("CHECK B RESULT: PASS")

        # -------------------------------------------------------------
        # CHECK C: Direct SQLite progress edit reflected in stream <= 3s
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("CHECK C: Change scan progress directly in DB with sqlite3 -> next snapshot <= 3s")
        print("-" * 70)
        new_progress_val = 88.5
        now_ts = int(time.time())
        with sqlite3.connect(db_path) as db:
            db.execute(
                "UPDATE scans SET progress = ?, updated_at = ? WHERE id = ?",
                (new_progress_val, now_ts, scan_a_id),
            )
            db.commit()

        print(f"[{time.strftime('%H:%M:%S')}] Executed direct SQL update: progress = {new_progress_val}")

        start_wait = time.time()
        progress_seen = False
        snapshot_c = None
        while time.time() - start_wait < 3.0:
            ev, snap = read_sse_event(stream_resp, timeout_seconds=3)
            if ev == "snapshot" and snap:
                matched = next((s for s in snap.get("scans", []) if s["id"] == scan_a_id), None)
                if matched and abs(float(matched.get("progress", 0)) - new_progress_val) < 0.01:
                    progress_seen = True
                    snapshot_c = snap
                    break

        print(f"[{time.strftime('%H:%M:%S')}] Updated snapshot received in {time.time() - start_wait:.2f}s:")
        print(f"RAW SNAPSHOT: {json.dumps(snapshot_c)}")
        assert progress_seen, "Check C Failed: Progress edit did not arrive in stream within 3s"
        print("CHECK C RESULT: PASS")

        conn.close()

        # -------------------------------------------------------------
        # CHECK D: Kill API, restart API -> state retained & stream reconnects
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("CHECK D: Kill API process, restart API -> scans and logs retained, stream reconnects")
        print("-" * 70)
        print(f"[{time.strftime('%H:%M:%S')}] Killing API process (PID: {api_proc.pid})...")
        kill_proc(api_proc)

        # Inspect SQLite rows while API is dead
        with sqlite3.connect(db_path) as db:
            db.row_factory = sqlite3.Row
            scan_row = dict(db.execute("SELECT id, status, progress, updated_at FROM scans WHERE id = ?", (scan_a_id,)).fetchone())
            log_count = db.execute("SELECT COUNT(*) FROM scan_events WHERE scan_id = ?", (scan_a_id,)).fetchone()[0]
        print(f"SQL EVIDENCE WHILE API IS DEAD: scans row = {scan_row}, scan_events count = {log_count}")
        assert scan_row is not None and log_count >= 1

        # Restart API process
        print(f"[{time.strftime('%H:%M:%S')}] Restarting API process on port {api_port}...")
        api_proc = subprocess.Popen(
            [PYTHON_EXE, "-m", "uvicorn", "server.app.main:app", "--host", "127.0.0.1", "--port", str(api_port), "--log-level", "warning"],
            cwd=str(ROOT),
            env=env,
        )
        assert wait_for_health(api_port, timeout=10)
        print(f"[API] Re-started (PID: {api_proc.pid})")

        # Stream reconnects and sends fresh snapshot
        conn2 = http.client.HTTPConnection("127.0.0.1", api_port, timeout=5)
        conn2.request("GET", "/api/stream?token=changeme")
        stream_resp2 = conn2.getresponse()
        assert stream_resp2.status == 200
        ev2, snap2 = read_sse_event(stream_resp2, timeout_seconds=5)
        print(f"[{time.strftime('%H:%M:%S')}] Reconnected stream received fresh snapshot:")
        print(f"RAW SNAPSHOT: {json.dumps(snap2)}")
        assert any(s["id"] == scan_a_id for s in snap2.get("scans", []))
        conn2.close()
        print("CHECK D RESULT: PASS")

        # -------------------------------------------------------------
        # CHECK E: Kill worker while running -> stale sweep marks failed
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("CHECK E: Worker killed while running -> stale timeout marks scan failed ('Worker stopped responding')")
        print("-" * 70)
        kill_proc(worker_proc)
        print(f"[{time.strftime('%H:%M:%S')}] Killed worker process")

        # Insert a running scan with updated_at faked to 15 seconds ago
        stale_updated = int(time.time()) - 15
        with sqlite3.connect(db_path) as db:
            cur = db.execute(
                "INSERT INTO scans (project_id, plugin, status, phase, worker_id, updated_at) VALUES (1, 'security_headers', 'running', 'running', 'dead-worker', ?)",
                (stale_updated,),
            )
            db.commit()
            stale_scan_id = cur.lastrowid

        print(f"[{time.strftime('%H:%M:%S')}] Inserted running scan id={stale_scan_id} with updated_at faked 15s in the past")

        # Run worker with STALE_SCAN_TIMEOUT=10
        worker_env_e = env.copy()
        worker_env_e["STALE_SCAN_TIMEOUT"] = "10"
        worker_proc = subprocess.Popen(
            [PYTHON_EXE, "worker/main.py"],
            cwd=str(ROOT),
            env=worker_env_e,
        )
        time.sleep(1.5)

        with sqlite3.connect(db_path) as db:
            db.row_factory = sqlite3.Row
            row_e = dict(db.execute("SELECT id, status, phase, error, updated_at FROM scans WHERE id = ?", (stale_scan_id,)).fetchone())

        print(f"[{time.strftime('%H:%M:%S')}] SQL EVIDENCE: {row_e}")
        assert row_e["status"] == "failed"
        assert "Worker stopped responding" in (row_e["error"] or "")
        print("CHECK E RESULT: PASS")

        # -------------------------------------------------------------
        # CHECK F: 3 scans with WORKER_CONCURRENCY=2 -> at most 2 running
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("CHECK F: Start 3 scans with WORKER_CONCURRENCY=2 -> at most 2 running simultaneously")
        print("-" * 70)
        kill_proc(worker_proc)

        # Set delay on dummy server to 0.8s so scans overlap
        TargetHandler.delay = 0.8

        scan_f_ids = []
        with sqlite3.connect(db_path) as db:
            for _ in range(3):
                cur = db.execute(
                    "INSERT INTO scans (project_id, plugin, status, phase, progress, updated_at) VALUES (1, 'security_headers', 'queued', 'queued', 0, ?)",
                    (int(time.time()),),
                )
                scan_f_ids.append(cur.lastrowid)
            db.commit()

        print(f"[{time.strftime('%H:%M:%S')}] Queued 3 scans: {scan_f_ids}")

        worker_env_f = env.copy()
        worker_env_f["WORKER_CONCURRENCY"] = "2"
        worker_proc = subprocess.Popen(
            [PYTHON_EXE, "worker/main.py"],
            cwd=str(ROOT),
            env=worker_env_f,
        )

        running_samples = []
        start_sample = time.time()
        while time.time() - start_sample < 3.5:
            with sqlite3.connect(db_path) as db:
                rows = db.execute(
                    "SELECT id, status FROM scans WHERE id IN (?, ?, ?) AND status = 'running'",
                    tuple(scan_f_ids),
                ).fetchall()
                running_ids = [r[0] for r in rows]
                running_samples.append((time.strftime("%H:%M:%S"), len(running_ids), running_ids))
            time.sleep(0.1)

        print("SQL RUNNING SAMPLES OVER TIME (concurrency=2):")
        for s in running_samples[:8]:
            print(f"  [{s[0]}] running_count={s[1]}, running_ids={s[2]}")

        max_concurrent = max(s[1] for s in running_samples)
        print(f"Maximum concurrent running scans observed: {max_concurrent}")
        assert max_concurrent <= 2, f"Expected at most 2 running scans, got {max_concurrent}"
        assert max_concurrent >= 1, "Expected at least 1 scan to run"
        TargetHandler.delay = 0.0
        print("CHECK F RESULT: PASS")

        # -------------------------------------------------------------
        # CHECK G: 2 worker processes at once with 5 queued scans
        # -------------------------------------------------------------
        print("\n" + "-" * 70)
        print("CHECK G: Two worker processes running concurrently with 5 queued scans")
        print("-" * 70)
        kill_proc(worker_proc)

        scan_g_ids = []
        with sqlite3.connect(db_path) as db:
            for _ in range(5):
                cur = db.execute(
                    "INSERT INTO scans (project_id, plugin, status, phase, progress, updated_at) VALUES (1, 'security_headers', 'queued', 'queued', 0, ?)",
                    (int(time.time()),),
                )
                scan_g_ids.append(cur.lastrowid)
            db.commit()

        print(f"[{time.strftime('%H:%M:%S')}] Queued 5 scans: {scan_g_ids}")

        worker_proc = subprocess.Popen([PYTHON_EXE, "worker/main.py"], cwd=str(ROOT), env=env)
        worker_proc2 = subprocess.Popen([PYTHON_EXE, "worker/main.py"], cwd=str(ROOT), env=env)
        print(f"[WORKERS] Spawned Worker 1 (PID: {worker_proc.pid}) and Worker 2 (PID: {worker_proc2.pid})")

        # Wait for all 5 scans to finish
        start_wait = time.time()
        while time.time() - start_wait < 10.0:
            with sqlite3.connect(db_path) as db:
                unfinished = db.execute(
                    "SELECT COUNT(*) FROM scans WHERE id IN (?, ?, ?, ?, ?) AND status NOT IN ('completed', 'failed', 'cancelled')",
                    tuple(scan_g_ids),
                ).fetchone()[0]
                if unfinished == 0:
                    break
            time.sleep(0.2)

        with sqlite3.connect(db_path) as db:
            db.row_factory = sqlite3.Row
            rows_g = [
                dict(r)
                for r in db.execute(
                    "SELECT id, status, worker_id, (SELECT count(*) FROM scan_events WHERE scan_id = scans.id) AS event_count FROM scans WHERE id IN (?, ?, ?, ?, ?)",
                    tuple(scan_g_ids),
                ).fetchall()
            ]

        print("SQL EVIDENCE OF 5 SCANS EXECUTED BY 2 WORKER PROCESSES:")
        for r in rows_g:
            print(f"  Scan ID {r['id']}: status={r['status']}, worker_id={r['worker_id']}, events={r['event_count']}")

        # Verify all finished
        assert all(r["status"] == "completed" for r in rows_g), "All scans should be completed"
        # Verify distinct workers participated or atomic execution
        worker_ids = {r["worker_id"] for r in rows_g}
        print(f"Workers that claimed scans: {worker_ids}")
        assert None not in worker_ids and "" not in worker_ids
        print("CHECK G RESULT: PASS")

        print("\n" + "=" * 70)
        print("ALL REAL PROCESS CHECKS (A to G) PASSED SUCCESSFULLY!")
        print("=" * 70)

    finally:
        print("\n[CLEANUP] Terminating background processes...")
        kill_proc(api_proc)
        kill_proc(worker_proc)
        kill_proc(worker_proc2)
        try:
            target_httpd.shutdown()
            target_httpd.server_close()
        except Exception:
            pass
        try:
            if os.path.exists(db_path):
                os.remove(db_path)
        except Exception:
            pass
        print("[CLEANUP] Complete.")


if __name__ == "__main__":
    main()

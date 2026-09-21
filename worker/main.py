import asyncio
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.app.database import (
    append_scan_event,
    claim_next_scan,
    delete_scan_auth,
    get_connection,
    get_project,
    get_scan,
    seed_db,
    sweep_stale_running_scans,
    update_scan,
)
from server.app.plugins import ScanCancelled, ScanContext, get_plugin_by_name


def run_scan_once(scan_id: int, worker_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return

    project = get_project(scan["project_id"])
    if not project:
        update_scan(
            scan_id,
            status="failed",
            phase="failed",
            error="Project missing",
            updated_at=int(time.time()),
            finished_at="CURRENT_TIMESTAMP",
        )
        return

    plugin_name = str(scan.get("plugin") or "security_headers")
    try:
        plugin = get_plugin_by_name(plugin_name)
    except Exception as exc:
        now = int(time.time())
        update_scan(
            scan_id,
            status="failed",
            phase="failed",
            error=f"Unknown plugin: {plugin_name} ({exc})",
            updated_at=now,
            finished_at="CURRENT_TIMESTAMP",
        )
        append_scan_event(scan_id, f"Failed: unknown plugin {plugin_name}", phase="failed")
        return

    target = str(project.get("target_url") or "")
    context = ScanContext(target=target, project_name=str(project.get("name") or "project"), scan_id=scan_id)

    try:
        now = int(time.time())
        update_scan(
            scan_id,
            status="running",
            phase="running",
            worker_id=worker_id,
            started_at="CURRENT_TIMESTAMP",
            updated_at=now,
        )
        append_scan_event(scan_id, f"Starting {plugin_name} scan for {target}", phase="running")

        plugin.run(context)

        findings = context.findings
        result_status = "cancelled" if context._cancel_requested else "completed"
        now = int(time.time())
        update_scan(
            scan_id,
            status=result_status,
            phase=result_status,
            worker_id=worker_id,
            error=None if result_status != "cancelled" else "Scan cancelled",
            progress=100,
            updated_at=now,
            finished_at="CURRENT_TIMESTAMP",
            high_count=sum(1 for f in findings if str(f.severity).lower() == "high"),
            medium_count=sum(1 for f in findings if str(f.severity).lower() == "medium"),
            low_count=sum(1 for f in findings if str(f.severity).lower() == "low"),
        )
        append_scan_event(scan_id, f"Scan {result_status} with {len(findings)} finding(s)", phase=result_status)
        delete_scan_auth(scan_id)

    except ScanCancelled:
        now = int(time.time())
        update_scan(
            scan_id,
            status="cancelled",
            phase="cancelled",
            worker_id=worker_id,
            cancel_requested=1,
            updated_at=now,
            finished_at="CURRENT_TIMESTAMP",
        )
        append_scan_event(scan_id, "Scan was cancelled", phase="cancelled")
        delete_scan_auth(scan_id)

    except Exception as exc:
        now = int(time.time())
        update_scan(
            scan_id,
            status="failed",
            phase="failed",
            worker_id=worker_id,
            error=str(exc),
            updated_at=now,
            finished_at="CURRENT_TIMESTAMP",
        )
        append_scan_event(scan_id, f"Scan failed: {exc}", phase="failed")
        delete_scan_auth(scan_id)


async def worker_loop():
    concurrency = int(os.getenv("WORKER_CONCURRENCY", "2") or "2")
    stale_timeout = int(os.getenv("STALE_SCAN_TIMEOUT", "300") or "300")
    active_tasks = set()

    while True:
        # Sweep stale scans
        try:
            sweep_stale_running_scans(stale_seconds=stale_timeout)
        except Exception:
            pass

        # Prune finished tasks
        active_tasks = {t for t in active_tasks if not t.done()}

        # Claim scans up to concurrency
        while len(active_tasks) < concurrency:
            worker_id = f"worker-{os.getpid()}-{time.time_ns()}"
            try:
                scan = claim_next_scan(worker_id)
            except Exception:
                scan = None

            if not scan:
                break

            task = asyncio.create_task(asyncio.to_thread(run_scan_once, scan["id"], worker_id))
            active_tasks.add(task)

        await asyncio.sleep(0.1)


async def main():
    seed_db()
    await worker_loop()


if __name__ == "__main__":
    asyncio.run(main())

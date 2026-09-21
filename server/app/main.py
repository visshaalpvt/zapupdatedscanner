import asyncio
import inspect
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_UPLOAD_EXTENSIONS = {
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".txt",
    ".md",
    ".csv",
    ".json",
    ".html",
    ".xml",
    ".svg",
    ".zip",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".yaml",
    ".yml",
}

from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

from .database import (
    append_scan_event,
    create_project,
    create_project_attachment,
    create_scan,
    delete_project_attachment,
    get_project,
    get_project_attachment,
    get_scan,
    get_scan_detail,
    get_scan_stats,
    get_user_by_username,
    list_project_attachments,
    list_projects,
    list_scan_events,
    list_scans_for_dashboard,
    list_scans_for_project,
    normalize_auth_config,
    seed_db,
    update_project,
    update_scan,
    verify_password,
)
from .plugins import get_plugin_catalog, ScanCancelled, ScanContext, SecurityHeadersPlugin
from .zap_client import run_full_scan

APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent.parent
STATIC_DIR = ROOT_DIR / "web"
DASHBOARD_TOKEN = os.environ.get("DASHBOARD_TOKEN", "changeme")

app = FastAPI(title="ZAP Scanner Dashboard")
security = HTTPBearer(auto_error=False)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

ACTIVE_STREAMS: dict[int, list[WebSocket]] = {}


def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(security)):
    if credentials is not None and credentials.scheme.lower() == "bearer":
        token = credentials.credentials.strip()
        if token == DASHBOARD_TOKEN:
            return {"id": 0, "username": "dashboard", "role": "admin"}
        if token and token.startswith("token:"):
            username = token.split(":", 1)[1]
            user = get_user_by_username(username)
            if user:
                return user
    raise HTTPException(status_code=401, detail="Not authenticated")


def get_request_user(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(security)):
    if credentials is not None and credentials.scheme.lower() == "bearer":
        token = credentials.credentials.strip()
        if token == DASHBOARD_TOKEN:
            return {"id": 0, "username": "dashboard", "role": "admin"}
        if token and token.startswith("token:"):
            username = token.split(":", 1)[1]
            user = get_user_by_username(username)
            if user:
                return user
    token = (request.query_params.get("token") or "").strip()
    if token == DASHBOARD_TOKEN:
        return {"id": 0, "username": "dashboard", "role": "admin"}
    if token and token.startswith("token:"):
        username = token.split(":", 1)[1]
        user = get_user_by_username(username)
        if user:
            return user
    raise HTTPException(status_code=401, detail="Not authenticated")


def user_can_access_project(user: dict, project_id: int) -> bool:
    project = get_project(project_id)
    if not project:
        return False
    if user.get("role") == "admin":
        return True
    return int(project.get("created_by")) == int(user.get("id"))


def is_safe_link_url(raw_url: str) -> bool:
    try:
        from urllib.parse import urlsplit
        value = (raw_url or "").strip()
        if not value:
            return False
        parsed = urlsplit(value)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except Exception:
        return False


def sanitize_upload_name(filename: str) -> str:
    basename = os.path.basename((filename or "upload").replace("\\", "/"))
    safe_name = "".join(ch for ch in basename if ch.isalnum() or ch in "._-")
    if not safe_name or safe_name in {".", ".."}:
        safe_name = "attachment"
    ext = os.path.splitext(safe_name)[1].lower()
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Unsupported file type")
    return f"attachment_{uuid.uuid4().hex}{ext}"


def safe_display_label(label: str | None, fallback: str = "upload") -> str:
    safe = os.path.basename((label or fallback).replace("\\", "/"))
    safe = safe.strip() or fallback
    return safe


@app.on_event("startup")
def startup_event():
    seed_db()


@app.get("/api/plugins")
def list_plugins(user=Depends(get_current_user)):
    return get_plugin_catalog()


@app.get("/api/stats")
def api_stats(user=Depends(get_current_user)):
    return get_scan_stats()


async def stream_snapshots(is_disconnected=None, interval: float = 1.0, keepalive_every: int = 15, max_events: int | None = None):
    yield "retry: 3000\n\n"
    event_count = 1
    if max_events is not None and event_count >= max_events:
        return

    last_sig = None
    ticks_since_change = 0

    while True:
        if is_disconnected is not None:
            try:
                disc = is_disconnected()
                if inspect.isawaitable(disc):
                    disc = await disc
                if disc:
                    break
            except Exception:
                break

        try:
            scan_rows = await asyncio.to_thread(list_scans_for_dashboard, limit=100)
            stats = await asyncio.to_thread(get_scan_stats)
        except Exception:
            break

        sig = {
            "count": len(scan_rows),
            "last_updated": max((int(item.get("updated_at") or 0) for item in scan_rows), default=0),
            "progress_sum": sum(float(item.get("progress") or 0) for item in scan_rows),
            "statuses": tuple((item.get("id"), item.get("status"), item.get("updated_at"), item.get("progress")) for item in scan_rows),
        }

        if sig != last_sig:
            snapshot = {
                "stats": stats,
                "scans": scan_rows,
                "server_time": int(time.time()),
            }
            yield f"event: snapshot\ndata: {json.dumps(snapshot)}\n\n"
            last_sig = sig
            ticks_since_change = 0
            event_count += 1
            if max_events is not None and event_count >= max_events:
                break
        else:
            ticks_since_change += 1
            if ticks_since_change >= keepalive_every:
                yield ": keepalive\n\n"
                ticks_since_change = 0
                event_count += 1
                if max_events is not None and event_count >= max_events:
                    break

        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break


@app.get("/api/stream")
async def stream_events(request: Request, user=Depends(get_request_user)):
    return StreamingResponse(
        stream_snapshots(request.is_disconnected),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/login")
def login(payload: dict):
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()
    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")
    if not verify_password(username, password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": f"token:{username}", "username": username, "role": "admin" if username == "admin" else "user"}


@app.get("/projects")
def get_projects(user=Depends(get_current_user)):
    return list_projects()


@app.get("/projects/{project_id}")
def get_project_detail(project_id: int, user=Depends(get_current_user)):
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not user_can_access_project(user, project_id):
        raise HTTPException(status_code=403, detail="Not allowed to access this project")
    return project


@app.post("/projects")
def create_new_project(payload: dict, user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can register projects")
    name = str(payload.get("name", "")).strip()
    target_url = str(payload.get("target_url", "")).strip()
    if not name or not target_url:
        raise HTTPException(status_code=400, detail="name and target_url are required")

    auth_config = payload.get("auth_config")
    save_credentials = bool((auth_config or {}).get("save_credentials", False)) if isinstance(auth_config, dict) else False
    if auth_config is not None and isinstance(auth_config, dict):
        auth_config = {
            "requires_auth": bool(auth_config.get("requires_auth", False)),
            "login_url": str(auth_config.get("login_url") or target_url).strip(),
            "username_field": str(auth_config.get("username_field") or "email").strip(),
            "password_field": str(auth_config.get("password_field") or "password").strip(),
            "username": str(auth_config.get("username") or "").strip(),
            "password": str(auth_config.get("password") or "").strip(),
            "save_credentials": save_credentials,
        }
        if auth_config["requires_auth"] and not auth_config["username"] and not auth_config["password"]:
            raise HTTPException(status_code=400, detail="Username and password are required when target auth is enabled")

    project = create_project(name=name, target_url=target_url, created_by=user["id"], auth_config=auth_config)
    return project


@app.put("/projects/{project_id}")
def update_project_details(project_id: int, payload: dict, user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can edit projects")
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    updated = update_project(
        project_id,
        name=payload.get("name"),
        target_url=payload.get("target_url"),
        auth_config=payload.get("auth_config"),
    )
    return updated


@app.post("/projects/{project_id}/scan")
def enqueue_scan(project_id: int, payload: dict | None = Body(default=None), user=Depends(get_current_user)):
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    plugin_name = "security_headers"
    if payload and isinstance(payload, dict):
        plugin_name = str(payload.get("plugin") or plugin_name).strip() or plugin_name

    auth_config = payload.get("auth_config") if payload else None
    scan_auth = None
    if auth_config is not None and isinstance(auth_config, dict):
        normalized = {
            "requires_auth": bool(auth_config.get("requires_auth", False)),
            "login_url": str(auth_config.get("login_url") or project["target_url"]).strip(),
            "username_field": str(auth_config.get("username_field") or "email").strip(),
            "password_field": str(auth_config.get("password_field") or "password").strip(),
            "username": str(auth_config.get("username") or "").strip(),
            "password": str(auth_config.get("password") or "").strip(),
        }
        if normalized["requires_auth"] and not normalized["username"] and not normalized["password"]:
            raise HTTPException(status_code=400, detail="Username and password are required when target auth is enabled")
        scan_auth = normalized.copy()
        save_credentials = bool(auth_config.get("save_credentials", False))
        if save_credentials:
            update_project(project_id, auth_config={**normalized, "save_credentials": True})

    scan = create_scan(project_id, status="queued", auth_config=scan_auth, plugin=plugin_name)
    return scan


@app.post("/api/scans")
def create_scan_api(payload: dict, user=Depends(get_current_user)):
    project_id = int(payload.get("project_id"))
    plugin = str(payload.get("plugin") or "security_headers")
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return create_scan(project_id, status="queued", plugin=plugin)


@app.post("/api/scans/{scan_id}/cancel")
def cancel_scan_api(scan_id: int, user=Depends(get_current_user)):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not user_can_access_project(user, scan["project_id"]):
        raise HTTPException(status_code=403, detail="Not allowed to access this project")
    if scan["status"] in {"completed", "failed", "cancelled"}:
        return {"status": scan["status"], "cancel_requested": True}
    update_scan(scan_id, cancel_requested=1, status="cancelled" if scan["status"] == "queued" else scan["status"], updated_at=int(time.time()))
    append_scan_event(scan_id, "Cancel requested by user", phase="cancelled")
    return {"status": "cancelled", "cancel_requested": True}


@app.get("/projects/{project_id}/scans")
def get_project_scans(project_id: int, user=Depends(get_current_user)):
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not user_can_access_project(user, project_id):
        raise HTTPException(status_code=403, detail="Not allowed to access this project")
    return list_scans_for_project(project_id)


@app.get("/projects/{project_id}/attachments")
def get_project_attachments(project_id: int, user=Depends(get_current_user)):
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not user_can_access_project(user, project_id):
        raise HTTPException(status_code=403, detail="Not allowed to access this project")
    return list_project_attachments(project_id)


@app.get("/projects/{project_id}/attachments/{attachment_id}")
def get_project_attachment_file(project_id: int, attachment_id: int, user=Depends(get_current_user)):
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not user_can_access_project(user, project_id):
        raise HTTPException(status_code=403, detail="Not allowed to access this project")
    attachment = get_project_attachment(project_id, attachment_id)
    if not attachment:
        raise HTTPException(status_code=404, detail="Attachment not found")
    if attachment["type"] == "link":
        raise HTTPException(status_code=400, detail="This attachment is a link")
    path = Path(attachment["url_or_path"])
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path, filename=attachment["label"])


@app.post("/projects/{project_id}/attachments")
async def create_attachment(
    request: Request,
    project_id: int,
    user=Depends(get_current_user),
    file: UploadFile | None = File(default=None),
):
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not user_can_access_project(user, project_id):
        raise HTTPException(status_code=403, detail="Not allowed to access this project")

    content_type = request.headers.get("content-type", "")
    if file is not None:
        original_name = file.filename or "upload"
        ext = os.path.splitext(original_name)[1].lower()
        if ext.lower() not in ALLOWED_UPLOAD_EXTENSIONS:
            raise HTTPException(status_code=400, detail="Unsupported file type")

        upload_dir = ROOT_DIR / "uploads"
        upload_dir.mkdir(exist_ok=True)
        safe_path = upload_dir / sanitize_upload_name(original_name)

        file.file.seek(0, os.SEEK_END)
        file_size = file.file.tell()
        file.file.seek(0)
        if file_size > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="File exceeds maximum upload size")

        display_label = safe_display_label(file.filename or "upload", fallback="upload")
        form = await request.form()
        if "label" in form:
            display_label = safe_display_label(str(form["label"]), fallback=display_label)

        with safe_path.open("wb") as fh:
            while True:
                chunk = file.file.read(65536)
                if not chunk:
                    break
                fh.write(chunk)

        attachment = create_project_attachment(
            project_id,
            "file",
            display_label,
            str(safe_path),
            user["id"],
        )
        return attachment

    if "multipart/form-data" in content_type:
        form = await request.form()
        link_url = str(form.get("url") or "").strip()
        link_label = safe_display_label(str(form.get("label") or "Link"), fallback="Link")
    else:
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        link_url = str(payload.get("url") or "").strip()
        link_label = safe_display_label(str(payload.get("label") or "Link"), fallback="Link")

    if not link_url:
        raise HTTPException(status_code=400, detail="Either file or url is required")
    if not is_safe_link_url(link_url):
        raise HTTPException(status_code=400, detail="Only http:// and https:// links are allowed")
    attachment = create_project_attachment(project_id, "link", link_label, link_url, user["id"])
    return attachment


@app.delete("/projects/{project_id}/attachments/{attachment_id}")
def delete_attachment(project_id: int, attachment_id: int, user=Depends(get_current_user)):
    project = get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not user_can_access_project(user, project_id):
        raise HTTPException(status_code=403, detail="Not allowed to access this project")
    attachment = get_project_attachment(project_id, attachment_id)
    if not attachment:
        raise HTTPException(status_code=404, detail="Attachment not found")
    if user.get("role") != "admin" and int(attachment.get("uploaded_by") or 0) != int(user.get("id") or -1):
        raise HTTPException(status_code=403, detail="Only admins or the uploader can delete this attachment")
    if attachment["type"] == "file":
        storage_path = Path(attachment["url_or_path"])
        if storage_path.exists():
            storage_path.unlink(missing_ok=True)
    if not delete_project_attachment(project_id, attachment_id):
        raise HTTPException(status_code=404, detail="Attachment not found")
    return {"deleted": True, "attachment_id": attachment_id}


@app.get("/api/scans")
def list_scans_api(status: str | None = None, search: str | None = None, user=Depends(get_current_user)):
    return list_scans_for_dashboard(status=status, search=search or None, limit=100)


@app.get("/scans/{scan_id}")
def get_scan_status(scan_id: int, user=Depends(get_current_user)):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not user_can_access_project(user, scan["project_id"]):
        raise HTTPException(status_code=403, detail="Not allowed to access this project")
    return scan


@app.get("/api/scans/{scan_id}")
def get_scan_status_api(scan_id: int, user=Depends(get_current_user)):
    scan = get_scan_detail(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not user_can_access_project(user, scan["project_id"]):
        raise HTTPException(status_code=403, detail="Not allowed to access this project")
    return scan


@app.get("/scans/{scan_id}/report")
def get_scan_report(scan_id: int, user=Depends(get_current_user)):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not user_can_access_project(user, scan["project_id"]):
        raise HTTPException(status_code=403, detail="Not allowed to access this project")
    report_path = scan.get("report_path")
    if not report_path:
        raise HTTPException(status_code=404, detail="Report not generated yet")
    return FileResponse(report_path)


@app.websocket("/scans/{scan_id}/stream")
async def stream_scan(websocket: WebSocket, scan_id: int):
    await websocket.accept()
    last_event_id = 0
    try:
        while True:
            rows = list_scan_events(scan_id, since_id=last_event_id)
            for row in rows:
                await websocket.send_json({
                    "type": "log",
                    "message": row["message"],
                    "phase": row["phase"],
                })
                last_event_id = max(last_event_id, int(row["id"]))
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass


@app.get("/")
def index():
    return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))


async def broadcast_scan_update(scan_id: int, message: dict):
    return None


async def worker_main():
    while True:
        scan = None
        with __import__("sqlite3").connect(str(ROOT_DIR / "zap_dashboard.db")) as conn:
            row = conn.execute("SELECT * FROM scans WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1").fetchone()
            if row:
                scan = dict(row)
                conn.execute("UPDATE scans SET status = 'running', phase = 'queued' WHERE id = ?", (scan["id"],))
                conn.commit()
        if not scan:
            await asyncio.sleep(2)
            continue

        project = get_project(scan["project_id"])
        if not project:
            update_scan(scan["id"], status="failed", phase="failed", error="Project missing")
            continue

        zap_node = os.environ.get("ZAP_NODE_NAME", "zap1")
        try:
            def emit(line: str):
                phase = "running"
                if line.startswith("Spidering"):
                    phase = "Spidering"
                elif line.startswith("Running AJAX"):
                    phase = "Running AJAX"
                elif line.startswith("Running active"):
                    phase = "Running active"
                elif line.startswith("Generating"):
                    phase = "Generating"
                update_scan(scan["id"], phase=phase)
                append_scan_event(scan["id"], line, phase=phase)

            auth_config = scan.get("auth_config")
            if isinstance(auth_config, str):
                import json
                try:
                    auth_config = json.loads(auth_config)
                except Exception:
                    auth_config = None
            auth_config = normalize_auth_config(auth_config) if isinstance(auth_config, (dict, str)) else None
            result = run_full_scan(f"http://{zap_node}:8080", project["target_url"], auth_config, emit)
            report_path = result.get("report_path")
            update_scan(
                scan["id"],
                status=result.get("status", "done"),
                phase=result.get("phase", "done"),
                report_path=report_path,
                high_count=result.get("high_count", 0),
                medium_count=result.get("medium_count", 0),
                low_count=result.get("low_count", 0),
                finished_at="CURRENT_TIMESTAMP",
            )
            append_scan_event(scan["id"], "Scan complete", phase="done")
        except Exception as exc:
            update_scan(scan["id"], status="failed", phase="failed", error=str(exc))
            append_scan_event(scan["id"], f"Scan failed: {exc}", phase="failed")
        await asyncio.sleep(1)


@app.on_event("shutdown")
def shutdown_event():
    pass

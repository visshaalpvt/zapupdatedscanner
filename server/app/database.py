import base64
import hashlib
import json
import os
import sqlite3
import time
from contextlib import closing
from typing import Any, Dict, List, Optional

try:
    from cryptography.fernet import Fernet
except Exception:  # pragma: no cover - dependency should be installed in runtime
    Fernet = None

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./zap_dashboard.db")


def _get_auth_encryption_key() -> Optional[bytes]:
    key = os.environ.get("ZAP_AUTH_ENCRYPTION_KEY")
    if not key:
        return None
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _encrypt_secret(value: str) -> str:
    if value in (None, ""):
        return ""
    key = _get_auth_encryption_key()
    if key is None:
        raise RuntimeError("ZAP_AUTH_ENCRYPTION_KEY is required to encrypt stored target credentials.")
    if Fernet is None:
        raise RuntimeError("cryptography package is required to encrypt stored target credentials.")
    return Fernet(key).encrypt(value.encode("utf-8")).decode("utf-8")


def _decrypt_secret(value: str) -> str:
    if value in (None, ""):
        return ""
    key = _get_auth_encryption_key()
    if key is None:
        return value
    if Fernet is None:
        return value
    try:
        return Fernet(key).decrypt(value.encode("utf-8")).decode("utf-8")
    except Exception:
        return value


def normalize_auth_config(value: Any) -> Optional[Dict[str, Any]]:
    if value in (None, ""):
        return None
    if isinstance(value, dict):
        loaded = value
    elif isinstance(value, str):
        try:
            loaded = json.loads(value)
        except Exception:
            return None
        if not isinstance(loaded, dict):
            return None
    else:
        return None

    normalized = dict(loaded)
    if normalized.get("encrypted"):
        normalized["username"] = _decrypt_secret(str(normalized.get("username") or ""))
        normalized["password"] = _decrypt_secret(str(normalized.get("password") or ""))
        normalized["save_credentials"] = bool(normalized.get("save_credentials", True))
    normalized["username"] = str(normalized.get("username") or "")
    normalized["password"] = str(normalized.get("password") or "")
    return normalized


def redact_auth_config(value: Any) -> Optional[Dict[str, Any]]:
    if value in (None, ""):
        return None
    if isinstance(value, dict):
        loaded = value
    elif isinstance(value, str):
        try:
            loaded = json.loads(value)
        except Exception:
            return None
        if not isinstance(loaded, dict):
            return None
    else:
        return None

    redacted = dict(loaded)
    redacted["username"] = "***"
    redacted["password"] = "***"
    redacted["save_credentials"] = bool(redacted.get("save_credentials", False))
    redacted["encrypted"] = bool(redacted.get("encrypted", False))
    return redacted


def sanitize_project_auth_config(auth_config: Optional[Dict[str, Any]], persist_credentials: bool = False) -> Optional[Dict[str, Any]]:
    if auth_config is None:
        return None
    if not isinstance(auth_config, dict):
        return None
    sanitized = {
        "requires_auth": bool(auth_config.get("requires_auth", False)),
        "login_url": str(auth_config.get("login_url") or "").strip(),
        "username_field": str(auth_config.get("username_field") or "email").strip(),
        "password_field": str(auth_config.get("password_field") or "password").strip(),
        "username": "",
        "password": "",
        "save_credentials": bool(persist_credentials),
        "encrypted": False,
    }
    if persist_credentials:
        sanitized["username"] = _encrypt_secret(str(auth_config.get("username") or "").strip())
        sanitized["password"] = _encrypt_secret(str(auth_config.get("password") or "").strip())
        sanitized["encrypted"] = True
    return sanitized


def scrub_auth_config(auth_config: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if auth_config is None:
        return None
    if not isinstance(auth_config, dict):
        return None
    scrubbed = dict(auth_config)
    scrubbed["username"] = ""
    scrubbed["password"] = ""
    scrubbed["save_credentials"] = False
    scrubbed["encrypted"] = False
    return scrubbed


def get_database_url() -> str:
    global DATABASE_URL
    DATABASE_URL = os.environ.get("DATABASE_URL", DATABASE_URL)
    return DATABASE_URL


def _db_path() -> str:
    url = get_database_url()
    if url.startswith("sqlite:///"):
        return url.replace("sqlite:///", "", 1)
    if url.startswith("sqlite://"):
        return url.replace("sqlite://", "", 1)
    return "zap_dashboard.db"


def get_engine():
    return _db_path()


def get_connection():
    conn = sqlite3.connect(_db_path(), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=15000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def _add_missing_columns(conn, table_name, column_defs):
    existing = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    existing_names = {row[1] for row in existing}
    for column_name, column_sql in column_defs.items():
        if column_name not in existing_names:
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_sql};")


def init_db():
    db_file = _db_path()
    if os.path.exists(db_file) and not os.path.exists(db_file + ".bak") and os.path.getsize(db_file) > 0:
        import shutil
        try:
            shutil.copy2(db_file, db_file + ".bak")
        except Exception:
            pass

    with closing(get_connection()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
            );

            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                target_url TEXT NOT NULL,
                auth_config TEXT,
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(created_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS project_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                type TEXT NOT NULL CHECK(type IN ('file', 'link')),
                label TEXT NOT NULL,
                url_or_path TEXT NOT NULL,
                uploaded_by INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(project_id) REFERENCES projects(id),
                FOREIGN KEY(uploaded_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                plugin TEXT NOT NULL DEFAULT 'security_headers',
                status TEXT NOT NULL DEFAULT 'queued',
                phase TEXT NOT NULL DEFAULT 'queued',
                progress REAL NOT NULL DEFAULT 0,
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                worker_id TEXT,
                started_at TEXT,
                finished_at TEXT,
                updated_at INTEGER,
                high_count INTEGER NOT NULL DEFAULT 0,
                medium_count INTEGER NOT NULL DEFAULT 0,
                low_count INTEGER NOT NULL DEFAULT 0,
                report_path TEXT,
                log_path TEXT,
                zap_node TEXT,
                auth_config TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(project_id) REFERENCES projects(id)
            );

            CREATE TABLE IF NOT EXISTS scan_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                phase TEXT NOT NULL DEFAULT 'running',
                message TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                ts INTEGER NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                url TEXT,
                description TEXT,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS zap_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                internal_url TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'idle'
            );

            CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
            CREATE INDEX IF NOT EXISTS idx_scans_updated_at ON scans(updated_at);
            CREATE INDEX IF NOT EXISTS idx_scan_logs_scan_id_id ON scan_logs(scan_id, id);
            CREATE INDEX IF NOT EXISTS idx_scan_events_scan_id_id ON scan_events(scan_id, id);
            CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
            """
        )
        _add_missing_columns(
            conn,
            "scans",
            {
                "plugin": "TEXT NOT NULL DEFAULT 'security_headers'",
                "progress": "REAL NOT NULL DEFAULT 0",
                "cancel_requested": "INTEGER NOT NULL DEFAULT 0",
                "error": "TEXT",
                "worker_id": "TEXT",
                "updated_at": "INTEGER",
            },
        )
        conn.commit()


def seed_db():
    init_db()
    with closing(get_connection()) as conn:
        user_exists = conn.execute(
            "SELECT 1 FROM users WHERE username = 'admin' LIMIT 1"
        ).fetchone()
        if not user_exists:
            import hashlib
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", hashlib.sha256(b"changeme").hexdigest(), "admin"),
            )

        zap_exists = conn.execute(
            "SELECT 1 FROM zap_nodes WHERE name = 'zap1' LIMIT 1"
        ).fetchone()
        if not zap_exists:
            conn.execute(
                "INSERT INTO zap_nodes (name, internal_url, status) VALUES (?, ?, ?)",
                ("zap1", "http://zap1:8080", "idle"),
            )
        conn.commit()


def verify_password(username: str, password: str) -> bool:
    import hashlib
    with closing(get_connection()) as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row:
            return False
        return row["password_hash"] == hashlib.sha256(password.encode("utf-8")).hexdigest()


def get_user_by_username(username: str):
    with closing(get_connection()) as conn:
        return dict(conn.execute(
            "SELECT id, username, role FROM users WHERE username = ?",
            (username,),
        ).fetchone() or {})


def create_project(name: str, target_url: str, created_by: str | int, auth_config: Optional[Dict[str, Any]] = None):
    with closing(get_connection()) as conn:
        user = conn.execute("SELECT id FROM users WHERE username = ?", (str(created_by),)).fetchone()
        if user is None and str(created_by).isdigit():
            user = conn.execute("SELECT id FROM users WHERE id = ?", (int(created_by),)).fetchone()
        if user is None:
            raise ValueError("Unknown user")

        persist_credentials = bool((auth_config or {}).get("save_credentials", False)) if isinstance(auth_config, dict) else False
        sanitized_config = sanitize_project_auth_config(auth_config, persist_credentials=persist_credentials)
        auth_json = json.dumps(sanitized_config) if sanitized_config is not None else None

        cursor = conn.execute(
            "INSERT INTO projects (name, target_url, auth_config, created_by) VALUES (?, ?, ?, ?)",
            (name, target_url, auth_json, user["id"]),
        )
        conn.commit()
        project_id = cursor.lastrowid
        row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        item = dict(row)
        if item.get("auth_config"):
            item["auth_config"] = redact_auth_config(item["auth_config"])
        return item


def list_projects():
    with closing(get_connection()) as conn:
        rows = conn.execute(
            "SELECT p.*, s.status AS last_status, s.high_count, s.medium_count, s.low_count FROM projects p LEFT JOIN scans s ON s.id = (SELECT id FROM scans WHERE project_id = p.id ORDER BY created_at DESC LIMIT 1) ORDER BY p.id DESC"
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            if item.get("auth_config"):
                item["auth_config"] = redact_auth_config(item["auth_config"])
            items.append(item)
        return items


def get_project(project_id: int):
    with closing(get_connection()) as conn:
        row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        if item.get("auth_config"):
            item["auth_config"] = redact_auth_config(item["auth_config"])
        return item


def update_project(project_id: int, name: Optional[str] = None, target_url: Optional[str] = None, auth_config: Optional[Dict[str, Any]] = None):
    with closing(get_connection()) as conn:
        project = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        if project is None:
            return None

        updates = []
        values = []
        if name is not None:
            updates.append("name = ?")
            values.append(name)
        if target_url is not None:
            updates.append("target_url = ?")
            values.append(target_url)
        if auth_config is not None:
            persist_credentials = bool((auth_config or {}).get("save_credentials", False)) if isinstance(auth_config, dict) else False
            sanitized_config = sanitize_project_auth_config(auth_config, persist_credentials=persist_credentials)
            updates.append("auth_config = ?")
            values.append(json.dumps(sanitized_config) if sanitized_config is not None else None)

        if not updates:
            return dict(project)

        values.append(project_id)
        conn.execute(f"UPDATE projects SET {', '.join(updates)} WHERE id = ?", values)
        conn.commit()
        row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        item = dict(row)
        if item.get("auth_config"):
            item["auth_config"] = redact_auth_config(item["auth_config"])
        return item


def create_project_attachment(project_id: int, attachment_type: str, label: str, url_or_path: str, uploaded_by: str | int):
    attachment_type = (attachment_type or "").strip().lower()
    if attachment_type not in {"file", "link"}:
        raise ValueError("attachment type must be 'file' or 'link'")
    if not label or not url_or_path:
        raise ValueError("label and url_or_path are required")

    with closing(get_connection()) as conn:
        user = conn.execute("SELECT id FROM users WHERE username = ?", (str(uploaded_by),)).fetchone()
        if user is None and str(uploaded_by).isdigit():
            user = conn.execute("SELECT id FROM users WHERE id = ?", (int(uploaded_by),)).fetchone()
        if user is None:
            raise ValueError("Unknown user")

        project = conn.execute("SELECT id FROM projects WHERE id = ?", (project_id,)).fetchone()
        if project is None:
            raise ValueError("Project not found")

        cursor = conn.execute(
            "INSERT INTO project_attachments (project_id, type, label, url_or_path, uploaded_by) VALUES (?, ?, ?, ?, ?)",
            (project_id, attachment_type, label, url_or_path, user["id"]),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM project_attachments WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return dict(row)


def list_project_attachments(project_id: int):
    with closing(get_connection()) as conn:
        rows = conn.execute(
            "SELECT * FROM project_attachments WHERE project_id = ? ORDER BY uploaded_at DESC",
            (project_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_project_attachment(project_id: int, attachment_id: int):
    with closing(get_connection()) as conn:
        row = conn.execute(
            "SELECT * FROM project_attachments WHERE project_id = ? AND id = ?",
            (project_id, attachment_id),
        ).fetchone()
        return dict(row) if row else None


def delete_project_attachment(project_id: int, attachment_id: int):
    with closing(get_connection()) as conn:
        row = conn.execute(
            "SELECT * FROM project_attachments WHERE project_id = ? AND id = ?",
            (project_id, attachment_id),
        ).fetchone()
        if row is None:
            return False
        conn.execute(
            "DELETE FROM project_attachments WHERE project_id = ? AND id = ?",
            (project_id, attachment_id),
        )
        conn.commit()
        return True


def create_scan(project_id: int, status: str = "queued", auth_config: Optional[Dict[str, Any]] = None, plugin: str = "security_headers") -> Dict[str, Any]:
    with closing(get_connection()) as conn:
        stored_auth = None
        if auth_config is not None and isinstance(auth_config, dict):
            stored_auth = {
                "requires_auth": bool(auth_config.get("requires_auth", False)),
                "login_url": str(auth_config.get("login_url") or "").strip(),
                "username_field": str(auth_config.get("username_field") or "email").strip(),
                "password_field": str(auth_config.get("password_field") or "password").strip(),
                "username": _encrypt_secret(str(auth_config.get("username") or "").strip()),
                "password": _encrypt_secret(str(auth_config.get("password") or "").strip()),
                "save_credentials": True,
                "encrypted": True,
            }
        auth_json = json.dumps(stored_auth) if stored_auth is not None else None
        now = int(time.time())
        cursor = conn.execute(
            "INSERT INTO scans (project_id, plugin, status, phase, started_at, auth_config, progress, cancel_requested, updated_at) VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)",
            (project_id, plugin, status, status, now, auth_json, now),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (cursor.lastrowid,)).fetchone()
        data = dict(row)
        if data.get("auth_config"):
            data["auth_config"] = redact_auth_config(data["auth_config"])
        return data


def delete_scan_auth(scan_id: int):
    with closing(get_connection()) as conn:
        conn.execute(
            "UPDATE scans SET auth_config = NULL WHERE id = ?",
            (scan_id,),
        )
        conn.commit()


def get_scan(scan_id: int):
    with closing(get_connection()) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        data = dict(row) if row else None
        if data and data.get("auth_config"):
            data["auth_config"] = redact_auth_config(data["auth_config"])
        return data


def list_scans_for_project(project_id: int):
    with closing(get_connection()) as conn:
        rows = conn.execute(
            "SELECT * FROM scans WHERE project_id = ? ORDER BY created_at DESC",
            (project_id,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            if item.get("auth_config"):
                item["auth_config"] = redact_auth_config(item["auth_config"])
            items.append(item)
        return items


def update_scan(scan_id: int, **kwargs):
    if not kwargs:
        return get_scan(scan_id)
    if "updated_at" not in kwargs:
        kwargs["updated_at"] = int(time.time())
    fields = []
    values = []
    for key, value in kwargs.items():
        if isinstance(value, str) and value.upper() == "CURRENT_TIMESTAMP":
            fields.append(f"{key} = CURRENT_TIMESTAMP")
        else:
            fields.append(f"{key} = ?")
            values.append(value)
    values.append(scan_id)
    with closing(get_connection()) as conn:
        conn.execute(f"UPDATE scans SET {', '.join(fields)} WHERE id = ?", values)
        conn.commit()
    return get_scan(scan_id)


def append_scan_event(scan_id: int, message: str, phase: Optional[str] = None):
    if message is None:
        return None
    event_phase = (phase or "running").strip() or "running"
    timestamp = int(time.time())
    with closing(get_connection()) as conn:
        cursor = conn.execute(
            "INSERT INTO scan_events (scan_id, phase, message) VALUES (?, ?, ?)",
            (scan_id, event_phase, str(message)),
        )
        conn.execute(
            "UPDATE scans SET updated_at = ?, phase = COALESCE(?, phase) WHERE id = ?",
            (timestamp, event_phase, scan_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM scan_events WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return dict(row) if row else None


def list_scan_events(scan_id: int, since_id: Optional[int] = None, limit: Optional[int] = None):
    with closing(get_connection()) as conn:
        if since_id is None:
            if limit is None:
                rows = conn.execute(
                    "SELECT * FROM scan_events WHERE scan_id = ? ORDER BY id ASC",
                    (scan_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scan_events WHERE scan_id = ? ORDER BY id ASC LIMIT ?",
                    (scan_id, int(limit)),
                ).fetchall()
        else:
            if limit is None:
                rows = conn.execute(
                    "SELECT * FROM scan_events WHERE scan_id = ? AND id > ? ORDER BY id ASC",
                    (scan_id, since_id),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scan_events WHERE scan_id = ? AND id > ? ORDER BY id ASC LIMIT ?",
                    (scan_id, since_id, int(limit)),
                ).fetchall()
        return [dict(row) for row in rows]


def claim_idle_zap_node() -> Optional[str]:
    with closing(get_connection()) as conn:
        row = conn.execute(
            """
            UPDATE zap_nodes
            SET status = 'busy'
            WHERE id = (
                SELECT id FROM zap_nodes WHERE status = 'idle' ORDER BY id ASC LIMIT 1
            )
            RETURNING name
            """
        ).fetchone()
        conn.commit()
        if row is None:
            return None
        return row["name"]


def release_zap_node(name: str):
    with closing(get_connection()) as conn:
        conn.execute("UPDATE zap_nodes SET status = 'idle' WHERE name = ?", (name,))
        conn.commit()


def get_next_queued_scan():
    with closing(get_connection()) as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None


def add_finding(scan_id: int, severity: str, title: str, url: str = "", description: str = "") -> Dict[str, Any]:
    clean_title = (title or "")[:300]
    clean_description = (description or "")[:4000]
    clean_url = (url or "")[:1000]
    now = int(time.time())
    with closing(get_connection()) as conn:
        cursor = conn.execute(
            "INSERT INTO findings (scan_id, severity, title, url, description, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, str(severity or "info").lower(), clean_title, clean_url, clean_description, now),
        )
        conn.execute(
            "UPDATE scans SET updated_at = ? WHERE id = ?",
            (now, scan_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return dict(row) if row else {}


def list_findings(scan_id: int):
    with closing(get_connection()) as conn:
        rows = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY created_at ASC", (scan_id,)).fetchall()
        return [dict(row) for row in rows]


def get_scan_stats():
    with closing(get_connection()) as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) as count FROM scans GROUP BY status"
        ).fetchall()
        status_counts = {str(row["status"]): int(row["count"]) for row in rows}
        totals = {
            "queued": status_counts.get("queued", 0),
            "running": status_counts.get("running", 0),
            "completed": status_counts.get("completed", 0) + status_counts.get("done", 0),
            "failed": status_counts.get("failed", 0),
            "cancelled": status_counts.get("cancelled", 0),
        }
        severity_rows = conn.execute(
            "SELECT severity, COUNT(*) AS count FROM findings GROUP BY severity"
        ).fetchall()
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for row in severity_rows:
            sev = str(row["severity"]).lower()
            if sev in severities:
                severities[sev] = int(row["count"])
        return {"counts": totals, "severities": severities}


def get_scan_stream_signature():
    with closing(get_connection()) as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS count, COALESCE(MAX(updated_at), 0) AS last_updated FROM scans"
        ).fetchone()
        return {"count": int(row["count"] or 0), "last_updated": int(row["last_updated"] or 0)}


def sweep_stale_running_scans(stale_seconds: int = 300, message: str = "Worker stopped responding"):
    cut_off = int(time.time()) - stale_seconds
    with closing(get_connection()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            "SELECT id FROM scans WHERE status = 'running' AND updated_at IS NOT NULL AND updated_at < ?",
            (cut_off,),
        ).fetchall()
        now = int(time.time())
        for row in rows:
            conn.execute(
                "UPDATE scans SET status = 'failed', phase = 'failed', error = ?, updated_at = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?",
                (message, now, row["id"]),
            )
            conn.execute(
                "INSERT INTO scan_events (scan_id, phase, message) VALUES (?, 'failed', ?)",
                (row["id"], message),
            )
        conn.commit()
        return len(rows)


def list_scans_for_dashboard(status: Optional[str] = None, limit: int = 100, search: Optional[str] = None):
    query = "SELECT s.*, p.name AS project_name, p.target_url FROM scans s LEFT JOIN projects p ON p.id = s.project_id"
    clauses = []
    params = []
    if status:
        normalized = str(status).lower()
        if normalized == "active":
            clauses.append("(s.status = 'queued' OR s.status = 'running')")
        elif normalized == "completed":
            clauses.append("s.status IN ('completed', 'done')")
        elif normalized == "failed":
            clauses.append("s.status = 'failed'")
        elif normalized == "cancelled":
            clauses.append("s.status = 'cancelled'")
        else:
            clauses.append("s.status = ?")
            params.append(normalized)
    if search:
        clauses.append("(p.name LIKE ? OR p.target_url LIKE ?)")
        term = f"%{search}%"
        params.extend([term, term])
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY s.updated_at DESC, s.created_at DESC LIMIT ?"
    params.append(int(limit))
    with closing(get_connection()) as conn:
        rows = conn.execute(query, params).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["logs"] = list_scan_events(item["id"], limit=20)
            item["findings"] = list_findings(item["id"])
            items.append(item)
        return items


def get_scan_detail(scan_id: int):
    with closing(get_connection()) as conn:
        row = conn.execute(
            "SELECT s.*, p.name AS project_name, p.target_url FROM scans s LEFT JOIN projects p ON p.id = s.project_id WHERE s.id = ?",
            (scan_id,),
        ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["logs"] = list_scan_events(scan_id, limit=200)
        item["findings"] = list_findings(scan_id)
        return item


def claim_next_scan(worker_id: str = "default"):
    with closing(get_connection()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM scans WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1",
        ).fetchone()
        if row is None:
            conn.execute("COMMIT")
            return None
        now = int(time.time())
        conn.execute(
            "UPDATE scans SET status = 'running', worker_id = ?, started_at = COALESCE(started_at, ?), updated_at = ?, phase='running', progress=0 WHERE id = ?",
            (worker_id, now, now, row["id"]),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (row["id"],)).fetchone()
        return dict(row)

import time
from typing import Any, Dict, List, Optional


def _severity_rank(level: str) -> int:
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return order.get(str(level).lower(), 0)


class ScanCancelled(Exception):
    pass


class ScanFinding:
    def __init__(self, severity: str, title: str, url: str = "", description: str = ""):
        self.severity = str(severity or "info").lower()
        self.title = (title or "Untitled finding")[:300]
        self.url = (url or "")[:1000]
        self.description = (description or "")[:4000]

    def as_dict(self):
        return {
            "severity": self.severity,
            "title": self.title,
            "url": self.url,
            "description": self.description,
        }


class ScanContext:
    def __init__(self, target: str, project_name: str = "project", scan_id: Optional[int] = None):
        self.target = target
        self.project_name = project_name
        self.scan_id = scan_id
        self.logs: List[str] = []
        self.findings: List[ScanFinding] = []
        self._progress = 0.0
        self._cancel_requested = False

    @property
    def progress_value(self):
        return self._progress

    def log(self, message: str):
        text = str(message or "")[:2000]
        self.logs.append(text)
        if self.scan_id:
            try:
                from ..database import append_scan_event
                append_scan_event(self.scan_id, text)
            except Exception:
                pass

    def progress(self, value: float, *, heartbeat: bool = False):
        try:
            self._progress = max(0.0, min(100.0, float(value)))
        except Exception:
            self._progress = 0.0
        if self.scan_id:
            try:
                from ..database import update_scan
                update_scan(self.scan_id, progress=self._progress, updated_at=int(time.time()))
            except Exception:
                pass
        return self._progress

    def finding(self, severity: str, title: str, url: str = "", description: str = ""):
        finding = ScanFinding(severity, title, url, description)
        self.findings.append(finding)
        self.findings.sort(key=lambda item: _severity_rank(item.severity), reverse=True)
        if self.scan_id:
            try:
                from ..database import add_finding
                add_finding(self.scan_id, finding.severity, finding.title, finding.url, finding.description)
            except Exception:
                pass
        return finding

    def checkpoint(self):
        if self._cancel_requested:
            raise ScanCancelled("Scan cancelled")
        if self.scan_id:
            try:
                from ..database import get_scan
                scan = get_scan(self.scan_id)
                if scan and scan.get("cancel_requested"):
                    self._cancel_requested = True
                    raise ScanCancelled("Scan cancelled")
            except ScanCancelled:
                raise
            except Exception:
                pass

    def request_cancel(self):
        self._cancel_requested = True


class ScannerPlugin:
    name = "base"
    label = "Base plugin"
    description = "Base scanner plugin."

    def run(self, ctx: ScanContext):
        raise NotImplementedError

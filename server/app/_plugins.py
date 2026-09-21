import importlib
import inspect
import os
import time
from pathlib import Path
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
        self._progress = 0
        self._cancel_requested = False

    @property
    def progress_value(self):
        return self._progress

    def log(self, message: str):
        text = str(message or "")[:2000]
        self.logs.append(text)
        if self.scan_id:
            try:
                from .database import append_scan_event
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
                from .database import update_scan
                update_scan(self.scan_id, progress=self._progress)
            except Exception:
                pass
        return self._progress

    def finding(self, severity: str, title: str, url: str = "", description: str = ""):
        finding = ScanFinding(severity, title, url, description)
        self.findings.append(finding)
        self.findings.sort(key=lambda item: _severity_rank(item.severity), reverse=True)
        if self.scan_id:
            try:
                from .database import add_finding
                add_finding(self.scan_id, finding.severity, finding.title, finding.url, finding.description)
            except Exception:
                pass
        return finding

    def checkpoint(self):
        if self._cancel_requested:
            raise ScanCancelled("Scan cancelled")
        if self.scan_id:
            try:
                from .database import get_scan
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


class SecurityHeadersPlugin(ScannerPlugin):
    name = "security_headers"
    label = "Security Headers"
    description = "Quick smoke-test for security headers and transport protections."

    def run(self, ctx: ScanContext):
        from urllib.parse import urlparse
        import urllib.request

        url = ctx.target.strip()
        if not url:
            raise ValueError("Target URL is required")
        parsed = urlparse(url)
        scheme = (parsed.scheme or "https").lower()
        host = parsed.netloc or parsed.path

        ctx.log(f"Checking security headers for {url}")
        req = urllib.request.Request(url, method="GET")
        ctx.progress(10)
        ctx.checkpoint()

        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
                status = getattr(response, "status", 200)
                ctx.log(f"Received HTTP {status} from target")
        except Exception as exc:
            raise RuntimeError(f"Could not reach target: {exc}")

        checks = [
            ("csp", "content-security-policy", "Content Security Policy"),
            ("hsts", "strict-transport-security", "HTTP Strict Transport Security"),
            ("x_content_type_options", "x-content-type-options", "X-Content-Type-Options"),
            ("x_frame_options", "x-frame-options", "X-Frame-Options"),
            ("referrer_policy", "referrer-policy", "Referrer Policy"),
            ("permissions_policy", "permissions-policy", "Permissions Policy"),
        ]

        weak_findings = []
        for key, header_name, label in checks:
            ctx.progress(20 + (60 * checks.index((key, header_name, label)) / max(len(checks), 1)))
            if not headers.get(header_name):
                weak_findings.append(("medium", f"Missing {label}", url, f"The response does not include the {label} header."))

        cookies = headers.get("set-cookie", "")
        if cookies:
            if "httponly" not in cookies.lower():
                weak_findings.append(("medium", "Cookie missing HttpOnly", url, "The application sets cookies without the HttpOnly flag."))
            if "secure" not in cookies.lower():
                weak_findings.append(("medium", "Cookie missing Secure", url, "Cookies are not marked Secure."))
            if "samesite" not in cookies.lower():
                weak_findings.append(("low", "Cookie missing SameSite", url, "The application does not set SameSite on cookies."))

        if scheme == "http":
            weak_findings.append(("high", "Plain HTTP is enabled", url, "The target is served over plain HTTP instead of HTTPS."))

        if "server" in headers:
            server = headers["server"]
            if server and not any(token in server.lower() for token in ("cloudflare", "nginx", "apache", "iis")):
                weak_findings.append(("info", "Version disclosure via Server header", url, f"The response exposes a server signature: {server}."))

        for severity, title, target_url, description in weak_findings:
            ctx.finding(severity, title, target_url, description)
            ctx.log(f"Finding: {title}")
            ctx.progress(min(95, ctx.progress_value + 5))
            ctx.checkpoint()

        if not weak_findings:
            ctx.finding("info", "Security headers look healthy", url, "No obvious header weakness was detected in the quick smoke test.")

        ctx.progress(100)
        ctx.log("Security headers smoke test finished.")
        return ctx


class ZapPlugin(ScannerPlugin):
    name = "zap"
    label = "OWASP ZAP"
    description = "OWASP ZAP automated spider and active vulnerability scan."

    def run(self, ctx: ScanContext):
        import json
        import os
        import time
        from urllib.parse import urlencode
        import urllib.request

        zap_url = os.environ.get("ZAP_API_URL", "http://localhost:8080").rstrip("/")
        zap_key = os.environ.get("ZAP_API_KEY", "")
        zap_active = os.environ.get("ZAP_ACTIVE", "1") != "0"
        max_minutes = float(os.environ.get("ZAP_MAX_MINUTES", "60"))
        max_seconds = max_minutes * 60.0
        start_time = time.time()

        def _zap_request(endpoint: str, params: dict | None = None):
            query = ""
            if params:
                query = "?" + urlencode(params)
            url = f"{zap_url}{endpoint}{query}"
            req = urllib.request.Request(url)
            if zap_key:
                req.add_header("X-ZAP-API-Key", zap_key)
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = resp.read().decode("utf-8")
                return json.loads(data) if data else {}

        ctx.log(f"Checking ZAP daemon connection at {zap_url}")
        try:
            _zap_request("/JSON/core/view/version/")
        except Exception as exc:
            raise RuntimeError(f"Cannot connect to ZAP at {zap_url}: {exc}")

        ctx.progress(10)
        ctx.checkpoint()

        try:
            _zap_request("/JSON/context/action/newContext/", {"contextName": f"scan_{ctx.scan_id or int(time.time())}"})
        except Exception:
            pass
        ctx.checkpoint()

        spider_scan_id = None
        ascan_id = None

        try:
            ctx.log(f"Spidering target {ctx.target}")
            ctx.progress(20)
            spider_res = _zap_request("/JSON/spider/action/scan/", {"url": ctx.target})
            spider_scan_id = spider_res.get("scan") or "0"

            while True:
                ctx.checkpoint()
                if time.time() - start_time > max_seconds:
                    raise TimeoutError(f"ZAP scan timed out after {int(max_minutes)} minute(s)")
                status_data = _zap_request("/JSON/spider/view/status/", {"scanId": spider_scan_id})
                raw_st = status_data.get("status", "100")
                try:
                    pct = int(raw_st)
                except Exception:
                    pct = 100
                ctx.progress(20 + int(pct * 0.3))
                if pct >= 100:
                    break
                time.sleep(0.1)

            ctx.checkpoint()

            if zap_active:
                ctx.log(f"Running active scan against {ctx.target}")
                ascan_res = _zap_request("/JSON/ascan/action/scan/", {"url": ctx.target, "recurse": "true"})
                ascan_id = ascan_res.get("scan") or "0"

                while True:
                    ctx.checkpoint()
                    if time.time() - start_time > max_seconds:
                        raise TimeoutError(f"ZAP scan timed out after {int(max_minutes)} minute(s)")
                    status_data = _zap_request("/JSON/ascan/view/status/", {"scanId": ascan_id})
                    raw_st = status_data.get("status", "100")
                    try:
                        pct = int(raw_st)
                    except Exception:
                        pct = 100
                    ctx.progress(50 + int(pct * 0.45))
                    if pct >= 100:
                        break
                    time.sleep(0.1)
            else:
                ctx.log("Active scan disabled (ZAP_ACTIVE=0), skipping active scan")
                ctx.progress(85)

            ctx.checkpoint()

            ctx.log(f"Collecting findings for {ctx.target}")
            try:
                alerts_data = _zap_request("/JSON/core/view/alerts/", {"baseurl": ctx.target})
                if isinstance(alerts_data, dict):
                    alerts = alerts_data.get("alerts", [])
                elif isinstance(alerts_data, list):
                    alerts = alerts_data
                else:
                    alerts = []
                for alert in alerts:
                    ctx.finding(
                        severity=alert.get("risk", "info"),
                        title=alert.get("alert", alert.get("name", "Vulnerability")),
                        url=alert.get("url", ctx.target),
                        description=alert.get("description", ""),
                    )
            except Exception as e:
                ctx.log(f"Warning: could not retrieve alerts: {e}")

            ctx.progress(100)
            ctx.log(f"ZAP scan finished with {len(ctx.findings)} finding(s)")
            return ctx

        except ScanCancelled:
            try:
                if spider_scan_id:
                    _zap_request("/JSON/spider/action/stop/", {"scanId": spider_scan_id})
                if ascan_id:
                    _zap_request("/JSON/ascan/action/stop/", {"scanId": ascan_id})
            except Exception:
                pass
            raise


def discover_plugins(plugin_dir: Optional[str] = None):
    root = Path(plugin_dir or Path(__file__).resolve().parent / "plugins")
    root.mkdir(parents=True, exist_ok=True)
    found = []
    if root.exists():
        for file in sorted(root.glob("*.py")):
            if file.name.startswith("__"):
                continue
            module_name = f"server.app.plugins.{file.stem}"
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location(module_name, file)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            except Exception:
                continue
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if obj is ScannerPlugin or not issubclass(obj, ScannerPlugin):
                    continue
                if obj.__module__ != module.__name__:
                    continue
                found.append(obj)
    return found


def get_plugin_catalog():
    plugins = [SecurityHeadersPlugin(), ZapPlugin()]
    seen = {p.name for p in plugins}
    for plugin_cls in discover_plugins():
        plugin = plugin_cls()
        if plugin.name not in seen:
            plugins.append(plugin)
            seen.add(plugin.name)
    return [{"name": plugin.name, "label": plugin.label, "description": plugin.description} for plugin in plugins]


def get_plugin_by_name(name: str) -> ScannerPlugin:
    clean = (name or "").strip().lower()
    if clean in ("security_headers", "securityheadersplugin"):
        return SecurityHeadersPlugin()
    if clean in ("zap", "zapplugin"):
        return ZapPlugin()
    for plugin_cls in discover_plugins():
        plugin = plugin_cls()
        if plugin.name.lower() == clean:
            return plugin
    raise ValueError(f"Unknown plugin: {name}")


__all__ = [
    "ScanCancelled",
    "ScanContext",
    "ScanFinding",
    "ScannerPlugin",
    "SecurityHeadersPlugin",
    "ZapPlugin",
    "discover_plugins",
    "get_plugin_catalog",
    "get_plugin_by_name",
]

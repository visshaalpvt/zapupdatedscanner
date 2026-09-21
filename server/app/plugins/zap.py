import json
import os
import time
from urllib.parse import urlencode
import urllib.request

from .base import ScanCancelled, ScanContext, ScannerPlugin


class ZapPlugin(ScannerPlugin):
    name = "zap"
    label = "OWASP ZAP"
    description = "OWASP ZAP automated spider and active vulnerability scan."

    def run(self, ctx: ScanContext):
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

        ctx.progress(10, heartbeat=True)
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
            ctx.progress(20, heartbeat=True)
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
                # Call progress on every poll with heartbeat=True so long scans with static % are not swept as stale
                ctx.progress(20 + int(pct * 0.3), heartbeat=True)
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
                    # Call progress on every poll with heartbeat=True to prevent stale timeout
                    ctx.progress(50 + int(pct * 0.45), heartbeat=True)
                    if pct >= 100:
                        break
                    time.sleep(0.1)
            else:
                ctx.log("Active scan disabled (ZAP_ACTIVE=0), skipping active scan")
                ctx.progress(85, heartbeat=True)

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

            ctx.progress(100, heartbeat=True)
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

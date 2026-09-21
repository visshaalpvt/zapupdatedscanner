import os
import re
import time
from pathlib import Path

import yaml

ROOT_DIR = Path(__file__).resolve().parents[2]
PROJECTS_DIR = Path(ROOT_DIR) / "projects"

from scripts.zap_core import (
    connect_zap,
    run_active_scan,
    run_ajax_spider,
    run_spider,
    save_html_report,
    setup_context_and_auth,
)


def _emit(log_callback, message: str):
    if log_callback is not None:
        log_callback(message)
    else:
        print(message)


def _load_project_config(project):
    project_name = str(project.get("name") or project.get("project_name") or "project")
    base_projects_dir = Path(PROJECTS_DIR)
    config_path = base_projects_dir / project_name / "config" / "scan_config.yaml"
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
        if isinstance(config, dict):
            return config

    target_url = str(project.get("target_url") or "https://example.com")
    domain = re.escape(target_url.rstrip("/"))
    auth_config = project.get("auth_config") or {}
    zap_cfg = project.get("zap_config") or {}
    return {
        "project_name": project_name,
        "target": {
            "url": target_url,
            "include_regex": f"{domain}.*",
        },
        "auth": auth_config if isinstance(auth_config, dict) else None,
        "scan": {"ajax_spider": True, "active_scan": True},
        "zap": {
            "api_key": str(zap_cfg.get("api_key") or os.getenv("ZAP_API_KEY") or ""),
            "api_url": str(zap_cfg.get("api_url") or os.getenv("ZAP_API_URL") or "http://localhost:8080"),
        },
    }


def _alert_counts_from_zap(zap, target_url):
    counts = {"high": 0, "medium": 0, "low": 0}
    try:
        summary = zap.core.alerts_summary(baseurl=target_url) or {}
        for risk_id, count in summary.items():
            try:
                risk_key = str(risk_id or "").strip()
                if risk_key == "3":
                    counts["high"] = int(count or 0)
                elif risk_key == "2":
                    counts["medium"] = int(count or 0)
                elif risk_key == "1":
                    counts["low"] = int(count or 0)
            except (TypeError, ValueError):
                continue
    except Exception:
        return counts
    return counts


def run_full_scan(node_url, target_url, auth_config, on_phase):
    """Run the real ZAP pipeline for the dashboard using the inline auth config."""
    project_name = "dashboard_scan"
    log_lines = []

    def record(message: str):
        log_lines.append(message)
        _emit(on_phase, message)

    include_regex = f"{re.escape(target_url.rstrip('/'))}.*"
    scan_opts = {"ajax_spider": True, "active_scan": True}
    zap_api_key = os.getenv("ZAP_API_KEY") or os.getenv("ZAP_KEY") or None
    zap_api_url = node_url or os.getenv("ZAP_API_URL") or "http://localhost:8080"
    project_dir = Path(PROJECTS_DIR) / project_name
    reports_dir = project_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_filename = f"{project_name}_{timestamp}.html"

    try:
        record(f"[scan] connecting to ZAP at {zap_api_url}")
        zap = connect_zap(api_key=zap_api_key, api_url=zap_api_url)

        record(f"[scan] opening target {target_url}")
        zap.urlopen(target_url)
        time.sleep(2)

        context_id, user_id = setup_context_and_auth(
            zap,
            project_name,
            target_url,
            include_regex,
            auth_config,
        )

        record(f"Spidering target {target_url}")
        run_spider(zap, target_url, context_id, user_id)

        if scan_opts.get("ajax_spider", True):
            record(f"Running AJAX spider against {target_url}")
            run_ajax_spider(zap, target_url)

        if scan_opts.get("active_scan", True):
            record(f"Running active scan against {target_url}")
            run_active_scan(zap, target_url, context_id, user_id)

        record(f"Generating HTML report for {target_url}")
        report_path = save_html_report(zap, target_url, str(reports_dir), report_filename)
        counts = _alert_counts_from_zap(zap, target_url)
        result = {
            "status": "done",
            "phase": "done",
            "report_path": str(report_path),
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
            "log": log_lines,
        }
        record(f"Done: report saved to {report_path}")
        return result
    except Exception as exc:
        record(f"[scan] failed: {exc}")
        raise

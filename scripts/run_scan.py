#!/usr/bin/env python3
"""
run_scan.py
-----------
Runs the full ZAP pipeline (spider -> AJAX spider -> active scan ->
scoped HTML report) for a named project created with new_project.py.

Usage:
    py scripts\\run_scan.py --project jharkhandtourism_vercel

This script starts a local ZAP daemon when needed, connects using the
project's API key, runs the configured scan, and shuts ZAP down in
finally so the machine is left clean for the next run.

Only run this against targets you own or are explicitly authorized to test.
"""

import argparse
import os
import sys
import time

import yaml

from zap_core import (
    start_local_zap,
    stop_local_zap,
    connect_zap,
    setup_context_and_auth,
    run_spider,
    run_ajax_spider,
    run_active_scan,
    save_html_report,
    notify_completion,
)

try:
    from paths import app_root
except ImportError:
    from scripts.paths import app_root
PROJECTS_DIR = os.path.join(str(app_root()), "projects")


def load_project_config(project_name):
    config_path = os.path.join(PROJECTS_DIR, project_name, "config", "scan_config.yaml")
    if not os.path.exists(config_path):
        print(f"[!] No project named '{project_name}' found at {config_path}")
        print(f"    Create it first: py scripts\\new_project.py <url> --name {project_name}")
        sys.exit(1)
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True, help="Project name (folder under projects/)")
    parser.add_argument("--zap-api-url", help="Override the project ZAP API URL for this run")
    parser.add_argument("--zap-api-key", help="Override the project ZAP API key for this run")
    args = parser.parse_args()

    cfg = load_project_config(args.project)
    project_name = cfg["project_name"]
    target_url = cfg["target"]["url"]
    include_regex = cfg["target"]["include_regex"]
    auth = cfg.get("auth")
    scan_opts = cfg["scan"]
    zap_cfg = cfg["zap"].copy()
    if args.zap_api_url:
        zap_cfg["api_url"] = args.zap_api_url
    if args.zap_api_key:
        zap_cfg["api_key"] = args.zap_api_key

    reports_dir = os.path.join(PROJECTS_DIR, project_name, "reports")
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_filename = f"{project_name}_{timestamp}.html"

    print("=" * 70)
    print(f"PROJECT: {project_name}")
    print(f"TARGET:  {target_url}")
    print("=" * 70)

    try:
        start_local_zap(
            api_key=zap_cfg["api_key"],
            api_url=zap_cfg["api_url"],
        )

        zap = connect_zap(
            api_key=zap_cfg["api_key"],
            api_url=zap_cfg["api_url"],
        )

    except ConnectionError as err:
        print(f"[!] {err}")
        return 1

    except Exception as err:
        print(f"[!] Failed to start/connect to local ZAP: {err}")
        return 1

    try:
        print(f"[+] Opening target URL: {target_url}")
        zap.urlopen(target_url)
        time.sleep(2)

        context_id, user_id = setup_context_and_auth(
            zap,
            project_name,
            target_url,
            include_regex,
            auth,
        )

        run_spider(
            zap,
            target_url,
            context_id,
            user_id,
        )

        if scan_opts.get("ajax_spider", True):
            run_ajax_spider(
                zap,
                target_url,
            )

        if scan_opts.get("active_scan", True):
            run_active_scan(
                zap,
                target_url,
                context_id,
                user_id,
            )

        report_path = save_html_report(
            zap,
            target_url,
            reports_dir,
            report_filename,
        )

        notify_completion(
            project_name,
            report_path,
        )

        return 0

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        return 130

    except Exception as err:
        print(f"\n[!] Scan failed with error: {err}")
        return 1

    finally:
        stop_local_zap(
            api_url=zap_cfg["api_url"],
            api_key=zap_cfg["api_key"],
        )


if __name__ == "__main__":
    sys.exit(main() or 0)

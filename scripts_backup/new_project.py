#!/usr/bin/env python3
"""
new_project.py
--------------
Creates a new named project folder under projects/<name>/ with a
scan_config.yaml pre-filled from the URL you give it, plus an empty
reports/ folder. The project name is auto-derived from the URL's
domain (e.g. https://uxpb-abc.vercel.app -> projects/uxpb_abc/),
or you can force a specific name with --name.

Usage:
    py scripts\\new_project.py https://uxpb-abc.vercel.app
    py scripts\\new_project.py https://tfo-xyz.vercel.app --name tfo_project
"""

import argparse
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import yaml

from zap_core import derive_project_name

PROJECTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "projects")


def build_project_config(project_name, url, auth=None, include_regex=None):
    """Return the YAML config dictionary used to create a scan project."""
    url = url.rstrip("/")
    if include_regex is None:
        domain_escaped = url.replace(".", r"\.")
        include_regex = f"{domain_escaped}.*"

    cfg = {
        "project_name": project_name,
        "target": {
            "url": url,
            "include_regex": include_regex,
        },
        "auth": None,
        "scan": {
            "ajax_spider": True,
            "active_scan": True,
        },
        "zap": {
            "api_key": "changeme123",
            "api_url": "http://localhost:8080",
        },
    }

    if auth is None:
        return cfg

    auth_method = str(auth.get("auth_method", "")).lower()
    username = (auth.get("username") or "").strip()
    password = (auth.get("password") or "").strip()

    if auth_method in ("", "none") or (not username and not password):
        return cfg

    normalized = {
        "method": auth_method or "browser",
        "login_url": auth.get("login_url") or url,
        "username": username,
        "password": password,
    }

    if auth.get("logged_in_indicator") is not None:
        normalized["logged_in_indicator"] = auth["logged_in_indicator"]
    if auth.get("logged_out_indicator") is not None:
        normalized["logged_out_indicator"] = auth["logged_out_indicator"]

    if auth_method == "form":
        normalized["username_field"] = auth.get("username_field") or "email"
        normalized["password_field"] = auth.get("password_field") or "password"
    elif auth_method == "browser":
        normalized.setdefault("logged_in_indicator", "Dashboard")

    cfg["auth"] = normalized
    return cfg


def create_project(project_name, url, auth=None):
    project_dir = os.path.join(PROJECTS_DIR, project_name)
    config_dir = os.path.join(project_dir, "config")
    reports_dir = os.path.join(project_dir, "reports")

    if os.path.exists(project_dir):
        print(f"[!] Project '{project_name}' already exists at {project_dir}")
        print("    Edit its config directly, or use --name to pick a different name.")
        return project_dir

    os.makedirs(config_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    config = build_project_config(project_name=project_name, url=url, auth=auth)
    config_path = os.path.join(config_dir, "scan_config.yaml")

    auth_help = """
# --------------------------------------------------------------------
# auth is 'null' (off) by default -- edit it below if this site needs
# login. Two methods are supported:
#
# METHOD 1: form  -- for NORMAL sites where login POSTs directly to
# the site's own server (most traditional login forms).
#
#   auth:
#     method: form
#     login_url: "https://example.com/login"
#     username_field: "email"       # the HTML input's name= attribute
#     password_field: "password"    # the HTML input's name= attribute
#     username: "you@example.com"
#     password: "yourpassword"
#     logged_in_indicator: "Dashboard"   # text only shown after login
#     logged_out_indicator: null         # optional
#
# METHOD 2: browser  -- for sites using Firebase / Clerk / Auth0 /
# Supabase (the login page talks to a THIRD-PARTY auth service, not
# the site's own server -- form-based auth cannot work for these).
# ZAP drives a real headless browser through the actual login page
# instead of faking a request. No field names needed -- ZAP
# auto-detects the email/password boxes on the real rendered page.
#
#   auth:
#     method: browser
#     login_url: "https://example.com/login"
#     username: "you@example.com"
#     password: "yourpassword"
#     logged_in_indicator: "Dashboard"
#     logged_out_indicator: null
# --------------------------------------------------------------------
""".lstrip("\n")

    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        f.write("\n" + auth_help)

    print(f"[+] Created project '{project_name}'")
    print(f"    Config:  {config_path}")
    print(f"    Reports: {reports_dir}")
    print()
    print(f"[+] To run it:  py scripts\\run_scan.py --project {project_name}")
    print(f"[+] To add login: edit {config_path} and fill in the 'auth' section")
    return project_dir


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="Target URL for this project")
    parser.add_argument("--name", help="Force a specific project name (default: derived from URL)")
    args = parser.parse_args()

    project_name = args.name or derive_project_name(args.url)
    create_project(project_name, args.url)
    return 0


if __name__ == "__main__":
    sys.exit(main())
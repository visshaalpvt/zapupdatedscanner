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

import yaml

from zap_core import derive_project_name

PROJECTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "projects")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="Target URL for this project")
    parser.add_argument("--name", help="Force a specific project name (default: derived from URL)")
    args = parser.parse_args()

    project_name = args.name or derive_project_name(args.url)
    project_dir = os.path.join(PROJECTS_DIR, project_name)
    config_dir = os.path.join(project_dir, "config")
    reports_dir = os.path.join(project_dir, "reports")

    if os.path.exists(project_dir):
        print(f"[!] Project '{project_name}' already exists at {project_dir}")
        print("    Edit its config directly, or use --name to pick a different name.")
        sys.exit(1)

    os.makedirs(config_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    domain_escaped = args.url.rstrip("/").replace(".", r"\.")
    config = {
        "project_name": project_name,
        "target": {
            "url": args.url,
            "include_regex": f"{domain_escaped}.*",
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


if __name__ == "__main__":
    main()
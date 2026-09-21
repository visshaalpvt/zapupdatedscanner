#!/usr/bin/env python3
"""Orchestrate multiple product scans across a pool of ZAP servers."""

import argparse
import concurrent.futures
import json
import re
import subprocess
import sys
import threading
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from new_project import create_project, derive_project_name

ROOT_DIR = Path(__file__).resolve().parent.parent
PROJECTS_DIR = ROOT_DIR / "projects"
CONFIG_PATH = ROOT_DIR / "config.json"
SERVER_POOL_PATH = ROOT_DIR / "zap_servers.json"


print_lock = threading.Lock()


def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)


class ServerSlot:
    def __init__(self, name, api_url, api_key, max_concurrent=1):
        self.name = name
        self.api_url = api_url
        self.api_key = api_key
        self.max_concurrent = int(max_concurrent)
        self.in_use = 0

    @property
    def available_slots(self):
        return max(self.max_concurrent - self.in_use, 0)

    def acquire(self):
        self.in_use += 1

    def release(self):
        self.in_use = max(self.in_use - 1, 0)

    def check_health(self, timeout=3):
        """Returns (is_healthy, message)"""
        from zap_core import check_zap_connection
        return check_zap_connection(api_url=self.api_url, api_key=self.api_key, timeout=timeout)


class ServerPool:
    def __init__(self, servers):
        self.servers = [
            ServerSlot(
                name=s.get("name", f"zap-{i+1}"),
                api_url=s["api_url"],
                api_key=s.get("api_key", "changeme123"),
                max_concurrent=s.get("max_concurrent", 1),
            )
            for i, s in enumerate(servers)
        ]
        self._condition = threading.Condition()

    @property
    def total_capacity(self):
        return sum(server.max_concurrent for server in self.servers)

    def acquire(self, preferred_server=None):
        if preferred_server and not any(s.name == preferred_server for s in self.servers):
            valid_names = [s.name for s in self.servers]
            raise ValueError(f"Requested server '{preferred_server}' not found in server pool: {valid_names}")

        with self._condition:
            while True:
                candidates = self.servers
                if preferred_server:
                    candidates = [s for s in self.servers if s.name == preferred_server]
                available = [s for s in candidates if s.available_slots > 0]
                if available:
                    chosen = min(available, key=lambda s: (s.in_use, s.name))
                    chosen.acquire()
                    return chosen
                self._condition.wait()

    def release(self, server):
        with self._condition:
            server.release()
            self._condition.notify_all()

    def check_all_health(self, timeout=3):
        """Check health of all servers in the pool. Returns dict of name -> (healthy, info)."""
        health_results = {}
        for server in self.servers:
            health_results[server.name] = server.check_health(timeout=timeout)
        return health_results


def load_config(path=CONFIG_PATH):
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_server_pool(path=SERVER_POOL_PATH):
    if not path.exists():
        raise FileNotFoundError(f"ZAP server pool file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list) or not data:
        raise ValueError("zap_servers.json must contain a non-empty array of server definitions")
    return ServerPool(data)


def normalize_product_entry(name, entry):
    if not isinstance(entry, dict):
        raise ValueError(f"Product '{name}' config must be an object")
    url = str(entry.get("url", "")).strip()
    if not url:
        raise ValueError(f"Product '{name}' is missing a URL")

    username = str(entry.get("username") or "").strip()
    password = str(entry.get("password") or "").strip()
    auth_method = str(entry.get("auth_method") or "none").strip().lower()

    if auth_method not in {"none", "form", "browser"}:
        auth_method = "none"

    auth = None
    if auth_method != "none" and (username or password):
        auth = {
            "method": auth_method,
            "auth_method": auth_method,
            "username": username,
            "password": password,
            "login_url": entry.get("login_url") or url,
            "logged_in_indicator": entry.get("logged_in_indicator"),
            "logged_out_indicator": entry.get("logged_out_indicator"),
        }
        if auth_method == "form":
            auth["username_field"] = entry.get("username_field") or "email"
            auth["password_field"] = entry.get("password_field") or "password"

    # Prefer explicit project_name, then product dictionary key 'name', else derive from URL
    sanitized_key = re.sub(r"[^a-zA-Z0-9_-]+", "_", str(name).strip()).strip("_")
    project_name = entry.get("project_name") or sanitized_key or derive_project_name(url)

    return {
        "name": name,
        "url": url,
        "auth": auth,
        "project_name": project_name,
    }


def ensure_project(product):
    project_name = product["project_name"]
    project_dir = PROJECTS_DIR / project_name
    if not project_dir.exists():
        create_project(project_name=project_name, url=product["url"], auth=product["auth"])
    return project_name


def run_scan_for_product(product_name, url, auth, project_name, zap_server=None):
    project_dir = PROJECTS_DIR / project_name
    if not project_dir.exists():
        ensure_project({"project_name": project_name, "url": url, "auth": auth})

    cmd = [sys.executable, str(ROOT_DIR / "scripts" / "run_scan.py"), "--project", project_name]
    if zap_server:
        cmd.extend(["--zap-api-url", zap_server.api_url, "--zap-api-key", zap_server.api_key])
    safe_print(f"\n=== START {project_name} :: {url} on {zap_server.name if zap_server else 'default'} ===")

    # Run subprocess with stdout/stderr piped and prefixed for clean concurrent output
    process = subprocess.Popen(
        cmd,
        cwd=str(ROOT_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    if process.stdout:
        for line in process.stdout:
            safe_print(f"[{project_name}] {line}", end="")
    process.wait()

    return {
        "project_name": project_name,
        "url": url,
        "server": zap_server.name if zap_server else "default",
        "return_code": process.returncode,
    }


def orchestrate(config_path=CONFIG_PATH, server_pool_path=SERVER_POOL_PATH, only=None, server_name=None, check_health=True):
    products = load_config(config_path)
    if not isinstance(products, dict):
        raise ValueError("config.json must contain an object keyed by product name")

    selected = []
    for name, entry in products.items():
        if only:
            allowed = {p.strip().lower() for p in only.split(",") if p.strip()}
            if name.lower() not in allowed:
                continue
        selected.append(normalize_product_entry(name, entry))

    if not selected:
        safe_print("[!] No matching products to scan")
        return 0

    pool = load_server_pool(server_pool_path)

    # Server health checks before dispatching
    if check_health:
        safe_print("[*] Checking ZAP server pool connectivity...")
        health = pool.check_all_health(timeout=4)
        online_count = 0
        for s_name, (is_online, info) in health.items():
            if is_online:
                safe_print(f"  [+] {s_name}: ONLINE (ZAP {info})")
                online_count += 1
            else:
                safe_print(f"  [-] {s_name}: OFFLINE ({info})")
        if online_count == 0:
            safe_print("[!] WARNING: All configured ZAP servers are currently OFFLINE/unreachable.")
            safe_print("    Please ensure ZAP daemon is running or check your network/VPN connection.")
            safe_print("    To run a local ZAP daemon: docker compose up -d\n")

    results = []
    lock = threading.Lock()
    completed = 0
    total = len(selected)

    def worker(product):
        nonlocal completed
        ensure_project(product)
        assigned_server = pool.acquire(preferred_server=server_name)
        try:
            result = run_scan_for_product(
                product["name"],
                product["url"],
                product["auth"],
                product["project_name"],
                zap_server=assigned_server,
            )
        finally:
            pool.release(assigned_server)
        with lock:
            completed += 1
            safe_print(f"\n[{completed}/{total}] COMPLETE {result['project_name']} on {result['server']} rc={result['return_code']}")
        results.append(result)
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=pool.total_capacity) as executor:
        futures = [executor.submit(worker, product) for product in selected]
        for future in concurrent.futures.as_completed(futures):
            future.result()

    failed = [r for r in results if r["return_code"] != 0]
    safe_print("\n=== SUMMARY ===")
    for item in results:
        status = "OK" if item["return_code"] == 0 else f"FAIL ({item['return_code']})"
        safe_print(f"- {item['project_name']}: {status} on {item['server']} :: {item['url']}")
    safe_print(f"Total: {len(results)} | Succeeded: {len(results)-len(failed)} | Failed: {len(failed)}")
    return 0 if not failed else 1


def main():
    parser = argparse.ArgumentParser(description="Run ZAP scans across a pool of ZAP servers with capacity-aware routing.")
    parser.add_argument("--config", default=str(CONFIG_PATH), help="Path to config.json")
    parser.add_argument("--servers", default=str(SERVER_POOL_PATH), help="Path to zap_servers.json")
    parser.add_argument("--only", help="Comma-separated project names to run, e.g. abc,pqr")
    parser.add_argument("--server", dest="server_name", help="Force scans onto a specific ZAP server name from zap_servers.json")
    parser.add_argument("--check-servers", action="store_true", help="Probe all servers in zap_servers.json and report connectivity without running scans")
    args = parser.parse_args()
    try:
        if args.check_servers:
            pool = load_server_pool(Path(args.servers))
            safe_print("[*] Probing ZAP server pool connectivity...")
            health = pool.check_all_health(timeout=4)
            for s_name, (is_online, info) in health.items():
                status_label = f"ONLINE (ZAP {info})" if is_online else f"OFFLINE ({info})"
                safe_print(f"  [{'+' if is_online else '-'}] {s_name}: {status_label}")
            return 0

        return orchestrate(
            config_path=Path(args.config),
            server_pool_path=Path(args.servers),
            only=args.only,
            server_name=args.server_name,
        )
    except FileNotFoundError as exc:
        print(f"[!] {exc}")
        print("Create config.json and zap_servers.json at the project root first, then rerun this command.")
        return 1
    except Exception as exc:
        print(f"[!] Failed to orchestrate scans: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

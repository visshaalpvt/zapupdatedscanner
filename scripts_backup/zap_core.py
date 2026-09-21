"""
zap_core.py
-----------
Shared logic for connecting to ZAP, running the spider/AJAX-spider/active
scan pipeline, generating a site-scoped HTML report, and notifying the
user when a scan finishes (terminal banner + beep + Windows popup).

Not run directly -- imported by run_scan.py and new_project.py.
"""

import os
import re
import sys
import time
import subprocess

from zapv2 import ZAPv2


# ---------------------------------------------------------------------
# Connection & Health Check
# ---------------------------------------------------------------------

def check_zap_connection(api_url="http://localhost:8080", api_key=None, timeout=5):
    """Check if the ZAP daemon is online and responsive within timeout seconds.
    Returns (True, version_str) if reachable, or (False, error_reason).
    """
    import urllib.request
    import urllib.error
    import json

    base_url = api_url.rstrip("/")
    probe_url = f"{base_url}/JSON/core/view/version/"
    headers = {"Accept": "application/json"}
    if api_key:
        headers["X-ZAP-API-Key"] = api_key

    req = urllib.request.Request(probe_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                version = data.get("version", "unknown")
                return True, version
            return False, f"HTTP {response.status}"
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", str(e))
        return False, str(reason)
    except Exception as e:
        return False, str(e)


def connect_zap(api_key="changeme123", api_url="http://localhost:8080", timeout=8):
    """Connect to ZAP daemon with a pre-flight reachability check to prevent hanging."""
    is_alive, info = check_zap_connection(api_url=api_url, api_key=api_key, timeout=timeout)
    if not is_alive:
        raise ConnectionError(
            f"Cannot connect to ZAP at {api_url} (reason: {info}).\n"
            f"Ensure ZAP daemon is running (e.g. 'docker compose up -d' or remote server is up and accessible)."
        )
    zap = ZAPv2(apikey=api_key, proxies={"http": api_url, "https": api_url})
    print(f"[+] Connected to ZAP {info} at {api_url}")
    return zap


# ---------------------------------------------------------------------
# Context / auth setup
# ---------------------------------------------------------------------

def setup_context_and_auth(zap, project_name, target_url, include_regex, auth=None):
    context_name = f"{project_name}_{int(time.time())}"
    context_id = zap.context.new_context(context_name)

    if not str(context_id).isdigit():
        print(
            f"[!] ZAP did not return a valid context id (got: {context_id!r}). "
            "Try: docker compose restart"
        )
        sys.exit(1)

    zap.context.include_in_context(context_name, include_regex)
    print(f"[+] Created context '{context_name}' (id={context_id})")

    if not auth:
        print("[+] No login configured -- scanning unauthenticated")
        return context_id, None

    auth_method = auth.get("method", "form")

    if auth_method == "browser":
        return _setup_browser_auth(zap, context_id, auth)
    else:
        return _setup_form_auth(zap, context_id, auth)


def _setup_form_auth(zap, context_id, auth):
    """Classic form-based auth: fakes a single POST request with
    username/password. Only works when the site's OWN server handles
    the login directly (no Firebase/Clerk/Auth0/Supabase in the middle)."""
    login_url = auth.get("login_url", "")
    username_field = auth.get("username_field", "email")
    password_field = auth.get("password_field", "password")
    login_request_data = (
        f"{username_field}={{%username%}}&"
        f"{password_field}={{%password%}}"
    )

    zap.authentication.set_authentication_method(
        contextid=context_id,
        authmethodname="formBasedAuthentication",
        authmethodconfigparams=f"loginUrl={login_url}&loginRequestData={login_request_data}",
    )
    if auth.get("logged_in_indicator"):
        zap.authentication.set_logged_in_indicator(context_id, str(auth["logged_in_indicator"]))
    if auth.get("logged_out_indicator"):
        zap.authentication.set_logged_out_indicator(context_id, str(auth["logged_out_indicator"]))

    user_id = zap.users.new_user(context_id, "scan_user")
    zap.users.set_authentication_credentials(
        context_id, user_id, f"username={auth.get('username', '')}&password={auth.get('password', '')}"
    )
    zap.users.set_user_enabled(context_id, user_id, "true")
    zap.forcedUser.set_forced_user(context_id, user_id)

    print("[+] Form-based authentication configured for context")
    return context_id, user_id


def _setup_browser_auth(zap, context_id, auth):
    """Browser-based auth: ZAP launches a real (headless) browser, loads
    the actual login page, auto-detects the username/password fields on
    the real rendered page, types the credentials in, and clicks submit --
    same as a human would. Works for Firebase/Clerk/Auth0/Supabase-style
    logins since it drives the real UI instead of faking a request."""
    login_url = auth.get("login_url", "")
    browser_id = auth.get("browser_id", "firefox-headless")

    zap.authentication.set_authentication_method(
        contextid=context_id,
        authmethodname="browserBasedAuthentication",
        authmethodconfigparams=f"loginPageUrl={login_url}&browserId={browser_id}",
    )
    if auth.get("logged_in_indicator"):
        zap.authentication.set_logged_in_indicator(context_id, str(auth["logged_in_indicator"]))
    if auth.get("logged_out_indicator"):
        zap.authentication.set_logged_out_indicator(context_id, str(auth["logged_out_indicator"]))

    user_id = zap.users.new_user(context_id, "scan_user")
    zap.users.set_authentication_credentials(
        context_id, user_id, f"username={auth.get('username', '')}&password={auth.get('password', '')}"
    )
    zap.users.set_user_enabled(context_id, user_id, "true")
    zap.forcedUser.set_forced_user(context_id, user_id)

    print("[+] Browser-based authentication configured (real headless browser login)")
    print("[!] Note: first login attempt can take 20-40s -- ZAP is actually")
    print("    opening a browser, loading the page, and typing credentials in.")
    return context_id, user_id


# ---------------------------------------------------------------------
# Scan phases -- each prints live progress, Burp-style
# ---------------------------------------------------------------------

def _wait_for(check_fn, label, poll_seconds=3):
    while True:
        raw_progress = check_fn()
        try:
            progress = int(raw_progress)
        except (ValueError, TypeError):
            if str(raw_progress).lower() in ("100", "completed", "complete", "stopped"):
                progress = 100
            else:
                print(f"    [{label}] status: {raw_progress}")
                time.sleep(poll_seconds)
                continue
        print(f"    [{label}] progress: {progress}%")
        if progress >= 100:
            break
        time.sleep(poll_seconds)


def run_spider(zap, target_url, context_id, user_id):
    print("[+] Spider: starting...")
    if user_id is None:
        scan_id = zap.spider.scan(url=target_url)
    else:
        scan_id = zap.spider.scan_as_user(contextid=context_id, userid=user_id, url=target_url)
    _wait_for(lambda: zap.spider.status(scan_id), "Spider")
    print("[+] Spider: complete")


def run_ajax_spider(zap, target_url):
    print("[+] AJAX Spider: starting (headless browser crawl)...")
    zap.ajaxSpider.scan(target_url)
    while zap.ajaxSpider.status == "running":
        print(f"    [AJAX Spider] running... ({zap.ajaxSpider.number_of_results} found so far)")
        time.sleep(5)
    print(f"[+] AJAX Spider: complete ({zap.ajaxSpider.number_of_results} URLs found)")


def run_active_scan(zap, target_url, context_id, user_id):
    print("[+] Active Scan: starting (this is the slow part)...")
    if user_id is None:
        scan_id = zap.ascan.scan(url=target_url, contextid=context_id, recurse=True)
    else:
        scan_id = zap.ascan.scan_as_user(
            url=target_url, contextid=context_id, userid=user_id, recurse=True
        )
    _wait_for(lambda: zap.ascan.status(scan_id), "Active Scan", poll_seconds=5)
    print("[+] Active Scan: complete")


# ---------------------------------------------------------------------
# Report generation -- scoped to just this site (safe for concurrent scans)
# ---------------------------------------------------------------------

def save_html_report(zap, target_url, output_dir, filename):
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, filename)
    site = target_url.rstrip("/")
    report_saved = False

    try:
        result = zap.reports.generate(
            title=f"ZAP Scan Report - {site}",
            template="traditional-html",
            sites=site,
            reportfilename=os.path.splitext(filename)[0],
            reportdir=os.path.abspath(output_dir),
        )
        if isinstance(result, str) and os.path.exists(result):
            report_saved = True
            out_path = result
            print(f"[+] Report (scoped to {site}) saved to {out_path}")
    except Exception as e:
        print(f"[!] Scoped report generation via reports add-on: {e}")

    if not report_saved:
        print(f"[+] Saving HTML report directly to client: {out_path}")
        try:
            html_report = zap.core.htmlreport()
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(html_report)
            print(f"[+] Report saved to {out_path}")
        except Exception as err:
            print(f"[!] Failed to fetch HTML report: {err}")
            raise

    return out_path


# ---------------------------------------------------------------------
# Completion notification: terminal banner + beep + Windows popup
# ---------------------------------------------------------------------

def notify_completion(project_name, report_path):
    banner = f"  SCAN COMPLETE: {project_name}  "
    print("\n" + "#" * len(banner))
    print(banner)
    print("#" * len(banner))
    print(f"Report: {report_path}\n")

    # Audible beep (built into Python on Windows, no install needed)
    try:
        import winsound
        for _ in range(3):
            winsound.Beep(1000, 300)
            time.sleep(0.15)
    except Exception:
        pass  # non-Windows or sound unavailable -- not critical

    # Native Windows toast popup (uses built-in .NET, no extra installs)
    try:
        ps_script = f'''
        Add-Type -AssemblyName System.Windows.Forms
        $notify = New-Object System.Windows.Forms.NotifyIcon
        $notify.Icon = [System.Drawing.SystemIcons]::Information
        $notify.Visible = $true
        $notify.ShowBalloonTip(8000, "ZAP Scan Complete", "{project_name} finished scanning.", [System.Windows.Forms.ToolTipIcon]::Info)
        Start-Sleep -Seconds 9
        $notify.Dispose()
        '''
        subprocess.Popen(
            ["powershell", "-NoProfile", "-Command", ps_script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass  # not on Windows / powershell unavailable -- terminal banner still shown


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def derive_project_name(url):
    """Turn a URL into a short, filesystem-safe project name.
    e.g. https://uxpb-something.vercel.app -> uxpb_something
    """
    name = re.sub(r"^https?://", "", url)
    name = name.split("/")[0]  # just the host
    name = re.sub(r"\.(vercel|netlify|herokuapp|com|app|dev|io|net|org)$", "", name)
    name = re.sub(r"\.(vercel|netlify|herokuapp|com|app|dev|io|net|org)\.", ".", name)
    name = re.sub(r"[^a-zA-Z0-9]+", "_", name).strip("_")
    return name.lower() or "project"
# ZAP Multi-Project Scanner (Rancher Desktop edition)

Runs OWASP ZAP scans against multiple named projects (e.g. `uxpb_project`,
`tfo_project`), each with its own config and reports folder, all sharing
one ZAP daemon. Supports running several projects at once from separate
terminals.

> Only run this against apps you own or are explicitly authorized to test.

## Project structure

```
zap-scanner/
├── docker-compose.yml       # runs the ZAP daemon (works with Rancher Desktop)
├── requirements.txt
├── scripts/
│   ├── zap_core.py          # shared scan logic (not run directly)
│   ├── new_project.py       # creates a new named project from a URL
│   └── run_scan.py          # runs the full scan for one project
└── projects/                # created automatically, one folder per target
    ├── uxpb_project/
    │   ├── config/scan_config.yaml
    │   └── reports/
    └── tfo_project/
        ├── config/scan_config.yaml
        └── reports/
```

## 1. Set up Rancher Desktop

If you haven't already:
1. Install Rancher Desktop
2. Open it → **Settings** (gear icon) → **Container Engine**
3. Select **dockerd (moby)** (NOT containerd)
4. Apply/restart if prompted

This matters: in `dockerd (moby)` mode, Rancher Desktop provides the same
`docker` and `docker compose` commands you'd use with Docker Desktop, so
nothing else in this guide changes.

## 2. Set up Python

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 3. Start ZAP (only once, no matter how many projects you run)

```bash
docker compose up -d
```

Leave this running in the background. You do NOT need to run this again
per project.

## 4. Create a project for each target

```bash
py scripts\new_project.py https://uxpb-something.vercel.app
py scripts\new_project.py https://tfo-something.vercel.app
```

The project name is auto-derived from the URL's domain (e.g.
`uxpb-something.vercel.app` becomes `projects/uxpb_something/`). Force a
specific name instead with `--name`:

```bash
py scripts\new_project.py https://uxpb-something.vercel.app --name uxpb_project
py scripts\new_project.py https://tfo-something.vercel.app --name tfo_project
```

Each command creates:
```
projects/uxpb_project/config/scan_config.yaml
projects/uxpb_project/reports/               (empty, fills up after scans)
```

### Adding login (only if that specific site needs it)

Open `projects/<name>/config/scan_config.yaml` and fill in the `auth`
section, e.g.:

```yaml
auth:
  login_url: "https://uxpb-something.vercel.app/login"
  username_field: "email"
  password_field: "password"
  username: "your_test_user"
  password: "your_test_password"
  logged_in_indicator: "Dashboard"
  logged_out_indicator: null
```

Leave `auth: null` (the default) to scan unauthenticated. Note: if a
site's login works through a third-party service (Firebase, Supabase,
Auth0, etc.) rather than a plain form POST, `formBasedAuthentication`
won't work for it -- that needs a different setup, ask if you hit this.

## 5. Run a scan

```bash
py scripts\run_scan.py --project uxpb_project
```

You'll see live progress for each phase, Burp-style:

```
======================================================================
PROJECT: uxpb_project
TARGET:  https://uxpb-something.vercel.app
======================================================================
[+] Connected to ZAP 2.17.0
[+] Created context 'uxpb_project_1725...' (id=3)
[+] No login configured -- scanning unauthenticated
[+] Spider: starting...
    [Spider] progress: 45%
    [Spider] progress: 100%
[+] Spider: complete
[+] AJAX Spider: starting (headless browser crawl)...
    [AJAX Spider] running... (120 found so far)
    [AJAX Spider] running... (340 found so far)
[+] AJAX Spider: complete (399 URLs found)
[+] Active Scan: starting (this is the slow part)...
    [Active Scan] progress: 20%
    ...
[+] Active Scan: complete
[+] Report (scoped to https://uxpb-something.vercel.app) saved to projects/uxpb_project/reports/uxpb_project_20260903_161500.html

######################################
  SCAN COMPLETE: uxpb_project
######################################
Report: projects/uxpb_project/reports/uxpb_project_20260903_161500.html
```

When it finishes, you'll get:
- That banner in the terminal
- **3 audible beeps**
- A **native Windows popup notification** (bottom-right corner), even if
  that terminal window is minimized or you're doing something else

## 6. Run multiple projects at once

Open a separate terminal per project, same folder each time:

**Terminal 1:**
```bash
py scripts\run_scan.py --project uxpb_project
```

**Terminal 2:**
```bash
py scripts\run_scan.py --project tfo_project
```

Both talk to the same ZAP daemon. Reports are scoped per-site, so they
won't mix each other's findings.

**Practical limit:** 2-3 concurrent scans on a typical laptop. Each AJAX
spider launches its own headless browser inside the container, so RAM is
usually the bottleneck before anything else. Check headroom anytime with:

```bash
docker stats zap-scanner
```

## 7. Where reports land

Each run drops a timestamped report in that project's own folder:

```
projects/uxpb_project/reports/uxpb_project_20260903_161500.html
projects/tfo_project/reports/tfo_project_20260903_162030.html
```

Open directly (`start projects\uxpb_project\reports\...\html`) to view
rendered with colors/tables. To email it: zip the file first, or print
to PDF with "Background graphics" enabled in the print dialog -- Gmail
(and most mail clients) can't render raw HTML attachments inline.

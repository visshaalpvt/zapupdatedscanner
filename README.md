# ZAP Scanner Dashboard MVP

This project now includes a minimal team-facing dashboard built around the existing ZAP scanning engine.

## What it includes

- FastAPI API for auth, project registration, scan queueing, and report access
- Worker process that polls scan jobs from the SQLite DB and runs the scan logic
- Internal ZAP node (`zap1`) with no published ports
- Plain HTML/JS dashboard served by the API container
- Shared SQLite DB as the single source of truth across API and worker

## Default credentials

- username: `admin`
- password: `changeme`

## Run locally

```bash
docker compose up --build
```

Then open:

```text
http://localhost:8000
```

## App structure

```text
server/app/
  database.py      # SQLite schema and DB helpers
  main.py          # FastAPI routes and WebSocket endpoints
  zap_client.py    # scan integration point; replace with real logic
worker/
  main.py          # scan worker loop
web/
  index.html       # lightweight dashboard UI
```

## Notes on the scan logic

The current `run_full_scan()` is intentionally a stub so the MVP can run without the full production scan workflow. Replace it with the real logic from `scripts/run_scan.py` once your app-specific login flow is ready.

## v1 -> v2 roadmap

- swap SQLite for Postgres
- add password reset / user management
- add more ZAP nodes and worker scaling
- turn project auth config into a richer persisted schema
- add proper report retention and health checks

## Security

This is an internal MVP. No SSO, no project ownership model, and no public ZAP ports are exposed.

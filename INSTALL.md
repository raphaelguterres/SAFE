# SAFE Installation Guide

SAFE is a Python/Flask enterprise-preview defense platform for local labs,
portfolio demos, and pilot deployments.

## Requirements

- Python 3.11+
- Git
- Windows PowerShell 5+ or PowerShell 7
- Optional: Docker Desktop
- Optional production-like services: PostgreSQL 16 and Redis 7

## Windows Local Setup

```powershell
cd "C:\Users\rapha\Downloads\PROJETO SOC"
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Create local config:

```powershell
Copy-Item .env.example .env
```

For local demo only, keep:

```powershell
$env:IDS_AUTH="false"
$env:HTTPS_ONLY="false"
```

For production-like validation, configure strong values:

```powershell
$env:IDS_AUTH="true"
$env:TOKEN_SIGNING_SECRET="replace-with-32-plus-random-characters"
$env:SECRET_KEY="replace-with-another-strong-random-secret"
```

## Bootstrap Helper

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap_dev.ps1
```

Linux/macOS:

```bash
sh scripts/bootstrap_dev.sh
```

## Start Server

```powershell
python app.py
```

Open:

- `http://127.0.0.1:5000/login`
- `http://127.0.0.1:5000/admin`
- `http://127.0.0.1:5000/client/overview`
- `http://127.0.0.1:5000/soc`
- `http://127.0.0.1:5000/soc/search`
- `http://127.0.0.1:5000/soc/detection-packs`
- `http://127.0.0.1:5000/api/openapi.yaml`

## PostgreSQL Migrations

SQLite remains the default for local demo. For production-like PostgreSQL, set
`DATABASE_URL` and run the idempotent migration runner:

```powershell
$env:DATABASE_URL="postgresql://safe:safe@localhost:5432/safe"
python scripts\migrate_postgres.py --dry-run
python scripts\migrate_postgres.py
```

You can also pass `--database-url` directly. The runner creates
`schema_migrations` and applies only pending files from `migrations/postgres`.

## Optional Redis Queues

The operational reliability queue uses memory by default. Redis can be enabled
for production-style pilots without making local demo dependent on Redis:

```powershell
$env:SAFE_QUEUE_BACKEND="redis"
$env:REDIS_URL="redis://localhost:6379/0"
$env:SAFE_REDIS_REQUIRED="false"
```

With `SAFE_REDIS_REQUIRED=false`, SAFE falls back to memory with a warning if
Redis is unavailable. Use `SAFE_REDIS_REQUIRED=true` only when Redis availability
must be a startup requirement.

## Seed Demo Data

```powershell
python demo\seed_demo.py
```

This creates synthetic tenant, host, incident, attack timeline, detection, case,
approval, and executive dashboard data. It does not contain real secrets and
does not execute response actions.

## Start SAFE Agent Demo

```powershell
python -m agent --config agent\config.yaml
```

Build `agent.exe`:

```powershell
cd agent
powershell -ExecutionPolicy Bypass -File .\build_agent.ps1 -Clean -WithService
```

## Docker Development

```powershell
Copy-Item .env.example .env
docker compose up --build safe-web redis
```

With worker:

```powershell
docker compose --profile workers up --build
```

With PostgreSQL:

```powershell
docker compose --profile postgres up --build
```

## Quality Gates

```powershell
python -m pytest -q
python run_pentest_audit.py
python scripts\release_check.py
python scripts\demo_readiness_check.py
python scripts\security_self_check.py
python scripts\template_check.py
python scripts\branding_check.py
```

Quick static release validation:

```powershell
python scripts\release_check.py --quick
```

## Troubleshooting

- PostgreSQL refused connection: unset `DATABASE_URL` for local SQLite mode.
- Missing `TOKEN_SIGNING_SECRET`: configure it outside dev/test.
- Rate limiting warning: install dependencies from `requirements.txt`.
- Agent cannot send events: verify `agent/config.yaml`, server URL, and API key.
- Template or branding check fails: inspect the file/line printed by the script.

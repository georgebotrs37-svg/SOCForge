# SOCForge

SOCForge is an educational SOC analyst training platform for students, companies,
and graduation projects. It is designed for Tier 1-2 practice through realistic,
seeded incidents and investigation workflows.

> **Educational use only. SOCForge scores are practice feedback and are not a
> certification or proof of professional qualification.**

## Architecture

The project starts as a modular monolith:

- `backend/app/api/`: FastAPI routes
- `backend/app/domain/`: domain enums and rules
- `backend/app/models/`: SQLAlchemy persistence models
- `backend/app/schemas/`: Pydantic API and scenario schemas
- `backend/app/services/`: application use cases
- `backend/app/generators/`: deterministic log and incident generation
- `backend/app/query_engine/`: SPL-like query parser and executor
- `backend/app/scoring/`: server-side scoring
- `frontend/`: React, TypeScript, Vite, and Tailwind

Ground truth is stored separately in `shift_truth`; trainee-facing schemas and
endpoints must never serialize it during an active shift. Scoring is a backend
responsibility. Scenario versions are pinned to shifts so edits cannot rewrite an
in-progress run's source definition.

## Database

SQLite is the local default. Set `SOCFORGE_DATABASE_URL` to a PostgreSQL SQLAlchemy
URL in production. Schema changes are managed with Alembic:

```powershell
cd backend
python -m pip install -e ".[dev]"
alembic upgrade head
```

The initial schema includes users, scenarios, assignments, shifts and isolated
shift truth, alerts and logs, incidents and evidence, response actions, reports,
scores, skill progress, and audit events.

## Backend development

```powershell
cd backend
python -m pip install -e ".[dev]"
uvicorn app.main:app --reload
```

OpenAPI documentation is available at `/docs`; the health endpoint is `/health`.
Copy `.env.example` to `.env` for local development. Production startup rejects
weak JWT keys, SQLite, non-TLS database connections, wildcard CORS/hosts, and
non-HTTPS browser origins. Generate a unique key with
`python -c "import secrets; print(secrets.token_urlsafe(48))"` and configure
`SOCFORGE_JWT_SECRET` through the deployment secret manager. Production also
requires `SOCFORGE_DATABASE_URL` to use PostgreSQL with `sslmode=require` (or
stronger), `SOCFORGE_CORS_ORIGINS` to list exact HTTPS frontend origins, and
`SOCFORGE_ALLOWED_HOSTS` to list exact public API host names. Production serves
HTTPS redirects, HSTS, security headers, and disables interactive API docs.

SOC operating defaults can be managed through deployment environment variables:

- `SOCFORGE_CRITICAL_ALERT_SLA_SECONDS`: grading SLA for critical response
- `SOCFORGE_DEFAULT_SHIFT_DURATION_MINUTES` and
  `SOCFORGE_DEFAULT_NOISE_EVENTS_PER_MINUTE`: default training workload
- `SOCFORGE_MAX_QUERY_ROWS`: hard ceiling for records scanned by a query

Authenticated users can view the non-secret policy at `/api/v1/settings/soc`.
The SOC Settings screen lets analysts customize their own scenario, shift
duration, telemetry noise, and alert/log refresh interval. Platform-wide policy
and secrets remain server-managed and are never editable or exposed in the
browser. Access tokens are held in tab-scoped session storage and are cleared
when the user signs out or closes the browser tab.

Run the backend tests and checks:

```powershell
cd backend
pytest
ruff check app tests
mypy app
```

## Frontend development

```powershell
cd frontend
npm install
npm run dev
```

The frontend connects to the backend at `/api/v1`. During development, Vite
proxies `/api` to `http://127.0.0.1:8000`; start the backend and frontend in
separate terminals. To use a different backend origin, set
`VITE_API_BASE_URL` in the frontend environment (for example,
`VITE_API_BASE_URL=http://127.0.0.1:8000`). Production deployments should route
`/api` to the backend or configure that variable. The UI supports account
registration and login, starting/selecting shifts, loading alerts and logs, and
running queries against the selected shift. Run `npm test` or `npm run build`
to validate the frontend.

## Scenario authoring

Scenario content is authored as YAML or JSON and validated against the versioned
Pydantic `ScenarioDefinition` in `backend/app/schemas/scenario.py`. Unknown keys
are rejected. The schema separates environment, attack-chain stages, alert
definitions, background-noise settings, hidden grading ground truth, and shift
constraints. Use `load_scenario` to load and validate either supported file
format.

## Delivery phases

1. Project structure, DB schema, scenario schema, and documentation
2. Seeded log generator and three attack-chain templates
3. SPL-like query parser and executor
4. API, authentication, and server-side scoring
5. Analyst UI: alert queue, log explorer, process tree, and case view
6. Learning path, instructor mode, and report grading
7. Docker, CI, and expanded documentation

## Deterministic generator (Phase 2)

The `generate_shift` function in `backend/app/generators/shift.py` (re-exported
from `app.generators`) creates a reproducible shift for `phishing_macro`, `brute_force`, or
`ransomware_precursor`. The same seed, template, shift start time, and generation
options produce the same timestamped logs and alerts. Generated activity
includes Windows Security, Sysmon, DNS, proxy, firewall, EDR, and email gateway
events, plus optional benign look-alike alerts.

```python
from app.generators import AttackTemplate, generate_shift

shift = generate_shift(seed=2026, template=AttackTemplate.PHISHING_MACRO)
```

Logs and alerts are the trainee-visible shift data. `shift.ground_truth` is
separate grading data and must stay in server-side code; do not include it in
trainee API responses. Generated external addresses use documentation-only
TEST-NET ranges and domains under `.test`; the generator does not contact any
external systems.

This repository currently contains the Phase 1 foundation and Phase 2 generator.
Later phases will build on these stable boundaries.

## Query language (Phase 3)

The query engine in `backend/app/query_engine/` parses a query into an AST before
executing it; it does not use Python evaluation or SQL string concatenation.
Supported operations are implicit/explicit boolean filters, comparisons,
`*`/`?` wildcards, `earliest`/`latest` time bounds, `where`, `stats` (`count`,
`sum`, `avg`, `min`, `max`, and `dc`), `dedup`, multi-key `sort`, `head`,
`table`, and `eval` arithmetic plus `lower`, `upper`, `abs`, `round`, `tostring`,
and `coalesce`.

```text
index=windows event_id=4625 earliest=-15m latest=now
| stats count by src_ip
| where count > 10
| sort -count
| head 20
```

`execute_query(query, records, now=...)` accepts mapping records and generated
or persisted log model objects. Relative times use the supplied `now` value (or
UTC current time), which allows deterministic tests. Parser and execution
failures raise `QuerySyntaxError` or `QueryExecutionError` with user-readable
messages.

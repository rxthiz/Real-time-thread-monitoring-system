# Realtime Threat Monitoring System

AI-powered realtime threat monitoring platform for weapon detection, explainable alerting, cross-camera tracking, predictive risk analysis, evidence capture, and SOS escalation workflows.

## Overview

This project is an end-to-end surveillance intelligence stack that turns live video streams into actionable incident workflows.

It combines:

- Weapon detection (YOLO/YOLO-World)
- Optional action recognition (Video Swin / MMAction2)
- Severity fusion + explainable AI
- Adaptive false-positive filtering with feedback learning
- ReID-based trajectory tracking
- Predictive pre-incident risk scoring
- Evidence clip generation
- Signed append-only audit trail
- SOS dispatch and escalation management
- Realtime dashboards via REST + WebSockets

## Key Features

- Realtime weapon threat detection (`gun`, `knife`, `stick` aliases)
- Rule-based severity scoring with XAI factors and model breakdown
- Cross-camera ReID correlation and path reconstruction
- Predictive risk scoring (loitering, transitions, pacing, speed, anomaly)
- False-positive ML filter (`accepted` / `uncertain` / `rejected`)
- Operator feedback loop to retrain false-positive model
- Pre/post event evidence clip capture with thumbnail + hash
- Incident timeline reconstruction + PDF export
- Shift analytics and heatmap generation
- Configurable escalation chain (webhook/SMS/push)
- Queue-worker pipeline with retries, DLQ, metrics (`/api/v3`)

## Architecture At A Glance

1. Stream source (camera/video) is ingested by `RealtimeThreatEngine`.
2. Detection and optional action inference run per configured frame interval.
3. Fusion computes severity and explanation payload.
4. ReID enriches detections with track/path context.
5. Predictive analyzer computes risk and pre-alert signals.
6. False-positive filter decides final alert acceptance.
7. Alerts are persisted, audited, and pushed over WebSocket.
8. High/critical alerts trigger evidence capture.
9. SOS and escalation workflows can auto/manual trigger dispatch.
10. Dashboards consume live and historical API data.

## Tech Stack

- Backend: `FastAPI`, `Uvicorn`, `Pydantic`
- Async DB: `SQLAlchemy[asyncio]`, `asyncpg`, `Alembic`
- Cache/Messaging: `Redis` (default), optional `RabbitMQ` / `Kafka`
- CV/ML: `PyTorch`, `TorchVision`, `OpenCV`, `Ultralytics`, `MMAction2`, `scikit-learn`
- Frontend: `React`, `Vite`, `Tailwind CSS`
- Storage:
  - `PostgreSQL` (app domain data / v3 pipeline)
  - `Redis` (cache, queue, pub/sub, metrics)
  - `SQLite` (`data/alert_audit.db` for immutable audit + policy state)
  - `JSONL` (`data/alerts.jsonl`)
  - Evidence files (`data/evidence/`)

## Repository Structure

- `api/main.py`: primary API app (auth, monitoring, incidents, SOS, WS)
- `api/realtime_engine.py`: core realtime detection + alerting engine
- `api/routes.py`: `/api/v3` queue/worker-facing endpoints
- `workers/alert_worker.py`: async worker with retry + DLQ behavior
- `services/`: queue producer, processing, broker abstraction
- `src/models/`: weapon/action model wrappers
- `src/fusion/`: severity rule engine
- `src/xai/`: explanation generation
- `src/reid/`: embedding + tracking + path management
- `src/predictive/`: behavior/risk/anomaly analysis
- `src/filters/`: false-positive filtering + feedback retraining
- `src/evidence/`: clip buffer/recording/writer
- `src/sos/`: dispatch, routing, escalation integration
- `src/alerts/audit_store.py`: signed append-only audit + policy/incident state
- `frontend/`: React zone-map dashboard
- `web/`: static dashboard assets served by FastAPI
- `scripts/`: bootstrap, smoke tests, dev services, DLQ replay

## Quick Start

### 1. Clone + Environment

```bash
python -m venv .venv
. .venv/Scripts/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
copy .env.example .env
```

### 2. Bootstrap (recommended)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
```

Useful options:

- Full infra + broker deps:
  - `powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1 -InfraProfile full -UseBrokerDeps`
- Skip Docker:
  - `powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1 -SkipDocker`

### 3. Run API

```bash
uvicorn api.main:app --host 127.0.0.1 --port 8000
```

### 4. Run Worker (for `/api/v3` queue pipeline)

```bash
python workers/alert_worker.py
```

### 5. Run Frontend Dashboard (React)

```bash
cd frontend
npm install
npm run dev
```

Production build (served by FastAPI at `/zone-map-dashboard`):

```bash
cd frontend
npm install
npm run build
```

## Default Credentials

- User: `user / user123`
- Admin: `admin / admin123`

Change these in `.env` before production use.

## Configuration

Primary runtime config lives in:

- `src/config/settings.yaml`

Main environment file:

- `.env` (copy from `.env.example`)

Important runtime env vars:

- `THREAT_CONFIG`, `THREAT_SOURCE`, `THREAT_VIDEO_PATH`, `THREAT_CAMERA_INDEX`
- `DATABASE_URL`, `REDIS_URL`
- `ALERT_BROKER_BACKEND=redis|rabbitmq|kafka`
- `THREAT_SMS_PROVIDER=webhook|twilio`
- `THREAT_AUDIT_DB_PATH`, `THREAT_AUDIT_SIGNING_KEY`

## Core API Surface

### Auth + Session

- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`

### Monitoring + Alerts

- `GET /api/status`
- `GET /api/detections/history`
- `GET /api/alerts/history`
- `POST /api/alerts/{alert_id}/disposition`
- `GET /api/alerts/{alert_id}/explanation`
- `GET /api/alerts/{alert_id}/evidence`

### ReID + Predictive

- `GET /api/reid/tracks`
- `GET /api/reid/tracks/{threat_id}`
- `GET /api/reid/tracks/{threat_id}/path`
- `GET /api/predictive/tracks`
- `GET /api/predictive/high-risk`
- `POST /api/reid/observe`

### Incidents + Escalation + SOS

- `GET /api/incidents/{incident_id}/timeline`
- `POST /api/incidents/{incident_id}/events`
- `GET /api/incidents/{incident_id}/report.pdf`
- `GET /api/escalation/chain`
- `POST /api/escalation/chain`
- `POST /api/sos/dispatch`
- `POST /api/sos/manual`

### Analytics

- `GET /api/analytics/overview`
- `GET /api/analytics/heatmap`
- `GET /api/analytics/shift-windows`
- `POST /api/analytics/shift-windows`

### WebSockets

- `WS /ws/stream` (annotated JPEG frame payloads)
- `WS /ws/detections` (live detection/alert/predictive packets)
- `WS /ws/alerts` (Redis pub/sub alert broadcast stream)

### Queue/Worker Ops (`/api/v3`)

- `POST /api/v3/alerts`
- `GET /api/v3/alerts/recent`
- `GET /api/v3/ops/metrics`
- `GET /api/v3/ops/health`

## Persistence

- Alerts log: `data/alerts.jsonl`
- Evidence clips: `data/evidence/`
- Audit/policy/incident state: `data/alert_audit.db`
- App DB tables (v3 pipeline): PostgreSQL via `DATABASE_URL`
- Queue/cache/pubsub: Redis via `REDIS_URL`

## Testing

Install test dependencies:

```bash
pip install -r requirements-dev.txt
```

Run integration tests:

```bash
pytest tests/test_alert_pipeline_integration.py -q
```

## Operations Utilities

Run smoke test:

```bash
python scripts/e2e_smoke_test.py
```

Replay DLQ:

```bash
python scripts/replay_dlq.py --limit 100
python scripts/replay_dlq.py --limit 100 --dry-run
```

Manage API + worker on Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/dev_services.ps1 -Action start
powershell -ExecutionPolicy Bypass -File scripts/dev_services.ps1 -Action status
powershell -ExecutionPolicy Bypass -File scripts/dev_services.ps1 -Action stop
```

Start infra:

```bash
docker compose up -d
```

## Implemented Scope

- Realtime detection and streaming pipeline
- XAI-integrated alert reasoning
- Adaptive per-zone policy controls
- ReID + predictive behavior intelligence
- Evidence + immutable audit chain
- SOS dispatch and escalation lifecycle
- Incident response timeline and reporting
- Async queue/worker reliability path

## Future Scope

- Privacy masking / anonymization
- Enterprise SSO + RBAC
- Mobile responder app
- Multi-site federation
- Model retraining automation from feedback
- SIEM/SOC integration
- Edge-optimized deployment profiles

## Limitations

- Compute-heavy ML stack for full feature set
- Accuracy depends on data quality and scene conditions
- ReID/predictive modules require calibration for new environments
- Production deployment needs enterprise-grade hardening (secrets, auth, network policy, observability)


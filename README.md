# Realtime Threat Monitoring System

This repo now runs a full backend runtime for:
- Weapon detection with YOLO / YOLO-World (gun, knife, stick aliases)
- Optional Video Swin action recognition (MMAction2)
- Rule-based threat fusion and severity scoring
- Alert logging to JSONL
- Signed immutable alert audit trail (append-only)
- Adaptive false-positive control (per camera-zone/hour thresholds + auto snooze learning)
- Advanced ReID correlation (embeddings + temporal matching + cross-zone paths)
- Incident timeline reconstruction + PDF export for handoff
- Configurable SOS escalation ladder with timed operator/supervisor/emergency delivery tracking
- Shift-aware analytics (configurable windows + operator/zone performance + heatmaps)
- WebSocket live stream + detection push for dashboard clients

## Added Features

- Real-time weapon and action detection pipeline
- Explainable AI outputs with factor-level risk breakdown
- Predictive threat intelligence for pre-incident risk scoring
- Evidence clip capture with pre/post-event buffering
- Signed immutable alert audit trail for forensic compliance
- Adaptive false-positive control by zone and hour
- Cross-camera ReID tracking with path reconstruction
- Incident timeline generation with PDF handoff reports
- Configurable SOS escalation ladder with delivery tracking
- React zone map dashboard with live overlays and drilldowns

## Future Scope

- Face anonymization and privacy masking for compliance-first deployments
- Multi-site federation dashboard for centralized monitoring
- Role-based access control with SSO integration (OAuth/SAML)
- Mobile responder app for push alerts and incident acknowledgements
- Model auto-retraining workflow with human feedback loops
- Edge deployment profile for low-latency offline campuses
- SIEM/SOC integrations (Splunk, QRadar, Sentinel) for enterprise ops
- Advanced geofencing and no-go zone behavioral policies
- Voice-driven incident notes and multilingual command support
- Digital twin simulation mode for training and stress testing

## 1. Setup

```bash
python -m venv .venv
. .venv/Scripts/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
copy .env.example .env
```

One-command bootstrap (recommended):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
```

Bootstrap options:
- Core infra (PostgreSQL + Redis) is default.
- Full infra: `powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1 -InfraProfile full -UseBrokerDeps`
- Skip Docker: `powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1 -SkipDocker`

Optional reproducible install (exact versions):

```bash
pip install -r requirements-lock.txt
```

Optional broker dependencies (for RabbitMQ/Kafka backends):

```bash
pip install -r requirements-broker.txt
```

Optional lock refresh from your current environment:

```bash
pip freeze > requirements-lock.txt
```

The backend auto-loads `.env` (via `python-dotenv`) if present.

## 2. Configure Models

Edit `src/config/settings.yaml`:
- `weapon.yolo_weights`: path to YOLO/YOLO-World weights
- `action.swin_config`: MMAction2 Video Swin config file
- `action.swin_checkpoint`: Video Swin checkpoint path

## 3. Run Backend API

```bash
uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Dev hot-reload (optional):

```bash
uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

If `--reload` fails on Windows with multiprocessing permission errors, use the non-reload command above.

Environment options:
- `THREAT_CONFIG` (default: `src/config/settings.yaml`)
- `THREAT_SOURCE` (`auto`, `video`, `camera`)
- `THREAT_VIDEO_PATH` (default: `data/sample.mp4`)
- `THREAT_CAMERA_INDEX` (default: `0`)
- `THREAT_LOOP_VIDEO` (`1` or `0`, default: `1`)
- `THREAT_AUDIT_DB_PATH` (default: `data/alert_audit.db`)
- `THREAT_AUDIT_SIGNING_KEY` (set this in production)
- `THREAT_ESCALATION_WEBHOOK_URL`, `THREAT_ESCALATION_SMS_WEBHOOK_URL`, `THREAT_ESCALATION_PUSH_WEBHOOK_URL`
- `THREAT_USER_USERNAME`, `THREAT_USER_PASSWORD` (default: `user` / `user123`)
- `THREAT_ADMIN_USERNAME`, `THREAT_ADMIN_PASSWORD` (default: `admin` / `admin123`)
- `ALERT_BROKER_BACKEND` (`redis`, `rabbitmq`, or `kafka`; default: `redis`)
- `RABBITMQ_URL` (default: `amqp://guest:guest@localhost/`)
- `KAFKA_BOOTSTRAP_SERVERS` (default: `localhost:9092`)
- `THREAT_SMS_PROVIDER` (`webhook` or `twilio`; default: `webhook`)
- `THREAT_TWILIO_ACCOUNT_SID`, `THREAT_TWILIO_AUTH_TOKEN`
- `THREAT_TWILIO_FROM_NUMBER` or `THREAT_TWILIO_MESSAGING_SERVICE_SID`

## 4. API Endpoints

- `GET /api/status`
- `GET /api/detections/history?limit=100`
- `DELETE /api/detections/history`
- `GET /api/alerts/history?limit=100`
- `GET /api/alerts/{alert_id}/explanation`
- `DELETE /api/alerts/history`
- `POST /api/alerts/{alert_id}/disposition` (acknowledged/escalated/dismissed)
- `GET /api/alerts/{alert_id}/audit?limit=200`
- `GET /api/alerts/{alert_id}/evidence` (`?download=1` returns the MP4 clip, `?thumbnail=1` returns the preview image)
- `GET /api/audit/entries?limit=200&alert_id=<optional>` (admin)
- `GET /api/audit/verify?alert_id=<optional>` (admin)
- `GET /api/zones/policies?limit=200` (admin)
- `GET /api/zones/live-status?limit=200`
- `GET /api/zones/layout?limit=200`
- `GET /api/zones/{zone_key}/policy?hour_of_day=<0-23>` (admin)
- `POST /api/zones/{zone_key}/policy` (admin; threshold/snooze tuner)
- `GET /api/analytics/shift-windows`
- `POST /api/analytics/shift-windows` (admin; update shift definitions)
- `GET /api/analytics/overview?from_ts=<iso>&to_ts=<iso>&zone_key=<optional>&hour_start=<0-23>&hour_end=<0-23>`
- `GET /api/analytics/heatmap?from_ts=<iso>&to_ts=<iso>&zone_key=<optional>`
- `GET /api/escalation/chain`
- `POST /api/escalation/chain` (admin; update timed escalation steps/channels)
- `GET /api/incidents/{incident_id}/escalation/status`
- `POST /api/incidents/{incident_id}/escalation/start`
- `POST /api/incidents/{incident_id}/escalation/ack`
- `GET /api/reid/tracks?limit=100&within_seconds=900`
- `GET /api/reid/tracks/{threat_id}`
- `GET /api/reid/tracks/{threat_id}/path`
- `GET /api/predictive/tracks?limit=100&within_seconds=900`
- `GET /api/predictive/high-risk?limit=100&within_seconds=900`
- `POST /api/reid/observe` (ingest external camera detections for cross-camera correlation)
- `GET /api/incidents/{incident_id}/timeline?limit=3000`
- `POST /api/incidents/{incident_id}/events` (event_type: `SOS_TRIGGERED`, `POLICE_DISPATCHED`, `OFFICER_DISPATCHED`, `OFFICER_ARRIVED`, `SCENE_CLEARED`, `MANUAL_NOTE`)
- `GET /api/incidents/{incident_id}/report.pdf` (export chronological report)
- `POST /api/sos/test-sms` (admin; provider-backed SMS smoke test)
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `WS /ws/stream` (annotated JPEG frames as base64)
- `WS /ws/detections` (realtime detection + severity packets)
- `GET /` (built-in dashboard UI)
- `GET /zone-map-dashboard` (serves the built React zone-map dashboard if `frontend/` has been built)

Alerts are persisted to `data/alerts.jsonl`.
Evidence clips are persisted to `data/evidence/`.
Immutable audit entries are persisted to `data/alert_audit.db` (`alert_audit` table).
Adaptive tuning state is stored in `zone_policy_state` in the same DB.
Shift windows are stored in `shift_window_config` in the same DB.
Escalation steps are stored in `escalation_chain_config` in the same DB.
Threat trajectories are maintained in-memory by the ReID correlator.

## 5. CLI Demo (Optional)

```bash
python scripts/run_demo.py --video data/sample.mp4 --config src/config/settings.yaml
```

## 6. React Zone Dashboard

The repo now includes a React + Tailwind zone monitoring dashboard scaffold in `frontend/`.
It now renders a control-room style live map with:

- backend-driven zone layout rectangles from `GET /api/zones/layout`
- websocket threat markers from `WS /ws/detections`
- ReID movement path overlays from `GET /api/reid/tracks`
- predictive risk labels over tracked paths and a high-risk individuals panel
- per-zone side-panel drilldown for alerts, thresholds, analytics, and selected track details
- evidence playback from the alert cards via `GET /api/alerts/{alert_id}/evidence`
- explanation-aware alert cards with confidence/model breakdowns

Development:

```bash
cd frontend
npm install
npm run dev
```

Production build for FastAPI static serving:

```bash
cd frontend
npm install
npm run build
```

The build output is written to `web/react-zone-dashboard/` and is served by FastAPI at:

- `GET /zone-map-dashboard`

## 7. Evidence Clip Capture

Realtime alerts can now trigger automatic pre-event + post-event evidence clips.
Clips are buffered in-memory before the alert, completed asynchronously in a background writer thread, and exposed back to the dashboard through the alert metadata and evidence endpoint.

Config in `src/config/settings.yaml`:

```yaml
evidence:
  enabled: true
  output_dir: "data/evidence"
  pre_event_seconds: 10
  post_event_seconds: 10
  watermark_timestamp: true
```

For qualifying alerts, the alert JSONL record is updated with:

- `evidence_status`
- `evidence_clip_path`
- `clip_duration`
- `frame_count`
- `evidence_clip`

`evidence_clip` is returned in alert history and evidence lookups in the form:

```json
{
  "path": "data/evidence/20260323T120000000000Z_zone-a_critical_ALT-123.mp4",
  "duration": 20.0,
  "frames": 600,
  "status": "ready",
  "created_at": "2026-03-23T12:00:20+00:00",
  "download_url": "/api/alerts/ALT-123/evidence?download=1"
}
```

The logical filename pattern follows `{timestamp}*{zone_key}*{severity}_{alert_id}.mp4`; on Windows the stored filename uses `_` in place of `*` because `*` is not a valid filesystem character.

## 8. Advanced ReID

The ReID subsystem now keeps:

- normalized embeddings per observation
- active cross-camera tracks
- per-track zone/camera history
- normalized path points for dashboard trajectory rendering

Track path points are returned in the format:

```json
[
  {
    "x": 0.32,
    "y": 0.45,
    "zone_key": "zone:A",
    "camera_id": "camera:2",
    "ts": "2026-03-23T10:00:05+00:00"
  }
]
```

`src/config/settings.yaml` now supports richer ReID settings, including:

- `reid.backend`
- `reid.model_name`
- `reid.weights_path`
- `reid.similarity_threshold`
- `reid.max_embeddings_per_track`
- `reid.max_path_points`
- `reid.target_labels`

If `torchreid` with OSNet weights is available locally, the tracker will use it. Otherwise it falls back to a torchvision backbone plus handcrafted appearance features.
`reid.target_labels` can be used to restrict correlation to person-like labels once a person detector feed is wired into the realtime pipeline or posted through `/api/reid/observe`.

## 9. Explainable AI

Alerts and websocket severity packets now include an `explanation` object with:

- `reason`
- `summary`
- `factors`
- `model_breakdown`
- `feature_importance`
- `final_score`

Config in `src/config/settings.yaml`:

```yaml
xai:
  enabled: true
  persistence_window_seconds: 20
  persistent_detection_threshold: 3
  max_feature_count: 5
```

The explanation layer is implemented with lightweight rule templates and weighted feature attribution, so it remains safe for realtime use.

## 10. Predictive Threat Intelligence

The predictive layer analyzes ReID track behavior before an incident is raised. It scores:

- loitering in the current zone
- repeated entry / exit transitions
- pacing and circular path patterns
- sudden speed / acceleration
- zone sensitivity from restricted-zone config and zone-policy thresholds

Tracks receive a smoothed `risk_score` between `0` and `1`.
`risk_score >= 0.70` is treated as high risk.
`risk_score >= 0.85` triggers a predictive pre-alert and websocket event.

Config in `src/config/settings.yaml`:

```yaml
predictive:
  enabled: true
  high_risk_threshold: 0.70
  pre_alert_threshold: 0.85
  restricted_zones: []
  zone_weights: {}
```

Predictive websocket packets are emitted on `WS /ws/detections` with `type: "predictive"`.

## 11. Project Layout

- `api/main.py`: FastAPI app, REST + WebSocket endpoints
- `api/realtime_engine.py`: capture loop + inference + alert pipeline
- `frontend/src/components/ZoneMapDashboard.jsx`: React zone monitoring dashboard
- `frontend/src/components/EvidenceModal.jsx`: modal video player for alert evidence clips
- `frontend/src/components/ZoneLayer.jsx`: zone overlay rendering + hover/select states
- `frontend/src/components/ThreatMarker.jsx`: live websocket threat marker rendering
- `frontend/src/components/PathLayer.jsx`: ReID movement path SVG overlay
- `frontend/src/components/SidePanel.jsx`: zone/alert/track drilldown panel
- `frontend/src/components/liveMapUtils.js`: marker normalization, retention, and heatmap helpers
- `frontend/src/components/XaiPanels.jsx`: alert explanation cards, confidence bars, and feature charts
- `frontend/src/components/reidTrajectoryUtils.js`: dashboard trajectory normalization + overlay helpers
- `src/evidence/clip_recorder.py`: background evidence clip capture and MP4 writing
- `src/evidence/buffer_manager.py`: rolling pre-event frame buffer management
- `src/evidence/video_writer.py`: MP4 writing, watermarking, hashing, and thumbnail generation
- `src/predictive/behavior_analyzer.py`: predictive behavior extraction + smoothed risk state
- `src/predictive/pattern_detector.py`: loitering, transition, pacing, circular, and speed analysis
- `src/predictive/risk_model.py`: weighted predictive risk scoring and explainability output
- `src/reid/embedding_model.py`: ReID embedding extraction backend
- `src/reid/tracker.py`: track matching and cross-camera trajectory state
- `src/reid/path_manager.py`: normalized path point management
- `src/xai/explainer.py`: explanation generation for alerts and websocket severity packets
- `src/xai/reason_templates.py`: human-readable alert reason templates
- `src/xai/feature_importance.py`: normalized feature contribution output
- `src/models/weapon_detector.py`: YOLO wrapper
- `src/models/action_recognizer.py`: Video Swin wrapper
- `src/fusion/rule_engine.py`: severity fusion
- `src/alerts/notifier.py`: alert JSONL/console outputs

## 12. Integration Testing (Queue + Worker + DB + Redis)

Install dev dependencies:

```bash
pip install -r requirements-dev.txt
```

Start isolated test services (Docker):

```bash
docker run -d --name threat-postgres-test -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=threat_monitor_test -p 5433:5432 postgres:16
docker run -d --name threat-redis-test -p 6380:6379 redis:7-alpine
```

Set test-only environment variables (PowerShell):

```bash
$env:TEST_DATABASE_URL="postgresql+asyncpg://postgres:postgres@localhost:5433/threat_monitor_test"
$env:TEST_REDIS_URL="redis://localhost:6380/0"
```

Run integration tests:

```bash
pytest tests/test_alert_pipeline_integration.py -q
```

Notes:
- `pytest.ini` is configured with `asyncio_mode = auto`.
- Tests require dedicated test services and will skip when `TEST_DATABASE_URL` / `TEST_REDIS_URL` are not set.

## 13. Operations (Migration, DLQ Replay, Metrics)

Apply DB migration for `alerts.alert_id` uniqueness:

```bash
alembic upgrade head
```

Replay failed DLQ records back to main queue:

```bash
python scripts/replay_dlq.py --limit 100
```

Dry-run replay validation:

```bash
python scripts/replay_dlq.py --limit 100 --dry-run
```

Read queue/worker metrics:

- `GET /api/v3/ops/metrics`
- `GET /api/v3/ops/health`

Run one-command end-to-end smoke test:

```bash
python scripts/e2e_smoke_test.py
```

Notes:
- By default, the script auto-starts API + worker if API is not reachable, validates enqueue/worker processing/metrics, then stops any processes it started.
- To validate only against already running services: `python scripts/e2e_smoke_test.py --no-auto-start`

Manage API + worker as background dev services (Windows PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/dev_services.ps1 -Action start
powershell -ExecutionPolicy Bypass -File scripts/dev_services.ps1 -Action status
powershell -ExecutionPolicy Bypass -File scripts/dev_services.ps1 -Action stop
```

Service logs are written to `tmp_dev_logs/`.

Bring up local infra stack (PostgreSQL + Redis + RabbitMQ + Kafka):

```bash
docker compose up -d
```

## 14. Production Upgrade Modules

1. PostgreSQL + Redis
- PostgreSQL is used as the primary async DB (`DATABASE_URL`).
- Redis is used for cache, queue, metrics, and websocket pub/sub (`REDIS_URL`).
- Dependency health is available at `GET /api/v3/ops/health`.

2. Message Broker (Redis / RabbitMQ / Kafka)
- Queue producer and worker now use a broker abstraction.
- Set `ALERT_BROKER_BACKEND=redis|rabbitmq|kafka`.
- Optional dependencies: `pip install -r requirements-broker.txt`

3. Real Notification Integration (Twilio)
- SMS sender supports provider mode:
  - `webhook` (existing webhook delivery)
  - `twilio` (real Twilio REST delivery)
- Configure in `src/config/settings.yaml` under `sos.sms` or with env vars:
  - `THREAT_SMS_PROVIDER=twilio`
  - `THREAT_TWILIO_ACCOUNT_SID`
  - `THREAT_TWILIO_AUTH_TOKEN`
  - `THREAT_TWILIO_FROM_NUMBER` (or `THREAT_TWILIO_MESSAGING_SERVICE_SID`)
- Admin SMS smoke test:
  - `POST /api/sos/test-sms`
  - Example body: `{"to":"+15551234567","message":"Threat monitor test"}`

4. Edge AI Deployment (Basic)
- New `edge` config enables lightweight local-edge behavior:
  - `edge.enabled`: enable edge mode
  - `edge.max_fps`: throttle processing FPS
  - `edge.input_scale`: downscale inference input for latency
  - `edge.prefer_cpu`: force CPU-friendly deployment path

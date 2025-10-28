# BlueSentinel SIEM 🛡️

A compact, hands-on SIEM you can run locally or with Docker. It ingests syslog (UDP) and file logs, normalizes them into a simple common schema, stores everything in SQLite, evaluates YAML detection rules (including sliding-window aggregations), and exposes a FastAPI for querying events and alerts.

Features

⚙️ Ingest: syslog (UDP on 5514) and a file-ingest endpoint; sample logs included

🧭 Normalize: Apache access, Linux auth (sshd), and JSON (CloudTrail-style) mappers → common schema

🔎 Detect: YAML-based rules with boolean conditions + sliding-window aggregations

🗃️ Store: SQLite by default (simple and portable)

🌐 API: FastAPI endpoints for events, alerts, and stats (Swagger UI at /docs)

🧪 Tests: pytest coverage for parsers and rules

🐳 Docker: single-container setup with docker compose up

🛡️ MITRE mapping: sample rules tagged to MITRE ATT&CK tactics/techniques

## Quickstart

### 1) Python
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn bluesentinel.api:app --host 0.0.0.0 --port 8000
```
Open http://localhost:8000/docs

### 2) Docker
```bash
docker compose up --build
# API on http://localhost:8000, syslog UDP on port 5514
```

## Try it fast
- Send an event via file ingest:
```bash
curl -X POST http://localhost:8000/ingest/file \
  -H "Content-Type: text/plain" \
  --data-binary @samples/logs/auth.log
```
- See alerts:
```
curl http://localhost:8000/alerts
```

## Repository Structure
```
BlueSentinel-SIEM/
├── rules/                      # YAML detection rules
├── samples/logs/               # Example logs (auth, apache)
├── src/bluesentinel/           # App source
│   ├── parsers/                # Source-specific parsers
│   ├── enrichers/              # Optional enrichers (GeoIP stub)
│   ├── api.py                  # FastAPI app + startup syslog server
│   ├── pipeline.py             # Orchestrates parse → normalize → store → detect
│   ├── rules_engine.py         # YAML rule loader + evaluator with windows
│   ├── storage.py              # SQLite helpers
│   ├── schema.py               # Common event schema helpers
│   └── syslog_server.py        # UDP syslog listener (5514)
├── tests/                      # Pytests
├── .github/workflows/ci.yml    # Lint + tests
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

## Schema (simplified)
We use a compact, Elastic-like schema for portability:
```json
{
  "@timestamp": "...ISO8601...",
  "event": {"module": "auth", "action": "FAILED_PASSWORD"},
  "source": {"ip": "1.2.3.4", "port": 5555},
  "destination": {"ip": null, "port": null},
  "user": {"name": "root"},
  "http": {"method": "GET", "status_code": 404, "path": "/index.html"},
  "log": {"original": "raw line here"}
}
```

## Roadmap
- [ ] Add Postgres option
- [ ] Add Sigma rule compatibility layer
- [ ] Add simple web UI (charts) on top of API
- [ ] Add Kafka ingestion and S3 archiving

---


from fastapi import FastAPI, UploadFile, Body
from fastapi.responses import PlainTextResponse
import asyncio

from . import storage
from .pipeline import Pipeline
from .syslog_server import run_syslog_server

app = FastAPI(title="BlueSentinel SIEM", version="0.1.0")
pipeline = Pipeline(rules_dir="rules")

@app.on_event("startup")
async def startup():
    asyncio.create_task(run_syslog_server(pipeline))

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.post("/ingest/file", response_class=PlainTextResponse)
async def ingest_file(file: UploadFile):
    count = 0
    async for chunk in file.stream():
        for line in chunk.decode(errors="ignore").splitlines():
            if line.strip():
                pipeline.ingest_line("syslog" if "sshd" in line else "apache", line)
                count += 1
    return f\"Ingested {count} lines.\"

@app.get("/events")
def list_events(limit: int = 100):
    return storage.select_events(limit=limit)

@app.get("/alerts")
def list_alerts(limit: int = 100):
    return storage.select_alerts(limit=limit)

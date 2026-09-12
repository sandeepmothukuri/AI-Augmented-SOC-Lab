"""AI SOC Engine - FastAPI server."""

import logging
import os
from datetime import datetime, timezone

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field

from analyzer import AlertAnalyzer
from thehive_client import TheHiveClient

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI SOC Engine",
    description="LLM-powered alert triage and analysis for an open-source SOC lab",
    version="1.0.0",
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

analyzer = AlertAnalyzer()
hive_client = TheHiveClient()


class AlertPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=32)
    rule_id: str | None = Field(default=None, max_length=128)
    rule_description: str = Field(min_length=1, max_length=4096)
    severity: int = Field(ge=1, le=15)
    source_ip: str | None = None
    dest_ip: str | None = None
    hostname: str | None = Field(default=None, max_length=255)
    timestamp: str
    raw_log: str = Field(min_length=1, max_length=32768)
    misp_context: dict | None = None
    geo_info: dict | None = None


class TriageResult(BaseModel):
    alert_id: str
    verdict: str = Field(pattern="^(CLOSE|ESCALATE|ENRICH)$")
    confidence: float = Field(ge=0.0, le=1.0)
    severity_normalized: str = Field(pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    mitre_tactic: str | None
    mitre_technique: str | None
    summary: str
    response_recommendation: str
    playbook_steps: list[str]
    analyst_notes: str
    ai_model: str
    processing_time_ms: int = Field(ge=0)
    timestamp: str


@app.get("/health")
async def health():
    return {"status": "ok", "model": os.getenv("MODEL_NAME", "llama3")}


@app.post("/analyze", response_model=TriageResult)
async def analyze_alert(alert: AlertPayload, background_tasks: BackgroundTasks):
    start = datetime.now(timezone.utc)
    logger.info("Analyzing alert %s from %s", alert.alert_id, alert.source)

    try:
        result = await analyzer.analyze(alert.model_dump())
    except Exception as exc:
        logger.error("Analysis failed for %s: %s", alert.alert_id, exc)
        raise HTTPException(status_code=500, detail="Alert analysis failed") from exc

    elapsed_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    result["processing_time_ms"] = elapsed_ms
    result["timestamp"] = datetime.now(timezone.utc).isoformat()
    result["alert_id"] = alert.alert_id

    if result.get("verdict") in ("ESCALATE", "ENRICH"):
        background_tasks.add_task(hive_client.create_case, alert.model_dump(), result)

    validated = TriageResult.model_validate(result)
    logger.info(
        "Alert %s -> verdict=%s severity=%s (%sms)",
        alert.alert_id,
        validated.verdict,
        validated.severity_normalized,
        elapsed_ms,
    )
    return validated


@app.post("/playbook")
async def generate_playbook(alert_type: str, context: str | None = None):
    steps = await analyzer.generate_playbook(alert_type, context)
    return {"alert_type": alert_type, "steps": steps}


@app.post("/query")
async def natural_language_query(question: str):
    """Convert plain English into an Elasticsearch DSL query."""
    dsl = await analyzer.nl_to_dsl(question)
    return {"question": question, "elasticsearch_dsl": dsl}


@app.get("/stats")
async def stats():
    return analyzer.get_stats()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8888)

"""
AI SOC Engine - FastAPI server.
Receives alert data, runs LLM analysis, and returns validated triage output.
"""

import logging
import os
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field

from analyzer import AlertAnalyzer
from thehive_client import TheHiveClient

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI SOC Engine",
    description="LLM-powered alert triage and analysis for open-source SOC",
    version="1.1.0",
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

analyzer = AlertAnalyzer()
hive_client = TheHiveClient()


class Verdict(str, Enum):
    CLOSE = "CLOSE"
    ESCALATE = "ESCALATE"
    ENRICH = "ENRICH"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=1, max_length=200)
    source: str = Field(min_length=1, max_length=50)
    rule_id: Optional[str] = Field(default=None, max_length=100)
    rule_description: str = Field(min_length=1, max_length=2000)
    severity: int = Field(ge=1, le=15)
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    hostname: Optional[str] = Field(default=None, max_length=255)
    timestamp: str
    raw_log: str = Field(min_length=1, max_length=10000)
    misp_context: Optional[dict] = None
    geo_info: Optional[dict] = None


class TriageResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    severity_normalized: Severity
    mitre_tactic: Optional[str]
    mitre_technique: Optional[str]
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

    if result["verdict"] in (Verdict.ESCALATE.value, Verdict.ENRICH.value):
        background_tasks.add_task(hive_client.create_case, alert.model_dump(), result)

    logger.info(
        "Alert %s -> verdict=%s severity=%s (%sms)",
        alert.alert_id,
        result["verdict"],
        result["severity_normalized"],
        elapsed_ms,
    )
    return result


@app.post("/playbook")
async def generate_playbook(alert_type: str, context: Optional[str] = None):
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

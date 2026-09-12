"""
Core alert analysis logic using LangChain + Ollama.

The LLM is treated as an analyst-assist component. Its output is parsed and
validated before it is allowed to influence the SOC workflow.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain_community.llms import Ollama
from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)
PROMPT_DIR = Path(__file__).parent / "prompts"

MITRE_PATTERNS = {
    "brute force": ("TA0006 - Credential Access", "T1110 - Brute Force"),
    "port scan": ("TA0007 - Discovery", "T1046 - Network Service Scanning"),
    "sql injection": ("TA0001 - Initial Access", "T1190 - Exploit Public-Facing Application"),
    "xss": ("TA0001 - Initial Access", "T1190 - Exploit Public-Facing Application"),
    "privilege escalation": (
        "TA0004 - Privilege Escalation",
        "T1068 - Exploitation for Privilege Escalation",
    ),
    "lateral movement": ("TA0008 - Lateral Movement", "T1021 - Remote Services"),
    "exfiltration": (
        "TA0010 - Exfiltration",
        "T1048 - Exfiltration Over Alternative Protocol",
    ),
    "malware": ("TA0002 - Execution", "T1204 - User Execution"),
    "ransomware": ("TA0040 - Impact", "T1486 - Data Encrypted for Impact"),
    "c2": ("TA0011 - Command and Control", "T1071 - Application Layer Protocol"),
    "phishing": ("TA0001 - Initial Access", "T1566 - Phishing"),
    "web shell": ("TA0003 - Persistence", "T1505.003 - Web Shell"),
    "dns tunneling": ("TA0011 - Command and Control", "T1071.004 - DNS"),
}

VERDICTS = {"CLOSE", "ESCALATE", "ENRICH"}
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class TriageDecision(BaseModel):
    """Validated contract accepted from the LLM triage response."""

    verdict: str = Field(pattern=r"^(CLOSE|ESCALATE|ENRICH)$")
    confidence: float = Field(ge=0.0, le=1.0)
    severity: str = Field(pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")
    reasoning: str = Field(min_length=1, max_length=4000)


class AlertAnalyzer:
    def __init__(self):
        self.model_name = os.getenv("MODEL_NAME", "llama3")
        self.ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self._stats = {"analyzed": 0, "escalated": 0, "closed": 0, "errors": 0}

        self.llm = Ollama(
            model=self.model_name,
            base_url=self.ollama_host,
            temperature=0.1,
        )

        self.triage_prompt = PromptTemplate(
            input_variables=["alert"], template=self._load_prompt("triage.txt")
        )
        self.summary_prompt = PromptTemplate(
            input_variables=["alert"], template=self._load_prompt("summary.txt")
        )
        self.playbook_prompt = PromptTemplate(
            input_variables=["alert_type", "context"], template=self._load_prompt("playbook.txt")
        )
        self.nl_dsl_prompt = PromptTemplate(
            input_variables=["question"], template=self._load_prompt("nl_to_dsl.txt")
        )

        self.triage_chain = LLMChain(llm=self.llm, prompt=self.triage_prompt)
        self.summary_chain = LLMChain(llm=self.llm, prompt=self.summary_prompt)
        self.playbook_chain = LLMChain(llm=self.llm, prompt=self.playbook_prompt)
        self.nl_dsl_chain = LLMChain(llm=self.llm, prompt=self.nl_dsl_prompt)

    def _load_prompt(self, filename: str) -> str:
        path = PROMPT_DIR / filename
        if path.exists():
            return path.read_text(encoding="utf-8")
        logger.warning("Prompt file %s not found, using fallback", filename)
        return self._fallback_prompt(filename)

    def _fallback_prompt(self, filename: str) -> str:
        fallbacks = {
            "triage.txt": (
                "You are a SOC analyst. Return JSON only.\nAlert: {alert}\n"
                '{"verdict":"ESCALATE|CLOSE|ENRICH","confidence":0.0,'
                '"severity":"LOW|MEDIUM|HIGH|CRITICAL","reasoning":"..."}'
            ),
            "summary.txt": "Summarize this security alert in 2-3 sentences for an analyst.\nAlert: {alert}",
            "playbook.txt": "Generate a step-by-step incident response playbook for: {alert_type}\nContext: {context}\nFormat as numbered list.",
            "nl_to_dsl.txt": "Convert this question to Elasticsearch DSL JSON query:\nQuestion: {question}\nRespond with valid JSON only.",
        }
        return fallbacks.get(filename, "{alert}")

    def _map_mitre(self, description: str) -> tuple[str, str]:
        desc_lower = description.lower()
        for keyword, (tactic, technique) in MITRE_PATTERNS.items():
            if keyword in desc_lower:
                return tactic, technique
        return "Unknown Tactic", "Unknown Technique"

    def _normalize_severity(self, wazuh_level: int) -> str:
        if wazuh_level >= 12:
            return "CRITICAL"
        if wazuh_level >= 9:
            return "HIGH"
        if wazuh_level >= 6:
            return "MEDIUM"
        return "LOW"

    def _extract_json_object(self, raw: str) -> dict[str, Any] | None:
        """Extract the first decodable JSON object without greedy regex parsing."""
        decoder = json.JSONDecoder()
        for index, char in enumerate(raw):
            if char != "{":
                continue
            try:
                value, _ = decoder.raw_decode(raw[index:])
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return value
        return None

    def _parse_triage_json(self, raw: str) -> dict[str, Any]:
        """Validate LLM output and fail closed to ENRICH on contract violations."""
        candidate = self._extract_json_object(raw)
        if candidate is not None:
            try:
                decision = TriageDecision.model_validate(candidate)
                return decision.model_dump()
            except ValidationError as exc:
                logger.warning("Invalid LLM triage contract: %s", exc)

        return {
            "verdict": "ENRICH",
            "confidence": 0.5,
            "severity": "MEDIUM",
            "reasoning": "LLM output did not satisfy the triage contract; manual enrichment required.",
        }

    async def analyze(self, alert: dict) -> dict:
        alert_str = json.dumps(alert, indent=2)
        mitre_tactic, mitre_technique = self._map_mitre(alert.get("rule_description", ""))
        severity_normalized = self._normalize_severity(alert.get("severity", 5))

        try:
            triage_raw = self.triage_chain.run(alert=alert_str)
            triage = self._parse_triage_json(triage_raw)
            summary_raw = self.summary_chain.run(alert=alert_str)
            self._stats["analyzed"] += 1

            verdict = triage["verdict"]
            if verdict == "ESCALATE":
                self._stats["escalated"] += 1
            elif verdict == "CLOSE":
                self._stats["closed"] += 1

            playbook = await self.generate_playbook(
                alert.get("rule_description", "security incident"),
                f"Source IP: {alert.get('source_ip')}, Severity: {severity_normalized}",
            )

            return {
                "verdict": verdict,
                "confidence": triage["confidence"],
                "severity_normalized": triage["severity"],
                "mitre_tactic": mitre_tactic,
                "mitre_technique": mitre_technique,
                "summary": summary_raw.strip(),
                "response_recommendation": triage["reasoning"],
                "playbook_steps": playbook,
                "analyst_notes": (
                    f"AI model: {self.model_name} | Rule: {alert.get('rule_id')} | "
                    f"Source: {alert.get('source')}"
                ),
                "ai_model": self.model_name,
            }
        except Exception as exc:
            self._stats["errors"] += 1
            logger.exception("LLM analysis error: %s", exc)
            raise

    async def generate_playbook(self, alert_type: str, context: str = "") -> list[str]:
        raw = self.playbook_chain.run(
            alert_type=alert_type, context=context or "No additional context"
        )
        lines = [line.strip() for line in raw.strip().splitlines() if line.strip()]
        steps = [re.sub(r"^\d+[\.\)]\s*", "", line) for line in lines]
        return steps[:10]

    async def nl_to_dsl(self, question: str) -> dict:
        raw = self.nl_dsl_chain.run(question=question)
        parsed = self._extract_json_object(raw)
        if parsed is not None:
            return parsed
        return {"error": "Could not parse DSL"}

    def get_stats(self) -> dict:
        return self._stats.copy()

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ai-engine"))
from analyzer import AlertAnalyzer  # noqa: E402


@pytest.fixture
def analyzer():
    return AlertAnalyzer.__new__(AlertAnalyzer)


def test_valid_triage_json_is_normalized(analyzer):
    result = analyzer._parse_triage_json(
        'analysis text {"verdict":"ESCALATE","confidence":0.91,'
        '"severity":"HIGH","reasoning":"Repeated authentication failures."} trailing'
    )
    assert result == {
        "verdict": "ESCALATE",
        "confidence": 0.91,
        "severity": "HIGH",
        "reasoning": "Repeated authentication failures.",
    }


def test_invalid_triage_fails_closed_to_enrich(analyzer):
    result = analyzer._parse_triage_json(
        '{"verdict":"DELETE_HOST","confidence":4,"severity":"HIGH","reasoning":"bad"}'
    )
    assert result["verdict"] == "ENRICH"
    assert result["confidence"] == 0.5


def test_malformed_triage_fails_closed_to_enrich(analyzer):
    result = analyzer._parse_triage_json("not json")
    assert result["verdict"] == "ENRICH"
    assert "manual enrichment" in result["reasoning"]


@pytest.mark.parametrize(
    ("description", "tactic", "technique"),
    [
        ("SSH brute force detected", "TA0006 - Credential Access", "T1110 - Brute Force"),
        ("Port scan detected", "TA0007 - Discovery", "T1046 - Network Service Scanning"),
        ("Ransomware behavior", "TA0040 - Impact", "T1486 - Data Encrypted for Impact"),
    ],
)
def test_mitre_mapping(analyzer, description, tactic, technique):
    assert analyzer._map_mitre(description) == (tactic, technique)


def test_wazuh_severity_normalization(analyzer):
    assert analyzer._normalize_severity(15) == "CRITICAL"
    assert analyzer._normalize_severity(10) == "HIGH"
    assert analyzer._normalize_severity(7) == "MEDIUM"
    assert analyzer._normalize_severity(3) == "LOW"


def test_lookup_runbook_finds_matching_guide(analyzer):
    bf = analyzer._lookup_runbook("SSH brute force attack")
    assert bf is not None
    assert bf["category"] == "brute_force"
    assert "T1110" in bf["mitre_techniques"]
    assert len(bf["containment_steps"]) > 0

    rw = analyzer._lookup_runbook("Suspected ransomware activity")
    assert rw is not None
    assert rw["category"] == "malware_ransomware"
    assert "T1486" in rw["mitre_techniques"]


def test_lookup_runbook_returns_none_for_unknown(analyzer):
    assert analyzer._lookup_runbook("unknown generic event") is None


def test_lookup_runbook_privilege_escalation(analyzer):
    pe = analyzer._lookup_runbook("sudo privilege escalation attempt detected")
    assert pe is not None
    assert pe["category"] == "privilege_escalation"
    assert "T1068" in pe["mitre_techniques"]
    assert len(pe["containment_steps"]) > 0
    assert len(pe["remediation_steps"]) > 0

    suid = analyzer._lookup_runbook("suid binary abuse on /usr/bin/bash")
    assert suid is not None
    assert suid["category"] == "privilege_escalation"


def test_lookup_runbook_web_attack_variants(analyzer):
    xss = analyzer._lookup_runbook("XSS payload injected via query parameter")
    assert xss is not None
    assert xss["category"] == "web_attack"

    sqli = analyzer._lookup_runbook("SQL injection attempt on /login endpoint")
    assert sqli is not None
    assert sqli["category"] == "web_attack"

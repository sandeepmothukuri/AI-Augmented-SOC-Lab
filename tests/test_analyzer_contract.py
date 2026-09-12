import pytest

from ai_engine.analyzer import AlertAnalyzer


@pytest.fixture
def analyzer():
    instance = AlertAnalyzer.__new__(AlertAnalyzer)
    return instance


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

#!/usr/bin/env python3
"""Send deterministic synthetic alerts to the local AI SOC engine."""

import json
import sys
from datetime import datetime, timezone

import httpx

AI_ENGINE_URL = "http://localhost:8888"


def now():
    return datetime.now(timezone.utc).isoformat()


TEST_ALERTS = {
    "ssh-bruteforce": {
        "alert_id": "TEST-001",
        "source": "wazuh",
        "rule_id": "5712",
        "rule_description": "SSH brute force attack followed by successful authentication",
        "severity": 12,
        "source_ip": "203.0.113.45",
        "dest_ip": "198.51.100.15",
        "hostname": "web-server-01",
        "timestamp": now(),
        "raw_log": (
            "sshd: Failed password for root from 203.0.113.45 (x200 attempts) | "
            "sshd: Accepted password for root from 203.0.113.45"
        ),
        "geo_info": {"country": "TEST-NET", "city": "Lab", "asn": "AS-EXAMPLE"},
        "misp_context": {
            "found": True,
            "tags": ["synthetic-test", "brute-force"],
            "threat_level": "high",
        },
    },
    "port-scan": {
        "alert_id": "TEST-002",
        "source": "suricata",
        "rule_id": "ET-SCAN-001",
        "rule_description": "Nmap SYN port scan detected from external host",
        "severity": 8,
        "source_ip": "198.51.100.50",
        "dest_ip": "192.0.2.0/24",
        "hostname": "firewall-01",
        "timestamp": now(),
        "raw_log": "Synthetic Nmap SYN scan | 2000 packets in 30 seconds",
        "geo_info": {"country": "TEST-NET", "city": "Lab", "asn": "AS-EXAMPLE"},
        "misp_context": None,
    },
    "web-attack": {
        "alert_id": "TEST-003",
        "source": "wazuh",
        "rule_id": "31103",
        "rule_description": "SQL injection attempt detected in web application",
        "severity": 10,
        "source_ip": "203.0.113.100",
        "dest_ip": "198.51.100.20",
        "hostname": "app-server-01",
        "timestamp": now(),
        "raw_log": "POST /login | User-Agent: synthetic-test | Payload: SQL injection test",
        "geo_info": {"country": "TEST-NET", "city": "Lab", "asn": "AS-EXAMPLE"},
        "misp_context": {"found": False},
    },
    "malware": {
        "alert_id": "TEST-004",
        "source": "wazuh",
        "rule_id": "553",
        "rule_description": "Malware detected - suspicious file execution with known hash",
        "severity": 14,
        "source_ip": None,
        "dest_ip": None,
        "hostname": "workstation-finance-03",
        "timestamp": now(),
        "raw_log": (
            "Synthetic file: invoice.exe | SHA256: TEST-HASH | "
            "Process spawned: cmd.exe | Network connection: 192.0.2.44:443"
        ),
        "geo_info": None,
        "misp_context": {
            "found": True,
            "tags": ["synthetic-test", "malware"],
            "threat_level": "critical",
        },
    },
    "data-exfil": {
        "alert_id": "TEST-005",
        "source": "zeek",
        "rule_id": "ZEEK-DNS-TUN",
        "rule_description": "Possible DNS tunneling / data exfiltration via DNS",
        "severity": 11,
        "source_ip": "192.0.2.55",
        "dest_ip": "192.0.2.53",
        "hostname": "dev-workstation-07",
        "timestamp": now(),
        "raw_log": (
            "Synthetic DNS anomaly | 4500 queries/hour | high subdomain entropy | "
            "domain: c2.example.invalid | synthetic transfer volume: 450MB"
        ),
        "geo_info": None,
        "misp_context": {
            "found": True,
            "tags": ["synthetic-test", "dns-tunneling"],
            "threat_level": "high",
        },
    },
}


def send_alert(scenario: str):
    alert = TEST_ALERTS.get(scenario)
    if not alert:
        print(f"Unknown scenario: {scenario}")
        print(f"Available: {', '.join(TEST_ALERTS.keys())}, all")
        sys.exit(1)

    print(f"\nSending synthetic test alert: {scenario}")
    print(f"Alert ID: {alert['alert_id']}")
    print(f"Severity: {alert['severity']}")
    print("-" * 50)

    try:
        with httpx.Client(timeout=120.0) as client:
            response = client.post(f"{AI_ENGINE_URL}/analyze", json=alert)
            response.raise_for_status()
            result = response.json()
    except httpx.ConnectError:
        print(f"Cannot connect to AI Engine at {AI_ENGINE_URL}")
        print("Is the AI Engine running? Check: docker ps")
        sys.exit(1)

    print(f"\nVERDICT:    {result['verdict']}")
    print(f"CONFIDENCE: {result['confidence']:.0%}")
    print(f"SEVERITY:   {result['severity_normalized']}")
    print(f"MITRE:      {result['mitre_tactic']}")
    print(f"            {result['mitre_technique']}")
    print(f"\nSUMMARY:\n{result['summary']}")
    print(f"\nRECOMMENDATION:\n{result['response_recommendation']}")
    print("\nPLAYBOOK STEPS:")
    for index, step in enumerate(result.get("playbook_steps", []), 1):
        print(f"  {index}. {step}")
    print(f"\nProcessing time: {result['processing_time_ms']}ms | Model: {result['ai_model']}")


def main():
    scenario = sys.argv[1] if len(sys.argv) > 1 else "ssh-bruteforce"
    if scenario == "all":
        for name in TEST_ALERTS:
            send_alert(name)
            print("\n" + "=" * 60 + "\n")
        return
    send_alert(scenario)


if __name__ == "__main__":
    main()

